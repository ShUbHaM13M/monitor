//! In-process rate limits. Each instance keeps its own buckets, so N instances
//! allow up to N times the rate; per-account login lockout lives in Postgres
//! (`db::users::begin_login_attempt`) because that one must hold across instances.

use std::collections::HashMap;
use std::hash::Hash;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use askama::Template;
use axum::extract::{Request, State};
use axum::http::{HeaderValue, Method, StatusCode, header};
use axum::middleware::Next;
use axum::response::{Html, IntoResponse, Response};

use super::client_ip::ClientIp;
use super::{AppState, Chrome, is_htmx};

/// Prune fully refilled buckets every this many calls, and early when the map
/// grows past `MAX_KEYS`, so memory stays bounded under a flood of new keys.
const PRUNE_EVERY: u32 = 1024;
const MAX_KEYS: usize = 100_000;

#[derive(Debug, Clone, Copy)]
pub struct Quota {
    /// Requests allowed at once.
    pub burst: u32,
    /// One more request allowed per this long.
    pub per: Duration,
}

impl Quota {
    pub const fn new(burst: u32, per: Duration) -> Self {
        Self { burst, per }
    }
}

/// A keyed GCRA limiter: one `Instant` per key ("theoretical arrival time").
pub struct RateLimiter<K> {
    quota: Quota,
    inner: Mutex<Inner<K>>,
}

struct Inner<K> {
    tat: HashMap<K, Instant>,
    calls: u32,
}

impl<K: Hash + Eq> RateLimiter<K> {
    pub fn new(quota: Quota) -> Self {
        Self {
            quota,
            inner: Mutex::new(Inner {
                tat: HashMap::new(),
                calls: 0,
            }),
        }
    }

    /// `Err(retry_after)` when `key` is over its quota.
    pub fn check(&self, key: K) -> Result<(), Duration> {
        self.check_at(key, Instant::now())
    }

    fn check_at(&self, key: K, now: Instant) -> Result<(), Duration> {
        let Quota { burst, per } = self.quota;
        let tolerance = per * burst.saturating_sub(1);
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        inner.calls = inner.calls.wrapping_add(1);
        if inner.calls.is_multiple_of(PRUNE_EVERY) || inner.tat.len() >= MAX_KEYS {
            inner.tat.retain(|_, tat| *tat > now);
        }
        let tat = inner.tat.get(&key).copied().unwrap_or(now).max(now);
        let ahead = tat - now;
        if ahead > tolerance {
            return Err(ahead - tolerance);
        }
        inner.tat.insert(key, tat + per);
        Ok(())
    }
}

/// Every limiter the web server uses.
pub struct Limits {
    /// Pings and webhook deliveries per token: a job can't flood its own log.
    pub ingest_token: RateLimiter<String>,
    /// Pings and webhook deliveries per client, across all tokens.
    pub ingest_ip: RateLimiter<IpAddr>,
    pub login: RateLimiter<IpAddr>,
    pub signup: RateLimiter<IpAddr>,
    /// Password reset, email and channel confirmation.
    pub account: RateLimiter<IpAddr>,
    /// REST API requests per key.
    pub api: RateLimiter<uuid::Uuid>,
    /// Public status pages per client.
    pub public: RateLimiter<IpAddr>,
}

impl Default for Limits {
    fn default() -> Self {
        let secs = Duration::from_secs;
        Self {
            ingest_token: RateLimiter::new(Quota::new(60, secs(1))),
            ingest_ip: RateLimiter::new(Quota::new(300, Duration::from_millis(50))),
            login: RateLimiter::new(Quota::new(10, secs(6))),
            signup: RateLimiter::new(Quota::new(5, secs(120))),
            account: RateLimiter::new(Quota::new(10, secs(30))),
            api: RateLimiter::new(Quota::new(120, Duration::from_millis(100))),
            public: RateLimiter::new(Quota::new(60, Duration::from_millis(500))),
        }
    }
}

/// Which limiter guards a form POST, if any.
fn auth_limiter<'a>(
    limits: &'a Limits,
    path: &str,
) -> Option<(&'static str, &'a RateLimiter<IpAddr>)> {
    match path {
        "/login" => Some(("login", &limits.login)),
        "/signup" => Some(("signup", &limits.signup)),
        "/forgot-password" | "/reset-password" | "/verify-email" | "/verify-channel" => {
            Some(("account", &limits.account))
        }
        _ => None,
    }
}

/// Per-client limits on the unauthenticated forms, which are what an attacker
/// would hammer (and login runs Argon2, which is expensive on purpose).
pub async fn protect_forms(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    req: Request,
    next: Next,
) -> Response {
    if req.method() == Method::POST
        && let Some(ip) = ip
        && let Some((scope, limiter)) = auth_limiter(&state.limits, req.uri().path())
        && let Err(wait) = limiter.check(ip)
    {
        tracing::warn!(%ip, scope, "rate limited");
        return too_many(scope, wait, is_htmx(req.headers()));
    }
    next.run(req).await
}

#[derive(Template)]
#[template(path = "rate_limited.html")]
struct RateLimitedPage<'a> {
    chrome: Chrome,
    message: &'a str,
}

#[derive(Template)]
#[template(source = r#"<p class="form-error">{{ message }}</p>"#, ext = "html")]
struct RateLimitedNotice<'a> {
    message: &'a str,
}

/// 429 with `Retry-After`. htmx forms get the message in the page's `#flash`
/// region instead of having their form replaced.
pub fn too_many(scope: &'static str, wait: Duration, htmx: bool) -> Response {
    metrics::counter!("rate_limited_total", "scope" => scope).increment(1);
    let secs = wait.as_secs_f64().ceil().max(1.0) as u64;
    let message = format!(
        "Too many attempts. Please wait {} and try again.",
        wait_text(secs)
    );
    let html = if htmx {
        RateLimitedNotice { message: &message }.render()
    } else {
        RateLimitedPage {
            chrome: Chrome::anonymous(),
            message: &message,
        }
        .render()
    }
    .unwrap_or(message);
    let mut res = (StatusCode::TOO_MANY_REQUESTS, Html(html)).into_response();
    let headers = res.headers_mut();
    headers.insert(header::RETRY_AFTER, HeaderValue::from(secs));
    if htmx {
        headers.insert("HX-Retarget", HeaderValue::from_static("#flash"));
        headers.insert("HX-Reswap", HeaderValue::from_static("innerHTML"));
    }
    res
}

/// Plain-text 429 for job and webhook clients.
pub fn too_many_plain(scope: &'static str, wait: Duration) -> Response {
    metrics::counter!("rate_limited_total", "scope" => scope).increment(1);
    let secs = wait.as_secs_f64().ceil().max(1.0) as u64;
    let mut res = (
        StatusCode::TOO_MANY_REQUESTS,
        format!("Rate limited: retry in {secs}s.\n"),
    )
        .into_response();
    res.headers_mut()
        .insert(header::RETRY_AFTER, HeaderValue::from(secs));
    res
}

fn wait_text(secs: u64) -> String {
    match secs {
        1 => "a second".to_owned(),
        s if s < 90 => format!("{s} seconds"),
        s => format!("{} minutes", s.div_ceil(60)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allows_a_burst_then_one_per_period() {
        let limiter = RateLimiter::new(Quota::new(3, Duration::from_secs(10)));
        let t0 = Instant::now();
        for _ in 0..3 {
            assert!(limiter.check_at("a", t0).is_ok());
        }
        let wait = limiter.check_at("a", t0).unwrap_err();
        assert_eq!(wait, Duration::from_secs(10));
        // Other keys have their own bucket.
        assert!(limiter.check_at("b", t0).is_ok());
        // One token comes back per period.
        let t1 = t0 + Duration::from_secs(10);
        assert!(limiter.check_at("a", t1).is_ok());
        assert!(limiter.check_at("a", t1).is_err());
        // A long pause refills the whole burst, but no more.
        let t2 = t1 + Duration::from_secs(3600);
        for _ in 0..3 {
            assert!(limiter.check_at("a", t2).is_ok());
        }
        assert!(limiter.check_at("a", t2).is_err());
    }

    #[test]
    fn prunes_refilled_keys() {
        let limiter = RateLimiter::new(Quota::new(1, Duration::from_secs(1)));
        let t0 = Instant::now();
        for i in 0..PRUNE_EVERY - 1 {
            limiter.check_at(i, t0).unwrap();
        }
        assert_eq!(
            limiter.inner.lock().unwrap().tat.len(),
            (PRUNE_EVERY - 1) as usize
        );
        limiter
            .check_at(u32::MAX, t0 + Duration::from_secs(5))
            .unwrap();
        assert_eq!(limiter.inner.lock().unwrap().tat.len(), 1);
    }

    #[test]
    fn waits_read_naturally() {
        assert_eq!(wait_text(1), "a second");
        assert_eq!(wait_text(42), "42 seconds");
        assert_eq!(wait_text(120), "2 minutes");
    }
}
