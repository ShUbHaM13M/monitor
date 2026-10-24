use axum::Router;
use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, Path, State};
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};

use super::client_ip::ClientIp;
use super::ratelimit::too_many_plain;
use super::{AppError, AppState};
use crate::db::pings::{self, Endpoint, PingMeta};
use crate::db::relay;
use crate::domain::ping::{Signal, capture_headers, head_utf8, tail_utf8};
use crate::domain::signature::{self, Scheme};

const UNKNOWN_PING: &str = "Unknown ping URL.\n";
const UNKNOWN_WEBHOOK: &str = "Unknown webhook URL.\n";

/// Requests up to this size are accepted; only `MAX_STORED_BODY` bytes are kept.
const MAX_REQUEST_BODY: usize = 1024 * 1024;
const MAX_STORED_BODY: usize = 10 * 1024;
const MAX_USER_AGENT: usize = 512;
/// Tokens are 22 characters; anything much longer can't be one.
const MAX_TOKEN: usize = 64;

/// Endpoints called by jobs and third-party services. Mounted outside the CSRF
/// layer: the token in the URL is the credential, and these clients send no `Origin`.
pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/p/{token}", get(ping).post(ping))
        .route("/p/{token}/{signal}", get(ping_signal).post(ping_signal))
        .route("/w/{token}", post(webhook).put(webhook).patch(webhook))
        .layer(DefaultBodyLimit::max(MAX_REQUEST_BODY))
}

async fn ping(
    State(state): State<AppState>,
    Path(token): Path<String>,
    ip: ClientIp,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, AppError> {
    handle(&state, &token, Signal::Success, ip, &headers, &body).await
}

async fn ping_signal(
    State(state): State<AppState>,
    Path((token, signal)): Path<(String, String)>,
    ip: ClientIp,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, AppError> {
    let Some(signal) = Signal::parse(Some(&signal)) else {
        return Ok((
            StatusCode::BAD_REQUEST,
            "Unknown signal: use start, fail or an exit code 0-255.\n",
        )
            .into_response());
    };
    handle(&state, &token, signal, ip, &headers, &body).await
}

/// `Some(response)` when the request must be turned away before touching the
/// database: an impossible token or a client over its rate limit.
fn turn_away(
    state: &AppState,
    token: &str,
    ClientIp(ip): ClientIp,
    not_found: &'static str,
) -> Option<Response> {
    if token.len() > MAX_TOKEN {
        return Some((StatusCode::NOT_FOUND, not_found).into_response());
    }
    if let Some(ip) = ip
        && let Err(wait) = state.limits.ingest_ip.check(ip)
    {
        return Some(too_many_plain("ingest_ip", wait));
    }
    if let Err(wait) = state.limits.ingest_token.check(token.to_owned()) {
        return Some(too_many_plain("ingest_token", wait));
    }
    None
}

fn base_meta(ClientIp(ip): ClientIp, headers: &HeaderMap) -> PingMeta {
    PingMeta {
        source_ip: ip,
        user_agent: headers
            .get(header::USER_AGENT)
            .and_then(|v| v.to_str().ok())
            .map(|ua| ua.chars().take(MAX_USER_AGENT).collect()),
        ..PingMeta::default()
    }
}

async fn handle(
    state: &AppState,
    token: &str,
    signal: Signal,
    ip: ClientIp,
    headers: &HeaderMap,
    body: &[u8],
) -> Result<Response, AppError> {
    if let Some(res) = turn_away(state, token, ip, UNKNOWN_PING) {
        return Ok(res);
    }
    let meta = PingMeta {
        // Job output: the end is where the errors are.
        body: (!body.is_empty()).then(|| tail_utf8(body, MAX_STORED_BODY)),
        ..base_meta(ip, headers)
    };
    let found = pings::record(
        &state.db,
        &state.config.base_url,
        Endpoint::Ping,
        token,
        signal,
        meta,
    )
    .await?;
    metrics::counter!("pings_total", "endpoint" => "ping", "result" => if found { "accepted" } else { "unknown" })
        .increment(1);
    Ok(if found {
        (StatusCode::OK, "OK\n").into_response()
    } else {
        // Tokens are 128-bit random values, so a 404 can't be used to enumerate
        // them, and it tells users their ping URL is wrong.
        (StatusCode::NOT_FOUND, UNKNOWN_PING).into_response()
    })
}

/// An inbound webhook from a third-party service. Verified (if the monitor has a
/// signing secret) against the raw body, then logged and counted as a heartbeat.
async fn webhook(
    State(state): State<AppState>,
    Path(token): Path<String>,
    method: Method,
    ip: ClientIp,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, AppError> {
    if let Some(res) = turn_away(&state, &token, ip, UNKNOWN_WEBHOOK) {
        return Ok(res);
    }
    let Some(target) = pings::webhook_target(&state.db, &token).await? else {
        metrics::counter!("pings_total", "endpoint" => "webhook", "result" => "unknown")
            .increment(1);
        return Ok((StatusCode::NOT_FOUND, UNKNOWN_WEBHOOK).into_response());
    };
    let (stored_body, truncated) = head_utf8(&body, MAX_STORED_BODY);
    let meta = PingMeta {
        body: (!body.is_empty()).then_some(stored_body),
        body_truncated: truncated,
        method: Some(method.to_string()),
        headers: Some(capture_headers(
            headers
                .iter()
                .map(|(name, value)| (name.as_str(), value.as_bytes())),
        )),
        ..base_meta(ip, &headers)
    };

    if let Some(rejection) = check_signature(&state, &target, &headers, &body) {
        pings::record_rejected(&state.db, target.id, meta, &rejection).await?;
        metrics::counter!("pings_total", "endpoint" => "webhook", "result" => "rejected")
            .increment(1);
        return Ok((
            StatusCode::UNAUTHORIZED,
            format!("Rejected: {rejection}.\n"),
        )
            .into_response());
    }
    if target.relay_url.is_some() {
        // Stored before answering: once the sender hears 200, the event is ours
        // to deliver. A full backlog is refused instead, so the sender keeps it.
        if relay::queue_full(&state.db, target.id).await? {
            pings::record_rejected(&state.db, target.id, meta, "relay backlog full").await?;
            let mut res = (
                StatusCode::SERVICE_UNAVAILABLE,
                "Relay backlog full; retry later.\n",
            )
                .into_response();
            res.headers_mut()
                .insert(header::RETRY_AFTER, HeaderValue::from_static("60"));
            return Ok(res);
        }
        let forwarded: Vec<(String, String)> = headers
            .iter()
            .filter(|(name, _)| relay::forwardable(name.as_str()))
            .filter_map(|(name, value)| Some((name.to_string(), value.to_str().ok()?.to_owned())))
            .collect();
        relay::enqueue(
            &state.db,
            target.id,
            method.as_str(),
            &forwarded,
            &body,
            meta.source_ip.map(|ip| ip.to_string()),
        )
        .await?;
    }
    pings::record(
        &state.db,
        &state.config.base_url,
        Endpoint::Webhook,
        &token,
        Signal::Webhook,
        meta,
    )
    .await?;
    metrics::counter!("pings_total", "endpoint" => "webhook", "result" => "accepted").increment(1);
    Ok((StatusCode::OK, "OK\n").into_response())
}

/// `Some(reason)` when the delivery must be rejected.
fn check_signature(
    state: &AppState,
    target: &pings::WebhookTarget,
    headers: &HeaderMap,
    body: &[u8],
) -> Option<String> {
    let scheme = Scheme::parse(target.signature_scheme.as_deref()?)?;
    let secret = target
        .signing_secret_enc
        .as_deref()
        .and_then(|sealed| state.secrets.open(sealed).ok())
        .and_then(|bytes| String::from_utf8(bytes).ok());
    let Some(secret) = secret else {
        // Fail closed: a monitor configured to verify never accepts unverified input.
        return Some("signing secret is unreadable (was SECRET_KEY changed?)".into());
    };
    let lookup = |name: &str| {
        headers
            .get(name)
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned)
    };
    signature::verify(
        scheme,
        &secret,
        target.signature_header.as_deref(),
        lookup,
        body,
        chrono::Utc::now().timestamp(),
    )
    .err()
}
