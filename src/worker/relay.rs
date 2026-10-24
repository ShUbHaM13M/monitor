//! Forwards queued webhook deliveries to each org's own server (see `db::relay`).

use std::time::Duration;

use futures::StreamExt;
use reqwest::Method;
use reqwest::header::{HeaderName, HeaderValue};

use crate::db::relay::{self, Attempt, Claimed};
use crate::notify::channels::webhook::sign;
use crate::notify::http::{parse_url, transport_error};
use crate::web::AppState;

const BATCH: i64 = 50;
/// Different checks forward in parallel; each check's queue is still one at a time.
const CONCURRENCY: usize = 10;
const TIMEOUT: Duration = Duration::from_secs(15);
const ERROR_SNIPPET: usize = 200;

/// Attempts every due queue head once. Returns how many were attempted.
pub async fn tick(state: &AppState) -> anyhow::Result<usize> {
    let claimed = relay::claim(&state.db, BATCH).await?;
    let count = claimed.len();
    futures::stream::iter(claimed)
        .for_each_concurrent(CONCURRENCY, |item| async move {
            let attempt = forward(state, &item).await;
            let result = match attempt {
                Attempt::Delivered { .. } => "delivered",
                Attempt::Failed { .. } => "failed",
            };
            metrics::counter!("relay_attempts_total", "result" => result).increment(1);
            if let Err(err) =
                relay::record(&state.db, &state.config.base_url, &item, &attempt).await
            {
                // The lease expires and the attempt is made again.
                tracing::error!(delivery = item.id, error = ?err, "could not record relay attempt");
            }
        })
        .await;
    Ok(count)
}

/// Makes one attempt. Every problem is a failed attempt, never an error.
async fn forward(state: &AppState, item: &Claimed) -> Attempt {
    let failed = |status: Option<u16>, error: String| Attempt::Failed { status, error };
    let url = match parse_url(&item.url, state.config.allow_private_targets) {
        Ok(url) => url,
        Err(err) => return failed(None, err),
    };
    let method = Method::from_bytes(item.method.as_bytes()).unwrap_or(Method::POST);
    let mut request = state
        .http
        .request(method, url)
        .timeout(TIMEOUT)
        .body(item.body.clone());

    if let Some(pairs) = item.headers.as_array() {
        for pair in pairs {
            let (Some(name), Some(value)) = (pair[0].as_str(), pair[1].as_str()) else {
                continue;
            };
            if let (Ok(name), Ok(value)) = (
                HeaderName::from_bytes(name.as_bytes()),
                HeaderValue::from_str(value),
            ) {
                request = request.header(name, value);
            }
        }
    }
    request = request
        .header("x-monitor-delivery", item.id.to_string())
        .header("x-monitor-attempt", item.attempts.to_string());
    if let Some(ip) = &item.source_ip {
        request = request.header("x-forwarded-for", ip.as_str());
    }
    // Our own signature, made now: a provider's signature may have expired by
    // the time a retry goes out (Stripe allows 5 minutes).
    let secret = item
        .secret_enc
        .as_deref()
        .and_then(|sealed| state.secrets.open(sealed).ok())
        .and_then(|bytes| String::from_utf8(bytes).ok());
    if let Some(secret) = secret {
        let timestamp = chrono::Utc::now().timestamp().to_string();
        request = request
            .header("x-monitor-signature", sign(&secret, &timestamp, &item.body))
            .header("x-monitor-timestamp", timestamp);
    }

    match request.send().await {
        Ok(res) if res.status().is_success() => Attempt::Delivered {
            status: res.status().as_u16(),
        },
        Ok(res) => {
            let status = res.status();
            let text = res.text().await.unwrap_or_default();
            let snippet: String = text.trim().chars().take(ERROR_SNIPPET).collect();
            let error = if snippet.is_empty() {
                format!("HTTP {status}")
            } else {
                format!("HTTP {status}: {snippet}")
            };
            failed(Some(status.as_u16()), error)
        }
        Err(err) => failed(None, transport_error(err).message().to_owned()),
    }
}
