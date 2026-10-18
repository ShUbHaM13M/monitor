use std::time::{Duration, Instant};

use futures::StreamExt;
use reqwest::Method;

use crate::crypto::SecretBox;
use crate::db::monitors::{self, ProbeTarget};
use crate::domain::uptime::{Expectations, MAX_BODY_BYTES, Outcome, Response, evaluate};
use crate::notify::http::parse_url;
use crate::web::AppState;

const BATCH: i64 = 100;
const CONCURRENCY: usize = 50;

/// Probes every due monitor and records the results. Returns how many were probed.
pub async fn tick(state: &AppState) -> anyhow::Result<usize> {
    let due = monitors::claim_due(&state.db, BATCH).await?;
    let count = due.len();
    futures::stream::iter(due)
        .for_each_concurrent(CONCURRENCY, |target| async move {
            let outcome = probe(state, &target).await;
            metrics::counter!("probes_total", "result" => if outcome.ok { "ok" } else { "failed" })
                .increment(1);
            metrics::histogram!("probe_duration_seconds")
                .record(f64::from(outcome.latency_ms) / 1000.0);
            if let Err(err) =
                monitors::record_result(&state.db, &state.config.base_url, target.id, &outcome)
                    .await
            {
                tracing::error!(monitor = %target.id, error = ?err, "could not record result");
            }
        })
        .await;
    Ok(count)
}

/// Makes the monitor's request and judges the response. Never fails: every problem
/// (bad URL, DNS, refused, timeout, blocked address) becomes a failed outcome.
pub async fn probe(state: &AppState, target: &ProbeTarget) -> Outcome {
    let expect = Expectations {
        status: target.expected_status.and_then(|s| u16::try_from(s).ok()),
        body_contains: target.body_contains.as_deref(),
        max_latency_ms: target.max_latency_ms,
    };
    let started = Instant::now();
    let elapsed_ms = || i32::try_from(started.elapsed().as_millis()).unwrap_or(i32::MAX);
    let failed = |error: String| Response::Failed {
        error,
        latency_ms: elapsed_ms(),
    };

    let request = match build_request(state, target) {
        Ok(request) => request,
        Err(error) => return evaluate(&failed(error), &expect),
    };
    let mut response = match request.send().await {
        Ok(response) => response,
        Err(err) if err.is_timeout() => {
            return evaluate(
                &Response::TimedOut {
                    after_ms: elapsed_ms(),
                },
                &expect,
            );
        }
        Err(err) => return evaluate(&failed(root_cause(&err)), &expect),
    };
    // Latency is time to the response headers; reading the body isn't counted.
    let latency_ms = elapsed_ms();
    let status = response.status().as_u16();

    let body = if expect.body_contains.is_some() {
        let mut buf = Vec::new();
        loop {
            match response.chunk().await {
                Ok(Some(chunk)) => {
                    buf.extend_from_slice(&chunk);
                    if buf.len() >= MAX_BODY_BYTES {
                        break;
                    }
                }
                Ok(None) => break,
                Err(err) if err.is_timeout() => {
                    return evaluate(
                        &Response::TimedOut {
                            after_ms: elapsed_ms(),
                        },
                        &expect,
                    );
                }
                Err(err) => return evaluate(&failed(root_cause(&err)), &expect),
            }
        }
        Some(String::from_utf8_lossy(&buf).into_owned())
    } else {
        None
    };
    evaluate(
        &Response::Received {
            status,
            latency_ms,
            body: body.as_deref(),
        },
        &expect,
    )
}

fn build_request(
    state: &AppState,
    target: &ProbeTarget,
) -> Result<reqwest::RequestBuilder, String> {
    let url = parse_url(&target.url, state.config.allow_private_targets)?;
    let method =
        Method::from_bytes(target.method.as_bytes()).map_err(|_| "Invalid method".to_owned())?;
    let timeout = Duration::from_millis(u64::try_from(target.timeout_ms).unwrap_or(10_000));
    let mut request = state.http.request(method, url).timeout(timeout);
    for (name, value) in decrypt_headers(&state.secrets, target.headers_enc.as_deref())? {
        request = request.header(name, value);
    }
    if let Some(body) = &target.body {
        request = request.body(body.clone());
    }
    Ok(request)
}

pub fn decrypt_headers(
    secrets: &SecretBox,
    sealed: Option<&[u8]>,
) -> Result<Vec<(String, String)>, String> {
    let Some(sealed) = sealed else {
        return Ok(Vec::new());
    };
    let bytes = secrets.open(sealed).map_err(|err| err.to_string())?;
    serde_json::from_slice(&bytes).map_err(|err| format!("stored headers are corrupt: {err}"))
}

/// The innermost error message: "Connection refused (os error 111)" rather than
/// reqwest's "error sending request for url (…)".
fn root_cause(err: &reqwest::Error) -> String {
    let mut message = err.to_string();
    let mut source = std::error::Error::source(err);
    while let Some(inner) = source {
        message = inner.to_string();
        source = inner.source();
    }
    message
}
