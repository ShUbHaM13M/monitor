use std::net::SocketAddr;

use axum::Router;
use axum::body::Bytes;
use axum::extract::{ConnectInfo, DefaultBodyLimit, Path, State};
use axum::http::{Extensions, HeaderMap, Method, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};

use super::{AppError, AppState};
use crate::db::pings::{self, Endpoint, PingMeta};
use crate::domain::ping::{Signal, capture_headers, head_utf8, tail_utf8};
use crate::domain::signature::{self, Scheme};

/// Requests up to this size are accepted; only `MAX_STORED_BODY` bytes are kept.
const MAX_REQUEST_BODY: usize = 1024 * 1024;
const MAX_STORED_BODY: usize = 10 * 1024;
const MAX_USER_AGENT: usize = 512;

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
    extensions: Extensions,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, AppError> {
    handle(
        &state,
        &token,
        Signal::Success,
        &extensions,
        &headers,
        &body,
    )
    .await
}

async fn ping_signal(
    State(state): State<AppState>,
    Path((token, signal)): Path<(String, String)>,
    extensions: Extensions,
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
    handle(&state, &token, signal, &extensions, &headers, &body).await
}

fn base_meta(extensions: &Extensions, headers: &HeaderMap) -> PingMeta {
    PingMeta {
        // Present when served via `into_make_service_with_connect_info`; trusted
        // proxy headers (X-Forwarded-For) are not honoured yet.
        source_ip: extensions
            .get::<ConnectInfo<SocketAddr>>()
            .map(|ConnectInfo(addr)| addr.ip()),
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
    extensions: &Extensions,
    headers: &HeaderMap,
    body: &[u8],
) -> Result<Response, AppError> {
    let meta = PingMeta {
        // Job output: the end is where the errors are.
        body: (!body.is_empty()).then(|| tail_utf8(body, MAX_STORED_BODY)),
        ..base_meta(extensions, headers)
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
    Ok(if found {
        (StatusCode::OK, "OK\n").into_response()
    } else {
        // Tokens are 128-bit random values, so a 404 can't be used to enumerate
        // them, and it tells users their ping URL is wrong.
        (StatusCode::NOT_FOUND, "Unknown ping URL.\n").into_response()
    })
}

/// An inbound webhook from a third-party service. Verified (if the monitor has a
/// signing secret) against the raw body, then logged and counted as a heartbeat.
async fn webhook(
    State(state): State<AppState>,
    Path(token): Path<String>,
    method: Method,
    extensions: Extensions,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, AppError> {
    let Some(target) = pings::webhook_target(&state.db, &token).await? else {
        return Ok((StatusCode::NOT_FOUND, "Unknown webhook URL.\n").into_response());
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
        ..base_meta(&extensions, &headers)
    };

    if let Some(rejection) = check_signature(&state, &target, &headers, &body) {
        pings::record_rejected(&state.db, target.id, meta, &rejection).await?;
        return Ok((
            StatusCode::UNAUTHORIZED,
            format!("Rejected: {rejection}.\n"),
        )
            .into_response());
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
