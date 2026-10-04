use std::net::SocketAddr;

use axum::Router;
use axum::body::Bytes;
use axum::extract::{ConnectInfo, DefaultBodyLimit, Path, State};
use axum::http::{Extensions, HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;

use super::{AppError, AppState};
use crate::db::pings::{self, PingMeta};
use crate::domain::ping::{Signal, tail_utf8};

/// Requests up to this size are accepted; only the last `MAX_STORED_BODY` bytes are kept.
const MAX_REQUEST_BODY: usize = 1024 * 1024;
const MAX_STORED_BODY: usize = 10 * 1024;
const MAX_USER_AGENT: usize = 512;

/// Ping endpoints called by cron jobs and workers. Mounted outside the CSRF layer:
/// the token in the URL is the credential, and curl sends no `Origin`.
pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/p/{token}", get(ping).post(ping))
        .route("/p/{token}/{signal}", get(ping_signal).post(ping_signal))
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

async fn handle(
    state: &AppState,
    token: &str,
    signal: Signal,
    extensions: &Extensions,
    headers: &HeaderMap,
    body: &[u8],
) -> Result<Response, AppError> {
    let meta = PingMeta {
        // Present when served via `into_make_service_with_connect_info`; trusted
        // proxy headers (X-Forwarded-For) are not honoured yet.
        source_ip: extensions
            .get::<ConnectInfo<SocketAddr>>()
            .map(|ConnectInfo(addr)| addr.ip()),
        user_agent: headers
            .get(header::USER_AGENT)
            .and_then(|v| v.to_str().ok())
            .map(|ua| ua.chars().take(MAX_USER_AGENT).collect()),
        body: (!body.is_empty()).then(|| tail_utf8(body, MAX_STORED_BODY)),
    };
    if pings::record(&state.db, token, signal, meta).await? {
        Ok((StatusCode::OK, "OK\n").into_response())
    } else {
        // Tokens are 128-bit random values, so a 404 can't be used to enumerate
        // them, and it tells users their ping URL is wrong.
        Ok((StatusCode::NOT_FOUND, "Unknown ping URL.\n").into_response())
    }
}
