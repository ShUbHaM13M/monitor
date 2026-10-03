use axum::body::{Body, to_bytes};
use axum::extract::{Request, State};
use axum::http::{HeaderMap, Method, StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use subtle::ConstantTimeEq;

use super::extract::lookup;
use crate::web::AppState;

pub const HEADER: &str = "x-csrf-token";
pub const FORM_FIELD: &str = "_csrf";

/// Largest form body we buffer to look for the `_csrf` field.
const MAX_FORM_BYTES: usize = 64 * 1024;

/// CSRF protection for state-changing requests:
///
/// 1. `Origin` (or `Referer`) must be our own origin. This covers anonymous forms
///    like login and signup too.
/// 2. With a session, the per-session token must also be sent, either in the
///    `X-CSRF-Token` header (htmx) or the `_csrf` form field (plain forms).
pub async fn protect(State(state): State<AppState>, req: Request, next: Next) -> Response {
    if matches!(
        *req.method(),
        Method::GET | Method::HEAD | Method::OPTIONS | Method::TRACE
    ) {
        return next.run(req).await;
    }
    if !same_origin(req.headers(), state.config.public_origin()) {
        return forbidden();
    }

    let (mut parts, body) = req.into_parts();
    let user = match lookup(&mut parts, &state).await {
        Ok(user) => user,
        Err(err) => return err.into_response(),
    };
    let Some(user) = user else {
        return next.run(Request::from_parts(parts, body)).await;
    };

    if let Some(sent) = parts.headers.get(HEADER) {
        if !tokens_match(sent.as_bytes(), &user.csrf_token) {
            return forbidden();
        }
        return next.run(Request::from_parts(parts, body)).await;
    }

    let is_form = parts
        .headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.starts_with("application/x-www-form-urlencoded"));
    if !is_form {
        return forbidden();
    }
    let Ok(bytes) = to_bytes(body, MAX_FORM_BYTES).await else {
        return StatusCode::PAYLOAD_TOO_LARGE.into_response();
    };
    let sent = form_urlencoded::parse(&bytes)
        .find(|(key, _)| key == FORM_FIELD)
        .map(|(_, value)| value);
    match sent {
        Some(sent) if tokens_match(sent.as_bytes(), &user.csrf_token) => {
            next.run(Request::from_parts(parts, Body::from(bytes)))
                .await
        }
        _ => forbidden(),
    }
}

fn same_origin(headers: &HeaderMap, origin: &str) -> bool {
    if let Some(sent) = headers.get(header::ORIGIN) {
        return sent.as_bytes() == origin.as_bytes();
    }
    // Some privacy settings drop Origin but keep a same-origin Referer.
    headers
        .get(header::REFERER)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|referer| {
            referer
                .strip_prefix(origin)
                .is_some_and(|rest| rest.is_empty() || rest.starts_with('/'))
        })
}

fn tokens_match(sent: &[u8], expected: &str) -> bool {
    sent.ct_eq(expected.as_bytes()).into()
}

fn forbidden() -> Response {
    (
        StatusCode::FORBIDDEN,
        "Forbidden: invalid or missing CSRF token",
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use axum::http::HeaderValue;

    use super::*;

    fn headers(name: header::HeaderName, value: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(name, HeaderValue::from_str(value).unwrap());
        h
    }

    #[test]
    fn origin_checks() {
        let ours = "https://monitor.example";
        assert!(same_origin(&headers(header::ORIGIN, ours), ours));
        assert!(!same_origin(
            &headers(header::ORIGIN, "https://evil.example"),
            ours
        ));
        assert!(!same_origin(&headers(header::ORIGIN, "null"), ours));
        assert!(same_origin(
            &headers(header::REFERER, "https://monitor.example/login"),
            ours
        ));
        assert!(!same_origin(
            &headers(header::REFERER, "https://monitor.example.evil.com/"),
            ours
        ));
        assert!(!same_origin(&HeaderMap::new(), ours));
    }
}
