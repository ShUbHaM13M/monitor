use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use axum::http::{HeaderValue, StatusCode};
use axum::response::{IntoResponse, Redirect, Response};
use axum_extra::extract::cookie::CookieJar;
use uuid::Uuid;

use super::{OrgId, session};
use crate::web::{AppError, AppState, is_htmx};

/// The signed-in user. Handlers that take it require a valid session; without one
/// the request is redirected to `/login?next=<path>`.
#[derive(Debug, Clone)]
pub struct CurrentUser {
    pub user_id: Uuid,
    pub email: String,
    pub org: OrgId,
    pub org_name: String,
    pub csrf_token: String,
}

/// The signed-in user if there is one, for pages that work either way.
pub struct MaybeUser(pub Option<CurrentUser>);

/// Per-request cache, so the CSRF middleware and the handler share one lookup.
#[derive(Clone)]
struct Lookup(Option<CurrentUser>);

/// Resolves the session cookie to a user, caching the result in request extensions.
pub(super) async fn lookup(
    parts: &mut Parts,
    state: &AppState,
) -> Result<Option<CurrentUser>, AppError> {
    if let Some(Lookup(user)) = parts.extensions.get::<Lookup>() {
        return Ok(user.clone());
    }
    let jar = CookieJar::from_headers(&parts.headers);
    let user = match jar.get(session::COOKIE_NAME) {
        Some(cookie) => session::load(&state.db, cookie.value())
            .await?
            .map(|row| CurrentUser {
                user_id: row.user_id,
                email: row.email,
                org: OrgId(row.org_id),
                org_name: row.org_name,
                csrf_token: row.csrf_token,
            }),
        None => None,
    };
    parts.extensions.insert(Lookup(user.clone()));
    Ok(user)
}

impl FromRequestParts<AppState> for CurrentUser {
    type Rejection = Response;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, Response> {
        match lookup(parts, state).await {
            Ok(Some(user)) => Ok(user),
            Ok(None) => Err(login_redirect(parts)),
            Err(err) => Err(err.into_response()),
        }
    }
}

impl FromRequestParts<AppState> for MaybeUser {
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, AppError> {
        Ok(MaybeUser(lookup(parts, state).await?))
    }
}

fn login_redirect(parts: &Parts) -> Response {
    if is_htmx(&parts.headers) {
        // A partial request can't usefully come back to itself after login;
        // send the whole page to the login screen instead.
        let mut res = StatusCode::UNAUTHORIZED.into_response();
        res.headers_mut()
            .insert("HX-Redirect", HeaderValue::from_static("/login"));
        return res;
    }
    let next = parts.uri.path_and_query().map_or("/", |pq| pq.as_str());
    let next: String = form_urlencoded::byte_serialize(next.as_bytes()).collect();
    Redirect::to(&format!("/login?next={next}")).into_response()
}
