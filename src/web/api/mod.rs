//! The REST API, `/api/v1`. JSON in and out, authenticated by org API keys
//! (`Authorization: Bearer mon_…`). Mounted outside the CSRF layer: there are
//! no cookies here, so nothing ambient for another site to ride on.
//!
//! Create and update go through the same validation as the dashboard forms: a
//! JSON body is translated into the form's input and parsed by the same code.

mod checks;
mod monitors;
mod org;

use std::time::Duration;

use axum::Router;
use axum::extract::rejection::JsonRejection;
use axum::extract::{DefaultBodyLimit, FromRequest, FromRequestParts, Request};
use axum::http::request::Parts;
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{any, get, post};
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::json;
use uuid::Uuid;

use super::AppState;
use crate::auth::OrgId;
use crate::auth::api_key::{self, Scope};
use crate::db::orgs::CreateError;

const MAX_BODY: usize = 256 * 1024;
const DEFAULT_LIMIT: i64 = 50;
const MAX_LIMIT: i64 = 100;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/api/v1/checks", get(checks::list).post(checks::create))
        .route(
            "/api/v1/checks/{id}",
            get(checks::get).put(checks::update).delete(checks::delete),
        )
        .route("/api/v1/checks/{id}/pause", post(checks::pause))
        .route("/api/v1/checks/{id}/resume", post(checks::resume))
        .route("/api/v1/checks/{id}/pings", get(checks::pings))
        .route(
            "/api/v1/monitors",
            get(monitors::list).post(monitors::create),
        )
        .route(
            "/api/v1/monitors/{id}",
            get(monitors::get)
                .put(monitors::update)
                .delete(monitors::delete),
        )
        .route("/api/v1/monitors/{id}/pause", post(monitors::pause))
        .route("/api/v1/monitors/{id}/resume", post(monitors::resume))
        .route("/api/v1/monitors/{id}/results", get(monitors::results))
        .route("/api/v1/channels", get(org::channels))
        .route("/api/v1/incidents", get(org::incidents))
        .route("/api/v1/{*rest}", any(not_found))
        .layer(DefaultBodyLimit::max(MAX_BODY))
}

async fn not_found() -> ApiError {
    ApiError::NotFound
}

// ───────────────────────────── errors ─────────────────────────────

/// Every error is `{"error": {"code": "...", "message": "..."}}`.
#[derive(Debug)]
pub enum ApiError {
    Unauthorized,
    /// A read-only key tried to change something.
    ReadOnly,
    NotFound,
    /// The request was understood but its content is invalid.
    Invalid(String),
    /// The org is at its plan's limit.
    Limit(String),
    TooMany(Duration),
    Internal(anyhow::Error),
}

impl ApiError {
    fn parts(&self) -> (StatusCode, &'static str, String) {
        match self {
            Self::Unauthorized => (
                StatusCode::UNAUTHORIZED,
                "unauthorized",
                "Send a valid API key as `Authorization: Bearer mon_…`.".into(),
            ),
            Self::ReadOnly => (
                StatusCode::FORBIDDEN,
                "read_only_key",
                "This API key is read-only.".into(),
            ),
            Self::NotFound => (StatusCode::NOT_FOUND, "not_found", "Not found.".into()),
            Self::Invalid(msg) => (StatusCode::UNPROCESSABLE_ENTITY, "invalid", msg.clone()),
            Self::Limit(msg) => (StatusCode::FORBIDDEN, "plan_limit", msg.clone()),
            Self::TooMany(wait) => (
                StatusCode::TOO_MANY_REQUESTS,
                "rate_limited",
                format!("Too many requests; retry in {}s.", retry_secs(*wait)),
            ),
            Self::Internal(_) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal",
                "Something went wrong on our side.".into(),
            ),
        }
    }
}

fn retry_secs(wait: Duration) -> u64 {
    wait.as_secs_f64().ceil().max(1.0) as u64
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        if let Self::Internal(err) = &self {
            tracing::error!(error = ?err, "API request failed");
        }
        let (status, code, message) = self.parts();
        let mut res = (
            status,
            axum::Json(json!({ "error": { "code": code, "message": message } })),
        )
            .into_response();
        match self {
            Self::Unauthorized => {
                res.headers_mut()
                    .insert(header::WWW_AUTHENTICATE, HeaderValue::from_static("Bearer"));
            }
            Self::TooMany(wait) => {
                res.headers_mut()
                    .insert(header::RETRY_AFTER, HeaderValue::from(retry_secs(wait)));
            }
            _ => {}
        }
        res
    }
}

impl From<sqlx::Error> for ApiError {
    fn from(err: sqlx::Error) -> Self {
        Self::Internal(err.into())
    }
}

impl From<anyhow::Error> for ApiError {
    fn from(err: anyhow::Error) -> Self {
        Self::Internal(err)
    }
}

impl From<super::AppError> for ApiError {
    fn from(err: super::AppError) -> Self {
        match err {
            super::AppError::NotFound => Self::NotFound,
            super::AppError::Internal(err) => Self::Internal(err),
        }
    }
}

/// Maps a create's outcome: plan limits become `plan_limit` errors.
fn created(result: Result<Uuid, CreateError>, noun: &str) -> Result<Uuid, ApiError> {
    match result {
        Ok(id) => Ok(id),
        Err(CreateError::LimitReached(limit)) => {
            Err(ApiError::Limit(super::plan_limit_message(limit, noun)))
        }
        Err(CreateError::Db(err)) => Err(err.into()),
    }
}

// ───────────────────────────── extractors ─────────────────────────────

/// A request with a valid API key, read or write.
#[derive(Debug, Clone, Copy)]
pub struct ApiKey {
    pub org: OrgId,
}

/// A request with a valid read-write API key.
#[derive(Debug, Clone, Copy)]
pub struct WriteKey {
    pub org: OrgId,
}

async fn authenticate(parts: &Parts, state: &AppState) -> Result<api_key::ApiKeyAuth, ApiError> {
    let token = parts
        .headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .ok_or(ApiError::Unauthorized)?;
    let auth = api_key::authenticate(&state.db, token.trim())
        .await?
        .ok_or(ApiError::Unauthorized)?;
    state
        .limits
        .api
        .check(auth.key_id)
        .map_err(ApiError::TooMany)?;
    Ok(auth)
}

impl FromRequestParts<AppState> for ApiKey {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, ApiError> {
        let auth = authenticate(parts, state).await?;
        Ok(Self { org: auth.org })
    }
}

impl FromRequestParts<AppState> for WriteKey {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, ApiError> {
        let auth = authenticate(parts, state).await?;
        if auth.scope != Scope::Write {
            return Err(ApiError::ReadOnly);
        }
        Ok(Self { org: auth.org })
    }
}

/// `axum::Json`, but malformed bodies get our JSON error shape.
pub struct Body<T>(pub T);

impl<T: DeserializeOwned, S: Send + Sync> FromRequest<S> for Body<T> {
    type Rejection = ApiError;

    async fn from_request(req: Request, state: &S) -> Result<Self, ApiError> {
        match axum::Json::<T>::from_request(req, state).await {
            Ok(axum::Json(value)) => Ok(Self(value)),
            Err(rejection) => Err(ApiError::Invalid(json_problem(&rejection))),
        }
    }
}

fn json_problem(rejection: &JsonRejection) -> String {
    match rejection {
        JsonRejection::MissingJsonContentType(_) => {
            "Send the body as JSON with `Content-Type: application/json`.".into()
        }
        other => other.body_text(),
    }
}

/// `{id}` path segments: anything that isn't a UUID simply doesn't exist.
fn parse_id(raw: &str) -> Result<Uuid, ApiError> {
    raw.parse().map_err(|_| ApiError::NotFound)
}

#[derive(serde::Deserialize, Default)]
#[serde(default)]
pub struct Paging {
    limit: Option<i64>,
}

impl Paging {
    fn limit(&self) -> Result<i64, ApiError> {
        match self.limit {
            None => Ok(DEFAULT_LIMIT),
            Some(n) if (1..=MAX_LIMIT).contains(&n) => Ok(n),
            Some(_) => Err(ApiError::Invalid(format!(
                "`limit` must be between 1 and {MAX_LIMIT}."
            ))),
        }
    }
}

/// `{"data": [...]}`: lists are wrapped so fields can be added beside them later.
fn list<T: Serialize>(items: Vec<T>) -> axum::Json<serde_json::Value> {
    axum::Json(json!({ "data": items }))
}

/// Checks that every requested channel belongs to the org (the database would
/// silently skip others, which would surprise an API user).
async fn check_channels(state: &AppState, org: OrgId, ids: &[Uuid]) -> Result<(), ApiError> {
    let known: Vec<Uuid> = crate::db::channels::options(&state.db, org)
        .await?
        .into_iter()
        .map(|c| c.id)
        .collect();
    match ids.iter().find(|id| !known.contains(id)) {
        Some(id) => Err(ApiError::Invalid(format!("Unknown channel {id}."))),
        None => Ok(()),
    }
}
