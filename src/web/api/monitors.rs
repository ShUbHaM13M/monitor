use std::collections::{BTreeMap, HashMap};

use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::{ApiError, ApiKey, Body, Paging, WriteKey, check_channels, created, parse_id};
use crate::auth::OrgId;
use crate::db::monitors::{self, Monitor};
use crate::db::{channels, orgs};
use crate::domain::uptime::format_headers;
use crate::web::AppState;
use crate::web::monitors::{MonitorInput, parse_spec};
use crate::worker::prober;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MonitorBody {
    name: String,
    url: String,
    /// Default GET.
    method: Option<String>,
    /// Seconds: 30, 60, 300, 900, 1800 or 3600. Default 60.
    interval: Option<i32>,
    /// Seconds, 1–30. Default 10.
    timeout: Option<i32>,
    expected_status: Option<u16>,
    body_contains: Option<String>,
    max_latency_ms: Option<i32>,
    /// Consecutive failures before alerting. Default 2.
    fail_threshold: Option<i32>,
    /// Request headers. Stored encrypted and never returned; omit on update to keep them.
    headers: Option<BTreeMap<String, String>>,
    /// Request body.
    body: Option<String>,
    /// Channel ids. Omitted: every channel on create, unchanged on update.
    channels: Option<Vec<Uuid>>,
}

#[derive(Serialize)]
pub struct MonitorOut {
    id: Uuid,
    name: String,
    url: String,
    method: String,
    interval: i32,
    timeout: i32,
    expected_status: Option<i16>,
    body_contains: Option<String>,
    max_latency_ms: Option<i32>,
    fail_threshold: i16,
    /// Names only: values may be credentials.
    header_names: Vec<String>,
    status: &'static str,
    last_checked_at: Option<DateTime<Utc>>,
    last_status_code: Option<i16>,
    last_latency_ms: Option<i32>,
    last_error: Option<String>,
    /// Share of checks that passed over the last 24 hours, 0–1; `null` before any.
    uptime_24h: Option<f64>,
    channels: Vec<Uuid>,
    created_at: DateTime<Utc>,
}

impl MonitorOut {
    fn new(state: &AppState, m: Monitor, channels: Vec<Uuid>, uptime_24h: Option<f64>) -> Self {
        let header_names = prober::decrypt_headers(&state.secrets, m.headers_enc.as_deref())
            .map(|h| h.into_iter().map(|(name, _)| name).collect())
            .unwrap_or_default();
        Self {
            id: m.id,
            name: m.name,
            url: m.url,
            method: m.method,
            interval: m.interval_secs,
            timeout: m.timeout_ms / 1000,
            expected_status: m.expected_status,
            body_contains: m.body_contains,
            max_latency_ms: m.max_latency_ms,
            fail_threshold: m.fail_threshold,
            header_names,
            status: m.status.label(),
            last_checked_at: m.last_checked_at,
            last_status_code: m.last_status_code,
            last_latency_ms: m.last_latency_ms,
            last_error: m.last_error,
            uptime_24h,
            channels,
            created_at: m.created_at,
        }
    }
}

async fn to_input(
    state: &AppState,
    org: OrgId,
    body: MonitorBody,
    existing: Option<&Monitor>,
) -> Result<MonitorInput, ApiError> {
    let opt = |v: Option<i32>| v.map(|v| v.to_string()).unwrap_or_default();
    let headers = match (body.headers, existing) {
        (Some(map), _) => {
            if let Some(name) = map.keys().find(|k| k.contains([':', '\n', '\r'])) {
                return Err(ApiError::Invalid(format!("Invalid header name {name:?}.")));
            }
            let pairs: Vec<(String, String)> = map.into_iter().collect();
            format_headers(&pairs)
        }
        (None, Some(m)) => prober::decrypt_headers(&state.secrets, m.headers_enc.as_deref())
            .map(|h| format_headers(&h))
            .map_err(|err| ApiError::Internal(anyhow::anyhow!(err)))?,
        (None, None) => String::new(),
    };
    let channel_ids = match (body.channels, existing) {
        (Some(ids), _) => {
            check_channels(state, org, &ids).await?;
            ids
        }
        (None, Some(m)) => channels::ids_for_monitor(&state.db, org, m.id).await?,
        (None, None) => channels::options(&state.db, org)
            .await?
            .into_iter()
            .map(|c| c.id)
            .collect(),
    };
    Ok(MonitorInput {
        name: body.name,
        url: body.url,
        method: body.method.unwrap_or_else(|| "GET".into()),
        interval_secs: body.interval.unwrap_or(60).to_string(),
        timeout_secs: body.timeout.unwrap_or(10).to_string(),
        expected_status: opt(body.expected_status.map(i32::from)),
        body_contains: body.body_contains.unwrap_or_default(),
        max_latency_ms: opt(body.max_latency_ms),
        fail_threshold: body.fail_threshold.unwrap_or(2).to_string(),
        headers,
        body: body.body.unwrap_or_default(),
        channel_ids: channel_ids.iter().map(Uuid::to_string).collect(),
    })
}

async fn load(state: &AppState, org: OrgId, raw_id: &str) -> Result<Monitor, ApiError> {
    monitors::get(&state.db, org, parse_id(raw_id)?)
        .await?
        .ok_or(ApiError::NotFound)
}

async fn out(state: &AppState, org: OrgId, m: Monitor) -> Result<MonitorOut, ApiError> {
    let channels = channels::ids_for_monitor(&state.db, org, m.id).await?;
    let uptime = monitors::uptime(&state.db, org, m.id, 24).await?;
    Ok(MonitorOut::new(state, m, channels, uptime))
}

pub async fn list(State(state): State<AppState>, key: ApiKey) -> Result<Response, ApiError> {
    let all = monitors::list(&state.db, key.org).await?;
    let uptimes = monitors::uptime_24h_by_monitor(&state.db, key.org).await?;
    let mut links: HashMap<Uuid, Vec<Uuid>> = channels::monitor_links(&state.db, key.org).await?;
    let items: Vec<MonitorOut> = all
        .into_iter()
        .map(|m| {
            let (ids, uptime) = (
                links.remove(&m.id).unwrap_or_default(),
                uptimes.get(&m.id).copied(),
            );
            MonitorOut::new(&state, m, ids, uptime)
        })
        .collect();
    Ok(super::list(items).into_response())
}

pub async fn get(
    State(state): State<AppState>,
    key: ApiKey,
    Path(id): Path<String>,
) -> Result<Json<MonitorOut>, ApiError> {
    let m = load(&state, key.org, &id).await?;
    Ok(Json(out(&state, key.org, m).await?))
}

pub async fn create(
    State(state): State<AppState>,
    key: WriteKey,
    Body(body): Body<MonitorBody>,
) -> Result<Response, ApiError> {
    let limits = orgs::limits(&state.db, key.org, &state.config.plan).await?;
    let input = to_input(&state, key.org, body, None).await?;
    let spec = parse_spec(&state, &input, limits.min_interval_secs).map_err(ApiError::Invalid)?;
    let id = created(
        monitors::create(&state.db, key.org, &spec, limits.max_monitors).await,
        "monitors",
    )?;
    let m = monitors::get(&state.db, key.org, id)
        .await?
        .ok_or(ApiError::NotFound)?;
    Ok((StatusCode::CREATED, Json(out(&state, key.org, m).await?)).into_response())
}

/// Replaces the monitor's definition; `headers` and `channels` are kept when omitted.
pub async fn update(
    State(state): State<AppState>,
    key: WriteKey,
    Path(id): Path<String>,
    Body(body): Body<MonitorBody>,
) -> Result<Json<MonitorOut>, ApiError> {
    let existing = load(&state, key.org, &id).await?;
    let limits = orgs::limits(&state.db, key.org, &state.config.plan).await?;
    let input = to_input(&state, key.org, body, Some(&existing)).await?;
    let spec = parse_spec(&state, &input, limits.min_interval_secs).map_err(ApiError::Invalid)?;
    if !monitors::update(&state.db, key.org, existing.id, &spec).await? {
        return Err(ApiError::NotFound);
    }
    let m = load(&state, key.org, &id).await?;
    Ok(Json(out(&state, key.org, m).await?))
}

pub async fn delete(
    State(state): State<AppState>,
    key: WriteKey,
    Path(id): Path<String>,
) -> Result<StatusCode, ApiError> {
    if !monitors::delete(&state.db, key.org, parse_id(&id)?).await? {
        return Err(ApiError::NotFound);
    }
    Ok(StatusCode::NO_CONTENT)
}

pub async fn pause(
    State(state): State<AppState>,
    key: WriteKey,
    Path(id): Path<String>,
) -> Result<Json<MonitorOut>, ApiError> {
    let m = load(&state, key.org, &id).await?;
    monitors::pause(&state.db, key.org, m.id).await?;
    let m = load(&state, key.org, &id).await?;
    Ok(Json(out(&state, key.org, m).await?))
}

pub async fn resume(
    State(state): State<AppState>,
    key: WriteKey,
    Path(id): Path<String>,
) -> Result<Json<MonitorOut>, ApiError> {
    let m = load(&state, key.org, &id).await?;
    monitors::resume(&state.db, key.org, m.id).await?;
    let m = load(&state, key.org, &id).await?;
    Ok(Json(out(&state, key.org, m).await?))
}

#[derive(Serialize)]
struct ResultOut {
    ok: bool,
    status_code: Option<i16>,
    latency_ms: Option<i32>,
    error: Option<String>,
    created_at: DateTime<Utc>,
}

/// Newest first.
pub async fn results(
    State(state): State<AppState>,
    key: ApiKey,
    Path(id): Path<String>,
    Query(paging): Query<Paging>,
) -> Result<Response, ApiError> {
    let m = load(&state, key.org, &id).await?;
    let items: Vec<ResultOut> = monitors::recent_results(&state.db, key.org, m.id, paging.limit()?)
        .await?
        .into_iter()
        .map(|r| ResultOut {
            ok: r.ok,
            status_code: r.status_code,
            latency_ms: r.latency_ms,
            error: r.error,
            created_at: r.created_at,
        })
        .collect();
    Ok(super::list(items).into_response())
}
