use std::collections::HashMap;

use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use uuid::Uuid;

use super::{ApiError, ApiKey, Body, Paging, WriteKey, check_channels, created, parse_id};
use crate::auth::OrgId;
use crate::db::checks::{self, Check};
use crate::db::{channels, orgs, pings};
use crate::web::AppState;
use crate::web::checks::{CheckInput, parse_spec};

/// Grace when none is given: the dashboard form's default.
const DEFAULT_GRACE_SECS: i64 = 3600;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CheckBody {
    name: String,
    /// "heartbeat" (default) or "webhook". Fixed once created.
    kind: Option<String>,
    schedule: ScheduleBody,
    /// Seconds.
    grace: Option<i64>,
    /// Seconds, a whole number of minutes. `null` for no limit.
    max_runtime: Option<i64>,
    duration_alerts: Option<bool>,
    /// Channel ids. Omitted: every channel on create, unchanged on update.
    channels: Option<Vec<Uuid>>,
    /// Webhook checks only. Omit `secret` on update to keep the stored one.
    signature: Option<SignatureBody>,
    /// Webhook checks: forward deliveries here. Omitted keeps the current
    /// setting; `null` turns forwarding off.
    #[serde(default, deserialize_with = "present")]
    relay_url: Option<Option<String>>,
}

/// Tells an absent field (`None`) from an explicit `null` (`Some(None)`).
fn present<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Option<Option<String>>, D::Error> {
    Option::<String>::deserialize(d).map(Some)
}

/// `{"every": 3600}` or `{"cron": "0 2 * * *", "tz": "Europe/Berlin"}`.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ScheduleBody {
    every: Option<i64>,
    cron: Option<String>,
    tz: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SignatureBody {
    scheme: String,
    header: Option<String>,
    secret: Option<String>,
}

#[derive(Serialize)]
pub struct CheckOut {
    id: Uuid,
    name: String,
    kind: String,
    status: &'static str,
    schedule: Value,
    grace: i32,
    max_runtime: Option<i32>,
    duration_alerts: bool,
    relay_url: Option<String>,
    /// Where the job (or the sending service) calls.
    url: String,
    signature: Option<Value>,
    channels: Vec<Uuid>,
    last_ping_at: Option<DateTime<Utc>>,
    next_expected_at: Option<DateTime<Utc>>,
    created_at: DateTime<Utc>,
}

impl CheckOut {
    fn new(check: Check, channels: Vec<Uuid>, base_url: &str) -> Self {
        let schedule = match &check.schedule_kind[..] {
            "cron" => json!({ "cron": check.cron_expr, "tz": check.tz }),
            _ => json!({ "every": check.period_secs }),
        };
        let base = base_url.trim_end_matches('/');
        let path = if check.is_webhook() { "w" } else { "p" };
        Self {
            url: format!("{base}/{path}/{}", check.token),
            signature: check.signature_scheme.as_ref().map(|scheme| {
                json!({ "scheme": scheme, "header": check.signature_header, "has_secret": check.has_secret })
            }),
            id: check.id,
            status: check.status.label(),
            schedule,
            grace: check.grace_secs,
            max_runtime: check.max_runtime_secs,
            duration_alerts: check.duration_alerts,
            relay_url: check.relay_url.clone(),
            last_ping_at: check.last_ping_at,
            next_expected_at: check.next_expected_at,
            created_at: check.created_at,
            name: check.name,
            kind: check.kind,
            channels,
        }
    }
}

/// The dashboard form's input for `body`, so both share one set of rules.
async fn to_input(
    state: &AppState,
    org: OrgId,
    body: CheckBody,
    existing: Option<&Check>,
) -> Result<CheckInput, ApiError> {
    if let (Some(check), Some(kind)) = (existing, &body.kind)
        && *kind != check.kind
    {
        return Err(ApiError::Invalid("A check's kind can't be changed.".into()));
    }
    let (schedule_kind, period_value, cron_expr, tz) = match body.schedule {
        ScheduleBody {
            every: Some(secs),
            cron: None,
            tz: None,
        } => ("period", secs.to_string(), String::new(), String::new()),
        ScheduleBody {
            every: None,
            cron: Some(expr),
            tz,
        } => ("cron", String::new(), expr, tz.unwrap_or_default()),
        _ => {
            return Err(ApiError::Invalid(
                "`schedule` is either {\"every\": seconds} or {\"cron\": \"…\", \"tz\": \"…\"}."
                    .into(),
            ));
        }
    };
    let max_runtime_minutes = match body.max_runtime {
        None => String::new(),
        Some(secs) if secs > 0 && secs % 60 == 0 => (secs / 60).to_string(),
        Some(_) => {
            return Err(ApiError::Invalid(
                "`max_runtime` is in seconds and must be a whole number of minutes.".into(),
            ));
        }
    };
    let channel_ids = match (body.channels, existing) {
        (Some(ids), _) => {
            check_channels(state, org, &ids).await?;
            ids
        }
        (None, Some(check)) => channels::ids_for_check(&state.db, org, check.id).await?,
        (None, None) => channels::options(&state.db, org)
            .await?
            .into_iter()
            .map(|c| c.id)
            .collect(),
    };
    let signature = body.signature;
    let relay_url = match (body.relay_url, existing) {
        (Some(url), _) => url.unwrap_or_default(),
        (None, Some(check)) => check.relay_url.clone().unwrap_or_default(),
        (None, None) => String::new(),
    };
    Ok(CheckInput {
        relay_url,
        name: body.name,
        kind: body.kind.unwrap_or_else(|| "heartbeat".into()),
        schedule_kind: schedule_kind.into(),
        period_value,
        period_unit: "seconds".into(),
        cron_expr,
        tz,
        grace_value: body.grace.unwrap_or(DEFAULT_GRACE_SECS).to_string(),
        grace_unit: "seconds".into(),
        max_runtime_minutes,
        channel_ids: channel_ids.iter().map(Uuid::to_string).collect(),
        signature_scheme: signature
            .as_ref()
            .map(|s| s.scheme.clone())
            .unwrap_or_default(),
        signature_header: signature
            .as_ref()
            .and_then(|s| s.header.clone())
            .unwrap_or_default(),
        signing_secret: signature.and_then(|s| s.secret).unwrap_or_default(),
        duration_alerts: if body.duration_alerts.unwrap_or(true) {
            "on"
        } else {
            ""
        }
        .into(),
    })
}

async fn load(state: &AppState, org: OrgId, raw_id: &str) -> Result<Check, ApiError> {
    checks::get(&state.db, org, parse_id(raw_id)?)
        .await?
        .ok_or(ApiError::NotFound)
}

async fn out(state: &AppState, org: OrgId, check: Check) -> Result<CheckOut, ApiError> {
    let channels = channels::ids_for_check(&state.db, org, check.id).await?;
    Ok(CheckOut::new(check, channels, &state.config.base_url))
}

pub async fn list(State(state): State<AppState>, key: ApiKey) -> Result<Response, ApiError> {
    let all = checks::list(&state.db, key.org).await?;
    let mut by_check: HashMap<Uuid, Vec<Uuid>> = channels::check_links(&state.db, key.org).await?;
    let items: Vec<CheckOut> = all
        .into_iter()
        .map(|c| {
            let ids = by_check.remove(&c.id).unwrap_or_default();
            CheckOut::new(c, ids, &state.config.base_url)
        })
        .collect();
    Ok(super::list(items).into_response())
}

pub async fn get(
    State(state): State<AppState>,
    key: ApiKey,
    Path(id): Path<String>,
) -> Result<Json<CheckOut>, ApiError> {
    let check = load(&state, key.org, &id).await?;
    Ok(Json(out(&state, key.org, check).await?))
}

pub async fn create(
    State(state): State<AppState>,
    key: WriteKey,
    Body(body): Body<CheckBody>,
) -> Result<Response, ApiError> {
    let input = to_input(&state, key.org, body, None).await?;
    let spec = parse_spec(
        &input,
        None,
        &state.secrets,
        state.config.allow_private_targets,
    )
    .map_err(ApiError::Invalid)?;
    let limits = orgs::limits(&state.db, key.org, &state.config.plan).await?;
    let id = created(
        checks::create(&state.db, key.org, &spec, limits.max_checks).await,
        "checks",
    )?;
    let check = checks::get(&state.db, key.org, id)
        .await?
        .ok_or(ApiError::NotFound)?;
    Ok((
        StatusCode::CREATED,
        Json(out(&state, key.org, check).await?),
    )
        .into_response())
}

/// Replaces the check's definition (`PUT`: send every field you want to keep,
/// except `channels` and a webhook's `secret`, which are kept when omitted).
pub async fn update(
    State(state): State<AppState>,
    key: WriteKey,
    Path(id): Path<String>,
    Body(body): Body<CheckBody>,
) -> Result<Json<CheckOut>, ApiError> {
    let existing = load(&state, key.org, &id).await?;
    let input = to_input(&state, key.org, body, Some(&existing)).await?;
    let spec = parse_spec(
        &input,
        Some(&existing),
        &state.secrets,
        state.config.allow_private_targets,
    )
    .map_err(ApiError::Invalid)?;
    if !checks::update(&state.db, key.org, existing.id, &spec).await? {
        return Err(ApiError::NotFound);
    }
    let check = load(&state, key.org, &id).await?;
    Ok(Json(out(&state, key.org, check).await?))
}

pub async fn delete(
    State(state): State<AppState>,
    key: WriteKey,
    Path(id): Path<String>,
) -> Result<StatusCode, ApiError> {
    if !checks::delete(&state.db, key.org, parse_id(&id)?).await? {
        return Err(ApiError::NotFound);
    }
    Ok(StatusCode::NO_CONTENT)
}

pub async fn pause(
    State(state): State<AppState>,
    key: WriteKey,
    Path(id): Path<String>,
) -> Result<Json<CheckOut>, ApiError> {
    let check = load(&state, key.org, &id).await?;
    checks::pause(&state.db, key.org, check.id).await?;
    let check = load(&state, key.org, &id).await?;
    Ok(Json(out(&state, key.org, check).await?))
}

pub async fn resume(
    State(state): State<AppState>,
    key: WriteKey,
    Path(id): Path<String>,
) -> Result<Json<CheckOut>, ApiError> {
    let check = load(&state, key.org, &id).await?;
    checks::resume(&state.db, key.org, check.id).await?;
    let check = load(&state, key.org, &id).await?;
    Ok(Json(out(&state, key.org, check).await?))
}

#[derive(Serialize)]
struct PingOut {
    id: i64,
    kind: String,
    exit_code: Option<i32>,
    duration_ms: Option<i32>,
    source_ip: Option<String>,
    user_agent: Option<String>,
    method: Option<String>,
    /// Why a webhook delivery was rejected.
    note: Option<String>,
    body: Option<String>,
    body_truncated: bool,
    created_at: DateTime<Utc>,
}

/// Newest first.
pub async fn pings(
    State(state): State<AppState>,
    key: ApiKey,
    Path(id): Path<String>,
    Query(paging): Query<Paging>,
) -> Result<Response, ApiError> {
    let check = load(&state, key.org, &id).await?;
    let items: Vec<PingOut> = pings::recent(&state.db, key.org, check.id, paging.limit()?)
        .await?
        .into_iter()
        .map(|p| PingOut {
            id: p.id,
            kind: p.kind,
            exit_code: p.exit_code,
            duration_ms: p.duration_ms,
            source_ip: p.source_ip,
            user_agent: p.user_agent,
            method: p.method,
            note: p.note,
            body: p.body,
            body_truncated: p.body_truncated,
            created_at: p.created_at,
        })
        .collect();
    Ok(super::list(items).into_response())
}
