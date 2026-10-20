//! Org-wide reads: alert channels and incidents.

use axum::extract::{Query, State};
use axum::response::{IntoResponse, Response};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use uuid::Uuid;

use super::{ApiError, ApiKey};
use crate::db::channels;
use crate::db::incidents::{self, IncidentState};
use crate::web::AppState;

#[derive(Serialize)]
struct ChannelOut {
    id: Uuid,
    kind: String,
    name: String,
    /// Safe description; secrets (webhook URLs, signing keys) are never returned.
    summary: String,
    verified: bool,
    created_at: DateTime<Utc>,
}

/// Channels are created in the dashboard (some need a confirmation step); the
/// API lists them so checks and monitors can refer to them by id.
pub async fn channels(State(state): State<AppState>, key: ApiKey) -> Result<Response, ApiError> {
    let items: Vec<ChannelOut> = channels::list(&state.db, key.org)
        .await?
        .iter()
        .map(|c| ChannelOut {
            id: c.id,
            kind: c.kind.clone(),
            name: c.name.clone(),
            summary: crate::web::channels::summary(&state, c),
            verified: c.verified_at.is_some(),
            created_at: c.created_at,
        })
        .collect();
    Ok(super::list(items).into_response())
}

#[derive(Deserialize, Default)]
#[serde(default)]
pub struct IncidentQuery {
    /// "open", "resolved", or omitted for both.
    state: Option<String>,
    limit: Option<i64>,
    /// Paging: the `started_at` and `id` of the last incident already seen.
    before: Option<DateTime<Utc>>,
    before_id: Option<Uuid>,
}

#[derive(Serialize)]
struct IncidentOut {
    id: Uuid,
    reason: String,
    detail: Option<String>,
    started_at: DateTime<Utc>,
    resolved_at: Option<DateTime<Utc>>,
    target: Value,
}

/// Newest first.
pub async fn incidents(
    State(state): State<AppState>,
    key: ApiKey,
    Query(query): Query<IncidentQuery>,
) -> Result<Response, ApiError> {
    let which = match query.state.as_deref() {
        None => IncidentState::All,
        Some("open") => IncidentState::Open,
        Some("resolved") => IncidentState::Resolved,
        Some(_) => {
            return Err(ApiError::Invalid(
                "`state` is \"open\" or \"resolved\".".into(),
            ));
        }
    };
    let limit = super::Paging { limit: query.limit }.limit()?;
    let before = match (query.before, query.before_id) {
        (Some(at), Some(id)) => Some((at, id)),
        (None, None) => None,
        _ => {
            return Err(ApiError::Invalid(
                "Send `before` and `before_id` together.".into(),
            ));
        }
    };
    let items: Vec<IncidentOut> = incidents::list_for_org(&state.db, key.org, which, before, limit)
        .await?
        .into_iter()
        .map(|i| IncidentOut {
            target: match (i.check_id, i.monitor_id) {
                (Some(id), _) => json!({ "type": "check", "id": id, "name": i.target_name }),
                (_, id) => json!({ "type": "monitor", "id": id, "name": i.target_name }),
            },
            id: i.id,
            reason: i.reason,
            detail: i.detail,
            started_at: i.started_at,
            resolved_at: i.resolved_at,
        })
        .collect();
    Ok(super::list(items).into_response())
}
