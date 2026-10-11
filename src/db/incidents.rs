use chrono::{DateTime, Utc};
use sqlx::{PgConnection, PgPool};
use uuid::Uuid;

use crate::auth::OrgId;

pub struct Incident {
    pub id: Uuid,
    pub reason: String,
    pub detail: Option<String>,
    pub started_at: DateTime<Utc>,
    pub resolved_at: Option<DateTime<Utc>>,
}

/// Opens an incident for a check unless one is already open.
/// Returns the new incident's id, or `None` if one was already open.
pub async fn open_for_check(
    conn: &mut PgConnection,
    org_id: Uuid,
    check_id: Uuid,
    reason: &str,
    detail: &str,
    cause_ping_id: Option<i64>,
) -> sqlx::Result<Option<Uuid>> {
    sqlx::query_scalar!(
        "INSERT INTO incidents (id, org_id, check_id, reason, detail, cause_ping_id)
         VALUES ($1, $2, $3, $4, $5, $6)
         ON CONFLICT (check_id) WHERE resolved_at IS NULL DO NOTHING
         RETURNING id",
        Uuid::now_v7(),
        org_id,
        check_id,
        reason,
        detail,
        cause_ping_id,
    )
    .fetch_optional(conn)
    .await
}

pub struct Resolved {
    pub id: Uuid,
    pub started_at: DateTime<Utc>,
}

/// Resolves the check's open incident, if any.
pub async fn resolve_for_check(
    conn: &mut PgConnection,
    check_id: Uuid,
) -> sqlx::Result<Option<Resolved>> {
    sqlx::query_as!(
        Resolved,
        "UPDATE incidents SET resolved_at = now()
         WHERE check_id = $1 AND resolved_at IS NULL
         RETURNING id, started_at",
        check_id,
    )
    .fetch_optional(conn)
    .await
}

/// Opens an incident for an HTTP monitor unless one is already open.
pub async fn open_for_monitor(
    conn: &mut PgConnection,
    org_id: Uuid,
    monitor_id: Uuid,
    reason: &str,
    detail: &str,
) -> sqlx::Result<Option<Uuid>> {
    sqlx::query_scalar!(
        "INSERT INTO incidents (id, org_id, monitor_id, reason, detail)
         VALUES ($1, $2, $3, $4, $5)
         ON CONFLICT (monitor_id) WHERE resolved_at IS NULL DO NOTHING
         RETURNING id",
        Uuid::now_v7(),
        org_id,
        monitor_id,
        reason,
        detail,
    )
    .fetch_optional(conn)
    .await
}

pub async fn resolve_for_monitor(
    conn: &mut PgConnection,
    monitor_id: Uuid,
) -> sqlx::Result<Option<Resolved>> {
    sqlx::query_as!(
        Resolved,
        "UPDATE incidents SET resolved_at = now()
         WHERE monitor_id = $1 AND resolved_at IS NULL
         RETURNING id, started_at",
        monitor_id,
    )
    .fetch_optional(conn)
    .await
}

pub async fn recent_for_monitor(
    db: &PgPool,
    org: OrgId,
    monitor_id: Uuid,
    limit: i64,
) -> sqlx::Result<Vec<Incident>> {
    sqlx::query_as!(
        Incident,
        "SELECT id, reason, detail, started_at, resolved_at
         FROM incidents
         WHERE monitor_id = $1 AND org_id = $2
         ORDER BY started_at DESC
         LIMIT $3",
        monitor_id,
        org.get(),
        limit,
    )
    .fetch_all(db)
    .await
}

pub async fn recent_for_check(
    db: &PgPool,
    org: OrgId,
    check_id: Uuid,
    limit: i64,
) -> sqlx::Result<Vec<Incident>> {
    sqlx::query_as!(
        Incident,
        "SELECT id, reason, detail, started_at, resolved_at
         FROM incidents
         WHERE check_id = $1 AND org_id = $2
         ORDER BY started_at DESC
         LIMIT $3",
        check_id,
        org.get(),
        limit,
    )
    .fetch_all(db)
    .await
}
