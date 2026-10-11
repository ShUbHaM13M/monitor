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

/// An incident with the check or monitor it belongs to, for org-wide lists.
pub struct OrgIncident {
    pub id: Uuid,
    pub reason: String,
    pub detail: Option<String>,
    pub started_at: DateTime<Utc>,
    pub resolved_at: Option<DateTime<Utc>>,
    pub check_id: Option<Uuid>,
    pub monitor_id: Option<Uuid>,
    pub target_name: String,
    /// "heartbeat" or "webhook" for checks, "http" for monitors.
    pub target_kind: String,
    pub target_status: String,
}

/// Which incidents `list_for_org` returns.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IncidentState {
    All,
    Open,
    Resolved,
}

/// Newest first. `before` is the `(started_at, id)` of the last incident on
/// the previous page.
pub async fn list_for_org(
    db: &PgPool,
    org: OrgId,
    state: IncidentState,
    before: Option<(DateTime<Utc>, Uuid)>,
    limit: i64,
) -> sqlx::Result<Vec<OrgIncident>> {
    let open = match state {
        IncidentState::All => None,
        IncidentState::Open => Some(true),
        IncidentState::Resolved => Some(false),
    };
    let (before_at, before_id) = before.unzip();
    sqlx::query_as!(
        OrgIncident,
        r#"SELECT i.id, i.reason, i.detail, i.started_at, i.resolved_at, i.check_id, i.monitor_id,
                  COALESCE(c.name, m.name) AS "target_name!",
                  COALESCE(c.kind, 'http') AS "target_kind!",
                  COALESCE(c.status, m.status) AS "target_status!"
           FROM incidents i
           LEFT JOIN checks c ON c.id = i.check_id
           LEFT JOIN http_monitors m ON m.id = i.monitor_id
           WHERE i.org_id = $1
             AND ($2::bool IS NULL OR (i.resolved_at IS NULL) = $2)
             AND ($3::timestamptz IS NULL OR (i.started_at, i.id) < ($3, $4::uuid))
           ORDER BY i.started_at DESC, i.id DESC
           LIMIT $5"#,
        org.get(),
        open,
        before_at,
        before_id,
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
