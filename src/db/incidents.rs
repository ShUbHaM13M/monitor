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
/// Returns whether a new incident was created.
pub async fn open_for_check(
    conn: &mut PgConnection,
    org_id: Uuid,
    check_id: Uuid,
    reason: &str,
    detail: &str,
    cause_ping_id: Option<i64>,
) -> sqlx::Result<bool> {
    let res = sqlx::query!(
        "INSERT INTO incidents (id, org_id, check_id, reason, detail, cause_ping_id)
         VALUES ($1, $2, $3, $4, $5, $6)
         ON CONFLICT (check_id) WHERE resolved_at IS NULL DO NOTHING",
        Uuid::now_v7(),
        org_id,
        check_id,
        reason,
        detail,
        cause_ping_id,
    )
    .execute(conn)
    .await?;
    Ok(res.rows_affected() == 1)
}

/// Resolves the check's open incident, if any. Returns whether one was resolved.
pub async fn resolve_for_check(conn: &mut PgConnection, check_id: Uuid) -> sqlx::Result<bool> {
    let res = sqlx::query!(
        "UPDATE incidents SET resolved_at = now()
         WHERE check_id = $1 AND resolved_at IS NULL",
        check_id,
    )
    .execute(conn)
    .await?;
    Ok(res.rows_affected() == 1)
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
