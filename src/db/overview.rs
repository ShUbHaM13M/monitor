//! Org-wide summaries for the overview page and the nav health badge.

use chrono::{DateTime, Utc};
use sqlx::PgPool;
use uuid::Uuid;

use crate::auth::OrgId;

/// `(status, count)` for the org's heartbeat and webhook checks.
pub async fn check_counts(db: &PgPool, org: OrgId) -> sqlx::Result<Vec<(String, i64)>> {
    let rows = sqlx::query!(
        r#"SELECT status, count(*) AS "count!" FROM checks WHERE org_id = $1 GROUP BY status"#,
        org.get(),
    )
    .fetch_all(db)
    .await?;
    Ok(rows.into_iter().map(|r| (r.status, r.count)).collect())
}

/// `(status, count)` for the org's HTTP monitors.
pub async fn monitor_counts(db: &PgPool, org: OrgId) -> sqlx::Result<Vec<(String, i64)>> {
    let rows = sqlx::query!(
        r#"SELECT status, count(*) AS "count!" FROM http_monitors WHERE org_id = $1 GROUP BY status"#,
        org.get(),
    )
    .fetch_all(db)
    .await?;
    Ok(rows.into_iter().map(|r| (r.status, r.count)).collect())
}

/// Checks plus monitors that are down right now.
pub async fn down_count(db: &PgPool, org: OrgId) -> sqlx::Result<i64> {
    sqlx::query_scalar!(
        r#"SELECT (SELECT count(*) FROM checks WHERE org_id = $1 AND status = 'down')
                + (SELECT count(*) FROM http_monitors WHERE org_id = $1 AND status = 'down')
                AS "count!""#,
        org.get(),
    )
    .fetch_one(db)
    .await
}

pub struct ChannelHealth {
    pub total: i64,
    /// Waiting for the recipient to confirm; gets no alerts meanwhile.
    pub unverified: i64,
}

pub async fn channel_health(db: &PgPool, org: OrgId) -> sqlx::Result<ChannelHealth> {
    sqlx::query_as!(
        ChannelHealth,
        r#"SELECT count(*) AS "total!", count(*) FILTER (WHERE verified_at IS NULL) AS "unverified!"
           FROM channels WHERE org_id = $1"#,
        org.get(),
    )
    .fetch_one(db)
    .await
}

/// A channel whose alerts recently gave up after all retries.
pub struct FailingChannel {
    pub id: Uuid,
    pub name: String,
    pub kind: String,
    pub failed: i64,
    pub last_error: Option<String>,
    pub last_at: DateTime<Utc>,
}

pub async fn failing_channels(
    db: &PgPool,
    org: OrgId,
    hours: i32,
) -> sqlx::Result<Vec<FailingChannel>> {
    sqlx::query_as!(
        FailingChannel,
        r#"SELECT ch.id, ch.name, ch.kind, count(*) AS "failed!",
                  (array_agg(n.last_error ORDER BY n.created_at DESC))[1] AS last_error,
                  max(n.created_at) AS "last_at!"
           FROM channels ch
           JOIN notifications n ON n.channel_id = ch.id
           WHERE ch.org_id = $1 AND n.status = 'dead'
             AND n.created_at > now() - make_interval(hours => $2)
           GROUP BY ch.id
           ORDER BY max(n.created_at) DESC"#,
        org.get(),
        hours,
    )
    .fetch_all(db)
    .await
}
