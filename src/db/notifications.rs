//! The alert outbox. Rows are written in the same transaction as the state change
//! that caused them and drained by `worker::notifier`.

use chrono::{DateTime, Utc};
use serde_json::Value;
use sqlx::{PgConnection, PgPool};
use uuid::Uuid;

use crate::auth::OrgId;
use crate::notify::Alert;

/// How long a claimed row stays `sending` before another worker may retry it.
const LEASE_SECS: f64 = 120.0;

/// Queues `alert` for every verified channel attached to the check.
pub async fn enqueue_for_check(
    conn: &mut PgConnection,
    incident_id: Uuid,
    check_id: Uuid,
    alert: &Alert,
) -> sqlx::Result<u64> {
    let payload = serde_json::to_value(alert).expect("Alert serialises");
    let res = sqlx::query!(
        "INSERT INTO notifications (incident_id, channel_id, event, payload)
         SELECT $1, cc.channel_id, $3, $4
         FROM check_channels cc
         JOIN channels ch ON ch.id = cc.channel_id
         WHERE cc.check_id = $2 AND ch.verified_at IS NOT NULL
         ON CONFLICT (incident_id, channel_id, event) DO NOTHING",
        incident_id,
        check_id,
        alert.event.as_str(),
        payload,
    )
    .execute(conn)
    .await?;
    Ok(res.rows_affected())
}

/// Queues `alert` for every verified channel attached to the HTTP monitor.
pub async fn enqueue_for_monitor(
    conn: &mut PgConnection,
    incident_id: Uuid,
    monitor_id: Uuid,
    alert: &Alert,
) -> sqlx::Result<u64> {
    let payload = serde_json::to_value(alert).expect("Alert serialises");
    let res = sqlx::query!(
        "INSERT INTO notifications (incident_id, channel_id, event, payload)
         SELECT $1, mc.channel_id, $3, $4
         FROM monitor_channels mc
         JOIN channels ch ON ch.id = mc.channel_id
         WHERE mc.monitor_id = $2 AND ch.verified_at IS NOT NULL
         ON CONFLICT (incident_id, channel_id, event) DO NOTHING",
        incident_id,
        monitor_id,
        alert.event.as_str(),
        payload,
    )
    .execute(conn)
    .await?;
    Ok(res.rows_affected())
}

/// Queues a recovery for the channels that were told about this incident, and only
/// those: a channel attached or confirmed mid-incident shouldn't hear "back up" for an
/// outage it never heard about, and one detached mid-incident still hears it's over.
pub async fn enqueue_recovery(
    conn: &mut PgConnection,
    incident_id: Uuid,
    alert: &Alert,
) -> sqlx::Result<u64> {
    let payload = serde_json::to_value(alert).expect("Alert serialises");
    let res = sqlx::query!(
        "INSERT INTO notifications (incident_id, channel_id, event, payload)
         SELECT DISTINCT $1::uuid, channel_id, $2, $3::jsonb
         FROM notifications
         WHERE incident_id = $1 AND event IN ('down', 'fail')
         ON CONFLICT (incident_id, channel_id, event) DO NOTHING",
        incident_id,
        alert.event.as_str(),
        payload,
    )
    .execute(conn)
    .await?;
    Ok(res.rows_affected())
}

pub struct Claimed {
    pub id: i64,
    pub attempts: i32,
    pub payload: Value,
    pub channel_kind: String,
    pub config_enc: Vec<u8>,
}

/// Claims up to `limit` due notifications: marks them `sending`, counts the attempt
/// and leases them. Expired leases (a worker died mid-send) are claimable again.
pub async fn claim(db: &PgPool, limit: i64) -> sqlx::Result<Vec<Claimed>> {
    sqlx::query_as!(
        Claimed,
        r#"WITH due AS (
               SELECT id FROM notifications
               WHERE status IN ('pending', 'sending') AND next_attempt_at <= now()
               ORDER BY next_attempt_at
               LIMIT $1
               FOR UPDATE SKIP LOCKED
           )
           UPDATE notifications n
           SET status = 'sending', attempts = n.attempts + 1,
               next_attempt_at = now() + make_interval(secs => $2)
           FROM due, channels ch
           WHERE n.id = due.id AND ch.id = n.channel_id
           RETURNING n.id, n.attempts, n.payload, ch.kind AS channel_kind, ch.config_enc"#,
        limit,
        LEASE_SECS,
    )
    .fetch_all(db)
    .await
}

pub async fn mark_sent(db: &PgPool, id: i64) -> sqlx::Result<()> {
    sqlx::query!(
        "UPDATE notifications SET status = 'sent', sent_at = now(), last_error = NULL WHERE id = $1",
        id
    )
    .execute(db)
    .await?;
    Ok(())
}

pub async fn mark_retry(db: &PgPool, id: i64, delay_secs: i64, error: &str) -> sqlx::Result<()> {
    sqlx::query!(
        "UPDATE notifications
         SET status = 'pending', next_attempt_at = now() + make_interval(secs => $2), last_error = $3
         WHERE id = $1",
        id,
        delay_secs as f64,
        error,
    )
    .execute(db)
    .await?;
    Ok(())
}

pub async fn mark_dead(db: &PgPool, id: i64, error: &str) -> sqlx::Result<()> {
    sqlx::query!(
        "UPDATE notifications SET status = 'dead', last_error = $2 WHERE id = $1",
        id,
        error
    )
    .execute(db)
    .await?;
    Ok(())
}

pub struct Delivery {
    pub event: String,
    /// Name of the check or monitor the alert was about.
    pub source_name: Option<String>,
    pub status: String,
    pub attempts: i32,
    pub last_error: Option<String>,
    pub created_at: DateTime<Utc>,
    pub sent_at: Option<DateTime<Utc>>,
}

/// A channel's recent deliveries, newest first.
pub async fn recent_for_channel(
    db: &PgPool,
    org: OrgId,
    channel_id: Uuid,
    limit: i64,
) -> sqlx::Result<Vec<Delivery>> {
    sqlx::query_as!(
        Delivery,
        r#"SELECT n.event, COALESCE(n.payload->'source'->>'name', n.payload->>'check_name') AS source_name, n.status, n.attempts,
                  n.last_error, n.created_at, n.sent_at
           FROM notifications n
           JOIN channels ch ON ch.id = n.channel_id
           WHERE n.channel_id = $1 AND ch.org_id = $2
           ORDER BY n.created_at DESC
           LIMIT $3"#,
        channel_id,
        org.get(),
        limit,
    )
    .fetch_all(db)
    .await
}

/// Delivered and abandoned alerts are kept this long for the channel pages.
const RETENTION_DAYS: i32 = 90;

pub async fn purge(db: &PgPool) -> sqlx::Result<u64> {
    let res = sqlx::query!(
        "DELETE FROM notifications
         WHERE status IN ('sent', 'dead') AND created_at < now() - make_interval(days => $1)",
        RETENTION_DAYS,
    )
    .execute(db)
    .await?;
    Ok(res.rows_affected())
}
