//! Webhook relay: accepted deliveries to a webhook check are stored here and
//! forwarded to the org's own server by `worker::relay`, at least once and in
//! order. Each check's oldest unfinished delivery is the head of its queue; only
//! the head is ever attempted, so a struggling server gets one request at a time
//! and events arrive in the order they came in.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::{DateTime, Utc};
use serde_json::Value;
use sqlx::PgPool;
use uuid::Uuid;

use super::{incidents, notifications};
use crate::auth::OrgId;
use crate::domain::time::duration;
use crate::notify::{Alert, AlertEvent};

/// Bodies up to this size are relayed (larger requests are refused at ingest).
pub const MAX_BODY: usize = 1024 * 1024;
/// Undelivered events per check before new ones are refused with 503, so the
/// sender keeps them until the backlog clears.
pub const MAX_QUEUED: i64 = 10_000;
/// Failed attempts in a row before the "forwarding failing" alert.
pub const FAILURES_BEFORE_ALERT: i32 = 3;
/// An event still undelivered this long after it arrived is given up on.
const GIVE_UP_AFTER_HOURS: i64 = 24;
/// How long a claimed delivery stays leased; well above the forward timeout.
const LEASE_SECS: f64 = 60.0;
/// Finished deliveries (bodies included) are kept this long, for inspection and
/// redelivery.
pub const RETENTION_DAYS: i32 = 7;

/// Request headers not passed on: hop-by-hop, credentials, proxy bookkeeping,
/// and our own `x-monitor-*` (which the relay sets itself and a sender mustn't spoof).
pub fn forwardable(name: &str) -> bool {
    const DROP: &[&str] = &[
        "host",
        "content-length",
        "connection",
        "keep-alive",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
        "cookie",
        "authorization",
        "forwarded",
        "x-real-ip",
        "x-request-id",
    ];
    let name = name.to_ascii_lowercase();
    !DROP.contains(&name.as_str())
        && !name.starts_with("proxy-")
        && !name.starts_with("x-forwarded-")
        && !name.starts_with("x-monitor-")
}

/// A secret for signing forwarded requests.
pub fn new_secret() -> String {
    let bytes: [u8; 24] = rand::random();
    format!("rsec_{}", URL_SAFE_NO_PAD.encode(bytes))
}

/// 30 s, doubling per attempt, at most an hour.
pub fn backoff_secs(attempts: i32) -> i64 {
    let exp = attempts.clamp(1, 20) - 1;
    (30_i64 << exp).min(3600)
}

/// Whether the check's backlog is full.
pub async fn queue_full(db: &PgPool, check_id: Uuid) -> sqlx::Result<bool> {
    let queued = sqlx::query_scalar!(
        r#"SELECT count(*) AS "n!" FROM (
               SELECT 1 FROM relay_deliveries
               WHERE check_id = $1 AND status IN ('pending', 'sending')
               LIMIT $2
           ) q"#,
        check_id,
        MAX_QUEUED,
    )
    .fetch_one(db)
    .await?;
    Ok(queued >= MAX_QUEUED)
}

pub async fn enqueue(
    db: &PgPool,
    check_id: Uuid,
    method: &str,
    headers: &[(String, String)],
    body: &[u8],
    source_ip: Option<String>,
) -> sqlx::Result<i64> {
    let headers = serde_json::to_value(headers).expect("headers serialise");
    sqlx::query_scalar!(
        "INSERT INTO relay_deliveries (check_id, method, headers, body, source_ip)
         VALUES ($1, $2, $3, $4, $5::text::inet)
         RETURNING id",
        check_id,
        method,
        headers,
        body,
        source_ip,
    )
    .fetch_one(db)
    .await
}

/// A delivery claimed for one forwarding attempt.
pub struct Claimed {
    pub id: i64,
    pub check_id: Uuid,
    pub url: String,
    pub secret_enc: Option<Vec<u8>>,
    pub method: String,
    pub headers: Value,
    pub body: Vec<u8>,
    pub source_ip: Option<String>,
    /// Including this one.
    pub attempts: i32,
}

/// Claims up to `limit` queue heads that are due, leasing them so no other
/// worker attempts them meanwhile. A head whose lease expired (its worker died)
/// is due again.
pub async fn claim(db: &PgPool, limit: i64) -> sqlx::Result<Vec<Claimed>> {
    sqlx::query_as!(
        Claimed,
        r#"WITH heads AS (
               SELECT DISTINCT ON (check_id) id
               FROM relay_deliveries
               WHERE status IN ('pending', 'sending')
               ORDER BY check_id, id
           ),
           due AS (
               SELECT d.id FROM relay_deliveries d
               JOIN heads h ON h.id = d.id
               JOIN checks c ON c.id = d.check_id
               WHERE d.next_attempt_at <= now() AND c.relay_url IS NOT NULL
               ORDER BY d.next_attempt_at
               LIMIT $1
               FOR UPDATE OF d SKIP LOCKED
           )
           UPDATE relay_deliveries d
           SET status = 'sending', attempts = d.attempts + 1, last_attempt_at = now(),
               next_attempt_at = now() + make_interval(secs => $2)
           FROM due, checks c
           WHERE d.id = due.id AND c.id = d.check_id
           RETURNING d.id, d.check_id, c.relay_url AS "url!", c.relay_secret_enc AS secret_enc,
                     d.method, d.headers, d.body, host(d.source_ip) AS source_ip, d.attempts"#,
        limit,
        LEASE_SECS,
    )
    .fetch_all(db)
    .await
}

/// How one attempt went.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Attempt {
    Delivered { status: u16 },
    Failed { status: Option<u16>, error: String },
}

/// Records an attempt and, in the same transaction, the relay's health: a
/// success clears the failure count (and resolves an open "forwarding failing"
/// incident); the `FAILURES_BEFORE_ALERT`th failure in a row opens one.
pub async fn record(
    db: &PgPool,
    base_url: &str,
    claimed: &Claimed,
    attempt: &Attempt,
) -> sqlx::Result<()> {
    let mut tx = db.begin().await?;
    let check = sqlx::query!(
        "SELECT org_id, name, relay_failures, relay_url FROM checks WHERE id = $1 FOR UPDATE",
        claimed.check_id,
    )
    .fetch_optional(&mut *tx)
    .await?;
    let Some(check) = check else {
        return Ok(()); // Deleted meanwhile; its deliveries went with it.
    };

    match attempt {
        Attempt::Delivered { status } => {
            sqlx::query!(
                "UPDATE relay_deliveries
                 SET status = 'delivered', finished_at = now(), last_status = $2, last_error = NULL
                 WHERE id = $1",
                claimed.id,
                *status as i16,
            )
            .execute(&mut *tx)
            .await?;
            sqlx::query!(
                "UPDATE checks SET relay_failures = 0 WHERE id = $1",
                claimed.check_id
            )
            .execute(&mut *tx)
            .await?;
            if let Some(resolved) =
                incidents::resolve_relay_failing(&mut tx, claimed.check_id).await?
            {
                let mut alert =
                    Alert::for_check(AlertEvent::RelayUp, claimed.check_id, &check.name, base_url);
                alert.down_since = Some(resolved.started_at);
                notifications::enqueue_recovery(&mut tx, resolved.id, &alert).await?;
            }
        }
        Attempt::Failed { status, error } => {
            let row = sqlx::query!(
                r#"UPDATE relay_deliveries
                   SET status = CASE WHEN received_at < now() - make_interval(hours => $5) THEN 'failed' ELSE 'pending' END,
                       finished_at = CASE WHEN received_at < now() - make_interval(hours => $5) THEN now() END,
                       next_attempt_at = now() + make_interval(secs => $4),
                       last_status = $2, last_error = $3
                   WHERE id = $1
                   RETURNING status"#,
                claimed.id,
                status.map(|s| s as i16),
                error,
                backoff_secs(claimed.attempts) as f64,
                GIVE_UP_AFTER_HOURS as i32,
            )
            .fetch_one(&mut *tx)
            .await?;
            let failures = check.relay_failures + 1;
            sqlx::query!(
                "UPDATE checks SET relay_failures = $2 WHERE id = $1",
                claimed.check_id,
                failures,
            )
            .execute(&mut *tx)
            .await?;
            if row.status == "failed" {
                tracing::warn!(
                    delivery = claimed.id,
                    "relay gave up on a delivery after 24 hours"
                );
            }
            if failures >= FAILURES_BEFORE_ALERT {
                let queued: i64 = sqlx::query_scalar!(
                    r#"SELECT count(*) AS "n!" FROM relay_deliveries
                       WHERE check_id = $1 AND status IN ('pending', 'sending')"#,
                    claimed.check_id,
                )
                .fetch_one(&mut *tx)
                .await?;
                let host = check
                    .relay_url
                    .as_deref()
                    .and_then(|u| url::Url::parse(u).ok())
                    .and_then(|u| u.host_str().map(str::to_owned))
                    .unwrap_or_else(|| "your server".into());
                let detail = format!(
                    "{host} failed the last {failures} attempts ({error}). {queued} {} waiting; \
                     they're retried in order and kept for up to 24 hours.",
                    if queued == 1 {
                        "delivery is"
                    } else {
                        "deliveries are"
                    }
                );
                if let Some(incident) =
                    incidents::open_relay_failing(&mut tx, check.org_id, claimed.check_id, &detail)
                        .await?
                {
                    let mut alert = Alert::for_check(
                        AlertEvent::RelayDown,
                        claimed.check_id,
                        &check.name,
                        base_url,
                    );
                    alert.reason = Some("Forwarding failing".into());
                    alert.detail = Some(detail);
                    notifications::enqueue_for_check(&mut tx, incident, claimed.check_id, &alert)
                        .await?;
                }
            }
        }
    }
    tx.commit().await
}

/// Turning forwarding off (or deleting nothing but the URL) gives up on what's queued.
pub async fn abandon_queue(conn: &mut sqlx::PgConnection, check_id: Uuid) -> sqlx::Result<u64> {
    let res = sqlx::query!(
        "UPDATE relay_deliveries
         SET status = 'failed', finished_at = now(), last_error = 'Forwarding was turned off'
         WHERE check_id = $1 AND status IN ('pending', 'sending')",
        check_id,
    )
    .execute(conn)
    .await?;
    Ok(res.rows_affected())
}

// ───────────────────────────── dashboard ─────────────────────────────

pub struct DeliveryRow {
    pub id: i64,
    pub method: String,
    pub status: String,
    pub attempts: i32,
    pub last_status: Option<i16>,
    pub last_error: Option<String>,
    pub size: i32,
    pub received_at: DateTime<Utc>,
    pub finished_at: Option<DateTime<Utc>>,
    pub next_attempt_at: DateTime<Utc>,
}

pub async fn recent(
    db: &PgPool,
    org: OrgId,
    check_id: Uuid,
    limit: i64,
) -> sqlx::Result<Vec<DeliveryRow>> {
    sqlx::query_as!(
        DeliveryRow,
        r#"SELECT d.id, d.method, d.status, d.attempts, d.last_status, d.last_error,
                  octet_length(d.body) AS "size!", d.received_at, d.finished_at, d.next_attempt_at
           FROM relay_deliveries d
           JOIN checks c ON c.id = d.check_id
           WHERE d.check_id = $1 AND c.org_id = $2
           ORDER BY d.id DESC
           LIMIT $3"#,
        check_id,
        org.get(),
        limit,
    )
    .fetch_all(db)
    .await
}

pub struct Health {
    pub queued: i64,
    pub failures: i32,
    pub secret_enc: Option<Vec<u8>>,
}

pub async fn health(db: &PgPool, org: OrgId, check_id: Uuid) -> sqlx::Result<Option<Health>> {
    sqlx::query_as!(
        Health,
        r#"SELECT (SELECT count(*) FROM relay_deliveries d
                   WHERE d.check_id = c.id AND d.status IN ('pending', 'sending')) AS "queued!",
                  c.relay_failures AS failures, c.relay_secret_enc AS secret_enc
           FROM checks c WHERE c.id = $1 AND c.org_id = $2"#,
        check_id,
        org.get(),
    )
    .fetch_optional(db)
    .await
}

/// Queues a finished delivery again, at the back of the queue so order holds
/// for everything after it. Returns the new delivery's id.
pub async fn redeliver(
    db: &PgPool,
    org: OrgId,
    check_id: Uuid,
    id: i64,
) -> sqlx::Result<Option<i64>> {
    sqlx::query_scalar!(
        "INSERT INTO relay_deliveries (check_id, method, headers, body, source_ip)
         SELECT d.check_id, d.method, d.headers, d.body, d.source_ip
         FROM relay_deliveries d
         JOIN checks c ON c.id = d.check_id
         WHERE d.id = $1 AND d.check_id = $2 AND c.org_id = $3 AND c.relay_url IS NOT NULL
           AND d.status IN ('delivered', 'failed')
         RETURNING id",
        id,
        check_id,
        org.get(),
    )
    .fetch_optional(db)
    .await
}

/// Gives up on the head of a stuck queue so the rest can go.
pub async fn skip(db: &PgPool, org: OrgId, check_id: Uuid, id: i64) -> sqlx::Result<bool> {
    let res = sqlx::query!(
        "UPDATE relay_deliveries d
         SET status = 'failed', finished_at = now(), last_error = 'Skipped'
         FROM checks c
         WHERE d.id = $1 AND d.check_id = $2 AND c.id = d.check_id AND c.org_id = $3
           AND d.status IN ('pending', 'sending')",
        id,
        check_id,
        org.get(),
    )
    .execute(db)
    .await?;
    Ok(res.rows_affected() == 1)
}

/// Deletes finished deliveries older than the retention period.
pub async fn purge(db: &PgPool) -> sqlx::Result<u64> {
    let res = sqlx::query!(
        "DELETE FROM relay_deliveries WHERE finished_at < now() - make_interval(days => $1)",
        RETENTION_DAYS,
    )
    .execute(db)
    .await?;
    Ok(res.rows_affected())
}

/// "in 4m", for when the head will be tried again.
pub fn retry_text(at: DateTime<Utc>, now: DateTime<Utc>) -> String {
    let ms = (at - now).num_milliseconds();
    if ms <= 0 {
        "now".into()
    } else {
        format!("in {}", duration(ms))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn headers_worth_forwarding() {
        for keep in [
            "Content-Type",
            "Stripe-Signature",
            "X-Hub-Signature-256",
            "User-Agent",
            "X-GitHub-Event",
        ] {
            assert!(forwardable(keep), "{keep}");
        }
        for drop in [
            "Host",
            "Content-Length",
            "Cookie",
            "Authorization",
            "X-Forwarded-For",
            "Proxy-Authorization",
            "X-Monitor-Signature",
            "x-request-id",
        ] {
            assert!(!forwardable(drop), "{drop}");
        }
    }

    #[test]
    fn backoff_doubles_to_an_hour() {
        assert_eq!(backoff_secs(1), 30);
        assert_eq!(backoff_secs(2), 60);
        assert_eq!(backoff_secs(8), 3600);
        assert_eq!(backoff_secs(50), 3600);
    }

    #[test]
    fn secrets_are_random() {
        let a = new_secret();
        assert!(a.starts_with("rsec_"));
        assert_ne!(a, new_secret());
    }
}
