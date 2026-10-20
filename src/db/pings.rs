use std::net::IpAddr;

use chrono::{DateTime, TimeDelta, Utc};
use serde_json::Value;
use sqlx::PgPool;
use uuid::Uuid;

use super::checks::{CheckStatus, deadlines};
use super::{incidents, notifications};
use crate::auth::OrgId;
use crate::domain::anomaly;
use crate::domain::ping::{Outcome, Signal};
use crate::domain::schedule::Schedule;
use crate::domain::time::duration;
use crate::notify::alert::log_tail;
use crate::notify::{Alert, AlertEvent};

pub struct Ping {
    pub id: i64,
    pub kind: String,
    pub exit_code: Option<i32>,
    pub duration_ms: Option<i32>,
    pub source_ip: Option<String>,
    pub user_agent: Option<String>,
    pub body: Option<String>,
    pub created_at: DateTime<Utc>,
    pub method: Option<String>,
    pub headers: Option<Value>,
    pub body_truncated: bool,
    pub note: Option<String>,
}

pub async fn recent(
    db: &PgPool,
    org: OrgId,
    check_id: Uuid,
    limit: i64,
) -> sqlx::Result<Vec<Ping>> {
    sqlx::query_as!(
        Ping,
        r#"SELECT p.id, p.kind, p.exit_code, p.duration_ms, host(p.source_ip) AS source_ip,
                  p.user_agent, p.body, p.created_at, p.method, p.headers, p.body_truncated, p.note
           FROM pings p
           JOIN checks c ON c.id = p.check_id
           WHERE p.check_id = $1 AND c.org_id = $2
           ORDER BY p.created_at DESC, p.id DESC
           LIMIT $3"#,
        check_id,
        org.get(),
        limit,
    )
    .fetch_all(db)
    .await
}

/// Durations (ms) of the check's latest successful timed runs, newest first.
pub async fn recent_run_durations(
    db: &PgPool,
    org: OrgId,
    check_id: Uuid,
    limit: i64,
) -> sqlx::Result<Vec<i64>> {
    sqlx::query_scalar!(
        r#"SELECT p.duration_ms::bigint AS "ms!"
           FROM pings p
           JOIN checks c ON c.id = p.check_id
           WHERE p.check_id = $1 AND c.org_id = $2 AND p.duration_ms IS NOT NULL
             AND (p.kind = 'success' OR (p.kind = 'exit' AND p.exit_code = 0))
           ORDER BY p.created_at DESC
           LIMIT $3"#,
        check_id,
        org.get(),
        limit,
    )
    .fetch_all(db)
    .await
}

#[derive(Default)]
pub struct PingMeta {
    pub source_ip: Option<IpAddr>,
    pub user_agent: Option<String>,
    pub body: Option<String>,
    /// Webhook deliveries only.
    pub method: Option<String>,
    pub headers: Option<Value>,
    pub body_truncated: bool,
}

/// Which endpoint a token arrived on. A token only works on its own endpoint, so
/// the ping URL can't be used to bypass a webhook's signature check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Endpoint {
    /// `/p/{token}`: heartbeat checks.
    Ping,
    /// `/w/{token}`: inbound webhook monitors.
    Webhook,
}

impl Endpoint {
    fn check_kind(self) -> &'static str {
        match self {
            Self::Ping => "heartbeat",
            Self::Webhook => "webhook",
        }
    }
}

pub struct WebhookTarget {
    pub id: Uuid,
    pub signature_scheme: Option<String>,
    pub signature_header: Option<String>,
    pub signing_secret_enc: Option<Vec<u8>>,
}

/// The signature settings of a webhook monitor, by token.
pub async fn webhook_target(db: &PgPool, token: &str) -> sqlx::Result<Option<WebhookTarget>> {
    sqlx::query_as!(
        WebhookTarget,
        "SELECT id, signature_scheme, signature_header, signing_secret_enc
         FROM checks WHERE token = $1 AND kind = 'webhook'",
        token,
    )
    .fetch_optional(db)
    .await
}

/// Logs a delivery that failed verification. It doesn't count as a heartbeat.
pub async fn record_rejected(
    db: &PgPool,
    check_id: Uuid,
    meta: PingMeta,
    reason: &str,
) -> sqlx::Result<()> {
    sqlx::query!(
        "INSERT INTO pings (check_id, kind, source_ip, user_agent, body, method, headers,
                            body_truncated, note)
         VALUES ($1, 'rejected', $2::text::inet, $3, $4, $5, $6, $7, $8)",
        check_id,
        meta.source_ip.map(|ip| ip.to_string()),
        meta.user_agent,
        meta.body,
        meta.method,
        meta.headers,
        meta.body_truncated,
        reason,
    )
    .execute(db)
    .await?;
    Ok(())
}

/// Records a ping and applies it to the check, in one transaction. Looked up by
/// token, which is the credential here, so this is deliberately not org-scoped.
/// Returns `false` for an unknown token, or one that belongs to the other endpoint.
pub async fn record(
    db: &PgPool,
    base_url: &str,
    endpoint: Endpoint,
    token: &str,
    signal: Signal,
    meta: PingMeta,
) -> anyhow::Result<bool> {
    let mut tx = db.begin().await?;
    // The row lock serialises concurrent pings for one check, and makes the
    // scheduler (FOR UPDATE SKIP LOCKED) skip this check until we commit.
    let check = sqlx::query!(
        r#"SELECT id, org_id, name, status AS "status: CheckStatus", schedule_kind, cron_expr, tz,
                  period_secs, grace_secs, max_runtime_secs, last_start_at, alert_after,
                  duration_alerts, now() AS "now!"
           FROM checks WHERE token = $1 AND kind = $2 FOR UPDATE"#,
        token,
        endpoint.check_kind(),
    )
    .fetch_optional(&mut *tx)
    .await?;
    let Some(check) = check else {
        return Ok(false);
    };
    let now = check.now;

    let duration_ms = match (signal.outcome(), check.status, check.last_start_at) {
        (Outcome::Succeeded | Outcome::Failed, CheckStatus::Started, Some(started)) => {
            Some((now - started).num_milliseconds().clamp(0, i32::MAX.into()) as i32)
        }
        _ => None,
    };
    let ping_id = sqlx::query_scalar!(
        "INSERT INTO pings (check_id, kind, exit_code, duration_ms, source_ip, user_agent, body,
                            created_at, method, headers, body_truncated)
         VALUES ($1, $2, $3, $4, $5::text::inet, $6, $7, $8, $9, $10, $11)
         RETURNING id",
        check.id,
        signal.kind(),
        signal.exit_code(),
        duration_ms,
        meta.source_ip.map(|ip| ip.to_string()),
        meta.user_agent,
        meta.body.as_deref(),
        now,
        meta.method,
        meta.headers,
        meta.body_truncated,
    )
    .fetch_one(&mut *tx)
    .await?;

    // Paused checks keep a log of pings but don't change state.
    if check.status == CheckStatus::Paused {
        tx.commit().await?;
        return Ok(true);
    }

    match signal.outcome() {
        Outcome::Started => {
            let alert_after = check
                .max_runtime_secs
                .map(|secs| now + TimeDelta::seconds(secs.into()))
                .or(check.alert_after);
            sqlx::query!(
                "UPDATE checks
                 SET status = 'started', last_start_at = $2, alert_after = $3, updated_at = now()
                 WHERE id = $1",
                check.id,
                now,
                alert_after,
            )
            .execute(&mut *tx)
            .await?;
        }
        outcome @ (Outcome::Succeeded | Outcome::Failed) => {
            let schedule = Schedule::from_db(
                &check.schedule_kind,
                check.cron_expr.as_deref(),
                check.tz.as_deref(),
                check.period_secs,
            )?;
            let (next_expected_at, alert_after) = deadlines(&schedule, check.grace_secs, now);
            let status = if outcome == Outcome::Succeeded {
                CheckStatus::Up
            } else {
                CheckStatus::Down
            };
            sqlx::query!(
                "UPDATE checks
                 SET status = $2, last_ping_at = $3, last_start_at = NULL,
                     next_expected_at = $4, alert_after = $5, updated_at = now()
                 WHERE id = $1",
                check.id,
                status as CheckStatus,
                now,
                next_expected_at,
                alert_after,
            )
            .execute(&mut *tx)
            .await?;

            if outcome == Outcome::Succeeded {
                if let Some(resolved) = incidents::resolve_for_check(&mut tx, check.id).await? {
                    let mut alert =
                        Alert::for_check(AlertEvent::Up, check.id, &check.name, base_url);
                    alert.occurred_at = now;
                    alert.down_since = Some(resolved.started_at);
                    notifications::enqueue_recovery(&mut tx, resolved.id, &alert).await?;
                }
                if let (true, Some(took)) = (check.duration_alerts, duration_ms) {
                    let history = sqlx::query_scalar!(
                        r#"SELECT duration_ms::bigint AS "ms!" FROM pings
                           WHERE check_id = $1 AND id <> $2 AND duration_ms IS NOT NULL
                             AND (kind = 'success' OR (kind = 'exit' AND exit_code = 0))
                           ORDER BY created_at DESC
                           LIMIT $3"#,
                        check.id,
                        ping_id,
                        anomaly::HISTORY,
                    )
                    .fetch_all(&mut *tx)
                    .await?;
                    if let Some(found) = anomaly::judge(&history, took.into()) {
                        let detail = format!(
                            "This run took {}; it usually takes about {} (median of the last {} runs).",
                            duration(took.into()),
                            duration(found.median_ms()),
                            history.len(),
                        );
                        let incident = incidents::record_instant_for_check(
                            &mut tx,
                            check.org_id,
                            check.id,
                            found.reason(),
                            &detail,
                            ping_id,
                        )
                        .await?;
                        let mut alert =
                            Alert::for_check(AlertEvent::Anomaly, check.id, &check.name, base_url);
                        alert.occurred_at = now;
                        alert.reason = Some(found.label().into());
                        alert.detail = Some(detail);
                        notifications::enqueue_for_check(&mut tx, incident, check.id, &alert)
                            .await?;
                    }
                }
            } else {
                let detail = match signal {
                    Signal::Exit(code) => format!("Job exited with code {code}."),
                    _ => "Job reported a failure.".to_owned(),
                };
                let opened = incidents::open_for_check(
                    &mut tx,
                    check.org_id,
                    check.id,
                    "failed",
                    &detail,
                    Some(ping_id),
                )
                .await?;
                if let Some(incident_id) = opened {
                    let mut alert =
                        Alert::for_check(AlertEvent::Fail, check.id, &check.name, base_url);
                    alert.occurred_at = now;
                    alert.reason = Some("Job failed".into());
                    alert.detail = Some(detail);
                    alert.log_tail = meta.body.as_deref().map(log_tail).filter(|t| !t.is_empty());
                    notifications::enqueue_for_check(&mut tx, incident_id, check.id, &alert)
                        .await?;
                }
            }
        }
    }

    tx.commit().await?;
    Ok(true)
}

/// Each check keeps at most this many pings…
pub const KEEP_PER_CHECK: i64 = 100;
/// …and none older than this. Pings that caused an incident are kept as long
/// as the incident, so its "cause" stays viewable.
pub const RETENTION_DAYS: i32 = 30;

/// Deletes pings beyond the per-check cap or the age limit. Returns how many.
pub async fn purge(db: &PgPool) -> sqlx::Result<u64> {
    let old = sqlx::query!(
        "DELETE FROM pings p
         WHERE p.created_at < now() - make_interval(days => $1)
           AND NOT EXISTS (SELECT 1 FROM incidents i WHERE i.cause_ping_id = p.id)",
        RETENTION_DAYS,
    )
    .execute(db)
    .await?
    .rows_affected();
    // For each check, find its (KEEP_PER_CHECK + 1)th newest ping and delete it
    // and everything older. Uses the (check_id, created_at DESC) index.
    let excess = sqlx::query!(
        "DELETE FROM pings p
         USING checks c
         CROSS JOIN LATERAL (
             SELECT created_at, id FROM pings
             WHERE check_id = c.id
             ORDER BY created_at DESC, id DESC
             OFFSET $1 LIMIT 1
         ) cut
         WHERE p.check_id = c.id
           AND (p.created_at, p.id) <= (cut.created_at, cut.id)
           AND NOT EXISTS (SELECT 1 FROM incidents i WHERE i.cause_ping_id = p.id)",
        KEEP_PER_CHECK,
    )
    .execute(db)
    .await?
    .rows_affected();
    Ok(old + excess)
}
