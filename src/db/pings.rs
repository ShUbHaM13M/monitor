use std::net::IpAddr;

use chrono::{DateTime, TimeDelta, Utc};
use sqlx::PgPool;
use uuid::Uuid;

use super::checks::{CheckStatus, deadlines};
use super::{incidents, notifications};
use crate::auth::OrgId;
use crate::domain::ping::{Outcome, Signal};
use crate::domain::schedule::Schedule;
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
                  p.user_agent, p.body, p.created_at
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

pub struct PingMeta {
    pub source_ip: Option<IpAddr>,
    pub user_agent: Option<String>,
    pub body: Option<String>,
}

/// Records a ping and applies it to the check, in one transaction. Looked up by
/// token, which is the credential here, so this is deliberately not org-scoped.
/// Returns `false` for an unknown token.
pub async fn record(
    db: &PgPool,
    base_url: &str,
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
                  now() AS "now!"
           FROM checks WHERE token = $1 FOR UPDATE"#,
        token,
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
        "INSERT INTO pings (check_id, kind, exit_code, duration_ms, source_ip, user_agent, body, created_at)
         VALUES ($1, $2, $3, $4, $5::text::inet, $6, $7, $8)
         RETURNING id",
        check.id,
        signal.kind(),
        signal.exit_code(),
        duration_ms,
        meta.source_ip.map(|ip| ip.to_string()),
        meta.user_agent,
        meta.body.as_deref(),
        now,
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
