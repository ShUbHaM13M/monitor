use std::collections::HashMap;

use chrono::{DateTime, Utc};
use sqlx::PgPool;
use uuid::Uuid;

use super::{channels, incidents, notifications};
use crate::auth::OrgId;
use crate::domain::uptime::{self, Event, MonitorStatus, Outcome};
use crate::notify::{Alert, AlertEvent};

/// Raw results are kept this long; hourly rollups much longer.
const RESULT_RETENTION_DAYS: i32 = 7;
const ROLLUP_RETENTION_DAYS: i32 = 90;

#[derive(Debug, Clone, Copy, PartialEq, Eq, sqlx::Type)]
#[sqlx(type_name = "text", rename_all = "lowercase")]
pub enum MonitorState {
    New,
    Up,
    Down,
    Paused,
}

impl MonitorState {
    pub fn label(self) -> &'static str {
        match self {
            Self::New => "new",
            Self::Up => "up",
            Self::Down => "down",
            Self::Paused => "paused",
        }
    }

    pub fn css(self) -> &'static str {
        match self {
            Self::Up => "pill-up",
            Self::Down => "pill-down",
            Self::New | Self::Paused => "pill-muted",
        }
    }

    fn domain(self) -> MonitorStatus {
        match self {
            Self::Up => MonitorStatus::Up,
            Self::Down => MonitorStatus::Down,
            Self::New | Self::Paused => MonitorStatus::New,
        }
    }

    fn from_domain(status: MonitorStatus) -> Self {
        match status {
            MonitorStatus::New => Self::New,
            MonitorStatus::Up => Self::Up,
            MonitorStatus::Down => Self::Down,
        }
    }
}

pub struct Monitor {
    pub id: Uuid,
    pub name: String,
    pub url: String,
    pub method: String,
    /// Sealed JSON list of `[name, value]` pairs.
    pub headers_enc: Option<Vec<u8>>,
    pub body: Option<String>,
    pub interval_secs: i32,
    pub timeout_ms: i32,
    pub expected_status: Option<i16>,
    pub body_contains: Option<String>,
    pub max_latency_ms: Option<i32>,
    pub fail_threshold: i16,
    pub status: MonitorState,
    pub consecutive_failures: i32,
    pub last_checked_at: Option<DateTime<Utc>>,
    pub last_status_code: Option<i16>,
    pub last_latency_ms: Option<i32>,
    pub last_error: Option<String>,
    pub created_at: DateTime<Utc>,
}

/// A validated monitor definition, as entered in the form.
pub struct MonitorSpec {
    pub name: String,
    pub url: String,
    pub method: String,
    pub headers_enc: Option<Vec<u8>>,
    pub body: Option<String>,
    pub interval_secs: i32,
    pub timeout_ms: i32,
    pub expected_status: Option<i16>,
    pub body_contains: Option<String>,
    pub max_latency_ms: Option<i32>,
    pub fail_threshold: i16,
    pub channel_ids: Vec<Uuid>,
}

pub async fn list(db: &PgPool, org: OrgId) -> sqlx::Result<Vec<Monitor>> {
    sqlx::query_as!(
        Monitor,
        r#"SELECT id, name, url, method, headers_enc, body, interval_secs, timeout_ms,
                  expected_status, body_contains, max_latency_ms, fail_threshold,
                  status AS "status: MonitorState", consecutive_failures, last_checked_at,
                  last_status_code, last_latency_ms, last_error, created_at
           FROM http_monitors WHERE org_id = $1 ORDER BY created_at"#,
        org.get(),
    )
    .fetch_all(db)
    .await
}

pub async fn get(db: &PgPool, org: OrgId, id: Uuid) -> sqlx::Result<Option<Monitor>> {
    sqlx::query_as!(
        Monitor,
        r#"SELECT id, name, url, method, headers_enc, body, interval_secs, timeout_ms,
                  expected_status, body_contains, max_latency_ms, fail_threshold,
                  status AS "status: MonitorState", consecutive_failures, last_checked_at,
                  last_status_code, last_latency_ms, last_error, created_at
           FROM http_monitors WHERE id = $1 AND org_id = $2"#,
        id,
        org.get(),
    )
    .fetch_optional(db)
    .await
}

/// Creates a monitor in the org's oldest project. The first check runs at a random
/// point within one interval, so monitors created together don't fire together.
pub async fn create(db: &PgPool, org: OrgId, spec: &MonitorSpec) -> sqlx::Result<Uuid> {
    let mut tx = db.begin().await?;
    let id = sqlx::query_scalar!(
        "INSERT INTO http_monitors (id, org_id, project_id, name, url, method, headers_enc, body,
                                    interval_secs, timeout_ms, expected_status, body_contains,
                                    max_latency_ms, fail_threshold, next_run_at)
         SELECT $1, $2, p.id, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13,
                now() + make_interval(secs => $14)
         FROM projects p WHERE p.org_id = $2 ORDER BY p.created_at LIMIT 1
         RETURNING id",
        Uuid::now_v7(),
        org.get(),
        spec.name,
        spec.url,
        spec.method,
        spec.headers_enc,
        spec.body,
        spec.interval_secs,
        spec.timeout_ms,
        spec.expected_status,
        spec.body_contains,
        spec.max_latency_ms,
        spec.fail_threshold,
        f64::from(uptime::jitter_secs(spec.interval_secs)),
    )
    .fetch_one(&mut *tx)
    .await?;
    channels::set_for_monitor(&mut tx, org, id, &spec.channel_ids).await?;
    tx.commit().await?;
    Ok(id)
}

/// Saves a new definition. A shorter interval takes effect right away.
pub async fn update(db: &PgPool, org: OrgId, id: Uuid, spec: &MonitorSpec) -> sqlx::Result<bool> {
    let mut tx = db.begin().await?;
    let res = sqlx::query!(
        "UPDATE http_monitors
         SET name = $3, url = $4, method = $5, headers_enc = $6, body = $7, interval_secs = $8::int,
             timeout_ms = $9, expected_status = $10, body_contains = $11, max_latency_ms = $12,
             fail_threshold = $13,
             next_run_at = LEAST(next_run_at, now() + make_interval(secs => $8::int)),
             updated_at = now()
         WHERE id = $1 AND org_id = $2",
        id,
        org.get(),
        spec.name,
        spec.url,
        spec.method,
        spec.headers_enc,
        spec.body,
        spec.interval_secs,
        spec.timeout_ms,
        spec.expected_status,
        spec.body_contains,
        spec.max_latency_ms,
        spec.fail_threshold,
    )
    .execute(&mut *tx)
    .await?;
    if res.rows_affected() == 0 {
        return Ok(false);
    }
    channels::set_for_monitor(&mut tx, org, id, &spec.channel_ids).await?;
    tx.commit().await?;
    Ok(true)
}

pub async fn pause(db: &PgPool, org: OrgId, id: Uuid) -> sqlx::Result<bool> {
    let res = sqlx::query!(
        "UPDATE http_monitors SET status = 'paused', updated_at = now()
         WHERE id = $1 AND org_id = $2",
        id,
        org.get(),
    )
    .execute(db)
    .await?;
    Ok(res.rows_affected() == 1)
}

/// Resumes with a check right away. A monitor paused mid-outage resumes as `down`,
/// so its first success resolves the open incident and sends the recovery.
pub async fn resume(db: &PgPool, org: OrgId, id: Uuid) -> sqlx::Result<bool> {
    let res = sqlx::query!(
        "UPDATE http_monitors m
         SET status = CASE WHEN EXISTS (
                 SELECT 1 FROM incidents i WHERE i.monitor_id = m.id AND i.resolved_at IS NULL
             ) THEN 'down' ELSE 'new' END,
             consecutive_failures = 0, next_run_at = now(), updated_at = now()
         WHERE id = $1 AND org_id = $2 AND status = 'paused'",
        id,
        org.get(),
    )
    .execute(db)
    .await?;
    Ok(res.rows_affected() == 1)
}

pub async fn delete(db: &PgPool, org: OrgId, id: Uuid) -> sqlx::Result<bool> {
    let res = sqlx::query!(
        "DELETE FROM http_monitors WHERE id = $1 AND org_id = $2",
        id,
        org.get()
    )
    .execute(db)
    .await?;
    Ok(res.rows_affected() == 1)
}

// ───────────────────────────── probing ─────────────────────────────

/// What the prober needs to make a request.
pub struct ProbeTarget {
    pub id: Uuid,
    pub url: String,
    pub method: String,
    pub headers_enc: Option<Vec<u8>>,
    pub body: Option<String>,
    pub timeout_ms: i32,
    pub expected_status: Option<i16>,
    pub body_contains: Option<String>,
    pub max_latency_ms: Option<i32>,
}

impl From<&Monitor> for ProbeTarget {
    fn from(m: &Monitor) -> Self {
        Self {
            id: m.id,
            url: m.url.clone(),
            method: m.method.clone(),
            headers_enc: m.headers_enc.clone(),
            body: m.body.clone(),
            timeout_ms: m.timeout_ms,
            expected_status: m.expected_status,
            body_contains: m.body_contains.clone(),
            max_latency_ms: m.max_latency_ms,
        }
    }
}

/// Claims due monitors by moving their `next_run_at` one interval ahead: that update
/// is the claim, so concurrent workers never probe the same monitor twice.
pub async fn claim_due(db: &PgPool, limit: i64) -> sqlx::Result<Vec<ProbeTarget>> {
    sqlx::query_as!(
        ProbeTarget,
        "UPDATE http_monitors m
         SET next_run_at = now() + make_interval(secs => m.interval_secs)
         FROM (
             SELECT id FROM http_monitors
             WHERE status <> 'paused' AND next_run_at <= now()
             ORDER BY next_run_at
             LIMIT $1
             FOR UPDATE SKIP LOCKED
         ) due
         WHERE m.id = due.id
         RETURNING m.id, m.url, m.method, m.headers_enc, m.body, m.timeout_ms,
                   m.expected_status, m.body_contains, m.max_latency_ms",
        limit,
    )
    .fetch_all(db)
    .await
}

/// Stores a result and applies it, in one transaction: the up/down transition,
/// incident, and alert (queued in the outbox). Returns what was announced.
pub async fn record_result(
    db: &PgPool,
    base_url: &str,
    monitor_id: Uuid,
    outcome: &Outcome,
) -> anyhow::Result<Event> {
    let mut tx = db.begin().await?;
    let monitor = sqlx::query!(
        r#"SELECT org_id, name, status AS "status: MonitorState", consecutive_failures,
                  fail_threshold
           FROM http_monitors WHERE id = $1 FOR UPDATE"#,
        monitor_id,
    )
    .fetch_optional(&mut *tx)
    .await?;
    // Deleted or paused while the request was in flight.
    let Some(monitor) = monitor.filter(|m| m.status != MonitorState::Paused) else {
        return Ok(Event::None);
    };

    let (status, failures, event) = uptime::transition(
        monitor.status.domain(),
        monitor.consecutive_failures,
        outcome.ok,
        monitor.fail_threshold,
    );
    let status_code = outcome.status_code.and_then(|c| i16::try_from(c).ok());
    sqlx::query!(
        "INSERT INTO http_results (monitor_id, ok, status_code, latency_ms, error)
         VALUES ($1, $2, $3, $4, $5)",
        monitor_id,
        outcome.ok,
        status_code,
        outcome.latency_ms,
        outcome.error,
    )
    .execute(&mut *tx)
    .await?;
    sqlx::query!(
        "UPDATE http_monitors
         SET status = $2, consecutive_failures = $3, last_checked_at = now(),
             last_status_code = $4, last_latency_ms = $5, last_error = $6
         WHERE id = $1",
        monitor_id,
        MonitorState::from_domain(status) as MonitorState,
        failures,
        status_code,
        outcome.latency_ms,
        outcome.error,
    )
    .execute(&mut *tx)
    .await?;

    match event {
        Event::Down => {
            let (reason, label) = if outcome.slow {
                ("http_slow", "Responding too slowly")
            } else {
                ("http_down", "Not responding as expected")
            };
            let detail = format!(
                "{} after {failures} consecutive failed check{}.",
                outcome.error.as_deref().unwrap_or("Failed"),
                if failures == 1 { "" } else { "s" }
            );
            let opened =
                incidents::open_for_monitor(&mut tx, monitor.org_id, monitor_id, reason, &detail)
                    .await?;
            if let Some(incident_id) = opened {
                let mut alert =
                    Alert::for_monitor(AlertEvent::Down, monitor_id, &monitor.name, base_url);
                alert.reason = Some(label.into());
                alert.detail = Some(detail);
                notifications::enqueue_for_monitor(&mut tx, incident_id, monitor_id, &alert)
                    .await?;
            }
        }
        Event::Up => {
            if let Some(resolved) = incidents::resolve_for_monitor(&mut tx, monitor_id).await? {
                let mut alert =
                    Alert::for_monitor(AlertEvent::Up, monitor_id, &monitor.name, base_url);
                alert.down_since = Some(resolved.started_at);
                notifications::enqueue_recovery(&mut tx, resolved.id, &alert).await?;
            }
        }
        Event::None => {}
    }
    tx.commit().await?;
    Ok(event)
}

// ───────────────────────────── history ─────────────────────────────

pub struct ResultRow {
    pub ok: bool,
    pub status_code: Option<i16>,
    pub latency_ms: Option<i32>,
    pub error: Option<String>,
    pub created_at: DateTime<Utc>,
}

pub async fn recent_results(
    db: &PgPool,
    org: OrgId,
    id: Uuid,
    limit: i64,
) -> sqlx::Result<Vec<ResultRow>> {
    sqlx::query_as!(
        ResultRow,
        "SELECT r.ok, r.status_code, r.latency_ms, r.error, r.created_at
         FROM http_results r JOIN http_monitors m ON m.id = r.monitor_id
         WHERE r.monitor_id = $1 AND m.org_id = $2
         ORDER BY r.created_at DESC, r.id DESC
         LIMIT $3",
        id,
        org.get(),
        limit,
    )
    .fetch_all(db)
    .await
}

/// Share of passing checks since `hours` ago (whole hours), or `None` without data.
pub async fn uptime(db: &PgPool, org: OrgId, id: Uuid, hours: i32) -> sqlx::Result<Option<f64>> {
    let row = sqlx::query!(
        r#"SELECT sum(r.count)::bigint AS total, sum(r.fail_count)::bigint AS failed
           FROM http_rollups r JOIN http_monitors m ON m.id = r.monitor_id
           WHERE r.monitor_id = $1 AND m.org_id = $2
             AND r.bucket_hour >= date_trunc('hour', now()) - make_interval(hours => $3 - 1)"#,
        id,
        org.get(),
        hours,
    )
    .fetch_one(db)
    .await?;
    Ok(ratio(row.total, row.failed))
}

fn ratio(total: Option<i64>, failed: Option<i64>) -> Option<f64> {
    match (total, failed) {
        (Some(total), Some(failed)) if total > 0 => Some((total - failed) as f64 / total as f64),
        _ => None,
    }
}

/// 24-hour uptime for every monitor in the org.
pub async fn uptime_24h_by_monitor(db: &PgPool, org: OrgId) -> sqlx::Result<HashMap<Uuid, f64>> {
    let rows = sqlx::query!(
        r#"SELECT r.monitor_id, sum(r.count)::bigint AS total, sum(r.fail_count)::bigint AS failed
           FROM http_rollups r JOIN http_monitors m ON m.id = r.monitor_id
           WHERE m.org_id = $1 AND r.bucket_hour >= date_trunc('hour', now()) - interval '23 hours'
           GROUP BY r.monitor_id"#,
        org.get(),
    )
    .fetch_all(db)
    .await?;
    Ok(rows
        .into_iter()
        .filter_map(|r| ratio(r.total, r.failed).map(|u| (r.monitor_id, u)))
        .collect())
}

pub struct LatencyPoint {
    pub bucket_hour: DateTime<Utc>,
    pub avg_ms: Option<i32>,
    pub p95_ms: Option<i32>,
    pub count: i32,
    pub fail_count: i32,
}

/// Hourly latency for the last 24 hours, oldest first.
pub async fn latency_24h(db: &PgPool, org: OrgId, id: Uuid) -> sqlx::Result<Vec<LatencyPoint>> {
    sqlx::query_as!(
        LatencyPoint,
        "SELECT r.bucket_hour, r.avg_ms, r.p95_ms, r.count, r.fail_count
         FROM http_rollups r JOIN http_monitors m ON m.id = r.monitor_id
         WHERE r.monitor_id = $1 AND m.org_id = $2
           AND r.bucket_hour >= date_trunc('hour', now()) - interval '23 hours'
         ORDER BY r.bucket_hour",
        id,
        org.get(),
    )
    .fetch_all(db)
    .await
}

/// Hourly average latency for the last 24 hours, for every monitor in the org.
pub async fn latency_24h_by_monitor(
    db: &PgPool,
    org: OrgId,
) -> sqlx::Result<HashMap<Uuid, Vec<(DateTime<Utc>, i32)>>> {
    let rows = sqlx::query!(
        r#"SELECT r.monitor_id, r.bucket_hour, r.avg_ms AS "avg_ms!"
           FROM http_rollups r JOIN http_monitors m ON m.id = r.monitor_id
           WHERE m.org_id = $1 AND r.avg_ms IS NOT NULL
             AND r.bucket_hour >= date_trunc('hour', now()) - interval '23 hours'
           ORDER BY r.bucket_hour"#,
        org.get(),
    )
    .fetch_all(db)
    .await?;
    let mut out: HashMap<Uuid, Vec<_>> = HashMap::new();
    for r in rows {
        out.entry(r.monitor_id)
            .or_default()
            .push((r.bucket_hour, r.avg_ms));
    }
    Ok(out)
}

/// Recomputes the hourly rollups for the current and previous hour. Latency stats
/// only count responses (a refused connection has no meaningful latency).
pub async fn rollup(db: &PgPool) -> sqlx::Result<u64> {
    let res = sqlx::query!(
        "INSERT INTO http_rollups (monitor_id, bucket_hour, count, fail_count, avg_ms, p50_ms, p95_ms)
         SELECT monitor_id, date_trunc('hour', created_at), count(*), count(*) FILTER (WHERE NOT ok),
                avg(latency_ms) FILTER (WHERE status_code IS NOT NULL),
                percentile_cont(0.5) WITHIN GROUP (ORDER BY latency_ms) FILTER (WHERE status_code IS NOT NULL),
                percentile_cont(0.95) WITHIN GROUP (ORDER BY latency_ms) FILTER (WHERE status_code IS NOT NULL)
         FROM http_results
         WHERE created_at >= date_trunc('hour', now()) - interval '1 hour'
         GROUP BY 1, 2
         ON CONFLICT (monitor_id, bucket_hour) DO UPDATE
         SET count = excluded.count, fail_count = excluded.fail_count, avg_ms = excluded.avg_ms,
             p50_ms = excluded.p50_ms, p95_ms = excluded.p95_ms",
    )
    .execute(db)
    .await?;
    Ok(res.rows_affected())
}

/// Drops raw results after 7 days and rollups after 90.
pub async fn purge(db: &PgPool) -> sqlx::Result<u64> {
    let results = sqlx::query!(
        "DELETE FROM http_results WHERE created_at < now() - make_interval(days => $1)",
        RESULT_RETENTION_DAYS,
    )
    .execute(db)
    .await?;
    let rollups = sqlx::query!(
        "DELETE FROM http_rollups WHERE bucket_hour < now() - make_interval(days => $1)",
        ROLLUP_RETENTION_DAYS,
    )
    .execute(db)
    .await?;
    Ok(results.rows_affected() + rollups.rows_affected())
}
