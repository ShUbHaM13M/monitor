use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::{DateTime, TimeDelta, Utc};
use sqlx::PgPool;
use uuid::Uuid;

use crate::auth::OrgId;
use crate::domain::schedule::{Schedule, ScheduleError};

#[derive(Debug, Clone, Copy, PartialEq, Eq, sqlx::Type)]
#[sqlx(type_name = "text", rename_all = "lowercase")]
pub enum CheckStatus {
    New,
    Up,
    Started,
    Down,
    Paused,
}

impl CheckStatus {
    pub fn label(self) -> &'static str {
        match self {
            Self::New => "new",
            Self::Up => "up",
            Self::Started => "running",
            Self::Down => "down",
            Self::Paused => "paused",
        }
    }

    /// CSS modifier for the status pill.
    pub fn css(self) -> &'static str {
        match self {
            Self::Up => "pill-up",
            Self::Down => "pill-down",
            Self::Started => "pill-run",
            Self::New | Self::Paused => "pill-muted",
        }
    }
}

pub struct Check {
    pub id: Uuid,
    pub name: String,
    pub token: String,
    pub schedule_kind: String,
    pub cron_expr: Option<String>,
    pub tz: Option<String>,
    pub period_secs: Option<i32>,
    pub grace_secs: i32,
    pub max_runtime_secs: Option<i32>,
    pub status: CheckStatus,
    pub last_ping_at: Option<DateTime<Utc>>,
    pub last_start_at: Option<DateTime<Utc>>,
    pub next_expected_at: Option<DateTime<Utc>>,
    pub alert_after: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

impl Check {
    pub fn schedule(&self) -> Result<Schedule, ScheduleError> {
        Schedule::from_db(
            &self.schedule_kind,
            self.cron_expr.as_deref(),
            self.tz.as_deref(),
            self.period_secs,
        )
    }
}

/// A validated check definition, as entered in the form.
pub struct CheckSpec {
    pub name: String,
    pub schedule: Schedule,
    pub grace_secs: i32,
    pub max_runtime_secs: Option<i32>,
}

struct ScheduleColumns {
    kind: &'static str,
    cron_expr: Option<String>,
    tz: Option<String>,
    period_secs: Option<i32>,
}

impl From<&Schedule> for ScheduleColumns {
    fn from(schedule: &Schedule) -> Self {
        match schedule {
            Schedule::Period { secs } => Self {
                kind: "period",
                cron_expr: None,
                tz: None,
                // Bounded by `Schedule::period` to at most a year.
                period_secs: Some(*secs as i32),
            },
            Schedule::Cron { expr, tz, .. } => Self {
                kind: "cron",
                cron_expr: Some(expr.clone()),
                tz: Some(tz.name().to_owned()),
                period_secs: None,
            },
        }
    }
}

/// When the next ping is due and when to give up on it.
pub fn deadlines(
    schedule: &Schedule,
    grace_secs: i32,
    from: DateTime<Utc>,
) -> (Option<DateTime<Utc>>, Option<DateTime<Utc>>) {
    let next = schedule.next_after(from);
    let alert_after = next.map(|t| t + TimeDelta::seconds(grace_secs.into()));
    (next, alert_after)
}

/// 16 random bytes, base64url: 22 URL-safe characters.
fn new_token() -> String {
    URL_SAFE_NO_PAD.encode(rand::random::<[u8; 16]>())
}

pub async fn list(db: &PgPool, org: OrgId) -> sqlx::Result<Vec<Check>> {
    sqlx::query_as!(
        Check,
        r#"SELECT id, name, token, schedule_kind, cron_expr, tz, period_secs, grace_secs,
                  max_runtime_secs, status AS "status: CheckStatus", last_ping_at,
                  last_start_at, next_expected_at, alert_after, created_at
           FROM checks
           WHERE org_id = $1
           ORDER BY created_at"#,
        org.get(),
    )
    .fetch_all(db)
    .await
}

pub async fn get(db: &PgPool, org: OrgId, id: Uuid) -> sqlx::Result<Option<Check>> {
    sqlx::query_as!(
        Check,
        r#"SELECT id, name, token, schedule_kind, cron_expr, tz, period_secs, grace_secs,
                  max_runtime_secs, status AS "status: CheckStatus", last_ping_at,
                  last_start_at, next_expected_at, alert_after, created_at
           FROM checks
           WHERE id = $1 AND org_id = $2"#,
        id,
        org.get(),
    )
    .fetch_optional(db)
    .await
}

/// Creates a heartbeat check in the org's oldest project.
pub async fn create(db: &PgPool, org: OrgId, spec: &CheckSpec) -> sqlx::Result<Uuid> {
    let cols = ScheduleColumns::from(&spec.schedule);
    sqlx::query_scalar!(
        "INSERT INTO checks (id, org_id, project_id, kind, name, token, schedule_kind,
                             cron_expr, tz, period_secs, grace_secs, max_runtime_secs)
         SELECT $1, $2, p.id, 'heartbeat', $3, $4, $5, $6, $7, $8, $9, $10
         FROM projects p
         WHERE p.org_id = $2
         ORDER BY p.created_at
         LIMIT 1
         RETURNING id",
        Uuid::now_v7(),
        org.get(),
        spec.name,
        new_token(),
        cols.kind,
        cols.cron_expr,
        cols.tz,
        cols.period_secs,
        spec.grace_secs,
        spec.max_runtime_secs,
    )
    .fetch_one(db)
    .await
}

/// Saves a new definition. For a check that is up, the deadline is recomputed
/// from its last ping so the new schedule takes effect immediately.
pub async fn update(db: &PgPool, org: OrgId, id: Uuid, spec: &CheckSpec) -> sqlx::Result<bool> {
    let mut tx = db.begin().await?;
    let current = sqlx::query!(
        r#"SELECT status AS "status: CheckStatus", last_ping_at, next_expected_at, alert_after
           FROM checks WHERE id = $1 AND org_id = $2 FOR UPDATE"#,
        id,
        org.get(),
    )
    .fetch_optional(&mut *tx)
    .await?;
    let Some(current) = current else {
        return Ok(false);
    };

    let (next_expected_at, alert_after) = match (current.status, current.last_ping_at) {
        (CheckStatus::Up, Some(last_ping)) => deadlines(&spec.schedule, spec.grace_secs, last_ping),
        _ => (current.next_expected_at, current.alert_after),
    };
    let cols = ScheduleColumns::from(&spec.schedule);
    sqlx::query!(
        "UPDATE checks
         SET name = $3, schedule_kind = $4, cron_expr = $5, tz = $6, period_secs = $7,
             grace_secs = $8, max_runtime_secs = $9, next_expected_at = $10, alert_after = $11,
             updated_at = now()
         WHERE id = $1 AND org_id = $2",
        id,
        org.get(),
        spec.name,
        cols.kind,
        cols.cron_expr,
        cols.tz,
        cols.period_secs,
        spec.grace_secs,
        spec.max_runtime_secs,
        next_expected_at,
        alert_after,
    )
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(true)
}

pub async fn pause(db: &PgPool, org: OrgId, id: Uuid) -> sqlx::Result<bool> {
    let res = sqlx::query!(
        "UPDATE checks
         SET status = 'paused', next_expected_at = NULL, alert_after = NULL, updated_at = now()
         WHERE id = $1 AND org_id = $2",
        id,
        org.get(),
    )
    .execute(db)
    .await?;
    Ok(res.rows_affected() == 1)
}

/// A resumed check starts over as `new`: no alerts until its next ping.
pub async fn resume(db: &PgPool, org: OrgId, id: Uuid) -> sqlx::Result<bool> {
    let res = sqlx::query!(
        "UPDATE checks
         SET status = 'new', last_start_at = NULL, updated_at = now()
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
        "DELETE FROM checks WHERE id = $1 AND org_id = $2",
        id,
        org.get()
    )
    .execute(db)
    .await?;
    Ok(res.rows_affected() == 1)
}
