//! Per-org plan limits: an org's own override, or the server-wide default.

use sqlx::{PgConnection, PgPool};

use crate::auth::OrgId;
use crate::config::PlanDefaults;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    pub max_checks: i32,
    pub max_monitors: i32,
    pub max_channels: i32,
    pub max_status_pages: i32,
    pub min_interval_secs: i32,
}

pub async fn limits(db: &PgPool, org: OrgId, defaults: &PlanDefaults) -> sqlx::Result<Limits> {
    sqlx::query_as!(
        Limits,
        r#"SELECT COALESCE(max_checks, $2) AS "max_checks!",
                  COALESCE(max_monitors, $3) AS "max_monitors!",
                  COALESCE(max_channels, $4) AS "max_channels!",
                  COALESCE(max_status_pages, $6) AS "max_status_pages!",
                  COALESCE(min_monitor_interval_secs, $5) AS "min_interval_secs!"
           FROM orgs WHERE id = $1"#,
        org.get(),
        defaults.max_checks,
        defaults.max_monitors,
        defaults.max_channels,
        defaults.min_interval_secs,
        defaults.max_status_pages,
    )
    .fetch_one(db)
    .await
}

#[derive(Debug, Clone, Copy)]
pub enum Resource {
    Checks,
    Monitors,
    Channels,
    StatusPages,
}

#[derive(Debug, thiserror::Error)]
pub enum CreateError {
    /// The org already has its plan's maximum.
    #[error("plan limit of {0} reached")]
    LimitReached(i32),
    #[error(transparent)]
    Db(#[from] sqlx::Error),
}

/// Call inside the creating transaction: locks the org row so concurrent
/// creates queue up behind it, then fails if the org is already at `limit`.
pub async fn reserve(
    conn: &mut PgConnection,
    org: OrgId,
    what: Resource,
    limit: i32,
) -> Result<(), CreateError> {
    sqlx::query!("SELECT id FROM orgs WHERE id = $1 FOR UPDATE", org.get())
        .fetch_one(&mut *conn)
        .await?;
    let count = match what {
        Resource::Checks => {
            sqlx::query_scalar!(
                r#"SELECT count(*) AS "n!" FROM checks WHERE org_id = $1"#,
                org.get()
            )
            .fetch_one(&mut *conn)
            .await?
        }
        Resource::Monitors => {
            sqlx::query_scalar!(
                r#"SELECT count(*) AS "n!" FROM http_monitors WHERE org_id = $1"#,
                org.get()
            )
            .fetch_one(&mut *conn)
            .await?
        }
        Resource::StatusPages => {
            sqlx::query_scalar!(
                r#"SELECT count(*) AS "n!" FROM status_pages WHERE org_id = $1"#,
                org.get()
            )
            .fetch_one(&mut *conn)
            .await?
        }
        Resource::Channels => {
            sqlx::query_scalar!(
                r#"SELECT count(*) AS "n!" FROM channels WHERE org_id = $1"#,
                org.get()
            )
            .fetch_one(&mut *conn)
            .await?
        }
    };
    if count >= i64::from(limit) {
        return Err(CreateError::LimitReached(limit));
    }
    Ok(())
}
