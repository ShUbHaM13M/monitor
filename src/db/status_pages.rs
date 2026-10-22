//! Status pages. Management queries are scoped by `OrgId`; the public ones are
//! keyed by the page itself and return only what a visitor may see.

use chrono::{DateTime, Utc};
use sqlx::PgPool;
use uuid::Uuid;

use super::orgs::{self, CreateError, Resource};
use crate::auth::OrgId;

pub struct StatusPage {
    pub id: Uuid,
    pub slug: String,
    pub title: String,
    pub description: Option<String>,
    pub published: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

pub struct PageSummary {
    pub id: Uuid,
    pub slug: String,
    pub title: String,
    pub published: bool,
    pub item_count: i64,
}

/// What a page shows, as entered in the form.
pub struct PageSpec {
    pub slug: String,
    pub title: String,
    pub description: Option<String>,
    pub published: bool,
    pub items: Vec<ItemSpec>,
}

pub struct ItemSpec {
    pub target: Target,
    pub display_name: String,
    pub position: i32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Target {
    Check(Uuid),
    Monitor(Uuid),
}

#[derive(Debug, thiserror::Error)]
pub enum SaveError {
    #[error("slug already in use")]
    SlugTaken,
    #[error("plan limit of {0} reached")]
    LimitReached(i32),
    #[error(transparent)]
    Db(#[from] sqlx::Error),
}

impl From<CreateError> for SaveError {
    fn from(err: CreateError) -> Self {
        match err {
            CreateError::LimitReached(n) => Self::LimitReached(n),
            CreateError::Db(err) => Self::Db(err),
        }
    }
}

fn slug_taken(err: sqlx::Error) -> SaveError {
    match &err {
        sqlx::Error::Database(e) if e.constraint() == Some("status_pages_slug_key") => {
            SaveError::SlugTaken
        }
        _ => SaveError::Db(err),
    }
}

pub async fn list(db: &PgPool, org: OrgId) -> sqlx::Result<Vec<PageSummary>> {
    sqlx::query_as!(
        PageSummary,
        r#"SELECT p.id, p.slug, p.title, p.published,
                  (SELECT count(*) FROM status_page_items i WHERE i.page_id = p.id) AS "item_count!"
           FROM status_pages p WHERE p.org_id = $1 ORDER BY p.created_at"#,
        org.get(),
    )
    .fetch_all(db)
    .await
}

pub async fn get(db: &PgPool, org: OrgId, id: Uuid) -> sqlx::Result<Option<StatusPage>> {
    sqlx::query_as!(
        StatusPage,
        "SELECT id, slug, title, description, published, created_at, updated_at
         FROM status_pages WHERE id = $1 AND org_id = $2",
        id,
        org.get(),
    )
    .fetch_optional(db)
    .await
}

/// The items as configured, for the edit form.
pub async fn item_specs(db: &PgPool, org: OrgId, page_id: Uuid) -> sqlx::Result<Vec<ItemSpec>> {
    let rows = sqlx::query!(
        "SELECT check_id, monitor_id, display_name, position
         FROM status_page_items WHERE page_id = $1 AND org_id = $2
         ORDER BY position, id",
        page_id,
        org.get(),
    )
    .fetch_all(db)
    .await?;
    Ok(rows
        .into_iter()
        .filter_map(|r| {
            let target = match (r.check_id, r.monitor_id) {
                (Some(id), _) => Target::Check(id),
                (_, Some(id)) => Target::Monitor(id),
                _ => return None,
            };
            Some(ItemSpec {
                target,
                display_name: r.display_name,
                position: r.position,
            })
        })
        .collect())
}

pub async fn create(
    db: &PgPool,
    org: OrgId,
    spec: &PageSpec,
    limit: i32,
) -> Result<Uuid, SaveError> {
    let mut tx = db.begin().await?;
    orgs::reserve(&mut tx, org, Resource::StatusPages, limit).await?;
    let id = sqlx::query_scalar!(
        "INSERT INTO status_pages (id, org_id, slug, title, description, published)
         VALUES ($1, $2, $3, $4, $5, $6) RETURNING id",
        Uuid::now_v7(),
        org.get(),
        spec.slug,
        spec.title,
        spec.description,
        spec.published,
    )
    .fetch_one(&mut *tx)
    .await
    .map_err(slug_taken)?;
    set_items(&mut tx, org, id, &spec.items).await?;
    tx.commit().await?;
    Ok(id)
}

pub async fn update(db: &PgPool, org: OrgId, id: Uuid, spec: &PageSpec) -> Result<bool, SaveError> {
    let mut tx = db.begin().await?;
    let res = sqlx::query!(
        "UPDATE status_pages
         SET slug = $3, title = $4, description = $5, published = $6, updated_at = now()
         WHERE id = $1 AND org_id = $2",
        id,
        org.get(),
        spec.slug,
        spec.title,
        spec.description,
        spec.published,
    )
    .execute(&mut *tx)
    .await
    .map_err(slug_taken)?;
    if res.rows_affected() == 0 {
        return Ok(false);
    }
    set_items(&mut tx, org, id, &spec.items).await?;
    tx.commit().await?;
    Ok(true)
}

/// Replaces the page's items. Other orgs' checks and monitors are refused by the
/// composite foreign keys, so a forged form can't publish them.
async fn set_items(
    conn: &mut sqlx::PgConnection,
    org: OrgId,
    page_id: Uuid,
    items: &[ItemSpec],
) -> sqlx::Result<()> {
    sqlx::query!("DELETE FROM status_page_items WHERE page_id = $1", page_id)
        .execute(&mut *conn)
        .await?;
    for item in items {
        let (check_id, monitor_id) = match item.target {
            Target::Check(id) => (Some(id), None),
            Target::Monitor(id) => (None, Some(id)),
        };
        sqlx::query!(
            "INSERT INTO status_page_items (page_id, org_id, check_id, monitor_id, display_name, position)
             VALUES ($1, $2, $3, $4, $5, $6)",
            page_id,
            org.get(),
            check_id,
            monitor_id,
            item.display_name,
            item.position,
        )
        .execute(&mut *conn)
        .await?;
    }
    Ok(())
}

pub async fn delete(db: &PgPool, org: OrgId, id: Uuid) -> sqlx::Result<bool> {
    let res = sqlx::query!(
        "DELETE FROM status_pages WHERE id = $1 AND org_id = $2",
        id,
        org.get()
    )
    .execute(db)
    .await?;
    Ok(res.rows_affected() == 1)
}

// ───────────────────────────── public ─────────────────────────────

/// A page as looked up by its public URL.
pub struct PublicPage {
    pub id: Uuid,
    pub org_id: Uuid,
    pub title: String,
    pub description: Option<String>,
    pub published: bool,
}

pub async fn find_by_slug(db: &PgPool, slug: &str) -> sqlx::Result<Option<PublicPage>> {
    sqlx::query_as!(
        PublicPage,
        "SELECT id, org_id, title, description, published FROM status_pages WHERE slug = $1",
        slug,
    )
    .fetch_optional(db)
    .await
}

/// A component as shown publicly: its display name and state, never its
/// internal name, URL or token.
pub struct PublicItem {
    pub check_id: Option<Uuid>,
    pub monitor_id: Option<Uuid>,
    pub display_name: String,
    /// The check's or monitor's status column.
    pub status: String,
    /// When monitoring began: the target's creation.
    pub since: DateTime<Utc>,
}

pub async fn public_items(db: &PgPool, page_id: Uuid) -> sqlx::Result<Vec<PublicItem>> {
    sqlx::query_as!(
        PublicItem,
        r#"SELECT i.check_id, i.monitor_id, i.display_name,
                  COALESCE(c.status, m.status) AS "status!",
                  COALESCE(c.created_at, m.created_at) AS "since!"
           FROM status_page_items i
           LEFT JOIN checks c ON c.id = i.check_id
           LEFT JOIN http_monitors m ON m.id = i.monitor_id
           WHERE i.page_id = $1
           ORDER BY i.position, i.id"#,
        page_id,
    )
    .fetch_all(db)
    .await
}

pub struct PublicOutage {
    pub check_id: Option<Uuid>,
    pub monitor_id: Option<Uuid>,
    pub reason: String,
    pub started_at: DateTime<Utc>,
    pub resolved_at: Option<DateTime<Utc>>,
}

/// Outages of the page's components overlapping `since..now`, newest first.
/// One-off events (unusual run times) aren't outages and are left out.
pub async fn outages(
    db: &PgPool,
    page_id: Uuid,
    since: DateTime<Utc>,
) -> sqlx::Result<Vec<PublicOutage>> {
    sqlx::query_as!(
        PublicOutage,
        "SELECT x.check_id, x.monitor_id, x.reason, x.started_at, x.resolved_at
         FROM incidents x
         JOIN status_page_items i
           ON (i.check_id = x.check_id OR i.monitor_id = x.monitor_id) AND i.page_id = $1
         WHERE x.reason NOT IN ('slow_run', 'fast_run')
           AND (x.resolved_at IS NULL OR x.resolved_at > $2)
         ORDER BY x.started_at DESC",
        page_id,
        since,
    )
    .fetch_all(db)
    .await
}
