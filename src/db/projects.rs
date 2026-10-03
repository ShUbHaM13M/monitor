use chrono::{DateTime, Utc};
use sqlx::PgPool;
use uuid::Uuid;

use crate::auth::OrgId;

pub struct Project {
    pub id: Uuid,
    pub name: String,
    pub created_at: DateTime<Utc>,
}

pub async fn list(db: &PgPool, org: OrgId) -> sqlx::Result<Vec<Project>> {
    sqlx::query_as!(
        Project,
        "SELECT id, name, created_at FROM projects WHERE org_id = $1 ORDER BY created_at",
        org.get(),
    )
    .fetch_all(db)
    .await
}
