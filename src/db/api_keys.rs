use chrono::{DateTime, Utc};
use sqlx::PgPool;
use uuid::Uuid;

use crate::auth::OrgId;
use crate::auth::api_key::{NewKey, Scope};

pub struct ApiKey {
    pub id: Uuid,
    pub name: String,
    pub prefix: String,
    pub scope: String,
    pub created_at: DateTime<Utc>,
    pub last_used_at: Option<DateTime<Utc>>,
    pub expires_at: Option<DateTime<Utc>>,
}

pub async fn list(db: &PgPool, org: OrgId) -> sqlx::Result<Vec<ApiKey>> {
    sqlx::query_as!(
        ApiKey,
        "SELECT id, name, prefix, scope, created_at, last_used_at, expires_at
         FROM api_keys WHERE org_id = $1 ORDER BY created_at DESC",
        org.get(),
    )
    .fetch_all(db)
    .await
}

pub async fn create(
    db: &PgPool,
    org: OrgId,
    user_id: Uuid,
    name: &str,
    scope: Scope,
    expires_in_days: Option<i32>,
    key: &NewKey,
) -> sqlx::Result<Uuid> {
    sqlx::query_scalar!(
        "INSERT INTO api_keys (id, org_id, name, token_hash, prefix, scope, created_by, expires_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, now() + make_interval(days => $8))
         RETURNING id",
        Uuid::now_v7(),
        org.get(),
        name,
        key.hash,
        key.prefix,
        scope.as_str(),
        user_id,
        expires_in_days,
    )
    .fetch_one(db)
    .await
}

/// Revoking deletes the key: there's nothing worth keeping about a dead one.
pub async fn delete(db: &PgPool, org: OrgId, id: Uuid) -> sqlx::Result<bool> {
    let res = sqlx::query!(
        "DELETE FROM api_keys WHERE id = $1 AND org_id = $2",
        id,
        org.get()
    )
    .execute(db)
    .await?;
    Ok(res.rows_affected() == 1)
}
