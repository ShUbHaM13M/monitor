use sqlx::PgPool;
use uuid::Uuid;

#[derive(Debug, thiserror::Error)]
pub enum CreateAccountError {
    #[error("email already registered")]
    EmailTaken,
    #[error(transparent)]
    Db(#[from] sqlx::Error),
}

pub struct NewAccount {
    pub user_id: Uuid,
    pub org_id: Uuid,
}

/// Creates a user together with their org (as owner) and a "Default" project.
pub async fn create_account(
    db: &PgPool,
    email: &str,
    password_hash: &str,
    org_name: &str,
) -> Result<NewAccount, CreateAccountError> {
    let user_id = Uuid::now_v7();
    let org_id = Uuid::now_v7();
    let mut tx = db.begin().await?;

    sqlx::query!(
        "INSERT INTO users (id, email, password_hash) VALUES ($1, $2, $3)",
        user_id,
        email,
        password_hash,
    )
    .execute(&mut *tx)
    .await
    .map_err(|err| match &err {
        sqlx::Error::Database(e) if e.constraint() == Some("users_email_key") => {
            CreateAccountError::EmailTaken
        }
        _ => err.into(),
    })?;
    sqlx::query!(
        "INSERT INTO orgs (id, name) VALUES ($1, $2)",
        org_id,
        org_name
    )
    .execute(&mut *tx)
    .await?;
    sqlx::query!(
        "INSERT INTO memberships (user_id, org_id, role) VALUES ($1, $2, 'owner')",
        user_id,
        org_id,
    )
    .execute(&mut *tx)
    .await?;
    sqlx::query!(
        "INSERT INTO projects (id, org_id, name) VALUES ($1, $2, 'Default')",
        Uuid::now_v7(),
        org_id,
    )
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;
    Ok(NewAccount { user_id, org_id })
}

pub struct LoginCandidate {
    pub user_id: Uuid,
    pub password_hash: String,
    /// The user's oldest org, which becomes the session's active org.
    pub org_id: Option<Uuid>,
}

pub async fn find_for_login(db: &PgPool, email: &str) -> sqlx::Result<Option<LoginCandidate>> {
    sqlx::query_as!(
        LoginCandidate,
        r#"SELECT u.id AS user_id, u.password_hash, m.org_id AS "org_id?"
           FROM users u
           LEFT JOIN LATERAL (
               SELECT org_id FROM memberships
               WHERE user_id = u.id
               ORDER BY created_at
               LIMIT 1
           ) m ON true
           WHERE lower(u.email) = lower($1)"#,
        email,
    )
    .fetch_optional(db)
    .await
}
