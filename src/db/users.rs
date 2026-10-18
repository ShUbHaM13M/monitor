use chrono::{DateTime, Utc};
use sqlx::{PgConnection, PgPool};
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

pub struct Account {
    pub id: Uuid,
    pub email: String,
    pub email_verified: bool,
}

pub async fn find_by_email(db: &PgPool, email: &str) -> sqlx::Result<Option<Account>> {
    sqlx::query_as!(
        Account,
        r#"SELECT id, email, email_verified_at IS NOT NULL AS "email_verified!"
           FROM users WHERE lower(email) = lower($1)"#,
        email,
    )
    .fetch_optional(db)
    .await
}

pub async fn mark_email_verified(conn: &mut PgConnection, user_id: Uuid) -> sqlx::Result<()> {
    sqlx::query!(
        "UPDATE users SET email_verified_at = now() WHERE id = $1 AND email_verified_at IS NULL",
        user_id,
    )
    .execute(conn)
    .await?;
    Ok(())
}

/// Attempts allowed before the account starts locking.
const LOGIN_ATTEMPTS: i32 = 5;

/// Counts a login attempt *before* the password is checked, so parallel guesses
/// can't slip past the limit; `login_succeeded` takes it back. From the 5th
/// unconfirmed attempt on, the account locks for 1, 2, 4… minutes (capped at an
/// hour). Returns `Some(until)` when it's locked and the attempt must not run.
pub async fn begin_login_attempt(
    db: &PgPool,
    user_id: Uuid,
) -> sqlx::Result<Option<DateTime<Utc>>> {
    let counted = sqlx::query_scalar!(
        "UPDATE users
         SET failed_logins = failed_logins + 1,
             locked_until = CASE
                 WHEN failed_logins + 1 >= $2 THEN now() + LEAST(
                     make_interval(mins => power(2, LEAST(failed_logins + 1 - $2, 6))::int),
                     interval '1 hour')
                 ELSE locked_until
             END
         WHERE id = $1 AND (locked_until IS NULL OR locked_until <= now())
         RETURNING id",
        user_id,
        LOGIN_ATTEMPTS,
    )
    .fetch_optional(db)
    .await?;
    if counted.is_some() {
        return Ok(None);
    }
    sqlx::query_scalar!("SELECT locked_until FROM users WHERE id = $1", user_id)
        .fetch_one(db)
        .await
}

pub async fn login_succeeded(db: &PgPool, user_id: Uuid) -> sqlx::Result<()> {
    sqlx::query!(
        "UPDATE users SET failed_logins = 0, locked_until = NULL WHERE id = $1",
        user_id,
    )
    .execute(db)
    .await?;
    Ok(())
}

/// Also lifts any login lock: whoever reset it controls the mailbox.
pub async fn set_password(
    conn: &mut PgConnection,
    user_id: Uuid,
    password_hash: &str,
) -> sqlx::Result<()> {
    sqlx::query!(
        "UPDATE users SET password_hash = $2, failed_logins = 0, locked_until = NULL WHERE id = $1",
        user_id,
        password_hash,
    )
    .execute(conn)
    .await?;
    Ok(())
}
