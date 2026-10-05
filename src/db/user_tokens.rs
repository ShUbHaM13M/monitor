//! One-time tokens mailed to account holders: email verification and password reset.

use sqlx::{PgConnection, PgPool};
use uuid::Uuid;

use crate::crypto::{random_token, sha256};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Purpose {
    VerifyEmail,
    ResetPassword,
}

impl Purpose {
    fn as_str(self) -> &'static str {
        match self {
            Self::VerifyEmail => "verify_email",
            Self::ResetPassword => "reset_password",
        }
    }

    fn ttl_secs(self) -> f64 {
        match self {
            Self::VerifyEmail => 7.0 * 24.0 * 3600.0,
            Self::ResetPassword => 3600.0,
        }
    }
}

/// Minimum gap between two tokens of the same purpose for one user, so the forms
/// can't be used to flood an inbox.
const COOLDOWN_SECS: f64 = 60.0;

/// Issues a token unless one of the same purpose was issued in the last minute.
/// Returns the raw token to put in the link.
pub async fn issue(db: &PgPool, user_id: Uuid, purpose: Purpose) -> sqlx::Result<Option<String>> {
    let token = random_token();
    let res = sqlx::query!(
        "INSERT INTO user_tokens (token_hash, user_id, purpose, expires_at)
         SELECT $1, $2, $3, now() + make_interval(secs => $4)
         WHERE NOT EXISTS (
             SELECT 1 FROM user_tokens
             WHERE user_id = $2 AND purpose = $3
               AND created_at > now() - make_interval(secs => $5)
         )",
        sha256(&token),
        user_id,
        purpose.as_str(),
        purpose.ttl_secs(),
        COOLDOWN_SECS,
    )
    .execute(db)
    .await?;
    Ok((res.rows_affected() == 1).then_some(token))
}

/// The account email for a live token, without using it up (for confirm pages).
pub async fn peek(db: &PgPool, token: &str, purpose: Purpose) -> sqlx::Result<Option<String>> {
    sqlx::query_scalar!(
        "SELECT u.email FROM user_tokens t JOIN users u ON u.id = t.user_id
         WHERE t.token_hash = $1 AND t.purpose = $2 AND t.used_at IS NULL AND t.expires_at > now()",
        sha256(token),
        purpose.as_str(),
    )
    .fetch_optional(db)
    .await
}

/// Uses up a live token and returns its user. Also retires the user's other
/// unused tokens of the same purpose, so older links in the inbox stop working.
pub async fn consume(
    conn: &mut PgConnection,
    token: &str,
    purpose: Purpose,
) -> sqlx::Result<Option<Uuid>> {
    let user_id = sqlx::query_scalar!(
        "UPDATE user_tokens SET used_at = now()
         WHERE token_hash = $1 AND purpose = $2 AND used_at IS NULL AND expires_at > now()
         RETURNING user_id",
        sha256(token),
        purpose.as_str(),
    )
    .fetch_optional(&mut *conn)
    .await?;
    if let Some(user_id) = user_id {
        sqlx::query!(
            "UPDATE user_tokens SET used_at = now()
             WHERE user_id = $1 AND purpose = $2 AND used_at IS NULL",
            user_id,
            purpose.as_str(),
        )
        .execute(&mut *conn)
        .await?;
    }
    Ok(user_id)
}

pub async fn delete_expired(db: &PgPool) -> sqlx::Result<u64> {
    let res = sqlx::query!("DELETE FROM user_tokens WHERE expires_at <= now()")
        .execute(db)
        .await?;
    Ok(res.rows_affected())
}
