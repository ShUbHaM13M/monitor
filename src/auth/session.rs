use axum_extra::extract::cookie::{Cookie, SameSite};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use sha2::{Digest, Sha256};
use sqlx::{PgConnection, PgPool};
use uuid::Uuid;

pub const COOKIE_NAME: &str = "session";

/// Idle timeout: a session expires this long after it was last used.
const IDLE_DAYS: i32 = 30;

/// The server-side `expires_at` is authoritative; the cookie just needs to outlive it.
/// 400 days is the longest lifetime browsers accept.
const COOKIE_MAX_AGE: time::Duration = time::Duration::days(400);

pub struct SessionRow {
    pub user_id: Uuid,
    pub email: String,
    pub email_verified: bool,
    pub org_id: Uuid,
    pub org_name: String,
    pub csrf_token: String,
}

/// 32 random bytes, base64url-encoded.
fn new_token() -> String {
    URL_SAFE_NO_PAD.encode(rand::random::<[u8; 32]>())
}

fn hash_token(token: &str) -> Vec<u8> {
    Sha256::digest(token.as_bytes()).to_vec()
}

/// Creates a session and returns the raw token to put in the cookie.
pub async fn create(db: &PgPool, user_id: Uuid, org_id: Uuid) -> sqlx::Result<String> {
    let token = new_token();
    sqlx::query!(
        "INSERT INTO sessions (token_hash, user_id, org_id, csrf_token, expires_at)
         VALUES ($1, $2, $3, $4, now() + make_interval(days => $5))",
        hash_token(&token),
        user_id,
        org_id,
        new_token(),
        IDLE_DAYS,
    )
    .execute(db)
    .await?;
    Ok(token)
}

/// Looks up a live session. Extends its expiry at most once an hour, so normal
/// browsing doesn't write to the database on every request.
pub async fn load(db: &PgPool, token: &str) -> sqlx::Result<Option<SessionRow>> {
    let token_hash = hash_token(token);
    let row = sqlx::query!(
        r#"SELECT s.user_id, u.email, u.email_verified_at IS NOT NULL AS "email_verified!",
                  s.org_id, o.name AS org_name, s.csrf_token,
                  s.last_seen_at < now() - interval '1 hour' AS "stale!"
           FROM sessions s
           JOIN users u ON u.id = s.user_id
           JOIN orgs o ON o.id = s.org_id
           WHERE s.token_hash = $1 AND s.expires_at > now()"#,
        token_hash,
    )
    .fetch_optional(db)
    .await?;
    let Some(row) = row else { return Ok(None) };

    if row.stale {
        sqlx::query!(
            "UPDATE sessions
             SET last_seen_at = now(), expires_at = now() + make_interval(days => $2)
             WHERE token_hash = $1",
            token_hash,
            IDLE_DAYS,
        )
        .execute(db)
        .await?;
    }

    Ok(Some(SessionRow {
        user_id: row.user_id,
        email: row.email,
        email_verified: row.email_verified,
        org_id: row.org_id,
        org_name: row.org_name,
        csrf_token: row.csrf_token,
    }))
}

pub async fn delete(db: &PgPool, token: &str) -> sqlx::Result<()> {
    sqlx::query!(
        "DELETE FROM sessions WHERE token_hash = $1",
        hash_token(token)
    )
    .execute(db)
    .await?;
    Ok(())
}

/// Logs a user out everywhere, e.g. after a password reset.
pub async fn delete_all_for_user(conn: &mut PgConnection, user_id: Uuid) -> sqlx::Result<u64> {
    let res = sqlx::query!("DELETE FROM sessions WHERE user_id = $1", user_id)
        .execute(conn)
        .await?;
    Ok(res.rows_affected())
}

pub async fn delete_expired(db: &PgPool) -> sqlx::Result<u64> {
    let res = sqlx::query!("DELETE FROM sessions WHERE expires_at <= now()")
        .execute(db)
        .await?;
    Ok(res.rows_affected())
}

pub fn cookie(token: String, secure: bool) -> Cookie<'static> {
    Cookie::build((COOKIE_NAME, token))
        .path("/")
        .http_only(true)
        .same_site(SameSite::Lax)
        .secure(secure)
        .max_age(COOKIE_MAX_AGE)
        .build()
}

/// A cookie that, passed to `CookieJar::remove`, clears the session cookie.
pub fn removal_cookie() -> Cookie<'static> {
    Cookie::build(COOKIE_NAME).path("/").build()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokens_are_random_and_url_safe() {
        let (a, b) = (new_token(), new_token());
        assert_ne!(a, b);
        assert_eq!(a.len(), 43);
        assert!(
            a.bytes()
                .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_')
        );
    }

    #[test]
    fn token_hash_is_stable_sha256() {
        assert_eq!(hash_token("abc"), hash_token("abc"));
        assert_ne!(hash_token("abc"), hash_token("abd"));
        assert_eq!(hash_token("abc").len(), 32);
    }
}
