use std::sync::LazyLock;

use argon2::Argon2;
use argon2::password_hash::{Error as HashError, PasswordHasher, PasswordVerifier};

pub const MIN_LEN: usize = 10;
pub const MAX_LEN: usize = 128;

/// Hashed on first use; verified against when the email is unknown so a failed
/// login takes the same time whether or not the account exists.
static DUMMY_HASH: LazyLock<String> =
    LazyLock::new(|| hash_blocking("dummy password for timing").expect("hash dummy password"));

/// Argon2id with default parameters, as a PHC string.
pub async fn hash(password: String) -> anyhow::Result<String> {
    tokio::task::spawn_blocking(move || hash_blocking(&password)).await?
}

/// Returns whether `password` matches `stored`. Pass `None` for an unknown account:
/// a dummy hash is still verified and the result is always `false`.
pub async fn verify(password: String, stored: Option<String>) -> anyhow::Result<bool> {
    tokio::task::spawn_blocking(move || match stored {
        Some(hash) => verify_blocking(&password, &hash),
        None => verify_blocking(&password, &DUMMY_HASH).map(|_| false),
    })
    .await?
}

fn hash_blocking(password: &str) -> anyhow::Result<String> {
    Argon2::default()
        .hash_password(password.as_bytes())
        .map(|h| h.to_string())
        .map_err(|err| anyhow::anyhow!("hash password: {err}"))
}

fn verify_blocking(password: &str, hash: &str) -> anyhow::Result<bool> {
    match Argon2::default().verify_password(password.as_bytes(), hash) {
        Ok(()) => Ok(true),
        Err(HashError::PasswordInvalid) => Ok(false),
        Err(err) => Err(anyhow::anyhow!("verify password: {err}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn round_trip() {
        let hash = hash("correct horse battery".into()).await.unwrap();
        assert!(hash.starts_with("$argon2id$"));
        assert!(
            verify("correct horse battery".into(), Some(hash.clone()))
                .await
                .unwrap()
        );
        assert!(
            !verify("wrong horse battery".into(), Some(hash))
                .await
                .unwrap()
        );
    }

    #[tokio::test]
    async fn unknown_account_never_verifies() {
        assert!(
            !verify("dummy password for timing".into(), None)
                .await
                .unwrap()
        );
    }
}
