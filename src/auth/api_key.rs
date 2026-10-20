//! API keys: `Authorization: Bearer mon_…`. Like sessions, only a SHA-256 of
//! the key is stored, and a valid key is the only other way to get an `OrgId`.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use uuid::Uuid;

use super::OrgId;

const PREFIX: &str = "mon_";
/// Characters of the key shown in lists ("mon_AbCdEfGh…").
const SHOWN: usize = PREFIX.len() + 8;
/// `last_used_at` is written at most this often per key.
const TOUCH_EVERY_SECS: f64 = 60.0;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope {
    Read,
    Write,
}

impl Scope {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "read" => Some(Self::Read),
            "write" => Some(Self::Write),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::Write => "write",
        }
    }
}

/// A newly generated key. `token` goes to the user once; the rest is stored.
pub struct NewKey {
    pub token: String,
    pub hash: Vec<u8>,
    pub prefix: String,
}

pub fn generate() -> NewKey {
    let bytes: [u8; 32] = rand::random();
    let token = format!("{PREFIX}{}", URL_SAFE_NO_PAD.encode(bytes));
    NewKey {
        hash: hash(&token),
        prefix: token[..SHOWN].to_owned(),
        token,
    }
}

pub fn hash(token: &str) -> Vec<u8> {
    Sha256::digest(token.as_bytes()).to_vec()
}

/// A request authenticated by an API key.
#[derive(Debug, Clone, Copy)]
pub struct ApiKeyAuth {
    pub key_id: Uuid,
    pub org: OrgId,
    pub scope: Scope,
}

/// Resolves a bearer token. Unknown, malformed and expired keys are all `None`.
pub async fn authenticate(db: &PgPool, token: &str) -> sqlx::Result<Option<ApiKeyAuth>> {
    if !token.starts_with(PREFIX) || token.len() > 100 {
        return Ok(None);
    }
    let row = sqlx::query!(
        r#"SELECT id, org_id, scope,
                  last_used_at IS NULL OR last_used_at < now() - make_interval(secs => $2) AS "stale!"
           FROM api_keys
           WHERE token_hash = $1 AND (expires_at IS NULL OR expires_at > now())"#,
        hash(token),
        TOUCH_EVERY_SECS,
    )
    .fetch_optional(db)
    .await?;
    let Some(row) = row else {
        return Ok(None);
    };
    if row.stale {
        sqlx::query!(
            "UPDATE api_keys SET last_used_at = now() WHERE id = $1",
            row.id
        )
        .execute(db)
        .await?;
    }
    Ok(Scope::parse(&row.scope).map(|scope| ApiKeyAuth {
        key_id: row.id,
        org: OrgId(row.org_id),
        scope,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_are_prefixed_random_and_hashed() {
        let a = generate();
        let b = generate();
        assert!(a.token.starts_with("mon_"));
        assert_eq!(a.token.len(), 4 + 43);
        assert_ne!(a.token, b.token);
        assert_eq!(a.prefix, a.token[..12]);
        assert_eq!(a.hash, hash(&a.token));
        assert_eq!(a.hash.len(), 32);
    }
}
