use chrono::{DateTime, Utc};
use sqlx::{PgConnection, PgPool};
use uuid::Uuid;

use super::orgs::{self, CreateError, Resource};
use crate::auth::OrgId;

/// How long a confirmation link stays valid.
const VERIFY_TTL_DAYS: i32 = 7;
/// Minimum gap between confirmation emails for one channel.
const RESEND_COOLDOWN_SECS: f64 = 60.0;

pub struct Channel {
    pub id: Uuid,
    pub kind: String,
    pub name: String,
    /// Sealed config JSON; open it with `crypto::SecretBox`.
    pub config_enc: Vec<u8>,
    pub verified_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub check_count: i64,
    pub last_status: Option<String>,
    pub last_at: Option<DateTime<Utc>>,
}

pub async fn list(db: &PgPool, org: OrgId) -> sqlx::Result<Vec<Channel>> {
    sqlx::query_as!(
        Channel,
        r#"SELECT ch.id, ch.kind, ch.name, ch.config_enc, ch.verified_at, ch.created_at,
                  (SELECT count(*) FROM check_channels cc WHERE cc.channel_id = ch.id)
                  + (SELECT count(*) FROM monitor_channels mc WHERE mc.channel_id = ch.id) AS "check_count!",
                  last.status AS "last_status?", last.created_at AS "last_at?"
           FROM channels ch
           LEFT JOIN LATERAL (
               SELECT status, created_at FROM notifications n
               WHERE n.channel_id = ch.id
               ORDER BY created_at DESC LIMIT 1
           ) last ON true
           WHERE ch.org_id = $1
           ORDER BY ch.created_at"#,
        org.get(),
    )
    .fetch_all(db)
    .await
}

pub async fn get(db: &PgPool, org: OrgId, id: Uuid) -> sqlx::Result<Option<Channel>> {
    sqlx::query_as!(
        Channel,
        r#"SELECT ch.id, ch.kind, ch.name, ch.config_enc, ch.verified_at, ch.created_at,
                  (SELECT count(*) FROM check_channels cc WHERE cc.channel_id = ch.id)
                  + (SELECT count(*) FROM monitor_channels mc WHERE mc.channel_id = ch.id) AS "check_count!",
                  last.status AS "last_status?", last.created_at AS "last_at?"
           FROM channels ch
           LEFT JOIN LATERAL (
               SELECT status, created_at FROM notifications n
               WHERE n.channel_id = ch.id
               ORDER BY created_at DESC LIMIT 1
           ) last ON true
           WHERE ch.org_id = $1 AND ch.id = $2"#,
        org.get(),
        id,
    )
    .fetch_optional(db)
    .await
}

pub struct NewChannel<'a> {
    pub kind: &'a str,
    pub name: &'a str,
    pub config_enc: Vec<u8>,
    /// `false` when the recipient must confirm first.
    pub verified: bool,
    /// sha256 of the confirmation token, when one is sent.
    pub verify_token_hash: Option<Vec<u8>>,
    /// Attach the new channel to every existing check and monitor in the org.
    pub attach_to_all_checks: bool,
}

pub async fn create(
    db: &PgPool,
    org: OrgId,
    new: NewChannel<'_>,
    limit: i32,
) -> Result<Uuid, CreateError> {
    let id = Uuid::now_v7();
    let mut tx = db.begin().await?;
    orgs::reserve(&mut tx, org, Resource::Channels, limit).await?;
    sqlx::query!(
        "INSERT INTO channels (id, org_id, kind, name, config_enc, verified_at, verify_token_hash, verify_sent_at)
         VALUES ($1, $2, $3, $4, $5,
                 CASE WHEN $6 THEN now() END,
                 $7,
                 CASE WHEN $7::bytea IS NOT NULL THEN now() END)",
        id,
        org.get(),
        new.kind,
        new.name,
        new.config_enc,
        new.verified,
        new.verify_token_hash,
    )
    .execute(&mut *tx)
    .await?;
    if new.attach_to_all_checks {
        sqlx::query!(
            "INSERT INTO check_channels (check_id, channel_id, org_id)
             SELECT c.id, $1, c.org_id FROM checks c WHERE c.org_id = $2",
            id,
            org.get(),
        )
        .execute(&mut *tx)
        .await?;
        sqlx::query!(
            "INSERT INTO monitor_channels (monitor_id, channel_id, org_id)
             SELECT m.id, $1, m.org_id FROM http_monitors m WHERE m.org_id = $2",
            id,
            org.get(),
        )
        .execute(&mut *tx)
        .await?;
    }
    tx.commit().await?;
    Ok(id)
}

pub async fn delete(db: &PgPool, org: OrgId, id: Uuid) -> sqlx::Result<bool> {
    let res = sqlx::query!(
        "DELETE FROM channels WHERE id = $1 AND org_id = $2",
        id,
        org.get()
    )
    .execute(db)
    .await?;
    Ok(res.rows_affected() == 1)
}

/// Stores a new confirmation token for an unverified channel, unless one was sent
/// in the last minute. Returns whether the caller should send it.
pub async fn renew_verify_token(
    db: &PgPool,
    org: OrgId,
    id: Uuid,
    token_hash: &[u8],
) -> sqlx::Result<bool> {
    let res = sqlx::query!(
        "UPDATE channels SET verify_token_hash = $3, verify_sent_at = now()
         WHERE id = $1 AND org_id = $2 AND verified_at IS NULL
           AND (verify_sent_at IS NULL OR verify_sent_at < now() - make_interval(secs => $4))",
        id,
        org.get(),
        token_hash,
        RESEND_COOLDOWN_SECS,
    )
    .execute(db)
    .await?;
    Ok(res.rows_affected() == 1)
}

pub struct PendingVerification {
    pub id: Uuid,
    pub kind: String,
    pub config_enc: Vec<u8>,
    pub org_name: String,
}

/// Looks up an unexpired confirmation token. Public: the recipient may not have
/// an account, so this is keyed by the token alone.
pub async fn find_by_verify_token(
    db: &PgPool,
    token_hash: &[u8],
) -> sqlx::Result<Option<PendingVerification>> {
    sqlx::query_as!(
        PendingVerification,
        "SELECT ch.id, ch.kind, ch.config_enc, o.name AS org_name
         FROM channels ch JOIN orgs o ON o.id = ch.org_id
         WHERE ch.verify_token_hash = $1 AND ch.verified_at IS NULL
           AND ch.verify_sent_at > now() - make_interval(days => $2)",
        token_hash,
        VERIFY_TTL_DAYS,
    )
    .fetch_optional(db)
    .await
}

/// Confirms the channel for an unexpired token; the token can't be reused.
pub async fn confirm_verify_token(db: &PgPool, token_hash: &[u8]) -> sqlx::Result<bool> {
    let res = sqlx::query!(
        "UPDATE channels SET verified_at = now(), verify_token_hash = NULL
         WHERE verify_token_hash = $1 AND verified_at IS NULL
           AND verify_sent_at > now() - make_interval(days => $2)",
        token_hash,
        VERIFY_TTL_DAYS,
    )
    .execute(db)
    .await?;
    Ok(res.rows_affected() == 1)
}

pub struct ChannelOption {
    pub id: Uuid,
    pub kind: String,
    pub name: String,
    pub verified: bool,
}

/// Channels offered on the check form.
pub async fn options(db: &PgPool, org: OrgId) -> sqlx::Result<Vec<ChannelOption>> {
    sqlx::query_as!(
        ChannelOption,
        r#"SELECT id, kind, name, verified_at IS NOT NULL AS "verified!"
           FROM channels WHERE org_id = $1 ORDER BY created_at"#,
        org.get(),
    )
    .fetch_all(db)
    .await
}

pub async fn ids_for_check(db: &PgPool, org: OrgId, check_id: Uuid) -> sqlx::Result<Vec<Uuid>> {
    sqlx::query_scalar!(
        "SELECT channel_id FROM check_channels WHERE check_id = $1 AND org_id = $2",
        check_id,
        org.get(),
    )
    .fetch_all(db)
    .await
}

/// Makes `ids` the check's channels. Ids from other orgs are ignored (and the
/// composite foreign keys would reject them anyway).
pub async fn set_for_check(
    conn: &mut PgConnection,
    org: OrgId,
    check_id: Uuid,
    ids: &[Uuid],
) -> sqlx::Result<()> {
    sqlx::query!(
        "DELETE FROM check_channels
         WHERE check_id = $1 AND org_id = $2 AND NOT (channel_id = ANY($3))",
        check_id,
        org.get(),
        ids,
    )
    .execute(&mut *conn)
    .await?;
    sqlx::query!(
        "INSERT INTO check_channels (check_id, channel_id, org_id)
         SELECT $1, ch.id, ch.org_id FROM channels ch
         WHERE ch.org_id = $2 AND ch.id = ANY($3)
         ON CONFLICT DO NOTHING",
        check_id,
        org.get(),
        ids,
    )
    .execute(&mut *conn)
    .await?;
    Ok(())
}

pub async fn ids_for_monitor(db: &PgPool, org: OrgId, monitor_id: Uuid) -> sqlx::Result<Vec<Uuid>> {
    sqlx::query_scalar!(
        "SELECT channel_id FROM monitor_channels WHERE monitor_id = $1 AND org_id = $2",
        monitor_id,
        org.get(),
    )
    .fetch_all(db)
    .await
}

/// Makes `ids` the monitor's channels, like [`set_for_check`].
pub async fn set_for_monitor(
    conn: &mut PgConnection,
    org: OrgId,
    monitor_id: Uuid,
    ids: &[Uuid],
) -> sqlx::Result<()> {
    sqlx::query!(
        "DELETE FROM monitor_channels
         WHERE monitor_id = $1 AND org_id = $2 AND NOT (channel_id = ANY($3))",
        monitor_id,
        org.get(),
        ids,
    )
    .execute(&mut *conn)
    .await?;
    sqlx::query!(
        "INSERT INTO monitor_channels (monitor_id, channel_id, org_id)
         SELECT $1, ch.id, ch.org_id FROM channels ch
         WHERE ch.org_id = $2 AND ch.id = ANY($3)
         ON CONFLICT DO NOTHING",
        monitor_id,
        org.get(),
        ids,
    )
    .execute(&mut *conn)
    .await?;
    Ok(())
}
