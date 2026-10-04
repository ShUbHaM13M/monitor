use std::time::Duration;

use futures::StreamExt;
use sqlx::PgPool;

use crate::crypto::SecretBox;
use crate::db::notifications::{self, Claimed};
use crate::notify::{Alert, Registry, SendError};

const BATCH: i64 = 20;
const CONCURRENCY: usize = 10;
/// After this many failed attempts (about two hours of backoff) give up.
pub const MAX_ATTEMPTS: i32 = 8;
const SEND_TIMEOUT: Duration = Duration::from_secs(30);

/// Delivers due notifications. Returns how many were claimed.
///
/// Claiming is `FOR UPDATE SKIP LOCKED` with a lease, so several workers can run
/// this at once and a worker that dies mid-send only delays a delivery.
pub async fn tick(db: &PgPool, registry: &Registry, secrets: &SecretBox) -> anyhow::Result<usize> {
    let claimed = notifications::claim(db, BATCH).await?;
    let count = claimed.len();
    futures::stream::iter(claimed)
        .for_each_concurrent(CONCURRENCY, |item| async move {
            let id = item.id;
            if let Err(err) = deliver(db, registry, secrets, item).await {
                // Recording the outcome failed; the lease expires and it's retried.
                tracing::error!(notification = id, error = ?err, "could not record delivery");
            }
        })
        .await;
    Ok(count)
}

async fn deliver(
    db: &PgPool,
    registry: &Registry,
    secrets: &SecretBox,
    item: Claimed,
) -> sqlx::Result<()> {
    let outcome = send(registry, secrets, &item).await;
    match outcome {
        Ok(()) => {
            tracing::info!(
                notification = item.id,
                kind = item.channel_kind,
                "alert sent"
            );
            notifications::mark_sent(db, item.id).await
        }
        Err(SendError::Retryable(err)) if item.attempts < MAX_ATTEMPTS => {
            let delay = backoff_secs(item.attempts);
            tracing::warn!(
                notification = item.id,
                attempt = item.attempts,
                delay,
                error = err,
                "alert failed, will retry"
            );
            notifications::mark_retry(db, item.id, delay, &err).await
        }
        Err(SendError::Retryable(err) | SendError::Permanent(err)) => {
            tracing::warn!(
                notification = item.id,
                attempt = item.attempts,
                error = err,
                "alert failed permanently"
            );
            notifications::mark_dead(db, item.id, &err).await
        }
    }
}

async fn send(registry: &Registry, secrets: &SecretBox, item: &Claimed) -> Result<(), SendError> {
    let kind = registry.get(&item.channel_kind).ok_or_else(|| {
        SendError::Permanent(format!(
            "channel type {:?} is unavailable",
            item.channel_kind
        ))
    })?;
    let config = secrets
        .open(&item.config_enc)
        .map_err(|err| SendError::Permanent(err.to_string()))
        .and_then(|bytes| {
            serde_json::from_slice(&bytes)
                .map_err(|err| SendError::Permanent(format!("bad channel config: {err}")))
        })?;
    let alert: Alert = serde_json::from_value(item.payload.clone())
        .map_err(|err| SendError::Permanent(format!("bad alert payload: {err}")))?;
    tokio::time::timeout(SEND_TIMEOUT, kind.send(&config, &alert))
        .await
        .map_err(|_| SendError::Retryable("timed out".into()))?
}

/// 30s, 1m, 2m, 4m … capped at 1h.
pub fn backoff_secs(attempts: i32) -> i64 {
    let exp = attempts.clamp(1, 20) - 1;
    (30_i64 << exp).min(3600)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_doubles_then_caps() {
        let delays: Vec<_> = (1..=MAX_ATTEMPTS).map(backoff_secs).collect();
        assert_eq!(delays, [30, 60, 120, 240, 480, 960, 1920, 3600]);
        assert_eq!(backoff_secs(50), 3600);
        // Total wait before giving up: about two hours.
        assert_eq!(delays[..7].iter().sum::<i64>(), 3810);
    }
}
