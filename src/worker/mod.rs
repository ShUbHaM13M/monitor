use std::future::Future;
use std::time::Duration;

use sqlx::PgPool;
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;

/// Runs all background loops until `shutdown` is cancelled.
///
/// Every loop claims its work from Postgres with `FOR UPDATE SKIP LOCKED`, so any
/// number of worker processes can run side by side.
pub async fn run(db: PgPool, shutdown: CancellationToken) -> anyhow::Result<()> {
    let mut tasks = JoinSet::new();

    // Phase 2 replaces this with the heartbeat deadline scheduler; later phases add
    // the HTTP prober, notifier and janitor.
    tasks.spawn(periodic(
        "scheduler",
        Duration::from_secs(5),
        shutdown.clone(),
        move || {
            let db = db.clone();
            async move {
                sqlx::query("SELECT 1").execute(&db).await?;
                Ok(())
            }
        },
    ));

    tracing::info!("worker started");
    while let Some(res) = tasks.join_next().await {
        res?;
    }
    tracing::info!("worker stopped");
    Ok(())
}

/// Calls `tick` every `period` until cancelled. A failing tick is logged and retried
/// on the next period rather than taking the whole worker down.
async fn periodic<F, Fut>(
    name: &'static str,
    period: Duration,
    shutdown: CancellationToken,
    mut tick: F,
) where
    F: FnMut() -> Fut,
    Fut: Future<Output = anyhow::Result<()>>,
{
    let mut interval = tokio::time::interval(period);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            _ = shutdown.cancelled() => break,
            _ = interval.tick() => {
                if let Err(err) = tick().await {
                    tracing::error!(task = name, error = ?err, "tick failed");
                }
            }
        }
    }
    tracing::debug!(task = name, "stopped");
}
