pub mod notifier;
pub mod prober;
pub mod scheduler;

use std::future::Future;
use std::time::Duration;

use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;

use crate::auth::session;
use crate::db::{monitors, user_tokens};
use crate::web::AppState;

/// Runs all background loops until `shutdown` is cancelled.
///
/// Every loop claims its work from Postgres with `FOR UPDATE SKIP LOCKED`, so any
/// number of worker processes can run side by side.
pub async fn run(state: AppState, shutdown: CancellationToken) -> anyhow::Result<()> {
    let mut tasks = JoinSet::new();

    let st = state.clone();
    tasks.spawn(periodic(
        "scheduler",
        Duration::from_secs(5),
        shutdown.clone(),
        move || {
            let st = st.clone();
            async move { scheduler::tick(&st.db, &st.config.base_url).await.map(drop) }
        },
    ));

    let st = state.clone();
    tasks.spawn(periodic(
        "notifier",
        Duration::from_secs(2),
        shutdown.clone(),
        move || {
            let st = st.clone();
            async move {
                notifier::tick(&st.db, &st.channels, &st.secrets)
                    .await
                    .map(drop)
            }
        },
    ));

    let st = state.clone();
    tasks.spawn(periodic(
        "prober",
        Duration::from_secs(1),
        shutdown.clone(),
        move || {
            let st = st.clone();
            async move { prober::tick(&st).await.map(drop) }
        },
    ));

    let db = state.db.clone();
    tasks.spawn(periodic(
        "rollups",
        Duration::from_secs(60),
        shutdown.clone(),
        move || {
            let db = db.clone();
            async move { monitors::rollup(&db).await.map(drop).map_err(Into::into) }
        },
    ));

    let db = state.db.clone();
    tasks.spawn(periodic(
        "cleanup",
        Duration::from_secs(60 * 60),
        shutdown.clone(),
        move || {
            let db = db.clone();
            async move {
                let deleted = session::delete_expired(&db).await?;
                if deleted > 0 {
                    tracing::info!(deleted, "removed expired sessions");
                }
                let deleted = user_tokens::delete_expired(&db).await?;
                if deleted > 0 {
                    tracing::info!(deleted, "removed expired account tokens");
                }
                let deleted = monitors::purge(&db).await?;
                if deleted > 0 {
                    tracing::info!(deleted, "removed old uptime results");
                }
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
