pub mod checks;
pub mod incidents;
pub mod pings;
pub mod users;

use std::time::Duration;

use sqlx::migrate::Migrator;
use sqlx::postgres::{PgPool, PgPoolOptions};

use crate::config::Config;

pub static MIGRATOR: Migrator = sqlx::migrate!("./migrations");

pub async fn connect(config: &Config) -> anyhow::Result<PgPool> {
    let pool = PgPoolOptions::new()
        .max_connections(config.db_max_connections)
        .acquire_timeout(Duration::from_secs(5))
        .connect(&config.database_url)
        .await?;
    Ok(pool)
}

pub async fn migrate(pool: &PgPool) -> anyhow::Result<()> {
    MIGRATOR.run(pool).await?;
    Ok(())
}
