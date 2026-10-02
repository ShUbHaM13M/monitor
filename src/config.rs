use std::net::SocketAddr;

use clap::{Args, ValueEnum};

/// Runtime configuration. Every field can be set by flag or environment variable;
/// a `.env` file is loaded first in development.
#[derive(Debug, Clone, Args)]
pub struct Config {
    #[arg(long, env = "DATABASE_URL")]
    pub database_url: String,

    #[arg(long, env = "DB_MAX_CONNECTIONS", default_value_t = 10)]
    pub db_max_connections: u32,

    #[arg(long, env = "BIND_ADDR", default_value = "0.0.0.0:3000")]
    pub bind_addr: SocketAddr,

    /// Public base URL, used when rendering ping URLs and links in alerts.
    #[arg(long, env = "BASE_URL", default_value = "http://localhost:3000")]
    pub base_url: String,

    /// Apply pending migrations on startup of `serve`, `worker` and `all`.
    #[arg(long, env = "AUTO_MIGRATE", default_value_t = false)]
    pub auto_migrate: bool,

    #[arg(long, env = "LOG_FORMAT", value_enum, default_value_t = LogFormat::Pretty)]
    pub log_format: LogFormat,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum LogFormat {
    Pretty,
    Json,
}
