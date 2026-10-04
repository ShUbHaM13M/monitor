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

    /// Base64-encoded 32-byte key for encrypting channel secrets.
    /// Generate one with `monitor gen-key`.
    #[arg(long, env = "SECRET_KEY", hide_env_values = true)]
    pub secret_key: String,

    /// SMTP server for email alerts, e.g. `smtp://localhost:1025` or
    /// `smtps://user:pass@smtp.example.com`. Email channels are unavailable without it.
    #[arg(long, env = "SMTP_URL", hide_env_values = true)]
    pub smtp_url: Option<String>,

    #[arg(long, env = "SMTP_FROM", default_value = "Monitor <alerts@localhost>")]
    pub smtp_from: String,

    /// Let webhook channels (and later HTTP monitors) reach private and loopback
    /// addresses. Only for development: in production it allows SSRF.
    #[arg(long, env = "ALLOW_PRIVATE_TARGETS", default_value_t = false)]
    pub allow_private_targets: bool,
}

impl Config {
    /// `scheme://host[:port]` of `base_url`, compared against the `Origin` header.
    pub fn public_origin(&self) -> &str {
        let url = self.base_url.trim_end_matches('/');
        let after_scheme = url.find("://").map_or(0, |i| i + 3);
        match url[after_scheme..].find('/') {
            Some(i) => &url[..after_scheme + i],
            None => url,
        }
    }

    /// Mark cookies `Secure` whenever the app is served over HTTPS.
    pub fn secure_cookies(&self) -> bool {
        self.base_url.starts_with("https://")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum LogFormat {
    Pretty,
    Json,
}
