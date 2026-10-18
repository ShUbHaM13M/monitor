use std::net::SocketAddr;

use clap::{Args, ValueEnum};
use ipnet::IpNet;

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

    /// Reverse proxies whose `X-Forwarded-For` is believed, as comma-separated
    /// addresses or CIDRs (e.g. `127.0.0.1,172.28.0.0/16`). Empty: the TCP peer
    /// is the client, and `X-Forwarded-For` is ignored.
    #[arg(long, env = "TRUSTED_PROXIES", value_delimiter = ',', value_parser = parse_net)]
    pub trusted_proxies: Vec<IpNet>,

    /// Serve Prometheus metrics at `/metrics` on this address (keep it private,
    /// e.g. `127.0.0.1:9090`). Off when unset.
    #[arg(long, env = "METRICS_ADDR")]
    pub metrics_addr: Option<SocketAddr>,

    #[command(flatten)]
    pub plan: PlanDefaults,
}

/// Limits for orgs without their own (see the `orgs.max_*` columns).
#[derive(Debug, Clone, Args)]
pub struct PlanDefaults {
    #[arg(long, env = "PLAN_MAX_CHECKS", default_value_t = 100)]
    pub max_checks: i32,

    #[arg(long, env = "PLAN_MAX_MONITORS", default_value_t = 20)]
    pub max_monitors: i32,

    #[arg(long, env = "PLAN_MAX_CHANNELS", default_value_t = 10)]
    pub max_channels: i32,

    /// Shortest interval an HTTP monitor may use.
    #[arg(long, env = "PLAN_MIN_INTERVAL_SECS", default_value_t = 30)]
    pub min_interval_secs: i32,
}

impl Default for PlanDefaults {
    fn default() -> Self {
        Self {
            max_checks: 100,
            max_monitors: 20,
            max_channels: 10,
            min_interval_secs: 30,
        }
    }
}

/// A single address counts as a /32 (or /128).
fn parse_net(s: &str) -> Result<IpNet, String> {
    let s = s.trim();
    s.parse::<IpNet>()
        .or_else(|_| s.parse::<std::net::IpAddr>().map(IpNet::from))
        .map_err(|_| format!("not an IP address or CIDR: {s:?}"))
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
