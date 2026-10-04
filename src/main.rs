use std::sync::Arc;

use clap::{Parser, Subcommand};
use tokio_util::sync::CancellationToken;
use tracing_subscriber::EnvFilter;

use monitor::config::{Config, LogFormat};
use monitor::crypto::SecretBox;
use monitor::{db, web, worker};

#[derive(Parser)]
#[command(version, about = "Cron, heartbeat and uptime monitoring")]
struct Cli {
    #[command(flatten)]
    config: Config,

    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand, Clone, Copy)]
enum Command {
    /// Run the web server (dashboard + ping ingest) only.
    Serve,
    /// Run the background workers (scheduler, prober, notifier) only.
    Worker,
    /// Run the web server and workers in one process (default).
    All,
    /// Apply pending database migrations and exit.
    Migrate,
    /// Print a new random SECRET_KEY and exit.
    GenKey,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();
    // Handled before parsing: generating the first key must not require one.
    if std::env::args().nth(1).as_deref() == Some("gen-key") {
        println!("{}", SecretBox::generate_key());
        return Ok(());
    }
    let cli = Cli::parse();
    init_tracing(cli.config.log_format);

    let config = Arc::new(cli.config);
    let command = cli.command.unwrap_or(Command::All);
    let db = db::connect(&config).await?;

    if matches!(command, Command::Migrate) {
        db::migrate(&db).await?;
        tracing::info!("migrations applied");
        return Ok(());
    }
    if config.auto_migrate {
        db::migrate(&db).await?;
    }

    let shutdown = CancellationToken::new();
    tokio::spawn(cancel_on_signal(shutdown.clone()));

    let state = web::AppState::new(db, config)?;
    match command {
        Command::Serve => web::serve(state, shutdown).await?,
        Command::Worker => worker::run(state, shutdown).await?,
        Command::All => {
            // If either half fails, stop the other so the process exits as a whole.
            let web = {
                let shutdown = shutdown.clone();
                let state = state.clone();
                async move {
                    let res = web::serve(state, shutdown.clone()).await;
                    shutdown.cancel();
                    res
                }
            };
            let worker = {
                let shutdown = shutdown.clone();
                async move {
                    let res = worker::run(state, shutdown.clone()).await;
                    shutdown.cancel();
                    res
                }
            };
            let (web_res, worker_res) = tokio::join!(web, worker);
            web_res?;
            worker_res?;
        }
        Command::Migrate | Command::GenKey => unreachable!(),
    }
    Ok(())
}

fn init_tracing(format: LogFormat) {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("monitor=info,tower_http=info,sqlx=warn"));
    let builder = tracing_subscriber::fmt().with_env_filter(filter);
    match format {
        LogFormat::Pretty => builder.init(),
        LogFormat::Json => builder.json().init(),
    }
}

async fn cancel_on_signal(shutdown: CancellationToken) {
    let ctrl_c = tokio::signal::ctrl_c();
    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("install SIGTERM handler")
            .recv()
            .await;
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
    tracing::info!("shutdown signal received");
    shutdown.cancel();
}
