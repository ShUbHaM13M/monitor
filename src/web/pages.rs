use std::time::Instant;

use askama::Template;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::Html;

use super::{AppError, AppState};

#[derive(Template)]
#[template(path = "index.html")]
struct IndexPage<'a> {
    base_url: &'a str,
}

pub async fn index(State(state): State<AppState>) -> Result<Html<String>, AppError> {
    let page = IndexPage {
        base_url: &state.config.base_url,
    };
    Ok(Html(page.render()?))
}

/// Liveness + database reachability, for load balancers and uptime checks.
pub async fn healthz(State(state): State<AppState>) -> (StatusCode, &'static str) {
    match sqlx::query("SELECT 1").execute(&state.db).await {
        Ok(_) => (StatusCode::OK, "ok"),
        Err(err) => {
            tracing::warn!(error = %err, "health check: database unreachable");
            (StatusCode::SERVICE_UNAVAILABLE, "database unavailable")
        }
    }
}

#[derive(Template)]
#[template(path = "partials/system_status.html")]
struct SystemStatus {
    db_ok: bool,
    db_latency_ms: u128,
}

/// htmx partial polled by the index page.
pub async fn system_status(State(state): State<AppState>) -> Result<Html<String>, AppError> {
    let started = Instant::now();
    let db_ok = sqlx::query("SELECT 1").execute(&state.db).await.is_ok();
    let partial = SystemStatus {
        db_ok,
        db_latency_ms: started.elapsed().as_millis(),
    };
    Ok(Html(partial.render()?))
}
