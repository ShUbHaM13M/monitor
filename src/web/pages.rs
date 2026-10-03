use std::time::Instant;

use askama::Template;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse, Redirect, Response};

use super::{AppError, AppState, Chrome};
use crate::auth::{CurrentUser, MaybeUser};
use crate::db::projects::{self, Project};

#[derive(Template)]
#[template(path = "index.html")]
struct IndexPage<'a> {
    chrome: Chrome,
    base_url: &'a str,
}

pub async fn index(
    State(state): State<AppState>,
    MaybeUser(user): MaybeUser,
) -> Result<Response, AppError> {
    if user.is_some() {
        return Ok(Redirect::to("/dashboard").into_response());
    }
    let page = IndexPage {
        chrome: Chrome::anonymous(),
        base_url: &state.config.base_url,
    };
    Ok(Html(page.render()?).into_response())
}

#[derive(Template)]
#[template(path = "dashboard.html")]
struct DashboardPage {
    chrome: Chrome,
    org_name: String,
    projects: Vec<Project>,
}

pub async fn dashboard(
    State(state): State<AppState>,
    user: CurrentUser,
) -> Result<Html<String>, AppError> {
    let page = DashboardPage {
        chrome: Chrome::signed_in(&user),
        projects: projects::list(&state.db, user.org).await?,
        org_name: user.org_name,
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
