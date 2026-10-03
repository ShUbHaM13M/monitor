mod assets;
mod auth;
mod error;
mod pages;

use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::middleware;
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use sqlx::PgPool;
use tokio_util::sync::CancellationToken;
use tower_http::compression::CompressionLayer;
use tower_http::request_id::{MakeRequestUuid, PropagateRequestIdLayer, SetRequestIdLayer};
use tower_http::timeout::TimeoutLayer;
use tower_http::trace::TraceLayer;

use crate::auth::CurrentUser;
use crate::config::Config;

pub use error::AppError;

#[derive(Clone)]
pub struct AppState {
    pub db: PgPool,
    pub config: Arc<Config>,
}

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/", get(pages::index))
        .route("/dashboard", get(pages::dashboard))
        .route("/signup", get(auth::signup_page).post(auth::signup))
        .route("/login", get(auth::login_page).post(auth::login))
        .route("/logout", post(auth::logout))
        .route("/healthz", get(pages::healthz))
        .route("/partials/system-status", get(pages::system_status))
        .route("/static/{*path}", get(assets::serve))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            crate::auth::csrf::protect,
        ))
        .with_state(state)
        .layer(CompressionLayer::new())
        .layer(TimeoutLayer::with_status_code(
            StatusCode::REQUEST_TIMEOUT,
            Duration::from_secs(15),
        ))
        .layer(TraceLayer::new_for_http())
        .layer(PropagateRequestIdLayer::x_request_id())
        .layer(SetRequestIdLayer::x_request_id(MakeRequestUuid))
}

pub async fn serve(state: AppState, shutdown: CancellationToken) -> anyhow::Result<()> {
    let addr = state.config.bind_addr;
    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!(%addr, "web server listening");
    axum::serve(listener, router(state))
        .with_graceful_shutdown(shutdown.cancelled_owned())
        .await?;
    Ok(())
}

pub fn is_htmx(headers: &HeaderMap) -> bool {
    headers.contains_key("HX-Request")
}

/// Redirect that works for both kinds of request: htmx follows `HX-Redirect`
/// with a full page load, plain requests get `303 See Other`.
pub fn redirect(headers: &HeaderMap, to: &str) -> Response {
    if is_htmx(headers) {
        match HeaderValue::from_str(to) {
            Ok(value) => ([("HX-Redirect", value)], StatusCode::OK).into_response(),
            Err(_) => Redirect::to("/").into_response(),
        }
    } else {
        Redirect::to(to).into_response()
    }
}

/// Data the page layout needs: who is signed in and the CSRF token for forms.
pub struct Chrome {
    pub user: Option<ChromeUser>,
    pub csrf: String,
}

pub struct ChromeUser {
    pub email: String,
    pub org_name: String,
}

impl Chrome {
    pub fn anonymous() -> Self {
        Self {
            user: None,
            csrf: String::new(),
        }
    }

    pub fn signed_in(user: &CurrentUser) -> Self {
        Self {
            user: Some(ChromeUser {
                email: user.email.clone(),
                org_name: user.org_name.clone(),
            }),
            csrf: user.csrf_token.clone(),
        }
    }
}
