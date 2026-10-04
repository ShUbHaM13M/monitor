mod assets;
mod auth;
mod channels;
mod checks;
mod error;
mod ingest;
mod pages;

use std::net::SocketAddr;
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
use crate::crypto::SecretBox;
use crate::notify::Registry;

pub use error::AppError;

#[derive(Clone)]
pub struct AppState {
    pub db: PgPool,
    pub config: Arc<Config>,
    pub channels: Arc<Registry>,
    pub secrets: Arc<SecretBox>,
}

impl AppState {
    pub fn new(db: PgPool, config: Arc<Config>) -> anyhow::Result<Self> {
        Ok(Self {
            secrets: Arc::new(SecretBox::from_base64(&config.secret_key)?),
            channels: Arc::new(Registry::from_config(&config)?),
            db,
            config,
        })
    }
}

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/", get(pages::index))
        .route("/dashboard", get(checks::dashboard))
        .route("/checks/table", get(checks::table))
        .route("/checks/new", get(checks::new_page))
        .route("/checks/preview", get(checks::preview))
        .route("/checks", post(checks::create))
        .route("/checks/{id}", get(checks::show).post(checks::update))
        .route("/checks/{id}/activity", get(checks::activity_partial))
        .route("/checks/{id}/edit", get(checks::edit_page))
        .route("/checks/{id}/pause", post(checks::pause))
        .route("/checks/{id}/resume", post(checks::resume))
        .route("/checks/{id}/delete", post(checks::delete))
        .route("/channels", get(channels::list))
        .route("/channels/new", get(channels::new_picker))
        .route(
            "/channels/new/{kind}",
            get(channels::new_form).post(channels::create),
        )
        .route("/channels/{id}", get(channels::show))
        .route("/channels/{id}/test", post(channels::test))
        .route("/channels/{id}/resend", post(channels::resend))
        .route("/channels/{id}/delete", post(channels::delete))
        .route(
            "/verify-channel",
            get(channels::verify_page).post(channels::verify_confirm),
        )
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
        .merge(ingest::routes())
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
    let app = router(state).into_make_service_with_connect_info::<SocketAddr>();
    axum::serve(listener, app)
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
