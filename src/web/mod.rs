mod account;
mod assets;
mod auth;
mod channels;
mod charts;
mod checks;
pub mod client_ip;
mod error;
mod filter;
mod incidents;
mod ingest;
mod monitors;
mod overview;
mod pages;
pub mod ratelimit;
mod stamp;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::extract::{Request, State};
use axum::http::{HeaderMap, HeaderName, HeaderValue, StatusCode, header};
use axum::middleware::{self, Next};
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
use crate::mail::Mailer;
use crate::notify::Registry;

pub use error::AppError;

#[derive(Clone)]
pub struct AppState {
    pub db: PgPool,
    pub config: Arc<Config>,
    pub channels: Arc<Registry>,
    pub secrets: Arc<SecretBox>,
    /// `None` when `SMTP_URL` isn't set: no email channels, verification or resets.
    pub mailer: Option<Arc<Mailer>>,
    /// SSRF-guarded client for user-supplied URLs (HTTP monitors).
    pub http: reqwest::Client,
    pub limits: Arc<ratelimit::Limits>,
}

impl AppState {
    pub fn new(db: PgPool, config: Arc<Config>) -> anyhow::Result<Self> {
        let mailer = match &config.smtp_url {
            Some(url) => Some(Arc::new(Mailer::new(url, &config.smtp_from)?)),
            None => None,
        };
        Ok(Self {
            secrets: Arc::new(SecretBox::from_base64(&config.secret_key)?),
            channels: Arc::new(Registry::from_config(&config, mailer.clone())),
            http: crate::notify::http::client(config.allow_private_targets),
            limits: Arc::default(),
            mailer,
            db,
            config,
        })
    }
}

/// No inline script or style, no eval, nothing from other origins, never framed.
/// htmx is configured to match (see `layout.html`).
const CSP: &str = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; \
                   connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'";

/// Headers on every response, unless a handler set its own.
async fn security_headers(State(state): State<AppState>, req: Request, next: Next) -> Response {
    let mut res = next.run(req).await;
    let headers = res.headers_mut();
    let mut set = |name: HeaderName, value: &'static str| {
        headers
            .entry(name)
            .or_insert(HeaderValue::from_static(value));
    };
    set(header::CONTENT_SECURITY_POLICY, CSP);
    set(header::X_CONTENT_TYPE_OPTIONS, "nosniff");
    set(header::X_FRAME_OPTIONS, "DENY");
    // Tokens travel in some URLs (confirmation and reset links); don't leak them.
    set(header::REFERRER_POLICY, "same-origin");
    set(
        HeaderName::from_static("cross-origin-opener-policy"),
        "same-origin",
    );
    set(
        HeaderName::from_static("permissions-policy"),
        "camera=(), microphone=(), geolocation=(), payment=()",
    );
    if state.config.secure_cookies() {
        set(
            header::STRICT_TRANSPORT_SECURITY,
            "max-age=31536000; includeSubDomains",
        );
    }
    res
}

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/", get(pages::index))
        .route("/dashboard", get(overview::page))
        .route("/dashboard/live", get(overview::live_partial))
        .route("/nav/health", get(overview::health))
        .route("/incidents", get(incidents::list))
        .route("/checks/table", get(checks::table))
        .route("/checks/new", get(checks::new_page))
        .route("/checks/preview", get(checks::preview))
        .route("/checks", get(checks::list).post(checks::create))
        .route("/checks/{id}", get(checks::show).post(checks::update))
        .route("/checks/{id}/activity", get(checks::activity_partial))
        .route("/checks/{id}/edit", get(checks::edit_page))
        .route("/checks/{id}/pause", post(checks::pause))
        .route("/checks/{id}/resume", post(checks::resume))
        .route("/checks/{id}/delete", post(checks::delete))
        .route("/monitors", get(monitors::list).post(monitors::create))
        .route("/monitors/table", get(monitors::table))
        .route("/monitors/new", get(monitors::new_page))
        .route("/monitors/{id}", get(monitors::show).post(monitors::update))
        .route("/monitors/{id}/activity", get(monitors::activity_partial))
        .route("/monitors/{id}/edit", get(monitors::edit_page))
        .route("/monitors/{id}/check", post(monitors::check_now))
        .route("/monitors/{id}/pause", post(monitors::pause))
        .route("/monitors/{id}/resume", post(monitors::resume))
        .route("/monitors/{id}/delete", post(monitors::delete))
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
        .route(
            "/verify-email",
            get(account::verify_page).post(account::verify_confirm),
        )
        .route("/verify-email/resend", post(account::resend_verification))
        .route(
            "/forgot-password",
            get(account::forgot_page).post(account::forgot),
        )
        .route(
            "/reset-password",
            get(account::reset_page).post(account::reset),
        )
        .route("/healthz", get(pages::healthz))
        .route("/partials/system-status", get(pages::system_status))
        .route("/static/{*path}", get(assets::serve))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            crate::auth::csrf::protect,
        ))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            ratelimit::protect_forms,
        ))
        .merge(ingest::routes())
        .layer(middleware::from_fn(crate::telemetry::track_http))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            security_headers,
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

/// Form error for a create that would exceed the org's plan.
pub(crate) fn plan_limit_message(limit: i32, noun: &str) -> String {
    format!(
        "Your plan allows {limit} {noun}. Delete one you no longer need, or ask us to raise the limit."
    )
}

/// Turns a plan-limit failure into a form error; database errors propagate.
pub(crate) fn created(
    result: Result<uuid::Uuid, crate::db::orgs::CreateError>,
    noun: &str,
) -> Result<Result<uuid::Uuid, String>, AppError> {
    use crate::db::orgs::CreateError;
    match result {
        Ok(id) => Ok(Ok(id)),
        Err(CreateError::LimitReached(limit)) => Ok(Err(plan_limit_message(limit, noun))),
        Err(CreateError::Db(err)) => Err(err.into()),
    }
}

/// Data the page layout needs: who is signed in and the CSRF token for forms.
pub struct Chrome {
    pub user: Option<ChromeUser>,
    pub csrf: String,
    /// Show the "confirm your email" banner.
    pub verify_banner: bool,
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
            verify_banner: false,
        }
    }

    pub fn signed_in(user: &CurrentUser) -> Self {
        Self {
            user: Some(ChromeUser {
                email: user.email.clone(),
                org_name: user.org_name.clone(),
            }),
            csrf: user.csrf_token.clone(),
            verify_banner: user.needs_email_verification,
        }
    }
}
