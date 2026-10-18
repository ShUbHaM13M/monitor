//! Helpers shared by the integration tests.
#![allow(dead_code)]

use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use axum::http::{HeaderMap, Request, StatusCode, header};
use http_body_util::BodyExt;
use monitor::config::{Config, LogFormat};
use monitor::web::{self, AppState};
use serde_json::Value;
use sqlx::PgPool;
use tower::ServiceExt;
use uuid::Uuid;

pub const ORIGIN: &str = "http://localhost:3000";
pub const PASSWORD: &str = "correct horse battery";

/// Fixed key so tests are reproducible; never used outside tests.
pub const TEST_SECRET_KEY: &str = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=";
/// Mailpit from docker-compose.
pub const SMTP_URL: &str = "smtp://localhost:1025";
pub const MAILPIT_API: &str = "http://localhost:8025/api/v1";

pub fn test_config() -> Config {
    Config {
        database_url: String::new(),
        db_max_connections: 1,
        bind_addr: "127.0.0.1:0".parse().unwrap(),
        base_url: ORIGIN.into(),
        auto_migrate: false,
        log_format: LogFormat::Pretty,
        secret_key: TEST_SECRET_KEY.into(),
        smtp_url: Some(SMTP_URL.into()),
        smtp_from: "Monitor <alerts@monitor.test>".into(),
        // Webhook tests target a local wiremock server.
        allow_private_targets: true,
        trusted_proxies: Vec::new(),
        metrics_addr: None,
        plan: Default::default(),
    }
}

pub fn state_with(db: PgPool, config: Config) -> AppState {
    AppState::new(db, Arc::new(config)).unwrap()
}

pub fn state(db: PgPool) -> AppState {
    state_with(db, test_config())
}

pub fn app(db: PgPool) -> Router {
    web::router(state(db))
}

pub struct Resp {
    pub status: StatusCode,
    pub headers: HeaderMap,
    pub body: String,
}

impl Resp {
    pub fn header(&self, name: &str) -> &str {
        self.headers
            .get(name)
            .map(|v| v.to_str().unwrap())
            .unwrap_or_default()
    }

    /// `session=<token>` from Set-Cookie, if a non-empty session cookie was set.
    pub fn session_cookie(&self) -> Option<String> {
        self.headers
            .get_all(header::SET_COOKIE)
            .iter()
            .map(|v| v.to_str().unwrap())
            .find(|c| c.starts_with("session=") && !c.starts_with("session=;"))
            .map(|c| c.split(';').next().unwrap().to_owned())
    }
}

pub async fn send(app: &Router, req: Request<Body>) -> Resp {
    let res = app.clone().oneshot(req).await.unwrap();
    let status = res.status();
    let headers = res.headers().clone();
    let bytes = res.into_body().collect().await.unwrap().to_bytes();
    Resp {
        status,
        headers,
        body: String::from_utf8(bytes.to_vec()).unwrap(),
    }
}

pub fn get(path: &str, cookie: Option<&str>) -> Request<Body> {
    let mut req = Request::get(path);
    if let Some(cookie) = cookie {
        req = req.header(header::COOKIE, cookie);
    }
    req.body(Body::empty()).unwrap()
}

pub fn post_form(path: &str, cookie: Option<&str>) -> axum::http::request::Builder {
    let mut req = Request::post(path)
        .header(header::ORIGIN, ORIGIN)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
    if let Some(cookie) = cookie {
        req = req.header(header::COOKIE, cookie);
    }
    req
}

pub fn form_req(path: &str, form: &str, cookie: Option<&str>) -> Request<Body> {
    post_form(path, cookie)
        .body(Body::from(form.to_owned()))
        .unwrap()
}

pub fn encode(s: &str) -> String {
    form_urlencoded::byte_serialize(s.as_bytes()).collect()
}

pub async fn signup(app: &Router, email: &str) -> String {
    let body = format!("email={}&password={}", encode(email), encode(PASSWORD));
    let res = send(app, form_req("/signup", &body, None)).await;
    assert_eq!(
        res.status,
        StatusCode::SEE_OTHER,
        "signup failed: {}",
        res.body
    );
    res.session_cookie().expect("signup sets a session cookie")
}

/// The CSRF token rendered into the page layout for a signed-in user.
pub async fn csrf_token(app: &Router, cookie: &str) -> String {
    let res = send(app, get("/dashboard", Some(cookie))).await;
    assert_eq!(res.status, StatusCode::OK);
    let marker = r#"name="_csrf" value=""#;
    let start = res.body.find(marker).expect("csrf field in page") + marker.len();
    let len = res.body[start..].find('"').unwrap();
    res.body[start..start + len].to_owned()
}

pub async fn count(db: &PgPool, sql: &'static str) -> i64 {
    sqlx::query_scalar(sql).fetch_one(db).await.unwrap()
}

/// Creates a check through the UI and returns its id.
pub async fn create_check(app: &Router, cookie: &str, form: &str) -> uuid::Uuid {
    let csrf = csrf_token(app, cookie).await;
    let body = format!("_csrf={csrf}&{form}");
    let res = send(app, form_req("/checks", &body, Some(cookie))).await;
    assert_eq!(
        res.status,
        StatusCode::SEE_OTHER,
        "create failed: {}",
        res.body
    );
    let location = res.header("location");
    location
        .strip_prefix("/checks/")
        .and_then(|id| id.parse().ok())
        .unwrap_or_else(|| panic!("unexpected redirect {location:?}"))
}

/// The ping token of a check, read straight from the database.
pub async fn token_of(db: &PgPool, check_id: uuid::Uuid) -> String {
    sqlx::query_scalar("SELECT token FROM checks WHERE id = $1")
        .bind(check_id)
        .fetch_one(db)
        .await
        .unwrap()
}

// ───────────────────────────── Mailpit ─────────────────────────────

/// Mailpit messages to `address`, newest first, as (id, subject).
pub async fn inbox(address: &str) -> Vec<(String, String)> {
    inbox_with_at_least(address, 0).await
}

/// Like [`inbox`], but waits (up to 3s) for `n` messages: some mail is sent in
/// the background.
pub async fn inbox_with_at_least(address: &str, n: usize) -> Vec<(String, String)> {
    for _ in 0..60 {
        let messages = fetch_inbox(address).await;
        if messages.len() >= n {
            return messages;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    fetch_inbox(address).await
}

async fn fetch_inbox(address: &str) -> Vec<(String, String)> {
    let url = format!(
        "{MAILPIT_API}/search?query={}",
        encode(&format!("to:\"{address}\""))
    );
    let json: Value = reqwest::get(url).await.unwrap().json().await.unwrap();
    json["messages"]
        .as_array()
        .unwrap()
        .iter()
        .map(|m| {
            (
                m["ID"].as_str().unwrap().to_owned(),
                m["Subject"].as_str().unwrap().to_owned(),
            )
        })
        .collect()
}

pub async fn message_text(id: &str) -> String {
    let json: Value = reqwest::get(format!("{MAILPIT_API}/message/{id}"))
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    json["Text"].as_str().unwrap().to_owned()
}

pub fn unique_address(tag: &str) -> String {
    format!("{tag}-{}@example.com", Uuid::new_v4().simple())
}

/// The first link in `text` that starts with `ORIGIN` + `path`, as a path.
pub fn link_path(text: &str, path: &str) -> String {
    let prefix = format!("{ORIGIN}{path}");
    let link = text
        .split_whitespace()
        .find(|w| w.starts_with(&prefix))
        .unwrap_or_else(|| panic!("no {prefix} link in {text:?}"));
    link.strip_prefix(ORIGIN).unwrap().to_owned()
}
