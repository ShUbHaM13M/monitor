use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use axum::http::{HeaderMap, Request, StatusCode, header};
use http_body_util::BodyExt;
use monitor::auth::session;
use monitor::config::{Config, LogFormat};
use monitor::web::{self, AppState};
use sqlx::PgPool;
use tower::ServiceExt;

const ORIGIN: &str = "http://localhost:3000";
const PASSWORD: &str = "correct horse battery";

fn app(db: PgPool) -> Router {
    let config = Config {
        database_url: String::new(),
        db_max_connections: 1,
        bind_addr: "127.0.0.1:0".parse().unwrap(),
        base_url: ORIGIN.into(),
        auto_migrate: false,
        log_format: LogFormat::Pretty,
    };
    web::router(AppState {
        db,
        config: Arc::new(config),
    })
}

struct Resp {
    status: StatusCode,
    headers: HeaderMap,
    body: String,
}

impl Resp {
    fn header(&self, name: &str) -> &str {
        self.headers
            .get(name)
            .map(|v| v.to_str().unwrap())
            .unwrap_or_default()
    }

    /// `session=<token>` from Set-Cookie, if a non-empty session cookie was set.
    fn session_cookie(&self) -> Option<String> {
        self.headers
            .get_all(header::SET_COOKIE)
            .iter()
            .map(|v| v.to_str().unwrap())
            .find(|c| c.starts_with("session=") && !c.starts_with("session=;"))
            .map(|c| c.split(';').next().unwrap().to_owned())
    }
}

async fn send(app: &Router, req: Request<Body>) -> Resp {
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

fn get(path: &str, cookie: Option<&str>) -> Request<Body> {
    let mut req = Request::get(path);
    if let Some(cookie) = cookie {
        req = req.header(header::COOKIE, cookie);
    }
    req.body(Body::empty()).unwrap()
}

fn post_form(path: &str, cookie: Option<&str>) -> axum::http::request::Builder {
    let mut req = Request::post(path)
        .header(header::ORIGIN, ORIGIN)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
    if let Some(cookie) = cookie {
        req = req.header(header::COOKIE, cookie);
    }
    req
}

fn form_req(path: &str, form: &str, cookie: Option<&str>) -> Request<Body> {
    post_form(path, cookie)
        .body(Body::from(form.to_owned()))
        .unwrap()
}

fn encode(s: &str) -> String {
    form_urlencoded::byte_serialize(s.as_bytes()).collect()
}

async fn signup(app: &Router, email: &str) -> String {
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
async fn csrf_token(app: &Router, cookie: &str) -> String {
    let res = send(app, get("/dashboard", Some(cookie))).await;
    assert_eq!(res.status, StatusCode::OK);
    let marker = r#"name="_csrf" value=""#;
    let start = res.body.find(marker).expect("csrf field in page") + marker.len();
    let len = res.body[start..].find('"').unwrap();
    res.body[start..start + len].to_owned()
}

async fn count(db: &PgPool, sql: &'static str) -> i64 {
    sqlx::query_scalar(sql).fetch_one(db).await.unwrap()
}

#[sqlx::test]
async fn signup_creates_account_org_project_and_session(db: PgPool) {
    let app = app(db.clone());
    let body = format!(
        "email={}&password={}",
        encode("ops@example.com"),
        encode(PASSWORD)
    );
    let res = send(&app, form_req("/signup", &body, None)).await;

    assert_eq!(res.status, StatusCode::SEE_OTHER);
    assert_eq!(res.header("location"), "/dashboard");
    let set_cookie = res.header("set-cookie");
    assert!(set_cookie.contains("HttpOnly"), "{set_cookie}");
    assert!(set_cookie.contains("SameSite=Lax"), "{set_cookie}");
    assert!(set_cookie.contains("Path=/"), "{set_cookie}");
    assert!(
        !set_cookie.contains("Secure"),
        "http base url must not set Secure"
    );

    assert_eq!(count(&db, "SELECT count(*) FROM users").await, 1);
    assert_eq!(
        count(&db, "SELECT count(*) FROM orgs WHERE name = 'ops''s org'").await,
        1
    );
    assert_eq!(
        count(&db, "SELECT count(*) FROM memberships WHERE role = 'owner'").await,
        1
    );
    assert_eq!(
        count(&db, "SELECT count(*) FROM projects WHERE name = 'Default'").await,
        1
    );
    assert_eq!(count(&db, "SELECT count(*) FROM sessions").await, 1);

    let cookie = res.session_cookie().unwrap();
    let dash = send(&app, get("/dashboard", Some(&cookie))).await;
    assert_eq!(dash.status, StatusCode::OK);
    assert!(dash.body.contains("ops&#39;s org") || dash.body.contains("ops's org"));
    assert!(dash.body.contains("Default"));
}

#[sqlx::test]
async fn signup_rejects_duplicate_email_case_insensitively(db: PgPool) {
    let app = app(db.clone());
    signup(&app, "ops@example.com").await;

    let body = format!(
        "email={}&password={}",
        encode("OPS@Example.com"),
        encode(PASSWORD)
    );
    let res = send(&app, form_req("/signup", &body, None)).await;
    assert_eq!(res.status, StatusCode::UNPROCESSABLE_ENTITY);
    assert!(res.body.contains("already exists"));
    assert_eq!(count(&db, "SELECT count(*) FROM users").await, 1);
    assert_eq!(count(&db, "SELECT count(*) FROM orgs").await, 1);
}

#[sqlx::test]
async fn signup_validation_error_htmx_returns_partial(db: PgPool) {
    let app = app(db);
    let req = post_form("/signup", None)
        .header("HX-Request", "true")
        .body(Body::from("email=ops%40example.com&password=short"))
        .unwrap();
    let res = send(&app, req).await;
    assert_eq!(res.status, StatusCode::UNPROCESSABLE_ENTITY);
    assert!(res.body.contains("at least 10 characters"));
    assert!(res.body.contains("ops@example.com"), "email is kept");
    assert!(!res.body.contains("<html"), "htmx gets only the form");
}

#[sqlx::test]
async fn login_rejects_bad_credentials_generically(db: PgPool) {
    let app = app(db);
    signup(&app, "ops@example.com").await;

    for body in [
        "email=ops%40example.com&password=wrong+password+here",
        "email=nobody%40example.com&password=correct+horse+battery",
    ] {
        let res = send(&app, form_req("/login", body, None)).await;
        assert_eq!(res.status, StatusCode::UNPROCESSABLE_ENTITY);
        assert!(res.body.contains("Invalid email or password."));
        assert!(res.session_cookie().is_none());
    }
}

#[sqlx::test]
async fn login_issues_fresh_token_and_invalidates_the_old_one(db: PgPool) {
    let app = app(db.clone());
    let old = signup(&app, "ops@example.com").await;
    let csrf = csrf_token(&app, &old).await;

    let body = format!(
        "email=OPS%40example.com&password={}&next=%2Fdashboard%3Ftab%3D1",
        encode(PASSWORD)
    );
    let req = post_form("/login", Some(&old))
        .header("X-CSRF-Token", csrf)
        .body(Body::from(body))
        .unwrap();
    let res = send(&app, req).await;
    assert_eq!(res.status, StatusCode::SEE_OTHER);
    assert_eq!(res.header("location"), "/dashboard?tab=1");

    let new = res.session_cookie().unwrap();
    assert_ne!(new, old);
    assert_eq!(
        send(&app, get("/dashboard", Some(&new))).await.status,
        StatusCode::OK
    );
    assert_eq!(
        send(&app, get("/dashboard", Some(&old))).await.status,
        StatusCode::SEE_OTHER
    );
    assert_eq!(count(&db, "SELECT count(*) FROM sessions").await, 1);
}

#[sqlx::test]
async fn login_ignores_offsite_next(db: PgPool) {
    let app = app(db);
    signup(&app, "ops@example.com").await;
    let body = format!(
        "email=ops%40example.com&password={}&next=%2F%2Fevil.com",
        encode(PASSWORD)
    );
    let res = send(&app, form_req("/login", &body, None)).await;
    assert_eq!(res.status, StatusCode::SEE_OTHER);
    assert_eq!(res.header("location"), "/dashboard");
}

#[sqlx::test]
async fn protected_pages_redirect_to_login(db: PgPool) {
    let app = app(db);

    let res = send(&app, get("/dashboard?x=1", None)).await;
    assert_eq!(res.status, StatusCode::SEE_OTHER);
    assert_eq!(res.header("location"), "/login?next=%2Fdashboard%3Fx%3D1");

    let req = Request::get("/dashboard")
        .header("HX-Request", "true")
        .body(Body::empty())
        .unwrap();
    let res = send(&app, req).await;
    assert_eq!(res.status, StatusCode::UNAUTHORIZED);
    assert_eq!(res.header("hx-redirect"), "/login");

    let res = send(&app, get("/dashboard", Some("session=forged"))).await;
    assert_eq!(res.status, StatusCode::SEE_OTHER);
}

#[sqlx::test]
async fn csrf_is_enforced_on_state_changing_requests(db: PgPool) {
    let app = app(db.clone());
    let cookie = signup(&app, "ops@example.com").await;
    let csrf = csrf_token(&app, &cookie).await;

    // Session but no token.
    let res = send(&app, form_req("/logout", "", Some(&cookie))).await;
    assert_eq!(res.status, StatusCode::FORBIDDEN);

    // Wrong token.
    let req = post_form("/logout", Some(&cookie))
        .header("X-CSRF-Token", "nope")
        .body(Body::empty())
        .unwrap();
    assert_eq!(send(&app, req).await.status, StatusCode::FORBIDDEN);

    // Right token, foreign origin.
    let req = Request::post("/logout")
        .header(header::ORIGIN, "https://evil.example")
        .header(header::COOKIE, &cookie)
        .header("X-CSRF-Token", &csrf)
        .body(Body::empty())
        .unwrap();
    assert_eq!(send(&app, req).await.status, StatusCode::FORBIDDEN);

    // No Origin or Referer at all (e.g. curl).
    let req = Request::post("/logout")
        .header(header::COOKIE, &cookie)
        .header("X-CSRF-Token", &csrf)
        .body(Body::empty())
        .unwrap();
    assert_eq!(send(&app, req).await.status, StatusCode::FORBIDDEN);

    // Anonymous forms still need a same-origin request (login CSRF).
    let req = Request::post("/login")
        .header(header::ORIGIN, "https://evil.example")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(Body::from("email=a%40b.co&password=x"))
        .unwrap();
    assert_eq!(send(&app, req).await.status, StatusCode::FORBIDDEN);

    assert_eq!(count(&db, "SELECT count(*) FROM sessions").await, 1);

    // Token in the form field works, and logout deletes the session.
    let body = format!("_csrf={csrf}");
    let res = send(&app, form_req("/logout", &body, Some(&cookie))).await;
    assert_eq!(res.status, StatusCode::SEE_OTHER);
    assert_eq!(res.header("location"), "/login");
    assert!(res.header("set-cookie").starts_with("session=;"));
    assert_eq!(count(&db, "SELECT count(*) FROM sessions").await, 0);
}

#[sqlx::test]
async fn csrf_header_works_for_htmx(db: PgPool) {
    let app = app(db.clone());
    let cookie = signup(&app, "ops@example.com").await;
    let csrf = csrf_token(&app, &cookie).await;

    let req = Request::post("/logout")
        .header(header::ORIGIN, ORIGIN)
        .header(header::COOKIE, &cookie)
        .header("HX-Request", "true")
        .header("X-CSRF-Token", &csrf)
        .body(Body::empty())
        .unwrap();
    let res = send(&app, req).await;
    assert_eq!(res.status, StatusCode::OK);
    assert_eq!(res.header("hx-redirect"), "/login");
    assert_eq!(count(&db, "SELECT count(*) FROM sessions").await, 0);
}

#[sqlx::test]
async fn users_only_see_their_own_org(db: PgPool) {
    let app = app(db.clone());
    let alice = signup(&app, "alice@example.com").await;
    let bob = signup(&app, "bob@example.com").await;

    sqlx::query(
        "INSERT INTO projects (id, org_id, name)
         SELECT gen_random_uuid(), m.org_id, 'Alice secret project'
         FROM memberships m JOIN users u ON u.id = m.user_id
         WHERE u.email = 'alice@example.com'",
    )
    .execute(&db)
    .await
    .unwrap();

    let alice_dash = send(&app, get("/dashboard", Some(&alice))).await;
    assert!(alice_dash.body.contains("Alice secret project"));
    assert!(alice_dash.body.contains("alice&#39;s org") || alice_dash.body.contains("alice's org"));

    let bob_dash = send(&app, get("/dashboard", Some(&bob))).await;
    assert_eq!(bob_dash.status, StatusCode::OK);
    assert!(!bob_dash.body.contains("Alice secret project"));
    assert!(!bob_dash.body.contains("alice"));
}

#[sqlx::test]
async fn expired_sessions_are_rejected_and_cleaned_up(db: PgPool) {
    let app = app(db.clone());
    let cookie = signup(&app, "ops@example.com").await;

    sqlx::query("UPDATE sessions SET expires_at = now() - interval '1 second'")
        .execute(&db)
        .await
        .unwrap();
    let res = send(&app, get("/dashboard", Some(&cookie))).await;
    assert_eq!(res.status, StatusCode::SEE_OTHER);

    assert_eq!(session::delete_expired(&db).await.unwrap(), 1);
    assert_eq!(count(&db, "SELECT count(*) FROM sessions").await, 0);
}

#[sqlx::test]
async fn logged_in_users_skip_public_pages(db: PgPool) {
    let app = app(db);
    let cookie = signup(&app, "ops@example.com").await;
    for path in ["/", "/login", "/signup"] {
        let res = send(&app, get(path, Some(&cookie))).await;
        assert_eq!(res.status, StatusCode::SEE_OTHER, "{path}");
        assert_eq!(res.header("location"), "/dashboard", "{path}");
    }
}
