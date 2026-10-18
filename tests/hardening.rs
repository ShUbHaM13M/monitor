mod common;

use std::net::SocketAddr;

use axum::Router;
use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{Request, StatusCode, header};
use monitor::db::{pings, users};
use monitor::web;
use sqlx::PgPool;
use uuid::Uuid;

use common::*;

const CHECK: &str = "name=Nightly+backup&schedule_kind=period&period_value=1&period_unit=hours&grace_value=10&grace_unit=minutes";

/// As if it came over TCP from `peer` (the in-process tests have no socket).
fn from(peer: &str, mut req: Request<Body>) -> Request<Body> {
    let addr: SocketAddr = format!("{peer}:40000").parse().unwrap();
    req.extensions_mut().insert(ConnectInfo(addr));
    req
}

fn login_form(email: &str, password: &str) -> String {
    format!("email={}&password={}", encode(email), encode(password))
}

async fn login(app: &Router, email: &str, password: &str) -> Resp {
    send(app, form_req("/login", &login_form(email, password), None)).await
}

async fn ping(app: &Router, token: &str, peer: Option<&str>, xff: Option<&str>) -> Resp {
    let mut req = Request::post(format!("/p/{token}"));
    if let Some(xff) = xff {
        req = req.header("x-forwarded-for", xff);
    }
    let req = req.body(Body::empty()).unwrap();
    send(
        app,
        match peer {
            Some(peer) => from(peer, req),
            None => req,
        },
    )
    .await
}

async fn org_id(db: &PgPool) -> Uuid {
    sqlx::query_scalar("SELECT id FROM orgs")
        .fetch_one(db)
        .await
        .unwrap()
}

// ───────────────────────────── login lockout ─────────────────────────────

#[sqlx::test]
async fn repeated_failures_lock_the_account(db: PgPool) {
    let app = app(db.clone());
    signup(&app, "ops@example.com").await;

    for _ in 0..5 {
        let res = login(&app, "ops@example.com", "wrong password!").await;
        assert!(res.body.contains("Invalid email or password."));
    }
    // Locked now: even the right password is refused, without being checked.
    let res = login(&app, "ops@example.com", PASSWORD).await;
    assert_eq!(res.status, StatusCode::UNPROCESSABLE_ENTITY);
    assert!(
        res.body
            .contains("Too many failed attempts. Try again in 1 minute"),
        "{}",
        res.body
    );
    assert!(res.session_cookie().is_none());

    // Other accounts, and unknown emails, are unaffected.
    assert!(
        login(&app, "nobody@example.com", PASSWORD)
            .await
            .body
            .contains("Invalid email or password.")
    );

    // Once the lock expires, the right password works and clears the count.
    sqlx::query("UPDATE users SET locked_until = now() - interval '1 second'")
        .execute(&db)
        .await
        .unwrap();
    let res = login(&app, "ops@example.com", PASSWORD).await;
    assert_eq!(res.status, StatusCode::SEE_OTHER, "{}", res.body);
    let (failed, locked): (i32, Option<chrono::DateTime<chrono::Utc>>) =
        sqlx::query_as("SELECT failed_logins, locked_until FROM users")
            .fetch_one(&db)
            .await
            .unwrap();
    assert_eq!((failed, locked), (0, None));
}

#[sqlx::test]
async fn locks_grow_longer_and_a_password_reset_lifts_them(db: PgPool) {
    let app = app(db.clone());
    signup(&app, "ops@example.com").await;
    let user: Uuid = sqlx::query_scalar("SELECT id FROM users")
        .fetch_one(&db)
        .await
        .unwrap();
    let lock_mins = || async {
        let mins: f64 = sqlx::query_scalar(
            "SELECT extract(epoch FROM locked_until - now())::float8 / 60 FROM users",
        )
        .fetch_one(&db)
        .await
        .unwrap();
        mins.round() as i64
    };

    for _ in 0..5 {
        login(&app, "ops@example.com", "wrong password!").await;
    }
    assert_eq!(lock_mins().await, 1);
    for expected in [2, 4, 8, 16, 32, 60, 60] {
        sqlx::query("UPDATE users SET locked_until = now() - interval '1 second'")
            .execute(&db)
            .await
            .unwrap();
        login(&app, "ops@example.com", "wrong password!").await;
        assert_eq!(lock_mins().await, expected);
    }

    let mut conn = db.acquire().await.unwrap();
    users::set_password(&mut conn, user, "irrelevant-hash")
        .await
        .unwrap();
    let (failed, locked): (i32, Option<chrono::DateTime<chrono::Utc>>) =
        sqlx::query_as("SELECT failed_logins, locked_until FROM users")
            .fetch_one(&db)
            .await
            .unwrap();
    assert_eq!((failed, locked), (0, None));
}

// ───────────────────────────── rate limits ─────────────────────────────

#[sqlx::test]
async fn login_form_is_rate_limited_per_client(db: PgPool) {
    let app = app(db);
    for _ in 0..10 {
        let req = from(
            "198.51.100.7",
            form_req(
                "/login",
                &login_form("x@example.com", "wrong password!"),
                None,
            ),
        );
        assert_eq!(
            send(&app, req).await.status,
            StatusCode::UNPROCESSABLE_ENTITY
        );
    }
    let req = from(
        "198.51.100.7",
        form_req(
            "/login",
            &login_form("x@example.com", "wrong password!"),
            None,
        ),
    );
    let res = send(&app, req).await;
    assert_eq!(res.status, StatusCode::TOO_MANY_REQUESTS);
    assert!(res.header("retry-after").parse::<u64>().unwrap() >= 1);
    assert!(res.body.contains("Too many attempts"));

    // htmx forms get the message in the page's #flash region.
    let mut req = from(
        "198.51.100.7",
        form_req("/login", &login_form("x@example.com", "x"), None),
    );
    req.headers_mut()
        .insert("HX-Request", "true".parse().unwrap());
    let res = send(&app, req).await;
    assert_eq!(res.status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(res.header("hx-retarget"), "#flash");
    assert!(res.body.starts_with(r#"<p class="form-error">"#));

    // Someone else isn't affected, and pages still load for this client.
    let other = from(
        "203.0.113.5",
        form_req(
            "/login",
            &login_form("x@example.com", "wrong password!"),
            None,
        ),
    );
    assert_eq!(
        send(&app, other).await.status,
        StatusCode::UNPROCESSABLE_ENTITY
    );
    let page = send(&app, from("198.51.100.7", get("/login", None))).await;
    assert_eq!(page.status, StatusCode::OK);
}

#[sqlx::test]
async fn pings_are_rate_limited_per_token(db: PgPool) {
    let app = app(db.clone());
    let cookie = signup(&app, "ops@example.com").await;
    let a = token_of(&db, create_check(&app, &cookie, CHECK).await).await;
    let b = token_of(&db, create_check(&app, &cookie, CHECK).await).await;

    // A burst of 60 is allowed, then one a second.
    let results = futures::future::join_all((0..80).map(|_| ping(&app, &a, None, None))).await;
    let limited: Vec<_> = results
        .iter()
        .filter(|r| r.status == StatusCode::TOO_MANY_REQUESTS)
        .collect();
    // The limiter runs before the first await, so all 80 are judged at once.
    assert_eq!(limited.len(), 20);
    assert_eq!(limited[0].header("retry-after"), "1");
    assert_eq!(ping(&app, &b, None, None).await.status, StatusCode::OK);
    let stored = count(&db, "SELECT count(*) FROM pings").await;
    assert_eq!(
        stored as usize,
        80 - limited.len() + 1,
        "rejected pings aren't stored"
    );

    // Absurd tokens are turned away before any lookup.
    let long = "x".repeat(200);
    assert_eq!(
        ping(&app, &long, None, None).await.status,
        StatusCode::NOT_FOUND
    );
}

#[sqlx::test]
async fn client_address_comes_from_trusted_proxies_only(db: PgPool) {
    let mut config = test_config();
    config.trusted_proxies = vec!["127.0.0.1/32".parse().unwrap()];
    let app = web::router(state_with(db.clone(), config));
    let cookie = signup(&app, "ops@example.com").await;
    let token = token_of(&db, create_check(&app, &cookie, CHECK).await).await;
    let last_ip = || async {
        sqlx::query_scalar::<_, String>(
            "SELECT host(source_ip) FROM pings ORDER BY id DESC LIMIT 1",
        )
        .fetch_one(&db)
        .await
        .unwrap()
    };

    // Via our proxy: the address it saw, not the one the client made up.
    ping(
        &app,
        &token,
        Some("127.0.0.1"),
        Some("6.6.6.6, 198.51.100.7"),
    )
    .await;
    assert_eq!(last_ip().await, "198.51.100.7");
    // Directly: the header is ignored.
    ping(&app, &token, Some("203.0.113.5"), Some("6.6.6.6")).await;
    assert_eq!(last_ip().await, "203.0.113.5");
}

// ───────────────────────────── retention ─────────────────────────────

#[sqlx::test]
async fn old_and_excess_pings_are_purged(db: PgPool) {
    let app = app(db.clone());
    let cookie = signup(&app, "ops@example.com").await;
    let busy = create_check(&app, &cookie, CHECK).await;
    let quiet = create_check(&app, &cookie, CHECK).await;

    // 150 recent pings, one a minute, on one check; 3 on the other, one of them 40 days old.
    sqlx::query(
        "INSERT INTO pings (check_id, kind, created_at)
         SELECT $1, 'success', now() - make_interval(mins => n) FROM generate_series(1, 150) n",
    )
    .bind(busy)
    .execute(&db)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO pings (check_id, kind, created_at)
         VALUES ($1, 'success', now()), ($1, 'success', now() - interval '1 day'),
                ($1, 'fail', now() - interval '40 days')",
    )
    .bind(quiet)
    .execute(&db)
    .await
    .unwrap();
    // An old ping that caused an incident survives with it.
    let cause: i64 = sqlx::query_scalar(
        "INSERT INTO pings (check_id, kind, created_at) VALUES ($1, 'fail', now() - interval '60 days') RETURNING id",
    )
    .bind(quiet)
    .fetch_one(&db)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO incidents (id, org_id, check_id, reason, cause_ping_id, started_at, resolved_at)
         VALUES (gen_random_uuid(), $1, $2, 'failed', $3, now() - interval '60 days', now() - interval '59 days')",
    )
    .bind(org_id(&db).await)
    .bind(quiet)
    .bind(cause)
    .execute(&db)
    .await
    .unwrap();

    let deleted = pings::purge(&db).await.unwrap();
    assert_eq!(deleted, 50 + 1);
    let per_check = |id: Uuid| {
        let db = db.clone();
        async move {
            sqlx::query_scalar::<_, i64>("SELECT count(*) FROM pings WHERE check_id = $1")
                .bind(id)
                .fetch_one(&db)
                .await
                .unwrap()
        }
    };
    assert_eq!(per_check(busy).await, pings::KEEP_PER_CHECK);
    assert_eq!(per_check(quiet).await, 3);
    // The newest were kept.
    let oldest_kept: f64 = sqlx::query_scalar(
        "SELECT extract(epoch FROM now() - min(created_at))::float8 / 60 FROM pings WHERE check_id = $1",
    )
    .bind(busy)
    .fetch_one(&db)
    .await
    .unwrap();
    assert_eq!(oldest_kept.round(), 100.0);
    assert_eq!(pings::purge(&db).await.unwrap(), 0, "idempotent");
}

// ───────────────────────────── plan limits ─────────────────────────────

#[sqlx::test]
async fn plan_limits_cap_what_an_org_can_create(db: PgPool) {
    let app = app(db.clone());
    let cookie = signup(&app, "ops@example.com").await;
    sqlx::query(
        "UPDATE orgs SET max_checks = 2, max_channels = 0, min_monitor_interval_secs = 300",
    )
    .execute(&db)
    .await
    .unwrap();
    let csrf = csrf_token(&app, &cookie).await;

    create_check(&app, &cookie, CHECK).await;
    create_check(&app, &cookie, CHECK).await;
    let res = send(
        &app,
        form_req("/checks", &format!("_csrf={csrf}&{CHECK}"), Some(&cookie)),
    )
    .await;
    assert_eq!(res.status, StatusCode::UNPROCESSABLE_ENTITY);
    assert!(res.body.contains("Your plan allows 2 checks."));
    assert_eq!(count(&db, "SELECT count(*) FROM checks").await, 2);

    let overview = send(&app, get("/dashboard", Some(&cookie))).await;
    assert!(overview.body.contains("2 of 2 on your plan"));

    let form = send(&app, get("/monitors/new", Some(&cookie))).await;
    assert!(form.body.contains("(not on your plan)"));
    assert!(
        form.body.contains(r#"<option value="300" selected>"#),
        "defaults to the shortest allowed"
    );
    let monitor = format!(
        "_csrf={csrf}&name=API&method=GET&url={}&interval_secs=60&timeout_secs=5&fail_threshold=2",
        encode("https://example.com/")
    );
    let res = send(&app, form_req("/monitors", &monitor, Some(&cookie))).await;
    assert_eq!(res.status, StatusCode::UNPROCESSABLE_ENTITY);
    assert!(
        res.body
            .contains("Your plan checks at most every 5 minutes."),
        "{}",
        res.body
    );
    let ok = monitor.replace("interval_secs=60", "interval_secs=300");
    assert_eq!(
        send(&app, form_req("/monitors", &ok, Some(&cookie)))
            .await
            .status,
        StatusCode::SEE_OTHER
    );

    let channel = format!("_csrf={csrf}&url={}", encode("https://hooks.example.com/x"));
    let res = send(
        &app,
        form_req("/channels/new/webhook", &channel, Some(&cookie)),
    )
    .await;
    assert_eq!(res.status, StatusCode::UNPROCESSABLE_ENTITY);
    assert!(res.body.contains("Your plan allows 0 alert channels."));
}

#[sqlx::test]
async fn concurrent_creates_cannot_overshoot_the_limit(db: PgPool) {
    let app = app(db.clone());
    let cookie = signup(&app, "ops@example.com").await;
    sqlx::query("UPDATE orgs SET max_checks = 3")
        .execute(&db)
        .await
        .unwrap();
    let csrf = csrf_token(&app, &cookie).await;
    let body = format!("_csrf={csrf}&{CHECK}");
    let results = futures::future::join_all(
        (0..8).map(|_| send(&app, form_req("/checks", &body, Some(&cookie)))),
    )
    .await;
    let created = results
        .iter()
        .filter(|r| r.status == StatusCode::SEE_OTHER)
        .count();
    assert_eq!(created, 3);
    assert_eq!(count(&db, "SELECT count(*) FROM checks").await, 3);
}

// ───────────────────────────── headers ─────────────────────────────

#[sqlx::test]
async fn responses_carry_security_headers(db: PgPool) {
    let app = app(db.clone());
    let page = send(&app, get("/login", None)).await;
    let csp = page.header("content-security-policy");
    assert!(csp.contains("script-src 'self'"));
    assert!(!csp.contains("unsafe-inline") && !csp.contains("unsafe-eval"));
    assert!(csp.contains("frame-ancestors 'none'"));
    assert_eq!(page.header("x-content-type-options"), "nosniff");
    assert_eq!(page.header("x-frame-options"), "DENY");
    assert_eq!(page.header("referrer-policy"), "same-origin");
    assert!(
        page.headers
            .get(header::STRICT_TRANSPORT_SECURITY)
            .is_none(),
        "plain HTTP: no HSTS"
    );
    // htmx is told not to eval or inject styles, which the policy would block.
    assert!(page.body.contains(r#""allowEval":false"#));
    assert!(page.body.contains(r#""includeIndicatorStyles":false"#));
    assert!(
        !page.body.contains("[!"),
        "no htmx trigger filters (they need eval)"
    );

    let mut config = test_config();
    config.base_url = "https://monitor.example.com".into();
    let app = web::router(state_with(db, config));
    let page = send(&app, get("/healthz", None)).await;
    assert!(
        page.header("strict-transport-security")
            .starts_with("max-age=")
    );
}
