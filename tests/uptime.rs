//! HTTP uptime monitors end to end: the prober against wiremock targets, state
//! transitions, incidents and alerts, rollups, retention and the UI.

mod common;

use std::time::Duration;

use axum::Router;
use axum::body::Body;
use axum::http::StatusCode;
use monitor::db::monitors;
use monitor::web::{self, AppState};
use monitor::worker::{notifier, prober};
use serde_json::Value;
use sqlx::PgPool;
use uuid::Uuid;
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use common::*;

struct Ctx {
    db: PgPool,
    state: AppState,
    app: Router,
    cookie: String,
}

async fn setup(db: PgPool) -> Ctx {
    let state = state(db.clone());
    let app = web::router(state.clone());
    let cookie = signup(&app, "ops@example.com").await;
    Ctx {
        db,
        state,
        app,
        cookie,
    }
}

impl Ctx {
    async fn post(&self, path: &str, form: &str) -> Resp {
        let csrf = csrf_token(&self.app, &self.cookie).await;
        send(
            &self.app,
            form_req(path, &format!("_csrf={csrf}&{form}"), Some(&self.cookie)),
        )
        .await
    }

    /// `extra` fields (`&key=value…`) replace the defaults of the same name.
    async fn create_monitor(&self, url: &str, extra: &str) -> Uuid {
        let mut form = format!("name=API&method=GET&url={}&interval_secs=60", encode(url));
        for (key, default) in [("timeout_secs", "5"), ("fail_threshold", "2")] {
            if !extra.contains(&format!("&{key}=")) {
                form.push_str(&format!("&{key}={default}"));
            }
        }
        let res = self.post("/monitors", &format!("{form}{extra}")).await;
        assert_eq!(res.status, StatusCode::SEE_OTHER, "{}", res.body);
        res.header("location")
            .strip_prefix("/monitors/")
            .unwrap()
            .parse()
            .unwrap()
    }

    /// Makes every monitor due and runs one prober tick.
    async fn probe_all(&self) -> usize {
        sqlx::query("UPDATE http_monitors SET next_run_at = now() WHERE status <> 'paused'")
            .execute(&self.db)
            .await
            .unwrap();
        prober::tick(&self.state).await.unwrap()
    }

    async fn status(&self, id: Uuid) -> (String, i32, Option<String>) {
        sqlx::query_as(
            "SELECT status, consecutive_failures, last_error FROM http_monitors WHERE id = $1",
        )
        .bind(id)
        .fetch_one(&self.db)
        .await
        .unwrap()
    }

    async fn deliver(&self) -> usize {
        notifier::tick(&self.db, &self.state.channels, &self.state.secrets)
            .await
            .unwrap()
    }
}

async fn target(status: u16, body: &str) -> MockServer {
    let server = MockServer::start().await;
    respond(&server, ResponseTemplate::new(status).set_body_string(body)).await;
    server
}

async fn respond(server: &MockServer, template: ResponseTemplate) {
    server.reset().await;
    Mock::given(method("GET"))
        .and(path("/health"))
        .respond_with(template)
        .mount(server)
        .await;
}

fn health(server: &MockServer) -> String {
    format!("{}/health", server.uri())
}

// ───────────────────────────── probing & state ─────────────────────────────

#[sqlx::test]
async fn first_check_records_a_result_and_marks_it_up(db: PgPool) {
    let ctx = setup(db).await;
    let server = target(200, "ok").await;
    let id = ctx.create_monitor(&health(&server), "").await;

    // Created with jitter: due somewhere within the first interval, not now.
    let due_in: i64 = sqlx::query_scalar(
        "SELECT EXTRACT(EPOCH FROM next_run_at - now())::bigint FROM http_monitors",
    )
    .fetch_one(&ctx.db)
    .await
    .unwrap();
    assert!((-1..=60).contains(&due_in), "{due_in}");

    assert_eq!(ctx.probe_all().await, 1);
    assert_eq!(ctx.status(id).await, ("up".into(), 0, None));
    assert_eq!(
        count(&ctx.db, "SELECT count(*) FROM http_results WHERE ok").await,
        1
    );
    let next_in: i64 = sqlx::query_scalar(
        "SELECT EXTRACT(EPOCH FROM next_run_at - now())::bigint FROM http_monitors",
    )
    .fetch_one(&ctx.db)
    .await
    .unwrap();
    assert!(
        (58..=60).contains(&next_in),
        "claimed for one interval, got {next_in}"
    );
    assert_eq!(
        prober::tick(&ctx.state).await.unwrap(),
        0,
        "not due again yet"
    );
}

#[sqlx::test]
async fn goes_down_after_the_threshold_alerts_and_recovers(db: PgPool) {
    let ctx = setup(db).await;
    let site = target(200, "ok").await;
    let hook = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(204))
        .mount(&hook)
        .await;
    let id = ctx.create_monitor(&health(&site), "").await;
    let res = ctx
        .post(
            "/channels/new/webhook",
            &format!(
                "url={}&attach_all=on",
                encode(&format!("{}/hook", hook.uri()))
            ),
        )
        .await;
    assert_eq!(res.status, StatusCode::SEE_OTHER);
    ctx.probe_all().await;

    respond(&site, ResponseTemplate::new(503)).await;
    ctx.probe_all().await;
    assert_eq!(
        ctx.status(id).await,
        ("up".into(), 1, Some("HTTP 503".into()))
    );
    assert_eq!(
        count(&ctx.db, "SELECT count(*) FROM incidents").await,
        0,
        "below threshold"
    );

    ctx.probe_all().await;
    assert_eq!(ctx.status(id).await.0, "down");
    let (reason, detail): (String, String) =
        sqlx::query_as("SELECT reason, detail FROM incidents WHERE monitor_id = $1")
            .bind(id)
            .fetch_one(&ctx.db)
            .await
            .unwrap();
    assert_eq!(reason, "http_down");
    assert_eq!(detail, "HTTP 503 after 2 consecutive failed checks.");

    assert_eq!(ctx.deliver().await, 1);
    let body: Value =
        serde_json::from_slice(&hook.received_requests().await.unwrap()[0].body).unwrap();
    assert_eq!(body["event"], "down");
    assert_eq!(body["title"], "🚨 API is down");
    assert_eq!(body["source"]["type"], "monitor");
    assert_eq!(body["source"]["url"], format!("{ORIGIN}/monitors/{id}"));
    assert_eq!(body["reason"], "Not responding as expected");

    // Still failing: no second alert.
    ctx.probe_all().await;
    assert_eq!(ctx.deliver().await, 0);

    respond(&site, ResponseTemplate::new(200)).await;
    ctx.probe_all().await;
    assert_eq!(ctx.status(id).await, ("up".into(), 0, None));
    assert_eq!(ctx.deliver().await, 1);
    let body: Value =
        serde_json::from_slice(&hook.received_requests().await.unwrap()[1].body).unwrap();
    assert_eq!(body["event"], "up");
    assert_eq!(body["title"], "✅ API is back up");
}

#[sqlx::test]
async fn each_failure_is_explained(db: PgPool) {
    let ctx = setup(db).await;

    let text = target(200, r#"{"status":"degraded"}"#).await;
    let wrong_body = ctx
        .create_monitor(
            &health(&text),
            &format!("&body_contains={}", encode(r#""status":"ok""#)),
        )
        .await;

    let slow = target(200, "ok").await;
    respond(
        &slow,
        ResponseTemplate::new(200).set_delay(Duration::from_millis(300)),
    )
    .await;
    let too_slow = ctx
        .create_monitor(&health(&slow), "&max_latency_ms=100&fail_threshold=1")
        .await;

    let hung = target(200, "ok").await;
    respond(
        &hung,
        ResponseTemplate::new(200).set_delay(Duration::from_secs(3)),
    )
    .await;
    let timeout = ctx.create_monitor(&health(&hung), "&timeout_secs=1").await;

    let refused = ctx.create_monitor("http://127.0.0.1:1/health", "").await;

    ctx.probe_all().await;
    assert_eq!(
        ctx.status(wrong_body).await.2.as_deref(),
        Some(r#"Response didn't contain ""status":"ok"""#)
    );
    let slow_error = ctx.status(too_slow).await.2.unwrap();
    assert!(
        slow_error.starts_with("Took ") && slow_error.ends_with("ms (limit 100 ms)"),
        "{slow_error}"
    );
    assert_eq!(ctx.status(too_slow).await.0, "down", "threshold 1");
    let reason: String = sqlx::query_scalar("SELECT reason FROM incidents WHERE monitor_id = $1")
        .bind(too_slow)
        .fetch_one(&ctx.db)
        .await
        .unwrap();
    assert_eq!(reason, "http_slow");
    assert_eq!(
        ctx.status(timeout).await.2.as_deref(),
        Some("Timed out after 1 s")
    );
    let refused_error = ctx.status(refused).await.2.unwrap();
    assert!(
        refused_error.to_lowercase().contains("refused"),
        "{refused_error}"
    );
}

#[sqlx::test]
async fn request_headers_are_sent_and_stored_encrypted(db: PgPool) {
    let ctx = setup(db).await;
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/health"))
        .and(header("authorization", "Bearer s3cret-token"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&server)
        .await;
    let id = ctx
        .create_monitor(
            &health(&server),
            &format!(
                "&headers={}&body={}",
                encode("Authorization: Bearer s3cret-token"),
                encode(r#"{"ping":1}"#)
            ),
        )
        .await;
    sqlx::query("UPDATE http_monitors SET method = 'POST'")
        .execute(&ctx.db)
        .await
        .unwrap();

    ctx.probe_all().await;
    assert_eq!(ctx.status(id).await.0, "up", "{:?}", ctx.status(id).await);
    let request = &server.received_requests().await.unwrap()[0];
    assert_eq!(request.body, br#"{"ping":1}"#);

    let sealed: Vec<u8> = sqlx::query_scalar("SELECT headers_enc FROM http_monitors")
        .fetch_one(&ctx.db)
        .await
        .unwrap();
    assert!(!String::from_utf8_lossy(&sealed).contains("s3cret"));
    let edit = send(
        &ctx.app,
        get(&format!("/monitors/{id}/edit"), Some(&ctx.cookie)),
    )
    .await;
    assert!(
        edit.body.contains("Authorization: Bearer s3cret-token"),
        "owner sees them to edit"
    );
}

#[sqlx::test]
async fn paused_monitors_are_not_probed(db: PgPool) {
    let ctx = setup(db).await;
    let server = target(200, "ok").await;
    let id = ctx.create_monitor(&health(&server), "").await;
    ctx.post(&format!("/monitors/{id}/pause"), "").await;

    assert_eq!(ctx.probe_all().await, 0);
    assert_eq!(ctx.status(id).await.0, "paused");

    ctx.post(&format!("/monitors/{id}/resume"), "").await;
    assert_eq!(ctx.status(id).await.0, "new");
    assert_eq!(
        prober::tick(&ctx.state).await.unwrap(),
        1,
        "resume checks right away"
    );
}

#[sqlx::test]
async fn resuming_mid_outage_still_sends_the_recovery(db: PgPool) {
    let ctx = setup(db).await;
    let site = target(500, "").await;
    let id = ctx
        .create_monitor(&health(&site), "&fail_threshold=1")
        .await;
    ctx.probe_all().await;
    assert_eq!(ctx.status(id).await.0, "down");

    ctx.post(&format!("/monitors/{id}/pause"), "").await;
    ctx.post(&format!("/monitors/{id}/resume"), "").await;
    assert_eq!(ctx.status(id).await.0, "down", "incident still open");

    respond(&site, ResponseTemplate::new(200)).await;
    ctx.probe_all().await;
    assert_eq!(
        count(
            &ctx.db,
            "SELECT count(*) FROM incidents WHERE resolved_at IS NOT NULL"
        )
        .await,
        1
    );
}

#[sqlx::test]
async fn concurrent_probers_check_each_monitor_once(db: PgPool) {
    let ctx = setup(db).await;
    let server = target(200, "ok").await;
    for _ in 0..10 {
        ctx.create_monitor(&health(&server), "").await;
    }
    sqlx::query("UPDATE http_monitors SET next_run_at = now()")
        .execute(&ctx.db)
        .await
        .unwrap();
    let (a, b) = tokio::join!(prober::tick(&ctx.state), prober::tick(&ctx.state));
    assert_eq!(a.unwrap() + b.unwrap(), 10);
    assert_eq!(
        count(&ctx.db, "SELECT count(*) FROM http_results").await,
        10
    );
    assert_eq!(server.received_requests().await.unwrap().len(), 10);
}

// ───────────────────────────── rollups & retention ─────────────────────────────

#[sqlx::test]
async fn rollups_drive_uptime_and_old_data_is_purged(db: PgPool) {
    let ctx = setup(db).await;
    let id = ctx.create_monitor("http://127.0.0.1:1/health", "").await;
    // Eight good checks at 100…800 ms, two failures without a response.
    for ms in (1..=8).map(|n| n * 100) {
        sqlx::query("INSERT INTO http_results (monitor_id, ok, status_code, latency_ms) VALUES ($1, true, 200, $2)")
            .bind(id)
            .bind(ms)
            .execute(&ctx.db)
            .await
            .unwrap();
    }
    for _ in 0..2 {
        sqlx::query("INSERT INTO http_results (monitor_id, ok, latency_ms, error) VALUES ($1, false, 5, 'refused')")
            .bind(id)
            .execute(&ctx.db)
            .await
            .unwrap();
    }
    monitors::rollup(&ctx.db).await.unwrap();
    let (count_, failed, avg, p50, p95): (i32, i32, i32, i32, i32) = sqlx::query_as(
        "SELECT count, fail_count, avg_ms, p50_ms, p95_ms FROM http_rollups WHERE monitor_id = $1",
    )
    .bind(id)
    .fetch_one(&ctx.db)
    .await
    .unwrap();
    // Latency stats only count responses: the refused connections' 5 ms are excluded.
    assert_eq!((count_, failed, avg, p50, p95), (10, 2, 450, 450, 765));

    // Idempotent: re-running updates in place.
    monitors::rollup(&ctx.db).await.unwrap();
    assert_eq!(count(&ctx.db, "SELECT count(*) FROM http_rollups").await, 1);

    let page = send(&ctx.app, get(&format!("/monitors/{id}"), Some(&ctx.cookie))).await;
    assert!(page.body.contains("80%"), "24h uptime tile");
    assert!(
        page.body.contains("Response time, last 24 hours"),
        "chart rendered"
    );
    let list = send(&ctx.app, get("/monitors", Some(&ctx.cookie))).await;
    assert!(list.body.contains("80%") && list.body.contains("class=\"viz spark\""));

    sqlx::query("UPDATE http_results SET created_at = now() - interval '8 days' WHERE NOT ok")
        .execute(&ctx.db)
        .await
        .unwrap();
    sqlx::query("INSERT INTO http_rollups (monitor_id, bucket_hour, count, fail_count) VALUES ($1, date_trunc('hour', now()) - interval '91 days', 5, 0)")
        .bind(id)
        .execute(&ctx.db)
        .await
        .unwrap();
    assert_eq!(monitors::purge(&ctx.db).await.unwrap(), 3);
    assert_eq!(count(&ctx.db, "SELECT count(*) FROM http_results").await, 8);
    assert_eq!(count(&ctx.db, "SELECT count(*) FROM http_rollups").await, 1);
}

// ───────────────────────────── UI ─────────────────────────────

#[sqlx::test]
async fn check_now_runs_a_real_check(db: PgPool) {
    let ctx = setup(db).await;
    let server = target(200, "ok").await;
    let id = ctx.create_monitor(&health(&server), "").await;
    let csrf = csrf_token(&ctx.app, &ctx.cookie).await;

    let req = post_form(&format!("/monitors/{id}/check"), Some(&ctx.cookie))
        .header("HX-Request", "true")
        .header("X-CSRF-Token", csrf)
        .body(Body::empty())
        .unwrap();
    let res = send(&ctx.app, req).await;
    assert!(res.body.contains("HTTP 200 in"), "{}", res.body);
    assert_eq!(res.header("hx-trigger"), "monitor-checked");
    assert_eq!(ctx.status(id).await.0, "up");
    assert_eq!(count(&ctx.db, "SELECT count(*) FROM http_results").await, 1);
}

#[sqlx::test]
async fn invalid_monitors_are_rejected_with_reasons(db: PgPool) {
    let ctx = setup(db).await;
    for (form, error) in [
        (
            "name=&url=https%3A%2F%2Fexample.com&interval_secs=60",
            "Give the monitor a name",
        ),
        (
            "name=A&url=ftp%3A%2F%2Fexample.com&interval_secs=60",
            "Only http",
        ),
        (
            "name=A&url=https%3A%2F%2Fexample.com&interval_secs=7",
            "Choose a check interval",
        ),
        (
            "name=A&url=https%3A%2F%2Fexample.com&interval_secs=60&headers=Host%3A+x",
            "set automatically",
        ),
        (
            "name=A&url=https%3A%2F%2Fexample.com&interval_secs=60&timeout_secs=2&max_latency_ms=5000",
            "below the timeout",
        ),
        (
            "name=A&url=https%3A%2F%2Fexample.com&interval_secs=60&expected_status=700",
            "status code",
        ),
    ] {
        let res = ctx.post("/monitors", &format!("method=GET&{form}")).await;
        assert_eq!(res.status, StatusCode::UNPROCESSABLE_ENTITY, "{form}");
        assert!(res.body.contains(error), "{form}: {}", res.body);
    }
    assert_eq!(
        count(&ctx.db, "SELECT count(*) FROM http_monitors").await,
        0
    );
}

#[sqlx::test]
async fn private_targets_are_refused_in_production_mode(db: PgPool) {
    let mut config = test_config();
    config.allow_private_targets = false;
    let app = web::router(state_with(db, config));
    let cookie = signup(&app, "ops@example.com").await;
    let csrf = csrf_token(&app, &cookie).await;
    for url in [
        "http://127.0.0.1:8080/",
        "http://169.254.169.254/latest",
        "http://[::1]/",
    ] {
        let body = format!(
            "_csrf={csrf}&name=A&method=GET&interval_secs=60&url={}",
            encode(url)
        );
        let res = send(&app, form_req("/monitors", &body, Some(&cookie))).await;
        assert_eq!(res.status, StatusCode::UNPROCESSABLE_ENTITY, "{url}");
    }
}

#[sqlx::test]
async fn monitors_are_private_to_their_org(db: PgPool) {
    let ctx = setup(db).await;
    let id = ctx.create_monitor("http://127.0.0.1:1/health", "").await;
    let bob = signup(&ctx.app, "bob@example.com").await;
    let csrf = csrf_token(&ctx.app, &bob).await;

    for page in ["", "/edit", "/activity"] {
        let res = send(&ctx.app, get(&format!("/monitors/{id}{page}"), Some(&bob))).await;
        assert_eq!(res.status, StatusCode::NOT_FOUND, "GET {page}");
    }
    for action in ["check", "pause", "resume", "delete"] {
        let res = send(
            &ctx.app,
            form_req(
                &format!("/monitors/{id}/{action}"),
                &format!("_csrf={csrf}"),
                Some(&bob),
            ),
        )
        .await;
        assert_eq!(res.status, StatusCode::NOT_FOUND, "POST {action}");
    }
    let list = send(&ctx.app, get("/monitors", Some(&bob))).await;
    assert!(list.body.contains("No monitors yet"));
}
