//! Alert delivery end to end: outbox rows written by the scheduler and ingest, then
//! drained by the notifier into a wiremock webhook or Mailpit (from docker-compose).

mod common;

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use monitor::notify::channels::webhook::sign;
use monitor::web::{self, AppState};
use monitor::worker::{notifier, scheduler};
use serde_json::Value;
use sqlx::PgPool;
use uuid::Uuid;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use common::*;

const HOURLY: &str = "name=Nightly+backup&schedule_kind=period&period_value=1&period_unit=hours&grace_value=10&grace_unit=minutes";
const SECRET: &str = "whsec_test_123";

struct Ctx {
    db: PgPool,
    state: AppState,
    app: Router,
    cookie: String,
}

async fn setup(db: PgPool, email: &str) -> Ctx {
    let state = state(db.clone());
    let app = web::router(state.clone());
    let cookie = signup(&app, email).await;
    Ctx {
        db,
        state,
        app,
        cookie,
    }
}

impl Ctx {
    async fn add_channel(&self, kind: &str, form: &str) -> Resp {
        let csrf = csrf_token(&self.app, &self.cookie).await;
        let body = format!("_csrf={csrf}&{form}");
        send(
            &self.app,
            form_req(&format!("/channels/new/{kind}"), &body, Some(&self.cookie)),
        )
        .await
    }

    async fn add_webhook(&self, url: &str) -> Uuid {
        let res = self
            .add_channel(
                "webhook",
                &format!(
                    "url={}&secret={SECRET}&channel_name=Ops+hook&attach_all=on",
                    encode(url)
                ),
            )
            .await;
        assert_eq!(res.status, StatusCode::SEE_OTHER, "{}", res.body);
        id_from(&res, "/channels/")
    }

    async fn ping(&self, check: Uuid, suffix: &str, body: &str) {
        let token = token_of(&self.db, check).await;
        let req = Request::post(format!("/p/{token}{suffix}"))
            .body(Body::from(body.to_owned()))
            .unwrap();
        assert_eq!(send(&self.app, req).await.status, StatusCode::OK);
    }

    async fn go_overdue(&self, check: Uuid) {
        sqlx::query("UPDATE checks SET alert_after = now() - interval '1 second' WHERE id = $1")
            .bind(check)
            .execute(&self.db)
            .await
            .unwrap();
        scheduler::tick(&self.db, ORIGIN).await.unwrap();
    }

    async fn deliver(&self) -> usize {
        notifier::tick(&self.db, &self.state.channels, &self.state.secrets)
            .await
            .unwrap()
    }
}

fn id_from(res: &Resp, prefix: &str) -> Uuid {
    res.header("location")
        .strip_prefix(prefix)
        .and_then(|id| id.parse().ok())
        .unwrap_or_else(|| panic!("unexpected redirect {:?}", res.header("location")))
}

async fn notification_row(db: &PgPool) -> (String, String, i32, Option<String>, bool) {
    sqlx::query_as(
        "SELECT event, status, attempts, last_error, sent_at IS NOT NULL
         FROM notifications ORDER BY id DESC LIMIT 1",
    )
    .fetch_one(db)
    .await
    .unwrap()
}

/// Asserts the request is a validly signed webhook and returns its JSON body.
fn verified_json(req: &wiremock::Request) -> Value {
    let header = |name: &str| req.headers.get(name).unwrap().to_str().unwrap().to_owned();
    let timestamp = header("x-monitor-timestamp");
    assert_eq!(
        header("x-monitor-signature"),
        sign(SECRET, &timestamp, &req.body)
    );
    let age = chrono::Utc::now().timestamp() - timestamp.parse::<i64>().unwrap();
    assert!((0..60).contains(&age), "fresh timestamp");
    serde_json::from_slice(&req.body).unwrap()
}

async fn hook_server(status: u16) -> MockServer {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/hook"))
        .respond_with(ResponseTemplate::new(status))
        .mount(&server)
        .await;
    server
}

// ───────────────────────────── webhook ─────────────────────────────

#[sqlx::test]
async fn webhook_gets_down_recovery_and_failure_alerts(db: PgPool) {
    let ctx = setup(db, "ops@example.com").await;
    let server = hook_server(200).await;
    let check = create_check(&ctx.app, &ctx.cookie, HOURLY).await;
    ctx.add_webhook(&format!("{}/hook", server.uri())).await;
    ctx.ping(check, "", "").await;
    assert_eq!(ctx.deliver().await, 0, "first ping: nothing to report");

    // Missed ping → 🚨
    ctx.go_overdue(check).await;
    assert_eq!(ctx.deliver().await, 1);
    let requests = server.received_requests().await.unwrap();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].headers.get("x-monitor-event").unwrap(), "down");
    let body = verified_json(&requests[0]);
    assert_eq!(body["event"], "down");
    assert_eq!(body["title"], "🚨 Nightly backup is down");
    assert_eq!(body["check"]["url"], format!("{ORIGIN}/checks/{check}"));
    assert_eq!(body["reason"], "Missed ping");
    let (event, status, attempts, error, sent) = notification_row(&ctx.db).await;
    assert_eq!(
        (event.as_str(), status.as_str(), attempts, error, sent),
        ("down", "sent", 1, None, true)
    );

    // Recovery → ✅
    ctx.ping(check, "", "").await;
    assert_eq!(ctx.deliver().await, 1);
    let body = verified_json(&server.received_requests().await.unwrap()[1]);
    assert_eq!(body["event"], "up");
    assert!(
        body["summary"]
            .as_str()
            .unwrap()
            .starts_with("It was down for")
    );

    // Reported failure → ❌ with the log tail
    ctx.ping(
        check,
        "/fail",
        "starting backup\npg_dump: connection refused\n",
    )
    .await;
    assert_eq!(ctx.deliver().await, 1);
    let body = verified_json(&server.received_requests().await.unwrap()[2]);
    assert_eq!(body["event"], "fail");
    assert_eq!(
        body["log_tail"],
        "starting backup\npg_dump: connection refused"
    );

    assert_eq!(ctx.deliver().await, 0, "nothing left");
}

#[sqlx::test]
async fn server_errors_are_retried_with_backoff_then_dead_lettered(db: PgPool) {
    let ctx = setup(db, "ops@example.com").await;
    let server = hook_server(503).await;
    let check = create_check(&ctx.app, &ctx.cookie, HOURLY).await;
    ctx.add_webhook(&format!("{}/hook", server.uri())).await;
    ctx.ping(check, "", "").await;
    ctx.go_overdue(check).await;

    ctx.deliver().await;
    let (_, status, attempts, error, sent) = notification_row(&ctx.db).await;
    assert_eq!((status.as_str(), attempts, sent), ("pending", 1, false));
    assert!(error.unwrap().contains("503"));
    let wait: i64 = sqlx::query_scalar(
        "SELECT EXTRACT(EPOCH FROM next_attempt_at - now())::bigint FROM notifications",
    )
    .fetch_one(&ctx.db)
    .await
    .unwrap();
    assert!((25..=30).contains(&wait), "first retry in ~30s, got {wait}");
    assert_eq!(ctx.deliver().await, 0, "not due yet");

    // Last allowed attempt fails too → dead.
    sqlx::query("UPDATE notifications SET next_attempt_at = now(), attempts = $1")
        .bind(notifier::MAX_ATTEMPTS - 1)
        .execute(&ctx.db)
        .await
        .unwrap();
    assert_eq!(ctx.deliver().await, 1);
    let (_, status, attempts, _, _) = notification_row(&ctx.db).await;
    assert_eq!(
        (status.as_str(), attempts),
        ("dead", notifier::MAX_ATTEMPTS)
    );
}

#[sqlx::test]
async fn client_errors_are_not_retried(db: PgPool) {
    let ctx = setup(db, "ops@example.com").await;
    let server = hook_server(404).await;
    let check = create_check(&ctx.app, &ctx.cookie, HOURLY).await;
    ctx.add_webhook(&format!("{}/hook", server.uri())).await;
    ctx.ping(check, "", "").await;
    ctx.go_overdue(check).await;

    ctx.deliver().await;
    let (_, status, attempts, error, _) = notification_row(&ctx.db).await;
    assert_eq!((status.as_str(), attempts), ("dead", 1));
    assert!(error.unwrap().contains("404"));
}

#[sqlx::test]
async fn expired_leases_are_reclaimed(db: PgPool) {
    let ctx = setup(db, "ops@example.com").await;
    let server = hook_server(200).await;
    let check = create_check(&ctx.app, &ctx.cookie, HOURLY).await;
    ctx.add_webhook(&format!("{}/hook", server.uri())).await;
    ctx.ping(check, "", "").await;
    ctx.go_overdue(check).await;

    // A worker claimed it and died: still 'sending', lease expired.
    sqlx::query("UPDATE notifications SET status = 'sending', attempts = 1, next_attempt_at = now() - interval '1 second'")
        .execute(&ctx.db)
        .await
        .unwrap();
    assert_eq!(ctx.deliver().await, 1);
    let (_, status, attempts, _, _) = notification_row(&ctx.db).await;
    assert_eq!((status.as_str(), attempts), ("sent", 2));
}

#[sqlx::test]
async fn test_button_sends_a_sample_alert(db: PgPool) {
    let ctx = setup(db, "ops@example.com").await;
    let server = hook_server(200).await;
    let channel = ctx.add_webhook(&format!("{}/hook", server.uri())).await;
    let csrf = csrf_token(&ctx.app, &ctx.cookie).await;

    let req = post_form(&format!("/channels/{channel}/test"), Some(&ctx.cookie))
        .header("HX-Request", "true")
        .header("X-CSRF-Token", csrf)
        .body(Body::empty())
        .unwrap();
    let res = send(&ctx.app, req).await;
    assert!(res.body.contains("Test alert sent."), "{}", res.body);
    let body = verified_json(&server.received_requests().await.unwrap()[0]);
    assert_eq!(body["check"]["name"], "Test alert");
}

#[sqlx::test]
async fn webhook_secrets_are_encrypted_and_never_shown(db: PgPool) {
    let ctx = setup(db, "ops@example.com").await;
    let channel = ctx
        .add_webhook("http://127.0.0.1:9/hook/path-token-xyz")
        .await;

    let sealed: Vec<u8> = sqlx::query_scalar("SELECT config_enc FROM channels")
        .fetch_one(&ctx.db)
        .await
        .unwrap();
    let raw = String::from_utf8_lossy(&sealed);
    assert!(!raw.contains("path-token-xyz") && !raw.contains(SECRET));

    for page in ["/channels".to_owned(), format!("/channels/{channel}")] {
        let res = send(&ctx.app, get(&page, Some(&ctx.cookie))).await;
        assert_eq!(res.status, StatusCode::OK);
        assert!(res.body.contains("http://127.0.0.1/…"), "{page}");
        assert!(!res.body.contains("path-token-xyz"), "{page}");
        assert!(!res.body.contains(SECRET), "{page}");
    }
}

#[sqlx::test]
async fn private_webhook_targets_are_refused_in_production_mode(db: PgPool) {
    let mut config = test_config();
    config.allow_private_targets = false;
    let app = web::router(state_with(db, config));
    let cookie = signup(&app, "ops@example.com").await;
    let csrf = csrf_token(&app, &cookie).await;

    for url in [
        "http://127.0.0.1:8080/hook",
        "http://169.254.169.254/latest/meta-data",
        "http://localhost/x",
    ] {
        let body = format!("_csrf={csrf}&url={}", encode(url));
        let res = send(
            &app,
            form_req("/channels/new/webhook", &body, Some(&cookie)),
        )
        .await;
        assert_eq!(res.status, StatusCode::UNPROCESSABLE_ENTITY, "{url}");
        assert!(
            res.body.contains("aren&#39;t allowed") || res.body.contains("aren't allowed"),
            "{url}"
        );
    }
}

// ───────────────────────────── tenancy ─────────────────────────────

#[sqlx::test]
async fn channels_are_private_to_their_org(db: PgPool) {
    let alice = setup(db.clone(), "alice@example.com").await;
    let channel = alice.add_webhook("http://127.0.0.1:9/hook").await;
    let bob = signup(&alice.app, "bob@example.com").await;
    let csrf = csrf_token(&alice.app, &bob).await;

    let res = send(&alice.app, get(&format!("/channels/{channel}"), Some(&bob))).await;
    assert_eq!(res.status, StatusCode::NOT_FOUND);
    for action in ["test", "resend", "delete"] {
        let res = send(
            &alice.app,
            form_req(
                &format!("/channels/{channel}/{action}"),
                &format!("_csrf={csrf}"),
                Some(&bob),
            ),
        )
        .await;
        assert_eq!(res.status, StatusCode::NOT_FOUND, "{action}");
    }

    // Bob can't attach Alice's channel to his check: the id is ignored.
    let bobs_check =
        create_check(&alice.app, &bob, &format!("{HOURLY}&channel_ids={channel}")).await;
    let linked: i64 = sqlx::query_scalar("SELECT count(*) FROM check_channels WHERE check_id = $1")
        .bind(bobs_check)
        .fetch_one(&db)
        .await
        .unwrap();
    assert_eq!(linked, 0);
    let list = send(&alice.app, get("/channels", Some(&bob))).await;
    assert!(!list.body.contains("Ops hook"));
}

#[sqlx::test]
async fn check_form_saves_channel_selection(db: PgPool) {
    let ctx = setup(db, "ops@example.com").await;
    let a = ctx.add_webhook("http://127.0.0.1:9/a").await;
    let b = ctx.add_webhook("http://127.0.0.1:9/b").await;

    // New checks offer every channel, ticked.
    let form = send(&ctx.app, get("/checks/new", Some(&ctx.cookie))).await;
    assert_eq!(form.body.matches(r#"name="channel_ids""#).count(), 2);
    assert_eq!(
        form.body.matches("checked>").count()
            - form.body.matches(r#"value="period" checked>"#).count(),
        2
    );

    let check = create_check(&ctx.app, &ctx.cookie, &format!("{HOURLY}&channel_ids={a}")).await;
    let linked: Vec<Uuid> =
        sqlx::query_scalar("SELECT channel_id FROM check_channels WHERE check_id = $1")
            .bind(check)
            .fetch_all(&ctx.db)
            .await
            .unwrap();
    assert_eq!(linked, vec![a]);

    let csrf = csrf_token(&ctx.app, &ctx.cookie).await;
    let body = format!("_csrf={csrf}&{HOURLY}&channel_ids={b}");
    send(
        &ctx.app,
        form_req(&format!("/checks/{check}"), &body, Some(&ctx.cookie)),
    )
    .await;
    let linked: Vec<Uuid> =
        sqlx::query_scalar("SELECT channel_id FROM check_channels WHERE check_id = $1")
            .bind(check)
            .fetch_all(&ctx.db)
            .await
            .unwrap();
    assert_eq!(linked, vec![b]);
}

// ───────────────────────────── email (Mailpit) ─────────────────────────────

/// Mailpit messages to `address`, newest first, as (id, subject).
async fn inbox(address: &str) -> Vec<(String, String)> {
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

async fn message_text(id: &str) -> String {
    let json: Value = reqwest::get(format!("{MAILPIT_API}/message/{id}"))
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    json["Text"].as_str().unwrap().to_owned()
}

fn unique_address(tag: &str) -> String {
    format!("{tag}-{}@example.com", Uuid::new_v4().simple())
}

#[sqlx::test]
async fn email_to_your_own_address_works_immediately(db: PgPool) {
    let me = unique_address("me");
    let ctx = setup(db, &me).await;
    let check = create_check(&ctx.app, &ctx.cookie, HOURLY).await;
    let res = ctx
        .add_channel(
            "email",
            &format!("address={}&attach_all=on", encode(&me.to_uppercase())),
        )
        .await;
    assert_eq!(res.status, StatusCode::SEE_OTHER, "{}", res.body);
    assert_eq!(
        count(
            &ctx.db,
            "SELECT count(*) FROM channels WHERE verified_at IS NOT NULL"
        )
        .await,
        1
    );

    ctx.ping(check, "", "").await;
    ctx.go_overdue(check).await;
    assert_eq!(ctx.deliver().await, 1);
    let (_, status, _, error, _) = notification_row(&ctx.db).await;
    assert_eq!(status, "sent", "{error:?}");

    let mail = inbox(&me).await;
    assert_eq!(mail.len(), 1);
    assert_eq!(mail[0].1, "🚨 Nightly backup is down");
    let text = message_text(&mail[0].0).await;
    assert!(text.contains("Missed ping: Expected a ping by"), "{text}");
    assert!(text.contains(&format!("{ORIGIN}/checks/{check}")));
}

#[sqlx::test]
async fn email_to_someone_else_needs_confirmation(db: PgPool) {
    let ctx = setup(db, &unique_address("me")).await;
    let team = unique_address("team");
    let check = create_check(&ctx.app, &ctx.cookie, HOURLY).await;
    let res = ctx
        .add_channel("email", &format!("address={}&attach_all=on", encode(&team)))
        .await;
    let channel = id_from(&res, "/channels/");
    let page = send(
        &ctx.app,
        get(&format!("/channels/{channel}"), Some(&ctx.cookie)),
    )
    .await;
    assert!(page.body.contains("Awaiting confirmation"));

    // Unconfirmed channels get nothing.
    ctx.ping(check, "", "").await;
    ctx.go_overdue(check).await;
    assert_eq!(
        count(&ctx.db, "SELECT count(*) FROM notifications").await,
        0
    );

    // The confirmation email carries a one-time link.
    let mail = inbox(&team).await;
    assert_eq!(mail.len(), 1);
    assert_eq!(mail[0].1, "Confirm alerts from Monitor");
    let text = message_text(&mail[0].0).await;
    let link = text
        .split_whitespace()
        .find(|w| w.starts_with(&format!("{ORIGIN}/verify-channel?token=")))
        .expect("link in email");
    let path = link.strip_prefix(ORIGIN).unwrap();
    let token = link.split("token=").nth(1).unwrap();

    // GET only asks (mail scanners prefetch links); it doesn't confirm.
    let confirm = send(&ctx.app, get(path, None)).await;
    assert!(confirm.body.contains("Yes, send me alerts"));
    assert!(confirm.body.contains(&team));
    assert_eq!(
        count(
            &ctx.db,
            "SELECT count(*) FROM channels WHERE verified_at IS NOT NULL"
        )
        .await,
        0
    );

    let res = send(
        &ctx.app,
        form_req("/verify-channel", &format!("token={token}"), None),
    )
    .await;
    assert!(res.body.contains("You're all set") || res.body.contains("You&#39;re all set"));
    assert_eq!(
        count(
            &ctx.db,
            "SELECT count(*) FROM channels WHERE verified_at IS NOT NULL"
        )
        .await,
        1
    );
    let again = send(
        &ctx.app,
        form_req("/verify-channel", &format!("token={token}"), None),
    )
    .await;
    assert!(again.body.contains("Link expired"), "one-time link");

    // The recovery from the incident it never heard about isn't sent to it…
    ctx.ping(check, "", "").await;
    assert_eq!(
        count(&ctx.db, "SELECT count(*) FROM notifications").await,
        0
    );
    // …but the next incident is.
    ctx.go_overdue(check).await;
    assert_eq!(ctx.deliver().await, 1);
    let mail = inbox(&team).await;
    assert_eq!(mail.len(), 2);
    assert_eq!(mail[0].1, "🚨 Nightly backup is down");
}

#[sqlx::test]
async fn resend_is_rate_limited(db: PgPool) {
    let ctx = setup(db, &unique_address("me")).await;
    let team = unique_address("team");
    let res = ctx
        .add_channel("email", &format!("address={}", encode(&team)))
        .await;
    let channel = id_from(&res, "/channels/");
    let csrf = csrf_token(&ctx.app, &ctx.cookie).await;

    let resend = || {
        form_req(
            &format!("/channels/{channel}/resend"),
            &format!("_csrf={csrf}"),
            Some(&ctx.cookie),
        )
    };
    send(&ctx.app, resend()).await;
    assert_eq!(
        inbox(&team).await.len(),
        1,
        "cooldown: no second email right away"
    );

    sqlx::query("UPDATE channels SET verify_sent_at = now() - interval '2 minutes'")
        .execute(&ctx.db)
        .await
        .unwrap();
    send(&ctx.app, resend()).await;
    assert_eq!(inbox(&team).await.len(), 2);
}

#[sqlx::test]
async fn bogus_verify_tokens_are_rejected(db: PgPool) {
    let app = app(db);
    let res = send(&app, get("/verify-channel?token=nope", None)).await;
    assert!(res.body.contains("Link expired"));
    let res = send(&app, form_req("/verify-channel", "token=nope", None)).await;
    assert!(res.body.contains("Link expired"));
}
