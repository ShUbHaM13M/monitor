//! Webhook relay: deliveries forwarded to the org's server (wiremock), in order,
//! retried, alerted on, redelivered.

mod common;

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use monitor::crypto::SecretBox;
use monitor::notify::channels::webhook::sign;
use monitor::web::{self, AppState};
use monitor::worker::relay;
use sqlx::PgPool;
use uuid::Uuid;
use wiremock::matchers::method;
use wiremock::{Mock, MockServer, ResponseTemplate};

use common::*;

const DAILY: &str = "name=Stripe+events&kind=webhook&schedule_kind=period&period_value=1&period_unit=days&grace_value=1&grace_unit=hours";

struct Ctx {
    db: PgPool,
    state: AppState,
    app: Router,
    cookie: String,
    server: MockServer,
}

async fn setup(db: PgPool) -> Ctx {
    let state = state(db.clone());
    let app = web::router(state.clone());
    let cookie = signup(&app, "ops@example.com").await;
    let server = MockServer::start().await;
    Ctx {
        db,
        state,
        app,
        cookie,
        server,
    }
}

impl Ctx {
    async fn respond(&self, status: u16) {
        self.server.reset().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(status).set_body_string("upstream says hi"))
            .mount(&self.server)
            .await;
    }

    /// A webhook check forwarding to the mock server. Returns (id, token).
    async fn relaying_check(&self) -> (Uuid, String) {
        let form = format!(
            "{DAILY}&relay_url={}",
            encode(&format!("{}/hooks/stripe", self.server.uri()))
        );
        let id = create_check(&self.app, &self.cookie, &form).await;
        (id, token_of(&self.db, id).await)
    }

    async fn deliver(&self, token: &str, body: &str) -> Resp {
        let req = Request::post(format!("/w/{token}"))
            .header("content-type", "application/json")
            .header("stripe-signature", "t=1,v1=abc")
            .header("cookie", "session=secret")
            .header("authorization", "Bearer nope")
            .header("x-forwarded-for", "6.6.6.6")
            .header("x-monitor-signature", "sha256=forged")
            .body(Body::from(body.to_owned()))
            .unwrap();
        send(&self.app, req).await
    }

    /// Makes everything waiting due now, then runs one relay tick.
    async fn tick(&self) -> usize {
        sqlx::query("UPDATE relay_deliveries SET next_attempt_at = now() WHERE status IN ('pending', 'sending')")
            .execute(&self.db)
            .await
            .unwrap();
        relay::tick(&self.state).await.unwrap()
    }

    async fn received(&self) -> Vec<wiremock::Request> {
        self.server.received_requests().await.unwrap()
    }

    async fn statuses(&self) -> Vec<String> {
        sqlx::query_scalar("SELECT status FROM relay_deliveries ORDER BY id")
            .fetch_all(&self.db)
            .await
            .unwrap()
    }

    async fn open_incidents(&self) -> Vec<String> {
        sqlx::query_scalar("SELECT reason FROM incidents WHERE resolved_at IS NULL ORDER BY reason")
            .fetch_all(&self.db)
            .await
            .unwrap()
    }
}

fn header<'a>(req: &'a wiremock::Request, name: &str) -> Option<&'a str> {
    req.headers.get(name).and_then(|v| v.to_str().ok())
}

#[sqlx::test]
async fn forwards_the_delivery_signed_and_cleaned(db: PgPool) {
    let ctx = setup(db).await;
    ctx.respond(200).await;
    let (id, token) = ctx.relaying_check().await;

    let res = ctx.deliver(&token, r#"{"type":"invoice.paid"}"#).await;
    assert_eq!(res.status, StatusCode::OK);
    assert_eq!(ctx.statuses().await, ["pending"], "stored before answering");
    let status: String = sqlx::query_scalar("SELECT status FROM checks")
        .fetch_one(&ctx.db)
        .await
        .unwrap();
    assert_eq!(status, "up", "still a heartbeat");

    assert_eq!(ctx.tick().await, 1);
    let got = ctx.received().await;
    assert_eq!(got.len(), 1);
    let req = &got[0];
    assert_eq!(req.url.path(), "/hooks/stripe");
    assert_eq!(req.body, br#"{"type":"invoice.paid"}"#);
    assert_eq!(header(req, "content-type"), Some("application/json"));
    assert_eq!(header(req, "stripe-signature"), Some("t=1,v1=abc"));
    for dropped in ["cookie", "authorization"] {
        assert_eq!(header(req, dropped), None, "{dropped}");
    }
    assert_ne!(
        header(req, "x-forwarded-for"),
        Some("6.6.6.6"),
        "a sender can't spoof it"
    );
    let delivery: i64 = sqlx::query_scalar("SELECT id FROM relay_deliveries")
        .fetch_one(&ctx.db)
        .await
        .unwrap();
    assert_eq!(
        header(req, "x-monitor-delivery"),
        Some(delivery.to_string().as_str())
    );
    assert_eq!(header(req, "x-monitor-attempt"), Some("1"));

    // Our signature checks out with the secret shown on the check page.
    let sealed: Vec<u8> = sqlx::query_scalar("SELECT relay_secret_enc FROM checks")
        .fetch_one(&ctx.db)
        .await
        .unwrap();
    let secret = String::from_utf8(
        SecretBox::from_base64(TEST_SECRET_KEY)
            .unwrap()
            .open(&sealed)
            .unwrap(),
    )
    .unwrap();
    let ts = header(req, "x-monitor-timestamp").unwrap();
    assert_eq!(
        header(req, "x-monitor-signature").unwrap(),
        sign(&secret, ts, &req.body)
    );
    let page = send(&ctx.app, get(&format!("/checks/{id}"), Some(&ctx.cookie))).await;
    assert!(page.body.contains(&secret));
    assert!(page.body.contains("Forwarding to 127.0.0.1"));
    assert!(page.body.contains("delivered"));

    assert_eq!(ctx.statuses().await, ["delivered"]);
    assert_eq!(ctx.tick().await, 0, "delivered once");
}

#[sqlx::test]
async fn retries_in_order_alerts_and_recovers(db: PgPool) {
    let ctx = setup(db).await;
    ctx.respond(503).await;
    let (id, token) = ctx.relaying_check().await;
    for n in 1..=3 {
        ctx.deliver(&token, &format!(r#"{{"n":{n}}}"#)).await;
    }

    // Only the head is tried while the server is down.
    for attempt in 1..=3 {
        assert_eq!(ctx.tick().await, 1);
        let got = ctx.received().await;
        assert_eq!(got.len(), attempt);
        assert_eq!(got.last().unwrap().body, br#"{"n":1}"#);
    }
    let (status, error): (String, String) =
        sqlx::query_as("SELECT status, last_error FROM relay_deliveries ORDER BY id LIMIT 1")
            .fetch_one(&ctx.db)
            .await
            .unwrap();
    assert_eq!(status, "pending");
    assert!(
        error.contains("503") && error.contains("upstream says hi"),
        "{error}"
    );
    assert_eq!(ctx.open_incidents().await, ["relay_failing"]);
    let detail: String = sqlx::query_scalar("SELECT detail FROM incidents")
        .fetch_one(&ctx.db)
        .await
        .unwrap();
    assert!(
        detail.contains("failed the last 3 attempts")
            && detail.contains("3 deliveries are waiting"),
        "{detail}"
    );
    let page = send(&ctx.app, get(&format!("/checks/{id}"), Some(&ctx.cookie))).await;
    assert!(page.body.contains("failing"));
    assert!(page.body.contains("retrying"));
    let overview = send(&ctx.app, get("/dashboard", Some(&ctx.cookie))).await;
    assert!(overview.body.contains("Forwarding is failing"));
    assert!(overview.body.contains("Needs attention"));

    // A missed webhook is a separate incident; both can be open.
    sqlx::query("UPDATE checks SET alert_after = now() - interval '1 second'")
        .execute(&ctx.db)
        .await
        .unwrap();
    monitor::worker::scheduler::tick(&ctx.db, "http://localhost:3000")
        .await
        .unwrap();
    assert_eq!(ctx.open_incidents().await, ["missed", "relay_failing"]);

    // The server recovers: everything arrives, in order, and the incident closes.
    ctx.respond(200).await;
    for _ in 0..3 {
        assert_eq!(ctx.tick().await, 1);
    }
    let bodies: Vec<_> = ctx
        .received()
        .await
        .iter()
        .map(|r| String::from_utf8(r.body.clone()).unwrap())
        .collect();
    assert_eq!(bodies, [r#"{"n":1}"#, r#"{"n":2}"#, r#"{"n":3}"#]);
    assert_eq!(
        ctx.statuses().await,
        ["delivered", "delivered", "delivered"]
    );
    assert_eq!(
        ctx.open_incidents().await,
        ["missed"],
        "only the relay incident resolves"
    );
    let failures: i32 = sqlx::query_scalar("SELECT relay_failures FROM checks")
        .fetch_one(&ctx.db)
        .await
        .unwrap();
    assert_eq!(failures, 0);
}

#[sqlx::test]
async fn gives_up_after_a_day_and_can_skip_or_redeliver(db: PgPool) {
    let ctx = setup(db).await;
    ctx.respond(500).await;
    let (id, token) = ctx.relaying_check().await;
    ctx.deliver(&token, "first").await;
    ctx.deliver(&token, "second").await;

    // Older than a day: one more failure and it's dropped, letting the next go.
    sqlx::query("UPDATE relay_deliveries SET received_at = now() - interval '25 hours' WHERE body = 'first'")
        .execute(&ctx.db)
        .await
        .unwrap();
    ctx.tick().await;
    assert_eq!(ctx.statuses().await, ["failed", "pending"]);
    ctx.tick().await;
    assert_eq!(ctx.received().await.last().unwrap().body, b"second");

    // Skipping the stuck head.
    let ids: Vec<i64> = sqlx::query_scalar("SELECT id FROM relay_deliveries ORDER BY id")
        .fetch_all(&ctx.db)
        .await
        .unwrap();
    let csrf = csrf_token(&ctx.app, &ctx.cookie).await;
    let res = send(
        &ctx.app,
        form_req(
            &format!("/checks/{id}/relay/{}/skip", ids[1]),
            &format!("_csrf={csrf}"),
            Some(&ctx.cookie),
        ),
    )
    .await;
    assert_eq!(res.status, StatusCode::SEE_OTHER);
    assert_eq!(ctx.statuses().await, ["failed", "failed"]);

    // Redelivering queues a copy at the back.
    ctx.respond(200).await;
    let res = send(
        &ctx.app,
        form_req(
            &format!("/checks/{id}/relay/{}/redeliver", ids[0]),
            &format!("_csrf={csrf}"),
            Some(&ctx.cookie),
        ),
    )
    .await;
    assert_eq!(res.status, StatusCode::SEE_OTHER);
    ctx.tick().await;
    assert_eq!(ctx.statuses().await, ["failed", "failed", "delivered"]);
    assert_eq!(ctx.received().await.last().unwrap().body, b"first");

    // Another org can't act on these.
    let eve = signup(&ctx.app, "eve@example.com").await;
    let eve_csrf = csrf_token(&ctx.app, &eve).await;
    let res = send(
        &ctx.app,
        form_req(
            &format!("/checks/{id}/relay/{}/redeliver", ids[0]),
            &format!("_csrf={eve_csrf}"),
            Some(&eve),
        ),
    )
    .await;
    assert_eq!(res.status, StatusCode::NOT_FOUND);
}

#[sqlx::test]
async fn concurrent_workers_attempt_each_head_once(db: PgPool) {
    let ctx = setup(db).await;
    // A slow server: the second worker looks while the first is mid-send.
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_delay(std::time::Duration::from_millis(500)))
        .mount(&ctx.server)
        .await;
    let (_, token) = ctx.relaying_check().await;
    ctx.deliver(&token, "a").await;
    ctx.deliver(&token, "b").await;
    let first = relay::tick(&ctx.state);
    let second = async {
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        relay::tick(&ctx.state).await
    };
    let (a, b) = tokio::join!(first, second);
    assert_eq!(
        (a.unwrap(), b.unwrap()),
        (1, 0),
        "the head is leased; the next waits its turn"
    );
    let bodies: Vec<_> = ctx
        .received()
        .await
        .iter()
        .map(|r| r.body.clone())
        .collect();
    assert_eq!(bodies, [b"a".to_vec()]);
    // Then the next one goes.
    assert_eq!(relay::tick(&ctx.state).await.unwrap(), 1);
    assert_eq!(ctx.received().await.last().unwrap().body, b"b");
}

#[sqlx::test]
async fn backlog_limits_rejections_and_switching_off(db: PgPool) {
    let ctx = setup(db).await;
    ctx.respond(200).await;
    let (id, token) = ctx.relaying_check().await;

    // A forged delivery to a signed webhook is never forwarded.
    let form = format!(
        "_csrf={}&name=Stripe+events&schedule_kind=period&period_value=1&period_unit=days&grace_value=1&grace_unit=hours&signature_scheme=stripe&signing_secret=whsec_x&relay_url={}",
        csrf_token(&ctx.app, &ctx.cookie).await,
        encode(&format!("{}/hooks/stripe", ctx.server.uri()))
    );
    assert_eq!(
        send(
            &ctx.app,
            form_req(&format!("/checks/{id}"), &form, Some(&ctx.cookie))
        )
        .await
        .status,
        StatusCode::SEE_OTHER
    );
    assert_eq!(
        ctx.deliver(&token, "forged").await.status,
        StatusCode::UNAUTHORIZED
    );
    assert!(ctx.statuses().await.is_empty());

    // A full backlog is refused, so the sender keeps the event and retries.
    sqlx::query(
        "INSERT INTO relay_deliveries (check_id, method, headers, body)
         SELECT $1, 'POST', '[]', ''::bytea FROM generate_series(1, 10000)",
    )
    .bind(id)
    .execute(&ctx.db)
    .await
    .unwrap();
    let ts = chrono::Utc::now().timestamp().to_string();
    let body = "{}";
    let sig = hex::encode_hmac("whsec_x", &format!("{ts}.{body}"));
    let req = Request::post(format!("/w/{token}"))
        .header("stripe-signature", format!("t={ts},v1={sig}"))
        .body(Body::from(body))
        .unwrap();
    let res = send(&ctx.app, req).await;
    assert_eq!(res.status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(res.header("retry-after"), "60");

    // Turning forwarding off gives up on the backlog.
    let off = form.replace(
        &format!(
            "&relay_url={}",
            encode(&format!("{}/hooks/stripe", ctx.server.uri()))
        ),
        "&relay_url=",
    );
    assert_eq!(
        send(
            &ctx.app,
            form_req(&format!("/checks/{id}"), &off, Some(&ctx.cookie))
        )
        .await
        .status,
        StatusCode::SEE_OTHER
    );
    assert_eq!(
        count(
            &ctx.db,
            "SELECT count(*) FROM relay_deliveries WHERE status = 'pending'"
        )
        .await,
        0
    );
    let secret: Option<Vec<u8>> = sqlx::query_scalar("SELECT relay_secret_enc FROM checks")
        .fetch_one(&ctx.db)
        .await
        .unwrap();
    assert!(secret.is_none());
}

#[sqlx::test]
async fn relay_url_is_validated_and_webhook_only(db: PgPool) {
    let mut config = test_config();
    config.allow_private_targets = false;
    let app = web::router(state_with(db.clone(), config));
    let cookie = signup(&app, "ops@example.com").await;
    let csrf = csrf_token(&app, &cookie).await;
    let res = send(
        &app,
        form_req(
            "/checks",
            &format!(
                "_csrf={csrf}&{DAILY}&relay_url={}",
                encode("http://10.0.0.5/hook")
            ),
            Some(&cookie),
        ),
    )
    .await;
    assert_eq!(res.status, StatusCode::UNPROCESSABLE_ENTITY);
    assert!(res.body.contains("Forwarding address"));

    // Heartbeat checks ignore it.
    let heartbeat = DAILY.replace("kind=webhook", "kind=heartbeat");
    create_check(
        &app,
        &cookie,
        &format!(
            "{heartbeat}&relay_url={}",
            encode("https://example.com/hook")
        ),
    )
    .await;
    let url: Option<String> = sqlx::query_scalar("SELECT relay_url FROM checks")
        .fetch_one(&db)
        .await
        .unwrap();
    assert_eq!(url, None);
}

mod hex {
    use hmac::{Hmac, KeyInit, Mac};
    use sha2::Sha256;

    pub fn encode_hmac(secret: &str, msg: &str) -> String {
        let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).unwrap();
        mac.update(msg.as_bytes());
        mac.finalize()
            .into_bytes()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    }
}

#[sqlx::test]
async fn failing_and_recovered_forwarding_reach_alert_channels(db: PgPool) {
    let ctx = setup(db).await;
    ctx.respond(502).await;
    let (_, token) = ctx.relaying_check().await;
    let alerts = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&alerts)
        .await;
    let csrf = csrf_token(&ctx.app, &ctx.cookie).await;
    let form = format!("_csrf={csrf}&url={}&attach_all=on", encode(&alerts.uri()));
    send(
        &ctx.app,
        form_req("/channels/new/webhook", &form, Some(&ctx.cookie)),
    )
    .await;

    ctx.deliver(&token, "x").await;
    for _ in 0..3 {
        ctx.tick().await;
    }
    ctx.respond(200).await;
    ctx.tick().await;
    monitor::worker::notifier::tick(&ctx.state.db, &ctx.state.channels, &ctx.state.secrets)
        .await
        .unwrap();
    let sent: Vec<serde_json::Value> = alerts
        .received_requests()
        .await
        .unwrap()
        .iter()
        .map(|r| serde_json::from_slice(&r.body).unwrap())
        .collect();
    let events: Vec<_> = sent
        .iter()
        .map(|a| (a["event"].as_str().unwrap(), a["title"].as_str().unwrap()))
        .collect();
    assert_eq!(
        events,
        [
            ("relay_down", "📭 Stripe events: forwarding is failing"),
            ("relay_up", "📬 Stripe events: forwarding recovered"),
        ]
    );
    assert!(
        sent[1]["summary"]
            .as_str()
            .unwrap()
            .starts_with("Forwarding was failing for")
    );
}
