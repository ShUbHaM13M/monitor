//! Inbound webhook monitors: signature verification per provider, the delivery
//! log, endpoint separation, and missing-webhook alerts.

mod common;

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use hmac::{Hmac, KeyInit, Mac};
use monitor::worker::scheduler;
use serde_json::Value;
use sha2::Sha256;
use sqlx::PgPool;
use uuid::Uuid;

use common::*;

const DAILY: &str = "name=Stripe+invoices&kind=webhook&schedule_kind=period&period_value=1&period_unit=days&grace_value=1&grace_unit=hours";

fn hmac(secret: &str, parts: &[&[u8]]) -> Vec<u8> {
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).unwrap();
    for part in parts {
        mac.update(part);
    }
    mac.finalize().into_bytes().to_vec()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

struct Ctx {
    db: PgPool,
    app: Router,
    cookie: String,
}

async fn setup(db: PgPool) -> Ctx {
    let app = app(db.clone());
    let cookie = signup(&app, "ops@example.com").await;
    Ctx { db, app, cookie }
}

impl Ctx {
    /// Creates a webhook monitor with extra form fields; returns (id, token).
    async fn create(&self, extra: &str) -> (Uuid, String) {
        let id = create_check(&self.app, &self.cookie, &format!("{DAILY}{extra}")).await;
        (id, token_of(&self.db, id).await)
    }

    async fn deliver(&self, token: &str, headers: &[(&str, String)], body: &[u8]) -> Resp {
        let mut req =
            Request::post(format!("/w/{token}")).header("content-type", "application/json");
        for (name, value) in headers {
            req = req.header(*name, value);
        }
        send(&self.app, req.body(Body::from(body.to_vec())).unwrap()).await
    }

    async fn status(&self, id: Uuid) -> String {
        sqlx::query_scalar("SELECT status FROM checks WHERE id = $1")
            .bind(id)
            .fetch_one(&self.db)
            .await
            .unwrap()
    }

    async fn last_ping(&self) -> (String, Option<String>, Option<Value>, Option<String>, bool) {
        sqlx::query_as(
            "SELECT kind, note, headers, body, body_truncated FROM pings ORDER BY id DESC LIMIT 1",
        )
        .fetch_one(&self.db)
        .await
        .unwrap()
    }
}

// ───────────────────────────── providers ─────────────────────────────

#[sqlx::test]
async fn github_signed_delivery_counts_and_is_logged(db: PgPool) {
    let ctx = setup(db).await;
    let (id, token) = ctx
        .create("&signature_scheme=github&signing_secret=gh-secret")
        .await;
    let body = br#"{"action":"opened","number":42}"#;
    let sig = format!("sha256={}", hex(&hmac("gh-secret", &[body])));

    let res = ctx
        .deliver(
            &token,
            &[
                ("x-hub-signature-256", sig),
                ("x-github-event", "pull_request".into()),
                ("authorization", "Bearer gho_secret_token".into()),
            ],
            body,
        )
        .await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.body);
    assert_eq!(ctx.status(id).await, "up");

    let (kind, note, headers, stored, truncated) = ctx.last_ping().await;
    assert_eq!((kind.as_str(), note, truncated), ("webhook", None, false));
    let headers = headers.unwrap();
    assert_eq!(headers["x-github-event"], "pull_request");
    assert_eq!(headers["authorization"], "[redacted]");
    assert_eq!(
        stored.as_deref(),
        Some(r#"{"action":"opened","number":42}"#)
    );

    let page = send(&ctx.app, get(&format!("/checks/{id}"), Some(&ctx.cookie))).await;
    assert!(page.body.contains("Recent deliveries"));
    assert!(page.body.contains("x-github-event: pull_request"));
    assert!(page.body.contains(&format!("{ORIGIN}/w/{token}")));
    assert!(!page.body.contains("gho_secret_token"));
}

#[sqlx::test]
async fn bad_signatures_are_rejected_and_logged(db: PgPool) {
    let ctx = setup(db).await;
    let (id, token) = ctx
        .create("&signature_scheme=github&signing_secret=gh-secret")
        .await;
    let body = br#"{"action":"opened"}"#;

    let forged = format!("sha256={}", hex(&hmac("guessed", &[body])));
    let res = ctx
        .deliver(&token, &[("x-hub-signature-256", forged)], body)
        .await;
    assert_eq!(res.status, StatusCode::UNAUTHORIZED);
    assert!(res.body.contains("signature mismatch"));
    assert_eq!(ctx.status(id).await, "new", "doesn't count as a heartbeat");
    let (kind, note, ..) = ctx.last_ping().await;
    assert_eq!(kind, "rejected");
    assert_eq!(
        note.as_deref(),
        Some("signature mismatch (check the signing secret)")
    );

    let res = ctx.deliver(&token, &[], body).await;
    assert_eq!(res.status, StatusCode::UNAUTHORIZED);
    assert_eq!(
        ctx.last_ping().await.1.as_deref(),
        Some("missing x-hub-signature-256 header")
    );

    let page = send(&ctx.app, get(&format!("/checks/{id}"), Some(&ctx.cookie))).await;
    assert!(page.body.contains("rejected"));
    assert!(page.body.contains("missing x-hub-signature-256 header"));
}

#[sqlx::test]
async fn stripe_signatures_and_replay_window(db: PgPool) {
    let ctx = setup(db).await;
    let (id, token) = ctx
        .create("&signature_scheme=stripe&signing_secret=whsec_abc")
        .await;
    let body = br#"{"type":"invoice.paid"}"#;
    let stripe = |t: i64| {
        let sig = hex(&hmac("whsec_abc", &[t.to_string().as_bytes(), b".", body]));
        vec![("stripe-signature", format!("t={t},v1={sig}"))]
    };
    let now = chrono::Utc::now().timestamp();

    assert_eq!(
        ctx.deliver(&token, &stripe(now - 600), body).await.status,
        StatusCode::UNAUTHORIZED
    );
    assert!(
        ctx.last_ping()
            .await
            .1
            .unwrap()
            .contains("more than 5 minutes")
    );
    assert_eq!(ctx.status(id).await, "new");

    assert_eq!(
        ctx.deliver(&token, &stripe(now), body).await.status,
        StatusCode::OK
    );
    assert_eq!(ctx.status(id).await, "up");
}

#[sqlx::test]
async fn shopify_and_generic_hmac(db: PgPool) {
    let ctx = setup(db).await;
    let body = br#"{"id":7}"#;

    let (shop, shop_token) = ctx
        .create("&signature_scheme=shopify&signing_secret=shpss_1")
        .await;
    let sig = STANDARD.encode(hmac("shpss_1", &[body]));
    assert_eq!(
        ctx.deliver(&shop_token, &[("x-shopify-hmac-sha256", sig)], body)
            .await
            .status,
        StatusCode::OK
    );
    assert_eq!(ctx.status(shop).await, "up");

    let (generic, generic_token) = ctx
        .create(
            "&signature_scheme=hmac_sha256&signature_header=X-Acme-Signature&signing_secret=acme",
        )
        .await;
    let sig = hex(&hmac("acme", &[body]));
    assert_eq!(
        ctx.deliver(&generic_token, &[("X-Acme-Signature", sig)], body)
            .await
            .status,
        StatusCode::OK
    );
    assert_eq!(ctx.status(generic).await, "up");
}

#[sqlx::test]
async fn unsigned_webhooks_accept_any_delivery(db: PgPool) {
    let ctx = setup(db).await;
    let (id, token) = ctx.create("").await;
    assert_eq!(ctx.deliver(&token, &[], b"{}").await.status, StatusCode::OK);
    assert_eq!(ctx.status(id).await, "up");

    let res = send(&ctx.app, get(&format!("/w/{token}"), None)).await;
    assert_eq!(res.status, StatusCode::METHOD_NOT_ALLOWED, "providers POST");
}

#[sqlx::test]
async fn large_payloads_keep_their_start_and_still_verify(db: PgPool) {
    let ctx = setup(db).await;
    let (_, token) = ctx
        .create("&signature_scheme=github&signing_secret=s")
        .await;
    let body = format!("{{\"data\":\"{}\"}}", "x".repeat(20_000));
    let sig = format!("sha256={}", hex(&hmac("s", &[body.as_bytes()])));

    let res = ctx
        .deliver(&token, &[("x-hub-signature-256", sig)], body.as_bytes())
        .await;
    assert_eq!(res.status, StatusCode::OK, "signature covers the full body");
    let (_, _, _, stored, truncated) = ctx.last_ping().await;
    let stored = stored.unwrap();
    assert!(truncated);
    assert_eq!(stored.len(), 10_240);
    assert!(stored.starts_with("{\"data\":\"xxx"));
}

// ───────────────────────────── separation & lifecycle ─────────────────────────────

#[sqlx::test]
async fn ping_and_webhook_urls_dont_cross(db: PgPool) {
    let ctx = setup(db).await;
    let (_, webhook_token) = ctx
        .create("&signature_scheme=github&signing_secret=s")
        .await;
    let heartbeat = create_check(
        &ctx.app,
        &ctx.cookie,
        "name=Backup&schedule_kind=period&period_value=1&period_unit=days&grace_value=1&grace_unit=hours",
    )
    .await;
    let heartbeat_token = token_of(&ctx.db, heartbeat).await;

    // The ping URL must not bypass the signature check.
    let res = send(
        &ctx.app,
        Request::post(format!("/p/{webhook_token}"))
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(res.status, StatusCode::NOT_FOUND);
    assert_eq!(
        ctx.deliver(&heartbeat_token, &[], b"{}").await.status,
        StatusCode::NOT_FOUND
    );
    assert_eq!(count(&ctx.db, "SELECT count(*) FROM pings").await, 0);
}

#[sqlx::test]
async fn missing_webhooks_go_down_and_alert(db: PgPool) {
    let ctx = setup(db).await;
    let (id, token) = ctx.create("").await;
    ctx.deliver(&token, &[], b"{}").await;
    sqlx::query("UPDATE checks SET alert_after = now() - interval '1 second'")
        .execute(&ctx.db)
        .await
        .unwrap();
    assert_eq!(scheduler::tick(&ctx.db, ORIGIN).await.unwrap(), 1);
    assert_eq!(ctx.status(id).await, "down");

    // The next delivery brings it back.
    ctx.deliver(&token, &[], b"{}").await;
    assert_eq!(ctx.status(id).await, "up");
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
async fn secrets_are_encrypted_kept_on_edit_and_cleared_when_unsigned(db: PgPool) {
    let ctx = setup(db).await;
    let (id, token) = ctx
        .create("&signature_scheme=github&signing_secret=original-secret")
        .await;
    let sealed: Vec<u8> = sqlx::query_scalar("SELECT signing_secret_enc FROM checks")
        .fetch_one(&ctx.db)
        .await
        .unwrap();
    assert!(!String::from_utf8_lossy(&sealed).contains("original-secret"));

    let edit = send(
        &ctx.app,
        get(&format!("/checks/{id}/edit"), Some(&ctx.cookie)),
    )
    .await;
    assert!(!edit.body.contains("original-secret"));
    assert!(edit.body.contains("Saved. Leave blank to keep it"));

    // Saving with a blank secret keeps it (and the kind can't be changed).
    let csrf = csrf_token(&ctx.app, &ctx.cookie).await;
    let form = format!(
        "_csrf={csrf}&{}&signature_scheme=github&signing_secret=",
        DAILY.replace("kind=webhook", "kind=heartbeat")
    );
    let res = send(
        &ctx.app,
        form_req(&format!("/checks/{id}"), &form, Some(&ctx.cookie)),
    )
    .await;
    assert_eq!(res.status, StatusCode::SEE_OTHER, "{}", res.body);
    let kind: String = sqlx::query_scalar("SELECT kind FROM checks")
        .fetch_one(&ctx.db)
        .await
        .unwrap();
    assert_eq!(kind, "webhook");
    let sig = format!("sha256={}", hex(&hmac("original-secret", &[b"{}"])));
    assert_eq!(
        ctx.deliver(&token, &[("x-hub-signature-256", sig)], b"{}")
            .await
            .status,
        StatusCode::OK
    );

    // Switching to "Don't verify" drops the secret.
    let form = format!("_csrf={csrf}&{DAILY}&signature_scheme=");
    send(
        &ctx.app,
        form_req(&format!("/checks/{id}"), &form, Some(&ctx.cookie)),
    )
    .await;
    assert_eq!(
        count(&ctx.db, "SELECT count(*) FROM checks WHERE signing_secret_enc IS NULL AND signature_scheme IS NULL").await,
        1
    );
}

#[sqlx::test]
async fn dashboard_tags_webhook_monitors(db: PgPool) {
    let ctx = setup(db).await;
    ctx.create("").await;
    let dash = send(&ctx.app, get("/checks", Some(&ctx.cookie))).await;
    assert!(dash.body.contains(r#"<span class="tag">webhook</span>"#));
}
