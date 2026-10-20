//! Slack and Discord delivery, against wiremock standing in for their webhook endpoints.

mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use monitor::web;
use monitor::worker::notifier;
use serde_json::Value;
use sqlx::PgPool;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use common::*;

const CHECK: &str = "name=Nightly+backup&schedule_kind=period&period_value=1&period_unit=hours&grace_value=10&grace_unit=minutes";

/// Adds a `kind` channel for `url` to a new check, fails the check and runs the notifier.
async fn fail_a_check_and_deliver(kind: &str, url: &str, db: &PgPool) {
    let state = state(db.clone());
    let app = web::router(state.clone());
    let cookie = signup(&app, "ops@example.com").await;
    let id = create_check(&app, &cookie, CHECK).await;
    let csrf = csrf_token(&app, &cookie).await;
    let form = format!(
        "_csrf={csrf}&url={}&channel_name=Team&attach_all=on",
        encode(url)
    );
    let res = send(
        &app,
        form_req(&format!("/channels/new/{kind}"), &form, Some(&cookie)),
    )
    .await;
    assert_eq!(res.status, StatusCode::SEE_OTHER, "{}", res.body);

    let token = token_of(db, id).await;
    let req = Request::post(format!("/p/{token}/fail"))
        .body(Body::from("pg_dump: connection refused"))
        .unwrap();
    send(&app, req).await;
    notifier::tick(&state.db, &state.channels, &state.secrets)
        .await
        .unwrap();
}

async fn received(server: &MockServer) -> Vec<Value> {
    server
        .received_requests()
        .await
        .unwrap()
        .iter()
        .map(|r| serde_json::from_slice(&r.body).unwrap())
        .collect()
}

async fn status(db: &PgPool) -> (String, Option<String>) {
    sqlx::query_as("SELECT status, last_error FROM notifications")
        .fetch_one(db)
        .await
        .unwrap()
}

#[sqlx::test]
async fn slack_gets_a_block_kit_message(db: PgPool) {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/services/T0/B0/secret"))
        .respond_with(ResponseTemplate::new(200).set_body_string("ok"))
        .mount(&server)
        .await;
    let url = format!("{}/services/T0/B0/secret", server.uri());
    fail_a_check_and_deliver("slack", &url, &db).await;

    let messages = received(&server).await;
    assert_eq!(messages.len(), 1);
    assert_eq!(messages[0]["text"], "❌ Nightly backup failed");
    let blocks = &messages[0]["attachments"][0]["blocks"];
    assert!(
        blocks[2]["text"]["text"]
            .as_str()
            .unwrap()
            .contains("pg_dump: connection refused")
    );
    assert_eq!(status(&db).await.0, "sent");
}

#[sqlx::test]
async fn discord_gets_an_embed_and_errors_are_explained(db: PgPool) {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/webhooks/1/tok"))
        .respond_with(
            ResponseTemplate::new(404)
                .set_body_string(r#"{"message": "Unknown Webhook", "code": 10015}"#),
        )
        .mount(&server)
        .await;
    let url = format!("{}/api/webhooks/1/tok", server.uri());
    fail_a_check_and_deliver("discord", &url, &db).await;

    let messages = received(&server).await;
    assert_eq!(
        messages[0]["embeds"][0]["title"],
        "❌ Nightly backup failed"
    );
    // A deleted webhook won't come back: no retries, and the reason is kept.
    let (status, error) = status(&db).await;
    assert_eq!(status, "dead");
    assert!(error.unwrap().contains("Unknown Webhook"));
}

#[sqlx::test]
async fn webhook_urls_are_secrets_and_checked(db: PgPool) {
    // Production settings: only real Slack URLs.
    let mut config = test_config();
    config.allow_private_targets = false;
    let app = web::router(state_with(db, config));
    let cookie = signup(&app, "ops@example.com").await;
    let csrf = csrf_token(&app, &cookie).await;
    let form = |url: &str| format!("_csrf={csrf}&url={}", encode(url));

    let res = send(
        &app,
        form_req(
            "/channels/new/slack",
            &form("https://example.com/services/x"),
            Some(&cookie),
        ),
    )
    .await;
    assert_eq!(res.status, StatusCode::UNPROCESSABLE_ENTITY);
    assert!(
        res.body.contains("isn&#39;t a Slack webhook URL")
            || res.body.contains("isn't a Slack webhook URL")
    );

    let real = "https://hooks.slack.com/services/T0/B0/abcdSECRET";
    let res = send(
        &app,
        form_req("/channels/new/slack", &form(real), Some(&cookie)),
    )
    .await;
    assert_eq!(res.status, StatusCode::SEE_OTHER, "{}", res.body);
    let page = send(&app, get(res.header("location"), Some(&cookie))).await;
    assert!(page.body.contains("Slack webhook …CRET"));
    assert!(
        !page.body.contains("abcdSECRET"),
        "the URL is never shown back"
    );
    let list = send(&app, get("/channels/new", Some(&cookie))).await;
    assert!(list.body.contains("Discord"));
}
