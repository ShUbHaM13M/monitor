//! The REST API at /api/v1, driven with keys created through the dashboard.

mod common;

use axum::Router;
use axum::body::Body;
use axum::http::{Method, Request, StatusCode, header};
use serde_json::{Value, json};
use sqlx::PgPool;

use common::*;

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
    /// Creates a key in the dashboard and returns the token shown once.
    async fn key(&self, scope: &str) -> String {
        let csrf = csrf_token(&self.app, &self.cookie).await;
        let form = format!("_csrf={csrf}&name=CI&scope={scope}&expires=90");
        let res = send(&self.app, form_req("/api-keys", &form, Some(&self.cookie))).await;
        assert_eq!(res.status, StatusCode::OK, "{}", res.body);
        assert_eq!(res.header("cache-control"), "no-store");
        let start = res.body.find("<code>mon_").expect("the new key is shown") + "<code>".len();
        res.body[start..start + 47].to_owned()
    }

    async fn call(
        &self,
        method: Method,
        path: &str,
        key: &str,
        body: Option<Value>,
    ) -> (StatusCode, Value) {
        let mut req = Request::builder()
            .method(method)
            .uri(path)
            .header(header::AUTHORIZATION, format!("Bearer {key}"));
        let body = match body {
            Some(json) => {
                req = req.header(header::CONTENT_TYPE, "application/json");
                Body::from(json.to_string())
            }
            None => Body::empty(),
        };
        let res = send(&self.app, req.body(body).unwrap()).await;
        let json = if res.body.is_empty() {
            Value::Null
        } else {
            serde_json::from_str(&res.body).unwrap_or_else(|_| panic!("not JSON: {}", res.body))
        };
        (res.status, json)
    }
}

fn backup() -> Value {
    json!({ "name": "Nightly backup", "schedule": { "cron": "0 2 * * *", "tz": "Europe/Berlin" }, "grace": 1800 })
}

#[sqlx::test]
async fn check_lifecycle(db: PgPool) {
    let ctx = setup(db).await;
    let key = ctx.key("write").await;

    let (status, check) = ctx
        .call(Method::POST, "/api/v1/checks", &key, Some(backup()))
        .await;
    assert_eq!(status, StatusCode::CREATED, "{check}");
    assert_eq!(check["name"], "Nightly backup");
    assert_eq!(check["kind"], "heartbeat");
    assert_eq!(check["status"], "new");
    assert_eq!(
        check["schedule"],
        json!({ "cron": "0 2 * * *", "tz": "Europe/Berlin" })
    );
    assert_eq!(check["grace"], 1800);
    assert_eq!(check["duration_alerts"], true);
    assert!(
        check["url"]
            .as_str()
            .unwrap()
            .starts_with("http://localhost:3000/p/")
    );
    let id = check["id"].as_str().unwrap().to_owned();

    // The ping URL it returned works.
    let ping_path = check["url"]
        .as_str()
        .unwrap()
        .trim_start_matches("http://localhost:3000")
        .to_owned();
    send(
        &ctx.app,
        Request::post(&ping_path).body(Body::empty()).unwrap(),
    )
    .await;

    let (_, listed) = ctx.call(Method::GET, "/api/v1/checks", &key, None).await;
    assert_eq!(listed["data"][0]["status"], "up");

    let mut changed = backup();
    changed["schedule"] = json!({ "every": 3600 });
    changed["max_runtime"] = json!(600);
    let (status, check) = ctx
        .call(
            Method::PUT,
            &format!("/api/v1/checks/{id}"),
            &key,
            Some(changed),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{check}");
    assert_eq!(check["schedule"], json!({ "every": 3600 }));
    assert_eq!(check["max_runtime"], 600);

    let (_, pings) = ctx
        .call(
            Method::GET,
            &format!("/api/v1/checks/{id}/pings?limit=10"),
            &key,
            None,
        )
        .await;
    assert_eq!(pings["data"].as_array().unwrap().len(), 1);
    assert_eq!(pings["data"][0]["kind"], "success");

    let (_, paused) = ctx
        .call(
            Method::POST,
            &format!("/api/v1/checks/{id}/pause"),
            &key,
            None,
        )
        .await;
    assert_eq!(paused["status"], "paused");
    let (_, resumed) = ctx
        .call(
            Method::POST,
            &format!("/api/v1/checks/{id}/resume"),
            &key,
            None,
        )
        .await;
    assert_eq!(resumed["status"], "new");

    let (status, _) = ctx
        .call(Method::DELETE, &format!("/api/v1/checks/{id}"), &key, None)
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, err) = ctx
        .call(Method::GET, &format!("/api/v1/checks/{id}"), &key, None)
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(err["error"]["code"], "not_found");
}

#[sqlx::test]
async fn validation_matches_the_dashboard(db: PgPool) {
    let ctx = setup(db).await;
    let key = ctx.key("write").await;
    let cases = [
        (
            json!({ "name": "", "schedule": { "every": 3600 } }),
            "Give the check a name.",
        ),
        (
            json!({ "name": "x", "schedule": { "every": 10 } }),
            "between 1 minute and 365 days",
        ),
        (
            json!({ "name": "x", "schedule": { "cron": "61 * * * *" } }),
            "cron",
        ),
        (
            json!({ "name": "x", "schedule": { "every": 60, "cron": "* * * * *" } }),
            "either",
        ),
        (
            json!({ "name": "x", "schedule": { "every": 60 }, "max_runtime": 90 }),
            "whole number of minutes",
        ),
        (
            json!({ "name": "x", "schedule": { "every": 60 }, "kind": "webhook", "signature": { "scheme": "github" } }),
            "secret",
        ),
        (
            json!({ "name": "x", "schedule": { "every": 60 }, "channels": ["00000000-0000-0000-0000-000000000000"] }),
            "Unknown channel",
        ),
        (
            json!({ "name": "x", "schedule": { "every": 60 }, "colour": "red" }),
            "unknown field",
        ),
    ];
    for (body, expected) in cases {
        let (status, err) = ctx
            .call(Method::POST, "/api/v1/checks", &key, Some(body.clone()))
            .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
        assert_eq!(err["error"]["code"], "invalid");
        let message = err["error"]["message"].as_str().unwrap();
        assert!(
            message.to_lowercase().contains(&expected.to_lowercase()),
            "{body}: {message}"
        );
    }
    assert_eq!(count(&ctx.db, "SELECT count(*) FROM checks").await, 0);

    // A malformed body is a JSON error too, not axum's plain text.
    let req = Request::post("/api/v1/checks")
        .header(header::AUTHORIZATION, format!("Bearer {key}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from("{not json"))
        .unwrap();
    let res = send(&ctx.app, req).await;
    assert_eq!(res.status, StatusCode::UNPROCESSABLE_ENTITY);
    assert!(res.body.contains(r#""code":"invalid""#));
}

#[sqlx::test]
async fn webhook_checks_keep_their_secret_when_omitted(db: PgPool) {
    let ctx = setup(db).await;
    let key = ctx.key("write").await;
    let body = json!({
        "name": "Stripe", "kind": "webhook", "schedule": { "every": 3600 },
        "signature": { "scheme": "stripe", "secret": "whsec_abc" }
    });
    let (status, check) = ctx
        .call(Method::POST, "/api/v1/checks", &key, Some(body))
        .await;
    assert_eq!(status, StatusCode::CREATED, "{check}");
    assert!(check["url"].as_str().unwrap().contains("/w/"));
    assert_eq!(
        check["signature"],
        json!({ "scheme": "stripe", "header": null, "has_secret": true })
    );
    assert!(
        !check.to_string().contains("whsec_abc"),
        "secrets are never returned"
    );

    let id = check["id"].as_str().unwrap();
    let update = json!({ "name": "Stripe events", "schedule": { "every": 3600 }, "signature": { "scheme": "stripe" } });
    let (status, check) = ctx
        .call(
            Method::PUT,
            &format!("/api/v1/checks/{id}"),
            &key,
            Some(update),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{check}");
    assert_eq!(check["signature"]["has_secret"], true);

    let change_kind = json!({ "name": "x", "kind": "heartbeat", "schedule": { "every": 3600 } });
    let (status, err) = ctx
        .call(
            Method::PUT,
            &format!("/api/v1/checks/{id}"),
            &key,
            Some(change_kind),
        )
        .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert!(
        err["error"]["message"]
            .as_str()
            .unwrap()
            .contains("kind can't be changed")
    );
}

#[sqlx::test]
async fn monitors_with_hidden_header_values(db: PgPool) {
    let ctx = setup(db).await;
    let key = ctx.key("write").await;
    let body = json!({
        "name": "API", "url": "https://example.com/health", "interval": 300,
        "headers": { "Authorization": "Bearer s3cret" }, "expected_status": 200
    });
    let (status, m) = ctx
        .call(Method::POST, "/api/v1/monitors", &key, Some(body))
        .await;
    assert_eq!(status, StatusCode::CREATED, "{m}");
    assert_eq!(m["header_names"], json!(["Authorization"]));
    assert_eq!(m["interval"], 300);
    assert!(!m.to_string().contains("s3cret"));
    let id = m["id"].as_str().unwrap();

    // Headers omitted on update are kept.
    let update = json!({ "name": "API", "url": "https://example.com/health", "interval": 60 });
    let (_, m) = ctx
        .call(
            Method::PUT,
            &format!("/api/v1/monitors/{id}"),
            &key,
            Some(update),
        )
        .await;
    assert_eq!(m["header_names"], json!(["Authorization"]));
    assert_eq!(m["interval"], 60);

    let bad = json!({ "name": "API", "url": "https://example.com/", "interval": 45 });
    let (status, err) = ctx
        .call(Method::POST, "/api/v1/monitors", &key, Some(bad))
        .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert!(
        err["error"]["message"]
            .as_str()
            .unwrap()
            .contains("interval")
    );

    let (_, results) = ctx
        .call(
            Method::GET,
            &format!("/api/v1/monitors/{id}/results"),
            &key,
            None,
        )
        .await;
    assert_eq!(results["data"], json!([]));
}

#[sqlx::test]
async fn keys_are_scoped_to_their_org_and_access(db: PgPool) {
    let ctx = setup(db.clone()).await;
    let read = ctx.key("read").await;
    let write = ctx.key("write").await;

    let (status, err) = ctx
        .call(Method::POST, "/api/v1/checks", &read, Some(backup()))
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(err["error"]["code"], "read_only_key");
    let (status, _) = ctx.call(Method::GET, "/api/v1/checks", &read, None).await;
    assert_eq!(status, StatusCode::OK);

    let (_, check) = ctx
        .call(Method::POST, "/api/v1/checks", &write, Some(backup()))
        .await;
    let id = check["id"].as_str().unwrap().to_owned();

    // Another org's key sees nothing of this one.
    let other_cookie = signup(&ctx.app, "eve@example.com").await;
    let eve = Ctx {
        db: db.clone(),
        app: ctx.app.clone(),
        cookie: other_cookie,
    };
    let eve_key = eve.key("write").await;
    let (_, listed) = eve
        .call(Method::GET, "/api/v1/checks", &eve_key, None)
        .await;
    assert_eq!(listed["data"], json!([]));
    for (method, path) in [
        (Method::GET, format!("/api/v1/checks/{id}")),
        (Method::DELETE, format!("/api/v1/checks/{id}")),
        (Method::POST, format!("/api/v1/checks/{id}/pause")),
    ] {
        let (status, _) = eve.call(method, &path, &eve_key, None).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{path}");
    }

    // Bad, missing, expired and revoked keys.
    for bad in ["mon_nope", "garbage", ""] {
        let (status, err) = ctx.call(Method::GET, "/api/v1/checks", bad, None).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(err["error"]["code"], "unauthorized");
    }
    sqlx::query(
        "UPDATE api_keys SET expires_at = now() - interval '1 second' WHERE scope = 'read'",
    )
    .execute(&db)
    .await
    .unwrap();
    assert_eq!(
        ctx.call(Method::GET, "/api/v1/checks", &read, None).await.0,
        StatusCode::UNAUTHORIZED
    );

    let page = send(&ctx.app, get("/api-keys", Some(&ctx.cookie))).await;
    assert!(page.body.contains("expired"));
    assert!(!page.body.contains(&write), "keys are never shown again");
    let key_id: uuid::Uuid = sqlx::query_scalar("SELECT id FROM api_keys WHERE scope = 'write' AND created_by = (SELECT id FROM users WHERE email = 'ops@example.com')")
        .fetch_one(&db)
        .await
        .unwrap();
    let csrf = csrf_token(&ctx.app, &ctx.cookie).await;
    let res = send(
        &ctx.app,
        form_req(
            &format!("/api-keys/{key_id}/delete"),
            &format!("_csrf={csrf}"),
            Some(&ctx.cookie),
        ),
    )
    .await;
    assert_eq!(res.status, StatusCode::SEE_OTHER);
    assert_eq!(
        ctx.call(Method::GET, "/api/v1/checks", &write, None)
            .await
            .0,
        StatusCode::UNAUTHORIZED
    );

    // last_used_at was recorded.
    let used: i64 =
        sqlx::query_scalar("SELECT count(*) FROM api_keys WHERE last_used_at IS NOT NULL")
            .fetch_one(&db)
            .await
            .unwrap();
    assert!(used >= 1);
}

#[sqlx::test]
async fn incidents_channels_limits_and_unknown_routes(db: PgPool) {
    let ctx = setup(db.clone()).await;
    let key = ctx.key("write").await;
    let (_, check) = ctx
        .call(Method::POST, "/api/v1/checks", &key, Some(backup()))
        .await;
    let ping = check["url"]
        .as_str()
        .unwrap()
        .trim_start_matches("http://localhost:3000")
        .to_owned();
    send(
        &ctx.app,
        Request::post(format!("{ping}/fail"))
            .body(Body::empty())
            .unwrap(),
    )
    .await;

    let (_, open) = ctx
        .call(Method::GET, "/api/v1/incidents?state=open", &key, None)
        .await;
    assert_eq!(open["data"][0]["reason"], "failed");
    assert_eq!(open["data"][0]["target"]["type"], "check");
    assert_eq!(open["data"][0]["target"]["name"], "Nightly backup");
    let (status, _) = ctx
        .call(Method::GET, "/api/v1/incidents?state=bogus", &key, None)
        .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);

    let (_, channels) = ctx.call(Method::GET, "/api/v1/channels", &key, None).await;
    assert_eq!(channels["data"], json!([]));

    sqlx::query("UPDATE orgs SET max_checks = 1")
        .execute(&db)
        .await
        .unwrap();
    let (status, err) = ctx
        .call(Method::POST, "/api/v1/checks", &key, Some(backup()))
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(err["error"]["code"], "plan_limit");

    let (status, err) = ctx
        .call(Method::GET, "/api/v1/nothing-here", &key, None)
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(err["error"]["code"], "not_found");
    let (status, _) = ctx
        .call(Method::GET, "/api/v1/checks/not-a-uuid", &key, None)
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}
