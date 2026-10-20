//! Alerts for runs that take far longer, or far less time, than usual.

mod common;

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use monitor::web::{self, AppState};
use monitor::worker::notifier;
use serde_json::Value;
use sqlx::PgPool;
use uuid::Uuid;
use wiremock::matchers::method;
use wiremock::{Mock, MockServer, ResponseTemplate};

use common::*;

const CHECK: &str = "name=Nightly+backup&schedule_kind=period&period_value=1&period_unit=days&grace_value=1&grace_unit=hours";

struct Ctx {
    db: PgPool,
    state: AppState,
    app: Router,
    cookie: String,
    hook: MockServer,
}

async fn setup(db: PgPool) -> Ctx {
    let state = state(db.clone());
    let app = web::router(state.clone());
    let cookie = signup(&app, "ops@example.com").await;
    let hook = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&hook)
        .await;
    Ctx {
        db,
        state,
        app,
        cookie,
        hook,
    }
}

impl Ctx {
    /// A check alerting a webhook, with ten earlier runs of about `usual_mins` minutes.
    async fn check(&self, form_extra: &str, usual_mins: i64) -> Uuid {
        let id = create_check(&self.app, &self.cookie, &format!("{CHECK}{form_extra}")).await;
        let csrf = csrf_token(&self.app, &self.cookie).await;
        let form = format!(
            "_csrf={csrf}&url={}&attach_all=on",
            encode(&self.hook.uri())
        );
        let res = send(
            &self.app,
            form_req("/channels/new/webhook", &form, Some(&self.cookie)),
        )
        .await;
        assert_eq!(res.status, StatusCode::SEE_OTHER, "{}", res.body);
        sqlx::query(
            "INSERT INTO pings (check_id, kind, duration_ms, created_at)
             SELECT $1, 'success', $2 * 60000 + n * 2000, now() - make_interval(days => n)
             FROM generate_series(1, 10) n",
        )
        .bind(id)
        .bind(usual_mins)
        .execute(&self.db)
        .await
        .unwrap();
        id
    }

    /// A run that started `mins` minutes ago finishes now.
    async fn run_for(&self, id: Uuid, mins: f64) {
        sqlx::query(
            "UPDATE checks SET status = 'started', last_start_at = now() - make_interval(secs => $2) WHERE id = $1",
        )
        .bind(id)
        .bind(mins * 60.0)
        .execute(&self.db)
        .await
        .unwrap();
        let token = token_of(&self.db, id).await;
        let req = Request::post(format!("/p/{token}/0"))
            .body(Body::empty())
            .unwrap();
        assert_eq!(send(&self.app, req).await.status, StatusCode::OK);
    }

    async fn delivered(&self) -> Vec<Value> {
        notifier::tick(&self.state.db, &self.state.channels, &self.state.secrets)
            .await
            .unwrap();
        self.hook
            .received_requests()
            .await
            .unwrap()
            .iter()
            .map(|r| serde_json::from_slice(&r.body).unwrap())
            .collect()
    }

    async fn incidents(&self) -> Vec<(String, bool)> {
        sqlx::query_as("SELECT reason, resolved_at = started_at FROM incidents ORDER BY started_at")
            .fetch_all(&self.db)
            .await
            .unwrap()
    }
}

#[sqlx::test]
async fn a_run_far_longer_than_usual_alerts_but_stays_up(db: PgPool) {
    let ctx = setup(db).await;
    let id = ctx.check("&duration_alerts=on", 10).await;

    ctx.run_for(id, 11.0).await;
    assert!(
        ctx.delivered().await.is_empty(),
        "a little slower is normal"
    );

    ctx.run_for(id, 35.0).await;
    let alerts = ctx.delivered().await;
    assert_eq!(alerts.len(), 1);
    assert_eq!(alerts[0]["event"], "anomaly");
    assert_eq!(alerts[0]["title"], "⚠️ Nightly backup: unusual run time");
    assert_eq!(alerts[0]["reason"], "Ran unusually long");
    let detail = alerts[0]["detail"].as_str().unwrap();
    assert!(
        detail.starts_with("This run took 35m 00s; it usually takes about 10m"),
        "{detail}"
    );

    let status: String = sqlx::query_scalar("SELECT status FROM checks")
        .fetch_one(&ctx.db)
        .await
        .unwrap();
    assert_eq!(status, "up");
    assert_eq!(ctx.incidents().await, [("slow_run".to_owned(), true)]);

    // Shown on the check page and in the incident history.
    let page = send(&ctx.app, get(&format!("/checks/{id}"), Some(&ctx.cookie))).await;
    assert!(page.body.contains("Typical run"));
    assert!(page.body.contains("Ran unusually long"));
    assert!(page.body.contains("single run"));
    let overview = send(&ctx.app, get("/dashboard", Some(&ctx.cookie))).await;
    assert!(!overview.body.contains("verdict-down"));
}

#[sqlx::test]
async fn a_run_that_finishes_suspiciously_fast_alerts(db: PgPool) {
    let ctx = setup(db).await;
    let id = ctx.check("&duration_alerts=on", 10).await;
    ctx.run_for(id, 0.2).await;
    let alerts = ctx.delivered().await;
    assert_eq!(alerts.len(), 1);
    assert_eq!(alerts[0]["reason"], "Finished unusually fast");
    assert_eq!(ctx.incidents().await, [("fast_run".to_owned(), true)]);
}

#[sqlx::test]
async fn can_be_switched_off_and_needs_history(db: PgPool) {
    let ctx = setup(db).await;
    let off = ctx.check("", 10).await;
    ctx.run_for(off, 60.0).await;
    assert!(ctx.delivered().await.is_empty());

    // On, but with too few timed runs to know what's usual.
    let new = create_check(
        &ctx.app,
        &ctx.cookie,
        &format!("{CHECK}&duration_alerts=on"),
    )
    .await;
    ctx.run_for(new, 1.0).await;
    ctx.run_for(new, 60.0).await;
    assert!(ctx.delivered().await.is_empty());
    assert!(ctx.incidents().await.is_empty());
    let page = send(&ctx.app, get(&format!("/checks/{new}"), Some(&ctx.cookie))).await;
    assert!(page.body.contains("learning: 2 of 8 runs timed"));
}
