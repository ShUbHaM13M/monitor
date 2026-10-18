//! Its own test binary: the metrics recorder is process-global.

mod common;

use axum::http::StatusCode;
use monitor::telemetry;
use sqlx::PgPool;

use common::*;

#[sqlx::test]
async fn metrics_cover_requests_pings_and_stored_state(db: PgPool) {
    let handle = telemetry::install().unwrap();
    let app = app(db.clone());
    let metrics = telemetry::router(handle, db.clone());

    let cookie = signup(&app, "ops@example.com").await;
    let id = create_check(
        &app,
        &cookie,
        "name=Backup&schedule_kind=period&period_value=1&period_unit=hours&grace_value=10&grace_unit=minutes",
    )
    .await;
    let token = token_of(&db, id).await;
    let ping = axum::http::Request::post(format!("/p/{token}/fail"))
        .body(axum::body::Body::empty())
        .unwrap();
    send(&app, ping).await;
    send(&app, get(&format!("/checks/{id}"), Some(&cookie))).await;

    let res = send(&metrics, get("/metrics", None)).await;
    assert_eq!(res.status, StatusCode::OK);
    assert!(res.header("content-type").starts_with("text/plain"));
    let body = res.body;
    // Routes are labelled by template, not by the real path.
    assert!(
        body.contains(r#"http_requests_total{method="GET",route="/checks/{id}",status="200"} 1"#),
        "{body}"
    );
    assert!(body.contains(r#"http_requests_total{method="POST",route="/signup",status="303"} 1"#));
    assert!(body.contains("http_request_duration_seconds_bucket"));
    assert!(body.contains(r#"pings_total{endpoint="ping",result="accepted"} 1"#));
    // Read from the database at scrape time.
    assert!(body.contains(r#"checks{status="down"} 1"#));
    assert!(body.contains(r#"checks{status="up"} 0"#));
    assert!(body.contains("incidents_open 1"));
    assert!(body.contains("alerts_queued 0"));
}
