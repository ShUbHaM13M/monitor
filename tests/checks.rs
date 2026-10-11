mod common;

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use monitor::worker::scheduler;
use sqlx::PgPool;
use uuid::Uuid;

use common::*;

const HOURLY: &str = "name=Nightly+backup&schedule_kind=period&period_value=1&period_unit=hours&grace_value=10&grace_unit=minutes";

/// A ping from a cron job: no cookies, no Origin.
async fn ping(app: &Router, path: &str, body: &str) -> Resp {
    let req = Request::post(path)
        .body(Body::from(body.to_owned()))
        .unwrap();
    send(app, req).await
}

async fn status_of(db: &PgPool, id: Uuid) -> String {
    sqlx::query_scalar("SELECT status FROM checks WHERE id = $1")
        .bind(id)
        .fetch_one(db)
        .await
        .unwrap()
}

async fn set_overdue(db: &PgPool, id: Uuid) {
    sqlx::query("UPDATE checks SET alert_after = now() - interval '1 second' WHERE id = $1")
        .bind(id)
        .execute(db)
        .await
        .unwrap();
}

/// Signs up, creates an hourly check and returns (app, cookie, check id, token).
async fn setup(db: &PgPool) -> (Router, String, Uuid, String) {
    let app = app(db.clone());
    let cookie = signup(&app, "ops@example.com").await;
    let id = create_check(&app, &cookie, HOURLY).await;
    let token = token_of(db, id).await;
    (app, cookie, id, token)
}

// ───────────────────────────── UI ─────────────────────────────

#[sqlx::test]
async fn created_check_shows_ping_url_and_starts_as_new(db: PgPool) {
    let (app, cookie, id, token) = setup(&db).await;

    let page = send(&app, get(&format!("/checks/{id}"), Some(&cookie))).await;
    assert_eq!(page.status, StatusCode::OK);
    assert!(page.body.contains("Nightly backup"));
    assert!(
        page.body
            .contains(&format!("http://localhost:3000/p/{token}"))
    );
    assert!(page.body.contains("every 1 hour"));
    assert_eq!(token.len(), 22);

    let dash = send(&app, get("/checks", Some(&cookie))).await;
    assert!(dash.body.contains("Nightly backup"));
    assert!(dash.body.contains("after first ping"));
    assert_eq!(status_of(&db, id).await, "new");
}

#[sqlx::test]
async fn invalid_form_returns_partial_with_values_kept(db: PgPool) {
    let app = app(db.clone());
    let cookie = signup(&app, "ops@example.com").await;
    let csrf = csrf_token(&app, &cookie).await;

    let req = post_form("/checks", Some(&cookie))
        .header("HX-Request", "true")
        .header("X-CSRF-Token", csrf)
        .body(Body::from(
            "name=Backup&schedule_kind=cron&cron_expr=99+2+*+*+*&tz=UTC&grace_value=1&grace_unit=hours",
        ))
        .unwrap();
    let res = send(&app, req).await;
    assert_eq!(res.status, StatusCode::UNPROCESSABLE_ENTITY);
    assert!(res.body.contains("Invalid cron expression"), "{}", res.body);
    assert!(res.body.contains("99 2 * * *"), "the expression is kept");
    assert!(!res.body.contains("<html"));
    assert_eq!(count(&db, "SELECT count(*) FROM checks").await, 0);
}

#[sqlx::test]
async fn schedule_preview_swaps_only_itself(db: PgPool) {
    // The preview sits inside a form with hx-target="this" + outerHTML, which htmx
    // children inherit; without its own target the preview replaced the whole form.
    let (app, cookie, id, _) = setup(&db).await;
    for path in ["/checks/new".to_owned(), format!("/checks/{id}/edit")] {
        let page = send(&app, get(&path, Some(&cookie))).await;
        let start = page.body.find(r#"class="preview"#).expect("preview div");
        let tag = &page.body[start..start + page.body[start..].find('>').unwrap()];
        assert!(tag.contains(r#"hx-target="this""#), "{path}: {tag}");
        assert!(tag.contains(r#"hx-swap="innerHTML""#), "{path}: {tag}");
    }
}

#[sqlx::test]
async fn editing_switches_to_a_cron_schedule(db: PgPool) {
    let (app, cookie, id, _) = setup(&db).await;
    let csrf = csrf_token(&app, &cookie).await;
    let body = format!(
        "_csrf={csrf}&name=Backup&schedule_kind=cron&cron_expr=0+2+*+*+*&tz=Asia%2FKolkata&grace_value=15&grace_unit=minutes&max_runtime_minutes=30"
    );
    let res = send(
        &app,
        form_req(&format!("/checks/{id}"), &body, Some(&cookie)),
    )
    .await;
    assert_eq!(res.status, StatusCode::SEE_OTHER, "{}", res.body);

    let (kind, expr, tz, period, grace, max_rt): (String, Option<String>, Option<String>, Option<i32>, i32, Option<i32>) =
        sqlx::query_as(
            "SELECT schedule_kind, cron_expr, tz, period_secs, grace_secs, max_runtime_secs FROM checks WHERE id = $1",
        )
        .bind(id)
        .fetch_one(&db)
        .await
        .unwrap();
    assert_eq!(kind, "cron");
    assert_eq!(expr.as_deref(), Some("0 2 * * *"));
    assert_eq!(tz.as_deref(), Some("Asia/Kolkata"));
    assert_eq!(period, None);
    assert_eq!(grace, 900);
    assert_eq!(max_rt, Some(1800));

    let edit = send(&app, get(&format!("/checks/{id}/edit"), Some(&cookie))).await;
    assert!(edit.body.contains(r#"value="Asia/Kolkata""#));
}

#[sqlx::test]
async fn other_orgs_get_404_everywhere(db: PgPool) {
    let (app, _, id, _) = setup(&db).await;
    let bob = signup(&app, "bob@example.com").await;
    let csrf = csrf_token(&app, &bob).await;

    for path in [
        format!("/checks/{id}"),
        format!("/checks/{id}/edit"),
        format!("/checks/{id}/activity"),
    ] {
        let res = send(&app, get(&path, Some(&bob))).await;
        assert_eq!(res.status, StatusCode::NOT_FOUND, "GET {path}");
    }
    for (path, body) in [
        (format!("/checks/{id}"), format!("_csrf={csrf}&{HOURLY}")),
        (format!("/checks/{id}"), format!("_csrf={csrf}&name=")),
        (format!("/checks/{id}/pause"), format!("_csrf={csrf}")),
        (format!("/checks/{id}/resume"), format!("_csrf={csrf}")),
        (format!("/checks/{id}/delete"), format!("_csrf={csrf}")),
    ] {
        let res = send(&app, form_req(&path, &body, Some(&bob))).await;
        assert_eq!(res.status, StatusCode::NOT_FOUND, "POST {path}");
    }
    assert_eq!(status_of(&db, id).await, "new", "untouched");
}

#[sqlx::test]
async fn preview_shows_next_runs_in_the_checks_timezone(db: PgPool) {
    let app = app(db);
    let cookie = signup(&app, "ops@example.com").await;
    let res = send(
        &app,
        get(
            "/checks/preview?schedule_kind=cron&cron_expr=0+2+*+*+*&tz=Asia%2FKolkata",
            Some(&cookie),
        ),
    )
    .await;
    assert_eq!(res.status, StatusCode::OK);
    assert_eq!(res.body.matches("02:00 IST").count(), 3, "{}", res.body);

    let res = send(
        &app,
        get(
            "/checks/preview?schedule_kind=cron&cron_expr=nope&tz=UTC",
            Some(&cookie),
        ),
    )
    .await;
    assert!(res.body.contains("Invalid cron expression"));
}

#[sqlx::test]
async fn pause_resume_and_delete(db: PgPool) {
    let (app, cookie, id, token) = setup(&db).await;
    let csrf = csrf_token(&app, &cookie).await;
    let csrf_body = format!("_csrf={csrf}");

    let res = send(
        &app,
        form_req(&format!("/checks/{id}/pause"), &csrf_body, Some(&cookie)),
    )
    .await;
    assert_eq!(res.status, StatusCode::SEE_OTHER);
    assert_eq!(status_of(&db, id).await, "paused");

    // Pings are logged but don't change a paused check.
    assert_eq!(
        ping(&app, &format!("/p/{token}"), "").await.status,
        StatusCode::OK
    );
    assert_eq!(status_of(&db, id).await, "paused");
    assert_eq!(count(&db, "SELECT count(*) FROM pings").await, 1);

    send(
        &app,
        form_req(&format!("/checks/{id}/resume"), &csrf_body, Some(&cookie)),
    )
    .await;
    assert_eq!(status_of(&db, id).await, "new");

    let res = send(
        &app,
        form_req(&format!("/checks/{id}/delete"), &csrf_body, Some(&cookie)),
    )
    .await;
    assert_eq!(res.status, StatusCode::SEE_OTHER);
    assert_eq!(res.header("location"), "/checks");
    assert_eq!(count(&db, "SELECT count(*) FROM checks").await, 0);
    assert_eq!(
        count(&db, "SELECT count(*) FROM pings").await,
        0,
        "pings cascade"
    );
}

// ───────────────────────────── ingest ─────────────────────────────

#[sqlx::test]
async fn success_ping_marks_up_and_sets_the_deadline(db: PgPool) {
    let (app, _, id, token) = setup(&db).await;

    let res = send(&app, get(&format!("/p/{token}"), None)).await;
    assert_eq!(res.status, StatusCode::OK);
    assert_eq!(res.body, "OK\n");
    assert_eq!(status_of(&db, id).await, "up");

    // Hourly with 10 minutes grace: alert 70 minutes after the ping.
    let (to_next, to_alert): (i64, i64) = sqlx::query_as(
        "SELECT EXTRACT(EPOCH FROM next_expected_at - last_ping_at)::bigint,
                EXTRACT(EPOCH FROM alert_after - last_ping_at)::bigint
         FROM checks WHERE id = $1",
    )
    .bind(id)
    .fetch_one(&db)
    .await
    .unwrap();
    assert_eq!((to_next, to_alert), (3600, 4200));
}

#[sqlx::test]
async fn start_then_success_records_duration(db: PgPool) {
    let app = app(db.clone());
    let cookie = signup(&app, "ops@example.com").await;
    let id = create_check(&app, &cookie, &format!("{HOURLY}&max_runtime_minutes=5")).await;
    let token = token_of(&db, id).await;

    ping(&app, &format!("/p/{token}/start"), "").await;
    assert_eq!(status_of(&db, id).await, "started");
    let to_alert: i64 = sqlx::query_scalar(
        "SELECT EXTRACT(EPOCH FROM alert_after - last_start_at)::bigint FROM checks WHERE id = $1",
    )
    .bind(id)
    .fetch_one(&db)
    .await
    .unwrap();
    assert_eq!(to_alert, 300, "max run time bounds a started run");

    ping(&app, &format!("/p/{token}"), "").await;
    assert_eq!(status_of(&db, id).await, "up");
    let duration: Option<i32> =
        sqlx::query_scalar("SELECT duration_ms FROM pings WHERE kind = 'success'")
            .fetch_one(&db)
            .await
            .unwrap();
    assert!(duration.is_some_and(|ms| ms >= 0));
    assert_eq!(
        count(
            &db,
            "SELECT count(*) FROM checks WHERE last_start_at IS NULL"
        )
        .await,
        1
    );
}

#[sqlx::test]
async fn failure_opens_an_incident_and_success_resolves_it(db: PgPool) {
    let (app, cookie, id, token) = setup(&db).await;

    let res = ping(
        &app,
        &format!("/p/{token}/fail"),
        "pg_dump: connection refused",
    )
    .await;
    assert_eq!(res.status, StatusCode::OK);
    assert_eq!(status_of(&db, id).await, "down");

    let (reason, cause_body): (String, Option<String>) = sqlx::query_as(
        "SELECT i.reason, p.body FROM incidents i JOIN pings p ON p.id = i.cause_ping_id
         WHERE i.check_id = $1 AND i.resolved_at IS NULL",
    )
    .bind(id)
    .fetch_one(&db)
    .await
    .unwrap();
    assert_eq!(reason, "failed");
    assert_eq!(cause_body.as_deref(), Some("pg_dump: connection refused"));

    let page = send(&app, get(&format!("/checks/{id}"), Some(&cookie))).await;
    assert!(page.body.contains("Job failed"));
    assert!(page.body.contains("pg_dump: connection refused"));

    // A second failure while down doesn't open another incident.
    ping(&app, &format!("/p/{token}/fail"), "").await;
    assert_eq!(count(&db, "SELECT count(*) FROM incidents").await, 1);

    ping(&app, &format!("/p/{token}"), "").await;
    assert_eq!(status_of(&db, id).await, "up");
    assert_eq!(
        count(
            &db,
            "SELECT count(*) FROM incidents WHERE resolved_at IS NOT NULL"
        )
        .await,
        1
    );
}

#[sqlx::test]
async fn exit_codes_map_to_success_and_failure(db: PgPool) {
    let (app, _, id, token) = setup(&db).await;

    ping(&app, &format!("/p/{token}/0"), "").await;
    assert_eq!(status_of(&db, id).await, "up");

    ping(&app, &format!("/p/{token}/3"), "").await;
    assert_eq!(status_of(&db, id).await, "down");
    let detail: String = sqlx::query_scalar("SELECT detail FROM incidents")
        .fetch_one(&db)
        .await
        .unwrap();
    assert_eq!(detail, "Job exited with code 3.");
    assert_eq!(
        count(
            &db,
            "SELECT count(*) FROM pings WHERE kind = 'exit' AND exit_code IS NOT NULL"
        )
        .await,
        2
    );
}

#[sqlx::test]
async fn bad_ping_urls_are_rejected(db: PgPool) {
    let (app, _, _, token) = setup(&db).await;
    assert_eq!(
        ping(&app, "/p/does-not-exist", "").await.status,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        ping(&app, &format!("/p/{token}/256"), "").await.status,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        ping(&app, &format!("/p/{token}/restart"), "").await.status,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(count(&db, "SELECT count(*) FROM pings").await, 0);
}

#[sqlx::test]
async fn large_bodies_keep_the_last_10kb(db: PgPool) {
    let (app, _, _, token) = setup(&db).await;
    let body = format!("{}{}", "A".repeat(10_240), "B".repeat(10_240));
    assert_eq!(
        ping(&app, &format!("/p/{token}/fail"), &body).await.status,
        StatusCode::OK
    );

    let stored: String = sqlx::query_scalar("SELECT body FROM pings")
        .fetch_one(&db)
        .await
        .unwrap();
    assert_eq!(stored.len(), 10_240);
    assert!(stored.chars().all(|c| c == 'B'));
}

// ───────────────────────────── scheduler ─────────────────────────────

#[sqlx::test]
async fn scheduler_marks_overdue_checks_down_once(db: PgPool) {
    let app = app(db.clone());
    let cookie = signup(&app, "ops@example.com").await;
    let quiet = create_check(&app, &cookie, HOURLY).await;
    let stuck = create_check(&app, &cookie, HOURLY).await;
    ping(&app, &format!("/p/{}", token_of(&db, quiet).await), "").await;
    ping(
        &app,
        &format!("/p/{}/start", token_of(&db, stuck).await),
        "",
    )
    .await;
    // Not overdue yet: nothing happens.
    assert_eq!(scheduler::tick(&db, ORIGIN).await.unwrap(), 0);

    set_overdue(&db, quiet).await;
    set_overdue(&db, stuck).await;
    assert_eq!(scheduler::tick(&db, ORIGIN).await.unwrap(), 2);
    assert_eq!(status_of(&db, quiet).await, "down");
    assert_eq!(status_of(&db, stuck).await, "down");

    let reasons: Vec<(Uuid, String)> =
        sqlx::query_as("SELECT check_id, reason FROM incidents ORDER BY reason")
            .fetch_all(&db)
            .await
            .unwrap();
    assert_eq!(
        reasons,
        vec![(stuck, "hung".into()), (quiet, "missed".into())]
    );

    // Already down: a second tick is a no-op.
    assert_eq!(scheduler::tick(&db, ORIGIN).await.unwrap(), 0);
    assert_eq!(count(&db, "SELECT count(*) FROM incidents").await, 2);

    // The next ping brings it back up and closes the incident.
    ping(&app, &format!("/p/{}", token_of(&db, quiet).await), "").await;
    assert_eq!(status_of(&db, quiet).await, "up");
    assert_eq!(
        count(
            &db,
            "SELECT count(*) FROM incidents WHERE resolved_at IS NULL"
        )
        .await,
        1
    );
}

#[sqlx::test]
async fn scheduler_ignores_new_and_paused_checks(db: PgPool) {
    let (app, cookie, id, _) = setup(&db).await;
    set_overdue(&db, id).await; // status 'new'
    assert_eq!(scheduler::tick(&db, ORIGIN).await.unwrap(), 0);

    let csrf = csrf_token(&app, &cookie).await;
    send(
        &app,
        form_req(
            &format!("/checks/{id}/pause"),
            &format!("_csrf={csrf}"),
            Some(&cookie),
        ),
    )
    .await;
    set_overdue(&db, id).await;
    assert_eq!(scheduler::tick(&db, ORIGIN).await.unwrap(), 0);
    assert_eq!(count(&db, "SELECT count(*) FROM incidents").await, 0);
}

#[sqlx::test]
async fn concurrent_schedulers_open_one_incident_per_check(db: PgPool) {
    let app = app(db.clone());
    let cookie = signup(&app, "ops@example.com").await;
    for _ in 0..25 {
        let id = create_check(&app, &cookie, HOURLY).await;
        ping(&app, &format!("/p/{}", token_of(&db, id).await), "").await;
    }
    sqlx::query("UPDATE checks SET alert_after = now() - interval '1 second'")
        .execute(&db)
        .await
        .unwrap();

    let (a, b, c) = tokio::join!(
        scheduler::tick(&db, ORIGIN),
        scheduler::tick(&db, ORIGIN),
        scheduler::tick(&db, ORIGIN)
    );
    assert_eq!(a.unwrap() + b.unwrap() + c.unwrap(), 25);
    assert_eq!(count(&db, "SELECT count(*) FROM incidents").await, 25);
    assert_eq!(
        count(&db, "SELECT count(*) FROM checks WHERE status = 'down'").await,
        25
    );
}
