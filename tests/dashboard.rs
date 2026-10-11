mod common;

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use sqlx::PgPool;
use uuid::Uuid;

use common::*;

fn check_form(name: &str) -> String {
    format!(
        "name={}&schedule_kind=period&period_value=1&period_unit=hours&grace_value=10&grace_unit=minutes",
        encode(name)
    )
}

async fn fail(app: &Router, db: &PgPool, id: Uuid) {
    let token = token_of(db, id).await;
    let req = Request::post(format!("/p/{token}/fail"))
        .body(Body::from("pg_dump: connection refused"))
        .unwrap();
    assert_eq!(send(app, req).await.status, StatusCode::OK);
}

async fn succeed(app: &Router, db: &PgPool, id: Uuid) {
    let token = token_of(db, id).await;
    let req = Request::post(format!("/p/{token}"))
        .body(Body::empty())
        .unwrap();
    assert_eq!(send(app, req).await.status, StatusCode::OK);
}

async fn org_of(db: &PgPool, check: Uuid) -> Uuid {
    sqlx::query_scalar("SELECT org_id FROM checks WHERE id = $1")
        .bind(check)
        .fetch_one(db)
        .await
        .unwrap()
}

/// A verified channel, written directly: the overview only reads its row.
async fn add_channel(db: &PgPool, org: Uuid, name: &str, verified: bool) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO channels (id, org_id, kind, name, config_enc, verified_at)
         VALUES (gen_random_uuid(), $1, 'webhook', $2, '\\x00', CASE WHEN $3 THEN now() END)
         RETURNING id",
    )
    .bind(org)
    .bind(name)
    .bind(verified)
    .fetch_one(db)
    .await
    .unwrap()
}

fn htmx_get(path: &str, cookie: &str, trigger: Option<&str>) -> Request<Body> {
    let mut req = Request::get(path)
        .header(header::COOKIE, cookie)
        .header("HX-Request", "true");
    if let Some(id) = trigger {
        req = req.header("HX-Trigger", id);
    }
    req.body(Body::empty()).unwrap()
}

// ───────────────────────────── overview ─────────────────────────────

#[sqlx::test]
async fn new_org_gets_a_getting_started_checklist(db: PgPool) {
    let app = app(db);
    let cookie = signup(&app, "ops@example.com").await;

    let page = send(&app, get("/dashboard", Some(&cookie))).await;
    assert_eq!(page.status, StatusCode::OK);
    assert!(page.body.contains("Get started"));
    assert!(page.body.contains(r#"href="/checks/new""#));
    assert!(page.body.contains(r#"href="/channels/new""#));
    assert!(!page.body.contains("All systems operational"));
}

#[sqlx::test]
async fn overview_shows_what_is_down_and_why(db: PgPool) {
    let app = app(db.clone());
    let cookie = signup(&app, "ops@example.com").await;
    let backup = create_check(&app, &cookie, &check_form("Nightly backup")).await;
    let report = create_check(&app, &cookie, &check_form("Weekly report")).await;
    succeed(&app, &db, report).await;
    fail(&app, &db, backup).await;

    let page = send(&app, get("/dashboard", Some(&cookie))).await;
    assert!(page.body.contains("verdict-down"));
    assert!(page.body.contains("1 down"));
    assert!(page.body.contains("Down right now"));
    assert!(page.body.contains("Job failed"));
    assert!(page.body.contains(&format!(r#"href="/checks/{backup}""#)));
    // Counts link to the filtered lists.
    assert!(page.body.contains(r#"href="/checks?status=down""#));
    assert!(page.body.contains(r#"href="/checks?status=up""#));

    // The nav badge (and so the tab title) carries the count.
    let badge = send(&app, get("/nav/health", Some(&cookie))).await;
    assert!(badge.body.contains(r#"data-down="1""#));
    assert!(!badge.body.contains("hidden"));

    // Recovery moves it to "Recently resolved".
    succeed(&app, &db, backup).await;
    let live = send(&app, htmx_get("/dashboard/live", &cookie, None)).await;
    assert!(!live.body.contains("Down right now"));
    assert!(live.body.contains("Recently resolved"));
    assert!(live.body.contains("resolved"));
    assert!(!live.body.contains("<html"), "the poll gets a fragment");
    let badge = send(&app, get("/nav/health", Some(&cookie))).await;
    assert!(badge.body.contains(r#"data-down="0""#));
    assert!(badge.body.contains("hidden"));
}

#[sqlx::test]
async fn overview_warns_when_alerts_cannot_reach_anyone(db: PgPool) {
    let app = app(db.clone());
    let cookie = signup(&app, "ops@example.com").await;
    let id = create_check(&app, &cookie, &check_form("Nightly backup")).await;
    succeed(&app, &db, id).await;

    let page = send(&app, get("/dashboard", Some(&cookie))).await;
    assert!(page.body.contains("verdict-warn"));
    assert!(page.body.contains("No alert channels"));

    // A channel nobody confirmed doesn't count.
    let org = org_of(&db, id).await;
    add_channel(&db, org, "Boss", false).await;
    let page = send(&app, get("/dashboard", Some(&cookie))).await;
    assert!(page.body.contains("1 channel is"));
    assert!(page.body.contains("verdict-warn"));

    let hook = add_channel(&db, org, "Ops hook", true).await;
    let page = send(&app, get("/dashboard", Some(&cookie))).await;
    assert!(page.body.contains("verdict-ok"));
    assert!(page.body.contains("All systems operational"));
    assert!(page.body.contains("1 check up."));

    // Alerts that gave up after every retry are flagged.
    let incident: Uuid = sqlx::query_scalar(
        "INSERT INTO incidents (id, org_id, check_id, reason, resolved_at)
         VALUES (gen_random_uuid(), $1, $2, 'missed', now()) RETURNING id",
    )
    .bind(org)
    .bind(id)
    .fetch_one(&db)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO notifications (incident_id, channel_id, event, payload, status, attempts, last_error)
         VALUES ($1, $2, 'down', '{}', 'dead', 8, 'HTTP 410 Gone')",
    )
    .bind(incident)
    .bind(hook)
    .execute(&db)
    .await
    .unwrap();
    let page = send(&app, get("/dashboard", Some(&cookie))).await;
    assert!(page.body.contains("verdict-warn"));
    assert!(
        page.body.contains("1 alert couldn&#39;t be delivered")
            || page.body.contains("1 alert couldn't be delivered")
    );
    assert!(page.body.contains("HTTP 410 Gone"));
    assert!(page.body.contains(&format!(r#"href="/channels/{hook}""#)));
}

#[sqlx::test]
async fn overview_and_incidents_stay_within_the_org(db: PgPool) {
    let app = app(db.clone());
    let alice = signup(&app, "alice@example.com").await;
    let bob = signup(&app, "bob@example.com").await;
    let id = create_check(&app, &alice, &check_form("Alice secret backup")).await;
    fail(&app, &db, id).await;

    let alice_page = send(&app, get("/dashboard", Some(&alice))).await;
    assert!(alice_page.body.contains("Alice secret backup"));
    for path in [
        "/dashboard",
        "/dashboard/live",
        "/incidents",
        "/incidents?state=open",
    ] {
        let page = send(&app, get(path, Some(&bob))).await;
        assert_eq!(page.status, StatusCode::OK, "{path}");
        assert!(!page.body.contains("Alice secret backup"), "{path}");
    }
    let badge = send(&app, get("/nav/health", Some(&bob))).await;
    assert!(badge.body.contains(r#"data-down="0""#));
}

#[sqlx::test]
async fn pages_need_a_session(db: PgPool) {
    let app = app(db);
    for path in [
        "/dashboard",
        "/dashboard/live",
        "/nav/health",
        "/incidents",
        "/checks",
        "/checks/table",
    ] {
        let res = send(&app, get(path, None)).await;
        assert_eq!(res.status, StatusCode::SEE_OTHER, "{path}");
    }
}

// ───────────────────────────── incidents ─────────────────────────────

#[sqlx::test]
async fn incidents_page_filters_and_pages(db: PgPool) {
    let app = app(db.clone());
    let cookie = signup(&app, "ops@example.com").await;
    let id = create_check(&app, &cookie, &check_form("Nightly backup")).await;
    let org = org_of(&db, id).await;

    let empty = send(&app, get("/incidents", Some(&cookie))).await;
    assert!(empty.body.contains("No incidents yet"));
    let none_open = send(&app, get("/incidents?state=open", Some(&cookie))).await;
    assert!(none_open.body.contains("Nothing is down"));

    // 55 resolved incidents, one a day, then one ongoing.
    sqlx::query(
        "INSERT INTO incidents (id, org_id, check_id, reason, detail, started_at, resolved_at)
         SELECT gen_random_uuid(), $1, $2, 'missed', 'old #' || n,
                now() - make_interval(days => n), now() - make_interval(days => n) + interval '5 min'
         FROM generate_series(1, 55) n",
    )
    .bind(org)
    .bind(id)
    .execute(&db)
    .await
    .unwrap();
    fail(&app, &db, id).await;

    let first = send(&app, get("/incidents", Some(&cookie))).await;
    assert!(first.body.contains("ongoing"));
    assert!(first.body.contains("old #1<"));
    assert!(first.body.contains("old #49<"));
    assert!(!first.body.contains("old #50<"), "50 per page");
    assert!(first.body.contains("5m 00s"));
    let link = first.body.find("\">Older →").expect("an Older link");
    let start = first.body[..link].rfind("href=\"").unwrap() + "href=\"".len();
    let older = first.body[start..link].replace("&#38;", "&");

    let second = send(&app, get(&older, Some(&cookie))).await;
    assert_eq!(second.status, StatusCode::OK, "{older}");
    for n in 50..=55 {
        assert!(second.body.contains(&format!("old #{n}<")), "{n}");
    }
    assert!(!second.body.contains("old #49<"));
    assert!(!second.body.contains("Older →"));
    assert!(second.body.contains("← Newest"));

    let open = send(&app, get("/incidents?state=open", Some(&cookie))).await;
    assert!(open.body.contains("Job failed"));
    assert!(!open.body.contains("old #"));
    let resolved = send(&app, get("/incidents?state=resolved", Some(&cookie))).await;
    assert!(!resolved.body.contains("Job failed"));
    assert!(resolved.body.contains("old #1<"));
}

// ───────────────────────────── lists ─────────────────────────────

#[sqlx::test]
async fn checks_list_puts_problems_first_and_filters(db: PgPool) {
    let app = app(db.clone());
    let cookie = signup(&app, "ops@example.com").await;
    let alpha = create_check(&app, &cookie, &check_form("Alpha sync")).await;
    let _beta = create_check(&app, &cookie, &check_form("Beta report")).await;
    let zulu = create_check(&app, &cookie, &check_form("Zulu backup")).await;
    succeed(&app, &db, alpha).await;
    fail(&app, &db, zulu).await;

    let page = send(&app, get("/checks", Some(&cookie))).await;
    let pos = |name: &str| page.body.find(name).unwrap_or_else(|| panic!("{name}"));
    assert!(pos("Zulu backup") < pos("Alpha sync"), "down first");
    assert!(pos("Alpha sync") < pos("Beta report"), "up before new");
    assert!(page.body.contains(r#"value="down""#));
    assert!(
        !page.body.contains(r#"value="paused""#),
        "empty statuses are hidden"
    );

    let down = send(&app, get("/checks?status=down", Some(&cookie))).await;
    assert!(down.body.contains("Zulu backup"));
    assert!(!down.body.contains("Alpha sync"));
    assert!(down.body.contains(r#"value="down" checked"#));

    let search = send(&app, get("/checks?q=REPORT", Some(&cookie))).await;
    assert!(search.body.contains("Beta report"));
    assert!(!search.body.contains("Zulu backup"));
    assert!(
        search.body.contains(r#"value="REPORT""#),
        "search box keeps its text"
    );

    let none = send(&app, get("/checks?q=nothing+like+this", Some(&cookie))).await;
    assert!(none.body.contains("No checks match"));

    // The filter form updates the address bar; the periodic refresh doesn't.
    let filtered = send(
        &app,
        htmx_get(
            "/checks/table?status=down&q=zulu",
            &cookie,
            Some("check-filters"),
        ),
    )
    .await;
    assert_eq!(
        filtered.header("HX-Replace-Url"),
        "/checks?status=down&q=zulu"
    );
    assert!(filtered.body.contains("Zulu backup"));
    assert!(!filtered.body.contains("<html"));
    let poll = send(
        &app,
        htmx_get("/checks/table?status=down", &cookie, Some("check-list")),
    )
    .await;
    assert!(poll.headers.get("HX-Replace-Url").is_none());
}

#[sqlx::test]
async fn monitors_list_filters_by_status_and_url(db: PgPool) {
    let app = app(db.clone());
    let cookie = signup(&app, "ops@example.com").await;
    let csrf = csrf_token(&app, &cookie).await;
    for (name, url) in [
        ("Website", "https://example.com/"),
        ("Payments API", "https://api.example.org/health"),
    ] {
        let form = format!(
            "_csrf={csrf}&name={}&method=GET&url={}&interval_secs=60&timeout_secs=5&fail_threshold=2",
            encode(name),
            encode(url)
        );
        let res = send(&app, form_req("/monitors", &form, Some(&cookie))).await;
        assert_eq!(res.status, StatusCode::SEE_OTHER, "{}", res.body);
    }
    sqlx::query("UPDATE http_monitors SET status = 'down' WHERE name = 'Payments API'")
        .execute(&db)
        .await
        .unwrap();

    let page = send(&app, get("/monitors", Some(&cookie))).await;
    assert!(page.body.find("Payments API").unwrap() < page.body.find("Website").unwrap());

    let by_url = send(&app, get("/monitors?q=api.example", Some(&cookie))).await;
    assert!(by_url.body.contains("Payments API"));
    assert!(!by_url.body.contains("Website"));

    let up = send(
        &app,
        htmx_get(
            "/monitors/table?status=new",
            &cookie,
            Some("monitor-filters"),
        ),
    )
    .await;
    assert!(up.body.contains("Website"));
    assert!(!up.body.contains("Payments API"));
    assert_eq!(up.header("HX-Replace-Url"), "/monitors?status=new");
}

#[sqlx::test]
async fn times_render_as_machine_readable_elements(db: PgPool) {
    let app = app(db.clone());
    let cookie = signup(&app, "ops@example.com").await;
    let id = create_check(&app, &cookie, &check_form("Nightly backup")).await;
    succeed(&app, &db, id).await;

    let list = send(&app, get("/checks", Some(&cookie))).await;
    assert!(list.body.contains(r#"<time datetime=""#));
    assert!(list.body.contains("just now</time>"));
    let detail = send(&app, get(&format!("/checks/{id}"), Some(&cookie))).await;
    assert!(detail.body.contains(" UTC\">just now</time>"));
    assert!(
        detail
            .body
            .contains(r#"<script src="/static/app.js" defer></script>"#)
    );
}
