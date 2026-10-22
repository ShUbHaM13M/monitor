//! Public status pages: managing them and what visitors see.

mod common;

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::Value;
use sqlx::PgPool;
use uuid::Uuid;

use common::*;

const CHECK: &str = "name=prod-db-backup-cron&schedule_kind=period&period_value=1&period_unit=days&grace_value=1&grace_unit=hours";

struct Ctx {
    db: PgPool,
    app: Router,
    cookie: String,
    check: Uuid,
    monitor: Uuid,
}

async fn setup(db: PgPool) -> Ctx {
    let app = app(db.clone());
    let cookie = signup(&app, "ops@example.com").await;
    let check = create_check(&app, &cookie, CHECK).await;
    let csrf = csrf_token(&app, &cookie).await;
    let form = format!(
        "_csrf={csrf}&name=internal-api-lb&method=GET&url={}&interval_secs=60&timeout_secs=5&fail_threshold=2",
        encode("https://api.internal.example.com/health")
    );
    let res = send(&app, form_req("/monitors", &form, Some(&cookie))).await;
    let monitor = res
        .header("location")
        .trim_start_matches("/monitors/")
        .parse()
        .unwrap();
    Ctx {
        db,
        app,
        cookie,
        check,
        monitor,
    }
}

impl Ctx {
    async fn save(&self, path: &str, fields: &str) -> Resp {
        let csrf = csrf_token(&self.app, &self.cookie).await;
        send(
            &self.app,
            form_req(path, &format!("_csrf={csrf}&{fields}"), Some(&self.cookie)),
        )
        .await
    }

    fn page_fields(&self, published: bool) -> String {
        let (c, m) = (self.check, self.monitor);
        format!(
            "title=Acme+Status&slug=acme&description=Live+status+of+Acme.\
             &show.c:{c}=on&name.c:{c}=Nightly+backups&pos.c:{c}=2\
             &show.m:{m}=on&name.m:{m}=Public+API&pos.m:{m}=1{}",
            if published { "&published=on" } else { "" }
        )
    }

    async fn ping(&self, suffix: &str) {
        let token = token_of(&self.db, self.check).await;
        let req = Request::post(format!("/p/{token}{suffix}"))
            .body(Body::empty())
            .unwrap();
        assert_eq!(send(&self.app, req).await.status, StatusCode::OK);
    }

    async fn sql(&self, sql: &'static str) {
        sqlx::query(sql).execute(&self.db).await.unwrap();
    }
}

#[sqlx::test]
async fn drafts_are_private_and_published_pages_hide_internals(db: PgPool) {
    let ctx = setup(db).await;
    let res = ctx.save("/status-pages", &ctx.page_fields(false)).await;
    assert_eq!(res.status, StatusCode::SEE_OTHER, "{}", res.body);

    // Draft: 404 for visitors, a preview for the org.
    assert_eq!(
        send(&ctx.app, get("/s/acme", None)).await.status,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        send(&ctx.app, get("/s/acme/status.json", None))
            .await
            .status,
        StatusCode::NOT_FOUND
    );
    let preview = send(&ctx.app, get("/s/acme", Some(&ctx.cookie))).await;
    assert_eq!(preview.status, StatusCode::OK);
    assert!(preview.body.contains("Draft preview"));
    assert!(preview.body.contains("noindex"));
    assert_eq!(preview.header("cache-control"), "private, no-store");
    let eve = signup(&ctx.app, "eve@example.com").await;
    assert_eq!(
        send(&ctx.app, get("/s/acme", Some(&eve))).await.status,
        StatusCode::NOT_FOUND
    );

    let id: Uuid = sqlx::query_scalar("SELECT id FROM status_pages")
        .fetch_one(&ctx.db)
        .await
        .unwrap();
    let res = ctx
        .save(&format!("/status-pages/{id}"), &ctx.page_fields(true))
        .await;
    assert_eq!(res.status, StatusCode::SEE_OTHER, "{}", res.body);

    let page = send(&ctx.app, get("/s/acme", None)).await;
    assert_eq!(page.status, StatusCode::OK);
    assert_eq!(page.header("cache-control"), "public, max-age=30");
    assert!(page.body.contains("Acme Status"));
    assert!(page.body.contains("Live status of Acme."));
    // Public names, in the chosen order; nothing internal.
    let api = page.body.find("Public API").unwrap();
    let backups = page.body.find("Nightly backups").unwrap();
    assert!(api < backups);
    let token = token_of(&ctx.db, ctx.check).await;
    for secret in [
        "prod-db-backup-cron",
        "internal-api-lb",
        "api.internal.example.com",
        token.as_str(),
        "ops@example.com",
    ] {
        assert!(!page.body.contains(secret), "leaked {secret}");
    }
    // No nav, session or CSRF on the public page.
    assert!(!page.body.contains("_csrf"));
    assert_eq!(page.body.matches("<rect x=").count(), 2 * 90);
}

#[sqlx::test]
async fn uptime_status_and_incidents(db: PgPool) {
    let ctx = setup(db).await;
    ctx.save("/status-pages", &ctx.page_fields(true)).await;
    ctx.ping("").await;
    // Monitoring for exactly 10 days; one hour down yesterday.
    ctx.sql("UPDATE checks SET created_at = now() - interval '10 days'")
        .await;
    let org: Uuid = sqlx::query_scalar("SELECT id FROM orgs")
        .fetch_one(&ctx.db)
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO incidents (id, org_id, check_id, reason, started_at, resolved_at)
         VALUES (gen_random_uuid(), $1, $2, 'missed',
                 date_trunc('day', now()) - interval '12 hours',
                 date_trunc('day', now()) - interval '11 hours'),
                (gen_random_uuid(), $1, $2, 'slow_run', now() - interval '1 day', now() - interval '1 day')",
    )
    .bind(org)
    .bind(ctx.check)
    .execute(&ctx.db)
    .await
    .unwrap();

    let page = send(&ctx.app, get("/s/acme", None)).await;
    assert!(page.body.contains("99.58% uptime"), "{}", page.body);
    assert_eq!(
        page.body.matches("class=\"day-partial\"><title>").count(),
        1
    );
    assert!(page.body.contains("1 day with downtime"));
    assert!(
        page.body.contains("Didn&#39;t run on time") || page.body.contains("Didn't run on time")
    );
    assert!(page.body.contains("lasted 1h 00m"));
    // Unusual run times aren't outages.
    assert!(!page.body.contains("unusually"));
    // The monitor hasn't reported yet: no data, and it doesn't count against the verdict.
    assert!(page.body.contains("No data yet"));
    assert!(page.body.contains("All systems operational"));

    ctx.sql("UPDATE http_monitors SET status = 'up', last_checked_at = now()")
        .await;
    ctx.ping("/fail").await;
    let live = send(&ctx.app, get("/s/acme/live", None)).await;
    assert!(live.body.contains("Partial outage"));
    assert!(!live.body.contains("<html"), "a fragment");
    assert!(live.body.contains("ongoing for"));

    let json: Value =
        serde_json::from_str(&send(&ctx.app, get("/s/acme/status.json", None)).await.body).unwrap();
    assert_eq!(json["status"], "partial_outage");
    assert_eq!(json["components"][0]["name"], "Public API");
    assert_eq!(json["components"][0]["status"], "operational");
    assert_eq!(json["components"][1]["status"], "down");
    assert!(json["components"][1]["uptime_90d"].as_f64().unwrap() < 1.0);
}

#[sqlx::test]
async fn pages_cannot_show_another_orgs_checks(db: PgPool) {
    let ctx = setup(db).await;
    let eve = signup(&ctx.app, "eve@example.com").await;
    let eve_ctx = Ctx {
        db: ctx.db.clone(),
        app: ctx.app.clone(),
        cookie: eve,
        check: ctx.check,
        monitor: ctx.monitor,
    };
    // Eve forges a form naming Ops' check.
    let res = eve_ctx
        .save(
            "/status-pages",
            &ctx.page_fields(true).replace("slug=acme", "slug=evil"),
        )
        .await;
    assert_eq!(res.status, StatusCode::NOT_FOUND);
    assert_eq!(
        count(&ctx.db, "SELECT count(*) FROM status_page_items").await,
        0
    );
    assert_eq!(
        send(&ctx.app, get("/s/evil", None)).await.status,
        StatusCode::NOT_FOUND
    );
}

#[sqlx::test]
async fn slugs_are_unique_validated_and_limited(db: PgPool) {
    let ctx = setup(db).await;
    assert_eq!(
        ctx.save("/status-pages", "title=Acme&slug=acme")
            .await
            .status,
        StatusCode::SEE_OTHER
    );

    let res = ctx.save("/status-pages", "title=Other&slug=acme").await;
    assert_eq!(res.status, StatusCode::UNPROCESSABLE_ENTITY);
    assert!(res.body.contains("That address is taken"));
    assert!(
        res.body.contains(r#"value="Other""#),
        "keeps what was typed"
    );

    let res = ctx.save("/status-pages", "title=Other&slug=-bad-").await;
    assert!(res.body.contains("3–40 lowercase letters"));

    // A blank address comes from the title.
    assert_eq!(
        ctx.save("/status-pages", "title=Acme+Cloud%21&slug=")
            .await
            .status,
        StatusCode::SEE_OTHER
    );
    let slugs: Vec<String> =
        sqlx::query_scalar("SELECT slug FROM status_pages ORDER BY created_at")
            .fetch_all(&ctx.db)
            .await
            .unwrap();
    assert_eq!(slugs, ["acme", "acme-cloud"]);

    ctx.sql("UPDATE orgs SET max_status_pages = 2").await;
    let res = ctx.save("/status-pages", "title=Third&slug=third").await;
    assert_eq!(res.status, StatusCode::UNPROCESSABLE_ENTITY);
    assert!(res.body.contains("Your plan allows 2 status pages."));

    let list = send(&ctx.app, get("/status-pages", Some(&ctx.cookie))).await;
    assert!(list.body.contains("http://localhost:3000/s/acme-cloud"));
    assert!(list.body.contains("draft"));
}
