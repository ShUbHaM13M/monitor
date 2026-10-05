//! Email confirmation and password reset, with mail delivered to Mailpit.

mod common;

use axum::http::StatusCode;
use monitor::web;
use sqlx::PgPool;

use common::*;

async fn verified(db: &PgPool, email: &str) -> bool {
    sqlx::query_scalar("SELECT email_verified_at IS NOT NULL FROM users WHERE email = $1")
        .bind(email)
        .fetch_one(db)
        .await
        .unwrap()
}

/// Subjects in `address`'s inbox, newest first, once there are at least `n`.
async fn subjects(address: &str, n: usize) -> Vec<String> {
    inbox_with_at_least(address, n)
        .await
        .into_iter()
        .map(|(_, s)| s)
        .collect()
}

/// The link to `path` in the newest message that has one (waiting for it to arrive).
async fn emailed_link(address: &str, path: &str) -> String {
    let prefix = format!("{ORIGIN}{path}");
    for _ in 0..60 {
        for (id, _) in inbox(address).await {
            let text = message_text(&id).await;
            if text.contains(&prefix) {
                return link_path(&text, path);
            }
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    panic!("no {prefix} link mailed to {address}");
}

fn token_of(path: &str) -> &str {
    path.split("token=").nth(1).unwrap()
}

// ───────────────────────────── email confirmation ─────────────────────────────

#[sqlx::test]
async fn signup_sends_a_confirmation_link(db: PgPool) {
    let app = app(db.clone());
    let me = unique_address("me");
    let cookie = signup(&app, &me).await;

    assert_eq!(subjects(&me, 1).await, ["Confirm your email address"]);
    assert!(!verified(&db, &me).await);
    let dash = send(&app, get("/dashboard", Some(&cookie))).await;
    assert!(dash.body.contains("Please confirm your email address"));

    // GET only asks: mail scanners open links on their own.
    let path = emailed_link(&me, "/verify-email?token=").await;
    let page = send(&app, get(&path, None)).await;
    assert!(page.body.contains("Confirm email"));
    assert!(page.body.contains(&me));
    assert!(!verified(&db, &me).await);

    let body = format!("token={}", token_of(&path));
    let res = send(&app, form_req("/verify-email", &body, None)).await;
    assert!(res.body.contains("Email confirmed"));
    assert!(verified(&db, &me).await);

    let dash = send(&app, get("/dashboard", Some(&cookie))).await;
    assert!(!dash.body.contains("Please confirm your email address"));

    let again = send(&app, form_req("/verify-email", &body, None)).await;
    assert!(again.body.contains("Link expired"), "one-time link");
}

#[sqlx::test]
async fn confirming_while_logged_in_needs_the_csrf_token(db: PgPool) {
    let app = app(db.clone());
    let me = unique_address("me");
    let cookie = signup(&app, &me).await;
    let path = emailed_link(&me, "/verify-email?token=").await;
    let body = format!("token={}", token_of(&path));

    let res = send(&app, form_req("/verify-email", &body, Some(&cookie))).await;
    assert_eq!(res.status, StatusCode::FORBIDDEN);

    // The confirm page carries it.
    let page = send(&app, get(&path, Some(&cookie))).await;
    let csrf = csrf_token(&app, &cookie).await;
    assert!(page.body.contains(&csrf));
    let res = send(
        &app,
        form_req(
            "/verify-email",
            &format!("{body}&_csrf={csrf}"),
            Some(&cookie),
        ),
    )
    .await;
    assert!(res.body.contains("Email confirmed"));
    assert!(
        !res.body.contains("Please confirm your email address"),
        "banner gone at once"
    );
}

#[sqlx::test]
async fn resend_is_rate_limited(db: PgPool) {
    let app = app(db.clone());
    let me = unique_address("me");
    let cookie = signup(&app, &me).await;
    let csrf = csrf_token(&app, &cookie).await;
    let resend = || {
        form_req(
            "/verify-email/resend",
            &format!("_csrf={csrf}"),
            Some(&cookie),
        )
    };

    let res = send(&app, resend()).await;
    assert!(res.body.contains("less than a minute ago"), "{}", res.body);
    assert_eq!(subjects(&me, 1).await.len(), 1);

    sqlx::query("UPDATE user_tokens SET created_at = now() - interval '2 minutes'")
        .execute(&db)
        .await
        .unwrap();
    let res = send(&app, resend()).await;
    assert!(res.body.contains("Check your inbox"));
    assert_eq!(subjects(&me, 2).await.len(), 2);
}

#[sqlx::test]
async fn own_address_channel_needs_a_confirmed_account(db: PgPool) {
    // Otherwise signing up with someone else's address would let you mail them.
    let app = app(db.clone());
    let me = unique_address("me");
    let cookie = signup(&app, &me).await;
    let csrf = csrf_token(&app, &cookie).await;
    let add = |address: &str| {
        form_req(
            "/channels/new/email",
            &format!("_csrf={csrf}&address={}", encode(address)),
            Some(&cookie),
        )
    };

    send(&app, add(&me)).await;
    assert_eq!(
        count(
            &db,
            "SELECT count(*) FROM channels WHERE verified_at IS NULL"
        )
        .await,
        1
    );

    sqlx::query("UPDATE users SET email_verified_at = now()")
        .execute(&db)
        .await
        .unwrap();
    send(&app, add(&me)).await;
    assert_eq!(
        count(
            &db,
            "SELECT count(*) FROM channels WHERE verified_at IS NOT NULL"
        )
        .await,
        1
    );
}

#[sqlx::test]
async fn without_smtp_there_is_no_banner_or_reset(db: PgPool) {
    let mut config = test_config();
    config.smtp_url = None;
    let app = web::router(state_with(db, config));
    let cookie = signup(&app, "ops@example.com").await;

    let dash = send(&app, get("/dashboard", Some(&cookie))).await;
    assert!(!dash.body.contains("Please confirm your email address"));
    let page = send(&app, get("/forgot-password", None)).await;
    assert!(page.body.contains("can&#39;t send email") || page.body.contains("can't send email"));
}

// ───────────────────────────── password reset ─────────────────────────────

const NEW_PASSWORD: &str = "a brand new passphrase";

#[sqlx::test]
async fn forgot_password_never_reveals_whether_an_account_exists(db: PgPool) {
    let app = app(db);
    let me = unique_address("me");
    signup(&app, &me).await;
    let nobody = unique_address("nobody");

    let known = send(
        &app,
        form_req("/forgot-password", &format!("email={}", encode(&me)), None),
    )
    .await;
    let unknown = send(
        &app,
        form_req(
            "/forgot-password",
            &format!("email={}", encode(&nobody)),
            None,
        ),
    )
    .await;
    assert_eq!(known.status, unknown.status);
    assert_eq!(
        known.body.replace(&me, "X"),
        unknown.body.replace(&nobody, "X"),
        "identical pages"
    );
    assert_eq!(subjects(&me, 2).await[0], "Reset your Monitor password");
    assert!(subjects(&nobody, 0).await.is_empty());
}

#[sqlx::test]
async fn reset_password_end_to_end(db: PgPool) {
    let app = app(db.clone());
    let me = unique_address("me");
    let old_session = signup(&app, &me).await;
    send(
        &app,
        form_req(
            "/forgot-password",
            &format!("email={}", encode(&me.to_uppercase())),
            None,
        ),
    )
    .await;
    let path = emailed_link(&me, "/reset-password?token=").await;
    let token = token_of(&path).to_owned();

    let page = send(&app, get(&path, None)).await;
    assert!(page.body.contains("Choose a new password"));
    assert!(page.body.contains(&me));

    // Validation keeps the token usable.
    for (password, confirm, error) in [
        ("short", "short", "at least 10 characters"),
        (NEW_PASSWORD, "something else entirely", "don&#39;t match"),
    ] {
        let body = format!(
            "token={token}&password={}&confirm={}",
            encode(password),
            encode(confirm)
        );
        let res = send(&app, form_req("/reset-password", &body, None)).await;
        assert_eq!(res.status, StatusCode::UNPROCESSABLE_ENTITY);
        assert!(
            res.body.contains(error) || res.body.contains(&error.replace("&#39;", "'")),
            "{}",
            res.body
        );
    }

    let body = format!(
        "token={token}&password={0}&confirm={0}",
        encode(NEW_PASSWORD)
    );
    let res = send(&app, form_req("/reset-password", &body, None)).await;
    assert_eq!(res.status, StatusCode::SEE_OTHER);
    assert_eq!(res.header("location"), "/login?reset=1");
    let login_page = send(&app, get("/login?reset=1", None)).await;
    assert!(login_page.body.contains("Your password was changed"));

    // Logged out everywhere; the email counts as confirmed now.
    assert_eq!(
        send(&app, get("/dashboard", Some(&old_session)))
            .await
            .status,
        StatusCode::SEE_OTHER
    );
    assert_eq!(count(&db, "SELECT count(*) FROM sessions").await, 0);
    assert!(verified(&db, &me).await);

    let login = |password: &str| {
        form_req(
            "/login",
            &format!("email={}&password={}", encode(&me), encode(password)),
            None,
        )
    };
    assert_eq!(
        send(&app, login(PASSWORD)).await.status,
        StatusCode::UNPROCESSABLE_ENTITY
    );
    assert_eq!(
        send(&app, login(NEW_PASSWORD)).await.status,
        StatusCode::SEE_OTHER
    );

    // One-time link.
    let again = send(&app, form_req("/reset-password", &body, None)).await;
    assert!(again.body.contains("Link expired"));
    assert!(
        send(&app, get(&path, None))
            .await
            .body
            .contains("Link expired")
    );
}

#[sqlx::test]
async fn reset_links_expire_and_older_links_die_with_the_newest(db: PgPool) {
    let app = app(db.clone());
    let me = unique_address("me");
    signup(&app, &me).await;
    let request = || form_req("/forgot-password", &format!("email={}", encode(&me)), None);

    send(&app, request()).await;
    let first = emailed_link(&me, "/reset-password?token=").await;
    send(&app, request()).await;
    tokio::time::sleep(std::time::Duration::from_millis(300)).await; // a stray email would land by now
    assert_eq!(
        subjects(&me, 2)
            .await
            .iter()
            .filter(|s| s.starts_with("Reset"))
            .count(),
        1,
        "one email a minute"
    );

    sqlx::query("UPDATE user_tokens SET created_at = now() - interval '2 minutes'")
        .execute(&db)
        .await
        .unwrap();
    send(&app, request()).await;
    subjects(&me, 3).await; // confirmation + two resets
    let second = emailed_link(&me, "/reset-password?token=").await;
    assert_ne!(first, second);

    // Using the newest link retires the older one too.
    let body = format!(
        "token={}&password={1}&confirm={1}",
        token_of(&second),
        encode(NEW_PASSWORD)
    );
    send(&app, form_req("/reset-password", &body, None)).await;
    assert!(
        send(&app, get(&first, None))
            .await
            .body
            .contains("Link expired")
    );

    // And links stop working after an hour.
    sqlx::query("UPDATE user_tokens SET created_at = now() - interval '2 minutes'")
        .execute(&db)
        .await
        .unwrap();
    send(&app, request()).await;
    subjects(&me, 4).await;
    let third = emailed_link(&me, "/reset-password?token=").await;
    sqlx::query("UPDATE user_tokens SET expires_at = now() - interval '1 second'")
        .execute(&db)
        .await
        .unwrap();
    assert!(
        send(&app, get(&third, None))
            .await
            .body
            .contains("Link expired")
    );
}

#[sqlx::test]
async fn tokens_only_work_for_their_purpose(db: PgPool) {
    let app = app(db.clone());
    let me = unique_address("me");
    signup(&app, &me).await;
    let verify = emailed_link(&me, "/verify-email?token=").await;

    let body = format!(
        "token={}&password={1}&confirm={1}",
        token_of(&verify),
        encode(NEW_PASSWORD)
    );
    let res = send(&app, form_req("/reset-password", &body, None)).await;
    assert!(
        res.body.contains("Link expired"),
        "a confirmation link can't reset passwords"
    );
    assert_eq!(
        count(&db, "SELECT count(*) FROM sessions").await,
        1,
        "nothing changed"
    );
}
