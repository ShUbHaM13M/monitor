use askama::Template;
use axum::Form;
use axum::extract::{Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum_extra::extract::cookie::CookieJar;
use serde::Deserialize;
use uuid::Uuid;

use super::{AppError, AppState, Chrome, account, is_htmx, redirect};
use crate::auth::{MaybeUser, password, session};
use crate::db::users::{self, CreateAccountError};

const AFTER_LOGIN: &str = "/dashboard";
const MAX_ORG_NAME: usize = 100;

// ───────────────────────────── signup ─────────────────────────────

#[derive(Default)]
pub struct SignupView {
    email: String,
    org_name: String,
    error: Option<&'static str>,
}

#[derive(Template)]
#[template(path = "auth/signup.html")]
struct SignupPage {
    chrome: Chrome,
    form: SignupView,
}

#[derive(Template)]
#[template(path = "auth/signup_form.html")]
struct SignupForm {
    form: SignupView,
}

#[derive(Deserialize)]
pub struct SignupInput {
    email: String,
    password: String,
    #[serde(default)]
    org_name: String,
}

pub async fn signup_page(MaybeUser(user): MaybeUser) -> Result<Response, AppError> {
    if user.is_some() {
        return Ok(Redirect::to(AFTER_LOGIN).into_response());
    }
    let page = SignupPage {
        chrome: Chrome::anonymous(),
        form: SignupView::default(),
    };
    Ok(Html(page.render()?).into_response())
}

pub async fn signup(
    State(state): State<AppState>,
    headers: HeaderMap,
    jar: CookieJar,
    Form(input): Form<SignupInput>,
) -> Result<Response, AppError> {
    let email = input.email.trim();
    let org_name = input.org_name.trim();
    let mut view = SignupView {
        email: email.to_owned(),
        org_name: org_name.to_owned(),
        error: None,
    };

    view.error = validate_email(email)
        .or_else(|| validate_password(&input.password))
        .or_else(|| {
            (org_name.chars().count() > MAX_ORG_NAME)
                .then_some("Organisation name must be at most 100 characters.")
        });
    if view.error.is_some() {
        return signup_error(&headers, view);
    }

    let org_name = if org_name.is_empty() {
        default_org_name(email)
    } else {
        org_name.to_owned()
    };
    let hash = password::hash(input.password).await?;
    match users::create_account(&state.db, email, &hash, &org_name).await {
        Ok(account) => {
            account::send_verification_email(&state, account.user_id, email).await;
            start_session(
                &state,
                jar,
                &headers,
                account.user_id,
                account.org_id,
                AFTER_LOGIN,
            )
            .await
        }
        Err(CreateAccountError::EmailTaken) => {
            view.error = Some("An account with this email already exists. Try logging in.");
            signup_error(&headers, view)
        }
        Err(CreateAccountError::Db(err)) => Err(err.into()),
    }
}

fn signup_error(headers: &HeaderMap, form: SignupView) -> Result<Response, AppError> {
    let html = if is_htmx(headers) {
        SignupForm { form }.render()?
    } else {
        SignupPage {
            chrome: Chrome::anonymous(),
            form,
        }
        .render()?
    };
    Ok((StatusCode::UNPROCESSABLE_ENTITY, Html(html)).into_response())
}

// ───────────────────────────── login ─────────────────────────────

#[derive(Default)]
pub struct LoginView {
    email: String,
    next: String,
    error: Option<&'static str>,
    notice: Option<&'static str>,
}

#[derive(Template)]
#[template(path = "auth/login.html")]
struct LoginPage {
    chrome: Chrome,
    form: LoginView,
}

#[derive(Template)]
#[template(path = "auth/login_form.html")]
struct LoginForm {
    form: LoginView,
}

#[derive(Deserialize)]
pub struct LoginQuery {
    next: Option<String>,
    /// Set after a successful password reset.
    reset: Option<String>,
}

#[derive(Deserialize)]
pub struct LoginInput {
    email: String,
    password: String,
    #[serde(default)]
    next: String,
}

pub async fn login_page(
    MaybeUser(user): MaybeUser,
    Query(query): Query<LoginQuery>,
) -> Result<Response, AppError> {
    let next = safe_next(query.next.as_deref().unwrap_or_default());
    if user.is_some() {
        return Ok(Redirect::to(next).into_response());
    }
    let page = LoginPage {
        chrome: Chrome::anonymous(),
        form: LoginView {
            next: next.to_owned(),
            notice: query
                .reset
                .is_some()
                .then_some("Your password was changed. Log in with the new one."),
            ..Default::default()
        },
    };
    Ok(Html(page.render()?).into_response())
}

pub async fn login(
    State(state): State<AppState>,
    headers: HeaderMap,
    jar: CookieJar,
    Form(input): Form<LoginInput>,
) -> Result<Response, AppError> {
    let email = input.email.trim();
    let next = safe_next(&input.next);

    let candidate = users::find_for_login(&state.db, email).await?;
    let (stored_hash, ids) = match candidate {
        Some(c) => (
            Some(c.password_hash),
            c.org_id.map(|org_id| (c.user_id, org_id)),
        ),
        None => (None, None),
    };
    let password_ok = password::verify(input.password, stored_hash).await?;

    match (password_ok, ids) {
        (true, Some((user_id, org_id))) => {
            start_session(&state, jar, &headers, user_id, org_id, next).await
        }
        (ok, _) => {
            if ok {
                tracing::warn!(email, "login for a user without any org membership");
            }
            let form = LoginView {
                email: email.to_owned(),
                next: next.to_owned(),
                error: Some("Invalid email or password."),
                notice: None,
            };
            let html = if is_htmx(&headers) {
                LoginForm { form }.render()?
            } else {
                LoginPage {
                    chrome: Chrome::anonymous(),
                    form,
                }
                .render()?
            };
            Ok((StatusCode::UNPROCESSABLE_ENTITY, Html(html)).into_response())
        }
    }
}

pub async fn logout(
    State(state): State<AppState>,
    headers: HeaderMap,
    jar: CookieJar,
) -> Result<Response, AppError> {
    if let Some(cookie) = jar.get(session::COOKIE_NAME) {
        session::delete(&state.db, cookie.value()).await?;
    }
    let jar = jar.remove(session::removal_cookie());
    Ok((jar, redirect(&headers, "/login")).into_response())
}

// ───────────────────────────── helpers ─────────────────────────────

/// Always issues a fresh token (and drops any previous session), so a token
/// planted before login can't be reused afterwards.
async fn start_session(
    state: &AppState,
    jar: CookieJar,
    headers: &HeaderMap,
    user_id: Uuid,
    org_id: Uuid,
    to: &str,
) -> Result<Response, AppError> {
    if let Some(old) = jar.get(session::COOKIE_NAME) {
        session::delete(&state.db, old.value()).await?;
    }
    let token = session::create(&state.db, user_id, org_id).await?;
    let jar = jar.add(session::cookie(token, state.config.secure_cookies()));
    Ok((jar, redirect(headers, to)).into_response())
}

/// Only same-site absolute paths are allowed as a post-login destination,
/// so `?next=` can't be used as an open redirect.
fn safe_next(next: &str) -> &str {
    let ok = next.starts_with('/')
        && !next.starts_with("//")
        && !next.starts_with("/\\")
        && next.len() <= 512
        && !next.chars().any(|c| c.is_control());
    if ok { next } else { AFTER_LOGIN }
}

fn validate_email(email: &str) -> Option<&'static str> {
    (!crate::domain::email::is_valid(email)).then_some("Enter a valid email address.")
}

pub(super) fn validate_password(password: &str) -> Option<&'static str> {
    let len = password.chars().count();
    if len < password::MIN_LEN {
        Some("Password must be at least 10 characters.")
    } else if len > password::MAX_LEN {
        Some("Password must be at most 128 characters.")
    } else {
        None
    }
}

fn default_org_name(email: &str) -> String {
    let local = email.split('@').next().unwrap_or(email);
    format!("{local}'s org")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn next_must_be_a_local_path() {
        assert_eq!(safe_next("/checks/1?tab=pings"), "/checks/1?tab=pings");
        assert_eq!(safe_next("//evil.com"), AFTER_LOGIN);
        assert_eq!(safe_next("/\\evil.com"), AFTER_LOGIN);
        assert_eq!(safe_next("https://evil.com"), AFTER_LOGIN);
        assert_eq!(safe_next("/ok\r\nSet-Cookie: x"), AFTER_LOGIN);
        assert_eq!(safe_next(""), AFTER_LOGIN);
    }

    #[test]
    fn password_length() {
        assert!(validate_password("short").is_some());
        assert!(validate_password("exactly10!").is_none());
        assert!(validate_password(&"x".repeat(129)).is_some());
    }

    #[test]
    fn default_org_uses_local_part() {
        assert_eq!(default_org_name("shubh@example.com"), "shubh's org");
    }
}
