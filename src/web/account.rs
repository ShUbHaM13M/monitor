//! Account emails: confirming the email address and resetting a forgotten password.
//! Both use one-time links (`db::user_tokens`); only their hashes are stored.

use askama::Template;
use axum::Form;
use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse, Redirect, Response};
use serde::Deserialize;
use uuid::Uuid;

use super::auth::validate_password;
use super::{AppError, AppState, Chrome};
use crate::auth::{CurrentUser, MaybeUser, password, session};
use crate::db::user_tokens::{self, Purpose};
use crate::db::users;
use crate::mail::Body;

fn link(state: &AppState, path: &str, token: &str) -> String {
    format!(
        "{}{path}?token={token}",
        state.config.base_url.trim_end_matches('/')
    )
}

/// Mails a confirmation link unless email is off or one went out in the last
/// minute. Returns whether a link was sent. Delivery failures are logged, not
/// shown: the banner offers "resend".
pub(super) async fn send_verification_email(state: &AppState, user_id: Uuid, email: &str) -> bool {
    let Some(mailer) = &state.mailer else {
        return false;
    };
    let token = match user_tokens::issue(&state.db, user_id, Purpose::VerifyEmail).await {
        Ok(Some(token)) => token,
        Ok(None) => return false,
        Err(err) => {
            tracing::error!(error = ?err, "could not issue verification token");
            return false;
        }
    };
    let text = format!(
        "Welcome to Monitor!\n\n\
         Confirm your email address to finish setting up your account:\n{}\n\n\
         The link expires in 7 days.",
        link(state, "/verify-email", &token)
    );
    match mailer
        .send(email, "Confirm your email address", Body::Text(text))
        .await
    {
        Ok(()) => true,
        Err(err) => {
            tracing::warn!(error = err.message(), "could not send verification email");
            false
        }
    }
}

// ───────────────────────────── email verification ─────────────────────────────

#[derive(Template)]
#[template(path = "account/banner_result.html")]
struct BannerResult {
    sent: bool,
}

/// The banner's "Resend" button.
pub async fn resend_verification(
    State(state): State<AppState>,
    user: CurrentUser,
) -> Result<Response, AppError> {
    if user.email_verified {
        return Ok(Redirect::to("/dashboard").into_response());
    }
    let sent = send_verification_email(&state, user.user_id, &user.email).await;
    Ok(Html(BannerResult { sent }.render()?).into_response())
}

enum VerifyState {
    /// Ask first: mail scanners follow links on their own, and a scanner
    /// confirming an address someone else signed up with would be bad.
    Confirm {
        token: String,
        email: String,
    },
    Done,
    Invalid,
}

#[derive(Template)]
#[template(path = "account/verify_email.html")]
struct VerifyPage {
    chrome: Chrome,
    state: VerifyState,
}

#[derive(Deserialize)]
pub struct TokenParam {
    #[serde(default)]
    token: String,
}

fn chrome_for(user: &Option<CurrentUser>) -> Chrome {
    user.as_ref()
        .map_or_else(Chrome::anonymous, Chrome::signed_in)
}

pub async fn verify_page(
    State(state): State<AppState>,
    MaybeUser(user): MaybeUser,
    Query(param): Query<TokenParam>,
) -> Result<Html<String>, AppError> {
    let email = user_tokens::peek(&state.db, &param.token, Purpose::VerifyEmail).await?;
    let page = VerifyPage {
        chrome: chrome_for(&user),
        state: match email {
            Some(email) => VerifyState::Confirm {
                token: param.token,
                email,
            },
            None => VerifyState::Invalid,
        },
    };
    Ok(Html(page.render()?))
}

pub async fn verify_confirm(
    State(state): State<AppState>,
    MaybeUser(user): MaybeUser,
    Form(param): Form<TokenParam>,
) -> Result<Html<String>, AppError> {
    let mut tx = state.db.begin().await?;
    let user_id = user_tokens::consume(&mut tx, &param.token, Purpose::VerifyEmail).await?;
    if let Some(user_id) = user_id {
        users::mark_email_verified(&mut tx, user_id).await?;
    }
    tx.commit().await?;

    let mut chrome = chrome_for(&user);
    if user_id.is_some() && user.as_ref().map(|u| u.user_id) == user_id {
        chrome.verify_banner = false; // the session was loaded before we confirmed
    }
    let page = VerifyPage {
        chrome,
        state: if user_id.is_some() {
            VerifyState::Done
        } else {
            VerifyState::Invalid
        },
    };
    Ok(Html(page.render()?))
}

// ───────────────────────────── forgot / reset password ─────────────────────────────

#[derive(Template)]
#[template(path = "account/forgot.html")]
struct ForgotPage {
    chrome: Chrome,
    available: bool,
    sent_to: Option<String>,
    email: String,
}

pub async fn forgot_page(State(state): State<AppState>) -> Result<Html<String>, AppError> {
    let page = ForgotPage {
        chrome: Chrome::anonymous(),
        available: state.mailer.is_some(),
        sent_to: None,
        email: String::new(),
    };
    Ok(Html(page.render()?))
}

#[derive(Deserialize)]
pub struct ForgotInput {
    #[serde(default)]
    email: String,
}

/// Always answers the same way, so the form doesn't reveal who has an account.
pub async fn forgot(
    State(state): State<AppState>,
    Form(input): Form<ForgotInput>,
) -> Result<Html<String>, AppError> {
    let email = input.email.trim();
    if let (Some(mailer), Some(account)) =
        (&state.mailer, users::find_by_email(&state.db, email).await?)
        && let Some(token) =
            user_tokens::issue(&state.db, account.id, Purpose::ResetPassword).await?
    {
        let text = format!(
            "Someone (hopefully you) asked to reset the Monitor password for {}.\n\n\
             Choose a new password here:\n{}\n\n\
             The link works once and expires in 1 hour. If you didn't ask for this, \
             ignore this email: your password won't change.",
            account.email,
            link(&state, "/reset-password", &token)
        );
        // Sent in the background: answering only after an SMTP round trip would
        // make known addresses measurably slower, revealing who has an account.
        let mailer = mailer.clone();
        tokio::spawn(async move {
            if let Err(err) = mailer
                .send(
                    &account.email,
                    "Reset your Monitor password",
                    Body::Text(text),
                )
                .await
            {
                tracing::warn!(error = err.message(), "could not send password reset email");
            }
        });
    }
    let page = ForgotPage {
        chrome: Chrome::anonymous(),
        available: state.mailer.is_some(),
        sent_to: Some(email.to_owned()),
        email: String::new(),
    };
    Ok(Html(page.render()?))
}

#[derive(Template)]
#[template(path = "account/reset.html")]
struct ResetPage {
    chrome: Chrome,
    /// `None`: the link is invalid or expired.
    form: Option<ResetForm>,
}

struct ResetForm {
    token: String,
    email: String,
    error: Option<&'static str>,
}

pub async fn reset_page(
    State(state): State<AppState>,
    Query(param): Query<TokenParam>,
) -> Result<Html<String>, AppError> {
    let email = user_tokens::peek(&state.db, &param.token, Purpose::ResetPassword).await?;
    let page = ResetPage {
        chrome: Chrome::anonymous(),
        form: email.map(|email| ResetForm {
            token: param.token,
            email,
            error: None,
        }),
    };
    Ok(Html(page.render()?))
}

#[derive(Deserialize)]
pub struct ResetInput {
    #[serde(default)]
    token: String,
    #[serde(default)]
    password: String,
    #[serde(default)]
    confirm: String,
}

pub async fn reset(
    State(state): State<AppState>,
    Form(input): Form<ResetInput>,
) -> Result<Response, AppError> {
    let error = validate_password(&input.password)
        .or_else(|| (input.password != input.confirm).then_some("The two passwords don't match."));
    if let Some(error) = error {
        let email = user_tokens::peek(&state.db, &input.token, Purpose::ResetPassword).await?;
        let status = if email.is_some() {
            StatusCode::UNPROCESSABLE_ENTITY
        } else {
            StatusCode::OK
        };
        let page = ResetPage {
            chrome: Chrome::anonymous(),
            form: email.map(|email| ResetForm {
                token: input.token,
                email,
                error: Some(error),
            }),
        };
        return Ok((status, Html(page.render()?)).into_response());
    }

    let hash = password::hash(input.password).await?;
    let mut tx = state.db.begin().await?;
    let Some(user_id) = user_tokens::consume(&mut tx, &input.token, Purpose::ResetPassword).await?
    else {
        let page = ResetPage {
            chrome: Chrome::anonymous(),
            form: None,
        };
        return Ok(Html(page.render()?).into_response());
    };
    users::set_password(&mut tx, user_id, &hash).await?;
    // Following the emailed link proves they control the address.
    users::mark_email_verified(&mut tx, user_id).await?;
    // Whoever knew the old password is logged out everywhere.
    session::delete_all_for_user(&mut tx, user_id).await?;
    tx.commit().await?;

    tracing::info!(%user_id, "password reset");
    Ok(Redirect::to("/login?reset=1").into_response())
}
