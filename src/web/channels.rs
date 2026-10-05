use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use askama::Template;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{Html, IntoResponse, Response};
use axum_extra::extract::{Form, Query};
use chrono::Utc;
use serde::Deserialize;
use serde_json::Value;
use uuid::Uuid;

use super::{AppError, AppState, Chrome, is_htmx, redirect};
use crate::auth::{CurrentUser, MaybeUser};
use crate::crypto::{random_token, sha256};
use crate::db::channels::{self, Channel, NewChannel};
use crate::db::notifications;
use crate::domain::time::relative;
use crate::notify::kind::{FieldValues, Input};
use crate::notify::{Alert, ChannelCtx, ChannelKind, Verification};

const MAX_NAME: usize = 100;
const RECENT_DELIVERIES: i64 = 50;
const TEST_TIMEOUT: Duration = Duration::from_secs(15);

// ───────────────────────────── list ─────────────────────────────

struct ChannelRow {
    id: Uuid,
    name: String,
    kind: String,
    summary: String,
    verified: bool,
    check_count: i64,
    last_delivery: Option<String>,
}

impl ChannelRow {
    fn new(state: &AppState, channel: &Channel) -> Self {
        let now = Utc::now();
        Self {
            id: channel.id,
            name: channel.name.clone(),
            kind: state.channels.label(&channel.kind),
            summary: summary(state, channel),
            verified: channel.verified_at.is_some(),
            check_count: channel.check_count,
            last_delivery: channel
                .last_status
                .as_ref()
                .zip(channel.last_at)
                .map(|(status, at)| format!("{} {}", status, relative(at, now))),
        }
    }
}

/// The kind's safe summary of the stored config.
fn summary(state: &AppState, channel: &Channel) -> String {
    match (
        state.channels.get(&channel.kind),
        open_config(state, &channel.config_enc),
    ) {
        (Some(kind), Ok(config)) => kind.summary(&config),
        _ => "—".into(),
    }
}

fn open_config(state: &AppState, sealed: &[u8]) -> anyhow::Result<Value> {
    let bytes = state.secrets.open(sealed)?;
    Ok(serde_json::from_slice(&bytes)?)
}

#[derive(Template)]
#[template(path = "channels/list.html")]
struct ListPage {
    chrome: Chrome,
    rows: Vec<ChannelRow>,
}

pub async fn list(
    State(state): State<AppState>,
    user: CurrentUser,
) -> Result<Html<String>, AppError> {
    let rows = channels::list(&state.db, user.org)
        .await?
        .iter()
        .map(|c| ChannelRow::new(&state, c))
        .collect();
    let page = ListPage {
        chrome: Chrome::signed_in(&user),
        rows,
    };
    Ok(Html(page.render()?))
}

// ───────────────────────────── create ─────────────────────────────

struct KindOption {
    id: &'static str,
    label: &'static str,
    description: &'static str,
}

#[derive(Template)]
#[template(path = "channels/new.html")]
struct PickerPage {
    chrome: Chrome,
    kinds: Vec<KindOption>,
}

pub async fn new_picker(
    State(state): State<AppState>,
    user: CurrentUser,
) -> Result<Html<String>, AppError> {
    let kinds = state
        .channels
        .available()
        .iter()
        .map(|k| KindOption {
            id: k.id(),
            label: k.label(),
            description: k.description(),
        })
        .collect();
    let page = PickerPage {
        chrome: Chrome::signed_in(&user),
        kinds,
    };
    Ok(Html(page.render()?))
}

struct FieldView {
    name: &'static str,
    label: &'static str,
    html_type: &'static str,
    required: bool,
    placeholder: &'static str,
    help: &'static str,
    value: String,
}

struct ChannelForm {
    kind_id: &'static str,
    kind_label: &'static str,
    name: String,
    fields: Vec<FieldView>,
    attach_all: bool,
    error: Option<String>,
}

impl ChannelForm {
    /// Secrets are never echoed back into the page.
    fn new(kind: &dyn ChannelKind, values: &FieldValues) -> Self {
        Self {
            kind_id: kind.id(),
            kind_label: kind.label(),
            name: values.get("channel_name").cloned().unwrap_or_default(),
            fields: kind
                .fields()
                .iter()
                .map(|f| FieldView {
                    name: f.name,
                    label: f.label,
                    html_type: f.input.html_type(),
                    required: f.required,
                    placeholder: f.placeholder,
                    help: f.help,
                    value: if f.input == Input::Secret {
                        String::new()
                    } else {
                        values.get(f.name).cloned().unwrap_or_default()
                    },
                })
                .collect(),
            attach_all: values.is_empty() || values.contains_key("attach_all"),
            error: None,
        }
    }
}

#[derive(Template)]
#[template(path = "channels/form.html")]
struct FormPage {
    chrome: Chrome,
    form: ChannelForm,
}

#[derive(Template)]
#[template(path = "channels/form_fields.html")]
struct FormPartial {
    form: ChannelForm,
}

fn kind(state: &AppState, id: &str) -> Result<Arc<dyn ChannelKind>, AppError> {
    state.channels.get(id).cloned().ok_or(AppError::NotFound)
}

pub async fn new_form(
    State(state): State<AppState>,
    user: CurrentUser,
    Path(kind_id): Path<String>,
) -> Result<Html<String>, AppError> {
    let kind = kind(&state, &kind_id)?;
    let page = FormPage {
        chrome: Chrome::signed_in(&user),
        form: ChannelForm::new(kind.as_ref(), &FieldValues::new()),
    };
    Ok(Html(page.render()?))
}

pub async fn create(
    State(state): State<AppState>,
    user: CurrentUser,
    Path(kind_id): Path<String>,
    headers: HeaderMap,
    Form(values): Form<HashMap<String, String>>,
) -> Result<Response, AppError> {
    let kind = kind(&state, &kind_id)?;
    let ctx = ChannelCtx {
        verified_account_email: user.email_verified.then(|| user.email.clone()),
        allow_private_targets: state.config.allow_private_targets,
    };
    let config = match kind.validate(&values, &ctx) {
        Ok(config) => config,
        Err(error) => return form_error(&headers, &user, kind.as_ref(), &values, error),
    };
    let name = match values.get("channel_name").map(|n| n.trim()) {
        Some(name) if !name.is_empty() => name.to_owned(),
        _ => kind.summary(&config),
    };
    if name.chars().count() > MAX_NAME {
        let error = "Name must be at most 100 characters.".to_owned();
        return form_error(&headers, &user, kind.as_ref(), &values, error);
    }

    let token = match kind.verification(&config, &ctx) {
        Verification::None => None,
        Verification::Link => Some(random_token()),
    };
    let sealed = state
        .secrets
        .seal(&serde_json::to_vec(&config).map_err(anyhow::Error::from)?);
    let id = channels::create(
        &state.db,
        user.org,
        NewChannel {
            kind: kind.id(),
            name: &name,
            config_enc: sealed,
            verified: token.is_none(),
            verify_token_hash: token.as_deref().map(sha256),
            attach_to_all_checks: values.contains_key("attach_all"),
        },
    )
    .await?;
    if let Some(token) = token {
        send_verification(&state, kind.as_ref(), &config, &token).await;
    }
    Ok(redirect(&headers, &format!("/channels/{id}")))
}

/// Failures are logged, not shown: the channel page offers "Resend".
async fn send_verification(state: &AppState, kind: &dyn ChannelKind, config: &Value, token: &str) {
    let link = format!(
        "{}/verify-channel?token={token}",
        state.config.base_url.trim_end_matches('/')
    );
    if let Err(err) = kind.send_verification(config, &link).await {
        tracing::warn!(
            kind = kind.id(),
            error = err.message(),
            "could not send channel confirmation"
        );
    }
}

fn form_error(
    headers: &HeaderMap,
    user: &CurrentUser,
    kind: &dyn ChannelKind,
    values: &FieldValues,
    error: String,
) -> Result<Response, AppError> {
    let mut form = ChannelForm::new(kind, values);
    form.error = Some(error);
    let html = if is_htmx(headers) {
        FormPartial { form }.render()?
    } else {
        FormPage {
            chrome: Chrome::signed_in(user),
            form,
        }
        .render()?
    };
    Ok((StatusCode::UNPROCESSABLE_ENTITY, Html(html)).into_response())
}

// ───────────────────────────── detail & actions ─────────────────────────────

struct DeliveryRow {
    event: String,
    check_name: String,
    status: String,
    css: &'static str,
    attempts: i32,
    error: Option<String>,
    when: String,
}

#[derive(Template)]
#[template(path = "channels/show.html")]
struct ShowPage {
    chrome: Chrome,
    channel: ChannelRow,
    deliveries: Vec<DeliveryRow>,
}

pub async fn show(
    State(state): State<AppState>,
    user: CurrentUser,
    Path(id): Path<Uuid>,
) -> Result<Html<String>, AppError> {
    let channel = channels::get(&state.db, user.org, id)
        .await?
        .ok_or(AppError::NotFound)?;
    let now = Utc::now();
    let deliveries = notifications::recent_for_channel(&state.db, user.org, id, RECENT_DELIVERIES)
        .await?
        .into_iter()
        .map(|d| DeliveryRow {
            css: match d.status.as_str() {
                "sent" => "pill-up",
                "dead" => "pill-down",
                _ => "pill-run",
            },
            event: d.event,
            check_name: d.check_name.unwrap_or_default(),
            status: d.status,
            attempts: d.attempts,
            error: d.last_error,
            when: relative(d.sent_at.unwrap_or(d.created_at), now),
        })
        .collect();
    let page = ShowPage {
        chrome: Chrome::signed_in(&user),
        channel: ChannelRow::new(&state, &channel),
        deliveries,
    };
    Ok(Html(page.render()?))
}

#[derive(Template)]
#[template(path = "channels/test_result.html")]
struct TestResult {
    ok: bool,
    message: String,
}

/// Sends a sample alert right away (not through the queue) and reports the result.
pub async fn test(
    State(state): State<AppState>,
    user: CurrentUser,
    Path(id): Path<Uuid>,
) -> Result<Html<String>, AppError> {
    let channel = channels::get(&state.db, user.org, id)
        .await?
        .ok_or(AppError::NotFound)?;
    let result = if channel.verified_at.is_none() {
        Err("Confirm this channel before sending a test.".to_owned())
    } else {
        let kind = kind(&state, &channel.kind)?;
        let config = open_config(&state, &channel.config_enc)?;
        let alert = Alert::sample(&state.config.base_url);
        match tokio::time::timeout(TEST_TIMEOUT, kind.send(&config, &alert)).await {
            Ok(Ok(())) => Ok(()),
            Ok(Err(err)) => Err(err.message().to_owned()),
            Err(_) => Err("Timed out.".to_owned()),
        }
    };
    let partial = match result {
        Ok(()) => TestResult {
            ok: true,
            message: "Test alert sent.".into(),
        },
        Err(message) => TestResult { ok: false, message },
    };
    Ok(Html(partial.render()?))
}

pub async fn resend(
    State(state): State<AppState>,
    user: CurrentUser,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let channel = channels::get(&state.db, user.org, id)
        .await?
        .ok_or(AppError::NotFound)?;
    let token = random_token();
    // False during the cooldown or once verified: nothing to send.
    if channels::renew_verify_token(&state.db, user.org, id, &sha256(&token)).await? {
        let kind = kind(&state, &channel.kind)?;
        let config = open_config(&state, &channel.config_enc)?;
        send_verification(&state, kind.as_ref(), &config, &token).await;
    }
    Ok(redirect(&headers, &format!("/channels/{id}")))
}

pub async fn delete(
    State(state): State<AppState>,
    user: CurrentUser,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    if !channels::delete(&state.db, user.org, id).await? {
        return Err(AppError::NotFound);
    }
    Ok(redirect(&headers, "/channels"))
}

// ───────────────────────────── recipient confirmation ─────────────────────────────

enum VerifyState {
    /// Ask before confirming: mail scanners follow GET links on their own.
    Confirm {
        token: String,
        org_name: String,
        summary: String,
    },
    Done,
    Invalid,
}

#[derive(Template)]
#[template(path = "channels/verify.html")]
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
    let pending = channels::find_by_verify_token(&state.db, &sha256(&param.token)).await?;
    let verify_state = match pending {
        Some(p) => VerifyState::Confirm {
            summary: match (
                state.channels.get(&p.kind),
                open_config(&state, &p.config_enc),
            ) {
                (Some(kind), Ok(config)) => kind.summary(&config),
                _ => String::new(),
            },
            token: param.token,
            org_name: p.org_name,
        },
        None => VerifyState::Invalid,
    };
    let page = VerifyPage {
        chrome: chrome_for(&user),
        state: verify_state,
    };
    Ok(Html(page.render()?))
}

pub async fn verify_confirm(
    State(state): State<AppState>,
    MaybeUser(user): MaybeUser,
    Form(param): Form<TokenParam>,
) -> Result<Html<String>, AppError> {
    let confirmed = channels::confirm_verify_token(&state.db, &sha256(&param.token)).await?;
    let page = VerifyPage {
        chrome: chrome_for(&user),
        state: if confirmed {
            VerifyState::Done
        } else {
            VerifyState::Invalid
        },
    };
    Ok(Html(page.render()?))
}
