//! Managing REST API keys. A new key is shown once, in the response to the
//! form that created it; only its hash is stored.

use askama::Template;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{Html, IntoResponse, Response};
use axum_extra::extract::Form;
use chrono::Utc;
use serde::Deserialize;
use uuid::Uuid;

use super::stamp::Stamp;
use super::{AppError, AppState, Chrome, redirect};
use crate::auth::CurrentUser;
use crate::auth::api_key::{self, Scope};
use crate::db::api_keys;

const MAX_NAME: usize = 100;
/// Expiry choices, in days; `None` is "never".
const EXPIRIES: [(Option<i32>, &str); 4] = [
    (Some(30), "30 days"),
    (Some(90), "90 days"),
    (Some(365), "1 year"),
    (None, "Never"),
];

struct KeyRow {
    id: Uuid,
    name: String,
    prefix: String,
    write: bool,
    created: Stamp,
    last_used: Stamp,
    expires: Stamp,
    expired: bool,
}

/// What the form showed, for re-rendering after an error.
#[derive(Deserialize, Default)]
#[serde(default)]
pub struct KeyInput {
    name: String,
    scope: String,
    expires: String,
}

#[derive(Template)]
#[template(path = "api_keys.html")]
struct Page {
    chrome: Chrome,
    keys: Vec<KeyRow>,
    input: KeyInput,
    error: Option<&'static str>,
    /// The key just created: shown this once.
    created: Option<String>,
    /// (form value, label).
    expiries: Vec<(String, &'static str)>,
    base_url: String,
}

async fn page(
    state: &AppState,
    user: &CurrentUser,
    input: KeyInput,
    error: Option<&'static str>,
    created: Option<String>,
) -> Result<Page, AppError> {
    let now = Utc::now();
    let keys = api_keys::list(&state.db, user.org)
        .await?
        .into_iter()
        .map(|k| KeyRow {
            id: k.id,
            name: k.name,
            prefix: k.prefix,
            write: k.scope == "write",
            created: Stamp::relative(k.created_at, now),
            last_used: Stamp::relative_or(k.last_used_at, now, "never"),
            expires: Stamp::relative_or(k.expires_at, now, "never"),
            expired: k.expires_at.is_some_and(|t| t <= now),
        })
        .collect();
    Ok(Page {
        chrome: Chrome::signed_in(user),
        keys,
        input,
        error,
        created,
        expiries: EXPIRIES
            .iter()
            .map(|(days, label)| {
                (
                    days.map_or_else(|| "never".to_owned(), |d| d.to_string()),
                    *label,
                )
            })
            .collect(),
        base_url: state.config.base_url.trim_end_matches('/').to_owned(),
    })
}

impl KeyInput {
    /// A blank form: read-only, expiring in 90 days.
    fn blank() -> Self {
        Self {
            scope: "read".into(),
            expires: "90".into(),
            ..Default::default()
        }
    }
}

pub async fn list(
    State(state): State<AppState>,
    user: CurrentUser,
) -> Result<Html<String>, AppError> {
    let page = page(&state, &user, KeyInput::blank(), None, None).await?;
    Ok(Html(page.render()?))
}

pub async fn create(
    State(state): State<AppState>,
    user: CurrentUser,
    Form(input): Form<KeyInput>,
) -> Result<Response, AppError> {
    let name = input.name.trim().to_owned();
    let scope = Scope::parse(&input.scope);
    let expires = match input.expires.as_str() {
        "never" => Some(None),
        days => days
            .parse::<i32>()
            .ok()
            .filter(|d| EXPIRIES.iter().any(|(e, _)| *e == Some(*d)))
            .map(Some),
    };
    let error = if name.is_empty() {
        Some("Name the key after what will use it, e.g. \"Terraform\" or \"CI\".")
    } else if name.chars().count() > MAX_NAME {
        Some("The name must be at most 100 characters.")
    } else if scope.is_none() {
        Some("Choose what the key may do.")
    } else if expires.is_none() {
        Some("Choose when the key expires.")
    } else {
        None
    };
    if let (Some(scope), Some(expires), None) = (scope, expires, error) {
        let key = api_key::generate();
        api_keys::create(
            &state.db,
            user.org,
            user.user_id,
            &name,
            scope,
            expires,
            &key,
        )
        .await?;
        let html = page(&state, &user, KeyInput::blank(), None, Some(key.token))
            .await?
            .render()?;
        // Never cache a page holding a secret.
        return Ok(([("Cache-Control", "no-store")], Html(html)).into_response());
    }
    let html = page(&state, &user, input, error, None).await?.render()?;
    Ok((StatusCode::UNPROCESSABLE_ENTITY, Html(html)).into_response())
}

pub async fn delete(
    State(state): State<AppState>,
    user: CurrentUser,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    if !api_keys::delete(&state.db, user.org, id).await? {
        return Err(AppError::NotFound);
    }
    Ok(redirect(&headers, "/api-keys"))
}
