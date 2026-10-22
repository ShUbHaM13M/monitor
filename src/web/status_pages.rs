//! Managing an org's public status pages.

use std::collections::HashMap;

use askama::Template;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{Html, IntoResponse, Response};
use axum_extra::extract::Form;
use uuid::Uuid;

use super::{AppError, AppState, Chrome, plan_limit_message, redirect};
use crate::auth::CurrentUser;
use crate::db::status_pages::{self, ItemSpec, PageSpec, SaveError, Target};
use crate::db::{checks, monitors, orgs};

const MAX_TITLE: usize = 100;
const MAX_DESCRIPTION: usize = 1000;
const MAX_NAME: usize = 100;

// ───────────────────────────── list ─────────────────────────────

#[derive(Template)]
#[template(path = "status/list.html")]
struct ListPage {
    chrome: Chrome,
    pages: Vec<status_pages::PageSummary>,
    base_url: String,
}

pub async fn list(
    State(state): State<AppState>,
    user: CurrentUser,
) -> Result<Html<String>, AppError> {
    let page = ListPage {
        chrome: Chrome::signed_in(&user),
        pages: status_pages::list(&state.db, user.org).await?,
        base_url: state.config.base_url.trim_end_matches('/').to_owned(),
    };
    Ok(Html(page.render()?))
}

// ───────────────────────────── form ─────────────────────────────

/// One check or monitor the page could show.
struct Row {
    /// Form key: "c:<id>" or "m:<id>".
    key: String,
    kind: &'static str,
    internal_name: String,
    shown: bool,
    display_name: String,
    position: String,
}

struct FormView {
    action: String,
    submit: &'static str,
    title: String,
    slug: String,
    description: String,
    published: bool,
    rows: Vec<Row>,
    error: Option<String>,
    base_url: String,
}

#[derive(Template)]
#[template(path = "status/form.html")]
struct FormPage {
    chrome: Chrome,
    heading: &'static str,
    form: FormView,
}

/// Every check and monitor in the org, with `items` (the page's current or
/// submitted choices) applied.
async fn rows(
    state: &AppState,
    user: &CurrentUser,
    items: &[ItemSpec],
) -> Result<Vec<Row>, AppError> {
    let chosen = |target: Target| items.iter().find(|i| i.target == target);
    let mut rows = Vec::new();
    for c in checks::list(&state.db, user.org).await? {
        let item = chosen(Target::Check(c.id));
        rows.push(Row {
            key: format!("c:{}", c.id),
            kind: if c.is_webhook() { "webhook" } else { "check" },
            shown: item.is_some(),
            display_name: item.map_or_else(|| c.name.clone(), |i| i.display_name.clone()),
            position: item.map(|i| i.position.to_string()).unwrap_or_default(),
            internal_name: c.name,
        });
    }
    for m in monitors::list(&state.db, user.org).await? {
        let item = chosen(Target::Monitor(m.id));
        rows.push(Row {
            key: format!("m:{}", m.id),
            kind: "uptime",
            shown: item.is_some(),
            display_name: item.map_or_else(|| m.name.clone(), |i| i.display_name.clone()),
            position: item.map(|i| i.position.to_string()).unwrap_or_default(),
            internal_name: m.name,
        });
    }
    // Shown items first, in page order; the rest after. Then number them all,
    // so leaving the order alone keeps what you see.
    rows.sort_by_key(|r| (!r.shown, r.position.parse::<i32>().unwrap_or(i32::MAX)));
    for (i, row) in rows.iter_mut().enumerate() {
        row.position = (i + 1).to_string();
    }
    Ok(rows)
}

pub async fn new_page(
    State(state): State<AppState>,
    user: CurrentUser,
) -> Result<Html<String>, AppError> {
    let form = FormView {
        action: "/status-pages".into(),
        submit: "Create page",
        title: user.org_name.clone(),
        slug: String::new(),
        description: String::new(),
        published: false,
        rows: rows(&state, &user, &[]).await?,
        error: None,
        base_url: state.config.base_url.trim_end_matches('/').to_owned(),
    };
    Ok(Html(
        FormPage {
            chrome: Chrome::signed_in(&user),
            heading: "New status page",
            form,
        }
        .render()?,
    ))
}

pub async fn edit_page(
    State(state): State<AppState>,
    user: CurrentUser,
    Path(id): Path<Uuid>,
) -> Result<Html<String>, AppError> {
    let page = status_pages::get(&state.db, user.org, id)
        .await?
        .ok_or(AppError::NotFound)?;
    let items = status_pages::item_specs(&state.db, user.org, id).await?;
    let form = FormView {
        action: format!("/status-pages/{id}"),
        submit: "Save changes",
        title: page.title,
        slug: page.slug,
        description: page.description.unwrap_or_default(),
        published: page.published,
        rows: rows(&state, &user, &items).await?,
        error: None,
        base_url: state.config.base_url.trim_end_matches('/').to_owned(),
    };
    Ok(Html(
        FormPage {
            chrome: Chrome::signed_in(&user),
            heading: "Edit status page",
            form,
        }
        .render()?,
    ))
}

/// "Acme Cloud!" → "acme-cloud".
pub fn slugify(text: &str) -> String {
    let mut slug = String::new();
    for c in text.to_lowercase().chars() {
        if c.is_ascii_alphanumeric() {
            slug.push(c);
        } else if !slug.ends_with('-') && !slug.is_empty() {
            slug.push('-');
        }
    }
    slug.truncate(40);
    slug.trim_end_matches('-').to_owned()
}

fn valid_slug(slug: &str) -> bool {
    (3..=40).contains(&slug.len())
        && slug
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        && !slug.starts_with('-')
        && !slug.ends_with('-')
}

/// Validates the submitted form into a spec, or a message for the user.
fn parse(values: &HashMap<String, String>) -> Result<PageSpec, String> {
    let get = |k: &str| values.get(k).map_or("", |v| v.trim());
    let title = get("title");
    if title.is_empty() || title.chars().count() > MAX_TITLE {
        return Err("Give the page a title of at most 100 characters.".into());
    }
    let slug = match get("slug") {
        "" => slugify(title),
        s => s.to_lowercase(),
    };
    if !valid_slug(&slug) {
        return Err(
            "The address must be 3–40 lowercase letters, digits or dashes, not starting or ending with a dash."
                .into(),
        );
    }
    let description = get("description");
    if description.chars().count() > MAX_DESCRIPTION {
        return Err("The description must be at most 1000 characters.".into());
    }
    let mut items = Vec::new();
    for (key, value) in values {
        let Some(target_key) = key.strip_prefix("show.") else {
            continue;
        };
        if value != "on" {
            continue;
        }
        let target = match target_key.split_once(':') {
            Some(("c", id)) => id.parse().map(Target::Check),
            Some(("m", id)) => id.parse().map(Target::Monitor),
            _ => continue,
        }
        .map_err(|_| "Unknown component.".to_owned())?;
        let display_name = get(&format!("name.{target_key}"));
        if display_name.is_empty() || display_name.chars().count() > MAX_NAME {
            return Err(
                "Each shown component needs a public name of at most 100 characters.".into(),
            );
        }
        let position = match get(&format!("pos.{target_key}")) {
            "" => 0,
            p => p
                .parse()
                .map_err(|_| "Order must be a whole number.".to_owned())?,
        };
        items.push(ItemSpec {
            target,
            display_name: display_name.to_owned(),
            position,
        });
    }
    Ok(PageSpec {
        slug,
        title: title.to_owned(),
        description: (!description.is_empty()).then(|| description.to_owned()),
        published: get("published") == "on",
        items,
    })
}

async fn save_error(
    state: &AppState,
    user: &CurrentUser,
    values: &HashMap<String, String>,
    action: String,
    heading: &'static str,
    error: String,
) -> Result<Response, AppError> {
    let get = |k: &str| values.get(k).cloned().unwrap_or_default();
    // Re-render with what was submitted, so nothing typed is lost.
    let submitted: Vec<ItemSpec> = values
        .keys()
        .filter_map(|k| k.strip_prefix("show."))
        .filter_map(|key| {
            let target = match key.split_once(':')? {
                ("c", id) => Target::Check(id.parse().ok()?),
                ("m", id) => Target::Monitor(id.parse().ok()?),
                _ => return None,
            };
            Some(ItemSpec {
                target,
                display_name: get(&format!("name.{key}")),
                position: get(&format!("pos.{key}")).parse().unwrap_or(0),
            })
        })
        .collect();
    let form = FormView {
        action,
        submit: if heading.starts_with("New") {
            "Create page"
        } else {
            "Save changes"
        },
        title: get("title"),
        slug: get("slug"),
        description: get("description"),
        published: get("published") == "on",
        rows: rows(state, user, &submitted).await?,
        error: Some(error),
        base_url: state.config.base_url.trim_end_matches('/').to_owned(),
    };
    let html = FormPage {
        chrome: Chrome::signed_in(user),
        heading,
        form,
    }
    .render()?;
    Ok((StatusCode::UNPROCESSABLE_ENTITY, Html(html)).into_response())
}

fn save_message(err: SaveError) -> Result<String, AppError> {
    match err {
        SaveError::SlugTaken => Ok("That address is taken. Choose another.".into()),
        SaveError::LimitReached(n) => Ok(plan_limit_message(n, "status pages")),
        SaveError::Db(err) => Err(err.into()),
    }
}

pub async fn create(
    State(state): State<AppState>,
    user: CurrentUser,
    headers: HeaderMap,
    Form(values): Form<HashMap<String, String>>,
) -> Result<Response, AppError> {
    let heading = "New status page";
    let spec = match parse(&values) {
        Ok(spec) => spec,
        Err(error) => {
            return save_error(
                &state,
                &user,
                &values,
                "/status-pages".into(),
                heading,
                error,
            )
            .await;
        }
    };
    let limits = orgs::limits(&state.db, user.org, &state.config.plan).await?;
    match status_pages::create(&state.db, user.org, &spec, limits.max_status_pages).await {
        Ok(_) => Ok(redirect(&headers, "/status-pages")),
        // A forged component id from another org fails the foreign keys.
        Err(SaveError::Db(sqlx::Error::Database(e))) if e.is_foreign_key_violation() => {
            Err(AppError::NotFound)
        }
        Err(err) => {
            let error = save_message(err)?;
            save_error(
                &state,
                &user,
                &values,
                "/status-pages".into(),
                heading,
                error,
            )
            .await
        }
    }
}

pub async fn update(
    State(state): State<AppState>,
    user: CurrentUser,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
    Form(values): Form<HashMap<String, String>>,
) -> Result<Response, AppError> {
    let heading = "Edit status page";
    let action = format!("/status-pages/{id}");
    status_pages::get(&state.db, user.org, id)
        .await?
        .ok_or(AppError::NotFound)?;
    let spec = match parse(&values) {
        Ok(spec) => spec,
        Err(error) => return save_error(&state, &user, &values, action, heading, error).await,
    };
    match status_pages::update(&state.db, user.org, id, &spec).await {
        Ok(true) => Ok(redirect(&headers, "/status-pages")),
        Ok(false) => Err(AppError::NotFound),
        // A forged component id from another org fails the foreign keys.
        Err(SaveError::Db(sqlx::Error::Database(e))) if e.is_foreign_key_violation() => {
            Err(AppError::NotFound)
        }
        Err(err) => {
            let error = save_message(err)?;
            save_error(&state, &user, &values, action, heading, error).await
        }
    }
}

pub async fn delete(
    State(state): State<AppState>,
    user: CurrentUser,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    if !status_pages::delete(&state.db, user.org, id).await? {
        return Err(AppError::NotFound);
    }
    Ok(redirect(&headers, "/status-pages"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slugs() {
        assert_eq!(slugify("Acme Cloud!"), "acme-cloud");
        assert_eq!(slugify("  --Ünïcode  API 2 "), "n-code-api-2");
        assert!(valid_slug("acme-cloud"));
        assert!(!valid_slug("ab"));
        assert!(!valid_slug("-acme"));
        assert!(!valid_slug("Acme"));
        assert!(!valid_slug(&"a".repeat(41)));
    }

    #[test]
    fn parses_the_form() {
        let id = Uuid::now_v7();
        let mut v = HashMap::new();
        v.insert("title".to_owned(), "Acme Status".to_owned());
        v.insert("slug".to_owned(), "".to_owned());
        v.insert(format!("show.c:{id}"), "on".to_owned());
        v.insert(format!("name.c:{id}"), "Nightly sync".to_owned());
        v.insert(format!("pos.c:{id}"), "2".to_owned());
        // Not ticked: ignored even with a name.
        v.insert(format!("name.m:{}", Uuid::now_v7()), "Hidden".to_owned());
        let spec = parse(&v).unwrap();
        assert_eq!(spec.slug, "acme-status");
        assert!(!spec.published);
        assert_eq!(spec.items.len(), 1);
        assert_eq!(spec.items[0].target, Target::Check(id));
        assert_eq!(spec.items[0].position, 2);

        v.insert(format!("name.c:{id}"), " ".to_owned());
        assert!(parse(&v).err().unwrap().contains("public name"));
    }
}
