use askama::Template;
use axum::extract::State;
use axum::response::Html;
use axum_extra::extract::Query;
use chrono::{DateTime, SecondsFormat, Utc};
use serde::Deserialize;
use uuid::Uuid;

use super::checks::reason_label;
use super::stamp::Stamp;
use super::{AppError, AppState, Chrome};
use crate::auth::CurrentUser;
use crate::db::incidents::{self, IncidentState, OrgIncident};
use crate::domain::time::duration;

const PAGE_SIZE: i64 = 50;

/// An incident in an org-wide list (overview, incidents page).
pub(super) struct IncidentItem {
    pub(super) open: bool,
    pub(super) href: String,
    pub(super) name: String,
    /// "heartbeat", "webhook" or "uptime".
    pub(super) tag: &'static str,
    /// The check or monitor is paused, so it won't recover on its own.
    pub(super) paused: bool,
    pub(super) reason: &'static str,
    pub(super) detail: String,
    pub(super) started: Stamp,
    /// "12m 05s" so far, or how long it lasted.
    pub(super) duration: String,
}

impl IncidentItem {
    pub(super) fn new(i: OrgIncident, now: DateTime<Utc>) -> Self {
        let (href, tag) = match (i.check_id, i.monitor_id) {
            (Some(id), _) => (
                format!("/checks/{id}"),
                if i.target_kind == "webhook" {
                    "webhook"
                } else {
                    "heartbeat"
                },
            ),
            (_, Some(id)) => (format!("/monitors/{id}"), "uptime"),
            // Ruled out by the table's CHECK constraint.
            (None, None) => (String::new(), ""),
        };
        let end = i.resolved_at.unwrap_or(now);
        Self {
            open: i.resolved_at.is_none(),
            href,
            name: i.target_name,
            tag,
            paused: i.target_status == "paused",
            reason: reason_label(&i.reason),
            detail: i.detail.unwrap_or_default(),
            started: Stamp::relative(i.started_at, now),
            duration: duration((end - i.started_at).num_milliseconds().max(0)),
        }
    }
}

#[derive(Deserialize, Default)]
#[serde(default)]
pub struct IncidentQuery {
    /// "open", "resolved" or anything else for all.
    state: String,
    before: Option<DateTime<Utc>>,
    before_id: Option<Uuid>,
}

struct StateTab {
    value: &'static str,
    label: &'static str,
    selected: bool,
}

#[derive(Template)]
#[template(path = "incidents/list.html")]
struct ListPage {
    chrome: Chrome,
    tabs: Vec<StateTab>,
    items: Vec<IncidentItem>,
    /// Query string for the next page, when there is one.
    older: Option<String>,
    /// Not on the first page.
    paged: bool,
    state: &'static str,
}

pub async fn list(
    State(state): State<AppState>,
    user: CurrentUser,
    Query(query): Query<IncidentQuery>,
) -> Result<Html<String>, AppError> {
    let (filter, value) = match query.state.as_str() {
        "open" => (IncidentState::Open, "open"),
        "resolved" => (IncidentState::Resolved, "resolved"),
        _ => (IncidentState::All, ""),
    };
    let before = query.before.zip(query.before_id);
    // One extra row tells us whether there's another page.
    let mut rows =
        incidents::list_for_org(&state.db, user.org, filter, before, PAGE_SIZE + 1).await?;
    let more = rows.len() as i64 > PAGE_SIZE;
    rows.truncate(PAGE_SIZE as usize);
    let older = more.then(|| rows.last()).flatten().map(|last| {
        let mut q = url::form_urlencoded::Serializer::new(String::new());
        if !value.is_empty() {
            q.append_pair("state", value);
        }
        q.append_pair(
            "before",
            &last.started_at.to_rfc3339_opts(SecondsFormat::Micros, true),
        );
        q.append_pair("before_id", &last.id.to_string());
        q.finish()
    });

    let now = Utc::now();
    let page = ListPage {
        chrome: Chrome::signed_in(&user),
        tabs: [("", "All"), ("open", "Ongoing"), ("resolved", "Resolved")]
            .into_iter()
            .map(|(v, label)| StateTab {
                value: v,
                label,
                selected: v == value,
            })
            .collect(),
        items: rows
            .into_iter()
            .map(|i| IncidentItem::new(i, now))
            .collect(),
        older,
        paged: before.is_some(),
        state: value,
    };
    Ok(Html(page.render()?))
}
