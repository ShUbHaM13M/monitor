//! Public status pages at `/s/{slug}`: no sign-in, read-only, and only the
//! display names and states an org chose to publish.

use std::collections::HashMap;

use askama::Template;
use axum::Json;
use axum::extract::{Path, State};
use axum::http::{StatusCode, header};
use axum::response::{Html, IntoResponse, Response};
use chrono::{DateTime, TimeDelta, Utc};
use serde_json::json;
use uuid::Uuid;

use super::client_ip::ClientIp;
use super::ratelimit::too_many_plain;
use super::stamp::Stamp;
use super::{AppError, AppState};
use crate::auth::MaybeUser;
use crate::db::status_pages::{self, PublicItem, PublicOutage, PublicPage};
use crate::domain::status::{self, Current, Day, Level, Outage, Verdict};
use crate::domain::time::duration;

/// Past incidents listed under the components.
const RECENT_INCIDENTS: usize = 10;
/// Bar geometry (SVG user units): cell width, gap, height.
const CELL: u32 = 6;
const GAP: u32 = 2;
const HEIGHT: u32 = 30;

struct Cell {
    x: u32,
    css: &'static str,
    /// Tooltip: "18 Oct 2026 · 97.92% uptime · 30m down".
    title: String,
}

struct Component {
    name: String,
    current: Current,
    /// "Operational", "Down", "Paused", "No data yet".
    state_label: &'static str,
    uptime: String,
    /// The same, 0–1, for `status.json`.
    uptime_ratio: Option<f64>,
    cells: Vec<Cell>,
    /// Days with downtime, for the text view.
    bad_days: Vec<(String, String, String)>,
}

struct PastIncident {
    name: String,
    what: &'static str,
    started: Stamp,
    /// "lasted 12m 05s" or "ongoing for 4m".
    duration: String,
    ongoing: bool,
}

struct Live {
    verdict: Verdict,
    components: Vec<Component>,
    incidents: Vec<PastIncident>,
    width: u32,
    updated: Stamp,
}

impl Live {
    fn verdict_css(&self) -> &'static str {
        match self.verdict {
            Verdict::AllOperational => "verdict-ok",
            Verdict::Partial => "verdict-warn",
            Verdict::Major => "verdict-down",
            Verdict::NoData => "verdict-none",
        }
    }

    fn levels(&self) -> [Level; 5] {
        [
            Level::Good,
            Level::Minor,
            Level::Partial,
            Level::Major,
            Level::NoData,
        ]
    }
}

#[derive(Template)]
#[template(path = "status/public.html")]
struct Page {
    slug: String,
    title: String,
    description: Option<String>,
    /// An unpublished page seen by its own org.
    draft: bool,
    live: Live,
    height: u32,
}

#[derive(Template)]
#[template(path = "status/live.html")]
struct LivePartial {
    live: Live,
    height: u32,
}

/// Visitors' wording: what happened, without internals.
fn what(reason: &str) -> &'static str {
    match reason {
        "missed" => "Didn't run on time",
        "failed" => "Failed",
        "hung" => "Run didn't finish",
        "http_slow" => "Slow responses",
        _ => "Not responding",
    }
}

fn current(status: &str) -> (Current, &'static str) {
    match status {
        "up" | "started" => (Current::Operational, "Operational"),
        "down" => (Current::Down, "Down"),
        "paused" => (Current::Unknown, "Paused"),
        _ => (Current::Unknown, "No data yet"),
    }
}

fn percent(uptime: Option<f64>) -> String {
    match uptime {
        // Never round a failure up to a perfect score.
        Some(u) if (0.9999..1.0).contains(&u) => "99.99%".to_owned(),
        Some(u) => format!("{:.2}%", u * 100.0).replace(".00%", "%"),
        None => "—".to_owned(),
    }
}

fn day_title(day: &Day) -> String {
    let date = day.date.format("%-d %b %Y");
    match day.uptime() {
        None => format!("{date} · no data"),
        Some(_) if day.downtime_secs == 0 => format!("{date} · no downtime"),
        Some(u) => format!(
            "{date} · {} uptime · {} down",
            percent(Some(u)),
            duration(day.downtime_secs * 1000)
        ),
    }
}

fn component(item: &PublicItem, outages: &[Outage], now: DateTime<Utc>) -> Component {
    let (state, state_label) = current(&item.status);
    // A check that never reported isn't being monitored yet.
    let since = (item.status != "new").then_some(item.since);
    let days = status::daily(outages, since, now, status::DAYS);
    let uptime_ratio = status::overall(&days);
    Component {
        uptime_ratio,
        name: item.display_name.clone(),
        current: state,
        state_label,
        uptime: percent(uptime_ratio),
        bad_days: days
            .iter()
            .filter(|d| d.downtime_secs > 0)
            .rev()
            .map(|d| {
                (
                    d.date.format("%-d %b %Y").to_string(),
                    duration(d.downtime_secs * 1000),
                    percent(d.uptime()),
                )
            })
            .collect(),
        cells: days
            .iter()
            .enumerate()
            .map(|(i, d)| Cell {
                x: i as u32 * (CELL + GAP),
                css: d.level.css(),
                title: day_title(d),
            })
            .collect(),
    }
}

async fn live(state: &AppState, page: &PublicPage) -> Result<Live, AppError> {
    let now = Utc::now();
    let window = now - TimeDelta::days(status::DAYS.into());
    let items = status_pages::public_items(&state.db, page.id).await?;
    let rows = status_pages::outages(&state.db, page.id, window).await?;

    let key = |o: &PublicOutage| o.check_id.or(o.monitor_id);
    let mut by_target: HashMap<Uuid, Vec<Outage>> = HashMap::new();
    for row in &rows {
        if let Some(id) = key(row) {
            by_target.entry(id).or_default().push(Outage {
                start: row.started_at,
                end: row.resolved_at,
            });
        }
    }
    let names: HashMap<Uuid, &str> = items
        .iter()
        .filter_map(|i| {
            i.check_id
                .or(i.monitor_id)
                .map(|id| (id, i.display_name.as_str()))
        })
        .collect();

    let components: Vec<Component> = items
        .iter()
        .map(|item| {
            let id = item.check_id.or(item.monitor_id).unwrap_or_default();
            component(item, by_target.get(&id).map_or(&[], Vec::as_slice), now)
        })
        .collect();
    let incidents = rows
        .iter()
        .filter_map(|o| Some((names.get(&key(o)?)?, o)))
        .take(RECENT_INCIDENTS)
        .map(|(name, o)| {
            let lasted = (o.resolved_at.unwrap_or(now) - o.started_at).num_milliseconds();
            PastIncident {
                name: (*name).to_owned(),
                what: what(&o.reason),
                started: Stamp::absolute(o.started_at),
                duration: match o.resolved_at {
                    Some(_) => format!("lasted {}", duration(lasted)),
                    None => format!("ongoing for {}", duration(lasted)),
                },
                ongoing: o.resolved_at.is_none(),
            }
        })
        .collect();
    let currents: Vec<Current> = components.iter().map(|c| c.current).collect();
    Ok(Live {
        verdict: Verdict::of(&currents),
        components,
        incidents,
        width: status::DAYS * (CELL + GAP) - GAP,
        updated: Stamp::absolute(now),
    })
}

/// The page, if visitors (or, for a draft, its own org) may see it.
async fn visible(
    state: &AppState,
    slug: &str,
    viewer: &MaybeUser,
) -> Result<Option<PublicPage>, AppError> {
    let Some(page) = status_pages::find_by_slug(&state.db, slug).await? else {
        return Ok(None);
    };
    let own = viewer
        .0
        .as_ref()
        .is_some_and(|user| user.org.get() == page.org_id);
    Ok((page.published || own).then_some(page))
}

fn limited(state: &AppState, ClientIp(ip): ClientIp) -> Option<Response> {
    let ip = ip?;
    state
        .limits
        .public
        .check(ip)
        .err()
        .map(|wait| too_many_plain("status_page", wait))
}

fn cache(published: bool) -> (header::HeaderName, &'static str) {
    // Published pages may sit in a CDN briefly; previews never.
    let value = if published {
        "public, max-age=30"
    } else {
        "private, no-store"
    };
    (header::CACHE_CONTROL, value)
}

pub async fn page(
    State(state): State<AppState>,
    Path(slug): Path<String>,
    viewer: MaybeUser,
    ip: ClientIp,
) -> Result<Response, AppError> {
    if let Some(res) = limited(&state, ip) {
        return Ok(res);
    }
    let Some(page) = visible(&state, &slug, &viewer).await? else {
        return Err(AppError::NotFound);
    };
    let html = Page {
        slug,
        draft: !page.published,
        live: live(&state, &page).await?,
        title: page.title,
        description: page.description,
        height: HEIGHT,
    }
    .render()?;
    Ok(([cache(page.published)], Html(html)).into_response())
}

/// The refreshing part of the page.
pub async fn live_partial(
    State(state): State<AppState>,
    Path(slug): Path<String>,
    viewer: MaybeUser,
    ip: ClientIp,
) -> Result<Response, AppError> {
    if let Some(res) = limited(&state, ip) {
        return Ok(res);
    }
    let Some(page) = visible(&state, &slug, &viewer).await? else {
        return Err(AppError::NotFound);
    };
    let html = LivePartial {
        live: live(&state, &page).await?,
        height: HEIGHT,
    }
    .render()?;
    Ok(([cache(page.published)], Html(html)).into_response())
}

/// Machine-readable status, for other dashboards and badges. Published pages only.
pub async fn json(
    State(state): State<AppState>,
    Path(slug): Path<String>,
    ip: ClientIp,
) -> Result<Response, AppError> {
    if let Some(res) = limited(&state, ip) {
        return Ok(res);
    }
    let page = match status_pages::find_by_slug(&state.db, &slug).await? {
        Some(page) if page.published => page,
        _ => {
            return Ok(
                (StatusCode::NOT_FOUND, Json(json!({ "error": "not found" }))).into_response(),
            );
        }
    };
    let live = live(&state, &page).await?;
    let body = json!({
        "title": page.title,
        "status": live.verdict.id(),
        "description": live.verdict.label(),
        "components": live.components.iter().map(|c| json!({
            "name": c.name,
            "status": match c.current {
                Current::Operational => "operational",
                Current::Down => "down",
                Current::Unknown => "unknown",
            },
            "uptime_90d": c.uptime_ratio,
        })).collect::<Vec<_>>(),
        "updated_at": Utc::now(),
    });
    Ok(([cache(true)], Json(body)).into_response())
}
