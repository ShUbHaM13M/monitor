//! The dashboard: answers "is anything broken?" for the whole org at a glance.

use askama::Template;
use axum::extract::State;
use axum::response::Html;
use chrono::Utc;
use uuid::Uuid;

use super::incidents::IncidentItem;
use super::stamp::Stamp;
use super::{AppError, AppState, Chrome};
use crate::auth::CurrentUser;
use crate::db::incidents::{self, IncidentState};
use crate::db::overview;

/// Failed alert deliveries are flagged for this long.
const DELIVERY_WINDOW_HOURS: i32 = 24;
const MAX_OPEN: i64 = 50;
const RECENTLY_RESOLVED: i64 = 5;

/// `(db status, label, pill css)` in display order. Labels match the lists' filters.
const CHECK_STATES: &[(&str, &str, &str)] = &[
    ("down", "down", "pill-down"),
    ("started", "running", "pill-run"),
    ("up", "up", "pill-up"),
    ("new", "new", "pill-muted"),
    ("paused", "paused", "pill-muted"),
];
const MONITOR_STATES: &[(&str, &str, &str)] = &[
    ("down", "down", "pill-down"),
    ("up", "up", "pill-up"),
    ("new", "new", "pill-muted"),
    ("paused", "paused", "pill-muted"),
];

struct StatusCount {
    label: &'static str,
    css: &'static str,
    count: i64,
    href: String,
}

struct Group {
    title: &'static str,
    href: &'static str,
    new_href: &'static str,
    noun: &'static str,
    total: i64,
    down: i64,
    counts: Vec<StatusCount>,
}

impl Group {
    fn new(
        title: &'static str,
        href: &'static str,
        new_href: &'static str,
        noun: &'static str,
        states: &[(&str, &'static str, &'static str)],
        rows: &[(String, i64)],
    ) -> Self {
        let count_of = |status: &str| {
            rows.iter()
                .find(|(s, _)| s == status)
                .map_or(0, |(_, n)| *n)
        };
        Self {
            title,
            href,
            new_href,
            noun,
            total: rows.iter().map(|(_, n)| n).sum(),
            down: count_of("down"),
            counts: states
                .iter()
                .filter(|(status, ..)| count_of(status) > 0)
                .map(|&(status, label, css)| StatusCount {
                    label,
                    css,
                    count: count_of(status),
                    href: format!("{href}?status={label}"),
                })
                .collect(),
        }
    }
}

/// The banner at the top.
#[derive(Debug, PartialEq, Eq)]
enum Verdict {
    /// Nothing set up yet.
    Empty,
    Down(i64),
    /// Everything's up, but an alert might not reach anyone.
    AlertsAtRisk,
    AllGood,
}

struct FailingChannel {
    id: Uuid,
    name: String,
    failed: i64,
    last_error: String,
    last_at: Stamp,
}

struct Live {
    verdict: Verdict,
    checks: Group,
    monitors: Group,
    open: Vec<IncidentItem>,
    resolved: Vec<IncidentItem>,
    failing: Vec<FailingChannel>,
    channels_total: i64,
    channels_unverified: i64,
}

impl Live {
    fn groups(&self) -> [&Group; 2] {
        [&self.checks, &self.monitors]
    }

    /// Names of what's down (paused targets aren't, even with an open incident).
    fn down_names(&self) -> String {
        let names: Vec<&str> = self
            .open
            .iter()
            .filter(|i| !i.paused)
            .map(|i| i.name.as_str())
            .collect();
        names.join(", ")
    }

    fn up_summary(&self) -> String {
        let up = |g: &Group| {
            g.counts
                .iter()
                .filter(|c| c.label == "up" || c.label == "running")
                .map(|c| c.count)
                .sum::<i64>()
        };
        let part = |n: i64, noun: &str| format!("{n} {noun}{}", if n == 1 { "" } else { "s" });
        let mut parts = Vec::new();
        if self.checks.total > 0 {
            parts.push(part(up(&self.checks), "check"));
        }
        if self.monitors.total > 0 {
            parts.push(part(up(&self.monitors), "monitor"));
        }
        format!("{} up.", parts.join(" and "))
    }
}

fn verdict(down: i64, things: i64, channels_ok: bool) -> Verdict {
    match () {
        _ if things == 0 => Verdict::Empty,
        _ if down > 0 => Verdict::Down(down),
        _ if !channels_ok => Verdict::AlertsAtRisk,
        _ => Verdict::AllGood,
    }
}

async fn live(state: &AppState, user: &CurrentUser) -> Result<Live, AppError> {
    let db = &state.db;
    let now = Utc::now();
    let checks = Group::new(
        "Checks",
        "/checks",
        "/checks/new",
        "check",
        CHECK_STATES,
        &overview::check_counts(db, user.org).await?,
    );
    let monitors = Group::new(
        "Uptime",
        "/monitors",
        "/monitors/new",
        "monitor",
        MONITOR_STATES,
        &overview::monitor_counts(db, user.org).await?,
    );
    let channels = overview::channel_health(db, user.org).await?;
    let failing: Vec<FailingChannel> =
        overview::failing_channels(db, user.org, DELIVERY_WINDOW_HOURS)
            .await?
            .into_iter()
            .map(|c| FailingChannel {
                id: c.id,
                name: c.name,
                failed: c.failed,
                last_error: c.last_error.unwrap_or_default(),
                last_at: Stamp::relative(c.last_at, now),
            })
            .collect();
    let open = incidents::list_for_org(db, user.org, IncidentState::Open, None, MAX_OPEN).await?;
    let resolved = incidents::list_for_org(
        db,
        user.org,
        IncidentState::Resolved,
        None,
        RECENTLY_RESOLVED,
    )
    .await?;

    let channels_ok = channels.total > channels.unverified && failing.is_empty();
    Ok(Live {
        verdict: verdict(
            checks.down + monitors.down,
            checks.total + monitors.total,
            channels_ok,
        ),
        checks,
        monitors,
        open: open
            .into_iter()
            .map(|i| IncidentItem::new(i, now))
            .collect(),
        resolved: resolved
            .into_iter()
            .map(|i| IncidentItem::new(i, now))
            .collect(),
        failing,
        channels_total: channels.total,
        channels_unverified: channels.unverified,
    })
}

#[derive(Template)]
#[template(path = "overview/page.html")]
struct Page {
    chrome: Chrome,
    org_name: String,
    live: Live,
}

#[derive(Template)]
#[template(path = "overview/live.html")]
struct LivePartial {
    live: Live,
}

pub async fn page(
    State(state): State<AppState>,
    user: CurrentUser,
) -> Result<Html<String>, AppError> {
    let page = Page {
        chrome: Chrome::signed_in(&user),
        live: live(&state, &user).await?,
        org_name: user.org_name,
    };
    Ok(Html(page.render()?))
}

/// Polled by the dashboard.
pub async fn live_partial(
    State(state): State<AppState>,
    user: CurrentUser,
) -> Result<Html<String>, AppError> {
    Ok(Html(
        LivePartial {
            live: live(&state, &user).await?,
        }
        .render()?,
    ))
}

#[derive(Template)]
#[template(path = "partials/health.html")]
struct Health {
    down: i64,
}

/// The nav badge, polled on every page. `static/app.js` mirrors it into the
/// tab title and favicon, so a background tab shows when something breaks.
pub async fn health(
    State(state): State<AppState>,
    user: CurrentUser,
) -> Result<Html<String>, AppError> {
    let down = overview::down_count(&state.db, user.org).await?;
    Ok(Html(Health { down }.render()?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verdict_puts_outages_first() {
        assert_eq!(verdict(0, 0, false), Verdict::Empty);
        assert_eq!(verdict(2, 5, false), Verdict::Down(2));
        assert_eq!(verdict(0, 5, false), Verdict::AlertsAtRisk);
        assert_eq!(verdict(0, 5, true), Verdict::AllGood);
    }

    #[test]
    fn groups_count_and_link_by_status() {
        let rows = [
            ("up".to_owned(), 3),
            ("started".to_owned(), 1),
            ("down".to_owned(), 2),
        ];
        let g = Group::new(
            "Checks",
            "/checks",
            "/checks/new",
            "check",
            CHECK_STATES,
            &rows,
        );
        assert_eq!((g.total, g.down), (6, 2));
        let shown: Vec<_> = g.counts.iter().map(|c| (c.label, c.count)).collect();
        assert_eq!(shown, [("down", 2), ("running", 1), ("up", 3)]);
        assert_eq!(g.counts[1].href, "/checks?status=running");
    }
}
