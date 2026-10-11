use askama::Template;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{Html, IntoResponse, Response};
use axum_extra::extract::{Form, Query};
use chrono::{DateTime, Utc};
use chrono_tz::{TZ_VARIANTS, Tz};
use serde::Deserialize;
use uuid::Uuid;

use super::{AppError, AppState, Chrome, is_htmx, redirect};
use crate::auth::CurrentUser;
use crate::db::channels;
use crate::db::checks::{self, Check, CheckSpec, CheckStatus};
use crate::db::incidents::{self, Incident};
use crate::db::pings::{self, Ping};
use crate::domain::schedule::Schedule;
use crate::domain::time::{duration, relative, span};

const MAX_NAME: usize = 100;
const MAX_GRACE_SECS: i64 = 30 * 24 * 60 * 60;
const MAX_RUNTIME_MINUTES: i64 = 7 * 24 * 60;
const RECENT_PINGS: i64 = 50;
const RECENT_INCIDENTS: i64 = 20;

// ───────────────────────────── dashboard ─────────────────────────────

struct CheckRow {
    id: Uuid,
    name: String,
    status: CheckStatus,
    schedule: String,
    last_ping: String,
    next_due: String,
}

impl CheckRow {
    fn new(check: &Check, now: DateTime<Utc>) -> Self {
        Self {
            id: check.id,
            name: check.name.clone(),
            status: check.status,
            schedule: schedule_text(check),
            last_ping: check
                .last_ping_at
                .map_or_else(|| "never".to_owned(), |t| relative(t, now)),
            next_due: next_due(check, now),
        }
    }
}

#[derive(Template)]
#[template(path = "checks/dashboard.html")]
struct DashboardPage {
    chrome: Chrome,
    org_name: String,
    rows: Vec<CheckRow>,
}

#[derive(Template)]
#[template(path = "checks/rows.html")]
struct RowsPartial {
    rows: Vec<CheckRow>,
}

pub async fn dashboard(
    State(state): State<AppState>,
    user: CurrentUser,
) -> Result<Html<String>, AppError> {
    let page = DashboardPage {
        chrome: Chrome::signed_in(&user),
        rows: rows(&state, &user).await?,
        org_name: user.org_name,
    };
    Ok(Html(page.render()?))
}

/// Table body, polled by the dashboard.
pub async fn table(
    State(state): State<AppState>,
    user: CurrentUser,
) -> Result<Html<String>, AppError> {
    let partial = RowsPartial {
        rows: rows(&state, &user).await?,
    };
    Ok(Html(partial.render()?))
}

async fn rows(state: &AppState, user: &CurrentUser) -> Result<Vec<CheckRow>, AppError> {
    let now = Utc::now();
    Ok(checks::list(&state.db, user.org)
        .await?
        .iter()
        .map(|c| CheckRow::new(c, now))
        .collect())
}

// ───────────────────────────── create / edit ─────────────────────────────

/// Raw form fields. Numbers stay strings so invalid input can be shown back.
#[derive(Deserialize, Default)]
#[serde(default)]
pub struct CheckInput {
    name: String,
    schedule_kind: String,
    period_value: String,
    period_unit: String,
    cron_expr: String,
    tz: String,
    grace_value: String,
    grace_unit: String,
    max_runtime_minutes: String,
    /// Repeated key, one per ticked checkbox (hence `axum_extra`'s `Form`/`Query`).
    channel_ids: Vec<String>,
}

struct FormView {
    action: String,
    submit: &'static str,
    input: CheckInput,
    channels: Vec<ChannelChoice>,
    error: Option<String>,
}

pub(super) struct ChannelChoice {
    pub(super) id: Uuid,
    pub(super) name: String,
    pub(super) kind: String,
    pub(super) verified: bool,
    pub(super) checked: bool,
}

/// The org's channels as checkboxes. `selected: None` ticks them all (new checks
/// and monitors alert everywhere by default).
pub(super) async fn channel_choices(
    state: &AppState,
    user: &CurrentUser,
    selected: Option<&[Uuid]>,
) -> Result<Vec<ChannelChoice>, AppError> {
    Ok(channels::options(&state.db, user.org)
        .await?
        .into_iter()
        .map(|c| ChannelChoice {
            checked: selected.is_none_or(|ids| ids.contains(&c.id)),
            kind: state.channels.label(&c.kind),
            id: c.id,
            name: c.name,
            verified: c.verified,
        })
        .collect())
}

fn selected_ids(input: &CheckInput) -> Vec<Uuid> {
    input
        .channel_ids
        .iter()
        .filter_map(|id| id.parse().ok())
        .collect()
}

impl FormView {
    fn blank(channels: Vec<ChannelChoice>) -> Self {
        Self {
            action: "/checks".into(),
            submit: "Create check",
            input: CheckInput {
                schedule_kind: "period".into(),
                period_value: "1".into(),
                period_unit: "days".into(),
                cron_expr: "0 2 * * *".into(),
                tz: "UTC".into(),
                grace_value: "1".into(),
                grace_unit: "hours".into(),
                ..Default::default()
            },
            channels,
            error: None,
        }
    }

    fn from_check(check: &Check, channels: Vec<ChannelChoice>) -> Self {
        let (period_value, period_unit) = split_span(check.period_secs.map_or(86_400, i64::from));
        let (grace_value, grace_unit) = split_span(check.grace_secs.into());
        Self {
            action: format!("/checks/{}", check.id),
            submit: "Save changes",
            input: CheckInput {
                name: check.name.clone(),
                schedule_kind: check.schedule_kind.clone(),
                period_value,
                period_unit,
                cron_expr: check
                    .cron_expr
                    .clone()
                    .unwrap_or_else(|| "0 2 * * *".into()),
                tz: check.tz.clone().unwrap_or_else(|| "UTC".into()),
                grace_value,
                grace_unit,
                max_runtime_minutes: check
                    .max_runtime_secs
                    .map(|s| (s / 60).to_string())
                    .unwrap_or_default(),
                channel_ids: Vec::new(),
            },
            channels,
            error: None,
        }
    }
}

#[derive(Template)]
#[template(path = "checks/form.html")]
struct FormPage {
    chrome: Chrome,
    title: &'static str,
    form: FormView,
    timezones: &'static [Tz],
}

#[derive(Template)]
#[template(path = "checks/form_fields.html")]
struct FormPartial {
    form: FormView,
    timezones: &'static [Tz],
}

pub async fn new_page(
    State(state): State<AppState>,
    user: CurrentUser,
) -> Result<Html<String>, AppError> {
    let page = FormPage {
        chrome: Chrome::signed_in(&user),
        title: "New check",
        form: FormView::blank(channel_choices(&state, &user, None).await?),
        timezones: &TZ_VARIANTS,
    };
    Ok(Html(page.render()?))
}

pub async fn create(
    State(state): State<AppState>,
    user: CurrentUser,
    headers: HeaderMap,
    Form(input): Form<CheckInput>,
) -> Result<Response, AppError> {
    match parse_spec(&input) {
        Ok(spec) => {
            let id = checks::create(&state.db, user.org, &spec).await?;
            Ok(redirect(&headers, &format!("/checks/{id}")))
        }
        Err(error) => {
            let selected = selected_ids(&input);
            let mut form = FormView::blank(channel_choices(&state, &user, Some(&selected)).await?);
            form.input = input;
            form.error = Some(error);
            form_error(&headers, &user, "New check", form)
        }
    }
}

pub async fn edit_page(
    State(state): State<AppState>,
    user: CurrentUser,
    Path(id): Path<Uuid>,
) -> Result<Html<String>, AppError> {
    let check = checks::get(&state.db, user.org, id)
        .await?
        .ok_or(AppError::NotFound)?;
    let selected = channels::ids_for_check(&state.db, user.org, id).await?;
    let page = FormPage {
        chrome: Chrome::signed_in(&user),
        title: "Edit check",
        form: FormView::from_check(
            &check,
            channel_choices(&state, &user, Some(&selected)).await?,
        ),
        timezones: &TZ_VARIANTS,
    };
    Ok(Html(page.render()?))
}

pub async fn update(
    State(state): State<AppState>,
    user: CurrentUser,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
    Form(input): Form<CheckInput>,
) -> Result<Response, AppError> {
    match parse_spec(&input) {
        Ok(spec) => {
            if !checks::update(&state.db, user.org, id, &spec).await? {
                return Err(AppError::NotFound);
            }
            Ok(redirect(&headers, &format!("/checks/{id}")))
        }
        Err(error) => {
            // Don't render a form for a check this org can't see.
            checks::get(&state.db, user.org, id)
                .await?
                .ok_or(AppError::NotFound)?;
            let selected = selected_ids(&input);
            let form = FormView {
                action: format!("/checks/{id}"),
                submit: "Save changes",
                input,
                channels: channel_choices(&state, &user, Some(&selected)).await?,
                error: Some(error),
            };
            form_error(&headers, &user, "Edit check", form)
        }
    }
}

fn form_error(
    headers: &HeaderMap,
    user: &CurrentUser,
    title: &'static str,
    form: FormView,
) -> Result<Response, AppError> {
    let html = if is_htmx(headers) {
        FormPartial {
            form,
            timezones: &TZ_VARIANTS,
        }
        .render()?
    } else {
        FormPage {
            chrome: Chrome::signed_in(user),
            title,
            form,
            timezones: &TZ_VARIANTS,
        }
        .render()?
    };
    Ok((StatusCode::UNPROCESSABLE_ENTITY, Html(html)).into_response())
}

#[derive(Template)]
#[template(path = "checks/preview.html")]
struct PreviewPartial {
    lines: Vec<String>,
    note: Option<String>,
    error: Option<String>,
}

/// Live schedule preview for the form.
pub async fn preview(
    _user: CurrentUser,
    Query(input): Query<CheckInput>,
) -> Result<Html<String>, AppError> {
    let partial = match parse_schedule(&input) {
        Ok(schedule @ Schedule::Cron { tz, .. }) => PreviewPartial {
            lines: schedule
                .upcoming(Utc::now(), 3)
                .into_iter()
                .map(|t| {
                    t.with_timezone(&tz)
                        .format("%a %d %b %Y, %H:%M %Z")
                        .to_string()
                })
                .collect(),
            note: Some("Next expected runs:".into()),
            error: None,
        },
        Ok(schedule) => PreviewPartial {
            lines: Vec::new(),
            note: Some(format!(
                "A ping is expected {schedule} after the previous one."
            )),
            error: None,
        },
        Err(error) => PreviewPartial {
            lines: Vec::new(),
            note: None,
            error: Some(error),
        },
    };
    Ok(Html(partial.render()?))
}

fn parse_spec(input: &CheckInput) -> Result<CheckSpec, String> {
    let name = input.name.trim();
    if name.is_empty() {
        return Err("Give the check a name.".into());
    }
    if name.chars().count() > MAX_NAME {
        return Err("Name must be at most 100 characters.".into());
    }
    let schedule = parse_schedule(input)?;
    let grace_secs = amount(&input.grace_value, &input.grace_unit)
        .filter(|secs| *secs <= MAX_GRACE_SECS)
        .ok_or("Grace period must be a whole number, at most 30 days.")?;
    let max_runtime_secs = match input.max_runtime_minutes.trim() {
        "" => None,
        minutes => Some(
            minutes
                .parse::<i64>()
                .ok()
                .filter(|m| (1..=MAX_RUNTIME_MINUTES).contains(m))
                .ok_or("Max run time must be between 1 minute and 7 days.")?
                * 60,
        ),
    };
    Ok(CheckSpec {
        name: name.to_owned(),
        schedule,
        // Both bounded above, well within i32.
        grace_secs: grace_secs as i32,
        max_runtime_secs: max_runtime_secs.map(|s| s as i32),
        channel_ids: selected_ids(input),
    })
}

fn parse_schedule(input: &CheckInput) -> Result<Schedule, String> {
    match input.schedule_kind.as_str() {
        "period" => {
            let secs = amount(&input.period_value, &input.period_unit)
                .ok_or("Enter the period as a whole number.")?;
            Schedule::period(secs).map_err(|e| e.to_string())
        }
        "cron" => {
            let tz = match input.tz.trim() {
                "" => "UTC",
                tz => tz,
            };
            Schedule::cron(&input.cron_expr, tz).map_err(|e| e.to_string())
        }
        _ => Err("Choose a schedule type.".into()),
    }
}

/// `value` × `unit` in seconds; `None` for non-numbers, negatives and unknown units.
fn amount(value: &str, unit: &str) -> Option<i64> {
    let n: i64 = value.trim().parse().ok().filter(|n| *n >= 0)?;
    let unit_secs = match unit {
        "minutes" => 60,
        "hours" => 3600,
        "days" => 86_400,
        _ => return None,
    };
    n.checked_mul(unit_secs)
}

/// The largest form unit that divides `secs` exactly.
fn split_span(secs: i64) -> (String, String) {
    let (n, unit) = match secs {
        s if s > 0 && s % 86_400 == 0 => (s / 86_400, "days"),
        s if s > 0 && s % 3600 == 0 => (s / 3600, "hours"),
        s => (s / 60, "minutes"),
    };
    (n.to_string(), unit.to_owned())
}

// ───────────────────────────── detail ─────────────────────────────

struct PingRow {
    kind: String,
    css: &'static str,
    when: String,
    at: String,
    duration: Option<String>,
    source_ip: Option<String>,
    user_agent: Option<String>,
    body: Option<String>,
}

impl PingRow {
    fn new(ping: Ping, now: DateTime<Utc>) -> Self {
        let (kind, css) = match (ping.kind.as_str(), ping.exit_code) {
            ("exit", Some(0)) => ("exit 0".to_owned(), "pill-up"),
            ("exit", Some(code)) => (format!("exit {code}"), "pill-down"),
            ("fail", _) => ("fail".to_owned(), "pill-down"),
            ("start", _) => ("start".to_owned(), "pill-run"),
            (kind, _) => (kind.to_owned(), "pill-up"),
        };
        Self {
            kind,
            css,
            when: relative(ping.created_at, now),
            at: absolute(ping.created_at),
            duration: ping.duration_ms.map(|ms| duration(ms.into())),
            source_ip: ping.source_ip,
            user_agent: ping.user_agent,
            body: ping.body,
        }
    }
}

pub(super) struct IncidentRow {
    pub(super) reason: &'static str,
    pub(super) detail: String,
    pub(super) started: String,
    pub(super) resolution: String,
    pub(super) open: bool,
}

impl IncidentRow {
    pub(super) fn new(incident: Incident) -> Self {
        let reason = match incident.reason.as_str() {
            "missed" => "Missed ping",
            "failed" => "Job failed",
            "hung" => "Run never finished",
            "http_down" => "Not responding as expected",
            "http_slow" => "Responding too slowly",
            _ => "Down",
        };
        let resolution = match incident.resolved_at {
            Some(end) => format!(
                "resolved after {}",
                duration((end - incident.started_at).num_milliseconds())
            ),
            None => "ongoing".to_owned(),
        };
        Self {
            reason,
            detail: incident.detail.unwrap_or_default(),
            started: absolute(incident.started_at),
            open: incident.resolved_at.is_none(),
            resolution,
        }
    }
}

struct Activity {
    id: Uuid,
    status: CheckStatus,
    last_ping: String,
    next_due: String,
    pings: Vec<PingRow>,
    incidents: Vec<IncidentRow>,
}

struct Snippets {
    ping_url: String,
    simple: String,
    crontab: Option<String>,
    wrapper: String,
}

impl Snippets {
    fn new(base_url: &str, check: &Check) -> Self {
        let url = format!("{}/p/{}", base_url.trim_end_matches('/'), check.token);
        let curl = "curl -fsS -m 10 --retry 3";
        Self {
            simple: format!("{curl} {url}"),
            crontab: check
                .cron_expr
                .as_ref()
                .map(|expr| format!("{expr} /path/to/job.sh && {curl} {url}")),
            wrapper: format!(
                "{curl} {url}/start\n\
                 OUTPUT=$(/path/to/job.sh 2>&1); CODE=$?\n\
                 printf '%s' \"$OUTPUT\" | tail -c 10000 | {curl} --data-binary @- {url}/$CODE"
            ),
            ping_url: url,
        }
    }
}

#[derive(Template)]
#[template(path = "checks/show.html")]
struct ShowPage {
    chrome: Chrome,
    id: Uuid,
    name: String,
    schedule: String,
    grace: String,
    max_runtime: Option<String>,
    paused: bool,
    snippets: Snippets,
    activity: Activity,
}

#[derive(Template)]
#[template(path = "checks/activity.html")]
struct ActivityPartial {
    activity: Activity,
}

pub async fn show(
    State(state): State<AppState>,
    user: CurrentUser,
    Path(id): Path<Uuid>,
) -> Result<Html<String>, AppError> {
    let check = checks::get(&state.db, user.org, id)
        .await?
        .ok_or(AppError::NotFound)?;
    let page = ShowPage {
        chrome: Chrome::signed_in(&user),
        id: check.id,
        name: check.name.clone(),
        schedule: schedule_text(&check),
        grace: span(check.grace_secs.into()),
        max_runtime: check.max_runtime_secs.map(|s| span(s.into())),
        paused: check.status == CheckStatus::Paused,
        snippets: Snippets::new(&state.config.base_url, &check),
        activity: activity(&state, &user, &check).await?,
    };
    Ok(Html(page.render()?))
}

/// Status, pings and incidents, polled by the detail page.
pub async fn activity_partial(
    State(state): State<AppState>,
    user: CurrentUser,
    Path(id): Path<Uuid>,
) -> Result<Html<String>, AppError> {
    let check = checks::get(&state.db, user.org, id)
        .await?
        .ok_or(AppError::NotFound)?;
    let partial = ActivityPartial {
        activity: activity(&state, &user, &check).await?,
    };
    Ok(Html(partial.render()?))
}

async fn activity(
    state: &AppState,
    user: &CurrentUser,
    check: &Check,
) -> Result<Activity, AppError> {
    let now = Utc::now();
    let pings = pings::recent(&state.db, user.org, check.id, RECENT_PINGS).await?;
    let incidents =
        incidents::recent_for_check(&state.db, user.org, check.id, RECENT_INCIDENTS).await?;
    Ok(Activity {
        id: check.id,
        status: check.status,
        last_ping: check
            .last_ping_at
            .map_or_else(|| "never".to_owned(), |t| relative(t, now)),
        next_due: next_due(check, now),
        pings: pings.into_iter().map(|p| PingRow::new(p, now)).collect(),
        incidents: incidents.into_iter().map(IncidentRow::new).collect(),
    })
}

// ───────────────────────────── actions ─────────────────────────────

pub async fn pause(
    State(state): State<AppState>,
    user: CurrentUser,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    if !checks::pause(&state.db, user.org, id).await? {
        return Err(AppError::NotFound);
    }
    Ok(redirect(&headers, &format!("/checks/{id}")))
}

pub async fn resume(
    State(state): State<AppState>,
    user: CurrentUser,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    // `false` also means "wasn't paused", which is fine; only a missing check is an error.
    if !checks::resume(&state.db, user.org, id).await?
        && checks::get(&state.db, user.org, id).await?.is_none()
    {
        return Err(AppError::NotFound);
    }
    Ok(redirect(&headers, &format!("/checks/{id}")))
}

pub async fn delete(
    State(state): State<AppState>,
    user: CurrentUser,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    if !checks::delete(&state.db, user.org, id).await? {
        return Err(AppError::NotFound);
    }
    Ok(redirect(&headers, "/dashboard"))
}

// ───────────────────────────── helpers ─────────────────────────────

fn schedule_text(check: &Check) -> String {
    check
        .schedule()
        .map_or_else(|_| "invalid schedule".to_owned(), |s| s.to_string())
}

fn next_due(check: &Check, now: DateTime<Utc>) -> String {
    match (check.status, check.next_expected_at) {
        (CheckStatus::Up, Some(t)) => relative(t, now),
        (CheckStatus::Started, _) => "running".to_owned(),
        (CheckStatus::New, _) => "after first ping".to_owned(),
        _ => "—".to_owned(),
    }
}

pub(super) fn absolute(t: DateTime<Utc>) -> String {
    t.format("%Y-%m-%d %H:%M:%S UTC").to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn input(kind: &str) -> CheckInput {
        let mut form = FormView::blank(Vec::new()).input;
        form.name = "Backup".into();
        form.schedule_kind = kind.into();
        form
    }

    #[test]
    fn parses_a_period_check() {
        let spec = parse_spec(&input("period")).unwrap();
        assert!(matches!(spec.schedule, Schedule::Period { secs: 86_400 }));
        assert_eq!(spec.grace_secs, 3600);
        assert_eq!(spec.max_runtime_secs, None);
    }

    #[test]
    fn parses_a_cron_check_with_max_runtime() {
        let mut form = input("cron");
        form.tz = "Asia/Kolkata".into();
        form.max_runtime_minutes = "90".into();
        let spec = parse_spec(&form).unwrap();
        assert_eq!(spec.schedule.to_string(), "0 2 * * * (Asia/Kolkata)");
        assert_eq!(spec.max_runtime_secs, Some(5400));
    }

    #[test]
    fn rejects_bad_input() {
        type Case = (&'static str, fn(&mut CheckInput));
        let cases: [Case; 7] = [
            ("name", |f| f.name = "  ".into()),
            ("period", |f| f.period_value = "abc".into()),
            ("period", |f| f.period_value = "-1".into()),
            ("whole number", |f| f.period_unit = "seconds".into()),
            ("Grace", |f| f.grace_value = "31".into()),
            ("Max run time", |f| f.max_runtime_minutes = "0".into()),
            ("schedule type", |f| f.schedule_kind = "sometimes".into()),
        ];
        for (expected, mutate) in cases {
            let mut form = input("period");
            mutate(&mut form);
            if expected == "Grace" {
                form.grace_unit = "days".into();
            }
            let err = parse_spec(&form).err().expect(expected);
            assert!(
                err.contains(expected),
                "{err:?} should mention {expected:?}"
            );
        }
    }

    #[test]
    fn split_span_round_trips() {
        assert_eq!(split_span(86_400 * 2), ("2".into(), "days".into()));
        assert_eq!(split_span(7200), ("2".into(), "hours".into()));
        assert_eq!(split_span(5400), ("90".into(), "minutes".into()));
        assert_eq!(split_span(0), ("0".into(), "minutes".into()));
    }
}
