use askama::Template;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{AppendHeaders, Html, IntoResponse, Response};
use axum_extra::extract::{Form, Query};
use chrono::Utc;
use serde::Deserialize;
use uuid::Uuid;

use super::charts::{self, HourInput, LatencyChart, Sparkline};
use super::checks::{ChannelChoice, IncidentRow, channel_choices};
use super::filter::{self, Chip, ListQuery};
use super::stamp::Stamp;
use super::{AppError, AppState, Chrome, created, is_htmx, redirect};
use crate::auth::CurrentUser;
use crate::db::incidents;
use crate::db::monitors::{self, Monitor, MonitorSpec, MonitorState, ProbeTarget};
use crate::db::{channels, orgs};
use crate::domain::time::span;
use crate::domain::uptime::{
    INTERVALS, MAX_THRESHOLD, MAX_TIMEOUT_SECS, METHODS, format_headers, parse_headers,
};
use crate::notify::http::parse_url;
use crate::worker::prober;

const MAX_NAME: usize = 100;
const MAX_BODY: usize = 10_000;
const RECENT_RESULTS: i64 = 50;
const RECENT_INCIDENTS: i64 = 20;

pub(super) fn percent(uptime: Option<f64>) -> String {
    match uptime {
        // Never round a failure up to a perfect score.
        Some(u) if (0.9999..1.0).contains(&u) => "99.99%".to_owned(),
        Some(u) => format!("{:.2}%", u * 100.0).replace(".00%", "%"),
        None => "—".to_owned(),
    }
}

fn host(url: &str) -> String {
    url::Url::parse(url)
        .ok()
        .and_then(|u| u.host_str().map(str::to_owned))
        .unwrap_or_else(|| url.to_owned())
}

// ───────────────────────────── list ─────────────────────────────

/// Filter chips, in display order. Values are the status labels.
const STATUSES: &[(&str, &str)] = &[
    ("down", "Down"),
    ("up", "Up"),
    ("new", "New"),
    ("paused", "Paused"),
];

/// Problems first, then the rest by name.
fn rank(status: MonitorState) -> u8 {
    match status {
        MonitorState::Down => 0,
        MonitorState::Up => 1,
        MonitorState::New => 2,
        MonitorState::Paused => 3,
    }
}

struct MonitorRow {
    id: Uuid,
    name: String,
    host: String,
    status: MonitorState,
    uptime: String,
    latency: String,
    last_checked: Stamp,
    sparkline: Option<Sparkline>,
}

/// Filter chips plus the table; swapped as one by the filter form and the poll.
struct ListBody {
    chips: Vec<Chip>,
    rows: Vec<MonitorRow>,
    total: usize,
}

#[derive(Template)]
#[template(path = "monitors/list.html")]
struct ListPage {
    chrome: Chrome,
    query: ListQuery,
    body: ListBody,
}

#[derive(Template)]
#[template(path = "monitors/list_body.html")]
struct ListBodyPartial {
    body: ListBody,
}

async fn list_body(
    state: &AppState,
    user: &CurrentUser,
    query: &ListQuery,
) -> Result<ListBody, AppError> {
    let now = Utc::now();
    let all = monitors::list(&state.db, user.org).await?;
    let total = all.len();
    let mut matching: Vec<Monitor> = all
        .into_iter()
        .filter(|m| query.matches_text(&[&m.name, &m.url]))
        .collect();
    let chips = query.chips(STATUSES, matching.iter().map(|m| m.status.label()));
    matching.retain(|m| query.matches_status(m.status.label(), STATUSES));
    matching.sort_by_cached_key(|m| (rank(m.status), m.name.to_lowercase()));

    let uptimes = monitors::uptime_24h_by_monitor(&state.db, user.org).await?;
    let mut latencies = monitors::latency_24h_by_monitor(&state.db, user.org).await?;
    let rows = matching
        .into_iter()
        .map(|m| MonitorRow {
            sparkline: latencies
                .remove(&m.id)
                .and_then(|points| charts::sparkline(&points, now)),
            uptime: percent(uptimes.get(&m.id).copied()),
            latency: m
                .last_latency_ms
                .filter(|_| m.last_status_code.is_some())
                .map_or_else(|| "—".to_owned(), |ms| format!("{ms} ms")),
            last_checked: Stamp::relative_or(m.last_checked_at, now, "not yet"),
            host: host(&m.url),
            id: m.id,
            name: m.name,
            status: m.status,
        })
        .collect();
    Ok(ListBody { chips, rows, total })
}

pub async fn list(
    State(state): State<AppState>,
    user: CurrentUser,
    Query(query): Query<ListQuery>,
) -> Result<Html<String>, AppError> {
    let page = ListPage {
        chrome: Chrome::signed_in(&user),
        body: list_body(&state, &user, &query).await?,
        query,
    };
    Ok(Html(page.render()?))
}

/// The list body, for the filter form and the periodic refresh.
pub async fn table(
    State(state): State<AppState>,
    user: CurrentUser,
    Query(query): Query<ListQuery>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let partial = ListBodyPartial {
        body: list_body(&state, &user, &query).await?,
    };
    let replace = filter::replace_url(&headers, "monitor-filters", &query.url("/monitors"));
    Ok((AppendHeaders(replace), Html(partial.render()?)).into_response())
}

// ───────────────────────────── create / edit ─────────────────────────────

/// Raw form fields, kept as strings so invalid input can be shown back.
#[derive(Deserialize, Default)]
#[serde(default)]
pub struct MonitorInput {
    pub(super) name: String,
    pub(super) url: String,
    pub(super) method: String,
    pub(super) interval_secs: String,
    pub(super) timeout_secs: String,
    pub(super) expected_status: String,
    pub(super) body_contains: String,
    pub(super) max_latency_ms: String,
    pub(super) fail_threshold: String,
    pub(super) headers: String,
    pub(super) body: String,
    pub(super) channel_ids: Vec<String>,
}

struct FormView {
    action: String,
    submit: &'static str,
    input: MonitorInput,
    channels: Vec<ChannelChoice>,
    error: Option<String>,
}

impl FormView {
    fn blank(channels: Vec<ChannelChoice>) -> Self {
        Self {
            action: "/monitors".into(),
            submit: "Create monitor",
            input: MonitorInput {
                method: "GET".into(),
                interval_secs: "60".into(),
                timeout_secs: "10".into(),
                fail_threshold: "2".into(),
                ..Default::default()
            },
            channels,
            error: None,
        }
    }

    fn from_monitor(state: &AppState, m: &Monitor, channels: Vec<ChannelChoice>) -> Self {
        let headers = prober::decrypt_headers(&state.secrets, m.headers_enc.as_deref())
            .map(|h| format_headers(&h))
            .unwrap_or_default();
        let opt = |v: Option<i32>| v.map(|v| v.to_string()).unwrap_or_default();
        Self {
            action: format!("/monitors/{}", m.id),
            submit: "Save changes",
            input: MonitorInput {
                name: m.name.clone(),
                url: m.url.clone(),
                method: m.method.clone(),
                interval_secs: m.interval_secs.to_string(),
                timeout_secs: (m.timeout_ms / 1000).to_string(),
                expected_status: opt(m.expected_status.map(i32::from)),
                body_contains: m.body_contains.clone().unwrap_or_default(),
                max_latency_ms: opt(m.max_latency_ms),
                fail_threshold: m.fail_threshold.to_string(),
                headers,
                body: m.body.clone().unwrap_or_default(),
                channel_ids: Vec::new(),
            },
            channels,
            error: None,
        }
    }
}

#[derive(Template)]
#[template(path = "monitors/form.html")]
struct FormPage {
    chrome: Chrome,
    title: &'static str,
    form: FormView,
    intervals: &'static [(i32, &'static str)],
    methods: &'static [&'static str],
    /// Shorter intervals are shown but disabled.
    min_interval: i32,
}

#[derive(Template)]
#[template(path = "monitors/form_fields.html")]
struct FormPartial {
    form: FormView,
    intervals: &'static [(i32, &'static str)],
    methods: &'static [&'static str],
    /// Shorter intervals are shown but disabled.
    min_interval: i32,
}

fn selected_ids(input: &MonitorInput) -> Vec<Uuid> {
    input
        .channel_ids
        .iter()
        .filter_map(|id| id.parse().ok())
        .collect()
}

pub async fn new_page(
    State(state): State<AppState>,
    user: CurrentUser,
) -> Result<Html<String>, AppError> {
    let limits = orgs::limits(&state.db, user.org, &state.config.plan).await?;
    let mut form = FormView::blank(channel_choices(&state, &user, None).await?);
    if form.input.interval_secs.parse().unwrap_or(0) < limits.min_interval_secs {
        form.input.interval_secs = limits.min_interval_secs.to_string();
    }
    let page = FormPage {
        chrome: Chrome::signed_in(&user),
        title: "New monitor",
        form,
        intervals: &INTERVALS,
        methods: &METHODS,
        min_interval: limits.min_interval_secs,
    };
    Ok(Html(page.render()?))
}

pub async fn create(
    State(state): State<AppState>,
    user: CurrentUser,
    headers: HeaderMap,
    Form(input): Form<MonitorInput>,
) -> Result<Response, AppError> {
    let limits = orgs::limits(&state.db, user.org, &state.config.plan).await?;
    let result = match parse_spec(&state, &input, limits.min_interval_secs) {
        Ok(spec) => created(
            monitors::create(&state.db, user.org, &spec, limits.max_monitors).await,
            "monitors",
        )?,
        Err(error) => Err(error),
    };
    match result {
        Ok(id) => Ok(redirect(&headers, &format!("/monitors/{id}"))),
        Err(error) => {
            let selected = selected_ids(&input);
            let mut form = FormView::blank(channel_choices(&state, &user, Some(&selected)).await?);
            form.input = input;
            form.error = Some(error);
            form_error(
                &headers,
                &user,
                "New monitor",
                form,
                limits.min_interval_secs,
            )
        }
    }
}

pub async fn edit_page(
    State(state): State<AppState>,
    user: CurrentUser,
    Path(id): Path<Uuid>,
) -> Result<Html<String>, AppError> {
    let monitor = monitors::get(&state.db, user.org, id)
        .await?
        .ok_or(AppError::NotFound)?;
    let selected = channels::ids_for_monitor(&state.db, user.org, id).await?;
    let choices = channel_choices(&state, &user, Some(&selected)).await?;
    let page = FormPage {
        chrome: Chrome::signed_in(&user),
        title: "Edit monitor",
        form: FormView::from_monitor(&state, &monitor, choices),
        intervals: &INTERVALS,
        methods: &METHODS,
        min_interval: orgs::limits(&state.db, user.org, &state.config.plan)
            .await?
            .min_interval_secs,
    };
    Ok(Html(page.render()?))
}

pub async fn update(
    State(state): State<AppState>,
    user: CurrentUser,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
    Form(input): Form<MonitorInput>,
) -> Result<Response, AppError> {
    let limits = orgs::limits(&state.db, user.org, &state.config.plan).await?;
    match parse_spec(&state, &input, limits.min_interval_secs) {
        Ok(spec) => {
            if !monitors::update(&state.db, user.org, id, &spec).await? {
                return Err(AppError::NotFound);
            }
            Ok(redirect(&headers, &format!("/monitors/{id}")))
        }
        Err(error) => {
            monitors::get(&state.db, user.org, id)
                .await?
                .ok_or(AppError::NotFound)?;
            let selected = selected_ids(&input);
            let form = FormView {
                action: format!("/monitors/{id}"),
                submit: "Save changes",
                input,
                channels: channel_choices(&state, &user, Some(&selected)).await?,
                error: Some(error),
            };
            form_error(
                &headers,
                &user,
                "Edit monitor",
                form,
                limits.min_interval_secs,
            )
        }
    }
}

fn form_error(
    headers: &HeaderMap,
    user: &CurrentUser,
    title: &'static str,
    form: FormView,
    min_interval: i32,
) -> Result<Response, AppError> {
    let html = if is_htmx(headers) {
        FormPartial {
            form,
            intervals: &INTERVALS,
            methods: &METHODS,
            min_interval,
        }
        .render()?
    } else {
        FormPage {
            chrome: Chrome::signed_in(user),
            title,
            form,
            intervals: &INTERVALS,
            methods: &METHODS,
            min_interval,
        }
        .render()?
    };
    Ok((StatusCode::UNPROCESSABLE_ENTITY, Html(html)).into_response())
}

/// An optional whole number within `range`; `Ok(None)` for an empty field.
fn optional_number(
    raw: &str,
    range: std::ops::RangeInclusive<i32>,
    message: &str,
) -> Result<Option<i32>, String> {
    match raw.trim() {
        "" => Ok(None),
        text => text
            .parse::<i32>()
            .ok()
            .filter(|n| range.contains(n))
            .map(Some)
            .ok_or_else(|| message.to_owned()),
    }
}

pub(super) fn parse_spec(
    state: &AppState,
    input: &MonitorInput,
    min_interval: i32,
) -> Result<MonitorSpec, String> {
    let name = input.name.trim();
    if name.is_empty() {
        return Err("Give the monitor a name.".into());
    }
    if name.chars().count() > MAX_NAME {
        return Err("Name must be at most 100 characters.".into());
    }
    let url = parse_url(&input.url, state.config.allow_private_targets)?;
    let method = input.method.trim().to_uppercase();
    if !METHODS.contains(&method.as_str()) {
        return Err("Choose an HTTP method.".into());
    }
    let interval_secs = input
        .interval_secs
        .trim()
        .parse::<i32>()
        .ok()
        .filter(|s| INTERVALS.iter().any(|(secs, _)| secs == s))
        .ok_or("Choose a check interval.")?;
    if interval_secs < min_interval {
        return Err(format!(
            "Your plan checks at most every {}. Choose a longer interval.",
            span(min_interval.into())
        ));
    }
    let timeout_secs = optional_number(
        &input.timeout_secs,
        1..=MAX_TIMEOUT_SECS,
        "Timeout must be between 1 and 30 seconds.",
    )?
    .unwrap_or(10);
    let expected_status = optional_number(
        &input.expected_status,
        100..=599,
        "Expected status must be an HTTP status code (100–599).",
    )?;
    let max_latency_ms = optional_number(
        &input.max_latency_ms,
        1..=timeout_secs * 1000,
        "Max response time must be a number of milliseconds, below the timeout.",
    )?;
    let fail_threshold = optional_number(
        &input.fail_threshold,
        1..=i32::from(MAX_THRESHOLD),
        "Failures before alerting must be between 1 and 10.",
    )?
    .unwrap_or(2);
    let body_contains = input.body_contains.trim();
    if body_contains.len() > 1000 {
        return Err("\"Response must contain\" is limited to 1000 characters.".into());
    }
    let header_list = parse_headers(&input.headers)?;
    let body = input.body.trim();
    if body.len() > MAX_BODY {
        return Err("The request body is limited to 10,000 characters.".into());
    }
    let headers_enc = (!header_list.is_empty()).then(|| {
        state
            .secrets
            .seal(&serde_json::to_vec(&header_list).expect("headers serialise"))
    });
    Ok(MonitorSpec {
        name: name.to_owned(),
        url: url.to_string(),
        method,
        headers_enc,
        body: (!body.is_empty()).then(|| body.to_owned()),
        interval_secs,
        timeout_ms: timeout_secs * 1000,
        expected_status: expected_status.and_then(|s| i16::try_from(s).ok()),
        body_contains: (!body_contains.is_empty()).then(|| body_contains.to_owned()),
        max_latency_ms,
        // Bounded to 1..=10 above.
        fail_threshold: fail_threshold as i16,
        channel_ids: selected_ids(input),
    })
}

// ───────────────────────────── detail ─────────────────────────────

struct ResultView {
    ok: bool,
    when: Stamp,
    status: String,
    latency: String,
    error: String,
}

struct Tile {
    label: &'static str,
    value: String,
}

struct Activity {
    id: Uuid,
    status: MonitorState,
    last_error: Option<String>,
    last_checked: Stamp,
    tiles: Vec<Tile>,
    chart: Option<LatencyChart>,
    results: Vec<ResultView>,
    incidents: Vec<IncidentRow>,
}

#[derive(Template)]
#[template(path = "monitors/show.html")]
struct ShowPage {
    chrome: Chrome,
    id: Uuid,
    name: String,
    url: String,
    method: String,
    interval: String,
    rules: Vec<String>,
    paused: bool,
    activity: Activity,
}

#[derive(Template)]
#[template(path = "monitors/activity.html")]
struct ActivityPartial {
    activity: Activity,
}

async fn activity(state: &AppState, user: &CurrentUser, m: &Monitor) -> Result<Activity, AppError> {
    let now = Utc::now();
    let mut tiles = Vec::new();
    for (label, hours) in [
        ("Uptime, 24 hours", 24),
        ("Uptime, 7 days", 24 * 7),
        ("Uptime, 30 days", 24 * 30),
    ] {
        tiles.push(Tile {
            label,
            value: percent(monitors::uptime(&state.db, user.org, m.id, hours).await?),
        });
    }
    let hours: Vec<HourInput> = monitors::latency_24h(&state.db, user.org, m.id)
        .await?
        .into_iter()
        .map(|p| HourInput {
            hour: p.bucket_hour,
            avg_ms: p.avg_ms,
            p95_ms: p.p95_ms,
            checks: p.count,
            failed: p.fail_count,
        })
        .collect();
    let results = monitors::recent_results(&state.db, user.org, m.id, RECENT_RESULTS)
        .await?
        .into_iter()
        .map(|r| ResultView {
            ok: r.ok,
            when: Stamp::relative(r.created_at, now),
            status: r
                .status_code
                .map_or_else(|| "—".to_owned(), |s| s.to_string()),
            latency: match (r.status_code, r.latency_ms) {
                (Some(_), Some(ms)) => format!("{ms} ms"),
                _ => "—".to_owned(),
            },
            error: r.error.unwrap_or_default(),
        })
        .collect();
    let incidents = incidents::recent_for_monitor(&state.db, user.org, m.id, RECENT_INCIDENTS)
        .await?
        .into_iter()
        .map(IncidentRow::new)
        .collect();
    Ok(Activity {
        id: m.id,
        status: m.status,
        last_error: m.last_error.clone(),
        last_checked: Stamp::relative_or(m.last_checked_at, now, "not yet"),
        tiles,
        chart: charts::latency_chart(&hours, now),
        results,
        incidents,
    })
}

fn rules(m: &Monitor) -> Vec<String> {
    let mut rules = vec![match m.expected_status {
        Some(code) => format!("status {code}"),
        None => "status 2xx or 3xx".to_owned(),
    }];
    if let Some(text) = &m.body_contains {
        rules.push(format!("contains \"{text}\""));
    }
    if let Some(ms) = m.max_latency_ms {
        rules.push(format!("responds within {ms} ms"));
    }
    rules.push(format!("timeout {} s", m.timeout_ms / 1000));
    rules.push(format!(
        "alert after {} failed check{}",
        m.fail_threshold,
        if m.fail_threshold == 1 { "" } else { "s" }
    ));
    rules
}

pub async fn show(
    State(state): State<AppState>,
    user: CurrentUser,
    Path(id): Path<Uuid>,
) -> Result<Html<String>, AppError> {
    let m = monitors::get(&state.db, user.org, id)
        .await?
        .ok_or(AppError::NotFound)?;
    let page = ShowPage {
        chrome: Chrome::signed_in(&user),
        id: m.id,
        name: m.name.clone(),
        url: m.url.clone(),
        method: m.method.clone(),
        interval: INTERVALS
            .iter()
            .find(|(secs, _)| *secs == m.interval_secs)
            .map_or_else(
                || format!("{} s", m.interval_secs),
                |(_, label)| (*label).to_owned(),
            ),
        rules: rules(&m),
        paused: m.status == MonitorState::Paused,
        activity: activity(&state, &user, &m).await?,
    };
    Ok(Html(page.render()?))
}

pub async fn activity_partial(
    State(state): State<AppState>,
    user: CurrentUser,
    Path(id): Path<Uuid>,
) -> Result<Html<String>, AppError> {
    let m = monitors::get(&state.db, user.org, id)
        .await?
        .ok_or(AppError::NotFound)?;
    Ok(Html(
        ActivityPartial {
            activity: activity(&state, &user, &m).await?,
        }
        .render()?,
    ))
}

#[derive(Template)]
#[template(path = "monitors/check_result.html")]
struct CheckResult {
    ok: bool,
    summary: String,
}

/// Runs a check right now, through the same path as the scheduler (so it counts),
/// and reports the result inline.
pub async fn check_now(
    State(state): State<AppState>,
    user: CurrentUser,
    Path(id): Path<Uuid>,
) -> Result<Response, AppError> {
    let m = monitors::get(&state.db, user.org, id)
        .await?
        .ok_or(AppError::NotFound)?;
    let outcome = prober::probe(&state, &ProbeTarget::from(&m)).await;
    if m.status != MonitorState::Paused {
        monitors::record_result(&state.db, &state.config.base_url, m.id, &outcome).await?;
    }
    let summary = match (&outcome.error, outcome.status_code) {
        (None, Some(code)) => format!("HTTP {code} in {} ms", outcome.latency_ms),
        (Some(error), _) => error.clone(),
        (None, None) => "OK".to_owned(),
    };
    // Tell the activity panel to refresh with the new result.
    let mut response = Html(
        CheckResult {
            ok: outcome.ok,
            summary,
        }
        .render()?,
    )
    .into_response();
    response.headers_mut().insert(
        "HX-Trigger",
        "monitor-checked".parse().expect("static header"),
    );
    Ok(response)
}

// ───────────────────────────── actions ─────────────────────────────

pub async fn pause(
    State(state): State<AppState>,
    user: CurrentUser,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    if !monitors::pause(&state.db, user.org, id).await? {
        return Err(AppError::NotFound);
    }
    Ok(redirect(&headers, &format!("/monitors/{id}")))
}

pub async fn resume(
    State(state): State<AppState>,
    user: CurrentUser,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    if !monitors::resume(&state.db, user.org, id).await?
        && monitors::get(&state.db, user.org, id).await?.is_none()
    {
        return Err(AppError::NotFound);
    }
    Ok(redirect(&headers, &format!("/monitors/{id}")))
}

pub async fn delete(
    State(state): State<AppState>,
    user: CurrentUser,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    if !monitors::delete(&state.db, user.org, id).await? {
        return Err(AppError::NotFound);
    }
    Ok(redirect(&headers, "/monitors"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn percentages() {
        assert_eq!(percent(Some(1.0)), "100%");
        assert_eq!(percent(Some(0.99995)), "99.99%", "never rounds up to 100");
        assert_eq!(percent(Some(0.9871)), "98.71%");
        assert_eq!(percent(None), "—");
    }

    #[test]
    fn hosts() {
        assert_eq!(
            host("https://api.example.com/health?x=1"),
            "api.example.com"
        );
        assert_eq!(host("not a url"), "not a url");
    }
}
