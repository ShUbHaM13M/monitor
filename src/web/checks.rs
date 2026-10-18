use askama::Template;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, HeaderName, StatusCode};
use axum::response::{AppendHeaders, Html, IntoResponse, Response};
use axum_extra::extract::{Form, Query};
use chrono::{DateTime, Utc};
use chrono_tz::{TZ_VARIANTS, Tz};
use serde::Deserialize;
use uuid::Uuid;

use super::filter::{self, Chip, ListQuery};
use super::stamp::Stamp;
use super::{AppError, AppState, Chrome, created, is_htmx, redirect};
use crate::auth::CurrentUser;
use crate::crypto::SecretBox;
use crate::db::checks::{self, Check, CheckKind, CheckSpec, CheckStatus, SignatureSpec};
use crate::db::incidents::{self, Incident};
use crate::db::pings::{self, Ping};
use crate::db::{channels, orgs};
use crate::domain::schedule::Schedule;
use crate::domain::signature::Scheme;
use crate::domain::time::{duration, span};

const MAX_NAME: usize = 100;
const MAX_GRACE_SECS: i64 = 30 * 24 * 60 * 60;
const MAX_RUNTIME_MINUTES: i64 = 7 * 24 * 60;
const RECENT_PINGS: i64 = 50;
const RECENT_INCIDENTS: i64 = 20;

// ───────────────────────────── list ─────────────────────────────

/// Filter chips, in display order. Values are the status labels.
const STATUSES: &[(&str, &str)] = &[
    ("down", "Down"),
    ("running", "Running"),
    ("up", "Up"),
    ("new", "New"),
    ("paused", "Paused"),
];

/// Problems first, then the rest by name.
fn rank(status: CheckStatus) -> u8 {
    match status {
        CheckStatus::Down => 0,
        CheckStatus::Started => 1,
        CheckStatus::Up => 2,
        CheckStatus::New => 3,
        CheckStatus::Paused => 4,
    }
}

struct CheckRow {
    id: Uuid,
    name: String,
    is_webhook: bool,
    status: CheckStatus,
    schedule: String,
    last_ping: Stamp,
    next_due: Stamp,
}

impl CheckRow {
    fn new(check: &Check, now: DateTime<Utc>) -> Self {
        Self {
            id: check.id,
            name: check.name.clone(),
            is_webhook: check.is_webhook(),
            status: check.status,
            schedule: schedule_text(check),
            last_ping: Stamp::relative_or(check.last_ping_at, now, "never"),
            next_due: next_due(check, now),
        }
    }
}

/// Filter chips plus the table; swapped as one by the filter form and the poll.
struct ListBody {
    chips: Vec<Chip>,
    rows: Vec<CheckRow>,
    total: usize,
}

#[derive(Template)]
#[template(path = "checks/list.html")]
struct ListPage {
    chrome: Chrome,
    query: ListQuery,
    body: ListBody,
}

#[derive(Template)]
#[template(path = "checks/list_body.html")]
struct ListBodyPartial {
    body: ListBody,
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
    let replace = filter::replace_url(&headers, "check-filters", &query.url("/checks"));
    Ok((AppendHeaders(replace), Html(partial.render()?)).into_response())
}

async fn list_body(
    state: &AppState,
    user: &CurrentUser,
    query: &ListQuery,
) -> Result<ListBody, AppError> {
    let now = Utc::now();
    let all = checks::list(&state.db, user.org).await?;
    let total = all.len();
    let mut matching: Vec<&Check> = all
        .iter()
        .filter(|c| query.matches_text(&[&c.name]))
        .collect();
    let chips = query.chips(STATUSES, matching.iter().map(|c| c.status.label()));
    matching.retain(|c| query.matches_status(c.status.label(), STATUSES));
    matching.sort_by_cached_key(|c| (rank(c.status), c.name.to_lowercase()));
    Ok(ListBody {
        chips,
        rows: matching
            .into_iter()
            .map(|c| CheckRow::new(c, now))
            .collect(),
        total,
    })
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
    /// "heartbeat" or "webhook"; only read on create.
    kind: String,
    /// Webhook monitors: "" (none) or a `Scheme` id.
    signature_scheme: String,
    signature_header: String,
    /// Never rendered back; blank on edit keeps the stored secret.
    signing_secret: String,
}

struct FormView {
    action: String,
    submit: &'static str,
    input: CheckInput,
    channels: Vec<ChannelChoice>,
    error: Option<String>,
    /// The kind can't change after creation (the URL a provider calls would).
    kind_locked: bool,
    has_secret: bool,
    schemes: [(&'static str, &'static str); 4],
}

fn schemes() -> [(&'static str, &'static str); 4] {
    Scheme::ALL.map(|s| (s.id(), s.label()))
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
                kind: "heartbeat".into(),
                ..Default::default()
            },
            channels,
            error: None,
            kind_locked: false,
            has_secret: false,
            schemes: schemes(),
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
                kind: check.kind.clone(),
                signature_scheme: check.signature_scheme.clone().unwrap_or_default(),
                signature_header: check.signature_header.clone().unwrap_or_default(),
                signing_secret: String::new(),
            },
            channels,
            error: None,
            kind_locked: true,
            has_secret: check.has_secret,
            schemes: schemes(),
        }
    }

    /// Re-renders an edit form after a validation error.
    fn for_edit(
        check: &Check,
        mut input: CheckInput,
        channels: Vec<ChannelChoice>,
        error: String,
    ) -> Self {
        input.kind = check.kind.clone();
        input.signing_secret.clear();
        Self {
            action: format!("/checks/{}", check.id),
            submit: "Save changes",
            input,
            channels,
            error: Some(error),
            kind_locked: true,
            has_secret: check.has_secret,
            schemes: schemes(),
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
    let result = match parse_spec(&input, None, &state.secrets) {
        Ok(spec) => {
            let limits = orgs::limits(&state.db, user.org, &state.config.plan).await?;
            created(
                checks::create(&state.db, user.org, &spec, limits.max_checks).await,
                "checks",
            )?
        }
        Err(error) => Err(error),
    };
    match result {
        Ok(id) => Ok(redirect(&headers, &format!("/checks/{id}"))),
        Err(error) => {
            let selected = selected_ids(&input);
            let mut form = FormView::blank(channel_choices(&state, &user, Some(&selected)).await?);
            form.input = input;
            form.input.signing_secret.clear();
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
    let existing = checks::get(&state.db, user.org, id)
        .await?
        .ok_or(AppError::NotFound)?;
    match parse_spec(&input, Some(&existing), &state.secrets) {
        Ok(spec) => {
            if !checks::update(&state.db, user.org, id, &spec).await? {
                return Err(AppError::NotFound);
            }
            Ok(redirect(&headers, &format!("/checks/{id}")))
        }
        Err(error) => {
            let selected = selected_ids(&input);
            let channels = channel_choices(&state, &user, Some(&selected)).await?;
            let form = FormView::for_edit(&existing, input, channels, error);
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
            note: Some(format!("Expected {schedule} after the previous one.")),
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

/// `existing` is the check being edited (its kind is fixed, and its stored secret
/// may be kept).
fn parse_spec(
    input: &CheckInput,
    existing: Option<&Check>,
    secrets: &SecretBox,
) -> Result<CheckSpec, String> {
    let kind = match (existing, input.kind.as_str()) {
        (Some(check), _) if check.is_webhook() => CheckKind::Webhook,
        (Some(_), _) | (None, "" | "heartbeat") => CheckKind::Heartbeat,
        (None, "webhook") => CheckKind::Webhook,
        (None, _) => return Err("Choose what to monitor.".into()),
    };
    let signature = match kind {
        CheckKind::Webhook => parse_signature(input, existing, secrets)?,
        CheckKind::Heartbeat => None,
    };
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
        kind,
        signature,
        name: name.to_owned(),
        schedule,
        // Both bounded above, well within i32.
        grace_secs: grace_secs as i32,
        // Webhooks have no runs to time.
        max_runtime_secs: max_runtime_secs
            .filter(|_| kind == CheckKind::Heartbeat)
            .map(|s| s as i32),
        channel_ids: selected_ids(input),
    })
}

const MAX_SECRET: usize = 512;

fn parse_signature(
    input: &CheckInput,
    existing: Option<&Check>,
    secrets: &SecretBox,
) -> Result<Option<SignatureSpec>, String> {
    let scheme = match input.signature_scheme.trim() {
        "" => return Ok(None),
        id => Scheme::parse(id).ok_or("Choose a signature type.")?,
    };
    let header = match scheme {
        Scheme::HmacSha256 => {
            let name = input.signature_header.trim();
            HeaderName::from_bytes(name.as_bytes())
                .map_err(|_| "Enter the name of the header that carries the signature.")?;
            Some(name.to_ascii_lowercase())
        }
        _ => None,
    };
    let secret = input.signing_secret.trim();
    let secret_enc = if secret.is_empty() {
        if !existing.is_some_and(|c| c.has_secret) {
            return Err("Enter the signing secret from the provider.".into());
        }
        None // keep the stored one
    } else if secret.len() > MAX_SECRET {
        return Err("The signing secret is limited to 512 characters.".into());
    } else {
        Some(secrets.seal(secret.as_bytes()))
    };
    Ok(Some(SignatureSpec {
        scheme: scheme.id(),
        header,
        secret_enc,
    }))
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
    when: Stamp,
    duration: Option<String>,
    source_ip: Option<String>,
    user_agent: Option<String>,
    body: Option<String>,
    /// Webhook deliveries: method, captured headers (one per line), cut marker.
    method: Option<String>,
    headers: Option<String>,
    body_truncated: bool,
    /// Why a delivery was rejected.
    note: Option<String>,
}

impl PingRow {
    fn new(ping: Ping, now: DateTime<Utc>) -> Self {
        let (kind, css) = match (ping.kind.as_str(), ping.exit_code) {
            ("exit", Some(0)) => ("exit 0".to_owned(), "pill-up"),
            ("exit", Some(code)) => (format!("exit {code}"), "pill-down"),
            ("fail", _) => ("fail".to_owned(), "pill-down"),
            ("start", _) => ("start".to_owned(), "pill-run"),
            ("webhook", _) => ("received".to_owned(), "pill-up"),
            ("rejected", _) => ("rejected".to_owned(), "pill-down"),
            (kind, _) => (kind.to_owned(), "pill-up"),
        };
        let headers = ping
            .headers
            .as_ref()
            .and_then(|h| h.as_object())
            .map(|map| {
                map.iter()
                    .map(|(name, value)| format!("{name}: {}", value.as_str().unwrap_or_default()))
                    .collect::<Vec<_>>()
                    .join("\n")
            });
        Self {
            kind,
            css,
            when: Stamp::relative(ping.created_at, now),
            duration: ping.duration_ms.map(|ms| duration(ms.into())),
            source_ip: ping.source_ip,
            user_agent: ping.user_agent,
            body: ping.body,
            method: ping.method,
            headers,
            body_truncated: ping.body_truncated,
            note: ping.note,
        }
    }
}

pub(super) fn reason_label(reason: &str) -> &'static str {
    match reason {
        "missed" => "Missed ping",
        "failed" => "Job failed",
        "hung" => "Run never finished",
        "http_down" => "Not responding as expected",
        "http_slow" => "Responding too slowly",
        _ => "Down",
    }
}

pub(super) struct IncidentRow {
    pub(super) reason: &'static str,
    pub(super) detail: String,
    pub(super) started: Stamp,
    pub(super) resolution: String,
    pub(super) open: bool,
}

impl IncidentRow {
    pub(super) fn new(incident: Incident) -> Self {
        let reason = reason_label(&incident.reason);
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
            started: Stamp::absolute(incident.started_at),
            open: incident.resolved_at.is_none(),
            resolution,
        }
    }
}

struct Activity {
    id: Uuid,
    is_webhook: bool,
    status: CheckStatus,
    last_ping: Stamp,
    next_due: Stamp,
    pings: Vec<PingRow>,
    incidents: Vec<IncidentRow>,
}

struct Snippets {
    ping_url: String,
    simple: String,
    crontab: Option<String>,
    wrapper: String,
}

/// What the detail page shows a webhook monitor's owner.
struct WebhookSetup {
    url: String,
    /// e.g. "Stripe", or `None` when unsigned.
    signed_by: Option<&'static str>,
    signature_header: Option<String>,
    /// A test request; only sensible when unsigned.
    test_curl: Option<String>,
}

impl WebhookSetup {
    fn new(base_url: &str, check: &Check) -> Self {
        let url = format!("{}/w/{}", base_url.trim_end_matches('/'), check.token);
        let scheme = check.signature_scheme.as_deref().and_then(Scheme::parse);
        Self {
            signed_by: scheme.map(Scheme::label),
            signature_header: scheme.and_then(|s| {
                s.header()
                    .map(str::to_owned)
                    .or_else(|| check.signature_header.clone())
            }),
            test_curl: scheme.is_none().then(|| {
                format!(
                    "curl -X POST -H 'Content-Type: application/json' -d '{{\"test\":true}}' {url}"
                )
            }),
            url,
        }
    }
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
    webhook: Option<WebhookSetup>,
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
        webhook: check
            .is_webhook()
            .then(|| WebhookSetup::new(&state.config.base_url, &check)),
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
        is_webhook: check.is_webhook(),
        status: check.status,
        last_ping: Stamp::relative_or(check.last_ping_at, now, "never"),
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
    Ok(redirect(&headers, "/checks"))
}

// ───────────────────────────── helpers ─────────────────────────────

fn schedule_text(check: &Check) -> String {
    check
        .schedule()
        .map_or_else(|_| "invalid schedule".to_owned(), |s| s.to_string())
}

fn next_due(check: &Check, now: DateTime<Utc>) -> Stamp {
    match (check.status, check.next_expected_at) {
        (CheckStatus::Up, Some(t)) => Stamp::relative(t, now),
        (CheckStatus::Started, _) => Stamp::text("running"),
        (CheckStatus::New, _) => Stamp::text("after first ping"),
        _ => Stamp::text("—"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn secrets() -> SecretBox {
        SecretBox::from_base64(&SecretBox::generate_key()).unwrap()
    }

    fn parse(input: &CheckInput) -> Result<CheckSpec, String> {
        parse_spec(input, None, &secrets())
    }

    fn webhook(scheme: &str, secret: &str) -> CheckInput {
        let mut form = input("period");
        form.kind = "webhook".into();
        form.signature_scheme = scheme.into();
        form.signing_secret = secret.into();
        form
    }

    #[test]
    fn webhook_monitors_need_a_secret_when_signed() {
        let spec = parse(&webhook("stripe", "whsec_123")).unwrap();
        assert_eq!(spec.kind, CheckKind::Webhook);
        let sig = spec.signature.unwrap();
        assert_eq!(sig.scheme, "stripe");
        assert!(sig.secret_enc.is_some());

        let unsigned = parse(&webhook("", "")).unwrap();
        assert!(unsigned.signature.is_none());
        assert!(
            parse(&webhook("github", ""))
                .err()
                .unwrap()
                .contains("signing secret")
        );
        assert!(
            parse(&webhook("md5", "x"))
                .err()
                .unwrap()
                .contains("signature type")
        );

        let mut generic = webhook("hmac_sha256", "k");
        assert!(parse(&generic).err().unwrap().contains("header"));
        generic.signature_header = "X-Signature".into();
        let sig = parse(&generic).unwrap().signature.unwrap();
        assert_eq!(sig.header.as_deref(), Some("x-signature"));
    }

    #[test]
    fn heartbeat_checks_ignore_signature_fields() {
        let mut form = input("period");
        form.signature_scheme = "stripe".into();
        let spec = parse(&form).unwrap();
        assert_eq!(spec.kind, CheckKind::Heartbeat);
        assert!(spec.signature.is_none());
    }

    fn input(kind: &str) -> CheckInput {
        let mut form = FormView::blank(Vec::new()).input;
        form.name = "Backup".into();
        form.schedule_kind = kind.into();
        form
    }

    #[test]
    fn parses_a_period_check() {
        let spec = parse(&input("period")).unwrap();
        assert!(matches!(spec.schedule, Schedule::Period { secs: 86_400 }));
        assert_eq!(spec.grace_secs, 3600);
        assert_eq!(spec.max_runtime_secs, None);
    }

    #[test]
    fn parses_a_cron_check_with_max_runtime() {
        let mut form = input("cron");
        form.tz = "Asia/Kolkata".into();
        form.max_runtime_minutes = "90".into();
        let spec = parse(&form).unwrap();
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
            let err = parse(&form).err().expect(expected);
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
