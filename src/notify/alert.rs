use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::domain::time::duration;

/// Bump when the shape changes; stored payloads keep their version and must stay
/// readable (see [`AlertWire`]).
const VERSION: u8 = 2;
const LOG_TAIL_LINES: usize = 30;
const LOG_TAIL_BYTES: usize = 2000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AlertEvent {
    /// Missed ping or hung run.
    Down,
    /// The job reported a failure.
    Fail,
    /// Recovered.
    Up,
}

impl AlertEvent {
    /// The `notifications.event` column value.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Down => "down",
            Self::Fail => "fail",
            Self::Up => "up",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SourceKind {
    /// A cron / heartbeat check.
    Check,
    /// An HTTP uptime monitor.
    Monitor,
}

/// What the alert is about.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Source {
    #[serde(rename = "type")]
    pub kind: SourceKind,
    pub id: Uuid,
    pub name: String,
    /// Link to it in the dashboard.
    pub url: String,
}

/// What every channel delivers, whatever its format. Stored in
/// `notifications.payload` as a snapshot, so later edits to the check don't change
/// what an alert said.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(from = "AlertWire")]
pub struct Alert {
    pub v: u8,
    pub event: AlertEvent,
    pub source: Source,
    /// Human-readable reason, e.g. "Missed ping".
    pub reason: Option<String>,
    pub detail: Option<String>,
    /// End of the job's output, for failures.
    pub log_tail: Option<String>,
    pub occurred_at: DateTime<Utc>,
    /// For recoveries: when the incident started.
    pub down_since: Option<DateTime<Utc>>,
}

/// Accepts both the current shape and v1 payloads (flat `check_id`, `check_name`,
/// `check_url`), which may still sit in the outbox awaiting a retry.
#[derive(Deserialize)]
struct AlertWire {
    v: u8,
    event: AlertEvent,
    source: Option<Source>,
    check_id: Option<Uuid>,
    check_name: Option<String>,
    check_url: Option<String>,
    reason: Option<String>,
    detail: Option<String>,
    log_tail: Option<String>,
    occurred_at: DateTime<Utc>,
    down_since: Option<DateTime<Utc>>,
}

impl From<AlertWire> for Alert {
    fn from(w: AlertWire) -> Self {
        let source = w.source.unwrap_or_else(|| Source {
            kind: SourceKind::Check,
            id: w.check_id.unwrap_or_default(),
            name: w.check_name.unwrap_or_default(),
            url: w.check_url.unwrap_or_default(),
        });
        Self {
            v: w.v,
            event: w.event,
            source,
            reason: w.reason,
            detail: w.detail,
            log_tail: w.log_tail,
            occurred_at: w.occurred_at,
            down_since: w.down_since,
        }
    }
}

impl Alert {
    pub fn for_check(event: AlertEvent, id: Uuid, name: &str, base_url: &str) -> Self {
        Self::new(event, SourceKind::Check, id, name, base_url)
    }

    pub fn for_monitor(event: AlertEvent, id: Uuid, name: &str, base_url: &str) -> Self {
        Self::new(event, SourceKind::Monitor, id, name, base_url)
    }

    fn new(event: AlertEvent, kind: SourceKind, id: Uuid, name: &str, base_url: &str) -> Self {
        let section = match kind {
            SourceKind::Check => "checks",
            SourceKind::Monitor => "monitors",
        };
        Self {
            v: VERSION,
            event,
            source: Source {
                kind,
                id,
                name: name.to_owned(),
                url: format!("{}/{section}/{id}", base_url.trim_end_matches('/')),
            },
            reason: None,
            detail: None,
            log_tail: None,
            occurred_at: Utc::now(),
            down_since: None,
        }
    }

    /// What "Send test" delivers.
    pub fn sample(base_url: &str) -> Self {
        let mut alert = Self::for_check(AlertEvent::Down, Uuid::nil(), "Test alert", base_url);
        alert.reason = Some("Test".into());
        alert.detail = Some("This is a test alert from Monitor. Your channel works.".into());
        alert
    }

    pub fn title(&self) -> String {
        match self.event {
            AlertEvent::Down => format!("🚨 {} is down", self.source.name),
            AlertEvent::Fail => format!("❌ {} failed", self.source.name),
            AlertEvent::Up => format!("✅ {} is back up", self.source.name),
        }
    }

    /// One-line summary under the title.
    pub fn summary(&self) -> Option<String> {
        if self.event == AlertEvent::Up {
            return self.down_since.map(|since| {
                let down_for = (self.occurred_at - since).num_milliseconds().max(0);
                format!("It was down for {}.", duration(down_for))
            });
        }
        match (&self.reason, &self.detail) {
            (Some(reason), Some(detail)) => Some(format!("{reason}: {detail}")),
            (Some(text), None) | (None, Some(text)) => Some(text.clone()),
            (None, None) => None,
        }
    }

    /// Plain-text rendering, shared by channels without rich formatting.
    pub fn text(&self) -> String {
        let mut out = self.title();
        if let Some(summary) = self.summary() {
            out.push_str("\n\n");
            out.push_str(&summary);
        }
        if let Some(log) = &self.log_tail {
            out.push_str("\n\nLast output:\n");
            out.push_str(log);
        }
        out.push_str("\n\n");
        out.push_str(&self.source.url);
        out
    }
}

/// The end of a job's output: at most the last 30 lines and 2000 bytes.
pub fn log_tail(body: &str) -> String {
    let body = body.trim_end();
    let from_lines = body
        .rmatch_indices('\n')
        .nth(LOG_TAIL_LINES - 1)
        .map_or(0, |(i, _)| i + 1);
    let mut from_bytes = body.len().saturating_sub(LOG_TAIL_BYTES);
    while !body.is_char_boundary(from_bytes) {
        from_bytes += 1;
    }
    body[from_lines.max(from_bytes)..].to_owned()
}

#[cfg(test)]
mod tests {
    use chrono::TimeDelta;

    use super::*;

    fn alert(event: AlertEvent) -> Alert {
        Alert::for_check(
            event,
            Uuid::nil(),
            "Daily Database Backup",
            "https://mon.example/",
        )
    }

    #[test]
    fn titles_and_links() {
        assert_eq!(
            alert(AlertEvent::Down).title(),
            "🚨 Daily Database Backup is down"
        );
        assert_eq!(
            alert(AlertEvent::Fail).title(),
            "❌ Daily Database Backup failed"
        );
        assert_eq!(
            alert(AlertEvent::Up).title(),
            "✅ Daily Database Backup is back up"
        );
        assert_eq!(
            alert(AlertEvent::Up).source.url,
            "https://mon.example/checks/00000000-0000-0000-0000-000000000000"
        );
    }

    #[test]
    fn text_includes_reason_and_log() {
        let mut a = alert(AlertEvent::Fail);
        a.reason = Some("Job failed".into());
        a.detail = Some("Job exited with code 3.".into());
        a.log_tail = Some("pg_dump: connection refused".into());
        let text = a.text();
        assert!(
            text.starts_with(
                "❌ Daily Database Backup failed\n\nJob failed: Job exited with code 3."
            )
        );
        assert!(text.contains("Last output:\npg_dump: connection refused"));
        assert!(text.ends_with(&a.source.url));
    }

    #[test]
    fn recovery_says_how_long_it_was_down() {
        let mut a = alert(AlertEvent::Up);
        a.down_since = Some(a.occurred_at - TimeDelta::minutes(12));
        assert_eq!(a.summary().unwrap(), "It was down for 12m 00s.");
    }

    #[test]
    fn monitors_link_to_the_uptime_pages() {
        let a = Alert::for_monitor(AlertEvent::Down, Uuid::nil(), "API", "https://mon.example");
        assert_eq!(a.source.kind, SourceKind::Monitor);
        assert!(a.source.url.starts_with("https://mon.example/monitors/"));
        assert_eq!(a.title(), "🚨 API is down");
    }

    #[test]
    fn reads_v1_payloads_still_in_the_outbox() {
        let v1 = serde_json::json!({
            "v": 1, "event": "down",
            "check_id": "00000000-0000-0000-0000-000000000000",
            "check_name": "Backup", "check_url": "https://m.example/checks/x",
            "reason": "Missed ping", "detail": null, "log_tail": null,
            "occurred_at": "2026-10-01T00:00:00Z", "down_since": null
        });
        let a: Alert = serde_json::from_value(v1).unwrap();
        assert_eq!(a.source.kind, SourceKind::Check);
        assert_eq!(a.source.name, "Backup");
        assert_eq!(a.source.url, "https://m.example/checks/x");
        assert_eq!(a.title(), "🚨 Backup is down");
    }

    #[test]
    fn payload_round_trips_as_json() {
        let a = alert(AlertEvent::Down);
        let json = serde_json::to_value(&a).unwrap();
        assert_eq!(json["event"], "down");
        assert_eq!(serde_json::from_value::<Alert>(json).unwrap(), a);
    }

    #[test]
    fn log_tail_limits_lines_and_bytes() {
        let many_lines: String = (1..=100).map(|i| format!("line {i}\n")).collect();
        let tail = log_tail(&many_lines);
        assert!(tail.starts_with("line 71\n"));
        assert!(tail.ends_with("line 100"));

        let long_line = "é".repeat(5000);
        let tail = log_tail(&long_line);
        assert!(tail.len() <= 2000);
        assert!(tail.chars().all(|c| c == 'é'));
    }
}
