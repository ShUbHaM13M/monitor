use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::domain::time::duration;

/// Bump when the shape changes; stored payloads keep their version.
const VERSION: u8 = 1;
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

/// What every channel delivers, whatever its format. Stored in
/// `notifications.payload` as a snapshot, so later edits to the check don't change
/// what an alert said.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Alert {
    pub v: u8,
    pub event: AlertEvent,
    pub check_id: Uuid,
    pub check_name: String,
    /// Link to the check in the dashboard.
    pub check_url: String,
    /// Human-readable reason, e.g. "Missed ping".
    pub reason: Option<String>,
    pub detail: Option<String>,
    /// End of the job's output, for failures.
    pub log_tail: Option<String>,
    pub occurred_at: DateTime<Utc>,
    /// For recoveries: when the incident started.
    pub down_since: Option<DateTime<Utc>>,
}

impl Alert {
    pub fn new(event: AlertEvent, check_id: Uuid, check_name: &str, base_url: &str) -> Self {
        Self {
            v: VERSION,
            event,
            check_id,
            check_name: check_name.to_owned(),
            check_url: format!("{}/checks/{check_id}", base_url.trim_end_matches('/')),
            reason: None,
            detail: None,
            log_tail: None,
            occurred_at: Utc::now(),
            down_since: None,
        }
    }

    /// What "Send test" delivers.
    pub fn sample(base_url: &str) -> Self {
        let mut alert = Self::new(AlertEvent::Down, Uuid::nil(), "Test alert", base_url);
        alert.reason = Some("Test".into());
        alert.detail = Some("This is a test alert from Monitor. Your channel works.".into());
        alert
    }

    pub fn title(&self) -> String {
        match self.event {
            AlertEvent::Down => format!("🚨 {} is down", self.check_name),
            AlertEvent::Fail => format!("❌ {} failed", self.check_name),
            AlertEvent::Up => format!("✅ {} is back up", self.check_name),
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
        out.push_str(&self.check_url);
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
        Alert::new(
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
            alert(AlertEvent::Up).check_url,
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
        assert!(text.ends_with(&a.check_url));
    }

    #[test]
    fn recovery_says_how_long_it_was_down() {
        let mut a = alert(AlertEvent::Up);
        a.down_since = Some(a.occurred_at - TimeDelta::minutes(12));
        assert_eq!(a.summary().unwrap(), "It was down for 12m 00s.");
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
