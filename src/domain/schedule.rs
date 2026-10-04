use std::fmt;
use std::str::FromStr;

use chrono::{DateTime, TimeDelta, Utc};
use chrono_tz::Tz;
use croner::Cron;
use croner::parser::{CronParser, Seconds, Year};

pub const MIN_PERIOD_SECS: i64 = 60;
pub const MAX_PERIOD_SECS: i64 = 365 * 24 * 60 * 60;

/// When a check is expected to ping.
#[derive(Debug, Clone)]
pub enum Schedule {
    /// Every `secs` seconds, measured from the last ping.
    Period { secs: i64 },
    /// At the times matched by a 5-field cron expression, evaluated in `tz`.
    Cron {
        expr: String,
        cron: Box<Cron>,
        tz: Tz,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ScheduleError {
    #[error("Period must be between 1 minute and 365 days.")]
    PeriodOutOfRange,
    #[error("Invalid cron expression: {0}")]
    InvalidCron(String),
    #[error("This cron expression never runs.")]
    CronNeverRuns,
    #[error("Unknown timezone \"{0}\".")]
    UnknownTimezone(String),
    #[error("Stored schedule is inconsistent.")]
    Corrupt,
}

impl Schedule {
    pub fn period(secs: i64) -> Result<Self, ScheduleError> {
        if (MIN_PERIOD_SECS..=MAX_PERIOD_SECS).contains(&secs) {
            Ok(Self::Period { secs })
        } else {
            Err(ScheduleError::PeriodOutOfRange)
        }
    }

    /// Accepts classic 5-field expressions (minute hour day-of-month month
    /// day-of-week) and `@daily`-style nicknames; seconds and years are rejected.
    /// Day-of-month and day-of-week are OR-ed, as in Vixie cron.
    pub fn cron(expr: &str, tz: &str) -> Result<Self, ScheduleError> {
        let expr = expr.split_whitespace().collect::<Vec<_>>().join(" ");
        let tz = Tz::from_str(tz.trim())
            .map_err(|_| ScheduleError::UnknownTimezone(tz.trim().to_owned()))?;
        let cron = CronParser::builder()
            .seconds(Seconds::Disallowed)
            .year(Year::Disallowed)
            .build()
            .parse(&expr)
            .map_err(|err| ScheduleError::InvalidCron(err.to_string()))?;
        let schedule = Self::Cron {
            expr,
            cron: Box::new(cron),
            tz,
        };
        if schedule.next_after(Utc::now()).is_none() {
            return Err(ScheduleError::CronNeverRuns);
        }
        Ok(schedule)
    }

    /// Rebuilds a schedule from the `checks` columns.
    pub fn from_db(
        kind: &str,
        cron_expr: Option<&str>,
        tz: Option<&str>,
        period_secs: Option<i32>,
    ) -> Result<Self, ScheduleError> {
        match (kind, cron_expr, tz, period_secs) {
            ("cron", Some(expr), Some(tz), _) => Self::cron(expr, tz),
            ("period", _, _, Some(secs)) => Self::period(secs.into()),
            _ => Err(ScheduleError::Corrupt),
        }
    }

    pub fn kind(&self) -> &'static str {
        match self {
            Self::Period { .. } => "period",
            Self::Cron { .. } => "cron",
        }
    }

    /// The first expected ping strictly after `t`.
    pub fn next_after(&self, t: DateTime<Utc>) -> Option<DateTime<Utc>> {
        match self {
            Self::Period { secs } => t.checked_add_signed(TimeDelta::seconds(*secs)),
            Self::Cron { cron, tz, .. } => cron
                .find_next_occurrence(&t.with_timezone(tz), false)
                .ok()
                .map(|next| next.with_timezone(&Utc)),
        }
    }

    /// The next `n` expected pings after `t`, for previews.
    pub fn upcoming(&self, t: DateTime<Utc>, n: usize) -> Vec<DateTime<Utc>> {
        std::iter::successors(self.next_after(t), |prev| self.next_after(*prev))
            .take(n)
            .collect()
    }
}

impl fmt::Display for Schedule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Period { secs } => write!(f, "every {}", super::time::span(*secs)),
            Self::Cron { expr, tz, .. } => write!(f, "{expr} ({tz})"),
        }
    }
}

#[cfg(test)]
mod tests {
    use chrono::TimeZone;

    use super::*;

    fn utc(s: &str) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339(s).unwrap().with_timezone(&Utc)
    }

    #[test]
    fn period_adds_seconds() {
        let s = Schedule::period(3600).unwrap();
        assert_eq!(
            s.next_after(utc("2026-10-03T10:15:00Z")),
            Some(utc("2026-10-03T11:15:00Z"))
        );
        assert_eq!(s.to_string(), "every 1 hour");
    }

    #[test]
    fn period_bounds() {
        assert_eq!(
            Schedule::period(59).unwrap_err(),
            ScheduleError::PeriodOutOfRange
        );
        assert!(Schedule::period(60).is_ok());
        assert!(Schedule::period(MAX_PERIOD_SECS + 1).is_err());
    }

    #[test]
    fn cron_is_evaluated_in_its_timezone() {
        // 02:00 in Kolkata (UTC+5:30) is 20:30 UTC the previous day.
        let s = Schedule::cron("0 2 * * *", "Asia/Kolkata").unwrap();
        assert_eq!(
            s.next_after(utc("2026-10-03T10:00:00Z")),
            Some(utc("2026-10-03T20:30:00Z"))
        );
        // A ping a few minutes after the run expects the next day's run.
        assert_eq!(
            s.next_after(utc("2026-10-03T20:32:00Z")),
            Some(utc("2026-10-04T20:30:00Z"))
        );
        assert_eq!(s.to_string(), "0 2 * * * (Asia/Kolkata)");
    }

    #[test]
    fn cron_dst_spring_forward_runs_after_the_gap() {
        // 2026-03-08: New York clocks jump from 02:00 to 03:00.
        let s = Schedule::cron("30 2 * * *", "America/New_York").unwrap();
        let ny = chrono_tz::America::New_York;
        let next = s.next_after(utc("2026-03-08T05:00:00Z")).unwrap();
        assert_eq!(
            next.with_timezone(&ny).date_naive().to_string(),
            "2026-03-08"
        );
        assert_eq!(
            next,
            ny.with_ymd_and_hms(2026, 3, 8, 3, 0, 0)
                .unwrap()
                .with_timezone(&Utc)
        );
    }

    #[test]
    fn cron_dst_fall_back_runs_once() {
        // 2026-11-01: New York repeats 01:00–02:00.
        let s = Schedule::cron("30 1 * * *", "America/New_York").unwrap();
        let runs = s.upcoming(utc("2026-11-01T04:00:00Z"), 2);
        assert_eq!(runs[0], utc("2026-11-01T05:30:00Z")); // 01:30 EDT
        assert_eq!(runs[1], utc("2026-11-02T06:30:00Z")); // next day, 01:30 EST
    }

    #[test]
    fn cron_rejects_bad_input() {
        assert!(matches!(
            Schedule::cron("not a cron", "UTC"),
            Err(ScheduleError::InvalidCron(_))
        ));
        assert!(matches!(
            Schedule::cron("0 0 2 * * *", "UTC"),
            Err(ScheduleError::InvalidCron(_))
        ));
        assert!(matches!(
            Schedule::cron("0 2 * * *", "Mars/Olympus"),
            Err(ScheduleError::UnknownTimezone(_))
        ));
        assert!(matches!(
            Schedule::cron("0 0 30 2 *", "UTC"),
            Err(ScheduleError::CronNeverRuns | ScheduleError::InvalidCron(_))
        ));
    }

    #[test]
    fn cron_accepts_nicknames_and_normalises_spaces() {
        assert!(Schedule::cron("@daily", "UTC").is_ok());
        let s = Schedule::cron("  */15   *  * * * ", "UTC").unwrap();
        assert_eq!(s.to_string(), "*/15 * * * * (UTC)");
    }

    #[test]
    fn from_db_round_trip() {
        assert!(matches!(
            Schedule::from_db("period", None, None, Some(300)),
            Ok(Schedule::Period { secs: 300 })
        ));
        assert!(Schedule::from_db("cron", Some("0 2 * * *"), Some("UTC"), None).is_ok());
        assert_eq!(
            Schedule::from_db("cron", None, None, None).unwrap_err(),
            ScheduleError::Corrupt
        );
    }
}
