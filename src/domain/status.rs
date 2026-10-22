//! Status-page arithmetic: daily uptime from outage intervals, and how a set of
//! components adds up to one verdict. UTC days throughout.

use chrono::{DateTime, Days, NaiveDate, TimeDelta, Utc};

/// Days of history a status page shows.
pub const DAYS: u32 = 90;

/// One outage (an incident), open-ended while ongoing.
#[derive(Debug, Clone, Copy)]
pub struct Outage {
    pub start: DateTime<Utc>,
    pub end: Option<DateTime<Utc>>,
}

/// How a day looks, from the status palette.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Level {
    /// Not monitored yet (or not yet that day).
    NoData,
    /// No downtime.
    Good,
    /// Under 1% down (about 14 minutes).
    Minor,
    /// Under 5% down (about 72 minutes).
    Partial,
    Major,
}

impl Level {
    pub fn css(self) -> &'static str {
        match self {
            Self::NoData => "day-none",
            Self::Good => "day-good",
            Self::Minor => "day-minor",
            Self::Partial => "day-partial",
            Self::Major => "day-major",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::NoData => "No data",
            Self::Good => "No downtime",
            Self::Minor => "Under 1% down",
            Self::Partial => "1–5% down",
            Self::Major => "Over 5% down",
        }
    }

    fn of(uptime: f64, downtime_secs: i64) -> Self {
        match uptime {
            _ if downtime_secs == 0 => Self::Good,
            u if u >= 0.99 => Self::Minor,
            u if u >= 0.95 => Self::Partial,
            _ => Self::Major,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Day {
    pub date: NaiveDate,
    /// Seconds of the day that were monitored (0 before monitoring began).
    pub observed_secs: i64,
    pub downtime_secs: i64,
    pub level: Level,
}

impl Day {
    pub fn uptime(&self) -> Option<f64> {
        (self.observed_secs > 0)
            .then(|| 1.0 - self.downtime_secs as f64 / self.observed_secs as f64)
    }
}

/// The last `days` UTC days up to and including today, oldest first. Time
/// before `since` (when monitoring began) counts as no data.
pub fn daily(
    outages: &[Outage],
    since: Option<DateTime<Utc>>,
    now: DateTime<Utc>,
    days: u32,
) -> Vec<Day> {
    let today = now.date_naive();
    let merged = merge(outages, now);
    (0..days)
        .rev()
        .filter_map(|back| today.checked_sub_days(Days::new(back.into())))
        .map(|date| {
            let day_start = date.and_hms_opt(0, 0, 0).unwrap().and_utc();
            let day_end = (day_start + TimeDelta::days(1)).min(now);
            let start = match since {
                Some(since) => day_start.max(since),
                None => day_end,
            };
            let observed_secs = (day_end - start).num_seconds().max(0);
            let downtime_secs = if observed_secs == 0 {
                0
            } else {
                merged
                    .iter()
                    .map(|&(s, e)| (e.min(day_end) - s.max(start)).num_seconds().max(0))
                    .sum()
            };
            let level = if observed_secs == 0 {
                Level::NoData
            } else {
                Level::of(
                    1.0 - downtime_secs as f64 / observed_secs as f64,
                    downtime_secs,
                )
            };
            Day {
                date,
                observed_secs,
                downtime_secs,
                level,
            }
        })
        .collect()
}

/// Uptime over all observed time in `days`, or `None` with nothing observed.
pub fn overall(days: &[Day]) -> Option<f64> {
    let observed: i64 = days.iter().map(|d| d.observed_secs).sum();
    let down: i64 = days.iter().map(|d| d.downtime_secs).sum();
    (observed > 0).then(|| 1.0 - down as f64 / observed as f64)
}

/// Sorted, non-overlapping intervals; ongoing outages end at `now`.
fn merge(outages: &[Outage], now: DateTime<Utc>) -> Vec<(DateTime<Utc>, DateTime<Utc>)> {
    let mut spans: Vec<_> = outages
        .iter()
        .map(|o| (o.start, o.end.unwrap_or(now).min(now)))
        .filter(|(s, e)| e > s)
        .collect();
    spans.sort();
    let mut merged: Vec<(DateTime<Utc>, DateTime<Utc>)> = Vec::new();
    for (s, e) in spans {
        match merged.last_mut() {
            Some(last) if s <= last.1 => last.1 = last.1.max(e),
            _ => merged.push((s, e)),
        }
    }
    merged
}

/// A component's state right now.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Current {
    Operational,
    Down,
    /// Paused, or not reporting yet: says nothing either way.
    Unknown,
}

/// What the whole page says.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    AllOperational,
    /// Some components are down.
    Partial,
    /// Everything that reports is down.
    Major,
    /// Nothing is reporting yet.
    NoData,
}

impl Verdict {
    pub fn of(components: &[Current]) -> Self {
        let known: Vec<_> = components
            .iter()
            .filter(|c| **c != Current::Unknown)
            .collect();
        let down = known.iter().filter(|c| ***c == Current::Down).count();
        match (known.len(), down) {
            (0, _) => Self::NoData,
            (_, 0) => Self::AllOperational,
            (n, d) if d == n => Self::Major,
            _ => Self::Partial,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::AllOperational => "All systems operational",
            Self::Partial => "Partial outage",
            Self::Major => "Major outage",
            Self::NoData => "No data yet",
        }
    }

    /// The `status.json` value.
    pub fn id(self) -> &'static str {
        match self {
            Self::AllOperational => "operational",
            Self::Partial => "partial_outage",
            Self::Major => "major_outage",
            Self::NoData => "unknown",
        }
    }
}

#[cfg(test)]
mod tests {
    use chrono::TimeZone;

    use super::*;

    fn at(d: u32, h: u32, m: u32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 10, d, h, m, 0).unwrap()
    }

    #[test]
    fn days_split_outages_at_midnight() {
        let now = at(20, 12, 0);
        // 23:30 on the 18th to 00:30 on the 19th: 30 minutes on each day.
        let outages = [Outage {
            start: at(18, 23, 30),
            end: Some(at(19, 0, 30)),
        }];
        let days = daily(&outages, Some(at(1, 0, 0)), now, 3);
        assert_eq!(
            days.iter().map(|d| d.date.to_string()).collect::<Vec<_>>(),
            ["2026-10-18", "2026-10-19", "2026-10-20"]
        );
        assert_eq!(days[0].downtime_secs, 1800);
        assert_eq!(days[1].downtime_secs, 1800);
        assert_eq!(days[0].level, Level::Partial); // 2.1% down
        assert_eq!(days[2].level, Level::Good);
        // Today is only observed up to now.
        assert_eq!(days[2].observed_secs, 12 * 3600);
    }

    #[test]
    fn levels_follow_the_downtime_share() {
        let now = at(20, 0, 0);
        let day = |mins: i64| {
            let o = [Outage {
                start: at(19, 1, 0),
                end: Some(at(19, 1, 0) + TimeDelta::minutes(mins)),
            }];
            daily(&o, Some(at(1, 0, 0)), now, 2)[0].level
        };
        assert_eq!(day(0), Level::Good);
        assert_eq!(day(10), Level::Minor);
        assert_eq!(day(60), Level::Partial);
        assert_eq!(day(180), Level::Major);
    }

    #[test]
    fn before_monitoring_began_is_no_data() {
        let now = at(20, 12, 0);
        let days = daily(&[], Some(at(19, 18, 0)), now, 3);
        assert_eq!(days[0].level, Level::NoData);
        assert_eq!(days[1].observed_secs, 6 * 3600);
        assert_eq!(days[1].level, Level::Good);
        assert!(
            daily(&[], None, now, 3)
                .iter()
                .all(|d| d.level == Level::NoData)
        );
        assert_eq!(overall(&daily(&[], None, now, 3)), None);
    }

    #[test]
    fn ongoing_and_overlapping_outages_count_once() {
        let now = at(20, 12, 0);
        let outages = [
            Outage {
                start: at(20, 10, 0),
                end: None,
            },
            Outage {
                start: at(20, 11, 0),
                end: Some(at(20, 11, 30)),
            },
        ];
        let days = daily(&outages, Some(at(20, 0, 0)), now, 1);
        assert_eq!(days[0].downtime_secs, 2 * 3600);
        let up = overall(&days).unwrap();
        assert!((up - 10.0 / 12.0).abs() < 1e-9);
    }

    #[test]
    fn verdicts() {
        use Current::*;
        assert_eq!(
            Verdict::of(&[Operational, Unknown]),
            Verdict::AllOperational
        );
        assert_eq!(Verdict::of(&[Operational, Down]), Verdict::Partial);
        assert_eq!(Verdict::of(&[Down, Unknown]), Verdict::Major);
        assert_eq!(Verdict::of(&[Unknown]), Verdict::NoData);
        assert_eq!(Verdict::of(&[]), Verdict::NoData);
    }
}
