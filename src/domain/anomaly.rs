//! Spotting runs that took far longer, or far less time, than usual.
//!
//! The baseline is the median of a check's recent successful run durations
//! (from `/start` to success). Medians shrug off the odd outlier, and the
//! extra conditions below keep jittery or very short jobs quiet: a run is only
//! flagged when it's well outside the usual *and* beyond anything seen recently.

/// How many recent runs make the baseline.
pub const HISTORY: i64 = 20;
/// Too few runs to know what's usual: say nothing.
pub const MIN_SAMPLES: usize = 8;
/// "Slow" means at least this many times the median…
const SLOW_FACTOR: i64 = 2;
/// …and at least this much longer, so a 2 s job taking 5 s doesn't page anyone.
const SLOW_MIN_EXTRA_MS: i64 = 60_000;
/// "Fast" means at most 1/FAST_DIVISOR of the median…
const FAST_DIVISOR: i64 = 5;
/// …of a job that usually takes at least this long (a backup that "finished" in
/// 3 s instead of 10 min probably did nothing).
const FAST_MIN_MEDIAN_MS: i64 = 60_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Anomaly {
    Slow { median_ms: i64 },
    Fast { median_ms: i64 },
}

impl Anomaly {
    /// The `incidents.reason` value.
    pub fn reason(self) -> &'static str {
        match self {
            Self::Slow { .. } => "slow_run",
            Self::Fast { .. } => "fast_run",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Slow { .. } => "Ran unusually long",
            Self::Fast { .. } => "Finished unusually fast",
        }
    }

    pub fn median_ms(self) -> i64 {
        match self {
            Self::Slow { median_ms } | Self::Fast { median_ms } => median_ms,
        }
    }
}

/// Judges `current_ms` against `history` (recent successful durations, any order).
pub fn judge(history: &[i64], current_ms: i64) -> Option<Anomaly> {
    if history.len() < MIN_SAMPLES {
        return None;
    }
    let median_ms = median(history)?;
    let longest = *history.iter().max()?;
    let shortest = *history.iter().min()?;
    if current_ms >= SLOW_FACTOR * median_ms
        && current_ms - median_ms >= SLOW_MIN_EXTRA_MS
        && current_ms > longest
    {
        return Some(Anomaly::Slow { median_ms });
    }
    if median_ms >= FAST_MIN_MEDIAN_MS
        && current_ms * FAST_DIVISOR <= median_ms
        && current_ms < shortest
    {
        return Some(Anomaly::Fast { median_ms });
    }
    None
}

pub fn median(values: &[i64]) -> Option<i64> {
    if values.is_empty() {
        return None;
    }
    let mut sorted = values.to_vec();
    sorted.sort_unstable();
    let mid = sorted.len() / 2;
    Some(if sorted.len().is_multiple_of(2) {
        (sorted[mid - 1] + sorted[mid]) / 2
    } else {
        sorted[mid]
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const MIN: i64 = 60_000;

    fn around(minutes: i64) -> Vec<i64> {
        // Nine runs of `minutes` ± up to 12 s; the median is exactly `minutes`.
        (0..9).map(|i| minutes * MIN + (i - 4) * 3_000).collect()
    }

    #[test]
    fn needs_enough_history() {
        let few: Vec<i64> = around(10).into_iter().take(MIN_SAMPLES - 1).collect();
        assert_eq!(judge(&few, 60 * MIN), None);
    }

    #[test]
    fn flags_runs_far_longer_than_usual() {
        let history = around(10);
        assert_eq!(
            judge(&history, 25 * MIN),
            Some(Anomaly::Slow {
                median_ms: 10 * MIN
            })
        );
        // Longer, but not twice as long.
        assert_eq!(judge(&history, 18 * MIN), None);
    }

    #[test]
    fn short_jobs_need_a_real_difference() {
        // A 5 s job taking 30 s is 6× but only 25 s longer.
        let history: Vec<i64> = (0..10).map(|i| 5_000 + i * 100).collect();
        assert_eq!(judge(&history, 30_000), None);
        assert!(matches!(
            judge(&history, 5 * MIN),
            Some(Anomaly::Slow { .. })
        ));
    }

    #[test]
    fn not_slower_than_a_recent_outlier() {
        // One earlier run already took 30 minutes; 25 isn't news.
        let mut history = around(10);
        history[3] = 30 * MIN;
        assert_eq!(judge(&history, 25 * MIN), None);
    }

    #[test]
    fn flags_runs_that_finish_suspiciously_fast() {
        let history = around(10);
        assert_eq!(
            judge(&history, 20_000),
            Some(Anomaly::Fast {
                median_ms: 10 * MIN
            })
        );
        assert_eq!(judge(&history, 3 * MIN), None, "a third of usual is fine");
        // Jobs that are quick anyway are never "too fast".
        let quick: Vec<i64> = (0..10).map(|i| 20_000 + i * 100).collect();
        assert_eq!(judge(&quick, 1_000), None);
    }

    #[test]
    fn medians() {
        assert_eq!(median(&[3, 1, 2]), Some(2));
        assert_eq!(median(&[4, 1, 3, 2]), Some(2));
        assert_eq!(median(&[]), None);
    }
}
