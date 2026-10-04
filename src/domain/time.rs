use chrono::{DateTime, Utc};

/// "3m ago", "in 2h", "just now".
pub fn relative(t: DateTime<Utc>, now: DateTime<Utc>) -> String {
    let secs = (t - now).num_seconds();
    if secs.abs() < 5 {
        return "just now".into();
    }
    let amount = compact(secs.abs());
    if secs < 0 {
        format!("{amount} ago")
    } else {
        format!("in {amount}")
    }
}

/// Largest whole unit: "45s", "12m", "3h", "2d".
fn compact(secs: i64) -> String {
    match secs {
        s if s < 60 => format!("{s}s"),
        s if s < 3600 => format!("{}m", s / 60),
        s if s < 86_400 => format!("{}h", s / 3600),
        s => format!("{}d", s / 86_400),
    }
}

/// Run duration: "850ms", "42s", "1m 05s", "2h 03m".
pub fn duration(ms: i64) -> String {
    let secs = ms / 1000;
    match ms {
        ms if ms < 1000 => format!("{ms}ms"),
        _ if secs < 60 => format!("{secs}s"),
        _ if secs < 3600 => format!("{}m {:02}s", secs / 60, secs % 60),
        _ => format!("{}h {:02}m", secs / 3600, (secs % 3600) / 60),
    }
}

/// An exact span in the largest unit that divides it: "1 hour", "90 minutes", "2 days".
pub fn span(secs: i64) -> String {
    let (n, unit) = if secs % 86_400 == 0 {
        (secs / 86_400, "day")
    } else if secs % 3600 == 0 {
        (secs / 3600, "hour")
    } else if secs % 60 == 0 {
        (secs / 60, "minute")
    } else {
        (secs, "second")
    };
    if n == 1 {
        format!("1 {unit}")
    } else {
        format!("{n} {unit}s")
    }
}

#[cfg(test)]
mod tests {
    use chrono::TimeDelta;

    use super::*;

    #[test]
    fn relative_times() {
        let now = Utc::now();
        assert_eq!(relative(now, now), "just now");
        assert_eq!(relative(now - TimeDelta::seconds(42), now), "42s ago");
        assert_eq!(relative(now - TimeDelta::minutes(3), now), "3m ago");
        assert_eq!(relative(now + TimeDelta::hours(2), now), "in 2h");
        assert_eq!(relative(now - TimeDelta::days(9), now), "9d ago");
    }

    #[test]
    fn durations() {
        assert_eq!(duration(850), "850ms");
        assert_eq!(duration(42_000), "42s");
        assert_eq!(duration(65_000), "1m 05s");
        assert_eq!(duration(7_380_000), "2h 03m");
    }

    #[test]
    fn spans() {
        assert_eq!(span(60), "1 minute");
        assert_eq!(span(5400), "90 minutes");
        assert_eq!(span(3600), "1 hour");
        assert_eq!(span(172_800), "2 days");
        assert_eq!(span(0), "0 days");
    }
}
