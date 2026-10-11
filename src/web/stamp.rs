use std::fmt;

use chrono::{DateTime, SecondsFormat, Utc};

use crate::domain::time::relative;

/// A timestamp rendered as `<time>`: "3m ago" with the exact time on hover.
/// `static/app.js` rewrites the exact time into the viewer's timezone, so the
/// server never needs to know it. Render with `{{ stamp|safe }}`.
pub struct Stamp(String);

impl Stamp {
    /// "3m ago" / "in 2h".
    pub fn relative(at: DateTime<Utc>, now: DateTime<Utc>) -> Self {
        Self::time(at, &relative(at, now), false)
    }

    /// The date and time itself.
    pub fn absolute(at: DateTime<Utc>) -> Self {
        Self::time(at, &utc(at), true)
    }

    /// Plain text where there's no time to show ("never", "running").
    pub fn text(text: &'static str) -> Self {
        Self(text.to_owned())
    }

    pub fn relative_or(
        at: Option<DateTime<Utc>>,
        now: DateTime<Utc>,
        missing: &'static str,
    ) -> Self {
        at.map_or_else(|| Self::text(missing), |t| Self::relative(t, now))
    }

    // `text` is always generated here or a `&'static str`, never user input,
    // so it needs no escaping.
    fn time(at: DateTime<Utc>, text: &str, absolute: bool) -> Self {
        Self(format!(
            r#"<time datetime="{}" title="{}"{}>{text}</time>"#,
            at.to_rfc3339_opts(SecondsFormat::Secs, true),
            utc(at),
            if absolute { " data-absolute" } else { "" },
        ))
    }
}

impl fmt::Display for Stamp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

pub fn utc(t: DateTime<Utc>) -> String {
    t.format("%Y-%m-%d %H:%M:%S UTC").to_string()
}

#[cfg(test)]
mod tests {
    use chrono::{TimeDelta, TimeZone};

    use super::*;

    #[test]
    fn renders_time_elements() {
        let at = Utc.with_ymd_and_hms(2026, 10, 11, 6, 37, 17).unwrap();
        assert_eq!(
            Stamp::relative(at, at + TimeDelta::minutes(3)).to_string(),
            r#"<time datetime="2026-10-11T06:37:17Z" title="2026-10-11 06:37:17 UTC">3m ago</time>"#
        );
        assert_eq!(
            Stamp::absolute(at).to_string(),
            r#"<time datetime="2026-10-11T06:37:17Z" title="2026-10-11 06:37:17 UTC" data-absolute>2026-10-11 06:37:17 UTC</time>"#
        );
        assert_eq!(Stamp::relative_or(None, at, "never").to_string(), "never");
    }
}
