//! Pure rules for HTTP monitors: what counts as a passing check, when a monitor
//! goes down or comes back, and which request settings are allowed.

use axum::http::{HeaderName, HeaderValue};

/// Intervals offered in the form, in seconds.
pub const INTERVALS: [(i32, &str); 6] = [
    (30, "30 seconds"),
    (60, "1 minute"),
    (300, "5 minutes"),
    (900, "15 minutes"),
    (1800, "30 minutes"),
    (3600, "1 hour"),
];
pub const METHODS: [&str; 7] = ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"];
pub const MAX_TIMEOUT_SECS: i32 = 30;
pub const MAX_THRESHOLD: i16 = 10;
/// How much of a response body is read to look for `body_contains`.
pub const MAX_BODY_BYTES: usize = 1024 * 1024;

/// What a monitor expects of a response.
pub struct Expectations<'a> {
    /// Exact status; `None` means any 2xx or 3xx.
    pub status: Option<u16>,
    pub body_contains: Option<&'a str>,
    pub max_latency_ms: Option<i32>,
}

/// What happened when we made the request.
pub enum Response<'a> {
    Received {
        status: u16,
        latency_ms: i32,
        /// Only read when the monitor looks for text in it.
        body: Option<&'a str>,
    },
    TimedOut {
        after_ms: i32,
    },
    /// DNS, connection refused, TLS, blocked address…
    Failed {
        error: String,
        latency_ms: i32,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outcome {
    pub ok: bool,
    /// Failed only on the latency limit (everything else was fine).
    pub slow: bool,
    pub status_code: Option<u16>,
    pub latency_ms: i32,
    pub error: Option<String>,
}

pub fn evaluate(response: &Response<'_>, expect: &Expectations<'_>) -> Outcome {
    match response {
        Response::TimedOut { after_ms } => Outcome {
            ok: false,
            slow: false,
            status_code: None,
            latency_ms: *after_ms,
            error: Some(format!("Timed out after {} s", after_ms / 1000)),
        },
        Response::Failed { error, latency_ms } => Outcome {
            ok: false,
            slow: false,
            status_code: None,
            latency_ms: *latency_ms,
            error: Some(error.clone()),
        },
        Response::Received {
            status,
            latency_ms,
            body,
        } => {
            let status_ok = match expect.status {
                Some(expected) => *status == expected,
                None => (200..400).contains(status),
            };
            let error = if !status_ok {
                Some(match expect.status {
                    Some(expected) => format!("HTTP {status} (expected {expected})"),
                    None => format!("HTTP {status}"),
                })
            } else if let Some(needle) = expect.body_contains
                && !body.is_some_and(|b| b.contains(needle))
            {
                Some(format!("Response didn't contain \"{needle}\""))
            } else {
                None
            };
            let too_slow = expect.max_latency_ms.is_some_and(|max| *latency_ms > max);
            let error = error.or_else(|| {
                too_slow.then(|| {
                    format!(
                        "Took {latency_ms} ms (limit {} ms)",
                        expect.max_latency_ms.unwrap_or_default()
                    )
                })
            });
            Outcome {
                ok: error.is_none(),
                slow: error.is_some() && too_slow && status_ok,
                status_code: Some(*status),
                latency_ms: *latency_ms,
                error,
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MonitorStatus {
    New,
    Up,
    Down,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Event {
    None,
    /// Reached the failure threshold: open an incident and alert.
    Down,
    /// First success after being down: resolve and send a recovery.
    Up,
}

/// Applies one result. Returns the new status, the new consecutive-failure count
/// and what (if anything) to announce.
pub fn transition(
    status: MonitorStatus,
    failures: i32,
    ok: bool,
    threshold: i16,
) -> (MonitorStatus, i32, Event) {
    if ok {
        let event = if status == MonitorStatus::Down {
            Event::Up
        } else {
            Event::None
        };
        return (MonitorStatus::Up, 0, event);
    }
    let failures = failures.saturating_add(1);
    if status != MonitorStatus::Down && failures >= threshold.into() {
        (MonitorStatus::Down, failures, Event::Down)
    } else {
        (status, failures, Event::None)
    }
}

/// Request headers from a textarea: one `Name: value` per line, blank lines ignored.
pub fn parse_headers(text: &str) -> Result<Vec<(String, String)>, String> {
    const FORBIDDEN: [&str; 6] = [
        "host",
        "content-length",
        "transfer-encoding",
        "connection",
        "upgrade",
        "te",
    ];
    let mut headers = Vec::new();
    for line in text.lines().map(str::trim).filter(|l| !l.is_empty()) {
        let Some((name, value)) = line.split_once(':') else {
            return Err(format!("Header \"{line}\" should look like Name: value."));
        };
        let (name, value) = (name.trim(), value.trim());
        let parsed = HeaderName::from_bytes(name.as_bytes())
            .map_err(|_| format!("\"{name}\" isn't a valid header name."))?;
        if FORBIDDEN.contains(&parsed.as_str()) {
            return Err(format!("The {name} header is set automatically."));
        }
        HeaderValue::from_str(value).map_err(|_| format!("The value of {name} isn't valid."))?;
        headers.push((name.to_owned(), value.to_owned()));
    }
    if headers.len() > 20 {
        return Err("At most 20 headers.".into());
    }
    Ok(headers)
}

/// Headers back to textarea form.
pub fn format_headers(headers: &[(String, String)]) -> String {
    headers
        .iter()
        .map(|(name, value)| format!("{name}: {value}"))
        .collect::<Vec<_>>()
        .join("\n")
}

/// Random first-run offset within one interval, so monitors created together
/// don't all fire on the same second.
pub fn jitter_secs(interval_secs: i32) -> i32 {
    rand::random_range(0..interval_secs.max(1))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn any() -> Expectations<'static> {
        Expectations {
            status: None,
            body_contains: None,
            max_latency_ms: None,
        }
    }

    fn got(status: u16, latency_ms: i32, body: Option<&str>) -> Response<'_> {
        Response::Received {
            status,
            latency_ms,
            body,
        }
    }

    #[test]
    fn status_rules() {
        assert!(evaluate(&got(200, 50, None), &any()).ok);
        assert!(
            evaluate(&got(301, 50, None), &any()).ok,
            "redirects aren't followed but count as up"
        );
        let down = evaluate(&got(503, 50, None), &any());
        assert_eq!(down.error.as_deref(), Some("HTTP 503"));
        assert_eq!(down.status_code, Some(503));

        let expect_204 = Expectations {
            status: Some(204),
            ..any()
        };
        assert!(evaluate(&got(204, 50, None), &expect_204).ok);
        assert_eq!(
            evaluate(&got(200, 50, None), &expect_204).error.as_deref(),
            Some("HTTP 200 (expected 204)")
        );
        // An expected 404 (e.g. "this must stay gone") is fine too.
        let expect_404 = Expectations {
            status: Some(404),
            ..any()
        };
        assert!(evaluate(&got(404, 50, None), &expect_404).ok);
    }

    #[test]
    fn body_must_contain_text() {
        let expect = Expectations {
            body_contains: Some("\"status\":\"ok\""),
            ..any()
        };
        assert!(evaluate(&got(200, 5, Some(r#"{"status":"ok"}"#)), &expect).ok);
        let bad = evaluate(&got(200, 5, Some(r#"{"status":"degraded"}"#)), &expect);
        assert_eq!(
            bad.error.as_deref(),
            Some(r#"Response didn't contain ""status":"ok"""#)
        );
        assert!(!evaluate(&got(200, 5, None), &expect).ok);
    }

    #[test]
    fn latency_limit() {
        let expect = Expectations {
            max_latency_ms: Some(2000),
            ..any()
        };
        assert!(evaluate(&got(200, 2000, None), &expect).ok);
        let slow = evaluate(&got(200, 2310, None), &expect);
        assert!(!slow.ok && slow.slow);
        assert_eq!(slow.error.as_deref(), Some("Took 2310 ms (limit 2000 ms)"));
        // A slow 500 is a 500 first.
        let both = evaluate(&got(500, 2310, None), &expect);
        assert_eq!(both.error.as_deref(), Some("HTTP 500"));
        assert!(!both.slow);
    }

    #[test]
    fn transport_failures() {
        let t = evaluate(&Response::TimedOut { after_ms: 10_000 }, &any());
        assert_eq!(
            (t.ok, t.error.as_deref()),
            (false, Some("Timed out after 10 s"))
        );
        let f = evaluate(
            &Response::Failed {
                error: "connection refused".into(),
                latency_ms: 3,
            },
            &any(),
        );
        assert_eq!(f.error.as_deref(), Some("connection refused"));
        assert_eq!(f.status_code, None);
    }

    #[test]
    fn goes_down_only_at_the_threshold() {
        use MonitorStatus::*;
        assert_eq!(transition(Up, 0, false, 3), (Up, 1, Event::None));
        assert_eq!(transition(Up, 1, false, 3), (Up, 2, Event::None));
        assert_eq!(transition(Up, 2, false, 3), (Down, 3, Event::Down));
        assert_eq!(
            transition(Down, 3, false, 3),
            (Down, 4, Event::None),
            "announce once"
        );
        assert_eq!(transition(Down, 4, true, 3), (Up, 0, Event::Up));
        // Threshold 1: the first failure alerts.
        assert_eq!(transition(Up, 0, false, 1), (Down, 1, Event::Down));
        // A blip below the threshold resets.
        assert_eq!(transition(Up, 2, true, 3), (Up, 0, Event::None));
    }

    #[test]
    fn new_monitors() {
        use MonitorStatus::*;
        assert_eq!(transition(New, 0, true, 2), (Up, 0, Event::None));
        assert_eq!(transition(New, 0, false, 2), (New, 1, Event::None));
        assert_eq!(
            transition(New, 1, false, 2),
            (Down, 2, Event::Down),
            "broken from the start"
        );
    }

    #[test]
    fn headers() {
        let parsed = parse_headers("Authorization: Bearer abc\n\n  X-Env:  prod  \n").unwrap();
        assert_eq!(
            parsed,
            vec![
                ("Authorization".into(), "Bearer abc".into()),
                ("X-Env".into(), "prod".into())
            ]
        );
        assert_eq!(
            format_headers(&parsed),
            "Authorization: Bearer abc\nX-Env: prod"
        );
        assert!(parse_headers("no colon here").is_err());
        assert!(parse_headers("Bad Name: x").is_err());
        assert!(parse_headers("Host: evil.example").is_err());
        assert!(parse_headers("X-Line: a\u{7}b").is_err());
        assert!(parse_headers("").unwrap().is_empty());
    }

    #[test]
    fn jitter_stays_within_the_interval() {
        for _ in 0..200 {
            let j = jitter_secs(30);
            assert!((0..30).contains(&j));
        }
    }
}
