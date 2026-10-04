/// What a ping reports, taken from the URL: `/p/{token}[/{signal}]`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Signal {
    Success,
    Start,
    Fail,
    Exit(u8),
}

/// How a ping changes the check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    Started,
    Succeeded,
    Failed,
}

impl Signal {
    /// `None` (no segment) is a plain success ping.
    pub fn parse(segment: Option<&str>) -> Option<Self> {
        match segment {
            None => Some(Self::Success),
            Some("start") => Some(Self::Start),
            Some("fail") => Some(Self::Fail),
            Some(code) if !code.is_empty() && code.bytes().all(|b| b.is_ascii_digit()) => {
                code.parse().ok().map(Self::Exit)
            }
            Some(_) => None,
        }
    }

    pub fn outcome(self) -> Outcome {
        match self {
            Self::Start => Outcome::Started,
            Self::Success | Self::Exit(0) => Outcome::Succeeded,
            Self::Fail | Self::Exit(_) => Outcome::Failed,
        }
    }

    /// The `pings.kind` column value.
    pub fn kind(self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::Start => "start",
            Self::Fail => "fail",
            Self::Exit(_) => "exit",
        }
    }

    pub fn exit_code(self) -> Option<i32> {
        match self {
            Self::Exit(code) => Some(code.into()),
            _ => None,
        }
    }
}

/// Decodes `bytes` (lossily) and keeps at most the last `max` bytes, cut on a
/// character boundary. Job output is kept from the end because that's where the
/// errors are.
pub fn tail_utf8(bytes: &[u8], max: usize) -> String {
    let text = String::from_utf8_lossy(bytes);
    if text.len() <= max {
        return text.into_owned();
    }
    let mut start = text.len() - max;
    while !text.is_char_boundary(start) {
        start += 1;
    }
    text[start..].to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_signals() {
        assert_eq!(Signal::parse(None), Some(Signal::Success));
        assert_eq!(Signal::parse(Some("start")), Some(Signal::Start));
        assert_eq!(Signal::parse(Some("fail")), Some(Signal::Fail));
        assert_eq!(Signal::parse(Some("0")), Some(Signal::Exit(0)));
        assert_eq!(Signal::parse(Some("255")), Some(Signal::Exit(255)));
        for bad in ["256", "-1", "+1", "", "foo", "1.5", "Start"] {
            assert_eq!(Signal::parse(Some(bad)), None, "{bad:?}");
        }
    }

    #[test]
    fn exit_codes_map_to_outcomes() {
        assert_eq!(Signal::Exit(0).outcome(), Outcome::Succeeded);
        assert_eq!(Signal::Exit(3).outcome(), Outcome::Failed);
        assert_eq!(Signal::Fail.outcome(), Outcome::Failed);
        assert_eq!(Signal::Start.outcome(), Outcome::Started);
    }

    #[test]
    fn tail_keeps_the_end_on_a_char_boundary() {
        assert_eq!(tail_utf8(b"short", 10), "short");
        assert_eq!(tail_utf8(b"0123456789abc", 4), "9abc");
        // "é" is 2 bytes; cutting 3 bytes from the end of "aéé" would split one.
        let tail = tail_utf8("aéé".as_bytes(), 3);
        assert_eq!(tail, "é");
        assert!(tail.len() <= 3);
        assert_eq!(tail_utf8(&[0xff, b'o', b'k'], 10), "\u{fffd}ok");
    }
}
