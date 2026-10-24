//! Shared by the chat channels (Slack, Discord): incoming-webhook URL checks,
//! text limits, and how an alert's event is coloured.

use serde_json::Value;
use url::Url;

use crate::notify::alert::AlertEvent;
use crate::notify::http::{classify, parse_url, transport_error};
use crate::notify::kind::SendError;

/// Parses an incoming-webhook URL and checks it belongs to the service.
///
/// In production only the service's own hosts are accepted (it's a secret
/// that a typo shouldn't send elsewhere); `allow_private` (development and
/// tests) accepts any URL that `parse_url` does.
pub fn webhook_url(
    raw: &str,
    hosts: &[&str],
    path_prefix: &str,
    service: &str,
    allow_private: bool,
) -> Result<Url, String> {
    let url = parse_url(raw, allow_private)
        .map_err(|_| format!("Paste the {service} webhook URL (it starts with https://)."))?;
    if allow_private {
        return Ok(url);
    }
    let host_ok = url.host_str().is_some_and(|h| hosts.contains(&h));
    if url.scheme() != "https" || !host_ok || !url.path().starts_with(path_prefix) {
        return Err(format!(
            "That isn't a {service} webhook URL. It should look like https://{}{path_prefix}…",
            hosts[0]
        ));
    }
    Ok(url)
}

/// POSTs `body` as JSON. On failure the service's own explanation (Slack says
/// `channel_is_archived`, Discord `Unknown Webhook`) goes into the error.
pub async fn post_json(client: &reqwest::Client, url: Url, body: &Value) -> Result<(), SendError> {
    let response = client
        .post(url)
        .json(body)
        .send()
        .await
        .map_err(transport_error)?;
    let status = response.status();
    if let Err(err) = classify(status) {
        let detail = response.text().await.unwrap_or_default();
        let detail = truncate(detail.trim(), 200);
        if detail.is_empty() {
            return Err(err);
        }
        let message = format!("{}: {detail}", err.message());
        return Err(match err {
            SendError::Retryable(_) => SendError::Retryable(message),
            SendError::Permanent(_) => SendError::Permanent(message),
        });
    }
    Ok(())
}

/// Safe summary of a webhook URL: the service and the token's last characters.
pub fn summary(service: &str, raw: &str) -> String {
    let tail: String = raw
        .trim_end_matches('/')
        .chars()
        .rev()
        .take(4)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect();
    format!("{service} webhook …{tail}")
}

/// At most `max` characters, ending in "…" when cut.
pub fn truncate(text: &str, max: usize) -> String {
    if text.chars().count() <= max {
        return text.to_owned();
    }
    let mut out: String = text.chars().take(max.saturating_sub(1)).collect();
    out.push('…');
    out
}

/// A log tail inside a fenced code block that it can't break out of.
pub fn code_block(log: &str, max: usize) -> String {
    let log = log.replace("```", "'''");
    format!("```\n{}\n```", truncate(&log, max))
}

/// 0xRRGGBB for the event: red for trouble, green for recovery, amber for warnings.
pub fn color(event: AlertEvent) -> u32 {
    match event {
        AlertEvent::Down | AlertEvent::Fail | AlertEvent::RelayDown => 0xD0_3B_3B,
        AlertEvent::Up | AlertEvent::RelayUp => 0x2F_9E_44,
        AlertEvent::Anomaly => 0xE0_A0_00,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SLACK: &[&str] = &["hooks.slack.com"];

    #[test]
    fn only_the_services_hosts_in_production() {
        let ok = "https://hooks.slack.com/services/T0/B0/xyz";
        assert!(webhook_url(ok, SLACK, "/services/", "Slack", false).is_ok());
        for bad in [
            "http://hooks.slack.com/services/T0/B0/xyz",
            "https://hooks.slack.com.evil.com/services/x",
            "https://example.com/services/x",
            "https://hooks.slack.com/other/x",
            "not a url",
        ] {
            assert!(
                webhook_url(bad, SLACK, "/services/", "Slack", false).is_err(),
                "{bad}"
            );
        }
        // Development: any reachable URL, e.g. a local test server.
        assert!(webhook_url("http://127.0.0.1:9/x", SLACK, "/services/", "Slack", true).is_ok());
    }

    #[test]
    fn summaries_and_limits() {
        assert_eq!(
            summary("Slack", "https://hooks.slack.com/services/T0/B0/abcdWXYZ"),
            "Slack webhook …WXYZ"
        );
        assert_eq!(truncate("héllo", 10), "héllo");
        assert_eq!(truncate("héllo world", 5), "héll…");
        assert_eq!(code_block("a```b", 100), "```\na'''b\n```");
    }
}
