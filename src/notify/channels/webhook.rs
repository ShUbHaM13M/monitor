use async_trait::async_trait;
use hmac::{Hmac, KeyInit, Mac};
use serde_json::{Value, json};
use sha2::Sha256;

use crate::notify::alert::Alert;
use crate::notify::http::{classify, parse_url, transport_error};
use crate::notify::kind::{
    ChannelCtx, ChannelKind, Field, FieldValues, Input, SendError, config_str, value,
};

/// POSTs each alert as JSON to a URL, optionally signed with HMAC-SHA256.
///
/// Signed requests carry `X-Monitor-Timestamp` and
/// `X-Monitor-Signature: sha256=<hex HMAC of "{timestamp}.{body}">`. Receivers should
/// recompute it with their secret and reject old timestamps to stop replays.
pub struct Webhook {
    client: reqwest::Client,
    allow_private: bool,
}

impl Webhook {
    pub fn new(client: reqwest::Client, allow_private: bool) -> Self {
        Self {
            client,
            allow_private,
        }
    }
}

static FIELDS: [Field; 2] = [
    Field {
        name: "url",
        label: "URL",
        input: Input::Url,
        required: true,
        placeholder: "https://example.com/hooks/monitor",
        help: "Alerts are POSTed here as JSON.",
    },
    Field {
        name: "secret",
        label: "Signing secret",
        input: Input::Secret,
        required: false,
        placeholder: "",
        help: "Optional. Requests get an X-Monitor-Signature header (HMAC-SHA256 of \"timestamp.body\").",
    },
];

#[async_trait]
impl ChannelKind for Webhook {
    fn id(&self) -> &'static str {
        "webhook"
    }

    fn label(&self) -> &'static str {
        "Webhook"
    }

    fn description(&self) -> &'static str {
        "POST alerts as signed JSON to your own endpoint or automation tool."
    }

    fn fields(&self) -> &'static [Field] {
        &FIELDS
    }

    fn validate(&self, input: &FieldValues, ctx: &ChannelCtx) -> Result<Value, String> {
        let url = parse_url(value(input, "url"), ctx.allow_private_targets)?;
        let secret = value(input, "secret");
        if secret.len() > 256 {
            return Err("The signing secret must be at most 256 characters.".into());
        }
        Ok(json!({ "url": url.as_str(), "secret": secret }))
    }

    /// Scheme and host only: paths often contain tokens.
    fn summary(&self, config: &Value) -> String {
        match url::Url::parse(config_str(config, "url")) {
            Ok(url) => format!(
                "{}://{}/…",
                url.scheme(),
                url.host_str().unwrap_or_default()
            ),
            Err(_) => "invalid URL".into(),
        }
    }

    async fn send(&self, config: &Value, alert: &Alert) -> Result<(), SendError> {
        let url = parse_url(config_str(config, "url"), self.allow_private)
            .map_err(SendError::Permanent)?;
        let body = serde_json::to_vec(&payload(alert))
            .map_err(|err| SendError::Permanent(err.to_string()))?;
        let mut request = self
            .client
            .post(url)
            .header("content-type", "application/json")
            .header("x-monitor-event", alert.event.as_str());
        let secret = config_str(config, "secret");
        if !secret.is_empty() {
            let timestamp = chrono::Utc::now().timestamp().to_string();
            request = request
                .header("x-monitor-signature", sign(secret, &timestamp, &body))
                .header("x-monitor-timestamp", timestamp);
        }
        let response = request.body(body).send().await.map_err(transport_error)?;
        classify(response.status())
    }
}

/// The JSON receivers get. Field names are a public contract: add, don't rename.
fn payload(alert: &Alert) -> Value {
    json!({
        "event": alert.event,
        "title": alert.title(),
        "summary": alert.summary(),
        "source": alert.source,
        "reason": alert.reason,
        "detail": alert.detail,
        "log_tail": alert.log_tail,
        "occurred_at": alert.occurred_at,
        "down_since": alert.down_since,
    })
}

/// `sha256=<hex>` of HMAC-SHA256(secret, "{timestamp}.{body}").
pub fn sign(secret: &str, timestamp: &str, body: &[u8]) -> String {
    let mut mac =
        Hmac::<Sha256>::new_from_slice(secret.as_bytes()).expect("HMAC accepts any key length");
    mac.update(timestamp.as_bytes());
    mac.update(b".");
    mac.update(body);
    let digest = mac.finalize().into_bytes();
    let hex: String = digest.iter().map(|b| format!("{b:02x}")).collect();
    format!("sha256={hex}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::notify::alert::AlertEvent;

    fn ctx(allow_private: bool) -> ChannelCtx {
        ChannelCtx {
            verified_account_email: None,
            allow_private_targets: allow_private,
        }
    }

    fn webhook() -> Webhook {
        Webhook::new(reqwest::Client::new(), false)
    }

    #[test]
    fn signature_matches_known_hmac_vector() {
        // RFC-style vector: HMAC-SHA256("key", "The quick brown fox jumps over the lazy dog").
        // Split as timestamp "The quick brown fox" + "." + body.
        let sig = sign("key", "The quick brown fox", b"jumps over the lazy dog");
        assert_eq!(
            sig,
            format!("sha256={}", {
                let mut mac = Hmac::<Sha256>::new_from_slice(b"key").unwrap();
                mac.update(b"The quick brown fox.jumps over the lazy dog");
                mac.finalize()
                    .into_bytes()
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect::<String>()
            })
        );
        let mut mac = Hmac::<Sha256>::new_from_slice(b"key").unwrap();
        mac.update(b"The quick brown fox jumps over the lazy dog");
        let known: String = mac
            .finalize()
            .into_bytes()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        assert_eq!(
            known,
            "f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8"
        );
    }

    #[test]
    fn validates_urls_and_hides_paths() {
        let mut input = FieldValues::new();
        input.insert(
            "url".into(),
            "https://hooks.example.com/T0/secret-token".into(),
        );
        let config = webhook().validate(&input, &ctx(false)).unwrap();
        assert_eq!(webhook().summary(&config), "https://hooks.example.com/…");

        input.insert("url".into(), "http://127.0.0.1:9000/hook".into());
        assert!(webhook().validate(&input, &ctx(false)).is_err());
        assert!(webhook().validate(&input, &ctx(true)).is_ok());
    }

    #[test]
    fn payload_shape() {
        let mut alert = Alert::for_check(
            AlertEvent::Fail,
            uuid::Uuid::nil(),
            "Backup",
            "https://m.example",
        );
        alert.log_tail = Some("boom".into());
        let p = payload(&alert);
        assert_eq!(p["event"], "fail");
        assert_eq!(p["source"]["type"], "check");
        assert_eq!(p["source"]["name"], "Backup");
        assert_eq!(p["log_tail"], "boom");
        assert_eq!(p["title"], "❌ Backup failed");
    }
}
