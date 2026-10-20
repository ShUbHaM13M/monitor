use async_trait::async_trait;
use serde_json::{Value, json};

use super::chat;
use crate::notify::alert::Alert;
use crate::notify::kind::{
    ChannelCtx, ChannelKind, Field, FieldValues, Input, SendError, config_str, value,
};

const HOSTS: &[&str] = &["hooks.slack.com"];
const PATH: &str = "/services/";
/// Slack's limits: header text 150 characters, section text 3000.
const HEADER_MAX: usize = 150;
const SECTION_MAX: usize = 2900;

/// Posts alerts to a Slack channel through an incoming webhook.
pub struct Slack {
    client: reqwest::Client,
    allow_private: bool,
}

impl Slack {
    pub fn new(client: reqwest::Client, allow_private: bool) -> Self {
        Self {
            client,
            allow_private,
        }
    }
}

static FIELDS: [Field; 1] = [Field {
    name: "url",
    label: "Webhook URL",
    input: Input::Secret,
    required: true,
    placeholder: "https://hooks.slack.com/services/…",
    help: "In Slack: Apps → Incoming Webhooks → Add to Slack, pick a channel, copy the URL. \
           It's a secret, so it isn't shown again after saving.",
}];

#[async_trait]
impl ChannelKind for Slack {
    fn id(&self) -> &'static str {
        "slack"
    }

    fn label(&self) -> &'static str {
        "Slack"
    }

    fn description(&self) -> &'static str {
        "Post alerts to a Slack channel."
    }

    fn fields(&self) -> &'static [Field] {
        &FIELDS
    }

    fn validate(&self, input: &FieldValues, ctx: &ChannelCtx) -> Result<Value, String> {
        let url = chat::webhook_url(
            value(input, "url"),
            HOSTS,
            PATH,
            "Slack",
            ctx.allow_private_targets,
        )?;
        Ok(json!({ "url": url.as_str() }))
    }

    fn summary(&self, config: &Value) -> String {
        chat::summary("Slack", config_str(config, "url"))
    }

    async fn send(&self, config: &Value, alert: &Alert) -> Result<(), SendError> {
        let url = chat::webhook_url(
            config_str(config, "url"),
            HOSTS,
            PATH,
            "Slack",
            self.allow_private,
        )
        .map_err(SendError::Permanent)?;
        chat::post_json(&self.client, url, &message(alert)).await
    }
}

/// Slack's mrkdwn treats `&`, `<` and `>` as control characters.
fn escape(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

/// A coloured attachment with Block Kit content; `text` is what notifications show.
fn message(alert: &Alert) -> Value {
    let title = alert.title();
    let mut blocks = vec![json!({
        "type": "header",
        "text": { "type": "plain_text", "text": chat::truncate(&title, HEADER_MAX), "emoji": true }
    })];
    if let Some(summary) = alert.summary() {
        blocks.push(json!({
            "type": "section",
            "text": { "type": "mrkdwn", "text": chat::truncate(&escape(&summary), SECTION_MAX) }
        }));
    }
    if let Some(log) = &alert.log_tail {
        blocks.push(json!({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": format!("*Last output*\n{}", chat::code_block(&escape(log), SECTION_MAX - 40))
            }
        }));
    }
    blocks.push(json!({
        "type": "context",
        "elements": [{
            "type": "mrkdwn",
            "text": format!(
                "<{}|Open in Monitor> · <!date^{}^{{date_short_pretty}} at {{time}}|{}>",
                alert.source.url,
                alert.occurred_at.timestamp(),
                alert.occurred_at.format("%Y-%m-%d %H:%M UTC"),
            )
        }]
    }));
    json!({
        "text": title,
        "attachments": [{
            "color": format!("#{:06x}", chat::color(alert.event)),
            "blocks": blocks,
        }]
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::notify::alert::AlertEvent;

    #[test]
    fn message_has_title_summary_log_and_link() {
        let mut alert = Alert::for_check(
            AlertEvent::Fail,
            uuid::Uuid::nil(),
            "Backup <prod>",
            "https://m.example",
        );
        alert.reason = Some("Job failed".into());
        alert.detail = Some("exit code 3 & more".into());
        alert.log_tail = Some("pg_dump: <error>".into());
        let m = message(&alert);
        assert_eq!(m["text"], "❌ Backup <prod> failed");
        assert_eq!(m["attachments"][0]["color"], "#d03b3b");
        let blocks = m["attachments"][0]["blocks"].as_array().unwrap();
        assert_eq!(blocks[0]["text"]["text"], "❌ Backup <prod> failed");
        assert_eq!(
            blocks[1]["text"]["text"],
            "Job failed: exit code 3 &amp; more"
        );
        assert_eq!(
            blocks[2]["text"]["text"],
            "*Last output*\n```\npg_dump: &lt;error&gt;\n```"
        );
        let context = blocks[3]["elements"][0]["text"].as_str().unwrap();
        assert!(context.starts_with(
            "<https://m.example/checks/00000000-0000-0000-0000-000000000000|Open in Monitor>"
        ));
    }

    #[test]
    fn recoveries_are_green() {
        let alert = Alert::for_check(
            AlertEvent::Up,
            uuid::Uuid::nil(),
            "Backup",
            "https://m.example",
        );
        assert_eq!(message(&alert)["attachments"][0]["color"], "#2f9e44");
    }
}
