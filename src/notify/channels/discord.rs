use async_trait::async_trait;
use serde_json::{Value, json};

use super::chat;
use crate::notify::alert::Alert;
use crate::notify::kind::{
    ChannelCtx, ChannelKind, Field, FieldValues, Input, SendError, config_str, value,
};

const HOSTS: &[&str] = &[
    "discord.com",
    "discordapp.com",
    "ptb.discord.com",
    "canary.discord.com",
];
const PATH: &str = "/api/webhooks/";
/// Discord's embed limits: title 256 characters, description 4096.
const TITLE_MAX: usize = 256;
const DESCRIPTION_MAX: usize = 4000;

/// Posts alerts to a Discord channel through a channel webhook.
pub struct Discord {
    client: reqwest::Client,
    allow_private: bool,
}

impl Discord {
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
    placeholder: "https://discord.com/api/webhooks/…",
    help: "In Discord: channel settings → Integrations → Webhooks → New Webhook → Copy Webhook URL. \
           It's a secret, so it isn't shown again after saving.",
}];

#[async_trait]
impl ChannelKind for Discord {
    fn id(&self) -> &'static str {
        "discord"
    }

    fn label(&self) -> &'static str {
        "Discord"
    }

    fn description(&self) -> &'static str {
        "Post alerts to a Discord channel."
    }

    fn fields(&self) -> &'static [Field] {
        &FIELDS
    }

    fn validate(&self, input: &FieldValues, ctx: &ChannelCtx) -> Result<Value, String> {
        let url = chat::webhook_url(
            value(input, "url"),
            HOSTS,
            PATH,
            "Discord",
            ctx.allow_private_targets,
        )?;
        Ok(json!({ "url": url.as_str() }))
    }

    fn summary(&self, config: &Value) -> String {
        chat::summary("Discord", config_str(config, "url"))
    }

    async fn send(&self, config: &Value, alert: &Alert) -> Result<(), SendError> {
        let url = chat::webhook_url(
            config_str(config, "url"),
            HOSTS,
            PATH,
            "Discord",
            self.allow_private,
        )
        .map_err(SendError::Permanent)?;
        chat::post_json(&self.client, url, &message(alert)).await
    }
}

/// Backslash-escapes Discord markdown so names and details show literally.
fn escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        if matches!(
            c,
            '\\' | '*' | '_' | '~' | '`' | '|' | '>' | '#' | '-' | '[' | ']'
        ) {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

/// One embed. Mentions are disabled, so text like "@everyone" in a job's
/// output can't ping a whole server.
fn message(alert: &Alert) -> Value {
    let mut description = alert.summary().map(|s| escape(&s)).unwrap_or_default();
    if let Some(log) = &alert.log_tail {
        if !description.is_empty() {
            description.push_str("\n\n");
        }
        description.push_str("**Last output**\n");
        let room = DESCRIPTION_MAX.saturating_sub(description.chars().count() + 10);
        description.push_str(&chat::code_block(log, room));
    }
    json!({
        "username": "Monitor",
        "allowed_mentions": { "parse": [] },
        "embeds": [{
            "title": chat::truncate(&alert.title(), TITLE_MAX),
            "url": alert.source.url,
            "description": chat::truncate(&description, DESCRIPTION_MAX),
            "color": chat::color(alert.event),
            "timestamp": alert.occurred_at.to_rfc3339(),
        }]
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::notify::alert::AlertEvent;

    #[test]
    fn embed_has_title_link_colour_and_log() {
        let mut alert = Alert::for_check(
            AlertEvent::Fail,
            uuid::Uuid::nil(),
            "Backup",
            "https://m.example",
        );
        alert.reason = Some("Job failed".into());
        alert.detail = Some("exit *3*".into());
        alert.log_tail = Some("@everyone ```oops```".into());
        let m = message(&alert);
        let embed = &m["embeds"][0];
        assert_eq!(embed["title"], "❌ Backup failed");
        assert_eq!(embed["color"], 0xD0_3B_3B);
        assert!(
            embed["url"]
                .as_str()
                .unwrap()
                .starts_with("https://m.example/checks/")
        );
        assert_eq!(
            embed["description"],
            "Job failed: exit \\*3\\*\n\n**Last output**\n```\n@everyone '''oops'''\n```"
        );
        assert_eq!(m["allowed_mentions"]["parse"], json!([]));
    }

    #[test]
    fn validates_discord_hosts() {
        let ctx = ChannelCtx {
            verified_account_email: None,
            allow_private_targets: false,
        };
        let mut input = FieldValues::new();
        input.insert(
            "url".into(),
            "https://discord.com/api/webhooks/123/abcDEF".into(),
        );
        let config = Discord::new(reqwest::Client::new(), false)
            .validate(&input, &ctx)
            .unwrap();
        assert_eq!(
            Discord::new(reqwest::Client::new(), false).summary(&config),
            "Discord webhook …cDEF"
        );
        input.insert("url".into(), "https://hooks.slack.com/services/x".into());
        assert!(
            Discord::new(reqwest::Client::new(), false)
                .validate(&input, &ctx)
                .is_err()
        );
    }
}
