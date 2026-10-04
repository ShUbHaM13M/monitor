use std::time::Duration;

use askama::Template;
use async_trait::async_trait;
use lettre::message::header::ContentType;
use lettre::message::{Mailbox, MultiPart};
use lettre::transport::smtp;
use lettre::{AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor};
use serde_json::{Value, json};

use crate::domain::email::is_valid;
use crate::notify::alert::Alert;
use crate::notify::kind::{
    ChannelCtx, ChannelKind, Field, FieldValues, Input, SendError, Verification, config_str, value,
};

/// Sends alerts over SMTP to one address per channel.
pub struct Email {
    transport: AsyncSmtpTransport<Tokio1Executor>,
    from: Mailbox,
}

impl Email {
    pub fn new(smtp_url: &str, from: &str) -> anyhow::Result<Self> {
        let transport = AsyncSmtpTransport::<Tokio1Executor>::from_url(smtp_url)?
            .timeout(Some(Duration::from_secs(15)))
            .build();
        let from = from
            .parse()
            .map_err(|err| anyhow::anyhow!("SMTP_FROM {from:?} is not a valid mailbox: {err}"))?;
        Ok(Self { transport, from })
    }

    async fn deliver(
        &self,
        to: &str,
        message: lettre::message::MessageBuilder,
        body: Body,
    ) -> Result<(), SendError> {
        let to: Mailbox = to
            .parse()
            .map_err(|err| SendError::Permanent(format!("invalid address {to:?}: {err}")))?;
        let message = message.from(self.from.clone()).to(to);
        let message = match body {
            Body::Text(text) => message.header(ContentType::TEXT_PLAIN).body(text),
            Body::Alternative { text, html } => {
                message.multipart(MultiPart::alternative_plain_html(text, html))
            }
        }
        .map_err(|err| SendError::Permanent(format!("could not build email: {err}")))?;
        self.transport
            .send(message)
            .await
            .map(drop)
            .map_err(smtp_error)
    }
}

enum Body {
    Text(String),
    Alternative { text: String, html: String },
}

/// 5xx replies are permanent (bad mailbox, rejected sender); anything else
/// (4xx, connection problems, timeouts) is worth retrying.
fn smtp_error(err: smtp::Error) -> SendError {
    if err.is_permanent() {
        SendError::Permanent(err.to_string())
    } else {
        SendError::Retryable(err.to_string())
    }
}

#[derive(Template)]
#[template(path = "email/alert.html")]
struct AlertHtml<'a> {
    alert: &'a Alert,
    summary: Option<String>,
}

static FIELDS: [Field; 1] = [Field {
    name: "address",
    label: "Email address",
    input: Input::Email,
    required: true,
    placeholder: "oncall@example.com",
    help: "Addresses other than your own get a confirmation link first.",
}];

#[async_trait]
impl ChannelKind for Email {
    fn id(&self) -> &'static str {
        "email"
    }

    fn label(&self) -> &'static str {
        "Email"
    }

    fn description(&self) -> &'static str {
        "Send alerts to an email address."
    }

    fn fields(&self) -> &'static [Field] {
        &FIELDS
    }

    fn validate(&self, input: &FieldValues, _ctx: &ChannelCtx) -> Result<Value, String> {
        let address = value(input, "address");
        if !is_valid(address) {
            return Err("Enter a valid email address.".into());
        }
        Ok(json!({ "address": address }))
    }

    fn summary(&self, config: &Value) -> String {
        config_str(config, "address").to_owned()
    }

    fn verification(&self, config: &Value, ctx: &ChannelCtx) -> Verification {
        if config_str(config, "address").eq_ignore_ascii_case(&ctx.account_email) {
            Verification::None
        } else {
            Verification::Link
        }
    }

    async fn send(&self, config: &Value, alert: &Alert) -> Result<(), SendError> {
        let html = AlertHtml {
            alert,
            summary: alert.summary(),
        }
        .render()
        .map_err(|err| SendError::Permanent(format!("render email: {err}")))?;
        let body = Body::Alternative {
            text: alert.text(),
            html,
        };
        self.deliver(
            config_str(config, "address"),
            Message::builder().subject(alert.title()),
            body,
        )
        .await
    }

    async fn send_verification(&self, config: &Value, link: &str) -> Result<(), SendError> {
        let text = format!(
            "Someone asked to send uptime and cron alerts from Monitor to this address.\n\n\
             To start receiving them, confirm here:\n{link}\n\n\
             If you didn't expect this, ignore this email and nothing will be sent."
        );
        self.deliver(
            config_str(config, "address"),
            Message::builder().subject("Confirm alerts from Monitor"),
            Body::Text(text),
        )
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn email() -> Email {
        Email::new("smtp://localhost:1025", "Monitor <alerts@localhost>").unwrap()
    }

    fn ctx() -> ChannelCtx {
        ChannelCtx {
            account_email: "Me@Example.com".into(),
            allow_private_targets: false,
        }
    }

    // lettre's connection pool spawns a Tokio task when built.
    #[tokio::test]
    async fn validates_and_summarises() {
        let mut input = FieldValues::new();
        input.insert("address".into(), "  oncall@example.com ".into());
        let config = email().validate(&input, &ctx()).unwrap();
        assert_eq!(config, json!({ "address": "oncall@example.com" }));
        assert_eq!(email().summary(&config), "oncall@example.com");

        input.insert("address".into(), "nope".into());
        assert!(email().validate(&input, &ctx()).is_err());
    }

    #[tokio::test]
    async fn own_address_needs_no_confirmation() {
        let own = json!({ "address": "me@example.com" });
        let other = json!({ "address": "team@example.com" });
        assert!(matches!(
            email().verification(&own, &ctx()),
            Verification::None
        ));
        assert!(matches!(
            email().verification(&other, &ctx()),
            Verification::Link
        ));
    }

    #[tokio::test]
    async fn rejects_a_bad_from_address() {
        assert!(Email::new("smtp://localhost:1025", "not an address").is_err());
    }
}
