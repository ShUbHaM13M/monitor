use std::sync::Arc;

use askama::Template;
use async_trait::async_trait;
use serde_json::{Value, json};

use crate::domain::email::is_valid;
use crate::mail::{Body, Mailer};
use crate::notify::alert::Alert;
use crate::notify::kind::{
    ChannelCtx, ChannelKind, Field, FieldValues, Input, SendError, Verification, config_str, value,
};

/// Sends alerts to one address per channel.
pub struct Email {
    mailer: Arc<Mailer>,
}

impl Email {
    pub fn new(mailer: Arc<Mailer>) -> Self {
        Self { mailer }
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
        let address = config_str(config, "address");
        let own = ctx
            .verified_account_email
            .as_deref()
            .is_some_and(|email| address.eq_ignore_ascii_case(email));
        if own {
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
        self.mailer
            .send(config_str(config, "address"), &alert.title(), body)
            .await
    }

    async fn send_verification(&self, config: &Value, link: &str) -> Result<(), SendError> {
        let text = format!(
            "Someone asked to send uptime and cron alerts from Monitor to this address.\n\n\
             To start receiving them, confirm here:\n{link}\n\n\
             If you didn't expect this, ignore this email and nothing will be sent."
        );
        self.mailer
            .send(
                config_str(config, "address"),
                "Confirm alerts from Monitor",
                Body::Text(text),
            )
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn email() -> Email {
        Email::new(Arc::new(
            Mailer::new("smtp://localhost:1025", "Monitor <alerts@localhost>").unwrap(),
        ))
    }

    fn ctx(verified: bool) -> ChannelCtx {
        ChannelCtx {
            verified_account_email: verified.then(|| "Me@Example.com".into()),
            allow_private_targets: false,
        }
    }

    // lettre's connection pool spawns a Tokio task when built.
    #[tokio::test]
    async fn validates_and_summarises() {
        let mut input = FieldValues::new();
        input.insert("address".into(), "  oncall@example.com ".into());
        let config = email().validate(&input, &ctx(true)).unwrap();
        assert_eq!(config, json!({ "address": "oncall@example.com" }));
        assert_eq!(email().summary(&config), "oncall@example.com");

        input.insert("address".into(), "nope".into());
        assert!(email().validate(&input, &ctx(true)).is_err());
    }

    #[tokio::test]
    async fn own_verified_address_needs_no_confirmation() {
        let own = json!({ "address": "me@example.com" });
        let other = json!({ "address": "team@example.com" });
        assert!(matches!(
            email().verification(&own, &ctx(true)),
            Verification::None
        ));
        assert!(matches!(
            email().verification(&other, &ctx(true)),
            Verification::Link
        ));
        // Until the account email is confirmed it's just another address: otherwise
        // signing up with someone else's email would let you mail them alerts.
        assert!(matches!(
            email().verification(&own, &ctx(false)),
            Verification::Link
        ));
    }
}
