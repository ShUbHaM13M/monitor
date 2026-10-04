use std::collections::HashMap;

use async_trait::async_trait;
use serde_json::Value;

use super::alert::Alert;

/// A kind of alert channel: email, webhook, and later Slack, WhatsApp, RCS…
///
/// Adding one means implementing this trait in `notify/channels/` and registering
/// it in [`super::Registry::from_config`]. The channel form, storage (encrypted
/// JSON config), delivery queue, retries and verification flow are all generic.
#[async_trait]
pub trait ChannelKind: Send + Sync {
    /// Stable identifier stored in `channels.kind`. Never change it once used.
    fn id(&self) -> &'static str;

    /// Shown in the UI, e.g. "Email".
    fn label(&self) -> &'static str;

    /// One line for the "add channel" picker.
    fn description(&self) -> &'static str;

    /// The fields the channel form asks for.
    fn fields(&self) -> &'static [Field];

    /// Turns submitted form values into the config to store, or a message for the user.
    fn validate(&self, input: &FieldValues, ctx: &ChannelCtx) -> Result<Value, String>;

    /// Safe one-line description of a config for lists. Must not reveal secrets.
    fn summary(&self, config: &Value) -> String;

    /// Whether the recipient must confirm before receiving alerts.
    fn verification(&self, _config: &Value, _ctx: &ChannelCtx) -> Verification {
        Verification::None
    }

    async fn send(&self, config: &Value, alert: &Alert) -> Result<(), SendError>;

    /// Delivers a confirmation link. Required when [`Self::verification`] can return
    /// [`Verification::Link`].
    async fn send_verification(&self, _config: &Value, _link: &str) -> Result<(), SendError> {
        Err(SendError::Permanent(format!(
            "{} channels don't support verification",
            self.label()
        )))
    }
}

/// Submitted form values, by field name.
pub type FieldValues = HashMap<String, String>;

/// Context for validating a channel.
pub struct ChannelCtx {
    /// The signed-in user's email: alerts to it need no confirmation.
    pub account_email: String,
    pub allow_private_targets: bool,
}

pub enum Verification {
    None,
    /// Confirm by following a link sent through the channel itself.
    Link,
    // Later, for phone channels (WhatsApp, SMS, RCS): `Code`, a one-time code
    // sent through the channel and typed back into the UI.
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SendError {
    /// Worth retrying later: timeouts, 5xx, rate limits.
    Retryable(String),
    /// Will never succeed as configured: bad address, 4xx, rejected credentials.
    Permanent(String),
}

impl SendError {
    pub fn message(&self) -> &str {
        match self {
            Self::Retryable(msg) | Self::Permanent(msg) => msg,
        }
    }
}

/// One input on the channel form.
pub struct Field {
    pub name: &'static str,
    pub label: &'static str,
    pub input: Input,
    pub required: bool,
    pub placeholder: &'static str,
    pub help: &'static str,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Input {
    Text,
    Email,
    Url,
    /// Rendered as a password field and never shown again after saving.
    Secret,
}

impl Input {
    /// The HTML `<input type>`.
    pub fn html_type(self) -> &'static str {
        match self {
            Self::Text => "text",
            Self::Email => "email",
            Self::Url => "url",
            Self::Secret => "password",
        }
    }
}

/// Trimmed value of a field, or `""`.
pub fn value<'a>(input: &'a FieldValues, name: &str) -> &'a str {
    input.get(name).map_or("", |v| v.trim())
}

/// String value from a stored config.
pub fn config_str<'a>(config: &'a Value, key: &str) -> &'a str {
    config.get(key).and_then(Value::as_str).unwrap_or_default()
}
