//! Alert channels. See [`kind::ChannelKind`] for how to add a new one.

pub mod alert;
pub mod channels;
pub mod http;
pub mod kind;

use std::sync::Arc;

use crate::config::Config;
use crate::mail::Mailer;
pub use alert::{Alert, AlertEvent};
pub use kind::{ChannelCtx, ChannelKind, SendError, Verification};

/// The channel kinds this deployment offers. A kind is only registered when its
/// provider is configured (email needs `SMTP_URL`), so the UI never offers a
/// channel that can't deliver.
pub struct Registry {
    kinds: Vec<Arc<dyn ChannelKind>>,
}

impl Registry {
    pub fn from_config(config: &Config, mailer: Option<Arc<Mailer>>) -> Self {
        let mut kinds: Vec<Arc<dyn ChannelKind>> = Vec::new();
        if let Some(mailer) = mailer {
            kinds.push(Arc::new(channels::email::Email::new(mailer)));
        }
        let client = http::client(config.allow_private_targets);
        let private = config.allow_private_targets;
        kinds.push(Arc::new(channels::slack::Slack::new(
            client.clone(),
            private,
        )));
        kinds.push(Arc::new(channels::discord::Discord::new(
            client.clone(),
            private,
        )));
        kinds.push(Arc::new(channels::webhook::Webhook::new(client, private)));
        // New kinds go here, e.g.:
        // if let Some(twilio) = &config.twilio { kinds.push(Arc::new(channels::whatsapp::WhatsApp::new(twilio))); }
        Self { kinds }
    }

    pub fn get(&self, id: &str) -> Option<&Arc<dyn ChannelKind>> {
        self.kinds.iter().find(|kind| kind.id() == id)
    }

    pub fn available(&self) -> &[Arc<dyn ChannelKind>] {
        &self.kinds
    }

    /// Display name for a stored kind, even one that's no longer registered.
    pub fn label(&self, id: &str) -> String {
        self.get(id).map_or_else(
            || format!("{id} (unavailable)"),
            |kind| kind.label().to_owned(),
        )
    }
}
