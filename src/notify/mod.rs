//! Alert channels. See [`kind::ChannelKind`] for how to add a new one.

pub mod alert;
pub mod channels;
pub mod http;
pub mod kind;

use std::sync::Arc;

use crate::config::Config;
pub use alert::{Alert, AlertEvent};
pub use kind::{ChannelCtx, ChannelKind, SendError, Verification};

/// The channel kinds this deployment offers. A kind is only registered when its
/// provider is configured (email needs `SMTP_URL`), so the UI never offers a
/// channel that can't deliver.
pub struct Registry {
    kinds: Vec<Arc<dyn ChannelKind>>,
}

impl Registry {
    pub fn from_config(config: &Config) -> anyhow::Result<Self> {
        let mut kinds: Vec<Arc<dyn ChannelKind>> = Vec::new();
        if let Some(smtp_url) = &config.smtp_url {
            kinds.push(Arc::new(channels::email::Email::new(
                smtp_url,
                &config.smtp_from,
            )?));
        }
        kinds.push(Arc::new(channels::webhook::Webhook::new(
            http::client(config.allow_private_targets),
            config.allow_private_targets,
        )));
        // New kinds go here, e.g.:
        // if let Some(twilio) = &config.twilio { kinds.push(Arc::new(channels::whatsapp::WhatsApp::new(twilio))); }
        Ok(Self { kinds })
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
