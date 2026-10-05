//! Outgoing email over SMTP, shared by the email alert channel and account emails
//! (verification, password reset).

use std::time::Duration;

use lettre::message::header::ContentType;
use lettre::message::{Mailbox, MultiPart};
use lettre::transport::smtp;
use lettre::{AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor};

use crate::notify::SendError;

pub struct Mailer {
    transport: AsyncSmtpTransport<Tokio1Executor>,
    from: Mailbox,
}

pub enum Body {
    Text(String),
    /// Plain text plus an HTML alternative.
    Alternative {
        text: String,
        html: String,
    },
}

impl Mailer {
    /// Must be called inside a Tokio runtime (the connection pool spawns a task).
    pub fn new(smtp_url: &str, from: &str) -> anyhow::Result<Self> {
        let transport = AsyncSmtpTransport::<Tokio1Executor>::from_url(smtp_url)?
            .timeout(Some(Duration::from_secs(15)))
            .build();
        let from = from
            .parse()
            .map_err(|err| anyhow::anyhow!("SMTP_FROM {from:?} is not a valid mailbox: {err}"))?;
        Ok(Self { transport, from })
    }

    pub async fn send(&self, to: &str, subject: &str, body: Body) -> Result<(), SendError> {
        let to: Mailbox = to
            .parse()
            .map_err(|err| SendError::Permanent(format!("invalid address {to:?}: {err}")))?;
        let message = Message::builder()
            .from(self.from.clone())
            .to(to)
            .subject(subject);
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

/// 5xx replies are permanent (bad mailbox, rejected sender); anything else
/// (4xx, connection problems, timeouts) is worth retrying.
fn smtp_error(err: smtp::Error) -> SendError {
    if err.is_permanent() {
        SendError::Permanent(err.to_string())
    } else {
        SendError::Retryable(err.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // lettre's connection pool spawns a Tokio task when built.
    #[tokio::test]
    async fn rejects_a_bad_from_address() {
        assert!(Mailer::new("smtp://localhost:1025", "not an address").is_err());
        assert!(Mailer::new("smtp://localhost:1025", "Monitor <alerts@localhost>").is_ok());
    }
}
