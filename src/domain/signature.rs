//! Verifying signed inbound webhooks. Every scheme is an HMAC-SHA256 over the raw
//! request body (Stripe also covers a timestamp); comparison is constant-time.

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;

/// Stripe's default: reject signatures more than five minutes old (replays).
pub const STRIPE_TOLERANCE_SECS: i64 = 300;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scheme {
    /// `Stripe-Signature: t=<unix>,v1=<hex>` over `"{t}.{body}"`.
    Stripe,
    /// `X-Hub-Signature-256: sha256=<hex>`.
    GitHub,
    /// `X-Shopify-Hmac-Sha256: <base64>`.
    Shopify,
    /// A header you name, holding the hex (optionally `sha256=`-prefixed) or base64 HMAC.
    HmacSha256,
}

impl Scheme {
    pub const ALL: [Scheme; 4] = [Self::Stripe, Self::GitHub, Self::Shopify, Self::HmacSha256];

    pub fn id(self) -> &'static str {
        match self {
            Self::Stripe => "stripe",
            Self::GitHub => "github",
            Self::Shopify => "shopify",
            Self::HmacSha256 => "hmac_sha256",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Stripe => "Stripe",
            Self::GitHub => "GitHub",
            Self::Shopify => "Shopify",
            Self::HmacSha256 => "Generic HMAC-SHA256",
        }
    }

    pub fn parse(id: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|s| s.id() == id)
    }

    /// The header the signature arrives in (the generic scheme's is configured).
    pub fn header(self) -> Option<&'static str> {
        match self {
            Self::Stripe => Some("stripe-signature"),
            Self::GitHub => Some("x-hub-signature-256"),
            Self::Shopify => Some("x-shopify-hmac-sha256"),
            Self::HmacSha256 => None,
        }
    }
}

fn hmac(secret: &[u8], parts: &[&[u8]]) -> Vec<u8> {
    let mut mac = Hmac::<Sha256>::new_from_slice(secret).expect("HMAC accepts any key length");
    for part in parts {
        mac.update(part);
    }
    mac.finalize().into_bytes().to_vec()
}

fn decode_hex(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) {
        return None;
    }
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(text.get(i..i + 2)?, 16).ok())
        .collect()
}

fn same(a: &[u8], b: &[u8]) -> bool {
    a.ct_eq(b).into()
}

/// Checks a delivery. `header` looks a request header up by lowercase name; `now`
/// is the current Unix time (for Stripe's replay window). The error explains why a
/// delivery was rejected, for the delivery log.
pub fn verify(
    scheme: Scheme,
    secret: &str,
    header_name: Option<&str>,
    header: impl Fn(&str) -> Option<String>,
    body: &[u8],
    now: i64,
) -> Result<(), String> {
    let name = scheme
        .header()
        .map(str::to_owned)
        .or_else(|| header_name.map(str::to_ascii_lowercase))
        .ok_or("no signature header configured")?;
    let sent = header(&name).ok_or_else(|| format!("missing {name} header"))?;
    let sent = sent.trim();
    let secret = secret.as_bytes();
    let mismatch = || Err("signature mismatch (check the signing secret)".to_owned());

    match scheme {
        Scheme::Stripe => {
            let mut timestamp = None;
            let mut signatures = Vec::new();
            for item in sent.split(',') {
                match item.trim().split_once('=') {
                    Some(("t", t)) => timestamp = t.parse::<i64>().ok(),
                    Some(("v1", sig)) => signatures.extend(decode_hex(sig)),
                    _ => {}
                }
            }
            let t = timestamp.ok_or("malformed Stripe-Signature: no timestamp")?;
            if (now - t).abs() > STRIPE_TOLERANCE_SECS {
                return Err(format!(
                    "timestamp is {} s off (more than 5 minutes: replayed or clock skew)",
                    (now - t).abs()
                ));
            }
            let expected = hmac(secret, &[t.to_string().as_bytes(), b".", body]);
            if signatures.iter().any(|sig| same(sig, &expected)) {
                Ok(())
            } else {
                mismatch()
            }
        }
        Scheme::GitHub => {
            let hex = sent
                .strip_prefix("sha256=")
                .ok_or("malformed X-Hub-Signature-256: expected sha256=…")?;
            match decode_hex(hex) {
                Some(sig) if same(&sig, &hmac(secret, &[body])) => Ok(()),
                _ => mismatch(),
            }
        }
        Scheme::Shopify => match STANDARD.decode(sent) {
            Ok(sig) if same(&sig, &hmac(secret, &[body])) => Ok(()),
            _ => mismatch(),
        },
        Scheme::HmacSha256 => {
            let value = sent.strip_prefix("sha256=").unwrap_or(sent);
            let expected = hmac(secret, &[body]);
            let ok = decode_hex(value).is_some_and(|sig| same(&sig, &expected))
                || STANDARD
                    .decode(value)
                    .is_ok_and(|sig| same(&sig, &expected));
            if ok { Ok(()) } else { mismatch() }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    fn headers(pairs: &[(&str, String)]) -> impl Fn(&str) -> Option<String> + use<> {
        let map: HashMap<String, String> = pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.clone()))
            .collect();
        move |name| map.get(name).cloned()
    }

    #[test]
    fn github_documented_example() {
        // From GitHub's "Validating webhook deliveries" docs.
        let sig =
            "sha256=757107ea0eb2509fc211221cce984b8a37570b6d7586c22c46f4379c8b043e17".to_owned();
        let h = headers(&[("x-hub-signature-256", sig)]);
        assert_eq!(
            verify(
                Scheme::GitHub,
                "It's a Secret to Everybody",
                None,
                &h,
                b"Hello, World!",
                0
            ),
            Ok(())
        );
        assert!(
            verify(
                Scheme::GitHub,
                "wrong secret",
                None,
                &h,
                b"Hello, World!",
                0
            )
            .is_err()
        );
        assert!(
            verify(
                Scheme::GitHub,
                "It's a Secret to Everybody",
                None,
                &h,
                b"Hello, World?",
                0
            )
            .is_err()
        );
        assert_eq!(
            verify(Scheme::GitHub, "s", None, headers(&[]), b"x", 0).unwrap_err(),
            "missing x-hub-signature-256 header"
        );
    }

    #[test]
    fn stripe_checks_signature_and_replay_window() {
        let (secret, body, t) = ("whsec_test", br#"{"type":"invoice.paid"}"#, 1_700_000_000);
        let good = hex(&hmac(
            secret.as_bytes(),
            &[t.to_string().as_bytes(), b".", body],
        ));
        let h = headers(&[(
            "stripe-signature",
            format!("t={t},v1=deadbeef,v1={good},v0=00"),
        )]);
        assert_eq!(
            verify(Scheme::Stripe, secret, None, &h, body, t + 10),
            Ok(()),
            "any v1 may match"
        );
        let stale = verify(Scheme::Stripe, secret, None, &h, body, t + 301).unwrap_err();
        assert!(stale.contains("more than 5 minutes"), "{stale}");
        assert!(verify(Scheme::Stripe, "whsec_other", None, &h, body, t).is_err());
        // The timestamp is signed: changing it breaks the signature.
        let moved = headers(&[("stripe-signature", format!("t={},v1={good}", t + 1))]);
        assert!(verify(Scheme::Stripe, secret, None, &moved, body, t).is_err());
        let malformed = headers(&[("stripe-signature", "v1=abc".to_owned())]);
        assert!(
            verify(Scheme::Stripe, secret, None, &malformed, body, t)
                .unwrap_err()
                .contains("no timestamp")
        );
    }

    #[test]
    fn shopify_uses_base64() {
        let body = br#"{"id":1}"#;
        let sig = STANDARD.encode(hmac(b"shpss_x", &[body]));
        let h = headers(&[("x-shopify-hmac-sha256", sig)]);
        assert_eq!(
            verify(Scheme::Shopify, "shpss_x", None, &h, body, 0),
            Ok(())
        );
        assert!(verify(Scheme::Shopify, "nope", None, &h, body, 0).is_err());
    }

    #[test]
    fn generic_accepts_hex_prefixed_hex_or_base64() {
        let body = b"payload";
        let mac = hmac(b"k", &[body]);
        for value in [
            hex(&mac),
            format!("sha256={}", hex(&mac)),
            STANDARD.encode(&mac),
        ] {
            let h = headers(&[("x-signature", value.clone())]);
            assert_eq!(
                verify(Scheme::HmacSha256, "k", Some("X-Signature"), &h, body, 0),
                Ok(()),
                "{value}"
            );
        }
        let h = headers(&[("x-signature", "zz".to_owned())]);
        assert!(verify(Scheme::HmacSha256, "k", Some("X-Signature"), &h, body, 0).is_err());
        assert!(verify(Scheme::HmacSha256, "k", None, &h, body, 0).is_err());
    }

    #[test]
    fn scheme_ids_round_trip() {
        for scheme in Scheme::ALL {
            assert_eq!(Scheme::parse(scheme.id()), Some(scheme));
        }
        assert_eq!(Scheme::parse("md5"), None);
    }
}
