use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use sha2::{Digest, Sha256};

const VERSION: u8 = 1;
const NONCE_LEN: usize = 12;

/// Encrypts small secrets (channel configs) at rest with ChaCha20-Poly1305.
///
/// Sealed format: `version (1) | nonce (12) | ciphertext + tag`. The version byte
/// leaves room for key rotation.
pub struct SecretBox {
    cipher: ChaCha20Poly1305,
}

#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("SECRET_KEY must be 32 bytes, base64-encoded (generate one with `monitor gen-key`)")]
    BadKey,
    #[error("ciphertext is corrupt, or was sealed with a different key")]
    Open,
}

impl SecretBox {
    pub fn from_base64(key: &str) -> Result<Self, CryptoError> {
        let bytes = STANDARD
            .decode(key.trim())
            .map_err(|_| CryptoError::BadKey)?;
        let key = Key::try_from(bytes.as_slice()).map_err(|_| CryptoError::BadKey)?;
        Ok(Self {
            cipher: ChaCha20Poly1305::new(&key),
        })
    }

    /// A fresh random key, base64-encoded, for `SECRET_KEY`.
    pub fn generate_key() -> String {
        STANDARD.encode(rand::random::<[u8; 32]>())
    }

    pub fn seal(&self, plaintext: &[u8]) -> Vec<u8> {
        let nonce_bytes: [u8; NONCE_LEN] = rand::random();
        let ciphertext = self
            .cipher
            .encrypt(&Nonce::from(nonce_bytes), plaintext)
            .expect("ChaCha20-Poly1305 encryption is infallible for small inputs");
        let mut out = Vec::with_capacity(1 + NONCE_LEN + ciphertext.len());
        out.push(VERSION);
        out.extend_from_slice(&nonce_bytes);
        out.extend_from_slice(&ciphertext);
        out
    }

    pub fn open(&self, sealed: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let [VERSION, rest @ ..] = sealed else {
            return Err(CryptoError::Open);
        };
        if rest.len() < NONCE_LEN {
            return Err(CryptoError::Open);
        }
        let (nonce, ciphertext) = rest.split_at(NONCE_LEN);
        let nonce = Nonce::try_from(nonce).map_err(|_| CryptoError::Open)?;
        self.cipher
            .decrypt(&nonce, ciphertext)
            .map_err(|_| CryptoError::Open)
    }
}

/// 32 random bytes, base64url: for one-time links.
pub fn random_token() -> String {
    URL_SAFE_NO_PAD.encode(rand::random::<[u8; 32]>())
}

/// What we store for a one-time token, so a database leak doesn't expose live links.
pub fn sha256(token: &str) -> Vec<u8> {
    Sha256::digest(token.as_bytes()).to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn secret_box() -> SecretBox {
        SecretBox::from_base64(&SecretBox::generate_key()).unwrap()
    }

    #[test]
    fn round_trip_with_fresh_nonces() {
        let sb = secret_box();
        let a = sb.seal(b"hooks.example.com/secret");
        let b = sb.seal(b"hooks.example.com/secret");
        assert_ne!(a, b, "nonces must differ");
        assert_eq!(a[0], VERSION);
        assert_eq!(sb.open(&a).unwrap(), b"hooks.example.com/secret");
    }

    #[test]
    fn rejects_tampering_wrong_key_and_bad_versions() {
        let sb = secret_box();
        let sealed = sb.seal(b"secret");

        let mut tampered = sealed.clone();
        *tampered.last_mut().unwrap() ^= 1;
        assert!(sb.open(&tampered).is_err());

        assert!(secret_box().open(&sealed).is_err(), "different key");

        let mut wrong_version = sealed.clone();
        wrong_version[0] = 2;
        assert!(sb.open(&wrong_version).is_err());

        assert!(sb.open(&[]).is_err());
        assert!(sb.open(&[VERSION, 1, 2]).is_err());
    }

    #[test]
    fn key_must_be_32_bytes_of_base64() {
        assert!(SecretBox::from_base64("not base64!").is_err());
        assert!(SecretBox::from_base64(&STANDARD.encode([0u8; 16])).is_err());
        assert!(SecretBox::from_base64(&STANDARD.encode([0u8; 32])).is_ok());
    }
}
