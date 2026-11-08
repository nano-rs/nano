// SPDX-License-Identifier: AGPL-3.0-or-later

//! Credential encryption backed by a key ring (NAN-4933, port of main's
//! NAN-4401 CP2a readers).
//!
//! Every stored secret (cloud credentials, SOAR connections, SSO client
//! secrets, AI gateway keys, webhooks, MFA, ...) goes through
//! [`EncryptionService`]. The service holds a validated [`keyring::KeyRing`]:
//!
//! - `NANOSIEM_ENCRYPTION_KEY` as a plain string (every install before the
//!   ring) becomes root `legacy-0` with the historical byte interpretation,
//!   so existing ciphertext keeps decrypting with no manual step.
//! - `NANOSIEM_ENCRYPTION_KEY` as ring JSON names an `active` root (all new
//!   writes) plus older roots that stay decrypt-only until the background
//!   re-wrap ([`rotation`]) has moved every row off them and an operator has
//!   retired them.
//!
//! Writes keep the original unmarked AES-256-GCM format under the active root
//! (main's CP2a writer contract), so a ciphertext's key is found by bounded
//! trial decryption over the ring's explicit decrypt candidates. Marked v2
//! envelopes (`nck2:`) carry their key id in authenticated header bytes and
//! are read with caller-supplied context; they are never retried as legacy.
//!
//! Key material never reaches a log, a `Debug` impl or an error string.
mod envelope;
mod keyring;
pub mod rotation;
mod selected;
pub use envelope::{CredentialContext, CredentialScope};
pub use keyring::{KeyRole, RingKeyInfo, LEGACY_ID};
pub use selected::{v2_key_id, V2CredentialReader};

use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Nonce,
};
use base64::{engine::general_purpose::STANDARD, Engine};
use rand::RngCore;
use std::sync::{Arc, OnceLock};
use thiserror::Error;
use zeroize::Zeroizing;

/// Errors that can occur during cryptographic operations. No variant ever
/// carries key material.
#[derive(Error, Debug)]
pub enum CryptoError {
    #[error("Encryption failed: {0}")]
    EncryptionFailed(String),
    #[error("Decryption failed: {0}")]
    DecryptionFailed(String),
    #[error("Invalid key length: expected 32 bytes")]
    InvalidKeyLength,
    #[error("Invalid nonce: expected 12 bytes")]
    InvalidNonce,
    #[error("Serialization error: {0}")]
    SerializationError(String),
    #[error("SECURITY ERROR: {0}")]
    Configuration(&'static str),
    #[error("Invalid or unauthorized credential envelope")]
    InvalidEnvelope,
}

/// Encrypted data with its nonce. The outer shape is preserved by every
/// existing hand-written JSON serializer.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct EncryptedData {
    /// Base64-encoded ciphertext
    pub ciphertext: String,
    /// Base64-encoded 12-byte nonce (`nck2:`-prefixed for v2 envelopes)
    pub nonce: String,
}
// Even ciphertexts (including legacy public-key ciphertexts) do not belong in logs.
impl std::fmt::Debug for EncryptedData {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("EncryptedData([redacted])")
    }
}

/// Built-in public development key. Accepted only through
/// `NANOSIEM_ALLOW_DEFAULT_KEYS=true` (NAN-1355) or as an explicit
/// decrypt-only ring entry, so data written under it can be rotated away.
const PUBLIC_DEV_KEY: &[u8] = b"nanosiem-default-key-32bytes!!";

/// Service for encrypting and decrypting sensitive data with the key ring.
#[derive(Clone)]
pub struct EncryptionService {
    ring: Arc<keyring::KeyRing>,
    context: Option<CredentialContext>,
}

impl EncryptionService {
    /// Raw single-key constructor (tests and fixtures). Keeps the historical
    /// pad/truncate interpretation so a fixture built from an old effective key
    /// reproduces old ciphertext exactly. Production loads through
    /// [`EncryptionService::from_env`], which validates key policy.
    pub fn new(key: &[u8]) -> Self {
        Self {
            ring: Arc::new(keyring::KeyRing::raw_unchecked(key)),
            context: None,
        }
    }

    /// Parse a plain legacy string or ring JSON (see [`keyring::KeyRing::parse`]).
    pub fn from_config(config: &str) -> Result<Self, CryptoError> {
        Ok(Self {
            ring: Arc::new(keyring::KeyRing::parse(config)?),
            context: None,
        })
    }

    /// Load the ring from the environment, without caching.
    ///
    /// Order: `NANOSIEM_ENCRYPTION_KEY`, then `NANOSIEM_ENCRYPTION_KEY_FILE`
    /// (a file holding the same value, for ring JSON kept in a secret mount),
    /// then the deprecated `OIDC_SECRET_KEY` fallback, then the public
    /// development key behind `NANOSIEM_ALLOW_DEFAULT_KEYS=true`.
    pub fn try_from_env() -> Result<Self, CryptoError> {
        let allow_default_keys = std::env::var("NANOSIEM_ALLOW_DEFAULT_KEYS")
            .map(|v| v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);
        let value = std::env::var("NANOSIEM_ENCRYPTION_KEY")
            .ok()
            .filter(|v| !v.is_empty())
            .map(Zeroizing::new);
        let value = match value {
            Some(value) => Some(value),
            None => match std::env::var("NANOSIEM_ENCRYPTION_KEY_FILE")
                .ok()
                .filter(|p| !p.is_empty())
            {
                Some(path) => {
                    let raw = Zeroizing::new(std::fs::read_to_string(&path).map_err(|_| {
                        CryptoError::Configuration(
                            "NANOSIEM_ENCRYPTION_KEY_FILE is set but cannot be read",
                        )
                    })?);
                    // A trailing newline from `echo > file` is not key material.
                    Some(Zeroizing::new(raw.trim_end_matches(['\n', '\r']).to_string()))
                }
                None => None,
            },
        };
        let value = match value {
            Some(value) => Some(value),
            None => {
                let fallback = std::env::var("OIDC_SECRET_KEY")
                    .ok()
                    .filter(|v| !v.is_empty())
                    .map(Zeroizing::new);
                if fallback.is_some() {
                    tracing::warn!(
                        "SECURITY WARNING: using deprecated OIDC_SECRET_KEY as the credential \
                         encryption key; move the value into NANOSIEM_ENCRYPTION_KEY"
                    );
                }
                fallback
            }
        };
        match value {
            Some(value) => Self::from_config_with_policy(&value, allow_default_keys),
            None if allow_default_keys => {
                // NAN-1355: gate the built-in public key behind
                // NANOSIEM_ALLOW_DEFAULT_KEYS, never NANOSIEM_DEV_MODE.
                tracing::warn!(
                    "SECURITY WARNING: Using the built-in public development encryption key \
                     (NANOSIEM_ALLOW_DEFAULT_KEYS=true). Only acceptable in development — \
                     never set this in production!"
                );
                Ok(Self {
                    ring: Arc::new(keyring::KeyRing::raw_unchecked(PUBLIC_DEV_KEY)),
                    context: None,
                })
            }
            None => Err(CryptoError::Configuration(
                "No encryption key configured. Set NANOSIEM_ENCRYPTION_KEY to a secure random \
                 32-byte value (or credential ring JSON). For local development only, set \
                 NANOSIEM_ALLOW_DEFAULT_KEYS=true to use the insecure built-in default key.",
            )),
        }
    }

    fn from_config_with_policy(config: &str, allow_default_keys: bool) -> Result<Self, CryptoError> {
        match keyring::KeyRing::parse(config) {
            Ok(ring) => Ok(Self {
                ring: Arc::new(ring),
                context: None,
            }),
            // A plain string that IS public material stays usable only behind
            // the explicit development switch.
            Err(error) if allow_default_keys && !config.trim_start().starts_with('{') => {
                if config.len() >= 16 && keyring::is_public_plain(config) {
                    tracing::warn!(
                        "SECURITY WARNING: NANOSIEM_ENCRYPTION_KEY is a public placeholder value; \
                         accepted only because NANOSIEM_ALLOW_DEFAULT_KEYS=true"
                    );
                    Ok(Self {
                        ring: Arc::new(keyring::KeyRing::raw_unchecked(config.as_bytes())),
                        context: None,
                    })
                } else {
                    Err(error)
                }
            }
            Err(error) => Err(error),
        }
    }

    /// The process-wide ring from the environment, parsed once.
    ///
    /// # Panics
    /// Panics with an operator-facing message (never key material) when the
    /// configuration is missing or invalid, so a misconfigured process refuses
    /// to boot instead of writing credentials under the wrong key.
    pub fn from_env() -> Self {
        match Self::process_ring() {
            Ok(service) => service,
            Err(message) => panic!("{message}"),
        }
    }

    /// The process-wide ring (parsed once), without panicking. Used where a
    /// process may legitimately have no key (the search service's pool).
    pub fn process_ring() -> Result<Self, String> {
        static PROCESS_RING: OnceLock<Result<EncryptionService, String>> = OnceLock::new();
        PROCESS_RING
            .get_or_init(|| Self::try_from_env().map_err(|e| e.to_string()))
            .clone()
    }

    /// Callers supply authenticated scope, stable purpose, and row identity.
    pub fn with_context(
        &self,
        scope: CredentialScope,
        purpose: &'static str,
        row: impl ToString,
    ) -> Self {
        Self {
            ring: Arc::clone(&self.ring),
            context: Some(CredentialContext::new(scope, purpose, row)),
        }
    }

    /// Common field adapters retain the trusted caller scope and row identity.
    pub fn with_purpose(&self, purpose: &'static str) -> Self {
        let mut scoped = self.clone();
        if let Some(context) = &mut scoped.context {
            context.purpose = purpose;
        }
        scoped
    }

    /// Key id every new write uses.
    pub fn active_key_id(&self) -> &str {
        &self.ring.active
    }

    /// Non-secret description of every ring key (id, role, fingerprint).
    pub fn ring_keys(&self) -> Vec<RingKeyInfo> {
        self.ring.describe()
    }

    /// Writes remain exactly the old AES-GCM bytes/nonce, under the active root.
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<EncryptedData, CryptoError> {
        let nonce = random_nonce();
        let cipher =
            Aes256Gcm::new_from_slice(self.ring.active_key().as_ref()).expect("validated key");
        let ciphertext = cipher
            .encrypt(Nonce::from_slice(&nonce), plaintext)
            .map_err(|_| CryptoError::EncryptionFailed("authentication failed".into()))?;
        Ok(EncryptedData {
            ciphertext: STANDARD.encode(ciphertext),
            nonce: STANDARD.encode(nonce),
        })
    }

    /// Explicit v2 sealing (context-bound HKDF key, key id in the header).
    /// Production writers keep using `encrypt`/`encrypt_json` (CP2a contract).
    pub fn seal_v2(&self, plaintext: &[u8]) -> Result<EncryptedData, CryptoError> {
        let context = self.context.as_ref().ok_or(CryptoError::InvalidEnvelope)?;
        let header = envelope::header(&self.ring.active);
        let key = derive(self.ring.active_key().as_ref(), context)?;
        let cipher = Aes256Gcm::new_from_slice(key.as_ref()).expect("derived key");
        let nonce = random_nonce();
        let mut bytes = header.clone();
        bytes.extend(
            cipher
                .encrypt(
                    Nonce::from_slice(&nonce),
                    Payload {
                        msg: plaintext,
                        aad: &context.aad(&header)?,
                    },
                )
                .map_err(|_| CryptoError::InvalidEnvelope)?,
        );
        Ok(EncryptedData {
            ciphertext: STANDARD.encode(bytes),
            nonce: format!(
                "{}{nonce}",
                envelope::V2_NONCE_PREFIX,
                nonce = STANDARD.encode(nonce)
            ),
        })
    }

    /// Decrypt with any eligible ring key. Fails closed: a ciphertext no ring
    /// key authenticates is an error, never garbage plaintext.
    pub fn decrypt(&self, encrypted: &EncryptedData) -> Result<Vec<u8>, CryptoError> {
        self.decrypt_with_key_id(encrypted).map(|(plain, _)| plain)
    }

    /// Decrypt and report which ring key opened the ciphertext (rotation
    /// bookkeeping: a row whose key is not the active one needs a re-wrap).
    pub fn decrypt_with_key_id(
        &self,
        encrypted: &EncryptedData,
    ) -> Result<(Vec<u8>, String), CryptoError> {
        let bytes = STANDARD
            .decode(&encrypted.ciphertext)
            .map_err(|_| CryptoError::InvalidEnvelope)?;
        if let Some(nonce) = encrypted.nonce.strip_prefix(envelope::V2_NONCE_PREFIX) {
            let context = self.context.as_ref().ok_or(CryptoError::InvalidEnvelope)?;
            let nonce = decode_nonce(nonce)?;
            let (id, header, ciphertext) = envelope::parse(&bytes)?;
            let root = self.ring.keys.get(id).ok_or(CryptoError::InvalidEnvelope)?;
            let key = derive(root.as_ref(), context)?;
            let plain = Aes256Gcm::new_from_slice(key.as_ref())
                .expect("derived key")
                .decrypt(
                    Nonce::from_slice(&nonce),
                    Payload {
                        msg: ciphertext,
                        aad: &context.aad(header)?,
                    },
                )
                .map_err(|_| CryptoError::InvalidEnvelope)?;
            return Ok((plain, id.to_owned()));
        }
        let nonce = decode_nonce(&encrypted.nonce)?;
        // Explicit, bounded candidates only (active first). Never retry a
        // marked v2 as legacy.
        for id in self.ring.decrypt_candidates() {
            let cipher =
                Aes256Gcm::new_from_slice(self.ring.keys[id].as_ref()).expect("validated key");
            if let Ok(plain) = cipher.decrypt(Nonce::from_slice(&nonce), bytes.as_slice()) {
                return Ok((plain, id.clone()));
            }
        }
        Err(CryptoError::InvalidEnvelope)
    }

    /// Re-encrypt under the active key if (and only if) the ciphertext is
    /// currently under another key. `Ok(None)` = already on the active key.
    /// The plaintext is zeroized and never leaves this function.
    pub fn rewrap(
        &self,
        encrypted: &EncryptedData,
    ) -> Result<Option<(EncryptedData, String)>, CryptoError> {
        if encrypted.nonce.starts_with(envelope::V2_NONCE_PREFIX) {
            // v2 envelopes are context-bound; this process writes none, and a
            // context-free re-wrap would drop the binding. Leave them alone.
            return Ok(None);
        }
        let (plain, key_id) = self.decrypt_with_key_id(encrypted)?;
        let plain = Zeroizing::new(plain);
        if key_id == self.ring.active {
            return Ok(None);
        }
        Ok(Some((self.encrypt(&plain)?, key_id)))
    }

    /// Encrypt a JSON-serializable value
    pub fn encrypt_json<T: serde::Serialize>(
        &self,
        value: &T,
    ) -> Result<EncryptedData, CryptoError> {
        let bytes = Zeroizing::new(
            serde_json::to_vec(value)
                .map_err(|_| CryptoError::SerializationError("invalid JSON value".into()))?,
        );
        self.encrypt(&bytes)
    }

    /// Decrypt and deserialize a JSON value
    pub fn decrypt_json<T: serde::de::DeserializeOwned>(
        &self,
        encrypted: &EncryptedData,
    ) -> Result<T, CryptoError> {
        let bytes = Zeroizing::new(self.decrypt(encrypted)?);
        serde_json::from_slice(&bytes)
            .map_err(|_| CryptoError::SerializationError("invalid JSON value".into()))
    }

    /// Decrypt credentials stored as raw BYTEA ciphertext + base64 nonce.
    pub fn decrypt_credentials_bytea(
        &self,
        ciphertext: &[u8],
        nonce: &str,
    ) -> Result<std::collections::HashMap<String, String>, CryptoError> {
        self.decrypt_json(&EncryptedData::from_bytea(ciphertext, nonce))
    }
}

fn random_nonce() -> [u8; 12] {
    let mut nonce = [0u8; 12];
    rand::rng().fill_bytes(&mut nonce);
    nonce
}

fn decode_nonce(value: &str) -> Result<[u8; 12], CryptoError> {
    STANDARD
        .decode(value)
        .map_err(|_| CryptoError::InvalidNonce)?
        .try_into()
        .map_err(|_| CryptoError::InvalidNonce)
}

fn derive(root: &[u8], context: &CredentialContext) -> Result<Zeroizing<[u8; 32]>, CryptoError> {
    let mut key = Zeroizing::new([0; 32]);
    hkdf::Hkdf::<sha2_10::Sha256>::new(Some(b"nano.credential-keys.hkdf.v2"), root)
        .expand(&context.info()?, key.as_mut())
        .map_err(|_| CryptoError::InvalidEnvelope)?;
    Ok(key)
}

#[cfg(test)]
mod tests;
