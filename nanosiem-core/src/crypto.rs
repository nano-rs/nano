// SPDX-License-Identifier: AGPL-3.0-or-later
//! Credential encryption. This reader release deliberately retains legacy writes.
mod envelope;
mod keyring;
pub use envelope::{CredentialContext, CredentialScope};

use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Nonce,
};
use base64::{engine::general_purpose::STANDARD, Engine};
use std::sync::Arc;
use thiserror::Error;
use zeroize::Zeroizing;

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

/// The outer shape is preserved by all existing hand-written JSON serializers.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct EncryptedData {
    pub ciphertext: String,
    pub nonce: String,
}
// Even ciphertexts (including legacy public-key ciphertexts) do not belong in logs.
impl std::fmt::Debug for EncryptedData {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("EncryptedData([redacted])")
    }
}

#[derive(Clone)]
pub struct EncryptionService {
    ring: Arc<keyring::KeyRing>,
    context: Option<CredentialContext>,
}
impl EncryptionService {
    /// Raw constructors enforce the same active-key policy. Historical padding is
    /// confined to an explicitly decrypt-only entry in the configuration parser.
    pub fn new(key: &[u8]) -> Self {
        Self {
            ring: Arc::new(keyring::KeyRing::raw(key).unwrap_or_else(|error| panic!("{error}"))),
            context: None,
        }
    }
    pub fn from_config(config: &str) -> Result<Self, CryptoError> {
        Ok(Self {
            ring: Arc::new(keyring::KeyRing::parse(config)?),
            context: None,
        })
    }
    pub fn try_from_env() -> Result<Self, CryptoError> {
        let value = Zeroizing::new(std::env::var("NANOSIEM_ENCRYPTION_KEY").map_err(|_| {
            if std::env::var_os("OIDC_SECRET_KEY").is_some() {
                CryptoError::Configuration("move the existing OIDC_SECRET_KEY value into NANOSIEM_ENCRYPTION_KEY; the OIDC fallback has been removed")
            } else { CryptoError::Configuration("NANOSIEM_ENCRYPTION_KEY is required; configure a generated root or credential ring JSON") }
        })?);
        Self::from_config(&value)
    }
    pub fn from_env() -> Self {
        Self::try_from_env().unwrap_or_else(|error| panic!("{error}"))
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
    pub fn active_key_id(&self) -> &str {
        &self.ring.active
    }
    /// Common field adapters retain the trusted caller scope and row identity.
    pub fn with_purpose(&self, purpose: &'static str) -> Self {
        let mut scoped = self.clone();
        if let Some(context) = &mut scoped.context {
            context.purpose = purpose;
        }
        scoped
    }

    /// Sign under the valid active root; the caller must persist active_key_id.
    pub fn keyed_mac_sha512(&self, domain: &[u8], message: &[u8]) -> [u8; 64] {
        use hmac::{Hmac, KeyInit, Mac};
        let key = &self.ring.keys[&self.ring.active];
        let mut mac =
            <Hmac<sha2::Sha512> as KeyInit>::new_from_slice(key.as_ref()).expect("validated key");
        mac.update(domain);
        mac.update(&[0]);
        mac.update(message);
        mac.finalize().into_bytes().into()
    }
    /// Verify historical HMACs only under their recorded immutable key id.
    pub fn verify_mac_sha512(
        &self,
        key_id: &str,
        domain: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), CryptoError> {
        use hmac::{Hmac, KeyInit, Mac};
        let key = self
            .ring
            .keys
            .get(key_id)
            .ok_or(CryptoError::InvalidEnvelope)?;
        let mut mac =
            <Hmac<sha2::Sha512> as KeyInit>::new_from_slice(key.as_ref()).expect("validated key");
        mac.update(domain);
        mac.update(&[0]);
        mac.update(message);
        mac.verify_slice(signature)
            .map_err(|_| CryptoError::InvalidEnvelope)
    }
    /// CP2a writes remain exactly the old AES-GCM bytes/nonce, using the active root.
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<EncryptedData, CryptoError> {
        let nonce = random_nonce();
        let cipher = Aes256Gcm::new_from_slice(self.ring.keys[&self.ring.active].as_ref())
            .expect("validated key");
        let ciphertext = cipher
            .encrypt(Nonce::from_slice(&nonce), plaintext)
            .map_err(|_| CryptoError::EncryptionFailed("authentication failed".into()))?;
        Ok(EncryptedData {
            ciphertext: STANDARD.encode(ciphertext),
            nonce: STANDARD.encode(nonce),
        })
    }
    /// Explicit v2 sealing supports compatibility fixtures and the later writer release.
    /// Production callers continue using encrypt/encrypt_json until CP2b.
    pub fn seal_v2(&self, plaintext: &[u8]) -> Result<EncryptedData, CryptoError> {
        let context = self.context.as_ref().ok_or(CryptoError::InvalidEnvelope)?;
        let header = envelope::header(&self.ring.active);
        let key = derive(self.ring.keys[&self.ring.active].as_ref(), context)?;
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
    pub fn decrypt(&self, encrypted: &EncryptedData) -> Result<Vec<u8>, CryptoError> {
        let bytes = STANDARD
            .decode(&encrypted.ciphertext)
            .map_err(|_| CryptoError::InvalidEnvelope)?;
        if let Some(nonce) = encrypted.nonce.strip_prefix(envelope::V2_NONCE_PREFIX) {
            let context = self.context.as_ref().ok_or(CryptoError::InvalidEnvelope)?;
            let nonce = decode_nonce(nonce)?;
            let (id, header, ciphertext) = envelope::parse(&bytes)?;
            let root = self.ring.keys.get(id).ok_or(CryptoError::InvalidEnvelope)?;
            let key = derive(root.as_ref(), context)?;
            return Aes256Gcm::new_from_slice(key.as_ref())
                .expect("derived key")
                .decrypt(
                    Nonce::from_slice(&nonce),
                    Payload {
                        msg: ciphertext,
                        aad: &context.aad(header)?,
                    },
                )
                .map_err(|_| CryptoError::InvalidEnvelope);
        }
        let nonce = decode_nonce(&encrypted.nonce)?;
        // Explicit, bounded candidates only. Never retry a marked v2 as legacy.
        for id in &self.ring.legacy {
            let cipher =
                Aes256Gcm::new_from_slice(self.ring.keys[id].as_ref()).expect("validated key");
            if let Ok(plain) = cipher.decrypt(Nonce::from_slice(&nonce), bytes.as_slice()) {
                return Ok(plain);
            }
        }
        Err(CryptoError::InvalidEnvelope)
    }
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
    pub fn decrypt_json<T: serde::de::DeserializeOwned>(
        &self,
        encrypted: &EncryptedData,
    ) -> Result<T, CryptoError> {
        let bytes = Zeroizing::new(self.decrypt(encrypted)?);
        serde_json::from_slice(&bytes)
            .map_err(|_| CryptoError::SerializationError("invalid JSON value".into()))
    }
    pub fn decrypt_credentials_bytea(
        &self,
        ciphertext: &[u8],
        nonce: &str,
    ) -> Result<std::collections::HashMap<String, String>, CryptoError> {
        self.decrypt_json(&EncryptedData::from_bytea(ciphertext, nonce))
    }
}
fn random_nonce() -> [u8; 12] {
    use aes_gcm::aead::rand_core::RngCore;
    let mut nonce = [0; 12];
    aes_gcm::aead::OsRng.fill_bytes(&mut nonce);
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
