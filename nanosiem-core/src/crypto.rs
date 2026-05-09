// SPDX-License-Identifier: AGPL-3.0-or-later

//! Cryptographic utilities for NanoSIEM
//!
//! Provides AES-256-GCM encryption for sensitive data like cloud credentials.
//! This module is used by multiple components that need to encrypt/decrypt secrets.

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use base64::Engine;
use rand::RngCore;
use thiserror::Error;

/// Errors that can occur during cryptographic operations
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
}

/// Encrypted data with its nonce
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct EncryptedData {
    /// Base64-encoded ciphertext
    pub ciphertext: String,
    /// Base64-encoded 12-byte nonce
    pub nonce: String,
}

/// Service for encrypting and decrypting sensitive data using AES-256-GCM
#[derive(Clone)]
pub struct EncryptionService {
    key: [u8; 32],
}

impl EncryptionService {
    /// Create a new encryption service with a 32-byte key
    ///
    /// If the provided key is shorter than 32 bytes, it will be zero-padded.
    /// If longer, it will be truncated.
    pub fn new(key: &[u8]) -> Self {
        let mut key_bytes = [0u8; 32];
        let len = std::cmp::min(key.len(), 32);
        key_bytes[..len].copy_from_slice(&key[..len]);
        Self { key: key_bytes }
    }

    /// Create an encryption service using the environment variable
    ///
    /// Checks `NANOSIEM_ENCRYPTION_KEY` first, then falls back to `OIDC_SECRET_KEY`
    /// for backward compatibility.
    ///
    /// # Panics
    /// Panics if no encryption key is configured and `NANOSIEM_DEV_MODE` is not set to "true".
    /// This ensures production deployments cannot accidentally run with default keys.
    pub fn from_env() -> Self {
        let key =
            std::env::var("NANOSIEM_ENCRYPTION_KEY").or_else(|_| std::env::var("OIDC_SECRET_KEY"));

        match key {
            Ok(key) if !key.is_empty() => {
                if key.len() < 16 {
                    panic!(
                        "SECURITY ERROR: Encryption key must be at least 16 bytes. \
                         Set NANOSIEM_ENCRYPTION_KEY to a secure random value (32 bytes recommended)."
                    );
                }
                Self::new(key.as_bytes())
            }
            _ => {
                // Check if development mode is explicitly enabled
                let dev_mode = std::env::var("NANOSIEM_DEV_MODE")
                    .map(|v| v.to_lowercase() == "true")
                    .unwrap_or(false);

                if dev_mode {
                    tracing::warn!(
                        "SECURITY WARNING: Using default development encryption key. \
                         This is only acceptable in development environments!"
                    );
                    Self::new(b"nanosiem-default-key-32bytes!!")
                } else {
                    panic!(
                        "SECURITY ERROR: No encryption key configured. \
                         Set NANOSIEM_ENCRYPTION_KEY environment variable to a secure random 32-byte value. \
                         If this is a development environment, set NANOSIEM_DEV_MODE=true to use default keys."
                    );
                }
            }
        }
    }

    /// Encrypt plaintext bytes and return the ciphertext with nonce
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<EncryptedData, CryptoError> {
        let cipher = Aes256Gcm::new_from_slice(&self.key)
            .map_err(|e| CryptoError::EncryptionFailed(e.to_string()))?;

        // Generate random 12-byte nonce
        let mut nonce_bytes = [0u8; 12];
        rand::rng().fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        // Encrypt
        let ciphertext = cipher
            .encrypt(nonce, plaintext)
            .map_err(|e| CryptoError::EncryptionFailed(e.to_string()))?;

        Ok(EncryptedData {
            ciphertext: base64::engine::general_purpose::STANDARD.encode(&ciphertext),
            nonce: base64::engine::general_purpose::STANDARD.encode(&nonce_bytes),
        })
    }

    /// Decrypt ciphertext using the provided nonce
    pub fn decrypt(&self, encrypted: &EncryptedData) -> Result<Vec<u8>, CryptoError> {
        let cipher = Aes256Gcm::new_from_slice(&self.key)
            .map_err(|e| CryptoError::DecryptionFailed(e.to_string()))?;

        // Decode base64
        let ciphertext = base64::engine::general_purpose::STANDARD
            .decode(&encrypted.ciphertext)
            .map_err(|e| {
                CryptoError::DecryptionFailed(format!("Invalid base64 ciphertext: {}", e))
            })?;

        let nonce_bytes = base64::engine::general_purpose::STANDARD
            .decode(&encrypted.nonce)
            .map_err(|e| CryptoError::DecryptionFailed(format!("Invalid base64 nonce: {}", e)))?;

        if nonce_bytes.len() != 12 {
            return Err(CryptoError::InvalidNonce);
        }

        let nonce = Nonce::from_slice(&nonce_bytes);

        // Decrypt
        cipher
            .decrypt(nonce, ciphertext.as_ref())
            .map_err(|e| CryptoError::DecryptionFailed(e.to_string()))
    }

    /// Encrypt a JSON-serializable value
    pub fn encrypt_json<T: serde::Serialize>(
        &self,
        value: &T,
    ) -> Result<EncryptedData, CryptoError> {
        let plaintext = serde_json::to_vec(value)
            .map_err(|e| CryptoError::SerializationError(e.to_string()))?;
        self.encrypt(&plaintext)
    }

    /// Decrypt and deserialize a JSON value
    pub fn decrypt_json<T: serde::de::DeserializeOwned>(
        &self,
        encrypted: &EncryptedData,
    ) -> Result<T, CryptoError> {
        let plaintext = self.decrypt(encrypted)?;
        serde_json::from_slice(&plaintext)
            .map_err(|e| CryptoError::SerializationError(e.to_string()))
    }

    /// Decrypt raw ciphertext bytes + nonce string into a `HashMap<String, String>`.
    ///
    /// This is the standard pattern for marketplace credentials stored as
    /// `(BYTEA ciphertext, VARCHAR nonce)` in PostgreSQL. The ciphertext is
    /// re-encoded to base64 for the `EncryptedData` struct, then decrypted
    /// and deserialized from JSON.
    pub fn decrypt_credentials_bytea(
        &self,
        ciphertext: &[u8],
        nonce: &str,
    ) -> Result<std::collections::HashMap<String, String>, CryptoError> {
        let ciphertext_b64 = base64::engine::general_purpose::STANDARD.encode(ciphertext);
        let encrypted = EncryptedData {
            ciphertext: ciphertext_b64,
            nonce: nonce.to_string(),
        };
        self.decrypt_json(&encrypted)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let service = EncryptionService::new(b"test-key-32-bytes-for-aes256!!");
        let plaintext = b"Hello, World! This is a secret message.";

        let encrypted = service.encrypt(plaintext).unwrap();
        let decrypted = service.decrypt(&encrypted).unwrap();

        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_encrypt_decrypt_json() {
        use serde::{Deserialize, Serialize};

        #[derive(Debug, Serialize, Deserialize, PartialEq)]
        struct Secret {
            access_key: String,
            secret_key: String,
        }

        let service = EncryptionService::new(b"test-key-32-bytes-for-aes256!!");
        let secret = Secret {
            access_key: "AKIAIOSFODNN7EXAMPLE".to_string(),
            secret_key: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY".to_string(),
        };

        let encrypted = service.encrypt_json(&secret).unwrap();
        let decrypted: Secret = service.decrypt_json(&encrypted).unwrap();

        assert_eq!(secret, decrypted);
    }

    #[test]
    fn test_unique_nonces() {
        let service = EncryptionService::new(b"test-key-32-bytes-for-aes256!!");
        let plaintext = b"Same message";

        let encrypted1 = service.encrypt(plaintext).unwrap();
        let encrypted2 = service.encrypt(plaintext).unwrap();

        // Nonces should be different
        assert_ne!(encrypted1.nonce, encrypted2.nonce);
        // Ciphertexts should also be different due to different nonces
        assert_ne!(encrypted1.ciphertext, encrypted2.ciphertext);
    }

    #[test]
    fn test_invalid_nonce_length() {
        let service = EncryptionService::new(b"test-key-32-bytes-for-aes256!!");
        let encrypted = EncryptedData {
            ciphertext: base64::engine::general_purpose::STANDARD.encode(b"fake"),
            nonce: base64::engine::general_purpose::STANDARD.encode(b"short"), // Only 5 bytes
        };

        let result = service.decrypt(&encrypted);
        assert!(matches!(result, Err(CryptoError::InvalidNonce)));
    }
}
