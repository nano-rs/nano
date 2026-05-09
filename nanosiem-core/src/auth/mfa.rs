// SPDX-License-Identifier: AGPL-3.0-or-later

//! TOTP Multi-Factor Authentication Service
//!
//! Provides TOTP (RFC 6238) enrollment, verification, and backup code management.
//! Uses Google Authenticator-compatible settings (SHA1, 6 digits, 30s step).

use base64::Engine;
use thiserror::Error;
use totp_rs::{Algorithm, Secret, TOTP};

use crate::crypto::{CryptoError, EncryptedData, EncryptionService};

/// MFA-related errors
#[derive(Debug, Error)]
pub enum MfaError {
    #[error("TOTP generation failed: {0}")]
    TotpError(String),
    #[error("Invalid TOTP code")]
    InvalidCode,
    #[error("MFA is not enabled for this user")]
    NotEnabled,
    #[error("MFA is already enabled for this user")]
    AlreadyEnabled,
    #[error("No pending TOTP secret found — start setup first")]
    NoPendingSecret,
    #[error("Invalid backup code")]
    InvalidBackupCode,
    #[error("No backup codes remaining")]
    NoBackupCodes,
    #[error("Encryption error: {0}")]
    EncryptionError(String),
    #[error("Invalid or expired MFA challenge")]
    InvalidChallenge,
    #[error("OIDC users cannot configure MFA (managed by identity provider)")]
    OidcUserNotAllowed,
    #[error("Password verification failed")]
    PasswordVerificationFailed,
}

impl From<CryptoError> for MfaError {
    fn from(err: CryptoError) -> Self {
        MfaError::EncryptionError(err.to_string())
    }
}

/// Generate a new TOTP secret and return the TOTP object + base32 secret
pub fn generate_totp_secret(email: &str) -> Result<(TOTP, String), MfaError> {
    let secret = Secret::generate_secret();
    let secret_base32 = secret.to_encoded().to_string();

    let totp = TOTP::new(
        Algorithm::SHA1,
        6,  // digits
        1,  // skew (allows ±1 period = 30 second tolerance)
        30, // step (seconds)
        secret
            .to_bytes()
            .map_err(|e| MfaError::TotpError(e.to_string()))?,
        Some("nano".to_string()),
        email.to_string(),
    )
    .map_err(|e| MfaError::TotpError(e.to_string()))?;

    Ok((totp, secret_base32))
}

/// Generate a QR code as a base64-encoded PNG from a TOTP object
pub fn generate_qr_code(totp: &TOTP) -> Result<String, MfaError> {
    totp.get_qr_base64()
        .map_err(|e| MfaError::TotpError(e.to_string()))
}

/// Reconstruct a TOTP from a base32 secret for verification
pub fn totp_from_secret(secret_base32: &str, email: &str) -> Result<TOTP, MfaError> {
    let secret = Secret::Encoded(secret_base32.to_string());
    TOTP::new(
        Algorithm::SHA1,
        6,
        1,
        30,
        secret
            .to_bytes()
            .map_err(|e| MfaError::TotpError(e.to_string()))?,
        Some("nano".to_string()),
        email.to_string(),
    )
    .map_err(|e| MfaError::TotpError(e.to_string()))
}

/// Verify a TOTP code against a base32 secret
pub fn verify_totp(secret_base32: &str, email: &str, code: &str) -> Result<bool, MfaError> {
    let totp = totp_from_secret(secret_base32, email)?;
    Ok(totp
        .check_current(code)
        .map_err(|e| MfaError::TotpError(e.to_string()))?)
}

/// Generate 10 random 8-character alphanumeric backup codes
pub fn generate_backup_codes() -> Vec<String> {
    use rand::Rng;
    let mut rng = rand::rng();
    let charset: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789"; // No ambiguous chars (0/O, 1/I)

    (0..10)
        .map(|_| {
            let code: String = (0..8)
                .map(|_| {
                    let idx = rng.random_range(0..charset.len());
                    charset[idx] as char
                })
                .collect();
            // Format as XXXX-XXXX for readability
            format!("{}-{}", &code[..4], &code[4..])
        })
        .collect()
}

/// Hash backup codes with bcrypt (cost 10, lower than passwords since codes are random)
pub fn hash_backup_codes(codes: &[String]) -> Vec<String> {
    codes
        .iter()
        .map(|code| {
            // Strip dashes for hashing (user may enter with or without)
            let normalized = code.replace('-', "");
            bcrypt::hash(normalized, 10).expect("bcrypt hashing should not fail")
        })
        .collect()
}

/// Verify a backup code against a list of hashed codes.
/// Returns the index of the matching code (for removal after use).
pub fn verify_backup_code(code: &str, hashed_codes: &[String]) -> Option<usize> {
    let normalized = code.replace('-', "").to_uppercase();
    for (i, hash) in hashed_codes.iter().enumerate() {
        if bcrypt::verify(&normalized, hash).unwrap_or(false) {
            return Some(i);
        }
    }
    None
}

/// Encrypt a TOTP secret for database storage
pub fn encrypt_secret(
    secret_base32: &str,
    encryption: &EncryptionService,
) -> Result<EncryptedData, MfaError> {
    encryption
        .encrypt(secret_base32.as_bytes())
        .map_err(MfaError::from)
}

/// Decrypt a TOTP secret from database storage
pub fn decrypt_secret(
    ciphertext: &[u8],
    nonce: &str,
    encryption: &EncryptionService,
) -> Result<String, MfaError> {
    let encrypted = EncryptedData {
        ciphertext: base64::engine::general_purpose::STANDARD.encode(ciphertext),
        nonce: nonce.to_string(),
    };
    let plaintext = encryption.decrypt(&encrypted)?;
    String::from_utf8(plaintext).map_err(|e| MfaError::EncryptionError(e.to_string()))
}

/// Encrypt backup code hashes for database storage
pub fn encrypt_backup_codes(
    hashed_codes: &[String],
    encryption: &EncryptionService,
) -> Result<EncryptedData, MfaError> {
    encryption
        .encrypt_json(&hashed_codes.to_vec())
        .map_err(MfaError::from)
}

/// Decrypt backup code hashes from database storage
pub fn decrypt_backup_codes(
    ciphertext: &[u8],
    nonce: &str,
    encryption: &EncryptionService,
) -> Result<Vec<String>, MfaError> {
    let encrypted = EncryptedData {
        ciphertext: base64::engine::general_purpose::STANDARD.encode(ciphertext),
        nonce: nonce.to_string(),
    };
    encryption.decrypt_json(&encrypted).map_err(MfaError::from)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_totp_secret() {
        let (totp, secret) = generate_totp_secret("test@example.com").unwrap();
        assert!(!secret.is_empty());
        // Verify we can generate a code (doesn't panic)
        let _code = totp.generate_current().unwrap();
    }

    #[test]
    fn test_verify_totp() {
        let (totp, secret) = generate_totp_secret("test@example.com").unwrap();
        let code = totp.generate_current().unwrap();
        assert!(verify_totp(&secret, "test@example.com", &code).unwrap());
        assert!(!verify_totp(&secret, "test@example.com", "000000").unwrap());
    }

    #[test]
    fn test_backup_codes() {
        let codes = generate_backup_codes();
        assert_eq!(codes.len(), 10);
        // Check format: XXXX-XXXX
        for code in &codes {
            assert_eq!(code.len(), 9); // 4 + 1 + 4
            assert_eq!(&code[4..5], "-");
        }

        let hashed = hash_backup_codes(&codes);
        assert_eq!(hashed.len(), 10);

        // Verify first code matches
        let idx = verify_backup_code(&codes[0], &hashed);
        assert_eq!(idx, Some(0));

        // Verify with stripped dashes
        let stripped = codes[0].replace('-', "");
        let idx = verify_backup_code(&stripped, &hashed);
        assert_eq!(idx, Some(0));

        // Invalid code doesn't match
        let idx = verify_backup_code("ZZZZ-ZZZZ", &hashed);
        assert!(idx.is_none());
    }
}
