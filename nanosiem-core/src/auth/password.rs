// SPDX-License-Identifier: AGPL-3.0-or-later

//! Password hashing and validation utilities
//!
//! Requirements: 1.1, 1.4
//!
//! This module provides:
//! - Password hashing using bcrypt
//! - Password verification for login
//! - Password complexity validation

use thiserror::Error;

/// Password-related errors
#[derive(Debug, Error)]
pub enum PasswordError {
    #[error("Password hashing failed: {0}")]
    HashingFailed(String),

    #[error("Password verification failed: {0}")]
    VerificationFailed(String),

    #[error("Password does not meet complexity requirements: {0}")]
    ComplexityNotMet(String),
}

/// Result of password complexity validation
#[derive(Debug, Clone)]
pub struct PasswordValidationResult {
    pub is_valid: bool,
    pub errors: Vec<String>,
}

impl PasswordValidationResult {
    pub fn valid() -> Self {
        Self {
            is_valid: true,
            errors: Vec::new(),
        }
    }

    pub fn invalid(errors: Vec<String>) -> Self {
        Self {
            is_valid: false,
            errors,
        }
    }
}

/// Password complexity requirements
/// Requirements: 1.4 - minimum 12 characters, mixed case, numbers, special characters
#[derive(Debug, Clone)]
pub struct PasswordRequirements {
    /// Minimum password length (default: 12)
    pub min_length: usize,
    /// Require at least one uppercase letter
    pub require_uppercase: bool,
    /// Require at least one lowercase letter
    pub require_lowercase: bool,
    /// Require at least one digit
    pub require_digit: bool,
    /// Require at least one special character
    pub require_special: bool,
}

impl Default for PasswordRequirements {
    fn default() -> Self {
        Self {
            min_length: 12,
            require_uppercase: true,
            require_lowercase: true,
            require_digit: true,
            require_special: true,
        }
    }
}

/// Hash a password using bcrypt
///
/// Requirements: 1.1 - Store user credentials with bcrypt-hashed passwords
///
/// # Arguments
/// * `password` - The plaintext password to hash
///
/// # Returns
/// * `Ok(String)` - The bcrypt hash of the password
/// * `Err(PasswordError)` - If hashing fails
pub fn hash_password(password: &str) -> Result<String, PasswordError> {
    // Use default cost factor of 12 (good balance of security and performance)
    bcrypt::hash(password, bcrypt::DEFAULT_COST)
        .map_err(|e| PasswordError::HashingFailed(e.to_string()))
}

/// Verify a password against a bcrypt hash
///
/// Requirements: 1.1 - Credential validation for login
///
/// # Arguments
/// * `password` - The plaintext password to verify
/// * `hash` - The bcrypt hash to verify against
///
/// # Returns
/// * `Ok(true)` - If the password matches the hash
/// * `Ok(false)` - If the password does not match
/// * `Err(PasswordError)` - If verification fails due to invalid hash format
pub fn verify_password(password: &str, hash: &str) -> Result<bool, PasswordError> {
    bcrypt::verify(password, hash).map_err(|e| PasswordError::VerificationFailed(e.to_string()))
}

/// Validate password complexity against requirements
///
/// Requirements: 1.4 - Enforce password complexity requirements
/// (minimum 12 characters, mixed case, numbers, special characters)
///
/// # Arguments
/// * `password` - The password to validate
/// * `requirements` - The complexity requirements to check against
///
/// # Returns
/// * `PasswordValidationResult` - Contains whether the password is valid and any error messages
pub fn validate_password_complexity(
    password: &str,
    requirements: &PasswordRequirements,
) -> PasswordValidationResult {
    let mut errors = Vec::new();

    // Check minimum length
    if password.len() < requirements.min_length {
        errors.push(format!(
            "Password must be at least {} characters long",
            requirements.min_length
        ));
    }

    // Check for uppercase letter
    if requirements.require_uppercase && !password.chars().any(|c| c.is_ascii_uppercase()) {
        errors.push("Password must contain at least one uppercase letter".to_string());
    }

    // Check for lowercase letter
    if requirements.require_lowercase && !password.chars().any(|c| c.is_ascii_lowercase()) {
        errors.push("Password must contain at least one lowercase letter".to_string());
    }

    // Check for digit
    if requirements.require_digit && !password.chars().any(|c| c.is_ascii_digit()) {
        errors.push("Password must contain at least one digit".to_string());
    }

    // Check for special character
    if requirements.require_special && !password.chars().any(is_special_char) {
        errors.push("Password must contain at least one special character".to_string());
    }

    if errors.is_empty() {
        PasswordValidationResult::valid()
    } else {
        PasswordValidationResult::invalid(errors)
    }
}

/// Check if a character is a special character
fn is_special_char(c: char) -> bool {
    // Common special characters allowed in passwords
    matches!(
        c,
        '!' | '@'
            | '#'
            | '$'
            | '%'
            | '^'
            | '&'
            | '*'
            | '('
            | ')'
            | '-'
            | '_'
            | '='
            | '+'
            | '['
            | ']'
            | '{'
            | '}'
            | '|'
            | '\\'
            | ';'
            | ':'
            | '\''
            | '"'
            | ','
            | '.'
            | '<'
            | '>'
            | '/'
            | '?'
            | '`'
            | '~'
    )
}

/// Validate password with default requirements and return an error if invalid
///
/// This is a convenience function that uses default requirements and returns
/// a PasswordError if the password doesn't meet them.
pub fn validate_password(password: &str) -> Result<(), PasswordError> {
    let requirements = PasswordRequirements::default();
    let result = validate_password_complexity(password, &requirements);

    if result.is_valid {
        Ok(())
    } else {
        Err(PasswordError::ComplexityNotMet(result.errors.join("; ")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_and_verify_password() {
        let password = "SecureP@ssw0rd!";
        let hash = hash_password(password).expect("Hashing should succeed");

        // Verify correct password
        assert!(verify_password(password, &hash).expect("Verification should succeed"));

        // Verify incorrect password
        assert!(!verify_password("WrongPassword", &hash).expect("Verification should succeed"));
    }

    #[test]
    fn test_password_complexity_valid() {
        let requirements = PasswordRequirements::default();
        let password = "SecureP@ssw0rd!";

        let result = validate_password_complexity(password, &requirements);
        assert!(result.is_valid);
        assert!(result.errors.is_empty());
    }

    #[test]
    fn test_password_complexity_too_short() {
        let requirements = PasswordRequirements::default();
        let password = "Short1!";

        let result = validate_password_complexity(password, &requirements);
        assert!(!result.is_valid);
        assert!(result
            .errors
            .iter()
            .any(|e| e.contains("at least 12 characters")));
    }

    #[test]
    fn test_password_complexity_no_uppercase() {
        let requirements = PasswordRequirements::default();
        let password = "securep@ssw0rd!";

        let result = validate_password_complexity(password, &requirements);
        assert!(!result.is_valid);
        assert!(result.errors.iter().any(|e| e.contains("uppercase")));
    }

    #[test]
    fn test_password_complexity_no_lowercase() {
        let requirements = PasswordRequirements::default();
        let password = "SECUREP@SSW0RD!";

        let result = validate_password_complexity(password, &requirements);
        assert!(!result.is_valid);
        assert!(result.errors.iter().any(|e| e.contains("lowercase")));
    }

    #[test]
    fn test_password_complexity_no_digit() {
        let requirements = PasswordRequirements::default();
        let password = "SecureP@ssword!";

        let result = validate_password_complexity(password, &requirements);
        assert!(!result.is_valid);
        assert!(result.errors.iter().any(|e| e.contains("digit")));
    }

    #[test]
    fn test_password_complexity_no_special() {
        let requirements = PasswordRequirements::default();
        let password = "SecurePassw0rd";

        let result = validate_password_complexity(password, &requirements);
        assert!(!result.is_valid);
        assert!(result.errors.iter().any(|e| e.contains("special")));
    }

    #[test]
    fn test_password_complexity_multiple_errors() {
        let requirements = PasswordRequirements::default();
        let password = "short";

        let result = validate_password_complexity(password, &requirements);
        assert!(!result.is_valid);
        // Should have multiple errors
        assert!(result.errors.len() > 1);
    }

    #[test]
    fn test_validate_password_convenience() {
        // Valid password
        assert!(validate_password("SecureP@ssw0rd!").is_ok());

        // Invalid password
        assert!(validate_password("weak").is_err());
    }

    #[test]
    fn test_custom_requirements() {
        let requirements = PasswordRequirements {
            min_length: 8,
            require_uppercase: false,
            require_lowercase: true,
            require_digit: true,
            require_special: false,
        };

        // This would fail default requirements but passes custom
        let password = "password123";
        let result = validate_password_complexity(password, &requirements);
        assert!(result.is_valid);
    }
}
