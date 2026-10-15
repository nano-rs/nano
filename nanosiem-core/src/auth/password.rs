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

/// Maximum accepted plaintext password length, in BYTES.
///
/// bcrypt cost is paid per hash invocation, but the caller still copies and
/// moves the plaintext, and an unbounded body lets one request dictate how much
/// work the hashing thread pool does. Every entry point that accepts a new
/// plaintext password bounds it here so the limit cannot drift between the
/// activation, reset, change and admin paths. Measured in bytes to match
/// `validate_password_complexity`, which uses `str::len()`.
pub const MAX_PASSWORD_BYTES: usize = 1024;

/// Password-related errors
#[derive(Debug, Error)]
pub enum PasswordError {
    #[error("Password hashing failed: {0}")]
    HashingFailed(String),

    #[error("Password verification failed: {0}")]
    VerificationFailed(String),

    #[error("Password does not meet complexity requirements: {0}")]
    ComplexityNotMet(String),

    /// The plaintext exceeded [`MAX_PASSWORD_BYTES`]. Carries only the limit —
    /// never the password or its actual length.
    #[error("Password must be at most {0} bytes long")]
    TooLong(usize),
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
///
/// It also enforces the upper bound ([`MAX_PASSWORD_BYTES`]): this is the single
/// function every new-password path funnels through, so the cap belongs here
/// rather than being restated at each call site.
pub fn validate_password(password: &str) -> Result<(), PasswordError> {
    if password.len() > MAX_PASSWORD_BYTES {
        return Err(PasswordError::TooLong(MAX_PASSWORD_BYTES));
    }

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
    fn test_validate_password_rejects_over_max_bytes() {
        // Complexity-compliant prefix, but one byte past the cap.
        let password = format!("Aa1!{}", "x".repeat(MAX_PASSWORD_BYTES));
        assert!(password.len() > MAX_PASSWORD_BYTES);

        match validate_password(&password) {
            Err(PasswordError::TooLong(limit)) => assert_eq!(limit, MAX_PASSWORD_BYTES),
            other => panic!("expected TooLong, got {other:?}"),
        }
    }

    #[test]
    fn test_validate_password_accepts_exactly_max_bytes() {
        let password = format!("Aa1!{}", "x".repeat(MAX_PASSWORD_BYTES - 4));
        assert_eq!(password.len(), MAX_PASSWORD_BYTES);
        assert!(validate_password(&password).is_ok());
    }

    #[test]
    fn test_validate_password_max_is_measured_in_bytes() {
        // Each em-dash is 3 bytes: 342 of them + "Aa1!" exceeds the cap while
        // the char count (346) stays far below it.
        let password = format!("Aa1!{}", "—".repeat(342));
        assert!(password.chars().count() < MAX_PASSWORD_BYTES);
        assert!(password.len() > MAX_PASSWORD_BYTES);
        assert!(matches!(
            validate_password(&password),
            Err(PasswordError::TooLong(_))
        ));
    }

    #[test]
    fn test_special_char_set_is_complete() {
        // The browser mirrors this set character-for-character
        // (nanosiem-web/src/lib/password.ts). Any addition here must be added
        // there too.
        for c in "!@#$%^&*()-_=+[]{}|\\;:'\",.<>/?`~".chars() {
            assert!(is_special_char(c), "{c:?} should count as special");
        }
        for c in "abzABZ09 \t\u{00e9}".chars() {
            assert!(!is_special_char(c), "{c:?} should not count as special");
        }
    }

    /// Documents why `MAX_PASSWORD_BYTES` is a resource bound, not a strength
    /// bound: bcrypt uses only the first 72 bytes and silently ignores the rest,
    /// so anything past 72 adds no entropy. If a future bcrypt release starts
    /// returning an error instead of truncating, this test fails and the cap
    /// must be revisited (an accepted password would otherwise 500 at hash
    /// time).
    #[test]
    fn hashing_accepts_every_length_the_policy_admits() {
        for length in [12usize, 72, 73, 200, MAX_PASSWORD_BYTES] {
            let password = format!("Aa1!{}", "x".repeat(length - 4));
            assert_eq!(password.len(), length);
            assert!(validate_password(&password).is_ok(), "len {length} must validate");
            assert!(
                hash_password(&password).is_ok(),
                "len {length} must hash without error"
            );
        }
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
