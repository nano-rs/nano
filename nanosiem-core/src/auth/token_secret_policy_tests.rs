// SPDX-License-Identifier: AGPL-3.0-or-later
//! Security review 2026-11-08 (NAN-5053): api, search and jobs refuse the same
//! JWT secrets. Every value nano shipped as a default or example is public, so
//! anyone could sign tokens with it.

use super::validate_jwt_secret;

#[test]
fn shipped_default_and_example_secrets_are_refused() {
    for public in [
        // docker-compose.yml default (the API's old deny-list covered only this)
        "nanosiem-dev-secret-change-in-production",
        // .env.example: 36 chars, so a length-only check accepted it
        "your-jwt-secret-change-in-production",
        // docs / dev scripts
        "K7xP9qR2sT5uV8wY1zA4bC7dE0fG3hI6jK9lM2nO5pQ8r",
        "dev-e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8",
        "CHANGE_ME_GENERATED",
    ] {
        let err = validate_jwt_secret(public).expect_err(public);
        assert!(err.contains("publicly known"), "{public}: {err}");
        assert!(err.contains("openssl rand -hex 32"), "the message names the fix");
        assert!(!err.contains(public), "the message never echoes the secret");
    }
}

#[test]
fn short_secrets_are_refused_and_generated_ones_pass() {
    assert!(validate_jwt_secret("too-short").unwrap_err().contains("at least 32"));
    assert!(validate_jwt_secret(
        "5d1f0c8a9b7e6d4c3b2a19087f6e5d4c3b2a19087f6e5d4c3b2a19087f6e5d4c"
    )
    .is_ok());
}
