// SPDX-License-Identifier: AGPL-3.0-or-later

//! Unit tests for the marketplace install service.
//!
//! Split out of `install_service.rs` (NAN-2343) per the repo's
//! sibling-test-file convention; still a child module, so private
//! helpers stay reachable.

use super::*;
use serde_json::json;

#[test]
fn empty_object_is_masked_or_empty() {
    assert!(credentials_payload_is_masked_or_empty(&json!({})));
}

#[test]
fn all_empty_strings_is_masked_or_empty() {
    assert!(credentials_payload_is_masked_or_empty(
        &json!({"API_KEY": "", "OTHER": ""})
    ));
}

#[test]
fn masked_sentinel_strings_count_as_empty() {
    assert!(credentials_payload_is_masked_or_empty(
        &json!({"API_KEY": "••••••••"})
    ));
    assert!(credentials_payload_is_masked_or_empty(
        &json!({"API_KEY": "***", "TOKEN": "••••••••"})
    ));
}

#[test]
fn masked_sentinel_is_length_agnostic() {
    // P2 follow-up: the original enumerated-list approach would have
    // missed length variants. A 9-bullet, 13-bullet, or 32-star sentinel
    // (the kind a "mask each typed char" UI might produce) must also
    // route through the skip.
    for n in 1..=64 {
        let bullets: String = "•".repeat(n);
        let stars: String = "*".repeat(n);
        assert!(
            credentials_payload_is_masked_or_empty(&json!({"API_KEY": bullets})),
            "{} bullets should count as masked",
            n
        );
        assert!(
            credentials_payload_is_masked_or_empty(&json!({"API_KEY": stars})),
            "{} stars should count as masked",
            n
        );
    }
}

#[test]
fn mixed_mask_characters_count_as_masked() {
    // Don't care which mask char a future UI picks; we'd rather skip
    // than overwrite.
    assert!(credentials_payload_is_masked_or_empty(
        &json!({"API_KEY": "•*●•*"})
    ));
}

#[test]
fn real_credential_starting_with_mask_char_is_not_skipped() {
    // Avoid the false-positive where someone's real key happens to lead
    // with `*` — the trailing alphanumeric breaks the all-mask check.
    assert!(!credentials_payload_is_masked_or_empty(&json!({
        "API_KEY": "***real-value***"
    })));
}

#[test]
fn null_values_count_as_empty() {
    assert!(credentials_payload_is_masked_or_empty(
        &json!({"API_KEY": null})
    ));
}

#[test]
fn whitespace_only_strings_count_as_empty() {
    assert!(credentials_payload_is_masked_or_empty(
        &json!({"API_KEY": "   "})
    ));
}

#[test]
fn real_credential_is_not_masked_or_empty() {
    // A 48-char abuse.ch-style key.
    assert!(!credentials_payload_is_masked_or_empty(&json!({
        "API_KEY": "e6c7e5ed3c360c53e8fc66228751af99a21c45788fea66ad"
    })));
}

#[test]
fn mixed_real_and_masked_is_treated_as_real() {
    // A POST that re-sends some masked fields but also includes a real
    // new value should still write — the user provided real material.
    assert!(!credentials_payload_is_masked_or_empty(&json!({
        "API_KEY": "real-value",
        "REGION": "••••••••"
    })));
}

#[test]
fn non_string_value_counts_as_real() {
    // Numeric/bool credential configs (rare, but allowed) must not be
    // silently dropped by the guard.
    assert!(!credentials_payload_is_masked_or_empty(
        &json!({"TIMEOUT_SECS": 30})
    ));
}

#[test]
fn non_object_payload_does_not_skip() {
    // Defensive: a non-object body falls through to the existing
    // encrypt path rather than being silently swallowed.
    assert!(!credentials_payload_is_masked_or_empty(&json!("string-body")));
    assert!(!credentials_payload_is_masked_or_empty(&json!([1, 2, 3])));
}

// ============================================================================
// NAN-4959 — no bring-your-own IPinfo download URL
//
// IPinfo Lite is served only from nano's signed platform feed bundle. The
// configure and install paths refuse a `download_url` on a native entry so no
// client can reintroduce the retired BYO token sync.
// ============================================================================

/// The IPinfo Lite native catalog entry.
fn native_entry() -> MarketplaceCatalogEntry {
    MarketplaceCatalogEntry {
        slug: "ipinfo_lite".to_string(),
        execution_backend: "native".to_string(),
        native_source_id: Some("ipinfo_lite".to_string()),
        ..Default::default()
    }
}

fn validate(credentials: &serde_json::Value) -> Result<(), MarketplaceError> {
    validate_credential_values(&native_entry(), credentials)
}

#[test]
fn refuses_any_download_url_on_a_native_entry() {
    for value in [
        json!("https://ipinfo.io/data/ipinfo_lite.csv.gz?token=abc123"),
        json!("ipinfo.io/data/ipinfo_lite.csv.gz"),
        json!(""),
        json!(123),
        json!({"url": "x"}),
    ] {
        match validate(&json!({ "download_url": value })) {
            Err(MarketplaceError::InvalidCredential { field, reason }) => {
                assert_eq!(field, "download_url");
                assert!(reason.contains("platform feed bundle"), "unexpected reason: {reason}");
            }
            other => panic!("expected {value:?} to be refused, got {other:?}"),
        }
    }
}

#[test]
fn absent_null_or_masked_download_url_is_not_a_submission() {
    assert!(validate(&json!({})).is_ok());
    assert!(validate(&json!({ "download_url": null })).is_ok());
    // A frontend round-tripping its own placeholder keeps the NAN-1107 no-op.
    for sentinel in ["••••••••", "***", "●●●●"] {
        assert!(validate(&json!({ "download_url": sentinel })).is_ok());
    }
    // Other native credentials (agent provider API keys) are untouched.
    assert!(validate(&json!({ "API_KEY": "k" })).is_ok());
}

#[test]
fn other_backends_may_use_the_name() {
    for backend in ["deno", "collector", "identity"] {
        let entry = MarketplaceCatalogEntry {
            execution_backend: backend.to_string(),
            ..native_entry()
        };
        let creds = json!({ "download_url": "https://example.com/feed" });
        assert!(validate_credential_values(&entry, &creds).is_ok(), "{backend}");
    }
}
