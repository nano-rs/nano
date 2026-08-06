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
// NAN-2343 — download_url validation at save time
//
// Regression cover for a support incident: a malformed download URL was
// persisted verbatim by the marketplace configure path (which validated
// nothing), then surfaced minutes later as
// "Download error: URL rejected by SSRF check before fetch: Invalid URL:
// relative URL without a base". The wording sent everyone hunting a security
// regression; the actual fault was that `Url::parse` had never been given a
// URL, and the operator was never told at the point they could fix it.
// ============================================================================

/// A native catalog entry — the only backend whose `download_url` this crate
/// claims to understand.
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

/// The reason string for a rejected `download_url`, or a panic naming what
/// came back instead.
fn rejection_reason(url: &str) -> String {
    match validate(&json!({ "download_url": url })) {
        Err(MarketplaceError::InvalidCredential { field, reason }) => {
            assert_eq!(field, "download_url", "error must name the offending field");
            reason
        }
        Err(other) => panic!("expected InvalidCredential for {url:?}, got {other:?}"),
        Ok(()) => panic!("expected {url:?} to be rejected, but it was accepted"),
    }
}

#[test]
fn accepts_a_well_formed_ipinfo_download_url() {
    let creds = json!({
        "download_url": "https://ipinfo.io/data/ipinfo_lite.csv.gz?token=abc123",
    });
    assert!(validate(&creds).is_ok());
}

#[test]
fn rejects_the_paste_artifacts_a_masked_field_hides() {
    // Every one of these renders identically as `••••••••`, which is why the
    // operator could not spot the problem and support could not either. All
    // produce `RelativeUrlWithoutBase` — the reported error.
    let good = "https://ipinfo.io/data/ipinfo_lite.csv.gz?token=abc123";
    for bad in [
        // scheme dropped, by far the most common
        "ipinfo.io/data/ipinfo_lite.csv.gz?token=abc123",
        // copied with surrounding punctuation
        &format!("\"{good}\""),
        &format!("<{good}>"),
        // copied from documentation as a command
        &format!("curl {good}"),
        &format!("wget {good}"),
    ] {
        let reason = rejection_reason(bad);
        assert!(
            reason.contains("relative URL without a base"),
            "unexpected reason for {bad:?}: {reason}"
        );
    }
}

#[test]
fn rejects_the_truncated_snapshots_the_shortcut_bug_produced() {
    // The ⌘↵ handler captured `credentials` at the first change event, so
    // typing a URL and pressing the shortcut persisted the opening keystrokes.
    // The frontend no longer does this; validation makes it unstorable
    // regardless of which client submits it.
    for truncated in ["h", "ht", "http", "https"] {
        let reason = rejection_reason(truncated);
        assert!(
            reason.contains("relative URL without a base"),
            "unexpected reason for {truncated:?}: {reason}"
        );
    }
    // A scheme with no host is a different parse error but equally unusable.
    for hostless in ["https:", "https://"] {
        rejection_reason(hostless);
    }
}

#[test]
fn rejects_blank_download_url_in_a_mixed_payload() {
    // An all-blank payload is short-circuited earlier by
    // `credentials_payload_is_masked_or_empty`, but a blank URL alongside real
    // material would otherwise persist an empty string — which parses as
    // `RelativeUrlWithoutBase` and reads to the operator as an SSRF rejection.
    for blank in ["", "   "] {
        let creds = json!({ "download_url": blank, "OTHER": "real-value" });
        match validate(&creds) {
            Err(MarketplaceError::InvalidCredential { field, reason }) => {
                assert_eq!(field, "download_url");
                assert!(reason.contains("empty"), "unexpected reason: {reason}");
            }
            other => panic!("expected blank {blank:?} to be rejected, got {other:?}"),
        }
    }
}

#[test]
fn accepts_urls_that_only_look_malformed() {
    // `Url::parse` tolerates surrounding whitespace and a trailing newline, so
    // these are NOT a cause of the reported failure — asserted so a future
    // "helpful" trim isn't mistaken for a fix, and so nobody sends a customer
    // chasing invisible whitespace.
    let good = "https://ipinfo.io/data/ipinfo_lite.csv.gz?token=abc123";
    for tolerated in [format!(" {good} "), format!("{good}\n")] {
        assert!(
            validate(&json!({ "download_url": tolerated })).is_ok(),
            "expected {tolerated:?} to be accepted"
        );
    }
}

#[test]
fn still_enforces_ssrf_policy_on_a_parseable_url() {
    // Save-time validation is deliberately DNS-free, but everything decidable
    // from the string itself is still refused here rather than at fetch time.
    for blocked in [
        "http://127.0.0.1/data.csv.gz",
        "http://169.254.169.254/latest/meta-data/",
        "file:///etc/passwd",
    ] {
        let reason = rejection_reason(blocked);
        assert!(
            !reason.contains("relative URL without a base"),
            "{blocked:?} parses fine; it must be refused on policy, not parsing: {reason}"
        );
    }
}

#[test]
fn ignores_payloads_without_a_download_url() {
    // Other backends' credentials are opaque secrets with no schema to check.
    let creds = json!({ "API_KEY": "not-a-url", "TIMEOUT_SECS": 30 });
    assert!(validate(&creds).is_ok());
}

#[test]
fn rejects_a_lone_blank_download_url() {
    // The operator clears the field and saves. `credentials_payload_is_masked_
    // _or_empty` calls this payload "empty" and skips the write, so without an
    // explicit check the API answered 200 "Credentials saved" having changed
    // nothing — the same class of silent success this whole issue is about.
    // Validation runs ahead of that shortcut so the submission is refused.
    for blank in ["", "   "] {
        let reason = rejection_reason(blank);
        assert!(reason.contains("empty"), "unexpected reason: {reason}");
    }
}

#[test]
fn rejects_a_non_string_download_url() {
    // The write path reads this with `as_str()`, so a number/bool/object/null
    // would be accepted, silently skipped, and reported as saved.
    for wrong_type in [json!(123), json!(true), json!({"url": "x"}), json!(["x"])] {
        match validate(&json!({ "download_url": wrong_type })) {
            Err(MarketplaceError::InvalidCredential { field, reason }) => {
                assert_eq!(field, "download_url");
                assert!(reason.contains("string"), "unexpected reason: {reason}");
            }
            other => panic!("expected {wrong_type:?} to be rejected, got {other:?}"),
        }
    }
    // JSON null is "absent" rather than a wrong-typed value, and the masked/
    // empty guard already skips it.
    assert!(validate(&json!({ "download_url": null })).is_ok());
}

#[test]
fn lets_a_masked_sentinel_through_to_the_nan1107_skip() {
    // A frontend round-tripping its own `••••••••` placeholder must keep
    // hitting the silent no-op that protects the stored value — turning that
    // into a 422 would break the NAN-1107 contract.
    for sentinel in ["••••••••", "***", "●●●●"] {
        assert!(
            validate(&json!({ "download_url": sentinel })).is_ok(),
            "masked sentinel {sentinel:?} must not be rejected"
        );
        assert!(credentials_payload_is_masked_or_empty(
            &json!({ "download_url": sentinel })
        ));
    }
}

#[test]
fn does_not_impose_the_url_contract_on_other_backends() {
    // `download_url` is not a reserved name. A third-party Deno or collector
    // manifest may use it for something that is legitimately not an http URL,
    // and only native entries have their value copied into a column that this
    // crate's fetcher dereferences.
    for backend in ["deno", "collector", "identity"] {
        let entry = MarketplaceCatalogEntry {
            execution_backend: backend.to_string(),
            ..native_entry()
        };
        let creds = json!({ "download_url": "not-a-url-at-all" });
        assert!(
            validate_credential_values(&entry, &creds).is_ok(),
            "{backend} entries must not inherit the native URL contract"
        );
    }
}
