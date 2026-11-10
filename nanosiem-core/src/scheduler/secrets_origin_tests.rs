// SPDX-License-Identifier: AGPL-3.0-or-later
//! Stored auth headers stay bound to the URL origin they were entered for
//! (security review 2026-11-09, NAN-5146).

use super::*;

fn map(pairs: &[(&str, &str)]) -> HashMap<String, String> {
    pairs
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

const OLD: &str = "https://feeds.vendor.example/v1/ioc.csv";

fn stored() -> HashMap<String, String> {
    map(&[("Authorization", "Bearer vendor-token")])
}

#[test]
fn origin_comparison_covers_scheme_host_and_port() {
    assert!(same_url_origin(OLD, "https://feeds.vendor.example/v2/other.json?x=1"));
    assert!(same_url_origin(OLD, "https://feeds.vendor.example:443/v1/ioc.csv"));
    assert!(same_url_origin(OLD, "https://FEEDS.vendor.example/v1/ioc.csv"));
    assert!(!same_url_origin(OLD, "https://collector.other.example/v1/ioc.csv"));
    assert!(!same_url_origin(OLD, "http://feeds.vendor.example/v1/ioc.csv"));
    assert!(!same_url_origin(OLD, "https://feeds.vendor.example:8443/v1/ioc.csv"));
    assert!(!same_url_origin(OLD, "https://feeds.vendor.example.other.example/v1"));
    assert!(!same_url_origin("not a url", OLD), "unparseable fails closed");
}

#[test]
fn cross_origin_with_omitted_headers_is_rejected() {
    let existing = stored();
    let r = merge_auth_headers_for_url(None, Some(&existing), Some(OLD), "https://other.example/x");
    assert_eq!(r, Err(AuthHeadersOriginChanged));
}

#[test]
fn cross_origin_with_echoed_placeholder_is_rejected() {
    let existing = stored();
    let incoming = map(&[("Authorization", REDACTED_PLACEHOLDER)]);
    let r = merge_auth_headers_for_url(
        Some(incoming),
        Some(&existing),
        Some(OLD),
        "https://other.example/x",
    );
    assert_eq!(r, Err(AuthHeadersOriginChanged));
}

#[test]
fn cross_origin_with_resupplied_headers_is_accepted() {
    let existing = stored();
    let incoming = map(&[("Authorization", "Bearer new-host-token")]);
    let merged = merge_auth_headers_for_url(
        Some(incoming),
        Some(&existing),
        Some(OLD),
        "https://other.example/x",
    )
    .unwrap()
    .unwrap()
    .unwrap();
    assert_eq!(merged["Authorization"], "Bearer new-host-token");
}

#[test]
fn cross_origin_with_explicit_clear_is_accepted() {
    let existing = stored();
    let merged = merge_auth_headers_for_url(
        Some(HashMap::new()),
        Some(&existing),
        Some(OLD),
        "https://other.example/x",
    )
    .unwrap()
    .unwrap()
    .unwrap();
    assert!(merged.is_empty());
}

#[test]
fn cross_origin_without_stored_headers_is_accepted() {
    assert_eq!(
        merge_auth_headers_for_url(None, None, Some(OLD), "https://other.example/x"),
        Ok(None)
    );
    let empty = HashMap::new();
    assert_eq!(
        merge_auth_headers_for_url(None, Some(&empty), Some(OLD), "https://other.example/x"),
        Ok(None)
    );
}

#[test]
fn same_origin_edit_keeps_stored_headers() {
    let existing = stored();
    // Omitted: unchanged.
    assert_eq!(
        merge_auth_headers_for_url(
            None,
            Some(&existing),
            Some(OLD),
            "https://feeds.vendor.example/v2/ioc.csv"
        ),
        Ok(None)
    );
    // Placeholder echoed: stored value kept.
    let merged = merge_auth_headers_for_url(
        Some(map(&[("Authorization", REDACTED_PLACEHOLDER)])),
        Some(&existing),
        Some(OLD),
        "https://feeds.vendor.example/v2/ioc.csv",
    )
    .unwrap()
    .unwrap()
    .unwrap();
    assert_eq!(merged["Authorization"], "Bearer vendor-token");
}

#[test]
fn fresh_create_has_no_stored_origin() {
    let incoming = map(&[("Authorization", "Bearer t")]);
    let merged = merge_auth_headers_for_url(Some(incoming), None, None, "https://new.example/x")
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(merged["Authorization"], "Bearer t");
    assert_eq!(merge_auth_headers_for_url(None, None, None, "https://new.example/x"), Ok(None));
}

#[test]
fn audit_url_drops_userinfo_query_and_fragment() {
    assert_eq!(
        redact_url_for_audit("https://u:p@feeds.example:8443/a/b?token=s#f"),
        "https://feeds.example:8443/a/b"
    );
    assert_eq!(redact_url_for_audit("::"), "<unparseable>");
}
