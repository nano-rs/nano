// SPDX-License-Identifier: AGPL-3.0-or-later

//! Unit tests for token generation, naming, routing keys and the platform pull
//! credential (ported from main's NAN-3770 / NAN-3806 tests).

use super::*;

#[test]
fn generated_tokens_are_unique_and_shaped() {
    let a = generate_token();
    let b = generate_token();
    assert_ne!(a.value, b.value);
    assert!(a.value.starts_with(TOKEN_MARKER));
    assert_eq!(a.value.len(), TOKEN_MARKER.len() + TOKEN_RANDOM_LEN);
    assert!(a.value[TOKEN_MARKER.len()..]
        .chars()
        .all(|c| c.is_ascii_alphanumeric()));
    assert!(a.value.starts_with(&a.prefix));
    assert_eq!(a.prefix.len(), TOKEN_MARKER.len() + PREFIX_RANDOM_LEN);
    assert_eq!(a.sha256_hex, sha256_hex(&a.value));
    assert_eq!(a.sha256_hex.len(), 64);
    // The prefix check in migration 290.
    let re = regex::Regex::new("^nit_[A-Za-z0-9]{8}$").unwrap();
    assert!(re.is_match(&a.prefix));
}

#[test]
fn debug_never_prints_the_value() {
    let token = generate_token();
    let printed = format!("{token:?}");
    assert!(!printed.contains(&token.value));
    assert!(!printed.contains(&token.sha256_hex));
}

#[test]
fn sha256_hex_matches_known_vector() {
    assert_eq!(
        sha256_hex("abc"),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
}

#[test]
fn route_key_is_the_routers_first_claim() {
    let values = vec!["apache_access".to_string(), "apache".to_string()];
    assert_eq!(route_key(Some(&values), "Apache HTTP"), "apache_access");
    assert_eq!(route_key(Some(&[]), "Apache HTTP"), "apache_http");
    assert_eq!(route_key(None, "Apache HTTP"), "apache_http");
    // Never the multiplex marker: a safe name has no `*`.
    assert_ne!(route_key(None, "*"), MULTIPLEX_ROUTE);
}

#[test]
fn push_capable_transports() {
    for st in [
        "routed", "splunk_hec", "apache_access", "http", "otlp", "opentelemetry",
    ] {
        assert!(is_push_capable(st), "{st}");
    }
    for st in ["kafka", "aws_s3", "s3", "gcp_pubsub", "azure_event_hubs"] {
        assert!(!is_push_capable(st), "{st}");
    }
}

#[test]
fn otlp_assertion_binds_expiry_route_and_key() {
    let id = uuid::Uuid::from_u128(9);
    assert_eq!(otlp_identity_assertion("", &id, "r", 10), None);
    let a = otlp_identity_assertion("k", &id, "r", 10).unwrap();
    let (exp, mac) = a.split_once('.').unwrap();
    assert_eq!(exp, "10");
    assert_eq!(mac.len(), 64);
    assert_ne!(otlp_identity_assertion("k", &id, "r", 11).unwrap(), a);
    assert_ne!(otlp_identity_assertion("k", &id, "s", 10).unwrap(), a);
    assert_ne!(otlp_identity_assertion("other", &id, "r", 10).unwrap(), a);
    assert_ne!(INSTALL_CREDENTIAL_ID, PLATFORM_PULL_CREDENTIAL_ID);
}

#[test]
fn token_delivery_is_explicit() {
    assert_eq!(TokenDelivery::parse(Some("shared_volume")), TokenDelivery::SharedVolume);
    // NAN-4973: the Helm chart's pull delivery.
    assert_eq!(TokenDelivery::parse(Some("http")), TokenDelivery::Http);
    for v in [None, Some(""), Some("auto"), Some("SHARED_VOLUME"), Some("HTTP")] {
        assert_eq!(TokenDelivery::parse(v), TokenDelivery::None, "{v:?}");
    }
}

#[test]
fn vector_native_sources_take_no_token() {
    assert!(!is_push_capable("vector"));
}

#[test]
fn names_are_validated() {
    assert_eq!(normalize_name("  firewall-01 ").unwrap(), "firewall-01");
    assert!(normalize_name("").is_err());
    assert!(normalize_name("   ").is_err());
    assert!(normalize_name(&"x".repeat(MAX_NAME_LEN + 1)).is_err());
    assert!(normalize_name("bad\nname").is_err());
}

#[test]
fn install_token_mode_round_trips() {
    for mode in [InstallTokenMode::Strict, InstallTokenMode::LegacyMultiplex] {
        assert_eq!(InstallTokenMode::parse(mode.as_str()), mode);
        assert_eq!(
            serde_json::to_value(mode).unwrap(),
            serde_json::json!(mode.as_str())
        );
    }
    assert_eq!(InstallTokenMode::parse("bogus"), InstallTokenMode::Strict);
    assert_eq!(
        IngestTokenSettings::default().install_token_mode,
        InstallTokenMode::Strict
    );
}
