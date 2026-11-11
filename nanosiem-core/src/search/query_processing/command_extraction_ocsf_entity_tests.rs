// SPDX-License-Identifier: AGPL-3.0-or-later

//! `| asset` / `| baseline` entity seeds named by OCSF paths (NAN-5277).

use super::*;
use crate::query::parse_query;

fn asset_seed(npl: &str) -> Option<(String, String)> {
    let q = parse_query(npl).unwrap_or_else(|e| panic!("{npl}: {e}"));
    let info = extract_asset_command(&q).expect("asset command");
    extract_asset_identifier_from_query(&q, &info)
}

fn baseline_seed(npl: &str) -> Option<(String, String)> {
    let q = parse_query(npl).unwrap_or_else(|e| panic!("{npl}: {e}"));
    let info = extract_baseline_command(&q).expect("baseline command");
    resolve_baseline_entity(&q, &info)
}

#[test]
fn canonical_entity_field_maps_ocsf_paths() {
    for (field, canonical) in [
        ("src_host", "src_host"),
        ("device.hostname", "src_host"),
        ("src_endpoint.hostname", "src_host"),
        ("src_host_unified", "src_host"),
        ("dst_endpoint.hostname", "dest_host"),
        ("src_endpoint.ip", "src_ip"),
        ("dst_endpoint.ip", "dest_ip"),
        ("user", "user"),
        ("user.name", "user"),
        ("actor.user.name", "user"),
        ("user_unified", "user"),
        ("mac", "mac"),
    ] {
        assert_eq!(canonical_entity_field(field), Some(canonical), "{field}");
    }
    for field in ["process.name", "class_uid", "message", "dest_user"] {
        assert_eq!(canonical_entity_field(field), None, "{field}");
    }
}

/// Before NAN-5277 only the UDM names seeded `| asset` from the query; an OCSF
/// path fell back to a throwaway search and could pick a different entity.
#[test]
fn asset_fast_path_accepts_ocsf_paths() {
    assert_eq!(
        asset_seed(r#"device.hostname="ws-it-029.corp.local" | asset"#),
        Some(("src_host".into(), "ws-it-029.corp.local".into()))
    );
    // Authentication (3002): the account is in `user.name`.
    assert_eq!(
        asset_seed(r#"class_uid=3002 user.name="gtorres" | asset"#),
        Some(("user".into(), "gtorres".into()))
    );
    // Endpoint classes: the account is in `actor.user.name`.
    assert_eq!(
        asset_seed(r#"actor.user.name="pgarcia" | asset"#),
        Some(("user".into(), "pgarcia".into()))
    );
    assert_eq!(
        asset_seed(r#"src_endpoint.ip="10.1.2.3" | asset"#),
        Some(("src_ip".into(), "10.1.2.3".into()))
    );
    // UDM names are unchanged.
    assert_eq!(
        asset_seed(r#"src_host="ws-1" | asset"#),
        Some(("src_host".into(), "ws-1".into()))
    );
    // A non-entity filter still has no fast-path seed.
    assert_eq!(asset_seed("class_uid=3002 | asset"), None);
}

#[test]
fn asset_explicit_field_matches_across_vocabularies() {
    // `field=src_host` matches an OCSF host filter and the reverse.
    assert_eq!(
        asset_seed(r#"device.hostname="ws-1" | asset field=src_host"#),
        Some(("src_host".into(), "ws-1".into()))
    );
    assert_eq!(
        asset_seed(r#"user="bob" | asset field=user.name"#),
        Some(("user".into(), "bob".into()))
    );
    // Different concepts never match.
    assert_eq!(asset_seed(r#"user.name="bob" | asset field=src_host"#), None);
}

#[test]
fn baseline_infers_entity_from_ocsf_paths() {
    for (npl, kind, value) in [
        (r#"device.hostname="ws-it-029.corp.local" | baseline"#, "host", "ws-it-029.corp.local"),
        (r#"src_endpoint.hostname="lt-mkt-045" | baseline"#, "host", "lt-mkt-045"),
        (r#"dst_endpoint.hostname="dc01" | baseline"#, "host", "dc01"),
        (r#"user.name="gtorres" | baseline"#, "user", "gtorres"),
        (r#"actor.user.name="pgarcia" | baseline"#, "user", "pgarcia"),
        (r#"src_endpoint.ip="10.1.2.3" | baseline"#, "ip", "10.1.2.3"),
        (r#"src_host="ws-1" | baseline"#, "host", "ws-1"),
    ] {
        assert_eq!(
            baseline_seed(npl),
            Some((kind.to_string(), value.to_string())),
            "{npl}"
        );
    }
    assert_eq!(baseline_seed("class_uid=3002 | baseline"), None);
}
