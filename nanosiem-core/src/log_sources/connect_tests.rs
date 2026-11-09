// SPDX-License-Identifier: AGPL-3.0-or-later

//! Pure tests for the connect-first read models (NAN-4912 P2).

use std::collections::BTreeSet;

use chrono::{TimeZone, Utc};
use uuid::Uuid;

use super::connect::*;
use super::types::LogSource;
use crate::auth::ScopeSet;
use crate::ingest_tokens::IngestToken;

fn source(name: &str, match_values: Option<&[&str]>, deployed: bool) -> LogSource {
    let json = serde_json::json!({
        "id": Uuid::new_v4().to_string(),
        "name": name,
        "description": null,
        "source_type": "routed",
        "parser_vrl": "",
        "output_fields": null,
        "category": null, "vendor": null, "product": null, "icon": null, "color": null,
        "match_field": null, "match_pattern": null,
        "match_values": match_values.map(|v| v.iter().map(|s| s.to_string()).collect::<Vec<_>>()),
        "validated": true, "validation_error": null,
        "deployed": deployed, "deployed_at": null, "enabled": true,
        "lifecycle_status": if deployed { "active" } else { "draft" },
        "stale_alert_enabled": false, "stale_threshold_minutes": 60,
        "sampling_ratio": null, "sampling_exclude_condition": null,
        "source_parser_repository_id": null, "source_parser_path": null,
        "created_at": Utc::now(), "updated_at": Utc::now(),
    });
    serde_json::from_value(json).expect("log source fixture")
}

fn activity(key: &str, events: u64) -> SourceActivity {
    SourceActivity {
        route_key: key.into(),
        events_24h: events,
        first_seen: Some(Utc.with_ymd_and_hms(2026, 11, 3, 10, 0, 0).unwrap()),
        last_seen: Some(Utc.with_ymd_and_hms(2026, 11, 3, 11, 0, 0).unwrap()),
    }
}

fn token(source_id: Option<Uuid>, state: &str, last_used_minute: Option<u32>) -> IngestToken {
    IngestToken {
        credential_id: Uuid::new_v4(),
        name: "t".into(),
        token_prefix: "nit_abcdefgh".into(),
        state: state.into(),
        source_id,
        source_name: None,
        route_key: None,
        source_bound_at: None,
        rotated_from: None,
        request_count: 0,
        created_at: Utc::now(),
        created_by: None,
        last_used_at: last_used_minute.map(|m| Utc.with_ymd_and_hms(2026, 11, 3, 12, m, 0).unwrap()),
        revoked_at: None,
        revoked_by: None,
        revocable: true,
    }
}

#[test]
fn state_follows_publication_and_arrivals() {
    assert_eq!(connect_state(false, true, 10), ConnectState::Disabled);
    // A draft is created disabled, yet its tokens already route events.
    assert_eq!(connect_state(false, false, 0), ConnectState::AwaitingData);
    assert_eq!(connect_state(false, false, 4), ConnectState::ReceivingUnparsed);
    assert_eq!(connect_state(true, false, 0), ConnectState::AwaitingData);
    assert_eq!(connect_state(true, false, 3), ConnectState::ReceivingUnparsed);
    assert_eq!(connect_state(true, true, 3), ConnectState::Receiving);
    assert_eq!(connect_state(true, true, 0), ConnectState::NoRecentData);
}

#[test]
fn draft_with_arrivals_is_receiving_unparsed_and_counts_its_tokens() {
    let vpn = source("Acme VPN", Some(&["acme_vpn"]), false);
    let fw = source("Firewall", Some(&["pan_traffic"]), true);
    let tokens = vec![
        token(Some(vpn.id), "active", Some(5)),
        token(Some(vpn.id), "active", Some(9)),
        token(Some(vpn.id), "revoked", Some(30)),
        token(Some(fw.id), "active", None),
    ];
    let statuses = connect_statuses(
        &[vpn.clone(), fw.clone()],
        &[activity("acme_vpn", 3)],
        &tokens,
    );
    let vpn_status = statuses.iter().find(|s| s.source_id == vpn.id).unwrap();
    assert_eq!(vpn_status.route_key, "acme_vpn");
    assert_eq!(vpn_status.state, ConnectState::ReceivingUnparsed);
    assert_eq!(vpn_status.events_24h, 3);
    assert_eq!(vpn_status.active_tokens, 2, "revoked tokens are not counted");
    assert_eq!(
        vpn_status.token_last_used_at,
        Some(Utc.with_ymd_and_hms(2026, 11, 3, 12, 9, 0).unwrap())
    );
    let fw_status = statuses.iter().find(|s| s.source_id == fw.id).unwrap();
    assert_eq!(fw_status.state, ConnectState::NoRecentData);
    assert_eq!(fw_status.active_tokens, 1);
}

#[test]
fn route_key_falls_back_to_safe_name_like_the_token_binding() {
    let s = source("Legacy FW", None, true);
    let statuses = connect_statuses(&[s], &[activity("legacy_fw", 7)], &[]);
    assert_eq!(statuses[0].route_key, "legacy_fw");
    assert_eq!(statuses[0].state, ConnectState::Receiving);
}

#[test]
fn unassigned_excludes_every_claimed_key_and_system_keys() {
    let multi = source("Multi", Some(&["a_one", "A_Two"]), true);
    let named = source("By Name", None, false);
    let rows = vec![
        activity("a_one", 5),
        activity("a_two", 5),
        activity("by_name", 5),
        activity("unknown", 100),
        activity("parse_failure", 100),
        activity("nano_enrich_identity", 100),
        activity("legacy_fw", 40),
        activity("Bad Key\"", 50),
        activity("idle", 0),
    ];
    let out = unassigned_sources(&[multi, named], &rows);
    let keys: Vec<&str> = out.iter().map(|u| u.route_key.as_str()).collect();
    assert_eq!(keys, vec!["Bad Key\"", "legacy_fw"], "busiest first; claimed, system and idle keys dropped");
    assert!(!out[0].convertible, "a key unsafe for generated config is shown but not convertible");
    assert!(out[1].convertible);
}

#[test]
fn route_key_validation_rejects_config_injection() {
    for ok in ["acme_vpn", "pan-traffic", "aws.cloudtrail", "0day", "a"] {
        assert!(validate_route_key(ok).is_ok(), "{ok} should be accepted");
    }
    for bad in [
        "",
        "Acme",
        "_lead",
        "x\" || true || \"",
        "a b",
        "a'b",
        "a\nb",
        "unknown",
        "parse_failure",
        "nano_enrich_ioc",
        &"x".repeat(MAX_ROUTE_KEY_LEN + 1),
    ] {
        assert!(validate_route_key(bad).is_err(), "{bad:?} should be refused");
    }
}

#[test]
fn activity_sql_is_a_single_where_with_scope_on_the_raw_key() {
    let open = activity_sql("logs_per_source_5m_v2", "udm", 24, &ScopeSet::unrestricted(), None);
    assert!(open.contains("WHERE bucket_start >= now() - INTERVAL 24 HOUR"));
    assert!(open.contains("schema_profile = 'udm'"));
    assert!(!open.to_uppercase().contains("PREWHERE"));
    assert!(!open.contains("scope_source_type"));

    let denied: BTreeSet<String> = ["secret_src".to_string()].into();
    let scoped = activity_sql("logs_per_source_5m_v2", "udm", 24, &ScopeSet::from_denied(denied), None);
    assert!(scoped.contains("scope_source_type_complete = 1"));
    assert!(scoped.contains("secret_src"));
}

#[test]
fn parses_quoted_uint64_and_epoch_millis() {
    let body = concat!(
        "{\"route_key\":\"acme_vpn\",\"events\":\"3\",\"first_ms\":\"1762164000000\",\"last_ms\":\"1762167600000\"}\n",
        "{\"route_key\":\"empty\",\"events\":0,\"first_ms\":0,\"last_ms\":0}\n",
        "not json\n"
    );
    let rows = parse_activity_rows(body);
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0].events_24h, 3);
    assert_eq!(rows[0].last_seen.unwrap().timestamp_millis(), 1_762_167_600_000);
    assert_eq!(rows[1].first_seen, None);
}

#[test]
fn known_key_activity_is_uncapped_and_escaped() {
    let inventory = activity_sql("logs_per_source_5m_v2", "udm", 24, &ScopeSet::unrestricted(), None);
    assert!(inventory.ends_with("LIMIT 1000"), "the unassigned inventory keeps its cap: {inventory}");
    let keys = vec!["Acme_VPN".to_string(), "o'brien".to_string()];
    let known = activity_sql("logs_per_source_5m_v2", "udm", 24, &ScopeSet::unrestricted(), Some(&keys));
    assert!(!known.contains("LIMIT"), "known-source status is never truncated: {known}");
    assert!(known.contains("source_type IN ('acme_vpn', 'o''brien')"), "{known}");
    assert!(!known.to_uppercase().contains("PREWHERE"));
}

/// NAN-5032: platform-owned source types (and the rewrite marker) are never
/// offered for conversion and cannot become a source's route key.
#[test]
fn platform_owned_source_types_are_system_route_keys() {
    for key in ["audit", "findings", "reserved_spoof"] {
        assert!(validate_route_key(key).is_err(), "{key} must not name a source");
    }
    let rows = vec![activity("audit", 100), activity("reserved_spoof", 9), activity("legacy_fw", 40)];
    let out = unassigned_sources(&[], &rows);
    let keys: Vec<&str> = out.iter().map(|u| u.route_key.as_str()).collect();
    assert_eq!(keys, vec!["legacy_fw"]);
    // Legitimate look-alikes still convert.
    assert!(validate_route_key("linux_audit").is_ok());
}
