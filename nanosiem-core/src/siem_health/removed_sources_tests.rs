// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-5760: deleted log sources leave the SIEM health per-source lists.

use chrono::{Duration, TimeZone, Utc};
use serde_json::json;

use super::*;
use crate::siem_health::analyzer::fallback_report;
use crate::siem_health::types::{CollectedMetrics, SiemHealthReport};

fn tombstone(name: &str, values: Option<&[&str]>, minutes_ago: i64) -> Tombstone {
    Tombstone {
        name: name.to_string(),
        match_values: values.map(|v| v.iter().map(|s| s.to_string()).collect()),
        deleted_at: Utc.with_ymd_and_hms(2026, 11, 19, 12, 0, 0).unwrap() - Duration::minutes(minutes_ago),
    }
}

fn keys(tombstones: &[Tombstone], live: &[(Option<Vec<String>>, String)]) -> RemovedSourceKeys {
    RemovedSourceKeys::from_parts(
        tombstones,
        live.iter().map(|(values, name)| (values.as_deref(), name.as_str())),
        std::iter::empty(),
    )
}

fn deleted_at() -> i64 {
    Utc.with_ymd_and_hms(2026, 11, 19, 12, 0, 0).unwrap().timestamp()
}

/// Evidence that every key was produced up to `minutes_ago` before the
/// reference delete time and stopped then.
fn produced_before(removed: &RemovedSourceKeys) -> HashMap<String, KeyEvidence> {
    removed
        .keys()
        .map(|k| (k.to_string(), KeyEvidence { first_event: deleted_at() - 86_400, last_event: deleted_at() - 7_200 }))
        .collect()
}

#[test]
fn a_tombstoned_key_no_live_source_claims_is_removed() {
    let removed = keys(
        &[
            tombstone("AWS CloudTrail (OCSF)", Some(&["AWS_CloudTrail", " cloudtrail_s3 "]), 5),
            tombstone("Palo Alto FW", None, 5),
        ],
        &[],
    );
    assert!(removed.contains("aws_cloudtrail"));
    assert!(removed.contains("CLOUDTRAIL_S3"), "lookups are case-insensitive");
    // No match values: the router's key is the safe name.
    assert!(removed.contains("palo_alto_fw"));
    assert_eq!(removed.get("aws_cloudtrail").unwrap().log_source_name, "AWS CloudTrail (OCSF)");
    assert!(!removed.contains("windows_event"));
    assert_eq!(removed.len(), 3);
}

#[test]
fn a_live_source_claiming_the_key_wins_over_its_tombstone() {
    // Deleted, then re-created under another name claiming the same key.
    let removed = keys(
        &[tombstone("sysmon old", Some(&["sysmon"]), 30)],
        &[(Some(vec!["sysmon".into()]), "sysmon new".into())],
    );
    assert!(removed.is_empty());

    // Re-created with no match values: its safe name claims the key.
    let removed = keys(&[tombstone("Palo Alto FW", None, 30)], &[(None, "palo alto fw".into())]);
    assert!(removed.is_empty());
}

#[test]
fn reserved_platform_and_non_literal_keys_are_never_set_aside() {
    // NAN-5760 review P1: a deleted source naming platform lanes must not hide them.
    let removed = keys(
        &[tombstone(
            "evil",
            Some(&[
                "audit", "findings", "signals", "nano_enrich", "nano_operational", "__nano:x",
                "nano_custom", "reserved_spoof", "parse_failure", "fw_*", "fw.+", "^fw$", "",
            ]),
            1,
        )],
        &[],
    );
    assert!(removed.is_empty(), "{:?}", removed.keys().collect::<Vec<_>>());
}

#[test]
fn a_routing_rule_target_claims_its_key() {
    let removed = RemovedSourceKeys::from_parts(
        &[tombstone("hec fw", Some(&["hec_firewall", "gone_fw"]), 1)],
        std::iter::empty(),
        ["HEC_Firewall"],
    );
    assert!(!removed.contains("hec_firewall"), "a live routing target stays live");
    assert!(removed.contains("gone_fw"));
}

#[test]
fn only_keys_the_source_produced_and_that_stopped_are_set_aside() {
    let t = deleted_at();
    let mut removed = keys(
        &[tombstone("s", Some(&["stopped", "never_ingested", "only_after", "still_sending", "late_buffer"]), 0)],
        &[],
    );
    let evidence: HashMap<String, KeyEvidence> = [
        // Produced while it existed, nothing since: set aside.
        ("stopped", KeyEvidence { first_event: t - 86_400, last_event: t - 60 }),
        // Events only after the delete: another sender owns it, stays live.
        ("only_after", KeyEvidence { first_event: t + 600, last_event: t + 900 }),
        // Produced before and still arriving after the grace: live again.
        ("still_sending", KeyEvidence { first_event: t - 86_400, last_event: t + LATE_ARRIVAL_GRACE_SECS + 1 }),
        // In-flight buffers inside the grace do not revive it.
        ("late_buffer", KeyEvidence { first_event: t - 3_600, last_event: t + LATE_ARRIVAL_GRACE_SECS }),
    ]
    .into_iter()
    .map(|(k, v)| (k.to_string(), v))
    .collect();
    // `never_ingested` has no events at all: nothing to set aside.
    removed.retain_evidenced(&evidence);
    let kept: Vec<&str> = removed.keys().collect();
    assert_eq!(kept, ["late_buffer", "stopped"]);
}

#[test]
fn evidence_sql_is_bounded_and_scoped_to_the_candidates() {
    let sql = evidence_sql("nanosiem.ocsf_logs", ["a_b", "c'd"].into_iter());
    assert!(sql.contains("timestamp >= now() - INTERVAL 48 HOUR"), "{sql}");
    assert!(sql.contains("source_type IN ('a_b', 'c\\'d')"), "{sql}");
    assert!(!sql.contains("PREWHERE"));
}

#[test]
fn the_most_recent_delete_names_a_shared_key() {
    let removed = keys(
        &[tombstone("first", Some(&["shared"]), 60), tombstone("second", Some(&["shared"]), 1)],
        &[],
    );
    assert_eq!(removed.get("shared").unwrap().log_source_name, "second");
}

fn metrics() -> CollectedMetrics {
    let volume = |source_type: &str, now: u64, prior: u64| {
        json!({ "source_type": source_type, "count_24h": now, "count_prior_24h": prior, "change_pct": 0.0 })
    };
    let coverage = |source_type: &str| {
        json!({
            "source_type": source_type, "total_events": 100,
            "src_ip_filled_pct": 0.0, "user_filled_pct": 0.0,
            "event_type_filled_pct": 0.0, "message_filled_pct": 0.0
        })
    };
    serde_json::from_value(json!({
        "ingestion": {
            "source_volumes": [
                volume("windows_event", 1000, 1000),
                volume("aws_cloudtrail", 0, 5000),
                volume("palo_alto_fw", 40, 60),
            ],
            "total_events_24h": 1040,
            "total_events_prior_24h": 6060,
            "silent_sources": ["aws_cloudtrail"]
        },
        "parsing": {
            "field_coverage": [coverage("windows_event"), coverage("palo_alto_fw")],
            "high_ext_sources": [{ "source_type": "palo_alto_fw", "total_events": 40, "ext_usage_pct": 90.0 }]
        },
        "enrichment": {
            "total_events_24h": 1040,
            "geoip_fill_pct": 0.0, "asn_fill_pct": 0.0, "ioc_hit_pct": 0.0, "identity_fill_pct": 0.0,
            "per_source_coverage": [
                { "source_type": "windows_event", "total_events": 1000, "geoip_pct": 0.0, "ioc_pct": 0.0, "identity_pct": 0.0 },
                { "source_type": "palo_alto_fw", "total_events": 40, "geoip_pct": 0.0, "ioc_pct": 0.0, "identity_pct": 0.0 }
            ]
        },
        "detection": {
            "total_enabled_rules": 1, "total_matches_24h": 0, "rules_by_mode": [],
            "stale_rules": [], "noisy_rules": [], "alerts_24h_by_severity": []
        },
        "alerting": {
            "total_alerts_24h": 0, "total_alerts_prior_24h": 0, "by_status": [],
            "mean_mtta_minutes": null, "active_webhooks": 0, "webhook_deliveries_24h": 0,
            "webhook_success_pct": null, "active_routing_rules": 0
        },
        "collected_at": Utc::now()
    }))
    .expect("metrics fixture")
}

fn deleted_cloudtrail_and_firewall() -> RemovedSourceKeys {
    keys(
        &[
            tombstone("AWS CloudTrail", Some(&["aws_cloudtrail"]), 10),
            tombstone("Palo Alto FW", None, 10),
        ],
        &[(Some(vec!["windows_event".into()]), "Windows".into())],
    )
}

#[test]
fn deleted_sources_leave_every_per_source_list_and_the_totals() {
    let mut m = metrics();
    assert!(m.set_aside_removed_sources(&deleted_cloudtrail_and_firewall()));

    let volumes: Vec<&str> = m.ingestion.source_volumes.iter().map(|v| v.source_type.as_str()).collect();
    assert_eq!(volumes, ["windows_event"]);
    assert!(m.ingestion.silent_sources.is_empty(), "a deleted source is never silent");
    assert_eq!(m.ingestion.total_events_24h, 1000);
    // The moved 40 events leave the enrichment denominator too (review P2).
    assert_eq!(m.enrichment.total_events_24h, 1000);
    assert_eq!(m.ingestion.total_events_prior_24h, 1000);
    assert_eq!(m.parsing.field_coverage.len(), 1);
    assert!(m.parsing.high_ext_sources.is_empty());
    assert_eq!(m.enrichment.per_source_coverage.len(), 1);

    // The quiet state: still visible, with its volumes and who it was.
    let removed: Vec<(&str, &str, u64, u64)> = m
        .ingestion
        .removed_sources
        .iter()
        .map(|r| (r.source_type.as_str(), r.log_source_name.as_str(), r.count_24h, r.count_prior_24h))
        .collect();
    assert_eq!(
        removed,
        [("aws_cloudtrail", "AWS CloudTrail", 0, 5000), ("palo_alto_fw", "Palo Alto FW", 40, 60)]
    );
}

#[test]
fn setting_aside_is_idempotent_and_a_no_op_without_removed_keys() {
    let mut m = metrics();
    assert!(!m.set_aside_removed_sources(&RemovedSourceKeys::default()));
    assert_eq!(m.ingestion.source_volumes.len(), 3);

    let removed = deleted_cloudtrail_and_firewall();
    assert!(m.set_aside_removed_sources(&removed));
    let once = serde_json::to_value(&m).unwrap();
    assert!(!m.set_aside_removed_sources(&removed), "nothing left to move");
    assert_eq!(serde_json::to_value(&m).unwrap(), once);
}

#[test]
fn a_deleted_silent_source_no_longer_lowers_the_ingestion_score() {
    let before = fallback_report(&metrics());
    let mut m = metrics();
    m.set_aside_removed_sources(&deleted_cloudtrail_and_firewall());
    let after = fallback_report(&m);
    assert!(
        after.ingestion_score > before.ingestion_score,
        "before {} after {}",
        before.ingestion_score,
        after.ingestion_score
    );
    assert_eq!(after.ingestion_score, 100, "the remaining source is steady");
}

#[test]
fn a_stored_report_is_reconciled_and_an_unaffected_one_stays_byte_identical() {
    let stored = serde_json::to_value(metrics()).unwrap();
    let mut report = SiemHealthReport {
        id: uuid::Uuid::now_v7(),
        overall_score: 50,
        overall_status: "warning".into(),
        ingestion_score: 40,
        parsing_score: 80,
        detection_score: 80,
        enrichment_score: None,
        alerting_score: None,
        summary: String::new(),
        metrics: stored.clone(),
        recommendations: json!([]),
        dimension_details: json!({}),
        triggered_by: None,
        created_at: Utc::now(),
        duration_ms: None,
        source_types: vec![],
        source_types_complete: false,
    };

    // A delete that touches none of the report's source types.
    report.set_aside_removed_sources(&keys(&[tombstone("other", Some(&["other"]), 1)], &[]));
    assert_eq!(report.metrics, stored);

    report.set_aside_removed_sources(&deleted_cloudtrail_and_firewall());
    assert_eq!(report.metrics["ingestion"]["silent_sources"], json!([]));
    assert_eq!(report.metrics["ingestion"]["source_volumes"].as_array().unwrap().len(), 1);
    assert_eq!(report.metrics["ingestion"]["removed_sources"].as_array().unwrap().len(), 2);
}

#[test]
fn reports_written_before_nan_5760_still_deserialize() {
    let mut legacy = serde_json::to_value(metrics()).unwrap();
    legacy["ingestion"].as_object_mut().unwrap().remove("removed_sources");
    let m: CollectedMetrics = serde_json::from_value(legacy).expect("legacy report");
    assert!(m.ingestion.removed_sources.is_empty());
}

#[test]
fn deleting_every_source_reads_as_no_events_not_as_a_live_fleet() {
    // Review P2: with every source set aside, deployment_state must see zero
    // events everywhere (Fresh / Stalled), not a live fleet.
    let mut m = metrics();
    let all = keys(
        &[
            tombstone("w", Some(&["windows_event"]), 1),
            tombstone("AWS CloudTrail", Some(&["aws_cloudtrail"]), 1),
            tombstone("Palo Alto FW", None, 1),
        ],
        &[],
    );
    let mut all = all;
    let evidence = produced_before(&all);
    all.retain_evidenced(&evidence);
    assert_eq!(all.len(), 3);
    assert!(m.set_aside_removed_sources(&all));
    assert_eq!(m.ingestion.total_events_24h, 0);
    assert_eq!(m.ingestion.total_events_prior_24h, 0);
    assert_eq!(m.enrichment.total_events_24h, 0);
    // One enabled rule: a configured tenant with no events is Stalled (critical).
    let report = fallback_report(&m);
    assert!(report.ingestion_score < 50, "stalled, got {}", report.ingestion_score);
}
