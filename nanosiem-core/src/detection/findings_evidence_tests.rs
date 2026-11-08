// SPDX-License-Identifier: AGPL-3.0-or-later
//! NAN-4902: detection findings carry ATT&CK mappings, observables, related
//! events, first/last seen and an alert link on the findings row (agnostic half
//! of NAN-3224), and restricted-origin findings carry none of the entity
//! values.
use serde_json::{json, Value};
use uuid::Uuid;

use super::tests::sample_rule;
use super::*;
use crate::detection::finding_evidence::{
    alert_src_url, attacks, observables, related_events, seen_window, MAX_OBSERVABLES,
};
use crate::detection::risk::RiskResult;

fn ids(values: &[&str]) -> Vec<String> {
    values.iter().map(|v| v.to_string()).collect()
}

#[test]
fn attacks_pair_techniques_with_rule_tactics_and_names() {
    let got = attacks(&ids(&["TA0003", "TA0002", " ta0003 "]), &ids(&["T1547.001", "t9999"]));
    assert_eq!(
        got[0],
        json!({
            "technique": {"uid": "T1547", "name": "Boot or Logon Autostart Execution"},
            "sub_technique": {"uid": "T1547.001", "name": "Registry Run Keys / Startup Folder"},
            "tactic": {"uid": "TA0003", "name": "Persistence"},
            "version": "19.1",
        })
    );
    // Unknown technique keeps its uid; no tactic pairs with it.
    assert_eq!(got[1], json!({"technique": {"uid": "T9999"}, "version": "19.1"}));
    // A rule tactic no technique pairs with is kept, de-duplicated.
    assert_eq!(got[2], json!({"tactic": {"uid": "TA0002", "name": "Execution"}, "version": "19.1"}));
    assert_eq!(got.len(), 3);
}

#[test]
fn observables_entity_first_then_udm_and_ocsf_sample_values_deduped() {
    let sample = vec![
        json!({"src_ip": "10.0.0.5", "user": "alice", "process_hash": "abc", "dest_host": "-"}),
        json!({
            "src_endpoint.ip": "10.0.0.5",
            "actor": {"user": {"name": "bob"}, "process": {"file": {"hashes": [{"algorithm_id": 3, "value": "def"}]}}},
            "url": {"url_string": "https://x.example/p"},
        }),
    ];
    let got = observables("10.0.0.5", "ip", Some("src_ip"), &sample);
    let pairs: Vec<(String, i64, String)> = got
        .iter()
        .map(|o| (o["name"].as_str().unwrap().into(), o["type_id"].as_i64().unwrap(), o["value"].as_str().unwrap().into()))
        .collect();
    assert_eq!(pairs[0], ("src_ip".into(), 2, "10.0.0.5".into()), "entity first");
    let values: Vec<&str> = pairs.iter().map(|p| p.2.as_str()).collect();
    assert_eq!(values.iter().filter(|v| **v == "10.0.0.5").count(), 1, "deduped by type+value");
    for want in ["alice", "abc", "bob", "def", "https://x.example/p"] {
        assert!(values.contains(&want), "missing {want}: {pairs:?}");
    }
    assert!(!values.contains(&"-"), "placeholder is not an observable");
    assert!(pairs.iter().any(|p| p.0 == "matched_events_sample[1].actor.process.file.hashes[0].value"));
}

#[test]
fn observables_are_capped() {
    let sample: Vec<Value> = (0..5)
        .map(|i| {
            let mut row = serde_json::Map::new();
            for f in ["user", "src_user", "dest_user", "src_ip", "dest_ip", "src_host", "dest_host", "url"] {
                row.insert(f.into(), json!(format!("{f}-{i}")));
            }
            Value::Object(row)
        })
        .collect();
    assert_eq!(observables("", "", None, &sample).len(), MAX_OBSERVABLES);
}

#[test]
fn related_events_and_seen_window() {
    let events = vec![
        json!({"id": "a", "timestamp": "2026-11-01 10:00:05.000"}),
        json!({"id": "a", "timestamp": "2026-11-01 10:00:01"}),
        json!({"metadata": {"uid": "b"}, "time": 1_793_530_800_000_i64}),
        json!({"_first_seen": "2026-11-01T09:00:00Z", "_last_seen": "2026-11-01T09:30:00Z"}),
    ];
    assert_eq!(related_events(&events), vec![json!({"uid": "a"}), json!({"uid": "b"})]);
    let (first, last) = seen_window(&events).unwrap();
    assert_eq!(first.to_rfc3339(), "2026-11-01T09:00:00+00:00");
    assert_eq!(last, DateTime::from_timestamp_millis(1_793_530_800_000).unwrap());
    assert!(seen_window(&[json!({"count": 3})]).is_none());
}

fn finding(events: &[Value]) -> FindingEvent {
    let rule = DetectionRule {
        mode: RuleMode::Live,
        mitre_tactics: ids(&["TA0003"]),
        mitre_techniques: ids(&["T1547.001"]),
        ..sample_rule()
    };
    let risk = RiskResult::new(40, 40, "alice".into(), Some("user".into()), vec![]);
    FindingEvent::detection_match(&rule, events, false, risk)
}

#[test]
fn findings_row_carries_evidence_and_timing() {
    let events: Vec<Value> = (0..8)
        .map(|i| json!({"id": format!("e{i}"), "user": "alice", "src_ip": "10.1.1.1", "timestamp": format!("2026-11-01 10:00:0{i}")}))
        .collect();
    let row = finding(&events).to_log_json();
    assert_eq!(row["attacks"][0]["sub_technique"]["uid"], "T1547.001");
    assert_eq!(row["attacks"][0]["tactic"]["name"], "Persistence");
    assert_eq!(row["observables"][0], json!({"name": "user", "type": "User Name", "type_id": 4, "value": "alice"}));
    assert!(row["observables"].as_array().unwrap().iter().any(|o| o["value"] == "10.1.1.1"));
    // Related events come from the (≤ 5) sample; timing spans ALL matched events.
    assert_eq!(row["related_events"].as_array().unwrap().len(), 5);
    assert_eq!(row["first_seen_time"], "2026-11-01T10:00:00+00:00");
    assert_eq!(row["last_seen_time"], "2026-11-01T10:00:07+00:00");
    assert_eq!(row["is_alert"], false);
    assert!(row["alert_url"].is_null());
    assert_eq!((row["analytic_state_id"].as_i64(), row["analytic_state"].as_str()), (Some(3), Some("Experimental")));
}

#[test]
fn alert_findings_link_their_alert() {
    let mut f = finding(&[json!({"user": "alice"})]);
    let alert_id = Uuid::now_v7();
    f.finding_type = FindingType::Alert;
    f.alert_id = Some(alert_id);
    let row = f.to_log_json();
    assert_eq!(row["is_alert"], true);
    let url = row["alert_url"].as_str().unwrap();
    assert_eq!(url, alert_src_url(&alert_id));
    assert!(url.starts_with("/alerts/alert_"), "{url}");
}

#[test]
fn restricted_origin_findings_carry_no_entity_evidence() {
    let events = vec![json!({"id": "e1", "user": "ceo", "src_ip": "10.9.9.9", "timestamp": "2026-11-01 10:00:00", "source_type": "hr_system"})];
    let mut f = finding(&events);
    f.redact_matched_events();
    let row = f.to_log_json();
    assert_eq!(row["observables"], json!([]));
    assert_eq!(row["related_events"], json!([]));
    // Rule metadata and event times are not entity values: kept.
    assert_eq!(row["attacks"][0]["technique"]["uid"], "T1547");
    assert_eq!(row["first_seen_time"], "2026-11-01T10:00:00+00:00");
    assert_eq!(row["origin_source_types"], json!(["hr_system"]));
    let ocsf = FindingLogger::build_ocsf_finding_event(&row, &f.message(), Utc::now());
    assert!(!ocsf.to_string().contains("ceo") && !ocsf.to_string().contains("10.9.9.9"));
}

#[test]
fn ocsf_row_mirrors_the_evidence_under_unmapped() {
    let row = finding(&[json!({"id": "e1", "user": "alice", "timestamp": "2026-11-01 10:00:00"})]).to_log_json();
    let ocsf = FindingLogger::build_ocsf_finding_event(&row, "m", Utc::now());
    for key in ["attacks", "observables", "related_events", "first_seen_time", "is_alert", "analytic_state"] {
        assert_eq!(ocsf["unmapped"][key], row[key], "{key}");
    }
}

#[test]
fn legacy_rows_without_timing_still_deserialize() {
    let legacy = json!({
        "finding_type": "alert", "rule_id": Uuid::now_v7(), "rule_name": "r", "rule_query": "q",
        "severity": "high", "rule_mode": "alerting", "mitre_tactics": [], "mitre_techniques": [],
        "alert_id": null, "matched_event_count": 1, "matched_events_sample": [], "realtime": false,
        "detected_at": Utc::now().to_rfc3339(), "raw_risk_score": 1, "risk_score": 1,
        "risk_entity": "a", "risk_entity_field": "user", "risk_factors": [],
    });
    let event: FindingEvent = serde_json::from_value(legacy).unwrap();
    assert!(event.first_seen_at.is_none() && event.last_seen_at.is_none());
}
