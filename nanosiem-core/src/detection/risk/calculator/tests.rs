// SPDX-License-Identifier: AGPL-3.0-or-later

//! Unit tests for `ScoreCalculator` query-score detection (audit D10).

use super::*;
use serde_json::json;

#[test]
fn has_query_risk_score_treats_null_as_absent() {
    // Audit D10: a JSON null `raw_risk_score` must count as ABSENT so a
    // null-scored `| risk` batch falls back to rule-level scoring instead of
    // being dropped and suppressing the whole alert.
    assert!(ScoreCalculator::has_query_risk_score(
        &json!({"raw_risk_score": 42})
    ));
    assert!(ScoreCalculator::has_query_risk_score(
        &json!({"raw_risk_score": 0})
    ));
    assert!(!ScoreCalculator::has_query_risk_score(
        &json!({"raw_risk_score": null})
    ));
    assert!(!ScoreCalculator::has_query_risk_score(
        &json!({"other": 1})
    ));
}

// ---------------------------------------------------------------------------
// NAN-5271 C: class-aware entity fallback.
// ---------------------------------------------------------------------------

fn ocsf_calc() -> ScoreCalculator {
    ScoreCalculator::new().with_profile(Arc::new(crate::schema::OcsfProfile::new()))
}

/// Finding #7: the real-time matched-log JSON is UDM-keyed even on OCSF
/// (`src_ip`, `src_host`, `src_user` holding class-correct values). The OCSF
/// extraction order never lists those keys, so every Sysmon finding became
/// `unknown` and grouped dedup collapsed into one bucket.
#[test]
fn ocsf_realtime_udm_keyed_payload_is_not_unknown() {
    let events = vec![json!({
        "id": "x", "message": "", "source_type": "windows_sysmon",
        "src_ip": "", "dest_ip": "", "src_host": "ws-exec-072.corp.local", "dest_host": "",
        "src_user": "canderson", "dest_user": "", "risk_entity": ""
    })];
    let (entity, field) = ocsf_calc().extract_entity(None, &events);
    assert_eq!(entity, "canderson");
    assert_eq!(field.as_deref(), Some("src_user"));

    // Two hosts give two distinct entities (two dedup buckets, not one).
    let other = vec![json!({"src_ip": "", "src_host": "ws-hr-083.corp.local", "src_user": ""})];
    assert_eq!(ocsf_calc().extract_entity(None, &other).0, "ws-hr-083.corp.local");
}

/// Finding #8 / #29: a UDM-named entity field on an OCSF row resolves through
/// its concept.
#[test]
fn ocsf_row_with_udm_named_entity_field_resolves() {
    let row = vec![json!({
        "class_uid": 1007, "src_endpoint.hostname": "", "device.hostname": "ws-exec-072.corp.local",
        "user.name": "", "actor.user.name": "canderson"
    })];
    assert_eq!(ocsf_calc().extract_entity(Some("src_host"), &row).0, "ws-exec-072.corp.local");
    // `stats count by src_ip` output on OCSF keeps the UDM output name.
    let agg = vec![json!({"src_ip": "10.1.8.114", "count": 12})];
    assert_eq!(ocsf_calc().extract_entity(None, &agg).0, "10.1.8.114");
}

/// The UDM profile is unchanged: its own order still wins.
#[test]
fn udm_auto_detect_order_unchanged() {
    let events = vec![json!({"src_ip": "10.0.0.1", "user": "alice"})];
    let (entity, field) = ScoreCalculator::new().extract_entity(None, &events);
    assert_eq!((entity.as_str(), field.as_deref()), ("10.0.0.1", Some("src_ip")));
}
