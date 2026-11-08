// SPDX-License-Identifier: AGPL-3.0-or-later
//! NAN-4169 parity (NAN-4902 lane G): a retro-hunt hit is flagged on the OCSF
//! finding itself, so `finding_info.types` / `unmapped.retro_ioc` find it even
//! when the matched-event sample is redacted.

use chrono::{DateTime, Utc};
use serde_json::json;

use super::FindingLogger;

fn metadata(rule_query: &str) -> serde_json::Value {
    json!({
        "signal_type": "detection_match",
        "rule_id": "rule-1",
        "rule_name": "Retro IOC hunt",
        "rule_query": rule_query,
        "severity": "high",
        "risk_score": 70,
        "risk_entity": "evil.example",
        "risk_entity_field": "indicator",
    })
}

fn ts() -> DateTime<Utc> {
    DateTime::parse_from_rfc3339("2026-11-03T12:00:00Z").unwrap().with_timezone(&Utc)
}

#[test]
fn retro_hunt_rule_query_marks_the_finding() {
    let event = FindingLogger::build_ocsf_finding_event(
        &metadata("retro-hunt: new IOCs from all feeds over last 5d"),
        "retro",
        ts(),
    );
    assert_eq!(event["finding_info"]["types"], json!(["detection_match", "retro_ioc"]));
    assert_eq!(event["unmapped"]["retro_ioc"], true);
    assert_eq!(event["unmapped"]["retro"], true);
}

#[test]
fn a_retro_flagged_sample_event_marks_the_finding() {
    let mut m = metadata("q");
    m["matched_events_sample"] = json!([{ "indicator": "evil.example", "retro_ioc": true }]);
    let event = FindingLogger::build_ocsf_finding_event(&m, "retro", ts());
    assert_eq!(event["unmapped"]["retro_ioc"], true);
}

#[test]
fn ordinary_findings_are_unchanged() {
    let event = FindingLogger::build_ocsf_finding_event(&metadata("user=admin"), "plain", ts());
    assert_eq!(event["finding_info"]["types"], json!(["detection_match"]));
    assert!(event["unmapped"].get("retro_ioc").is_none());
}
