// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-5079: everything nano itself writes as OCSF passes the same validator
//! the Log Sources parser test enforces — the audit (API Activity 6003) and
//! Detection Finding (2004) emitters, and the checked-in OCSF fixtures.

use chrono::{DateTime, Utc};
use serde_json::json;
use uuid::Uuid;

use crate::audit::{AuditEvent, AuditSource};
use crate::detection::findings::FindingLogger;
use crate::parsers::{ocsf_validation_version, validate_ocsf_event};

fn assert_valid(label: &str, event: &serde_json::Value) {
    let result = validate_ocsf_event(event);
    assert!(result.valid, "{label}: {:#?}\n{event:#}", result.errors);
    assert_eq!(
        event["metadata"]["version"],
        ocsf_validation_version(),
        "{label} must declare the OCSF version it was written for"
    );
}

fn at() -> DateTime<Utc> {
    DateTime::parse_from_rfc3339("2026-06-06T12:00:00Z")
        .unwrap()
        .with_timezone(&Utc)
}

#[test]
fn audit_api_activity_events_validate() {
    let cases = [
        (
            "full",
            AuditEvent::builder(AuditSource::Auth, "login")
                .actor(Some(Uuid::now_v7()), Some("alice".into()))
                .api_key(Some(Uuid::now_v7()), Some("ci-bot".into()))
                .resource("session", Some(Uuid::now_v7()), Some("web".into()))
                .client(Some("198.51.100.7".into()), Some("curl/8".into()))
                .details(json!({"reason": "ok"}))
                .build(),
        ),
        (
            "failure, no client",
            AuditEvent::builder(AuditSource::Auth, "login")
                .actor(None, Some("bob".into()))
                .success(false)
                .build(),
        ),
        (
            "type-only resource",
            AuditEvent::builder(AuditSource::Mitre, "mitre_catalog_synced")
                .resource("mitre_catalog", None, None)
                .build(),
        ),
        (
            "system actor",
            AuditEvent::builder(AuditSource::Auth, "system_initialized").build(),
        ),
    ];
    for (label, event) in cases {
        assert_valid(label, &event.to_ocsf_event(at()));
    }
}

fn finding_metadata() -> serde_json::Value {
    json!({
        "signal_type": "detection_match",
        "rule_id": "rule-abc-123",
        "rule_name": "Suspicious Login",
        "rule_query": "user=admin failed",
        "severity": "high",
        "rule_mode": "live",
        "mitre_tactics": ["TA0001"],
        "mitre_techniques": ["T1078"],
        "alert_id": null,
        "matched_event_count": 3,
        "matched_events_sample": [],
        "realtime": false,
        "raw_risk_score": 50,
        "risk_score": 75,
        "risk_entity": "10.0.0.5",
        "risk_entity_field": "src_ip",
        "risk_entity_type": "ip",
        "risk_factors": ["off-hours"]
    })
}

#[test]
fn detection_findings_validate() {
    let mut cases = vec![("base", finding_metadata())];
    let mut alert = finding_metadata();
    alert["alert_id"] = json!(Uuid::now_v7().to_string());
    cases.push(("with alert", alert));
    for (entity, kind) in [
        ("alice", "user"),
        ("ws-01", "host"),
        ("d41d8cd98f00b204e9800998ecf8427e", "hash"),
        ("evil.example", "domain"),
        ("thing", "other"),
    ] {
        let mut metadata = finding_metadata();
        metadata["risk_entity"] = json!(entity);
        metadata["risk_entity_type"] = json!(kind);
        cases.push(("entity", metadata));
    }
    for severity in ["critical", "medium", "low", "info", "unknown"] {
        let mut metadata = finding_metadata();
        metadata["severity"] = json!(severity);
        cases.push(("severity", metadata));
    }
    for (label, metadata) in cases {
        let event = FindingLogger::build_ocsf_finding_event(&metadata, "Suspicious Login", at());
        assert_valid(label, &event);
    }
}

#[test]
fn checked_in_ocsf_fixtures_validate() {
    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/../clickhouse/ocsf/fixtures");
    let mut seen = 0;
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        let event: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_valid(&path.display().to_string(), &event);
        seen += 1;
    }
    assert!(seen >= 6, "fixtures found: {seen}");
}
