// SPDX-License-Identifier: AGPL-3.0-or-later

use super::{serialize_rule_to_npl, splice_query};
use crate::models::detection_rule::{
    AlertMode, DetectionMode, DetectionRule, RuleMode, Severity,
};
use crate::rule_repository::parse_npl;
use chrono::Utc;
use uuid::Uuid;

fn sample_rule() -> DetectionRule {
    DetectionRule {
        id: Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").unwrap(),
        name: "Failed Logins".to_string(),
        description: None,
        query: "source_type=windows | stats count by user".to_string(),
        severity: Severity::High,
        mitre_tactics: vec!["TA0006".to_string()],
        mitre_techniques: vec![],
        schedule_cron: None,
        mode: RuleMode::Alerting,
        narrative: None,
        reference_url: None,
        author: None,
        tags: vec![],
        ai_generated: false,
        realtime_enabled: false,
        detection_mode: DetectionMode::Scheduled,
        materialized_view_name: None,
        risk_score: None,
        risk_entity_field: None,
        risk_modifiers: sqlx::types::Json(vec![]),
        created_at: Utc::now(),
        updated_at: Utc::now(),
        last_run_at: None,
        last_match_at: None,
        match_count: 0,
        live_match_count: 0,
        archived: false,
        folder: None,
        ai_triage_hints: sqlx::types::Json(Default::default()),
        lookback_minutes: None,
        dataset: None,
        auto_tuning_enabled: true,
        auto_tuning_min_confidence: 0.8,
        auto_tuning_critical: false,
        auto_tuning_disabled_until: None,
        case_visibility: "private".to_string(),
        case_assigned_group: None,
        alert_mode: AlertMode::Grouped,
        next_run_at: None,
        claimed_by: None,
        claimed_at: None,
        playbook_selector_mode: "none".to_string(),
        playbook_id: None,
        source_path: None,
        source_repo_url: None,
        kind: "standard".to_string(),
        alert_cooldown_minutes: None,
    }
}

#[test]
fn serialize_emits_stable_id_and_reparses() {
    let rule = sample_rule();
    let out = serialize_rule_to_npl(&rule, "source_type=windows | where count > 9").unwrap();

    // The raw UUID is emitted so a later push can find this file by id, and a
    // merge webhook can match the PR back to the rule (NAN-1764).
    assert!(
        out.contains("id: 550e8400-e29b-41d4-a716-446655440000"),
        "frontmatter must carry the rule id: {out}"
    );
    // The file still parses as nPL (RawNplFrontmatter ignores the unknown `id`).
    let parsed = parse_npl(&out).expect("serialized output must re-parse as nPL");
    assert_eq!(parsed.title, "Failed Logins");
    assert_eq!(parsed.query, "source_type=windows | where count > 9");
}

#[test]
fn splice_preserves_existing_id() {
    let existing = "---\nid: 550e8400-e29b-41d4-a716-446655440000\ntitle: Failed Logins\nseverity: high\n---\nfoo | where count > 5\n";
    let out = splice_query(existing, "foo | where count > 50").unwrap();
    assert!(out.contains("id: 550e8400-e29b-41d4-a716-446655440000"));
    assert!(out.contains("where count > 50"));
    assert!(!out.contains("where count > 5\n"));
}

const EXISTING: &str = "---\ntitle: Failed Logins\nseverity: high\ncustom_field: keepme\nmitre_tactics:\n  - TA0006\n---\nsource_type=windows | stats count by user | where count > 5\n";

#[test]
fn splice_preserves_frontmatter_and_swaps_query() {
    let new_query = "source_type=windows | stats count by user | where count > 20";
    let out = splice_query(EXISTING, new_query).expect("valid frontmatter should splice");

    // Frontmatter is kept verbatim — including a field nano doesn't model.
    assert!(out.contains("title: Failed Logins"));
    assert!(out.contains("severity: high"));
    assert!(out.contains("custom_field: keepme"));
    assert!(out.contains("mitre_tactics:"));

    // Only the query body changed.
    assert!(out.contains("where count > 20"));
    assert!(!out.contains("where count > 5"));
}

#[test]
fn spliced_file_reparses_cleanly() {
    let new_query = "source_type=windows | stats count by user | where count > 20";
    let out = splice_query(EXISTING, new_query).unwrap();

    let parsed = parse_npl(&out).expect("spliced output must re-parse as nPL");
    assert_eq!(parsed.title, "Failed Logins");
    assert_eq!(parsed.severity.as_deref(), Some("high"));
    assert_eq!(parsed.query, new_query);
}

#[test]
fn splice_rejects_non_frontmatter_input() {
    assert!(splice_query("just a query, no frontmatter", "q").is_none());
    // Opening delimiter but no closing one.
    assert!(splice_query("---\ntitle: x\nno closing delimiter", "q").is_none());
}
