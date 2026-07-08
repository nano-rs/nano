// SPDX-License-Identifier: AGPL-3.0-or-later

//! Tests for the tuning repository.

use crate::tuning::types::{
    AlertPattern, ComparisonMetrics, ProposalType, SafetyCheck, SafetyValidation, TestResults,
    TuningLogEntry, TuningProposal, TuningStatus,
};
use chrono::Utc;
use std::collections::HashMap;
use uuid::Uuid;

fn create_test_proposal(rule_id: Uuid) -> TuningProposal {
    TuningProposal {
        id: Uuid::now_v7(),
        rule_id,
        rule_name: None,
        created_at: Utc::now(),
        proposal_type: ProposalType::QueryTuning,
        original_query: "source_type = 'sysmon' AND event_id = 1".to_string(),
        proposed_query: "source_type = 'sysmon' AND event_id = 1 AND process.name != 'chrome.exe'"
            .to_string(),
        rationale: "Excessive alerts from chrome.exe process".to_string(),
        confidence_score: 0.85,
        changes_summary: vec!["Added exclusion for chrome.exe".to_string()],
        affected_patterns: vec![AlertPattern {
            field_name: "process.name".to_string(),
            field_value: "chrome.exe".to_string(),
            occurrence_count: 1000,
            percentage: 75.0,
        }],
        safety_validation: SafetyValidation {
            is_safe: true,
            critical_indicators_preserved: true,
            validation_checks: vec![SafetyCheck {
                check_name: "Critical indicators".to_string(),
                passed: true,
                details: "All critical indicators preserved".to_string(),
            }],
            warnings: vec![],
        },
        status: TuningStatus::Proposed,
        current_hints: None,
        proposed_hints: None,
        hints_diff: None,
        pr_url: None,
        pr_number: None,
        pr_state: None,
    }
}

fn create_test_log_entry(rule_id: Uuid) -> TuningLogEntry {
    TuningLogEntry {
        id: Uuid::now_v7(),
        rule_id,
        rule_name: "Test Detection Rule".to_string(),
        triggered_at: Utc::now(),
        trigger_reason: "Alert volume exceeded baseline by 3 standard deviations".to_string(),
        proposal: create_test_proposal(rule_id),
        test_results: Some(TestResults {
            proposal_id: Uuid::now_v7(),
            tested_at: Utc::now(),
            original_alert_count: 1000,
            tuned_alert_count: 250,
            reduction_percentage: 75.0,
            true_positives_preserved: true,
            validation_passed: true,
            comparison_metrics: ComparisonMetrics {
                alerts_removed: 750,
                alerts_preserved: 250,
                unique_entities_removed: 50,
                severity_distribution_change: HashMap::new(),
                pattern_changes: vec![],
            },
        }),
        staging_deployment: None,
        status: TuningStatus::TestPassed,
        reverted_at: None,
        reverted_by: None,
        revert_reason: None,
    }
}

#[test]
fn test_tuning_log_entry_creation() {
    let rule_id = Uuid::now_v7();
    let entry = create_test_log_entry(rule_id);

    assert_eq!(entry.rule_id, rule_id);
    assert_eq!(entry.rule_name, "Test Detection Rule");
    assert_eq!(entry.status, TuningStatus::TestPassed);
    assert!(entry.test_results.is_some());
    assert!(entry.reverted_at.is_none());
}

#[test]
fn test_proposal_serialization() {
    let rule_id = Uuid::now_v7();
    let proposal = create_test_proposal(rule_id);

    let json = serde_json::to_value(&proposal).unwrap();
    let deserialized: TuningProposal = serde_json::from_value(json).unwrap();

    assert_eq!(deserialized.rule_id, rule_id);
    assert_eq!(deserialized.confidence_score, 0.85);
    assert_eq!(deserialized.changes_summary.len(), 1);
}
