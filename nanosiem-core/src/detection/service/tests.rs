// SPDX-License-Identifier: AGPL-3.0-or-later

//! Tests for the detection service

use super::*;
use crate::detection::scheduler::validate_cron_expression;
use crate::{parse_query, DetectionMode, NewDetectionRule, RuleMode, Severity};

// Test validation functions directly without needing a database connection

#[test]
fn test_validate_cron_valid() {
    // Valid 5-field cron expressions
    assert!(validate_cron_expression("* * * * *").is_ok());
    assert!(validate_cron_expression("0 * * * *").is_ok());
    assert!(validate_cron_expression("*/5 * * * *").is_ok());
    assert!(validate_cron_expression("0 0 * * *").is_ok());
    assert!(validate_cron_expression("0 0 1 * *").is_ok());
    assert!(validate_cron_expression("0 0 * * SUN").is_ok());
    assert!(validate_cron_expression("0 9 * * MON-FRI").is_ok());

    // Valid 6-field cron expressions
    assert!(validate_cron_expression("0 0 0 * * *").is_ok());
    assert!(validate_cron_expression("0 */5 * * * *").is_ok());
}

#[test]
fn test_validate_cron_invalid() {
    // Invalid cron expressions
    assert!(validate_cron_expression("* * * *").is_err()); // Too few fields
    assert!(validate_cron_expression("invalid").is_err());
}

#[test]
fn test_validate_query_valid() {
    // Valid queries - use parse_query directly
    assert!(parse_query("error").is_ok());
    assert!(parse_query("status=500").is_ok());
    assert!(parse_query("error | stats count() by src_ip").is_ok());
    assert!(parse_query("error OR warning").is_ok());
}

#[test]
fn test_validate_query_invalid() {
    // Invalid queries
    assert!(parse_query("").is_err());
    assert!(parse_query("error |").is_err());
}

#[test]
fn test_rule_mode_display() {
    assert_eq!(RuleMode::Live.to_string(), "live");
    assert_eq!(RuleMode::Alerting.to_string(), "alerting");
}

#[test]
fn test_rule_mode_default() {
    assert_eq!(RuleMode::default(), RuleMode::Staging);
}

#[test]
fn test_validate_realtime_rule_simple_filter() {
    // Valid real-time rule: simple filter with risk_entity_field
    let rule = NewDetectionRule {
        name: "Test Rule".to_string(),
        description: None,
        query: "dest_ip IN (192.0.2.1, 198.51.100.1)".to_string(),
        severity: Severity::High,
        mitre_tactics: None,
        mitre_techniques: None,
        schedule_cron: None,
        mode: Some(RuleMode::Live),
        narrative: None,
        reference_url: None,
        author: None,
        tags: None,
        ai_generated: None,
        realtime_enabled: None,
        detection_mode: Some(DetectionMode::RealTime),
        risk_score: Some(75),
        risk_entity_field: Some("src_ip".to_string()),
        risk_modifiers: None,
        lookback_minutes: None,
        auto_tuning_enabled: Some(true),
        auto_tuning_min_confidence: Some(0.8),
        auto_tuning_critical: Some(false),
        ai_triage_hints: None,
        folder: None,
        case_visibility: None,
        case_group_ids: None,
        alert_mode: None,
        case_assigned_group: None,
        playbook_selector_mode: None,
        playbook_id: None,
    };

    assert!(DetectionService::validate_realtime_rule_static(&rule).is_ok());
}

#[test]
fn test_validate_realtime_rule_with_aggregation() {
    // Real-time rule with aggregation should fail
    let rule = NewDetectionRule {
        name: "Test Rule".to_string(),
        description: None,
        query: "error | stats count() by src_ip".to_string(),
        severity: Severity::High,
        mitre_tactics: None,
        mitre_techniques: None,
        schedule_cron: None,
        mode: Some(RuleMode::Live),
        narrative: None,
        reference_url: None,
        author: None,
        tags: None,
        ai_generated: None,
        realtime_enabled: None,
        detection_mode: Some(DetectionMode::RealTime),
        risk_score: Some(75),
        risk_entity_field: Some("src_ip".to_string()),
        risk_modifiers: None,
        lookback_minutes: None,
        auto_tuning_enabled: Some(true),
        auto_tuning_min_confidence: Some(0.8),
        auto_tuning_critical: Some(false),
        ai_triage_hints: None,
        folder: None,
        case_visibility: None,
        case_group_ids: None,
        alert_mode: None,
        case_assigned_group: None,
        playbook_selector_mode: None,
        playbook_id: None,
    };

    let result = DetectionService::validate_realtime_rule_static(&rule);
    assert!(result.is_err());
    if let Err(DetectionError::InvalidRealtimeRule(msg)) = result {
        assert!(msg.contains("aggregations"));
    }
}

#[test]
fn test_validate_realtime_rule_with_join() {
    // Real-time rule with lookup should fail
    let rule = NewDetectionRule {
        name: "Test Rule".to_string(),
        description: None,
        query: "error | lookup assets src_ip".to_string(),
        severity: Severity::High,
        mitre_tactics: None,
        mitre_techniques: None,
        schedule_cron: None,
        mode: Some(RuleMode::Live),
        narrative: None,
        reference_url: None,
        author: None,
        tags: None,
        ai_generated: None,
        realtime_enabled: None,
        detection_mode: Some(DetectionMode::RealTime),
        risk_score: Some(75),
        risk_entity_field: Some("src_ip".to_string()),
        risk_modifiers: None,
        lookback_minutes: None,
        auto_tuning_enabled: Some(true),
        auto_tuning_min_confidence: Some(0.8),
        auto_tuning_critical: Some(false),
        ai_triage_hints: None,
        folder: None,
        case_visibility: None,
        case_group_ids: None,
        alert_mode: None,
        case_assigned_group: None,
        playbook_selector_mode: None,
        playbook_id: None,
    };

    let result = DetectionService::validate_realtime_rule_static(&rule);
    assert!(result.is_err());
    if let Err(DetectionError::InvalidRealtimeRule(msg)) = result {
        assert!(msg.contains("joins"));
    }
}

#[test]
fn test_validate_realtime_rule_without_risk_entity() {
    // Real-time rule without risk_entity_field should now succeed (auto-detection)
    let rule = NewDetectionRule {
        name: "Test Rule".to_string(),
        description: None,
        query: "dest_ip IN (192.0.2.1, 198.51.100.1)".to_string(),
        severity: Severity::High,
        mitre_tactics: None,
        mitre_techniques: None,
        schedule_cron: None,
        mode: Some(RuleMode::Live),
        narrative: None,
        reference_url: None,
        author: None,
        tags: None,
        ai_generated: None,
        realtime_enabled: None,
        detection_mode: Some(DetectionMode::RealTime),
        risk_score: Some(75),
        risk_entity_field: None, // Will auto-detect
        risk_modifiers: None,
        lookback_minutes: None,
        auto_tuning_enabled: Some(true),
        auto_tuning_min_confidence: Some(0.8),
        auto_tuning_critical: Some(false),
        ai_triage_hints: None,
        folder: None,
        case_visibility: None,
        case_group_ids: None,
        alert_mode: None,
        case_assigned_group: None,
        playbook_selector_mode: None,
        playbook_id: None,
    };

    // Should succeed with auto-detection
    let result = DetectionService::validate_realtime_rule_static(&rule);
    assert!(result.is_ok());
}
