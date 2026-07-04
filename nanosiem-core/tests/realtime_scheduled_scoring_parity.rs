// SPDX-License-Identifier: AGPL-3.0-or-later
//
//! NAN-1663 (audit R1): the real-time detection path must score a rule
//! identically to the scheduled path. Both now route through the single scoring
//! engine (`ScoreCalculator::calculate`) via `score_rule_match`, applying the
//! rule's `risk_modifiers` and the global `risk_weight` — instead of the static
//! score the materialized view bakes into the `signals` row.
//!
//! These are the exact behaviors that were WRONG on the real-time path before the
//! fix (baked score ignored modifiers + weight), asserted against the shared
//! `score_rule_match` that the `SignalProcessor` now calls.

use nanosiem_core::detection::risk::{score_rule_match, RiskModifier, ScoreCalculator};
use nanosiem_core::models::detection_rule::{AiTriageHints, DetectionMode};
use nanosiem_core::models::{AlertMode, DetectionRule, RuleMode, Severity};
use serde_json::json;

/// Build a real-time rule with a base score, a `risk_modifiers` bump, and a
/// configured `risk_entity_field`. Field set mirrors the live `create_test_rule`
/// in `detection::materialized_view` tests.
fn rule_with_modifier() -> DetectionRule {
    use chrono::Utc;
    DetectionRule {
        id: uuid::Uuid::now_v7(),
        name: "admin-login".to_string(),
        description: None,
        query: "user=admin".to_string(),
        severity: Severity::Medium, // severity default (50) would apply if risk_score were None
        mitre_tactics: vec![],
        mitre_techniques: vec![],
        schedule_cron: None,
        mode: RuleMode::Alerting,
        narrative: None,
        reference_url: None,
        author: None,
        tags: vec![],
        ai_generated: false,
        realtime_enabled: true,
        detection_mode: DetectionMode::RealTime,
        materialized_view_name: Some("mv_rt_detection_x".to_string()),
        risk_score: Some(50),
        risk_entity_field: Some("user".to_string()),
        risk_modifiers: sqlx::types::Json(vec![RiskModifier {
            condition: "user = admin".to_string(),
            score: 90,
        }]),
        created_at: Utc::now(),
        updated_at: Utc::now(),
        last_run_at: None,
        last_match_at: None,
        match_count: 0,
        live_match_count: 0,
        archived: false,
        folder: None,
        ai_triage_hints: sqlx::types::Json(AiTriageHints::default()),
        lookback_minutes: None,
        dataset: None,
        auto_tuning_enabled: true,
        auto_tuning_min_confidence: 0.8,
        auto_tuning_critical: false,
        auto_tuning_disabled_until: None,
        case_visibility: "private".to_string(),
        case_assigned_group: None,
        alert_mode: AlertMode::default(),
        next_run_at: None,
        claimed_by: None,
        claimed_at: None,
        playbook_selector_mode: "none".to_string(),
        playbook_id: None,
    }
}

#[test]
fn realtime_score_applies_modifier_and_global_weight() {
    let calc = ScoreCalculator::new();
    let rule = rule_with_modifier();

    // Matched event trips the modifier (user=admin) → raw jumps 50 → 90, then the
    // global weight 0.5 attenuates it → 45. The pre-NAN-1663 baked path would have
    // emitted the rule's base 50 with no modifier and no weight.
    let events = vec![json!({"user": "admin", "src_ip": "10.0.0.9"})];
    let r = score_rule_match(&calc, &rule, &events, 0.5);

    assert_eq!(r.raw_score, 90, "modifier must apply on the real-time path");
    assert_eq!(r.weighted_score, 45, "global risk_weight must apply (90 * 0.5)");
    assert_eq!(r.entity, "admin", "entity extracted from risk_entity_field");
    assert_eq!(r.entity_field.as_deref(), Some("user"));
    assert!(r.factors.iter().any(|f| f.contains("user = admin")));
}

#[test]
fn realtime_score_without_modifier_match_uses_base_and_weight() {
    let calc = ScoreCalculator::new();
    let rule = rule_with_modifier();

    // user=bob does NOT trip the modifier → base 50, weighted by 0.5 → 25.
    let events = vec![json!({"user": "bob", "src_ip": "10.0.0.9"})];
    let r = score_rule_match(&calc, &rule, &events, 0.5);

    assert_eq!(r.raw_score, 50);
    assert_eq!(r.weighted_score, 25);
    assert_eq!(r.entity, "bob");
}

#[test]
fn realtime_and_scheduled_calls_are_equivalent() {
    // score_rule_match must be exactly the rule-level `calculate` call the
    // scheduled path makes (alerts::risk_result_for_group, non-query branch), so
    // the two execution modes cannot drift. Assert they produce identical results.
    let calc = ScoreCalculator::new();
    let rule = rule_with_modifier();
    let events = vec![json!({"user": "admin", "src_ip": "10.0.0.9"})];

    let via_helper = score_rule_match(&calc, &rule, &events, 0.7);
    let via_engine = calc.calculate(
        rule.risk_score,
        rule.severity,
        rule.risk_entity_field.as_deref(),
        &rule.risk_modifiers,
        &events,
        0.7,
    );

    assert_eq!(via_helper.raw_score, via_engine.raw_score);
    assert_eq!(via_helper.weighted_score, via_engine.weighted_score);
    assert_eq!(via_helper.entity, via_engine.entity);
    assert_eq!(via_helper.entity_field, via_engine.entity_field);
}
