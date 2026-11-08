// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-4917: the detection-rule compiler shares the query complexity guard —
//! a chained-eval rule that would blow up once ClickHouse inlines its aliases
//! is rejected at validation instead of reaching the scheduler.

use super::*;
use crate::{DetectionMode, NewDetectionRule, RuleMode, Severity};

fn rule(query: &str) -> NewDetectionRule {
    NewDetectionRule {
        name: "Test Rule".to_string(),
        description: None,
        query: query.to_string(),
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
        dataset: None,
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
        source_path: None,
        source_repo_url: None,
        alert_cooldown_minutes: None,
    }
}

fn hash_chain(stages: usize, depth: usize) -> String {
    let mut q = String::from("*");
    let mut prev = "src_ip".to_string();
    for s in 0..stages {
        let mut e = prev.clone();
        for _ in 0..depth {
            e = format!("md5({e})");
        }
        q.push_str(&format!(" | eval h{s}={e}"));
        prev = format!("h{s}");
    }
    q
}

#[test]
fn detection_compile_rejects_6x20_eval_chain() {
    let err = DetectionService::validate_realtime_rule_static(&rule(&hash_chain(6, 20)))
        .expect_err("6x20 chained eval must be rejected");
    assert!(
        matches!(err, DetectionError::QueryParseError(ref m) if m.contains("Query too complex")),
        "unexpected error: {err:?}"
    );
}

#[test]
fn detection_compile_accepts_normal_eval_chain() {
    let q = "process_name=\"cmd.exe\" | eval c=lower(command_line) | eval h=md5(c) | where len(h) > 3";
    let res = DetectionService::validate_realtime_rule_static(&rule(q));
    assert!(
        !matches!(res, Err(DetectionError::QueryParseError(_))),
        "normal eval chain must parse: {res:?}"
    );
}
