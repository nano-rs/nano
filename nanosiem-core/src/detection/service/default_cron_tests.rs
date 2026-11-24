// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-5826: a scheduled rule saved without a `schedule_cron` was stored
//! unrunnable (the scheduler only claims rules with a cron) and only surfaced
//! as an ERROR log on every sync. Every save path now defaults the cron.

use super::rules::{missing_schedule_cron, DEFAULT_SCHEDULE_CRON};
use super::DetectionService;
use crate::models::detection_rule::DetectionMode;
use crate::detection::findings::tests::sample_rule;
use crate::models::{DetectionRule, NewDetectionRule, RuleMode, UpdateDetectionRule};

const SOURCE: &str = include_str!("rules.rs");

fn fn_body(name: &str) -> &'static str {
    let start = SOURCE
        .find(&format!("pub async fn {name}("))
        .unwrap_or_else(|| panic!("{name} exists"));
    let rest = &SOURCE[start + 1..];
    let end = rest
        .find("\n    pub async fn ")
        .map(|i| start + 1 + i)
        .unwrap_or(SOURCE.len());
    &SOURCE[start..end]
}

fn new_rule(body: serde_json::Value) -> NewDetectionRule {
    serde_json::from_value(body).expect("rule")
}

#[test]
fn scheduled_without_cron_needs_the_default() {
    assert_eq!(
        missing_schedule_cron(DetectionMode::Scheduled, None).as_deref(),
        Some(DEFAULT_SCHEDULE_CRON)
    );
    assert_eq!(
        missing_schedule_cron(DetectionMode::Scheduled, Some("  ")).as_deref(),
        Some(DEFAULT_SCHEDULE_CRON)
    );
    assert_eq!(missing_schedule_cron(DetectionMode::Scheduled, Some("0 * * * *")), None);
    assert_eq!(missing_schedule_cron(DetectionMode::RealTime, None), None);
}

#[test]
fn create_defaults_a_missing_cron_and_keeps_a_given_one() {
    // The e2e lookup UI test's body: scheduled, no cron.
    let mut rule = new_rule(serde_json::json!({
        "name": "e2e lookup ui", "query": "* | lookup t src_ip", "severity": "low",
        "mode": "live", "detection_mode": "scheduled",
    }));
    DetectionService::default_new_rule_cron(&mut rule);
    assert_eq!(rule.schedule_cron.as_deref(), Some(DEFAULT_SCHEDULE_CRON));

    // No detection_mode means scheduled.
    let mut rule = new_rule(serde_json::json!({"name": "n", "query": "q", "severity": "low"}));
    DetectionService::default_new_rule_cron(&mut rule);
    assert_eq!(rule.schedule_cron.as_deref(), Some(DEFAULT_SCHEDULE_CRON));

    let mut rule = new_rule(serde_json::json!({
        "name": "n", "query": "q", "severity": "low", "schedule_cron": "0 * * * *",
    }));
    DetectionService::default_new_rule_cron(&mut rule);
    assert_eq!(rule.schedule_cron.as_deref(), Some("0 * * * *"));

    let mut rule = new_rule(serde_json::json!({
        "name": "n", "query": "q", "severity": "low", "detection_mode": "real-time",
    }));
    DetectionService::default_new_rule_cron(&mut rule);
    assert_eq!(rule.schedule_cron, None);
}

#[test]
fn every_save_path_defaults_the_cron() {
    for name in ["create_rule", "create_rule_with_mode"] {
        let body = fn_body(name);
        let at = body.find("Self::default_new_rule_cron(&mut rule)").expect("defaults");
        let create = body.find("self.rule_repo.create(").expect("creates");
        let validate = body.find("self.validate_cron(").expect("validates");
        assert!(at < create, "{name} defaults the cron before it creates");
        assert!(at < validate, "{name} defaults the cron before it validates it");
    }
    for name in ["update_rule", "update_rule_with_mode"] {
        let body = fn_body(name);
        let at = body
            .find("Self::default_updated_rule_cron(&existing_rule, &mut update)")
            .expect("defaults");
        let write = body.find("self.rule_repo.update(").expect("updates");
        let validate = body.find("self.validate_cron(").expect("validates");
        assert!(at < write, "{name} defaults the cron before it writes");
        // Review P2: update_rule_with_mode validated first, so a blank cron
        // was a 400 there and a default everywhere else.
        assert!(at < validate, "{name} defaults the cron before it validates it");
    }
}

fn stored(mode: RuleMode, detection_mode: DetectionMode, cron: Option<&str>) -> DetectionRule {
    DetectionRule {
        mode,
        detection_mode,
        schedule_cron: cron.map(str::to_string),
        ..sample_rule()
    }
}

fn defaulted(existing: &DetectionRule, mut update: UpdateDetectionRule) -> Option<String> {
    DetectionService::default_updated_rule_cron(existing, &mut update);
    update.schedule_cron
}

#[test]
fn update_keeps_a_stored_cron() {
    let hourly = stored(RuleMode::Live, DetectionMode::Scheduled, Some("0 * * * *"));
    // Omitted: nothing written (COALESCE keeps the stored cron).
    assert_eq!(defaulted(&hourly, UpdateDetectionRule::default()), None);
    // Review P2: blank meant "missing" and clobbered the hourly cron with */5.
    for blank in ["", "   "] {
        let update = UpdateDetectionRule { schedule_cron: Some(blank.into()), ..Default::default() };
        assert_eq!(defaulted(&hourly, update), None, "{blank:?} must keep the stored cron");
    }
    let explicit = UpdateDetectionRule { schedule_cron: Some("*/15 * * * *".into()), ..Default::default() };
    assert_eq!(defaulted(&hourly, explicit).as_deref(), Some("*/15 * * * *"));
}

#[test]
fn update_defaults_a_cronless_scheduled_rule() {
    let cronless = stored(RuleMode::Staging, DetectionMode::Scheduled, None);
    assert_eq!(
        defaulted(&cronless, UpdateDetectionRule::default()).as_deref(),
        Some(DEFAULT_SCHEDULE_CRON)
    );
    let blank = UpdateDetectionRule { schedule_cron: Some(String::new()), ..Default::default() };
    assert_eq!(defaulted(&cronless, blank).as_deref(), Some(DEFAULT_SCHEDULE_CRON));
}

#[test]
fn update_mode_transitions() {
    // Real-time -> scheduled with no cron anywhere: the default.
    let realtime = stored(RuleMode::Live, DetectionMode::RealTime, None);
    let to_scheduled =
        UpdateDetectionRule { detection_mode: Some(DetectionMode::Scheduled), ..Default::default() };
    assert_eq!(defaulted(&realtime, to_scheduled).as_deref(), Some(DEFAULT_SCHEDULE_CRON));
    // Staying real-time, or scheduled -> real-time: never a cron.
    assert_eq!(defaulted(&realtime, UpdateDetectionRule::default()), None);
    let cronless = stored(RuleMode::Live, DetectionMode::Scheduled, None);
    let to_realtime =
        UpdateDetectionRule { detection_mode: Some(DetectionMode::RealTime), ..Default::default() };
    assert_eq!(defaulted(&cronless, to_realtime), None);
}

#[test]
fn activation_is_a_promotion_only_for_live_or_alerting() {
    let edit = UpdateDetectionRule { description: Some("typo".into()), ..Default::default() };
    for (mode, promote) in [
        (RuleMode::Live, true),
        (RuleMode::Alerting, true),
        (RuleMode::Staging, false),
        (RuleMode::Paused, false),
    ] {
        let cronless = stored(mode, DetectionMode::Scheduled, None);
        assert!(DetectionService::update_activates_schedule(&cronless, &edit), "{mode:?}");
        assert_eq!(
            DetectionService::update_activation_needs_promote(&cronless, &edit),
            promote,
            "{mode:?}"
        );
    }
    // Promoting a cron-less staging rule in the same edit is an activation too.
    let staging = stored(RuleMode::Staging, DetectionMode::Scheduled, None);
    let promote = UpdateDetectionRule { mode: Some(RuleMode::Alerting), ..Default::default() };
    assert!(DetectionService::update_activation_needs_promote(&staging, &promote));
    // A rule that already has a cron, or is real-time, or is deleted: no activation.
    let hourly = stored(RuleMode::Alerting, DetectionMode::Scheduled, Some("0 * * * *"));
    assert!(!DetectionService::update_activates_schedule(&hourly, &edit));
    let realtime = stored(RuleMode::Alerting, DetectionMode::RealTime, None);
    assert!(!DetectionService::update_activates_schedule(&realtime, &edit));
    let deleted = DetectionRule { archived: true, ..stored(RuleMode::Staging, DetectionMode::Scheduled, None) };
    assert!(!DetectionService::update_activates_schedule(&deleted, &edit));
}
