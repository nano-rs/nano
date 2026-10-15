// SPDX-License-Identifier: AGPL-3.0-or-later

//! Per-entity risk semantics shared by BOTH detection engines (NAN-2713).
//!
//! The dedicated engine (`detection::service::alerts`) and the hosted-shared
//! publish path (`shared_security::publish_search_result`) must
//! score a firing rule identically:
//!
//! * **per entity**: a result set is partitioned into one finding group per
//!   entity. When the query ran `| risk score=… entity=…`, each event with a
//!   non-null query score is its own group keyed on the query entity; otherwise
//!   events are grouped by the rule's `risk_entity_field` (or every entity the
//!   active schema profile extracts when the field is unset);
//! * **risk_weight**: the deployment's (dedicated) or the tenant's (shared)
//!   weight multiplies every score, and a query `weight=` overrides it;
//! * **dataset=risk feedback guard**: a risk-dataset rule's score is forced to
//!   0 at the single scoring choke point;
//! * **alert cooldown**: an alert is suppressed for an entity still inside the
//!   rule's `alert_cooldown_minutes` window (time-anchored, anti-flap).
//!
//! Everything here is pure (no I/O): each engine reads its own persisted state
//! (the dedicated deployment tables, or the tenant's rows inside its signed
//! tenant transaction) and hands it in. That is also what keeps the shared
//! path tenant-local: nothing in this module can reach another tenant's data.

use std::collections::{HashMap, HashSet};

use chrono::{DateTime, Utc};
use serde_json::Value;

use crate::models::DetectionRule;
use crate::schema::SchemaProfile;

use super::risk::{RiskResult, ScoreCalculator};

/// One finding group: `(entity value, entity field, events)`.
pub type EntityGroup = (String, String, Vec<Value>);

/// Whether a rule targets the derived `risk` dataset (NAN-1805).
pub fn is_risk_dataset_rule(rule: &DetectionRule) -> bool {
    crate::query::Dataset::from_selector(rule.dataset.as_deref().unwrap_or("logs"))
        == crate::query::Dataset::Risk
}

/// Resolve `field` in a result row: a FLAT key first (OCSF dotted columns and
/// single-segment UDM fields), then a nested-path walk (UDM `metadata.*`).
/// Empty strings count as missing.
pub fn event_string_field(event: &Value, field: &str) -> Option<String> {
    if let Some(value) = event.get(field) {
        return value_to_string(value);
    }
    let mut current = event;
    for part in field.split('.') {
        current = current.get(part)?;
    }
    value_to_string(current)
}

fn value_to_string(value: &Value) -> Option<String> {
    match value {
        Value::String(text) if text.is_empty() => None,
        Value::String(text) => Some(text.clone()),
        Value::Number(number) => Some(number.to_string()),
        Value::Bool(flag) => Some(flag.to_string()),
        _ => None,
    }
}

/// Group events by entity so each entity gets its own risk score.
///
/// With `entity_field`, group by that field only (`unknown` when absent).
/// Without it, extract EVERY entity the profile's extraction order finds in
/// each event; an event with none falls back to its `time_bucket` (NAN-1711)
/// or `unknown`.
pub fn group_events_by_entity(
    profile: &dyn SchemaProfile,
    entity_field: Option<&str>,
    events: &[Value],
) -> HashMap<(String, String), Vec<Value>> {
    let mut grouped: HashMap<(String, String), Vec<Value>> = HashMap::new();
    match entity_field {
        Some(field) => {
            for event in events {
                let entity =
                    event_string_field(event, field).unwrap_or_else(|| "unknown".to_string());
                grouped
                    .entry((entity, field.to_string()))
                    .or_default()
                    .push(event.clone());
            }
        }
        None => {
            let order = profile.entity_extraction_order();
            for event in events {
                let mut found_any = false;
                for &(_role, field) in order {
                    if let Some(entity) = event_string_field(event, field) {
                        grouped
                            .entry((entity, field.to_string()))
                            .or_default()
                            .push(event.clone());
                        found_any = true;
                    }
                }
                if !found_any {
                    let key = match event_string_field(event, "time_bucket") {
                        Some(bucket) => (bucket, "time_bucket".to_string()),
                        None => ("unknown".to_string(), "unknown".to_string()),
                    };
                    grouped.entry(key).or_default().push(event.clone());
                }
            }
        }
    }
    grouped
}

/// Partition a result set into per-entity finding groups, honouring the nPL
/// `| risk` command's per-event score/entity when present.
///
/// Returns `(has_query_scores, groups)`. The batch has query scores iff ANY
/// event carries a non-null `raw_risk_score` (audit D10); then each such event
/// is its own group keyed on its query entity (a null-scored event in a mixed
/// batch produces no group, as authored). Otherwise events are grouped by the
/// rule's risk-entity field.
pub fn partition_entity_groups(
    calculator: &ScoreCalculator,
    profile: &dyn SchemaProfile,
    rule: &DetectionRule,
    results: &[Value],
    weight: f64,
) -> (bool, Vec<EntityGroup>) {
    let has_query_scores = results.iter().any(ScoreCalculator::has_query_risk_score);
    let groups = if has_query_scores {
        results
            .iter()
            .filter_map(|event| {
                let scored = calculator.calculate_from_query_result(event, weight)?;
                let field = scored.entity_field.clone().unwrap_or_default();
                Some((scored.entity, field, vec![event.clone()]))
            })
            .collect()
    } else {
        group_events_by_entity(profile, rule.risk_entity_field.as_deref(), results)
            .into_iter()
            .map(|((entity, field), events)| (entity, field, events))
            .collect()
    };
    (has_query_scores, groups)
}

/// The risk result for one entity group: the query-derived per-event score
/// when the rule's `| risk` produced one, else the rule-level score for the
/// group (`risk_score` or the severity default, `risk_modifiers`, `weight`).
/// A `dataset=risk` rule is forced to 0 here (NAN-1805 feedback-loop guard).
/// `None` only when a query-scored event can no longer be scored.
pub fn risk_result_for_group(
    calculator: &ScoreCalculator,
    rule: &DetectionRule,
    has_query_scores: bool,
    entity: &str,
    field: &str,
    events: &[Value],
    weight: f64,
) -> Option<RiskResult> {
    let result = if has_query_scores {
        calculator.calculate_from_query_result(events.first()?, weight)
    } else {
        let scored = calculator.calculate(
            rule.risk_score,
            rule.severity,
            Some(field),
            &rule.risk_modifiers,
            events,
            weight,
        );
        Some(RiskResult::new(
            scored.raw_score,
            scored.weighted_score,
            entity.to_string(),
            Some(field.to_string()),
            scored.factors,
        ))
    };
    if is_risk_dataset_rule(rule) {
        return result.map(|mut forced| {
            forced.raw_score = 0;
            forced.weighted_score = 0;
            forced.factors = vec![
                "dataset=risk rule: score forced to 0 (feedback-loop guard)".to_string(),
            ];
            forced
        });
    }
    result
}

/// Hysteresis gate for the per-rule alert cooldown (NAN-1805): is `now` still
/// inside the window that opened at the entity's last alert? `None` (no prior
/// alert) always fires. TIME-based, not edge-triggered.
pub fn within_alert_cooldown(
    last_alert_at: Option<DateTime<Utc>>,
    now: DateTime<Utc>,
    cooldown_minutes: i32,
) -> bool {
    match last_alert_at {
        None => false,
        Some(last) => {
            now.signed_duration_since(last)
                < chrono::Duration::minutes(i64::from(cooldown_minutes.max(0)))
        }
    }
}

/// The entities among `anchors` (persisted `(entity, last_alert_at)`) that are
/// still inside the cooldown window at `now`.
pub fn entities_in_cooldown(
    anchors: impl IntoIterator<Item = (String, DateTime<Utc>)>,
    now: DateTime<Utc>,
    cooldown_minutes: i32,
) -> HashSet<String> {
    if cooldown_minutes <= 0 {
        return HashSet::new();
    }
    anchors
        .into_iter()
        .filter(|(_, last)| within_alert_cooldown(Some(*last), now, cooldown_minutes))
        .map(|(entity, _)| entity)
        .collect()
}

/// Per-event mode: an event is suppressed when it carries at least one entity
/// and EVERY entity it carries is cooled (persisted anchor inside the window)
/// or already alerted earlier in this batch. An event with one fresh entity
/// still alerts (the grouped path's any-entity-passes semantics).
pub fn event_suppressed_by_cooldown(
    event_entities: &[String],
    cooled: &HashSet<String>,
    fired_this_batch: &HashSet<String>,
) -> bool {
    !event_entities.is_empty()
        && event_entities
            .iter()
            .all(|entity| cooled.contains(entity) || fired_this_batch.contains(entity))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{DetectionRule, Severity};
    use crate::schema::UdmProfile;
    use serde_json::json;

    fn rule(entity_field: Option<&str>, risk_score: Option<i32>) -> DetectionRule {
        use crate::models::detection_rule::{AlertMode, DetectionMode, RuleMode};
        DetectionRule {
            id: uuid::Uuid::now_v7(),
            name: "Test Rule".to_string(),
            description: None,
            query: "*".to_string(),
            severity: Severity::High,
            mitre_tactics: vec![],
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
            near_real_time_interval_seconds: None,
            execution_mode: None,
            risk_score,
            risk_entity_field: entity_field.map(str::to_string),
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

    fn sorted(groups: Vec<EntityGroup>) -> Vec<(String, String, usize)> {
        let mut out: Vec<_> = groups
            .into_iter()
            .map(|(entity, field, events)| (entity, field, events.len()))
            .collect();
        out.sort();
        out
    }

    #[test]
    fn grouped_rows_score_one_group_per_entity() {
        let rows = vec![
            json!({"device.hostname": "h1", "log_id": "1"}),
            json!({"device.hostname": "h1", "log_id": "2"}),
            json!({"device.hostname": "h2", "log_id": "3"}),
        ];
        let (query, groups) = partition_entity_groups(
            &ScoreCalculator::new(),
            &UdmProfile::new(),
            &rule(Some("device.hostname"), Some(80)),
            &rows,
            1.0,
        );
        assert!(!query);
        assert_eq!(
            sorted(groups),
            vec![
                ("h1".into(), "device.hostname".into(), 2),
                ("h2".into(), "device.hostname".into(), 1)
            ]
        );
    }

    #[test]
    fn query_scores_make_each_scored_row_its_own_entity() {
        let rows = vec![
            json!({"raw_risk_score": 80, "risk_entity": "h1", "risk_factors": ["a"]}),
            json!({"raw_risk_score": 90, "risk_entity": "h2", "risk_factors": ["b"]}),
            json!({"raw_risk_score": null, "risk_entity": "h3"}),
        ];
        let calculator = ScoreCalculator::new();
        let rule = rule(None, None);
        let (query, groups) =
            partition_entity_groups(&calculator, &UdmProfile::new(), &rule, &rows, 0.5);
        assert!(query);
        assert_eq!(groups.len(), 2, "a null-scored row is authored as no-risk");
        let (entity, field, events) = &groups[1];
        let risk =
            risk_result_for_group(&calculator, &rule, true, entity, field, events, 0.5).unwrap();
        assert_eq!((risk.entity.as_str(), risk.raw_score, risk.weighted_score), ("h2", 90, 45));
        assert_eq!(risk.factors, vec!["b".to_string()]);
    }

    #[test]
    fn weight_applies_to_rule_scores_and_query_weight_overrides_it() {
        let calculator = ScoreCalculator::new();
        let rule = rule(Some("user"), Some(80));
        let events = vec![json!({"user": "alice"})];
        let risk =
            risk_result_for_group(&calculator, &rule, false, "alice", "user", &events, 0.25)
                .unwrap();
        assert_eq!((risk.raw_score, risk.weighted_score), (80, 20));
        let row = json!({"raw_risk_score": 60, "risk_entity": "bob", "risk_weight": 1.0});
        let risk = risk_result_for_group(&calculator, &rule, true, "bob", "", &[row], 0.25)
            .unwrap();
        assert_eq!(risk.weighted_score, 60, "a query `weight=` overrides the tenant weight");
    }

    #[test]
    fn risk_dataset_rules_score_zero() {
        let calculator = ScoreCalculator::new();
        let mut rule = rule(Some("user"), Some(80));
        rule.dataset = Some("risk".into());
        let risk = risk_result_for_group(
            &calculator,
            &rule,
            false,
            "alice",
            "user",
            &[json!({"user": "alice"})],
            1.0,
        )
        .unwrap();
        assert_eq!((risk.raw_score, risk.weighted_score), (0, 0));
    }

    #[test]
    fn cooldown_is_time_anchored_and_per_entity() {
        let now = Utc::now();
        let cooled = entities_in_cooldown(
            vec![
                ("h1".to_string(), now - chrono::Duration::minutes(10)),
                ("h2".to_string(), now - chrono::Duration::minutes(90)),
            ],
            now,
            60,
        );
        assert_eq!(cooled, HashSet::from(["h1".to_string()]));
        assert!(entities_in_cooldown(vec![("h1".into(), now)], now, 0).is_empty());

        let fired = HashSet::from(["h3".to_string()]);
        assert!(event_suppressed_by_cooldown(&["h1".into()], &cooled, &fired));
        assert!(event_suppressed_by_cooldown(&["h1".into(), "h3".into()], &cooled, &fired));
        assert!(!event_suppressed_by_cooldown(&["h1".into(), "h2".into()], &cooled, &fired));
        assert!(!event_suppressed_by_cooldown(&[], &cooled, &fired));
    }
}
