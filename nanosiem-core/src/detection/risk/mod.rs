// SPDX-License-Identifier: AGPL-3.0-or-later

//! Risk Scoring Module
//!
//! Provides risk-based alerting capabilities for NanoSIEM:
//! - Static risk scores on detection rules with severity-based defaults
//! - Conditional score modifiers that adjust scores based on matched event conditions
//! - Global risk weight multiplier for system-wide tuning
//! - Entity extraction for cumulative risk tracking
//! - Cumulative risk aggregation for meta-detections
//!
//! Risk scores are integers from 0-100, where:
//! - 0-30: Low risk
//! - 31-50: Medium risk
//! - 51-70: High risk
//! - 71-100: Critical risk

mod calculator;
mod cumulative;
mod defaults;
mod types;

pub use calculator::{RiskResult, ScoreCalculator};
pub use cumulative::{
    extract_cumulative_risk_config, is_cumulative_risk_rule, CumulativeRiskConfig,
    CumulativeRiskResult,
};
pub use defaults::default_score_for_severity;
pub use types::{RiskError, RiskModifier};

#[cfg(any())]
mod tests {
    use super::*;
    use crate::models::Severity;
    use serde_json::{json, Value};

    // ========================================================================
    // RiskModifier Tests
    // ========================================================================

    #[test]
    fn test_risk_modifier_valid_score() {
        assert!(RiskModifier::validate_score(0).is_ok());
        assert!(RiskModifier::validate_score(50).is_ok());
        assert!(RiskModifier::validate_score(100).is_ok());
    }

    #[test]
    fn test_risk_modifier_invalid_score() {
        assert!(matches!(
            RiskModifier::validate_score(-1),
            Err(RiskError::ScoreOutOfBounds(-1))
        ));
        assert!(matches!(
            RiskModifier::validate_score(101),
            Err(RiskError::ScoreOutOfBounds(101))
        ));
    }

    #[test]
    fn test_risk_modifier_valid_conditions() {
        assert!(RiskModifier::validate_condition("count > 10").is_ok());
        assert!(RiskModifier::validate_condition("status = failure").is_ok());
        assert!(RiskModifier::validate_condition("count >= 5").is_ok());
        assert!(RiskModifier::validate_condition("count <= 100").is_ok());
        assert!(RiskModifier::validate_condition("status != success").is_ok());
        assert!(RiskModifier::validate_condition("message contains error").is_ok());
    }

    #[test]
    fn test_risk_modifier_invalid_conditions() {
        assert!(RiskModifier::validate_condition("").is_err());
        assert!(RiskModifier::validate_condition("just_a_field").is_err());
        assert!(RiskModifier::validate_condition("no operator here").is_err());
    }

    #[test]
    fn test_risk_modifier_evaluate_greater_than() {
        let modifier = RiskModifier {
            condition: "count > 10".to_string(),
            score: 80,
        };

        let events_match = vec![json!({"count": 15})];
        let events_no_match = vec![json!({"count": 5})];
        let events_equal = vec![json!({"count": 10})];

        assert!(modifier.evaluate(&events_match));
        assert!(!modifier.evaluate(&events_no_match));
        assert!(!modifier.evaluate(&events_equal));
    }

    #[test]
    fn test_risk_modifier_evaluate_equality() {
        let modifier = RiskModifier {
            condition: "status = failure".to_string(),
            score: 75,
        };

        let events_match = vec![json!({"status": "failure"})];
        let events_no_match = vec![json!({"status": "success"})];

        assert!(modifier.evaluate(&events_match));
        assert!(!modifier.evaluate(&events_no_match));
    }

    #[test]
    fn test_risk_modifier_evaluate_contains() {
        let modifier = RiskModifier {
            condition: "message contains error".to_string(),
            score: 60,
        };

        let events_match = vec![json!({"message": "An error occurred"})];
        let events_no_match = vec![json!({"message": "All good"})];

        assert!(modifier.evaluate(&events_match));
        assert!(!modifier.evaluate(&events_no_match));
    }

    #[test]
    fn test_risk_modifier_evaluate_nested_field() {
        let modifier = RiskModifier {
            condition: "metadata.count > 5".to_string(),
            score: 70,
        };

        let events_match = vec![json!({"metadata": {"count": 10}})];
        let events_no_match = vec![json!({"metadata": {"count": 3}})];

        assert!(modifier.evaluate(&events_match));
        assert!(!modifier.evaluate(&events_no_match));
    }

    // ========================================================================
    // ScoreCalculator Tests
    // ========================================================================

    #[test]
    fn test_severity_to_score_mapping() {
        let calc = ScoreCalculator::new();

        assert_eq!(calc.severity_to_score(Severity::Critical), 90);
        assert_eq!(calc.severity_to_score(Severity::High), 75);
        assert_eq!(calc.severity_to_score(Severity::Medium), 50);
        assert_eq!(calc.severity_to_score(Severity::Low), 25);
        assert_eq!(calc.severity_to_score(Severity::Informational), 10);
    }

    #[test]
    fn test_calculate_with_explicit_score() {
        let calc = ScoreCalculator::new();
        let events = vec![json!({"src_ip": "192.168.1.1"})];

        let result = calc.calculate(
            Some(75),
            Severity::Medium, // Should be ignored
            None,
            &[],
            &events,
            1.0,
        );

        assert_eq!(result.raw_score, 75);
        assert_eq!(result.weighted_score, 75);
    }

    #[test]
    fn test_calculate_with_severity_default() {
        let calc = ScoreCalculator::new();
        let events = vec![json!({"src_ip": "192.168.1.1"})];

        let result = calc.calculate(None, Severity::High, None, &[], &events, 1.0);

        assert_eq!(result.raw_score, 75);
        assert_eq!(result.weighted_score, 75);
        assert!(result
            .factors
            .iter()
            .any(|f| f.contains("severity_default")));
    }

    #[test]
    fn test_calculate_with_global_weight() {
        let calc = ScoreCalculator::new();
        let events = vec![json!({"src_ip": "192.168.1.1"})];

        let result = calc.calculate(Some(100), Severity::Critical, None, &[], &events, 0.5);

        assert_eq!(result.raw_score, 100);
        assert_eq!(result.weighted_score, 50);
    }

    #[test]
    fn test_calculate_with_zero_weight() {
        let calc = ScoreCalculator::new();
        let events = vec![json!({"src_ip": "192.168.1.1"})];

        let result = calc.calculate(Some(100), Severity::Critical, None, &[], &events, 0.0);

        assert_eq!(result.raw_score, 100);
        assert_eq!(result.weighted_score, 0);
    }

    #[test]
    fn test_calculate_with_modifiers() {
        let calc = ScoreCalculator::new();
        let events = vec![json!({"count": 15, "src_ip": "192.168.1.1"})];

        let modifiers = vec![
            RiskModifier {
                condition: "count > 10".to_string(),
                score: 85,
            },
            RiskModifier {
                condition: "count > 20".to_string(),
                score: 95,
            },
        ];

        let result = calc.calculate(Some(50), Severity::Medium, None, &modifiers, &events, 1.0);

        // Only first modifier matches, so score should be 85
        assert_eq!(result.raw_score, 85);
        assert!(result.factors.iter().any(|f| f.contains("count > 10")));
    }

    #[test]
    fn test_calculate_with_multiple_matching_modifiers() {
        let calc = ScoreCalculator::new();
        let events = vec![json!({"count": 25, "src_ip": "192.168.1.1"})];

        let modifiers = vec![
            RiskModifier {
                condition: "count > 10".to_string(),
                score: 70,
            },
            RiskModifier {
                condition: "count > 20".to_string(),
                score: 90,
            },
        ];

        let result = calc.calculate(Some(50), Severity::Medium, None, &modifiers, &events, 1.0);

        // Both modifiers match, highest score (90) should be used
        assert_eq!(result.raw_score, 90);
    }

    #[test]
    fn test_extract_entity_with_specified_field() {
        let calc = ScoreCalculator::new();
        let events = vec![json!({"user": "admin", "src_ip": "192.168.1.1"})];

        let (entity, field) = calc.extract_entity(Some("user"), &events);
        assert_eq!(entity, "admin");
        assert_eq!(field, Some("user".to_string()));
    }

    #[test]
    fn test_extract_entity_with_fallback() {
        let calc = ScoreCalculator::new();
        let events = vec![json!({"src_ip": "192.168.1.1"})];

        // No entity field specified, should fall back to src_ip
        let (entity, field) = calc.extract_entity(None, &events);
        assert_eq!(entity, "192.168.1.1");
        assert_eq!(field, Some("src_ip".to_string()));
    }

    #[test]
    fn test_extract_entity_fallback_order() {
        let calc = ScoreCalculator::new();

        // Test src_ip is preferred (IP addresses highest priority)
        let events1 =
            vec![json!({"src_ip": "10.0.0.1", "hostname": "server1", "file_hash": "abc123"})];
        let (entity1, field1) = calc.extract_entity(None, &events1);
        assert_eq!(entity1, "10.0.0.1");
        assert_eq!(field1, Some("src_ip".to_string()));

        // Test hostname is second preference when no IPs
        let events2 = vec![json!({"src_host": "server1", "user": "admin", "file_hash": "abc123"})];
        let (entity2, field2) = calc.extract_entity(None, &events2);
        assert_eq!(entity2, "server1");
        assert_eq!(field2, Some("src_host".to_string()));

        // Test user is third preference when no IPs or hostnames
        let events3 = vec![json!({"user": "admin", "file_hash": "abc123"})];
        let (entity3, field3) = calc.extract_entity(None, &events3);
        assert_eq!(entity3, "admin");
        assert_eq!(field3, Some("user".to_string()));

        // Test file_hash is fourth preference when no IPs, hostnames, or users
        let events4 = vec![json!({"file_hash": "abc123def456"})];
        let (entity4, field4) = calc.extract_entity(None, &events4);
        assert_eq!(entity4, "abc123def456");
        assert_eq!(field4, Some("file_hash".to_string()));
    }

    #[test]
    fn test_extract_entity_missing_field() {
        let calc = ScoreCalculator::new();
        let events = vec![json!({"other_field": "value"})];

        let (entity, field) = calc.extract_entity(Some("nonexistent"), &events);
        assert_eq!(entity, "unknown");
        assert_eq!(field, None);
    }

    #[test]
    fn test_extract_entity_empty_events() {
        let calc = ScoreCalculator::new();
        let events: Vec<Value> = vec![];

        let (entity, field) = calc.extract_entity(Some("user"), &events);
        assert_eq!(entity, "unknown");
        assert_eq!(field, None);
    }

    #[test]
    fn test_validate_weight() {
        assert!(ScoreCalculator::validate_weight(0.0).is_ok());
        assert!(ScoreCalculator::validate_weight(0.5).is_ok());
        assert!(ScoreCalculator::validate_weight(1.0).is_ok());
        assert!(ScoreCalculator::validate_weight(-0.1).is_err());
        assert!(ScoreCalculator::validate_weight(1.1).is_err());
    }

    // ========================================================================
    // Cumulative Risk Helper Tests
    // ========================================================================

    fn create_test_rule(query: &str) -> crate::models::DetectionRule {
        use crate::models::RuleMode;
        use chrono::Utc;
        crate::models::DetectionRule {
            id: uuid::Uuid::now_v7(),
            name: "Test Rule".to_string(),
            description: None,
            query: query.to_string(),
            severity: Severity::High,
            mitre_tactics: vec![],
            mitre_techniques: vec![],
            schedule_cron: None,
            enabled: true,
            mode: RuleMode::Alerting,
            narrative: None,
            reference_url: None,
            author: None,
            tags: vec![],
            ai_generated: false,
            realtime_enabled: false,
            risk_score: None,
            risk_entity_field: None,
            risk_modifiers: sqlx::types::Json(vec![]),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            last_run_at: None,
            last_match_at: None,
            match_count: 0,
            live_match_count: 0,
            detection_mode: crate::models::detection_rule::DetectionMode::Scheduled,
            materialized_view_name: None,
            archived: false,
            lookback_minutes: None,
            auto_tuning_enabled: true,
            auto_tuning_min_confidence: 0.8,
            auto_tuning_critical: false,
            auto_tuning_disabled_until: None,
        }
    }

    #[test]
    fn test_is_cumulative_risk_rule_valid() {
        let rule = create_test_rule(
            "source_type=findings | bin span=1h | stats sum(risk_score) as total by risk_entity | where total > 100"
        );
        assert!(is_cumulative_risk_rule(&rule));
    }

    #[test]
    fn test_is_cumulative_risk_rule_with_src_ip() {
        let rule = create_test_rule(
            "source_type=findings | stats sum(risk_score) as total by src_ip | where total >= 50",
        );
        assert!(is_cumulative_risk_rule(&rule));
    }

    #[test]
    fn test_is_cumulative_risk_rule_not_findings() {
        let rule = create_test_rule(
            "source_type=apache | stats sum(risk_score) as total by risk_entity | where total > 100"
        );
        assert!(!is_cumulative_risk_rule(&rule));
    }

    #[test]
    fn test_is_cumulative_risk_rule_no_sum() {
        let rule = create_test_rule(
            "source_type=findings | stats count() as total by risk_entity | where total > 100",
        );
        assert!(!is_cumulative_risk_rule(&rule));
    }

    #[test]
    fn test_is_cumulative_risk_rule_no_where() {
        let rule = create_test_rule(
            "source_type=findings | stats sum(risk_score) as total by risk_entity",
        );
        assert!(!is_cumulative_risk_rule(&rule));
    }

    #[test]
    fn test_is_cumulative_risk_rule_no_group_by() {
        let rule = create_test_rule(
            "source_type=findings | stats sum(risk_score) as total | where total > 100",
        );
        assert!(!is_cumulative_risk_rule(&rule));
    }

    #[test]
    fn test_extract_cumulative_risk_config_full() {
        let rule = create_test_rule(
            "source_type=findings | bin span=2h | stats sum(risk_score) as total by risk_entity | where total > 150"
        );
        let config = extract_cumulative_risk_config(&rule).unwrap();

        assert_eq!(config.window_seconds, 7200); // 2 hours
        assert_eq!(config.threshold, 150);
        assert_eq!(config.entity_field, "risk_entity");
    }

    #[test]
    fn test_extract_cumulative_risk_config_minutes() {
        let rule = create_test_rule(
            "source_type=findings | bin span=30m | stats sum(risk_score) as total by user | where total >= 75"
        );
        let config = extract_cumulative_risk_config(&rule).unwrap();

        assert_eq!(config.window_seconds, 1800); // 30 minutes
        assert_eq!(config.threshold, 75);
        assert_eq!(config.entity_field, "user");
    }

    #[test]
    fn test_extract_cumulative_risk_config_defaults() {
        let rule = create_test_rule(
            "source_type=findings | stats sum(risk_score) as total by risk_entity | where total > 100"
        );
        let config = extract_cumulative_risk_config(&rule).unwrap();

        // No bin span specified, should default to 1 hour
        assert_eq!(config.window_seconds, 3600);
        assert_eq!(config.threshold, 100);
    }

    #[test]
    fn test_extract_cumulative_risk_config_not_cumulative_rule() {
        let rule = create_test_rule("error | stats count() by src_ip");
        let config = extract_cumulative_risk_config(&rule);

        assert!(config.is_none());
    }

    #[test]
    fn test_cumulative_risk_result() {
        let result = CumulativeRiskResult::new("192.168.1.1".to_string(), 150, 5, 100, 3600);

        assert_eq!(result.entity, "192.168.1.1");
        assert_eq!(result.total_risk, 150);
        assert_eq!(result.signal_count, 5);
        assert!(result.threshold_exceeded);
        assert_eq!(result.threshold, 100);
        assert_eq!(result.window_seconds, 3600);
    }

    #[test]
    fn test_cumulative_risk_result_below_threshold() {
        let result = CumulativeRiskResult::new("admin".to_string(), 50, 2, 100, 3600);

        assert!(!result.threshold_exceeded);
    }

    #[test]
    fn test_cumulative_risk_config_window_duration() {
        let config = CumulativeRiskConfig::new(7200, 100);
        let duration = config.window_duration();

        assert_eq!(duration.num_seconds(), 7200);
    }
}
