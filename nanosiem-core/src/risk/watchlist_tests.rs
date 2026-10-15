use super::*;

#[test]
fn multiplier_math_tracks_doubles_and_rounds_like_clickhouse() {
    assert_eq!(effective_score(100, 0.0), 100, "weight 0 tracks only");
    assert_eq!(effective_score(100, 0.6), 160);
    assert_eq!(effective_score(100, 1.0), 200, "weight 1 doubles");
    assert_eq!(effective_score(0, 1.0), 0);
    // Half-to-even, like ClickHouse round() on Float64.
    assert_eq!(effective_score(3, 0.5), 4);
    assert_eq!(effective_score(1, 0.5), 2);
    assert_eq!(effective_score(5, 0.5), 8);
}

#[test]
fn stacking_takes_the_max_weight_and_drops_zero_weights() {
    let weights = RiskWatchWeights::from_rows([
        ("alice".to_string(), 25),
        ("alice".to_string(), 60),
        ("ALICE ".to_string(), 40),
        ("bob".to_string(), 0),
        ("10.0.0.5".to_string(), 100),
    ]);
    assert_eq!(
        weights.weight("alice"),
        0.6,
        "max of the enabled lists, never compounded"
    );
    assert_eq!(weights.weight("Alice"), 0.6, "matched case-insensitively");
    assert_eq!(
        weights.weight("bob"),
        0.0,
        "a weight-0 list tracks without amplifying"
    );
    assert_eq!(weights.weight("carol"), 0.0);
    assert_eq!(weights.len(), 2);
    assert_eq!(effective_score(100, weights.weight("alice")), 160);
    assert_eq!(effective_score(100, weights.weight("10.0.0.5")), 200);
}

#[test]
fn parallel_arrays_carry_a_typing_sentinel() {
    let (entities, weights) = RiskWatchWeights::default().parallel_arrays();
    assert_eq!(entities, vec![String::new()]);
    assert_eq!(weights, vec![0.0]);
    let (entities, weights) =
        RiskWatchWeights::from_rows([("x".to_string(), 50)]).parallel_arrays();
    assert_eq!(entities, vec!["x".to_string(), String::new()]);
    assert_eq!(weights, vec![0.5, 0.0]);
    let lake = RiskWatchWeights::from_rows([("x".to_string(), 50)]).lake_map();
    assert_eq!(lake.get("x"), Some(&0.5));
    assert!(!lake.contains_key(""), "the lake map carries no sentinel");
}

#[test]
fn type_detection_follows_the_design_rules() {
    assert_eq!(detect_entity_type("10.1.2.3"), WatchEntityType::Ip);
    assert_eq!(detect_entity_type("10.1.0.0/16"), WatchEntityType::Ip);
    assert_eq!(detect_entity_type("fe80::1"), WatchEntityType::Ip);
    assert_eq!(detect_entity_type(&"a".repeat(32)), WatchEntityType::Hash);
    assert_eq!(detect_entity_type(&"0F".repeat(20)), WatchEntityType::Hash);
    assert_eq!(detect_entity_type(&"b".repeat(64)), WatchEntityType::Hash);
    assert_eq!(detect_entity_type(&"b".repeat(33)), WatchEntityType::User);
    assert_eq!(
        detect_entity_type("ws-042.corp.local"),
        WatchEntityType::Host
    );
    assert_eq!(detect_entity_type("alice@corp.com"), WatchEntityType::User);
    assert_eq!(detect_entity_type("svc_backup"), WatchEntityType::User);
    assert_eq!(
        detect_entity_type("10.1.2.3/40"),
        WatchEntityType::Host,
        "an invalid prefix is not an address"
    );
}

#[test]
fn validation_normalizes_and_refuses_bad_input() {
    assert_eq!(validate_name(" vip_execs ").unwrap(), "vip_execs");
    assert!(validate_name("VIP").is_err());
    assert!(validate_name("_x").is_err());
    assert!(validate_name("has space").is_err());
    assert!(validate_name(&"a".repeat(65)).is_err());
    assert!(validate_name("").is_err());
    assert_eq!(validate_weight(0.6).unwrap(), 60);
    assert_eq!(validate_weight(1.0).unwrap(), 100);
    assert!(validate_weight(1.01).is_err());
    assert!(validate_weight(-0.1).is_err());
    assert!(validate_weight(f64::NAN).is_err());
    assert_eq!(
        normalize_entity_value("  Alice@Corp.COM ").unwrap(),
        "alice@corp.com"
    );
    assert!(
        normalize_entity_value("10.0.0.0/8").is_err(),
        "CIDR is refused, not silently unscored"
    );
    assert!(normalize_entity_value("   ").is_err());
    assert!(normalize_entity_value("a\nb").is_err());
    assert!(validate_description(&"d".repeat(201)).is_err());
    assert!(validate_note(&"n".repeat(501)).is_err());
}

#[test]
fn entity_type_round_trips() {
    for kind in [
        WatchEntityType::User,
        WatchEntityType::Host,
        WatchEntityType::Ip,
        WatchEntityType::Hash,
    ] {
        assert_eq!(WatchEntityType::parse(kind.as_str()), Some(kind));
        assert_eq!(serde_json::to_value(kind).unwrap(), kind.as_str());
    }
    assert_eq!(WatchEntityType::parse("email"), None);
}

// NAN-3232: callers without `risk:watchlists` see the effective score but no
// watch fields, and the serialized rows carry no trace of them.
#[test]
fn hiding_watch_fields_keeps_the_effective_score_and_drops_every_hint() {
    use crate::risk::{EntityRiskSummary, RiskLevel, TimeWindowedRiskScore};
    assert!(may_view_watchlists(&["risk:view", "risk:watchlists"]));
    assert!(!may_view_watchlists(&["risk:view", "risk:configure"]));
    assert!(!may_view_watchlists::<&str>(&[]));

    let mut summary = EntityRiskSummary {
        entity: "alice".into(),
        entity_type: "user".into(),
        risk_score: 160,
        signal_count: 3,
        last_signal_at: None,
        last_rule_name: None,
        last_severity: None,
        risk_level: RiskLevel::Critical,
        base_risk_score: Some(100),
        watch_weight: Some(0.6),
    };
    summary.hide_watch();
    assert_eq!(summary.risk_score, 160, "effective score stays");
    let json = serde_json::to_value(&summary).unwrap();
    assert!(
        json.get("base_risk_score").is_none() && json.get("watch_weight").is_none(),
        "{json}"
    );

    let mut windowed = TimeWindowedRiskScore {
        entity: "alice".into(),
        entity_type: "user".into(),
        risk_score_24h: 10,
        risk_score_7d: 100,
        decayed_score_24h: 16,
        decayed_score_7d: 160,
        finding_count_24h: 1,
        finding_count_7d: 3,
        last_finding_at: None,
        last_rule_name: None,
        last_severity: None,
        base_decayed_score_24h: Some(10),
        base_decayed_score_7d: Some(100),
        watch_weight: Some(0.6),
    };
    windowed.hide_watch();
    assert_eq!(windowed.decayed_score_7d, 160);
    let json = serde_json::to_value(&windowed).unwrap();
    for field in [
        "base_decayed_score_24h",
        "base_decayed_score_7d",
        "watch_weight",
    ] {
        assert!(json.get(field).is_none(), "{field} leaked: {json}");
    }
}

#[test]
fn hidden_timeline_contributions_sum_to_the_effective_score() {
    use crate::risk::timeline::EntityRiskTimeline;
    use crate::risk::EntityRuleContribution;
    let contribution = |rule: &str, c24: i64, c7: i64| EntityRuleContribution {
        rule_id: rule.into(),
        rule_name: rule.into(),
        severity: "high".into(),
        fires_24h: 1,
        fires_7d: 1,
        decayed_contribution_24h: c24,
        decayed_contribution_7d: c7,
        last_fire_at: chrono::Utc::now(),
        last_fire_score: 50,
        mitre_tactics: vec![],
        mitre_techniques: vec![],
    };
    let mut timeline = EntityRiskTimeline::empty(chrono::Utc::now());
    timeline.contributions = vec![contribution("a", 10, 60), contribution("b", 0, 40)];
    timeline.apply_watch_weight(0.5);
    assert_eq!(timeline.watch_weight, Some(0.5));
    timeline.hide_watch();
    assert_eq!(timeline.watch_weight, None);
    let sum: i64 = timeline
        .contributions
        .iter()
        .map(|c| c.decayed_contribution_7d)
        .sum();
    assert_eq!(
        sum,
        effective_score(100, 0.5),
        "base 100 is not recoverable from the breakdown"
    );
    assert_eq!(timeline.contributions[0].decayed_contribution_24h, 15);

    // Unwatched: hiding changes nothing.
    let mut unwatched = vec![contribution("a", 10, 60)];
    scale_contributions_to_effective(&mut unwatched, None);
    scale_contributions_to_effective(&mut unwatched, Some(0.0));
    assert_eq!(unwatched[0].decayed_contribution_7d, 60);
}
