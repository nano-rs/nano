// SPDX-License-Identifier: AGPL-3.0-or-later
//! NAN-4954: SIEM Health surfaces security-critical audit delivery problems.

use super::tests::base_zero_metrics_fixture;
use super::*;
use crate::audit::AuditOutboxStats;

fn backlog(overdue: i64, oldest_secs: i64) -> AuditOutboxStats {
    AuditOutboxStats {
        pending: overdue,
        overdue,
        oldest_pending_age_secs: Some(oldest_secs),
        max_attempts: 3,
        last_error: Some("Code: 241. DB::Exception: MEMORY_LIMIT_EXCEEDED".to_string()),
        last_error_at: None,
        recorded_24h: overdue,
        deferred_24h: overdue,
    }
}

#[test]
fn no_stats_or_clean_stats_produce_no_finding() {
    assert!(audit_durability_recommendations(None).is_empty());
    assert!(audit_durability_recommendations(Some(&AuditOutboxStats::default())).is_empty());
    // Pending but still inside the inline window is not a backlog yet.
    let fresh = AuditOutboxStats { pending: 2, ..Default::default() };
    assert!(audit_durability_recommendations(Some(&fresh)).is_empty());
}

#[test]
fn backlog_is_high_then_critical_after_fifteen_minutes() {
    let recs = audit_durability_recommendations(Some(&backlog(4, 120)));
    assert_eq!(recs.len(), 1);
    assert_eq!(recs[0].priority, "high");
    assert!(recs[0].description.contains("MEMORY_LIMIT_EXCEEDED"));

    let recs = audit_durability_recommendations(Some(&backlog(4, 16 * 60)));
    assert_eq!(recs[0].priority, "critical");
}

#[test]
fn recovered_failures_stay_visible_as_medium() {
    let stats = AuditOutboxStats { recorded_24h: 10, deferred_24h: 3, ..Default::default() };
    let recs = audit_durability_recommendations(Some(&stats));
    assert_eq!(recs.len(), 1);
    assert_eq!(recs[0].priority, "medium");
    assert!(recs[0].title.contains("3 security audit writes"));
}

/// While ClickHouse is down the ingestion probes read zero, so the heuristic
/// lands on "Fresh" (score 100, no findings). The backlog must still surface.
#[test]
fn finding_survives_the_fresh_deployment_short_circuit() {
    let mut metrics = base_zero_metrics_fixture();
    metrics.audit_durability = Some(backlog(1, 300));
    let mut analysis = fallback_report(&metrics);
    assert!(analysis.recommendations.is_empty(), "fixture is a Fresh deployment");
    ensure_audit_durability_findings(&mut analysis, &metrics);
    assert_eq!(analysis.recommendations.len(), 1);
    // The headline can no longer read "healthy" (Fresh scores 100).
    assert_eq!(HealthStatus::from_score(analysis.overall_score), HealthStatus::Warning);
    // Idempotent: an AI result that already carries it is not duplicated.
    ensure_audit_durability_findings(&mut analysis, &metrics);
    assert_eq!(analysis.recommendations.len(), 1);
}

#[test]
fn critical_backlog_caps_the_score_at_critical() {
    let mut metrics = base_zero_metrics_fixture();
    metrics.audit_durability = Some(backlog(1, 20 * 60));
    let mut analysis = fallback_report(&metrics);
    ensure_audit_durability_findings(&mut analysis, &metrics);
    assert_eq!(HealthStatus::from_score(analysis.overall_score), HealthStatus::Critical);

    // A recovered (medium) finding informs but does not cap.
    metrics.audit_durability = Some(AuditOutboxStats { recorded_24h: 5, deferred_24h: 1, ..Default::default() });
    let mut analysis = fallback_report(&metrics);
    let before = analysis.overall_score;
    ensure_audit_durability_findings(&mut analysis, &metrics);
    assert_eq!(analysis.overall_score, before);
}

#[test]
fn reports_stored_before_nan4954_still_deserialize() {
    let mut value = serde_json::to_value(base_zero_metrics_fixture()).unwrap();
    value.as_object_mut().unwrap().remove("audit_durability");
    let metrics: CollectedMetrics =
        serde_json::from_value(value).expect("pre-NAN-4954 report deserializes");
    assert!(metrics.audit_durability.is_none());
}
