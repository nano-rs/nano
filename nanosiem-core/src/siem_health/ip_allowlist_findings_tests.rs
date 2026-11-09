// SPDX-License-Identifier: AGPL-3.0-or-later
//! NAN-5077: SIEM Health surfaces IP allowlist rule-load failures published
//! to the system-health bus.

use super::tests::base_zero_metrics_fixture;
use super::*;
use crate::ip_allowlist::LOAD_FAILED_DEDUP_PREFIX;
use crate::system_health::SystemHealthEvent;

fn event(dedup_key: &str, status: &str, severity: &str, last_seen_hours_ago: i64) -> SystemHealthEvent {
    let now = chrono::Utc::now();
    let last_seen = now - chrono::Duration::hours(last_seen_hours_ago);
    SystemHealthEvent {
        id: uuid::Uuid::now_v7(),
        tenant_id: "default".into(),
        dedup_key: dedup_key.into(),
        category: "service".into(),
        severity: severity.into(),
        status: status.into(),
        title: "t".into(),
        summary: "Loading the IP allowlist rules from PostgreSQL failed (pool timed out).".into(),
        resource_type: "ip_allowlist".into(),
        resource_id: Some("api-0".into()),
        resource_name: Some("nanosiem-api".into()),
        diagnostic_context: serde_json::json!({}),
        remediation: Some("Break-glass: NANO_IP_ALLOWLIST_DISABLED=true.".into()),
        source: "nanosiem-api".into(),
        occurrence_count: 1,
        first_seen_at: last_seen,
        last_seen_at: last_seen,
        last_notified_at: None,
        acknowledged_at: None,
        acknowledged_by: None,
        resolved_at: (status == "resolved").then_some(last_seen),
        created_at: last_seen,
        updated_at: last_seen,
    }
}

fn key() -> String {
    format!("{LOAD_FAILED_DEDUP_PREFIX}nanosiem-api:api-0")
}

#[test]
fn an_active_fail_closed_condition_is_critical_and_caps_the_score() {
    let mut analysis = fallback_report(&base_zero_metrics_fixture());
    let events = vec![event(&key(), "active", "critical", 0)];
    ensure_ip_allowlist_findings(&mut analysis, &events);
    assert_eq!(analysis.recommendations.len(), 1);
    assert_eq!(analysis.recommendations[0].priority, "critical");
    assert!(analysis.recommendations[0].description.contains("NANO_IP_ALLOWLIST_DISABLED"));
    assert_eq!(HealthStatus::from_score(analysis.overall_score), HealthStatus::Critical);
    // Idempotent across report paths.
    ensure_ip_allowlist_findings(&mut analysis, &events);
    assert_eq!(analysis.recommendations.len(), 1);
}

#[test]
fn an_active_last_known_condition_is_high() {
    let recs = ip_allowlist_load_recommendations(&[event(&key(), "active", "high", 0)], chrono::Utc::now());
    assert_eq!(recs.len(), 1);
    assert_eq!(recs[0].priority, "high");
}

#[test]
fn a_recovered_failure_is_reported_for_24_hours() {
    let now = chrono::Utc::now();
    let recent = ip_allowlist_load_recommendations(&[event(&key(), "resolved", "critical", 2)], now);
    assert_eq!(recent.len(), 1);
    assert_eq!(recent[0].priority, "medium");
    let old = ip_allowlist_load_recommendations(&[event(&key(), "resolved", "critical", 30)], now);
    assert!(old.is_empty());
}

/// An active condition whose process stopped heartbeating (died mid-outage)
/// no longer counts as live: it does not pin the score at critical.
#[test]
fn an_orphaned_active_condition_is_not_live() {
    let mut analysis = fallback_report(&base_zero_metrics_fixture());
    let before = analysis.overall_score;
    ensure_ip_allowlist_findings(&mut analysis, &[event(&key(), "active", "critical", 2)]);
    assert_eq!(analysis.recommendations.len(), 1);
    assert_eq!(analysis.recommendations[0].priority, "medium");
    assert_eq!(analysis.overall_score, before);
    let old = ip_allowlist_load_recommendations(&[event(&key(), "active", "critical", 30)], chrono::Utc::now());
    assert!(old.is_empty());
}

#[test]
fn unrelated_service_events_and_a_quiet_bus_add_nothing() {
    let mut analysis = fallback_report(&base_zero_metrics_fixture());
    let before = analysis.overall_score;
    ensure_ip_allowlist_findings(&mut analysis, &[event("disk_pressure:x", "active", "critical", 0)]);
    ensure_ip_allowlist_findings(&mut analysis, &[]);
    assert!(analysis.recommendations.is_empty());
    assert_eq!(analysis.overall_score, before);
}
