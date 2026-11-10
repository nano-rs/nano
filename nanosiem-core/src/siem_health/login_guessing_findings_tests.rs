// SPDX-License-Identifier: AGPL-3.0-or-later
//! NAN-5149: SIEM Health reports emails whose failed sign-ins across source
//! addresses reached the alert threshold (published to the system-health bus).

use super::tests::base_zero_metrics_fixture;
use super::*;
use crate::auth::login_throttle::GUESSING_DEDUP_KEY;
use crate::system_health::SystemHealthEvent;

fn event(email: &str, status: &str, last_seen_hours_ago: i64) -> SystemHealthEvent {
    let last_seen = chrono::Utc::now() - chrono::Duration::hours(last_seen_hours_ago);
    SystemHealthEvent {
        id: uuid::Uuid::now_v7(),
        tenant_id: "default".into(),
        dedup_key: GUESSING_DEDUP_KEY.into(),
        category: "service".into(),
        severity: "high".into(),
        status: status.into(),
        title: "t".into(),
        summary: "s".into(),
        resource_type: "user".into(),
        resource_id: None,
        resource_name: Some(email.into()),
        diagnostic_context: serde_json::json!({}),
        remediation: None,
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

#[test]
fn a_recent_guessing_condition_becomes_one_high_finding() {
    let mut analysis = fallback_report(&base_zero_metrics_fixture());
    let before = analysis.recommendations.len();
    let mut ev = event("admin@example.com", "active", 1);
    ev.occurrence_count = 3;
    let events = vec![ev];
    ensure_login_guessing_findings(&mut analysis, &events);
    assert_eq!(analysis.recommendations.len(), before + 1);
    let rec = &analysis.recommendations[0];
    assert_eq!(rec.priority, "high");
    assert!(rec.description.contains("3 time(s)"), "{}", rec.description);
    assert!(rec.description.contains("latest: admin@example.com"));
    // Idempotent across report paths.
    ensure_login_guessing_findings(&mut analysis, &events);
    assert_eq!(analysis.recommendations.len(), before + 1);
}

#[test]
fn stale_resolved_and_unrelated_events_are_ignored() {
    let mut other = event("x@example.com", "active", 0);
    other.dedup_key = "ip_allowlist:load_failed:nanosiem-api:0".into();
    let events = vec![
        event("old@example.com", "active", 30),
        event("done@example.com", "resolved", 1),
        other,
    ];
    assert!(login_guessing_recommendations(&events, chrono::Utc::now()).is_empty());
}
