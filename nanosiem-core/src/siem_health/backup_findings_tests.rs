// SPDX-License-Identifier: AGPL-3.0-or-later
//! NAN-5204: SIEM Health raises a high finding when automatic backups are
//! enabled but none succeeded in 36 hours.

use super::tests::base_zero_metrics_fixture;
use super::*;
use crate::backup_status::BackupStatus;
use chrono::{DateTime, Duration, TimeZone, Utc};

fn now() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 11, 10, 12, 0, 0).unwrap()
}

fn status(enabled: bool, last_success_hours_ago: Option<i64>) -> BackupStatus {
    BackupStatus {
        enabled,
        enabled_since: Some(now() - Duration::days(10)),
        last_attempt_at: Some(now() - Duration::hours(2)),
        last_outcome: Some("failure".into()),
        last_success_at: last_success_hours_ago.map(|h| now() - Duration::hours(h)),
        last_success_backup_id: None,
        last_success_size_bytes: None,
        last_failure_at: Some(now() - Duration::hours(2)),
        last_failure_error: Some("s3 upload: AccessDenied".into()),
        consecutive_failures: 2,
        destination_kind: Some("s3".into()),
        destination: Some("s3://bucket/nano".into()),
        clickhouse_data: Some("excluded".into()),
        schedule: Some("02:00".into()),
        keep: Some(7),
        next_run_at: None,
        updated_at: now(),
    }
}

#[test]
fn stale_backup_surfaces_high_finding_and_caps_score() {
    let metrics = base_zero_metrics_fixture();
    let mut analysis = fallback_report(&metrics);
    assert!(analysis.recommendations.is_empty(), "fixture is a Fresh deployment");
    let s = status(true, Some(50));
    ensure_backup_findings(&mut analysis, Some(&s), now());
    assert_eq!(analysis.recommendations.len(), 1);
    let rec = &analysis.recommendations[0];
    assert_eq!(rec.title, BACKUP_STALE_TITLE);
    assert_eq!(rec.priority, "high");
    assert!(rec.description.contains("2026-11-08 10:00 UTC (50h ago)"), "{}", rec.description);
    assert!(rec.description.contains("AccessDenied"));
    assert!(rec.description.contains("scripts/nano backup-schedule --status"));
    assert!(rec.description.contains("Automatic backups"));
    assert!(analysis.overall_score <= 79);
    // Idempotent across report paths.
    ensure_backup_findings(&mut analysis, Some(&s), now());
    assert_eq!(analysis.recommendations.len(), 1);
}

#[test]
fn never_succeeded_says_never() {
    let recs = backup_recommendations(Some(&status(true, None)), now());
    assert_eq!(recs.len(), 1);
    assert!(recs[0].description.contains("was: never."), "{}", recs[0].description);
}

#[test]
fn fresh_disabled_or_unconfigured_adds_nothing() {
    let metrics = base_zero_metrics_fixture();
    for s in [Some(status(true, Some(5))), Some(status(false, Some(500))), None] {
        let mut analysis = fallback_report(&metrics);
        let before = analysis.overall_score;
        ensure_backup_findings(&mut analysis, s.as_ref(), now());
        assert!(analysis.recommendations.is_empty());
        assert_eq!(analysis.overall_score, before);
    }
}

#[test]
fn fresh_partial_backup_surfaces_the_missing_lookups() {
    // NAN-5204 review M4.
    let mut s = status(true, Some(3));
    s.last_outcome = Some("partial".into());
    s.consecutive_failures = 0;
    s.last_failure_error = Some("lookup rows not included: ClickHouse unreachable".into());
    let recs = backup_recommendations(Some(&s), now());
    assert_eq!(recs.len(), 1);
    assert_eq!(recs[0].title, "Last backup is missing the ClickHouse lookup tables");
    assert!(recs[0].description.contains("ClickHouse unreachable"));
    s.enabled = false;
    assert!(backup_recommendations(Some(&s), now()).is_empty());
}
