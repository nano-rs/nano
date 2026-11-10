// SPDX-License-Identifier: AGPL-3.0-or-later
//! NAN-5204: backup status staleness rule and report validation.

use super::*;
use chrono::TimeZone;

fn now() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 11, 10, 12, 0, 0).unwrap()
}

fn status(enabled: bool) -> BackupStatus {
    BackupStatus {
        enabled,
        enabled_since: Some(now() - Duration::days(30)),
        last_attempt_at: None,
        last_outcome: None,
        last_success_at: None,
        last_success_backup_id: None,
        last_success_size_bytes: None,
        last_failure_at: None,
        last_failure_error: None,
        consecutive_failures: 0,
        destination_kind: Some("path".into()),
        destination: Some("/mnt/backups".into()),
        clickhouse_data: Some("excluded".into()),
        schedule: Some("02:00".into()),
        keep: Some(7),
        next_run_at: None,
        updated_at: now(),
    }
}

#[test]
fn re_enabled_recently_with_an_old_success_is_not_stale() {
    let s = BackupStatus {
        enabled_since: Some(now() - Duration::hours(2)),
        last_success_at: Some(now() - Duration::days(10)),
        ..status(true)
    };
    assert!(!is_stale(&s, now()));
    let s = BackupStatus { enabled_since: Some(now() - Duration::hours(40)), ..s };
    assert!(is_stale(&s, now()));
}

#[test]
fn fresh_success_is_not_stale() {
    let s = BackupStatus { last_success_at: Some(now() - Duration::hours(10)), ..status(true) };
    assert!(!is_stale(&s, now()));
}

#[test]
fn success_37_hours_old_is_stale() {
    let s = BackupStatus { last_success_at: Some(now() - Duration::hours(37)), ..status(true) };
    assert!(is_stale(&s, now()));
}

#[test]
fn exactly_36_hours_is_not_yet_stale() {
    let s = BackupStatus { last_success_at: Some(now() - Duration::hours(36)), ..status(true) };
    assert!(!is_stale(&s, now()));
}

#[test]
fn never_succeeded_but_enabled_10_hours_ago_is_not_stale() {
    let s = BackupStatus { enabled_since: Some(now() - Duration::hours(10)), ..status(true) };
    assert!(!is_stale(&s, now()));
}

#[test]
fn never_succeeded_enabled_40_hours_ago_is_stale() {
    let s = BackupStatus { enabled_since: Some(now() - Duration::hours(40)), ..status(true) };
    assert!(is_stale(&s, now()));
}

#[test]
fn disabled_with_old_success_is_not_stale() {
    let s = BackupStatus { last_success_at: Some(now() - Duration::days(30)), ..status(false) };
    assert!(!is_stale(&s, now()));
}

#[test]
fn recent_success_wins_over_old_enabled_since() {
    let s = BackupStatus {
        enabled_since: Some(now() - Duration::days(90)),
        last_success_at: Some(now() - Duration::hours(1)),
        ..status(true)
    };
    assert!(!is_stale(&s, now()));
}

fn report(json: serde_json::Value) -> BackupStatusReport {
    serde_json::from_value(json).expect("report deserializes")
}

fn base() -> serde_json::Value {
    serde_json::json!({
        "enabled": true,
        "outcome": "success",
        "started_at": "2026-11-10T02:00:00Z",
        "finished_at": "2026-11-10T02:04:00Z",
        "backup_id": "nano-20261110T020000Z-ab12cd34-host",
        "size_bytes": 12345,
        "destination_kind": "s3",
        "destination": "s3://bucket/prefix",
        "clickhouse_data": "excluded",
        "schedule": "02:00",
        "keep": 7,
        "next_run_at": "2026-11-11T02:00:00Z"
    })
}

fn with(key: &str, value: serde_json::Value) -> serde_json::Value {
    let mut v = base();
    v[key] = value;
    v
}

#[test]
fn valid_success_report_passes() {
    let r = report(base()).validate().unwrap();
    assert!(r.enabled);
    assert_eq!(r.outcome, BackupOutcome::Success);
    assert_eq!(r.backup_id.as_deref(), Some("nano-20261110T020000Z-ab12cd34-host"));
    assert_eq!(r.size_bytes, Some(12345));
    assert_eq!(r.error, None);
}

#[test]
fn unknown_enum_values_are_rejected_at_deserialize() {
    for (k, v) in [("outcome", "half"), ("destination_kind", "gcs"), ("clickhouse_data", "some")] {
        assert!(serde_json::from_value::<BackupStatusReport>(with(k, v.into())).is_err(), "{k}={v}");
    }
}

#[test]
fn bounds_are_enforced() {
    let long = "x".repeat(MAX_DESTINATION_LEN + 1);
    assert_eq!(
        report(with("destination", long.into())).validate(),
        Err(BackupStatusValidationError::Destination)
    );
    assert_eq!(
        report(with("destination", "s3://key:secret@bucket/p".into())).validate(),
        Err(BackupStatusValidationError::DestinationCredentials)
    );
    assert_eq!(
        report(with("backup_id", "../etc/passwd".into())).validate(),
        Err(BackupStatusValidationError::BackupId)
    );
    assert_eq!(
        report(with("backup_id", "a".repeat(201).into())).validate(),
        Err(BackupStatusValidationError::BackupId)
    );
    assert_eq!(
        report(with("size_bytes", (-1).into())).validate(),
        Err(BackupStatusValidationError::SizeBytes)
    );
    assert_eq!(report(with("keep", (-1).into())).validate(), Err(BackupStatusValidationError::Keep));
    assert_eq!(report(with("schedule", "".into())).validate(), Err(BackupStatusValidationError::Schedule));
}

#[test]
fn failure_error_is_truncated_and_success_fields_dropped() {
    let mut v = with("outcome", "failure".into());
    v["error"] = "é".repeat(MAX_ERROR_CHARS + 50).into();
    let r = report(v).validate().unwrap();
    assert_eq!(r.error.as_ref().unwrap().chars().count(), MAX_ERROR_CHARS);
    assert_eq!(r.backup_id, None);
    assert_eq!(r.size_bytes, None);
}

#[test]
fn disabled_outcome_forces_enabled_false() {
    let r = report(with("outcome", "disabled".into())).validate().unwrap();
    assert!(!r.enabled);
    assert_eq!(r.backup_id, None);
}

#[test]
fn success_drops_error_text() {
    let r = report(with("error", "boom".into())).validate().unwrap();
    assert_eq!(r.error, None);
}

#[test]
fn partial_keeps_the_backup_and_its_warning() {
    // NAN-5204 review M4: a partial backup is the latest backup AND carries
    // its warning; it is never recorded as a clean success.
    let mut value = with("outcome", "partial".into());
    value["error"] = "lookup rows not included: ClickHouse unreachable".into();
    let r = report(value).validate().unwrap();
    assert_eq!(r.outcome, BackupOutcome::Partial);
    assert_eq!(r.backup_id.as_deref(), Some("nano-20261110T020000Z-ab12cd34-host"));
    assert_eq!(r.size_bytes, Some(12345));
    assert_eq!(r.error.as_deref(), Some("lookup rows not included: ClickHouse unreachable"));
}
