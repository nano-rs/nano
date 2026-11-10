// SPDX-License-Identifier: AGPL-3.0-or-later
//! NAN-5204: backup status report auth + read response shape.

use super::*;
use chrono::{Duration, TimeZone};

#[test]
fn unconfigured_token_disables_the_endpoint() {
    assert_eq!(authorize_report(Some("Bearer x"), None), Err(StatusCode::NOT_FOUND));
    assert_eq!(authorize_report(None, None), Err(StatusCode::NOT_FOUND));
}

#[test]
fn wrong_or_missing_bearer_is_unauthorized() {
    let token = Some("s3cr3t-token");
    assert_eq!(authorize_report(None, token), Err(StatusCode::UNAUTHORIZED));
    assert_eq!(authorize_report(Some("s3cr3t-token"), token), Err(StatusCode::UNAUTHORIZED));
    assert_eq!(authorize_report(Some("Basic s3cr3t-token"), token), Err(StatusCode::UNAUTHORIZED));
    assert_eq!(authorize_report(Some("Bearer s3cr3t-tokeX"), token), Err(StatusCode::UNAUTHORIZED));
    assert_eq!(authorize_report(Some("Bearer s3cr3t"), token), Err(StatusCode::UNAUTHORIZED));
    assert_eq!(authorize_report(Some("Bearer s3cr3t-token"), token), Ok(()));
}

#[test]
fn unconfigured_response_is_all_nulls_and_not_stale() {
    let r = BackupStatusResponse::from_status(None, Utc::now());
    let v = serde_json::to_value(&r).unwrap();
    assert_eq!(v["configured"], false);
    assert_eq!(v["stale"], false);
    assert_eq!(v["stale_after_hours"], 36);
    assert!(v["enabled"].is_null());
    assert!(v["last_success_at"].is_null());
    assert!(v["destination"].is_null());
}

#[test]
fn configured_response_carries_staleness() {
    let now = Utc.with_ymd_and_hms(2026, 11, 10, 12, 0, 0).unwrap();
    let status = BackupStatus {
        enabled: true,
        enabled_since: Some(now - Duration::days(5)),
        last_attempt_at: Some(now - Duration::hours(1)),
        last_outcome: Some("failure".into()),
        last_success_at: Some(now - Duration::hours(40)),
        last_success_backup_id: Some("nano-20261108T200000Z-ab12cd34-host".into()),
        last_success_size_bytes: Some(1024),
        last_failure_at: Some(now - Duration::hours(1)),
        last_failure_error: Some("disk full".into()),
        consecutive_failures: 1,
        destination_kind: Some("path".into()),
        destination: Some("/mnt/backups".into()),
        clickhouse_data: Some("excluded".into()),
        schedule: Some("02:00".into()),
        keep: Some(7),
        next_run_at: None,
        updated_at: now,
    };
    let r = BackupStatusResponse::from_status(Some(status), now);
    assert!(r.configured);
    assert!(r.stale);
    assert_eq!(r.enabled, Some(true));
    assert_eq!(r.consecutive_failures, Some(1));
}
