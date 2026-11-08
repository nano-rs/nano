// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-1747 pure-logic tests for the alert repository: the SOAR stream safety
//! lag (A5) and the status-count mapper (A12). Kept in a sibling file per the
//! repo convention (tests in dedicated files, not large inline modules).

use super::*;
use chrono::{TimeZone, Utc};

#[test]
fn apply_safety_lag_subtracts_positive_lag() {
    let now = Utc.with_ymd_and_hms(2026, 7, 7, 12, 0, 30).unwrap();
    let cutoff = apply_safety_lag(now, 5);
    assert_eq!(cutoff, Utc.with_ymd_and_hms(2026, 7, 7, 12, 0, 25).unwrap());
    // A row created within the lag window is excluded (created_at > cutoff);
    // one older than the lag is eligible.
    let just_created = Utc.with_ymd_and_hms(2026, 7, 7, 12, 0, 28).unwrap();
    let settled = Utc.with_ymd_and_hms(2026, 7, 7, 12, 0, 20).unwrap();
    assert!(just_created > cutoff, "recent row must be held back");
    assert!(settled <= cutoff, "settled row must be eligible");
}

#[test]
fn apply_safety_lag_zero_is_noop() {
    let now = Utc.with_ymd_and_hms(2026, 7, 7, 12, 0, 30).unwrap();
    assert_eq!(apply_safety_lag(now, 0), now);
}

#[test]
fn apply_safety_lag_negative_clamps_to_zero() {
    // A negative lag must never push the cutoff into the future (which would
    // re-open the out-of-order window); it clamps to 0.
    let now = Utc.with_ymd_and_hms(2026, 7, 7, 12, 0, 30).unwrap();
    assert_eq!(apply_safety_lag(now, -10), now);
}

#[test]
fn stream_safety_lag_secs_defaults_when_env_unset() {
    // Env is process-global; only assert the default when the var is absent so
    // this stays robust under parallel test execution.
    if std::env::var("NANOSIEM_ALERT_STREAM_SAFETY_LAG_SECS").is_err() {
        assert_eq!(stream_safety_lag_secs(), DEFAULT_ALERT_STREAM_SAFETY_LAG_SECS);
    }
}

#[test]
fn map_status_counts_maps_known_and_drops_unknown() {
    let rows = vec![
        ("new".to_string(), 3i64),
        ("acknowledged".to_string(), 2),
        ("closed".to_string(), 7),
        ("bogus".to_string(), 99), // unknown status is dropped
    ];
    let mapped = map_status_counts(rows);
    assert_eq!(mapped.len(), 3, "unknown status must be dropped");
    assert!(mapped.contains(&(AlertStatus::New, 3)));
    assert!(mapped.contains(&(AlertStatus::Acknowledged, 2)));
    assert!(mapped.contains(&(AlertStatus::Closed, 7)));
}
