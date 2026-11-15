// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-5450: the hourly reminder rate limit.

use chrono::{Duration, TimeZone, Utc};

use super::repository::reminder_due;

#[test]
fn a_reminder_waits_one_interval_after_the_trigger_and_between_repeats() {
    let t0 = Utc.with_ymd_and_hms(2026, 11, 14, 0, 0, 0).unwrap();
    let hour = Duration::hours(1);
    // The trigger itself notified: nothing repeats in the first hour.
    assert!(!reminder_due(t0, None, t0 + Duration::minutes(5), hour));
    assert!(!reminder_due(t0, None, t0 + Duration::minutes(59), hour));
    assert!(reminder_due(t0, None, t0 + hour, hour));
    // After a reminder at 01:00, the next is due at 02:00, not on every
    // five-minute health cycle in between.
    let r = t0 + hour;
    for m in [5, 30, 59] {
        assert!(!reminder_due(t0, Some(r), r + Duration::minutes(m), hour), "{m}");
    }
    assert!(reminder_due(t0, Some(r), r + hour, hour));
}

#[test]
fn the_repository_claims_the_slot_with_the_same_predicate() {
    let src = include_str!("repository.rs");
    assert!(src.contains("AND first_seen_at <= NOW() - make_interval(secs => $3)"));
    assert!(src.contains("AND (last_reminded_at IS NULL OR last_reminded_at <= NOW() - make_interval(secs => $3))"));
    // Only finished reminder rows are recycled; one in flight blocks a second.
    assert!(src.contains("AND event_action = 'reminder' AND status IN ('delivered', 'dead')"));
}
