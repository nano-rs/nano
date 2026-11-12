// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-5296: ingest-stall alert thresholds.

use super::*;
use chrono::TimeZone;

fn at(seconds: i64) -> DateTime<Utc> {
    Utc.timestamp_opt(1_800_000_000 + seconds, 0).unwrap()
}

fn saturated() -> IngestStallProbe {
    IngestStallProbe {
        ingest_slots_full_with_queue: true,
        ..Default::default()
    }
}

#[test]
fn flush_running_longer_than_five_minutes_fires_immediately() {
    let mut tracker = StallTracker::default();
    let healthy = IngestStallProbe {
        longest_async_flush_seconds: STUCK_FLUSH_ALERT_SECS,
        ..Default::default()
    };
    assert_eq!(tracker.observe(&healthy, at(0)), StallAlert::Calm);

    let stuck = IngestStallProbe {
        longest_async_flush_seconds: STUCK_FLUSH_ALERT_SECS + 1,
        stuck_async_flushes: 2,
        ..Default::default()
    };
    match tracker.observe(&stuck, at(30)) {
        StallAlert::Firing(reasons) => {
            assert_eq!(reasons.len(), 1);
            assert!(reasons[0].contains("AsyncInsertFlush running for 301s"), "{reasons:?}");
        }
        other => panic!("expected a firing alert, got {other:?}"),
    }
    assert_eq!(tracker.observe(&healthy, at(60)), StallAlert::Cleared);
    assert_eq!(tracker.observe(&healthy, at(90)), StallAlert::Calm);
}

#[test]
fn saturated_ingest_slots_fire_only_after_a_minute() {
    let mut tracker = StallTracker::default();
    assert_eq!(tracker.observe(&saturated(), at(0)), StallAlert::Calm);
    assert_eq!(tracker.observe(&saturated(), at(30)), StallAlert::Calm);
    match tracker.observe(&saturated(), at(60)) {
        StallAlert::Firing(reasons) => {
            assert!(reasons[0].contains("slots full with waiters for 60s"), "{reasons:?}");
        }
        other => panic!("expected a firing alert, got {other:?}"),
    }
}

#[test]
fn a_gap_in_saturation_restarts_the_clock() {
    let mut tracker = StallTracker::default();
    assert_eq!(tracker.observe(&saturated(), at(0)), StallAlert::Calm);
    assert_eq!(tracker.observe(&IngestStallProbe::default(), at(30)), StallAlert::Calm);
    assert_eq!(tracker.observe(&saturated(), at(60)), StallAlert::Calm);
    assert_eq!(tracker.observe(&saturated(), at(90)), StallAlert::Calm);
    assert!(matches!(tracker.observe(&saturated(), at(120)), StallAlert::Firing(_)));
}

#[test]
fn merge_keeps_the_worst_replica() {
    let a = IngestStallProbe {
        longest_async_flush_seconds: 400,
        stuck_async_flushes: 1,
        ingest_slots_full_with_queue: false,
    };
    let b = IngestStallProbe {
        longest_async_flush_seconds: 10,
        stuck_async_flushes: 0,
        ingest_slots_full_with_queue: true,
    };
    assert_eq!(
        a.merge(b),
        IngestStallProbe {
            longest_async_flush_seconds: 400,
            stuck_async_flushes: 1,
            ingest_slots_full_with_queue: true,
        }
    );
}

#[test]
fn probe_sql_reads_only_system_tables_and_has_no_bind_placeholders() {
    let sql = stall_probe_sql();
    assert!(!sql.contains('?'), "clickhouse-rs treats `?` as a bind placeholder: {sql}");
    assert!(!sql.to_uppercase().contains("INSERT INTO"));
    assert!(sql.contains("elapsed > 300"));
}
