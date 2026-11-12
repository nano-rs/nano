// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-5302: the stepped rule tester counted each event once per overlapping
//! lookback window (9 "matches" for 3 events, the same event repeated in the
//! sample). These pin distinct-event counting and the trailing window.

use chrono::{Duration, TimeZone, Utc};
use serde_json::json;

use super::analysis::{enumerate_test_windows, with_trailing_window, SteppedMatchAccumulator};
use crate::search::TimeRangeInput;

#[test]
fn overlapping_windows_count_each_event_once() {
    let t0 = Utc.with_ymd_and_hms(2026, 11, 12, 3, 0, 0).unwrap();
    let t1 = t0 + Duration::seconds(30);
    let t2 = t0 + Duration::seconds(60);
    let e = |id: &str| json!({"id": id, "process": {"name": "powershell.exe"}});

    let mut acc = SteppedMatchAccumulator::new(100);
    // Completion order is arbitrary: the latest window finishes first.
    acc.add_window(t2, vec![e("a"), e("b"), e("c")]);
    acc.add_window(t0, vec![e("a")]);
    acc.add_window(t1, vec![e("a"), e("b"), e("c")]);

    let (total, samples, buckets) = acc.finish();
    assert_eq!(total, 3, "3 distinct events, not 7 window hits");
    assert_eq!(samples.len(), 3, "sample holds no duplicates");
    let ids: Vec<&str> = samples.iter().map(|s| s["id"].as_str().unwrap()).collect();
    assert_eq!(ids[0], "a", "oldest-first by first matching tick");

    // Each event is attributed to the earliest tick that matched it.
    let counts: Vec<(chrono::DateTime<Utc>, u64)> =
        buckets.iter().map(|b| (b.bucket_start, b.count)).collect();
    assert_eq!(counts, vec![(t0, 1), (t1, 2), (t2, 0)]);
    assert_eq!(buckets.iter().map(|b| b.count).sum::<u64>(), total);
}

#[test]
fn failed_and_empty_windows_keep_zero_buckets() {
    let t0 = Utc.with_ymd_and_hms(2026, 11, 12, 3, 0, 0).unwrap();
    let mut acc = SteppedMatchAccumulator::new(100);
    acc.add_failed_window(t0);
    acc.add_window(t0 + Duration::minutes(1), vec![]);
    let (total, samples, buckets) = acc.finish();
    assert_eq!(total, 0);
    assert!(samples.is_empty());
    assert_eq!(buckets.len(), 2);
}

#[test]
fn sample_cap_is_on_distinct_events() {
    let t0 = Utc.with_ymd_and_hms(2026, 11, 12, 3, 0, 0).unwrap();
    let mut acc = SteppedMatchAccumulator::new(2);
    let rows: Vec<_> = (0..5).map(|i| json!({"id": format!("e{i}")})).collect();
    acc.add_window(t0, rows.clone());
    acc.add_window(t0 + Duration::seconds(30), rows);
    let (total, samples, _) = acc.finish();
    assert_eq!(total, 5);
    assert_eq!(samples.len(), 2);
}

#[test]
fn trailing_window_covers_events_younger_than_one_tick() {
    // Range ends 20s after the last */30s tick: an event in those 20s was
    // invisible to the tester while search found it.
    let start = Utc.with_ymd_and_hms(2026, 11, 12, 3, 0, 0).unwrap();
    let end = start + Duration::seconds(80);
    let range = TimeRangeInput::new(start, end);
    let lookback = Duration::minutes(15);
    let ticks = enumerate_test_windows(&range, "*/30 * * * * *", lookback).unwrap();
    assert_eq!(ticks.last().unwrap().end, start + Duration::seconds(60));

    let windows = with_trailing_window(ticks.clone(), &range, lookback);
    assert_eq!(windows.len(), ticks.len() + 1);
    let tail = windows.last().unwrap();
    assert_eq!(tail.end, end);
    assert_eq!(tail.end - tail.start, lookback);
}

#[test]
fn no_trailing_window_when_range_ends_on_a_tick() {
    let start = Utc.with_ymd_and_hms(2026, 11, 12, 3, 0, 0).unwrap();
    let end = start + Duration::minutes(5);
    let range = TimeRangeInput::new(start, end);
    let lookback = Duration::minutes(15);
    let ticks = enumerate_test_windows(&range, "* * * * *", lookback).unwrap();
    let windows = with_trailing_window(ticks.clone(), &range, lookback);
    assert_eq!(windows.len(), ticks.len());
}
