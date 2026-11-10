// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-5144: the histogram bucket count is bounded for any window, the SQL
//! bucketing and the gap-fill use the same interval, and normal windows
//! keep their intervals.

use chrono::{TimeZone, Utc};

use super::histogram::{
    capped_histogram_interval, npl_histogram_bucket, raw_histogram_bucket, MAX_HISTOGRAM_BUCKETS,
};
use super::SearchService;
use super::TimeRange;
use super::HistogramBucket;

const HOUR: i64 = 3_600;
const DAY: i64 = 86_400;

fn window(start: chrono::DateTime<Utc>, end: chrono::DateTime<Utc>) -> TimeRange {
    TimeRange { start, end }
}

#[test]
fn normal_windows_keep_their_intervals() {
    // nPL path.
    let npl = |d: i64| npl_histogram_bucket(d, "timestamp");
    assert_eq!(npl(HOUR), ("toStartOfMinute(timestamp)".to_string(), 60));
    assert_eq!(npl(DAY), ("toStartOfFiveMinutes(timestamp)".to_string(), 300));
    assert_eq!(npl(7 * DAY), ("toStartOfInterval(timestamp, INTERVAL 30 MINUTE)".to_string(), 1800));
    assert_eq!(npl(30 * DAY), ("toStartOfHour(timestamp)".to_string(), 3600));
    assert_eq!(npl(90 * DAY).1, 3600);
    // Raw-SQL / field-stats path.
    assert_eq!(raw_histogram_bucket(HOUR), ("toStartOfMinute(timestamp)".to_string(), 60));
    assert_eq!(raw_histogram_bucket(DAY), ("toStartOfFifteenMinutes(timestamp)".to_string(), 900));
    assert_eq!(raw_histogram_bucket(7 * DAY), ("toStartOfHour(timestamp)".to_string(), 3600));
    assert_eq!(raw_histogram_bucket(30 * DAY), ("toStartOfDay(timestamp)".to_string(), 86400));
    // The dataset's own time column is threaded through unchanged.
    assert_eq!(npl_histogram_bucket(DAY, "start_time").0, "toStartOfFiveMinutes(start_time)");
}

#[test]
fn long_windows_coarsen_under_the_cap() {
    let max = MAX_HISTOGRAM_BUCKETS as i64;
    for duration in [365 * DAY, 2 * 365 * DAY, 30 * 365 * DAY, 400 * 365 * DAY, i64::MAX / 2] {
        for base in [3600, 86400] {
            let interval = capped_histogram_interval(duration, base);
            assert!(interval >= base);
            assert!(duration / interval < max, "{duration}s / {interval}s");
        }
    }
    // A year of hourly buckets would be 8760: still under the cap, kept.
    assert_eq!(capped_histogram_interval(365 * DAY, 3600), 3600);
    // Two years step up to 6-hour buckets.
    assert_eq!(capped_histogram_interval(2 * 365 * DAY, 3600), 21_600);
    let (sql, interval) = npl_histogram_bucket(2 * 365 * DAY, "timestamp");
    assert_eq!(sql, "toDateTime(intDiv(toUnixTimestamp(timestamp), 21600) * 21600, 'UTC')");
    assert_eq!(interval, 21_600);
}

#[test]
fn multi_century_window_has_a_bounded_bucket_count() {
    let start = Utc.with_ymd_and_hms(1900, 1, 1, 0, 0, 0).unwrap();
    let end = Utc.with_ymd_and_hms(2299, 12, 31, 23, 59, 59).unwrap();
    let duration = (end - start).num_seconds();
    for (_, interval) in [npl_histogram_bucket(duration, "timestamp"), raw_histogram_bucket(duration)] {
        let filled = SearchService::fill_histogram_gaps(Vec::new(), &window(start, end), interval);
        assert!(!filled.is_empty());
        assert!(filled.len() <= MAX_HISTOGRAM_BUCKETS, "{} buckets", filled.len());
        assert!(filled.first().unwrap().time <= start);
        // Covers the whole window: the last bucket's span reaches the end.
        assert!(filled.last().unwrap().time + chrono::Duration::seconds(interval) >= end);
    }
}

#[test]
fn gap_fill_has_a_hard_cap_for_any_interval() {
    // Backstop: even a too-fine interval cannot make the fill unbounded.
    let start = Utc.with_ymd_and_hms(1900, 1, 1, 0, 0, 0).unwrap();
    let end = Utc.with_ymd_and_hms(2299, 1, 1, 0, 0, 0).unwrap();
    let filled = SearchService::fill_histogram_gaps(Vec::new(), &window(start, end), 5);
    assert_eq!(filled.len(), MAX_HISTOGRAM_BUCKETS);
    assert!(SearchService::fill_histogram_gaps(Vec::new(), &window(start, end), 0).is_empty());
}

#[test]
fn coarse_sql_buckets_line_up_with_the_gap_fill() {
    // A bucket key the coarse SQL produces (epoch floor) is found by the fill.
    let start = Utc.with_ymd_and_hms(2024, 3, 5, 7, 13, 0).unwrap();
    let end = start + chrono::Duration::days(3 * 365);
    let (_, interval) = npl_histogram_bucket((end - start).num_seconds(), "timestamp");
    assert!(interval > HOUR);
    let event = Utc.with_ymd_and_hms(2025, 6, 1, 12, 34, 56).unwrap();
    let key = event.timestamp().div_euclid(interval) * interval;
    let bucket = HistogramBucket { time: chrono::DateTime::from_timestamp(key, 0).unwrap(), count: 42 };
    let filled = SearchService::fill_histogram_gaps(vec![bucket], &window(start, end), interval);
    assert_eq!(filled.iter().map(|b| b.count).sum::<u64>(), 42);
    assert!(filled.len() <= MAX_HISTOGRAM_BUCKETS);
}

#[test]
fn normal_window_fill_is_unchanged() {
    let start = Utc.with_ymd_and_hms(2026, 11, 1, 0, 0, 0).unwrap();
    let end = start + chrono::Duration::days(1);
    let (_, interval) = npl_histogram_bucket(DAY, "timestamp");
    let filled = SearchService::fill_histogram_gaps(Vec::new(), &window(start, end), interval);
    assert_eq!(filled.len(), 288);
}
