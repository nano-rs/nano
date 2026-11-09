// SPDX-License-Identifier: AGPL-3.0-or-later
//! Streaming time-range bounds (security review 2026-11-08, NAN-5026).

use super::*;
use crate::search::{SearchError, TimeRangeInput};
use chrono::{Duration, TimeZone};

fn utc(y: i32, m: u32, d: u32) -> DateTime<Utc> {
    Utc.with_ymd_and_hms(y, m, d, 0, 0, 0).unwrap()
}

/// The chunks are contiguous, newest-first, and tile `[start, end]` exactly.
fn assert_tiles(chunks: &[(DateTime<Utc>, DateTime<Utc>)], start: DateTime<Utc>, end: DateTime<Utc>) {
    assert_eq!(chunks.first().unwrap().1, end);
    assert_eq!(chunks.last().unwrap().0, start);
    for pair in chunks.windows(2) {
        assert_eq!(pair[0].0, pair[1].1, "chunks must be contiguous");
        assert!(pair[1].0 < pair[1].1);
    }
}

/// Exploit regression: a 400-year in-range span used to produce ~146k chunks
/// (one sequential ClickHouse query each).
#[test]
fn chunk_count_is_capped_and_still_covers_the_range() {
    let (start, end) = (utc(1900, 1, 1), utc(2299, 6, 1));
    let chunks = compute_daily_chunks(start, end);
    assert_eq!(chunks.len(), MAX_DAILY_CHUNKS);
    assert_tiles(&chunks, start, end);
    // All but the last are single days.
    for (s, e) in &chunks[..chunks.len() - 1] {
        assert!(*e - *s <= Duration::days(1));
    }
}

/// Legitimate path: the UI's "All time" (2020 onward) keeps one chunk per day
/// for the most recent 399 days and folds the rest into one tail chunk.
#[test]
fn all_time_window_keeps_daily_chunks_for_recent_data() {
    let (start, end) = (utc(2020, 1, 1), utc(2026, 11, 8) + Duration::hours(15));
    let chunks = compute_daily_chunks(start, end);
    assert_eq!(chunks.len(), MAX_DAILY_CHUNKS);
    assert_tiles(&chunks, start, end);
}

/// A window within the cap is unchanged: one chunk per calendar day.
#[test]
fn short_windows_are_unchanged() {
    let (start, end) = (utc(2026, 1, 1) + Duration::hours(6), utc(2026, 1, 31));
    let chunks = compute_daily_chunks(start, end);
    assert_eq!(chunks.len(), 30);
    assert_tiles(&chunks, start, end);
}

/// Exploit regression: years far outside ClickHouse's DateTime64 range are a
/// clean 400 before any work is sized from them.
#[test]
fn out_of_range_years_are_rejected() {
    let far = Utc.with_ymd_and_hms(200_000, 1, 1, 0, 0, 0).unwrap();
    let range = TimeRangeInput::new(utc(2026, 1, 1), far);
    assert!(matches!(range.validate(), Err(SearchError::SqlValidationError(m)) if m.contains("outside the searchable range")));
    let ancient = Utc.with_ymd_and_hms(-200_000, 1, 1, 0, 0, 0).unwrap();
    assert!(TimeRangeInput::new(ancient, utc(2026, 1, 1)).validate().is_err());
    assert!(TimeRangeInput::new(utc(1899, 12, 31), utc(2026, 1, 1)).validate().is_err());
}

#[test]
fn storable_windows_validate() {
    assert!(TimeRangeInput::new(utc(1900, 1, 1), utc(2299, 12, 31)).validate().is_ok());
    assert!(TimeRangeInput::new(utc(1970, 1, 1), Utc::now()).validate().is_ok());
    assert!(matches!(
        TimeRangeInput::new(utc(2026, 1, 2), utc(2026, 1, 1)).validate(),
        Err(SearchError::InvalidTimeRange)
    ));
}

/// `earliest=` tokens resolve to checked but unbounded instants; the adjusted
/// window is validated too.
#[test]
fn earliest_token_outside_range_is_rejected() {
    let base = TimeRangeInput::new(utc(2026, 1, 1), utc(2026, 1, 2));
    let now = utc(2026, 1, 2);
    let err = crate::search::service::apply_query_time_bounds_at(
        "earliest=-100000y error",
        &base,
        now,
    )
    .unwrap_err();
    assert!(matches!(err, SearchError::SqlValidationError(ref m) if m.contains("outside")), "{err}");
    // Legitimate relative window still works.
    assert!(crate::search::service::apply_query_time_bounds_at("earliest=-7d error", &base, now).is_ok());
}
