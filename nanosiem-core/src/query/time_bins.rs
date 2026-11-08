// SPDX-License-Identifier: AGPL-3.0-or-later

//! `bins=N` → a round time span over the query window (NAN-3385
//! `timechart`). `bins` is a maximum bucket count, so the
//! span is the smallest round span that splits the window into at most N.

use std::time::Duration;

use super::{Command, Query, TimeRange};

const ROUND_SPANS: [u64; 22] = [
    1, 2, 5, 10, 15, 30, // seconds
    60, 120, 300, 600, 900, 1800, // minutes
    3600, 7200, 10800, 21600, 43200, // hours
    86400, 172800, 604800, 1209600, 2592000, // days, weeks, ~month
];

/// The smallest round span that splits `range` into at most `bins` buckets.
/// `bins` must be greater than 0 (the parsers reject 0).
///
/// The count is taken over the buckets the generated SQL actually produces
/// (see [`bucket_count`]), not `window / span`: buckets are aligned to the
/// clock, not to the search start, so an unaligned window (12:00:30 → next
/// day 12:00:30) touches one more bucket than `window / span` suggests. The
/// ladder is stepped until the aligned count fits.
pub fn round_span_for_bins(range: &TimeRange, bins: u32) -> Duration {
    let bins = u64::from(bins.max(1));
    let window_secs = (range.end - range.start).num_seconds().max(1) as u64;
    let minimum = window_secs.div_ceil(bins).max(1);
    // Beyond a month per bucket, whole days are round enough.
    let fallback = minimum.div_ceil(86400) * 86400;
    let secs = ROUND_SPANS
        .iter()
        .copied()
        .filter(|s| *s >= minimum)
        .chain(std::iter::once(fallback.max(minimum)))
        .find(|s| bucket_count(range, *s) <= bins)
        .unwrap_or(fallback);
    Duration::from_secs(secs)
}

/// How many distinct `timechart` buckets of `span_secs` the half-open window
/// `[start, end)` touches, mirroring `generate_time_bucket` and ClickHouse's
/// alignment of each bucket function:
/// - spans that divide a day (every sub-day ladder rung) align to the clock,
///   which for those spans is the same as aligning to the epoch;
/// - `toStartOfDay` and the multi-day `INTERVAL n HOUR` forms (ClickHouse
///   aligns hour intervals to the start of the day) are DAY buckets;
/// - `toStartOfWeek` is Sunday-aligned weeks;
/// - month-or-longer spans are `toStartOfMonth`, i.e. calendar months.
fn bucket_count(range: &TimeRange, span_secs: u64) -> u64 {
    use chrono::Datelike;
    // DateTime64(3): the last selectable instant is one millisecond before end.
    let first = range.start;
    let last = (range.end - chrono::Duration::milliseconds(1)).max(first);
    let span = span_secs.max(1) as i64;
    if span >= 2_592_000 {
        let month = |t: chrono::DateTime<chrono::Utc>| i64::from(t.year()) * 12 + i64::from(t.month0());
        return (month(last) - month(first) + 1) as u64;
    }
    let day = |t: chrono::DateTime<chrono::Utc>| t.timestamp().div_euclid(86_400);
    if span == 604_800 {
        // 1970-01-01 was a Thursday; Sunday-aligned week index.
        let week = |t| (day(t) + 4).div_euclid(7);
        return (week(last) - week(first) + 1) as u64;
    }
    if span >= 86_400 {
        return (day(last) - day(first) + 1) as u64;
    }
    let idx = |t: chrono::DateTime<chrono::Utc>| t.timestamp().div_euclid(span);
    (idx(last) - idx(first) + 1) as u64
}

/// Replace every top-level `timechart bins=N` span with the span `range`
/// gives it and clear `bins`, so every later reader (rollup routing, lake
/// count plans, the presentation wrapper, re-printing for the lake cell) sees
/// the real bucket width. Returns whether anything changed.
pub fn resolve_timechart_bins(query: &mut Query, range: &TimeRange) -> bool {
    let mut changed = false;
    let mut node = query;
    while let Query::Piped { source, command } = node {
        if let Command::Timechart { span, bins, .. } = command {
            if let Some(n) = bins.take() {
                *span = round_span_for_bins(range, n);
                changed = true;
            }
        }
        node = source.as_mut();
    }
    changed
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::query::{parse_query, PrettyPrint};

    fn hours(h: i64) -> TimeRange {
        let end: chrono::DateTime<chrono::Utc> = "2026-10-08T12:00:00Z".parse().unwrap();
        TimeRange {
            start: end - chrono::Duration::hours(h),
            end,
        }
    }

    fn timechart(query: &Query) -> (Duration, Option<u32>) {
        match query {
            Query::Piped {
                command: Command::Timechart { span, bins, .. },
                ..
            } => (*span, *bins),
            other => panic!("expected a timechart, got {other:?}"),
        }
    }

    #[test]
    fn timechart_bins_parses_and_resolves_to_a_round_span_nan3385() {
        let mut query = parse_query("metadata.log_source=windows_event | timechart bins=10 count").unwrap();
        assert_eq!(timechart(&query).1, Some(10));
        // Re-printing keeps bins= until it is resolved (hosted re-print).
        assert!(query.pretty_print().contains("timechart bins=10 count"), "{}", query.pretty_print());

        assert!(resolve_timechart_bins(&mut query, &hours(3)));
        // 3 h / 10 = 18 min → the next round span, 30 min (6 buckets ≤ 10).
        assert_eq!(timechart(&query), (Duration::from_secs(1800), None));
        assert!(query.pretty_print().contains("timechart span=30m count"), "{}", query.pretty_print());
        assert!(!resolve_timechart_bins(&mut query, &hours(3)));
    }

    #[test]
    fn timechart_bins_options_in_any_order_and_span_wins_nan3385() {
        for q in [
            "* | timechart limit=5 bins=24 count by user",
            "* | timechart bins=24 limit=5 count by user",
            "* | timechart cont=true bins=24 count",
        ] {
            let query = parse_query(q).unwrap_or_else(|e| panic!("{q}: {e}"));
            assert_eq!(timechart(&query).1, Some(24), "{q}");
        }
        let query = parse_query("* | timechart span=5m bins=24 count").unwrap();
        assert_eq!(timechart(&query), (Duration::from_secs(300), None));
        let query = parse_query("* | timechart bins=24 span=5m count").unwrap();
        assert_eq!(timechart(&query), (Duration::from_secs(300), None));
        assert!(parse_query("* | timechart bins=0 count").is_err());
    }

    /// Codex P2: an unaligned 24 h window touches 97 fifteen-minute buckets
    /// (12:00 through the next day's 12:00), so bins=96 must step to 30 min.
    #[test]
    fn unaligned_window_never_exceeds_bins() {
        let start: chrono::DateTime<chrono::Utc> = "2026-10-08T12:00:30Z".parse().unwrap();
        let range = TimeRange { start, end: start + chrono::Duration::hours(24) };
        assert_eq!(bucket_count(&range, 900), 97);
        let span = round_span_for_bins(&range, 96);
        assert_eq!(span, Duration::from_secs(1800));
        assert!(bucket_count(&range, span.as_secs()) <= 96);
        // Aligned 24 h still fits 96 x 15 min exactly.
        assert_eq!(round_span_for_bins(&hours(24), 96), Duration::from_secs(900));
        // Every N over a sweep of unaligned windows stays within N buckets.
        for n in 1..=200u32 {
            let span = round_span_for_bins(&range, n).as_secs();
            if span < 2_592_000 {
                assert!(bucket_count(&range, span) <= u64::from(n), "bins={n} span={span}");
            }
        }
    }

    #[test]
    fn multi_day_hour_intervals_count_as_day_buckets() {
        // INTERVAL 48 HOUR aligns to the day in ClickHouse, so 2 d is 1-day
        // buckets; a 10-day window (noon to noon: 11 days touched) with
        // bins=5 must not pick it.
        let range = hours(240);
        assert_eq!(bucket_count(&range, 172_800), 11);
        assert!(bucket_count(&range, round_span_for_bins(&range, 5).as_secs()) <= 5);
    }

    #[test]
    fn round_span_ladder_matches_bin_bins() {
        assert_eq!(round_span_for_bins(&hours(24), 100), Duration::from_secs(900));
        assert_eq!(round_span_for_bins(&hours(1), 100), Duration::from_secs(60));
        assert_eq!(round_span_for_bins(&hours(24 * 365), 2), Duration::from_secs(183 * 86400));
    }
}
