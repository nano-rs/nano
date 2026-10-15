// SPDX-License-Identifier: AGPL-3.0-or-later

//! `bins=N` → a round time span over the query window (NAN-3312 `bin`,
//! NAN-3385 `timechart`). Splunk's `bins` is a maximum bucket count, so the
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
pub fn round_span_for_bins(range: &TimeRange, bins: u32) -> Duration {
    let window_secs = (range.end - range.start).num_seconds().max(1) as u64;
    let minimum = window_secs.div_ceil(u64::from(bins.max(1))).max(1);
    let secs = ROUND_SPANS
        .iter()
        .copied()
        .find(|s| *s >= minimum)
        // Beyond a month per bucket, whole days are round enough.
        .unwrap_or_else(|| minimum.div_ceil(86400) * 86400);
    Duration::from_secs(secs)
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

    #[test]
    fn round_span_ladder_matches_bin_bins() {
        assert_eq!(round_span_for_bins(&hours(24), 100), Duration::from_secs(900));
        assert_eq!(round_span_for_bins(&hours(1), 100), Duration::from_secs(60));
        assert_eq!(round_span_for_bins(&hours(24 * 365), 2), Duration::from_secs(183 * 86400));
    }
}
