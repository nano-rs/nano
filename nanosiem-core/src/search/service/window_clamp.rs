// SPDX-License-Identifier: AGPL-3.0-or-later

//! End-anchored window clamping for range-capped search commands (NAN-2022).
//!
//! Three view-builder commands run heavy per-window aggregation and cap the
//! analyst's search range: `asset` (6h), `cloud` (6h), and `baseline` (7d
//! current window). Historically an over-wide window was hard-rejected with a
//! 400 — hostile in the middle of a hunt. Instead, clamp the range to the cap
//! keeping the **most recent** slice (`[end - cap, end]`) and surface a
//! non-blocking warning naming the window actually analyzed.
//!
//! End-anchored because the newest activity is almost always what an analyst
//! wants in frame; the warning echoes the exact clamped window so an
//! unexpectedly-sparse view is never mysterious. The clamp is applied both on
//! the primary `/api/search` path (with the warning) and on the asset/cloud
//! timeline pagination endpoints (silently), so "load more" stays consistent
//! with the clamped primary view.

use chrono::Duration;

use crate::query::TimeRange;
use crate::search::types::QueryWarningOutput;

/// Clamp `range` to at most `cap`, keeping the most recent slice
/// (`[end - cap, end]`). Returns the range unchanged when it is already within
/// `cap` (never widens a range).
pub(crate) fn end_anchored_clamp(range: &TimeRange, cap: Duration) -> TimeRange {
    if range.end - range.start <= cap {
        return range.clone();
    }
    TimeRange::new(range.end - cap, range.end)
}

/// Clamp `range` to `cap` (end-anchored) and, when clamping actually happened,
/// build the analyst-facing warning that names the command, the cap, and the
/// exact window that will be analyzed.
///
/// `label` is the command name shown to the analyst (e.g. `"asset"`);
/// `cap_human` is the human cap string (e.g. `"6h"`, `"7d"`). Returns `None`
/// for the warning when the range was already within the cap.
pub(crate) fn clamp_with_warning(
    range: &TimeRange,
    cap: Duration,
    label: &str,
    cap_human: &str,
) -> (TimeRange, Option<QueryWarningOutput>) {
    let clamped = end_anchored_clamp(range, cap);
    // Byte-identical range => nothing was clamped, so emit no warning.
    if clamped.start == range.start && clamped.end == range.end {
        return (clamped, None);
    }
    let warning = QueryWarningOutput {
        severity: "warning".to_string(),
        code: format!("{}_WINDOW_CLAMPED", label.to_ascii_uppercase()),
        message: format!(
            "{label} view is capped at {cap_human}; analyzing the most recent {cap_human} \
             ({} to {} UTC) instead of the full range you requested.",
            clamped.start.format("%Y-%m-%d %H:%M"),
            clamped.end.format("%Y-%m-%d %H:%M"),
        ),
        suggestion: Some(format!(
            "Narrow your search time range to {cap_human} or less to control exactly which \
             window {label} analyzes."
        )),
        impact: Some(
            "Activity before the most recent window is not included in this view.".to_string(),
        ),
    };
    (clamped, Some(warning))
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{TimeZone, Utc};

    fn range(start_h: i64, end_h: i64) -> TimeRange {
        // Anchor at a fixed epoch (no Utc::now — deterministic).
        let base = Utc.with_ymd_and_hms(2026, 3, 29, 0, 0, 0).unwrap();
        TimeRange::new(
            base + Duration::hours(start_h),
            base + Duration::hours(end_h),
        )
    }

    #[test]
    fn within_cap_is_untouched_and_warns_nothing() {
        let r = range(0, 6); // exactly 6h
        let (clamped, warn) = clamp_with_warning(&r, Duration::hours(6), "asset", "6h");
        assert_eq!(clamped.start, r.start);
        assert_eq!(clamped.end, r.end);
        assert!(warn.is_none());
    }

    #[test]
    fn under_cap_is_untouched() {
        let r = range(0, 2); // 2h, under the 6h cap
        let (clamped, warn) = clamp_with_warning(&r, Duration::hours(6), "asset", "6h");
        assert_eq!(clamped.start, r.start);
        assert_eq!(clamped.end, r.end);
        assert!(warn.is_none());
    }

    #[test]
    fn over_cap_keeps_most_recent_slice_end_anchored() {
        let r = range(0, 24); // 24h
        let (clamped, warn) = clamp_with_warning(&r, Duration::hours(6), "asset", "6h");
        // End is preserved; start moves forward to end - 6h.
        assert_eq!(clamped.end, r.end);
        assert_eq!(clamped.end - clamped.start, Duration::hours(6));
        assert_eq!(clamped.start, r.end - Duration::hours(6));
        let w = warn.expect("clamp must warn");
        assert_eq!(w.severity, "warning");
        assert_eq!(w.code, "ASSET_WINDOW_CLAMPED");
        assert!(w.message.contains("6h"));
        assert!(w.suggestion.is_some());
    }

    #[test]
    fn baseline_day_cap_clamps_and_labels() {
        let r = range(0, 24 * 30); // 30 days
        let (clamped, warn) = clamp_with_warning(&r, Duration::days(7), "baseline", "7d");
        assert_eq!(clamped.end, r.end);
        assert_eq!(clamped.end - clamped.start, Duration::days(7));
        let w = warn.expect("clamp must warn");
        assert_eq!(w.code, "BASELINE_WINDOW_CLAMPED");
        assert!(w.message.contains("7d"));
    }

    #[test]
    fn end_anchored_clamp_never_widens() {
        let r = range(0, 3); // 3h, cap 6h
        let clamped = end_anchored_clamp(&r, Duration::hours(6));
        assert_eq!(clamped.start, r.start);
        assert_eq!(clamped.end, r.end);
    }
}
