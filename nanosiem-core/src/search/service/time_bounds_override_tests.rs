// SPDX-License-Identifier: AGPL-3.0-or-later
//! NAN-4288: in-query `earliest=` overrides only the start and `latest=` only
//! the end of the requested window; a range they leave empty is a named 400
//! instead of an inverted window that silently matches nothing.
use super::{apply_time_bounds, extract_time_bounds_at, TimeRangeInput};
use crate::search::SearchError;
use chrono::TimeZone;

fn picker() -> TimeRangeInput {
    TimeRangeInput::new(
        chrono::Utc.with_ymd_and_hms(2026, 10, 19, 0, 0, 0).unwrap(),
        chrono::Utc.with_ymd_and_hms(2026, 10, 19, 1, 0, 0).unwrap(),
    )
}

#[test]
fn query_time_bounds_override_one_side_or_fail_clearly() {
    let now = chrono::Utc.with_ymd_and_hms(2026, 10, 20, 22, 0, 0).unwrap();
    let picker = picker();
    // A past picker window plus `earliest=-1h` starts after the picker's end.
    for token in ["earliest=-1h", "earliest=-1d"] {
        let query = format!("source_type=apache_access {token} | stats count");
        let (_, earliest, latest) = extract_time_bounds_at(&query, now).unwrap();
        let error = apply_time_bounds(&picker, earliest, latest).unwrap_err();
        assert!(
            matches!(&error, SearchError::SqlValidationError(m) if m.contains("earliest=/latest=")),
            "{token}: {error}"
        );
    }
    let (_, earliest, latest) = extract_time_bounds_at("x earliest=-3d", now).unwrap();
    let range = apply_time_bounds(&picker, earliest, latest).unwrap();
    assert_eq!((range.start, range.end), (now - chrono::Duration::days(3), picker.end));
    let (_, earliest, latest) = extract_time_bounds_at("x latest=-1d", now).unwrap();
    let range = apply_time_bounds(&picker, earliest, latest).unwrap();
    assert_eq!((range.start, range.end), (picker.start, now - chrono::Duration::days(1)));
    let range = apply_time_bounds(&picker, None, None).unwrap();
    assert_eq!((range.start, range.end), (picker.start, picker.end));
    let (_, earliest, latest) = extract_time_bounds_at("x earliest=-1h latest=-2h", now).unwrap();
    assert!(apply_time_bounds(&picker, earliest, latest).is_err());
}

/// Detection windows stay contiguous: a late (catch-up) run keeps its own
/// window end, with or without an `earliest=` token in the rule.
#[test]
fn detection_catch_up_windows_keep_their_end() {
    let now = chrono::Utc.with_ymd_and_hms(2026, 10, 20, 22, 0, 0).unwrap();
    let base = now - chrono::Duration::hours(3);
    let windows: Vec<TimeRangeInput> = (0..3)
        .map(|i| TimeRangeInput::new(base + chrono::Duration::hours(i), base + chrono::Duration::hours(i + 1)))
        .collect();
    for rule in ["process_name=cmd.exe", "process_name=cmd.exe earliest=-4h"] {
        let (_, earliest, latest) = extract_time_bounds_at(rule, now).unwrap();
        for window in &windows {
            let range = apply_time_bounds(window, earliest, latest).unwrap();
            assert_eq!(range.end, window.end, "{rule}");
            if earliest.is_none() {
                assert_eq!(range.start, window.start, "{rule}");
            }
        }
    }
}
