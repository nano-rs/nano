// SPDX-License-Identifier: AGPL-3.0-or-later
//! NAN-4288 review: the detection execution path applies a rule's in-query
//! `earliest=` / `latest=` to the scheduler's window. `parse_query` strips
//! the tokens, so before this the SearchRequest carried only the slice.
use super::window_search_request;
use crate::query::{parse_query, AggFunc, Command, Query};
use crate::search::TimeRangeInput;
use chrono::{Duration, TimeZone, Utc};

const RULE: &str = "process_name=cmd.exe earliest=-4h | stats count | where count > 100";

/// NAN-5612 review P3: a rule always names its dataset, so a leading
/// `dataset=risk` / `dataset=signals` token in its body stays a field filter
/// and can never switch the dataset (the NAN-1805 loop guards key on the
/// rule's dataset).
#[test]
fn a_rule_body_never_selects_a_dataset() {
    let now = Utc.with_ymd_and_hms(2026, 11, 3, 12, 0, 0).unwrap();
    let slice = TimeRangeInput::new(now - Duration::minutes(5), now);
    for body in ["dataset=risk | where score_24h > 1", "dataset=signals severity=high"] {
        let request = window_search_request(body, slice.clone(), None, 1000, None, now).unwrap();
        assert_eq!(request.dataset.as_deref(), Some("logs"), "{body}");
        let (_, resolved) = crate::search::query_processing::resolve_dataset_selector(
            &request.query,
            request.dataset.as_deref(),
        )
        .unwrap();
        assert_eq!(resolved.as_deref(), Some("logs"), "{body}: {}", request.query);
    }
}

#[test]
fn earliest_widens_a_five_minute_scheduler_slice() {
    let now = Utc.with_ymd_and_hms(2026, 11, 3, 12, 0, 0).unwrap();
    let slice = TimeRangeInput::new(now - Duration::minutes(5), now);
    let request = window_search_request(RULE, slice.clone(), None, 1000, None, now).unwrap();
    assert_eq!(request.time_range.start, now - Duration::hours(4));
    assert_eq!(request.time_range.end, slice.end);
    assert!(!request.query.contains("earliest"), "{}", request.query);
}

#[test]
fn a_catch_up_chunk_keeps_its_own_end() {
    let now = Utc.with_ymd_and_hms(2026, 11, 3, 12, 0, 0).unwrap();
    // A backlog chunk from three hours ago, run late.
    let chunk = TimeRangeInput::new(now - Duration::hours(3), now - Duration::hours(2));
    let request = window_search_request(RULE, chunk.clone(), None, 1000, None, now).unwrap();
    assert_eq!(request.time_range.start, now - Duration::hours(4));
    assert_eq!(request.time_range.end, chunk.end);
}

#[test]
fn rules_without_tokens_keep_the_window_and_an_empty_window_is_refused() {
    let now = Utc.with_ymd_and_hms(2026, 11, 3, 12, 0, 0).unwrap();
    let slice = TimeRangeInput::new(now - Duration::minutes(5), now);
    let request =
        window_search_request("process_name=cmd.exe | stats count", slice.clone(), None, 10, None, now).unwrap();
    assert_eq!((request.time_range.start, request.time_range.end), (slice.start, slice.end));
    // `latest=-1h` ends the window before a 5-minute slice ending now starts.
    let inverted = window_search_request("x latest=-1h", slice, None, 10, None, now);
    assert!(matches!(inverted, Err(super::DetectionError::InvalidQuery(_))), "{inverted:?}");
}

#[test]
fn detection_timechart_enrichment_preserves_split_and_canonical_bounds() {
    let now = Utc.with_ymd_and_hms(2026, 11, 3, 12, 0, 0).unwrap();
    let slice = TimeRangeInput::new(now - Duration::minutes(5), now);
    let request = window_search_request(
        "* | timechart span=5m count by src_ip",
        slice,
        None,
        1000,
        None,
        now,
    )
    .unwrap();
    let parsed = parse_query(&request.query).unwrap();
    let Query::Piped {
        command:
            Command::Timechart {
                split_by,
                aggregations,
                ..
            },
        ..
    } = parsed
    else {
        panic!("expected terminal timechart: {}", request.query);
    };
    assert_eq!(split_by, ["src_ip"]);
    assert!(aggregations.iter().any(|aggregation| {
        aggregation.func == AggFunc::Min
            && aggregation.field.as_deref() == Some("timestamp")
            && aggregation.alias.as_deref() == Some("_first_seen")
    }));
    assert!(aggregations.iter().any(|aggregation| {
        aggregation.func == AggFunc::Max
            && aggregation.field.as_deref() == Some("timestamp")
            && aggregation.alias.as_deref() == Some("_last_seen")
    }));
}
