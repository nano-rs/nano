// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-3277: a lean `| baseline` never claims "no history" for an entity
//! whose history was not read. `no_history` requires the activity read AND
//! a raw presence read of the same entity fields to complete and find
//! nothing; a deadline, refusal or read error anywhere makes the answer
//! incomplete with coverage `unknown` (and escalates to the durable job).

use super::*;
use chrono::{Duration, TimeZone, Utc};
use serde_json::json;
use std::sync::{Arc, Mutex};

type Reads = Arc<Mutex<Vec<(String, TimeRange, &'static str)>>>;

/// The live shape: `device.hostname="ws-it-083" | baseline window=7d` over
/// the last hour.
fn plan() -> LakeBaselinePlan {
    let end = Utc.with_ymd_and_hms(2026, 10, 8, 14, 0, 0).unwrap();
    LakeBaselinePlan::new(
        &BaselineCommandInfo {
            entity_type: None,
            entity_value: None,
            window: std::time::Duration::from_secs(7 * 86_400),
            dims: None,
        },
        ("host".to_string(), "ws-it-083".to_string()),
        &TimeRange::new(end - Duration::hours(1), end),
        false,
    )
    .unwrap()
}

fn hourly(range: &TimeRange) -> Vec<serde_json::Value> {
    let mut rows = Vec::new();
    let mut hour = range.start;
    while hour < range.end {
        rows.push(json!({"time_bucket": hour.to_rfc3339(), "count": 50}));
        hour += Duration::hours(1);
    }
    rows
}

/// The one summary row of an answer that has no value rows.
fn summary(outcome: &LakeBaselineOutcome) -> &serde_json::Value {
    assert_eq!(outcome.rows.len(), 1, "{:?}", outcome.rows);
    &outcome.rows[0]
}

fn assert_unknown(outcome: &LakeBaselineOutcome, reason: &str) {
    assert!(!outcome.complete, "{:?}", outcome.rows);
    for row in &outcome.rows {
        assert_ne!(row["coverage"], "no_history", "{row}");
    }
    let marker = summary(outcome);
    assert_eq!(marker["coverage"], "unknown", "{marker}");
    assert_eq!(marker["incomplete"], true, "{marker}");
    assert_eq!(
        marker["unread_dimensions"],
        json!(["users", "processes", "destination IPs"]),
        "{marker}"
    );
    assert!(
        marker["reason"].as_str().unwrap().contains(reason),
        "{marker}"
    );
}

/// The live case: the activity read answers zero buckets at once, the
/// window reads run into the 40 s deadline. Was `no_history`,
/// `complete=true`; now unknown + incomplete, so the interactive lane
/// escalates it to the durable job.
#[tokio::test(start_paused = true)]
async fn zero_activity_with_a_window_deadline_is_incomplete_not_no_history() {
    let reads: Reads = Arc::default();
    let outcome = run_lake_baseline(
        &plan(),
        |query: String, range: TimeRange, view: &'static str, _limit| {
            let reads = reads.clone();
            async move {
                reads.lock().unwrap().push((query, range, view));
                if view == "baseline-window" {
                    tokio::time::sleep(std::time::Duration::from_secs(120)).await;
                }
                Ok(Vec::new())
            }
        },
        Some(tokio::time::Instant::now() + std::time::Duration::from_secs(40)),
    )
    .await
    .expect("a deadline never fails the baseline");
    assert_unknown(&outcome, "interactive wall budget");
}

/// Same, with the window reads cut by the deadline after the presence read
/// already confirmed the host is silent: still incomplete, never claimed.
#[tokio::test(start_paused = true)]
async fn a_deadline_in_any_phase_is_incomplete_even_for_a_silent_entity() {
    let outcome = run_lake_baseline(
        &plan(),
        |_query: String, _range: TimeRange, view: &'static str, _limit| async move {
            if view == "baseline-window" {
                tokio::time::sleep(std::time::Duration::from_secs(10)).await;
            }
            Ok(Vec::new())
        },
        // The window reads outlive the deadline; activity and the presence
        // probe answer at once (queued behind them for the in-flight bound).
        Some(tokio::time::Instant::now() + std::time::Duration::from_secs(5)),
    )
    .await
    .unwrap();
    assert_unknown(&outcome, "interactive wall budget");
}

#[tokio::test]
async fn an_activity_read_error_is_unknown_not_no_history() {
    let outcome = run_lake_baseline(
        &plan(),
        |_query: String, _range: TimeRange, view: &'static str, _limit| async move {
            if view == "baseline-activity" {
                return Err(SearchError::ServiceUnavailable(
                    "lane_wait_timeout: the read-write lane stayed busy".to_string(),
                ));
            }
            Ok(Vec::new())
        },
        None,
    )
    .await
    .expect("a read error degrades, it never claims an answer");
    assert_unknown(&outcome, "lane_wait_timeout");
}

#[tokio::test]
async fn an_activity_read_refused_at_the_minimum_span_is_unknown() {
    // A refusal the reader cannot split further: the activity read reports
    // its span unread.
    let outcome = run_lake_baseline(
        &plan(),
        |_query: String, range: TimeRange, view: &'static str, _limit| async move {
            if view == "baseline-activity" {
                let _ = range;
                return Err(SearchError::ColdScanTooLarge { needed_bytes: 1 << 40, ceiling_bytes: 1 << 31, background_ceiling_bytes: None });
            }
            Ok(Vec::new())
        },
        None,
    )
    .await
    .unwrap();
    assert_unknown(&outcome, "refused for its size");
}

/// Root cause (3): the activity read answered zero buckets for a host that
/// has lookback events (the rollup did not carry its dotless name). The
/// raw presence read finds an event, so the dimensions are evaluated and
/// coverage is reported unknown — never "no history".
#[tokio::test]
async fn zero_activity_for_an_entity_with_lookback_events_still_evaluates_dimensions() {
    let plan = plan();
    let spans = plan.spans();
    let reads: Reads = Arc::default();
    let outcome = run_lake_baseline(
        &plan,
        |query: String, range: TimeRange, view: &'static str, _limit| {
            let reads = reads.clone();
            async move {
                reads
                    .lock()
                    .unwrap()
                    .push((query.clone(), range.clone(), view));
                Ok(match view {
                    "baseline-activity" => Vec::new(),
                    "baseline-presence" => vec![json!({"time": range.end.to_rfc3339()})],
                    "baseline-window" if query.contains("process.name") => vec![
                        json!({"process.name": "svchost.exe", "count": 900, "first_seen": range.start.to_rfc3339()}),
                        json!({"process.name": "rare.exe", "count": 1, "first_seen": range.end.to_rfc3339()}),
                    ],
                    "baseline-lookback" if query.contains("svchost.exe") => vec![
                        json!({"process.name": "svchost.exe", "first_seen": range.start.to_rfc3339()}),
                    ],
                    _ => Vec::new(),
                })
            }
        },
        None,
    )
    .await
    .unwrap();
    assert!(outcome.complete, "{:?}", outcome.rows);
    let rare = outcome
        .rows
        .iter()
        .find(|row| row["value"] == "rare.exe")
        .expect("the new process is listed");
    assert_eq!(rare["coverage"], "unknown");
    assert!(!outcome.rows.iter().any(|row| row["value"] == "svchost.exe"));
    assert!(outcome
        .rows
        .iter()
        .all(|row| row["coverage"] != "no_history"));
    let marker = outcome
        .rows
        .iter()
        .find(|row| row["dimension"].is_null())
        .expect("coverage caveat row");
    assert_eq!(marker["incomplete"], true);
    assert_eq!(marker["reason"], "activity counts unavailable");

    // The presence read asks for the same source-side entity fields the
    // activity read counts, over the activity span, newest day first.
    let reads = reads.lock().unwrap();
    let presence = reads
        .iter()
        .filter(|(_, _, view)| *view == "baseline-presence")
        .collect::<Vec<_>>();
    assert_eq!(presence.len(), 1, "stops at the first span with an event");
    assert!(presence[0]
        .0
        .contains("src_endpoint.hostname=\"ws-it-083\""));
    assert!(presence[0].0.contains("device.hostname=\"ws-it-083\""));
    assert!(!presence[0].0.contains("dst_endpoint"));
    assert!(presence[0].0.ends_with("| head 1"));
    assert!(presence[0].1.end < spans.coverage_end());
    assert!(presence[0].1.start >= spans.coverage_end() - Duration::days(1));
}

#[tokio::test]
async fn a_presence_read_error_is_unknown() {
    let outcome = run_lake_baseline(
        &plan(),
        |_query: String, _range: TimeRange, view: &'static str, _limit| async move {
            if view == "baseline-presence" {
                return Err(SearchError::ServiceUnavailable("down".to_string()));
            }
            Ok(Vec::new())
        },
        None,
    )
    .await
    .unwrap();
    assert_unknown(&outcome, "activity confirmation read failed");
}

/// `no_history` is claimed only when the activity read and the presence
/// read both completed and found nothing, and every other read finished.
#[tokio::test]
async fn no_history_only_after_a_completed_zero_answer() {
    let reads: Reads = Arc::default();
    let outcome = run_lake_baseline(
        &plan(),
        |query: String, range: TimeRange, view: &'static str, _limit| {
            let reads = reads.clone();
            async move {
                reads.lock().unwrap().push((query, range, view));
                Ok(Vec::new())
            }
        },
        Some(tokio::time::Instant::now() + std::time::Duration::from_secs(30)),
    )
    .await
    .unwrap();
    assert!(outcome.complete);
    let row = summary(&outcome);
    assert_eq!(row["coverage"], "no_history");
    assert_eq!(row["incomplete"], false);
    // Both presence spans (newest day, then the remainder) were read.
    let reads = reads.lock().unwrap();
    assert_eq!(
        reads
            .iter()
            .filter(|(_, _, view)| *view == "baseline-presence")
            .count(),
        2
    );
}

/// A dimension whose read fails is skipped and reported, the others are
/// still answered; the result is incomplete (escalates) instead of a 5xx.
#[tokio::test]
async fn a_dimension_read_error_marks_the_baseline_incomplete() {
    let outcome = run_lake_baseline(
        &plan(),
        |query: String, range: TimeRange, view: &'static str, _limit| async move {
            match view {
                "baseline-activity" => Ok(hourly(&range)),
                "baseline-window" if query.contains("dst_endpoint.ip") => Err(
                    SearchError::ServiceUnavailable("lane_wait_timeout".to_string()),
                ),
                _ => Ok(Vec::new()),
            }
        },
        None,
    )
    .await
    .unwrap();
    assert!(!outcome.complete);
    let marker = outcome
        .rows
        .iter()
        .find(|row| row["dimension"].is_null())
        .expect("marker row");
    assert_eq!(marker["incomplete"], true);
    assert_eq!(marker["coverage"], "sufficient");
    assert_eq!(marker["skipped_dimensions"], json!(["destination IPs"]));
    assert!(marker["reason"]
        .as_str()
        .unwrap()
        .contains("destination IPs: "));
}

/// ClickHouse may quote 64-bit counts; the baseline reads them, and rows it
/// cannot read never count as "zero activity".
#[tokio::test]
async fn quoted_counts_are_read_and_unreadable_activity_is_unknown() {
    let outcome = run_lake_baseline(
        &plan(),
        |_query: String, range: TimeRange, view: &'static str, _limit| async move {
            Ok(match view {
                "baseline-activity" => hourly(&range)
                    .into_iter()
                    .map(|mut row| {
                        row["count"] = json!("50");
                        row
                    })
                    .collect(),
                _ => Vec::new(),
            })
        },
        None,
    )
    .await
    .unwrap();
    assert!(outcome.complete);
    assert_eq!(summary(&outcome)["coverage"], "sufficient");

    let outcome = run_lake_baseline(
        &plan(),
        |_query: String, range: TimeRange, view: &'static str, _limit| async move {
            Ok(match view {
                "baseline-activity" => vec![json!({"bucket": range.start.to_rfc3339(), "n": 5})],
                _ => Vec::new(),
            })
        },
        None,
    )
    .await
    .unwrap();
    assert_unknown(&outcome, "without a readable time_bucket/count");
}
