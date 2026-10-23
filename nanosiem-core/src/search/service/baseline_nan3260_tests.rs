// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-3260: a lean `| baseline` is never refused by the lake's per-query
//! cold-read budget. The lookback is read newest-first in spans; a span the
//! lake refuses for its size is split, and a span already at the minimum is
//! reported unread (`incomplete`) instead of failing the search.

use super::*;
use chrono::{Duration, TimeZone, Utc};
use serde_json::json;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

const GIB: u64 = 1 << 30;

type Reads = Arc<Mutex<Vec<(String, TimeRange, &'static str)>>>;

fn plan(window_days: u64, dims: Option<Vec<&str>>) -> LakeBaselinePlan {
    let end = Utc.with_ymd_and_hms(2026, 10, 7, 20, 0, 0).unwrap();
    LakeBaselinePlan::new(
        &BaselineCommandInfo {
            entity_type: Some("host".to_string()),
            entity_value: Some("ws-it-083.corp.local".to_string()),
            window: std::time::Duration::from_secs(window_days * 86_400),
            dims: dims.map(|dims| dims.into_iter().map(str::to_string).collect()),
        },
        ("host".to_string(), "ws-it-083.corp.local".to_string()),
        &TimeRange::new(end - Duration::hours(1), end),
        false,
    )
    .unwrap()
}

fn micros(range: &TimeRange) -> (i64, i64) {
    (range.start.timestamp_micros(), range.end.timestamp_micros())
}

/// `pieces` are newest first, disjoint, contiguous and cover `span`.
fn assert_tiles(span: &TimeRange, pieces: &[TimeRange]) {
    let mut oldest_first = pieces.iter().map(micros).collect::<Vec<_>>();
    oldest_first.reverse();
    assert_eq!(oldest_first.first().unwrap().0, micros(span).0);
    assert_eq!(oldest_first.last().unwrap().1, micros(span).1);
    // NAN-4280: half-open pieces share each boundary (gap-free, no overlap).
    for pair in oldest_first.windows(2) {
        assert_eq!(pair[0].1, pair[1].0, "{pieces:?}");
        assert!(pair[0].0 < pair[0].1);
    }
}

#[test]
fn the_lookback_is_read_newest_day_first_then_the_remainder() {
    let end = Utc.with_ymd_and_hms(2026, 10, 7, 19, 0, 0).unwrap();
    let lookback = TimeRange::new(end - Duration::days(7), end);
    let spans = lake_baseline_lookback_spans(&lookback);
    assert_eq!(spans.len(), 2);
    assert_tiles(&lookback, &spans);
    assert_eq!(spans[0].end, end);
    assert_eq!(
        micros(&spans[0]).1 - micros(&spans[0]).0,
        86_400_000_000
    );

    // A lookback of a day or less is one span.
    let day = TimeRange::new(end - Duration::hours(20), end);
    assert_eq!(lake_baseline_lookback_spans(&day).len(), 1);
}

#[test]
fn a_cold_budget_refusal_splits_the_span_into_budget_sized_pieces() {
    let end = Utc.with_ymd_and_hms(2026, 10, 7, 19, 0, 0).unwrap();
    let six_days = TimeRange::new(end - Duration::days(6), end);

    // The live 7d case: 3.18 GB needed against a 2 GiB budget.
    let refused = SearchError::ColdScanTooLarge { needed_bytes: 3_180_000_000, ceiling_bytes: 2 * GIB, background_ceiling_bytes: None };
    let Some(LakeBaselineRefusal::Split(pieces)) = lake_baseline_refusal(&refused, &six_days)
    else {
        panic!("a multi-hour span is split");
    };
    assert_eq!(pieces.len(), 2);
    assert_tiles(&six_days, &pieces);
    assert!(pieces[0].start > pieces[1].start, "newest piece first");

    // Each piece aims at ~3/4 of the budget: 10x over needs 14 pieces.
    let far_over = SearchError::ColdScanTooLarge { needed_bytes: 20 * GIB, ceiling_bytes: 2 * GIB, background_ceiling_bytes: None };
    let Some(LakeBaselineRefusal::Split(pieces)) = lake_baseline_refusal(&far_over, &six_days)
    else {
        panic!("split");
    };
    assert_eq!(pieces.len(), 14);
    assert_tiles(&six_days, &pieces);

    // Never below the minimum span: a 3h span splits at most into 3.
    let three_hours = TimeRange::new(end - Duration::hours(3), end);
    let Some(LakeBaselineRefusal::Split(pieces)) = lake_baseline_refusal(&far_over, &three_hours)
    else {
        panic!("split");
    };
    assert_eq!(pieces.len(), 3);
    assert_tiles(&three_hours, &pieces);

    // A minimal span is reported unread, never refused.
    let hour = TimeRange::new(end - Duration::minutes(59), end);
    assert!(matches!(
        lake_baseline_refusal(&refused, &hour),
        Some(LakeBaselineRefusal::Unread)
    ));

    // Scan and memory refusals halve; anything else is not a size refusal.
    for kind in ["scan; estimated_bytes=9; budget_bytes=1", "scan", "memory"] {
        let Some(LakeBaselineRefusal::Split(pieces)) =
            lake_baseline_refusal(&SearchError::ResourceExhausted(kind.to_string()), &six_days)
        else {
            panic!("{kind} splits");
        };
        assert_eq!(pieces.len(), 2);
    }
    for error in [
        SearchError::ResourceExhausted("concurrency".to_string()),
        SearchError::ServiceUnavailable("down".to_string()),
        SearchError::SqlValidationError("bad".to_string()),
    ] {
        assert!(
            lake_baseline_refusal(&error, &six_days).is_none(),
            "{error:?}"
        );
    }
}

#[test]
fn span_pieces_tile_the_span_newest_first() {
    let end = Utc.with_ymd_and_hms(2026, 10, 7, 19, 0, 0).unwrap();
    let span = TimeRange::new(end - Duration::days(5) - Duration::microseconds(7), end);
    for pieces in [1, 2, 3, 7, 16] {
        let out = lake_baseline_span_pieces(&span, pieces);
        assert_eq!(out.len(), pieces as usize);
        assert_tiles(&span, &out);
    }
}

/// A lake whose cold-read fence charges 0.6 GB per lookback day not yet
/// cached, against a 2 GiB budget: a single 7d lookback read is refused
/// (like the live 3.18 GB), a day is not. Every window value but `new_ips`
/// was seen in the lookback.
async fn budgeted_lake(
    reads: Reads,
    refuse_all_lookback: bool,
    query: String,
    range: TimeRange,
    view: &'static str,
) -> Result<Vec<serde_json::Value>, SearchError> {
    reads
        .lock()
        .unwrap()
        .push((query.clone(), range.clone(), view));
    let days = (range.end - range.start).num_minutes() as f64 / 1_440.0;
    let needed = (days * 600_000_000.0) as u64;
    if matches!(view, "baseline-lookback" | "baseline-history")
        && (refuse_all_lookback || needed > 2 * GIB)
    {
        return Err(SearchError::ColdScanTooLarge { needed_bytes: needed.max(2 * GIB + 1), ceiling_bytes: 2 * GIB, background_ceiling_bytes: None });
    }
    Ok(match view {
        "baseline-activity" => {
            let mut rows = Vec::new();
            let mut hour = range.start;
            while hour < range.end {
                rows.push(json!({"time_bucket": hour.to_rfc3339(), "count": 50}));
                hour += Duration::hours(1);
            }
            rows
        }
        "baseline-window" if query.contains("process.name") => ["svchost.exe", "rare.exe"]
            .into_iter()
            .map(|name| json!({"process.name": name, "count": 2, "first_seen": range.start.to_rfc3339()}))
            .collect(),
        // Seen only in the OLDEST lookback day: every span must be read.
        "baseline-lookback"
            if query.contains("svchost.exe")
                && range.start <= Utc.with_ymd_and_hms(2026, 10, 1, 20, 0, 0).unwrap() =>
        {
            vec![json!({"process.name": "svchost.exe", "first_seen": range.start.to_rfc3339()})]
        }
        _ => Vec::new(),
    })
}

#[tokio::test]
async fn a_7d_lookback_over_the_cold_budget_is_split_never_refused() {
    let plan = plan(7, Some(vec!["process.name"]));
    let spans = plan.spans();
    let reads: Reads = Arc::default();
    let outcome = run_lake_baseline(
        &plan,
        |query, range, view, _limit| budgeted_lake(reads.clone(), false, query, range, view),
        Some(tokio::time::Instant::now() + std::time::Duration::from_secs(30)),
    )
    .await
    .expect("a baseline is never refused by the cold-read budget");
    assert!(outcome.complete);
    // svchost was seen (on the oldest day), rare.exe is new; nothing unread.
    let new = outcome
        .rows
        .iter()
        .filter(|row| row["dimension"] == "processes")
        .collect::<Vec<_>>();
    assert_eq!(new.len(), 1, "{:?}", outcome.rows);
    assert_eq!(new[0]["value"], "rare.exe");
    assert_eq!(new[0]["incomplete"], false);

    // Every lookback day was read exactly once by an accepted read, and
    // accepted reads stay inside the lookback.
    let reads = reads.lock().unwrap();
    let accepted = reads
        .iter()
        .filter(|(_, range, view)| {
            *view == "baseline-lookback"
                && (range.end - range.start).num_minutes() as f64 / 1_440.0 * 600_000_000.0
                    <= (2 * GIB) as f64
        })
        .map(|(_, range, _)| range.clone())
        .collect::<Vec<_>>();
    let lookback = TimeRange::new(spans.new_start, spans.incident_start);
    let mut sorted = accepted.clone();
    sorted.sort_by_key(|range| std::cmp::Reverse(range.start));
    assert_tiles(&lookback, &sorted);
    // Activity covers only the new-to-entity window, not 30 days.
    let activity = reads
        .iter()
        .filter(|(_, _, view)| *view == "baseline-activity")
        .collect::<Vec<_>>();
    assert_eq!(activity.len(), 2);
    for (_, range, _) in activity {
        assert_eq!(
            (range.start, range.end),
            (spans.new_start, spans.coverage_end())
        );
    }
}

#[tokio::test]
async fn an_unreadable_lookback_degrades_to_incomplete_not_an_error() {
    let plan = plan(7, Some(vec!["process.name"]));
    let reads: Reads = Arc::default();
    let outcome = run_lake_baseline(
        &plan,
        |query, range, view, _limit| budgeted_lake(reads.clone(), true, query, range, view),
        Some(tokio::time::Instant::now() + std::time::Duration::from_secs(30)),
    )
    .await
    .expect("refused reads degrade, they never fail the search");
    // Answered (no durable escalation), but every claim is caveated.
    assert!(outcome.complete);
    let marker = outcome
        .rows
        .iter()
        .find(|row| row["dimension"].is_null())
        .expect("marker row");
    assert_eq!(marker["incomplete"], true);
    assert_eq!(marker["incomplete_dimensions"], json!(["processes"]));
    assert!(
        marker["note"]
            .as_str()
            .unwrap()
            .contains("cold-read budget"),
        "{marker}"
    );
    // Nothing was seen and the history probe was unreadable too, so nothing
    // is claimed as a first sighting.
    assert!(outcome.rows.iter().all(|row| row["dimension"].is_null()));
    // Splitting stops at the minimum span or the split cap: bounded work.
    let refused_reads = reads
        .lock()
        .unwrap()
        .iter()
        .filter(|(_, _, view)| matches!(*view, "baseline-lookback" | "baseline-history"))
        .count();
    assert!(
        refused_reads <= 4 + LAKE_BASELINE_MAX_SPLITS * LAKE_BASELINE_MAX_PIECES as usize,
        "{refused_reads}"
    );
}

#[tokio::test]
async fn unconfirmed_first_sightings_are_listed_as_incomplete() {
    // Lookback reads of the newest day succeed (svchost seen there), the
    // older remainder is unreadable even at the minimum span.
    let plan = plan(7, Some(vec!["process.name"]));
    let spans = plan.spans();
    let newest_day = spans.incident_start - Duration::days(1);
    let outcome = run_lake_baseline(
        &plan,
        move |query, range, view, _limit| async move {
            if view == "baseline-lookback" && range.start < newest_day {
                return Err(SearchError::ColdScanTooLarge { needed_bytes: 3 * GIB, ceiling_bytes: 2 * GIB, background_ceiling_bytes: None });
            }
            if view == "baseline-lookback" && query.contains("svchost.exe") {
                return Ok(vec![
                    json!({"process.name": "svchost.exe", "first_seen": range.start.to_rfc3339()}),
                ]);
            }
            budgeted_lake(Arc::default(), false, query, range, view).await
        },
        None,
    )
    .await
    .unwrap();
    assert!(outcome.complete);
    let rare = outcome
        .rows
        .iter()
        .find(|row| row["value"] == "rare.exe")
        .expect("listed");
    assert_eq!(rare["incomplete"], true);
    assert!(!outcome.rows.iter().any(|row| row["value"] == "svchost.exe"));
}

#[tokio::test(start_paused = true)]
async fn reads_share_one_in_flight_bound_across_phases_and_dimensions() {
    let in_flight = Arc::new(AtomicUsize::new(0));
    let peak = Arc::new(AtomicUsize::new(0));
    let total = Arc::new(AtomicUsize::new(0));
    let plan = plan(7, None);
    let outcome = run_lake_baseline(
        &plan,
        |query: String, range: TimeRange, view: &'static str, _limit| {
            let (in_flight, peak, total) = (in_flight.clone(), peak.clone(), total.clone());
            async move {
                let now = in_flight.fetch_add(1, Ordering::SeqCst) + 1;
                peak.fetch_max(now, Ordering::SeqCst);
                total.fetch_add(1, Ordering::SeqCst);
                tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                in_flight.fetch_sub(1, Ordering::SeqCst);
                Ok(match view {
                    "baseline-activity" => {
                        let mut rows = Vec::new();
                        let mut hour = range.start;
                        while hour < range.end {
                            rows.push(json!({"time_bucket": hour.to_rfc3339(), "count": 50}));
                            hour += Duration::hours(1);
                        }
                        rows
                    }
                    // Every dimension has a window value nobody saw before.
                    "baseline-window" => {
                        let field = query.rsplit(" by ").next().unwrap().split(',').next().unwrap().split(' ').next().unwrap().to_string();
                        vec![json!({field: "10.9.9.9", "count": 1, "first_seen": range.start.to_rfc3339()})]
                    }
                    "baseline-history" => vec![json!({"time": range.start.to_rfc3339()})],
                    _ => Vec::new(),
                })
            }
        },
        Some(tokio::time::Instant::now() + std::time::Duration::from_secs(40)),
    )
    .await
    .unwrap();
    assert!(outcome.complete);
    assert_eq!(peak.load(Ordering::SeqCst), LAKE_BASELINE_CONCURRENCY);
    // 2 activity + 3 window + 3 dims x (2 lookback spans + 1 probe).
    assert_eq!(total.load(Ordering::SeqCst), 2 + 3 + 3 * 3);
    assert_eq!(
        outcome
            .rows
            .iter()
            .filter(|row| !row["dimension"].is_null())
            .count(),
        3
    );
}
