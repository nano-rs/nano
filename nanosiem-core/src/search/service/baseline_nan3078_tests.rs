// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-3078: one lean baseline plan for both lanes; the durable job reads
//! every dimension inside the plan's contribution range.

use super::*;
use chrono::{Duration, TimeZone, Utc};
use serde_json::json;
use std::sync::{Arc, Mutex};

fn info(dims: Option<Vec<&str>>) -> BaselineCommandInfo {
    BaselineCommandInfo {
        entity_type: Some("host".to_string()),
        entity_value: Some("gate-01".to_string()),
        window: std::time::Duration::from_secs(7 * 86_400),
        dims: dims.map(|dims| dims.into_iter().map(str::to_string).collect()),
    }
}

fn incident() -> TimeRange {
    let end = Utc.with_ymd_and_hms(2026, 9, 29, 12, 0, 0).unwrap();
    TimeRange::new(end - Duration::hours(1), end)
}

fn plan() -> LakeBaselinePlan {
    LakeBaselinePlan::new(
        &info(None),
        ("host".to_string(), "gate-01".to_string()),
        &incident(),
        false,
    )
    .unwrap()
}

type Reads = Arc<Mutex<Vec<(String, TimeRange, &'static str)>>>;

/// A lake that has activity every hour and one never-seen process.
async fn fake_read(
    reads: Reads,
    query: String,
    range: TimeRange,
    view: &'static str,
) -> Result<Vec<serde_json::Value>, SearchError> {
    reads
        .lock()
        .unwrap()
        .push((query.clone(), range.clone(), view));
    Ok(match view {
        "baseline-activity" => {
            let mut rows = Vec::new();
            let mut hour = range.start;
            while hour < range.end {
                rows.push(json!({"time_bucket": hour.to_rfc3339(), "count": 10}));
                hour += Duration::hours(1);
            }
            rows
        }
        "baseline-window" if query.contains("process.name") => vec![
            json!({
                "process.name": "mimikatz.exe",
                "count": 1,
                "first_seen": (range.end - Duration::minutes(5)).to_rfc3339(),
            }),
            json!({
                "process.name": "svchost.exe",
                "count": 900,
                "first_seen": (range.start + Duration::minutes(1)).to_rfc3339(),
            }),
        ],
        // A known value: the dimension has history, so "new" is meaningful.
        "baseline-lookback" if query.contains("svchost.exe") => vec![json!({
            "process.name": "svchost.exe",
            "first_seen": (range.start + Duration::hours(1)).to_rfc3339(),
        })],
        _ => Vec::new(),
    })
}

#[test]
fn the_plan_round_trips_through_its_durable_task() {
    let plan = plan();
    let task = plan.to_task();
    task.validate().unwrap();
    let back = LakeBaselinePlan::from_task(&task).unwrap();
    assert_eq!(
        back.contribution_range().start,
        plan.contribution_range().start
    );
    assert_eq!(back.incident.end, plan.incident.end);
    assert_eq!(
        (back.window_days, back.activity_days),
        (plan.window_days, plan.activity_days)
    );
    // The contribution range covers the lookback, not only the incident.
    let spans = plan.spans();
    assert_eq!(
        plan.contribution_range().start,
        spans.activity_start.min(spans.new_start)
    );
    assert_eq!(plan.contribution_range().end, incident().end);
    assert!(LakeBaselinePlan::from_task(&crate::search::DurableLakeTask::SearchNplV1).is_err());
}

#[test]
fn a_plan_refuses_what_the_interactive_lane_refuses() {
    let too_wide = TimeRange::new(incident().end - Duration::days(8), incident().end);
    assert!(LakeBaselinePlan::new(
        &info(None),
        ("host".into(), "gate-01".into()),
        &too_wide,
        false
    )
    .is_err());
    assert!(LakeBaselinePlan::new(
        &info(Some(vec!["process.cmd_line"])),
        ("host".into(), "gate-01".into()),
        &incident(),
        false
    )
    .is_err());
    assert!(LakeBaselinePlan::new(
        &info(None),
        ("process".into(), "x".into()),
        &incident(),
        false
    )
    .is_err());
}

#[tokio::test]
async fn the_durable_run_reads_every_dimension_inside_the_contribution_range() {
    let plan = plan();
    let reads: Reads = Arc::default();
    let outcome = run_lake_baseline(
        &plan,
        |query, range, view, _limit| fake_read(reads.clone(), query, range, view),
        None,
    )
    .await
    .unwrap();
    assert!(outcome.complete);
    assert!(outcome.rows.iter().all(|row| row.get("partial").is_none()));
    assert!(outcome
        .rows
        .iter()
        .any(|row| row["dimension"] == "processes" && row["value"] == "mimikatz.exe"));
    assert!(!outcome.rows.iter().any(|row| row["value"] == "svchost.exe"));
    let contribution = plan.contribution_range();
    let reads = reads.lock().unwrap();
    // Two activity reads, one window read per host dimension, and the
    // lookback checks of the only dimension with window values: the newest
    // day (both values), then the remainder for the one it did not see
    // (NAN-3260).
    assert_eq!(reads.len(), 2 + 3 + 2);
    let checks = reads
        .iter()
        .filter(|(_, _, view)| *view == "baseline-lookback")
        .collect::<Vec<_>>();
    assert_eq!(checks.len(), 2);
    assert!(checks[0].0.contains("svchost.exe") && checks[0].0.contains("mimikatz.exe"));
    assert!(!checks[1].0.contains("svchost.exe") && checks[1].0.contains("mimikatz.exe"));
    for (_, range, view) in reads.iter() {
        assert!(
            range.start >= contribution.start && range.end <= contribution.end,
            "{view} read {range:?} outside the admitted range {contribution:?}"
        );
    }
}

#[tokio::test]
async fn an_interactive_run_past_its_deadline_is_partial() {
    let plan = plan();
    let reads: Reads = Arc::default();
    let outcome = run_lake_baseline(
        &plan,
        |query, range, view, _limit| {
            let reads = reads.clone();
            async move {
                if view == "baseline-window" {
                    tokio::time::sleep(std::time::Duration::from_secs(60)).await;
                }
                fake_read(reads, query, range, view).await
            }
        },
        Some(tokio::time::Instant::now() + std::time::Duration::from_millis(200)),
    )
    .await
    .unwrap();
    // The interactive lane turns this into ResourceExhausted when a durable
    // lane exists, so the handler escalates it to a BaselineV1 job.
    assert!(!outcome.complete);
    assert!(outcome
        .rows
        .iter()
        .any(|row| row.get("skipped_dimensions").is_some()));
}
