// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-5303: real-time rules matched and alerted but never wrote
//! `detection_matches`, so the Matches page, `/api/rules/stats` and
//! tune-from-match were empty for them. The end-to-end proof (MV → signals →
//! SignalProcessor → `detection_matches` rows in Postgres) is
//! `tests/realtime_detection_matches_e2e.rs`; these pin the per-cycle row
//! shape and where in `process_signal` the match is captured.

use serde_json::json;

use super::signal_processor::tests::d13_test_rule;
use super::signal_processor::MatchReviewBuffer;
use crate::models::{AlertMode, RuleMode};

#[test]
fn grouped_rule_writes_one_row_per_cycle_per_event_rule_one_per_event() {
    let grouped = d13_test_rule(RuleMode::Live, AlertMode::Grouped);
    let mut per_event = d13_test_rule(RuleMode::Alerting, AlertMode::PerEvent);
    per_event.id = uuid::Uuid::from_u128(0xd2);

    let mut buf = MatchReviewBuffer::default();
    for i in 0..500 {
        buf.push(grouped.clone(), json!({"id": format!("g{i}")}));
    }
    for i in 0..3 {
        buf.push(per_event.clone(), json!({"id": format!("p{i}")}));
    }

    let rows = buf.into_rows();
    // 500 grouped signals collapse into ONE review row (not 500 INSERTs);
    // per-event rules keep one row per event, like the scheduled path.
    assert_eq!(rows.len(), 1 + 3);
    assert_eq!(rows[0].0.id, grouped.id);
    assert_eq!(rows[0].1.len(), 500);
    assert!(rows[1..].iter().all(|(r, ev)| r.id == per_event.id && ev.len() == 1));
}

#[test]
fn empty_cycle_writes_nothing() {
    assert!(MatchReviewBuffer::default().into_rows().is_empty());
}

/// The match is captured for EVERY active-rule signal: after the
/// Staging/Paused gate and before the Live / Alerting split, so window-deduped
/// and Live bake-in signals are recorded too.
#[test]
fn review_match_is_captured_before_the_live_alerting_split() {
    const SOURCE: &str = include_str!("signal_processor.rs");
    let start = SOURCE.find("async fn process_signal(").expect("process_signal");
    let end = start
        + SOURCE[start..]
            .find("fn build_window_dedup_candidate(")
            .expect("process_signal is followed by build_window_dedup_candidate");
    let body = &SOURCE[start..end];
    let gate = body.find("RuleMode::Staging | RuleMode::Paused").expect("gate");
    let capture = body.find("*review_match = Some(").expect("capture (NAN-5303)");
    let live_split = body.find("if matches!(rule.mode, RuleMode::Live)").expect("live");
    assert!(gate < capture && capture < live_split);
}
