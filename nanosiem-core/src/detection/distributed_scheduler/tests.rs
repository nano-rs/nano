// SPDX-License-Identifier: AGPL-3.0-or-later

//! Unit tests for the distributed detection scheduler's window arithmetic.
//!
//! These pin the audit D1/D2/D22 contract for `compute_window_start`:
//! - contiguous catch-up from `last_run_at` (minus the 5s overlap buffer),
//! - explicit `lookback_minutes` wins and is never capped,
//! - a long-dormant rule's catch-up window is bounded to `max_catchup_minutes`
//!   by slicing its END, never by moving its start forward (NAN-4910; the
//!   catch-up/coverage-gap contract lives in `catchup_tests.rs`).

use super::*;

const DEFAULT_LOOKBACK: i64 = 15;
const MAX_CATCHUP: i64 = 1440; // 24h

fn t(s: &str) -> DateTime<Utc> {
    DateTime::parse_from_rfc3339(s).unwrap().with_timezone(&Utc)
}

#[test]
fn first_run_uses_default_lookback() {
    let end = t("2026-07-05T12:00:00Z");
    let start = compute_window_start(None, None, end, DEFAULT_LOOKBACK);
    assert_eq!(start, end - Duration::minutes(DEFAULT_LOOKBACK));
}

#[test]
fn explicit_lookback_wins_and_is_not_capped() {
    let end = t("2026-07-05T12:00:00Z");
    // 3 days > max_catchup (24h): explicit lookback must NOT be floored — the
    // window is intentional and bounded by the rule's own lookback cap.
    let start = compute_window_start(Some(3 * 24 * 60), Some(end), end, DEFAULT_LOOKBACK);
    assert_eq!(start, end - Duration::minutes(3 * 24 * 60));
}

#[test]
fn catchup_is_contiguous_from_last_run_with_5s_overlap() {
    // Audit D2: the next window starts at the *previous window end* (last_run_at),
    // minus a 5s ingestion-lag buffer — NOT at query-completion time.
    let end = t("2026-07-05T12:05:00Z");
    let last_run = t("2026-07-05T12:00:00Z");
    let start = compute_window_start(None, Some(last_run), end, DEFAULT_LOOKBACK);
    assert_eq!(start, last_run - Duration::seconds(5));
    // The window covers [last_run - 5s, end] with no gap after last_run.
    assert!(start <= last_run);
}

#[test]
fn long_dormant_rule_is_bounded_by_slicing_not_by_dropping_its_backlog() {
    // Audit D22: a rule idle for ~90 days must not build a 90-day window.
    // NAN-4910: the bound comes from the window END (an oldest-first slice of
    // at most MAX_CATCHUP), never from moving the start forward — the old
    // `end - max_catchup` floor silently discarded everything older.
    let now = t("2026-07-05T12:00:00Z");
    let last_run = t("2026-04-06T12:00:00Z"); // ~90 days earlier
    let end = compute_window_end(None, Some(last_run), now, MAX_CATCHUP);
    let start = compute_window_start(None, Some(last_run), end, DEFAULT_LOOKBACK);
    assert_eq!(start, last_run - Duration::seconds(5));
    assert_eq!(end, last_run + Duration::minutes(MAX_CATCHUP));
    // Window is bounded to 24h (+5s overlap), not 90 days.
    assert_eq!(end - start, Duration::minutes(MAX_CATCHUP) + Duration::seconds(5));
}

#[test]
fn recent_last_run_within_cap_is_not_floored() {
    // A rule that ran 30 minutes ago (well within the 24h cap) catches up fully.
    let end = t("2026-07-05T12:00:00Z");
    let last_run = t("2026-07-05T11:30:00Z");
    let start = compute_window_start(None, Some(last_run), end, DEFAULT_LOOKBACK);
    assert_eq!(start, last_run - Duration::seconds(5));
}

#[test]
fn success_advances_last_run_to_window_end() {
    // Audit D2: on success the high-water mark becomes the executed window end.
    let start = t("2026-07-05T11:45:00Z");
    let end = t("2026-07-05T12:00:00Z");
    assert_eq!(
        next_last_run_at(true, Some(t("2026-07-05T11:45:05Z")), start, end),
        Some(end)
    );
}

#[test]
fn failure_with_prior_mark_leaves_last_run_untouched() {
    // Audit D1: a failed run must NOT advance last_run_at; the failed window is
    // re-scanned from the existing high-water mark next cycle.
    let prior = t("2026-07-05T11:45:00Z");
    let start = prior - Duration::seconds(5);
    let end = t("2026-07-05T12:00:00Z");
    assert_eq!(next_last_run_at(false, Some(prior), start, end), None);
}

#[test]
fn first_run_failure_pins_the_bootstrap_start() {
    // Codex/audit D1 edge: on the very first run (no prior mark) a failure pins
    // last_run_at to the window start so the bootstrap window is re-covered next
    // cycle instead of sliding forward.
    let end = t("2026-07-05T12:00:00Z");
    let start = end - Duration::minutes(DEFAULT_LOOKBACK);
    assert_eq!(next_last_run_at(false, None, start, end), Some(start));
}

#[test]
fn deterministic_query_failures_are_backed_off() {
    use crate::detection::DetectionError;
    assert!(is_deterministic_failure::<()>(&Err(DetectionError::InvalidQuery("bad".into()))));
    assert!(is_deterministic_failure::<()>(&Err(DetectionError::QueryParseError("bad".into()))));
    assert!(!is_deterministic_failure::<()>(&Err(DetectionError::SearchError("timeout".into()))));
    assert!(!is_deterministic_failure::<()>(&Err(DetectionError::QueryExecutionError("timed out".into()))));
    assert!(!is_deterministic_failure::<()>(&Ok(())));
}

#[test]
fn realtime_microbatches_disable_schedule_phase() {
    assert_eq!(schedule_phase_cap_for_mode(DetectionMode::RealTime, 300), 0);
    assert_eq!(schedule_phase_cap_for_mode(DetectionMode::Scheduled, 300), 300);
}

/// NAN-3063: the phase offset moves *when* a rule fires, never *what* it
/// scans. Drive a rule through its phased schedule the way
/// `execute_and_release` does (success stamps `last_run_at = end`) and check the high-water mark tiles exactly: each
/// window's watermark origin is the previous window's end (the scan adds the
/// documented 5 s ingest buffer before it), ends strictly increase, and the
/// covered span equals wall time elapsed. Includes a missed run (execution
/// longer than the interval) and a failure, which must not advance the mark.
#[test]
fn phased_schedule_windows_tile_exactly() {
    use crate::detection::scheduler::rule_phase_offset;
    let config = DistributedSchedulerConfig::default();
    for cron in ["*/1 * * * *", "*/5 * * * *", "*/15 * * * *", "0 * * * *"] {
        for seed in 0..50u128 {
            let rule_id = Uuid::from_u128(0x0192_0000_0000_7000_8000_0000_0000_0000 | seed * 7919);
            let mut last_run_at: Option<DateTime<Utc>> = None;
            let mut fire = calculate_next_run_phased(
                cron,
                t("2026-07-05T12:00:00Z"),
                rule_id,
                config.phase_max_secs,
            );
            let offset = rule_phase_offset(cron, fire, rule_id, config.phase_max_secs);
            let mut first_end: Option<DateTime<Utc>> = None;
            let mut prev_end: Option<DateTime<Utc>> = None;
            for run in 0..40 {
                // The base scheduler's window ends at the fire time.
                let end = fire;
                let start = compute_window_start(
                    None,
                    last_run_at,
                    end,
                    config.default_lookback_minutes,
                );
                if let Some(prev) = prev_end {
                    assert_eq!(start, prev - Duration::seconds(5), "{cron}: gap or drift");
                    assert!(end > prev, "{cron}: window did not advance");
                }
                // Every 7th run fails: the mark must stay put and the next
                // window must re-cover the failed span.
                let success = run % 7 != 3;
                if let Some(mark) = next_last_run_at(success, last_run_at, start, end) {
                    last_run_at = Some(mark);
                }
                if success {
                    first_end.get_or_insert(end);
                    prev_end = Some(end);
                }
                // Every 11th run overruns its interval.
                let done = fire + if run % 11 == 5 {
                    schedule_interval_for_test(cron) + Duration::seconds(20)
                } else {
                    Duration::seconds(3)
                };
                let next = calculate_next_run_phased(cron, done, rule_id, config.phase_max_secs);
                assert_eq!(
                    rule_phase_offset(cron, next, rule_id, config.phase_max_secs),
                    offset,
                    "{cron}: offset drifted"
                );
                fire = next;
            }
            // Contiguous coverage: from the first successful end to the last,
            // the chained windows cover exactly the elapsed event time.
            assert!(prev_end.unwrap() > first_end.unwrap());
        }
    }
}

/// With an explicit lookback equal to the interval the sliding windows tile
/// exactly too, because the phase offset is constant per rule.
#[test]
fn phased_schedule_lookback_windows_tile_exactly() {
    let config = DistributedSchedulerConfig::default();
    let rule_id = Uuid::from_u128(0x0192_1234_5678_7abc_8def_0123_4567_89ab);
    let mut fire = calculate_next_run_phased("*/5 * * * *", t("2026-07-05T12:00:00Z"), rule_id, config.phase_max_secs);
    let mut prev_end: Option<DateTime<Utc>> = None;
    for _ in 0..24 {
        let end = fire;
        let start = compute_window_start(Some(5), None, end, config.default_lookback_minutes);
        if let Some(prev) = prev_end {
            assert_eq!(start, prev, "sliding lookback windows must abut exactly");
        }
        prev_end = Some(end);
        fire = calculate_next_run_phased("*/5 * * * *", fire + Duration::seconds(4), rule_id, config.phase_max_secs);
    }
}

fn schedule_interval_for_test(cron: &str) -> Duration {
    crate::detection::scheduler::schedule_interval(cron, t("2026-07-05T12:00:00Z")).unwrap()
}

