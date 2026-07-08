// SPDX-License-Identifier: AGPL-3.0-or-later

//! Unit tests for the distributed detection scheduler's window arithmetic.
//!
//! These pin the audit D1/D2/D22 contract for `compute_window_start`:
//! - contiguous catch-up from `last_run_at` (minus the 5s overlap buffer),
//! - explicit `lookback_minutes` wins and is never capped,
//! - a long-dormant rule's catch-up window is floored to `max_catchup_minutes`.

use super::*;

const DEFAULT_LOOKBACK: i64 = 15;
const MAX_CATCHUP: i64 = 1440; // 24h

fn t(s: &str) -> DateTime<Utc> {
    DateTime::parse_from_rfc3339(s).unwrap().with_timezone(&Utc)
}

#[test]
fn first_run_uses_default_lookback() {
    let end = t("2026-07-05T12:00:00Z");
    let start = compute_window_start(None, None, end, DEFAULT_LOOKBACK, MAX_CATCHUP);
    assert_eq!(start, end - Duration::minutes(DEFAULT_LOOKBACK));
}

#[test]
fn explicit_lookback_wins_and_is_not_capped() {
    let end = t("2026-07-05T12:00:00Z");
    // 3 days > max_catchup (24h): explicit lookback must NOT be floored — the
    // window is intentional and bounded by the rule's own lookback cap.
    let start = compute_window_start(Some(3 * 24 * 60), Some(end), end, DEFAULT_LOOKBACK, MAX_CATCHUP);
    assert_eq!(start, end - Duration::minutes(3 * 24 * 60));
}

#[test]
fn catchup_is_contiguous_from_last_run_with_5s_overlap() {
    // Audit D2: the next window starts at the *previous window end* (last_run_at),
    // minus a 5s ingestion-lag buffer — NOT at query-completion time.
    let end = t("2026-07-05T12:05:00Z");
    let last_run = t("2026-07-05T12:00:00Z");
    let start = compute_window_start(None, Some(last_run), end, DEFAULT_LOOKBACK, MAX_CATCHUP);
    assert_eq!(start, last_run - Duration::seconds(5));
    // The window covers [last_run - 5s, end] with no gap after last_run.
    assert!(start <= last_run);
}

#[test]
fn long_dormant_rule_is_capped_to_max_catchup() {
    // Audit D22: a rule idle for ~90 days must not build a 90-day window.
    let end = t("2026-07-05T12:00:00Z");
    let last_run = t("2026-04-06T12:00:00Z"); // ~90 days earlier
    let start = compute_window_start(None, Some(last_run), end, DEFAULT_LOOKBACK, MAX_CATCHUP);
    let floor = end - Duration::minutes(MAX_CATCHUP);
    assert_eq!(start, floor);
    // Window is bounded to 24h, not 90 days.
    assert_eq!(end - start, Duration::minutes(MAX_CATCHUP));
}

#[test]
fn recent_last_run_within_cap_is_not_floored() {
    // A rule that ran 30 minutes ago (well within the 24h cap) catches up fully.
    let end = t("2026-07-05T12:00:00Z");
    let last_run = t("2026-07-05T11:30:00Z");
    let start = compute_window_start(None, Some(last_run), end, DEFAULT_LOOKBACK, MAX_CATCHUP);
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
