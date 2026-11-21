// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-4910 (port of NAN-2564): detection catch-up never silently drops
//! coverage.
//!
//! A model of the dedicated scheduler's marker transitions driven by the same
//! pure functions `execute_and_release` uses (`catchup_chunk_minutes`,
//! `compute_window_end`, `compute_window_start`, `decide_release`). Each step
//! is one claim → execute → release; `reclaim_immediately` means the next
//! step runs right away, otherwise on the next cron tick (time is frozen
//! here, which only makes a missed interval easier to spot).

use super::*;
use crate::detection::DetectionError;

const DEFAULT_LOOKBACK: i64 = 15;
const MAX_CATCHUP: i64 = 1440; // 24h
const OVERLAP: Duration = Duration::seconds(5);

fn t(s: &str) -> DateTime<Utc> {
    DateTime::parse_from_rfc3339(s).unwrap().with_timezone(&Utc)
}

#[derive(Default)]
struct RuleModel {
    lookback_minutes: Option<i32>,
    last_run_at: Option<DateTime<Utc>>,
    size_failures: i16,
    /// NAN-5424: non-size failure streak.
    consecutive_failures: i16,
    failing_since: Option<DateTime<Utc>>,
    failure_class: Option<&'static str>,
    /// Successfully evaluated windows, in execution order.
    evaluated: Vec<(DateTime<Utc>, DateTime<Utc>)>,
    /// Windows recorded as coverage gaps.
    gaps: Vec<(DateTime<Utc>, DateTime<Utc>)>,
    /// Every attempted window, in order, with its outcome.
    attempts: Vec<(DateTime<Utc>, DateTime<Utc>, ExecutionOutcome)>,
}

impl RuleModel {
    fn marker_driven(&self) -> bool {
        self.lookback_minutes.is_none() && self.last_run_at.is_some()
    }

    /// One scheduler execution. `execute` decides the outcome for a window.
    fn step(
        &mut self,
        now: DateTime<Utc>,
        execute: &dyn Fn(DateTime<Utc>, DateTime<Utc>) -> ExecutionOutcome,
    ) -> ReleaseDecision {
        let marker_driven = self.marker_driven();
        let failures = if marker_driven { self.size_failures } else { 0 };
        let chunk = catchup_chunk_minutes(MAX_CATCHUP, failures);
        let end = compute_window_end(self.lookback_minutes, self.last_run_at, now, chunk);
        let start = compute_window_start(self.lookback_minutes, self.last_run_at, end, DEFAULT_LOOKBACK);
        let outcome = execute(start, end);
        self.attempts.push((start, end, outcome));
        let decision = decide_release(
            outcome,
            marker_driven,
            self.last_run_at,
            &RuleFailureCounters {
                catchup_size_failures: self.size_failures,
                consecutive_failures: self.consecutive_failures,
                failing_since: self.failing_since,
                failure_class: self.failure_class.map(str::to_string),
                crashed_attempts: 0,
                crash_streak: 0,
                crash_suspect: false,
                isolated_claim: false,
            },
            start,
            end,
            now,
            MAX_CATCHUP,
        );
        if outcome == ExecutionOutcome::Success {
            self.evaluated.push((start, end));
        }
        if let Some((gap_start, gap_end, _attempts)) = decision.coverage_gap {
            self.gaps.push((gap_start, gap_end));
        }
        if let Some(mark) = decision.advance_last_run_to {
            self.last_run_at = Some(mark);
        }
        self.size_failures = decision.catchup_size_failures;
        self.consecutive_failures = decision.consecutive_failures;
        self.failing_since = decision.failing_since;
        self.failure_class = decision.failure_class;
        decision
    }

    /// Run until the rule is caught up to `now` (bounded so a livelock fails
    /// the test instead of hanging it).
    fn run_until_caught_up(
        &mut self,
        now: DateTime<Utc>,
        execute: &dyn Fn(DateTime<Utc>, DateTime<Utc>) -> ExecutionOutcome,
    ) {
        for _ in 0..500 {
            self.step(now, execute);
            if self.last_run_at == Some(now) {
                return;
            }
        }
        panic!("rule never caught up; attempts: {:?}", self.attempts);
    }
}

/// Every instant of `[from, to]` is inside an evaluated window or a recorded
/// gap — nothing was silently skipped.
fn assert_fully_accounted(
    windows: &[(DateTime<Utc>, DateTime<Utc>)],
    from: DateTime<Utc>,
    to: DateTime<Utc>,
) {
    let mut sorted = windows.to_vec();
    sorted.sort();
    let mut covered_to = from;
    for (start, end) in sorted {
        assert!(
            start <= covered_to,
            "interval [{covered_to}, {start}) was never evaluated nor recorded as a gap"
        );
        covered_to = covered_to.max(end);
    }
    assert!(covered_to >= to, "coverage stops at {covered_to}, expected {to}");
}

#[test]
fn chunk_ladder_shrinks_by_four_to_a_five_minute_floor() {
    let ladder: Vec<i64> = (0..7).map(|n| catchup_chunk_minutes(MAX_CATCHUP, n)).collect();
    assert_eq!(ladder, [1440, 360, 90, 22, 5, 5, 5]);
    assert_eq!(size_failures_at_min_chunk(MAX_CATCHUP), 4);
    // A tiny configured cap never goes below the floor.
    assert_eq!(catchup_chunk_minutes(1, 0), MIN_CATCHUP_CHUNK_MINUTES);
}

#[test]
fn three_day_outage_is_drained_oldest_first_in_bounded_slices_with_no_skipped_interval() {
    let now = t("2026-07-05T12:00:00Z");
    let outage_start = now - Duration::hours(72) - Duration::minutes(7);
    let mut rule = RuleModel {
        last_run_at: Some(outage_start),
        ..RuleModel::default()
    };

    let mut decisions = Vec::new();
    while rule.last_run_at != Some(now) {
        decisions.push(rule.step(now, &|_, _| ExecutionOutcome::Success));
        assert!(decisions.len() < 10, "backlog did not drain");
    }

    // 72h07m of backlog in <= 24h slices: four slices, oldest first.
    assert_eq!(rule.evaluated.len(), 4);
    assert_eq!(rule.evaluated[0].0, outage_start - OVERLAP, "oldest interval first");
    for pair in rule.evaluated.windows(2) {
        let (prev, next) = (pair[0], pair[1]);
        assert_eq!(next.0, prev.1 - OVERLAP, "slices are contiguous");
        assert!(next.0 > prev.0, "oldest-first");
    }
    for (start, end) in &rule.evaluated {
        assert!(*end - *start <= Duration::minutes(MAX_CATCHUP) + OVERLAP);
    }
    assert_eq!(rule.evaluated.last().unwrap().1, now);
    // Every slice but the last leaves backlog behind and is reclaimed at once;
    // the last returns to the normal cron cadence.
    assert!(decisions[..decisions.len() - 1].iter().all(|d| d.reclaim_immediately));
    assert!(!decisions.last().unwrap().reclaim_immediately);
    assert!(rule.gaps.is_empty());
    assert_fully_accounted(&rule.evaluated, outage_start, now);
}

#[test]
fn the_old_24h_floor_regression_cannot_recur() {
    // Before NAN-4910 the first window after a 3-day outage started at
    // `now - 24h`: the first 48h were never evaluated.
    let now = t("2026-07-05T12:00:00Z");
    let outage_start = now - Duration::hours(72);
    let end = compute_window_end(None, Some(outage_start), now, MAX_CATCHUP);
    let start = compute_window_start(None, Some(outage_start), end, DEFAULT_LOOKBACK);
    assert_eq!(start, outage_start - OVERLAP);
    assert!(start < now - Duration::minutes(MAX_CATCHUP));
}

#[test]
fn a_size_failing_window_is_retried_smaller_rather_than_forever() {
    // Any window longer than 100 minutes blows the memory limit / timeout.
    let now = t("2026-07-05T12:00:00Z");
    let outage_start = now - Duration::hours(30);
    let mut rule = RuleModel {
        last_run_at: Some(outage_start),
        ..RuleModel::default()
    };
    let too_big = |start: DateTime<Utc>, end: DateTime<Utc>| {
        if end - start > Duration::minutes(100) {
            ExecutionOutcome::SizeFailure
        } else {
            ExecutionOutcome::Success
        }
    };

    // First attempt: the 24h slice fails, the retry is a smaller slice and is
    // scheduled immediately; then 360 min fails; then 90 min succeeds.
    let first = rule.step(now, &too_big);
    assert_eq!(first.advance_last_run_to, None, "marker kept on a size failure");
    assert_eq!(first.catchup_size_failures, 1);
    assert!(first.reclaim_immediately, "a strictly smaller slice retries at once");
    let second = rule.step(now, &too_big);
    assert_eq!(second.catchup_size_failures, 2);
    let third = rule.step(now, &too_big);
    assert_eq!(third.catchup_size_failures, 0, "success resets the shrink");
    assert_eq!(
        rule.attempts.iter().map(|(s, e, _)| (*e - *s - OVERLAP).num_minutes()).collect::<Vec<_>>(),
        [1440, 360, 90]
    );

    rule.run_until_caught_up(now, &too_big);
    assert!(rule.gaps.is_empty(), "a window that fits after shrinking is never a gap");
    assert!(rule.evaluated.iter().all(|(s, e)| *e - *s <= Duration::minutes(100)));
    assert_fully_accounted(&rule.evaluated, outage_start, now);
}

#[test]
fn an_unrecoverable_slice_is_recorded_as_a_coverage_gap_and_the_rule_moves_on() {
    // A 2-minute stretch no window can evaluate, whatever its size (e.g. a
    // pathological burst). Everything else succeeds.
    let now = t("2026-07-05T12:00:00Z");
    let outage_start = now - Duration::hours(26);
    let poison_start = outage_start + Duration::hours(3);
    let poison_end = poison_start + Duration::minutes(2);
    let mut rule = RuleModel {
        last_run_at: Some(outage_start),
        ..RuleModel::default()
    };
    let poisoned = |start: DateTime<Utc>, end: DateTime<Utc>| {
        if start < poison_end && end > poison_start {
            ExecutionOutcome::SizeFailure
        } else {
            ExecutionOutcome::Success
        }
    };

    rule.run_until_caught_up(now, &poisoned);

    assert_eq!(rule.gaps.len(), 1, "exactly one recorded gap: {:?}", rule.gaps);
    let (gap_start, gap_end) = rule.gaps[0];
    assert!(gap_start <= poison_start && gap_end >= poison_end, "gap covers the poison");
    assert!(
        gap_end - gap_start <= Duration::minutes(MIN_CATCHUP_CHUNK_MINUTES) + OVERLAP,
        "only the minimum slice is given up"
    );
    // The gap was recorded only after the minimum slice failed
    // MIN_CHUNK_ATTEMPTS times in a row.
    let min_chunk_failures = rule
        .attempts
        .iter()
        .filter(|(s, e, o)| {
            *o == ExecutionOutcome::SizeFailure
                && *e - *s <= Duration::minutes(MIN_CATCHUP_CHUNK_MINUTES) + OVERLAP
        })
        .count();
    assert_eq!(min_chunk_failures, MIN_CHUNK_ATTEMPTS as usize);
    // Nothing else was lost: evaluated windows plus the gap account for the
    // whole outage, and the rule caught up to now.
    let mut accounted = rule.evaluated.clone();
    accounted.extend(rule.gaps.iter().copied());
    assert_fully_accounted(&accounted, outage_start, now);
    assert_eq!(rule.last_run_at, Some(now));
}

#[test]
fn a_transient_failure_keeps_the_marker_and_never_records_a_gap() {
    // NAN-5424: an infrastructure failure (backend unreachable) keeps the
    // window until the rule has been failing for TRANSIENT_FAILURE_MAX_PIN;
    // time is frozen here, so it never reaches that.
    let now = t("2026-07-05T12:00:00Z");
    let mark = now - Duration::hours(30);
    let mut rule = RuleModel {
        last_run_at: Some(mark),
        ..RuleModel::default()
    };
    for _ in 0..20 {
        let decision = rule.step(now, &|_, _| ExecutionOutcome::TransientFailure);
        assert_eq!(decision.advance_last_run_to, None);
        assert!(!decision.reclaim_immediately);
    }
    assert_eq!(rule.last_run_at, Some(mark));
    assert_eq!(rule.size_failures, 0);
    assert!(rule.gaps.is_empty());
}

#[test]
fn a_sliding_lookback_rule_never_shrinks_its_window() {
    let now = t("2026-07-05T12:00:00Z");
    let mut rule = RuleModel {
        lookback_minutes: Some(60),
        last_run_at: Some(now - Duration::hours(1)),
        ..RuleModel::default()
    };
    for _ in 0..10 {
        let decision = rule.step(now, &|_, _| ExecutionOutcome::SizeFailure);
        assert_eq!(decision.advance_last_run_to, None);
        assert_eq!(decision.catchup_size_failures, 0);
    }
    assert!(rule.attempts.iter().all(|(s, e, _)| *e - *s == Duration::minutes(60)));
    // NAN-5424: it can't shrink, so it is bounded like an unclassified
    // failure (attempts AND a time floor); time is frozen here, so no gap.
    assert!(rule.gaps.is_empty());
}

#[test]
fn a_first_run_size_failure_pins_the_bootstrap_window() {
    let now = t("2026-07-05T12:00:00Z");
    let mut rule = RuleModel::default();
    let decision = rule.step(now, &|_, _| ExecutionOutcome::SizeFailure);
    assert_eq!(
        decision.advance_last_run_to,
        Some(now - Duration::minutes(DEFAULT_LOOKBACK))
    );
    assert!(decision.coverage_gap.is_none());
}

#[test]
fn size_dependent_errors_are_classified() {
    // NAN-5424: by type / ClickHouse code only (see `detection_error_from_search`).
    use crate::detection::service::detection_error_from_search as map;
    use crate::search::{parse_clickhouse_error, SearchError};
    for error in [
        map(SearchError::Timeout(30_012)),
        map(parse_clickhouse_error(
            "Code: 159. DB::Exception: Timeout exceeded: elapsed 10030.03 ms, maximum: 10000 ms (TIMEOUT_EXCEEDED)",
        )),
        map(parse_clickhouse_error(
            "Code: 241. DB::Exception: Memory limit (for query) exceeded (MEMORY_LIMIT_EXCEEDED)",
        )),
        map(parse_clickhouse_error(
            "Code: 396. DB::Exception: Limit for result exceeded (TOO_MANY_ROWS_OR_BYTES)",
        )),
        map(SearchError::ResponseTooLarge(900, 100)),
    ] {
        assert!(error.is_window_size_dependent(), "{error}");
    }
    for error in [
        DetectionError::InvalidQuery("bad".into()),
        map(parse_clickhouse_error("Code: 62. DB::Exception: Syntax error (SYNTAX_ERROR)")),
        map(SearchError::Unavailable("network error: client error (Connect)".into())),
        // The scheduler's outer timeout also fires on a stalled backend.
        DetectionError::BackendUnavailable("Rule execution timed out after 300s".into()),
        // A timeout with no elapsed time does not prove ClickHouse ran it.
        map(SearchError::Timeout(0)),
        // Text is never trusted.
        DetectionError::SearchError("MEMORY_LIMIT_EXCEEDED".into()),
    ] {
        assert!(!error.is_window_size_dependent(), "{error}");
    }
}

/// NAN-5565: ClickHouse refuses query TEXT over `max_query_size` with code 62
/// (SYNTAX_ERROR). The prevalence rescue's inlined literals grow with the
/// window, so that refusal is a size failure the scheduler must answer by
/// shrinking the window, never the deterministic-invalid back-off.
#[test]
fn max_query_size_refusal_is_a_size_failure_not_an_invalid_query() {
    use crate::detection::service::detection_error_from_search as map;
    use crate::search::{parse_clickhouse_error, SearchError};
    for message in [
        // Exact wording from ClickHouse 26.11 (clickhouse-local and an HTTP
        // server, 2026-11-17); production runs 26.10.
        "Code: 62. DB::Exception: Max query size exceeded (can be increased with the `max_query_size` setting): Syntax error: failed at position 262120 ('aaaa'): 'aaaa'. . (SYNTAX_ERROR)",
    ] {
        let search_error = parse_clickhouse_error(message);
        assert!(
            matches!(search_error, SearchError::ResourceLimit(_)),
            "{message} -> {search_error:?}"
        );
        let detection = map(search_error);
        assert!(detection.is_window_size_dependent(), "{detection}");
        let result: Result<(), DetectionError> = Err(detection);
        assert!(!is_deterministic_failure(&result));
    }
    // A real syntax error stays a deterministic invalid query, and the marker
    // inside the QUOTED excerpt (data) is never trusted.
    for message in [
        "Code: 62. DB::Exception: Syntax error: failed at position 12 ('FORM'): FORM logs. Expected FROM. (SYNTAX_ERROR)",
        "Code: 62. DB::Exception: Syntax error: failed at position 40 ('Max query size exceeded'): x. (SYNTAX_ERROR)",
    ] {
        let detection = map(parse_clickhouse_error(message));
        assert!(!detection.is_window_size_dependent(), "{message} -> {detection}");
        let result: Result<(), DetectionError> = Err(detection);
        assert!(is_deterministic_failure(&result), "{message}");
    }
}

#[test]
fn a_stalled_backend_timeout_never_creates_a_gap() {
    // ClickHouse accepts connections but stalls past the scheduler's
    // execution timeout: every attempt fails with the outer timeout. That is
    // not proof the window is too large, so the marker must stay put — no
    // shrink, no gap — however long the stall lasts.
    let now = t("2026-07-05T12:00:00Z");
    let mark = now - Duration::hours(30);
    let mut rule = RuleModel {
        last_run_at: Some(mark),
        ..RuleModel::default()
    };
    let stalled = DetectionError::BackendUnavailable("Rule execution timed out after 300s".into());
    let outcome = classify_outcome::<()>(&Err(stalled));
    assert_eq!(outcome, ExecutionOutcome::TransientFailure);
    for _ in 0..50 {
        rule.step(now, &|_, _| outcome);
    }
    assert!(rule.gaps.is_empty(), "a stall recorded a gap: {:?}", rule.gaps);
    assert_eq!(rule.last_run_at, Some(mark), "high-water mark moved during a stall");
    assert_eq!(rule.size_failures, 0, "a stall must not shrink the slice");
    // Every attempt re-scanned the same full slice from the mark.
    assert!(rule
        .attempts
        .iter()
        .all(|(s, e, _)| *s == mark - OVERLAP && *e == mark + Duration::minutes(MAX_CATCHUP)));
}

/// NAN-5565: a run that succeeded but left input out (a prevalence rescue cut
/// at its key-byte cap) records a `[partial] …` last_error; a failed run keeps
/// its own error, and a full run records nothing.
#[test]
fn a_partial_run_records_a_visible_partial_error() {
    let ok: Result<(), DetectionError> = Ok(());
    let failed: Result<(), DetectionError> = Err(DetectionError::InvalidQuery("bad".into()));
    let notes = vec!["prevalence rescue left out 3 dict-blind artifact(s)".to_string()];
    assert_eq!(
        partial_run_error(&ok, &notes).as_deref(),
        Some("[partial] prevalence rescue left out 3 dict-blind artifact(s)")
    );
    assert_eq!(partial_run_error(&ok, &[]), None);
    assert_eq!(partial_run_error(&failed, &notes), None);
}
