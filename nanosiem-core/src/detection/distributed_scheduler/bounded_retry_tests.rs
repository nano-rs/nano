// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-5424: a window that keeps failing for a non-size reason is retried a
//! bounded number of times, then recorded as a coverage gap and moved past —
//! never pinned forever, and never skipped without a gap row. Failures are
//! classified by TYPE / error code, never by message text.

use super::*;
use crate::detection::DetectionError;

const MAX_CATCHUP: i64 = 1440;

fn t(s: &str) -> DateTime<Utc> {
    DateTime::parse_from_rfc3339(s).unwrap().with_timezone(&Utc)
}

fn counters_from(d: &ReleaseDecision) -> RuleFailureCounters {
    RuleFailureCounters {
        catchup_size_failures: d.catchup_size_failures,
        consecutive_failures: d.consecutive_failures,
        failing_since: d.failing_since,
        failure_class: d.failure_class.map(str::to_string),
        crashed_attempts: 0,
    }
}

/// A rule failing on the same window. `lookback` = sliding rule.
struct Rule {
    lookback: Option<i32>,
    last_run_at: DateTime<Utc>,
    counters: RuleFailureCounters,
    gaps: Vec<(DateTime<Utc>, DateTime<Utc>, i32)>,
    evaluated: Vec<(DateTime<Utc>, DateTime<Utc>)>,
}

impl Rule {
    fn marker(last_run_at: DateTime<Utc>) -> Self {
        Self {
            lookback: None,
            last_run_at,
            counters: RuleFailureCounters::default(),
            gaps: Vec::new(),
            evaluated: Vec::new(),
        }
    }

    fn sliding(lookback: i32, last_run_at: DateTime<Utc>) -> Self {
        Self { lookback: Some(lookback), ..Self::marker(last_run_at) }
    }

    fn window(&self, now: DateTime<Utc>) -> (DateTime<Utc>, DateTime<Utc>) {
        let marker_driven = self.lookback.is_none();
        let failures = if marker_driven { self.counters.catchup_size_failures } else { 0 };
        let chunk = catchup_chunk_minutes(MAX_CATCHUP, failures);
        let end = compute_window_end(self.lookback, Some(self.last_run_at), now, chunk);
        let start = compute_window_start(self.lookback, Some(self.last_run_at), end, 15);
        (start, end)
    }

    fn step(&mut self, now: DateTime<Utc>, outcome: ExecutionOutcome) -> ReleaseDecision {
        let marker_driven = self.lookback.is_none();
        let (start, end) = self.window(now);
        let d = decide_release(
            outcome,
            marker_driven,
            Some(self.last_run_at),
            &self.counters,
            start,
            end,
            now,
            MAX_CATCHUP,
        );
        if outcome == ExecutionOutcome::Success {
            self.evaluated.push((start, end));
        }
        if let Some(mark) = d.advance_last_run_to {
            if outcome != ExecutionOutcome::Success && marker_driven {
                // A marker-driven rule moves past a failed window only with
                // a gap row for exactly that window.
                let gap = d.coverage_gap.expect("marker moved past a failed window without a gap");
                assert_eq!((gap.0, gap.1), (start, end));
            }
            self.last_run_at = mark;
        }
        if let Some(gap) = d.coverage_gap {
            self.gaps.push(gap);
        }
        self.counters = counters_from(&d);
        d
    }
}

#[test]
fn a_persistent_data_failure_is_retried_then_gapped_and_the_rule_advances() {
    let now = t("2026-11-14T12:00:00Z");
    let mark = now - Duration::minutes(3);
    let mut rule = Rule::marker(mark);
    for attempt in 1..DATA_FAILURE_ATTEMPTS {
        let d = rule.step(now, ExecutionOutcome::DataFailure);
        assert_eq!(d.advance_last_run_to, None, "attempt {attempt} must keep the window");
        assert_eq!(d.consecutive_failures, attempt);
        assert_eq!(d.failure_class, Some("data"));
        assert!(d.coverage_gap.is_none());
    }
    let d = rule.step(now, ExecutionOutcome::DataFailure);
    assert_eq!(d.advance_last_run_to, Some(now));
    assert_eq!(d.consecutive_failures, 0);
    assert_eq!(rule.gaps, vec![(mark - Duration::seconds(5), now, i32::from(DATA_FAILURE_ATTEMPTS))]);
}

#[test]
fn a_data_failure_in_a_large_catch_up_window_gaps_only_the_minimum_slice() {
    // A day-old backlog: the window is a full 24h chunk. A value that breaks
    // it must cost at most the 5-minute minimum slice, not the whole day.
    let now = t("2026-11-14T12:00:00Z");
    let mark = now - Duration::hours(30);
    let poison = mark + Duration::hours(20);
    let mut rule = Rule::marker(mark);
    for _ in 0..400 {
        let (start, end) = rule.window(now);
        let outcome = if start <= poison && poison < end {
            ExecutionOutcome::DataFailure
        } else {
            ExecutionOutcome::Success
        };
        let d = rule.step(now, outcome);
        if rule.last_run_at >= now || (d.advance_last_run_to.is_none() && !d.reclaim_immediately && outcome == ExecutionOutcome::Success) {
            break;
        }
    }
    assert_eq!(rule.gaps.len(), 1, "{:?}", rule.gaps);
    let (gap_start, gap_end, _) = rule.gaps[0];
    assert!(gap_start <= poison && poison < gap_end);
    assert!(
        gap_end - gap_start <= Duration::minutes(MIN_CATCHUP_CHUNK_MINUTES) + Duration::seconds(5),
        "gapped {:?}",
        gap_end - gap_start
    );
}

#[test]
fn an_unclassified_failure_needs_attempts_and_a_time_floor() {
    let start = t("2026-11-14T12:00:00Z");
    let mut rule = Rule::marker(start - Duration::minutes(1));
    // Twenty one-minute failures: plenty of attempts, but younger than the floor.
    for minute in 0..20 {
        let d = rule.step(start + Duration::minutes(minute), ExecutionOutcome::OtherFailure);
        assert!(d.coverage_gap.is_none(), "gapped after {minute} minutes");
    }
    let d = rule.step(start + OTHER_FAILURE_MIN_PIN, ExecutionOutcome::OtherFailure);
    assert!(d.coverage_gap.is_some(), "the floor has passed and the attempts are spent");
}

#[test]
fn an_outage_is_caught_up_unless_it_outlasts_the_transient_pin() {
    let start = t("2026-11-14T12:00:00Z");
    let mark = start - Duration::minutes(1);
    let mut rule = Rule::marker(mark);
    for minute in 0..300 {
        let d = rule.step(start + Duration::minutes(minute), ExecutionOutcome::TransientFailure);
        assert!(d.coverage_gap.is_none(), "gapped an outage after {minute} minutes");
        assert_eq!(d.catchup_size_failures, 0, "an outage must not shrink the slice");
    }
    assert_eq!(rule.last_run_at, mark);
    let d = rule.step(start + TRANSIENT_FAILURE_MAX_PIN, ExecutionOutcome::TransientFailure);
    assert!(d.coverage_gap.is_some());
}

#[test]
fn a_class_change_starts_a_new_streak() {
    let now = t("2026-11-14T12:00:00Z");
    let mut rule = Rule::marker(now - Duration::minutes(1));
    for _ in 0..(TRANSIENT_FAILURE_ATTEMPTS * 2) {
        rule.step(now, ExecutionOutcome::TransientFailure);
    }
    // An outage's many attempts must not spend the data budget.
    let d = rule.step(now, ExecutionOutcome::DataFailure);
    assert_eq!(d.consecutive_failures, 1);
    assert_eq!(d.failing_since, Some(now));
    assert!(d.coverage_gap.is_none());
}

#[test]
fn a_deterministic_failure_counts_but_never_gaps() {
    let now = t("2026-11-14T12:00:00Z");
    let mark = now - Duration::minutes(5);
    let mut rule = Rule::marker(mark);
    for n in 1..=50 {
        let d = rule.step(now + Duration::hours(i64::from(n)), ExecutionOutcome::DeterministicFailure);
        assert!(d.coverage_gap.is_none());
        assert_eq!(d.consecutive_failures, n);
    }
    assert_eq!(rule.last_run_at, mark, "the window is kept for when the rule is fixed");
}

#[test]
fn a_sliding_rule_records_everything_since_its_last_success() {
    let start = t("2026-11-14T12:00:00Z");
    let last_success = start - Duration::minutes(1);
    let mut rule = Rule::sliding(15, last_success);
    for _ in 1..DATA_FAILURE_ATTEMPTS {
        rule.step(start, ExecutionOutcome::DataFailure);
    }
    let later = start + Duration::hours(2);
    let d = rule.step(later, ExecutionOutcome::DataFailure);
    let (gap_start, gap_end, _) = d.coverage_gap.expect("gap");
    assert_eq!(gap_start, last_success, "the interval the lookback no longer covers is included");
    assert_eq!(gap_end, later);
    assert_eq!(rule.last_run_at, later);
}

#[test]
fn a_sliding_rule_recovering_after_a_long_streak_records_the_missed_interval() {
    let start = t("2026-11-14T12:00:00Z");
    let last_success = start - Duration::minutes(1);
    let mut rule = Rule::sliding(15, last_success);
    rule.step(start, ExecutionOutcome::TransientFailure);
    let later = start + Duration::hours(1);
    let d = rule.step(later, ExecutionOutcome::Success);
    let (gap_start, gap_end, _) = d.coverage_gap.expect("missed interval");
    assert_eq!(gap_start, last_success);
    assert_eq!(gap_end, later - Duration::minutes(15));
    // A short streak inside the lookback records nothing.
    let mut short = Rule::sliding(15, last_success);
    short.step(start, ExecutionOutcome::TransientFailure);
    assert!(short.step(start + Duration::minutes(5), ExecutionOutcome::Success).coverage_gap.is_none());
}

#[test]
fn no_outcome_sequence_moves_a_marker_without_a_gap() {
    use ExecutionOutcome::*;
    let all = [Success, SizeFailure, DeterministicFailure, DataFailure, TransientFailure, OtherFailure];
    let base = t("2026-11-14T00:00:00Z");
    for a in all {
        for b in all {
            for c in all {
                for d in all {
                    let mut rule = Rule::marker(base - Duration::hours(30));
                    for (i, outcome) in [a, b, c, d, a, b, c, d].into_iter().enumerate() {
                        rule.step(base + Duration::hours(i as i64 * 2), outcome);
                    }
                }
            }
        }
    }
}

#[test]
fn failures_are_classified_by_type_not_text() {
    use crate::detection::DetectionError as E;
    let class = |e: E| classify_outcome::<()>(&Err(e));
    assert_eq!(class(E::InvalidQuery("x".into())), ExecutionOutcome::DeterministicFailure);
    assert_eq!(class(E::BackendUnavailable("x".into())), ExecutionOutcome::TransientFailure);
    assert_eq!(class(E::DatabaseError(sqlx::Error::PoolTimedOut)), ExecutionOutcome::TransientFailure);
    assert_eq!(class(E::WindowTooLarge("x".into())), ExecutionOutcome::SizeFailure);
    assert_eq!(class(E::QueryDataError("x".into())), ExecutionOutcome::DataFailure);
    assert_eq!(class(E::QueryExecutionError("Rule execution panicked".into())), ExecutionOutcome::OtherFailure);
    assert_eq!(class(E::DatabaseError(sqlx::Error::RowNotFound)), ExecutionOutcome::OtherFailure);
    // Text that used to steer the class is ignored now.
    for text in [
        "Connection refused NETWORK_ERROR",
        "MEMORY_LIMIT_EXCEEDED too many rows",
        "Rule execution timed out",
        "Syntax error",
    ] {
        assert_eq!(class(E::SearchError(text.into())), ExecutionOutcome::OtherFailure, "{text}");
        assert_eq!(class(E::QueryExecutionError(text.into())), ExecutionOutcome::OtherFailure, "{text}");
    }
}

#[test]
fn clickhouse_errors_are_classified_by_code_not_by_quoted_or_unquoted_values() {
    use crate::detection::service::detection_error_from_search;
    use crate::search::parse_clickhouse_error;
    let class = |msg: &str| classify_outcome::<()>(&Err(detection_error_from_search(parse_clickhouse_error(msg))));
    // CANNOT_PARSE_NUMBER with the value echoed UNQUOTED, containing words
    // that used to select other classes.
    let poisoned = "Code: 72. DB::Exception: Cannot read floating point value here: Syntax error \
                    MEMORY_LIMIT_EXCEEDED Connection refused Unknown function (CANNOT_PARSE_NUMBER) (version 26.10.4.207)";
    assert_eq!(class(poisoned), ExecutionOutcome::DataFailure);
    assert_eq!(
        class("Code: 62. DB::Exception: Syntax error: failed at position 10 (SYNTAX_ERROR)"),
        ExecutionOutcome::DeterministicFailure
    );
    assert_eq!(
        class("Code: 241. DB::Exception: Memory limit (for query) exceeded (MEMORY_LIMIT_EXCEEDED)"),
        ExecutionOutcome::SizeFailure
    );
    assert_eq!(
        class("Code: 159. DB::Exception: Timeout exceeded: elapsed 10030.03 ms, maximum: 10000 ms (TIMEOUT_EXCEEDED)"),
        ExecutionOutcome::SizeFailure
    );
    assert_eq!(
        class("Code: 70. DB::Exception: Unexpected inf or nan to integer conversion: in toInt32 (CANNOT_CONVERT_TYPE)"),
        ExecutionOutcome::DataFailure
    );
    // An unknown code with scary words is just unclassified.
    assert_eq!(
        class("Code: 999. DB::Exception: value Syntax error MEMORY_LIMIT_EXCEEDED (SOMETHING)"),
        ExecutionOutcome::OtherFailure
    );
}

#[tokio::test]
async fn a_refused_clickhouse_connection_is_transient() {
    // A real client against a closed port: the error type, not its text,
    // must classify it ("network error: client error (Connect)").
    let client = clickhouse::Client::default().with_url("http://127.0.0.1:1");
    let err = client.query("SELECT 1").fetch_all::<u8>().await.expect_err("port 1 is closed");
    let search_error = crate::search::search_error_from_error(&err);
    assert!(matches!(search_error, crate::search::SearchError::Unavailable(_)), "{search_error:?}");
    let detection = crate::detection::service::detection_error_from_search(search_error);
    assert_eq!(classify_outcome::<()>(&Err(detection)), ExecutionOutcome::TransientFailure);
}

#[tokio::test]
async fn a_refused_postgres_connection_is_transient() {
    let err = sqlx::postgres::PgPoolOptions::new()
        .acquire_timeout(std::time::Duration::from_secs(2))
        .connect("postgres://nobody:nothing@127.0.0.1:1/none")
        .await
        .expect_err("port 1 is closed");
    let outcome = classify_outcome::<()>(&Err(DetectionError::DatabaseError(err)));
    assert_eq!(outcome, ExecutionOutcome::TransientFailure);
}

#[test]
fn errors_shown_to_users_carry_no_event_bytes() {
    let raw = "Code: 72. DB::Exception: Cannot read floating point value here: secret\u{0}value\n (CANNOT_PARSE_NUMBER)";
    let shown = DetectionError::SearchError(raw.into()).redacted_summary();
    assert_eq!(shown, "ClickHouse error (Code 72)");
    let shown = DetectionError::QueryDataError("CANNOT_PARSE_NUMBER (Code 72)".into()).redacted_summary();
    assert!(!shown.contains("secret"));
}
