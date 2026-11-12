// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-5296: the migrator's 202 retry policy.

use std::time::Duration;

use super::busy_retry::{
    busy_retry_delays, describe_stuck_inserts, is_too_many_simultaneous_queries,
    BUSY_RETRY_BUDGET,
};

#[test]
fn only_202_is_retried() {
    assert!(is_too_many_simultaneous_queries(
        "bad response: Code: 202. DB::Exception: Too many simultaneous insert queries. \
         Maximum: 20. (TOO_MANY_SIMULTANEOUS_QUERIES) (version 26.10.3.7 (official build))"
    ));
    assert!(!is_too_many_simultaneous_queries(
        "Code: 60. DB::Exception: Unknown table expression identifier 'nanosiem.x'. (UNKNOWN_TABLE)"
    ));
    assert!(!is_too_many_simultaneous_queries(
        "Code: 2020. DB::Exception: something else"
    ));
}

#[test]
fn backoff_is_exponential_capped_and_bounded_to_two_and_a_half_minutes() {
    let delays = busy_retry_delays();
    assert_eq!(
        &delays[..5],
        &[1, 2, 4, 8, 15].map(Duration::from_secs),
        "{delays:?}"
    );
    assert!(delays.iter().all(|delay| *delay <= Duration::from_secs(15)));
    let total: Duration = delays.iter().sum();
    assert!(total <= BUSY_RETRY_BUDGET, "{total:?}");
    assert!(
        total >= Duration::from_secs(120),
        "a 202 must be retried for at least two minutes, got {total:?}"
    );
}

#[test]
fn stuck_insert_report_names_count_age_and_kind() {
    let report = describe_stuck_inserts(2, 34_211, &["AsyncInsertFlush".into(), "Insert".into()]);
    assert!(report.starts_with(
        "insert slots exhausted by 2 stuck inserts (oldest 34211s, kind AsyncInsertFlush/Insert)"
    ));
    assert!(describe_stuck_inserts(1, 400, &["Insert".into()]).contains("1 stuck insert (oldest"));
}
