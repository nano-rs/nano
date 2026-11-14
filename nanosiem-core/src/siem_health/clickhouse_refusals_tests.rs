// SPDX-License-Identifier: AGPL-3.0-or-later
//! NAN-5390: ClickHouse refusing nano's logins or writes is one critical finding.

use super::*;
use crate::siem_health::analyzer::fallback_report;
use crate::siem_health::analyzer::tests::base_zero_metrics_fixture;

fn analysis() -> AnalysisResult {
    fallback_report(&base_zero_metrics_fixture())
}

#[test]
fn parses_the_clickhouse_error_code_anywhere_in_a_message() {
    assert_eq!(
        clickhouse_error_code("bad response: Code: 516. DB::Exception: nanosiem: Authentication failed"),
        Some(516)
    );
    assert_eq!(clickhouse_error_code("Code: 195. DB::Exception: x"), Some(195));
    assert_eq!(clickhouse_error_code("Code: 19. x"), Some(19));
    assert_eq!(clickhouse_error_code("network error: connection refused"), None);
    assert_eq!(clickhouse_error_code("Code: ."), None);
}

#[test]
fn only_login_refusals_count_as_a_refused_probe() {
    assert!(refusal_from_error("bad response: Code: 516. DB::Exception: nanosiem_admin: Authentication failed").is_some());
    assert!(refusal_from_error("Code: 195. DB::Exception: IP address not allowed").is_some());
    // A missing grant on a system table, memory, or a timeout is not a refused login.
    assert!(refusal_from_error("Code: 497. DB::Exception: Not enough privileges").is_none());
    assert!(refusal_from_error("Code: 241. DB::Exception: Memory limit").is_none());
    assert!(refusal_from_error("Code: 19. x").is_none());
    assert!(refusal_from_error("timeout").is_none());
}

fn err(code: i32, value: u64, msg: &str) -> ErrorRow {
    ErrorRow { name: "AUTHENTICATION_FAILED".into(), code, value, last_error_message: msg.into() }
}

#[test]
fn session_log_counts_only_nano_users_with_repeated_failures() {
    let logins = vec![
        LoginFailureRow { user: "nanosiem_vector".into(), failures: 40 },
        LoginFailureRow { user: "nanosiem".into(), failures: 1 }, // one typo
        LoginFailureRow { user: "default".into(), failures: 9 },  // not nano's
        LoginFailureRow { user: "bob".into(), failures: 50 },
    ];
    assert_eq!(refusal_lines(&logins, &[], &[]), vec!["40 refused logins for nanosiem_vector".to_string()]);
}

#[test]
fn errors_fallback_needs_a_nano_user_in_the_last_message_and_repeats() {
    let errors = vec![
        err(516, 12, "nanosiem_vector: Authentication failed: password is incorrect\n"),
        err(516, 30, "operator: Authentication failed"),
        err(193, 1, "nanosiem: wrong password"),
        err(195, 5, "Connections from 10.0.0.1 are not allowed"),
    ];
    assert_eq!(
        refusal_lines(&[], &errors, &[]),
        vec!["AUTHENTICATION_FAILED (516) for nanosiem_vector, 12 since ClickHouse started: last nanosiem_vector: Authentication failed: password is incorrect".to_string()]
    );
}

#[test]
fn denied_inserts_need_repeats() {
    let denied = vec![
        DeniedInsertRow { user: "nanosiem_vector".into(), refused: 12 },
        DeniedInsertRow { user: "nanosiem_ingest".into(), refused: 1 },
    ];
    assert_eq!(
        refusal_lines(&[], &[], &denied),
        vec!["12 INSERTs by nanosiem_vector refused for missing grants (ACCESS_DENIED, 497)".to_string()]
    );
}

#[test]
fn nano_user_is_read_from_the_message_prefix() {
    assert_eq!(nano_user_in_message("nanosiem_ingest: Authentication failed"), Some("nanosiem_ingest"));
    assert_eq!(nano_user_in_message("default: Authentication failed"), None);
    assert_eq!(nano_user_in_message("nanosiem x: y"), None);
    assert_eq!(nano_user_in_message("no separator"), None);
}

#[test]
fn refusals_are_one_critical_finding_and_cap_the_score() {
    let mut a = analysis();
    a.overall_score = 95;
    let lines = vec!["AUTHENTICATION_FAILED (516): last x".to_string()];
    ensure_clickhouse_refusal_findings(&mut a, &lines);
    ensure_clickhouse_refusal_findings(&mut a, &lines);
    assert!(a.overall_score <= 49);
    let found: Vec<_> = a
        .recommendations
        .iter()
        .filter(|r| r.title == CLICKHOUSE_REFUSALS_TITLE)
        .collect();
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].priority, "critical");
    assert!(found[0].description.contains("AUTHENTICATION_FAILED (516)"));
    assert_eq!(a.recommendations[0].title, CLICKHOUSE_REFUSALS_TITLE);
}

#[test]
fn no_refusals_change_nothing() {
    let mut a = analysis();
    let before = (a.overall_score, a.recommendations.len());
    ensure_clickhouse_refusal_findings(&mut a, &[]);
    assert_eq!((a.overall_score, a.recommendations.len()), before);
}
