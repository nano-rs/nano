// SPDX-License-Identifier: AGPL-3.0-or-later
//! NAN-4902 review follow-ups: predicates evaluated Nano-side, after a
//! post-processing stage (`| prevalence`, `| risk`), must give the same answer
//! as the ClickHouse SQL the generator emits for the same predicate — or fail
//! as a query error. They must never evaluate to null and silently filter
//! (which `NOT` turns into match-all).
use super::apply_post_prevalence_commands;
use crate::query::{parse_query, Command, Query, SearchExpr};
use serde_json::{json, Value};

fn condition(predicate: &str) -> SearchExpr {
    match parse_query(&format!("* | where {predicate}")).expect("parse production nPL") {
        Query::Piped { command: Command::Where { condition }, .. } => condition,
        other => panic!("expected where stage, got {other:?}"),
    }
}

/// Run `predicate` as a post-processing `where` and return the matching row ids.
fn post_ids(rows: &[Value], predicate: &str) -> Vec<u64> {
    let result = apply_post_prevalence_commands(
        rows.to_vec(),
        &[Command::Where { condition: condition(predicate) }],
    )
    .unwrap_or_else(|e| panic!("{predicate}: unexpected error {e:?}"));
    let mut ids: Vec<u64> = result.results.iter().map(|r| r["row_id"].as_u64().unwrap()).collect();
    ids.sort();
    ids
}

fn post_err(rows: &[Value], predicate: &str) -> bool {
    apply_post_prevalence_commands(rows.to_vec(), &[Command::Where { condition: condition(predicate) }]).is_err()
}

fn all_ids(rows: &[Value]) -> Vec<u64> {
    (0..rows.len() as u64).collect()
}

/// Assert `predicate` matches exactly `expected`, and `NOT predicate` the complement.
fn assert_positive_and_negated(rows: &[Value], predicate: &str, expected: &[u64]) {
    assert_eq!(post_ids(rows, predicate), expected, "{predicate}");
    let complement: Vec<u64> = all_ids(rows).into_iter().filter(|id| !expected.contains(id)).collect();
    assert_eq!(post_ids(rows, &format!("NOT {predicate}")), complement, "NOT {predicate}");
}

fn ip_rows() -> Vec<Value> {
    ["10.1.2.3", "192.168.0.1", "172.16.0.1", "172.32.0.1", "8.8.8.8", "127.0.0.1", "", "not-an-ip", "10.foo", "::ffff:10.0.0.1"]
        .iter()
        .enumerate()
        .map(|(id, ip)| json!({"row_id": id, "src_ip": ip}))
        .collect()
}

fn text_rows() -> Vec<Value> {
    ["svchost.exe", "SVCHOST.EXE", "powershell -enc AAA", "a\nb", "100%_done", ""]
        .iter()
        .enumerate()
        .map(|(id, s)| json!({"row_id": id, "process_name": s, "tags": ["Malware", "c2"], "ioc_tags": "phishing,C2"}))
        .collect()
}

// ---------------------------------------------------------------- finding 1

#[test]
fn cidr_match_both_argument_orders_positive_and_negated() {
    let rows = ip_rows();
    // 10.1.2.3 and ::ffff:10.0.0.1 (IPv4-mapped); empty/malformed never match.
    for predicate in [
        r#"cidrmatch("10.0.0.0/8", src_ip)"#,
        r#"cidr_match(src_ip, "10.0.0.0/8")"#,
        r#"CIDRMATCH("10.0.0.0/8", src_ip)"#,
    ] {
        assert_positive_and_negated(&rows, predicate, &[0, 9]);
    }
    assert_positive_and_negated(&rows, r#"cidr_match(src_ip, "10.0.0.0/8", "192.168.0.0/16")"#, &[0, 1, 9]);
    assert_positive_and_negated(&rows, r#"cidr_match(src_ip, "172.16.0.0/12")"#, &[2]);
}

#[test]
fn cidr_match_invalid_literal_cidr_is_a_query_error() {
    let rows = ip_rows();
    for predicate in [r#"cidr_match(src_ip, "10.0.0.0/33")"#, r#"NOT cidrmatch("bogus/8", src_ip)"#, r#"cidr_match(src_ip)"#] {
        assert!(post_err(&rows, predicate), "{predicate}");
    }
}

#[test]
fn match_and_regex_match_are_case_sensitive_positive_and_negated() {
    let rows = text_rows();
    for name in ["match", "regex_match", "MATCH"] {
        assert_positive_and_negated(&rows, &format!(r#"{name}(process_name, "^svchost\.exe$")"#), &[0]);
        assert_positive_and_negated(&rows, &format!(r#"{name}(process_name, "(?i)^svchost")"#), &[0, 1]);
        assert_positive_and_negated(&rows, &format!(r#"{name}(process_name, "-enc")"#), &[2]);
    }
    // ClickHouse RE2 defaults: dot matches newline.
    assert_positive_and_negated(&rows, r#"match(process_name, "^a.b$")"#, &[3]);
}

#[test]
fn match_with_invalid_literal_regex_is_a_query_error() {
    let rows = text_rows();
    for predicate in [r#"match(process_name, "[")"#, r#"NOT regex_match(process_name, "(")"#] {
        assert!(post_err(&rows, predicate), "{predicate}");
        assert!(post_err(&[], predicate), "{predicate} on an empty page");
    }
}

#[test]
fn like_is_case_insensitive_with_wildcards_positive_and_negated() {
    // NAN-3041 / NAN-4943: like() compiles to `lower(..) LIKE` in SQL (ASCII
    // fold), so it is case-insensitive here too.
    let rows = text_rows();
    assert_positive_and_negated(&rows, r#"like(process_name, "svchost%")"#, &[0, 1]);
    assert_positive_and_negated(&rows, r#"like(process_name, "%EXE")"#, &[0, 1]);
    assert_positive_and_negated(&rows, r#"like(process_name, "_vchost.exe")"#, &[0, 1]);
    assert_positive_and_negated(&rows, r#"like(process_name, "100\%\_done")"#, &[4]);
    assert_positive_and_negated(&rows, r#"LIKE(process_name, "%")"#, &[0, 1, 2, 3, 4, 5]);
}

#[test]
fn has_is_case_insensitive_substring_positive_and_negated() {
    let rows = text_rows();
    assert_positive_and_negated(&rows, r#"has(ioc_tags, "c2")"#, &[0, 1, 2, 3, 4, 5]);
    assert_positive_and_negated(&rows, r#"has(tags, "MALWARE")"#, &[0, 1, 2, 3, 4, 5]);
    assert_positive_and_negated(&rows, r#"has(tags, "ransom")"#, &[]);
    assert_positive_and_negated(&rows, r#"has(process_name, "SVCHOST")"#, &[0, 1]);
}

#[test]
fn isnull_and_isnotnull_positive_and_negated() {
    let rows = vec![json!({"row_id": 0, "user": "alice"}), json!({"row_id": 1, "user": null}), json!({"row_id": 2})];
    assert_positive_and_negated(&rows, "isnull(user)", &[1, 2]);
    assert_positive_and_negated(&rows, "isnotnull(user)", &[0]);
}

#[test]
fn functions_without_an_evaluator_are_query_errors_not_silent_filters() {
    // NAN-4933: isnum/isint/isstr/isbool/searchmatch now evaluate Nano-side
    // (eval_capability_tests, npl_bc_ch parity); an unknown name still errors.
    let rows = text_rows();
    for predicate in ["nosuchfn(process_name) = 1", "NOT nosuchfn(process_name) = 1"] {
        assert!(post_err(&rows, predicate), "{predicate}");
        assert!(post_err(&[], predicate), "{predicate} on an empty page");
    }
    // Also beneath OR / a group, and in an `fn(...) op value` filter.
    assert!(post_err(&rows, "isnull(user) OR nosuchfn(process_name) = 1"));
    assert!(post_err(&rows, "NOT (nosuchfn(process_name) = 1)"));
}

// ---------------------------------------------------------------- finding 2

#[test]
fn ip_classifiers_reject_empty_and_malformed_addresses() {
    let rows = ip_rows();
    // ids: 0 10.1.2.3 | 1 192.168.0.1 | 2 172.16.0.1 | 3 172.32.0.1 | 4 8.8.8.8
    //      5 127.0.0.1 | 6 "" | 7 not-an-ip | 8 10.foo | 9 ::ffff:10.0.0.1
    assert_eq!(post_ids(&rows, "is_public_ip(src_ip)"), vec![3, 4]);
    assert_eq!(post_ids(&rows, "NOT is_public_ip(src_ip)"), vec![0, 1, 2, 5, 6, 7, 8, 9]);
    assert_eq!(post_ids(&rows, "is_public_ip(src_ip) = true"), vec![3, 4]);
    assert_eq!(post_ids(&rows, "is_private_ip(src_ip)"), vec![0, 1, 2, 9]);
    assert_eq!(post_ids(&rows, "NOT is_private_ip(src_ip)"), vec![3, 4, 5, 6, 7, 8]);
    assert_eq!(post_ids(&rows, "is_private_ip(src_ip) = 0"), vec![3, 4, 5, 6, 7, 8]);
    assert_eq!(post_ids(&rows, "is_loopback(src_ip) = true"), vec![5]);
    assert_eq!(post_ids(&rows, "ispublicip(src_ip)"), vec![3, 4]);
}

#[test]
fn empty_source_ip_is_not_public() {
    let rows = vec![json!({"row_id": 0, "src_ip": ""}), json!({"row_id": 1, "src_ip": "203.0.113.9"})];
    assert_eq!(post_ids(&rows, "is_public_ip(src_ip)"), vec![1]);
}

// ---------------------------------------------------------------- finding 3

#[test]
fn scalar_min_max_function_filters_are_case_insensitive() {
    let rows = vec![json!({"row_id": 0, "risk_score": 90}), json!({"row_id": 1, "risk_score": 10})];
    for name in ["max", "MAX", "Max"] {
        assert_eq!(post_ids(&rows, &format!("{name}(risk_score, 50) > 75")), vec![0], "{name}");
        assert_eq!(post_ids(&rows, &format!("NOT {name}(risk_score, 50) > 75")), vec![1], "{name}");
        assert_eq!(post_ids(&rows, &format!("{name}(risk_score, 50) = 50")), vec![1], "{name}");
    }
    for name in ["min", "MIN"] {
        assert_eq!(post_ids(&rows, &format!("{name}(risk_score, 50) < 20")), vec![1], "{name}");
        assert_eq!(post_ids(&rows, &format!("{name}(risk_score, 50) = 50")), vec![0], "{name}");
    }
}

#[test]
fn dayofweek_matches_clickhouse_to_day_of_week_in_any_case() {
    // SQL emits toDayOfWeek(ts): Monday = 1 … Sunday = 7.
    // 2026-11-01 is a Sunday, 2026-11-02 a Monday.
    let rows = vec![
        json!({"row_id": 0, "timestamp": "2026-11-01T12:00:00Z"}),
        json!({"row_id": 1, "timestamp": "2026-11-02T12:00:00Z"}),
    ];
    assert_eq!(post_ids(&rows, "dayofweek(timestamp) = 7"), vec![0]);
    assert_eq!(post_ids(&rows, "DAYOFWEEK(timestamp) = 1"), vec![1]);
    assert_eq!(post_ids(&rows, "NOT dayofweek(timestamp) = 1"), vec![0]);
}

// ------------------------------------------------- r2: computed predicates

fn numeric_rows() -> Vec<Value> {
    vec![
        json!({"row_id": 0, "message": "abcd", "risk_score": 10, "delta": -5}),
        json!({"row_id": 1, "message": "ab", "risk_score": 3, "delta": -5}),
        json!({"row_id": 2, "message": "abcdef", "risk_score": 90, "delta": 100}),
    ]
}

#[test]
fn eval_predicate_uses_the_full_function_engine_positive_and_negated() {
    let rows = numeric_rows();
    assert_positive_and_negated(&rows, "(len(message) + 0) > 3", &[0, 2]);
    assert_positive_and_negated(&rows, "(abs(delta) * 2) >= 10", &[0, 1, 2]);
    assert_positive_and_negated(&rows, "(LEN(message) - abs(delta)) < -2", &[1, 2]);
    // Integer row values compare equal to float arithmetic results.
    assert_positive_and_negated(&rows, "(risk_score + 0) = 90", &[2]);
}

#[test]
fn field_function_filter_rhs_uses_the_full_function_engine_positive_and_negated() {
    let rows = numeric_rows();
    assert_positive_and_negated(&rows, "risk_score > abs(delta)", &[0]);
    assert_positive_and_negated(&rows, "risk_score >= (abs(delta) - 2)", &[0, 1]);
    assert_positive_and_negated(&rows, "risk_score < max(delta, 5)", &[1, 2]);
}

#[test]
fn field_function_filter_keeps_datetime_comparisons() {
    let rows = vec![
        json!({"row_id": 0, "first_seen": "2020-01-01T00:00:00Z"}),
        json!({"row_id": 1, "first_seen": "2999-01-01T00:00:00Z"}),
    ];
    assert_positive_and_negated(&rows, "first_seen < now()", &[0]);
    assert_positive_and_negated(&rows, "first_seen < now() - INTERVAL 1 DAY", &[0]);
}

#[test]
fn unsupported_functions_in_computed_predicates_are_query_errors() {
    let rows = numeric_rows();
    for predicate in [
        "(nosuchfn(message) + 0) > 3",
        "NOT (nosuchfn(message) + 0) > 3",
        "risk_score > nosuchfn(delta)",
        "NOT risk_score > nosuchfn(delta)",
        "(len(message, 2) + 0) > 3",
        "risk_score > abs(delta, 1)",
    ] {
        assert!(post_err(&rows, predicate), "{predicate}");
        assert!(post_err(&[], predicate), "{predicate} on an empty page");
    }
}

// ------------------------------------------------------------ r2: arity

#[test]
fn wrong_arity_is_a_query_error_positive_negated_and_on_an_empty_page() {
    let rows = ip_rows();
    let mut checked = 0;
    for call in [
        "is_private_ip()", "is_public_ip()", "is_loopback()", "isnull()", "isnotnull()",
        "is_private_ip(src_ip, src_ip)", "isnull(src_ip, src_ip)",
        "match(src_ip)", "like(src_ip)", "cidr_match(src_ip)", "has(src_ip)",
        "max() = 1", "min() = 1", "lower() = \"x\"", "if(src_ip, 1) = 1", "tostring(src_ip, \"%H\") = \"x\"",
        "round(src_ip, 1, 2) = 1", "dayofweek() = 1", "now(src_ip) = 1",
    ] {
        // Some empty-argument spellings are already rejected by the parser,
        // which is also a query error; only parseable ones reach the validator.
        if parse_query(&format!("* | where {call}")).is_err() {
            continue;
        }
        checked += 1;
        for predicate in [call.to_string(), format!("NOT {call}")] {
            assert!(post_err(&rows, &predicate), "{predicate}");
            assert!(post_err(&[], &predicate), "{predicate} on an empty page");
        }
    }
    assert!(checked >= 12, "only {checked} arity cases reached the validator");
}
