// SPDX-License-Identifier: AGPL-3.0-or-later
//! NAN-4285: Nano-side `| where` (after `| prevalence` / `| risk`) treats a
//! CIDR in an IN-list or in `=` / `!=` as network membership, like the SQL
//! path; `NOT IN` / `!=` only match a row that carries an IP.
use super::condition::evaluate_condition_on_json;
use crate::query::{Comparator, SearchExpr, Value};
use serde_json::json;

fn list(values: &[&str], negated: bool) -> SearchExpr {
    SearchExpr::InList {
        field: "dst_endpoint.ip".into(),
        values: values.iter().map(|v| Value::String(v.to_string())).collect(),
        negated,
    }
}

fn row(ip: &str) -> serde_json::Value {
    json!({"dst_endpoint": {"ip": ip}})
}

#[test]
fn in_list_cidr_entries_are_network_membership() {
    let private = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"];
    assert!(evaluate_condition_on_json(&list(&private, false), &row("10.1.2.3")));
    assert!(!evaluate_condition_on_json(&list(&private, false), &row("8.8.8.8")));
    assert!(evaluate_condition_on_json(&list(&private, true), &row("8.8.8.8")));
    assert!(!evaluate_condition_on_json(&list(&private, true), &row("192.168.4.4")));
    // Mixed exact + CIDR, IPv6.
    let mixed = ["8.8.8.8", "fe80::/10"];
    assert!(evaluate_condition_on_json(&list(&mixed, false), &row("8.8.8.8")));
    assert!(evaluate_condition_on_json(&list(&mixed, false), &row("fe80::1")));
    assert!(!evaluate_condition_on_json(&list(&mixed, false), &row("2001:db8::1")));
    // NOT IN requires the field, like the SQL presence rule.
    assert!(!evaluate_condition_on_json(&list(&private, true), &json!({})));
    assert!(!evaluate_condition_on_json(&list(&private, true), &row("")));
}

#[test]
fn cidr_equality_is_network_membership() {
    let filter = |op: Comparator| SearchExpr::FieldFilter {
        field: "dst_endpoint.ip".into(),
        op,
        value: Value::String("10.0.0.0/8".into()),
    };
    assert!(evaluate_condition_on_json(&filter(Comparator::Eq), &row("10.9.9.9")));
    assert!(!evaluate_condition_on_json(&filter(Comparator::Eq), &row("11.0.0.1")));
    assert!(evaluate_condition_on_json(&filter(Comparator::Ne), &row("11.0.0.1")));
    assert!(!evaluate_condition_on_json(&filter(Comparator::Ne), &row("10.9.9.9")));
}

/// NAN-4285 review: a slash-containing literal that is not a CIDR (a URL or
/// a path) keeps exact IN / NOT IN / = semantics, as the SQL path does for a
/// non-IP field -- e.g. a prevalence-backed `where url IN ("https://…")`.
#[test]
fn url_and_path_literals_keep_exact_semantics() {
    let url_list = |negated| SearchExpr::InList {
        field: "url".into(),
        values: vec![Value::String("https://example.test/a".into())],
        negated,
    };
    let hit = json!({"url": "https://example.test/a", "_prevalence": {"host_count": 1}});
    let miss = json!({"url": "https://example.test/b"});
    assert!(evaluate_condition_on_json(&url_list(false), &hit));
    assert!(!evaluate_condition_on_json(&url_list(false), &miss));
    assert!(!evaluate_condition_on_json(&url_list(true), &hit));
    assert!(evaluate_condition_on_json(&url_list(true), &miss));
    // A missing field is still NOT IN a non-CIDR list.
    assert!(evaluate_condition_on_json(&url_list(true), &json!({})));
    // The same predicate a prevalence-backed rule leaves Nano-side.
    let rule = SearchExpr::And(
        Box::new(SearchExpr::FieldFilter {
            field: "_prevalence.host_count".into(),
            op: Comparator::Lt,
            value: Value::Number(3.0),
        }),
        Box::new(url_list(false)),
    );
    assert!(evaluate_condition_on_json(&rule, &hit));
    // `=` with a path literal is equality.
    let path_eq = SearchExpr::FieldFilter {
        field: "file_path".into(),
        op: Comparator::Eq,
        value: Value::String("/var/tmp".into()),
    };
    assert!(evaluate_condition_on_json(&path_eq, &json!({"file_path": "/var/tmp"})));
    // A CIDR literal against a non-IP value is not membership.
    assert!(!evaluate_condition_on_json(&list(&["10.0.0.0/8"], false), &row("not-an-ip")));
}
