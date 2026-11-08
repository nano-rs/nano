// SPDX-License-Identifier: AGPL-3.0-or-later
//! NAN-4902 lane I: the post-stage evaluator implements eval `NOT` with
//! ClickHouse semantics (rules put it after `| prevalence`, so it runs in Rust).
use super::eval::evaluate_eval_expression;
use crate::query::parse_query;
use crate::query::{Command, EvalExpression, Query};
use serde_json::{json, Map, Value as J};

fn expr(src: &str) -> EvalExpression {
    match parse_query(&format!("* | eval x={src}")).unwrap() {
        Query::Piped { command: Command::Eval { assignments }, .. } => assignments[0].expression.clone(),
        other => panic!("{other:?}"),
    }
}

fn eval(src: &str, row: J) -> Option<J> {
    let row: Map<String, J> = row.as_object().cloned().unwrap();
    evaluate_eval_expression(&expr(src), &row)
}

#[test]
fn not_negates_booleans_and_numbers_like_clickhouse() {
    assert_eq!(eval("NOT a", json!({"a": true})), Some(json!(false)));
    assert_eq!(eval("NOT a", json!({"a": false})), Some(json!(true)));
    // ClickHouse: NOT 0 = 1, NOT 5 = 0.
    assert_eq!(eval("NOT a", json!({"a": 0})), Some(json!(true)));
    assert_eq!(eval("NOT a", json!({"a": 5})), Some(json!(false)));
    assert_eq!(eval("NOT NOT a", json!({"a": 5})), Some(json!(true)));
}

#[test]
fn not_null_is_null() {
    assert_eq!(eval("NOT a", json!({})), None);
    assert_eq!(eval("NOT a", json!({"a": null})), None);
    // A string operand is a ClickHouse type error, never a silent true/false.
    assert_eq!(eval("NOT a", json!({"a": "yes"})), None);
}

#[test]
fn content_rule_non_standard_port_expression() {
    let src = "(NOT has(dst_ports, 80) AND NOT has(dst_ports, 443) AND NOT has(dst_ports, 53))";
    assert_eq!(eval(src, json!({"dst_ports": [3389, 22]})), Some(json!(true)));
    // Numeric literal needles match integer array items (443.0 renders "443").
    assert_eq!(eval(src, json!({"dst_ports": [443]})), Some(json!(false)));
    assert_eq!(eval(src, json!({"dst_ports": [22, 53]})), Some(json!(false)));
    let risk = "if(esc, 35, 0)";
    let esc = eval(src, json!({"dst_ports": [22]})).unwrap();
    assert_eq!(eval(risk, json!({"esc": esc})), Some(json!(35.0)));
}
