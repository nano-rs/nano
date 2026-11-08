// SPDX-License-Identifier: AGPL-3.0-or-later
//! NAN-3041 (ported to clickhouse/dev, NAN-4933): eval / if() predicates after a
//! Nano-side stage mean what they mean in `| where` and in the SQL generator:
//! `f=/re/` is a case-insensitive regex match, `f="x"` a case-insensitive string
//! compare, `f IN (…)` / `in(f, …)` membership. Before, the regex literal was
//! compared to the field as plain text (never matched), `="x"` was exact case,
//! and `in` was not a capability.
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

fn eval(src: &str) -> Option<J> {
    let row: Map<String, J> = json!({"p": "MicrosoftEdgeUpdate.exe", "port": 443}).as_object().cloned().unwrap();
    evaluate_eval_expression(&expr(src), &row)
}

#[test]
fn regex_string_and_in_predicates_match_the_sql_semantics() {
    let one = Some(json!(1.0));
    let zero = Some(json!(0.0));
    for (src, want) in [
        (r#"if(p=/edge.*update/i, 1, 0)"#, &one),
        (r#"if(p=/EDGE/, 1, 0)"#, &one),
        (r#"if(p!=/edge/, 1, 0)"#, &zero),
        (r#"if(p CONTAINS "EDGEUPDATE", 1, 0)"#, &one),
        (r#"if(p IN ("microsoftedgeupdate.exe", "b"), 1, 0)"#, &one),
        (r#"if(in(port, 80, 443), 1, 0)"#, &one),
        (r#"if(p NOT IN ("a"), 1, 0)"#, &one),
        (r#"if(NOT p="MicrosoftEdgeUpdate.exe", 1, 0)"#, &zero),
        (r#"if(p="MICROSOFTEDGEUPDATE.EXE", 1, 0)"#, &one),
        (r#"if(p!="microsoftedgeupdate.exe", 1, 0)"#, &zero),
        (r#"if(port="443", 1, 0)"#, &one),
        (r#"if(like(p, "%edge%"), 1, 0)"#, &one),
    ] {
        assert_eq!(&eval(src), want, "{src}");
    }
}

#[test]
fn a_missing_subject_is_null_like_clickhouse() {
    // `if(NULL, a, b)` is b in ClickHouse; the predicate itself is NULL.
    assert_eq!(eval(r#"missing IN ("a")"#), None);
    assert_eq!(eval(r#"missing="a""#), None);
    assert_eq!(eval(r#"missing=/a/"#), None);
}
