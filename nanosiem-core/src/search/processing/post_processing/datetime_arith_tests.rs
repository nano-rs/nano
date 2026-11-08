// SPDX-License-Identifier: AGPL-3.0-or-later
//! NAN-3329 (ported to clickhouse/dev, NAN-4933): after a Nano-side stage
//! (prevalence, lookup, identity, ai) `eval age=now()-timestamp` runs here.
//! `now()` and the time column are datetime text, so on dev the subtraction
//! was NULL. They are epoch seconds now, as in the SQL generator.
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
fn now_minus_time_is_whole_seconds() {
    let row = json!({"timestamp": "2026-10-01 00:10:00.500", "other": "2026-10-01 00:09:00.000"});
    let age = eval("now()-timestamp", row.clone()).expect("not NULL").as_i64().expect("integer");
    assert!(age > 0, "{age}");
    assert_eq!(eval("timestamp-timestamp", row.clone()), Some(json!(0)));
    assert_eq!(eval("timestamp+60", row.clone()), Some(json!(1_790_813_460.5)));
    assert_eq!(eval("if(now() > timestamp, 1, 0)", row.clone()), Some(json!(1.0)));
    // Any other text field is not a datetime operand.
    assert_eq!(eval("other-1", row), None);
}
