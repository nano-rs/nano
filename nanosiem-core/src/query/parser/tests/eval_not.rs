// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-4902 lane I: unary `NOT` inside `eval` expressions.
//!
//! The OCSF content rule `execution-ocsf/rare_process_network_activity.yml`
//! writes `eval esc=(NOT has(dst_ports, 80) AND NOT has(dst_ports, 443))`;
//! the eval grammar had no `NOT`, so the rule failed to parse. `NOT` now lowers
//! to `not(expr)`, binding like SQL (looser than comparison, tighter than AND).

use crate::query::{
    parse_query, BinaryOperator, ClickHouseSqlGenerator, Command, EvalExpression, PrettyPrint,
    Query, TimeRange, Value,
};

fn tr() -> TimeRange {
    TimeRange {
        start: "2024-01-01T00:00:00Z".parse().unwrap(),
        end: "2024-01-02T00:00:00Z".parse().unwrap(),
    }
}

/// The expression of the first eval assignment in `npl`.
fn eval_expr(npl: &str) -> EvalExpression {
    let parsed = parse_query(npl).unwrap_or_else(|e| panic!("{npl} must parse: {e:?}"));
    fn find(q: &Query) -> Option<EvalExpression> {
        match q {
            Query::Piped { source, command } => match command {
                Command::Eval { assignments } => Some(assignments[0].expression.clone()),
                _ => find(source),
            },
            Query::Search(_) => None,
        }
    }
    find(&parsed).unwrap_or_else(|| panic!("no eval in {npl}"))
}

fn not(e: EvalExpression) -> EvalExpression {
    EvalExpression::FunctionCall { name: "not".into(), args: vec![e] }
}
fn field(f: &str) -> EvalExpression {
    EvalExpression::Field(f.into())
}
fn num(n: f64) -> EvalExpression {
    EvalExpression::Literal(Value::Number(n))
}
fn has(f: &str, n: f64) -> EvalExpression {
    EvalExpression::FunctionCall { name: "has".into(), args: vec![field(f), num(n)] }
}
fn bin(l: EvalExpression, op: BinaryOperator, r: EvalExpression) -> EvalExpression {
    EvalExpression::BinaryOp { left: Box::new(l), op, right: Box::new(r) }
}

#[test]
fn content_rule_eval_parses_with_sql_precedence() {
    let got = eval_expr(
        "* | eval esc=(NOT has(dst_ports, 80) AND NOT has(dst_ports, 443) AND NOT has(dst_ports, 53))",
    );
    let want = bin(
        bin(not(has("dst_ports", 80.0)), BinaryOperator::And, not(has("dst_ports", 443.0))),
        BinaryOperator::And,
        not(has("dst_ports", 53.0)),
    );
    assert_eq!(got, want);
}

#[test]
fn not_binds_looser_than_comparison_and_tighter_than_and_or() {
    assert_eq!(
        eval_expr("* | eval x=NOT a = 1"),
        not(bin(field("a"), BinaryOperator::Eq, num(1.0)))
    );
    assert_eq!(
        eval_expr("* | eval x=NOT a OR b"),
        bin(not(field("a")), BinaryOperator::Or, field("b"))
    );
    assert_eq!(
        eval_expr("* | eval x=a AND NOT (b OR c)"),
        bin(field("a"), BinaryOperator::And, not(bin(field("b"), BinaryOperator::Or, field("c"))))
    );
    assert_eq!(eval_expr("* | eval x=not not a"), not(not(field("a"))));
}

#[test]
fn keyword_needs_a_separator_so_not_prefixed_fields_still_parse() {
    assert_eq!(eval_expr("* | eval x=notes"), field("notes"));
    assert_eq!(eval_expr("* | eval x=not_flag"), field("not_flag"));
    assert_eq!(eval_expr("* | eval x=NOT(a)"), not(field("a")));
    assert_eq!(eval_expr("* | eval x=not(a)"), not(field("a")));
}

#[test]
fn not_inside_if_and_other_function_arguments() {
    assert_eq!(
        eval_expr("* | eval x=if(NOT is_private_ip(dst_ip), 1, 0)"),
        EvalExpression::FunctionCall {
            name: "if".into(),
            args: vec![
                not(EvalExpression::FunctionCall {
                    name: "is_private_ip".into(),
                    args: vec![field("dst_ip")],
                }),
                num(1.0),
                num(0.0),
            ],
        }
    );
}

#[test]
fn sql_emits_three_valued_clickhouse_not() {
    let q = parse_query("* | eval x=NOT (bytes_in > 10) AND NOT isnull(user) | table x").unwrap();
    let sql = ClickHouseSqlGenerator::new().generate(&q, &tr()).unwrap();
    assert!(sql.contains("(NOT (toFloat64OrNull("), "{sql}");
    assert!(sql.contains("(NOT isNull("), "{sql}");
}

#[test]
fn pretty_print_round_trips() {
    let q = parse_query("* | eval x=NOT a = 1 AND NOT has(p, 80)").unwrap();
    let again = parse_query(&q.pretty_print()).unwrap();
    assert_eq!(q, again, "{}", q.pretty_print());
}

#[test]
fn deep_not_chains_are_refused_not_crashed() {
    // Each NOT is one function-nesting level; the NAN-4917 budget refuses the
    // chain with a query error rather than letting it reach a recursive walk.
    let npl = format!("* | eval x={}a", "NOT ".repeat(500));
    assert!(parse_query(&npl).is_err());
    // A handful is fine.
    let npl = format!("* | eval x={}a", "NOT ".repeat(5));
    assert!(parse_query(&npl).is_ok());
}
