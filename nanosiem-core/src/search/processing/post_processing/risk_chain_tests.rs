// SPDX-License-Identifier: AGPL-3.0-or-later
//! NAN-3055 (ported to clickhouse/dev, NAN-4933): a Nano-side `| risk` pipe
//! (after `| prevalence` / lookup) has the SQL generator's RBA semantics. On
//! dev it overwrote the score, reset the entity to `unknown` and dropped the
//! earlier factors, so `… | prevalence … | risk score=5` erased the SQL-side
//! `| risk score=10 entity=user` that ran before it.
use super::apply_post_prevalence_commands;
use crate::query::{parse_query, Command, Query};
use serde_json::{json, Value};

fn commands(pipeline: &str) -> Vec<Command> {
    fn collect(query: &Query, out: &mut Vec<Command>) {
        if let Query::Piped { source, command } = query {
            collect(source, out);
            out.push(command.clone());
        }
    }
    let mut out = Vec::new();
    collect(&parse_query(&format!("* | {pipeline}")).unwrap(), &mut out);
    out
}

fn run(rows: Vec<Value>, pipeline: &str) -> Vec<Value> {
    apply_post_prevalence_commands(rows, &commands(pipeline)).unwrap().results
}

#[test]
fn chained_nano_side_risk_pipes_are_one_risk_object() {
    let out = run(
        vec![json!({"user": "alice"})],
        r#"risk score=10 entity=user factor="a" | risk score=5 factor="b""#,
    );
    let row = &out[0];
    assert_eq!(row["risk_score"], json!(15));
    assert_eq!(row["raw_risk_score"], json!(15));
    assert_eq!(row["risk_entity"], json!("alice"));
    assert_eq!(row["risk_factors"], json!(["a", "b"]));
}

#[test]
fn a_nano_side_risk_pipe_accumulates_onto_a_sql_side_one() {
    // The columns an SQL-side `| risk score=10 entity=user factor="a"` left.
    let row = json!({"user": "alice", "risk_score": 10, "raw_risk_score": 10,
                     "risk_entity": "alice", "risk_factors": ["a"]});
    let out = run(vec![row], r#"risk score=95 factor="b""#);
    assert_eq!(out[0]["risk_score"], json!(100), "clamped at 100");
    assert_eq!(out[0]["risk_entity"], json!("alice"));
    assert_eq!(out[0]["risk_factors"], json!(["a", "b"]));
}

#[test]
fn a_first_pipe_without_entity_is_unknown() {
    let out = run(vec![json!({"user": "alice"})], "risk score=7");
    assert_eq!(out[0]["risk_entity"], json!("unknown"));
    assert_eq!(out[0]["risk_score"], json!(7));
    assert_eq!(out[0]["risk_factors"], json!(["risk_assigned"]));
}
