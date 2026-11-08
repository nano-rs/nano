// SPDX-License-Identifier: AGPL-3.0-or-later
//! NAN-4917: the in-memory post-processing evaluator recurses once per
//! expression level. Every tree the parser + complexity budget admits must
//! evaluate on a small stack (a stack overflow aborts the whole search
//! process — it cannot be caught).
use super::condition::{evaluate_condition_on_json, evaluate_expression_on_json};
use super::eval::evaluate_eval_expression;
use crate::query::{parse_query, Command, Query};
use serde_json::json;

fn on_small_stack(f: impl FnOnce() + Send + 'static) {
    std::thread::Builder::new()
        .stack_size(256 * 1024)
        .spawn(f)
        .unwrap()
        .join()
        .unwrap();
}

#[test]
fn admitted_worst_case_trees_evaluate_on_small_stack() {
    on_small_stack(|| {
        let and_chain: Vec<String> = (0..1024).map(|i| format!("src_port>{i}")).collect();
        let plus_chain = vec!["src_port"; 1024].join(" + ");
        let mut nested_if = "src_ip".to_string();
        for _ in 0..49 {
            nested_if = format!("if(src_port>1, {nested_if}, \"a\")");
        }
        let mut nested_paren = "src_port=1".to_string();
        for _ in 0..48 {
            nested_paren = format!("({nested_paren} OR src_port=2)");
        }
        let queries = [
            format!("* | where {}", and_chain.join(" AND ")),
            format!("* | eval x={plus_chain} | where x > 3"),
            format!("* | eval x={nested_if}"),
            format!("* | where {nested_paren}"),
        ];
        let row = json!({"src_port": 5, "src_ip": "10.0.0.1"});
        let row_map = row.as_object().unwrap().clone();
        for q in queries {
            let mut cur = parse_query(&q).unwrap_or_else(|e| panic!("{e:?}"));
            loop {
                match cur {
                    Query::Search(expr) => {
                        evaluate_condition_on_json(&expr, &row);
                        break;
                    }
                    Query::Piped { source, command } => {
                        match command {
                            Command::Where { condition } => {
                                evaluate_condition_on_json(&condition, &row);
                            }
                            Command::Eval { assignments } => {
                                for a in assignments {
                                    evaluate_expression_on_json(&a.expression, &row);
                                    evaluate_eval_expression(&a.expression, &row_map);
                                }
                            }
                            _ => {}
                        }
                        cur = *source;
                    }
                }
            }
        }
    });
}
