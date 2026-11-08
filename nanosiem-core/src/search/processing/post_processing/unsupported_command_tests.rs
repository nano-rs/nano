// SPDX-License-Identifier: AGPL-3.0-or-later
//! NAN-3311 (ported to clickhouse/dev, NAN-4933): a command after a Nano-side
//! stage (prevalence, lookup, inputlookup, lateral, ai) that the in-memory
//! evaluator cannot run is refused as a query error. On dev it hit the `_` arm,
//! logged a warning and was DROPPED: `| prevalence … | streamstats count as n`
//! answered 200 with rows that had no `n`. `reverse` now runs.
use super::apply_post_prevalence_commands;
use crate::query::{parse_query, Command, Query};
use serde_json::{json, Value};

fn suffix(pipeline: &str) -> Vec<Command> {
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

fn rows() -> Vec<Value> {
    vec![json!({"time": 3}), json!({"time": 2}), json!({"time": 1})]
}

#[test]
fn unsupported_suffix_command_is_refused_not_skipped() {
    for pipeline in [
        "streamstats count as n | table time, n",
        "eventstats count",
        "bin span=1h",
        "mvexpand x",
    ] {
        let error = apply_post_prevalence_commands(rows(), &suffix(pipeline))
            .err()
            .unwrap_or_else(|| panic!("{pipeline}: dropped silently"));
        assert!(error.to_string().contains("cannot run after"), "{pipeline}: {error}");
    }
}

#[test]
fn reverse_runs_and_caller_dispatched_stages_stay_accepted() {
    let out = apply_post_prevalence_commands(rows(), &suffix("reverse | table time")).unwrap().results;
    assert_eq!(out, vec![json!({"time": 1}), json!({"time": 2}), json!({"time": 3})]);
    assert!(apply_post_prevalence_commands(rows(), &suffix("prevalence enrich=true | head 1")).is_ok());
}
