// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-2373 — a stage that DECLARES output columns must actually produce them.
//!
//! The lake `| prevalence` defect was not a crash and not a wrong number: the
//! command ran, returned 200, and emitted none of its output columns. The
//! downstream `| where host_count < 10` then compared against a column that did
//! not exist and dropped every row. A detection rule of that shape reports
//! healthy, never errors, and can never fire — strictly worse than one that
//! fails loudly, because nothing surfaces it.
//!
//! This module closes the class from both ends:
//!
//! * **Static** ([`validate_declared_output_column_references`]) — a filter that
//!   thresholds on a decoration-owned column (`host_count`, `ai_verdict`, …)
//!   that NO upstream stage produces is a query error, not an empty result set.
//! * **Runtime** ([`missing_declared_columns`]) — after a Nano-side decoration
//!   stage executes, its declared columns are checked against the rows it
//!   actually returned. Columns that never materialized raise a response
//!   warning naming the stage, so "0 rows" can never again be
//!   indistinguishable from "the column was never there".
//!
//! Scope is deliberately narrow to avoid rejecting valid queries, which would
//! be worse than the bug: only columns that exist *solely* because a Nano-side
//! decoration stage writes them are policed. Every dynamically produced name —
//! `stats … as foo`, `eval foo=…`, `rex` captures, `rename`, `lookup … OUTPUT`,
//! bin/spath/table aliases — is resolved through the shared
//! [`crate::query::collect_derived_fields`] contract, and any stage whose output
//! schema is only known at runtime (`inputlookup`, an un-projected `lookup`)
//! disables the static check entirely.

use crate::query::{Command, EvalExpression, Query, SearchExpr};
use crate::search::SearchError;

/// Mirror of `query::validation::derived_fields::DYNAMIC_PIPELINE_SCHEMA` (that
/// constant is crate-internal to the validation module). It marks a pipeline
/// whose output schema is only known at runtime, where no static claim about
/// produced columns is possible.
const DYNAMIC_PIPELINE_SCHEMA: &str = "__nano_dynamic_pipeline_schema__";

/// Columns that exist ONLY because a Nano-side decoration stage writes them
/// onto the row after the storage engine has returned it. None of these is a
/// column of any schema profile, so a reference to one is meaningful only when
/// an upstream stage produced it.
///
/// Keep in lock-step with [`declared_output_columns`] — that function says which
/// stage produces which name; this list says which names are policed at all.
const DECORATION_OUTPUT_COLUMNS: &[&str] = &[
    // `| prevalence enrich=true`
    "host_count",
    "is_rare",
    "prevalence_score",
    "prevalence_type",
    "prevalence_artifact",
    "prevalence_first_seen",
    "prevalence_last_seen",
    // `| ai`
    "ai_verdict",
    "ai_confidence",
    "ai_reasoning",
];

/// The output columns a Nano-side decoration stage promises to write.
///
/// `total_occurrences` / `first_seen` / `last_seen` are deliberately absent:
/// prevalence writes them, but they are also plausible aggregation aliases and
/// real event fields, so policing them buys nothing and risks a false positive.
pub(crate) fn declared_output_columns(command: &Command) -> Option<(&'static str, Vec<String>)> {
    let owned = |names: &[&str]| names.iter().map(|name| (*name).to_string()).collect();
    match command {
        Command::Prevalence { enrich: true, .. } => Some((
            "prevalence",
            owned(&[
                "host_count",
                "is_rare",
                "prevalence_score",
                "prevalence_type",
                "prevalence_artifact",
            ]),
        )),
        Command::Ai { .. } => Some((
            "ai",
            owned(&["ai_verdict", "ai_confidence", "ai_reasoning"]),
        )),
        Command::Lookup {
            output_fields: Some(fields),
            output_renames,
            ..
        } if !fields.is_empty() => Some((
            "lookup",
            fields
                .iter()
                .map(|field| {
                    output_renames
                        .iter()
                        .find(|r| &r.from == field)
                        .map_or(field, |r| &r.to)
                        .clone()
                })
                .collect(),
        )),
        _ => None,
    }
}

/// Whether a result row carries `column`, flat or as a nested path. Mirrors the
/// result-row access the decoration stages themselves use: ClickHouse rows are
/// keyed by SELECT alias (flat, dots and all), primary-lake rows are native
/// nested OCSF JSON.
pub(crate) fn row_has_column(row: &serde_json::Value, column: &str) -> bool {
    if row.get(column).is_some_and(|value| !value.is_null()) {
        return true;
    }
    if !column.contains('.') {
        return false;
    }
    let mut current = row;
    for segment in column.split('.') {
        match current.get(segment) {
            Some(value) => current = value,
            None => return false,
        }
    }
    !current.is_null()
}

/// Declared columns that no row carries. An empty result set yields nothing —
/// there is no row to inspect, so there is no claim to check.
pub(crate) fn missing_declared_columns(
    results: &[serde_json::Value],
    declared: &[String],
) -> Vec<String> {
    if results.is_empty() {
        return Vec::new();
    }
    declared
        .iter()
        .filter(|column| !results.iter().any(|row| row_has_column(row, column)))
        .cloned()
        .collect()
}

/// The warning text for a stage whose declared columns never materialized.
pub(crate) fn missing_output_column_warning(stage: &str, missing: &[String]) -> String {
    format!(
        "`{stage}` produced no value for {} on any returned row. Downstream filters or displays referencing {} see a column that does not exist — a threshold on it matches nothing.",
        missing
            .iter()
            .map(|column| format!("`{column}`"))
            .collect::<Vec<_>>()
            .join(", "),
        if missing.len() == 1 { "it" } else { "them" }
    )
}

/// Static half: reject a filter that thresholds on a decoration-owned column no
/// upstream stage produces.
///
/// `| where host_count < 10` with no `| prevalence enrich=true` ahead of it is
/// today indistinguishable from a legitimate zero-match query. It is not one: it
/// can never match. Runs on every search path through
/// [`super::validate_query_field_names`].
pub(crate) fn validate_declared_output_column_references(query: &Query) -> Result<(), SearchError> {
    let mut node = query;
    while let Query::Piped { source, command } = node {
        if let Command::Where { condition } = command {
            let mut referenced = Vec::new();
            collect_search_expr_fields(condition, &mut referenced);
            // The prefix IS the upstream pipeline, so the shared derived-field
            // contract answers "did anything upstream produce this name?" for
            // every dynamic producer at once.
            let mut produced = crate::query::collect_derived_fields(source);
            // `collect_derived_fields` is the shared contract for SQL/in-memory
            // producers, but it does not know every Nano-side decoration stage
            // (`| ai` registers nothing there). Union this module's own
            // declarations so the guard never contradicts them.
            collect_declared_output_columns(source, &mut produced);
            if produced.contains(DYNAMIC_PIPELINE_SCHEMA) {
                // A runtime-loaded output schema (inputlookup / un-projected
                // lookup) can supply any name. No static claim is possible.
                node = source;
                continue;
            }
            for field in referenced {
                let lowered = field.to_ascii_lowercase();
                if DECORATION_OUTPUT_COLUMNS.contains(&lowered.as_str())
                    && !produced.contains(&lowered)
                {
                    return Err(SearchError::SqlValidationError(format!(
                        "`where {field}` filters on `{field}`, but no earlier stage in this pipeline produces it. `{field}` only exists after the stage that writes it (for example `| prevalence enrich=true` for prevalence columns, `| ai` for AI columns); without that stage the filter can never match."
                    )));
                }
            }
        }
        node = source;
    }
    Ok(())
}

/// Union every decoration stage's declared columns from `query` (a pipeline
/// prefix) into `produced`, lowercased to match the derived-field contract.
fn collect_declared_output_columns(
    query: &Query,
    produced: &mut std::collections::HashSet<String>,
) {
    let mut node = query;
    while let Query::Piped { source, command } = node {
        if let Some((_, columns)) = declared_output_columns(command) {
            produced.extend(
                columns
                    .into_iter()
                    .map(|column| column.to_ascii_lowercase()),
            );
        }
        node = source;
    }
}

fn collect_search_expr_fields(expr: &SearchExpr, fields: &mut Vec<String>) {
    match expr {
        SearchExpr::FieldFilter { field, .. }
        | SearchExpr::FieldFunctionFilter { field, .. }
        | SearchExpr::InList { field, .. } => fields.push(field.clone()),
        SearchExpr::And(left, right) | SearchExpr::Or(left, right) => {
            collect_search_expr_fields(left, fields);
            collect_search_expr_fields(right, fields);
        }
        SearchExpr::Not(inner) | SearchExpr::Group(inner) => {
            collect_search_expr_fields(inner, fields)
        }
        SearchExpr::EvalPredicate(expression) | SearchExpr::BooleanFunction(expression) => {
            collect_eval_expr_fields(expression, fields)
        }
        SearchExpr::FunctionFilter { function, .. } => collect_eval_expr_fields(function, fields),
        SearchExpr::Keyword(_)
        | SearchExpr::LiteralComparison { .. }
        | SearchExpr::InSubsearch { .. }
        | SearchExpr::IocMatch { .. } => {}
    }
}

fn collect_eval_expr_fields(expr: &EvalExpression, fields: &mut Vec<String>) {
    match expr {
        EvalExpression::Field(field) => fields.push(field.clone()),
        EvalExpression::Literal(_) => {}
        EvalExpression::FunctionCall { args, .. } => {
            if let Some(search) = crate::query::searchmatch_search_expr(expr) {
                collect_search_expr_fields(&search, fields);
                return;
            }
            for arg in args {
                collect_eval_expr_fields(arg, fields);
            }
        }
        EvalExpression::BinaryOp { left, right, .. } => {
            collect_eval_expr_fields(left, fields);
            collect_eval_expr_fields(right, fields);
        }
    }
}

#[cfg(test)]
mod tests;
