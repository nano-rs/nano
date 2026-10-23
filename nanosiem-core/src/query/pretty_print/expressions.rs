// SPDX-License-Identifier: AGPL-3.0-or-later

//! Pretty-print implementations for eval expressions and aggregations.

use super::super::ast::*;
use super::PrettyPrint;

impl PrettyPrint for EvalExpression {
    fn pretty_print(&self) -> String {
        match self {
            EvalExpression::Field(name) => name.clone(),
            EvalExpression::Literal(value) => {
                // Always quote string literals to distinguish from field names.
                // NAN-2006: never emit the no-op `\"` escape (the parser has no
                // working backslash escape, NAN-1157) — `npl_quoted_literal`
                // picks a delimiter the literal cannot terminate, so an eval
                // literal cannot break out of the gate's pretty_print ->
                // re-parse round-trip.
                match value {
                    Value::String(s) => super::helpers::npl_quoted_literal(s),
                    _ => value.to_string(),
                }
            }
            EvalExpression::BinaryOp { left, op, right } => {
                format!(
                    "{} {} {}",
                    left.pretty_print(),
                    op.as_str(),
                    right.pretty_print()
                )
            }
            EvalExpression::FunctionCall { name, args } => {
                let arg_strs = args
                    .iter()
                    .map(|a| a.pretty_print())
                    .collect::<Vec<_>>()
                    .join(", ");
                format!("{}({})", name, arg_strs)
            }
        }
    }
}

impl PrettyPrint for Aggregation {
    fn pretty_print(&self) -> String {
        let field_str = if let Some(expr) = &self.field_expr {
            expr.pretty_print()
        } else {
            self.field.as_deref().unwrap_or("").to_string()
        };

        // Handle percentile specially since it has a parameter
        let base = match self.func {
            AggFunc::Percentile(pct) => format!("percentile({}, {})", field_str, pct),
            // NAN-1528: histogram_quantile carries a percentile arg too; emit it
            // so the query round-trips (parser expects `histogram_quantile(f, N)`).
            AggFunc::HistogramQuantile(pct) => {
                format!("histogram_quantile({}, {})", field_str, pct)
            }
            // NAN-2361: a CONDITIONAL aggregation must round-trip its predicate.
            //
            // This printed `func(field)` and dropped `condition` entirely, so
            // `count(eval(<predicate>))` serialized back to a bare `count()`.
            // That is not cosmetic: the lake path pretty-prints the AST to nPL
            // and sends THAT to the worker, so the predicate never reached
            // storage and every conditional aggregate silently returned the
            // unconditional result. Measured live on 2,345 proxy events,
            // `count(eval(query.hostname=<value>))` returned 2,345 for a column
            // NULL on all of them — the worker was correct, it was simply asked
            // the wrong question. Every layer downstream (parser, ClickHouse
            // codegen, lake compiler) already handled the condition properly;
            // the loss happened here, on the way out.
            _ if self.condition.is_some() => {
                // Safe to unwrap: guarded by the match arm.
                let condition = self
                    .condition
                    .as_ref()
                    .expect("condition present in this arm");
                format!("{}(eval({}))", self.func.as_str(), condition.pretty_print())
            }
            _ => format!("{}({})", self.func.as_str(), field_str),
        };

        match &self.alias {
            // NAN-4279: a display-name alias (`dc(a)`) or one written quoted
            // (`as "Total Bytes"`) must stay quoted to re-parse; the lake
            // sends the printed query to the worker.
            Some(alias) if !is_plain_alias(alias) => {
                format!("{} as {}", base, super::helpers::npl_quoted_literal(alias))
            }
            Some(alias) => format!("{} as {}", base, alias),
            None => base,
        }
    }
}

/// An alias the parser reads back as a bare `field_name`.
fn is_plain_alias(alias: &str) -> bool {
    alias.split('.').all(|segment| {
        segment
            .chars()
            .next()
            .is_some_and(|c| c == '_' || c.is_alphabetic())
            && segment.chars().all(|c| c == '_' || c.is_alphanumeric())
    })
}

#[cfg(test)]
mod nan2361_tests {
    use super::*;
    use crate::query::parse_query;

    #[test]
    fn nan2361_conditional_aggregation_round_trips_its_predicate() {
        let printed = parse_query(r#"* | stats count(eval(status="error")) as errors"#)
            .expect("parses")
            .pretty_print();
        assert!(printed.contains("eval("), "predicate dropped: {printed}");
        let plain = parse_query("* | stats count() as c")
            .expect("parses")
            .pretty_print();
        assert!(!plain.contains("eval("));
    }
}
