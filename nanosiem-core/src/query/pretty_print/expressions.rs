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
            _ => format!("{}({})", self.func.as_str(), field_str),
        };

        match &self.alias {
            Some(alias) => format!("{} as {}", base, alias),
            None => base,
        }
    }
}
