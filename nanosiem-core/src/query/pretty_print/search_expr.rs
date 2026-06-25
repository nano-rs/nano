// SPDX-License-Identifier: AGPL-3.0-or-later

//! Pretty-print implementation for search expressions.

use super::super::ast::*;
use super::PrettyPrint;

impl PrettyPrint for SearchExpr {
    fn pretty_print(&self) -> String {
        match self {
            SearchExpr::Keyword(kw) => {
                // Quote keywords with spaces
                if kw.contains(' ') {
                    format!("\"{}\"", kw)
                } else {
                    kw.clone()
                }
            }
            SearchExpr::FieldFilter { field, op, value } => {
                // Word-based operators need spaces around them
                let op_str = op.as_str();
                let needs_spaces = matches!(
                    op,
                    Comparator::Like
                        | Comparator::NotLike
                        | Comparator::Contains
                        | Comparator::NotContains
                        | Comparator::StartsWith
                        | Comparator::NotStartsWith
                        | Comparator::EndsWith
                        | Comparator::NotEndsWith
                );
                let value_str = format_value_for_filter(value);
                if needs_spaces {
                    format!("{} {} {}", field, op_str, value_str)
                } else {
                    format!("{}{}{}", field, op_str, value_str)
                }
            }
            SearchExpr::FunctionFilter {
                function,
                op,
                value,
            } => {
                format!("{}{}{}", function.pretty_print(), op.as_str(), value)
            }
            SearchExpr::BooleanFunction(function) => function.pretty_print(),
            SearchExpr::FieldFunctionFilter {
                field,
                op,
                function,
            } => {
                format!("{}{}{}", field, op.as_str(), function.pretty_print())
            }
            SearchExpr::InList {
                field,
                values,
                negated,
            } => {
                let values_str = values
                    .iter()
                    .map(|v| format_value_for_filter(v))
                    .collect::<Vec<_>>()
                    .join(", ");
                if *negated {
                    format!("{} NOT IN ({})", field, values_str)
                } else {
                    format!("{} IN ({})", field, values_str)
                }
            }
            SearchExpr::And(left, right) => {
                format!("{} {}", left.pretty_print(), right.pretty_print())
            }
            SearchExpr::Or(left, right) => {
                format!("{} OR {}", left.pretty_print(), right.pretty_print())
            }
            SearchExpr::Not(expr) => {
                format!("NOT {}", expr.pretty_print())
            }
            SearchExpr::Group(expr) => {
                format!("({})", expr.pretty_print())
            }
            SearchExpr::LiteralComparison { left, op, right } => {
                format!("\"{}\"{}\"{}\"", left, op.as_str(), right)
            }
            SearchExpr::InSubsearch {
                field,
                subsearch,
                negated,
                subsearch_dataset,
            } => {
                let not_str = if *negated { "NOT " } else { "" };
                // NAN-1562: render the cross-dataset selector inside the brackets.
                let ds_prefix = match subsearch_dataset {
                    Some(ds) => {
                        format!("dataset={} ", super::helpers::dataset_selector_str(*ds))
                    }
                    None => String::new(),
                };
                format!(
                    "{} {}IN [{}{}]",
                    field,
                    not_str,
                    ds_prefix,
                    subsearch.pretty_print()
                )
            }
        }
    }
}

/// Format a Value for use in a field filter, always quoting strings for safety
pub(super) fn format_value_for_filter(value: &Value) -> String {
    match value {
        Value::String(s) => {
            // Always quote strings in field filters to ensure correct parsing
            format!("\"{}\"", s.replace('"', "\\\""))
        }
        // For other value types, use their Display impl
        _ => value.to_string(),
    }
}
