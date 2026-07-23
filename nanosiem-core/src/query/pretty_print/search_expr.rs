// SPDX-License-Identifier: AGPL-3.0-or-later

//! Pretty-print implementation for search expressions.

use super::super::ast::*;
use super::PrettyPrint;

impl PrettyPrint for SearchExpr {
    fn pretty_print(&self) -> String {
        match self {
            SearchExpr::Keyword(kw) => {
                // NAN-2006: emit a keyword bare ONLY when it re-parses verbatim
                // as an `unquoted_keyword`. Anything else (space, quote, paren,
                // pipe, `=`, a reserved AND/OR/NOT, …) MUST be a double-quoted
                // string with breakout chars stripped, so the source-scope
                // gate's pretty_print -> re-parse round-trip cannot be broken
                // out of. The old code only quoted on a space, leaving e.g.
                // `x") OR source_type=audit OR ("y` to re-tokenize into an
                // ungated top-level OR arm (F1/F2/F6/F7).
                if is_bare_keyword(kw) {
                    kw.clone()
                } else {
                    format!("\"{}\"", super::helpers::npl_quoted_body(kw))
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
                let field_str = emit_field(field);
                let value_str = format_value_for_filter(value);
                if needs_spaces {
                    format!("{} {} {}", field_str, op_str, value_str)
                } else {
                    format!("{}{}{}", field_str, op_str, value_str)
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
            // NAN-1580 / NAN-1581: render the `ioc` surface forms back out.
            SearchExpr::IocMatch { values, feed, lookup } => {
                if let Some(f) = feed {
                    format!("ioc in {}(\"{}\")", f.name, f.arg)
                } else if let Some(l) = lookup {
                    match &l.column {
                        Some(col) => format!("ioc in lookup(\"{}\", \"{}\")", l.table, col),
                        None => format!("ioc in lookup(\"{}\")", l.table),
                    }
                } else if values.len() == 1 {
                    format!("ioc={}", format_value_for_filter(&values[0]))
                } else {
                    let values_str = values
                        .iter()
                        .map(format_value_for_filter)
                        .collect::<Vec<_>>()
                        .join(", ");
                    format!("ioc in [{}]", values_str)
                }
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
            // Always quote strings in field filters. NAN-2006: the parser has no
            // working backslash escape (NAN-1157), so the old `s.replace('"',
            // "\\\"")` was a no-op that let a `"`-bearing value break out of the
            // source-scope gate (F1/F4). Strip the breakout `"`/newlines instead.
            format!("\"{}\"", super::helpers::npl_quoted_body(s))
        }
        // For other value types, use their Display impl
        _ => value.to_string(),
    }
}

/// Emit a field-filter LHS. A field that re-parses verbatim via `field_name`
/// is emitted bare; anything else came from a quoted-string field (the parser
/// accepts `alt((quoted_string, field_name))` for the LHS — NAN-2006/F4, e.g.
/// `'src_ip=1) OR source_type=audit OR (user'=1`) and is emitted as a
/// double-quoted string with breakout chars stripped so it cannot re-tokenize
/// into query structure.
fn emit_field(field: &str) -> String {
    if is_bare_field(field) {
        field.to_string()
    } else {
        format!("\"{}\"", super::helpers::npl_quoted_body(field))
    }
}

/// True when `kw` re-parses verbatim as an `unquoted_keyword`
/// (`query::parser::search_expr::unquoted_keyword`): non-empty, every char in
/// `[alnum _ - . * ?]`, and NOT a reserved word (`AND`/`OR`/`NOT`, which would
/// re-tokenize as a boolean operator). Anything else must be quoted.
fn is_bare_keyword(kw: &str) -> bool {
    !kw.is_empty()
        && kw
            .chars()
            .all(|c| c.is_alphanumeric() || matches!(c, '_' | '-' | '.' | '*' | '?'))
        && !matches!(kw.to_ascii_uppercase().as_str(), "AND" | "OR" | "NOT")
}

/// True when `field` re-parses verbatim as a `field_name`
/// (`query::parser::values::field_name`): dot-separated segments where the
/// first segment starts with a letter or `_` and every char is alphanumeric or
/// `_`. Anything else (came from a quoted-string field) must be quoted.
fn is_bare_field(field: &str) -> bool {
    let mut segments = field.split('.');
    let first_ok = match segments.next() {
        Some(seg) => {
            let mut chars = seg.chars();
            matches!(chars.next(), Some(c) if c.is_alphabetic() || c == '_')
                && chars.all(|c| c.is_alphanumeric() || c == '_')
        }
        None => false,
    };
    first_ok
        && segments.all(|seg| !seg.is_empty() && seg.chars().all(|c| c.is_alphanumeric() || c == '_'))
}
