// SPDX-License-Identifier: AGPL-3.0-or-later

//! Pretty-print implementation for search expressions.

use super::super::ast::*;
use super::PrettyPrint;

/// Render a boolean tree in the precedence context of its command. Parsed
/// parenthesized expressions retain a `Group` node, preserving round trips.
pub(super) fn print_search_expr(expr: &SearchExpr, where_mode: bool) -> String {
    fn render(expr: &SearchExpr, where_mode: bool, parent: u8) -> String {
        let precedence = match expr {
            SearchExpr::And(_, _) => {
                if where_mode {
                    2
                } else {
                    1
                }
            }
            SearchExpr::Or(_, _) => {
                if where_mode {
                    1
                } else {
                    2
                }
            }
            _ => 3,
        };
        let body = match expr {
            SearchExpr::And(left, right) => format!(
                "{} {}",
                render(left, where_mode, precedence),
                render(right, where_mode, precedence)
            ),
            SearchExpr::Or(left, right) => format!(
                "{} OR {}",
                render(left, where_mode, precedence),
                render(right, where_mode, precedence)
            ),
            SearchExpr::Not(inner) => format!("NOT {}", render(inner, where_mode, 3)),
            SearchExpr::Group(inner) => format!("({})", render(inner, where_mode, 0)),
            _ => expr.pretty_print(),
        };
        if precedence < parent {
            format!("({body})")
        } else {
            body
        }
    }
    render(expr, where_mode, 0)
}

/// `search` and `where` share the existing `Command::Where` AST variant. The
/// tree itself tells us which spelling preserves an ungrouped OR under AND.
pub(super) fn requires_search_spelling(expr: &SearchExpr) -> bool {
    match expr {
        SearchExpr::And(left, right) => {
            matches!(&**left, SearchExpr::Or(_, _))
                || matches!(&**right, SearchExpr::Or(_, _))
                || requires_search_spelling(left)
                || requires_search_spelling(right)
        }
        SearchExpr::Or(left, right) => {
            requires_search_spelling(left) || requires_search_spelling(right)
        }
        SearchExpr::Not(inner) | SearchExpr::Group(inner) => requires_search_spelling(inner),
        _ => false,
    }
}

impl PrettyPrint for SearchExpr {
    fn pretty_print(&self) -> String {
        match self {
            SearchExpr::Keyword(kw) => {
                // NAN-2006: emit a keyword bare ONLY when it re-parses verbatim
                // as an `unquoted_keyword`. Anything else (space, quote, paren,
                // pipe, `=`, a reserved AND/OR/NOT, …) MUST be a quoted literal
                // the keyword cannot terminate, so the source-scope gate's
                // pretty_print -> re-parse round-trip cannot be broken out of.
                // The old code only quoted on a space, leaving e.g.
                // `x") OR source_type=audit OR ("y` to re-tokenize into an
                // ungated top-level OR arm (F1/F2/F6/F7).
                if is_bare_keyword(kw) {
                    kw.clone()
                } else {
                    super::helpers::npl_quoted_literal(kw)
                }
            }
            SearchExpr::FieldFilter {
                field,
                op,
                value,
                rhs,
            } => {
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
                // NAN-2380: a BAREWORD right-hand side must be re-emitted bare.
                // Quoting it would erase the one bit that distinguishes
                // `src_ip != dest_ip` (a column comparison) from
                // `src_ip != "dest_ip"` (a literal), so an AST -> text -> AST
                // round-trip — which the source-scope gate performs on every
                // scoped query — would silently downgrade the comparison back to
                // the inverted literal form. `is_bareword_identifier` only ever
                // marks tokens that re-tokenize verbatim (dotted identifier
                // segments, no reserved words), so emitting them bare cannot
                // break out of the filter the way an unquoted arbitrary value
                // could (NAN-2006).
                let value_str = match (rhs, value) {
                    (RhsSyntax::Bareword, Value::String(text)) if is_bareword_identifier(text) => {
                        text.clone()
                    }
                    _ => format_value_for_filter(value),
                };
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
            // Preserve this as a single search-expression leaf when the
            // source-scope gate pretty-prints and re-parses the query.
            SearchExpr::EvalPredicate(expression) => {
                format!("({})", expression.pretty_print())
            }
            SearchExpr::FieldFunctionFilter {
                field,
                op,
                function,
            } => {
                // NAN-2380: a bare field reference on the RHS of `=` / `!=` must
                // be re-emitted in backticks. Printed bare it would re-parse as
                // an ordinary `FieldFilter` — ambiguous on UDM, and a literal
                // wherever the field is unknown — so an AST -> text -> AST
                // round-trip (the source-scope gate does one on every scoped
                // query) would silently change an explicit column comparison
                // into something else. `>` `<` `>=` `<=` already re-parse as a
                // field reference bare, so they keep their existing spelling.
                if let (EvalExpression::Field(name), Comparator::Eq | Comparator::Ne) =
                    (function, op)
                {
                    if is_bareword_identifier(name) {
                        return format!("{}{}`{}`", emit_field(field), op.as_str(), name);
                    }
                }
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
            SearchExpr::And(_, _)
            | SearchExpr::Or(_, _)
            | SearchExpr::Not(_)
            | SearchExpr::Group(_) => print_search_expr(self, false),
            SearchExpr::LiteralComparison { left, op, right } => {
                // `quoted_string_comparison` requires BOTH sides quoted, so both
                // go through the literal serializer — the old raw `"{}"`
                // interpolation let a `"`-bearing side re-tokenize into query
                // structure. Non-string values keep their quoted shape (the
                // parser only ever builds `Value::String` here).
                let right = match right {
                    Value::String(s) => super::helpers::npl_quoted_literal(s),
                    other => super::helpers::npl_quoted_literal(&other.to_string()),
                };
                format!(
                    "{}{}{}",
                    super::helpers::npl_quoted_literal(left),
                    op.as_str(),
                    right
                )
            }
            // NAN-1580 / NAN-1581: render the `ioc` surface forms back out.
            SearchExpr::IocMatch {
                values,
                feed,
                lookup,
            } => {
                let lit = super::helpers::npl_quoted_literal;
                if let Some(f) = feed {
                    format!("ioc in {}({})", f.name, lit(&f.arg))
                } else if let Some(l) = lookup {
                    match &l.column {
                        Some(col) => {
                            format!("ioc in lookup({}, {})", lit(&l.table), lit(col))
                        }
                        None => format!("ioc in lookup({})", lit(&l.table)),
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
            // source-scope gate (F1/F4). `npl_quoted_literal` picks the
            // delimiter the value cannot terminate (NAN-2241).
            super::helpers::npl_quoted_literal(s)
        }
        // For other value types, use their Display impl
        _ => value.to_string(),
    }
}

/// Emit a field-filter LHS. A field that re-parses verbatim via `field_name`
/// is emitted bare; anything else came from a quoted-string field (the parser
/// accepts `alt((quoted_string, field_name))` for the LHS — NAN-2006/F4, e.g.
/// `'src_ip=1) OR source_type=audit OR (user'=1`) and is emitted as a quoted
/// literal whose delimiter the name does not contain, so it cannot re-tokenize
/// into query structure.
fn emit_field(field: &str) -> String {
    if is_bare_field(field) {
        field.to_string()
    } else {
        super::helpers::npl_quoted_literal(field)
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
        && segments
            .all(|seg| !seg.is_empty() && seg.chars().all(|c| c.is_alphanumeric() || c == '_'))
}
