// SPDX-License-Identifier: AGPL-3.0-or-later

//! Eval expression parsers for the query parser
//!
//! Handles eval command parsing and the eval expression hierarchy:
//! logical OR/AND, comparison, additive, multiplicative, concatenation,
//! and primary expressions (function calls, literals, field references).

use nom::{
    branch::alt,
    bytes::complete::{tag, tag_no_case, take_while1},
    character::complete::{char, multispace0, multispace1},
    combinator::{map, value},
    multi::separated_list0,
    sequence::{delimited, pair},
    Parser,
};

use super::values::{
    bool_value, field_name, interval_value, ip_value, number_value, quoted_string,
};
use super::ParseResult;
use crate::query::ast::*;

/// Parse eval expression (supports arithmetic, comparison, and logical operations)
pub(super) fn eval_expression(input: &str) -> ParseResult<'_, EvalExpression> {
    logical_or_expr(input)
}

/// Parse one comparison predicate without consuming search-level `AND`/`OR`.
///
/// `where` uses this narrower entry point when bridging computed predicates
/// into the eval grammar. Keeping logical composition in the search grammar
/// preserves ordinary field filters as index-aware `SearchExpr` nodes.
pub(super) fn eval_predicate_expression(input: &str) -> ParseResult<'_, EvalExpression> {
    comparison_expr(input)
}

/// Parse one comparison operand: arithmetic, function calls, literals and
/// parenthesized expressions, but no comparison or logical operator at the top.
///
/// The right side of a search/`where` comparison (`time >= now() - INTERVAL 2
/// HOUR`) uses this so a following `AND`/`OR` stays in the search grammar
/// (NAN-3384); the full eval grammar turned `A >= B AND C < D` into
/// `A >= (B AND C < D)`.
pub(super) fn eval_operand_expression(input: &str) -> ParseResult<'_, EvalExpression> {
    additive_expr(input)
}

/// Parse logical OR expressions (|| or OR)
fn logical_or_expr(input: &str) -> ParseResult<'_, EvalExpression> {
    let (input, first) = logical_and_expr(input)?;
    let (input, rest) = nom::multi::many0(pair(
        delimited(
            multispace0,
            alt((
                value(BinaryOperator::Or, tag("||")),
                value(BinaryOperator::Or, tag_no_case("OR")),
            )),
            multispace0,
        ),
        logical_and_expr,
    ))
    .parse(input)?;

    // NAN-2010 (D: F13/F31): bound the eval operator-chain length so a
    // left-nested `BinaryOp` spine (e.g. `1+1+1+…`) can't stack-overflow the
    // recursive evaluator.
    super::check_chain_len(input, rest.len())?;

    let expr = rest
        .into_iter()
        .fold(first, |acc, (op, e)| EvalExpression::BinaryOp {
            left: Box::new(acc),
            op,
            right: Box::new(e),
        });

    Ok((input, expr))
}

/// Parse logical AND expressions (&& or AND)
fn logical_and_expr(input: &str) -> ParseResult<'_, EvalExpression> {
    let (input, first) = not_expr(input)?;
    let (input, rest) = nom::multi::many0(pair(
        delimited(
            multispace0,
            alt((
                value(BinaryOperator::And, tag("&&")),
                value(BinaryOperator::And, tag_no_case("AND")),
            )),
            multispace0,
        ),
        not_expr,
    ))
    .parse(input)?;

    // NAN-2010 (D: F13/F31): bound the eval operator-chain length so a
    // left-nested `BinaryOp` spine (e.g. `1+1+1+…`) can't stack-overflow the
    // recursive evaluator.
    super::check_chain_len(input, rest.len())?;

    let expr = rest
        .into_iter()
        .fold(first, |acc, (op, e)| EvalExpression::BinaryOp {
            left: Box::new(acc),
            op,
            right: Box::new(e),
        });

    Ok((input, expr))
}

/// Parse `NOT <predicate>` (NAN-3041). Splunk's eval accepts a unary `NOT`;
/// nPL had none, so `if(NOT x IN (...), …)` could not be written. It lowers
/// to the `not()` function, which the SQL generator makes null-safe like the
/// search-side `NOT` (a missing value does not match the inner predicate).
fn not_expr(input: &str) -> ParseResult<'_, EvalExpression> {
    if let Ok((rest, _)) = nom::sequence::terminated(
        tag_no_case::<&str, &str, nom::error::Error<&str>>("NOT"),
        multispace1,
    )
    .parse(input)
    {
        let _guard = super::enter_nesting(input)?;
        let (rest, inner) = not_expr(rest)?;
        return Ok((
            rest,
            EvalExpression::FunctionCall {
                name: "not".to_string(),
                args: vec![inner],
            },
        ));
    }
    comparison_expr(input)
}

/// Parse the `IN (v1, v2, …)` / `NOT IN (…)` membership suffix (NAN-3041).
///
/// `where` has always accepted `field IN (...)`; eval and `if()` did not, so a
/// rule could filter with it but not score with it. It lowers to the
/// `in(expr, v1, v2, …)` function (wrapped in `not()` for `NOT IN`), which is
/// also directly callable.
fn in_list_suffix(input: &str) -> ParseResult<'_, (bool, Vec<EvalExpression>)> {
    let (input, _) = multispace1(input)?;
    let (input, negated) = alt((
        value(
            true,
            pair(tag_no_case("NOT"), pair(multispace1, tag_no_case("IN"))),
        ),
        value(false, pair(tag_no_case("IN"), multispace0)),
    ))
    .parse(input)?;
    let (input, _) = multispace0(input)?;
    let (input, _) = char('(').parse(input)?;
    let (input, _) = multispace0(input)?;
    let (input, values) = nom::multi::separated_list1(
        delimited(multispace0, char(','), multispace0),
        eval_expression,
    )
    .parse(input)?;
    let (input, _) = multispace0(input)?;
    let (input, _) = char(')').parse(input)?;
    Ok((input, (negated, values)))
}

/// Parse comparison expressions (==, =, !=, >, <, >=, <=, CONTAINS, LIKE)
/// Note: Both = and == are supported for equality (PPL compatibility)
/// In eval expressions, = means "equals" not "assign" (assignment is handled at top level)
/// plus the `IN (…)` / `NOT IN (…)` membership suffix.
fn comparison_expr(input: &str) -> ParseResult<'_, EvalExpression> {
    let (input, first) = additive_expr(input)?;
    let (input, first) = match in_list_suffix(input) {
        Ok((rest, (negated, values))) => {
            let mut args = Vec::with_capacity(values.len() + 1);
            args.push(first);
            args.extend(values);
            let membership = EvalExpression::FunctionCall {
                name: "in".to_string(),
                args,
            };
            let expr = if negated {
                EvalExpression::FunctionCall {
                    name: "not".to_string(),
                    args: vec![membership],
                }
            } else {
                membership
            };
            (rest, expr)
        }
        Err(_) => (input, first),
    };
    let (input, rest) = nom::multi::many0(pair(
        delimited(
            multispace0,
            alt((
                value(BinaryOperator::Gte, tag(">=")),
                value(BinaryOperator::Lte, tag("<=")),
                value(BinaryOperator::Eq, tag("==")), // Try == first (longer match)
                value(BinaryOperator::Ne, tag("!=")),
                value(BinaryOperator::Eq, char('=')), // Single = also means equality in expressions
                value(BinaryOperator::Gt, char('>')),
                value(BinaryOperator::Lt, char('<')),
                // Word-based operators for eval context (e.g., command_line CONTAINS "-enc")
                value(
                    BinaryOperator::Contains,
                    nom::sequence::terminated(tag_no_case("CONTAINS"), multispace1),
                ),
                value(
                    BinaryOperator::Like,
                    nom::sequence::terminated(tag_no_case("LIKE"), multispace1),
                ),
            )),
            multispace0,
        ),
        additive_expr,
    ))
    .parse(input)?;

    // NAN-2010 (D: F13/F31): bound the eval operator-chain length so a
    // left-nested `BinaryOp` spine (e.g. `1+1+1+…`) can't stack-overflow the
    // recursive evaluator.
    super::check_chain_len(input, rest.len())?;

    let expr = rest
        .into_iter()
        .fold(first, |acc, (op, e)| EvalExpression::BinaryOp {
            left: Box::new(acc),
            op,
            right: Box::new(e),
        });

    Ok((input, expr))
}

/// Parse additive expressions (+ and -)
fn additive_expr(input: &str) -> ParseResult<'_, EvalExpression> {
    let (input, first) = multiplicative_expr(input)?;
    let (input, rest) = nom::multi::many0(pair(
        delimited(
            multispace0,
            alt((
                value(BinaryOperator::Add, char('+')),
                value(BinaryOperator::Sub, char('-')),
            )),
            multispace0,
        ),
        multiplicative_expr,
    ))
    .parse(input)?;

    // NAN-2010 (D: F13/F31): bound the eval operator-chain length so a
    // left-nested `BinaryOp` spine (e.g. `1+1+1+…`) can't stack-overflow the
    // recursive evaluator.
    super::check_chain_len(input, rest.len())?;

    let expr = rest
        .into_iter()
        .fold(first, |acc, (op, e)| EvalExpression::BinaryOp {
            left: Box::new(acc),
            op,
            right: Box::new(e),
        });

    Ok((input, expr))
}

/// Parse multiplicative expressions (*, /, %)
fn multiplicative_expr(input: &str) -> ParseResult<'_, EvalExpression> {
    let (input, first) = concat_expr(input)?;
    let (input, rest) = nom::multi::many0(pair(
        delimited(
            multispace0,
            alt((
                value(BinaryOperator::Mul, char('*')),
                value(BinaryOperator::Div, char('/')),
                value(BinaryOperator::Mod, char('%')),
            )),
            multispace0,
        ),
        concat_expr,
    ))
    .parse(input)?;

    // NAN-2010 (D: F13/F31): bound the eval operator-chain length so a
    // left-nested `BinaryOp` spine (e.g. `1+1+1+…`) can't stack-overflow the
    // recursive evaluator.
    super::check_chain_len(input, rest.len())?;

    let expr = rest
        .into_iter()
        .fold(first, |acc, (op, e)| EvalExpression::BinaryOp {
            left: Box::new(acc),
            op,
            right: Box::new(e),
        });

    Ok((input, expr))
}

/// Parse concatenation expressions (.)
fn concat_expr(input: &str) -> ParseResult<'_, EvalExpression> {
    let (input, first) = primary_eval_expr(input)?;
    let (input, rest) = nom::multi::many0(pair(
        delimited(
            multispace0,
            value(BinaryOperator::Concat, char('.')),
            multispace0,
        ),
        primary_eval_expr,
    ))
    .parse(input)?;

    // NAN-2010 (D: F13/F31): bound the eval operator-chain length so a
    // left-nested `BinaryOp` spine (e.g. `1+1+1+…`) can't stack-overflow the
    // recursive evaluator.
    super::check_chain_len(input, rest.len())?;

    let expr = rest
        .into_iter()
        .fold(first, |acc, (op, e)| EvalExpression::BinaryOp {
            left: Box::new(acc),
            op,
            right: Box::new(e),
        });

    Ok((input, expr))
}

/// Parse primary eval expressions (literals, fields, function calls, parentheses)
fn primary_eval_expr(input: &str) -> ParseResult<'_, EvalExpression> {
    alt((
        eval_function_call,
        eval_parentheses,
        // Try numeric/bool/ip/interval literals first (they have distinct syntax)
        eval_numeric_literal,
        eval_bool_literal,
        eval_ip_literal,
        eval_interval_literal,
        // Quoted strings BEFORE field names — in eval context, quoted strings are always
        // string literals (e.g. "%H" in strftime), not field references
        eval_quoted_string_literal,
        // Regex literals (/pattern/) — used in eval if() conditions like if(field=/regex/, a, b)
        eval_regex_literal,
        eval_field,
    ))
    .parse(input)
}

/// Parse regex literal in eval expression: /pattern/
fn eval_regex_literal(input: &str) -> ParseResult<'_, EvalExpression> {
    let (input, pattern) = super::search_expr::regex_literal(input)?;
    Ok((input, EvalExpression::Literal(Value::Regex(pattern))))
}

/// Parse function call in eval expression
fn eval_function_call(input: &str) -> ParseResult<'_, EvalExpression> {
    let _guard = super::enter_nesting(input)?;
    let (input, name) = take_while1(|c: char| c.is_alphanumeric() || c == '_').parse(input)?;
    let (input, _) = char('(').parse(input)?;
    let (input, _) = multispace0(input)?;
    let (input, args) = separated_list0(
        delimited(multispace0, char(','), multispace0),
        eval_expression,
    )
    .parse(input)?;
    let (input, _) = multispace0(input)?;
    let (input, _) = char(')').parse(input)?;

    Ok((
        input,
        EvalExpression::FunctionCall {
            name: name.to_string(),
            args,
        },
    ))
}

/// Parse parenthesized eval expression
fn eval_parentheses(input: &str) -> ParseResult<'_, EvalExpression> {
    let _guard = super::enter_nesting(input)?;
    delimited(
        pair(char('('), multispace0),
        eval_expression,
        pair(multispace0, char(')')),
    )
    .parse(input)
}

/// Parse numeric literal in eval expression
fn eval_numeric_literal(input: &str) -> ParseResult<'_, EvalExpression> {
    map(number_value, EvalExpression::Literal).parse(input)
}

/// Parse boolean literal in eval expression
fn eval_bool_literal(input: &str) -> ParseResult<'_, EvalExpression> {
    map(bool_value, EvalExpression::Literal).parse(input)
}

/// Parse IP literal in eval expression
fn eval_ip_literal(input: &str) -> ParseResult<'_, EvalExpression> {
    map(ip_value, EvalExpression::Literal).parse(input)
}

/// Parse interval literal in eval expression
fn eval_interval_literal(input: &str) -> ParseResult<'_, EvalExpression> {
    map(interval_value, EvalExpression::Literal).parse(input)
}

/// Parse quoted string literal in eval expression
fn eval_quoted_string_literal(input: &str) -> ParseResult<'_, EvalExpression> {
    map(map(quoted_string, Value::String), EvalExpression::Literal).parse(input)
}

/// Parse field reference in eval expression
/// Only unquoted field names — quoted strings are always string literals in eval context
fn eval_field(input: &str) -> ParseResult<'_, EvalExpression> {
    map(field_name, EvalExpression::Field).parse(input)
}

/// Parse eval command: eval field1=expr1, field2=expr2, ...
pub(super) fn eval_command(input: &str) -> ParseResult<'_, Command> {
    let (input, _) = tag_no_case("eval").parse(input)?;
    let (input, _) = multispace1(input)?;
    let (input, assignments) = nom::multi::separated_list1(
        delimited(multispace0, char(','), multispace0),
        eval_assignment,
    )
    .parse(input)?;

    Ok((input, Command::Eval { assignments }))
}

/// Parse a single eval assignment: field = expression
/// Supports quoted field names for fields with spaces
fn eval_assignment(input: &str) -> ParseResult<'_, EvalAssignment> {
    let (input, field) = alt((quoted_string, field_name)).parse(input)?;
    let (input, _) = multispace0(input)?;
    let (input, _) = char('=').parse(input)?;
    let (input, _) = multispace0(input)?;
    let (input, expression) = eval_expression(input)?;

    Ok((input, EvalAssignment { field, expression }))
}
