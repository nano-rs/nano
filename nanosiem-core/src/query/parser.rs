// SPDX-License-Identifier: AGPL-3.0-or-later

//! Parser for piped query syntax using nom combinators
//!
//! Grammar (EBNF):
//! ```ebnf
//! query       = search_term { "|" command } ;
//! search_term = keyword_search | regex_filter | field_filter | "(" query ")" ;
//! keyword_search = word { word } ;
//! regex_filter = field_name ("=" | "!=") "/" regex_pattern "/" ;
//! field_filter = field_name comparator value ;
//! comparator  = "=" | "!=" | ">" | "<" | ">=" | "<=" ;
//! command     = stats_cmd | where_cmd | sort_cmd | head_cmd | tail_cmd | timechart_cmd | table_cmd ;
//! ```

mod commands_core;
mod commands_enrichment;
mod commands_extended;
mod commands_security;
mod error;
mod eval_expr;
mod search_expr;
mod values;

#[cfg(test)]
mod tests;

use error::convert_error;
pub use error::ParseError;

use nom::{
    bytes::complete::tag_no_case,
    character::complete::{char, multispace0, multispace1},
    combinator::{all_consuming, opt},
    multi::many0,
    sequence::{delimited, preceded, terminated},
    Finish, IResult, Parser,
};

use super::ast::*;
use commands_core::command;
use search_expr::search_expr;

type ParseResult<'a, T> = IResult<&'a str, T>;

/// Maximum nesting depth for expressions to prevent stack overflow (C3)
const MAX_NESTING_DEPTH: usize = 50;

/// Maximum number of pipe commands allowed in a single query to prevent DoS
/// via CTE explosion (each pipe generates a SQL CTE stage)
const MAX_PIPE_COMMANDS: usize = 25;

thread_local! {
    static NESTING_DEPTH: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// Increment nesting depth and return error if exceeded.
/// Returns a guard that decrements on drop.
fn enter_nesting(input: &str) -> Result<NestingGuard, nom::Err<nom::error::Error<&str>>> {
    let depth = NESTING_DEPTH.with(|d| {
        let current = d.get();
        d.set(current + 1);
        current + 1
    });
    if depth > MAX_NESTING_DEPTH {
        NESTING_DEPTH.with(|d| d.set(d.get() - 1));
        return Err(nom::Err::Failure(nom::error::Error::new(
            input,
            nom::error::ErrorKind::TooLarge,
        )));
    }
    Ok(NestingGuard)
}

struct NestingGuard;

impl Drop for NestingGuard {
    fn drop(&mut self) {
        NESTING_DEPTH.with(|d| d.set(d.get() - 1));
    }
}

/// Strip comments from query input
/// Handles:
/// - Single-line comments: // comment (to end of line)
/// - Block comments: /* comment */
fn strip_comments(input: &str) -> String {
    let mut result = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();
    let mut in_string = false;
    let mut string_char = '"';

    while let Some(c) = chars.next() {
        // Track string state to avoid stripping "comments" inside strings
        if !in_string && (c == '"' || c == '\'') {
            in_string = true;
            string_char = c;
            result.push(c);
            continue;
        }

        if in_string {
            result.push(c);
            if c == string_char {
                in_string = false;
            } else if c == '\\' {
                // Handle escape sequences in strings
                if let Some(&next) = chars.peek() {
                    result.push(next);
                    chars.next();
                }
            }
            continue;
        }

        // Check for comments
        if c == '/' {
            match chars.peek() {
                Some(&'/') => {
                    // Single-line comment: skip to end of line
                    chars.next(); // consume second /
                    while let Some(&next) = chars.peek() {
                        if next == '\n' || next == '\r' {
                            break;
                        }
                        chars.next();
                    }
                    // Add a space to separate tokens that were around the comment
                    result.push(' ');
                }
                Some(&'*') => {
                    // Block comment: skip to */
                    chars.next(); // consume *
                    while let Some(next) = chars.next() {
                        if next == '*' {
                            if chars.peek() == Some(&'/') {
                                chars.next(); // consume /
                                break;
                            }
                        }
                    }
                    // Add a space to separate tokens
                    result.push(' ');
                }
                _ => {
                    // Not a comment, just a regular /
                    result.push(c);
                }
            }
        } else {
            result.push(c);
        }
    }

    result
}

/// Strip earliest/latest time modifiers from query input.
/// Removes `earliest=<value>` and `latest=<value>` tokens from the search expression —
/// these are time-range controls handled by the UI/API TimeRange parameter, not by the parser.
/// Values can be: -24h, -1d, -7d@d, now, @d, etc. (relative or snap-to time specs)
fn strip_time_modifiers(input: &str) -> String {
    let mut result = String::with_capacity(input.len());
    let mut remaining = input;

    while !remaining.is_empty() {
        // Check if we're inside a quoted string — don't strip there
        if remaining.starts_with('"') || remaining.starts_with('\'') {
            let quote = remaining.chars().next().unwrap();
            result.push(quote);
            remaining = &remaining[1..];
            // Consume until matching close quote
            while !remaining.is_empty() {
                let c = remaining.chars().next().unwrap();
                result.push(c);
                remaining = &remaining[c.len_utf8()..];
                if c == quote {
                    break;
                }
                if c == '\\' && !remaining.is_empty() {
                    let esc = remaining.chars().next().unwrap();
                    result.push(esc);
                    remaining = &remaining[esc.len_utf8()..];
                }
            }
            continue;
        }

        // Check for earliest= or latest= (case-insensitive)
        let lower = remaining.to_lowercase();
        if lower.starts_with("earliest=") || lower.starts_with("latest=") {
            let eq_pos = remaining.find('=').unwrap();
            let after_eq = &remaining[eq_pos + 1..];
            // Consume the value: everything up to the next whitespace, pipe, or closing bracket
            let value_end = after_eq
                .find(|c: char| c.is_whitespace() || c == '|' || c == ']')
                .unwrap_or(after_eq.len());
            remaining = &after_eq[value_end..];
            // Add a space to keep tokens separated
            result.push(' ');
            continue;
        }

        // Regular character — pass through
        let c = remaining.chars().next().unwrap();
        result.push(c);
        remaining = &remaining[c.len_utf8()..];
    }

    result
}

/// Parse a piped query string into an AST
pub fn parse_query(input: &str) -> Result<Query, ParseError> {
    // Reset nesting depth counter at the start of each parse
    NESTING_DEPTH.with(|d| d.set(0));

    // Strip comments before parsing
    // Handle // single-line comments and /* */ block comments
    let without_comments = strip_comments(input);

    // Normalize the input: replace newlines with spaces
    let normalized: String = without_comments
        .chars()
        .map(|c| if c == '\n' || c == '\r' { ' ' } else { c })
        .collect();
    // Strip earliest=X / latest=X time modifiers — handled by the search UI/API
    // via TimeRange, not by the query parser.
    let normalized = strip_time_modifiers(&normalized);
    let normalized = normalized.trim();

    if normalized.is_empty() {
        return Err(ParseError {
            message: "Empty query".to_string(),
            position: 0,
            line: 1,
            column: 1,
            token: None,
            context_before: None,
            expected: vec!["search expression".to_string()],
            suggestions: vec![],
            full_query: Some(input.to_string()),
        });
    }

    // Handle standalone subsearch: [search ...] — strip outer brackets.
    // This is a simple heuristic (not balanced-bracket matching) but safe because
    // all_consuming(query) will reject malformed inner content anyway.
    let normalized = if normalized.starts_with('[') && normalized.ends_with(']') {
        &normalized[1..normalized.len() - 1]
    } else {
        normalized
    };

    let result = all_consuming(query).parse(normalized).finish();
    match result {
        Ok((_, parsed_query)) => {
            // Enforce pipe depth limit to prevent DoS via CTE explosion
            let pipe_count = count_pipe_commands(&parsed_query);
            if pipe_count > MAX_PIPE_COMMANDS {
                return Err(ParseError {
                    message: format!(
                        "Query too complex: maximum {} pipe commands allowed (found {})",
                        MAX_PIPE_COMMANDS, pipe_count
                    ),
                    position: 0,
                    line: 1,
                    column: 1,
                    token: None,
                    context_before: None,
                    expected: vec![],
                    suggestions: vec![],
                    full_query: Some(input.to_string()),
                });
            }
            Ok(parsed_query)
        }
        Err(e) => Err(convert_error(normalized, e)),
    }
}

// ============================================================================
// Top-level parsers
// ============================================================================

/// Parse a complete query (search with optional piped commands)
/// Handles optional leading "search" keyword (PPL compatibility)
/// Also handles generating commands that start with | (e.g., | inputlookup ...)
fn query(input: &str) -> ParseResult<'_, Query> {
    // Optionally consume leading "search" keyword (common in subsearches)
    // e.g., [search status=500] or just [status=500]
    let (input, _) = opt(terminated(tag_no_case("search"), multispace1)).parse(input)?;

    // Check if query starts with | (generating command like inputlookup)
    let (input, search) = if input.trim_start().starts_with('|') {
        // Use implicit wildcard for generating commands
        (input, SearchExpr::Keyword("*".to_string()))
    } else {
        search_expr(input)?
    };

    let (input, commands) = many0(preceded(
        delimited(multispace0, char('|'), multispace0),
        command,
    ))
    .parse(input)?;

    let query = commands
        .into_iter()
        .fold(Query::Search(search), |acc, cmd| Query::Piped {
            source: Box::new(acc),
            command: cmd,
        });

    Ok((input, query))
}

/// Count the number of pipe commands in a parsed query tree.
fn count_pipe_commands(query: &Query) -> usize {
    match query {
        Query::Search(_) => 0,
        Query::Piped { source, .. } => 1 + count_pipe_commands(source),
    }
}
