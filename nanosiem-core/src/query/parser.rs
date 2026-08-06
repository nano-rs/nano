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

pub use error::ParseError;
use error::{convert_error, rewrite_spl_escaped_double_quote};

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

/// Maximum length of a single operator/term chain — AND/OR boolean chains and
/// eval arithmetic/logical/comparison chains. Each term becomes one level of a
/// LEFT-NESTED AST, and many recursive walks (in-memory eval/where evaluation,
/// `PrettyPrint`, the audit source-scope gate, command extraction) descend that
/// spine, so an unbounded chain stack-overflows the worker process — an
/// uncatchable abort. The parser builds these via `many0(...).fold(...)`, which
/// is iterative and therefore NOT bounded by `MAX_NESTING_DEPTH` (that guard
/// only covers parenthesis/subsearch recursion). NAN-2010 (D: F13/F14/F30/F31).
const MAX_CHAIN_LEN: usize = 1024;

/// Absolute raw-query length cap (bytes), enforced before parsing as a cheap DoS
/// backstop that bounds total work/AST size regardless of shape. Generous — far
/// above any legitimate query (large IN/IOC lists included). NAN-2010.
const MAX_QUERY_LEN: usize = 1_048_576;

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

/// Reject an over-long operator/term chain (see [`MAX_CHAIN_LEN`]) at parse time,
/// before the `many0(...).fold(...)` combinators build a deep left-nested AST
/// that a later recursive walk would stack-overflow on. Returns a nom `Failure`
/// (halts backtracking) so the query is rejected with a clean parse error.
fn check_chain_len(input: &str, len: usize) -> Result<(), nom::Err<nom::error::Error<&str>>> {
    if len > MAX_CHAIN_LEN {
        return Err(nom::Err::Failure(nom::error::Error::new(
            input,
            nom::error::ErrorKind::TooLarge,
        )));
    }
    Ok(())
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
            // The matching quote always closes the string; a backslash is a
            // literal char and does NOT escape it (mirrors values.rs — so a
            // trailing `\` in a Windows path doesn't swallow the close). NAN-1157.
            if c == string_char {
                in_string = false;
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
    split_time_modifiers(input).0
}

/// Extract the literal `earliest=`/`latest=` modifier tokens from query input,
/// preserving their original text (e.g. `earliest=-12h`).
///
/// Because `parse_query` strips these tokens (they are TimeRange controls, not
/// AST nodes), any rewrite that round-trips through `parse_query` +
/// `PrettyPrint` would silently drop them. Callers that rewrite a query but must
/// preserve the analyst's time window (e.g. access-control enforcement) re-append
/// these so the downstream search layer still sees them (NAN-1453).
pub(crate) fn extract_time_modifier_tokens(input: &str) -> Vec<String> {
    split_time_modifiers(input).1
}

/// Split `earliest=`/`latest=` time modifiers out of the query input.
///
/// Returns `(query_without_modifiers, modifier_tokens)`. The scanner is
/// quote-aware so it never strips a modifier-looking substring that lives inside
/// a quoted value. Capture and strip share this single implementation so the two
/// can never drift out of sync.
fn split_time_modifiers(input: &str) -> (String, Vec<String>) {
    let mut result = String::with_capacity(input.len());
    let mut tokens = Vec::new();
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
            // Capture the full literal token (`earliest=-12h`) before advancing.
            tokens.push(remaining[..eq_pos + 1 + value_end].to_string());
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

    (result, tokens)
}

/// Parse a piped query string into an AST
pub fn parse_query(input: &str) -> Result<Query, ParseError> {
    // Reset nesting depth counter at the start of each parse
    NESTING_DEPTH.with(|d| d.set(0));

    // NAN-2010: reject an absurdly long query before doing any work — a cheap
    // DoS backstop that bounds total AST size regardless of shape.
    if input.len() > MAX_QUERY_LEN {
        return Err(ParseError {
            message: format!(
                "Query too long: {} bytes exceeds limit of {}",
                input.len(),
                MAX_QUERY_LEN
            ),
            position: 0,
            line: 1,
            column: 1,
            token: None,
            context_before: None,
            expected: vec![],
            suggestions: vec![],
            full_query: None,
        });
    }

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

    let parsed = match all_consuming(query).parse(normalized).finish() {
        Ok((_, parsed_query)) => validate_pipe_depth(parsed_query, input),
        Err(error) => {
            // SPL compatibility without regressing NAN-1157: valid historic nPL
            // (especially `file_path="C:\Windows\"`) already returned above.
            // Only a failed parse at the familiar `\"` trap gets bounded
            // retries after rewriting each affected literal to nPL's equivalent
            // delimiter. One retry was not enough for a normal SPL pipeline
            // containing two `rex` stages: the first pattern was repaired, the
            // second failed, and the whole original query was rejected.
            let original_error = error;
            let mut recovery_input = normalized.to_string();
            let mut position = normalized.len().saturating_sub(original_error.input.len());
            for _ in 0..MAX_PIPE_COMMANDS {
                let Some((rewritten, _)) =
                    rewrite_spl_escaped_double_quote(&recovery_input, position)
                else {
                    break;
                };
                if rewritten == recovery_input {
                    break;
                }
                NESTING_DEPTH.with(|depth| depth.set(0));
                let attempt = {
                    let mut recovery_parser = all_consuming(query);
                    recovery_parser.parse(rewritten.as_str()).finish()
                };
                match attempt {
                    Ok((_, parsed_query)) => return validate_pipe_depth(parsed_query, input),
                    Err(next_error) => {
                        position = rewritten.len().saturating_sub(next_error.input.len());
                        drop(next_error);
                        recovery_input = rewritten;
                    }
                }
            }
            // Recovery is invisible unless the complete query succeeds. If an
            // unrelated syntax problem remains, keep the original query and
            // its original SPL-quote guidance in the diagnostic.
            Err(convert_error(normalized, original_error))
        }
    };
    parsed
}

/// Enforce the CTE-depth bound identically for the primary parse and the one
/// SPL-compatibility retry.
fn validate_pipe_depth(parsed_query: Query, input: &str) -> Result<Query, ParseError> {
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

// ============================================================================
// Top-level parsers
// ============================================================================

/// Parse a complete query (search with optional piped commands)
/// Handles optional leading "search" keyword (PPL compatibility)
/// Also handles generating commands that start with | (e.g., | inputlookup ...)
/// and bare leading commands with no pipe (e.g., stats count by src_ip) — NAN-1843
fn query(input: &str) -> ParseResult<'_, Query> {
    // Optionally consume leading "search" keyword (common in subsearches)
    // e.g., [search status=500] or just [status=500]
    let (input, explicit_search) = opt(terminated(tag_no_case("search"), multispace1)).parse(input)?;

    // Three entry shapes:
    //   | stats ...   generating command, explicit leading pipe
    //   stats ...     bare leading command (NAN-1843), implicit `* |`
    //   status=500    search expression
    // The first two share an implicit `*` source.
    //
    // An explicit `search` keyword means the user asked for a keyword search, so
    // it suppresses bare-command recognition — `search top user` hunts for those
    // words, it does not run `| top user`.
    let leading = if explicit_search.is_some() {
        None
    } else {
        leading_command(input).ok()
    };

    let (input, search, mut commands) = if input.trim_start().starts_with('|') {
        (input, SearchExpr::Keyword("*".to_string()), Vec::new())
    } else if let Some((rest, cmd)) = leading {
        (rest, SearchExpr::Keyword("*".to_string()), vec![cmd])
    } else {
        let (rest, search) = search_expr(input)?;
        (rest, search, Vec::new())
    };

    let (input, piped) = many0(preceded(
        delimited(multispace0, char('|'), multispace0),
        command,
    ))
    .parse(input)?;
    commands.extend(piped);

    let query = commands
        .into_iter()
        .fold(Query::Search(search), |acc, cmd| Query::Piped {
            source: Box::new(acc),
            command: cmd,
        });

    Ok((input, query))
}

/// Parse a query-opening command that was written without a leading pipe, so
/// `stats count by src_ip` behaves like `* | stats count by src_ip` (NAN-1843).
///
/// Command names are ordinary English words, so this must not steal queries that
/// are really free-text searches. A keyword search silently reinterpreted as a
/// command is the same class of bug this change exists to kill, just pointed the
/// other way — so recognition is deliberately narrow. Three guards, and any
/// failure falls back to `search_expr`:
///
/// 1. **Only an aggregating or generating command may open a query**
///    ([`opens_a_query`]). Those are the ones analysts actually type bare, and
///    the ones with no sane keyword-search reading. Post-processors are excluded
///    precisely because their names are common words with real fields as
///    arguments: `sort timestamp`, `table message` and `head 10` are plausible
///    keyword searches, and they would otherwise parse as commands and *pass*
///    field validation — silently returning the wrong rows. Those still work one
///    pipe away (`| sort timestamp`).
/// 2. **The command must take arguments.** A lone command word is always a
///    keyword search. No allowlisted command parses with zero arguments today,
///    so this is belt-and-braces against one ever doing so and swallowing a
///    one-word hunt.
/// 3. **The command must consume the whole segment.** `top secret (classified)`
///    leaves `(classified)` dangling, which means the words were search terms;
///    falling back keeps the search working instead of hard-failing the parse.
///
/// What remains ambiguous is an allowlisted command whose arguments happen to be
/// real fields — `top user` is both a reasonable aggregation and a conceivable
/// keyword hunt, and no guard can tell them apart. It resolves to the command,
/// because in a query bar that is overwhelmingly the intent, and an aggregation
/// is unmistakably not a list of events, so a surprised user sees it instantly.
/// Two escapes force the search reading: quote it (`"top user"`) or say so
/// (`search top user`).
fn leading_command(input: &str) -> ParseResult<'_, Command> {
    let reject = || {
        nom::Err::Error(nom::error::Error::new(
            input,
            nom::error::ErrorKind::Verify,
        ))
    };

    let (rest, cmd) = command(input)?;

    // Guard 1: only aggregating/generating commands may open a query.
    if !opens_a_query(&cmd) {
        return Err(reject());
    }

    // Guard 2: the command must have consumed arguments, not just its own name.
    // `rest` is always a suffix of `input` (nom borrows it), but do the
    // arithmetic defensively — this parses untrusted input, and a panic here
    // would take the query path down.
    let consumed_len = input.len().checked_sub(rest.len()).ok_or_else(reject)?;
    let consumed = input.get(..consumed_len).ok_or_else(reject)?;
    if !consumed.trim().contains(char::is_whitespace) {
        return Err(reject());
    }

    // Guard 3: nothing may dangle before the next pipe / end of query.
    let remainder = rest.trim_start();
    if !remainder.is_empty() && !remainder.starts_with('|') {
        return Err(reject());
    }

    Ok((rest, cmd))
}

/// Whether a command is meaningful as the *first* thing in a query, and so may
/// be written without a leading pipe (NAN-1843).
///
/// Aggregating and generating commands qualify: they produce their own result
/// set, and `stats count by src_ip` reads as a complete query on its own.
/// Everything else post-processes rows that some earlier stage produced, so as a
/// query opener it is far more likely to be a keyword search that happens to
/// start with a command word. Keep this list conservative — see
/// [`leading_command`] for why widening it is dangerous.
fn opens_a_query(cmd: &Command) -> bool {
    matches!(
        cmd,
        Command::Stats { .. }
            | Command::Chart { .. }
            | Command::Timechart { .. }
            | Command::StreamStats { .. }
            | Command::EventStats { .. }
            | Command::Top { .. }
            | Command::Rare { .. }
            | Command::InputLookup { .. }
    )
}

/// Count the number of pipe commands in a parsed query tree.
fn count_pipe_commands(query: &Query) -> usize {
    match query {
        Query::Search(_) => 0,
        Query::Piped { source, .. } => 1 + count_pipe_commands(source),
    }
}
