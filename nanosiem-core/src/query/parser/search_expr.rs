// SPDX-License-Identifier: AGPL-3.0-or-later

//! Search expression parsers for the query parser
//!
//! Handles AND/OR/NOT precedence, field filters, regex filters,
//! keyword searches, function calls, IN lists, and grouped expressions.

use nom::{
    branch::alt,
    bytes::complete::{tag, tag_no_case, take_while1},
    character::complete::{char, multispace0, multispace1},
    combinator::{map, opt, value},
    multi::{many0, separated_list0, separated_list1},
    sequence::{delimited, pair, preceded, terminated},
    Parser,
};
use regex;

use super::eval_expr::eval_expression;
use super::values::{comparator, field_name, filter_value, quoted_string};
use super::ParseResult;
use crate::query::ast::*;

/// Parse a search expression (handles AND/OR precedence)
pub(super) fn search_expr(input: &str) -> ParseResult<'_, SearchExpr> {
    or_expr(input)
}

/// Parse a parenthesized search expression: (action="login") or (action="login" status="failure")
/// Used by transaction startswith=/endswith= and funnel step= parameters.
pub(super) fn parse_paren_search_expr(input: &str) -> ParseResult<'_, SearchExpr> {
    let (input, _) = char('(').parse(input)?;
    // Find matching closing paren, respecting nested parens, quotes, and regex literals
    let mut depth = 1;
    let mut i = 0;
    let bytes = input.as_bytes();
    let mut in_quote = false;
    let mut quote_char = b'"';
    let mut in_regex = false;
    while i < bytes.len() && depth > 0 {
        if in_regex {
            if bytes[i] == b'\\' {
                i += 1; // skip escaped char in regex
            } else if bytes[i] == b'/' {
                in_regex = false;
            }
        } else if in_quote {
            // The matching quote always closes; backslash is literal inside
            // strings (no escape), so a trailing `\` doesn't swallow the close.
            // Regex (above) keeps its `\/` escape. NAN-1157.
            if bytes[i] == quote_char {
                in_quote = false;
            }
        } else {
            match bytes[i] {
                b'"' | b'\'' => {
                    in_quote = true;
                    quote_char = bytes[i];
                }
                b'/' => {
                    // Regex literal: must follow = or space (e.g., field=/pattern/)
                    if i > 0 && (bytes[i - 1] == b'=' || bytes[i - 1] == b' ') {
                        in_regex = true;
                    }
                }
                b'(' => depth += 1,
                b')' => depth -= 1,
                _ => {}
            }
        }
        if depth > 0 {
            i += 1;
        }
    }
    if depth != 0 {
        return Err(nom::Err::Error(nom::error::Error::new(
            input,
            nom::error::ErrorKind::Char,
        )));
    }
    let content = &input[..i];
    let remaining = &input[i + 1..]; // skip closing paren
    let (leftover, expr) = search_expr(content)?;
    if !leftover.trim().is_empty() {
        return Err(nom::Err::Error(nom::error::Error::new(
            leftover,
            nom::error::ErrorKind::Complete,
        )));
    }
    Ok((remaining, expr))
}

/// Parse OR expressions (lowest precedence)
/// Supports both OR keyword and || operator
fn or_expr(input: &str) -> ParseResult<'_, SearchExpr> {
    let (input, first) = and_expr(input)?;
    let (input, rest) = many0(preceded(
        alt((
            delimited(multispace1, tag_no_case("OR"), multispace1),
            delimited(multispace0, tag("||"), multispace0),
        )),
        and_expr,
    ))
    .parse(input)?;

    // NAN-2010 (D): bound the OR-chain length so the left-nested `Or(Or(...))`
    // AST can't stack-overflow a recursive walk.
    super::check_chain_len(input, rest.len())?;

    let expr = rest
        .into_iter()
        .fold(first, |acc, e| SearchExpr::Or(Box::new(acc), Box::new(e)));

    Ok((input, expr))
}

/// Parse AND expressions (higher precedence than OR)
/// Supports both AND keyword and && operator
fn and_expr(input: &str) -> ParseResult<'_, SearchExpr> {
    let (input, first) = not_expr(input)?;
    let (input, rest) = many0(preceded(
        alt((
            delimited(multispace1, tag_no_case("AND"), multispace1),
            delimited(multispace0, tag("&&"), multispace0),
            // Implicit AND via whitespace, but NOT if followed by pipe (command separator)
            // or OR/|| (lower precedence operator that should end this and_expr)
            implicit_and_separator,
        )),
        not_expr,
    ))
    .parse(input)?;

    // NAN-2010 (D): bound the AND-chain length (implicit-AND `a a a …` included)
    // so the left-nested `And(And(...))` AST can't stack-overflow a recursive walk.
    super::check_chain_len(input, rest.len())?;

    let expr = rest
        .into_iter()
        .fold(first, |acc, e| SearchExpr::And(Box::new(acc), Box::new(e)));

    Ok((input, expr))
}

/// Match whitespace as implicit AND, but fail if followed by | or OR
/// This ensures that `a OR b | cmd` parses correctly (pipe ends the search expr)
fn implicit_and_separator(input: &str) -> ParseResult<'_, &str> {
    let (remaining, ws) = multispace1(input)?;

    // Check what comes after the whitespace - don't consume implicit AND
    // if the next thing is a pipe or OR operator
    let next = remaining.trim_start();
    if next.starts_with('|') || next.to_uppercase().starts_with("OR ") || next.starts_with("||") {
        // Fail the parse - this whitespace should not be treated as implicit AND
        Err(nom::Err::Error(nom::error::Error::new(
            input,
            nom::error::ErrorKind::Verify,
        )))
    } else {
        Ok((remaining, ws))
    }
}

/// Parse NOT expressions
fn not_expr(input: &str) -> ParseResult<'_, SearchExpr> {
    alt((
        map(
            preceded(terminated(tag_no_case("NOT"), multispace1), primary_expr),
            |e| SearchExpr::Not(Box::new(e)),
        ),
        primary_expr,
    ))
    .parse(input)
}

/// Parse primary expressions (field filters, keywords, groups, function calls)
fn primary_expr(input: &str) -> ParseResult<'_, SearchExpr> {
    // function_call_expr (func(args) op value) must come before boolean_function_expr (func(args))
    // since the former is more specific; boolean_function_expr catches the standalone case
    alt((
        grouped_expr,
        // `ioc=` / `ioc in [...]` / `ioc in feed("arg")` are special-cased ahead
        // of the generic field/in-list filters so the `ioc` pseudo-field expands
        // to an observable-anywhere match (NAN-1580).
        ioc_filter,
        in_cidr_filter,
        in_subsearch_filter,
        in_list_filter,
        regex_match_operator_filter,
        regex_filter,
        wildcard_keyword,
        function_word_comparator_filter,
        word_comparator_filter,
        function_call_expr,
        boolean_function_expr,
        quoted_string_comparison,
        field_filter,
        keyword_search,
    ))
    .parse(input)
}

/// Parse quoted string comparison: "value" = "value" or "value" != "value"
/// This is commonly used for parameter expansion checks like: "$user"="*"
/// When both sides are equal, it evaluates to true (wildcard match pattern)
fn quoted_string_comparison(input: &str) -> ParseResult<'_, SearchExpr> {
    let (input, left) = quoted_string(input)?;
    let (input, _) = multispace0(input)?;
    let (input, op) = comparator(input)?;
    let (input, _) = multispace0(input)?;
    let (input, right) = quoted_string(input)?;

    // Convert to a literal comparison expression
    // This handles patterns like "$user"="*" which is used for conditional filtering
    // SQL generators will convert this to 'left' = 'right' which ClickHouse can evaluate
    Ok((
        input,
        SearchExpr::LiteralComparison {
            left,
            op,
            right: Value::String(right),
        },
    ))
}

/// Parse wildcard keyword: *keyword* (converts to regex search on message)
/// This allows AI-generated queries like *users* to work as expected
fn wildcard_keyword(input: &str) -> ParseResult<'_, SearchExpr> {
    let (input, _) = char('*').parse(input)?;
    // Parse the keyword content (alphanumeric, _, -, .)
    let (input, keyword) =
        take_while1(|c: char| c.is_alphanumeric() || c == '_' || c == '-' || c == '.')
            .parse(input)?;
    let (input, _) = char('*').parse(input)?;

    // Convert *keyword* to a regex search on message
    // The pattern will match the keyword anywhere in the content
    Ok((
        input,
        SearchExpr::FieldFilter {
            field: "message".to_string(),
            op: Comparator::Regex,
            value: Value::Regex(format!("(?i){}", regex::escape(keyword))),
        },
    ))
}

/// Parse function call expression in search context: func(args) op value
fn function_call_expr(input: &str) -> ParseResult<'_, SearchExpr> {
    let (input, name) = take_while1(|c: char| c.is_alphanumeric() || c == '_').parse(input)?;
    let (input, _) = char('(').parse(input)?;
    let (input, _) = multispace0(input)?;
    let (input, args) = separated_list0(
        delimited(multispace0, char(','), multispace0),
        alt((
            // Quoted string as field reference (for fields with spaces)
            map(quoted_string, |f| EvalExpression::Field(f)),
            map(field_name, |f| EvalExpression::Field(f)),
            map(filter_value, |v| EvalExpression::Literal(v)),
        )),
    )
    .parse(input)?;
    let (input, _) = multispace0(input)?;
    let (input, _) = char(')').parse(input)?;
    let (input, _) = multispace0(input)?;
    let (input, op) = comparator(input)?;
    let (input, _) = multispace0(input)?;
    let (input, val) = filter_value(input)?;

    // Create a function call expression
    let func_call = EvalExpression::FunctionCall {
        name: name.to_string(),
        args,
    };

    Ok((
        input,
        SearchExpr::FunctionFilter {
            function: func_call,
            op,
            value: val,
        },
    ))
}

/// Parse standalone boolean function call: isnull(user), like(field, "%pat%"), cidrmatch("10.0.0.0/8", ip)
/// These are function calls used as boolean predicates without an explicit op + value.
fn boolean_function_expr(input: &str) -> ParseResult<'_, SearchExpr> {
    let (input, name) = take_while1(|c: char| c.is_alphanumeric() || c == '_').parse(input)?;

    // Only accept known boolean function names to avoid greedily consuming field names
    let lower = name.to_lowercase();
    let is_boolean_func = matches!(
        lower.as_str(),
        "isnull"
            | "is_null"
            | "isnotnull"
            | "is_not_null"
            | "like"
            | "match"
            | "regex_match"
            | "cidrmatch"
            | "cidr_match"
            | "isnum"
            | "isint"
            | "isstr"
            | "searchmatch"
            | "isbool"
            | "is_private_ip"
            | "isprivateip"
            | "is_public_ip"
            | "ispublicip"
            | "has"
    );
    if !is_boolean_func {
        return Err(nom::Err::Error(nom::error::Error::new(
            input,
            nom::error::ErrorKind::Verify,
        )));
    }

    let (input, _) = char('(').parse(input)?;
    let (input, _) = multispace0(input)?;
    let (input, args) = separated_list0(
        delimited(multispace0, char(','), multispace0),
        alt((
            map(quoted_string, |f| EvalExpression::Literal(Value::String(f))),
            map(field_name, |f| EvalExpression::Field(f)),
            map(filter_value, |v| EvalExpression::Literal(v)),
        )),
    )
    .parse(input)?;
    let (input, _) = multispace0(input)?;
    let (input, _) = char(')').parse(input)?;

    let func_call = EvalExpression::FunctionCall {
        name: name.to_string(),
        args,
    };

    Ok((input, SearchExpr::BooleanFunction(func_call)))
}

/// Parse grouped expression in parentheses
fn grouped_expr(input: &str) -> ParseResult<'_, SearchExpr> {
    let _guard = super::enter_nesting(input)?;
    map(
        delimited(
            pair(char('('), multispace0),
            search_expr,
            pair(multispace0, char(')')),
        ),
        |e| SearchExpr::Group(Box::new(e)),
    )
    .parse(input)
}

/// Parse the `=~` / `!~` regex-match operators: `field =~ "pattern"` / `field !~ "pattern"`.
///
/// NAN-1993: these are aliases for the `field=/pattern/` regex-match filter — they build the
/// SAME AST (`Comparator::Regex` / `NotRegex` + `Value::Regex`), so they reuse the identical,
/// already-safely-escaped (`escape_regex_pattern`) SQL-gen path; no new injection surface. The
/// RHS is a quoted string treated as an (unanchored) regex, matching `=/pattern/` semantics.
/// Registered ahead of `regex_filter`/`field_filter`; it fails through cleanly for `=`, `!=`,
/// and `=/…/` because those don't match the `=~` / `!~` tags.
fn regex_match_operator_filter(input: &str) -> ParseResult<'_, SearchExpr> {
    let (input, field) = field_name(input)?;
    let (input, _) = multispace0(input)?;
    let (input, negated) = alt((value(true, tag("!~")), value(false, tag("=~")))).parse(input)?;
    let (input, _) = multispace0(input)?;
    let (input, pattern) = quoted_string(input)?;

    let op = if negated {
        Comparator::NotRegex
    } else {
        Comparator::Regex
    };

    Ok((
        input,
        SearchExpr::FieldFilter {
            field,
            op,
            value: Value::Regex(pattern),
        },
    ))
}

/// Parse regex filter: field=/pattern/ or field!=/pattern/
/// This parser peeks ahead to check if the value is a complete regex pattern before committing
fn regex_filter(input: &str) -> ParseResult<'_, SearchExpr> {
    // First, peek to see if this looks like a regex filter
    // Pattern: field_name whitespace? (= or !=) whitespace? /...pattern.../
    let check_input = input;

    // Try to parse field name
    let (rest, field) = field_name(check_input)?;
    let (rest, _) = multispace0(rest)?;

    // Try to parse = or !=
    let (rest, negated) = match alt((
        value(true, tag::<&str, &str, nom::error::Error<&str>>("!=")),
        value(false, tag("=")),
    ))
    .parse(rest)
    {
        Ok(r) => r,
        Err(_) => {
            return Err(nom::Err::Error(nom::error::Error::new(
                input,
                nom::error::ErrorKind::Tag,
            )))
        }
    };

    let (rest, _) = multispace0(rest)?;

    // Check if next char is / and if it looks like a complete regex pattern
    if !rest.starts_with('/') {
        return Err(nom::Err::Error(nom::error::Error::new(
            input,
            nom::error::ErrorKind::Tag,
        )));
    }

    // Peek ahead to see if this is a complete regex pattern (has closing /)
    // We need to find the closing / that's not escaped and is not part of a path
    // Use char_indices() to get byte offsets (not character indices) for safe UTF-8 slicing
    let chars = rest[1..].char_indices(); // Skip the opening /
    let mut found_closing = false;
    let mut escaped = false;
    let mut closing_pos = None;

    for (byte_offset, c) in chars {
        if escaped {
            escaped = false;
            continue;
        }

        match c {
            '\\' => escaped = true,
            '/' => {
                // Check if this looks like a regex closing (not followed by more path-like content)
                // byte_offset is relative to rest[1..], so add 1 for the opening /, then add c.len_utf8() to skip current char
                let slice_start = 1 + byte_offset + c.len_utf8();
                if slice_start > rest.len() {
                    found_closing = true;
                    closing_pos = Some(slice_start);
                    break;
                }
                let remaining = &rest[slice_start..];

                // Check for regex flags (i, g, m, s, u, y) immediately after the closing /
                // e.g., /pattern/i or /pattern/gi
                let mut flag_end = 0;
                for (idx, ch) in remaining.char_indices() {
                    if matches!(ch, 'i' | 'g' | 'm' | 's' | 'u' | 'y') {
                        flag_end = idx + ch.len_utf8();
                    } else {
                        break;
                    }
                }
                let after_flags = &remaining[flag_end..];

                // If the next character after / (and flags) is whitespace, end of string, pipe, closing bracket, paren, or AND/OR, it's a regex
                if after_flags.is_empty()
                    || after_flags.starts_with(' ')
                    || after_flags.starts_with('\t')
                    || after_flags.starts_with('|')
                    || after_flags.starts_with(')')  // Closing paren for grouped expressions
                    || after_flags.starts_with(']')  // Closing bracket for sequence conditions
                    || after_flags.starts_with(" AND ")
                    || after_flags.starts_with(" OR ")
                    || after_flags.starts_with(" and ")
                    || after_flags.starts_with(" or ")
                {
                    found_closing = true;
                    closing_pos = Some(slice_start);
                    break;
                }

                // If the FIRST character after / (and any flags) is alphanumeric or path-like, it might be a file path
                // Only check the immediate next character, not further ahead
                // But skip this check if we consumed any flags (clearly a regex)
                if flag_end == 0 {
                    let first_char = after_flags.chars().next();
                    if let Some(ch) = first_char {
                        if ch.is_alphanumeric() || ch == '_' || ch == '-' || ch == '.' || ch == '*'
                        {
                            // This looks like a path component, not the end of a regex
                            break;
                        }
                    }
                }

                found_closing = true;
                closing_pos = Some(slice_start);
                break;
            }
            _ => {}
        }
    }

    if !found_closing {
        return Err(nom::Err::Error(nom::error::Error::new(
            input,
            nom::error::ErrorKind::Tag,
        )));
    }

    // Additional validation: check if the pattern between the slashes looks like a regex
    // and not like a file path
    // We only reject patterns that look like absolute Unix paths (start with common path prefixes)
    if let Some(pos) = closing_pos {
        let pattern_content = &rest[1..pos - 1]; // Extract content between slashes

        // Only reject if it looks like an absolute Unix path (starts with common directories)
        // This allows patterns like /cmd.exe/ or /login/ while rejecting /var/log/ or /etc/passwd/
        let looks_like_unix_path = pattern_content.starts_with("var/")
            || pattern_content.starts_with("etc/")
            || pattern_content.starts_with("usr/")
            || pattern_content.starts_with("home/")
            || pattern_content.starts_with("tmp/")
            || pattern_content.starts_with("opt/")
            || pattern_content.starts_with("bin/")
            || pattern_content.starts_with("sbin/")
            || pattern_content.starts_with("lib/")
            || pattern_content.starts_with("proc/")
            || pattern_content.starts_with("sys/")
            || pattern_content.starts_with("dev/");

        if looks_like_unix_path {
            // This looks like a Unix path, not a regex pattern
            return Err(nom::Err::Error(nom::error::Error::new(
                input,
                nom::error::ErrorKind::Tag,
            )));
        }
    }

    // Now we're committed - parse the regex literal
    let (rest, pattern) = regex_literal(rest)?;

    let op = if negated {
        Comparator::NotRegex
    } else {
        Comparator::Regex
    };

    Ok((
        rest,
        SearchExpr::FieldFilter {
            field,
            op,
            value: Value::Regex(pattern),
        },
    ))
}

/// Parse regex literal: /pattern/ with proper escape handling
pub(super) fn regex_literal(input: &str) -> ParseResult<'_, String> {
    let (input, _) = char('/').parse(input)?;
    let mut result = String::new();
    let mut chars = input.chars().peekable();
    let mut consumed = 0;

    while let Some(c) = chars.next() {
        consumed += c.len_utf8();
        match c {
            '\\' => {
                // Handle escape sequences
                if let Some(&next) = chars.peek() {
                    match next {
                        '/' | '\\' => {
                            // Escaped slash or backslash
                            result.push('\\');
                            result.push(next);
                            chars.next();
                            consumed += next.len_utf8();
                        }
                        _ => {
                            // Keep other escapes as-is (regex escapes like \d, \w, \s)
                            result.push(c);
                        }
                    }
                } else {
                    result.push(c);
                }
            }
            '/' => {
                // End of regex - consume optional flags (i, g, m, s, u, y)
                let remaining = &input[consumed..];
                let mut flag_len = 0;
                let mut flags = String::new();
                for ch in remaining.chars() {
                    if matches!(ch, 'i' | 'g' | 'm' | 's' | 'u' | 'y') {
                        flags.push(ch);
                        flag_len += ch.len_utf8();
                    } else {
                        break;
                    }
                }
                // Prepend inline flags to pattern for ClickHouse (e.g., (?i) for case-insensitive)
                if flags.contains('i') {
                    result = format!("(?i){}", result);
                }
                return Ok((&input[consumed + flag_len..], result));
            }
            _ => {
                result.push(c);
            }
        }
    }

    Err(nom::Err::Error(nom::error::Error::new(
        input,
        nom::error::ErrorKind::Tag,
    )))
}

/// Parse IN list filter: field IN (val1, val2, ...) or field NOT IN (val1, val2, ...)
fn in_list_filter(input: &str) -> ParseResult<'_, SearchExpr> {
    let (input, field) = field_name(input)?;
    let (input, _) = multispace1(input)?;

    // Check for NOT IN or IN
    let (input, negated) = alt((
        value(
            true,
            pair(tag_no_case("NOT"), preceded(multispace1, tag_no_case("IN"))),
        ),
        value(false, tag_no_case("IN")),
    ))
    .parse(input)?;

    let (input, _) = multispace0(input)?;
    let (input, _) = char('(').parse(input)?;
    let (input, _) = multispace0(input)?;

    // Parse comma-separated values
    let (input, values) =
        separated_list1(delimited(multispace0, char(','), multispace0), filter_value)
            .parse(input)?;

    let (input, _) = multispace0(input)?;
    let (input, _) = char(')').parse(input)?;

    Ok((
        input,
        SearchExpr::InList {
            field,
            values,
            negated,
        },
    ))
}

/// Parse the `ioc` observable term (NAN-1580 / NAN-1581 Phase 6). Surface forms:
///   - `ioc = <value>`             -> IocMatch { values: [value] }
///   - `ioc in [v1, v2, ...]`      -> IocMatch { values } (also `( )`)
///   - `ioc in <feed>("arg")`      -> IocMatch { feed: Some(..) }
///     where feed in {threatfox, misp, otx, feodo, abuse}.
///   - `ioc in lookup("name")`     -> IocMatch { lookup: Some(..) }
///   - `ioc in lookup("name","col")` -> IocMatch { lookup: Some(.. column) }
///   - `ioc in [inputlookup name]` -> IocMatch { lookup: Some(..) } (alias)
/// The `ioc` keyword is matched as a whole word (not "ioc_score" etc.). When
/// used without a trailing `| retro` it is still a normal observable-anywhere
/// match — the AST node is reusable on its own. The lookup/feed sources are
/// PRE-RESOLVED to concrete `values` by the service layer before SQL generation.
///
/// Parse a single bare IOC observable value: a quoted string, or a token that
/// runs to whitespace / `|`. Unlike `filter_value`, it does NOT number-match a
/// leading digit — `ioc=5fb90fd…` (a hash, which most are) must capture the
/// WHOLE token, not just the leading `5`. IOC values are compared as strings.
fn ioc_single_value(input: &str) -> ParseResult<'_, Value> {
    alt((
        map(quoted_string, Value::String),
        map(
            take_while1(|c: char| !c.is_whitespace() && c != '|'),
            |s: &str| Value::String(s.to_string()),
        ),
    ))
    .parse(input)
}

/// Parse one IOC value inside a `[ ]` / `( )` list — same as `ioc_single_value`
/// but also stops at the list delimiters `, ] ) [ (`.
fn ioc_list_value(input: &str) -> ParseResult<'_, Value> {
    alt((
        map(quoted_string, Value::String),
        map(
            take_while1(|c: char| {
                !c.is_whitespace()
                    && c != ','
                    && c != ']'
                    && c != ')'
                    && c != '['
                    && c != '('
            }),
            |s: &str| Value::String(s.to_string()),
        ),
    ))
    .parse(input)
}

fn ioc_filter(input: &str) -> ParseResult<'_, SearchExpr> {
    // Match `ioc` as a complete identifier — reject `ioc_foo`, `iocx`, etc.
    let (input, _) = tag_no_case("ioc").parse(input)?;
    if input
        .chars()
        .next()
        .is_some_and(|c| c.is_alphanumeric() || c == '_')
    {
        return Err(nom::Err::Error(nom::error::Error::new(
            input,
            nom::error::ErrorKind::Tag,
        )));
    }

    let (input, _) = multispace0(input)?;

    // Form 1: ioc = <value>
    if let Ok((rest, _)) = char::<&str, nom::error::Error<&str>>('=').parse(input) {
        let (rest, _) = multispace0(rest)?;
        let (rest, val) = ioc_single_value(rest)?;
        return Ok((
            rest,
            SearchExpr::IocMatch {
                values: vec![val],
                feed: None,
                lookup: None,
            },
        ));
    }

    // Forms 2–5 all start with `in`.
    let (input, _) = tag_no_case("in").parse(input)?;
    let (input, _) = multispace1(input)?;

    // Form 2 / alias: ioc in [...]  — either a literal value list, OR the
    // `[inputlookup <name>]` lookup-source alias. Parens accept value lists only.
    let open = input.chars().next();
    if open == Some('[') || open == Some('(') {
        let close = if open == Some('[') { ']' } else { ')' };
        let (after_open, _) = char(open.unwrap()).parse(input)?;
        let (after_open, _) = multispace0(after_open)?;

        // Alias: `ioc in [inputlookup <name>]` → lookup source. Only inside `[ ]`.
        if open == Some('[') {
            if let Ok((rest, _)) =
                tag_no_case::<&str, &str, nom::error::Error<&str>>("inputlookup").parse(after_open)
            {
                let (rest, _) = multispace1(rest)?;
                let (rest, table) = alt((quoted_string, lookup_table_ident)).parse(rest)?;
                let (rest, _) = multispace0(rest)?;
                let (rest, _) = char(']').parse(rest)?;
                return Ok((
                    rest,
                    SearchExpr::IocMatch {
                        values: vec![],
                        feed: None,
                        lookup: Some(IocLookup {
                            table,
                            column: None,
                        }),
                    },
                ));
            }
        }

        // Literal value list.
        let (input, values) = separated_list1(
            delimited(multispace0, char(','), multispace0),
            ioc_list_value,
        )
        .parse(after_open)?;
        let (input, _) = multispace0(input)?;
        let (input, _) = char(close).parse(input)?;
        return Ok((
            input,
            SearchExpr::IocMatch {
                values,
                feed: None,
                lookup: None,
            },
        ));
    }

    // Form 4: ioc in lookup("name") / ioc in lookup("name", "column")
    if let Ok((rest, _)) =
        tag_no_case::<&str, &str, nom::error::Error<&str>>("lookup").parse(input)
    {
        // Guard against a feed/identifier that merely starts with "lookup".
        if !rest
            .chars()
            .next()
            .is_some_and(|c| c.is_alphanumeric() || c == '_')
        {
            let (rest, _) = multispace0(rest)?;
            let (rest, _) = char('(').parse(rest)?;
            let (rest, _) = multispace0(rest)?;
            let (rest, table) = quoted_string(rest)?;
            let (rest, _) = multispace0(rest)?;
            // Optional second arg: the column to read indicator values from.
            let (rest, column) = opt(preceded(
                delimited(multispace0, char(','), multispace0),
                quoted_string,
            ))
            .parse(rest)?;
            let (rest, _) = multispace0(rest)?;
            let (rest, _) = char(')').parse(rest)?;
            return Ok((
                rest,
                SearchExpr::IocMatch {
                    values: vec![],
                    feed: None,
                    lookup: Some(IocLookup { table, column }),
                },
            ));
        }
    }

    // Form 3: ioc in <feed>("arg")
    let (input, feed_name) =
        take_while1(|c: char| c.is_alphanumeric() || c == '_').parse(input)?;
    let lower = feed_name.to_lowercase();
    if !matches!(
        lower.as_str(),
        "threatfox" | "misp" | "otx" | "feodo" | "abuse"
    ) {
        return Err(nom::Err::Error(nom::error::Error::new(
            input,
            nom::error::ErrorKind::Verify,
        )));
    }
    let (input, _) = multispace0(input)?;
    let (input, _) = char('(').parse(input)?;
    let (input, _) = multispace0(input)?;
    let (input, arg) = quoted_string(input)?;
    let (input, _) = multispace0(input)?;
    let (input, _) = char(')').parse(input)?;

    Ok((
        input,
        SearchExpr::IocMatch {
            values: vec![],
            feed: Some(IocFeed {
                name: lower,
                arg,
            }),
            lookup: None,
        },
    ))
}

/// Parse a bare (unquoted) lookup-table identifier for the
/// `[inputlookup <name>]` alias: alphanumerics, `_`, `-`, `.`.
fn lookup_table_ident(input: &str) -> ParseResult<'_, String> {
    map(
        take_while1(|c: char| c.is_alphanumeric() || c == '_' || c == '-' || c == '.'),
        |s: &str| s.to_string(),
    )
    .parse(input)
}

/// Parse word-based comparators: field LIKE "pattern", field CONTAINS "value", etc.
fn word_comparator_filter(input: &str) -> ParseResult<'_, SearchExpr> {
    let (input, field) = field_name(input)?;
    let (input, _) = multispace1(input)?;

    // Parse the word-based operator (NOT variants must come before positive variants for longest-match)
    let (input, op) = alt((
        value(
            Comparator::NotLike,
            pair(
                tag_no_case("NOT"),
                preceded(multispace1, tag_no_case("LIKE")),
            ),
        ),
        value(
            Comparator::NotContains,
            pair(
                tag_no_case("NOT"),
                preceded(multispace1, tag_no_case("CONTAINS")),
            ),
        ),
        value(
            Comparator::NotStartsWith,
            pair(
                tag_no_case("NOT"),
                preceded(multispace1, tag_no_case("STARTSWITH")),
            ),
        ),
        value(
            Comparator::NotEndsWith,
            pair(
                tag_no_case("NOT"),
                preceded(multispace1, tag_no_case("ENDSWITH")),
            ),
        ),
        value(Comparator::Like, tag_no_case("LIKE")),
        value(Comparator::Contains, tag_no_case("CONTAINS")),
        value(Comparator::StartsWith, tag_no_case("STARTSWITH")),
        value(Comparator::EndsWith, tag_no_case("ENDSWITH")),
    ))
    .parse(input)?;

    let (input, _) = multispace1(input)?;
    let (input, val) = filter_value(input)?;

    Ok((
        input,
        SearchExpr::FieldFilter {
            field,
            op,
            value: val,
        },
    ))
}

/// Parse field filter: field op value or field op function(args)
///
/// For simple values (strings, numbers, IPs, etc.), we use filter_value which treats
/// unquoted identifiers as string literals (e.g., source_type=squid_proxy).
/// For function calls and expressions (e.g., field > now() - INTERVAL 1 DAY), we use eval_expression.
/// Supports quoted field names for fields with spaces.
fn field_filter(input: &str) -> ParseResult<'_, SearchExpr> {
    let (input, field) = alt((quoted_string, field_name)).parse(input)?;
    let (input, _) = multispace0(input)?;
    let (input, op) = comparator(input)?;
    let (input, _) = multispace0(input)?;

    let field_str = field.to_string();

    // Check if the right-hand side starts with a function call (identifier followed by parenthesis)
    // This handles cases like: field > now() - INTERVAL 1 DAY
    // We need to peek ahead to see if this looks like a function call
    let trimmed = input.trim_start();
    let first_char = trimmed.chars().next();

    let looks_like_function = {
        if let Some(c) = first_char {
            if c.is_alphabetic() || c == '_' {
                // Find where the identifier ends
                let id_end = trimmed
                    .chars()
                    .take_while(|c| c.is_alphanumeric() || *c == '_')
                    .count();
                // Check if followed by '('
                trimmed.chars().nth(id_end) == Some('(')
            } else {
                false
            }
        } else {
            false
        }
    };

    if looks_like_function {
        // Parse as a full eval expression (handles function calls with operators like now() - INTERVAL 1 DAY)
        let (input, expr) = eval_expression(input)?;
        return Ok((
            input,
            SearchExpr::FieldFunctionFilter {
                field: field_str,
                op,
                function: expr,
            },
        ));
    }

    // Comparison operators (>, <, >=, <=) get special handling for RHS expressions.
    // For = and !=, the common case is field=value where value is a string literal.
    let is_comparison_op = matches!(
        op,
        Comparator::Gt | Comparator::Lt | Comparator::Gte | Comparator::Lte
    );

    // Check if RHS starts with '(' — parenthesized arithmetic expression
    // e.g., response_time > (avg_time + (3 * std_time))
    // Only for comparison operators to avoid changing semantics of
    // field=(value) which should remain a string literal match, not a field reference.
    let looks_like_paren_expr = is_comparison_op && first_char == Some('(');

    if looks_like_paren_expr {
        let (input, expr) = eval_expression(input)?;
        return Ok((
            input,
            SearchExpr::FieldFunctionFilter {
                field: field_str,
                op,
                function: expr,
            },
        ));
    }

    // Check if RHS is a bare identifier (could be a field reference like: first_seen > time_threshold)
    // This handles cases like: `where first_seen > time_threshold` or `where count >= min_count`
    // For field-to-field equality, use eval: `| eval same = (field1 = field2)`

    let looks_like_field_ref = is_comparison_op && {
        if let Some(c) = first_char {
            // Must start with letter or underscore (not a digit, not a quote)
            if c.is_alphabetic() || c == '_' {
                // Extract the identifier
                let id: String = trimmed
                    .chars()
                    .take_while(|c| c.is_alphanumeric() || *c == '_')
                    .collect();
                // Check it's not a boolean keyword or interval
                let upper = id.to_uppercase();
                if upper == "TRUE" || upper == "FALSE" || upper.starts_with("INTERVAL") {
                    false
                } else {
                    // Check what follows - should be end of input or whitespace/pipe/paren/logical operator
                    let rest = &trimmed[id.len()..];
                    rest.is_empty()
                        || rest.starts_with(|c: char| c.is_whitespace())
                        || rest.starts_with('|')
                        || rest.starts_with(')')
                        || rest.starts_with("AND")
                        || rest.starts_with("OR")
                }
            } else {
                false
            }
        } else {
            false
        }
    };

    if looks_like_field_ref {
        // Parse as a field reference using eval expression
        // This handles cases like: where first_seen > time_threshold
        let (input, expr) = eval_expression(input)?;
        return Ok((
            input,
            SearchExpr::FieldFunctionFilter {
                field: field_str,
                op,
                function: expr,
            },
        ));
    }

    // Otherwise, parse as a simple filter value (number, IP, bool, interval, quoted string)
    let (input, value) = filter_value(input)?;

    Ok((
        input,
        SearchExpr::FieldFilter {
            field: field_str,
            op,
            value,
        },
    ))
}

/// Parse function call with word-based comparator: func(args) LIKE/CONTAINS/etc value
/// Handles cases like: lower(user) LIKE "%admin%"
fn function_word_comparator_filter(input: &str) -> ParseResult<'_, SearchExpr> {
    let (input, name) = take_while1(|c: char| c.is_alphanumeric() || c == '_').parse(input)?;
    let (input, _) = char('(').parse(input)?;
    let (input, _) = multispace0(input)?;
    let (input, args) = separated_list0(
        delimited(multispace0, char(','), multispace0),
        alt((
            map(quoted_string, |f| EvalExpression::Field(f)),
            map(field_name, |f| EvalExpression::Field(f)),
            map(filter_value, |v| EvalExpression::Literal(v)),
        )),
    )
    .parse(input)?;
    let (input, _) = multispace0(input)?;
    let (input, _) = char(')').parse(input)?;
    let (input, _) = multispace1(input)?;

    // Parse word-based operator
    let (input, op) = alt((
        value(
            Comparator::NotLike,
            pair(
                tag_no_case("NOT"),
                preceded(multispace1, tag_no_case("LIKE")),
            ),
        ),
        value(
            Comparator::NotContains,
            pair(
                tag_no_case("NOT"),
                preceded(multispace1, tag_no_case("CONTAINS")),
            ),
        ),
        value(Comparator::Like, tag_no_case("LIKE")),
        value(Comparator::Contains, tag_no_case("CONTAINS")),
    ))
    .parse(input)?;

    let (input, _) = multispace1(input)?;
    let (input, val) = filter_value(input)?;

    let func_call = EvalExpression::FunctionCall {
        name: name.to_string(),
        args,
    };

    Ok((
        input,
        SearchExpr::FunctionFilter {
            function: func_call,
            op,
            value: val,
        },
    ))
}

/// Parse IN [search ...] subsearch filter: field IN [search ...] or field NOT IN [search ...]
fn in_subsearch_filter(input: &str) -> ParseResult<'_, SearchExpr> {
    // NAN-2010 (F10): a nested `field IN [ field IN [ … ] ]` chain recurses
    // through `query` once per bracket. Count it toward MAX_NESTING_DEPTH — the
    // guard otherwise only wraps parenthesized groups, so bracket nesting drove
    // unbounded recursive-descent stack depth (uncatchable overflow).
    let _guard = super::enter_nesting(input)?;
    let (input, field) = field_name(input)?;
    let (input, _) = multispace1(input)?;

    let (input, negated) = alt((
        value(
            true,
            pair(tag_no_case("NOT"), preceded(multispace1, tag_no_case("IN"))),
        ),
        value(false, tag_no_case("IN")),
    ))
    .parse(input)?;

    let (input, _) = multispace0(input)?;
    let (input, _) = char('[').parse(input)?;
    let (input, _) = multispace0(input)?;

    // NAN-1562: optional leading `dataset=<logs|spans|metrics>` (or `from=`)
    // token scopes the IN subsearch to a different dataset (cross-dataset semi-join).
    let (input, subsearch_dataset) =
        opt(super::commands_extended::subsearch_dataset_token).parse(input)?;
    let (input, _) = multispace0(input)?;

    // Forward-declare query parser for recursive subsearch
    fn query(input: &str) -> super::ParseResult<'_, Query> {
        super::query(input)
    }

    let (input, subsearch) = query(input)?;
    let (input, _) = multispace0(input)?;
    let (input, _) = char(']').parse(input)?;

    Ok((
        input,
        SearchExpr::InSubsearch {
            field,
            subsearch: Box::new(subsearch),
            negated,
            subsearch_dataset,
        },
    ))
}

/// Parse NOT IN CIDR(...) filter: field [NOT] IN CIDR("cidr1", "cidr2", ...)
/// Transforms into a BooleanFunction wrapping cidr_match calls
fn in_cidr_filter(input: &str) -> ParseResult<'_, SearchExpr> {
    let (input, field) = field_name(input)?;
    let (input, _) = multispace1(input)?;

    let (input, negated) = alt((
        value(
            true,
            pair(tag_no_case("NOT"), preceded(multispace1, tag_no_case("IN"))),
        ),
        value(false, tag_no_case("IN")),
    ))
    .parse(input)?;

    let (input, _) = multispace0(input)?;
    let (input, _) = tag_no_case("CIDR").parse(input)?;
    let (input, _) = char('(').parse(input)?;
    let (input, _) = multispace0(input)?;

    let (input, cidrs) =
        separated_list1(delimited(multispace0, char(','), multispace0), filter_value)
            .parse(input)?;

    let (input, _) = multispace0(input)?;
    let (input, _) = char(')').parse(input)?;

    // Build cidr_match(field, cidr) function call args
    let mut args = vec![EvalExpression::Field(field)];
    for cidr in cidrs {
        args.push(EvalExpression::Literal(cidr));
    }

    let func_call = EvalExpression::FunctionCall {
        name: "cidr_match".to_string(),
        args,
    };

    let expr = SearchExpr::BooleanFunction(func_call);
    if negated {
        Ok((input, SearchExpr::Not(Box::new(expr))))
    } else {
        Ok((input, expr))
    }
}

/// Parse a keyword (for keyword search)
fn keyword_search(input: &str) -> ParseResult<'_, SearchExpr> {
    map(keyword, SearchExpr::Keyword).parse(input)
}

/// Parse a single keyword
pub(super) fn keyword(input: &str) -> ParseResult<'_, String> {
    alt((quoted_string, url_keyword_string, unquoted_keyword)).parse(input)
}

/// Parse a URL as a keyword string (http:// or https:// followed by URL characters)
fn url_keyword_string(input: &str) -> ParseResult<'_, String> {
    let (remaining, scheme) = alt((tag("https://"), tag("http://"))).parse(input)?;
    let (remaining, rest) = nom::bytes::complete::take_while(|c: char| {
        !c.is_whitespace() && c != '|' && c != ')' && c != '('
    })
    .parse(remaining)?;
    Ok((remaining, format!("{}{}", scheme, rest)))
}

/// Parse unquoted keyword (alphanumeric, _, -, ., *, ?)
/// Excludes reserved words: AND, OR, NOT
pub(super) fn unquoted_keyword(input: &str) -> ParseResult<'_, String> {
    let (remaining, s) = take_while1(|c: char| {
        c.is_alphanumeric() || c == '_' || c == '-' || c == '.' || c == '*' || c == '?'
    })
    .parse(input)?;

    // Check if it's a reserved word
    let upper = s.to_uppercase();
    if upper == "AND" || upper == "OR" || upper == "NOT" {
        return Err(nom::Err::Error(nom::error::Error::new(
            input,
            nom::error::ErrorKind::Tag,
        )));
    }

    Ok((remaining, s.to_string()))
}
