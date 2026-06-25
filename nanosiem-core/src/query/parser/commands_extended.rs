// SPDX-License-Identifier: AGPL-3.0-or-later

//! Extended command parsers for the query parser
//!
//! Handles: dedup, bin, rex, regex, fields, top, rare, transaction,
//! fillnull, mvexpand, spath, append, join, format, return.

use nom::{
    branch::alt,
    bytes::complete::{tag, tag_no_case},
    character::complete::{alpha1, char, digit1, multispace0, multispace1, one_of},
    combinator::{map, map_res, opt, peek, recognize, value},
    multi::separated_list1,
    sequence::{delimited, pair, preceded, terminated},
    Parser,
};
use std::time::Duration;

use super::commands_core::{duration, field_list};
use super::search_expr::{parse_paren_search_expr, search_expr, unquoted_keyword};
use super::values::{field_name, field_name_with_wildcard, quoted_string};
use super::ParseResult;
use crate::query::ast::*;

// Forward-declare query for subsearch parsing
use super::query;

/// Parse dedup command: dedup [N] field1, field2, ... [keepfirst=true|false] [sortby [-|+]field, ...]
/// Also accepts "uniq" as an alias for Unix familiarity.
/// The optional leading N (numeric count) is parsed and ignored (AST has no count field).
/// The optional trailing `sortby` clause is parsed and ignored (AST has no sort field).
pub(super) fn dedup_command(input: &str) -> ParseResult<'_, Command> {
    let (input, _) = alt((tag_no_case("dedup"), tag_no_case("uniq"))).parse(input)?;
    let (input, _) = multispace1(input)?;

    // Parse optional leading count N (e.g., "dedup 3 src_ip") — parsed and ignored
    let (input, _count) = opt(terminated(
        map_res(digit1, |s: &str| s.parse::<usize>()),
        multispace1,
    ))
    .parse(input)?;

    let (input, fields) = field_list(input)?;

    // Parse optional keepfirst/keeplast parameter
    let (input, keep_first) = opt(preceded(
        multispace1,
        alt((
            value(true, tag_no_case("keepfirst=true")),
            value(false, tag_no_case("keepfirst=false")),
            value(false, tag_no_case("keeplast=true")),
            value(true, tag_no_case("keeplast=false")),
        )),
    ))
    .parse(input)?;

    // Parse optional sortby clause — parsed and ignored (AST doesn't support it)
    // Syntax: sortby [-|+]field, [-|+]field2, ...
    let (input, _sortby) = opt(preceded(
        delimited(multispace1, tag_no_case("sortby"), multispace1),
        dedup_sortby_fields,
    ))
    .parse(input)?;

    Ok((
        input,
        Command::Dedup {
            fields,
            keep_first: keep_first.unwrap_or(true), // Default to keeping first
        },
    ))
}

/// Parse the sort field list for dedup's sortby clause.
/// Accepts comma or space-separated [-|+]field entries.
fn dedup_sortby_fields(input: &str) -> ParseResult<'_, Vec<String>> {
    let (mut input, first) = sort_field_for_dedup(input)?;
    let mut fields = vec![first];

    loop {
        let comma: Result<(&str, char), nom::Err<nom::error::Error<&str>>> =
            delimited(multispace0, char(','), multispace0).parse(input);
        if let Ok((rest, _)) = comma {
            if let Ok((rest2, f)) = sort_field_for_dedup(rest) {
                fields.push(f);
                input = rest2;
                continue;
            }
        }
        let space: Result<(&str, &str), nom::Err<nom::error::Error<&str>>> = multispace1(input);
        if let Ok((rest, _)) = space {
            if let Ok((rest2, f)) = sort_field_for_dedup(rest) {
                fields.push(f);
                input = rest2;
                continue;
            }
        }
        break;
    }

    Ok((input, fields))
}

/// Parse a sort field for dedup's sortby clause: [-|+]field_name
/// Returns the field name (direction is ignored since we discard sortby).
fn sort_field_for_dedup(input: &str) -> ParseResult<'_, String> {
    let (input, _) = opt(one_of("-+")).parse(input)?;
    field_name(input)
}

/// Parse bin command: bin [field] span=<duration|number> [field] [as alias]
/// Also accepts "bucket" as an alias.
/// Creates time buckets or numeric bins for aggregation
/// Supports both syntaxes: field before OR after span
/// Examples:
///   | bin span=10m                           -- bucket _time into 10-minute windows
///   | bin _time span=5m                      -- explicit _time field (field before span)
///   | bin span=1h _time                      -- explicit _time field (field after span)
///   | bin bytes_out span=5000                -- numeric binning (field before span)
///   | bin span=5000 bytes_out                -- numeric binning (field after span)
///   | bin _time span=5m as time_window       -- with alias
///   | bin span=1h hop=5m                     -- hop window (1h windows, advancing every 5m)
///   | bin span=1h sliding                    -- sliding window (1h window per event)
pub(super) fn bin_command(input: &str) -> ParseResult<'_, Command> {
    let (input, _) = alt((tag_no_case("bucket"), tag_no_case("bin"))).parse(input)?;
    let (input, _) = multispace1(input)?;

    // Try to parse optional field name first (PPL syntax: bin _time span=5m)
    // Field is NOT followed by "=" (to distinguish from span=)
    let (input, field_before) = opt(terminated(
        field_name,
        // Lookahead: must be followed by whitespace (not "=")
        peek(multispace1),
    ))
    .parse(input)?;

    // Skip whitespace if we parsed a field
    let input = if field_before.is_some() {
        multispace0(input)?.0
    } else {
        input
    };

    // Parse span=duration|number OR bins=N (one is required)
    let (input, span) = alt((
        bin_span_spec,
        // bins=N — use a placeholder Numeric(1.0); execution layer computes actual span
        map(
            preceded(
                tag_no_case("bins="),
                map_res(digit1, |s: &str| s.parse::<f64>()),
            ),
            |_n| BinSpan::Numeric(1.0),
        ),
    ))
    .parse(input)?;

    // Parse optional window type parameters in any order: hop=, sliding, field, as
    let mut hop_advance: Option<Duration> = None;
    let mut is_sliding = false;
    let mut field_after: Option<String> = None;
    let mut alias: Option<String> = None;

    let mut remaining = input;

    loop {
        // Try to consume whitespace
        let (input, ws) = multispace0(remaining)?;
        if ws.is_empty() && !remaining.is_empty() && remaining != input {
            break;
        }
        remaining = input;

        // Check if we're at end or pipe
        if remaining.is_empty() || remaining.starts_with('|') {
            break;
        }

        // Try parsing hop=duration
        if let Ok((input, _)) =
            tag_no_case::<_, _, nom::error::Error<&str>>("hop=").parse(remaining)
        {
            if hop_advance.is_some() {
                break; // Already parsed
            }
            let (input, dur) = duration(input)?;
            hop_advance = Some(dur);
            remaining = input;
            continue;
        }

        // Try parsing "sliding" keyword
        if let Ok((input, _)) =
            tag_no_case::<_, _, nom::error::Error<&str>>("sliding").parse(remaining)
        {
            // Make sure it's followed by whitespace, pipe, or end
            if input.is_empty() || input.starts_with(|c: char| c.is_whitespace() || c == '|') {
                is_sliding = true;
                remaining = input;
                continue;
            }
        }

        // Try parsing "as <alias>"
        if let Ok((input, _)) = tag_no_case::<_, _, nom::error::Error<&str>>("as").parse(remaining)
        {
            if let Ok((input, _)) = multispace1::<_, nom::error::Error<&str>>(input) {
                if let Ok((input, parsed_alias)) = field_name(input) {
                    if alias.is_none() {
                        alias = Some(parsed_alias.to_string());
                        remaining = input;
                        continue;
                    }
                }
            }
        }

        // Try parsing field=<name> parameter
        if let Ok((input, _)) =
            tag_no_case::<_, _, nom::error::Error<&str>>("field=").parse(remaining)
        {
            if field_after.is_none() {
                if let Ok((input, f)) = field_name(input) {
                    field_after = Some(f.to_string());
                    remaining = input;
                    continue;
                }
            }
        }

        // Try parsing field name (not a keyword)
        if let Ok((input, f)) = field_name(remaining) {
            // Skip if it's a keyword or contains =
            if !f.eq_ignore_ascii_case("as")
                && !f.eq_ignore_ascii_case("hop")
                && !f.eq_ignore_ascii_case("sliding")
                && !f.contains('=')
                && field_after.is_none()
            {
                field_after = Some(f.to_string());
                remaining = input;
                continue;
            }
        }

        break; // No more recognized parameters
    }

    // Use field_before if provided, otherwise field_after (field can appear in either position)
    let field = field_before.map(|s| s.to_string()).or(field_after);

    // Determine window type
    let window_type = if is_sliding {
        WindowType::Sliding
    } else if let Some(advance) = hop_advance {
        WindowType::Hop { advance }
    } else {
        WindowType::Tumbling
    };

    Ok((
        remaining,
        Command::Bin {
            span,
            field,
            alias,
            window_type,
        },
    ))
}

/// Parse bin span specification: span=<duration|number>
/// Supports both time durations (10m, 1h) and numeric values (5000, 100.5)
fn bin_span_spec(input: &str) -> ParseResult<'_, BinSpan> {
    let (input, _) = tag_no_case("span").parse(input)?;
    let (input, _) = char('=').parse(input)?;

    // Try to parse as time duration first (has unit suffix)
    // If that fails, parse as numeric value
    alt((
        map(duration, BinSpan::Time),
        map(
            map_res(recognize((digit1, opt((char('.'), digit1)))), |s: &str| {
                s.parse::<f64>()
            }),
            BinSpan::Numeric,
        ),
    ))
    .parse(input)
}

/// Parse rex command: rex [mode=sed] [field=<field>] "pattern" [mode=sed "replacement"]
/// Also accepts "extract" as an alias.
/// `mode=sed` can appear before or after `field=`, and the sed expression can be
/// a single "s/pattern/replacement/flags" string.
/// Examples:
///   | rex field=message "(?<user>\w+)@(?<domain>\w+)"
///   | rex "(?<ip>\d+\.\d+\.\d+\.\d+)"
///   | rex mode=sed field=message "s/password=[^ ]*/REDACTED/g"
///   | rex field=message "pattern" mode=sed "replacement"
pub(super) fn rex_command(input: &str) -> ParseResult<'_, Command> {
    let (input, _) = alt((tag_no_case("extract"), tag_no_case("rex"))).parse(input)?;
    let (input, _) = multispace1(input)?;

    // Parse optional mode=sed and field= in any order.
    let mut is_sed_mode = false;
    let mut field: Option<String> = None;
    let mut remaining = input;

    // Try up to 2 optional params before the pattern string
    for _ in 0..2 {
        // Try mode=sed
        if let Ok((rest, _)) = terminated(
            tag_no_case::<_, _, nom::error::Error<&str>>("mode=sed"),
            multispace1,
        )
        .parse(remaining)
        {
            is_sed_mode = true;
            remaining = rest;
            continue;
        }
        // Try field=<name>
        if let Ok((rest, f)) = terminated(
            preceded(
                pair(
                    tag_no_case::<_, _, nom::error::Error<&str>>("field="),
                    multispace0,
                ),
                field_name,
            ),
            multispace1,
        )
        .parse(remaining)
        {
            field = Some(f);
            remaining = rest;
            continue;
        }
        break;
    }
    let input = remaining;

    // Parse the pattern string (quoted)
    let (input, pattern_str) = quoted_string(input)?;

    // Parse optional max_match=N — parsed and ignored (AST doesn't support it)
    let (input, _max_match) = opt(preceded(
        multispace1,
        preceded(
            tag_no_case("max_match="),
            map_res(digit1, |s: &str| s.parse::<usize>()),
        ),
    ))
    .parse(input)?;

    // Determine mode:
    // 1. If mode=sed was already set, parse pattern_str as sed expression "s/old/new/flags"
    // 2. Otherwise, check for trailing mode=sed "replacement" (our extended syntax)
    let (input, mode) = if is_sed_mode {
        // Parse the inline sed expression: "s/pattern/replacement/flags"
        let (pat, replacement) = parse_sed_expression(&pattern_str);
        (
            input,
            RexMode::Sed {
                pattern: pat,
                replacement,
            },
        )
    } else {
        // Check for trailing mode=sed "replacement" (extended syntax)
        let trailing: Result<(&str, String), nom::Err<nom::error::Error<&str>>> = preceded(
            delimited(multispace1, tag_no_case("mode=sed"), multispace1),
            quoted_string,
        )
        .parse(input);
        match trailing {
            Ok((rest, replacement)) => (
                rest,
                RexMode::Sed {
                    pattern: pattern_str.clone(),
                    replacement,
                },
            ),
            Err(_) => (input, RexMode::Extract),
        }
    };

    let pattern = match &mode {
        RexMode::Sed { pattern, .. } => pattern.clone(),
        RexMode::Extract => pattern_str,
    };

    Ok((
        input,
        Command::Rex {
            field,
            pattern,
            mode,
        },
    ))
}

/// Parse a sed expression like "s/pattern/replacement/flags" into (pattern, replacement).
/// Handles arbitrary delimiters: s|old|new|g, s#old#new#, etc.
/// Handles escaped delimiters: s/foo\/bar/baz/g correctly splits on unescaped delimiters.
fn parse_sed_expression(expr: &str) -> (String, String) {
    let trimmed = expr.trim();
    // Must start with s or S followed by a delimiter
    if trimmed.len() < 4 || (!trimmed.starts_with('s') && !trimmed.starts_with('S')) {
        return (trimmed.to_string(), String::new());
    }
    let delim = trimmed.chars().nth(1).unwrap();
    let rest = &trimmed[2..];

    // Find unescaped delimiter positions to correctly split pattern/replacement/flags
    let parts = split_on_unescaped(rest, delim);
    match parts.len() {
        0 => (rest.to_string(), String::new()),
        1 => (parts[0].clone(), String::new()),
        _ => (parts[0].clone(), parts[1].clone()),
    }
}

/// Split a string on an unescaped delimiter character.
/// Backslash-escaped delimiters (e.g., `\/` when delim is `/`) are treated as literal.
fn split_on_unescaped(s: &str, delim: char) -> Vec<String> {
    let mut parts = Vec::new();
    let mut current = String::new();
    let mut chars = s.chars().peekable();

    while let Some(c) = chars.next() {
        if c == '\\' {
            // Escaped character — consume the next char literally
            current.push(c);
            if let Some(&next) = chars.peek() {
                current.push(next);
                chars.next();
            }
        } else if c == delim {
            parts.push(current);
            current = String::new();
        } else {
            current.push(c);
        }
    }
    parts.push(current);
    parts
}

/// Parse regex command: regex field="pattern" or regex field!="pattern"
/// Desugars to Where { condition } — no new AST node needed.
/// Syntax: regex field="pattern" | regex field!="pattern" | regex "pattern" (matches message)
pub(super) fn regex_command(input: &str) -> ParseResult<'_, Command> {
    let (input, _) = tag_no_case("regex").parse(input)?;
    let (input, _) = multispace1(input)?;

    // Try field= or field!= prefix, otherwise default to message
    let (input, field, negated) = match opt(pair(
        field_name,
        alt((
            value(true, tag::<&str, &str, nom::error::Error<&str>>("!=")),
            value(false, tag("=")),
        )),
    ))
    .parse(input)?
    {
        (rest, Some((f, neg))) => (rest, f, neg),
        (rest, None) => (rest, "message".to_string(), false),
    };

    let (input, pattern) = quoted_string(input)?;

    let op = if negated {
        Comparator::NotRegex
    } else {
        Comparator::Regex
    };
    let condition = SearchExpr::FieldFilter {
        field,
        op,
        value: Value::Regex(pattern),
    };
    Ok((input, Command::Where { condition }))
}

/// Parse fields command: fields [+|-] field1, field2, ...
/// Supports wildcard patterns like src_*, dest_*, *_time, _*
/// Examples:
///   | fields src_ip, dest_ip, user
///   | fields + src_ip, dest_ip
///   | fields - message, metadata
///   | fields src_*, dest_*
///   | fields - _*, metadata
pub(super) fn fields_command(input: &str) -> ParseResult<'_, Command> {
    let (input, _) = tag_no_case("fields").parse(input)?;
    let (input, _) = multispace1(input)?;

    // Parse optional +/- prefix
    let (input, keep) = map(opt(terminated(one_of("+-"), multispace0)), |c| {
        c != Some('-')
    })
    .parse(input)?;

    // Parse field list with wildcard support (comma or space-separated)
    let (mut input, first) = field_name_with_wildcard(input)?;
    let mut fields = vec![first];

    loop {
        let comma: Result<(&str, char), nom::Err<nom::error::Error<&str>>> =
            delimited(multispace0, char(','), multispace0).parse(input);
        if let Ok((rest, _)) = comma {
            if let Ok((rest2, field)) = field_name_with_wildcard(rest) {
                fields.push(field);
                input = rest2;
                continue;
            }
        }

        let space: Result<(&str, &str), nom::Err<nom::error::Error<&str>>> = multispace1(input);
        if let Ok((rest, _)) = space {
            if let Ok((rest2, field)) = field_name_with_wildcard(rest) {
                fields.push(field);
                input = rest2;
                continue;
            }
        }

        break;
    }

    Ok((input, Command::Fields { fields, keep }))
}

/// Parse top command: top [limit=N | N] field [by field2] [showcount=bool] [showperc=bool]
/// Examples:
///   | top src_ip
///   | top 20 dest_host       (PPL shorthand - limit as first arg)
///   | top limit=20 user by action
pub(super) fn top_command(input: &str) -> ParseResult<'_, Command> {
    let (input, _) = tag_no_case("top").parse(input)?;
    let (input, _) = multispace1(input)?;

    // Parse optional limit - supports both "limit=N" and just "N" (PPL shorthand)
    let (input, limit) = opt(alt((
        // Format: limit=N
        terminated(
            preceded(
                pair(tag_no_case("limit"), char('=')),
                map_res(digit1, |s: &str| s.parse::<usize>()),
            ),
            multispace1,
        ),
        // Format: just N (PPL shorthand)
        terminated(map_res(digit1, |s: &str| s.parse::<usize>()), multispace1),
    )))
    .parse(input)?;

    // Parse field list (comma or space-separated). AST only supports one field,
    // so we take the first and ignore extras. This lets multi-field queries parse.
    let (input, fields) = top_rare_field_list(input)?;
    let field = fields.into_iter().next().unwrap_or_default();

    // Parse optional by clause (comma-separated fields)
    let (input, by_fields) = map(
        opt(preceded(
            delimited(multispace1, tag_no_case("by"), multispace1),
            field_list,
        )),
        |opt| opt.unwrap_or_default(),
    )
    .parse(input)?;

    // Parse optional trailing parameters in any order: showcount=, showperc=, limit=
    let mut show_count = true;
    let mut show_percent = true;
    let mut final_limit = limit;
    let mut input = input;

    loop {
        let ws: Result<(&str, &str), nom::Err<nom::error::Error<&str>>> = multispace1(input);
        let rest = match ws {
            Ok((rest, _)) => rest,
            Err(_) => break,
        };
        if rest.is_empty() || rest.starts_with('|') {
            break;
        }

        if let Ok((r, _)) = tag_no_case::<_, _, nom::error::Error<&str>>("showcount=").parse(rest) {
            if let Ok((r, val)) = alt((
                value(false, tag_no_case::<_, _, nom::error::Error<&str>>("false")),
                value(true, tag_no_case("true")),
            ))
            .parse(r)
            {
                show_count = val;
                input = r;
                continue;
            }
        }
        if let Ok((r, _)) = tag_no_case::<_, _, nom::error::Error<&str>>("showperc=").parse(rest) {
            if let Ok((r, val)) = alt((
                value(false, tag_no_case::<_, _, nom::error::Error<&str>>("false")),
                value(true, tag_no_case("true")),
            ))
            .parse(r)
            {
                show_percent = val;
                input = r;
                continue;
            }
        }
        if final_limit.is_none() {
            if let Ok((r, _)) = tag_no_case::<_, _, nom::error::Error<&str>>("limit=").parse(rest) {
                if let Ok((r, n)) = map_res(digit1::<_, nom::error::Error<&str>>, |s: &str| {
                    s.parse::<usize>()
                })
                .parse(r)
                {
                    final_limit = Some(n);
                    input = r;
                    continue;
                }
            }
        }
        break;
    }

    Ok((
        input,
        Command::Top {
            field,
            limit: final_limit.unwrap_or(10),
            by_fields,
            show_count,
            show_percent,
        },
    ))
}

/// Parse rare command: rare [limit=N | N] field [by field1, field2]
/// Examples:
///   | rare status
///   | rare 5 action             (PPL shorthand - limit as first arg)
///   | rare limit=5 action by user, src_ip
pub(super) fn rare_command(input: &str) -> ParseResult<'_, Command> {
    let (input, _) = tag_no_case("rare").parse(input)?;
    let (input, _) = multispace1(input)?;

    // Parse optional limit - supports both "limit=N" and just "N" (PPL shorthand)
    let (input, limit) = opt(alt((
        // Format: limit=N
        terminated(
            preceded(
                pair(tag_no_case("limit"), char('=')),
                map_res(digit1, |s: &str| s.parse::<usize>()),
            ),
            multispace1,
        ),
        // Format: just N (PPL shorthand)
        terminated(map_res(digit1, |s: &str| s.parse::<usize>()), multispace1),
    )))
    .parse(input)?;

    // Parse field list (comma or space-separated). AST only supports one field,
    // so we take the first and ignore extras. This lets multi-field queries parse.
    let (input, fields) = top_rare_field_list(input)?;
    let field = fields.into_iter().next().unwrap_or_default();

    // Parse optional by clause (comma-separated fields)
    let (input, by_fields) = map(
        opt(preceded(
            delimited(multispace1, tag_no_case("by"), multispace1),
            field_list,
        )),
        |opt| opt.unwrap_or_default(),
    )
    .parse(input)?;

    // Parse optional trailing parameters in any order: showcount=, showperc=, limit=
    let mut show_count = true;
    let mut show_percent = true;
    let mut final_limit = limit;
    let mut input = input;

    loop {
        let ws: Result<(&str, &str), nom::Err<nom::error::Error<&str>>> = multispace1(input);
        let rest = match ws {
            Ok((rest, _)) => rest,
            Err(_) => break,
        };
        if rest.is_empty() || rest.starts_with('|') {
            break;
        }

        if let Ok((r, _)) = tag_no_case::<_, _, nom::error::Error<&str>>("showcount=").parse(rest) {
            if let Ok((r, val)) = alt((
                value(false, tag_no_case::<_, _, nom::error::Error<&str>>("false")),
                value(true, tag_no_case("true")),
            ))
            .parse(r)
            {
                show_count = val;
                input = r;
                continue;
            }
        }
        if let Ok((r, _)) = tag_no_case::<_, _, nom::error::Error<&str>>("showperc=").parse(rest) {
            if let Ok((r, val)) = alt((
                value(false, tag_no_case::<_, _, nom::error::Error<&str>>("false")),
                value(true, tag_no_case("true")),
            ))
            .parse(r)
            {
                show_percent = val;
                input = r;
                continue;
            }
        }
        if final_limit.is_none() {
            if let Ok((r, _)) = tag_no_case::<_, _, nom::error::Error<&str>>("limit=").parse(rest) {
                if let Ok((r, n)) = map_res(digit1::<_, nom::error::Error<&str>>, |s: &str| {
                    s.parse::<usize>()
                })
                .parse(r)
                {
                    final_limit = Some(n);
                    input = r;
                    continue;
                }
            }
        }
        break;
    }

    Ok((
        input,
        Command::Rare {
            field,
            limit: final_limit.unwrap_or(10),
            by_fields,
            show_count,
            show_percent,
        },
    ))
}

/// Parse a field list for top/rare commands.
/// Accepts comma-separated fields. Space-separated fields are accepted only if
/// followed by another field or comma (stops before keywords like "by", "showcount=", etc.).
fn top_rare_field_list(input: &str) -> ParseResult<'_, Vec<String>> {
    let (mut input, first) = alt((quoted_string, field_name)).parse(input)?;
    let mut fields = vec![first];

    loop {
        // Try comma separator
        let comma: Result<(&str, char), nom::Err<nom::error::Error<&str>>> =
            delimited(multispace0, char(','), multispace0).parse(input);
        if let Ok((rest, _)) = comma {
            if let Ok((rest2, f)) = alt((quoted_string, field_name)).parse(rest) {
                fields.push(f);
                input = rest2;
                continue;
            }
        }

        // Try space separator, but reject if followed by '=' (keyword) or is a known keyword
        let space: Result<(&str, &str), nom::Err<nom::error::Error<&str>>> = multispace1(input);
        if let Ok((rest, _)) = space {
            if let Ok((rest2, f)) = alt((quoted_string, field_name)).parse(rest) {
                // Stop if the field is a keyword or followed by '='
                if !rest2.starts_with('=')
                    && !f.eq_ignore_ascii_case("by")
                    && !f.eq_ignore_ascii_case("showcount")
                    && !f.eq_ignore_ascii_case("showperc")
                {
                    fields.push(f);
                    input = rest2;
                    continue;
                }
            }
        }

        break;
    }

    Ok((input, fields))
}

/// Parse transaction command: transaction field [startswith=expr] [endswith=expr] [maxspan=duration] [maxevents=N]
/// Parameters can appear in any order.
/// Examples:
///   | transaction session_id
///   | transaction user maxspan=1h
///   | transaction session_id startswith="login" endswith="logout" maxspan=24h
pub(super) fn transaction_command(input: &str) -> ParseResult<'_, Command> {
    let (input, _) = tag_no_case("transaction").parse(input)?;
    let (input, _) = multispace1(input)?;

    // Parse fields to group by
    let (input, fields) = transaction_field_list(input)?;

    // Parse optional parameters in any order
    let mut startswith: Option<SearchExpr> = None;
    let mut endswith: Option<SearchExpr> = None;
    let mut maxspan: Option<Duration> = None;
    let mut maxevents: Option<usize> = None;
    let mut remaining = input;

    loop {
        // Need whitespace before each parameter
        let ws: Result<(&str, &str), nom::Err<nom::error::Error<&str>>> = multispace1(remaining);
        let rest = match ws {
            Ok((rest, _)) => rest,
            Err(_) => break,
        };

        // Stop at pipe or end of input
        if rest.is_empty() || rest.starts_with('|') {
            break;
        }

        if startswith.is_none() {
            if let Ok((after_tag, _)) =
                tag_no_case::<_, _, nom::error::Error<&str>>("startswith=").parse(rest)
            {
                let (after_val, _) = multispace0(after_tag)?;
                // Parenthesized expression: startswith=(action="login")
                if let Ok((r, expr)) = parse_paren_search_expr(after_val) {
                    startswith = Some(expr);
                    remaining = r;
                    continue;
                }
                // Quoted string: startswith="login"
                if let Ok((r, val)) = quoted_string(after_val) {
                    startswith = Some(SearchExpr::Keyword(val));
                    remaining = r;
                    continue;
                }
                // Bare search expression: startswith=action="login"
                if let Ok((r, expr)) = search_expr(after_val) {
                    startswith = Some(expr);
                    remaining = r;
                    continue;
                }
            }
        }

        if endswith.is_none() {
            if let Ok((after_tag, _)) =
                tag_no_case::<_, _, nom::error::Error<&str>>("endswith=").parse(rest)
            {
                let (after_val, _) = multispace0(after_tag)?;
                // Parenthesized expression: endswith=(action="logout")
                if let Ok((r, expr)) = parse_paren_search_expr(after_val) {
                    endswith = Some(expr);
                    remaining = r;
                    continue;
                }
                // Quoted string: endswith="logout"
                if let Ok((r, val)) = quoted_string(after_val) {
                    endswith = Some(SearchExpr::Keyword(val));
                    remaining = r;
                    continue;
                }
                // Bare search expression
                if let Ok((r, expr)) = search_expr(after_val) {
                    endswith = Some(expr);
                    remaining = r;
                    continue;
                }
            }
        }

        if maxspan.is_none() {
            if let Ok((after_tag, _)) =
                tag_no_case::<_, _, nom::error::Error<&str>>("maxspan=").parse(rest)
            {
                let (after_val, _) = multispace0(after_tag)?;
                if let Ok((r, dur)) = duration(after_val) {
                    maxspan = Some(dur);
                    remaining = r;
                    continue;
                }
            }
        }

        if maxevents.is_none() {
            if let Ok((after_tag, _)) =
                tag_no_case::<_, _, nom::error::Error<&str>>("maxevents=").parse(rest)
            {
                let (after_val, _) = multispace0(after_tag)?;
                if let Ok((r, n)) = map_res(digit1::<_, nom::error::Error<&str>>, |s: &str| {
                    s.parse::<usize>()
                })
                .parse(after_val)
                {
                    maxevents = Some(n);
                    remaining = r;
                    continue;
                }
            }
        }

        break;
    }

    Ok((
        remaining,
        Command::Transaction {
            fields,
            startswith,
            endswith,
            maxspan,
            maxevents,
        },
    ))
}

/// Parse field list for transaction command.
/// Stops at transaction-specific keywords (startswith, endswith, maxspan, maxevents).
fn transaction_field_list(input: &str) -> ParseResult<'_, Vec<String>> {
    let (mut input, first) = alt((quoted_string, field_name)).parse(input)?;
    let mut fields = vec![first];

    loop {
        // Try comma separator
        let comma: Result<(&str, char), nom::Err<nom::error::Error<&str>>> =
            delimited(multispace0, char(','), multispace0).parse(input);
        if let Ok((rest, _)) = comma {
            if let Ok((rest2, f)) = alt((quoted_string, field_name)).parse(rest) {
                if !is_transaction_keyword(&f) {
                    fields.push(f);
                    input = rest2;
                    continue;
                }
            }
        }

        // Try space separator
        let space: Result<(&str, &str), nom::Err<nom::error::Error<&str>>> = multispace1(input);
        if let Ok((rest, _)) = space {
            if let Ok((rest2, f)) = alt((quoted_string, field_name)).parse(rest) {
                if !rest2.starts_with('=') && !is_transaction_keyword(&f) {
                    fields.push(f);
                    input = rest2;
                    continue;
                }
            }
        }

        break;
    }

    Ok((input, fields))
}

/// Check if a word is a transaction command keyword that should stop field list parsing.
fn is_transaction_keyword(s: &str) -> bool {
    matches!(
        s.to_lowercase().as_str(),
        "startswith" | "endswith" | "maxspan" | "maxevents"
    )
}

/// Parse fillnull command: fillnull [value=<string>] [field1, field2, ...]
/// Examples:
///   | fillnull
///   | fillnull value="N/A"
///   | fillnull value=0 bytes_in, bytes_out
pub(super) fn fillnull_command(input: &str) -> ParseResult<'_, Command> {
    let (input, _) = tag_no_case("fillnull").parse(input)?;

    // Parse optional value=<string>
    let (input, value) = opt(preceded(
        delimited(multispace1, tag_no_case("value="), multispace0),
        alt((quoted_string, unquoted_keyword)),
    ))
    .parse(input)?;

    // Parse optional field list
    let (input, fields) = opt(preceded(multispace1, field_list)).parse(input)?;

    Ok((
        input,
        Command::Fillnull {
            value: value.unwrap_or_else(|| "NULL".to_string()),
            fields,
        },
    ))
}

/// Parse mvexpand command: mvexpand field [limit=N]
/// Examples:
///   | mvexpand tags
///   | mvexpand values limit=100
pub(super) fn mvexpand_command(input: &str) -> ParseResult<'_, Command> {
    let (input, _) = tag_no_case("mvexpand").parse(input)?;
    let (input, _) = multispace1(input)?;

    // Parse the field
    let (input, field) = field_name(input)?;

    // Parse optional limit
    let (input, limit) = opt(preceded(
        delimited(multispace1, tag_no_case("limit="), multispace0),
        map_res(digit1, |s: &str| s.parse::<usize>()),
    ))
    .parse(input)?;

    Ok((input, Command::Mvexpand { field, limit }))
}

/// Parse spath command: spath [input=field] [output=field] [path=jsonpath]
/// Parameters can appear in any order.
/// Examples:
///   | spath
///   | spath input=json_data
///   | spath path=user.name output=username
///   | spath input=ext path="user.name" output=username
pub(super) fn spath_command(input: &str) -> ParseResult<'_, Command> {
    let (input, _) = tag_no_case("spath").parse(input)?;

    let mut input_field: Option<String> = None;
    let mut output: Option<String> = None;
    let mut path: Option<String> = None;
    let mut remaining = input;

    // Parse input=, output=, path= in any order (up to 3 params)
    for _ in 0..3 {
        if input_field.is_none() {
            if let Ok((rest, f)) = preceded(
                delimited(
                    multispace1,
                    tag_no_case::<_, _, nom::error::Error<&str>>("input="),
                    multispace0,
                ),
                field_name,
            )
            .parse(remaining)
            {
                input_field = Some(f);
                remaining = rest;
                continue;
            }
        }
        if output.is_none() {
            if let Ok((rest, f)) = preceded(
                delimited(
                    multispace1,
                    tag_no_case::<_, _, nom::error::Error<&str>>("output="),
                    multispace0,
                ),
                field_name,
            )
            .parse(remaining)
            {
                output = Some(f);
                remaining = rest;
                continue;
            }
        }
        if path.is_none() {
            if let Ok((rest, f)) = preceded(
                delimited(
                    multispace1,
                    tag_no_case::<_, _, nom::error::Error<&str>>("path="),
                    multispace0,
                ),
                alt((quoted_string, field_name)),
            )
            .parse(remaining)
            {
                path = Some(f);
                remaining = rest;
                continue;
            }
        }
        break;
    }

    Ok((
        remaining,
        Command::Spath {
            input: input_field,
            output,
            path,
        },
    ))
}

/// Parse append command: append [maxout=N] [subsearch]
/// Examples:
///   | append [search error | stats count]
///   | append maxout=50000 [search error | stats count]
pub(super) fn append_command(input: &str) -> ParseResult<'_, Command> {
    let (input, _) = tag_no_case("append").parse(input)?;
    let (input, _) = multispace0(input)?;

    // Parse optional maxout=N before the subsearch bracket
    let (input, maxout) = opt(terminated(
        preceded(
            tag_no_case("maxout="),
            map_res(digit1, |s: &str| s.parse::<usize>()),
        ),
        multispace0,
    ))
    .parse(input)?;

    let (input, _) = char('[').parse(input)?;
    let (input, _) = multispace0(input)?;

    // Parse the subsearch query
    let (input, subsearch) = query(input)?;

    let (input, _) = multispace0(input)?;
    let (input, _) = char(']').parse(input)?;

    Ok((
        input,
        Command::Append {
            subsearch: Box::new(subsearch),
            maxout,
        },
    ))
}

/// Parse join command: join [type=inner|left|outer] field [, field2] [max=N] [maxout=N] [subsearch]
/// Examples:
///   | join user [search source_type=users | fields user, department]
///   | join type=left user [search source_type=users | fields user, department]
///   | join type=inner src_ip, dest_ip [search source_type=firewall | table src_ip, dest_ip, action]
///   | join maxout=50000 user [search source_type=users | fields user, department]
pub(super) fn join_command(input: &str) -> ParseResult<'_, Command> {
    let (input, _) = tag_no_case("join").parse(input)?;
    let (input, _) = multispace1(input)?;

    // Parse optional type=inner|left|outer
    let (input, join_type) = opt(terminated(
        preceded(
            tag_no_case("type="),
            alt((
                map(tag_no_case("inner"), |_| JoinType::Inner),
                map(tag_no_case("left"), |_| JoinType::Left),
                map(tag_no_case("outer"), |_| JoinType::Outer),
            )),
        ),
        multispace1,
    ))
    .parse(input)?;
    let join_type = join_type.unwrap_or(JoinType::Inner);

    // Parse optional maxout=N before fields (MUST come before max= to avoid prefix match)
    let (input, maxout_before) = opt(terminated(
        preceded(
            tag_no_case("maxout="),
            map_res(digit1, |s: &str| s.parse::<usize>()),
        ),
        multispace1,
    ))
    .parse(input)?;

    // Parse optional max=N before fields
    let (input, max_before) = opt(terminated(
        preceded(
            tag_no_case("max="),
            map_res(digit1, |s: &str| s.parse::<usize>()),
        ),
        multispace1,
    ))
    .parse(input)?;

    // Parse optional overwrite=true|false before fields
    let (input, overwrite_opt) = opt(terminated(
        preceded(
            tag_no_case("overwrite="),
            alt((
                map(tag_no_case("true"), |_| true),
                map(tag_no_case("false"), |_| false),
            )),
        ),
        multispace1,
    ))
    .parse(input)?;

    // Parse the fields to join on (comma-separated list)
    let (input, fields) =
        separated_list1(delimited(multispace0, char(','), multispace0), field_name).parse(input)?;

    let (input, _) = multispace0(input)?;

    // Parse optional maxout=N after fields (MUST come before max= to avoid prefix match)
    let (input, maxout_after) = opt(preceded(
        multispace0,
        preceded(
            tag_no_case("maxout="),
            map_res(digit1, |s: &str| s.parse::<usize>()),
        ),
    ))
    .parse(input)?;

    // Parse optional max=N after fields
    let (input, max_after) = opt(preceded(
        multispace0,
        preceded(
            tag_no_case("max="),
            map_res(digit1, |s: &str| s.parse::<usize>()),
        ),
    ))
    .parse(input)?;

    let (input, _) = multispace0(input)?;

    // Parse the subsearch in brackets
    let (input, _) = char('[').parse(input)?;
    let (input, _) = multispace0(input)?;

    // NAN-1562: optional leading `dataset=<logs|spans|metrics>` (or `from=`)
    // token scopes the subsearch to a different dataset (cross-dataset join).
    let (input, subsearch_dataset) = opt(subsearch_dataset_token).parse(input)?;
    let (input, _) = multispace0(input)?;

    // Parse the subsearch query
    let (input, subsearch) = query(input)?;

    let (input, _) = multispace0(input)?;
    let (input, _) = char(']').parse(input)?;

    // Use max/maxout from either position, with after-fields taking precedence
    let max = max_after.or(max_before).unwrap_or(1);
    let overwrite = overwrite_opt.unwrap_or(true);
    let maxout = maxout_after.or(maxout_before);

    Ok((
        input,
        Command::Join {
            join_type,
            fields,
            subsearch: Box::new(subsearch),
            max,
            overwrite,
            maxout,
            subsearch_dataset,
        },
    ))
}

/// Parse a leading `dataset=<name>` token inside a subsearch bracket and resolve
/// it through the strict [`Dataset::from_selector_strict`] (NAN-1562). Used by
/// both `| join […]` and `field IN […]`. Consumes the token plus its trailing
/// whitespace so the subsearch `query(…)` parser sees a clean start.
///
/// NAN-1562 fixes:
/// - The `from=` alias is GONE. `from` is a real log field (email/syslog
///   sender), and an aliased `from=` here silently swallowed a `from=<word>`
///   field filter (`[from=production …]` parsed as a dataset selector, dropping
///   the filter). Only `dataset=` is accepted; a `from=…` token is left for the
///   subsearch's own search parser to consume as a field filter.
/// - An UNKNOWN selector value is now a hard parse error (`map_res` → `Err`)
///   rather than the lenient `Logs` fallback. `dataset=spanz` previously
///   resolved to the logs table and silently scanned the wrong dataset.
pub(super) fn subsearch_dataset_token(
    input: &str,
) -> ParseResult<'_, crate::query::clickhouse_sql_gen::otel::Dataset> {
    use crate::query::clickhouse_sql_gen::otel::Dataset;
    use nom::error::{Error, ErrorKind};
    // `dataset=` absent → recoverable Error so the wrapping `opt(...)` yields
    // None (no selector). Once the prefix matched, an unknown value is a HARD
    // Failure: `opt` would otherwise swallow a recoverable Error and let the
    // bogus `dataset=spanz` token fall through to the subsearch's search parser,
    // silently scanning the wrong (logs) table (NAN-1562 FIX 3).
    let (input, _) = tag_no_case("dataset=").parse(input)?;
    let (rest, name) = alpha1(input)?;
    let dataset = Dataset::from_selector_strict(name)
        .ok_or_else(|| nom::Err::Failure(Error::new(input, ErrorKind::Verify)))?;
    let (rest, _) = multispace1(rest)?;
    Ok((rest, dataset))
}

/// Parse format command: format [maxresults=N]
/// Examples:
///   | format
///   | format maxresults=100
pub(super) fn format_command(input: &str) -> ParseResult<'_, Command> {
    let (input, _) = tag_no_case("format").parse(input)?;

    // Parse optional maxresults
    let (input, maxresults) = opt(preceded(
        delimited(multispace1, tag_no_case("maxresults="), multispace0),
        map_res(digit1, |s: &str| s.parse::<usize>()),
    ))
    .parse(input)?;

    // Parse optional row_sep (also accepts "sep=" as alias)
    let (input, row_sep) = opt(preceded(
        delimited(
            multispace1,
            alt((tag_no_case("row_sep="), tag_no_case("sep="))),
            multispace0,
        ),
        quoted_string,
    ))
    .parse(input)?;

    // Parse optional col_sep
    let (input, col_sep) = opt(preceded(
        delimited(multispace1, tag_no_case("col_sep="), multispace0),
        quoted_string,
    ))
    .parse(input)?;

    Ok((
        input,
        Command::Format {
            maxresults,
            row_sep: row_sep.unwrap_or_else(|| " OR ".to_string()),
            col_sep: col_sep.unwrap_or_else(|| " AND ".to_string()),
        },
    ))
}

/// Parse return command: return [count] [field1, field2, ...]
/// Accepts `$field` syntax (strips leading `$`). If no fields given, returns all.
/// Examples:
///   | return src_ip
///   | return 10 src_ip, user
///   | return 10 $src_ip
///   | return 10
pub(super) fn return_command(input: &str) -> ParseResult<'_, Command> {
    let (input, _) = tag_no_case("return").parse(input)?;
    let (input, _) = multispace1(input)?;

    // Try: count followed by optional fields
    // First attempt: number + whitespace + fields
    let (input, count, fields) = if let Ok((rest, n)) = terminated(
        map_res(digit1::<_, nom::error::Error<&str>>, |s: &str| {
            s.parse::<usize>()
        }),
        multispace1,
    )
    .parse(input)
    {
        // Got a count and whitespace — try to parse fields after it
        let (rest, fields) = opt(return_field_list).parse(rest)?;
        (rest, n, fields.unwrap_or_default())
    } else if let Ok((rest, n)) = map_res(digit1::<_, nom::error::Error<&str>>, |s: &str| {
        s.parse::<usize>()
    })
    .parse(input)
    {
        // Got a count at end-of-input (or before pipe) — no fields
        (rest, n, Vec::new())
    } else {
        // No count — parse fields directly
        let (rest, fields) = opt(return_field_list).parse(input)?;
        (rest, 1, fields.unwrap_or_default())
    };

    Ok((input, Command::Return { count, fields }))
}

/// Parse a field list for the return command, stripping optional `$` prefixes.
fn return_field_list(input: &str) -> ParseResult<'_, Vec<String>> {
    let (mut input, first) = return_field_name(input)?;
    let mut fields = vec![first];

    loop {
        // Try comma separator
        let comma: Result<(&str, char), nom::Err<nom::error::Error<&str>>> =
            delimited(multispace0, char(','), multispace0).parse(input);
        if let Ok((rest, _)) = comma {
            if let Ok((rest2, f)) = return_field_name(rest) {
                fields.push(f);
                input = rest2;
                continue;
            }
        }

        // Try space separator
        let space: Result<(&str, &str), nom::Err<nom::error::Error<&str>>> = multispace1(input);
        if let Ok((rest, _)) = space {
            if let Ok((rest2, f)) = return_field_name(rest) {
                if !rest2.starts_with('=') {
                    fields.push(f);
                    input = rest2;
                    continue;
                }
            }
        }

        break;
    }

    Ok((input, fields))
}

/// Parse a single field name for the return command, stripping an optional leading `$`.
fn return_field_name(input: &str) -> ParseResult<'_, String> {
    let (input, _) = opt(char('$')).parse(input)?;
    field_name(input)
}
