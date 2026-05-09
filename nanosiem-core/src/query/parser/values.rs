// SPDX-License-Identifier: AGPL-3.0-or-later

//! Value parsing utilities for the query parser

use nom::{
    branch::alt,
    bytes::complete::tag,
    bytes::complete::tag_no_case,
    bytes::complete::take_while,
    bytes::complete::{escaped, take_while1},
    character::complete::{anychar, char, digit1, multispace1, none_of},
    combinator::{map, map_res, opt, recognize, value},
    sequence::{delimited, pair},
    IResult, Parser,
};
use std::net::IpAddr;
use std::time::Duration;

use crate::query::ast::{Comparator, IntervalUnit, Value};

type ParseResult<'a, T> = IResult<&'a str, T>;

/// Parse a filter value (IP, number, bool, interval, or string)
pub(crate) fn filter_value(input: &str) -> ParseResult<'_, Value> {
    alt((
        ip_value,
        bool_value,
        number_value,
        interval_value,
        string_value,
    ))
    .parse(input)
}

/// Parse IP address value
pub(crate) fn ip_value(input: &str) -> ParseResult<'_, Value> {
    map_res(
        recognize((
            digit1,
            char('.'),
            digit1,
            char('.'),
            digit1,
            char('.'),
            digit1,
        )),
        |s: &str| s.parse::<IpAddr>().map(Value::Ip),
    )
    .parse(input)
}

/// Parse interval value: INTERVAL 1 DAY, INTERVAL 2 HOUR, etc.
pub(crate) fn interval_value(input: &str) -> ParseResult<'_, Value> {
    let (input, _) = tag_no_case("INTERVAL").parse(input)?;
    let (input, _) = multispace1(input)?;
    let (input, num) = map_res(digit1, |s: &str| s.parse::<u64>()).parse(input)?;
    let (input, _) = multispace1(input)?;
    let (input, unit) = interval_unit(input)?;

    let duration = Duration::from_secs(unit.to_seconds(num));
    Ok((input, Value::Interval(duration, unit)))
}

/// Parse interval unit (DAY, HOUR, MINUTE, etc.)
fn interval_unit(input: &str) -> ParseResult<'_, IntervalUnit> {
    alt((
        // Plural forms
        value(IntervalUnit::Microsecond, tag_no_case("MICROSECONDS")),
        value(IntervalUnit::Millisecond, tag_no_case("MILLISECONDS")),
        value(IntervalUnit::Second, tag_no_case("SECONDS")),
        value(IntervalUnit::Minute, tag_no_case("MINUTES")),
        value(IntervalUnit::Hour, tag_no_case("HOURS")),
        value(IntervalUnit::Day, tag_no_case("DAYS")),
        value(IntervalUnit::Week, tag_no_case("WEEKS")),
        value(IntervalUnit::Month, tag_no_case("MONTHS")),
        value(IntervalUnit::Year, tag_no_case("YEARS")),
        // Singular forms
        value(IntervalUnit::Microsecond, tag_no_case("MICROSECOND")),
        value(IntervalUnit::Millisecond, tag_no_case("MILLISECOND")),
        value(IntervalUnit::Second, tag_no_case("SECOND")),
        value(IntervalUnit::Minute, tag_no_case("MINUTE")),
        value(IntervalUnit::Hour, tag_no_case("HOUR")),
        value(IntervalUnit::Day, tag_no_case("DAY")),
        value(IntervalUnit::Week, tag_no_case("WEEK")),
        value(IntervalUnit::Month, tag_no_case("MONTH")),
        value(IntervalUnit::Year, tag_no_case("YEAR")),
    ))
    .parse(input)
}

/// Parse boolean value
pub(crate) fn bool_value(input: &str) -> ParseResult<'_, Value> {
    alt((
        value(Value::Bool(true), tag_no_case("true")),
        value(Value::Bool(false), tag_no_case("false")),
    ))
    .parse(input)
}

/// Parse number value (integer or float)
pub(crate) fn number_value(input: &str) -> ParseResult<'_, Value> {
    map_res(
        recognize((opt(char('-')), digit1, opt(pair(char('.'), digit1)))),
        |s: &str| s.parse::<f64>().map(Value::Number),
    )
    .parse(input)
}

/// Parse string value (quoted or unquoted)
pub(crate) fn string_value(input: &str) -> ParseResult<'_, Value> {
    map(alt((quoted_string, unquoted_string)), Value::String).parse(input)
}

/// Parse quoted string with escape sequences (handles both double and single quotes)
pub(crate) fn quoted_string(input: &str) -> ParseResult<'_, String> {
    alt((double_quoted_string, single_quoted_string)).parse(input)
}

/// Parse double-quoted string with escape sequences
/// Allows any character after backslash to support regex patterns like \. \d \w etc.
fn double_quoted_string(input: &str) -> ParseResult<'_, String> {
    delimited(
        char('"'),
        map(
            opt(escaped(none_of("\\\""), '\\', anychar)),
            |s: Option<&str>| {
                // Only unescape standard string escapes, preserve regex escapes
                s.unwrap_or("").replace("\\\"", "\"").replace("\\\\", "\\")
            },
        ),
        char('"'),
    )
    .parse(input)
}

/// Parse single-quoted string with escape sequences
/// Allows any character after backslash to support regex patterns like \. \d \w etc.
fn single_quoted_string(input: &str) -> ParseResult<'_, String> {
    delimited(
        char('\''),
        map(
            opt(escaped(none_of("\\'"), '\\', anychar)),
            |s: Option<&str>| {
                // Only unescape standard string escapes, preserve regex escapes
                s.unwrap_or("").replace("\\'", "'").replace("\\\\", "\\")
            },
        ),
        char('\''),
    )
    .parse(input)
}

/// Parse unquoted string value (includes wildcards, paths, and common chars)
pub(crate) fn unquoted_string(input: &str) -> ParseResult<'_, String> {
    map(
        take_while1(|c: char| {
            c.is_alphanumeric() 
            || c == '_' 
            || c == '-' 
            || c == '.' 
            || c == '*' 
            || c == '?' 
            || c == '/'  // Allow forward slashes for paths
            || c == ':' // Allow colons for URLs/protocols
        }),
        |s: &str| s.to_string(),
    )
    .parse(input)
}

/// Parse field name (supports dot notation and metadata_ prefix)
pub(crate) fn field_name(input: &str) -> ParseResult<'_, String> {
    // Parse initial field name (letters/underscore, then alphanumeric/underscore)
    let (mut remaining, base) = recognize(pair(
        alt((
            // Handle metadata_ prefix
            recognize(pair(
                tag("metadata_"),
                take_while1(|c: char| c.is_alphanumeric() || c == '_'),
            )),
            // Regular field name
            take_while1(|c: char| c.is_alphabetic() || c == '_'),
        )),
        take_while(|c: char| c.is_alphanumeric() || c == '_'),
    ))
    .parse(input)?;

    let mut field = base.to_string();

    // Handle dots for nested fields (e.g., user.name)
    // But stop if dot is followed by a quote (string concatenation)
    loop {
        // Check if we have a dot
        if remaining.starts_with('.') {
            // Peek at what comes after the dot
            let after_dot = &remaining[1..];
            let trimmed = after_dot.trim_start();

            // Stop if dot is followed by a quote (concatenation operator)
            if trimmed.starts_with('"') || trimmed.starts_with('\'') {
                break;
            }

            // Try to parse the next field segment
            if let Ok((new_remaining, segment)) =
                take_while1::<_, _, nom::error::Error<&str>>(|c: char| {
                    c.is_alphanumeric() || c == '_'
                })
                .parse(after_dot)
            {
                field.push('.');
                field.push_str(segment);
                remaining = new_remaining;
            } else {
                // Dot not followed by valid field chars, stop
                break;
            }
        } else {
            // No more dots
            break;
        }
    }

    Ok((remaining, field))
}

/// Parse field name with wildcard support (for table/fields commands)
/// Supports patterns like: src_*, *_time, dest_*, _*, *
pub(crate) fn field_name_with_wildcard(input: &str) -> ParseResult<'_, String> {
    map(
        recognize(pair(
            alt((
                // Handle metadata_ prefix with optional wildcard
                recognize(pair(
                    tag("metadata_"),
                    take_while1(|c: char| c.is_alphanumeric() || c == '_' || c == '*'),
                )),
                // Wildcard at start: *_time, *
                recognize(pair(
                    char('*'),
                    take_while(|c: char| c.is_alphanumeric() || c == '_'),
                )),
                // Regular start: src_*, field, field*
                take_while1(|c: char| c.is_alphabetic() || c == '_'),
            )),
            take_while(|c: char| c.is_alphanumeric() || c == '_' || c == '.' || c == '*'),
        )),
        |s: &str| s.to_string(),
    )
    .parse(input)
}

/// Parse comparison operator (excludes regex which uses /pattern/ syntax)
pub(crate) fn comparator(input: &str) -> ParseResult<'_, Comparator> {
    alt((
        value(Comparator::Ne, tag("!=")),
        value(Comparator::Gte, tag(">=")),
        value(Comparator::Lte, tag("<=")),
        value(Comparator::Eq, tag("=")),
        value(Comparator::Gt, tag(">")),
        value(Comparator::Lt, tag("<")),
    ))
    .parse(input)
}
