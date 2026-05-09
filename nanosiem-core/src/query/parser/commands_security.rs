// SPDX-License-Identifier: AGPL-3.0-or-later

//! Security and analytics command parsers for the query parser
//!
//! Handles: risk, prevalence, sample, reverse, eventstats, sequence,
//! funnel, anomaly, inputlookup, lateral.

use nom::{
    branch::alt,
    bytes::complete::{tag, tag_no_case},
    character::complete::{char, digit1, multispace0, multispace1, one_of},
    combinator::{map_res, opt, recognize, value},
    multi::{many1, separated_list0},
    number::complete::double,
    sequence::{delimited, pair, preceded, terminated},
    Parser,
};
use std::time::Duration;

use super::commands_core::{aggregation_list, duration, field_list};
use super::eval_expr::eval_expression;
use super::search_expr::{parse_paren_search_expr, search_expr};
use super::values::{field_name, quoted_string};
use super::ParseResult;
use crate::query::ast::*;

/// Parse risk command: assign risk scores to events for risk-based alerting
///
/// Classic syntax (score first):
///   | risk score=50
///   | risk score=75 entity=src_ip
///   | risk score=90 entity=user factor="brute_force_attempt"
///   | risk score=count*10 entity=src_ip
///   | risk score=if(is_admin, 80, 40) entity=user
///   | risk score=severity_level entity=user weight=0.5
///
/// Alternate syntax with field/type aliases (any order):
///   | risk field=src_ip score=25 type="brute_force"
///   | risk score=25 field=src_ip type="brute_force"
pub(super) fn risk_command(input: &str) -> ParseResult<'_, Command> {
    let (input, _) = tag_no_case("risk").parse(input)?;
    let (input, _) = multispace1(input)?;

    // Parse parameters in any order: score=, entity=/field=, factor=/type=, weight=
    let mut score_expr: Option<EvalExpression> = None;
    let mut entity_field: Option<String> = None;
    let mut factor: Option<EvalExpression> = None;
    let mut weight: Option<f64> = None;

    let mut remaining = input;
    let mut first = true;

    loop {
        if !first {
            let (next, ws) = multispace0(remaining)?;
            if ws.is_empty() && !remaining.is_empty() && !remaining.starts_with('|') {
                break;
            }
            remaining = next;
        }
        first = false;

        if remaining.is_empty() || remaining.starts_with('|') {
            break;
        }

        // score=<expr>
        if let Ok((next, _)) =
            tag_no_case::<_, _, nom::error::Error<&str>>("score=").parse(remaining)
        {
            if score_expr.is_some() {
                break;
            }
            let (next, expr) = risk_score_expression(next)?;
            score_expr = Some(expr);
            remaining = next;
        }
        // entity=field (classic) or field=field (alias, maps to entity_field)
        else if let Ok((next, _)) =
            tag_no_case::<_, _, nom::error::Error<&str>>("entity=").parse(remaining)
        {
            if entity_field.is_some() {
                break;
            }
            let (next, val) = field_name(next)?;
            entity_field = Some(val);
            remaining = next;
        } else if let Ok((next, _)) =
            tag_no_case::<_, _, nom::error::Error<&str>>("field=").parse(remaining)
        {
            if entity_field.is_some() {
                break;
            }
            let (next, val) = field_name(next)?;
            entity_field = Some(val);
            remaining = next;
        }
        // factor=expr (classic) or type=expr (alias, maps to factor)
        else if let Ok((next, _)) =
            tag_no_case::<_, _, nom::error::Error<&str>>("factor=").parse(remaining)
        {
            if factor.is_some() {
                break;
            }
            let (next, val) = eval_expression(next)?;
            factor = Some(val);
            remaining = next;
        } else if let Ok((next, _)) =
            tag_no_case::<_, _, nom::error::Error<&str>>("type=").parse(remaining)
        {
            if factor.is_some() {
                break;
            }
            let (next, val) = eval_expression(next)?;
            factor = Some(val);
            remaining = next;
        }
        // weight=0.5
        else if let Ok((next, _)) =
            tag_no_case::<_, _, nom::error::Error<&str>>("weight=").parse(remaining)
        {
            if weight.is_some() {
                break;
            }
            let (next, val) = double(next)?;
            weight = Some(val);
            remaining = next;
        } else {
            break;
        }
    }

    // score is required
    let score_expr = score_expr.ok_or_else(|| {
        nom::Err::Error(nom::error::Error::new(
            remaining,
            nom::error::ErrorKind::Tag,
        ))
    })?;

    // Convert to RiskScoreExpr
    let score = match &score_expr {
        EvalExpression::Literal(Value::Number(n)) => {
            let score_val = *n as i32;
            if score_val < 0 || score_val > 100 {
                return Err(nom::Err::Error(nom::error::Error::new(
                    remaining,
                    nom::error::ErrorKind::Verify,
                )));
            }
            RiskScoreExpr::Literal(score_val)
        }
        _ => RiskScoreExpr::Dynamic(score_expr),
    };

    // Validate weight
    if let Some(w) = weight {
        if !(0.0..=1.0).contains(&w) {
            return Err(nom::Err::Error(nom::error::Error::new(
                remaining,
                nom::error::ErrorKind::Verify,
            )));
        }
    }

    Ok((
        remaining,
        Command::Risk {
            score,
            entity_field,
            factor,
            weight,
        },
    ))
}

/// Parse a risk score expression - a subset of eval expressions suitable for scoring
/// This is more restrictive than full eval_expression to avoid ambiguity with subsequent parameters
fn risk_score_expression(input: &str) -> ParseResult<'_, EvalExpression> {
    // Try to parse as a simple number first (most common case)
    if let Ok((remaining, num)) = double::<&str, nom::error::Error<&str>>(input) {
        // Check if this is really just a number (not followed by operators that would make it an expression)
        let trimmed = remaining.trim_start();
        // If followed by space and a keyword (entity, factor, weight) or end, treat as literal
        if trimmed.is_empty()
            || trimmed.starts_with("entity")
            || trimmed.starts_with("ENTITY")
            || trimmed.starts_with("factor")
            || trimmed.starts_with("FACTOR")
            || trimmed.starts_with("weight")
            || trimmed.starts_with("WEIGHT")
            || trimmed.starts_with("field")
            || trimmed.starts_with("FIELD")
            || trimmed.starts_with("type")
            || trimmed.starts_with("TYPE")
            || trimmed.starts_with('|')
        {
            return Ok((remaining, EvalExpression::Literal(Value::Number(num))));
        }
    }

    // Otherwise parse as a full eval expression
    // We need to be careful not to consume too much - stop at space + keyword
    eval_expression_until_keyword(input)
}

/// Parse an eval expression but stop before risk command keywords (entity, factor, weight)
fn eval_expression_until_keyword(input: &str) -> ParseResult<'_, EvalExpression> {
    // Parse the expression
    let (remaining, expr) = eval_expression(input)?;
    Ok((remaining, expr))
}

/// Parse prevalence command: filter or enrich results based on artifact prevalence
///
/// Filtering mode (supports multiple conditions):
///   | prevalence hash_prevalence < 5 window=24h
///   | prevalence domain_prevalence <= 3
///   | prevalence hash_first_seen > now() - 24h
///   | prevalence domain_prevalence < 10 domain_first_seen > now()-86400 window=24h
///
/// Enrichment mode (explicit):
///   | prevalence enrich=true
///   | prevalence enrich=true window=24h
///
/// Enrichment mode (positional shorthand):
///   | prevalence src_ip
///   | prevalence src_ip threshold=rare
///   | prevalence src_ip, dest_ip
pub(super) fn prevalence_command(input: &str) -> ParseResult<'_, Command> {
    let (input, _) = tag_no_case("prevalence").parse(input)?;
    let (input, _) = multispace1(input)?;

    // Check if this is enrichment mode (enrich=true)
    if let Ok((remaining, _)) =
        tag_no_case::<&str, &str, nom::error::Error<&str>>("enrich").parse(input)
    {
        if let Ok((remaining, _)) = char::<&str, nom::error::Error<&str>>('=').parse(remaining) {
            let (remaining, enrich_value) = alt((
                value(true, tag_no_case("true")),
                value(false, tag_no_case("false")),
            ))
            .parse(remaining)?;

            // Parse optional window parameter
            let (remaining, time_window) =
                opt(preceded(multispace1, prevalence_window_spec)).parse(remaining)?;

            return Ok((
                remaining,
                Command::Prevalence {
                    conditions: vec![],
                    time_window,
                    enrich: enrich_value,
                },
            ));
        }
    }

    // Try filtering mode first: parse a prevalence condition (field operator threshold)
    if let Ok((cond_remaining, first_condition)) = prevalence_condition(input) {
        let mut conditions = vec![first_condition];

        // Try to parse additional conditions (space-separated, optionally with AND)
        let mut remaining = cond_remaining;
        loop {
            let trimmed = remaining.trim_start();
            if trimmed.is_empty() || trimmed.starts_with('|') {
                remaining = trimmed;
                break;
            }

            // Check if this looks like a window/interval spec or enrich
            let trimmed_lower = trimmed.to_ascii_lowercase();
            if trimmed_lower.starts_with("window=") || trimmed_lower.starts_with("window ")
                || trimmed_lower.starts_with("interval=") || trimmed_lower.starts_with("interval ")
            {
                remaining = trimmed;
                break;
            }
            if trimmed.to_ascii_lowercase().starts_with("enrich=") {
                remaining = trimmed;
                break;
            }

            // Skip optional AND keyword between conditions
            let cond_input = if let Ok((after_and, _)) =
                terminated::<_, _, nom::error::Error<&str>, _, _>(tag_no_case("AND"), multispace1)
                    .parse(trimmed)
            {
                after_and
            } else {
                trimmed
            };

            // Try to parse a condition
            if let Ok((new_remaining, condition)) = prevalence_condition(cond_input) {
                conditions.push(condition);
                remaining = new_remaining;
            } else {
                remaining = trimmed;
                break;
            }
        }

        // Parse optional window and enrich parameters
        let mut time_window = None;
        let mut enrich = false;
        let remaining = remaining.trim_start();

        // Parse remaining optional params in any order
        let mut remaining = remaining;
        loop {
            let trimmed = remaining.trim_start();
            if trimmed.is_empty() || trimmed.starts_with('|') {
                remaining = trimmed;
                break;
            }
            if let Ok((r, _)) = alt((
                tag_no_case::<_, _, nom::error::Error<&str>>("window="),
                tag_no_case("interval="),
            ))
            .parse(trimmed)
            {
                if let Ok((r, tw)) = alt((
                    value(
                        PrevalenceTimeWindow::OneHour,
                        tag_no_case::<_, _, nom::error::Error<&str>>("1h"),
                    ),
                    value(PrevalenceTimeWindow::TwentyFourHours, tag_no_case("24h")),
                    value(PrevalenceTimeWindow::SevenDays, tag_no_case("7d")),
                    value(PrevalenceTimeWindow::ThirtyDays, tag_no_case("30d")),
                ))
                .parse(r)
                {
                    time_window = Some(tw);
                    remaining = r;
                    continue;
                }
            }
            if let Ok((r, _)) =
                tag_no_case::<_, _, nom::error::Error<&str>>("enrich=").parse(trimmed)
            {
                if let Ok((r, val)) = alt((
                    value(true, tag_no_case::<_, _, nom::error::Error<&str>>("true")),
                    value(false, tag_no_case("false")),
                ))
                .parse(r)
                {
                    enrich = val;
                    remaining = r;
                    continue;
                }
            }
            break;
        }

        return Ok((
            remaining,
            Command::Prevalence {
                conditions,
                time_window,
                enrich,
            },
        ));
    }

    // Positional enrichment shorthand: prevalence field1, field2 [threshold=rare|uncommon|common]
    // Parse comma-separated field names
    let (remaining, _fields) =
        separated_list0(delimited(multispace0, char(','), multispace0), field_name).parse(input)?;

    if _fields.is_empty() {
        return Err(nom::Err::Error(nom::error::Error::new(
            input,
            nom::error::ErrorKind::Tag,
        )));
    }

    // Parse optional threshold=rare|uncommon|common (accepted but ignored for now)
    let mut remaining = remaining;
    if let Ok((next, _)) = preceded::<_, _, nom::error::Error<&str>, _, _>(
        multispace1,
        preceded(
            tag_no_case("threshold="),
            alt((
                tag_no_case("rare"),
                tag_no_case("uncommon"),
                tag_no_case("common"),
            )),
        ),
    )
    .parse(remaining)
    {
        remaining = next;
    }

    // Parse optional window parameter
    let (remaining, time_window) =
        opt(preceded(multispace1, prevalence_window_spec)).parse(remaining)?;

    Ok((
        remaining,
        Command::Prevalence {
            conditions: vec![],
            time_window,
            enrich: true,
        },
    ))
}

/// Parse a single prevalence condition: field operator threshold
fn prevalence_condition(input: &str) -> ParseResult<'_, PrevalenceCondition> {
    let (input, field) = prevalence_field(input)?;
    let (input, _) = multispace0(input)?;
    let (input, operator) = prevalence_operator(input)?;
    let (input, _) = multispace0(input)?;
    let (input, threshold) = prevalence_threshold(input, &field)?;

    Ok((
        input,
        PrevalenceCondition {
            field,
            operator,
            threshold,
        },
    ))
}

/// Parse prevalence field name
fn prevalence_field(input: &str) -> ParseResult<'_, PrevalenceField> {
    alt((
        value(
            PrevalenceField::HashPrevalence,
            tag_no_case("hash_prevalence"),
        ),
        value(
            PrevalenceField::DomainPrevalence,
            tag_no_case("domain_prevalence"),
        ),
        value(
            PrevalenceField::HashFirstSeen,
            tag_no_case("hash_first_seen"),
        ),
        value(
            PrevalenceField::DomainFirstSeen,
            tag_no_case("domain_first_seen"),
        ),
    ))
    .parse(input)
}

/// Parse prevalence comparison operator
fn prevalence_operator(input: &str) -> ParseResult<'_, PrevalenceOperator> {
    alt((
        value(PrevalenceOperator::Lte, tag("<=")),
        value(PrevalenceOperator::Gte, tag(">=")),
        value(PrevalenceOperator::Ne, tag("!=")),
        value(PrevalenceOperator::Lt, tag("<")),
        value(PrevalenceOperator::Gt, tag(">")),
        value(PrevalenceOperator::Eq, tag("=")),
    ))
    .parse(input)
}

/// Parse prevalence threshold value
/// For count fields: just a number (e.g., 5)
/// For timestamp fields: now() - duration (e.g., now() - 24h or now()-86400)
fn prevalence_threshold<'a>(
    input: &'a str,
    field: &PrevalenceField,
) -> ParseResult<'a, PrevalenceThreshold> {
    if field.is_timestamp_field() {
        // Parse "now() - duration" syntax
        let (input, _) = tag_no_case("now").parse(input)?;
        let (input, _) = multispace0(input)?;
        let (input, _) = char('(').parse(input)?;
        let (input, _) = char(')').parse(input)?;
        let (input, _) = multispace0(input)?;
        let (input, _) = char('-').parse(input)?;
        let (input, _) = multispace0(input)?;
        // Parse duration with or without unit suffix (bare number = seconds)
        let (input, dur) = duration_with_optional_unit(input)?;
        Ok((input, PrevalenceThreshold::Duration(dur)))
    } else {
        // Parse count threshold
        let (input, count) = map_res(digit1, |s: &str| s.parse::<u64>()).parse(input)?;
        Ok((input, PrevalenceThreshold::Count(count)))
    }
}

/// Parse duration with optional unit suffix - bare number means seconds
/// Also supports SQL INTERVAL syntax: INTERVAL N UNIT (e.g., INTERVAL 24 HOUR)
fn duration_with_optional_unit(input: &str) -> ParseResult<'_, Duration> {
    // Try SQL INTERVAL syntax first: INTERVAL N UNIT
    if let Ok((input, _)) = tag_no_case::<_, _, nom::error::Error<&str>>("INTERVAL").parse(input) {
        let (input, _) = multispace1(input)?;
        let (input, num) = map_res(digit1, |s: &str| s.parse::<u64>()).parse(input)?;
        let (input, _) = multispace1(input)?;
        let (input, seconds) = alt((
            value(num, alt((tag_no_case("SECOND"), tag_no_case("SECONDS")))),
            value(
                num * 60,
                alt((tag_no_case("MINUTE"), tag_no_case("MINUTES"))),
            ),
            value(num * 3600, alt((tag_no_case("HOUR"), tag_no_case("HOURS")))),
            value(num * 86400, alt((tag_no_case("DAY"), tag_no_case("DAYS")))),
            value(
                num * 604800,
                alt((tag_no_case("WEEK"), tag_no_case("WEEKS"))),
            ),
            value(
                num * 2592000,
                alt((tag_no_case("MONTH"), tag_no_case("MONTHS"))),
            ),
        ))
        .parse(input)?;
        return Ok((input, Duration::from_secs(seconds)));
    }

    let (input, num) = map_res(digit1, |s: &str| s.parse::<u64>()).parse(input)?;
    // Try to parse optional unit suffix
    let (input, unit) = opt(one_of("smhdSMHD")).parse(input)?;

    let seconds = match unit.map(|c| c.to_ascii_lowercase()) {
        Some('s') | None => num, // No unit = seconds (PPL compatibility)
        Some('m') => num * 60,
        Some('h') => num * 3600,
        Some('d') => num * 86400,
        _ => unreachable!(),
    };

    Ok((input, Duration::from_secs(seconds)))
}

/// Parse prevalence window specification: window=1h, window=24h, etc.
fn prevalence_window_spec(input: &str) -> ParseResult<'_, PrevalenceTimeWindow> {
    let (input, _) = alt((tag_no_case("window"), tag_no_case("interval"))).parse(input)?;
    let (input, _) = char('=').parse(input)?;

    alt((
        value(PrevalenceTimeWindow::OneHour, tag_no_case("1h")),
        value(PrevalenceTimeWindow::TwentyFourHours, tag_no_case("24h")),
        value(PrevalenceTimeWindow::SevenDays, tag_no_case("7d")),
        value(PrevalenceTimeWindow::ThirtyDays, tag_no_case("30d")),
    ))
    .parse(input)
}

/// Parse sample command: sample [N]
/// Returns a random sample of N events (default: 1000)
/// Examples:
///   | sample
///   | sample 100
pub(super) fn sample_command(input: &str) -> ParseResult<'_, Command> {
    let (input, _) = tag_no_case("sample").parse(input)?;

    // Parse optional limit (default: 1000)
    let (input, limit) = opt(preceded(
        multispace1,
        map_res(digit1, |s: &str| s.parse::<usize>()),
    ))
    .parse(input)?;

    Ok((
        input,
        Command::Sample {
            limit: limit.unwrap_or(1000),
        },
    ))
}

/// Parse reverse command: reverse
/// Reverses the order of events (ascending by timestamp)
/// Example:
///   | head 100 | reverse
pub(super) fn reverse_command(input: &str) -> ParseResult<'_, Command> {
    let (input, _) = tag_no_case("reverse").parse(input)?;
    Ok((input, Command::Reverse))
}

/// Parse eventstats command: eventstats agg1, agg2 [by field1, field2]
/// Calculates statistics and adds them to each row (unlike stats which aggregates)
/// Examples:
///   | eventstats count() by src_ip
///   | eventstats avg(bytes_in) as avg_bytes by user
pub(super) fn eventstats_command(input: &str) -> ParseResult<'_, Command> {
    let (input, _) = tag_no_case("eventstats").parse(input)?;
    let (input, _) = multispace1(input)?;
    let (input, aggregations) = aggregation_list(input)?;
    let (input, group_by) = opt(preceded(
        delimited(multispace1, tag_no_case("by"), multispace1),
        field_list,
    ))
    .parse(input)?;

    Ok((
        input,
        Command::EventStats {
            aggregations,
            group_by,
        },
    ))
}

/// Parse content inside sequence brackets, handling nested ] in regex and strings
fn sequence_bracket_content(input: &str) -> ParseResult<'_, &str> {
    let mut depth = 0; // Track nested brackets in regex character classes
    let mut in_regex = false;
    let mut in_string = false;
    let mut string_char = '"';
    let mut chars = input.char_indices().peekable();
    let mut end_pos = 0;

    while let Some((pos, c)) = chars.next() {
        if in_string {
            if c == '\\' {
                // Skip escaped character
                chars.next();
            } else if c == string_char {
                in_string = false;
            }
        } else if in_regex {
            if c == '\\' {
                // Skip escaped character in regex
                chars.next();
            } else if c == '[' {
                depth += 1;
            } else if c == ']' {
                if depth > 0 {
                    depth -= 1;
                }
            } else if c == '/' {
                // End of regex - consume optional flags
                in_regex = false;
                while let Some(&(_, fc)) = chars.peek() {
                    if fc.is_ascii_alphabetic() {
                        chars.next();
                    } else {
                        break;
                    }
                }
            }
        } else {
            match c {
                '"' | '\'' => {
                    in_string = true;
                    string_char = c;
                }
                '/' => {
                    // Check if this looks like start of regex (preceded by = or space)
                    in_regex = true;
                }
                ']' => {
                    // Found the closing bracket
                    end_pos = pos;
                    break;
                }
                _ => {}
            }
        }
        end_pos = pos + c.len_utf8();
    }

    if end_pos == 0 && !input.is_empty() {
        end_pos = input.len();
    }

    let content = &input[..end_pos];
    let remaining = &input[end_pos..];

    if content.is_empty() {
        return Err(nom::Err::Error(nom::error::Error::new(
            input,
            nom::error::ErrorKind::TakeWhile1,
        )));
    }

    Ok((remaining, content))
}

pub(super) fn sequence_command(input: &str) -> ParseResult<'_, Command> {
    let (input, _) = tag_no_case("sequence").parse(input)?;
    let (input, _) = multispace1(input)?;

    // Parse "by field1, field2"
    let (input, _) = tag_no_case("by").parse(input)?;
    let (input, _) = multispace1(input)?;
    let (input, group_by) = field_list(input)?;

    // Parse optional "maxspan=5m"
    let (input, maxspan) = opt(preceded(
        delimited(multispace1, tag_no_case("maxspan="), multispace0),
        duration,
    ))
    .parse(input)?;

    // Parse optional "maxgap=5m" (accepted for backwards compat, parsed and ignored)
    let (input, _maxgap) = opt(preceded(
        delimited(multispace1, tag_no_case("maxgap="), multispace0),
        duration,
    ))
    .parse(input)?;

    // Parse optional "fields(field1, field2, ...)" to capture additional fields from each step
    let (input, capture_fields) = opt(preceded(
        multispace1,
        delimited(
            tag_no_case("fields("),
            separated_list0(delimited(multispace0, char(','), multispace0), field_name),
            preceded(multispace0, char(')')),
        ),
    ))
    .parse(input)?;
    let capture_fields = capture_fields.unwrap_or_default();

    // Parse sequence conditions: [condition1] [condition2] ...
    // Use custom bracket parser to handle ] inside regex patterns
    let (input, _) = multispace0(input)?;
    let (input, conditions) = many1(|input| {
        let (input, _) = multispace0(input)?;
        let (input, _) = char('[').parse(input)?;
        let (input, content) = sequence_bracket_content(input)?;
        let (input, _) = char(']').parse(input)?;

        // Parse the bracket content as a search expression
        let (remaining, condition) = search_expr(content)?;
        if !remaining.trim().is_empty() {
            return Err(nom::Err::Error(nom::error::Error::new(
                input,
                nom::error::ErrorKind::Complete,
            )));
        }

        Ok((input, condition))
    })
    .parse(input)?;

    Ok((
        input,
        Command::Sequence {
            group_by,
            maxspan,
            conditions,
            capture_fields,
        },
    ))
}

pub(super) fn funnel_command(input: &str) -> ParseResult<'_, Command> {
    let (input, _) = tag_no_case("funnel").parse(input)?;
    let (input, _) = multispace1(input)?;

    // Parse "by field1, field2"
    let (input, _) = tag_no_case("by").parse(input)?;
    let (input, _) = multispace1(input)?;
    let (input, group_by) = field_list(input)?;

    // Parse window/maxspan parameter - try both "window=" and "maxspan=" as aliases
    // These may appear before or after bracket steps, so try here first
    let (input, window_before) = opt(preceded(
        multispace1,
        preceded(
            alt((tag_no_case("window="), tag_no_case("maxspan="))),
            duration,
        ),
    ))
    .parse(input)?;

    // Try bracket syntax first: [condition1] [condition2] ...
    let trimmed = input.trim_start();
    if trimmed.starts_with('[') {
        let (input, _) = multispace0(input)?;
        let (input, bracket_steps) = many1(|input| {
            let (input, _) = multispace0(input)?;
            let (input, _) = char('[').parse(input)?;
            let (input, content) = sequence_bracket_content(input)?;
            let (input, _) = char(']').parse(input)?;

            // Parse the bracket content as a search expression
            let (remaining, condition) = search_expr(content)?;
            if !remaining.trim().is_empty() {
                return Err(nom::Err::Error(nom::error::Error::new(
                    input,
                    nom::error::ErrorKind::Complete,
                )));
            }

            Ok((input, condition))
        })
        .parse(input)?;

        // Parse optional window/maxspan after brackets if not found before
        let (input, window_after) = if window_before.is_none() {
            opt(preceded(
                multispace1,
                preceded(
                    alt((tag_no_case("window="), tag_no_case("maxspan="))),
                    duration,
                ),
            ))
            .parse(input)?
        } else {
            (input, None)
        };

        let window = window_before
            .or(window_after)
            .unwrap_or(Duration::from_secs(3600));

        // Convert bracket conditions to named steps
        let steps: Vec<(String, SearchExpr)> = bracket_steps
            .into_iter()
            .enumerate()
            .map(|(i, cond)| (format!("step{}", i + 1), cond))
            .collect();

        return Ok((
            input,
            Command::Funnel {
                group_by,
                window,
                steps,
            },
        ));
    }

    // Classic step syntax: window is required if not already parsed
    let (input, window) = if let Some(w) = window_before {
        (input, w)
    } else {
        // window= is required for classic syntax
        let (input, _) = multispace1(input)?;
        let (input, _) = alt((tag_no_case("window="), tag_no_case("maxspan="))).parse(input)?;
        let (input, w) = duration(input)?;
        (input, w)
    };

    // Parse steps: step1="value" or step1=(action="login") or step1=(action="login" status="ok")
    let (input, steps) = many1(|input| {
        let (input, _) = multispace1(input)?;
        let (input, _) = tag_no_case("step").parse(input)?;
        let (input, step_num) = digit1(input)?;
        let (input, _) = char('=').parse(input)?;

        // Try parenthesized expression first: step1=(action="login")
        if let Ok((r, expr)) = parse_paren_search_expr(input) {
            return Ok((r, (format!("step{}", step_num), expr)));
        }
        // Quoted string: step1="login"
        let (input, value) = quoted_string(input)?;
        let condition = SearchExpr::Keyword(value.to_string());
        Ok((input, (format!("step{}", step_num), condition)))
    })
    .parse(input)?;

    Ok((
        input,
        Command::Funnel {
            group_by,
            window,
            steps,
        },
    ))
}

pub(super) fn anomaly_command(input: &str) -> ParseResult<'_, Command> {
    let (input, _) = tag_no_case("anomaly").parse(input)?;
    let (input, _) = multispace1(input)?;

    // Try classic syntax: "field=field_name" first
    let (field, remaining) = if let Ok((next, _)) =
        tag_no_case::<_, _, nom::error::Error<&str>>("field=").parse(input)
    {
        let (next, f) = field_name(next)?;
        (f, next)
    }
    // Aggregation-first syntax: "count()" or "sum(bytes)" — keep the full expression
    // so the SQL gen can compute it as an aggregation, not treat it as a column name
    else if let Ok((agg_name_end, agg_name)) =
        recognize::<_, nom::error::Error<&str>, _>(nom::sequence::pair(
            nom::bytes::complete::take_while1::<_, _, nom::error::Error<&str>>(|c: char| {
                c.is_alphanumeric() || c == '_'
            }),
            nom::sequence::delimited(
                char('('),
                nom::bytes::complete::take_while(|c: char| c != ')'),
                char(')'),
            ),
        ))
        .parse(input)
    {
        // Keep full expression like "count()" or "sum(bytes_out)"
        (agg_name.to_string(), agg_name_end)
    }
    // Bare field name syntax: "anomaly threat_score by src_ip"
    else if let Ok((next, f)) = field_name(input) {
        (f, next)
    } else {
        return Err(nom::Err::Error(nom::error::Error::new(
            input,
            nom::error::ErrorKind::Tag,
        )));
    };

    // Parse optional parameters in any order: by=, by , threshold=, method=, span=, sensitivity=
    let mut by_fields: Vec<String> = Vec::new();
    let mut threshold: Option<f64> = None;
    let mut method: Option<AnomalyMethod> = None;

    let mut remaining = remaining;

    loop {
        // Try to consume whitespace, if none and we haven't reached end, break
        let (input, ws) = multispace0(remaining)?;
        if ws.is_empty() && !remaining.is_empty() {
            break;
        }
        remaining = input;

        if remaining.is_empty() || remaining.starts_with('|') {
            break;
        }

        // Try parsing each optional parameter
        // Support both "by field1, field2" and "by=field" syntax
        if let Ok((input, _)) = tag_no_case::<_, _, nom::error::Error<&str>>("by=").parse(remaining)
        {
            if !by_fields.is_empty() {
                break; // Already parsed, stop
            }
            let (input, val) = field_name(input)?;
            by_fields.push(val.to_string());
            remaining = input;
        } else if let Ok((input, _)) =
            terminated::<_, _, nom::error::Error<&str>, _, _>(tag_no_case("by"), multispace1)
                .parse(remaining)
        {
            if !by_fields.is_empty() {
                break;
            }
            // Parse comma-separated field list: field1, field2, field3
            let (input, first) = field_name(input)?;
            by_fields.push(first.to_string());
            let mut input = input;
            loop {
                let (next, _) = multispace0(input)?;
                if let Ok((next, _)) = char::<_, nom::error::Error<&str>>(',').parse(next) {
                    let (next, _) = multispace0(next)?;
                    if let Ok((next, f)) = field_name(next) {
                        by_fields.push(f.to_string());
                        input = next;
                    } else {
                        break;
                    }
                } else {
                    // Don't consume whitespace here — let the outer loop handle it
                    // so it can detect leading whitespace before method=/threshold= etc.
                    break;
                }
            }
            remaining = input;
        } else if let Ok((input, _)) =
            tag_no_case::<_, _, nom::error::Error<&str>>("threshold=").parse(remaining)
        {
            if threshold.is_some() {
                break; // Already parsed, stop
            }
            let (input, val) = map_res(
                recognize(pair(digit1, opt(pair(char('.'), digit1)))),
                |s: &str| s.parse::<f64>(),
            )
            .parse(input)?;
            threshold = Some(val);
            remaining = input;
        } else if let Ok((input, _)) =
            tag_no_case::<_, _, nom::error::Error<&str>>("method=").parse(remaining)
        {
            if method.is_some() {
                break; // Already parsed, stop
            }
            let (input, val) = alt((
                value(AnomalyMethod::ZScore, tag_no_case("zscore")),
                value(AnomalyMethod::Mad, tag_no_case("mad")),
            ))
            .parse(input)?;
            method = Some(val);
            remaining = input;
        }
        // span= parameter (accepted for backwards compat, parsed and ignored)
        else if let Ok((input, _)) =
            tag_no_case::<_, _, nom::error::Error<&str>>("span=").parse(remaining)
        {
            let (input, _dur) = duration(input)?;
            remaining = input;
        }
        // sensitivity=high|medium|low (accepted, parsed and ignored)
        else if let Ok((input, _)) =
            tag_no_case::<_, _, nom::error::Error<&str>>("sensitivity=").parse(remaining)
        {
            let (input, _) = alt((
                tag_no_case::<_, _, nom::error::Error<&str>>("high"),
                tag_no_case("medium"),
                tag_no_case("low"),
            ))
            .parse(input)?;
            remaining = input;
        } else {
            break; // No more recognized parameters
        }
    }

    Ok((
        remaining,
        Command::Anomaly {
            field,
            by_fields,
            threshold: threshold.unwrap_or(3.0),
            method: method.unwrap_or_default(),
        },
    ))
}

/// Parse inputlookup command: inputlookup url="URL" [format=json|csv] [key=field] [timeout=N] [max_rows=N] [cache_ttl=N]
/// Examples:
///   # Data source mode - fetch URL and return as results
///   | inputlookup url="https://feeds.example.com/iocs.csv" format=csv
///
///   # Enrichment mode - join URL results with search results
///   | inputlookup url="https://api.ipinfo.io/{src_ip}/json" key=src_ip format=json
pub(super) fn inputlookup_command(input: &str) -> ParseResult<'_, Command> {
    let (input, _) = tag_no_case("inputlookup").parse(input)?;
    let (input, _) = multispace1(input)?;

    // Try url="..." syntax first, otherwise accept a bare table/feed name
    let (input, url_str) =
        if let Ok((next, _)) = tag_no_case::<_, _, nom::error::Error<&str>>("url=").parse(input) {
            let (next, s) = quoted_string(next)?;
            (next, s)
        } else {
            // Positional table name: inputlookup threat_intel
            // Parse a bare identifier (alphanumeric + underscore + hyphen + dot)
            let (next, name) =
                nom::bytes::complete::take_while1::<_, _, nom::error::Error<&str>>(|c: char| {
                    c.is_alphanumeric() || c == '_' || c == '-' || c == '.'
                })
                .parse(input)
                .map_err(|_| {
                    nom::Err::Error(nom::error::Error::new(input, nom::error::ErrorKind::Tag))
                })?;
            (next, format!("lookup://{}", name))
        };

    // Parse optional parameters in any order: format=, key=, timeout=, max_rows=, cache_ttl=
    let mut format: Option<InputLookupFormat> = None;
    let mut key_field: Option<String> = None;
    let mut timeout_secs: Option<u32> = None;
    let mut max_rows: Option<usize> = None;
    let mut cache_ttl_secs: Option<u32> = None;

    let mut remaining = input;

    loop {
        // Try to consume whitespace
        let (input, ws) = multispace0(remaining)?;
        if ws.is_empty() && !remaining.is_empty() && !remaining.starts_with('|') {
            break;
        }
        remaining = input;

        // Check if we've reached a pipe (end of command)
        if remaining.is_empty() || remaining.starts_with('|') {
            break;
        }

        // Try parsing each optional parameter
        if let Ok((input, _)) =
            tag_no_case::<_, _, nom::error::Error<&str>>("format=").parse(remaining)
        {
            if format.is_some() {
                break;
            }
            let (input, val) = alt((
                value(InputLookupFormat::Json, tag_no_case("json")),
                value(InputLookupFormat::Csv, tag_no_case("csv")),
            ))
            .parse(input)?;
            format = Some(val);
            remaining = input;
        } else if let Ok((input, _)) =
            tag_no_case::<_, _, nom::error::Error<&str>>("key=").parse(remaining)
        {
            if key_field.is_some() {
                break;
            }
            let (input, val) = field_name(input)?;
            key_field = Some(val);
            remaining = input;
        } else if let Ok((input, _)) =
            tag_no_case::<_, _, nom::error::Error<&str>>("timeout=").parse(remaining)
        {
            if timeout_secs.is_some() {
                break;
            }
            let (input, val) = map_res(digit1, |s: &str| s.parse::<u32>()).parse(input)?;
            // Clamp to valid range (1-60)
            timeout_secs = Some(val.clamp(1, 60));
            remaining = input;
        } else if let Ok((input, _)) =
            tag_no_case::<_, _, nom::error::Error<&str>>("max_rows=").parse(remaining)
        {
            if max_rows.is_some() {
                break;
            }
            let (input, val) = map_res(digit1, |s: &str| s.parse::<usize>()).parse(input)?;
            // Clamp to valid range (1-100000)
            max_rows = Some(val.clamp(1, 100000));
            remaining = input;
        } else if let Ok((input, _)) =
            tag_no_case::<_, _, nom::error::Error<&str>>("cache_ttl=").parse(remaining)
        {
            if cache_ttl_secs.is_some() {
                break;
            }
            let (input, val) = map_res(digit1, |s: &str| s.parse::<u32>()).parse(input)?;
            // Clamp to valid range (0-3600)
            cache_ttl_secs = Some(val.min(3600));
            remaining = input;
        } else {
            break;
        }
    }

    Ok((
        remaining,
        Command::InputLookup {
            url: UrlTemplate::new(&url_str),
            format: format.unwrap_or_default(),
            key_field,
            timeout_secs: timeout_secs.unwrap_or(30),
            max_rows: max_rows.unwrap_or(10000),
            cache_ttl_secs: cache_ttl_secs.unwrap_or(300),
        },
    ))
}

/// Parse lateral command: trace lateral movement paths across the network
///
/// Syntax: lateral [seed=user|host] [entity=field] [maxhops=N] [window=duration] [methods=auth,network,process]
///
/// Examples:
///   user="jsmith" | lateral
///   src_host="WKS-0142" | lateral seed=host
///   user="jsmith" | lateral maxhops=3 window=12h methods=auth,network
pub(super) fn lateral_command(input: &str) -> ParseResult<'_, Command> {
    let (input, _) = tag_no_case("lateral").parse(input)?;

    // Try bracket subsearch syntax: lateral [search src_ip=$src_ip$ | stats ...]
    let trimmed = input.trim_start();
    if trimmed.starts_with('[') {
        let remaining = trimmed;
        let (remaining, _) = char::<_, nom::error::Error<&str>>('[')
            .parse(remaining)
            .map_err(|_| {
                nom::Err::Error(nom::error::Error::new(input, nom::error::ErrorKind::Char))
            })?;
        // Consume everything until the matching closing bracket
        let (remaining, _content) = lateral_bracket_content(remaining)?;
        let (remaining, _) = char::<_, nom::error::Error<&str>>(']')
            .parse(remaining)
            .map_err(|_| {
                nom::Err::Error(nom::error::Error::new(input, nom::error::ErrorKind::Char))
            })?;

        // Use defaults — the AST doesn't support a subsearch field yet
        return Ok((
            remaining,
            Command::Lateral {
                seed_type: LateralSeedType::default(),
                entity_field: None,
                max_hops: 4,
                time_window: None,
                methods: LateralMethod::all(),
            },
        ));
    }

    // Classic key=value syntax: parse optional parameters in any order
    let mut seed_type: Option<LateralSeedType> = None;
    let mut entity_field: Option<String> = None;
    let mut max_hops: Option<u32> = None;
    let mut time_window: Option<Duration> = None;
    let mut methods: Option<Vec<LateralMethod>> = None;

    let mut remaining = input;

    loop {
        let (input, ws) = multispace0(remaining)?;
        if ws.is_empty() && !remaining.is_empty() && !remaining.starts_with('|') {
            break;
        }
        remaining = input;

        if remaining.is_empty() || remaining.starts_with('|') {
            break;
        }

        if let Ok((input, _)) =
            tag_no_case::<_, _, nom::error::Error<&str>>("seed=").parse(remaining)
        {
            if seed_type.is_some() {
                break;
            }
            let (input, val) = alt((
                value(LateralSeedType::Auto, tag_no_case("auto")),
                value(LateralSeedType::User, tag_no_case("user")),
                value(LateralSeedType::Host, tag_no_case("host")),
            ))
            .parse(input)?;
            seed_type = Some(val);
            remaining = input;
        } else if let Ok((input, _)) =
            tag_no_case::<_, _, nom::error::Error<&str>>("entity=").parse(remaining)
        {
            if entity_field.is_some() {
                break;
            }
            let (input, val) = field_name(input)?;
            entity_field = Some(val);
            remaining = input;
        } else if let Ok((input, _)) =
            tag_no_case::<_, _, nom::error::Error<&str>>("maxhops=").parse(remaining)
        {
            if max_hops.is_some() {
                break;
            }
            let (input, val) = map_res(digit1, |s: &str| s.parse::<u32>()).parse(input)?;
            max_hops = Some(val.clamp(1, 10));
            remaining = input;
        } else if let Ok((input, _)) =
            tag_no_case::<_, _, nom::error::Error<&str>>("window=").parse(remaining)
        {
            if time_window.is_some() {
                break;
            }
            let (input, dur) = duration(input)?;
            time_window = Some(dur);
            remaining = input;
        } else if let Ok((input, _)) =
            tag_no_case::<_, _, nom::error::Error<&str>>("methods=").parse(remaining)
        {
            if methods.is_some() {
                break;
            }
            let (input, method_list) = separated_list0(
                char(','),
                alt((
                    value(LateralMethod::Auth, tag_no_case("auth")),
                    value(LateralMethod::Network, tag_no_case("network")),
                    value(LateralMethod::Process, tag_no_case("process")),
                )),
            )
            .parse(input)?;
            if method_list.is_empty() {
                return Err(nom::Err::Error(nom::error::Error::new(
                    input,
                    nom::error::ErrorKind::SeparatedList,
                )));
            }
            methods = Some(method_list);
            remaining = input;
        } else {
            break;
        }
    }

    Ok((
        remaining,
        Command::Lateral {
            seed_type: seed_type.unwrap_or_default(),
            entity_field,
            max_hops: max_hops.unwrap_or(4),
            time_window,
            methods: methods.unwrap_or_else(LateralMethod::all),
        },
    ))
}

/// Parse content inside lateral brackets, handling nested brackets, strings, and pipes
fn lateral_bracket_content(input: &str) -> ParseResult<'_, &str> {
    let mut depth = 0;
    let mut in_string = false;
    let mut string_char = '"';
    let mut chars = input.char_indices().peekable();
    let mut end_pos = 0;

    while let Some((pos, c)) = chars.next() {
        if in_string {
            if c == '\\' {
                chars.next(); // skip escaped char
            } else if c == string_char {
                in_string = false;
            }
        } else {
            match c {
                '"' | '\'' => {
                    in_string = true;
                    string_char = c;
                }
                '[' => depth += 1,
                ']' => {
                    if depth > 0 {
                        depth -= 1;
                    } else {
                        // Found the matching closing bracket
                        let content = &input[..pos];
                        if content.is_empty() {
                            return Err(nom::Err::Error(nom::error::Error::new(
                                input,
                                nom::error::ErrorKind::TakeWhile1,
                            )));
                        }
                        return Ok((&input[pos..], content));
                    }
                }
                _ => {}
            }
        }
        end_pos = pos + c.len_utf8();
    }

    // If we reach end without closing bracket, return error
    Err(nom::Err::Error(nom::error::Error::new(
        &input[end_pos..],
        nom::error::ErrorKind::Char,
    )))
}
