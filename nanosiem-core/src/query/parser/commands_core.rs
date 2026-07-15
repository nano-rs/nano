// SPDX-License-Identifier: AGPL-3.0-or-later

//! Core command parsers for the query parser
//!
//! Handles: stats, chart, streamstats, where, search, sort, head, tail,
//! timechart, table, rename, lookup, and shared helpers (aggregation_list,
//! aggregation, agg_func, field_list, duration, span_spec).

use nom::{
    branch::alt,
    bytes::complete::{tag_no_case, take_while1},
    character::complete::{char, digit1, multispace0, multispace1, one_of},
    combinator::{map, map_res, opt, value},
    multi::separated_list1,
    sequence::{delimited, pair, preceded, terminated},
    Parser,
};
use std::time::Duration;

use super::eval_expr::eval_expression;
use super::search_expr::search_expr;
use super::values::{field_name, field_name_with_wildcard, quoted_string};
use super::ParseResult;
use crate::query::ast::*;

// Re-export helpers used by other command modules
pub(super) use self::duration_fn as duration;
pub(super) use self::field_list_fn as field_list;
/// Parse a piped command
pub(super) fn command(input: &str) -> ParseResult<'_, Command> {
    alt((
        alt((
            // streamstats must come before stats (longer match first)
            super::commands_core::streamstats_command,
            super::commands_core::stats_command,
            super::commands_core::chart_command,
            super::commands_core::where_command,
            super::commands_core::search_command,
            super::commands_core::sort_command,
            super::commands_core::head_command,
            super::commands_core::tail_command,
            super::commands_core::timechart_command,
            super::commands_core::table_command,
        )),
        alt((
            super::commands_core::rename_command,
            super::commands_core::lookup_command,
            super::eval_expr::eval_command,
            super::commands_extended::dedup_command,
            super::commands_extended::bin_command,
            super::commands_extended::rex_command,
            super::commands_extended::regex_command,
            super::commands_extended::fields_command,
            super::commands_extended::top_command,
        )),
        alt((
            super::commands_extended::rare_command,
            super::commands_extended::transaction_command,
            super::commands_extended::fillnull_command,
            super::commands_extended::mvexpand_command,
            super::commands_extended::spath_command,
            super::commands_extended::append_command,
            super::commands_extended::join_command,
            super::commands_extended::format_command,
            super::commands_extended::return_command,
        )),
        alt((
            super::commands_security::risk_command,
            super::commands_security::prevalence_command,
            // New commands
            super::commands_security::sample_command,
            super::commands_security::reverse_command,
            super::commands_security::eventstats_command,
            super::commands_security::sequence_command,
            super::commands_security::funnel_command,
            super::commands_security::anomaly_command,
            super::commands_security::inputlookup_command,
            super::commands_enrichment::tree_command,
            super::commands_enrichment::resolve_identity_command,
            super::commands_enrichment::asset_command,
            super::commands_enrichment::cloud_command,
            super::commands_enrichment::baseline_command,
            super::commands_security::lateral_command,
            super::commands_enrichment::retro_command,
            super::commands_enrichment::ai_command,
            // Command-page directives (NAN-1560). Plural `services` BEFORE
            // singular `service` so `| services` isn't mis-parsed as
            // `service` with the literal token "services" as its name.
            alt((
                super::commands_enrichment::services_command,
                super::commands_enrichment::service_command,
                super::commands_enrichment::trace_command,
                super::commands_enrichment::metric_command,
            )),
            super::commands_core::output_command,
        )),
    ))
    .parse(input)
}

/// Parse stats command: stats agg1, agg2 [by field1, field2]
fn stats_command(input: &str) -> ParseResult<'_, Command> {
    let (input, _) = tag_no_case("stats").parse(input)?;
    let (input, _) = multispace1(input)?;
    let (input, aggregations) = aggregation_list(input)?;
    let (input, group_by) = opt(preceded(
        delimited(multispace1, tag_no_case("by"), multispace1),
        field_list_fn,
    ))
    .parse(input)?;

    Ok((
        input,
        Command::Stats {
            aggregations,
            group_by,
        },
    ))
}

/// Parse chart command: chart agg1, agg2 [by|over field1, field2] [by split_field]
/// Chart is an alias for stats, used for visualization.
/// Accepts `over` as an alias for `by`. When both `over` and `by` are present,
/// `over` provides the main grouping and `by` provides the split-by (the split-by
/// fields are appended to the group_by list).
fn chart_command(input: &str) -> ParseResult<'_, Command> {
    let (input, _) = tag_no_case("chart").parse(input)?;
    let (input, _) = multispace1(input)?;
    let (input, aggregations) = aggregation_list(input)?;

    // Try "over" first, then "by"
    let (input, over_fields) = opt(preceded(
        delimited(multispace1, tag_no_case("over"), multispace1),
        field_list_fn,
    ))
    .parse(input)?;

    let (input, by_fields) = opt(preceded(
        delimited(multispace1, tag_no_case("by"), multispace1),
        field_list_fn,
    ))
    .parse(input)?;

    // Merge: over fields come first, then by fields
    let group_by = match (over_fields, by_fields) {
        (Some(mut over), Some(by)) => {
            over.extend(by);
            Some(over)
        }
        (Some(over), None) => Some(over),
        (None, Some(by)) => Some(by),
        (None, None) => None,
    };

    Ok((
        input,
        Command::Chart {
            aggregations,
            group_by,
        },
    ))
}

/// Parse streamstats command: streamstats [current=true|false] [window=N] agg1, agg2 [by field1, field2]
/// Example: streamstats current=false last(timestamp) as prev_ts by dest_host
/// Example: streamstats window=10 avg(bytes) as rolling_avg by src_ip
fn streamstats_command(input: &str) -> ParseResult<'_, Command> {
    let (input, _) = tag_no_case("streamstats").parse(input)?;
    let (input, _) = multispace1(input)?;

    // Parse optional current=true|false
    let (input, current_opt) = opt(terminated(
        preceded(
            tag_no_case("current="),
            alt((
                value(true, tag_no_case("true")),
                value(false, tag_no_case("false")),
            )),
        ),
        multispace1,
    ))
    .parse(input)?;
    let current = current_opt.unwrap_or(true);

    // Parse optional window=N
    let (input, window) = opt(terminated(
        preceded(
            tag_no_case("window="),
            map_res(digit1, |s: &str| s.parse::<usize>()),
        ),
        multispace1,
    ))
    .parse(input)?;

    // Parse aggregations
    let (input, aggregations) = aggregation_list(input)?;

    // Parse optional by clause
    let (input, group_by) = opt(preceded(
        delimited(multispace1, tag_no_case("by"), multispace1),
        field_list_fn,
    ))
    .parse(input)?;

    Ok((
        input,
        Command::StreamStats {
            aggregations,
            group_by,
            current,
            window,
        },
    ))
}

/// Parse where command: where condition
fn where_command(input: &str) -> ParseResult<'_, Command> {
    let (input, _) = tag_no_case("where").parse(input)?;
    let (input, _) = multispace1(input)?;
    let (input, condition) = search_expr(input)?;

    Ok((input, Command::Where { condition }))
}

/// Parse search command (piped): | search condition
/// Identical to | where but uses search expression syntax.
/// Commonly used after commands that add/modify fields (e.g., resolve_identity, eval).
fn search_command(input: &str) -> ParseResult<'_, Command> {
    let (input, _) = tag_no_case("search").parse(input)?;
    let (input, _) = multispace1(input)?;
    let (input, condition) = search_expr(input)?;

    Ok((input, Command::Where { condition }))
}

/// Parse sort command: sort [N] [-|+]field, [-|+]field2, ... or sort field [asc|desc]
/// Supports an inline result limit via `sort N field` (N comes before the field list).
/// Supports both prefix style (-field for desc) and suffix style (field desc).
/// Supports multiple fields separated by commas.
fn sort_command(input: &str) -> ParseResult<'_, Command> {
    let (input, _) = tag_no_case("sort").parse(input)?;
    let (input, _) = multispace1(input)?;

    // Optional "by" keyword (for SQL-style: sort by field)
    let (input, _) = opt(terminated(tag_no_case("by"), multispace1)).parse(input)?;

    // Optional leading number N: `sort N field` = sort by field, limit results to N.
    let (input, limit) = opt(terminated(
        map_res(digit1, |s: &str| s.parse::<usize>()),
        multispace1,
    ))
    .parse(input)?;

    // Parse first field
    let (mut input, first_field) = sort_field_spec(input)?;
    let mut fields = vec![first_field];

    // Parse additional fields (comma or space-separated)
    loop {
        // Try comma separator first
        let comma: Result<(&str, char), nom::Err<nom::error::Error<&str>>> =
            delimited(multispace0, char(','), multispace0).parse(input);
        if let Ok((rest, _)) = comma {
            if let Ok((rest2, field)) = sort_field_spec(rest) {
                fields.push(field);
                input = rest2;
                continue;
            }
        }

        // Try space separator - peek to see if next token starts a sort field
        // (a direction prefix -/+ or a field name, but not a pipe | or keyword=)
        let space: Result<(&str, &str), nom::Err<nom::error::Error<&str>>> = multispace1(input);
        if let Ok((rest, _)) = space {
            // Stop if this is limit=N (not a sort field)
            if rest.to_ascii_lowercase().starts_with("limit=") {
                break;
            }
            let looks_like_sort_field = rest.chars().next().map_or(false, |c| {
                c == '-' || c == '+' || c.is_alphabetic() || c == '_' || c == '"'
            });
            if looks_like_sort_field {
                if let Ok((rest2, field)) = sort_field_spec(rest) {
                    fields.push(field);
                    input = rest2;
                    continue;
                }
            }
        }

        break;
    }

    // Support trailing limit=N (e.g., "sort -count limit=10")
    let (input, trailing_limit) = opt(preceded(
        multispace1,
        preceded(
            tag_no_case::<_, _, nom::error::Error<&str>>("limit="),
            map_res(digit1, |s: &str| s.parse::<usize>()),
        ),
    ))
    .parse(input)?;
    let limit = limit.or(trailing_limit);

    Ok((input, Command::Sort { fields, limit }))
}

/// Parse a single sort field specification: [-|+]field or field [asc|desc]
/// Also supports aggregation function syntax like sum(field) for sorting after stats
/// Supports quoted field names for fields with spaces
fn sort_field_spec(input: &str) -> ParseResult<'_, SortField> {
    // Check for prefix direction (-/+), with optional whitespace after
    let (input, prefix_dir) = opt(one_of("-+")).parse(input)?;
    let (input, _) = multispace0(input)?;

    // Try to parse as aggregation function first (e.g., sum(bytes_out))
    // This allows sorting by the aggregation column name after stats
    let (input, field) = alt((
        // Try aggregation function syntax: func(field)
        map(
            pair(
                take_while1(|c: char| c.is_alphanumeric() || c == '_'),
                delimited(char('('), alt((quoted_string, field_name)), char(')')),
            ),
            |(func, field_name): (&str, String)| format!("{}({})", func, field_name),
        ),
        // Quoted field name (for fields with spaces)
        quoted_string,
        // Regular field name
        field_name,
    ))
    .parse(input)?;

    // Check for suffix direction (asc/desc)
    let (input, suffix_dir) = opt(preceded(
        multispace1,
        alt((
            value(true, tag_no_case("desc")),
            value(false, tag_no_case("asc")),
        )),
    ))
    .parse(input)?;

    // Determine final direction: prefix takes precedence, then suffix, default ascending
    let descending = match (prefix_dir, suffix_dir) {
        (Some('-'), _) => true,
        (Some('+'), _) | (Some(_), _) => false, // + or any other char means ascending
        (None, Some(desc)) => desc,
        (None, None) => false,
    };

    Ok((input, SortField { field, descending }))
}

/// Parse head command: head [N]
/// If N is omitted, defaults to 10.
fn head_command(input: &str) -> ParseResult<'_, Command> {
    let (input, _) = tag_no_case("head").parse(input)?;
    let (input, count) = opt(preceded(
        multispace1,
        map_res(digit1, |s: &str| s.parse::<usize>()),
    ))
    .parse(input)?;

    Ok((
        input,
        Command::Head {
            count: count.unwrap_or(10),
        },
    ))
}

/// Parse tail command: tail [N]
/// If N is omitted, defaults to 10.
fn tail_command(input: &str) -> ParseResult<'_, Command> {
    let (input, _) = tag_no_case("tail").parse(input)?;
    let (input, count) = opt(preceded(
        multispace1,
        map_res(digit1, |s: &str| s.parse::<usize>()),
    ))
    .parse(input)?;

    Ok((
        input,
        Command::Tail {
            count: count.unwrap_or(10),
        },
    ))
}

/// Parse timechart command: timechart [span=duration] [limit=N] agg1, agg2 [by field] [limit=N]
/// limit can appear before aggregations or after split-by
fn timechart_command(input: &str) -> ParseResult<'_, Command> {
    let (input, _) = tag_no_case("timechart").parse(input)?;
    let (input, _) = multispace1(input)?;

    // Parse optional span=, limit=, cont= before aggregations (any order)
    let mut span: Option<Duration> = None;
    let mut limit: Option<usize> = None;
    let mut cont = false;
    let mut remaining = input;

    loop {
        if span.is_none() {
            if let Ok((rest, s)) = terminated(span_spec, multispace1).parse(remaining) {
                span = Some(s);
                remaining = rest;
                continue;
            }
        }
        if limit.is_none() {
            if let Ok((rest, _)) =
                tag_no_case::<_, _, nom::error::Error<&str>>("limit=").parse(remaining)
            {
                let limit_val: Result<(&str, usize), nom::Err<nom::error::Error<&str>>> =
                    terminated(map_res(digit1, |s: &str| s.parse::<usize>()), multispace1)
                        .parse(rest);
                if let Ok((rest2, n)) = limit_val {
                    limit = Some(n);
                    remaining = rest2;
                    continue;
                }
            }
        }
        if let Ok((rest, _)) =
            tag_no_case::<_, _, nom::error::Error<&str>>("cont=").parse(remaining)
        {
            let cont_val: Result<(&str, bool), nom::Err<nom::error::Error<&str>>> = terminated(
                alt((
                    value(true, tag_no_case("true")),
                    value(false, tag_no_case("false")),
                )),
                multispace1,
            )
            .parse(rest);
            if let Ok((rest2, v)) = cont_val {
                cont = v;
                remaining = rest2;
                continue;
            }
        }
        break;
    }

    let (input, aggregations) = aggregation_list(remaining)?;
    let (input, split_by) = map(
        opt(preceded(
            delimited(multispace1, tag_no_case("by"), multispace1),
            field_list_fn,
        )),
        |opt| opt.unwrap_or_default(),
    )
    .parse(input)?;

    // Parse optional trailing params after split-by (limit=, cont=)
    let mut remaining = input;
    loop {
        if limit.is_none() {
            let limit_result: Result<(&str, usize), nom::Err<nom::error::Error<&str>>> = preceded(
                delimited(multispace1, tag_no_case("limit="), multispace0),
                map_res(digit1, |s: &str| s.parse::<usize>()),
            )
            .parse(remaining);
            if let Ok((rest, n)) = limit_result {
                limit = Some(n);
                remaining = rest;
                continue;
            }
        }
        if !cont {
            let cont_result: Result<(&str, bool), nom::Err<nom::error::Error<&str>>> = preceded(
                multispace1,
                preceded(
                    tag_no_case("cont="),
                    alt((
                        value(true, tag_no_case("true")),
                        value(false, tag_no_case("false")),
                    )),
                ),
            )
            .parse(remaining);
            if let Ok((rest, v)) = cont_result {
                cont = v;
                remaining = rest;
                continue;
            }
        }
        break;
    }

    Ok((
        remaining,
        Command::Timechart {
            span: span.unwrap_or(Duration::from_secs(3600)), // Default 1 hour
            aggregations,
            split_by,
            limit,
            cont,
        },
    ))
}

/// Parse span specification: span=1h, span=5m, etc.
fn span_spec(input: &str) -> ParseResult<'_, Duration> {
    let (input, _) = tag_no_case("span").parse(input)?;
    let (input, _) = char('=').parse(input)?;
    duration_fn(input)
}

/// Parse duration: 1h, 5m, 30s, 1d
pub(super) fn duration_fn(input: &str) -> ParseResult<'_, Duration> {
    let (input, num) = map_res(digit1, |s: &str| s.parse::<u64>()).parse(input)?;
    let (input, unit) = one_of("smhdSMHD").parse(input)?;

    let seconds = match unit.to_ascii_lowercase() {
        's' => num,
        'm' => num * 60,
        'h' => num * 3600,
        'd' => num * 86400,
        _ => unreachable!(),
    };

    Ok((input, Duration::from_secs(seconds)))
}

/// Parse table command: table field1 [as alias1], field2 [as alias2], ...
/// Also supports: table * (to select all fields)
fn table_command(input: &str) -> ParseResult<'_, Command> {
    let (input, _) = tag_no_case("table").parse(input)?;
    let (input, _) = multispace1(input)?;

    // Check for wildcard: table *
    if let Ok((remaining, _)) = char::<&str, nom::error::Error<&str>>('*').parse(input) {
        // Wildcard - select all fields
        return Ok((
            remaining,
            Command::Table {
                fields: vec![TableField {
                    name: "*".to_string(),
                    alias: None,
                }],
            },
        ));
    }

    // Regular field list (comma or space-separated)
    let (mut input, first) = table_field(input)?;
    let mut fields = vec![first];

    loop {
        // Try comma separator first
        let comma: Result<(&str, char), nom::Err<nom::error::Error<&str>>> =
            delimited(multispace0, char(','), multispace0).parse(input);
        if let Ok((rest, _)) = comma {
            if let Ok((rest2, field)) = table_field(rest) {
                fields.push(field);
                input = rest2;
                continue;
            }
        }

        // Try space separator
        let space: Result<(&str, &str), nom::Err<nom::error::Error<&str>>> = multispace1(input);
        if let Ok((rest, _)) = space {
            if let Ok((rest2, field)) = table_field(rest) {
                fields.push(field);
                input = rest2;
                continue;
            }
        }

        break;
    }

    Ok((input, Command::Table { fields }))
}

/// Parse a table field with optional alias: field [as alias]
/// Supports wildcard patterns like src_*, dest_*, *_time
/// Also supports quoted field names for fields with spaces: "GICS Sector"
fn table_field(input: &str) -> ParseResult<'_, TableField> {
    let (input, name) = alt((quoted_string, field_name_with_wildcard)).parse(input)?;
    let (input, alias) = opt(preceded(
        delimited(multispace1, tag_no_case("as"), multispace1),
        alt((quoted_string, field_name)),
    ))
    .parse(input)?;

    Ok((input, TableField { name, alias }))
}

/// Parse rename command: rename old_field as new_field, old_field2 as new_field2
fn rename_command(input: &str) -> ParseResult<'_, Command> {
    let (input, _) = tag_no_case("rename").parse(input)?;
    let (input, _) = multispace1(input)?;
    let (input, mappings) =
        separated_list1(delimited(multispace0, char(','), multispace0), field_rename)
            .parse(input)?;

    Ok((input, Command::Rename { mappings }))
}

/// Parse a single field rename: old_field as new_field
/// Supports quoted field names for fields with spaces: "GICS Sector" as sector
fn field_rename(input: &str) -> ParseResult<'_, FieldRename> {
    let (input, from) = alt((quoted_string, field_name)).parse(input)?;
    let (input, _) = delimited(multispace1, tag_no_case("as"), multispace1).parse(input)?;
    let (input, to) = alt((quoted_string, field_name)).parse(input)?;

    Ok((input, FieldRename { from, to }))
}

/// Parse lookup command: lookup <table_name> <key_field> [OUTPUT <field1>, <field2>, ...] [CASE_INSENSITIVE]
/// Examples:
///   lookup assets src_ip
///   lookup users user OUTPUT name, email
///   lookup threats ip OUTPUT threat_level, category CASE_INSENSITIVE
fn lookup_command(input: &str) -> ParseResult<'_, Command> {
    let (input, _) = tag_no_case("lookup").parse(input)?;
    let (input, _) = multispace1(input)?;

    // Parse table name (can be quoted or unquoted)
    let (input, table_name) = alt((quoted_string, field_name)).parse(input)?;
    let (input, _) = multispace1(input)?;

    // Parse key field
    let (input, key_field_local) = field_name(input)?;

    // Parse optional "as alias" clause: maps local field to a different name in the lookup table
    // e.g., "lookup assets src_ip as ip" means match events' src_ip against lookup's ip column
    let (input, key_field_alias) = opt(preceded(
        delimited(multispace1, tag_no_case("as"), multispace1),
        field_name,
    ))
    .parse(input)?;

    // When "as alias" is present, use the alias as key_field (the lookup table's column name)
    // — e.g. `src_ip as ip` -> use "ip" as the key_field for the lookup join.
    let key_field = key_field_alias.unwrap_or(key_field_local);

    // Parse optional OUTPUT clause
    let (input, output_fields) = opt(preceded(
        delimited(multispace1, tag_no_case("OUTPUT"), multispace1),
        field_list_fn,
    ))
    .parse(input)?;

    // Parse optional CASE_INSENSITIVE flag
    let (input, case_insensitive) = map(
        opt(preceded(multispace1, tag_no_case("CASE_INSENSITIVE"))),
        |opt| opt.is_some(),
    )
    .parse(input)?;

    Ok((
        input,
        Command::Lookup {
            table_name,
            key_field,
            output_fields,
            case_insensitive,
        },
    ))
}

/// Parse aggregation list separated by commas or spaces.
/// Safe because aggregation() starts with agg_func which won't match "by" or "|"
pub(super) fn aggregation_list(input: &str) -> ParseResult<'_, Vec<Aggregation>> {
    let (mut input, first) = aggregation(input)?;
    let mut aggs = vec![first];

    loop {
        // Try comma separator first
        let comma: Result<(&str, char), nom::Err<nom::error::Error<&str>>> =
            delimited(multispace0, char(','), multispace0).parse(input);
        if let Ok((rest, _)) = comma {
            if let Ok((rest2, agg)) = aggregation(rest) {
                aggs.push(agg);
                input = rest2;
                continue;
            }
        }

        // Try space separator
        let space: Result<(&str, &str), nom::Err<nom::error::Error<&str>>> = multispace1(input);
        if let Ok((rest, _)) = space {
            if let Ok((rest2, agg)) = aggregation(rest) {
                aggs.push(agg);
                input = rest2;
                continue;
            }
        }

        break;
    }

    Ok((input, aggs))
}

/// Parse aggregation: func([field]) [as alias] or percentile(field, N) [as alias]
/// Also supports count without parentheses (e.g., "count" instead of "count()")
fn aggregation(input: &str) -> ParseResult<'_, Aggregation> {
    // histogram_quantile(field, N) — special two-arg syntax (NAN-1528). Must run
    // before the generic path; `histogram_quantile` would otherwise mis-parse.
    if let Ok((remaining, agg)) = histogram_quantile_aggregation(input) {
        return Ok((remaining, agg));
    }

    // Try percentile first (has special syntax with two args)
    if let Ok((remaining, agg)) = percentile_aggregation(input) {
        return Ok((remaining, agg));
    }

    // Standard aggregation: func([field]) [as alias] or func(eval(condition)) [as alias]
    let (input, func) = agg_func(input)?;

    // Check if there's an opening parenthesis - if not, allow bare function name for count
    let (input, has_parens) = opt(char('(')).parse(input)?;

    let (input, field, condition, alias, field_expr_val) = if has_parens.is_some() {
        // Has parentheses - check if it's eval(...) for conditional aggregation
        let (input, is_eval) = opt(tag_no_case("eval")).parse(input)?;

        if is_eval.is_some() {
            // Conditional aggregation: func(eval(condition))
            let (input, _) = char('(').parse(input)?;
            let (input, cond_expr) = eval_expression(input)?;
            let (input, _) = char(')').parse(input)?;
            let (input, _) = char(')').parse(input)?;
            let (input, alias) = opt(preceded(
                delimited(multispace1, tag_no_case("as"), multispace1),
                alt((quoted_string, field_name)),
            ))
            .parse(input)?;
            (input, None, Some(cond_expr), alias, None)
        } else {
            // Regular aggregation: func(field) or func(expr)
            // Try simple field name first, then fall back to eval expression
            let save_input = input;
            let try_field: Result<(&str, Option<String>), nom::Err<nom::error::Error<&str>>> =
                opt(alt((quoted_string, field_name))).parse(input);

            if let Ok((rest, Some(f))) = try_field {
                // Got a field name — check if closing paren follows
                let rest_trimmed = rest.trim_start();
                if rest_trimmed.starts_with(')') {
                    let (rest, _) = multispace0(rest)?;
                    let (rest, _) = char(')').parse(rest)?;
                    let (rest, alias) = opt(preceded(
                        delimited(multispace1, tag_no_case("as"), multispace1),
                        alt((quoted_string, field_name)),
                    ))
                    .parse(rest)?;
                    (rest, Some(f), None, alias, None)
                } else {
                    // Field name didn't consume all of arg — try as eval expression
                    let (rest, expr) = eval_expression(save_input)?;
                    let (rest, _) = multispace0(rest)?;
                    let (rest, _) = char(')').parse(rest)?;
                    let (rest, alias) = opt(preceded(
                        delimited(multispace1, tag_no_case("as"), multispace1),
                        alt((quoted_string, field_name)),
                    ))
                    .parse(rest)?;
                    (rest, None, None, alias, Some(expr))
                }
            } else {
                // No field name — empty parens like count()
                let (rest, _) = multispace0(save_input)?;
                let (rest, _) = char(')').parse(rest)?;
                let (rest, alias) = opt(preceded(
                    delimited(multispace1, tag_no_case("as"), multispace1),
                    alt((quoted_string, field_name)),
                ))
                .parse(rest)?;
                (rest, None, None, alias, None)
            }
        }
    } else {
        // No parentheses - only allowed for count and sparkline
        if func != AggFunc::Count && func != AggFunc::Sparkline {
            return Err(nom::Err::Error(nom::error::Error::new(
                input,
                nom::error::ErrorKind::Tag,
            )));
        }
        // Check for optional alias
        let (input, alias) = opt(preceded(
            delimited(multispace1, tag_no_case("as"), multispace1),
            alt((quoted_string, field_name)),
        ))
        .parse(input)?;
        (input, None, None, alias, None)
    };

    Ok((
        input,
        Aggregation {
            func,
            field,
            alias,
            condition,
            field_expr: field_expr_val,
        },
    ))
}

/// Parse percentile aggregation: percentile(field, N) [as alias]
/// Supports quoted field names for fields with spaces
fn percentile_aggregation(input: &str) -> ParseResult<'_, Aggregation> {
    let (input, _) = tag_no_case("percentile").parse(input)?;
    let (input, _) = char('(').parse(input)?;
    let (input, _) = multispace0(input)?;
    let (input, field) = alt((quoted_string, field_name)).parse(input)?;
    let (input, _) = multispace0(input)?;
    let (input, _) = char(',').parse(input)?;
    let (input, _) = multispace0(input)?;
    let (input, pct) = map_res(digit1, |s: &str| s.parse::<u8>()).parse(input)?;
    let (input, _) = multispace0(input)?;
    let (input, _) = char(')').parse(input)?;
    let (input, alias) = opt(preceded(
        delimited(multispace1, tag_no_case("as"), multispace1),
        alt((quoted_string, field_name)),
    ))
    .parse(input)?;

    Ok((
        input,
        Aggregation {
            func: AggFunc::Percentile(pct),
            field: Some(field),
            alias,
            condition: None,
            field_expr: None,
        },
    ))
}

/// Parse histogram_quantile aggregation: histogram_quantile(field, N) [as alias]
/// (NAN-1528, OTLP metrics). Mirrors [`percentile_aggregation`]'s two-arg shape;
/// N is the percentile 0-100.
fn histogram_quantile_aggregation(input: &str) -> ParseResult<'_, Aggregation> {
    let (input, _) = tag_no_case("histogram_quantile").parse(input)?;
    let (input, _) = char('(').parse(input)?;
    let (input, _) = multispace0(input)?;
    let (input, field) = alt((quoted_string, field_name)).parse(input)?;
    let (input, _) = multispace0(input)?;
    let (input, _) = char(',').parse(input)?;
    let (input, _) = multispace0(input)?;
    let (input, pct) = map_res(digit1, |s: &str| s.parse::<u8>()).parse(input)?;
    let (input, _) = multispace0(input)?;
    let (input, _) = char(')').parse(input)?;
    let (input, alias) = opt(preceded(
        delimited(multispace1, tag_no_case("as"), multispace1),
        alt((quoted_string, field_name)),
    ))
    .parse(input)?;

    Ok((
        input,
        Aggregation {
            func: AggFunc::HistogramQuantile(pct),
            field: Some(field),
            alias,
            condition: None,
            field_expr: None,
        },
    ))
}

/// Parse aggregation function name
fn agg_func(input: &str) -> ParseResult<'_, AggFunc> {
    alt((
        alt((
            value(AggFunc::Count, tag_no_case("count")),
            // distinct_count must come before dc to avoid partial match
            value(AggFunc::Dc, tag_no_case("distinct_count")),
            // estdc: approximate distinct count (uniqCombined64)
            value(AggFunc::EstDc, tag_no_case("estdc")),
            value(AggFunc::Dc, tag_no_case("dc")),
            value(AggFunc::Sum, tag_no_case("sum")),
            value(AggFunc::Avg, tag_no_case("avg")),
            value(AggFunc::Min, tag_no_case("min")),
            value(AggFunc::Max, tag_no_case("max")),
            value(AggFunc::Values, tag_no_case("values")),
            value(AggFunc::List, tag_no_case("list")),
            value(AggFunc::First, tag_no_case("first")),
            value(AggFunc::Last, tag_no_case("last")),
            value(AggFunc::Range, tag_no_case("range")),
        )),
        alt((
            value(AggFunc::Earliest, tag_no_case("earliest")),
            value(AggFunc::Latest, tag_no_case("latest")),
            value(AggFunc::Stdev, tag_no_case("stdev")),
            value(AggFunc::Var, tag_no_case("var")),
            value(AggFunc::Median, tag_no_case("median")),
            // perc95 must come before p95 to avoid partial match
            value(AggFunc::Perc95, tag_no_case("perc95")),
            value(AggFunc::Percentile(95), tag_no_case("p95")),
            value(AggFunc::Percentile(99), tag_no_case("p99")),
            value(AggFunc::Mode, tag_no_case("mode")),
            value(AggFunc::Sparkline, tag_no_case("sparkline")),
            // NAN-1528 (OTLP metrics): per-second counter rate.
            value(AggFunc::Rate, tag_no_case("rate")),
        )),
    ))
    .parse(input)
}

/// Parse field list separated by commas or spaces.
/// Supports quoted field names for fields with spaces
/// Stops consuming space-separated fields when the next token looks like a
/// keyword parameter (e.g. keepfirst=true, maxspan=1h)
pub(super) fn field_list_fn(input: &str) -> ParseResult<'_, Vec<String>> {
    // Parse first field
    let (mut input, first) = alt((quoted_string, field_name)).parse(input)?;
    let mut fields = vec![first];

    loop {
        // Try comma separator first (always safe)
        let comma: Result<(&str, char), nom::Err<nom::error::Error<&str>>> =
            delimited(multispace0, char(','), multispace0).parse(input);
        if let Ok((rest, _)) = comma {
            if let Ok((rest2, field)) = alt((quoted_string, field_name)).parse(rest) {
                fields.push(field);
                input = rest2;
                continue;
            }
        }

        // Try space separator, but reject if followed by '=' (keyword parameter)
        // or if the token is a reserved keyword like "sortby"
        let space: Result<(&str, &str), nom::Err<nom::error::Error<&str>>> = multispace1(input);
        if let Ok((rest, _)) = space {
            if let Ok((rest2, field)) = alt((quoted_string, field_name)).parse(rest) {
                if !rest2.starts_with('=') && !is_field_list_stop_keyword(&field) {
                    fields.push(field);
                    input = rest2;
                    continue;
                }
            }
        }

        break;
    }

    Ok((input, fields))
}

/// Check if a token is a keyword that should stop field_list parsing.
/// These are words that follow field lists in various commands and should
/// not be consumed as field names.
fn is_field_list_stop_keyword(s: &str) -> bool {
    matches!(
        s.to_lowercase().as_str(),
        // `by`/`over` are clause keywords (NAN-1344): in a space-separated field list
        // they must terminate it, not be consumed as bare field names — otherwise
        // `chart … over X by Y` swallows `by Y` into the over-clause group list.
        "sortby" | "keepfirst" | "keeplast" | "by" | "over"
    )
}

/// Parse output command: output <destination_name>
/// Legacy syntax for writing results to a named destination. Parsed but treated as a no-op.
fn output_command(input: &str) -> ParseResult<'_, Command> {
    let (input, _) = tag_no_case("output").parse(input)?;
    let (input, _) = multispace1(input)?;
    let (input, destination) = field_name(input)?;
    Ok((input, Command::Output { destination }))
}
