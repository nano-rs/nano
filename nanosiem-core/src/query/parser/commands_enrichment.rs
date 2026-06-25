// SPDX-License-Identifier: AGPL-3.0-or-later

//! Enrichment command parsers for the query parser
//!
//! Handles: tree, resolve_identity, asset, cloud, ai.

use nom::{
    branch::alt,
    bytes::complete::tag_no_case,
    character::complete::{char, multispace0, multispace1},
    multi::separated_list1,
    Parser,
};
use std::time::Duration;

use super::commands_core::{duration, field_list};
use super::values::{field_name, quoted_string, unquoted_string};
use super::ParseResult;
use crate::query::ast::*;

/// Parse tree command: tree parent=<field> child=<field> label=<field> [detail=<field>] [prevalence=<field>]
/// Visualizes hierarchical relationships with optional prevalence enrichment
pub(super) fn tree_command(input: &str) -> ParseResult<'_, Command> {
    let (input, _) = tag_no_case("tree").parse(input)?;
    let (input, _) = multispace1(input)?;

    // Check for preset aliases first (may have optional root= after)
    if let Ok((remaining, _)) = tag_no_case::<_, _, nom::error::Error<&str>>("process").parse(input)
    {
        // Check we're at end of command or whitespace (not "process_id" etc)
        if remaining.is_empty()
            || remaining.starts_with('|')
            || remaining.starts_with(char::is_whitespace)
        {
            // Check for optional root= parameter after preset
            let (remaining, root_filter) = parse_optional_root_filter(remaining.trim_start())?;
            return Ok((
                remaining,
                Command::Tree {
                    parent_field: "parent_process_guid".to_string(),
                    child_field: "process_guid".to_string(),
                    label_field: "process_name".to_string(),
                    detail_field: Some("command_line".to_string()),
                    prevalence_field: Some("process_hash".to_string()),
                    root_filter,
                },
            ));
        }
    }

    if let Ok((remaining, _)) = tag_no_case::<_, _, nom::error::Error<&str>>("web").parse(input) {
        // Check we're at end of command or whitespace
        if remaining.is_empty()
            || remaining.starts_with('|')
            || remaining.starts_with(char::is_whitespace)
        {
            // Check for optional root= parameter after preset
            let (remaining, root_filter) = parse_optional_root_filter(remaining.trim_start())?;
            return Ok((
                remaining,
                Command::Tree {
                    parent_field: "http_referrer".to_string(),
                    child_field: "url".to_string(),
                    label_field: "dest_host".to_string(),
                    detail_field: None,
                    prevalence_field: Some("dest_host".to_string()),
                    root_filter,
                },
            ));
        }
    }

    // Try positional syntax first: tree <field_name> [parent=<field>] [by ...] [depth=N] [maxchildren=N] [format=...]
    // The first bare field_name (not a key=value) becomes child_field and label_field.
    if let Ok((pos_remaining, positional_field)) = field_name(input) {
        // Make sure it's not actually a key=value param (e.g., "parent=...")
        let after_trim = pos_remaining.trim_start();
        let is_key_value = after_trim.starts_with('=');
        if !is_key_value {
            // We have a positional field name — parse optional trailing params
            let mut parent_field = String::new();
            let mut root_filter: Option<String> = None;
            let mut remaining = pos_remaining;

            loop {
                let (input, ws) = multispace0(remaining)?;
                remaining = input;
                if remaining.is_empty() || remaining.starts_with('|') {
                    break;
                }
                if ws.is_empty() {
                    break;
                }

                // parent=<field>
                if let Ok((input, _)) =
                    tag_no_case::<_, _, nom::error::Error<&str>>("parent=").parse(remaining)
                {
                    let (input, val) = field_name(input)?;
                    parent_field = val;
                    remaining = input;
                }
                // root=<pattern>
                else if let Ok((input, _)) =
                    tag_no_case::<_, _, nom::error::Error<&str>>("root=").parse(remaining)
                {
                    let (input, val) = parse_pattern_value(input)?;
                    root_filter = Some(val);
                    remaining = input;
                }
                // Accept and discard: by <field_list>
                else if let Ok((input, _)) =
                    tag_no_case::<_, _, nom::error::Error<&str>>("by").parse(remaining)
                {
                    // Must be followed by whitespace (not "bytes" etc.)
                    if let Ok((input, _)) = multispace1::<_, nom::error::Error<&str>>(input) {
                        // Consume comma-separated field names (discarded — not in AST)
                        let (input, _fields) = field_list(input)?;
                        remaining = input;
                    } else {
                        break;
                    }
                }
                // Accept and discard: depth=N, maxchildren=N, format=<word>
                else if let Ok((input, _)) =
                    tag_no_case::<_, _, nom::error::Error<&str>>("depth=").parse(remaining)
                {
                    let (input, _) =
                        nom::character::complete::digit1::<_, nom::error::Error<&str>>(input)
                            .map_err(|_| {
                                nom::Err::Error(nom::error::Error::new(
                                    remaining,
                                    nom::error::ErrorKind::Digit,
                                ))
                            })?;
                    remaining = input;
                } else if let Ok((input, _)) =
                    tag_no_case::<_, _, nom::error::Error<&str>>("maxchildren=").parse(remaining)
                {
                    let (input, _) =
                        nom::character::complete::digit1::<_, nom::error::Error<&str>>(input)
                            .map_err(|_| {
                                nom::Err::Error(nom::error::Error::new(
                                    remaining,
                                    nom::error::ErrorKind::Digit,
                                ))
                            })?;
                    remaining = input;
                } else if let Ok((input, _)) =
                    tag_no_case::<_, _, nom::error::Error<&str>>("format=").parse(remaining)
                {
                    let (input, _) = field_name(input)?;
                    remaining = input;
                } else {
                    break;
                }
            }

            return Ok((
                remaining,
                Command::Tree {
                    parent_field,
                    child_field: positional_field.clone(),
                    label_field: positional_field,
                    detail_field: None,
                    prevalence_field: None,
                    root_filter,
                },
            ));
        }
    }

    // Fall back to full key=value syntax: parent=<field> child=<field> label=<field> ...
    let mut parent_field: Option<String> = None;
    let mut child_field: Option<String> = None;
    let mut label_field: Option<String> = None;
    let mut detail_field: Option<String> = None;
    let mut prevalence_field: Option<String> = None;
    let mut root_filter: Option<String> = None;

    let mut remaining = input;
    let mut first_iteration = true;

    loop {
        // Check if we've reached a pipe (end of command) or end of input
        if remaining.is_empty() || remaining.starts_with('|') {
            break;
        }

        // After first iteration, require whitespace between parameters
        if !first_iteration {
            let (input, ws) = multispace0(remaining)?;
            if ws.is_empty() {
                break;
            }
            remaining = input;

            // Check again after consuming whitespace
            if remaining.is_empty() || remaining.starts_with('|') {
                break;
            }
        }
        first_iteration = false;

        // Try parsing each parameter (all support optional spaces around =)
        if let Ok((input, _)) =
            tag_no_case::<_, _, nom::error::Error<&str>>("parent").parse(remaining)
        {
            let (input, _) = multispace0(input)?;
            if !input.starts_with('=') {
                break;
            }
            let (input, _) = multispace0(&input[1..])?;
            if parent_field.is_some() {
                break;
            }
            let (input, val) = field_name(input)?;
            parent_field = Some(val);
            remaining = input;
        } else if let Ok((input, _)) =
            tag_no_case::<_, _, nom::error::Error<&str>>("child").parse(remaining)
        {
            let (input, _) = multispace0(input)?;
            if !input.starts_with('=') {
                break;
            }
            let (input, _) = multispace0(&input[1..])?;
            if child_field.is_some() {
                break;
            }
            let (input, val) = field_name(input)?;
            child_field = Some(val);
            remaining = input;
        } else if let Ok((input, _)) =
            tag_no_case::<_, _, nom::error::Error<&str>>("label").parse(remaining)
        {
            let (input, _) = multispace0(input)?;
            if !input.starts_with('=') {
                break;
            }
            let (input, _) = multispace0(&input[1..])?;
            if label_field.is_some() {
                break;
            }
            let (input, val) = field_name(input)?;
            label_field = Some(val);
            remaining = input;
        } else if let Ok((input, _)) =
            tag_no_case::<_, _, nom::error::Error<&str>>("detail").parse(remaining)
        {
            let (input, _) = multispace0(input)?;
            if !input.starts_with('=') {
                break;
            }
            let (input, _) = multispace0(&input[1..])?;
            if detail_field.is_some() {
                break;
            }
            let (input, val) = field_name(input)?;
            detail_field = Some(val);
            remaining = input;
        } else if let Ok((input, _)) =
            tag_no_case::<_, _, nom::error::Error<&str>>("prevalence").parse(remaining)
        {
            let (input, _) = multispace0(input)?;
            if !input.starts_with('=') {
                break;
            }
            let (input, _) = multispace0(&input[1..])?;
            if prevalence_field.is_some() {
                break;
            }
            let (input, val) = field_name(input)?;
            prevalence_field = Some(val);
            remaining = input;
        } else if let Ok((input, _)) =
            tag_no_case::<_, _, nom::error::Error<&str>>("root").parse(remaining)
        {
            let (input, _) = multispace0(input)?;
            if !input.starts_with('=') {
                break;
            }
            let (input, _) = multispace0(&input[1..])?;
            if root_filter.is_some() {
                break;
            }
            // root= takes a pattern: quoted string or regex
            let (input, val) = parse_pattern_value(input)?;
            root_filter = Some(val);
            remaining = input;
        } else {
            break;
        }
    }

    // Validate required fields
    let parent_field = parent_field.ok_or_else(|| {
        nom::Err::Failure(nom::error::Error::new(
            remaining,
            nom::error::ErrorKind::Tag,
        ))
    })?;
    let child_field = child_field.ok_or_else(|| {
        nom::Err::Failure(nom::error::Error::new(
            remaining,
            nom::error::ErrorKind::Tag,
        ))
    })?;
    let label_field = label_field.ok_or_else(|| {
        nom::Err::Failure(nom::error::Error::new(
            remaining,
            nom::error::ErrorKind::Tag,
        ))
    })?;

    Ok((
        remaining,
        Command::Tree {
            parent_field,
            child_field,
            label_field,
            detail_field,
            prevalence_field,
            root_filter,
        },
    ))
}

/// Helper to parse a pattern value - either a quoted string or a /regex/ pattern
fn parse_pattern_value(input: &str) -> ParseResult<'_, String> {
    // Try quoted string first
    if let Ok((remaining, val)) = quoted_string(input) {
        return Ok((remaining, val));
    }

    // Try regex pattern: /pattern/
    if input.starts_with('/') {
        let chars: Vec<char> = input[1..].chars().collect();
        let mut escaped = false;
        for (i, &c) in chars.iter().enumerate() {
            if escaped {
                escaped = false;
                continue;
            }
            match c {
                '\\' => escaped = true,
                '/' => {
                    // Found closing slash - return the full pattern including slashes
                    let pattern = &input[..i + 2]; // +2 for both slashes
                    let remaining = &input[i + 2..];
                    return Ok((remaining, pattern.to_string()));
                }
                _ => {}
            }
        }
    }

    Err(nom::Err::Error(nom::error::Error::new(
        input,
        nom::error::ErrorKind::Tag,
    )))
}

/// Helper to parse optional root= filter after tree presets
fn parse_optional_root_filter(input: &str) -> ParseResult<'_, Option<String>> {
    if input.is_empty() || input.starts_with('|') {
        return Ok((input, None));
    }

    if let Ok((remaining, _)) = tag_no_case::<_, _, nom::error::Error<&str>>("root").parse(input) {
        // Allow optional whitespace around =
        let (remaining, _) = multispace0(remaining)?;
        if !remaining.starts_with('=') {
            return Ok((input, None));
        }
        let remaining = &remaining[1..]; // skip '='
        let (remaining, _) = multispace0(remaining)?;
        let (remaining, val) = parse_pattern_value(remaining)?;
        Ok((remaining.trim_start(), Some(val)))
    } else {
        Ok((input, None))
    }
}

/// Parse resolve_identity command: enrich events with identity from ASOF JOIN lookup
/// Syntax: | resolve_identity [field=src_ip] [max_age=24h]
///         | resolve-identity src_ip
///         | resolve-identity src_ip, dest_ip
///
/// Examples:
///   | resolve_identity                                    -- resolve src_ip with all fields
///   | resolve_identity field=dest_ip                      -- resolve different field
///   | resolve_identity max_age=4h                         -- custom max age
///   | resolve_identity field=dest_ip max_age=12h
///   | resolve-identity src_ip                             -- positional field
///   | resolve-identity src_ip, dest_ip                    -- positional fields (first used)
pub(super) fn resolve_identity_command(input: &str) -> ParseResult<'_, Command> {
    // Accept both resolve_identity and resolve-identity (hyphen variant)
    let (input, _) = alt((
        tag_no_case("resolve_identity"),
        tag_no_case("resolve-identity"),
    ))
    .parse(input)?;

    // Parse optional parameters in any order: field=, max_age=, or positional field names
    let mut field: Option<String> = None;
    let mut max_age: Option<Duration> = None;

    let mut remaining = input;

    loop {
        // Try to consume whitespace, if none and we haven't reached end, break
        let (input, ws) = multispace0(remaining)?;
        remaining = input;

        // Check if we've reached end of command (pipe or end of input)
        if remaining.is_empty() || remaining.starts_with('|') {
            break;
        }

        if ws.is_empty() {
            break;
        }

        // Try parsing each optional parameter
        if let Ok((input, _)) =
            tag_no_case::<_, _, nom::error::Error<&str>>("field=").parse(remaining)
        {
            if field.is_some() {
                break; // Already parsed, stop
            }
            let (input, val) = field_name(input)?;
            field = Some(val);
            remaining = input;
        } else if let Ok((input, _)) =
            tag_no_case::<_, _, nom::error::Error<&str>>("max_age=").parse(remaining)
        {
            if max_age.is_some() {
                break; // Already parsed, stop
            }
            let (input, dur) = duration(input)?;
            max_age = Some(dur);
            remaining = input;
        } else if field.is_none() {
            // Try positional field name(s): field_name [, field_name]*
            // Only the first field is used (AST supports single field).
            if let Ok((input, fields)) = field_list(remaining) {
                // Use the first field
                field = Some(fields.into_iter().next().unwrap());
                remaining = input;
            } else {
                break;
            }
        } else {
            break; // No more recognized parameters
        }
    }

    Ok((
        remaining,
        Command::ResolveIdentity {
            field: field.unwrap_or_else(|| "src_ip".to_string()),
            max_age: max_age.unwrap_or(Duration::from_secs(24 * 3600)), // 24h default
        },
    ))
}

/// Parse asset command: create an asset-centric view with identity resolution and activity aggregation
/// Syntax: | asset [field=src_host] [sections=network,process,auth,file,dns,alerts] [max_age=14d]
///         | asset src_ip                               -- positional field
///
/// Examples:
///   | asset                                           -- auto-detect asset field, all sections
///   | asset field=src_ip                              -- use src_ip as identifier
///   | asset src_ip                                    -- positional: use src_ip as identifier
///   | asset sections=auth,process                     -- only show auth and process sections
///   | asset field=user max_age=7d                     -- user-based view with 7 day lookback
pub(super) fn asset_command(input: &str) -> ParseResult<'_, Command> {
    let (input, _) = tag_no_case("asset").parse(input)?;

    // Parse optional parameters in any order: field=, sections=, max_age=, or positional field
    let mut identifier_field: Option<String> = None;
    let mut sections: Option<Vec<AssetSection>> = None;
    let mut max_identity_age: Option<Duration> = None;

    let mut remaining = input;

    loop {
        // Try to consume whitespace, if none and we haven't reached end, break
        let (input, ws) = multispace0(remaining)?;
        remaining = input;

        // Check if we've reached end of command (pipe or end of input)
        if remaining.is_empty() || remaining.starts_with('|') {
            break;
        }

        if ws.is_empty() {
            break;
        }

        // Try parsing each optional parameter
        if let Ok((input, _)) =
            tag_no_case::<_, _, nom::error::Error<&str>>("field=").parse(remaining)
        {
            if identifier_field.is_some() {
                break; // Already parsed, stop
            }
            let (input, val) = field_name(input)?;
            identifier_field = Some(val);
            remaining = input;
        } else if let Ok((input, _)) =
            tag_no_case::<_, _, nom::error::Error<&str>>("sections=").parse(remaining)
        {
            if sections.is_some() {
                break; // Already parsed, stop
            }
            // Parse comma-separated list of section names
            let (input, section_strs) = separated_list1(char(','), field_name).parse(input)?;
            // Convert strings to AssetSection enum
            let mut parsed_sections = Vec::new();
            for section_str in section_strs {
                if let Some(section) = AssetSection::from_str(&section_str) {
                    parsed_sections.push(section);
                }
                // Silently ignore invalid section names
            }
            if !parsed_sections.is_empty() {
                sections = Some(parsed_sections);
            }
            remaining = input;
        } else if let Ok((input, _)) =
            tag_no_case::<_, _, nom::error::Error<&str>>("max_age=").parse(remaining)
        {
            if max_identity_age.is_some() {
                break; // Already parsed, stop
            }
            let (input, dur) = duration(input)?;
            max_identity_age = Some(dur);
            remaining = input;
        } else if identifier_field.is_none() {
            // Try positional field name (bare field_name not followed by =)
            if let Ok((pos_remaining, val)) = field_name(remaining) {
                if !pos_remaining.trim_start().starts_with('=') {
                    identifier_field = Some(val);
                    remaining = pos_remaining;
                } else {
                    break;
                }
            } else {
                break;
            }
        } else {
            break; // No more recognized parameters
        }
    }

    Ok((
        remaining,
        Command::Asset {
            identifier_field,
            sections,
            max_identity_age: max_identity_age.unwrap_or(Duration::from_secs(14 * 24 * 3600)), // 14d default
        },
    ))
}

/// Parse cloud command: cloud [by=provider|account|region|service|resource] [show_mfa=true]
///                       cloud service          -- positional grouping
///                       cloud region           -- positional grouping
pub(super) fn cloud_command(input: &str) -> ParseResult<'_, Command> {
    let (input, _) = tag_no_case("cloud").parse(input)?;
    // Must be followed by whitespace, pipe, or end of input (not "cloud_provider" etc.)
    if !input.is_empty() && !input.starts_with(|c: char| c.is_whitespace() || c == '|') {
        return Err(nom::Err::Error(nom::error::Error::new(
            input,
            nom::error::ErrorKind::Tag,
        )));
    }

    let mut remaining = input;
    let mut group_by: Option<CloudGroupBy> = None;
    let mut show_mfa = false;
    let mut principal: Option<String> = None;
    let mut account: Option<String> = None;
    let mut positional_consumed = false;

    loop {
        // Skip whitespace
        if let Ok((input, _)) = multispace1::<_, nom::error::Error<&str>>(remaining) {
            remaining = input;
        } else {
            break;
        }

        // Stop at pipe or end
        if remaining.is_empty() || remaining.starts_with('|') {
            break;
        }

        if let Ok((input, _)) = tag_no_case::<_, _, nom::error::Error<&str>>("by=").parse(remaining)
        {
            if group_by.is_some() {
                break;
            }
            let (input, val) = field_name(input)?;
            if let Some(gb) = CloudGroupBy::from_str(&val) {
                group_by = Some(gb);
            }
            remaining = input;
        } else if let Ok((input, _)) =
            tag_no_case::<_, _, nom::error::Error<&str>>("show_mfa=").parse(remaining)
        {
            let (input, val) = field_name(input)?;
            show_mfa = val.to_lowercase() == "true";
            remaining = input;
        } else if let Ok((input, _)) =
            tag_no_case::<_, _, nom::error::Error<&str>>("principal=").parse(remaining)
        {
            // Principal ids span ARNs, IAM names, federated subjects — use the
            // permissive unquoted token parser so digit-only / hyphenated /
            // dotted ids round-trip without requiring quotes.
            let (input, val) = alt((quoted_string, unquoted_string)).parse(input)?;
            if !val.is_empty() {
                principal = Some(val.to_string());
            }
            remaining = input;
        } else if let Ok((input, _)) =
            tag_no_case::<_, _, nom::error::Error<&str>>("account=").parse(remaining)
        {
            // AWS account IDs are 12 digits, GCP project ids contain hyphens,
            // Azure subscription ids are GUIDs — none parse as a field_name.
            let (input, val) = alt((quoted_string, unquoted_string)).parse(input)?;
            if !val.is_empty() {
                account = Some(val.to_string());
            }
            remaining = input;
        } else if !positional_consumed {
            // Try positional grouping: bare word that may map to a CloudGroupBy variant
            // Unrecognized values (e.g., "identity", "permissions", "cost") are accepted
            // and silently use the default grouping — this allows cloud sub-views.
            if let Ok((pos_remaining, val)) = field_name(remaining) {
                if !pos_remaining.trim_start().starts_with('=') {
                    if let Some(gb) = CloudGroupBy::from_str(&val) {
                        group_by = Some(gb);
                    }
                    // Always advance past the positional value, even if not a known GroupBy
                    positional_consumed = true;
                    remaining = pos_remaining;
                } else {
                    break;
                }
            } else {
                break;
            }
        } else {
            // Try to consume unknown key=value pairs (e.g., user=admin)
            // These are accepted and silently discarded — they serve as
            // command-level hints that the execution layer can inspect.
            if let Ok((kv_remaining, _key)) = field_name(remaining) {
                let kv_trimmed = kv_remaining.trim_start();
                if kv_trimmed.starts_with('=') {
                    // Consume the =value part
                    let after_eq = &kv_trimmed[1..];
                    if let Ok((val_remaining, _val)) =
                        alt((quoted_string, unquoted_string)).parse(after_eq)
                    {
                        remaining = val_remaining;
                        continue;
                    }
                }
            }
            break;
        }
    }

    Ok((
        remaining,
        Command::Cloud {
            group_by: group_by.unwrap_or_default(),
            show_mfa,
            principal,
            account,
        },
    ))
}

/// Parse ai command: ai prompt="<instruction>" [max_rows=N]
///                    ai "summarize threats"    -- bare quoted string as prompt
/// Sends pipeline results to an LLM for inline classification/enrichment.
///
/// # Open-core split (Phase 2.6, NAN-744)
///
/// This is **parser-only** code — it builds a [`Command::Ai`] AST node from
/// the surface syntax and has zero dependency on any AI runtime. The actual
/// row enrichment is dispatched at search-execution time through the
/// [`crate::extensions::AiClient::enrich_rows`] trait method, so the `| ai`
/// pipe stays available in open-core builds without dragging meloD into the
/// query layer.
///
/// In open-core builds the wired implementation is `NoopAiClient`, whose
/// `enrich_rows` returns each row tagged `ai_verdict = "SKIPPED"` (with
/// `ai_confidence = 0` and a placeholder `ai_reasoning`) rather than raising
/// a hard error — this preserves the result table shape so any post-`| ai`
/// commands (`where ai_verdict="TP"`, `stats count by ai_verdict`, etc.)
/// continue to parse and execute exactly as in enterprise builds. The
/// enterprise crate provides the real AI-backed `enrich_rows` impl.
pub(super) fn ai_command(input: &str) -> ParseResult<'_, Command> {
    let (input, _) = tag_no_case("ai").parse(input)?;
    // Must be followed by whitespace, pipe, or end of input (not "aim", "air", etc.)
    if !input.is_empty() && !input.starts_with(|c: char| c.is_whitespace() || c == '|') {
        return Err(nom::Err::Error(nom::error::Error::new(
            input,
            nom::error::ErrorKind::Tag,
        )));
    }

    let mut remaining = input;
    let mut prompt: Option<String> = None;
    let mut max_rows: usize = 100;

    loop {
        // Skip whitespace
        if let Ok((input, _)) = multispace1::<_, nom::error::Error<&str>>(remaining) {
            remaining = input;
        } else {
            break;
        }

        // Stop at pipe or end
        if remaining.is_empty() || remaining.starts_with('|') {
            break;
        }

        if let Ok((input, _)) =
            tag_no_case::<_, _, nom::error::Error<&str>>("prompt=").parse(remaining)
        {
            if prompt.is_some() {
                break;
            }
            let (input, val) = quoted_string(input)?;
            prompt = Some(val);
            remaining = input;
        } else if let Ok((input, _)) =
            tag_no_case::<_, _, nom::error::Error<&str>>("max_rows=").parse(remaining)
        {
            let (input, val) = nom::character::complete::digit1::<_, nom::error::Error<&str>>(
                input,
            )
            .map_err(|_| {
                nom::Err::Error(nom::error::Error::new(
                    remaining,
                    nom::error::ErrorKind::Digit,
                ))
            })?;
            let parsed: usize = val.parse().unwrap_or(100);
            // Hard cap at 500
            max_rows = parsed.min(500);
            remaining = input;
        } else if prompt.is_none() {
            // Try bare quoted string as prompt (not preceded by prompt=)
            if let Ok((input, val)) = quoted_string(remaining) {
                prompt = Some(val);
                remaining = input;
            } else {
                break;
            }
        } else {
            break;
        }
    }

    let prompt = prompt.ok_or_else(|| {
        nom::Err::Error(nom::error::Error::new(
            remaining,
            nom::error::ErrorKind::Tag,
        ))
    })?;

    Ok((remaining, Command::Ai { prompt, max_rows }))
}

/// Parse services command (bare overview): | services
/// Short-circuits to the observability services overview page (NAN-1560).
pub(super) fn services_command(input: &str) -> ParseResult<'_, Command> {
    let (input, _) = tag_no_case("services").parse(input)?;
    // Must be at end / pipe / whitespace (not "services_foo").
    if !input.is_empty() && !input.starts_with(|c: char| c.is_whitespace() || c == '|') {
        return Err(nom::Err::Error(nom::error::Error::new(
            input,
            nom::error::ErrorKind::Tag,
        )));
    }
    Ok((input, Command::Services))
}

/// Parse service command: | service <name>
/// Short-circuits to the single-service detail page (NAN-1560).
pub(super) fn service_command(input: &str) -> ParseResult<'_, Command> {
    let (input, _) = tag_no_case("service").parse(input)?;
    // Must be followed by whitespace (a name is required) — guards against
    // "service" with no arg and against "service_name" identifier prefixes.
    let (input, _) = multispace1(input)?;
    // Service names span hyphens/dots/digits — use the permissive token parser.
    let (input, name) = alt((quoted_string, unquoted_string)).parse(input)?;
    if name.is_empty() {
        return Err(nom::Err::Error(nom::error::Error::new(
            input,
            nom::error::ErrorKind::Tag,
        )));
    }
    Ok((input, Command::Service { name }))
}

/// Parse trace command: | trace <trace_id>
/// Short-circuits to the trace waterfall page (NAN-1560).
pub(super) fn trace_command(input: &str) -> ParseResult<'_, Command> {
    let (input, _) = tag_no_case("trace").parse(input)?;
    let (input, _) = multispace1(input)?;
    let (input, trace_id) = alt((quoted_string, unquoted_string)).parse(input)?;
    if trace_id.is_empty() {
        return Err(nom::Err::Error(nom::error::Error::new(
            input,
            nom::error::ErrorKind::Tag,
        )));
    }
    Ok((input, Command::Trace { trace_id }))
}

/// Parse metric command: | metric <name> [service=<service_name>]
/// Short-circuits to the metric time-series page (NAN-1560). The optional
/// `service=<name>` scopes the chart to one OTLP service — it is carried on the
/// marker and seeds MetricsExplorer's `service_name` query param (the promoted
/// `otel_metrics.service_name` column), so the chart opens genuinely scoped
/// rather than silently unscoped (NAN-1564).
pub(super) fn metric_command(input: &str) -> ParseResult<'_, Command> {
    let (input, _) = tag_no_case("metric").parse(input)?;
    let (input, _) = multispace1(input)?;
    let (input, name) = alt((quoted_string, unquoted_string)).parse(input)?;
    if name.is_empty() {
        return Err(nom::Err::Error(nom::error::Error::new(
            input,
            nom::error::ErrorKind::Tag,
        )));
    }

    // Optional, bounded `service=<value>` scope. Skip leading space, then if a
    // `service=` token is present consume its value. Anything else (e.g. a `|`
    // boundary or end-of-input) leaves `service` as None — back-compatible.
    let after_name = input;
    let (input, service) = {
        let trimmed = after_name.trim_start();
        match tag_no_case::<_, _, nom::error::Error<&str>>("service=").parse(trimmed) {
            Ok((rest, _)) => {
                let (rest, value) = alt((quoted_string, unquoted_string)).parse(rest)?;
                if value.is_empty() {
                    return Err(nom::Err::Error(nom::error::Error::new(
                        rest,
                        nom::error::ErrorKind::Tag,
                    )));
                }
                (rest, Some(value))
            }
            // No `service=` here — don't consume the trimmed whitespace, leave
            // the original remainder for the pipe/EOF boundary.
            Err(_) => (after_name, None),
        }
    };

    Ok((input, Command::Metric { name, service }))
}
