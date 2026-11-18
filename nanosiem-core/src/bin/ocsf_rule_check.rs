// SPDX-License-Identifier: AGPL-3.0-or-later

//! Check nPL detection rules against the OCSF profile, offline (NAN-5557).
//!
//! Reads newline-delimited JSON `{"id": "...", "query": "<nPL>"}` on stdin and
//! writes one JSON result per line: whether the query parses, the field
//! validator's errors (the same check the detection editor and rule create
//! run), how every dotted field reference resolves under the OCSF profile, and
//! whether the OCSF-profiled SQL generator compiles the query. No ClickHouse
//! and no running stack are needed, so `scripts/ocsf-content-convert.py
//! --validate` can prove a converted rule set before it is imported.
//!
//! Compiles exactly what the search service sends to ClickHouse: commands after
//! `| prevalence` are post-processing in Rust (`strip_post_prevalence_commands`),
//! as in `tests/ocsf_content_rules_live.rs`.

use std::io::{self, BufRead, BufWriter, Write};
use std::sync::Arc;

use nanosiem_core::query::validation::validate_query_fields_with_profile;
use nanosiem_core::query::{parse_query, ClickHouseSqlGenerator, TimeRange};
use nanosiem_core::schema::{FieldResolution, OcsfProfile, SchemaProfile};
use nanosiem_core::search::query_processing::query_manipulation::strip_post_prevalence_commands;
use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
struct Input {
    #[serde(default)]
    id: Option<String>,
    query: String,
}

#[derive(Serialize)]
struct FieldError {
    field: String,
    message: String,
    suggestions: Vec<String>,
}

#[derive(Serialize)]
struct FieldInfo {
    field: String,
    /// `column`, `event_json`, `unmapped`, `alias`, `unknown`, `refused`.
    resolves_to: &'static str,
    queryable: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    suggestions: Option<Vec<String>>,
}

#[derive(Serialize)]
struct Output {
    line: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    id: Option<String>,
    ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    input_error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    parse_error: Option<String>,
    field_errors: Vec<FieldError>,
    fields: Vec<FieldInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    codegen_error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    sql: Option<String>,
}

/// Dotted identifiers outside string and `/regex/` literals: the field
/// references a rule can make. Same scan as `tests/ocsf_content_rules_live.rs`.
fn dotted_fields(npl: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut cur = String::new();
    let (mut in_str, mut in_regex, mut escaped) = (false, false, false);
    let mut last_sig = ' ';
    let push = |cur: &str, out: &mut Vec<String>| {
        let c = cur.trim_end_matches('.');
        if c.contains('.')
            && c.chars().next().is_some_and(|c| c.is_ascii_lowercase())
            && !out.iter().any(|o| o == c)
        {
            out.push(c.to_string());
        }
    };
    for c in npl.chars() {
        if in_regex {
            if escaped {
                escaped = false;
            } else if c == '\\' {
                escaped = true;
            } else if c == '/' {
                in_regex = false;
            }
            continue;
        }
        if !in_str && c == '/' && matches!(last_sig, '=' | '~') {
            in_regex = true;
            cur.clear();
            continue;
        }
        if !c.is_whitespace() {
            last_sig = c;
        }
        if in_str {
            if escaped {
                escaped = false;
            } else if c == '\\' {
                escaped = true;
            } else if c == '"' {
                in_str = false;
            }
            cur.clear();
            continue;
        }
        if c == '"' {
            in_str = true;
            push(&cur, &mut out);
            cur.clear();
            continue;
        }
        if c.is_ascii_alphanumeric() || c == '_' || c == '.' {
            cur.push(c);
        } else {
            push(&cur, &mut out);
            cur.clear();
        }
    }
    push(&cur, &mut out);
    out
}

fn classify(profile: &OcsfProfile, field: &str) -> FieldInfo {
    if let Some(paths) = profile.retired_field_suggestions(field) {
        return FieldInfo {
            field: field.to_string(),
            resolves_to: "refused",
            queryable: false,
            suggestions: Some(paths.iter().map(|p| p.to_string()).collect()),
        };
    }
    let queryable = profile.is_queryable_field(field);
    let resolves_to = match profile.resolve(field) {
        FieldResolution::ExplicitColumn(_) => "column",
        FieldResolution::Alias(_) => "alias",
        FieldResolution::JsonPath { col, .. } | FieldResolution::ArrayElement { col, .. } => {
            if col == "unmapped" {
                "unmapped"
            } else {
                "event_json"
            }
        }
        FieldResolution::MapKey { .. } => "map",
        FieldResolution::Unknown => "unknown",
    };
    let suggestions = if queryable {
        None
    } else {
        match nanosiem_core::schema::ocsf_registry::lookup(field) {
            nanosiem_core::schema::ocsf_registry::OcsfLookup::Unknown { suggestions } => Some(suggestions),
            _ => None,
        }
    };
    FieldInfo {
        field: field.to_string(),
        resolves_to,
        queryable,
        suggestions,
    }
}

fn check(profile: &OcsfProfile, gen: &ClickHouseSqlGenerator, range: &TimeRange, line: usize, input: Input) -> Output {
    let mut out = Output {
        line,
        id: input.id,
        ok: false,
        input_error: None,
        parse_error: None,
        field_errors: Vec::new(),
        fields: Vec::new(),
        codegen_error: None,
        sql: None,
    };
    out.fields = dotted_fields(&input.query)
        .into_iter()
        .filter(|f| !f.starts_with("unmapped.") && !f.starts_with("ext."))
        .map(|f| classify(profile, &f))
        .collect();
    let query = match parse_query(&input.query) {
        Ok(q) => q,
        Err(e) => {
            out.parse_error = Some(e.to_string());
            return out;
        }
    };
    out.field_errors = validate_query_fields_with_profile(&query, Some(profile as &dyn SchemaProfile))
        .into_iter()
        .map(|e| FieldError {
            field: e.field_name,
            message: e.message,
            suggestions: e.suggestions,
        })
        .collect();
    let stripped = strip_post_prevalence_commands(&query);
    match gen.generate(&stripped, range) {
        Ok(sql) => out.sql = Some(sql),
        Err(e) => out.codegen_error = Some(e.to_string()),
    }
    out.ok = out.field_errors.is_empty()
        && out.codegen_error.is_none()
        && out.fields.iter().all(|f| f.queryable);
    out
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let profile = OcsfProfile::new();
    let gen = ClickHouseSqlGenerator::with_table("nanosiem.ocsf_logs".to_string())
        .with_profile(Arc::new(OcsfProfile::new()));
    let range = TimeRange {
        start: "2026-01-01T00:00:00Z".parse()?,
        end: "2026-01-02T00:00:00Z".parse()?,
    };
    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut output = BufWriter::new(stdout.lock());
    for (index, line) in stdin.lock().lines().enumerate() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let result = match serde_json::from_str::<Input>(&line) {
            Ok(input) => check(&profile, &gen, &range, index + 1, input),
            Err(e) => Output {
                line: index + 1,
                id: None,
                ok: false,
                input_error: Some(e.to_string()),
                parse_error: None,
                field_errors: Vec::new(),
                fields: Vec::new(),
                codegen_error: None,
                sql: None,
            },
        };
        serde_json::to_writer(&mut output, &result)?;
        output.write_all(b"\n")?;
    }
    output.flush()?;
    Ok(())
}
