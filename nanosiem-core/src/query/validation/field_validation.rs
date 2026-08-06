// SPDX-License-Identifier: AGPL-3.0-or-later

//! Field name validation against the UDM schema
//!
//! Validates field references in queries, suggests corrections for typos,
//! and allows ext JSON fields that don't closely match UDM fields.

use crate::query::ast::{Command, Query, RexMode, RiskScoreExpr, SearchExpr};
use crate::udm::fields::UdmField;
use std::collections::HashSet;
use std::str::FromStr;

use super::derived_fields::collect_command_output_fields;

/// Error type for field validation
#[derive(Debug, Clone)]
pub struct FieldValidationError {
    pub field_name: String,
    pub message: String,
    pub suggestions: Vec<String>,
}

impl std::fmt::Display for FieldValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)?;
        if !self.suggestions.is_empty() {
            write!(f, "\n\nDid you mean one of these?\n")?;
            for suggestion in &self.suggestions {
                write!(f, "  - {}\n", suggestion)?;
            }
        }
        Ok(())
    }
}

impl std::error::Error for FieldValidationError {}

/// Validate that a field name is a valid UDM field
///
/// Returns Ok(UdmField) if the field is valid, or Err with suggestions if invalid.
///
/// # Examples
///
/// ```
/// use nanosiem_core::query::validation::validate_field_name;
///
/// // Valid field
/// assert!(validate_field_name("src_ip").is_ok());
///
/// // Invalid field with suggestions
/// let err = validate_field_name("source_ip").unwrap_err();
/// assert!(err.suggestions.contains(&"src_ip".to_string()));
/// ```
/// Check that a field name has a safe syntactic format (no parentheses, SQL operators, etc.)
///
/// Field names must match `^[a-zA-Z_][a-zA-Z0-9_.]*$`. This prevents injection of
/// function calls like `version()` or SQL fragments through field name positions.
pub fn validate_field_name_format(field_name: &str) -> Result<(), FieldValidationError> {
    if field_name.is_empty() {
        return Err(FieldValidationError {
            field_name: field_name.to_string(),
            message: "Field name cannot be empty".to_string(),
            suggestions: vec![],
        });
    }

    // First character must be a letter or underscore
    let first = field_name.chars().next().unwrap();
    if !first.is_ascii_alphabetic() && first != '_' {
        return Err(FieldValidationError {
            field_name: field_name.to_string(),
            message: format!(
                "Invalid field name '{}': must start with a letter or underscore",
                field_name
            ),
            suggestions: vec![],
        });
    }

    // Remaining characters must be alphanumeric, underscore, or dot (for nested fields)
    for ch in field_name.chars().skip(1) {
        if !ch.is_ascii_alphanumeric() && ch != '_' && ch != '.' {
            return Err(FieldValidationError {
                field_name: field_name.to_string(),
                message: format!(
                    "Invalid field name '{}': contains illegal character '{}'. Field names may only contain letters, digits, underscores, and dots.",
                    field_name, ch
                ),
                suggestions: vec![],
            });
        }
    }

    Ok(())
}

/// Validate the syntactic format of a wildcard field pattern (`src_*`, `*_ip`).
///
/// `table` / `fields` accept glob-style patterns that codegen expands against
/// schema columns and pipeline-computed fields (`expand_wildcard`, #2064), so
/// they are not literal field references and must bypass [`is_valid_field`]
/// (NAN-1380). They still get a format gate: the same alphabet as field names
/// plus `*`, so SQL metacharacters can't ride in on a "pattern".
fn validate_wildcard_pattern_format(pattern: &str) -> Result<(), FieldValidationError> {
    for ch in pattern.chars() {
        if !ch.is_ascii_alphanumeric() && ch != '_' && ch != '.' && ch != '*' {
            return Err(FieldValidationError {
                field_name: pattern.to_string(),
                message: format!(
                    "Invalid field pattern '{}': contains illegal character '{}'. Field patterns may only contain letters, digits, underscores, dots, and '*' wildcards.",
                    pattern, ch
                ),
                suggestions: vec![],
            });
        }
    }
    Ok(())
}

pub fn validate_field_name(field_name: &str) -> Result<UdmField, FieldValidationError> {
    // Reject syntactically invalid field names (e.g. "version()", "1+1")
    validate_field_name_format(field_name)?;

    // Check direct UDM field match first
    if let Ok(field) = UdmField::from_str(field_name) {
        return Ok(field);
    }

    // Check known aliases (fields accepted in queries that map to UDM columns)
    if let Some(canonical) = resolve_field_alias(field_name) {
        if let Ok(field) = UdmField::from_str(canonical) {
            return Ok(field);
        }
    }

    // Field not found - generate suggestions
    let suggestions = suggest_similar_fields(field_name, 5);
    Err(FieldValidationError {
        field_name: field_name.to_string(),
        message: format!("Unknown field '{}' in query", field_name),
        suggestions,
    })
}

/// Resolve a field alias to its canonical UDM field name.
///
/// These aliases are accepted in queries and transparently mapped to the
/// underlying UDM column during SQL generation (see `field_utils.rs` and
/// `clickhouse_sql_gen.rs`). The validator must accept them too.
fn resolve_field_alias(field_name: &str) -> Option<&'static str> {
    match field_name {
        "process" => Some("command_line"),
        "parent_process" => Some("parent_command_line"),
        _ => None,
    }
}

/// Suggest similar field names for a typo or unknown field
///
/// Uses Levenshtein distance to find the closest matching field names.
/// Returns up to `max_suggestions` field names sorted by similarity.
///
/// # Examples
///
/// ```ignore
/// use nanosiem_core::query::validation::suggest_similar_fields;
///
/// let suggestions = suggest_similar_fields("source_ip", 3);
/// assert!(!suggestions.is_empty());
/// ```
pub fn suggest_similar_fields(field_name: &str, max_suggestions: usize) -> Vec<String> {
    let all_fields = UdmField::all();
    let mut scored_fields: Vec<(String, usize)> = all_fields
        .iter()
        .map(|field| {
            let field_str = field.column_name();
            let distance = levenshtein_distance(field_name, field_str);
            (field_str.to_string(), distance)
        })
        .collect();

    // Sort by distance (lower is better)
    scored_fields.sort_by_key(|(_, distance)| *distance);

    // Return top N suggestions, but only if they're reasonably close
    // (distance <= 3 or within 50% of the field name length)
    let max_distance = std::cmp::max(3, field_name.len() / 2);
    scored_fields
        .into_iter()
        .filter(|(_, distance)| *distance <= max_distance)
        .take(max_suggestions)
        .map(|(field, _)| field)
        .collect()
}

/// Calculate Levenshtein distance between two strings
///
/// This is the minimum number of single-character edits (insertions, deletions, or substitutions)
/// required to change one string into the other.
fn levenshtein_distance(s1: &str, s2: &str) -> usize {
    let len1 = s1.len();
    let len2 = s2.len();

    if len1 == 0 {
        return len2;
    }
    if len2 == 0 {
        return len1;
    }

    let mut matrix = vec![vec![0; len2 + 1]; len1 + 1];

    // Initialize first row and column
    for i in 0..=len1 {
        matrix[i][0] = i;
    }
    for j in 0..=len2 {
        matrix[0][j] = j;
    }

    // Fill in the rest of the matrix
    for (i, c1) in s1.chars().enumerate() {
        for (j, c2) in s2.chars().enumerate() {
            let cost = if c1 == c2 { 0 } else { 1 };
            matrix[i + 1][j + 1] = std::cmp::min(
                std::cmp::min(
                    matrix[i][j + 1] + 1, // deletion
                    matrix[i + 1][j] + 1, // insertion
                ),
                matrix[i][j] + cost, // substitution
            );
        }
    }

    matrix[len1][len2]
}

/// Validate all field references in a query
///
/// Walks through the query AST and validates all field names against UDM fields,
/// derived fields from pipeline stages, and potential ext JSON fields.
///
/// Fields that closely match a UDM field are flagged as likely typos. Fields with
/// no close UDM match are allowed through as potential ext JSON fields.
///
/// # Examples
///
/// ```
/// use nanosiem_core::query::{parse_query, validation::validate_query_fields};
///
/// // Typo "source_ip" is close to "src_ip" — caught as error
/// let query = parse_query("source_ip=192.168.1.1").unwrap();
/// let errors = validate_query_fields(&query);
/// assert_eq!(errors.len(), 1);
/// assert_eq!(errors[0].field_name, "source_ip");
/// ```
pub fn validate_query_fields(query: &Query) -> Vec<FieldValidationError> {
    validate_query_fields_with_profile(query, None)
}

/// Profile-aware variant of [`validate_query_fields`] (NAN-1380).
///
/// The typo gate in [`is_valid_field`] measures edit distance against the UDM
/// field universe only, so a real column of the *active* schema that happens to
/// sit near a UDM name (`.`→`_` costs one edit: OCSF `user.name` vs UDM
/// `user_name`) would be rejected as a typo. Passing the active
/// [`SchemaProfile`](crate::schema::SchemaProfile) lets the validator accept any
/// name the schema itself knows (promoted OCSF columns, UDM explicit columns)
/// before the distance heuristic runs. `None` preserves the profile-blind
/// behavior for callers without a schema context.
pub fn validate_query_fields_with_profile(
    query: &Query,
    profile: Option<&dyn crate::schema::SchemaProfile>,
) -> Vec<FieldValidationError> {
    let mut errors = Vec::new();
    let mut derived = HashSet::new();
    validate_query_fields_recursive(query, &mut errors, &mut derived, profile);
    errors
}

/// Check if a field is valid in pipeline context.
///
/// A field is valid if it's:
/// 1. A derived field from a prior pipeline stage (stats alias, eval, etc.)
/// 2. A known UDM field or alias
/// 3. An unknown field that doesn't closely resemble a UDM field (likely an ext JSON field)
///
/// Only rejects fields that have similar UDM matches (suggesting a typo) or that fail
/// the safe-format check. Fields with no close UDM match (but a valid format) are allowed
/// through as potential ext JSON fields — the SQL generator handles these via JSON extraction.
fn is_valid_field(
    field_name: &str,
    derived: &HashSet<String>,
    profile: Option<&dyn crate::schema::SchemaProfile>,
) -> Result<(), FieldValidationError> {
    if derived.contains(&field_name.to_lowercase()) {
        return Ok(());
    }
    // SECURITY (NAN-1354): enforce a safe syntactic format for EVERY non-derived
    // field reference, unconditionally. Previously the format check lived only
    // inside `validate_field_name` and was re-raised below solely when the name
    // was close to a UDM field — so a format-invalid name far from any UDM field
    // (e.g. a quoted `rename "v()" as x`) slipped through this gate. Codegen still
    // escapes such names, but this validator is the documented input-side guard
    // and must reject them outright. Derived fields (pipeline output aliases) are
    // exempt by the early return above: codegen owns their escaping (see the
    // output-name note in `validate_command_fields`).
    validate_field_name_format(field_name)?;

    match validate_field_name(field_name) {
        Ok(_) => Ok(()),
        Err(err) => {
            // NAN-1380 (G5): before the UDM-distance typo gate, consult the
            // active schema profile. A name the active schema itself knows —
            // a promoted OCSF column (`user.name`, `file.path`, `process.pid`)
            // or a UDM explicit column — is a real column reference, never a
            // typo, even when it sits one edit away from a UDM field name
            // (`.`→`_` costs exactly 1). Without this, native OCSF names near
            // a UDM alias are 400-rejected under the OCSF profile.
            if let Some(p) = profile {
                if p.is_known_field(field_name) {
                    return Ok(());
                }
                // O6 (NAN-1721): a name the active profile resolves to a `Map`
                // attribute key — the spans `attributes`/`resource_attributes`
                // tail or the metrics tags tail (`FieldResolution::MapKey`) — is
                // a real attribute reference, never a UDM typo. Un-promoted OTel
                // attributes are the flagship span/metric filter surface
                // (NAN-1555), but common dotted names sit within one edit of a
                // UDM column (`http.method` vs `http_method`, `user.name` vs
                // `user_name`) and the distance gate below 400-rejects them.
                // Accept MapKey-resolvable names before the typo gate. UDM/OCSF
                // never resolve to `MapKey` (their tail is a JSON column), so
                // this is inert under the logs profiles.
                if matches!(
                    p.resolve(field_name),
                    crate::schema::FieldResolution::MapKey { .. }
                ) {
                    return Ok(());
                }
            }
            // Format already passed above, so `err` here is an "unknown field".
            // Compute minimum edit distance to any UDM field. Use a tight threshold
            // (≤ 33% of name length, min 2) to catch likely typos while allowing
            // legitimate ext fields. The suggestion list uses a looser threshold
            // (max(3, len/2)) which would false-flag long ext field names.
            let lower = field_name.to_lowercase();
            let min_distance = UdmField::all()
                .iter()
                .map(|f| levenshtein_distance(&lower, f.column_name()))
                .min()
                .unwrap_or(usize::MAX);
            let typo_threshold = std::cmp::max(2, field_name.len() / 3);
            if min_distance <= typo_threshold {
                Err(err)
            } else {
                Ok(())
            }
        }
    }
}

/// Recursively validate field names in a query, accumulating derived fields through the pipeline.
fn validate_query_fields_recursive(
    query: &Query,
    errors: &mut Vec<FieldValidationError>,
    derived: &mut HashSet<String>,
    profile: Option<&dyn crate::schema::SchemaProfile>,
) {
    match query {
        Query::Search(search_expr) => {
            validate_search_expr_fields(search_expr, errors, derived, profile);
        }
        Query::Piped { source, command } => {
            validate_query_fields_recursive(source, errors, derived, profile);
            validate_command_fields(command, errors, derived, profile);
            collect_command_output_fields(command, derived);
        }
    }
}

/// Validate field names in a search expression
fn validate_search_expr_fields(
    expr: &SearchExpr,
    errors: &mut Vec<FieldValidationError>,
    derived: &HashSet<String>,
    profile: Option<&dyn crate::schema::SchemaProfile>,
) {
    match expr {
        SearchExpr::Keyword(_) => {
            // Keywords don't reference fields
        }
        SearchExpr::FieldFilter { field, .. } => {
            if let Err(err) = is_valid_field(field, derived, profile) {
                errors.push(err);
            }
        }
        SearchExpr::FunctionFilter { function, .. } => {
            // Validate fields referenced in function arguments
            validate_eval_expr_fields(function, errors, derived, profile);
        }
        SearchExpr::FieldFunctionFilter {
            field, function, ..
        } => {
            // Validate the field and fields referenced in function arguments
            if let Err(err) = is_valid_field(field, derived, profile) {
                errors.push(err);
            }
            validate_eval_expr_fields(function, errors, derived, profile);
        }
        SearchExpr::InList { field, .. } => {
            if let Err(err) = is_valid_field(field, derived, profile) {
                errors.push(err);
            }
        }
        SearchExpr::And(left, right) | SearchExpr::Or(left, right) => {
            validate_search_expr_fields(left, errors, derived, profile);
            validate_search_expr_fields(right, errors, derived, profile);
        }
        SearchExpr::Not(expr) | SearchExpr::Group(expr) => {
            validate_search_expr_fields(expr, errors, derived, profile);
        }
        SearchExpr::BooleanFunction(function) => {
            validate_eval_expr_fields(function, errors, derived, profile);
        }
        SearchExpr::EvalPredicate(expression) => {
            validate_eval_expr_fields(expression, errors, derived, profile);
        }
        SearchExpr::LiteralComparison { .. } => {
            // Literal comparisons don't reference fields
        }
        SearchExpr::IocMatch { .. } => {
            // NAN-1580: the `ioc` pseudo-field is an observable-anywhere term —
            // it doesn't reference a named column, so there is nothing to
            // validate (and `ioc` is intentionally permitted as a pseudo-field).
        }
        SearchExpr::InSubsearch { field, subsearch, .. } => {
            if let Err(err) = is_valid_field(field, derived, profile) {
                errors.push(err);
            }
            // Validate fields in the subsearch query
            let mut sub_derived = HashSet::new();
            validate_query_fields_recursive(subsearch, errors, &mut sub_derived, profile);
        }
    }
}

/// Validate field names in an eval expression
fn validate_eval_expr_fields(
    expr: &crate::query::EvalExpression,
    errors: &mut Vec<FieldValidationError>,
    derived: &HashSet<String>,
    profile: Option<&dyn crate::schema::SchemaProfile>,
) {
    use crate::query::EvalExpression;

    match expr {
        EvalExpression::Field(field) => {
            if let Err(err) = is_valid_field(field, derived, profile) {
                errors.push(err);
            }
        }
        EvalExpression::Literal(_) => {
            // Literals don't reference fields
        }
        EvalExpression::FunctionCall { args, .. } => {
            // Validate fields in function arguments
            for arg in args {
                validate_eval_expr_fields(arg, errors, derived, profile);
            }
        }
        EvalExpression::BinaryOp { left, right, .. } => {
            validate_eval_expr_fields(left, errors, derived, profile);
            validate_eval_expr_fields(right, errors, derived, profile);
        }
    }
}

/// Validate field names in a command
fn validate_command_fields(
    command: &Command,
    errors: &mut Vec<FieldValidationError>,
    derived: &mut HashSet<String>,
    profile: Option<&dyn crate::schema::SchemaProfile>,
) {
    match command {
        Command::Stats {
            aggregations,
            group_by,
        }
        | Command::Chart {
            aggregations,
            group_by,
        } => {
            // Validate aggregation fields
            for agg in aggregations {
                if let Some(field) = &agg.field {
                    if let Err(err) = is_valid_field(field, derived, profile) {
                        errors.push(err);
                    }
                }
            }
            // Validate group by fields
            if let Some(fields) = group_by {
                for field in fields {
                    if let Err(err) = is_valid_field(field, derived, profile) {
                        errors.push(err);
                    }
                }
            }
        }
        Command::StreamStats {
            aggregations,
            group_by,
            ..
        } => {
            // Validate aggregation fields
            for agg in aggregations {
                if let Some(field) = &agg.field {
                    if let Err(err) = is_valid_field(field, derived, profile) {
                        errors.push(err);
                    }
                }
            }
            // Validate group by fields
            if let Some(fields) = group_by {
                for field in fields {
                    if let Err(err) = is_valid_field(field, derived, profile) {
                        errors.push(err);
                    }
                }
            }
        }
        Command::Where { condition } => {
            validate_search_expr_fields(condition, errors, derived, profile);
        }
        Command::Sort { fields, .. } => {
            for sf in fields {
                if let Err(err) = is_valid_field(&sf.field, derived, profile) {
                    errors.push(err);
                }
            }
        }
        Command::Timechart {
            aggregations,
            split_by,
            ..
        } => {
            // Validate aggregation fields
            for agg in aggregations {
                if let Some(field) = &agg.field {
                    if let Err(err) = is_valid_field(field, derived, profile) {
                        errors.push(err);
                    }
                }
            }
            // Validate split by fields
            for field in split_by {
                if let Err(err) = is_valid_field(field, derived, profile) {
                    errors.push(err);
                }
            }
        }
        Command::Table { fields } => {
            for table_field in fields {
                // Wildcard patterns (`*`, `src_*`, `*_ip`) are not literal field
                // references — codegen expands them against schema columns and
                // pipeline-computed fields (#2064, `expand_wildcard`). Skip
                // field-name validation but keep a format gate so SQL
                // metacharacters can't ride in on a "pattern" (NAN-1380).
                if table_field.name.contains('*') {
                    if let Err(err) = validate_wildcard_pattern_format(&table_field.name) {
                        errors.push(err);
                    }
                    continue;
                }
                if let Err(err) = is_valid_field(&table_field.name, derived, profile) {
                    errors.push(err);
                }
            }
        }
        Command::Rename { mappings } => {
            for mapping in mappings {
                if let Err(err) = is_valid_field(&mapping.from, derived, profile) {
                    errors.push(err);
                }
                // Note: We don't validate the 'to' field since it's a new name being created
            }
        }
        Command::Lookup {
            key_field,
            output_fields,
            ..
        } => {
            if let Err(err) = is_valid_field(key_field, derived, profile) {
                errors.push(err);
            }
            // OUTPUT names are columns of the lookup TABLE that the command
            // adds to the result — not event-field references — so the UDM
            // typo gate doesn't apply (NAN-1396: `OUTPUT confidence` sat 3
            // edits from `ai_confidence` and was rejected as a typo). Keep
            // the safe-format gate: the names are interpolated into the
            // lookup SQL (the lookup repository re-validates and quotes them,
            // this is the documented input-side guard).
            if let Some(fields) = output_fields {
                for field in fields {
                    if let Err(err) = validate_field_name_format(field) {
                        errors.push(err);
                    }
                }
            }
        }
        Command::Dedup { fields, .. } => {
            for field in fields {
                if let Err(err) = is_valid_field(field, derived, profile) {
                    errors.push(err);
                }
            }
        }
        Command::Bin { field, .. } => {
            if let Some(field_name) = field {
                if let Err(err) = is_valid_field(field_name, derived, profile) {
                    errors.push(err);
                }
            }
        }
        Command::Rex {
            field,
            pattern,
            mode,
        } => {
            if let Some(field_name) = field {
                if let Err(err) = is_valid_field(field_name, derived, profile) {
                    errors.push(err);
                }
            }
            // NAN-1992: a rex capture-group NAME becomes an output-column alias
            // in generated SQL (`extractGroups(...)[i] AS <name>`). Regex group
            // names are extracted as `[^>]+` — unconstrained — so `rex` was the
            // ONE identifier slot that never reached this format check, letting a
            // name like `a,version()` (with `/**/` for whitespace) thread through
            // `escape_identifier` into raw SQL. Validate the names like every
            // other alias; legitimate group names are always
            // `[A-Za-z_][A-Za-z0-9_]*`, so this rejects only injection attempts.
            // The sink itself (`escape_identifier`) is also hardened — this is the
            // consistent parse-time layer, matching lookup/dedup/bin/etc.
            if matches!(mode, RexMode::Extract) {
                for cap in regex::Regex::new(r"\(\?(?:P?<([^>]+)>)")
                    .unwrap()
                    .captures_iter(pattern)
                {
                    if let Some(name) = cap.get(1) {
                        if let Err(err) = validate_field_name_format(name.as_str()) {
                            errors.push(err);
                        }
                    }
                }
            }
        }
        Command::Fields { fields, .. } => {
            for field in fields {
                // Same wildcard-pattern skip as `table` above (NAN-1380):
                // `fields src_*` / `fields - src_*` / bare `fields *` are
                // expanded by codegen, not literal field references.
                if field.contains('*') {
                    if let Err(err) = validate_wildcard_pattern_format(field) {
                        errors.push(err);
                    }
                    continue;
                }
                if let Err(err) = is_valid_field(field, derived, profile) {
                    errors.push(err);
                }
            }
        }
        Command::Top {
            field, by_fields, ..
        }
        | Command::Rare {
            field, by_fields, ..
        } => {
            if let Err(err) = is_valid_field(field, derived, profile) {
                errors.push(err);
            }
            for by in by_fields {
                if let Err(err) = is_valid_field(by, derived, profile) {
                    errors.push(err);
                }
            }
        }
        Command::Transaction {
            fields,
            startswith,
            endswith,
            ..
        } => {
            for field in fields {
                if let Err(err) = is_valid_field(field, derived, profile) {
                    errors.push(err);
                }
            }
            if let Some(expr) = startswith {
                validate_search_expr_fields(expr, errors, derived, profile);
            }
            if let Some(expr) = endswith {
                validate_search_expr_fields(expr, errors, derived, profile);
            }
        }
        Command::Fillnull { fields, .. } => {
            if let Some(field_list) = fields {
                for field in field_list {
                    if let Err(err) = is_valid_field(field, derived, profile) {
                        errors.push(err);
                    }
                }
            }
        }
        Command::Mvexpand { field, .. } => {
            if let Err(err) = is_valid_field(field, derived, profile) {
                errors.push(err);
            }
        }
        Command::Spath { input, output, .. } => {
            if let Some(field_name) = input {
                if let Err(err) = is_valid_field(field_name, derived, profile) {
                    errors.push(err);
                }
            }
            if let Some(field_name) = output {
                // Output field is being created, so we don't validate it
                let _ = field_name;
            }
        }
        Command::Append { subsearch, .. } => {
            // Validate subsearch in its own context, then merge its output
            // fields into the parent pipeline (appended rows carry those fields)
            let mut sub_derived = HashSet::new();
            validate_query_fields_recursive(subsearch, errors, &mut sub_derived, profile);
            derived.extend(sub_derived);
        }
        Command::Join {
            fields, subsearch, ..
        } => {
            for field in fields {
                if let Err(err) = is_valid_field(field, derived, profile) {
                    errors.push(err);
                }
            }
            // Validate subsearch in its own context, then merge its output
            // fields into the parent pipeline (joined columns are available downstream)
            let mut sub_derived = HashSet::new();
            validate_query_fields_recursive(subsearch, errors, &mut sub_derived, profile);
            derived.extend(sub_derived);
        }
        Command::Return { fields, .. } => {
            for field in fields {
                if let Err(err) = is_valid_field(field, derived, profile) {
                    errors.push(err);
                }
            }
        }
        Command::Risk {
            score,
            entity_field,
            weight,
            ..
        } => {
            if let Some(field) = entity_field {
                if let Err(err) = is_valid_field(field, derived, profile) {
                    errors.push(err);
                }
            }
            // Validate literal score is within bounds (already validated at parse time, but double-check)
            if let RiskScoreExpr::Literal(s) = score {
                if *s < 0 || *s > 100 {
                    errors.push(FieldValidationError {
                        field_name: "score".to_string(),
                        message: format!("Risk score {} is out of bounds (must be 0-100)", s),
                        suggestions: vec![],
                    });
                }
            }
            // Validate weight is within bounds if provided
            if let Some(w) = weight {
                if !(*w >= 0.0 && *w <= 1.0) {
                    errors.push(FieldValidationError {
                        field_name: "weight".to_string(),
                        message: format!("Risk weight {} is out of bounds (must be 0.0-1.0)", w),
                        suggestions: vec![],
                    });
                }
            }
            // For dynamic expressions, validate field references
            if let RiskScoreExpr::Dynamic(expr) = score {
                validate_eval_expr_fields(expr, errors, derived, profile);
            }
        }
        Command::Prevalence { conditions, .. } => {
            // Prevalence conditions use special PrevalenceField enum, not regular field names
            // So we don't validate them here
            let _ = conditions;
        }
        Command::EventStats {
            aggregations,
            group_by,
        } => {
            // Validate aggregation fields
            for agg in aggregations {
                if let Some(field) = &agg.field {
                    if let Err(err) = is_valid_field(field, derived, profile) {
                        errors.push(err);
                    }
                }
            }
            // Validate group by fields
            if let Some(fields) = group_by {
                for field in fields {
                    if let Err(err) = is_valid_field(field, derived, profile) {
                        errors.push(err);
                    }
                }
            }
        }
        Command::Sequence {
            group_by,
            conditions,
            ..
        } => {
            if group_by.is_empty() {
                errors.push(FieldValidationError {
                    field_name: "sequence".to_string(),
                    message: "Sequence requires at least one group by field".to_string(),
                    suggestions: vec![],
                });
            }
            if conditions.len() < 2 {
                errors.push(FieldValidationError {
                    field_name: "sequence".to_string(),
                    message: "Sequence requires at least two conditions".to_string(),
                    suggestions: vec![],
                });
            }
            for field in group_by {
                if let Err(err) = is_valid_field(field, derived, profile) {
                    errors.push(err);
                }
            }
            for condition in conditions {
                validate_search_expr_fields(condition, errors, derived, profile);
            }
        }
        Command::Funnel {
            group_by, steps, ..
        } => {
            if group_by.is_empty() {
                errors.push(FieldValidationError {
                    field_name: "funnel".to_string(),
                    message: "Funnel requires at least one group by field".to_string(),
                    suggestions: vec![],
                });
            }
            if steps.len() < 2 {
                errors.push(FieldValidationError {
                    field_name: "funnel".to_string(),
                    message: "Funnel requires at least two steps".to_string(),
                    suggestions: vec![],
                });
            }
            for field in group_by {
                if let Err(err) = is_valid_field(field, derived, profile) {
                    errors.push(err);
                }
            }
            for (_, condition) in steps {
                validate_search_expr_fields(condition, errors, derived, profile);
            }
        }
        Command::Anomaly {
            field, by_fields, ..
        } => {
            // Skip validation for aggregation expressions like "count()" or "sum(bytes_out)"
            if !field.contains('(') {
                if let Err(err) = is_valid_field(field, derived, profile) {
                    errors.push(err);
                }
            }
            for by in by_fields {
                if let Err(err) = is_valid_field(by, derived, profile) {
                    errors.push(err);
                }
            }
        }
        Command::Eval { assignments } => {
            // Validate RHS expressions. Assignments are sequential: earlier
            // assignments in the same eval are available to later ones.
            //
            // NOTE (NAN-1354): the LHS target name (`assignment.field`) is an
            // OUTPUT alias, not an input reference, and is deliberately NOT
            // format-validated here. Output-name safety is owned by codegen
            // escaping — `clickhouse_sql_gen` wraps it in `escape_identifier`
            // (NAN-1352) just like rename's `to`, spath's `output`, and the
            // bin/rex/mvexpand aliases. Format-validating output names would
            // reject legitimate quoted aliases (`eval "p95 latency" = …`) that
            // codegen handles safely. Same rationale for the un-validated
            // `to`/`output` fields in the Rename and Spath arms above.
            let mut local_derived = derived.clone();
            for assignment in assignments {
                validate_eval_expr_fields(&assignment.expression, errors, &local_derived, profile);
                local_derived.insert(assignment.field.to_lowercase());
            }
        }
        // Commands that don't reference fields
        Command::Head { .. }
        | Command::Tail { .. }
        | Command::Format { .. }
        | Command::Sample { .. }
        | Command::Reverse
        | Command::InputLookup { .. }
        | Command::Tree { .. }
        | Command::ResolveIdentity { .. }
        | Command::Asset { .. }
        | Command::Cloud { .. }
        | Command::Lateral { .. }
        | Command::Ai { .. }
        | Command::Services
        | Command::Service { .. }
        | Command::Trace { .. }
        | Command::Metric { .. }
        // NAN-1580: retro references no UDM fields directly (its observable
        // expansion targets the base columns).
        | Command::Retro { .. }
        // NAN-1868: baseline's `dims=`/`entity=` args are validated in its own
        // executor against the profile, not here.
        | Command::Baseline { .. }
        | Command::Output { .. } => {
            // These commands don't reference UDM fields directly or are handled in post-processing
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::query::parse_query;

    #[test]
    fn test_validate_field_name_valid() {
        assert!(validate_field_name("src_ip").is_ok());
        assert!(validate_field_name("dest_port").is_ok());
        assert!(validate_field_name("user").is_ok());
        assert!(validate_field_name("process_name").is_ok());
    }

    #[test]
    fn test_validate_field_name_aliases() {
        // process is a backward-compat alias for command_line
        let field = validate_field_name("process").unwrap();
        assert_eq!(field, UdmField::CommandLine);

        // parent_process is a backward-compat alias for parent_command_line
        let field = validate_field_name("parent_process").unwrap();
        assert_eq!(field, UdmField::ParentCommandLine);
    }

    #[test]
    fn test_validate_field_name_invalid() {
        let err = validate_field_name("src_ipp").unwrap_err();
        assert_eq!(err.field_name, "src_ipp");
        assert!(!err.suggestions.is_empty());
        assert!(err.suggestions.contains(&"src_ip".to_string()));
    }

    #[test]
    fn test_suggest_similar_fields() {
        let suggestions = suggest_similar_fields("source_ip", 5);
        assert!(suggestions.contains(&"src_ip".to_string()));

        let suggestions = suggest_similar_fields("destination_port", 5);
        assert!(suggestions.contains(&"dest_port".to_string()));

        let suggestions = suggest_similar_fields("username", 5);
        assert!(
            suggestions.contains(&"user".to_string())
                || suggestions.contains(&"user_name".to_string())
        );
    }

    #[test]
    fn test_levenshtein_distance() {
        assert_eq!(levenshtein_distance("", ""), 0);
        assert_eq!(levenshtein_distance("abc", "abc"), 0);
        assert_eq!(levenshtein_distance("abc", "ab"), 1);
        assert_eq!(levenshtein_distance("abc", "abcd"), 1);
        assert_eq!(levenshtein_distance("abc", "adc"), 1);
        assert_eq!(levenshtein_distance("kitten", "sitting"), 3);
    }

    #[test]
    fn test_validate_query_fields_valid() {
        let query = parse_query("src_ip=192.168.1.1 AND dest_port=80").unwrap();
        let errors = validate_query_fields(&query);
        assert_eq!(errors.len(), 0);
    }

    #[test]
    fn test_validate_query_fields_typo_rejected() {
        // source_ip is close to src_ip — should be caught as a typo
        let query = parse_query("source_ip=192.168.1.1").unwrap();
        let errors = validate_query_fields(&query);
        assert_eq!(errors.len(), 1);
        assert_eq!(errors[0].field_name, "source_ip");
        assert!(errors[0].suggestions.contains(&"src_ip".to_string()));
    }

    #[test]
    fn test_validate_query_fields_typo_in_stats() {
        // src_ipp is a typo for src_ip
        let query = parse_query("error | stats count() by src_ipp").unwrap();
        let errors = validate_query_fields(&query);
        assert_eq!(errors.len(), 1);
        assert_eq!(errors[0].field_name, "src_ipp");
    }

    #[test]
    fn test_validate_query_fields_typo_in_where() {
        let query = parse_query("error | where src_ipp=test").unwrap();
        let errors = validate_query_fields(&query);
        assert_eq!(errors.len(), 1);
        assert_eq!(errors[0].field_name, "src_ipp");
    }

    #[test]
    fn test_validate_query_fields_typo_in_sort() {
        let query = parse_query("error | sort src_ipp").unwrap();
        let errors = validate_query_fields(&query);
        assert_eq!(errors.len(), 1);
        assert_eq!(errors[0].field_name, "src_ipp");
    }

    #[test]
    fn test_validate_query_fields_typo_in_table() {
        let query = parse_query("error | table src_ip, src_ipp").unwrap();
        let errors = validate_query_fields(&query);
        assert_eq!(errors.len(), 1);
        assert_eq!(errors[0].field_name, "src_ipp");
    }

    // --- Derived fields from pipeline stages ---

    #[test]
    fn test_stats_derived_fields_accepted_in_where() {
        let query = parse_query(
            "* | stats dc(src_host) as host_count by process_hash | where host_count < 10",
        )
        .unwrap();
        let errors = validate_query_fields(&query);
        assert_eq!(
            errors.len(),
            0,
            "where should accept derived field from stats: {:?}",
            errors
        );
    }

    #[test]
    fn test_stats_derived_fields_accepted_in_table() {
        let query = parse_query(
            "* | stats dc(user) as unique_users by src_ip | table src_ip, unique_users",
        )
        .unwrap();
        let errors = validate_query_fields(&query);
        assert_eq!(
            errors.len(),
            0,
            "table should accept derived fields from stats: {:?}",
            errors
        );
    }

    #[test]
    fn test_stats_derived_fields_accepted_in_sort() {
        let query = parse_query("* | stats count() as cnt by src_ip | sort -cnt").unwrap();
        let errors = validate_query_fields(&query);
        assert_eq!(
            errors.len(),
            0,
            "sort should accept derived field from stats: {:?}",
            errors
        );
    }

    #[test]
    fn test_eval_derived_fields_accepted_downstream() {
        let query = parse_query("* | eval total=bytes_in+bytes_out | where total > 1000").unwrap();
        let errors = validate_query_fields(&query);
        assert_eq!(
            errors.len(),
            0,
            "where should accept derived field from eval: {:?}",
            errors
        );
    }

    #[test]
    fn test_multi_stage_derived_fields() {
        let query = parse_query("* | stats dc(user) as unique_users by src_ip | where unique_users > 5 | table src_ip, unique_users").unwrap();
        let errors = validate_query_fields(&query);
        assert_eq!(
            errors.len(),
            0,
            "multi-stage pipeline should accept derived fields: {:?}",
            errors
        );
    }

    #[test]
    fn test_default_stats_count_accepted() {
        let query = parse_query("* | stats count() by src_ip | where count > 100").unwrap();
        let errors = validate_query_fields(&query);
        assert_eq!(
            errors.len(),
            0,
            "where should accept default 'count' from stats: {:?}",
            errors
        );
    }

    #[test]
    fn test_typo_still_rejected_after_stats() {
        // stats creates host_count, but src_ipp is a typo (not derived)
        let query = parse_query(
            "* | stats dc(src_host) as host_count by process_hash | where src_ipp < 10",
        )
        .unwrap();
        let errors = validate_query_fields(&query);
        assert_eq!(errors.len(), 1);
        assert_eq!(errors[0].field_name, "src_ipp");
    }

    // --- Ext JSON fields (non-UDM, no close match) ---

    #[test]
    fn test_ext_field_accepted_in_search() {
        // threat_score is not a UDM field and not close to one — treat as ext field
        let query = parse_query("threat_score=high").unwrap();
        let errors = validate_query_fields(&query);
        assert_eq!(
            errors.len(),
            0,
            "ext fields should be accepted: {:?}",
            errors
        );
    }

    #[test]
    fn test_ext_field_accepted_in_where() {
        let query = parse_query("* | where vendor_severity > 5").unwrap();
        let errors = validate_query_fields(&query);
        assert_eq!(
            errors.len(),
            0,
            "ext fields in where should be accepted: {:?}",
            errors
        );
    }

    // --- Join/append subsearch fields propagated ---

    #[test]
    fn test_join_subsearch_fields_available_downstream() {
        let query = parse_query("* | join type=left src_ip [search * | stats dc(src_host) as unique_hosts by src_ip] | where unique_hosts > 5").unwrap();
        let errors = validate_query_fields(&query);
        assert_eq!(
            errors.len(),
            0,
            "join subsearch derived fields should be available downstream: {:?}",
            errors
        );
    }

    #[test]
    fn test_append_subsearch_fields_available_downstream() {
        let query = parse_query("* | append [search * | stats count() as alert_count by src_ip] | where alert_count > 0").unwrap();
        let errors = validate_query_fields(&query);
        assert_eq!(
            errors.len(),
            0,
            "append subsearch derived fields should be available downstream: {:?}",
            errors
        );
    }

    // --- Eval RHS validation ---

    #[test]
    fn test_eval_rhs_typo_caught() {
        // src_ipp is a typo in eval expression — should be caught
        let query = parse_query("* | eval total=src_ipp+dest_port").unwrap();
        let errors = validate_query_fields(&query);
        assert_eq!(errors.len(), 1);
        assert_eq!(errors[0].field_name, "src_ipp");
    }

    #[test]
    fn test_eval_rhs_valid_udm_fields() {
        let query = parse_query("* | eval total=bytes_in+bytes_out").unwrap();
        let errors = validate_query_fields(&query);
        assert_eq!(
            errors.len(),
            0,
            "eval should accept valid UDM fields: {:?}",
            errors
        );
    }

    #[test]
    fn test_eval_sequential_assignments() {
        // Second assignment references field from first — should be valid
        let query =
            parse_query("* | eval total=bytes_in+bytes_out, ratio=total/bytes_out").unwrap();
        let errors = validate_query_fields(&query);
        assert_eq!(
            errors.len(),
            0,
            "eval should accept earlier assignment fields: {:?}",
            errors
        );
    }

    #[test]
    fn test_eval_rhs_accepts_derived_from_prior_stage() {
        let query =
            parse_query("* | stats sum(bytes_in) as total_in by src_ip | eval doubled=total_in*2")
                .unwrap();
        let errors = validate_query_fields(&query);
        assert_eq!(
            errors.len(),
            0,
            "eval should accept derived fields from prior stages: {:?}",
            errors
        );
    }

    // --- NAN-1354: unconditional format enforcement on field references ---

    #[test]
    fn test_format_invalid_field_rejected_regardless_of_udm_distance() {
        // A quoted field name carrying SQL metacharacters reaches a validated
        // INPUT position (rename's `from`). It is far from any UDM field, so
        // pre-NAN-1354 the distance gate let it through. It must now be rejected
        // by the unconditional format check.
        for q in [
            r#"error | rename "v()" as x"#,
            r#"error | rename "a;DROP" as x"#,
            r#"error | rename "a, b" as x"#,
        ] {
            let query = parse_query(q).unwrap_or_else(|e| panic!("parse {q}: {e}"));
            let errors = validate_query_fields(&query);
            assert!(
                !errors.is_empty(),
                "format-invalid field must be rejected: {q}"
            );
        }
    }

    #[test]
    fn test_format_valid_non_udm_fields_still_pass() {
        // Ext-JSON fields and native OCSF dotted names typed directly are
        // format-valid and far from UDM — they must keep passing as ext fields.
        for q in [
            "threat_score=high",
            r#"src_endpoint.ip="1.2.3.4""#,
            "* | where vendor_severity > 5",
        ] {
            let query = parse_query(q).unwrap_or_else(|e| panic!("parse {q}: {e}"));
            let errors = validate_query_fields(&query);
            assert_eq!(errors.len(), 0, "format-valid ext/OCSF field must pass: {q}");
        }
    }

    // --- NAN-1380 G7: table/fields wildcard patterns are not field references ---

    #[test]
    fn test_table_and_fields_wildcard_patterns_pass() {
        for q in [
            "* | table src_*",
            "* | table *",
            "* | table src_*, dest_*",
            "* | fields src_*",
            "* | fields - src_*",
            "* | fields *",
        ] {
            let query = parse_query(q).unwrap_or_else(|e| panic!("parse {q}: {e}"));
            let errors = validate_query_fields(&query);
            assert_eq!(
                errors.len(),
                0,
                "wildcard pattern must pass validation: {q} -> {errors:?}"
            );
        }
    }

    #[test]
    fn test_table_wildcard_does_not_mask_typos() {
        // The wildcard skip applies per-field: a literal typo alongside a
        // wildcard pattern must still be caught.
        let query = parse_query("* | table src_*, src_ipp").unwrap();
        let errors = validate_query_fields(&query);
        assert_eq!(errors.len(), 1);
        assert_eq!(errors[0].field_name, "src_ipp");
    }

    // --- NAN-1380 G8: resolve_identity bare identity_* aliases are derived fields ---

    #[test]
    fn test_resolve_identity_bare_aliases_accepted_downstream() {
        for f in [
            // 8 column-backed + 5 dict-only attribute aliases (IDENTITY_*_FIELDS)
            "identity_department",
            "identity_title",
            "identity_groups",
            "identity_account_status",
            "identity_employee_type",
            "identity_mfa_enabled",
            "identity_country",
            "identity_display_name",
            "identity_email",
            "identity_manager",
            "identity_manager_upn",
            "identity_company",
            "identity_office_location",
            // always-bare resolve_identity outputs
            "identity_confidence",
            "identity_observed_at",
            "identity_source",
            "identity_fqdn",
            "identity_ip",
        ] {
            let q = format!(r#"* | resolve_identity | where {f}="x""#);
            let query = parse_query(&q).unwrap_or_else(|e| panic!("parse {q}: {e}"));
            let errors = validate_query_fields(&query);
            assert_eq!(
                errors.len(),
                0,
                "bare identity alias must pass after resolve_identity: {q} -> {errors:?}"
            );
        }
    }

    #[test]
    fn test_identity_alias_without_resolve_identity_still_typo_gated() {
        // Without a resolve_identity stage the bare alias is NOT derived; it
        // stays subject to the typo gate (close to user_identity_department).
        let query = parse_query(r#"* | where identity_department="x""#).unwrap();
        let errors = validate_query_fields(&query);
        assert_eq!(errors.len(), 1);
        assert_eq!(errors[0].field_name, "identity_department");
    }

    // --- NAN-1380 G5: profile-aware validation of promoted schema columns ---

    #[test]
    fn test_promoted_ocsf_columns_pass_under_ocsf_profile() {
        let profile = crate::schema::OcsfProfile::new();
        for q in [
            r#"user.name="admin""#,
            r#"file.path="/etc/passwd""#,
            r#"file.name="evil.exe""#,
            "process.pid=4",
            r#"cloud.provider="AWS""#,
            r#"cloud.region="us-east-1""#,
            r#"api.operation="GetObject""#,
            // pipeline positions hit the same gate
            "* | stats count() by user.name",
            "* | table file.path, process.pid",
            "* | sort cloud.region",
        ] {
            let query = parse_query(q).unwrap_or_else(|e| panic!("parse {q}: {e}"));
            let errors = validate_query_fields_with_profile(&query, Some(&profile));
            assert_eq!(
                errors.len(),
                0,
                "promoted OCSF column must pass under the OCSF profile: {q} -> {errors:?}"
            );
        }
    }

    #[test]
    fn test_typos_still_rejected_under_both_profiles() {
        let ocsf = crate::schema::OcsfProfile::new();
        let udm = crate::schema::UdmProfile::new();
        for q in [
            r#"usre="x""#,
            r#"source_ip="1.2.3.4""#,
            "* | stats count() by src_ipp",
        ] {
            let query = parse_query(q).unwrap_or_else(|e| panic!("parse {q}: {e}"));
            for profile in [
                &ocsf as &dyn crate::schema::SchemaProfile,
                &udm as &dyn crate::schema::SchemaProfile,
            ] {
                let errors = validate_query_fields_with_profile(&query, Some(profile));
                assert_eq!(
                    errors.len(),
                    1,
                    "genuine typo must still be rejected under {:?}: {q}",
                    profile.id()
                );
            }
        }
    }

    #[test]
    fn test_udm_profile_matches_profile_blind_behavior() {
        // UDM safety: passing Some(UdmProfile) must not change outcomes vs the
        // profile-blind path for representative queries (valid, typo, ext,
        // dotted-near-UDM, wildcards).
        let udm = crate::schema::UdmProfile::new();
        for q in [
            "src_ip=192.168.1.1 AND dest_port=80",
            r#"source_ip="1.2.3.4""#,
            "threat_score=high",
            r#"user.name="admin""#,
            "* | table src_*",
            "* | fields - src_*",
            "* | stats count() by src_ipp",
        ] {
            let query = parse_query(q).unwrap_or_else(|e| panic!("parse {q}: {e}"));
            let blind: Vec<String> = validate_query_fields(&query)
                .into_iter()
                .map(|e| e.field_name)
                .collect();
            let with_udm: Vec<String> = validate_query_fields_with_profile(&query, Some(&udm))
                .into_iter()
                .map(|e| e.field_name)
                .collect();
            assert_eq!(blind, with_udm, "UDM profile must not change outcomes: {q}");
        }
    }

    // --- NAN-1396 Bug A: unaliased {func}_{field} aggregate references ---

    #[test]
    fn test_unaliased_agg_func_field_reference_accepted() {
        // Codegen (NAN-1339) accepts `avg_bytes_in` as a reference to
        // un-aliased `avg(bytes_in)` for stats/chart/timechart/eventstats —
        // validation must too, under both profiles identically.
        let ocsf = crate::schema::OcsfProfile::new();
        let udm = crate::schema::UdmProfile::new();
        for q in [
            "* | stats avg(bytes_in) by dest_port | sort -avg_bytes_in",
            "* | chart avg(bytes_in) by dest_port | sort -avg_bytes_in",
            "* | chart avg(bytes_in) over dest_port | sort -avg_bytes_in",
            "* | timechart span=1h avg(bytes_in) | sort -avg_bytes_in",
            "* | eventstats avg(bytes_in) | where avg_bytes_in > 100",
            "* | stats sum(bytes_out) by src_ip | where sum_bytes_out > 0 | table src_ip, sum_bytes_out",
        ] {
            let query = parse_query(q).unwrap_or_else(|e| panic!("parse {q}: {e}"));
            let errors = validate_query_fields(&query);
            assert_eq!(
                errors.len(),
                0,
                "{{func}}_{{field}} reference must pass: {q} -> {errors:?}"
            );
            for profile in [
                &ocsf as &dyn crate::schema::SchemaProfile,
                &udm as &dyn crate::schema::SchemaProfile,
            ] {
                let errors = validate_query_fields_with_profile(&query, Some(profile));
                assert_eq!(
                    errors.len(),
                    0,
                    "{{func}}_{{field}} reference must pass under {:?}: {q} -> {errors:?}",
                    profile.id()
                );
            }
        }
    }

    #[test]
    fn test_streamstats_func_field_reference_still_rejected() {
        // The codegen remap doesn't cover streamstats, so the validator must
        // not accept the reference form there (it would only unmask a later
        // codegen failure).
        let query = parse_query("* | streamstats avg(bytes_in) | sort -avg_bytes_in").unwrap();
        let errors = validate_query_fields(&query);
        assert_eq!(errors.len(), 1, "expected typo rejection: {errors:?}");
        assert_eq!(errors[0].field_name, "avg_bytes_in");
    }

    // --- NAN-1396 Bug B: lookup OUTPUT names are not event-field references ---

    #[test]
    fn test_lookup_output_fields_not_typo_gated() {
        // `confidence` sits 3 edits from `ai_confidence` (threshold for a
        // 10-char name is 3) and was rejected as a typo even though it's a
        // lookup-table column, not an event-field reference.
        let ocsf = crate::schema::OcsfProfile::new();
        let udm = crate::schema::UdmProfile::new();
        for q in [
            "* | lookup threats src_ip OUTPUT threat_type, confidence | where isnotnull(confidence)",
            "* | lookup threats src_ip OUTPUT confidence | where isnotnull(confidence)",
        ] {
            let query = parse_query(q).unwrap_or_else(|e| panic!("parse {q}: {e}"));
            let errors = validate_query_fields(&query);
            assert_eq!(
                errors.len(),
                0,
                "lookup OUTPUT names must not be typo-gated: {q} -> {errors:?}"
            );
            for profile in [
                &ocsf as &dyn crate::schema::SchemaProfile,
                &udm as &dyn crate::schema::SchemaProfile,
            ] {
                let errors = validate_query_fields_with_profile(&query, Some(profile));
                assert_eq!(
                    errors.len(),
                    0,
                    "lookup OUTPUT must pass under {:?}: {q} -> {errors:?}",
                    profile.id()
                );
            }
        }
    }

    #[test]
    fn test_lookup_output_fields_still_format_gated() {
        // The safe-format gate stays: OUTPUT names are interpolated into the
        // lookup SQL (the repository re-validates, this is the input-side guard).
        let query = parse_query(r#"* | lookup threats src_ip OUTPUT "a;DROP""#).unwrap();
        let errors = validate_query_fields(&query);
        assert!(
            !errors.is_empty(),
            "format-invalid lookup OUTPUT name must be rejected"
        );
    }

    #[test]
    fn test_rex_capture_name_injection_rejected() {
        // NAN-1992: a rex capture-group name that isn't a plain identifier
        // (comma/parens — a SQL-injection attempt) is rejected at validation,
        // aligning rex with every other identifier slot. `escape_identifier`
        // also neutralizes it at the sink; this is the parse-time defense layer.
        for q in [
            r#"* | rex field=message "(?<a,version()/**/v>\w+)""#,
            r#"* | rex field=message "(?P<a,(SELECT/**/1)/**/x>\w+)""#,
        ] {
            let query = parse_query(q).unwrap_or_else(|e| panic!("parse {q}: {e}"));
            assert!(
                !validate_query_fields(&query).is_empty(),
                "injection rex capture name must be rejected: {q}"
            );
        }
        // Legit capture names (both PCRE forms) still validate cleanly.
        let query =
            parse_query(r#"* | rex field=message "(?<user>\w+)@(?P<domain>\w+\.\w+)""#).unwrap();
        assert_eq!(
            validate_query_fields(&query).len(),
            0,
            "legit rex capture names must not be rejected"
        );
    }

    #[test]
    fn test_lookup_key_field_still_typo_gated() {
        // The key field IS an event-field reference — the typo gate stays.
        let query = parse_query("* | lookup threats src_ipp OUTPUT threat_type").unwrap();
        let errors = validate_query_fields(&query);
        assert_eq!(errors.len(), 1);
        assert_eq!(errors[0].field_name, "src_ipp");
    }

    // --- NAN-1422: flat operational aliases pass under the OCSF profile ---

    #[test]
    fn test_flat_operational_aliases_pass_under_ocsf_profile() {
        // `sourcetype` sits one edit from `source_type` so the UDM-distance typo
        // gate rejects it unless the active profile claims it. OCSF now
        // canonicalizes the flat alias to its operational column (NAN-1422), so
        // the G5 profile gate must accept it — on the search term and in
        // pipeline positions.
        let ocsf = crate::schema::OcsfProfile::new();
        for q in [
            r#"sourcetype="windows_sysmon""#,
            r#"* | where sourcetype="windows_sysmon""#,
            "* | stats count() by sourcetype",
            "* | table sourcetype",
        ] {
            let query = parse_query(q).unwrap_or_else(|e| panic!("parse {q}: {e}"));
            let errors = validate_query_fields_with_profile(&query, Some(&ocsf));
            assert_eq!(
                errors.len(),
                0,
                "flat operational alias must pass under the OCSF profile: {q} -> {errors:?}"
            );
        }
    }

    #[test]
    fn test_gated_alias_without_ocsf_target_still_rejected_under_ocsf() {
        // `username` normalizes to `user`, which is NOT a physical ocsf_logs
        // column — the canonicalize gate must refuse the rewrite, leaving the
        // alias subject to the same typo rejection as today (and as UDM).
        let ocsf = crate::schema::OcsfProfile::new();
        let query = parse_query(r#"username="admin""#).unwrap();
        let errors = validate_query_fields_with_profile(&query, Some(&ocsf));
        assert_eq!(errors.len(), 1, "gated alias must stay rejected: {errors:?}");
        assert_eq!(errors[0].field_name, "username");
    }

    // --- NAN-1425: the explicit alias set passes under the UDM profile ---

    /// Every `normalize_field_name` alias whose target is a physical explicit
    /// column of `logs` — pinned alias-by-alias (NAN-1425). `source_ip` is
    /// deliberately absent: it is a pinned typo case and the NAN-1380 G5 gate
    /// takes precedence over the alias map (see
    /// `test_pinned_typo_alias_source_ip_still_rejected_under_udm`).
    const UDM_ACCEPTED_ALIASES: &[(&str, &str)] = &[
        ("_time", "timestamp"),
        ("sourcetype", "source_type"),
        ("dest_hostname", "dest_host"),
        ("src_hostname", "src_host"),
        ("username", "user"),
        ("destination_ip", "dest_ip"),
        ("src_address", "src_ip"),
        ("dest_address", "dest_ip"),
        ("source_port", "src_port"),
        ("destination_port", "dest_port"),
        ("source_mac", "src_mac"),
        ("destination_mac", "dest_mac"),
        ("process", "command_line"),
        ("parent_process", "parent_command_line"),
        ("uri", "url"),
        ("referer", "http_referrer"),
        ("referrer", "http_referrer"),
        ("useragent", "http_user_agent"),
        ("filename", "file_name"),
        ("filepath", "file_path"),
        ("outcome", "status"),
        ("response_code", "http_status_code"),
        ("http_status", "http_status_code"),
        ("http_response_code", "http_status_code"),
        ("resp_code", "http_status_code"),
        ("request_method", "http_method"),
        ("method", "http_method"),
        ("dns_query", "query"),
        ("dns_response", "answer"),
        ("dns_answer", "answer"),
        ("cloud.provider", "cloud_provider"),
        ("cloud.account.id", "cloud_account_id"),
        ("cloud.account.name", "cloud_account_name"),
        ("cloud.region", "cloud_region"),
        ("cloud.service.name", "cloud_service"),
        ("service_name", "cloud_service"),
        ("event_id", "signature_id"),
        ("eventid", "signature_id"),
    ];

    #[test]
    fn test_explicit_alias_set_passes_under_udm_profile() {
        // The whole explicit alias set (every normalize_field_name entry whose
        // target is a UDM explicit column) must pass the input-side validator
        // under the UDM profile (NAN-1425) — previously the G5 typo gate
        // 400-rejected the near-miss-shaped ones (`sourcetype`, `_time`,
        // `username`, `filepath`, `cloud.provider`, …) on the RAW spelling
        // before alias canonicalization ever ran, even though codegen
        // normalized them fine.
        let udm = crate::schema::UdmProfile::new();
        for (alias, target) in UDM_ACCEPTED_ALIASES {
            let q = format!(r#"{alias}="x""#);
            let query = parse_query(&q).unwrap_or_else(|e| panic!("parse {q}: {e}"));
            let errors = validate_query_fields_with_profile(&query, Some(&udm));
            assert_eq!(
                errors.len(),
                0,
                "alias {alias} (→ {target}) must pass under the UDM profile: {errors:?}"
            );
        }
    }

    #[test]
    fn test_alias_passes_in_pipeline_positions_under_udm_profile() {
        // Same gate fires in pipeline positions — pin the representative
        // alias (`sourcetype`, the NAN-1425 report) across where/stats/table
        // and the IN-list seam.
        let udm = crate::schema::UdmProfile::new();
        for q in [
            r#"sourcetype="windows_sysmon""#,
            r#"* | where sourcetype="windows_sysmon""#,
            "* | stats count() by sourcetype",
            "* | table sourcetype",
            r#"sourcetype IN ("windows_sysmon", "conduit_proxy")"#,
            r#"_time="2024-01-01""#,
        ] {
            let query = parse_query(q).unwrap_or_else(|e| panic!("parse {q}: {e}"));
            let errors = validate_query_fields_with_profile(&query, Some(&udm));
            assert_eq!(
                errors.len(),
                0,
                "alias must pass under the UDM profile: {q} -> {errors:?}"
            );
        }
    }

    #[test]
    fn test_pinned_typo_alias_source_ip_still_rejected_under_udm() {
        // COLLISION (recorded on NAN-1425): normalize_field_name DOES map
        // `source_ip` → `src_ip`, but the typo gate's rejection of `source_ip`
        // is pinned behavior (test_typos_still_rejected_under_both_profiles,
        // test_udm_profile_matches_profile_blind_behavior) and takes
        // precedence over the alias map — the profile must NOT claim it.
        let udm = crate::schema::UdmProfile::new();
        let query = parse_query(r#"source_ip="1.2.3.4""#).unwrap();
        let errors = validate_query_fields_with_profile(&query, Some(&udm));
        assert_eq!(
            errors.len(),
            1,
            "pinned typo case source_ip must stay rejected: {errors:?}"
        );
        assert_eq!(errors[0].field_name, "source_ip");
        assert!(
            errors[0].suggestions.contains(&"src_ip".to_string()),
            "did-you-mean must still suggest src_ip: {:?}",
            errors[0].suggestions
        );
    }

    #[test]
    fn test_aliases_without_explicit_target_unchanged_under_udm() {
        // `hostname` → `host` and `destination` → `dest` have no explicit
        // `logs` column as target, so the profile's gated alias authority
        // refuses the rewrite (mirroring NAN-1422's `hostname` pin on OCSF).
        // They are far from every UDM name, so the distance gate lets them
        // through as potential ext fields — exactly the pre-NAN-1425 outcome.
        let udm = crate::schema::UdmProfile::new();
        for q in [r#"hostname="web-01""#, r#"destination="db-01""#] {
            let query = parse_query(q).unwrap_or_else(|e| panic!("parse {q}: {e}"));
            let errors = validate_query_fields_with_profile(&query, Some(&udm));
            assert_eq!(
                errors.len(),
                0,
                "non-rewriting alias must keep passing (as ext): {q} -> {errors:?}"
            );
        }
    }

    #[test]
    fn test_quoted_output_alias_not_format_checked() {
        // Output aliases (eval/rename `to`/spath `output`) are owned by codegen
        // escaping (NAN-1352), not format-validated here. A spaced quoted alias
        // plus a downstream reference to it (derived) must both pass.
        let query = parse_query(r#"* | eval "p95 latency"=1 | where "p95 latency" > 0"#).unwrap();
        let errors = validate_query_fields(&query);
        assert_eq!(
            errors.len(),
            0,
            "quoted output alias + downstream derived ref must pass: {:?}",
            errors
        );
    }

    #[test]
    fn nan2331_arithmetic_where_accepts_upstream_stats_aliases() {
        let query = parse_query(
            "* | stats min(timestamp) as first_seen, max(timestamp) as last_seen, \
             count() as event_count by user | where event_count > 5 AND \
             (last_seen - first_seen) >= 300",
        )
        .unwrap();
        let errors = validate_query_fields(&query);

        assert!(
            errors.is_empty(),
            "stats aliases referenced by arithmetic where must validate: {errors:?}"
        );
    }
}
