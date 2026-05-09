// SPDX-License-Identifier: AGPL-3.0-or-later

//! Search expression → WHERE clause generation
//!
//! Converts `SearchExpr` AST nodes into ClickHouse WHERE clause SQL,
//! handling UDM fields, JSON metadata fields, wildcards, regex, and
//! case-insensitive matching.

use super::eval_functions::eval_expression_to_sql;
use super::helpers::*;
use super::{
    ClickHouseSqlGenerator, LOWERCASE_NORMALIZED_FIELDS, NUMERIC_UDM_FIELDS, SUBSEARCH_RESULT_LIMIT,
    UUID_FIELDS,
};
use crate::query::ast::*;
use crate::query::sql_gen::SqlGenError;

/// Build optimized SQL for a regex match against a field expression.
///
/// Applies optimizations in priority order:
/// 1. Simple literal (no metacharacters) → hasToken() (already handled by extract_simple_regex_token)
/// 2. Anchored prefix `^literal.*` → startsWith(lower(field), 'literal')
/// 3. Anchored suffix `.*literal$` → endsWith(lower(field), '.exe')
/// 4. Pure literal alternation `(a|b|c)` → hasToken OR chain
/// 5. Bloom guard: longest literal → hasToken(field, 'token') AND match(field, pattern)
/// 6. Fallback: plain match(field, pattern)
///
/// `field_expr`: the SQL expression for the field (e.g., `"command_line"`, `toString(ext.foo)`)
/// `is_message`: true if field is `message` (uses `lower(message)` for hasToken)
/// `negated`: true for NotRegex (inverts the result)
fn build_optimized_regex_sql(
    field_expr: &str,
    pattern: &str,
    is_message: bool,
    negated: bool,
) -> String {
    let escaped = escape_regex_pattern(pattern);
    let ci_pattern = if escaped.starts_with("(?i)") {
        format!("'{}'", escaped)
    } else {
        format!("'(?i){}'", escaped)
    };

    // Try optimizations on the raw pattern (before escaping for SQL)
    if let Some(opt) = analyze_regex_for_optimization(pattern) {
        match opt {
            RegexOptimization::Prefix(prefix) => {
                let escaped_prefix = escape_string(&prefix);
                return if negated {
                    format!(
                        "NOT startsWith(lower({}), '{}')",
                        field_expr, escaped_prefix
                    )
                } else {
                    format!("startsWith(lower({}), '{}')", field_expr, escaped_prefix)
                };
            }
            RegexOptimization::Suffix(suffix) => {
                let escaped_suffix = escape_string(&suffix);
                return if negated {
                    format!("NOT endsWith(lower({}), '{}')", field_expr, escaped_suffix)
                } else {
                    format!("endsWith(lower({}), '{}')", field_expr, escaped_suffix)
                };
            }
            RegexOptimization::LiteralAlternation(literals) => {
                let conditions: Vec<String> = literals
                    .iter()
                    .map(|lit| {
                        let escaped_lit = escape_string(lit);
                        if is_message {
                            format!("hasToken(lower(message), '{}')", escaped_lit)
                        } else {
                            format!(
                                "hasTokenCaseInsensitive(toString({}), '{}')",
                                field_expr, escaped_lit
                            )
                        }
                    })
                    .collect();
                let joined = conditions.join(" OR ");
                return if negated {
                    format!("NOT ({})", joined)
                } else if conditions.len() > 1 {
                    format!("({})", joined)
                } else {
                    joined
                };
            }
            RegexOptimization::BloomGuard(token) => {
                let escaped_token = escape_string(&token);
                let guard = if is_message {
                    format!("hasToken(lower(message), '{}')", escaped_token)
                } else {
                    format!(
                        "hasTokenCaseInsensitive(toString({}), '{}')",
                        field_expr, escaped_token
                    )
                };
                // For negated: NOT (guard AND match) → we can't short-circuit, just negate the match
                // The bloom filter wouldn't help for NOT match anyway (need to scan all)
                if negated {
                    return format!("match({}, {}) = 0", field_expr, ci_pattern);
                }
                return format!("{} AND match({}, {})", guard, field_expr, ci_pattern);
            }
        }
    }

    // No optimization possible — plain regex
    if negated {
        format!("match({}, {}) = 0", field_expr, ci_pattern)
    } else {
        format!("match({}, {})", field_expr, ci_pattern)
    }
}

impl ClickHouseSqlGenerator {
    /// Generate SQL for a search expression (WHERE clause content)
    pub fn generate_search_expr(&self, expr: &SearchExpr) -> Result<String, SqlGenError> {
        match expr {
            SearchExpr::Keyword(kw) => {
                // Handle wildcard * as match-all
                if kw == "*" {
                    return Ok("1".to_string());
                }

                let escaped = escape_string(&kw.to_lowercase());

                // For SIEM use cases, we need substring matching (e.g., "cmd.exe", "192.168")
                // But we also want to leverage the bloom filter index for performance.
                //
                // Strategy: Use multiSearchAny with the bloom filter for pre-filtering,
                // combined with position() for exact substring verification.
                //
                // The tokenbf_v1 index will help skip blocks that definitely don't contain
                // hasToken() only works for pure alphanumeric words - it tokenizes on
                // separators like dots, slashes, underscores. For searches containing these
                // special chars (IPs, file paths, etc.), we use LIKE which leverages the
                // ngrambf_v1 index for acceleration.
                //
                // Both the text index (for hasToken) and ngrambf_v1 (for LIKE) are used.

                let has_special_chars = kw.chars().any(|c| !c.is_alphanumeric());

                if has_special_chars {
                    // Keywords with special chars (IPs, domains, file paths) need iLike
                    // for exact substring matching. But iLike alone bypasses the bloom
                    // index, causing full scans (32s for a bare IP over 4h).
                    //
                    // Bloom guard: extract the longest alphanumeric token and prepend
                    // a hasToken() check. The bloom index skips 90%+ of granules,
                    // then iLike verifies on the small remainder. Same results, no
                    // false positives, massive speedup.
                    let ilike_pattern = escaped
                        .to_lowercase()
                        .replace('%', "\\%")
                        .replace('_', "\\_");
                    let ilike_clause =
                        format!("lower(message) iLike '%{}%'", ilike_pattern);

                    // Find the longest alphanumeric token for the bloom guard
                    let longest_token = kw
                        .split(|c: char| !c.is_alphanumeric())
                        .filter(|t| !t.is_empty())
                        .max_by_key(|t| t.len());

                    if let Some(token) = longest_token {
                        if token.len() >= 3 {
                            // Guard with hasToken for index acceleration
                            let guard_token = escape_string(&token.to_lowercase());
                            Ok(format!(
                                "hasToken(lower(message), '{}') AND {}",
                                guard_token, ilike_clause
                            ))
                        } else {
                            // Token too short (e.g., "a.b") — bloom filter would match
                            // too many granules, just use iLike alone
                            Ok(ilike_clause)
                        }
                    } else {
                        Ok(ilike_clause)
                    }
                } else {
                    // Pure alphanumeric word - use hasToken on lower(message) for text index acceleration
                    Ok(format!("hasToken(lower(message), '{}')", escaped))
                }
            }
            SearchExpr::FieldFilter { field, op, value } => {
                self.generate_field_filter(field, op, value)
            }
            SearchExpr::FunctionFilter {
                function,
                op,
                value,
            } => {
                let func_sql = eval_expression_to_sql(self, function)?;
                let sql_op = comparator_to_sql(op);
                // Case-insensitive string comparison for Eq/Ne
                match (op, value) {
                    (Comparator::Eq | Comparator::Ne, Value::String(s)) => Ok(format!(
                        "lower({}) {} '{}'",
                        func_sql,
                        sql_op,
                        escape_string(&s.to_lowercase())
                    )),
                    _ => {
                        let value_sql = value_to_sql(value);
                        Ok(format!("{} {} {}", func_sql, sql_op, value_sql))
                    }
                }
            }
            SearchExpr::BooleanFunction(function) => {
                // Standalone boolean function predicate: isnull(user), like(field, pattern), etc.
                eval_expression_to_sql(self, function)
            }
            SearchExpr::FieldFunctionFilter {
                field,
                op,
                function,
            } => {
                let field_sql = self.generate_json_extract(field, "String");
                let func_sql = eval_expression_to_sql(self, function)?;
                let sql_op = comparator_to_sql(op);
                // Case-insensitive comparison for Eq/Ne
                match op {
                    Comparator::Eq | Comparator::Ne => Ok(format!(
                        "lower({}) {} lower({})",
                        field_sql, sql_op, func_sql
                    )),
                    _ => Ok(format!("{} {} {}", field_sql, sql_op, func_sql)),
                }
            }
            SearchExpr::InList {
                field,
                values,
                negated,
            } => self.generate_in_list_filter(field, values, *negated),
            SearchExpr::And(left, right) => {
                let left_sql = self.generate_search_expr(left)?;
                let right_sql = self.generate_search_expr(right)?;
                Ok(format!("({} AND {})", left_sql, right_sql))
            }
            SearchExpr::Or(left, right) => {
                let left_sql = self.generate_search_expr(left)?;
                let right_sql = self.generate_search_expr(right)?;
                Ok(format!("({} OR {})", left_sql, right_sql))
            }
            SearchExpr::Not(inner) => {
                let inner_sql = self.generate_search_expr(inner)?;
                Ok(format!("NOT ({})", inner_sql))
            }
            SearchExpr::Group(inner) => {
                let inner_sql = self.generate_search_expr(inner)?;
                Ok(format!("({})", inner_sql))
            }
            SearchExpr::LiteralComparison { left, op, right } => {
                // Literal string comparison - e.g., "$user"="*"
                // These evaluate to a constant true/false at runtime
                // Use case-insensitive comparison for Eq/Ne with strings
                let op_sql = comparator_to_sql(op);
                match (op, right) {
                    (Comparator::Eq | Comparator::Ne, Value::String(s)) => Ok(format!(
                        "lower('{}') {} '{}'",
                        escape_string(left),
                        op_sql,
                        escape_string(&s.to_lowercase())
                    )),
                    _ => {
                        let left_sql = format!("'{}'", escape_string(left));
                        let right_sql = value_to_sql(right);
                        Ok(format!("{} {} {}", left_sql, op_sql, right_sql))
                    }
                }
            }
            SearchExpr::InSubsearch {
                field,
                subsearch,
                negated,
            } => self.generate_in_subsearch_filter(field, subsearch, *negated),
        }
    }

    /// Generate SQL for IN list filter (case-insensitive for strings)
    pub(super) fn generate_in_list_filter(
        &self,
        field: &str,
        values: &[Value],
        negated: bool,
    ) -> Result<String, SqlGenError> {
        let op = if negated { "NOT IN" } else { "IN" };

        // Check if all values are strings (for case-insensitive handling)
        let all_strings = values.iter().all(|v| matches!(v, Value::String(_)));

        if is_udm_field(field) {
            // Determine if this is an explicit column or a JSON field
            let field_expr = if super::is_explicit_column(field) {
                escape_identifier(field)
            } else {
                // Access via ext JSON column (extended fields)
                format!("ext.{}", field)
            };

            if UUID_FIELDS.contains(&field) {
                // UUID fields: use toString() instead of lower()
                let values_sql: Vec<String> = values
                    .iter()
                    .map(|v| match v {
                        Value::String(s) => format!("'{}'", escape_string(&s.to_lowercase())),
                        _ => value_to_sql_for_field(field, v),
                    })
                    .collect();
                let values_list = values_sql.join(", ");
                Ok(format!("toString({}) {} ({})", field_expr, op, values_list))
            } else if NUMERIC_UDM_FIELDS.contains(&field) {
                // Numeric fields: never apply lower() — convert string values to numbers
                let values_sql: Vec<String> = values
                    .iter()
                    .map(|v| match v {
                        Value::String(s) => {
                            if s.parse::<i64>().is_ok() || s.parse::<f64>().is_ok() {
                                s.to_string()
                            } else {
                                // Non-numeric string — use 0 as fallback (will never match)
                                "0".to_string()
                            }
                        }
                        _ => value_to_sql_for_field(field, v),
                    })
                    .collect();
                let values_list = values_sql.join(", ");
                Ok(format!("{} {} ({})", field_expr, op, values_list))
            } else if all_strings {
                // Case-insensitive: lower(field) IN ('val1', 'val2')
                let values_sql: Vec<String> = values
                    .iter()
                    .map(|v| match v {
                        Value::String(s) => format!("'{}'", escape_string(&s.to_lowercase())),
                        _ => value_to_sql_for_field(field, v),
                    })
                    .collect();
                let values_list = values_sql.join(", ");
                Ok(format!("lower({}) {} ({})", field_expr, op, values_list))
            } else {
                let values_sql: Vec<String> = values
                    .iter()
                    .map(|v| value_to_sql_for_field(field, v))
                    .collect();
                let values_list = values_sql.join(", ");
                Ok(format!("{} {} ({})", field_expr, op, values_list))
            }
        } else {
            // For metadata fields, use JSONExtractString
            let json_extract = self.generate_json_extract(field, "String");

            if all_strings {
                // Case-insensitive
                let values_sql: Vec<String> = values
                    .iter()
                    .map(|v| match v {
                        Value::String(s) => format!("'{}'", escape_string(&s.to_lowercase())),
                        _ => value_to_sql(v),
                    })
                    .collect();
                let values_list = values_sql.join(", ");
                Ok(format!("lower({}) {} ({})", json_extract, op, values_list))
            } else {
                let values_sql: Vec<String> = values.iter().map(value_to_sql).collect();
                let values_list = values_sql.join(", ");
                Ok(format!("{} {} ({})", json_extract, op, values_list))
            }
        }
    }

    /// Generate SQL for a field filter
    pub(super) fn generate_field_filter(
        &self,
        field: &str,
        op: &Comparator,
        value: &Value,
    ) -> Result<String, SqlGenError> {
        // SECURITY: Validate field name format to prevent injection of function calls
        // (e.g., "version()" or "currentDatabase()") through field name positions.
        crate::query::validation::validate_field_name_format(field)
            .map_err(|e| SqlGenError::InvalidQuery(e.message))?;

        // Validate regex patterns before generating SQL
        if let Value::Regex(pattern) = value {
            validate_regex_pattern(pattern).map_err(|e| SqlGenError::InvalidQuery(e))?;
        }

        // Normalize field name (apply aliases like sourcetype -> source_type)
        let field = normalize_field_name(field);

        // Check if it's a UDM field (direct column) or metadata field (JSON)
        if is_udm_field(field) {
            self.generate_udm_field_filter(field, op, value)
        } else {
            self.generate_json_field_filter(field, op, value)
        }
    }

    /// Generate SQL for UDM field filter (direct column or ext JSON access)
    ///
    /// In the hybrid schema:
    /// - Explicit columns are accessed directly (e.g., `src_ip = '1.2.3.4'`)
    /// - Other UDM fields are accessed via the ext JSON column (e.g., `ext.ssl_hash = 'abc'`)
    fn generate_udm_field_filter(
        &self,
        field: &str,
        op: &Comparator,
        value: &Value,
    ) -> Result<String, SqlGenError> {
        // Determine if this is an explicit column or a JSON field
        let field_expr = if super::is_explicit_column(field) {
            escape_identifier(field)
        } else {
            // Native JSON dot-notation: ext.field returns Dynamic, which works
            // for comparisons. Returns NULL for missing paths.
            format!("ext.{}", sanitize_json_path(field))
        };

        // Check if the value contains wildcards (* or ?) and we're using Eq/Ne
        if let Value::String(s) = value {
            if (s.contains('*') || s.contains('?')) && matches!(op, Comparator::Eq | Comparator::Ne)
            {
                // Special case: pure wildcard "*" means "match all" - just return true/false
                // This avoids generating useless "field LIKE '%'" which adds overhead
                if s == "*" {
                    return Ok(if *op == Comparator::Eq {
                        "1".to_string()
                    } else {
                        "0".to_string()
                    });
                }
                let pattern = wildcard_to_like_pattern(&s.to_lowercase());
                let sql_op = if *op == Comparator::Eq {
                    "iLike"
                } else {
                    "NOT iLike"
                };
                return Ok(format!("{} {} '{}'", field_expr, sql_op, pattern));
            }
        }

        let value_sql = match value {
            Value::Regex(pattern) => format!("'{}'", escape_regex_pattern(pattern)),
            _ => value_to_sql_for_field(field, value),
        };

        match op {
            Comparator::Regex => {
                // For simple patterns (no regex metacharacters), use hasToken for index acceleration
                if let Value::Regex(pattern) = value {
                    if let Some(token) = extract_simple_regex_token(pattern) {
                        if field == "message" {
                            return Ok(format!(
                                "hasToken(lower(message), '{}')",
                                escape_string(&token.to_lowercase())
                            ));
                        }
                        return Ok(format!(
                            "hasTokenCaseInsensitive(toString({}), '{}')",
                            field_expr,
                            escape_string(&token)
                        ));
                    }
                    // Complex regex — try bloom filter pre-filtering and pattern rewrites
                    return Ok(build_optimized_regex_sql(
                        &field_expr,
                        pattern,
                        field == "message",
                        false,
                    ));
                }
                Ok(format!("match({}, {})", field_expr, value_sql))
            }
            Comparator::NotRegex => {
                // For simple patterns, use NOT hasToken for index acceleration
                if let Value::Regex(pattern) = value {
                    if let Some(token) = extract_simple_regex_token(pattern) {
                        if field == "message" {
                            return Ok(format!(
                                "NOT hasToken(lower(message), '{}')",
                                escape_string(&token.to_lowercase())
                            ));
                        }
                        return Ok(format!(
                            "NOT hasTokenCaseInsensitive(toString({}), '{}')",
                            field_expr,
                            escape_string(&token)
                        ));
                    }
                    // Complex regex — try pattern rewrites (bloom guard not useful for negation)
                    return Ok(build_optimized_regex_sql(
                        &field_expr,
                        pattern,
                        field == "message",
                        true,
                    ));
                }
                // Use match() = 0 instead of NOT match() — ClickHouse optimizer
                // mishandles NOT match() when PREWHERE contains OR conditions.
                Ok(format!("match({}, {}) = 0", field_expr, value_sql))
            }
            Comparator::Like => {
                // Use iLike for case-insensitive matching
                Ok(format!("{} iLike {}", field_expr, value_sql))
            }
            Comparator::NotLike => Ok(format!("{} NOT iLike {}", field_expr, value_sql)),
            Comparator::Contains => {
                // Use hasToken for index acceleration on pure alphanumeric words,
                // iLike for values with separators (dots, slashes, etc.)
                if let Value::String(s) = value {
                    let has_separators = s.chars().any(|c| !c.is_alphanumeric());
                    if has_separators {
                        let escaped = escape_string(&s.to_lowercase())
                            .replace('%', "\\%")
                            .replace('_', "\\_");
                        Ok(format!("{} iLike '%{}%'", field_expr, escaped))
                    } else if field == "message" {
                        Ok(format!(
                            "hasToken(lower(message), '{}')",
                            escape_string(&s.to_lowercase())
                        ))
                    } else {
                        Ok(format!(
                            "hasTokenCaseInsensitive(toString({}), '{}')",
                            field_expr,
                            escape_string(&s.to_lowercase())
                        ))
                    }
                } else {
                    Ok(format!(
                        "{} iLike concat('%', {}, '%')",
                        field_expr, value_sql
                    ))
                }
            }
            Comparator::NotContains => {
                // Negated CONTAINS: NOT hasToken / NOT iLike
                if let Value::String(s) = value {
                    let has_separators = s.chars().any(|c| !c.is_alphanumeric());
                    if has_separators {
                        let escaped = escape_string(&s.to_lowercase())
                            .replace('%', "\\%")
                            .replace('_', "\\_");
                        Ok(format!("{} NOT iLike '%{}%'", field_expr, escaped))
                    } else if field == "message" {
                        Ok(format!(
                            "NOT hasToken(lower(message), '{}')",
                            escape_string(&s.to_lowercase())
                        ))
                    } else {
                        Ok(format!(
                            "NOT hasTokenCaseInsensitive(toString({}), '{}')",
                            field_expr,
                            escape_string(&s.to_lowercase())
                        ))
                    }
                } else {
                    Ok(format!(
                        "{} NOT iLike concat('%', {}, '%')",
                        field_expr, value_sql
                    ))
                }
            }
            Comparator::StartsWith => {
                let pattern = match value {
                    Value::String(s) => format!("'{}%'", escape_string(&s.to_lowercase())),
                    _ => format!("concat(lower({}), '%')", value_sql),
                };
                Ok(format!("{} iLike {}", field_expr, pattern))
            }
            Comparator::NotStartsWith => {
                let pattern = match value {
                    Value::String(s) => format!("'{}%'", escape_string(&s.to_lowercase())),
                    _ => format!("concat(lower({}), '%')", value_sql),
                };
                Ok(format!("{} NOT iLike {}", field_expr, pattern))
            }
            Comparator::EndsWith => {
                let pattern = match value {
                    Value::String(s) => format!("'%{}'", escape_string(&s.to_lowercase())),
                    _ => format!("concat('%', lower({}))", value_sql),
                };
                Ok(format!("{} iLike {}", field_expr, pattern))
            }
            Comparator::NotEndsWith => {
                let pattern = match value {
                    Value::String(s) => format!("'%{}'", escape_string(&s.to_lowercase())),
                    _ => format!("concat('%', lower({}))", value_sql),
                };
                Ok(format!("{} NOT iLike {}", field_expr, pattern))
            }
            Comparator::Eq | Comparator::Ne => {
                let sql_op = comparator_to_sql(op);

                // For numeric UDM fields, never apply lower() - compare as numbers
                if NUMERIC_UDM_FIELDS.contains(&field) {
                    match value {
                        Value::String(s) => {
                            // Convert string to number for comparison (handles drilldown from UI)
                            // Use toInt64OrZero for safe conversion of potentially non-numeric strings
                            if s.parse::<i64>().is_ok() {
                                Ok(format!("{} {} {}", field_expr, sql_op, s))
                            } else if s.parse::<f64>().is_ok() {
                                Ok(format!("{} {} {}", field_expr, sql_op, s))
                            } else {
                                // Non-numeric string on numeric field - use toString for comparison
                                Ok(format!(
                                    "toString({}) {} '{}'",
                                    field_expr,
                                    sql_op,
                                    escape_string(s)
                                ))
                            }
                        }
                        _ => Ok(format!("{} {} {}", field_expr, sql_op, value_sql)),
                    }
                } else if UUID_FIELDS.contains(&field) {
                    // UUID fields: compare via toString() — lower() doesn't work on UUID type
                    match value {
                        Value::String(s) => Ok(format!(
                            "toString({}) {} '{}'",
                            field_expr,
                            sql_op,
                            escape_string(&s.to_lowercase())
                        )),
                        _ => Ok(format!("{} {} {}", field_expr, sql_op, value_sql)),
                    }
                } else {
                    // Case-insensitive string comparison for text fields
                    match value {
                        Value::String(s) => {
                            let escaped_lower = escape_string(&s.to_lowercase());

                            // Hostname expansion: for src_host/dest_host without dots,
                            // match both exact and FQDN variants (e.g., "workstation" matches "workstation.corp.local")
                            let is_hostname_field = field == "src_host" || field == "dest_host";
                            let has_no_dot = !s.contains('.');

                            if is_hostname_field && has_no_dot && *op == Comparator::Eq {
                                // Expand: exact match OR starts with "value."
                                Ok(format!(
                                    "(lower({}) = '{}' OR startsWith(lower({}), '{}.'))",
                                    field_expr, escaped_lower, field_expr, escaped_lower
                                ))
                            } else if is_hostname_field && has_no_dot && *op == Comparator::Ne {
                                // Negated: NOT exact AND NOT starts with "value."
                                Ok(format!(
                                    "(lower({}) != '{}' AND NOT startsWith(lower({}), '{}.'))",
                                    field_expr, escaped_lower, field_expr, escaped_lower
                                ))
                            } else if LOWERCASE_NORMALIZED_FIELDS.contains(&field) {
                                // For fields normalized to lowercase at ingest, skip lower() wrapper
                                // This allows efficient index usage (set indexes, bloom filters)
                                Ok(format!("{} {} '{}'", field_expr, sql_op, escaped_lower))
                            } else {
                                Ok(format!(
                                    "lower({}) {} '{}'",
                                    field_expr, sql_op, escaped_lower
                                ))
                            }
                        }
                        _ => Ok(format!("{} {} {}", field_expr, sql_op, value_sql)),
                    }
                }
            }
            _ => {
                // Numeric comparisons (Gt, Lt, Gte, Lte) - no case handling needed
                let sql_op = comparator_to_sql(op);
                Ok(format!("{} {} {}", field_expr, sql_op, value_sql))
            }
        }
    }

    /// Generate SQL for extended/metadata field filter
    ///
    /// By default, searches the `ext` JSON column where parser-defined queryable fields live.
    /// Use `metadata_field` or `metadata.field` prefix to search the metadata column instead.
    fn generate_json_field_filter(
        &self,
        field: &str,
        op: &Comparator,
        value: &Value,
    ) -> Result<String, SqlGenError> {
        // Check for explicit metadata column targeting via prefix
        let (use_metadata, field_path) = if let Some(stripped) = field.strip_prefix("metadata_") {
            (true, stripped.to_string())
        } else if let Some(stripped) = field.strip_prefix("metadata.") {
            (true, stripped.to_string())
        } else {
            (false, field.to_string())
        };

        // Generate field expression: ext.field or JSONExtract for metadata
        let field_expr = if use_metadata {
            // Use JSONExtract for metadata column access
            let json_type = match value {
                Value::Number(_) => "Float64",
                Value::Bool(_) => "Bool",
                _ => "String",
            };
            self.generate_json_extract(&field_path, json_type)
        } else {
            // Native JSON dot-notation for ext field access
            format!("ext.{}", sanitize_json_path(&field_path))
        };

        // Check if the value contains wildcards (* or ?) and we're using Eq/Ne
        if let Value::String(s) = value {
            if (s.contains('*') || s.contains('?')) && matches!(op, Comparator::Eq | Comparator::Ne)
            {
                // Special case: pure wildcard "*" means "match all" - just return true/false
                // This avoids generating useless "field LIKE '%'" which adds overhead
                if s == "*" {
                    return Ok(if *op == Comparator::Eq {
                        "1".to_string()
                    } else {
                        "0".to_string()
                    });
                }
                let pattern = wildcard_to_like_pattern(&s.to_lowercase());
                let sql_op = if *op == Comparator::Eq {
                    "iLike"
                } else {
                    "NOT iLike"
                };
                return Ok(format!("{} {} '{}'", field_expr, sql_op, pattern));
            }
        }

        match op {
            Comparator::Regex => {
                // For simple patterns (no regex metacharacters), use hasTokenCaseInsensitive()
                if let Value::Regex(pattern) = value {
                    if let Some(token) = extract_simple_regex_token(pattern) {
                        return Ok(format!(
                            "hasTokenCaseInsensitive(toString({}), '{}')",
                            field_expr,
                            escape_string(&token)
                        ));
                    }
                    // Complex regex — try bloom filter pre-filtering and pattern rewrites
                    return Ok(build_optimized_regex_sql(
                        &field_expr,
                        pattern,
                        false,
                        false,
                    ));
                }
                Ok(format!("match({}, {})", field_expr, value_to_sql(value)))
            }
            Comparator::NotRegex => {
                // For simple patterns, use NOT hasTokenCaseInsensitive()
                if let Value::Regex(pattern) = value {
                    if let Some(token) = extract_simple_regex_token(pattern) {
                        return Ok(format!(
                            "NOT hasTokenCaseInsensitive(toString({}), '{}')",
                            field_expr,
                            escape_string(&token)
                        ));
                    }
                    // Complex regex — try pattern rewrites
                    return Ok(build_optimized_regex_sql(&field_expr, pattern, false, true));
                }
                Ok(format!(
                    "match({}, {}) = 0",
                    field_expr,
                    value_to_sql(value)
                ))
            }
            Comparator::Like => Ok(format!("{} iLike {}", field_expr, value_to_sql(value))),
            Comparator::NotLike => Ok(format!("{} NOT iLike {}", field_expr, value_to_sql(value))),
            Comparator::Contains => {
                if let Value::String(s) = value {
                    let has_separators = s.chars().any(|c| !c.is_alphanumeric());
                    if has_separators {
                        let escaped = escape_string(&s.to_lowercase())
                            .replace('%', "\\%")
                            .replace('_', "\\_");
                        Ok(format!("{} iLike '%{}%'", field_expr, escaped))
                    } else {
                        Ok(format!(
                            "hasTokenCaseInsensitive(toString({}), '{}')",
                            field_expr,
                            escape_string(&s.to_lowercase())
                        ))
                    }
                } else {
                    Ok(format!(
                        "{} iLike concat('%', {}, '%')",
                        field_expr,
                        value_to_sql(value)
                    ))
                }
            }
            Comparator::NotContains => {
                if let Value::String(s) = value {
                    let has_separators = s.chars().any(|c| !c.is_alphanumeric());
                    if has_separators {
                        let escaped = escape_string(&s.to_lowercase())
                            .replace('%', "\\%")
                            .replace('_', "\\_");
                        Ok(format!("{} NOT iLike '%{}%'", field_expr, escaped))
                    } else {
                        Ok(format!(
                            "NOT hasTokenCaseInsensitive(toString({}), '{}')",
                            field_expr,
                            escape_string(&s.to_lowercase())
                        ))
                    }
                } else {
                    Ok(format!(
                        "{} NOT iLike concat('%', {}, '%')",
                        field_expr,
                        value_to_sql(value)
                    ))
                }
            }
            Comparator::StartsWith => {
                let pattern = match value {
                    Value::String(s) => format!("'{}%'", escape_string(&s.to_lowercase())),
                    _ => format!("concat(lower({}), '%')", value_to_sql(value)),
                };
                Ok(format!("{} iLike {}", field_expr, pattern))
            }
            Comparator::NotStartsWith => {
                let pattern = match value {
                    Value::String(s) => format!("'{}%'", escape_string(&s.to_lowercase())),
                    _ => format!("concat(lower({}), '%')", value_to_sql(value)),
                };
                Ok(format!("{} NOT iLike {}", field_expr, pattern))
            }
            Comparator::EndsWith => {
                let pattern = match value {
                    Value::String(s) => format!("'%{}'", escape_string(&s.to_lowercase())),
                    _ => format!("concat('%', lower({}))", value_to_sql(value)),
                };
                Ok(format!("{} iLike {}", field_expr, pattern))
            }
            Comparator::NotEndsWith => {
                let pattern = match value {
                    Value::String(s) => format!("'%{}'", escape_string(&s.to_lowercase())),
                    _ => format!("concat('%', lower({}))", value_to_sql(value)),
                };
                Ok(format!("{} NOT iLike {}", field_expr, pattern))
            }
            Comparator::Eq | Comparator::Ne => {
                // Case-insensitive string comparison
                let sql_op = comparator_to_sql(op);
                match value {
                    Value::String(s) => Ok(format!(
                        "lower({}) {} '{}'",
                        field_expr,
                        sql_op,
                        escape_string(&s.to_lowercase())
                    )),
                    _ => Ok(format!("{} {} {}", field_expr, sql_op, value_to_sql(value))),
                }
            }
            _ => {
                // Numeric comparisons
                let sql_op = comparator_to_sql(op);
                Ok(format!("{} {} {}", field_expr, sql_op, value_to_sql(value)))
            }
        }
    }

    /// Generate ClickHouse JSONExtract expression for metadata field access
    ///
    /// Handles:
    /// - Simple fields: metadata_field -> JSONExtractString(metadata, 'field')
    /// - Nested fields: a.b.c -> JSONExtractString(metadata, 'a', 'b', 'c')
    /// - Type-specific extraction: JSONExtractString, JSONExtractInt, JSONExtractFloat, JSONExtractBool
    pub fn generate_json_extract(&self, field: &str, json_type: &str) -> String {
        // Handle metadata_ prefix: metadata_endpoint -> JSONExtract(metadata, 'endpoint')
        let field_path = if let Some(stripped) = field.strip_prefix("metadata_") {
            stripped.to_string()
        } else {
            field.to_string()
        };

        // Handle dot notation for nested paths
        let parts: Vec<&str> = field_path.split('.').collect();
        let path_args: Vec<String> = parts
            .iter()
            .map(|p| format!("'{}'", escape_string(p)))
            .collect();

        format!(
            "JSONExtract{}(metadata, {})",
            json_type,
            path_args.join(", ")
        )
    }

    /// Generate ClickHouse time bucket expression
    ///
    /// Maps span durations to ClickHouse time functions:
    /// - < 60s: toStartOfSecond or toStartOfInterval
    /// - 60s: toStartOfMinute
    /// - 300s (5m): toStartOfFiveMinutes
    /// - 600s (10m): toStartOfTenMinutes
    /// - 900s (15m): toStartOfFifteenMinutes
    /// - 3600s (1h): toStartOfHour
    /// - 86400s (1d): toStartOfDay
    /// - 604800s (1w): toStartOfWeek
    /// - 2592000s (30d): toStartOfMonth
    pub fn generate_time_bucket(&self, span: &std::time::Duration) -> String {
        let secs = span.as_secs();

        match secs {
            s if s < 60 => {
                // Use toStartOfInterval for sub-minute intervals
                format!("toStartOfInterval(timestamp, INTERVAL {} SECOND)", s)
            }
            60 => "toStartOfMinute(timestamp)".to_string(),
            300 => "toStartOfFiveMinutes(timestamp)".to_string(),
            600 => "toStartOfTenMinutes(timestamp)".to_string(),
            900 => "toStartOfFifteenMinutes(timestamp)".to_string(),
            3600 => "toStartOfHour(timestamp)".to_string(),
            86400 => "toStartOfDay(timestamp)".to_string(),
            604800 => "toStartOfWeek(timestamp)".to_string(),
            s if s >= 2592000 => "toStartOfMonth(timestamp)".to_string(),
            _ => {
                // For non-standard intervals, use toStartOfInterval
                if secs % 3600 == 0 {
                    format!(
                        "toStartOfInterval(timestamp, INTERVAL {} HOUR)",
                        secs / 3600
                    )
                } else if secs % 60 == 0 {
                    format!(
                        "toStartOfInterval(timestamp, INTERVAL {} MINUTE)",
                        secs / 60
                    )
                } else {
                    format!("toStartOfInterval(timestamp, INTERVAL {} SECOND)", secs)
                }
            }
        }
    }

    /// Generate SQL for a WHERE condition in piped commands (after stats, etc.)
    /// This treats all fields as direct column references, not JSON metadata
    pub(super) fn generate_where_condition(
        &self,
        expr: &SearchExpr,
    ) -> Result<String, SqlGenError> {
        match expr {
            SearchExpr::Keyword(kw) => {
                if kw == "*" {
                    return Ok("1".to_string());
                }
                // In piped commands (search, where), keywords are text searches on message.
                // Note: after stats/timechart where message doesn't exist, ClickHouse will
                // return a clear "column not found" error — which is correct behavior since
                // bare keyword searches don't make sense after aggregation.
                let escaped = escape_string(&kw.to_lowercase());
                Ok(format!("position(lower(message), '{}') > 0", escaped))
            }
            SearchExpr::FieldFilter { field, op, value } => {
                // Normalize field name (apply aliases like command_line -> process)
                let field = normalize_field_name(field);
                // Check if field is an aggregation expression like "avg(bytes_out)"
                // If so, extract the function name to use as the column reference
                let column_ref = if field.contains('(') && field.contains(')') {
                    // Only allow known aggregation function names as column refs
                    if let Some(func_end) = field.find('(') {
                        let func_name = &field[..func_end];
                        match func_name.to_lowercase().as_str() {
                            "count" | "sum" | "avg" | "min" | "max" | "dc" | "values" | "first"
                            | "last" | "stdev" | "stdevp" | "var" | "varp" | "median" | "perc"
                            | "list" | "earliest" | "latest" | "rate" | "per_second"
                            | "per_minute" | "per_hour" => escape_identifier(func_name),
                            _ => {
                                return Err(SqlGenError::InvalidQuery(format!(
                                    "Invalid field name '{}': contains parentheses. Field names may only contain letters, digits, underscores, and dots.",
                                    field
                                )));
                            }
                        }
                    } else {
                        escape_identifier(field)
                    }
                } else {
                    // SECURITY: Validate field name format for regular fields
                    crate::query::validation::validate_field_name_format(field)
                        .map_err(|e| SqlGenError::InvalidQuery(e.message))?;
                    escape_identifier(field)
                };

                // Always treat as direct column reference
                let value_sql = match value {
                    Value::Regex(pattern) => format!("'{}'", escape_regex_pattern(pattern)),
                    _ => value_to_sql(value),
                };

                match op {
                    Comparator::Regex => {
                        // For simple patterns, use hasTokenCaseInsensitive() for better performance
                        if let Value::Regex(pattern) = value {
                            if let Some(token) = extract_simple_regex_token(pattern) {
                                return Ok(format!(
                                    "hasTokenCaseInsensitive(toString({}), '{}')",
                                    column_ref,
                                    escape_string(&token)
                                ));
                            }
                            // Complex regex — try bloom filter pre-filtering and pattern rewrites
                            let col_str = format!("toString({})", column_ref);
                            return Ok(build_optimized_regex_sql(&col_str, pattern, false, false));
                        }
                        Ok(format!("match(toString({}), {})", column_ref, value_sql))
                    }
                    Comparator::NotRegex => {
                        // For simple patterns, use NOT hasTokenCaseInsensitive()
                        if let Value::Regex(pattern) = value {
                            if let Some(token) = extract_simple_regex_token(pattern) {
                                return Ok(format!(
                                    "NOT hasTokenCaseInsensitive(toString({}), '{}')",
                                    column_ref,
                                    escape_string(&token)
                                ));
                            }
                            // Complex regex — try pattern rewrites
                            let col_str = format!("toString({})", column_ref);
                            return Ok(build_optimized_regex_sql(&col_str, pattern, false, true));
                        }
                        Ok(format!(
                            "match(toString({}), {}) = 0",
                            column_ref, value_sql
                        ))
                    }
                    Comparator::Like => Ok(format!("toString({}) iLike {}", column_ref, value_sql)),
                    Comparator::NotLike => {
                        Ok(format!("toString({}) NOT iLike {}", column_ref, value_sql))
                    }
                    Comparator::Contains => {
                        if let Value::String(s) = value {
                            let has_separators = s.chars().any(|c| !c.is_alphanumeric());
                            if has_separators {
                                let escaped = escape_string(&s.to_lowercase())
                                    .replace('%', "\\%")
                                    .replace('_', "\\_");
                                Ok(format!("toString({}) iLike '%{}%'", column_ref, escaped))
                            } else {
                                Ok(format!(
                                    "hasTokenCaseInsensitive(toString({}), '{}')",
                                    column_ref,
                                    escape_string(&s.to_lowercase())
                                ))
                            }
                        } else {
                            Ok(format!(
                                "toString({}) iLike concat('%', {}, '%')",
                                column_ref, value_sql
                            ))
                        }
                    }
                    Comparator::NotContains => {
                        if let Value::String(s) = value {
                            let has_separators = s.chars().any(|c| !c.is_alphanumeric());
                            if has_separators {
                                let escaped = escape_string(&s.to_lowercase())
                                    .replace('%', "\\%")
                                    .replace('_', "\\_");
                                Ok(format!(
                                    "toString({}) NOT iLike '%{}%'",
                                    column_ref, escaped
                                ))
                            } else {
                                Ok(format!(
                                    "NOT hasTokenCaseInsensitive(toString({}), '{}')",
                                    column_ref,
                                    escape_string(&s.to_lowercase())
                                ))
                            }
                        } else {
                            Ok(format!(
                                "toString({}) NOT iLike concat('%', {}, '%')",
                                column_ref, value_sql
                            ))
                        }
                    }
                    Comparator::StartsWith => {
                        let pattern = match value {
                            Value::String(s) => format!("'{}%'", escape_string(&s.to_lowercase())),
                            _ => format!("concat(lower({}), '%')", value_sql),
                        };
                        Ok(format!("toString({}) iLike {}", column_ref, pattern))
                    }
                    Comparator::NotStartsWith => {
                        let pattern = match value {
                            Value::String(s) => format!("'{}%'", escape_string(&s.to_lowercase())),
                            _ => format!("concat(lower({}), '%')", value_sql),
                        };
                        Ok(format!("toString({}) NOT iLike {}", column_ref, pattern))
                    }
                    Comparator::EndsWith => {
                        let pattern = match value {
                            Value::String(s) => format!("'%{}'", escape_string(&s.to_lowercase())),
                            _ => format!("concat('%', lower({}))", value_sql),
                        };
                        Ok(format!("toString({}) iLike {}", column_ref, pattern))
                    }
                    Comparator::NotEndsWith => {
                        let pattern = match value {
                            Value::String(s) => format!("'%{}'", escape_string(&s.to_lowercase())),
                            _ => format!("concat('%', lower({}))", value_sql),
                        };
                        Ok(format!("toString({}) NOT iLike {}", column_ref, pattern))
                    }
                    Comparator::Eq | Comparator::Ne => {
                        // Case-insensitive string comparison
                        let sql_op = comparator_to_sql(op);
                        match value {
                            Value::String(s) => {
                                // Boolean coercion: "true"/"false" → 1/0 for boolean fields (is_*, has_*, *_enabled, *_supported)
                                let lower = s.to_lowercase();
                                if (lower == "true" || lower == "false") && is_boolean_field(field)
                                {
                                    let bool_val = if lower == "true" { 1 } else { 0 };
                                    return Ok(format!("{} {} {}", column_ref, sql_op, bool_val));
                                }
                                Ok(format!(
                                    "lower(toString({})) {} '{}'",
                                    column_ref,
                                    sql_op,
                                    escape_string(&lower)
                                ))
                            }
                            _ => Ok(format!("{} {} {}", column_ref, sql_op, value_sql)),
                        }
                    }
                    _ => {
                        // Numeric comparisons
                        let sql_op = comparator_to_sql(op);
                        Ok(format!("{} {} {}", column_ref, sql_op, value_sql))
                    }
                }
            }
            SearchExpr::InList {
                field,
                values,
                negated,
            } => {
                // Check if field is an aggregation expression
                let column_ref = if field.contains('(') && field.contains(')') {
                    if let Some(func_end) = field.find('(') {
                        let func_name = &field[..func_end];
                        escape_identifier(func_name)
                    } else {
                        escape_identifier(field)
                    }
                } else {
                    escape_identifier(field)
                };

                let op = if *negated { "NOT IN" } else { "IN" };
                // Case-insensitive for string values
                let all_strings = values.iter().all(|v| matches!(v, Value::String(_)));
                if all_strings {
                    let values_sql: Vec<String> = values
                        .iter()
                        .map(|v| match v {
                            Value::String(s) => format!("'{}'", escape_string(&s.to_lowercase())),
                            _ => value_to_sql(v),
                        })
                        .collect();
                    let values_list = values_sql.join(", ");
                    Ok(format!("lower({}) {} ({})", column_ref, op, values_list))
                } else {
                    let values_sql: Vec<String> = values.iter().map(value_to_sql).collect();
                    let values_list = values_sql.join(", ");
                    Ok(format!("{} {} ({})", column_ref, op, values_list))
                }
            }
            SearchExpr::FunctionFilter {
                function,
                op,
                value,
            } => {
                // Check if this is an aggregation function reference (e.g., avg(bytes_out) in WHERE after stats)
                // If so, use just the function name as the column reference
                let func_sql = if let EvalExpression::FunctionCall { name, args } = function {
                    // Check if it's an aggregation function
                    let agg_funcs = [
                        "count", "sum", "avg", "min", "max", "dc", "values", "list", "first",
                        "last", "earliest", "latest", "stdev", "var", "median", "perc95",
                    ];
                    if agg_funcs.contains(&name.to_lowercase().as_str()) && !args.is_empty() {
                        // This is an aggregation reference - use just the function name as column
                        escape_identifier(name)
                    } else {
                        // Regular function call
                        eval_expression_to_sql(self, function)?
                    }
                } else {
                    eval_expression_to_sql(self, function)?
                };

                let sql_op = comparator_to_sql(op);
                // Case-insensitive for string comparisons
                match (op, value) {
                    (Comparator::Eq | Comparator::Ne, Value::String(s)) => Ok(format!(
                        "lower({}) {} '{}'",
                        func_sql,
                        sql_op,
                        escape_string(&s.to_lowercase())
                    )),
                    _ => {
                        let value_sql = value_to_sql(value);
                        Ok(format!("{} {} {}", func_sql, sql_op, value_sql))
                    }
                }
            }
            SearchExpr::BooleanFunction(function) => eval_expression_to_sql(self, function),
            SearchExpr::FieldFunctionFilter {
                field,
                op,
                function,
            } => {
                // Check if field is an aggregation expression
                let column_ref = if field.contains('(') && field.contains(')') {
                    if let Some(func_end) = field.find('(') {
                        let func_name = &field[..func_end];
                        escape_identifier(func_name)
                    } else {
                        escape_identifier(field)
                    }
                } else {
                    escape_identifier(field)
                };

                let func_sql = eval_expression_to_sql(self, function)?;
                let sql_op = comparator_to_sql(op);
                // Case-insensitive for Eq/Ne
                match op {
                    Comparator::Eq | Comparator::Ne => Ok(format!(
                        "lower({}) {} lower({})",
                        column_ref, sql_op, func_sql
                    )),
                    _ => Ok(format!("{} {} {}", column_ref, sql_op, func_sql)),
                }
            }
            SearchExpr::And(left, right) => {
                let left_sql = self.generate_where_condition(left)?;
                let right_sql = self.generate_where_condition(right)?;
                Ok(format!("({} AND {})", left_sql, right_sql))
            }
            SearchExpr::Or(left, right) => {
                let left_sql = self.generate_where_condition(left)?;
                let right_sql = self.generate_where_condition(right)?;
                Ok(format!("({} OR {})", left_sql, right_sql))
            }
            SearchExpr::Not(inner) => {
                let inner_sql = self.generate_where_condition(inner)?;
                Ok(format!("NOT ({})", inner_sql))
            }
            SearchExpr::Group(inner) => {
                let inner_sql = self.generate_where_condition(inner)?;
                Ok(format!("({})", inner_sql))
            }
            SearchExpr::LiteralComparison { left, op, right } => {
                // Literal string comparison - case-insensitive for Eq/Ne
                let op_sql = comparator_to_sql(op);
                match (op, right) {
                    (Comparator::Eq | Comparator::Ne, Value::String(s)) => Ok(format!(
                        "lower('{}') {} '{}'",
                        escape_string(left),
                        op_sql,
                        escape_string(&s.to_lowercase())
                    )),
                    _ => {
                        let left_sql = format!("'{}'", escape_string(left));
                        let right_sql = value_to_sql(right);
                        Ok(format!("{} {} {}", left_sql, op_sql, right_sql))
                    }
                }
            }
            SearchExpr::InSubsearch {
                field,
                subsearch,
                negated,
            } => self.generate_in_subsearch_filter(field, subsearch, *negated),
        }
    }

    /// Generate SQL for `field IN [search ... | return field]` subsearch expressions.
    /// Produces a ClickHouse subquery: `lower(field) IN (SELECT DISTINCT lower(return_field) FROM ... LIMIT 10000)`
    fn generate_in_subsearch_filter(
        &self,
        field: &str,
        subsearch: &Query,
        negated: bool,
    ) -> Result<String, SqlGenError> {
        let time_range_guard = self
            .generation_time_range
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let time_range = time_range_guard.as_ref().ok_or_else(|| {
            SqlGenError::UnsupportedOperation(
                "Subsearch IN requires a time range context".to_string(),
            )
        })?;

        // Walk the subsearch Query to extract the search expression and return fields
        let stages = self.collect_stages(subsearch);

        // Find the search expression (first stage)
        let search_expr = stages.iter().find_map(|s| match s {
            super::QueryStage::Search(expr) => Some(*expr),
            _ => None,
        });

        // Find the return command to get the target field(s)
        let return_fields: Vec<&str> = stages
            .iter()
            .filter_map(|s| match s {
                super::QueryStage::Command(Command::Return { fields, .. }) => {
                    Some(fields.iter().map(|f| f.as_str()).collect::<Vec<_>>())
                }
                _ => None,
            })
            .flatten()
            .collect();

        // Determine which field to SELECT from the subsearch
        // Default to the outer field name if no return command specified
        let return_field = if return_fields.is_empty() {
            field
        } else {
            return_fields[0]
        };

        // Build the inner WHERE clause from the subsearch's search expression
        let inner_where = if let Some(expr) = search_expr {
            let where_sql = self.generate_search_expr(expr)?;
            format!(" WHERE ({})", where_sql)
        } else {
            String::new()
        };

        // Build PREWHERE with time range and any indexed field conditions
        let mut prewhere = format!(
            "timestamp BETWEEN '{}' AND '{}'",
            time_range.start.format("%Y-%m-%d %H:%M:%S%.6f"),
            time_range.end.format("%Y-%m-%d %H:%M:%S%.6f"),
        );
        if let Some(expr) = search_expr {
            let extra = super::extract_prewhere_conditions(expr);
            if !extra.is_empty() {
                prewhere = format!("{} AND {}", prewhere, extra.join(" AND "));
            }
        }

        // Build the SELECT expression for the return field
        let return_field_expr = if super::is_explicit_column(return_field) {
            escape_identifier(return_field)
        } else {
            format!("ext.{}", return_field)
        };

        // Build the outer field expression
        let outer_field_expr = if super::is_explicit_column(field) {
            escape_identifier(field)
        } else {
            format!("ext.{}", field)
        };

        let op = if negated { "NOT IN" } else { "IN" };

        // Use case-insensitive matching for string fields, direct for numeric
        let is_numeric = NUMERIC_UDM_FIELDS.contains(&field);
        if is_numeric {
            Ok(format!(
                "{} {} (SELECT DISTINCT {} FROM {} PREWHERE {}{} LIMIT {})",
                outer_field_expr,
                op,
                return_field_expr,
                self.table_name,
                prewhere,
                inner_where,
                SUBSEARCH_RESULT_LIMIT,
            ))
        } else {
            Ok(format!(
                "lower({}) {} (SELECT DISTINCT lower({}) FROM {} PREWHERE {}{} LIMIT {})",
                outer_field_expr,
                op,
                return_field_expr,
                self.table_name,
                prewhere,
                inner_where,
                SUBSEARCH_RESULT_LIMIT,
            ))
        }
    }
}
