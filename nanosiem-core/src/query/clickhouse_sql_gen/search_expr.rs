// SPDX-License-Identifier: AGPL-3.0-or-later

//! Search expression → WHERE clause generation
//!
//! Converts `SearchExpr` AST nodes into ClickHouse WHERE clause SQL,
//! handling UDM fields, JSON metadata fields, wildcards, regex, and
//! case-insensitive matching.

use super::eval_functions::eval_expression_to_sql;
use super::helpers::*;
use super::{ClickHouseSqlGenerator, SUBSEARCH_RESULT_LIMIT};
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
/// `skip_tostring`: true when `field_expr` is a plain String column, so the
///   case-insensitive substring guard uses `lower(field_expr)` — which matches
///   the `lower(<col>)` text skip index (NAN-1247). false keeps
///   `lower(toString(field_expr))` for ext/JSON/numeric fields (NULL-safety /
///   coercion). Computed by the caller via `search_lowered`/
///   `is_plain_string_search_column`.
/// `negated`: true for NotRegex (inverts the result)
fn build_optimized_regex_sql(
    field_expr: &str,
    pattern: &str,
    skip_tostring: bool,
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
                // NAN-1026 Phase 2: each literal lowered to iLike instead of hasToken*.
                // iLike with splitByNonAlpha gives substring-correct matching and
                // CH 26.4's LIKE-via-dictionary-scan keeps it index-accelerated.
                let conditions: Vec<String> = literals
                    .iter()
                    .map(|lit| {
                        let escaped_lit = escape_string(&lit.to_lowercase());
                        let pattern = escape_like_pattern(&escaped_lit);
                        if skip_tostring {
                            format!("lower({}) iLike '%{}%'", field_expr, pattern)
                        } else {
                            format!(
                                "lower(toString({})) iLike '%{}%'",
                                field_expr, pattern
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
                // NAN-1026 Phase 2: the guard becomes iLike (substring-correct, index-
                // accelerated via splitByNonAlpha) instead of hasToken*. Granules where
                // the longest literal substring isn't present get pruned, then match()
                // verifies the full regex on survivors.
                let escaped_token = escape_string(&token.to_lowercase());
                let pattern = escape_like_pattern(&escaped_token);
                let guard = if skip_tostring {
                    format!("lower({}) iLike '%{}%'", field_expr, pattern)
                } else {
                    format!(
                        "lower(toString({})) iLike '%{}%'",
                        field_expr, pattern
                    )
                };
                // For negated: NOT (guard AND match) → can't short-circuit, just negate match.
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
    /// True when `field` resolves to a plain String column — a UDM/OCSF promoted
    /// `ExplicitColumn` that is neither numeric nor UUID. For these, full-text
    /// substring search must use `lower(<col>)`, NOT `lower(toString(<col>))`:
    /// ClickHouse matches a text skip index by EXPRESSION, and the `toString`
    /// wrapper orphans the `lower(<col>)` index → full scan (NAN-1247). For a real
    /// String column `toString(col)` is a semantic no-op, so dropping it changes
    /// only the SQL form (and turns the index back on), never the result.
    fn is_plain_string_search_column(&self, field: &str) -> bool {
        matches!(
            self.profile.resolve(field),
            crate::schema::FieldResolution::ExplicitColumn(_)
        ) && !self.profile.is_numeric_field(field)
            && !self.profile.is_uuid_field(field)
    }

    /// Lowercased, index-matchable expression for case-insensitive substring /
    /// full-text search on `field` (whose access SQL is `field_expr`). Plain
    /// String columns → `lower(field_expr)` (matches the `lower(col)` text index);
    /// ext/JSON/numeric/uuid → `lower(toString(field_expr))` (NULL-safety /
    /// coercion). `message` flows through the String-column branch, so it stays
    /// byte-identical (`lower(message)`).
    fn search_lowered(&self, field: &str, field_expr: &str) -> String {
        if self.is_plain_string_search_column(field) {
            format!("lower({})", field_expr)
        } else {
            format!("lower(toString({}))", field_expr)
        }
    }

    /// Generate SQL for a search expression (WHERE clause content)
    pub fn generate_search_expr(&self, expr: &SearchExpr) -> Result<String, SqlGenError> {
        match expr {
            SearchExpr::Keyword(kw) => {
                // Handle wildcard * as match-all
                if kw == "*" {
                    return Ok("1".to_string());
                }

                // Bare keyword: lower to substring iLike against the message column.
                // splitByNonAlpha text index (migration 119) + CH 26.4's
                // LIKE-via-dictionary-scan does granule pruning, so this is both
                // correct (substring semantics — `anom` matches `anomalous`) and
                // index-accelerated. Pre-NAN-1026 the codegen used hasToken which
                // silently dropped any needle that wasn't a whole CH token.
                let escaped = escape_string(&kw.to_lowercase());
                Ok(format!(
                    "lower(message) iLike '%{}%'",
                    escape_like_pattern(&escaped)
                ))
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

        // NAN-1321: OCSF class-split UDM aliases (`src_host`, `user`, …) are not
        // promoted columns, so `is_known_field` is false and they would fall to the
        // metadata-JSON branch below (`JSONExtractString(metadata, 'src_host')`) —
        // empty under OCSF. Route them through the column branch so the IN-list
        // matches the value-pick `if(...)` like the `=` filter does. UDM never
        // class-splits → gate unchanged → byte-identical.
        let is_class_split = self.profile.class_split_value_sql(field).is_some();
        if self.profile.is_known_field(field) || is_class_split {
            // Determine the physical access expression via the active profile:
            // ExplicitColumn → escaped column, JsonPath → JSONExtract, Unknown →
            // `ext.{field}` (UDM's spill). For OCSF a known field is always a
            // promoted ExplicitColumn, so this is byte-identical for UDM.
            // NAN-1321: class-split concepts resolve to the value-pick `if(...)` so
            // an IN-list filter matches the host/user/process wherever the class put
            // it (UDM unaffected → bare column).
            let field_expr = self.filter_field_expr(field, "String");

            if self.profile.is_uuid_field(field) {
                // UUID fields: use toString() instead of lower()
                let values_sql: Vec<String> = values
                    .iter()
                    .map(|v| match v {
                        Value::String(s) => format!("'{}'", escape_string(&s.to_lowercase())),
                        _ => value_to_sql_for_field(field, v, self.profile.as_ref()),
                    })
                    .collect();
                let values_list = values_sql.join(", ");
                Ok(format!("toString({}) {} ({})", field_expr, op, values_list))
            } else if self.profile.is_numeric_field(field) {
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
                        _ => value_to_sql_for_field(field, v, self.profile.as_ref()),
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
                        _ => value_to_sql_for_field(field, v, self.profile.as_ref()),
                    })
                    .collect();
                let values_list = values_sql.join(", ");
                Ok(format!("lower({}) {} ({})", field_expr, op, values_list))
            } else {
                let values_sql: Vec<String> = values
                    .iter()
                    .map(|v| value_to_sql_for_field(field, v, self.profile.as_ref()))
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
        if self.profile.is_known_field(field) {
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
        // Profile-aware physical access: ExplicitColumn → escaped column (direct,
        // possibly dotted/promoted), JsonPath → JSONExtract (OCSF tail), Unknown →
        // `ext.{field}` (UDM's existing ext-JSON dot-notation, byte-identical).
        // NAN-1321: a class-split concept resolves to the value-pick `if(...)`.
        let field_expr = self.filter_field_expr(field, "String");

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
            _ => value_to_sql_for_field(field, value, self.profile.as_ref()),
        };

        match op {
            Comparator::Regex => {
                // NAN-1026 Phase 2: simple regex literals lower to iLike (substring-
                // correct + splitByNonAlpha index-accelerated) instead of hasToken*.
                if let Value::Regex(pattern) = value {
                    if let Some(token) = extract_simple_regex_token(pattern) {
                        let escaped = escape_string(&token.to_lowercase());
                        let like = escape_like_pattern(&escaped);
                        return Ok(format!(
                            "{} iLike '%{}%'",
                            self.search_lowered(field, &field_expr),
                            like
                        ));
                    }
                    // Complex regex — try bloom-guard pre-filtering and pattern rewrites
                    return Ok(build_optimized_regex_sql(
                        &field_expr,
                        pattern,
                        self.is_plain_string_search_column(field),
                        false,
                    ));
                }
                Ok(format!("match({}, {})", field_expr, value_sql))
            }
            Comparator::NotRegex => {
                // NAN-1026 Phase 2: NOT iLike instead of NOT hasToken — substring-correct.
                if let Value::Regex(pattern) = value {
                    if let Some(token) = extract_simple_regex_token(pattern) {
                        let escaped = escape_string(&token.to_lowercase());
                        let like = escape_like_pattern(&escaped);
                        return Ok(format!(
                            "{} NOT iLike '%{}%'",
                            self.search_lowered(field, &field_expr),
                            like
                        ));
                    }
                    // Complex regex — try pattern rewrites (bloom guard not useful for negation)
                    return Ok(build_optimized_regex_sql(
                        &field_expr,
                        pattern,
                        self.is_plain_string_search_column(field),
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
                // NAN-1026 Phase 2: every CONTAINS lowers to substring iLike
                // (case-insensitive, substring-correct). splitByNonAlpha indexes
                // + CH 26.4 LIKE-via-dictionary-scan provide granule pruning so
                // perf is comparable to the old hasToken* path on indexed columns,
                // and the behavior is correct for fragment matches that hasToken
                // silently dropped (`message CONTAINS "anom"` matches "anomalous";
                // `src_host CONTAINS "dc"` matches "srv-dc01"; etc.).
                if let Value::String(s) = value {
                    let escaped = escape_like_pattern(&escape_string(&s.to_lowercase()));
                    Ok(format!(
                        "{} iLike '%{}%'",
                        self.search_lowered(field, &field_expr),
                        escaped
                    ))
                } else {
                    Ok(format!(
                        "{} iLike concat('%', {}, '%')",
                        field_expr, value_sql
                    ))
                }
            }
            Comparator::NotContains => {
                // NAN-1026 Phase 2: negated CONTAINS → NOT iLike, never NOT hasToken*.
                // The hasToken path used to leak DCs through `src_host NOT CONTAINS "dc"`
                // filters when host tokens were `dc01`, not `dc`.
                if let Value::String(s) = value {
                    let escaped = escape_like_pattern(&escape_string(&s.to_lowercase()));
                    Ok(format!(
                        "{} NOT iLike '%{}%'",
                        self.search_lowered(field, &field_expr),
                        escaped
                    ))
                } else {
                    Ok(format!(
                        "{} NOT iLike concat('%', {}, '%')",
                        field_expr, value_sql
                    ))
                }
            }
            Comparator::StartsWith => {
                let pattern = match value {
                    Value::String(s) => {
                        // NAN-1160: escape_like_pattern so a literal `_`/`%` in the value is
                        // matched literally, not as an iLike wildcard (mirrors Contains:480).
                        format!("'{}%'", escape_like_pattern(&escape_string(&s.to_lowercase())))
                    }
                    _ => format!("concat(lower({}), '%')", value_sql),
                };
                Ok(format!("{} iLike {}", field_expr, pattern))
            }
            Comparator::NotStartsWith => {
                let pattern = match value {
                    Value::String(s) => {
                        // NAN-1160: escape_like_pattern so a literal `_`/`%` in the value is
                        // matched literally, not as an iLike wildcard (mirrors Contains:480).
                        format!("'{}%'", escape_like_pattern(&escape_string(&s.to_lowercase())))
                    }
                    _ => format!("concat(lower({}), '%')", value_sql),
                };
                Ok(format!("{} NOT iLike {}", field_expr, pattern))
            }
            Comparator::EndsWith => {
                let pattern = match value {
                    Value::String(s) => {
                        // NAN-1160: escape_like_pattern so a literal `_`/`%` in the value is
                        // matched literally, not as an iLike wildcard (mirrors Contains:480).
                        format!("'%{}'", escape_like_pattern(&escape_string(&s.to_lowercase())))
                    }
                    _ => format!("concat('%', lower({}))", value_sql),
                };
                Ok(format!("{} iLike {}", field_expr, pattern))
            }
            Comparator::NotEndsWith => {
                let pattern = match value {
                    Value::String(s) => {
                        // NAN-1160: escape_like_pattern so a literal `_`/`%` in the value is
                        // matched literally, not as an iLike wildcard (mirrors Contains:480).
                        format!("'%{}'", escape_like_pattern(&escape_string(&s.to_lowercase())))
                    }
                    _ => format!("concat('%', lower({}))", value_sql),
                };
                Ok(format!("{} NOT iLike {}", field_expr, pattern))
            }
            Comparator::Eq | Comparator::Ne => {
                let sql_op = comparator_to_sql(op);

                // For numeric UDM fields, never apply lower() - compare as numbers
                if self.profile.is_numeric_field(field) {
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
                } else if self.profile.is_uuid_field(field) {
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

                            // Hostname expansion: for host-entity fields without dots,
                            // match both exact and FQDN variants (e.g., "workstation"
                            // matches "workstation.corp.local"). Driven by the active
                            // profile's entity classification so OCSF promoted host
                            // columns (e.g. `src_endpoint.hostname`) expand too — for
                            // UDM these are exactly the host-entity columns.
                            let is_hostname_field =
                                self.profile.entity_type(field) == Some(crate::schema::EntityType::Host);
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
                            } else if self.profile.is_lowercased_at_ingest(field) {
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
        let json_type = match value {
            Value::Number(_) => "Float64",
            Value::Bool(_) => "Bool",
            _ => "String",
        };
        let field_expr = if use_metadata {
            // Use JSONExtract for metadata column access
            self.generate_json_extract(&field_path, json_type)
        } else {
            // Profile-aware spill access. For UDM the profile returns Unknown →
            // `ext.{field}` (byte-identical to the prior native-dot-notation). For
            // OCSF an unpromoted tail field resolves to JsonPath →
            // `JSONExtract<T>(event, 'p1', 'p2', …)`. NAN-1321: OCSF UDM-semantic
            // aliases (`src_host`, `user`, …) are not promoted columns so they reach
            // THIS path; `filter_field_expr` resolves the class-split ones to the
            // value-pick `if(...)` so `src_host="ws-01"` matches device.hostname too.
            self.filter_field_expr(&field_path, json_type)
        };

        // String/pattern comparisons compare against toString(field) so a missing ext key
        // (JSON null) becomes '' rather than NULL. Otherwise a negated match (`NOT iLike`,
        // `!=`, or an outer `NOT (... iLike ...)`) evaluates `NOT NULL` = NULL and silently
        // drops every row where the key is absent — e.g. `NOT integrity_level CONTAINS "x"`
        // returned only the rows that HAVE the field. The post-pipe `| where` path already
        // does this. Numeric comparisons keep the raw field (toString would break them), and
        // build_optimized_regex_sql is passed the raw field_expr (it wraps internally). NAN-1161.
        let field_str = format!("toString({})", field_expr);

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
                return Ok(format!("{} {} '{}'", field_str, sql_op, pattern));
            }
        }

        // NAN-1161: string/pattern arms compare `field_str` (= toString(field_expr)) so a
        // missing ext key reads as '' not NULL — see the binding above. build_optimized_regex_sql
        // gets the raw field_expr (it wraps internally); the numeric arm stays raw.
        match op {
            Comparator::Regex => {
                // For simple patterns (no regex metacharacters), use substring iLike.
                if let Value::Regex(pattern) = value {
                    if let Some(token) = extract_simple_regex_token(pattern) {
                        // NAN-1160: substring iLike, not hasTokenCaseInsensitive. hasToken
                        // matches whole tokens only (`dc` never matches `dc01`) and ext is
                        // native JSON with no token index (idx_ext_text dropped, migration 118),
                        // so hasToken under-matched AND bought no acceleration.
                        return Ok(format!(
                            "{} iLike '%{}%'",
                            field_str,
                            escape_like_pattern(&escape_string(&token.to_lowercase()))
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
                Ok(format!("match({}, {})", field_str, value_to_sql(value)))
            }
            Comparator::NotRegex => {
                // For simple patterns, use substring NOT iLike (see Regex above, NAN-1160).
                if let Value::Regex(pattern) = value {
                    if let Some(token) = extract_simple_regex_token(pattern) {
                        return Ok(format!(
                            "{} NOT iLike '%{}%'",
                            field_str,
                            escape_like_pattern(&escape_string(&token.to_lowercase()))
                        ));
                    }
                    // Complex regex — try pattern rewrites
                    return Ok(build_optimized_regex_sql(&field_expr, pattern, false, true));
                }
                Ok(format!(
                    "match({}, {}) = 0",
                    field_str,
                    value_to_sql(value)
                ))
            }
            Comparator::Like => Ok(format!("{} iLike {}", field_str, value_to_sql(value))),
            Comparator::NotLike => Ok(format!("{} NOT iLike {}", field_str, value_to_sql(value))),
            Comparator::Contains => {
                if let Value::String(s) = value {
                    // NAN-1160: always substring iLike, never hasTokenCaseInsensitive. hasToken
                    // matched whole tokens only (`medi` never matches `Medium`) and ext is native
                    // JSON with no token index (idx_ext_text dropped, migration 118) — wrong AND
                    // no faster. Mirrors the UDM Contains path.
                    let escaped = escape_like_pattern(&escape_string(&s.to_lowercase()));
                    Ok(format!("{} iLike '%{}%'", field_str, escaped))
                } else {
                    Ok(format!(
                        "{} iLike concat('%', {}, '%')",
                        field_str,
                        value_to_sql(value)
                    ))
                }
            }
            Comparator::NotContains => {
                if let Value::String(s) = value {
                    // NAN-1160: NOT iLike, never NOT hasTokenCaseInsensitive — the token form
                    // leaked sub-token matches through the exclusion (e.g. `NOT CONTAINS "medi"`
                    // failed to exclude `Medium`).
                    let escaped = escape_like_pattern(&escape_string(&s.to_lowercase()));
                    Ok(format!("{} NOT iLike '%{}%'", field_str, escaped))
                } else {
                    Ok(format!(
                        "{} NOT iLike concat('%', {}, '%')",
                        field_str,
                        value_to_sql(value)
                    ))
                }
            }
            Comparator::StartsWith => {
                let pattern = match value {
                    Value::String(s) => {
                        // NAN-1160: escape_like_pattern so a literal `_`/`%` in the value is
                        // matched literally, not as an iLike wildcard (mirrors Contains:480).
                        format!("'{}%'", escape_like_pattern(&escape_string(&s.to_lowercase())))
                    }
                    _ => format!("concat(lower({}), '%')", value_to_sql(value)),
                };
                Ok(format!("{} iLike {}", field_str, pattern))
            }
            Comparator::NotStartsWith => {
                let pattern = match value {
                    Value::String(s) => {
                        // NAN-1160: escape_like_pattern so a literal `_`/`%` in the value is
                        // matched literally, not as an iLike wildcard (mirrors Contains:480).
                        format!("'{}%'", escape_like_pattern(&escape_string(&s.to_lowercase())))
                    }
                    _ => format!("concat(lower({}), '%')", value_to_sql(value)),
                };
                Ok(format!("{} NOT iLike {}", field_str, pattern))
            }
            Comparator::EndsWith => {
                let pattern = match value {
                    Value::String(s) => {
                        // NAN-1160: escape_like_pattern so a literal `_`/`%` in the value is
                        // matched literally, not as an iLike wildcard (mirrors Contains:480).
                        format!("'%{}'", escape_like_pattern(&escape_string(&s.to_lowercase())))
                    }
                    _ => format!("concat('%', lower({}))", value_to_sql(value)),
                };
                Ok(format!("{} iLike {}", field_str, pattern))
            }
            Comparator::NotEndsWith => {
                let pattern = match value {
                    Value::String(s) => {
                        // NAN-1160: escape_like_pattern so a literal `_`/`%` in the value is
                        // matched literally, not as an iLike wildcard (mirrors Contains:480).
                        format!("'%{}'", escape_like_pattern(&escape_string(&s.to_lowercase())))
                    }
                    _ => format!("concat('%', lower({}))", value_to_sql(value)),
                };
                Ok(format!("{} NOT iLike {}", field_str, pattern))
            }
            Comparator::Eq | Comparator::Ne => {
                // Case-insensitive string comparison. NAN-1161: lower(toString(field)) so a
                // missing key compares as '' — `field != "x"` keeps absent-key rows (NULL != x
                // would drop them).
                let sql_op = comparator_to_sql(op);
                match value {
                    // NAN-1333: a class-split concept resolves to its INDEXED unified
                    // column (`<field>_unified`), a plain non-null String/LowCardinality
                    // column. The `toString` wrapper that NAN-1161 adds for ext/JSON-null
                    // safety ORPHANS the `lower(<col>)` text index here (CH matches a skip
                    // index by EXPRESSION) → full scan. Drop it for class-split fields so
                    // `lower(<col>_unified) = v` matches the words index and prunes
                    // (640/640 → 294/640 on local CH). toString on a real String column is
                    // a semantic no-op, and the column is NOT NULL (MATERIALIZED ''), so the
                    // NAN-1161 absent-key concern does not apply. UDM never class-splits →
                    // this branch is OCSF-only → UDM byte-identical.
                    Value::String(s) if self.profile.class_split_column(&field_path).is_some() => {
                        Ok(format!(
                            "lower({}) {} '{}'",
                            field_expr,
                            sql_op,
                            escape_string(&s.to_lowercase())
                        ))
                    }
                    Value::String(s) => Ok(format!(
                        "lower({}) {} '{}'",
                        field_str,
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
    ///
    /// OCSF Phase 2: when the active profile resolves `field` to a
    /// [`FieldResolution::JsonPath`] (a nested path in an arbitrary JSON column,
    /// e.g. OCSF's `event` column), emit an N-level
    /// `JSONExtract<T>(col, 'p1', 'p2', …)` against that column. For UDM the
    /// profile only ever returns `ExplicitColumn` or `Unknown` — neither hits the
    /// JsonPath branch — so the legacy `metadata`-prefixed behavior below is
    /// preserved byte-for-byte.
    pub fn generate_json_extract(&self, field: &str, json_type: &str) -> String {
        // OCSF nested-path resolution (additive; never exercised by UDM).
        if let crate::schema::FieldResolution::JsonPath { col, path } = self.profile.resolve(field) {
            let path_args: Vec<String> = path
                .iter()
                .map(|p| format!("'{}'", escape_string(p)))
                .collect();
            return format!(
                "JSONExtract{}({}, {})",
                json_type,
                col,
                path_args.join(", ")
            );
        }

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
                // In piped commands (search, where), keywords are substring text searches
                // on message. Use the same `lower(message) iLike '%kw%'` form as the
                // top-level keyword path (generate_search_expr) so the splitByNonAlpha text
                // index (idx_message_words) prunes granules. The previous
                // `position(lower(message), 'kw') > 0` bypasses that index and
                // full-scans/decompresses the entire message column (~100x more bytes_read,
                // and can OOM on large windows) — yet is byte-for-byte semantically identical
                // to the escaped iLike, verified across substring/multi-word/metachar cases
                // (NAN-1153). escape_like_pattern keeps `%`/`_` literal for parity with
                // position(). After stats/timechart where message no longer exists,
                // ClickHouse returns a clear "column not found" error — correct, since bare
                // keyword searches don't make sense after aggregation.
                let escaped = escape_string(&kw.to_lowercase());
                Ok(format!(
                    "lower(message) iLike '%{}%'",
                    escape_like_pattern(&escaped)
                ))
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
                    // {func}_{field} reference to an UN-aliased prior aggregation
                    // (NAN-1339): the output column is the bare func name.
                    if let Some(target) = self.agg_reference_alias(field) {
                        escape_identifier(&target)
                    } else {
                        escape_identifier(field)
                    }
                };

                // Always treat as direct column reference
                let value_sql = match value {
                    Value::Regex(pattern) => format!("'{}'", escape_regex_pattern(pattern)),
                    _ => value_to_sql(value),
                };

                match op {
                    Comparator::Regex => {
                        // For simple patterns, use substring iLike (NAN-1160).
                        if let Value::Regex(pattern) = value {
                            if let Some(token) = extract_simple_regex_token(pattern) {
                                // NAN-1160: substring iLike, not hasTokenCaseInsensitive —
                                // post-stats columns are unindexed CTE intermediates, so
                                // hasToken under-matched (`dc` ≠ `dc01`) for zero index gain.
                                return Ok(format!(
                                    "toString({}) iLike '%{}%'",
                                    column_ref,
                                    escape_like_pattern(&escape_string(&token.to_lowercase()))
                                ));
                            }
                            // Complex regex — try bloom filter pre-filtering and pattern rewrites
                            let col_str = format!("toString({})", column_ref);
                            return Ok(build_optimized_regex_sql(&col_str, pattern, false, false));
                        }
                        Ok(format!("match(toString({}), {})", column_ref, value_sql))
                    }
                    Comparator::NotRegex => {
                        // For simple patterns, use substring NOT iLike (NAN-1160).
                        if let Value::Regex(pattern) = value {
                            if let Some(token) = extract_simple_regex_token(pattern) {
                                return Ok(format!(
                                    "toString({}) NOT iLike '%{}%'",
                                    column_ref,
                                    escape_like_pattern(&escape_string(&token.to_lowercase()))
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
                            // NAN-1160: always substring iLike, never hasTokenCaseInsensitive —
                            // post-stats columns are unindexed CTE intermediates, so hasToken
                            // matched whole tokens only (`medi` ≠ `Medium`) for zero index gain.
                            let escaped = escape_like_pattern(&escape_string(&s.to_lowercase()));
                            Ok(format!("toString({}) iLike '%{}%'", column_ref, escaped))
                        } else {
                            Ok(format!(
                                "toString({}) iLike concat('%', {}, '%')",
                                column_ref, value_sql
                            ))
                        }
                    }
                    Comparator::NotContains => {
                        if let Value::String(s) = value {
                            // NAN-1160: NOT iLike, never NOT hasTokenCaseInsensitive — the token
                            // form leaked sub-token matches through the exclusion filter.
                            let escaped = escape_like_pattern(&escape_string(&s.to_lowercase()));
                            Ok(format!(
                                "toString({}) NOT iLike '%{}%'",
                                column_ref, escaped
                            ))
                        } else {
                            Ok(format!(
                                "toString({}) NOT iLike concat('%', {}, '%')",
                                column_ref, value_sql
                            ))
                        }
                    }
                    Comparator::StartsWith => {
                        let pattern = match value {
                            Value::String(s) => {
                                // NAN-1160: escape_like_pattern so a literal `_`/`%` in the
                                // value is matched literally, not as an iLike wildcard.
                                format!("'{}%'", escape_like_pattern(&escape_string(&s.to_lowercase())))
                            }
                            _ => format!("concat(lower({}), '%')", value_sql),
                        };
                        Ok(format!("toString({}) iLike {}", column_ref, pattern))
                    }
                    Comparator::NotStartsWith => {
                        let pattern = match value {
                            Value::String(s) => {
                                // NAN-1160: escape_like_pattern so a literal `_`/`%` in the
                                // value is matched literally, not as an iLike wildcard.
                                format!("'{}%'", escape_like_pattern(&escape_string(&s.to_lowercase())))
                            }
                            _ => format!("concat(lower({}), '%')", value_sql),
                        };
                        Ok(format!("toString({}) NOT iLike {}", column_ref, pattern))
                    }
                    Comparator::EndsWith => {
                        let pattern = match value {
                            Value::String(s) => {
                                // NAN-1160: escape_like_pattern so a literal `_`/`%` in the
                                // value is matched literally, not as an iLike wildcard.
                                format!("'%{}'", escape_like_pattern(&escape_string(&s.to_lowercase())))
                            }
                            _ => format!("concat('%', lower({}))", value_sql),
                        };
                        Ok(format!("toString({}) iLike {}", column_ref, pattern))
                    }
                    Comparator::NotEndsWith => {
                        let pattern = match value {
                            Value::String(s) => {
                                // NAN-1160: escape_like_pattern so a literal `_`/`%` in the
                                // value is matched literally, not as an iLike wildcard.
                                format!("'%{}'", escape_like_pattern(&escape_string(&s.to_lowercase())))
                            }
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
            let extra = super::extract_prewhere_conditions(expr, self.profile.as_ref());
            if !extra.is_empty() {
                prewhere = format!("{} AND {}", prewhere, extra.join(" AND "));
            }
        }

        // Build the SELECT expression for the return field (profile-aware: direct
        // column for promoted/UDM columns, JSONExtract for an OCSF tail path,
        // `ext.{field}` for a UDM Unknown — byte-identical for UDM).
        let return_field_expr = self.field_access_expr(return_field, "String");

        // Build the outer field expression (same profile-aware resolution).
        let outer_field_expr = self.field_access_expr(field, "String");

        let op = if negated { "NOT IN" } else { "IN" };

        // Use case-insensitive matching for string fields, direct for numeric
        let is_numeric = self.profile.is_numeric_field(field);
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
