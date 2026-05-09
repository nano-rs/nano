// SPDX-License-Identifier: AGPL-3.0-or-later

//! Search expression and WHERE clause SQL generation
//!
//! Converts SearchExpr AST nodes into PostgreSQL WHERE clause SQL,
//! handling UDM fields (direct columns), JSONB metadata fields,
//! and post-aggregation WHERE conditions.

use super::eval_functions::eval_expression_to_sql;
use super::field_utils::*;
use super::SqlGenError;
use crate::query::ast::*;

impl super::SqlGenerator {
    /// Generate SQL for a search expression (WHERE clause content)
    ///
    /// For keyword searches, this generates a placeholder that will be handled
    /// specially in the query generation to use the bm25_search_full function.
    /// For field filters, it generates standard SQL WHERE conditions.
    pub fn generate_search_expr(&self, expr: &SearchExpr) -> Result<String, SqlGenError> {
        match expr {
            SearchExpr::Keyword(kw) => {
                // Handle wildcard * as match-all
                if kw == "*" {
                    return Ok("TRUE".to_string());
                }
                // Use ILIKE as fallback - the search service will use BM25 when possible
                // BM25 is used via bm25_search_full() function at the query level
                // This ILIKE is only used when BM25 can't be applied (e.g., in WHERE after stats)
                let escaped = escape_string(kw);
                Ok(format!("lower(message) ILIKE '%{}%'", escaped))
            }
            SearchExpr::FieldFilter { field, op, value } => {
                self.generate_field_filter(field, op, value)
            }
            SearchExpr::FunctionFilter {
                function,
                op,
                value,
            } => {
                let func_sql = eval_expression_to_sql(function)?;
                let value_sql = value_to_sql(value);
                let sql_op = comparator_to_sql(op);
                Ok(format!("{} {} {}", func_sql, sql_op, value_sql))
            }
            SearchExpr::BooleanFunction(function) => eval_expression_to_sql(function),
            SearchExpr::FieldFunctionFilter {
                field,
                op,
                function,
            } => {
                let field_sql = field_to_jsonb_path(field);
                let func_sql = eval_expression_to_sql(function)?;
                let sql_op = comparator_to_sql(op);
                Ok(format!("({}) {} {}", field_sql, sql_op, func_sql))
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
                // Literal string comparison
                let left_sql = format!("'{}'", escape_string(left));
                let right_sql = value_to_sql(right);
                let op_sql = comparator_to_sql(op);
                Ok(format!("{} {} {}", left_sql, op_sql, right_sql))
            }
            SearchExpr::InSubsearch { .. } => {
                Err(SqlGenError::UnsupportedOperation(
                    "Subsearch (IN [...]) is not supported in PostgreSQL backend".to_string(),
                ))
            }
        }
    }

    /// Generate SQL for IN list filter
    pub(super) fn generate_in_list_filter(
        &self,
        field: &str,
        values: &[Value],
        negated: bool,
    ) -> Result<String, SqlGenError> {
        let op = if negated { "NOT IN" } else { "IN" };

        if is_udm_field(field) {
            let values_sql: Vec<String> = values
                .iter()
                .map(|v| value_to_sql_for_field(field, v))
                .collect();
            let values_list = values_sql.join(", ");
            Ok(format!(
                "{} {} ({})",
                escape_identifier(field),
                op,
                values_list
            ))
        } else {
            let json_path = field_to_jsonb_path(field);

            // Determine if we need to cast the JSONB value based on the value types
            // Check if all values are numeric
            let all_numeric = values.iter().all(|v| matches!(v, Value::Number(_)));
            let all_bool = values.iter().all(|v| matches!(v, Value::Bool(_)));

            let values_sql: Vec<String> = values.iter().map(|v| value_to_sql(v)).collect();
            let values_list = values_sql.join(", ");

            // Cast the JSONB extraction to match the value types
            let cast_expr = if all_numeric {
                format!("({})::numeric", json_path)
            } else if all_bool {
                format!("({})::boolean", json_path)
            } else {
                // For strings/mixed types, cast to text for consistent comparison
                format!("({})::text", json_path)
            };

            Ok(format!("{} {} ({})", cast_expr, op, values_list))
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

        // Normalize field name (apply aliases like sourcetype -> source_type)
        let field = normalize_field_name(field);

        // Check if it's a UDM field (direct column) or metadata field (JSONB)
        if is_udm_field(field) {
            self.generate_udm_field_filter(field, op, value)
        } else {
            self.generate_jsonb_field_filter(field, op, value)
        }
    }

    /// Generate SQL for UDM field filter (direct column access)
    pub(super) fn generate_udm_field_filter(
        &self,
        field: &str,
        op: &Comparator,
        value: &Value,
    ) -> Result<String, SqlGenError> {
        // Check if the value contains wildcards (* or ?) and we're using Eq/Ne
        // If so, convert to ILIKE pattern matching
        if let Value::String(s) = value {
            if (s.contains('*') || s.contains('?')) && matches!(op, Comparator::Eq | Comparator::Ne)
            {
                let pattern = wildcard_to_like_pattern(s);
                let sql_op = if *op == Comparator::Eq {
                    "ILIKE"
                } else {
                    "NOT ILIKE"
                };
                return Ok(format!(
                    "{} {} '{}'",
                    escape_identifier(field),
                    sql_op,
                    pattern
                ));
            }
        }

        let value_sql = match value {
            Value::Regex(pattern) => format!("'{}'", pattern.replace('\'', "''")),
            _ => value_to_sql_for_field(field, value),
        };

        match op {
            Comparator::Regex => {
                // Use PostgreSQL regex operator
                Ok(format!("{} ~ {}", escape_identifier(field), value_sql))
            }
            Comparator::NotRegex => {
                // Use PostgreSQL negated regex operator
                Ok(format!("{} !~ {}", escape_identifier(field), value_sql))
            }
            Comparator::Like => {
                // LIKE pattern match (case-insensitive with ILIKE)
                Ok(format!("{} ILIKE {}", escape_identifier(field), value_sql))
            }
            Comparator::NotLike => {
                // NOT LIKE pattern match
                Ok(format!(
                    "{} NOT ILIKE {}",
                    escape_identifier(field),
                    value_sql
                ))
            }
            Comparator::Contains => {
                // Contains substring - wrap value with %
                let pattern = match value {
                    Value::String(s) => format!("'%{}%'", escape_string(s)),
                    _ => format!("'%' || {} || '%'", value_sql),
                };
                Ok(format!("{} ILIKE {}", escape_identifier(field), pattern))
            }
            Comparator::NotContains => {
                let pattern = match value {
                    Value::String(s) => format!("'%{}%'", escape_string(s)),
                    _ => format!("'%' || {} || '%'", value_sql),
                };
                Ok(format!(
                    "{} NOT ILIKE {}",
                    escape_identifier(field),
                    pattern
                ))
            }
            Comparator::StartsWith => {
                // Starts with - append % to value
                let pattern = match value {
                    Value::String(s) => format!("'{}%'", escape_string(s)),
                    _ => format!("{} || '%'", value_sql),
                };
                Ok(format!("{} ILIKE {}", escape_identifier(field), pattern))
            }
            Comparator::NotStartsWith => {
                let pattern = match value {
                    Value::String(s) => format!("'{}%'", escape_string(s)),
                    _ => format!("{} || '%'", value_sql),
                };
                Ok(format!(
                    "{} NOT ILIKE {}",
                    escape_identifier(field),
                    pattern
                ))
            }
            Comparator::EndsWith => {
                // Ends with - prepend % to value
                let pattern = match value {
                    Value::String(s) => format!("'%{}'", escape_string(s)),
                    _ => format!("'%' || {}", value_sql),
                };
                Ok(format!("{} ILIKE {}", escape_identifier(field), pattern))
            }
            Comparator::NotEndsWith => {
                let pattern = match value {
                    Value::String(s) => format!("'%{}'", escape_string(s)),
                    _ => format!("'%' || {}", value_sql),
                };
                Ok(format!(
                    "{} NOT ILIKE {}",
                    escape_identifier(field),
                    pattern
                ))
            }
            _ => {
                let sql_op = comparator_to_sql(op);
                Ok(format!(
                    "{} {} {}",
                    escape_identifier(field),
                    sql_op,
                    value_sql
                ))
            }
        }
    }

    /// Generate SQL for JSONB metadata field filter
    pub(super) fn generate_jsonb_field_filter(
        &self,
        field: &str,
        op: &Comparator,
        value: &Value,
    ) -> Result<String, SqlGenError> {
        // Handle nested fields (dot notation)
        let json_path = field_to_jsonb_path(field);

        // Check if the value contains wildcards (* or ?) and we're using Eq/Ne
        // If so, convert to ILIKE pattern matching
        if let Value::String(s) = value {
            if (s.contains('*') || s.contains('?')) && matches!(op, Comparator::Eq | Comparator::Ne)
            {
                let pattern = wildcard_to_like_pattern(s);
                let sql_op = if *op == Comparator::Eq {
                    "ILIKE"
                } else {
                    "NOT ILIKE"
                };
                return Ok(format!("({})::text {} '{}'", json_path, sql_op, pattern));
            }
        }

        match op {
            Comparator::Regex => {
                let pattern_sql = match value {
                    Value::Regex(pattern) => format!("'{}'", pattern.replace('\'', "''")),
                    _ => value_to_sql(value),
                };
                // Cast to text and use regex
                Ok(format!("({})::text ~ {}", json_path, pattern_sql))
            }
            Comparator::NotRegex => {
                let pattern_sql = match value {
                    Value::Regex(pattern) => format!("'{}'", pattern.replace('\'', "''")),
                    _ => value_to_sql(value),
                };
                // Cast to text and use negated regex
                Ok(format!("({})::text !~ {}", json_path, pattern_sql))
            }
            Comparator::Like => {
                // LIKE pattern match (case-insensitive with ILIKE)
                Ok(format!(
                    "({})::text ILIKE {}",
                    json_path,
                    value_to_sql(value)
                ))
            }
            Comparator::NotLike => {
                // NOT LIKE pattern match
                Ok(format!(
                    "({})::text NOT ILIKE {}",
                    json_path,
                    value_to_sql(value)
                ))
            }
            Comparator::Contains => {
                // Contains substring - wrap value with %
                let pattern = match value {
                    Value::String(s) => format!("'%{}%'", escape_string(s)),
                    _ => format!("'%' || {} || '%'", value_to_sql(value)),
                };
                Ok(format!("({})::text ILIKE {}", json_path, pattern))
            }
            Comparator::NotContains => {
                let pattern = match value {
                    Value::String(s) => format!("'%{}%'", escape_string(s)),
                    _ => format!("'%' || {} || '%'", value_to_sql(value)),
                };
                Ok(format!("({})::text NOT ILIKE {}", json_path, pattern))
            }
            Comparator::StartsWith => {
                // Starts with - append % to value
                let pattern = match value {
                    Value::String(s) => format!("'{}%'", escape_string(s)),
                    _ => format!("{} || '%'", value_to_sql(value)),
                };
                Ok(format!("({})::text ILIKE {}", json_path, pattern))
            }
            Comparator::NotStartsWith => {
                let pattern = match value {
                    Value::String(s) => format!("'{}%'", escape_string(s)),
                    _ => format!("{} || '%'", value_to_sql(value)),
                };
                Ok(format!("({})::text NOT ILIKE {}", json_path, pattern))
            }
            Comparator::EndsWith => {
                // Ends with - prepend % to value
                let pattern = match value {
                    Value::String(s) => format!("'%{}'", escape_string(s)),
                    _ => format!("'%' || {}", value_to_sql(value)),
                };
                Ok(format!("({})::text ILIKE {}", json_path, pattern))
            }
            Comparator::NotEndsWith => {
                let pattern = match value {
                    Value::String(s) => format!("'%{}'", escape_string(s)),
                    _ => format!("'%' || {}", value_to_sql(value)),
                };
                Ok(format!("({})::text NOT ILIKE {}", json_path, pattern))
            }
            _ => {
                let sql_op = comparator_to_sql(op);
                // For comparisons, we need to cast appropriately
                let cast_expr = match value {
                    Value::Number(_) => format!("({})::numeric", json_path),
                    Value::Bool(_) => format!("({})::boolean", json_path),
                    // IP addresses are stored as TEXT, so no cast needed
                    Value::Ip(_) => format!("({})", json_path),
                    Value::String(_) => format!("({})", json_path),
                    Value::Regex(_) => format!("({})", json_path),
                    Value::Interval(_, _) => format!("({})", json_path),
                };
                Ok(format!("{} {} {}", cast_expr, sql_op, value_to_sql(value)))
            }
        }
    }

    /// Generate SQL for a WHERE condition in piped commands (after stats, etc.)
    /// This treats all fields as direct column references, not JSONB metadata
    pub(super) fn generate_where_condition(
        &self,
        expr: &SearchExpr,
    ) -> Result<String, SqlGenError> {
        match expr {
            SearchExpr::Keyword(kw) => {
                if kw == "*" {
                    return Ok("TRUE".to_string());
                }
                // In a where clause after aggregation, keywords don't make sense
                // but we'll allow it as a column name check
                Ok(format!("{} IS NOT NULL", escape_identifier(kw)))
            }
            SearchExpr::FieldFilter { field, op, value } => {
                // SECURITY: Validate field name format to prevent function call injection
                crate::query::validation::validate_field_name_format(field)
                    .map_err(|e| SqlGenError::InvalidQuery(e.message))?;

                // Always treat as direct column reference
                let value_sql = match value {
                    Value::Regex(pattern) => format!("'{}'", pattern.replace('\'', "''")),
                    _ => value_to_sql(value),
                };

                match op {
                    Comparator::Regex => Ok(format!(
                        "{}::text ~ {}",
                        escape_identifier(field),
                        value_sql
                    )),
                    Comparator::NotRegex => Ok(format!(
                        "{}::text !~ {}",
                        escape_identifier(field),
                        value_sql
                    )),
                    Comparator::Like => Ok(format!(
                        "{}::text ILIKE {}",
                        escape_identifier(field),
                        value_sql
                    )),
                    Comparator::NotLike => Ok(format!(
                        "{}::text NOT ILIKE {}",
                        escape_identifier(field),
                        value_sql
                    )),
                    Comparator::Contains => {
                        let pattern = match value {
                            Value::String(s) => format!("'%{}%'", escape_string(s)),
                            _ => format!("'%' || {} || '%'", value_sql),
                        };
                        Ok(format!(
                            "{}::text ILIKE {}",
                            escape_identifier(field),
                            pattern
                        ))
                    }
                    Comparator::NotContains => {
                        let pattern = match value {
                            Value::String(s) => format!("'%{}%'", escape_string(s)),
                            _ => format!("'%' || {} || '%'", value_sql),
                        };
                        Ok(format!(
                            "{}::text NOT ILIKE {}",
                            escape_identifier(field),
                            pattern
                        ))
                    }
                    Comparator::StartsWith => {
                        let pattern = match value {
                            Value::String(s) => format!("'{}%'", escape_string(s)),
                            _ => format!("{} || '%'", value_sql),
                        };
                        Ok(format!(
                            "{}::text ILIKE {}",
                            escape_identifier(field),
                            pattern
                        ))
                    }
                    Comparator::NotStartsWith => {
                        let pattern = match value {
                            Value::String(s) => format!("'{}%'", escape_string(s)),
                            _ => format!("{} || '%'", value_sql),
                        };
                        Ok(format!(
                            "{}::text NOT ILIKE {}",
                            escape_identifier(field),
                            pattern
                        ))
                    }
                    Comparator::EndsWith => {
                        let pattern = match value {
                            Value::String(s) => format!("'%{}'", escape_string(s)),
                            _ => format!("'%' || {}", value_sql),
                        };
                        Ok(format!(
                            "{}::text ILIKE {}",
                            escape_identifier(field),
                            pattern
                        ))
                    }
                    Comparator::NotEndsWith => {
                        let pattern = match value {
                            Value::String(s) => format!("'%{}'", escape_string(s)),
                            _ => format!("'%' || {}", value_sql),
                        };
                        Ok(format!(
                            "{}::text NOT ILIKE {}",
                            escape_identifier(field),
                            pattern
                        ))
                    }
                    _ => {
                        let sql_op = comparator_to_sql(op);
                        Ok(format!(
                            "{} {} {}",
                            escape_identifier(field),
                            sql_op,
                            value_sql
                        ))
                    }
                }
            }
            SearchExpr::InList {
                field,
                values,
                negated,
            } => {
                let values_sql: Vec<String> = values.iter().map(|v| value_to_sql(v)).collect();
                let values_list = values_sql.join(", ");
                let op = if *negated { "NOT IN" } else { "IN" };
                Ok(format!(
                    "{} {} ({})",
                    escape_identifier(field),
                    op,
                    values_list
                ))
            }
            SearchExpr::FunctionFilter {
                function,
                op,
                value,
            } => {
                let func_sql = eval_expression_to_sql(function)?;
                let value_sql = value_to_sql(value);
                let sql_op = comparator_to_sql(op);
                Ok(format!("{} {} {}", func_sql, sql_op, value_sql))
            }
            SearchExpr::BooleanFunction(function) => eval_expression_to_sql(function),
            SearchExpr::FieldFunctionFilter {
                field,
                op,
                function,
            } => {
                let func_sql = eval_expression_to_sql(function)?;
                let sql_op = comparator_to_sql(op);
                Ok(format!(
                    "{} {} {}",
                    escape_identifier(field),
                    sql_op,
                    func_sql
                ))
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
                // Literal string comparison
                let left_sql = format!("'{}'", escape_string(left));
                let right_sql = value_to_sql(right);
                let op_sql = comparator_to_sql(op);
                Ok(format!("{} {} {}", left_sql, op_sql, right_sql))
            }
            SearchExpr::InSubsearch { .. } => {
                Err(SqlGenError::UnsupportedOperation(
                    "Subsearch (IN [...]) is not supported in PostgreSQL backend".to_string(),
                ))
            }
        }
    }
}
