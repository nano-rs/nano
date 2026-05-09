// SPDX-License-Identifier: AGPL-3.0-or-later

//! Materialized View Generator for Real-Time Detection
//!
//! This module implements the materialized view generator that creates ClickHouse
//! materialized views for real-time detection rules. Materialized views enable
//! instant detection (10-30s latency) for simple IOC matching rules.
//!
//! Requirements: 4.1, 4.4, 4.5

use crate::detection::risk::default_score_for_severity;
use crate::models::detection_rule::DetectionRule;
use crate::query::{parse_query, Comparator, Query, SearchExpr};
use crate::udm::fields::UdmField;
use thiserror::Error;
use tracing::{debug, error, info};

/// Validate that a field name is safe for interpolation into DDL statements.
///
/// This prevents SQL injection via crafted `risk_entity_field` values (e.g.,
/// `concat(currentDatabase(), ':', version())`). The function checks:
/// 1. The field is a known UDM column name, OR
/// 2. The field is a valid `ext.*` extension field
///
/// As defense-in-depth, all fields must also match `^[a-z][a-z0-9_.]*$`.
fn validate_ddl_field_name(field: &str) -> Result<(), MaterializedViewError> {
    // Defense-in-depth: reject anything that doesn't match a strict identifier pattern.
    // This blocks parentheses, semicolons, quotes, spaces, SQL keywords used as
    // function calls, and any other unexpected characters.
    let is_safe_identifier = !field.is_empty()
        && field.len() <= 128
        && field
            .bytes()
            .next()
            .map_or(false, |b| b.is_ascii_lowercase())
        && field
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'.');

    if !is_safe_identifier {
        return Err(MaterializedViewError::InvalidRule(format!(
            "Invalid field name for DDL interpolation: '{}'. \
             Field names must match [a-z][a-z0-9_.]*",
            field
        )));
    }

    // Check if it's a known UDM field
    if field.parse::<UdmField>().is_ok() {
        return Ok(());
    }

    // Allow ext.* extension fields (e.g., ext.custom_field)
    if field.starts_with("ext.") && field.len() > 4 {
        return Ok(());
    }

    Err(MaterializedViewError::InvalidRule(format!(
        "Unknown field '{}' cannot be used in DDL. \
         Must be a valid UDM field name or an ext.* extension field.",
        field
    )))
}

/// Errors that can occur during materialized view operations
#[derive(Debug, Error)]
pub enum MaterializedViewError {
    #[error("ClickHouse error: {0}")]
    ClickHouseError(String),

    #[error("Invalid rule for real-time detection: {0}")]
    InvalidRule(String),

    #[error("Query parse error: {0}")]
    QueryParseError(String),

    #[error("DDL generation error: {0}")]
    DdlGenerationError(String),

    #[error("View already exists: {0}")]
    ViewAlreadyExists(String),

    #[error("View not found: {0}")]
    ViewNotFound(String),
}

/// Materialized View Generator
///
/// Generates and manages ClickHouse materialized views for real-time detection rules.
/// Materialized views automatically process incoming logs and write signals to the
/// signals table when matches occur.
///
/// Requirements: 4.1
pub struct MaterializedViewGenerator {
    /// ClickHouse client for DDL operations
    clickhouse_client: clickhouse::Client,
}

impl MaterializedViewGenerator {
    /// Create a new materialized view generator
    ///
    /// # Arguments
    /// * `clickhouse_client` - ClickHouse client for executing DDL statements
    ///
    /// Requirements: 4.1
    pub fn new(clickhouse_client: clickhouse::Client) -> Self {
        Self { clickhouse_client }
    }

    /// Generate materialized view name from rule ID
    ///
    /// Format: mv_rt_detection_{rule_id_without_hyphens}
    ///
    /// Example: mv_rt_detection_550e8400e29b41d4a716446655440000
    fn generate_view_name(rule: &DetectionRule) -> String {
        format!("mv_rt_detection_{}", rule.id.to_string().replace('-', ""))
    }

    /// Create a materialized view for a real-time detection rule
    ///
    /// This method generates the DDL for the materialized view and executes it
    /// in ClickHouse. The view will automatically process incoming logs and write
    /// signals to the signals table.
    ///
    /// # Arguments
    /// * `rule` - The detection rule to create a view for
    ///
    /// # Returns
    /// * `Ok(String)` - The name of the created view
    /// * `Err(MaterializedViewError)` - If the view creation fails
    ///
    /// Requirements: 4.1
    pub async fn create_view(&self, rule: &DetectionRule) -> Result<String, MaterializedViewError> {
        let view_name = Self::generate_view_name(rule);

        info!(
            "Creating materialized view {} for rule {}",
            view_name, rule.name
        );

        // Generate DDL
        let ddl = self.generate_view_ddl(rule)?;

        debug!("Generated DDL for view {}: {}", view_name, ddl);

        // Execute DDL
        self.clickhouse_client
            .query(&ddl)
            .execute()
            .await
            .map_err(|e| {
                // ALERTING: Log ERROR on materialized view creation failure (Requirement 9.4)
                tracing::error!(
                    view_name = %view_name,
                    rule_id = %rule.id,
                    rule_name = %rule.name,
                    error = %e,
                    "ALERT: Failed to create materialized view for real-time detection rule"
                );
                MaterializedViewError::ClickHouseError(format!(
                    "Failed to create materialized view: {}",
                    e
                ))
            })?;

        info!("Successfully created materialized view {}", view_name);

        Ok(view_name)
    }

    /// Drop a materialized view from ClickHouse
    ///
    /// # Arguments
    /// * `view_name` - The name of the view to drop
    ///
    /// # Returns
    /// * `Ok(())` - If the view was dropped successfully
    /// * `Err(MaterializedViewError)` - If the drop operation fails
    ///
    /// Requirements: 4.5
    pub async fn drop_view(&self, view_name: &str) -> Result<(), MaterializedViewError> {
        info!("Dropping materialized view {}", view_name);

        let ddl = format!("DROP VIEW IF EXISTS {}", view_name);

        self.clickhouse_client
            .query(&ddl)
            .execute()
            .await
            .map_err(|e| {
                error!("Failed to drop materialized view {}: {}", view_name, e);
                MaterializedViewError::ClickHouseError(format!(
                    "Failed to drop materialized view: {}",
                    e
                ))
            })?;

        info!("Successfully dropped materialized view {}", view_name);

        Ok(())
    }

    /// Recreate a materialized view (for rule updates)
    ///
    /// This method drops the existing view and creates a new one with the updated
    /// rule definition. This is necessary when a real-time rule is modified.
    ///
    /// # Arguments
    /// * `rule` - The updated detection rule
    ///
    /// # Returns
    /// * `Ok(String)` - The name of the recreated view
    /// * `Err(MaterializedViewError)` - If the recreation fails
    ///
    /// Requirements: 4.4
    pub async fn recreate_view(
        &self,
        rule: &DetectionRule,
    ) -> Result<String, MaterializedViewError> {
        let view_name = Self::generate_view_name(rule);

        info!(
            "Recreating materialized view {} for rule {}",
            view_name, rule.name
        );

        // Drop existing view (ignore errors if it doesn't exist)
        let _ = self.drop_view(&view_name).await;

        // Create new view
        self.create_view(rule).await.map_err(|e| {
            // ALERTING: Log ERROR on materialized view update failure (Requirement 9.4)
            tracing::error!(
                view_name = %view_name,
                rule_id = %rule.id,
                rule_name = %rule.name,
                error = %e,
                "ALERT: Failed to recreate materialized view for real-time detection rule update"
            );
            e
        })
    }

    /// Generate CREATE MATERIALIZED VIEW DDL statement
    ///
    /// This method parses the detection rule query, extracts filter conditions,
    /// and generates a ClickHouse materialized view DDL statement that writes
    /// matching logs to the signals table.
    ///
    /// # Arguments
    /// * `rule` - The detection rule to generate DDL for
    ///
    /// # Returns
    /// * `Ok(String)` - The generated DDL statement
    /// * `Err(MaterializedViewError)` - If DDL generation fails
    ///
    /// Requirements: 4.1
    pub fn generate_view_ddl(&self, rule: &DetectionRule) -> Result<String, MaterializedViewError> {
        // Parse the rule query
        let query = parse_query(&rule.query).map_err(|e| {
            MaterializedViewError::QueryParseError(format!("Failed to parse rule query: {}", e))
        })?;

        // Extract filter conditions from the query
        let where_clause = self.extract_where_clause(&query)?;

        // Get risk entity field - auto-detect if not specified or empty
        let risk_entity_field = match rule.risk_entity_field.as_ref() {
            Some(field) if !field.is_empty() => field.clone(),
            _ => {
                // Auto-detect by analyzing which fields are referenced in the query
                self.auto_detect_risk_entity(&where_clause)
            }
        };

        // Validate risk_entity_field before interpolating into DDL to prevent SQL injection.
        // An attacker could set risk_entity_field to a SQL expression like
        // `concat(currentDatabase(), ':', version())` to exfiltrate data.
        validate_ddl_field_name(&risk_entity_field)?;

        // Calculate risk score (use rule's risk_score or default based on severity).
        // Severity defaults are sourced from `crate::detection::risk` so the MV path
        // and the scheduled path can never drift apart.
        let risk_score = rule
            .risk_score
            .unwrap_or_else(|| default_score_for_severity(rule.severity));

        // Generate view name
        let view_name = Self::generate_view_name(rule);

        // Generate DDL
        let ddl = format!(
            r#"CREATE MATERIALIZED VIEW {} TO signals AS
SELECT
    generateUUIDv4() AS id,
    timestamp,
    '{}' AS rule_id,
    '{}' AS rule_name,
    '{}' AS severity,
    {} AS risk_score,
    {} AS risk_entity,
    logs.id AS matched_log_id,
    toJSONString(map()) AS metadata,
    now64(6) AS _inserted_at
FROM logs
WHERE {}
  AND timestamp >= now() - INTERVAL 1 HOUR"#,
            view_name,
            rule.id,
            rule.name.replace('\'', "''"), // Escape single quotes
            format!("{:?}", rule.severity).to_lowercase(),
            risk_score,
            risk_entity_field,
            where_clause
        );

        Ok(ddl)
    }

    /// Auto-detect the best risk entity field by analyzing the query
    ///
    /// Analyzes which UDM fields are referenced in the WHERE clause and picks
    /// the most appropriate one for risk scoring based on priority:
    /// 1. IP addresses (src_ip, dest_ip, dvc_ip, etc.)
    /// 2. Hostnames (src_host, dest_host, host, etc.)
    /// 3. Users (src_user, dest_user, user, etc.)
    /// 4. File hashes (file_hash, process_hash, service_hash, ssl_hash)
    ///
    /// # Arguments
    /// * `where_clause` - The SQL WHERE clause to analyze
    ///
    /// # Returns
    /// * The detected field name, or "src_ip" as default
    fn auto_detect_risk_entity(&self, where_clause: &str) -> String {
        // Priority order for risk entity fields (matching risk.rs)
        let priority_fields = [
            // IP addresses (highest priority)
            "src_ip",
            "dest_ip",
            "dvc_ip",
            "src_translated_ip",
            "dest_translated_ip",
            // Hostnames
            "src_host",
            "dest_host",
            "host",
            "hostname",
            "dest_nt_host",
            "src_nt_host",
            "dvc",
            // Users
            "src_user",
            "dest_user",
            "user",
            "src_user_name",
            "dest_user_name",
            // File hashes
            "file_hash",
            "process_hash",
            "service_hash",
            "service_dll_hash",
            "ssl_hash",
        ];

        // Check which fields are referenced in the query
        for field in &priority_fields {
            if where_clause.contains(field) {
                tracing::debug!(
                    "Auto-detected risk entity field: {} (found in query)",
                    field
                );
                return field.to_string();
            }
        }

        // Default to src_ip if no fields found
        tracing::debug!("Auto-detected risk entity field: src_ip (default)");
        "src_ip".to_string()
    }

    /// Check if a query string contains piped commands
    ///
    /// This is a quick check before parsing to determine if a query
    /// has piped commands that would make it incompatible with real-time mode.
    ///
    /// # Arguments
    /// * `query_str` - The query string to check
    ///
    /// # Returns
    /// * `true` if the query contains piped commands (|)
    /// * `false` if it's a simple filter query
    pub fn has_piped_commands(query_str: &str) -> bool {
        query_str.contains('|')
    }

    /// Extract WHERE clause from parsed query
    ///
    /// Converts the parsed query AST into a ClickHouse WHERE clause.
    /// Only supports simple filters (no aggregations, no joins).
    ///
    /// # Arguments
    /// * `query` - The parsed query AST
    ///
    /// # Returns
    /// * `Ok(String)` - The WHERE clause (without the WHERE keyword)
    /// * `Err(MaterializedViewError)` - If the query contains unsupported features
    ///
    /// Requirements: 4.1
    fn extract_where_clause(&self, query: &Query) -> Result<String, MaterializedViewError> {
        match query {
            Query::Search(search_expr) => self.search_expr_to_sql(search_expr),
            Query::Piped { .. } => Err(MaterializedViewError::InvalidRule(
                "Real-time rules cannot contain piped commands (stats, where, etc.)".to_string(),
            )),
        }
    }

    /// Convert search expression to SQL WHERE clause
    ///
    /// Recursively converts the search expression AST to SQL.
    ///
    /// # Arguments
    /// * `expr` - The search expression to convert
    ///
    /// # Returns
    /// * `Ok(String)` - The SQL WHERE clause
    /// * `Err(MaterializedViewError)` - If the expression contains unsupported features
    fn search_expr_to_sql(&self, expr: &SearchExpr) -> Result<String, MaterializedViewError> {
        match expr {
            SearchExpr::FieldFilter { field, op, value } => {
                self.field_filter_to_sql(field, op, value)
            }
            SearchExpr::And(left, right) => {
                let left_sql = self.search_expr_to_sql(left)?;
                let right_sql = self.search_expr_to_sql(right)?;
                Ok(format!("({} AND {})", left_sql, right_sql))
            }
            SearchExpr::Or(left, right) => {
                let left_sql = self.search_expr_to_sql(left)?;
                let right_sql = self.search_expr_to_sql(right)?;
                Ok(format!("({} OR {})", left_sql, right_sql))
            }
            SearchExpr::Not(inner) => {
                let inner_sql = self.search_expr_to_sql(inner)?;
                Ok(format!("NOT ({})", inner_sql))
            }
            SearchExpr::Group(inner) => {
                let inner_sql = self.search_expr_to_sql(inner)?;
                Ok(format!("({})", inner_sql))
            }
            SearchExpr::FunctionFilter {
                function,
                op,
                value,
            } => {
                // Convert function call to SQL and apply comparison
                let func_sql = self.eval_expression_to_sql(function)?;
                let value_sql = self.value_to_sql(value)?;
                let op_sql = match op {
                    Comparator::Eq => "=",
                    Comparator::Ne => "!=",
                    Comparator::Gt => ">",
                    Comparator::Lt => "<",
                    Comparator::Gte => ">=",
                    Comparator::Lte => "<=",
                    _ => {
                        return Err(MaterializedViewError::DdlGenerationError(format!(
                            "Unsupported operator for function filter: {:?}",
                            op
                        )))
                    }
                };
                Ok(format!("{} {} {}", func_sql, op_sql, value_sql))
            }
            SearchExpr::FieldFunctionFilter {
                field,
                op,
                function,
            } => {
                // Convert field op function(args) to SQL
                let field_sql = format!("JSONExtractString(metadata, '{}')", field);
                let func_sql = self.eval_expression_to_sql(function)?;
                let op_sql = match op {
                    Comparator::Eq => "=",
                    Comparator::Ne => "!=",
                    Comparator::Gt => ">",
                    Comparator::Lt => "<",
                    Comparator::Gte => ">=",
                    Comparator::Lte => "<=",
                    _ => {
                        return Err(MaterializedViewError::DdlGenerationError(format!(
                            "Unsupported operator for field function filter: {:?}",
                            op
                        )))
                    }
                };
                Ok(format!("{} {} {}", field_sql, op_sql, func_sql))
            }
            SearchExpr::InList {
                field,
                values,
                negated,
            } => self.in_list_to_sql(field, values, *negated),
            SearchExpr::Keyword(_) => Err(MaterializedViewError::InvalidRule(
                "Real-time rules cannot use keyword search (requires full-text search)".to_string(),
            )),
            SearchExpr::BooleanFunction(function) => {
                // Standalone boolean function predicate (e.g., isnull(field))
                let func_sql = self.eval_expression_to_sql(function)?;
                Ok(func_sql)
            }
            SearchExpr::LiteralComparison { left, op, right } => {
                // Literal string comparison - e.g., "$user"="*"
                // These are typically used for parameter expansion and evaluate at runtime
                let value_sql = self.value_to_sql(right)?;
                let op_sql = match op {
                    Comparator::Eq => "=",
                    Comparator::Ne => "!=",
                    _ => {
                        return Err(MaterializedViewError::DdlGenerationError(format!(
                            "Unsupported operator for literal comparison: {:?}",
                            op
                        )))
                    }
                };
                Ok(format!(
                    "'{}' {} {}",
                    left.replace('\'', "''"),
                    op_sql,
                    value_sql
                ))
            }
            SearchExpr::InSubsearch { .. } => Err(MaterializedViewError::InvalidRule(
                "Real-time rules cannot use subsearch (IN [...])".to_string(),
            )),
        }
    }

    /// Convert field filter to SQL
    fn field_filter_to_sql(
        &self,
        field: &str,
        op: &Comparator,
        value: &crate::query::Value,
    ) -> Result<String, MaterializedViewError> {
        let value_sql = self.value_to_sql(value)?;

        let sql = match op {
            Comparator::Eq => format!("{} = {}", field, value_sql),
            Comparator::Ne => format!("{} != {}", field, value_sql),
            Comparator::Gt => format!("{} > {}", field, value_sql),
            Comparator::Lt => format!("{} < {}", field, value_sql),
            Comparator::Gte => format!("{} >= {}", field, value_sql),
            Comparator::Lte => format!("{} <= {}", field, value_sql),
            Comparator::Regex => {
                if let crate::query::Value::Regex(pattern) = value {
                    format!("match({}, '{}')", field, pattern.replace('\'', "''"))
                } else {
                    return Err(MaterializedViewError::DdlGenerationError(
                        "Regex comparator requires regex value".to_string(),
                    ));
                }
            }
            Comparator::NotRegex => {
                if let crate::query::Value::Regex(pattern) = value {
                    // Use match() = 0 instead of NOT match() — ClickHouse optimizer bug
                    format!("match({}, '{}') = 0", field, pattern.replace('\'', "''"))
                } else {
                    return Err(MaterializedViewError::DdlGenerationError(
                        "NotRegex comparator requires regex value".to_string(),
                    ));
                }
            }
            Comparator::Like => format!("{} LIKE {}", field, value_sql),
            Comparator::NotLike => format!("{} NOT LIKE {}", field, value_sql),
            Comparator::Contains => {
                if let crate::query::Value::String(s) = value {
                    format!("position({}, '{}') > 0", field, s.replace('\'', "''"))
                } else {
                    return Err(MaterializedViewError::DdlGenerationError(
                        "Contains comparator requires string value".to_string(),
                    ));
                }
            }
            Comparator::NotContains => {
                if let crate::query::Value::String(s) = value {
                    format!("NOT (position({}, '{}') > 0)", field, s.replace('\'', "''"))
                } else {
                    return Err(MaterializedViewError::DdlGenerationError(
                        "NotContains comparator requires string value".to_string(),
                    ));
                }
            }
            Comparator::StartsWith => {
                if let crate::query::Value::String(s) = value {
                    format!("startsWith({}, '{}')", field, s.replace('\'', "''"))
                } else {
                    return Err(MaterializedViewError::DdlGenerationError(
                        "StartsWith comparator requires string value".to_string(),
                    ));
                }
            }
            Comparator::NotStartsWith => {
                if let crate::query::Value::String(s) = value {
                    format!("NOT startsWith({}, '{}')", field, s.replace('\'', "''"))
                } else {
                    return Err(MaterializedViewError::DdlGenerationError(
                        "NotStartsWith comparator requires string value".to_string(),
                    ));
                }
            }
            Comparator::EndsWith => {
                if let crate::query::Value::String(s) = value {
                    format!("endsWith({}, '{}')", field, s.replace('\'', "''"))
                } else {
                    return Err(MaterializedViewError::DdlGenerationError(
                        "EndsWith comparator requires string value".to_string(),
                    ));
                }
            }
            Comparator::NotEndsWith => {
                if let crate::query::Value::String(s) = value {
                    format!("NOT endsWith({}, '{}')", field, s.replace('\'', "''"))
                } else {
                    return Err(MaterializedViewError::DdlGenerationError(
                        "NotEndsWith comparator requires string value".to_string(),
                    ));
                }
            }
        };

        Ok(sql)
    }

    /// Convert IN list to SQL
    fn in_list_to_sql(
        &self,
        field: &str,
        values: &[crate::query::Value],
        negated: bool,
    ) -> Result<String, MaterializedViewError> {
        let values_sql: Result<Vec<String>, _> =
            values.iter().map(|v| self.value_to_sql(v)).collect();

        let values_sql = values_sql?;
        let values_list = values_sql.join(", ");

        if negated {
            Ok(format!("{} NOT IN ({})", field, values_list))
        } else {
            Ok(format!("{} IN ({})", field, values_list))
        }
    }

    /// Convert value to SQL literal
    fn value_to_sql(&self, value: &crate::query::Value) -> Result<String, MaterializedViewError> {
        match value {
            crate::query::Value::String(s) => Ok(format!("'{}'", s.replace('\'', "''"))),
            crate::query::Value::Number(n) => Ok(n.to_string()),
            crate::query::Value::Bool(b) => Ok(if *b { "1".to_string() } else { "0".to_string() }),
            crate::query::Value::Ip(ip) => Ok(format!("'{}'", ip)),
            crate::query::Value::Regex(pattern) => Ok(format!("'{}'", pattern.replace('\'', "''"))),
            crate::query::Value::Interval(duration, unit) => {
                let seconds = duration.as_secs();
                match unit {
                    crate::query::IntervalUnit::Microsecond => {
                        Ok(format!("INTERVAL {} MICROSECOND", seconds * 1_000_000))
                    }
                    crate::query::IntervalUnit::Millisecond => {
                        Ok(format!("INTERVAL {} MILLISECOND", seconds * 1_000))
                    }
                    crate::query::IntervalUnit::Second => {
                        Ok(format!("INTERVAL {} SECOND", seconds))
                    }
                    crate::query::IntervalUnit::Minute => {
                        Ok(format!("INTERVAL {} MINUTE", seconds / 60))
                    }
                    crate::query::IntervalUnit::Hour => {
                        Ok(format!("INTERVAL {} HOUR", seconds / 3600))
                    }
                    crate::query::IntervalUnit::Day => {
                        Ok(format!("INTERVAL {} DAY", seconds / 86400))
                    }
                    crate::query::IntervalUnit::Week => {
                        Ok(format!("INTERVAL {} WEEK", seconds / 604800))
                    }
                    crate::query::IntervalUnit::Month => {
                        Ok(format!("INTERVAL {} MONTH", seconds / 2592000))
                    }
                    crate::query::IntervalUnit::Year => {
                        Ok(format!("INTERVAL {} YEAR", seconds / 31536000))
                    }
                }
            }
        }
    }

    /// Convert eval expression to SQL for function calls in materialized views
    fn eval_expression_to_sql(
        &self,
        expr: &crate::query::EvalExpression,
    ) -> Result<String, MaterializedViewError> {
        use crate::query::EvalExpression;

        match expr {
            EvalExpression::Field(field) => Ok(field.clone()),
            EvalExpression::Literal(value) => self.value_to_sql(value),
            EvalExpression::FunctionCall { name, args } => {
                let arg_sqls: Result<Vec<String>, _> = args
                    .iter()
                    .map(|arg| self.eval_expression_to_sql(arg))
                    .collect();
                let arg_sqls = arg_sqls?;

                // Map function names to ClickHouse equivalents
                let clickhouse_func = match name.as_str() {
                    // Date/time functions
                    "now" => "now64(6)",
                    "year" => "toYear",
                    "month" => "toMonth",
                    "day" => "toDayOfMonth",
                    "hour" => "toHour",
                    "minute" => "toMinute",
                    "second" => "toSecond",
                    "dayofweek" => "toDayOfWeek",
                    "dayofyear" => "toDayOfYear",
                    "weekofyear" => "toWeek",
                    "date_add" => "addInterval",
                    "date_sub" => "subtractInterval",
                    "date_format" => "formatDateTime",
                    "date_trunc" => "date_trunc",
                    "unix_timestamp" => "toUnixTimestamp",
                    "from_unixtime" => "fromUnixTimestamp",

                    // String functions
                    "upper" => "upper",
                    "lower" => "lower",
                    "length" => "length",
                    "substr" => "substring",
                    "substring" => "substring",
                    "concat" => "concat",
                    "replace" => "replaceAll",
                    "trim" => "trim",
                    "ltrim" => "trimLeft",
                    "rtrim" => "trimRight",

                    // Math functions
                    "abs" => "abs",
                    "ceil" => "ceil",
                    "floor" => "floor",
                    "round" => "round",
                    "sqrt" => "sqrt",
                    "pow" => "pow",

                    // Conditional functions
                    "if" => "if",
                    "case" => "multiIf",
                    "coalesce" => "coalesce",
                    "nullif" => "nullIf",

                    // Type conversion
                    "tostring" => "toString",
                    "tonumber" => "toFloat64OrNull",
                    "toint" => "toInt64OrNull",

                    // Pass through unknown functions (might be ClickHouse-specific)
                    other => other,
                };

                if arg_sqls.is_empty() && clickhouse_func == "now64(6)" {
                    Ok(clickhouse_func.to_string())
                } else {
                    Ok(format!("{}({})", clickhouse_func, arg_sqls.join(", ")))
                }
            }
            EvalExpression::BinaryOp { left, op, right } => {
                let left_sql = self.eval_expression_to_sql(left)?;
                let right_sql = self.eval_expression_to_sql(right)?;
                let op_sql = match op {
                    crate::query::BinaryOperator::Add => "+",
                    crate::query::BinaryOperator::Sub => "-",
                    crate::query::BinaryOperator::Mul => "*",
                    crate::query::BinaryOperator::Div => "/",
                    crate::query::BinaryOperator::Mod => "%",
                    crate::query::BinaryOperator::Concat => "||",
                    crate::query::BinaryOperator::Eq => "=",
                    crate::query::BinaryOperator::Ne => "!=",
                    crate::query::BinaryOperator::Lt => "<",
                    crate::query::BinaryOperator::Lte => "<=",
                    crate::query::BinaryOperator::Gt => ">",
                    crate::query::BinaryOperator::Gte => ">=",
                    crate::query::BinaryOperator::And => "AND",
                    crate::query::BinaryOperator::Or => "OR",
                    crate::query::BinaryOperator::Contains | crate::query::BinaryOperator::Like => {
                        ""
                    }
                };
                match op {
                    crate::query::BinaryOperator::Contains => {
                        Ok(format!("(position({}, {}) > 0)", left_sql, right_sql))
                    }
                    crate::query::BinaryOperator::Like => {
                        Ok(format!("({} LIKE {})", left_sql, right_sql))
                    }
                    _ => Ok(format!("({} {} {})", left_sql, op_sql, right_sql)),
                }
            }
        }
    }
}

#[cfg(any())]
mod tests {
    use super::*;
    use crate::models::detection_rule::{DetectionMode, DetectionRule, Severity};
    use chrono::Utc;
    use uuid::Uuid;

    fn create_test_rule() -> DetectionRule {
        DetectionRule {
            id: Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").unwrap(),
            name: "Test Rule".to_string(),
            description: Some("Test description".to_string()),
            query: "dest_ip=\"192.0.2.1\"".to_string(),
            severity: Severity::High,
            mitre_tactics: vec![],
            mitre_techniques: vec![],
            schedule_cron: None,
            enabled: true,
            mode: crate::models::detection_rule::RuleMode::Alerting,
            narrative: None,
            reference_url: None,
            author: None,
            tags: vec![],
            ai_generated: false,
            realtime_enabled: false,
            detection_mode: DetectionMode::RealTime,
            materialized_view_name: None,
            risk_score: Some(75),
            risk_entity_field: Some("src_ip".to_string()),
            risk_modifiers: sqlx::types::Json(vec![]),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            last_run_at: None,
            last_match_at: None,
            match_count: 0,
            live_match_count: 0,
            archived: false,
            lookback_minutes: None,
            auto_tuning_enabled: true,
            auto_tuning_min_confidence: 0.8,
            auto_tuning_critical: false,
            auto_tuning_disabled_until: None,
        }
    }

    #[test]
    fn test_generate_view_name() {
        let rule = create_test_rule();
        let view_name = MaterializedViewGenerator::generate_view_name(&rule);
        assert_eq!(
            view_name,
            "mv_rt_detection_550e8400e29b41d4a716446655440000"
        );
    }

    #[test]
    fn test_generate_view_ddl_simple_filter() {
        let rule = create_test_rule();
        let generator = MaterializedViewGenerator::new(clickhouse::Client::default());

        let ddl = generator.generate_view_ddl(&rule).unwrap();

        assert!(ddl
            .contains("CREATE MATERIALIZED VIEW mv_rt_detection_550e8400e29b41d4a716446655440000"));
        assert!(ddl.contains("TO signals"));
        assert!(ddl.contains("dest_ip = '192.0.2.1'"));
        assert!(ddl.contains("src_ip AS risk_entity"));
        assert!(ddl.contains("75 AS risk_score"));
    }

    #[test]
    fn test_generate_view_ddl_auto_detects_risk_entity() {
        let mut rule = create_test_rule();
        rule.risk_entity_field = None; // Should auto-detect based on query

        let generator = MaterializedViewGenerator::new(clickhouse::Client::default());
        let result = generator.generate_view_ddl(&rule);

        assert!(result.is_ok(), "Should succeed with auto-detection");
        let ddl = result.unwrap();
        // Query has dest_ip, so should auto-detect dest_ip
        assert!(
            ddl.contains("dest_ip AS risk_entity"),
            "Should auto-detect dest_ip as risk entity from query"
        );
    }

    #[test]
    fn test_auto_detect_src_ip() {
        let mut rule = create_test_rule();
        rule.query = "src_ip=\"10.0.0.1\"".to_string();
        rule.risk_entity_field = None;

        let generator = MaterializedViewGenerator::new(clickhouse::Client::default());
        let result = generator.generate_view_ddl(&rule);

        assert!(result.is_ok());
        let ddl = result.unwrap();
        assert!(
            ddl.contains("src_ip AS risk_entity"),
            "Should detect src_ip from query"
        );
    }

    #[test]
    fn test_auto_detect_src_user() {
        let mut rule = create_test_rule();
        rule.query = "src_user=\"alice\"".to_string();
        rule.risk_entity_field = None;

        let generator = MaterializedViewGenerator::new(clickhouse::Client::default());
        let result = generator.generate_view_ddl(&rule);

        assert!(result.is_ok());
        let ddl = result.unwrap();
        assert!(
            ddl.contains("src_user AS risk_entity"),
            "Should detect src_user from query"
        );
    }

    #[test]
    fn test_auto_detect_user() {
        let mut rule = create_test_rule();
        rule.query = "user=\"bob\" AND action=\"login\"".to_string();
        rule.risk_entity_field = None;

        let generator = MaterializedViewGenerator::new(clickhouse::Client::default());
        let result = generator.generate_view_ddl(&rule);

        assert!(result.is_ok());
        let ddl = result.unwrap();
        assert!(
            ddl.contains("user AS risk_entity"),
            "Should detect user from query"
        );
    }

    #[test]
    fn test_auto_detect_empty_string() {
        let mut rule = create_test_rule();
        rule.query = "src_user=\"alice\"".to_string();
        rule.risk_entity_field = Some("".to_string()); // Empty string should trigger auto-detect

        let generator = MaterializedViewGenerator::new(clickhouse::Client::default());
        let result = generator.generate_view_ddl(&rule);

        assert!(result.is_ok());
        let ddl = result.unwrap();
        assert!(
            ddl.contains("src_user AS risk_entity"),
            "Empty string should trigger auto-detection"
        );
    }

    #[test]
    fn test_generate_view_ddl_with_and() {
        let mut rule = create_test_rule();
        rule.query = "dest_ip=\"192.0.2.1\" AND dest_port=443".to_string();

        let generator = MaterializedViewGenerator::new(clickhouse::Client::default());
        let ddl = generator.generate_view_ddl(&rule).unwrap();

        assert!(ddl.contains("dest_ip = '192.0.2.1' AND dest_port = 443"));
    }

    #[test]
    fn test_generate_view_ddl_with_or() {
        let mut rule = create_test_rule();
        rule.query = "dest_ip=\"192.0.2.1\" OR dest_ip=\"198.51.100.1\"".to_string();

        let generator = MaterializedViewGenerator::new(clickhouse::Client::default());
        let ddl = generator.generate_view_ddl(&rule).unwrap();

        assert!(ddl.contains("dest_ip = '192.0.2.1' OR dest_ip = '198.51.100.1'"));
    }

    #[test]
    fn test_generate_view_ddl_with_in_list() {
        let mut rule = create_test_rule();
        rule.query = "dest_ip IN (\"192.0.2.1\", \"198.51.100.1\", \"203.0.113.1\")".to_string();

        let generator = MaterializedViewGenerator::new(clickhouse::Client::default());
        let ddl = generator.generate_view_ddl(&rule).unwrap();

        assert!(ddl.contains("dest_ip IN ('192.0.2.1', '198.51.100.1', '203.0.113.1')"));
    }

    #[test]
    fn test_generate_view_ddl_rejects_piped_commands() {
        let mut rule = create_test_rule();
        rule.query = "dest_ip=\"192.0.2.1\" | stats count by src_ip".to_string();

        let generator = MaterializedViewGenerator::new(clickhouse::Client::default());
        let result = generator.generate_view_ddl(&rule);

        assert!(result.is_err());
        match result.unwrap_err() {
            MaterializedViewError::InvalidRule(_) => {}
            e => panic!("Expected InvalidRule error, got: {:?}", e),
        }
    }

    #[test]
    fn test_generate_view_ddl_rejects_keyword_search() {
        let mut rule = create_test_rule();
        rule.query = "malware".to_string();

        let generator = MaterializedViewGenerator::new(clickhouse::Client::default());
        let result = generator.generate_view_ddl(&rule);

        assert!(result.is_err());
        match result.unwrap_err() {
            MaterializedViewError::InvalidRule(_) => {}
            e => panic!("Expected InvalidRule error, got: {:?}", e),
        }
    }

    // --- SQL injection prevention tests ---

    #[test]
    fn test_validate_ddl_field_name_accepts_udm_fields() {
        assert!(validate_ddl_field_name("src_ip").is_ok());
        assert!(validate_ddl_field_name("dest_ip").is_ok());
        assert!(validate_ddl_field_name("user").is_ok());
        assert!(validate_ddl_field_name("src_host").is_ok());
        assert!(validate_ddl_field_name("process_name").is_ok());
    }

    #[test]
    fn test_validate_ddl_field_name_accepts_ext_fields() {
        assert!(validate_ddl_field_name("ext.custom_field").is_ok());
        assert!(validate_ddl_field_name("ext.my_app_status").is_ok());
    }

    #[test]
    fn test_validate_ddl_field_name_rejects_sql_injection() {
        // The specific attack vector from the issue
        assert!(validate_ddl_field_name("concat(currentDatabase(), ':', version())").is_err());
        // Other injection attempts
        assert!(validate_ddl_field_name("1; DROP TABLE logs--").is_err());
        assert!(validate_ddl_field_name("src_ip' OR '1'='1").is_err());
        assert!(validate_ddl_field_name("toString(now())").is_err());
        assert!(validate_ddl_field_name("").is_err());
        assert!(validate_ddl_field_name("SRC_IP").is_err()); // uppercase not allowed
    }

    #[test]
    fn test_validate_ddl_field_name_rejects_unknown_fields() {
        // Valid identifier format but not a known UDM field or ext.* field
        assert!(validate_ddl_field_name("not_a_real_field").is_err());
        assert!(validate_ddl_field_name("ext.").is_err()); // ext. with nothing after
    }

    #[test]
    fn test_generate_view_ddl_rejects_malicious_risk_entity_field() {
        let mut rule = create_test_rule();
        rule.risk_entity_field = Some("concat(currentDatabase(), ':', version())".to_string());

        let generator = MaterializedViewGenerator::new(clickhouse::Client::default());
        let result = generator.generate_view_ddl(&rule);

        assert!(
            result.is_err(),
            "Should reject SQL injection in risk_entity_field"
        );
        let err = result.unwrap_err();
        match err {
            MaterializedViewError::InvalidRule(msg) => {
                assert!(
                    msg.contains("concat"),
                    "Error should mention the invalid field: {}",
                    msg
                );
            }
            e => panic!("Expected InvalidRule error, got: {:?}", e),
        }
    }
}
