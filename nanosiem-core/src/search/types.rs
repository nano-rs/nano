// SPDX-License-Identifier: AGPL-3.0-or-later

//! Types for search service responses
//!
//! Defines the structured response types for search results,
//! field statistics, and query execution metadata.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use thiserror::Error;

/// Errors that can occur during search execution
#[derive(Debug, Error)]
pub enum SearchError {
    #[error("Query parse error: {0}")]
    ParseError(String),
    #[error("{formatted}")]
    StructuredParseError {
        message: String,
        position: usize,
        line: usize,
        column: usize,
        token: Option<String>,
        expected: Vec<String>,
        suggestions: Vec<ErrorSuggestion>,
        formatted: String,
    },
    #[error("Field not found: {field}")]
    FieldNotFound {
        field: String,
        suggestions: Vec<String>,
        message: String,
    },
    #[error("SQL generation error: {0}")]
    SqlGenError(String),
    #[error("Database error: {0}")]
    DatabaseError(#[from] sqlx::Error),
    #[error("Query timeout after {0}ms")]
    Timeout(u64),
    #[error("Invalid time range: start must be before end")]
    InvalidTimeRange,
    #[error("SQL validation error: {0}")]
    SqlValidationError(String),
    #[error("Prevalence error: {0}")]
    PrevalenceError(String),
    #[error("Response too large: {0} bytes exceeds limit of {1} bytes")]
    ResponseTooLarge(usize, usize),
    #[error("Admission denied: {0}")]
    AdmissionDenied(String),
    /// The query was killed (`KILL QUERY` via the search-cancel endpoint, or an
    /// admin kill) — ClickHouse error code 394 / `QUERY_WAS_CANCELLED`.
    /// Distinct from the generic `DatabaseError` so the HTTP layer can return
    /// a deliberate status instead of a misleading 500 (NAN-1436).
    #[error("Query was cancelled")]
    Cancelled,
}

/// Parse a ClickHouse error message and convert to a user-friendly SearchError
pub fn parse_clickhouse_error(error_msg: &str) -> SearchError {
    // Pattern: Code 394 — the query was killed (search cancel / KILL QUERY).
    // Checked first: it is the most specific signal and must not fall through
    // to the generic DatabaseError mapping, which the HTTP layer renders as a
    // misleading 500 INTERNAL_ERROR for what was a deliberate cancellation
    // (NAN-1435 made cancel actually kill queries; NAN-1436 maps the result).
    // Message shapes: "Query was cancelled" / "Query was cancelled or a client
    // has disconnected" + "(QUERY_WAS_CANCELLED)".
    if error_msg.contains("QUERY_WAS_CANCELLED") || error_msg.contains("Query was cancelled") {
        return SearchError::Cancelled;
    }

    // Pattern: "Unknown expression identifier `field_name` ... Maybe you meant: ['suggestion1', 'suggestion2']"
    if error_msg.contains("Unknown expression identifier")
        || error_msg.contains("UNKNOWN_IDENTIFIER")
    {
        // Extract field name from backticks
        if let Some(start) = error_msg.find('`') {
            if let Some(end) = error_msg[start + 1..].find('`') {
                let field = error_msg[start + 1..start + 1 + end].to_string();

                // Extract suggestions from "Maybe you meant: ['field1', 'field2']"
                let mut suggestions = Vec::new();
                if let Some(meant_pos) = error_msg.find("Maybe you meant:") {
                    let after_meant = &error_msg[meant_pos..];
                    if let Some(bracket_start) = after_meant.find('[') {
                        if let Some(bracket_end) = after_meant.find(']') {
                            let suggestions_str = &after_meant[bracket_start + 1..bracket_end];
                            suggestions = suggestions_str
                                .split(',')
                                .map(|s| s.trim().trim_matches('\'').trim_matches('"').to_string())
                                .filter(|s| !s.is_empty())
                                .collect();
                        }
                    }
                }

                let message = if suggestions.is_empty() {
                    format!("Field '{}' does not exist in the data.", field)
                } else if suggestions.len() == 1 {
                    format!(
                        "Field '{}' does not exist. Did you mean '{}'?",
                        field, suggestions[0]
                    )
                } else {
                    format!(
                        "Field '{}' does not exist. Did you mean one of: {}?",
                        field,
                        suggestions
                            .iter()
                            .map(|s| format!("'{}'", s))
                            .collect::<Vec<_>>()
                            .join(", ")
                    )
                };

                return SearchError::FieldNotFound {
                    field,
                    suggestions,
                    message,
                };
            }
        }
    }

    // Pattern: "Unknown column `field_name`" (alternative ClickHouse error format)
    if error_msg.contains("Unknown column") {
        if let Some(start) = error_msg.find('`') {
            if let Some(end) = error_msg[start + 1..].find('`') {
                let field = error_msg[start + 1..start + 1 + end].to_string();
                return SearchError::FieldNotFound {
                    field: field.clone(),
                    suggestions: vec![],
                    message: format!("Field '{}' does not exist in the data.", field),
                };
            }
        }
    }

    // Pattern: Type mismatch - "no supertype for types String, UInt16" or "NO_COMMON_TYPE"
    if error_msg.contains("no supertype for types") || error_msg.contains("NO_COMMON_TYPE") {
        // Try to extract the field and types involved
        let message = if error_msg.contains("String")
            && (error_msg.contains("UInt")
                || error_msg.contains("Int")
                || error_msg.contains("Float"))
        {
            "Type mismatch: cannot compare text field with a number. The field may contain text values. Try using tonumber() to convert it.".to_string()
        } else {
            "Type mismatch: cannot compare values of different types.".to_string()
        };
        return SearchError::SqlValidationError(message);
    }

    // Pattern: Unknown function
    if error_msg.contains("Unknown function") || error_msg.contains("UNKNOWN_FUNCTION") {
        if let Some(start) = error_msg.find('`') {
            if let Some(end) = error_msg[start + 1..].find('`') {
                let func = error_msg[start + 1..start + 1 + end].to_string();
                return SearchError::SqlValidationError(
                    format!("Unknown function '{}'. Check the function name or see documentation for available functions.", func)
                );
            }
        }
        return SearchError::SqlValidationError("Unknown function. Check the function name or see documentation for available functions.".to_string());
    }

    // Pattern: Illegal aggregation - aggregate in GROUP BY
    if error_msg.contains("ILLEGAL_AGGREGATION")
        || error_msg.contains("Aggregate function") && error_msg.contains("GROUP BY")
    {
        return SearchError::SqlValidationError(
            "Invalid query: cannot use an aggregate function (like count, sum, avg) in a GROUP BY clause. Remove the aggregate from GROUP BY or use it only in the SELECT.".to_string()
        );
    }

    // Pattern: Syntax error
    if error_msg.contains("Syntax error") || error_msg.contains("SYNTAX_ERROR") {
        // Try to extract position info
        let message = if let Some(pos) = error_msg.find("at position") {
            let snippet = &error_msg[pos..].chars().take(50).collect::<String>();
            format!("Query syntax error {}. Check for missing commas, parentheses, or invalid keywords.", snippet)
        } else {
            "Query syntax error. Check for missing commas, parentheses, or invalid keywords."
                .to_string()
        };
        return SearchError::SqlValidationError(message);
    }

    // Pattern: Memory limit exceeded
    if error_msg.contains("MEMORY_LIMIT_EXCEEDED") || error_msg.contains("Memory limit") {
        return SearchError::SqlValidationError(
            "Query exceeded memory limit. Try adding more filters, reducing the time range, or using sampling.".to_string()
        );
    }

    // Pattern: Timeout
    if error_msg.contains("TIMEOUT_EXCEEDED")
        || error_msg.contains("timeout") && error_msg.contains("exceeded")
    {
        // NAN-1653: surface the real elapsed instead of a misleading "0ms".
        // ClickHouse phrases it as "elapsed 10030.034392 ms, maximum: 10000 ms".
        return SearchError::Timeout(parse_elapsed_ms(error_msg).unwrap_or(0));
    }

    // Pattern: Division by zero
    if error_msg.contains("ILLEGAL_DIVISION") || error_msg.contains("division by zero") {
        return SearchError::SqlValidationError(
            "Division by zero error. Use nullif() or add a condition to avoid dividing by zero."
                .to_string(),
        );
    }

    // Pattern: Invalid regex
    if error_msg.contains("invalid regular expression")
        || error_msg.contains("CANNOT_COMPILE_REGEXP")
    {
        return SearchError::SqlValidationError(
            "Invalid regular expression pattern. Check your regex syntax - common issues include unescaped special characters.".to_string()
        );
    }

    // Pattern: Too many rows / result too large
    if error_msg.contains("TOO_MANY_ROWS") || error_msg.contains("too many rows") {
        return SearchError::SqlValidationError(
            "Query returned too many rows. Add more filters or use head/limit to reduce the result size.".to_string()
        );
    }

    // Pattern: Number of arguments mismatch
    if error_msg.contains("NUMBER_OF_ARGUMENTS_DOESNT_MATCH")
        || error_msg.contains("requires") && error_msg.contains("argument")
    {
        // Try to extract function name
        if let Some(start) = error_msg.find("Function ") {
            let after = &error_msg[start + 9..];
            if let Some(end) = after.find(' ') {
                let func = after[..end].trim_matches('\'').to_string();
                return SearchError::SqlValidationError(
                    format!("Wrong number of arguments for function '{}'. Check the function documentation for correct usage.", func)
                );
            }
        }
        return SearchError::SqlValidationError(
            "Wrong number of arguments for function. Check the function documentation for correct usage.".to_string()
        );
    }

    // Default: return as DatabaseError but with cleaned up message
    let cleaned_msg = clean_clickhouse_error(error_msg);
    SearchError::DatabaseError(sqlx::Error::Protocol(cleaned_msg))
}

/// Extract the elapsed milliseconds from a ClickHouse timeout message so the
/// surfaced error reports the real duration rather than a misleading `0ms`
/// (NAN-1653). ClickHouse phrases it as `elapsed 10030.034392 ms, maximum: …`.
/// Returns `None` when the message doesn't carry an `elapsed <n> ms` clause.
fn parse_elapsed_ms(error_msg: &str) -> Option<u64> {
    let after = error_msg.split("elapsed ").nth(1)?;
    let num = after.split(" ms").next()?.trim();
    num.parse::<f64>().ok().map(|ms| ms as u64)
}

/// Clean up a ClickHouse error message to be more user-friendly
fn clean_clickhouse_error(error_msg: &str) -> String {
    // Remove version info like "(version 25.8.13.73 (official build))"
    let cleaned = if let Some(pos) = error_msg.find("(version") {
        error_msg[..pos].trim().to_string()
    } else {
        error_msg.to_string()
    };

    // Remove "bad response:" prefix if present
    let cleaned = cleaned
        .replace("bad response:", "")
        .replace("Error reading ClickHouse response:", "")
        .trim()
        .to_string();

    // Try to extract just the exception message
    if let Some(start) = cleaned.find("DB::Exception:") {
        let after = &cleaned[start + 14..];
        // Find the error code at the end like "(UNKNOWN_IDENTIFIER)"
        if let Some(end) = after.rfind('(') {
            return after[..end].trim().to_string();
        }
        return after.trim().to_string();
    }

    cleaned
}

/// A suggested fix for a parse error
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct ErrorSuggestion {
    /// Description of the fix
    pub description: String,
    /// The corrected query snippet
    pub replacement: String,
}

/// Input for search requests
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct SearchRequest {
    /// The piped query string
    pub query: String,
    /// Time range for the search
    pub time_range: TimeRangeInput,
    /// Maximum number of results to return
    pub limit: Option<usize>,
    /// Offset for pagination
    pub offset: Option<usize>,
    /// Whether to include the generated SQL in the response
    pub include_sql: Option<bool>,
    /// Skip histogram generation (useful for detection execution where histogram isn't needed)
    #[serde(default)]
    pub skip_histogram: bool,
    /// Skip field statistics generation (useful for detection execution)
    #[serde(default)]
    pub skip_field_stats: bool,
    /// Enable query cache (useful for shared searches with fixed time ranges)
    /// When true, adds SETTINGS use_query_cache=1, query_cache_ttl=300
    #[serde(default)]
    pub use_cache: bool,
    /// Table view mode - only return minimal columns (id, timestamp, source_type, message + query fields)
    /// Full row data is fetched on demand when user expands a row
    #[serde(default)]
    pub table_view: bool,
    /// Client-generated request ID for query tracking and cancellation
    /// When provided, the query can be cancelled via DELETE /api/search/:request_id
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
    /// Run query asynchronously. Returns job_id immediately for polling.
    /// Use for long-running queries to avoid HTTP timeout issues.
    #[serde(default)]
    pub async_mode: bool,
    /// Query priority for admission control. Defaults to "interactive".
    /// Set to "analytics" for long-running threat hunting queries.
    /// Only "interactive" and "analytics" are accepted from API clients.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub priority: Option<String>,
    /// Dataset to run the nPL pipeline against (NAN-1534).
    /// `"logs"` (default) | `"spans"` | `"metrics"` | `"risk"`. Selects the FROM
    /// source and the time-bound column (spans → `start_time`, logs/metrics →
    /// `timestamp`) in the SQL generator. `"risk"` (NAN-1798 P2) targets the
    /// DERIVED accumulated-entity-risk grain (one row per entity; fixed trailing
    /// 24h/7d score windows the time picker does not reshape). Unknown values
    /// fall back to `logs` (never an error) via
    /// [`Dataset::from_selector`](crate::query::Dataset::from_selector).
    /// Omit for the default logs dataset — `with_dataset(Logs)` is byte-identical
    /// to the prior generator, so existing clients are unaffected.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dataset: Option<String>,
}

/// Internal hard limits for unattended query execution.
///
/// These are deliberately not part of the public `SearchRequest`: API callers
/// cannot opt out of count companions or choose ClickHouse overflow settings.
/// Detection tuning installs them on a cloned `SearchService` for one replay.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SearchExecutionLimits {
    pub max_result_rows: u64,
    pub max_result_bytes: u64,
}

/// Input for raw SQL search requests
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct RawSqlRequest {
    /// The raw SQL query (must be SELECT only)
    pub sql: String,
    /// Time range for the search
    pub time_range: TimeRangeInput,
    /// Maximum number of results to return
    pub limit: Option<usize>,
    /// Offset for pagination
    pub offset: Option<usize>,
}

/// Time range input for search requests
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct TimeRangeInput {
    /// Start of the time range (ISO 8601 format)
    pub start: DateTime<Utc>,
    /// End of the time range (ISO 8601 format)
    pub end: DateTime<Utc>,
}

impl TimeRangeInput {
    /// Create a new time range
    pub fn new(start: DateTime<Utc>, end: DateTime<Utc>) -> Self {
        Self { start, end }
    }

    /// Validate the time range
    pub fn validate(&self) -> Result<(), SearchError> {
        if self.start >= self.end {
            return Err(SearchError::InvalidTimeRange);
        }
        Ok(())
    }
}

/// A single bucket in the event histogram
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct HistogramBucket {
    /// Start time of the bucket (ISO 8601)
    pub time: DateTime<Utc>,
    /// Number of events in this bucket
    pub count: u64,
}

/// Response from a search query
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct SearchResponse {
    /// The search results as JSON values
    pub results: Vec<serde_json::Value>,
    /// Total count of matching records (before limit/offset).
    ///
    /// Exact for first-page requests (offset 0). Page flips (offset > 0) skip
    /// the count companion (NAN-1645) and report a monotonic estimate instead:
    /// `offset + returned + limit` when a full page came back (signals "more"),
    /// `offset + returned` (exact) on a partial last page. Clients should keep
    /// the page-1 total across flips.
    pub total_count: u64,
    /// Query execution time in milliseconds
    pub execution_time_ms: u64,
    /// Field information with statistics
    pub fields: Vec<FieldInfo>,
    /// The generated SQL (if requested)
    pub generated_sql: Option<String>,
    /// Event histogram for timeline visualization.
    ///
    /// Omitted when `skip_histogram` was set, when the display type renders no
    /// timeline (NAN-1429), and on page flips (offset > 0, NAN-1645) — the
    /// histogram is page-invariant, so clients keep the page-1 timeline.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub histogram: Option<Vec<HistogramBucket>>,
    /// Query performance warnings (query cost analysis)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub warnings: Option<Vec<QueryWarningOutput>>,
    /// Estimated query cost score (0-100, higher = more expensive)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cost_score: Option<u32>,
    /// Display type hint for frontend visualization selection
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_type: Option<DisplayType>,
    /// Column order for table display (from | table command)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub column_order: Option<Vec<String>>,
}

/// Query warning output for API responses
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct QueryWarningOutput {
    /// Severity: "info", "warning", or "error"
    pub severity: String,
    /// Warning code for programmatic handling
    pub code: String,
    /// Human-readable message
    pub message: String,
    /// Suggestion for how to fix the issue
    #[serde(skip_serializing_if = "Option::is_none")]
    pub suggestion: Option<String>,
    /// Estimated impact description
    #[serde(skip_serializing_if = "Option::is_none")]
    pub impact: Option<String>,
}

impl SearchResponse {
    /// Create a new empty search response
    pub fn empty() -> Self {
        Self {
            results: Vec::new(),
            total_count: 0,
            execution_time_ms: 0,
            fields: Vec::new(),
            generated_sql: None,
            histogram: None,
            warnings: None,
            cost_score: None,
            display_type: None,
            column_order: None,
        }
    }
}

/// Information about a field in the search results
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct FieldInfo {
    /// Field name
    pub name: String,
    /// Field type (string, number, boolean, ip, timestamp, object, array)
    pub field_type: String,
    /// Number of results containing this field
    pub count: u64,
    /// Top values for this field with their counts
    pub top_values: Vec<(String, u64)>,
    /// Total unique values (cardinality) for this field across all matching events
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cardinality: Option<u64>,
}

impl FieldInfo {
    /// Create a new field info
    pub fn new(name: String, field_type: String) -> Self {
        Self {
            name,
            field_type,
            count: 0,
            top_values: Vec::new(),
            cardinality: None,
        }
    }
}

/// A single field value with its count and percentage (for on-demand field values)
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct FieldValueInfo {
    /// The field value
    pub value: String,
    /// Number of events with this value
    pub count: u64,
    /// Percentage of total (0-100)
    pub percentage: f64,
}

/// Statistics calculator for field values
#[derive(Debug, Default)]
pub struct FieldStatistics {
    /// Map of field name to value counts
    field_values: HashMap<String, HashMap<String, u64>>,
    /// Map of field name to detected type
    field_types: HashMap<String, String>,
    /// Map of field name to occurrence count
    field_counts: HashMap<String, u64>,
}

impl FieldStatistics {
    /// Create a new field statistics calculator
    pub fn new() -> Self {
        Self::default()
    }

    /// Process a result row and update statistics
    pub fn process_row(&mut self, row: &serde_json::Value) {
        if let Some(obj) = row.as_object() {
            for (key, value) in obj {
                self.process_field(key, value);
            }
        }
    }

    /// Process a single field value
    fn process_field(&mut self, field: &str, value: &serde_json::Value) {
        // Update field count
        *self.field_counts.entry(field.to_string()).or_insert(0) += 1;

        // Detect and update field type
        let field_type = detect_json_type(value);
        self.field_types
            .entry(field.to_string())
            .or_insert_with(|| field_type.to_string());

        // Update value counts (only for scalar values)
        if !value.is_null() && !value.is_object() && !value.is_array() {
            let value_str = value_to_string(value);
            let values = self.field_values.entry(field.to_string()).or_default();
            *values.entry(value_str).or_insert(0) += 1;
        }

        // Flatten nested objects (like metadata) to expose their fields
        if let Some(obj) = value.as_object() {
            for (nested_key, nested_value) in obj {
                let flattened_key = format!("{}.{}", field, nested_key);
                self.process_field(&flattened_key, nested_value);
            }
        }
    }

    /// Get field information with top values
    pub fn get_field_info(&self, top_n: usize) -> Vec<FieldInfo> {
        let mut fields: Vec<FieldInfo> = self
            .field_counts
            .iter()
            .map(|(name, &count)| {
                let field_type = self
                    .field_types
                    .get(name)
                    .cloned()
                    .unwrap_or_else(|| "unknown".to_string());

                let mut info = FieldInfo::new(name.clone(), field_type);
                info.count = count;

                // Get top values
                if let Some(values) = self.field_values.get(name) {
                    let mut sorted_values: Vec<_> = values.iter().collect();
                    sorted_values.sort_by(|a, b| b.1.cmp(a.1));
                    info.top_values = sorted_values
                        .into_iter()
                        .take(top_n)
                        .map(|(v, &c)| (v.clone(), c))
                        .collect();
                }

                info
            })
            .collect();

        // Sort by count descending
        fields.sort_by(|a, b| b.count.cmp(&a.count));
        fields
    }
}

/// Detect the JSON type of a value
fn detect_json_type(value: &serde_json::Value) -> &'static str {
    match value {
        serde_json::Value::Null => "null",
        serde_json::Value::Bool(_) => "boolean",
        serde_json::Value::Number(_) => "number",
        serde_json::Value::String(s) => {
            // Try to detect more specific types
            if s.parse::<std::net::IpAddr>().is_ok() {
                "ip"
            } else if chrono::DateTime::parse_from_rfc3339(s).is_ok() {
                "timestamp"
            } else {
                "string"
            }
        }
        serde_json::Value::Array(_) => "array",
        serde_json::Value::Object(_) => "object",
    }
}

/// Convert a JSON value to a string for statistics
fn value_to_string(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::String(s) => s.clone(),
        serde_json::Value::Number(n) => n.to_string(),
        serde_json::Value::Bool(b) => b.to_string(),
        _ => value.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_time_range_validation() {
        let valid = TimeRangeInput::new(
            "2024-01-01T00:00:00Z".parse().unwrap(),
            "2024-01-02T00:00:00Z".parse().unwrap(),
        );
        assert!(valid.validate().is_ok());

        let invalid = TimeRangeInput::new(
            "2024-01-02T00:00:00Z".parse().unwrap(),
            "2024-01-01T00:00:00Z".parse().unwrap(),
        );
        assert!(invalid.validate().is_err());
    }

    #[test]
    fn test_field_statistics() {
        let mut stats = FieldStatistics::new();

        stats.process_row(&json!({
            "src_ip": "192.168.1.1",
            "status": 200,
            "action": "login"
        }));

        stats.process_row(&json!({
            "src_ip": "192.168.1.1",
            "status": 500,
            "action": "login"
        }));

        stats.process_row(&json!({
            "src_ip": "10.0.0.1",
            "status": 200,
            "action": "logout"
        }));

        let fields = stats.get_field_info(10);
        assert_eq!(fields.len(), 3);

        // Check src_ip field
        let src_ip = fields.iter().find(|f| f.name == "src_ip").unwrap();
        assert_eq!(src_ip.count, 3);
        assert_eq!(src_ip.field_type, "ip");
        assert_eq!(src_ip.top_values.len(), 2);
        // 192.168.1.1 should be first (count 2)
        assert_eq!(src_ip.top_values[0].0, "192.168.1.1");
        assert_eq!(src_ip.top_values[0].1, 2);
    }

    #[test]
    fn test_detect_json_type() {
        assert_eq!(detect_json_type(&json!(null)), "null");
        assert_eq!(detect_json_type(&json!(true)), "boolean");
        assert_eq!(detect_json_type(&json!(42)), "number");
        assert_eq!(detect_json_type(&json!("hello")), "string");
        assert_eq!(detect_json_type(&json!("192.168.1.1")), "ip");
        assert_eq!(
            detect_json_type(&json!("2024-01-01T00:00:00Z")),
            "timestamp"
        );
        assert_eq!(detect_json_type(&json!([1, 2, 3])), "array");
        assert_eq!(detect_json_type(&json!({"a": 1})), "object");
    }

    /// NAN-1436: CH Code 394 (search cancel / KILL QUERY) must map to the
    /// dedicated `Cancelled` variant, not the generic DatabaseError that the
    /// HTTP layer renders as a 500.
    #[test]
    fn test_parse_clickhouse_error_query_was_cancelled() {
        // Shape observed live via clickhouse-rs (HTTP transport)
        let live = "bad response: Code: 394. DB::Exception: Query was cancelled (QUERY_WAS_CANCELLED) (version 26.4.1.1)";
        assert!(matches!(
            parse_clickhouse_error(live),
            SearchError::Cancelled
        ));

        // Alternate server wording (client disconnect variant)
        let disconnect = "Code: 394. DB::Exception: Query was cancelled or a client has disconnected (QUERY_WAS_CANCELLED)";
        assert!(matches!(
            parse_clickhouse_error(disconnect),
            SearchError::Cancelled
        ));
    }

    /// NAN-1653: a CH timeout must surface the real elapsed, not `0ms`.
    #[test]
    fn test_timeout_reports_real_elapsed() {
        let msg = "Code: 159. DB::Exception: Timeout exceeded: elapsed 10030.034392 ms, maximum: 10000 ms: While executing MergeTreeSelect. (TIMEOUT_EXCEEDED)";
        match parse_clickhouse_error(msg) {
            SearchError::Timeout(ms) => assert_eq!(ms, 10030),
            other => panic!("expected Timeout, got {other:?}"),
        }
        // No parseable elapsed → falls back to 0 rather than misreporting.
        match parse_clickhouse_error("Code: 159. TIMEOUT_EXCEEDED: query timed out") {
            SearchError::Timeout(ms) => assert_eq!(ms, 0),
            other => panic!("expected Timeout, got {other:?}"),
        }
    }

    /// NAN-1436: the 394 mapping must not change how other ClickHouse errors
    /// are classified.
    #[test]
    fn test_parse_clickhouse_error_other_codes_unchanged() {
        assert!(matches!(
            parse_clickhouse_error(
                "Code: 47. DB::Exception: Unknown expression identifier `bogus_field` in scope (UNKNOWN_IDENTIFIER)"
            ),
            SearchError::FieldNotFound { .. }
        ));
        assert!(matches!(
            parse_clickhouse_error(
                "Code: 241. DB::Exception: Memory limit (for query) exceeded (MEMORY_LIMIT_EXCEEDED)"
            ),
            SearchError::SqlValidationError(_)
        ));
        assert!(matches!(
            parse_clickhouse_error("Code: 159. DB::Exception: Timeout exceeded: elapsed 1.2 seconds (TIMEOUT_EXCEEDED)"),
            SearchError::Timeout(_)
        ));
        // Anything unrecognized still falls through to DatabaseError
        assert!(matches!(
            parse_clickhouse_error("Code: 999. DB::Exception: something else entirely"),
            SearchError::DatabaseError(_)
        ));
    }
}

// ============================================================================
// UDM Field Query Types
// ============================================================================

use crate::udm::{UdmField, UdmFieldCategory};

/// Display type hint for the frontend to select the appropriate visualization
/// This is determined by the terminal command in the query AST
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum DisplayType {
    /// Raw log events with infinite scroll (default for no aggregation)
    Events,
    /// Paginated table (stats, table after aggregation)
    Table,
    /// Time-series chart (timechart command)
    Timechart,
    /// Horizontal bar chart for ranked values (top, rare commands)
    RankedBar,
    /// Transaction cards with grouped events (transaction command)
    Transaction,
    /// Flow/funnel diagram (sequence, funnel commands)
    Flow,
    /// Hierarchical tree visualization (tree command)
    Tree,
    /// Asset-centric view with identity resolution and activity aggregation (asset command)
    Asset,
    /// Cloud investigation view with faceted summaries and resource activity (cloud command)
    Cloud,
    /// Lateral movement trace view with hop-by-hop path visualization (lateral command)
    Lateral,
    /// Observability services overview page (services command) — curated surface, no log scan
    Services,
    /// Single-service detail page (service command) — curated surface, no log scan
    Service,
    /// Distributed-trace waterfall page (trace command) — curated surface, no log scan
    Trace,
    /// Metric time-series page (metric command) — curated surface, no log scan
    Metric,
    /// IOC retro-hunt view (`ioc=… | retro`) — summary / list / pivot surface
    /// fetched from the companion `/api/search/retro` endpoint (NAN-1580).
    Retro,
    /// Entity-baseline view (`… | baseline`) — new-to-entity rows built by
    /// `build_baseline_view` from the shadow-investigator's primitives (NAN-1868).
    Baseline,
}

// ============================================================================
// IOC Retro-Hunt Types (NAN-1580)
// ============================================================================

/// Request for the IOC retro-hunt companion endpoint (`POST /api/search/retro`).
///
/// The `query` carries the full nPL (`ioc=… | retro [by asset|user]`); the
/// service re-parses it to recover the indicator/feed and submode. `axis`
/// mirrors the parsed `RetroAxis` (`indicator` | `asset` | `user`) so the client
/// can request a pivot without re-deriving it. Pagination + sort apply to the
/// list/pivot rollups.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct RetroRequest {
    /// The full nPL query string (`ioc=… | retro [by asset|user]`).
    pub query: String,
    /// Time range; the engine widens the floor to full retention internally.
    pub time_range: TimeRangeInput,
    /// Pivot axis: `indicator` (default) | `asset` | `user`.
    #[serde(default)]
    pub axis: String,
    /// Row offset for list/pivot pagination.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub offset: Option<usize>,
    /// Page size for list/pivot pagination.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<usize>,
    /// Optional explicit sort key override (engine picks a sensible default).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sort: Option<String>,
}

/// Verdict rarity band for a retro indicator/entity (NAN-1580).
///
/// `ratio = distinct_hosts_touched / total_hosts_in_env`; `rare <= 0.02`,
/// `uncommon <= 0.15`, else `common`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum RetroVerdict {
    /// Touched <= 2% of hosts in the environment.
    Rare,
    /// Touched <= 15% of hosts.
    Uncommon,
    /// Touched > 15% of hosts.
    Common,
}

impl RetroVerdict {
    /// Band a host-ratio into a verdict (rare<=0.02, uncommon<=0.15, else common).
    pub fn from_ratio(ratio: f64) -> Self {
        if ratio <= 0.02 {
            RetroVerdict::Rare
        } else if ratio <= 0.15 {
            RetroVerdict::Uncommon
        } else {
            RetroVerdict::Common
        }
    }

    /// String form used in the response payload.
    pub fn as_str(&self) -> &'static str {
        match self {
            RetroVerdict::Rare => "rare",
            RetroVerdict::Uncommon => "uncommon",
            RetroVerdict::Common => "common",
        }
    }
}

/// A top entity (asset/user) touched by a single indicator (summary submode).
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct RetroTopEntity {
    /// Canonical entity identifier (host / ip / user).
    pub id: String,
    /// Hit count for this entity against the indicator.
    pub hits: u64,
    /// Entity kind: `asset` | `user`.
    pub kind: String,
}

/// A newly-landed feed indicator considered by an auto retro-hunt run (NAN-1791).
///
/// Pulled from `custom_enrichment_results` above the rule's watermark, before the
/// per-run cap + hunted-set anti-join. `value` is lowercased to match the
/// ingest-lowercased raw columns and the `lower(col)` expression indexes.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct RetroFeedCandidate {
    /// Lowercased indicator value.
    pub value: String,
    /// Artifact type (`ip` | `domain` | `hash` | `url` | `custom`).
    pub key_type: String,
    /// Feed name (`enrichment_name`) the indicator came from.
    pub enrichment_name: String,
    /// Intel confidence (0-100).
    pub confidence: u32,
    /// When the indicator most recently landed in the feed table (the watermark
    /// cursor value), as epoch milliseconds.
    pub fetched_at_ms: i64,
}

/// A retro-hunt HIT: a delta indicator that was found in historical logs
/// (NAN-1791). Emitted as a synthesized detection match through the standard
/// signal processor → alerts path.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct RetroHuntHit {
    /// The indicator value that matched.
    pub value: String,
    /// Inferred indicator type (ip | hash | domain | url | …).
    pub indicator_type: String,
    /// The logical observable field the indicator matched on (e.g. `src_ip`).
    pub field: String,
    /// Total event hits in the lookback window.
    pub hits: u64,
    /// Distinct hosts the indicator touched.
    pub hosts: u64,
    /// Total distinct hosts in the environment (verdict denominator).
    pub total_hosts: u64,
    /// First seen in logs (ISO-8601).
    pub first_seen: Option<String>,
    /// Last seen in logs (ISO-8601).
    pub last_seen: Option<String>,
    /// Rarity verdict band (`rare` | `uncommon` | `common`).
    pub verdict: String,
}

/// Summary submode payload — a single indicator's environment-wide footprint.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct RetroIndicatorSummary {
    /// The indicator value.
    pub value: String,
    /// Inferred indicator type (ip | hash | domain | url | user | other).
    #[serde(rename = "type")]
    pub indicator_type: String,
    /// Intel source (feed name, or `query` for a typed literal).
    pub source: String,
    /// Campaign / actor association (from feed tags), if known.
    pub campaign: Option<String>,
    /// Intel confidence (0-100), 0 when not enriched.
    pub confidence: u32,
    /// Total event hits across all observable columns.
    pub hits: u64,
    /// First seen (ISO-8601) across retention.
    pub first_seen: Option<String>,
    /// Last seen (ISO-8601) across retention.
    pub last_seen: Option<String>,
    /// Per-observable-column match counts: `[field, count]`.
    pub matched_fields: Vec<(String, u64)>,
    /// Distinct hosts the indicator touched.
    pub distinct_hosts: u64,
    /// Total distinct hosts in the environment (verdict denominator).
    pub total_hosts: u64,
    /// Rarity verdict band.
    pub verdict: String,
    /// Top entities by hit count.
    pub top_entities: Vec<RetroTopEntity>,
}

/// A single indicator row in the list submode (campaign / multi-value).
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct RetroListRow {
    /// The indicator value.
    pub value: String,
    /// Inferred indicator type.
    #[serde(rename = "type")]
    pub indicator_type: String,
    /// Event hits across observable columns.
    pub hits: u64,
    /// Distinct hosts touched.
    pub hosts: u64,
    /// Total hosts in the environment.
    pub total_hosts: u64,
    /// First seen (ISO-8601).
    pub first_seen: Option<String>,
    /// Last seen (ISO-8601).
    pub last_seen: Option<String>,
    /// Observable column the indicator predominantly matched.
    pub field: String,
    /// Rarity verdict band.
    pub verdict: String,
}

/// A single entity row in the pivot submode (axis = asset | user).
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct RetroPivotRow {
    /// Canonical entity identifier.
    pub id: String,
    /// Display name (resolved identity, or the id when unresolved).
    pub name: String,
    /// Secondary label (e.g. department / ip), when resolved.
    pub sub: Option<String>,
    /// Distinct indicators this entity was touched by.
    pub iocs: u64,
    /// The matched indicator values (capped sample).
    pub indicators: Vec<String>,
    /// First seen (ISO-8601).
    pub first_seen: Option<String>,
    /// Last seen (ISO-8601).
    pub last_seen: Option<String>,
    /// Worst (rarest) verdict across the entity's indicators.
    pub worst_verdict: String,
}

/// Response from the IOC retro-hunt companion endpoint (NAN-1580).
///
/// Shaped by `submode`: `summary` populates `indicator`; `list` populates
/// `rows`/`no_hits`/`total_indicators`; `pivot` populates `pivot_rows`. Common
/// fields (`submode`, `axis`, `total_hosts`, `generated_sql`) are always set.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct RetroResponse {
    /// Submode: `summary` | `list` | `pivot`.
    pub submode: String,
    /// Resolved axis: `indicator` | `asset` | `user`.
    pub axis: String,
    /// Total distinct hosts in the environment (verdict denominator).
    pub total_hosts: u64,
    /// The generated rollup SQL (always included for transparency).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub generated_sql: Option<String>,

    // ── summary submode ──
    /// Single-indicator summary (summary submode only).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub indicator: Option<RetroIndicatorSummary>,

    // ── list submode ──
    /// Total indicators with at least one hit (list submode).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total_indicators: Option<u64>,
    /// Indicator rows, rarest-first (list submode).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rows: Option<Vec<RetroListRow>>,
    /// Indicators with zero hits in the environment (list submode).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub no_hits: Option<Vec<String>>,

    // ── pivot submode ──
    /// Entity rows (pivot submode).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pivot_rows: Option<Vec<RetroPivotRow>>,

    // ── pagination (list + pivot) ──
    /// Row offset applied.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub offset: Option<usize>,
    /// Page size applied.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<usize>,
    /// Whether more rows exist past this page.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub has_more: Option<bool>,
}

/// Request for querying by UDM field
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct UdmFieldQueryRequest {
    /// The UDM field to query
    #[schema(value_type = String)]
    pub field: UdmField,
    /// The value to search for
    pub value: String,
    /// The comparison operator
    pub operator: UdmQueryOperator,
    /// Time range for the search
    pub time_range: TimeRangeInput,
    /// Maximum number of results to return
    pub limit: Option<usize>,
    /// Offset for pagination
    pub offset: Option<usize>,
    /// Whether to include the generated SQL in the response
    pub include_sql: Option<bool>,
}

/// Operators for UDM field queries
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum UdmQueryOperator {
    /// Exact match (=)
    Equals,
    /// Not equal (!=)
    NotEquals,
    /// Contains substring (ILIKE %value%)
    Contains,
    /// Starts with (ILIKE value%)
    StartsWith,
    /// Ends with (ILIKE %value)
    EndsWith,
    /// Regex match (=/pattern/)
    Regex,
    /// Greater than (>)
    GreaterThan,
    /// Less than (<)
    LessThan,
    /// Is null
    IsNull,
    /// Is not null
    IsNotNull,
}

impl Default for UdmQueryOperator {
    fn default() -> Self {
        Self::Equals
    }
}

impl UdmFieldCategory {
    /// Convert to string representation
    pub fn to_string(&self) -> String {
        match self {
            UdmFieldCategory::Alerts => "alerts".to_string(),
            UdmFieldCategory::Authentication => "authentication".to_string(),
            UdmFieldCategory::Certificate => "certificate".to_string(),
            UdmFieldCategory::Change => "change".to_string(),
            UdmFieldCategory::DataAccess => "data_access".to_string(),
            UdmFieldCategory::Database => "database".to_string(),
            UdmFieldCategory::DataLossPrevention => "data_loss_prevention".to_string(),
            UdmFieldCategory::Dns => "dns".to_string(),
            UdmFieldCategory::Email => "email".to_string(),
            UdmFieldCategory::Endpoint => "endpoint".to_string(),
            UdmFieldCategory::InterprocessMessaging => "interprocess_messaging".to_string(),
            UdmFieldCategory::Intrusion => "intrusion".to_string(),
            UdmFieldCategory::Inventory => "inventory".to_string(),
            UdmFieldCategory::Malware => "malware".to_string(),
            UdmFieldCategory::Network => "network".to_string(),
            UdmFieldCategory::Performance => "performance".to_string(),
            UdmFieldCategory::Vulnerability => "vulnerability".to_string(),
            UdmFieldCategory::Web => "web".to_string(),
            UdmFieldCategory::Custom => "custom".to_string(),
            UdmFieldCategory::System => "system".to_string(),
            UdmFieldCategory::Enrichment => "enrichment".to_string(),
            UdmFieldCategory::ThreatIntelligence => "threat_intelligence".to_string(),
            UdmFieldCategory::CustomEnrichment => "custom_enrichment".to_string(),
            UdmFieldCategory::Prevalence => "prevalence".to_string(),
            UdmFieldCategory::Risk => "risk".to_string(),
            UdmFieldCategory::Detection => "detection".to_string(),
            UdmFieldCategory::Cloud => "cloud".to_string(),
        }
    }
}

// ============================================================================
// Asset Pagination Types
// ============================================================================

/// Pagination metadata for asset events
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct AssetPagination {
    /// Total number of events matching the query
    pub total_count: u64,
    /// Current offset (events already returned)
    pub offset: usize,
    /// Page size limit
    pub limit: usize,
    /// Whether more events are available
    pub has_more: bool,
    /// Facet counts for filtering UI
    pub facets: AssetFacets,
}

/// Facet counts for asset view filtering
#[derive(Debug, Clone, Default, Serialize, Deserialize, utoipa::ToSchema)]
pub struct AssetFacets {
    /// Source type facet: [(value, count), ...]
    pub source_type: Vec<(String, u64)>,
    /// Event-kind facet — the classifier label (`PROCESS`, `AUTH_FAILURE`, …),
    /// NOT the UDM `event_type` field value (NAN-2211).
    pub event_kind: Vec<(String, u64)>,
    /// User facet: [(value, count), ...]
    pub user: Vec<(String, u64)>,
}

/// Filters for paginated asset event queries
#[derive(Debug, Clone, Default, Serialize, Deserialize, utoipa::ToSchema)]
pub struct AssetEventFilters {
    /// Filter by source types (OR)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_types: Option<Vec<String>>,
    /// Filter by event kinds (OR) — classifier labels, not UDM `event_type`
    /// field values (NAN-2211).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub event_kinds: Option<Vec<String>>,
    /// Filter by users (OR)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub users: Option<Vec<String>>,
    /// Text search across message, process, file_path, etc.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub search_text: Option<String>,
}

// ============================================================================
// Cloud Pagination Types
// ============================================================================

/// Facet counts for cloud view filtering
#[derive(Debug, Clone, Default, Serialize, Deserialize, utoipa::ToSchema)]
pub struct CloudFacets {
    /// Cloud provider facet: [(value, count), ...]
    pub cloud_provider: Vec<(String, u64)>,
    /// Cloud service facet: [(value, count), ...]
    pub cloud_service: Vec<(String, u64)>,
    /// Cloud region facet: [(value, count), ...]
    pub cloud_region: Vec<(String, u64)>,
    /// Cloud account ID facet: [(value, count), ...]
    pub cloud_account_id: Vec<(String, u64)>,
    /// Resource type facet: [(value, count), ...]
    pub resource_type: Vec<(String, u64)>,
    /// Change type facet: [(value, count), ...]
    pub change_type: Vec<(String, u64)>,
}

/// Filters for paginated cloud event queries
#[derive(Debug, Clone, Default, Serialize, Deserialize, utoipa::ToSchema)]
pub struct CloudEventFilters {
    /// Filter by cloud providers (OR)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cloud_providers: Option<Vec<String>>,
    /// Filter by cloud services (OR)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cloud_services: Option<Vec<String>>,
    /// Filter by cloud regions (OR)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cloud_regions: Option<Vec<String>>,
    /// Filter by cloud account IDs (OR)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cloud_account_ids: Option<Vec<String>>,
    /// Filter by resource types (OR)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource_types: Option<Vec<String>>,
    /// Filter by change types (OR)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub change_types: Option<Vec<String>>,
    /// Text search across action, user, src_ip, resource_id, resource_name, message, http_user_agent
    #[serde(skip_serializing_if = "Option::is_none")]
    pub search_text: Option<String>,
}

// ============================================================================
// Cloud Investigation Types
// ============================================================================

/// Pre-aggregated cloud user activity (from cloud_user_activity_agg MV)
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct CloudUserActivity {
    /// Username (cloud identity)
    pub user: String,
    /// Total event count in the time window
    pub event_count: u64,
    /// Distinct cloud services accessed
    pub distinct_services: u64,
    /// Distinct cloud regions accessed
    pub distinct_regions: u64,
    /// Distinct source IPs used
    pub distinct_ips: u64,
    /// Failed API calls (HTTP >= 400)
    pub fail_count: u64,
    /// Permission/IAM change operations
    pub permission_change_count: u64,
    /// Delete operations
    pub delete_count: u64,
    /// Requests made with MFA
    pub mfa_count: u64,
    /// Requests made without MFA
    pub no_mfa_count: u64,
    /// Computed risk indicators (e.g. "high_fail_rate", "no_mfa", "multi_region")
    pub risk_indicators: Vec<String>,
}

/// Session summary for a single user's cloud activity timeline
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct CloudUserSessionSummary {
    /// Cloud services accessed
    pub services: Vec<String>,
    /// Cloud regions accessed
    pub regions: Vec<String>,
    /// Source IPs used
    pub ips: Vec<String>,
    /// Total event count
    pub event_count: u64,
    /// Failed API calls
    pub fail_count: u64,
    /// Permission/IAM change operations
    pub permission_change_count: u64,
    /// Delete operations
    pub delete_count: u64,
    /// Whether any request lacked MFA
    pub has_no_mfa: bool,
    /// Computed risk indicators
    pub risk_indicators: Vec<String>,
}

/// Cross-referenced entity from an entity pivot query
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct EntityCrossReference {
    /// Entity type (e.g. "user", "ip", "resource")
    pub entity_type: String,
    /// Entity value
    pub entity_value: String,
    /// Number of events involving this entity
    pub event_count: u64,
}

#[cfg(test)]
mod udm_tests {
    use super::*;

    #[test]
    fn test_udm_query_operator_default() {
        assert_eq!(UdmQueryOperator::default(), UdmQueryOperator::Equals);
    }

    #[test]
    fn test_udm_field_category_to_string() {
        assert_eq!(UdmFieldCategory::Inventory.to_string(), "inventory");
        assert_eq!(UdmFieldCategory::Network.to_string(), "network");
        assert_eq!(
            UdmFieldCategory::Authentication.to_string(),
            "authentication"
        );
        assert_eq!(UdmFieldCategory::Endpoint.to_string(), "endpoint");
        assert_eq!(UdmFieldCategory::Custom.to_string(), "custom");
    }
}

#[cfg(test)]
mod asset_pagination_tests {
    use super::*;

    #[test]
    fn test_asset_pagination_serialization() {
        let pagination = AssetPagination {
            total_count: 85000,
            offset: 0,
            limit: 500,
            has_more: true,
            facets: AssetFacets {
                source_type: vec![("edr".to_string(), 45000), ("proxy".to_string(), 30000)],
                event_kind: vec![
                    ("PROCESS".to_string(), 35000),
                    ("NETWORK".to_string(), 28000),
                ],
                user: vec![("admin".to_string(), 15000), ("system".to_string(), 12000)],
            },
        };

        let json = serde_json::to_string(&pagination).unwrap();
        assert!(json.contains("\"total_count\":85000"));
        assert!(json.contains("\"has_more\":true"));
    }

    #[test]
    fn test_asset_event_filters_default() {
        let filters = AssetEventFilters::default();
        assert!(filters.source_types.is_none());
        assert!(filters.event_kinds.is_none());
        assert!(filters.users.is_none());
        assert!(filters.search_text.is_none());
    }
}
