// SPDX-License-Identifier: AGPL-3.0-or-later

//! Field normalization and SQL conversion utilities

use crate::query::ast::{Comparator, IntervalUnit, Value};
use std::fmt::Write;

/// Normalize field name to canonical UDM field name
pub(crate) fn normalize_field_name(field: &str) -> &str {
    match field {
        // CIM compatibility aliases
        "sourcetype" => "source_type",

        // Host aliases (common variations)
        "hostname" => "host",
        "dest_hostname" => "dest_host",
        "src_hostname" => "src_host",

        // User aliases (common variations)
        "username" => "user",
        "user_name" => "user", // Some logs use user_name

        // Destination shorthand (CIM)
        // Note: "source" is NOT aliased - it's a real column for audit subsystem
        "destination" => "dest",

        // IP address variations
        "source_ip" => "src_ip",
        "destination_ip" => "dest_ip",
        "src_address" => "src_ip",
        "dest_address" => "dest_ip",

        // Port variations
        "source_port" => "src_port",
        "destination_port" => "dest_port",

        // MAC address variations
        "source_mac" => "src_mac",
        "destination_mac" => "dest_mac",

        // Process variations
        "process" => "command_line",
        "parent_process" => "parent_command_line",

        // HTTP/Web aliases
        "uri" => "url",
        "uri_path" => "url",
        "referer" => "http_referrer", // Common misspelling
        "referrer" => "http_referrer",
        "useragent" => "http_user_agent",
        // Note: user_agent is a real UDM column (used by audit logs), don't alias it

        // File aliases
        "filename" => "file_name",
        "filepath" => "file_path",

        // Status/Result aliases
        "result" => "status",
        "outcome" => "status",

        // Add other aliases here as needed
        _ => field,
    }
}

/// Convert a field name to its SQL expression, handling metadata fields
/// Returns (sql_expression, needs_alias) where needs_alias indicates if the field
/// should be aliased to its original name for clean output
pub(crate) fn field_to_sql_expr(field: &str) -> (String, bool) {
    // Normalize field name (apply aliases)
    let field = normalize_field_name(field);

    // Fields with metadata_ prefix always go to JSONB
    if field.starts_with("metadata_") {
        return (field_to_jsonb_path(field), true);
    }

    // Known UDM fields are direct column references
    if is_udm_field(field) {
        return (escape_identifier(field), false);
    }

    // Dot notation means nested metadata access
    if field.contains('.') {
        return (field_to_jsonb_path(field), true);
    }

    // Known metadata fields that need JSONB extraction
    // These are fields stored in the metadata JSON column but commonly queried
    if is_known_metadata_field(field) {
        return (field_to_jsonb_path(field), true);
    }

    // For unknown fields without metadata_ prefix and no dots:
    // Treat as a direct column reference (could be a computed column from eval,
    // a renamed column, or a column from a previous stage)
    // This allows eval'd fields like "response_kb" to be referenced in subsequent commands
    (escape_identifier(field), false)
}

/// Check if a field is a known metadata field that should be extracted from JSONB
pub(crate) fn is_known_metadata_field(field: &str) -> bool {
    matches!(
        field,
        // Risk scoring fields (from signals)
        "risk_score" | "raw_risk_score" | "risk_entity" | "risk_factors" |
        // Signal fields
        "signal_type" | "rule_id" | "rule_name" | "rule_query" | "severity" |
        "rule_mode" | "alert_id" | "matched_event_count" | "realtime" |
        "detected_at" | "mitre_tactics" | "mitre_techniques"
    )
}

/// Check if a field is a UDM field (direct column) vs metadata (JSONB)
pub(crate) fn is_udm_field(field: &str) -> bool {
    use crate::udm::fields::UdmField;
    use std::str::FromStr;

    // Check if it's a valid UDM field
    if UdmField::from_str(field).is_ok() {
        return true;
    }

    // Also check common computed/result column names (from stats, timechart, etc.)
    matches!(
        field,
        "count"
            | "sum"
            | "avg"
            | "min"
            | "max"
            | "total"
            | "time_bucket"
            | "bytes"
            | "total_bytes"
            | "requests"
    )
}

/// Convert a comparator to SQL operator
pub(crate) fn comparator_to_sql(op: &Comparator) -> &'static str {
    match op {
        Comparator::Eq => "=",
        Comparator::Ne => "!=",
        Comparator::Gt => ">",
        Comparator::Lt => "<",
        Comparator::Gte => ">=",
        Comparator::Lte => "<=",
        Comparator::Regex => "~",     // PostgreSQL regex
        Comparator::NotRegex => "!~", // PostgreSQL negated regex
        Comparator::Like => "ILIKE",
        Comparator::NotLike => "NOT ILIKE",
        Comparator::Contains => "ILIKE", // Handled specially with % wrapping
        Comparator::NotContains => "NOT ILIKE",
        Comparator::StartsWith => "ILIKE", // Handled specially with % suffix
        Comparator::NotStartsWith => "NOT ILIKE",
        Comparator::EndsWith => "ILIKE", // Handled specially with % prefix
        Comparator::NotEndsWith => "NOT ILIKE",
    }
}

/// Convert a Value to SQL literal
pub fn value_to_sql(value: &Value) -> String {
    match value {
        Value::String(s) => format!("'{}'", escape_string(s)),
        Value::Number(n) => {
            if n.fract() == 0.0 {
                format!("{}", *n as i64)
            } else {
                format!("{}", n)
            }
        }
        Value::Bool(b) => if *b { "TRUE" } else { "FALSE" }.to_string(),
        // IP addresses are stored as TEXT in the database, so compare as text
        Value::Ip(ip) => format!("'{}'", ip),
        // Regex patterns are just strings for PostgreSQL
        Value::Regex(pattern) => format!("'{}'", escape_string(pattern)),
        // Intervals are converted to PostgreSQL interval syntax
        Value::Interval(duration, unit) => {
            let seconds = duration.as_secs();
            match unit {
                IntervalUnit::Microsecond => {
                    format!("INTERVAL '{} microseconds'", seconds * 1_000_000)
                }
                IntervalUnit::Millisecond => format!("INTERVAL '{} milliseconds'", seconds * 1_000),
                IntervalUnit::Second => format!("INTERVAL '{} seconds'", seconds),
                IntervalUnit::Minute => format!("INTERVAL '{} minutes'", seconds / 60),
                IntervalUnit::Hour => format!("INTERVAL '{} hours'", seconds / 3600),
                IntervalUnit::Day => format!("INTERVAL '{} days'", seconds / 86400),
                IntervalUnit::Week => format!("INTERVAL '{} weeks'", seconds / 604800),
                IntervalUnit::Month => format!("INTERVAL '{} months'", seconds / 2592000),
                IntervalUnit::Year => format!("INTERVAL '{} years'", seconds / 31536000),
            }
        }
    }
}

/// Convert a Value to SQL literal, respecting the target field's column type
/// This ensures numeric values are quoted as strings for TEXT columns
pub(crate) fn value_to_sql_for_field(field: &str, value: &Value) -> String {
    // Check if the field is a TEXT column that might receive numeric values
    if is_text_column(field) {
        match value {
            Value::Number(n) => {
                // Convert number to string literal for TEXT columns
                if n.fract() == 0.0 {
                    format!("'{}'", *n as i64)
                } else {
                    format!("'{}'", n)
                }
            }
            _ => value_to_sql(value),
        }
    } else {
        value_to_sql(value)
    }
}

/// Check if a UDM field is stored as TEXT in the database
/// This is used to properly quote numeric values when comparing against TEXT columns
pub(crate) fn is_text_column(field: &str) -> bool {
    matches!(
        field,
        // Entity fields (TEXT)
        "src_ip" | "dest_ip" | "src_host" | "dest_host" |
        // User/Action fields (TEXT)
        "user" | "action" | "status" |
        // Network fields (TEXT)
        "protocol" |
        // Authentication fields (TEXT)
        "auth_type" | "auth_result" | "session_id" |
        // Process fields (TEXT)
        "process_name" | "parent_command_line" | "command_line" |
        // File fields (TEXT)
        "file_path" | "file_name" | "file_hash" | "file_action" |
        // System fields (TEXT)
        "message" | "source_type" | "source" | "user_agent" |
        // Enrichment fields (TEXT)
        "enriched_src_country" | "enriched_src_country_code" |
        "enriched_src_continent" | "enriched_src_continent_code" |
        "enriched_src_as_name" | "enriched_src_as_domain" |
        "enriched_dest_country" | "enriched_dest_country_code" |
        "enriched_dest_continent" | "enriched_dest_continent_code" |
        "enriched_dest_as_name" | "enriched_dest_as_domain"
    )
}

/// Escape a string for SQL (single quotes)
pub fn escape_string(s: &str) -> String {
    s.replace('\'', "''")
}

/// Convert wildcard pattern (* and ?) to SQL LIKE pattern (% and _)
/// Also escapes SQL LIKE special characters in the literal parts
pub fn wildcard_to_like_pattern(s: &str) -> String {
    let mut result = String::with_capacity(s.len() * 2);
    for c in s.chars() {
        match c {
            '*' => result.push('%'),
            '?' => result.push('_'),
            '%' => result.push_str("\\%"), // Escape literal %
            '_' => result.push_str("\\_"), // Escape literal _
            '\'' => result.push_str("''"), // Escape single quote
            _ => result.push(c),
        }
    }
    result
}

/// Escape an identifier (column/table name)
pub(crate) fn escape_identifier(name: &str) -> String {
    // Handle reserved words and special characters
    if name.contains('.') || is_reserved_word(name) {
        format!("\"{}\"", name.replace('"', "\"\""))
    } else {
        name.to_string()
    }
}

/// Check if a word is a PostgreSQL reserved word
pub(crate) fn is_reserved_word(word: &str) -> bool {
    matches!(
        word.to_uppercase().as_str(),
        "USER"
            | "ORDER"
            | "GROUP"
            | "SELECT"
            | "FROM"
            | "WHERE"
            | "AND"
            | "OR"
            | "NOT"
            | "NULL"
            | "TRUE"
            | "FALSE"
            | "AS"
            | "BY"
            | "ASC"
            | "DESC"
            | "LIMIT"
            | "OFFSET"
    )
}

/// Convert field name to JSONB path expression
/// Handles both dot notation (field.subfield) and underscore prefix (metadata_field)
pub fn field_to_jsonb_path(field: &str) -> String {
    // Handle metadata_ prefix: metadata_endpoint -> metadata->>'endpoint'
    if let Some(stripped) = field.strip_prefix("metadata_") {
        // Check for nested underscore paths: metadata_user_id -> metadata->'user'->>'id'
        // But be careful - single underscores in field names are common
        // For now, treat the whole thing after metadata_ as a single field name
        return format!("metadata->>'{}'", escape_string(stripped));
    }

    // Handle dot notation for nested paths
    let parts: Vec<&str> = field.split('.').collect();
    if parts.len() == 1 {
        format!("metadata->>'{}'", escape_string(parts[0]))
    } else {
        // Nested path: metadata->'a'->'b'->>'c'
        let mut path = "metadata".to_string();
        for (i, part) in parts.iter().enumerate() {
            if i == parts.len() - 1 {
                // Last part uses ->> for text extraction
                write!(path, "->>'{}'", escape_string(part)).unwrap();
            } else {
                // Intermediate parts use -> for object traversal
                write!(path, "->'{}'", escape_string(part)).unwrap();
            }
        }
        path
    }
}

/// Convert duration to PostgreSQL interval string for date_trunc
pub fn duration_to_interval(duration: &std::time::Duration) -> &'static str {
    let secs = duration.as_secs();
    if secs >= 86400 {
        "day"
    } else if secs >= 3600 {
        "hour"
    } else if secs >= 60 {
        "minute"
    } else {
        "second"
    }
}

// ============================================================================
