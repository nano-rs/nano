// SPDX-License-Identifier: AGPL-3.0-or-later

//! Shared field name utilities for search query processing and post-processing.
//!
//! Provides alias normalization and post-processing field identification used
//! across query manipulation, SQL generation, and result post-processing.

/// Normalize common field name aliases to their canonical ClickHouse column names.
///
/// This mirrors the aliases in `clickhouse_sql_gen::normalize_field_name` for the
/// most common cases. Used in post-processing and query manipulation where the
/// full SQL generator normalization isn't available.
pub fn normalize_field_alias(name: &str) -> &str {
    match name {
        "_time" => "timestamp",
        "sourcetype" => "source_type",
        "hostname" => "host",
        "dest_hostname" => "dest_host",
        "src_hostname" => "src_host",
        _ => name,
    }
}

/// Check if a field is produced by post-processing commands (ai, anomaly, risk, etc.)
/// and does not exist in the database. These must be excluded from SQL SELECT clauses
/// and ext JSON materialization.
pub fn is_post_processing_field(field: &str) -> bool {
    field.starts_with("ai_")
        || field.starts_with("anomaly_")
        || field.starts_with("risk_")
        || matches!(
            field,
            "is_anomaly" | "is_rare" | "host_count" | "total_occurrences"
        )
}
