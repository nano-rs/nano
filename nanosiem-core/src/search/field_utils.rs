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

/// Check if a field is produced by post-processing commands (ai, anomaly,
/// prevalence) or the `| risk` command's runtime-only outputs, and does NOT
/// exist as a physical column. These must be excluded from SQL SELECT clauses
/// and ext JSON materialization.
///
/// NAN-1909: `risk_score`/`risk_entity`/`risk_level` are deliberately NOT here.
/// Despite the `risk_` prefix they are REAL `logs` columns (findings ingest
/// populates them), so excluding them pruned them from the base-table
/// projection — `risk_entity="x" | stats sum(risk_score)` then referenced a
/// column absent from the inner scan (CH: "Unknown expression identifier").
/// The `| risk` command's *recomputation* of risk_score/risk_entity is already
/// handled per-command by `collect_computed_field_names`; only fields that are
/// ONLY ever produced at runtime (never physical columns) belong in this list.
pub fn is_post_processing_field(field: &str) -> bool {
    field.starts_with("ai_")
        || field.starts_with("anomaly_")
        || matches!(
            field,
            "is_anomaly"
                | "is_rare"
                | "host_count"
                | "total_occurrences"
                | "raw_risk_score"
                | "risk_factors"
                | "risk_weight"
        )
}
