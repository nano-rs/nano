// SPDX-License-Identifier: AGPL-3.0-or-later

//! Helper functions for log source repository operations

use sqlx::Row;

use super::super::types::LogSource;

/// Parse a JSON value as i64, handling both integer and string formats
pub(crate) fn parse_json_i64(json: &serde_json::Value, key: &str) -> i64 {
    json.get(key)
        .and_then(|v| {
            // Try as integer first, then as string
            v.as_i64()
                .or_else(|| v.as_u64().map(|u| u as i64))
                .or_else(|| v.as_str().and_then(|s| s.parse::<i64>().ok()))
        })
        .unwrap_or(0)
}

pub(crate) fn row_to_log_source(row: &sqlx::postgres::PgRow) -> LogSource {
    LogSource {
        id: row.get("id"),
        name: row.get("name"),
        description: row.get("description"),
        namespace: row
            .try_get("namespace")
            .unwrap_or_else(|_| "default".to_string()),
        timezone: row
            .try_get("timezone")
            .unwrap_or_else(|_| "UTC".to_string()),
        source_type: row.get("source_type"),
        source_config: row.get("source_config"),
        credential_id: row.get("credential_id"),
        parser_vrl: row.get("parser_vrl"),
        output_fields: row.get("output_fields"),
        category: row.get("category"),
        vendor: row.get("vendor"),
        product: row.get("product"),
        icon: row.get("icon"),
        color: row.get("color"),
        match_field: row.get("match_field"),
        match_pattern: row.get("match_pattern"),
        match_values: row.get("match_values"),
        validated: row.get("validated"),
        validation_error: row.get("validation_error"),
        deployed: row.get("deployed"),
        deployed_at: row.get("deployed_at"),
        enabled: row.get("enabled"),
        stale_alert_enabled: row.get("stale_alert_enabled"),
        stale_threshold_minutes: row.get("stale_threshold_minutes"),
        sampling_ratio: row.try_get("sampling_ratio").unwrap_or(None),
        sampling_exclude_condition: row.try_get("sampling_exclude_condition").unwrap_or(None),
        parser_only: row.try_get("parser_only").unwrap_or(false),
        source_parser_repository_id: row.try_get("source_parser_repository_id").unwrap_or(None),
        source_parser_path: row.try_get("source_parser_path").unwrap_or(None),
        source_parser_linked: row.try_get("source_parser_linked").unwrap_or(false),
        created_at: row.get("created_at"),
        updated_at: row.get("updated_at"),
    }
}
