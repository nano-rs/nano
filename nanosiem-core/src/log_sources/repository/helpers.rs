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
        // NAN-928: try_get keeps reads working against tenants that have not
        // yet applied migration 189; the column simply reads as None.
        dispatch_source_config_id: row.try_get("dispatch_source_config_id").unwrap_or(None),
        // NAN-1084: only present when the SELECT joins source_configurations.
        dispatch_source_config_type: row.try_get("dispatch_source_config_type").unwrap_or(None),
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
        // NAN-1920: try_get so read paths whose SELECT omits the column (or
        // tenants pre-migration 258) default to "active" rather than panicking.
        lifecycle_status: row
            .try_get("lifecycle_status")
            .unwrap_or_else(|_| "active".to_string()),
        stale_alert_enabled: row.get("stale_alert_enabled"),
        stale_threshold_minutes: row.get("stale_threshold_minutes"),
        sampling_ratio: row.try_get("sampling_ratio").unwrap_or(None),
        sampling_exclude_condition: row.try_get("sampling_exclude_condition").unwrap_or(None),
        extension_vrl: row.try_get("extension_vrl").unwrap_or(None),
        extension_enabled: row.try_get("extension_enabled").unwrap_or(false),
        // NAN-1149: enrichment-parser flavor. try_get so read paths whose
        // SELECT omits these columns (or tenants pre-migration 198) default to
        // kind="log" with no enrich routing; the deploy-path SELECTs include
        // them so an enrichment source stages into the push enrichment lane.
        kind: row.try_get("kind").unwrap_or_else(|_| "log".to_string()),
        enrich_kind: row.try_get("enrich_kind").unwrap_or(None),
        enrich_source: row.try_get("enrich_source").unwrap_or(None),
        target_table: row.try_get("target_table").unwrap_or(None),
        normalize_vrl: row.try_get("normalize_vrl").unwrap_or(None),
        source_parser_repository_id: row.try_get("source_parser_repository_id").unwrap_or(None),
        source_parser_path: row.try_get("source_parser_path").unwrap_or(None),
        source_parser_linked: row.try_get("source_parser_linked").unwrap_or(false),
        created_at: row.get("created_at"),
        updated_at: row.get("updated_at"),
    }
}

/// Which `deployed`-reset rules an update triggers (NAN-5321).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct DeployedResetFlags {
    /// A column Vector renders straight from `log_sources` changed: always undeployed.
    pub config_changed: bool,
    /// A working-draft column changed (`parser_vrl`, `output_fields`,
    /// `extension_*`). Vector renders the ACTIVE version of these
    /// (`EFFECTIVE_DEPLOYED_PARSERS_SQL`), so this undeploys only a source
    /// with no published version.
    pub draft_changed: bool,
    /// `output_fields` changed. The effective query falls back to the working
    /// copy's `output_fields` when the active version has none.
    pub output_fields_changed: bool,
}

pub(crate) fn deployed_reset_flags(
    update: &super::super::types::UpdateLogSource,
) -> DeployedResetFlags {
    DeployedResetFlags {
        config_changed: update.source_type.is_some()
            || update.dispatch_source_config_id.is_some()
            || update.match_field.is_some()
            || update.match_pattern.is_some()
            || update.match_values.is_some()
            || update.sampling_ratio.is_some()
            || update.sampling_exclude_condition.is_some()
            // normalize_vrl is not versioned: it renders from log_sources.
            || update.normalize_vrl.is_some(),
        draft_changed: update.parser_vrl.is_some()
            || update.output_fields.is_some()
            || update.extension_vrl.is_some()
            || update.extension_enabled.is_some(),
        output_fields_changed: update.output_fields.is_some(),
    }
}

#[cfg(test)]
#[path = "deployed_reset_flags_tests.rs"]
mod deployed_reset_flags_tests;
