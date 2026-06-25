// SPDX-License-Identifier: AGPL-3.0-or-later

//! [`MetricsProfile`] — the [`SchemaProfile`] implementation for the OpenTelemetry
//! metrics table (`nanosiem.otel_metrics`, migration 140), NAN-1555 Phase 2.
//!
//! Like [`SpansProfile`](super::spans::SpansProfile) this is a **per-QUERY
//! dataset** profile (injected by `with_dataset(Dataset::Metrics)`), never a
//! tenant log schema. Metrics are a time-series model: one row per data point
//! (`metric_name`, `value`, `service_name`, the attribute `Map` tail), keyed
//! `(metric_name, service_name, timestamp)`. nPL `stats`/`timechart` over `value`
//! map onto metric aggregation; the metrics-specific query semantics (gap-fill,
//! counter-reset-aware rate, resolution routing to the `otel_metrics_1m/_1h`
//! rollups) live in the SQL generator's metrics path.
//!
//! Field model is the same A-plus as spans: promoted columns first-class;
//! un-promoted tags resolve by dotted name into the `attributes` ->
//! `resource_attributes` `Map` tail via [`FieldResolution::MapKey`].

use std::borrow::Cow;
use std::collections::HashSet;
use std::sync::OnceLock;

use super::profile::SchemaProfile;
use super::types::{
    EnrichmentKind, EnrichmentMode, EntityRole, EntityType, FieldCategory, FieldDef,
    FieldResolution, FieldType, SchemaId,
};

/// Fully-qualified ClickHouse table for the metrics dataset (raw data points).
const METRICS_TABLE_NAME: &str = "nanosiem.otel_metrics";

/// Timestamp expression for metrics — the data point time (migration 140).
const METRICS_TIMESTAMP_EXPR: &str = "timestamp";

/// The primary / fallback attribute `Map` columns (data-point + resource tags).
const METRICS_TAIL_COLUMN: &str = "attributes";
const METRICS_TAIL_FALLBACK_COLUMN: &str = "resource_attributes";

/// Bare-keyword target. Metrics carry no free-text body; `metric_name` is the
/// closest searchable identifier (no text index, but `hasAllTokens` still works).
const METRICS_KEYWORD_COLUMN: &str = "metric_name";

/// Promoted, first-class columns of `otel_metrics` (migration 140).
const METRIC_PROMOTED_COLUMNS: &[&str] = &[
    "metric_name",
    "metric_type",
    "unit",
    "value",
    "count",
    "sum",
    "bucket_counts",
    "explicit_bounds",
    "service_name",
    "timestamp",
    "ingest_time",
    "attributes",
    "resource_attributes",
];

/// Columns conventionally lowercase at ingest (OTel metric names + service names
/// are lowercase dotted identifiers — verified 0 mixed-case on local CH). Skipping
/// the `lower()` wrapper keeps the `idx_metric_name` set index and the
/// `(metric_name, service_name, …)` sort-key prefix prunable on equality.
const METRICS_LOWERCASED_AT_INGEST: &[&str] = &["metric_name", "service_name"];

/// Numeric value columns (no `lower()`, string literals coerce to numbers).
const METRICS_NUMERIC_COLUMNS: &[&str] = &["value", "count", "sum"];

/// Default table-view / FieldsPanel summary columns.
const METRICS_DEFAULT_TABLE_FIELDS: &[&str] = &[
    "timestamp",
    "metric_name",
    "metric_type",
    "service_name",
    "value",
    "unit",
];

/// Always-projected core fields for a slim metrics query: identity (`metric_name`/
/// `service_name`), time (`timestamp`), and the scalar (`value`).
const METRICS_CORE_FIELDS: &[&str] = &["metric_name", "service_name", "timestamp", "value"];

fn promoted() -> &'static HashSet<&'static str> {
    static SET: OnceLock<HashSet<&'static str>> = OnceLock::new();
    SET.get_or_init(|| METRIC_PROMOTED_COLUMNS.iter().copied().collect())
}

fn lowercased() -> &'static HashSet<&'static str> {
    static SET: OnceLock<HashSet<&'static str>> = OnceLock::new();
    SET.get_or_init(|| METRICS_LOWERCASED_AT_INGEST.iter().copied().collect())
}

fn numeric() -> &'static HashSet<&'static str> {
    static SET: OnceLock<HashSet<&'static str>> = OnceLock::new();
    SET.get_or_init(|| METRICS_NUMERIC_COLUMNS.iter().copied().collect())
}

fn fields() -> &'static [FieldDef] {
    static FIELDS: OnceLock<Vec<FieldDef>> = OnceLock::new();
    FIELDS.get_or_init(|| {
        METRIC_PROMOTED_COLUMNS
            .iter()
            .map(|&name| FieldDef {
                name,
                field_type: metric_field_type(name),
                category: FieldCategory::Performance,
                entity_type: None,
            })
            .collect()
    })
}

fn metric_field_type(field: &str) -> FieldType {
    match field {
        "value" | "sum" => FieldType::Float,
        "count" => FieldType::Long,
        "timestamp" | "ingest_time" => FieldType::Timestamp,
        "bucket_counts" | "explicit_bounds" | "attributes" | "resource_attributes" => {
            FieldType::Array
        }
        _ => FieldType::String,
    }
}

/// Canonicalize a flat nPL field token to its promoted metric column (NAN-1555).
/// Dotted names are attribute-tail keys (pass through). NO UDM aliasing
/// (`service_name` stays itself). Single source of truth shared with the
/// generator's value/group/filter seams.
pub(crate) fn canonicalize_metric_field(npl_field: &str) -> &str {
    if npl_field.contains('.') {
        return npl_field;
    }
    match npl_field {
        "metric" | "name" => "metric_name",
        "service" => "service_name",
        "type" => "metric_type",
        "_time" => "timestamp",
        _ => npl_field,
    }
}

/// The OpenTelemetry metrics dataset profile (NAN-1555 Phase 2).
#[derive(Debug, Default, Clone, Copy)]
pub struct MetricsProfile;

impl MetricsProfile {
    pub fn new() -> Self {
        MetricsProfile
    }
}

impl SchemaProfile for MetricsProfile {
    fn id(&self) -> SchemaId {
        SchemaId::Metrics
    }

    fn fields(&self) -> &[FieldDef] {
        fields()
    }

    fn resolve(&self, npl_field: &str) -> FieldResolution {
        let canonical = self.canonicalize(npl_field);
        let f = canonical.as_ref();
        if promoted().contains(f) {
            FieldResolution::ExplicitColumn(f.to_string())
        } else {
            FieldResolution::MapKey {
                col: METRICS_TAIL_COLUMN.to_string(),
                fallback: Some(METRICS_TAIL_FALLBACK_COLUMN.to_string()),
                key: f.to_string(),
            }
        }
    }

    fn canonicalize<'a>(&self, npl_field: &'a str) -> Cow<'a, str> {
        Cow::Borrowed(canonicalize_metric_field(npl_field))
    }

    fn is_known_field(&self, name: &str) -> bool {
        promoted().contains(self.canonicalize(name).as_ref())
    }

    fn field_type(&self, field: &str) -> Option<FieldType> {
        let canonical = self.canonicalize(field);
        promoted()
            .contains(canonical.as_ref())
            .then(|| metric_field_type(canonical.as_ref()))
    }

    fn is_lowercased_at_ingest(&self, field: &str) -> bool {
        lowercased().contains(self.canonicalize(field).as_ref())
    }

    fn is_numeric_field(&self, field: &str) -> bool {
        numeric().contains(self.canonicalize(field).as_ref())
    }

    fn is_uuid_field(&self, _field: &str) -> bool {
        false
    }

    fn prewhere_fields(&self) -> &[&str] {
        &[]
    }

    fn materialized_columns(&self) -> &[&str] {
        &[]
    }

    fn category(&self, _field: &str) -> FieldCategory {
        FieldCategory::Performance
    }

    fn entity_type(&self, _field: &str) -> Option<EntityType> {
        // Metrics carry no promoted entity columns; host/service live in the
        // attribute maps and are reached by dotted key.
        None
    }

    fn default_table_fields(&self) -> &[&str] {
        METRICS_DEFAULT_TABLE_FIELDS
    }

    fn priority_fields(&self) -> &[&str] {
        METRICS_DEFAULT_TABLE_FIELDS
    }

    fn json_tail_column(&self) -> &'static str {
        METRICS_TAIL_COLUMN
    }

    fn json_tail_fallback_column(&self) -> Option<&'static str> {
        Some(METRICS_TAIL_FALLBACK_COLUMN)
    }

    fn keyword_search_column(&self) -> &'static str {
        METRICS_KEYWORD_COLUMN
    }

    fn core_fields(&self) -> &[&str] {
        METRICS_CORE_FIELDS
    }

    fn entity_extraction_order(&self) -> &[(EntityRole, &str)] {
        &[]
    }

    fn risk_entity_default(&self) -> Option<&str> {
        None
    }

    fn enrichment_mode(&self) -> EnrichmentMode {
        EnrichmentMode::Read
    }

    fn enrichment_field(&self, _semantic: EnrichmentKind) -> Option<FieldResolution> {
        None
    }

    fn table_name(&self) -> &str {
        METRICS_TABLE_NAME
    }

    fn timestamp_expr(&self) -> &str {
        METRICS_TIMESTAMP_EXPR
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn storage_binding_is_metrics() {
        let p = MetricsProfile::new();
        assert_eq!(p.id(), SchemaId::Metrics);
        assert_eq!(p.table_name(), "nanosiem.otel_metrics");
        assert_eq!(p.timestamp_expr(), "timestamp");
        assert_eq!(p.json_tail_column(), "attributes");
        assert_eq!(p.json_tail_fallback_column(), Some("resource_attributes"));
    }

    #[test]
    fn value_and_count_are_numeric() {
        let p = MetricsProfile::new();
        assert!(p.is_numeric_field("value"));
        assert!(p.is_numeric_field("count"));
        assert!(p.is_numeric_field("sum"));
        assert!(!p.is_numeric_field("metric_name"));
        assert_eq!(
            p.resolve("value"),
            FieldResolution::ExplicitColumn("value".to_string())
        );
    }

    #[test]
    fn metric_aliases_and_tags() {
        let p = MetricsProfile::new();
        assert_eq!(
            p.resolve("service"),
            FieldResolution::ExplicitColumn("service_name".to_string())
        );
        assert_eq!(
            p.resolve("metric"),
            FieldResolution::ExplicitColumn("metric_name".to_string())
        );
        // Un-promoted tag -> Map tail with resource fallback.
        assert_eq!(
            p.resolve("http.route"),
            FieldResolution::MapKey {
                col: "attributes".to_string(),
                fallback: Some("resource_attributes".to_string()),
                key: "http.route".to_string(),
            }
        );
    }

    #[test]
    fn metric_name_is_index_friendly_lowercased() {
        let p = MetricsProfile::new();
        assert!(p.is_lowercased_at_ingest("metric_name"));
        assert!(p.is_lowercased_at_ingest("service_name"));
    }
}
