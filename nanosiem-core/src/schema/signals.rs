// SPDX-License-Identifier: AGPL-3.0-or-later

//! [`SignalsProfile`] — the [`SchemaProfile`] implementation for the derived
//! detection-matches dataset (`dataset=signals`, NAN-5612).
//!
//! Like [`RiskProfile`](super::risk::RiskProfile) this is a **per-QUERY
//! dataset** profile (injected by `with_dataset(Dataset::Signals)`), never a
//! tenant log schema. Its "table" is a DERIVED, window-bound subquery: the
//! shared detections source (`crate::hunts::detections::detections_source_scoped`,
//! real-time `signals` rows plus scheduled findings rows), so the field
//! universe is exactly that source's ten columns and there is NO spill tail:
//! an unknown field resolves to a bare identifier that fails loudly at
//! ClickHouse rather than silently reading a nonexistent `ext`/Map column.

use std::borrow::Cow;
use std::collections::HashSet;
use std::sync::OnceLock;

use super::profile::SchemaProfile;
use super::types::{
    EnrichmentKind, EnrichmentMode, EntityRole, EntityType, FieldCategory, FieldDef,
    FieldResolution, FieldType, SchemaId,
};
use crate::query::clickhouse_sql_gen::otel::{SIGNALS_COLUMNS, SIGNALS_NUMERIC_COLUMNS};

/// The real-time half of the derived source. The generator never scans this
/// directly for a signals query (its FROM is the derived union), but the
/// trait's storage binding must name a real table for introspection callers.
const SIGNALS_TABLE_NAME: &str = "nanosiem.signals";

const SIGNALS_TIMESTAMP_EXPR: &str = "timestamp";

/// Bare-keyword target: the rule name is the free-text-ish column analysts
/// type (`dataset=signals powershell`).
const SIGNALS_KEYWORD_COLUMN: &str = "rule_name";

/// Default table-view / FieldsPanel summary columns (the triage shape).
const SIGNALS_DEFAULT_TABLE_FIELDS: &[&str] = &[
    "timestamp",
    "rule_name",
    "severity",
    "risk_entity",
    "risk_score",
    "source_type",
    "detection_path",
];

/// Columns written lowercase by both legs of the source (`severity` is the
/// lowercased enum on real-time rows and `lower(f.severity)` on findings;
/// `detection_path` is a literal). Equality compares raw.
const SIGNALS_LOWERCASED: &[&str] = &["severity", "detection_path"];

/// ClickHouse `UUID` columns: equality compares as a UUID.
const SIGNALS_UUID_COLUMNS: &[&str] = &["id", "rule_id", "matched_log_id"];

fn promoted() -> &'static HashSet<&'static str> {
    static SET: OnceLock<HashSet<&'static str>> = OnceLock::new();
    SET.get_or_init(|| SIGNALS_COLUMNS.iter().copied().collect())
}

fn numeric() -> &'static HashSet<&'static str> {
    static SET: OnceLock<HashSet<&'static str>> = OnceLock::new();
    SET.get_or_init(|| SIGNALS_NUMERIC_COLUMNS.iter().copied().collect())
}

fn fields() -> &'static [FieldDef] {
    static FIELDS: OnceLock<Vec<FieldDef>> = OnceLock::new();
    FIELDS.get_or_init(|| {
        SIGNALS_COLUMNS
            .iter()
            .map(|&name| FieldDef {
                name,
                field_type: signals_field_type(name),
                category: signals_category(name),
                entity_type: None,
            })
            .collect()
    })
}

fn signals_field_type(field: &str) -> FieldType {
    match field {
        "timestamp" => FieldType::Timestamp,
        f if numeric().contains(f) => FieldType::Long,
        _ => FieldType::String,
    }
}

fn signals_category(field: &str) -> FieldCategory {
    match field {
        "risk_score" | "risk_entity" => FieldCategory::Risk,
        "id" | "timestamp" | "source_type" => FieldCategory::System,
        _ => FieldCategory::Detection,
    }
}

/// The detection-matches dataset profile (NAN-5612).
#[derive(Debug, Default, Clone, Copy)]
pub struct SignalsProfile;

impl SignalsProfile {
    pub fn new() -> Self {
        SignalsProfile
    }
}

impl SchemaProfile for SignalsProfile {
    fn id(&self) -> SchemaId {
        SchemaId::Signals
    }

    fn fields(&self) -> &[FieldDef] {
        fields()
    }

    fn resolve(&self, npl_field: &str) -> FieldResolution {
        // Every name resolves to a direct identifier: the promoted set is the
        // source's real projection; anything else is a pipeline-computed field
        // (eval/rename output) or a genuine unknown that must fail loudly.
        FieldResolution::ExplicitColumn(npl_field.to_string())
    }

    fn canonicalize<'a>(&self, npl_field: &'a str) -> Cow<'a, str> {
        Cow::Borrowed(npl_field)
    }

    fn is_known_field(&self, name: &str) -> bool {
        promoted().contains(name)
    }

    fn field_type(&self, field: &str) -> Option<FieldType> {
        promoted().contains(field).then(|| signals_field_type(field))
    }

    fn is_lowercased_at_ingest(&self, field: &str) -> bool {
        SIGNALS_LOWERCASED.contains(&field)
    }

    fn is_numeric_field(&self, field: &str) -> bool {
        numeric().contains(field)
    }

    fn is_uuid_field(&self, field: &str) -> bool {
        SIGNALS_UUID_COLUMNS.contains(&field)
    }

    fn prewhere_fields(&self) -> &[&str] {
        &[]
    }

    fn materialized_columns(&self) -> &[&str] {
        &[]
    }

    fn category(&self, field: &str) -> FieldCategory {
        signals_category(field)
    }

    fn entity_type(&self, _field: &str) -> Option<EntityType> {
        // `risk_entity` is polymorphic (a host, user or IP), so no static
        // column typing applies.
        None
    }

    fn default_table_fields(&self) -> &[&str] {
        SIGNALS_DEFAULT_TABLE_FIELDS
    }

    fn priority_fields(&self) -> &[&str] {
        SIGNALS_DEFAULT_TABLE_FIELDS
    }

    fn keyword_search_column(&self) -> &'static str {
        SIGNALS_KEYWORD_COLUMN
    }

    fn core_fields(&self) -> &[&str] {
        SIGNALS_COLUMNS
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
        SIGNALS_TABLE_NAME
    }

    fn timestamp_expr(&self) -> &str {
        SIGNALS_TIMESTAMP_EXPR
    }
}
