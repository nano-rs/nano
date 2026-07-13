// SPDX-License-Identifier: AGPL-3.0-or-later

//! [`RiskProfile`] — the [`SchemaProfile`] implementation for the derived
//! accumulated-risk dataset (`dataset=risk`, NAN-1798 P2).
//!
//! Like [`SpansProfile`](super::spans::SpansProfile) /
//! [`MetricsProfile`](super::metrics::MetricsProfile) this is a **per-QUERY
//! dataset** profile (injected by `with_dataset(Dataset::Risk)`), never a
//! tenant log schema. Unlike those, its "table" is a DERIVED subquery — the
//! shared risk builder's entity-grain aggregation over the findings stream
//! (`crate::risk::clickhouse_sql::risk_dataset_base_query`) — so the field
//! universe is exactly the subquery's 15-column projection and there is NO
//! spill tail: an unknown field resolves to a bare identifier that fails
//! loudly at ClickHouse rather than silently reading a nonexistent `ext`/Map
//! column.

use std::borrow::Cow;
use std::collections::HashSet;
use std::sync::OnceLock;

use super::profile::SchemaProfile;
use super::types::{
    EnrichmentKind, EnrichmentMode, EntityRole, EntityType, FieldCategory, FieldDef,
    FieldResolution, FieldType, SchemaId,
};
use crate::query::clickhouse_sql_gen::otel::{RISK_COLUMNS, RISK_NUMERIC_COLUMNS};

/// The dataset's UNDERLYING storage (the findings stream lives in the logs
/// table). The generator never scans this directly for a risk query — its FROM
/// is the derived subquery — but the trait's storage binding must name a real
/// table for introspection callers.
const RISK_TABLE_NAME: &str = "nanosiem.logs";

/// The derived grain's only time-typed column (`fromUnixTimestamp64Micro(max(ts_micros))`).
const RISK_TIMESTAMP_EXPR: &str = "last_finding_at";

/// Bare-keyword target: the entity value is the only free-text-ish identifier
/// on the grain, so `search dataset=risk 10.0.0` matches by entity.
const RISK_KEYWORD_COLUMN: &str = "entity";

/// Default table-view / FieldsPanel summary columns — the risk-notable triage
/// shape (entity + both decayed windows + last-fire context).
const RISK_DEFAULT_TABLE_FIELDS: &[&str] = &[
    "entity",
    "entity_type",
    "score_24h",
    "score_7d",
    "distinct_rules_7d",
    "last_finding_at",
    "last_rule_name",
    "last_severity",
];

fn promoted() -> &'static HashSet<&'static str> {
    static SET: OnceLock<HashSet<&'static str>> = OnceLock::new();
    SET.get_or_init(|| RISK_COLUMNS.iter().copied().collect())
}

fn numeric() -> &'static HashSet<&'static str> {
    static SET: OnceLock<HashSet<&'static str>> = OnceLock::new();
    SET.get_or_init(|| RISK_NUMERIC_COLUMNS.iter().copied().collect())
}

fn fields() -> &'static [FieldDef] {
    static FIELDS: OnceLock<Vec<FieldDef>> = OnceLock::new();
    FIELDS.get_or_init(|| {
        RISK_COLUMNS
            .iter()
            .map(|&name| FieldDef {
                name,
                field_type: risk_field_type(name),
                category: FieldCategory::Risk,
                entity_type: None,
            })
            .collect()
    })
}

fn risk_field_type(field: &str) -> FieldType {
    match field {
        "last_finding_at" => FieldType::Timestamp,
        f if numeric().contains(f) => FieldType::Long,
        _ => FieldType::String,
    }
}

/// The accumulated-risk dataset profile (NAN-1798 P2).
#[derive(Debug, Default, Clone, Copy)]
pub struct RiskProfile;

impl RiskProfile {
    pub fn new() -> Self {
        RiskProfile
    }
}

impl SchemaProfile for RiskProfile {
    fn id(&self) -> SchemaId {
        SchemaId::Risk
    }

    fn fields(&self) -> &[FieldDef] {
        fields()
    }

    fn resolve(&self, npl_field: &str) -> FieldResolution {
        // Every name resolves to a direct identifier: the promoted set is the
        // subquery's real projection; anything else is a pipeline-computed
        // field (eval/rename output) or a genuine unknown that must fail
        // loudly at ClickHouse — there is no spill tail on the derived grain.
        FieldResolution::ExplicitColumn(npl_field.to_string())
    }

    fn canonicalize<'a>(&self, npl_field: &'a str) -> Cow<'a, str> {
        Cow::Borrowed(npl_field)
    }

    fn is_known_field(&self, name: &str) -> bool {
        promoted().contains(name)
    }

    fn field_type(&self, field: &str) -> Option<FieldType> {
        promoted().contains(field).then(|| risk_field_type(field))
    }

    fn is_lowercased_at_ingest(&self, _field: &str) -> bool {
        // `risk_entity` (and thus `entity`) is written raw by the finding
        // logger — the repository compares raw too, so no ingest-lowercase
        // equality shortcut applies on this grain.
        false
    }

    fn is_numeric_field(&self, field: &str) -> bool {
        numeric().contains(field)
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
        FieldCategory::Risk
    }

    fn entity_type(&self, _field: &str) -> Option<EntityType> {
        // The grain's `entity` is polymorphic (typed by the sibling
        // `entity_type` VALUE), so no static column typing applies.
        None
    }

    fn default_table_fields(&self) -> &[&str] {
        RISK_DEFAULT_TABLE_FIELDS
    }

    fn priority_fields(&self) -> &[&str] {
        RISK_DEFAULT_TABLE_FIELDS
    }

    fn keyword_search_column(&self) -> &'static str {
        RISK_KEYWORD_COLUMN
    }

    fn core_fields(&self) -> &[&str] {
        RISK_COLUMNS
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
        RISK_TABLE_NAME
    }

    fn timestamp_expr(&self) -> &str {
        RISK_TIMESTAMP_EXPR
    }
}

#[cfg(test)]
#[path = "risk_tests.rs"]
mod risk_tests;
