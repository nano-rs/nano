// SPDX-License-Identifier: AGPL-3.0-or-later

//! [`SpansProfile`] — the [`SchemaProfile`] implementation for the OpenTelemetry
//! spans table (`nanosiem.otel_spans`, migration 138), NAN-1555.
//!
//! Unlike [`UdmProfile`](super::udm::UdmProfile) / [`OcsfProfile`](super::ocsf::OcsfProfile)
//! — which are TENANT log schemas selected once at boot from `NANO_SCHEMA_PROFILE`
//! — `SpansProfile` is a **per-QUERY dataset** profile: the SQL generator injects
//! it via `with_dataset(Dataset::Spans)` when a request carries `dataset=spans`,
//! and the tenant logs profile (UDM/OCSF) is untouched. Datasets are orthogonal
//! to the UDM-vs-OCSF logs choice (spans are never "OCSF-unmapped"); the
//! cross-dataset bridge is the **entity overlay** (`src_ip`/`user`/`host` on
//! spans, `trace_id`/`span_id` on logs), not a shared schema.
//!
//! Field model (locked "A-plus", NAN-1555):
//! - **Promoted span columns are first-class nPL fields** — `trace_id`,
//!   `service_name`, `span_name`, `duration_ns`, the entity overlay, … resolve to
//!   [`FieldResolution::ExplicitColumn`].
//! - **Un-promoted attributes resolve generically by dotted name** into the
//!   `attributes` → `resource_attributes` `Map(LowCardinality(String), String)`
//!   tail via [`FieldResolution::MapKey`] — `http.method` →
//!   `attributes['http.method']` (literal dotted key, NOT the dot-stripped
//!   `ext.httpmethod` the UDM `Unknown` arm emits). This mirrors UDM's `ext.x` /
//!   OCSF's `event` tail access, so it is consistent for nano-natives and
//!   OTel-natives, with NO hand-maintained semconv alias table.

use std::borrow::Cow;
use std::collections::HashSet;
use std::sync::OnceLock;

use super::profile::SchemaProfile;
use super::types::{
    EnrichmentKind, EnrichmentMode, EntityRole, EntityType, FieldCategory, FieldDef,
    FieldResolution, FieldType, SchemaId,
};

/// Fully-qualified ClickHouse table for the spans dataset.
const SPANS_TABLE_NAME: &str = "nanosiem.otel_spans";

/// Timestamp expression for spans — the OTLP span START time (migration 138).
const SPANS_TIMESTAMP_EXPR: &str = "start_time";

/// The primary attribute `Map` column (span-level attributes). The OTel analog of
/// UDM's `ext` / OCSF's `unmapped` tail, but a native `Map`, not JSON.
const SPANS_TAIL_COLUMN: &str = "attributes";

/// The secondary attribute `Map` column — resource-level attributes
/// (`service.*`, `host.*`, `deployment.environment`, …). Tried when a key is
/// absent in [`SPANS_TAIL_COLUMN`].
const SPANS_TAIL_FALLBACK_COLUMN: &str = "resource_attributes";

/// The text-indexed free-text column a bare keyword tokenizes against —
/// `lower(span_name)` carries `idx_span_words` (`text(splitByNonAlpha)`,
/// migration 138), the spans analog of logs' `idx_message_words` on
/// `lower(message)`.
const SPANS_KEYWORD_COLUMN: &str = "span_name";

/// Promoted, first-class columns of `otel_spans` (migration 138). A bare nPL
/// token matching one of these (after [`canonicalize`](SpansProfile::canonicalize))
/// resolves to the direct column; everything else falls to the attribute `Map`
/// tail. `attributes` / `resource_attributes` / `events` are listed so a `| table
/// attributes` projects the raw map rather than a self-referential tail lookup.
const SPAN_PROMOTED_COLUMNS: &[&str] = &[
    "trace_id",
    "span_id",
    "parent_span_id",
    "service_name",
    "span_name",
    "span_kind",
    "status_code",
    "status_message",
    "duration_ns",
    "src_ip",
    "dest_ip",
    "user",
    "host",
    "start_time",
    "end_time",
    "ingest_time",
    "attributes",
    "resource_attributes",
    "events",
];

/// Columns lowercased at ingest (migration 138 `lower(...)` on the hex ids + the
/// entity overlay) — verified empirically (0 mixed-case rows on local CH). The
/// generator skips the redundant `lower()` wrapper on these so the bloom/set
/// index applies directly (same fast-path UDM's `LOWERCASE_NORMALIZED_FIELDS`
/// drives). `service_name`/`span_kind`/`status_code` are deliberately ABSENT:
/// `status_code`/`span_kind` carry UPPERCASE OTel enums (`OK`/`ERROR`/`SERVER`),
/// so a `lower(col) = lower(val)` comparison (both sides lowered) is the correct,
/// case-insensitive form there.
const SPANS_LOWERCASED_AT_INGEST: &[&str] = &[
    "trace_id",
    "span_id",
    "parent_span_id",
    "src_ip",
    "dest_ip",
    "user",
    "host",
];

/// Default table-view / FieldsPanel summary columns.
const SPANS_DEFAULT_TABLE_FIELDS: &[&str] = &[
    "start_time",
    "service_name",
    "span_name",
    "span_kind",
    "status_code",
    "duration_ns",
    "trace_id",
    "src_ip",
    "user",
    "host",
];

/// Always-projected core fields for a slim/table-view spans query: identity
/// (`trace_id`/`span_id` — needed for row expand + the trace-waterfall pivot),
/// time (`start_time`), and free-text display (`span_name`/`service_name`). The
/// UDM/OCSF default (`id`/`timestamp`/`message`/`source_type`) names columns that
/// do not exist on `otel_spans`, so spans MUST override it.
const SPANS_CORE_FIELDS: &[&str] = &[
    "trace_id",
    "span_id",
    "start_time",
    "span_name",
    "service_name",
];

/// Detection entity-extraction priority order — the convergence bridge. A span's
/// `src_ip`/`user`/`host` pivots to the same detections a log's would
/// (`unify entities, not schemas`). `dest_ip` is included for completeness; spans
/// carry no separate src/dst user.
const SPANS_ENTITY_EXTRACTION_ORDER: &[(EntityRole, &str)] = &[
    (EntityRole::SrcIp, "src_ip"),
    (EntityRole::DestIp, "dest_ip"),
    (EntityRole::User, "user"),
    (EntityRole::SrcHost, "host"),
];

/// O(1) promoted-column membership, built once.
fn promoted() -> &'static HashSet<&'static str> {
    static SET: OnceLock<HashSet<&'static str>> = OnceLock::new();
    SET.get_or_init(|| SPAN_PROMOTED_COLUMNS.iter().copied().collect())
}

fn lowercased() -> &'static HashSet<&'static str> {
    static SET: OnceLock<HashSet<&'static str>> = OnceLock::new();
    SET.get_or_init(|| SPANS_LOWERCASED_AT_INGEST.iter().copied().collect())
}

/// The static [`FieldDef`] universe for the FieldsPanel / LLM context.
fn fields() -> &'static [FieldDef] {
    static FIELDS: OnceLock<Vec<FieldDef>> = OnceLock::new();
    FIELDS.get_or_init(|| {
        SPAN_PROMOTED_COLUMNS
            .iter()
            .map(|&name| FieldDef {
                name,
                field_type: span_field_type(name),
                category: span_category(name),
                entity_type: span_entity_type(name),
            })
            .collect()
    })
}

/// Value type of a promoted span column (drives `lower()`/numeric/UUID decisions).
fn span_field_type(field: &str) -> FieldType {
    match field {
        "duration_ns" => FieldType::Long,
        "start_time" | "end_time" | "ingest_time" => FieldType::Timestamp,
        "src_ip" | "dest_ip" => FieldType::IpAddress,
        "attributes" | "resource_attributes" => FieldType::Array,
        _ => FieldType::String,
    }
}

/// Coarse category for a promoted span column (grouping/colorizing/LLM context).
fn span_category(field: &str) -> FieldCategory {
    match field {
        "src_ip" | "dest_ip" => FieldCategory::Network,
        "user" => FieldCategory::Authentication,
        "host" => FieldCategory::Endpoint,
        "duration_ns" => FieldCategory::Performance,
        "service_name" | "span_name" | "span_kind" | "status_code" | "status_message" => {
            FieldCategory::Web
        }
        _ => FieldCategory::System,
    }
}

/// The security entity a promoted span column denotes, if any (the overlay).
fn span_entity_type(field: &str) -> Option<EntityType> {
    match field {
        "src_ip" | "dest_ip" => Some(EntityType::Ip),
        "user" => Some(EntityType::User),
        "host" => Some(EntityType::Host),
        _ => None,
    }
}

/// Canonicalize a flat nPL field token to its promoted span column (NAN-1555).
/// Dotted names are attribute-tail keys (`http.method`) and pass through
/// untouched. Deliberately applies NO UDM-style aliasing (`service_name` stays
/// `service_name`, never `cloud_service`). Returns `&'a str` (a borrowed slice or
/// a `'static` alias literal) so the generator's value/group/filter seams can
/// canonicalize without an allocation. Single source of truth — both
/// [`SpansProfile::canonicalize`] and `ClickHouseSqlGenerator::canonicalize_field`
/// route through it.
pub(crate) fn canonicalize_span_field(npl_field: &str) -> &str {
    if npl_field.contains('.') {
        return npl_field;
    }
    match npl_field {
        "duration" | "dur" => "duration_ns",
        "service" => "service_name",
        "status" => "status_code",
        // `_time` / `timestamp` are the conventional time aliases; on spans the
        // event clock is `start_time`.
        "_time" | "timestamp" => "start_time",
        _ => npl_field,
    }
}

/// The OpenTelemetry spans dataset profile (NAN-1555).
///
/// Zero-sized; all state lives in process-wide [`OnceLock`]s. Cheap to wrap in
/// `Arc`.
#[derive(Debug, Default, Clone, Copy)]
pub struct SpansProfile;

impl SpansProfile {
    /// Construct the spans profile.
    pub fn new() -> Self {
        SpansProfile
    }
}

impl SchemaProfile for SpansProfile {
    fn id(&self) -> SchemaId {
        SchemaId::Spans
    }

    fn fields(&self) -> &[FieldDef] {
        fields()
    }

    fn resolve(&self, npl_field: &str) -> FieldResolution {
        // Canonicalize flat aliases first (`duration` → `duration_ns`); dotted
        // attribute names borrow straight through, so the Map-tail key keeps its
        // literal dotted spelling.
        let canonical = self.canonicalize(npl_field);
        let f = canonical.as_ref();
        if promoted().contains(f) {
            FieldResolution::ExplicitColumn(f.to_string())
        } else {
            // A-plus field model: any un-promoted token is an attribute lookup by
            // dotted name into `attributes`, falling back to `resource_attributes`.
            FieldResolution::MapKey {
                col: SPANS_TAIL_COLUMN.to_string(),
                fallback: Some(SPANS_TAIL_FALLBACK_COLUMN.to_string()),
                key: f.to_string(),
            }
        }
    }

    fn canonicalize<'a>(&self, npl_field: &'a str) -> Cow<'a, str> {
        // Single source of truth (no UDM aliasing — `service_name` stays itself,
        // which is exactly the bug a tenant `UdmProfile` would introduce on spans).
        Cow::Borrowed(canonicalize_span_field(npl_field))
    }

    fn is_known_field(&self, name: &str) -> bool {
        // Promoted columns (alias-aware via canonicalize) are known; un-promoted
        // attribute paths are NOT (they are tail lookups, like OCSF's unpromoted
        // `event` paths) — but a dotted attribute name is still queryable.
        promoted().contains(self.canonicalize(name).as_ref())
    }

    fn field_type(&self, field: &str) -> Option<FieldType> {
        let canonical = self.canonicalize(field);
        promoted()
            .contains(canonical.as_ref())
            .then(|| span_field_type(canonical.as_ref()))
    }

    fn is_lowercased_at_ingest(&self, field: &str) -> bool {
        lowercased().contains(self.canonicalize(field).as_ref())
    }

    fn is_numeric_field(&self, field: &str) -> bool {
        matches!(self.field_type(field), Some(FieldType::Long | FieldType::Integer | FieldType::Float))
    }

    fn is_uuid_field(&self, _field: &str) -> bool {
        // Span ids are lowercase-hex `String`, not CH `UUID` columns.
        false
    }

    fn prewhere_fields(&self) -> &[&str] {
        // Single time-bound WHERE + auto move-to-prewhere (NAN-1412): no explicit
        // PREWHERE-eligibility set is threaded for spans. Empty is the safe,
        // byte-conservative choice.
        &[]
    }

    fn materialized_columns(&self) -> &[&str] {
        // Spans have no nano-computed MATERIALIZED enrichment columns to re-add in
        // CTE stages — `SELECT *` already carries every stored span column.
        &[]
    }

    fn category(&self, field: &str) -> FieldCategory {
        let canonical = self.canonicalize(field);
        if promoted().contains(canonical.as_ref()) {
            span_category(canonical.as_ref())
        } else {
            // Un-promoted attribute → custom extension.
            FieldCategory::Custom
        }
    }

    fn entity_type(&self, field: &str) -> Option<EntityType> {
        span_entity_type(self.canonicalize(field).as_ref())
    }

    fn default_table_fields(&self) -> &[&str] {
        SPANS_DEFAULT_TABLE_FIELDS
    }

    fn priority_fields(&self) -> &[&str] {
        SPANS_DEFAULT_TABLE_FIELDS
    }

    fn json_tail_column(&self) -> &'static str {
        SPANS_TAIL_COLUMN
    }

    fn json_tail_fallback_column(&self) -> Option<&'static str> {
        Some(SPANS_TAIL_FALLBACK_COLUMN)
    }

    fn keyword_search_column(&self) -> &'static str {
        SPANS_KEYWORD_COLUMN
    }

    fn core_fields(&self) -> &[&str] {
        SPANS_CORE_FIELDS
    }

    fn entity_extraction_order(&self) -> &[(EntityRole, &str)] {
        SPANS_ENTITY_EXTRACTION_ORDER
    }

    fn risk_entity_default(&self) -> Option<&str> {
        Some("src_ip")
    }

    fn enrichment_mode(&self) -> EnrichmentMode {
        // Spans carry client-populated attributes; nano does not materialize
        // enrichment on them.
        EnrichmentMode::Read
    }

    fn enrichment_field(&self, _semantic: EnrichmentKind) -> Option<FieldResolution> {
        // No promoted enrichment columns on spans (geo/ASN, if present, live in the
        // attribute maps and are reached by dotted key like any other attribute).
        None
    }

    fn table_name(&self) -> &str {
        SPANS_TABLE_NAME
    }

    fn timestamp_expr(&self) -> &str {
        SPANS_TIMESTAMP_EXPR
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn storage_binding_is_spans() {
        let p = SpansProfile::new();
        assert_eq!(p.id(), SchemaId::Spans);
        assert_eq!(p.table_name(), "nanosiem.otel_spans");
        assert_eq!(p.timestamp_expr(), "start_time");
        assert_eq!(p.enrichment_mode(), EnrichmentMode::Read);
        assert_eq!(p.keyword_search_column(), "span_name");
        assert_eq!(p.json_tail_column(), "attributes");
        assert_eq!(p.json_tail_fallback_column(), Some("resource_attributes"));
    }

    #[test]
    fn promoted_columns_resolve_direct() {
        let p = SpansProfile::new();
        for col in [
            "trace_id",
            "service_name",
            "span_name",
            "duration_ns",
            "status_code",
            "src_ip",
            "user",
            "host",
            "start_time",
        ] {
            assert_eq!(
                p.resolve(col),
                FieldResolution::ExplicitColumn(col.to_string()),
                "{col} should resolve to a direct column",
            );
            assert!(p.is_known_field(col), "{col} should be known");
        }
    }

    #[test]
    fn flat_aliases_canonicalize_without_udm_aliasing() {
        let p = SpansProfile::new();
        // `service_name` must NOT become `cloud_service` (the UDM-profile bug).
        assert_eq!(
            p.resolve("service_name"),
            FieldResolution::ExplicitColumn("service_name".to_string())
        );
        // Ergonomic aliases.
        assert_eq!(
            p.resolve("duration"),
            FieldResolution::ExplicitColumn("duration_ns".to_string())
        );
        assert_eq!(
            p.resolve("service"),
            FieldResolution::ExplicitColumn("service_name".to_string())
        );
        assert_eq!(
            p.resolve("status"),
            FieldResolution::ExplicitColumn("status_code".to_string())
        );
    }

    #[test]
    fn unpromoted_dotted_attribute_resolves_to_map_tail() {
        let p = SpansProfile::new();
        assert_eq!(
            p.resolve("http.method"),
            FieldResolution::MapKey {
                col: "attributes".to_string(),
                fallback: Some("resource_attributes".to_string()),
                key: "http.method".to_string(),
            }
        );
        // Not a "known" field (it's a tail lookup) but still queryable.
        assert!(!p.is_known_field("http.method"));
    }

    #[test]
    fn map_tail_column_sql_emits_literal_dotted_key_with_fallback() {
        // The shared `column_sql` MapKey arm must keep the dotted key literal and
        // include the resource fallback (lockstep with `field_access_expr`).
        let p = SpansProfile::new();
        let sql = p.column_sql("http.method");
        assert!(
            sql.contains("attributes['http.method']")
                && sql.contains("resource_attributes['http.method']"),
            "MapKey must emit literal dotted Map subscript + resource fallback, got: {sql}",
        );
    }

    #[test]
    fn duration_is_numeric_ids_are_not_lowercased_enums() {
        let p = SpansProfile::new();
        assert!(p.is_numeric_field("duration_ns"));
        assert!(p.is_numeric_field("duration")); // alias
        assert!(!p.is_numeric_field("service_name"));
        // Lowercased-at-ingest fast-path: ids/overlay yes, uppercase enums no.
        assert!(p.is_lowercased_at_ingest("src_ip"));
        assert!(p.is_lowercased_at_ingest("trace_id"));
        assert!(!p.is_lowercased_at_ingest("status_code"));
        assert!(!p.is_lowercased_at_ingest("span_kind"));
    }

    #[test]
    fn projection_seams_are_span_shaped() {
        let p = SpansProfile::new();
        // No UDM `action AS event_type` rename, no MATERIALIZED enrichment re-add.
        assert!(p.default_view_renames().is_empty());
        assert!(p.materialized_columns().is_empty());
        // Core/summary fields are real `otel_spans` columns.
        assert!(p.core_fields().contains(&"start_time"));
        assert!(!p.core_fields().contains(&"timestamp"));
        assert!(!p.core_fields().contains(&"message"));
    }

    #[test]
    fn entity_overlay_is_the_convergence_bridge() {
        let p = SpansProfile::new();
        assert_eq!(p.entity_type("src_ip"), Some(EntityType::Ip));
        assert_eq!(p.entity_type("user"), Some(EntityType::User));
        assert_eq!(p.entity_type("host"), Some(EntityType::Host));
        let order: Vec<&str> = p.entity_extraction_order().iter().map(|(_, f)| *f).collect();
        assert_eq!(order.first(), Some(&"src_ip"));
    }
}
