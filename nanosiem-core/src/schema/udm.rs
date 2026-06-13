// SPDX-License-Identifier: AGPL-3.0-or-later

//! [`UdmProfile`] — the [`SchemaProfile`] implementation for today's native
//! Unified Data Model (NAN-1244 / OCSF Phase 1).
//!
//! Parity is the whole point of this phase: `UdmProfile` **references** the
//! existing canonical data — the const arrays in
//! `crate::query::clickhouse_sql_gen` and the build-time-generated
//! [`UdmField`](crate::udm::fields::UdmField) enum — rather than copying any
//! values. That guarantees byte-for-byte parity and makes the anti-drift tests
//! (`super::tests`) trivially true. No existing call site is re-pointed at this
//! profile in Phase 1; that is Phase 2.

use std::borrow::Cow;
use std::collections::HashSet;
use std::str::FromStr;
use std::sync::OnceLock;

use crate::query::{
    normalize_field_name, EXPLICIT_COLUMNS, LOWERCASE_NORMALIZED_FIELDS, MATERIALIZED_COLUMNS,
    NUMERIC_UDM_FIELDS, PREWHERE_FIELDS, UUID_FIELDS,
};
use crate::udm::fields::{UdmDataType, UdmField, UdmFieldCategory};

use super::profile::SchemaProfile;
use super::types::{
    EnrichmentKind, EnrichmentMode, EntityRole, EntityType, FieldCategory, FieldDef,
    FieldResolution, FieldType, SchemaId,
};

/// Fully-qualified ClickHouse table for the UDM schema.
const UDM_TABLE_NAME: &str = "nanosiem.logs";

/// Timestamp expression for UDM — the `timestamp` column is already `DateTime64`.
const UDM_TIMESTAMP_EXPR: &str = "timestamp";

/// Default table-view summary fields (mirrors the table-view projection used by
/// field-analysis today; consumed in Phase 2).
const UDM_DEFAULT_TABLE_FIELDS: &[&str] = &[
    "timestamp",
    "source_type",
    "src_host",
    "src_ip",
    "dest_host",
    "dest_ip",
    "user",
    "message",
];

/// Fields pinned to the top of the FieldsPanel.
const UDM_PRIORITY_FIELDS: &[&str] = &[
    "timestamp",
    "source_type",
    "src_ip",
    "dest_ip",
    "src_host",
    "dest_host",
    "user",
    "process_name",
];

/// Detection entity-extraction priority order (semantic role → physical field).
///
/// Phase 5 (NAN-1241) re-points the three hard-coded detection lists at this
/// single source. The `EntityRole` is a semantic tag; the physical field string
/// is what the detection engine extracts. A role may appear more than once
/// (e.g. several `SrcIp` physical fields) — extraction iterates the list in
/// order and the role tag is metadata for callers, not a uniqueness key.
///
/// This list is the exact UNION (and priority order) of the previously
/// hard-coded lists in `risk/calculator.rs::extract_entity` (the most complete:
/// 27 fields, incl. `*_nt_domain` and the legacy `metadata.*` paths),
/// `service/helpers.rs::group_events_by_entity`, and
/// `materialized_view.rs::auto_detect_risk_entity`. The calculator list is the
/// superset, so `extract_entity` stays byte-identical; the other two sites gain
/// the few extra trailing fields (additive — only reached when no
/// higher-priority field is present). The ordering of the leading IP → host →
/// user → hash tiers (which the priority tests assert) is unchanged.
const UDM_ENTITY_EXTRACTION_ORDER: &[(EntityRole, &str)] = &[
    // IP addresses (highest priority for network-based threats)
    (EntityRole::SrcIp, "src_ip"),
    (EntityRole::DestIp, "dest_ip"),
    (EntityRole::SrcIp, "dvc_ip"),
    (EntityRole::SrcIp, "src_translated_ip"),
    (EntityRole::DestIp, "dest_translated_ip"),
    // Hostnames (host-based threats)
    (EntityRole::SrcHost, "src_host"),
    (EntityRole::DestHost, "dest_host"),
    (EntityRole::SrcHost, "host"),
    (EntityRole::SrcHost, "hostname"),
    (EntityRole::DestHost, "dest_nt_host"),
    (EntityRole::SrcHost, "src_nt_host"),
    (EntityRole::SrcHost, "dvc"),
    // Users (user-based threats)
    (EntityRole::SrcUser, "src_user"),
    (EntityRole::DestUser, "dest_user"),
    (EntityRole::User, "user"),
    (EntityRole::SrcUser, "src_user_name"),
    (EntityRole::DestUser, "dest_user_name"),
    (EntityRole::SrcUser, "src_nt_domain"),
    (EntityRole::DestUser, "dest_nt_domain"),
    // File hashes (malware/file-based threats)
    (EntityRole::FileHash, "file_hash"),
    (EntityRole::ProcessHash, "process_hash"),
    (EntityRole::FileHash, "service_hash"),
    (EntityRole::FileHash, "service_dll_hash"),
    (EntityRole::FileHash, "ssl_hash"),
    // Legacy/nested paths for backward compatibility
    (EntityRole::SrcIp, "metadata.src_ip"),
    (EntityRole::User, "metadata.user"),
    (EntityRole::SrcHost, "metadata.hostname"),
];

/// Default-view column rewrites for UDM: drop `action` from `SELECT *` and
/// re-project it as `action AS event_type` (NAN-659/671/876). Single source of
/// the byte-identical rewrite the SQL generator emits.
const UDM_DEFAULT_VIEW_RENAMES: &[(&str, &str)] = &[("action", "event_type")];

/// Aliases `normalize_field_name` maps that the profile must NOT claim as known
/// fields (NAN-1425): the NAN-1380 G5 typo gate PINS `source_ip` as a rejected
/// near-miss of `src_ip` (`test_typos_still_rejected_under_both_profiles`,
/// `test_udm_profile_matches_profile_blind_behavior` — "did you mean src_ip"),
/// and that pinned teaching behavior takes precedence over the alias map. The
/// collision is deliberate and recorded on NAN-1425: codegen's Eq path would
/// normalize the spelling fine, but the input-side validator keeps steering
/// users to the canonical name.
const TYPO_GATE_PINNED_ALIASES: &[&str] = &["source_ip"];

/// O(1) lookup sets precomputed once. Mirrors the lazily-initialized
/// `EXPLICIT_COLUMNS_SET` in `clickhouse_sql_gen` so `resolve()` stays O(1).
struct UdmLookups {
    explicit: HashSet<&'static str>,
    lowercased: HashSet<&'static str>,
    numeric: HashSet<&'static str>,
    uuid: HashSet<&'static str>,
    fields: Vec<FieldDef>,
}

fn lookups() -> &'static UdmLookups {
    static LOOKUPS: OnceLock<UdmLookups> = OnceLock::new();
    LOOKUPS.get_or_init(|| {
        let fields = UdmField::all()
            .iter()
            .map(|f| FieldDef {
                name: f.column_name(),
                field_type: map_data_type(f.data_type()),
                category: map_category(f.category()),
                entity_type: infer_entity_type(f.column_name()),
            })
            .collect();

        UdmLookups {
            explicit: EXPLICIT_COLUMNS.iter().copied().collect(),
            lowercased: LOWERCASE_NORMALIZED_FIELDS.iter().copied().collect(),
            numeric: NUMERIC_UDM_FIELDS.iter().copied().collect(),
            uuid: UUID_FIELDS.iter().copied().collect(),
            fields,
        }
    })
}

/// Map the generated UDM data-type enum onto the schema-agnostic [`FieldType`].
fn map_data_type(dt: UdmDataType) -> FieldType {
    match dt {
        UdmDataType::String => FieldType::String,
        UdmDataType::Integer => FieldType::Integer,
        UdmDataType::Long => FieldType::Long,
        UdmDataType::Float => FieldType::Float,
        UdmDataType::Boolean => FieldType::Boolean,
        UdmDataType::IpAddress => FieldType::IpAddress,
        UdmDataType::Timestamp => FieldType::Timestamp,
        UdmDataType::Array => FieldType::Array,
    }
}

/// Map the generated UDM category enum onto the schema-agnostic [`FieldCategory`].
fn map_category(cat: UdmFieldCategory) -> FieldCategory {
    match cat {
        UdmFieldCategory::Alerts => FieldCategory::Alerts,
        UdmFieldCategory::Authentication => FieldCategory::Authentication,
        UdmFieldCategory::Certificate => FieldCategory::Certificate,
        UdmFieldCategory::Change => FieldCategory::Change,
        UdmFieldCategory::DataAccess => FieldCategory::DataAccess,
        UdmFieldCategory::Database => FieldCategory::Database,
        UdmFieldCategory::DataLossPrevention => FieldCategory::DataLossPrevention,
        UdmFieldCategory::Dns => FieldCategory::Dns,
        UdmFieldCategory::Email => FieldCategory::Email,
        UdmFieldCategory::Endpoint => FieldCategory::Endpoint,
        UdmFieldCategory::InterprocessMessaging => FieldCategory::InterprocessMessaging,
        UdmFieldCategory::Intrusion => FieldCategory::Intrusion,
        UdmFieldCategory::Inventory => FieldCategory::Inventory,
        UdmFieldCategory::Malware => FieldCategory::Malware,
        UdmFieldCategory::Network => FieldCategory::Network,
        UdmFieldCategory::Performance => FieldCategory::Performance,
        UdmFieldCategory::Vulnerability => FieldCategory::Vulnerability,
        UdmFieldCategory::Web => FieldCategory::Web,
        UdmFieldCategory::Custom => FieldCategory::Custom,
        UdmFieldCategory::System => FieldCategory::System,
        UdmFieldCategory::Enrichment => FieldCategory::Enrichment,
        UdmFieldCategory::ThreatIntelligence => FieldCategory::ThreatIntelligence,
        UdmFieldCategory::CustomEnrichment => FieldCategory::CustomEnrichment,
        UdmFieldCategory::Prevalence => FieldCategory::Prevalence,
        UdmFieldCategory::Risk => FieldCategory::Risk,
        UdmFieldCategory::Detection => FieldCategory::Detection,
        UdmFieldCategory::Cloud => FieldCategory::Cloud,
    }
}

/// Infer the security-entity type for a UDM field from its canonical name.
/// Conservative: returns `None` unless the name clearly denotes a known entity.
fn infer_entity_type(name: &str) -> Option<EntityType> {
    match name {
        "src_ip" | "dest_ip" | "dvc_ip" => Some(EntityType::Ip),
        "src_host" | "dest_host" | "dvc" => Some(EntityType::Host),
        "user" | "src_user" | "dest_user" | "user_name" => Some(EntityType::User),
        "file_hash" | "process_hash" => Some(EntityType::Hash),
        "url_domain" | "sender_domain" | "recipient_domain" | "prevalence_dest_domain" => {
            Some(EntityType::Domain)
        }
        "url" => Some(EntityType::Url),
        "process_name" => Some(EntityType::Process),
        "file_name" | "file_path" => Some(EntityType::File),
        _ => None,
    }
}

/// The Unified Data Model schema profile.
///
/// Zero-sized; all state lives in process-wide [`OnceLock`] lookups. Cheap to
/// construct and to wrap in `Arc`.
#[derive(Debug, Default, Clone, Copy)]
pub struct UdmProfile;

impl UdmProfile {
    /// Construct the UDM profile.
    pub fn new() -> Self {
        UdmProfile
    }

    /// Raw-spelling membership in the UDM field universe — the historical
    /// [`is_known_field`](SchemaProfile::is_known_field) body: explicit column
    /// OR a valid generated [`UdmField`]. No alias canonicalization.
    fn is_known_raw(name: &str) -> bool {
        lookups().explicit.contains(name) || UdmField::from_str(name).is_ok()
    }

    /// The explicit-alias rewrite the profile accepts (NAN-1425), mirroring
    /// NAN-1422's gated alias authority on the OCSF side. The
    /// `normalize_field_name` rewrite is claimed only when ALL of:
    ///
    /// 1. it actually rewrites (`sourcetype` → `source_type`; non-aliased names
    ///    return the input slice and never enter this path),
    /// 2. the raw spelling is NOT itself a known UDM field — a real field never
    ///    re-aliases. This keeps `service_name` (a generated `UdmField` whose
    ///    spelling the codegen map happens to rewrite to `cloud_service`)
    ///    resolving as itself, per the `schema::tests` anti-drift gates,
    /// 3. the normalized target IS a physical explicit column of `logs` — an
    ///    alias whose target only exists in the CSV universe (`destination` →
    ///    `dest`) does not rewrite; it stays exactly as unknown as before and
    ///    spills to `ext` under its raw spelling, and
    /// 4. the alias is not a pinned typo case ([`TYPO_GATE_PINNED_ALIASES`]):
    ///    the NAN-1380 G5 gate's `source_ip` → "did you mean src_ip" rejection
    ///    takes precedence over the alias map.
    ///
    /// This is what lets the input-side field validator accept the explicit
    /// alias set without weakening the typo gate: `is_known_field` (the gate's
    /// G5 predicate) and `resolve` (the IN-list seam, which passes RAW names)
    /// both consult it, so an accepted alias lands on the same physical column
    /// as its canonical spelling.
    fn accepted_alias(name: &str) -> Option<&str> {
        if TYPO_GATE_PINNED_ALIASES.contains(&name) {
            return None;
        }
        let normalized = normalize_field_name(name);
        if std::ptr::eq(normalized, name) || Self::is_known_raw(name) {
            return None;
        }
        lookups().explicit.contains(normalized).then_some(normalized)
    }
}

impl SchemaProfile for UdmProfile {
    fn id(&self) -> SchemaId {
        SchemaId::Udm
    }

    fn fields(&self) -> &[FieldDef] {
        &lookups().fields
    }

    fn resolve(&self, npl_field: &str) -> FieldResolution {
        // Byte-for-byte parity with is_explicit_column(): known explicit column →
        // direct column reference; everything else is Unknown (routed to ext by
        // the SQL generator in Phase 2).
        if lookups().explicit.contains(npl_field) {
            FieldResolution::ExplicitColumn(npl_field.to_string())
        } else if let Some(canonical) = Self::accepted_alias(npl_field) {
            // NAN-1425: the explicit alias set resolves to its canonical
            // physical column, so codegen seams that pass the RAW name — the
            // IN-list filter, `is_text_column` — land on the same column as
            // the canonical spelling (codegen's Eq path already normalizes
            // before consulting the profile, so this only changes names that
            // previously resolved Unknown and spilled to `ext.<alias>`).
            FieldResolution::ExplicitColumn(canonical.to_string())
        } else {
            FieldResolution::Unknown
        }
    }

    fn canonicalize<'a>(&self, npl_field: &'a str) -> Cow<'a, str> {
        // OCSF Phase 2: delegate to the canonical alias map (sourcetype →
        // source_type, hostname → host, …) rather than duplicating it. The free
        // fn returns the input slice unchanged when no alias applies (Borrowed),
        // and a `&'static str` literal when it rewrites (Owned).
        let normalized = normalize_field_name(npl_field);
        if std::ptr::eq(normalized, npl_field) {
            Cow::Borrowed(npl_field)
        } else {
            Cow::Owned(normalized.to_string())
        }
    }

    fn is_known_field(&self, name: &str) -> bool {
        // Mirrors is_udm_field()'s first two branches: explicit column OR a valid
        // UdmField from the CSV. (The computed-aggregation-name branch belongs to
        // the SQL generator's pipeline context, not the schema universe.)
        // NAN-1425: alias-aware — the gated explicit alias set (`sourcetype` →
        // `source_type`, `_time` → `timestamp`, …) belongs to the field
        // universe too. This is the predicate the input-side field validator
        // consults (NAN-1380 G5): `sourcetype` sits one edit from
        // `source_type`, so without this it was 400-rejected as a typo while
        // codegen normalized it fine. Pinned typo cases (`source_ip`) are
        // excluded — the gate keeps precedence.
        Self::is_known_raw(name) || Self::accepted_alias(name).is_some()
    }

    fn field_type(&self, field: &str) -> Option<FieldType> {
        if lookups().uuid.contains(field) {
            return Some(FieldType::Uuid);
        }
        UdmField::from_str(field)
            .ok()
            .map(|f| map_data_type(f.data_type()))
    }

    fn is_lowercased_at_ingest(&self, field: &str) -> bool {
        lookups().lowercased.contains(field)
    }

    fn is_numeric_field(&self, field: &str) -> bool {
        // NAN-1425: judged on the accepted-alias target too, so the IN-list
        // seam (which passes RAW names) types `response_code IN ("200")`
        // exactly like `http_status_code IN ("200")` — the numeric branch —
        // instead of emitting `lower(<UInt16 col>)` (CH type error).
        lookups().numeric.contains(field)
            || Self::accepted_alias(field).is_some_and(|c| lookups().numeric.contains(c))
    }

    fn is_uuid_field(&self, field: &str) -> bool {
        // NAN-1425: alias-aware for the same IN-list seam consistency as
        // `is_numeric_field` (no current alias targets a UUID column; this
        // keeps the predicates agreeing if one ever does).
        lookups().uuid.contains(field)
            || Self::accepted_alias(field).is_some_and(|c| lookups().uuid.contains(c))
    }

    fn prewhere_fields(&self) -> &[&str] {
        PREWHERE_FIELDS
    }

    fn materialized_columns(&self) -> &[&str] {
        MATERIALIZED_COLUMNS
    }

    fn category(&self, field: &str) -> FieldCategory {
        UdmField::from_str(field)
            .ok()
            .map(|f| map_category(f.category()))
            .unwrap_or(FieldCategory::Custom)
    }

    fn entity_type(&self, field: &str) -> Option<EntityType> {
        infer_entity_type(field)
    }

    fn default_table_fields(&self) -> &[&str] {
        UDM_DEFAULT_TABLE_FIELDS
    }

    fn priority_fields(&self) -> &[&str] {
        UDM_PRIORITY_FIELDS
    }

    fn default_view_renames(&self) -> &[(&str, &str)] {
        // `action` is the physical column for what UDM canonically calls
        // `event_type` (NAN-659). The default-view projection drops `action`
        // from `SELECT *` and re-projects it as `action AS event_type`. This is
        // the single source of the byte-identical UDM rewrite.
        UDM_DEFAULT_VIEW_RENAMES
    }

    fn entity_extraction_order(&self) -> &[(EntityRole, &str)] {
        UDM_ENTITY_EXTRACTION_ORDER
    }

    fn risk_entity_default(&self) -> Option<&str> {
        Some("risk_entity")
    }

    fn enrichment_mode(&self) -> EnrichmentMode {
        // UDM owns ingestion: enrichment is computed via MATERIALIZED columns + dicts.
        EnrichmentMode::Materialized
    }

    fn enrichment_field(&self, semantic: EnrichmentKind) -> Option<FieldResolution> {
        let col = match semantic {
            EnrichmentKind::SrcCountry => "enriched_src_country",
            EnrichmentKind::SrcAsn => "enriched_src_asn",
            EnrichmentKind::DestCountry => "enriched_dest_country",
            EnrichmentKind::DestAsn => "enriched_dest_asn",
            EnrichmentKind::IocMatch => "ioc_matched",
            EnrichmentKind::Prevalence => "prevalence_file_hash",
        };
        Some(FieldResolution::ExplicitColumn(col.to_string()))
    }

    fn table_name(&self) -> &str {
        UDM_TABLE_NAME
    }

    fn timestamp_expr(&self) -> &str {
        UDM_TIMESTAMP_EXPR
    }
}
