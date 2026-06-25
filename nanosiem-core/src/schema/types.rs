// SPDX-License-Identifier: AGPL-3.0-or-later

//! Supporting types for the [`SchemaProfile`](crate::schema::SchemaProfile) seam.
//!
//! These are the schema-agnostic vocabulary the trait speaks in. `UdmProfile`
//! and (later) `OcsfProfile` both express their field universe, resolution, and
//! query-optimization hints through these types. They are intentionally minimal
//! but complete enough that a future `OcsfProfile` can implement the same trait
//! without changing this module (NAN-1244, OCSF Phase 1).

use serde::{Deserialize, Serialize};

/// Identity of an active schema profile.
///
/// Selected per-deployment at boot (see scoping §2.4). A deployment has exactly
/// one active schema; the enum leaves a forward door for per-source later without
/// building it now.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SchemaId {
    /// Today's native Unified Data Model.
    Udm,
    /// Open Cybersecurity Schema Framework.
    Ocsf,
    /// OpenTelemetry spans (`otel_spans`) — a per-QUERY dataset profile, NOT a
    /// tenant log schema (NAN-1555). Selected via `/search?dataset=spans` and
    /// injected by the SQL generator's `with_dataset(Spans)`, never by the
    /// `NANO_SCHEMA_PROFILE` env (`from_env_str` rejects it). Datasets are
    /// orthogonal to the UDM-vs-OCSF logs choice: spans carry the entity overlay
    /// (`src_ip`/`user`/`host`) and a CH `Map` attribute tail, so they are never
    /// "OCSF-unmapped" — the cross-dataset bridge is entities, not schemas.
    Spans,
    /// OpenTelemetry metrics (`otel_metrics`) — a per-QUERY dataset profile like
    /// [`Spans`](SchemaId::Spans), NOT a tenant log schema (NAN-1555 Phase 2).
    /// A time-series model: `stats`/`timechart` over `value` map onto metric
    /// aggregation, with gap-fill, counter-reset-aware rates, and resolution
    /// routing to the `otel_metrics_1m/_1h` rollups handled in the SQL generator.
    Metrics,
}

impl SchemaId {
    /// Parse the active schema id from the `NANO_SCHEMA_PROFILE` env value.
    ///
    /// `udm` (the default) and `ocsf` are accepted, case-insensitively, with
    /// surrounding whitespace trimmed. An empty/unset value resolves to
    /// [`SchemaId::Udm`] so the default deployment is unchanged. Any other value
    /// is an error — boot fails fast (DualPool fail-fast philosophy, NAN-800)
    /// rather than silently falling back to UDM against an OCSF table.
    pub fn from_env_str(value: &str) -> Result<Self, String> {
        match value.trim().to_ascii_lowercase().as_str() {
            "" | "udm" => Ok(SchemaId::Udm),
            "ocsf" => Ok(SchemaId::Ocsf),
            other => Err(format!(
                "invalid NANO_SCHEMA_PROFILE {other:?}: expected \"udm\" or \"ocsf\""
            )),
        }
    }
}

/// How an nPL field token maps to its physical ClickHouse location.
///
/// This is the pivotal type that makes OCSF's nesting tractable without
/// translating to UDM. `UdmProfile` only ever emits [`ExplicitColumn`] (known
/// names) or [`Unknown`] (everything else, which the SQL generator routes to the
/// `ext` JSON column) — byte-for-byte identical to today's `is_explicit_column()`
/// behavior. `OcsfProfile` additionally uses [`JsonPath`] / [`ArrayElement`] /
/// [`Alias`] for its nested layout.
///
/// [`ExplicitColumn`]: FieldResolution::ExplicitColumn
/// [`Unknown`]: FieldResolution::Unknown
/// [`JsonPath`]: FieldResolution::JsonPath
/// [`ArrayElement`]: FieldResolution::ArrayElement
/// [`Alias`]: FieldResolution::Alias
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FieldResolution {
    /// Direct ClickHouse column (UDM `src_ip`; OCSF a promoted/flattened column).
    ExplicitColumn(String),
    /// `JSONExtract(col, 'a', 'b', 'c')` for OCSF nested paths in a JSON column.
    JsonPath {
        /// The JSON-typed column holding the record (e.g. `event`, or UDM `ext`).
        col: String,
        /// The ordered path segments to extract (e.g. `["actor", "process", "cmd_line"]`).
        path: Vec<String>,
    },
    /// An OCSF array element selected by a key attribute, e.g. `file.hashes[]`
    /// where `algorithm_id == 3` yields `.value`.
    ArrayElement {
        /// The JSON-typed column holding the record.
        col: String,
        /// Path to the array (e.g. `["file", "hashes"]`).
        path: Vec<String>,
        /// The element attribute used to select the desired entry (e.g. `algorithm_id`).
        key_attr: String,
        /// The value `key_attr` must equal (e.g. SHA-256 == 3).
        key_val: i64,
        /// The element attribute to extract from the matched entry (e.g. `value`).
        value_attr: String,
    },
    /// A schema alias to another physical column (UDM `action AS event_type`).
    Alias(String),
    /// A ClickHouse `Map(String, String)` subscript — the spans/metrics attribute
    /// tail (NAN-1555). Unlike [`JsonPath`] (a JSON column the generator extracts
    /// from), the tail is a native `Map` column, so access is `col['key']` with
    /// the LITERAL dotted key preserved (`attributes['http.method']`, NOT the
    /// dot-stripped `ext.httpmethod` the UDM `Unknown` arm emits). `fallback`, when
    /// set, is a second `Map` column tried when `key` is absent in `col`
    /// (`resource_attributes` for spans), so an OTel attribute matches regardless
    /// of which map carries it.
    ///
    /// [`JsonPath`]: FieldResolution::JsonPath
    MapKey {
        /// The primary `Map` column (e.g. `attributes`).
        col: String,
        /// A secondary `Map` column to fall back to when `key` is absent in `col`
        /// (e.g. `resource_attributes`), or `None` for no fallback.
        fallback: Option<String>,
        /// The literal map key (dotted OTel attribute name, e.g. `http.method`).
        key: String,
    },
    /// Field is not part of this schema's universe; falls to the overflow column
    /// (`ext` for UDM, `unmapped`/`event` tail for OCSF).
    Unknown,
}

/// Physical/value type of a field, used to drive query-optimization decisions
/// (whether to apply `lower()`, numeric coercion, `toString()` for UUIDs, etc.).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FieldType {
    /// String/text value.
    String,
    /// Integer value.
    Integer,
    /// Long integer value.
    Long,
    /// Floating point value.
    Float,
    /// Boolean value.
    Boolean,
    /// IP address (IPv4 or IPv6).
    IpAddress,
    /// Timestamp with timezone.
    Timestamp,
    /// Array of values.
    Array,
    /// ClickHouse `UUID` type (compared via `toString()`, never `lower()`).
    Uuid,
}

/// Coarse category for grouping/colorizing fields in UX and for LLM context.
///
/// Mirrors the concepts in the UDM `UdmFieldCategory` enum but is deliberately a
/// distinct, schema-agnostic type so a future `OcsfProfile` can map its own
/// taxonomy onto these without depending on the generated UDM enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FieldCategory {
    /// Alert-related fields.
    Alerts,
    /// Authentication-related fields.
    Authentication,
    /// Certificate-related fields (SSL/TLS).
    Certificate,
    /// Change management fields.
    Change,
    /// Data access fields.
    DataAccess,
    /// Database-related fields.
    Database,
    /// Data loss prevention fields.
    DataLossPrevention,
    /// DNS resolution fields.
    Dns,
    /// Email message fields.
    Email,
    /// Endpoint/host fields.
    Endpoint,
    /// Interprocess messaging fields.
    InterprocessMessaging,
    /// Intrusion detection fields.
    Intrusion,
    /// Asset inventory fields.
    Inventory,
    /// Malware detection fields.
    Malware,
    /// Network traffic fields.
    Network,
    /// System performance fields.
    Performance,
    /// Vulnerability scanning fields.
    Vulnerability,
    /// Web/HTTP traffic fields.
    Web,
    /// Custom extensions.
    Custom,
    /// System/metadata fields (`source_type`, `ingest_time`, etc.).
    System,
    /// GeoIP/ASN enrichment fields.
    Enrichment,
    /// IOC/threat intelligence fields.
    ThreatIntelligence,
    /// Custom enrichment fields (user-defined IOC feeds).
    CustomEnrichment,
    /// Prevalence tracking fields (artifact rarity).
    Prevalence,
    /// Risk scoring fields.
    Risk,
    /// Detection engine fields (`rule_id`, `rule_name`).
    Detection,
    /// Cloud infrastructure and SaaS fields.
    Cloud,
}

/// The kind of security entity a field represents, used for drilldowns,
/// entity panels, and detection entity extraction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EntityType {
    /// IP address.
    Ip,
    /// Hostname / device.
    Host,
    /// User / account.
    User,
    /// File or process hash.
    Hash,
    /// Domain name.
    Domain,
    /// URL.
    Url,
    /// Process.
    Process,
    /// File.
    File,
}

/// Semantic role of a field for detection entity extraction. The profile maps
/// each role to one or more physical fields in priority order, replacing the
/// three hard-coded entity-priority lists in the detection engine (scoping §2.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EntityRole {
    /// Source IP address.
    SrcIp,
    /// Destination IP address.
    DestIp,
    /// Source host.
    SrcHost,
    /// Destination host.
    DestHost,
    /// Acting / primary user.
    User,
    /// Source user.
    SrcUser,
    /// Destination user.
    DestUser,
    /// File hash.
    FileHash,
    /// Process hash.
    ProcessHash,
    /// Domain.
    Domain,
}

/// Who owns and computes enrichment for the active schema.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EnrichmentMode {
    /// nanosiem computes enrichment via ClickHouse `MATERIALIZED` columns + dicts
    /// at insert time (UDM mode — we own ingestion).
    Materialized,
    /// The client materialized enrichment inline; nanosiem only reads it
    /// (OCSF mode — we do not own ingestion).
    Read,
}

/// A semantic enrichment concept that the UI surfaces, mapped by the profile to
/// the physical field/path that carries it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EnrichmentKind {
    /// Source IP country.
    SrcCountry,
    /// Source IP ASN.
    SrcAsn,
    /// Destination IP country.
    DestCountry,
    /// Destination IP ASN.
    DestAsn,
    /// IOC match indicator / threat-intel.
    IocMatch,
    /// Artifact prevalence.
    Prevalence,
}

/// How a schema translates human enum LABELS onto an enum-INT column so a
/// string-verb predicate (`auth_result="failure"`) can compare against the
/// integer the column actually stores (NAN-1382 / parity gap G6). Without a
/// mapping the codegen falls back to `lower(toString(<int col>))`, which can
/// never equal a verb → silent zero matches.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnumIntMapping<'a> {
    /// Fixed, class-independent `lowercase label → integer id` table (manifest
    /// `enum_values`), e.g. OCSF `status_id` 1=Success / 2=Failure. The verb is
    /// translated to the id and compared on the indexed int column; a label
    /// outside the table is a loud validation error (never a silent 0-match).
    Values(&'a std::collections::HashMap<String, i64>),
    /// Class-scoped enum whose integer meaning depends on another column
    /// (OCSF `activity_id`: 1=Logon on class 3002 but 1=Create on 1001), so no
    /// fixed table exists. The label lives in the named SIBLING string column
    /// (manifest `enum_label_column`, e.g. `activity`); a string verb is
    /// compared case-insensitively against that column instead.
    LabelColumn(&'a str),
}

/// Static description of a single queryable field in a schema's universe.
///
/// Borrowed string slices (`&'static str`) because both `UdmProfile` and the
/// future build-time-generated `OcsfProfile` source their field universe from
/// compile-time data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FieldDef {
    /// Canonical field name as typed in nPL (e.g. `src_ip`).
    pub name: &'static str,
    /// Value type, for query-optimization decisions.
    pub field_type: FieldType,
    /// Coarse category for grouping/UX.
    pub category: FieldCategory,
    /// Entity type, if the field denotes a security entity.
    pub entity_type: Option<EntityType>,
}
