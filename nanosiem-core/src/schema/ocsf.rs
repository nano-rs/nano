// SPDX-License-Identifier: AGPL-3.0-or-later

//! [`OcsfProfile`] — the [`SchemaProfile`] implementation for the canonical OCSF
//! 1.8.0 storage table (`nanosiem.ocsf_logs`), OCSF Phase 4 (NAN-1241).
//!
//! Unlike [`UdmProfile`](super::udm::UdmProfile) — which references the build-time
//! `UdmField` enum and the `clickhouse_sql_gen` const arrays — `OcsfProfile` is
//! **data-driven**: it parses the promotion manifest
//! `docs/ocsf/1.8.0/udm_ocsf_mapping.json` (the same artifact gated against the
//! DDL by `tests/ocsf_manifest_ddl_consistency.rs`) once into a process-wide
//! [`OnceLock`] registry. No `build.rs` / generated enum is needed because the
//! manifest is *data*, not a type. See `OCSF_SCHEMA_SUPPORT_SCOPING.md` §2.2–2.4.
//!
//! Resolution contract (scoping §2.4 / Phase 4):
//! - A **promoted** dotted OCSF path (a manifest `ch_column_name`, e.g.
//!   `src_endpoint.ip`, `actor.process.cmd_line`, `class_uid`) resolves to a
//!   direct [`FieldResolution::ExplicitColumn`] — the SQL generator backtick/
//!   quote-escapes the dotted name via `escape_identifier`.
//! - Any **unpromoted** tail path (e.g. `actor.process.parent_process.name`)
//!   resolves to [`FieldResolution::JsonPath`] against the `event` JSON column —
//!   the OCSF analog of UDM's `ext`. The generator emits
//!   `JSONExtract<T>(event, 'p1', 'p2', …)`.
//!
//! Array `[]` paths never arrive from the nPL tokenizer (it only emits dotted
//! identifiers), so `resolve()` does not synthesize `ArrayElement`; array-derived
//! values are reached through their promoted dotted column (`file.hashes.sha256`)
//! instead.

use std::borrow::Cow;
use std::collections::HashSet;
use std::sync::OnceLock;

use serde::Deserialize;

use super::profile::SchemaProfile;
use super::types::{
    EnrichmentKind, EnrichmentMode, EntityRole, EntityType, FieldCategory, FieldDef,
    FieldResolution, FieldType, SchemaId,
};

/// Fully-qualified canonical OCSF table (`clickhouse/ocsf/init.sql`).
const OCSF_TABLE_NAME: &str = "nanosiem.ocsf_logs";

/// The sort-key timestamp column. OCSF `time` (epoch ms) DEFAULT-derives into
/// this `DateTime64` column at ingest (see the DDL header "WHY timestamp IS NOT
/// MATERIALIZED"); queries treat it exactly like UDM's `timestamp`.
const OCSF_TIMESTAMP_EXPR: &str = "timestamp";

/// The JSON column holding the full standard OCSF record. The unpromoted tail
/// resolves to `JSONExtract*(event, …)` against this column.
const OCSF_EVENT_COLUMN: &str = "event";

/// The operational provenance / routing key (Security Lake "custom source"
/// pattern). NOT an OCSF `event` field and NOT manifest-promoted: it is a plain
/// ingest-written column written from the `X-Source-Type` header, lowercased at
/// ingest, sitting next to `timestamp`/`_inserted_at`. It mirrors UDM
/// `source_type` byte-for-byte so the SQL generator's PREWHERE + lowercase
/// fast-path engages identically (NAN-1241). Special-cased exactly like the
/// `timestamp`/`_inserted_at` bookkeeping columns — see [`OcsfProfile::resolve`].
const OCSF_SOURCE_TYPE_COLUMN: &str = "source_type";

/// The vendored promotion manifest — the single source of truth for the OCSF
/// field universe (and the DDL's mechanical basis).
const MANIFEST: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/docs/ocsf/1.8.0/udm_ocsf_mapping.json"
));

/// One manifest row, deserialized. Fields we don't consume are simply omitted —
/// `serde` ignores unknown keys by default.
#[derive(Debug, Clone, Deserialize)]
struct ManifestEntry {
    /// The UDM field this OCSF column corresponds to (manifest `udm_field`). Lets
    /// UDM-semantic raw-SQL builders (asset dossier, lateral, signal fetch) map a
    /// UDM field name → the OCSF column via [`OcsfProfile::udm_column_sql`].
    #[serde(default)]
    udm_field: Option<String>,
    ch_column_name: String,
    ch_type: String,
    #[serde(default)]
    prewhere: bool,
    #[serde(default)]
    is_search_col: bool,
    #[serde(default)]
    entity_type: Option<String>,
    #[serde(default)]
    category: Option<String>,
}

/// Default table-view summary fields for OCSF (the dotted analog of UDM's
/// `src_host, src_ip, …` projection).
const OCSF_DEFAULT_TABLE_FIELDS: &[&str] = &[
    "timestamp",
    "class_uid",
    "src_endpoint.ip",
    "dst_endpoint.ip",
    "user.name",
    "message",
];

/// Fields pinned to the top of the FieldsPanel.
const OCSF_PRIORITY_FIELDS: &[&str] = &[
    "timestamp",
    "class_uid",
    "type_uid",
    "severity_id",
    "src_endpoint.ip",
    "dst_endpoint.ip",
    "user.name",
    "process.name",
];

/// Detection entity-extraction priority order (semantic role → promoted OCSF
/// column). Consumed in Phase 5; the class-dependent `user` COALESCE
/// (`user.name` vs `actor.user.name`) is deferred (see module note + §3 row 5).
const OCSF_ENTITY_EXTRACTION_ORDER: &[(EntityRole, &str)] = &[
    (EntityRole::SrcIp, "src_endpoint.ip"),
    (EntityRole::DestIp, "dst_endpoint.ip"),
    (EntityRole::User, "user.name"),
    (EntityRole::SrcUser, "actor.user.name"),
    (EntityRole::SrcHost, "src_endpoint.hostname"),
    (EntityRole::DestHost, "dst_endpoint.hostname"),
    // `device.hostname` is the endpoint the event occurred on — the only entity
    // column on host-grouped sysmon findings (`… | stats … by device.hostname`).
    // Without it, risk auto-detect fell through to "unknown" for persistence /
    // lsass / certutil rules (NAN-1302). Placed after the src/dst hostnames (and
    // below IPs/users) so it only attributes findings that carry no
    // higher-priority entity — existing attributions are unchanged. Mirrors the
    // device.hostname additions already made for case grouping (NAN-1295/96),
    // matches entity (NAN-1287), and shadow investigation (NAN-1291).
    (EntityRole::SrcHost, "device.hostname"),
    (EntityRole::FileHash, "file.hashes.sha256"),
    (EntityRole::ProcessHash, "process.file.hashes.sha256"),
    (EntityRole::Domain, "http_request.url.hostname"),
];

/// Promoted columns whose MATERIALIZED expression in `clickhouse/ocsf/init.sql`
/// is wrapped in `lower(...)` at ingest — IPs, MACs, hostnames, users, domain,
/// hashes, email addresses. For these the SQL generator's
/// `is_lowercased_at_ingest` fast-path skips the redundant `lower()` wrapper so
/// the bloom/set index applies directly (matches the UDM
/// `LOWERCASE_NORMALIZED_FIELDS` semantics). Kept as an explicit list because the
/// manifest does not carry a lowercased flag; this is the exact set the DDL
/// lower()s (gated by the materialization integration test on representative
/// fields).
const OCSF_LOWERCASED_AT_INGEST: &[&str] = &[
    "src_endpoint.ip",
    "dst_endpoint.ip",
    "src_endpoint.mac",
    "dst_endpoint.mac",
    "src_endpoint.hostname",
    "device.hostname",
    "dst_endpoint.hostname",
    "user.name",
    "actor.user.name",
    "user.domain",
    "file.hashes.sha256",
    "process.file.hashes.sha256",
    "actor.process.file.hashes.sha256",
    "email.from",
    "email.to",
];

/// Process-wide parsed registry. Built once from [`MANIFEST`].
struct OcsfRegistry {
    /// Every queryable promoted field, in manifest order, deduplicated by name
    /// (`activity_id` appears twice in the manifest — taxonomy + file_action).
    fields: Vec<FieldDef>,
    /// Promoted-column membership for O(1) `resolve()` / `is_known_field()`.
    promoted: HashSet<String>,
    /// PREWHERE-eligible promoted columns (manifest `prewhere == true`).
    prewhere: Vec<String>,
    /// All promoted columns are MATERIALIZED (except the `time_dt` ALIAS) and so
    /// must be re-added in multi-stage CTE SELECTs, same as UDM's
    /// `MATERIALIZED_COLUMNS`.
    materialized: Vec<String>,
    /// `<col>` for every manifest entry with `is_search_col == true` (the
    /// `<col>.search` companion realized in the DDL). Retained for the field
    /// universe / future `_search` routing and asserted by the unit tests.
    #[cfg_attr(not(test), allow(dead_code))]
    search_stems: HashSet<String>,
    lowercased: HashSet<String>,
    /// UDM field name → OCSF promoted `ch_column_name` (from manifest `udm_field`).
    /// First mapping wins. Powers [`OcsfProfile::udm_column_sql`] so UDM-semantic
    /// raw-SQL builders resolve to the right OCSF column (NAN-1241).
    udm_to_column: std::collections::HashMap<String, String>,
}

fn registry() -> &'static OcsfRegistry {
    static REG: OnceLock<OcsfRegistry> = OnceLock::new();
    REG.get_or_init(|| {
        let entries: Vec<ManifestEntry> =
            serde_json::from_str(MANIFEST).expect("udm_ocsf_mapping.json must be valid JSON");

        let mut promoted = HashSet::new();
        let mut prewhere = Vec::new();
        let mut materialized = Vec::new();
        let mut search_stems = HashSet::new();
        let mut fields: Vec<FieldDef> = Vec::new();
        let mut seen: HashSet<String> = HashSet::new();
        let mut udm_to_column: std::collections::HashMap<String, String> =
            std::collections::HashMap::new();

        for e in &entries {
            let name = leak_str(&e.ch_column_name);
            // UDM-semantic → OCSF-column index (first mapping wins; the manifest
            // occasionally maps two UDM fields to one column, e.g. file_action).
            if let Some(udm) = &e.udm_field {
                udm_to_column
                    .entry(udm.clone())
                    .or_insert_with(|| e.ch_column_name.clone());
            }
            if promoted.insert(e.ch_column_name.clone()) {
                // First time we see this column name: record universe metadata.
                materialized.push(e.ch_column_name.clone());
            }
            if e.prewhere && prewhere.iter().all(|p: &String| p != &e.ch_column_name) {
                prewhere.push(e.ch_column_name.clone());
            }
            if e.is_search_col {
                search_stems.insert(e.ch_column_name.clone());
            }
            if seen.insert(e.ch_column_name.clone()) {
                fields.push(FieldDef {
                    name,
                    field_type: map_ch_type(&e.ch_type),
                    category: map_category(e.category.as_deref()),
                    entity_type: map_entity_type(e.entity_type.as_deref()),
                });
            }
        }

        // `time_dt` is an ALIAS column in the DDL (not MATERIALIZED) — keep it in
        // the field universe / promoted set but drop it from the re-add list so a
        // CTE SELECT does not try to project an alias.
        materialized.retain(|c| c != "time_dt");

        let lowercased = OCSF_LOWERCASED_AT_INGEST
            .iter()
            .map(|s| s.to_string())
            .collect();

        OcsfRegistry {
            fields,
            promoted,
            prewhere,
            materialized,
            search_stems,
            lowercased,
            udm_to_column,
        }
    })
}

/// NAN-1276: UDM concepts whose OCSF home is class-dependent. Returns
/// `(primary_col, fallback_col, is_numeric)`: the primary is preferred when
/// non-empty, else the fallback. Process Activity 1007 puts the subject in the
/// top-level `process.*`; Module/Network/File/DNS/Registry put the acting
/// process in `actor.process.*`. Authentication's subject is `user.*`, the
/// initiator `actor.user.*`. HTTP's URL is `http_request.url.*`, Network's is
/// top-level `url.*`. Consumed only by `udm_column_sql` (raw-SQL string builders);
/// the interactive-search WHERE path resolves OCSF field names directly.
fn class_split_udm_field(udm_field: &str) -> Option<(&'static str, &'static str, bool)> {
    let m = match udm_field {
        "process_name" => ("process.name", "actor.process.name", false),
        "process_path" => ("process.file.path", "actor.process.file.path", false),
        "command_line" => ("process.cmd_line", "actor.process.cmd_line", false),
        "process_id" => ("process.pid", "actor.process.pid", true),
        "process_guid" => ("process.uid", "actor.process.uid", false),
        "process_hash" => (
            "process.file.hashes.sha256",
            "actor.process.file.hashes.sha256",
            false,
        ),
        "user" => ("user.name", "actor.user.name", false),
        "url_domain" => ("http_request.url.hostname", "url.hostname", false),
        "url" => ("http_request.url.url_string", "url.url_string", false),
        // NAN-1319: "the source host" is class-split too. Network events carry it
        // in `src_endpoint.hostname`; endpoint/sysmon events (Process/File/Registry
        // activity) have no src/dst sidedness and put the host they occurred on in
        // `device.hostname`. The manifest maps `src_host` → `src_endpoint.hostname`
        // alone, so value/group projections (`stats count by src_host`, prevalence
        // artifacts, asset dossier) saw only network hosts and dropped all endpoint
        // activity — on local OCSF data 119K rows via src_endpoint vs 832K via the
        // union (712K device-only rows). Prefer the explicit source endpoint, fall
        // back to the observing device. Mirrors the entity-extraction priority
        // (`src_endpoint.hostname` before `device.hostname`, line ~121) and makes the
        // per-surface device.hostname patches (NAN-1295/1302/1318) redundant safety
        // nets. NOTE: this is the value/group seam only — the asset match-all clause
        // (`build_log_identity_clause_for`) still unions all three host columns since
        // a host can appear as src, dst, OR device on different events. `dest_host`
        // is intentionally NOT split: `device.hostname` is the local endpoint (src
        // side), never the remote peer.
        "src_host" => ("src_endpoint.hostname", "device.hostname", false),
        _ => return None,
    };
    Some(m)
}

/// Intern a manifest column name into a `&'static str` so it can live in a
/// [`FieldDef`] (whose `name` is `&'static str`, shared with the build-time UDM
/// profile). The leak is bounded — the manifest has 82 distinct columns, parsed
/// exactly once at process start.
fn leak_str(s: &str) -> &'static str {
    Box::leak(s.to_string().into_boxed_str())
}

/// Map a manifest ClickHouse type to the schema-agnostic [`FieldType`]. Collapses
/// `LowCardinality(...)` / `DateTime64(...)` like the manifest⟷DDL gate does.
fn map_ch_type(ch_type: &str) -> FieldType {
    let base = {
        let t = ch_type.trim();
        let t = t
            .strip_prefix("LowCardinality(")
            .and_then(|i| i.strip_suffix(')'))
            .unwrap_or(t);
        t.split('(').next().unwrap_or(t).trim()
    };
    match base {
        "UInt8" | "UInt16" | "UInt32" | "Int32" => FieldType::Integer,
        "UInt64" | "Int64" => FieldType::Long,
        "Float32" | "Float64" => FieldType::Float,
        "Bool" | "Boolean" => FieldType::Boolean,
        "DateTime" | "DateTime64" => FieldType::Timestamp,
        // OCSF IPs/MACs are stored as String (handles v4+v6 uniformly, per DDL).
        _ => FieldType::String,
    }
}

/// Map the manifest `category` string onto the schema-agnostic [`FieldCategory`].
fn map_category(cat: Option<&str>) -> FieldCategory {
    match cat {
        Some("Network") => FieldCategory::Network,
        Some("Identity") => FieldCategory::Authentication,
        Some("Process") => FieldCategory::Endpoint,
        Some("File") => FieldCategory::Endpoint,
        Some("Authentication") => FieldCategory::Authentication,
        Some("Web") => FieldCategory::Web,
        Some("DNS") => FieldCategory::Dns,
        Some("Email") => FieldCategory::Email,
        Some("Cloud") => FieldCategory::Cloud,
        Some("Finding") => FieldCategory::Vulnerability,
        Some("Enrichment") => FieldCategory::Enrichment,
        // OCSF `metadata.*` provenance (product/log/uid/version) — source-identity
        // fields; the System bucket is "System/metadata fields" (NAN-1241).
        Some("Taxonomy") | Some("Core") | Some("Metadata") => FieldCategory::System,
        _ => FieldCategory::Custom,
    }
}

/// Map the manifest `entity_type` string onto the schema-agnostic [`EntityType`].
fn map_entity_type(ent: Option<&str>) -> Option<EntityType> {
    match ent {
        Some("ip") => Some(EntityType::Ip),
        Some("host") => Some(EntityType::Host),
        Some("user") => Some(EntityType::User),
        Some("hash") => Some(EntityType::Hash),
        Some("domain") => Some(EntityType::Domain),
        Some("url") => Some(EntityType::Url),
        Some("process") => Some(EntityType::Process),
        Some("file") => Some(EntityType::File),
        _ => None,
    }
}

/// The OCSF 1.8.0 schema profile (NAN-1241 / Phase 4).
///
/// Cheap to construct; all parsed manifest state lives in the process-wide
/// [`registry`] `OnceLock`. The only per-instance state is the enrichment mode.
#[derive(Debug, Clone, Copy)]
pub struct OcsfProfile {
    enrichment_mode: EnrichmentMode,
}

impl Default for OcsfProfile {
    fn default() -> Self {
        Self::new()
    }
}

impl OcsfProfile {
    /// Construct the OCSF profile with the default enrichment mode ([`Read`]).
    ///
    /// Enrichment lives in OCSF-native fields (`*.location.*`,
    /// `*.autonomous_system.*`, `cloud.*`, `enrichments[]`). Dual-mode selection
    /// (nano-owned ingestion *computes* it vs the client ships it pre-enriched) is
    /// a Phase-6 / deployment concern; the query layer only ever *reads* these
    /// promoted columns, so `Read` is the correct default here.
    ///
    /// [`Read`]: EnrichmentMode::Read
    pub fn new() -> Self {
        Self {
            enrichment_mode: EnrichmentMode::Read,
        }
    }

    /// Construct the OCSF profile with an explicit enrichment mode. (Phase-6 knob;
    /// see [`new`](OcsfProfile::new) for why `Read` is the default.)
    pub fn with_enrichment_mode(mode: EnrichmentMode) -> Self {
        Self {
            enrichment_mode: mode,
        }
    }
}

impl SchemaProfile for OcsfProfile {
    fn id(&self) -> SchemaId {
        SchemaId::Ocsf
    }

    fn fields(&self) -> &[FieldDef] {
        &registry().fields
    }

    fn resolve(&self, npl_field: &str) -> FieldResolution {
        // The physical sort column `timestamp` (and its bookkeeping sibling
        // `_inserted_at`) are real, non-promoted columns of the OCSF table. They
        // MUST resolve to a direct column, not a JsonPath: the query layer injects
        // `timestamp` as a required field, and JsonPath'ing it would emit
        // `JSONExtractString(event,'timestamp') AS timestamp` — an alias that
        // SHADOWS the real sort column and silently breaks the time-range
        // PREWHERE (CH alias-shadows-column, NAN-1034). `event.time` is the OCSF
        // time source; `timestamp` is the materialized sort column it derives.
        if matches!(npl_field, "timestamp" | "_inserted_at") {
            return FieldResolution::ExplicitColumn(npl_field.to_string());
        }
        // `time_dt` is the OCSF logical time field, exposed in the DDL only as an
        // ALIAS of the physical `timestamp` sort column. A DDL alias resolves at
        // the base table but NOT in derived `| where`/`| table` stages (CH:
        // "Unknown identifier time_dt in scope stage_2"). Resolve it to the real
        // `timestamp` column so it works in every stage (NAN-1294).
        if npl_field == "time_dt" {
            return FieldResolution::ExplicitColumn("timestamp".to_string());
        }
        // `id` is the server-owned physical row key (UUIDv7 DEFAULT, NAN-1241) —
        // a real top-level column next to the bookkeeping clocks, NOT part of the
        // OCSF `event`. It MUST resolve to the direct column so the slim
        // table_view projects a real uuid (not `JSONExtract(event,'id') -> ''`)
        // and fetch-by-id (row expand / event inspector) can refetch the row.
        if npl_field == "id" {
            return FieldResolution::ExplicitColumn("id".to_string());
        }
        // `source_type` is the operational provenance / routing key — a plain
        // ingest-written column next to `timestamp`/`_inserted_at`, NOT part of
        // the OCSF `event`. Like the bookkeeping columns it MUST resolve to a
        // direct column (never JsonPath into `event`, which would emit
        // `JSONExtractString(event,'source_type')` against a key that does not
        // exist there and silently return ''). This is the high-frequency
        // first-filter; resolving it to the real LowCardinality column is what
        // lets the PREWHERE / set-index fast-path engage like UDM (NAN-1241).
        if npl_field == OCSF_SOURCE_TYPE_COLUMN {
            return FieldResolution::ExplicitColumn(OCSF_SOURCE_TYPE_COLUMN.to_string());
        }
        // Promoted dotted OCSF path → direct (possibly dotted) column. The SQL
        // generator's `escape_identifier` quotes the dotted name. Everything else
        // is the unpromoted `event` tail → N-level JSONExtract.
        if registry().promoted.contains(npl_field) {
            return FieldResolution::ExplicitColumn(npl_field.to_string());
        }
        // UDM-semantic alias (NAN-1248): an nPL token written in UDM terms
        // (`src_ip`, `user`, `dest_ip`, `file_hash`, …) resolves to its promoted
        // OCSF column via the manifest `udm_field` correspondence — the SAME map
        // `udm_column_sql` uses, so the general query path (search / where / stats /
        // table / sort) accepts UDM-named queries the way the hand-threaded
        // cloud / asset / lateral surfaces already do. Without this a UDM token
        // fell through to `JSONExtract(event,'src_ip')` — a key OCSF does not carry
        // — returning silently empty (or a bare-column 500 in a stats stage).
        // Native OCSF names still win above (promoted check); this only catches the
        // UDM aliases. The UDM profile is unaffected (this is OcsfProfile::resolve).
        if let Some(col) = registry().udm_to_column.get(npl_field) {
            return FieldResolution::ExplicitColumn(col.clone());
        }
        // Everything else is the unpromoted `event` tail → N-level JSONExtract.
        FieldResolution::JsonPath {
            col: OCSF_EVENT_COLUMN.to_string(),
            path: npl_field.split('.').map(String::from).collect(),
        }
    }

    fn canonicalize<'a>(&self, npl_field: &'a str) -> Cow<'a, str> {
        // Pass-through: dotted OCSF paths are already canonical and MUST NOT be
        // mangled by UDM-style snake_case aliasing (scoping §Phase 4 ⚠️). TODO
        // (deferred): add OCSF-flavored aliases (e.g. UDM `src_ip` →
        // `src_endpoint.ip`, `user` → class-aware COALESCE) once the alias surface
        // is designed — do NOT invent them here.
        Cow::Borrowed(npl_field)
    }

    fn is_known_field(&self, name: &str) -> bool {
        name == OCSF_SOURCE_TYPE_COLUMN || registry().promoted.contains(name)
    }

    fn field_type(&self, field: &str) -> Option<FieldType> {
        // The operational `source_type` column is a String (LowCardinality).
        if field == OCSF_SOURCE_TYPE_COLUMN {
            return Some(FieldType::String);
        }
        registry()
            .fields
            .iter()
            .find(|f| f.name == field)
            .map(|f| f.field_type)
    }

    fn is_lowercased_at_ingest(&self, field: &str) -> bool {
        // `source_type` is lowercased by ingestion (downcase of X-Source-Type),
        // mirroring UDM — so the generator skips the redundant lower() wrapper and
        // the set index applies directly on equality.
        field == OCSF_SOURCE_TYPE_COLUMN || registry().lowercased.contains(field)
    }

    fn is_numeric_field(&self, field: &str) -> bool {
        matches!(
            self.field_type(field),
            Some(FieldType::Integer | FieldType::Long | FieldType::Float)
        )
    }

    fn is_uuid_field(&self, field: &str) -> bool {
        // The server-owned physical row key `id` is a genuine CH `UUID` column
        // (NAN-1241), so equality compares as a UUID — never toString-wrapped.
        // Everything else: OCSF identifiers (uid/message_uid/session.uid) are
        // opaque String_t, not CH `UUID` columns — they compare as plain strings.
        field == "id"
    }

    fn prewhere_fields(&self) -> &[&str] {
        prewhere_fields_slice()
    }

    fn materialized_columns(&self) -> &[&str] {
        materialized_columns_slice()
    }

    fn category(&self, field: &str) -> FieldCategory {
        // Operational provenance key → System/Metadata bucket (source identity).
        if field == OCSF_SOURCE_TYPE_COLUMN {
            return FieldCategory::System;
        }
        registry()
            .fields
            .iter()
            .find(|f| f.name == field)
            .map(|f| f.category)
            .unwrap_or(FieldCategory::Custom)
    }

    fn entity_type(&self, field: &str) -> Option<EntityType> {
        registry()
            .fields
            .iter()
            .find(|f| f.name == field)
            .and_then(|f| f.entity_type)
    }

    fn default_table_fields(&self) -> &[&str] {
        OCSF_DEFAULT_TABLE_FIELDS
    }

    fn priority_fields(&self) -> &[&str] {
        OCSF_PRIORITY_FIELDS
    }

    fn entity_extraction_order(&self) -> &[(EntityRole, &str)] {
        OCSF_ENTITY_EXTRACTION_ORDER
    }

    fn risk_entity_default(&self) -> Option<&str> {
        // OCSF has no `risk_entity` column; the default initiator is the source IP.
        Some("src_endpoint.ip")
    }

    fn enrichment_mode(&self) -> EnrichmentMode {
        self.enrichment_mode
    }

    fn udm_column_sql(&self, udm_field: &str) -> Option<String> {
        // NAN-1276: a handful of UDM process/identity/url concepts are SPLIT
        // across two OCSF columns by event class — the "primary/acting" object
        // sits in the top-level `process`/`user`/`url` on some classes and in
        // `actor.process`/`actor.user`/`http_request.url` on others. A single
        // manifest column would only see one class group. Resolve these as a
        // class-spanning preference expression so UDM-semantic raw-SQL builders
        // (prevalence, shadow-investigation, stats/eval) see the value wherever
        // it landed. NOTE: OCSF promoted columns default to ''/0 (NOT NULL), so
        // this is `if(primary != <sentinel>, primary, fallback)`, not COALESCE
        // (which only skips NULL).
        if let Some(expr) = self.class_split_value_sql(udm_field) {
            return Some(expr);
        }
        // Map a UDM-semantic field name → its promoted OCSF column via the
        // manifest's `udm_field` correspondence, then escape it (dotted columns
        // need quoting). Returns None when OCSF has no column for that UDM concept
        // (e.g. `prevalence_*`), so raw-SQL builders skip it (NAN-1241).
        registry()
            .udm_to_column
            .get(udm_field)
            .map(|col| crate::query::escape_identifier(col))
    }

    fn class_split_value_sql(&self, udm_field: &str) -> Option<String> {
        // The single source of truth for the class-spanning `if(...)` value
        // expression (NAN-1276/1319). `udm_column_sql` consumes it for raw-SQL
        // builders; `field_to_sql_expr` consumes it for projection / GROUP BY /
        // SORT so the interactive `stats count by src_host` (and by user /
        // process_name) group on the value wherever the OCSF class put it instead
        // of the primary column alone. OCSF promoted columns default to ''/0 (NOT
        // NULL), so this is `if(primary != <sentinel>, primary, fallback)`, not
        // COALESCE (which only skips NULL).
        class_split_udm_field(udm_field).map(|(primary, fallback, numeric)| {
            let p = crate::query::escape_identifier(primary);
            let f = crate::query::escape_identifier(fallback);
            let sentinel = if numeric { "0" } else { "''" };
            format!("if({p} != {sentinel}, {p}, {f})")
        })
    }

    fn display_field_name(&self, udm_field: &str) -> Option<String> {
        // The bare native OCSF column name a result row should be keyed by (no
        // quoting). For class-split concepts there is no single native column, so
        // use the primary (acting) one for display. Mirrors `udm_column_sql`'s
        // resolution so a projection aliased to this name and a consumer reading
        // it back agree (NAN-1303 — asset stream renders native OCSF fields).
        if let Some((primary, _, _)) = class_split_udm_field(udm_field) {
            return Some(primary.to_string());
        }
        registry().udm_to_column.get(udm_field).cloned()
    }

    fn enrichment_field(&self, semantic: EnrichmentKind) -> Option<FieldResolution> {
        let col = match semantic {
            EnrichmentKind::SrcCountry => "src_endpoint.location.country",
            EnrichmentKind::SrcAsn => "src_endpoint.autonomous_system.number",
            EnrichmentKind::DestCountry => "dst_endpoint.location.country",
            EnrichmentKind::DestAsn => "dst_endpoint.autonomous_system.number",
            EnrichmentKind::IocMatch => "enrichments.ioc_src_ip_threat_type",
            // OCSF has no prevalence concept of its own (client-side; Phase 6).
            EnrichmentKind::Prevalence => return None,
        };
        Some(FieldResolution::ExplicitColumn(col.to_string()))
    }

    fn table_name(&self) -> &str {
        OCSF_TABLE_NAME
    }

    fn timestamp_expr(&self) -> &str {
        OCSF_TIMESTAMP_EXPR
    }
}

/// `&'static [&'static str]` view of the PREWHERE columns, built once. The
/// operational `source_type` provenance key leads the list (high-frequency
/// first-filter; PREWHERE-eligible exactly like UDM `source_type`).
fn prewhere_fields_slice() -> &'static [&'static str] {
    static SLICE: OnceLock<Vec<&'static str>> = OnceLock::new();
    SLICE.get_or_init(|| {
        let mut v = vec![OCSF_SOURCE_TYPE_COLUMN];
        v.extend(registry().prewhere.iter().map(|s| leak_str(s)));
        v
    })
}

/// `&'static [&'static str]` view of the MATERIALIZED columns to re-add in CTEs.
fn materialized_columns_slice() -> &'static [&'static str] {
    static SLICE: OnceLock<Vec<&'static str>> = OnceLock::new();
    SLICE.get_or_init(|| registry().materialized.iter().map(|s| leak_str(s)).collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn id_table_and_timestamp() {
        let p = OcsfProfile::new();
        assert_eq!(p.id(), SchemaId::Ocsf);
        assert_eq!(p.table_name(), "nanosiem.ocsf_logs");
        assert_eq!(p.timestamp_expr(), "timestamp");
        assert_eq!(p.enrichment_mode(), EnrichmentMode::Read);
    }

    /// NAN-1303: display_field_name gives the native OCSF column a result row
    /// should be keyed by for a UDM-semantic concept (asset stream renders native).
    #[test]
    fn display_field_name_maps_udm_concept_to_native_ocsf_column() {
        let p = OcsfProfile::new();
        assert_eq!(p.display_field_name("src_ip").as_deref(), Some("src_endpoint.ip"));
        assert_eq!(
            p.display_field_name("dest_host").as_deref(),
            Some("dst_endpoint.hostname")
        );
        // Class-split concept resolves to its primary (acting) column.
        assert!(p
            .display_field_name("user")
            .map(|n| n.contains("user.name"))
            .unwrap_or(false));
        // NAN-1319: class-split `src_host` displays under its primary native column
        // (`src_endpoint.hostname`); the device fallback still feeds the value via
        // `udm_column_sql`'s `if(...)`.
        assert_eq!(
            p.display_field_name("src_host").as_deref(),
            Some("src_endpoint.hostname")
        );
        // Concept OCSF doesn't map → None (caller falls back).
        assert_eq!(p.display_field_name("prevalence_min"), None);
    }

    /// NAN-1302: `device.hostname` must be in the entity-extraction order so
    /// host-grouped sysmon findings (the only entity column on those aggregate
    /// rows) attribute risk to the host instead of falling through to "unknown".
    #[test]
    fn entity_extraction_order_includes_device_hostname() {
        let p = OcsfProfile::new();
        assert!(
            p.entity_extraction_order()
                .iter()
                .any(|(_, f)| *f == "device.hostname"),
            "OCSF entity_extraction_order must include device.hostname (NAN-1302)"
        );
    }

    #[test]
    fn enrichment_mode_is_configurable() {
        assert_eq!(
            OcsfProfile::with_enrichment_mode(EnrichmentMode::Materialized).enrichment_mode(),
            EnrichmentMode::Materialized
        );
    }

    #[test]
    fn promoted_paths_resolve_to_explicit_columns() {
        let p = OcsfProfile::new();
        for col in [
            "src_endpoint.ip",
            "actor.process.cmd_line",
            "class_uid",
            "user.name",
            "file.hashes.sha256",
            "enrichments.ioc_dest_ip_threat_type",
        ] {
            assert_eq!(
                p.resolve(col),
                FieldResolution::ExplicitColumn(col.to_string()),
                "{col} should be a promoted ExplicitColumn",
            );
            assert!(p.is_known_field(col), "{col} should be known");
        }
        // `time_dt` is the OCSF logical-time alias of the physical `timestamp`
        // sort column (NAN-1294): it resolves to `timestamp`, not itself, so it
        // works in derived `| where`/`| table` stages. (It was previously listed
        // in the loop above expecting self-resolution, which was stale/red.)
        assert_eq!(
            p.resolve("time_dt"),
            FieldResolution::ExplicitColumn("timestamp".to_string()),
            "time_dt resolves to the physical timestamp column",
        );
    }

    #[test]
    fn tail_paths_resolve_to_jsonpath_against_event() {
        let p = OcsfProfile::new();
        // An unpromoted nested OCSF attribute lands in the `event` tail.
        assert_eq!(
            p.resolve("actor.process.parent_process.name"),
            FieldResolution::JsonPath {
                col: "event".into(),
                path: vec![
                    "actor".into(),
                    "process".into(),
                    "parent_process".into(),
                    "name".into(),
                ],
            },
        );
        assert!(!p.is_known_field("actor.process.parent_process.name"));
    }

    #[test]
    fn canonicalize_is_pass_through() {
        let p = OcsfProfile::new();
        // Dotted paths must NOT be mangled.
        assert_eq!(p.canonicalize("src_endpoint.ip").as_ref(), "src_endpoint.ip");
        assert_eq!(
            p.canonicalize("actor.process.cmd_line").as_ref(),
            "actor.process.cmd_line"
        );
    }

    #[test]
    fn field_typing_from_manifest() {
        let p = OcsfProfile::new();
        assert_eq!(p.field_type("class_uid"), Some(FieldType::Integer));
        assert_eq!(p.field_type("type_uid"), Some(FieldType::Long));
        assert_eq!(p.field_type("src_endpoint.ip"), Some(FieldType::String));
        assert!(p.is_numeric_field("class_uid"));
        assert!(p.is_numeric_field("src_endpoint.port"));
        assert!(!p.is_numeric_field("src_endpoint.ip"));
        assert!(!p.is_uuid_field("user.uid"));
    }

    #[test]
    fn lowercased_at_ingest_matches_ddl_lower_set() {
        let p = OcsfProfile::new();
        assert!(p.is_lowercased_at_ingest("src_endpoint.ip"));
        assert!(p.is_lowercased_at_ingest("user.name"));
        assert!(!p.is_lowercased_at_ingest("class_uid"));
        assert!(!p.is_lowercased_at_ingest("message"));
    }

    #[test]
    fn prewhere_fields_are_a_subset_of_promoted_and_nonempty() {
        let p = OcsfProfile::new();
        assert!(!p.prewhere_fields().is_empty());
        for f in p.prewhere_fields() {
            assert!(p.is_known_field(f), "PREWHERE field {f} must be promoted");
        }
        // Taxonomy ints + endpoint IPs are PREWHERE-eligible per the manifest.
        assert!(p.prewhere_fields().contains(&"class_uid"));
        assert!(p.prewhere_fields().contains(&"src_endpoint.ip"));
    }

    #[test]
    fn materialized_columns_exclude_alias_and_match_promoted() {
        let p = OcsfProfile::new();
        // The `time_dt` ALIAS must not be in the CTE re-add list.
        assert!(!p.materialized_columns().contains(&"time_dt"));
        for c in p.materialized_columns() {
            assert!(p.is_known_field(c));
        }
    }

    #[test]
    fn fields_universe_matches_distinct_manifest_columns() {
        let p = OcsfProfile::new();
        // 82 distinct columns in the 1.8.0 manifest (activity_id appears twice).
        assert_eq!(p.fields().len(), registry().promoted.len());
        let names: HashSet<&str> = p.fields().iter().map(|f| f.name).collect();
        for c in &registry().promoted {
            assert!(names.contains(c.as_str()), "fields() missing {c}");
        }
    }

    #[test]
    fn source_type_is_operational_explicit_column() {
        let p = OcsfProfile::new();
        // Resolves to a direct column, NOT a JsonPath into `event` (it is not an
        // OCSF event field — it is the ingest-written provenance/routing key).
        assert_eq!(
            p.resolve("source_type"),
            FieldResolution::ExplicitColumn("source_type".to_string()),
        );
        assert!(p.is_known_field("source_type"));
        // It is NOT a manifest promotion (mirrors timestamp/_inserted_at).
        assert!(!registry().promoted.contains("source_type"));
        assert!(!registry().materialized.iter().any(|c| c == "source_type"));
        // Typed String, System/Metadata category.
        assert_eq!(p.field_type("source_type"), Some(FieldType::String));
        assert!(!p.is_numeric_field("source_type"));
        assert_eq!(p.category("source_type"), FieldCategory::System);
    }

    #[test]
    fn source_type_speed_path_matches_udm() {
        let p = OcsfProfile::new();
        // PREWHERE-eligible (high-frequency first-filter) and lowercased-at-ingest
        // (generator skips lower() and the set index applies) — exactly like UDM.
        assert!(p.prewhere_fields().contains(&"source_type"));
        assert!(p.is_lowercased_at_ingest("source_type"));
    }

    #[test]
    fn udm_column_sql_maps_udm_semantics_to_ocsf_columns() {
        let p = OcsfProfile::new();
        // UDM-semantic field name → escaped OCSF promoted column (NAN-1241).
        // NAN-1319: `src_host` is class-split — network events carry the source in
        // `src_endpoint.hostname`, endpoint/sysmon events in `device.hostname`. The
        // value/group seam prefers the explicit source endpoint, falls back to the
        // observing device (712K device-only rows on local OCSF data otherwise lost).
        assert_eq!(
            p.udm_column_sql("src_host").as_deref(),
            Some("if(\"src_endpoint.hostname\" != '', \"src_endpoint.hostname\", \"device.hostname\")")
        );
        assert_eq!(p.udm_column_sql("src_ip").as_deref(), Some("\"src_endpoint.ip\""));
        // NAN-1276 class-split resolution: OCSF puts the primary process in the
        // top-level `process.*` (Process Activity 1007) but in `actor.process.*`
        // on Module/Network/File/DNS/Registry; UDM process_name/path/cmd/etc.
        // must see it wherever it landed -> `if(primary != '', primary, fallback)`.
        // (OCSF columns default to ''/0, not NULL, so this is `if`, not COALESCE.)
        assert_eq!(
            p.udm_column_sql("process_name").as_deref(),
            Some("if(\"process.name\" != '', \"process.name\", \"actor.process.name\")")
        );
        assert_eq!(
            p.udm_column_sql("command_line").as_deref(),
            Some("if(\"process.cmd_line\" != '', \"process.cmd_line\", \"actor.process.cmd_line\")")
        );
        assert_eq!(
            p.udm_column_sql("process_id").as_deref(),
            Some("if(\"process.pid\" != 0, \"process.pid\", \"actor.process.pid\")")
        );
        // `user` spans Authentication subject (`user.name`) vs initiator (`actor.user.name`).
        assert_eq!(
            p.udm_column_sql("user").as_deref(),
            Some("if(\"user.name\" != '', \"user.name\", \"actor.user.name\")")
        );
        // parent_command_line stays the parent column (not class-split).
        assert_eq!(p.udm_column_sql("parent_command_line").as_deref(), Some("\"actor.process.cmd_line\""));
        assert_eq!(p.udm_column_sql("dest_ip").as_deref(), Some("\"dst_endpoint.ip\""));
        // NAN-1241/1254: the additional UDM-semantic fields that the findings,
        // prevalence-artifact, case-extraction and GDPR fixes resolve through this
        // map. `file_hash` flattens the OCSF `file.hashes` array to a scalar
        // `file.hashes.sha256` column — locking it here guards the artifact/finding
        // hash lookups from silently regressing to the array form.
        assert_eq!(p.udm_column_sql("dest_host").as_deref(), Some("\"dst_endpoint.hostname\""));
        assert_eq!(p.udm_column_sql("file_hash").as_deref(), Some("\"file.hashes.sha256\""));
        assert_eq!(p.udm_column_sql("file_name").as_deref(), Some("\"file.name\""));
        assert_eq!(p.udm_column_sql("file_path").as_deref(), Some("\"file.path\""));
        // Prevalence is real now (NAN-1248): the prevalence_* columns are promoted
        // OCSF columns keyed on the OCSF hash/domain/ip cols, so UDM-semantic
        // prevalence field names resolve to them. The column names are non-dotted
        // so they emit bare (no backtick/quote escaping, unlike dotted columns).
        assert_eq!(
            p.udm_column_sql("prevalence_file_hash").as_deref(),
            Some("prevalence_file_hash")
        );
        assert_eq!(
            p.udm_column_sql("prevalence_process_hash").as_deref(),
            Some("prevalence_process_hash")
        );
        assert_eq!(
            p.udm_column_sql("prevalence_dest_domain").as_deref(),
            Some("prevalence_dest_domain")
        );
        assert_eq!(
            p.udm_column_sql("prevalence_dest_ip").as_deref(),
            Some("prevalence_dest_ip")
        );
        // Concepts OCSF still has no column for → None so callers skip the field.
        assert_eq!(p.udm_column_sql("parent_process_name"), None);
    }

    /// NAN-1319: the class-split value seam exposes the `if(...)` union to the
    /// `field_to_sql_expr` projection/GROUP BY path. OCSF returns it for split
    /// concepts only; UDM (and OCSF non-split / native fields) return None so the
    /// caller keeps its single-column resolution (UDM byte-identical).
    #[test]
    fn class_split_value_sql_exposes_union_for_split_concepts_only() {
        use crate::schema::{SchemaProfile, UdmProfile};
        let ocsf = OcsfProfile::new();
        assert_eq!(
            ocsf.class_split_value_sql("src_host").as_deref(),
            Some("if(\"src_endpoint.hostname\" != '', \"src_endpoint.hostname\", \"device.hostname\")")
        );
        assert_eq!(
            ocsf.class_split_value_sql("user").as_deref(),
            Some("if(\"user.name\" != '', \"user.name\", \"actor.user.name\")")
        );
        // Non-split UDM concept and native OCSF column → None (caller resolves single col).
        assert_eq!(ocsf.class_split_value_sql("src_ip"), None);
        assert_eq!(ocsf.class_split_value_sql("dest_host"), None);
        assert_eq!(ocsf.class_split_value_sql("src_endpoint.hostname"), None);
        // UDM has no class-split → always None (byte-identical projection/group).
        let udm = UdmProfile::new();
        assert_eq!(udm.class_split_value_sql("src_host"), None);
        assert_eq!(udm.class_split_value_sql("user"), None);
    }

    #[test]
    fn search_column_companion_naming() {
        // is_search_col stems get a `.search` companion; the DDL realizes them.
        assert!(registry().search_stems.contains("message"));
        assert!(registry().search_stems.contains("actor.process.cmd_line"));
    }
}
