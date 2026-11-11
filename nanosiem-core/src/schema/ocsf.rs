// SPDX-License-Identifier: AGPL-3.0-or-later

//! [`OcsfProfile`] — the [`SchemaProfile`] implementation for the canonical OCSF
//! 1.8.0 storage table (`nanosiem.ocsf_logs`), OCSF Phase 4 (NAN-1241).
//!
//! Unlike [`UdmProfile`](super::udm::UdmProfile) — which references the build-time
//! `UdmField` enum and the `clickhouse_sql_gen` const arrays — `OcsfProfile` is
//! **data-driven**: it parses the promotion manifest
//! `docs/ocsf/events/promoted.json` (NAN-4903; the same artifact gated against the
//! DDL by `tests/ocsf_manifest_ddl_consistency.rs`) once into a process-wide
//! [`OnceLock`] registry. No `build.rs` / generated enum is needed because the
//! manifest is *data*, not a type. See `OCSF_SCHEMA_SUPPORT_SCOPING.md` §2.2–2.4.
//!
//! Resolution contract (scoping §2.4 / Phase 4):
//! - A **promoted** dotted OCSF path (a manifest `ch_column_name`, e.g.
//!   `src_endpoint.ip`, `actor.process.cmd_line`, `class_uid`) resolves to a
//!   direct [`FieldResolution::ExplicitColumn`] — the SQL generator backtick/
//!   quote-escapes the dotted name via `escape_identifier`.
//! - Any other attribute of an embedded OCSF contract (NAN-4903,
//!   [`ocsf_registry`]; e.g. `actor.process.parent_process.name`) resolves to
//!   [`FieldResolution::JsonPath`] against the stored `event` JSON column, with
//!   a `[]` marker after every array segment so the generator emits
//!   `event."a"[]."b"` element access (an `Array(String)`).
//! - Everything else is vendor data: `JsonPath` against the `unmapped` column.
//!
//! See docs/design/OCSF-CLICKHOUSE.md §6.

use std::borrow::Cow;
use std::collections::HashSet;
use std::sync::OnceLock;

use serde::Deserialize;

use super::profile::SchemaProfile;
use super::types::{
    EnrichmentKind, EnrichmentMode, EntityRole, EntityType, EnumIntMapping, FieldCategory,
    FieldDef, FieldResolution, FieldType, SchemaId,
};
use super::ocsf_registry;
use crate::query::normalize_field_name;

/// Fully-qualified canonical OCSF table (`clickhouse/ocsf/init.sql`).
const OCSF_TABLE_NAME: &str = "nanosiem.ocsf_logs";

/// The sort-key timestamp column. OCSF `time` (epoch ms) DEFAULT-derives into
/// this `DateTime64` column at ingest (see the DDL header "WHY timestamp IS NOT
/// MATERIALIZED"); queries treat it exactly like UDM's `timestamp`.
const OCSF_TIMESTAMP_EXPR: &str = "timestamp";

/// The stored JSON column holding the OCSF `unmapped` spill — the producer
/// source fields that did not map to a standard OCSF attribute (the OCSF analog
/// of UDM's `ext`). The unpromoted tail resolves to native subcolumn access
/// against this column. NAN-1443 repointed this from the full `event` column
/// (now `EPHEMERAL`, never stored) to `unmapped`; paths are RELATIVE to the
/// spill sub-object (e.g. `ext.error_code` → `unmapped."error_code"`, which is
/// the same data that was `event."unmapped"."error_code"` pre-chop).
const OCSF_TAIL_COLUMN: &str = "unmapped";

/// The stored OCSF object (`JSON`, promoted scalars SKIPped). Unpromoted
/// attributes the registry knows resolve here (NAN-4903).
const OCSF_EVENT_COLUMN: &str = "event";

/// JSON path segments for an OCSF attribute, with
/// [`JSON_ARRAY_SEGMENT`](crate::query::JSON_ARRAY_SEGMENT) after every array
/// segment so the SQL generator emits `event."a"[]."b"` element access.
fn event_json_path(info: &ocsf_registry::OcsfPathInfo) -> Vec<String> {
    let mut out = Vec::with_capacity(info.segments.len() + info.array_depth());
    for (seg, is_array) in info.segments.iter().zip(&info.arrays) {
        out.push(seg.clone());
        if *is_array {
            out.push(crate::query::JSON_ARRAY_SEGMENT.to_string());
        }
    }
    out
}

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
    "/docs/ocsf/events/promoted.json"
));

/// JSON type hints of the stored `event` column (CH-2610 adoption): hot
/// unpromoted OCSF scalar strings that `scripts/gen-ocsf-ddl.py` types as
/// `Nullable(String)` / `LowCardinality(Nullable(String))` paths inside
/// `event` instead of leaving them Dynamic. Gated against the DDL and the OCSF
/// contract by `tests/ocsf_manifest_ddl_consistency.rs`.
const JSON_HINTS: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/docs/ocsf/events/json_hints.json"
));

#[derive(Deserialize)]
struct JsonHintEntry {
    ocsf_path: String,
}

static EVENT_JSON_HINTS: std::sync::LazyLock<std::collections::HashSet<String>> =
    std::sync::LazyLock::new(|| {
        serde_json::from_str::<Vec<JsonHintEntry>>(JSON_HINTS)
            .expect("docs/ocsf/events/json_hints.json must parse")
            .into_iter()
            .map(|h| h.ocsf_path)
            .collect()
    });

/// Manifest hints that are typed in the LIVE `ocsf_logs.event` column of this
/// deployment, detected at boot by [`refresh_live_event_json_hints`]. Empty
/// until then, and on a table created before the hints existed (the DDL is
/// `CREATE IF NOT EXISTS`, so existing installs keep an unhinted `event`).
static LIVE_EVENT_JSON_HINTS: std::sync::LazyLock<
    std::sync::RwLock<std::collections::HashSet<String>>,
> = std::sync::LazyLock::new(Default::default);

thread_local! {
    /// Test override for [`is_event_json_hint`] (see [`with_event_json_hints`]).
    static EVENT_JSON_HINTS_OVERRIDE: std::cell::RefCell<Option<std::collections::HashSet<String>>> =
        const { std::cell::RefCell::new(None) };
}

/// True when `path` (dotted, no `event.` prefix) is a typed String path of the
/// live `event` JSON column, so the SQL generator may read the typed subcolumn
/// alone (see `json_tail_access_sql`). Only a hint that is physically present
/// qualifies: on an unhinted table an object-valued producer value lives in the
/// `event.^path` sub-object, which only the parity form reads.
pub fn is_event_json_hint(path: &str) -> bool {
    if let Some(found) = EVENT_JSON_HINTS_OVERRIDE.with(|o| o.borrow().as_ref().map(|s| s.contains(path))) {
        return found;
    }
    LIVE_EVENT_JSON_HINTS
        .read()
        .map(|s| s.contains(path))
        .unwrap_or(false)
}

/// Manifest hints whose typed path appears in a `system.columns.type` string of
/// the `event` column, such as `JSON(action LowCardinality(Nullable(String)), …)`.
/// ClickHouse back-quotes only the names that need it (dotted paths), so both
/// spellings are accepted.
pub fn event_json_hints_in_type(column_type: &str) -> std::collections::HashSet<String> {
    const TYPES: [&str; 2] = ["Nullable(String)", "LowCardinality(Nullable(String))"];
    EVENT_JSON_HINTS
        .iter()
        .filter(|p| {
            [format!("`{p}`"), (*p).clone()].iter().any(|name| {
                TYPES.iter().any(|t| {
                    ["(", ", "].iter().any(|pre| {
                        [",", ")"].iter().any(|post| column_type.contains(&format!("{pre}{name} {t}{post}")))
                    })
                })
            })
        })
        .cloned()
        .collect()
}

/// Replace the live hint set (boot detection, or a test harness).
pub fn set_live_event_json_hints(paths: std::collections::HashSet<String>) {
    if let Ok(mut live) = LIVE_EVENT_JSON_HINTS.write() {
        *live = paths;
    }
}

/// Read the live `event` column type of `local_table` (`db.table`) once and
/// cache which manifest hints it carries. Returns how many are live. On any
/// error the cache is cleared, so the generator keeps the parity form.
pub async fn refresh_live_event_json_hints(
    client: &clickhouse::Client,
    local_table: &str,
) -> Result<usize, String> {
    let (db, table) = local_table.split_once('.').unwrap_or(("nanosiem", local_table));
    let types = client
        .query("SELECT type FROM system.columns WHERE database = ? AND table = ? AND name = 'event'")
        .bind(db)
        .bind(table)
        .fetch_all::<String>()
        .await;
    match types {
        Ok(rows) => {
            let live = rows.first().map(|t| event_json_hints_in_type(t)).unwrap_or_default();
            let n = live.len();
            set_live_event_json_hints(live);
            Ok(n)
        }
        Err(e) => {
            set_live_event_json_hints(Default::default());
            Err(e.to_string())
        }
    }
}

/// Run `f` with `paths` as the live hint set on this thread only (tests).
#[doc(hidden)]
pub fn with_event_json_hints<R>(paths: &[&str], f: impl FnOnce() -> R) -> R {
    let set = paths.iter().map(|p| (*p).to_string()).collect();
    let prev = EVENT_JSON_HINTS_OVERRIDE.with(|o| o.replace(Some(set)));
    let out = f();
    EVENT_JSON_HINTS_OVERRIDE.with(|o| *o.borrow_mut() = prev);
    out
}

/// All manifest hint paths (`json_hints.json`).
pub fn manifest_event_json_hints() -> Vec<&'static str> {
    let mut v: Vec<&'static str> = EVENT_JSON_HINTS.iter().map(String::as_str).collect();
    v.sort_unstable();
    v
}

/// One manifest row, deserialized. Fields we don't consume are simply omitted —
/// `serde` ignores unknown keys by default.
#[derive(Debug, Clone, Deserialize)]
struct ManifestEntry {
    /// The UDM field names this OCSF column answers for (manifest `udm_fields`,
    /// carried from the 1.8 correspondence table, first-wins order). Lets
    /// UDM-semantic raw-SQL builders (asset dossier, lateral, signal fetch) map a
    /// UDM field name → the OCSF column via [`OcsfProfile::udm_column_sql`].
    #[serde(default)]
    udm_fields: Vec<String>,
    ch_column_name: String,
    ch_type: String,
    /// The DDL generator wraps this column's MV expression in `lower()`
    /// (scripts/gen-ocsf-ddl.py). Drives `is_lowercased_at_ingest`.
    #[serde(default)]
    lowered_at_ingest: bool,
    #[serde(default)]
    prewhere: bool,
    #[serde(default)]
    entity_type: Option<String>,
    #[serde(default)]
    category: Option<String>,
    /// Fixed `lowercase label → integer id` table for an enum-int column whose
    /// values are class-INDEPENDENT (`status_id`, `auth_protocol_id`,
    /// `severity_id`). Drives [`EnumIntMapping::Values`] so string verbs compare
    /// against the indexed int (NAN-1382).
    #[serde(default)]
    enum_values: Option<std::collections::HashMap<String, i64>>,
    /// Sibling STRING column carrying the human label for a CLASS-SCOPED
    /// enum-int column (`activity_id` → `activity`), where no fixed table can
    /// exist. Drives [`EnumIntMapping::LabelColumn`] (NAN-1382).
    #[serde(default)]
    enum_label_column: Option<String>,
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

/// nano-derived physical columns of `ocsf_logs` that are NOT OCSF attribute
/// paths (scripts/gen-ocsf-ddl.py renders them next to the promoted columns):
/// `(column, ch_type, category, entity_type, lowered_at_ingest, udm_field,
/// select_star)`. `select_star == false` marks ALIAS columns, which `SELECT *`
/// omits and multi-stage CTEs must re-add.
const OCSF_DERIVED_COLUMNS: &[(
    &str,
    &str,
    &str,
    Option<&str>,
    bool,
    Option<&str>,
    bool,
)] = &[
    // SHA-256 picked out of `*.hashes[]` (algorithm_id = 3), lowered.
    ("file.hashes.sha256", "String", "File", Some("hash"), true, Some("file_hash"), true),
    ("process.file.hashes.sha256", "String", "Process", Some("hash"), true, Some("process_hash"), true),
    ("actor.process.file.hashes.sha256", "String", "Process", Some("hash"), true, None, true),
    // Ingest-time IOC / custom-tag enrichment (UDM parity; producer-supplied
    // `enrichments[]` entries with the same name win). NAN-4982: every slot
    // (src/dest IP, domain, hash of any algorithm, URL) from both the
    // marketplace dictionary (`ioc_*`: bundle ThreatFox / Tor) and the custom
    // one (`custom_ioc_*`: IOC lists, user IOC enrichments); the UDM column
    // name of each is its nPL alias.
    ("enrichments.ioc_src_ip_threat_type", "String", "Enrichment", None, false, Some("ioc_src_ip_threat_type"), true),
    ("enrichments.ioc_src_ip_malware", "String", "Enrichment", None, false, Some("ioc_src_ip_malware"), true),
    ("enrichments.ioc_src_ip_confidence", "UInt8", "Enrichment", None, false, Some("ioc_src_ip_confidence"), true),
    ("enrichments.ioc_dest_ip_threat_type", "String", "Enrichment", None, false, Some("ioc_dest_ip_threat_type"), true),
    ("enrichments.ioc_dest_ip_malware", "String", "Enrichment", None, false, Some("ioc_dest_ip_malware"), true),
    ("enrichments.ioc_dest_ip_confidence", "UInt8", "Enrichment", None, false, Some("ioc_dest_ip_confidence"), true),
    ("enrichments.ioc_domain_threat_type", "String", "Enrichment", None, false, Some("ioc_domain_threat_type"), true),
    ("enrichments.ioc_domain_malware", "String", "Enrichment", None, false, Some("ioc_domain_malware"), true),
    ("enrichments.ioc_domain_confidence", "UInt8", "Enrichment", None, false, Some("ioc_domain_confidence"), true),
    ("enrichments.ioc_hash_threat_type", "String", "Enrichment", None, false, Some("ioc_hash_threat_type"), true),
    ("enrichments.ioc_hash_malware", "String", "Enrichment", None, false, Some("ioc_hash_malware"), true),
    ("enrichments.ioc_hash_confidence", "UInt8", "Enrichment", None, false, Some("ioc_hash_confidence"), true),
    ("enrichments.ioc_url_threat_type", "String", "Enrichment", None, false, Some("ioc_url_threat_type"), true),
    ("enrichments.ioc_url_malware", "String", "Enrichment", None, false, Some("ioc_url_malware"), true),
    ("enrichments.ioc_url_confidence", "UInt8", "Enrichment", None, false, Some("ioc_url_confidence"), true),
    ("enrichments.ioc_confidence", "UInt8", "Enrichment", None, false, Some("ioc_confidence"), true),
    ("enrichments.ioc_tags", "String", "Enrichment", None, false, Some("ioc_tags"), true),
    ("enrichments.ioc_source", "String", "Enrichment", None, false, Some("ioc_source"), true),
    ("enrichments.custom_ioc_src_ip_threat_type", "String", "Enrichment", None, false, Some("custom_ioc_src_ip_threat_type"), true),
    ("enrichments.custom_ioc_src_ip_malware", "String", "Enrichment", None, false, Some("custom_ioc_src_ip_malware"), true),
    ("enrichments.custom_ioc_src_ip_confidence", "UInt8", "Enrichment", None, false, Some("custom_ioc_src_ip_confidence"), true),
    ("enrichments.custom_ioc_dest_ip_threat_type", "String", "Enrichment", None, false, Some("custom_ioc_dest_ip_threat_type"), true),
    ("enrichments.custom_ioc_dest_ip_malware", "String", "Enrichment", None, false, Some("custom_ioc_dest_ip_malware"), true),
    ("enrichments.custom_ioc_dest_ip_confidence", "UInt8", "Enrichment", None, false, Some("custom_ioc_dest_ip_confidence"), true),
    ("enrichments.custom_ioc_domain_threat_type", "String", "Enrichment", None, false, Some("custom_ioc_domain_threat_type"), true),
    ("enrichments.custom_ioc_domain_malware", "String", "Enrichment", None, false, Some("custom_ioc_domain_malware"), true),
    ("enrichments.custom_ioc_domain_confidence", "UInt8", "Enrichment", None, false, Some("custom_ioc_domain_confidence"), true),
    ("enrichments.custom_ioc_hash_threat_type", "String", "Enrichment", None, false, Some("custom_ioc_hash_threat_type"), true),
    ("enrichments.custom_ioc_hash_malware", "String", "Enrichment", None, false, Some("custom_ioc_hash_malware"), true),
    ("enrichments.custom_ioc_hash_confidence", "UInt8", "Enrichment", None, false, Some("custom_ioc_hash_confidence"), true),
    ("enrichments.custom_ioc_url_threat_type", "String", "Enrichment", None, false, Some("custom_ioc_url_threat_type"), true),
    ("enrichments.custom_ioc_url_malware", "String", "Enrichment", None, false, Some("custom_ioc_url_malware"), true),
    ("enrichments.custom_ioc_url_confidence", "UInt8", "Enrichment", None, false, Some("custom_ioc_url_confidence"), true),
    ("enrichments.custom_src_ip_tags", "String", "Enrichment", None, false, Some("custom_src_ip_tags"), true),
    ("enrichments.custom_dest_ip_tags", "String", "Enrichment", None, false, Some("custom_dest_ip_tags"), true),
    // MATERIALIZED prevalence (dictGet at insert), absent from `SELECT *`.
    ("prevalence_file_hash", "UInt16", "Enrichment", None, false, Some("prevalence_file_hash"), false),
    ("prevalence_process_hash", "UInt16", "Enrichment", None, false, Some("prevalence_process_hash"), false),
    ("prevalence_dest_domain", "UInt16", "Enrichment", None, false, Some("prevalence_dest_domain"), false),
    ("prevalence_dest_ip", "UInt16", "Enrichment", None, false, Some("prevalence_dest_ip"), false),
    ("prevalence_min", "UInt16", "Enrichment", None, false, Some("prevalence_min"), false),
    // ALIAS columns.
    ("activity", "LowCardinality(String)", "Taxonomy", None, false, Some("action"), false),
    ("trace_id", "String", "Core", None, true, None, false),
    ("span_id", "String", "Core", None, true, None, false),
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
    /// Columns `SELECT *` omits (ALIAS: the `*_unified` unions, `activity`,
    /// `trace_id`, `span_id`) that multi-stage CTE SELECTs must re-add, same
    /// role as UDM's `MATERIALIZED_COLUMNS`. Promoted columns are plain columns
    /// and are NOT listed: re-adding them beside `SELECT *` would
    /// duplicate-project (CH Code 352).
    materialized: Vec<String>,
    /// Columns the DDL lower()s at ingest (manifest `lowered_at_ingest` plus the
    /// derived SHA-256 / trace columns).
    lowercased: HashSet<String>,
    /// Promoted `Array(..)` columns (manifest `ch_type`), multi-valued in nPL.
    array_columns: HashSet<String>,
    /// UDM field name → OCSF promoted `ch_column_name` (from manifest `udm_field`).
    /// First mapping wins. Powers [`OcsfProfile::udm_column_sql`] so UDM-semantic
    /// raw-SQL builders resolve to the right OCSF column (NAN-1241).
    udm_to_column: std::collections::HashMap<String, String>,
    /// Enum-int column → fixed `lowercase label → id` table (manifest
    /// `enum_values`, NAN-1382). Keys are column names (`status_id`); labels are
    /// stored lowercased so lookup is case-insensitive.
    enum_values: std::collections::HashMap<String, std::collections::HashMap<String, i64>>,
    /// Class-scoped enum-int column → sibling label String column (manifest
    /// `enum_label_column`, NAN-1382), e.g. `activity_id` → `activity`.
    enum_label_columns: std::collections::HashMap<String, String>,
}

fn registry() -> &'static OcsfRegistry {
    static REG: OnceLock<OcsfRegistry> = OnceLock::new();
    REG.get_or_init(|| {
        let entries: Vec<ManifestEntry> =
            serde_json::from_str(MANIFEST).expect("udm_ocsf_mapping.json must be valid JSON");

        let mut promoted = HashSet::new();
        let mut prewhere = Vec::new();
        let mut materialized = Vec::new();
        let mut fields: Vec<FieldDef> = Vec::new();
        let mut seen: HashSet<String> = HashSet::new();
        let mut udm_to_column: std::collections::HashMap<String, String> =
            std::collections::HashMap::new();
        let mut enum_values: std::collections::HashMap<
            String,
            std::collections::HashMap<String, i64>,
        > = std::collections::HashMap::new();
        let mut enum_label_columns: std::collections::HashMap<String, String> =
            std::collections::HashMap::new();
        let mut lowercased: HashSet<String> = HashSet::new();
        let mut array_columns: HashSet<String> = HashSet::new();

        for e in &entries {
            let name = leak_str(&e.ch_column_name);
            // UDM-semantic → OCSF-column index (first mapping wins; the manifest
            // occasionally maps two UDM fields to one column, e.g. file_action).
            for udm in &e.udm_fields {
                udm_to_column
                    .entry(udm.clone())
                    .or_insert_with(|| e.ch_column_name.clone());
            }
            // NAN-4903: promoted columns are plain columns written by
            // `ocsf_logs_raw_mv` (no longer MATERIALIZED from an EPHEMERAL
            // `event`), so `SELECT *` already returns them — only ALIAS /
            // MATERIALIZED derived columns go on the CTE re-add list below.
            promoted.insert(e.ch_column_name.clone());
            if e.prewhere && prewhere.iter().all(|p: &String| p != &e.ch_column_name) {
                prewhere.push(e.ch_column_name.clone());
            }
            // Enum metadata (NAN-1382). Labels are lowercased defensively so a
            // capitalized manifest label still matches the lowercase lookup. A
            // column appearing in multiple entries (activity_id ×3) merges; the
            // metadata is identical across its rows by construction.
            if let Some(values) = &e.enum_values {
                let m = enum_values.entry(e.ch_column_name.clone()).or_default();
                for (label, id) in values {
                    m.insert(label.to_lowercase(), *id);
                }
            }
            if let Some(sibling) = &e.enum_label_column {
                enum_label_columns
                    .entry(e.ch_column_name.clone())
                    .or_insert_with(|| sibling.clone());
            }
            if e.lowered_at_ingest {
                lowercased.insert(e.ch_column_name.clone());
            }
            if e.ch_type.starts_with("Array(") {
                array_columns.insert(e.ch_column_name.clone());
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

        for (col, ch_type, cat, ent, lowered, udm, select_star) in OCSF_DERIVED_COLUMNS {
            promoted.insert((*col).to_string());
            if *lowered {
                lowercased.insert((*col).to_string());
            }
            if let Some(udm) = udm {
                udm_to_column
                    .entry((*udm).to_string())
                    .or_insert_with(|| (*col).to_string());
            }
            if !*select_star {
                materialized.push((*col).to_string());
            }
            if seen.insert((*col).to_string()) {
                fields.push(FieldDef {
                    name: col,
                    field_type: map_ch_type(ch_type),
                    category: map_category(Some(cat)),
                    entity_type: map_entity_type(*ent),
                });
            }
        }

        // NAN-1337: the `*_unified` ALIAS columns are not in `SELECT *`, so a
        // multi-stage CTE that references one in a later stage (`SELECT
        // src_host_unified … FROM stage_0`) fails with "Unknown identifier"
        // unless stage_0 projects it. Append them to the re-add list.
        for u in OCSF_UNIFIED_COLUMNS {
            materialized.push((*u).to_string());
        }

        OcsfRegistry {
            fields,
            promoted,
            prewhere,
            materialized,
            lowercased,
            array_columns,
            udm_to_column,
            enum_values,
            enum_label_columns,
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

/// NAN-1623 (D4): the enumerable key set of the class-split sites — the single
/// source of truth the drift guard derives from. Four hand-maintained sites must
/// agree per concept: [`class_split_udm_field`] (the value-pick definition),
/// [`class_split_column`] (the indexed unified column), and the
/// [`OCSF_UNIFIED_COLUMNS`] / [`OCSF_BOOKKEEPING_COLUMNS`] re-add lists. The unified
/// column is always `<field>_unified`. If a concept is added to only some sites the
/// query layer and the physical table silently disagree (a multi-stage CTE stage
/// references a `*_unified` column that the re-add list omitted → CH Code 47
/// "Unknown identifier"). `class_split_sites_stay_in_lockstep` asserts all four
/// agree, so a partial edit fails the build instead of failing at query time.
///
/// Only the lockstep test consumes this — it's the assertion's key set, not a
/// production-consumed list — so it's `#[cfg(test)]` to stay out of prod builds.
#[cfg(test)]
const CLASS_SPLIT_UDM_FIELDS: &[&str] = &[
    "process_name",
    "process_path",
    "command_line",
    "process_id",
    "process_guid",
    "process_hash",
    "user",
    "url_domain",
    "url",
    "src_host",
];

/// NAN-1337: the 10 NAN-1333 `<udm_field>_unified` columns. They are MATERIALIZED
/// real columns (so absent from `SELECT *`) but are NOT manifest entries, so the
/// manifest-built re-add list (`OcsfRegistry.materialized`) omits them. They MUST be
/// appended to that list so every multi-stage CTE stage projects them — otherwise a
/// query whose later stage references one (`SELECT src_host_unified … FROM stage_0`),
/// e.g. `* | stats count by src_host`, fails with CH Code 47 "Unknown identifier".
/// Kept in lockstep with [`class_split_column`] (asserted in tests).
const OCSF_UNIFIED_COLUMNS: &[&str] = &[
    "process_name_unified",
    "process_path_unified",
    "command_line_unified",
    "process_id_unified",
    "process_guid_unified",
    "process_hash_unified",
    "user_unified",
    "url_domain_unified",
    "url_unified",
    "src_host_unified",
];

/// Columns the OCSF DDL owns for bookkeeping/ingest that legitimately have no
/// manifest promotion entry. `source_type` is the operational provenance/routing
/// key — ingest-written from the `X-Source-Type` header (not derived from the
/// OCSF `event`), so like `event`/`timestamp`/`_inserted_at` it must NOT be
/// required as a manifest promotion (NAN-1241).
///
/// NAN-1333: the `*_unified` columns are DERIVED — a class-spanning
/// `if(primary != s, primary, fallback)` union of two ALREADY-promoted manifest
/// columns, not a new OCSF source field. They exist only to give the codegen a
/// single indexed column to filter/group on. Each one's two source columns ARE in
/// the manifest; the union itself is bookkeeping, like the prevalence_* derivations.
///
/// NAN-1385: `event_bytes` is the stored-payload size feeding the
/// ocsf_logs_per_source_5m_mv telemetry rollup — pure operational bookkeeping,
/// never a queryable OCSF field.
///
/// Consumed by the `ocsf_manifest_ddl_consistency` DDL↔manifest gate AND by the
/// field-stats inventory regression tests (NAN-1397): a bookkeeping column that
/// is MATERIALIZED and not in [`SchemaProfile::materialized_columns`]'s re-add
/// list (i.e. invisible inside the companion's CTE wrap) must be excluded from
/// the analyst-facing field-stats inventory, or every wrapped OCSF search fails
/// with Code 47 and degrades to client-side stats. Register any future
/// metering/bookkeeping column here.
pub const OCSF_BOOKKEEPING_COLUMNS: &[&str] = &[
    "event",
    // NAN-1443: the stored OCSF spill column. Reached via the `ext.*` /
    // `unmapped.*` tail namespaces (and `spath input=ext`), never surfaced as a
    // bare analyst field — same treatment the full `event` column had.
    "unmapped",
    "timestamp",
    "_inserted_at",
    "source_type",
    "process_name_unified",
    "process_path_unified",
    "command_line_unified",
    "process_id_unified",
    "process_guid_unified",
    "process_hash_unified",
    "user_unified",
    "url_domain_unified",
    "url_unified",
    "src_host_unified",
    "event_bytes",
];

/// NAN-1333: the INDEXED unified physical column that materializes the exact
/// `class_split_value_sql` union for a class-split UDM concept. The inline
/// `if(primary != <sentinel>, primary, fallback)` value-pick is opaque to every
/// skip index (a function of two columns), so a filter on it FULL-SCANS even
/// though both source columns are individually indexed. `clickhouse/ocsf/init.sql`
/// materializes the same union into one plain column per concept and attaches a
/// words text index; routing WHERE / GROUP BY / raw-SQL to this column makes the
/// index actually prune (prototype: src_host 640/640 → 294/640 granules, identical
/// match counts). The mapping is 1:1 with [`class_split_udm_field`] — keep them in
/// lockstep — and the column name is always `<udm_field>_unified`. Returns `None`
/// for every non-split concept (the caller then keeps its single-column /
/// value-pick resolution unchanged).
fn class_split_column(udm_field: &str) -> Option<&'static str> {
    let col = match udm_field {
        "process_name" => "process_name_unified",
        "process_path" => "process_path_unified",
        "command_line" => "command_line_unified",
        "process_id" => "process_id_unified",
        "process_guid" => "process_guid_unified",
        "process_hash" => "process_hash_unified",
        "user" => "user_unified",
        "url_domain" => "url_domain_unified",
        "url" => "url_unified",
        "src_host" => "src_host_unified",
        _ => return None,
    };
    Some(col)
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
/// nPL names owned by risk-based alerting (risk entity scoring). They resolve to
/// the `unmapped` spill the finding writer populates, ahead of the OCSF
/// registry, so a bare `risk_score` never reads a source-reported value.
const RBA_SPILL_FIELDS: &[&str] = &[
    "risk_score",
    "raw_risk_score",
    "risk_entity",
    "risk_level",
    "risk_factors",
];

/// NAN-5275: the nano finding envelope keys (beyond [`RBA_SPILL_FIELDS`]) that
/// the finding writer stores under `unmapped` on OCSF. They are real, queryable
/// names on `source_type=findings` rows even though no OCSF column carries them.
const OCSF_FINDING_SPILL_FIELDS: &[&str] = &[
    "signal_type",
    "rule_id",
    "rule_name",
    "rule_mode",
    "risk_entity_field",
    "risk_entity_type",
    "mitre_tactics",
    "mitre_techniques",
];

/// NAN-4918: explicit nPL names for the producer-reported OCSF risk attributes.
/// The bare `risk_score` / `risk_level` stay owned by risk-based alerting (see
/// [`RBA_SPILL_FIELDS`]); these aliases read the source's own value, exactly
/// like the `event.<name>` spelling.
const VENDOR_RISK_ALIASES: &[(&str, &str)] = &[
    ("vendor_risk_score", "risk_score"),
    ("vendor_risk_level", "risk_level"),
];

/// The OCSF attribute a vendor-risk alias names, if `name` is one.
fn vendor_risk_attribute(name: &str) -> Option<&'static str> {
    VENDOR_RISK_ALIASES
        .iter()
        .find(|(alias, _)| *alias == name)
        .map(|(_, attr)| *attr)
}

/// [`FieldType`] of an OCSF contract leaf.
fn ocsf_leaf_field_type(info: &ocsf_registry::OcsfPathInfo) -> FieldType {
    match info.leaf {
        ocsf_registry::OcsfLeafType::Integer => FieldType::Integer,
        ocsf_registry::OcsfLeafType::Long => FieldType::Long,
        ocsf_registry::OcsfLeafType::Float => FieldType::Float,
        ocsf_registry::OcsfLeafType::Boolean => FieldType::Boolean,
        _ => FieldType::String,
    }
}

fn map_ch_type(ch_type: &str) -> FieldType {
    let base = {
        let t = ch_type.trim();
        // Element type of a promoted array (`Array(UInt16)` → UInt16): nPL
        // compares multi-valued fields element-wise, so `observables.type_id`
        // must be numeric for the element-wise numeric filter to apply.
        let t = t
            .strip_prefix("Array(")
            .and_then(|i| i.strip_suffix(')'))
            .unwrap_or(t)
            .trim();
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

    /// Whether `name` — taken verbatim, with NO alias canonicalization — resolves
    /// to a real physical column of `ocsf_logs` (operational/bookkeeping column,
    /// promoted manifest column, or a UDM-correspondence column). This is the
    /// [`canonicalize`](SchemaProfile::canonicalize) gate predicate (NAN-1422):
    /// it must consult [`resolve_canonical`](Self::resolve_canonical) directly
    /// (never the canonicalizing `resolve`) or the two would recurse.
    fn resolves_to_physical_column(&self, name: &str) -> bool {
        matches!(
            self.resolve_canonical(name),
            FieldResolution::ExplicitColumn(_)
        )
    }

    /// Resolve an already-canonical field name (the historical `resolve` body).
    /// The trait's [`resolve`](SchemaProfile::resolve) canonicalizes flat
    /// operational aliases first (NAN-1422) and delegates here; internal
    /// recursions (the `ext.` / `event.` prefix remaps) stay on this method so
    /// stripped tails are never re-aliased.
    fn resolve_canonical(&self, npl_field: &str) -> FieldResolution {
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
        // NAN-4903: OCSF `time` (epoch ms in `event`) is the same instant; the
        // upstream rules project it (`| table time, …`), so it reads the sort
        // column too — a DateTime64, not the raw epoch integer.
        if npl_field == "time_dt" || npl_field == "time" {
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
        // NAN-4903: `metadata.log_source` IS the routing key. The Vector prepare
        // stage stamps it from the source type and the raw table DEFAULTs
        // `source_type` from it, so the 129 upstream rule references
        // (`metadata.log_source="windows_sysmon"`) hit the LowCardinality column
        // and its set index instead of a JSON subcolumn read.
        if npl_field == "metadata.log_source" {
            return FieldResolution::ExplicitColumn(OCSF_SOURCE_TYPE_COLUMN.to_string());
        }
        // NAN-4918: `vendor_risk_score` / `vendor_risk_level` are the explicit
        // names for the producer's OCSF risk attributes and resolve exactly like
        // `event.risk_score` / `event.risk_level` (the bare names are RBA's).
        if let Some(attr) = vendor_risk_attribute(npl_field) {
            return self.resolve_canonical(&format!("event.{attr}"));
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
        // Spill namespace (NAN-1388 G14; repointed by NAN-1443). The spill is
        // the stored `unmapped` column — the OCSF analog of UDM's `ext`. Both
        // `ext.*` (UDM muscle memory from saved searches) and `unmapped.*` (the
        // OCSF-native spelling) address it, with the path RELATIVE to the
        // sub-object: `ext.error_code` / `unmapped.error_code` →
        // `unmapped."error_code"`. That is the SAME data that resolved to
        // `event."unmapped"."error_code"` before the full `event` column was
        // dropped to `EPHEMERAL`. No manifest column or UDM alias starts with
        // `ext.`/`unmapped.`/`event.` (verified), so nothing real is shadowed;
        // bare `ext`/`event` (no dot) fall through to the spill below, keeping
        // the `spath input=ext` tail fallback (#2043) intact. UDM is unaffected
        // (this is OcsfProfile::resolve; `ext.*` is native there).
        if let Some(rest) = npl_field
            .strip_prefix("ext.")
            .or_else(|| npl_field.strip_prefix("unmapped."))
        {
            return FieldResolution::JsonPath {
                col: OCSF_TAIL_COLUMN.to_string(),
                path: rest.split('.').map(String::from).collect(),
            };
        }
        if npl_field.starts_with("event.") {
            // `event.<rest>` strips the (now-EPHEMERAL) tail-column prefix and
            // re-resolves: `event.src_endpoint.ip` lands on the promoted column,
            // `event.<unpromoted>` falls through to the spill below. Strip ALL
            // leading `event.` segments iteratively (not one per recursive call)
            // so an adversarial `event.event.…` chain cannot grow the stack.
            let mut rest = npl_field;
            while let Some(r) = rest.strip_prefix("event.") {
                rest = r;
            }
            // `event.<x>` explicitly names the OCSF attribute, so it skips the
            // name-level overrides below that would otherwise shadow it: the RBA
            // names (`event.risk_score` is the producer's own value) and UDM-era
            // aliases that collide with an OCSF name (`event.auth_type` is
            // `ssh_activity.auth_type`, not `auth_protocol_id`).
            if !registry().promoted.contains(rest) {
                if let Some(info) = ocsf_registry::known(rest) {
                    let canonical = info.segments.join(".");
                    if canonical != rest && registry().promoted.contains(&canonical) {
                        return FieldResolution::ExplicitColumn(canonical);
                    }
                    return FieldResolution::JsonPath {
                        col: OCSF_EVENT_COLUMN.to_string(),
                        path: event_json_path(&info),
                    };
                }
            }
            return self.resolve_canonical(rest);
        }
        // RBA outputs (risk entity scoring) live in the `unmapped` spill that the
        // finding writer and risk repository use. OCSF 1.9 also defines
        // `risk_score` / `risk_level` on 87 classes, but a bare name must keep
        // reading the RBA value, never a source-reported one (RBA owns these
        // names); the producer's native value stays reachable as `event.<name>`.
        if RBA_SPILL_FIELDS.contains(&npl_field) {
            return FieldResolution::JsonPath {
                col: OCSF_TAIL_COLUMN.to_string(),
                path: vec![npl_field.to_string()],
            };
        }
        // NAN-4903: any other attribute of a known OCSF version is read from the
        // stored `event` JSON (the full object minus promoted scalars), so
        // unpromoted standard fields stay queryable without a promotion. An
        // attribute renamed by a later OCSF version canonicalizes to its new
        // name first; promoted names were matched above.
        if let Some(info) = ocsf_registry::known(npl_field) {
            let canonical = info.segments.join(".");
            if canonical != npl_field && registry().promoted.contains(&canonical) {
                return FieldResolution::ExplicitColumn(canonical);
            }
            return FieldResolution::JsonPath {
                col: OCSF_EVENT_COLUMN.to_string(),
                path: event_json_path(&info),
            };
        }
        // Everything else is the unpromoted tail → the `unmapped` spill column.
        // A bare non-promoted token that was a top-level `event.<x>` field
        // pre-chop now resolves into `unmapped` and returns NULL if absent — the
        // accepted "promote-to-query" tradeoff: standard OCSF attributes we did
        // not promote AND that the producer did not place under `unmapped` are
        // no longer stored (NAN-1443).
        FieldResolution::JsonPath {
            col: OCSF_TAIL_COLUMN.to_string(),
            path: npl_field.split('.').map(String::from).collect(),
        }
    }
}

impl SchemaProfile for OcsfProfile {
    fn id(&self) -> SchemaId {
        SchemaId::Ocsf
    }

    /// OCSF's JSON tail is the stored `unmapped` spill column (UDM uses `ext`) —
    /// NAN-1343; repointed from the now-EPHEMERAL `event` column by NAN-1443.
    fn json_tail_column(&self) -> &'static str {
        OCSF_TAIL_COLUMN
    }

    /// The stored OCSF object: unpromoted attributes the registry knows resolve
    /// here (NAN-4903), so it is the source of the fields panel's Extended
    /// bucket (NAN-5265).
    fn extended_json_column(&self) -> Option<&'static str> {
        Some(OCSF_EVENT_COLUMN)
    }

    /// NAN-1828: a bare keyword must ALSO tokenize against `raw_data`, because on
    /// OCSF the raw log lands in a different column depending on the producer.
    ///
    /// Our Vector OCSF parsers put the raw log in `message` and emit no
    /// `raw_data`. A direct producer (Tenzir) puts the untouched original —
    /// syslog header and all — in `raw_data` and a human summary in `message`.
    /// Searching `message` alone therefore made a Tenzir tenant's original log
    /// invisible to the primary hunt path: NAN-1827 persisted it, but the only
    /// nPL form that reached it (`raw_data=*kw*`) emitted `iLike` (now `lower(col) LIKE`), which extracts
    /// no index tokens and degrades to a dictionary scan.
    ///
    /// OR-folding the two is cheap because the body lives in exactly ONE of them:
    /// the other column's text index prunes to (near) zero granules rather than
    /// doubling the read. `keyword_search_column()` deliberately stays `message`
    /// — it is consumed in identifier position (the `transaction` capture), where
    /// `raw_data` would be the wrong display field.
    fn keyword_search_secondary_columns(&self) -> &'static [&'static str] {
        &["raw_data"]
    }

    fn fields(&self) -> &[FieldDef] {
        &registry().fields
    }

    fn resolve(&self, npl_field: &str) -> FieldResolution {
        // Flat operational aliases canonicalize first (NAN-1422) so every
        // resolve consumer — including codegen seams that pass the RAW name,
        // like the IN-list filter — lands on the same physical column as the
        // canonical spelling. Dotted / non-aliased names borrow straight
        // through, so this is a no-op for native OCSF paths.
        self.resolve_canonical(self.canonicalize(npl_field).as_ref())
    }

    fn canonicalize<'a>(&self, npl_field: &'a str) -> Cow<'a, str> {
        // Dotted OCSF paths are already canonical and MUST NOT be mangled by
        // UDM-style snake_case aliasing (scoping §Phase 4 ⚠️) — this also keeps
        // the dotted `normalize_field_name` entries (`cloud.provider` →
        // `cloud_provider`) from rewriting a PROMOTED OCSF column backwards.
        if npl_field.contains('.') {
            return Cow::Borrowed(npl_field);
        }
        // Flat (dot-free) inputs: apply the operational aliases UDM applies via
        // `normalize_field_name` (`sourcetype` → `source_type`, `_time` →
        // `timestamp`, …), gated conservatively (NAN-1422): accept the rewrite
        // only when the normalized target is a real physical column of
        // `ocsf_logs` AND the raw spelling is not. An alias whose target has no
        // OCSF column (`hostname` → `host`) does NOT rewrite — it stays exactly
        // as unknown as before. This deliberately does NOT invent OCSF-flavored
        // aliases: UDM `src_ip` → `src_endpoint.ip` is `resolve_canonical`'s
        // manifest correspondence (NAN-1248), and the class-aware `user`
        // COALESCE surface remains deferred until designed.
        let normalized = normalize_field_name(npl_field);
        if std::ptr::eq(normalized, npl_field) {
            return Cow::Borrowed(npl_field);
        }
        if !self.resolves_to_physical_column(npl_field)
            && self.resolves_to_physical_column(normalized)
        {
            Cow::Owned(normalized.to_string())
        } else {
            Cow::Borrowed(npl_field)
        }
    }

    fn is_known_field(&self, name: &str) -> bool {
        // Alias-aware (NAN-1422): judge the canonical spelling, so the flat
        // operational aliases (`sourcetype` → `source_type`) belong to the field
        // universe. This is the gate the input-side field validator consults
        // (NAN-1380 G5) — `sourcetype` sits one edit from `source_type`, so
        // without this it was 400-rejected as a typo while codegen handled it.
        let canonical = self.canonicalize(name);
        canonical.as_ref() == OCSF_SOURCE_TYPE_COLUMN
            || vendor_risk_attribute(canonical.as_ref()).is_some()
            || registry().promoted.contains(canonical.as_ref())
            || ocsf_registry::known(canonical.as_ref()).is_some()
    }

    fn is_queryable_field(&self, name: &str) -> bool {
        // NAN-5275: the field universe plus every name `resolve_canonical`
        // gives a real meaning to, so the editor accepts what codegen reads and
        // flags what would fall through to an empty `unmapped` lookup.
        if self.is_known_field(name) {
            return true;
        }
        // Bookkeeping / time columns resolved by name.
        if matches!(name, "timestamp" | "_inserted_at" | "id" | "time" | "time_dt") {
            return true;
        }
        // RBA outputs owned by risk-based alerting, and the rest of the nano
        // finding envelope the finding writer puts in the `unmapped` spill
        // (`detection/findings.rs`), so `source_type=findings` hunts validate.
        if RBA_SPILL_FIELDS.contains(&name) || OCSF_FINDING_SPILL_FIELDS.contains(&name) {
            return true;
        }
        // Explicit spill / event namespaces: the user named the location.
        if let Some(rest) = name
            .strip_prefix("ext.")
            .or_else(|| name.strip_prefix("unmapped."))
        {
            return !rest.is_empty();
        }
        if name.starts_with("event.") {
            // Strip every leading `event.` iteratively (as `resolve_canonical`
            // does) so an `event.event.…` chain cannot grow the stack.
            let mut rest = name;
            while let Some(r) = rest.strip_prefix("event.") {
                rest = r;
            }
            return !rest.starts_with("event.") && self.is_queryable_field(rest);
        }
        // UDM-name alias layer: the manifest correspondence plus the
        // class-split surfaces (`user`, `src_host`, `process_name`, …).
        self.udm_column_sql(name).is_some()
    }

    fn field_type(&self, field: &str) -> Option<FieldType> {
        // The operational `source_type` column is a String (LowCardinality).
        if field == OCSF_SOURCE_TYPE_COLUMN {
            return Some(FieldType::String);
        }
        // NAN-1911: the RBA risk fields have no promoted OCSF column — they spill
        // into `unmapped` (the risk engine writes numeric `risk_score`/
        // `raw_risk_score` there). Without a type they extract as String, so
        // `| stats sum(risk_score)` fails ("Illegal type String for sum"). Type
        // the numeric ones as Float so `json_tail_access_sql` emits the numeric
        // subcolumn extractor. `risk_entity`/`risk_level` stay String (their
        // group-by/filter use is already correct as strings).
        if matches!(field, "risk_score" | "raw_risk_score") {
            return Some(FieldType::Float);
        }
        // NAN-4918: a vendor-risk alias (and the `event.<x>` spelling it stands
        // for) takes the OCSF contract type of the attribute it reads, so
        // `vendor_risk_score > 50` compares numbers, not strings.
        let event_attr = vendor_risk_attribute(field).or_else(|| {
            let mut rest = field.strip_prefix("event.")?;
            while let Some(r) = rest.strip_prefix("event.") {
                rest = r;
            }
            Some(rest)
        });
        if let Some(attr) = event_attr {
            if registry().promoted.contains(attr) {
                return self.field_type(attr);
            }
            if let Some(info) = ocsf_registry::known(attr) {
                return Some(ocsf_leaf_field_type(&info));
            }
        }
        registry()
            .fields
            .iter()
            .find(|f| f.name == field)
            .map(|f| f.field_type)
            .or_else(|| {
                if registry().promoted.contains(field) {
                    return None;
                }
                // A name that resolves to a DIFFERENT physical column (a UDM-era
                // alias: `auth_type` → `auth_protocol_id`) takes that column's
                // type. Without this, a UDM alias that is also an OCSF attribute
                // name (`ssh_activity.auth_type` is `string_t`) was typed from the
                // contract while it reads the Int32 column, so verb translation
                // was skipped and `lower(<int col>)` was emitted (CH Code 43).
                if let FieldResolution::ExplicitColumn(col) = self.resolve(field) {
                    if col != field {
                        return self.field_type(&col);
                    }
                }
                ocsf_registry::known(field).map(|info| ocsf_leaf_field_type(&info))
            })
    }

    fn is_array_field(&self, field: &str) -> bool {
        let canonical = self.canonicalize(field);
        let name = canonical.as_ref();
        if registry().array_columns.contains(name) {
            return true;
        }
        if registry().promoted.contains(name) || name == OCSF_SOURCE_TYPE_COLUMN {
            return false;
        }
        match self.resolve_canonical(name) {
            // NAN-5271 E: a UDM alias whose promoted target is an Array column
            // (`category` → `http_request.url.categories`, `recipient` →
            // `email.to`, `cve`, `answer`, `resource_*`) needs membership
            // semantics too. Checking only the alias NAME let `category=x`
            // compile to `lower(<Array(String)>) = 'x'` — a CH Code 43 error.
            FieldResolution::ExplicitColumn(ref c) => registry().array_columns.contains(c),
            FieldResolution::JsonPath { ref col, ref path } => {
                col == OCSF_EVENT_COLUMN
                    && path.iter().any(|p| p == crate::query::JSON_ARRAY_SEGMENT)
            }
            _ => false,
        }
    }

    fn is_lowercased_at_ingest(&self, field: &str) -> bool {
        // `source_type` is deliberately NOT in this set (NAN-1384, G18). The
        // Vector lane lowercases it (downcase of X-Source-Type), but ocsf_logs
        // also accepts DIRECT client INSERTs and a client-written DEFAULT column
        // cannot be normalized server-side — a MixedCase direct write used to
        // produce rows the `source_type = '<lowered>'` fast-path could never
        // match (silently filter-invisible). Queries now emit
        // `lower(source_type) = '...'`; on a LowCardinality column lower() is
        // evaluated per dictionary entry, so the cost is negligible. UDM keeps
        // its fast-path: `logs` ingestion is exclusively Vector-owned.
        registry().lowercased.contains(field)
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
        // NAN-1333: route class-split concepts to the INDEXED unified column
        // (which materializes the identical `if(...)` union) instead of the inline
        // value-pick, so raw-SQL builders' WHERE/GROUP BY can prune via the words
        // index. `class_split_value_sql` (the `if(...)`) remains the source-of-truth
        // value expr + the materialization definition; this just swaps the emitted
        // reference. Falls through to the inline `if(...)` only if the column lookup
        // ever diverges (it cannot — both keyed off the same field set).
        if let Some(col) = class_split_column(udm_field) {
            return Some(crate::query::escape_identifier(col));
        }
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

    fn class_split_column(&self, udm_field: &str) -> Option<String> {
        // NAN-1333: the indexed unified column that materializes the
        // `class_split_value_sql` union, so WHERE / GROUP BY / SORT / raw-SQL on a
        // split concept reference a plain indexed column (words-index prunable)
        // rather than the skip-index-opaque inline `if(...)`. `None` for non-split
        // concepts (caller keeps single-column / value-pick resolution).
        class_split_column(udm_field).map(|c| c.to_string())
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

    fn enum_int_mapping(&self, field: &str) -> Option<EnumIntMapping<'_>> {
        // Resolve the nPL token first so BOTH spellings work: the UDM-semantic
        // alias (`auth_result` → `status_id` via the manifest correspondence)
        // and the native column name (`status_id` itself). Anything that does
        // not land on a single physical column has no enum semantics.
        let col = match self.resolve(field) {
            FieldResolution::ExplicitColumn(col) => col,
            _ => return None,
        };
        let reg = registry();
        if let Some(values) = reg.enum_values.get(&col) {
            return Some(EnumIntMapping::Values(values));
        }
        reg.enum_label_columns
            .get(&col)
            .map(|sibling| EnumIntMapping::LabelColumn(sibling.as_str()))
    }

    fn concept_value_predicate(&self, field: &str, value: &str) -> Option<&'static str> {
        // NAN-5271 E: `action=blocked` → `disposition_id` / `action_id`
        // (block/allow vocabulary only; `action=Get` keeps `activity`).
        super::ocsf_predicates::npl_value_concept(field, value).map(|c| c.sql())
    }

    fn concept_value_columns(&self, field: &str, value: &str) -> &'static [&'static str] {
        super::ocsf_predicates::npl_value_concept(field, value).map_or(&[], |c| c.columns())
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
        // NAN-1383: `prevalence_min` is a real promoted column now (least() of
        // the four prevalence_* columns) — displays under its own name.
        assert_eq!(
            p.display_field_name("prevalence_min").as_deref(),
            Some("prevalence_min")
        );
        // NAN-4903: `process.parent_process.name` is promoted, so the UDM
        // concept now displays under it.
        assert_eq!(
            p.display_field_name("parent_process_name").as_deref(),
            Some("process.parent_process.name")
        );
        // Concept OCSF doesn't map → None (caller falls back).
        assert_eq!(p.display_field_name("registry_value"), None);
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
    fn tail_paths_resolve_to_jsonpath_against_unmapped() {
        let p = OcsfProfile::new();
        // NAN-4903: an unpromoted OCSF attribute reads the stored `event` JSON
        // (the full object minus promoted scalars) — no promote-to-query gap.
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
        assert!(p.is_known_field("actor.process.parent_process.name"));
        // A non-OCSF name still spills to `unmapped`.
        assert_eq!(
            p.resolve("vendor_thing.x"),
            FieldResolution::JsonPath {
                col: "unmapped".into(),
                path: vec!["vendor_thing".into(), "x".into()],
            },
        );
    }

    /// NAN-1388 (G14) / NAN-1443: UDM-muscle-memory `ext.foo` and OCSF-native
    /// `unmapped.foo` both address the stored `unmapped` spill column with a
    /// path RELATIVE to the sub-object; `event.foo` strips the (now-EPHEMERAL)
    /// tail-column prefix and resolves the rest. Each yields the SAME underlying
    /// data it did when the spill lived inside the full `event` column
    /// (`event."unmapped"."error_code"` → `unmapped."error_code"`).
    #[test]
    fn ext_and_event_prefixes_strip_and_remap() {
        let p = OcsfProfile::new();
        // ext.foo → unmapped column, relative path [foo].
        assert_eq!(
            p.resolve("ext.error_code"),
            FieldResolution::JsonPath {
                col: "unmapped".into(),
                path: vec!["error_code".into()],
            },
        );
        // unmapped.foo (OCSF-native spelling) resolves identically.
        assert_eq!(
            p.resolve("unmapped.error_code"),
            FieldResolution::JsonPath {
                col: "unmapped".into(),
                path: vec!["error_code".into()],
            },
        );
        // Nested ext path keeps the rest of the path intact.
        assert_eq!(
            p.resolve("ext.request.method"),
            FieldResolution::JsonPath {
                col: "unmapped".into(),
                path: vec!["request".into(), "method".into()],
            },
        );
        // event.<unpromoted OCSF attribute> → the stripped path in `event`.
        assert_eq!(
            p.resolve("event.actor.process.parent_process.name"),
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
        // event.<promoted> lands on the promoted column (same value, indexed).
        assert_eq!(
            p.resolve("event.src_endpoint.ip"),
            FieldResolution::ExplicitColumn("src_endpoint.ip".to_string()),
        );
        // Bare `ext` / `event` (no dot) fall through to the spill tail —
        // `spath input=ext`'s tail fallback (#2043) keys off the unresolved form.
        assert_eq!(
            p.resolve("ext"),
            FieldResolution::JsonPath {
                col: "unmapped".into(),
                path: vec!["ext".into()],
            },
        );
        // ext.unmapped.foo composes to unmapped column path [unmapped, foo] —
        // same data as the pre-chop event."unmapped"."unmapped"."foo".
        assert_eq!(
            p.resolve("ext.unmapped.foo"),
            FieldResolution::JsonPath {
                col: "unmapped".into(),
                path: vec!["unmapped".into(), "foo".into()],
            },
        );
    }

    #[test]
    fn canonicalize_is_pass_through_for_dotted_and_non_aliased() {
        let p = OcsfProfile::new();
        // Dotted paths must NOT be mangled — byte-identical pass-through
        // (Borrowed, never re-spelled). NAN-1422 scoped aliasing to dot-free
        // inputs only.
        for dotted in [
            "src_endpoint.ip",
            "actor.process.cmd_line",
            // Dotted normalize_field_name entries must not rewrite a PROMOTED
            // OCSF column backwards (`cloud.provider` → `cloud_provider`).
            "cloud.provider",
            // Unpromoted event-tail paths stay verbatim too.
            "unmapped.error_code",
        ] {
            assert!(
                matches!(p.canonicalize(dotted), Cow::Borrowed(s) if s == dotted),
                "dotted path {dotted} must pass through byte-identical"
            );
        }
        // Non-aliased flat names are untouched as well.
        for flat in ["class_uid", "message", "source_type", "timestamp", "severity"] {
            assert!(
                matches!(p.canonicalize(flat), Cow::Borrowed(s) if s == flat),
                "non-aliased flat name {flat} must pass through byte-identical"
            );
        }
    }

    #[test]
    fn canonicalize_applies_flat_operational_aliases() {
        let p = OcsfProfile::new();
        // `sourcetype` → `source_type`: the operational provenance column exists
        // on ocsf_logs, so the Splunk-muscle-memory alias must land on it
        // (NAN-1422 — previously a validator 400 under the OCSF profile).
        assert_eq!(p.canonicalize("sourcetype").as_ref(), "source_type");
        assert_eq!(
            p.resolve("sourcetype"),
            FieldResolution::ExplicitColumn("source_type".to_string())
        );
        assert!(p.is_known_field("sourcetype"));
        // `_time` → `timestamp`: the bookkeeping sort column resolves directly.
        assert_eq!(p.canonicalize("_time").as_ref(), "timestamp");
        assert_eq!(
            p.resolve("_time"),
            FieldResolution::ExplicitColumn("timestamp".to_string())
        );
        // The alias and the canonical spelling must resolve identically.
        assert_eq!(p.resolve("sourcetype"), p.resolve("source_type"));
        assert_eq!(p.resolve("_time"), p.resolve("timestamp"));
    }

    #[test]
    fn canonicalize_gate_refuses_alias_without_physical_target() {
        let p = OcsfProfile::new();
        // `hostname` normalizes to `host` under UDM, but `host` is NOT a
        // physical ocsf_logs column (not promoted, not operational, no manifest
        // udm_field correspondence) — the rewrite must be refused so the alias
        // stays exactly as unknown as before (the deferred OCSF alias design
        // owns any future mapping; do NOT invent one here).
        for (alias, target) in [
            ("hostname", "host"),
            ("destination", "dest"),
            ("event_id", "signature_id"),
        ] {
            assert!(
                !p.resolves_to_physical_column(target),
                "{target} unexpectedly became a physical column — revisit the gate"
            );
            assert!(
                matches!(p.canonicalize(alias), Cow::Borrowed(s) if s == alias),
                "alias {alias} must NOT rewrite (target {target} has no OCSF column)"
            );
            assert!(!p.is_known_field(alias));
            // Unchanged fall-through: the raw spelling still resolves to the
            // spill tail (NAN-1443: the stored `unmapped` column, was `event`).
            assert_eq!(
                p.resolve(alias),
                FieldResolution::JsonPath {
                    col: "unmapped".into(),
                    path: vec![alias.into()],
                },
            );
        }
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
        assert!(p.is_lowercased_at_ingest("src_endpoint.hostname"));
        // NAN-1698: user-name identity fields are NOT on the fast-path — they are
        // client-writable on direct OCSF INSERTs and can't be server-normalized
        // (parity with source_type / UDM NAN-1697). Queries emit lower("user.name").
        assert!(!p.is_lowercased_at_ingest("user.name"));
        assert!(!p.is_lowercased_at_ingest("actor.user.name"));
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
        // NAN-4903: promoted columns are plain (MV-written) and already in
        // `SELECT *`; re-adding any would duplicate-project (CH Code 352).
        for c in ["class_uid", "src_endpoint.ip", "user.name", "observables.value"] {
            assert!(!p.materialized_columns().contains(&c), "{c} is in SELECT *");
            assert!(p.is_known_field(c));
        }
        // ALIAS-derived columns are not in `SELECT *` and must be re-added.
        for c in ["activity", "trace_id", "span_id"] {
            assert!(p.materialized_columns().contains(&c), "{c} must be re-added");
        }
        // NAN-1337: the unified columns ARE re-added (so multi-stage CTEs project
        // them, fixing `* | stats count by src_host` → Code 47). They are derived
        // accelerators, not manifest fields, so they're exempt from is_known_field.
        for u in OCSF_UNIFIED_COLUMNS {
            assert!(
                p.materialized_columns().contains(u),
                "unified column {u} must be in the CTE re-add list (NAN-1337)",
            );
        }
        for c in p.materialized_columns() {
            if OCSF_UNIFIED_COLUMNS.contains(&c) {
                continue;
            }
            assert!(p.is_known_field(c));
        }
        // Lockstep: every class-split concept's unified column is in the const list.
        // Derived from the single CLASS_SPLIT_UDM_FIELDS source (NAN-1623, D4).
        for udm in CLASS_SPLIT_UDM_FIELDS.iter().copied() {
            let col = class_split_column(udm).expect("class-split concept");
            assert!(
                OCSF_UNIFIED_COLUMNS.contains(&col),
                "{col} (class_split_column({udm})) must be in OCSF_UNIFIED_COLUMNS",
            );
        }
        assert_eq!(OCSF_UNIFIED_COLUMNS.len(), 10);
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
        // PREWHERE-eligible (high-frequency first-filter), exactly like UDM.
        assert!(p.prewhere_fields().contains(&"source_type"));
        // NAN-1384 (G18): NOT lowercased-at-ingest under OCSF. ocsf_logs accepts
        // direct client INSERTs that may carry MixedCase source_type values; the
        // generator must emit lower(source_type) or those rows are silently
        // filter-invisible. (UDM keeps the fast-path — Vector owns its ingest.)
        assert!(!p.is_lowercased_at_ingest("source_type"));
    }

    #[test]
    fn udm_column_sql_maps_udm_semantics_to_ocsf_columns() {
        let p = OcsfProfile::new();
        // UDM-semantic field name → escaped OCSF promoted column (NAN-1241).
        // NAN-1319: `src_host` is class-split — network events carry the source in
        // `src_endpoint.hostname`, endpoint/sysmon events in `device.hostname`.
        // NAN-1333: raw-SQL now references the INDEXED unified column that
        // materializes that union (`src_host_unified`), not the inline `if(...)`,
        // so WHERE/GROUP BY prunes via the words index. The `if(...)` survives as
        // `class_split_value_sql` (the column's materialization def + source of
        // truth) — see `udm_column_sql_emits_unified_column_for_class_split`.
        assert_eq!(p.udm_column_sql("src_host").as_deref(), Some("src_host_unified"));
        assert_eq!(p.udm_column_sql("src_ip").as_deref(), Some("\"src_endpoint.ip\""));
        // NAN-1276 class-split resolution: OCSF puts the primary process in the
        // top-level `process.*` (Process Activity 1007) but in `actor.process.*`
        // on Module/Network/File/DNS/Registry. NAN-1333 routes these to their
        // indexed unified columns (same union, words-index prunable).
        assert_eq!(p.udm_column_sql("process_name").as_deref(), Some("process_name_unified"));
        assert_eq!(p.udm_column_sql("command_line").as_deref(), Some("command_line_unified"));
        assert_eq!(p.udm_column_sql("process_id").as_deref(), Some("process_id_unified"));
        // `user` spans Authentication subject (`user.name`) vs initiator
        // (`actor.user.name`); NAN-1333 → indexed unified column.
        assert_eq!(p.udm_column_sql("user").as_deref(), Some("user_unified"));
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
        // NAN-1383: prevalence_min is promoted too (least() of the four columns,
        // materialized in the DDL) so prevalence-gated saved content resolves it.
        assert_eq!(
            p.udm_column_sql("prevalence_min").as_deref(),
            Some("prevalence_min")
        );
        assert_eq!(
            p.udm_column_sql("parent_process_name").as_deref(),
            Some("\"process.parent_process.name\"")
        );
        // Concepts OCSF still has no column for → None so callers skip the field.
        assert_eq!(p.udm_column_sql("registry_value"), None);
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

    /// NAN-1333: the class-split unified COLUMN seam — the indexed column that
    /// materializes the same union. OCSF returns `<udm_field>_unified` for the 10
    /// split concepts; UDM and OCSF non-split/native fields return None. The codegen
    /// routes WHERE/GROUP BY/raw-SQL to this column so the words index prunes.
    #[test]
    fn class_split_column_maps_split_concepts_to_unified_column() {
        use crate::schema::{SchemaProfile, UdmProfile};
        let ocsf = OcsfProfile::new();
        // All 10 split concepts → `<udm_field>_unified`, derived from the single
        // CLASS_SPLIT_UDM_FIELDS source (NAN-1623, D4) — the column is always
        // `<udm_field>_unified`.
        for udm in CLASS_SPLIT_UDM_FIELDS.iter().copied() {
            let col = format!("{udm}_unified");
            assert_eq!(
                ocsf.class_split_column(udm).as_deref(),
                Some(col.as_str()),
                "OCSF class_split_column({udm})"
            );
            // The unified-column set must be 1:1 with the value-pick set.
            assert!(ocsf.class_split_value_sql(udm).is_some());
        }
        // Non-split UDM concept + native OCSF column → None.
        assert_eq!(ocsf.class_split_column("src_ip"), None);
        assert_eq!(ocsf.class_split_column("dest_host"), None);
        assert_eq!(ocsf.class_split_column("src_endpoint.hostname"), None);
        // UDM never class-splits → always None (byte-identical codegen).
        let udm = UdmProfile::new();
        assert_eq!(udm.class_split_column("src_host"), None);
        assert_eq!(udm.class_split_column("user"), None);
    }

    /// NAN-1333: `udm_column_sql` (raw-SQL builders) now emits the indexed unified
    /// column for a class-split concept, NOT the inline value-pick `if(...)`. The
    /// `if(...)` survives as `class_split_value_sql` (source of truth + the column's
    /// materialization def), but raw-SQL/projection should reference the column.
    #[test]
    fn udm_column_sql_emits_unified_column_for_class_split() {
        use crate::schema::SchemaProfile;
        let ocsf = OcsfProfile::new();
        assert_eq!(ocsf.udm_column_sql("src_host").as_deref(), Some("src_host_unified"));
        assert_eq!(ocsf.udm_column_sql("user").as_deref(), Some("user_unified"));
        assert_eq!(
            ocsf.udm_column_sql("process_name").as_deref(),
            Some("process_name_unified")
        );
        // No inline `if(` in the emitted raw-SQL reference for a split concept.
        assert!(!ocsf.udm_column_sql("src_host").unwrap().contains("if("));
    }

    /// NAN-1623 (D4): the four class-split sites stay in lockstep. The unified
    /// columns are hand-maintained in four places (the value-pick definition, the
    /// indexed-column map, and the OCSF_UNIFIED / OCSF_BOOKKEEPING re-add lists);
    /// drift between them is a silent CH Code 47 at query time (a CTE stage selects
    /// a `*_unified` column the re-add list omitted). This derives everything from
    /// the single `CLASS_SPLIT_UDM_FIELDS` key set and asserts all four agree.
    #[test]
    fn class_split_sites_stay_in_lockstep() {
        let unified: std::collections::HashSet<&str> =
            OCSF_UNIFIED_COLUMNS.iter().copied().collect();
        let bookkeeping: std::collections::HashSet<&str> =
            OCSF_BOOKKEEPING_COLUMNS.iter().copied().collect();

        for k in CLASS_SPLIT_UDM_FIELDS.iter().copied() {
            // The key set must match the value-pick definition's key set.
            assert!(
                class_split_udm_field(k).is_some(),
                "{k} is in CLASS_SPLIT_UDM_FIELDS but class_split_udm_field({k}) is None",
            );
            // The indexed column is exactly `<field>_unified`.
            let expected = format!("{k}_unified");
            assert_eq!(
                class_split_column(k),
                Some(expected.as_str()),
                "class_split_column({k}) must be Some(\"{expected}\")",
            );
            // …and that column must be registered in BOTH re-add lists.
            assert!(
                unified.contains(expected.as_str()),
                "{expected} missing from OCSF_UNIFIED_COLUMNS",
            );
            assert!(
                bookkeeping.contains(expected.as_str()),
                "{expected} missing from OCSF_BOOKKEEPING_COLUMNS",
            );
        }

        // Exact size: 10 split concepts, 10 unified columns (no extras on either side).
        assert_eq!(CLASS_SPLIT_UDM_FIELDS.len(), 10);
        assert_eq!(OCSF_UNIFIED_COLUMNS.len(), 10);
        assert_eq!(
            unified.len(),
            CLASS_SPLIT_UDM_FIELDS.len(),
            "OCSF_UNIFIED_COLUMNS has a column with no class-split key",
        );
        // The unified set is a subset of the bookkeeping set (each unified column is
        // bookkeeping, but bookkeeping also carries event/unmapped/timestamp/etc).
        assert!(
            unified.is_subset(&bookkeeping),
            "OCSF_UNIFIED_COLUMNS must be a subset of OCSF_BOOKKEEPING_COLUMNS",
        );

        // Reverse direction: a class-split arm added to `class_split_udm_field` /
        // `class_split_column` but forgotten in `CLASS_SPLIT_UDM_FIELDS` (or the
        // re-add lists) would otherwise slip through the forward checks above. Probe
        // the whole UDM field universe (`EXPLICIT_COLUMNS` — every class-split
        // concept is a promoted UDM field, so a real new split concept appears here)
        // and assert the two split functions return Some for EXACTLY the registered
        // keys and agree with each other per field.
        let keys: std::collections::HashSet<&str> =
            CLASS_SPLIT_UDM_FIELDS.iter().copied().collect();
        for field in crate::query::EXPLICIT_COLUMNS.iter().copied() {
            let by_column = class_split_column(field).is_some();
            let by_value = class_split_udm_field(field).is_some();
            assert_eq!(
                by_column, by_value,
                "{field}: class_split_column / class_split_udm_field disagree on split-ness",
            );
            assert_eq!(
                by_column,
                keys.contains(field),
                "{field}: class-split functions return Some={by_column} but \
                 CLASS_SPLIT_UDM_FIELDS membership={} — a split arm and the SoT const drifted",
                keys.contains(field),
            );
        }
    }

    /// NAN-1382 (G6): manifest-driven enum label→int metadata. Fixed-table enum
    /// columns (status_id / auth_protocol_id / severity_id) expose `Values`;
    /// the class-scoped activity_id exposes its sibling label column; both the
    /// UDM alias and the native column spelling resolve; string columns and
    /// plain numerics expose nothing.
    #[test]
    fn enum_int_mapping_resolves_aliases_and_native_columns() {
        let p = OcsfProfile::new();
        // UDM alias → fixed table on the resolved int column.
        match p.enum_int_mapping("auth_result") {
            Some(EnumIntMapping::Values(m)) => {
                assert_eq!(m.get("failure"), Some(&2));
                assert_eq!(m.get("success"), Some(&1));
                assert_eq!(m.get("unknown"), Some(&0));
                assert_eq!(m.get("other"), Some(&99));
            }
            other => panic!("auth_result must map to a fixed enum table, got {other:?}"),
        }
        // Native column spelling resolves to the same table.
        assert_eq!(p.enum_int_mapping("status_id"), p.enum_int_mapping("auth_result"));
        match p.enum_int_mapping("auth_type") {
            Some(EnumIntMapping::Values(m)) => {
                assert_eq!(m.get("kerberos"), Some(&2));
                assert_eq!(m.get("ntlm"), Some(&1));
            }
            other => panic!("auth_type must map to a fixed enum table, got {other:?}"),
        }
        match p.enum_int_mapping("severity_id") {
            Some(EnumIntMapping::Values(m)) => assert_eq!(m.get("high"), Some(&4)),
            other => panic!("severity_id must map to a fixed enum table, got {other:?}"),
        }
        // Class-scoped activity_id (and its UDM aliases) → sibling label column.
        for f in ["event_type", "file_action", "change_type", "activity_id"] {
            assert_eq!(
                p.enum_int_mapping(f),
                Some(EnumIntMapping::LabelColumn("activity")),
                "{f} must redirect string verbs to the sibling `activity` column"
            );
        }
        // String columns / plain numerics / unknowns expose nothing.
        for f in ["status", "severity", "action", "src_ip", "src_endpoint.port", "nonexistent"] {
            assert!(p.enum_int_mapping(f).is_none(), "{f} must have no enum mapping");
        }
    }

    /// NAN-1827: `raw_data` must resolve to the real promoted column, NOT fall
    /// through to `unmapped.raw_data`.
    ///
    /// This is the silent half of the bug the column fixes. `raw_data` is a
    /// standard OCSF attribute, so a conformant producer never writes it into
    /// `unmapped` — but before it was promoted, `resolve()` had no entry for it
    /// and hit the json-tail fallthrough. A hunt for `raw_data` therefore
    /// returned EMPTY RESULTS WITH NO ERROR: the producer's original had been
    /// dropped at ingest, and the query said "no matches" rather than "no such
    /// field". Promoting the column without this assertion would fix the storage
    /// and leave the query layer reading the wrong place.
    #[test]
    fn raw_data_resolves_to_the_promoted_column_not_the_json_tail() {
        let p = OcsfProfile::new();
        assert_eq!(
            p.resolve("raw_data"),
            FieldResolution::ExplicitColumn("raw_data".to_string()),
            "raw_data must resolve to the promoted column; a JsonPath into `{OCSF_TAIL_COLUMN}` \
             means nPL reads the tail while the data sits in the column — empty results, no error"
        );
        // The bare-keyword hunt column is deliberately NOT widened to raw_data:
        // OR-ing a second text index unions the granule sets and roughly doubles
        // the read. Explicit `raw_data` hunts get the idx_raw_data_words index;
        // bare keywords stay on `message` alone.
        assert_eq!(p.keyword_search_column(), "message");
    }

    // ---- NAN-4903: version-agnostic resolution -------------------------------

    #[test]
    fn unpromoted_ocsf_attribute_reads_event_json() {
        let p = OcsfProfile::new();
        assert_eq!(
            p.resolve("process.file.name"),
            FieldResolution::JsonPath {
                col: "event".into(),
                path: vec!["process".into(), "file".into(), "name".into()],
            }
        );
        assert!(p.is_known_field("process.file.name"));
        assert!(!p.is_array_field("process.file.name"));
    }

    #[test]
    fn array_crossing_attribute_gets_element_markers() {
        let p = OcsfProfile::new();
        let FieldResolution::JsonPath { col, path } = p.resolve("module.file.signatures.state") else {
            panic!("expected JsonPath");
        };
        assert_eq!(col, "event");
        assert_eq!(path, vec!["module", "file", "signatures", "[]", "state"]);
        assert!(p.is_array_field("module.file.signatures.state"));
        let sql = crate::query::json_tail_access_sql(&col, &path, "String");
        assert_eq!(
            sql,
            "arrayMap(x -> ifNull(toString(x), ''), event.\"module\".\"file\".\"signatures\"[].\"state\")"
        );
    }

    #[test]
    fn promoted_arrays_and_routing_aliases() {
        let p = OcsfProfile::new();
        assert!(p.is_array_field("observables.value"));
        assert!(p.is_array_field("process.file.hashes.value"));
        assert!(p.is_lowercased_at_ingest("process.file.hashes.value"));
        assert!(!p.is_lowercased_at_ingest("observables.value"));
        assert!(!p.is_array_field("src_endpoint.ip"));
        assert_eq!(p.resolve("metadata.log_source"), FieldResolution::ExplicitColumn("source_type".into()));
        assert_eq!(p.resolve("time"), FieldResolution::ExplicitColumn("timestamp".into()));
        // Derived scalars keep the UDM-era names working.
        assert_eq!(p.resolve("file_hash"), FieldResolution::ExplicitColumn("file.hashes.sha256".into()));
        assert!(p.is_known_field("process.file.hashes.sha256"));
        assert!(p.is_known_field("enrichments.ioc_src_ip_threat_type"));
    }

    #[test]
    fn non_ocsf_names_still_spill_to_unmapped() {
        let p = OcsfProfile::new();
        assert_eq!(
            p.resolve("api_key_name"),
            FieldResolution::JsonPath { col: "unmapped".into(), path: vec!["api_key_name".into()] }
        );
        assert!(!p.is_known_field("api_key_name"));
    }

    #[test]
    fn registry_leaf_types_drive_json_field_types() {
        let p = OcsfProfile::new();
        assert_eq!(p.field_type("connection_info.direction_id"), Some(FieldType::Integer));
        assert!(p.is_numeric_field("connection_info.direction_id"));
    }
}
