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
//!   the OCSF analog of UDM's `ext`. The generator emits native subcolumn
//!   access (`event."p1"."p2"` forms — NAN-1426; JSONExtract* re-serialized
//!   the whole event per row).
//!
//! Array `[]` paths never arrive from the nPL tokenizer (it only emits dotted
//! identifiers), so `resolve()` does not synthesize `ArrayElement`; array-derived
//! values are reached through their promoted dotted column (`file.hashes.sha256`)
//! instead.

use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::sync::{Arc, OnceLock};

use serde::Deserialize;

use super::profile::SchemaProfile;
use super::types::{
    EnrichmentKind, EnrichmentMode, EntityRole, EntityType, EnumIntMapping, FieldCategory,
    FieldDef, FieldResolution, FieldType, SchemaId,
};
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

/// The operational provenance / routing key (Security Lake "custom source"
/// pattern). NOT an OCSF `event` field and NOT manifest-promoted: it is a plain
/// ingest-written column written from the `X-Source-Type` header, lowercased at
/// ingest, sitting next to `timestamp`/`_inserted_at`. It mirrors UDM
/// `source_type` byte-for-byte so the SQL generator's PREWHERE + lowercase
/// fast-path engages identically (NAN-1241). Special-cased exactly like the
/// `timestamp`/`_inserted_at` bookkeeping columns — see [`OcsfProfile::resolve`].
const OCSF_SOURCE_TYPE_COLUMN: &str = "source_type";

/// Storage binding for one OCSF profile instance. The ClickHouse layout keeps
/// its historical serving columns. The lake layout is strict canonical OCSF
/// 1.9: product aliases resolve to canonical paths without serving columns.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OcsfStorageLayout {
    ClickHouse18,
    Lake19,
}

const OCSF_1_9_NATIVE_FIELDS: &[&str] = &[
    "time",
    "type_uid",
    "class_uid",
    "class_name",
    "category_uid",
    "category_name",
    "activity_id",
    "activity_name",
    "severity_id",
    "severity",
    "status_id",
    "status",
    "status_code",
    "status_detail",
    "count",
    "risk_score",
    "risk_level_id",
    "risk_level",
    "risk_details",
    "message",
    "raw_data",
    "raw_data_size",
    "unmapped",
    "actor.user.domain",
    "metadata.uid",
    "metadata.version",
    "metadata.log_name",
    "metadata.log_provider",
    "metadata.log_source",
    "metadata.original_event_uid",
    "metadata.tenant_uid",
    "metadata.processed_time",
    "metadata.logged_time",
    "metadata.transformation_info_list",
    // Nano platform stamps the platform base lake prepare writes on source
    // rows (NAN-3003; admitted by `nanosiem-lake-worker` normalize as the
    // closed `PLATFORM_METADATA_STAMPS` list): which ingest credential sent
    // the row and which parser bundle parsed it.
    "metadata.nano_credential_id",
    "metadata.nano_parser_bundle_sha256",
    // Nano-authored OCSF 1.9 Detection Finding (2004) leaves. These are part
    // of the product's canonical writer contract, so validation must recognize
    // them even before a tenant snapshot happens to contain a Signal.
    "finding_info.uid",
    "finding_info.title",
    "finding_info.analytic.uid",
    "finding_info.analytic.name",
    "finding_info.analytic.type",
    "finding_info.analytic.type_id",
    "finding_info.types",
    "finding_info.data_sources",
    "finding_info.attacks.tactic.uid",
    "finding_info.attacks.technique.uid",
    // NAN-3224: paired ATT&CK names, timing, alert link, analytic state.
    "is_alert",
    "start_time",
    "end_time",
    "finding_info.created_time",
    "finding_info.first_seen_time",
    "finding_info.last_seen_time",
    "finding_info.uid_alt",
    "finding_info.src_url",
    "finding_info.analytic.state",
    "finding_info.analytic.state_id",
    "finding_info.attacks.tactic.name",
    "finding_info.attacks.technique.name",
    "finding_info.attacks.sub_technique.uid",
    "finding_info.attacks.sub_technique.name",
    "finding_info.related_events.uid",
    "resources.name",
    "resources.role",
    "resources.role_id",
    "resources.ip",
    "resources.hostname",
    "resources.uid",
    "resources.type",
    "resources.device.name",
    "resources.device.hostname",
    "resources.device.type_id",
    "resources.device.risk_score",
    "resources.device.risk_level",
    "resources.device.risk_level_id",
    "resources.user.name",
    "resources.user.uid",
    "resources.user.risk_score",
    "resources.user.risk_level",
    "resources.user.risk_level_id",
    "evidences.name",
    "evidences.query.hostname",
    "evidences.url.url_string",
    // NAN-3224: curated matched-event evidence.
    "evidences.uid",
    "evidences.actor.user.name",
    "evidences.actor.process.name",
    "evidences.actor.process.cmd_line",
    "evidences.process.name",
    "evidences.process.cmd_line",
    "evidences.user.name",
    "evidences.device.hostname",
    "evidences.src_endpoint.ip",
    "evidences.dst_endpoint.ip",
    "evidences.file.name",
    "evidences.file.path",
    "evidences.reg_key.path",
    "enrichments.name",
    "enrichments.value",
    "enrichments.type",
    "enrichments.provider",
    "enrichments.short_desc",
    "observables.name",
    "observables.type",
    "observables.type_id",
    "observables.value",
];

/// Canonical OCSF leaves whose parent object is repeated. ClickHouse exposes
/// these Parquet leaves as `Array(Nullable(String))`; nPL treats equality as
/// membership and text operators as an element-wise predicate. These are
/// schema paths, not persisted scalar aliases.
const OCSF_1_9_STRING_ARRAY_FIELDS: &[&str] = &[
    "actor.process.file.hashes.value",
    "answers.rdata",
    // NAN-2379: `email.to[]` and `vulnerabilities[].cve.uid` are advertised by
    // the field universe but had NO addressable dotted sibling — the only two of
    // the nine `[]` paths with no other way in. They are genuine OCSF 1.9
    // repeated attributes (`email.to` is `email_address[]`; `vulnerabilities` is
    // `vulnerability[]`), so they belong here with the rest of the array leaves.
    "email.to",
    "vulnerabilities.cve.uid",
    "file.hashes.value",
    "finding_info.types",
    "finding_info.data_sources",
    "finding_info.attacks.tactic.uid",
    "finding_info.attacks.technique.uid",
    // NAN-3224: paired ATT&CK names and related events.
    "finding_info.attacks.tactic.name",
    "finding_info.attacks.technique.name",
    "finding_info.attacks.sub_technique.uid",
    "finding_info.attacks.sub_technique.name",
    "finding_info.related_events.uid",
    "http_request.url.categories",
    "metadata.transformation_info_list.lang",
    "metadata.transformation_info_list.name",
    "metadata.transformation_info_list.uid",
    "privileges",
    "process.file.hashes.value",
    "resources.name",
    "resources.role",
    "resources.role_id",
    "resources.ip",
    "resources.hostname",
    "resources.type",
    "resources.uid",
    "resources.device.name",
    "resources.device.hostname",
    "resources.device.type_id",
    "resources.device.risk_score",
    "resources.device.risk_level",
    "resources.device.risk_level_id",
    "resources.user.name",
    "resources.user.uid",
    "resources.user.risk_score",
    "resources.user.risk_level",
    "resources.user.risk_level_id",
    "evidences.name",
    "evidences.query.hostname",
    "evidences.url.url_string",
    // NAN-3224: curated matched-event evidence.
    "evidences.uid",
    "evidences.actor.user.name",
    "evidences.actor.process.name",
    "evidences.actor.process.cmd_line",
    "evidences.process.name",
    "evidences.process.cmd_line",
    "evidences.user.name",
    "evidences.device.hostname",
    "evidences.src_endpoint.ip",
    "evidences.dst_endpoint.ip",
    "evidences.file.name",
    "evidences.file.path",
    "evidences.reg_key.path",
    "enrichments.name",
    "enrichments.value",
    "enrichments.type",
    "enrichments.provider",
    "enrichments.short_desc",
    "observables.name",
    "observables.type",
    "observables.type_id",
    "observables.value",
];

const OCSF_1_9_CORE_FIELDS: &[&str] = &["metadata.uid", "time", "message", "metadata.log_source"];

const OCSF_1_9_DEFAULT_TABLE_FIELDS: &[&str] = &[
    "time",
    "class_uid",
    "src_endpoint.ip",
    "dst_endpoint.ip",
    "user.name",
    "message",
];

const OCSF_1_9_PRIORITY_FIELDS: &[&str] = &[
    "time",
    "metadata.log_source",
    "class_uid",
    "type_uid",
    "severity_id",
    "src_endpoint.ip",
    "dst_endpoint.ip",
    "user.name",
    "process.name",
];

const OCSF_1_9_PREWHERE_FIELDS: &[&str] = &[
    "metadata.log_source",
    "class_uid",
    "type_uid",
    "src_endpoint.ip",
    "dst_endpoint.ip",
    "user.name",
    "actor.user.name",
    "device.hostname",
    "file.hashes.value",
    "process.file.hashes.value",
];

/// Promoted columns the DDL declares `DEFAULT` (NOT `MATERIALIZED`) because they
/// sit in the sort key, which ClickHouse forbids MATERIALIZED columns from
/// joining — the same carve-out that already applies to `timestamp` (NAN-1334).
/// Unlike MATERIALIZED columns, `DEFAULT` columns ARE included in `SELECT *`, so
/// they MUST be EXCLUDED from the [`OcsfRegistry::materialized`] re-add list:
/// re-adding them alongside `SELECT *` would emit a duplicate column (CH Code 352).
/// They still derive from `event` on insert exactly as before. `timestamp` is not
/// listed here because it is bookkeeping (never in the manifest promotion set, so
/// never on the re-add list to begin with).
const OCSF_DEFAULT_SORTKEY_COLUMNS: &[&str] = &["class_uid", "src_endpoint.ip"];

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
    #[serde(default)]
    ocsf_path: Option<String>,
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

/// Detection entity-extraction priority for the canonical OCSF 1.9 lake
/// contract. Repeated hash objects expose their value through the canonical
/// `hashes.value` leaf; the ClickHouse-era scalar `hashes.sha256` projections
/// above do not exist in strict lake rows.
const OCSF_1_9_ENTITY_EXTRACTION_ORDER: &[(EntityRole, &str)] = &[
    (EntityRole::SrcIp, "src_endpoint.ip"),
    (EntityRole::DestIp, "dst_endpoint.ip"),
    (EntityRole::User, "user.name"),
    (EntityRole::SrcUser, "actor.user.name"),
    (EntityRole::User, "user.uid"),
    (EntityRole::SrcUser, "actor.user.uid"),
    (EntityRole::SrcHost, "src_endpoint.hostname"),
    (EntityRole::DestHost, "dst_endpoint.hostname"),
    (EntityRole::SrcHost, "device.hostname"),
    (EntityRole::FileHash, "file.hashes.value"),
    (EntityRole::ProcessHash, "process.file.hashes.value"),
    (EntityRole::ProcessHash, "actor.process.file.hashes.value"),
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
    // NAN-1698: `user.name` / `actor.user.name` are deliberately ABSENT (parity
    // with the `source_type` exclusion above and UDM NAN-1697). The derivation MV
    // (`ocsf_logs_raw_mv`) lower()s them — but ONLY on the raw/parser path; the
    // hardened DIRECT-INSERT-into-`ocsf_logs` path (migration 127) bypasses that
    // MV and lands the client's `user.name` verbatim into a plain String column
    // with no `lower()` DEFAULT. A raw `= '<lowered>'` compare then silently drops
    // a mixed-case direct write — the same hole that excluded `source_type`.
    // Queries emit `lower("user.name") = '…'`, served by the `idx_user_name_words`
    // / `idx_actor_user_name_words` text indexes. `user.domain` stays (parity with
    // UDM `user_domain`).
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
    /// Canonical OCSF paths and metadata for the object-lake contract. This is
    /// distinct from `fields`, whose names are historical ClickHouse serving
    /// columns and include Nano-only names such as `time_dt` and `activity`.
    canonical_fields: Vec<FieldDef>,
    canonical_paths: HashSet<String>,
    /// Promoted-column membership for O(1) `resolve()` / `is_known_field()`.
    promoted: HashSet<String>,
    /// PREWHERE-eligible promoted columns (manifest `prewhere == true`).
    prewhere: Vec<String>,
    /// Promoted columns that are MATERIALIZED in the DDL (so excluded from
    /// `SELECT *`) and must be re-added in multi-stage CTE SELECTs, same as UDM's
    /// `MATERIALIZED_COLUMNS`. EXCLUDES the `time_dt` ALIAS and the
    /// `OCSF_DEFAULT_SORTKEY_COLUMNS` (`class_uid`, `src_endpoint.ip`) — those are
    /// DEFAULT-derived (sort-key carve-out, NAN-1334) and therefore already in
    /// `SELECT *`; re-adding them would duplicate-project (CH Code 352).
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
    /// Product aliases → canonical lake paths (never ClickHouse serving columns).
    udm_to_lake: std::collections::HashMap<String, String>,
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
        let mut search_stems = HashSet::new();
        let mut fields: Vec<FieldDef> = Vec::new();
        let mut canonical_fields: Vec<FieldDef> = Vec::new();
        let mut canonical_paths: HashSet<String> = HashSet::new();
        let mut seen: HashSet<String> = HashSet::new();
        let mut udm_to_column: std::collections::HashMap<String, String> =
            std::collections::HashMap::new();
        let mut udm_to_lake = std::collections::HashMap::new();
        let mut enum_values: std::collections::HashMap<
            String,
            std::collections::HashMap<String, i64>,
        > = std::collections::HashMap::new();
        let mut enum_label_columns: std::collections::HashMap<String, String> =
            std::collections::HashMap::new();

        for e in &entries {
            let name = leak_str(&e.ch_column_name);
            if let Some(path) = e.ocsf_path.as_deref() {
                // NAN-2379: `enrichments[name=<x>].value` is a PROMOTION RECIPE
                // (which array element the ClickHouse-1.8 DDL materializes),
                // not an addressable field path — no tokenizer accepts a
                // key-selector, and there is no flat spelling to fall back to.
                // Keep it out of the advertised universe rather than publish a
                // name no query can use; the addressable enrichment surface is
                // the `enrichments.{name,value,type,provider}` array leaves.
                let advertisable = !path.contains("[name=");
                if canonical_paths.insert(path.to_string()) && advertisable {
                    canonical_fields.push(FieldDef {
                        name: leak_str(path),
                        field_type: map_ch_type(&e.ch_type),
                        category: map_category(e.category.as_deref()),
                        entity_type: map_entity_type(e.entity_type.as_deref()),
                    });
                }
            }
            // UDM-semantic → OCSF-column index (first mapping wins; the manifest
            // occasionally maps two UDM fields to one column, e.g. file_action).
            if let Some(udm) = &e.udm_field {
                // Prevalence counters and selected enrichment values are derived
                // data, not aliases for the artifact/name in their recipe.
                if !udm.starts_with("prevalence_") {
                    if let Some(path) = e.ocsf_path.as_deref().filter(|p| !p.contains("[name=")) {
                        let path = path.replace("[]", "");
                        let path = if path.ends_with(".hashes") {
                            format!("{path}.value")
                        } else {
                            path
                        };
                        udm_to_lake.entry(udm.clone()).or_insert(path);
                    }
                }
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
            if seen.insert(e.ch_column_name.clone()) {
                fields.push(FieldDef {
                    name,
                    field_type: map_ch_type(&e.ch_type),
                    category: map_category(e.category.as_deref()),
                    entity_type: map_entity_type(e.entity_type.as_deref()),
                });
            }
        }

        // The promotion manifest covers only a subset of OCSF enum ids.
        // Load the vendored dictionary's class-independent top-level enums too.
        // Class-specific activity labels keep their sibling-column mapping.
        let dictionary: serde_json::Value = serde_json::from_str(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"), "/docs/ocsf/1.8.0/dictionary.json"
        ))).expect("vendored OCSF dictionary");
        for (field, attribute) in dictionary["attributes"].as_object().expect("OCSF attributes") {
            if !field.ends_with("_id") || field == "activity_id" { continue; }
            let Some(values) = attribute["enum"].as_object() else { continue; };
            let labels = enum_values.entry(field.clone()).or_default();
            for (id, entry) in values {
                if let (Ok(id), Some(label)) = (id.parse::<i64>(), entry["caption"].as_str()) {
                    labels.entry(label.to_lowercase()).or_insert(id);
                }
            }
        }

        // Source routing is metadata, not the taxonomy IDs that share its
        // UDM correspondence in the 1.8 promotion manifest.
        udm_to_lake.insert("source_type".into(), "metadata.log_source".into());
        udm_to_lake.insert("host".into(), "device.hostname".into());
        // Directory enrichment has no manifest OCSF counterpart. Address
        // these known UDM attributes in the explicit producer spill namespace;
        // this does not imply a join to the separate identity directory.
        // Missing leaves are typed NULLs in the lake compatibility projection.
        for field in crate::udm::UdmField::all() {
            let name = field.column_name();
            if name.starts_with("user_identity_")
                || name.starts_with("src_user_identity_")
                || name.starts_with("dest_user_identity_")
            {
                udm_to_lake.insert(name.into(), format!("unmapped.{name}"));
            }
        }

        // `time_dt` is an ALIAS column in the DDL (not MATERIALIZED) — keep it in
        // the field universe / promoted set but drop it from the re-add list so a
        // CTE SELECT does not try to project an alias.
        //
        // `class_uid` / `src_endpoint.ip` are DEFAULT (not MATERIALIZED) because
        // they sit in the sort key (NAN-1334). DEFAULT columns ARE in `SELECT *`,
        // so re-adding them would duplicate-project (CH Code 352). Drop them too.
        materialized
            .retain(|c| c != "time_dt" && !OCSF_DEFAULT_SORTKEY_COLUMNS.contains(&c.as_str()));

        // NAN-1337: the NAN-1333 unified columns are MATERIALIZED real columns but
        // NOT manifest entries, so the loop above never added them. They're absent
        // from `SELECT *`, so a multi-stage CTE that references one in a later stage
        // (`SELECT src_host_unified … FROM stage_0`) fails with "Unknown identifier"
        // unless stage_0 projects it. Append them to the re-add list.
        for u in OCSF_UNIFIED_COLUMNS {
            materialized.push((*u).to_string());
        }

        let lowercased = OCSF_LOWERCASED_AT_INGEST
            .iter()
            .map(|s| s.to_string())
            .collect();

        OcsfRegistry {
            fields,
            canonical_fields,
            canonical_paths,
            promoted,
            prewhere,
            materialized,
            search_stems,
            lowercased,
            udm_to_column,
            udm_to_lake,
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

/// Why a strict lake snapshot may not carry `path` (`None`: admissible).
fn snapshot_field_path_error(path: &str) -> Option<String> {
    if matches!(
        path,
        "id" | "timestamp"
            | "source_type"
            | "src_ip"
            | "dest_ip"
            | "src_host"
            | "dest_host"
            | "user"
            | "process_name"
            | "command_line"
            | "file_hash"
            | "process_hash"
            | "ext"
            | "udm"
    ) || path.starts_with("ext.")
        || path.starts_with("udm.")
    {
        return Some(format!(
            "strict OCSF snapshot exposes forbidden compatibility field {path}"
        ));
    }
    if !is_snapshot_identifier_path(path) {
        return Some(format!("invalid OCSF snapshot field path: {path}"));
    }
    None
}

/// Whether every dot-separated segment of `path` is a plain query identifier
/// (`[A-Za-z_][A-Za-z0-9_]*`). Producer keys such as `unmapped.@timestamp` or
/// `unmapped.Event-ID` are storable but not addressable (NAN-3422).
fn is_snapshot_identifier_path(path: &str) -> bool {
    path.split('.').all(|segment| {
        segment
            .chars()
            .next()
            .is_some_and(|character| character == '_' || character.is_ascii_alphabetic())
            && segment
                .chars()
                .all(|character| character == '_' || character.is_ascii_alphanumeric())
    })
}

/// Map the manifest `category` string onto the schema-agnostic [`FieldCategory`].
/// A scalar leaf of the pinned OCSF 1.9 schema (NAN-2994), derived from the
/// same embedded contract the parser validator enforces at ingest, so the
/// query surface can never lag what producers are allowed to store.
fn ocsf_1_9_leaf(path: &str) -> Option<crate::parsers::OcsfAttributeLeaf> {
    if path == OCSF_TAIL_COLUMN || path.starts_with("unmapped.") {
        return None;
    }
    // The `*_dt` datetime-profile siblings are not stored by the lake (`time`
    // is the physical timestamp); `time_dt` stays a rejected legacy alias.
    crate::parsers::ocsf_attribute_leaf(path).filter(|leaf| !leaf.datetime_profile_only)
}

/// Physical lake type of an OCSF 1.9 contract leaf that the snapshot does not
/// type. Repeated leaves are arrays at rest (see [`OCSF_1_9_STRING_ARRAY_FIELDS`]).
fn ocsf_1_9_leaf_field_type(leaf: crate::parsers::OcsfAttributeLeaf) -> FieldType {
    if leaf.repeated {
        return FieldType::Array;
    }
    match leaf.primitive_type {
        "integer_t" => FieldType::Integer,
        "long_t" => FieldType::Long,
        "float_t" => FieldType::Float,
        "boolean_t" => FieldType::Boolean,
        _ => FieldType::String,
    }
}

/// Physical type of a strict-lake native/array column, shared by
/// [`SchemaProfile::field_type`] and the advertised-universe builder so the
/// inventory can never publish a type the resolver disagrees with.
fn lake_1_9_field_type(column: &str) -> FieldType {
    match column {
        _ if OCSF_1_9_STRING_ARRAY_FIELDS.contains(&column) => FieldType::Array,
        "time" => FieldType::Timestamp,
        "raw_data_size" | "metadata.processed_time" | "metadata.logged_time" => FieldType::Long,
        "type_uid" | "class_uid" | "category_uid" => FieldType::Long,
        "activity_id" | "severity_id" | "status_id" | "risk_score" | "risk_level_id"
        | "finding_info.analytic.state_id" => FieldType::Integer,
        // NAN-3224: OCSF `timestamp_t` leaves of findings (epoch ms).
        "start_time" | "end_time" | "finding_info.created_time" | "finding_info.first_seen_time"
        | "finding_info.last_seen_time" => FieldType::Long,
        "is_alert" => FieldType::Boolean,
        "metadata.transformation_info_list" => FieldType::Array,
        _ => FieldType::String,
    }
}

/// Display bucket for a strict-lake native/array column that has no manifest
/// entry to inherit a category from. Prefix-keyed because these are whole OCSF
/// objects (`finding_info`, `evidences`, `resources`, `enrichments`), not
/// one-off leaves.
fn lake_1_9_category(column: &str) -> FieldCategory {
    if column.starts_with("metadata.") {
        return FieldCategory::System;
    }
    if column.starts_with("enrichments.") {
        return FieldCategory::Enrichment;
    }
    if column.starts_with("observables.") {
        return FieldCategory::Detection;
    }
    if column.starts_with("finding_info.")
        || column.starts_with("evidences.")
        || column.starts_with("resources.")
    {
        return FieldCategory::Alerts;
    }
    if column.starts_with("vulnerabilities.") {
        return FieldCategory::Vulnerability;
    }
    if column.starts_with("risk_") {
        return FieldCategory::Risk;
    }
    match column {
        "time" | "class_uid" | "class_name" | "category_uid" | "category_name" | "type_uid"
        | "activity_id" | "activity_name" | "severity" | "severity_id" | "status" | "status_id"
        | "status_code" | "status_detail" | "count" | "message" | "raw_data" | "raw_data_size" => {
            FieldCategory::System
        }
        _ => FieldCategory::Custom,
    }
}

/// Entity role for a strict-lake native/array column, so drilldowns and
/// detection entity panels treat a finding's evidence exactly like the
/// top-level endpoint columns they mirror.
fn lake_1_9_entity_type(column: &str) -> Option<EntityType> {
    match column {
        "evidences.query.hostname"
        | "resources.hostname"
        | "resources.device.hostname"
        | "resources.device.name" => Some(EntityType::Host),
        "evidences.url.url_string" => Some(EntityType::Url),
        "resources.ip" => Some(EntityType::Ip),
        "resources.user.name" | "resources.user.uid" => Some(EntityType::User),
        "file.hashes.value" | "process.file.hashes.value" | "actor.process.file.hashes.value" => {
            Some(EntityType::Hash)
        }
        _ => None,
    }
}

/// The advertised field universe for the strict OCSF 1.9 lake layout.
///
/// Historically this was `registry().canonical_fields` alone — the OCSF paths
/// the 1.8 promotion manifest happens to carry. That silently hid 65 paths
/// which [`OcsfProfile::lake_1_9_column`] already accepts, resolves to a real
/// serving column, and executes correctly: the whole ATT&CK surface
/// (`finding_info.attacks.{tactic,technique}.uid`), the Detection Finding
/// evidence surface (`evidences.*`), the affected-resource surface
/// (`resources.user.*`, `resources.ip`, `resources.device.*`),
/// `vulnerabilities.cve.uid`, `email.to`, and the core taxonomy leaves
/// (`severity`, `status*`, `risk_*`, `raw_data`, `metadata.log_*`). They were
/// queryable but undiscoverable — absent from `/api/schema/fields`, the
/// FieldsPanel, and every meloD prompt that enumerates the schema.
///
/// Two exclusions keep the inventory honest:
/// - `unmapped` is the bookkeeping spill root (see [`OCSF_BOOKKEEPING_COLUMNS`]),
///   reached through the `unmapped.*` tail namespace, never as a bare field.
/// - A path that is the parent OBJECT of another advertised path (e.g.
///   `metadata.transformation_info_list`) is dropped: advertising an object
///   rather than the leaf that carries a value is exactly the NAN-2379
///   advertised-but-unqueryable shape.
fn lake_field_universe() -> &'static [FieldDef] {
    static UNIVERSE: OnceLock<Vec<FieldDef>> = OnceLock::new();
    UNIVERSE.get_or_init(|| {
        let allowlist: Vec<&'static str> = OCSF_1_9_NATIVE_FIELDS
            .iter()
            .chain(OCSF_1_9_STRING_ARRAY_FIELDS.iter())
            .copied()
            .collect();
        let is_parent_object = |name: &str| {
            allowlist.iter().any(|other| {
                other.len() > name.len()
                    && other.starts_with(name)
                    && other.as_bytes()[name.len()] == b'.'
            })
        };

        let mut fields = registry().canonical_fields.clone();
        for &name in super::stored_enrichment::FIELDS {
            fields.push(FieldDef { name,
                field_type: super::stored_enrichment::selector(name).unwrap().field_type,
                category: FieldCategory::Enrichment, entity_type: None });
        }
        let mut seen: HashSet<&'static str> = fields.iter().map(|f| f.name).collect();
        for name in allowlist.iter().copied() {
            if name == OCSF_TAIL_COLUMN || !seen.insert(name) || is_parent_object(name) {
                continue;
            }
            fields.push(FieldDef {
                name,
                field_type: lake_1_9_field_type(name),
                category: lake_1_9_category(name),
                entity_type: lake_1_9_entity_type(name),
            });
        }

        // A manifest `X[]` spelling and the flat leaf it canonicalizes to are
        // the SAME serving column. Advertising both puts two names for one
        // column in every field picker, and only one of them is what a parsed
        // query actually carries (the tokenizer drops `[]`). Keep the flat
        // leaf; the bracket spelling stays ACCEPTED by `is_known_field` — it is
        // simply no longer a second advertised name.
        let lake = OcsfProfile::lake_1_9();
        fields.retain(|field| {
            if !field.name.contains("[]") {
                return true;
            }
            let addressable = field.name.replace("[]", "");
            let canonical = lake.canonicalize(&addressable).into_owned();
            !seen.contains(canonical.as_str())
        });
        fields
    })
}

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
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OcsfProfile {
    enrichment_mode: EnrichmentMode,
    storage_layout: OcsfStorageLayout,
    /// Exact producer-owned non-OCSF leaf types from the trusted immutable lake
    /// manifest. These are physical `unmapped.*` struct leaves, not aliases.
    lake_unmapped_field_types: Arc<BTreeMap<String, FieldType>>,
    /// Exact physical leaves published by the immutable, schema-validated OCSF
    /// snapshot. This keeps minor OCSF upgrades data-driven: a newly standard
    /// field is queryable as its native path without adding a Nano alias.
    lake_snapshot_field_types: Arc<BTreeMap<String, FieldType>>,
    /// Lake 1.9 only: paths every part of the queried window proves were
    /// lowercased at rest (signed part provenance, admission v2). String
    /// equality on them compares raw, so Parquet blooms/statistics prune.
    lake_lowercased_at_rest: Arc<BTreeSet<String>>,
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
            storage_layout: OcsfStorageLayout::ClickHouse18,
            lake_unmapped_field_types: Arc::new(BTreeMap::new()),
            lake_snapshot_field_types: Arc::new(BTreeMap::new()),
            lake_lowercased_at_rest: Arc::new(BTreeSet::new()),
        }
    }

    /// Construct the OCSF profile with an explicit enrichment mode. (Phase-6 knob;
    /// see [`new`](OcsfProfile::new) for why `Read` is the default.)
    pub fn with_enrichment_mode(mode: EnrichmentMode) -> Self {
        Self {
            enrichment_mode: mode,
            storage_layout: OcsfStorageLayout::ClickHouse18,
            lake_unmapped_field_types: Arc::new(BTreeMap::new()),
            lake_snapshot_field_types: Arc::new(BTreeMap::new()),
            lake_lowercased_at_rest: Arc::new(BTreeSet::new()),
        }
    }

    /// Construct the canonical OCSF 1.9 object-lake profile. This is selected
    /// only by the tenant-pinned lake compiler; the existing ClickHouse OCSF
    /// deployment keeps [`new`](Self::new) and remains byte-compatible.
    pub fn lake_1_9() -> Self {
        Self {
            enrichment_mode: EnrichmentMode::Read,
            storage_layout: OcsfStorageLayout::Lake19,
            lake_unmapped_field_types: Arc::new(BTreeMap::new()),
            lake_snapshot_field_types: Arc::new(BTreeMap::new()),
            lake_lowercased_at_rest: Arc::new(BTreeSet::new()),
        }
    }

    /// Construct the strict OCSF 1.9 lake profile with the producer-field type
    /// contract published beside an immutable event snapshot.
    pub fn try_lake_1_9_with_unmapped_field_types(
        field_types: BTreeMap<String, FieldType>,
    ) -> Result<Self, String> {
        Self::try_lake_1_9_with_snapshot_field_types(field_types)
    }

    /// Whether [`Self::try_lake_1_9_with_snapshot_field_types`] admits `path`
    /// (NAN-2997: a lean tenant's part schema can hold producer keys that are
    /// not query identifiers, e.g. `unmapped.Event-ID`; the caller drops those
    /// leaves instead of losing the whole inventory).
    pub fn is_admissible_snapshot_field_path(path: &str) -> bool {
        snapshot_field_path_error(path).is_none()
    }

    /// Construct the strict lake profile from the field inventory signed into
    /// the immutable snapshot manifest. Producer validation is responsible for
    /// proving that non-`unmapped` paths belong to the selected OCSF release;
    /// this seam drops leaves that are not safe native identifiers and rejects
    /// every legacy compatibility namespace.
    pub fn try_lake_1_9_with_snapshot_field_types(
        field_types: BTreeMap<String, FieldType>,
    ) -> Result<Self, String> {
        // NAN-3422: a producer key that is not a query identifier (Beats'
        // `unmapped.@timestamp`) is storable but cannot be addressed. Drop that
        // leaf instead of refusing the whole inventory: one odd field name must
        // never fail queries that do not reference it. Legacy compatibility
        // namespaces are still refused outright.
        let mut field_types = field_types;
        field_types.retain(|path, _| is_snapshot_identifier_path(path));
        for path in field_types.keys() {
            if let Some(error) = snapshot_field_path_error(path) {
                return Err(error);
            }
        }
        let unmapped = field_types
            .iter()
            .filter(|(path, _)| path.starts_with("unmapped."))
            .map(|(path, field_type)| (path.clone(), *field_type))
            .collect();
        Ok(Self {
            enrichment_mode: EnrichmentMode::Read,
            storage_layout: OcsfStorageLayout::Lake19,
            lake_unmapped_field_types: Arc::new(unmapped),
            lake_snapshot_field_types: Arc::new(field_types),
            lake_lowercased_at_rest: Arc::new(BTreeSet::new()),
        })
    }

    /// Lake 1.9: treat `paths` as lowercased at rest (raw string equality).
    /// The caller must hold proof that every row of the queried source was
    /// lowercased on these paths; an unproven path silently drops mixed-case
    /// rows. Only string leaves of the snapshot are accepted.
    pub fn with_lake_lowercased_at_rest(mut self, paths: &[String]) -> Result<Self, String> {
        if !self.is_lake_1_9() {
            return Err("lowercased-at-rest paths apply to the OCSF 1.9 lake profile only".to_string());
        }
        for path in paths {
            if self.lake_snapshot_field_types.get(path) != Some(&FieldType::String) {
                return Err(format!("lowercased-at-rest path {path} is not a string leaf of the snapshot"));
            }
        }
        self.lake_lowercased_at_rest = Arc::new(paths.iter().cloned().collect());
        Ok(self)
    }

    fn is_lake_1_9(&self) -> bool {
        self.storage_layout == OcsfStorageLayout::Lake19
    }

    /// Rewrite a repeated-object path that names an OBJECT rather than a leaf
    /// onto the leaf that carries its value (NAN-2379).
    ///
    /// The field universe advertises `file.hashes[]` / `process.file.hashes[]` /
    /// `actor.process.file.hashes[]`. The tokenizer drops the `[]` marker
    /// (`parser::values::strip_repeated_marker`), which leaves `<p>.hashes` —
    /// an array of `fingerprint` objects, not something a predicate can compare
    /// against. The value lives one level down, and WHICH leaf depends on the
    /// storage layout: strict lake rows expose the canonical `hashes.value`
    /// array, while the ClickHouse-1.8 table carries the scalar first-SHA-256
    /// projection `hashes.sha256` (see `OCSF_1_9_ENTITY_EXTRACTION_ORDER`).
    ///
    /// Gated on the target actually resolving to a physical column, so this can
    /// only ever turn an unresolvable name into a resolvable one.
    fn repeated_object_leaf(&self, npl_field: &str) -> Option<String> {
        if !(npl_field == "hashes" || npl_field.ends_with(".hashes")) {
            return None;
        }
        let leaf = if self.is_lake_1_9() {
            format!("{npl_field}.value")
        } else {
            format!("{npl_field}.sha256")
        };
        self.resolves_to_physical_column(&leaf).then_some(leaf)
    }

    fn lake_1_9_column<'a>(&self, field: &'a str) -> Option<&'a str> {
        if !self.is_lake_1_9() {
            return None;
        }
        (OCSF_1_9_NATIVE_FIELDS.contains(&field) || OCSF_1_9_STRING_ARRAY_FIELDS.contains(&field))
            .then_some(field)
    }

    /// NAN-3451: the snapshot carries the aligned `enrichments[]` prevalence
    /// stamp arrays the `prevalence_*` scalars are derived from.
    fn has_lake_prevalence_stamp(&self) -> bool {
        self.is_lake_1_9()
            && super::lake_prevalence::has_stamp(&|field| {
                self.lake_snapshot_field_types.get(field).copied()
            })
    }

    /// NAN-3451: a `prevalence_*` scalar derived from `enrichments[]` on an
    /// open-core lake. Never when the snapshot has the physical column: lean
    /// signed parts carry immutable ingest-time stamps (NAN-2915), and those
    /// must not be shadowed.
    fn derives_lake_prevalence_scalar(&self, field: &str) -> bool {
        super::lake_prevalence::is_scalar(field)
            && !self.lake_snapshot_field_types.contains_key(field)
            && self.has_lake_prevalence_stamp()
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
        // Analyst compatibility spellings have explicit, layout-independent targets.
        let npl_field = match npl_field {
            "auth_result" => "status_id",
            "protocol" => "connection_info.protocol_num",
            "protocol_name" => "connection_info.protocol_name",
            other => other,
        };
        if self.is_lake_1_9() {
            // Unstamped lake data has no prevalence (#4644). Lean signed parts
            // carry physical ingest-time columns (NAN-2915); open-core lake
            // generations derive them from the enrichment arrays (NAN-3451).
            if super::lake_prevalence::is_scalar(npl_field)
                && !self.has_lake_prevalence_stamp()
                && !self.lake_snapshot_field_types.contains_key(npl_field)
            {
                return FieldResolution::Unknown;
            }
            if super::stored_enrichment::selector(npl_field).is_some()
                || super::lake_prevalence::is_scalar(npl_field)
                || self.lake_1_9_column(npl_field).is_some()
                || registry().canonical_paths.contains(npl_field)
                || self.lake_snapshot_field_types.contains_key(npl_field)
            {
                return FieldResolution::ExplicitColumn(npl_field.to_string());
            }
            if let Some(target) = registry()
                .udm_to_lake
                .get(npl_field)
                .filter(|t| t.as_str() != npl_field)
            {
                return self.resolve_canonical(target);
            }
            if let Some(rest) = npl_field.strip_prefix("unmapped.") {
                if !rest.is_empty() {
                    // Iceberg exposes the typed `unmapped` struct as dotted leaf
                    // columns. Missing leaves are supplied as typed NULLs by the
                    // snapshot compatibility plan, so no Dynamic/JSON probe is
                    // valid or necessary in this storage layout.
                    return FieldResolution::ExplicitColumn(npl_field.to_string());
                }
            }
            // NAN-2994: every scalar leaf of the OCSF 1.9 schema is a canonical
            // path, whether or not this profile's snapshot inventory lists it.
            // A lean-lake cell tenant's front-door profile has NO inventory
            // (query[T] owns the part schema), so the hand lists above were the
            // whole universe and `metadata.event_code` / `action_id` 400'd while
            // being stored on every matching row. A leaf absent from the data is
            // a typed NULL at plan time, never a missing-column fault.
            if ocsf_1_9_leaf(npl_field).is_some() {
                return FieldResolution::ExplicitColumn(npl_field.to_string());
            }
            return FieldResolution::Unknown;
        }
        if let Some(column) = self.lake_1_9_column(npl_field) {
            return FieldResolution::ExplicitColumn(column.to_string());
        }
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
            return self.resolve_canonical(rest);
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
    fn source_computed_column(&self, field: &str) -> Option<(String, Vec<&'static str>)> {
        if self.is_lake_1_9() {
            if let Some(selector) = super::stored_enrichment::selector(field) {
                return Some(selector.expression(|name| self.lake_snapshot_field_types.contains_key(name)));
            }
        }
        // Lean signed parts carry immutable ingest-time scalar stamps; the
        // enrichment derivation is only for open-core lake generations that
        // have no physical stamp column (NAN-3451, see `lake_prevalence`).
        if !self.derives_lake_prevalence_scalar(field) {
            return None;
        }
        // An artifact source is usable when this lake can address it: an
        // inventory column or an OCSF 1.9 contract leaf (typed NULL when the
        // data never carried it).
        super::lake_prevalence::expression(field, |name| self.resolves_to_physical_column(name))
    }

    fn id(&self) -> SchemaId {
        SchemaId::Ocsf
    }

    fn uses_strict_canonical_fields(&self) -> bool {
        self.is_lake_1_9()
    }

    fn lowercased_host_prefix_compares_raw(&self) -> bool {
        self.is_lake_1_9()
    }

    /// OCSF's JSON tail is the stored `unmapped` spill column (UDM uses `ext`) —
    /// NAN-1343; repointed from the now-EPHEMERAL `event` column by NAN-1443.
    fn json_tail_column(&self) -> &'static str {
        OCSF_TAIL_COLUMN
    }

    /// NAN-1828: a bare keyword must ALSO tokenize against `raw_data`, because on
    /// OCSF the raw log lands in a different column depending on the producer.
    ///
    /// Our Vector OCSF parsers put the raw log in `message` and emit no
    /// `raw_data`. A direct producer (Tenzir) puts the untouched original —
    /// syslog header and all — in `raw_data` and a human summary in `message`.
    /// Searching `message` alone therefore made a Tenzir tenant's original log
    /// invisible to the primary hunt path: NAN-1827 persisted it, but the only
    /// nPL form that reached it (`raw_data=*kw*`) emits `iLike`, which extracts
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
        if self.is_lake_1_9() {
            lake_field_universe()
        } else {
            &registry().fields
        }
    }

    fn snapshot_fields(&self) -> Vec<(String, FieldType)> {
        if !self.is_lake_1_9() {
            return Vec::new();
        }
        self.lake_snapshot_field_types
            .iter()
            .map(|(name, field_type)| (name.clone(), *field_type))
            .collect()
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
        match npl_field {
            "auth_result" => return Cow::Borrowed("status_id"),
            "protocol" => return Cow::Borrowed("connection_info.protocol_num"),
            "protocol_name" => return Cow::Borrowed("connection_info.protocol_name"),
            _ => {}
        }
        // A `<p>.hashes` object path (the `[]`-stripped `<p>.hashes[]` the field
        // universe advertises) addresses the leaf that carries the value —
        // layout-dependent, so it is resolved here rather than in the tokenizer
        // (NAN-2379). Runs ahead of the lake short-circuit because both layouts
        // advertise the bracket form.
        if let Some(leaf) = self.repeated_object_leaf(npl_field) {
            return Cow::Owned(leaf);
        }
        if self.is_lake_1_9() {
            if super::stored_enrichment::selector(npl_field).is_some()
                || super::lake_prevalence::is_scalar(npl_field)
                || self.lake_1_9_column(npl_field).is_some()
                || registry().canonical_paths.contains(npl_field)
                || self.lake_snapshot_field_types.contains_key(npl_field)
            {
                return Cow::Borrowed(npl_field);
            }
            let normalized = if npl_field.contains('.') {
                npl_field
            } else {
                normalize_field_name(crate::search::field_utils::normalize_field_alias(npl_field))
            };
            // Keep class-spanning concepts intact until codegen chooses the
            // value expression; canonical OCSF paths always stay single-column.
            if self.class_split_source_fields(normalized).is_some() {
                return Cow::Borrowed(normalized);
            }
            if let Some(target) = registry().udm_to_lake.get(normalized) {
                return Cow::Borrowed(target);
            }
            return Cow::Borrowed(normalized);
        }
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
        if self.is_lake_1_9() {
            return matches!(self.resolve(name), FieldResolution::ExplicitColumn(_));
        }
        // Alias-aware (NAN-1422): judge the canonical spelling, so the flat
        // operational aliases (`sourcetype` → `source_type`) belong to the field
        // universe. This is the gate the input-side field validator consults
        // (NAN-1380 G5) — `sourcetype` sits one edit from `source_type`, so
        // without this it was 400-rejected as a typo while codegen handled it.
        let canonical = self.canonicalize(name);
        self.lake_1_9_column(canonical.as_ref()).is_some()
            || canonical.as_ref() == OCSF_SOURCE_TYPE_COLUMN
            || registry().promoted.contains(canonical.as_ref())
    }

    fn field_type(&self, field: &str) -> Option<FieldType> {
        if self.is_lake_1_9() {
            if let Some(selector) = super::stored_enrichment::selector(field) {
                return Some(selector.field_type);
            }
        }
        if super::lake_prevalence::is_scalar(field) && self.has_lake_prevalence_stamp() {
            return Some(FieldType::Integer);
        }
        if self.is_lake_1_9() {
            if let FieldResolution::ExplicitColumn(column) = self.resolve(field) {
                if column != field {
                    return self.field_type(&column);
                }
            }
        }
        // NAN-2361: PHYSICAL array-ness wins over the logical element type.
        //
        // The OCSF contract types the ELEMENT of a list-of-struct: `file.hashes`
        // is an array of Hash objects, so `file.hashes.value` is a String *per
        // element*. On disk it is `Array(String)`. Typing it String made the
        // codegen emit `lower(toString("file.hashes.value")) = '<hash>'`, which
        // compares against the rendered whole array (`['abc','def']`) and
        // matches NOTHING while returning HTTP 200 — a hash hunt that silently
        // finds nothing. 61 leaves are affected in the live manifest, including
        // file/process hashes, observables.*, resources.*, answers.rdata and
        // every enrichments.* path.
        //
        // Only the Array verdict is promoted; every other snapshot type keeps
        // its previous precedence, so no other field changes shape.
        if self.is_lake_1_9()
            && self.lake_snapshot_field_types.get(field) == Some(&FieldType::Array)
        {
            return Some(FieldType::Array);
        }
        // NOTE: the `enrichments[].data` leaves are deliberately NOT in the
        // static universe. They exist only once the ingest enrichment stage has
        // written them, and `is_known_field` already consults
        // `lake_snapshot_field_types`, so a tenant that has them can query them
        // and a tenant that has not deployed prevalence stamping gets a clean
        // "unknown canonical OCSF field" instead of a reference to a column its
        // Iceberg schema lacks. Advertising them statically broke exactly that
        // invariant (`lake_field_universe_is_a_subset_of_what_a_query_can_address`).
        if let Some(column) = self.lake_1_9_column(field) {
            return Some(lake_1_9_field_type(column));
        }
        if self.is_lake_1_9() {
            if let Some(field_type) = self.lake_snapshot_field_types.get(field) {
                return Some(*field_type);
            }
            if field.starts_with("unmapped.") {
                return self
                    .lake_unmapped_field_types
                    .get(field)
                    .copied()
                    .or(Some(match field {
                        "unmapped.risk_score" | "unmapped.raw_risk_score" => FieldType::Float,
                        _ => FieldType::String,
                    }));
            }
            if let Some(field_type) = lake_field_universe()
                .iter()
                .find(|candidate| candidate.name == field)
                .map(|candidate| candidate.field_type)
            {
                return Some(field_type);
            }
            // NAN-2994: a contract leaf the snapshot does not (yet) type.
            return ocsf_1_9_leaf(field).map(ocsf_1_9_leaf_field_type);
        }
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
        registry()
            .fields
            .iter()
            .find(|f| f.name == field)
            .map(|f| f.field_type)
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
        registry().lowercased.contains(field) || self.lake_lowercased_at_rest.contains(field)
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
        !self.is_lake_1_9() && field == "id"
    }

    fn is_string_array_field(&self, field: &str) -> bool {
        if !self.is_lake_1_9() {
            return false;
        }
        // Canonicalized, so a repeated-object path gets ARRAY predicate
        // semantics rather than a scalar compare against an Array column
        // (a ClickHouse type error, not a silent miss) — NAN-2379.
        self.field_type(field) == Some(FieldType::Array)
    }

    fn prewhere_fields(&self) -> &[&str] {
        if self.is_lake_1_9() {
            OCSF_1_9_PREWHERE_FIELDS
        } else {
            prewhere_fields_slice()
        }
    }

    fn materialized_columns(&self) -> &[&str] {
        if self.is_lake_1_9() {
            &[]
        } else {
            materialized_columns_slice()
        }
    }

    fn category(&self, field: &str) -> FieldCategory {
        if self.is_lake_1_9() {
            if let FieldResolution::ExplicitColumn(column) = self.resolve(field) {
                if column != field {
                    return self.category(&column);
                }
            }
            return lake_field_universe()
                .iter()
                .find(|candidate| candidate.name == field)
                .map(|candidate| candidate.category)
                .unwrap_or(FieldCategory::Custom);
        }
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
        if self.is_lake_1_9() {
            if let FieldResolution::ExplicitColumn(column) = self.resolve(field) {
                if column != field {
                    return self.entity_type(&column);
                }
            }
        }
        let fields = if self.is_lake_1_9() {
            lake_field_universe()
        } else {
            &registry().fields
        };
        fields
            .iter()
            .find(|f| f.name == field)
            .and_then(|f| f.entity_type)
    }

    fn default_table_fields(&self) -> &[&str] {
        if self.is_lake_1_9() {
            OCSF_1_9_DEFAULT_TABLE_FIELDS
        } else {
            OCSF_DEFAULT_TABLE_FIELDS
        }
    }

    fn priority_fields(&self) -> &[&str] {
        if self.is_lake_1_9() {
            OCSF_1_9_PRIORITY_FIELDS
        } else {
            OCSF_PRIORITY_FIELDS
        }
    }

    fn core_fields(&self) -> &[&str] {
        if self.is_lake_1_9() {
            OCSF_1_9_CORE_FIELDS
        } else {
            &["id", "timestamp", "message", "source_type"]
        }
    }

    fn entity_extraction_order(&self) -> &[(EntityRole, &str)] {
        if self.is_lake_1_9() {
            OCSF_1_9_ENTITY_EXTRACTION_ORDER
        } else {
            OCSF_ENTITY_EXTRACTION_ORDER
        }
    }

    fn risk_entity_default(&self) -> Option<&str> {
        // OCSF has no `risk_entity` column; the default initiator is the source IP.
        Some("src_endpoint.ip")
    }

    fn enrichment_mode(&self) -> EnrichmentMode {
        self.enrichment_mode
    }

    fn udm_column_sql(&self, udm_field: &str) -> Option<String> {
        if self.is_lake_1_9() {
            return None;
        }
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
        if !self.is_lake_1_9() {
            if let Some(col) = class_split_column(udm_field) {
                return Some(crate::query::escape_identifier(col));
            }
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
        if self.is_lake_1_9() {
            return self
                .class_split_source_fields(udm_field)
                .map(|(primary, fallback)| {
                    let p = crate::query::escape_identifier(primary);
                    let f = crate::query::escape_identifier(fallback);
                    let present = match self.field_type(primary) {
                        Some(FieldType::Array) => format!("notEmpty({p})"),
                        Some(FieldType::Long | FieldType::Integer) => format!("{p} != 0"),
                        _ => format!("{p} != ''"),
                    };
                    format!("if({present}, {p}, {f})")
                });
        }
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

    fn class_split_source_fields(&self, udm_field: &str) -> Option<(&'static str, &'static str)> {
        if self.is_lake_1_9() {
            return match normalize_field_name(udm_field) {
                "process_hash" => Some((
                    "process.file.hashes.value",
                    "actor.process.file.hashes.value",
                )),
                "user_domain" => Some(("user.domain", "actor.user.domain")),
                // NAN-3242: `service_name` (rewritten to `cloud_service`) means the
                // API service on API Activity rows and the OTLP resource
                // `service.name` on the generic lane's OTLP logs, which carry it on
                // `metadata.product.feature.name` (class 0 has no service slot).
                "cloud_service" | "service_name" => {
                    Some(("api.service.name", "metadata.product.feature.name"))
                }
                normalized => class_split_udm_field(normalized).map(|(p, f, _)| (p, f)),
            };
        }
        class_split_udm_field(udm_field).map(|(primary, fallback, _)| (primary, fallback))
    }

    fn class_split_column(&self, udm_field: &str) -> Option<String> {
        // NAN-1333: the indexed unified column that materializes the
        // `class_split_value_sql` union, so WHERE / GROUP BY / SORT / raw-SQL on a
        // split concept reference a plain indexed column (words-index prunable)
        // rather than the skip-index-opaque inline `if(...)`. `None` for non-split
        // concepts (caller keeps single-column / value-pick resolution).
        if self.is_lake_1_9() {
            None
        } else {
            class_split_column(udm_field).map(|c| c.to_string())
        }
    }

    fn display_field_name(&self, udm_field: &str) -> Option<String> {
        if self.is_lake_1_9() {
            return None;
        }
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
        if self.is_lake_1_9() && col == "activity_id" {
            return Some(EnumIntMapping::LabelColumn("activity_name"));
        }
        reg.enum_label_columns
            .get(&col)
            .map(|sibling| EnumIntMapping::LabelColumn(sibling.as_str()))
    }

    fn enrichment_field(&self, semantic: EnrichmentKind) -> Option<FieldResolution> {
        let col = match semantic {
            EnrichmentKind::SrcCountry => "src_endpoint.location.country",
            EnrichmentKind::SrcAsn => "src_endpoint.autonomous_system.number",
            EnrichmentKind::DestCountry => "dst_endpoint.location.country",
            EnrichmentKind::DestAsn => "dst_endpoint.autonomous_system.number",
            EnrichmentKind::IocMatch if self.is_lake_1_9() => "ioc_src_ip_threat_type",
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
        if self.is_lake_1_9() {
            "time"
        } else {
            OCSF_TIMESTAMP_EXPR
        }
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
    SLICE.get_or_init(|| {
        registry()
            .materialized
            .iter()
            .map(|s| leak_str(s))
            .collect()
    })
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

    /// NAN-2361: the advertised lake universe must stay a SUBSET of what the
    /// tokenizer can produce and the resolver can turn into a physical column.
    ///
    /// The failure this pins is the NAN-2379 shape: a name published by
    /// `/api/schema/fields` that no query can address. The tokenizer drops the
    /// `[]` repeated marker, so the check runs on the stripped spelling — the
    /// exact string a parsed query carries.
    #[test]
    fn lake_field_universe_is_a_subset_of_what_a_query_can_address() {
        let profile = OcsfProfile::lake_1_9();
        assert!(!profile.fields().is_empty());
        for field in profile.fields() {
            let addressable = field.name.replace("[]", "");
            let canonical = profile.canonicalize(&addressable).into_owned();
            assert!(
                profile.is_known_field(&addressable),
                "advertised lake field {} is rejected by field validation",
                field.name,
            );
            assert!(
                matches!(
                    profile.resolve(&addressable),
                    FieldResolution::ExplicitColumn(_)
                ),
                "advertised lake field {} does not resolve to a physical column",
                field.name,
            );
            assert!(
                !addressable.contains(['[', ']', '=']),
                "advertised lake field {} is not tokenizable as a field name",
                field.name,
            );
            assert!(
                profile.field_type(&canonical).is_some(),
                "advertised lake field {} has no resolvable type",
                field.name,
            );
        }
    }

    /// Every path `lake_1_9_column` accepts is queryable, so every one of them
    /// must also be DISCOVERABLE. Before NAN-2361 the universe was the 1.8
    /// promotion manifest alone, which hid the entire ATT&CK / evidence /
    /// affected-resource surface behind a name an analyst had to already know.
    #[test]
    fn lake_field_universe_advertises_every_accepted_native_path() {
        let profile = OcsfProfile::lake_1_9();
        let advertised: HashSet<&str> = profile.fields().iter().map(|f| f.name).collect();
        for path in OCSF_1_9_NATIVE_FIELDS
            .iter()
            .chain(OCSF_1_9_STRING_ARRAY_FIELDS.iter())
            .copied()
        {
            // The spill root is bookkeeping and the object roots are addressed
            // through their leaves — both are deliberate exclusions.
            if path == OCSF_TAIL_COLUMN || path == "metadata.transformation_info_list" {
                assert!(!advertised.contains(path), "{path} must stay unadvertised");
                continue;
            }
            assert!(
                advertised.contains(path) || advertised.contains(format!("{path}[]").as_str()),
                "accepted lake path {path} is queryable but not advertised",
            );
        }
        // The paths this change actually unhides — the ranked gaps from the
        // NAN-2361 measurement that the serving generation already carries.
        for path in [
            "finding_info.attacks.technique.uid",
            "finding_info.attacks.tactic.uid",
            "evidences.name",
            "evidences.query.hostname",
            "evidences.url.url_string",
            "resources.ip",
            "resources.user.name",
            "resources.user.uid",
            "vulnerabilities.cve.uid",
            "severity",
            "status_detail",
            "risk_level",
        ] {
            assert!(advertised.contains(path), "{path} must be advertised");
        }
    }

    /// Advertising a field also advertises its metadata; a lake-only path with
    /// no manifest row must not silently land in `Custom`/`None`.
    #[test]
    fn lake_only_paths_carry_category_and_entity_metadata() {
        let profile = OcsfProfile::lake_1_9();
        assert_eq!(
            profile.category("finding_info.attacks.technique.uid"),
            FieldCategory::Alerts
        );
        assert_eq!(profile.category("evidences.name"), FieldCategory::Alerts);
        assert_eq!(profile.category("metadata.log_name"), FieldCategory::System);
        assert_eq!(
            profile.category("enrichments.provider"),
            FieldCategory::Enrichment
        );
        assert_eq!(
            profile.entity_type("resources.user.name"),
            Some(EntityType::User)
        );
        assert_eq!(profile.entity_type("resources.ip"), Some(EntityType::Ip));
        assert_eq!(
            profile.entity_type("evidences.url.url_string"),
            Some(EntityType::Url)
        );
        // Array-typed lake paths keep array predicate semantics once advertised.
        assert_eq!(
            profile.field_type("finding_info.attacks.technique.uid"),
            Some(FieldType::Array)
        );
        assert!(profile.is_string_array_field("finding_info.attacks.technique.uid"));
    }

    /// The ClickHouse-1.8 layout is untouched: its universe stays the manifest
    /// column set, so no OCSF-1.9-only path leaks into a deployment whose DDL
    /// has no such column.
    #[test]
    fn clickhouse_1_8_universe_is_unchanged_by_the_lake_universe() {
        let profile = OcsfProfile::new();
        let advertised: HashSet<&str> = profile.fields().iter().map(|f| f.name).collect();
        for path in [
            "finding_info.attacks.technique.uid",
            "evidences.name",
            "resources.user.name",
            "resources.ip",
        ] {
            assert!(
                !advertised.contains(path),
                "{path} must not be advertised by the ClickHouse 1.8 layout",
            );
        }
    }

    #[test]
    fn lake_product_aliases_share_resolution_and_types() {
        let profile = OcsfProfile::lake_1_9();
        for (alias, column) in &registry().udm_to_lake {
            assert!(profile.is_known_field(alias), "{alias} -> {column}");
            assert!(
                matches!(profile.resolve(alias), FieldResolution::ExplicitColumn(_)),
                "{alias}"
            );
            assert!(
                profile.field_type(alias).is_some(),
                "missing type: {alias} -> {column}"
            );
        }
        for (alias, column) in [
            ("user", "user.name"),
            ("user_domain", "user.domain"),
            ("src_ip", "src_endpoint.ip"),
            ("dest_ip", "dst_endpoint.ip"),
            ("src_host", "src_endpoint.hostname"),
            ("dest_host", "dst_endpoint.hostname"),
            ("src_port", "src_endpoint.port"),
            ("dest_port", "dst_endpoint.port"),
            ("process_name", "process.name"),
            ("command_line", "process.cmd_line"),
            ("parent_command_line", "actor.process.cmd_line"),
            ("process_hash", "process.file.hashes.value"),
            ("file_path", "file.path"),
            ("file_hash", "file.hashes.value"),
            ("auth_result", "status_id"),
            ("message", "message"),
            ("timestamp", "time"),
            ("source_type", "metadata.log_source"),
            ("sourcetype", "metadata.log_source"),
            ("user_identity_email", "unmapped.user_identity_email"),
        ] {
            assert_eq!(
                profile.resolve(alias),
                FieldResolution::ExplicitColumn(column.into()),
                "{alias}"
            );
            assert_eq!(
                profile.field_type(alias),
                profile.field_type(column),
                "{alias}"
            );
        }
        assert_eq!(profile.field_type("risk_score"), Some(FieldType::Integer));
        assert_eq!(profile.entity_type("src_host"), Some(EntityType::Host));
        assert_eq!(profile.entity_type("src_hostname"), Some(EntityType::Host));
        assert_eq!(profile.category("src_ip"), profile.category("src_endpoint.ip"));
        assert!(profile.is_string_array_field("process_hash"));
        assert!(profile.is_string_array_field("file_hash"));
        assert!(!profile.is_known_field("user_identity_emali"));
        // Native attributes retain their meanings even if the old manifest
        // associates that UDM spelling with another taxonomy column.
        assert_eq!(
            profile.resolve("severity"),
            FieldResolution::ExplicitColumn("severity".into())
        );
        assert!(matches!(
            profile.enum_int_mapping("event_type"),
            Some(EnumIntMapping::LabelColumn("activity_name"))
        ));
    }

    /// NAN-3003: the platform stamps lean ingest admits on source rows are
    /// queryable by name (not only through the tail namespace).
    #[test]
    fn lake_1_9_resolves_the_platform_metadata_stamps() {
        let p = OcsfProfile::lake_1_9();
        for field in ["metadata.nano_parser_bundle_sha256", "metadata.nano_credential_id"] {
            assert_eq!(
                p.resolve(field),
                FieldResolution::ExplicitColumn(field.to_string()),
                "lake field {field}",
            );
            assert!(p.is_known_field(field), "lake field {field}");
            assert_eq!(p.field_type(field), Some(FieldType::String), "{field}");
        }
    }

    #[test]
    fn lake_1_9_accepts_only_canonical_fields_and_explicit_unmapped_paths() {
        let p = OcsfProfile::lake_1_9();
        for field in [
            "metadata.uid",
            "metadata.log_source",
            "metadata.original_event_uid",
            "time",
            "raw_data_size",
            "activity_name",
            "category_name",
            "src_endpoint.ip",
            "finding_info.analytic.name",
            "finding_info.attacks.technique.uid",
            "resources.hostname",
            "observables.value",
        ] {
            assert_eq!(
                p.resolve(field),
                FieldResolution::ExplicitColumn(field.to_string()),
                "lake field {field}",
            );
            assert!(p.is_known_field(field), "lake field {field}");
        }
        assert_eq!(
            p.resolve("unmapped.vendor_key"),
            FieldResolution::ExplicitColumn("unmapped.vendor_key".to_string())
        );
        for legacy in [
            "time_dt",
            "event_bytes",
            "activity",
            "ext.vendor_key",
            "vendor_key",
        ] {
            assert_eq!(p.resolve(legacy), FieldResolution::Unknown, "{legacy}");
            assert!(!p.is_known_field(legacy), "{legacy}");
            assert_eq!(p.canonicalize(legacy).as_ref(), legacy);
        }
        assert_eq!(p.timestamp_expr(), "time");
        assert!(!p.is_uuid_field("id"));
        assert!(p.materialized_columns().is_empty());
        assert_eq!(p.class_split_column("user"), None);
        assert_eq!(p.udm_column_sql("src_ip"), None);
        assert_eq!(p.core_fields(), OCSF_1_9_CORE_FIELDS);
        assert_eq!(
            p.field_type("finding_info.analytic.name"),
            Some(FieldType::String)
        );
        assert_eq!(p.field_type("resources.hostname"), Some(FieldType::Array));
        assert!(p.is_string_array_field("finding_info.data_sources"));

        let clickhouse = OcsfProfile::new();
        assert_eq!(
            clickhouse.resolve("source_type"),
            FieldResolution::ExplicitColumn("source_type".to_string())
        );
        assert_eq!(clickhouse.timestamp_expr(), "timestamp");
        assert!(clickhouse.is_uuid_field("id"));
        assert!(clickhouse.class_split_column("user").is_some());
    }

    /// NAN-2994: a lean-lake cell tenant's front-door profile carries NO
    /// snapshot inventory (query[T] owns the part schema), so canonical OCSF
    /// 1.9 leaves must resolve from the OCSF contract itself, not from hand
    /// lists. `metadata.event_code` and `action_id` 400'd on lean while being
    /// stored on every Windows / proxy row.
    /// NAN-3422: a stored producer key that is not a query identifier
    /// (`unmapped.@timestamp` from Winlogbeat) is dropped from the profile
    /// instead of refusing the whole inventory; legacy namespaces still refuse.
    #[test]
    fn nan3422_snapshot_profile_drops_unaddressable_leaves() {
        let profile = OcsfProfile::try_lake_1_9_with_snapshot_field_types(BTreeMap::from([
            ("unmapped.@timestamp".to_string(), FieldType::String),
            ("unmapped.@metadata.beat".to_string(), FieldType::String),
            ("unmapped.Event-ID".to_string(), FieldType::String),
            ("unmapped..empty".to_string(), FieldType::String),
            ("unmapped.winlog.event_id".to_string(), FieldType::Integer),
        ]))
        .expect("odd producer keys must not refuse the inventory");
        assert_eq!(profile.field_type("unmapped.winlog.event_id"), Some(FieldType::Integer));
        assert!(!profile.lake_snapshot_field_types.keys().any(|path| path.contains('@') || path.contains('-')));
        assert!(OcsfProfile::try_lake_1_9_with_snapshot_field_types(BTreeMap::from([(
            "ext.legacy".to_string(),
            FieldType::String,
        )]))
        .is_err());
        assert!(!OcsfProfile::is_admissible_snapshot_field_path("unmapped.@timestamp"));
    }

    #[test]
    fn nan2994_inventoryless_lake_profile_accepts_every_ocsf_1_9_leaf() {
        let p = OcsfProfile::try_lake_1_9_with_snapshot_field_types(BTreeMap::new()).unwrap();
        for (field, field_type) in [
            ("metadata.event_code", FieldType::String),
            ("action_id", FieldType::Integer),
            ("disposition_id", FieldType::Integer),
            ("logon_type_id", FieldType::Integer),
            ("dst_endpoint.port", FieldType::Integer),
            ("traffic.bytes_in", FieldType::Long),
            ("is_remote", FieldType::Boolean),
            ("metadata.product.vendor_name", FieldType::String),
            // Recursive objects resolve by walking, with no depth bound.
            (
                "actor.process.parent_process.parent_process.cmd_line",
                FieldType::String,
            ),
            // A leaf under a repeated object is an array at rest.
            ("metadata.profiles", FieldType::Array),
            ("module.file.signatures.algorithm_id", FieldType::Array),
        ] {
            assert_eq!(
                p.resolve(field),
                FieldResolution::ExplicitColumn(field.to_string()),
                "{field}"
            );
            assert!(p.is_known_field(field), "{field}");
            assert_eq!(p.field_type(field), Some(field_type), "{field}");
        }
        for rejected in [
            // Objects are not leaves (NAN-2379).
            "metadata",
            "actor.process",
            // `json_t` keys are producer-defined: only an inventory vouches.
            "enrichments.data.host_count",
            // Not OCSF.
            "metadata.not_an_attribute",
            "event_code",
            // Datetime-profile siblings are not stored; `time_dt` stays legacy.
            "time_dt",
            "metadata.logged_time_dt",
        ] {
            assert_eq!(p.resolve(rejected), FieldResolution::Unknown, "{rejected}");
            assert!(!p.is_known_field(rejected), "{rejected}");
        }
        // A snapshot type still wins over the contract's.
        let typed = OcsfProfile::try_lake_1_9_with_snapshot_field_types(BTreeMap::from([(
            "metadata.event_code".to_string(),
            FieldType::Integer,
        )]))
        .unwrap();
        assert_eq!(
            typed.field_type("metadata.event_code"),
            Some(FieldType::Integer)
        );
    }

    /// NAN-2994: every leaf of a real stored lake event schema (the live
    /// tenant read schema fixture) is queryable, both through the
    /// inventory-less front-door profile and through the snapshot-backed
    /// profile query[T]'s compiler builds from the part schema. The only
    /// leaves the front door cannot vouch for are producer-defined ones
    /// (`unmapped.*` is accepted by namespace; `enrichments.data.*` is a
    /// `json_t` bag and needs the inventory).
    #[test]
    fn nan2994_every_stored_lake_leaf_is_queryable() {
        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../../../nanosiem-lake-worker/tests/fixtures/nan2469-live-tail-read-schema.json"
        ))
        .unwrap();
        let paths: Vec<String> =
            serde_json::from_value(fixture["available_paths"].clone()).unwrap();
        assert!(paths.iter().any(|path| path == "metadata.event_code"));
        assert!(paths.iter().any(|path| path == "action_id"));

        let front_door =
            OcsfProfile::try_lake_1_9_with_snapshot_field_types(BTreeMap::new()).unwrap();
        let inventory = OcsfProfile::try_lake_1_9_with_snapshot_field_types(
            paths
                .iter()
                .map(|path| (path.clone(), FieldType::String))
                .collect(),
        )
        .unwrap();
        let mut front_door_rejects = Vec::new();
        for path in &paths {
            let query = crate::query::parse_query(&format!("{path}=\"x\"")).unwrap();
            assert!(
                crate::query::validate_query_fields_with_profile(&query, Some(&inventory))
                    .is_empty(),
                "inventory profile rejects stored leaf {path}"
            );
            if !crate::query::validate_query_fields_with_profile(&query, Some(&front_door))
                .is_empty()
            {
                front_door_rejects.push(path.as_str());
            }
        }
        assert!(
            front_door_rejects
                .iter()
                .all(|path| path.starts_with("enrichments.data.")),
            "front door rejects stored canonical leaves: {front_door_rejects:?}"
        );
    }

    #[test]
    fn lake_1_9_uses_manifest_types_for_exact_unmapped_leaves() {
        let profile = OcsfProfile::try_lake_1_9_with_unmapped_field_types(BTreeMap::from([
            ("unmapped.score".to_string(), FieldType::Float),
            ("unmapped.blocked".to_string(), FieldType::Boolean),
            ("unmapped.tags".to_string(), FieldType::Array),
        ]))
        .unwrap();

        assert_eq!(profile.field_type("unmapped.score"), Some(FieldType::Float));
        assert!(profile.is_numeric_field("unmapped.score"));
        assert_eq!(
            profile.field_type("unmapped.blocked"),
            Some(FieldType::Boolean)
        );
        assert!(profile.is_string_array_field("unmapped.tags"));
        assert_eq!(
            profile.resolve("unmapped.score"),
            FieldResolution::ExplicitColumn("unmapped.score".to_string())
        );
        assert!(
            OcsfProfile::try_lake_1_9_with_unmapped_field_types(BTreeMap::from([(
                "src_ip".to_string(),
                FieldType::String,
            )]))
            .is_err()
        );

        let evolved = OcsfProfile::try_lake_1_9_with_snapshot_field_types(BTreeMap::from([
            ("ai_operation.name".to_string(), FieldType::String),
            ("ai_operation.tools".to_string(), FieldType::Array),
        ]))
        .unwrap();
        assert!(evolved.is_known_field("ai_operation.name"));
        assert_eq!(
            evolved.resolve("ai_operation.name"),
            FieldResolution::ExplicitColumn("ai_operation.name".to_string())
        );
        assert!(evolved.is_string_array_field("ai_operation.tools"));
    }

    #[test]
    fn lean_physical_prevalence_stamp_takes_priority_over_legacy_array_derivation() {
        let profile = OcsfProfile::try_lake_1_9_with_snapshot_field_types(BTreeMap::from([
            ("prevalence_dest_ip".to_string(), FieldType::Integer),
            ("prevalence_file_hash".to_string(), FieldType::Integer),
            ("prevalence_min".to_string(), FieldType::Integer),
            ("enrichments.data.host_count".to_string(), FieldType::Array),
            ("enrichments.data.host_count_saturated".to_string(), FieldType::Array),
        ])).unwrap();
        assert!(profile.is_known_field("prevalence_dest_ip"));
        assert!(profile.is_known_field("prevalence_file_hash"));
        assert!(profile.is_known_field("prevalence_min"));
        assert!(profile.source_computed_column("prevalence_dest_ip").is_none());
    }

    fn open_core_stamped_inventory() -> BTreeMap<String, FieldType> {
        [
            "enrichments.name",
            "enrichments.provider",
            "enrichments.value",
            "enrichments.data.host_count",
            "enrichments.data.host_count_saturated",
            "file.hashes.value",
            "process.file.hashes.value",
        ]
        .into_iter()
        .map(|name| (name.to_string(), FieldType::Array))
        .chain(
            ["dst_endpoint.ip", "dst_endpoint.hostname", "query.hostname"]
                .into_iter()
                .map(|name| (name.to_string(), FieldType::String)),
        )
        .collect()
    }

    /// NAN-3451: every scalar `prevalence_*` field resolves on an open-core
    /// lake as an integer computed from `enrichments[]`, reading only the
    /// stamp arrays and that column's own artifact source(s).
    #[test]
    fn open_core_lake_derives_every_prevalence_scalar_from_enrichments() {
        let profile =
            OcsfProfile::try_lake_1_9_with_snapshot_field_types(open_core_stamped_inventory())
                .unwrap();
        let stamp = [
            "enrichments.data.host_count",
            "enrichments.data.host_count_saturated",
            "enrichments.name",
            "enrichments.provider",
            "enrichments.value",
        ];
        for (field, sources) in [
            ("prevalence_file_hash", vec!["file.hashes.value"]),
            ("prevalence_process_hash", vec!["process.file.hashes.value"]),
            (
                "prevalence_dest_domain",
                vec!["dst_endpoint.hostname", "query.hostname"],
            ),
            ("prevalence_dest_ip", vec!["dst_endpoint.ip"]),
            (
                "prevalence_min",
                vec![
                    "dst_endpoint.hostname",
                    "dst_endpoint.ip",
                    "file.hashes.value",
                    "process.file.hashes.value",
                    "query.hostname",
                ],
            ),
        ] {
            assert!(profile.is_known_field(field), "{field}");
            assert_eq!(profile.field_type(field), Some(FieldType::Integer), "{field}");
            assert_eq!(
                profile.resolve(field),
                FieldResolution::ExplicitColumn(field.to_string())
            );
            let (sql, inputs) = profile
                .source_computed_column(field)
                .unwrap_or_else(|| panic!("{field} is not derived"));
            assert!(sql.contains("p = 'nano'"), "{field}: {sql}");
            let mut expected = stamp.to_vec();
            expected.extend(sources);
            expected.sort_unstable();
            assert_eq!(inputs, expected, "{field}");
        }
    }

    /// NAN-3451: lean keeps its physical ingest-time columns for every scalar,
    /// and an unstamped open-core snapshot keeps all five unknown (#4644).
    #[test]
    fn prevalence_scalars_never_shadow_lean_columns_and_need_the_stamp() {
        let mut lean = open_core_stamped_inventory();
        for field in super::super::lake_prevalence::SCALARS {
            lean.insert(field.to_string(), FieldType::Integer);
        }
        let lean = OcsfProfile::try_lake_1_9_with_snapshot_field_types(lean).unwrap();
        let unstamped = OcsfProfile::try_lake_1_9_with_snapshot_field_types(BTreeMap::from([(
            "dst_endpoint.ip".to_string(),
            FieldType::String,
        )]))
        .unwrap();
        for field in super::super::lake_prevalence::SCALARS {
            assert!(lean.source_computed_column(field).is_none(), "{field}");
            assert_eq!(
                lean.resolve(field),
                FieldResolution::ExplicitColumn(field.to_string())
            );
            assert_eq!(unstamped.resolve(field), FieldResolution::Unknown, "{field}");
            assert!(unstamped.source_computed_column(field).is_none(), "{field}");
        }
    }

    /// NAN-1303: display_field_name gives the native OCSF column a result row
    /// should be keyed by for a UDM-semantic concept (asset stream renders native).
    #[test]
    fn display_field_name_maps_udm_concept_to_native_ocsf_column() {
        let p = OcsfProfile::new();
        assert_eq!(
            p.display_field_name("src_ip").as_deref(),
            Some("src_endpoint.ip")
        );
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
        // Concept OCSF doesn't map → None (caller falls back).
        assert_eq!(p.display_field_name("parent_process_name"), None);
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
    fn lake_1_9_entity_extraction_uses_canonical_repeated_hash_values() {
        let p = OcsfProfile::lake_1_9();
        let fields: Vec<_> = p
            .entity_extraction_order()
            .iter()
            .map(|(_, field)| *field)
            .collect();

        assert!(fields.contains(&"file.hashes.value"));
        assert!(fields.contains(&"process.file.hashes.value"));
        assert!(fields.contains(&"actor.process.file.hashes.value"));
        assert!(fields.contains(&"device.hostname"));
        assert!(!fields.iter().any(|field| field.ends_with(".sha256")));
        for field in fields {
            assert_eq!(
                p.resolve(field),
                FieldResolution::ExplicitColumn(field.to_string()),
                "entity extraction path must be queryable in the strict lake profile: {field}",
            );
        }
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
        // An unpromoted attribute lands in the `unmapped` spill tail (NAN-1443;
        // was the full `event` column before the chop). At runtime it returns
        // NULL unless the producer placed it under `unmapped` — the
        // promote-to-query tradeoff.
        assert_eq!(
            p.resolve("actor.process.parent_process.name"),
            FieldResolution::JsonPath {
                col: "unmapped".into(),
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
        // event.<unpromoted> → the stripped path in the spill tail.
        assert_eq!(
            p.resolve("event.actor.process.parent_process.name"),
            FieldResolution::JsonPath {
                col: "unmapped".into(),
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
        for flat in [
            "class_uid",
            "message",
            "source_type",
            "timestamp",
            "severity",
        ] {
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

        let lake = OcsfProfile::lake_1_9();
        assert_eq!(lake.field_type("status_code"), Some(FieldType::String));
        assert_eq!(lake.field_type("status_detail"), Some(FieldType::String));
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
        // The `time_dt` ALIAS must not be in the CTE re-add list.
        assert!(!p.materialized_columns().contains(&"time_dt"));
        // The DEFAULT sort-key columns (NAN-1334) ARE in `SELECT *`, so they must
        // NOT be re-added — doing so would duplicate-project (CH Code 352).
        for c in OCSF_DEFAULT_SORTKEY_COLUMNS {
            assert!(
                !p.materialized_columns().contains(c),
                "DEFAULT sort-key column {c} must be excluded from the CTE re-add list",
            );
            // Still a real, known, promoted field — just DEFAULT not MATERIALIZED.
            assert!(p.is_known_field(c));
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
        assert_eq!(
            p.udm_column_sql("src_host").as_deref(),
            Some("src_host_unified")
        );
        assert_eq!(
            p.udm_column_sql("src_ip").as_deref(),
            Some("\"src_endpoint.ip\"")
        );
        // NAN-1276 class-split resolution: OCSF puts the primary process in the
        // top-level `process.*` (Process Activity 1007) but in `actor.process.*`
        // on Module/Network/File/DNS/Registry. NAN-1333 routes these to their
        // indexed unified columns (same union, words-index prunable).
        assert_eq!(
            p.udm_column_sql("process_name").as_deref(),
            Some("process_name_unified")
        );
        assert_eq!(
            p.udm_column_sql("command_line").as_deref(),
            Some("command_line_unified")
        );
        assert_eq!(
            p.udm_column_sql("process_id").as_deref(),
            Some("process_id_unified")
        );
        // `user` spans Authentication subject (`user.name`) vs initiator
        // (`actor.user.name`); NAN-1333 → indexed unified column.
        assert_eq!(p.udm_column_sql("user").as_deref(), Some("user_unified"));
        // parent_command_line stays the parent column (not class-split).
        assert_eq!(
            p.udm_column_sql("parent_command_line").as_deref(),
            Some("\"actor.process.cmd_line\"")
        );
        assert_eq!(
            p.udm_column_sql("dest_ip").as_deref(),
            Some("\"dst_endpoint.ip\"")
        );
        // NAN-1241/1254: the additional UDM-semantic fields that the findings,
        // prevalence-artifact, case-extraction and GDPR fixes resolve through this
        // map. `file_hash` flattens the OCSF `file.hashes` array to a scalar
        // `file.hashes.sha256` column — locking it here guards the artifact/finding
        // hash lookups from silently regressing to the array form.
        assert_eq!(
            p.udm_column_sql("dest_host").as_deref(),
            Some("\"dst_endpoint.hostname\"")
        );
        assert_eq!(
            p.udm_column_sql("file_hash").as_deref(),
            Some("\"file.hashes.sha256\"")
        );
        assert_eq!(
            p.udm_column_sql("file_name").as_deref(),
            Some("\"file.name\"")
        );
        assert_eq!(
            p.udm_column_sql("file_path").as_deref(),
            Some("\"file.path\"")
        );
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
        assert_eq!(
            ocsf.udm_column_sql("src_host").as_deref(),
            Some("src_host_unified")
        );
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
        assert_eq!(
            p.enum_int_mapping("status_id"),
            p.enum_int_mapping("auth_result")
        );
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
        for f in [
            "status",
            "severity",
            "action",
            "src_ip",
            "src_endpoint.port",
            "nonexistent",
        ] {
            assert!(
                p.enum_int_mapping(f).is_none(),
                "{f} must have no enum mapping"
            );
        }
    }

    #[test]
    fn search_column_companion_naming() {
        // is_search_col stems get a `.search` companion; the DDL realizes them.
        assert!(registry().search_stems.contains("message"));
        assert!(registry().search_stems.contains("actor.process.cmd_line"));
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
}


/// NAN-3492: a worker-served (hot-swapped) schema only ever ADDS fields to
/// the profile a lake process resolves at boot. Search, API and jobs re-pin to
/// it at runtime (#5974), so a field the boot profile accepted and the
/// refreshed one refused would turn a working query into a 400 mid-flight.
#[cfg(test)]
mod refreshed_schema_tests {
    use super::*;
    use crate::schema::SchemaProfile;

    fn refreshed(fields: &[(&str, FieldType)]) -> OcsfProfile {
        OcsfProfile::try_lake_1_9_with_snapshot_field_types(
            fields.iter().map(|(name, ty)| (name.to_string(), *ty)).collect(),
        )
        .unwrap()
    }

    fn errors(profile: &OcsfProfile, npl: &str) -> Vec<String> {
        let query = crate::query::parse_query(npl).unwrap();
        crate::query::validate_query_fields_with_profile(&query, Some(profile))
            .into_iter()
            .map(|error| error.message)
            .collect()
    }

    #[test]
    fn refreshed_schema_keeps_every_field_and_alias_the_boot_schema_accepted() {
        let boot = OcsfProfile::lake_1_9();
        let mut names: Vec<String> = boot.fields().iter().map(|f| f.name.to_string()).collect();
        names.extend(crate::udm::UdmField::all().iter().map(|f| f.column_name().to_string()));
        names.extend(["source_type", "sourcetype", "metadata.log_source", "risk_score"].map(String::from));
        // A sparse inventory (one source's leaves) and one without the source
        // column at all: neither may narrow what the boot profile accepted.
        for refreshed in [
            refreshed(&[("metadata.log_source", FieldType::String), ("class_uid", FieldType::Integer)]),
            refreshed(&[("class_uid", FieldType::Integer)]),
        ] {
            let lost: Vec<_> =
                names.iter().filter(|n| boot.is_known_field(n) && !refreshed.is_known_field(n)).collect();
            assert!(lost.is_empty(), "the refreshed schema dropped {lost:?}");
            for npl in [
                "metadata.log_source=findings",
                "source_type=findings",
                "sourcetype=findings",
                "metadata.log_source=risk",
                "source_type=risk",
                "metadata.log_source IN (risk, signals)",
            ] {
                assert_eq!(errors(&refreshed, npl), Vec::<String>::new(), "{npl}");
                assert_eq!(errors(&boot, npl), Vec::<String>::new(), "{npl}");
            }
        }
    }

    /// Bare `log_source` is not a source spelling on the lake, before or after
    /// a refresh: the source field is `metadata.log_source` (aliases
    /// `source_type` / `sourcetype`).
    #[test]
    fn bare_log_source_is_refused_by_boot_and_refreshed_schema_alike() {
        let refreshed = refreshed(&[("metadata.log_source", FieldType::String)]);
        for profile in [OcsfProfile::lake_1_9(), refreshed] {
            let errors = errors(&profile, "log_source=findings");
            assert!(errors.iter().any(|e| e.contains("Unknown canonical OCSF field 'log_source'")), "{errors:?}");
        }
    }
}
