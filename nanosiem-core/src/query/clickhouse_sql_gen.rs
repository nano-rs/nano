// SPDX-License-Identifier: AGPL-3.0-or-later

//! SQL Generator for converting piped query AST to ClickHouse SQL
//!
//! This module generates ClickHouse SQL from the piped query AST, using:
//! - hasToken() for simple keyword searches (leverages tokenbf_v1 bloom filter index)
//! - position() for keywords with special chars like dots/slashes (cmd.exe, 192.168.1.1)
//! - JSONExtract functions for metadata field access
//! - ClickHouse-specific time bucketing functions (toStartOfMinute, etc.)
//! - CTEs for multi-stage piped queries
//! - ClickHouse aggregation functions
//!
//! Submodules:
//! - `search_expr`: Search expression → WHERE clause generation
//! - `commands`: Command SQL dispatch (match statement)
//! - `commands_advanced`: Complex command helpers (streamstats, sequence, anomaly, etc.)
//! - `aggregation`: Stats and timechart SQL generation
//! - `identity`: resolve_identity ASOF JOIN generation
//! - `helpers`: Standalone helper functions (escaping, field normalization, etc.)
//! - `field_analysis`: Field requirement analysis for query optimization (existing)
//! - `eval_functions`: Eval expression → SQL conversion (existing)

mod aggregation;
mod commands;
mod commands_advanced;
mod eval_functions;
// pub(crate): `query::validation::derived_fields` pins its registered
// aggregation reference names against `collect_agg_reference_aliases`
// (NAN-1396 drift test).
pub(crate) mod field_analysis;
mod helpers;
// pub(crate): `query::validation::derived_fields` mirrors the resolve_identity
// output registration from the IDENTITY_*_FIELDS tables (NAN-1380).
pub(crate) mod identity;
// pub: the OTLP dataset selector + trace/metrics fetch helpers are called by the
// search/api layer to target the `otel_spans`/`otel_metrics` tables (NAN-1528).
pub mod otel;
pub(crate) mod search_expr;

// Re-export helpers so submodules and external code can access them
pub(crate) use helpers::*;

use super::ast::*;
use super::sql_gen::{SqlGenError, TimeRange};
use crate::schema::{FieldResolution, SchemaProfile, UdmProfile};
use once_cell::sync::Lazy;
use std::collections::HashSet;
use std::sync::Arc;
use std::sync::RwLock;
use std::fmt::Write;

/// Default limit for subsearches — prevents memory exhaustion from
/// unbounded JOINs and APPENDs.
pub(crate) const SUBSEARCH_RESULT_LIMIT: usize = 10_000;

/// Absolute maximum a user can set maxout to (safety valve against OOM)
const SUBSEARCH_RESULT_LIMIT_MAX: usize = 100_000;

/// Resolve the effective subsearch limit from an optional maxout parameter.
/// Clamps to SUBSEARCH_RESULT_LIMIT_MAX to prevent OOM.
pub(crate) fn resolve_subsearch_limit(maxout: Option<usize>) -> usize {
    maxout
        .unwrap_or(SUBSEARCH_RESULT_LIMIT)
        .min(SUBSEARCH_RESULT_LIMIT_MAX)
}

/// Explicit columns in the hybrid schema (stored as direct columns with bloom filters)
/// All other UDM fields are stored in the `ext` JSON column (extended fields)
///
/// This list should match the columns defined in clickhouse/057_hybrid_json_schema.sql
///
/// `pub(crate)` so `UdmProfile` (`crate::schema::udm`) can reference the *same*
/// slice for byte-for-byte parity rather than copying values (NAN-1244). Widening
/// visibility is non-behavioral.
pub(crate) const EXPLICIT_COLUMNS: &[&str] = &[
    // Core fields
    "id",
    "timestamp",
    "message",
    "metadata",
    "namespace",
    "source_type",
    "source",
    "ingest_time",
    "_inserted_at",
    "enrich_time",
    // Network fields
    "src_ip",
    "dest_ip",
    "src_host",
    "dest_host",
    "src_port",
    "dest_port",
    "protocol",
    "bytes_in",
    "bytes_out",
    "packets_in",
    "packets_out",
    "direction",
    "src_mac",
    "dest_mac",
    "vlan",
    // User/Identity fields
    "user",
    "src_user",
    "dest_user",
    "user_id",
    "user_name",
    "user_domain",
    "user_type",
    // Event type / Status fields
    "event_type",
    "action", // legacy synonym; kept so user-typed `action=` queries route to the
    // physical column rather than ext.action (CH alias handles the column lookup).
    // Result projections strip `action` and rename to `event_type` — see build_select_clause.
    "status",
    "status_code",
    "result",
    "severity",
    "category",
    // Authentication fields
    "auth_type",
    "auth_result",
    "session_id",
    "authentication_method",
    // OpenTelemetry trace-correlation fields (NAN-1528). Plain stored String
    // columns on `logs` (migration 141, DEFAULT ''); ingest-lowercased hex, so
    // they also join LOWERCASE_NORMALIZED_FIELDS to engage the raw-column bloom.
    "trace_id",
    "span_id",
    // Process fields
    "command_line",
    "process_name",
    "process_id",
    "process_path",
    "process_hash",
    "process_guid",
    "parent_command_line",
    "parent_process_name",
    "parent_process_id",
    "parent_process_path",
    "parent_process_guid",
    // File fields
    "file_path",
    "file_name",
    "file_hash",
    "file_size",
    "file_action",
    // Registry fields
    "registry_path",
    "registry_key_name",
    "registry_value_name",
    "registry_value_data",
    // Web/HTTP fields
    "url",
    "url_domain",
    "uri_path",
    "http_method",
    "http_user_agent",
    "http_referrer",
    "http_content_type",
    "http_status_code",
    // DNS fields
    "query",
    "query_type",
    "answer",
    "dns_answers",
    "record_type",
    // Email fields
    "sender",
    "sender_domain",
    "recipient",
    "recipient_domain",
    "subject",
    "message_id",
    // Security/Detection fields
    "signature",
    "signature_id",
    "cve",
    "mitre_technique_id",
    "rule_id",
    "rule_name",
    "vendor_product",
    // Risk/Prevalence fields
    "risk_entity",
    "risk_score",
    "risk_level",
    "prevalence_file_hash",
    "prevalence_process_hash",
    "prevalence_dest_domain",
    "prevalence_dest_ip",
    "prevalence_min",
    // Device fields
    "dvc",
    "dvc_ip",
    "dvc_mac",
    // Duration/Timing fields
    "duration",
    "response_time",
    // Legacy compatibility
    "user_agent",
    // Cloud fields
    "cloud_provider",
    "cloud_account_id",
    "cloud_account_name",
    "cloud_region",
    "cloud_service",
    // Resource fields
    "resource_id",
    "resource_name",
    "resource_type",
    // Change tracking
    "change_type",
    "mfa_used",
    // Enrichment fields (computed by ClickHouse)
    "enriched_src_country",
    "enriched_src_country_code",
    "enriched_src_continent",
    "enriched_src_continent_code",
    "enriched_src_asn",
    "enriched_src_as_name",
    "enriched_src_as_domain",
    "enriched_dest_country",
    "enriched_dest_country_code",
    "enriched_dest_continent",
    "enriched_dest_continent_code",
    "enriched_dest_asn",
    "enriched_dest_as_name",
    "enriched_dest_as_domain",
    // IOC enrichment fields (computed by ClickHouse via dictionary lookup)
    "ioc_matched",
    "ioc_confidence",
    "ioc_tags",
    "ioc_source",
    "ioc_src_ip_threat_type",
    "ioc_src_ip_malware",
    "ioc_src_ip_confidence",
    "ioc_dest_ip_threat_type",
    "ioc_dest_ip_malware",
    "ioc_dest_ip_confidence",
    "ioc_domain_threat_type",
    "ioc_domain_malware",
    "ioc_domain_confidence",
    "ioc_hash_threat_type",
    "ioc_hash_malware",
    "ioc_hash_confidence",
    // Custom enrichment fields (user-defined threat intel)
    "custom_src_ip_risk",
    "custom_src_ip_tags",
    "custom_dest_ip_risk",
    "custom_dest_ip_tags",
    "custom_domain_risk",
    "custom_domain_tags",
    "custom_hash_risk",
    "custom_hash_tags",
    "custom_url_risk",
    "custom_url_tags",
    "custom_ioc_src_ip_confidence",
    "custom_ioc_src_ip_malware",
    "custom_ioc_src_ip_threat_type",
    "custom_ioc_dest_ip_confidence",
    "custom_ioc_dest_ip_malware",
    "custom_ioc_dest_ip_threat_type",
    "custom_ioc_domain_confidence",
    "custom_ioc_domain_threat_type",
    "custom_ioc_hash_confidence",
    "custom_ioc_hash_threat_type",
    // Resolved-identity enrichment (user_registry_dict fills — forward + src/dest).
    // MATERIALIZED, like enriched_*/ioc_*; must be here too so `user_identity_*=…`
    // filters route to the column instead of ext JSON (NAN-1154).
    "user_identity_display_name",
    "user_identity_title",
    "user_identity_department",
    "user_identity_country",
    "user_identity_employee_type",
    "user_identity_account_status",
    "user_identity_mfa_enabled",
    "user_identity_groups",
    "src_user_identity_display_name",
    "src_user_identity_title",
    "src_user_identity_department",
    "src_user_identity_country",
    "src_user_identity_employee_type",
    "src_user_identity_account_status",
    "src_user_identity_mfa_enabled",
    "src_user_identity_groups",
    "dest_user_identity_display_name",
    "dest_user_identity_title",
    "dest_user_identity_department",
    "dest_user_identity_country",
    "dest_user_identity_employee_type",
    "dest_user_identity_account_status",
    "dest_user_identity_mfa_enabled",
    "dest_user_identity_groups",
    // NAN-1464: CIM event-class taxonomy, Array(String). Membership via has().
    "tags",
];

/// HashSet for O(1) explicit column lookups (initialized lazily)
static EXPLICIT_COLUMNS_SET: Lazy<HashSet<&'static str>> =
    Lazy::new(|| EXPLICIT_COLUMNS.iter().copied().collect());

/// UDM columns physically typed `Array(String)` on `logs`. nPL equality on these
/// must compile to `has(col, 'v')` (array membership) — a scalar `col = 'v'` is a
/// ClickHouse type error that silently returns nothing (NAN-1464). The existing
/// `*_tags` enrichment columns were already subject to this and are fixed here too.
pub(crate) const ARRAY_COLUMNS: &[&str] = &[
    "tags",
    "ioc_tags",
    "custom_src_ip_tags",
    "custom_dest_ip_tags",
    "custom_domain_tags",
    "custom_hash_tags",
    "custom_url_tags",
    // OCSF web content categories (NAN-1465) — membership via has().
    "http_request.url.categories",
];

static ARRAY_COLUMNS_SET: Lazy<HashSet<&'static str>> =
    Lazy::new(|| ARRAY_COLUMNS.iter().copied().collect());

/// True when `field` is an `Array(String)` column (membership via `has()`).
pub(crate) fn is_array_column(field: &str) -> bool {
    ARRAY_COLUMNS_SET.contains(field)
}

/// Columns declared `MATERIALIZED` on the `logs` table (computed at insert — enrichment,
/// IOC, custom threat-intel, prevalence, process-GUID hashing, and resolved-identity
/// dictionary fills). ClickHouse excludes MATERIALIZED columns from `SELECT *`, so a
/// multi-stage CTE chain must re-add them explicitly in stage_0 or any downstream stage
/// that references one fails with Code 47 (NAN-1147). This is the single source of truth
/// for that re-add list; ground-truthed against
/// `system.columns WHERE default_kind='MATERIALIZED'`.
///
/// NOT included: `event_type` (an ALIAS — handled via `action AS event_type`) and
/// regular stored columns like `src_ip`/`prevalence_min` (already in `SELECT *`).
pub(crate) const MATERIALIZED_COLUMNS: &[&str] = &[
    // GeoIP / ASN enrichment (dictGet at insert)
    "enriched_src_country",
    "enriched_src_country_code",
    "enriched_src_continent",
    "enriched_src_continent_code",
    "enriched_src_asn",
    "enriched_src_as_name",
    "enriched_src_as_domain",
    "enriched_dest_country",
    "enriched_dest_country_code",
    "enriched_dest_continent",
    "enriched_dest_continent_code",
    "enriched_dest_asn",
    "enriched_dest_as_name",
    "enriched_dest_as_domain",
    // IOC enrichment (threat-intel dict)
    "ioc_confidence",
    "ioc_tags",
    "ioc_source",
    "ioc_src_ip_threat_type",
    "ioc_src_ip_malware",
    "ioc_src_ip_confidence",
    "ioc_dest_ip_threat_type",
    "ioc_dest_ip_malware",
    "ioc_dest_ip_confidence",
    "ioc_domain_threat_type",
    "ioc_domain_malware",
    "ioc_domain_confidence",
    "ioc_hash_threat_type",
    "ioc_hash_malware",
    "ioc_hash_confidence",
    // Custom (user-defined) threat-intel enrichment
    "custom_src_ip_risk",
    "custom_src_ip_tags",
    "custom_dest_ip_risk",
    "custom_dest_ip_tags",
    "custom_domain_risk",
    "custom_domain_tags",
    "custom_hash_risk",
    "custom_hash_tags",
    "custom_url_risk",
    "custom_url_tags",
    "custom_ioc_src_ip_confidence",
    "custom_ioc_src_ip_malware",
    "custom_ioc_src_ip_threat_type",
    "custom_ioc_dest_ip_confidence",
    "custom_ioc_dest_ip_malware",
    "custom_ioc_dest_ip_threat_type",
    "custom_ioc_domain_confidence",
    "custom_ioc_domain_threat_type",
    "custom_ioc_hash_confidence",
    "custom_ioc_hash_threat_type",
    // Prevalence (dict lookups)
    "prevalence_file_hash",
    "prevalence_process_hash",
    "prevalence_dest_domain",
    "prevalence_dest_ip",
    // Process GUID hashing
    "process_guid",
    "parent_process_guid",
    // Resolved-identity dictionary fills (forward + reverse)
    "user_identity_display_name",
    "user_identity_title",
    "user_identity_department",
    "user_identity_country",
    "user_identity_employee_type",
    "user_identity_account_status",
    "user_identity_mfa_enabled",
    "user_identity_groups",
    "src_user_identity_display_name",
    "src_user_identity_title",
    "src_user_identity_department",
    "src_user_identity_country",
    "src_user_identity_employee_type",
    "src_user_identity_account_status",
    "src_user_identity_mfa_enabled",
    "src_user_identity_groups",
    "dest_user_identity_display_name",
    "dest_user_identity_title",
    "dest_user_identity_department",
    "dest_user_identity_country",
    "dest_user_identity_employee_type",
    "dest_user_identity_account_status",
    "dest_user_identity_mfa_enabled",
    "dest_user_identity_groups",
];

/// Check if a field is an explicit column (direct column access) vs JSON field.
///
/// Superseded by `SchemaProfile::resolve` (NAN-1241): callers now consult the
/// active profile (`matches!(profile.resolve(f), FieldResolution::ExplicitColumn)`)
/// so OCSF promoted columns classify correctly. Retained as the canonical
/// UDM-parity reference (the schema anti-drift test asserts `resolve` reproduces
/// this for every UDM field).
#[allow(dead_code)]
pub(crate) fn is_explicit_column(field: &str) -> bool {
    EXPLICIT_COLUMNS_SET.contains(field)
}

/// Check if a field pattern contains wildcards
fn is_wildcard_pattern(field: &str) -> bool {
    field.contains('*')
}

/// Expand a wildcard pattern to matching explicit column names
/// Supports patterns like: src_*, *_ip, dest_*, _*
fn expand_wildcard_pattern(pattern: &str) -> Vec<String> {
    if !is_wildcard_pattern(pattern) {
        return vec![pattern.to_string()];
    }

    // Convert glob pattern to regex: * -> .*
    let regex_pattern = format!("^{}$", pattern.replace('*', ".*"));
    let re = match regex::Regex::new(&regex_pattern) {
        Ok(r) => r,
        Err(_) => return vec![pattern.to_string()], // If regex fails, return as-is
    };

    EXPLICIT_COLUMNS
        .iter()
        .filter(|col| re.is_match(col))
        .map(|s| s.to_string())
        .collect()
}

/// Extract field names from a SearchExpr (for sequence auto-capture)
fn extract_fields_from_search_expr(expr: &SearchExpr) -> Vec<String> {
    let mut fields = Vec::new();
    match expr {
        SearchExpr::FieldFilter { field, .. } => {
            fields.push(field.clone());
        }
        SearchExpr::FieldFunctionFilter { field, .. } => {
            fields.push(field.clone());
        }
        SearchExpr::InList { field, .. } => {
            fields.push(field.clone());
        }
        SearchExpr::And(left, right) | SearchExpr::Or(left, right) => {
            fields.extend(extract_fields_from_search_expr(left));
            fields.extend(extract_fields_from_search_expr(right));
        }
        SearchExpr::Not(inner) => {
            fields.extend(extract_fields_from_search_expr(inner));
        }
        SearchExpr::Group(inner) => {
            fields.extend(extract_fields_from_search_expr(inner));
        }
        // These don't have specific fields we want to capture
        // NAN-1580: IocMatch is an observable-anywhere term — no single field.
        SearchExpr::Keyword(_)
        | SearchExpr::FunctionFilter { .. }
        | SearchExpr::BooleanFunction(_)
        | SearchExpr::IocMatch { .. }
        | SearchExpr::LiteralComparison { .. } => {}
        SearchExpr::InSubsearch { field, .. } => {
            fields.push(field.clone());
        }
    }
    // Deduplicate
    fields.sort();
    fields.dedup();
    fields
}

/// Options for SQL query generation
#[derive(Debug, Clone)]
pub struct QueryOptions {
    /// Enable query cache for shared searches with fixed time ranges
    /// Adds SETTINGS use_query_cache=1, query_cache_ttl=300
    pub use_cache: bool,
    /// Table view mode - only return minimal columns (id, timestamp, source_type, message + query fields)
    /// Full row data is fetched on demand when user expands a row
    pub table_view: bool,
    /// Maximum results the generator bakes into the SQL as a trailing LIMIT.
    ///
    /// `None` means the generator emits NO trailing result LIMIT — the caller
    /// owns pagination and injects/wraps its own LIMIT/OFFSET (the executor's
    /// paginated path). Baking the page-size limit here made the executor's
    /// LIMIT/OFFSET injection a silent no-op (page N re-served page 1) and
    /// capped the count companion's total at the page size (NAN-1410).
    ///
    /// User-level limits (`| head N`, subsearch caps) are emitted regardless —
    /// they are query semantics, not pagination.
    pub limit: Option<usize>,
}

impl Default for QueryOptions {
    fn default() -> Self {
        Self {
            use_cache: false,
            table_view: false,
            // Safety bound for callers that execute the generated SQL directly
            // (explain, detection, …) without an executor-side pagination step.
            limit: Some(ClickHouseSqlGenerator::DEFAULT_RESULT_LIMIT),
        }
    }
}

/// Indexed equality fields (primary key or set/bloom indexes). Historically the
/// PREWHERE promotion list; since NAN-1412 the generator emits a single WHERE
/// (explicit PREWHERE suppressed ClickHouse's `optimize_move_to_prewhere`) and
/// this list only feeds `has_selective_indexed_eq` (the `optimize_read_in_order`
/// toggle) and the field-metadata API's "indexed" flag.
///
/// `pub(crate)` for `UdmProfile` parity (NAN-1244).
pub(crate) const PREWHERE_FIELDS: &[&str] = &[
    "source_type",
    "sourcetype",
    "src_host",
    "src_ip",
    "event_type",
    "action",
    "dest_host",
    "dest_ip",
    "process_name",
    "user",
];

/// Fields that are normalized to lowercase at ingest time.
/// For these fields, we can skip the lower() wrapper and do direct comparison,
/// which allows efficient index usage.
///
/// `pub(crate)` for `UdmProfile` parity (NAN-1244).
pub(crate) const LOWERCASE_NORMALIZED_FIELDS: &[&str] = &[
    "source_type",
    "sourcetype",
    "event_type",
    "action",
    "src_host",
    "dest_host",
    "user",
    "user_domain",
    "src_ip",
    "dest_ip",
    "protocol",
    "src_mac",
    "dest_mac",
    // NAN-1415: src_user is downcased in the Vector clickhouse_mapping stage
    // (same lane as src_ip/user) and history is empirically all-lowercase, so
    // the raw compare engages the whole-value `idx_src_user` bloom.
    // dest_user is deliberately ABSENT: the VRL never downcased it and stored
    // data is mixed-case (52k+ uppercase rows locally) — a raw compare would
    // silently drop those matches. Same for file_hash / process_hash /
    // process_guid: ingest now canonicalizes them (NAN-1415) but history is
    // mixed-case, so queries keep the `lower(col)` form, served by the
    // migration-132 `idx_*_lower` expression blooms.
    "src_user",
    // NAN-1528: OTLP trace/span ids are emitted lowercase-hex (the spans MV uses
    // `lower(hex(...))` and the logs-lane parsers downcase them), so a raw
    // `trace_id = '<lowered>'` engages the migration-141 `idx_trace_id` bloom.
    "trace_id",
    "span_id",
];

/// Numeric UDM fields (UInt16, UInt32, Int64, Float64).
/// For these fields, we should NOT apply lower() even when the value is passed as a string.
/// We convert string values to numbers for comparison.
///
/// `pub(crate)` for `UdmProfile` parity (NAN-1244).
pub(crate) const NUMERIC_UDM_FIELDS: &[&str] = &[
    // Ports (UInt16)
    "src_port",
    "dest_port",
    "transport_dest_port",
    // HTTP status (UInt16)
    "status_code",
    "http_status_code",
    // Byte counts (UInt64)
    "bytes_in",
    "bytes_out",
    "packets_in",
    "packets_out",
    // File size (UInt64)
    "file_size",
    // Process IDs (UInt32/Int64)
    "process_id",
    "parent_process_id",
    // Duration/timing (Float64)
    "duration",
    "response_time",
    // Risk/prevalence (UInt8/UInt16)
    "risk_score",
    "prevalence_file_hash",
    "prevalence_process_hash",
    "prevalence_dest_domain",
    "prevalence_dest_ip",
    "prevalence_min",
    // IOC enrichment confidence (UInt8)
    "ioc_matched",
    "ioc_confidence",
    "ioc_src_ip_confidence",
    "ioc_dest_ip_confidence",
    "ioc_domain_confidence",
    "ioc_hash_confidence",
    // Custom enrichment risk/confidence (UInt8)
    "custom_src_ip_risk",
    "custom_dest_ip_risk",
    "custom_domain_risk",
    "custom_hash_risk",
    "custom_url_risk",
    "custom_ioc_src_ip_confidence",
    "custom_ioc_dest_ip_confidence",
    "custom_ioc_domain_confidence",
    "custom_ioc_hash_confidence",
    // Other UInt8 fields
    "mfa_used",
    // VLAN (UInt16)
    "vlan",
];

/// UUID fields — ClickHouse UUID type doesn't support lower(), so we compare
/// via toString() cast. `toString(UUID)` renders lowercase, so comparing it to
/// the lowered literal is correct. Add any new genuinely UUID-typed columns here.
///
/// NAN-1415: `rule_id` was removed — `logs.rule_id` is a plain String (only
/// `signals.rule_id` is a CH UUID, and that table is never queried through this
/// generator). Routing it here emitted `toString(rule_id) = '<lowered literal>'`:
/// a CASE-SENSITIVE compare against a lowered literal, so uppercase-stored
/// vendor rule ids never matched, and the toString() wrapper orphaned every
/// index. It now flows through the generic string arm (`lower(rule_id) = …`),
/// which the migration-132 `idx_rule_id_lower` expression bloom serves.
///
/// `pub(crate)` for `UdmProfile` parity (NAN-1244).
pub(crate) const UUID_FIELDS: &[&str] = &["id"];

/// Check if a SearchExpr has a top-level conjunctive equality on a selective
/// indexed field (anything in `prewhere_fields()` beyond source_type/sourcetype).
/// When true, `optimize_read_in_order` should be disabled to allow parallel
/// granule scanning — sequential scanning through mostly-empty granules is much
/// slower for sparse matches.
///
/// NAN-1412: the generator no longer emits an explicit PREWHERE (it suppressed
/// ClickHouse's `optimize_move_to_prewhere`, leaving every non-promoted filter
/// after the full-projection read — up to 349x read amplification). This check
/// is the surviving consumer of the per-profile `prewhere_fields()` indexed-
/// column list: it now only drives the read-in-order toggle.
pub(super) fn has_selective_indexed_eq(expr: &SearchExpr, profile: &dyn SchemaProfile) -> bool {
    // Eligibility is judged through the active profile on the resolved physical
    // column, not the raw UDM token (NAN-1299). UDM resolves to the identity
    // column, so behavior is unchanged there.
    fn check(expr: &SearchExpr, profile: &dyn SchemaProfile) -> bool {
        match expr {
            SearchExpr::And(left, right) => check(left, profile) || check(right, profile),
            // NAN-1379: recurse through pure parenthesization (the audit wrap
            // `Group(expr) AND source_type != 'audit'` must not hide selective
            // conditions, or `optimize_read_in_order` stays on for a selective
            // equality that is present).
            SearchExpr::Group(inner) => check(inner, profile),
            SearchExpr::FieldFilter {
                field,
                op: Comparator::Eq,
                value,
            } => {
                let normalized = normalize_field_name(field);
                // NAN-1321: a class-split concept (OCSF host/user/process/url)
                // matches a value-pick / unified-column expression in WHERE, not
                // a clean single-column indexed equality — don't count it as
                // selective.
                if profile.class_split_value_sql(normalized).is_some() {
                    return false;
                }
                let col = match profile.resolve(normalized) {
                    FieldResolution::ExplicitColumn(c) | FieldResolution::Alias(c) => c,
                    _ => return false,
                };
                // Only source_type/sourcetype are broad filters; everything else is selective
                if col == "source_type" || col == "sourcetype" {
                    return false;
                }
                if profile.prewhere_fields().contains(&col.as_str()) {
                    // Skip wildcards — those compile to iLike patterns, not
                    // indexed equality.
                    if let Value::String(s) = value {
                        if s.contains('*') || s.contains('?') {
                            return false;
                        }
                    }
                    return true;
                }
                false
            }
            _ => false,
        }
    }
    check(expr, profile)
}

/// Default max elements for groupArray/groupUniqArray to prevent OOM from unbounded array aggregation.
/// Capped at 100 — high-cardinality fields (e.g., a parser that maps session UUIDs into `user`)
/// can produce 780K+ unique values per group, and 10K × thousands of groups was enough to OOM
/// ClickHouse on small clusters. 100 values per group is more than enough for triage context in
/// detection rules and search results.
const DEFAULT_MAX_GROUP_ARRAY_SIZE: usize = 100;

/// Default max rows after mvexpand (arrayJoin) when user doesn't specify a limit
const DEFAULT_MAX_MVEXPAND_ROWS: usize = 100_000;

/// SQL Generator for converting Query AST to ClickHouse SQL
pub struct ClickHouseSqlGenerator {
    /// Table name for logs
    table_name: String,
    /// Primary time column for the time-bound WHERE / default ORDER BY and the
    /// counter-rate window. Defaults to `"timestamp"` (logs/metrics); set to
    /// `"start_time"` for the OTLP spans dataset via [`with_dataset`] (NAN-1534).
    /// When this is the default `"timestamp"`, every emitted statement is
    /// byte-identical to the pre-dataset generator.
    ///
    /// [`with_dataset`]: ClickHouseSqlGenerator::with_dataset
    time_column: String,
    /// Promoted columns of the active OTLP dataset (NAN-1534). EMPTY for the
    /// default logs dataset — logs field resolution is owned entirely by
    /// `self.profile`, so when this is empty every resolution path is
    /// byte-identical. When non-empty (spans/metrics), a field token present here
    /// resolves to a DIRECT column ahead of the profile's `ext.*` spill (the OTLP
    /// tables have no `ext` column).
    dataset_columns: HashSet<&'static str>,
    /// Numeric columns of the active OTLP dataset (`duration_ns`, `value`, …) —
    /// suppress `lower()`, coerce string literals to numbers. Empty for logs.
    dataset_numeric_columns: HashSet<&'static str>,
    /// Max elements in groupArray/groupUniqArray (prevents OOM from unbounded array agg)
    max_group_array_size: usize,
    /// Default row limit for mvexpand when user doesn't specify one
    max_mvexpand_rows: usize,
    /// Time range set during generation for subsearch IN subqueries
    generation_time_range: RwLock<Option<TimeRange>>,
    /// Field names produced by earlier pipeline commands (eval, stats aliases,
    /// risk, …), set at the start of generation. A name in this set is a real
    /// column in the current scope, so it must be referenced directly even when
    /// it collides with a "known metadata" field (e.g. `risk_factors` after a
    /// `| risk` command). (NAN-1236)
    computed_fields: RwLock<HashSet<String>>,
    /// Fields created with NEW VALUES (rex captures, eval assignments, rename
    /// targets, aggregation aliases, command outputs) by pipeline stages
    /// strictly UPSTREAM of the stage currently being generated (NAN-1341).
    /// Unlike `computed_fields` — the whole-query set consulted after schema
    /// resolution — this set is maintained incrementally as stages generate and
    /// is consulted BEFORE `normalize_field_name` / `resolves_to_column`: a rex
    /// capture or eval output shadows a same-named schema field or UDM alias
    /// for the rest of the pipeline. Whole-query population can't work here:
    /// stats group_by self-registers raw by-field names, which would make a
    /// plain `stats count by method` (no rex) shadow its own schema resolution.
    /// Empty outside `generate_with_options`.
    upstream_computed_fields: RwLock<HashSet<String>>,
    /// Reference-side aliases for UN-aliased aggregations (NAN-1339): an
    /// un-aliased `avg(bytes_in)` outputs a column literally named `avg`
    /// (`Aggregation::output_alias` fallback), but users following the
    /// `values_`/`list_` convention reference it as `avg_bytes_in` — which
    /// previously emitted a bare unknown identifier (Code 47). Maps
    /// `{func}_{field}` → the actual output column. Renaming the output
    /// itself would break saved content referencing the bare func name.
    agg_reference_aliases: RwLock<std::collections::HashMap<String, String>>,
    /// Active schema profile (OCSF Phase 2). Defaults to [`UdmProfile`] so the
    /// ~79 `::new()` / `::with_table()` construction sites keep today's exact
    /// behavior; OCSF deployments inject an `OcsfProfile` via [`with_profile`].
    ///
    /// [`with_profile`]: ClickHouseSqlGenerator::with_profile
    profile: Arc<dyn SchemaProfile>,
    /// The tenant logs profile (UDM/OCSF) captured on the first
    /// [`with_dataset`](ClickHouseSqlGenerator::with_dataset) swap, so a later
    /// `Dataset::Logs` (e.g. a cross-dataset subsearch INTO logs from a
    /// spans/metrics outer query) can RESTORE it instead of inheriting the outer
    /// spans/metrics profile — which would resolve logs fields like `source_type`
    /// as `attributes['source_type']` → a correlated subquery (NAN-1567). `None`
    /// until the first dataset swap; logs-only queries never swap, so it stays
    /// `None` and behavior is byte-identical.
    base_profile: Option<Arc<dyn SchemaProfile>>,
}

impl Clone for ClickHouseSqlGenerator {
    fn clone(&self) -> Self {
        Self {
            table_name: self.table_name.clone(),
            time_column: self.time_column.clone(),
            dataset_columns: self.dataset_columns.clone(),
            dataset_numeric_columns: self.dataset_numeric_columns.clone(),
            max_group_array_size: self.max_group_array_size,
            max_mvexpand_rows: self.max_mvexpand_rows,
            generation_time_range: RwLock::new(None),
            computed_fields: RwLock::new(HashSet::new()),
            upstream_computed_fields: RwLock::new(HashSet::new()),
            agg_reference_aliases: RwLock::new(std::collections::HashMap::new()),
            profile: Arc::clone(&self.profile),
            base_profile: self.base_profile.clone(),
        }
    }
}

impl Default for ClickHouseSqlGenerator {
    fn default() -> Self {
        Self::new()
    }
}

impl ClickHouseSqlGenerator {
    /// Create a new ClickHouse SQL generator with default table name "logs"
    /// and the UDM schema profile (today's behavior, unchanged).
    pub fn new() -> Self {
        Self {
            table_name: "logs".to_string(),
            time_column: "timestamp".to_string(),
            dataset_columns: HashSet::new(),
            dataset_numeric_columns: HashSet::new(),
            max_group_array_size: DEFAULT_MAX_GROUP_ARRAY_SIZE,
            max_mvexpand_rows: DEFAULT_MAX_MVEXPAND_ROWS,
            generation_time_range: RwLock::new(None),
            computed_fields: RwLock::new(HashSet::new()),
            upstream_computed_fields: RwLock::new(HashSet::new()),
            agg_reference_aliases: RwLock::new(std::collections::HashMap::new()),
            profile: Arc::new(UdmProfile::new()),
            base_profile: None,
        }
    }

    /// Create a new ClickHouse SQL generator with a custom table name
    /// (UDM schema profile).
    pub fn with_table(table_name: impl Into<String>) -> Self {
        Self {
            table_name: table_name.into(),
            time_column: "timestamp".to_string(),
            dataset_columns: HashSet::new(),
            dataset_numeric_columns: HashSet::new(),
            max_group_array_size: DEFAULT_MAX_GROUP_ARRAY_SIZE,
            max_mvexpand_rows: DEFAULT_MAX_MVEXPAND_ROWS,
            generation_time_range: RwLock::new(None),
            computed_fields: RwLock::new(HashSet::new()),
            upstream_computed_fields: RwLock::new(HashSet::new()),
            agg_reference_aliases: RwLock::new(std::collections::HashMap::new()),
            profile: Arc::new(UdmProfile::new()),
            base_profile: None,
        }
    }

    /// Inject an explicit schema profile (OCSF Phase 2). Builder-style so it
    /// composes with the existing `with_*` setters. UDM call sites that never
    /// call this keep the default [`UdmProfile`], so behavior is unchanged.
    pub fn with_profile(mut self, profile: Arc<dyn SchemaProfile>) -> Self {
        self.profile = profile;
        self
    }

    /// Point the generator at an OTLP [`Dataset`] (NAN-1534). Builder-style; sets
    /// the storage table AND the primary time column in lock-step so the
    /// time-bound WHERE, default ORDER BY, and the `rate()` window all reference
    /// the dataset's own time column (`start_time` for spans).
    ///
    /// `Dataset::Logs` (the default) sets `table_name = "logs"` /
    /// `time_column = "timestamp"`, keeping every emitted statement
    /// byte-for-byte identical to the pre-dataset generator. The whole nPL
    /// pipeline (search terms, stats/where/sort/timechart/eval) then runs against
    /// the selected table unchanged.
    ///
    /// [`Dataset`]: otel::Dataset
    pub fn with_dataset(mut self, dataset: otel::Dataset) -> Self {
        // NAN-1567: capture the tenant logs profile (UDM/OCSF) on the FIRST dataset
        // swap, before it is replaced below. A later `Dataset::Logs` — e.g. a
        // cross-dataset subsearch INTO logs from a spans/metrics outer query —
        // restores it, so logs fields resolve against the logs profile rather than
        // the inherited spans/metrics one (which would emit `attributes['…']`
        // Map access → a correlated subquery CH rejects).
        if self.base_profile.is_none() {
            self.base_profile = Some(Arc::clone(&self.profile));
        }
        self.table_name = dataset.table_name().to_string();
        self.time_column = dataset.time_column().to_string();
        self.dataset_columns = dataset.columns().iter().copied().collect();
        self.dataset_numeric_columns = dataset.numeric_columns().iter().copied().collect();
        // NAN-1555: a spans/metrics query resolves fields, projection, the keyword
        // column, and the attribute `Map` tail through its own dataset profile —
        // NOT the tenant UDM/OCSF logs profile, which would alias `service_name` →
        // `cloud_service`, treat `value`/`duration_ns` as a String `ext` spill,
        // re-add nonexistent enrichment columns, and project the wrong core fields.
        match dataset {
            otel::Dataset::Spans => self.profile = Arc::new(crate::schema::SpansProfile::new()),
            otel::Dataset::Metrics => {
                self.profile = Arc::new(crate::schema::MetricsProfile::new())
            }
            // NAN-1567: restore the captured tenant logs profile. For a logs-only
            // query `with_dataset` is never called, so this arm is only reached for
            // a cross-dataset subsearch INTO logs — where `base_profile` was
            // captured from the outer query's original tenant profile above.
            otel::Dataset::Logs => {
                self.profile = self
                    .base_profile
                    .clone()
                    .expect("base_profile captured at top of with_dataset");
            }
        }
        self
    }

    /// NAN-1555 resolution routing: point a metrics query at the pre-aggregated
    /// `otel_metrics_1m`/`_1h` rollup (migration 144) instead of raw `otel_metrics`.
    /// MUST be called AFTER [`with_dataset`](Self::with_dataset)`(Metrics)` — it
    /// overrides the storage table + time column to the rollup's. `core_search`
    /// calls this only for rollup-eligible aggregate queries over wide windows;
    /// the value-aggregations are then rewritten onto the rollup's pre-aggregated
    /// state columns by `rollup_value_agg`. The `MetricsProfile` stays active so
    /// `metric_name`/`service_name`/`value` still resolve as columns (they exist on
    /// the rollup); tag access does NOT (the rollup carries no tag maps — which is
    /// exactly why core_search never routes a tag-filtered/grouped query here).
    pub fn with_metrics_rollup(mut self, grain: otel::MetricRollup) -> Self {
        self.table_name = grain.table_name().to_string();
        self.time_column = grain.time_column().to_string();
        self
    }

    /// Whether the generator is currently pointed at a metrics rollup table.
    pub(crate) fn is_metrics_rollup(&self) -> bool {
        self.table_name == "otel_metrics_1m" || self.table_name == "otel_metrics_1h"
    }

    /// Whether `field` is a promoted column of the active OTLP dataset (NAN-1534).
    /// Always false for the default logs dataset (empty overlay) → byte-identical.
    pub(crate) fn is_dataset_column(&self, field: &str) -> bool {
        self.dataset_columns.contains(field)
    }

    /// Whether `field` is a numeric column of the active OTLP dataset (NAN-1534).
    /// Always false for logs.
    pub(crate) fn is_dataset_numeric_column(&self, field: &str) -> bool {
        self.dataset_numeric_columns.contains(field)
    }

    /// The primary time column for the active dataset (`"timestamp"` for
    /// logs/metrics, `"start_time"` for spans). Used by the time-bound WHERE,
    /// default ORDER BY, and the `rate()` counter window (NAN-1534).
    pub(crate) fn time_column(&self) -> &str {
        &self.time_column
    }

    // Phase 2b: route the storage binding (table name / timestamp expression)
    // through `self.profile.table_name()` / `self.profile.timestamp_expr()`.
    // Deliberately NOT wired here: the generator threads `self.table_name`
    // (default "logs"/with_table) and the literal `timestamp` column through
    // many sites, and consulting the profile risks diverging current UDM output.
    // The existing `table_name` field must keep winning until OCSF wiring lands.

    /// Whether `field` resolves to a direct ClickHouse column under the active
    /// profile (`&self` wrapper over `profile.resolve()`). For UDM this is
    /// byte-for-byte identical to the free `is_explicit_column()` — the profile's
    /// `resolve()` returns `ExplicitColumn` for exactly the `EXPLICIT_COLUMNS`
    /// set (proven by `schema::tests`).
    pub(crate) fn resolves_to_column(&self, field: &str) -> bool {
        // NAN-1534: an OTLP dataset column resolves to a direct column ahead of
        // the profile (the spans/metrics tables have no `ext` spill). Empty
        // overlay for logs → falls straight through, byte-identical.
        self.is_dataset_column(normalize_field_name(field))
            || matches!(self.profile.resolve(field), FieldResolution::ExplicitColumn(_))
    }

    /// Whether `field` resolves to a JSON-tail path under the active profile
    /// (`&self` wrapper over `profile.resolve()`). **Always false for UDM** —
    /// `UdmProfile::resolve` only ever returns `ExplicitColumn`/`Unknown`, never
    /// `JsonPath` — so callers that branch on it stay UDM-byte-identical. True
    /// only for OCSF unpromoted/unmapped names, which must be accessed inside the
    /// `event` JSON tail (native subcolumn access, NAN-1426) rather than
    /// referenced as a (nonexistent) bare column that 500s. (NAN-1248)
    pub(crate) fn resolves_to_json_path(&self, field: &str) -> bool {
        matches!(self.profile.resolve(field), FieldResolution::JsonPath { .. })
    }

    /// Whether `field` resolves to a `Map`-tail attribute lookup under the active
    /// profile — only true for the spans/metrics datasets (NAN-1555). UDM/OCSF
    /// never return `MapKey`, so logs callers that branch on it stay
    /// byte-identical. The value/group seams (`field_to_sql_expr`/`by_field_sql`)
    /// route these to [`field_access_expr`] (the attribute `Map` subscript) instead
    /// of the UDM `metadata` JSON column or a bare reference.
    ///
    /// [`field_access_expr`]: ClickHouseSqlGenerator::field_access_expr
    pub(crate) fn resolves_to_map_key(&self, field: &str) -> bool {
        matches!(self.profile.resolve(field), FieldResolution::MapKey { .. })
    }

    /// Canonicalize an nPL field token for the value/group/filter seams (NAN-1555).
    /// Spans canonicalize through the `SpansProfile` (`duration` → `duration_ns`,
    /// and crucially NO UDM aliasing so `service_name` stays itself rather than
    /// becoming `cloud_service`). Logs (UDM/OCSF) keep the exact free
    /// `normalize_field_name` alias map, so every logs statement is byte-identical.
    pub(crate) fn canonicalize_field<'a>(&self, field: &'a str) -> &'a str {
        match self.profile.id() {
            crate::schema::SchemaId::Spans => crate::schema::canonicalize_span_field(field),
            crate::schema::SchemaId::Metrics => crate::schema::canonicalize_metric_field(field),
            _ => normalize_field_name(field),
        }
    }

    /// The class-spanning value expression for a UDM-semantic concept the active
    /// profile splits across columns by event class (`&self` wrapper over
    /// `profile.class_split_value_sql()`, NAN-1319). `None` for UDM (no split →
    /// byte-identical) and for non-split / native fields. Lets the value/group
    /// seam (`field_to_sql_expr`) project the host/user/process value wherever
    /// the OCSF class put it.
    pub(crate) fn class_split_value_sql(&self, field: &str) -> Option<String> {
        self.profile.class_split_value_sql(field)
    }

    /// The INDEXED unified column that materializes the `class_split_value_sql`
    /// union for a class-split concept (`&self` wrapper over
    /// `profile.class_split_column()`, NAN-1333). When `Some`, the value/group/sort
    /// and filter seams emit `escape_identifier(col)` — a plain words-index-prunable
    /// column reference — instead of the skip-index-opaque inline `if(...)`. `None`
    /// for UDM (no split → byte-identical) and for non-split / native fields.
    pub(crate) fn class_split_column(&self, field: &str) -> Option<String> {
        self.profile.class_split_column(field)
    }

    /// Whether `field` belongs to the active profile's field universe (`&self`
    /// wrapper over `profile.is_known_field()`, mirroring the `resolves_to_column`
    /// pattern). Replaces the free `is_udm_field()` at generator-scoped call sites.
    /// For UDM this is `EXPLICIT_COLUMNS ∪ valid UdmField` — i.e. the first two
    /// branches of the free `is_udm_field()`; the computed-aggregation-name branch
    /// (`count`/`sum`/…) of that free fn is handled separately by
    /// [`is_computed_field`] in pipeline context, not the schema universe.
    ///
    /// [`is_computed_field`]: ClickHouseSqlGenerator::is_computed_field
    // NAN-1248 re-pointed `field_to_sql_expr` (the last caller) at
    // `resolves_to_column`, which catches OCSF UDM-semantic aliases that
    // `is_known_field` does not. Kept (like the free `is_udm_field`) for the
    // field universe semantics a future phase may route through.
    #[allow(dead_code)]
    pub(crate) fn is_known_profile_field(&self, field: &str) -> bool {
        self.profile.is_known_field(field)
    }

    /// Profile-aware physical access expression for a field that is *not* a plain
    /// computed/pipeline column — i.e. the "spill" access path the SQL generator
    /// uses when a field is not a direct `ExplicitColumn`.
    ///
    /// This centralizes the historically-hardcoded `ext.{field}` access so OCSF's
    /// nested layout works without changing UDM. It consults the active profile's
    /// [`resolve`]:
    /// - [`ExplicitColumn`] → `escape_identifier(col)` (a direct, possibly dotted,
    ///   promoted column — backtick/quote-safe).
    /// - [`JsonPath`] → native **subcolumn** access against the JSON-typed column
    ///   (OCSF's `event` tail) via [`json_tail_access_sql`] — `toString(event."a"."b")`
    ///   shapes instead of `JSONExtract<T>(event, …)`, which re-serialized the
    ///   entire event object per row (87–300x read_bytes, NAN-1426). `json_type`
    ///   is chosen by the caller from the comparison/value (`String`/`Float`/`Bool`
    ///   — the typed extractor suffixes; numeric is `Float`, NOT `Float64`,
    ///   NAN-1383). Parity carve-outs (missing-key zero/'' semantics, object/array
    ///   serialization, Bool kept on JSONExtractBool) live on the helper.
    /// - [`Unknown`] (and the array/alias variants, which the tokenizer never
    ///   produces on this path) → `ext.{field}` — UDM's existing behavior, kept
    ///   **byte-for-byte identical** because `UdmProfile::resolve` only ever
    ///   returns `ExplicitColumn`/`Unknown`.
    ///
    /// [`resolve`]: crate::schema::SchemaProfile::resolve
    /// [`ExplicitColumn`]: FieldResolution::ExplicitColumn
    /// [`JsonPath`]: FieldResolution::JsonPath
    /// [`Unknown`]: FieldResolution::Unknown
    pub(crate) fn field_access_expr(&self, field: &str, json_type: &str) -> String {
        // NAN-1534: a promoted OTLP dataset column is a direct, escape-safe
        // column reference — resolved ahead of the profile so it never falls to
        // UDM's `ext.<field>` spill (the spans/metrics tables have no `ext`).
        // Empty overlay for logs → this guard is skipped, byte-identical.
        if self.is_dataset_column(normalize_field_name(field)) {
            return escape_identifier(normalize_field_name(field));
        }
        match self.profile.resolve(field) {
            FieldResolution::ExplicitColumn(col) => escape_identifier(&col),
            FieldResolution::JsonPath { col, path } => {
                json_tail_access_sql(&col, &path, json_type)
            }
            // NAN-1555: spans/metrics attribute `Map` tail. The literal dotted key
            // is preserved (`attributes['http.method']`) — NOT dot-stripped like
            // the UDM `Unknown` arm below — with a `resource_attributes` fallback.
            // `json_type` is ignored: the map is `Map(_, String)`, so access is
            // always String-typed (kept in lockstep with `column_sql`'s MapKey
            // arm). Only `SpansProfile::resolve` returns this variant, so UDM/OCSF
            // are unaffected.
            FieldResolution::MapKey { col, fallback, key } => {
                map_tail_access_sql(&col, fallback.as_deref(), &key)
            }
            // UDM Unknown (and OCSF array/alias variants the field tokenizer does
            // not surface here): UDM's `ext.{field}` spill access.
            //
            // NAN-1411: the explicitly prefixed spelling (`ext.channel=…`) must
            // land on the same `ext.channel` access as the unprefixed fallthrough
            // (`channel=…`). Without the strip, the dotted name reaches
            // `sanitize_json_path`, which deletes the dot — probing
            // `ext.extchannel`: 0 rows, silently. Strip exactly the `ext.` prefix
            // (so `external_id` etc. are untouched); the remainder goes through
            // the same sanitize as the unprefixed form. A remainder that
            // sanitizes to nothing (`ext.` — a trailing dot passes field-name
            // validation) falls back to the whole-name sanitize so we never
            // emit a dangling `ext.`. UDM-scoped by construction: only
            // `UdmProfile::resolve` returns `Unknown` here —
            // `OcsfProfile::resolve` remaps `ext.*` to its `unmapped.*` event
            // tail (JsonPath) and never returns this variant (NAN-1388).
            FieldResolution::ArrayElement { .. }
            | FieldResolution::Alias(_)
            | FieldResolution::Unknown => {
                match field.strip_prefix("ext.").map(sanitize_json_path) {
                    Some(key) if !key.is_empty() => format!("ext.{}", key),
                    _ => format!("ext.{}", sanitize_json_path(field)),
                }
            }
        }
    }

    /// Physical access expression for a field used on the LEFT of a `field=value`
    /// search FILTER (NAN-1321). Identical to [`field_access_expr`] except that a
    /// UDM-semantic concept OCSF splits across columns by event class (host / user
    /// / process / url) resolves to its class-spanning value-pick
    /// `if(primary != '', primary, fallback)` instead of the primary column alone —
    /// so `src_host="ws-01"` matches the host wherever the OCSF class put it
    /// (`device.hostname` on endpoint events), mirroring the `stats by src_host`
    /// projection. Single expression, so negation (`!=`, `NOT iLike`) stays correct
    /// with no De Morgan across columns. UDM has no class-split → falls through to
    /// the bare column, byte-identical. `has_selective_indexed_eq` deliberately
    /// skips class-split fields — a value-pick is not a clean single-column
    /// indexed equality.
    ///
    /// [`field_access_expr`]: ClickHouseSqlGenerator::field_access_expr
    pub(crate) fn filter_field_expr(&self, field: &str, json_type: &str) -> String {
        // NAN-1333: prefer the INDEXED unified column (which materializes the exact
        // same union) so the WHERE predicate prunes via the words index instead of
        // full-scanning the opaque inline `if(...)`. Falls back to the value-pick
        // `if(...)` if a split concept has no materialized column, then to the plain
        // field access for non-split fields. UDM never class-splits → both lookups
        // are `None` → byte-identical bare column.
        if let Some(col) = self.profile.class_split_column(field) {
            return escape_identifier(&col);
        }
        self.profile
            .class_split_value_sql(field)
            .unwrap_or_else(|| self.field_access_expr(field, json_type))
    }

    /// Whether `field` is produced by an earlier pipeline command (eval, stats
    /// alias, risk, …) and is therefore a real column in the current scope —
    /// rather than a value to extract from the `metadata`/`ext` JSON. Populated
    /// for the duration of [`generate_with_options`]. (NAN-1236)
    /// Expand a `table`/`fields` wildcard pattern against the schema's
    /// explicit columns AND the pipeline's computed fields (rex captures,
    /// spath outputs, eval/stats aliases) — the static-only expansion made
    /// `table ext_*` after a spath silently expand to NOTHING, emitting an
    /// empty SELECT list (CH Code 62 syntax error, NAN-1339).
    pub(crate) fn expand_wildcard(&self, pattern: &str) -> Vec<String> {
        let mut cols = expand_wildcard_pattern(pattern);
        if !is_wildcard_pattern(pattern) {
            return cols;
        }
        let regex_pattern = format!("^{}$", regex::escape(pattern).replace("\\*", ".*"));
        if let Ok(re) = regex::Regex::new(&regex_pattern) {
            let computed: Vec<String> = match self.computed_fields.read() {
                Ok(guard) => guard.iter().filter(|f| re.is_match(f)).cloned().collect(),
                Err(poisoned) => poisoned
                    .get_ref()
                    .iter()
                    .filter(|f| re.is_match(f))
                    .cloned()
                    .collect(),
            };
            let mut computed = computed;
            computed.sort();
            for c in computed {
                if !cols.contains(&c) {
                    cols.push(c);
                }
            }
        }
        cols
    }

    pub(crate) fn is_computed_field(&self, field: &str) -> bool {
        match self.computed_fields.read() {
            Ok(guard) => guard.contains(field),
            Err(poisoned) => poisoned.get_ref().contains(field),
        }
    }

    /// Whether `field` (the PRE-normalization name) was created with a new
    /// value by a pipeline stage upstream of the one currently being generated
    /// — and therefore shadows any same-named schema field / UDM alias
    /// (NAN-1341). See `upstream_computed_fields`.
    pub(crate) fn is_upstream_computed_field(&self, field: &str) -> bool {
        match self.upstream_computed_fields.read() {
            Ok(guard) => guard.contains(field),
            Err(poisoned) => poisoned.get_ref().contains(field),
        }
    }

    /// Record the value-computed outputs of a just-generated pipeline stage so
    /// the stages after it see them as shadowing columns (NAN-1341).
    fn note_upstream_computed(&self, cmd: &Command) {
        let added = {
            let guard = self
                .upstream_computed_fields
                .read()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            field_analysis::upstream_computed_added_by_command(cmd, &guard)
        };
        match self.upstream_computed_fields.write() {
            Ok(mut guard) => guard.extend(added),
            Err(poisoned) => poisoned.into_inner().extend(added),
        }
    }

    /// Swap the upstream-computed scope (NAN-1341). A subsearch is its own
    /// pipeline scope — its references must not see the outer pipeline's
    /// computed fields — so its generation swaps in an empty set and restores
    /// the outer scope afterwards. Also used to reset the scope at the start
    /// and end of `generate_with_options`.
    fn swap_upstream_computed(&self, new: HashSet<String>) -> HashSet<String> {
        match self.upstream_computed_fields.write() {
            Ok(mut guard) => std::mem::replace(&mut *guard, new),
            Err(poisoned) => std::mem::replace(&mut *poisoned.into_inner(), new),
        }
    }

    /// Resolve a `{func}_{field}` reference to the actual output column of an
    /// UN-aliased aggregation earlier in this pipeline (NAN-1339). Returns
    /// `None` for everything else — including names an explicit alias already
    /// owns (real columns win at population time).
    pub(crate) fn agg_reference_alias(&self, field: &str) -> Option<String> {
        match self.agg_reference_aliases.read() {
            Ok(guard) => guard.get(field).cloned(),
            Err(poisoned) => poisoned.get_ref().get(field).cloned(),
        }
    }

    /// Set the max elements for groupArray/groupUniqArray
    pub fn with_max_group_array_size(mut self, size: usize) -> Self {
        self.max_group_array_size = size;
        self
    }

    /// Set the default row limit for mvexpand
    pub fn with_max_mvexpand_rows(mut self, rows: usize) -> Self {
        self.max_mvexpand_rows = rows;
        self
    }

    /// Generate SQL from a Query AST with time range constraints
    pub fn generate(&self, query: &Query, time_range: &TimeRange) -> Result<String, SqlGenError> {
        self.generate_with_options(query, time_range, &QueryOptions::default())
    }

    /// Generate SQL from a Query AST with time range constraints and options
    pub fn generate_with_options(
        &self,
        query: &Query,
        time_range: &TimeRange,
        options: &QueryOptions,
    ) -> Result<String, SqlGenError> {
        // Store time range for subsearch IN subquery generation
        // Use write_or_default to avoid panic on poisoned lock
        match self.generation_time_range.write() {
            Ok(mut guard) => *guard = Some(time_range.clone()),
            Err(poisoned) => *poisoned.into_inner() = Some(time_range.clone()),
        }

        // Record the fields computed by pipeline commands (risk, eval, stats
        // aliases, …) so `field_to_sql_expr` references them as real columns
        // instead of JSON-extracting from `metadata`/`ext` (NAN-1236).
        let computed = field_analysis::collect_computed_field_names(query);
        let agg_aliases = field_analysis::collect_agg_reference_aliases(query, &computed);
        match self.computed_fields.write() {
            Ok(mut guard) => *guard = computed,
            Err(poisoned) => *poisoned.into_inner() = computed,
        }
        match self.agg_reference_aliases.write() {
            Ok(mut guard) => *guard = agg_aliases,
            Err(poisoned) => *poisoned.into_inner() = agg_aliases,
        }

        let mut ctx = GeneratorContext::new(&self.table_name, &self.time_column, time_range);
        ctx.use_cache = options.use_cache;
        // With exactly ONE resolve_identity in the pipeline, the bare
        // `identity_*` names are unambiguous — the stage emits them as extra
        // aliases of the prefixed columns (NAN-1346 #5). Two resolved entities
        // keep requiring the prefix.
        ctx.single_resolve_identity = self
            .collect_stages(query)
            .iter()
            .filter(|st| matches!(st, QueryStage::Command(Command::ResolveIdentity { .. })))
            .count()
            == 1;
        ctx.limit = options.limit;

        // Analyze query to determine required fields for optimization
        // In table_view mode, always use minimal fields for fast initial load
        ctx.required_fields =
            field_analysis::analyze_required_fields(query, options.table_view, self.profile.as_ref());
        // NAN-1555: a metrics rollup read aggregates the pre-aggregated state
        // columns (value_sum/value_count/value_state/value_min/value_max) that the
        // slim projection never lists — and the slim list names raw `value`/
        // `timestamp`, which the rollup lacks. `SELECT *` so every state column
        // flows from the base read into the aggregation stage. Rollup-only.
        if self.is_metrics_rollup() {
            ctx.required_fields = None;
        }

        // Identify ext JSON fields referenced by the query so they can be
        // materialized in stage_0 SELECT, making them visible to downstream CTEs
        ctx.ext_fields = field_analysis::analyze_ext_fields(query, self.profile.as_ref());

        // Fresh upstream-computed scope for this generation (NAN-1341).
        self.swap_upstream_computed(HashSet::new());

        let result = self.generate_query(query, &mut ctx);
        match self.generation_time_range.write() {
            Ok(mut guard) => *guard = None,
            Err(poisoned) => *poisoned.into_inner() = None,
        }
        match self.computed_fields.write() {
            Ok(mut guard) => guard.clear(),
            Err(poisoned) => poisoned.into_inner().clear(),
        }
        self.swap_upstream_computed(HashSet::new());
        result
    }

    /// Generate SQL for a query, handling piped commands via CTEs
    fn generate_query(
        &self,
        query: &Query,
        ctx: &mut GeneratorContext,
    ) -> Result<String, SqlGenError> {
        // Collect all stages (search + commands)
        let stages = self.collect_stages(query);

        if stages.is_empty() {
            return Err(SqlGenError::EmptyQuery);
        }

        // Single stage - no CTEs needed
        if stages.len() == 1 {
            return self.generate_single_stage(&stages[0], ctx);
        }

        // Optimization: search | head N -> single query with LIMIT (no CTEs)
        // This is much faster than CTE approach for simple limit queries
        if stages.len() == 2 {
            if let (QueryStage::Search(expr), QueryStage::Command(Command::Head { count })) =
                (&stages[0], &stages[1])
            {
                return self.generate_search_with_limit(expr, *count, ctx);
            }
        }

        // Multiple stages - use CTEs
        self.generate_cte_query(&stages, ctx)
    }

    /// Generate optimized SQL for search | head N (avoids CTE overhead)
    fn generate_search_with_limit(
        &self,
        expr: &SearchExpr,
        limit: usize,
        ctx: &mut GeneratorContext,
    ) -> Result<String, SqlGenError> {
        let where_clause = self.generate_search_expr(expr)?;
        let select_clause = self.build_select_clause(&ctx.required_fields, &ctx.ext_fields);

        let selective = has_selective_indexed_eq(expr, self.profile.as_ref());

        // Single WHERE with all conjuncts — `optimize_move_to_prewhere` decides
        // PREWHERE placement (NAN-1412: an explicit PREWHERE disables the auto
        // move, leaving every non-promoted filter after the full-projection read).
        // Single query with ORDER BY and LIMIT together - much faster than CTE approach
        Ok(format!(
            "SELECT {} FROM {} WHERE {tc} BETWEEN '{}' AND '{}' AND ({}) ORDER BY {tc} DESC LIMIT {} {}",
            select_clause,
            ctx.table_name,
            ctx.time_range.start.format("%Y-%m-%d %H:%M:%S%.6f"),
            ctx.time_range.end.format("%Y-%m-%d %H:%M:%S%.6f"),
            where_clause,
            limit,
            generate_settings(ctx.use_cache, selective, false),
            tc = ctx.time_column,
        ))
    }

    /// Collect all stages from a query (flattens nested Piped queries)
    fn collect_stages<'a>(&self, query: &'a Query) -> Vec<QueryStage<'a>> {
        let mut stages = Vec::new();
        self.collect_stages_recursive(query, &mut stages);
        stages
    }

    fn collect_stages_recursive<'a>(&self, query: &'a Query, stages: &mut Vec<QueryStage<'a>>) {
        match query {
            Query::Search(expr) => {
                stages.push(QueryStage::Search(expr));
            }
            Query::Piped { source, command } => {
                self.collect_stages_recursive(source, stages);
                stages.push(QueryStage::Command(command));
            }
        }
    }

    /// Default limit for queries without an explicit `| head N`.
    const DEFAULT_RESULT_LIMIT: usize = 1_000_000;

    /// Generate SQL for a single-stage query (no CTEs)
    /// Emits a single WHERE (time bounds + filters); `optimize_move_to_prewhere`
    /// owns placement (NAN-1412)
    fn generate_single_stage(
        &self,
        stage: &QueryStage,
        ctx: &mut GeneratorContext,
    ) -> Result<String, SqlGenError> {
        match stage {
            QueryStage::Search(expr) => {
                let where_clause = self.generate_search_expr(expr)?;
                let select_clause = self.build_select_clause(&ctx.required_fields, &ctx.ext_fields);

                let selective = has_selective_indexed_eq(expr, self.profile.as_ref());

                // Single WHERE — `optimize_move_to_prewhere` does placement (NAN-1412).
                // Apply the caller's result limit when one was requested; with
                // ctx.limit == None the executor owns pagination and injects
                // its own LIMIT/OFFSET — baking one here turned that injection
                // into a silent no-op (NAN-1410).
                let limit_clause = match ctx.limit {
                    Some(limit) => format!("LIMIT {} ", limit),
                    None => String::new(),
                };
                Ok(format!(
                    "SELECT {} FROM {} WHERE {tc} BETWEEN '{}' AND '{}' AND ({}) ORDER BY {tc} DESC {}{}",
                    select_clause,
                    ctx.table_name,
                    ctx.time_range.start.format("%Y-%m-%d %H:%M:%S%.6f"),
                    ctx.time_range.end.format("%Y-%m-%d %H:%M:%S%.6f"),
                    where_clause,
                    limit_clause,
                    generate_settings(ctx.use_cache, selective, false),
                    tc = ctx.time_column,
                ))
            }
            QueryStage::Command(_) => Err(SqlGenError::UnsupportedOperation(
                "Command without search source".to_string(),
            )),
        }
    }

    /// Generate SQL with CTEs for multi-stage queries
    fn generate_cte_query(
        &self,
        stages: &[QueryStage],
        ctx: &mut GeneratorContext,
    ) -> Result<String, SqlGenError> {
        // `asset` renders a terminal dossier view (DisplayType::Asset, built in
        // post-processing) — it is not a columnar transform, and its rendered
        // attributes (asset_criticality, …) are not pipeline fields. A command
        // piped after it (`| asset X | where asset_criticality …`) previously
        // fell through to ext JSON extraction and failed at execution or
        // silently matched nothing (NAN-1346 #5). Refuse with guidance.
        if let Some(pos) = stages
            .iter()
            .position(|st| matches!(st, QueryStage::Command(Command::Asset { .. })))
        {
            if pos != stages.len() - 1 {
                return Err(SqlGenError::InvalidQuery(
                    "asset renders an asset dossier and must be the last command in the \
                     query. Filter and shape results before it (e.g. `src_host=server-01 \
                     | where ... | asset`)"
                        .to_string(),
                ));
            }
        }
        let mut sql = String::from("WITH ");
        let mut cte_parts = Vec::new();
        let mut last_stage_has_ordering = false;
        let mut has_aggregate_or_projection = false;
        let mut has_non_timechart_aggregation = false;

        // Collect MATERIALIZED columns needed by downstream Tree commands.
        // MATERIALIZED columns are excluded from SELECT * so they must be
        // explicitly named in the base CTE for downstream CTEs to reference them.
        let mut materialized_cols: Vec<String> = Vec::new();
        // Check if downstream commands re-query ClickHouse themselves (asset/tree),
        // meaning the initial query is only for identifier detection / small sample.
        // In that case, push ctx.limit into the base CTE to avoid unbounded scans.
        let has_requery_command = stages.iter().any(|s| {
            matches!(
                s,
                QueryStage::Command(Command::Asset { .. })
                    | QueryStage::Command(Command::Tree { .. })
                    | QueryStage::Command(Command::Cloud { .. })
            )
        });
        for stage in stages.iter() {
            if let QueryStage::Command(Command::Tree {
                parent_field,
                child_field,
                ..
            }) = stage
            {
                // Skip fields already re-added by build_select_clause's MATERIALIZED_COLUMNS
                // list (e.g. process_guid/parent_process_guid) — adding them again would
                // produce a duplicate column in `SELECT *, ...` (NAN-1147).
                for f in [parent_field, child_field] {
                    // A parent-less positional `tree <field>` carries an empty
                    // parent_field — generation refuses it later (commands.rs),
                    // but never emit an empty identifier into the select list.
                    // A field the profile maps to a DIFFERENT column (an OCSF
                    // class-split concept or a UDM alias like
                    // parent_process_guid → "actor.process.uid") must not be
                    // injected raw either — the resolved column is already in
                    // the wide base clause, and the raw name does not exist on
                    // the table (NAN-1346 #5). UDM resolves every known field
                    // to itself, so this is byte-identical there.
                    let maps_elsewhere = self.class_split_column(f).is_some()
                        || matches!(
                            self.profile.resolve(f),
                            FieldResolution::ExplicitColumn(ref c) if c != f
                        )
                        || matches!(self.profile.resolve(f), FieldResolution::JsonPath { .. });
                    if !f.is_empty()
                        && !maps_elsewhere
                        && !self.profile.materialized_columns().contains(&f.as_str())
                    {
                        materialized_cols.push(escape_identifier(f));
                    }
                }
            }
        }
        materialized_cols.sort();
        materialized_cols.dedup();

        for (i, stage) in stages.iter().enumerate() {
            let cte_name = format!("stage_{}", i);
            let cte_sql = match stage {
                QueryStage::Search(expr) => {
                    let where_clause = self.generate_search_expr(expr)?;
                    // NAN-876: stage_0 of a multi-stage CTE chain must
                    // preserve the physical `action` column so downstream
                    // stages (and LLM-generated commands like `| where
                    // action="..."` or `| stats count by action`) can
                    // resolve it by its UDM name. The `action AS
                    // event_type` alias is still emitted so the canonical
                    // name is also available; the redundant `action`
                    // column is dropped once at the outer SELECT below
                    // when the last stage left it in scope.
                    let base_select = self.build_select_clause_with_options(
                        &ctx.required_fields,
                        &ctx.ext_fields,
                        true,
                    );
                    let select_clause = if materialized_cols.is_empty() {
                        base_select
                    } else {
                        format!("{}, {}", base_select, materialized_cols.join(", "))
                    };

                    // Single WHERE — `optimize_move_to_prewhere` does placement (NAN-1412).
                    // For asset/tree commands, inject LIMIT into the base CTE to avoid
                    // unbounded scans — these commands re-query ClickHouse for actual data.
                    let limit_clause = if has_requery_command {
                        // Asset/tree/cloud always pass an explicit limit; fall
                        // back to the safety bound so the base CTE stays
                        // bounded even for a pagination-owning caller (None).
                        format!(
                            "\n  ORDER BY {} DESC\n  LIMIT {}",
                            ctx.time_column,
                            ctx.limit.unwrap_or(Self::DEFAULT_RESULT_LIMIT)
                        )
                    } else {
                        String::new()
                    };
                    format!(
                        "{} AS (\n  SELECT {} FROM {}\n  WHERE {tc} BETWEEN '{}' AND '{}'\n  AND ({}){}\n)",
                        cte_name,
                        select_clause,
                        ctx.table_name,
                        ctx.time_range.start.format("%Y-%m-%d %H:%M:%S%.6f"),
                        ctx.time_range.end.format("%Y-%m-%d %H:%M:%S%.6f"),
                        where_clause,
                        limit_clause,
                        tc = ctx.time_column,
                    )
                }
                QueryStage::Command(cmd) => {
                    let prev_cte = format!("stage_{}", i - 1);
                    // Track commands that affect column availability or have their own ordering
                    match cmd {
                        Command::Sort { .. } | Command::Tail { .. } => {
                            if i == stages.len() - 1 {
                                last_stage_has_ordering = true;
                            }
                        }
                        Command::Timechart { .. } => {
                            // Timechart has its own ordering AND transforms columns (no timestamp)
                            if i == stages.len() - 1 {
                                last_stage_has_ordering = true;
                            }
                            has_aggregate_or_projection = true;
                        }
                        Command::Stats { .. } | Command::Chart { .. } => {
                            // Stats and Chart produce GROUP BY aggregations
                            has_aggregate_or_projection = true;
                            has_non_timechart_aggregation = true;
                        }
                        Command::Table { .. } | Command::Fields { keep: true, .. } => {
                            // Table and Fields (include mode) commands may not include timestamp column
                            has_aggregate_or_projection = true;
                        }
                        Command::Top { .. } | Command::Rare { .. } => {
                            // Top/Rare produce GROUP BY aggregations
                            has_aggregate_or_projection = true;
                            has_non_timechart_aggregation = true;
                        }
                        Command::Return { .. }
                        | Command::Transaction { .. }
                        | Command::Sequence { .. }
                        | Command::Funnel { .. }
                        | Command::Anomaly { .. }
                        | Command::Tree { .. }
                        | Command::Asset { .. }
                        | Command::Cloud { .. } => {
                            // These commands also produce aggregated/projected results
                            has_aggregate_or_projection = true;
                        }
                        Command::Rename { .. } | Command::Fields { keep: false, .. } => {
                            // NAN-876: these don't aggregate, but they CAN strip
                            // `action` from the CTE schema — `rename action AS x`
                            // or `fields - action`. The flag's secondary job is
                            // gating the outer SELECT's `* EXCEPT (action)`
                            // collapse; if action might be gone, we must not
                            // attempt the EXCEPT or CH will reject the column
                            // reference.
                            has_aggregate_or_projection = true;
                        }
                        _ => {}
                    }
                    let cte =
                        self.generate_command_cte(&cte_name, &prev_cte, cmd, ctx, &stages[..i])?;
                    // This stage's value-computed outputs (rex captures, eval
                    // assignments, …) shadow schema fields / UDM aliases for
                    // every stage after it (NAN-1341).
                    self.note_upstream_computed(cmd);
                    cte
                }
            };
            cte_parts.push(cte_sql);
            ctx.current_stage = i;
        }

        sql.push_str(&cte_parts.join(",\n"));

        // Final SELECT from the last CTE
        // CTE final SELECT operates on already-filtered/aggregated data,
        // so optimize_read_in_order is irrelevant here (pass false).
        let last_cte = format!("stage_{}", stages.len() - 1);
        let mut settings = generate_settings(ctx.use_cache, false, has_non_timechart_aggregation);
        // An append UNION can produce Variant-typed columns when the arms carry
        // different types under the same name (e.g. a numeric group-by column
        // unioned with an eval'd string literal). ClickHouse rejects ORDER
        // BY/GROUP BY on Variant/Dynamic by default — opt in for append
        // queries only, matching append's type-loose union semantics.
        if stages
            .iter()
            .any(|s| matches!(s, QueryStage::Command(Command::Append { .. })))
        {
            settings.push_str(
                ", allow_suspicious_types_in_order_by=1, allow_suspicious_types_in_group_by=1",
            );
        }

        // NAN-876: stage_0 preserves the physical `action` column for
        // downstream stages, so the last CTE may still carry it alongside
        // its `event_type` alias. When no transforming command stripped
        // those columns (i.e. the pipeline is search → optional
        // sort/filter/head/eval), apply the NAN-671 EXCEPT collapse once
        // at the outer SELECT so the user-facing result keeps only
        // `event_type`. When an aggregation/projection ran, the last
        // CTE's schema is whatever that command produced (`action` is
        // gone), so plain `SELECT *` is correct.
        let select_list = if has_aggregate_or_projection {
            "*".to_string()
        } else {
            // Profile-aware terminal collapse: UDM → `* EXCEPT (action)`; OCSF
            // (no default-view renames) → bare `*` so we never reference a
            // nonexistent UDM `action` column.
            self.outer_select_except_list()
        };
        if last_stage_has_ordering || has_aggregate_or_projection {
            write!(sql, "\nSELECT {} FROM {} {}", select_list, last_cte, settings).unwrap();
        } else {
            // NAN-1555: order by the active dataset's time column (`start_time` for
            // spans) — `timestamp` does not exist on `otel_spans`. Logs keep
            // `timestamp` (byte-identical).
            write!(
                sql,
                "\nSELECT {} FROM {} ORDER BY {} DESC {}",
                select_list, last_cte, self.time_column, settings
            )
            .unwrap();
        }

        Ok(sql)
    }

    /// Generate a CTE for a command stage
    ///
    /// `prior_stages` is the pipeline prefix feeding this stage (everything
    /// before the current command) — `append` uses it to compute the main
    /// side's output shape so the UNION arms can be column-aligned.
    fn generate_command_cte(
        &self,
        cte_name: &str,
        source_cte: &str,
        cmd: &Command,
        ctx: &mut GeneratorContext,
        prior_stages: &[QueryStage],
    ) -> Result<String, SqlGenError> {
        // Handle join specially since it needs to generate subsearch SQL
        if let Command::Join {
            join_type,
            fields,
            subsearch,
            max,
            overwrite: _,
            maxout,
            subsearch_dataset,
        } = cmd
        {
            let limit = resolve_subsearch_limit(*maxout);
            let inner_sql = self.generate_join_sql(
                source_cte,
                join_type,
                fields,
                subsearch,
                *max,
                limit,
                ctx,
                prior_stages,
                *subsearch_dataset,
            )?;
            return Ok(format!("{} AS (\n{}\n)", cte_name, inner_sql));
        }

        // Handle append specially - UNION ALL with subsearch
        if let Command::Append { subsearch, maxout } = cmd {
            let limit = resolve_subsearch_limit(*maxout);
            let inner_sql =
                self.generate_append_sql(source_cte, subsearch, limit, ctx, prior_stages)?;
            return Ok(format!("{} AS (\n{}\n)", cte_name, inner_sql));
        }

        let inner_sql = self.generate_command_sql_with_ctx(source_cte, cmd, ctx)?;
        Ok(format!("{} AS (\n{}\n)", cte_name, inner_sql))
    }

    /// Generate SQL for an APPEND command (UNION ALL)
    ///
    /// ClickHouse `UNION ALL` is positional: both arms must produce the same
    /// number of columns, in the same order. nPL's `append` instead aligns
    /// by name and pads missing columns with null. To match that, when both
    /// sides have a statically known projection (`stats`/`chart`/`table`/…)
    /// the arms are re-projected onto the name-union of their columns with
    /// `NULL AS <col>` padding (NAN-1346 #3). When both sides are unprojected
    /// passthroughs they share the identical base select clause (see
    /// [`generate_subsearch_sql`]) so the positional union is already aligned.
    /// Any other mix (raw events + aggregate, or a command whose output shape
    /// isn't modeled) can't be aligned — return an actionable error instead of
    /// letting ClickHouse fail with a bare Code 53 TYPE_MISMATCH.
    fn generate_append_sql(
        &self,
        source_cte: &str,
        subsearch: &Query,
        limit: usize,
        ctx: &GeneratorContext,
        prior_stages: &[QueryStage],
    ) -> Result<String, SqlGenError> {
        // Generate the subsearch SQL
        let subsearch_sql = self.generate_subsearch_sql(subsearch, ctx, limit)?;

        let main_shape = self.pipeline_output_shape(prior_stages);
        let sub_shape = self.pipeline_output_shape(&self.collect_stages(subsearch));

        match (main_shape, sub_shape) {
            (OutputShape::Columns(main_cols), OutputShape::Columns(sub_cols)) => {
                // Name-union, main side's order first, then subsearch-only columns
                let mut union_cols = main_cols.clone();
                for c in &sub_cols {
                    if !union_cols.contains(c) {
                        union_cols.push(c.clone());
                    }
                }
                let project = |side: &[String]| -> String {
                    union_cols
                        .iter()
                        .map(|c| {
                            if side.contains(c) {
                                escape_identifier(c)
                            } else {
                                format!("NULL AS {}", escape_identifier(c))
                            }
                        })
                        .collect::<Vec<_>>()
                        .join(", ")
                };
                // The subsearch SQL is either a bare SELECT (single-stage) or
                // already parenthesized (multi-stage) — normalize to a
                // parenthesized table expression.
                let trimmed = subsearch_sql.trim();
                let sub_expr = if trimmed.starts_with('(') {
                    trimmed.to_string()
                } else {
                    format!("({})", trimmed)
                };
                Ok(format!(
                    "  SELECT {} FROM {}\n  UNION ALL\n  SELECT {} FROM {} AS _append_sub",
                    project(&main_cols),
                    source_cte,
                    project(&sub_cols),
                    sub_expr
                ))
            }
            (OutputShape::Wide(main_extra), OutputShape::Wide(sub_extra))
                if main_extra == sub_extra =>
            {
                // Both sides are passthroughs over the same base select clause
                // (plus identical eval/rename extras) — positionally aligned.
                Ok(format!(
                    "  SELECT * FROM {}\n  UNION ALL\n{}",
                    source_cte, subsearch_sql
                ))
            }
            _ => Err(SqlGenError::UnsupportedOperation(
                "append: the main search and the appended subsearch produce different result \
                 shapes that cannot be combined. Aggregate or project explicit fields on both \
                 sides (e.g. end each with `stats ...` or `table ...`) so append can align \
                 their columns"
                    .to_string(),
            )),
        }
    }

    /// Whether the full pipeline's terminal output is still wide — i.e.
    /// `SELECT *`-shaped over the base table (filters / sort / head / dedup /
    /// eval / rename / join only).
    ///
    /// Consumed by the field-stats companion gate (NAN-1395): the companion
    /// aggregates `topK`/`uniq` over the base table's column inventory, which
    /// only resolves against a wide output. `Columns(...)` shapes
    /// (stats/chart/table/fields) project a new column set with none of the
    /// base columns, and `Unknown` shapes (funnel/sequence/transaction and
    /// every unmodeled command) cannot be proven safe — both must skip the
    /// companion rather than fire a guaranteed-Code-47 query (the semantic
    /// sibling of NAN-1315's Code 62 slicing bug). `WideJoined` (NAN-1420)
    /// also skips: the base columns survive, but the leaked `sub.<col>`
    /// duplicates make the inventory unclean — same conservative treatment the
    /// shape got when it modeled as `Unknown`.
    pub fn pipeline_output_is_wide(&self, query: &Query) -> bool {
        matches!(
            self.pipeline_output_shape(&self.collect_stages(query)),
            OutputShape::Wide(_)
        )
    }

    /// Compute the statically known output shape of a pipeline stage prefix.
    ///
    /// Used by `append` to align UNION arms (see [`generate_append_sql`]).
    /// Conservative by design: commands whose output projection isn't modeled
    /// here yield [`OutputShape::Unknown`], which makes `append` refuse with an
    /// actionable error rather than emit a misaligned UNION. Column names must
    /// match what the corresponding SQL generators alias their outputs to:
    /// `stats`/`chart` alias group-bys to `by_field_output_name(f)` — the raw
    /// name when an upstream stage value-computed it (NAN-1341), the
    /// normalized canonical name otherwise — and aggregations to
    /// `Aggregation::output_alias()` (aggregation.rs); `table`/`fields` alias
    /// to the requested name (commands.rs).
    fn pipeline_output_shape(&self, stages: &[QueryStage]) -> OutputShape {
        let mut shape = OutputShape::Unknown;
        // Mirror the generator's upstream value-computed tracking so the
        // modeled group-by column names match the emitted aliases (NAN-1341).
        let mut upstream: HashSet<String> = HashSet::new();
        for stage in stages {
            match stage {
                QueryStage::Search(_) => shape = OutputShape::Wide(Vec::new()),
                QueryStage::Command(cmd) => {
                    shape = match cmd {
                        // Row filters / reorderings — projection unchanged
                        Command::Where { .. }
                        | Command::Sort { .. }
                        | Command::Head { .. }
                        | Command::Tail { .. }
                        | Command::Reverse
                        | Command::Dedup { .. } => shape,
                        Command::Stats {
                            aggregations,
                            group_by,
                        }
                        | Command::Chart {
                            aggregations,
                            group_by,
                        } => {
                            let mut cols: Vec<String> = group_by
                                .as_deref()
                                .unwrap_or(&[])
                                .iter()
                                .map(|f| {
                                    if upstream.contains(f.as_str()) {
                                        f.clone()
                                    } else {
                                        normalize_field_name(f).to_string()
                                    }
                                })
                                .collect();
                            cols.extend(aggregations.iter().map(|a| a.output_alias()));
                            OutputShape::Columns(cols)
                        }
                        // eval/rename emit `SELECT *, expr AS name` — appended columns
                        Command::Eval { assignments } => {
                            let mut cur = shape;
                            for a in assignments {
                                match &mut cur {
                                    OutputShape::Wide(extra) | OutputShape::WideJoined(extra) => {
                                        if !extra.contains(&a.field) {
                                            extra.push(a.field.clone());
                                        }
                                    }
                                    OutputShape::Columns(cols) => {
                                        if !cols.contains(&a.field) {
                                            cols.push(a.field.clone());
                                        }
                                    }
                                    OutputShape::Unknown => {}
                                }
                            }
                            cur
                        }
                        Command::Rename { mappings } => {
                            let mut cur = shape;
                            for m in mappings {
                                match &mut cur {
                                    OutputShape::Wide(extra) | OutputShape::WideJoined(extra) => {
                                        if !extra.contains(&m.to) {
                                            extra.push(m.to.clone());
                                        }
                                    }
                                    OutputShape::Columns(cols) => {
                                        if !cols.contains(&m.to) {
                                            cols.push(m.to.clone());
                                        }
                                    }
                                    OutputShape::Unknown => {}
                                }
                            }
                            cur
                        }
                        Command::Table { fields } => {
                            // Wildcard patterns expand against live columns —
                            // not statically known here
                            if fields.iter().any(|f| f.name.contains('*')) {
                                OutputShape::Unknown
                            } else {
                                OutputShape::Columns(
                                    fields
                                        .iter()
                                        .map(|f| f.alias.clone().unwrap_or_else(|| f.name.clone()))
                                        .collect(),
                                )
                            }
                        }
                        Command::Fields { keep: true, fields } => {
                            if fields.iter().any(|f| f.contains('*')) {
                                OutputShape::Unknown
                            } else {
                                OutputShape::Columns(fields.clone())
                            }
                        }
                        // A join with a known sub shape projects `main.*` plus
                        // the sub's non-key columns under bare names (see
                        // generate_join_sql) — model it like eval-added columns.
                        Command::Join {
                            subsearch, fields, ..
                        } => {
                            let sub = self.pipeline_output_shape(&self.collect_stages(subsearch));
                            let key_names: Vec<String> = fields
                                .iter()
                                .map(|f| normalize_field_name(f).to_string())
                                .collect();
                            match (shape, sub) {
                                (OutputShape::Wide(mut e), OutputShape::Columns(s)) => {
                                    for c in s {
                                        if !key_names.contains(&c) && !e.contains(&c) {
                                            e.push(c);
                                        }
                                    }
                                    OutputShape::Wide(e)
                                }
                                // A wide-joined main side keeps its wide
                                // guarantee through a projected sub (the
                                // generated SELECT is `main.*` + the sub's
                                // bare non-key columns) — but it stays
                                // WideJoined: `main.*` still carries the
                                // earlier join's leaked `sub.<col>` columns.
                                (OutputShape::WideJoined(mut e), OutputShape::Columns(s)) => {
                                    for c in s {
                                        if !key_names.contains(&c) && !e.contains(&c) {
                                            e.push(c);
                                        }
                                    }
                                    OutputShape::WideJoined(e)
                                }
                                (OutputShape::Columns(mut m), OutputShape::Columns(s)) => {
                                    for c in s {
                                        if !key_names.contains(&c) && !m.contains(&c) {
                                            m.push(c);
                                        }
                                    }
                                    OutputShape::Columns(m)
                                }
                                // Wide main side joined to a wide(-joined) sub:
                                // the stage emits `SELECT *` over the join, so
                                // every base physical column survives bare on
                                // the main side, but the sub's columns leak in
                                // as literal `sub.<col>` duplicates — model the
                                // wide guarantee WITHOUT claiming a clean Wide
                                // (NAN-1420). Used to be Unknown, which made a
                                // chained join's key fall back to the legacy
                                // bare emission (Code 47 under OCSF).
                                (
                                    OutputShape::Wide(e) | OutputShape::WideJoined(e),
                                    OutputShape::Wide(_) | OutputShape::WideJoined(_),
                                ) => OutputShape::WideJoined(e),
                                _ => OutputShape::Unknown,
                            }
                        }
                        // A nested append: combine shapes the same way the
                        // generated UNION does
                        Command::Append { subsearch, .. } => {
                            let sub = self.pipeline_output_shape(&self.collect_stages(subsearch));
                            match (shape, sub) {
                                (OutputShape::Columns(mut m), OutputShape::Columns(s)) => {
                                    for c in s {
                                        if !m.contains(&c) {
                                            m.push(c);
                                        }
                                    }
                                    OutputShape::Columns(m)
                                }
                                (OutputShape::Wide(m), OutputShape::Wide(s)) if m == s => {
                                    OutputShape::Wide(m)
                                }
                                _ => OutputShape::Unknown,
                            }
                        }
                        _ => OutputShape::Unknown,
                    };
                    let added =
                        field_analysis::upstream_computed_added_by_command(cmd, &upstream);
                    upstream.extend(added);
                }
            }
        }
        shape
    }

    /// Resolve a join key to the column reference carried by ONE side of the
    /// join, given that side's statically known output shape (NAN-1413).
    ///
    /// Historically both sides emitted `escape_identifier(normalize_field_name(f))`
    /// — a raw UDM column name. Under OCSF a class-split concept (`user`, `src_host`,
    /// `process_name`, …) has no such physical column, so `ON main."user" = sub."user"`
    /// died with Code 47 UNKNOWN_IDENTIFIER while `stats by user` (which resolves
    /// through the profile to `user_unified`) worked. Resolution rules, per side:
    ///
    /// - A [`OutputShape::Wide`] side still carries the base table's physical
    ///   columns — resolve through the active profile exactly like `stats by`
    ///   does: the indexed unified column for class-split concepts (NAN-1333),
    ///   else the promoted/explicit column (`field_access_expr`). Both are plain
    ///   (possibly dotted, quote-escaped) column names, never expressions, so
    ///   they stay valid under a `main.`/`sub.` qualifier. Exception: an eval /
    ///   rename that value-computed exactly the normalized name shadows the
    ///   schema column (NAN-1341) — the bare name IS the real column then.
    ///   A [`OutputShape::WideJoined`] side (a wide pipeline that already went
    ///   through a wide-sub join, NAN-1420) carries the same wide guarantee —
    ///   every base physical column is still present bare — so it resolves
    ///   identically; the extra leaked `sub.<col>` columns are all dotted names
    ///   that can never collide with a normalized key.
    /// - A projected ([`OutputShape::Columns`]) side aliases its outputs back to
    ///   the normalized name (`stats by user` emits `user_unified AS user` under
    ///   OCSF) — the bare normalized reference IS the real column there.
    /// - Anything else (ext/unknown fields, [`OutputShape::Unknown`] sides, a
    ///   projected side that dropped the key) keeps the legacy normalized
    ///   reference byte-for-byte — including its legacy failure modes.
    ///
    /// Under UDM every branch collapses to `escape_identifier(normalize_field_name(f))`
    /// (no class split; `field_access_expr` of an explicit column is the escaped
    /// name itself), so UDM join SQL is byte-identical to the pre-NAN-1413 form.
    ///
    /// NAN-1562: every column resolution flows through `resolver`, the generator
    /// whose profile/table the side reads against. For a same-table join this is
    /// always `self` (byte-identical to the pre-NAN-1562 form). For a CROSS-dataset
    /// join the SUB side must pass `sub_gen` (the subsearch dataset's generator):
    /// the field is canonicalized through `resolver.canonicalize_field` (which
    /// KEEPS `service_name` for spans/metrics rather than the free
    /// `normalize_field_name` mapping it to the logs-only `cloud_service`) and the
    /// column is resolved against `resolver`'s profile, so `ON main.k = sub.k`
    /// references a column that actually exists in `otel_spans`/`otel_metrics`
    /// (was Code 47 UNKNOWN_IDENTIFIER when the sub side used the outer profile).
    fn join_key_column(
        &self,
        resolver: &ClickHouseSqlGenerator,
        field: &str,
        shape: &OutputShape,
    ) -> String {
        let normalized = resolver.canonicalize_field(field);
        if let OutputShape::Wide(extra) | OutputShape::WideJoined(extra) = shape {
            if !extra.iter().any(|c| c == normalized) {
                if let Some(col) = resolver.class_split_column(normalized) {
                    return escape_identifier(&col);
                }
                if resolver.resolves_to_column(normalized) {
                    return resolver.field_access_expr(normalized, "String");
                }
            }
        }
        escape_identifier(normalized)
    }

    /// Generate SQL for a JOIN command
    #[allow(clippy::too_many_arguments)]
    #[allow(clippy::too_many_arguments)]
    fn generate_join_sql(
        &self,
        source_cte: &str,
        join_type: &JoinType,
        fields: &[String],
        subsearch: &Query,
        max: usize,
        limit: usize,
        ctx: &GeneratorContext,
        prior_stages: &[QueryStage],
        subsearch_dataset: Option<otel::Dataset>,
    ) -> Result<String, SqlGenError> {
        // NAN-1562: cross-dataset only when the selected dataset's table differs
        // from the outer table — `dataset=logs` from a logs query stays
        // byte-identical (no clone, no settings, same ctx).
        let cross_dataset = subsearch_dataset
            .map(|ds| ds.table_name() != self.table_name)
            .unwrap_or(false);

        // NAN-1562 bound: a cross-dataset join MUST have positional key fields —
        // a keyless cross-dataset join is a Cartesian product across two tables.
        // Reject with an actionable error (the per-key LIMIT BY also needs keys).
        if cross_dataset && fields.is_empty() {
            return Err(SqlGenError::UnsupportedOperation(
                "cross-dataset correlation requires a join key, e.g. \
                 `| join trace_id [dataset=logs …]`"
                    .to_string(),
            ));
        }

        // Generate the subsearch SQL. For a cross-dataset join, build a SCOPED
        // sub-generator pointed at the subsearch's dataset (its own table, time
        // column, and profile) plus a ctx carrying that table/time column, so the
        // FROM, time-bound WHERE, field resolution, and projection all hit the
        // subsearch's dataset. The clone is local — the sub-dataset never leaks
        // into the outer pipeline (mirrors the IN path / NAN-1555 scoped swap).
        let sub_gen_owned: Option<ClickHouseSqlGenerator> = if cross_dataset {
            let g = self.clone().with_dataset(subsearch_dataset.unwrap());
            match g.generation_time_range.write() {
                Ok(mut guard) => *guard = Some(ctx.time_range.clone()),
                Err(poisoned) => *poisoned.into_inner() = Some(ctx.time_range.clone()),
            }
            Some(g)
        } else {
            None
        };
        let sub_gen: &ClickHouseSqlGenerator = sub_gen_owned.as_ref().unwrap_or(self);
        // Sub table + time column the subsearch reads against (own dataset when cross).
        let (sub_table, sub_time_col): (String, String) = if cross_dataset {
            let ds = subsearch_dataset.unwrap();
            (ds.table_name().to_string(), ds.time_column().to_string())
        } else {
            (ctx.table_name.to_string(), ctx.time_column.to_string())
        };
        let subsearch_sql = if cross_dataset {
            let mut sub_ctx =
                GeneratorContext::new(&sub_table, &sub_time_col, ctx.time_range);
            sub_ctx.required_fields = ctx.required_fields.clone();
            sub_ctx.ext_fields = ctx.ext_fields.clone();
            sub_ctx.use_cache = ctx.use_cache;
            sub_gen.generate_subsearch_sql(subsearch, &sub_ctx, limit)?
        } else {
            self.generate_subsearch_sql(subsearch, ctx, limit)?
        };

        // Resolve each join key PER SIDE (NAN-1413): the outer (main) side
        // against the prior pipeline's output shape, the subsearch (sub) side
        // against its own — a `[search …]` passthrough carries the profile's
        // physical/unified column while a `[… | stats … by user]` projects the
        // bare normalized name, and the two must be allowed to differ in the
        // ON clause or the join references a nonexistent column (Code 47).
        // The MAIN side resolves against `self` (the outer profile); the SUB side
        // resolves against `sub_gen` — the subsearch dataset's generator for a
        // cross-dataset join, `self` otherwise (NAN-1562). Using `self` for the
        // sub keys aliased `service_name → cloud_service` for a spans subsearch,
        // a column `otel_spans` has no → Code 47 at runtime.
        let main_shape = self.pipeline_output_shape(prior_stages);
        let sub_shape_for_keys = sub_gen.pipeline_output_shape(&sub_gen.collect_stages(subsearch));
        let main_keys: Vec<String> = fields
            .iter()
            .map(|f| self.join_key_column(self, f, &main_shape))
            .collect();
        let sub_keys: Vec<String> = fields
            .iter()
            .map(|f| self.join_key_column(sub_gen, f, &sub_shape_for_keys))
            .collect();

        // A join CHAINED after a wide-sub join needs a stage-unique subsearch
        // alias (NAN-1420). The prior join's `SELECT *` leaked its sub's
        // columns as literal `sub.<col>` names into this stage's main side, and
        // ClickHouse resolves a compound identifier `sub."x"` against that
        // dotted MAIN-side column in preference to the new `sub` table — both
        // ON operands then bind to `main` and the join dies (Code 48 "JOIN ON
        // constant", observed on live CH). A per-stage alias (`sub_2`, `sub_3`,
        // …; `prior_stages.len()` is this stage's index, so chains never
        // collide with an earlier stage's leak) can only bind to the new sub
        // table. Applies under EVERY profile (NAN-1423): NAN-1420 initially
        // gated this off for UDM to preserve byte-parity, but the pinned
        // legacy emission was itself the Code 48 failure — there was no
        // working behavior to preserve. Single (non-chained) joins still see
        // a `Wide` main shape and keep the legacy `sub` alias byte-for-byte.
        let sub_alias = if matches!(main_shape, OutputShape::WideJoined(_)) {
            format!("sub_{}", prior_stages.len())
        } else {
            "sub".to_string()
        };

        // Build the JOIN condition with the per-side resolved key columns
        let join_conditions: Vec<String> = main_keys
            .iter()
            .zip(&sub_keys)
            .map(|(mk, sk)| format!("main.{} = {}.{}", mk, sub_alias, sk))
            .collect();
        let join_condition = join_conditions.join(" AND ");

        // Map join type to SQL keyword
        let join_keyword = match join_type {
            JoinType::Inner => "INNER JOIN",
            JoinType::Left => "LEFT JOIN",
            JoinType::Outer => "FULL OUTER JOIN",
        };

        // Join semantics: events without the join field never match. An
        // empty/NULL key on the subsearch side would otherwise equi-join every
        // empty-keyed main row against every empty-keyed sub row — a hash-join
        // row explosion that OOMs on real data (NAN-1346 #4). Evict them from
        // the sub side; LEFT-join main rows with empty keys simply get no match.
        // (toString of a NULL key yields NULL, which is falsy in WHERE.)
        // Filter on the SUB-side resolved key — the same column the ON clause
        // compares (NAN-1413) — or the eviction misses the rows being joined.
        let sub_key_filter = sub_keys
            .iter()
            .map(|k| format!("toString({}) != ''", k))
            .collect::<Vec<_>>()
            .join(" AND ");

        // `join` matches at most `max` subsearch results per join key (default 1).
        // The old SQL only enforced this for max > 1, via a
        // `ROW_NUMBER() OVER (… ORDER BY timestamp)` window — which broke on
        // aggregated subsearches (no `timestamp` column → the ClickHouse
        // analyzer resolved it from the OUTER query and rejected the join as a
        // correlated subquery, Code 48), and for the default max=1 the join was
        // unbounded many-to-many, exploding memory when sub keys repeat
        // (NAN-1346 #4). Use ClickHouse-native `LIMIT {max} BY {keys}` on the
        // sub side instead: no window, no `_join_rn` leaking into `SELECT *`
        // output, and first-in-time selection when the subsearch still carries
        // `timestamp` (an aggregated subsearch has one row per key anyway).
        // LIMIT … BY the SUB-side resolved keys (same columns the ON clause
        // compares, NAN-1413) so the per-key cap binds to the join key.
        let key_list = sub_keys.join(", ");
        let sub_shape = sub_shape_for_keys;
        // NAN-1555: order the subsearch on the active dataset's time column
        // (`start_time` for spans). Logs/metrics keep `timestamp` → byte-identical.
        // NAN-1562: for a cross-dataset subsearch, order on the SUBSEARCH
        // dataset's time column (`sub_time_col`) — the rows being ordered are the
        // subsearch's, not the outer query's.
        let tc: &str = if cross_dataset {
            &sub_time_col
        } else {
            self.time_column()
        };
        let sub_order: String = match &sub_shape {
            OutputShape::Wide(_) => format!("\n    ORDER BY {tc}"),
            OutputShape::Columns(cols) if cols.iter().any(|c| c == tc) => {
                format!("\n    ORDER BY {tc}")
            }
            _ => String::new(),
        };
        // When the subsearch's output columns are known, project `main.*` plus
        // the sub's non-key columns under their bare names. A bare `SELECT *`
        // over the join emits the sub's columns as literal `sub.<col>`
        // duplicates — a later CHAINED join's `ON main.k = sub.k` then binds
        // `sub.k` to the prior stage's "sub.k" column instead of the new sub
        // table (Code 403 INVALID_JOIN_ON_EXPRESSION), and downstream stages
        // can't reference the bare name. Join keys are already in `main.*`.
        let select_clause = match &sub_shape {
            OutputShape::Columns(cols) => {
                // NAN-1562: the sub-side Columns shape is computed by `sub_gen`,
                // so canonicalize the key names through the SAME profile to match
                // (spans/metrics keep `service_name`; logs map through the free
                // alias table — byte-identical for the same-table path).
                let key_names: Vec<&str> =
                    fields.iter().map(|f| sub_gen.canonicalize_field(f)).collect();
                let sub_cols: Vec<String> = cols
                    .iter()
                    .filter(|c| !key_names.contains(&c.as_str()))
                    .map(|c| {
                        let escaped = escape_identifier(c);
                        format!("{}.{} AS {}", sub_alias, escaped, escaped)
                    })
                    .collect();
                if sub_cols.is_empty() {
                    "main.*".to_string()
                } else {
                    format!("main.*, {}", sub_cols.join(", "))
                }
            }
            _ => "*".to_string(),
        };
        // NAN-1562: when the subsearch targets a NON-logs dataset, the hash join
        // build side is the OTLP table (spans/metrics), which is wider and pushes
        // peak memory; `partial_merge` measured ~36% less peak memory than the
        // default hash algorithm for that shape. Logs subsearches keep CH's
        // default (hash) → byte-identical. Emitted on the JOIN CTE.
        let join_settings = match subsearch_dataset {
            Some(otel::Dataset::Spans) | Some(otel::Dataset::Metrics) if cross_dataset => {
                "\n  SETTINGS join_algorithm = 'partial_merge'"
            }
            _ => "",
        };
        Ok(format!(
            "  SELECT {} FROM {} AS main\n  {} (\n    SELECT * FROM (\n{}\n    ) WHERE {}{}\n    LIMIT {} BY {}\n  ) AS {} ON {}{}",
            select_clause,
            source_cte,
            join_keyword,
            subsearch_sql,
            sub_key_filter,
            sub_order,
            max,
            key_list,
            sub_alias,
            join_condition,
            join_settings
        ))
    }

    /// Generate SQL for a subsearch (used by join/append)
    /// Applies the given limit to prevent memory exhaustion
    fn generate_subsearch_sql(
        &self,
        subsearch: &Query,
        ctx: &GeneratorContext,
        limit: usize,
    ) -> Result<String, SqlGenError> {
        // A subsearch is its own pipeline scope: its field references must not
        // see the OUTER pipeline's value-computed fields as shadowing columns,
        // and its own stage tracking must not leak out (the outer loop adds
        // the join/append OUTPUT columns itself via `note_upstream_computed`).
        // Swap in an empty scope, restore the outer one afterwards (NAN-1341).
        let outer_scope = self.swap_upstream_computed(HashSet::new());
        let result = self.generate_subsearch_sql_inner(subsearch, ctx, limit);
        self.swap_upstream_computed(outer_scope);
        result
    }

    fn generate_subsearch_sql_inner(
        &self,
        subsearch: &Query,
        ctx: &GeneratorContext,
        limit: usize,
    ) -> Result<String, SqlGenError> {
        // Collect stages from subsearch
        let stages = self.collect_stages(subsearch);

        if stages.is_empty() {
            return Err(SqlGenError::EmptyQuery);
        }

        // Base select clause for the subsearch's table scan. MUST be the same
        // clause the main pipeline's stage_0 uses (generate_cte_query): a bare
        // `SELECT *` omits MATERIALIZED columns (ClickHouse excludes them from
        // `*`), so a subsearch `stats by <materialized col>` hits Code 47, and
        // an append of two passthroughs ends up with mismatched UNION arms
        // (NAN-1346 #3). With append/join present, field analysis sets
        // needs_all, so this is the full wide clause on both sides.
        let base_select =
            self.build_select_clause_with_options(&ctx.required_fields, &ctx.ext_fields, true);

        // For single-stage subsearch (just a search), generate inline with LIMIT
        if stages.len() == 1 {
            if let QueryStage::Search(expr) = &stages[0] {
                let where_clause = self.generate_search_expr(expr)?;
                // Single WHERE — `optimize_move_to_prewhere` does placement (NAN-1412).
                // Time column is the (sub)dataset's `ctx.time_column` — `start_time`
                // for a spans subsearch, not the literal `timestamp` (NAN-1562).
                return Ok(format!(
                    "    SELECT {} FROM {}\n    WHERE {} BETWEEN '{}' AND '{}'\n    AND ({})\n    LIMIT {}",
                    base_select,
                    ctx.table_name,
                    ctx.time_column,
                    ctx.time_range.start.format("%Y-%m-%d %H:%M:%S%.6f"),
                    ctx.time_range.end.format("%Y-%m-%d %H:%M:%S%.6f"),
                    where_clause,
                    limit
                ));
            }
        }

        // For multi-stage subsearch, generate nested subqueries
        let mut current_sql = String::new();

        for (i, stage) in stages.iter().enumerate() {
            match stage {
                QueryStage::Search(expr) => {
                    let where_clause = self.generate_search_expr(expr)?;
                    // Single WHERE — `optimize_move_to_prewhere` does placement (NAN-1412).
                    // Time column is the (sub)dataset's `ctx.time_column` (NAN-1562).
                    current_sql = format!(
                        "SELECT {} FROM {} WHERE {} BETWEEN '{}' AND '{}' AND ({})",
                        base_select,
                        ctx.table_name,
                        ctx.time_column,
                        ctx.time_range.start.format("%Y-%m-%d %H:%M:%S%.6f"),
                        ctx.time_range.end.format("%Y-%m-%d %H:%M:%S%.6f"),
                        where_clause
                    );
                }
                QueryStage::Command(cmd) => {
                    // For Tree commands, MATERIALIZED columns (e.g. process_guid,
                    // parent_process_guid) are excluded from SELECT * — inject them
                    // into the base query so they're visible in the subquery
                    if let Command::Tree {
                        parent_field,
                        child_field,
                        ..
                    } = cmd
                    {
                        // Only inject fields that resolve to themselves on the
                        // active profile — a class-split concept or mapped UDM
                        // alias (parent_process_guid → "actor.process.uid") is
                        // already carried by the wide base clause, and the raw
                        // name does not exist on the table (NAN-1346 #5).
                        let inject: Vec<String> = [parent_field, child_field]
                            .into_iter()
                            .filter(|f| {
                                // Exclude only fields the profile maps ELSEWHERE;
                                // Unknown (UDM ext) fields keep the old raw injection.
                                !f.is_empty()
                                    && self.class_split_column(f).is_none()
                                    && !matches!(
                                        self.profile.resolve(f),
                                        FieldResolution::ExplicitColumn(ref c) if c != *f
                                    )
                                    && !matches!(
                                        self.profile.resolve(f),
                                        FieldResolution::JsonPath { .. }
                                    )
                            })
                            .map(|f| escape_identifier(f).to_string())
                            .collect();
                        if !inject.is_empty() && !current_sql.contains(&inject[0]) {
                            current_sql = current_sql.replacen(
                                "SELECT *",
                                &format!("SELECT *, {}", inject.join(", ")),
                                1,
                            );
                        }
                    }
                    // Use previous result as source, wrapped in parentheses with alias
                    let source = format!("({}) AS stage_{}", current_sql, i - 1);
                    let cmd_sql = self.generate_command_sql(&source, cmd)?;
                    // Track this subsearch stage's value-computed outputs for
                    // the subsearch stages after it (NAN-1341).
                    self.note_upstream_computed(cmd);
                    // Wrap the command result for next iteration
                    current_sql = cmd_sql.trim().to_string();
                }
            }
        }

        // Apply subsearch limit to the final multi-stage subsearch output.
        // LIMIT must be inside the parens so it's valid when used as a
        // JOIN/subquery source, and the stage SQL is wrapped in its own
        // subquery first — the last stage may already end in a LIMIT
        // (`head`/`sort`), and `... LIMIT 5 LIMIT 10000` is a syntax error
        // (NAN-1346 #3).
        Ok(format!(
            "    (SELECT * FROM ({}) LIMIT {})",
            current_sql.replace('\n', "\n    "),
            limit
        ))
    }

    /// Build SELECT clause based on required fields
    /// Returns "*" if all fields needed, or comma-separated field list if optimized
    /// Also materializes ext JSON fields so they're visible to downstream CTEs
    fn build_select_clause(
        &self,
        required_fields: &Option<HashSet<String>>,
        ext_fields: &HashSet<String>,
    ) -> String {
        self.build_select_clause_with_options(required_fields, ext_fields, false)
    }

    /// Build the default-view `SELECT *` base from the active profile's
    /// [`default_view_renames`]. Each `(column, alias)` pair re-projects
    /// `column AS alias`; in terminal projections the columns are also stripped
    /// from the wildcard via `* EXCEPT (col, …)` so the result header carries the
    /// canonical alias (and CH does not emit the column twice).
    ///
    /// - UDM (`[("action", "event_type")]`) reproduces today's
    ///   `* EXCEPT (action), action AS event_type` /
    ///   `*, action AS event_type` **byte-for-byte**.
    /// - OCSF (`[]`) yields a bare `*`, so a default-view search on the OCSF
    ///   table does not reference the nonexistent UDM `action` column.
    ///
    /// `preserve_legacy_columns = true` keeps the renamed columns inside `*` for
    /// intermediate CTE stages (NAN-876); the terminal `EXCEPT` collapse, when
    /// applicable, happens once at the outer SELECT in [`generate_cte_query`].
    ///
    /// [`default_view_renames`]: crate::schema::SchemaProfile::default_view_renames
    fn build_default_view_base(&self, preserve_legacy_columns: bool) -> String {
        let renames = self.profile.default_view_renames();
        if renames.is_empty() {
            return "*".to_string();
        }
        let alias_exprs = renames
            .iter()
            .map(|(col, alias)| {
                format!("{} AS {}", escape_identifier(col), escape_identifier(alias))
            })
            .collect::<Vec<_>>()
            .join(", ");
        if preserve_legacy_columns {
            format!("*, {}", alias_exprs)
        } else {
            let except_cols = renames
                .iter()
                .map(|(col, _)| escape_identifier(col))
                .collect::<Vec<_>>()
                .join(", ");
            format!("* EXCEPT ({}), {}", except_cols, alias_exprs)
        }
    }

    /// The terminal-projection `SELECT` list used by [`generate_cte_query`]'s
    /// outer SELECT when no aggregation/projection ran: `* EXCEPT (col, …)` over
    /// the active profile's [`default_view_renames`] columns (the renamed
    /// `event_type` alias was already added by stage_0's
    /// `preserve_legacy_columns` base). UDM yields `* EXCEPT (action)`; OCSF
    /// (no renames) yields a bare `*`.
    ///
    /// [`default_view_renames`]: crate::schema::SchemaProfile::default_view_renames
    fn outer_select_except_list(&self) -> String {
        let renames = self.profile.default_view_renames();
        if renames.is_empty() {
            return "*".to_string();
        }
        let except_cols = renames
            .iter()
            .map(|(col, _)| escape_identifier(col))
            .collect::<Vec<_>>()
            .join(", ");
        format!("* EXCEPT ({})", except_cols)
    }

    /// Variant of [`build_select_clause`] that controls whether the
    /// physical `action` column is excluded from the wildcard expansion
    /// (NAN-671's terminal-projection behavior) or kept alongside its
    /// canonical `event_type` alias (NAN-876's intermediate-CTE
    /// behavior).
    ///
    /// **When to set `preserve_legacy_columns = true`:** stage_0 of a
    /// multi-stage CTE chain, where downstream stages (e.g. a LLM-
    /// generated `... | where action="foo"` or `... | stats count by
    /// action`) need to reference `action` by its physical name. The
    /// terminal `EXCEPT (action)` collapse, if there is one, is applied
    /// once at the outer SELECT in [`generate_cte_query`] — not at every
    /// intermediate stage. NAN-876 was the bug where intermediate
    /// stages stripped `action` and the LLM hunting queries hit
    /// `Unknown expression identifier \`action\`` for every reference.
    fn build_select_clause_with_options(
        &self,
        required_fields: &Option<HashSet<String>>,
        ext_fields: &HashSet<String>,
        preserve_legacy_columns: bool,
    ) -> String {
        match required_fields {
            None => {
                // ClickHouse's SELECT * excludes MATERIALIZED and ALIAS columns.
                // Enrichment and IOC columns are MATERIALIZED (computed at insert via
                // dictionary lookups), so they must be explicitly named alongside *.
                // This ensures they're visible in CTE stages and downstream queries.
                //
                // `action` is the physical column for what the UDM canonically calls
                // `event_type` (NAN-659). For terminal projections we project
                // `event_type` (the alias) and exclude `action` from the wildcard so
                // default search results show the canonical name in the column header.
                // User queries that type `action=` keep working (alias is bidirectional
                // and `action` is still in EXPLICIT_COLUMNS so the SQL gen routes it
                // to the column not ext.action).
                //
                // For intermediate CTE stages we keep `action` inside `*` so
                // downstream stages (and LLM-generated commands) can still reference
                // it directly. The redundant column is dropped at the outer SELECT
                // when the last stage didn't transform it away. See NAN-876.
                let base = self.build_default_view_base(preserve_legacy_columns);
                // Re-add every MATERIALIZED column (excluded from `SELECT *`) so any
                // downstream CTE stage can reference it. Derived from the single
                // MATERIALIZED_COLUMNS source of truth — the previous hand-maintained
                // subset dropped enriched_*_continent / custom_* / *_identity_* and any
                // downstream reference to those hit Code 47 (NAN-1147).
                // Escape each materialized column name. UDM columns are bare
                // snake_case so `escape_identifier` is a no-op (byte-identical);
                // OCSF promoted columns are dotted (`src_endpoint.ip`) and MUST be
                // quoted or ClickHouse parses them as tuple/sub-column access.
                let materialized = self
                    .profile
                    .materialized_columns()
                    .iter()
                    .map(|c| escape_identifier(c))
                    .collect::<Vec<_>>()
                    .join(", ");

                // NAN-1555: assemble from non-empty parts only. Spans have no
                // MATERIALIZED columns (`materialized` is ""), so a flat
                // `format!("{base}, {materialized}")` would emit a trailing-comma
                // `SELECT *,  FROM` — a CH syntax error. UDM/OCSF always have a
                // non-empty materialized list, so this is byte-identical for them.
                let mut parts: Vec<String> = vec![base];
                if !materialized.is_empty() {
                    parts.push(materialized);
                }
                if !ext_fields.is_empty() {
                    // Materialize ext/attribute fields alongside SELECT * so they
                    // appear as regular columns in downstream CTEs.
                    let mut ext_cols: Vec<_> = ext_fields.iter().collect();
                    ext_cols.sort();
                    let ext_exprs: Vec<String> = ext_cols
                        .iter()
                        .map(|f| {
                            format!(
                                "toString({}) AS {}",
                                self.field_access_expr(f, "String"),
                                escape_identifier(f)
                            )
                        })
                        .collect();
                    parts.push(ext_exprs.join(", "));
                }
                parts.join(", ")
            }
            Some(fields) => {
                // Explicit-fields path: `preserve_legacy_columns` is not
                // consulted here — when field_analysis enumerates required
                // columns, it's expected to include `action` if any stage
                // references it. If a future LLM-generated query slips a
                // reference past field_analysis (e.g. via an unusual
                // construct), NAN-876's symptom (`Unknown expression
                // identifier`) can reappear in this branch. The fix in
                // that case lives in field_analysis, not here.
                //
                // Sort fields for consistent output
                let mut field_list: Vec<_> = fields.iter().collect();
                field_list.sort();

                // Build field expressions, handling JSON fields
                // Cast JSON fields to String to avoid Dynamic type issues in GROUP BY
                let mut field_exprs: Vec<String> = field_list
                    .iter()
                    .map(|field| {
                        if let Some(unified) = self.class_split_column(field) {
                            // NAN-1337: a class-split concept (src_host / process_name /
                            // user / url) must project its INDEXED unified column
                            // (`<field>_unified`) — the SAME column the value/group/sort
                            // seam (`by_field_sql`) references in later stages — so a
                            // `stats by src_host` GROUP BY binds to it here. Projecting the
                            // class-split *primary* (`src_endpoint.hostname`) instead left
                            // the later `GROUP BY src_host_unified` with nothing to bind →
                            // CH Code 47. UDM never class-splits → `None` → byte-identical.
                            escape_identifier(&unified)
                        } else if self.resolves_to_column(field) {
                            // Resolve to the PHYSICAL column (NAN-1248): under OCSF a
                            // UDM-semantic required field (`src_ip`) must project the
                            // promoted column (`"src_endpoint.ip"`), not a bare `src_ip`
                            // that ocsf_logs lacks — so a later stage that references the
                            // resolved column (`stats`/`timechart`/`top` GROUP BY) finds
                            // it in this stage's output. UDM byte-identical: for a UDM
                            // explicit column `field_access_expr` == `escape_identifier`.
                            self.field_access_expr(field, "String")
                        } else {
                            // Spill field — cast to String to avoid Dynamic type in
                            // GROUP BY. Profile-aware: UDM Unknown → `ext.{field}`
                            // (byte-identical); an OCSF tail path → native `event`
                            // subcolumn access (NAN-1426; the ''-defaulting multiIf
                            // string form, no longer whole-event JSONExtractString).
                            format!(
                                "toString({}) AS {}",
                                self.field_access_expr(field, "String"),
                                escape_identifier(field)
                            )
                        }
                    })
                    .collect();

                // Also materialize any ext fields not already in the required fields set
                for f in ext_fields {
                    if !fields.contains(f) {
                        field_exprs.push(format!(
                            "toString({}) AS {}",
                            self.field_access_expr(f, "String"),
                            escape_identifier(f)
                        ));
                    }
                }

                // OCSF tail-column passthrough (NAN-1248 follow-up). The slim
                // projection above materializes each required field's *value*
                // (e.g. `toString(event."unmapped"."foo"…) AS foo`) but
                // drops the underlying `event` JSON column. A later CTE stage that
                // re-extracts an unpromoted/tail OCSF field — a `timechart`/`top`/
                // `stats` split-by on a `JsonPath` field — emits a fresh
                // subcolumn access that references `event` against
                // this stage's output, which no longer has it → CH
                // "Unknown identifier: event" 500. When any required field
                // resolves to a `JsonPath`, append its backing JSON column
                // (OCSF's `event`) as a passthrough so downstream extracts
                // resolve. UDM is untouched: `UdmProfile::resolve` never yields
                // `JsonPath`, so `tail_col` stays `None` and the join below is
                // byte-identical to before.
                //
                // NAN-1555: the same hazard for the spans/metrics attribute `Map`
                // tail. A required `MapKey` field is materialized above as
                // `toString(if(has(attributes,'k'),attributes['k'],…)) AS k`, but a
                // later stage that re-derives the SAME map subscript (`stats`/
                // `timechart`/`top` split-by on `http.method`) references
                // `attributes`/`resource_attributes` against this stage's output,
                // which the slim projection dropped → CH Code 47 "Unknown
                // identifier: attributes". Pass through BOTH backing map columns.
                // UDM/OCSF never yield `MapKey`, so this is spans/metrics-only.
                let mut tail_cols: Vec<String> = Vec::new();
                let mut push_tail = |c: String, acc: &mut Vec<String>| {
                    if !acc.contains(&c) {
                        acc.push(c);
                    }
                };
                for field in &field_list {
                    match self.profile.resolve(field) {
                        FieldResolution::JsonPath { col, .. } => push_tail(col, &mut tail_cols),
                        FieldResolution::MapKey { col, fallback, .. } => {
                            push_tail(col, &mut tail_cols);
                            if let Some(fb) = fallback {
                                push_tail(fb, &mut tail_cols);
                            }
                        }
                        _ => {}
                    }
                }
                for col in tail_cols {
                    let escaped = escape_identifier(&col);
                    // Guard against an accidental duplicate if the tail column
                    // ever appears as its own bare required field.
                    if !field_exprs.iter().any(|e| e == &escaped) {
                        field_exprs.push(escaped);
                    }
                }

                field_exprs.join(", ")
            }
        }
    }

    /// Generate SQL for a command (public API without context tracking)
    pub fn generate_command_sql(&self, source: &str, cmd: &Command) -> Result<String, SqlGenError> {
        let mut no_ctx: Option<HashSet<String>> = None;
        self.generate_command_sql_inner(source, cmd, &mut no_ctx, None, false, false, false)
    }

    fn generate_command_sql_with_ctx(
        &self,
        source: &str,
        cmd: &Command,
        ctx: &mut GeneratorContext,
    ) -> Result<String, SqlGenError> {
        let sparkline_span = Self::compute_sparkline_span_secs(ctx.time_range);
        let has_prior_risk = ctx.has_prior_risk;
        let result = self.generate_command_sql_inner(
            source,
            cmd,
            &mut ctx.available_columns,
            Some(sparkline_span),
            has_prior_risk,
            ctx.aggregated,
            ctx.single_resolve_identity,
        );
        if matches!(cmd, Command::Risk { .. }) {
            ctx.has_prior_risk = true;
        }
        // Aggregating commands GROUP BY and drop the raw `timestamp` column; mark the
        // pipeline so downstream order-sensitive commands (tail/reverse) don't ORDER BY
        // a column that no longer exists (NAN-1146).
        if matches!(
            cmd,
            Command::Stats { .. }
                | Command::Chart { .. }
                | Command::Timechart { .. }
                | Command::Top { .. }
                | Command::Rare { .. }
                | Command::Transaction { .. }
                | Command::Sequence { .. }
                | Command::Funnel { .. }
                | Command::Anomaly { .. }
        ) {
            ctx.aggregated = true;
        }
        result
    }

    /// Compute the sparkline time-bucket span from the search time range.
    /// Targets ~30 buckets (enough detail for a small inline chart).
    fn compute_sparkline_span_secs(time_range: &TimeRange) -> u64 {
        let duration_secs = (time_range.end - time_range.start).num_seconds().max(1) as u64;
        // Target ~30 buckets, minimum 60s per bucket
        (duration_secs / 30).max(60)
    }
}

/// Internal stage representation for query processing
pub(super) enum QueryStage<'a> {
    Search(&'a SearchExpr),
    Command(&'a Command),
}

/// Statically known output projection of a pipeline prefix — used by `append`
/// to align its UNION arms (see `generate_append_sql`).
#[derive(Debug, Clone, PartialEq)]
enum OutputShape {
    /// Still `SELECT *`-shaped over the base select clause; the Vec holds
    /// extra columns appended by eval/rename, in order.
    Wide(Vec<String>),
    /// A wide pipeline that went through a wide-subsearch join (NAN-1420): the
    /// base table's physical columns are all still present under their bare
    /// names (the Vec holds eval/rename extras, like [`Wide`]), so join keys /
    /// field references resolve through the schema profile exactly like a wide
    /// side — but the stage's `SELECT *` over the join ALSO leaked the
    /// subsearch's columns as literal `sub.<col>` duplicates, so the output is
    /// neither positionally append-alignable nor a clean column inventory.
    /// `append` and the field-stats companion treat it exactly like
    /// [`Unknown`] (they refuse / skip); only join-key resolution exploits the
    /// wide guarantee.
    WideJoined(Vec<String>),
    /// Explicit projection (stats/chart/table/fields), output names in order.
    Columns(Vec<String>),
    /// Not statically modeled — append refuses to align this.
    Unknown,
}

/// Context for SQL generation
struct GeneratorContext<'a> {
    table_name: &'a str,
    /// Primary time column for the dataset's main-table read — `"timestamp"`
    /// (logs/metrics) or `"start_time"` (spans). Drives the time-bound WHERE and
    /// the default ORDER BY at the base-table seam (NAN-1534). Subsearch /
    /// IN-subquery reads always hit `logs` and keep the literal `timestamp`.
    time_column: &'a str,
    time_range: &'a TimeRange,
    current_stage: usize,
    /// Fields required by the query (for field pruning optimization)
    /// None = SELECT *, Some(set) = SELECT specific fields
    required_fields: Option<HashSet<String>>,
    /// Enable query cache (for shared searches)
    use_cache: bool,
    /// Maximum results to return as a generator-baked trailing LIMIT.
    /// `None` = emit no trailing LIMIT — the executor owns pagination (NAN-1410).
    limit: Option<usize>,
    /// Fields that live in the `ext` JSON column and need materializing in stage_0
    ext_fields: HashSet<String>,
    /// Columns available after a column-pruning command (table, fields keep).
    /// None = all columns available (no pruning), Some(set) = only these columns exist.
    available_columns: Option<HashSet<String>>,
    /// Whether a prior Risk command exists in the pipeline (for score accumulation)
    has_prior_risk: bool,
    /// Whether the pipeline contains exactly one resolve_identity — the bare
    /// `identity_*` aliases are only emitted when unambiguous (NAN-1346 #5).
    single_resolve_identity: bool,
    /// Whether a prior aggregating command (stats/chart/timechart/top/rare/transaction/
    /// sequence/funnel/anomaly) has run — these GROUP BY and drop the raw `timestamp`
    /// column, so order-sensitive commands (tail/reverse) must not ORDER BY timestamp.
    aggregated: bool,
}

impl<'a> GeneratorContext<'a> {
    fn new(table_name: &'a str, time_column: &'a str, time_range: &'a TimeRange) -> Self {
        Self {
            table_name,
            time_column,
            time_range,
            current_stage: 0,
            required_fields: None,
            use_cache: false,
            limit: Some(ClickHouseSqlGenerator::DEFAULT_RESULT_LIMIT),
            ext_fields: HashSet::new(),
            available_columns: None,
            has_prior_risk: false,
            single_resolve_identity: false,
            aggregated: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::query::parser::parse_query;
    use crate::query::TimeRange;

    fn time_range() -> TimeRange {
        TimeRange {
            start: "2024-01-01T00:00:00Z".parse().unwrap(),
            end: "2024-01-02T00:00:00Z".parse().unwrap(),
        }
    }

    /// NAN-1410: with `limit: None` (executor-owned pagination) the generator
    /// must NOT bake a trailing LIMIT into a raw single-stage query — a baked
    /// LIMIT turned the executor's LIMIT/OFFSET injection into a silent no-op,
    /// so page N re-served page 1's rows and total_count was capped at the
    /// page size.
    #[test]
    fn raw_single_stage_with_limit_none_emits_no_limit() {
        let gen = ClickHouseSqlGenerator::new();
        let query = parse_query("error").unwrap();
        let options = QueryOptions {
            limit: None,
            ..Default::default()
        };
        let sql = gen
            .generate_with_options(&query, &time_range(), &options)
            .unwrap();
        assert!(
            !sql.to_uppercase().contains(" LIMIT "),
            "executor-paginated raw query must carry no generator LIMIT, got:\n{sql}"
        );
        assert!(
            sql.contains("ORDER BY timestamp DESC"),
            "ordering must be preserved, got:\n{sql}"
        );
    }

    /// NAN-1410: default options keep the safety bound for callers that
    /// execute the generated SQL directly (explain, detection) — unchanged
    /// from the pre-fix behavior.
    #[test]
    fn raw_single_stage_default_options_keeps_safety_limit() {
        let gen = ClickHouseSqlGenerator::new();
        let query = parse_query("error").unwrap();
        let sql = gen.generate(&query, &time_range()).unwrap();
        assert!(
            sql.contains(&format!(
                "LIMIT {} ",
                ClickHouseSqlGenerator::DEFAULT_RESULT_LIMIT
            )),
            "default options must keep the safety LIMIT, got:\n{sql}"
        );
    }

    /// NAN-1410: an explicit caller limit is still baked (aggregation /
    /// tree / asset paths pass their own caps).
    #[test]
    fn raw_single_stage_explicit_limit_is_baked() {
        let gen = ClickHouseSqlGenerator::new();
        let query = parse_query("error").unwrap();
        let options = QueryOptions {
            limit: Some(10_000),
            ..Default::default()
        };
        let sql = gen
            .generate_with_options(&query, &time_range(), &options)
            .unwrap();
        assert!(
            sql.contains("LIMIT 10000 "),
            "explicit caller limit must be baked, got:\n{sql}"
        );
    }

    /// NAN-1410: a user `| head N` is query semantics, not pagination — it
    /// must keep its LIMIT even when the executor owns pagination. The
    /// executor then wraps the query so pages slice within the head cap
    /// (page past N is empty) instead of replacing or ignoring it.
    #[test]
    fn user_head_limit_survives_executor_owned_pagination() {
        let gen = ClickHouseSqlGenerator::new();
        let query = parse_query("error | head 10").unwrap();
        let options = QueryOptions {
            limit: None,
            ..Default::default()
        };
        let sql = gen
            .generate_with_options(&query, &time_range(), &options)
            .unwrap();
        assert!(
            sql.contains("LIMIT 10 "),
            "user head cap must be preserved, got:\n{sql}"
        );
        assert!(
            !sql.contains(&format!("LIMIT {}", ClickHouseSqlGenerator::DEFAULT_RESULT_LIMIT)),
            "no safety LIMIT should stack on top of the head cap, got:\n{sql}"
        );
    }

    /// NAN-1410: multi-stage row-preserving pipelines (the NAN-1159 shape)
    /// keep their LIMIT-free CTE tail under executor-owned pagination, so the
    /// count companion (which wraps this SQL) still returns the true total.
    #[test]
    fn multistage_raw_pipeline_with_limit_none_emits_no_limit() {
        let gen = ClickHouseSqlGenerator::new();
        let query = parse_query("error | where src_ip!=\"\"").unwrap();
        let options = QueryOptions {
            limit: None,
            ..Default::default()
        };
        let sql = gen
            .generate_with_options(&query, &time_range(), &options)
            .unwrap();
        assert!(
            sql.trim_start().starts_with("WITH "),
            "expected a CTE chain, got:\n{sql}"
        );
        assert!(
            !sql.to_uppercase().contains(" LIMIT "),
            "row-preserving CTE pipeline must carry no LIMIT, got:\n{sql}"
        );
    }

    /// NAN-1311: under OCSF a `sequence` step-capture column whose field is dotted
    /// (`[process.name=…]` → emitted alias `step1_process_name`) must be registered
    /// as a computed column, so a downstream `| table step1_process_name` references
    /// it bare. Previously it was JSON-tailed as `JSONExtractString(event,
    /// 'step1_process_name')`, but the sequence output stage drops `event` →
    /// `Code 47 UNKNOWN_IDENTIFIER: event`.
    #[test]
    fn ocsf_sequence_capture_column_not_json_tailed() {
        use crate::schema::OcsfProfile;
        use std::sync::Arc;
        let gen = ClickHouseSqlGenerator::new().with_profile(Arc::new(OcsfProfile::new()));
        let query = parse_query(
            "| sequence by user.name maxspan=2h [process.name=\"whoami.exe\"] \
             [process.name=\"net.exe\"] | table step1_time, step2_time, user.name, step1_process_name",
        )
        .unwrap();
        let sql = gen.generate(&query, &time_range()).unwrap();
        // The fatal scope is the downstream `| table` stage (stage_2): its source
        // is the sequence output, which drops `event`. Re-deriving the capture from
        // `event` there is the Code 47. (stage_0 still pre-projects the computed
        // columns from `event` as harmless, unused noise — it carries `event`.)
        let downstream = &sql[sql
            .find("stage_2 AS")
            .expect("expected a stage_2 for the trailing table command")..];
        assert!(
            !downstream.contains("JSONExtractString(event"),
            "downstream sequence stage must not JSON-tail capture columns from `event` (NAN-1311), got:\n{downstream}"
        );
        assert!(
            downstream.contains("step1_process_name FROM stage_"),
            "downstream stage should select step1_process_name as a bare computed column, got:\n{downstream}"
        );
    }

    /// NAN-1384 (G18): `source_type` equality must be case-tolerant under OCSF.
    /// `ocsf_logs` accepts direct client INSERTs, and a client-written DEFAULT
    /// column cannot be lowercase-normalized server-side — so a MixedCase
    /// `source_type` row used to be silently invisible to the
    /// `source_type = '<lowered>'` fast-path (verified live: a `MixedCase` probe
    /// row matched 0 rows). The generator must emit `lower(source_type)` in both
    /// WHERE and PREWHERE under OCSF, while UDM (whose ingest is exclusively
    /// Vector-owned and lowercases at the edge) keeps the index fast-path.
    #[test]
    fn ocsf_source_type_eq_is_case_tolerant_udm_keeps_fast_path() {
        use crate::schema::OcsfProfile;
        use std::sync::Arc;
        let q = parse_query("source_type=MixedCase").unwrap();

        let ocsf = ClickHouseSqlGenerator::new().with_profile(Arc::new(OcsfProfile::new()));
        let ocsf_sql = ocsf.generate(&q, &time_range()).unwrap();
        assert!(
            ocsf_sql.contains("lower(source_type) = 'mixedcase'"),
            "OCSF source_type equality must lower() the stored column, got:\n{ocsf_sql}"
        );
        assert!(
            !ocsf_sql.contains("source_type = 'mixedcase'"),
            "OCSF must not emit the bare ingest-lowercased fast-path, got:\n{ocsf_sql}"
        );
        // NAN-1412: a single WHERE carries the filter — no explicit PREWHERE
        // (it suppressed `optimize_move_to_prewhere`).
        assert!(
            !ocsf_sql.contains("PREWHERE"),
            "no explicit PREWHERE may be emitted (NAN-1412), got:\n{ocsf_sql}"
        );

        // UDM safety: byte-identical fast-path emission (no lower() wrapper).
        let udm = ClickHouseSqlGenerator::new();
        let udm_sql = udm.generate(&q, &time_range()).unwrap();
        assert!(
            udm_sql.contains("source_type = 'mixedcase'"),
            "UDM must keep the ingest-lowercased equality fast-path, got:\n{udm_sql}"
        );
        assert!(
            !udm_sql.contains("lower(source_type)"),
            "UDM source_type emission must be unchanged by NAN-1384, got:\n{udm_sql}"
        );
    }

    /// NAN-1323: `| resolve_identity` must not reference UDM column names that do
    /// not exist under OCSF (`src_mac`, `user`, `user_identity_*`) — doing so 500s
    /// with an unknown-identifier error. Across src_host / src_ip / user lookups the
    /// OCSF SQL must (a) not `EXCEPT` or `main.`-reference those bare UDM names, and
    /// (b) key the registry dict on the resolved physical user column (`user.name`).
    /// Validated end-to-end on live OCSF CH.
    #[test]
    fn ocsf_resolve_identity_avoids_udm_only_columns() {
        use crate::schema::OcsfProfile;
        use std::sync::Arc;
        let gen = ClickHouseSqlGenerator::new().with_profile(Arc::new(OcsfProfile::new()));
        for field in ["src_host", "src_ip", "user"] {
            let q = parse_query(&format!("source_type=x | resolve_identity {field}")).unwrap();
            let sql = gen.generate(&q, &time_range()).unwrap();
            let stage = &sql[sql.find("ASOF LEFT JOIN").map(|i| sql[..i].rfind("SELECT").unwrap()).unwrap()..];
            assert!(
                !stage.contains("EXCEPT (") && !stage.contains("main.src_mac") && !stage.contains("main.\"user\""),
                "OCSF resolve_identity {field} must not EXCEPT/reference bare UDM columns, got:\n{stage}"
            );
            assert!(
                !stage.contains("main.user_identity_"),
                "OCSF resolve_identity {field} must not read physical user_identity_* (absent in ocsf_logs), got:\n{stage}"
            );
            // The IP/user lookups key the registry dict on the resolved physical
            // user column (`user.name`) — this is the `main."user"` → `main."user.name"`
            // fix. (src_host is a HOST reverse lookup, keyed on the hostname instead.)
            if field != "src_host" {
                assert!(
                    stage.contains("\"user.name\""),
                    "OCSF resolve_identity {field} should key the user dict on user.name, got:\n{stage}"
                );
            }
        }
    }

    /// NAN-1323 parity: UDM `resolve_identity` is byte-identical — it still EXCEPTs
    /// the physical UDM columns and reads them via `main.<col>`.
    #[test]
    fn udm_resolve_identity_unchanged() {
        let gen = ClickHouseSqlGenerator::new();
        let sql = gen
            .generate(&parse_query("source_type=x | resolve_identity src_host").unwrap(), &time_range())
            .unwrap();
        assert!(
            sql.contains("main.* EXCEPT (src_mac, user)")
                && sql.contains("if(main.src_mac = '' OR main.src_mac IS NULL"),
            "UDM resolve_identity must keep the EXCEPT + main.<col> fill form, got:\n{sql}"
        );
    }

    /// NAN-1299: under OCSF, UDM-alias `field=value` search terms must resolve to
    /// the promoted OCSF column in the WHERE filter, never the raw UDM token.
    /// Emitting the bare token (`src_ip = '…'`) references a column that does not
    /// exist in `ocsf_logs` → Code 47 (500) / silent 0-rows. (NAN-1412 moved the
    /// filter from PREWHERE to the single WHERE — same resolution contract.)
    #[test]
    fn ocsf_udm_alias_filter_resolves_to_promoted_column() {
        use crate::schema::OcsfProfile;
        use std::sync::Arc;
        let gen = ClickHouseSqlGenerator::new().with_profile(Arc::new(OcsfProfile::new()));

        // src_ip → src_endpoint.ip ; dest_ip → dst_endpoint.ip. NAN-1412: the
        // equality must be the RAW column form (`"src_endpoint.ip" = '…'`, no
        // lower() wrapper) — these columns are ingest-lowercased and carry
        // raw-expression bloom indexes that `lower(col) =` orphans. The raw
        // form previously lived only in the explicit-PREWHERE duplicate
        // (resolved in extract_prewhere_conditions); with the single WHERE
        // the resolved-column lowercased check must fire here instead
        // (EXPLAIN-verified: idx_src_endpoint_ip 553→88 granules, local CH).
        for (query_str, expected_col) in [
            ("src_ip=\"89.248.167.131\"", "src_endpoint.ip"),
            ("dest_ip=\"10.0.0.1\"", "dst_endpoint.ip"),
        ] {
            let query = parse_query(query_str).unwrap();
            let sql = gen.generate(&query, &time_range()).unwrap();
            let where_clause = where_slice(&sql);
            let value = query_str.split('"').nth(1).unwrap();
            assert!(
                where_clause.contains(&format!("(\"{expected_col}\" = '{value}')")),
                "OCSF WHERE for `{query_str}` should compare the promoted column \
                 \"{expected_col}\" in raw (bloom-served) form, got WHERE:\n{where_clause}"
            );
            assert!(
                !where_clause.contains(&format!("lower(\"{expected_col}\")")),
                "OCSF WHERE for `{query_str}` must not lower()-wrap the ingest-lowercased \
                 column (orphans the raw bloom index, NAN-1412), got:\n{where_clause}"
            );
            // The raw UDM token must NOT appear as a bare WHERE identifier.
            let raw_token = query_str.split('=').next().unwrap();
            assert!(
                !where_clause.contains(&format!("lower({raw_token}) ="))
                    && !where_clause.contains(&format!("{raw_token} =")),
                "OCSF WHERE for `{query_str}` must not emit the raw UDM token, got:\n{where_clause}"
            );
            assert!(
                !sql.contains("PREWHERE"),
                "no explicit PREWHERE may be emitted (NAN-1412), got:\n{sql}"
            );
        }
    }

    /// NAN-1319: a UDM-semantic concept OCSF splits across columns by event class
    /// (`src_host` → `src_endpoint.hostname` on network events, `device.hostname`
    /// on endpoint/sysmon events) must GROUP BY / project the class-spanning value,
    /// not just the primary column — otherwise `stats count by src_host` buckets
    /// every endpoint event as empty (on local OCSF data the empty bucket held
    /// 1.07M rows; the fix attributes them to their device host).
    /// NAN-1333: the group key + projection now reference the INDEXED unified column
    /// (`src_host_unified`), which materializes that same union — identical buckets,
    /// but the words index can prune. Both SELECT and GROUP BY use the same column.
    #[test]
    fn ocsf_stats_by_class_split_host_groups_on_the_union() {
        use crate::schema::OcsfProfile;
        use std::sync::Arc;
        let gen = ClickHouseSqlGenerator::new().with_profile(Arc::new(OcsfProfile::new()));
        let query = parse_query("* | stats count by src_host").unwrap();
        let sql = gen.generate(&query, &time_range()).unwrap();
        assert!(
            sql.contains("SELECT src_host_unified AS src_host"),
            "OCSF `stats by src_host` must PROJECT the indexed unified column, got:\n{sql}"
        );
        assert!(
            sql.contains("GROUP BY src_host_unified"),
            "OCSF `stats by src_host` must GROUP BY the same unified column, got:\n{sql}"
        );
        // No inline `if(...)` union should leak into the projection/group anymore.
        assert!(
            !sql.contains("if(\"src_endpoint.hostname\""),
            "OCSF `stats by src_host` must not emit the skip-index-opaque if(...), got:\n{sql}"
        );
        // The other class-split concepts go through the same seam (consistency).
        let q2 = parse_query("* | stats count by user").unwrap();
        let sql2 = gen.generate(&q2, &time_range()).unwrap();
        assert!(
            sql2.contains("GROUP BY user_unified"),
            "OCSF `stats by user` must group on the indexed unified column, got:\n{sql2}"
        );
    }

    /// NAN-1413: under OCSF a `| join user [search …]` must resolve the join key
    /// through the schema profile — `user` is class-split, so both sides of the
    /// join carry the INDEXED unified column (`user_unified`), exactly like
    /// `stats by user` (NAN-1333). The legacy emission referenced `main."user"`,
    /// a column that does not exist on ocsf_logs → ClickHouse Code 47
    /// UNKNOWN_IDENTIFIER → 500. Validated end-to-end on live OCSF CH:
    /// pre-fix Code 47; post-fix the joined-row count matches a hand-written
    /// equivalent JOIN (50/50, and 9/9 on a single-user deterministic variant).
    #[test]
    fn ocsf_join_key_resolves_through_profile() {
        use crate::schema::OcsfProfile;
        use std::sync::Arc;
        let gen = ClickHouseSqlGenerator::new().with_profile(Arc::new(OcsfProfile::new()));
        let q = parse_query(
            "source_type=windows_sysmon | join user [search source_type=windows_event]",
        )
        .unwrap();
        let sql = gen.generate(&q, &time_range()).unwrap();
        assert!(
            sql.contains("ON main.user_unified = sub.user_unified"),
            "OCSF join must compare the profile-resolved unified column on both sides, got:\n{sql}"
        );
        // The per-key empty-eviction filter and LIMIT BY must bind to the SAME
        // resolved column, or the anti-explosion cap misses the join key.
        assert!(
            sql.contains("toString(user_unified) != ''"),
            "OCSF join empty-key eviction must filter the resolved column, got:\n{sql}"
        );
        assert!(
            sql.contains("LIMIT 1 BY user_unified"),
            "OCSF join per-key cap must LIMIT BY the resolved column, got:\n{sql}"
        );
        assert!(
            !sql.contains("main.\"user\"") && !sql.contains("sub.\"user\""),
            "OCSF join must not reference the bare UDM `user` column (Code 47), got:\n{sql}"
        );
    }

    /// NAN-1413 parity pin: UDM join emission is byte-unchanged — every branch of
    /// the per-side key resolution collapses to the legacy
    /// `escape_identifier(normalize_field_name(f))` under UDM (no class split, and
    /// an explicit column's access expression is its escaped name). Verified
    /// byte-for-byte against main's generator output during the fix; pinned here.
    #[test]
    fn udm_join_sql_unchanged() {
        let q = parse_query(
            "source_type=windows_sysmon | join user [search source_type=windows_event]",
        )
        .unwrap();
        let sql = ClickHouseSqlGenerator::new()
            .generate(&q, &time_range())
            .unwrap();
        assert!(
            sql.contains("ON main.\"user\" = sub.\"user\""),
            "UDM join must keep the legacy bare-column condition, got:\n{sql}"
        );
        assert!(
            sql.contains("toString(\"user\") != ''") && sql.contains("LIMIT 1 BY \"user\""),
            "UDM join key filter/cap must stay on the bare column, got:\n{sql}"
        );
        assert!(
            !sql.contains("user_unified"),
            "UDM must never reference OCSF unified columns, got:\n{sql}"
        );
    }

    /// NAN-1413: multi-field join resolves EACH key independently per profile —
    /// under OCSF `user` is class-split (→ `user_unified`) while `src_ip` is a
    /// dotted promoted column (→ `"src_endpoint.ip"`, which stays valid under the
    /// `main.`/`sub.` qualifiers). UDM keeps both keys bare. Executed live on
    /// both tables (OCSF 8 joined rows = hand-written tuple-IN equivalent).
    #[test]
    fn join_multi_field_key_resolution_both_profiles() {
        use crate::schema::OcsfProfile;
        use std::sync::Arc;
        let q = parse_query(
            "source_type=windows_sysmon | join user, src_ip [search source_type=windows_event]",
        )
        .unwrap();
        let ocsf_sql = ClickHouseSqlGenerator::new()
            .with_profile(Arc::new(OcsfProfile::new()))
            .generate(&q, &time_range())
            .unwrap();
        assert!(
            ocsf_sql.contains(
                "ON main.user_unified = sub.user_unified AND main.\"src_endpoint.ip\" = sub.\"src_endpoint.ip\""
            ),
            "OCSF multi-field join must resolve each key through the profile, got:\n{ocsf_sql}"
        );
        assert!(
            ocsf_sql.contains("LIMIT 1 BY user_unified, \"src_endpoint.ip\""),
            "OCSF multi-field per-key cap must use the resolved columns, got:\n{ocsf_sql}"
        );

        let udm_sql = ClickHouseSqlGenerator::new()
            .generate(&q, &time_range())
            .unwrap();
        assert!(
            udm_sql.contains("ON main.\"user\" = sub.\"user\" AND main.src_ip = sub.src_ip"),
            "UDM multi-field join must keep the legacy bare columns, got:\n{udm_sql}"
        );
        assert!(
            udm_sql.contains("LIMIT 1 BY \"user\", src_ip"),
            "UDM multi-field per-key cap must stay on the bare columns, got:\n{udm_sql}"
        );
    }

    /// NAN-1413: the two sides of a join resolve INDEPENDENTLY. An aggregated
    /// subsearch (`[… | stats count by user]`) projects the key back under its
    /// bare normalized name (`user_unified AS user`), so the sub side references
    /// `sub."user"` while the wide outer side references `main.user_unified` —
    /// forcing one shared name on both sides would make one of them Code 47.
    /// Executed live on OCSF CH: 50 joined rows, equal to the wide-sub variant
    /// and to a hand-written IN-subquery equivalent.
    #[test]
    fn ocsf_join_aggregated_subsearch_resolves_sides_independently() {
        use crate::schema::OcsfProfile;
        use std::sync::Arc;
        let q = parse_query(
            "source_type=windows_sysmon | join user [search source_type=windows_event | stats count by user]",
        )
        .unwrap();
        let sql = ClickHouseSqlGenerator::new()
            .with_profile(Arc::new(OcsfProfile::new()))
            .generate(&q, &time_range())
            .unwrap();
        assert!(
            sql.contains("ON main.user_unified = sub.\"user\""),
            "OCSF join with aggregated sub must mix sides (wide main → unified, projected sub → bare alias), got:\n{sql}"
        );
        assert!(
            sql.contains("toString(\"user\") != ''") && sql.contains("LIMIT 1 BY \"user\""),
            "sub-side filter/cap must bind to the sub's projected key column, got:\n{sql}"
        );
    }

    /// NAN-1413: an upstream eval that value-computes exactly the normalized key
    /// name shadows the schema column (NAN-1341) — the outer side must reference
    /// the bare computed column, not re-resolve to the unified column the eval
    /// just shadowed.
    #[test]
    fn ocsf_join_eval_computed_key_stays_bare() {
        use crate::schema::OcsfProfile;
        use std::sync::Arc;
        let q = parse_query(
            "source_type=windows_sysmon | eval user=\"x\" | join user [search source_type=windows_event]",
        )
        .unwrap();
        let sql = ClickHouseSqlGenerator::new()
            .with_profile(Arc::new(OcsfProfile::new()))
            .generate(&q, &time_range())
            .unwrap();
        assert!(
            sql.contains("ON main.\"user\" = sub.user_unified"),
            "eval-computed key must shadow the profile resolution on the main side only, got:\n{sql}"
        );
    }

    /// NAN-1420: a second `| join` chained after a wide-sub join must still
    /// resolve its keys through the schema profile. The first wide join used to
    /// collapse the pipeline shape to `Unknown` (Wide+Wide), so the second
    /// join's main-side key fell back to the legacy bare emission —
    /// `main.src_ip` does not exist on ocsf_logs → Code 47. The wide guarantee
    /// now carries through as `WideJoined`, and the chained join's subsearch
    /// gets a stage-unique alias (`sub_2`): the prior join's `SELECT *` leaked
    /// literal `sub.<col>` columns into the main side, and ClickHouse binds a
    /// reused `sub."x"` qualifier to that dotted main-side column instead of
    /// the new sub table (Code 48 "JOIN ON constant", observed live).
    /// Validated end-to-end on live OCSF CH (1.19M rows): pre-fix Code 47;
    /// post-fix a deterministic chain (sub filters < 10k rows) returns 64
    /// matched rows = a hand-written double-JOIN equivalent.
    #[test]
    fn ocsf_chained_join_resolves_second_key_with_unique_alias() {
        use crate::schema::OcsfProfile;
        use std::sync::Arc;
        let q = parse_query(
            "source_type=windows_sysmon | join user [search source_type=windows_event] | join src_ip [search source_type=conduit_proxy]",
        )
        .unwrap();
        let sql = ClickHouseSqlGenerator::new()
            .with_profile(Arc::new(OcsfProfile::new()))
            .generate(&q, &time_range())
            .unwrap();
        // First join: byte-unchanged from NAN-1413.
        assert!(
            sql.contains(") AS sub ON main.user_unified = sub.user_unified"),
            "first OCSF join must keep the NAN-1413 emission, got:\n{sql}"
        );
        // Second join: profile-resolved key on BOTH sides, stage-unique alias.
        assert!(
            sql.contains(") AS sub_2 ON main.\"src_endpoint.ip\" = sub_2.\"src_endpoint.ip\""),
            "chained OCSF join must resolve the second key through the profile \
             under a stage-unique sub alias, got:\n{sql}"
        );
        assert!(
            !sql.contains("main.src_ip"),
            "chained OCSF join must not fall back to the bare UDM key (Code 47), got:\n{sql}"
        );
    }

    /// NAN-1420: every chained join gets its own stage-unique alias — a third
    /// join after two wide joins must not collide with `sub.<col>` OR
    /// `sub_2.<col>` columns leaked by the earlier stages.
    #[test]
    fn ocsf_triple_chained_join_aliases_stay_unique() {
        use crate::schema::OcsfProfile;
        use std::sync::Arc;
        let q = parse_query(
            "source_type=windows_sysmon | join user [search source_type=windows_event] | join src_ip [search source_type=conduit_proxy] | join dest_ip [search source_type=aws_cloudtrail]",
        )
        .unwrap();
        let sql = ClickHouseSqlGenerator::new()
            .with_profile(Arc::new(OcsfProfile::new()))
            .generate(&q, &time_range())
            .unwrap();
        assert!(
            sql.contains(") AS sub_2 ON main.\"src_endpoint.ip\" = sub_2.\"src_endpoint.ip\"")
                && sql.contains(") AS sub_3 ON main.\"dst_endpoint.ip\" = sub_3.\"dst_endpoint.ip\""),
            "each chained join must use a distinct per-stage sub alias, got:\n{sql}"
        );
    }

    /// NAN-1423: UDM chained joins get the same stage-unique sub alias as OCSF
    /// (`sub_2`, `sub_3`, …). The predecessor pin (`udm_chained_join_sql_unchanged`,
    /// NAN-1420) deliberately froze the legacy reused-`sub` emission for byte
    /// parity — but that emission had ALWAYS died on ClickHouse with Code 48
    /// ("JOIN ON constant"): the first join's `SELECT *` leaks literal
    /// `sub.<col>` columns into the main side and the second join's reused
    /// `sub."x"` qualifier binds to that dotted column, collapsing the ON to
    /// one table. There was no working behavior to preserve, so the gate is
    /// gone. Key RESOLUTION stays legacy-bare under UDM (no unified columns).
    /// Validated end-to-end on live UDM CH (`logs`, 2.06M rows): the pre-fix
    /// SQL reproduces Code 48; post-fix a deterministic chain (bounded subs,
    /// LIMIT never truncating) returns matched rows equal to a hand-written
    /// double-JOIN equivalent.
    #[test]
    fn udm_chained_join_uses_stage_unique_alias() {
        let q = parse_query(
            "source_type=windows_sysmon | join user [search source_type=windows_event] | join src_ip [search source_type=conduit_proxy]",
        )
        .unwrap();
        let sql = ClickHouseSqlGenerator::new()
            .generate(&q, &time_range())
            .unwrap();
        // First join: byte-unchanged legacy emission (plain `sub`, bare key).
        assert!(
            sql.contains(") AS sub ON main.\"user\" = sub.\"user\""),
            "first UDM join must keep the legacy `sub` alias and bare key, got:\n{sql}"
        );
        // Second join: stage-unique alias, keys still legacy-bare.
        assert!(
            sql.contains(") AS sub_2 ON main.src_ip = sub_2.src_ip"),
            "chained UDM join must use a stage-unique sub alias (Code 48 \
             leak-capture fix, NAN-1423), got:\n{sql}"
        );
        assert!(
            !sql.contains("user_unified"),
            "UDM must never resolve keys to OCSF unified columns, got:\n{sql}"
        );
    }

    /// NAN-1423: a SINGLE (non-chained) UDM join keeps the plain `sub` alias
    /// byte-for-byte — the stage-unique alias only kicks in when the main side
    /// is already `WideJoined` (i.e. second+ joins), exactly as under OCSF.
    #[test]
    fn udm_single_join_keeps_plain_sub_alias() {
        let q = parse_query(
            "source_type=windows_sysmon | join user [search source_type=windows_event]",
        )
        .unwrap();
        let sql = ClickHouseSqlGenerator::new()
            .generate(&q, &time_range())
            .unwrap();
        assert!(
            sql.contains(") AS sub ON main.\"user\" = sub.\"user\""),
            "single UDM join must keep the legacy `sub` alias and bare key, got:\n{sql}"
        );
        assert!(
            !sql.contains("sub_2"),
            "single UDM join must not get a stage-unique alias, got:\n{sql}"
        );
    }

    /// NAN-1420 (quirk pinned deliberately): `eval username=… | join username`
    /// resolves the key to the BASE schema column (`user_unified` under OCSF),
    /// not the eval'd `username` column — the join key normalizes
    /// `username` → `user` before the NAN-1341 shadow check, and the eval
    /// created a column literally named `username`, which never shadows the
    /// normalized name. Parity-correct with UDM legacy semantics (UDM joins on
    /// the `user` column there too); pinned so a future change is a decision,
    /// not an accident.
    #[test]
    fn ocsf_join_eval_aliased_key_resolves_to_base_column() {
        use crate::schema::OcsfProfile;
        use std::sync::Arc;
        let q = parse_query(
            "source_type=windows_sysmon | eval username=\"x\" | join username [search source_type=windows_event]",
        )
        .unwrap();
        let sql = ClickHouseSqlGenerator::new()
            .with_profile(Arc::new(OcsfProfile::new()))
            .generate(&q, &time_range())
            .unwrap();
        assert!(
            sql.contains("ON main.user_unified = sub.user_unified"),
            "`join username` must resolve to the base unified column (legacy-parity \
             quirk), got:\n{sql}"
        );
        assert!(
            !sql.contains("main.\"username\""),
            "the eval'd `username` column must not capture the normalized join key, got:\n{sql}"
        );
    }

    /// NAN-1420 append safety: the Wide+Wide join rule used to collapse to
    /// `Unknown`, which made a downstream `append` refuse with the actionable
    /// shape error. The new `WideJoined` shape must keep that refusal —
    /// the join stage's `SELECT *` output carries leaked `sub.<col>` duplicates
    /// and is NOT positionally alignable with a passthrough UNION arm.
    #[test]
    fn append_after_wide_join_still_refuses() {
        use crate::schema::OcsfProfile;
        use std::sync::Arc;
        let q = parse_query(
            "source_type=windows_sysmon | join user [search source_type=windows_event] | append [search source_type=conduit_proxy]",
        )
        .unwrap();
        for gen in [
            ClickHouseSqlGenerator::new(),
            ClickHouseSqlGenerator::new().with_profile(Arc::new(OcsfProfile::new())),
        ] {
            let err = gen.generate(&q, &time_range()).unwrap_err();
            assert!(
                matches!(&err, SqlGenError::UnsupportedOperation(m) if m.contains("append")),
                "append after a wide-sub join must keep refusing with the shape \
                 error (pre-NAN-1420 behavior), got: {err:?}"
            );
        }
    }

    /// NAN-1319 parity: under UDM a class-split concept does not exist — `src_host`
    /// IS one column, so `class_split_value_sql` returns `None` and GROUP BY / the
    /// projection stay the bare column, byte-for-byte unchanged.
    #[test]
    fn udm_stats_by_src_host_unchanged() {
        let query = parse_query("* | stats count by src_host").unwrap();
        let sql = ClickHouseSqlGenerator::new()
            .generate(&query, &time_range())
            .unwrap();
        assert!(
            sql.contains("SELECT src_host AS src_host") && sql.contains("GROUP BY src_host"),
            "UDM `stats by src_host` must stay the bare column (no `if(...)`), got:\n{sql}"
        );
        assert!(
            !sql.contains("device.hostname"),
            "UDM must never reference OCSF columns, got:\n{sql}"
        );
    }

    /// NAN-1321: an OCSF search FILTER on a class-split concept (`src_host="x"`)
    /// must match the union (so it finds the host on `device.hostname` endpoint
    /// events) — never a single primary column that would silently drop every
    /// device-host row. Validated end-to-end on live OCSF CH: 39 → 464.
    /// NAN-1333: the WHERE predicate now references the INDEXED unified column
    /// (`src_host_unified`) instead of the inline value-pick `if(...)`, so the words
    /// index prunes granules (prototype: 640/640 → 294/640, identical match counts).
    #[test]
    fn ocsf_filter_on_class_split_host_uses_unified_column() {
        use crate::schema::OcsfProfile;
        use std::sync::Arc;
        let gen = ClickHouseSqlGenerator::new().with_profile(Arc::new(OcsfProfile::new()));
        let col = "src_host_unified";

        // Equality: WHERE matches the unified column; PREWHERE must not carry the host.
        // NAN-1333: no `toString` wrapper — `lower(<col>_unified)` matches the words
        // text index by expression and prunes (the toString form orphans the index).
        let sql = gen
            .generate(&parse_query("src_host=\"ws-01\"").unwrap(), &time_range())
            .unwrap();
        assert!(
            sql.contains(&format!("lower({col}) = 'ws-01'"))
                && !sql.contains(&format!("lower(toString({col}))")),
            "OCSF src_host= must filter on the unified column WITHOUT toString (index-matchable), got:\n{sql}"
        );
        // The skip-index-opaque inline if(...) must NOT appear in WHERE anymore.
        assert!(
            !sql.contains("if(\"src_endpoint.hostname\""),
            "OCSF src_host= must not emit the inline if(...), got:\n{sql}"
        );
        // NAN-1412: no explicit PREWHERE anywhere — placement is ClickHouse's
        // call, so the old "must not promote the primary column" hazard is gone
        // structurally.
        assert!(
            !sql.contains("PREWHERE"),
            "no explicit PREWHERE may be emitted (NAN-1412), got:\n{sql}"
        );

        // Negation stays correct with the single column (no De Morgan).
        let sql_ne = gen
            .generate(&parse_query("src_host!=\"ws-01\"").unwrap(), &time_range())
            .unwrap();
        assert!(
            sql_ne.contains(&format!("lower({col}) != 'ws-01'")),
            "OCSF src_host!= must negate the unified column, got:\n{sql_ne}"
        );

        // IN-list (the UDM alias is not a promoted column, so it must be routed
        // explicitly rather than falling to the empty metadata-JSON branch).
        let sql_in = gen
            .generate(&parse_query("src_host IN (\"a\",\"b\")").unwrap(), &time_range())
            .unwrap();
        assert!(
            sql_in.contains(&format!("lower({col}) IN ('a', 'b')")),
            "OCSF src_host IN must match the unified column, got:\n{sql_in}"
        );
    }

    /// NAN-1321 parity: UDM has no class-split, so a `src_host="x"` filter stays
    /// the single column in WHERE with the hostname FQDN expansion. The lower()
    /// form is deliberate — the `lower(src_host)` text index serves both OR arms
    /// (equality + startsWith), while the raw form's startsWith arm is not
    /// bloom-servable (2026-06-12 query audit, verified on local CH).
    #[test]
    fn udm_filter_on_src_host_unchanged() {
        let sql = ClickHouseSqlGenerator::new()
            .generate(&parse_query("src_host=\"ws-01\"").unwrap(), &time_range())
            .unwrap();
        let where_clause = where_slice(&sql);
        assert!(
            where_clause.contains("lower(src_host) = 'ws-01'")
                && where_clause.contains("startsWith(lower(src_host), 'ws-01.')"),
            "UDM src_host= must keep the lower()-column equality + FQDN expansion in WHERE, got:\n{where_clause}"
        );
        assert!(
            !sql.contains("device.hostname") && !sql.contains("if("),
            "UDM must never emit OCSF columns or the class-split `if(...)`, got:\n{sql}"
        );
    }

    /// NAN-1412: every generated query carries a SINGLE WHERE with all conjuncts
    /// (time bounds first) and never an explicit PREWHERE. An explicit PREWHERE
    /// disables ClickHouse's `optimize_move_to_prewhere`, so every non-promoted
    /// filter (ranges, CONTAINS/regex, JSON-tail, unified columns) was evaluated
    /// only after reading the full projection — measured up to 349x read_bytes
    /// on zero-match entity hunts. A plain WHERE was byte-identical in I/O to a
    /// hand-tuned PREWHERE in every probe, including the previously-promoted
    /// paths (`source_type=` did not regress).
    #[test]
    fn single_where_no_prewhere_both_profiles() {
        use crate::schema::OcsfProfile;
        use std::sync::Arc;
        let udm = ClickHouseSqlGenerator::new();
        let ocsf = ClickHouseSqlGenerator::new().with_profile(Arc::new(OcsfProfile::new()));

        // Cover every emission shape: plain search, search|head (fast path),
        // multi-stage CTE, stats aggregation, subsearch join, and subsearch IN.
        let queries = [
            "error",
            "source_type=windows_sysmon user=\"admin\"",
            "error | head 50",
            "dest_port>=1024 dest_port<=2048 | stats count by src_ip | where count > 10",
            "* | stats count by source_type",
            "user=\"a\" | join user [search source_type=x | head 5]",
            "src_ip IN [search dest_port=443 | return src_ip]",
        ];
        for (gen, profile) in [(&udm, "UDM"), (&ocsf, "OCSF")] {
            for q in queries {
                let sql = gen
                    .generate(&parse_query(q).unwrap(), &time_range())
                    .unwrap();
                assert!(
                    !sql.contains("PREWHERE"),
                    "{profile} `{q}` must not emit an explicit PREWHERE (NAN-1412), got:\n{sql}"
                );
                // Time bounds stay in the WHERE conjunct chain, same DateTime64
                // literal format as before (only the keyword changed).
                assert!(
                    sql.contains("WHERE timestamp BETWEEN '2024-01-01 00:00:00.000000' AND '2024-01-02 00:00:00.000000'"),
                    "{profile} `{q}` must carry the time bounds as the first WHERE conjunct, got:\n{sql}"
                );
                // Exactly one base-scan filter keyword per table scan: every WHERE
                // is followed by the timestamp guard (no second filter clause on
                // the raw table), except CTE-stage WHEREs on derived stages.
                assert!(
                    !sql.contains("WHERE (1) WHERE") && !sql.contains(") WHERE ("),
                    "{profile} `{q}` must not emit split filter clauses, got:\n{sql}"
                );
            }
        }
    }

    /// NAN-1412: the read-in-order toggle survives the PREWHERE removal — a
    /// selective indexed equality (src_ip/user/…) still disables
    /// `optimize_read_in_order`; a broad source_type filter keeps it on.
    #[test]
    fn read_in_order_toggle_survives_single_where() {
        let gen = ClickHouseSqlGenerator::new();
        let selective = gen
            .generate(&parse_query("src_ip=\"10.0.0.1\"").unwrap(), &time_range())
            .unwrap();
        assert!(
            selective.contains("optimize_read_in_order=0"),
            "selective indexed equality must disable read-in-order, got:\n{selective}"
        );
        let broad = gen
            .generate(&parse_query("source_type=windows_sysmon").unwrap(), &time_range())
            .unwrap();
        assert!(
            broad.contains("optimize_read_in_order=1"),
            "broad source_type filter must keep read-in-order, got:\n{broad}"
        );
    }

    /// NAN-1299 parity: UDM filter output keeps the identity-column raw-equality
    /// fast path (`src_ip = '…'`, no lower() wrapper) in the single WHERE.
    #[test]
    fn udm_where_keeps_raw_equality_for_alias_fields() {
        let query = parse_query("src_ip=\"89.248.167.131\"").unwrap();
        let sql = ClickHouseSqlGenerator::new()
            .generate(&query, &time_range())
            .unwrap();
        let where_clause = where_slice(&sql);
        assert!(
            where_clause.contains("src_ip = '89.248.167.131'"),
            "UDM WHERE must keep the direct `src_ip = '…'` fast path, got:\n{where_clause}"
        );
    }

    /// NAN-1381 (root cause of NAN-1247): non-Eq string operators on a UDM alias
    /// that resolves to a plain non-null String column must reference `lower(col)`,
    /// never `toString(col)` — ClickHouse matches a text/bloom skip index by
    /// EXPRESSION, so the toString wrapper orphans every `lower(col)` index and
    /// full-scans (601/601 granules vs 55/601 via idx_user_unified_words on a
    /// `user CONTAINS "intern"` probe, local CH; counts identical — toString is a
    /// semantic no-op on a MATERIALIZED-'' String column).
    #[test]
    fn ocsf_alias_string_pattern_ops_use_lower_not_tostring() {
        use crate::schema::OcsfProfile;
        let gen = ClickHouseSqlGenerator::new().with_profile(Arc::new(OcsfProfile::new()));

        // Class-split alias → unified column, every string-pattern arm.
        for (q, want) in [
            ("user CONTAINS \"intern\"", "lower(user_unified) iLike '%intern%'"),
            (
                "NOT user CONTAINS \"intern\"",
                "lower(user_unified) iLike '%intern%'",
            ),
            ("user=/intern/", "lower(user_unified) iLike '%intern%'"),
            ("user=\"inte*\"", "lower(user_unified) iLike 'inte%'"),
            ("user!=\"inte*\"", "lower(user_unified) NOT iLike 'inte%'"),
            ("user STARTSWITH \"inte\"", "lower(user_unified) iLike 'inte%'"),
            ("user ENDSWITH \"ern\"", "lower(user_unified) iLike '%ern'"),
            ("user LIKE \"%intern%\"", "lower(user_unified) iLike '%intern%'"),
        ] {
            let sql = gen.generate(&parse_query(q).unwrap(), &time_range()).unwrap();
            assert!(
                sql.contains(want) && !sql.contains("toString(user_unified)"),
                "OCSF `{q}` must use the index-matchable lower(user_unified) form, got:\n{sql}"
            );
        }

        // Promoted-column alias (Eq exception broadened beyond class-split):
        // NAN-1412 — the resolved column is in `OCSF_LOWERCASED_AT_INGEST`, so
        // Eq drops the lower() wrapper entirely and the RAW-column bloom index
        // can prune (lower(col)= orphans it; pre-NAN-1412 the raw form lived in
        // the explicit-PREWHERE duplicate, now this arm is the only emission).
        // The literal still lowercases — data is ingest-lowercased.
        let sql = gen
            .generate(&parse_query("file_hash=\"ab12\"").unwrap(), &time_range())
            .unwrap();
        assert!(
            sql.contains("(\"file.hashes.sha256\" = 'ab12')")
                && !sql.contains("toString(\"file.hashes.sha256\")"),
            "OCSF file_hash= must compare the raw ingest-lowercased column (NAN-1412), got:\n{sql}"
        );
        let sql = gen
            .generate(
                &parse_query("file_hash CONTAINS \"ab12\"").unwrap(),
                &time_range(),
            )
            .unwrap();
        assert!(
            sql.contains("lower(\"file.hashes.sha256\") iLike '%ab12%'"),
            "OCSF file_hash CONTAINS must use lower(col), got:\n{sql}"
        );

        // A UDM alias resolving to a NUMERIC column must keep the toString guard —
        // the type check consults the RESOLVED column (`is_numeric_field("src_port")`
        // is false under OCSF even though `src_endpoint.port` is UInt16; lower()
        // on a numeric column is a CH type error).
        let sql = gen
            .generate(
                &parse_query("src_port CONTAINS \"44\"").unwrap(),
                &time_range(),
            )
            .unwrap();
        assert!(
            sql.contains("toString(\"src_endpoint.port\") iLike '%44%'"),
            "OCSF src_port CONTAINS must keep toString on the numeric target, got:\n{sql}"
        );

        // An unpromoted JSON-tail field keeps the NAN-1161 toString null-guard:
        // a missing key must read as '' so negation keeps absent-key rows.
        // NAN-1426: the tail access is native subcolumn (the multiIf parity
        // form), no longer `JSONExtractString(…)` which re-serialized the whole
        // JSON per row; the multiIf itself yields '' for missing keys and the
        // outer toString wrapper is preserved. NAN-1443: the tail column is the
        // stored `unmapped` spill (was the now-EPHEMERAL `event`).
        let sql = gen
            .generate(
                &parse_query("custom_tail_key CONTAINS \"x\"").unwrap(),
                &time_range(),
            )
            .unwrap();
        assert!(
            sql.contains(
                "toString(multiIf(isNotNull(unmapped.\"custom_tail_key\"), \
                 toString(unmapped.\"custom_tail_key\"), \
                 toJSONString(unmapped.^\"custom_tail_key\") != '{}', \
                 toJSONString(unmapped.^\"custom_tail_key\"), '')) iLike '%x%'"
            ),
            "OCSF JSON-tail CONTAINS must keep the toString null-guard over the subcolumn access, got:\n{sql}"
        );
    }

    /// NAN-1426: OCSF JSON-tail filters access the `event` column via native
    /// subcolumns, never `JSONExtract*(event, …)` (which re-serializes the whole
    /// event per row — 8.06 GiB vs 64 MiB read on the local 3M-row headline
    /// probe). Pins the two filter-arm parity forms end-to-end:
    /// - string negation keeps the NAN-1161 guarantee: the multiIf yields ''
    ///   (never NULL) for missing keys, so `!=` keeps absent-key rows;
    /// - numeric comparisons carry the MANDATORY coalesce(…, 0.) — without it
    ///   `=0` flips 2.7M→0 and `!=N` drops every absent-key row (measured).
    #[test]
    fn nan1426_ocsf_tail_filters_use_subcolumn_access() {
        use crate::schema::OcsfProfile;
        let gen = ClickHouseSqlGenerator::new().with_profile(Arc::new(OcsfProfile::new()));

        // Negated string compare on an unpromoted tail path.
        let sql = gen
            .generate(
                &parse_query("unmapped.signature_status != \"valid\"").unwrap(),
                &time_range(),
            )
            .unwrap();
        assert!(
            sql.contains(
                "lower(toString(multiIf(isNotNull(unmapped.\"signature_status\"), \
                 toString(unmapped.\"signature_status\"), \
                 toJSONString(unmapped.^\"signature_status\") != '{}', \
                 toJSONString(unmapped.^\"signature_status\"), ''))) != 'valid'"
            ) && !sql.contains("JSONExtractString(unmapped"),
            "OCSF negated tail string compare must use the ''-defaulting subcolumn multiIf, got:\n{sql}"
        );

        // Numeric compare on an unpromoted tail path.
        let sql = gen
            .generate(
                &parse_query("unmapped.error_code=23").unwrap(),
                &time_range(),
            )
            .unwrap();
        // NAN-1443: the spill is the stored `unmapped` column, addressed with a
        // RELATIVE path (was `event."unmapped"."error_code"` pre-chop).
        assert!(
            sql.contains(
                "coalesce(accurateCastOrNull(unmapped.\"error_code\", 'Float64'), 0.) = 23"
            ) && !sql.contains("JSONExtractFloat("),
            "OCSF numeric tail compare must use the coalesced subcolumn cast, got:\n{sql}"
        );

        // Bool tail compare deliberately keeps JSONExtractBool (cast form is
        // not parity-safe for string-typed "true" values).
        let sql = gen
            .generate(
                &parse_query("unmapped.signed=true").unwrap(),
                &time_range(),
            )
            .unwrap();
        assert!(
            sql.contains("JSONExtractBool(unmapped, 'signed')"),
            "OCSF bool tail compare must keep JSONExtractBool, got:\n{sql}"
        );
    }

    /// NAN-1426 unit pins for `json_tail_access_sql` — one per parity
    /// carve-out. The empirical battery (identical counts/checksums vs the old
    /// JSONExtract emission on 3M-row local ocsf_logs, incl. the missing-key
    /// `=0`/`!=N` flips, object-valued paths, and arrays) lives in the PR.
    #[test]
    fn nan1426_json_tail_access_sql_carveouts() {
        // String → the multiIf parity form: scalar/array leaves via
        // toString(sub) (JSONExtractString-over-a-JSON-column formats arrays
        // identically — it operates on the column's own CH serialization);
        // object-valued paths via toJSONString(event.^…) (byte-equal to the
        // old raw-JSON return); missing keys/JSON nulls → '' never NULL
        // (NAN-1161: negation keeps absent-key rows).
        assert_eq!(
            json_tail_access_sql(
                "event",
                &["unmapped".to_string(), "signature_status".to_string()],
                "String"
            ),
            "multiIf(isNotNull(event.\"unmapped\".\"signature_status\"), \
             toString(event.\"unmapped\".\"signature_status\"), \
             toJSONString(event.^\"unmapped\".\"signature_status\") != '{}', \
             toJSONString(event.^\"unmapped\".\"signature_status\"), '')"
        );

        // Float → coalesce(accurateCastOrNull(…, 'Float64'), 0.). The coalesce
        // is MANDATORY (missing key: JSONExtractFloat=0, bare cast=NULL).
        assert_eq!(
            json_tail_access_sql(
                "event",
                &["unmapped".to_string(), "EventID".to_string()],
                "Float"
            ),
            "coalesce(accurateCastOrNull(event.\"unmapped\".\"EventID\", 'Float64'), 0.)"
        );

        // Bool stays on JSONExtractBool: accurateCastOrNull('true','Bool') is
        // true where JSONExtractBool returns false for string-typed values.
        assert_eq!(
            json_tail_access_sql("event", &["unmapped".to_string(), "signed".to_string()], "Bool"),
            "JSONExtractBool(event, 'unmapped', 'signed')"
        );

        // Raw/array suffixes keep the legacy JSONExtract forms untouched
        // (arrayFirst/hashes/enrichment patterns depend on raw-JSON returns).
        assert_eq!(
            json_tail_access_sql("event", &["file".to_string(), "hashes".to_string()], "ArrayRaw"),
            "JSONExtractArrayRaw(event, 'file', 'hashes')"
        );

        // Path segments embed as double-quoted identifiers, backslash-escaped
        // FIRST then ""-doubled — CH honors both escape forms inside quoted
        // identifiers (verified on 26.4), so a raw `\` would silently address
        // the wrong key and an embedded quote could break out.
        assert_eq!(
            json_tail_access_sql("event", &["se\"lect".to_string()], "Float"),
            "coalesce(accurateCastOrNull(event.\"se\"\"lect\", 'Float64'), 0.)"
        );
        assert_eq!(
            json_tail_access_sql("event", &["a\\b".to_string()], "Float"),
            "coalesce(accurateCastOrNull(event.\"a\\\\b\", 'Float64'), 0.)"
        );
    }

    /// NAN-1426: `generate_json_extract` (the seam OCSF dotted tails route
    /// through in eval/where/sort contexts) emits the SAME subcolumn forms —
    /// the two chokepoints stay in lockstep — while UDM stays byte-unchanged
    /// on both its spill arm and the metadata column (a plain String column,
    /// where subcolumn syntax does not apply).
    #[test]
    fn nan1426_chokepoints_lockstep_and_udm_pinned() {
        use crate::schema::OcsfProfile;
        let ocsf = ClickHouseSqlGenerator::new().with_profile(Arc::new(OcsfProfile::new()));
        assert_eq!(
            ocsf.generate_json_extract("unmapped.error_code", "Float"),
            // NAN-1443: spill addressed relative to the stored `unmapped` column.
            "coalesce(accurateCastOrNull(unmapped.\"error_code\", 'Float64'), 0.)"
        );
        assert_eq!(
            ocsf.generate_json_extract("connection_info.direction", "String"),
            ocsf.field_access_expr("connection_info.direction", "String"),
        );

        // UDM byte-unchanged: the spill arm already does native ext.{field}
        // subcolumn access, and resolve never yields JsonPath.
        let udm = ClickHouseSqlGenerator::new();
        assert_eq!(udm.field_access_expr("custom_key", "String"), "ext.custom_key");
        assert_eq!(udm.field_access_expr("custom_key", "Float"), "ext.custom_key");
        assert_eq!(
            udm.generate_json_extract("metadata_endpoint", "String"),
            "JSONExtractString(metadata, 'endpoint')"
        );
    }

    /// NAN-1381 (UDM side of the shared gap): wildcard / STARTSWITH / ENDSWITH /
    /// LIKE previously emitted the bare column (`user iLike 'bob%'`), which cannot
    /// use the `lower(col)` text indexes. They now emit the lowered form the
    /// Contains/Regex arms already used — iLike is case-insensitive either way, so
    /// matches are unchanged (count-identity verified on local CH, 543/543 →
    /// 334/543 granules on a `user` contains-shaped probe).
    #[test]
    fn udm_wildcard_prefix_suffix_like_use_lowered_column() {
        let gen = ClickHouseSqlGenerator::new();
        for (q, want) in [
            ("user=\"bob*\"", "lower(\"user\") iLike 'bob%'"),
            ("user!=\"bob*\"", "lower(\"user\") NOT iLike 'bob%'"),
            ("user STARTSWITH \"bob\"", "lower(\"user\") iLike 'bob%'"),
            ("user ENDSWITH \"son\"", "lower(\"user\") iLike '%son'"),
            ("user LIKE \"%wilson%\"", "lower(\"user\") iLike '%wilson%'"),
            // Contains was already lowered (NAN-1026/NAN-1247) — pinned here so the
            // whole pattern family stays on one form.
            ("user CONTAINS \"wilson\"", "lower(\"user\") iLike '%wilson%'"),
        ] {
            let sql = gen.generate(&parse_query(q).unwrap(), &time_range()).unwrap();
            assert!(
                sql.contains(want),
                "UDM `{q}` must use the lowered index-matchable form, got:\n{sql}"
            );
        }

        // UDM ext-spill fields keep the NAN-1161 toString null-guard on the
        // pattern arms (missing key must read '' so negation keeps absent rows).
        let sql = gen
            .generate(
                &parse_query("integrity_level CONTAINS \"high\"").unwrap(),
                &time_range(),
            )
            .unwrap();
        assert!(
            sql.contains("toString(ext.integrity_level) iLike '%high%'"),
            "UDM ext CONTAINS must keep the toString null-guard, got:\n{sql}"
        );

        // UDM equality stays the bare indexed comparison; the bare keyword now
        // drives idx_message_words via hasAllTokens (NAN-1515).
        let sql = gen
            .generate(&parse_query("user=\"bob\" error").unwrap(), &time_range())
            .unwrap();
        assert!(
            sql.contains("\"user\" = 'bob'")
                && sql.contains("hasAllTokens(lower(message), 'error')"),
            "UDM Eq stays bare; bare keyword uses hasAllTokens, got:\n{sql}"
        );
    }

    /// Extract the PREWHERE clause text (up to the following WHERE/GROUP/ORDER/LIMIT).
    /// Extract the WHERE clause text (up to the following GROUP/ORDER/LIMIT or
    /// CTE close) so assertions don't accidentally match SELECT-list aliases.
    fn where_slice(sql: &str) -> String {
        let start = match sql.find("WHERE") {
            Some(i) => i,
            None => return String::new(),
        };
        let rest = &sql[start..];
        let end = ["GROUP BY", "ORDER BY", "LIMIT", "\n)"]
            .iter()
            .filter_map(|m| rest.find(m))
            .min()
            .unwrap_or(rest.len());
        rest[..end].to_string()
    }

    /// NAN-671: the unfiltered SELECT * path must drop the physical `action`
    /// column from result projections and surface it as `event_type` instead.
    /// ClickHouse returns physical column names (not aliases) for `SELECT *`,
    /// so the canonical UDM name only reaches result headers if we explicitly
    /// EXCEPT the column and re-project under the alias name.
    #[test]
    fn select_star_excepts_action_and_renames_to_event_type() {
        let query = parse_query("error").unwrap();
        let sql = ClickHouseSqlGenerator::new()
            .generate(&query, &time_range())
            .unwrap();

        assert!(
            sql.contains("* EXCEPT (action)"),
            "expected `* EXCEPT (action)` to drop the legacy column from SELECT *, got:\n{}",
            sql
        );
        assert!(
            sql.contains("action AS event_type"),
            "expected `action AS event_type` so result header carries the canonical UDM name, got:\n{}",
            sql
        );
    }

    /// NAN-876: multi-stage CTE chains must keep `action` accessible to
    /// downstream stages. The shadow_hunting LLM agent generates queries
    /// like `... | stats count by action` and `... | where action="foo"`,
    /// and the previous SELECT clause stripped `action` in stage_0 of the
    /// wildcard path, causing ClickHouse to fail with `Unknown expression
    /// identifier \`action\` in scope stage_1`. Pin: when stage_0 falls
    /// back to `SELECT *` (no field-pruning), it must NOT also apply the
    /// NAN-671 EXCEPT — the alias still gets projected, but `action`
    /// stays inside `*` so downstream stages can reference it.
    ///
    /// Uses `sort -timestamp` because it doesn't drive field_analysis to
    /// enumerate explicit columns; it preserves the wildcard path that
    /// the original NAN-876 reproducer (saturn shadow_hunting at
    /// 16:40:51 UTC) hit.
    #[test]
    fn cte_stage_0_preserves_action_for_downstream_reference() {
        let query = parse_query("error | sort -timestamp").unwrap();
        let sql = ClickHouseSqlGenerator::new()
            .generate(&query, &time_range())
            .unwrap();

        let stage_0_marker = "stage_0 AS (";
        let stage_0_start = sql
            .find(stage_0_marker)
            .expect("expected a stage_0 CTE for a piped query");
        let stage_0_end = sql[stage_0_start..]
            .find("),")
            .or_else(|| sql[stage_0_start..].find(')'))
            .map(|i| stage_0_start + i)
            .unwrap_or(sql.len());
        let stage_0_body = &sql[stage_0_start..stage_0_end];

        assert!(
            !stage_0_body.contains("* EXCEPT (action)"),
            "stage_0 must preserve `action` for downstream stages (NAN-876), got:\n{}",
            stage_0_body
        );
        assert!(
            stage_0_body.contains("action AS event_type"),
            "stage_0 should still expose the `event_type` alias alongside `action`, got:\n{}",
            stage_0_body
        );
    }

    /// NAN-876: non-aggregating multi-stage pipelines should still hide
    /// `action` from the final user-facing result, matching NAN-671's
    /// intent. The outer SELECT applies `* EXCEPT (action)` when the
    /// pipeline didn't transform columns away.
    #[test]
    fn cte_outer_select_strips_redundant_action_when_no_aggregation() {
        let query = parse_query("error | sort -timestamp").unwrap();
        let sql = ClickHouseSqlGenerator::new()
            .generate(&query, &time_range())
            .unwrap();

        // Locate the outer SELECT (the one after the last CTE closes).
        // It should EXCEPT(action) because `sort` preserves columns.
        let last_select = sql
            .rfind("SELECT")
            .map(|i| &sql[i..])
            .expect("outer SELECT present");
        assert!(
            last_select.contains("* EXCEPT (action)"),
            "outer SELECT must drop the redundant `action` column when the last stage didn't aggregate, got:\n{}",
            last_select
        );
    }

    /// NAN-876: aggregating pipelines (stats / table / timechart) produce
    /// their own column set in the last CTE — `action` is gone by then,
    /// and the outer SELECT must NOT attempt EXCEPT(action) (CH would
    /// reject the reference). Plain `SELECT *` from the last CTE.
    #[test]
    fn cte_outer_select_plain_when_aggregation_ran() {
        let query = parse_query("error | stats count by user").unwrap();
        let sql = ClickHouseSqlGenerator::new()
            .generate(&query, &time_range())
            .unwrap();

        let last_select = sql
            .rfind("SELECT")
            .map(|i| &sql[i..])
            .expect("outer SELECT present");
        assert!(
            !last_select.contains("EXCEPT (action)"),
            "outer SELECT after an aggregation must not reference `action`, got:\n{}",
            last_select
        );
    }

    // ---- NAN-1026 Phase 2 regression coverage ---------------------------
    // hasToken*-based codegen silently dropped fragment matches when the needle
    // wasn't a whole CH token in the data. Phase 2 lowers all alphanumeric
    // needles to substring iLike instead. These tests pin the bug shapes that
    // motivated the fix so we don't regress to whole-token semantics.

    /// `src_host = /dc/` must lower to substring iLike, not hasTokenCaseInsensitive.
    /// Pre-fix: hosts like `srv-dc01.corp.local` tokenize to `[srv, dc01, corp, local]`
    /// and silently fail the `dc` whole-token check, so all DCs slip through
    /// "find DCs" / "exclude DCs" filters.
    #[test]
    fn regex_fragment_on_udm_field_uses_ilike_not_hastoken() {
        let query = parse_query("src_host = /dc/").unwrap();
        let sql = ClickHouseSqlGenerator::new()
            .generate(&query, &time_range())
            .unwrap();

        assert!(
            sql.contains("iLike '%dc%'"),
            "expected substring iLike, got:\n{}",
            sql
        );
        assert!(
            !sql.contains("hasToken"),
            "must NOT lower to any hasToken variant (silently drops `dc` inside `dc01`), got:\n{}",
            sql
        );
    }

    /// NAN-1157: a literal backslash in a CONTAINS/keyword must reach `\\` in the
    /// iLike pattern *value* — i.e. `\\\\` in the SQL text — or ClickHouse iLike
    /// consumes the backslash as its escape char and the Windows-path filter
    /// silently matches nothing (every `\Windows\System32\`-style rule did).
    /// Verified against real data: the 4-backslash form matches 552k sysmon
    /// rows; the 2-backslash form matches 0.
    #[test]
    fn backslash_contains_quad_escapes_for_ilike() {
        let query = parse_query(r#"process_path CONTAINS "C:\Windows\System32\""#).unwrap();
        let sql = ClickHouseSqlGenerator::new()
            .generate(&query, &time_range())
            .unwrap();
        assert!(
            sql.contains(r"c:\\\\windows\\\\system32\\\\"),
            "literal backslashes must be 4x-escaped in the SQL text for iLike, got:\n{}",
            sql
        );

        // The `| where … CONTAINS` command is a SEPARATE codegen path
        // (generate_where_condition) that inlined the escaping — it must get the
        // same 4-backslash form, or the rules (which all use `| where`) match 0.
        let piped = parse_query(
            r#"source_type="windows_sysmon" | where process_path CONTAINS "C:\Windows\System32\""#,
        )
        .unwrap();
        let psql = ClickHouseSqlGenerator::new()
            .generate(&piped, &time_range())
            .unwrap();
        assert!(
            psql.contains(r"c:\\\\windows\\\\system32\\\\"),
            "| where CONTAINS must also 4x-escape backslashes, got:\n{}",
            psql
        );
    }

    /// `src_host != /ws/` should NOT iLike — same fragment concern, just negated.
    /// Pre-fix: workstations `ws-mkt-088` were correctly excluded but WSUS hosts
    /// `srv-wsus01` (tokens `[srv, wsus01, corp, local]`) leaked through because
    /// `ws` isn't a whole token there.
    #[test]
    fn negated_regex_fragment_on_udm_field_uses_not_ilike() {
        let query = parse_query("src_host != /ws/").unwrap();
        let sql = ClickHouseSqlGenerator::new()
            .generate(&query, &time_range())
            .unwrap();

        assert!(
            sql.contains("NOT iLike '%ws%'"),
            "expected NOT iLike on substring, got:\n{}",
            sql
        );
        assert!(
            !sql.contains("hasToken"),
            "must NOT lower to NOT hasTokenCaseInsensitive (leaked WSUS), got:\n{}",
            sql
        );
    }

    /// `message contains "anom"` must match "anomalous" rows.
    /// The `rules/credential_access/golden_ticket.yml` rule literally has this
    /// pattern and was silently returning 0 hits under hasToken.
    #[test]
    fn contains_fragment_on_message_uses_ilike_not_hastoken() {
        let query = parse_query("message contains \"anom\"").unwrap();
        let sql = ClickHouseSqlGenerator::new()
            .generate(&query, &time_range())
            .unwrap();

        assert!(
            sql.contains("lower(message) iLike '%anom%'"),
            "expected substring iLike on message, got:\n{}",
            sql
        );
        assert!(
            !sql.contains("hasToken"),
            "must NOT lower to hasToken (would never match `anomalous` rows), got:\n{}",
            sql
        );
    }

    /// NAN-1515: a single-token bare keyword is now a TOKEN match
    /// (`hasAllTokens`, posting-list lookup), not a substring iLike. This is the
    /// one deliberate semantic change — bare `anom` no longer matches
    /// `anomalous`; substring intent goes through `*kw*` / `CONTAINS` (still
    /// iLike). The substring form was 77–250× slower at Saturn scale.
    #[test]
    fn bare_keyword_single_token_uses_hasalltokens() {
        let query = parse_query("anom").unwrap();
        let sql = ClickHouseSqlGenerator::new()
            .generate(&query, &time_range())
            .unwrap();

        assert!(
            sql.contains("hasAllTokens(lower(message), 'anom')"),
            "single-token bare keyword should use hasAllTokens, got:\n{}",
            sql
        );
        assert!(
            !sql.contains("lower(message) iLike "),
            "single-token bare keyword must NOT emit a substring iLike, got:\n{}",
            sql
        );
        assert!(
            !sql.contains("position("),
            "single clean token must NOT grow a position guard, got:\n{}",
            sql
        );
    }

    /// NAN-1515: whole-token analyst patterns (`mimikatz`, `kerberos`) lower to
    /// a bare `hasAllTokens` — a posting-list lookup on idx_message_words, no
    /// position guard (single clean token = token match).
    #[test]
    fn bare_whole_token_keyword_uses_hasalltokens() {
        let query = parse_query("mimikatz").unwrap();
        let sql = ClickHouseSqlGenerator::new()
            .generate(&query, &time_range())
            .unwrap();

        assert!(
            sql.contains("hasAllTokens(lower(message), 'mimikatz')"),
            "whole-token keyword should lower to a bare hasAllTokens, got:\n{}",
            sql
        );
        assert!(
            !sql.contains("position(") && !sql.contains("iLike"),
            "single clean token must be bare hasAllTokens (no position, no iLike), got:\n{}",
            sql
        );
    }

    /// NAN-1515: multi-token / structured needles (`file.exe`, snake_case) lower
    /// to a bare `hasAllTokens` — token-AND via posting-list lookup, same shape as
    /// single-token. No position guard, no iLike. Replaces the NAN-1416 guard.
    #[test]
    fn bare_special_char_keyword_uses_hasalltokens() {
        let query = parse_query("svchost.exe").unwrap();
        let sql = ClickHouseSqlGenerator::new()
            .generate(&query, &time_range())
            .unwrap();

        assert!(
            sql.contains("hasAllTokens(lower(message), 'svchost.exe')"),
            "multi-token keyword should emit bare hasAllTokens, got:\n{}",
            sql
        );
        assert!(
            !sql.contains("iLike") && !sql.contains("position("),
            "multi-token keyword must NOT emit iLike or position, got:\n{}",
            sql
        );
    }

    /// NAN-1515: quoted phrase → hasAllTokens(both tokens). Token-AND, no
    /// adjacency guard — `"failed login"` matches rows with tokens `failed` AND
    /// `login` (Splunk parity).
    #[test]
    fn quoted_phrase_keyword_uses_hasalltokens() {
        let query = parse_query("\"failed login\"").unwrap();
        let sql = ClickHouseSqlGenerator::new()
            .generate(&query, &time_range())
            .unwrap();

        assert!(
            sql.contains("hasAllTokens(lower(message), 'failed login')"),
            "phrase keyword should emit bare hasAllTokens, got:\n{}",
            sql
        );
        assert!(
            !sql.contains("position(") && !sql.contains("iLike"),
            "phrase keyword must NOT emit position or iLike, got:\n{}",
            sql
        );
    }

    /// NAN-1515: every structured needle (IPs, dotted names, snake_case) takes
    /// the same bare hasAllTokens path — no per-token length heuristics, no
    /// position, no iLike. CH tokenizes the string needle itself.
    #[test]
    fn structured_keyword_uses_hasalltokens() {
        for needle in ["a.b.c", "10.0.0.52", "cmd.exe", "192.168.1.100", "event_data"] {
            let query = parse_query(&format!("\"{}\"", needle)).unwrap();
            let sql = ClickHouseSqlGenerator::new()
                .generate(&query, &time_range())
                .unwrap();

            assert!(
                sql.contains(&format!("hasAllTokens(lower(message), '{needle}')")),
                "structured needle {:?} should emit bare hasAllTokens, got:\n{}",
                needle,
                sql
            );
            assert!(
                !sql.contains("iLike") && !sql.contains("position("),
                "structured needle {:?} must NOT emit iLike or position, got:\n{}",
                needle,
                sql
            );
        }
    }

    /// NAN-1515: an explicit wildcard in a bare keyword (`cmd*`, `c?d`) is
    /// partial-match intent → iLike pattern (the escape hatch from token search),
    /// not a hasAllTokens token lookup.
    #[test]
    fn bare_keyword_wildcard_uses_ilike_not_hasalltokens() {
        for (q, want) in [
            ("cmd*", "lower(message) iLike 'cmd%'"),
            ("c?d", "lower(message) iLike 'c_d'"),
        ] {
            let sql = ClickHouseSqlGenerator::new()
                .generate(&parse_query(q).unwrap(), &time_range())
                .unwrap();
            assert!(
                sql.contains(want) && !sql.contains("hasAllTokens"),
                "wildcard keyword {q:?} should emit {want:?} (no hasAllTokens), got:\n{sql}"
            );
        }
    }

    /// NAN-1515 edge cases: LIKE metachars are literal (no escaping — hasAllTokens
    /// takes a literal string); all-symbol needles fall back to substring iLike
    /// (no index tokens); non-ASCII stays inside a CH token.
    #[test]
    fn keyword_edge_cases() {
        // Spaces are token separators; the needle is just tokenized by CH.
        let query = parse_query("\" error \"").unwrap();
        let sql = ClickHouseSqlGenerator::new()
            .generate(&query, &time_range())
            .unwrap();
        assert!(
            sql.contains("hasAllTokens(lower(message), ' error ')")
                && !sql.contains("position(")
                && !sql.contains("iLike"),
            "spaced phrase lowers to bare hasAllTokens, got:\n{}",
            sql
        );

        // LIKE metachars `%`/`_` are ordinary literals to hasAllTokens — no escaping.
        let query = parse_query("\"100%_download\"").unwrap();
        let sql = ClickHouseSqlGenerator::new()
            .generate(&query, &time_range())
            .unwrap();
        assert!(
            sql.contains("hasAllTokens(lower(message), '100%_download')"),
            "LIKE metachars must be literal in hasAllTokens, got:\n{}",
            sql
        );

        // All-separator needle with no wildcard → no index tokens → substring iLike.
        let query = parse_query("\"!!!\"").unwrap();
        let sql = ClickHouseSqlGenerator::new()
            .generate(&query, &time_range())
            .unwrap();
        assert!(
            sql.contains("lower(message) iLike '%!!!%'") && !sql.contains("hasAllTokens"),
            "all-separator needle falls back to substring iLike, got:\n{}",
            sql
        );

        // Unicode: non-ASCII stays inside a CH token, so `café` is a real token.
        let query = parse_query("\"café attachment\"").unwrap();
        let sql = ClickHouseSqlGenerator::new()
            .generate(&query, &time_range())
            .unwrap();
        assert!(
            sql.contains("hasAllTokens(lower(message), 'café attachment')")
                && !sql.contains("position(")
                && !sql.contains("iLike"),
            "unicode phrase searches café as a token via hasAllTokens, got:\n{}",
            sql
        );
    }

    /// NAN-1416: `contains` on an indexed plain-String column mirrors the
    /// keyword guard; ext/JSON targets (no index) and negations get none.
    #[test]
    fn contains_multi_token_gets_guard_only_on_plain_string_columns() {
        // message contains a phrase → guard.
        let query = parse_query("message contains \"failed login\"").unwrap();
        let sql = ClickHouseSqlGenerator::new()
            .generate(&query, &time_range())
            .unwrap();
        assert!(
            sql.contains(
                "lower(message) iLike '%failed login%' AND lower(message) iLike '%failed%'"
            ),
            "multi-token CONTAINS on message should emit the guard, got:\n{}",
            sql
        );

        // Single-token CONTAINS keeps the exact pre-NAN-1416 shape.
        let query = parse_query("message contains \"anom\"").unwrap();
        let sql = ClickHouseSqlGenerator::new()
            .generate(&query, &time_range())
            .unwrap();
        assert!(
            sql.contains("(lower(message) iLike '%anom%')")
                && !sql.contains(" AND lower(message) iLike "),
            "single-token CONTAINS must stay a single bare iLike, got:\n{}",
            sql
        );

        // Negated CONTAINS: NOT full ≢ guard ∧ NOT full — never guarded.
        let query = parse_query("message NOT contains \"failed login\"").unwrap();
        let sql = ClickHouseSqlGenerator::new()
            .generate(&query, &time_range())
            .unwrap();
        assert!(
            sql.contains("lower(message) NOT iLike '%failed login%'")
                && !sql.contains("AND lower(message) iLike '%failed%'"),
            "negated CONTAINS must NOT be guarded, got:\n{}",
            sql
        );

        // ext-JSON target (UDM field without explicit column): no index to
        // serve a guard → unguarded toString shape unchanged.
        let query = parse_query("ssl_hash contains \"failed login\"").unwrap();
        let sql = ClickHouseSqlGenerator::new()
            .generate(&query, &time_range())
            .unwrap();
        assert!(
            sql.contains("lower(toString(ext.ssl_hash)) iLike '%failed login%'")
                && !sql.contains("AND lower(message) iLike '%failed%'"),
            "ext-JSON CONTAINS must stay unguarded, got:\n{}",
            sql
        );
    }

    /// NAN-1515: the keyword codegen is profile-independent — OCSF keywords go
    /// through the same `lower(message)` arm (ocsf_logs carries the identical
    /// splitByNonAlpha index on lower(message)).
    #[test]
    fn ocsf_keyword_matches_udm_shape() {
        let gen = ClickHouseSqlGenerator::new()
            .with_profile(std::sync::Arc::new(crate::schema::OcsfProfile::new()));

        let query = parse_query("\"failed login\"").unwrap();
        let sql = gen.generate(&query, &time_range()).unwrap();
        assert!(
            sql.contains("hasAllTokens(lower(message), 'failed login')")
                && !sql.contains("position(")
                && !sql.contains("iLike"),
            "OCSF multi-token keyword should emit the same bare hasAllTokens shape, got:\n{}",
            sql
        );

        let query = parse_query("mimikatz").unwrap();
        let sql = gen.generate(&query, &time_range()).unwrap();
        assert!(
            sql.contains("hasAllTokens(lower(message), 'mimikatz')")
                && !sql.contains("position(")
                && !sql.contains("iLike"),
            "OCSF single-token keyword must be a bare hasAllTokens, got:\n{}",
            sql
        );
    }

    /// NAN-1416: regex pre-filters pick a single index-servable token — both
    /// the simple-literal lowering and the BloomGuard literal extraction.
    #[test]
    fn regex_prefilter_guard_is_single_token() {
        // Simple multi-token literal regex → full-needle iLike + guard.
        let query = parse_query("message=/failed login/").unwrap();
        let sql = ClickHouseSqlGenerator::new()
            .generate(&query, &time_range())
            .unwrap();
        assert!(
            sql.contains(
                "lower(message) iLike '%failed login%' AND lower(message) iLike '%failed%'"
            ),
            "multi-token literal regex should emit full iLike + guard, got:\n{}",
            sql
        );

        // Single-token literal regex pins the pre-NAN-1416 shape.
        let query = parse_query("message=/mimikatz/").unwrap();
        let sql = ClickHouseSqlGenerator::new()
            .generate(&query, &time_range())
            .unwrap();
        assert!(
            sql.contains("(lower(message) iLike '%mimikatz%')")
                && !sql.contains(" AND lower(message) iLike "),
            "single-token literal regex must stay a single bare iLike, got:\n{}",
            sql
        );

        // Complex regex: extract_longest_literal must tokenize its winning
        // literal (`svchost.exe `) down to `svchost`, not emit the
        // index-useless multi-token guard `'%svchost.exe %'`.
        let query = parse_query("message=/svchost\\.exe (started|stopped)/").unwrap();
        let sql = ClickHouseSqlGenerator::new()
            .generate(&query, &time_range())
            .unwrap();
        assert!(
            sql.contains("lower(message) iLike '%svchost%' AND match(message,"),
            "complex regex pre-filter should guard on the longest single token, got:\n{}",
            sql
        );
        assert!(
            !sql.contains("iLike '%svchost.exe %'"),
            "must NOT emit the multi-token (index-useless) literal guard, got:\n{}",
            sql
        );
    }

    /// NAN-1395: the field-stats companion gate. Wide (filter-only / row-shape
    /// preserving) pipelines keep the companion; transformative pipelines whose
    /// output projection replaces the base columns — `Columns(...)` from
    /// stats/chart/table/fields, or `Unknown` from funnel/sequence/transaction
    /// and any unmodeled command — must report non-wide so the companion is
    /// skipped instead of firing a guaranteed-Code-47 query.
    #[test]
    fn pipeline_output_is_wide_gates_field_stats_companion() {
        let generator = ClickHouseSqlGenerator::new();
        let wide = [
            "error",
            "status=500 | head 5",
            "* | where status=500 | sort -timestamp",
            "* | eval hash = md5(message) | head 10",
            "* | dedup src_ip | eval x = 1 | rename x as y",
        ];
        for q in wide {
            let query = parse_query(q).unwrap();
            assert!(
                generator.pipeline_output_is_wide(&query),
                "expected wide output (companion runs) for: {q}"
            );
        }

        let non_wide = [
            // Columns(...) — explicit reprojection.
            "* | stats count by src_ip",
            "* | chart count() by src_ip",
            "* | head 10 | table timestamp, src_ip, user",
            "* | fields src_ip, user",
            // Unknown — transformative commands not statically modeled.
            "* | transaction user",
            "* | sequence by src_ip maxspan=300s [status=403] [status=200]",
            // Columns appears mid-pipeline: downstream filters keep the
            // transformed (non-base) projection.
            "* | stats count by src_ip | where count > 10",
        ];
        for q in non_wide {
            let query = parse_query(q).unwrap();
            assert!(
                !generator.pipeline_output_is_wide(&query),
                "expected non-wide output (companion skipped) for: {q}"
            );
        }
    }

    /// NAN-1415: `logs.rule_id` is a plain String, but UUID_FIELDS routed it
    /// through `toString(rule_id) = '<lowered literal>'` — a case-SENSITIVE
    /// compare against a lowered literal, so uppercase-stored vendor rule ids
    /// never matched (empirically: the same form against an uppercase-stored
    /// hash matches 0 rows; the lower() form matches). It must emit
    /// `lower(rule_id) = …`, the exact expression the migration-132
    /// `idx_rule_id_lower` bloom is built on.
    #[test]
    fn rule_id_eq_emits_lower_not_tostring() {
        let query = parse_query("rule_id=\"AB-1234-Suspicious\"").unwrap();
        let sql = ClickHouseSqlGenerator::new()
            .generate(&query, &time_range())
            .unwrap();

        assert!(
            sql.contains("lower(rule_id) = 'ab-1234-suspicious'"),
            "rule_id equality must emit lower(rule_id) = '<lowered>', got:\n{sql}"
        );
        assert!(
            !sql.contains("toString(rule_id)"),
            "rule_id must not be toString-wrapped (case-sensitive vs lowered literal + orphans the lower-expression bloom), got:\n{sql}"
        );
    }

    /// `id` stays on the UUID arm: it is a genuine CH UUID column where
    /// lower() is a type error and toString() renders lowercase already.
    #[test]
    fn id_eq_keeps_tostring_uuid_arm() {
        let query = parse_query("id=\"018F3A2B-0000-7000-8000-000000000000\"").unwrap();
        let sql = ClickHouseSqlGenerator::new()
            .generate(&query, &time_range())
            .unwrap();

        assert!(
            sql.contains("toString(id) = '018f3a2b-0000-7000-8000-000000000000'"),
            "id (real UUID column) must keep the toString compare, got:\n{sql}"
        );
    }

    // NAN-1464: equality on an Array(String) column must compile to has()
    // (membership), never scalar `col = 'v'` (a CH type error that silently
    // matches nothing).
    #[test]
    fn tags_eq_emits_has_membership() {
        let query = parse_query("tags=\"web\"").unwrap();
        let sql = ClickHouseSqlGenerator::new()
            .generate(&query, &time_range())
            .unwrap();
        assert!(
            sql.contains("has(tags, 'web')"),
            "tags equality must emit has(tags, '<lowered>'), got:\n{sql}"
        );
        assert!(!sql.contains("tags = "), "must not scalar-compare an array, got:\n{sql}");
    }

    #[test]
    fn tags_ne_emits_not_has() {
        let query = parse_query("tags!=\"web\"").unwrap();
        let sql = ClickHouseSqlGenerator::new()
            .generate(&query, &time_range())
            .unwrap();
        assert!(
            sql.contains("NOT has(tags, 'web')"),
            "tags inequality must emit NOT has(...), got:\n{sql}"
        );
    }

    #[test]
    fn tags_wildcard_emits_array_exists() {
        let query = parse_query("tags=\"web*\"").unwrap();
        let sql = ClickHouseSqlGenerator::new()
            .generate(&query, &time_range())
            .unwrap();
        assert!(
            sql.contains("arrayExists(x -> lower(x) iLike 'web%', tags)"),
            "tags wildcard must emit arrayExists over the elements, got:\n{sql}"
        );
    }

    // The pre-existing `*_tags` enrichment columns were subject to the same bug;
    // they now route through the same has() path.
    #[test]
    fn ioc_tags_eq_emits_has_membership() {
        let query = parse_query("ioc_tags=\"phishing\"").unwrap();
        let sql = ClickHouseSqlGenerator::new()
            .generate(&query, &time_range())
            .unwrap();
        assert!(
            sql.contains("has(ioc_tags, 'phishing')"),
            "ioc_tags equality must emit has(), got:\n{sql}"
        );
    }

    /// NAN-1415: src_user is downcased at ingest (Vector clickhouse_mapping),
    /// so equality compares RAW and the whole-value `idx_src_user` bloom
    /// engages. dest_user is NOT ingest-normalized (mixed-case history) and
    /// must keep the lower() form — a raw compare would silently drop
    /// uppercase-stored matches.
    #[test]
    fn src_user_eq_compares_raw_dest_user_keeps_lower() {
        let query = parse_query("src_user=\"CORP-Admin\"").unwrap();
        let sql = ClickHouseSqlGenerator::new()
            .generate(&query, &time_range())
            .unwrap();
        assert!(
            sql.contains("src_user = 'corp-admin'"),
            "src_user is ingest-lowercased; equality must compare raw for bloom pruning, got:\n{sql}"
        );
        assert!(
            !sql.contains("lower(src_user)"),
            "src_user must not be lower-wrapped on equality, got:\n{sql}"
        );

        let query = parse_query("dest_user=\"CORP-Admin\"").unwrap();
        let sql = ClickHouseSqlGenerator::new()
            .generate(&query, &time_range())
            .unwrap();
        assert!(
            sql.contains("lower(dest_user) = 'corp-admin'"),
            "dest_user has mixed-case history and must keep the lower() compare, got:\n{sql}"
        );
    }

    /// NAN-1415: the IOC-hunt equality fields must emit exactly `lower(col) =`
    /// — the expression the migration-132 `idx_<col>_lower` blooms are built
    /// on (ClickHouse matches skip indexes by expression). These columns have
    /// mixed-case history, so they must NOT join LOWERCASE_NORMALIZED_FIELDS
    /// even though ingest now canonicalizes hashes.
    #[test]
    fn ioc_equality_fields_emit_lower_form_matching_expression_blooms() {
        let cases = [
            ("process_hash", "7E48FDDCA1227FC511CEFA2EE473DC9C"),
            ("file_hash", "DEADBEEF"),
            ("process_guid", "40D3C75628DAEBB6"),
            ("user_id", "S-1-5-21-1888852550-2391102044-1519127082-9493"),
            ("url_domain", "DL-srv01"),
            ("file_name", "Tmp31a5fdf6.TMP"),
            ("signature_id", "4688"),
        ];
        for (field, value) in cases {
            let query = parse_query(&format!("{field}=\"{value}\"")).unwrap();
            let sql = ClickHouseSqlGenerator::new()
                .generate(&query, &time_range())
                .unwrap();
            let expected = format!("lower({field}) = '{}'", value.to_lowercase());
            assert!(
                sql.contains(&expected),
                "{field} equality must emit `{expected}` (the indexed expression), got:\n{sql}"
            );
        }
    }

    // ── NAN-1580: IOC observable-anywhere term expansion ──────────────────

    /// `ioc=<v>` emits ONE index-friendly predicate per observable column using
    /// an IN-list of the (lowercased) values: RAW (`col IN ('<lowered>')`) for
    /// the ingest-lowercased columns, `lower(col) IN (…)` for the mixed-case ones.
    /// IN on an indexed column prunes like equality but collapses the clause count
    /// from values×columns to columns (NAN-1580 P1-f).
    #[test]
    fn ioc_term_expands_across_observable_columns_index_friendly() {
        let query = parse_query("ioc=\"1.2.3.4\"").unwrap();
        let sql = ClickHouseSqlGenerator::new()
            .generate(&query, &time_range())
            .unwrap();

        // Single WHERE, full partition-pruning time bound, NO explicit PREWHERE.
        assert!(
            sql.contains("WHERE timestamp BETWEEN") && !sql.contains("PREWHERE"),
            "ioc term must emit a single WHERE with no PREWHERE, got:\n{sql}"
        );

        // RAW-compared ingest-lowercased observable columns (bloom prunes).
        for raw in [
            "src_ip IN ('1.2.3.4')",
            "dest_ip IN ('1.2.3.4')",
            "dvc_ip IN ('1.2.3.4')",
        ] {
            assert!(sql.contains(raw), "missing raw observable leg `{raw}`, got:\n{sql}");
        }

        // lower(col) IN-list form for mixed-case-history observable columns.
        for lowered in [
            "lower(file_hash) IN ('1.2.3.4')",
            "lower(url_domain) IN ('1.2.3.4')",
            "lower(query) IN ('1.2.3.4')",
            "lower(user_id) IN ('1.2.3.4')",
            "lower(sender) IN ('1.2.3.4')",
            "lower(cve) IN ('1.2.3.4')",
            "lower(signature_id) IN ('1.2.3.4')",
        ] {
            assert!(
                sql.contains(lowered),
                "missing lowered observable leg `{lowered}`, got:\n{sql}"
            );
        }

        // The per-observable legs are OR'd (single disjunctive matchset).
        assert!(sql.contains(" OR "), "observable legs must be OR'd, got:\n{sql}");
    }

    /// NAN-1580 (OCSF-aware): under an `OcsfProfile`-configured generator the
    /// `ioc` term must resolve the LOGICAL observable names to the promoted OCSF
    /// physical columns (dotted → backtick-quoted), never the raw UDM column
    /// names — those don't exist on `ocsf_logs`, so emitting them would 500.
    /// Observables OCSF has no column for (`dvc_ip`, …) are silently skipped.
    #[test]
    fn ioc_term_resolves_ocsf_columns_under_ocsf_profile() {
        use crate::schema::OcsfProfile;
        use std::sync::Arc;
        let query = parse_query("ioc=\"1.2.3.4\"").unwrap();
        let sql = ClickHouseSqlGenerator::new()
            .with_profile(Arc::new(OcsfProfile::new()))
            .generate(&query, &time_range())
            .unwrap();

        assert!(
            sql.contains("WHERE timestamp BETWEEN") && !sql.contains("PREWHERE"),
            "single WHERE, no PREWHERE, got:\n{sql}"
        );
        // RAW ingest-lowercased OCSF ip columns as IN-lists (escape_identifier
        // double-quotes dotted names).
        assert!(
            sql.contains("\"src_endpoint.ip\" IN ('1.2.3.4')"),
            "src_ip must resolve to src_endpoint.ip, got:\n{sql}"
        );
        assert!(
            sql.contains("\"dst_endpoint.ip\" IN ('1.2.3.4')"),
            "dest_ip must resolve to dst_endpoint.ip, got:\n{sql}"
        );
        // lower() OCSF hash column as an IN-list.
        assert!(
            sql.contains("lower(\"file.hashes.sha256\") IN ('1.2.3.4')"),
            "file_hash must resolve to file.hashes.sha256, got:\n{sql}"
        );
        // No bare UDM observable column leaks through.
        assert!(!sql.contains("src_ip IN ('1.2.3.4')"), "raw UDM src_ip leaked, got:\n{sql}");
        assert!(!sql.contains("lower(file_hash)"), "raw UDM file_hash leaked, got:\n{sql}");
        // dvc_ip has no OCSF mapping → skipped.
        assert!(!sql.contains("dvc_ip"), "dvc_ip should be skipped under OCSF, got:\n{sql}");
    }

    /// `ioc in [a, b]` emits ONE IN-list per observable column carrying every
    /// value (not value×column equalities).
    #[test]
    fn ioc_in_list_expands_each_value() {
        let query = parse_query("ioc in [\"evil.com\", \"bad.net\"]").unwrap();
        let sql = ClickHouseSqlGenerator::new()
            .generate(&query, &time_range())
            .unwrap();
        // Both values in a single IN-list on each observable column.
        assert!(
            sql.contains("lower(url_domain) IN ('evil.com', 'bad.net')"),
            "values must collapse into one IN-list per observable, got:\n{sql}"
        );
        assert!(
            sql.contains("src_ip IN ('evil.com', 'bad.net')"),
            "values must collapse into one IN-list per observable, got:\n{sql}"
        );
    }

    /// `ioc in feed("arg")` resolves the indicator set via a
    /// `custom_enrichment_results` IN-subquery (live IOC rows only).
    #[test]
    fn ioc_feed_term_emits_enrichment_subquery() {
        let query = parse_query("ioc in threatfox(\"apt29\")").unwrap();
        let sql = ClickHouseSqlGenerator::new()
            .generate(&query, &time_range())
            .unwrap();
        assert!(
            sql.contains("custom_enrichment_results")
                && sql.contains("is_ioc = 1")
                && sql.contains("expires_at > now()"),
            "feed term must pull live IOCs from custom_enrichment_results, got:\n{sql}"
        );
        assert!(
            sql.contains("has(tags, 'apt29')") || sql.contains("LIKE '%apt29%'"),
            "feed arg must filter by tag or name, got:\n{sql}"
        );
        // Subquery wired into the observable columns via IN (…).
        assert!(
            sql.contains("src_ip IN (") && sql.contains("lower(file_hash) IN ("),
            "feed indicators must match each observable column via IN, got:\n{sql}"
        );
    }
}



