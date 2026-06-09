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
mod field_analysis;
mod helpers;
mod identity;
mod search_expr;

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
];

/// HashSet for O(1) explicit column lookups (initialized lazily)
static EXPLICIT_COLUMNS_SET: Lazy<HashSet<&'static str>> =
    Lazy::new(|| EXPLICIT_COLUMNS.iter().copied().collect());

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
        SearchExpr::Keyword(_)
        | SearchExpr::FunctionFilter { .. }
        | SearchExpr::BooleanFunction(_)
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
#[derive(Debug, Clone, Default)]
pub struct QueryOptions {
    /// Enable query cache for shared searches with fixed time ranges
    /// Adds SETTINGS use_query_cache=1, query_cache_ttl=300
    pub use_cache: bool,
    /// Table view mode - only return minimal columns (id, timestamp, source_type, message + query fields)
    /// Full row data is fetched on demand when user expands a row
    pub table_view: bool,
    /// Maximum results to return (overrides DEFAULT_RESULT_LIMIT)
    pub limit: Option<usize>,
}

/// Fields that benefit from being in PREWHERE (primary key or have set/bloom indexes)
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
/// via toString() cast. UUIDs are case-insensitive by spec so no lower() needed.
/// Add any new UUID-typed columns here.
///
/// `pub(crate)` for `UdmProfile` parity (NAN-1244).
pub(crate) const UUID_FIELDS: &[&str] = &["id", "rule_id"];

/// Extract PREWHERE-eligible equality conditions from a SearchExpr.
/// Returns SQL conditions that can be added to PREWHERE for better index usage.
/// These conditions will also remain in WHERE (duplicate is fine, ClickHouse optimizes).
pub(super) fn extract_prewhere_conditions(expr: &SearchExpr, profile: &dyn SchemaProfile) -> Vec<String> {
    let mut prewhere = Vec::new();

    // Recursively collect equality conditions on PREWHERE-eligible *physical
    // columns*, resolved through the active `SchemaProfile`. Resolving here
    // (instead of emitting the raw UDM token) is what keeps PREWHERE in step with
    // the profile-resolved WHERE clause: under OCSF a UDM alias like `src_ip` must
    // become the promoted column `"src_endpoint.ip"`, never the literal `src_ip`
    // (which is not a column → Code 47 / silent 0-rows, NAN-1299). Fields that do
    // not resolve to a single physical column (JSON tail, class-split expression,
    // unknown) are left to WHERE and never promoted to PREWHERE. For UDM the
    // resolution is the identity column, so output is byte-for-byte unchanged.
    fn collect_prewhere(
        expr: &SearchExpr,
        profile: &dyn SchemaProfile,
        conditions: &mut Vec<String>,
    ) {
        match expr {
            SearchExpr::And(left, right) => {
                collect_prewhere(left, profile, conditions);
                collect_prewhere(right, profile, conditions);
            }
            SearchExpr::FieldFilter {
                field,
                op: Comparator::Eq,
                value,
            } => {
                let normalized = normalize_field_name(field);
                // NAN-1321: a class-split concept (OCSF host/user/process/url) matches
                // a value-pick `if(primary != '', primary, fallback)` in WHERE. Its
                // `resolve()` returns only the PRIMARY column, so promoting THAT to
                // PREWHERE would pre-filter to `primary = x` and drop every fallback
                // row (the device.hostname endpoint events) before WHERE ever runs —
                // a silent under-match. The `if(...)` is not a clean indexed equality,
                // so leave class-split fields entirely to WHERE. UDM never class-splits
                // → no-op, PREWHERE byte-identical.
                if profile.class_split_value_sql(normalized).is_some() {
                    return;
                }
                // Resolve to a real physical column (follow same-schema aliases).
                // Anything else (JsonPath / ArrayElement / Unknown) is not
                // PREWHERE-safe — leave it to the profile-resolved WHERE clause.
                let col = match profile.resolve(normalized) {
                    FieldResolution::ExplicitColumn(c) | FieldResolution::Alias(c) => c,
                    _ => return,
                };
                // Only promote columns the active profile marks PREWHERE-worthy.
                if !profile.prewhere_fields().contains(&col.as_str()) {
                    return;
                }
                // Dotted OCSF columns are double-quoted; simple UDM names stay bare.
                let col_sql = escape_identifier(&col);
                let is_lowered = profile.is_lowercased_at_ingest(&col);
                let condition = match value {
                    Value::String(s) => {
                        // Skip wildcards in PREWHERE — the WHERE clause handles them
                        // correctly (pure "*" → 1, patterns → iLike). Adding a literal
                        // '*' to PREWHERE would match nothing and break the query.
                        if s.contains('*') || s.contains('?') {
                            return;
                        }
                        let escaped = escape_string(&s.to_lowercase());
                        // Hostname expansion: for src_host/dest_host without dots,
                        // match both exact and FQDN variants in PREWHERE too.
                        let is_hostname_field =
                            normalized == "src_host" || normalized == "dest_host";
                        if is_hostname_field && !s.contains('.') {
                            if is_lowered {
                                // Direct comparison — uses bloom/set indexes
                                format!(
                                    "({col_sql} = '{escaped}' OR startsWith({col_sql}, '{escaped}.'))"
                                )
                            } else {
                                format!(
                                    "(lower({col_sql}) = '{escaped}' OR startsWith(lower({col_sql}), '{escaped}.'))"
                                )
                            }
                        } else if is_lowered {
                            format!("{col_sql} = '{escaped}'")
                        } else {
                            format!("lower({col_sql}) = '{escaped}'")
                        }
                    }
                    Value::Number(n) => format!("{col_sql} = {n}"),
                    _ => return, // Skip complex values
                };
                conditions.push(condition);
            }
            // For OR and NOT, don't extract (too complex for PREWHERE optimization)
            _ => {}
        }
    }

    collect_prewhere(expr, profile, &mut prewhere);
    prewhere
}

/// Check if a SearchExpr has PREWHERE-eligible conditions on selective fields
/// (anything beyond source_type/sourcetype). When true, `optimize_read_in_order`
/// should be disabled to allow parallel granule scanning — sequential scanning
/// through mostly-empty granules is much slower for sparse matches.
pub(super) fn has_selective_prewhere(expr: &SearchExpr, profile: &dyn SchemaProfile) -> bool {
    // Mirrors `extract_prewhere_conditions`' eligibility through the active
    // profile so PREWHERE selectivity is judged on the resolved physical column,
    // not the raw UDM token (NAN-1299). UDM resolves to the identity column, so
    // behavior is unchanged there.
    fn check(expr: &SearchExpr, profile: &dyn SchemaProfile) -> bool {
        match expr {
            SearchExpr::And(left, right) => check(left, profile) || check(right, profile),
            SearchExpr::FieldFilter {
                field,
                op: Comparator::Eq,
                value,
            } => {
                let normalized = normalize_field_name(field);
                // NAN-1321: class-split fields are not promoted to PREWHERE (see
                // `extract_prewhere_conditions`), so they cannot make PREWHERE
                // selective — keep this in lockstep or `optimize_read_in_order` is
                // toggled off for a PREWHERE condition that was never emitted.
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
                    // Skip wildcards — those aren't added to PREWHERE anyway
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
    /// Active schema profile (OCSF Phase 2). Defaults to [`UdmProfile`] so the
    /// ~79 `::new()` / `::with_table()` construction sites keep today's exact
    /// behavior; OCSF deployments inject an `OcsfProfile` via [`with_profile`].
    ///
    /// [`with_profile`]: ClickHouseSqlGenerator::with_profile
    profile: Arc<dyn SchemaProfile>,
}

impl Clone for ClickHouseSqlGenerator {
    fn clone(&self) -> Self {
        Self {
            table_name: self.table_name.clone(),
            max_group_array_size: self.max_group_array_size,
            max_mvexpand_rows: self.max_mvexpand_rows,
            generation_time_range: RwLock::new(None),
            computed_fields: RwLock::new(HashSet::new()),
            profile: Arc::clone(&self.profile),
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
            max_group_array_size: DEFAULT_MAX_GROUP_ARRAY_SIZE,
            max_mvexpand_rows: DEFAULT_MAX_MVEXPAND_ROWS,
            generation_time_range: RwLock::new(None),
            computed_fields: RwLock::new(HashSet::new()),
            profile: Arc::new(UdmProfile::new()),
        }
    }

    /// Create a new ClickHouse SQL generator with a custom table name
    /// (UDM schema profile).
    pub fn with_table(table_name: impl Into<String>) -> Self {
        Self {
            table_name: table_name.into(),
            max_group_array_size: DEFAULT_MAX_GROUP_ARRAY_SIZE,
            max_mvexpand_rows: DEFAULT_MAX_MVEXPAND_ROWS,
            generation_time_range: RwLock::new(None),
            computed_fields: RwLock::new(HashSet::new()),
            profile: Arc::new(UdmProfile::new()),
        }
    }

    /// Inject an explicit schema profile (OCSF Phase 2). Builder-style so it
    /// composes with the existing `with_*` setters. UDM call sites that never
    /// call this keep the default [`UdmProfile`], so behavior is unchanged.
    pub fn with_profile(mut self, profile: Arc<dyn SchemaProfile>) -> Self {
        self.profile = profile;
        self
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
        matches!(self.profile.resolve(field), FieldResolution::ExplicitColumn(_))
    }

    /// Whether `field` resolves to a JSON-tail path under the active profile
    /// (`&self` wrapper over `profile.resolve()`). **Always false for UDM** —
    /// `UdmProfile::resolve` only ever returns `ExplicitColumn`/`Unknown`, never
    /// `JsonPath` — so callers that branch on it stay UDM-byte-identical. True
    /// only for OCSF unpromoted/unmapped names, which must be JSONExtracted from
    /// `event` rather than referenced as a (nonexistent) bare column that 500s.
    /// (NAN-1248)
    pub(crate) fn resolves_to_json_path(&self, field: &str) -> bool {
        matches!(self.profile.resolve(field), FieldResolution::JsonPath { .. })
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
    /// - [`JsonPath`] → an N-level `JSONExtract<T>(col, 'p1', 'p2', …)` against the
    ///   JSON-typed column (OCSF's `event` tail). `json_type` is chosen by the
    ///   caller from the comparison/value (`String`/`Float64`/`Bool`).
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
        match self.profile.resolve(field) {
            FieldResolution::ExplicitColumn(col) => escape_identifier(&col),
            FieldResolution::JsonPath { col, path } => {
                let path_args: Vec<String> = path
                    .iter()
                    .map(|p| format!("'{}'", escape_string(p)))
                    .collect();
                format!("JSONExtract{}({}, {})", json_type, col, path_args.join(", "))
            }
            // UDM Unknown (and OCSF array/alias variants the field tokenizer does
            // not surface here): preserve UDM's `ext.{field}` spill access exactly.
            FieldResolution::ArrayElement { .. }
            | FieldResolution::Alias(_)
            | FieldResolution::Unknown => format!("ext.{}", sanitize_json_path(field)),
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
    /// the bare column, byte-identical. PREWHERE deliberately does NOT use this (it
    /// skips class-split fields entirely — see `extract_prewhere_conditions`), so it
    /// never pre-filters to the primary column and drops the fallback's rows.
    ///
    /// [`field_access_expr`]: ClickHouseSqlGenerator::field_access_expr
    pub(crate) fn filter_field_expr(&self, field: &str, json_type: &str) -> String {
        self.profile
            .class_split_value_sql(field)
            .unwrap_or_else(|| self.field_access_expr(field, json_type))
    }

    /// Whether `field` is produced by an earlier pipeline command (eval, stats
    /// alias, risk, …) and is therefore a real column in the current scope —
    /// rather than a value to extract from the `metadata`/`ext` JSON. Populated
    /// for the duration of [`generate_with_options`]. (NAN-1236)
    pub(crate) fn is_computed_field(&self, field: &str) -> bool {
        match self.computed_fields.read() {
            Ok(guard) => guard.contains(field),
            Err(poisoned) => poisoned.get_ref().contains(field),
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
        match self.computed_fields.write() {
            Ok(mut guard) => *guard = computed,
            Err(poisoned) => *poisoned.into_inner() = computed,
        }

        let mut ctx = GeneratorContext::new(&self.table_name, time_range);
        ctx.use_cache = options.use_cache;
        if let Some(limit) = options.limit {
            ctx.limit = limit;
        }

        // Analyze query to determine required fields for optimization
        // In table_view mode, always use minimal fields for fast initial load
        ctx.required_fields =
            field_analysis::analyze_required_fields(query, options.table_view, self.profile.as_ref());

        // Identify ext JSON fields referenced by the query so they can be
        // materialized in stage_0 SELECT, making them visible to downstream CTEs
        ctx.ext_fields = field_analysis::analyze_ext_fields(query, self.profile.as_ref());

        let result = self.generate_query(query, &mut ctx);
        match self.generation_time_range.write() {
            Ok(mut guard) => *guard = None,
            Err(poisoned) => *poisoned.into_inner() = None,
        }
        match self.computed_fields.write() {
            Ok(mut guard) => guard.clear(),
            Err(poisoned) => poisoned.into_inner().clear(),
        }
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

        // Extract equality conditions on indexed fields for PREWHERE optimization
        let prewhere_conditions = extract_prewhere_conditions(expr, self.profile.as_ref());
        let extra_prewhere = if prewhere_conditions.is_empty() {
            String::new()
        } else {
            format!(" AND {}", prewhere_conditions.join(" AND "))
        };
        let selective = has_selective_prewhere(expr, self.profile.as_ref());

        // Single query with ORDER BY and LIMIT together - much faster than CTE approach
        Ok(format!(
            "SELECT {} FROM {} PREWHERE timestamp BETWEEN '{}' AND '{}'{} WHERE ({}) ORDER BY timestamp DESC LIMIT {} {}",
            select_clause,
            ctx.table_name,
            ctx.time_range.start.format("%Y-%m-%d %H:%M:%S%.6f"),
            ctx.time_range.end.format("%Y-%m-%d %H:%M:%S%.6f"),
            extra_prewhere,
            where_clause,
            limit,
            generate_settings(ctx.use_cache, selective, false)
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
    /// Uses PREWHERE for time filter and indexed field equality checks to reduce I/O
    fn generate_single_stage(
        &self,
        stage: &QueryStage,
        ctx: &mut GeneratorContext,
    ) -> Result<String, SqlGenError> {
        match stage {
            QueryStage::Search(expr) => {
                let where_clause = self.generate_search_expr(expr)?;
                let select_clause = self.build_select_clause(&ctx.required_fields, &ctx.ext_fields);

                // Extract equality conditions on indexed fields for PREWHERE optimization
                let prewhere_conditions = extract_prewhere_conditions(expr, self.profile.as_ref());
                let extra_prewhere = if prewhere_conditions.is_empty() {
                    String::new()
                } else {
                    format!(" AND {}", prewhere_conditions.join(" AND "))
                };
                let selective = has_selective_prewhere(expr, self.profile.as_ref());

                // Use PREWHERE for time filter + indexed field equality checks
                // Apply limit to prevent unbounded queries
                Ok(format!(
                    "SELECT {} FROM {} PREWHERE timestamp BETWEEN '{}' AND '{}'{} WHERE ({}) ORDER BY timestamp DESC LIMIT {} {}",
                    select_clause,
                    ctx.table_name,
                    ctx.time_range.start.format("%Y-%m-%d %H:%M:%S%.6f"),
                    ctx.time_range.end.format("%Y-%m-%d %H:%M:%S%.6f"),
                    extra_prewhere,
                    where_clause,
                    ctx.limit,
                    generate_settings(ctx.use_cache, selective, false)
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
                    if !self.profile.materialized_columns().contains(&f.as_str()) {
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

                    // Extract equality conditions on indexed fields for PREWHERE optimization
                    let prewhere_conditions = extract_prewhere_conditions(expr, self.profile.as_ref());
                    let extra_prewhere = if prewhere_conditions.is_empty() {
                        String::new()
                    } else {
                        format!(" AND {}", prewhere_conditions.join(" AND "))
                    };

                    // Use PREWHERE for time filter + indexed field equality checks
                    // For asset/tree commands, inject LIMIT into the base CTE to avoid
                    // unbounded scans — these commands re-query ClickHouse for actual data.
                    let limit_clause = if has_requery_command {
                        format!("\n  ORDER BY timestamp DESC\n  LIMIT {}", ctx.limit)
                    } else {
                        String::new()
                    };
                    format!(
                        "{} AS (\n  SELECT {} FROM {}\n  PREWHERE timestamp BETWEEN '{}' AND '{}'{}\n  WHERE ({}){}\n)",
                        cte_name,
                        select_clause,
                        ctx.table_name,
                        ctx.time_range.start.format("%Y-%m-%d %H:%M:%S%.6f"),
                        ctx.time_range.end.format("%Y-%m-%d %H:%M:%S%.6f"),
                        extra_prewhere,
                        where_clause,
                        limit_clause
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
                    self.generate_command_cte(&cte_name, &prev_cte, cmd, ctx)?
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
        let settings = generate_settings(ctx.use_cache, false, has_non_timechart_aggregation);

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
            write!(
                sql,
                "\nSELECT {} FROM {} ORDER BY timestamp DESC {}",
                select_list, last_cte, settings
            )
            .unwrap();
        }

        Ok(sql)
    }

    /// Generate a CTE for a command stage
    fn generate_command_cte(
        &self,
        cte_name: &str,
        source_cte: &str,
        cmd: &Command,
        ctx: &mut GeneratorContext,
    ) -> Result<String, SqlGenError> {
        // Handle join specially since it needs to generate subsearch SQL
        if let Command::Join {
            join_type,
            fields,
            subsearch,
            max,
            overwrite: _,
            maxout,
        } = cmd
        {
            let limit = resolve_subsearch_limit(*maxout);
            let inner_sql =
                self.generate_join_sql(source_cte, join_type, fields, subsearch, *max, limit, ctx)?;
            return Ok(format!("{} AS (\n{}\n)", cte_name, inner_sql));
        }

        // Handle append specially - UNION ALL with subsearch
        if let Command::Append { subsearch, maxout } = cmd {
            let limit = resolve_subsearch_limit(*maxout);
            let inner_sql = self.generate_append_sql(source_cte, subsearch, limit, ctx)?;
            return Ok(format!("{} AS (\n{}\n)", cte_name, inner_sql));
        }

        let inner_sql = self.generate_command_sql_with_ctx(source_cte, cmd, ctx)?;
        Ok(format!("{} AS (\n{}\n)", cte_name, inner_sql))
    }

    /// Generate SQL for an APPEND command (UNION ALL)
    fn generate_append_sql(
        &self,
        source_cte: &str,
        subsearch: &Query,
        limit: usize,
        ctx: &GeneratorContext,
    ) -> Result<String, SqlGenError> {
        // Generate the subsearch SQL
        let subsearch_sql = self.generate_subsearch_sql(subsearch, ctx, limit)?;

        // UNION ALL combines results from main query and subsearch
        Ok(format!(
            "  SELECT * FROM {}\n  UNION ALL\n{}",
            source_cte, subsearch_sql
        ))
    }

    /// Generate SQL for a JOIN command
    fn generate_join_sql(
        &self,
        source_cte: &str,
        join_type: &JoinType,
        fields: &[String],
        subsearch: &Query,
        max: usize,
        limit: usize,
        ctx: &GeneratorContext,
    ) -> Result<String, SqlGenError> {
        // Generate the subsearch SQL
        let subsearch_sql = self.generate_subsearch_sql(subsearch, ctx, limit)?;

        // Build the JOIN condition with normalized field names
        let join_conditions: Vec<String> = fields
            .iter()
            .map(|f| {
                let normalized = escape_identifier(normalize_field_name(f));
                format!("main.{} = sub.{}", normalized, normalized)
            })
            .collect();
        let join_condition = join_conditions.join(" AND ");

        // Map join type to SQL keyword
        let join_keyword = match join_type {
            JoinType::Inner => "INNER JOIN",
            JoinType::Left => "LEFT JOIN",
            JoinType::Outer => "FULL OUTER JOIN",
        };

        // For max > 1, use ROW_NUMBER to limit matches per key
        if max > 1 {
            let partition_fields: Vec<String> = fields
                .iter()
                .map(|f| escape_identifier(normalize_field_name(f)))
                .collect();
            Ok(format!(
                "  SELECT * FROM {} AS main\n  {} (\n    SELECT *, ROW_NUMBER() OVER (PARTITION BY {} ORDER BY timestamp) AS _join_rn\n    FROM ({})\n  ) AS sub ON {} AND sub._join_rn <= {}",
                source_cte,
                join_keyword,
                partition_fields.join(", "),
                subsearch_sql,
                join_condition,
                max
            ))
        } else {
            // Standard join with max=1 (default behavior)
            Ok(format!(
                "  SELECT * FROM {} AS main\n  {} (\n{}\n  ) AS sub ON {}",
                source_cte, join_keyword, subsearch_sql, join_condition
            ))
        }
    }

    /// Generate SQL for a subsearch (used by join/append)
    /// Applies the given limit to prevent memory exhaustion
    fn generate_subsearch_sql(
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

        // For single-stage subsearch (just a search), generate inline with LIMIT
        if stages.len() == 1 {
            if let QueryStage::Search(expr) = &stages[0] {
                let where_clause = self.generate_search_expr(expr)?;
                let prewhere_conditions = extract_prewhere_conditions(expr, self.profile.as_ref());
                let extra_prewhere = if prewhere_conditions.is_empty() {
                    String::new()
                } else {
                    format!(" AND {}", prewhere_conditions.join(" AND "))
                };
                // Use PREWHERE for time filter + indexed field equality checks
                return Ok(format!(
                    "    SELECT * FROM {}\n    PREWHERE timestamp BETWEEN '{}' AND '{}'{}\n    WHERE ({})\n    LIMIT {}",
                    ctx.table_name,
                    ctx.time_range.start.format("%Y-%m-%d %H:%M:%S%.6f"),
                    ctx.time_range.end.format("%Y-%m-%d %H:%M:%S%.6f"),
                    extra_prewhere,
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
                    let prewhere_conditions = extract_prewhere_conditions(expr, self.profile.as_ref());
                    let extra_prewhere = if prewhere_conditions.is_empty() {
                        String::new()
                    } else {
                        format!(" AND {}", prewhere_conditions.join(" AND "))
                    };
                    // Use PREWHERE for time filter + indexed field equality checks
                    current_sql = format!(
                        "SELECT * FROM {} PREWHERE timestamp BETWEEN '{}' AND '{}'{} WHERE ({})",
                        ctx.table_name,
                        ctx.time_range.start.format("%Y-%m-%d %H:%M:%S%.6f"),
                        ctx.time_range.end.format("%Y-%m-%d %H:%M:%S%.6f"),
                        extra_prewhere,
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
                        let extra_cols = format!(
                            ", {}, {}",
                            escape_identifier(parent_field),
                            escape_identifier(child_field)
                        );
                        if !current_sql.contains(&escape_identifier(parent_field)) {
                            current_sql = current_sql.replacen(
                                "SELECT *",
                                &format!("SELECT *{}", extra_cols),
                                1,
                            );
                        }
                    }
                    // Use previous result as source, wrapped in parentheses with alias
                    let source = format!("({}) AS stage_{}", current_sql, i - 1);
                    let cmd_sql = self.generate_command_sql(&source, cmd)?;
                    // Wrap the command result for next iteration
                    current_sql = cmd_sql.trim().to_string();
                }
            }
        }

        // Apply subsearch limit to the final multi-stage subsearch output
        // LIMIT must be inside the parens so it's valid when used as a JOIN/subquery source
        Ok(format!(
            "    ({} LIMIT {})",
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

                if ext_fields.is_empty() {
                    format!("{}, {}", base, materialized)
                } else {
                    // Materialize ext JSON fields alongside SELECT * so they appear
                    // as regular columns in downstream CTEs
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
                    format!("{}, {}, {}", base, materialized, ext_exprs.join(", "))
                }
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
                        if self.resolves_to_column(field) {
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
                            // (byte-identical); an OCSF tail path →
                            // `JSONExtractString(event, …)`.
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
                // (e.g. `JSONExtractString(event, 'unmapped', 'foo') AS foo`) but
                // drops the underlying `event` JSON column. A later CTE stage that
                // re-extracts an unpromoted/tail OCSF field — a `timechart`/`top`/
                // `stats` split-by on a `JsonPath` field — emits a fresh
                // `JSONExtractString(event, …)` that references `event` against
                // this stage's output, which no longer has it → CH
                // "Unknown identifier: event" 500. When any required field
                // resolves to a `JsonPath`, append its backing JSON column
                // (OCSF's `event`) as a passthrough so downstream extracts
                // resolve. UDM is untouched: `UdmProfile::resolve` never yields
                // `JsonPath`, so `tail_col` stays `None` and the join below is
                // byte-identical to before.
                let tail_col: Option<String> = field_list.iter().find_map(|field| {
                    match self.profile.resolve(field) {
                        FieldResolution::JsonPath { col, .. } => Some(col),
                        _ => None,
                    }
                });
                if let Some(col) = tail_col {
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
        self.generate_command_sql_inner(source, cmd, &mut no_ctx, None, false, false)
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

/// Context for SQL generation
struct GeneratorContext<'a> {
    table_name: &'a str,
    time_range: &'a TimeRange,
    current_stage: usize,
    /// Fields required by the query (for field pruning optimization)
    /// None = SELECT *, Some(set) = SELECT specific fields
    required_fields: Option<HashSet<String>>,
    /// Enable query cache (for shared searches)
    use_cache: bool,
    /// Maximum results to return
    limit: usize,
    /// Fields that live in the `ext` JSON column and need materializing in stage_0
    ext_fields: HashSet<String>,
    /// Columns available after a column-pruning command (table, fields keep).
    /// None = all columns available (no pruning), Some(set) = only these columns exist.
    available_columns: Option<HashSet<String>>,
    /// Whether a prior Risk command exists in the pipeline (for score accumulation)
    has_prior_risk: bool,
    /// Whether a prior aggregating command (stats/chart/timechart/top/rare/transaction/
    /// sequence/funnel/anomaly) has run — these GROUP BY and drop the raw `timestamp`
    /// column, so order-sensitive commands (tail/reverse) must not ORDER BY timestamp.
    aggregated: bool,
}

impl<'a> GeneratorContext<'a> {
    fn new(table_name: &'a str, time_range: &'a TimeRange) -> Self {
        Self {
            table_name,
            time_range,
            current_stage: 0,
            required_fields: None,
            use_cache: false,
            limit: ClickHouseSqlGenerator::DEFAULT_RESULT_LIMIT,
            ext_fields: HashSet::new(),
            available_columns: None,
            has_prior_risk: false,
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
    /// the promoted OCSF column in PREWHERE (matching the profile-resolved WHERE),
    /// never the raw UDM token. Emitting the bare token (`src_ip = '…'`) references
    /// a column that does not exist in `ocsf_logs` → Code 47 (500) / silent 0-rows.
    #[test]
    fn ocsf_udm_alias_prewhere_resolves_to_promoted_column() {
        use crate::schema::OcsfProfile;
        use std::sync::Arc;
        let gen = ClickHouseSqlGenerator::new().with_profile(Arc::new(OcsfProfile::new()));

        // src_ip → src_endpoint.ip ; dest_ip → dst_endpoint.ip. (NAN-1321: the
        // class-split `src_host` is intentionally NOT promoted to PREWHERE — its
        // WHERE filter is a value-pick `if(...)` spanning device.hostname, which a
        // single-column PREWHERE would pre-filter away. See
        // `ocsf_filter_on_class_split_host_uses_value_pick_and_skips_prewhere`.)
        for (query_str, expected_col) in [
            ("src_ip=\"89.248.167.131\"", "src_endpoint.ip"),
            ("dest_ip=\"10.0.0.1\"", "dst_endpoint.ip"),
        ] {
            let query = parse_query(query_str).unwrap();
            let sql = gen.generate(&query, &time_range()).unwrap();
            let prewhere = prewhere_slice(&sql);
            assert!(
                prewhere.contains(&format!("\"{expected_col}\"")),
                "OCSF PREWHERE for `{query_str}` should reference the promoted column \
                 \"{expected_col}\", got PREWHERE:\n{prewhere}"
            );
            // The raw UDM token must NOT appear as a bare PREWHERE identifier.
            assert!(
                !prewhere.contains(&format!("lower({}) =", query_str.split('=').next().unwrap()))
                    && !prewhere.contains(&format!(
                        "{} =",
                        query_str.split('=').next().unwrap()
                    )),
                "OCSF PREWHERE for `{query_str}` must not emit the raw UDM token, got:\n{prewhere}"
            );
        }
    }

    /// NAN-1319: a UDM-semantic concept OCSF splits across columns by event class
    /// (`src_host` → `src_endpoint.hostname` on network events, `device.hostname`
    /// on endpoint/sysmon events) must GROUP BY / project the class-spanning value,
    /// not just the primary column — otherwise `stats count by src_host` buckets
    /// every endpoint event as empty (on local OCSF data the empty bucket held
    /// 1.07M rows; the fix attributes them to their device host). The group key and
    /// the SELECT projection must be the SAME `if(...)` expression.
    #[test]
    fn ocsf_stats_by_class_split_host_groups_on_the_union() {
        use crate::schema::OcsfProfile;
        use std::sync::Arc;
        let gen = ClickHouseSqlGenerator::new().with_profile(Arc::new(OcsfProfile::new()));
        let query = parse_query("* | stats count by src_host").unwrap();
        let sql = gen.generate(&query, &time_range()).unwrap();
        let union = "if(\"src_endpoint.hostname\" != '', \"src_endpoint.hostname\", \"device.hostname\")";
        assert!(
            sql.contains(&format!("SELECT {union} AS src_host")),
            "OCSF `stats by src_host` must PROJECT the class-spanning union, got:\n{sql}"
        );
        assert!(
            sql.contains(&format!("GROUP BY {union}")),
            "OCSF `stats by src_host` must GROUP BY the same union expression, got:\n{sql}"
        );
        // The other class-split concepts go through the same seam (consistency).
        let q2 = parse_query("* | stats count by user").unwrap();
        let sql2 = gen.generate(&q2, &time_range()).unwrap();
        assert!(
            sql2.contains("GROUP BY if(\"user.name\" != '', \"user.name\", \"actor.user.name\")"),
            "OCSF `stats by user` must group on the class-spanning union, got:\n{sql2}"
        );
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
    /// must match the value-pick `if(...)` (so it finds the host on `device.hostname`
    /// endpoint events), and must NOT promote the primary column to PREWHERE — that
    /// would pre-filter to `src_endpoint.hostname = x` and silently drop every
    /// device-host row before WHERE. Validated end-to-end on live OCSF CH: 39 → 464.
    #[test]
    fn ocsf_filter_on_class_split_host_uses_value_pick_and_skips_prewhere() {
        use crate::schema::OcsfProfile;
        use std::sync::Arc;
        let gen = ClickHouseSqlGenerator::new().with_profile(Arc::new(OcsfProfile::new()));
        let union = "if(\"src_endpoint.hostname\" != '', \"src_endpoint.hostname\", \"device.hostname\")";

        // Equality: WHERE matches the value-pick; PREWHERE must not carry the host.
        let sql = gen
            .generate(&parse_query("src_host=\"ws-01\"").unwrap(), &time_range())
            .unwrap();
        assert!(
            sql.contains(&format!("lower(toString({union})) = 'ws-01'")),
            "OCSF src_host= must filter on the value-pick, got:\n{sql}"
        );
        let pw = prewhere_slice(&sql);
        assert!(
            !pw.contains("src_endpoint.hostname") && !pw.contains("device.hostname"),
            "OCSF src_host= must NOT promote a host column to PREWHERE, got PREWHERE:\n{pw}"
        );

        // Negation stays correct with the single expression (no De Morgan).
        let sql_ne = gen
            .generate(&parse_query("src_host!=\"ws-01\"").unwrap(), &time_range())
            .unwrap();
        assert!(
            sql_ne.contains(&format!("lower(toString({union})) != 'ws-01'")),
            "OCSF src_host!= must negate the value-pick, got:\n{sql_ne}"
        );

        // IN-list (the UDM alias is not a promoted column, so it must be routed
        // explicitly rather than falling to the empty metadata-JSON branch).
        let sql_in = gen
            .generate(&parse_query("src_host IN (\"a\",\"b\")").unwrap(), &time_range())
            .unwrap();
        assert!(
            sql_in.contains(&format!("lower({union}) IN ('a', 'b')")),
            "OCSF src_host IN must match the value-pick, got:\n{sql_in}"
        );
    }

    /// NAN-1321 parity: UDM has no class-split, so a `src_host="x"` filter stays the
    /// bare column in BOTH WHERE and PREWHERE — byte-for-byte unchanged.
    #[test]
    fn udm_filter_on_src_host_unchanged() {
        let sql = ClickHouseSqlGenerator::new()
            .generate(&parse_query("src_host=\"ws-01\"").unwrap(), &time_range())
            .unwrap();
        // PREWHERE still promotes the bare column (with the hostname FQDN expansion).
        let pw = prewhere_slice(&sql);
        assert!(
            pw.contains("src_host = 'ws-01'"),
            "UDM src_host= must still promote the bare column to PREWHERE, got:\n{pw}"
        );
        assert!(
            !sql.contains("device.hostname") && !sql.contains("if("),
            "UDM must never emit OCSF columns or the class-split `if(...)`, got:\n{sql}"
        );
    }

    /// NAN-1299 parity: UDM PREWHERE output is byte-for-byte unchanged — the
    /// field resolves to the identity column, so `lower(src_ip) = '…'` still holds.
    #[test]
    fn udm_prewhere_unchanged_for_alias_fields() {
        let query = parse_query("src_ip=\"89.248.167.131\"").unwrap();
        let sql = ClickHouseSqlGenerator::new()
            .generate(&query, &time_range())
            .unwrap();
        let prewhere = prewhere_slice(&sql);
        assert!(
            prewhere.contains("src_ip = '89.248.167.131'"),
            "UDM PREWHERE must stay byte-identical (direct `src_ip = '…'`), got:\n{prewhere}"
        );
    }

    /// Extract the PREWHERE clause text (up to the following WHERE/GROUP/ORDER/LIMIT).
    fn prewhere_slice(sql: &str) -> String {
        let start = match sql.find("PREWHERE") {
            Some(i) => i,
            None => return String::new(),
        };
        let rest = &sql[start..];
        let end = ["\nWHERE", " WHERE", "GROUP BY", "ORDER BY", "LIMIT", "\n)"]
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

    /// Bare keyword `anom` (no field qualifier) must also use iLike.
    /// Same surface as CONTAINS — the bare-keyword codegen path was the third
    /// site emitting hasToken on alphanumeric needles.
    #[test]
    fn bare_keyword_fragment_uses_ilike_not_hastoken() {
        let query = parse_query("anom").unwrap();
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
            "must NOT lower to hasToken, got:\n{}",
            sql
        );
    }

    /// Whole-token analyst patterns (`mimikatz`, `kerberos`) still work — same
    /// iLike codegen now, splitByNonAlpha + LIKE-via-dictionary-scan keeps perf
    /// in the same ballpark as the prior hasToken path.
    #[test]
    fn bare_whole_token_keyword_uses_ilike() {
        let query = parse_query("mimikatz").unwrap();
        let sql = ClickHouseSqlGenerator::new()
            .generate(&query, &time_range())
            .unwrap();

        assert!(
            sql.contains("lower(message) iLike '%mimikatz%'"),
            "whole-token keyword should still lower to iLike (same codegen), got:\n{}",
            sql
        );
    }

    /// Special-char keywords (paths, IPs) collapse to a single iLike — the
    /// pre-fix bloom-guard + iLike pair becomes redundant once iLike is itself
    /// index-accelerated.
    #[test]
    fn bare_special_char_keyword_uses_single_ilike() {
        let query = parse_query("cmd.exe").unwrap();
        let sql = ClickHouseSqlGenerator::new()
            .generate(&query, &time_range())
            .unwrap();

        assert!(
            sql.contains("lower(message) iLike '%cmd.exe%'"),
            "special-char keyword should iLike the full pattern, got:\n{}",
            sql
        );
        assert!(
            !sql.contains(" AND lower(message) iLike "),
            "should NOT emit a redundant bloom-guard iLike alongside the main one, got:\n{}",
            sql
        );
    }
}
