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

/// What the generator knows about the CTE feeding a command stage.
///
/// Generator CTEs are ordinary (non-materialized) CTEs: ClickHouse re-executes
/// every reference independently. So any rewrite that references its source
/// MORE THAN ONCE is only sound when re-executing that source yields the same
/// rows — otherwise the two references silently see different data.
#[derive(Clone, Debug, Default)]
pub(crate) struct SourceStability {
    /// `source` is the deterministic base scan: `stage_0`, no requery command
    /// injected an `ORDER BY … LIMIT` into it. The dedup survivor-id rewrite
    /// needs this stronger property — it scans the source twice AND assumes a
    /// plain base projection (NAN-1636).
    pub deterministic_base: bool,
    /// Re-executing `source` yields the same ROW SET. False once any upstream
    /// stage picks an arbitrary bounded subset (`head`, `tail`, `sort N`,
    /// `sample`, `top`/`rare`, a LIMITed subsearch, a requery-limited base) —
    /// see [`command_preserves_row_stability`] (NAN-2265).
    pub rows_stable: bool,
    /// Escape hatch for an UNSTABLE source: `Some` when the instability is
    /// only a trailing run of pure row-subset selectors (`head` / `tail` /
    /// `sort N` / `sample`) over identity-carrying rows — see
    /// [`ClickHouseSqlGenerator::snapshot_refetch_plan`]. The eventstats /
    /// anomaly attach then replaces the unstable source with its
    /// deterministic id-closure (`FROM <ancestor> WHERE <sid> IN <ids pinned
    /// once via the scalar cache>` — `snapshot_closure_source_sql`), which
    /// the bounded NAN-1642 map/scalar attach applies to verbatim, instead of
    /// falling back to the whole-partition window that re-buffers every wide
    /// row. Measured on Saturn (24h / 21.9M rows, wide `SELECT *` terminal,
    /// 3 GiB/query cap, max_threads=4, real generated SQL both sides), peak
    /// memory for `head N | eventstats avg(bytes_out) by dest_ip`, closure vs
    /// window: 20k → 131 MiB vs 491 MiB; 200k → 0.92–1.01 GiB vs 1.74–1.78
    /// GiB; 500k → 2.03–2.29 GiB vs **Code 241 (both runs)**; 1M → 2.58 GiB
    /// — at the plain-`head` pipeline floor (~2.5 GiB), where the window is
    /// long dead (NAN-2265).
    pub snapshot_refetch: Option<SnapshotRefetch>,
}

/// The two ingredients of the snapshot id-closure shape (NAN-2265): the last
/// row-stable CTE to re-read, and the row-identity column whose pinned values
/// select the closure. `sid` is a CONTENT hash on the ingest path (NAN-2264),
/// so the closure may contain content-twin copies beyond the selector's bound
/// — the emitted rows and the attached aggregates always come from the same
/// deterministic set either way.
#[derive(Clone, Debug)]
pub(crate) struct SnapshotRefetch {
    /// Name of the last row-stable CTE (`stage_<j>`). Re-executing it yields
    /// the same row set, so `FROM <ancestor> WHERE <sid> IN <pinned ids>` is
    /// a deterministic stand-in for the selector chain's sample.
    pub ancestor: String,
    /// The row-identity column (`id` for logs, `span_id` for spans).
    pub sid: &'static str,
}

/// Whether `cmd` hands its downstream stages the same ROW SET on every
/// re-execution, given a stable input (NAN-2265).
///
/// `false` for the commands that select an arbitrary bounded subset: their
/// `LIMIT` has no total order to break ties, so two executions of the same CTE
/// can emit different rows. Exhaustive on purpose — a new command must make
/// this call explicitly rather than inherit "stable" from a `_` arm.
fn command_preserves_row_stability(cmd: &Command) -> bool {
    match cmd {
        // Arbitrary bounded subsets: an unordered `LIMIT` (head), a partially
        // ordered one (tail / sort N / top / rare — ties at the cut are broken
        // by whichever thread got there first), or an explicitly random one
        // (sample). `head` is the analyst-facing case from NAN-2265.
        Command::Head { .. }
        | Command::Tail { .. }
        | Command::Sample { .. }
        | Command::Top { .. }
        | Command::Rare { .. } => false,
        Command::Sort { limit, .. } => limit.is_none(),
        // `timechart … limit=N` keeps the top N split-by SERIES by total, so
        // series tied on the cut are picked arbitrarily. Unlimited timechart is
        // a plain GROUP BY over a stable input.
        Command::Timechart { limit, .. } => limit.is_none(),
        // Subsearch arms carry their own unordered `LIMIT maxout`, so which
        // rows they contribute (and, for join, which main-side rows survive)
        // can differ per execution. Note these are the one unstable case whose
        // ROW COUNT is not itself bounded — the main arm is whatever the
        // pipeline produced — so the eventstats/anomaly window fallback can
        // buffer a large partition here. Correctness wins: a Code 241 is loud,
        // a mis-attached aggregate is silent.
        Command::Join { .. } | Command::Append { .. } => false,
        // Re-query commands: the base CTE gets an injected `ORDER BY … LIMIT`
        // (see `has_requery_command`), and their own output is assembled in
        // Rust post-processing.
        Command::Asset { .. }
        | Command::Tree { .. }
        | Command::Cloud { .. }
        | Command::Baseline { .. }
        | Command::Lateral { .. }
        // Rows come from an external service capped at max_rows.
        | Command::InputLookup { .. }
        | Command::Ai { .. } => false,
        // Row-set preserving (projections, filters, per-row enrichment) or
        // group-determined (GROUP BY over a stable input yields the same
        // groups). `dedup` keeps one row per key group: the row COUNT is
        // stable and only a timestamp TIE can swap which member survives —
        // already arbitrary in both dedup shapes — so it is not treated as a
        // subset selector here. Gating on it would send the common
        // `dedup | eventstats` pipeline back to the whole-partition window
        // over an unbounded row set, i.e. the OOM class NAN-1642 removed.
        Command::Stats { .. }
        | Command::Chart { .. }
        | Command::StreamStats { .. }
        | Command::Where { .. }
        | Command::Table { .. }
        | Command::Rename { .. }
        | Command::Lookup { .. }
        | Command::Eval { .. }
        | Command::Dedup { .. }
        | Command::Bin { .. }
        | Command::Rex { .. }
        | Command::Fields { .. }
        | Command::Transaction { .. }
        | Command::Fillnull { .. }
        | Command::Mvexpand { .. }
        | Command::Spath { .. }
        | Command::Format { .. }
        | Command::Return { .. }
        | Command::Risk { .. }
        | Command::Prevalence { .. }
        | Command::Reverse
        | Command::EventStats { .. }
        | Command::Sequence { .. }
        | Command::Funnel { .. }
        | Command::Anomaly { .. }
        | Command::ResolveIdentity { .. }
        // Markers that short-circuit to a curated surface or are pure
        // pass-throughs in SQL generation.
        | Command::Output { .. }
        | Command::Services
        | Command::Service { .. }
        | Command::Trace { .. }
        | Command::Metric { .. }
        | Command::Retro { .. } => true,
    }
}

/// Whether `cmd` merely SELECTS A SUBSET of its input rows, passing every
/// selected row through byte-identical — `SELECT * FROM src [ORDER BY …]
/// LIMIT n` shapes with no aggregation, projection, or row synthesis
/// (NAN-2265).
///
/// These are the stages the eventstats / anomaly snapshot-refetch can rewind
/// through: because each selected row IS a row of the stable ancestor,
/// re-reading the ancestor filtered to the snapshotted row ids reproduces
/// exactly the rows the selector chain emitted. `top` / `rare` /
/// `timechart limit=N` are unstable but NOT selectors — they emit aggregated
/// rows, so their fallback window buffers narrow aggregates, not the raw-row
/// OOM class this shape exists to avoid.
fn command_is_row_subset_selector(cmd: &Command) -> bool {
    match cmd {
        Command::Head { .. } | Command::Tail { .. } | Command::Sample { .. } => true,
        Command::Sort { limit, .. } => limit.is_some(),
        _ => false,
    }
}

/// Whether `cmd` preserves the ROW IDENTITY of its input: every output row is
/// exactly one input row (no aggregation, no row synthesis or duplication)
/// still carrying the untouched `sid` column (NAN-2265).
///
/// Row-stability is NOT enough for the snapshot id-closure ancestor: `stats`
/// is row-stable but its output rows have no `id` at all (UNKNOWN_IDENTIFIER
/// in the closure), and `mvexpand` multiplies rows per id. Conservative
/// allowlist: a command not listed keeps the window fallback (correct, just
/// heavier); add it here once its identity behavior is reasoned through.
fn command_preserves_row_identity(cmd: &Command, sid: &str) -> bool {
    match cmd {
        // Per-row filters/enrichers/annotators: one output row per input row
        // (or a subset), `SELECT *`-style so the id column passes through.
        Command::Where { .. }
        | Command::Lookup { .. }
        | Command::Rex { .. }
        | Command::Bin { .. }
        | Command::Fillnull { .. }
        | Command::Spath { .. }
        | Command::Risk { .. }
        | Command::Prevalence { .. }
        | Command::Reverse
        | Command::Dedup { .. }
        | Command::EventStats { .. }
        | Command::StreamStats { .. }
        | Command::ResolveIdentity { .. }
        | Command::Anomaly { .. } => true,
        // Full sort (no limit) reorders only; a LIMITed sort is a selector,
        // handled by `command_is_row_subset_selector`.
        Command::Sort { limit, .. } => limit.is_none(),
        // Eval keeps every row; an `eval id=…` reassignment is caught by the
        // caller's `is_upstream_computed_field(sid)` guard.
        Command::Eval { .. } => true,
        // Keep-mode projections update `available_columns`, which the caller
        // checks for `sid` — the projection itself is one-row-per-row.
        Command::Table { .. } | Command::Fields { keep: true, .. } => true,
        // Exclude-mode can drop the id column (`fields - id`); renames can
        // alias it away. Allowed only when they provably don't touch it.
        Command::Fields {
            keep: false,
            fields,
        } => !fields.iter().any(|f| f.eq_ignore_ascii_case(sid)),
        Command::Rename { mappings } => !mappings
            .iter()
            .any(|m| m.from.eq_ignore_ascii_case(sid) || m.to.eq_ignore_ascii_case(sid)),
        // Everything else aggregates, duplicates, or synthesizes rows
        // (stats/chart/timechart/top/rare/transaction/sequence/funnel/
        // mvexpand/format/return/…): no physical row identity survives.
        _ => false,
    }
}

/// Explicit columns in the hybrid schema (stored as direct columns with bloom filters)
/// All other UDM fields are stored in the `ext` JSON column (extended fields)
///
/// This list must match the physical `nanosiem.logs` columns in
/// `clickhouse/init.sql` (plus the column-adding migrations under `clickhouse/`).
/// The `logs_ddl_column_consistency` integration test (NAN-1623) gates that
/// drift: a `logs` column missing here is silently routed to `ext` JSON instead
/// of its direct column (wrong / empty results, never an error).
///
/// `pub` so `UdmProfile` (`crate::schema::udm`) can reference the *same* slice for
/// byte-for-byte parity rather than copying values (NAN-1244), and so the
/// DDL↔Rust drift gate (`tests/logs_ddl_column_consistency.rs`, NAN-1623) can
/// consume the canonical list. Widening visibility is non-behavioral.
pub const EXPLICIT_COLUMNS: &[&str] = &[
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
///
/// `pub` so the DDL↔Rust drift gate (`tests/logs_ddl_column_consistency.rs`,
/// NAN-1623) asserts this list equals the DDL's MATERIALIZED column set.
pub const MATERIALIZED_COLUMNS: &[&str] = &[
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
    /// Emit no trailing result ORDER BY (the generator's implicit
    /// `ORDER BY <time> DESC` on raw-event output). Companion queries
    /// (histogram, count) wrap the SQL in an aggregation where row order is
    /// irrelevant — and under the count companion's bounded inner LIMIT a
    /// trailing ORDER BY becomes a semantic top-N that ClickHouse cannot
    /// elide, defeating early termination (NAN-1635). This is the structural
    /// alternative to string-stripping ORDER BY from generated SQL, which
    /// truncates mid-literal (NAN-1160). User-level ordering (`| sort`) is
    /// query semantics and keeps its ORDER BY inside its own stage.
    pub unordered: bool,
}

impl Default for QueryOptions {
    fn default() -> Self {
        Self {
            use_cache: false,
            table_view: false,
            // Safety bound for callers that execute the generated SQL directly
            // (explain, detection, …) without an executor-side pagination step.
            limit: Some(ClickHouseSqlGenerator::DEFAULT_RESULT_LIMIT),
            unordered: false,
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
    // NAN-1697: `user` is deliberately ABSENT. It was assumed lowercased at
    // ingest, but the logs lane never downcases it — OTLP and Windows-event
    // ingest write it verbatim (`CORP\JSmith`, mixed-case service accounts), so
    // a raw `user = '<lowered>'` compare silently dropped those rows (0 vs 2310
    // locally; 781 mixed-case rows / 1.82B on Saturn). Unlike the host-entity
    // fields it gets no hostname-expansion case rescue. Queries now emit
    // `lower(user) = '…'`, served by the migration-119 `idx_user_words` text
    // index (Saturn EXPLAIN: prunes 13,215 vs the raw bloom's 28,307 granules on
    // a dotted username; ~1.6x on a single-token value but still sub-2s). The
    // audit writer still downcases `user`, so audit-row search is unaffected.
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
    // NAN-1647 (NAN-1632 finding 3.9): dvc_ip carries a raw whole-value bloom
    // and full-retention history is empirically all-lowercase (Saturn probe:
    // 0/1.75B rows mixed-case), so the raw compare engages the index that the
    // previous `lower(dvc_ip)` form orphaned. The IOC sweep
    // (IOC_OBSERVABLE_RAW_COLUMNS, NAN-1580) already compared this column RAW.
    // DEPENDENCY: membership is sound only because the Vector clickhouse_mapping
    // lane downcases dvc_ip at ingest (NAN-1646) — that change must be deployed
    // to ingest before this one goes live, or uppercase IPv6 rows written in
    // between become unfindable by raw equality.
    "dvc_ip",
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

/// True when `expr` is exactly the source-scope gate conjunct that
/// `query_processing::mandatory_exclusion` appends at every scan. Two shapes
/// exist (see that function for the authoritative emitted AST):
///
///  * NAN-704 legacy audit gate — a deny set of exactly `{"audit"}` emits
///    `source_type != "audit"` (case-insensitive on both sides).
///  * NAN-1799 per-source RBAC scoping — any other non-empty deny set emits
///    ONE negated IN-list, `source_type NOT IN ("a", "b", …)`
///    (`SearchExpr::InList { negated: true, .. }`).
///
/// Both must be recognized here: a scoped user's spans/metrics query carries
/// the NOT-IN form, and missing it would leave a per-row `attributes` Map
/// probe on a column class that doesn't exist there AND silently drop any
/// span a tenant tagged with a denied `source_type` value (perf + correctness
/// on spans; the logs dataset never strips, so there is no leak either way).
///
/// The field-name check is the same relaxed normalization for both arms
/// (`eq_ignore_ascii_case("source_type")`); values are NOT inspected for the
/// IN-list arm — the injector is the only producer of the
/// `And(Group(inner), <gate>)` wrap this matcher is applied under, and its
/// value set is exactly the caller's deny set.
fn is_injected_audit_gate_filter(expr: &SearchExpr) -> bool {
    match expr {
        SearchExpr::FieldFilter {
            field,
            op: Comparator::Ne,
            value: Value::String(s),
        } => field.eq_ignore_ascii_case("source_type") && s.eq_ignore_ascii_case("audit"),
        SearchExpr::InList {
            field,
            negated: true,
            values: _,
        } => field.eq_ignore_ascii_case("source_type"),
        _ => false,
    }
}

/// Strip the injected source-scope gate from a query so it is NOT emitted on
/// the spans/metrics datasets (O45 / NAN-1733; generalized for NAN-1799).
///
/// `enforce_source_scope` (and its `enforce_non_audit_query` /
/// `enforce_source_type_exclusion` wrappers) wraps EVERY scan as
/// `(<expr>) AND <gate>`, where `<gate>` is `source_type != "audit"` for the
/// legacy `{"audit"}` deny set or `source_type NOT IN (…)` for any other
/// deny set (NAN-1799 per-source RBAC scoping — see
/// `is_injected_audit_gate_filter` for both recognized shapes). On
/// `Dataset::Logs` that resolves to a cheap `source_type` column compare and is
/// correct — audit rows live only in the `logs` table (`source_type = 'audit'`).
/// On the OTLP spans/metrics datasets there IS no `source_type` column: the
/// spans/metrics profile resolves it to a per-row `attributes` / `resource_attributes`
/// Map lookup, so the gate (a) costs a double Map probe for a row class that can
/// never exist there and (b) silently drops any span/metric a tenant legitimately
/// tagged with a denied `source_type` value. This is the exact structural
/// inverse of the injection in
/// `query_processing::inject_source_type_exclusion_recursive`:
/// unwrap `And(Group(inner), <gate>)` back to `inner`. Only the
/// auto-injected wrap (`Group` on the left) is matched, so a user's own top-level
/// `source_type!="audit"` term is left untouched.
///
/// NAN-1794: the injection now also gates every SUBSEARCH (`join` / `append` /
/// `IN [ … ]`), so the strip must walk them too — and it must decide PER SCAN,
/// because a subsearch can target a different dataset than the outer query
/// (NAN-1562 cross-dataset correlation). The rule is simply "does THIS scan read
/// the logs table?":
///
///  * spans query + inherited subsearch → subsearch reads spans → strip.
///  * spans query + `[dataset=logs …]`  → subsearch reads LOGS → KEEP the gate.
///    (Dropping it there would be the audit leak this gate exists to prevent.)
///  * logs query  + `[dataset=spans …]` → subsearch reads spans → strip.
///
/// Fail-closed by construction: anything this walker does not recognize keeps
/// its gate. A missed variant costs a redundant Map probe on spans — never a
/// leaked audit row.
fn strip_injected_audit_gate(query: &Query, dataset: otel::Dataset) -> Query {
    match query {
        Query::Search(expr) => Query::Search(strip_injected_audit_gate_expr(expr, dataset)),
        Query::Piped { source, command } => Query::Piped {
            source: Box::new(strip_injected_audit_gate(source, dataset)),
            command: strip_injected_audit_gate_command(command, dataset),
        },
    }
}

/// Unwrap the gate from one scan (only when that scan does NOT read `logs`),
/// then recurse into any subsearches the expression carries.
fn strip_injected_audit_gate_expr(expr: &SearchExpr, dataset: otel::Dataset) -> SearchExpr {
    if !matches!(dataset, otel::Dataset::Logs) {
        if let SearchExpr::And(left, right) = expr {
            if is_injected_audit_gate_filter(right) {
                if let SearchExpr::Group(inner) = left.as_ref() {
                    return strip_injected_audit_gate_subsearches(inner, dataset);
                }
            }
        }
    }
    strip_injected_audit_gate_subsearches(expr, dataset)
}

/// Walk an expression and strip the gate inside every `IN [ <subsearch> ]`,
/// each resolved against ITS OWN dataset (inheriting the outer one when unset).
fn strip_injected_audit_gate_subsearches(
    expr: &SearchExpr,
    dataset: otel::Dataset,
) -> SearchExpr {
    match expr {
        SearchExpr::InSubsearch {
            field,
            subsearch,
            negated,
            subsearch_dataset,
        } => SearchExpr::InSubsearch {
            field: field.clone(),
            subsearch: Box::new(strip_injected_audit_gate(
                subsearch,
                subsearch_dataset.unwrap_or(dataset),
            )),
            negated: *negated,
            subsearch_dataset: *subsearch_dataset,
        },
        SearchExpr::And(left, right) => SearchExpr::And(
            Box::new(strip_injected_audit_gate_subsearches(left, dataset)),
            Box::new(strip_injected_audit_gate_subsearches(right, dataset)),
        ),
        SearchExpr::Or(left, right) => SearchExpr::Or(
            Box::new(strip_injected_audit_gate_subsearches(left, dataset)),
            Box::new(strip_injected_audit_gate_subsearches(right, dataset)),
        ),
        SearchExpr::Not(inner) => SearchExpr::Not(Box::new(
            strip_injected_audit_gate_subsearches(inner, dataset),
        )),
        SearchExpr::Group(inner) => SearchExpr::Group(Box::new(
            strip_injected_audit_gate_subsearches(inner, dataset),
        )),
        other => other.clone(),
    }
}

/// Mirror of `query_processing::gate_command`: reach the subsearch of every
/// command that carries one.
fn strip_injected_audit_gate_command(command: &Command, dataset: otel::Dataset) -> Command {
    let mut stripped = command.clone();
    match &mut stripped {
        Command::Join {
            subsearch,
            subsearch_dataset,
            ..
        } => {
            let sub_dataset = subsearch_dataset.unwrap_or(dataset);
            **subsearch = strip_injected_audit_gate(subsearch, sub_dataset);
        }
        // `append` has no dataset selector — its subsearch inherits the outer one.
        Command::Append { subsearch, .. } => {
            **subsearch = strip_injected_audit_gate(subsearch, dataset);
        }
        Command::Where { condition } => {
            *condition = strip_injected_audit_gate_subsearches(condition, dataset);
        }
        Command::Transaction {
            startswith,
            endswith,
            ..
        } => {
            if let Some(expr) = startswith {
                *expr = strip_injected_audit_gate_subsearches(expr, dataset);
            }
            if let Some(expr) = endswith {
                *expr = strip_injected_audit_gate_subsearches(expr, dataset);
            }
        }
        Command::Sequence { conditions, .. } => {
            for condition in conditions.iter_mut() {
                *condition = strip_injected_audit_gate_subsearches(condition, dataset);
            }
        }
        Command::Funnel { steps, .. } => {
            for (_, condition) in steps.iter_mut() {
                *condition = strip_injected_audit_gate_subsearches(condition, dataset);
            }
        }
        // Everything else carries no subsearch. A wildcard is safe HERE (unlike
        // on the injection side): an unrecognized variant simply keeps its gate.
        _ => {}
    }
    stripped
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
    /// True once a generated stage has rewritten the `timestamp` column
    /// WITHOUT registering it in `upstream_computed_fields` (`bin timestamp
    /// span=…` in-place, `table x as timestamp` — see
    /// `command_rewrites_timestamp`) — rewritten values can precede the query
    /// window start, so the resolve_identity ASOF build-side bound (NAN-1638)
    /// must not be applied after one. Registered rewriters (eval/rename/rex/
    /// spath/stats aliases) are caught via the upstream-computed set instead.
    /// Maintained by `note_upstream_computed`; deliberately NOT swapped with
    /// the subsearch scope: a rewrite in either scope keeps the bound off for
    /// the rest of the generation (conservative — falls back to the legacy
    /// unbounded join). Reset by `generate_with_options`.
    upstream_timestamp_rewritten: RwLock<bool>,
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
    /// The tenant logs STORAGE table captured on the first
    /// [`with_dataset`](ClickHouseSqlGenerator::with_dataset) swap, alongside
    /// [`base_profile`](Self::base_profile) (NAN-1721 / O8). A later
    /// `Dataset::Logs` restore (a cross-dataset subsearch INTO logs from a
    /// spans/metrics outer query) points `table_name` back at THIS table
    /// (`ocsf_logs` / tenant-prefixed) rather than the literal `"logs"` that
    /// `Dataset::table_name()` returns — which on an OCSF/tenant-prefixed tenant
    /// is the wrong (empty or legacy-UDM) table, so the correlation silently
    /// joins zero rows. `None` until the first dataset swap; logs-only queries
    /// never swap, so it stays `None` and behavior is byte-identical.
    base_table: Option<String>,
    /// The dataset the generator currently targets (NAN-1721 / O8). Defaults to
    /// [`Dataset::Logs`]; set in lock-step with `table_name`/`time_column`/
    /// `profile` by [`with_dataset`](ClickHouseSqlGenerator::with_dataset).
    /// Cross-dataset subsearch detection compares this DATASET IDENTITY against
    /// the subsearch's dataset — not `table_name` strings, which falsely flags an
    /// OCSF/tenant-prefixed logs table (`ocsf_logs` != `"logs"`) as cross-dataset
    /// and re-points the sub at the wrong table.
    dataset: otel::Dataset,
    /// Per-request configuration for the derived `risk` dataset (NAN-1798 P2):
    /// the decay factors + cleared-entity boundaries the shared risk builder
    /// inlines into the `FROM (<risk aggregation>)` base source, resolved by
    /// `core_search`'s cached provider and injected via
    /// [`with_risk_config`](Self::with_risk_config) BEFORE any
    /// [`with_dataset`](Self::with_dataset)`(Risk)` swap (including the scoped
    /// clones a `[dataset=risk …]` subsearch takes — the field is carried by
    /// `Clone`). `None` (every non-risk path, and tests that never touch risk)
    /// falls back to [`RiskQueryConfig::default`] at swap time.
    risk_config: Option<crate::risk::clickhouse_sql::RiskQueryConfig>,
    /// Whether this deployment is a multi-shard ClickHouse cluster (NAN-1728 / C5).
    /// Set from `DualPool::TableNames::is_clustered()` at construction via
    /// [`with_cluster_routing`](Self::with_cluster_routing). When `true`, a
    /// dataset/rollup swap ([`with_dataset`](Self::with_dataset) Spans/Metrics,
    /// [`with_metrics_rollup`](Self::with_metrics_rollup)) routes its otel storage
    /// table to the `_distributed` wrapper so spans/metrics searches fan in across
    /// all shards — mirroring how the logs lane is pre-routed via `read_bare` in
    /// `ch_generator_for_pool`. Defaults to `false`, so single-shard (dev/Saturn/
    /// most tenants) and every `::new()`/`::with_table()` site keep byte-identical
    /// literal-local output. The `Dataset::Logs` restore arm is unaffected: its
    /// table comes from `base_table`, already routed by `read_bare`.
    is_clustered: bool,
    /// Caller-scope deny set for gating the `| identity` ASOF-join build-side
    /// (NAN-1801). The P1 main-scan enforcement is a text rewrite of the outer
    /// query and does NOT reach joined datasets; when set via
    /// [`with_source_scope_deny`](Self::with_source_scope_deny), the identity
    /// build-side subquery filters denied `source` values.
    /// Config-like (mirrors `is_clustered`): carried across clone, not reset.
    ///
    /// NOTE: the direct `/api/identity/resolve` endpoints (the primary leak) are
    /// gated separately in the handlers. This field is NOT yet populated by the
    /// interactive search pipeline (`ch_generator_for_pool` doesn't carry scope),
    /// so the `| identity` enrich-side gate is inert until that threading lands —
    /// tracked as a NAN-1801 follow-up. Empty default = no behavior change.
    source_scope_deny: std::collections::BTreeSet<String>,
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
            upstream_timestamp_rewritten: RwLock::new(false),
            computed_fields: RwLock::new(HashSet::new()),
            upstream_computed_fields: RwLock::new(HashSet::new()),
            agg_reference_aliases: RwLock::new(std::collections::HashMap::new()),
            profile: Arc::clone(&self.profile),
            base_profile: self.base_profile.clone(),
            base_table: self.base_table.clone(),
            dataset: self.dataset,
            risk_config: self.risk_config.clone(),
            is_clustered: self.is_clustered,
            source_scope_deny: self.source_scope_deny.clone(),
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
            upstream_timestamp_rewritten: RwLock::new(false),
            computed_fields: RwLock::new(HashSet::new()),
            upstream_computed_fields: RwLock::new(HashSet::new()),
            agg_reference_aliases: RwLock::new(std::collections::HashMap::new()),
            profile: Arc::new(UdmProfile::new()),
            base_profile: None,
            base_table: None,
            dataset: otel::Dataset::Logs,
            risk_config: None,
            is_clustered: false,
            source_scope_deny: std::collections::BTreeSet::new(),
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
            upstream_timestamp_rewritten: RwLock::new(false),
            computed_fields: RwLock::new(HashSet::new()),
            upstream_computed_fields: RwLock::new(HashSet::new()),
            agg_reference_aliases: RwLock::new(std::collections::HashMap::new()),
            profile: Arc::new(UdmProfile::new()),
            base_profile: None,
            base_table: None,
            dataset: otel::Dataset::Logs,
            risk_config: None,
            is_clustered: false,
            source_scope_deny: std::collections::BTreeSet::new(),
        }
    }

    /// Inject an explicit schema profile (OCSF Phase 2). Builder-style so it
    /// composes with the existing `with_*` setters. UDM call sites that never
    /// call this keep the default [`UdmProfile`], so behavior is unchanged.
    pub fn with_profile(mut self, profile: Arc<dyn SchemaProfile>) -> Self {
        self.profile = profile;
        self
    }

    /// Enable multi-shard cluster routing for otel dataset/rollup swaps
    /// (NAN-1728 / C5). Builder-style; pass `DualPool::TableNames::is_clustered()`.
    /// When `true`, [`with_dataset`](Self::with_dataset) (Spans/Metrics) and
    /// [`with_metrics_rollup`](Self::with_metrics_rollup) point their otel storage
    /// table at the `_distributed` wrapper so those searches fan in across all
    /// shards — mirroring the logs lane, which is pre-routed via
    /// `TableNames::read_bare` in `ch_generator_for_pool`. `false` (the default and
    /// every `::new()`/`::with_table()` site) keeps literal-local output, so
    /// single-shard deployments are byte-identical.
    pub fn with_cluster_routing(mut self, is_clustered: bool) -> Self {
        self.is_clustered = is_clustered;
        self
    }

    /// Route a bare read table to its `_distributed` wrapper on clustered
    /// deployments (NAN-1728 / C5, R2). Mirrors `TableNames::read_bare`: the
    /// tables this is called for (otel dataset/rollup storage tables in
    /// `with_dataset`/`with_metrics_rollup`, `identity_observations` in the ASOF
    /// build side) are all members of the distributed set, so appending
    /// `_distributed` when clustered is the same resolution `read_bare` performs
    /// for the logs lane. `is_clustered=false` returns the bare literal unchanged
    /// — byte-identical single-shard output. The generator relies on the CH
    /// client's default `nanosiem` database, so this returns the BARE name (no
    /// `nanosiem.` prefix), like the logs lane.
    fn route_dataset_table(&self, base: &str) -> String {
        if self.is_clustered {
            format!("{base}_distributed")
        } else {
            base.to_string()
        }
    }

    /// Inject the per-request risk-dataset configuration (NAN-1798 P2): the
    /// decay factors + cleared-entity boundaries + evaluation anchor the shared
    /// risk builder inlines into the derived `FROM (<risk aggregation>)` base
    /// source. Builder-style; MUST be applied before a
    /// [`with_dataset`](Self::with_dataset)`(Risk)` swap (or before generating
    /// a query whose subsearch selects `dataset=risk` — the scoped clone
    /// carries the field). `core_search` resolves it from the cached
    /// [`RiskQueryConfigProvider`](crate::risk::config_provider::RiskQueryConfigProvider)
    /// so `dataset=risk` scores are computed with the SAME values the
    /// enterprise repository binds — never a divergent computation. Non-risk
    /// generation never consults it, so attaching it is output-neutral for
    /// `dataset=logs/spans/metrics`.
    pub fn with_risk_config(
        mut self,
        config: crate::risk::clickhouse_sql::RiskQueryConfig,
    ) -> Self {
        self.risk_config = Some(config);
        self
    }

    /// The derived base source for the `risk` dataset (NAN-1798 P2): the shared
    /// risk builder's entity-grain aggregation, rendered inline and
    /// parenthesized for a `FROM (…)` position. Built from the CAPTURED tenant
    /// logs binding (`base_table`/`base_profile` — already cluster-routed via
    /// `read_bare` and OCSF-aware), so the findings scan targets the same table
    /// the enterprise repository reads, whichever dataset the generator was on
    /// when the swap happened.
    fn risk_base_source(&self) -> String {
        let cfg = self
            .risk_config
            .clone()
            .unwrap_or_else(crate::risk::clickhouse_sql::RiskQueryConfig::default);
        let logs_table = self
            .base_table
            .clone()
            .expect("base_table captured at top of with_dataset");
        let ocsf = self
            .base_profile
            .as_ref()
            .map(|p| p.id() == crate::schema::SchemaId::Ocsf)
            .unwrap_or(false);
        let source = crate::risk::clickhouse_sql::RiskFindingsSource::new(ocsf, logs_table)
            .with_source_deny(&self.source_scope_deny);
        let query = crate::risk::clickhouse_sql::risk_dataset_base_query(
            &source,
            cfg.now,
            &cfg.decay,
            &cfg.cleared,
        );
        format!("({})", query.to_inline_sql())
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
    /// `Dataset::Risk` (NAN-1798 P2) swaps in a DERIVED subquery instead of a
    /// storage table ([`risk_base_source`](Self::risk_base_source)) — the first
    /// dataset whose base source is not a table string.
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
            // O8 (NAN-1721): capture the tenant logs STORAGE table too, so a later
            // `Dataset::Logs` restore points back at THIS table (`ocsf_logs` /
            // tenant-prefixed) rather than the literal `"logs"` — see the
            // `Dataset::Logs` arm below.
            self.base_table = Some(self.table_name.clone());
        }
        self.dataset = dataset;
        // O8 (NAN-1721): for a `Dataset::Logs` restore, keep the captured tenant
        // logs table (`base_table`) rather than the literal `Dataset::table_name()`
        // (`"logs"`), which is the wrong table on OCSF/tenant-prefixed tenants.
        self.table_name = match dataset {
            otel::Dataset::Logs => self
                .base_table
                .clone()
                .unwrap_or_else(|| dataset.table_name().to_string()),
            // NAN-1798 P2: the risk dataset's base source is a DERIVED subquery
            // over the captured tenant logs table (cluster routing + OCSF
            // sentinels inherited from the shared builder), not a storage table.
            otel::Dataset::Risk => self.risk_base_source(),
            // NAN-1728 (C5): route the spans/metrics storage table to its
            // `_distributed` wrapper when clustered so the search reads all
            // shards; single-shard (default) keeps the bare literal.
            // (The Logs arm restores `base_table`, already routed by `read_bare`.)
            _ => self.route_dataset_table(dataset.table_name()),
        };
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
            // NAN-1798 P2: the derived risk grain resolves fields through its
            // own 15-column profile (no ext/Map spill on a subquery source).
            otel::Dataset::Risk => self.profile = Arc::new(crate::schema::RiskProfile::new()),
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
        // NAN-1728 (C5): route the rollup storage table to its `_distributed`
        // wrapper when clustered; single-shard (default) keeps the bare literal.
        self.table_name = self.route_dataset_table(grain.table_name());
        self.time_column = grain.time_column().to_string();
        self
    }

    /// Whether the generator is currently pointed at a metrics rollup table.
    /// NAN-1728 (C5): also recognizes the `_distributed` wrapper names, since a
    /// clustered [`with_metrics_rollup`](Self::with_metrics_rollup) points
    /// `table_name` at `otel_metrics_1m_distributed`/`_1h_distributed`.
    pub(crate) fn is_metrics_rollup(&self) -> bool {
        matches!(
            self.table_name.as_str(),
            "otel_metrics_1m"
                | "otel_metrics_1h"
                | "otel_metrics_1m_distributed"
                | "otel_metrics_1h_distributed"
        )
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

    /// The base-scan time-bound predicate for the ACTIVE dataset (NAN-1798 P2).
    ///
    /// Every non-risk dataset emits the exact historical
    /// `{time_column} BETWEEN '{start}' AND '{end}'` form — byte-identical to
    /// the previously inlined format strings. The derived `risk` dataset emits
    /// a constant-true predicate instead: its 24h/7d score windows are FIXED
    /// trailing windows anchored at evaluation time and baked into the derived
    /// base source (design §4 — "the search time-picker does not reshape
    /// them"), so bounding the entity grain by the picker window would
    /// silently drop entities whose last finding predates it and diverge from
    /// the Risk page / leaderboard numbers.
    pub(crate) fn time_bound_predicate(
        &self,
        time_column: &str,
        time_range: &TimeRange,
    ) -> String {
        if matches!(self.dataset, otel::Dataset::Risk) {
            "1 = 1".to_string()
        } else {
            format!(
                "{} BETWEEN '{}' AND '{}'",
                time_column,
                crate::sql_hygiene::format_ch_bound_micros(&time_range.start),
                crate::sql_hygiene::format_ch_bound_micros(&time_range.end),
            )
        }
    }

    /// The physical per-row identity column for the active dataset (NAN-1721 /
    /// O27) — the deterministic tie-break in window `ORDER BY` clauses. `id` on
    /// logs (UDM/OCSF), `span_id` on spans; `None` for a profile with no unique
    /// per-row id (metrics), where callers drop the tie-break / fall back to the
    /// sort-based shape. Keyed off `core_fields` so it stays in lock-step with
    /// the profile's own identity contract.
    ///
    /// NOT a de-duplication key: on logs `id` is a CONTENT hash, so
    /// content-identical rows share one (NAN-2264). `dedup` consults this only
    /// to recognise a physical row scan, never to elect a survivor.
    pub(crate) fn row_identity_column(&self) -> Option<&'static str> {
        if self.profile.core_fields().contains(&"id") {
            Some("id")
        } else if self.profile.core_fields().contains(&"span_id") {
            Some("span_id")
        } else {
            None
        }
    }

    /// NAN-2265: plan the snapshot id-closure rewrite for an UNSTABLE command
    /// stage source, or `None` when the guards fail (callers then fall back to
    /// the single-scan window shape).
    ///
    /// Applicable when the prefix decomposes into `stage_0 … stage_j` all
    /// row-stable AND row-identity-preserving, followed by a non-empty run of
    /// pure row-subset selectors (`head` / `tail` / `sort N` / `sample`) —
    /// and the row-identity column still exists at the source. The attach
    /// then pins the selector output's ids ONCE (scalar-subquery cache: one
    /// evaluation per query, `ScalarSubqueriesCacheMiss = 1`) and swaps the
    /// unstable source for `stage_j WHERE id IN <pinned ids>` — a
    /// deterministic set every reference reads identically, so the bounded
    /// map/scalar attach applies to it unchanged.
    fn snapshot_refetch_plan(
        &self,
        prior_stages: &[QueryStage],
        base_is_deterministic: bool,
        available_columns: &Option<HashSet<String>>,
    ) -> Option<SnapshotRefetch> {
        if !base_is_deterministic || !matches!(prior_stages.first(), Some(QueryStage::Search(_))) {
            return None;
        }
        let sid = self.row_identity_column()?;
        // The id must still exist at the source (an include-mode `fields` /
        // `table` prunes it) and must be the physical row identity, not an
        // upstream `eval id=…` reassignment. Selectors neither prune nor
        // compute columns, so a check at the source covers the ancestor too.
        if self.is_upstream_computed_field(sid) {
            return None;
        }
        if let Some(cols) = available_columns {
            if !cols.contains(sid) {
                return None;
            }
        }
        // `stage_1..=stage_j` is the maximal contiguous prefix that is BOTH
        // row-stable (re-reading it yields the same rows) and row-identity
        // preserving (its rows still ARE base rows, one per id) — `stats` is
        // stable but emits id-less aggregate rows, `mvexpand` duplicates ids;
        // an id-filtered re-read of either cannot reproduce a sample.
        let mut j = 0usize;
        for (idx, stage) in prior_stages.iter().enumerate().skip(1) {
            match stage {
                QueryStage::Command(c)
                    if command_preserves_row_stability(c)
                        && command_preserves_row_identity(c, sid) =>
                {
                    j = idx
                }
                _ => break,
            }
        }
        // The remainder must be a non-empty run of pure row-subset selectors:
        // anything else (top/rare/timechart-limit output, join/append, a stage
        // sandwiched behind a selector) cannot be reproduced by an id-filtered
        // re-read of the ancestor.
        if j + 1 >= prior_stages.len() {
            return None;
        }
        for stage in &prior_stages[j + 1..] {
            match stage {
                QueryStage::Command(c) if command_is_row_subset_selector(c) => {}
                _ => return None,
            }
        }
        Some(SnapshotRefetch {
            ancestor: format!("stage_{}", j),
            sid,
        })
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

    /// Whether the active profile types `field` as numeric (Integer/Long/Float).
    /// Used by the value seam to pick the `json_tail_access_sql` extractor for a
    /// JSON-tail field: a numeric type emits the `Float64` subcolumn extractor
    /// (summable/averagable) instead of the default `String` one. UDM never
    /// resolves a numeric concept to a JSON path, so UDM callers stay
    /// byte-identical; this only re-types OCSF's unmapped-tail numerics
    /// (`risk_score`/`raw_risk_score`, NAN-1911). (NAN-1911)
    pub(crate) fn is_numeric_field(&self, field: &str) -> bool {
        self.profile.is_numeric_field(field)
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

    /// Whether `field_to_sql_expr` JSON-extracts `field` from the `metadata`
    /// column: `metadata_`-prefixed / `metadata.*` names, known metadata
    /// fields, and non-`ext.*` dotted paths (NAN-1644). The slim projection
    /// must pass the backing `metadata` column through for these — downstream
    /// stages re-derive `JSONExtract…(metadata, …)` per reference. Gated off
    /// for names the profile resolves natively (OCSF `event` tail JsonPath,
    /// spans/metrics `Map` attributes), which never read `metadata`.
    pub(crate) fn is_metadata_extracted_field(&self, field: &str) -> bool {
        if self.resolves_to_json_path(field) || self.resolves_to_map_key(field) {
            return false;
        }
        field.starts_with("metadata_")
            || field.starts_with("metadata.")
            || (field.contains('.') && !field.starts_with("ext."))
            || is_known_metadata_field(field)
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

    /// The column `bin` buckets/reads for a given user field token (NAN-1721 / O7).
    /// The default (`bin span=…`) and the time aliases (`bin _time` / `bin
    /// timestamp`) resolve to the active dataset's [`time_column`](Self::time_column)
    /// — `start_time` on spans, where a literal `timestamp` column does not exist —
    /// while an explicit non-time field is canonicalized through the profile
    /// (`duration` → `duration_ns`). Logs keep `timestamp` byte-identical: the free
    /// `normalize_field_name` maps `_time`→`timestamp` and leaves `timestamp` itself
    /// untouched, matching the pre-fix literal default.
    pub(crate) fn bin_field_name(&self, field: Option<&str>) -> String {
        match field {
            Some("_time") | None => self.time_column().to_string(),
            Some(f) => self.canonicalize_field(f).to_string(),
        }
    }

    /// The output column name `bin` projects for `cmd` (NAN-1721 / O7), mirroring
    /// the Bin generator's alias resolution exactly: an explicit `as <alias>`, else
    /// the canonicalized binned field (`bin_field_name`) when a field was given,
    /// else `time_bucket`. Registered in `upstream_computed_fields` so a downstream
    /// `by <alias>` references this real bucket column directly instead of — on
    /// spans — resolving the un-promoted name to an `attributes['<alias>']` Map
    /// subscript. `None` for non-bin commands.
    fn bin_output_alias(&self, cmd: &Command) -> Option<String> {
        match cmd {
            Command::Bin { field, alias, .. } => Some(match (alias, field.is_some()) {
                (Some(a), _) => a.clone(),
                (None, true) => self.bin_field_name(field.as_deref()),
                (None, false) => "time_bucket".to_string(),
            }),
            _ => None,
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

    /// Display expression for a field-values aggregation (NAN-2149).
    ///
    /// Field-values group on the value returned to the caller, rather than on the
    /// first physical column a semantic field happens to resolve to:
    ///
    /// - OCSF class-split UDM concepts (`user`, `process_name`, `src_host`, …)
    ///   use the same indexed unified column / value-pick fallback as filters and
    ///   `stats by`, so events from every OCSF class contribute.
    /// - A class-scoped enum-int (`event_type` / `activity_id`) displays its
    ///   manifest-declared sibling label column (`activity`), because the same ID
    ///   has different meanings in different classes.
    /// - A fixed enum-int (`severity_id`, `status_id`, …) is decoded with the
    ///   manifest label table, falling back to the raw ID for forward-compatible
    ///   values the current manifest does not know.
    ///
    /// UDM exposes neither class splits nor enum-int mappings, so this falls
    /// through to [`field_access_expr`](Self::field_access_expr) byte-for-byte.
    pub(crate) fn field_values_display_expr(&self, field: &str) -> String {
        let value_expr = self.filter_field_expr(field, "String");

        match self.profile.enum_int_mapping(field) {
            Some(crate::schema::EnumIntMapping::LabelColumn(sibling)) => {
                escape_identifier(sibling)
            }
            Some(crate::schema::EnumIntMapping::Values(labels)) => {
                // HashMap iteration is deliberately not observable in generated
                // SQL: sort by ID, then label, for stable snapshots/cache keys.
                let mut entries: Vec<(&str, i64)> = labels
                    .iter()
                    .map(|(label, id)| (label.as_str(), *id))
                    .collect();
                entries.sort_unstable_by(|(label_a, id_a), (label_b, id_b)| {
                    id_a.cmp(id_b).then_with(|| label_a.cmp(label_b))
                });
                let ids = entries
                    .iter()
                    .map(|(_, id)| id.to_string())
                    .collect::<Vec<_>>()
                    .join(", ");
                let display_labels = entries
                    .iter()
                    .map(|(label, _)| format!("'{}'", escape_string(label)))
                    .collect::<Vec<_>>()
                    .join(", ");
                format!(
                    "transform({value_expr}, [{ids}], [{display_labels}], toString({value_expr}))"
                )
            }
            None => value_expr,
        }
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
        let mut added = {
            let guard = self
                .upstream_computed_fields
                .read()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            field_analysis::upstream_computed_added_by_command(cmd, &guard)
        };
        // O7 (NAN-1721): `field_analysis` deliberately omits `bin` from the
        // computed set (its floored values can precede the window start — the
        // resolve_identity bound is handled separately by
        // `upstream_timestamp_rewritten`). But bin's OUTPUT alias is still a real
        // in-scope column, and a downstream `by <alias>` must reference it
        // directly. On spans an un-registered alias canonicalizes to the raw time
        // column (`by timestamp` → `start_time`, silently per-event) or resolves
        // to an `attributes['<alias>']` Map subscript — both silently wrong.
        // Registering it is byte-identical on logs (the alias already fell through
        // to a bare identifier there).
        if let Some(alias) = self.bin_output_alias(cmd) {
            added.insert(alias);
        }
        match self.upstream_computed_fields.write() {
            Ok(mut guard) => guard.extend(added),
            Err(poisoned) => poisoned.into_inner().extend(added),
        }
        if Self::command_rewrites_timestamp(cmd) {
            match self.upstream_timestamp_rewritten.write() {
                Ok(mut guard) => *guard = true,
                Err(poisoned) => *poisoned.into_inner() = true,
            }
        }
    }

    /// Whether `cmd` rewrites the `timestamp` column WITHOUT registering it in
    /// the upstream-computed set, so downstream row timestamps may no longer
    /// fall inside the query window (NAN-1638). Only two commands escape that
    /// set: `bin` in-place modification (`bin timestamp span=X` floors values
    /// up to one span before window start; bins are not value-computed
    /// registrations) and a `table … AS timestamp` re-alias (table aliases are
    /// projections, not registered computations). Every OTHER timestamp
    /// rewriter — eval/rename/rex captures/spath output/streamstats/stats
    /// aliases — registers `timestamp` via `note_upstream_computed`, and the
    /// resolve_identity bound checks `is_upstream_computed_field("timestamp")`
    /// alongside this flag. The bin conditions mirror the Bin arm's alias
    /// resolution exactly: an explicit `as timestamp` alias, or no alias with
    /// the binned field being `timestamp`/`_time` (in-place modification); a
    /// field-less `bin span=X` writes `time_bucket` and leaves `timestamp`
    /// intact.
    fn command_rewrites_timestamp(cmd: &Command) -> bool {
        match cmd {
            Command::Bin { field, alias, .. } => {
                alias.as_deref() == Some("timestamp")
                    || (alias.is_none()
                        && matches!(field.as_deref(), Some("timestamp") | Some("_time")))
            }
            Command::Table { fields } => fields
                .iter()
                .any(|f| f.alias.as_deref() == Some("timestamp")),
            _ => false,
        }
    }

    /// Whether an already-generated stage rewrote `timestamp` in place — the
    /// resolve_identity ASOF build-side bound must stay off then (NAN-1638).
    pub(crate) fn is_upstream_timestamp_rewritten(&self) -> bool {
        match self.upstream_timestamp_rewritten.read() {
            Ok(guard) => *guard,
            Err(poisoned) => **poisoned.get_ref(),
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
        // O45 (NAN-1733): the source-scope gate (`… AND source_type != "audit"`
        // for the legacy audit gate, `… AND source_type NOT IN (…)` for
        // NAN-1799 per-source RBAC deny sets — both injected by
        // `enforce_source_scope`/`enforce_source_type_exclusion`) is a
        // logs-domain concern — audit rows live only in the `logs` table and
        // per-source scoping is a logs-table access control. On the OTLP
        // spans/metrics datasets `source_type` has no column and resolves to a
        // per-row Map lookup, so the gate is pure cost and can hide rows a
        // tenant tagged with a denied `source_type` value.
        //
        // NAN-1794: run the strip for EVERY dataset, not just non-`Logs`. The
        // gate is now injected into subsearches too, and a subsearch can target
        // a different dataset than the outer query (`[dataset=spans …]` from a
        // logs query, `[dataset=logs …]` from a spans query), so the keep/strip
        // decision is per-scan — see `strip_injected_audit_gate`. On a pure-logs
        // query the walk is a structural no-op and the SQL stays byte-identical.
        let stripped_query = strip_injected_audit_gate(query, self.dataset);
        let query = &stripped_query;

        // Store time range for subsearch IN subquery generation
        // Use write_or_default to avoid panic on poisoned lock
        match self.generation_time_range.write() {
            Ok(mut guard) => *guard = Some(time_range.clone()),
            Err(poisoned) => *poisoned.into_inner() = Some(time_range.clone()),
        }
        // Fresh timestamp-rewrite tracking for this generation (NAN-1638).
        match self.upstream_timestamp_rewritten.write() {
            Ok(mut guard) => *guard = false,
            Err(poisoned) => *poisoned.into_inner() = false,
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
        ctx.unordered = options.unordered;

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
        // NAN-1798 P2: the risk dataset's base source is a derived 15-column
        // entity grain — the slim/table-view projections enumerate logs-shaped
        // columns that don't exist on it. `SELECT *` is both correct and cheap
        // at this grain (entity cardinality, not event volume).
        if matches!(self.dataset, otel::Dataset::Risk) {
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
        match self.upstream_timestamp_rewritten.write() {
            Ok(mut guard) => *guard = false,
            Err(poisoned) => *poisoned.into_inner() = false,
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
        let mut stages = self.collect_stages(query);

        if stages.is_empty() {
            return Err(SqlGenError::EmptyQuery);
        }

        // NAN-1657: count-companion regenerations (`ctx.unordered`) drop
        // pure-reorder stages (sort/reverse) that cannot change the row count.
        // An explicit `| sort` becomes its own CTE — a full sort barrier that
        // must consume the ENTIRE match set before a downstream `head N` emits
        // anything, so the count companion for `… | sort -ts | head 10` scanned
        // the full window (Saturn: 151M rows to compute a count that is ≤ 10).
        // With the sort gone, `search | head N` collapses to the flat fast path
        // below and the count's inner LIMIT genuinely early-terminates. Applied
        // only at this top-level entry (single call site) — subsearch/append
        // legs use their own generators and keep their sorts (WHICH rows they
        // emit feeds the outer query there).
        if ctx.unordered {
            drop_count_invariant_reorders(&mut stages);
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
        // Single query with ORDER BY and LIMIT together - much faster than CTE approach.
        // NAN-1635: unordered callers (companion count wraps) keep the user's
        // head LIMIT — it bounds the count — but drop the implicit ORDER BY,
        // which under that LIMIT would be a semantic top-N.
        let order_clause = if ctx.unordered {
            String::new()
        } else {
            format!("ORDER BY {} DESC ", ctx.time_column)
        };
        Ok(format!(
            "SELECT {} FROM {} WHERE {} AND ({}) {}LIMIT {} {}",
            select_clause,
            ctx.table_name,
            self.time_bound_predicate(&ctx.time_column, &ctx.time_range),
            where_clause,
            order_clause,
            limit,
            generate_settings(ctx.use_cache, selective, false),
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
    pub(crate) const DEFAULT_RESULT_LIMIT: usize = 1_000_000;

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
                // NAN-1635: companion wraps (histogram GROUP BY, count) are
                // order-insensitive — dropping the implicit ORDER BY here keeps
                // the base flat, like the raw-SQL time-range histogram.
                let order_clause = if ctx.unordered {
                    String::new()
                } else {
                    format!("ORDER BY {} DESC ", ctx.time_column)
                };
                Ok(format!(
                    "SELECT {} FROM {} WHERE {} AND ({}) {}{}{}",
                    select_clause,
                    ctx.table_name,
                    self.time_bound_predicate(&ctx.time_column, &ctx.time_range),
                    where_clause,
                    order_clause,
                    limit_clause,
                    generate_settings(ctx.use_cache, selective, false),
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
        // Check if downstream commands re-query ClickHouse themselves (asset/tree/
        // cloud/baseline), meaning the initial query is only for identifier
        // detection / small sample. In that case, push ctx.limit into the base CTE
        // to avoid unbounded scans.
        let has_requery_command = stages.iter().any(|s| {
            matches!(
                s,
                QueryStage::Command(Command::Asset { .. })
                    | QueryStage::Command(Command::Tree { .. })
                    | QueryStage::Command(Command::Cloud { .. })
                    | QueryStage::Command(Command::Baseline { .. })
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
                        "{} AS (\n  SELECT {} FROM {}\n  WHERE {}\n  AND ({}){}\n)",
                        cte_name,
                        select_clause,
                        ctx.table_name,
                        self.time_bound_predicate(&ctx.time_column, &ctx.time_range),
                        where_clause,
                        limit_clause,
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
                    // The sort-free dedup rewrite (commands.rs) scans its source
                    // CTE twice — only sound when that source is the deterministic
                    // base scan: stage_0, and no requery command (asset/tree/cloud)
                    // injected `ORDER BY … LIMIT` into it (a bounded top-N samples
                    // tie rows nondeterministically per scan).
                    let base_is_deterministic =
                        !has_requery_command && matches!(stages[0], QueryStage::Search(_));
                    // NAN-2265: the eventstats / anomaly map-scalar attach also
                    // references its source twice (once to build the constants,
                    // once to emit the rows they are attached to). It needs the
                    // weaker property — same row set per execution — which the
                    // whole prefix must satisfy, not just stage_0.
                    let rows_stable = base_is_deterministic
                        && stages[1..i].iter().all(|s| match s {
                            QueryStage::Search(_) => false,
                            QueryStage::Command(c) => command_preserves_row_stability(c),
                        });
                    // Unstable source: offer the snapshot-refetch escape hatch
                    // when the instability is only a trailing selector run —
                    // eventstats / numeric-anomaly then pin the subset once
                    // instead of re-buffering wide rows in a window.
                    let snapshot_refetch = if rows_stable {
                        None
                    } else {
                        self.snapshot_refetch_plan(
                            &stages[..i],
                            base_is_deterministic,
                            &ctx.available_columns,
                        )
                    };
                    let stability = SourceStability {
                        deterministic_base: i == 1 && base_is_deterministic,
                        rows_stable,
                        snapshot_refetch,
                    };
                    let cte = self.generate_command_cte(
                        &cte_name,
                        &prev_cte,
                        cmd,
                        ctx,
                        &stages[..i],
                        stability,
                    )?;
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
        // NAN-1635 (finding p12): the read-in-order toggle is NOT irrelevant
        // for CTE tails — CH 26.4's analyzer inlines the CTEs and pushes the
        // outer `ORDER BY timestamp DESC` down to the base ReadFromMergeTree,
        // so `optimize_read_in_order=1` forces sequential in-order-per-part
        // reads whenever a source_type equality pins the sort-key prefix
        // (Saturn: ~23% wall on a pinned-source_type + selective-eq hunt, and
        // 78.91k rows read on a zero-match probe vs 0 with the toggle off).
        // Mirror the single-stage paths: disable read-in-order when any Search
        // stage carries a selective indexed equality (`any` also covers
        // append-arm Search stages).
        let selective = stages.iter().any(|s| {
            matches!(s, QueryStage::Search(expr) if has_selective_indexed_eq(expr, self.profile.as_ref()))
        });
        let last_cte = format!("stage_{}", stages.len() - 1);
        let mut settings =
            generate_settings(ctx.use_cache, selective, has_non_timechart_aggregation);
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
        // NAN-2274: the analyzer evaluates the NAN-1642 group-agg map scalars
        // during analysis and folds the result into the plan as a literal map —
        // one entry per group key (230k on the incident query). On CH ≥26.4,
        // skip-index condition building (MergeTreeIndexConditionBloomFilter →
        // tryMatchJSONSubcolumnToIndex) effectively never terminates traversing
        // a condition tree carrying such a map, and planning never checks the
        // cancel flag — max_execution_time fires but is ignored, KILL QUERY is
        // ignored, and an HTTPHandler thread burns a full core until the server
        // is restarted (reproduced on 26.4.3 and 26.7.1). Skip indexes are pure
        // granule pruning — disabling them cannot change results — and these
        // pipelines filter on the (source_type, timestamp) primary key, which
        // this setting does not touch: the incident query went from
        // wedged-forever to 16s with identical output.
        if commands_advanced::emits_group_agg_map(&sql) {
            settings.push_str(", use_skip_indexes=0");
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
        // NAN-1635 (finding 3.6): apply the caller's result limit to the final
        // SELECT. Multi-stage SQL previously dropped `QueryOptions.limit`
        // entirely, so the documented safety bound vanished for every piped
        // query — a streamed high-cardinality `| stats count by col` ran
        // unbounded, and deployments with query_limits.xml turned the intended
        // graceful cap into a hard max_result_rows error. `ctx.limit == None`
        // keeps the executor-pagination contract (NAN-1410): the executor
        // injects/wraps its own LIMIT/OFFSET, so baking one here would
        // double-limit.
        let limit_clause = match ctx.limit {
            Some(limit) => format!("LIMIT {} ", limit),
            None => String::new(),
        };
        if last_stage_has_ordering || has_aggregate_or_projection || ctx.unordered {
            write!(
                sql,
                "\nSELECT {} FROM {} {}{}",
                select_list, last_cte, limit_clause, settings
            )
            .unwrap();
        } else {
            // NAN-1555: order by the active dataset's time column (`start_time` for
            // spans) — `timestamp` does not exist on `otel_spans`. Logs keep
            // `timestamp` (byte-identical).
            write!(
                sql,
                "\nSELECT {} FROM {} ORDER BY {} DESC {}{}",
                select_list, last_cte, self.time_column, limit_clause, settings
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
        // What re-executing `source_cte` is guaranteed to yield — see the dedup
        // survivor-id rewrite guards (NAN-1636) and the eventstats / anomaly
        // attach guard (NAN-2265).
        stability: SourceStability,
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

        let inner_sql = self.generate_command_sql_with_ctx(source_cte, cmd, ctx, stability)?;
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
        // NAN-1562: cross-dataset only when the subsearch targets a DIFFERENT
        // dataset than the outer query — `dataset=logs` from a logs query stays
        // byte-identical (no clone, no settings, same ctx).
        // O8 (NAN-1721): compare by DATASET IDENTITY, not `table_name` strings —
        // an OCSF/tenant-prefixed logs table (`ocsf_logs` != `"logs"`) is NOT a
        // different dataset, and the string form falsely flagged it cross-dataset
        // → re-pointed the sub at the wrong (`"logs"`) table.
        let cross_dataset = subsearch_dataset
            .map(|ds| ds != self.dataset)
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
        // O8 (NAN-1721): read the SUB generator's RESTORED table/time column, not
        // the literal `Dataset::table_name()`. For `dataset=logs` the sub generator
        // restored the tenant-aware logs table (`ocsf_logs`/tenant-prefixed) from
        // the captured `base_table`; the bare `"logs"` literal targets the wrong
        // (empty or legacy-UDM) table → silently zero correlated rows.
        let (sub_table, sub_time_col): (String, String) = if cross_dataset {
            (sub_gen.table_name.clone(), sub_gen.time_column.clone())
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
                    "    SELECT {} FROM {}\n    WHERE {}\n    AND ({})\n    LIMIT {}",
                    base_select,
                    ctx.table_name,
                    self.time_bound_predicate(&ctx.time_column, &ctx.time_range),
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
                        "SELECT {} FROM {} WHERE {} AND ({})",
                        base_select,
                        ctx.table_name,
                        self.time_bound_predicate(&ctx.time_column, &ctx.time_range),
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
                    // A subsearch stage source is an inline subquery, textually
                    // duplicated by any twice-scanning rewrite — so the same
                    // row-stability rule applies as for CTE stages (NAN-2265).
                    // The multi-stage subsearch base carries no LIMIT (the
                    // subsearch bound is applied to the finished body), so the
                    // prefix decides. `deterministic_base` stays false: this is
                    // never the base CTE scan the dedup rewrite requires.
                    let stability = SourceStability {
                        deterministic_base: false,
                        rows_stable: matches!(stages[0], QueryStage::Search(_))
                            && stages[1..i].iter().all(|s| match s {
                                QueryStage::Search(_) => false,
                                QueryStage::Command(c) => command_preserves_row_stability(c),
                            }),
                        // Subsearch stages are nested inline subqueries, not
                        // named CTEs — there is no ancestor CTE name for the
                        // snapshot-refetch to re-read, so an unstable subsearch
                        // prefix keeps the single-scan window fallback.
                        snapshot_refetch: None,
                    };
                    let cmd_sql = self.generate_command_sql_with_stability(&source, cmd, stability)?;
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
                let mut needs_metadata_tail = false;
                let mut field_exprs: Vec<String> = field_list
                    .iter()
                    .filter_map(|field| {
                        if let Some(unified) = self.class_split_column(field) {
                            // NAN-1337: a class-split concept (src_host / process_name /
                            // user / url) must project its INDEXED unified column
                            // (`<field>_unified`) — the SAME column the value/group/sort
                            // seam (`by_field_sql`) references in later stages — so a
                            // `stats by src_host` GROUP BY binds to it here. Projecting the
                            // class-split *primary* (`src_endpoint.hostname`) instead left
                            // the later `GROUP BY src_host_unified` with nothing to bind →
                            // CH Code 47. UDM never class-splits → `None` → byte-identical.
                            Some(escape_identifier(&unified))
                        } else if self.resolves_to_column(field) {
                            // Resolve to the PHYSICAL column (NAN-1248): under OCSF a
                            // UDM-semantic required field (`src_ip`) must project the
                            // promoted column (`"src_endpoint.ip"`), not a bare `src_ip`
                            // that ocsf_logs lacks — so a later stage that references the
                            // resolved column (`stats`/`timechart`/`top` GROUP BY) finds
                            // it in this stage's output. UDM byte-identical: for a UDM
                            // explicit column `field_access_expr` == `escape_identifier`.
                            Some(self.field_access_expr(field, "String"))
                        } else if self.is_metadata_extracted_field(field) {
                            // NAN-1644: a field `field_to_sql_expr` JSON-extracts from the
                            // `metadata` column (metadata_-prefixed, metadata.*, known
                            // metadata fields, non-ext dotted paths) — downstream stages
                            // re-derive `JSONExtract…(metadata, …)`, so the backing
                            // column must survive the slim projection (mirroring the OCSF
                            // `event` tail passthrough below). The previous ext-spill
                            // projection here emitted a junk `toString(ext.metadata_foo)`
                            // alias no stage ever bound.
                            needs_metadata_tail = true;
                            None
                        } else if self.resolves_to_json_path(field)
                            && self.is_numeric_field(field)
                        {
                            // NAN-1911: a numeric OCSF unmapped-tail field (`risk_score`)
                            // projects as a concrete `Float64` (the coalesce/accurateCastOrNull
                            // extractor), NOT `toString(...)`. The `toString` below exists
                            // only to keep a `Dynamic`-typed JSON value out of GROUP BY;
                            // `Float64` is already concrete, so it groups/sorts fine — and
                            // numerically, so `sort -risk_score` / `stats by risk_score` order
                            // by value rather than lexicographically. Matches the value seam
                            // (`field_to_sql_expr`) and the window-key seam (`by_field_sql`).
                            // UDM never resolves to JsonPath → byte-identical.
                            Some(format!(
                                "{} AS {}",
                                self.field_access_expr(field, "Float"),
                                escape_identifier(field)
                            ))
                        } else {
                            // Spill field — cast to String to avoid Dynamic type in
                            // GROUP BY. Profile-aware: UDM Unknown → `ext.{field}`
                            // (byte-identical); an OCSF tail path → native `event`
                            // subcolumn access (NAN-1426; the ''-defaulting multiIf
                            // string form, no longer whole-event JSONExtractString).
                            Some(format!(
                                "toString({}) AS {}",
                                self.field_access_expr(field, "String"),
                                escape_identifier(field)
                            ))
                        }
                    })
                    .collect();
                if needs_metadata_tail && !fields.contains("metadata") {
                    field_exprs.push("metadata".to_string());
                }

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
                let push_tail = |c: String, acc: &mut Vec<String>| {
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

    /// Generate SQL for a command (public API without context tracking).
    /// Callers here (subsearch nesting, prevalence re-embedding) hand an
    /// arbitrary — often `LIMIT`-bounded — subquery as `source` and cannot
    /// vouch for what re-executing it yields, so every source-scanned-twice
    /// rewrite stays off: dedup keeps the legacy single-scan `ORDER BY <keys>,
    /// <time> LIMIT 1 BY <keys>` shape (NAN-1636, corrected by NAN-2264) and
    /// eventstats / anomaly keep the single-scan window shape (NAN-2265).
    pub fn generate_command_sql(&self, source: &str, cmd: &Command) -> Result<String, SqlGenError> {
        self.generate_command_sql_with_stability(source, cmd, SourceStability::default())
    }

    /// [`Self::generate_command_sql`] for callers that CAN vouch for what
    /// re-executing `source` yields (the subsearch stage chain, NAN-2265).
    fn generate_command_sql_with_stability(
        &self,
        source: &str,
        cmd: &Command,
        stability: SourceStability,
    ) -> Result<String, SqlGenError> {
        let mut no_ctx: Option<HashSet<String>> = None;
        self.generate_command_sql_inner(
            source, cmd, &mut no_ctx, None, false, false, false, stability,
        )
    }

    fn generate_command_sql_with_ctx(
        &self,
        source: &str,
        cmd: &Command,
        ctx: &mut GeneratorContext,
        stability: SourceStability,
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
            stability,
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

/// NAN-1657: remove pure-reorder stages (`sort` / `reverse`) that cannot change
/// the pipeline's row count, for count-companion regenerations (`unordered`).
///
/// A reorder never changes HOW MANY rows flow — only WHICH rows survive a later
/// `head`/`tail` cut. That only matters to the count when a value-dependent
/// stage (where/stats/dedup/…) sits after such a cut: different surviving rows
/// then produce a different count. So a reorder at index `i` is droppable iff
/// every stage after `i` is itself count-safe under reordering:
/// - `sort` / `reverse` — reorders, no count effect;
/// - `sort N …` / `head` / `tail` — cap the count identically regardless of order;
/// - `table` / `fields` / `rename` — pure projections.
/// Any other downstream command keeps the reorder (conservative).
///
/// A limited sort (`sort N -field`, `limit: Some`) is a top-N — it CAPS the
/// count, so it is never dropped itself (only `limit: None` sorts are pure
/// reorders), but as a suffix member it is benign like `head`.
fn drop_count_invariant_reorders(stages: &mut Vec<QueryStage<'_>>) {
    fn reorder_benign(stage: &QueryStage<'_>) -> bool {
        matches!(
            stage,
            QueryStage::Command(
                Command::Sort { .. }
                    | Command::Reverse
                    | Command::Head { .. }
                    | Command::Tail { .. }
                    | Command::Table { .. }
                    | Command::Fields { .. }
                    | Command::Rename { .. }
            )
        )
    }

    let n = stages.len();
    let mut keep = vec![true; n];
    // Walk back to front: `suffix_benign` holds for stages strictly after `i`.
    let mut suffix_benign = true;
    for i in (0..n).rev() {
        if suffix_benign
            && matches!(
                stages[i],
                QueryStage::Command(Command::Sort { limit: None, .. } | Command::Reverse)
            )
        {
            keep[i] = false;
        }
        if !reorder_benign(&stages[i]) {
            suffix_benign = false;
        }
    }
    let mut keep_iter = keep.into_iter();
    stages.retain(|_| keep_iter.next().unwrap_or(true));
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
    /// Suppress the implicit trailing `ORDER BY <time> DESC` — companion
    /// queries wrap the SQL in order-insensitive aggregation (NAN-1635).
    unordered: bool,
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
            unordered: false,
            ext_fields: HashSet::new(),
            available_columns: None,
            has_prior_risk: false,
            single_resolve_identity: false,
            aggregated: false,
        }
    }
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod risk_dataset_tests;

/// NAN-1799 (per-source RBAC scoping) — OTLP strip coverage for the
/// generalized deny-set gate.
///
/// The legacy `{"audit"}` gate (`source_type != "audit"`) is pinned
/// end-to-end in `tests/spans_codegen.rs` (O45 / NAN-1733 / NAN-1794) and is
/// byte-identical after NAN-1799, so those tests keep guarding it. This
/// module exercises the SECOND recognized conjunct shape — the
/// `SearchExpr::InList { field: "source_type", negated: true, .. }` gate that
/// `enforce_source_scope` injects for every deny set other than exactly
/// `{"audit"}` — against `is_injected_audit_gate_filter` /
/// `strip_injected_audit_gate`, which are private to this module (hence the
/// inline `#[cfg(test)]` module rather than the sibling `tests.rs`).
#[cfg(test)]
mod source_scope_otel_strip_tests {
    use super::*;
    use crate::query::parse_query;
    use chrono::{TimeZone, Utc};
    use std::collections::BTreeSet;

    fn time_range() -> TimeRange {
        TimeRange {
            start: Utc.with_ymd_and_hms(2024, 1, 1, 0, 0, 0).unwrap(),
            end: Utc.with_ymd_and_hms(2024, 1, 2, 0, 0, 0).unwrap(),
        }
    }

    /// Reproduce the real scoped search path: `enforce_source_scope` rewrites
    /// the nPL text (injecting the deny-set gate at every scan), the service
    /// re-parses the rewritten text, and the generator runs over `dataset` —
    /// exactly the production flow, so the gate arrives through the parser's
    /// `in_list_filter` round-trip and not as a hand-built AST.
    fn scoped_sql(q: &str, deny: &[&str], dataset: otel::Dataset) -> String {
        let deny_set: BTreeSet<String> = deny.iter().map(|s| s.to_string()).collect();
        let enforced = crate::search::query_processing::enforce_source_scope(q, &deny_set)
            .unwrap_or_else(|e| panic!("enforce {q}: {e}"));
        ClickHouseSqlGenerator::new()
            .with_dataset(dataset)
            .generate(
                &parse_query(&enforced).unwrap_or_else(|e| panic!("parse {enforced}: {e}")),
                &time_range(),
            )
            .unwrap_or_else(|e| panic!("generate {enforced}: {e}"))
    }

    /// The multi-member gate renders on logs as
    /// `lower(source_type) NOT IN ('audit', 'insider')` (negated membership
    /// keeps the `lower(...)` form — no skip index prunes a negation).
    fn multi_gate_count(sql: &str) -> usize {
        sql.matches("NOT IN ('audit', 'insider')").count()
    }

    /// AST-level: the matcher recognizes BOTH injected conjunct shapes and
    /// nothing else.
    #[test]
    fn matcher_recognizes_both_gate_shapes() {
        // Legacy audit FieldFilter (NAN-704) — unchanged.
        assert!(is_injected_audit_gate_filter(&SearchExpr::FieldFilter {
            field: "source_type".to_string(),
            op: Comparator::Ne,
            value: Value::String("audit".to_string()),
        }));
        // NAN-1799 deny-set gate — negated IN-list on source_type.
        assert!(is_injected_audit_gate_filter(&SearchExpr::InList {
            field: "source_type".to_string(),
            values: vec![
                Value::String("audit".to_string()),
                Value::String("insider".to_string()),
            ],
            negated: true,
        }));
        // A POSITIVE in-list on source_type is a user filter, never the gate.
        assert!(!is_injected_audit_gate_filter(&SearchExpr::InList {
            field: "source_type".to_string(),
            values: vec![Value::String("audit".to_string())],
            negated: false,
        }));
        // Negated in-list on any other field is untouched.
        assert!(!is_injected_audit_gate_filter(&SearchExpr::InList {
            field: "user".to_string(),
            values: vec![Value::String("audit".to_string())],
            negated: true,
        }));
    }

    /// On spans there is no `source_type` column — a scoped user's NOT-IN gate
    /// would resolve to a per-row attributes-Map probe that hides any span a
    /// tenant tagged with a denied value. It must not survive into the SQL.
    #[test]
    fn spans_strip_the_multi_member_deny_gate() {
        for q in ["error", "* | stats count by span_kind"] {
            let sql = scoped_sql(q, &["audit", "insider"], otel::Dataset::Spans);
            assert!(
                !sql.contains("source_type"),
                "spans must not carry the deny-set gate for `{q}`: {sql}"
            );
            assert!(
                !sql.contains("'insider'"),
                "spans must not reference denied source_type values for `{q}`: {sql}"
            );
        }
    }

    /// A single-member NON-audit deny set also takes the NOT-IN form (only
    /// exactly `{"audit"}` keeps the legacy FieldFilter) — the strip must
    /// recognize it too.
    #[test]
    fn spans_strip_the_single_member_non_audit_gate() {
        let sql = scoped_sql("error", &["insider"], otel::Dataset::Spans);
        assert!(
            !sql.contains("source_type") && !sql.contains("'insider'"),
            "spans must strip the single-member NOT-IN gate: {sql}"
        );
    }

    /// The same gate MUST remain on the logs dataset — per-source scoping is
    /// enforced there, and stripping it would be the access-control bypass.
    #[test]
    fn logs_keep_the_multi_member_deny_gate() {
        for q in ["error", "* | stats count by src_ip"] {
            let sql = scoped_sql(q, &["audit", "insider"], otel::Dataset::Logs);
            assert_eq!(
                multi_gate_count(&sql),
                1,
                "logs must keep the deny-set gate for `{q}`: {sql}"
            );
            assert!(
                sql.contains("lower(source_type) NOT IN ('audit', 'insider')"),
                "logs gate must render as the lower() NOT-IN membership: {sql}"
            );
        }
    }

    /// A subsearch with no `dataset=` selector inherits the outer spans
    /// dataset, so it reads SPANS and its gate is stripped too (NAN-1794
    /// per-scan walk, NOT-IN shape).
    #[test]
    fn spans_subsearch_drops_the_multi_member_gate() {
        let sql = scoped_sql(
            r#"service_name="checkout" | append [search span_kind="server"]"#,
            &["audit", "insider"],
            otel::Dataset::Spans,
        );
        assert!(
            !sql.contains("source_type"),
            "inherited spans subsearch must not carry the deny-set gate: {sql}"
        );
    }

    /// `Dataset::Risk` (NAN-1798 P2) joins spans/metrics in the strip set:
    /// the risk dataset is a DERIVED aggregate over the findings stream — per
    /// the RBAC design (§3.4), entity/prevalence-style aggregates are a
    /// documented accepted-leak in v1, and the derived projection has no
    /// per-row `source_type` for the gate to bind to (it would resolve
    /// against the aggregate output, hiding whole entities instead of
    /// scoping rows). The gate must not survive into the risk SQL — while the
    /// risk source's OWN `source_type = 'findings'` predicate (positive
    /// equality, part of the derived subquery) stays intact.
    #[test]
    fn risk_dataset_strips_the_deny_gate() {
        for q in ["*", "entity_type=\"user\" | sort -decayed_score_24h"] {
            let sql = scoped_sql(q, &["audit", "insider"], otel::Dataset::Risk);
            assert_eq!(
                multi_gate_count(&sql),
                0,
                "risk dataset must strip the deny-set gate for `{q}`: {sql}"
            );
            assert!(
                !sql.contains("'insider'"),
                "risk dataset must not reference denied source_type values for `{q}`: {sql}"
            );
            assert!(
                sql.contains("source_type = 'findings'"),
                "the risk derived source must survive the strip intact for `{q}`: {sql}"
            );
        }
    }

    /// SECURITY, cross-dataset (NAN-1562): a spans query pulling a
    /// `[dataset=logs …]` subsearch reads the scoped table THERE — that scan
    /// must keep exactly its own NOT-IN gate while the outer spans scan keeps
    /// none. This is precisely the scan a "strip the gate on spans queries"
    /// shortcut would wrongly expose to a scoped user.
    #[test]
    fn cross_dataset_logs_subsearch_from_spans_keeps_the_multi_member_gate() {
        let sql = scoped_sql(
            r#"service_name="checkout" | join trace_id [dataset=logs search status=500]"#,
            &["audit", "insider"],
            otel::Dataset::Spans,
        );
        assert_eq!(
            multi_gate_count(&sql),
            1,
            "the logs subsearch of a spans query must keep exactly its own \
             deny-set gate (outer spans scan keeps none): {sql}"
        );
    }

    /// Same cross-dataset rule from the RISK side: a risk query joining a
    /// `[dataset=logs …]` subsearch reads the scoped logs table THERE — that
    /// scan keeps exactly its own gate while the outer risk scan keeps none.
    #[test]
    fn cross_dataset_logs_subsearch_from_risk_keeps_the_multi_member_gate() {
        let sql = scoped_sql(
            r#"entity_type="user" | join entity [dataset=logs search status=500 | eval entity=user]"#,
            &["audit", "insider"],
            otel::Dataset::Risk,
        );
        assert_eq!(
            multi_gate_count(&sql),
            1,
            "the logs subsearch of a risk query must keep exactly its own \
             deny-set gate (outer risk scan keeps none): {sql}"
        );
    }
}
