// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-5359 (Agent Lane P1): the ClickHouse objects every Agent Lane token
//! identity is built on. The migrator converges three things on every run:
//!
//! * the `agentlane` settings profile: read-only, time-indexed reads only,
//!   hard caps on time, result size, read volume, memory, threads and
//!   concurrency, pinned to the `agentlane` workload;
//! * the `agentlane_reader` role: `SELECT` on the event, signal, identity and
//!   source-attributed prevalence tables, and nothing else, plus row policies
//!   that hide nano's own audit events (`source_type = 'audit'`) from it;
//! * the `agentlane` workload under the `nano` fair root, below ingest,
//!   detections and interactive work, with a hard CPU-slot cap.
//!
//! This is inert config: it creates no user. The enterprise token control
//! plane (P2) creates one `agentlane_<id>` user per token with
//! `SETTINGS PROFILE 'agentlane'` and `DEFAULT ROLE agentlane_reader`.
//!
//! Topology mirrors [`ClickHouseMigrator::ensure_rawsql_row_policies`]: access
//! entities fan out `ON CLUSTER` on an operator-managed explicit cluster
//! (`local_directory` access storage on every node), workloads fan out on any
//! cluster (server-scoped, never propagated by a Replicated database), and a
//! single node gets plain DDL. Every statement is idempotent; re-running
//! converges on the same definition:
//!
//! * the profile is created if absent and then `ALTER`ed. Never `OR REPLACE`:
//!   that mints a new entity id and silently detaches every user that already
//!   references the profile (verified on 26.10);
//! * the role likewise (`OR REPLACE` would drop its grants and memberships);
//! * grants converge by diff against `system.grants`: missing grants are added
//!   and anything else held by the role is revoked. `GRANT ... WITH REPLACE
//!   OPTION` is not used because it requires the grantor to hold every
//!   privilege (including named-collection secrets) with grant option;
//! * row policies and the workload use `OR REPLACE`, which swaps them in place.
//!
//! Order matters on a first run: the audit-hiding RESTRICTIVE policy exists
//! before the PERMISSIVE baseline, and both exist before the role can read.

use std::collections::BTreeSet;

use super::{ClickHouseMigrateError, ClickHouseMigrator};
use crate::sql_hygiene::escape_sql_string;

/// The settings profile every Agent Lane identity runs under.
pub const AGENTLANE_PROFILE: &str = "agentlane";
/// The role every Agent Lane identity is granted.
pub const AGENTLANE_ROLE: &str = "agentlane_reader";
/// The scheduler workload Agent Lane queries run in.
pub const AGENTLANE_WORKLOAD: &str = "agentlane";
/// The fair root the workload hangs under (ClickHouse migration 189).
pub(super) const AGENTLANE_PARENT_WORKLOAD: &str = "nano";

/// Tables the role may read, with the column that names the event source.
/// Every granted table carries the audit-hiding policy on that column, so a
/// table can only be granted together with its policy column. The column is
/// picked per table, never templated: `identity_observations` keeps `source`.
///
/// Deliberately absent: `ingestion_errors` (raw rows, Dan 2026-11-13), the
/// dictionaries and every `READ ON` source, and the source-less prevalence
/// families (`*_prevalence_agg`, `*_prevalence_summary`). Those merge audit
/// contributions into their aggregate states, so no row policy can take them
/// out (the same reason `nanosiem_rawsql_noaudit` omits them). The
/// source-attributed `*_prevalence_source_summary` tables carry the same
/// verdicts per source and are policy-coverable.
pub(super) const AGENTLANE_TABLES: &[(&str, &str)] = &[
    ("ocsf_logs", "source_type"),
    ("logs", "source_type"),
    ("signals", "source_type"),
    ("identity_observations", "source"),
    ("hash_prevalence_source_summary", "source_type"),
    ("domain_prevalence_source_summary", "source_type"),
    ("ip_prevalence_source_summary", "source_type"),
];

/// Each table is granted under every name it exists as: the bare name (the
/// table itself, or the Distributed wrapper on a cluster), the shard-local
/// `_local` table and the legacy `_distributed` wrapper. Remote shards check
/// the hop identity's grants on `_local` (cluster `<secret>` mode, P0 #11).
pub(super) const TABLE_NAME_SUFFIXES: [&str; 3] = ["", "_local", "_distributed"];

/// Row policy names. One name covers every table it is attached to.
pub(super) const HIDE_AUDIT_POLICY: &str = "agentlane_hide_audit";
pub(super) const BASELINE_POLICY: &str = "agentlane_baseline";

/// Fixed caps (Dan 2026-11-13: 60 s, 100k rows, 64 MiB, 2 concurrent).
pub const MAX_EXECUTION_TIME_SECS: u64 = 60;
pub const MAX_RESULT_ROWS: u64 = 100_000;
pub const MAX_RESULT_BYTES: u64 = 64 * 1024 * 1024;
pub const MAX_MEMORY_USAGE_BYTES: u64 = 4 * 1024 * 1024 * 1024;
pub const MAX_THREADS: u64 = 4;
pub const MAX_CONCURRENT_QUERIES_PER_USER: u64 = 2;
/// Largest SQL text a caller may send (1 MiB; ClickHouse's default is 256 KiB).
pub const MAX_QUERY_SIZE_BYTES: u64 = 1024 * 1024;

/// Read caps per server. `force_index_by_date` only forces the time column to
/// be used, not bounded (`timestamp > 0` passes), so these are what bound a
/// scan. Defaults cover several days of a default 50-100 GB/day install.
pub const DEFAULT_MAX_ROWS_TO_READ: u64 = 500_000_000;
pub const DEFAULT_MAX_BYTES_TO_READ: u64 = 50 * 1024 * 1024 * 1024;
/// Accepted ranges. Zero would mean "unlimited" to ClickHouse, so the floor is
/// what keeps a misconfiguration from removing the bound.
pub(super) const MIN_MAX_ROWS_TO_READ: u64 = 1_000_000;
pub(super) const MAX_MAX_ROWS_TO_READ: u64 = 1_000_000_000_000;
pub(super) const MIN_MAX_BYTES_TO_READ: u64 = 1024 * 1024 * 1024;
pub(super) const MAX_MAX_BYTES_TO_READ: u64 = 1024 * 1024 * 1024 * 1024 * 1024;

pub const MAX_ROWS_TO_READ_ENV: &str = "NANO_AGENTLANE_MAX_ROWS_TO_READ";
pub const MAX_BYTES_TO_READ_ENV: &str = "NANO_AGENTLANE_MAX_BYTES_TO_READ";

/// CPU-slot cap of the `agentlane` workload, per server. Raise for
/// hunt-heavy installs. P6 (NAN-5364, 2-shard 6-CPU rig, 16 agents) at the
/// default of 2: nano is unaffected (ingest flush p95 -8.9%, detection lag
/// p95 +9.4%, analyst p50/p95 within 3%), but agents get 0.62 queries/s in
/// total versus 19.7 on plain ClickHouse (NAN-4664), and 27% of hunts time
/// out at 60 s. Raising it trades detection and analyst latency for agent
/// throughput.
pub const DEFAULT_MAX_CONCURRENT_THREADS: u64 = 2;
pub(super) const MIN_MAX_CONCURRENT_THREADS: u64 = 1;
/// A sane ceiling: well above any node's core count we ship sizing for, and
/// low enough that a typo (e.g. 4000) is refused rather than handing agents
/// the whole server.
pub(super) const MAX_MAX_CONCURRENT_THREADS: u64 = 256;
pub const MAX_CONCURRENT_THREADS_ENV: &str = "NANO_AGENTLANE_MAX_CONCURRENT_THREADS";

/// Memory cap of the whole `agentlane` workload, per server (ClickHouse
/// `max_memory` on the workload, enforced through the `memory` MEMORY
/// RESERVATION resource). Without it, memory across tokens is unbounded: 16
/// tokens x 2 queries x 4 GiB could push the server into OOM kills of ingest
/// or detection queries. When the workload is full, ClickHouse evicts (kills,
/// Code 776/777) its largest Agent Lane query; other workloads are untouched.
///
/// Unset: a quarter of the server's EFFECTIVE `max_server_memory_usage`
/// (`getServerSetting`, which follows the cgroup / install.sh
/// `CLICKHOUSE_MEM_LIMIT` sizing), so three quarters stay for ingest,
/// materialized views, detections and analysts. Read on the node the
/// migrator connects to and applied to every node (nodes in a tier are sized
/// alike). Floor 512 MiB; when the limit cannot be read, 4 GiB (one query's
/// own cap).
pub const WORKLOAD_MAX_MEMORY_ENV: &str = "NANO_AGENTLANE_WORKLOAD_MAX_MEMORY";

/// Memory budget per token, per server, shared by that token's concurrent
/// queries (`max_memory_usage_for_user`, CONST). Without it, one token's two
/// queries could each stay under the 4 GiB per-query cap yet together exhaust
/// the SERVER-WIDE limit (P6: Code 241 "(total) memory limit exceeded"),
/// failing ingest and detection allocations at that moment.
///
/// This limit is checked synchronously at every allocation, unlike the
/// workload `max_memory`, which evicts after the fact and can lag one large
/// allocation (a 1 GiB `groupArray` chunk reached the server limit on a
/// 2.4 GiB node before the eviction, lane `agentlane-lockdown`). So it is the
/// guard that keeps a token off the server limit.
///
/// Unset: the per-query cap (4 GiB), lowered to a quarter of the server's
/// effective memory limit on smaller nodes (so a 4 GB Compose box gives a
/// token ~800 MiB, never more than the whole server), floor 256 MiB; 4 GiB
/// when the limit cannot be read. The per-query `max_memory_usage` stays
/// 4 GiB; the smaller of the two wins. 0 would mean unlimited and is refused.
pub const MAX_MEMORY_PER_TOKEN_ENV: &str = "NANO_AGENTLANE_MAX_MEMORY_PER_TOKEN";
pub const DEFAULT_MAX_MEMORY_PER_TOKEN: u64 = MAX_MEMORY_USAGE_BYTES;
pub(super) const MIN_MAX_MEMORY_PER_TOKEN: u64 = 256 * 1024 * 1024;
pub(super) const MAX_MAX_MEMORY_PER_TOKEN: u64 = 1024 * 1024 * 1024 * 1024;
pub(super) const WORKLOAD_MEMORY_SERVER_FRACTION_DIVISOR: u64 = 4;
pub(super) const MIN_DERIVED_WORKLOAD_MAX_MEMORY: u64 = 512 * 1024 * 1024;
pub(super) const FALLBACK_WORKLOAD_MAX_MEMORY: u64 = 4 * 1024 * 1024 * 1024;
pub(super) const MIN_WORKLOAD_MAX_MEMORY: u64 = 256 * 1024 * 1024;
pub(super) const MAX_WORKLOAD_MAX_MEMORY: u64 = 1024 * 1024 * 1024 * 1024;

/// No workload `max_concurrent_queries`. Shard hops inherit
/// `workload = agentlane` and take a query slot on the REMOTE node, so two
/// tokens initiating cross-shard queries on two nodes each hold their own
/// node's slot and wait for the other's: a distributed deadlock that hung for
/// ~300 s (`receive_timeout`) past `max_execution_time` on 26.10.3.7, in both
/// hop modes, at any slot count. Per-token concurrency is
/// `max_concurrent_queries_for_user` (CONST), which refuses with 202 instead
/// of waiting. The QUERY resource that made the workload limit effective is
/// dropped on existing installs ([`QUERY_RESOURCE`]).
///
/// The MEMORY RESERVATION scheduler resource makes the workload `max_memory`
/// effective (inert until it exists, verified on 26.10.3.7). Server-wide like
/// migration 189's `cpu`; workloads without `max_memory` (ingest, default,
/// interactive, background) are not limited by it.
pub(super) const MEMORY_RESOURCE: &str = "memory";
/// Created by an earlier build of this step for the removed workload
/// `max_concurrent_queries`; nothing else in nano uses it.
pub(super) const QUERY_RESOURCE: &str = "query";

/// Overcommit victim selection (`memory_overcommit_ratio_denominator` and
/// `_for_user`, CONST). When the SERVER-wide memory limit is reached,
/// ClickHouse's overcommit tracker kills the running query with the highest
/// `memory_usage / denominator` and lets the others wait for the freed memory
/// (`memory_usage_overcommit_max_wait_microseconds`, 5 s by default on 26.10
/// and not overridden in nano's profiles). With 1 MiB here versus the 1 GiB
/// default for every other profile, an Agent Lane query is chosen first, so
/// ingest, detections and analysts normally wait and then succeed. 0 would
/// disable the tracker for the query, hence CONST.
///
/// NOT a guarantee on 26.10.3.7: an allocation that trips the RSS-based
/// server check ("attempt to allocate chunk of 0.00 B") fails without any
/// victim selection. With the per-token and workload caps lifted on a
/// 2.4 GiB node, an ingest INSERT still failed that way in 1 of 8 rounds
/// (lane `agentlane-lockdown`, evidence mode). The per-token budget is the
/// guard that is checked before allocating; the cross-token bound is
/// pending a lead decision.
pub const OVERCOMMIT_RATIO_DENOMINATOR: u64 = 1024 * 1024;

/// Settings an Agent Lane caller may set despite `readonly = 1`: output
/// formatting and response encoding only. `format_schema` and
/// `output_format_schema` (file paths) are deliberately absent.
pub(super) const CHANGEABLE_OUTPUT_SETTINGS: &[&str] = &[
    "log_comment",
    "session_timezone",
    "default_format",
    "date_time_output_format",
    "output_format_json_quote_64bit_integers",
    "output_format_json_named_tuples_as_objects",
    "enable_http_compression",
];

/// The per-install Agent Lane settings. Everything else is fixed.
///
/// Every limit here is PER SERVER: behind a load balancer over N nodes, or on
/// a cluster where each node runs its own shard of a query, a token's
/// effective totals multiply by N (e.g. its 2 concurrent queries become
/// 2 x N).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AgentlaneSettings {
    pub max_rows_to_read: u64,
    pub max_bytes_to_read: u64,
    pub max_concurrent_threads: u64,
    /// `None`: derived from the server memory limit at migrate time.
    pub max_memory_per_token: Option<u64>,
    /// `None`: derived from the server memory limit at migrate time.
    pub workload_max_memory: Option<u64>,
}

impl Default for AgentlaneSettings {
    fn default() -> Self {
        Self {
            max_rows_to_read: DEFAULT_MAX_ROWS_TO_READ,
            max_bytes_to_read: DEFAULT_MAX_BYTES_TO_READ,
            max_concurrent_threads: DEFAULT_MAX_CONCURRENT_THREADS,
            max_memory_per_token: None,
            workload_max_memory: None,
        }
    }
}

/// The raw `NANO_AGENTLANE_*` values, one field per variable.
#[derive(Debug, Clone, Copy, Default)]
pub struct AgentlaneEnv<'a> {
    pub max_rows_to_read: Option<&'a str>,
    pub max_bytes_to_read: Option<&'a str>,
    pub max_concurrent_threads: Option<&'a str>,
    pub max_memory_per_token: Option<&'a str>,
    pub workload_max_memory: Option<&'a str>,
}

/// Settings from `NANO_AGENTLANE_MAX_ROWS_TO_READ`,
/// `NANO_AGENTLANE_MAX_BYTES_TO_READ`, `NANO_AGENTLANE_MAX_CONCURRENT_THREADS`,
/// `NANO_AGENTLANE_MAX_MEMORY_PER_TOKEN` and `NANO_AGENTLANE_WORKLOAD_MAX_MEMORY`.
/// Unset or empty is the
/// default; a value that is not a whole number in range is an error (never
/// silently unlimited: 0 means "no limit" to ClickHouse for every one).
pub fn agentlane_settings_from_env(
    env: AgentlaneEnv<'_>,
) -> Result<AgentlaneSettings, ClickHouseMigrateError> {
    let AgentlaneEnv {
        max_rows_to_read,
        max_bytes_to_read,
        max_concurrent_threads,
        max_memory_per_token,
        workload_max_memory,
    } = env;
    let defaults = AgentlaneSettings::default();
    Ok(AgentlaneSettings {
        max_rows_to_read: parse_cap(
            MAX_ROWS_TO_READ_ENV,
            max_rows_to_read,
            defaults.max_rows_to_read,
            MIN_MAX_ROWS_TO_READ,
            MAX_MAX_ROWS_TO_READ,
        )?,
        max_bytes_to_read: parse_cap(
            MAX_BYTES_TO_READ_ENV,
            max_bytes_to_read,
            defaults.max_bytes_to_read,
            MIN_MAX_BYTES_TO_READ,
            MAX_MAX_BYTES_TO_READ,
        )?,
        max_concurrent_threads: parse_cap(
            MAX_CONCURRENT_THREADS_ENV,
            max_concurrent_threads,
            defaults.max_concurrent_threads,
            MIN_MAX_CONCURRENT_THREADS,
            MAX_MAX_CONCURRENT_THREADS,
        )?,
        max_memory_per_token: parse_optional_cap(
            MAX_MEMORY_PER_TOKEN_ENV,
            max_memory_per_token,
            MIN_MAX_MEMORY_PER_TOKEN,
            MAX_MAX_MEMORY_PER_TOKEN,
        )?,
        workload_max_memory: parse_optional_cap(
            WORKLOAD_MAX_MEMORY_ENV,
            workload_max_memory,
            MIN_WORKLOAD_MAX_MEMORY,
            MAX_WORKLOAD_MAX_MEMORY,
        )?,
    })
}

/// [`parse_cap`] for a setting whose unset default is derived at migrate time.
fn parse_optional_cap(
    name: &str,
    value: Option<&str>,
    min: u64,
    max: u64,
) -> Result<Option<u64>, ClickHouseMigrateError> {
    match value.map(str::trim).filter(|v| !v.is_empty()) {
        None => Ok(None),
        Some(raw) => parse_cap(name, Some(raw), 0, min, max).map(Some),
    }
}

/// The per-token budget when `NANO_AGENTLANE_MAX_MEMORY_PER_TOKEN` is unset:
/// the 4 GiB per-query cap, or a quarter of the server limit when that is
/// smaller (floor 256 MiB); 4 GiB when the limit is unknown (0).
pub(super) fn derived_max_memory_per_token(server_memory_limit_bytes: u64) -> u64 {
    if server_memory_limit_bytes == 0 {
        return DEFAULT_MAX_MEMORY_PER_TOKEN;
    }
    (server_memory_limit_bytes / WORKLOAD_MEMORY_SERVER_FRACTION_DIVISOR)
        .clamp(MIN_MAX_MEMORY_PER_TOKEN, DEFAULT_MAX_MEMORY_PER_TOKEN)
}

/// The workload memory cap when `NANO_AGENTLANE_WORKLOAD_MAX_MEMORY` is
/// unset: a quarter of the effective server limit, at least 512 MiB; 4 GiB
/// when the limit is unknown (0).
pub(super) fn derived_workload_max_memory(server_memory_limit_bytes: u64) -> u64 {
    if server_memory_limit_bytes == 0 {
        return FALLBACK_WORKLOAD_MAX_MEMORY;
    }
    (server_memory_limit_bytes / WORKLOAD_MEMORY_SERVER_FRACTION_DIVISOR)
        .max(MIN_DERIVED_WORKLOAD_MAX_MEMORY)
}

fn parse_cap(
    name: &str,
    value: Option<&str>,
    default: u64,
    min: u64,
    max: u64,
) -> Result<u64, ClickHouseMigrateError> {
    let Some(raw) = value.map(str::trim).filter(|v| !v.is_empty()) else {
        return Ok(default);
    };
    match raw.parse::<u64>() {
        Ok(v) if (min..=max).contains(&v) => Ok(v),
        _ => Err(ClickHouseMigrateError::ClickHouse(format!(
            "{name} must be a whole number from {min} to {max} (got '{raw}')"
        ))),
    }
}

/// The `SETTINGS` list of the `agentlane` profile.
///
/// `readonly = 1 CONST` already refuses every other setting change (SET,
/// SETTINGS clause, HTTP parameters); the CONST / MAX constraints restate each
/// cap so a future readonly change cannot widen them. `CHANGEABLE_IN_READONLY`
/// with a `MAX` lets a caller only lower the time and row caps.
///
/// `http_wait_end_of_query` + `http_response_buffer_size` (P0 #3): without
/// them a result that overflows `max_result_rows` streams HTTP 200 with partial
/// rows and an in-body exception; with them the overflow is a clean HTTP 500.
/// The buffer is bounded by `max_result_bytes`.
///
/// `serialize_query_plan = 0 CONST`: a shipped query plan is not filtered by
/// the underlying-table row policy (26.10 error text), so it stays off.
///
/// 0 means "no limit" for every cap here. `max_execution_time` carries
/// `MIN 1` (Codex FIX FIRST: `SETTINGS max_execution_time = 0` used to lift
/// the 60 s cap); every non-changeable cap is CONST.
///
/// `max_result_rows` deliberately has NO `MIN`: for a subquery or remote
/// stage ClickHouse resets it to 0 on the shard hop, and the shard CLAMPS it
/// to the profile's constraints, so `MIN 1` made every multi-row
/// `FROM (subquery)`, `IN`, `GLOBAL IN` and `GLOBAL JOIN` across
/// `_distributed` fail with 396 once a shard returned two rows (P5). A caller
/// can therefore lower it to 0 (no row cap), but the result stays bounded by
/// `max_result_bytes` (64 MiB, CONST) with `result_overflow_mode = 'throw'`
/// (CONST), and it can never be raised above 100k.
///
/// Known and accepted: on a `<secret>` cluster (the hop runs as the token) the
/// shard also enforces the 64 MiB `max_result_bytes` on its stream to the
/// initiator, so a subquery that pulls more than 64 MiB from one shard is
/// refused (396) even if the final result is small. The value reaches the
/// shard as the initiator's own setting, so `MAX` instead of CONST does not
/// change it (verified). Every other constraint was checked across shard hops
/// (lane `agentlane-lockdown`, split and secret): `max_execution_time`
/// reaches the shard unchanged, and the CONST read, memory and thread caps
/// do not break multi-row subqueries or slow shard stages. `timeout_overflow_mode` is
/// pinned to `throw` so a timeout can never return a silent partial result,
/// and `max_query_size` is pinned so a (decompressed) request body cannot
/// grow the parser's input. `enable_http_compression` only selects the
/// response encoding: it is applied after the result and buffer caps, so it
/// cannot lift a limit.
///
/// `distributed_product_mode = 'global' CONST`: the server default profile sets
/// `allow`, under which a plain `IN` / `JOIN` over two Distributed tables runs
/// double-distributed (every shard re-runs the subquery cluster-wide, and on
/// `<secret>` clusters those hops count against the token's two concurrent
/// queries). `global` rewrites it to `GLOBAL IN` / `GLOBAL JOIN`: the subquery
/// runs once on the initiator and ships to the shards as a temporary table.
pub(super) fn profile_settings_sql(caps: &AgentlaneSettings) -> String {
    let mut parts: Vec<String> = vec![
        "readonly = 1 CONST".into(),
        "allow_ddl = 0 CONST".into(),
        "allow_introspection_functions = 0 CONST".into(),
        "force_index_by_date = 1 CONST".into(),
        "skip_unavailable_shards = 0 CONST".into(),
        "serialize_query_plan = 0 CONST".into(),
        "distributed_product_mode = 'global' CONST".into(),
        format!("workload = '{AGENTLANE_WORKLOAD}' CONST"),
        format!(
            "max_execution_time = {MAX_EXECUTION_TIME_SECS} MIN 1 MAX {MAX_EXECUTION_TIME_SECS} \
             CHANGEABLE_IN_READONLY"
        ),
        format!(
            "max_result_rows = {MAX_RESULT_ROWS} MAX {MAX_RESULT_ROWS} CHANGEABLE_IN_READONLY"
        ),
        "timeout_overflow_mode = 'throw' CONST".into(),
        format!("max_result_bytes = {MAX_RESULT_BYTES} CONST"),
        "result_overflow_mode = 'throw' CONST".into(),
        "read_overflow_mode = 'throw' CONST".into(),
        format!("max_rows_to_read = {} CONST", caps.max_rows_to_read),
        format!("max_bytes_to_read = {} CONST", caps.max_bytes_to_read),
        format!("max_memory_usage = {MAX_MEMORY_USAGE_BYTES} CONST"),
        format!("memory_overcommit_ratio_denominator = {OVERCOMMIT_RATIO_DENOMINATOR} CONST"),
        format!("memory_overcommit_ratio_denominator_for_user = {OVERCOMMIT_RATIO_DENOMINATOR} CONST"),
        format!(
            "max_memory_usage_for_user = {} CONST",
            caps.max_memory_per_token.unwrap_or(DEFAULT_MAX_MEMORY_PER_TOKEN)
        ),
        format!("max_threads = {MAX_THREADS} CONST"),
        format!("max_query_size = {MAX_QUERY_SIZE_BYTES} CONST"),
        format!("max_concurrent_queries_for_user = {MAX_CONCURRENT_QUERIES_PER_USER} CONST"),
        "http_wait_end_of_query = 1 CONST".into(),
        format!("http_response_buffer_size = {MAX_RESULT_BYTES} CONST"),
    ];
    parts.extend(
        CHANGEABLE_OUTPUT_SETTINGS
            .iter()
            .map(|name| format!("{name} CHANGEABLE_IN_READONLY")),
    );
    parts.join(", ")
}

/// Create-if-absent, then converge with `ALTER` (which replaces the whole
/// settings list and keeps the entity id users reference).
pub(super) fn profile_statements(on_cluster: &str, caps: &AgentlaneSettings) -> [String; 2] {
    let settings = profile_settings_sql(caps);
    [
        format!("CREATE SETTINGS PROFILE IF NOT EXISTS {AGENTLANE_PROFILE}{on_cluster} SETTINGS {settings}"),
        format!("ALTER SETTINGS PROFILE {AGENTLANE_PROFILE}{on_cluster} SETTINGS {settings}"),
    ]
}

/// The workload: lowest weight, a lower priority than every sibling (lower
/// value = served first; the siblings use the default 0), and a hard thread
/// cap (per install, [`DEFAULT_MAX_CONCURRENT_THREADS`]). P0 #5 verified
/// `priority` creates a real priority node under the fair root on 26.10.
/// `OR REPLACE` swaps the scheduler node in place (migration 198): running
/// queries keep running, and users reference the workload by name through
/// the profile, so nothing detaches.
///
/// `max_memory` bounds the whole workload per server (see
/// [`WORKLOAD_MAX_MEMORY_ENV`]); deliberately no `max_concurrent_queries`
/// (distributed deadlock, see [`QUERY_RESOURCE`]). The `OR REPLACE` also
/// strips `max_concurrent_queries` from a workload an earlier build created.
pub(super) fn workload_statement(
    workload_on_cluster: &str,
    max_concurrent_threads: u64,
    max_memory: u64,
) -> String {
    format!(
        "CREATE OR REPLACE WORKLOAD {AGENTLANE_WORKLOAD}{workload_on_cluster} \
         IN {AGENTLANE_PARENT_WORKLOAD} \
         SETTINGS weight = 1, priority = 10, max_concurrent_threads = {max_concurrent_threads}, \
         max_memory = {max_memory}"
    )
}

/// Run after [`workload_statement`]: create the MEMORY RESERVATION resource
/// (until it exists the workload `max_memory` is inert, so there is no
/// half-applied window that could block a query) and drop the QUERY resource
/// an earlier build created, now that no workload limits queries.
pub(super) fn resource_statements(workload_on_cluster: &str) -> [String; 2] {
    [
        format!(
            "CREATE RESOURCE IF NOT EXISTS {MEMORY_RESOURCE}{workload_on_cluster} (MEMORY RESERVATION)"
        ),
        format!("DROP RESOURCE IF EXISTS {QUERY_RESOURCE}{workload_on_cluster}"),
    ]
}

/// The role, carrying the profile too: an identity that holds the role runs
/// under the caps even if its own user definition were to miss the profile.
pub(super) fn role_statements(on_cluster: &str) -> [String; 2] {
    [
        format!(
            "CREATE ROLE IF NOT EXISTS {AGENTLANE_ROLE}{on_cluster} \
             SETTINGS PROFILE '{AGENTLANE_PROFILE}'"
        ),
        format!("ALTER ROLE {AGENTLANE_ROLE}{on_cluster} SETTINGS PROFILE '{AGENTLANE_PROFILE}'"),
    ]
}

/// One `system.tables` row for a candidate table name.
#[derive(Debug, Clone, PartialEq, Eq, clickhouse::Row, serde::Deserialize)]
pub(super) struct ExistingTable {
    pub name: String,
    pub engine: String,
}

/// What the role is granted and where its policies attach.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(super) struct AgentlaneObjects {
    /// Every existing name of every allowed table, granted `SELECT`.
    pub grant_tables: BTreeSet<String>,
    /// Physical (non-Distributed) tables with their source column. Policies
    /// attach to the data-holding table, never the Distributed wrapper:
    /// ClickHouse refuses a wrapper policy it cannot push down (26.10,
    /// ILLEGAL_PREWHERE), and an underlying-table policy is honored on every
    /// shard in both hop modes (`<secret>` and role-split `<user>`).
    pub policy_tables: Vec<(String, &'static str)>,
}

/// Every name the allowed tables could exist under.
pub(super) fn candidate_table_names() -> Vec<String> {
    AGENTLANE_TABLES
        .iter()
        .flat_map(|(table, _)| TABLE_NAME_SUFFIXES.iter().map(move |s| format!("{table}{s}")))
        .collect()
}

/// Resolve grants and policy targets from what exists. A table absent under
/// every name (UDM `logs` on an OCSF install) gets neither.
pub(super) fn plan_objects(existing: &[ExistingTable]) -> AgentlaneObjects {
    let mut objects = AgentlaneObjects::default();
    for (table, column) in AGENTLANE_TABLES {
        for suffix in TABLE_NAME_SUFFIXES {
            let name = format!("{table}{suffix}");
            let Some(found) = existing.iter().find(|t| t.name == name) else {
                continue;
            };
            objects.grant_tables.insert(name.clone());
            if found.engine != "Distributed" {
                objects.policy_tables.push((name, column));
            }
        }
    }
    objects
}

/// Row policies: per source column, one RESTRICTIVE `lower(col) != 'audit'`
/// over every physical table using that column, then one PERMISSIVE `USING 1`
/// baseline over all of them. RESTRICTIVE first, so a first run never has a
/// moment where the baseline exists without the audit filter. ClickHouse ANDs
/// RESTRICTIVE policies with all access, so no later PERMISSIVE policy on the
/// same table can widen it.
pub(super) fn policy_statements(
    database: &str,
    on_cluster: &str,
    objects: &AgentlaneObjects,
) -> Vec<String> {
    if objects.policy_tables.is_empty() {
        return Vec::new();
    }
    let qualified = |tables: Vec<&String>| {
        tables
            .into_iter()
            .map(|t| format!("{database}.{t}"))
            .collect::<Vec<_>>()
            .join(", ")
    };
    let columns: BTreeSet<&str> = objects.policy_tables.iter().map(|(_, c)| *c).collect();
    let mut out = Vec::new();
    for column in columns {
        let tables = objects
            .policy_tables
            .iter()
            .filter(|(_, c)| *c == column)
            .map(|(t, _)| t)
            .collect();
        out.push(format!(
            "CREATE ROW POLICY OR REPLACE {HIDE_AUDIT_POLICY}{on_cluster} ON {tables} \
             USING lower({column}) != 'audit' AS RESTRICTIVE TO {AGENTLANE_ROLE}",
            tables = qualified(tables),
        ));
    }
    out.push(format!(
        "CREATE ROW POLICY OR REPLACE {BASELINE_POLICY}{on_cluster} ON {tables} \
         USING 1 AS PERMISSIVE TO {AGENTLANE_ROLE}",
        tables = qualified(objects.policy_tables.iter().map(|(t, _)| t).collect()),
    ));
    out
}

/// One `GRANT SELECT` statement covering every allowed table name.
pub(super) fn grant_statement(
    database: &str,
    on_cluster: &str,
    objects: &AgentlaneObjects,
) -> Option<String> {
    if objects.grant_tables.is_empty() {
        return None;
    }
    let privileges = objects
        .grant_tables
        .iter()
        .map(|t| format!("SELECT ON {database}.{t}"))
        .collect::<Vec<_>>()
        .join(", ");
    Some(format!("GRANT{on_cluster} {privileges} TO {AGENTLANE_ROLE}"))
}

/// One `system.grants` row held by the role.
#[derive(Debug, Clone, PartialEq, Eq, clickhouse::Row, serde::Deserialize)]
pub(super) struct ObservedGrant {
    pub access_type: String,
    pub database: Option<String>,
    pub table: Option<String>,
    pub column: Option<String>,
    pub is_partial_revoke: u8,
    pub grant_option: u8,
    pub is_wildcard: u8,
}

pub(super) const OBSERVED_GRANT_COLUMNS: &str = "toString(access_type) AS access_type, database, \
     `table`, `column`, toUInt8(is_partial_revoke) AS is_partial_revoke, \
     toUInt8(grant_option) AS grant_option, toUInt8(is_wildcard) AS is_wildcard";

/// `REVOKE` statements for everything the role holds beyond the desired
/// `SELECT` grants: other privileges, other tables, column grants, grant
/// options. Partial-revoke rows only narrow access and are left alone (the
/// desired `GRANT` re-adds anything they took away). Returns an error for a
/// grant whose object cannot be named safely, so drift fails closed.
pub(super) fn revoke_statements(
    database: &str,
    on_cluster: &str,
    objects: &AgentlaneObjects,
    observed: &[ObservedGrant],
) -> Result<Vec<String>, ClickHouseMigrateError> {
    let mut out = Vec::new();
    for grant in observed {
        if grant.is_partial_revoke != 0 {
            continue;
        }
        let desired_select = grant.access_type == "SELECT"
            && grant.database.as_deref() == Some(database)
            && grant
                .table
                .as_ref()
                .is_some_and(|t| grant.is_wildcard == 0 && objects.grant_tables.contains(t))
            && grant.column.is_none();
        if desired_select && grant.grant_option == 0 {
            continue;
        }
        let object = grant_object(grant)?;
        let privilege = match &grant.column {
            Some(col) => format!("{}({})", grant.access_type, safe_ident(col)?),
            None => grant.access_type.clone(),
        };
        if !grant
            .access_type
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == ' ' || c == '_')
        {
            return Err(unsafe_grant(grant));
        }
        let what = if desired_select {
            // Keep SELECT; drop only the grant option.
            format!("GRANT OPTION FOR {privilege}")
        } else {
            privilege
        };
        out.push(format!(
            "REVOKE{on_cluster} {what} ON {object} FROM {AGENTLANE_ROLE}"
        ));
    }
    Ok(out)
}

fn grant_object(grant: &ObservedGrant) -> Result<String, ClickHouseMigrateError> {
    let star = if grant.is_wildcard != 0 { "*" } else { "" };
    Ok(match (&grant.database, &grant.table) {
        (None, _) => "*.*".to_string(),
        (Some(db), None) => format!("{}{star}.*", safe_ident(db)?),
        (Some(db), Some(table)) => format!("{}.{}{star}", safe_ident(db)?, safe_ident(table)?),
    })
}

fn safe_ident(name: &str) -> Result<String, ClickHouseMigrateError> {
    if crate::sql_hygiene::is_safe_sql_identifier(name) {
        Ok(name.to_string())
    } else {
        Err(ClickHouseMigrateError::ClickHouse(format!(
            "role {AGENTLANE_ROLE} holds a grant on '{name}', which cannot be revoked \
             automatically; revoke it by hand and rerun the migrator"
        )))
    }
}

fn unsafe_grant(grant: &ObservedGrant) -> ClickHouseMigrateError {
    ClickHouseMigrateError::ClickHouse(format!(
        "role {AGENTLANE_ROLE} holds an unexpected grant {grant:?}, which cannot be revoked \
         automatically; revoke it by hand and rerun the migrator"
    ))
}

/// One `system.role_grants` row that grants `agentlane_reader` to someone.
#[derive(Debug, Clone, PartialEq, Eq, clickhouse::Row, serde::Deserialize)]
pub(super) struct ObservedMembership {
    pub user_name: Option<String>,
    pub role_name: Option<String>,
    pub with_admin_option: u8,
}

pub(super) const OBSERVED_MEMBERSHIP_COLUMNS: &str =
    "user_name, role_name, toUInt8(with_admin_option) AS with_admin_option";

/// A legitimate holder of the role: a per-token user `agentlane_<id>`, `<id>`
/// lowercase `[a-z0-9]` (V2021-AGENTLANE-CONTRACT). The P4 query-audit reader
/// `nanosiem_agentlane_audit` has its own column-scoped system grants and
/// never holds this role.
pub(super) fn is_token_user(name: &str) -> bool {
    name.strip_prefix("agentlane_").is_some_and(|id| {
        !id.is_empty() && id.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
    })
}

/// `REVOKE` statements for role memberships that should not exist: any role
/// granted `agentlane_reader`, any user that is not a token user, and the
/// admin option on a token user (a token must not pass the role on).
pub(super) fn membership_revoke_statements(
    on_cluster: &str,
    observed: &[ObservedMembership],
) -> Result<Vec<String>, ClickHouseMigrateError> {
    let mut out = BTreeSet::new();
    for m in observed {
        let (grantee, token) = match (&m.user_name, &m.role_name) {
            (Some(user), _) => (user, is_token_user(user)),
            (None, Some(role)) => (role, false),
            (None, None) => continue,
        };
        let grantee = safe_ident(grantee)?;
        if !token {
            out.insert(format!("REVOKE{on_cluster} {AGENTLANE_ROLE} FROM {grantee}"));
        } else if m.with_admin_option != 0 {
            out.insert(format!(
                "REVOKE{on_cluster} ADMIN OPTION FOR {AGENTLANE_ROLE} FROM {grantee}"
            ));
        }
    }
    Ok(out.into_iter().collect())
}

/// Where per-node drift is read from: the connected node's own system
/// tables, or another replica through `remote()` / `remoteSecure()` as the
/// migrator's admin. `remote()` is used instead of `clusterAllReplicas()`
/// because on a Compose role-split cluster the latter hops as the runtime
/// user, which cannot read `system.grants`. The password inside `remote()`
/// is masked (`[HIDDEN]`) in `system.query_log` (verified on 26.10), and the
/// SQL is never logged here. Port 9440 is taken to mean the TLS native port.
pub(super) fn node_source(table: &str, node: Option<(&str, u16)>, user: &str, password: &str) -> String {
    match node {
        None => format!("system.{table}"),
        Some((host, port)) => format!(
            "{func}('{addr}', system.{table}, '{user}', '{password}')",
            func = if port == 9440 { "remoteSecure" } else { "remote" },
            addr = escape_sql_string(format!("{host}:{port}")),
            user = escape_sql_string(user),
            password = escape_sql_string(password),
        ),
    }
}

/// Admin credentials the migrator uses to read other replicas' access
/// entities. Without them only the connected node is checked for drift.
#[derive(Clone, Copy)]
pub struct NodeCredentials<'a> {
    pub user: &'a str,
    pub password: &'a str,
}

impl std::fmt::Debug for NodeCredentials<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NodeCredentials")
            .field("user", &self.user)
            .field("password", &"<redacted>")
            .finish()
    }
}

/// Counts from one [`ClickHouseMigrator::ensure_agentlane_objects`] run.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AgentlaneOutcome {
    pub granted_tables: usize,
    pub policy_tables: usize,
    /// Revoked privileges plus revoked role memberships.
    pub revoked: usize,
    /// Nodes whose grants and memberships were read for drift.
    pub nodes_checked: usize,
    /// Replicas that could not be read (down, or no credentials); drift
    /// there is fixed on the next run that can reach them.
    pub nodes_unchecked: usize,
    /// Stray role memberships seen on another replica whose grantee does not
    /// exist on the connected node, so they cannot be revoked from here
    /// (logged as a SECURITY error with the REVOKE to run on that node).
    pub unresolved_memberships: usize,
    pub workload_max_memory: u64,
}

impl ClickHouseMigrator {
    /// NAN-5359: converge the Agent Lane profile, workload, role, grants and
    /// audit row policies (see the module docs). Must run after the tables
    /// and any `_local` / Distributed split exist, and after migration 189
    /// created the `nano` workload root. Creates no user. Fails closed: any
    /// statement error stops the migrator rather than leaving a role that can
    /// read without its audit policy.
    ///
    /// Drift (extra privileges or role memberships) is read on every replica
    /// of an explicit cluster through `remote()` as `node_credentials` (see
    /// [`node_source`]) and revoked `ON CLUSTER`. The connected node must be
    /// readable (fails closed); a replica that is down or refuses is counted
    /// in [`AgentlaneOutcome::nodes_unchecked`] and logged, not fatal.
    pub async fn ensure_agentlane_objects(
        &mut self,
        caps: &AgentlaneSettings,
        node_credentials: Option<NodeCredentials<'_>>,
    ) -> Result<AgentlaneOutcome, ClickHouseMigrateError> {
        let cluster_name = self.detect_cluster().await?;
        let explicit_cluster = self.explicit_cluster_name().map(str::to_string);
        // Access entities: ON CLUSTER only on an explicit cluster, like the
        // raw-SQL users and policies. Workloads: on any cluster (NAN-4988).
        let on_cluster = on_cluster_clause(explicit_cluster.as_deref());
        let workload_on_cluster = on_cluster_clause(cluster_name.as_deref());

        // NAN-5215: with a replica down, every idempotent statement returns
        // once the live replicas applied it; the down replica replays the DDL
        // queue when it returns. A healthy cluster keeps the strict wait.
        let reachability = match &explicit_cluster {
            Some(cluster) => Self::probe_reachability(&self.client, cluster).await.ok(),
            None => None,
        };
        let all_reachable = match &explicit_cluster {
            Some(_) => reachability.as_ref().is_some_and(|r| r.all_reachable()),
            None => true,
        };
        let ddl = super::distributed::rawsql_policy_ddl_options(
            explicit_cluster.is_some(),
            all_reachable,
        )
        .iter()
        .fold(self.client.clone(), |client, (name, value)| {
            client.with_option(*name, *value)
        });

        let existing = self
            .client
            .query("SELECT name, engine FROM system.tables WHERE database = ? AND name IN ?")
            .bind(&self.database)
            .bind(candidate_table_names())
            .fetch_all::<ExistingTable>()
            .await
            .map_err(|e| {
                ClickHouseMigrateError::ClickHouse(format!("listing Agent Lane tables: {e}"))
            })?;
        let objects = plan_objects(&existing);

        // Unset memory limits are sized from the connected node's EFFECTIVE
        // server limit (nodes in a tier are sized alike).
        let server_memory = if caps.workload_max_memory.is_none() || caps.max_memory_per_token.is_none() {
            self.client
                .query("SELECT toUInt64(getServerSetting('max_server_memory_usage'))")
                .fetch_one::<u64>()
                .await
                .unwrap_or_else(|e| {
                    tracing::warn!(error = %e, "NAN-5359: could not read the server memory limit; Agent Lane memory caps use their fallbacks");
                    0
                })
        } else {
            0
        };
        let workload_max_memory = caps
            .workload_max_memory
            .unwrap_or_else(|| derived_workload_max_memory(server_memory));
        let caps = &AgentlaneSettings {
            max_memory_per_token: Some(
                caps.max_memory_per_token
                    .unwrap_or_else(|| derived_max_memory_per_token(server_memory)),
            ),
            ..*caps
        };

        let mut statements = vec![workload_statement(
            &workload_on_cluster,
            caps.max_concurrent_threads,
            workload_max_memory,
        )];
        statements.extend(resource_statements(&workload_on_cluster));
        statements.extend(profile_statements(&on_cluster, caps));
        statements.extend(role_statements(&on_cluster));
        statements.extend(policy_statements(&self.database, &on_cluster, &objects));
        statements.extend(grant_statement(&self.database, &on_cluster, &objects));
        for sql in &statements {
            self.execute_agentlane(&ddl, sql).await?;
        }

        // Drift: the connected node first (fails closed), then every other
        // replica of an explicit cluster through remote().
        let (mut observed, mut members) = self.read_agentlane_drift(None, None).await?;
        // On an explicit cluster the connected node is also read again
        // through remote() below, so it is counted there.
        let mut nodes_checked = usize::from(explicit_cluster.is_none());
        let mut nodes_unchecked = 0usize;
        if let Some(cluster) = &explicit_cluster {
            let replicas = self
                .client
                .query(&super::cluster_reachability::cluster_replicas_sql(cluster))
                .fetch_all::<super::cluster_reachability::ClusterReplica>()
                .await
                .unwrap_or_else(|e| {
                    // Never silent: the outcome then reports no replica checked.
                    tracing::warn!(
                        error = %e,
                        "NAN-5359: could not list the cluster replicas; Agent Lane grant drift was checked on the connected node only"
                    );
                    Vec::new()
                });
            if replicas.is_empty() {
                nodes_checked = 1;
            }
            for (index, replica) in replicas.iter().enumerate() {
                let up = reachability
                    .as_ref()
                    .is_none_or(|r| r.reachable.contains(&(index as u32 + 1)));
                let Some(creds) = node_credentials.filter(|_| up) else {
                    nodes_unchecked += 1;
                    tracing::warn!(
                        host = %replica.host_name,
                        "NAN-5359: Agent Lane grant drift not checked on this replica ({})",
                        if up { "no admin credentials" } else { "unreachable" }
                    );
                    continue;
                };
                match self
                    .read_agentlane_drift(Some((&replica.host_name, replica.port)), Some(creds))
                    .await
                {
                    Ok((grants, memberships)) => {
                        nodes_checked += 1;
                        observed.extend(grants);
                        members.extend(memberships);
                    }
                    Err(e) => {
                        nodes_unchecked += 1;
                        tracing::warn!(
                            host = %replica.host_name,
                            error = %e,
                            "NAN-5359: could not read Agent Lane grants on this replica; drift there is fixed on a later run"
                        );
                    }
                }
            }
        }
        let mut revokes = revoke_statements(&self.database, &on_cluster, &objects, &observed)?;
        revokes.sort();
        revokes.dedup();
        for sql in &revokes {
            tracing::warn!("NAN-5359: revoking unexpected Agent Lane grant: {sql}");
            self.execute_agentlane(&ddl, sql).await?;
        }
        let memberships = membership_revoke_statements(&on_cluster, &members)?;
        let mut unresolved = 0usize;
        for sql in &memberships {
            tracing::warn!("NAN-5359: revoking unexpected Agent Lane role membership: {sql}");
            if let Err(e) = ddl.query(sql).execute().await {
                // A stray grantee that exists only on OTHER replicas: the
                // connected node validates the grantee before queueing the ON
                // CLUSTER DDL and refuses with UNKNOWN_ROLE (511), so the
                // migrator cannot revoke it from here. It is reported (error
                // log + `unresolved_memberships`), not fatal: failing the
                // migrator would take the whole install down over one
                // hand-made grant. Revoke it on that node by hand.
                let message = e.to_string();
                if on_cluster.is_empty() || !message.contains("Code: 511") {
                    return Err(self
                        .with_unreachable_replicas(ClickHouseMigrateError::ClickHouse(format!(
                            "Agent Lane DDL failed ({sql}): {message}"
                        )))
                        .await);
                }
                unresolved += 1;
                tracing::error!(
                    "NAN-5359: SECURITY: {sql} could not run: the grantee exists only on another \
                     replica. Run the same REVOKE (without ON CLUSTER) on the node that has it."
                );
                continue;
            }
        }
        let revoked_total = revokes.len() + memberships.len() - unresolved;

        let outcome = AgentlaneOutcome {
            granted_tables: objects.grant_tables.len(),
            policy_tables: objects.policy_tables.len(),
            revoked: revoked_total,
            nodes_checked,
            nodes_unchecked,
            unresolved_memberships: unresolved,
            workload_max_memory,
        };
        tracing::info!(
            granted_tables = outcome.granted_tables,
            policy_tables = outcome.policy_tables,
            revoked = outcome.revoked,
            max_rows_to_read = caps.max_rows_to_read,
            max_bytes_to_read = caps.max_bytes_to_read,
            max_concurrent_threads = caps.max_concurrent_threads,
            max_memory_per_token = caps.max_memory_per_token.unwrap_or_default(),
            workload_max_memory,
            nodes_checked,
            nodes_unchecked,
            unresolved_memberships = unresolved,
            on_cluster = !on_cluster.is_empty(),
            "NAN-5359: Agent Lane profile, workload, role and audit policies ensured"
        );
        Ok(outcome)
    }

    /// The role's privileges and memberships on one node: the connected node
    /// when `node` is `None`, else that replica through `remote()`. The error
    /// never carries the SQL (it holds the admin password).
    async fn read_agentlane_drift(
        &self,
        node: Option<(&str, u16)>,
        creds: Option<NodeCredentials<'_>>,
    ) -> Result<(Vec<ObservedGrant>, Vec<ObservedMembership>), ClickHouseMigrateError> {
        let (user, password) = creds.map_or(("", ""), |c| (c.user, c.password));
        let role = escape_sql_string(AGENTLANE_ROLE);
        let where_ = |table: &str| {
            let column = if table == "grants" { "role_name" } else { "granted_role_name" };
            format!("{} WHERE {column} = '{role}'", node_source(table, node, user, password))
        };
        let grants = self
            .client
            .query(&format!("SELECT {OBSERVED_GRANT_COLUMNS} FROM {}", where_("grants")))
            .fetch_all::<ObservedGrant>()
            .await
            .map_err(|e| {
                ClickHouseMigrateError::ClickHouse(format!(
                    "reading grants of role {AGENTLANE_ROLE}: {}",
                    redact(&e.to_string(), password)
                ))
            })?;
        let members = self
            .client
            .query(&format!(
                "SELECT {OBSERVED_MEMBERSHIP_COLUMNS} FROM {}",
                where_("role_grants")
            ))
            .fetch_all::<ObservedMembership>()
            .await
            .map_err(|e| {
                ClickHouseMigrateError::ClickHouse(format!(
                    "reading members of role {AGENTLANE_ROLE}: {}",
                    redact(&e.to_string(), password)
                ))
            })?;
        Ok((grants, members))
    }

    async fn execute_agentlane(
        &self,
        client: &clickhouse::Client,
        sql: &str,
    ) -> Result<(), ClickHouseMigrateError> {
        if let Err(e) = client.query(sql).execute().await {
            return Err(self
                .with_unreachable_replicas(ClickHouseMigrateError::ClickHouse(format!(
                    "Agent Lane DDL failed ({sql}): {e}"
                )))
                .await);
        }
        Ok(())
    }
}

/// Strip a secret from an error message (belt and braces: ClickHouse masks
/// `remote()` passwords itself).
pub(super) fn redact(message: &str, secret: &str) -> String {
    if secret.is_empty() {
        message.to_string()
    } else {
        message.replace(secret, "[HIDDEN]")
    }
}

pub(super) fn on_cluster_clause(cluster: Option<&str>) -> String {
    match cluster {
        Some(c) => format!(" ON CLUSTER '{}'", escape_sql_string(c)),
        None => String::new(),
    }
}
