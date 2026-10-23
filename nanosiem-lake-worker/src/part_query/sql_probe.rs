// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-3715: the operator SQL probe, `POST /v1/debug/sql-probe` on query[T].
//!
//! In the ClickHouse days a slow search was tuned by hand-crafting variants
//! and timing them against a live tenant. On lean the cell runs embedded
//! chDB over Parquet parts and SQL is only generated from nPL, so trying an
//! alternative statement, chDB setting, engine knob or prune strategy meant a
//! code change, an image build and a roll. The probe runs one variant live,
//! against this process's own verified parts, and reports what it cost.
//!
//! **Modes.**
//! - `engine` (an nPL query, no `sql`): the real search path
//!   ([`PartQueryEngine::broad_npl`]: membership, progressive pages,
//!   two-pass, cold batches...) under the call's knobs and settings.
//! - `statement` (raw `sql`, or `mode: "statement"`): ONE statement over the
//!   selection of the nPL (default `*`) window: compile, membership, select
//!   (every prune stage), owner probe, then the generated or hand-written
//!   SQL, bound to the selected files exactly as the planner binds the
//!   compiler's. Raw SQL reads [`planner::PROBE_SOURCE_PLACEHOLDER`] and may
//!   use `{probe_start:String}` / `{probe_end:String}` (the request window,
//!   RFC 3339) so a variants file needs no literal times. EXPLAIN runs only
//!   here.
//!
//! **Knobs** ([`crate::perf_overrides::PROBE_KNOBS`]) and **settings**
//! ([`SETTINGS`]) apply to this call only, through the request's task-local
//! scope; nothing is written to process state: no result or fragment cache
//! (a probe is never cacheable), no locator cache, no lane memo. Reading
//! part files still warms the reader's object cache, as any search does.
//!
//! **Safety.** Reachable only through the cell router's
//! `/v1/tenants/{t}/query/v1/debug/...`, which admits only the full or
//! cluster query token (never a per-tenant token) and stamps
//! [`OPERATOR_HEADER`] (callers can never set it); the search service and
//! the Worker have no route to it (tested in nanosiem-search). The request
//! must name this process's tenant. Raw SQL passes the engine's own
//! compiler-output validator plus [`planner::validate_probe_sql`]. The
//! engine's admission, memory caps and execution deadline apply; settings
//! that bound resources may only tighten them. One probe runs at a time per
//! process (409 when busy). Every call is audit-logged with the sha256 of
//! its SQL and nPL, never their text and never row data; the answer carries
//! row counts, not rows.

use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::time::Instant;

use super::engine::{BroadNplRequest, PartQueryEngine, PartQueryError, QueryResult};
use crate::perf_overrides::{KnobKind, Probe, PROBE_KNOBS, PROBE_PROCESS_LEVEL};
use crate::planner::{self, NativeQueryPlan, RequiredColumn};

/// Set by the cell router on a `/v1/debug/` request it admitted with an
/// operator scope (see `nanosiem_lake_cell::router`); stripped from callers.
pub use nanosiem_lake_cell::router::OPERATOR_DEBUG_HEADER as OPERATOR_HEADER;

/// Answer schema.
pub const SCHEMA: &str = "nano.lake-sql-probe.v1";
/// Most result rows a probe statement may produce (only counted, never returned).
pub const MAX_LIMIT: usize = 100_000;
/// Largest page offset a probe replays.
pub const MAX_OFFSET: usize = 1_000_000;
/// Wall-clock bound of one probe call (statements also carry the engine's
/// own interactive deadline).
pub const PROBE_WALL_LIMIT: std::time::Duration = std::time::Duration::from_secs(180);
/// Longest nPL text accepted.
const MAX_NPL_BYTES: usize = 64 * 1024;
/// Most extra columns a raw statement may add to the read projection.
const MAX_EXTRA_COLUMNS: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    Engine,
    Statement,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExplainKind {
    /// `EXPLAIN PLAN actions = 1, indexes = 1`.
    Plan,
    /// `EXPLAIN PIPELINE`.
    Pipeline,
    /// `EXPLAIN SYNTAX` (the statement as chDB rewrote it).
    Syntax,
}

impl ExplainKind {
    fn clause(self) -> &'static str {
        match self {
            Self::Plan => "EXPLAIN PLAN actions = 1, indexes = 1",
            Self::Pipeline => "EXPLAIN PIPELINE",
            Self::Syntax => "EXPLAIN SYNTAX",
        }
    }
    fn name(self) -> &'static str {
        match self {
            Self::Plan => "plan",
            Self::Pipeline => "pipeline",
            Self::Syntax => "syntax",
        }
    }
}

/// `POST /v1/debug/sql-probe`.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProbeRequest {
    /// Must be this process's tenant.
    pub tenant_id: String,
    #[serde(default)]
    pub request_id: Option<String>,
    /// RFC 3339 window.
    pub start: String,
    pub end: String,
    /// The nPL query (default `*`); in statement mode it drives the
    /// selection's prune hints and required columns.
    #[serde(default)]
    pub npl: Option<String>,
    /// Raw SQL reading the source placeholder (statement mode).
    #[serde(default)]
    pub sql: Option<String>,
    /// Leaf paths a raw statement reads beyond what the nPL requires.
    #[serde(default)]
    pub extra_columns: Vec<String>,
    #[serde(default)]
    pub mode: Option<Mode>,
    #[serde(default = "default_limit")]
    pub limit: usize,
    #[serde(default)]
    pub table_view: bool,
    /// Page offset (engine mode), as a captured search had it.
    #[serde(default)]
    pub offset: usize,
    /// Source types withheld from the caller (only ever narrows the read),
    /// as a captured search had them.
    #[serde(default)]
    pub deny_source_types: std::collections::BTreeSet<String>,
    /// chDB settings from [`SETTINGS`].
    #[serde(default)]
    pub settings: BTreeMap<String, Value>,
    /// Engine knobs from [`PROBE_KNOBS`].
    #[serde(default)]
    pub knobs: BTreeMap<String, Value>,
    /// Statement mode only.
    #[serde(default)]
    pub explain: Vec<ExplainKind>,
}

fn default_limit() -> usize {
    100
}

/// How an allowlisted chDB setting is validated and applied.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rule {
    /// 0/1.
    Flag,
    /// An integer in `min..=max`.
    Range(u64, u64),
    /// One of these bare words.
    Word(&'static [&'static str]),
    /// A resource bound: positive, at most the engine's cap ([`Cap`]), and
    /// applied only where it is lower than the statement's own value.
    Limit(Cap),
}

/// The engine cap a [`Rule::Limit`] setting may not exceed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cap {
    Threads,
    MemoryBytes,
    ExecutionSeconds,
    QueryBytes,
}

/// NAN-3715: the chDB settings a probe may set. Read-path and planner
/// switches, block sizes, and resource bounds that can only tighten. Anything
/// else (caches, `readonly`, server or user memory, overcommit, quotas,
/// network/remote access, logging) is refused.
pub const SETTINGS: &[(&str, Rule)] = &[
    ("max_threads", Rule::Limit(Cap::Threads)),
    ("max_parsing_threads", Rule::Limit(Cap::Threads)),
    ("max_memory_usage", Rule::Limit(Cap::MemoryBytes)),
    (
        "max_bytes_before_external_sort",
        Rule::Limit(Cap::MemoryBytes),
    ),
    (
        "max_bytes_before_external_group_by",
        Rule::Limit(Cap::MemoryBytes),
    ),
    ("max_execution_time", Rule::Limit(Cap::ExecutionSeconds)),
    ("max_bytes_to_read", Rule::Limit(Cap::QueryBytes)),
    ("max_block_size", Rule::Range(128, 65_536)),
    (
        "preferred_block_size_bytes",
        Rule::Range(65_536, 67_108_864),
    ),
    (
        "input_format_parquet_max_block_size",
        Rule::Range(128, 65_536),
    ),
    (
        "input_format_parquet_prefer_block_bytes",
        Rule::Range(65_536, 67_108_864),
    ),
    (
        "input_format_parquet_local_file_min_bytes_for_seek",
        Rule::Range(1_024, 67_108_864),
    ),
    ("input_format_parquet_filter_push_down", Rule::Flag),
    ("input_format_parquet_bloom_filter_push_down", Rule::Flag),
    ("input_format_parquet_page_filter_push_down", Rule::Flag),
    ("input_format_parquet_use_offset_index", Rule::Flag),
    ("input_format_parquet_use_native_reader", Rule::Flag),
    ("input_format_parquet_use_native_reader_v3", Rule::Flag),
    ("input_format_parquet_preserve_order", Rule::Flag),
    ("input_format_parquet_enable_row_group_prefetch", Rule::Flag),
    ("optimize_move_to_prewhere", Rule::Flag),
    ("move_all_conditions_to_prewhere", Rule::Flag),
    ("allow_reorder_prewhere_conditions", Rule::Flag),
    ("move_primary_key_columns_to_end_of_prewhere", Rule::Flag),
    ("optimize_read_in_order", Rule::Flag),
    ("optimize_aggregation_in_order", Rule::Flag),
    ("query_plan_filter_push_down", Rule::Flag),
    ("query_plan_optimize_prewhere", Rule::Flag),
    ("query_plan_merge_filters", Rule::Flag),
    ("optimize_functions_to_subcolumns", Rule::Flag),
    ("optimize_trivial_count_query", Rule::Flag),
    (
        "storage_file_read_method",
        Rule::Word(&["pread", "read", "mmap"]),
    ),
];

/// The rule of setting `name`.
pub fn rule(name: &str) -> Option<(&'static str, Rule)> {
    SETTINGS.iter().find(|(known, _)| *known == name).copied()
}

/// The engine caps a [`Rule::Limit`] is checked against.
#[derive(Debug, Clone, Copy)]
pub struct Caps {
    pub threads: u64,
    pub memory_bytes: u64,
    pub execution_seconds: u64,
    pub query_bytes: u64,
}

impl Caps {
    pub fn of(engine: &PartQueryEngine) -> Self {
        let settings = engine.settings();
        Self {
            threads: settings.threads,
            memory_bytes: settings.max_memory_bytes,
            execution_seconds: crate::query_timing::interactive_execution_seconds()
                .min(settings.max_execution_seconds),
            query_bytes: settings.max_query_bytes,
        }
    }
    fn get(&self, cap: Cap) -> u64 {
        match cap {
            Cap::Threads => self.threads,
            Cap::MemoryBytes => self.memory_bytes,
            Cap::ExecutionSeconds => self.execution_seconds,
            Cap::QueryBytes => self.query_bytes,
        }
    }
}

fn invalid(text: impl Into<String>) -> PartQueryError {
    PartQueryError::Invalid(text.into())
}

fn integer(value: &Value) -> Option<u64> {
    match value {
        Value::Bool(flag) => Some(u64::from(*flag)),
        Value::Number(number) => number.as_u64(),
        Value::String(text) => text.trim().parse().ok(),
        _ => None,
    }
}

/// Validate the requested chDB settings against [`SETTINGS`] and `caps`.
pub fn validate_settings(
    requested: &BTreeMap<String, Value>,
    caps: &Caps,
) -> QueryResult<Vec<(&'static str, String)>> {
    if requested.len() > SETTINGS.len() {
        return Err(invalid("too many settings"));
    }
    let mut out = Vec::with_capacity(requested.len());
    for (name, value) in requested {
        let Some((known, rule)) = rule(name) else {
            return Err(invalid(format!(
                "setting {name} is not on the probe allowlist"
            )));
        };
        let literal = match rule {
            Rule::Flag => match integer(value) {
                Some(flag @ (0 | 1)) => flag.to_string(),
                _ => return Err(invalid(format!("setting {known} takes 0/1"))),
            },
            Rule::Range(min, max) => match integer(value) {
                Some(number) if (min..=max).contains(&number) => number.to_string(),
                _ => {
                    return Err(invalid(format!(
                        "setting {known} takes an integer in {min}..={max}"
                    )))
                }
            },
            Rule::Word(words) => match value.as_str().map(str::trim) {
                Some(word) if words.contains(&word) => format!("'{word}'"),
                _ => {
                    return Err(invalid(format!(
                        "setting {known} takes one of {}",
                        words.join("|")
                    )))
                }
            },
            Rule::Limit(cap) => match integer(value) {
                Some(number) if number > 0 && number <= caps.get(cap) => number.to_string(),
                _ => {
                    return Err(invalid(format!(
                        "setting {known} may only tighten the engine's limit (1..={})",
                        caps.get(cap)
                    )))
                }
            },
        };
        out.push((known, literal));
    }
    Ok(out)
}

/// Validate the requested knobs against [`PROBE_KNOBS`]: the scope of the
/// call (the five header switches go in [`crate::perf_overrides::Overrides`]).
pub fn validate_knobs(
    requested: &BTreeMap<String, Value>,
) -> QueryResult<(
    crate::perf_overrides::Overrides,
    BTreeMap<&'static str, u64>,
)> {
    let mut overrides = crate::perf_overrides::Overrides::default();
    let mut knobs = BTreeMap::new();
    for (name, value) in requested {
        let Some(knob) = crate::perf_overrides::probe_knob(name) else {
            return Err(invalid(format!("unknown knob {name}")));
        };
        let number = match knob.kind {
            KnobKind::Flag => match integer(value) {
                Some(flag @ (0 | 1)) => flag,
                _ => return Err(invalid(format!("knob {} takes true/false", knob.name))),
            },
            KnobKind::Count { min, max } => match integer(value) {
                Some(number) if (min..=max).contains(&number) => number,
                _ => {
                    return Err(invalid(format!(
                        "knob {} takes an integer in {min}..={max}",
                        knob.name
                    )))
                }
            },
        };
        match knob.name {
            "flat_filter_leaves" => overrides.flat_filter_leaves = Some(number == 1),
            "lane_routing_v2" => overrides.lane_routing_v2 = Some(number == 1),
            "identity_merged_index" => overrides.identity_merged_index = Some(number == 1),
            "entity_index" => overrides.entity_index = Some(number == 1),
            "payload_threads" => overrides.payload_threads = Some(number),
            "payload_block_rows" => overrides.payload_block_rows = Some(number),
            name => {
                knobs.insert(name, number);
            }
        }
    }
    Ok((overrides, knobs))
}

fn setting_pattern(name: &str) -> regex::Regex {
    regex::Regex::new(&format!(
        r"(?i)\b{}\s*=\s*('(?:[^'\\]|\\.)*'|[A-Za-z0-9_.\-]+)",
        regex::escape(name)
    ))
    .expect("escaped setting name")
}

/// Apply probe `settings` to one statement. A setting the statement already
/// carries is rewritten in place (every occurrence), a [`Rule::Limit`] only
/// where the probe's value is lower; one it lacks is appended to its
/// trailing `SETTINGS`. Nothing here can raise a bound.
pub fn apply_settings(sql: &str, settings: &[(&'static str, String)]) -> String {
    let mut sql = sql.to_string();
    for (name, literal) in settings {
        let pattern = setting_pattern(name);
        let limit = matches!(rule(name), Some((_, Rule::Limit(_))));
        if pattern.is_match(&sql) {
            sql = pattern
                .replace_all(&sql, |captures: &regex::Captures<'_>| {
                    let existing = &captures[1];
                    let keep = limit
                        && match (existing.parse::<f64>(), literal.parse::<f64>()) {
                            (Ok(existing), Ok(wanted)) => existing <= wanted,
                            // A non-numeric bound is never loosened by guessing.
                            _ => true,
                        };
                    if keep {
                        captures[0].to_string()
                    } else {
                        format!("{name}={literal}")
                    }
                })
                .into_owned();
        } else {
            sql = crate::executor::with_setting(&sql, &format!("{name}={literal}"));
        }
    }
    sql
}

/// `plan` with this call's probe settings (unchanged outside a probe).
pub(super) fn with_probe_settings(mut plan: NativeQueryPlan) -> NativeQueryPlan {
    let settings = crate::perf_overrides::probe_settings();
    if !settings.is_empty() {
        plan.sql = apply_settings(&plan.sql, &settings);
    }
    plan
}

/// The validated call: its scope, mode, and what it will compile.
pub struct Prepared {
    pub request_id: String,
    pub mode: Mode,
    pub npl: String,
    pub scope: crate::perf_overrides::Parsed,
}

/// Check everything that does not need the engine's data.
pub fn prepare(request: &ProbeRequest, tenant_id: &str, caps: &Caps) -> QueryResult<Prepared> {
    if request.tenant_id != tenant_id {
        return Err(invalid("request tenant is not this process's tenant"));
    }
    let request_id = request
        .request_id
        .clone()
        .unwrap_or_else(|| format!("probe-{}", uuid::Uuid::new_v4()));
    if request_id.is_empty()
        || request_id.len() > 128
        || !request_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err(invalid("request_id must be 1-128 of [A-Za-z0-9._-]"));
    }
    if request.limit == 0 || request.limit > MAX_LIMIT {
        return Err(invalid(format!("limit must be 1..={MAX_LIMIT}")));
    }
    if request.offset > MAX_OFFSET {
        return Err(invalid(format!("offset must be at most {MAX_OFFSET}")));
    }
    let npl = request.npl.clone().unwrap_or_else(|| "*".to_string());
    if npl.trim().is_empty() || npl.len() > MAX_NPL_BYTES {
        return Err(invalid("npl must be 1..=64 KiB"));
    }
    let mode = match (request.mode, &request.sql) {
        (Some(Mode::Engine), Some(_)) => return Err(invalid("raw sql runs in statement mode")),
        (Some(mode), _) => mode,
        (None, Some(_)) => Mode::Statement,
        (None, None) => Mode::Engine,
    };
    if let Some(sql) = &request.sql {
        planner::validate_probe_sql(sql).map_err(|error| invalid(error.to_string()))?;
    }
    if !request.extra_columns.is_empty() && request.sql.is_none() {
        return Err(invalid("extra_columns needs raw sql"));
    }
    if request.extra_columns.len() > MAX_EXTRA_COLUMNS {
        return Err(invalid("too many extra_columns"));
    }
    if mode == Mode::Engine && !request.explain.is_empty() {
        return Err(invalid("explain runs in statement mode"));
    }
    let settings = validate_settings(&request.settings, caps)?;
    let (overrides, knobs) = validate_knobs(&request.knobs)?;
    Ok(Prepared {
        request_id,
        mode,
        npl,
        scope: crate::perf_overrides::Parsed {
            overrides,
            probe: Some(Probe { knobs, settings }),
            ..Default::default()
        },
    })
}

fn sha256_hex(text: &str) -> String {
    hex::encode(Sha256::digest(text.as_bytes()))
}

fn broad_request(request: &ProbeRequest, prepared: &Prepared) -> QueryResult<BroadNplRequest> {
    serde_json::from_value(json!({
        "request_id": prepared.request_id,
        "tenant_id": request.tenant_id,
        "dataset": "logs",
        "query": prepared.npl,
        "start": request.start,
        "end": request.end,
        "limit": request.limit,
        "table_view": request.table_view,
        "offset": request.offset,
        "deny_source_types": request.deny_source_types,
        "use_cache": false,
    }))
    .map_err(|error| invalid(format!("probe request: {error}")))
}

/// Process memory from `/proc/self/status` (chDB runs in-process; its C ABI
/// reports rows/bytes read and elapsed time, not a statement's peak memory).
fn process_memory() -> Value {
    let status = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
    let kib = |key: &str| {
        status
            .lines()
            .find_map(|line| line.strip_prefix(key))
            .and_then(|rest| rest.split_whitespace().next()?.parse::<u64>().ok())
            .map(|kib| kib * 1024)
    };
    json!({"rss_bytes": kib("VmRSS:"), "hwm_bytes": kib("VmHWM:")})
}

/// The prune funnel from a selection's evidence (a `SelectionEvidence` or a
/// request's `query_timing` funnel, both serialized): files left after each
/// stage in the order the engine runs them, and row groups kept.
pub fn funnel(evidence: &Value) -> Value {
    let n = |key: &str| evidence.get(key).and_then(Value::as_u64).unwrap_or(0);
    let after_time = n("time_files");
    let after_uid = after_time.saturating_sub(n("uid_pruned_files"));
    let after_sidecars = after_uid.saturating_sub(n("entity_sidecar_pruned_files"));
    let after_tokens = after_sidecars.saturating_sub(n("token_pruned_files"));
    let selected = after_tokens.saturating_sub(n("infile_pruned_files"));
    json!({
        "parts_in_window": n("time_parts"),
        "parts_pruned_membership": n("membership_pruned_parts"),
        "stages": [
            {"stage": "time_and_source_family", "files": after_time, "pruned_family": n("source_family_pruned_files")},
            {"stage": "uid_sidecars", "files": after_uid, "pruned": n("uid_pruned_files")},
            {"stage": "entity_sidecars", "files": after_sidecars, "pruned": n("entity_sidecar_pruned_files"),
                "resident_infile": n("resident_infile_files")},
            {"stage": "token_indexes", "files": after_tokens, "pruned": n("token_pruned_files")},
            {"stage": "footer_blooms", "files": selected, "pruned": n("infile_pruned_files"),
                "row_groups": n("row_groups"), "kept_row_groups": n("kept_row_groups")},
        ],
        "candidate_blocks": evidence.get("candidate_blocks").cloned().unwrap_or(Value::Null),
        "fine_runs": n("fine_runs"),
        "fine_declined_runs": n("fine_declined_runs"),
    })
}

fn knob_evidence(scope: &crate::perf_overrides::Parsed) -> Value {
    let probe = scope.probe.as_ref();
    let overrides = scope.overrides;
    let header = |name: &str| -> Option<u64> {
        match name {
            "flat_filter_leaves" => overrides.flat_filter_leaves.map(u64::from),
            "lane_routing_v2" => overrides.lane_routing_v2.map(u64::from),
            "identity_merged_index" => overrides.identity_merged_index.map(u64::from),
            "entity_index" => overrides.entity_index.map(u64::from),
            "payload_threads" => overrides.payload_threads,
            "payload_block_rows" => overrides.payload_block_rows,
            _ => None,
        }
    };
    let knobs = PROBE_KNOBS
        .iter()
        .map(|knob| {
            let value = header(knob.name)
                .or_else(|| probe.and_then(|probe| probe.knobs.get(knob.name).copied()));
            (
                knob.name.to_string(),
                json!({
                    "env": knob.env,
                    "env_value": knob.env.and_then(|env| std::env::var(env).ok()),
                    "probe": value,
                    "what": knob.what,
                }),
            )
        })
        .collect::<serde_json::Map<_, _>>();
    json!({
        "knobs": knobs,
        "settings": probe.map(|probe| probe.settings.iter().map(|(name, value)| json!({"name": name, "value": value})).collect::<Vec<_>>()),
        "process_level": PROBE_PROCESS_LEVEL,
    })
}

/// The current request's phase record as JSON (null outside `measure`).
pub(crate) fn phases_json() -> Value {
    crate::query_timing::current()
        .and_then(|phases| {
            serde_json::to_value(&*phases.lock().unwrap_or_else(|e| e.into_inner())).ok()
        })
        .unwrap_or(Value::Null)
}

/// Run one probe (the caller holds admission and the busy flag, and runs
/// this inside `query_timing::measure` and the probe's perf scope).
pub async fn run(
    engine: &PartQueryEngine,
    request: &ProbeRequest,
    prepared: &Prepared,
) -> QueryResult<Value> {
    let started = Instant::now();
    let memory_before = process_memory();
    let broad = broad_request(request, prepared)?;
    let mut answer = match prepared.mode {
        Mode::Engine => engine_mode(engine, &broad).await?,
        Mode::Statement => statement_mode(engine, request, &broad).await?,
    };
    answer["ok"] = json!(true);
    answer["schema"] = json!(SCHEMA);
    answer["request_id"] = json!(prepared.request_id);
    answer["tenant_id"] = json!(request.tenant_id);
    answer["mode"] = json!(match prepared.mode {
        Mode::Engine => "engine",
        Mode::Statement => "statement",
    });
    answer["window"] = json!({"start": request.start, "end": request.end});
    answer["log_head"] = engine.head_json().await;
    answer["npl_sha256"] = json!(sha256_hex(&prepared.npl));
    answer["phases"] = phases_json();
    answer["memory"] = json!({
        "peak_bytes": Value::Null,
        "source": "unavailable: chDB's C ABI reports rows/bytes read and elapsed only, and embedded chDB keeps no query_log; process RSS/HWM below are process-wide",
        "process_before": memory_before,
        "process_after": process_memory(),
        "statement_cap_bytes": engine.settings().max_memory_bytes,
    });
    answer["overrides"] = knob_evidence(&prepared.scope);
    answer["wall_ms"] = json!(started.elapsed().as_secs_f64() * 1000.0);
    Ok(answer)
}

async fn engine_mode(engine: &PartQueryEngine, broad: &BroadNplRequest) -> QueryResult<Value> {
    let answer = engine.broad_npl(broad).await?;
    let result = &answer["result"];
    let planner = answer.get("planner").cloned().unwrap_or(Value::Null);
    // The engine path does not hand its statements back; the generated
    // statement (compile only, after the timed run) is what it starts from.
    let template = engine
        .explain_npl(broad)
        .await
        .ok()
        .and_then(|explained| explained["result"]["sql"].as_str().map(str::to_string));
    Ok(json!({
        "sql": {
            "template": template,
            "template_sha256": template.as_deref().map(sha256_hex),
            "query_sha256": answer["query_sha256"],
            "source_placeholder": planner::PROBE_SOURCE_PLACEHOLDER,
        },
        "rows": result["result_rows"],
        "page_has_more": result["page_has_more"],
        "group_total": result["group_total"],
        "read": {"rows": result["storage_rows"], "bytes": result["storage_bytes"], "engine_seconds": result["engine_seconds"]},
        "prune": funnel(&planner),
        "planner": planner,
    }))
}

/// The compiled statement of `broad`, with raw `sql` (and its extra
/// columns) in place of the compiler's.
fn substitute(
    mut compiled: planner::CompiledQuery,
    sql: &str,
    extra: &[String],
    field_types: &BTreeMap<String, String>,
) -> QueryResult<planner::CompiledQuery> {
    compiled.sql = sql.to_string();
    // A hand-written statement is not the compiler's page shape: no
    // cursor/locator paths, and its read projection is the required set.
    compiled.newest_first_event_rows = false;
    compiled.stats_page = false;
    compiled.projected_scan_columns.clear();
    for path in extra {
        let Some(field_type) = field_types.get(path) else {
            return Err(invalid(format!(
                "extra column {path} is not a leaf of this tenant's schema"
            )));
        };
        if !compiled
            .required_columns
            .iter()
            .any(|column| &column.name == path)
        {
            compiled.required_columns.push(RequiredColumn {
                name: path.clone(),
                field_type: field_type.clone(),
            });
        }
    }
    Ok(compiled)
}

async fn statement_mode(
    engine: &PartQueryEngine,
    request: &ProbeRequest,
    broad: &BroadNplRequest,
) -> QueryResult<Value> {
    engine
        .pinned(statement_mode_pinned(engine, request, broad))
        .await?
}

async fn statement_mode_pinned(
    engine: &PartQueryEngine,
    request: &ProbeRequest,
    broad: &BroadNplRequest,
) -> QueryResult<Value> {
    let mut laps = serde_json::Map::new();
    let mut clock = Instant::now();
    let mut lap = |name: &str, laps: &mut serde_json::Map<String, Value>| {
        laps.insert(
            format!("{name}_ms"),
            json!(clock.elapsed().as_secs_f64() * 1000.0),
        );
        clock = Instant::now();
    };
    let field_types = engine.field_types().await?;
    let compiled = engine.compile(broad, field_types.clone()).await?;
    let template = compiled.sql.clone();
    let compiled = match &request.sql {
        Some(sql) => substitute(compiled, sql, &request.extra_columns, &field_types)?,
        None => compiled,
    };
    lap("compile", &mut laps);
    let (from_us, to_us) = super::engine::compiled_window_us(&compiled)?;
    let membership = engine
        .membership_with(&broad.query, &field_types, from_us, to_us, false)
        .await?;
    lap("membership", &mut laps);
    let selection = engine
        .select_with(
            from_us,
            to_us,
            &compiled.candidate_hints,
            membership.as_ref(),
        )
        .await?;
    lap("select", &mut laps);
    let mut plan = super::engine::plan_logs(&selection, &compiled, None)?;
    if crate::perf_overrides::probe_flag("threshold_first", false) {
        if let Some(sql) = super::engine::threshold_first(&plan.sql) {
            plan.sql = sql;
        }
    }
    for (name, value) in [("probe_start", &request.start), ("probe_end", &request.end)] {
        if plan.sql.contains(&format!("{{{name}:String}}")) {
            plan.params.push((name.to_string(), value.clone()));
        }
    }
    let bound = with_probe_settings(plan.clone()).sql;
    lap("plan", &mut laps);
    let output = engine.execute(plan.clone()).await?;
    let rows = super::engine::decode_rows(&output.data)?.len();
    lap("execute", &mut laps);
    let mut explained = serde_json::Map::new();
    for kind in &request.explain {
        let statement = NativeQueryPlan {
            sql: format!(
                "{} {}",
                kind.clause(),
                with_probe_settings(plan.clone()).sql
            ),
            ..plan.clone()
        };
        let lines = match engine
            .execute_materialized(statement)
            .await
            .and_then(|output| super::engine::decode_rows(&output.data))
        {
            Ok(rows) => json!(rows
                .iter()
                .map(|row| row.get("explain").cloned().unwrap_or_else(|| row.clone()))
                .collect::<Vec<_>>()),
            Err(error) => json!({"unavailable": error.reason(), "error": error.to_string()}),
        };
        explained.insert(kind.name().to_string(), lines);
    }
    if !request.explain.is_empty() {
        lap("explain", &mut laps);
    }
    let evidence = serde_json::to_value(&selection.evidence).map_err(super::engine::internal)?;
    Ok(json!({
        "sql": {
            "template": template,
            "template_sha256": sha256_hex(&template),
            "bound": bound,
            "bound_sha256": sha256_hex(&bound),
            "params": plan.params.iter().map(|(name, value)| json!({"name": name, "bytes": value.len()})).collect::<Vec<_>>(),
            "raw": request.sql.is_some(),
            "source_placeholder": planner::PROBE_SOURCE_PLACEHOLDER,
        },
        "rows": rows,
        "read": {"rows": output.storage_rows_read, "bytes": output.storage_bytes_read, "engine_seconds": output.elapsed.as_secs_f64()},
        "estimated_scan_bytes": plan.budget.estimated_scan_bytes,
        "timings_ms": laps,
        "prune": funnel(&evidence),
        "selection": evidence,
        "explain": explained,
    }))
}

/// The audit record of one probe call: hashes and counts only.
pub fn audit(
    request: &ProbeRequest,
    prepared: Option<&Prepared>,
    outcome: Result<&Value, &PartQueryError>,
    wall_ms: f64,
) {
    let sql_sha256 = request.sql.as_deref().map(sha256_hex);
    let npl_sha256 = sha256_hex(request.npl.as_deref().unwrap_or("*"));
    let (status, reason, rows, read_bytes, bound_sha256) = match outcome {
        Ok(answer) => (
            "ok",
            "",
            answer["rows"].as_u64(),
            answer["read"]["bytes"].as_u64(),
            answer["sql"]["bound_sha256"]
                .as_str()
                .or(answer["sql"]["template_sha256"].as_str())
                .map(str::to_string),
        ),
        Err(error) => ("error", error.reason(), None, None, None),
    };
    let knobs = request.knobs.keys().cloned().collect::<Vec<_>>().join(",");
    let settings = request
        .settings
        .keys()
        .cloned()
        .collect::<Vec<_>>()
        .join(",");
    tracing::info!(
        target: "nano_audit",
        event = "lake_sql_probe",
        tenant_id = %request.tenant_id,
        request_id = prepared.map(|prepared| prepared.request_id.as_str()).unwrap_or(""),
        mode = prepared.map(|prepared| match prepared.mode { Mode::Engine => "engine", Mode::Statement => "statement" }).unwrap_or(""),
        raw_sql_sha256 = sql_sha256.as_deref().unwrap_or(""),
        bound_sql_sha256 = bound_sha256.as_deref().unwrap_or(""),
        npl_sha256 = %npl_sha256,
        knobs = %knobs,
        settings = %settings,
        status,
        reason,
        rows,
        read_bytes,
        wall_ms,
        "lake sql probe"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    fn caps() -> Caps {
        Caps {
            threads: 4,
            memory_bytes: 1 << 30,
            execution_seconds: 55,
            query_bytes: 1 << 40,
        }
    }

    fn request(value: Value) -> ProbeRequest {
        serde_json::from_value(value).unwrap()
    }

    #[test]
    fn settings_are_allowlisted_and_limits_only_tighten() {
        let ok = validate_settings(&serde_json::from_value(json!({
            "max_threads": 2, "optimize_move_to_prewhere": false, "storage_file_read_method": "mmap",
            "max_memory_usage": 1 << 29, "input_format_parquet_bloom_filter_push_down": 1,
        })).unwrap(), &caps()).unwrap();
        assert!(ok.contains(&("max_threads", "2".to_string())));
        assert!(ok.contains(&("optimize_move_to_prewhere", "0".to_string())));
        assert!(ok.contains(&("storage_file_read_method", "'mmap'".to_string())));
        for bad in [
            json!({"max_threads": 5}),
            json!({"max_memory_usage": (1u64 << 30) + 1}),
            json!({"max_execution_time": 56}),
            json!({"max_threads": 0}),
            json!({"readonly": 0}),
            json!({"use_query_cache": 1}),
            json!({"max_server_memory_usage": 1}),
            json!({"max_memory_usage_for_user": 1}),
            json!({"memory_overcommit_ratio_denominator": 0}),
            json!({"allow_experimental_analyzer": 1}),
            json!({"storage_file_read_method": "io_uring' , readonly=0, x='"}),
            json!({"optimize_move_to_prewhere": 2}),
        ] {
            assert!(
                validate_settings(&serde_json::from_value(bad.clone()).unwrap(), &caps()).is_err(),
                "{bad}"
            );
        }
    }

    #[test]
    fn applied_settings_never_raise_a_bound() {
        let sql = "SELECT 1 FROM t SETTINGS max_threads=4, max_memory_usage=1000, max_execution_time=55, max_block_size=8192";
        let applied = apply_settings(
            sql,
            &[
                ("max_threads", "8".into()),
                ("max_memory_usage", "500".into()),
                ("max_block_size", "1024".into()),
                ("optimize_move_to_prewhere", "0".into()),
            ],
        );
        assert!(applied.contains("max_threads=4"), "{applied}");
        assert!(
            applied.contains("max_memory_usage=500") && !applied.contains("max_memory_usage=1000"),
            "{applied}"
        );
        assert!(
            applied.contains("max_block_size=1024") && !applied.contains("8192"),
            "{applied}"
        );
        assert!(
            applied.ends_with(", optimize_move_to_prewhere=0"),
            "{applied}"
        );
        // Absent from the statement: appended (the request was capped already).
        assert_eq!(
            apply_settings("SELECT 1", &[("max_threads", "2".into())]),
            "SELECT 1 SETTINGS max_threads=2"
        );
        // Outside a probe nothing changes.
        let plan = NativeQueryPlan {
            query_sha256: String::new(),
            sql: sql.into(),
            params: Vec::new(),
            budget: planner::QueryBudget {
                candidate_objects: 0,
                estimated_scan_bytes: 0,
                max_query_bytes: 0,
            },
            native_event_rows: false,
            temporary_aliases: Default::default(),
            schema_defaults: Vec::new(),
            reader: Default::default(),
        };
        assert_eq!(with_probe_settings(plan).sql, sql);
    }

    #[test]
    fn knobs_are_validated_and_split() {
        let (overrides, knobs) = validate_knobs(&serde_json::from_value(json!({
            "flat_filter_leaves": true, "payload_threads": 3, "range_fetch": false, "prune_tokens": 0,
            "evidence_probe_concurrency": 2,
        })).unwrap()).unwrap();
        assert_eq!(overrides.flat_filter_leaves, Some(true));
        assert_eq!(overrides.payload_threads, Some(3));
        assert_eq!(knobs.get("range_fetch"), Some(&0));
        assert_eq!(knobs.get("prune_tokens"), Some(&0));
        assert_eq!(knobs.get("evidence_probe_concurrency"), Some(&2));
        for bad in [
            json!({"nope": 1}),
            json!({"range_fetch": 2}),
            json!({"evidence_probe_concurrency": 0}),
            json!({"evidence_probe_concurrency": 33}),
        ] {
            assert!(
                validate_knobs(&serde_json::from_value(bad.clone()).unwrap()).is_err(),
                "{bad}"
            );
        }
    }

    #[test]
    fn every_knob_reads_its_value_only_inside_the_probe_scope() {
        for knob in PROBE_KNOBS {
            assert!(crate::perf_overrides::probe_knob(knob.name).is_some());
        }
        let scope = crate::perf_overrides::Parsed {
            probe: Some(Probe {
                knobs: [("prune_tokens", 0), ("evidence_probe_concurrency", 3)]
                    .into_iter()
                    .collect(),
                settings: vec![("max_threads", "1".into())],
            }),
            ..Default::default()
        };
        let inside = futures::executor::block_on(crate::perf_overrides::scoped(
            Some(std::sync::Arc::new(scope)),
            async {
                (
                    crate::perf_overrides::probe_flag("prune_tokens", true),
                    crate::perf_overrides::probe_count("evidence_probe_concurrency"),
                    crate::perf_overrides::in_probe(),
                    crate::perf_overrides::active(),
                    crate::perf_overrides::probe_settings().len(),
                )
            },
        ));
        assert_eq!(inside, (false, Some(3), true, true, 1));
        assert!(crate::perf_overrides::probe_flag("prune_tokens", true));
        assert!(!crate::perf_overrides::in_probe() && !crate::perf_overrides::active());
    }

    #[test]
    fn prepare_binds_the_tenant_and_picks_the_mode() {
        let base = json!({"tenant_id": "t1", "start": "2026-10-12T00:00:00Z", "end": "2026-10-12T01:00:00Z"});
        let mut other = base.clone();
        other["tenant_id"] = json!("t2");
        assert!(
            prepare(&request(other), "t1", &caps()).is_err(),
            "another tenant is refused"
        );
        let engine = prepare(&request(base.clone()), "t1", &caps()).unwrap();
        assert_eq!((engine.mode, engine.npl.as_str()), (Mode::Engine, "*"));
        assert!(
            engine.scope.probe.is_some(),
            "every probe runs in a probe scope (caches bypassed)"
        );
        let mut raw = base.clone();
        raw["sql"] = json!("SELECT count() FROM __nano_lake_source__ WHERE time >= parseDateTime64BestEffort({probe_start:String}, 6, 'UTC')");
        assert_eq!(
            prepare(&request(raw.clone()), "t1", &caps()).unwrap().mode,
            Mode::Statement
        );
        raw["mode"] = json!("engine");
        assert!(prepare(&request(raw), "t1", &caps()).is_err());
        let mut explain = base.clone();
        explain["explain"] = json!(["plan"]);
        assert!(
            prepare(&request(explain), "t1", &caps()).is_err(),
            "explain needs statement mode"
        );
        let mut long = base;
        long["limit"] = json!(MAX_LIMIT + 1);
        assert!(prepare(&request(long), "t1", &caps()).is_err());
    }

    #[test]
    fn raw_sql_is_held_to_the_engine_validator_and_more() {
        let base = json!({"tenant_id": "t1", "start": "2026-10-12T00:00:00Z", "end": "2026-10-12T01:00:00Z"});
        for bad in [
            "SELECT 1",
            "SELECT * FROM __nano_lake_source__; SELECT 1",
            "INSERT INTO t SELECT * FROM __nano_lake_source__",
            "SELECT * FROM url('http://x', CSV) UNION ALL SELECT * FROM __nano_lake_source__",
            "SELECT * FROM s3('s3://b/k') JOIN __nano_lake_source__ USING (time)",
            "SELECT * FROM file('/etc/passwd') JOIN __nano_lake_source__ USING (time)",
            "SELECT * FROM remote('h', db.t) JOIN __nano_lake_source__ USING (time)",
            "SELECT count() FROM __nano_lake_source__ SETTINGS max_memory_usage=0",
            "SELECT count() FROM __nano_lake_source__ INTO OUTFILE 'x'",
            "SELECT count() FROM __nano_lake_source__ FORMAT JSON",
            "SELECT * FROM system.settings, __nano_lake_source__",
            "SELECT * FROM \"system\".\"settings\", __nano_lake_source__",
            "SELECT count() FROM __nano_lake_source__ -- c",
            "EXPLAIN SELECT count() FROM __nano_lake_source__",
            "SELECT * FROM `url`('http://x') , __nano_lake_source__",
        ] {
            let mut value = base.clone();
            value["sql"] = json!(bad);
            assert!(prepare(&request(value), "t1", &caps()).is_err(), "{bad}");
        }
        let mut ok = base;
        ok["sql"] = json!("WITH x AS (SELECT time, `unmapped.system.name` AS n FROM __nano_lake_source__) SELECT count() FROM x WHERE n = 'system.x'");
        // A literal that looks like a system table is refused too (documented).
        assert!(prepare(&request(ok.clone()), "t1", &caps()).is_err());
        ok["sql"] = json!("WITH x AS (SELECT time, `unmapped.system.name` AS n FROM __nano_lake_source__) SELECT count() FROM x WHERE n = 'ok'");
        prepare(&request(ok), "t1", &caps()).unwrap();
    }

    #[test]
    fn funnel_counts_files_left_after_each_stage() {
        let evidence = json!({"time_parts": 3, "time_files": 20, "uid_pruned_files": 2, "entity_sidecar_pruned_files": 5,
            "token_pruned_files": 3, "infile_pruned_files": 4, "row_groups": 40, "kept_row_groups": 9, "membership_pruned_parts": 1});
        let funnel = funnel(&evidence);
        let files = funnel["stages"]
            .as_array()
            .unwrap()
            .iter()
            .map(|stage| stage["files"].as_u64().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(files, vec![20, 18, 13, 10, 6]);
        assert_eq!(funnel["stages"][4]["kept_row_groups"], 9);
    }
}

/// Native: the probe end to end over real parts (compiler, planner, chDB).
///
/// ```sh
/// export NANO_CHDB_LIBRARY_PATH=... NANO_CHDB_LIBRARY_SHA256=... NANO_LAKE_COMPILER=...
/// cargo test -p nanosiem-lake-worker --lib part_query::sql_probe::native -- --ignored --nocapture --test-threads=1
/// ```
#[cfg(test)]
mod native {
    use super::*;
    use crate::part_query::engine::lean_query_native::{
        engine, ingest, source, ROWS, TENANT,
    };
    use chrono::{Duration, Utc};

    fn caps() -> Caps {
        Caps {
            threads: 2,
            memory_bytes: 256 << 20,
            execution_seconds: 55,
            query_bytes: 64 << 30,
        }
    }

    async fn probe(engine: &PartQueryEngine, body: Value) -> Value {
        let request: ProbeRequest = serde_json::from_value(body).unwrap();
        let prepared = prepare(&request, TENANT, &caps()).unwrap();
        let scope = Some(std::sync::Arc::new(prepared.scope.clone()));
        crate::query_timing::measure(
            &prepared.request_id,
            Box::pin(crate::perf_overrides::scoped(scope, run(engine, &request, &prepared))),
        )
        .await
        .unwrap_or_else(|error| panic!("probe failed: {error}"))
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore = "native: NANO_CHDB_LIBRARY_PATH, NANO_CHDB_LIBRARY_SHA256, NANO_LAKE_COMPILER"]
    async fn engine_and_raw_statement_variants_agree_and_report_their_cost() {
        let root = tempfile::tempdir().unwrap();
        let now = Utc::now();
        ingest(root.path(), now).await;
        let engine = engine(root.path()).await;
        let window = json!({"tenant_id": TENANT, "start": (now - Duration::hours(24)).to_rfc3339(), "end": (now + Duration::minutes(1)).to_rfc3339()});
        let with = |extra: Value| {
            let mut body = window.clone();
            body.as_object_mut()
                .unwrap()
                .extend(extra.as_object().unwrap().clone());
            body
        };
        let truth = (0..ROWS).filter(|i| source(*i) == "windows_sysmon").count() as u64;

        // Engine mode: the real search path; the count comes back as one row.
        let engine_mode = probe(
            &engine,
            with(json!({"npl": "metadata.log_source=windows_sysmon | stats count() as n"})),
        )
        .await;
        assert_eq!(engine_mode["mode"], "engine");
        assert_eq!(engine_mode["rows"], 1);
        assert!(engine_mode["sql"]["template"]
            .as_str()
            .unwrap()
            .contains(planner::PROBE_SOURCE_PLACEHOLDER));
        assert!(
            engine_mode["read"]["bytes"].as_u64().unwrap() > 0,
            "{engine_mode}"
        );
        assert!(
            engine_mode["phases"]["native_statements"].as_u64().unwrap() >= 1,
            "{engine_mode}"
        );

        // Statement mode, hand-written: one row per event, counted only.
        let raw = "SELECT `metadata.uid` FROM __nano_lake_source__ WHERE lower(`metadata.log_source`) = 'windows_sysmon' \
                   AND time >= parseDateTime64BestEffort({probe_start:String}, 6, 'UTC') \
                   AND time <= parseDateTime64BestEffort({probe_end:String}, 6, 'UTC')";
        let statement = probe(&engine, with(json!({"npl": "metadata.log_source=windows_sysmon", "sql": raw, "limit": 1000,
            "extra_columns": ["metadata.uid"], "settings": {"max_threads": 1, "optimize_move_to_prewhere": 0},
            "explain": ["plan", "syntax"]}))).await;
        assert_eq!(statement["mode"], "statement");
        assert_eq!(statement["rows"].as_u64(), Some(truth), "{statement}");
        let bound = statement["sql"]["bound"].as_str().unwrap();
        assert!(
            bound.contains("max_threads=1") && bound.contains("optimize_move_to_prewhere=0"),
            "{bound}"
        );
        assert!(
            !bound.contains(planner::PROBE_SOURCE_PLACEHOLDER),
            "the placeholder is bound to the parts"
        );
        assert!(
            statement["explain"]["plan"]
                .as_array()
                .is_some_and(|lines| !lines.is_empty()),
            "{}",
            statement["explain"]
        );
        assert!(statement["timings_ms"]["execute_ms"].as_f64().is_some());
        assert!(statement["prune"]["stages"].as_array().unwrap().len() == 5);
        assert!(
            statement.to_string().find("uid-0").is_none(),
            "no row data in the answer"
        );

        // A prune stage off: same rows, more (or equal) files read.
        let generated = probe(&engine, with(json!({"npl": "metadata.log_source=windows_sysmon", "mode": "statement", "limit": 1000}))).await;
        let unpruned = probe(&engine, with(json!({"npl": "metadata.log_source=windows_sysmon", "mode": "statement", "limit": 1000,
            "knobs": {"prune_source_family": false, "prune_blooms": false, "prune_tokens": false}}))).await;
        assert_eq!(generated["rows"], unpruned["rows"]);
        let files = |answer: &Value| answer["prune"]["stages"][4]["files"].as_u64().unwrap();
        assert!(
            files(&unpruned) >= files(&generated),
            "{} vs {}",
            unpruned["prune"],
            generated["prune"]
        );
        assert_eq!(unpruned["overrides"]["knobs"]["prune_blooms"]["probe"], 0);
    }
}
