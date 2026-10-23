// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-3406: per-request A/B overrides of lean search speed switches.
//!
//! The speed switches below are process env vars (cluster `featureEnv` ->
//! the cell supervisor's `FEATURE_ENV` allowlist -> query[T]). Flipping one
//! costs a warm handover (~25 min), and only a live A/B on the same cell
//! measures anything. A request that carries [`HEADER`] (for example
//! `flat_filter_leaves=1,lane_routing_v2=0,identity_merged_index=0`) runs
//! with those values instead of the env-derived ones, for that request only.
//!
//! **Authorization.** query[T] has no end-user caller: the cell router
//! accepts only service tokens and query[T] never listens. The search
//! service forwards [`HEADER`] only for a request it already honours
//! `x-nano-search-debug: 1` for (the caller holds `search:sql`), always with
//! that header, and builds every lake request itself (no caller header is
//! copied). Here an override is honoured only beside [`DEBUG_HEADER`]`: 1`;
//! anything else is ignored silently.
//!
//! **Per-request switches** (read per statement/lookup through
//! [`flat_filter_leaves`], [`lane_routing_v2`], [`identity_merged_index`]):
//!
//! - `flat_filter_leaves` (`NANO_LAKE_FLAT_FILTER_LEAVES`): the planner's
//!   flat filter-leaf read schema.
//! - `lane_routing_v2` (`NANO_LAKE_LANE_ROUTING_V2`): the routing decision,
//!   the 4-thread cap, the bounded wide-text reader and the lane memo. The
//!   large lane's connection count (2 x 768 MiB on, 1 x 1.5 GiB off) is fixed
//!   when the engine opens: `lane_routing_v2=0` on a v2 process routes the
//!   NAN-3077 way but runs a large statement alone with all of the lane's
//!   memory (both permits), and `lane_routing_v2=1` on a v1 process routes
//!   the v2 way on its one-wide large lane.
//! - `identity_merged_index` (`NANO_LAKE_IDENTITY_MERGED_INDEX`): whether a
//!   lookup reads the merged identity file. The background build stays
//!   process-level: `identity_merged_index=1` on a process with the index
//!   off finds no merged file and reads every source, as off does.
//! - `entity_index` (`NANO_LAKE_ENTITY_INDEX`, NAN-4190): whether a selection
//!   reads the window entity index. The build is process-level, as for the
//!   identity index: `entity_index=1` on a process without one changes
//!   nothing.
//!
//! - `payload_threads=N` (`NANO_LAKE_PAYLOAD_MAX_THREADS`, NAN-3411) and
//!   `payload_block_rows=N` (`NANO_LAKE_PAYLOAD_BLOCK_ROWS`): the full-event
//!   payload statement's reader threads (default 1) and block rows (default
//!   128), see `planner::bounded_payload_settings`. Numeric, clamped there
//!   (threads to the interactive 4-thread cap and the tenant's budget, rows
//!   to 128..=8192); every other payload memory bound stays.
//!
//! **Process-level, never per-request** ([`PROCESS_LEVEL`]): prewarm pacing
//! (`NANO_LAKE_PREWARM_THROTTLE`, `..._MIN_INTERVAL_SECONDS`), chDB DNS
//! refresh (`NANO_CHDB_DNS_REFRESH_SECONDS`), the large-lane split and the
//! identity index build. Naming one in [`HEADER`] changes nothing; the
//! evidence lists it under `process_level_ignored`.
//!
//! **Caches.** A request with an override never reads or writes a result
//! cache (the worker result cache and the part fragment cache, see
//! `part_query::result_cache::cacheable`), so one mode's answer is never
//! served to the other. The lane memo is keyed by the effective flat-leaf
//! mode (the statement shape it remembers); the select evidence cache holds
//! per-file bloom masks that no switch here affects, so it is shared.

use serde_json::{json, Value};
use std::sync::Arc;

/// The override header (see the module docs).
pub const HEADER: &str = "x-nano-perf-overrides";
/// The search service's debug header; overrides are honoured only beside it.
pub const DEBUG_HEADER: &str = "x-nano-search-debug";
/// Longest header value read (anything longer is ignored whole).
pub const MAX_HEADER_BYTES: usize = 512;
/// Switch names that are process-level: accepted and ignored.
pub const PROCESS_LEVEL: &[&str] = &[
    "prewarm_throttle",
    "prewarm_min_interval_seconds",
    "dns_refresh",
    "large_lane_split",
    "identity_merged_build",
];

/// One request's overrides; `None` keeps the process value.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct Overrides {
    pub flat_filter_leaves: Option<bool>,
    pub lane_routing_v2: Option<bool>,
    pub identity_merged_index: Option<bool>,
    /// NAN-4190: read the window entity index.
    pub entity_index: Option<bool>,
    /// NAN-3411: payload statement reader threads (unclamped; see module docs).
    pub payload_threads: Option<u64>,
    /// NAN-3411: payload statement block rows (unclamped; see module docs).
    pub payload_block_rows: Option<u64>,
}

impl Overrides {
    pub fn is_empty(&self) -> bool {
        *self == Self::default()
    }
}

/// A parsed header: the overrides plus what was named but not applied.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Parsed {
    pub overrides: Overrides,
    /// Process-level switches named (from [`PROCESS_LEVEL`]).
    pub process_level_ignored: Vec<&'static str>,
    /// Entries that were not `known=0|1` / `numeric=N` (unknown names, bad values).
    pub invalid: usize,
    /// NAN-3715: an operator SQL probe's knobs and chDB settings. Never
    /// parsed from [`HEADER`]: only `POST /v1/debug/sql-probe` builds one.
    pub probe: Option<Probe>,
}

/// NAN-3715: one probe call's engine knobs ([`PROBE_KNOBS`], validated) and
/// chDB settings (validated by `part_query::sql_probe`). Applies to that call
/// only: it lives in the request's task-local scope and never touches
/// process state.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Probe {
    /// Knob name -> value (flags are 0/1).
    pub knobs: std::collections::BTreeMap<&'static str, u64>,
    /// `name=value` chDB settings appended to every statement, tighten-only
    /// for limits (see `part_query::sql_probe::apply_settings`).
    pub settings: Vec<(&'static str, String)>,
}

/// What a probe knob takes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KnobKind {
    /// 0/1 (`true`/`false` on the wire).
    Flag,
    /// An integer in `min..=max`.
    Count { min: u64, max: u64 },
}

/// One per-request engine knob of the SQL probe.
#[derive(Clone, Copy, Debug)]
pub struct Knob {
    pub name: &'static str,
    /// The process env var it shadows (`None`: a constant or a prune stage).
    pub env: Option<&'static str>,
    pub kind: KnobKind,
    pub what: &'static str,
}

const fn flag_knob(name: &'static str, env: Option<&'static str>, what: &'static str) -> Knob {
    Knob { name, env, kind: KnobKind::Flag, what }
}

/// NAN-3715: every engine knob the SQL probe may override for one call. The
/// first six are the [`HEADER`] switches (carried in [`Overrides`]); the
/// rest are read through [`probe_flag`] / [`probe_count`] at their single
/// call site and fall back to the process value outside a probe.
pub const PROBE_KNOBS: &[Knob] = &[
    flag_knob("flat_filter_leaves", Some("NANO_LAKE_FLAT_FILTER_LEAVES"), "planner flat filter-leaf read schema"),
    flag_knob("lane_routing_v2", Some("NANO_LAKE_LANE_ROUTING_V2"), "lane routing v2 (4-thread cap, bounded wide reader)"),
    flag_knob("identity_merged_index", Some("NANO_LAKE_IDENTITY_MERGED_INDEX"), "read the merged identity index"),
    Knob { name: "payload_threads", env: Some("NANO_LAKE_PAYLOAD_MAX_THREADS"), kind: KnobKind::Count { min: 1, max: 64 }, what: "payload statement reader threads (planner clamps)" },
    Knob { name: "payload_block_rows", env: Some("NANO_LAKE_PAYLOAD_BLOCK_ROWS"), kind: KnobKind::Count { min: 1, max: 65_536 }, what: "payload statement block rows (planner clamps)" },
    flag_knob("entity_index", Some("NANO_LAKE_ENTITY_INDEX"), "read the window entity index (exact entity row runs)"),
    flag_knob("range_fetch", Some("NANO_LAKE_SEARCH_RANGE_FETCH"), "sparse column-range fetch of data files"),
    Knob { name: "range_narrow_denominator", env: None, kind: KnobKind::Count { min: 1, max: 64 }, what: "a ranged read is used when its chunks are <= 1/N of the file (default 2)" },
    flag_knob("two_pass", Some("NANO_LAKE_TWO_PASS"), "two-pass row queries (narrow locate, then payload)"),
    flag_knob("full_event_locator", Some("NANO_LAKE_FULL_EVENT_LOCATOR"), "narrow locator for full-event pages"),
    flag_knob("fence_set", Some("NANO_LAKE_FENCE_SET"), "set-membership row fence (off: per-block OR list)"),
    flag_knob("fine_run_cost", Some("NANO_LAKE_FINE_RUN_COST"), "cost model for v2 block runs over the fixed budget"),
    flag_knob("resident_infile_blooms", Some("NANO_LAKE_RESIDENT_INFILE_BLOOMS"), "resident files take entity evidence from in-file blooms, skipping sidecars"),
    flag_knob("payload_at_instants", Some("NANO_LAKE_PAYLOAD_AT_INSTANTS"), "payload reads only files holding a located instant"),
    flag_knob("density_over_selective", Some("NANO_LAKE_DENSITY_OVER_SELECTIVE"), "density estimate may override a selective whole-window read"),
    flag_knob("narrow_aggregate_schema", Some("NANO_LAKE_NARROW_AGGREGATE_SCHEMA"), "aggregates read compiler-owned roots only"),
    flag_knob("dotless_host_hint", Some("NANO_LAKE_DOTLESS_HOST_HINT"), "dotless hostname candidate hints"),
    flag_knob("token_case_insensitive", None, "single-token keyword tests use hasTokenCaseInsensitive"),
    flag_knob("text_after_fence", None, "row-fenced statements keep wide text tests out of PREWHERE"),
    flag_knob("threshold_first", None, "statement mode: rewrite a newest-first top-n to threshold-first (as streamed pages do)"),
    flag_knob("prune_membership", None, "rollup-partial value membership (parts and time buckets)"),
    flag_knob("prune_source_family", None, "signed source-family / class file pruning"),
    flag_knob("prune_uid", None, "uid bloom sidecars"),
    flag_knob("prune_entity_sidecars", None, "entity locator / bloom sidecars"),
    flag_knob("prune_tokens", None, "per-file token indexes"),
    flag_knob("prune_blooms", None, "data-file footer stats / in-file bloom row-group pruning"),
    flag_knob("fine_runs", None, "v2 block runs in place of whole row groups"),
    flag_knob("keyword_counts", None, "single-keyword counts, histograms and by-source counts from v3 token counts (off: scan)"),
    Knob { name: "evidence_probe_concurrency", env: None, kind: KnobKind::Count { min: 1, max: 32 }, what: "files probed at once for footer/bloom/entity evidence (default 8)" },
    Knob { name: "token_probe_concurrency", env: None, kind: KnobKind::Count { min: 1, max: 128 }, what: "token-index files probed at once in select and the token seed (default 32)" },
];

/// NAN-3715: process-level settings a probe cannot override (named in its
/// answer so a comparison does not assume it changed them).
pub const PROBE_PROCESS_LEVEL: &[&str] = &[
    "NANO_LAKE_READER_CACHE_FETCH_CONCURRENCY (process semaphore)",
    "NANO_LAKE_READER_COLD_HEAVY_CONCURRENCY (process semaphore)",
    "NANO_LAKE_READER_CACHE_BYTES / _QUERY_BYTES (cache sizing)",
    "large-lane split and lane memory (fixed when the engine opens)",
    "NANO_LAKE_LOCAL_HOT_WINDOW_WARM_GATE (readiness, not a read path)",
    "NANO_LAKE_PART_RESULT_CACHE (the probe never reads or writes it)",
    "prewarm pacing, product state, identity index build",
];

/// The probe knob named `name` (exact, lower-case).
pub fn probe_knob(name: &str) -> Option<&'static Knob> {
    PROBE_KNOBS.iter().find(|knob| knob.name == name)
}

fn flag(value: &str) -> Option<bool> {
    match value.trim().to_ascii_lowercase().as_str() {
        "1" | "on" | "true" => Some(true),
        "0" | "off" | "false" => Some(false),
        _ => None,
    }
}

/// A positive decimal of at most six digits (larger values are clamped by
/// their reader anyway; anything else is invalid).
fn number(value: &str) -> Option<u64> {
    let value = value.trim();
    (value.len() <= 6 && value.bytes().all(|b| b.is_ascii_digit()))
        .then(|| value.parse::<u64>().ok())
        .flatten()
        .filter(|number| *number > 0)
}

/// Parse a [`HEADER`] value: comma-separated `name=value`, value one of
/// `1|0|on|off|true|false` (numeric knobs: a positive decimal). Unknown
/// names and bad values are counted and skipped; an over-long value is
/// ignored whole.
pub fn parse(text: &str) -> Parsed {
    let mut parsed = Parsed::default();
    if text.len() > MAX_HEADER_BYTES {
        parsed.invalid = 1;
        return parsed;
    }
    for entry in text.split(',').map(str::trim).filter(|entry| !entry.is_empty()) {
        let Some((name, value)) = entry.split_once('=') else {
            parsed.invalid += 1;
            continue;
        };
        let name = name.trim().to_ascii_lowercase();
        if let Some(process) = PROCESS_LEVEL.iter().find(|known| **known == name) {
            if !parsed.process_level_ignored.contains(process) {
                parsed.process_level_ignored.push(process);
            }
            continue;
        }
        let numeric = match name.as_str() {
            "payload_threads" => Some(&mut parsed.overrides.payload_threads),
            "payload_block_rows" => Some(&mut parsed.overrides.payload_block_rows),
            _ => None,
        };
        if let Some(slot) = numeric {
            match number(value) {
                Some(value) => *slot = Some(value),
                None => parsed.invalid += 1,
            }
            continue;
        }
        let slot = match name.as_str() {
            "flat_filter_leaves" => &mut parsed.overrides.flat_filter_leaves,
            "lane_routing_v2" => &mut parsed.overrides.lane_routing_v2,
            "identity_merged_index" => &mut parsed.overrides.identity_merged_index,
            "entity_index" => &mut parsed.overrides.entity_index,
            _ => {
                parsed.invalid += 1;
                continue;
            }
        };
        match flag(value) {
            Some(value) => *slot = Some(value),
            None => parsed.invalid += 1,
        }
    }
    parsed
}

tokio::task_local! {
    static SCOPE: Arc<Parsed>;
}

/// The request's scope from its headers: `Some` only for a debug request
/// (`x-nano-search-debug: 1`), with its overrides when [`HEADER`] is also
/// present. A debug request without overrides still gets a scope, so its
/// evidence records the process values it ran with.
pub fn from_headers(headers: &axum::http::HeaderMap) -> Option<Arc<Parsed>> {
    let debug = headers.get(DEBUG_HEADER).and_then(|value| value.to_str().ok()).is_some_and(|value| value.trim() == "1");
    if !debug {
        return None;
    }
    let parsed = headers.get(HEADER).and_then(|value| value.to_str().ok()).map(parse).unwrap_or_default();
    Some(Arc::new(parsed))
}

/// The active scope, to carry across a `tokio::spawn`.
pub fn capture() -> Option<Arc<Parsed>> {
    SCOPE.try_with(Arc::clone).ok()
}

/// Run `future` under `scope` (none: unscoped, process values).
pub async fn scoped<F: std::future::Future>(scope: Option<Arc<Parsed>>, future: F) -> F::Output {
    match scope {
        Some(scope) => SCOPE.scope(scope, future).await,
        None => future.await,
    }
}

/// [`scoped`] for synchronous code (tests, planners).
pub fn sync_scoped<R>(overrides: Overrides, work: impl FnOnce() -> R) -> R {
    SCOPE.sync_scope(Arc::new(Parsed { overrides, ..Parsed::default() }), work)
}

/// This request's overrides (none outside a debug scope).
pub fn current() -> Overrides {
    SCOPE.try_with(|scope| scope.overrides).unwrap_or_default()
}

/// Whether this request overrides any switch, or is an SQL probe (result
/// caches are bypassed either way).
pub fn active() -> bool {
    !current().is_empty() || in_probe()
}

/// NAN-3715: whether this request is an operator SQL probe. Probes never
/// write per-statement memos or result caches.
pub fn in_probe() -> bool {
    SCOPE.try_with(|scope| scope.probe.is_some()).unwrap_or(false)
}

/// NAN-3715: a probe's value of flag knob `name`, else `process`.
pub fn probe_flag(name: &'static str, process: bool) -> bool {
    debug_assert!(probe_knob(name).is_some_and(|knob| knob.kind == KnobKind::Flag), "unknown flag knob {name}");
    SCOPE.try_with(|scope| scope.probe.as_ref().and_then(|probe| probe.knobs.get(name).copied()))
        .ok().flatten().map_or(process, |value| value != 0)
}

/// NAN-3715: a probe's value of count knob `name` (`None`: the default).
pub fn probe_count(name: &'static str) -> Option<u64> {
    debug_assert!(probe_knob(name).is_some_and(|knob| matches!(knob.kind, KnobKind::Count { .. })), "unknown count knob {name}");
    SCOPE.try_with(|scope| scope.probe.as_ref().and_then(|probe| probe.knobs.get(name).copied())).ok().flatten()
}

/// NAN-3715: a probe's chDB settings (empty outside a probe).
pub fn probe_settings() -> Vec<(&'static str, String)> {
    SCOPE.try_with(|scope| scope.probe.as_ref().map(|probe| probe.settings.clone())).ok().flatten().unwrap_or_default()
}

/// Effective `NANO_LAKE_FLAT_FILTER_LEAVES` given the process value.
pub fn flat_filter_leaves(process: bool) -> bool {
    current().flat_filter_leaves.unwrap_or(process)
}

/// Effective `NANO_LAKE_LANE_ROUTING_V2` given the large lane's value.
pub fn lane_routing_v2(process: bool) -> bool {
    current().lane_routing_v2.unwrap_or(process)
}

/// Effective `NANO_LAKE_IDENTITY_MERGED_INDEX` given the process value.
pub fn identity_merged_index(process: bool) -> bool {
    current().identity_merged_index.unwrap_or(process)
}

/// Effective `NANO_LAKE_ENTITY_INDEX` given the process value (NAN-4190).
pub fn entity_index(process: bool) -> bool {
    current().entity_index.unwrap_or(process)
}

/// This request's `payload_threads` / `payload_block_rows`, else the
/// process values (unclamped; the planner clamps).
pub fn payload_read(process_threads: Option<u64>, process_block_rows: Option<u64>) -> (Option<u64>, Option<u64>) {
    let current = current();
    (current.payload_threads.or(process_threads), current.payload_block_rows.or(process_block_rows))
}

fn switch(env: bool, value: Option<bool>) -> Value {
    json!({"env": env, "override": value, "effective": value.unwrap_or(env)})
}

fn knob(env: Option<u64>, value: Option<u64>, effective: u64) -> Value {
    json!({"env": env, "override": value, "effective": effective})
}

/// The effective switches of this debug request (`None` outside one):
/// per switch its env default, the override (or null) and the value used,
/// plus the process-level names that were ignored.
pub fn evidence() -> Option<Value> {
    let scope = capture()?;
    let overrides = scope.overrides;
    let (env_threads, env_rows) = (crate::planner::payload_max_threads_env(), crate::planner::payload_block_rows_env());
    let (threads, rows) = crate::planner::payload_read_settings(
        overrides.payload_threads.or(env_threads), overrides.payload_block_rows.or(env_rows), crate::part_query::lanes::INTERACTIVE_MAX_THREADS);
    Some(json!({
        "flat_filter_leaves": switch(crate::planner::flat_filter_leaves_env(), overrides.flat_filter_leaves),
        "lane_routing_v2": switch(crate::part_query::lanes::lane_routing_v2_enabled(), overrides.lane_routing_v2),
        "identity_merged_index": switch(crate::part_query::identity_merged::enabled(), overrides.identity_merged_index),
        "entity_index": switch(crate::part_query::entity_index::enabled(), overrides.entity_index),
        // Effective before the tenant's thread budget (the plan may lower it).
        "payload_threads": knob(env_threads, overrides.payload_threads, threads),
        "payload_block_rows": knob(env_rows, overrides.payload_block_rows, rows),
        "result_cache_bypassed": !overrides.is_empty(),
        "process_level_ignored": scope.process_level_ignored,
        "invalid_entries": scope.invalid,
    }))
}

/// Add [`evidence`] to `answer["planner"]["perf_switches"]` (debug only).
pub fn annotate(answer: &mut Value) {
    let Some(evidence) = evidence() else { return };
    let Some(object) = answer.as_object_mut() else { return };
    let planner = object.entry("planner").or_insert_with(|| json!({}));
    if let Some(planner) = planner.as_object_mut() {
        planner.insert("perf_switches".to_string(), evidence);
    }
}

/// Router middleware: runs the request under its scope ([`from_headers`]).
pub async fn middleware(request: axum::extract::Request, next: axum::middleware::Next) -> axum::response::Response {
    let scope = from_headers(request.headers());
    scoped(scope, next.run(request)).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::{HeaderMap, HeaderValue};

    fn headers(pairs: &[(&'static str, &'static str)]) -> HeaderMap {
        let mut map = HeaderMap::new();
        for (name, value) in pairs {
            map.insert(*name, HeaderValue::from_static(value));
        }
        map
    }

    #[test]
    fn parses_known_switches_and_skips_the_rest() {
        let parsed = parse("flat_filter_leaves=1, lane_routing_v2=off,identity_merged_index=TRUE,prewarm_throttle=0,bogus=1,flat_filter_leaves");
        assert_eq!(parsed.overrides, Overrides { flat_filter_leaves: Some(true), lane_routing_v2: Some(false), identity_merged_index: Some(true), ..Overrides::default() });
        assert_eq!(parsed.process_level_ignored, vec!["prewarm_throttle"]);
        assert_eq!(parsed.invalid, 2);
        assert!(parse("").overrides.is_empty());
        assert!(parse("flat_filter_leaves=maybe").overrides.is_empty());
        let long = format!("flat_filter_leaves=1,{}", "x".repeat(MAX_HEADER_BYTES));
        assert!(parse(&long).overrides.is_empty());
    }

    /// NAN-3411: numeric payload knobs take positive decimals only.
    #[test]
    fn parses_numeric_payload_knobs() {
        let parsed = parse("payload_threads=4, PAYLOAD_BLOCK_ROWS=1024");
        assert_eq!(parsed.overrides, Overrides { payload_threads: Some(4), payload_block_rows: Some(1024), ..Overrides::default() });
        assert_eq!(parsed.invalid, 0);
        assert!(!parsed.overrides.is_empty(), "a numeric override bypasses the result caches");
        for bad in ["payload_threads=0", "payload_threads=on", "payload_threads=-2", "payload_threads=1234567", "payload_block_rows=1.5"] {
            let parsed = parse(bad);
            assert!(parsed.overrides.is_empty(), "{bad}");
            assert_eq!(parsed.invalid, 1, "{bad}");
        }
        sync_scoped(Overrides { payload_threads: Some(3), ..Overrides::default() }, || {
            assert!(active());
            assert_eq!(payload_read(Some(2), Some(256)), (Some(3), Some(256)));
        });
        assert_eq!(payload_read(None, None), (None, None), "outside a scope: the process values");
        assert_eq!(payload_read(Some(2), None), (Some(2), None));
    }

    /// Without `x-nano-search-debug: 1` the header is ignored: no scope.
    #[test]
    fn overrides_need_the_debug_header() {
        assert!(from_headers(&headers(&[(HEADER, "flat_filter_leaves=1")])).is_none());
        assert!(from_headers(&headers(&[(HEADER, "flat_filter_leaves=1"), (DEBUG_HEADER, "true")])).is_none());
        let scope = from_headers(&headers(&[(HEADER, "flat_filter_leaves=1"), (DEBUG_HEADER, "1")])).unwrap();
        assert_eq!(scope.overrides.flat_filter_leaves, Some(true));
        // Debug alone: a scope with no overrides (evidence only).
        assert!(from_headers(&headers(&[(DEBUG_HEADER, "1")])).unwrap().overrides.is_empty());
    }

    #[tokio::test]
    async fn overrides_apply_inside_the_scope_only() {
        assert!(!flat_filter_leaves(false) && lane_routing_v2(true) && identity_merged_index(true));
        assert!(evidence().is_none());
        let scope = from_headers(&headers(&[(HEADER, "flat_filter_leaves=1,lane_routing_v2=0,identity_merged_index=0"), (DEBUG_HEADER, "1")]));
        scoped(scope, async {
            assert!(active());
            assert!(flat_filter_leaves(false));
            assert!(!lane_routing_v2(true));
            assert!(!identity_merged_index(true));
            let evidence = evidence().unwrap();
            assert_eq!(evidence["flat_filter_leaves"]["override"], true);
            assert_eq!(evidence["flat_filter_leaves"]["effective"], true);
            assert_eq!(evidence["lane_routing_v2"]["effective"], false);
            assert_eq!(evidence["result_cache_bypassed"], true);
            let mut answer = json!({"ok": true});
            annotate(&mut answer);
            assert_eq!(answer["planner"]["perf_switches"]["identity_merged_index"]["override"], false);
            // A spawned task does not inherit the scope unless carried.
            assert!(!tokio::spawn(async { active() }).await.unwrap());
            assert!(tokio::spawn(scoped(capture(), async { active() })).await.unwrap());
        })
        .await;
        assert!(!active());
        let mut answer = json!({"ok": true});
        annotate(&mut answer);
        assert_eq!(answer, json!({"ok": true}), "no debug scope: the answer is unchanged");
    }
}
