// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-3393: interactive lane routing by reader memory.
//!
//! The query role runs interactive statements on size classes (NAN-3077,
//! [`super::memory_budget::LaneClasses`]): six 256 MiB small lanes and a
//! large lane. Routing used to look at the estimated scan bytes only, so a
//! statement that decodes wide text (`message`, `raw_data`, `enrichments`)
//! with eight threads ran on a small lane first, failed MEMORY_LIMIT and ran
//! again on the single large lane, where two users' 7 d scans queued for up
//! to 16 s. Here:
//!
//! - every interactive statement runs on at most [`INTERACTIVE_MAX_THREADS`]
//!   (the query role is guaranteed ~4 cores; eight threads per statement
//!   only oversubscribed them and doubled peak memory);
//! - a wide-text statement gets a bounded Parquet reader on a small lane
//!   ([`bounded_reader_sql`]), so it fits there instead of failing;
//! - a statement that still needed a bigger lane is remembered per query,
//!   window class and statement shape ([`LaneMemo`]), so it never retries
//!   the smaller lane in this process again;
//! - the large lane is [`LargeLane`]: two statements at half its memory
//!   each, and a statement that outgrows half takes the whole lane (both
//!   permits), so the sum of statement caps never exceeds chDB's server
//!   memory.
//!
//! - NAN-3650: a statement refused by the top class runs once more on the
//!   last rung, [`LaneClass::Degraded`]: the whole large lane with one
//!   thread and a bounded Parquet reader ([`degraded_sql`]), spilling GROUP
//!   BY / ORDER BY at half the cap to the query role's `$TMPDIR` (chDB's
//!   embedded path, on the per-pod data volume, bounded by
//!   `max_temporary_data_on_disk_size_for_query`). Slower, but it finishes
//!   instead of answering MEMORY_LIMIT; if even that refuses, the error
//!   names the cap ([`ExecutorError::MemoryExhausted`]).
//!
//! Every change here is an execution setting: no statement's rows change.
//!
//! Kill switch: `NANO_LAKE_LANE_ROUTING_V2=0` (read once when the engine
//! opens; unset or any other value is on) restores the NAN-3077 router: one
//! large connection with all of the large memory, scan-size routing with a
//! single large-lane retry, no bounded reader, no memo and the planner's own
//! thread counts. Roles without size classes (detect, product) never take
//! any of the above, on or off.

use super::memory_budget::{is_memory_limit_error, MIB, MIN_LARGE_QUERY_BYTES, SMALL_QUERY_BYTES};
use crate::executor::{ExecutorError, NativeExecutor};
use crate::native::NativeQueryOutput;
use crate::planner::{NativeQueryPlan, ReaderShape};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Instant;

/// Interactive statements' thread cap.
pub const INTERACTIVE_MAX_THREADS: u64 = 4;
/// A bounded wide-text reader's threads on a small lane.
pub const BOUNDED_READER_THREADS: u64 = 2;
/// Decoded bytes one row group of one wide column is assumed to hold
/// (65,536 rows x ~1 KiB of `raw_data`).
pub const WIDE_COLUMN_GROUP_BYTES: u64 = 64 * MIB;
/// Statements on the large lane at once, when its memory affords it.
pub const MAX_LARGE_LANES: usize = 2;
/// Remembered lane outcomes per process (a full memo is rebuilt).
const MEMO_ENTRIES: usize = 4_096;

/// The lane class a statement runs on, smallest first.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum LaneClass {
    Small,
    /// One permit of the large lane: its memory / its width.
    Large,
    /// Every permit of the large lane: all of its memory.
    LargeFull,
    /// NAN-3650, the last rung: all of the large lane's memory, one thread,
    /// a bounded reader and disk spill ([`degraded_sql`]).
    Degraded,
}

impl LaneClass {
    pub fn label(self) -> &'static str {
        match self {
            Self::Small => "small",
            Self::Large => "large",
            Self::LargeFull => "large_full",
            Self::Degraded => "degraded",
        }
    }
}

/// How many statements a large lane of `large_bytes` runs at once: two at
/// half each when half is still a large lane ([`MIN_LARGE_QUERY_BYTES`]).
pub fn large_lane_width(large_bytes: u64) -> usize {
    if large_bytes / MAX_LARGE_LANES as u64 >= MIN_LARGE_QUERY_BYTES { MAX_LARGE_LANES } else { 1 }
}

/// The kill switch's variable (see the module docs).
pub const LANE_ROUTING_V2_ENV: &str = "NANO_LAKE_LANE_ROUTING_V2";

/// Whether this process routes interactive statements the NAN-3393 way:
/// on unless `NANO_LAKE_LANE_ROUTING_V2` is literally `0`.
pub fn lane_routing_v2_enabled() -> bool {
    routing_v2(std::env::var(LANE_ROUTING_V2_ENV).ok().as_deref())
}

fn routing_v2(value: Option<&str>) -> bool {
    value != Some("0")
}

/// The large lane's connection count: [`large_lane_width`] with routing v2,
/// else one (NAN-3077: a single statement with all of the large memory).
pub fn large_lane_connections(large_bytes: u64, routing_v2: bool) -> usize {
    if routing_v2 { large_lane_width(large_bytes) } else { 1 }
}

/// The large lane: an executor of `width` connections, gated by `width`
/// permits so that a statement needing all of its memory runs alone.
#[derive(Clone)]
pub struct LargeLane {
    executor: NativeExecutor,
    bytes: u64,
    width: u32,
    permits: Arc<tokio::sync::Semaphore>,
    /// `false`: `NANO_LAKE_LANE_ROUTING_V2=0`, the NAN-3077 router.
    routing_v2: bool,
}

impl LargeLane {
    /// `bytes` is the whole lane's memory; the width is the executor's
    /// connection count (at most [`MAX_LARGE_LANES`]).
    pub fn new(executor: NativeExecutor, bytes: u64) -> Self {
        Self::with_routing(executor, bytes, true)
    }

    /// [`Self::new`], or with `routing_v2` false the NAN-3077 lane: one
    /// statement at a time with all of `bytes`, whatever the executor's width.
    pub fn with_routing(executor: NativeExecutor, bytes: u64, routing_v2: bool) -> Self {
        let width = if routing_v2 { executor.connection_count().clamp(1, MAX_LARGE_LANES) as u32 } else { 1 };
        Self { executor, bytes, width, permits: Arc::new(tokio::sync::Semaphore::new(width as usize)), routing_v2 }
    }

    /// Whether this lane routes the NAN-3393 way (see [`lane_routing_v2_enabled`]).
    pub fn routing_v2(&self) -> bool {
        self.routing_v2
    }

    /// Statements this lane runs at once.
    pub fn width(&self) -> usize {
        self.width as usize
    }

    /// The whole lane's memory (a durable job's cap).
    pub fn bytes(&self) -> u64 {
        self.bytes
    }

    /// A statement's memory cap in `class`.
    pub fn cap_bytes(&self, class: LaneClass) -> u64 {
        match class {
            LaneClass::LargeFull | LaneClass::Degraded => self.bytes,
            _ => self.bytes / u64::from(self.width),
        }
    }

    pub fn executor(&self) -> &NativeExecutor {
        &self.executor
    }

    /// The class above `class` on this lane, if any (see [`next_class`]).
    fn escalate(&self, class: LaneClass) -> Option<LaneClass> {
        next_class(self.width, class)
    }

    async fn run(&self, plan: NativeQueryPlan, class: LaneClass) -> Result<NativeQueryOutput, ExecutorError> {
        let permits = if matches!(class, LaneClass::LargeFull | LaneClass::Degraded) { self.width } else { 1 };
        let started = Instant::now();
        let permit = match tokio::time::timeout(self.executor.lane_wait_timeout(), self.permits.clone().acquire_many_owned(permits)).await {
            Ok(Ok(permit)) => permit,
            Ok(Err(_)) => return Err(ExecutorError::Unavailable),
            Err(_) => {
                crate::query_timing::record(|p| p.outcome = Some("lane_wait_timeout"));
                tracing::warn!(outcome = "lane_wait_timeout", class = class.label(), "large lane permit wait timed out");
                return Err(ExecutorError::LaneWaitTimeout);
            }
        };
        let gate_wait = started.elapsed();
        crate::query_timing::record(|p| p.lane_wait_ms += gate_wait.as_secs_f64() * 1000.0);
        let mut plan = super::engine::with_memory_cap(plan, self.cap_bytes(class));
        if class == LaneClass::Degraded {
            plan.sql = degraded_sql(&plan.sql);
        }
        let output = super::engine::run_on_routed(&self.executor, plan, Route { class, bounded: false, gate_wait_ms: gate_wait.as_secs_f64() * 1000.0 }).await;
        drop(permit);
        output
    }
}

/// The class above `class` on a large lane `width` wide, if any. NAN-3650:
/// the top class (the whole lane) is followed by [`LaneClass::Degraded`],
/// so a statement is never refused for size while a cheaper way to run it
/// remains.
fn next_class(width: u32, class: LaneClass) -> Option<LaneClass> {
    match class {
        LaneClass::Small => Some(LaneClass::Large),
        LaneClass::Large if width > 1 => Some(LaneClass::LargeFull),
        LaneClass::Large | LaneClass::LargeFull => Some(LaneClass::Degraded),
        LaneClass::Degraded => None,
    }
}

/// Normalize `class` to a large lane `width` wide (one-wide: Large == Full).
fn normalize(width: u32, class: LaneClass) -> LaneClass {
    if class == LaneClass::LargeFull && width == 1 { LaneClass::Large } else { class }
}

/// How [`run_sized`] starts a statement on the size classes. NAN-3406: the
/// router (`v2`) is the large lane's process value unless this request
/// overrides `lane_routing_v2`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Start {
    /// Routed the NAN-3393 way (else [`run_sized_v1`]).
    pub v2: bool,
    /// The first lane class (v1: by scan size only).
    pub class: LaneClass,
    /// The statement as it is first run (v2: threads capped).
    pub sql: String,
    /// The lane memo entry consulted and written (v2 only).
    pub memo_key: Option<String>,
}

pub(crate) fn start(routing_v2: bool, width: u32, memo: &LaneMemo, plan: &NativeQueryPlan) -> Start {
    let by_size = if super::engine::needs_large_lane(plan.budget.estimated_scan_bytes) { LaneClass::Large } else { LaneClass::Small };
    if !crate::perf_overrides::lane_routing_v2(routing_v2) {
        return Start { v2: false, class: by_size, sql: plan.sql.clone(), memo_key: None };
    }
    let memo_key = LaneMemo::key(plan);
    let remembered = memo_key.as_deref().map_or(LaneClass::Small, |key| memo.needed(key));
    Start { v2: true, class: normalize(width, remembered.max(by_size)), sql: cap_threads(&plan.sql, INTERACTIVE_MAX_THREADS), memo_key }
}

/// How a statement was routed (for the debug evidence).
#[derive(Clone, Copy, Debug)]
pub struct Route {
    pub class: LaneClass,
    /// Ran with [`bounded_reader_sql`].
    pub bounded: bool,
    /// Wait for a large-lane permit (before the executor's own lane wait).
    pub gate_wait_ms: f64,
}

/// Remembered "needed a bigger lane" outcomes, keyed by query, window
/// class and statement shape. Only escalations are stored, so a statement
/// that fits where it starts costs nothing here.
#[derive(Default)]
pub struct LaneMemo {
    needed: Mutex<HashMap<String, LaneClass>>,
}

impl LaneMemo {
    /// The memo key of `plan`; `None` for statements without a query hash
    /// (trusted typed routes). NAN-3406: a statement planned with flat
    /// filter leaves is another shape (its reader memory differs), so the
    /// effective flat-leaf mode is part of the key: one A/B mode's
    /// escalations never route the other's statements.
    ///
    /// NAN-3411: non-default payload reader threads / block rows decode more
    /// at once, so they are part of the key too (empty at the defaults: the
    /// key is unchanged), and an escalation under one A/B mode never routes
    /// the other's statements.
    pub fn key(plan: &NativeQueryPlan) -> Option<String> {
        let flat = if crate::planner::flat_filter_leaves_enabled() { ":flat" } else { "" };
        let payload = payload_key_suffix();
        (!plan.query_sha256.is_empty())
            .then(|| format!("{}:{}:{:016x}{flat}{payload}", plan.query_sha256, plan.reader.window_class, plan.reader.columns_key))
    }

    pub fn needed(&self, key: &str) -> LaneClass {
        self.needed.lock().expect("lane memo").get(key).copied().unwrap_or(LaneClass::Small)
    }

    pub fn remember(&self, key: &str, class: LaneClass) {
        let mut needed = self.needed.lock().expect("lane memo");
        if needed.len() >= MEMO_ENTRIES && !needed.contains_key(key) {
            needed.clear();
        }
        let entry = needed.entry(key.to_string()).or_insert(class);
        *entry = (*entry).max(class);
    }

    pub fn len(&self) -> usize {
        self.needed.lock().expect("lane memo").len()
    }
}

/// NAN-3411: `:p{threads}x{rows}` for non-default effective payload reader
/// settings (before a tenant's own thread budget), else empty.
fn payload_key_suffix() -> String {
    use crate::planner::{payload_block_rows_env, payload_max_threads_env, payload_read_settings, PAYLOAD_DEFAULT_BLOCK_ROWS, PAYLOAD_DEFAULT_THREADS};
    let (threads, rows) = crate::perf_overrides::payload_read(payload_max_threads_env(), payload_block_rows_env());
    match payload_read_settings(threads, rows, INTERACTIVE_MAX_THREADS) {
        (PAYLOAD_DEFAULT_THREADS, PAYLOAD_DEFAULT_BLOCK_ROWS) => String::new(),
        (threads, rows) => format!(":p{threads}x{rows}"),
    }
}

/// Run one interactive statement on the size classes: capped threads; the
/// smallest class its scan estimate and the memo allow; a bounded reader on
/// a small lane for wide text; one step up (remembered) on a memory refusal.
pub async fn run_sized(
    small: &NativeExecutor,
    large: Option<&LargeLane>,
    memo: &LaneMemo,
    mut plan: NativeQueryPlan,
) -> Result<NativeQueryOutput, ExecutorError> {
    // No size classes: detect and product run rule/product statements, not
    // the query role's interactive ones, so their threads stay as planned.
    let Some(large) = large else {
        return super::engine::run_on_routed(small, plan, Route { class: LaneClass::Small, bounded: false, gate_wait_ms: 0.0 }).await;
    };
    // NAN-3406: the routing decision is per request (an authorized
    // `lane_routing_v2` override); the lane's width is the process's.
    let Start { v2, class, sql, memo_key: key } = start(large.routing_v2, large.width, memo, &plan);
    if !v2 {
        return run_sized_v1(small, large, plan).await;
    }
    plan.sql = sql;
    let first = class;
    let mut class = class;
    loop {
        let result = match class {
            LaneClass::Small => {
                let bounded = needs_bounded_reader(&plan.reader, setting(&plan.sql, "max_threads").unwrap_or(INTERACTIVE_MAX_THREADS));
                let mut small_plan = plan.clone();
                if bounded {
                    small_plan.sql = bounded_reader_sql(&small_plan.sql, BOUNDED_READER_THREADS);
                }
                super::engine::run_on_routed(small, small_plan, Route { class, bounded, gate_wait_ms: 0.0 }).await
            }
            _ => large.run(plan.clone(), class).await,
        };
        match result {
            // A statement memory refusal (not a result-size one: that would
            // refuse on a bigger lane too).
            Err(error) if is_memory_limit_error(&error.to_string()) => {
                let Some(next) = large.escalate(class) else {
                    // NAN-3650: even the degraded rung refused. Name the cap
                    // and the rung; never an empty or cancelled answer.
                    tracing::warn!(error = %error, cap_bytes = large.cap_bytes(class), class = class.label(),
                        "statement exceeded every lane class, including the degraded rung");
                    return Err(ExecutorError::MemoryExhausted { cap_bytes: large.cap_bytes(class), class: class.label(), detail: error.to_string() });
                };
                tracing::info!(error = %error, from = class.label(), to = next.label(), "statement exceeded its lane; retrying one class up");
                // A chDB-wide refusal ("(total) memory limit") is contention,
                // not this statement's size: escalate now, remember nothing.
                // NAN-3715: an SQL probe never writes the memo.
                if let Some(key) = key.as_ref().filter(|_| !error.to_string().contains("(total)") && !crate::perf_overrides::in_probe()) {
                    memo.remember(key, next);
                }
                class = next;
            }
            Ok(output) => {
                if class != first {
                    tracing::info!(from = first.label(), finished_on = class.label(), cap_bytes = large.cap_bytes(class),
                        "statement finished after lane escalation");
                }
                return Ok(output);
            }
            other => return other,
        }
    }
}

/// `NANO_LAKE_LANE_ROUTING_V2=0`: the NAN-3077 router, unchanged. A small
/// lane, or the large lane (all of its memory) when the scan estimate
/// exceeds `LARGE_SCAN_BYTES` or the statement ran out of a small lane.
///
/// NAN-3406: on a v2 process's two-wide large lane (a per-request
/// `lane_routing_v2=0`), a large statement takes every permit, so it runs
/// alone with all of the lane's memory exactly as on the one-wide v1 lane
/// and never co-runs past chDB's server memory.
async fn run_sized_v1(small: &NativeExecutor, large: &LargeLane, plan: NativeQueryPlan) -> Result<NativeQueryOutput, ExecutorError> {
    let on_large = |plan: NativeQueryPlan| async move {
        if large.width > 1 {
            return large.run(plan, LaneClass::LargeFull).await;
        }
        super::engine::run_on_routed(
            &large.executor, super::engine::with_memory_cap(plan, large.bytes),
            Route { class: LaneClass::Large, bounded: false, gate_wait_ms: 0.0 }).await
    };
    if super::engine::needs_large_lane(plan.budget.estimated_scan_bytes) {
        return on_large(plan).await;
    }
    match super::engine::run_on_routed(small, plan.clone(), Route { class: LaneClass::Small, bounded: false, gate_wait_ms: 0.0 }).await {
        // A statement memory refusal (not a result-size one: that would
        // refuse on the large lane too).
        Err(error) if is_memory_limit_error(&error.to_string()) => {
            tracing::info!(error = %error, "statement exceeded a small lane; retrying on the large lane");
            on_large(plan).await
        }
        other => other,
    }
}

/// Whether a statement's decoded wide text (row groups in flight x wide
/// columns) would take more than half of a small lane at `threads`.
pub fn needs_bounded_reader(shape: &ReaderShape, threads: u64) -> bool {
    shape.wide_columns > 0
        && shape.row_groups.min(threads.max(1)).saturating_mul(shape.wide_columns).saturating_mul(WIDE_COLUMN_GROUP_BYTES)
            > SMALL_QUERY_BYTES / 2
}

/// `sql` with its `max_threads` at most `threads` (a statement without
/// one is left alone).
pub fn cap_threads(sql: &str, threads: u64) -> String {
    if setting(sql, "max_threads").is_some() { lower_setting(sql, "max_threads", threads) } else { sql.to_string() }
}

/// Reader-memory bounds for a wide-text statement on a small lane, like
/// the planner's full-payload bound (`planner::bounded_payload_settings`)
/// but sized for an aggregate: chDB's Parquet reader (v3) prefetches row
/// groups up to `input_format_parquet_memory_high_watermark` (default
/// 4 GiB), far past a 256 MiB statement cap, and decodes 64k-row blocks of
/// up to 16 MiB. Measured on 24 files x 4 row groups of ~300 B message +
/// ~1 KiB raw_data (`lanes::native`): the live hash statement needs 384 MiB
/// at 8 or 4 threads, and fits 128 MiB bounded (wall +20% on 16 cores, where
/// 4 vs 8 threads made no difference). Every value only ever lowers the
/// statement's own, and none of them changes what a statement returns.
pub fn bounded_reader_sql(sql: &str, threads: u64) -> String {
    let mut sql = sql.to_string();
    for (name, value) in [
        ("max_threads", threads),
        ("input_format_parquet_max_block_size", 8_192),
        ("input_format_parquet_prefer_block_bytes", 2 * MIB),
        ("input_format_parquet_memory_high_watermark", 32 * MIB),
    ] {
        sql = lower_setting(&sql, name, value);
    }
    sql
}

/// NAN-3650: the degraded rung's settings, for a statement the whole large
/// lane refused. The 2026-10-12 refusal was in the read stage (`ColumnData:
/// column: user.name` at 768 MiB), which spilling GROUP BY cannot fix, so
/// this bounds the reader to about one row group in flight: one thread
/// (`max_threads`, `max_parsing_threads`), small output blocks and a low
/// Parquet prefetch watermark. GROUP BY / ORDER BY already spill at half the
/// cap (`engine::with_memory_cap`, `planner::external_processing_limits`),
/// to the query role's `$TMPDIR` on the data volume. Like
/// [`bounded_reader_sql`], every value only lowers the statement's own and
/// none changes what it returns.
pub fn degraded_sql(sql: &str) -> String {
    let mut sql = bounded_reader_sql(sql, 1);
    for (name, value) in [
        ("max_parsing_threads", 1),
        ("max_block_size", 4_096),
        ("preferred_block_size_bytes", MIB),
        ("input_format_parquet_max_block_size", 4_096),
        ("input_format_parquet_prefer_block_bytes", MIB),
        ("input_format_parquet_memory_high_watermark", 16 * MIB),
    ] {
        sql = lower_setting(&sql, name, value);
    }
    sql
}

/// The numeric value of `name` in the statement's trailing settings.
pub fn setting(sql: &str, name: &str) -> Option<u64> {
    let pattern = regex::Regex::new(&format!(r"\b{name}\s*=\s*(\d+)\b")).expect("setting regex");
    let clause = crate::executor::statement_settings(sql)?;
    pattern.captures(clause).and_then(|found| found[1].parse().ok())
}

/// `sql` with its trailing `SETTINGS name=value` at most `value`.
pub fn lower_setting(sql: &str, name: &str, value: u64) -> String {
    let sql = sql.trim_end();
    let pattern = regex::Regex::new(&format!(r"\b{name}\s*=\s*(\d+)\b")).expect("setting regex");
    if let Some(clause) = crate::executor::statement_settings(sql) {
        if let Some(found) = pattern.captures(clause) {
            let current = found[1].parse::<u64>().unwrap_or(u64::MAX);
            if current <= value {
                return sql.to_string();
            }
            let start = sql.len() - clause.len();
            return format!("{}{}", &sql[..start], pattern.replace(clause, format!("{name}={value}")));
        }
    }
    crate::executor::with_setting(sql, &format!("{name}={value}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::memory_budget::GIB;

    fn shape(wide_columns: u64, row_groups: u64) -> ReaderShape {
        ReaderShape { wide_columns, row_groups, window_class: 8, columns_key: 7 }
    }

    #[test]
    fn interactive_threads_are_capped_never_raised() {
        let sql = "SELECT 1 SETTINGS max_threads=8, max_execution_time=55, max_parsing_threads=8";
        assert_eq!(cap_threads(sql, 4), "SELECT 1 SETTINGS max_threads=4, max_execution_time=55, max_parsing_threads=8");
        assert_eq!(cap_threads("SELECT 1 SETTINGS max_threads=1", 4), "SELECT 1 SETTINGS max_threads=1");
        // No thread setting: nothing is added.
        assert_eq!(cap_threads("SELECT 1", 4), "SELECT 1");
        assert_eq!(cap_threads("SELECT 'max_threads=9' SETTINGS use_query_cache=0", 4), "SELECT 'max_threads=9' SETTINGS use_query_cache=0");
    }

    #[test]
    fn bounded_reader_only_lowers_settings() {
        let sql = "SELECT 1 SETTINGS max_threads=4, max_block_size=8192, input_format_parquet_prefer_block_bytes=65536";
        assert_eq!(
            bounded_reader_sql(sql, 2),
            "SELECT 1 SETTINGS max_threads=2, max_block_size=8192, input_format_parquet_prefer_block_bytes=65536, \
             input_format_parquet_max_block_size=8192, input_format_parquet_memory_high_watermark=33554432"
        );
        // A payload-bounded statement (max_threads=1, 128-row blocks) keeps its tighter values.
        let payload = crate::planner::bounded_payload_settings("SELECT 1 SETTINGS max_threads=4".into(), 4);
        let bounded = bounded_reader_sql(&payload, 2);
        for kept in ["max_threads=1", "input_format_parquet_max_block_size=128", "input_format_parquet_prefer_block_bytes=1048576",
            "input_format_parquet_memory_high_watermark=33554432"] {
            assert!(bounded.contains(kept), "{kept}: {bounded}");
        }
        assert_eq!(setting(&bounded, "max_threads"), Some(1));
    }

    /// NAN-3650: the degraded rung only lowers settings (one thread, small
    /// blocks, low Parquet watermark) and keeps a tighter value.
    #[test]
    fn degraded_sql_bounds_the_reader_and_only_lowers() {
        let sql = "SELECT 1 SETTINGS max_threads=4, max_memory_usage=1610612736, max_bytes_before_external_group_by=805306368, \
                   max_block_size=8192, preferred_block_size_bytes=8388608, input_format_parquet_max_block_size=128";
        let degraded = degraded_sql(sql);
        for (name, value) in [("max_threads", 1), ("max_parsing_threads", 1), ("max_block_size", 4_096),
            ("preferred_block_size_bytes", MIB), ("input_format_parquet_max_block_size", 128),
            ("input_format_parquet_prefer_block_bytes", MIB), ("input_format_parquet_memory_high_watermark", 16 * MIB),
            ("max_memory_usage", 1_610_612_736), ("max_bytes_before_external_group_by", 805_306_368)] {
            assert_eq!(setting(&degraded, name), Some(value), "{name}: {degraded}");
        }
        assert_eq!(degraded_sql(&degraded), degraded, "idempotent");
    }

    /// NAN-3650: the ladder ends on the degraded rung, never on the top
    /// class, on one- and two-wide large lanes.
    #[test]
    fn ladder_ends_on_the_degraded_rung() {
        use LaneClass::*;
        let ladder = |width: u32| {
            let mut rungs = vec![Small];
            while let Some(next) = next_class(width, *rungs.last().unwrap()) { rungs.push(next); }
            rungs
        };
        assert_eq!(ladder(1), vec![Small, Large, Degraded]);
        assert_eq!(ladder(2), vec![Small, Large, LargeFull, Degraded]);
        assert!(Degraded > LargeFull, "the memo keeps the degraded rung once needed");
        assert_eq!(normalize(1, Degraded), Degraded);
    }

    #[test]
    fn wide_text_needs_a_bounded_reader_only_when_groups_in_flight_outgrow_half_a_small_lane() {
        // The live hash statement: message + raw_data over 387 kept row groups.
        assert!(needs_bounded_reader(&shape(2, 387), 4));
        // One wide column, one or two row groups in flight: 64-128 MiB fits.
        assert!(!needs_bounded_reader(&shape(1, 2), 4));
        assert!(!needs_bounded_reader(&shape(2, 1), 4));
        assert!(needs_bounded_reader(&shape(1, 3), 4));
        // Narrow statements never do, however many groups.
        assert!(!needs_bounded_reader(&shape(0, 10_000), 8));
        // Threads bound the groups in flight.
        assert!(!needs_bounded_reader(&shape(1, 387), 2));
    }

    #[test]
    fn memo_keeps_the_largest_class_per_query_window_and_shape() {
        let memo = LaneMemo::default();
        let mut plan = plan("SELECT 1", shape(2, 10));
        assert_eq!(LaneMemo::key(&plan), None, "no query hash, no memo");
        plan.query_sha256 = "ab".repeat(32);
        let key = LaneMemo::key(&plan).unwrap();
        assert_eq!(memo.needed(&key), LaneClass::Small);
        memo.remember(&key, LaneClass::LargeFull);
        memo.remember(&key, LaneClass::Large);
        assert_eq!(memo.needed(&key), LaneClass::LargeFull);
        // Another window class or statement shape of the same query is its own entry.
        let mut day = plan.clone();
        day.reader.window_class = 5;
        assert_ne!(LaneMemo::key(&day).unwrap(), key);
        let mut companion = plan.clone();
        companion.reader.columns_key = 8;
        assert_ne!(LaneMemo::key(&companion).unwrap(), key);
        for i in 0..MEMO_ENTRIES + 1 {
            memo.remember(&format!("k{i}"), LaneClass::Large);
        }
        assert!(memo.len() <= MEMO_ENTRIES);
    }

    /// NAN-3406: an authorized `lane_routing_v2` override flips the routing
    /// decision per request (router, thread cap, memo), either way; the
    /// lane memo is keyed by the effective flat-leaf mode; and without an
    /// override the decision is the process value's.
    #[test]
    fn lane_routing_override_flips_the_decision_per_request() {
        use crate::perf_overrides::{sync_scoped, Overrides};
        let memo = LaneMemo::default();
        let mut wide = plan("SELECT 1 SETTINGS max_threads=8", shape(2, 387));
        wide.query_sha256 = "ab".repeat(32);
        let routing = |value: Option<bool>| Overrides { lane_routing_v2: value, ..Overrides::default() };
        let flat = |value: bool| Overrides { flat_filter_leaves: Some(value), ..Overrides::default() };
        // v2 process, request asks for v1: NAN-3077 routing, threads as planned, no memo.
        let off = sync_scoped(routing(Some(false)), || start(true, 2, &memo, &wide));
        assert_eq!(off, Start { v2: false, class: LaneClass::Small, sql: wide.sql.clone(), memo_key: None });
        // v1 process, request asks for v2: capped threads and the memo.
        let on = sync_scoped(routing(Some(true)), || start(false, 1, &memo, &wide));
        assert!(on.v2 && on.sql.contains("max_threads=4") && on.memo_key.is_some(), "{on:?}");
        // No override: the process value, unchanged.
        assert_eq!(start(true, 2, &memo, &wide), sync_scoped(Overrides::default(), || start(true, 2, &memo, &wide)));
        assert!(start(true, 2, &memo, &wide).v2 && !start(false, 1, &memo, &wide).v2);
        // A remembered escalation is read by v2 only.
        memo.remember(on.memo_key.as_deref().unwrap(), LaneClass::LargeFull);
        assert_eq!(sync_scoped(routing(Some(true)), || start(false, 2, &memo, &wide)).class, LaneClass::LargeFull);
        assert_eq!(sync_scoped(routing(Some(true)), || start(false, 1, &memo, &wide)).class, LaneClass::Large);
        assert_eq!(sync_scoped(routing(Some(false)), || start(true, 2, &memo, &wide)).class, LaneClass::Small);
        // The memo separates flat-leaf modes: one mode's escalation never routes the other.
        let flat_key = sync_scoped(flat(true), || LaneMemo::key(&wide)).unwrap();
        let nested_key = sync_scoped(flat(false), || LaneMemo::key(&wide)).unwrap();
        assert_ne!(flat_key, nested_key);
        let modes = LaneMemo::default();
        modes.remember(&flat_key, LaneClass::Large);
        assert_eq!(modes.needed(&nested_key), LaneClass::Small);
    }

    /// NAN-3411: payload reader overrides key the lane memo apart; the
    /// defaults (and an override equal to them) keep the key unchanged.
    #[test]
    fn payload_read_override_keys_the_lane_memo_apart() {
        use crate::perf_overrides::{sync_scoped, Overrides};
        let mut wide = plan("SELECT 1 SETTINGS max_threads=1", shape(0, 387));
        wide.query_sha256 = "cd".repeat(32);
        let payload = |threads: Option<u64>, rows: Option<u64>| Overrides { payload_threads: threads, payload_block_rows: rows, ..Overrides::default() };
        let base = LaneMemo::key(&wide).unwrap();
        assert!(!base.contains(":p"), "{base}");
        assert_eq!(sync_scoped(payload(Some(1), Some(128)), || LaneMemo::key(&wide)).unwrap(), base);
        let four = sync_scoped(payload(Some(4), None), || LaneMemo::key(&wide)).unwrap();
        assert_eq!(four, format!("{base}:p4x128"));
        // Clamped like the planner: 64 threads is the 4-thread key.
        assert_eq!(sync_scoped(payload(Some(64), None), || LaneMemo::key(&wide)).unwrap(), four);
        let memo = LaneMemo::default();
        memo.remember(&four, LaneClass::LargeFull);
        assert_eq!(memo.needed(&base), LaneClass::Small);
    }

    #[test]
    fn large_lane_is_two_wide_only_when_half_is_still_a_large_lane() {
        // The 4 GiB query role (the load-test tenant): 3 GiB chDB = 6 x 256 MiB + 1.5 GiB large.
        assert_eq!(large_lane_width(3 * GIB / 2), 2);
        assert_eq!(large_lane_width(2 * MIN_LARGE_QUERY_BYTES), 2);
        // The 3 GiB role: 2.25 GiB chDB = 6 x 256 MiB + 768 MiB large.
        assert_eq!(large_lane_width(768 * MIB), 1);
        assert_eq!(large_lane_width(2 * MIN_LARGE_QUERY_BYTES - 1), 1);
    }

    /// The kill switch: only a literal `0` turns routing v2 off, and off is
    /// NAN-3077's layout (one large connection with all of the large memory).
    #[test]
    fn lane_routing_v2_zero_restores_the_single_large_lane() {
        assert!(routing_v2(None));
        assert!(routing_v2(Some("1")));
        assert!(routing_v2(Some("")));
        assert!(!routing_v2(Some("0")));
        // The 4 GiB role (the load-test tenant): 2 x 768 MiB on, 1 x 1.5 GiB off.
        assert_eq!(large_lane_connections(3 * GIB / 2, true), 2);
        assert_eq!(large_lane_connections(3 * GIB / 2, false), 1);
        assert_eq!(large_lane_connections(768 * MIB, true), 1);
        // The process reads the variable itself: rerun this test with `=0`.
        if std::env::var(LANE_ROUTING_V2_ENV).as_deref() != Ok("0") {
            assert!(lane_routing_v2_enabled() || std::env::var(LANE_ROUTING_V2_ENV).is_ok());
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "part_query::lanes::tests::lane_routing_v2_zero_restores_the_single_large_lane"])
                .env(LANE_ROUTING_V2_ENV, "0").output().unwrap();
            assert!(output.status.success(), "{}{}", String::from_utf8_lossy(&output.stdout), String::from_utf8_lossy(&output.stderr));
            assert!(String::from_utf8_lossy(&output.stdout).contains("1 passed"), "{}", String::from_utf8_lossy(&output.stdout));
            return;
        }
        assert!(!lane_routing_v2_enabled());
        assert_eq!(large_lane_connections(3 * GIB / 2, lane_routing_v2_enabled()), 1);
    }

    pub(super) fn plan(sql: &str, reader: ReaderShape) -> NativeQueryPlan {
        NativeQueryPlan {
            query_sha256: String::new(),
            sql: sql.into(),
            params: vec![],
            budget: crate::planner::QueryBudget { candidate_objects: 1, estimated_scan_bytes: 0, max_query_bytes: u64::MAX },
            native_event_rows: false,
            temporary_aliases: Default::default(),
            schema_defaults: vec![],
            reader,
        }
    }
}

#[cfg(test)]
#[path = "lane_routing_native_tests.rs"]
mod native;
