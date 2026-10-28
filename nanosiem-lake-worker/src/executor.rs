// SPDX-License-Identifier: AGPL-3.0-or-later

//! Bounded persistent native executors, each owned by a dedicated thread.

use crate::native::{NativeChdb, NativeChdbError, NativeQueryOutput};
use crate::planner::NativeQueryPlan;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::sync::Mutex;
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, oneshot};

// Use the process tracker, not sibling durable engines in the same cgroup.
// Keep the startup server ceiling and per-query max_memory_usage; only disable
// cgroup usage correction and pressure-driven shrinking of that static ceiling.
const EXECUTOR_MEMORY_ARGS: &[&str] = &[
    "--memory_worker_use_cgroup=0",
    "--memory_worker_dynamic_hard_limit=0",
    // Embedded chDB otherwise has no console channel. The cell supervisor
    // already forwards stderr; keep only fatal engine diagnostics (no SQL
    // tracing or ordinary query-error logging).
    "--logger.console=1",
    "--log-level=fatal",
];

/// Startup arguments for one executor connection.
///
/// `server_memory_limit_bytes` becomes chDB's engine-wide
/// `max_server_memory_usage` (NAN-2361). Per-query `max_memory_usage` bounds
/// one query; this bounds the sum of every concurrent query in the process,
/// so N lanes x per-query budget can no longer outgrow the container and get
/// the pod OOM-killed. A query that would cross it fails with chDB's
/// `(total) memory limit exceeded` (Code 241) instead.
///
/// chDB applies server settings once, from the first `chdb_connect` that
/// starts the embedded engine; later connections while it is open inherit
/// that value and their own server arguments are ignored (verified against
/// libchdb 26.7.0). Every connection in a process must therefore be opened
/// with the same value, which is why it is fixed per executor and resolved
/// once at boot by the caller.
pub fn executor_connection_args(server_memory_limit_bytes: Option<u64>) -> Vec<String> {
    let mut arguments = EXECUTOR_MEMORY_ARGS
        .iter()
        .map(|argument| (*argument).to_string())
        .collect::<Vec<_>>();
    if let Some(bytes) = server_memory_limit_bytes {
        arguments.push(format!("--max_server_memory_usage={bytes}"));
    }
    arguments
}
const EXECUTOR_QUEUE_DEPTH: usize = 64;
const EXECUTOR_ADMISSION_TIMEOUT: Duration = Duration::from_secs(1);
const EXECUTOR_CONNECTION_RECYCLE_TIMEOUT: Duration = Duration::from_secs(10);
// Keep retained query high-water below the room reserved for the next query.
// The command runs only after the caller has its response and the lane queue
// is empty, so a busy lane is never interrupted for allocator maintenance.
const EXECUTOR_ALLOCATOR_PURGE_INTERVAL: u64 = 8;
static NEXT_QUERY_ID: AtomicU64 = AtomicU64::new(1);
static NEXT_EXECUTOR_ID: AtomicU64 = AtomicU64::new(1);

#[derive(Debug, thiserror::Error)]
pub enum ExecutorError {
    #[error("native chDB startup failed: {0}")]
    Startup(#[source] NativeChdbError),
    #[error("native chDB executor is unavailable")]
    Unavailable,
    #[error("native chDB executor requires at least one connection")]
    EmptyPool,
    #[error("native chDB server memory limit must be positive")]
    ZeroServerMemoryLimit,
    #[error("native chDB executor admission timed out")]
    AdmissionTimeout,
    #[error("native chDB lane wait timed out; retry the request")]
    LaneWaitTimeout,
    #[error("native chDB connection recycle timed out")]
    ConnectionRecycleTimeout,
    #[error("interactive query scan estimate {estimated_bytes} exceeds budget {budget_bytes}")]
    EstimateExceeded { estimated_bytes: u64, budget_bytes: u64 },
    #[error("native chDB query failed: {0}")]
    Query(#[source] NativeChdbError),
    /// The raw result is larger than the caller's decode budget; it is
    /// dropped instead of being decoded into rows.
    #[error("query result of {bytes} bytes exceeds the {limit_bytes}-byte result memory budget; narrow the query or add | head")]
    ResultTooLarge { bytes: u64, limit_bytes: u64 },
    /// NAN-3650: the statement was refused on every lane class, including
    /// the degraded rung (one thread, bounded reader, disk spill). `detail`
    /// keeps chDB's own Code 241 text, so budget classifiers still see it.
    #[error("statement exceeded the top lane memory class ({class}, {cap_bytes} bytes) even with one thread, a bounded reader and disk spill; narrow the time range or add filters: {detail}")]
    MemoryExhausted { cap_bytes: u64, class: &'static str, detail: String },
}

/// How a lane pool executes the SQL handed to it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExecutorMode {
    /// Every query runs with `readonly=2`: reads and query-level settings
    /// only. Table functions (needed for the Parquet/Iceberg sources) stay
    /// available; INSERT/CREATE/ALTER/DROP/SYSTEM/KILL are refused by chDB.
    ReadOnly,
    /// Job mode: the isolated worker spools its result through
    /// `INSERT INTO FUNCTION file(...)` and needs write access.
    ReadWrite,
}

/// Reject an oversized interactive plan before queueing any native work.
pub fn check_interactive_estimate(estimated_bytes: u64, budget_bytes: u64) -> Result<(), ExecutorError> {
    if estimated_bytes > budget_bytes {
        return Err(ExecutorError::EstimateExceeded { estimated_bytes, budget_bytes });
    }
    Ok(())
}

/// Append `readonly=2` to a statement, extending an existing trailing
/// `SETTINGS` list when the statement ends with one (every planner and
/// typed-route builder emits its resource limits that way) and adding a
/// fresh clause otherwise.
pub fn with_read_only_setting(sql: &str) -> String {
    with_setting(sql, "readonly=2")
}

/// The local-file read method of every read-lane statement (NAN-3152).
///
/// chDB's `file()` defaults to `mmap` here. A query that needs a few leaves
/// of a wide part (an entity pivot reads `device.hostname`, `time` and
/// `metadata.log_source`) then faults its column chunks in through the page
/// cache, and kernel readahead pulls in the neighbouring chunks too: on a
/// cold page cache a 12 h real-sysmon host pivot read 919 MB of its 1.1 GB of
/// parts (raw_data dominates every row group) and spent 2x the CPU, where
/// `pread` reads only the requested ranges (42 MB) with identical rows.
/// Whenever the hot window is larger than the page cache the cell can keep,
/// every pivot paid the whole dataset in I/O. Writer lanes (merges read
/// every column anyway) keep the engine default.
pub const READ_LANE_FILE_METHOD: &str = "storage_file_read_method='pread'";

/// [`with_read_only_setting`] plus [`READ_LANE_FILE_METHOD`], unless the
/// statement already names its own read method.
pub fn read_lane_sql(sql: &str) -> String {
    let sql = with_read_only_setting(sql);
    // Lab A/B only: the engine default (mmap) for a before/after run.
    #[cfg(feature = "part-lab")]
    if std::env::var_os("NAN3152_LAB_MMAP").is_some() {
        return sql;
    }
    if statement_settings(&sql).is_some_and(|settings| settings.contains("storage_file_read_method")) {
        return sql;
    }
    with_setting(&sql, READ_LANE_FILE_METHOD)
}

/// NAN-4174: `sql` under its thread grant (unchanged without one), and the
/// largest grant of the request in its timing record.
fn grant_sql(
    grant: Option<&crate::thread_budget::ThreadGrant>,
    sql: String,
    timing: Option<&Arc<Mutex<crate::query_timing::Phases>>>,
) -> String {
    let Some(grant) = grant else { return sql };
    if let Some(timing) = timing {
        let mut phases = timing.lock().unwrap_or_else(|e| e.into_inner());
        phases.threads_granted = phases.threads_granted.max(grant.threads());
    }
    grant.apply(&sql)
}

/// Append one `name=value` setting the same way as [`with_read_only_setting`].
pub fn with_setting(sql: &str, setting: &str) -> String {
    let trimmed = sql.trim_end();
    if trailing_settings_list().is_match(trimmed) {
        format!("{trimmed}, {setting}")
    } else {
        format!("{trimmed} SETTINGS {setting}")
    }
}

/// The trailing statement settings, using the same parser as execution.
pub(crate) fn statement_settings(sql: &str) -> Option<&str> {
    trailing_settings_list().find(sql.trim_end()).map(|m| sql[m.start() + "SETTINGS".len()..].trim())
}

fn trailing_settings_list() -> &'static regex::Regex {
    static PATTERN: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    PATTERN.get_or_init(|| {
        // name = 'quoted' | number | bare-word, comma separated, at the very end.
        regex::Regex::new(
            r"(?i)\bSETTINGS\s+[A-Za-z_][A-Za-z0-9_]*\s*=\s*(?:'(?:[^'\\]|\\.)*'|-?[0-9]+(?:\.[0-9]+)?|[A-Za-z0-9_.]+)(?:\s*,\s*[A-Za-z_][A-Za-z0-9_]*\s*=\s*(?:'(?:[^'\\]|\\.)*'|-?[0-9]+(?:\.[0-9]+)?|[A-Za-z0-9_.]+))*\s*$",
        )
        .expect("static regex")
    })
}

struct Job {
    query_id: u64,
    request_id: String,
    budget: Option<Duration>,
    sql: String,
    params: Vec<(String, String)>,
    response: oneshot::Sender<Result<NativeQueryOutput, NativeChdbError>>,
    timing: Option<Arc<Mutex<crate::query_timing::Phases>>>,
    /// This statement's own clock (see [`capture_statement_times`]).
    clock: Option<Arc<StatementClock>>,
    derivative: bool,
    admitted_at: Instant,
    deadline: Instant,
    started: oneshot::Sender<Instant>,
    /// NAN-4174: whom the statement serves (its thread grant's class).
    priority: crate::thread_budget::Priority,
    /// NAN-4742: an agent statement's slot ([`AgentLaneGate`]), released
    /// when the lane is done with the job (or skips it), not when the
    /// caller stops waiting.
    _agent_slot: Option<AgentSlot>,
}

/// One streamed statement's lane job (see [`NativeExecutor::execute_streaming`]).
struct StreamJob {
    query_id: u64,
    request_id: String,
    budget: Option<Duration>,
    sql: String,
    params: Vec<(String, String)>,
    chunks: mpsc::Sender<StreamItem>,
    timing: Option<Arc<Mutex<crate::query_timing::Phases>>>,
    clock: Option<Arc<StatementClock>>,
    deadline: Instant,
    started: oneshot::Sender<Instant>,
    /// NAN-4174: whom the statement serves (its thread grant's class).
    priority: crate::thread_budget::Priority,
    /// NAN-4742: an agent statement's slot ([`AgentLaneGate`]), released
    /// when the lane is done with the job (or skips it), not when the
    /// caller stops waiting.
    _agent_slot: Option<AgentSlot>,
}

enum StreamItem {
    Chunk(NativeQueryOutput),
    End,
    Failed(NativeChdbError),
}

/// A statement's output, block by block, as chDB produces it (NAN-3060).
/// The statement runs exactly once, on one lane, which stays busy until the
/// stream ends or is dropped; dropping it early cancels the statement. At
/// most one block waits between the lane and the reader (backpressure).
pub struct NativeRowStream {
    chunks: mpsc::Receiver<StreamItem>,
    result_limit_bytes: Option<u64>,
    done: bool,
    query_id: u64,
}

/// NAN-4742: the most agent-class statements (`thread_budget::Priority::Agent`)
/// an executor of `lanes` lanes holds at once, queued or running: one lane
/// less than it has, so at least one lane of every executor (query[T]'s small
/// and large pools) never carries agent work and an analyst statement always
/// finds a lane free of it. Derived from the configured lane count; a
/// one-lane executor cannot reserve a lane and admits one agent statement.
pub const fn agent_lane_limit(lanes: usize) -> usize {
    if lanes <= 1 { 1 } else { lanes - 1 }
}

/// NAN-4742: admission of agent statements to one executor's lanes (see
/// [`agent_lane_limit`]). Every other class passes without waiting.
#[derive(Debug)]
pub(crate) struct AgentLaneGate {
    slots: Arc<tokio::sync::Semaphore>,
    limit: usize,
    /// NAN-4747: time agent statements spent waiting for an agent slot
    /// (this gate's or the large lane's), folded into `lane_wait_ms`.
    wait_micros: AtomicU64,
    /// NAN-4747: agent statements that found no agent slot in time, folded
    /// into `lane_wait_timeouts`.
    wait_timeouts: AtomicU64,
    /// NAN-4747: agent statements refused instead of escalating to the
    /// whole large lane ([`crate::part_query::lanes::admit_large`]).
    escalations_refused: AtomicU64,
}

impl AgentLaneGate {
    pub(crate) fn for_lanes(lanes: usize) -> Self {
        let limit = agent_lane_limit(lanes);
        Self {
            slots: Arc::new(tokio::sync::Semaphore::new(limit)),
            limit,
            wait_micros: AtomicU64::new(0),
            wait_timeouts: AtomicU64::new(0),
            escalations_refused: AtomicU64::new(0),
        }
    }

    /// NAN-4747: an agent statement waited `elapsed` for an agent slot and
    /// got none when `timed_out`.
    pub(crate) fn record_wait(&self, elapsed: Duration, timed_out: bool) {
        StatementClock::add(&self.wait_micros, elapsed);
        if timed_out {
            self.wait_timeouts.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// NAN-4747: an agent statement was refused the whole large lane.
    pub(crate) fn record_escalation_refused(&self) {
        self.escalations_refused.fetch_add(1, Ordering::Relaxed);
    }

    /// NAN-4747: agent statements refused the whole large lane so far.
    pub(crate) fn escalations_refused(&self) -> u64 {
        self.escalations_refused.load(Ordering::Relaxed)
    }

    pub(crate) fn limit(&self) -> usize {
        self.limit
    }

    /// Agent statements holding a slot.
    pub(crate) fn held(&self) -> usize {
        self.limit - self.slots.available_permits()
    }

    /// A slot for a `priority` statement (`None`: not agent work, nothing
    /// held), waiting at most until `deadline`.
    pub(crate) async fn admit(
        &self,
        priority: crate::thread_budget::Priority,
        deadline: Instant,
    ) -> Result<Option<tokio::sync::OwnedSemaphorePermit>, ExecutorError> {
        if priority != crate::thread_budget::Priority::Agent {
            return Ok(None);
        }
        match tokio::time::timeout_at(deadline.into(), self.slots.clone().acquire_owned()).await {
            Ok(Ok(permit)) => Ok(Some(permit)),
            Ok(Err(_)) => Err(ExecutorError::Unavailable),
            Err(_) => Err(ExecutorError::LaneWaitTimeout),
        }
    }
}

/// NAN-4742: an agent statement's slot on the lane it was sent to. Counted on
/// the lane (so analysts prefer lanes without agent work, see
/// [`NativeExecutor::least_loaded_lane`]) and given back when dropped: with
/// the lane job once the lane finishes or skips it, or on any early return
/// before the job is sent.
struct AgentSlot {
    _permit: tokio::sync::OwnedSemaphorePermit,
    lane: Arc<LaneStatus>,
}

impl AgentSlot {
    fn on_lane(permit: tokio::sync::OwnedSemaphorePermit, lane: &Arc<LaneStatus>) -> Self {
        lane.agents.fetch_add(1, Ordering::Relaxed);
        Self { _permit: permit, lane: lane.clone() }
    }
}

impl Drop for AgentSlot {
    fn drop(&mut self) {
        self.lane.agents.fetch_sub(1, Ordering::Relaxed);
    }
}

impl NativeRowStream {
    /// The next block, `None` once the statement has finished. Every block
    /// must fit the executor's result budget on its own.
    pub async fn next(&mut self) -> Option<Result<NativeQueryOutput, ExecutorError>> {
        if self.done {
            return None;
        }
        let item = self.chunks.recv().await;
        match item {
            Some(StreamItem::Chunk(output)) => match self.result_limit_bytes {
                Some(limit_bytes) if output.data.len() as u64 > limit_bytes => {
                    self.done = true;
                    tracing::warn!(bytes = output.data.len(), limit_bytes, query_id = self.query_id,
                        "native stream block exceeds the result memory budget");
                    Some(Err(ExecutorError::ResultTooLarge { bytes: output.data.len() as u64, limit_bytes }))
                }
                _ => Some(Ok(output)),
            },
            Some(StreamItem::End) => {
                self.done = true;
                None
            }
            Some(StreamItem::Failed(error)) => {
                self.done = true;
                Some(Err(ExecutorError::Query(error)))
            }
            // The lane went away without finishing the statement.
            None => {
                self.done = true;
                Some(Err(ExecutorError::Unavailable))
            }
        }
    }
}

enum Command {
    Query(Job),
    Stream(StreamJob),
    RecycleConnection {
        response: oneshot::Sender<Result<(), NativeChdbError>>,
    },
}

#[derive(Clone)]
pub struct NativeExecutor {
    lane_name: Arc<str>,
    senders: Arc<[mpsc::Sender<Command>]>,
    lanes: Arc<[Arc<LaneStatus>]>,
    next: Arc<AtomicUsize>,
    identity: u64,
    lane_wait_timeout: Duration,
    server_memory_limit_bytes: Option<u64>,
    result_limit_bytes: Option<u64>,
    streaming: bool,
    /// NAN-4174: the process thread budget every statement on this pool
    /// takes a grant from when its lane starts it (unset: threads as written).
    thread_budget: Arc<std::sync::OnceLock<Arc<crate::thread_budget::ThreadBudget>>>,
    /// NAN-4742: agent statements never hold every lane.
    agent_gate: Arc<AgentLaneGate>,
    /// NAN-3391: keeps the process-wide chDB DNS cache refresher running
    /// while this executor (or a clone) is alive.
    #[allow(dead_code)] // held for its Drop, never read
    dns_refresher: Option<Arc<crate::native_dns::RefresherLease>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NativeExecutorStatus {
    pub connections: usize,
    pub queue_capacity: usize,
    pub queued: usize,
    pub in_flight: usize,
    pub longest_in_flight: Duration,
    pub watchdog_query: Option<ExecutorQueryStatus>,
    pub completed: u64,
    pub failed: u64,
    pub admission_timeouts: u64,
    /// Cumulative post-admission queue time (including cancelled/timed-out waits).
    pub lane_wait_ms: u64,
    pub lane_wait_timeouts: u64,
    /// NAN-4747: agent statements refused (as lanes busy) instead of
    /// escalating to the whole large lane.
    pub agent_escalations_refused: u64,
    pub allocator_purges: u64,
    pub allocator_purge_failures: u64,
    pub allocator_purge_in_flight: usize,
    pub connection_recycles: u64,
    pub connection_recycle_failures: u64,
    pub connection_recycle_in_flight: usize,
}

/// Identity is unique per native execution, even across phases of one request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExecutorQueryStatus {
    pub query_id: u64,
    pub lane: usize,
    pub elapsed: Duration,
    pub budget: Duration,
    pub cancel_elapsed: Option<Duration>,
    pub no_progress_for: Duration,
}

struct RunningQuery {
    query_id: u64,
    request_id: String,
    budget: Option<Duration>,
    started: Instant,
    cancel_requested: Option<Instant>,
}

#[derive(Default)]
struct LaneStatus {
    query: Mutex<Option<RunningQuery>>,
    last_finished: Mutex<Option<Instant>>,
    queued: AtomicUsize,
    /// NAN-4742: agent statements queued or running on this lane.
    agents: AtomicUsize,
    started: Mutex<Option<Instant>>,
    completed: AtomicU64,
    failed: AtomicU64,
    admission_timeouts: AtomicU64,
    lane_wait_micros: AtomicU64,
    lane_wait_timeouts: AtomicU64,
    allocator_purges: AtomicU64,
    allocator_purge_failures: AtomicU64,
    allocator_purge_started: Mutex<Option<Instant>>,
    connection_recycles: AtomicU64,
    connection_recycle_failures: AtomicU64,
    connection_recycle_started: Mutex<Option<Instant>>,
}

impl NativeExecutor {
    pub fn start(runtime: NativeChdb, connection_count: usize) -> Result<Self, ExecutorError> {
        Self::start_named(runtime, connection_count, "query")
    }

    pub fn start_named(
        runtime: NativeChdb,
        connection_count: usize,
        lane_name: &str,
    ) -> Result<Self, ExecutorError> {
        Self::start_named_with_mode(
            runtime,
            connection_count,
            lane_name,
            ExecutorMode::ReadWrite,
        )
    }

    /// Start a lane pool whose queries run under the given mode. Interactive
    /// serving lanes use [`ExecutorMode::ReadOnly`]: every query is executed
    /// with `readonly=2`, so a compiler or planner defect that produced DML,
    /// DDL, `SYSTEM`, or `KILL` is refused by chDB itself (NAN-2361). The
    /// allocator purge and connection recycle paths are executor-owned
    /// maintenance and are not subject to the per-query setting.
    pub fn start_named_with_mode(
        runtime: NativeChdb,
        connection_count: usize,
        lane_name: &str,
        mode: ExecutorMode,
    ) -> Result<Self, ExecutorError> {
        Self::start_with_server_memory_limit(runtime, connection_count, lane_name, mode, None)
    }

    /// [`Self::start_named_with_mode`] with an engine-wide memory cap; see
    /// [`executor_connection_args`]. `None` keeps chDB's own default
    /// (a fraction of host RAM). A zero cap is refused: chDB reads 0 as "use
    /// the host-RAM default", the opposite of what a caller passing 0 means.
    pub fn start_with_server_memory_limit(
        runtime: NativeChdb,
        connection_count: usize,
        lane_name: &str,
        mode: ExecutorMode,
        server_memory_limit_bytes: Option<u64>,
    ) -> Result<Self, ExecutorError> {
        if server_memory_limit_bytes == Some(0) {
            return Err(ExecutorError::ZeroServerMemoryLimit);
        }
        if connection_count == 0 {
            return Err(ExecutorError::EmptyPool);
        }
        if lane_name.is_empty()
            || lane_name.len() > 32
            || !lane_name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
        {
            return Err(ExecutorError::Unavailable);
        }
        let mut senders = Vec::with_capacity(connection_count);
        let lanes = (0..connection_count)
            .map(|_| Arc::new(LaneStatus::default()))
            .collect::<Vec<_>>();
        let connection_args: Arc<[String]> =
            executor_connection_args(server_memory_limit_bytes).into();
        let streaming = runtime.supports_streaming();
        let thread_budget: Arc<std::sync::OnceLock<Arc<crate::thread_budget::ThreadBudget>>> = Arc::default();
        for index in 0..connection_count {
            senders.push(start_connection(
                runtime.clone(),
                index,
                lane_name,
                lanes[index].clone(),
                mode,
                connection_args.clone(),
                thread_budget.clone(),
            )?);
        }
        // NAN-3391: embedded chDB never refreshes its DNS cache; see native_dns.
        let dns_refresher = crate::native_dns::lease_refresher(&runtime, &connection_args);
        Ok(Self {
            lane_name: lane_name.into(),
            senders: senders.into(),
            lanes: lanes.into(),
            next: Arc::new(AtomicUsize::new(0)),
            identity: NEXT_EXECUTOR_ID.fetch_add(1, Ordering::Relaxed),
            lane_wait_timeout: std::env::var("EXECUTOR_LANE_WAIT_TIMEOUT")
                .ok()
                .and_then(|v| v.parse::<u64>().ok())
                .filter(|v| *v > 0 && *v <= 3600)
                .map(Duration::from_secs)
                .unwrap_or(Duration::from_secs(20)),
            server_memory_limit_bytes,
            result_limit_bytes: None,
            streaming,
            thread_budget,
            agent_gate: Arc::new(AgentLaneGate::for_lanes(connection_count)),
            dns_refresher,
        })
    }

    /// The raw-result cap set by [`Self::with_result_limit`].
    /// How long a statement may wait for a lane before it is shed.
    pub fn lane_wait_timeout(&self) -> Duration {
        self.lane_wait_timeout
    }

    pub fn result_limit_bytes(&self) -> Option<u64> {
        self.result_limit_bytes
    }

    /// Refuse (and drop) any raw result larger than `bytes` before a caller
    /// decodes it (query[T]'s memory budget).
    pub fn with_result_limit(mut self, bytes: u64) -> Self {
        self.result_limit_bytes = Some(bytes);
        self
    }

    /// NAN-4174: take every statement's threads from `budget` (see
    /// [`crate::thread_budget`]). Set once; a second budget is ignored.
    pub fn with_thread_budget(self, budget: Arc<crate::thread_budget::ThreadBudget>) -> Self {
        let _ = self.thread_budget.set(budget);
        self
    }

    /// NAN-4742: agent statements this executor holds (queued or running)
    /// and the most it admits at once ([`agent_lane_limit`]).
    pub fn agent_slots(&self) -> (usize, usize) {
        (self.agent_gate.held(), self.agent_gate.limit())
    }

    /// NAN-4747: this executor's agent gate, whose wait and refusal counters
    /// the large lane in front of it also feeds.
    pub(crate) fn agent_gate(&self) -> &AgentLaneGate {
        &self.agent_gate
    }

    /// NAN-4742: an agent slot for a `priority` statement (`None` for every
    /// other class), shed as a lane wait timeout ("all query lanes are
    /// busy") when none frees within the lane wait.
    async fn admit_agent(
        &self,
        priority: crate::thread_budget::Priority,
    ) -> Result<Option<tokio::sync::OwnedSemaphorePermit>, ExecutorError> {
        let started = Instant::now();
        let admitted = self.agent_gate.admit(priority, started + self.lane_wait_timeout).await;
        if priority == crate::thread_budget::Priority::Agent {
            // NAN-4747: the agent-slot wait is lane wait, for the executor,
            // the statement's clock and its timing line alike.
            let waited = started.elapsed();
            let timed_out = matches!(admitted, Err(ExecutorError::LaneWaitTimeout));
            self.agent_gate.record_wait(waited, timed_out);
            if let Ok(clock) = STATEMENT_CLOCK.try_with(Arc::clone) {
                StatementClock::add(&clock.wait_us, waited);
            }
            crate::query_timing::record(|p| p.lane_wait_ms += waited.as_secs_f64() * 1000.0);
        }
        if matches!(admitted, Err(ExecutorError::LaneWaitTimeout)) {
            crate::query_timing::record(|p| p.outcome = Some("lane_wait_timeout"));
            tracing::warn!(outcome = "lane_wait_timeout", lane = %self.lane_name,
                "agent statement found no free agent slot; shedding it");
        }
        admitted
    }

    /// The thread budget set by [`Self::with_thread_budget`].
    pub fn thread_budget(&self) -> Option<&Arc<crate::thread_budget::ThreadBudget>> {
        self.thread_budget.get()
    }

    /// Whether [`Self::execute_streaming`] is available (the chDB artifact
    /// exports the streaming ABI).
    pub fn supports_streaming(&self) -> bool {
        self.streaming
    }

    pub fn lane_name(&self) -> &str {
        &self.lane_name
    }

    pub fn connection_count(&self) -> usize {
        self.senders.len()
    }

    /// The engine-wide `max_server_memory_usage` this executor's connections
    /// were opened with, or `None` when chDB's default applies.
    pub fn server_memory_limit_bytes(&self) -> Option<u64> {
        self.server_memory_limit_bytes
    }

    pub fn identity(&self) -> u64 {
        self.identity
    }

    pub fn status(&self) -> NativeExecutorStatus {
        let now = Instant::now();
        let mut status = NativeExecutorStatus {
            connections: self.senders.len(),
            queue_capacity: self.senders.len().saturating_mul(EXECUTOR_QUEUE_DEPTH),
            queued: 0,
            in_flight: 0,
            longest_in_flight: Duration::ZERO,
            watchdog_query: None,
            completed: 0,
            failed: 0,
            admission_timeouts: 0,
            // NAN-4747: agent-slot waits and timeouts count as lane waits.
            lane_wait_ms: self.agent_gate.wait_micros.load(Ordering::Relaxed) / 1000,
            lane_wait_timeouts: self.agent_gate.wait_timeouts.load(Ordering::Relaxed),
            agent_escalations_refused: self.agent_gate.escalations_refused(),
            allocator_purges: 0,
            allocator_purge_failures: 0,
            allocator_purge_in_flight: 0,
            connection_recycles: 0,
            connection_recycle_failures: 0,
            connection_recycle_in_flight: 0,
        };
        let last_finished = self.lanes.iter().filter_map(|lane| *lane.last_finished.lock().expect("executor progress poisoned")).max();
        for (index, lane) in self.lanes.iter().enumerate() {
            if let Some(query) = lane.query.lock().expect("executor query poisoned").as_ref() {
                if let Some(budget) = query.budget {
                    let elapsed = now.saturating_duration_since(query.started);
                    // Prefer overdue work so a long durable query cannot hide a
                    // shorter interactive query that has exhausted its budget.
                    let rank = (elapsed > budget, elapsed);
                    if status.watchdog_query.is_none_or(|q| rank > (q.elapsed > q.budget, q.elapsed)) {
                        status.watchdog_query = Some(ExecutorQueryStatus {
                            query_id: query.query_id, lane: index, elapsed, budget,
                            cancel_elapsed: query.cancel_requested.map(|at| now.saturating_duration_since(at)),
                            no_progress_for: query.cancel_requested.map_or(Duration::ZERO, |at| {
                                now.saturating_duration_since(last_finished.map_or(at, |last| last.max(at)))
                            }),
                        });
                    }
                }
            }
            status.lane_wait_ms = status
                .lane_wait_ms
                .saturating_add(lane.lane_wait_micros.load(Ordering::Relaxed) / 1000);
            status.lane_wait_timeouts = status
                .lane_wait_timeouts
                .saturating_add(lane.lane_wait_timeouts.load(Ordering::Relaxed));
            status.queued = status
                .queued
                .saturating_add(lane.queued.load(Ordering::Relaxed));
            if let Some(started) = *lane.started.lock().expect("executor lane status poisoned") {
                status.in_flight += 1;
                status.longest_in_flight =
                    status.longest_in_flight.max(now.duration_since(started));
            }
            status.completed = status
                .completed
                .saturating_add(lane.completed.load(Ordering::Relaxed));
            status.failed = status
                .failed
                .saturating_add(lane.failed.load(Ordering::Relaxed));
            status.admission_timeouts = status
                .admission_timeouts
                .saturating_add(lane.admission_timeouts.load(Ordering::Relaxed));
            status.allocator_purges = status
                .allocator_purges
                .saturating_add(lane.allocator_purges.load(Ordering::Relaxed));
            status.allocator_purge_failures = status
                .allocator_purge_failures
                .saturating_add(lane.allocator_purge_failures.load(Ordering::Relaxed));
            status.allocator_purge_in_flight += usize::from(
                lane.allocator_purge_started
                    .lock()
                    .expect("executor allocator-purge status poisoned")
                    .is_some(),
            );
            status.connection_recycles = status
                .connection_recycles
                .saturating_add(lane.connection_recycles.load(Ordering::Relaxed));
            status.connection_recycle_failures = status
                .connection_recycle_failures
                .saturating_add(lane.connection_recycle_failures.load(Ordering::Relaxed));
            status.connection_recycle_in_flight += usize::from(
                lane.connection_recycle_started
                    .lock()
                    .expect("executor connection-recycle status poisoned")
                    .is_some(),
            );
        }
        status
    }

    pub fn request_id(&self, query: ExecutorQueryStatus) -> String {
        self.lanes[query.lane].query.lock().expect("executor query poisoned")
            .as_ref().filter(|q| q.query_id == query.query_id)
            .map_or_else(String::new, |q| q.request_id.clone())
    }

    /// The bound synchronous C ABI has no cancellation handle. Until a
    /// digest-pinned runtime proves concurrent KILL works, do not queue a
    /// control statement behind the engine it is supposed to interrupt.
    /// Record the attempt against this execution only; SQL limits and lane
    /// shedding remain the available containment mechanisms.
    pub fn cancel(&self, query: ExecutorQueryStatus) {
        let mut running = self.lanes[query.lane].query.lock().expect("executor query poisoned");
        if let Some(running) = running.as_mut().filter(|q| q.query_id == query.query_id) {
            if running.cancel_requested.is_none() {
                running.cancel_requested = Some(Instant::now());
                tracing::warn!(request_id = %running.request_id, lane = query.lane,
                    elapsed = query.elapsed.as_secs_f64(), budget = query.budget.as_secs_f64(),
                    cancel_supported = false, "native query cancellation unavailable; relying on SQL deadline and lane shedding");
            }
        }
    }

    fn all_lanes_over_budget(&self) -> bool {
        let now = Instant::now();
        self.lanes.iter().all(|lane| {
            lane.query.lock().expect("executor query poisoned").as_ref().is_some_and(|q| {
                q.budget.is_some_and(|budget| now.saturating_duration_since(q.started) > budget)
            })
        })
    }

    pub async fn execute(&self, plan: NativeQueryPlan) -> Result<NativeQueryOutput, ExecutorError> {
        if crate::query_timing::current().is_some() {
            check_interactive_estimate(plan.budget.estimated_scan_bytes, plan.budget.max_query_bytes)?;
        }
        self.execute_sql(plan.sql, plan.params).await
    }

    /// Run `plan` once and read its output as a stream of blocks
    /// ([`NativeRowStream`]); the same admission, lane choice, shedding and
    /// execution deadline as [`Self::execute`]. The result budget applies to
    /// each block instead of the whole result, which is never materialized.
    pub async fn execute_streaming(&self, plan: NativeQueryPlan) -> Result<NativeRowStream, ExecutorError> {
        if crate::query_timing::current().is_some() {
            check_interactive_estimate(plan.budget.estimated_scan_bytes, plan.budget.max_query_bytes)?;
        }
        // NAN-4742: an agent statement first takes one of the executor's
        // agent slots (one lane fewer than it has), then a lane.
        let priority = crate::thread_budget::Priority::current();
        let agent_permit = self.admit_agent(priority).await?;
        let index = self.least_loaded_lane(priority);
        let agent_slot = agent_permit.map(|permit| AgentSlot::on_lane(permit, &self.lanes[index]));
        let timing = crate::query_timing::current();
        let query_id = NEXT_QUERY_ID.fetch_add(1, Ordering::Relaxed);
        let request_id = timing.as_ref().map_or_else(|| format!("native-{query_id}"), |p| {
            p.lock().unwrap_or_else(|e| e.into_inner()).request_id.clone()
        });
        if self.all_lanes_over_budget() {
            self.lanes[index].lane_wait_timeouts.fetch_add(1, Ordering::Relaxed);
            crate::query_timing::record(|p| p.outcome = Some("lane_wait_timeout"));
            tracing::warn!(outcome = "lane_wait_timeout", request_id = %request_id, lane = index,
                "all native executor lanes are over budget; shedding a streamed statement");
            return Err(ExecutorError::LaneWaitTimeout);
        }
        let (sql, budget) = execution_sql(plan.sql, timing.as_ref());
        let permit = match tokio::time::timeout(EXECUTOR_ADMISSION_TIMEOUT, self.senders[index].reserve()).await {
            Ok(Ok(permit)) => permit,
            Ok(Err(_)) => return Err(ExecutorError::Unavailable),
            Err(_) => {
                self.lanes[index].admission_timeouts.fetch_add(1, Ordering::Relaxed);
                return Err(ExecutorError::AdmissionTimeout);
            }
        };
        let admitted_at = Instant::now();
        let deadline = admitted_at + self.lane_wait_timeout;
        let (chunks, receiver) = mpsc::channel(1);
        let (started, start_receiver) = oneshot::channel();
        let clock = STATEMENT_CLOCK.try_with(Arc::clone).ok();
        let mut wait = LaneWait { admitted_at, finished_at: None, timing: timing.clone(), statement_wait: clock.clone(), lane: self.lanes[index].clone() };
        self.lanes[index].queued.fetch_add(1, Ordering::Relaxed);
        permit.send(Command::Stream(StreamJob {
            query_id, request_id, budget, sql, params: plan.params, chunks, timing, clock, deadline, started,
            priority,
            _agent_slot: agent_slot,
        }));
        match tokio::time::timeout_at(deadline.into(), start_receiver).await {
            Ok(Ok(started_at)) => wait.finished_at = Some(started_at),
            Ok(Err(_)) if Instant::now() < deadline => return Err(ExecutorError::Unavailable),
            _ => {
                self.lanes[index].lane_wait_timeouts.fetch_add(1, Ordering::Relaxed);
                crate::query_timing::record(|p| p.outcome = Some("lane_wait_timeout"));
                tracing::warn!(outcome = "lane_wait_timeout", lane = index,
                    timeout_ms = self.lane_wait_timeout.as_millis() as u64, "native executor lane wait timed out");
                return Err(ExecutorError::LaneWaitTimeout);
            }
        }
        drop(wait);
        Ok(NativeRowStream { chunks: receiver, result_limit_bytes: self.result_limit_bytes, done: false, query_id })
    }

    pub async fn execute_sql(
        &self,
        sql: String,
        params: Vec<(String, String)>,
    ) -> Result<NativeQueryOutput, ExecutorError> {
        // NAN-4742: an agent statement first takes one of the executor's
        // agent slots (one lane fewer than it has), then a lane.
        let priority = crate::thread_budget::Priority::current();
        let agent_permit = self.admit_agent(priority).await?;
        let index = self.least_loaded_lane(priority);
        let agent_slot = agent_permit.map(|permit| AgentSlot::on_lane(permit, &self.lanes[index]));
        let timing = crate::query_timing::current();
        let query_id = NEXT_QUERY_ID.fetch_add(1, Ordering::Relaxed);
        let request_id = timing.as_ref().map_or_else(|| format!("native-{query_id}"), |p| {
            p.lock().unwrap_or_else(|e| e.into_inner()).request_id.clone()
        });
        if self.all_lanes_over_budget() {
            self.lanes[index].lane_wait_timeouts.fetch_add(1, Ordering::Relaxed);
            crate::query_timing::record(|p| p.outcome = Some("lane_wait_timeout"));
            let running = self.lanes[index].query.lock().expect("executor query poisoned");
            tracing::warn!(outcome = "lane_wait_timeout", request_id = %request_id, lane = index,
                elapsed = running.as_ref().map(|q| q.started.elapsed().as_secs_f64()),
                budget = running.as_ref().and_then(|q| q.budget).map(|b| b.as_secs_f64()),
                "all native executor lanes are over budget; shedding admission");
            return Err(ExecutorError::LaneWaitTimeout);
        }
        // chDB stops producing a result past the byte budget (TOO_MANY_ROWS_OR_BYTES)
        // instead of formatting it whole into memory first.
        let sql = match self.result_limit_bytes {
            Some(limit) if !sql.contains("max_result_bytes") => with_setting(&sql, &format!("max_result_bytes={limit}")),
            _ => sql,
        };
        let statement_head: String = if std::env::var_os("NANO_EXECUTOR_LOG_FULL_SQL").is_some() {
            format!("{sql} PARAMS {:?}", params.iter().map(|(name, value)| (name, value.chars().take(300).collect::<String>())).collect::<Vec<_>>())
        } else {
            sql.chars().take(160).collect()
        };
        let (sql, budget) = execution_sql(sql, timing.as_ref());
        // Reserve first so admission cancellation cannot leak queued counts.
        let permit =
            match tokio::time::timeout(EXECUTOR_ADMISSION_TIMEOUT, self.senders[index].reserve())
                .await
            {
                Ok(Ok(permit)) => permit,
                Ok(Err(_)) => return Err(ExecutorError::Unavailable),
                Err(_) => {
                    self.lanes[index]
                        .admission_timeouts
                        .fetch_add(1, Ordering::Relaxed);
                    return Err(ExecutorError::AdmissionTimeout);
                }
            };
        let admitted_at = Instant::now();
        let deadline = admitted_at + self.lane_wait_timeout;
        let (response, receiver) = oneshot::channel();
        let (started, start_receiver) = oneshot::channel();
        let derivative = timing
            .as_ref()
            .is_some_and(|p| p.lock().unwrap_or_else(|e| e.into_inner()).derivative_depth > 0);
        let mut wait = LaneWait {
            admitted_at,
            finished_at: None,
            timing: timing.clone(),
            statement_wait: STATEMENT_CLOCK.try_with(Arc::clone).ok(),
            lane: self.lanes[index].clone(),
        };
        self.lanes[index].queued.fetch_add(1, Ordering::Relaxed);
        permit.send(Command::Query(Job {
            query_id, request_id, budget,
            sql,
            params,
            response,
            timing,
            clock: STATEMENT_CLOCK.try_with(Arc::clone).ok(),
            derivative,
            admitted_at,
            deadline,
            started,
            priority,
            _agent_slot: agent_slot,
        }));
        match tokio::time::timeout_at(deadline.into(), start_receiver).await {
            Ok(Ok(started_at)) => wait.finished_at = Some(started_at),
            // The lane also refuses expired jobs, even if the async timer has
            // not been polled yet. No expired/abandoned SQL enters chDB.
            Ok(Err(_)) if Instant::now() < deadline => return Err(ExecutorError::Unavailable),
            _ => {
                self.lanes[index]
                    .lane_wait_timeouts
                    .fetch_add(1, Ordering::Relaxed);
                crate::query_timing::record(|p| p.outcome = Some("lane_wait_timeout"));
                tracing::warn!(
                    outcome = "lane_wait_timeout",
                    lane = index,
                    timeout_ms = self.lane_wait_timeout.as_millis() as u64,
                    "native executor lane wait timed out"
                );
                return Err(ExecutorError::LaneWaitTimeout);
            }
        }
        drop(wait);
        let output = receiver
            .await
            .map_err(|_| ExecutorError::Unavailable)?
            .map_err(ExecutorError::Query)?;
        match self.result_limit_bytes {
            Some(limit_bytes) if output.data.len() as u64 > limit_bytes => {
                let rows = output.data.iter().filter(|byte| **byte == b'\n').count();
                let first_row: String = String::from_utf8_lossy(&output.data[..output.data.len().min(200)]).into_owned();
                tracing::warn!(bytes = output.data.len(), rows, limit_bytes, query_id,
                    statement = %statement_head, first_row = %first_row, "native result exceeds the result memory budget");
                Err(ExecutorError::ResultTooLarge { bytes: output.data.len() as u64, limit_bytes })
            }
            _ => Ok(output),
        }
    }

    /// Pick the lane with the least admitted work, using the round-robin
    /// cursor only to break ties.
    ///
    /// A native chDB query cannot be preempted once it enters the blocking C
    /// API. Blind round-robin therefore lets a timed-out heavy request create
    /// head-of-line blocking even while another connection is idle. Count the
    /// running request plus queued requests on every lane and, for equal
    /// loads, prefer the lane whose current request has run for less time.
    /// This keeps unrelated interactive traffic off an old slow lane without
    /// increasing connection, CPU, or memory envelopes.
    ///
    /// NAN-4742: among equally loaded lanes, a statement that is not agent
    /// work prefers a lane carrying no agent statement, so an analyst does
    /// not queue behind a one-thread agent statement while a lane of equal
    /// load serves only analysts.
    fn least_loaded_lane(&self, priority: crate::thread_budget::Priority) -> usize {
        let avoid_agents = priority != crate::thread_budget::Priority::Agent;
        let start = self.next.fetch_add(1, Ordering::Relaxed) % self.lanes.len();
        let now = Instant::now();
        (0..self.lanes.len())
            .map(|offset| (start + offset) % self.lanes.len())
            .min_by_key(|index| {
                let lane = &self.lanes[*index];
                let started = *lane.started.lock().expect("executor lane status poisoned");
                let in_flight = usize::from(started.is_some());
                let load = lane
                    .queued
                    .load(Ordering::Relaxed)
                    .saturating_add(in_flight);
                let running_for = started.map_or(Duration::ZERO, |started| {
                    now.saturating_duration_since(started)
                });
                let overdue = lane.query.lock().expect("executor query poisoned").as_ref()
                    .is_some_and(|q| q.budget.is_some_and(|budget| now.saturating_duration_since(q.started) > budget));
                let agent_work = avoid_agents && lane.agents.load(Ordering::Relaxed) > 0;
                (overdue, load, agent_work, running_for)
            })
            .expect("native executor has at least one lane")
    }

    /// Close and reopen every idle native connection, releasing session-local
    /// chDB caches without discarding the verified generation or its sidecars.
    pub async fn recycle_connections(&self) -> Result<(), ExecutorError> {
        for sender in self.senders.iter() {
            let (response, receiver) = oneshot::channel();
            match tokio::time::timeout(
                EXECUTOR_ADMISSION_TIMEOUT,
                sender.send(Command::RecycleConnection { response }),
            )
            .await
            {
                Ok(Ok(())) => {}
                Ok(Err(_)) => return Err(ExecutorError::Unavailable),
                Err(_) => return Err(ExecutorError::AdmissionTimeout),
            }
            tokio::time::timeout(EXECUTOR_CONNECTION_RECYCLE_TIMEOUT, receiver)
                .await
                .map_err(|_| ExecutorError::ConnectionRecycleTimeout)?
                .map_err(|_| ExecutorError::Unavailable)?
                .map_err(ExecutorError::Startup)?;
        }
        Ok(())
    }
}

// Planner SQL is already tier-bounded. Also fence interactive helper SQL that
// bypasses the planner (e.g. derivative probes), before it enters native code.
pub(crate) fn execution_sql(mut sql: String, timing: Option<&Arc<Mutex<crate::query_timing::Phases>>>) -> (String, Option<Duration>) {
    static LIMIT: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    let limit = LIMIT.get_or_init(|| regex::Regex::new(r"(?i)\bmax_execution_time\s*=\s*([0-9]+(?:\.[0-9]+)?)").unwrap());
    let settings_start = trailing_settings_list().find(sql.trim_end()).map(|m| m.start());
    let settings = settings_start.map_or("", |start| &sql[start..]);
    let configured = limit.captures(settings).and_then(|c| c[1].parse::<f64>().ok()).filter(|n| *n > 0.0);
    let seconds = if let Some(timing) = timing {
        let interactive = timing.lock().unwrap_or_else(|e| e.into_inner()).execution_seconds as f64;
        let seconds = configured.map_or(interactive, |n| n.min(interactive));
        if limit.is_match(settings) {
            let updated = limit.replace_all(settings, format!("max_execution_time={seconds}")).into_owned();
            sql.truncate(settings_start.unwrap());
            sql.push_str(&updated);
        } else {
            let separator = if trailing_settings_list().is_match(sql.trim_end()) { "," } else { " SETTINGS" };
            sql.push_str(&format!("{separator} max_execution_time={seconds}"));
        }
        sql = with_bounded_parsing_threads(sql);
        Some(seconds)
    } else { configured };
    (sql, seconds.and_then(|n| Duration::try_from_secs_f64(n).ok()))
}

/// NAN-3169: an interactive statement's Parquet decode stays on its thread
/// budget. chDB decodes row groups on its format-parsing pool, sized by
/// `max_parsing_threads` (default: every host core), not `max_threads`; on a
/// cell limited to a few cores a wide decode oversubscribed the CPU quota
/// and was throttled (a `max_threads=1` read burned 9.2 cores, NAN-3168).
/// A statement that names its own parsing pool, or no `max_threads`, is left
/// alone. Kill switch: `NANO_LAKE_BOUND_PARSING_THREADS=0`.
pub(crate) fn with_bounded_parsing_threads(sql: String) -> String {
    static THREADS: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    let threads = THREADS.get_or_init(|| regex::Regex::new(r"(?i)\bmax_threads\s*=\s*([0-9]+)\b").unwrap());
    if std::env::var("NANO_LAKE_BOUND_PARSING_THREADS").is_ok_and(|value| value == "0") {
        return sql;
    }
    let Some(settings) = statement_settings(&sql) else { return sql };
    if settings.to_ascii_lowercase().contains("max_parsing_threads") {
        return sql;
    }
    match threads.captures(settings).and_then(|c| c[1].parse::<u64>().ok()).filter(|n| *n > 0) {
        Some(n) => with_setting(&sql, &format!("max_parsing_threads={n}")),
        None => sql,
    }
}

tokio::task_local! {
    static STATEMENT_CLOCK: Arc<StatementClock>;
}

/// One statement's own lane wait and native time, in microseconds (the
/// request's `query_timing` phases sum every statement of the request).
#[derive(Debug, Default)]
pub(crate) struct StatementClock {
    wait_us: AtomicU64,
    init_us: AtomicU64,
    fetch_us: AtomicU64,
    first_fetch_us: AtomicU64,
    native_us: AtomicU64,
}

impl StatementClock {
    fn add(counter: &AtomicU64, elapsed: Duration) {
        counter.fetch_add(elapsed.as_micros().min(u64::MAX as u128) as u64, Ordering::Relaxed);
    }
}

/// A [`StatementClock`] read in milliseconds.
#[derive(Debug, Default, Clone, Copy, PartialEq)]
pub(crate) struct StatementTimes {
    pub lane_wait_ms: f64,
    /// Streamed statements: statement initialization (parse, plan, setup).
    pub init_ms: f64,
    /// Streamed statements: every block fetch, the first one included.
    pub fetch_ms: f64,
    pub first_fetch_ms: f64,
    /// All native time on the lane (init + fetch, or the whole call).
    pub native_ms: f64,
}

/// Isolated per-statement wait accounting, excluding diagnostic settings probes.
pub(crate) async fn capture_lane_wait<T>(work: impl std::future::Future<Output = T>) -> (T, f64) {
    let (output, times) = capture_statement_times(work).await;
    (output, times.lane_wait_ms)
}

/// Per-statement lane wait and native times of the statements `work` runs
/// (NAN-3393: a small-lane attempt that failed before its large-lane rerun
/// gets its own numbers).
pub(crate) async fn capture_statement_times<T>(work: impl std::future::Future<Output = T>) -> (T, StatementTimes) {
    let clock = Arc::new(StatementClock::default());
    let output = STATEMENT_CLOCK.scope(clock.clone(), Box::pin(work)).await;
    let ms = |counter: &AtomicU64| counter.load(Ordering::Relaxed) as f64 / 1000.0;
    (output, StatementTimes {
        lane_wait_ms: ms(&clock.wait_us),
        init_ms: ms(&clock.init_us),
        fetch_ms: ms(&clock.fetch_us),
        first_fetch_ms: ms(&clock.first_fetch_us),
        native_ms: ms(&clock.native_us),
    })
}

/// Record actual admission-to-start time, or elapsed wait on timeout/cancellation.
struct LaneWait {
    statement_wait: Option<Arc<StatementClock>>,
    admitted_at: Instant,
    finished_at: Option<Instant>,
    timing: Option<Arc<Mutex<crate::query_timing::Phases>>>,
    lane: Arc<LaneStatus>,
}

impl Drop for LaneWait {
    fn drop(&mut self) {
        let elapsed = self
            .finished_at
            .unwrap_or_else(Instant::now)
            .duration_since(self.admitted_at);
        if let Some(clock) = &self.statement_wait {
            StatementClock::add(&clock.wait_us, elapsed);
        }
        self.lane.lane_wait_micros.fetch_add(
            elapsed.as_micros().min(u64::MAX as u128) as u64,
            Ordering::Relaxed,
        );
        if let Some(timing) = &self.timing {
            timing
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .lane_wait_ms += elapsed.as_secs_f64() * 1000.0;
        }
    }
}

/// NAN-3391: after a statement failed because the object store was
/// unreachable, drop chDB's process-wide DNS cache. The next statement then
/// resolves the store's current address and does not wait for the periodic
/// refresher. Other failures leave the cache alone. This runs on the failed
/// connection, which the lane discards right after (NAN-3046), so the
/// maintenance statement never touches a connection that serves queries.
fn drop_dns_cache_after_connection_error(
    connection: &crate::native::NativeConnection,
    error: &NativeChdbError,
    lane_label: &str,
) {
    let message = error.to_string();
    if !crate::native_dns::is_connection_error(&message) {
        return;
    }
    match crate::native_dns::drop_dns_cache(connection) {
        Ok(()) => tracing::warn!(lane = %lane_label,
            error = %message.chars().take(240).collect::<String>(),
            "object-store connection failed; dropped the chDB DNS cache so the next statement re-resolves the endpoint"),
        Err(drop_error) => tracing::warn!(lane = %lane_label, error = %drop_error,
            "object-store connection failed and the chDB DNS cache could not be dropped; the periodic refresher will retry"),
    }
}

fn start_connection(
    runtime: NativeChdb,
    index: usize,
    lane_name: &str,
    status: Arc<LaneStatus>,
    mode: ExecutorMode,
    connection_args: Arc<[String]>,
    thread_budget: Arc<std::sync::OnceLock<Arc<crate::thread_budget::ThreadBudget>>>,
) -> Result<mpsc::Sender<Command>, ExecutorError> {
    let (sender, mut receiver) = mpsc::channel::<Command>(EXECUTOR_QUEUE_DEPTH);
    let (ready_sender, ready_receiver) = std::sync::mpsc::sync_channel(1);
    let lane_label = format!("{lane_name}-{index}");
    std::thread::Builder::new()
        .name(format!("nano-chdb-{lane_name}-{index}"))
        .spawn(move || {
            #[cfg(target_os = "linux")]
            if let Err(error) = nanosiem_lake_cell::crash_capture::register_thread() {
                eprintln!("lake_native_crash alternate stack registration failed: {error}");
            }

            let connection_args = connection_args
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>();
            let mut connection = match runtime.connect(&connection_args) {
                Ok(connection) => {
                    // Exercise native statement setup before the lane admits queries.
                    // Settings remain statement-local; no tenant data or temp tables.
                    if let Err(error) = connection.query_with_params("SELECT 1 SETTINGS readonly=2, max_threads=1", "Null", &[]) {
                        let _ = ready_sender.send(Err(error));
                        return;
                    }
                    let _ = ready_sender.send(Ok(()));
                    connection
                }
                Err(error) => {
                    let _ = ready_sender.send(Err(error));
                    return;
                }
            };
            let mut session_used = true;
            let mut jobs_since_allocator_purge = 0_u64;
            while let Some(command) = receiver.blocking_recv() {
                match command {
                    Command::Query(job) => {
                        status.queued.fetch_sub(1, Ordering::Relaxed);
                        // The HTTP client can time out while this job waits
                        // behind native work. The receiver is then gone and
                        // executing the abandoned query would only consume a
                        // lane and delay live callers. A query already inside
                        // chDB remains bounded by its SQL execution deadline.
                        if job.response.is_closed() {
                            continue;
                        }
                        let started_at = Instant::now();
                        debug_assert!(started_at >= job.admitted_at);
                        if started_at >= job.deadline || job.started.send(started_at).is_err() {
                            continue;
                        }
                        *status
                            .started
                            .lock()
                            .expect("executor lane status poisoned") = Some(Instant::now());
                        *status.query.lock().expect("executor query poisoned") = Some(RunningQuery {
                            query_id: job.query_id, request_id: job.request_id.clone(),
                            budget: job.budget, started: started_at, cancel_requested: None,
                        });
                        let prepare_started = Instant::now();
                        let params = job
                            .params
                            .iter()
                            .map(|(name, value)| (name.as_str(), value.as_str()))
                            .collect::<Vec<_>>();
                        let sql = match mode {
                            ExecutorMode::ReadOnly => read_lane_sql(&job.sql),
                            ExecutorMode::ReadWrite => job.sql.clone(),
                        };
                        // NAN-4174: threads by what runs now, held to the end;
                        // NAN-4751: one share per request, not per statement.
                        let grant = thread_budget.get().map(|budget| budget.grant_for_request(job.priority, &job.request_id));
                        let sql = grant_sql(grant.as_ref(), sql, job.timing.as_ref());
                        if let Some(timing) = &job.timing {
                            timing.lock().unwrap_or_else(|e| e.into_inner()).sql_prepare_ms += prepare_started.elapsed().as_secs_f64() * 1000.0;
                        }
                        if let Some(timing) = &job.timing {
                            timing.lock().unwrap_or_else(|e| e.into_inner()).native_session_reused += usize::from(session_used);
                        }
                        session_used = true;
                        let native_started = Instant::now();
                        if let Some(timing) = &job.timing {
                            timing.lock().unwrap_or_else(|e| e.into_inner()).native_inflight.push(native_started);
                        }
                        let result = connection.query_with_params(&sql, "JSONEachRow", &params);
                        if let Some(timing) = &job.timing {
                            timing.lock().unwrap_or_else(|e| e.into_inner()).native_finished(native_started);
                        }
                        if let Some(clock) = &job.clock {
                            StatementClock::add(&clock.native_us, native_started.elapsed());
                        }
                        // Sidecar SQL is already included in derivative_ms;
                        // chdb_ms measures result/locator/chunk execution only.
                        if !job.derivative {
                            if let Some(timing) = job.timing {
                                timing.lock().unwrap_or_else(|e| e.into_inner()).chdb_ms +=
                                    native_started.elapsed().as_secs_f64() * 1000.0;
                            }
                        }
                        *status
                            .started
                            .lock()
                            .expect("executor lane status poisoned") = None;
                        *status.last_finished.lock().expect("executor progress poisoned") = Some(Instant::now());
                        *status.query.lock().expect("executor query poisoned") = None;
                        let failed = result.is_err();
                        if failed {
                            status.failed.fetch_add(1, Ordering::Relaxed);
                        } else {
                            status.completed.fetch_add(1, Ordering::Relaxed);
                        }
                        jobs_since_allocator_purge = jobs_since_allocator_purge.saturating_add(1);
                        // libchdb keeps the output a statement had produced
                        // before it failed (e.g. a memory limit mid-result)
                        // and hands it to the NEXT statement on the same
                        // connection as that statement's result (NAN-3046:
                        // 600 MB of another query's rows for `SELECT 1`).
                        // Never reuse a connection after a failure.
                        if failed {
                            if let Err(error) = &result {
                                drop_dns_cache_after_connection_error(&connection, error, &lane_label);
                            }
                            session_used = false;
                            drop(connection);
                            connection = match runtime.connect(&connection_args) {
                                Ok(connection) => connection,
                                Err(error) => {
                                    tracing::error!(lane = %lane_label, error = %error,
                                        "native chDB connection could not be reopened after a failed statement; lane stops");
                                    status.connection_recycle_failures.fetch_add(1, Ordering::Relaxed);
                                    let _ = job.response.send(result);
                                    return;
                                }
                            };
                            status.connection_recycles.fetch_add(1, Ordering::Relaxed);
                        }
                        // A large-lane retry must wait until the failed small
                        // session has released its native allocations.
                        let _ = job.response.send(result);
                    }
                    Command::Stream(job) => {
                        status.queued.fetch_sub(1, Ordering::Relaxed);
                        if job.chunks.is_closed() {
                            continue;
                        }
                        let started_at = Instant::now();
                        if started_at >= job.deadline || job.started.send(started_at).is_err() {
                            continue;
                        }
                        *status.started.lock().expect("executor lane status poisoned") = Some(Instant::now());
                        *status.query.lock().expect("executor query poisoned") = Some(RunningQuery {
                            query_id: job.query_id, request_id: job.request_id.clone(),
                            budget: job.budget, started: started_at, cancel_requested: None,
                        });
                        let prepare_started = Instant::now();
                        let params = job.params.iter().map(|(name, value)| (name.as_str(), value.as_str())).collect::<Vec<_>>();
                        let sql = match mode {
                            ExecutorMode::ReadOnly => read_lane_sql(&job.sql),
                            ExecutorMode::ReadWrite => job.sql.clone(),
                        };
                        // NAN-4174: threads by what runs now, held to the end;
                        // NAN-4751: one share per request, not per statement.
                        let grant = thread_budget.get().map(|budget| budget.grant_for_request(job.priority, &job.request_id));
                        let sql = grant_sql(grant.as_ref(), sql, job.timing.as_ref());
                        if let Some(timing) = &job.timing {
                            timing.lock().unwrap_or_else(|e| e.into_inner()).sql_prepare_ms += prepare_started.elapsed().as_secs_f64() * 1000.0;
                        }
                        if let Some(timing) = &job.timing {
                            timing.lock().unwrap_or_else(|e| e.into_inner()).native_session_reused += usize::from(session_used);
                        }
                        session_used = true;
                        let native_started = Instant::now();
                        if let Some(timing) = &job.timing {
                            timing.lock().unwrap_or_else(|e| e.into_inner()).native_inflight.push(native_started);
                        }
                        // `clean`: the statement ran to its end and the reader
                        // took every block. Anything else (an error, or a reader
                        // that went away mid-result) reopens the connection, as
                        // a failed materialized statement does.
                        let mut failure = None;
                        let clean = {
                            // Statement initialization (parse, analysis, planning
                            // and stream setup), not chdb_connect. Successful
                            // statements retain this lane's connection.
                            let mut init = crate::native::NativeInitTimings::default();
                            let initialized = connection.stream_query_with_params_timed(&sql, "JSONEachRow", &params, &mut init);
                            if let Some(timing) = &job.timing {
                                let mut phases = timing.lock().unwrap_or_else(|e| e.into_inner());
                                phases.native_init_ms += native_started.elapsed().as_secs_f64() * 1000.0;
                                phases.native_bind_ms += init.bind_ms;
                                phases.native_init_abi_ms += init.abi_ms;
                                phases.native_statements += 1;
                            }
                            if let Some(clock) = &job.clock {
                                StatementClock::add(&clock.init_us, native_started.elapsed());
                            }
                            match initialized {
                                Err(error) => {
                                    failure = Some(error);
                                    false
                                }
                                Ok(mut stream) => {
                                    let mut first_fetch = true;
                                    loop {
                                        let fetch_started = Instant::now();
                                        let fetched = stream.fetch();
                                        if let Some(timing) = &job.timing {
                                            let ms = fetch_started.elapsed().as_secs_f64() * 1000.0;
                                            let mut phases = timing.lock().unwrap_or_else(|e| e.into_inner());
                                            phases.native_fetch_ms += ms;
                                            phases.native_fetch_calls += 1;
                                            if first_fetch { phases.native_first_fetch_ms += ms; }
                                        }
                                        if let Some(clock) = &job.clock {
                                            let elapsed = fetch_started.elapsed();
                                            StatementClock::add(&clock.fetch_us, elapsed);
                                            if first_fetch { StatementClock::add(&clock.first_fetch_us, elapsed); }
                                        }
                                        first_fetch = false;
                                        match fetched {
                                            Ok(Some(output)) => {
                                                if job.chunks.blocking_send(StreamItem::Chunk(output)).is_err() {
                                                    break false;
                                                }
                                            }
                                            Ok(None) => break true,
                                            Err(error) => {
                                                failure = Some(error);
                                                break false;
                                            }
                                        }
                                    }
                                },
                            }
                        };
                        if let Some(timing) = job.timing {
                            let mut phases = timing.lock().unwrap_or_else(|e| e.into_inner());
                            phases.chdb_ms += native_started.elapsed().as_secs_f64() * 1000.0;
                            phases.native_finished(native_started);
                        }
                        if let Some(clock) = &job.clock {
                            StatementClock::add(&clock.native_us, native_started.elapsed());
                        }
                        if clean {
                            // Publish End after phase accounting: otherwise a
                            // fast reader can snapshot incomplete native times.
                            // Keep the lane busy until this send completes.
                            let _ = job.chunks.blocking_send(StreamItem::End);
                        }
                        *status.started.lock().expect("executor lane status poisoned") = None;
                        *status.last_finished.lock().expect("executor progress poisoned") = Some(Instant::now());
                        *status.query.lock().expect("executor query poisoned") = None;
                        if clean {
                            status.completed.fetch_add(1, Ordering::Relaxed);
                        } else {
                            status.failed.fetch_add(1, Ordering::Relaxed);
                            if let Some(error) = &failure {
                                drop_dns_cache_after_connection_error(&connection, error, &lane_label);
                            }
                            session_used = false;
                            drop(connection);
                            connection = match runtime.connect(&connection_args) {
                                Ok(connection) => connection,
                                Err(error) => {
                                    tracing::error!(lane = %lane_label, error = %error,
                                        "native chDB connection could not be reopened after a streamed statement; lane stops");
                                    status.connection_recycle_failures.fetch_add(1, Ordering::Relaxed);
                                    if let Some(error) = failure {
                                        let _ = job.chunks.blocking_send(StreamItem::Failed(error));
                                    }
                                    return;
                                }
                            };
                            status.connection_recycles.fetch_add(1, Ordering::Relaxed);
                        }
                        // Report failure only after stream cancellation and
                        // connection replacement, before a caller can retry.
                        if let Some(error) = failure {
                            let _ = job.chunks.blocking_send(StreamItem::Failed(error));
                        }
                        jobs_since_allocator_purge = jobs_since_allocator_purge.saturating_add(1);
                    }
                    Command::RecycleConnection { response } => {
                        *status
                            .connection_recycle_started
                            .lock()
                            .expect("executor connection-recycle status poisoned") =
                            Some(Instant::now());
                        session_used = false;
                        drop(connection);
                        connection = match runtime.connect(&connection_args) {
                            Ok(connection) => connection,
                            Err(error) => {
                                status
                                    .connection_recycle_failures
                                    .fetch_add(1, Ordering::Relaxed);
                                *status
                                    .connection_recycle_started
                                    .lock()
                                    .expect("executor connection-recycle status poisoned") = None;
                                let _ = response.send(Err(error));
                                return;
                            }
                        };
                        let purge = connection
                            .query_with_params("SYSTEM JEMALLOC PURGE", "Null", &[])
                            .map(|_| ());
                        *status
                            .connection_recycle_started
                            .lock()
                            .expect("executor connection-recycle status poisoned") = None;
                        if purge.is_ok() {
                            status.connection_recycles.fetch_add(1, Ordering::Relaxed);
                        } else {
                            status
                                .connection_recycle_failures
                                .fetch_add(1, Ordering::Relaxed);
                        }
                        if purge.is_err() {
                            session_used = false;
                            drop(connection);
                            connection = match runtime.connect(&connection_args) {
                                Ok(connection) => connection,
                                Err(error) => {
                                    status.connection_recycle_failures.fetch_add(1, Ordering::Relaxed);
                                    tracing::error!(lane = %lane_label, error = %error,
                                        "native chDB connection could not be reopened after recycle maintenance; lane stops");
                                    let _ = response.send(purge);
                                    return;
                                }
                            };
                            status.connection_recycles.fetch_add(1, Ordering::Relaxed);
                        }
                        let _ = response.send(purge);
                        jobs_since_allocator_purge = 0;
                        continue;
                    }
                }

                // ClickHouse/chDB uses jemalloc. Large aggregations can return
                // their tracked query memory while leaving dirty allocator
                // pages resident in a persistent embedded process. Purge only
                // between requests and only when this lane has no queued work,
                // so the fast path keeps its session/cache locality and the
                // maintenance never delays an already-admitted query.
                if jobs_since_allocator_purge >= EXECUTOR_ALLOCATOR_PURGE_INTERVAL
                    && receiver.is_empty()
                {
                    *status
                        .allocator_purge_started
                        .lock()
                        .expect("executor allocator-purge status poisoned") = Some(Instant::now());
                    let purge = connection.query_with_params("SYSTEM JEMALLOC PURGE", "Null", &[]);
                    *status
                        .allocator_purge_started
                        .lock()
                        .expect("executor allocator-purge status poisoned") = None;
                    if purge.is_ok() {
                        status.allocator_purges.fetch_add(1, Ordering::Relaxed);
                    } else {
                        status
                            .allocator_purge_failures
                            .fetch_add(1, Ordering::Relaxed);
                        session_used = false;
                        drop(connection);
                        connection = match runtime.connect(&connection_args) {
                            Ok(connection) => connection,
                            Err(error) => {
                                status.connection_recycle_failures.fetch_add(1, Ordering::Relaxed);
                                tracing::error!(lane = %lane_label, error = %error,
                                    "native chDB connection could not be reopened after allocator maintenance; lane stops");
                                return;
                            }
                        };
                        status.connection_recycles.fetch_add(1, Ordering::Relaxed);
                    }
                    jobs_since_allocator_purge = 0;
                }
            }
        })
        .map_err(|_| ExecutorError::Unavailable)?;
    ready_receiver
        .recv()
        .map_err(|_| ExecutorError::Unavailable)?
        .map_err(ExecutorError::Startup)?;
    Ok(sender)
}

/// NAN-4747: an executor whose lanes never run anything, for admission
/// tests outside this module; [`TestLanes::jobs`] drains and counts the
/// statements sent to its lanes. A sent statement is never started, so its
/// caller ends in a lane wait timeout.
#[cfg(test)]
pub(crate) struct TestLanes {
    receivers: Vec<mpsc::Receiver<Command>>,
}

#[cfg(test)]
impl TestLanes {
    pub(crate) fn jobs(&mut self) -> usize {
        self.receivers.iter_mut().map(|receiver| std::iter::from_fn(|| receiver.try_recv().ok()).count()).sum()
    }
}

#[cfg(test)]
impl NativeExecutor {
    pub(crate) fn test_lanes(count: usize, lane_wait_timeout: Duration) -> (Self, TestLanes) {
        let (senders, receivers): (Vec<_>, Vec<_>) = (0..count).map(|_| mpsc::channel(EXECUTOR_QUEUE_DEPTH)).unzip();
        let executor = Self {
            lane_name: "test".into(),
            senders: senders.into(),
            lanes: (0..count).map(|_| Arc::new(LaneStatus::default())).collect::<Vec<_>>().into(),
            next: Arc::new(AtomicUsize::new(0)),
            identity: NEXT_EXECUTOR_ID.fetch_add(1, Ordering::Relaxed),
            lane_wait_timeout,
            server_memory_limit_bytes: None,
            result_limit_bytes: None,
            streaming: false,
            thread_budget: Arc::default(),
            agent_gate: Arc::new(AgentLaneGate::for_lanes(count)),
            dns_refresher: None,
        };
        (executor, TestLanes { receivers })
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn interactive_estimate_is_checked_before_execution() {
        assert!(super::check_interactive_estimate(25 << 20, 4 << 30).is_ok());
        assert!(super::check_interactive_estimate(4 << 30, 4 << 30).is_ok());
        assert!(matches!(super::check_interactive_estimate((4 << 30) + 1, 4 << 30),
            Err(super::ExecutorError::EstimateExceeded { budget_bytes: 4_294_967_296, .. })));
    }
    use super::*;

    #[tokio::test]
    async fn oversized_plan_never_reaches_native_admission() {
        let executor = scheduler(vec![Arc::new(LaneStatus::default())]);
        let plan = NativeQueryPlan {
            query_sha256: String::new(), sql: "SELECT 1".into(), params: vec![],
            budget: crate::planner::QueryBudget {
                candidate_objects: 1, estimated_scan_bytes: (4 << 30) + 1,
                max_query_bytes: 4 << 30,
            },
            native_event_rows: false, temporary_aliases: Default::default(), schema_defaults: vec![], reader: Default::default(),
        };
        let result = crate::query_timing::measure("oversized", executor.execute(plan)).await;
        // A closed native channel would return Unavailable if reached.
        assert!(matches!(result, Err(ExecutorError::EstimateExceeded { .. })));
        assert_eq!(executor.status().queued, 0);
    }

    #[tokio::test]
    #[ignore = "requires digest-verified NANO_CHDB_LIBRARY_PATH / NANO_CHDB_LIBRARY_SHA256"]
    async fn native_executor_uses_process_memory_tracking() {
        let runtime = NativeChdb::load_verified(
            std::env::var("NANO_CHDB_LIBRARY_PATH").unwrap(),
            &std::env::var("NANO_CHDB_LIBRARY_SHA256").unwrap(),
        ).unwrap();
        // Match the native deadline probes: chDB retains process-global hooks
        // beyond the connection, so its library must stay loaded until exit.
        std::mem::forget(runtime.clone());
        let executor = NativeExecutor::start_named_with_mode(runtime, 1, "isolation", ExecutorMode::ReadOnly).unwrap();
        let output = executor.execute_sql(
            "SELECT name, value FROM system.server_settings WHERE name IN ('memory_worker_use_cgroup', 'memory_worker_dynamic_hard_limit') ORDER BY name".into(), vec![],
        ).await.unwrap();
        let rows: Vec<serde_json::Value> = output.data.split(|byte| *byte == b'\n')
            .filter(|row| !row.is_empty()).map(|row| serde_json::from_slice(row).unwrap()).collect();
        assert_eq!(rows.len(), 2);
        assert!(rows.iter().all(|row| row["value"] == "0"));
    }

    #[tokio::test]
    #[ignore = "requires digest-verified native runtime"]
    async fn native_stream_phases_preserve_bound_rows() {
        let runtime = NativeChdb::load_verified(
            std::env::var("NANO_CHDB_LIBRARY_PATH").unwrap(),
            &std::env::var("NANO_CHDB_LIBRARY_SHA256").unwrap(),
        ).unwrap();
        std::mem::forget(runtime.clone());
        let executor = NativeExecutor::start_named_with_mode(runtime, 1, "phase-parity", ExecutorMode::ReadOnly).unwrap();
        assert!(executor.supports_streaming());
        let baseline = executor.execute_sql("SELECT getSetting('max_threads') AS threads".into(), vec![]).await.unwrap();
        executor.execute_sql("SELECT getSetting('max_threads') AS threads SETTINGS max_threads=1".into(), vec![]).await.unwrap();
        let reset = executor.execute_sql("SELECT getSetting('max_threads') AS threads".into(), vec![]).await.unwrap();
        assert_eq!(baseline.data, reset.data, "statement settings leaked into the resident session");
        let sql = "SELECT number FROM numbers(100) WHERE number >= {floor:UInt64} ORDER BY number SETTINGS max_threads=2";
        let params = vec![("floor".into(), "42".into())];
        let reference = executor.execute_sql(sql.into(), params.clone()).await.unwrap();
        crate::query_timing::measure("phase-parity", async {
            let plan = NativeQueryPlan {
                query_sha256: String::new(), sql: sql.into(), params,
                budget: crate::planner::QueryBudget { candidate_objects: 0, estimated_scan_bytes: 0, max_query_bytes: 1 << 20 },
                native_event_rows: false, temporary_aliases: Default::default(), schema_defaults: vec![], reader: Default::default(),
            };
            let mut stream = executor.execute_streaming(plan).await.unwrap();
            let mut data = Vec::new();
            while let Some(chunk) = stream.next().await { data.extend(chunk.unwrap().data); }
            assert_eq!(data, reference.data);
            // End can arrive before the lane publishes its completion count.
            // Wait for the count before checking the lane's finished work.
            tokio::time::timeout(Duration::from_secs(5), async {
                while executor.status().completed < 5 {
                    tokio::task::yield_now().await;
                }
            }).await.unwrap();
            let phases = crate::query_timing::current().unwrap();
            let p = phases.lock().unwrap();
            assert!(p.native_init_ms > 0.0);
            assert!(p.native_bind_ms > 0.0);
            assert!(p.native_init_abi_ms > 0.0);
            assert!(p.native_init_ms >= p.native_bind_ms + p.native_init_abi_ms);
            assert!(p.native_fetch_ms > 0.0);
            assert!(p.native_first_fetch_ms > 0.0);
            assert!(p.native_fetch_ms >= p.native_first_fetch_ms);
            assert_eq!(p.native_statements, 1);
            assert_eq!(p.native_session_reused, 1);
            assert!(p.native_fetch_calls >= 2);
            assert!(p.sql_prepare_ms > 0.0);
            assert!(p.chdb_ms >= p.native_init_ms + p.native_fetch_ms);
            Ok::<_, ()>(())
        }).await.unwrap();
    }

    #[tokio::test]
    #[ignore = "requires digest-verified native runtime"]
    async fn native_resident_lanes_isolate_parameters_and_recover_stream_errors() {
        let runtime = NativeChdb::load_verified(
            std::env::var("NANO_CHDB_LIBRARY_PATH").unwrap(),
            &std::env::var("NANO_CHDB_LIBRARY_SHA256").unwrap(),
        ).unwrap();
        std::mem::forget(runtime.clone());
        let executor = NativeExecutor::start_named_with_mode(runtime, 2, "resident", ExecutorMode::ReadOnly).unwrap();
        let plan = |value: u64| NativeQueryPlan {
            query_sha256: String::new(),
            sql: "SELECT {value:UInt64} AS value SETTINGS max_threads=1".into(),
            params: vec![("value".into(), value.to_string())],
            budget: crate::planner::QueryBudget { candidate_objects: 0, estimated_scan_bytes: 0, max_query_bytes: 1 << 20 },
            native_event_rows: false, temporary_aliases: Default::default(), schema_defaults: vec![], reader: Default::default(),
        };
        // Alternate concurrent callers on both persistent lanes. Bound values
        // must remain statement-local, and successes must not recycle a lane.
        for value in 0..60 {
            let executor = &executor;
            let read = |value| async move {
                let mut stream = executor.execute_streaming(plan(value)).await.unwrap();
                let mut data = Vec::new();
                while let Some(block) = stream.next().await { data.extend(block.unwrap().data); }
                let row: serde_json::Value = serde_json::from_slice(&data).unwrap();
                assert_eq!(row["value"], value);
            };
            tokio::join!(read(value * 2), read(value * 2 + 1));
        }
        assert_eq!(executor.status().connection_recycles, 0);
        let mut broken = plan(0);
        broken.sql = "SELECT __nano_missing_column".into();
        let mut stream = executor.execute_streaming(broken).await.unwrap();
        assert!(stream.next().await.unwrap().is_err());
        drop(stream);
        // Failure delivery is the recovery fence: a retry must never overlap
        // destruction of the failed session or its native allocations.
        assert_eq!(executor.status().connection_recycles, 1);
        let mut stream = executor.execute_streaming(plan(999)).await.unwrap();
        let mut data = Vec::new();
        while let Some(block) = stream.next().await { data.extend(block.unwrap().data); }
        let row: serde_json::Value = serde_json::from_slice(&data).unwrap();
        assert_eq!(row["value"], 999);
        assert_eq!(executor.status().connection_recycle_failures, 0);
    }

    #[test]
    fn connection_args_carry_the_server_memory_cap_next_to_the_tracker_args() {
        // NAN-2361: without a cap every lane opens chDB with only the tracker
        // flags, so the engine-wide ceiling is chDB's 0.9 x host RAM default
        // and N lanes x per-query budget can outgrow the container.
        assert_eq!(
            executor_connection_args(None),
            vec!["--memory_worker_use_cgroup=0", "--memory_worker_dynamic_hard_limit=0", "--logger.console=1", "--log-level=fatal"],
        );
        assert_eq!(
            executor_connection_args(Some(6 << 30)),
            vec![
                "--memory_worker_use_cgroup=0",
                "--memory_worker_dynamic_hard_limit=0",
                "--logger.console=1",
                "--log-level=fatal",
                "--max_server_memory_usage=6442450944",
            ],
        );
    }

    /// Two concurrent queries, each inside its own 4 GiB `max_memory_usage`,
    /// together exceed a 1 GiB engine-wide cap. Without the cap both succeed
    /// and the process grows past it; with it chDB fails the query that
    /// crosses the total with MEMORY_LIMIT_EXCEEDED and the executor keeps
    /// serving. Run ALONE (`--exact`): chDB fixes server settings at the first
    /// connect in the process, so an earlier uncapped test would mask it.
    #[tokio::test]
    #[ignore = "requires digest-verified NANO_CHDB_LIBRARY_PATH / NANO_CHDB_LIBRARY_SHA256; run alone"]
    async fn native_server_memory_cap_fails_concurrent_over_budget_queries_cleanly() {
        let runtime = NativeChdb::load_verified(
            std::env::var("NANO_CHDB_LIBRARY_PATH").unwrap(),
            &std::env::var("NANO_CHDB_LIBRARY_SHA256").unwrap(),
        ).unwrap();
        std::mem::forget(runtime.clone());
        let cap = 1u64 << 30;
        let executor = NativeExecutor::start_with_server_memory_limit(
            runtime, 2, "interactive", ExecutorMode::ReadOnly, Some(cap),
        ).unwrap();
        assert_eq!(executor.server_memory_limit_bytes(), Some(cap));
        let applied = executor.execute_sql(
            "SELECT value FROM system.server_settings WHERE name = 'max_server_memory_usage'".into(),
            vec![],
        ).await.unwrap();
        let applied: serde_json::Value = serde_json::from_slice(applied.data.trim_ascii()).unwrap();
        assert_eq!(applied["value"], cap.to_string());

        // ~640 MiB resident each; the per-query limit (4 GiB) never binds.
        let sql = "SELECT length(groupArray(number)) AS n FROM numbers(80000000) \
                   SETTINGS max_memory_usage=4294967296, max_threads=1";
        let (left, right) = tokio::join!(
            executor.execute_sql(sql.into(), vec![]),
            executor.execute_sql(sql.into(), vec![]),
        );
        let failures = [&left, &right]
            .into_iter()
            .filter_map(|result| result.as_ref().err())
            .map(|error| error.to_string())
            .collect::<Vec<_>>();
        assert!(!failures.is_empty(), "two 640 MiB queries must not both fit a 1 GiB cap");
        for failure in &failures {
            assert!(
                failure.contains("(total) memory limit exceeded") && failure.contains("MEMORY_LIMIT_EXCEEDED"),
                "failure must be the engine-wide cap: {failure}"
            );
        }
        // The process survived and the lanes still serve.
        let alive = executor.execute_sql("SELECT 1 AS ok".into(), vec![]).await.unwrap();
        assert!(String::from_utf8_lossy(&alive.data).contains("\"ok\":1"));
    }

    fn scheduler(lanes: Vec<Arc<LaneStatus>>) -> NativeExecutor {
        let senders = lanes
            .iter()
            .map(|_| {
                let (sender, _receiver) = mpsc::channel(1);
                sender
            })
            .collect::<Vec<_>>();
        let lane_count = senders.len();
        NativeExecutor {
            lane_name: "test".into(),
            senders: senders.into(),
            lanes: lanes.into(),
            next: Arc::new(AtomicUsize::new(0)),
            identity: 1,
            lane_wait_timeout: Duration::from_millis(50),
            server_memory_limit_bytes: None,
            result_limit_bytes: None,
            streaming: false,
            thread_budget: Arc::default(),
            agent_gate: Arc::new(AgentLaneGate::for_lanes(lane_count)),
            dns_refresher: None,
        }
    }

    fn running(lane: &Arc<LaneStatus>, id: u64, elapsed: u64, budget: u64) {
        let started = Instant::now() - Duration::from_secs(elapsed);
        *lane.started.lock().unwrap() = Some(started);
        *lane.query.lock().unwrap() = Some(RunningQuery {
            query_id: id, request_id: format!("request-{id}"),
            budget: Some(Duration::from_secs(budget)), started, cancel_requested: None,
        });
    }

    #[tokio::test]
    async fn executor_sheds_all_over_budget_without_admission_or_wait() {
        let lanes = vec![Arc::new(LaneStatus::default()), Arc::new(LaneStatus::default())];
        running(&lanes[0], 1, 61, 55);
        running(&lanes[1], 2, 56, 55);
        let executor = scheduler(lanes);
        // Closed channels would return Unavailable if admission were attempted.
        assert!(matches!(executor.execute_sql("SELECT 1".into(), vec![]).await, Err(ExecutorError::LaneWaitTimeout)));
        assert_eq!(executor.status().queued, 0);
        assert_eq!(executor.status().lane_wait_timeouts, 1);
        assert_eq!(executor.status().lane_wait_ms, 0);
    }

    #[test]
    fn agent_lane_limit_reserves_one_lane() {
        assert_eq!((agent_lane_limit(0), agent_lane_limit(1)), (1, 1), "a one-lane executor cannot reserve");
        assert_eq!(agent_lane_limit(2), 1, "query[T] large pool: one of two lanes for agents");
        assert_eq!(agent_lane_limit(6), 5, "query[T] small pool: five of six lanes for agents");
    }

    /// NAN-4747: an agent statement's wait for an agent slot is lane wait
    /// (`lane_wait_ms`), and one that finds no slot in time is a lane wait
    /// timeout (`lane_wait_timeouts`), on the executor and its timing line.
    #[tokio::test]
    async fn agent_slot_wait_and_timeout_count_as_lane_wait() {
        let (executor, mut lanes) = NativeExecutor::test_lanes(2, Duration::from_millis(60));
        let held = executor.agent_gate.slots.clone().try_acquire_owned().unwrap();
        let shed = crate::query_timing::measure("agent-wait", async {
            let result = executor.execute_sql("SELECT 1".into(), vec![]).await;
            let waited = crate::query_timing::current().map(|p| p.lock().unwrap().lane_wait_ms);
            result.map(|_| ()).map_err(|error| (error, waited))
        })
        .await;
        let Err((ExecutorError::LaneWaitTimeout, Some(waited))) = shed else { panic!("{shed:?}") };
        assert!(waited >= 50.0, "timing line lane_wait_ms {waited}");
        assert_eq!(lanes.jobs(), 0, "a shed agent reaches no lane");
        let status = executor.status();
        assert_eq!(status.lane_wait_timeouts, 1);
        assert!(status.lane_wait_ms >= 50, "{status:?}");
        assert_eq!(executor.agent_slots(), (1, 1), "nothing leaked beyond the held slot");
        drop(held);
        assert_eq!(executor.agent_slots(), (0, 1));
    }

    /// NAN-4742: 16 concurrent agent statements on a 6-lane executor hold at
    /// most 5 lanes; an analyst statement started beside them is sent to the
    /// sixth lane at once, and the agents waiting for a slot run as soon as
    /// a lane finishes an agent job.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn sixteen_agent_statements_leave_an_analyst_a_free_lane() {
        let lanes = (0..6).map(|_| Arc::new(LaneStatus::default())).collect::<Vec<_>>();
        let mut executor = scheduler(lanes.clone());
        let mut receivers = Vec::new();
        let mut senders = Vec::new();
        for _ in 0..6 {
            let (sender, receiver) = mpsc::channel(EXECUTOR_QUEUE_DEPTH);
            senders.push(sender);
            receivers.push(receiver);
        }
        executor.senders = senders.into();
        executor.lane_wait_timeout = Duration::from_secs(10);
        assert_eq!(executor.agent_slots(), (0, 5));

        let agents = (0..16)
            .map(|n| {
                let executor = executor.clone();
                tokio::spawn(async move {
                    crate::query_timing::measure(&format!("agent-{n}"), executor.execute_sql("SELECT 1".into(), vec![])).await
                })
            })
            .collect::<Vec<_>>();
        for _ in 0..500 {
            if executor.agent_slots().0 == 5 && executor.status().queued == 5 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(executor.agent_slots(), (5, 5), "agents hold one lane fewer than there are");
        assert_eq!(executor.status().queued, 5, "the other 11 agent statements wait for a slot, not on a lane");
        let free = (0..6).filter(|lane| lanes[*lane].queued.load(Ordering::Relaxed) == 0).collect::<Vec<_>>();
        assert_eq!(free.len(), 1, "one lane carries no agent work");

        let analyst_executor = executor.clone();
        let started = Instant::now();
        let analyst = tokio::spawn(async move {
            crate::query_timing::measure("user-a", analyst_executor.execute_sql("SELECT 1".into(), vec![])).await
        });
        let Command::Query(job) = tokio::time::timeout(Duration::from_secs(1), receivers[free[0]].recv())
            .await
            .expect("the analyst statement reaches the free lane at once")
            .unwrap()
        else {
            panic!("expected a query")
        };
        assert!(started.elapsed() < Duration::from_millis(500));
        assert_eq!(job.request_id, "user-a");
        assert_eq!(job.priority, crate::thread_budget::Priority::Interactive);
        drop(job);
        let _ = analyst.await;

        // Lanes finishing agent jobs admit the waiting agents: all 16 reach a
        // lane, never more than five at once.
        let mut delivered = 0;
        while delivered < 16 {
            let mut progressed = false;
            for (lane, receiver) in receivers.iter_mut().enumerate() {
                while let Ok(Command::Query(job)) = receiver.try_recv() {
                    assert_eq!(job.priority, crate::thread_budget::Priority::Agent, "lane {lane}");
                    assert!(executor.agent_slots().0 <= 5);
                    delivered += 1;
                    progressed = true;
                    drop(job);
                }
            }
            if !progressed {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            assert!(started.elapsed() < Duration::from_secs(5), "agents stalled at {delivered}");
        }
        for agent in agents {
            let _ = agent.await.unwrap();
        }
        assert_eq!(executor.agent_slots(), (0, 5));
    }

    #[tokio::test]
    async fn executor_waits_when_one_lane_is_within_budget() {
        let lanes = vec![Arc::new(LaneStatus::default()), Arc::new(LaneStatus::default())];
        running(&lanes[0], 1, 61, 55);
        running(&lanes[1], 2, 1, 55);
        let mut executor = scheduler(lanes);
        let (sender, mut receiver) = mpsc::channel(2);
        executor.senders = vec![executor.senders[0].clone(), sender].into();
        let result = executor.execute_sql("SELECT 1".into(), vec![]).await;
        assert!(matches!(result, Err(ExecutorError::LaneWaitTimeout)));
        assert!(executor.status().lane_wait_ms >= 40);
        assert_eq!(executor.status().queued, 1);
        let Command::Query(job) = receiver.recv().await.unwrap() else { panic!("expected query") };
        assert!(job.response.is_closed());
    }

    #[test]
    fn executor_cancellation_is_execution_specific_and_progress_includes_failures() {
        let lanes = vec![Arc::new(LaneStatus::default()), Arc::new(LaneStatus::default())];
        running(&lanes[0], 1, 61, 55);
        let executor = scheduler(lanes.clone());
        let query = executor.status().watchdog_query.unwrap();
        executor.cancel(query);
        lanes[0].query.lock().unwrap().as_mut().unwrap().cancel_requested = Some(Instant::now() - Duration::from_secs(70));
        assert!(executor.status().watchdog_query.unwrap().no_progress_for >= Duration::from_secs(70));
        // An errored native query also frees a lane and is forward progress.
        lanes[1].failed.fetch_add(1, Ordering::Relaxed);
        *lanes[1].last_finished.lock().unwrap() = Some(Instant::now());
        assert!(executor.status().watchdog_query.unwrap().no_progress_for < Duration::from_secs(1));
        running(&lanes[0], 2, 61, 55);
        executor.cancel(query);
        assert_eq!(executor.status().watchdog_query.unwrap().cancel_elapsed, None);
    }

    #[test]
    fn executor_interactive_helpers_are_bounded_and_durable_sql_is_unchanged() {
        let phases = Arc::new(Mutex::new(crate::query_timing::Phases { execution_seconds: 55, ..Default::default() }));
        let sql = "SELECT 1 SETTINGS max_execution_time=300".to_string();
        let (interactive, budget) = execution_sql(sql.clone(), Some(&phases));
        assert_eq!(interactive, "SELECT 1 SETTINGS max_execution_time=55");
        assert_eq!(budget, Some(Duration::from_secs(55)));
        assert_eq!(execution_sql(sql.clone(), None).0, sql);
        assert_eq!(execution_sql("SELECT 1".into(), Some(&phases)).0, "SELECT 1 SETTINGS max_execution_time=55");
        assert_eq!(execution_sql("SELECT 1 SETTINGS max_execution_time=10".into(), Some(&phases)).1, Some(Duration::from_secs(10)));
        assert!(execution_sql("SELECT 'max_execution_time=300'".into(), Some(&phases)).0.starts_with("SELECT 'max_execution_time=300'"));
        // NAN-3169: the parsing pool follows the statement's thread budget.
        assert_eq!(execution_sql("SELECT 1 SETTINGS max_threads=3".into(), Some(&phases)).0,
            "SELECT 1 SETTINGS max_threads=3, max_execution_time=55, max_parsing_threads=3");
        assert_eq!(execution_sql("SELECT 1 SETTINGS max_threads=3, max_parsing_threads=1".into(), Some(&phases)).0,
            "SELECT 1 SETTINGS max_threads=3, max_parsing_threads=1, max_execution_time=55");
        assert_eq!(execution_sql("SELECT 'max_threads=3'".into(), Some(&phases)).0, "SELECT 'max_threads=3' SETTINGS max_execution_time=55");
        assert_eq!(execution_sql("SELECT 1 SETTINGS max_threads=3".into(), None).0, "SELECT 1 SETTINGS max_threads=3", "jobs keep their settings");
    }

    #[tokio::test]
    async fn lane_wait_head_of_line_is_visible_and_bounded() {
        let (sender, mut receiver) = mpsc::channel(2);
        let mut executor = scheduler(vec![Arc::new(LaneStatus::default())]);
        executor.senders = vec![sender].into();
        // A deterministic blocked lane: the first admitted job occupies it for
        // one second; the second trivial query must stop waiting before that.
        let worker = tokio::spawn(async move {
            let Command::Query(first) = receiver.recv().await.unwrap() else {
                panic!("expected query")
            };
            first.started.send(Instant::now()).unwrap();
            tokio::time::sleep(Duration::from_secs(1)).await;
            drop(first.response);
            receiver.recv().await
        });
        let first_executor = executor.clone();
        let first =
            tokio::spawn(
                async move { first_executor.execute_sql("SELECT 1".into(), vec![]).await },
            );
        tokio::task::yield_now().await;
        crate::query_timing::measure("hol", async {
            let result = tokio::time::timeout(Duration::from_millis(200),
                executor.execute_sql("SELECT 2".into(), vec![])).await;
            let phases = crate::query_timing::current().unwrap();
            let value = serde_json::to_value(&*phases.lock().unwrap()).unwrap();
            assert!(value["lane_wait_ms"].as_f64().unwrap_or(0.0) > 0.0, "{value}");
            assert!(matches!(result, Ok(Err(ref error)) if error.to_string().contains("lane wait timed out")), "{result:?}");
            assert!(executor.status().lane_wait_ms > 0);
            assert_eq!(executor.status().lane_wait_timeouts, 1);
            Ok::<_, ()>(())
        }).await.unwrap();
        first.abort();
        worker.abort();
    }

    #[test]
    fn least_loaded_lane_avoids_an_old_in_flight_query() {
        let lanes = (0..3)
            .map(|_| Arc::new(LaneStatus::default()))
            .collect::<Vec<_>>();
        *lanes[0]
            .started
            .lock()
            .expect("executor lane status poisoned") =
            Some(Instant::now() - Duration::from_secs(30));
        *lanes[1]
            .started
            .lock()
            .expect("executor lane status poisoned") =
            Some(Instant::now() - Duration::from_secs(1));
        lanes[2].queued.store(2, Ordering::Relaxed);

        assert_eq!(scheduler(lanes).least_loaded_lane(crate::thread_budget::Priority::Interactive), 1);
    }

    #[test]
    fn read_only_setting_extends_a_trailing_settings_list_or_adds_one() {
        assert_eq!(
            with_read_only_setting("SELECT 1 SETTINGS max_threads=4, max_execution_time=30"),
            "SELECT 1 SETTINGS max_threads=4, max_execution_time=30, readonly=2"
        );
        assert_eq!(
            with_read_only_setting("SELECT 1 SETTINGS max_threads=4, x='a, b' \n"),
            "SELECT 1 SETTINGS max_threads=4, x='a, b', readonly=2"
        );
        assert_eq!(
            with_read_only_setting("SELECT count() FROM icebergS3('s3://b/t', SETTINGS iceberg_metadata_file_path='m.json') WHERE x = 1"),
            "SELECT count() FROM icebergS3('s3://b/t', SETTINGS iceberg_metadata_file_path='m.json') WHERE x = 1 SETTINGS readonly=2"
        );
        assert_eq!(
            with_read_only_setting("SELECT 1 LIMIT 10"),
            "SELECT 1 LIMIT 10 SETTINGS readonly=2"
        );
    }

    #[test]
    fn read_lanes_read_local_files_with_pread() {
        assert_eq!(
            read_lane_sql("SELECT 1 SETTINGS max_threads=4"),
            "SELECT 1 SETTINGS max_threads=4, readonly=2, storage_file_read_method='pread'"
        );
        assert_eq!(
            read_lane_sql("SELECT 1 LIMIT 10"),
            "SELECT 1 LIMIT 10 SETTINGS readonly=2, storage_file_read_method='pread'"
        );
        // A statement that names its own method keeps it.
        assert_eq!(
            read_lane_sql("SELECT 1 SETTINGS storage_file_read_method='mmap'"),
            "SELECT 1 SETTINGS storage_file_read_method='mmap', readonly=2"
        );
    }

    /// NAN-3152: an entity pivot over a wide part decodes only its own
    /// leaves (chDB prunes the unused CTE columns and Tuple siblings), and the
    /// read lane's range reads return the same rows as mmap. Run alone
    /// (`--exact`): SelectedBytes is process-global.
    #[tokio::test]
    #[ignore = "requires digest-verified native runtime"]
    async fn native_entity_pivot_reads_only_its_leaves() {
        let runtime = NativeChdb::load_verified(
            std::env::var("NANO_CHDB_LIBRARY_PATH").unwrap(),
            &std::env::var("NANO_CHDB_LIBRARY_SHA256").unwrap(),
        ).unwrap();
        std::mem::forget(runtime.clone());
        let work = tempfile::tempdir().unwrap();
        let path = work.path().join("wide.parquet").to_str().unwrap().to_string();
        let writer = NativeExecutor::start_named_with_mode(runtime.clone(), 1, "pivot-writer", ExecutorMode::ReadWrite).unwrap();
        // ~1 KiB of incompressible raw_data per row next to narrow leaves.
        writer.execute_sql(
            "INSERT INTO FUNCTION file({out:String}, Parquet) SELECT toDateTime64('2026-10-01 00:00:00', 6, 'UTC') + toIntervalMillisecond(number) AS time, \
             CAST(tuple(toString(generateUUIDv4()), if(number % 7 = 0, 'windows_security', 'windows_sysmon')), 'Tuple(uid Nullable(String), log_source Nullable(String))') AS metadata, \
             CAST(tuple(concat('host-', toString(number % 400))), 'Tuple(hostname Nullable(String))') AS device, \
             randomPrintableASCII(1024) AS raw_data FROM numbers(200000) SETTINGS max_threads=2".into(),
            vec![("out".into(), path.clone())],
        ).await.unwrap();
        let schema = "`time` DateTime64(6, 'UTC'), `metadata` Tuple(`uid` Nullable(String), `log_source` Nullable(String)), `device` Tuple(`hostname` Nullable(String)), `raw_data` Nullable(String)";
        // The planner's pivot shape: the stage carries raw_data/uid it never uses.
        let pivot = "WITH stage_0 AS (SELECT \"device.hostname\", \"metadata.log_source\", \"metadata.uid\", raw_data, time FROM \
             (SELECT `device`.`hostname` AS `device.hostname`, `metadata`.`log_source` AS `metadata.log_source`, `metadata`.`uid` AS `metadata.uid`, `raw_data` AS `raw_data`, `time` AS `time` \
             FROM file({source:String}, Parquet, {schema:String})) WHERE \"device.hostname\" = 'host-7') \
             SELECT \"metadata.log_source\", count() AS count FROM stage_0 GROUP BY \"metadata.log_source\" ORDER BY \"metadata.log_source\"";
        let reader = NativeExecutor::start_named_with_mode(runtime, 1, "pivot-reader", ExecutorMode::ReadOnly).unwrap();
        let params = vec![("source".to_string(), path), ("schema".to_string(), schema.to_string())];
        let selected_bytes = || async {
            let output = reader.execute_sql("SELECT value FROM system.events WHERE event = 'SelectedBytes'".into(), vec![]).await.unwrap();
            serde_json::from_slice::<serde_json::Value>(&output.data).unwrap()["value"].as_u64().unwrap()
        };
        let before = selected_bytes().await;
        let rows = reader.execute_sql(format!("{pivot} SETTINGS max_threads=2"), params.clone()).await.unwrap().data;
        let decoded = selected_bytes().await - before;
        // The narrow leaves are ~40 B/row; raw_data alone is 1 KiB/row.
        assert!(decoded < 200_000 * 100, "pivot decoded {decoded} bytes: unused wide columns were read");
        // An explicit mmap read (the engine default) returns the same rows.
        let mmap = reader.execute_sql(format!("{pivot} SETTINGS max_threads=2, storage_file_read_method='mmap'"), params).await.unwrap().data;
        assert_eq!(rows, mmap);
        assert!(String::from_utf8_lossy(&rows).contains("windows_sysmon"));
    }

    #[test]
    fn analysts_prefer_an_equally_loaded_lane_without_agent_work() {
        use crate::thread_budget::Priority;
        let lanes = (0..3).map(|_| Arc::new(LaneStatus::default())).collect::<Vec<_>>();
        // Every lane runs one statement; lanes 0 and 1 carry agent work and
        // lane 0's statement is the freshest, so load and age alone pick it.
        for (lane, age) in lanes.iter().zip([1, 5, 9]) {
            *lane.started.lock().unwrap() = Some(Instant::now() - Duration::from_secs(age));
        }
        let gate = AgentLaneGate::for_lanes(3);
        let permit = |gate: &AgentLaneGate| gate.slots.clone().try_acquire_owned().unwrap();
        let first = AgentSlot::on_lane(permit(&gate), &lanes[0]);
        let second = AgentSlot::on_lane(permit(&gate), &lanes[1]);
        let executor = scheduler(lanes.clone());
        assert_eq!(executor.least_loaded_lane(Priority::Interactive), 2, "the analyst skips agent lanes of equal load");
        assert_eq!(executor.least_loaded_lane(Priority::Agent), 0, "agents keep the plain order");
        lanes[2].queued.store(1, Ordering::Relaxed);
        assert_eq!(executor.least_loaded_lane(Priority::Interactive), 0, "load still comes first");
        drop((first, second));
        assert_eq!(lanes.iter().map(|lane| lane.agents.load(Ordering::Relaxed)).sum::<usize>(), 0);
        assert_eq!(gate.held(), 0, "dropping the slot gives the permit back");
    }

    #[test]
    fn least_loaded_lane_keeps_round_robin_tie_breaking() {
        let lanes = (0..3)
            .map(|_| Arc::new(LaneStatus::default()))
            .collect::<Vec<_>>();
        let scheduler = scheduler(lanes);

        assert_eq!(scheduler.least_loaded_lane(crate::thread_budget::Priority::Interactive), 0);
        assert_eq!(scheduler.least_loaded_lane(crate::thread_budget::Priority::Interactive), 1);
        assert_eq!(scheduler.least_loaded_lane(crate::thread_budget::Priority::Interactive), 2);
    }
}
