// SPDX-License-Identifier: AGPL-3.0-or-later

//! Async / durable search jobs over parts (design 3.2 "Async search,
//! exports"). A job is the reader's durable `SearchNplV1` path with the part
//! source: the same compiled SQL and planner binding as an interactive
//! search, spooled by chDB straight to Parquet (`INSERT INTO FUNCTION file`)
//! on the engine's single read-write lane, then committed with the reader's
//! own `job::commit_bounded_parquet_result`, so result pages are
//! byte-compatible with `/v1/jobs/result-page`.
//!
//! Hosted results use the tenant's durable R2 result prefix. Local cells can
//! keep results in their private state directory for tests and development.
//!
//! Read point (NAN-2924): a job runs at the cell's CURRENT verified head, which
//! the admitted head bounds from below, as ClickHouse async jobs read the data
//! present when they execute. The admitted head is a floor, not a snapshot, so
//! no admitted part set has to outlive part GC while a job waits in the queue.
//! During execution the selection holds local leases on every selected part
//! file, and a superseded part stays in R2 for at least the delete grace
//! floor (1 h, migration 9003440) after the merge that retires it.

use anyhow::{bail, Context, Result};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeSet, VecDeque};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;

use super::engine::{compiled_bound_us, compiled_window_us, plan_logs, BroadNplRequest, JobLane, PartQueryEngine, PartQueryError};
use crate::job::{commit_bounded_parquet_result_to, LakeQueryJobSpec, ResultArtifactRef, ResultExecutionMetadata};
use super::job_results::JobResultStore;

/// Generation identity recorded on part-backed job specs.
pub const PARTS_GENERATION_ID: &str = "parts-v1";

/// A job's immutable part-log read point and image-pinned executables.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PartJobPin {
    pub generation_id: String,
    pub snapshot_id: i64,
    pub event_config_sha256: String,
    pub compiler_sha256: String,
    pub native_artifact_sha256: String,
}

impl PartJobPin {
    pub fn at_head(head: Option<(u64, String)>, schema_fingerprint: Option<&str>, compiler_sha256: &str, native_artifact_sha256: &str) -> Result<Self> {
        let (seq, head_sha256) = head.unwrap_or((0, "0".repeat(64)));
        let snapshot_id = i64::try_from(seq).context("part-log sequence exceeds job pin range")?;
        let mut hasher = Sha256::new();
        hasher.update(b"nano.parts-query-event-config.v1\0");
        hasher.update(crate::parts::provenance::ADMISSION_CONTRACT.as_bytes());
        hasher.update(b"\0");
        hasher.update(schema_fingerprint.unwrap_or("empty").as_bytes());
        let event_config_sha256 = hex::encode(hasher.finalize());
        let generation_id = if seq == 0 {
            format!("event-0-{}", &event_config_sha256[..16])
        } else {
            format!("{PARTS_GENERATION_ID}-{seq}-{}", head_sha256.get(..16).context("part-log head digest is malformed")?)
        };
        Ok(Self {
            generation_id,
            snapshot_id,
            event_config_sha256,
            compiler_sha256: compiler_sha256.to_string(),
            native_artifact_sha256: native_artifact_sha256.to_string(),
        })
    }

    /// Whether this (current) pin may execute `spec`: the same image-pinned
    /// compiler and native artifact, no gen1 hot tail, a well-formed part
    /// generation, and an admitted head at or below this head. The schema
    /// digest is not compared: the job compiles against the current schema,
    /// exactly as an interactive search does.
    pub fn admits(&self, spec: &LakeQueryJobSpec) -> Result<()> {
        if spec.compiler_sha256 != self.compiler_sha256 || spec.native_artifact_sha256 != self.native_artifact_sha256 {
            bail!("search job was admitted for different query artifacts");
        }
        if spec.hot_tail_manifest_sha256.is_some() || spec.hot_tail_snapshot_id.is_some() || spec.hot_tail_id.is_some() {
            bail!("part jobs carry no hot tail");
        }
        let admitted = admitted_seq(spec)?;
        if admitted > self.snapshot_id {
            bail!("search job was admitted at part-log head {admitted}, beyond this cell's verified head {}", self.snapshot_id);
        }
        Ok(())
    }
}

/// The admitted part-log sequence named by a part job's generation:
/// `event-0-{config16}` for an empty log, else `parts-v1-{seq}-{head16}`.
fn admitted_seq(spec: &LakeQueryJobSpec) -> Result<i64> {
    let digest = if spec.snapshot_id == 0 {
        spec.generation_id.strip_prefix("event-0-")
    } else {
        spec.generation_id.strip_prefix(&format!("{PARTS_GENERATION_ID}-{}-", spec.snapshot_id))
    }
    .context("job generation does not name its admitted part-log head")?;
    if spec.snapshot_id < 0 || digest.len() != 16 || !digest.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        bail!("job generation head is malformed");
    }
    Ok(spec.snapshot_id)
}

/// Run one durable job attempt: a search, or (NAN-3078) a typed product
/// view. Both read only inside [`LakeQueryJobSpec::execution_window`].
pub async fn run_job(engine: &PartQueryEngine, spec: &LakeQueryJobSpec, results: &JobResultStore, pin: &PartJobPin, cancelled: &AtomicBool) -> Result<ResultArtifactRef> {
    run_job_on(engine, JobLane::General, spec, results, pin, cancelled).await
}

/// [`run_job`] on the job lane query[T] admitted it to (NAN-4290). Only a
/// search runs on the small-job lane.
pub async fn run_job_on(engine: &PartQueryEngine, lane: JobLane, spec: &LakeQueryJobSpec, results: &JobResultStore, pin: &PartJobPin, cancelled: &AtomicBool) -> Result<ResultArtifactRef> {
    if spec.task.is_lean_view() {
        if lane != JobLane::General {
            bail!("product-view jobs run on the general job lane only");
        }
        super::view_jobs::run_view_job(engine, spec, results, pin, cancelled).await
    } else {
        run_search_job_on(engine, lane, spec, results, pin, cancelled).await
    }
}

/// NAN-4290: whether query[T] admits this job to its small-job lane: a
/// search over at most a day ([`nanosiem_core::search::small_job_lane`]) in
/// the medium resource class (a promoted job is large). Classified from the
/// signed spec itself, never from the runner's slot.
pub fn small_job_spec(spec: &LakeQueryJobSpec) -> bool {
    let at = |text: &str| chrono::DateTime::parse_from_rfc3339(text).ok().map(|time| time.with_timezone(&chrono::Utc));
    match (at(&spec.request.start), at(&spec.request.end)) {
        (Some(start), Some(end)) => nanosiem_core::search::small_job_lane(
            &spec.task, start, end, spec.resource_class == crate::job::ResourceClass::Large,
        ),
        _ => false,
    }
}

/// Run one durable `logs` search job and commit its result under the
/// tenant's R2 result root through the exchanged `job_results` grant.
pub async fn run_search_job(engine: &PartQueryEngine, spec: &LakeQueryJobSpec, results: &JobResultStore, pin: &PartJobPin, cancelled: &AtomicBool) -> Result<ResultArtifactRef> {
    run_search_job_on(engine, JobLane::General, spec, results, pin, cancelled).await
}

async fn run_search_job_on(engine: &PartQueryEngine, lane: JobLane, spec: &LakeQueryJobSpec, results: &JobResultStore, pin: &PartJobPin, cancelled: &AtomicBool) -> Result<ResultArtifactRef> {
    spec.validate()?;
    pin.admits(spec)?;
    if cancelled.load(Ordering::Acquire) {
        bail!("search job was cancelled before execution");
    }
    if spec.tenant_id != engine.settings().tenant_id {
        bail!("job tenant is not this process's tenant");
    }
    if spec.request.dataset != "logs" {
        bail!("part jobs serve dataset logs; risk nPL runs through /v1/risk");
    }
    // NAN-3078: a post-processed search runs its SQL-only candidate prefix
    // (`request.query`) exactly like a plain search; Search applies the suffix.
    if !spec.task.is_search() {
        bail!("part jobs run search tasks only");
    }
    if results.tenant_id() != spec.tenant_id {
        bail!("job-result store belongs to another tenant");
    }
    // Fail before executing: no grant, no job (typed, never file://).
    results.current()?;
    // NAN-3078: never read before the proof's current retention cutoff.
    let (window_start, window_end) = spec.execution_window(chrono::Utc::now())?;
    let writer = engine.job_writer(lane).context("the part engine has no read-write lane for this job lane")?;
    let started = Instant::now();
    let request = BroadNplRequest {
        request_id: format!("{}-{}-search", spec.job_id, spec.attempt_id),
        tenant_id: spec.tenant_id.clone(),
        dataset: spec.request.dataset.clone(),
        query: spec.request.query.clone(),
        start: window_start.to_rfc3339(),
        end: window_end.to_rfc3339(),
        limit: spec.request.limit,
        offset: spec.request.offset,
        table_view: spec.request.table_view,
        use_cache: false,
        cursor_time: None,
        cursor_event_uid: None,
        anchor_us: None,
        decay: None,
        clear_boundaries: Default::default(),
        watch_weights: Default::default(),
        minimum_clear_revision: None,
        deny_source_types: nanosiem_core::auth::source_visibility::expand_unattributed_sources(&spec.scope_deny),
    };
    let work = async {
        let field_types = engine.field_types().await.map_err(|error| anyhow::anyhow!(error.to_string()))?;
        let compiled = engine.compile(&request, field_types).await.map_err(|error| anyhow::anyhow!(error.to_string()))?;
        // NAN-4280: the request's half-open `[from, to)` µs; chunks below are
        // request windows in the same terms (selection converts per chunk).
        let (from_us, to_us) = compiled_bound_us(&compiled).map_err(|error| anyhow::anyhow!(error.to_string()))?;
        if !super::view_jobs::compiled_within((from_us, to_us), window_start, window_end) {
            bail!("search job compiled a window outside its retention-bound range");
        }
        let field_types = engine.field_types().await.map_err(|error| anyhow::anyhow!(error.to_string()))?;
        // NAN-3809: a plain search over a settled window records the data
        // identity it read, bracketed before selection and after commit, so a
        // later identical search can be re-served from these result pages.
        let reuse_before = if reuse_eligible(spec, &request, to_us) {
            window_reuse_identity(engine, pin, from_us, to_us).await.ok()
        } else {
            None
        };
        // NAN-4156 / NAN-4164: a newest-first event page (`… | head N`,
        // statement `ORDER BY time DESC LIMIT n`) reads disjoint time chunks
        // newest first (see [`disjoint_chunks`]), appending each chunk's rows,
        // and stops once it holds `n`: every row a later chunk could add is
        // older than all of them. A chunk whose statement hits the statement
        // time limit is halved and both halves read, newer first, so a cold
        // week finishes in bounded statements instead of timing out whole.
        // Any other statement reads the whole window once, as before.
        let walk = newest_first_walk(engine, &compiled, from_us, to_us).await?;
        let row_cap = walk.as_ref().map(|walk| walk.row_cap);
        let mut chunks = walk.map_or_else(|| VecDeque::from([(from_us, to_us)]), |walk| disjoint_chunks(&walk.starts, to_us));
        let (mut engine_seconds, mut storage_rows, mut storage_bytes) = (0.0_f64, 0_u64, 0_u64);
        let mut spools: Vec<(tempfile::TempDir, std::path::PathBuf)> = Vec::new();
        let mut aliases = BTreeSet::new();
        let (mut found, mut statements, mut splits) = (0_u64, 0_usize, 0_usize);
        while let Some((chunk_from_us, chunk_to_us)) = chunks.pop_front() {
            let narrowed;
            let chunk_compiled = if (chunk_from_us, chunk_to_us) == (from_us, to_us) {
                &compiled
            } else {
                let narrowed_request = BroadNplRequest {
                    start: micros_rfc3339(chunk_from_us)?,
                    end: micros_rfc3339(chunk_to_us)?,
                    ..request.clone()
                };
                narrowed = engine.compile(&narrowed_request, field_types.clone()).await.map_err(|error| anyhow::anyhow!(error.to_string()))?;
                // The narrowed statement must be the same page over less time;
                // anything else reads the whole window once.
                if crate::planner::newest_first_row_cap(&narrowed.sql) != row_cap {
                    tracing::warn!(job_id = %spec.job_id, chunk_from_us, chunk_to_us, "newest-first job chunk changed statement shape; reading the whole window");
                    (spools, aliases, found) = (Vec::new(), BTreeSet::new(), 0);
                    chunks = VecDeque::from([(from_us, to_us)]);
                    // Its halves would recompile to the same shape change.
                    splits = JOB_MAX_SPLITS;
                    continue;
                }
                &narrowed
            };
            let (attempt_from_us, attempt_to_us) = compiled_window_us(chunk_compiled).map_err(|error| anyhow::anyhow!(error.to_string()))?;
            if !super::view_jobs::compiled_within((attempt_from_us, attempt_to_us), window_start, window_end) {
                bail!("search job compiled a window outside its retention-bound range");
            }
            let membership = engine
                .membership(&request.query, &field_types, attempt_from_us, attempt_to_us)
                .await
                .map_err(|error| anyhow::anyhow!(error.to_string()))?;
            // Leases every selected part file locally before execution. NAN-3644:
            // a window over the cold ceiling runs its first stage in batches
            // instead, each batch leased and released in turn (see
            // `cold_batches`); the statement then reads the spooled rows.
            let (selection, batched) = match engine
                .select_with(attempt_from_us, attempt_to_us, &chunk_compiled.candidate_hints, membership.as_ref())
                .await
            {
                Ok(selection) => (Some(selection), None),
                Err(PartQueryError::ColdScanTooLarge { needed_bytes, .. }) if super::cold_batches::not_batchable(chunk_compiled).is_none() => {
                    let fence = super::cold_batches::BatchFence { scan_budget: Some(spec.scan_budget_bytes), cancelled: Some(cancelled) };
                    let batched = Box::pin(engine.cold_batches(chunk_compiled, (attempt_from_us, attempt_to_us), membership.as_ref(), needed_bytes, fence))
                        .await
                        .map_err(anyhow::Error::new)?;
                    (None, Some(batched))
                }
                // NAN-3272: keep the typed refusal (cold budget) for the HTTP mapping.
                Err(error) => return Err(anyhow::Error::new(error)),
            };
            // The head only advances, so the selection is at or after admission.
            let (selected_head, selected_schema) = engine.head_and_schema_fingerprint().await;
            PartJobPin::at_head(selected_head, selected_schema.as_deref(), &pin.compiler_sha256, &pin.native_artifact_sha256)?
                .admits(spec)?;
            if cancelled.load(Ordering::Acquire) {
                bail!("search job was cancelled before execution");
            }
            let mut plan = match (&selection, &batched) {
                (Some(selection), _) => plan_logs(selection, chunk_compiled, None).map_err(|error| anyhow::anyhow!(error.to_string()))?,
                (None, Some(batched)) => batched.plan.clone(),
                (None, None) => bail!("search job has neither a selection nor a batched read"),
            };
            // Each chunk is inside the window, so no chunk reads more than the
            // whole window's statement would have.
            if plan.budget.estimated_scan_bytes > spec.scan_budget_bytes {
                bail!("job scan of {} bytes exceeds its budget of {}", plan.budget.estimated_scan_bytes, spec.scan_budget_bytes);
            }
            let spool = tempfile::tempdir().context("create durable search result spool")?;
            let output_path = spool.path().join("search-result.parquet");
            plan.params.push((
                "job_result_output".to_string(),
                output_path.to_str().context("spool path is not UTF-8")?.to_string(),
            ));
            plan.sql = format!("INSERT INTO FUNCTION file({{job_result_output:String}}, Parquet) {}", plan.sql);
            let chunk_aliases = plan.temporary_aliases.iter().cloned().collect::<BTreeSet<_>>();
            let plan = job_statement_plan(plan, engine.job_lane_memory_bytes(lane), row_cap);
            statements += 1;
            let output = match execute_with_memory_rungs(writer, plan, &output_path, &spec.job_id, cancelled).await {
                Ok(output) => output,
                Err(error) if row_cap.is_some() && splits < JOB_MAX_SPLITS && is_statement_timeout(&error) && !cancelled.load(Ordering::Acquire) => {
                    let Some((older, newer)) = split_chunk((chunk_from_us, chunk_to_us)) else {
                        return Err(error);
                    };
                    splits += 1;
                    tracing::warn!(job_id = %spec.job_id, chunk_from_us, chunk_to_us, splits, "newest-first job chunk exceeded the statement time limit; reading it in halves, newer first");
                    chunks.push_front(older);
                    chunks.push_front(newer);
                    continue;
                }
                Err(error) => return Err(error),
            };
            // The rows are in the spool: release this chunk's leases before
            // the next chunk selects, so a long walk never holds the week.
            drop(selection);
            drop(batched);
            engine_seconds += output.elapsed.as_secs_f64();
            storage_rows = storage_rows.saturating_add(output.storage_rows_read);
            storage_bytes = storage_bytes.saturating_add(output.storage_bytes_read);
            if cancelled.load(Ordering::Acquire) {
                bail!("search job was cancelled before result commit");
            }
            if !output_path.is_file() {
                bail!("durable search query did not produce its Parquet spool");
            }
            found = found.saturating_add(spooled_rows(&output_path)?);
            aliases.extend(chunk_aliases);
            spools.push((spool, output_path));
            if page_full(row_cap, found) {
                break;
            }
        }
        if let Some(row_cap) = row_cap {
            tracing::info!(job_id = %spec.job_id, chunks = spools.len(), statements, splits, rows = found, row_cap, from_us, "newest-first job page read");
        }
        let (output_path, _spools) = match spools.len() {
            0 => bail!("search job read no chunk"),
            1 => (spools[0].1.clone(), spools),
            _ => {
                let merged = tempfile::tempdir().context("create merged search result spool")?;
                let path = merged.path().join("search-result.parquet");
                let parts = spools.iter().map(|(_, path)| path.as_path()).collect::<Vec<_>>();
                concat_spools(&parts, row_cap, &path)?;
                spools.push((merged, path.clone()));
                (path, spools)
            }
        };
        let execution = ResultExecutionMetadata {
            wall_seconds: started.elapsed().as_secs_f64(),
            engine_seconds,
            storage_rows,
            storage_bytes,
            peak_rss_bytes: None,
            spill_bytes: None,
        };
        let reference = commit_job_result(results, spec, &output_path, &aliases, &execution).await?;
        if let Some(before) = reuse_before.filter(|_| reference.rows > 0 && reference.parts > 0) {
            record_reuse_marker(engine, results, pin, spec, &reference, (from_us, to_us), before).await;
        }
        Ok(reference)
    };
    work.await
}

/// NAN-4277 (F18): the statement time limit of a durable job statement that
/// reads its whole window at once (an aggregate such as `| stats count`).
///
/// It used to inherit the engine's interactive-era cap (120 s, `EngineBoot`
/// default), so the durable lane could not run any aggregate the interactive
/// path could not: on a large hosted tenant (2026-10-20) a 7 d `HOSTNAME.EXE | stats
/// count` escalated at the 45 s deadline, then both durable attempts died at
/// exactly 120 s (`TIMEOUT_EXCEEDED`, the second after two memory rungs).
/// Ten minutes per statement keeps a job with every memory rung
/// (3 statements) inside the runner's dispatch timeout
/// (`--execution-seconds`, default 3,600 s). The work stays inside the
/// tenant's query[T] cgroup, so the CPU budget is unchanged; only the wall
/// time it may take grows.
pub(crate) const JOB_STATEMENT_SECONDS: u64 = 600;

/// The statement a durable search job executes: the job lane's memory cap
/// (NAN-3077) and, for a whole-window statement (`row_cap` `None`: nothing
/// to split into chunks, e.g. an aggregate), [`JOB_STATEMENT_SECONDS`]
/// (NAN-4277, only ever raised). A newest-first chunk keeps the engine cap,
/// so a slow chunk is halved early (NAN-4164).
pub(crate) fn job_statement_plan(
    mut plan: crate::planner::NativeQueryPlan,
    memory_bytes: u64,
    row_cap: Option<usize>,
) -> crate::planner::NativeQueryPlan {
    plan = super::engine::with_memory_cap(plan, memory_bytes);
    if row_cap.is_none() {
        plan.sql = job_statement_time_sql(&plan.sql, JOB_STATEMENT_SECONDS);
    }
    plan
}

fn job_statement_time_sql(sql: &str, seconds: u64) -> String {
    static LIMIT: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    let limit = LIMIT.get_or_init(|| regex::Regex::new(r"max_execution_time\s*=\s*(\d+)").expect("static regex"));
    if limit.is_match(sql) {
        return limit
            .replace_all(sql, |captures: &regex::Captures<'_>| {
                let current = captures[1].parse::<u64>().unwrap_or(0);
                format!("max_execution_time={}", current.max(seconds))
            })
            .into_owned();
    }
    let separator = if super::lanes::setting(sql, "max_threads").is_some() { "," } else { " SETTINGS" };
    format!("{sql}{separator} max_execution_time={seconds}")
}

/// NAN-4164: the settings a job statement reruns with after chDB refuses it
/// for memory, cheapest first. A job has no lane ladder (it already holds
/// the job lane's whole cap), and the 2026-10-20 7 d bare-IP job failed in
/// the read stage (`ColumnData: column: raw_data`, 3.55 of 3.54 GiB at 16
/// threads with the default 4 GiB Parquet prefetch watermark), which no
/// spill can fix. So the first rung keeps the statement's threads and bounds
/// the Parquet reader ([`super::lanes::bounded_reader_sql`]), the second is
/// the interactive path's degraded rung (one thread, NAN-3650). Every rung
/// only lowers settings, so the rows are unchanged; a rung identical to the
/// statement before it is skipped.
pub(crate) fn job_memory_rungs(sql: &str) -> Vec<String> {
    let threads = super::lanes::setting(sql, "max_threads").unwrap_or(super::lanes::BOUNDED_READER_THREADS);
    let mut rungs: Vec<String> = Vec::new();
    for rung in [super::lanes::bounded_reader_sql(sql, threads), super::lanes::degraded_sql(sql)] {
        if rung != sql && rungs.last() != Some(&rung) {
            rungs.push(rung);
        }
    }
    rungs
}

/// Run a job statement, rerunning it on [`job_memory_rungs`] while chDB
/// refuses it for memory (and the job is not cancelled). A refused
/// `INSERT INTO FUNCTION file` can leave a partial spool, which is removed
/// before each rerun.
async fn execute_with_memory_rungs(
    writer: &crate::executor::NativeExecutor,
    plan: crate::planner::NativeQueryPlan,
    spool: &std::path::Path,
    job_id: &str,
    cancelled: &AtomicBool,
) -> Result<crate::native::NativeQueryOutput> {
    let rungs = job_memory_rungs(&plan.sql);
    let mut error = match writer.execute(plan.clone()).await {
        Ok(output) => return Ok(output),
        Err(error) => error,
    };
    for (rung, sql) in rungs.into_iter().enumerate() {
        if !super::memory_budget::is_memory_limit_error(&error.to_string()) || cancelled.load(Ordering::Acquire) {
            break;
        }
        tracing::warn!(job_id, rung, "search job statement exceeded its memory cap; rerunning with a bounded Parquet reader");
        if spool.exists() {
            std::fs::remove_file(spool).context("remove a refused job's partial spool")?;
        }
        let mut again = plan.clone();
        again.sql = sql;
        match writer.execute(again).await {
            Ok(output) => return Ok(output),
            Err(next) => error = next,
        }
    }
    Err(anyhow::Error::new(error))
}

/// NAN-4156: the newest window a newest-first job reads first (µs), and
/// the factor each wider window grows by. A 168 h job reads at most
/// 15 m, 1 h, 4 h, 16 h, 64 h and then the whole window.
pub const JOB_WALK_FIRST_US: i64 = 15 * 60 * 1_000_000;
pub const JOB_WALK_GROWTH: i64 = 4;

/// NAN-4156: the cumulative windows of a newest-first job.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewestFirstWalk {
    /// The statement's `ORDER BY time DESC LIMIT n` bound.
    pub row_cap: usize,
    /// Window starts (µs), newest first; the last is the job's own start.
    pub starts: Vec<i64>,
}

/// The starts of the cumulative windows `[start, to]` anchored at
/// `anchor_us` (the newest data, at most `to`), widening by
/// [`JOB_WALK_GROWTH`] from [`JOB_WALK_FIRST_US`]; the last is `from_us`.
pub fn walk_starts(from_us: i64, anchor_us: i64) -> Vec<i64> {
    let mut starts = Vec::new();
    let mut width = JOB_WALK_FIRST_US;
    while anchor_us.saturating_sub(width) > from_us {
        starts.push(anchor_us - width);
        width = width.saturating_mul(JOB_WALK_GROWTH);
    }
    starts.push(from_us);
    starts
}

/// Whether a window's statement returned its whole page: the top `n` rows
/// of `[start, to)` are then exactly the top `n` of the whole window, since
/// every row the window leaves out is older than all of them.
pub fn page_full(row_cap: Option<usize>, rows: u64) -> bool {
    row_cap.is_none_or(|cap| rows >= cap as u64)
}

/// NAN-4164: the most times one job halves a chunk that hit the statement
/// time limit, and the narrowest chunk it halves (µs). A 104 h chunk reaches
/// 15 m in nine halvings; past the bound the timeout is the job's error.
pub const JOB_MAX_SPLITS: usize = 16;
pub const JOB_SPLIT_MIN_US: i64 = JOB_WALK_FIRST_US;

/// NAN-4164: the disjoint chunks of a newest-first walk, newest first:
/// `[starts[0], to)`, then `[starts[i], starts[i-1])`. NAN-4280: the compiled
/// time bound is half-open (`time >= start AND time < end`, µs), so adjacent
/// chunks share their boundary instant and still cover `[starts.last(), to)`
/// exactly once. (The old inclusive `BETWEEN` needed `starts[i-1] - 1 µs`.)
/// Unlike the cumulative windows before them, a chunk never re-reads newer
/// data. An empty chunk (`start >= end`) is never emitted: it would not
/// compile.
pub fn disjoint_chunks(starts: &[i64], to_us: i64) -> VecDeque<(i64, i64)> {
    let mut chunks = VecDeque::with_capacity(starts.len());
    let mut end = to_us;
    for start in starts {
        let start = (*start).min(end);
        if start < end {
            chunks.push_back((start, end));
        }
        end = start;
    }
    chunks
}

/// NAN-4164: a chunk's older and newer halves (half-open µs bounds that
/// share `mid` and cover it exactly once, NAN-4280), or `None` when it is
/// narrower than twice [`JOB_SPLIT_MIN_US`].
pub fn split_chunk((from_us, to_us): (i64, i64)) -> Option<((i64, i64), (i64, i64))> {
    if to_us.saturating_sub(from_us) < 2 * JOB_SPLIT_MIN_US {
        return None;
    }
    let mid = from_us + (to_us - from_us) / 2;
    Some(((from_us, mid), (mid, to_us)))
}

/// Whether a job statement failed on chDB's statement time limit
/// (`max_execution_time`, `Code: 159 … TIMEOUT_EXCEEDED`).
fn is_statement_timeout(error: &anyhow::Error) -> bool {
    format!("{error:#}").contains("TIMEOUT_EXCEEDED")
}

fn micros_rfc3339(us: i64) -> Result<String> {
    Ok(chrono::DateTime::<chrono::Utc>::from_timestamp_micros(us)
        .context("job chunk bound is not a valid time")?
        .to_rfc3339_opts(chrono::SecondsFormat::Micros, true))
}

/// NAN-4164: one Parquet result from chunk spools read newest first, in
/// order, keeping at most `row_cap` rows. Every chunk ran the same
/// statement, so their schemas match; a mismatch is an error, never a
/// silently reshaped page.
pub(crate) fn concat_spools(spools: &[&std::path::Path], row_cap: Option<usize>, output: &std::path::Path) -> Result<u64> {
    use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;
    let first = ParquetRecordBatchReaderBuilder::try_new(std::fs::File::open(spools[0]).context("open a job chunk spool")?)?;
    let schema = first.schema().clone();
    let file = std::fs::File::create(output).context("create the merged job result spool")?;
    let mut writer = parquet::arrow::ArrowWriter::try_new(file, schema.clone(), None)?;
    let mut left = row_cap.map_or(u64::MAX, |cap| cap as u64);
    let mut written = 0_u64;
    for path in spools {
        if left == 0 {
            break;
        }
        let reader = ParquetRecordBatchReaderBuilder::try_new(std::fs::File::open(path).context("open a job chunk spool")?)?;
        if reader.schema().fields() != schema.fields() {
            bail!("job chunk spools disagree on their result schema");
        }
        for batch in reader.build()? {
            let batch = batch?;
            let take = (batch.num_rows() as u64).min(left);
            if take == 0 {
                break;
            }
            writer.write(&batch.slice(0, take as usize))?;
            (left, written) = (left - take, written + take);
        }
    }
    writer.close()?;
    Ok(written)
}

/// The walk for a newest-first page statement, or `None` for any other
/// statement shape (which reads the whole window once).
async fn newest_first_walk(engine: &PartQueryEngine, compiled: &crate::planner::CompiledQuery, from_us: i64, to_us: i64) -> Result<Option<NewestFirstWalk>> {
    if !compiled.newest_first_event_rows {
        return Ok(None);
    }
    let Some(row_cap) = crate::planner::newest_first_row_cap(&compiled.sql).filter(|cap| *cap > 0) else {
        return Ok(None);
    };
    // Anchor at the newest data that exists (ingest lag leaves the end of
    // a window empty); chunking never changes the rows.
    let (parts, _, _, _) = engine.snapshot(from_us, to_us).await.map_err(|error| anyhow::anyhow!(error.to_string()))?;
    let anchor_us = parts.iter().map(|part| part.max_time_us.saturating_add(1)).max().unwrap_or(to_us).clamp(from_us, to_us);
    Ok(Some(NewestFirstWalk { row_cap, starts: walk_starts(from_us, anchor_us) }))
}

/// Rows in a spooled Parquet result.
fn spooled_rows(path: &std::path::Path) -> Result<u64> {
    use parquet::file::reader::FileReader;
    let file = std::fs::File::open(path).context("open the job result spool")?;
    let reader = parquet::file::reader::SerializedFileReader::new(file).context("read the job result spool footer")?;
    u64::try_from(reader.metadata().file_metadata().num_rows()).context("job result spool row count")
}

/// NAN-3809: the schema tag of a settled-job reuse marker.
pub const REUSE_MARKER_SCHEMA: &str = "nano.settled-job-reuse.v1";

/// NAN-3809: written next to a finished plain search job's result pages
/// (`{root}/tenant-{sha256(T)}/job-{id}/reuse-v1.json`), so the marker shares
/// the result's tenant prefix, grant and 7-day retention. It names the data
/// identity the job read; `/v1/jobs/reuse-check` re-serves the job only while
/// the current identity of the same window is equal.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReuseMarker {
    pub schema: String,
    pub tenant_id: String,
    pub job_id: String,
    pub attempt_id: String,
    pub from_us: i64,
    pub to_us: i64,
    pub manifest_sha256: String,
    pub rows: u64,
    pub window_identity: String,
}

impl ReuseMarker {
    /// Whether this marker re-serves `job_id`'s result `manifest_sha256` for
    /// `tenant_id` now, given the window's `current_identity`.
    pub fn admits(&self, tenant_id: &str, job_id: &str, manifest_sha256: &str, current_identity: &str, now: chrono::DateTime<chrono::Utc>) -> bool {
        self.schema == REUSE_MARKER_SCHEMA
            && self.tenant_id == tenant_id
            && self.job_id == job_id
            && self.manifest_sha256 == manifest_sha256
            && self.rows > 0
            && self.from_us <= self.to_us
            && nanosiem_core::search::settled_reuse::is_settled_end_us(self.to_us, now)
            && self.window_identity == current_identity
    }
}

/// Only a plain search (not a post-processed prefix or a typed view) over a
/// settled window whose query reads events alone is ever re-served.
fn reuse_eligible(spec: &LakeQueryJobSpec, request: &BroadNplRequest, to_us: i64) -> bool {
    matches!(spec.task, nanosiem_core::search::DurableLakeTask::SearchNplV1 | nanosiem_core::search::DurableLakeTask::SearchNplShedV1 { .. })
        && request.dataset == "logs"
        && nanosiem_core::search::settled_reuse::is_settled_end_us(to_us, chrono::Utc::now())
        && nanosiem_core::search::settled_reuse::query_allows_settled_reuse(&request.query)
}

/// The current data identity of `[from_us, to_us]` on this cell: the
/// overlapping parts, read schema and query
/// artifacts ([`super::result_cache::window_identity`]).
pub async fn window_reuse_identity(engine: &PartQueryEngine, pin: &PartJobPin, from_us: i64, to_us: i64) -> Result<String> {
    let (parts, _, _, _) = engine.snapshot(from_us, to_us).await.map_err(|error| anyhow::anyhow!(error.to_string()))?;
    let (_, schema) = engine.head_and_schema_fingerprint().await;
    let execution = format!("{}\0{}", pin.compiler_sha256, pin.native_artifact_sha256);
    Ok(super::result_cache::window_identity(&parts, schema.as_deref(), &execution))
}

/// The marker's object key under the result root, or an error for a job id
/// that is not a UUID (no caller-controlled path segments).
fn reuse_marker_key(results: &JobResultStore, tenant_id: &str, job_id: &str) -> Result<String> {
    uuid::Uuid::parse_str(job_id).context("reuse marker job id is not a UUID")?;
    let (_, root_prefix) = crate::job::parse_s3_root(results.root())?;
    let tenant = hex::encode(Sha256::digest(tenant_id.as_bytes()));
    Ok(crate::job::join_object_prefix(root_prefix, &format!("tenant-{tenant}/job-{job_id}/reuse-v1.json")))
}

/// Record the marker when the identity after commit equals the one before
/// selection (nothing in the window changed while the job read it). A
/// failure only loses reuse; the job result stands.
async fn record_reuse_marker(
    engine: &PartQueryEngine,
    results: &JobResultStore,
    pin: &PartJobPin,
    spec: &LakeQueryJobSpec,
    reference: &ResultArtifactRef,
    (from_us, to_us): (i64, i64),
    before: String,
) {
    let after = match window_reuse_identity(engine, pin, from_us, to_us).await {
        Ok(after) => after,
        Err(error) => {
            tracing::warn!(job_id = %spec.job_id, %error, "settled reuse marker skipped: window identity unavailable");
            return;
        }
    };
    if after != before {
        tracing::info!(job_id = %spec.job_id, "settled reuse marker skipped: the window changed while the job read it");
        return;
    }
    let marker = ReuseMarker {
        schema: REUSE_MARKER_SCHEMA.into(),
        tenant_id: spec.tenant_id.clone(),
        job_id: spec.job_id.clone(),
        attempt_id: spec.attempt_id.clone(),
        from_us,
        to_us,
        manifest_sha256: reference.manifest_sha256.clone(),
        rows: reference.rows,
        window_identity: after,
    };
    let written = async {
        let key = reuse_marker_key(results, &spec.tenant_id, &spec.job_id)?;
        let bytes = serde_json::to_vec(&marker)?;
        results.with_operator(|operator| {
            let (key, bytes) = (key.clone(), bytes.clone());
            async move { operator.write(&key, bytes).await.map(|_| ()).map_err(anyhow::Error::new) }
        }).await
    }.await;
    if let Err(error) = written {
        tracing::warn!(job_id = %spec.job_id, error = %format!("{error:#}"), "settled reuse marker was not written");
    }
}

/// Read a job's reuse marker; `None` when it has none (never settled, older
/// cell, or retired with the result).
pub async fn read_reuse_marker(results: &JobResultStore, tenant_id: &str, job_id: &str) -> Result<Option<ReuseMarker>> {
    let key = reuse_marker_key(results, tenant_id, job_id)?;
    results.with_operator(|operator| {
        let key = key.clone();
        async move {
            match operator.read(&key).await {
                Ok(bytes) => Ok(Some(serde_json::from_slice(&bytes.to_vec()).context("reuse marker is malformed")?)),
                Err(error) if error.kind() == opendal::ErrorKind::NotFound => Ok(None),
                Err(error) => Err(anyhow::Error::new(error)),
            }
        }
    }).await
}

/// Commit a result spool under the tenant's result root with the current
/// `job_results` operator (one refresh-and-retry on a refused credential).
pub async fn commit_job_result(
    results: &JobResultStore,
    spec: &LakeQueryJobSpec,
    parquet_path: &std::path::Path,
    excluded_columns: &BTreeSet<String>,
    execution: &ResultExecutionMetadata,
) -> Result<ResultArtifactRef> {
    results.with_operator(|operator| async move {
        commit_bounded_parquet_result_to(
            &operator, results.root(), spec, parquet_path, spec.request.offset, spec.request.limit,
            excluded_columns, execution.clone(),
        ).await
    }).await
}

/// One page of a committed result (the result-page route), read back with
/// the same `job_results` grant.
pub async fn result_page(results: &JobResultStore, reference: &ResultArtifactRef, job_id: &str, tenant_id: &str, page: usize) -> Result<Value> {
    let page = results.with_operator(|operator| async move {
        crate::job::read_result_page_from(&operator, results.bucket(), reference, job_id, tenant_id, page).await
    }).await?;
    Ok(serde_json::to_value(page)?)
}

#[cfg(test)]
mod nan4156_walk_tests {
    use super::{page_full, walk_starts, JOB_WALK_FIRST_US};

    const HOUR: i64 = 3_600_000_000;

    /// NAN-4156: a 168 h newest-first job reads 15 m, 1 h, 4 h, 16 h, 64 h
    /// and only then the whole window, every window ending at the newest data.
    #[test]
    fn a_week_walks_six_windows_from_the_newest_data() {
        let (from, anchor) = (0, 168 * HOUR);
        let starts = walk_starts(from, anchor);
        assert_eq!(starts, vec![anchor - JOB_WALK_FIRST_US, anchor - HOUR, anchor - 4 * HOUR, anchor - 16 * HOUR, anchor - 64 * HOUR, from]);
        assert!(starts.windows(2).all(|pair| pair[0] > pair[1]), "windows only widen");
    }

    #[test]
    fn a_short_window_reads_once() {
        assert_eq!(walk_starts(0, JOB_WALK_FIRST_US), vec![0]);
        assert_eq!(walk_starts(5, 5), vec![5]);
    }

    /// NAN-4277 (F18): an aggregate job statement gets the durable statement
    /// time (only raised, never lowered), and the memory rungs keep it.
    #[test]
    fn whole_window_job_statements_get_the_durable_time_limit() {
        use crate::part_query::lanes::setting;
        let compiled = "SELECT count() FROM t WHERE match(raw_data, 'hostname') SETTINGS max_threads=8, max_execution_time=120";
        let raised = super::job_statement_time_sql(compiled, super::JOB_STATEMENT_SECONDS);
        assert_eq!(setting(&raised, "max_execution_time"), Some(super::JOB_STATEMENT_SECONDS));
        assert_eq!(setting(&raised, "max_threads"), Some(8));
        assert_eq!(super::job_statement_time_sql("SELECT 1 SETTINGS max_threads=1, max_execution_time=900", 600),
            "SELECT 1 SETTINGS max_threads=1, max_execution_time=900", "never lowered");
        assert_eq!(super::job_statement_time_sql("SELECT 1", 600), "SELECT 1 SETTINGS max_execution_time=600");
        for rung in super::job_memory_rungs(&raised) {
            assert_eq!(setting(&rung, "max_execution_time"), Some(super::JOB_STATEMENT_SECONDS), "{rung}");
        }
        // The statement `run_search_job` executes: an aggregate gets the
        // durable time and the job memory cap; a newest-first chunk keeps the
        // engine's time cap so it can still be halved.
        let plan = |sql: &str| crate::planner::NativeQueryPlan {
            query_sha256: String::new(),
            sql: sql.to_string(),
            params: Vec::new(),
            budget: crate::planner::QueryBudget { candidate_objects: 0, estimated_scan_bytes: 0, max_query_bytes: u64::MAX },
            native_event_rows: false,
            temporary_aliases: std::collections::BTreeSet::new(),
            schema_defaults: Vec::new(),
            reader: Default::default(),
        };
        let compiled = "SELECT count() FROM t SETTINGS max_threads=8, max_execution_time=120, max_memory_usage=1";
        let aggregate = super::job_statement_plan(plan(compiled), 4 << 30, None);
        assert_eq!(setting(&aggregate.sql, "max_execution_time"), Some(super::JOB_STATEMENT_SECONDS));
        assert_eq!(setting(&aggregate.sql, "max_memory_usage"), Some(4 << 30));
        let listing = super::job_statement_plan(plan(compiled), 4 << 30, Some(50));
        assert_eq!(setting(&listing.sql, "max_execution_time"), Some(120));
        assert_eq!(setting(&listing.sql, "max_memory_usage"), Some(4 << 30));
    }

    /// NAN-4164: a refused job statement reruns bounded at its own threads,
    /// then on the degraded rung; every rung only lowers settings.
    #[test]
    fn job_memory_rungs_bound_the_reader_then_degrade() {
        use crate::part_query::lanes::setting;
        let sql = "SELECT * FROM t WHERE match(raw_data, 'x') ORDER BY time DESC LIMIT 100 SETTINGS max_threads=16, max_execution_time=300";
        let rungs = super::job_memory_rungs(sql);
        assert_eq!(rungs.len(), 2, "{rungs:?}");
        assert_eq!(setting(&rungs[0], "max_threads"), Some(16), "{}", rungs[0]);
        assert_eq!(setting(&rungs[0], "input_format_parquet_memory_high_watermark"), Some(32 << 20));
        assert_eq!(setting(&rungs[1], "max_threads"), Some(1), "{}", rungs[1]);
        assert_eq!(setting(&rungs[1], "input_format_parquet_memory_high_watermark"), Some(16 << 20));
        assert_eq!(setting(&rungs[1], "max_execution_time"), Some(300));
        // A statement already on the degraded settings has nothing left to lower.
        assert!(super::job_memory_rungs(&rungs[1]).is_empty());
        // A bounded statement at one thread skips the identical first rung.
        let one = crate::part_query::lanes::bounded_reader_sql(sql, 1);
        assert_eq!(super::job_memory_rungs(&one), vec![crate::part_query::lanes::degraded_sql(sql)]);
    }

    /// NAN-4164 / NAN-4280: the chunks are disjoint half-open `[lo, hi)` µs
    /// windows, newest first, and cover the window exactly once: each
    /// chunk's end is the next newer chunk's start.
    #[test]
    fn a_week_reads_disjoint_chunks_newest_first() {
        let (from, anchor, to) = (0, 168 * HOUR, 168 * HOUR + 7);
        let chunks = super::disjoint_chunks(&walk_starts(from, anchor), to);
        assert_eq!(chunks.len(), 6);
        assert_eq!(chunks[0], (anchor - JOB_WALK_FIRST_US, to));
        assert_eq!(chunks[1], (anchor - HOUR, anchor - JOB_WALK_FIRST_US));
        assert_eq!(chunks[5], (from, anchor - 64 * HOUR));
        for pair in chunks.iter().collect::<Vec<_>>().windows(2) {
            assert_eq!(pair[1].1, pair[0].0, "adjacent, no gap and no overlap: {chunks:?}");
        }
        assert!(chunks.iter().all(|(lo, hi)| lo < hi));
        assert_eq!(chunks.iter().map(|(lo, hi)| hi - lo).sum::<i64>(), to - from, "exact cover");
        assert_eq!(super::disjoint_chunks(&[from], to), [(from, to)]);
        // An event exactly on a chunk boundary is in exactly one chunk.
        let boundary = chunks[1].1;
        assert_eq!(chunks.iter().filter(|(lo, hi)| *lo <= boundary && boundary < *hi).count(), 1);
        // A start at the end yields no empty chunk.
        assert_eq!(super::disjoint_chunks(&[to, from], to), [(from, to)]);
    }

    /// NAN-4164: a timed-out chunk halves into two disjoint halves that
    /// cover it, down to twice the minimum span.
    #[test]
    fn a_timed_out_chunk_halves_down_to_the_minimum() {
        let (older, newer) = super::split_chunk((0, 104 * HOUR)).unwrap();
        assert_eq!((older.0, older.1, newer.1), (0, newer.0, 104 * HOUR), "halves share mid");
        assert!(super::split_chunk((0, 2 * super::JOB_SPLIT_MIN_US)).is_some());
        assert!(super::split_chunk((0, 2 * super::JOB_SPLIT_MIN_US - 1)).is_none());
        let mut chunk = (0, 104 * HOUR);
        let mut halvings = 0;
        while let Some((_, newer)) = super::split_chunk(chunk) {
            chunk = newer;
            halvings += 1;
        }
        assert!(halvings <= super::JOB_MAX_SPLITS, "{halvings}");
        let timeout = anyhow::anyhow!("Code: 159. DB::Exception: Timeout exceeded: elapsed 120000.1 ms, maximum: 120000 ms. (TIMEOUT_EXCEEDED)");
        assert!(super::is_statement_timeout(&timeout.context("job statement")));
        assert!(!super::is_statement_timeout(&anyhow::anyhow!("Code: 241. (MEMORY_LIMIT_EXCEEDED)")));
    }

    /// NAN-4164: chunk spools concatenate in order, truncated to the page.
    #[test]
    fn chunk_spools_concatenate_newest_first_up_to_the_cap() {
        use arrow_array::{ArrayRef, Int64Array, RecordBatch};
        use std::sync::Arc;
        let dir = tempfile::tempdir().unwrap();
        let write = |name: &str, values: Vec<i64>| {
            let path = dir.path().join(name);
            let batch = RecordBatch::try_from_iter([("v", Arc::new(Int64Array::from(values)) as ArrayRef)]).unwrap();
            let mut writer = parquet::arrow::ArrowWriter::try_new(std::fs::File::create(&path).unwrap(), batch.schema(), None).unwrap();
            writer.write(&batch).unwrap();
            writer.close().unwrap();
            path
        };
        let (a, empty, b) = (write("a", vec![9, 8]), write("e", vec![]), write("b", vec![7, 6, 5]));
        let read = |path: &std::path::Path| {
            parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder::try_new(std::fs::File::open(path).unwrap())
                .unwrap()
                .build()
                .unwrap()
                .flat_map(|batch| batch.unwrap().column(0).as_any().downcast_ref::<Int64Array>().unwrap().values().to_vec())
                .collect::<Vec<_>>()
        };
        let out = dir.path().join("out");
        assert_eq!(super::concat_spools(&[&a, &empty, &b], Some(4), &out).unwrap(), 4);
        assert_eq!(read(&out), vec![9, 8, 7, 6]);
        let all = dir.path().join("all");
        assert_eq!(super::concat_spools(&[&empty, &a, &b], None, &all).unwrap(), 5);
        assert_eq!(read(&all), vec![9, 8, 7, 6, 5]);
        let other = dir.path().join("other");
        let batch = RecordBatch::try_from_iter([("w", Arc::new(Int64Array::from(vec![1])) as ArrayRef)]).unwrap();
        let mut writer = parquet::arrow::ArrowWriter::try_new(std::fs::File::create(&other).unwrap(), batch.schema(), None).unwrap();
        writer.write(&batch).unwrap();
        writer.close().unwrap();
        assert!(super::concat_spools(&[&a, &other], None, &dir.path().join("x")).is_err(), "schemas must match");
    }

    /// The walk stops on the first window holding the whole page, and only
    /// then; other statements (no cap) always take their single window.
    #[test]
    fn only_a_full_page_stops_the_walk() {
        assert!(page_full(Some(10), 10));
        assert!(!page_full(Some(10), 9));
        assert!(!page_full(Some(10), 0));
        assert!(page_full(None, 0));
    }
}

#[cfg(test)]
mod tests {
    use super::PartJobPin;

    #[test]
    fn job_identity_binds_the_log_head_schema_and_artifacts() {
        let head = Some((42, "a".repeat(64)));
        let a = PartJobPin::at_head(head.clone(), Some("schema-a"), &"b".repeat(64), &"c".repeat(64)).unwrap();
        assert_eq!(a.snapshot_id, 42);
        assert!(a.generation_id.starts_with("parts-v1-42-"));
        assert_ne!(a, PartJobPin::at_head(Some((43, "a".repeat(64))), Some("schema-a"), &"b".repeat(64), &"c".repeat(64)).unwrap());
        assert_ne!(a.event_config_sha256, PartJobPin::at_head(head.clone(), Some("schema-b"), &"b".repeat(64), &"c".repeat(64)).unwrap().event_config_sha256);
        assert_ne!(a, PartJobPin::at_head(head, Some("schema-a"), &"d".repeat(64), &"c".repeat(64)).unwrap());
        let empty = PartJobPin::at_head(None, None, &"b".repeat(64), &"c".repeat(64)).unwrap();
        assert_eq!(empty.snapshot_id, 0);
        assert!(empty.generation_id.starts_with("event-0-"));
    }

    fn spec_at(pin: &PartJobPin) -> crate::job::LakeQueryJobSpec {
        crate::job::LakeQueryJobSpec {
            schema_version: crate::job::JOB_SCHEMA_VERSION,
            job_id: "job1".into(),
            attempt_id: "attempt-1".into(),
            fence_token: "f".repeat(64),
            tenant_id: "tenant-a".into(),
            generation_id: pin.generation_id.clone(),
            event_config_sha256: pin.event_config_sha256.clone(),
            snapshot_id: pin.snapshot_id,
            compiler_sha256: pin.compiler_sha256.clone(),
            native_artifact_sha256: pin.native_artifact_sha256.clone(),
            hot_tail_manifest_sha256: None,
            hot_tail_snapshot_id: None,
            hot_tail_id: None,
            resource_class: crate::job::ResourceClass::Medium,
            scan_budget_bytes: 1 << 30,
            submitted_at: chrono::Utc::now(),
            scope_deny: Default::default(),
            task: nanosiem_core::search::DurableLakeTask::SearchNplV1,
            request: crate::job::LakeQueryJobRequest {
                dataset: "logs".into(),
                query: "*".into(),
                start: "2026-09-26T00:00:00Z".into(),
                end: "2026-09-27T00:00:00Z".into(),
                limit: 10,
                offset: 0,
                table_view: false,
                anchor_us: None,
                decay: None,
                clear_boundaries: Default::default(),
                minimum_clear_revision: None,
            },
            result_page_rows: 10_000,
            retention_proof: None,
        }
    }

    /// NAN-4290: query[T] classifies the small-job lane from the signed spec.
    #[test]
    fn cell_feature_lean_job_small_lane_v1_is_backed() {
        assert!(nanosiem_lake_cell::features::CELL_FEATURES.contains(&"lean_job_small_lane_v1"));
        let pin = PartJobPin::at_head(Some((1, "a".repeat(64))), None, &"b".repeat(64), &"c".repeat(64)).unwrap();
        let mut spec = spec_at(&pin);
        assert!(super::small_job_spec(&spec), "a 24 h search is small");
        spec.request.start = "2026-09-26T23:00:00Z".into();
        assert!(super::small_job_spec(&spec), "a 1 h search is small");
        spec.resource_class = crate::job::ResourceClass::Large;
        assert!(!super::small_job_spec(&spec), "a promoted job takes the general lane");
        spec.resource_class = crate::job::ResourceClass::Medium;
        spec.request.start = "2026-08-27T00:00:00Z".into();
        assert!(!super::small_job_spec(&spec), "a 30 d search is not small");
        spec.request.start = "not a time".into();
        assert!(!super::small_job_spec(&spec), "an unreadable window is never small");
    }

    fn marker(now: chrono::DateTime<chrono::Utc>) -> super::ReuseMarker {
        super::ReuseMarker {
            schema: super::REUSE_MARKER_SCHEMA.into(),
            tenant_id: "tenant-a".into(),
            job_id: "0192f0c0-0000-7000-8000-000000000001".into(),
            attempt_id: "attempt-1".into(),
            from_us: (now - chrono::Duration::hours(2)).timestamp_micros(),
            to_us: (now - chrono::Duration::hours(1)).timestamp_micros(),
            manifest_sha256: "m".repeat(64),
            rows: 42,
            window_identity: "identity-a".into(),
        }
    }

    #[test]
    fn a_reuse_marker_admits_only_its_own_settled_unchanged_result() {
        let now = chrono::Utc::now();
        let marker = marker(now);
        let job = marker.job_id.clone();
        let manifest = "m".repeat(64);
        assert!(marker.admits("tenant-a", &job, &manifest, "identity-a", now));
        // A late part, merge, erasure, schema, artifact or enrichment-authority
        // change is a different window identity.
        assert!(!marker.admits("tenant-a", &job, &manifest, "identity-b", now));
        assert!(!marker.admits("tenant-b", &job, &manifest, "identity-a", now));
        assert!(!marker.admits("tenant-a", "0192f0c0-0000-7000-8000-000000000002", &manifest, "identity-a", now));
        assert!(!marker.admits("tenant-a", &job, &"n".repeat(64), "identity-a", now), "another attempt's result");
        let mut empty = marker.clone();
        empty.rows = 0;
        assert!(!empty.admits("tenant-a", &job, &manifest, "identity-a", now));
        let mut hot = marker.clone();
        hot.to_us = now.timestamp_micros();
        assert!(!hot.admits("tenant-a", &job, &manifest, "identity-a", now), "a window overlapping the late-arrival grace");
        let mut foreign = marker;
        foreign.schema = "nano.other.v1".into();
        assert!(!foreign.admits("tenant-a", &job, &manifest, "identity-a", now));
    }

    #[test]
    fn a_queued_job_runs_at_any_later_head_but_never_an_earlier_one() {
        let (compiler, native) = ("b".repeat(64), "c".repeat(64));
        let admitted = PartJobPin::at_head(Some((42, "a".repeat(64))), Some("schema-a"), &compiler, &native).unwrap();
        let spec = spec_at(&admitted);
        admitted.admits(&spec).unwrap();
        // Ingest advanced and the schema grew while the job waited: it runs at
        // the current head, so its admitted parts need no retention pin.
        let later = PartJobPin::at_head(Some((97, "e".repeat(64))), Some("schema-b"), &compiler, &native).unwrap();
        later.admits(&spec).unwrap();
        // A cell behind the admitted head (a stale restore) refuses it.
        let earlier = PartJobPin::at_head(Some((41, "a".repeat(64))), Some("schema-a"), &compiler, &native).unwrap();
        assert!(earlier.admits(&spec).is_err());
        // A different query image refuses it.
        let rebuilt = PartJobPin::at_head(Some((97, "e".repeat(64))), Some("schema-b"), &"d".repeat(64), &native).unwrap();
        assert!(rebuilt.admits(&spec).is_err());
        // An empty-log admission runs once parts exist.
        let bootstrap = PartJobPin::at_head(None, None, &compiler, &native).unwrap();
        later.admits(&spec_at(&bootstrap)).unwrap();
        // A generation that does not name its head, or a gen1 hot tail, is refused.
        let mut forged = spec.clone();
        forged.generation_id = "parts-v1-41-aaaaaaaaaaaaaaaa".into();
        assert!(later.admits(&forged).is_err());
        let mut tailed = spec;
        tailed.hot_tail_id = Some("tail".into());
        assert!(later.admits(&tailed).is_err());
    }
}

#[cfg(test)]
#[path = "job_memory_native_tests.rs"]
mod memory_native;
