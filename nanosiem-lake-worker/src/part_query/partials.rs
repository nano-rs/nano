// SPDX-License-Identifier: AGPL-3.0-or-later

//! Aggregate reads from per-part partials (contract section 3).
//!
//! - **Counts / timecharts** (`/v1/aggregate/count`): rollup-aligned full
//!   5-minute buckets come from the parts' rollup partials through the
//!   reader's own [`CountRollup::plan`]; the ragged edges come from a native
//!   scan through [`planner::plan_count_aggregate_query`] over the parts that
//!   overlap each edge; the fragments are merged by the shared
//!   [`crate::count_aggregate::merge_outputs`]. That is the reader's route
//!   with the generation rollup swapped for part partials.
//! - **Prevalence** (`/v1/prevalence/lookup`, `/v1/prevalence/explorer`): a
//!   window relation with the reader's window-file row shape is built from
//!   the prevalence partials of every part overlapping the window, whole
//!   (NAN-3161: never from raw rows; edges are event-hour aligned, see
//!   `prevalence_relation`).
//! - **Entity ranges** (`/v1/entity/ranges`): first/last/events per identity
//!   value from the entity-range partials, with straddling parts answered from
//!   their rows.

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::Instant;

use super::engine::{rfc3339_us, PartQueryEngine, PartQueryError, QueryResult};
use super::fetch::FileSet;
use crate::count_aggregate::{merge_outputs, CountAggregateRequest};
use crate::parts::part_log::PartRef;
use crate::parts::provenance::PartialKind;
use crate::planner::{self, CountAggregatePlanRequest, CountAggregateSource};
use crate::rollup::{CountRollup, LocalRollupPartial, COUNT_ROLLUP_BUCKET_US};

fn invalid(message: impl Into<String>) -> PartQueryError {
    PartQueryError::Invalid(message.into())
}

fn internal(error: impl std::fmt::Display) -> PartQueryError {
    super::engine::internal_text(error.to_string())
}

// ---------------------------------------------------------------------------
// Counts
// ---------------------------------------------------------------------------

/// `/v1/aggregate/count` over parts.
pub async fn count_aggregate(engine: &PartQueryEngine, request: &CountAggregateRequest) -> QueryResult<Value> {
    if request.tenant_id != engine.settings().tenant_id {
        return Err(invalid("request tenant is not this process's tenant"));
    }
    engine.pinned(count_aggregate_pinned(engine, request)).await?
}

async fn count_aggregate_pinned(engine: &PartQueryEngine, request: &CountAggregateRequest) -> QueryResult<Value> {
    let started = Instant::now();
    if request.tenant_id != engine.settings().tenant_id {
        return Err(invalid("request tenant is not this process's tenant"));
    }
    let multi_value = crate::rollup::count_rollup_field_multi_value(&request.group_field)
        .ok_or_else(|| invalid("exact count rollup does not cover the requested field"))?;
    request.validate_shape().map_err(|error| invalid(error.to_string()))?;
    let window = request.window().map_err(|error| invalid(error.to_string()))?;
    let work = async {
        let mut outputs = Vec::new();
        // NAN-4298: an entity-field equality count from the signed hourly
        // entity counts; any other shape, or a window they do not cover,
        // keeps the rollup route below.
        if let Some(output) = super::entity_count::count_aggregate(engine, request).await? {
            outputs.push(output);
            return Ok::<_, PartQueryError>(outputs);
        }
        let rollup_eligible = window.full_start_us < window.full_end_us;
        let native_ranges = if rollup_eligible {
            let (parts, _, _, _) = engine.snapshot(window.full_start_us, window.full_end_us - 1).await?;
            outputs.push(rollup_fragment(engine, request, &parts, window.full_start_us, window.full_end_us).await?);
            let mut ranges = Vec::new();
            if window.start_us < window.full_start_us {
                ranges.push((window.start_us, window.full_start_us.min(window.end_exclusive_us)));
            }
            if window.full_end_us < window.end_exclusive_us {
                ranges.push((window.full_end_us.max(window.start_us), window.end_exclusive_us));
            }
            ranges
        } else {
            vec![(window.start_us, window.end_exclusive_us)]
        };
        for (start_us, end_exclusive_us) in native_ranges {
            let selection = engine.select(start_us, end_exclusive_us - 1, &[]).await?;
            if selection.manifest.objects.is_empty() {
                continue;
            }
            if let Some(plan) = planner::plan_count_aggregate_query(
                &selection.tenant,
                &selection.manifest,
                &CountAggregatePlanRequest {
                    group_field: &request.group_field,
                    group_results: request.group_results,
                    multi_value,
                    predicate: request.predicate.as_ref(),
                    bucket_span_us: request.bucket_span_us,
                    start_us,
                    end_exclusive_us,
                    source_filter: request.source_filter.as_deref(),
                    deny_source_types: &request.deny_source_types,
                    source: CountAggregateSource::Base,
                    group_by_source: request.group_by_source,
                },
            )
            .map_err(|error| invalid(error.to_string()))?
            {
                outputs.push(engine.execute(plan).await?);
            }
        }
        Ok::<_, PartQueryError>(outputs)
    };
    let outputs = work.await?;
    let merged = merge_outputs(request, outputs).map_err(|error| match error {
        crate::count_aggregate::CountAggregateError::Invalid(message) => invalid(message),
        crate::count_aggregate::CountAggregateError::Internal(message) => internal(message),
    })?;
    let wall_seconds = started.elapsed().as_secs_f64();
    Ok(json!({
        "ok": true,
        "schema_version": 1,
        "request_id": request.request_id,
        "tenant_id": request.tenant_id,
        "route": "count_aggregate",
        "source_mode": "parts",
        "log_head": engine.head_json().await,
        "wall_seconds": wall_seconds,
        "planner": crate::query_timing::current().map(|phases| {
            serde_json::to_value(&*phases.lock().unwrap_or_else(|error| error.into_inner()))
                .expect("numeric query phases serialize")
        }),
        "result": {
            "result_rows": merged.rows.len(),
            "rows": merged.rows,
            "engine_seconds": merged.engine_seconds,
            "storage_rows": merged.storage_rows,
            "storage_bytes": merged.storage_bytes,
            "wall_seconds": wall_seconds,
        }
    }))
}

/// NAN-4293: parts per per-part rollup statement. One statement over all of
/// a 7 d window's ~250 cold parts took ~6 s (~20–48 CPU-s) on a large tenant, longer
/// than the segments refresh's per-read deadline; 32 parts is ~0.7 s, and
/// every finished chunk is memoized before the next one starts.
const ROLLUP_MEMO_CHUNK_PARTS: usize = 32;

/// Why a chunk of the per-part rollup did not answer.
enum ChunkError {
    /// The answer is too wide for the per-part shape: the caller answers
    /// from the merged rollup plan instead.
    TooWide(String),
    Fail(PartQueryError),
}

/// Run `run` over `items` a chunk of `chunk` at a time, handing each
/// finished chunk's answer to `keep` before the next chunk starts. A caller
/// that is cancelled (its future dropped) or fails part-way has kept every
/// chunk that finished.
async fn by_chunks<T: Clone, R, E, F, Fut>(items: &[T], chunk: usize, mut run: F, mut keep: impl FnMut(R)) -> Result<(), E>
where
    F: FnMut(Vec<T>) -> Fut,
    Fut: std::future::Future<Output = Result<R, E>>,
{
    for items in items.chunks(chunk.max(1)) {
        keep(run(items.to_vec()).await?);
    }
    Ok(())
}

/// The whole-bucket fragment of a count over `parts` from their rollup
/// partials, served per part from [`super::rollup_rows`] (NAN-3093): only
/// parts without a memoized answer are read, in statements of at most
/// [`ROLLUP_MEMO_CHUNK_PARTS`] parts that keep every file's rows apart (each
/// chunk memoized as it finishes, NAN-4293), and the window and span are
/// applied in memory. If a per-part statement outgrows its result or memory
/// budget, the merged single-statement plan answers instead.
async fn rollup_fragment(
    engine: &PartQueryEngine,
    request: &CountAggregateRequest,
    parts: &[PartRef],
    full_start_us: i64,
    full_end_us: i64,
) -> QueryResult<crate::native::NativeQueryOutput> {
    use super::rollup_rows;
    let started = Instant::now();
    let key = rollup_rows::key(request);
    let memo = engine.rollup_rows();
    let mut answers = Vec::with_capacity(parts.len());
    let mut pending = Vec::new();
    for part in parts {
        match memo.for_request(request, &part.part_id) {
            Some(rows) => answers.push(rows),
            None => pending.push(part.clone()),
        }
    }
    crate::query_timing::record(|phases| {
        phases.rollup_memo_hits += answers.len();
        phases.rollup_memo_misses += pending.len();
    });
    let (mut storage_rows_read, mut storage_bytes_read) = (0_u64, 0_u64);
    if !pending.is_empty() {
        let fetch_timer = crate::query_timing::timer(crate::query_timing::Phase::RollupFetch);
        let partials = engine
            .fetcher()
            .ensure(&pending, &[FileSet::Partial(PartialKind::Rollup)])
            .await
            .map_err(|error| internal(format!("{error:#}")))?;
        drop(fetch_timer);
        let mut by_path = std::collections::BTreeMap::new();
        let local = partials
            .of(FileSet::Partial(PartialKind::Rollup))
            .map(|file| {
                let part = pending.iter().find(|part| part.part_id == file.part_id).expect("leased part is selected");
                by_path.insert(file.path.to_string_lossy().to_string(), part.part_id.clone());
                LocalRollupPartial {
                    path: file.path.clone(),
                    min_bucket_start_us: part.min_time_us.div_euclid(COUNT_ROLLUP_BUCKET_US) * COUNT_ROLLUP_BUCKET_US,
                    max_bucket_start_us: part.max_time_us.div_euclid(COUNT_ROLLUP_BUCKET_US) * COUNT_ROLLUP_BUCKET_US,
                    bytes: file.bytes,
                }
            })
            .collect::<Vec<_>>();
        if local.len() != pending.len() {
            // Contract 3.2: every part carries a rollup. A part without
            // one cannot be served from partials; fail rather than undercount.
            return Err(internal("a live part has no rollup partial"));
        }
        let selection_tenant = engine.limits_tenant();
        // NAN-4293: plan, run and memoize the pending parts a bounded chunk
        // at a time. A read cancelled at its caller's deadline (the segments
        // refresh gives each read 6 s) keeps every chunk it finished, so the
        // next retry starts where it stopped instead of re-reading every part.
        let chunked = by_chunks(&local, ROLLUP_MEMO_CHUNK_PARTS, |chunk| {
            let (by_path, selection_tenant) = (&by_path, &selection_tenant);
            async move {
                let first = chunk.iter().map(|partial| partial.min_bucket_start_us).min().expect("chunks are not empty");
                let last = chunk.iter().map(|partial| partial.max_bucket_start_us).max().expect("chunks are not empty");
                let plans = CountRollup::from_local_partials(chunk.clone())
                    .plan_by_part_with_source_groups(
                        selection_tenant,
                        &request.group_field,
                        request.group_results,
                        request.group_by_source,
                        request.predicate.as_ref(),
                        first,
                        last + COUNT_ROLLUP_BUCKET_US,
                        request.source_filter.as_deref(),
                        &request.deny_source_types,
                    )
                    .map_err(|error| ChunkError::Fail(invalid(error.to_string())))?;
                let mut fresh = std::collections::BTreeMap::<crate::parts::format::PartId, Vec<rollup_rows::RollupRow>>::new();
                for partial in &chunk {
                    let part = by_path.get(&partial.path.to_string_lossy().to_string())
                        .ok_or_else(|| ChunkError::Fail(internal("a leased rollup partial has no part")))?;
                    fresh.insert(part.clone(), Vec::new());
                }
                let (mut rows_read, mut bytes_read) = (0_u64, 0_u64);
                for plan in plans {
                    let output = match engine.run_sql(plan.sql, plan.params).await {
                        Ok(output) => output,
                        // Only an answer too wide for the per-part shape falls
                        // back; a deadline, a shed lane or any other fault is
                        // the caller's.
                        Err(error) if !per_part_answer_too_wide(&error) => return Err(ChunkError::Fail(internal(error.to_string()))),
                        Err(error) => return Err(ChunkError::TooWide(error.to_string())),
                    };
                    rows_read = rows_read.saturating_add(output.storage_rows_read);
                    bytes_read = bytes_read.saturating_add(output.storage_bytes_read);
                    for line in output.data.split(|byte| *byte == b'\n').filter(|line| !line.is_empty()) {
                        let (path, row) = rollup_rows::decode(line).ok_or_else(|| ChunkError::Fail(internal("per-part count rollup row is malformed")))?;
                        let rows = by_path.get(&path).and_then(|part| fresh.get_mut(part))
                            .ok_or_else(|| ChunkError::Fail(internal("per-part count rollup named a file outside its chunk")))?;
                        rows.push(row);
                    }
                }
                Ok((fresh, rows_read, bytes_read))
            }
        }, |(fresh, rows_read, bytes_read)| {
            storage_rows_read = storage_rows_read.saturating_add(rows_read);
            storage_bytes_read = storage_bytes_read.saturating_add(bytes_read);
            for (part, rows) in fresh {
                let rows = Arc::new(rows);
                memo.insert(key.clone(), part, rows.clone());
                answers.push(rows);
            }
        }).await;
        drop(partials);
        match chunked {
            Ok(()) => {}
            Err(ChunkError::Fail(error)) => return Err(error),
            Err(ChunkError::TooWide(error)) => {
                tracing::warn!(error = %error, "per-part count rollup failed; answering from the merged rollup plan");
                return merged_rollup_fragment(engine, request, parts, full_start_us, full_end_us).await;
            }
        }
    }
    let _fold_timer = crate::query_timing::timer(crate::query_timing::Phase::RollupFold);
    Ok(crate::native::NativeQueryOutput {
        data: rollup_rows::fold(&answers, full_start_us, full_end_us, request.bucket_span_us, request.grouped()),
        elapsed: started.elapsed(),
        storage_rows_read,
        storage_bytes_read,
    })
}

/// Warm the small source histogram inventory while the native lanes are idle.
/// Only live recent parts are passed by the arrival prewarm; retiring a part
/// removes it from future answers even if its immutable memo entry remains.
pub(super) async fn prewarm_source_summaries(engine: &PartQueryEngine, parts: &[PartRef]) -> QueryResult<()> {
    if parts.is_empty() { return Ok(()); }
    let mut request = super::rollup_rows::source_summary_request(&engine.settings().tenant_id);
    rollup_fragment(engine, &request, parts, i64::MIN, i64::MAX).await?;
    // The normal analyst scope excludes audit. Keep a separately SQL-fenced
    // summary, since log_source and source_type need not be identical.
    request.deny_source_types.insert("audit".into());
    rollup_fragment(engine, &request, parts, i64::MIN, i64::MAX).await?;
    Ok(())
}

/// The per-part statement ran out of result or memory budget (its rows are
/// per file, so a high-cardinality field can outgrow what the merged
/// statement returns).
fn per_part_answer_too_wide(error: &crate::executor::ExecutorError) -> bool {
    match error {
        crate::executor::ExecutorError::ResultTooLarge { .. } | crate::executor::ExecutorError::MemoryExhausted { .. } => true,
        crate::executor::ExecutorError::Query(error) => {
            let message = error.to_string();
            message.contains("TOO_MANY_ROWS_OR_BYTES") || message.contains("MEMORY_LIMIT_EXCEEDED")
        }
        _ => false,
    }
}

/// The pre-NAN-3093 whole-bucket fragment: one merged statement over every
/// part's rollup partial, nothing memoized.
async fn merged_rollup_fragment(
    engine: &PartQueryEngine,
    request: &CountAggregateRequest,
    parts: &[PartRef],
    full_start_us: i64,
    full_end_us: i64,
) -> QueryResult<crate::native::NativeQueryOutput> {
    let started = Instant::now();
    let partials = engine
        .fetcher()
        .ensure(parts, &[FileSet::Partial(PartialKind::Rollup)])
        .await
        .map_err(|error| internal(format!("{error:#}")))?;
    let local = partials
        .of(FileSet::Partial(PartialKind::Rollup))
        .map(|file| {
            let part = parts.iter().find(|part| part.part_id == file.part_id).expect("leased part is selected");
            LocalRollupPartial {
                path: file.path.clone(),
                min_bucket_start_us: part.min_time_us.div_euclid(COUNT_ROLLUP_BUCKET_US) * COUNT_ROLLUP_BUCKET_US,
                max_bucket_start_us: part.max_time_us.div_euclid(COUNT_ROLLUP_BUCKET_US) * COUNT_ROLLUP_BUCKET_US,
                bytes: file.bytes,
            }
        })
        .collect::<Vec<_>>();
    if local.len() != parts.len() {
        return Err(internal("a live part has no rollup partial"));
    }
    let rollup = CountRollup::from_local_partials(local);
    let selection_tenant = engine.limits_tenant();
    let mut data = Vec::new();
    let (mut storage_rows_read, mut storage_bytes_read) = (0_u64, 0_u64);
    for plan in rollup
        .plan_with_source_groups(
            &selection_tenant,
            &request.group_field,
            request.group_results,
            request.group_by_source,
            request.predicate.as_ref(),
            request.bucket_span_us,
            full_start_us,
            full_end_us,
            request.source_filter.as_deref(),
            &request.deny_source_types,
        )
        .map_err(|error| invalid(error.to_string()))?
    {
        let output = engine.run_sql(plan.sql, plan.params).await.map_err(|error| internal(error.to_string()))?;
        storage_rows_read = storage_rows_read.saturating_add(output.storage_rows_read);
        storage_bytes_read = storage_bytes_read.saturating_add(output.storage_bytes_read);
        data.extend_from_slice(&output.data);
        if !data.is_empty() && !data.ends_with(b"\n") {
            data.push(b'\n');
        }
    }
    drop(partials);
    Ok(crate::native::NativeQueryOutput { data, elapsed: started.elapsed(), storage_rows_read, storage_bytes_read })
}

// ---------------------------------------------------------------------------
// Window relation shared by prevalence and entity ranges
// ---------------------------------------------------------------------------

/// Entity ranges: parts entirely inside `[from_us, to_us]` (served from
/// partials) and parts straddling an edge (served from their rows).
fn split_inside(parts: Vec<PartRef>, from_us: i64, to_us: i64) -> (Vec<PartRef>, Vec<PartRef>) {
    parts.into_iter().partition(|part| part.min_time_us >= from_us && part.max_time_us <= to_us)
}

/// A brace-glob over leased cache files (all in one objects directory).
pub(super) fn path_set(paths: &[std::path::PathBuf]) -> QueryResult<String> {
    let mut strings = paths
        .iter()
        .map(|path| path.to_str().map(ToOwned::to_owned).ok_or_else(|| internal("cache path is not UTF-8")))
        .collect::<QueryResult<Vec<_>>>()?;
    planner::local_path_spec(&mut strings).map_err(|error| internal(error.to_string()))
}

/// The reader's prevalence window-file row shape over `[from_us, to_us]`:
/// `(kind, scope, entity, host_fingerprints, host_count_saturated,
/// is_private, first_seen, last_seen, total_occurrences)`.
pub(super) struct WindowRelation {
    sql: String,
    params: Vec<(String, String)>,
    _leases: Vec<super::fetch::LocalParts>,
    /// The single maintained state the relation re-aggregates, when it is
    /// exactly that (NAN-3161: a product window links it instead).
    state: Option<std::path::PathBuf>,
}

/// NAN-3068: the point-lookup filter over `{lookup_kinds}` / `{lookup_entities}`
/// (bound per statement). Applied inside every arm of a lookup relation so a
/// statement aggregates only the looked-up entities, never every entity seen
/// in the window.
const LOOKUP_FILTER: &str = "(kind, entity) IN (SELECT tupleElement(pair, 1), tupleElement(pair, 2) \
     FROM (SELECT arrayJoin(arrayZip({lookup_kinds:Array(String)}, {lookup_entities:Array(String)})) AS pair))";

/// Which prevalence relation to build: every entity (explorer) or only the
/// entities bound as `lookup_kinds` / `lookup_entities` (point lookups).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WindowScope {
    AllEntities,
    LookupOnly,
}

impl WindowScope {
    fn arm_filter(self) -> String {
        match self {
            Self::AllEntities => String::new(),
            Self::LookupOnly => format!(" AND {LOOKUP_FILTER}"),
        }
    }
}

async fn prevalence_window(engine: &PartQueryEngine, from_us: i64, to_us: i64, floor_us: Option<i64>, window_scope: WindowScope) -> QueryResult<Option<WindowRelation>> {
    super::fetch::prevalence_path(async {
        let parts = window_parts(engine, from_us, to_us, floor_us).await?;
        prevalence_relation(engine, parts, window_scope).await
    })
    .await
}

/// The parts a window is answered from (see [`prevalence_relation`]):
/// every live part overlapping `[from_us, to_us]`, minus any part that
/// starts before `floor_us`. A floor is a hard lower bound (a durable job's
/// retention cutoff, NAN-3078): a part straddling it is excluded rather
/// than widened over, so nothing before the floor is ever counted; the
/// floor's edge rounds inward to the next whole part.
async fn window_parts(engine: &PartQueryEngine, from_us: i64, to_us: i64, floor_us: Option<i64>) -> QueryResult<Vec<PartRef>> {
    let (mut parts, _, _, _) = engine.snapshot(from_us, to_us).await?;
    if let Some(floor_us) = floor_us {
        parts.retain(|part| part.min_time_us >= floor_us);
    }
    Ok(parts)
}

/// NAN-3161 window-edge semantics: a prevalence window is served at PART
/// granularity from the parts' prevalence partials, never from raw rows.
/// Every live part overlapping `[from_us, to_us]` contributes whole. Parts
/// are event-hour bound (L0/M/H span one event hour; adopted parts are
/// single-hour), so a window is its edges widened outward to whole event
/// hours: `[floor_hour(from), floor_hour(to) + 1h)`. A day part (only with
/// `ingest.day_merges`, off by default) widens its edge to the whole day.
/// On hour-aligned bounds (`from % 1h == 0`, `(to + 1) % 1h == 0`) the
/// answer is identical to an exact scan.
async fn prevalence_relation(engine: &PartQueryEngine, parts: Vec<PartRef>, window_scope: WindowScope) -> QueryResult<Option<WindowRelation>> {
    let lookup_filter = window_scope.arm_filter();
    if parts.is_empty() {
        return Ok(None);
    }
    let mut arms = Vec::new();
    let mut params = Vec::new();
    let mut leases = Vec::new();
    // Explorer reuses the committed whole-part state across moving
    // anchors. Scope remains outside it.
    // NAN-3148: a consumer never builds it; it reuses a published one
    // when product[T] maintained exactly this inventory, else it reads
    // the same committed partials directly (the writer-less path).
    let published = if window_scope == WindowScope::AllEntities && super::product_publish::is_consumer(engine) {
        Some(window_state_path(engine, &parts)?).filter(|path| path.is_file())
    } else {
        None
    };
    let mut state = None;
    if let Some(path) = published {
        params.push(("prevalence_state".into(), path.to_string_lossy().into_owned()));
        arms.push(STATE_ARM.replace("{prevalence_states:String}", "{prevalence_state:String}"));
        state = Some(path);
    } else if window_scope == WindowScope::AllEntities && engine.writer().is_some()
        && super::product_publish::writes(engine) && engine.product_dir().is_dir() {
        let path = maintained_prevalence(engine, &parts).await?;
        params.push(("prevalence_state".into(), path.to_string_lossy().into_owned()));
        arms.push(STATE_ARM.replace("{prevalence_states:String}", "{prevalence_state:String}"));
        state = Some(path);
    } else {
        let local = engine.fetcher().ensure(&parts, &[FileSet::Partial(PartialKind::Prevalence)]).await
            .map_err(|error| internal(format!("{error:#}")))?;
        let paths = local.of(FileSet::Partial(PartialKind::Prevalence)).map(|file| file.path.clone()).collect::<Vec<_>>();
        if !paths.is_empty() {
            params.push(("prevalence_partials".to_string(), path_set(&paths)?));
            arms.push(partial_arm_sql(&lookup_filter));
        }
        leases.push(local);
    }
    if arms.is_empty() {
        return Ok(None);
    }
    let sql = format!("{MERGE_SELECT} FROM ({}) GROUP BY kind, scope, entity", arms.join(" UNION ALL "));
    Ok(Some(WindowRelation { sql, params, _leases: leases, state }))
}

/// The window-file row shape aggregated over state and partial arms.
const MERGE_SELECT: &str = "SELECT kind, scope, entity, arraySort(groupUniqArrayArray(1000)(hf)) AS host_fingerprints, \
        toUInt8(length(host_fingerprints) = 1000) AS host_count_saturated, max(private_flag) AS is_private, \
        min(first_us) AS first_seen, max(last_us) AS last_seen, sum(occurrence_count) AS total_occurrences";

/// A maintained state file (or glob of them) as a merge arm.
const STATE_ARM: &str = "SELECT kind, scope, entity, host_fingerprints AS hf, is_private AS private_flag, \
        toDateTime64(first_seen, 6, 'UTC') AS first_us, toDateTime64(last_seen, 6, 'UTC') AS last_us, \
        total_occurrences AS occurrence_count FROM file({prevalence_states:String}, Parquet)";

/// Scope-preserving maintained state for an immutable whole-part inventory.
/// New/retired parts change the key; timestamps and viewer filters do not.
/// The content-addressed whole-part state of `parts` (built or not).
/// Day blocks (long-lived: a month of reuse).
fn prevalence_state_path(engine: &PartQueryEngine, parts: &[PartRef]) -> QueryResult<std::path::PathBuf> {
    inventory_path(engine, STATE_PREFIX, parts)
}

/// NAN-3161: a moving window's state and its stable prefix: superseded
/// within hours, so kept only [`WINDOW_STATE_RETAIN_SECS`] past last use.
fn window_state_path(engine: &PartQueryEngine, parts: &[PartRef]) -> QueryResult<std::path::PathBuf> {
    inventory_path(engine, WINDOW_STATE_PREFIX, parts)
}

const WINDOW_STATE_PREFIX: &str = "prevalence-window-v2-";
/// NAN-3279: v2 states carry `bucket` and are bucket-sorted ([`fold_states`]).
const STATE_PREFIX: &str = "prevalence-state-v2-";
const WINDOW_STATE_RETAIN_SECS: u64 = 7_200;

fn inventory_path(engine: &PartQueryEngine, prefix: &str, parts: &[PartRef]) -> QueryResult<std::path::PathBuf> {
    use sha2::{Digest, Sha256};
    let mut identities = parts.iter().map(serde_json::to_vec).collect::<Result<Vec<_>, _>>().map_err(internal)?;
    identities.sort();
    let mut digest = Sha256::new();
    for identity in identities { digest.update((identity.len() as u64).to_le_bytes()); digest.update(identity); }
    Ok(engine.product_dir().join(format!("{prefix}{}.parquet", hex::encode(digest.finalize()))))
}

const HOURS_PER_DAY: i64 = 24;

/// The event hour a part's prevalence rows are filed under: its own hour,
/// or the first hour of its day for a day part (whose rows carry only day
/// granularity). Every part lands in exactly one hour.
fn leaf_hour(part: &PartRef) -> i64 {
    if part.level.is_hourly() {
        i64::from(part.event_hour)
    } else {
        i64::from(part.event_day.unwrap_or_else(|| part.event_hour.div_euclid(24))) * HOURS_PER_DAY
    }
}

/// The maintained whole-part state of `parts` (the window state product[T]
/// publishes and the explorer reads), content-addressed by the inventory.
///
/// NAN-3161: built incrementally. With `b` the newest event hour among the
/// parts, the state is `stable(hours < b) ⊕ leaf(hour b)`: between hour
/// rolls a cycle folds only the open hour's leaf into the cached stable
/// state. The stable state, rebuilt when an hour rolls, a day ages out or a
/// late part lands, is composed from cached aligned day blocks (1, 2, 4, 8,
/// 16 … days; [`day_blocks`]) plus the leaves of the at most two partial
/// days at its edges, so dropping an aged-out day re-merges a handful of
/// cached blocks rather than every daily state.
///
/// NAN-3279: no statement reads more than a bounded slice. Raw partials are
/// read only by leaf statements (an aligned group of
/// [`product_state::leaf_hours`] event hours); every other state is a fold
/// of states, run in hash-range steps ([`fold_states`]) of at most
/// [`product_state::step_bytes`] of input each, so after a restart the 7d
/// and 30d windows converge in many short statements, each under the time
/// cap and each holding the idle admission slot only for itself.
///
/// [`product_state::leaf_hours`]: super::product_state::leaf_hours
/// [`product_state::step_bytes`]: super::product_state::step_bytes
pub(super) async fn maintained_prevalence(engine: &PartQueryEngine, parts: &[PartRef]) -> QueryResult<std::path::PathBuf> {
    let path = window_state_path(engine, parts)?;
    if path.is_file() {
        touch_product_state(engine, &path)?;
        return Ok(path);
    }
    if !super::product_state::building() {
        super::product_state::request_at(engine, engine.identity_state_dir(), super::product_state::Work::Prevalence(parts.to_vec()));
        return Err(PartQueryError::Unavailable(super::product_state::WARMING.into()));
    }
    super::fetch::prevalence_path(async {
        let newest = parts.iter().map(leaf_hour).max().expect("a maintained inventory is non-empty");
        let (stable, open): (Vec<PartRef>, Vec<PartRef>) = parts.iter().cloned().partition(|part| leaf_hour(part) < newest);
        let mut inputs = Vec::new();
        if !stable.is_empty() {
            inputs.push(stable_state(engine, &stable).await?);
        }
        inputs.extend(leaf_states(engine, &open).await?);
        fold_states(engine, &path, inputs).await
    })
    .await
}

/// The cached state of `parts` (a stable prefix), built from
/// [`span_inputs`] on a miss.
async fn stable_state(engine: &PartQueryEngine, parts: &[PartRef]) -> QueryResult<std::path::PathBuf> {
    let path = window_state_path(engine, parts)?;
    if path.is_file() {
        touch_product_state(engine, &path)?;
        return Ok(path);
    }
    let inputs = span_inputs(engine, parts).await?;
    fold_states(engine, &path, inputs).await
}

fn hour_range(parts: &[PartRef]) -> (i64, i64) {
    parts.iter().map(leaf_hour).fold((i64::MAX, i64::MIN), |(lo, hi), hour| (lo.min(hour), hi.max(hour)))
}

/// `parts` split into: days wholly inside its hour span (served by cached
/// aligned day blocks) and the partial days at either edge (their leaves).
async fn span_inputs(engine: &PartQueryEngine, parts: &[PartRef]) -> QueryResult<Vec<std::path::PathBuf>> {
    let (first, last) = hour_range(parts);
    let mut whole = std::collections::BTreeMap::<i64, Vec<PartRef>>::new();
    let mut ragged = Vec::new();
    for part in parts {
        let day = leaf_hour(part).div_euclid(HOURS_PER_DAY);
        if day * HOURS_PER_DAY >= first && day * HOURS_PER_DAY + HOURS_PER_DAY - 1 <= last {
            whole.entry(day).or_default().push(part.clone());
        } else {
            ragged.push(part.clone());
        }
    }
    let mut inputs = Vec::new();
    if let (Some(&first_day), Some(&last_day)) = (whole.keys().next(), whole.keys().next_back()) {
        for (level, index) in day_blocks(first_day, last_day) {
            if let Some(path) = Box::pin(day_block(engine, &whole, level, index)).await? {
                inputs.push(path);
            }
        }
    }
    inputs.extend(leaf_states(engine, &ragged).await?);
    Ok(inputs)
}

/// The canonical decomposition of days `[first, last]` into aligned blocks
/// `(level, index)` covering days `[index << level, (index + 1) << level)`.
fn day_blocks(first: i64, last: i64) -> Vec<(u32, i64)> {
    let mut blocks = Vec::new();
    let mut day = first;
    while day <= last {
        let mut level = 0_u32;
        while level < 16 {
            let size = 1_i64 << (level + 1);
            if day.rem_euclid(size) != 0 || day + size - 1 > last { break; }
            level += 1;
        }
        blocks.push((level, day >> level));
        day += 1_i64 << level;
    }
    blocks
}

/// The cached state of aligned day block `(level, index)` over `days`
/// (`None`: no parts in it). A one-day block is the fold of that day's
/// leaves; a wider block is the fold of its two halves, so a new or changed
/// day rebuilds only the blocks above it, each from two cached states. A
/// block with one populated half IS that half (same inventory, same content
/// address), as is a day with a single leaf.
async fn day_block(
    engine: &PartQueryEngine,
    days: &std::collections::BTreeMap<i64, Vec<PartRef>>,
    level: u32,
    index: i64,
) -> QueryResult<Option<std::path::PathBuf>> {
    let (start, end) = (index << level, (index + 1) << level);
    let parts = days.range(start..end).flat_map(|(_, parts)| parts.iter().cloned()).collect::<Vec<_>>();
    if parts.is_empty() {
        return Ok(None);
    }
    let path = prevalence_state_path(engine, &parts)?;
    if path.is_file() {
        touch_product_state(engine, &path)?;
        return Ok(Some(path));
    }
    let inputs = if level == 0 {
        leaf_states(engine, &parts).await?
    } else {
        let mut inputs = Vec::new();
        for half in [index * 2, index * 2 + 1] {
            if let Some(path) = Box::pin(day_block(engine, days, level - 1, half)).await? {
                inputs.push(path);
            }
        }
        if let [only] = inputs.as_slice() {
            return Ok(Some(only.clone()));
        }
        inputs
    };
    Ok(Some(fold_states(engine, &path, inputs).await?))
}

/// NAN-3279: `parts` grouped into leaves: aligned groups of `hours` event
/// hours within one day (`hours` divides 24), in hour order. A part lands in
/// exactly one leaf ([`leaf_hour`]); a window edge sliding by an hour
/// changes only the leaf it slides through.
fn leaf_groups(parts: &[PartRef], hours: i64) -> Vec<Vec<PartRef>> {
    let hours = hours.clamp(1, HOURS_PER_DAY);
    let mut groups = std::collections::BTreeMap::<i64, Vec<PartRef>>::new();
    for part in parts {
        groups.entry(leaf_hour(part).div_euclid(hours)).or_default().push(part.clone());
    }
    groups.into_values().collect()
}

/// The leaf states covering `parts` (see [`leaf_groups`]).
async fn leaf_states(engine: &PartQueryEngine, parts: &[PartRef]) -> QueryResult<Vec<std::path::PathBuf>> {
    let mut states = Vec::new();
    for group in leaf_groups(parts, super::product_state::leaf_hours()) {
        states.push(leaf_state(engine, &group).await?);
    }
    Ok(states)
}

/// NAN-3279: maintained states carry `bucket` (a hash of the group key) and
/// are written sorted by it in small row groups, so a fold step reading one
/// bucket range prunes every other row group by its min/max.
const STATE_BUCKETS: u32 = 256;
const BUCKET_SQL: &str = "toUInt8(cityHash64(kind, scope, entity) % 256)";
const STATE_WRITE_SETTINGS: &str = ", output_format_parquet_row_group_size=65536, input_format_parquet_filter_push_down=1";

/// The disjoint bucket ranges `[lo, hi)` a fold over `input_bytes` of state
/// runs in: one per [`product_state::step_bytes`] of input, at most one per
/// bucket. Their union is every bucket.
///
/// [`product_state::step_bytes`]: super::product_state::step_bytes
fn step_ranges(input_bytes: u64, step_bytes: u64) -> Vec<(u32, u32)> {
    let steps = input_bytes.div_ceil(step_bytes.max(1)).clamp(1, u64::from(STATE_BUCKETS)) as u32;
    (0..steps).map(|step| (step * STATE_BUCKETS / steps, (step + 1) * STATE_BUCKETS / steps)).collect()
}

/// One leaf: the state of `parts`' prevalence partials (one statement over
/// at most [`product_state::leaf_hours`] event hours of partials).
///
/// [`product_state::leaf_hours`]: super::product_state::leaf_hours
async fn leaf_state(engine: &PartQueryEngine, parts: &[PartRef]) -> QueryResult<std::path::PathBuf> {
    let path = prevalence_state_path(engine, parts)?;
    if path.is_file() {
        touch_product_state(engine, &path)?;
        return Ok(path);
    }
    let local = engine.fetcher().ensure(parts, &[FileSet::Partial(PartialKind::Prevalence)]).await
        .map_err(|error| internal(format!("{error:#}")))?;
    let paths = local.of(FileSet::Partial(PartialKind::Prevalence)).map(|file| file.path.clone()).collect::<Vec<_>>();
    if paths.len() != parts.len() { return Err(internal("a live part has no prevalence partial")); }
    let params = vec![("prevalence_partials".to_string(), path_set(&paths)?)];
    let sql = format!("{MERGE_SELECT}, {BUCKET_SQL} AS bucket FROM ({}) GROUP BY kind, scope, entity ORDER BY bucket",
        partial_arm_sql(""));
    run_state_statement(engine, &path, sql, params).await?;
    STATE_MERGES.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    tracing::debug!(partials = parts.len(), "prevalence leaf state merged");
    sweep_state_dir(engine.product_dir(), &path);
    Ok(path)
}

/// NAN-3279: fold maintained states into the state file `path`
/// (idempotent: content-addressed). Over [`product_state::step_bytes`] of
/// input the fold runs in hash-range steps: each step folds only the groups
/// of its bucket range (every input row of a group shares its bucket, so a
/// step sees a group whole and the steps' groups are disjoint), holds the
/// idle admission slot for that statement alone and persists its output, so
/// an interrupted build resumes at the next step. The step outputs are then
/// concatenated without a native statement ([`super::parquet_concat`]).
/// The result has exactly the rows of the one-statement fold.
///
/// [`product_state::step_bytes`]: super::product_state::step_bytes
pub(super) async fn fold_states(engine: &PartQueryEngine, path: &std::path::Path, inputs: Vec<std::path::PathBuf>) -> QueryResult<std::path::PathBuf> {
    if path.is_file() {
        touch_product_state(engine, path)?;
        return Ok(path.to_path_buf());
    }
    let mut inputs = inputs;
    inputs.sort();
    inputs.dedup();
    match inputs.as_slice() {
        [] => return Err(internal("a prevalence state fold has no inputs")),
        [only] if only == path => return Ok(path.to_path_buf()),
        [only] => {
            // One input IS the state: link it (copy across devices).
            let temporary = engine.product_dir().join(format!(".prevalence-state-{}.parquet", uuid::Uuid::new_v4().simple()));
            if std::fs::hard_link(only, &temporary).is_err() {
                std::fs::copy(only, &temporary).map_err(internal)?;
            }
            std::fs::rename(&temporary, path).map_err(internal)?;
            return Ok(path.to_path_buf());
        }
        _ => {}
    }
    let started = Instant::now();
    let input_bytes = inputs.iter().map(|input| std::fs::metadata(input).map(|metadata| metadata.len()))
        .sum::<std::io::Result<u64>>().map_err(internal)?;
    let ranges = step_ranges(input_bytes, super::product_state::step_bytes());
    let fold_sql = |range: Option<(u32, u32)>| {
        let filter = range.map(|(lo, hi)| format!(" WHERE bucket >= {lo} AND bucket < {hi}")).unwrap_or_default();
        format!("{MERGE_SELECT}, {BUCKET_SQL} AS bucket FROM ({STATE_ARM}{filter}) GROUP BY kind, scope, entity ORDER BY bucket")
    };
    let params = vec![("prevalence_states".to_string(), path_set(&inputs)?)];
    if let [_] = ranges.as_slice() {
        run_state_statement(engine, path, fold_sql(None), params).await?;
    } else {
        let stem = path.file_stem().and_then(|stem| stem.to_str()).ok_or_else(|| internal("a state path has no name"))?;
        let mut steps = Vec::with_capacity(ranges.len());
        let mut slowest_ms = 0_u64;
        for (index, range) in ranges.iter().enumerate() {
            let step = engine.product_dir().join(format!("{STEP_PREFIX}{stem}-{}-{index:03}.parquet", ranges.len()));
            if step.is_file() {
                // A step an interrupted build already persisted.
                let _ = std::fs::File::open(&step).and_then(|file| file.set_modified(std::time::SystemTime::now()));
            } else {
                let step_started = Instant::now();
                run_state_statement(engine, &step, fold_sql(Some(*range)), params.clone()).await?;
                FOLD_STEPS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                slowest_ms = slowest_ms.max(step_started.elapsed().as_millis() as u64);
            }
            steps.push(step);
        }
        let temporary = engine.product_dir().join(format!(".prevalence-state-{}.parquet", uuid::Uuid::new_v4().simple()));
        let (sources, target) = (steps.clone(), temporary.clone());
        let assembled = tokio::task::spawn_blocking(move || super::parquet_concat::concat(&sources, &target)).await
            .map_err(internal)?;
        if let Err(error) = assembled {
            // A step that cannot be assembled is never resumed from.
            for step in &steps {
                let _ = std::fs::remove_file(step);
            }
            return Err(internal(format!("{error:#}")));
        }
        std::fs::rename(&temporary, path).map_err(internal)?;
        for step in steps {
            let _ = std::fs::remove_file(step);
        }
        tracing::info!(states = inputs.len(), input_bytes, steps = ranges.len(), slowest_step_ms = slowest_ms,
            wall_ms = started.elapsed().as_millis() as u64, "prevalence state folded in steps");
    }
    STATE_MERGES.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    tracing::debug!(states = inputs.len(), input_bytes, wall_ms = started.elapsed().as_millis() as u64, "prevalence state merged");
    sweep_state_dir(engine.product_dir(), path);
    Ok(path.to_path_buf())
}

/// Run one state-writing statement (`select_sql` over `params`) into
/// `output`, through a temporary renamed into place. One statement at a
/// time per process, each under its own idle admission slot, released when
/// the statement ends.
async fn run_state_statement(engine: &PartQueryEngine, output: &std::path::Path, select_sql: String, mut params: Vec<(String, String)>) -> QueryResult<()> {
    static BUILD: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
    let _build = BUILD.lock().await;
    if output.is_file() { return Ok(()); }
    let _slot = super::product_state::idle(engine).await;
    IDLE_STATEMENTS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let temporary = engine.product_dir().join(format!(".prevalence-state-{}.parquet", uuid::Uuid::new_v4().simple()));
    params.push(("state_output".into(), temporary.to_string_lossy().into_owned()));
    let sql = format!("INSERT INTO FUNCTION file({{state_output:String}}, Parquet) {select_sql}{}{STATE_WRITE_SETTINGS}",
        statement_settings(engine));
    let result = engine.with_job_statements(engine.run_sql(sql, params)).await;
    if let Err(error) = result { let _ = std::fs::remove_file(&temporary); return Err(internal(error)); }
    std::fs::rename(&temporary, output).map_err(internal)
}

/// Prefix of a persisted fold step (NAN-3279), kept a day for resumption.
const STEP_PREFIX: &str = ".prevalence-step-";
/// State files of the pre-NAN-3279 format (no `bucket`): never read again.
const LEGACY_PREFIXES: [&str; 3] = ["prevalence-state-v1-", "prevalence-window-v1-", "prevalence-history-v1-"];

/// NAN-4154: how long a maintained state or day history survives a complete
/// product cycle that did not use it.
///
/// Both are content-addressed by their part inventory, so every merge,
/// arrival or retirement writes a new name and the old one is never read
/// again. [`sweep_state_dir`] keeps them a month by age, which kept every
/// superseded version: a large hosted tenant held 1,111 state files (17 GiB) and
/// 580 day histories (14.8 GiB) after five days, growing ~6 GiB a day, on the
/// hot volume the 7-day hot window shares. Only ~4.9 GiB had been used in
/// the last day. The volume target was exceeded, the hot window evicted its
/// oldest parts, and 7-day searches fetched them back from R2.
///
/// A complete cycle (every window rebuilt) touches every state and history
/// file a published window is built from (`touch_product_state` on reuse,
/// the manifest's own files every tick). A file it left untouched for this
/// long is superseded. Six hours spans several hour rolls (each one rebuilds
/// the stable prefix and walks its day blocks) and a demand-built window's
/// reuse. A quiet tenant runs no cycle, so its files are never swept while
/// it is quiet. Removing a file still needed is a rebuild, never a wrong
/// answer: it is rebuilt from its inputs under the same name.
pub(super) const SUPERSEDED_STATE_GRACE: std::time::Duration = std::time::Duration::from_secs(6 * 3_600);

/// NAN-4154: remove the maintained prevalence states and day histories in
/// `state` last used before `used_before` (see [`SUPERSEDED_STATE_GRACE`]).
/// Temporaries, fold steps, windows and product files are left to
/// [`sweep_state_dir`] and [`prune_product_state`]. Returns the files removed
/// and the bytes freed (a name whose inode is still linked elsewhere frees
/// nothing).
pub(super) fn sweep_superseded_states(state: &std::path::Path, used_before: std::time::SystemTime) -> (u64, u64) {
    use std::os::unix::fs::MetadataExt as _;
    let Ok(entries) = std::fs::read_dir(state) else { return (0, 0) };
    let (mut files, mut bytes) = (0_u64, 0_u64);
    for entry in entries.flatten() {
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if !(name.starts_with(STATE_PREFIX) || name.starts_with(HISTORY_STATE_PREFIX)) {
            continue;
        }
        let Ok(metadata) = entry.metadata() else { continue };
        if !metadata.is_file() || !metadata.modified().is_ok_and(|at| at < used_before) {
            continue;
        }
        if std::fs::remove_file(entry.path()).is_ok() {
            files += 1;
            if metadata.nlink() <= 1 {
                bytes += metadata.len();
            }
        }
    }
    (files, bytes)
}

/// NAN-4154: maintained prevalence states and day histories may use at most
/// this fraction (1/N) of the volume product[T]'s dir lives on. They share it
/// with the 7-day hot window (the A/B hot volume, NAN-3799), so their growth
/// is capacity taken from search.
pub(super) const STATE_BUDGET_DIVISOR: u64 = 8;
/// NAN-4154: a state or history used this recently is never removed for budget.
pub(super) const STATE_BUDGET_FLOOR: std::time::Duration = std::time::Duration::from_secs(15 * 60);

/// NAN-4154: bound the maintained states and day histories to `budget_bytes`,
/// removing the least recently used first, never one used at or after
/// `keep_after`. A file another name links (a published window) frees no
/// bytes and is not counted twice. Returns (files removed, bytes freed,
/// bytes left). A removed state is rebuilt under the same content address
/// the next time a window needs it: this costs build time, never answers.
pub(super) fn enforce_state_budget(
    state: &std::path::Path,
    budget_bytes: u64,
    keep_after: std::time::SystemTime,
) -> (u64, u64, u64) {
    use std::os::unix::fs::MetadataExt as _;
    let Ok(entries) = std::fs::read_dir(state) else { return (0, 0, 0) };
    let mut seen = std::collections::HashSet::new();
    let mut candidates = Vec::new();
    let mut total = 0_u64;
    for entry in entries.flatten() {
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if !(name.starts_with(STATE_PREFIX) || name.starts_with(HISTORY_STATE_PREFIX)) {
            continue;
        }
        let Ok(metadata) = entry.metadata() else { continue };
        if !metadata.is_file() || !seen.insert((metadata.dev(), metadata.ino())) {
            continue;
        }
        total += metadata.len();
        let Ok(modified) = metadata.modified() else { continue };
        if modified < keep_after {
            candidates.push((modified, entry.path(), metadata.len(), metadata.nlink()));
        }
    }
    let (mut files, mut freed) = (0_u64, 0_u64);
    if total <= budget_bytes {
        return (0, 0, total);
    }
    candidates.sort();
    for (_, path, bytes, links) in candidates {
        if total <= budget_bytes {
            break;
        }
        if std::fs::remove_file(&path).is_ok() {
            files += 1;
            if links <= 1 {
                freed += bytes;
                total -= bytes;
            }
        }
    }
    (files, freed, total)
}

/// Retain daily aggregates and day blocks across quiet periods so a new
/// arrival only rebuilds its day. A month bounds reuse to the supported
/// product window.
fn sweep_state_dir(state: &std::path::Path, keep: &std::path::Path) {
    let Ok(entries) = std::fs::read_dir(state) else { return };
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        let retain_secs = if name.starts_with(WINDOW_STATE_PREFIX) {
            WINDOW_STATE_RETAIN_SECS
        } else if LEGACY_PREFIXES.iter().any(|prefix| name.starts_with(prefix)) {
            0
        } else if name.starts_with(STEP_PREFIX) {
            86_400
        } else if name.starts_with(STATE_PREFIX) || name.starts_with(HISTORY_STATE_PREFIX)
            || name.starts_with(".prevalence-state-") || name.starts_with(".prevalence-history-") {
            30 * 86_400
        } else {
            continue;
        };
        if entry.path() != keep
            && entry.metadata().ok().and_then(|m| m.modified().ok()).and_then(|at| at.elapsed().ok())
                .is_some_and(|age| age.as_secs() >= retain_secs) {
            let _ = std::fs::remove_file(entry.path());
        }
    }
}

/// NAN-3279 evidence: fold steps (hash-range statements) this process ran.
static FOLD_STEPS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
/// NAN-3279 evidence: state statements run, each under its own idle slot.
static IDLE_STATEMENTS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Hash-range fold steps run by this process (bench/test evidence).
pub fn prevalence_fold_steps() -> u64 {
    FOLD_STEPS.load(std::sync::atomic::Ordering::Relaxed)
}

/// State statements run by this process, each holding its own idle slot.
pub fn prevalence_state_statements() -> u64 {
    IDLE_STATEMENTS.load(std::sync::atomic::Ordering::Relaxed)
}

/// NAN-3161 evidence: maintained prevalence state merges this process ran.
static STATE_MERGES: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Maintained prevalence state merges run by this process (bench evidence).
pub fn prevalence_state_merges() -> u64 {
    STATE_MERGES.load(std::sync::atomic::Ordering::Relaxed)
}

/// The committed-partials arm of the window relation.
fn partial_arm_sql(lookup_filter: &str) -> String {
    format!(
        "SELECT kind, scope, entity, host_fingerprints AS hf, is_private AS private_flag, \
                toDateTime64(first_seen, 6, 'UTC') AS first_us, toDateTime64(last_seen, 6, 'UTC') AS last_us, \
                daily_count AS occurrence_count \
         FROM file({{prevalence_partials:String}}, Parquet) WHERE host_cap = 1000{lookup_filter}"
    )
}

/// One point-lookup statement over a lookup-scoped relation. The lookup
/// filter already sits inside every arm; only the caller's source scope is
/// applied here.
fn lookup_statement_sql(relation_sql: &str, scope: &str, settings: &str) -> String {
    format!(
        "SELECT kind, entity, length(arrayDistinct(arrayFlatten(groupArray(host_fingerprints)))) AS raw_hosts, \
                max(host_count_saturated) AS any_saturated, max(is_private) AS private, \
                toUnixTimestamp64Micro(min(first_seen)) AS first_us, toUnixTimestamp64Micro(max(last_seen)) AS last_us, \
                sum(total_occurrences) AS total \
         FROM ({relation_sql}) WHERE {scope} \
         GROUP BY kind, entity{settings}"
    )
}

/// Results in request order (first occurrence), O(n) instead of a linear
/// `position` scan per result.
fn order_by_request(results: &mut [crate::prevalence::PrevalenceResult], order: &[(String, String)]) {
    let mut rank: std::collections::HashMap<&str, usize> = std::collections::HashMap::with_capacity(order.len());
    for (index, (_, entity)) in order.iter().enumerate() {
        rank.entry(entity.as_str()).or_insert(index);
    }
    results.sort_by_key(|result| rank.get(result.artifact.as_str()).copied().unwrap_or(usize::MAX));
}

pub(super) fn settings(engine: &PartQueryEngine) -> String {
    format!("{}, readonly=2", statement_settings(engine))
}

/// [`settings`] without `readonly`: a durable job's spool statement
/// (`INSERT INTO FUNCTION file`) runs on the read-write lane (NAN-3088).
pub(super) fn statement_settings(engine: &PartQueryEngine) -> String {
    statement_settings_within(engine, u64::MAX, engine.settings().max_memory_bytes)
}

/// [`statement_settings`] with the bytes read capped at `read_budget_bytes`
/// as well as the engine's own bound (a durable job's scan budget), under a
/// statement memory cap of `memory_bytes` (a job's lane cap).
fn statement_settings_within(engine: &PartQueryEngine, read_budget_bytes: u64, memory_bytes: u64) -> String {
    let settings = engine.settings();
    // Wide aggregations (prevalence over 30 d, entity ranges) spill to the
    // process's state dir on the cell volume before the memory fence, like
    // the planner's broad search (NAN-3046).
    let (spill_at, spill_disk) = crate::planner::external_processing_limits(memory_bytes);
    format!(
        " SETTINGS {}, max_execution_time={}, max_bytes_to_read={}, max_memory_usage={}, \
         max_bytes_before_external_group_by={spill_at}, max_bytes_before_external_sort={spill_at}, \
         max_temporary_data_on_disk_size_for_query={spill_disk}, use_query_cache=0",
        // NAN-3168: product-state builds run on the product thread budget.
        super::product_state::thread_settings(settings.threads),
        crate::query_timing::execution_seconds(settings.max_execution_seconds),
        settings.max_query_bytes.min(read_budget_bytes), memory_bytes
    )
}

/// The detail scan's source fence over raw rows: exactly the explorer's
/// deny scope, applied to each row's `metadata.log_source`.
pub(super) fn detail_scope_filter(deny: &[String], params: &mut Vec<(String, String)>) -> QueryResult<String> {
    Ok(scope_filter(deny, params)?.replace("lower(scope)", "lower(tupleElement(metadata, 'log_source'))"))
}

fn write_state_atomically(path: &std::path::Path, value: &Value) -> QueryResult<()> {
    let temporary = path.with_extension(format!("{}.tmp", uuid::Uuid::new_v4().simple()));
    std::fs::write(&temporary, serde_json::to_vec(value).map_err(internal)?).map_err(internal)?;
    std::fs::rename(&temporary, path).map_err(|error| { let _ = std::fs::remove_file(&temporary); internal(error) })
}

fn scope_filter(deny: &[String], params: &mut Vec<(String, String)>) -> QueryResult<String> {
    if deny.len() > 1_024 || deny.iter().any(|source| source.is_empty() || source.len() > 512 || source.chars().any(char::is_control)) {
        return Err(invalid("prevalence source scope exceeds its bound"));
    }
    if deny.is_empty() {
        return Ok("1 = 1".to_string());
    }
    let denied = deny.iter().map(|source| source.trim().to_ascii_lowercase()).collect::<BTreeSet<_>>();
    params.push(("denied_scopes".to_string(), sql_string_array(denied.iter().map(String::as_str))));
    Ok("NOT has({denied_scopes:Array(String)}, lower(scope))".to_string())
}

pub(super) fn sql_string_array<'a>(values: impl Iterator<Item = &'a str>) -> String {
    format!(
        "[{}]",
        values.map(|value| format!("'{}'", value.replace('\\', "\\\\").replace('\'', "\\'"))).collect::<Vec<_>>().join(",")
    )
}

// ---------------------------------------------------------------------------
// Prevalence
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrevalenceLookupRequest {
    pub request_id: String,
    pub tenant_id: String,
    /// `1h`, `24h`, `7d` or `30d` (the reader's snapshot windows).
    pub window: String,
    /// Window end (RFC3339); defaults to now.
    #[serde(default)]
    pub end: Option<String>,
    pub artifacts: Vec<String>,
    #[serde(default)]
    pub rarity_threshold: Option<u64>,
    #[serde(default, deserialize_with = "nanosiem_core::auth::source_visibility::deserialize_lake_deny_set")]
    pub deny_source_types: Vec<String>,
}

/// The default rarity threshold (NAN-3492: 3, was 5). A cell process falls
/// back to [`crate::prevalence::tenant_rarity_threshold`], bound from its
/// assignment.
pub const DEFAULT_RARITY_THRESHOLD: u64 = crate::prevalence::DEFAULT_RARITY_THRESHOLD;
/// Artifacts per prevalence lookup statement. NAN-3046 bounded this at 2,000
/// because each statement aggregated the whole window relation. NAN-3068
/// pushes the lookup filter into every arm, so a statement's aggregation
/// state is the lookup set itself. A request (at most 10,000 artifacts) is
/// now one scan of the window instead of five.
const PREVALENCE_LOOKUP_BATCH: usize = 10_000;

pub fn window_us(window: &str) -> QueryResult<i64> {
    const HOUR: i64 = 3_600_000_000;
    Ok(match window {
        "1h" => HOUR,
        "24h" => 24 * HOUR,
        "7d" => 7 * 24 * HOUR,
        "30d" => 30 * 24 * HOUR,
        _ => return Err(invalid("prevalence window must be 1h, 24h, 7d or 30d")),
    })
}

fn window_bounds(window: &str, end: Option<&str>) -> QueryResult<(i64, i64)> {
    let end_us = match end {
        Some(end) => rfc3339_us(end)?,
        None => chrono::Utc::now().timestamp_micros(),
    };
    Ok((end_us - window_us(window)?, end_us))
}

/// Point lookups over the window relation, merged across allowed scopes.
pub async fn prevalence_lookup(engine: &PartQueryEngine, request: &PrevalenceLookupRequest) -> QueryResult<Value> {
    if request.tenant_id != engine.settings().tenant_id {
        return Err(invalid("request tenant is not this process's tenant"));
    }
    let threshold = request.rarity_threshold.unwrap_or_else(crate::prevalence::tenant_rarity_threshold);
    let (from_us, to_us) = window_bounds(&request.window, request.end.as_deref())?;
    // Capture a conservative watermark before taking the query snapshot. A
    // later head could include parts that this response did not read.
    let log_head = engine.head_json().await;
    let results = prevalence_lookup_bounds(engine, &request.artifacts, from_us, to_us, &request.deny_source_types, threshold).await?;
    Ok(json!({
        "ok": true,
        "request_id": request.request_id,
        "tenant_id": request.tenant_id,
        "route": "prevalence_lookup",
        "source_mode": "parts",
        // The verified part-log head is a conservative freshness watermark.
        "log_head": log_head,
        "window": request.window,
        "window_start_us": from_us,
        "window_end_us": to_us,
        "results": results,
    }))
}

/// Lookups over exact `[from_us, to_us]` bounds, in request order.
pub async fn prevalence_lookup_bounds(
    engine: &PartQueryEngine,
    artifacts: &[String],
    from_us: i64,
    to_us: i64,
    deny_source_types: &[String],
    threshold: u64,
) -> QueryResult<Vec<crate::prevalence::PrevalenceResult>> {
    prevalence_lookup_floored(engine, artifacts, from_us, to_us, None, deny_source_types, threshold).await
}

/// [`prevalence_lookup_bounds`] under a hard lower bound `floor_us` (a
/// durable job's retention cutoff; see [`window_parts`]).
pub async fn prevalence_lookup_floored(
    engine: &PartQueryEngine,
    artifacts: &[String],
    from_us: i64,
    to_us: i64,
    floor_us: Option<i64>,
    deny_source_types: &[String],
    threshold: u64,
) -> QueryResult<Vec<crate::prevalence::PrevalenceResult>> {
    engine.pinned_if_needed(super::fetch::prevalence_path(prevalence_lookup_memoized(engine, artifacts, from_us, to_us, floor_us, deny_source_types, threshold))).await?
}

async fn prevalence_lookup_memoized(
    engine: &PartQueryEngine,
    artifacts: &[String],
    from_us: i64,
    to_us: i64,
    floor_us: Option<i64>,
    deny_source_types: &[String],
    threshold: u64,
) -> QueryResult<Vec<crate::prevalence::PrevalenceResult>> {
    use super::prevalence_rows::{self, Summary};
    if artifacts.len() > 10_000 {
        return Err(invalid("prevalence lookup exceeds 10000 artifacts"));
    }
    let mut scope_params = Vec::new();
    let scope = scope_filter(deny_source_types, &mut scope_params)?;
    let order = artifacts
        .iter()
        .filter_map(|artifact| crate::prevalence::parse_lookup_artifact(artifact))
        .collect::<Vec<_>>();
    let parsed = order
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    if parsed.is_empty() {
        return Ok(Vec::new());
    }
    // NAN-3161: every overlapping part is answered whole from its memoized
    // partial summary (see `prevalence_relation` for the edge semantics);
    // no part is ever re-scanned from its rows.
    let inside = window_parts(engine, from_us, to_us, floor_us).await?;
    let records = engine
        .fetcher()
        .records(&inside)
        .await
        .map_err(|error| internal(format!("{error:#}")))?;
    let mut results = Vec::new();
    for batch in parsed.chunks(PREVALENCE_LOOKUP_BATCH) {
        let shape = prevalence_rows::shape(
            &engine.settings().tenant_id,
            batch,
            deny_source_types,
        );
        let mut summaries = Vec::new();
        let mut pending = Vec::new();
        let mut keys = std::collections::BTreeMap::new();
        for (part, record) in inside.iter().zip(&records) {
            let Some(partial) = record
                .files
                .partials
                .iter()
                .find(|partial| partial.kind == PartialKind::Prevalence)
            else {
                // Preserve legacy semantics and errors through the exact path.
                return prevalence_lookup_uncached_floored(engine, artifacts, from_us, to_us, floor_us, deny_source_types, threshold)
                .await;
            };
            let key = prevalence_rows::key(&shape, part, &partial.sha256);
            if let Some(rows) = engine.prevalence_rows().get(&key) {
                summaries.push(rows);
            } else {
                keys.insert(part.part_id.clone(), key);
                pending.push(part.clone());
            }
        }
        crate::query_timing::record(|phases| {
            phases.prevalence_memo_hits += summaries.len();
            phases.prevalence_memo_misses += pending.len();
        });
        let mut lookup_params = scope_params.clone();
        lookup_params.push((
            "lookup_kinds".into(),
            sql_string_array(batch.iter().map(|(kind, _)| kind.as_str())),
        ));
        lookup_params.push((
            "lookup_entities".into(),
            sql_string_array(batch.iter().map(|(_, entity)| entity.as_str())),
        ));
        if !pending.is_empty() {
            let local = engine
                .fetcher()
                .ensure(&pending, &[FileSet::Partial(PartialKind::Prevalence)])
                .await
                .map_err(|error| internal(format!("{error:#}")))?;
            let files = local
                .of(FileSet::Partial(PartialKind::Prevalence))
                .collect::<Vec<_>>();
            if files.len() != pending.len() {
                return Err(internal("a live part has no prevalence partial"));
            }
            let by_path = files
                .iter()
                .map(|file| {
                    (
                        file.path.to_string_lossy().into_owned(),
                        file.part_id.clone(),
                    )
                })
                .collect::<std::collections::BTreeMap<_, _>>();
            let mut params = lookup_params.clone();
            params.push((
                "prevalence_partials".into(),
                path_set(
                    &files
                        .iter()
                        .map(|file| file.path.clone())
                        .collect::<Vec<_>>(),
                )?,
            ));
            let sql = format!(
                "SELECT _path AS path, kind, entity, arraySort(groupUniqArrayArray(1000)(host_fingerprints)) AS hosts, \
                 toUInt8(length(hosts) = 1000) AS saturated, max(is_private) AS private, \
                 toUnixTimestamp64Micro(min(first_seen)) AS first_us, toUnixTimestamp64Micro(max(last_seen)) AS last_us, \
                 sum(daily_count) AS total FROM file({{prevalence_partials:String}}, Parquet) \
                 WHERE host_cap = 1000 AND {LOOKUP_FILTER} AND {scope} GROUP BY path, kind, entity{}",
                settings(engine)
            );
            let output = match engine.run_sql(sql, params).await {
                Ok(output) => output,
                Err(error) if per_part_answer_too_wide(&error) => {
                    drop(local);
                    return prevalence_lookup_uncached_floored(engine, artifacts, from_us, to_us, floor_us, deny_source_types, threshold)
                    .await;
                }
                Err(error) => return Err(super::engine::map_executor_error(error)),
            };
            if output.data.len() > 16 * 1024 * 1024 {
                drop(local);
                return prevalence_lookup_uncached_floored(engine, artifacts, from_us, to_us, floor_us, deny_source_types, threshold)
                .await;
            }
            let mut fresh = pending
                .iter()
                .map(|part| (part.part_id.clone(), Vec::new()))
                .collect::<std::collections::BTreeMap<_, _>>();
            for line in output
                .data
                .split(|byte| *byte == b'\n')
                .filter(|line| !line.is_empty())
            {
                let row: Value = serde_json::from_slice(line).map_err(internal)?;
                let path = row["path"]
                    .as_str()
                    .ok_or_else(|| internal("prevalence summary has no path"))?;
                let part = by_path
                    .get(path)
                    .ok_or_else(|| internal("prevalence summary named an unleased file"))?;
                fresh
                    .get_mut(part)
                    .expect("leased part is pending")
                    .push(Summary::decode(&row).map_err(internal)?);
            }
            for (part, rows) in fresh {
                let rows = Arc::new(rows);
                engine.prevalence_rows().insert(keys[&part], rows.clone());
                summaries.push(rows);
            }
        }
        match prevalence_rows::fold(&summaries, threshold) {
            Ok(rows) => results.extend(rows),
            Err(error)
                if error
                    .downcast_ref::<prevalence_rows::FoldTooWide>()
                    .is_some() =>
            {
                return prevalence_lookup_uncached_floored(engine, artifacts, from_us, to_us, floor_us, deny_source_types, threshold)
                .await;
            }
            Err(error) => return Err(internal(error)),
        }
    }
    order_by_request(&mut results, &order);
    Ok(results)
}

pub(super) async fn prevalence_lookup_uncached(
    engine: &PartQueryEngine,
    artifacts: &[String],
    from_us: i64,
    to_us: i64,
    deny_source_types: &[String],
    threshold: u64,
) -> QueryResult<Vec<crate::prevalence::PrevalenceResult>> {
    prevalence_lookup_uncached_floored(engine, artifacts, from_us, to_us, None, deny_source_types, threshold).await
}

async fn prevalence_lookup_uncached_floored(
    engine: &PartQueryEngine,
    artifacts: &[String],
    from_us: i64,
    to_us: i64,
    floor_us: Option<i64>,
    deny_source_types: &[String],
    threshold: u64,
) -> QueryResult<Vec<crate::prevalence::PrevalenceResult>> {
    if artifacts.len() > 10_000 {
        return Err(invalid("prevalence lookup exceeds 10000 artifacts"));
    }
    let order = artifacts
        .iter()
        .filter_map(|artifact| crate::prevalence::parse_lookup_artifact(artifact))
        .collect::<Vec<_>>();
    let parsed = order.iter().cloned().collect::<BTreeSet<_>>();
    let mut results = Vec::new();
    if parsed.is_empty() {
        return Ok(results);
    }
    let Some(relation) = prevalence_window(engine, from_us, to_us, floor_us, WindowScope::LookupOnly).await? else { return Ok(results) };
    // NAN-3046: a rule's `| prevalence` looks up every result row's
    // artifacts (up to 10k) over 30 d. One statement per bounded batch keeps
    // each statement's aggregation state and result inside the budget.
    let parsed = parsed.into_iter().collect::<Vec<_>>();
    for batch in parsed.chunks(PREVALENCE_LOOKUP_BATCH) {
    let mut params = relation.params.clone();
    let scope = scope_filter(deny_source_types, &mut params)?;
    params.push(("lookup_kinds".to_string(), sql_string_array(batch.iter().map(|(kind, _)| kind.as_str()))));
    params.push(("lookup_entities".to_string(), sql_string_array(batch.iter().map(|(_, entity)| entity.as_str()))));
    let sql = lookup_statement_sql(&relation.sql, &scope, &settings(engine));
    for row in engine.execute_sql(sql, params).await? {
        let kind = row["kind"].as_str().unwrap_or_default().to_string();
        let entity = row["entity"].as_str().unwrap_or_default().to_string();
        let raw_hosts = json_u64(&row["raw_hosts"]);
        let saturated = json_u64(&row["any_saturated"]) != 0 || raw_hosts >= 1_000;
        results.push(
            crate::prevalence::prevalence_result(
                &kind,
                &entity,
                raw_hosts.min(1_000),
                saturated,
                json_u64(&row["private"]) != 0,
                json_i64(&row["first_us"]),
                json_i64(&row["last_us"]),
                json_u64(&row["total"]),
                threshold,
            )
            .map_err(internal)?,
        );
    }
    }
    order_by_request(&mut results, &order);
    Ok(results)
}

fn json_u64(value: &Value) -> u64 {
    value.as_u64().or_else(|| value.as_str().and_then(|text| text.parse().ok())).unwrap_or_default()
}

/// NAN-3802: the continuation cursor after `row`, with `last_seen` in the
/// RFC 3339 form every consumer validates (derived from the exact event
/// microseconds, not from a SQL-side text rendering).
fn explorer_next_cursor(row: &Value) -> Value {
    let last_seen = nanosiem_core::prevalence::explorer_cursor_timestamp_from_micros(json_i64(&row["last_us"]))
        .map(Value::String)
        .unwrap_or_else(|| row["last_seen_text"].clone());
    json!({"last_seen": last_seen, "kind": row["kind"], "artifact": row["entity"]})
}

fn json_i64(value: &Value) -> i64 {
    value.as_i64().or_else(|| value.as_str().and_then(|text| text.parse().ok())).unwrap_or_default()
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrevalenceExplorerRequest {
    pub request_id: String,
    pub tenant_id: String,
    pub window: String,
    #[serde(default)]
    pub end: Option<String>,
    #[serde(default)]
    pub artifact_type: Option<String>,
    #[serde(default)]
    pub risk_level: Option<String>,
    #[serde(default)]
    pub first_seen_since: Option<String>,
    #[serde(default)]
    pub search: Option<String>,
    pub limit: u64,
    #[serde(default)]
    pub offset: u64,
    #[serde(default)]
    pub cursor: Option<nanosiem_core::prevalence::PrevalenceExplorerCursor>,
    #[serde(default)]
    pub rarity_threshold: Option<u64>,
    #[serde(default, deserialize_with = "nanosiem_core::auth::source_visibility::deserialize_lake_deny_set")]
    pub deny_source_types: Vec<String>,
}

#[derive(Debug, Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct PrevalenceDetailRequest {
    pub request_id: String,
    pub tenant_id: String,
    pub window: String,
    pub artifact: String,
    #[serde(default, deserialize_with = "nanosiem_core::auth::source_visibility::deserialize_lake_deny_set")]
    pub deny_source_types: Vec<String>,
}

/// Context from the tenant's verified, leased event files, never gen1 storage.
pub async fn prevalence_detail(engine: &PartQueryEngine, request: &PrevalenceDetailRequest) -> QueryResult<Value> {
    engine.pinned_if_needed(prevalence_detail_pinned(engine, request)).await?
}

async fn prevalence_detail_pinned(engine: &PartQueryEngine, request: &PrevalenceDetailRequest) -> QueryResult<Value> {
    if request.tenant_id != engine.settings().tenant_id {
        return Err(invalid("request tenant is not this process's tenant"));
    }
    if request.artifact.trim().is_empty() || request.artifact.len() > 512 || request.artifact.chars().any(char::is_control) {
        return Err(invalid("invalid detail artifact"));
    }
    let result = maintained_detail(engine, request).await?;
    Ok(json!({"ok": true, "request_id": request.request_id, "tenant_id": request.tenant_id,
        "route": "prevalence_detail", "source_mode": "parts", "window": request.window, "result": result}))
}

pub(super) async fn maintained_detail(engine: &PartQueryEngine, request: &PrevalenceDetailRequest) -> QueryResult<Value> {
    let (from_us, to_us) = product_bounds(&request.window, None)?;
    maintained_detail_bounds(engine, request, from_us, to_us).await
}

pub(super) async fn maintained_detail_bounds(engine: &PartQueryEngine, request: &PrevalenceDetailRequest, from_us: i64, to_us: i64) -> QueryResult<Value> {
    let (path, _) = match detail_state(engine, request, from_us, to_us).await {
        Ok(found) => found,
        // NAN-3791: a consumer with no published detail answers from a
        // first-answer-budget scan of its own instead of warming until
        // product[T] serves a demand (on tenant-a no demand was ever served:
        // the inbox write failed with EACCES and a 7d window build holds
        // the publisher for ~20 min between demand passes).
        Err(PartQueryError::Unavailable(reason)) if reason == super::product_state::WARMING
            && super::product_publish::is_consumer(engine) => return quick_detail(engine, request, from_us, to_us).await,
        Err(error) => return Err(error),
    };
    let mut answer = serde_json::from_slice(&std::fs::read(path).map_err(internal)?).map_err(internal)?;
    // NAN-3766: a first answer never replaced by its final build is served
    // as a final partial answer, never as "refining" indefinitely.
    super::detail_scan::settle_refining(&mut answer, chrono::Utc::now().timestamp_micros());
    Ok(answer)
}

/// NAN-3791: how long a consumer's own detail scan may run: one first
/// answer, newest slices first (so a rare artifact's few occurrences are
/// counted whole, and a common one's newest minutes are, with its coverage
/// saying exactly which range).
const QUICK_DETAIL_BUDGET: super::detail_scan::DetailBudget =
    super::detail_scan::DetailBudget { total: std::time::Duration::from_millis(1_500), first: std::time::Duration::from_millis(1_500),
        slice: std::time::Duration::from_millis(1_500) };
/// A consumer's quick answers are reused this long (UI polls, re-expands).
const QUICK_DETAIL_TTL: std::time::Duration = std::time::Duration::from_secs(60);
const QUICK_DETAIL_ENTRIES: usize = 256;
/// Native threads (and Parquet parsing threads) per quick detail slice.
const QUICK_DETAIL_THREADS: u64 = 2;

type QuickDetails = std::sync::Mutex<std::collections::HashMap<String, (Instant, Value)>>;
static QUICK_DETAILS: std::sync::OnceLock<QuickDetails> = std::sync::OnceLock::new();

/// A consumer's bounded in-process detail answer (never refining: nothing
/// replaces it; the coverage states the scanned range). Keyed by the full
/// request identity (tenant, artifact, window bounds, deny scope); the
/// process serves exactly one tenant.
async fn quick_detail(engine: &PartQueryEngine, request: &PrevalenceDetailRequest, from_us: i64, to_us: i64) -> QueryResult<Value> {
    let mut identity = serde_json::to_value(request).map_err(internal)?;
    if let Some(object) = identity.as_object_mut() { object.remove("request_id"); }
    let key = format!("{}|{from_us}|{to_us}|{}", engine.settings().tenant_id, identity);
    let cache = QUICK_DETAILS.get_or_init(Default::default);
    if let Some((at, answer)) = cache.lock().map_err(internal)?.get(&key) {
        if at.elapsed() < QUICK_DETAIL_TTL { return Ok(answer.clone()); }
    }
    // Bounded beside interactive search: one quick scan per process at a
    // time, on a companion admission slot, at QUICK_DETAIL_THREADS. A busy
    // process keeps answering `warming` (the UI polls) rather than queue.
    static RUNNING: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(1);
    let warming = || PartQueryError::Unavailable(super::product_state::WARMING.into());
    let Ok(_running) = RUNNING.try_acquire() else { return Err(warming()) };
    let Ok(_slot) = engine.admit_class(super::engine::RequestClass::Companion, std::time::Duration::from_millis(250)).await
    else { return Err(warming()) };
    let started = Instant::now();
    let scan = super::detail_scan::scan(engine, request, from_us, to_us, started, |_| Ok(()));
    let answer = super::detail_scan::BUDGET.scope(QUICK_DETAIL_BUDGET,
        super::detail_scan::THREAD_CAP.scope(QUICK_DETAIL_THREADS, scan)).await?;
    tracing::info!(artifact_len = request.artifact.len(), window = %request.window, wall_ms = started.elapsed().as_millis() as u64,
        complete = answer["coverage"]["complete"].as_bool(), "prevalence quick detail answered");
    let mut cache = cache.lock().map_err(internal)?;
    cache.retain(|_, (at, _)| at.elapsed() < QUICK_DETAIL_TTL);
    if cache.len() >= QUICK_DETAIL_ENTRIES {
        if let Some(oldest) = cache.iter().min_by_key(|(_, (at, _))| *at).map(|(key, _)| key.clone()) { cache.remove(&oldest); }
    }
    cache.insert(key, (Instant::now(), answer.clone()));
    Ok(answer)
}

/// The detail state file of `request` over `[from_us, to_us]` and the
/// request identity it is keyed by (`request_id` removed). Built only under
/// product-state build authority; a consumer serves product[T]'s newest
/// published detail of the same identity while it is recent (NAN-3148).
pub(super) async fn detail_state(engine: &PartQueryEngine, request: &PrevalenceDetailRequest, from_us: i64, to_us: i64) -> QueryResult<(std::path::PathBuf, String)> {
    detail_state_with(engine, request, from_us, to_us, None).await
}

/// [`detail_state`] that also sends the path of a first, partial answer to
/// `first` when the build continues past its first-answer budget (NAN-3766).
pub(super) async fn detail_state_with(engine: &PartQueryEngine, request: &PrevalenceDetailRequest, from_us: i64, to_us: i64,
    first: Option<&tokio::sync::mpsc::UnboundedSender<std::path::PathBuf>>) -> QueryResult<(std::path::PathBuf, String)> {
    let started = Instant::now();
    // Demand inbox entries must be fenced just like HTTP requests.
    if request.tenant_id != engine.settings().tenant_id {
        return Err(invalid("request tenant is not this process's tenant"));
    }
    let mut identity = serde_json::to_value(request).map_err(internal)?;
    identity.as_object_mut().unwrap().remove("request_id");
    let identity_text = identity.to_string();
    // NAN-3760: a consumer needs neither the explorer window nor an exact
    // inventory-addressed path. Read the logical published identity first,
    // without walking every part in the window on every poll.
    if super::product_publish::is_consumer(engine) {
        identity["request_id"] = json!("");
        let work = super::product_state::Work::Detail(identity.to_string(), from_us, to_us);
        if let Some((published, _)) = super::product_publish::latest(engine, &super::product_publish::detail_key(&identity_text), &work) {
            return Ok((published, identity_text));
        }
        return Err(PartQueryError::Unavailable(super::product_state::WARMING.into()));
    }
    let path = product_path(engine, "detail", from_us, to_us, &identity_text).await?;
    if path.is_file() {
        touch_product_state(engine, &path)?;
        return Ok((path, identity_text));
    }
    if !super::product_state::building() {
        let work = super::product_state::Work::Detail({ identity["request_id"] = json!(""); identity.to_string() }, from_us, to_us);
        if let Some((published, _)) = super::product_publish::latest(engine, &super::product_publish::detail_key(&identity_text), &work) {
            return Ok((published, identity_text));
        }
        super::product_state::request_at(engine, engine.identity_state_dir(), work);
        return Err(PartQueryError::Unavailable(super::product_state::WARMING.into()));
    }
    let meter = super::product_state::BuildMeter::start();
    // NAN-3766: newest-first slices within the build budget. A scan that
    // will run past the first-answer budget hands its partial answer to
    // `first` (the publisher publishes it while the walk continues).
    // NAN-3858: each slice takes the idle slot itself (ahead of background
    // window statements, boundedly); holding it here for the whole walk
    // would block both that and every window build behind it.
    let partial = path.with_extension("partial.state");
    let result = super::detail_scan::scan(engine, request, from_us, to_us, started, |answer| {
        let Some(first) = first else { return Ok(()) };
        write_state_atomically(&partial, answer)?;
        let _ = first.send(partial.clone());
        Ok(())
    }).await?;
    write_state_atomically(&path, &result)?;
    prune_product_state(engine.product_dir());
    let rows: usize = result.as_object().into_iter().flat_map(|object| object.values()).filter_map(Value::as_array).map(Vec::len).sum();
    tracing::info!(state = "prevalence_detail", rows, wall_ms = meter.wall_ms(), cpu_ms = meter.cpu_ms(),
        cpu_scope = super::product_state::CPU_SCOPE, complete = result["coverage"]["complete"].as_bool(), "product state ready");
    Ok((path, identity_text))
}

/// The explorer (summary + keyset page + 30-day heatmap) over the window
/// relation, with the reader's filters, ordering and counters.
pub async fn prevalence_explorer(engine: &PartQueryEngine, request: &PrevalenceExplorerRequest) -> QueryResult<Value> {
    engine.pinned_if_needed(prevalence_explorer_pinned(engine, request)).await?
}

async fn prevalence_explorer_pinned(engine: &PartQueryEngine, request: &PrevalenceExplorerRequest) -> QueryResult<Value> {
    if request.tenant_id != engine.settings().tenant_id {
        return Err(invalid("request tenant is not this process's tenant"));
    }
    if request.limit == 0
        || request.limit > 200
        || (request.cursor.is_none() && request.offset.saturating_add(request.limit) > 50_000)
        || (request.cursor.is_some() && request.offset != 0)
        || !matches!(request.artifact_type.as_deref(), None | Some("hash" | "domain" | "ip"))
        || !matches!(request.risk_level.as_deref(), None | Some("rare" | "new"))
        || request.search.as_ref().is_some_and(|value| value.len() > 512 || value.chars().any(char::is_control))
    {
        return Err(invalid("prevalence explorer request exceeds its bound"));
    }
    let threshold = request.rarity_threshold.unwrap_or_else(crate::prevalence::tenant_rarity_threshold);
    let (from_us, to_us) = product_bounds(&request.window, request.end.as_deref())?;
    let log_head = engine.head_json().await;
    // NAN-3148: a consumer serves product[T]'s newest published snapshot of
    // a moving window (its own anchor and history), marked stale once old.
    let published = match request.end {
        None => super::product_publish::published_window(engine, &request.window).transpose()?,
        Some(_) => None,
    };
    let (to_us, history, freshness) = match &published {
        Some(published) => (published.to_us, Some(published.history.clone()), Some(published.freshness.clone())),
        None => (to_us, None, None),
    };
    let empty = || {
        let mut answer = json!({
            "ok": true, "request_id": request.request_id, "tenant_id": request.tenant_id,
            "route": "prevalence_explorer", "source_mode": "parts", "log_head": log_head,
            "result": {"artifacts": [], "total": 0, "limit": request.limit, "offset": request.offset, "has_more": false,
                       "rarity_threshold": threshold, "rare_count": 0, "new_count": 0, "high_risk_asset_count": 0,
                       "counts_approximate": false}
        });
        if let Some(freshness) = &freshness { answer["product_state"] = freshness.clone(); }
        answer
    };
    let window_path = match &published {
        Some(published) => published.window.clone(),
        None => maintained_window_file(engine, from_us, to_us).await?,
    };
    let Some(window_path) = window_path else { return Ok(empty()) };
    let relation = file_relation(&window_path);
    let mut params = relation.params.clone();
    let scope = scope_filter(&request.deny_source_types, &mut params)?;
    params.push(("threshold".to_string(), threshold.to_string()));
    params.push(("limit".to_string(), request.limit.saturating_add(1).to_string()));
    params.push(("offset".to_string(), request.offset.to_string()));
    let mut predicates = vec![scope];
    if let Some(kind) = &request.artifact_type {
        predicates.push("kind = {artifact_type:String}".to_string());
        params.push(("artifact_type".to_string(), kind.clone()));
    }
    if let Some(search) = &request.search {
        predicates.push("positionCaseInsensitiveUTF8(entity, {search:String}) > 0".to_string());
        params.push(("search".to_string(), search.clone()));
    }
    let mut filtered = Vec::new();
    match request.risk_level.as_deref() {
        Some("rare") => filtered.push("host_count < {threshold:UInt64} AND saturated = 0".to_string()),
        Some("new") => filtered.push("first_seen >= now64(6) - INTERVAL 24 HOUR".to_string()),
        _ => {}
    }
    if let Some(since) = &request.first_seen_since {
        chrono::DateTime::parse_from_rfc3339(since).map_err(|_| invalid("prevalence first-seen boundary must be RFC3339"))?;
        filtered.push("first_seen >= parseDateTime64BestEffort({first_seen_since:String}, 6)".to_string());
        params.push(("first_seen_since".to_string(), since.clone()));
    }
    let filtered_sql = filtered.iter().map(|clause| format!(" AND {clause}")).collect::<String>();
    let cursor_sql = if let Some(cursor) = &request.cursor {
        // NAN-3802: RFC 3339 or the legacy pre-NAN-3802 text form.
        let cursor = cursor.validated().ok_or_else(|| invalid("prevalence explorer cursor is invalid"))?;
        params.extend([
            ("cursor_last_seen".to_string(), cursor.last_seen.clone()),
            ("cursor_kind".to_string(), cursor.kind.clone()),
            ("cursor_artifact".to_string(), cursor.artifact.clone()),
        ]);
        " WHERE last_seen < parseDateTime64BestEffort({cursor_last_seen:String}, 6, 'UTC') \
           OR (last_seen = parseDateTime64BestEffort({cursor_last_seen:String}, 6, 'UTC') \
               AND (kind > {cursor_kind:String} OR (kind = {cursor_kind:String} AND entity > {cursor_artifact:String})))"
    } else {
        ""
    };
    let scan_started = Instant::now();
    // NAN-3791: the maintained unscoped aggregate answers exactly whenever
    // none of the window's rows is in a scope this viewer is denied.
    let explorer = explorer_path(&window_path);
    let served_from_state = explorer.is_file()
        && (request.deny_source_types.is_empty() || !denied_scope_present(engine, &relation, &request.deny_source_types).await?);
    let (summary, rows) = if served_from_state {
        // predicates[0] is the scope filter (pushed first above); the state
        // path drops it, having proved no denied scope is in the window.
        explorer_from_state(engine, &explorer, &predicates[1..], &filtered_sql, cursor_sql, params).await?
    } else {
        explorer_from_window(engine, &relation, &predicates, &filtered_sql, cursor_sql, request, params).await?
    };
    let scan_ms = scan_started.elapsed().as_millis() as u64;
    let has_more = rows.len() > request.limit as usize;
    let mut rows = rows;
    rows.truncate(request.limit as usize);
    let next_cursor = if has_more {
        rows.last().map(explorer_next_cursor)
    } else {
        None
    };
    let mut artifacts = Vec::with_capacity(rows.len());
    for row in &rows {
        let kind = row["kind"].as_str().unwrap_or_default();
        let entity = row["entity"].as_str().unwrap_or_default();
        let result = crate::prevalence::prevalence_result(
            kind,
            entity,
            json_u64(&row["host_count"]),
            json_u64(&row["saturated"]) != 0,
            json_u64(&row["private"]) != 0,
            json_i64(&row["first_us"]),
            json_i64(&row["last_us"]),
            json_u64(&row["total_occurrences"]),
            threshold,
        )
        .map_err(internal)?;
        artifacts.push(serde_json::to_value(result).map_err(internal)?);
    }
    let history_started = Instant::now();
    attach_daily_history(engine, to_us, history, &request.deny_source_types, &mut artifacts, &rows).await?;
    tracing::debug!(scan_ms, history_ms = history_started.elapsed().as_millis() as u64,
        published = published.is_some(), served_from_state, "prevalence explorer phases");
    let mut answer = json!({
        "ok": true,
        "request_id": request.request_id,
        "tenant_id": request.tenant_id,
        "route": "prevalence_explorer",
        "source_mode": "parts",
        "log_head": log_head,
        "result": {
            "artifacts": artifacts,
            "total": json_u64(&summary["total"]),
            "limit": request.limit,
            "offset": request.offset,
            "has_more": has_more,
            "next_cursor": next_cursor,
            "rarity_threshold": threshold,
            "rare_count": json_u64(&summary["rare_count"]),
            "new_count": json_u64(&summary["new_count"]),
            "high_risk_asset_count": json_u64(&summary["high_risk_asset_count"]),
            "counts_approximate": false,
        }
    });
    if let Some(freshness) = freshness { answer["product_state"] = freshness; }
    Ok(answer)
}

/// The explorer's summary counters over the filtered aggregate `filtered`
/// (a relation alias in scope). Shared by both explorer sources.
const EXPLORER_COUNTERS: &str = "count() AS total, \
     countIf(host_count < {threshold:UInt64} AND saturated = 0) AS rare_count, \
     countIf(first_seen >= now64(6) - INTERVAL 24 HOUR) AS new_count, \
     countIf(host_count < {threshold:UInt64} AND saturated = 0 AND last_seen >= now64(6) - INTERVAL 24 HOUR) AS high_risk_asset_count";

/// Whether any row of the window is in one of `deny`'s scopes (then the
/// unscoped explorer state would count rows this viewer may not see).
/// Reads only the window's `scope` column and stops at the first match.
async fn denied_scope_present(engine: &PartQueryEngine, relation: &WindowRelation, deny: &[String]) -> QueryResult<bool> {
    let mut params = relation.params.clone();
    let scope = scope_filter(deny, &mut params)?;
    let sql = format!("SELECT 1 AS denied FROM ({}) WHERE NOT ({scope}) LIMIT 1{}", relation.sql, settings(engine));
    Ok(!engine.execute_sql(sql, params).await?.is_empty())
}

/// NAN-3791: summary and page from the maintained explorer state: two
/// bounded statements over one `(kind, entity)` row per artifact, the page
/// a top-k in the state's own order. `predicates` are the request's
/// kind/search filters (the scope filter is not needed: the caller proved
/// no denied scope is in the window).
async fn explorer_from_state(
    engine: &PartQueryEngine,
    explorer: &std::path::Path,
    predicates: &[String],
    filtered_sql: &str,
    cursor_sql: &str,
    mut params: Vec<(String, String)>,
) -> QueryResult<(Value, Vec<Value>)> {
    params.push(("explorer_state".into(), explorer.to_string_lossy().into_owned()));
    let mut filters = predicates.to_vec();
    filters.insert(0, "1 = 1".into());
    let filtered = format!("SELECT * FROM file({{explorer_state:String}}, Parquet) WHERE {}{filtered_sql}", filters.join(" AND "));
    let counts_sql = format!("SELECT {EXPLORER_COUNTERS} FROM ({filtered}){}", settings(engine));
    let summary = engine.execute_sql(counts_sql, params.clone()).await?.into_iter().next().unwrap_or(Value::Null);
    let page_sql = format!(
        "SELECT kind, entity, host_count, saturated, private, toUnixTimestamp64Micro(first_seen) AS first_us, \
                toUnixTimestamp64Micro(last_seen) AS last_us, \
                formatDateTime(last_seen, '%Y-%m-%d %H:%i:%S.%f', 'UTC') AS last_seen_text, total_occurrences \
         FROM ({filtered}){cursor_sql} \
         ORDER BY -toUnixTimestamp64Micro(last_seen), kind, entity LIMIT {{limit:UInt64}} OFFSET {{offset:UInt64}}{}",
        settings(engine)
    );
    let rows = engine.execute_sql(page_sql, params).await?;
    Ok((summary, rows))
}

/// The per-request explorer: the cross-scope aggregate of the window's
/// per-scope rows under the viewer's scope filter (NAN-3760: summary and
/// page share one snapshot scan/host union).
async fn explorer_from_window(
    engine: &PartQueryEngine,
    relation: &WindowRelation,
    predicates: &[String],
    filtered_sql: &str,
    cursor_sql: &str,
    request: &PrevalenceExplorerRequest,
    mut params: Vec<(String, String)>,
) -> QueryResult<(Value, Vec<Value>)> {
    // Cross-scope explorer aggregation (the reader's `explorer_aggregate_sql`).
    let aggregated = explorer_aggregate_sql(&relation.sql, &predicates.join(" AND "));
    // NAN-3760: summary and page share one snapshot scan/host union. A
    // bounded sorted aggregate retains only offset + limit + 1 tuples, so
    // unlike window counters it never buffers the full artifact inventory.
    // Negated event microseconds encode last_seen DESC; kind/entity remain
    // ascending, exactly as the public keyset cursor orders them.
    let page_predicate = if request.cursor.is_some() { cursor_sql.trim().trim_start_matches("WHERE ") } else { "1" };
    params.push(("page_capacity".into(), request.offset.saturating_add(request.limit).saturating_add(1).to_string()));
    params.push(("page_start".into(), request.offset.saturating_add(1).to_string()));
    let page_sql = format!(
        "WITH aggregated AS ({aggregated}), filtered AS (SELECT * FROM aggregated WHERE 1 = 1{filtered_sql}) \
         SELECT {EXPLORER_COUNTERS}, \
              arraySlice(groupArraySortedIf({{page_capacity:UInt64}})(tuple(-toUnixTimestamp64Micro(last_seen), kind, entity, \
                  host_count, saturated, private, toUnixTimestamp64Micro(first_seen), toUnixTimestamp64Micro(last_seen), \
                  formatDateTime(last_seen, '%Y-%m-%d %H:%i:%S.%f', 'UTC'), total_occurrences), {page_predicate}), \
                  {{page_start:UInt64}}, {{limit:UInt64}}) AS page_rows \
         FROM filtered{}",
        settings(engine)
    );
    let output = engine.execute_sql(page_sql, params).await?;
    let summary = output.first().cloned().unwrap_or(Value::Null);
    let rows = summary["page_rows"].as_array().ok_or_else(|| internal("explorer page is malformed"))?
        .iter().map(|row| {
            let values = row.as_array().filter(|values| values.len() == 10).ok_or_else(|| internal("explorer page tuple is malformed"))?;
            Ok(json!({"kind": values[1], "entity": values[2], "host_count": values[3], "saturated": values[4],
                "private": values[5], "first_us": values[6], "last_us": values[7], "last_seen_text": values[8], "total_occurrences": values[9]}))
        }).collect::<QueryResult<Vec<Value>>>()?;
    Ok((summary, rows))
}

/// The fixed 30-day heatmap: per-day `daily_count` straight from the
/// partials (their `day` key), across scopes.
/// `published`: the history file product[T] published with the window
/// (NAN-3148); `None` builds/reads it in-process.
async fn attach_daily_history(
    engine: &PartQueryEngine,
    end_us: i64,
    published: Option<Option<std::path::PathBuf>>,
    deny: &[String],
    artifacts: &mut [Value],
    rows: &[Value],
) -> QueryResult<()> {
    if artifacts.is_empty() {
        return Ok(());
    }
    const DAY_US: i64 = 86_400_000_000;
    let end_day = end_us.div_euclid(DAY_US);
    let start_day = end_day - 29;
    let paths = match published {
        Some(history) => history.into_iter().collect::<Vec<_>>(),
        None => history_state(engine, end_us).await?.into_iter().collect(),
    };
    let mut counts = vec![vec![0_u64; 30]; artifacts.len()];
    if !paths.is_empty() {
        let mut params = vec![("history".to_string(), path_set(&paths)?)];
        let scope = scope_filter(deny, &mut params)?;
        params.push(("kinds".to_string(), sql_string_array(rows.iter().map(|row| row["kind"].as_str().unwrap_or_default()))));
        params.push(("entities".to_string(), sql_string_array(rows.iter().map(|row| row["entity"].as_str().unwrap_or_default()))));
        params.push(("start_day".to_string(), start_day.to_string()));
        let sql = format!(
            "SELECT kind, entity, toInt64(toUInt32(day)) AS day_number, sum(daily_count) AS daily_count \
             FROM file({{history:String}}, Parquet) \
             WHERE has({{entities:Array(String)}}, entity) AND {scope} AND toInt64(toUInt32(day)) >= {{start_day:Int64}} AND (kind, entity) IN \
                   (SELECT tupleElement(pair, 1), tupleElement(pair, 2) FROM (SELECT arrayJoin(arrayZip({{kinds:Array(String)}}, {{entities:Array(String)}})) AS pair)) \
             GROUP BY kind, entity, day_number{}",
            settings(engine)
        );
        for row in engine.execute_sql(sql, params).await? {
            let day = json_i64(&row["day_number"]) - start_day;
            if !(0..30).contains(&day) {
                continue;
            }
            if let Some(index) = rows.iter().position(|candidate| candidate["kind"] == row["kind"] && candidate["entity"] == row["entity"]) {
                counts[index][day as usize] += json_u64(&row["daily_count"]);
            }
        }
    }
    let daily_start = chrono::DateTime::<chrono::Utc>::from_timestamp_micros(start_day * DAY_US)
        .map(|time| time.format("%Y-%m-%d").to_string())
        .unwrap_or_default();
    for (artifact, counts) in artifacts.iter_mut().zip(counts) {
        if let Some(object) = artifact.as_object_mut() {
            object.insert("daily_counts".to_string(), json!(counts));
            object.insert("daily_start".to_string(), json!(daily_start));
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Durable rare-artifact export (NAN-3088)
// ---------------------------------------------------------------------------

/// One durable prevalence export statement, holding the leases of every part
/// file its relation reads until it has executed.
pub(super) struct PrevalenceExportStatement {
    pub sql: String,
    pub params: Vec<(String, String)>,
    _leases: Vec<super::fetch::LocalParts>,
}

/// The durable rare-artifact export over `[from_us, to_us]`: the window
/// relation `| prevalence` reads (the partials of every overlapping part,
/// edges event-hour aligned per NAN-3161, with `from_us` a hard floor: the
/// admitted start is the job's retention cutoff, so a part straddling it is
/// left out rather than counted before it), aggregated across the
/// caller's allowed scopes, cut to the artifacts under the rarity threshold
/// and `max_prevalence`, spooled by chDB to Parquet at
/// `{job_result_output:String}` (bound by the caller) in the gen1 export's
/// column shape. `first_seen` / `last_seen` are RFC3339 strings, so every
/// page reader (download, rare list) sees one spelling. `max_rows + 1` rows
/// are written so the commit can flag truncation.
///
/// `None` when the window holds no parts.
#[allow(clippy::too_many_arguments)]
pub(super) async fn prevalence_export_statement(
    engine: &PartQueryEngine,
    from_us: i64,
    to_us: i64,
    artifact_type: Option<&str>,
    max_prevalence: u64,
    threshold: u64,
    deny_source_types: &[String],
    max_rows: usize,
    read_budget_bytes: u64,
) -> QueryResult<Option<PrevalenceExportStatement>> {
    if from_us >= to_us
        || max_rows == 0
        || !matches!(artifact_type, None | Some("hash" | "domain" | "ip"))
    {
        return Err(invalid("prevalence export request exceeds its bound"));
    }
    let Some(relation) = prevalence_window(engine, from_us, to_us, Some(from_us), WindowScope::AllEntities).await? else { return Ok(None) };
    let mut params = relation.params.clone();
    let mut predicates = vec![scope_filter(deny_source_types, &mut params)?];
    if let Some(kind) = artifact_type {
        predicates.push("kind = {artifact_type:String}".to_string());
        params.push(("artifact_type".to_string(), kind.to_string()));
    }
    params.push(("threshold".to_string(), threshold.max(1).to_string()));
    params.push(("max_prevalence".to_string(), max_prevalence.to_string()));
    params.push(("export_rows".to_string(), max_rows.saturating_add(1).to_string()));
    // The explorer's cross-scope aggregation, with the gen1 export's filters,
    // column shape, scoring and order.
    let sql = format!(
        "INSERT INTO FUNCTION file({{job_result_output:String}}, Parquet) \
         WITH aggregated AS (\
           SELECT kind, entity, uniqExactArray(host_fingerprints) AS agg_hosts, \
                  max(toUInt8(host_count_saturated)) AS agg_saturated, max(toUInt8(is_private)) AS agg_private, \
                  min(first_seen) AS agg_first, max(last_seen) AS agg_last, \
                  sum(total_occurrences) AS agg_total \
           FROM ({}) WHERE {} GROUP BY kind, entity\
         ), filtered AS (\
           SELECT * FROM aggregated \
           WHERE agg_saturated = 0 AND agg_hosts < 1000 AND agg_hosts < {{threshold:UInt64}} \
             AND agg_hosts <= {{max_prevalence:UInt64}}\
         ) SELECT entity AS artifact, \
                  multiIf(\
                    kind = 'hash' AND length(entity) = 32, 'hash_md5', \
                    kind = 'hash', 'hash_sha256', \
                    kind = 'domain' AND length(splitByChar('.', entity)) > 2, 'subdomain', \
                    kind = 'domain', 'domain', \
                    agg_private != 0, 'ip_address_private', 'ip_address'\
                  ) AS artifact_type, \
                  toUInt64(agg_hosts) AS host_count, toUInt64(agg_total) AS total_occurrences, \
                  formatDateTime(agg_first, '%Y-%m-%dT%H:%i:%S.%fZ', 'UTC') AS first_seen, \
                  formatDateTime(agg_last, '%Y-%m-%dT%H:%i:%S.%fZ', 'UTC') AS last_seen, \
                  CAST(1 AS Bool) AS is_rare, \
                  toUInt8(round(least(20.0, toFloat64(agg_hosts) / toFloat64({{threshold:UInt64}}) * 20.0))) AS prevalence_score \
           FROM filtered ORDER BY agg_hosts ASC, agg_last DESC, entity ASC \
           LIMIT {{export_rows:UInt64}}{}, output_format_parquet_compression_method='zstd'",
        relation.sql,
        predicates.join(" AND "),
        // The job lane's statement cap (NAN-3077), like every durable read.
        statement_settings_within(engine, read_budget_bytes, engine.job_memory_bytes()),
    );
    Ok(Some(PrevalenceExportStatement { sql, params, _leases: relation._leases }))
}

// ---------------------------------------------------------------------------
// Entity ranges
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EntityRangesRequest {
    pub request_id: String,
    pub tenant_id: String,
    /// An identity path with entity-range rows
    /// (`crate::parts::format::ENTITY_RANGE_PATHS`).
    pub path: String,
    pub values: Vec<String>,
    pub start: String,
    pub end: String,
    /// Case-insensitive value match (nPL semantics). Default true.
    #[serde(default = "default_true")]
    pub case_insensitive: bool,
}

fn default_true() -> bool {
    true
}

/// Inside-window parts answer from their partial alone, so only a path whose
/// rows every part carries may be asked (NAN-3694: not the later `BLOOM_PATHS`
/// additions), with bounded, non-empty values.
fn entity_range_request_in_bounds(request: &EntityRangesRequest) -> bool {
    crate::parts::format::ENTITY_RANGE_PATHS.contains(&request.path.as_str())
        && request.path != crate::parts::format::UID_PATH
        && !request.values.is_empty()
        && request.values.len() <= 1_000
        && request.values.iter().all(|value| !value.is_empty() && value.len() <= 2_048 && !value.chars().any(char::is_control))
}

/// When was each value active: `first_time`, `last_time`, `events` over the
/// window. Parts inside the window answer from `entity_ranges.parquet`;
/// straddling parts answer from their rows (exact at the edges).
pub async fn entity_ranges(engine: &PartQueryEngine, request: &EntityRangesRequest) -> QueryResult<Value> {
    if request.tenant_id != engine.settings().tenant_id {
        return Err(invalid("request tenant is not this process's tenant"));
    }
    if !entity_range_request_in_bounds(request) {
        return Err(invalid("entity range request violates its path or value bound"));
    }
    let (from_us, to_us) = (rfc3339_us(&request.start)?, rfc3339_us(&request.end)?);
    if from_us > to_us {
        return Err(invalid("entity range window is reversed"));
    }
    let (parts, read_schema, _, _) = engine.snapshot(from_us, to_us).await?;
    let (inside, edges) = split_inside(parts, from_us, to_us);
    let fold = if request.case_insensitive { "lower" } else { "" };
    let mut params = vec![
        ("entity_path".to_string(), request.path.clone()),
        ("entity_values".to_string(), sql_string_array(request.values.iter().map(|value| value.as_str()))),
        ("window_start_us".to_string(), from_us.to_string()),
        ("window_end_us".to_string(), to_us.to_string()),
    ];
    let mut arms = Vec::new();
    let mut leases: Vec<Box<dyn std::any::Any + Send>> = Vec::new();
    if !inside.is_empty() {
        let local = engine
            .fetcher()
            .ensure(&inside, &[FileSet::Partial(PartialKind::EntityRanges)])
            .await
            .map_err(|error| internal(format!("{error:#}")))?;
        let paths = local.of(FileSet::Partial(PartialKind::EntityRanges)).map(|file| file.path.clone()).collect::<Vec<_>>();
        if !paths.is_empty() {
            params.push(("entity_partials".to_string(), path_set(&paths)?));
            arms.push(format!(
                "SELECT {fold}(value) AS entity, toUnixTimestamp64Micro(first_time) AS first_us, \
                        toUnixTimestamp64Micro(last_time) AS last_us, events \
                 FROM file({{entity_partials:String}}, Parquet) \
                 WHERE path = {{entity_path:String}} AND has(arrayMap(v -> {fold}(v), {{entity_values:Array(String)}}), {fold}(value))"
            ));
        }
        leases.push(Box::new(local));
    }
    if !edges.is_empty() {
        let local = engine.fetcher().ensure(&edges, &[FileSet::AllData]).await.map_err(|error| internal(format!("{error:#}")))?;
        let edge_objects = local.of(FileSet::AllData).map(|file| file.path.clone()).collect::<Vec<_>>();
        if !edge_objects.is_empty() {
            let schema = crate::iceberg::clickhouse_read_schema(&read_schema).map_err(internal)?;
            params.push(("edge_source".to_string(), path_set(&edge_objects)?));
            params.push(("edge_schema".to_string(), schema));
            let column = request.path.split('.').map(|segment| format!("`{segment}`")).collect::<Vec<_>>().join(".");
            arms.push(format!(
                "SELECT {fold}(toString({column})) AS entity, toUnixTimestamp64Micro(min(time)) AS first_us, \
                        toUnixTimestamp64Micro(max(time)) AS last_us, count() AS events \
                 FROM file({{edge_source:String}}, Parquet, {{edge_schema:String}}) \
                 WHERE toUnixTimestamp64Micro(time) >= {{window_start_us:Int64}} AND toUnixTimestamp64Micro(time) <= {{window_end_us:Int64}} \
                   AND isNotNull({column}) AND has(arrayMap(v -> {fold}(v), {{entity_values:Array(String)}}), {fold}(toString({column}))) \
                 GROUP BY entity"
            ));
        }
        leases.push(Box::new(local));
    }
    let rows = if arms.is_empty() {
        Vec::new()
    } else {
        let sql = format!(
            "SELECT entity, min(first_us) AS first_us, max(last_us) AS last_us, sum(events) AS events \
             FROM ({}) GROUP BY entity ORDER BY entity{}",
            arms.join(" UNION ALL "),
            settings(engine)
        );
        engine.execute_sql(sql, params).await?
    };
    drop(leases);
    Ok(json!({
        "ok": true,
        "request_id": request.request_id,
        "tenant_id": request.tenant_id,
        "route": "entity_ranges",
        "source_mode": "parts",
        "path": request.path,
        "result": { "result_rows": rows.len(), "rows": rows }
    }))
}

#[cfg(test)]
mod nan3068_lookup_tests {
    use super::*;

    #[test]
    fn entity_ranges_refuse_paths_without_range_rows() {
        let request = |path: &str| EntityRangesRequest {
            request_id: "r".into(),
            tenant_id: "t".into(),
            path: path.into(),
            values: vec!["10.1.4.63".into()],
            start: "2026-10-01T00:00:00Z".into(),
            end: "2026-10-02T00:00:00Z".into(),
            case_insensitive: true,
        };
        assert!(entity_range_request_in_bounds(&request("src_endpoint.ip")));
        assert!(entity_range_request_in_bounds(&request("actor.user.name")));
        // Blooms but no range rows (NAN-3694); uid never.
        for path in ["device.ip", "device.uid", "user.email_addr", "actor.user.email_addr", "actor.process.user.name", "metadata.uid"] {
            assert!(!entity_range_request_in_bounds(&request(path)), "{path}");
        }
        let mut empty = request("src_endpoint.ip");
        empty.values = vec![String::new()];
        assert!(!entity_range_request_in_bounds(&empty));
    }

    #[test]
    fn lookup_relation_filters_inside_every_arm_and_explorer_does_not() {
        let lookup = partial_arm_sql(&WindowScope::LookupOnly.arm_filter());
        assert!(lookup.contains(LOOKUP_FILTER), "{lookup}");
        assert!(lookup.contains("{prevalence_partials:String}"));
        assert!(lookup.ends_with(&format!("WHERE host_cap = 1000 AND {LOOKUP_FILTER}")));
        let explorer = partial_arm_sql(&WindowScope::AllEntities.arm_filter());
        assert!(!explorer.contains("lookup_entities"));
        assert!(explorer.ends_with("WHERE host_cap = 1000"));
    }

    #[test]
    fn lookup_statement_applies_scope_once_and_no_second_lookup_join() {
        let sql = lookup_statement_sql("SELECT 1", "1 = 1", " SETTINGS max_threads=1");
        assert!(sql.contains("FROM (SELECT 1) WHERE 1 = 1"));
        assert!(!sql.contains("lookup_entities"), "the lookup filter lives in the arms: {sql}");
        assert!(sql.ends_with("GROUP BY kind, entity SETTINGS max_threads=1"));
    }

    #[test]
    fn a_full_request_is_one_statement() {
        // The request cap in `prevalence_lookup_bounds` is 10,000 artifacts.
        const { assert!(PREVALENCE_LOOKUP_BATCH >= 10_000) };
    }

    #[test]
    fn results_come_back_in_request_order() {
        let order = vec![
            ("ip".to_string(), "10.0.0.3".to_string()),
            ("domain".to_string(), "b.example".to_string()),
            ("ip".to_string(), "10.0.0.1".to_string()),
            ("ip".to_string(), "10.0.0.3".to_string()),
        ];
        let result = |kind: &str, entity: &str| crate::prevalence::prevalence_result(kind, entity, 1, false, false, 0, 0, 1, 5).unwrap();
        let mut results = vec![result("ip", "10.0.0.1"), result("domain", "b.example"), result("ip", "10.0.0.3")];
        order_by_request(&mut results, &order);
        let got: Vec<&str> = results.iter().map(|r| r.artifact.as_str()).collect();
        assert_eq!(got, ["10.0.0.3", "b.example", "10.0.0.1"]);
    }
}

#[cfg(test)]
mod nan3161_tests {
    use super::*;

    fn covered(blocks: &[(u32, i64)]) -> Vec<i64> {
        blocks.iter().flat_map(|(level, index)| (index << level)..((index + 1) << level)).collect()
    }

    #[test]
    fn day_blocks_tile_the_span_once_with_aligned_power_of_two_blocks() {
        for first in 19_990_i64..20_030 {
            for last in first..first + 40 {
                let blocks = day_blocks(first, last);
                assert_eq!(covered(&blocks), (first..=last).collect::<Vec<_>>(), "{first}..={last}");
                for (level, index) in &blocks {
                    assert!(*level <= 5);
                    assert_eq!((index << level).rem_euclid(1 << level), 0);
                }
                // A 30-day span never needs more than ~2·log2(30) blocks.
                assert!(blocks.len() <= 10, "{first}..={last}: {blocks:?}");
            }
        }
    }

    #[test]
    fn a_sliding_month_reuses_all_but_a_few_blocks_per_day() {
        // Aligned blocks are global and a wide block is built from its two
        // halves, so every block tomorrow's decomposition needs was already
        // built (it or an ancestor was in today's), except the new day.
        let built_under = |(level, index): (u32, i64), (top, top_index): (u32, i64)| level <= top && index >> (top - level) == top_index;
        for start in 20_000_i64..20_040 {
            let today = day_blocks(start, start + 29);
            let tomorrow = day_blocks(start + 1, start + 30);
            let new = tomorrow.iter().filter(|block| !today.iter().any(|top| built_under(**block, *top))).collect::<Vec<_>>();
            assert!(new.iter().all(|(level, index)| (index << level) <= start + 30 && ((index + 1) << level) > start + 30),
                "only blocks holding the new day are new: {today:?} -> {tomorrow:?}");
            assert!(new.len() <= 1, "{new:?}");
        }
    }

    fn part(level: crate::parts::levels::Level, event_hour: i32) -> PartRef {
        PartRef {
            part_id: crate::parts::format::PartId::parse(&format!("{:013}-{:016x}", 1_700_000_000_000_i64, event_hour as u64)).unwrap(),
            level,
            event_hour,
            event_day: (level == crate::parts::levels::Level::Day).then(|| event_hour.div_euclid(24)),
            rows: 1,
            min_time_us: i64::from(event_hour) * 3_600_000_000,
            max_time_us: i64::from(event_hour) * 3_600_000_000 + 1,
            schema_fingerprint: "0".repeat(64),
            provenance_sha256: "0".repeat(64),
            merkle_root: "0".repeat(64),
            sorted: true,
            data_bytes: 1,
            row_groups: 1,
            data_files: 1,
        }
    }

    #[test]
    fn every_part_files_under_one_event_hour() {
        use crate::parts::levels::Level;
        for level in [Level::L0, Level::Minute, Level::Hour] {
            assert_eq!(leaf_hour(&part(level, 480_013)), 480_013);
        }
        // A day part (ingest.day_merges) carries day-granular rows: it files
        // under its day's first hour, so a window widens to the whole day.
        assert_eq!(leaf_hour(&part(Level::Day, 480_000)), 480_000);
        assert_eq!(hour_range(&[part(Level::L0, 480_013), part(Level::Day, 480_024), part(Level::Hour, 480_002)]), (480_002, 480_024));
    }

    /// NAN-3279: a stepwise fold's ranges tile every bucket exactly once, one
    /// step per `step_bytes` of input, never more steps than buckets.
    #[test]
    fn fold_steps_tile_every_bucket_once_sized_by_input() {
        for (input, step, steps) in [(0, 128, 1), (1, 128, 1), (128, 128, 1), (129, 128, 2), (5_700, 177, 33),
                                     (u64::MAX, 1, STATE_BUCKETS as usize), (10, 0, 10)] {
            let ranges = step_ranges(input, step);
            assert_eq!(ranges.len(), steps, "{input} bytes / {step}");
            assert_eq!(ranges.first().unwrap().0, 0);
            assert_eq!(ranges.last().unwrap().1, STATE_BUCKETS);
            for pair in ranges.windows(2) {
                assert_eq!(pair[0].1, pair[1].0, "contiguous, disjoint");
            }
            assert!(ranges.iter().all(|(lo, hi)| lo < hi), "no empty step");
        }
        // The bucket expression is what the ranges partition.
        assert!(BUCKET_SQL.ends_with("% 256)") && STATE_BUCKETS == 256);
    }

    /// NAN-3279: leaves are aligned hour groups within a day; every part in
    /// exactly one; sliding a window edge by an hour changes one leaf.
    #[test]
    fn leaves_are_aligned_hour_groups_inside_a_day() {
        use crate::parts::levels::Level;
        let day = 20_000 * 24;
        let parts = (day - 3..day + 30).map(|hour| part(Level::L0, hour)).collect::<Vec<_>>();
        let groups = leaf_groups(&parts, 4);
        let flat = groups.iter().flatten().map(|part| part.event_hour).collect::<Vec<_>>();
        assert_eq!(flat, parts.iter().map(|part| part.event_hour).collect::<Vec<_>>(), "each part once, in hour order");
        for group in &groups {
            let (lo, hi) = hour_range(group);
            assert_eq!(lo.div_euclid(4), hi.div_euclid(4), "one aligned group");
            assert_eq!(lo.div_euclid(24), hi.div_euclid(24), "never across midnight");
        }
        assert_eq!(groups[0].len(), 3, "the ragged edge before midnight");
        // The window slides by an hour: only the edge leaf changes.
        let slid = leaf_groups(&parts[1..], 4);
        assert_eq!(slid.len(), groups.len());
        assert_ne!(slid[0], groups[0]);
        assert_eq!(slid[1..], groups[1..]);
        // A whole day in one leaf (24) and an hour per leaf (1).
        assert_eq!(leaf_groups(&parts[3..27], 24).len(), 1);
        assert_eq!(leaf_groups(&parts, 1).len(), parts.len());
        // A day part files under its day's first hour, in that day's first leaf.
        let mixed = [part(Level::Day, day), part(Level::L0, day + 2), part(Level::L0, day + 5)];
        assert_eq!(leaf_groups(&mixed, 4).iter().map(Vec::len).collect::<Vec<_>>(), vec![2, 1]);
    }
}

// Moving product windows share a one-minute snapshot. Explicit historical
// anchors retain their exact bounds. New parts always invalidate the snapshot.
fn product_bounds(window: &str, end: Option<&str>) -> QueryResult<(i64, i64)> {
    let (from, to) = window_bounds(window, end)?;
    if end.is_some() {
        return Ok((from, to));
    }
    let anchor = to.div_euclid(60_000_000) * 60_000_000;
    Ok((anchor - (to - from), anchor))
}

/// The minute-anchored bounds of a moving product window (NAN-3148: what
/// product[T] builds each cycle).
pub(super) fn moving_bounds(window: &str) -> QueryResult<(i64, i64)> {
    product_bounds(window, None)
}

/// The fixed 30-day history state ending at `to_us` (`None`: no parts).
async fn history_state(engine: &PartQueryEngine, to_us: i64) -> QueryResult<Option<std::path::PathBuf>> {
    const DAY_US: i64 = 86_400_000_000;
    let start = (to_us.div_euclid(DAY_US) - 29) * DAY_US;
    let (parts, _, _, _) = engine.snapshot(start, to_us).await?;
    if parts.is_empty() { return Ok(None); }
    Ok(Some(maintained_history(engine, &parts).await?))
}

/// A published window state as a relation.
fn file_relation(path: &std::path::Path) -> WindowRelation {
    WindowRelation {
        sql: "SELECT * FROM file({product_window:String}, Parquet)".into(),
        params: vec![("product_window".into(), path.to_string_lossy().into_owned())],
        _leases: Vec::new(),
        state: None,
    }
}

/// A window's state file (`None`: the window held no parts) and the 30-day
/// history at its anchor: what product[T] publishes per window (NAN-3148).
pub(super) async fn window_state(engine: &PartQueryEngine, from: i64, to: i64) -> QueryResult<(Option<std::path::PathBuf>, Option<std::path::PathBuf>)> {
    super::fetch::prevalence_path(async {
        let window = maintained_window_file(engine, from, to).await?;
        let history = history_state(engine, to).await?;
        Ok((window, history))
    })
    .await
}

async fn product_path(
    engine: &PartQueryEngine,
    name: &str,
    from: i64,
    to: i64,
    extra: &str,
) -> QueryResult<std::path::PathBuf> {
    use sha2::{Digest, Sha256};
    let (parts, _, _, _) = engine.snapshot(from, to).await?;
    let mut identities = parts
        .iter()
        .map(serde_json::to_vec)
        .collect::<Result<Vec<_>, _>>()
        .map_err(internal)?;
    identities.sort();
    let mut hash = Sha256::new();
    hash.update(from.to_le_bytes());
    hash.update(to.to_le_bytes());
    hash.update(extra.as_bytes());
    for identity in identities {
        hash.update((identity.len() as u64).to_le_bytes());
        hash.update(identity);
    }
    Ok(engine.product_dir().join(format!(
        "product-{name}-{}.state",
        hex::encode(hash.finalize())
    )))
}

/// Materialize the window state in the background, never on a viewer's
/// request. The completed relation is atomically published for bounded reads.
pub(super) async fn maintained_window(
    engine: &PartQueryEngine,
    from: i64,
    to: i64,
) -> QueryResult<Option<WindowRelation>> {
    Ok(maintained_window_file(engine, from, to).await?.map(|path| file_relation(&path)))
}

async fn maintained_window_file(
    engine: &PartQueryEngine,
    from: i64,
    to: i64,
) -> QueryResult<Option<std::path::PathBuf>> {
    let path = product_path(engine, "window", from, to, "").await?;
    if path.with_extension("empty").is_file() {
        touch_product_state(engine, &path.with_extension("empty"))?;
        return Ok(None);
    }
    if !path.is_file() {
        if !super::product_state::building() {
            super::product_state::request_at(
                engine,
                engine.identity_state_dir(),
                super::product_state::Work::Window(from, to),
            );
            return Err(PartQueryError::Unavailable(
                super::product_state::WARMING.into(),
            ));
        }
        let meter = super::product_state::BuildMeter::start();
        let threads = super::product_state::statement_threads(engine.settings().threads);
        let Some(relation) = prevalence_window(engine, from, to, None, WindowScope::AllEntities).await?
        else {
            std::fs::write(path.with_extension("empty"), []).map_err(internal)?;
            prune_product_state(engine.product_dir());
            tracing::info!(
                state = "prevalence",
                window_hours = (to - from) / 3_600_000_000,
                rows = 0_u64,
                wall_ms = meter.wall_ms(),
                cpu_ms = meter.cpu_ms(),
                cpu_scope = super::product_state::CPU_SCOPE,
                threads,
                "product state ready"
            );
            return Ok(None);
        };
        let temporary = path.with_extension(format!("{}.tmp", uuid::Uuid::new_v4().simple()));
        match relation.state {
            // NAN-3161: the maintained state already is the window file's
            // exact row shape; link it rather than re-aggregating it.
            Some(state) if std::fs::hard_link(&state, &temporary).is_ok() => {}
            _ => {
                let _slot = super::product_state::idle(engine).await;
                let mut params = relation.params;
                params.push((
                    "product_output".into(),
                    temporary.to_string_lossy().into_owned(),
                ));
                let sql = format!(
                    "INSERT INTO FUNCTION file({{product_output:String}}, Parquet) {}{}",
                    relation.sql,
                    statement_settings(engine)
                );
                let result = engine
                    .with_job_statements(engine.run_sql(sql, params))
                    .await;
                if let Err(error) = result {
                    let _ = std::fs::remove_file(&temporary);
                    return Err(internal(error));
                }
            }
        }
        let history = history_state(engine, to).await.map(|_| ());
        if let Err(error) = history {
            let _ = std::fs::remove_file(&temporary);
            return Err(error);
        }
        std::fs::rename(temporary, &path).map_err(internal)?;
        prune_product_state(engine.product_dir());
        let rows = parquet::file::reader::SerializedFileReader::new(
            std::fs::File::open(&path).map_err(internal)?,
        )
        .map_err(internal)?;
        use parquet::file::reader::FileReader;
        tracing::info!(
            state = "prevalence",
            window_hours = (to - from) / 3_600_000_000,
            rows = rows.metadata().file_metadata().num_rows(),
            wall_ms = meter.wall_ms(),
            cpu_ms = meter.cpu_ms(),
            cpu_scope = super::product_state::CPU_SCOPE,
            threads,
            "product state ready"
        );
    }
    touch_product_state(engine, &path)?;
    // NAN-3791: the window's cross-scope explorer state, built with the
    // window (before it is published) so a viewer never aggregates it.
    if let Err(error) = explorer_state(engine, &path).await {
        tracing::warn!(error = %error, "prevalence explorer state not built; the explorer aggregates the window per request");
    }
    Ok(Some(path))
}

/// NAN-3791: the cross-scope explorer state beside a window file.
pub(super) fn explorer_path(window: &std::path::Path) -> std::path::PathBuf {
    window.with_extension("explorer")
}

/// The explorer's cross-scope aggregation (one row per `(kind, entity)`)
/// over a window relation `relation_sql` whose rows pass `predicates`.
/// Shared by the per-request fallback and the maintained explorer state so
/// both answer from exactly the same aggregate.
fn explorer_aggregate_sql(relation_sql: &str, predicates: &str) -> String {
    format!(
        "SELECT kind, entity, length(hosts) AS host_count, toUInt8(any_saturated OR length(hosts) = 1000) AS saturated, \
                private, first_seen, last_seen, total_occurrences \
         FROM (SELECT kind, entity, groupUniqArrayArray(1000)(host_fingerprints) AS hosts, \
                      max(toUInt8(host_count_saturated)) = 1 AS any_saturated, max(toUInt8(is_private)) AS private, \
                      min(first_seen) AS first_seen, max(last_seen) AS last_seen, sum(total_occurrences) AS total_occurrences \
               FROM ({relation_sql}) WHERE {predicates} GROUP BY kind, entity)"
    )
}

/// NAN-3791: the unscoped explorer aggregate of the window file `window`,
/// written once beside it (product[T], under build authority) in the
/// explorer's page order. A viewer whose deny set touches none of the
/// window's scopes reads it instead of re-aggregating every per-scope row
/// and host array of the window per request (tenant-a 24 h: 6.2 M rows, cancelled
/// at the API's 20 s). Idempotent: the window file is content-addressed,
/// and so is this state. Outside build authority a missing state is not
/// built here (the explorer falls back to the per-request aggregate).
async fn explorer_state(engine: &PartQueryEngine, window: &std::path::Path) -> QueryResult<Option<std::path::PathBuf>> {
    let path = explorer_path(window);
    if path.is_file() {
        touch_product_state(engine, &path)?;
        return Ok(Some(path));
    }
    if !super::product_state::building() {
        return Ok(None);
    }
    let meter = super::product_state::BuildMeter::start();
    let temporary = path.with_extension(format!("{}.tmp", uuid::Uuid::new_v4().simple()));
    let params = vec![
        ("explorer_window".to_string(), window.to_string_lossy().into_owned()),
        ("explorer_output".to_string(), temporary.to_string_lossy().into_owned()),
    ];
    let sql = format!(
        "INSERT INTO FUNCTION file({{explorer_output:String}}, Parquet) {} ORDER BY last_seen DESC, kind, entity{}{EXPLORER_WRITE_SETTINGS}",
        explorer_aggregate_sql("SELECT * FROM file({explorer_window:String}, Parquet)", "1 = 1"),
        statement_settings(engine)
    );
    let _slot = super::product_state::idle(engine).await;
    let result = engine.with_job_statements(engine.run_sql(sql, params)).await;
    if let Err(error) = result {
        let _ = std::fs::remove_file(&temporary);
        return Err(internal(error));
    }
    std::fs::rename(&temporary, &path).map_err(|error| { let _ = std::fs::remove_file(&temporary); internal(error) })?;
    tracing::info!(state = "prevalence_explorer", wall_ms = meter.wall_ms(), cpu_ms = meter.cpu_ms(),
        cpu_scope = super::product_state::CPU_SCOPE, "product state ready");
    Ok(Some(path))
}

/// Small row groups in page order: a first page reads the head of the file.
const EXPLORER_WRITE_SETTINGS: &str = ", output_format_parquet_row_group_size=65536";

pub(super) async fn maintained_history(
    engine: &PartQueryEngine,
    parts: &[PartRef],
) -> QueryResult<std::path::PathBuf> {
    use sha2::{Digest, Sha256};
    let mut identities = parts
        .iter()
        .map(serde_json::to_vec)
        .collect::<Result<Vec<_>, _>>()
        .map_err(internal)?;
    identities.sort();
    let mut hash = Sha256::new();
    for identity in identities {
        hash.update((identity.len() as u64).to_le_bytes());
        hash.update(identity);
    }
    let path = engine.product_dir().join(format!(
        "product-history-v2-{}.state",
        hex::encode(hash.finalize())
    ));
    if path.is_file() {
        touch_product_state(engine, &path)?;
        return Ok(path);
    }
    if !super::product_state::building() {
        super::product_state::request_at(
            engine,
            engine.identity_state_dir(),
            super::product_state::Work::History(parts.to_vec()),
        );
        return Err(PartQueryError::Unavailable(
            super::product_state::WARMING.into(),
        ));
    }
    // NAN-3161: one cached history per event day (keyed by that day's
    // inventory), concatenated. Readers sum per (kind, entity, day), so the
    // concatenation is exact; a cycle re-aggregates only days whose parts
    // changed instead of every partial of the month.
    super::fetch::prevalence_path(async {
        let mut days = std::collections::BTreeMap::<i64, Vec<PartRef>>::new();
        for part in parts {
            days.entry(leaf_hour(part).div_euclid(HOURS_PER_DAY)).or_default().push(part.clone());
        }
        let mut paths = Vec::new();
        for day in days.values() {
            paths.push(day_history(engine, day).await?);
        }
        let temporary = path.with_extension(format!("{}.tmp", uuid::Uuid::new_v4().simple()));
        // NAN-3279: the month is the plain concatenation of its days; copy
        // their encoded row groups instead of re-encoding a month of rows in
        // one native statement (no admission slot, no time cap). Day files of
        // another schema fall back to the statement.
        let (sources, target) = (paths.clone(), temporary.clone());
        let copied = tokio::task::spawn_blocking(move || super::parquet_concat::concat(&sources, &target)).await.map_err(internal)?;
        if let Err(error) = copied {
            tracing::warn!(error = %format!("{error:#}"), "history concatenation fell back to a statement");
            let params = vec![
                ("history_source".into(), path_set(&paths)?),
                ("history_output".into(), temporary.to_string_lossy().into_owned()),
            ];
            let _slot = super::product_state::idle(engine).await;
            let sql = format!("INSERT INTO FUNCTION file({{history_output:String}}, Parquet) SELECT kind, scope, entity, day, daily_count FROM file({{history_source:String}}, Parquet){}", statement_settings(engine));
            let result = engine.with_job_statements(engine.run_sql(sql, params)).await;
            if let Err(error) = result {
                let _ = std::fs::remove_file(&temporary);
                return Err(internal(error));
            }
        }
        std::fs::rename(temporary, &path).map_err(internal)?;
        prune_product_state(engine.product_dir());
        Ok(path)
    })
    .await
}

/// One event day's history rows `(kind, scope, entity, day, daily_count)`
/// from its parts' partials, content-addressed by the day's inventory.
async fn day_history(engine: &PartQueryEngine, parts: &[PartRef]) -> QueryResult<std::path::PathBuf> {
    let path = inventory_path(engine, HISTORY_STATE_PREFIX, parts)?;
    if path.is_file() {
        touch_product_state(engine, &path)?;
        return Ok(path);
    }
    let local = engine
        .fetcher()
        .ensure(parts, &[FileSet::Partial(PartialKind::Prevalence)])
        .await
        .map_err(internal)?;
    let paths = local
        .of(FileSet::Partial(PartialKind::Prevalence))
        .map(|file| file.path.clone())
        .collect::<Vec<_>>();
    let temporary = engine.product_dir().join(format!(".prevalence-history-{}.parquet", uuid::Uuid::new_v4().simple()));
    let params = vec![
        ("history_source".into(), path_set(&paths)?),
        (
            "history_output".into(),
            temporary.to_string_lossy().into_owned(),
        ),
    ];
    let _slot = super::product_state::idle(engine).await;
    // NAN-3791: sorted by entity in small row groups. The month is the
    // concatenation of its days (row-group statistics kept, page indexes
    // not), so a heatmap lookup of one page's entities prunes every other
    // row group of every day by its entity min/max instead of decoding the
    // whole month per explorer request.
    let sql = format!("INSERT INTO FUNCTION file({{history_output:String}}, Parquet) SELECT kind, scope, entity, day, sum(daily_count) AS daily_count FROM file({{history_source:String}}, Parquet) GROUP BY kind, scope, entity, day ORDER BY entity, kind, scope, day{}{HISTORY_WRITE_SETTINGS}", statement_settings(engine));
    let result = engine
        .with_job_statements(engine.run_sql(sql, params))
        .await;
    if let Err(error) = result {
        let _ = std::fs::remove_file(&temporary);
        return Err(internal(error));
    }
    std::fs::rename(temporary, &path).map_err(internal)?;
    Ok(path)
}

/// v2 (NAN-3791): entity-sorted day files in [`HISTORY_WRITE_SETTINGS`] row
/// groups; v1 day files (unsorted) are never reused.
const HISTORY_STATE_PREFIX: &str = "prevalence-history-v2-";
const HISTORY_WRITE_SETTINGS: &str = ", output_format_parquet_row_group_size=8192";

fn prune_product_state(state: &std::path::Path) {
    if let Ok(entries) = std::fs::read_dir(state) {
        for entry in entries.flatten() {
            if entry.file_name().to_string_lossy().starts_with("product-")
                && entry
                    .metadata()
                    .ok()
                    .and_then(|metadata| metadata.modified().ok())
                    .and_then(|at| at.elapsed().ok())
                    .is_some_and(|age| age.as_secs() > 7200)
            {
                let _ = std::fs::remove_file(entry.path());
            }
        }
    }
}

/// Keep a used state file young. A consumer never writes product[T]'s
/// files; the publisher touches what it has published.
fn touch_product_state(engine: &PartQueryEngine, path: &std::path::Path) -> QueryResult<()> {
    if !super::product_publish::writes(engine) {
        return Ok(());
    }
    std::fs::File::open(path).and_then(|file| file.set_modified(std::time::SystemTime::now())).map_err(internal)
}

#[cfg(test)]
mod nan3802_cursor_tests {
    use super::*;
    use nanosiem_core::prevalence::lookup::validated_explorer_cursor;
    use nanosiem_core::prevalence::PrevalenceExplorerCursor;

    /// Page 1's `next_cursor` must pass the API's (lookup.rs) validation
    /// unchanged and come back as page 2's seek key. Before NAN-3802 the
    /// cursor carried `2026-10-14 02:04:14.359000`, which lookup.rs refused,
    /// so explorer page 2 always answered 502.
    #[test]
    fn page_one_cursor_round_trips_through_lookup_validation_to_page_two() {
        // A page tuple as `explorer_from_*` returns it: microseconds may come
        // back as a JSON string (UInt64/Int64 quoting) or a number.
        for last_us in [json!("1791943454359000"), json!(1_791_943_454_359_000_i64)] {
            let row = json!({"kind": "domain", "entity": "next.example", "last_us": last_us,
                             "last_seen_text": "2026-10-14 02:04:14.359000"});
            let emitted = explorer_next_cursor(&row);
            assert_eq!(emitted["last_seen"], "2026-10-14T02:04:14.359000Z");
            assert!(chrono::DateTime::parse_from_rfc3339(emitted["last_seen"].as_str().unwrap()).is_ok());

            // API: what the browser sends back for page 2.
            let cursor: PrevalenceExplorerCursor = serde_json::from_value(emitted).unwrap();
            let forwarded = validated_explorer_cursor(&cursor).expect("page-1 cursor must validate");
            assert_eq!(forwarded, cursor);

            // Cell: page 2's request accepts it and seeks on the same instant.
            let seek = forwarded.validated().unwrap();
            assert_eq!(seek.last_seen, "2026-10-14T02:04:14.359000Z");
        }
    }

    /// A tab opened before the roll still holds a legacy-form cursor: the API
    /// and the cell normalize it instead of answering 502.
    #[test]
    fn legacy_text_cursor_is_accepted_and_normalized() {
        let legacy = PrevalenceExplorerCursor {
            last_seen: "2026-10-14 02:04:14.359000".into(),
            kind: "ip".into(),
            artifact: "203.0.113.9".into(),
        };
        let forwarded = validated_explorer_cursor(&legacy).unwrap();
        assert_eq!(forwarded.last_seen, "2026-10-14T02:04:14.359000Z");
        assert_eq!(forwarded.artifact, legacy.artifact);
        for bad in ["", "yesterday", "2026-10-14", "2026-13-14 02:04:14"] {
            let cursor = PrevalenceExplorerCursor { last_seen: bad.into(), ..legacy.clone() };
            assert!(validated_explorer_cursor(&cursor).is_err(), "{bad}");
        }
    }
}

#[cfg(test)]
mod nan4154_superseded_state_tests {
    use super::*;
    use std::time::{Duration, SystemTime};

    fn file(dir: &std::path::Path, name: &str, bytes: usize, age: Duration) -> std::path::PathBuf {
        let path = dir.join(name);
        std::fs::write(&path, vec![7_u8; bytes]).unwrap();
        let file = std::fs::File::options().write(true).open(&path).unwrap();
        file.set_modified(SystemTime::now() - age).unwrap();
        path
    }

    /// NAN-4154 PR2: over budget, the least recently used states and
    /// histories go first until it fits; nothing used since `keep_after`,
    /// no other family, and no bytes a published window still links count
    /// as freed.
    #[test]
    fn the_state_budget_removes_least_recently_used_first_and_keeps_recent_use() {
        let dir = tempfile::tempdir().unwrap();
        let hour = Duration::from_secs(3_600);
        let digest = |n: u8| format!("{:064x}", n);
        let oldest = file(dir.path(), &format!("{STATE_PREFIX}{}.parquet", digest(1)), 400, 5 * hour);
        let older = file(dir.path(), &format!("{HISTORY_STATE_PREFIX}{}.parquet", digest(2)), 300, 4 * hour);
        let newer = file(dir.path(), &format!("{STATE_PREFIX}{}.parquet", digest(3)), 200, 3 * hour);
        let recent = file(dir.path(), &format!("{HISTORY_STATE_PREFIX}{}.parquet", digest(4)), 500, Duration::from_secs(60));
        let window = file(dir.path(), &format!("{WINDOW_STATE_PREFIX}{}.parquet", digest(5)), 5_000, 9 * hour);
        let keep_after = SystemTime::now() - STATE_BUDGET_FLOOR;

        // Within budget: nothing goes.
        assert_eq!(enforce_state_budget(dir.path(), 1_400, keep_after), (0, 0, 1_400));
        // 1,400 over 800: the two least recently used go (700), then it fits.
        assert_eq!(enforce_state_budget(dir.path(), 800, keep_after), (2, 700, 700));
        assert!(!oldest.exists() && !older.exists());
        assert!(newer.exists() && recent.exists() && window.exists());
        // Recent use is never removed, even when that leaves it over budget.
        assert_eq!(enforce_state_budget(dir.path(), 100, keep_after), (1, 200, 500));
        assert!(recent.exists() && window.exists());
    }

    /// Superseded states and day histories (unused for longer than the grace
    /// at a complete cycle) go; everything a cycle used, and every other
    /// family the existing sweeps own, stays.
    #[test]
    fn only_states_and_histories_unused_since_the_cutoff_are_removed() {
        let dir = tempfile::tempdir().unwrap();
        let hour = Duration::from_secs(3_600);
        let digest = |n: u8| format!("{:064x}", n);
        let stale_state = file(dir.path(), &format!("{STATE_PREFIX}{}.parquet", digest(1)), 100, 7 * hour);
        let stale_history = file(dir.path(), &format!("{HISTORY_STATE_PREFIX}{}.parquet", digest(2)), 50, 30 * hour);
        let used_state = file(dir.path(), &format!("{STATE_PREFIX}{}.parquet", digest(3)), 10, Duration::ZERO);
        let used_history = file(dir.path(), &format!("{HISTORY_STATE_PREFIX}{}.parquet", digest(4)), 10, hour);
        // Other families keep their own retention, however old.
        let others = [
            file(dir.path(), &format!("{WINDOW_STATE_PREFIX}{}.parquet", digest(5)), 10, 30 * hour),
            file(dir.path(), &format!("product-history-v2-{}.state", digest(6)), 10, 30 * hour),
            file(dir.path(), ".prevalence-state-0123.parquet", 10, 30 * hour),
            file(dir.path(), &format!("{STEP_PREFIX}x-2-000.parquet"), 10, 30 * hour),
            file(dir.path(), "product-manifest.json", 10, 30 * hour),
        ];
        // A state linked into a published window frees no bytes when unlinked.
        let linked = file(dir.path(), &format!("{STATE_PREFIX}{}.parquet", digest(7)), 1_000, 8 * hour);
        let window_link = dir.path().join(format!("{WINDOW_STATE_PREFIX}{}.parquet", digest(8)));
        std::fs::hard_link(&linked, &window_link).unwrap();

        let cutoff = SystemTime::now() - SUPERSEDED_STATE_GRACE;
        let (files, bytes) = sweep_superseded_states(dir.path(), cutoff);
        assert_eq!((files, bytes), (3, 150));
        for gone in [&stale_state, &stale_history, &linked] {
            assert!(!gone.exists(), "{} is superseded", gone.display());
        }
        for kept in [&used_state, &used_history, &window_link].into_iter().chain(others.iter()) {
            assert!(kept.exists(), "{} must stay", kept.display());
        }
        // Idempotent; a missing directory is not an error.
        assert_eq!(sweep_superseded_states(dir.path(), cutoff), (0, 0));
        assert_eq!(sweep_superseded_states(&dir.path().join("absent"), cutoff), (0, 0));
    }

    #[test]
    fn the_grace_spans_several_hour_rolls() {
        assert!(SUPERSEDED_STATE_GRACE >= Duration::from_secs(3 * 3_600));
        assert!(SUPERSEDED_STATE_GRACE < Duration::from_secs(86_400));
    }
}

#[cfg(test)]
mod nan4293_tests {
    use super::*;

    /// Every chunk is kept, in order, and a statement never spans more than
    /// one chunk of parts.
    #[tokio::test]
    async fn every_chunk_is_kept_in_order() {
        let items = (0..70).collect::<Vec<u32>>();
        let mut kept = Vec::new();
        let result: Result<(), ()> = by_chunks(&items, ROLLUP_MEMO_CHUNK_PARTS, |chunk| async move { Ok(chunk) }, |chunk| kept.push(chunk)).await;
        assert!(result.is_ok());
        assert_eq!(kept.iter().map(Vec::len).collect::<Vec<_>>(), [32, 32, 6]);
        assert_eq!(kept.concat(), items);
    }

    /// A failure part-way keeps the chunks that finished before it.
    #[tokio::test]
    async fn a_failed_chunk_keeps_the_chunks_before_it() {
        let items = (0..10).collect::<Vec<u32>>();
        let mut kept = Vec::new();
        let result = by_chunks(&items, 3, |chunk| async move { if chunk[0] == 6 { Err("too wide") } else { Ok(chunk) } }, |chunk| kept.push(chunk)).await;
        assert_eq!(result, Err("too wide"));
        assert_eq!(kept, [vec![0, 1, 2], vec![3, 4, 5]]);
    }

    /// The segments refresh shape: the caller's deadline drops the read
    /// while a later chunk is still running, and the finished chunks are
    /// already kept (memoized), so the next read resumes after them.
    #[tokio::test]
    async fn a_cancelled_read_keeps_its_finished_chunks() {
        let items = (0..10).collect::<Vec<u32>>();
        let kept = std::sync::Mutex::new(Vec::new());
        let read = by_chunks(&items, 4, |chunk| async move {
            if chunk[0] >= 4 {
                std::future::pending::<()>().await;
            }
            Ok::<_, ()>(chunk)
        }, |chunk| kept.lock().unwrap().push(chunk));
        assert!(tokio::time::timeout(std::time::Duration::from_millis(20), read).await.is_err(), "the read is cancelled");
        assert_eq!(*kept.lock().unwrap(), [vec![0, 1, 2, 3]]);
    }
}
