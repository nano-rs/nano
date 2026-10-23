// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-3078: typed product views as durable jobs on query[T].
//!
//! A view job (`| cloud` overview, event summary and principal dossier, the
//! Asset summary, `| baseline`, (NAN-3086) the `| retro` hunt, and (NAN-3088)
//! the Prevalence export) runs the same reads its interactive lane
//! runs, on the engine's read-write job lane, and commits one typed artifact
//! under the tenant's R2 result root through the exchanged `job_results`
//! grant, exactly like a search job.
//!
//! Retention: the runner signs a moving-cutoff proof over the admitted range
//! and sends it in the spec. Every read here is clamped to
//! [`LakeQueryJobSpec::execution_window`] (the proof's CURRENT cutoff), and a
//! compiled window that escapes the clamped window (e.g. a time modifier in
//! the query text) refuses the job. The proof then travels on the result
//! reference and every user read re-checks it against the moving cutoff.
//!
//! Memory: rows are spooled by chDB to a JSONEachRow file (the interactive
//! lane's byte format) and streamed back one line at a time. The Cloud
//! dossier folds them ([`CloudDossierAccumulator`]), so an unbounded event set
//! costs only its rollup state; every other view's reads are bounded
//! aggregates, collected under the process's per-request result budget.

use anyhow::{bail, Context, Result};
use chrono::{DateTime, Utc};
use nanosiem_core::query::TimeRange;
use nanosiem_core::search::{
    run_lake_baseline, CloudDossierAccumulator, DurableLakeTask, LakeAssetCards, LakeBaselinePlan,
    SearchError, SearchService,
};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::io::BufRead;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;

use super::engine::{compiled_window_us, plan_logs, BroadNplRequest, PartQueryEngine, MAX_RESULT_LIMIT};
use super::job_results::JobResultStore;
use super::jobs::PartJobPin;
use crate::executor::NativeExecutor;
use crate::job::{commit_result_to, LakeQueryJobSpec, MaterializedJobResult, ResultArtifactRef, ResultExecutionMetadata};

/// Raw JSON bytes a collected (non-folded) view read may hold when the
/// engine reports no per-request result budget.
const DEFAULT_COLLECT_BYTES: u64 = 64 * 1024 * 1024;

fn view_error(error: anyhow::Error) -> SearchError {
    SearchError::SqlValidationError(error.to_string())
}

/// What one read produced.
struct ReadOutcome {
    has_more: bool,
}

/// One view job's reads: clamped to the execution window, serialized on the
/// single read-write lane, with their execution metadata summed.
struct ViewReader<'a> {
    engine: &'a PartQueryEngine,
    writer: &'a NativeExecutor,
    spec: &'a LakeQueryJobSpec,
    pin: &'a PartJobPin,
    window: (DateTime<Utc>, DateTime<Utc>),
    cancelled: &'a AtomicBool,
    collect_bytes: u64,
    lane: tokio::sync::Mutex<ResultExecutionMetadata>,
}

/// The part of `[start, end]` inside `window`, or `None` when they do not
/// overlap. Every view read goes through this.
pub fn clamp_to_window(
    start: DateTime<Utc>,
    end: DateTime<Utc>,
    window: (DateTime<Utc>, DateTime<Utc>),
) -> Option<(DateTime<Utc>, DateTime<Utc>)> {
    let start = start.max(window.0);
    let end = end.min(window.1);
    (start < end).then_some((start, end))
}

/// A compiled read may not look outside the window it was admitted for.
pub fn compiled_within(compiled: (i64, i64), start: DateTime<Utc>, end: DateTime<Utc>) -> bool {
    compiled.0 >= start.timestamp_micros() && compiled.1 <= end.timestamp_micros()
}

impl ViewReader<'_> {
    fn check_cancelled(&self) -> Result<()> {
        if self.cancelled.load(Ordering::Acquire) {
            bail!("view job was cancelled");
        }
        Ok(())
    }

    /// Execute one nPL read over `[start, end]` ∩ the execution window and
    /// hand each row (newest first when the query sorts so) to `sink`, up to
    /// `limit` rows.
    async fn read(
        &self,
        query: &str,
        start: DateTime<Utc>,
        end: DateTime<Utc>,
        limit: usize,
        suffix: &str,
        mut sink: impl FnMut(Value) -> Result<()>,
    ) -> Result<ReadOutcome> {
        let mut execution = self.lane.lock().await;
        self.check_cancelled()?;
        let Some((start, end)) = clamp_to_window(start, end, self.window) else {
            return Ok(ReadOutcome { has_more: false });
        };
        if limit == 0 || limit > MAX_RESULT_LIMIT {
            bail!("view read limit is outside its bound");
        }
        let started = Instant::now();
        let request = BroadNplRequest {
            request_id: format!("{}-{}-{suffix}", self.spec.job_id, self.spec.attempt_id),
            tenant_id: self.spec.tenant_id.clone(),
            dataset: "logs".to_string(),
            query: query.to_string(),
            start: start.to_rfc3339(),
            end: end.to_rfc3339(),
            limit,
            offset: 0,
            table_view: false,
            use_cache: false,
            cursor_time: None,
            cursor_event_uid: None,
            anchor_us: None,
            decay: None,
            clear_boundaries: Default::default(),
            watch_weights: Default::default(),
            minimum_clear_revision: None,
            deny_source_types: nanosiem_core::auth::source_visibility::expand_unattributed_sources(
                &self.spec.scope_deny,
            ),
        };
        let engine = self.engine;
        let field_types = engine.field_types().await.map_err(|error| anyhow::anyhow!(error.to_string()))?;
        let compiled = engine
            .compile(&request, field_types.clone())
            .await
            .map_err(|error| anyhow::anyhow!(error.to_string()))?;
        let (from_us, to_us) = compiled_window_us(&compiled).map_err(|error| anyhow::anyhow!(error.to_string()))?;
        if !compiled_within((from_us, to_us), start, end) {
            bail!("view read compiled a window outside the job's retention-bound range");
        }
        let membership = engine
            .membership(&request.query, &field_types, from_us, to_us)
            .await
            .map_err(|error| anyhow::anyhow!(error.to_string()))?;
        let selection = engine
            .select_with(from_us, to_us, &compiled.candidate_hints, membership.as_ref())
            .await
            // NAN-3272: keep the typed refusal (cold budget) for the HTTP mapping.
            .map_err(anyhow::Error::new)?;
        let (head, schema) = engine.head_and_schema_fingerprint().await;
        PartJobPin::at_head(head, schema.as_deref(), &self.pin.compiler_sha256, &self.pin.native_artifact_sha256)?
            .admits(self.spec)?;
        self.check_cancelled()?;
        let mut plan = plan_logs(&selection, &compiled, None).map_err(|error| anyhow::anyhow!(error.to_string()))?;
        if plan.budget.estimated_scan_bytes > self.spec.scan_budget_bytes {
            bail!(
                "view read {suffix} would scan {} bytes, over the job budget of {}",
                plan.budget.estimated_scan_bytes,
                self.spec.scan_budget_bytes
            );
        }
        let spool = tempfile::tempdir().context("create view read spool")?;
        let output_path = spool.path().join("rows.jsonl");
        plan.params.push((
            "job_result_output".to_string(),
            output_path.to_str().context("spool path is not UTF-8")?.to_string(),
        ));
        // JSONEachRow is the interactive lane's own result format, so the
        // product assemblers see byte-identical values.
        plan.sql = format!("INSERT INTO FUNCTION file({{job_result_output:String}}, JSONEachRow) {}", plan.sql);
        let aliases = plan.temporary_aliases.iter().cloned().collect::<BTreeSet<_>>();
        let plan = super::engine::with_memory_cap(plan, self.engine.job_memory_bytes());
        let output = self.writer.execute(plan).await.map_err(anyhow::Error::new)?;
        drop(selection);
        self.check_cancelled()?;
        let mut rows = 0_u64;
        let mut has_more = false;
        if output_path.is_file() {
            let file = std::fs::File::open(&output_path).context("open view read spool")?;
            for line in std::io::BufReader::new(file).lines() {
                let line = line.context("read view read spool")?;
                if line.is_empty() {
                    continue;
                }
                if rows as usize >= limit {
                    has_more = true;
                    break;
                }
                let mut row: Value = serde_json::from_str(&line).context("view read row is not JSON")?;
                if let Some(object) = row.as_object_mut() {
                    for alias in &aliases {
                        object.remove(alias);
                    }
                }
                rows += 1;
                sink(row)?;
            }
        }
        execution.wall_seconds += started.elapsed().as_secs_f64();
        execution.engine_seconds += output.elapsed.as_secs_f64();
        execution.storage_rows = execution.storage_rows.saturating_add(output.storage_rows_read);
        execution.storage_bytes = execution.storage_bytes.saturating_add(output.storage_bytes_read);
        Ok(ReadOutcome { has_more })
    }

    /// [`Self::read`] into memory, bounded by the per-request result budget.
    async fn collect(
        &self,
        query: &str,
        start: DateTime<Utc>,
        end: DateTime<Utc>,
        limit: usize,
        suffix: &str,
    ) -> Result<(Vec<Value>, bool)> {
        let mut rows = Vec::new();
        let mut bytes = 0_u64;
        let budget = self.collect_bytes;
        let outcome = self
            .read(query, start, end, limit, suffix, |row| {
                bytes = bytes.saturating_add(row.to_string().len() as u64);
                if bytes > budget {
                    bail!("view read {suffix} exceeded the durable view envelope of {budget} bytes; narrow the time range");
                }
                rows.push(row);
                Ok(())
            })
            .await?;
        Ok((rows, outcome.has_more))
    }

    async fn collect_window(&self, query: &str, limit: usize, suffix: &str) -> Result<Vec<Value>> {
        Ok(self.collect(query, self.window.0, self.window.1, limit, suffix).await?.0)
    }

    async fn execution(&self) -> ResultExecutionMetadata {
        self.lane.lock().await.clone()
    }
}

fn materialized(row: Value, execution: ResultExecutionMetadata) -> MaterializedJobResult {
    MaterializedJobResult { rows: vec![row], has_more: false, execution }
}

// Conservative allowance for serde_json tree nodes and Vec spare capacity.
// The row is already parsed by the shared spool reader, so recursive traversal
// stays within serde_json's decoding depth limit.
fn json_resident_bytes(value: &Value) -> u64 {
    let own = std::mem::size_of::<Value>() as u64;
    own.saturating_add(match value {
        Value::String(value) => value.capacity() as u64,
        Value::Array(values) => (values.capacity() as u64).saturating_mul(own)
            .saturating_add(values.iter().map(json_resident_bytes).sum::<u64>()),
        Value::Object(values) => values.iter().map(|(key, value)| {
            128_u64.saturating_add(key.capacity() as u64).saturating_add(json_resident_bytes(value))
        }).sum(),
        _ => 0,
    })
}

/// Run one typed view job and commit its artifact.
pub async fn run_view_job(
    engine: &PartQueryEngine,
    spec: &LakeQueryJobSpec,
    results: &JobResultStore,
    pin: &PartJobPin,
    cancelled: &AtomicBool,
) -> Result<ResultArtifactRef> {
    spec.validate()?;
    pin.admits(spec)?;
    if !spec.task.is_lean_view() {
        bail!("{} is not a lean view task", spec.task.kind());
    }
    if spec.tenant_id != engine.settings().tenant_id {
        bail!("job tenant is not this process's tenant");
    }
    if spec.request.dataset != "logs" {
        bail!("view jobs read dataset logs");
    }
    if results.tenant_id() != spec.tenant_id {
        bail!("job-result store belongs to another tenant");
    }
    // A hosted view job always carries its moving-retention receipt: the cell
    // holds no tenant policy, so without it nothing bounds the reads.
    // NAN-3492: a trusted-local install has no hosted retention identity; its
    // retention retires parts physically (local GC), so the request window is
    // the bound, exactly like a dedicated nPL job.
    if spec.retention_proof.is_none() && !results.is_trusted_local() {
        bail!("view jobs require the runner's retention proof");
    }
    let window = spec.execution_window(Utc::now())?;
    if cancelled.load(Ordering::Acquire) {
        bail!("view job was cancelled before execution");
    }
    results.current()?;
    let writer = engine.writer().context("the part engine has no read-write lane for jobs")?;
    // NAN-3088: a Prevalence export is not an nPL read; it spools the
    // prevalence window relation over the same clamped window to Parquet.
    if let DurableLakeTask::PrevalenceExportV1 { window: declared, artifact_type, max_prevalence, .. } = &spec.task {
        let export = PrevalenceExport { declared, artifact_type: artifact_type.as_deref(), max_prevalence: *max_prevalence };
        return run_prevalence_export(engine, writer, spec, results, pin, window, cancelled, export).await;
    }
    let reader = ViewReader {
        engine,
        writer,
        spec,
        pin,
        window,
        cancelled,
        collect_bytes: engine.executor().result_limit_bytes().unwrap_or(DEFAULT_COLLECT_BYTES),
        lane: tokio::sync::Mutex::new(ResultExecutionMetadata::default()),
    };
    let work = async {
        let result = execute_view(&reader, spec).await?;
        if cancelled.load(Ordering::Acquire) {
            bail!("view job was cancelled before result commit");
        }
        results
            .with_operator(|operator| {
                // A refused credential is refreshed and the commit retried.
                let result = result.clone();
                async move { commit_result_to(&operator, results.root(), spec, result).await }
            })
            .await
    };
    engine.with_job_statements(work).await
}

/// The typed filters of one durable Prevalence export (NAN-3088).
struct PrevalenceExport<'a> {
    /// The task's declared window (`1h` .. `30d`): the admitted range may be
    /// narrower (the retention cutoff), never wider.
    declared: &'a str,
    artifact_type: Option<&'a str>,
    max_prevalence: u64,
}

/// Admitted-range slack over the declared window: admission and the
/// runner's re-bind stamp `now` a little apart.
const PREVALENCE_EXPORT_RANGE_SKEW_US: i64 = 5 * 60 * 1_000_000;

/// A durable Prevalence export on query[T] (NAN-3088): the rare artifacts of
/// the prevalence window relation over the proof's CURRENT clamped window,
/// scoped by the job's deny set, committed as bounded Parquet pages under
/// the tenant's result root.
#[allow(clippy::too_many_arguments)]
async fn run_prevalence_export(
    engine: &PartQueryEngine,
    writer: &NativeExecutor,
    spec: &LakeQueryJobSpec,
    results: &JobResultStore,
    pin: &PartJobPin,
    window: (DateTime<Utc>, DateTime<Utc>),
    cancelled: &AtomicBool,
    export: PrevalenceExport<'_>,
) -> Result<ResultArtifactRef> {
    let declared_us = super::partials::window_us(export.declared).map_err(|error| anyhow::anyhow!(error.to_string()))?;
    let admitted_start = DateTime::parse_from_rfc3339(&spec.request.start).context("job start is not RFC3339")?;
    let admitted_end = DateTime::parse_from_rfc3339(&spec.request.end).context("job end is not RFC3339")?;
    if (admitted_end - admitted_start).num_microseconds().unwrap_or(i64::MAX) > declared_us + PREVALENCE_EXPORT_RANGE_SKEW_US {
        bail!("prevalence export admitted range is wider than its {} window", export.declared);
    }
    if spec.request.offset != 0 || spec.request.limit == 0 {
        bail!("prevalence export row envelope is invalid");
    }
    let started = Instant::now();
    let deny = nanosiem_core::auth::source_visibility::expand_unattributed_sources(&spec.scope_deny)
        .into_iter()
        .collect::<Vec<_>>();
    let work = async {
        let statement = super::partials::prevalence_export_statement(
            engine,
            window.0.timestamp_micros(),
            window.1.timestamp_micros(),
            export.artifact_type,
            export.max_prevalence,
            nanosiem_core::search::lake_cell::LAKE_CELL_PREVALENCE_RARITY_THRESHOLD,
            &deny,
            spec.request.limit,
            // The job's resource-class scan budget bounds chDB's reads.
            spec.scan_budget_bytes,
        )
        .await
        .map_err(|error| anyhow::anyhow!(error.to_string()))?;
        // The window relation leased its parts at the current head, which
        // only advances: at or after the admitted head.
        let (head, schema) = engine.head_and_schema_fingerprint().await;
        PartJobPin::at_head(head, schema.as_deref(), &pin.compiler_sha256, &pin.native_artifact_sha256)?.admits(spec)?;
        if cancelled.load(Ordering::Acquire) {
            bail!("prevalence export was cancelled before execution");
        }
        let Some(statement) = statement else {
            // No part in the window: an empty, committed result.
            let execution = ResultExecutionMetadata { wall_seconds: started.elapsed().as_secs_f64(), ..Default::default() };
            return results
                .with_operator(|operator| {
                    let result = MaterializedJobResult { rows: Vec::new(), has_more: false, execution: execution.clone() };
                    async move { commit_result_to(&operator, results.root(), spec, result).await }
                })
                .await;
        };
        let spool = tempfile::tempdir().context("create prevalence export spool")?;
        let output_path = spool.path().join("prevalence-export.parquet");
        let mut params = statement.params.clone();
        params.push(("job_result_output".to_string(), output_path.to_str().context("spool path is not UTF-8")?.to_string()));
        let output = writer
            .execute_sql(statement.sql.clone(), params)
            .await
            .map_err(|error| anyhow::anyhow!(error.to_string()))?;
        drop(statement);
        if cancelled.load(Ordering::Acquire) {
            bail!("prevalence export was cancelled before result commit");
        }
        if !output_path.is_file() {
            bail!("prevalence export did not produce its Parquet spool");
        }
        let execution = ResultExecutionMetadata {
            wall_seconds: started.elapsed().as_secs_f64(),
            engine_seconds: output.elapsed.as_secs_f64(),
            storage_rows: output.storage_rows_read,
            storage_bytes: output.storage_bytes_read,
            peak_rss_bytes: None,
            spill_bytes: None,
        };
        super::jobs::commit_job_result(results, spec, &output_path, &BTreeSet::new(), &execution).await
    };
    work.await
}

async fn execute_view(reader: &ViewReader<'_>, spec: &LakeQueryJobSpec) -> Result<MaterializedJobResult> {
    let window_range = TimeRange::new(reader.window.0, reader.window.1);
    match &spec.task {
        DurableLakeTask::CloudDossierV1 { principal, account, provider, filters, event_query, risk } => {
            let mut accumulator = CloudDossierAccumulator::new(principal, filters, &window_range);
            let outcome = reader
                .read(event_query, reader.window.0, reader.window.1, MAX_RESULT_LIMIT, "cloud-dossier-events", |row| {
                    accumulator.push(row);
                    Ok(())
                })
                .await?;
            if outcome.has_more {
                bail!("durable Cloud dossier exceeded the one-million-event envelope; narrow the time range");
            }
            let response = serde_json::to_value(accumulator.finish(risk.clone()))
                .context("serialize durable Cloud dossier")?;
            Ok(materialized(
                json!({
                    "operation": "cloud_dossier",
                    "principal": principal,
                    "account": account,
                    "provider": provider,
                    "filters": filters,
                    "response": response,
                }),
                reader.execution().await,
            ))
        }
        DurableLakeTask::LateralV1 { query, start_micros, end_micros } => {
            let start = DateTime::from_timestamp_micros(*start_micros).context("invalid Lateral start")?;
            let end = DateTime::from_timestamp_micros(*end_micros).context("invalid Lateral end")?;
            if start < DateTime::parse_from_rfc3339(&spec.request.start)?.with_timezone(&Utc) || end > reader.window.1 {
                bail!("Lateral incident escaped its admitted contribution window");
            }
            let (start, end) = clamp_to_window(start, end, reader.window).context("Lateral incident has expired")?;
            let window = TimeRange::new(start, end);
            let scope = nanosiem_core::auth::ScopeSet::from_denied(spec.scope_deny.clone());
            // The same budget must cover retained edges and assembly, not just
            // each read in isolation. Four KiB/edge conservatively includes the
            // raw graph projection and the final JSON DTO alongside the edge.
            let edge_cap = (reader.collect_bytes.min(reader.engine.job_memory_bytes() / 4) / 4096).min(1_000_000) as usize;
            let raw_bytes = std::sync::atomic::AtomicU64::new(0);
            let raw_budget = reader.collect_bytes.min(reader.engine.job_memory_bytes() / 8);
            let rows = nanosiem_core::search::run_lake_lateral_job(query, &window, &scope, edge_cap,
                |query, limit| {
                    let raw_bytes = &raw_bytes;
                    async move {
                    reader.check_cancelled().map_err(view_error)?;
                    let mut rows = Vec::new();
                    let outcome = reader.read(&query, start, end, limit, "lateral-frontier", |row| {
                        let bytes = json_resident_bytes(&row);
                        let accumulated = raw_bytes.fetch_add(bytes, Ordering::Relaxed).saturating_add(bytes);
                        if accumulated > raw_budget { bail!("Lateral reads exceeded their retained heap envelope"); }
                        rows.push(row);
                        Ok(())
                    }).await.map_err(view_error)?;
                    let more = outcome.has_more;
                    // Seed previews intentionally fetch ten rows; every graph
                    // frontier is complete or the artifact is refused.
                    if limit != 10 && more { return Err(SearchError::ResourceExhausted("Lateral frontier exceeded the complete event envelope".into())); }
                    Ok(rows)
                    }
                },
                |items| async move {
                    let mut answers = Vec::with_capacity(items.len());
                    let denied = super::identity::normalize_denied(&spec.scope_deny).map_err(|e| view_error(anyhow::anyhow!(e.to_string())))?;
                    for chunk in items.chunks(super::identity::MAX_ITEMS) {
                        reader.check_cancelled().map_err(view_error)?;
                        let raw = chunk.iter().map(|(ip, at)| (ip.to_string(), at.to_rfc3339())).collect::<Vec<_>>();
                        let normalized = super::identity::normalize_items(super::identity::LookupKind::Ip, &raw).map_err(|e| view_error(anyhow::anyhow!(e.to_string())))?;
                        let (rows, coverage) = super::identity::lookup_bounds(reader.engine, reader.engine.identity_state_dir(),
                            super::identity::LookupKind::Ip, &normalized, &denied,
                            (reader.window.0.timestamp_micros(), reader.window.1.timestamp_micros())).await
                            .map_err(|e| view_error(anyhow::anyhow!(e.to_string())))?;
                        if coverage["state"] != "complete" {
                            return Err(SearchError::ResourceExhausted("Lateral identity coverage is incomplete; finish historical backfill before retrying".into()));
                        }
                        let mut names = vec![None; chunk.len()];
                        for row in rows {
                            let ordinal = row["ordinal"].as_u64().context("identity ordinal missing").map_err(view_error)? as usize;
                            let slot = names.get_mut(ordinal).context("identity ordinal escaped its batch").map_err(view_error)?;
                            *slot = row["hostname"].as_str().map(str::to_string);
                        }
                        answers.extend(names);
                    }
                    Ok(answers)
                },
            ).await.map_err(|error| anyhow::anyhow!(error.to_string()))?;
            reader.check_cancelled()?;
            let total = rows.len().saturating_sub(1);
            Ok(materialized(json!({"operation": "lateral", "response": {
                "results": rows, "total_count": total, "total_count_exact": true,
                "execution_time_ms": (reader.execution().await.wall_seconds * 1000.0) as u64,
                "fields": [], "display_type": "lateral",
            }}), reader.execution().await))
        }
        DurableLakeTask::CloudOverviewV1 { provider, account, identity_query, service_query, change_query, denied_query, risk } => {
            let (identities, more_identities) = reader
                .collect(identity_query, reader.window.0, reader.window.1, MAX_RESULT_LIMIT, "cloud-overview-identities")
                .await?;
            let (services, more_services) = reader
                .collect(service_query, reader.window.0, reader.window.1, MAX_RESULT_LIMIT, "cloud-overview-services")
                .await?;
            if more_identities || more_services {
                bail!("durable Cloud overview exceeded the one-million-group envelope; narrow the time range");
            }
            let changes = reader.collect_window(change_query, 200, "cloud-overview-changes").await?;
            let denied = reader.collect_window(denied_query, 1, "cloud-overview-denied").await?;
            let risk = risk
                .iter()
                .map(|(entity, score, reason)| (entity.clone(), ((*score).max(0) as u32, reason.clone())))
                .collect::<BTreeMap<_, _>>();
            let denied_count = denied
                .first()
                .map(|row| crate::product_payloads::row_u64(row, "events"))
                .unwrap_or_default();
            let response = SearchService::assemble_lake_cloud_overview(
                identities, services, changes, denied_count, &window_range, &risk,
            );
            let response = serde_json::to_value(response).context("serialize durable Cloud overview")?;
            Ok(materialized(
                json!({"operation": "cloud_overview", "provider": provider, "account": account, "response": response}),
                reader.execution().await,
            ))
        }
        DurableLakeTask::CloudEventsSummaryV1 { query, filters, queries, include_panels } => {
            let total = reader.collect_window(&queries.total, 1, "cloud-summary-total").await?;
            let providers = reader.collect_window(&queries.providers, 20, "cloud-summary-providers").await?;
            let services = reader.collect_window(&queries.services, 20, "cloud-summary-services").await?;
            let regions = reader.collect_window(&queries.regions, 20, "cloud-summary-regions").await?;
            let accounts = reader.collect_window(&queries.accounts, 20, "cloud-summary-accounts").await?;
            let resource_types = reader.collect_window(&queries.resource_types, 20, "cloud-summary-resource-types").await?;
            let change_types = reader.collect_window(&queries.change_types, 20, "cloud-summary-change-types").await?;
            let (resources, users) = if *include_panels {
                (
                    reader.collect_window(&queries.resources, 100, "cloud-summary-resources").await?,
                    reader.collect_window(&queries.users, 100, "cloud-summary-users").await?,
                )
            } else {
                (Vec::new(), Vec::new())
            };
            let (total_count, facets, resources_response, user_activity) =
                SearchService::assemble_lake_cloud_events_summary(
                    &total, &providers, &services, &regions, &accounts, &resource_types, &change_types,
                    &resources, &users, *include_panels,
                );
            Ok(materialized(
                json!({
                    "operation": "cloud_events_summary",
                    "query": query,
                    "filters": filters,
                    "response": {
                        "events": [],
                        "total_count": total_count,
                        "total_count_exact": true,
                        "facets": facets,
                        "offset": 0,
                        "limit": 1,
                        "has_more": total_count > 0,
                        "resources": resources_response,
                        "user_activity": user_activity,
                    },
                }),
                reader.execution().await,
            ))
        }
        DurableLakeTask::AssetDossierV1 {
            identifier_field,
            identifier_value,
            identities,
            ..
        } => {
            // NAN-3276: the same bounded card aggregates the interactive
            // dossier reads (group rows, at most the card cap per slice),
            // never the window's event rows: a busy host's ~100k events per
            // day blew the old row read's byte/heap envelope. The task's
            // `event_query` stays on the wire for compatibility only.
            let reads = SearchService::lake_asset_dossier_card_reads(
                identifier_field,
                identifier_value,
                identities,
                &window_range,
            )
            .map_err(|error| anyhow::anyhow!(error.to_string()))?;
            let mut cards = LakeAssetCards::new();
            for read in &reads {
                let mut rows = Vec::new();
                let mut exact = true;
                for (index, query) in read.queries.iter().enumerate() {
                    let (slice, has_more) = reader
                        .collect(
                            query,
                            reader.window.0,
                            reader.window.1,
                            read.limit,
                            &format!("{}-{index}", read.view),
                        )
                        .await?;
                    exact &= !has_more && slice.len() < read.limit;
                    rows.extend(slice);
                }
                cards.insert(read, rows, exact);
            }
            reader.check_cancelled()?;
            let artifacts = cards.artifacts();
            let mut prevalence = BTreeMap::new();
            // Use a 24h baseline ending at the selected window end, bound to
            // the admitted retention window and the same source visibility fence.
            let from = (reader.window.1 - chrono::Duration::hours(24)).max(reader.window.0);
            let deny = spec.scope_deny.iter().cloned().collect::<Vec<_>>();
            for chunk in artifacts.chunks(10_000) {
                reader.check_cancelled()?;
                // NAN-3161: whole parts answer the lookup; the admitted
                // retention start is a hard floor no straddling part crosses.
                for row in super::partials::prevalence_lookup_floored(
                    reader.engine, chunk, from.timestamp_micros(), reader.window.1.timestamp_micros(),
                    Some(reader.window.0.timestamp_micros()), &deny, crate::prevalence::tenant_rarity_threshold(),
                ).await.map_err(|error| anyhow::anyhow!(error.to_string()))? {
                    prevalence.insert(row.artifact, (row.host_count, row.is_rare, row.prevalence_score));
                }
            }
            reader.check_cancelled()?;
            let response = cards.dossier(&window_range, &prevalence);
            Ok(materialized(
                json!({
                    "operation": "asset_dossier",
                    "identifier_field": identifier_field,
                    "identifier_value": identifier_value,
                    "identities": identities,
                    "response": response,
                }),
                reader.execution().await,
            ))
        }
        DurableLakeTask::AssetV1 { identifier_field, identifier_value, identities, filters, summary_query, source_query, user_query } => {
            let summary = reader.collect_window(summary_query, 1, "asset-counts").await?;
            let sources = reader.collect_window(source_query, 50, "asset-sources").await?;
            let users = reader.collect_window(user_query, 50, "asset-users").await?;
            let response = crate::product_payloads::asset_summary_payload(&summary, &sources, &users);
            Ok(materialized(
                json!({
                    "operation": "summary",
                    "identifier_field": identifier_field,
                    "identifier_value": identifier_value,
                    "identities": identities,
                    "filters": filters,
                    "response": response,
                }),
                reader.execution().await,
            ))
        }
        DurableLakeTask::BaselineV1 { .. } => {
            let plan = LakeBaselinePlan::from_task(&spec.task).map_err(|error| anyhow::anyhow!(error.to_string()))?;
            // The admitted range is the whole contribution envelope, so the
            // lookback reads are clamped to the retention cutoff like the
            // incident reads.
            // NAN-3272: the shared baseline assembly speaks `SearchError`, which
            // flattens a read's typed refusal (cold budget, lane wait) into
            // "Search dependency is temporarily unavailable" text and a 500.
            // Keep the first read error as-is and surface it instead.
            let read_error = std::sync::Mutex::new(None::<anyhow::Error>);
            let first_read_error = &read_error;
            let outcome = run_lake_baseline(
                &plan,
                |query: String, range: TimeRange, view: &'static str, limit: usize| async move {
                    reader
                        .collect(&query, range.start, range.end, limit, view)
                        .await
                        .map(|(rows, _)| rows)
                        .map_err(|error| {
                            let flattened = SearchError::ServiceUnavailable(format!("{error:#}"));
                            first_read_error.lock().expect("baseline read error").get_or_insert(error);
                            flattened
                        })
                },
                None,
            )
            .await;
            let outcome = match outcome {
                Ok(outcome) => outcome,
                Err(error) => {
                    return Err(read_error.into_inner().expect("baseline read error")
                        .unwrap_or_else(|| anyhow::anyhow!(error.to_string())));
                }
            };
            if !outcome.complete {
                // NAN-3277: a failed read no longer fails the shared assembly
                // (it marks the answer incomplete); surface the typed read
                // error so the runner can retry it (e.g. lane_wait_timeout).
                if let Some(error) = read_error.into_inner().expect("baseline read error") {
                    return Err(error);
                }
                bail!("durable baseline did not evaluate every dimension");
            }
            Ok(MaterializedJobResult { rows: outcome.rows, has_more: false, execution: reader.execution().await })
        }
        DurableLakeTask::RetroV1 { indicators, axis, submode, offset, limit } => {
            // NAN-3086: the shared retro assembly, over the retention-bound
            // execution window. Every read (denominator, rollups, pivot
            // slices) goes through the clamped reader.
            let job = crate::retro_job::RetroJob { indicators, axis, submode, offset: *offset, limit: *limit };
            let payload = crate::retro_job::run_retro(
                |query: String, start: DateTime<Utc>, end: DateTime<Utc>, limit: usize, suffix: String| async move {
                    let (rows, has_more) = reader.collect(&query, start, end, limit, &suffix).await?;
                    Ok(crate::retro_job::RetroRead { rows, has_more })
                },
                reader.window.0,
                reader.window.1,
                &job,
            )
            .await?;
            Ok(materialized(payload, reader.execution().await))
        }
        DurableLakeTask::PrevalenceExportV1 { .. } => bail!("a prevalence export is not a materialized view"),
        other => bail!("{} does not run on a lean cell", other.kind()),
    }
}

#[cfg(test)]
mod tests {
    use super::{clamp_to_window, compiled_within};
    use chrono::{Duration, TimeZone, Utc};

    #[test]
    fn typed_lateral_seed_refuses_product_and_nested_commands() {
        assert!(nanosiem_core::search::validate_lake_lateral_job("device.hostname=\"h0\" | lateral methods=auth maxhops=2").is_ok());
        for query in ["* | baseline | lateral", "* | asset | lateral", "* | lateral | lateral",
            "ioc=\"10.0.0.1\" | retro | lateral", "* | append [ * | baseline ] | lateral",
            "device.hostname IN [ * | baseline ] | lateral", "* | lateral | head 1"] {
            assert!(nanosiem_core::search::validate_lake_lateral_job(query).is_err(), "{query}");
        }
    }

    #[test]
    fn every_view_read_is_clamped_to_the_retention_bound_window() {
        let floor = Utc.with_ymd_and_hms(2026, 9, 1, 0, 0, 0).unwrap();
        let end = floor + Duration::days(30);
        let window = (floor, end);
        // A baseline lookback that starts before the cutoff reads from it.
        let (start, stop) = clamp_to_window(floor - Duration::days(30), floor + Duration::days(1), window).unwrap();
        assert_eq!((start, stop), (floor, floor + Duration::days(1)));
        // A read wholly past the cutoff reads nothing.
        assert!(clamp_to_window(floor - Duration::days(9), floor - Duration::days(1), window).is_none());
        // A read past the admitted end is cut at it.
        assert_eq!(clamp_to_window(end - Duration::hours(1), end + Duration::days(1), window).unwrap().1, end);
    }

    #[test]
    fn a_compiled_window_outside_the_clamp_is_refused() {
        let start = Utc.with_ymd_and_hms(2026, 9, 1, 0, 0, 0).unwrap();
        let end = start + Duration::days(1);
        let micros = |time: chrono::DateTime<Utc>| time.timestamp_micros();
        assert!(compiled_within((micros(start), micros(end)), start, end));
        // e.g. `earliest=-400d` in the query text widening the compiled start.
        assert!(!compiled_within((micros(start - Duration::seconds(1)), micros(end)), start, end));
        assert!(!compiled_within((micros(start), micros(end + Duration::seconds(1))), start, end));
    }
}

#[cfg(test)]
#[path = "view_jobs_native_tests.rs"]
mod native;
