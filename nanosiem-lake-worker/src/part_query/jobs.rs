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
use std::collections::BTreeSet;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;

use super::engine::{compiled_window_us, plan_logs, BroadNplRequest, PartQueryEngine, PartQueryError};
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
    if spec.task.is_lean_view() {
        super::view_jobs::run_view_job(engine, spec, results, pin, cancelled).await
    } else {
        run_search_job(engine, spec, results, pin, cancelled).await
    }
}

/// Run one durable `logs` search job and commit its result under the
/// tenant's R2 result root through the exchanged `job_results` grant.
pub async fn run_search_job(engine: &PartQueryEngine, spec: &LakeQueryJobSpec, results: &JobResultStore, pin: &PartJobPin, cancelled: &AtomicBool) -> Result<ResultArtifactRef> {
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
    let writer = engine.writer().context("the part engine has no read-write lane for jobs")?;
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
    let tenant = spec.tenant_id.clone();
    let work = async {
        let field_types = engine.field_types().await.map_err(|error| anyhow::anyhow!(error.to_string()))?;
        let compiled = engine.compile(&request, field_types).await.map_err(|error| anyhow::anyhow!(error.to_string()))?;
        let (from_us, to_us) = compiled_window_us(&compiled).map_err(|error| anyhow::anyhow!(error.to_string()))?;
        if !super::view_jobs::compiled_within((from_us, to_us), window_start, window_end) {
            bail!("search job compiled a window outside its retention-bound range");
        }
        let field_types = engine.field_types().await.map_err(|error| anyhow::anyhow!(error.to_string()))?;
        // NAN-3809: a plain search over a settled window records the data
        // identity it read, bracketed before selection and after commit, so a
        // later identical search can be re-served from these result pages.
        let reuse_before = if reuse_eligible(spec, &request, to_us) {
            window_reuse_identity(engine, pin, &spec.tenant_id, from_us, to_us).await.ok()
        } else {
            None
        };
        let membership = engine
            .membership(&request.query, &field_types, from_us, to_us)
            .await
            .map_err(|error| anyhow::anyhow!(error.to_string()))?;
        // Leases every selected part file locally before execution. NAN-3644:
        // a window over the cold ceiling runs its first stage in batches
        // instead, each batch leased and released in turn (see
        // `cold_batches`); the statement then reads the spooled rows.
        let (selection, batched) = match engine
            .select_with(from_us, to_us, &compiled.candidate_hints, membership.as_ref())
            .await
        {
            Ok(selection) => (Some(selection), None),
            Err(PartQueryError::ColdScanTooLarge { needed_bytes, .. }) if super::cold_batches::not_batchable(&compiled).is_none() => {
                let fence = super::cold_batches::BatchFence { scan_budget: Some(spec.scan_budget_bytes), cancelled: Some(cancelled) };
                let batched = Box::pin(engine.cold_batches(&compiled, (from_us, to_us), membership.as_ref(), needed_bytes, fence))
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
            (Some(selection), _) => plan_logs(selection, &compiled, None).map_err(|error| anyhow::anyhow!(error.to_string()))?,
            (None, Some(batched)) => batched.plan.clone(),
            (None, None) => bail!("search job has neither a selection nor a batched read"),
        };
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
        let aliases = plan.temporary_aliases.iter().cloned().collect::<BTreeSet<_>>();
        let plan = super::engine::with_memory_cap(plan, engine.job_memory_bytes());
        let output = writer.execute(plan).await.map_err(anyhow::Error::new)?;
        if cancelled.load(Ordering::Acquire) {
            bail!("search job was cancelled before result commit");
        }
        if !output_path.is_file() {
            bail!("durable search query did not produce its Parquet spool");
        }
        let execution = ResultExecutionMetadata {
            wall_seconds: started.elapsed().as_secs_f64(),
            engine_seconds: output.elapsed.as_secs_f64(),
            storage_rows: output.storage_rows_read,
            storage_bytes: output.storage_bytes_read,
            peak_rss_bytes: None,
            spill_bytes: None,
        };
        let reference = commit_job_result(results, spec, &output_path, &aliases, &execution).await?;
        drop(selection);
        drop(batched);
        if let Some(before) = reuse_before.filter(|_| reference.rows > 0 && reference.parts > 0) {
            record_reuse_marker(engine, results, pin, spec, &reference, (from_us, to_us), before).await;
        }
        Ok(reference)
    };
    crate::enrichment_read::execute(|| crate::enrichment_read::resolve(&tenant), work).await?
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
/// overlapping parts, read schema, enrichment read authority and query
/// artifacts ([`super::result_cache::window_identity`]).
pub async fn window_reuse_identity(engine: &PartQueryEngine, pin: &PartJobPin, tenant_id: &str, from_us: i64, to_us: i64) -> Result<String> {
    let (parts, _, _, _) = engine.snapshot(from_us, to_us).await.map_err(|error| anyhow::anyhow!(error.to_string()))?;
    let (_, schema) = engine.head_and_schema_fingerprint().await;
    let authority = crate::enrichment_read::resolve(tenant_id).await.cache_identity();
    let execution = format!("{}\0{}", pin.compiler_sha256, pin.native_artifact_sha256);
    Ok(super::result_cache::window_identity(&parts, schema.as_deref(), &authority, &execution))
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
    let after = match window_reuse_identity(engine, pin, &spec.tenant_id, from_us, to_us).await {
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
