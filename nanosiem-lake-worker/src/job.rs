// SPDX-License-Identifier: AGPL-3.0-or-later

//! Durable result artifacts for isolated lake-query jobs.
//!
//! The job specification is produced by Nano's trusted scheduler. It contains
//! no object-store credentials. The runner derives its tenant/job prefix and
//! reads storage credentials only from deployment-owned environment variables.

use anyhow::{bail, Context, Result};
use arrow_json::reader::infer_json_schema_from_seekable;
use arrow_json::{LineDelimitedWriter, ReaderBuilder};
use chrono::{DateTime, SecondsFormat, Utc};
use nanosiem_core::search::DurableLakeTask;
use opendal::{services::S3, Buffer, Operator};
use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;
use parquet::arrow::ArrowWriter;
use parquet::basic::{Compression, ZstdLevel};
use parquet::file::properties::WriterProperties;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{File, OpenOptions};
use std::io::{Cursor, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;

pub mod result_gc;

pub const JOB_SCHEMA_VERSION: u64 = 1;
pub const RESULT_MANIFEST_SCHEMA_VERSION: u64 = 1;
const MAX_JOB_QUERY_BYTES: usize = 262_144;
const MAX_JOB_RESULTS: usize = 1_000_000;
const MAX_PAGE_ROWS: usize = 50_000;

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ResourceClass {
    Medium,
    Large,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LakeQueryJobSpec {
    pub schema_version: u64,
    pub job_id: String,
    pub attempt_id: String,
    pub fence_token: String,
    pub tenant_id: String,
    pub generation_id: String,
    pub event_config_sha256: String,
    pub snapshot_id: i64,
    pub compiler_sha256: String,
    pub native_artifact_sha256: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hot_tail_manifest_sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hot_tail_snapshot_id: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hot_tail_id: Option<String>,
    pub resource_class: ResourceClass,
    /// Runner-owned scan allowance for this isolated attempt. Durable jobs may
    /// read more than the interactive lane while remaining finite and auditable.
    pub scan_budget_bytes: u64,
    pub submitted_at: DateTime<Utc>,
    pub scope_deny: BTreeSet<String>,
    /// Closed, server-authored product operation. This is deliberately kept
    /// separate from the public nPL request so a caller cannot manufacture a
    /// privileged view task or inject storage coordinates.
    pub task: DurableLakeTask,
    pub request: LakeQueryJobRequest,
    #[serde(default = "default_page_rows")]
    pub result_page_rows: usize,
    /// NAN-3078: the runner-signed moving-retention receipt for this attempt
    /// (shared tenants). Its contribution range is exactly `request.start..
    /// request.end`; the executing query[T] derives the current cutoff from it
    /// ([`Self::execution_window`]) and never reads before it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retention_proof: Option<nanosiem_core::search::DurableResultRetentionProof>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LakeQueryJobRequest {
    pub dataset: String,
    pub query: String,
    pub start: String,
    pub end: String,
    pub limit: usize,
    #[serde(default)]
    pub offset: usize,
    #[serde(default)]
    pub table_view: bool,
    #[serde(default)]
    pub anchor_us: Option<i64>,
    #[serde(default)]
    pub decay: Option<crate::risk::RiskDecay>,
    #[serde(default)]
    pub clear_boundaries: BTreeMap<String, i64>,
    #[serde(default)]
    pub minimum_clear_revision: Option<i64>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ResultArtifactRef {
    pub manifest_uri: String,
    pub manifest_sha256: String,
    pub rows: u64,
    pub parts: usize,
    #[serde(default)]
    pub has_more: bool,
    #[serde(default = "default_page_rows")]
    pub page_rows: usize,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ResultPage {
    pub page: usize,
    pub pages: usize,
    pub total_rows: u64,
    pub row_offset: u64,
    pub rows: Vec<Value>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ResultManifest {
    /// NAN-4168: read-time enrichment authority was removed. Manifests
    /// written before it may carry these; they are accepted and ignored.
    #[serde(default, rename = "enrichment_authority", skip_serializing)]
    pub legacy_enrichment_authority: Option<String>,
    #[serde(default, rename = "enrichment_expiry", skip_serializing)]
    pub legacy_enrichment_expiry: Option<i64>,
    pub schema_version: u64,
    pub job_id: String,
    pub attempt_id: String,
    pub fence_sha256: String,
    pub tenant_sha256: String,
    pub generation_id: String,
    pub event_config_sha256: String,
    pub snapshot_id: i64,
    pub compiler_sha256: String,
    pub native_artifact_sha256: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hot_tail_manifest_sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hot_tail_snapshot_id: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hot_tail_id: Option<String>,
    pub resource_class: ResourceClass,
    pub scope_deny_sha256: String,
    pub query_sha256: String,
    pub created_at: String,
    pub completed_at: String,
    pub rows: u64,
    pub has_more: bool,
    /// Top-level result columns whose arbitrary JSON values are stored as
    /// canonical JSON strings in Parquet. Arrow lists require one homogeneous
    /// child type, while product payloads legitimately contain tuple-shaped
    /// arrays such as `[timestamp, count]`. The verified reader restores these
    /// columns after checking the manifest and part digests.
    #[serde(default)]
    pub json_columns: BTreeSet<String>,
    pub parts: Vec<ResultPart>,
    pub execution: ResultExecutionMetadata,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ResultPart {
    pub relative_path: String,
    pub rows: u64,
    pub bytes: u64,
    pub sha256: String,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ResultExecutionMetadata {
    pub wall_seconds: f64,
    pub engine_seconds: f64,
    pub storage_rows: u64,
    pub storage_bytes: u64,
    pub peak_rss_bytes: Option<u64>,
    pub spill_bytes: Option<u64>,
}

#[derive(Debug, Clone)]
pub struct MaterializedJobResult {
    pub rows: Vec<Value>,
    pub has_more: bool,
    pub execution: ResultExecutionMetadata,
}

fn default_page_rows() -> usize {
    10_000
}

impl LakeQueryJobSpec {
    /// Snapshot 0 under an `event-0-<config>` identity: the bootstrap
    /// generation of an empty Iceberg table (NAN-2361 wave 8).
    pub fn is_bootstrap(&self) -> bool {
        self.snapshot_id == 0 && self.generation_id.starts_with("event-0-")
    }

    pub fn validate(&self) -> Result<()> {
        if self.schema_version != JOB_SCHEMA_VERSION {
            bail!("unsupported lake-query job schema version");
        }
        for (name, value, max) in [
            ("job ID", self.job_id.as_str(), 128_usize),
            ("attempt ID", self.attempt_id.as_str(), 128),
            ("generation ID", self.generation_id.as_str(), 256),
            ("tenant ID", self.tenant_id.as_str(), 256),
        ] {
            if value.is_empty()
                || value.len() > max
                || !value
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
            {
                bail!("{name} is invalid");
            }
        }
        if self.job_id.bytes().all(|byte| byte == b'.')
            || self.attempt_id.bytes().all(|byte| byte == b'.')
        {
            bail!("job or attempt ID is an unsafe path component");
        }
        if self.fence_token.len() < 32
            || self.fence_token.len() > 512
            || self.fence_token.chars().any(char::is_control)
        {
            bail!("job fence token is invalid");
        }
        for (name, digest) in [
            ("event config", self.event_config_sha256.as_str()),
            ("compiler", self.compiler_sha256.as_str()),
            ("native artifact", self.native_artifact_sha256.as_str()),
        ] {
            if !valid_sha256(digest) {
                bail!("{name} SHA-256 is invalid");
            }
        }
        if self
            .hot_tail_manifest_sha256
            .as_deref()
            .is_some_and(|digest| !valid_sha256(digest))
            || self
                .hot_tail_id
                .as_deref()
                .is_some_and(|digest| !valid_sha256(digest))
            || !matches!(
                (&self.hot_tail_manifest_sha256, self.hot_tail_snapshot_id, self.is_bootstrap()),
                (None, None, _) | (Some(_), Some(1..), _) | (Some(_), Some(0), true)
            )
            || (self.hot_tail_manifest_sha256.is_none() && self.hot_tail_id.is_some())
        {
            bail!("job hot-tail generation pin is invalid");
        }
        // The bootstrap generation (NAN-2361 wave 8) is the only zero snapshot
        // admitted: an empty tenant's durable job runs over the empty
        // generation plus its signed hot tail and returns what is there.
        if self.snapshot_id <= 0 && !self.is_bootstrap() {
            bail!("job snapshot ID must be positive");
        }
        if !(1_u64 << 30..=1_u64 << 50).contains(&self.scan_budget_bytes) {
            bail!("job scan budget is outside its safety bound");
        }
        if !matches!(self.request.dataset.as_str(), "logs" | "risk")
            || self.request.query.is_empty()
            || self.request.query.len() > MAX_JOB_QUERY_BYTES
            || self
                .request
                .query
                .chars()
                .any(|character| character == '\0')
            || self.request.limit == 0
            || self.request.limit > MAX_JOB_RESULTS
            || self.request.offset > MAX_JOB_RESULTS
            || self.request.offset.saturating_add(self.request.limit) > MAX_JOB_RESULTS
            || self.request.clear_boundaries.len() > 10_000
            || self
                .request
                .minimum_clear_revision
                .is_some_and(|revision| revision < 0)
            || self.result_page_rows == 0
            || self.result_page_rows > MAX_PAGE_ROWS
        {
            bail!("job request violates its dataset, query, result, or page bound");
        }
        let start = DateTime::parse_from_rfc3339(&self.request.start)
            .context("job start is not RFC3339")?;
        let end =
            DateTime::parse_from_rfc3339(&self.request.end).context("job end is not RFC3339")?;
        if start >= end {
            bail!("job time range is empty or reversed");
        }
        if self.scope_deny.iter().any(|source| {
            source.is_empty() || source.len() > 512 || source.chars().any(char::is_control)
        }) {
            bail!("job source-scope deny set is invalid");
        }
        if self
            .request
            .clear_boundaries
            .iter()
            .any(|(entity, boundary)| {
                entity.is_empty()
                    || entity.len() > 4_096
                    || entity.chars().any(char::is_control)
                    || *boundary <= 0
            })
        {
            bail!("job risk-clear delta is invalid");
        }
        self.task
            .validate()
            .map_err(|error| anyhow::anyhow!(error.to_string()))?;
        Ok(())
    }

    /// NAN-3078: the event-time window this attempt may read at `now`.
    ///
    /// Without a proof this is the request window (dedicated tenants have no
    /// retention cutoff). With one, the proof must cover exactly the request
    /// window, and the start is raised to the proof's CURRENT cutoff, so a
    /// job that waited in the queue while the cutoff moved reads less, never
    /// expired events. A window the cutoff has fully passed is refused.
    pub fn execution_window(&self, now: DateTime<Utc>) -> Result<(DateTime<Utc>, DateTime<Utc>)> {
        let start = DateTime::parse_from_rfc3339(&self.request.start)
            .context("job start is not RFC3339")?
            .with_timezone(&Utc);
        let end = DateTime::parse_from_rfc3339(&self.request.end)
            .context("job end is not RFC3339")?
            .with_timezone(&Utc);
        let Some(proof) = self.retention_proof.as_ref() else {
            return Ok((start, end));
        };
        if proof.min_event_time_micros != start.timestamp_micros()
            || proof.max_event_time_micros != end.timestamp_micros()
        {
            bail!("job retention proof does not cover exactly its request window");
        }
        let floor = proof
            .execution_floor(now)
            .map_err(|error| anyhow::anyhow!(error.to_string()))?;
        let start = start.max(floor);
        if start >= end {
            bail!("job window is entirely past the tenant's retention cutoff");
        }
        Ok((start, end))
    }

    pub fn validate_generation(
        &self,
        generation_id: &str,
        event_config_sha256: &str,
        snapshot_id: i64,
        compiler_sha256: &str,
        native_artifact_sha256: &str,
    ) -> Result<()> {
        if self.generation_id != generation_id
            || self.event_config_sha256 != event_config_sha256
            || self.snapshot_id != snapshot_id
            || self.compiler_sha256 != compiler_sha256
            || self.native_artifact_sha256 != native_artifact_sha256
        {
            bail!("job execution generation differs from its immutable admission pin");
        }
        Ok(())
    }
}

/// NAN-2653: the one structured stdout line an isolated job child emits right
/// before exiting when its compiler/native artifact differs from the job's
/// immutable admission pin. The durable runner matches only this line (never
/// free-form stderr) and hands the job back to the pod that admitted it.
pub const PIN_MISMATCH_LINE_KEY: &str = "durable_pin_mismatch";

pub fn pin_mismatch_line() -> String {
    serde_json::json!({ PIN_MISMATCH_LINE_KEY: true }).to_string()
}

/// True only for a complete JSON object whose sole member is
/// `"durable_pin_mismatch": true`.
pub fn is_pin_mismatch_line(line: &[u8]) -> bool {
    let Ok(serde_json::Value::Object(object)) = serde_json::from_slice(line) else {
        return false;
    };
    object.len() == 1 && object.get(PIN_MISMATCH_LINE_KEY) == Some(&serde_json::Value::Bool(true))
}

pub fn stdout_reports_pin_mismatch(stdout: &[u8]) -> bool {
    stdout
        .split(|byte| *byte == b'\n')
        .any(is_pin_mismatch_line)
}

pub async fn commit_result(
    result_root: &str,
    spec: &LakeQueryJobSpec,
    result: MaterializedJobResult,
) -> Result<ResultArtifactRef> {
    spec.validate()?;
    let staged = stage_result(spec, result)?;
    let reference = if result_root.starts_with("s3://") {
        commit_s3(result_root, spec, staged).await?
    } else {
        commit_local(result_root, spec, staged)?
    };
    Ok(reference)
}

/// Commit a query result already materialized as Parquet without loading the
/// complete result into Rust memory. The isolated chDB process may spill and
/// write this source file directly; this pass only re-chunks Arrow batches into
/// transport-sized, independently checksummed result pages.
pub async fn commit_parquet_result(
    result_root: &str,
    spec: &LakeQueryJobSpec,
    parquet_path: &Path,
    has_more: bool,
    execution: ResultExecutionMetadata,
) -> Result<ResultArtifactRef> {
    spec.validate()?;
    let staged = stage_parquet_result(
        spec,
        parquet_path,
        has_more,
        execution,
        0,
        None,
        &BTreeSet::new(),
    )?;
    let reference = if result_root.starts_with("s3://") {
        commit_s3(result_root, spec, staged).await?
    } else {
        commit_local(result_root, spec, staged)?
    };
    Ok(reference)
}

/// Commit a chDB-written Parquet spool while keeping only the caller-visible
/// result envelope. Durable search compiles one sentinel row beyond the
/// requested limit and may add planner-only columns used to bind exact object
/// ranges. Neither belongs in the published result artifact.
pub async fn commit_bounded_parquet_result(
    result_root: &str,
    spec: &LakeQueryJobSpec,
    parquet_path: &Path,
    row_offset: usize,
    max_rows: usize,
    excluded_columns: &BTreeSet<String>,
    execution: ResultExecutionMetadata,
) -> Result<ResultArtifactRef> {
    spec.validate()?;
    if row_offset != spec.request.offset
        || max_rows == 0
        || max_rows > spec.request.limit
        || row_offset.saturating_add(max_rows) > MAX_JOB_RESULTS
    {
        bail!("bounded query-result row envelope is invalid");
    }
    let staged = stage_parquet_result(
        spec,
        parquet_path,
        false,
        execution,
        row_offset,
        Some(max_rows),
        excluded_columns,
    )?;
    let reference = if result_root.starts_with("s3://") {
        commit_s3(result_root, spec, staged).await?
    } else {
        commit_local(result_root, spec, staged)?
    };
    Ok(reference)
}

/// [`commit_bounded_parquet_result`] through an explicitly granted operator
/// over `result_root`'s bucket (query[T]'s exchanged `job_results`
/// credential; NAN-3042). No ambient environment credential, serialized
/// writer or local-filesystem fallback is consulted.
#[allow(clippy::too_many_arguments)]
pub async fn commit_bounded_parquet_result_to(
    operator: &Operator,
    result_root: &str,
    spec: &LakeQueryJobSpec,
    parquet_path: &Path,
    row_offset: usize,
    max_rows: usize,
    excluded_columns: &BTreeSet<String>,
    execution: ResultExecutionMetadata,
) -> Result<ResultArtifactRef> {
    spec.validate()?;
    if row_offset != spec.request.offset
        || max_rows == 0
        || max_rows > spec.request.limit
        || row_offset.saturating_add(max_rows) > MAX_JOB_RESULTS
    {
        bail!("bounded query-result row envelope is invalid");
    }
    let (bucket, root_prefix) = parse_s3_root(result_root)?;
    let staged = stage_parquet_result(
        spec,
        parquet_path,
        false,
        execution,
        row_offset,
        Some(max_rows),
        excluded_columns,
    )?;
    let prefix = join_object_prefix(root_prefix, &artifact_prefix(spec));
    let reference = write_staged_s3(operator, bucket, &prefix, spec, &staged).await?;
    Ok(reference)
}

/// [`commit_result`] of a materialized product result through an explicitly
/// granted operator over `result_root`'s bucket (query[T]'s exchanged
/// `job_results` credential; NAN-3078).
pub async fn commit_result_to(
    operator: &Operator,
    result_root: &str,
    spec: &LakeQueryJobSpec,
    result: MaterializedJobResult,
) -> Result<ResultArtifactRef> {
    spec.validate()?;
    let (bucket, root_prefix) = parse_s3_root(result_root)?;
    let staged = stage_result(spec, result)?;
    let prefix = join_object_prefix(root_prefix, &artifact_prefix(spec));
    let reference = write_staged_s3(operator, bucket, &prefix, spec, &staged).await?;
    Ok(reference)
}

/// The manifest URI a fenced attempt must publish under `result_root`:
/// `{root}/tenant-{sha256(T)}/job-{job}/attempt-{attempt}/manifest.json`.
/// `lake_job_runner` accepts a cell result only when it is exactly this.
pub fn expected_manifest_uri(result_root: &str, tenant_id: &str, job_id: &str, attempt_id: &str) -> String {
    format!(
        "{}/tenant-{}/job-{job_id}/attempt-{attempt_id}/manifest.json",
        result_root.trim_end_matches('/'),
        sha256(tenant_id.as_bytes()),
    )
}

pub(crate) struct StagedResult {
    pub(crate) directory: tempfile::TempDir,
    pub(crate) manifest: ResultManifest,
    pub(crate) manifest_bytes: Vec<u8>,
}

fn stage_result(spec: &LakeQueryJobSpec, result: MaterializedJobResult) -> Result<StagedResult> {
    let directory = tempfile::tempdir().context("create query-result staging directory")?;
    let json_columns = dynamic_json_columns(&result.rows)?;
    let encoded_rows = encode_dynamic_json_columns(&result.rows, &json_columns)?;
    let schema = if encoded_rows.is_empty() {
        None
    } else {
        Some(infer_result_schema(&encoded_rows)?)
    };
    let properties = WriterProperties::builder()
        .set_compression(Compression::ZSTD(ZstdLevel::try_new(6)?))
        .set_max_row_group_row_count(Some(8_192))
        .build();
    let mut parts = Vec::new();
    for (index, rows) in encoded_rows.chunks(spec.result_page_rows).enumerate() {
        let relative_path = format!("part-{index:06}.parquet");
        let output = directory.path().join(&relative_path);
        let schema = schema
            .clone()
            .context("non-empty result has no Arrow schema")?;
        let bytes = parquet_page(schema, rows, properties.clone())?;
        write_new_file(&output, &bytes)?;
        parts.push(ResultPart {
            relative_path,
            rows: u64::try_from(rows.len())?,
            bytes: u64::try_from(bytes.len())?,
            sha256: sha256(&bytes),
        });
    }
    let manifest = result_manifest(
        spec,
        u64::try_from(result.rows.len())?,
        result.has_more,
        json_columns,
        parts,
        result.execution,
    )?;
    stage_manifest(directory, manifest)
}

struct OpenParquetPart {
    relative_path: String,
    writer: ArrowWriter<File>,
    rows: usize,
}

fn stage_parquet_result(
    spec: &LakeQueryJobSpec,
    parquet_path: &Path,
    has_more: bool,
    execution: ResultExecutionMetadata,
    row_offset: usize,
    max_rows: Option<usize>,
    excluded_columns: &BTreeSet<String>,
) -> Result<StagedResult> {
    let directory = tempfile::tempdir().context("create query-result staging directory")?;
    let source = File::open(parquet_path)
        .with_context(|| format!("open query-result Parquet {}", parquet_path.display()))?;
    let builder = ParquetRecordBatchReaderBuilder::try_new(source)?;
    let source_rows = builder.metadata().file_metadata().num_rows();
    if source_rows < 0 {
        bail!("query-result Parquet reported a negative row count");
    }
    let source_rows = u64::try_from(source_rows)?;
    let source_schema = builder.schema().clone();
    let projection = source_schema
        .fields()
        .iter()
        .enumerate()
        .filter_map(|(index, field)| (!excluded_columns.contains(field.name())).then_some(index))
        .collect::<Vec<_>>();
    if projection.is_empty() && source_rows > 0 {
        bail!("query-result projection removed every result column");
    }
    let schema = Arc::new(source_schema.project(&projection)?);
    let reader = builder
        .with_batch_size(spec.result_page_rows.min(8_192).max(1))
        .build()?;
    let properties = WriterProperties::builder()
        .set_compression(Compression::ZSTD(ZstdLevel::try_new(6)?))
        .set_max_row_group_row_count(Some(8_192))
        .build();
    let mut parts = Vec::new();
    let mut open: Option<OpenParquetPart> = None;
    let mut total_rows = 0_u64;
    let mut rows_to_skip = row_offset;

    'batches: for batch in reader {
        let batch = batch.context("read query-result Parquet batch")?;
        if rows_to_skip >= batch.num_rows() {
            rows_to_skip -= batch.num_rows();
            continue;
        }
        let batch = batch
            .slice(rows_to_skip, batch.num_rows() - rows_to_skip)
            .project(&projection)?;
        rows_to_skip = 0;
        let mut offset = 0;
        while offset < batch.num_rows() {
            let remaining = max_rows
                .map(|max_rows| {
                    max_rows.saturating_sub(usize::try_from(total_rows).unwrap_or(usize::MAX))
                })
                .unwrap_or(batch.num_rows() - offset);
            if remaining == 0 {
                break 'batches;
            }
            if open.is_none() {
                let relative_path = format!("part-{:06}.parquet", parts.len());
                let output = directory.path().join(&relative_path);
                let file = OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(&output)?;
                open = Some(OpenParquetPart {
                    relative_path,
                    writer: ArrowWriter::try_new(file, schema.clone(), Some(properties.clone()))?,
                    rows: 0,
                });
            }
            let part = open.as_mut().context("result page writer disappeared")?;
            let available = spec.result_page_rows.saturating_sub(part.rows);
            let take = available.min(batch.num_rows() - offset).min(remaining);
            part.writer.write(&batch.slice(offset, take))?;
            part.rows += take;
            total_rows = total_rows
                .checked_add(u64::try_from(take)?)
                .context("query-result row count overflowed")?;
            offset += take;
            if part.rows == spec.result_page_rows {
                let finished = open.take().context("result page writer disappeared")?;
                parts.push(finish_parquet_part(directory.path(), finished)?);
            }
        }
    }
    if let Some(part) = open {
        parts.push(finish_parquet_part(directory.path(), part)?);
    }
    let requested_end = row_offset.saturating_add(max_rows.unwrap_or(usize::MAX));
    let has_more = has_more
        || max_rows.is_some_and(|_| source_rows > u64::try_from(requested_end).unwrap_or(u64::MAX));
    let manifest = result_manifest(
        spec,
        total_rows,
        has_more,
        BTreeSet::new(),
        parts,
        execution,
    )?;
    stage_manifest(directory, manifest)
}

fn finish_parquet_part(directory: &Path, part: OpenParquetPart) -> Result<ResultPart> {
    let file = part.writer.into_inner()?;
    file.sync_all()?;
    drop(file);
    let path = directory.join(&part.relative_path);
    let (bytes, digest) = file_size_and_sha256(&path)?;
    Ok(ResultPart {
        relative_path: part.relative_path,
        rows: u64::try_from(part.rows)?,
        bytes,
        sha256: digest,
    })
}

fn file_size_and_sha256(path: &Path) -> Result<(u64, String)> {
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut bytes = 0_u64;
    let mut buffer = vec![0_u8; 1024 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
        bytes = bytes
            .checked_add(u64::try_from(read)?)
            .context("query-result part size overflowed")?;
    }
    Ok((bytes, hex::encode(hasher.finalize())))
}

fn result_manifest(
    spec: &LakeQueryJobSpec,
    rows: u64,
    has_more: bool,
    json_columns: BTreeSet<String>,
    parts: Vec<ResultPart>,
    execution: ResultExecutionMetadata,
) -> Result<ResultManifest> {
    let completed_at = Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true);
    let query_sha256 = sha256(spec.request.query.as_bytes());
    Ok(ResultManifest {
        legacy_enrichment_authority: None,
        // Not written since NAN-4168 (no read-time enrichment authority).
        legacy_enrichment_expiry: None,
        schema_version: RESULT_MANIFEST_SCHEMA_VERSION,
        job_id: spec.job_id.clone(),
        attempt_id: spec.attempt_id.clone(),
        fence_sha256: sha256(spec.fence_token.as_bytes()),
        tenant_sha256: sha256(spec.tenant_id.as_bytes()),
        generation_id: spec.generation_id.clone(),
        event_config_sha256: spec.event_config_sha256.clone(),
        snapshot_id: spec.snapshot_id,
        compiler_sha256: spec.compiler_sha256.clone(),
        native_artifact_sha256: spec.native_artifact_sha256.clone(),
        hot_tail_manifest_sha256: spec.hot_tail_manifest_sha256.clone(),
        hot_tail_snapshot_id: spec.hot_tail_snapshot_id,
        hot_tail_id: spec.hot_tail_id.clone(),
        resource_class: spec.resource_class,
        scope_deny_sha256: scope_digest(&spec.scope_deny)?,
        query_sha256,
        created_at: spec
            .submitted_at
            .to_rfc3339_opts(SecondsFormat::Millis, true),
        completed_at,
        rows,
        has_more,
        json_columns,
        parts,
        execution,
    })
}

fn stage_manifest(directory: tempfile::TempDir, manifest: ResultManifest) -> Result<StagedResult> {
    let mut manifest_bytes = serde_json::to_vec_pretty(&manifest)?;
    manifest_bytes.push(b'\n');
    Ok(StagedResult {
        directory,
        manifest,
        manifest_bytes,
    })
}

fn commit_local(
    result_root: &str,
    spec: &LakeQueryJobSpec,
    staged: StagedResult,
) -> Result<ResultArtifactRef> {
    let root = result_root.strip_prefix("file://").unwrap_or(result_root);
    if root.is_empty() {
        bail!("local result root is empty");
    }
    let root = PathBuf::from(root);
    std::fs::create_dir_all(&root)?;
    let prefix = artifact_prefix(spec);
    let destination = root.join(&prefix);
    std::fs::create_dir_all(&destination)?;
    for part in &staged.manifest.parts {
        let source = staged.directory.path().join(&part.relative_path);
        let destination_part = destination.join(&part.relative_path);
        let bytes = std::fs::read(&source)?;
        write_new_file(&destination_part, &bytes)?;
    }
    let manifest_path = destination.join("manifest.json");
    write_new_file(&manifest_path, &staged.manifest_bytes)
        .context("commit local result manifest; an executor may already own this fence")?;
    Ok(ResultArtifactRef {
        manifest_uri: format!("file://{}", manifest_path.display()),
        manifest_sha256: sha256(&staged.manifest_bytes),
        rows: staged.manifest.rows,
        parts: staged.manifest.parts.len(),
        has_more: staged.manifest.has_more,
        page_rows: spec.result_page_rows,
    })
}

async fn commit_s3(
    result_root: &str,
    spec: &LakeQueryJobSpec,
    staged: StagedResult,
) -> Result<ResultArtifactRef> {
    let (bucket, root_prefix) = parse_s3_root(result_root)?;
    let prefix = join_object_prefix(root_prefix, &artifact_prefix(spec));
    if crate::shared_mode::active() {
        return crate::shared_mode::hooks()
            .commit_durable_result(DurableResultPublication {
                bucket,
                root_prefix,
                artifact_prefix: &prefix,
                spec,
                staged,
            })
            .await;
    }
    crate::shared_mode::require_serialized_writer_authority("durable_query_result")?;
    let operator = result_s3_operator(bucket)?;
    write_staged_s3(&operator, bucket, &prefix, spec, &staged).await
}

/// Pages first, then `manifest.json` (the commit pointer), under `prefix`.
async fn write_staged_s3(
    operator: &Operator,
    bucket: &str,
    prefix: &str,
    spec: &LakeQueryJobSpec,
    staged: &StagedResult,
) -> Result<ResultArtifactRef> {
    for part in &staged.manifest.parts {
        let bytes = std::fs::read(staged.directory.path().join(&part.relative_path))?;
        operator
            .write(
                &join_object_prefix(prefix, &part.relative_path),
                Buffer::from(bytes),
            )
            .await?;
    }
    let manifest_key = join_object_prefix(prefix, "manifest.json");
    // The attempt/fence pair makes this prefix unique, and Dragonfly permits
    // only the current fenced lease owner to publish its pointer. S3 writes
    // are atomic at the object boundary, so committing the manifest after all
    // pages is sufficient and works across AWS S3, RustFS, GCS, and Azure S3
    // gateways. OpenDAL's S3 service does not expose conditional writes.
    operator
        .write(&manifest_key, Buffer::from(staged.manifest_bytes.clone()))
        .await?;
    Ok(ResultArtifactRef {
        manifest_uri: format!("s3://{bucket}/{manifest_key}"),
        manifest_sha256: sha256(&staged.manifest_bytes),
        rows: staged.manifest.rows,
        parts: staged.manifest.parts.len(),
        has_more: staged.manifest.has_more,
        page_rows: spec.result_page_rows,
    })
}

/// A staged durable result for the shared-mode writer
/// ([`crate::shared_mode::SharedModeHooks::commit_durable_result`]).
#[cfg_attr(not(feature = "enterprise"), allow(dead_code))]
pub(crate) struct DurableResultPublication<'a> {
    pub(crate) bucket: &'a str,
    pub(crate) root_prefix: &'a str,
    pub(crate) artifact_prefix: &'a str,
    pub(crate) spec: &'a LakeQueryJobSpec,
    pub(crate) staged: StagedResult,
}

#[cfg_attr(not(feature = "enterprise"), allow(dead_code))]
pub(crate) async fn publish_manifest_last<F, M>(parts: impl IntoIterator<Item = F>, manifest: M) -> Result<()>
where
    F: std::future::Future<Output = Result<()>>,
    M: std::future::Future<Output = Result<()>>,
{
    // Bound memory and network work; drain issued publications on failure so
    // retries never race a dropped sibling's ambiguous completion.
    crate::pipeline::publish_bounded(parts, 4).await?;
    manifest.await
}

fn infer_result_schema(rows: &[Value]) -> Result<Arc<arrow_schema::Schema>> {
    let encoded = encode_json_lines(rows)?;
    let mut cursor = Cursor::new(encoded);
    let (schema, _) = infer_json_schema_from_seekable(&mut cursor, None)
        .context("infer query-result Arrow schema")?;
    Ok(Arc::new(schema))
}

/// Identify top-level columns that need the lossless arbitrary-JSON envelope.
/// Scalar-only query results stay byte-for-byte on the existing Arrow path.
fn dynamic_json_columns(rows: &[Value]) -> Result<BTreeSet<String>> {
    let mut columns = BTreeSet::new();
    for row in rows {
        let object = row
            .as_object()
            .context("query result row is not an object")?;
        for (name, value) in object {
            // An all-null column is inferred as Arrow Null and disappears from
            // the JSON writer on readback. Put null-bearing columns through the
            // same envelope so optional typed-product fields round-trip too.
            if value.is_null() || value.is_object() || value.is_array() {
                columns.insert(name.clone());
            }
        }
    }
    if columns.len() > 1_024
        || columns
            .iter()
            .any(|name| name.is_empty() || name.len() > 1_024 || name.chars().any(char::is_control))
    {
        bail!("query result JSON-column inventory is invalid");
    }
    Ok(columns)
}

fn encode_dynamic_json_columns(
    rows: &[Value],
    json_columns: &BTreeSet<String>,
) -> Result<Vec<Value>> {
    rows.iter()
        .map(|row| {
            let mut object = row
                .as_object()
                .context("query result row is not an object")?
                .clone();
            for name in json_columns {
                if let Some(value) = object.get_mut(name) {
                    *value = Value::String(serde_json::to_string(value)?);
                }
            }
            Ok(Value::Object(object))
        })
        .collect()
}

fn restore_dynamic_json_columns(rows: &mut [Value], json_columns: &BTreeSet<String>) -> Result<()> {
    for row in rows {
        let object = row
            .as_object_mut()
            .context("query result row is not an object")?;
        for name in json_columns {
            let Some(encoded) = object.get(name).and_then(Value::as_str) else {
                bail!("query result JSON column is absent or not encoded as a string");
            };
            object.insert(
                name.clone(),
                serde_json::from_str(encoded)
                    .with_context(|| format!("decode query-result JSON column {name}"))?,
            );
        }
    }
    Ok(())
}

fn parquet_page(
    schema: Arc<arrow_schema::Schema>,
    rows: &[Value],
    properties: WriterProperties,
) -> Result<Vec<u8>> {
    let encoded = encode_json_lines(rows)?;
    let reader = ReaderBuilder::new(schema.clone())
        .with_batch_size(rows.len().min(8_192).max(1))
        .build(Cursor::new(encoded))?;
    let mut writer = ArrowWriter::try_new(Vec::new(), schema, Some(properties))?;
    for batch in reader {
        writer.write(&batch.context("decode query-result JSON page")?)?;
    }
    Ok(writer.into_inner()?)
}

fn encode_json_lines(rows: &[Value]) -> Result<Vec<u8>> {
    let mut encoded = Vec::new();
    for row in rows {
        if !row.is_object() {
            bail!("query result row is not an object");
        }
        serde_json::to_writer(&mut encoded, row)?;
        encoded.push(b'\n');
    }
    Ok(encoded)
}

fn write_new_file(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

fn artifact_prefix(spec: &LakeQueryJobSpec) -> String {
    format!(
        "tenant-{}/job-{}/attempt-{}",
        sha256(spec.tenant_id.as_bytes()),
        spec.job_id,
        spec.attempt_id
    )
}

fn scope_digest(scope: &BTreeSet<String>) -> Result<String> {
    Ok(sha256(&serde_json::to_vec(scope)?))
}

pub(crate) fn sha256(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

pub(crate) fn parse_s3_root(value: &str) -> Result<(&str, &str)> {
    let value = value
        .strip_prefix("s3://")
        .context("result root is not an s3:// URI")?;
    let (bucket, prefix) = value.split_once('/').unwrap_or((value, ""));
    if bucket.is_empty()
        || bucket.chars().any(char::is_control)
        || prefix.split('/').any(|component| component == "..")
        || prefix.chars().any(char::is_control)
    {
        bail!("result S3 root is invalid");
    }
    Ok((bucket, prefix.trim_matches('/')))
}

pub(crate) fn join_object_prefix(left: &str, right: &str) -> String {
    match (left.trim_matches('/'), right.trim_matches('/')) {
        ("", right) => right.to_string(),
        (left, "") => left.to_string(),
        (left, right) => format!("{left}/{right}"),
    }
}

pub(crate) fn result_s3_operator(bucket: &str) -> Result<Operator> {
    let region = required_env("NANO_LAKE_RESULT_S3_REGION")?;
    let mut builder = S3::default().bucket(bucket).region(&region);
    if let Some(endpoint) = optional_env("NANO_LAKE_RESULT_S3_ENDPOINT") {
        builder = builder.endpoint(&endpoint);
    }
    if env_bool("NANO_LAKE_RESULT_S3_VIRTUAL_HOST_STYLE", false)? {
        builder = builder.enable_virtual_host_style();
    }
    if !env_bool("NANO_LAKE_RESULT_S3_DEFAULT_CREDENTIALS", true)? {
        builder = builder
            .access_key_id(&required_env("NANO_LAKE_RESULT_S3_ACCESS_KEY_ID")?)
            .secret_access_key(&required_env("NANO_LAKE_RESULT_S3_SECRET_ACCESS_KEY")?)
            .disable_config_load()
            .disable_ec2_metadata();
        if let Some(token) = optional_env("NANO_LAKE_RESULT_S3_SESSION_TOKEN") {
            builder = builder.session_token(&token);
        }
    }
    Ok(Operator::new(builder)?.layer(crate::r2_ops::layer()).finish())
}

fn required_env(name: &str) -> Result<String> {
    optional_env(name).with_context(|| format!("{name} is required"))
}

fn optional_env(name: &str) -> Option<String> {
    std::env::var(name)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn env_bool(name: &str, default: bool) -> Result<bool> {
    let Some(value) = optional_env(name) else {
        return Ok(default);
    };
    match value.to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" => Ok(true),
        "0" | "false" | "no" => Ok(false),
        _ => bail!("{name} must be true or false"),
    }
}

pub fn read_local_manifest(reference: &ResultArtifactRef) -> Result<ResultManifest> {
    let path = reference
        .manifest_uri
        .strip_prefix("file://")
        .context("result manifest is not local")?;
    let bytes = std::fs::read(path)?;
    if sha256(&bytes) != reference.manifest_sha256 {
        bail!("result manifest checksum differs from its job-store pointer");
    }
    let manifest: ResultManifest = serde_json::from_slice(&bytes)?;
    if manifest.schema_version != RESULT_MANIFEST_SCHEMA_VERSION {
        bail!("result manifest schema is unsupported");
    }
    Ok(manifest)
}

pub async fn read_result_page(
    reference: &ResultArtifactRef,
    expected_job_id: &str,
    expected_tenant_id: &str,
    page: usize,
) -> Result<ResultPage> {
    let (manifest, part_bytes) = if let Some(path) = reference.manifest_uri.strip_prefix("file://")
    {
        let manifest_bytes = std::fs::read(path)?;
        let manifest = validate_result_manifest(
            reference,
            expected_job_id,
            expected_tenant_id,
            &manifest_bytes,
        )?;
        let part = manifest
            .parts
            .get(page)
            .context("result page is out of range")?;
        let parent = Path::new(path)
            .parent()
            .context("result manifest has no parent directory")?;
        let bytes = std::fs::read(parent.join(&part.relative_path))?;
        (manifest, bytes)
    } else if reference.manifest_uri.starts_with("s3://") {
        let (bucket, _) = parse_s3_root(&reference.manifest_uri)?;
        let operator = result_s3_operator(bucket)?;
        read_s3_manifest_and_page(&operator, reference, expected_job_id, expected_tenant_id, page).await?
    } else {
        bail!("result manifest URI uses an unsupported scheme");
    };
    decode_result_page(manifest, part_bytes, page)
}

/// One page of a result in `bucket`, read with an explicitly granted
/// operator (query[T]'s exchanged `job_results` credential), never ambient
/// environment credentials or the local filesystem.
pub async fn read_result_page_from(
    operator: &Operator,
    bucket: &str,
    reference: &ResultArtifactRef,
    expected_job_id: &str,
    expected_tenant_id: &str,
    page: usize,
) -> Result<ResultPage> {
    let (manifest_bucket, _) = parse_s3_root(&reference.manifest_uri)?;
    if manifest_bucket != bucket {
        bail!("result manifest is outside the granted result bucket");
    }
    let (manifest, part_bytes) =
        read_s3_manifest_and_page(operator, reference, expected_job_id, expected_tenant_id, page).await?;
    decode_result_page(manifest, part_bytes, page)
}

async fn read_s3_manifest_and_page(
    operator: &Operator,
    reference: &ResultArtifactRef,
    expected_job_id: &str,
    expected_tenant_id: &str,
    page: usize,
) -> Result<(ResultManifest, Vec<u8>)> {
    let (_, manifest_key) = parse_s3_root(&reference.manifest_uri)?;
    if manifest_key.is_empty() || !manifest_key.ends_with("/manifest.json") {
        bail!("result manifest URI is invalid");
    }
    let manifest_bytes = operator.read(manifest_key).await?.to_vec();
    let manifest = validate_result_manifest(
        reference,
        expected_job_id,
        expected_tenant_id,
        &manifest_bytes,
    )?;
    let part = manifest
        .parts
        .get(page)
        .context("result page is out of range")?;
    let parent = manifest_key
        .strip_suffix("manifest.json")
        .context("result manifest URI is invalid")?;
    let bytes = operator
        .read(&format!("{parent}{}", part.relative_path))
        .await?
        .to_vec();
    Ok((manifest, bytes))
}

fn decode_result_page(
    manifest: ResultManifest,
    part_bytes: Vec<u8>,
    page: usize,
) -> Result<ResultPage> {
    let part = manifest
        .parts
        .get(page)
        .context("result page is out of range")?;
    if u64::try_from(part_bytes.len())? != part.bytes || sha256(&part_bytes) != part.sha256 {
        bail!("result page differs from its manifest fence");
    }
    let reader = ParquetRecordBatchReaderBuilder::try_new(bytes::Bytes::from(part_bytes))?
        .with_batch_size(8_192)
        .build()?;
    let mut json = LineDelimitedWriter::new(Vec::new());
    let mut rows_read = 0_u64;
    for batch in reader {
        let batch = batch?;
        rows_read = rows_read.saturating_add(u64::try_from(batch.num_rows())?);
        json.write(&batch)?;
    }
    json.finish()?;
    if rows_read != part.rows {
        bail!("result page row count differs from its manifest fence");
    }
    let mut rows = std::str::from_utf8(&json.into_inner())?
        .lines()
        .filter(|line| !line.is_empty())
        .map(serde_json::from_str)
        .collect::<std::result::Result<Vec<Value>, _>>()?;
    restore_dynamic_json_columns(&mut rows, &manifest.json_columns)?;
    let row_offset = manifest.parts[..page]
        .iter()
        .try_fold(0_u64, |total, part| total.checked_add(part.rows))
        .context("result page row offset overflowed")?;
    Ok(ResultPage {
        page,
        pages: manifest.parts.len(),
        total_rows: manifest.rows,
        row_offset,
        rows,
    })
}

fn validate_result_manifest(
    reference: &ResultArtifactRef,
    expected_job_id: &str,
    expected_tenant_id: &str,
    bytes: &[u8],
) -> Result<ResultManifest> {
    if sha256(bytes) != reference.manifest_sha256 {
        bail!("result manifest checksum differs from its job-store pointer");
    }
    let manifest: ResultManifest = serde_json::from_slice(bytes)?;
    if manifest.schema_version != RESULT_MANIFEST_SCHEMA_VERSION
        || manifest.job_id != expected_job_id
        || manifest.tenant_sha256 != sha256(expected_tenant_id.as_bytes())
        || manifest.rows != reference.rows
        || manifest.parts.len() != reference.parts
        || manifest.has_more != reference.has_more
        || manifest.json_columns.len() > 1_024
        || manifest
            .json_columns
            .iter()
            .any(|name| name.is_empty() || name.len() > 1_024 || name.chars().any(char::is_control))
        || reference.page_rows == 0
        || reference.page_rows > MAX_PAGE_ROWS
    {
        bail!("result manifest identity differs from its job-store pointer");
    }
    if (manifest.rows == 0) != manifest.parts.is_empty() {
        bail!("result manifest row and part counts are inconsistent");
    }
    let mut rows = 0_u64;
    for (index, part) in manifest.parts.iter().enumerate() {
        let expected_path = format!("part-{index:06}.parquet");
        if part.relative_path != expected_path
            || part.rows == 0
            || part.rows > u64::try_from(reference.page_rows)?
            || (index + 1 < manifest.parts.len()
                && part.rows != u64::try_from(reference.page_rows)?)
            || part.bytes == 0
            || !valid_sha256(&part.sha256)
        {
            bail!("result manifest part metadata is invalid");
        }
        rows = rows
            .checked_add(part.rows)
            .context("result manifest row count overflowed")?;
    }
    if rows != manifest.rows {
        bail!("result manifest part rows differ from its total row count");
    }
    Ok(manifest)
}

#[cfg(test)]
mod pin_mismatch_line_tests {
    use super::*;

    #[test]
    fn only_the_dedicated_structured_line_reports_a_pin_mismatch() {
        let line = pin_mismatch_line();
        assert!(is_pin_mismatch_line(line.as_bytes()));
        assert!(is_pin_mismatch_line(format!("{line}\n").as_bytes()));
        let stdout = format!("{{\"durable_phase\":\"hydrating_tail\"}}\n{line}\n");
        assert!(stdout_reports_pin_mismatch(stdout.as_bytes()));
        for impostor in [
            // Free-form text carrying the old error message is not a signal.
            "Error: job execution generation differs from its immutable admission pin",
            "{\"durable_pin_mismatch\":false}",
            "{\"durable_pin_mismatch\":\"true\"}",
            "{\"durable_pin_mismatch\":true,\"extra\":1}",
            "{\"fields\":{\"durable_pin_mismatch\":true}}",
            "log line mentioning durable_pin_mismatch true",
            "",
        ] {
            assert!(!is_pin_mismatch_line(impostor.as_bytes()), "{impostor}");
            assert!(!stdout_reports_pin_mismatch(impostor.as_bytes()), "{impostor}");
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;
    use std::fs::File;

    pub(crate) fn spec() -> LakeQueryJobSpec {
        LakeQueryJobSpec {
            schema_version: JOB_SCHEMA_VERSION,
            job_id: "019fe-job".to_string(),
            attempt_id: "attempt-1".to_string(),
            fence_token: "f".repeat(64),
            tenant_id: "tenant-a".to_string(),
            generation_id: "generation-1".to_string(),
            event_config_sha256: "a".repeat(64),
            snapshot_id: 42,
            compiler_sha256: "b".repeat(64),
            native_artifact_sha256: "c".repeat(64),
            hot_tail_manifest_sha256: None,
            hot_tail_snapshot_id: None,
            hot_tail_id: None,
            resource_class: ResourceClass::Medium,
            scan_budget_bytes: 64_u64 << 30,
            submitted_at: Utc::now(),
            scope_deny: BTreeSet::from(["secret-source".to_string()]),
            task: DurableLakeTask::SearchNplV1,
            request: LakeQueryJobRequest {
                dataset: "logs".to_string(),
                query: "metadata.log_source=windows_sysmon | stats count by process.name"
                    .to_string(),
                start: "2026-08-14T00:00:00Z".to_string(),
                end: "2026-08-14T01:00:00Z".to_string(),
                limit: 100,
                offset: 0,
                table_view: false,
                anchor_us: None,
                decay: None,
                clear_boundaries: BTreeMap::new(),
                minimum_clear_revision: None,
            },
            result_page_rows: 2,
            retention_proof: None,
        }
    }

    #[tokio::test]
    async fn result_pages_verify_concurrently_but_manifest_is_always_last() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        for fail in [false, true] {
            let finished = AtomicUsize::new(0);
            let active = AtomicUsize::new(0);
            let peak = AtomicUsize::new(0);
            let published = AtomicUsize::new(0);
            let pages = (0..6).map(|index| {
                let (finished, active, peak) = (&finished, &active, &peak);
                async move {
                    let count = active.fetch_add(1, Ordering::SeqCst) + 1;
                    peak.fetch_max(count, Ordering::SeqCst);
                    tokio::task::yield_now().await;
                    active.fetch_sub(1, Ordering::SeqCst);
                    finished.fetch_add(1, Ordering::SeqCst);
                    if fail && index == 0 { bail!("readback identity differs"); }
                    Ok(())
                }
            });
            let result = publish_manifest_last(pages, async {
                assert_eq!(finished.load(Ordering::SeqCst), 6);
                published.fetch_add(1, Ordering::SeqCst);
                Ok(())
            }).await;
            assert_eq!(result.is_err(), fail);
            assert_eq!(finished.load(Ordering::SeqCst), 6);
            assert_eq!(peak.load(Ordering::SeqCst), 4);
            assert_eq!(published.load(Ordering::SeqCst), usize::from(!fail));
        }
    }

    #[test]
    fn warm_jobs_reuse_only_the_same_tenant_pin_and_runtime() {
        let first = spec();
        let mut next = first.clone();
        next.job_id = "another-job".into();
        next.scope_deny.clear();
        next.request.query = "metadata.log_source = linux".into();
        assert!(same_warm_job_identity(&first, &next));
        for changed in 0..10 {
            let mut other = next.clone();
            match changed {
                0 => other.tenant_id = "other-tenant".into(),
                1 => other.snapshot_id += 1,
                2 => other.native_artifact_sha256 = "d".repeat(64),
                3 => other.compiler_sha256 = "e".repeat(64),
                4 => other.hot_tail_id = Some("new-tail".into()),
                5 => other.event_config_sha256 = "f".repeat(64),
                6 => other.resource_class = ResourceClass::Large,
                7 => other.scan_budget_bytes += 1,
                8 => other.hot_tail_manifest_sha256 = Some("d".repeat(64)),
                _ => other.hot_tail_snapshot_id = Some(43),
            }
            assert!(!same_warm_job_identity(&first, &other));
        }
    }

    #[test]
    fn job_spec_admits_only_the_bootstrap_zero_snapshot() {
        let mut job = spec();
        job.snapshot_id = 0;
        assert!(job.validate().is_err(), "a real generation id never carries snapshot 0");
        job.generation_id = format!("event-0-{}", &job.event_config_sha256[..16]);
        assert!(job.is_bootstrap());
        assert!(job.validate().is_ok());
        job.hot_tail_manifest_sha256 = Some("d".repeat(64));
        job.hot_tail_snapshot_id = Some(0);
        assert!(job.validate().is_ok(), "the bootstrap hot tail is pinned at 0");
        let mut real = spec();
        real.hot_tail_manifest_sha256 = Some("d".repeat(64));
        real.hot_tail_snapshot_id = Some(0);
        assert!(real.validate().is_err());
    }

    #[test]
    fn job_spec_rejects_paths_digests_and_reversed_time() {
        let mut invalid = spec();
        invalid.job_id = "../escape".to_string();
        assert!(invalid.validate().is_err());

        let mut invalid = spec();
        invalid.compiler_sha256 = "not-a-digest".to_string();
        assert!(invalid.validate().is_err());

        let mut invalid = spec();
        invalid.request.start = invalid.request.end.clone();
        assert!(invalid.validate().is_err());

        for unsafe_id in [".", "..", "..."] {
            let mut invalid = spec();
            invalid.job_id = unsafe_id.to_string();
            assert!(invalid.validate().is_err());

            let mut invalid = spec();
            invalid.attempt_id = unsafe_id.to_string();
            assert!(invalid.validate().is_err());
        }
    }

    #[tokio::test]
    async fn result_manifest_rejects_unsafe_or_inconsistent_part_metadata() {
        let root = tempfile::tempdir().unwrap();
        let spec = spec();
        let reference = commit_result(
            root.path().to_str().unwrap(),
            &spec,
            MaterializedJobResult {
                rows: vec![
                    serde_json::json!({"event": "one"}),
                    serde_json::json!({"event": "two"}),
                    serde_json::json!({"event": "three"}),
                ],
                has_more: false,
                execution: ResultExecutionMetadata::default(),
            },
        )
        .await
        .unwrap();
        let manifest_path = PathBuf::from(reference.manifest_uri.trim_start_matches("file://"));
        let original_bytes = std::fs::read(&manifest_path).unwrap();
        let original: ResultManifest = serde_json::from_slice(&original_bytes).unwrap();

        let cases = [
            {
                let mut manifest = original.clone();
                manifest.parts[0].relative_path = "../outside.parquet".to_string();
                manifest
            },
            {
                let mut manifest = original.clone();
                manifest.parts[0].rows = 1;
                manifest
            },
            {
                let mut manifest = original.clone();
                manifest.parts[0].sha256 = "not-a-digest".to_string();
                manifest
            },
        ];

        for manifest in cases {
            let bytes = serde_json::to_vec(&manifest).unwrap();
            let mut tampered_reference = reference.clone();
            tampered_reference.manifest_sha256 = sha256(&bytes);
            let error = validate_result_manifest(
                &tampered_reference,
                &spec.job_id,
                &spec.tenant_id,
                &bytes,
            )
            .unwrap_err();
            assert!(
                error.to_string().contains("result manifest part"),
                "unexpected manifest validation error: {error:#}"
            );
        }
    }

    #[tokio::test]
    async fn local_commit_is_manifest_last_paged_and_fenced() {
        let root = tempfile::tempdir().unwrap();
        let spec = spec();
        let rows = vec![
            serde_json::json!({"process": {"name": "a"}, "count": 3}),
            serde_json::json!({"process": {"name": "b"}, "count": 2}),
            serde_json::json!({"process": {"name": "c"}, "count": 1}),
        ];
        let reference = commit_result(
            root.path().to_str().unwrap(),
            &spec,
            MaterializedJobResult {
                rows: rows.clone(),
                has_more: false,
                execution: ResultExecutionMetadata::default(),
            },
        )
        .await
        .unwrap();
        assert_eq!(reference.rows, 3);
        assert_eq!(reference.parts, 2);
        assert_eq!(reference.page_rows, 2);
        let manifest = read_local_manifest(&reference).unwrap();
        assert_eq!(manifest.rows, 3);
        assert_eq!(manifest.parts.len(), 2);
        assert_eq!(manifest.fence_sha256, sha256(spec.fence_token.as_bytes()));
        let manifest_path = PathBuf::from(reference.manifest_uri.trim_start_matches("file://"));
        for part in &manifest.parts {
            let path = manifest_path.parent().unwrap().join(&part.relative_path);
            let bytes = std::fs::read(&path).unwrap();
            assert_eq!(sha256(&bytes), part.sha256);
            let rows = ParquetRecordBatchReaderBuilder::try_new(File::open(path).unwrap())
                .unwrap()
                .build()
                .unwrap()
                .map(|batch| batch.unwrap().num_rows())
                .sum::<usize>();
            assert_eq!(rows as u64, part.rows);
        }
        let first_page = read_result_page(&reference, &spec.job_id, &spec.tenant_id, 0)
            .await
            .unwrap();
        assert_eq!(first_page.pages, 2);
        assert_eq!(first_page.total_rows, 3);
        assert_eq!(first_page.row_offset, 0);
        assert_eq!(first_page.rows, rows[..2]);
        let second_page = read_result_page(&reference, &spec.job_id, &spec.tenant_id, 1)
            .await
            .unwrap();
        assert_eq!(second_page.row_offset, 2);
        assert_eq!(second_page.rows, rows[2..]);
        assert!(
            read_result_page(&reference, &spec.job_id, "another-tenant", 0)
                .await
                .is_err()
        );
        assert!(
            read_result_page(&reference, &spec.job_id, &spec.tenant_id, 2)
                .await
                .is_err()
        );

        let duplicate = commit_result(
            root.path().to_str().unwrap(),
            &spec,
            MaterializedJobResult {
                rows,
                has_more: false,
                execution: ResultExecutionMetadata::default(),
            },
        )
        .await;
        assert!(
            duplicate.is_err(),
            "the same attempt fence cannot commit twice"
        );
    }

    #[tokio::test]
    async fn typed_result_round_trips_heterogeneous_json_tuples() {
        let root = tempfile::tempdir().unwrap();
        let mut spec = spec();
        spec.job_id = "019fe-cloud-overview".to_string();
        spec.attempt_id = "attempt-cloud-overview".to_string();
        let rows = vec![serde_json::json!({
            "operation": "cloud_overview",
            "provider": null,
            "response": {
                "header": {"events_total": 47},
                "timeline": {
                    "points": [
                        ["2026-08-16T15:00:00Z", 47],
                        ["2026-08-16T16:00:00Z", 3]
                    ]
                },
                "accounts": [
                    ["aws", "123456789012", 19]
                ]
            }
        })];

        let reference = commit_result(
            root.path().to_str().unwrap(),
            &spec,
            MaterializedJobResult {
                rows: rows.clone(),
                has_more: false,
                execution: ResultExecutionMetadata::default(),
            },
        )
        .await
        .unwrap();
        let manifest = read_local_manifest(&reference).unwrap();
        assert_eq!(
            manifest.json_columns,
            BTreeSet::from(["provider".to_string(), "response".to_string()])
        );

        let page = read_result_page(&reference, &spec.job_id, &spec.tenant_id, 0)
            .await
            .unwrap();
        assert_eq!(page.rows, rows);
    }

    #[tokio::test]
    async fn parquet_commit_rechunks_without_materializing_one_result_vec() {
        let root = tempfile::tempdir().unwrap();
        let input = tempfile::tempdir().unwrap();
        let mut spec = spec();
        spec.attempt_id = "attempt-streamed-parquet".to_string();
        let rows = (0..5)
            .map(|index| serde_json::json!({"artifact": format!("hash-{index}"), "host_count": index}))
            .collect::<Vec<_>>();
        let schema = infer_result_schema(&rows).unwrap();
        let properties = WriterProperties::builder()
            .set_compression(Compression::ZSTD(ZstdLevel::try_new(6).unwrap()))
            .build();
        let source = input.path().join("source.parquet");
        write_new_file(&source, &parquet_page(schema, &rows, properties).unwrap()).unwrap();

        let reference = commit_parquet_result(
            root.path().to_str().unwrap(),
            &spec,
            &source,
            false,
            ResultExecutionMetadata::default(),
        )
        .await
        .unwrap();
        assert_eq!(reference.rows, 5);
        assert_eq!(reference.parts, 3);
        let mut restored = Vec::new();
        for page in 0..reference.parts {
            restored.extend(
                read_result_page(&reference, &spec.job_id, &spec.tenant_id, page)
                    .await
                    .unwrap()
                    .rows,
            );
        }
        assert_eq!(restored, rows);
    }

    // Interactive Search uses the same artifact writer at every result size:
    // no threshold suppresses a 50- or 500-row result, including offset jobs.
    #[tokio::test]
    async fn interactive_artifact_pages_have_no_materialization_threshold() {
        for (offset, limit, page_rows) in [(0, 500, 10_000), (50, 50, 10_000), (500, 500, 50)] {
            let root = tempfile::tempdir().unwrap();
            let input = tempfile::tempdir().unwrap();
            let mut spec = spec();
            spec.request.offset = offset;
            spec.request.limit = limit;
            spec.result_page_rows = page_rows;
            let rows = (0..offset + limit + 1)
                .map(|index| serde_json::json!({"event": index}))
                .collect::<Vec<_>>();
            let schema = infer_result_schema(&rows).unwrap();
            let source = input.path().join("source.parquet");
            let properties = WriterProperties::builder().build();
            write_new_file(&source, &parquet_page(schema, &rows, properties).unwrap()).unwrap();
            let reference = commit_bounded_parquet_result(
                root.path().to_str().unwrap(), &spec, &source, offset, limit,
                &BTreeSet::new(), ResultExecutionMetadata::default(),
            ).await.unwrap();
            assert_eq!(reference.rows, limit as u64);
            assert_eq!(reference.parts, limit.div_ceil(page_rows));
            assert!(reference.has_more);
            let mut restored = Vec::new();
            for page in 0..reference.parts {
                let result = read_result_page(&reference, &spec.job_id, &spec.tenant_id, page)
                    .await.unwrap();
                assert_eq!(result.row_offset, (page * page_rows) as u64);
                restored.extend(result.rows);
            }
            assert_eq!(restored, rows[offset..offset + limit]);
        }
    }

    #[tokio::test]
    async fn bounded_parquet_commit_drops_offset_sentinel_and_planner_columns() {
        let root = tempfile::tempdir().unwrap();
        let input = tempfile::tempdir().unwrap();
        let mut spec = spec();
        spec.attempt_id = "attempt-bounded-parquet".to_string();
        spec.request.offset = 1;
        spec.request.limit = 3;
        let rows = (0..5)
            .map(|index| {
                serde_json::json!({
                    "event": format!("event-{index}"),
                    "__nano_row_start": index,
                })
            })
            .collect::<Vec<_>>();
        let schema = infer_result_schema(&rows).unwrap();
        let properties = WriterProperties::builder()
            .set_compression(Compression::ZSTD(ZstdLevel::try_new(6).unwrap()))
            .build();
        let source = input.path().join("source.parquet");
        write_new_file(&source, &parquet_page(schema, &rows, properties).unwrap()).unwrap();

        let reference = commit_bounded_parquet_result(
            root.path().to_str().unwrap(),
            &spec,
            &source,
            1,
            3,
            &BTreeSet::from(["__nano_row_start".to_string()]),
            ResultExecutionMetadata::default(),
        )
        .await
        .unwrap();
        assert_eq!(reference.rows, 3);
        assert!(reference.has_more);
        assert_eq!(reference.parts, 2);
        let mut restored = Vec::new();
        for page in 0..reference.parts {
            restored.extend(
                read_result_page(&reference, &spec.job_id, &spec.tenant_id, page)
                    .await
                    .unwrap()
                    .rows,
            );
        }
        assert_eq!(
            restored,
            vec![
                serde_json::json!({"event": "event-1"}),
                serde_json::json!({"event": "event-2"}),
                serde_json::json!({"event": "event-3"}),
            ]
        );
    }

    #[tokio::test]
    async fn typed_retro_result_round_trips_as_one_object_artifact() {
        let root = tempfile::tempdir().unwrap();
        let mut spec = spec();
        spec.job_id = "019fe-retro".to_string();
        spec.task = DurableLakeTask::RetroV1 {
            indicators: vec!["198.51.100.25".to_string(), "203.0.113.9".to_string()],
            axis: "indicator".to_string(),
            submode: "list".to_string(),
            offset: 0,
            limit: 50,
        };
        let row = serde_json::json!({
            "submode": "list",
            "axis": "indicator",
            "total_hosts": 42,
            "total_indicators": 1,
            "rows": [{
                "value": "198.51.100.25",
                "type": "ip",
                "hits": 51_619,
                "hosts": 12,
                "total_hosts": 42,
                "first_seen": "2026-08-01T00:00:00Z",
                "last_seen": "2026-08-15T00:00:00Z",
                "field": "src_endpoint.ip",
                "verdict": "common"
            }],
            "no_hits": ["203.0.113.9"],
            "offset": 0,
            "limit": 50,
            "has_more": false
        });
        let reference = commit_result(
            root.path().to_str().unwrap(),
            &spec,
            MaterializedJobResult {
                rows: vec![row.clone()],
                has_more: false,
                execution: ResultExecutionMetadata::default(),
            },
        )
        .await
        .unwrap();
        let page = read_result_page(&reference, &spec.job_id, &spec.tenant_id, 0)
            .await
            .unwrap();
        assert_eq!(page.total_rows, 1);
        assert_eq!(page.rows, vec![row]);
    }

    #[tokio::test]
    async fn durable_result_manifest_and_page_tampering_fail_closed() {
        let root = tempfile::tempdir().unwrap();
        let rows = vec![
            serde_json::json!({"process": {"name": "a"}, "count": 3}),
            serde_json::json!({"process": {"name": "b"}, "count": 2}),
        ];

        let manifest_spec = spec();
        let manifest_reference = commit_result(
            root.path().to_str().unwrap(),
            &manifest_spec,
            MaterializedJobResult {
                rows: rows.clone(),
                has_more: false,
                execution: ResultExecutionMetadata::default(),
            },
        )
        .await
        .unwrap();
        let manifest_path = PathBuf::from(
            manifest_reference
                .manifest_uri
                .trim_start_matches("file://"),
        );
        let mut manifest_bytes = std::fs::read(&manifest_path).unwrap();
        manifest_bytes.extend_from_slice(b" ");
        std::fs::write(&manifest_path, manifest_bytes).unwrap();
        let manifest_error = read_result_page(
            &manifest_reference,
            &manifest_spec.job_id,
            &manifest_spec.tenant_id,
            0,
        )
        .await
        .unwrap_err();
        assert!(
            manifest_error
                .to_string()
                .contains("result manifest checksum differs"),
            "unexpected manifest-tamper error: {manifest_error:#}"
        );

        let mut page_spec = spec();
        page_spec.attempt_id = "attempt-page-tamper".to_string();
        let page_reference = commit_result(
            root.path().to_str().unwrap(),
            &page_spec,
            MaterializedJobResult {
                rows,
                has_more: false,
                execution: ResultExecutionMetadata::default(),
            },
        )
        .await
        .unwrap();
        let manifest = read_local_manifest(&page_reference).unwrap();
        let manifest_path =
            PathBuf::from(page_reference.manifest_uri.trim_start_matches("file://"));
        let part_path = manifest_path
            .parent()
            .unwrap()
            .join(&manifest.parts[0].relative_path);
        let mut part_bytes = std::fs::read(&part_path).unwrap();
        part_bytes[0] ^= 0xff;
        std::fs::write(&part_path, part_bytes).unwrap();
        let page_error =
            read_result_page(&page_reference, &page_spec.job_id, &page_spec.tenant_id, 0)
                .await
                .unwrap_err();
        assert!(
            page_error
                .to_string()
                .contains("result page differs from its manifest fence"),
            "unexpected page-tamper error: {page_error:#}"
        );
    }

    #[tokio::test]
    async fn empty_result_commits_without_fake_part() {
        let root = tempfile::tempdir().unwrap();
        let reference = commit_result(
            root.path().to_str().unwrap(),
            &spec(),
            MaterializedJobResult {
                rows: Vec::new(),
                has_more: false,
                execution: ResultExecutionMetadata::default(),
            },
        )
        .await
        .unwrap();
        let manifest = read_local_manifest(&reference).unwrap();
        assert_eq!(manifest.rows, 0);
        assert!(manifest.parts.is_empty());
    }
}

/// A warm process retains only one tenant's immutable event view and resource contract.
pub fn same_warm_job_identity(first: &LakeQueryJobSpec, next: &LakeQueryJobSpec) -> bool {
    first.resource_class == ResourceClass::Medium
        && next.resource_class == ResourceClass::Medium
        && first.request.dataset == "logs"
        && next.request.dataset == "logs"
        && first.task.is_search()
        && next.task.is_search()
        && first.tenant_id == next.tenant_id
        && first.generation_id == next.generation_id
        && first.event_config_sha256 == next.event_config_sha256
        && first.snapshot_id == next.snapshot_id
        && first.compiler_sha256 == next.compiler_sha256
        && first.native_artifact_sha256 == next.native_artifact_sha256
        && first.hot_tail_manifest_sha256 == next.hot_tail_manifest_sha256
        && first.hot_tail_snapshot_id == next.hot_tail_snapshot_id
        && first.hot_tail_id == next.hot_tail_id
        && first.scan_budget_bytes == next.scan_budget_bytes
}
