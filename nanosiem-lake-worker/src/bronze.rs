// SPDX-License-Identifier: AGPL-3.0-or-later

//! Canonical Vector-bronze admission into Nano's Iceberg event writer.
//!
//! Vector owns source parsing and durable Parquet delivery. This module turns
//! a bounded set of coordinator-selected, exact-version local copies into one
//! deterministic OCSF 1.9 publication batch. Storage discovery, object-version
//! fencing, and the durable publication ledger remain coordinator concerns.

use anyhow::{bail, Context, Result};
use arrow_json::LineDelimitedWriter;
use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;
use rayon::prelude::*;
use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use thiserror::Error;

use crate::enrichment::{BronzeIngestEnricher, IngestEnrichmentMetrics};
use crate::iceberg::{normalize_event, EventKind, EventRow, NormalizedEventBatch};
use crate::ingest_source_counters::{refusal_attribution, RefusedSources, SourceKey};

// These are safety bounds for one atomic publication, not tenant ingest quotas.
// Keep individual commits bounded so memory, retry cost, and failure blast radius
// remain predictable. High-rate deployments scale with sized writer output,
// deterministic input shards, and horizontally replicated publishers; they do
// not remove these bounds or turn one Iceberg commit into a multi-terabyte job.
// See `nanosiem-lake-worker/README.md` for the deployment contract.
pub const MAX_BRONZE_FILES: usize = 500;
pub const MAX_BRONZE_ROWS: usize = 250_000;
pub const MAX_BRONZE_BYTES: u64 = 1_073_741_824;

#[derive(Debug, Error)]
pub enum BronzeAdmissionError {
    #[error("Vector bronze replay identity {event_uid} has conflicting event data")]
    ConflictingReplay { event_uid: String },
}

/// Where per-batch admission CPU actually goes.
///
/// Measured because the extrapolated fleet size for a large tenant came out
/// absurd (~200 cores for 1 TB/day) off a per-event cost of ~5.2 ms. A columnar
/// bulk insert does the equivalent in microseconds, so the gap is in what this
/// path does PER EVENT, not in the storage format — and guessing which stage
/// owns it is how you optimise the wrong thing.
#[derive(Debug, Clone, Default, Serialize)]
pub struct AdmissionTimings {
    /// Parquet -> Arrow -> newline-delimited JSON bytes.
    pub decode_us: u64,
    /// `serde_json::from_slice` per row.
    pub json_parse_us: u64,
    /// IOC + IP-context + IPinfo enrichment.
    pub enrich_us: u64,
    /// `normalize_event`, which carries OCSF 1.9 contract validation.
    pub normalize_us: u64,
    /// Whole-file SHA-256 (per BYTE, unlike everything else here).
    pub hash_us: u64,
}

#[derive(Debug)]
pub struct BronzeAdmission {
    pub timings: AdmissionTimings,
    pub source_files: usize,
    pub source_rows: u64,
    pub source_bytes: u64,
    pub duplicate_rows_removed: u64,
    /// Rows dropped because another row of this admission carries the same
    /// `metadata.uid` with a different source identity (NAN-3719). A subset of
    /// `duplicate_rows_removed`. The conflict is row-scoped: one winner per
    /// uid is kept and every other row is still admitted.
    pub conflicting_replay_rows_dropped: u64,
    pub enrichment: IngestEnrichmentMetrics,
    pub files: Vec<BronzeFileAdmission>,
    pub batch: NormalizedEventBatch,
    /// Pre-enrichment semantic identities keyed by Vector's stable OCSF UID.
    ///
    /// This is deliberately captured before IOC, IP context, IPinfo, or
    /// prevalence decoration. A retry that crosses an enrichment rotation is
    /// still the same source event and must not become a conflicting replay.
    source_identity_digests: BTreeMap<String, [u8; 32]>,
}

impl BronzeAdmission {
    /// Values exposed only for the optional prevalence decorator. The source
    /// digest is intentionally fixed before decoration, while the batch keeps
    /// tenant and partition bindings private and revalidates them at staging.
    pub fn prevalence_inputs(&mut self) -> (Vec<&mut Value>, &mut IngestEnrichmentMetrics) {
        let events = self.batch.event_values_mut().collect();
        (events, &mut self.enrichment)
    }

    pub fn source_identity_digests(&self) -> &BTreeMap<String, [u8; 32]> {
        &self.source_identity_digests
    }

    /// Move the source identities out (lean part ingest compares them across
    /// batches, NAN-3704); the admission is then consumed for its rows.
    pub fn take_source_identity_digests(&mut self) -> BTreeMap<String, [u8; 32]> {
        std::mem::take(&mut self.source_identity_digests)
    }

    /// Retain the exact source identities that won the durable cross-cycle
    /// claim. Callers handle the all-replay case separately, so this method
    /// never creates an invalid empty normalized batch.
    pub fn retain_claimed_uids(&mut self, keep: &BTreeSet<String>) -> Result<()> {
        if keep.is_empty()
            || !keep
                .iter()
                .all(|uid| self.source_identity_digests.contains_key(uid))
        {
            bail!("bronze cross-cycle UID selection is empty or foreign");
        }
        self.batch.retain_source_event_uids(keep)?;
        self.source_identity_digests
            .retain(|uid, _| keep.contains(uid));
        if self.batch.len() != self.source_identity_digests.len() {
            bail!("bronze cross-cycle UID selection changed identity cardinality");
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct BronzeFileAdmission {
    pub path: PathBuf,
    pub rows: u64,
    pub bytes: u64,
    pub sha256: String,
}

struct AdmittedEvent {
    event_uid: String,
    digest: [u8; 32],
    time_ms: i64,
    event_hour: i32,
    row: EventRow,
    enrichment: IngestEnrichmentMetrics,
    timings: AdmissionTimings,
    platform_output: Option<PlatformOutput>,
    stamp_counts: StampCounts,
}

/// One admitted copy's live or shadow stamp counters (NAN-2361). They travel
/// with the copy's row and output through the UID merge, so the per-batch
/// summary counts each surviving UID once and never a losing duplicate.
#[derive(Clone, Debug, Default)]
struct StampCounts {
    #[cfg(all(feature = "enterprise", target_os = "linux"))]
    live: Option<crate::platform_stamping::LiveStampSummary>,
    #[cfg(all(feature = "enterprise", target_os = "linux"))]
    shadow: Option<crate::platform_stamping::ShadowComparisonSummary>,
}

/// The signed platform output one copy of an event carries, plus the claim
/// it came from. The claim identity decides which copy a batch keeps when one
/// UID was claimed more than once (NAN-2361).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct PlatformOutput {
    digest: [u8; 32],
    admitted_at: chrono::DateTime<chrono::Utc>,
    admission_id: uuid::Uuid,
}

/// The copy of one `metadata.uid` an admission keeps, and how many source rows
/// it stands for.
struct AdmittedIdentity {
    digest: [u8; 32],
    time_ms: i64,
    event_hour: i32,
    row: EventRow,
    output: Option<PlatformOutput>,
    counts: StampCounts,
    /// Source rows merged into this copy: the same uid AND source identity.
    copies: u64,
}

#[derive(Default)]
struct AdmittedIdentities {
    by_uid: BTreeMap<String, AdmittedIdentity>,
    /// Rows dropped because their uid's kept copy has a different source
    /// identity (NAN-3719). Order-independent: it is always the uid's rows
    /// minus the winning copy's.
    conflicting_rows: u64,
    /// Uids that saw such a conflict.
    conflicting_uids: BTreeSet<String>,
}

impl AdmittedIdentities {
    fn new() -> Self {
        Self::default()
    }

    fn len(&self) -> usize {
        self.by_uid.len()
    }

    fn is_empty(&self) -> bool {
        self.by_uid.is_empty()
    }
}

/// Decode exact local copies of Vector Parquet objects, validate every event
/// against the pinned OCSF contract, reject conflicting replay identities, and
/// return a deterministic newest-first publication batch.
pub fn admit_bronze_files(paths: &[PathBuf], tenant_id: &str) -> Result<BronzeAdmission> {
    admit_bronze_files_with_enrichment(paths, tenant_id, &BronzeIngestEnricher::disabled())
}

/// Read only the bounded physical shape needed to select an atomic publication
/// prefix.  This deliberately does not decode or normalize rows: full OCSF
/// admission still runs exactly once after the publisher has selected the
/// prefix it can commit.
pub fn bronze_file_row_count(path: &Path) -> Result<u64> {
    validate_source_file(path)?;
    let bytes = std::fs::metadata(path)?.len();
    if bytes == 0 || bytes > MAX_BRONZE_BYTES {
        bail!("bronze source file is outside its byte bound");
    }
    let builder = ParquetRecordBatchReaderBuilder::try_new(File::open(path)?)?;
    let rows = u64::try_from(builder.metadata().file_metadata().num_rows())
        .context("bronze source file reported a negative row count")?;
    if rows == 0 || rows > MAX_BRONZE_ROWS as u64 {
        bail!("bronze source file is outside its row bound");
    }
    Ok(rows)
}

pub fn admit_bronze_files_with_enrichment(
    paths: &[PathBuf],
    tenant_id: &str,
    enricher: &BronzeIngestEnricher,
) -> Result<BronzeAdmission> {
    admit_bronze_files_inner(paths, tenant_id, enricher, None)
}

/// Rows of one source file that admission refused: `(rows, first refusal)`.
pub type RefusedRows = BTreeMap<PathBuf, (u64, RowRefusal)>;

/// Why admission refused one row, free of row content (NAN-3490): a stable
/// reason code and, when known, the OCSF attribute it concerns. Error text is
/// NOT kept: admission errors embed `metadata.uid` (vendor identifiers such as
/// a customer id) and validator previews embed values, and this lands in logs
/// and in the durable `reject` entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RowRefusal {
    pub reason: &'static str,
    /// An OCSF attribute path (schema names and array indexes only).
    pub field: Option<String>,
}

impl RowRefusal {
    pub fn new(reason: &'static str, field: Option<&str>) -> Self {
        Self {
            reason,
            field: field.map(bounded_field_name).filter(|field| !field.is_empty()),
        }
    }

    /// The field for a structured log line (`""` when unknown).
    pub fn field_name(&self) -> &str {
        self.field.as_deref().unwrap_or("")
    }
}

impl std::fmt::Display for RowRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "first_row_reason={}", self.reason)?;
        if let Some(field) = &self.field {
            write!(f, " first_row_field={field}")?;
        }
        Ok(())
    }
}

/// An attribute path cut to a log-safe name: path characters only, at most
/// 128 of them.
fn bounded_field_name(field: &str) -> String {
    field
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '[' | ']'))
        .take(128)
        .collect()
}

/// Every row of an object was refused, so admission has nothing to publish
/// (NAN-3490). Carries the object's first row refusal, value-free, so the
/// object-level `bronze data refused` line names the cause, and (NAN-3680)
/// the refused rows per source, so they are still counted where the tenant
/// looks even though nothing publishes.
#[derive(Debug, thiserror::Error)]
#[error("bronze admission produced no canonical events{}", .first_row.as_ref().map(|first| format!("; {first}")).unwrap_or_default())]
pub struct NoCanonicalEvents {
    pub first_row: Option<RowRefusal>,
    pub refused_sources: RefusedSources,
}

/// Row refusals collected by a salvaging admission: per file (the object
/// log lines and part-log entries) and per source (NAN-3680, the per-source
/// counters).
#[derive(Default)]
struct Salvage {
    rows: RefusedRows,
    sources: RefusedSources,
}

/// Like [`admit_bronze_files_with_enrichment`], but a row that fails to
/// parse or admit (e.g. a missing or invalid `time`) is refused on its own
/// and reported per file instead of failing the whole admission (part
/// ingest, NAN-2868). Object-level failures still fail the call.
pub fn admit_bronze_files_salvaging(
    paths: &[PathBuf],
    tenant_id: &str,
    enricher: &BronzeIngestEnricher,
) -> Result<(BronzeAdmission, RefusedRows)> {
    admit_bronze_files_attributing(paths, tenant_id, enricher).map(|(admission, rows, _)| (admission, rows))
}

/// [`admit_bronze_files_salvaging`] that also attributes every refused row
/// to its source (NAN-3680): the counter key read value-free from the row
/// before admission ([`SourceKey::of`]), or the default source for a row too
/// broken to read. When every row is refused the error is
/// [`NoCanonicalEvents`] and carries the same per-source refusals.
pub fn admit_bronze_files_attributing(
    paths: &[PathBuf],
    tenant_id: &str,
    enricher: &BronzeIngestEnricher,
) -> Result<(BronzeAdmission, RefusedRows, RefusedSources)> {
    let mut salvage = Salvage::default();
    let admission = admit_bronze_files_inner(paths, tenant_id, enricher, Some(&mut salvage))?;
    Ok((admission, salvage.rows, salvage.sources))
}

fn admit_bronze_files_inner(
    paths: &[PathBuf],
    tenant_id: &str,
    enricher: &BronzeIngestEnricher,
    mut refused: Option<&mut Salvage>,
) -> Result<BronzeAdmission> {
    if paths.is_empty() || paths.len() > MAX_BRONZE_FILES {
        bail!("bronze admission requires one to {MAX_BRONZE_FILES} files");
    }
    if tenant_id.is_empty() || tenant_id.len() > 256 || tenant_id.chars().any(char::is_control) {
        bail!("bronze admission tenant is invalid");
    }

    #[cfg(all(feature = "enterprise", target_os = "linux"))]
    let admission_start = std::time::Instant::now();
    let mut source_rows = 0_u64;
    let mut source_bytes = 0_u64;
    let mut files = Vec::with_capacity(paths.len());
    let mut enrichment = enricher.initial_metrics();
    let mut timings = AdmissionTimings::default();
    let mut identities = AdmittedIdentities::new();
    #[cfg(all(feature = "enterprise", target_os = "linux"))]
    let _platform_batch_budget = if enricher.platform.is_some() {
        Some(
            nanosiem_core::platform_enrichment::cache::OutputReservation::reserve(16 * 1024 * 1024)
                .map_err(|_| crate::platform_stamping::AdmissionUnavailable)?,
        )
    } else {
        None
    };
    let mut ordered = paths.to_vec();
    ordered.sort();
    #[allow(unused_mut)]
    let mut object_pins: BTreeMap<PathBuf, String> = BTreeMap::new();
    #[cfg(all(feature = "enterprise", target_os = "linux"))]
    if let Some(stamper) = &enricher.platform {
        let m = enricher.initial_metrics();
        let legacy = [
            m.ipinfo_snapshot_sha256,
            m.ioc_snapshot_sha256,
            m.ip_context_snapshot_sha256,
        ];
        let mut pinned_bytes = 0_u64;
        for path in &ordered {
            validate_source_file(path)?;
            let bytes = std::fs::metadata(path)?.len();
            pinned_bytes = pinned_bytes
                .checked_add(bytes)
                .context("source bytes overflow")?;
            if bytes == 0 || pinned_bytes > MAX_BRONZE_BYTES {
                bail!("bronze source byte bound before claim");
            }
        }
        for path in &ordered {
            let digest = sha256_file(path)?;
            object_pins.insert(path.clone(), digest);
        }
        stamper.pin_objects(tenant_id, &object_pins.values().cloned().collect::<Vec<_>>(), &legacy)?;
    }
    #[cfg(all(feature = "enterprise", target_os = "linux"))]
    let platform_pool = enricher.platform.as_ref().map(|_| {
        rayon::ThreadPoolBuilder::new().num_threads(crate::platform_stamping::ADMISSION_CONCURRENCY).build()
    }).transpose()?;
    for path in &ordered {
        validate_source_file(path)?;
        let byte_count = std::fs::metadata(path)?.len();
        source_bytes = source_bytes
            .checked_add(byte_count)
            .context("bronze source byte count overflow")?;
        if source_bytes > MAX_BRONZE_BYTES {
            bail!("bronze admission exceeds its source-byte bound");
        }
        #[cfg(all(feature = "enterprise", target_os = "linux"))]
        let group_rows = if enricher.platform.is_some() { crate::platform_stamping::CLAIM_GROUP_ROWS } else { 8_192 };
        #[cfg(not(all(feature = "enterprise", target_os = "linux")))]
        let group_rows = 8_192;
        let reader = ParquetRecordBatchReaderBuilder::try_new(File::open(path)?)?
            .with_batch_size(group_rows)
            .build()?;
        let before = source_rows;
        for batch in reader {
            let batch = batch?;
            source_rows = source_rows
                .checked_add(batch.num_rows() as u64)
                .context("bronze source row count overflow")?;
            if source_rows > MAX_BRONZE_ROWS as u64 {
                bail!("bronze admission exceeds its source-row bound");
            }
            let decode_start = std::time::Instant::now();
            let mut writer = LineDelimitedWriter::new(Vec::new());
            writer.write(&batch)?;
            writer.finish()?;
            let json = writer.into_inner();
            timings.decode_us += decode_start.elapsed().as_micros() as u64;
            let lines = json
                .split(|byte| *byte == b'\n')
                .filter(|line| !line.is_empty())
                .collect::<Vec<_>>();
            // Parse in input order before the grouped claim. Enrichment and
            // normalization remain parallel; the serial identity merge keeps
            // deterministic conflict and replay behavior.
            let parse_start = std::time::Instant::now();
            let parsed = lines.par_iter().map(|line| serde_json::from_slice::<Value>(line)
                .map_err(anyhow::Error::from)
                .and_then(decode_bronze_row)
                .with_context(|| format!("decode Vector bronze row from {}", path.display())))
                .collect::<Vec<Result<Value>>>();
            let mut events = Vec::with_capacity(parsed.len());
            for event in parsed {
                match (event, refused.as_deref_mut()) {
                    (Ok(event), _) => events.push(event),
                    (Err(error), Some(refused)) => {
                        note_refused(refused, path, &error, (SourceKey::unreadable(), None));
                    }
                    (Err(error), None) => return Err(error),
                }
            }
            timings.json_parse_us += parse_start.elapsed().as_micros() as u64;
            // A `None` claim on a platform admission is a row whose uid the
            // journal already holds under another source identity: that row
            // alone is refused (NAN-3719), never the whole group.
            #[cfg(all(feature = "enterprise", target_os = "linux"))]
            let (claims, conflicted) = if let Some(stamper) = &enricher.platform {
                let metrics = enricher.initial_metrics();
                let claims = stamper.claim_events(tenant_id, &events,
                    &[metrics.ipinfo_snapshot_sha256, metrics.ioc_snapshot_sha256, metrics.ip_context_snapshot_sha256],
                    object_pins.get(path).context("platform source object pin required")?)?;
                let conflicted = claims.iter().map(Option::is_none).collect::<Vec<_>>();
                (claims, conflicted)
            } else { (vec![None; events.len()], vec![false; events.len()]) };
            // NAN-3680: a salvaging admission reads each row's counter key
            // before admission consumes it, so a refused row is still
            // attributed to its source (value-free).
            let salvaging = refused.is_some();
            let admit_lines = || events.into_par_iter().enumerate().map(|(index, event)| {
                #[cfg(not(all(feature = "enterprise", target_os = "linux")))]
                let _ = index;
                let attribution = salvaging.then(|| refusal_attribution(&event));
                #[cfg(all(feature = "enterprise", target_os = "linux"))]
                if conflicted[index] {
                    let event_uid = event.pointer("/metadata/uid").and_then(Value::as_str).unwrap_or_default().to_owned();
                    return (Err(BronzeAdmissionError::ConflictingReplay { event_uid }.into()), attribution);
                }
                let admitted = admit_event(event, tenant_id, enricher, object_pins.get(path).map(String::as_str),
                    #[cfg(all(feature = "enterprise", target_os = "linux"))]
                    claims[index].clone());
                (admitted, attribution)
            }).collect::<Vec<_>>();
            #[cfg(all(feature = "enterprise", target_os = "linux"))]
            let admitted = match &platform_pool {
                Some(pool) => pool.install(admit_lines),
                None => admit_lines(),
            };
            #[cfg(not(all(feature = "enterprise", target_os = "linux")))]
            let admitted = admit_lines();
            for (admitted, attribution) in admitted {
                let admitted = match (admitted, refused.as_deref_mut()) {
                    (Ok(admitted), _) => admitted,
                    (Err(error), Some(refused)) if !is_resource_error(&error) => {
                        let attribution = attribution.unwrap_or_else(|| (SourceKey::unreadable(), None));
                        note_refused(refused, path, &error, attribution);
                        continue;
                    }
                    (Err(error), _) => return Err(error),
                };
                merge_admission_timings(&mut timings, &admitted.timings);
                merge_enrichment_metrics(&mut enrichment, &admitted.enrichment);
                insert_admitted_event(&mut identities, admitted)?;
            }
        }
        let rows = source_rows.saturating_sub(before);
        if rows == 0 {
            bail!("Vector bronze object {} contains no rows", path.display());
        }
        #[cfg(all(feature = "enterprise", target_os = "linux"))]
        if let Some(stamper) = &enricher.platform {
            let object = object_pins.get(path).context("platform source object pin required")?;
            anyhow::ensure!(sha256_file(path)? == *object, "bronze object changed before sidecar commit");
            stamper.flush_object(object)?;
        }
        files.push(BronzeFileAdmission {
            path: path.clone(),
            rows,
            bytes: byte_count,
            sha256: {
                let hash_start = std::time::Instant::now();
                let digest = sha256_file(path)?;
                if object_pins
                    .get(path)
                    .is_some_and(|pinned| pinned != &digest)
                {
                    bail!("bronze object changed after its durable platform pin");
                }
                timings.hash_us += hash_start.elapsed().as_micros() as u64;
                digest
            },
        });
    }
    // One signed sidecar covers the whole publication batch, so the per-object
    // flushes above only buffered. Nothing is durable, and nothing may be
    // published, until this PUT and its digest commits return (NAN-2519).
    #[cfg(all(feature = "enterprise", target_os = "linux"))]
    if let Some(stamper) = &enricher.platform {
        stamper.flush_batch()?;
        // One summary line per publication batch, only once its stamps are
        // durable (NAN-2361), summed over the UIDs that survived the merge.
        // Failures above keep their own per-occurrence warn/error lines.
        let mut live = crate::platform_stamping::LiveStampSummary::default();
        let mut shadow = crate::platform_stamping::ShadowComparisonSummary::default();
        for AdmittedIdentity { counts, .. } in identities.by_uid.values() {
            if let Some(counts) = &counts.live {
                live.merge(counts);
            }
            if let Some(counts) = &counts.shadow {
                shadow.merge(counts);
            }
        }
        live.emit(ordered.len(), admission_start.elapsed());
        shadow.emit(ordered.len(), admission_start.elapsed());
    }
    if source_rows == 0 || identities.is_empty() {
        let first_row = refused
            .as_deref()
            .and_then(|refused| refused.rows.values().next())
            .map(|(_, first)| first.clone());
        let refused_sources = refused
            .as_deref_mut()
            .map(|refused| std::mem::take(&mut refused.sources))
            .unwrap_or_default();
        return Err(NoCanonicalEvents { first_row, refused_sources }.into());
    }
    let duplicate_rows_removed = source_rows.saturating_sub(identities.len() as u64);
    let conflicting_replay_rows_dropped = identities.conflicting_rows;
    if conflicting_replay_rows_dropped > 0 {
        // The integrity signal ConflictingReplay used to carry, now row-scoped
        // (NAN-3719). Debug only: callers count it (part ingest folds it into
        // `same_uid_payload_diff_total` and samples a warn). Value-free: uids
        // can be vendor identifiers, so only a digest prefix is logged.
        let first = identities.conflicting_uids.iter().next().map(|uid| hex::encode(&Sha256::digest(uid.as_bytes())[..8])).unwrap_or_default();
        tracing::debug!(rows_dropped = conflicting_replay_rows_dropped,
            uids = identities.conflicting_uids.len(), first_uid_sha256_prefix = %first,
            "same metadata.uid with a different source identity in one admission; one copy kept per uid");
    }
    let source_identity_digests = identities
        .by_uid
        .iter()
        .map(|(uid, identity)| (uid.clone(), identity.digest))
        .collect::<BTreeMap<_, _>>();
    let mut output_hash = Sha256::new();
    let mut has_platform = false;
    output_hash.update(b"nano/platform-enrichment/batch-outputs/v1\0");
    for (uid, AdmittedIdentity { output, .. }) in &identities.by_uid {
        if let Some(output) = output {
            has_platform = true;
            output_hash.update((uid.len() as u64).to_be_bytes());
            output_hash.update(uid.as_bytes());
            output_hash.update(output.digest);
        }
    }
    if has_platform {
        enrichment.platform_admission_sha256 = Some(hex::encode(output_hash.finalize()));
    }
    let mut ordered = identities
        .by_uid
        .into_values()
        .map(|identity| (identity.time_ms, identity.event_hour, identity.row))
        .collect::<Vec<_>>();
    ordered.sort_by(|left, right| {
        (right.0, right.2.event_uid.as_str()).cmp(&(left.0, left.2.event_uid.as_str()))
    });
    let normalized = ordered
        .into_iter()
        .map(|(_, event_hour, row)| (event_hour, row))
        .collect::<Vec<_>>();
    Ok(BronzeAdmission {
        timings,
        source_files: paths.len(),
        source_rows,
        source_bytes,
        duplicate_rows_removed,
        conflicting_replay_rows_dropped,
        enrichment,
        files,
        batch: NormalizedEventBatch::from_admitted(tenant_id, normalized)?,
        source_identity_digests,
    })
}

fn note_refused(
    refused: &mut Salvage,
    path: &Path,
    error: &anyhow::Error,
    (source, at): (SourceKey, Option<chrono::DateTime<chrono::Utc>>),
) {
    let refusal = classify_row_refusal(error);
    refused.sources.note(source, &refusal, at);
    let entry = refused.rows.entry(path.to_path_buf()).or_insert_with(|| (0, refusal));
    entry.0 += 1;
}

/// Exact admission messages that carry no row content, by reason and field.
const ROW_REFUSALS: &[(&str, &str, Option<&str>)] = &[
    ("bronze row event is not a JSON object", "event_not_object", Some(nanosiem_core::parsers::lake_bronze_row::BRONZE_EVENT_COLUMN)),
    ("bronze row event is not JSON", "event_not_json", Some(nanosiem_core::parsers::lake_bronze_row::BRONZE_EVENT_COLUMN)),
    ("Vector bronze event has no bounded metadata.uid", "uid_missing", Some("metadata.uid")),
    ("outbox event or tenant identity is invalid", "uid_invalid", Some("metadata.uid")),
    ("OCSF outbox event must be an object", "event_not_object", None),
    ("source OCSF event must preserve one bounded non-empty raw_data value", "raw_data_missing", Some("raw_data")),
    ("source OCSF event must preserve raw_data_size", "raw_data_size_missing", Some("raw_data_size")),
    ("source OCSF raw_data_size does not match its encoded byte length", "raw_data_size_mismatch", Some("raw_data_size")),
    ("OCSF outbox event lacks metadata", "metadata_missing", Some("metadata")),
    ("OCSF metadata.uid conflicts with the durable outbox identity", "metadata_conflict", Some("metadata.uid")),
    ("OCSF metadata.tenant_uid conflicts with the durable outbox identity", "metadata_conflict", Some("metadata.tenant_uid")),
    ("OCSF metadata.version conflicts with the durable outbox identity", "metadata_conflict", Some("metadata.version")),
    ("OCSF metadata.log_source is invalid", "log_source_invalid", Some("metadata.log_source")),
    ("OCSF event time must be positive epoch milliseconds", "time_invalid", Some("time")),
    ("OCSF event time is outside the supported range", "time_out_of_range", Some("time")),
    ("normalized Vector bronze event has no timestamp", "time_missing", Some("time")),
];

/// Classify a row's admission error into a value-free [`RowRefusal`]. Only
/// typed errors and exact static messages are read; anything else is
/// `unclassified` (or the stage it failed in), never its text.
pub fn classify_row_refusal(error: &anyhow::Error) -> RowRefusal {
    for cause in error.chain() {
        if cause.downcast_ref::<BronzeAdmissionError>().is_some() {
            return RowRefusal::new("conflicting_replay_identity", Some("metadata.uid"));
        }
        if let Some(rejected) = cause.downcast_ref::<crate::iceberg::OcsfValidationRejected>() {
            return RowRefusal::new(rejected.reason(), Some(&rejected.attribute_path));
        }
        if cause.downcast_ref::<nanosiem_core::platform_enrichment::StampError>().is_some() {
            return RowRefusal::new("producer_provenance", None);
        }
        let text = cause.to_string();
        if let Some((_, reason, field)) = ROW_REFUSALS.iter().find(|(message, _, _)| text == *message) {
            return RowRefusal::new(reason, *field);
        }
        for &name in crate::iceberg::PLATFORM_METADATA_STAMPS {
            if text == format!("OCSF metadata.{name} must be a string platform stamp")
                || text == format!("OCSF metadata.{name} is not a well-formed nano platform stamp")
            {
                return RowRefusal::new("platform_stamp_invalid", Some(&format!("metadata.{name}")));
            }
        }
    }
    // Stage contexts carry the event uid, so only their fixed prefix is read.
    let stage = error.chain().map(|cause| cause.to_string()).find_map(|text| {
        [
            ("enrich Vector bronze event ", "enrichment_failed"),
            ("validate Vector bronze event ", "validation_failed"),
            ("decode Vector bronze row from ", "row_decode_failed"),
        ]
        .into_iter()
        .find_map(|(prefix, reason)| text.starts_with(prefix).then_some(reason))
    });
    RowRefusal::new(stage.unwrap_or("unclassified"), None)
}

/// IO and platform-capacity failures are transient, never a row's fault.
fn is_resource_error(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| {
        #[cfg(all(feature = "enterprise", target_os = "linux"))]
        if cause.downcast_ref::<crate::platform_stamping::AdmissionUnavailable>().is_some() {
            return true;
        }
        cause.downcast_ref::<std::io::Error>().is_some()
    })
}

fn sha256_file(path: &Path) -> Result<String> {
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0_u8; 1024 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hex::encode(hasher.finalize()))
}

fn validate_source_file(path: &Path) -> Result<()> {
    if !path.is_absolute()
        || path.extension().and_then(|value| value.to_str()) != Some("parquet")
        || !std::fs::metadata(path)?.is_file()
    {
        bail!("bronze source is not one absolute Parquet file");
    }
    Ok(())
}

/// NAN-3807: the checks bronze admission runs on one decoded bronze row
/// before it may enter the lake (producer provenance, a bounded
/// `metadata.uid`, the source identity, and strict OCSF 1.9 normalization),
/// without enrichment. The landing converter runs it on every row it is about
/// to write, so a landed file's status names refused rows up front; part
/// ingest still admits (and enriches) the written object as usual.
pub fn precheck_source_row(event: Value, tenant_id: &str) -> std::result::Result<(), RowRefusal> {
    let check = || -> Result<()> {
        nanosiem_core::platform_enrichment::reject_producer_provenance(&event)?;
        let event_uid = event
            .pointer("/metadata/uid")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty() && value.len() <= 4_096)
            .context("Vector bronze event has no bounded metadata.uid")?
            .to_string();
        source_identity_digest(&event)?;
        let row = EventRow { event_uid, event_kind: EventKind::Source, ocsf_event: event.clone() };
        normalize_event(&row, tenant_id).map(|_| ())
    };
    check().map_err(|error| classify_row_refusal(&error))
}

#[cfg(test)]
fn admit_event_without_pin(
    event: Value,
    tenant_id: &str,
    enricher: &BronzeIngestEnricher,
) -> Result<AdmittedEvent> {
    admit_event(event, tenant_id, enricher, None,
        #[cfg(all(feature = "enterprise", target_os = "linux"))]
        None)
}

#[cfg_attr(
    not(all(feature = "enterprise", target_os = "linux")),
    allow(unused_mut, unused_variables)
)]
fn admit_event(
    mut event: Value,
    tenant_id: &str,
    enricher: &BronzeIngestEnricher,
    object: Option<&str>,
    #[cfg(all(feature = "enterprise", target_os = "linux"))]
    prepared: Option<crate::platform_stamping::Claim>,
) -> Result<AdmittedEvent> {
    nanosiem_core::platform_enrichment::reject_producer_provenance(&event)?;
    let mut enrichment = IngestEnrichmentMetrics::default();
    let mut timings = AdmissionTimings::default();
    let event_uid = event
        .pointer("/metadata/uid")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty() && value.len() <= 4_096)
        .context("Vector bronze event has no bounded metadata.uid")?
        .to_string();
    // Capture source identity before any deployment-owned decoration. IOC,
    // IP-context, IPinfo and prevalence assignments may legitimately rotate
    // between two deliveries of the same Vector event.
    let digest = source_identity_digest(&event)?;
    #[cfg(all(feature = "enterprise", target_os = "linux"))]
    let mut platform = enricher
        .platform
        .as_ref()
        .map(|stamper| {
            let metrics = enricher.initial_metrics();
            stamper.begin_claim(
                tenant_id,
                &event_uid,
                digest,
                &mut event,
                [
                    metrics.ipinfo_snapshot_sha256,
                    metrics.ioc_snapshot_sha256,
                    metrics.ip_context_snapshot_sha256,
                ],
                object.context("platform source object pin required")?,
                prepared,
            )
        })
        .transpose()?;
    #[cfg(all(feature = "enterprise", target_os = "linux"))]
    let pinned_enricher = platform
        .as_ref()
        .map(|session| session.legacy_enricher(enricher))
        .transpose()?;
    #[cfg(all(feature = "enterprise", target_os = "linux"))]
    let enricher = pinned_enricher.as_ref().unwrap_or(enricher);
    let enrich_start = std::time::Instant::now();
    #[cfg(all(feature = "enterprise", target_os = "linux"))]
    let platform_shadow = platform.is_some();
    #[cfg(not(all(feature = "enterprise", target_os = "linux")))]
    let platform_shadow = false;
    enricher
        .enrich_before_normalization(&mut event, &mut enrichment, platform_shadow)
        .with_context(|| format!("enrich Vector bronze event {event_uid}"))?;
    timings.enrich_us += enrich_start.elapsed().as_micros() as u64;
    #[cfg(all(feature = "enterprise", target_os = "linux"))]
    let undo = platform
        .as_mut()
        .map(|session| session.decorate_with_legacy(&mut event, enricher))
        .transpose()?;
    let mut row = EventRow {
        event_uid: event_uid.clone(),
        event_kind: EventKind::Source,
        ocsf_event: event,
    };
    let normalize_start = std::time::Instant::now();
    let (mut event_hour, mut normalized) = normalize_event(&row, tenant_id)
        .with_context(|| format!("validate Vector bronze event {event_uid}"))?;
    let mut platform_output = None;
    #[allow(unused_mut)]
    let mut stamp_counts = StampCounts::default();
    #[cfg(all(feature = "enterprise", target_os = "linux"))]
    if let (Some(session), Some(undo)) = (&platform, undo) {
        let (admitted_at, admission_id) = session.admission();
        platform_output = Some(PlatformOutput {
            digest: hex::decode(session.finalize(&normalized)?)?
                .try_into()
                .map_err(|_| anyhow::anyhow!("invalid output digest"))?,
            admitted_at,
            admission_id,
        });
        if !session.is_live() {
            undo.restore(&mut row.ocsf_event)?;
            // The candidate uses producer -> custom -> platform. The shadow base
            // still uses its existing tenant IPinfo baseline until later rollout.
            enricher.restore_legacy_baseline(&mut row.ocsf_event, &mut enrichment)?;
            // Shadow only: the finalized stamped reference is durable, but visible
            // publication receives the existing producer/custom row.
            drop(normalized);
            (event_hour, normalized) = normalize_event(&row, tenant_id)?;
            stamp_counts.shadow = Some(session.compare_shadow(&normalized));
        } else {
            stamp_counts.live = Some(session.live_counts());
        }
    }
    timings.normalize_us += normalize_start.elapsed().as_micros() as u64;
    let time_ms = normalized
        .get("time")
        .and_then(Value::as_str)
        .and_then(|value| chrono::DateTime::parse_from_rfc3339(value).ok())
        .map(|value| value.timestamp_millis())
        .context("normalized Vector bronze event has no timestamp")?;
    let normalized = EventRow {
        event_uid: event_uid.clone(),
        event_kind: EventKind::Source,
        ocsf_event: normalized,
    };
    Ok(AdmittedEvent {
        event_uid,
        digest,
        time_ms,
        event_hour,
        row: normalized,
        platform_output,
        stamp_counts,
        enrichment,
        timings,
    })
}

fn insert_admitted_event(identities: &mut AdmittedIdentities, admitted: AdmittedEvent) -> Result<()> {
    let Some(existing) = identities.by_uid.get_mut(&admitted.event_uid) else {
        identities.by_uid.insert(
            admitted.event_uid,
            AdmittedIdentity {
                digest: admitted.digest,
                time_ms: admitted.time_ms,
                event_hour: admitted.event_hour,
                row: admitted.row,
                output: admitted.platform_output,
                counts: admitted.stamp_counts,
                copies: 1,
            },
        );
        return Ok(());
    };
    if existing.digest != admitted.digest {
        // NAN-3719: the same uid with a different source identity. This used
        // to refuse the whole admission (every unrelated row in the object
        // with it); since parse-failure fallbacks hash the raw line, two
        // identical non-JSON lines are enough. It is row-scoped now, like the
        // cross-batch window (NAN-3704): one copy is kept, the others are
        // dropped and counted. The winner is the earliest event time, then
        // the smallest source digest, so the kept copy and the count never
        // depend on the order rows were read in.
        identities.conflicting_uids.insert(admitted.event_uid.clone());
        if (admitted.time_ms, admitted.digest) < (existing.time_ms, existing.digest) {
            identities.conflicting_rows += existing.copies;
            *existing = AdmittedIdentity {
                digest: admitted.digest,
                time_ms: admitted.time_ms,
                event_hour: admitted.event_hour,
                row: admitted.row,
                output: admitted.platform_output,
                counts: admitted.stamp_counts,
                copies: 1,
            };
        } else {
            identities.conflicting_rows += 1;
        }
        return Ok(());
    }
    existing.copies += 1;
    match (existing.output, admitted.platform_output) {
        (None, None) => {}
        (Some(kept), Some(copy)) if kept.digest == copy.digest => {}
        // The offload journal claims per (object, UID): a redelivered
        // event in two objects of one batch holds two claims, both durable
        // once the batch sidecar commits, with two signed outputs
        // (NAN-2361). Converge on the first claim admitted -- a digest row
        // committed in an earlier cycle beats a fresh one -- and keep its
        // row and its output together, so the published row is the one
        // that output signs. Admission id breaks an exact tie, so the
        // choice does not depend on the order objects are read.
        (Some(kept), Some(copy)) if kept.admission_id != copy.admission_id => {
            if (copy.admitted_at, copy.admission_id) < (kept.admitted_at, kept.admission_id) {
                existing.time_ms = admitted.time_ms;
                existing.event_hour = admitted.event_hour;
                existing.row = admitted.row;
                existing.output = admitted.platform_output;
                existing.counts = admitted.stamp_counts;
            }
            return Ok(());
        }
        // One claim with two outputs, or a stamped and an unstamped copy
        // in one batch: the journal broke its contract. Never pick one.
        _ => bail!("divergent platform output for one UID"),
    }
    // Vector's per-delivery observation clocks legitimately change when
    // the same native event is retried. They are not part of the source
    // event's semantic identity. Keep the lexicographically smallest full
    // row so exact-object discovery order cannot change the generation.
    if serde_json::to_vec(&admitted.row)? < serde_json::to_vec(&existing.row)? {
        existing.row = admitted.row;
    }
    Ok(())
}

fn merge_admission_timings(total: &mut AdmissionTimings, next: &AdmissionTimings) {
    total.decode_us = total.decode_us.saturating_add(next.decode_us);
    total.json_parse_us = total.json_parse_us.saturating_add(next.json_parse_us);
    total.enrich_us = total.enrich_us.saturating_add(next.enrich_us);
    total.normalize_us = total.normalize_us.saturating_add(next.normalize_us);
    total.hash_us = total.hash_us.saturating_add(next.hash_us);
}

fn merge_enrichment_metrics(total: &mut IngestEnrichmentMetrics, next: &IngestEnrichmentMetrics) {
    total.ipinfo_candidates = total
        .ipinfo_candidates
        .saturating_add(next.ipinfo_candidates);
    total.ipinfo_hits = total.ipinfo_hits.saturating_add(next.ipinfo_hits);
    total.ipinfo_enriched_endpoints = total
        .ipinfo_enriched_endpoints
        .saturating_add(next.ipinfo_enriched_endpoints);
    total.ip_context_candidates = total
        .ip_context_candidates
        .saturating_add(next.ip_context_candidates);
    total.ip_context_hits = total.ip_context_hits.saturating_add(next.ip_context_hits);
    total.ip_context_enriched_endpoints = total
        .ip_context_enriched_endpoints
        .saturating_add(next.ip_context_enriched_endpoints);
    total.ioc_candidates = total.ioc_candidates.saturating_add(next.ioc_candidates);
    total.ioc_hits = total.ioc_hits.saturating_add(next.ioc_hits);
    total.ioc_attached = total.ioc_attached.saturating_add(next.ioc_attached);
    total.prevalence_candidates = total
        .prevalence_candidates
        .saturating_add(next.prevalence_candidates);
    total.prevalence_hits = total.prevalence_hits.saturating_add(next.prevalence_hits);
    total.prevalence_attached = total
        .prevalence_attached
        .saturating_add(next.prevalence_attached);
    if next.prevalence_state.is_some() {
        total.prevalence_state.clone_from(&next.prevalence_state);
    }
    total.identity_candidates = total.identity_candidates.saturating_add(next.identity_candidates);
    total.identity_hits = total.identity_hits.saturating_add(next.identity_hits);
    total.identity_attached = total.identity_attached.saturating_add(next.identity_attached);
}

/// NAN-3339: turn one decoded bronze row back into its OCSF event.
///
/// A row written under the fixed bronze row contract
/// (`nanosiem_core::parsers::lake_bronze_row`) carries the event as ONE JSON
/// string in `_nano_bronze_event` plus the typed `time` column. It decodes to
/// exactly what the columnar form decoded to: the Arrow JSON writer omits
/// null object members, so they are dropped here too (array elements are
/// kept, as Arrow keeps them), and `time` is the column's own rendering. Then
/// `unmapped` is decoded as for any row ([`decode_bronze_unmapped`]), so a
/// replay that straddles the contract keeps one source identity.
///
/// A row without the column (columnar bronze written before the contract) is
/// only `unmapped`-decoded, exactly as before. A contract row whose event is
/// not a JSON object is refused (this row only, on the salvaging path).
pub fn decode_bronze_row(mut row: Value) -> Result<Value> {
    use nanosiem_core::parsers::lake_bronze_row::{BRONZE_EVENT_COLUMN, BRONZE_TIME_COLUMN};
    let Some(Value::String(text)) = row.get(BRONZE_EVENT_COLUMN) else {
        decode_bronze_unmapped(&mut row);
        return Ok(row);
    };
    let mut event = match serde_json::from_str::<Value>(text) {
        Ok(event @ Value::Object(_)) => event,
        Ok(_) => bail!("bronze row event is not a JSON object"),
        Err(error) => return Err(error).context("bronze row event is not JSON"),
    };
    strip_null_members(&mut event);
    let Value::Object(fields) = &mut event else { unreachable!("checked above") };
    match row.get_mut(BRONZE_TIME_COLUMN).map(Value::take) {
        Some(time) if !time.is_null() => {
            fields.insert(BRONZE_TIME_COLUMN.to_string(), time);
        }
        _ => {
            fields.remove(BRONZE_TIME_COLUMN);
        }
    }
    decode_bronze_unmapped(&mut event);
    Ok(event)
}

/// Drop every object member whose value is null, at any depth (the Arrow
/// JSON writer's `explicit_nulls = false` rendering of columnar bronze).
fn strip_null_members(value: &mut Value) {
    match value {
        Value::Object(map) => {
            map.retain(|_, member| !member.is_null());
            map.values_mut().for_each(strip_null_members);
        }
        Value::Array(items) => items.iter_mut().for_each(strip_null_members),
        _ => {}
    }
}

/// NAN-3079: restore a bronze row's `unmapped` object from its bronze form.
///
/// A tenant parser bundle's lake lane writes `unmapped` into bronze as ONE
/// JSON string, because the bronze sink infers each batch's Parquet schema and
/// one type-drifted `unmapped` value (a `[]` next to a JSON-string spill, a
/// number next to a string) otherwise fails the encode and Vector drops the
/// whole batch. Decoding here, before identity, enrichment and normalization,
/// keeps parts byte-identical to rows whose `unmapped` arrived as an object.
///
/// Only a string that decodes to a JSON object is replaced; an object (older
/// bases) or any other value is left exactly as it arrived.
pub fn decode_bronze_unmapped(event: &mut Value) {
    let Some(Value::String(text)) = event.get("unmapped") else {
        return;
    };
    if let Ok(object @ Value::Object(_)) = serde_json::from_str::<Value>(text) {
        event["unmapped"] = object;
    }
}

pub(crate) fn source_identity_digest(event: &Value) -> Result<[u8; 32]> {
    let mut semantic = event.clone();
    if let Some(metadata) = semantic.get_mut("metadata").and_then(Value::as_object_mut) {
        metadata.remove("logged_time");
        metadata.remove("processed_time");
        // A parser may mint a UUID before a durable ingress adapter replaces
        // metadata.uid with its stable delivery identity. Retrying the same
        // raw event then legitimately produces a new diagnostic source UID.
        // The stable metadata.uid remains authoritative and every other event
        // field is still compared, so this delivery-local value cannot turn a
        // safe replay into a permanent UID conflict.
        metadata.remove("original_event_uid");
    }
    Ok(Sha256::digest(serde_json::to_vec(&semantic)?).into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use arrow_json::reader::infer_json_schema_from_seekable;
    use arrow_json::ReaderBuilder;
    use parquet::arrow::ArrowWriter;
    use serde_json::json;
    use std::io::Cursor;
    use std::sync::Arc;

    fn source_event(message: &str) -> Value {
        json!({
            "activity_id": 1,
            "activity_name": "Create",
            "actor": {"user": {"name": "TESTER"}},
            "api": {"operation": "test"},
            "category_name": "System Activity",
            "category_uid": 6,
            "class_name": "API Activity",
            "class_uid": 6003,
            "message": message,
            "raw_data": "fixture",
            "raw_data_size": 7,
            "metadata": {
                "log_name": "source",
                "log_source": "WINDOWS_EVENT",
                "product": {"name": "fixture", "vendor_name": "nano"},
                "tenant_uid": "tenant-a",
                "uid": "source-1",
                "version": "1.9.0"
            },
            "severity": "Informational",
            "severity_id": 1,
            "src_endpoint": {"ip": "10.1.2.3"},
            "status": "Success",
            "status_id": 1,
            "time": "2026-08-11T08:00:00.123456+00:00",
            "type_uid": 600301
        })
    }

    fn write_fixture(path: &Path, events: &[Value]) {
        let mut json = Vec::new();
        for event in events {
            serde_json::to_writer(&mut json, event).unwrap();
            json.push(b'\n');
        }
        let mut cursor = Cursor::new(json.clone());
        let (schema, _) = infer_json_schema_from_seekable(&mut cursor, None).unwrap();
        let mut reader = ReaderBuilder::new(Arc::new(schema))
            .build(Cursor::new(json))
            .unwrap();
        let batch = reader.next().unwrap().unwrap();
        let mut writer =
            ArrowWriter::try_new(File::create(path).unwrap(), batch.schema(), None).unwrap();
        writer.write(&batch).unwrap();
        for batch in reader {
            writer.write(&batch.unwrap()).unwrap();
        }
        writer.close().unwrap();
    }

    #[tokio::test]
    async fn pipeline_schema_cache_keeps_live_binding_and_additive_checks() {
        use crate::iceberg::ensure_additive_event_schema_with_cache;
        use iceberg::{Catalog, CatalogBuilder};
        let directory = tempfile::tempdir().unwrap();
        let catalog = iceberg::memory::MemoryCatalogBuilder::default()
            .load(
                "test",
                std::collections::HashMap::from([(
                    "warehouse".to_string(),
                    "s3://test/cache".to_string(),
                )]),
            )
            .await
            .unwrap();
        let table_id = crate::iceberg::table_ident("tenant_a.events").unwrap();
        catalog
            .create_namespace(&table_id.namespace, Default::default())
            .await
            .unwrap();
        let location = "s3://test/cache/events/";
        let path = directory.path().join("source.parquet");
        write_fixture(&path, &[source_event("base")]);
        let mut admitted = admit_bronze_files(&[path.clone()], "tenant-a").unwrap();
        admitted.batch.seal_source_identity().unwrap();
        catalog
            .create_table(
                &table_id.namespace,
                crate::iceberg::pipeline_test_table(&admitted.batch, location).unwrap(),
            )
            .await
            .unwrap();
        let before = ensure_additive_event_schema_with_cache(
            &catalog,
            &table_id,
            location,
            &admitted.batch,
            true,
        )
        .await
        .unwrap();
        assert!(ensure_additive_event_schema_with_cache(
            &catalog,
            &table_id,
            "s3://other/table/",
            &admitted.batch,
            true
        )
        .await
        .is_err());
        let mut changed = source_event("new field");
        changed["src_endpoint"]["hostname"] = json!("new-host");
        write_fixture(&path, &[changed]);
        let mut admitted = admit_bronze_files(&[path], "tenant-a").unwrap();
        admitted.batch.seal_source_identity().unwrap();
        let after = ensure_additive_event_schema_with_cache(
            &catalog,
            &table_id,
            location,
            &admitted.batch,
            true,
        )
        .await
        .unwrap();
        assert_ne!(
            before.metadata().current_schema_id(),
            after.metadata().current_schema_id()
        );
        assert!(after
            .metadata()
            .current_schema()
            .field_by_name("src_endpoint.hostname")
            .is_some());
        ensure_additive_event_schema_with_cache(
            &catalog,
            &table_id,
            location,
            &admitted.batch,
            true,
        )
        .await
        .unwrap();
    }

    /// NAN-3401 regression. The ocsf-1.9 catalog parsers' residual spill
    /// (NAN-2421) writes FLAT dotted keys under `unmapped`, e.g. Sysmon EID 3's
    /// `unmapped["event_data.destination_is_ipv_6"]`. The lean path keeps that
    /// literal child name in its Parquet `unmapped` struct and chDB resolves
    /// `unmapped.event_data.destination_is_ipv_6` against it (NAN-2998). The
    /// open-core Iceberg path must store the same shape: before the fix,
    /// adding such a child to an existing `unmapped` struct failed with
    /// "Cannot add column with ambiguous name", and the Bronze publisher
    /// retried that batch forever ahead of every later one.
    #[tokio::test]
    async fn dotted_unmapped_keys_are_admitted_staged_and_readable() {
        use crate::iceberg::{
            encode_staged_event_files_normalized, ensure_additive_event_schema_with_cache,
            table_read_contract,
        };
        use iceberg::{Catalog, CatalogBuilder};
        use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;
        let directory = tempfile::tempdir().unwrap();
        let catalog = iceberg::memory::MemoryCatalogBuilder::default()
            .load(
                "test",
                std::collections::HashMap::from([(
                    "warehouse".to_string(),
                    "s3://test/dotted".to_string(),
                )]),
            )
            .await
            .unwrap();
        let table_id = crate::iceberg::table_ident("tenant_a.events").unwrap();
        catalog
            .create_namespace(&table_id.namespace, Default::default())
            .await
            .unwrap();
        let location = "s3://test/dotted/events/";
        let admit = |name: &str, event: Value| {
            let path = directory.path().join(name);
            write_fixture(&path, &[event]);
            let mut admitted = admit_bronze_files(&[path], "tenant-a").unwrap();
            admitted.batch.seal_source_identity().unwrap();
            admitted
        };

        // The live table already has an `unmapped` struct, as every tenant
        // that has ingested a parser event with a residual spill does.
        let mut base = source_event("base");
        base["unmapped"] = json!({"channel": "Security"});
        let base = admit("base.parquet", base);
        catalog
            .create_table(
                &table_id.namespace,
                crate::iceberg::pipeline_test_table(&base.batch, location).unwrap(),
            )
            .await
            .unwrap();

        let mut sysmon = source_event("sysmon 3");
        sysmon["metadata"]["uid"] = json!("sysmon-3");
        sysmon["unmapped"] = json!({
            "channel": "Microsoft-Windows-Sysmon/Operational",
            "event_data.destination_is_ipv_6": "false",
            "event_data.destination_hostname": "-",
        });
        let sysmon = admit("sysmon.parquet", sysmon);
        let table = ensure_additive_event_schema_with_cache(
            &catalog,
            &table_id,
            location,
            &sysmon.batch,
            true,
        )
        .await
        .expect("dotted unmapped keys must be admitted additively");
        let schema = table.metadata().current_schema();
        let unmapped = schema.field_by_name("unmapped").unwrap();
        let iceberg::spec::Type::Struct(unmapped) = unmapped.field_type.as_ref() else {
            panic!("unmapped must stay a struct");
        };
        for leaf in ["event_data.destination_is_ipv_6", "event_data.destination_hostname"] {
            assert!(
                unmapped.field_by_name(leaf).is_some(),
                "unmapped must keep the literal dotted child {leaf}, like the lean part schema"
            );
        }

        // A second batch adds another dotted child to the now-dotted struct.
        let mut later = source_event("sysmon 22");
        later["metadata"]["uid"] = json!("sysmon-22");
        later["unmapped"] = json!({"event_data.query_status": "0"});
        let later = admit("later.parquet", later);
        let table = ensure_additive_event_schema_with_cache(
            &catalog,
            &table_id,
            location,
            &later.batch,
            true,
        )
        .await
        .expect("a later dotted unmapped key must also be admitted");

        // The read contract exposes the same logical path the lean planner
        // and `unmapped.*` search resolution use.
        let (read_schema, paths) = table_read_contract(&table).unwrap();
        for path in [
            "unmapped.event_data.destination_is_ipv_6",
            "unmapped.event_data.query_status",
            "unmapped.channel",
        ] {
            assert!(paths.iter().any(|candidate| candidate == path), "{path} missing from {paths:?}");
        }
        assert!(read_schema.contains("`event_data.destination_is_ipv_6`"), "{read_schema}");

        // Staged encoding stores the values under the dotted child.
        let staged = encode_staged_event_files_normalized(&table, &sysmon.batch).unwrap();
        let mut found = None;
        for file in staged {
            let reader = ParquetRecordBatchReaderBuilder::try_new(bytes::Bytes::from(file.bytes))
                .unwrap()
                .build()
                .unwrap();
            for batch in reader {
                let batch = batch.unwrap();
                let mut writer = arrow_json::LineDelimitedWriter::new(Vec::new());
                writer.write(&batch).unwrap();
                writer.finish().unwrap();
                for line in String::from_utf8(writer.into_inner()).unwrap().lines() {
                    let row: Value = serde_json::from_str(line).unwrap();
                    found = row["unmapped"]["event_data.destination_is_ipv_6"]
                        .as_str()
                        .map(str::to_owned);
                }
            }
        }
        assert_eq!(found.as_deref(), Some("false"));

        // A batch the schema can never admit is refused as such, so the
        // publisher quarantines it instead of retrying it forever:
        // (1) a changed physical type of an existing leaf;
        let mut flipped = source_event("type flip");
        flipped["metadata"]["uid"] = json!("flip");
        flipped["unmapped"] = json!({"channel": {"nested": true}});
        let flipped = admit("flipped.parquet", flipped);
        let error = ensure_additive_event_schema_with_cache(
            &catalog, &table_id, location, &flipped.batch, true,
        )
        .await
        .unwrap_err()
        .context("admit additive OCSF fields before staging tail");
        assert!(crate::iceberg::is_schema_admission_refused(&error), "{error:#}");
        // (2) a nested object whose full leaf name collides with an existing
        // flat dotted child (`unmapped.event_data.query_status` both ways).
        // The lean planner has the same collision (NAN-2998, moat_edr); here
        // it must quarantine one batch, not wedge the shard.
        let mut colliding = source_event("collision");
        colliding["metadata"]["uid"] = json!("collision");
        colliding["unmapped"] = json!({"event_data": {"query_status": "1"}});
        let colliding = admit("colliding.parquet", colliding);
        let error = ensure_additive_event_schema_with_cache(
            &catalog, &table_id, location, &colliding.batch, true,
        )
        .await
        .unwrap_err();
        assert!(crate::iceberg::is_schema_admission_refused(&error), "{error:#}");
        // Neither refusal changed the live schema.
        let live = catalog.load_table(&table_id).await.unwrap();
        assert_eq!(
            live.metadata().current_schema_id(),
            table.metadata().current_schema_id()
        );
    }

    /// NAN-3401, against the open-core REST catalog (Lakekeeper) rather than
    /// iceberg-rust's in-memory one: the server must also accept a schema
    /// whose `unmapped` struct gains flat dotted children. Point it at a
    /// throwaway catalog whose warehouse lives under `NAN3401_REST_LOCATION`:
    /// `NAN3401_REST_URI=http://127.0.0.1:38181/catalog NAN3401_REST_WAREHOUSE=nan3401
    ///  NAN3401_REST_LOCATION=s3://nan3401/wh cargo test -p nanosiem-lake-worker --lib
    ///  dotted_unmapped_keys_on_a_rest_catalog -- --ignored`
    #[tokio::test]
    #[ignore = "requires NAN3401_REST_URI/_WAREHOUSE/_LOCATION pointing at a disposable REST catalog"]
    async fn dotted_unmapped_keys_on_a_rest_catalog() {
        use crate::iceberg::ensure_additive_event_schema_with_cache;
        use iceberg::{Catalog, CatalogBuilder};
        let env = |name: &str| std::env::var(name).unwrap_or_else(|_| panic!("{name} is required"));
        let catalog = iceberg_catalog_rest::RestCatalogBuilder::default()
            .with_storage_factory(Arc::new(iceberg_storage_opendal::OpenDalStorageFactory::S3 {
                customized_credential_load: None,
            }))
            .load(
                "nan3401",
                std::collections::HashMap::from([
                    (iceberg_catalog_rest::REST_CATALOG_PROP_URI.to_string(), env("NAN3401_REST_URI")),
                    (
                        iceberg_catalog_rest::REST_CATALOG_PROP_WAREHOUSE.to_string(),
                        env("NAN3401_REST_WAREHOUSE"),
                    ),
                ]),
            )
            .await
            .unwrap();
        let run = format!(
            "r{}",
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        );
        let table_id = crate::iceberg::table_ident(&format!("nan3401_{run}.events")).unwrap();
        catalog
            .create_namespace(&table_id.namespace, Default::default())
            .await
            .unwrap();
        let location = format!("{}/nan3401/{run}/events/", env("NAN3401_REST_LOCATION").trim_end_matches('/'));
        let directory = tempfile::tempdir().unwrap();
        let admit = |name: &str, event: Value| {
            let path = directory.path().join(name);
            write_fixture(&path, &[event]);
            let mut admitted = admit_bronze_files(&[path], "tenant-a").unwrap();
            admitted.batch.seal_source_identity().unwrap();
            admitted
        };
        let mut base = source_event("base");
        base["unmapped"] = json!({"channel": "Security"});
        let base = admit("base.parquet", base);
        catalog
            .create_table(
                &table_id.namespace,
                crate::iceberg::pipeline_test_table(&base.batch, &location).unwrap(),
            )
            .await
            .unwrap();
        let mut sysmon = source_event("sysmon 3");
        sysmon["metadata"]["uid"] = json!("sysmon-3");
        sysmon["unmapped"] = json!({"event_data.destination_is_ipv_6": "false"});
        let sysmon = admit("sysmon.parquet", sysmon);
        ensure_additive_event_schema_with_cache(&catalog, &table_id, &location, &sysmon.batch, true)
            .await
            .expect("the REST catalog must accept a dotted child under unmapped");
        let reloaded = catalog.load_table(&table_id).await.unwrap();
        let schema = reloaded.metadata().current_schema();
        let iceberg::spec::Type::Struct(unmapped) =
            schema.field_by_name("unmapped").unwrap().field_type.as_ref()
        else {
            panic!("unmapped must stay a struct");
        };
        assert!(unmapped.field_by_name("event_data.destination_is_ipv_6").is_some());
        // A collision is refused by the catalog-bound admission without
        // changing the committed schema.
        let mut colliding = source_event("collision");
        colliding["metadata"]["uid"] = json!("collision");
        colliding["unmapped"] = json!({"event_data": {"destination_is_ipv_6": "true"}});
        let colliding = admit("colliding.parquet", colliding);
        let error = ensure_additive_event_schema_with_cache(
            &catalog, &table_id, &location, &colliding.batch, true,
        )
        .await
        .unwrap_err();
        assert!(crate::iceberg::is_schema_admission_refused(&error), "{error:#}");
        assert_eq!(
            catalog.load_table(&table_id).await.unwrap().metadata().current_schema_id(),
            reloaded.metadata().current_schema_id()
        );
    }

    /// Correctness gate: runs in every default `cargo test`. The NAN-2404
    /// rates are printed but not asserted, because a debug-build throughput
    /// floor depends on the runner (spot-x64-4 ran 912 rows/s wall where
    /// spot-x64-3 and the proxmox builders clear 1500). The floor lives in
    /// `pipeline_100k_rows_throughput_floor` (NAN-2817).
    #[tokio::test]
    async fn pipeline_100k_rows_produces_two_real_iceberg_snapshots() {
        run_synthetic_pipeline_100k().await;
    }

    /// Measurement gate, not part of the default run:
    /// `cargo test -p nanosiem-lake-worker --lib
    ///  bronze::tests::pipeline_100k_rows_throughput_floor -- --ignored --nocapture`
    #[tokio::test]
    #[ignore = "measurement; run explicitly with --ignored --nocapture"]
    async fn pipeline_100k_rows_throughput_floor() {
        let (wall_rate, cpu_rate) = run_synthetic_pipeline_100k().await;
        // A conservative debug-build regression floor; the release hosted
        // acceptance rate must be measured separately with network and UID IO.
        // A real regression is slower on BOTH clocks. Wall time alone also
        // counts other jobs on a shared runner, and process CPU time alone
        // over-counts any parallel stage, so the floor holds on the better one.
        let rate = wall_rate.max(cpu_rate);
        assert!(
            rate >= 1500.0,
            "synthetic pipeline fell below 1500 rows/s on both clocks: wall {wall_rate}, CPU {cpu_rate}"
        );
    }

    /// Runs 100k synthetic rows through bronze admission, staged encoding
    /// and compaction, asserts the correctness invariants, prints the rates
    /// and returns `(wall rows/s, rows/CPU-s)`.
    async fn run_synthetic_pipeline_100k() -> (f64, f64) {
        use crate::iceberg::{
            encode_staged_event_files_normalized, ensure_additive_event_schema_with_cache,
            register_compacted_staged_file_for, repack_staged_files_with_profile,
            TailIdentityProfile,
        };
        use crate::pipeline::CompactionCadence;
        use iceberg::{Catalog, CatalogBuilder};
        use sha2::Digest;
        let directory = tempfile::tempdir().unwrap();
        let catalog = iceberg::memory::MemoryCatalogBuilder::default()
            .load(
                "test",
                std::collections::HashMap::from([(
                    "warehouse".to_string(),
                    "s3://test/warehouse".to_string(),
                )]),
            )
            .await
            .unwrap();
        let table_id = crate::iceberg::table_ident("tenant_a.events").unwrap();
        catalog
            .create_namespace(&table_id.namespace, Default::default())
            .await
            .unwrap();
        let location = "s3://test/warehouse/events/";
        let cadence = CompactionCadence {
            target_rows: 50_000,
            target_bytes: 64 << 20,
            interval_seconds: 300,
        };
        let mut pending = Vec::new();
        let (mut pending_rows, mut pending_bytes, mut committed_rows) = (0_u64, 0_u64, 0_u64);
        let mut oldest_pending_epoch = 0;
        let uid_ledger = crate::bronze_uid_ledger::BronzeUidLedger::open(
            "pipeline-uid-ledger",
            Arc::new(slatedb::object_store::memory::InMemory::new()),
            None,
            0,
            32,
            100_000,
        )
        .await
        .unwrap();
        uid_ledger.verify_or_initialize(false).await.unwrap();
        let started = std::time::Instant::now();
        let cpu_started = crate::query_timing::process_cpu_ms().expect("process CPU clock");
        for pass in 0..10 {
            let events = (0..10_000)
                .map(|row| {
                    let mut event = source_event("synthetic throughput");
                    event["metadata"]["uid"] = json!(format!("{pass}-{row}"));
                    event
                })
                .collect::<Vec<_>>();
            let bronze = directory.path().join(format!("bronze-{pass}.parquet"));
            write_fixture(&bronze, &events);
            let mut admitted = admit_bronze_files(&[bronze], "tenant-a").unwrap();
            let owner = hex::encode(sha2::Sha256::digest(format!("pass-{pass}").as_bytes()));
            let claims = uid_ledger
                .claim_batch(&owner, admitted.source_identity_digests())
                .await
                .unwrap();
            assert_eq!(claims.claimed_uids.len(), 10_000);
            admitted.batch.seal_source_identity().unwrap();
            assert_eq!(admitted.batch.len(), 10_000);
            if pass == 0 {
                catalog
                    .create_table(
                        &table_id.namespace,
                        crate::iceberg::pipeline_test_table(&admitted.batch, location).unwrap(),
                    )
                    .await
                    .unwrap();
            }
            let table = ensure_additive_event_schema_with_cache(
                &catalog,
                &table_id,
                location,
                &admitted.batch,
                true,
            )
            .await
            .unwrap();
            let staged = encode_staged_event_files_normalized(&table, &admitted.batch).unwrap();
            assert_eq!(staged.len(), 1);
            let file = &staged[0];
            let path = directory.path().join(format!("staged-{pass}.parquet"));
            std::fs::write(&path, &file.bytes).unwrap();
            pending.push(path);
            pending_rows += file.rows;
            pending_bytes += file.bytes.len() as u64;
            if !cadence.ready(pending_rows, pending_bytes, oldest_pending_epoch, pass) {
                continue;
            }
            let pack_id = hex::encode(sha2::Sha256::digest(format!("pack-{pass}").as_bytes()));
            let packed = crate::iceberg::with_refreshed_staged_schema(
                &catalog, &table_id, &table, |arrow_schema| {
                    repack_staged_files_with_profile(
                        arrow_schema,
                        TailIdentityProfile::for_table_name("events"),
                        "tenant-a",
                        file.event_hour,
                        &pack_id,
                        &pending,
                        3,
                    )
                }).await.unwrap();
            assert_eq!(packed.rows, pending_rows);
            let object_path = format!("{}{}", location, packed.relative_path);
            let mut writer = table
                .file_io()
                .new_output(&object_path)
                .unwrap()
                .writer()
                .await
                .unwrap();
            writer
                .write(bytes::Bytes::from(packed.bytes.clone()))
                .await
                .unwrap();
            writer.close().await.unwrap();
            let committed = register_compacted_staged_file_for(
                &catalog,
                &table_id,
                TailIdentityProfile::for_table_name("events"),
                "tenant-a",
                &pack_id,
                &packed.sha256,
                &object_path,
                packed.event_hour,
                packed.bytes.len() as u64,
                packed.rows,
            )
            .await
            .unwrap();
            assert_eq!(committed.status, "compacted");
            // An ambiguous catalog acknowledgment retries the same snapshot.
            let replay = register_compacted_staged_file_for(
                &catalog,
                &table_id,
                TailIdentityProfile::for_table_name("events"),
                "tenant-a",
                &pack_id,
                &packed.sha256,
                &object_path,
                packed.event_hour,
                packed.bytes.len() as u64,
                packed.rows,
            )
            .await
            .unwrap();
            assert_eq!(replay.snapshot_id, committed.snapshot_id);
            committed_rows += packed.rows;
            oldest_pending_epoch = pass + 1;
            pending.clear();
            pending_rows = 0;
            pending_bytes = 0;
        }
        uid_ledger.close().await.unwrap();
        let table = catalog.load_table(&table_id).await.unwrap();
        assert_eq!(table.metadata().snapshots().count(), 2);
        assert_eq!(committed_rows, 100_000);
        assert!(pending.is_empty());
        let wall_rate = committed_rows as f64 / started.elapsed().as_secs_f64();
        let cpu_seconds = (crate::query_timing::process_cpu_ms().expect("process CPU clock")
            - cpu_started)
            / 1000.0;
        let cpu_rate = committed_rows as f64 / cpu_seconds.max(f64::EPSILON);
        eprintln!(
            "NAN-2404 synthetic bronze/staged/compaction: {wall_rate:.0} rows/s wall, \
             {cpu_rate:.0} rows/CPU-s, 2 snapshots, 100000 rows"
        );
        (wall_rate, cpu_rate)
    }

    /// NAN-3079 regression: a tenant bundle writes `unmapped` into bronze as
    /// one JSON string (so a `threat_signals: []` row next to a JSON-string
    /// spill cannot fail the batch's Parquet encode and drop the batch).
    /// Admission must restore the object, so the admitted row is identical to
    /// the same event whose `unmapped` arrived as an object.
    #[test]
    fn bronze_admission_decodes_string_unmapped_like_an_object() {
        let directory = tempfile::tempdir().unwrap();
        let with_unmapped = |uid: &str, unmapped: Value| {
            let mut event = source_event("drift");
            event["metadata"]["uid"] = json!(uid);
            event["unmapped"] = unmapped;
            event
        };
        let probe = json!({"threat_signals": [], "tls_intercepted": true, "cache_status": "miss"});
        let spill = json!({"threat_signals": "[{\"name\":\"dga_entropy\"}]", "cache_status": "hit"});

        // Bronze form: both rows carry a string `unmapped`, one Parquet column.
        let encoded = directory.path().join("encoded.parquet");
        write_fixture(&encoded, &[
            with_unmapped("probe", json!(probe.to_string())),
            with_unmapped("blaster", json!(spill.to_string())),
        ]);
        let from_string = admit_bronze_files(&[encoded], "tenant-a").unwrap();
        assert_eq!(from_string.batch.len(), 2, "no row of the mixed batch is lost");

        // Reference: the same events with `unmapped` as objects, one per file
        // (together they would not share one inferred Parquet schema).
        let mut expected = Vec::new();
        for (uid, unmapped) in [("probe", probe), ("blaster", spill)] {
            let path = directory.path().join(format!("{uid}.parquet"));
            write_fixture(&path, &[with_unmapped(uid, unmapped)]);
            let admitted = admit_bronze_files(&[path], "tenant-a").unwrap();
            expected.push(admitted.batch.rows()[0].clone());
        }
        let mut rows = from_string.batch.rows().to_vec();
        rows.sort_by(|a, b| a.event_uid.cmp(&b.event_uid));
        expected.sort_by(|a, b| a.event_uid.cmp(&b.event_uid));
        for (row, want) in rows.iter().zip(&expected) {
            assert_eq!(row.event_uid, want.event_uid);
            assert!(row.ocsf_event["unmapped"].is_object(), "{}", row.ocsf_event["unmapped"]);
            assert_eq!(row.ocsf_event["unmapped"], want.ocsf_event["unmapped"]);
        }
    }

    /// NAN-3339: a contract row decodes to the columnar form's event (null
    /// members dropped, `time` from its column, `unmapped` decoded); a
    /// columnar row is only `unmapped`-decoded; a broken contract row is
    /// refused on its own.
    #[test]
    fn decode_bronze_row_unwraps_the_contract_and_keeps_columnar_rows() {
        let inner = json!({"class_uid": 0, "metadata": {"uid": "u1", "gone": null},
            "observables": [{"name": "a", "value": null}, null], "unmapped": "{\"k\":null}"});
        let row = json!({"time": "2026-10-08T15:33:17.123Z", "_nano_bronze_event": inner.to_string()});
        assert_eq!(decode_bronze_row(row).unwrap(), json!({"class_uid": 0, "metadata": {"uid": "u1"},
            "observables": [{"name": "a"}, null], "unmapped": {"k": null}, "time": "2026-10-08T15:33:17.123Z"}));
        let columnar = json!({"time": "2026-10-08T15:33:17.123Z", "unmapped": "{\"a\":1}"});
        assert_eq!(decode_bronze_row(columnar).unwrap(), json!({"time": "2026-10-08T15:33:17.123Z", "unmapped": {"a": 1}}));
        for broken in ["[1]", "\"s\"", "{not json"] {
            assert!(decode_bronze_row(json!({"time": null, "_nano_bronze_event": broken})).is_err(), "{broken}");
        }
        assert_eq!(decode_bronze_row(json!({"_nano_bronze_event": "{\"a\":1}"})).unwrap(), json!({"a": 1}));
    }

    #[test]
    fn decode_bronze_unmapped_only_replaces_a_json_object_string() {
        let mut event = json!({"unmapped": "{\"a\":[]}"});
        decode_bronze_unmapped(&mut event);
        assert_eq!(event, json!({"unmapped": {"a": []}}));
        for untouched in [json!({"unmapped": {"a": 1}}), json!({"unmapped": "[1]"}),
                          json!({"unmapped": "not json"}), json!({"other": "{}"})] {
            let mut event = untouched.clone();
            decode_bronze_unmapped(&mut event);
            assert_eq!(event, untouched);
        }
    }

    #[test]
    fn bronze_admission_deduplicates_identical_retries_and_normalizes() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("events.parquet");
        let event = source_event("same");
        write_fixture(&path, &[event.clone(), event]);
        let admitted = admit_bronze_files(&[path], "tenant-a").unwrap();
        assert_eq!(admitted.source_rows, 2);
        assert_eq!(admitted.duplicate_rows_removed, 1);
        assert_eq!(admitted.files.len(), 1);
        assert_eq!(admitted.files[0].rows, 2);
        assert_eq!(admitted.batch.len(), 1);
        assert_eq!(
            admitted.batch.rows()[0].ocsf_event["metadata"]["log_source"],
            "windows_event"
        );
        assert_eq!(
            admitted.batch.rows()[0].ocsf_event["actor"]["user"]["name"],
            "tester"
        );
        assert_eq!(bronze_file_row_count(&admitted.files[0].path).unwrap(), 2);
    }

    #[test]
    fn admission_v2_fields_are_lowercase_in_stored_rows() {
        let mut event = source_event("lowercase guarantee");
        event["src_endpoint"] = json!({"ip": "FE80::ABCD", "hostname": "SRC.EXAMPLE", "mac": "AA:BB:CC:DD:EE:FF"});
        event["dst_endpoint"] = json!({"ip": "FE80::DCBA", "hostname": "DST.EXAMPLE", "mac": "FF:EE:DD:CC:BB:AA"});
        let admitted = admit_event_without_pin(event, "tenant-a", &BronzeIngestEnricher::disabled()).unwrap();
        let stored = &admitted.row.ocsf_event;
        for path in crate::parts::provenance::LOWERCASED_AT_REST {
            let value = path.split('.').fold(stored, |node, key| &node[key]);
            let text = value.as_str().expect("fixture has every attested path");
            assert_eq!(text, text.trim().to_ascii_lowercase(), "{path}");
        }
        assert!(!crate::parts::provenance::LOWERCASED_AT_REST.contains(&"user.name"));
    }

    /// NAN-3490: refusal reasons name the cause and field, never row content.
    #[test]
    fn row_refusals_are_classified_without_row_values() {
        const SECRET: &str = "C0secretcustomer";
        let enricher = BronzeIngestEnricher::disabled();
        let refuse = |event: Value| {
            let error = admit_event_without_pin(event, "tenant-a", &enricher)
                .err()
                .expect("refused");
            let refusal = classify_row_refusal(&error);
            assert!(!refusal.to_string().contains(SECRET), "{refusal}");
            refusal
        };
        let mut no_uid = source_event("x");
        no_uid["metadata"].as_object_mut().unwrap().remove("uid");
        assert_eq!(refuse(no_uid), RowRefusal::new("uid_missing", Some("metadata.uid")));

        let mut wrong_tenant = source_event("x");
        wrong_tenant["metadata"]["uid"] = json!(format!("gws|token|{SECRET}|1"));
        wrong_tenant["metadata"]["tenant_uid"] = json!(SECRET);
        assert_eq!(
            refuse(wrong_tenant),
            RowRefusal::new("metadata_conflict", Some("metadata.tenant_uid"))
        );

        let mut bad_time = source_event("x");
        bad_time["metadata"]["uid"] = json!(format!("gws|token|{SECRET}|2"));
        bad_time["time"] = json!(0);
        assert_eq!(refuse(bad_time), RowRefusal::new("time_invalid", Some("time")));

        // The validator preview quotes the offending value; the refusal
        // keeps only the diagnostic code and the attribute path.
        let mut bad_enum = source_event("x");
        bad_enum["metadata"]["uid"] = json!(format!("gws|token|{SECRET}|3"));
        bad_enum["src_endpoint"] = json!({"ip": SECRET});
        let refusal = refuse(bad_enum);
        assert!(refusal.reason.starts_with("ocsf_"), "{refusal}");
        assert_eq!(refusal.field.as_deref(), Some("src_endpoint.ip"), "{refusal}");

        let unknown = classify_row_refusal(&anyhow::anyhow!("{SECRET} broke"));
        assert_eq!(unknown, RowRefusal::new("unclassified", None));
        let staged = classify_row_refusal(
            &anyhow::anyhow!("{SECRET} broke").context(format!("enrich Vector bronze event gws|{SECRET}")),
        );
        assert_eq!(staged, RowRefusal::new("enrichment_failed", None));
        assert_eq!(
            RowRefusal::new("x", Some("unmapped.a b=\"v\"[0]")).field.as_deref(),
            Some("unmapped.abv[0]")
        );
    }

    /// NAN-3490: an object whose every row is refused fails as a whole, and
    /// the failure names its first row's cause (value-free).
    #[test]
    fn an_all_refused_object_names_its_first_row_refusal() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("events.parquet");
        let rows = (0..4)
            .map(|index| {
                let mut event = source_event("x");
                event["metadata"]["uid"] = json!(format!("gws|token|C0secretcustomer|{index}"));
                event["metadata"]["tenant_uid"] = json!("C0secretcustomer");
                event
            })
            .collect::<Vec<_>>();
        write_fixture(&path, &rows);
        let Err(error) = admit_bronze_files_salvaging(&[path], "tenant-a", &BronzeIngestEnricher::disabled()) else {
            panic!("no row may be admitted");
        };
        let refused = error.downcast_ref::<NoCanonicalEvents>().expect("typed");
        assert_eq!(
            refused.first_row,
            Some(RowRefusal::new("metadata_conflict", Some("metadata.tenant_uid")))
        );
        let text = format!("{error:#}");
        assert_eq!(
            text,
            "bronze admission produced no canonical events; first_row_reason=metadata_conflict first_row_field=metadata.tenant_uid"
        );

        // One good row keeps the object; the refused rows carry the same
        // value-free first refusal.
        let path = directory.path().join("mixed.parquet");
        let mut mixed = rows;
        mixed.push(source_event("good"));
        write_fixture(&path, &mixed);
        let (admission, refused) =
            admit_bronze_files_salvaging(std::slice::from_ref(&path), "tenant-a", &BronzeIngestEnricher::disabled()).unwrap();
        assert_eq!(admission.batch.len(), 1);
        let (count, first) = &refused[&path];
        assert_eq!(*count, 4);
        assert_eq!(first.to_string(), "first_row_reason=metadata_conflict first_row_field=metadata.tenant_uid");
    }

    /// An Entra SignInLogs row as the `azure_monitor_ocsf` parser emitted it
    /// on tenant-b (NAN-3680): Authentication 3002 whose `device` carries
    /// only `os` and no identifier.
    fn entra_sign_in(uid: &str, device: Value) -> Value {
        json!({
            "activity_id": 1,
            "activity_name": "Logon",
            "category_name": "Identity & Access Management",
            "category_uid": 3,
            "class_name": "Authentication",
            "class_uid": 3002,
            "device": device,
            "message": "Entra sign-in",
            "raw_data": "fixture",
            "raw_data_size": 7,
            "metadata": {
                "log_name": "SignInLogs",
                "log_source": "azure_monitor",
                "profiles": ["host"],
                "ingress_transport": "hec",
                "nano_credential_id": "7d0b5c2e-4f1a-4c3e-9a6b-1e2f3a4b5c6d",
                "product": {"name": "Entra ID", "vendor_name": "Microsoft"},
                "tenant_uid": "tenant-a",
                "uid": uid,
                "version": "1.9.0"
            },
            "service": {"name": "Microsoft Entra ID"},
            "severity": "Informational",
            "severity_id": 1,
            "src_endpoint": {"ip": "10.1.2.3"},
            "status": "Success",
            "status_id": 1,
            "time": "2026-10-12T08:00:00.000000+00:00",
            "type_uid": 300201,
            "user": {"name": "fixture-user", "uid": "fixture-user-id"}
        })
    }

    /// NAN-3680: the tenant-b SignInLogs drop. The device-without-an-
    /// identifier row is refused by the strict OCSF constraint and attributed
    /// to its `metadata.log_source`; its sibling in the same object publishes.
    #[test]
    fn a_device_without_an_identifier_is_refused_and_attributed_to_its_source() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("signin.parquet");
        let refused = entra_sign_in("signin-bad", json!({"os": {"name": "Windows10", "type_id": 100}, "type_id": 0}));
        let good = entra_sign_in(
            "signin-good",
            json!({"hostname": "laptop-1", "os": {"name": "Windows10", "type_id": 100}, "type_id": 0}),
        );
        write_fixture(&path, &[refused, good]);
        let (admission, rows, sources) = admit_bronze_files_attributing(
            std::slice::from_ref(&path),
            "tenant-a",
            &BronzeIngestEnricher::disabled(),
        )
        .unwrap();
        assert_eq!(admission.batch.len(), 1, "the good sibling publishes");
        assert_eq!(admission.batch.rows()[0].event_uid, "signin-good");
        let (count, first) = &rows[&path];
        assert_eq!(*count, 1);
        assert_eq!(*first, RowRefusal::new("ocsf_constraint_failed", Some("device")));

        let attributed = sources.iter().collect::<Vec<_>>();
        assert_eq!(attributed.len(), 1);
        let (key, source) = attributed[0];
        assert_eq!(key.source_slug, "azure_monitor");
        assert_eq!(key.protocol, "hec");
        assert_eq!(key.credential_id.as_deref(), Some("7d0b5c2e-4f1a-4c3e-9a6b-1e2f3a4b5c6d"));
        assert_eq!(source.rows, 1);
        assert_eq!(source.first.reason, "ocsf_constraint_failed");
        assert_eq!(source.first.field.as_deref(), Some("device"));

        // Every row refused: nothing publishes, but the per-source refusals
        // ride on the error so the publisher can still count them.
        let path = directory.path().join("all-refused.parquet");
        let rows = (0..3)
            .map(|index| {
                entra_sign_in(&format!("signin-{index}"), json!({"os": {"name": "Windows10", "type_id": 100}, "type_id": 0}))
            })
            .collect::<Vec<_>>();
        write_fixture(&path, &rows);
        let Err(error) = admit_bronze_files_attributing(&[path], "tenant-a", &BronzeIngestEnricher::disabled()) else {
            panic!("no row may be admitted");
        };
        let refused = error.downcast_ref::<NoCanonicalEvents>().expect("typed");
        assert_eq!(refused.refused_sources.total(), 3);
        let (key, source) = refused.refused_sources.iter().next().unwrap();
        assert_eq!(key.source_slug, "azure_monitor");
        assert_eq!(source.first.reason, "ocsf_constraint_failed");
    }

    /// A row refused before any OCSF check (no `metadata.uid`) is still
    /// attributed by its readable `metadata.log_source`.
    #[test]
    fn a_row_refused_before_validation_keeps_its_readable_source() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("events.parquet");
        let mut no_uid = source_event("no uid");
        no_uid["metadata"].as_object_mut().unwrap().remove("uid");
        write_fixture(&path, &[no_uid, source_event("good")]);
        let (_, _, sources) =
            admit_bronze_files_attributing(&[path], "tenant-a", &BronzeIngestEnricher::disabled()).unwrap();
        let attributed = sources.iter().collect::<Vec<_>>();
        assert_eq!(attributed.len(), 1);
        assert_eq!(attributed[0].0.source_slug, "windows_event");
        assert_eq!(attributed[0].1.first.reason, "uid_missing");
    }

    #[test]
    fn bronze_shape_inspection_rejects_a_non_parquet_file() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("events.parquet");
        std::fs::write(&path, b"not parquet").unwrap();
        assert!(bronze_file_row_count(&path).is_err());
    }

    /// NAN-3719: one uid under two source identities in one admission is
    /// row-scoped. One copy is kept, the others are dropped and counted, and
    /// every unrelated row is still admitted.
    #[test]
    fn bronze_admission_keeps_one_copy_of_a_conflicting_replay_identity() {
        let admit = |events: &[Value]| {
            let directory = tempfile::tempdir().unwrap();
            let path = directory.path().join("events.parquet");
            write_fixture(&path, events);
            admit_bronze_files(&[path], "tenant-a").unwrap()
        };
        let other = |n: usize| {
            let mut event = source_event("unrelated");
            event["metadata"]["uid"] = json!(format!("other-{n}"));
            event
        };
        let left = source_event("left");
        let right = source_event("right");
        let mut right_retry = right.clone();
        right_retry["metadata"]["logged_time"] = json!(1_786_465_781_371_i64);
        let kept_message = |admission: &BronzeAdmission| {
            admission.batch.rows().iter()
                .find(|row| row.event_uid == "source-1")
                .map(|row| row.ocsf_event["message"].as_str().unwrap().to_owned())
                .unwrap()
        };
        // Every read order keeps the same copy and counts the same rows.
        let orders = [
            vec![other(0), left.clone(), right.clone(), right_retry.clone(), other(1)],
            vec![right.clone(), right_retry.clone(), other(1), left.clone(), other(0)],
            vec![right_retry.clone(), other(0), left.clone(), other(1), right.clone()],
        ];
        let mut kept = BTreeSet::new();
        for order in &orders {
            let admission = admit(order);
            assert_eq!(admission.batch.len(), 3, "both unrelated rows and one source-1 copy");
            assert_eq!(admission.duplicate_rows_removed, 2);
            // `right` and its retry are one copy (2 rows), `left` the other.
            let kept_copy = kept_message(&admission);
            let expected = if kept_copy == "left" { 2 } else { 1 };
            assert_eq!(admission.conflicting_replay_rows_dropped, expected, "every row of the losing copy counts");
            kept.insert((kept_copy, admission.conflicting_replay_rows_dropped));
        }
        assert_eq!(kept.len(), 1, "the kept copy and count never depend on read order: {kept:?}");
        // An earlier event time wins regardless of digest order.
        let mut early = source_event("early");
        early["time"] = json!("2026-08-11T07:59:00+00:00");
        for order in [vec![left.clone(), early.clone()], vec![early.clone(), left.clone()]] {
            let admission = admit(&order);
            assert_eq!(kept_message(&admission), "early");
            assert_eq!(admission.conflicting_replay_rows_dropped, 1);
        }
    }

    #[test]
    fn bronze_admission_ignores_delivery_metadata_but_is_deterministic() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("events.parquet");
        let mut earlier = source_event("same");
        earlier["metadata"]["logged_time"] = json!(1_786_465_198_969_i64);
        earlier["metadata"]["processed_time"] = json!(1_786_465_198_969_i64);
        earlier["metadata"]["original_event_uid"] = json!("parser-attempt-1");
        let mut later = earlier.clone();
        later["metadata"]["logged_time"] = json!(1_786_465_781_371_i64);
        later["metadata"]["processed_time"] = json!(1_786_465_781_371_i64);
        later["metadata"]["original_event_uid"] = json!("parser-attempt-2");
        write_fixture(&path, &[later, earlier]);
        let admitted = admit_bronze_files(&[path], "tenant-a").unwrap();
        assert_eq!(admitted.duplicate_rows_removed, 1);
        assert_eq!(
            admitted.batch.rows()[0].ocsf_event["metadata"]["logged_time"],
            1_786_465_198_969_i64
        );
    }

    #[test]
    fn durable_source_identity_is_captured_before_normalization_or_decoration() {
        let event = source_event("same");
        let expected = source_identity_digest(&event).unwrap();
        let admitted =
            admit_event_without_pin(event, "tenant-a", &BronzeIngestEnricher::disabled()).unwrap();
        assert_eq!(admitted.digest, expected);
        assert_ne!(
            admitted.digest,
            source_identity_digest(&admitted.row.ocsf_event).unwrap(),
            "normalization lowercases source fields and must not redefine retry identity"
        );
    }

    #[test]
    fn cross_cycle_selection_reseals_only_claimed_rows() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("events.parquet");
        let mut first = source_event("first");
        first["metadata"]["uid"] = json!("source-1");
        let mut second = source_event("second");
        second["metadata"]["uid"] = json!("source-2");
        write_fixture(&path, &[first, second]);
        let mut admitted = admit_bronze_files(&[path], "tenant-a").unwrap();
        let original = admitted.batch.seal_source_identity().unwrap().to_string();
        admitted
            .retain_claimed_uids(&BTreeSet::from(["source-2".to_string()]))
            .unwrap();
        let retained = admitted.batch.seal_source_identity().unwrap().to_string();
        assert_ne!(original, retained);
        assert_eq!(admitted.batch.len(), 1);
        assert_eq!(admitted.batch.rows()[0].event_uid, "source-2");
        assert_eq!(admitted.source_identity_digests().len(), 1);
    }
}
