// SPDX-License-Identifier: AGPL-3.0-or-later

//! The one-time, resumable adoption job.
//!
//! **State lives in the part log, not in the job.** The adopted set is the
//! live parts with `sorted = false`, each record naming its `(key, sha256)`.
//! On every start the job verifies the log, rebuilds that set, and adopts
//! only the plan's objects missing from it:
//! - a re-run after completion is a no-op (nothing appended);
//! - a crash (including `kill -9`) before an `adopt` entry commits leaves
//!   only orphan sidecar files (unique part ids; GC'd after 24 h) and the
//!   objects of that batch are redone;
//! - a crash after the commit loses nothing: the next start sees the parts.
//!
//! Writes: sidecars and `provenance.json` under `parts/`, then `schema` /
//! `adopt` entries under `log/`, all conditional creates. Reads of source
//! objects go through [`AdoptSource`], read-only.

use anyhow::{bail, Context, Result};
use arrow_schema::{DataType, Field, Fields, Schema as ArrowSchema};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;

use super::build::{build_adopted_sidecars, BuildBudgets, BuiltSidecars};
use super::plan::{AdoptionPlan, PlannedObject};
use super::source::AdoptSource;
use crate::parts::format::{schema_fingerprint, tokens_file_name, PartId, PartKeys, MAX_OBJECT_BYTES};
use crate::parts::part_log::{
    load_log, LiveSet, LogOp, LogSchema, ObjectStore, PartLogWriter, PartRef, WriteHints, WriterClass,
};
use crate::parts::provenance::{
    AdoptedObject, DataFileDigest, DedupStats, FileDigest, PartFiles, PartInputs, PartSigner, PartialDigest,
    ProvenanceRecord, SignedProvenance, TenantKeySet, WriterInfo, MAX_PROVENANCE_BYTES, PROVENANCE_FORMAT,
    SIGN_BATCH_MAX,
};
use crate::parts::{sha256_hex, DedupWindow, Level};

/// Where the job is, for crash-injection hooks (tests) and progress.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdoptStage<'a> {
    /// One object's sidecars and record are uploaded; its entry is pending.
    PartUploaded { key: &'a str, part_id: &'a PartId },
    /// A batch is about to be committed.
    BeforeAppend { batch: usize, parts: usize },
    /// A batch committed at `seq`.
    AfterAppend { batch: usize, seq: u64 },
}

/// Test and progress hooks. An error aborts the run at that point.
pub trait AdoptHooks: Send + Sync {
    fn at(&self, stage: &AdoptStage<'_>) -> Result<()>;
}

/// Parts per `adopt` entry at most (a `PartRef` is ~600 B of canonical
/// JSON; this keeps an entry far below the 4 MiB log-object cap).
pub const MAX_BATCH_PARTS: usize = 1_000;

#[derive(Clone)]
pub struct AdoptOptions {
    /// Local scratch (under ~/.cache for lab and runbook runs).
    pub work_dir: PathBuf,
    /// Parts per `adopt` entry (bounds the work redone after a crash).
    pub batch_parts: usize,
    /// Records per `lake-parts:sign` call (1..=16). The owner re-reads and
    /// SHA-checks every file a record names, the adopted object included,
    /// so a smaller batch bounds each call's verify bytes.
    pub sign_batch: usize,
    pub budgets: BuildBudgets,
    /// `writer.build` recorded in each record (e.g. `git:<sha>`).
    pub writer_build: String,
    /// Stop after this many newly adopted objects (bounded runs).
    pub max_objects: Option<usize>,
    pub hooks: Option<Arc<dyn AdoptHooks>>,
}

impl AdoptOptions {
    pub fn new(work_dir: impl Into<PathBuf>, writer_build: impl Into<String>) -> Self {
        Self {
            work_dir: work_dir.into(),
            batch_parts: 24,
            sign_batch: 8,
            budgets: BuildBudgets::default(),
            writer_build: writer_build.into(),
            max_objects: None,
            hooks: None,
        }
    }
}

/// Who signs and who is trusted. Records are signed by the owner through
/// `lake-parts:sign` (contract 4.4); the job holds no signing key.
pub struct AdoptSigner<'a> {
    pub signer: &'a dyn PartSigner,
    /// The tenant's trusted owner keys; every returned signature is checked.
    pub trusted: &'a TenantKeySet,
    pub writer_epoch: u64,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct ObjectReport {
    pub key: String,
    pub part_id: String,
    pub level: String,
    pub rows: u64,
    pub bytes: u64,
    pub row_groups: u32,
    pub hours: usize,
    pub blooms_missing: usize,
    pub duplicate_uids: u64,
    pub leaf_runs: usize,
    pub partial_runs: usize,
    pub build_seconds: f64,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct AdoptReport {
    pub tenant_id: String,
    pub generation_id: String,
    pub objects_in_plan: usize,
    pub already_adopted: usize,
    pub adopted_now: usize,
    /// Objects whose rows are all at or after T0 (shadow ingest owns them).
    pub skipped_at_or_after_t0: Vec<String>,
    pub remaining: usize,
    pub rows_adopted: u64,
    pub bytes_read: u64,
    pub adopt_entries: usize,
    pub schema_entries: usize,
    pub head_seq: Option<u64>,
    pub wall_seconds: f64,
    pub cpu_seconds: f64,
    pub peak_rss_kib: u64,
    pub objects: Vec<ObjectReport>,
}

/// One adopted part as the log names it.
#[derive(Debug, Clone)]
pub struct AdoptedPart {
    pub part: PartRef,
    pub record: ProvenanceRecord,
}

/// Every live adopted part (`sorted = false`) with its verified record,
/// keyed by the original object key. O(adopted parts) record GETs.
pub async fn adopted_parts(
    store: &dyn ObjectStore,
    tenant_id: &str,
    trusted: &TenantKeySet,
) -> Result<BTreeMap<String, AdoptedPart>> {
    let live = load_log(store, tenant_id).await?;
    adopted_in(store, tenant_id, trusted, &live).await
}

/// [`adopted_parts`] over an already-loaded live set (the writer's own).
pub async fn adopted_in(
    store: &dyn ObjectStore,
    tenant_id: &str,
    trusted: &TenantKeySet,
    live: &LiveSet,
) -> Result<BTreeMap<String, AdoptedPart>> {
    let mut adopted = BTreeMap::new();
    for part in live.parts().filter(|p| !p.sorted) {
        let keys = PartKeys::new(tenant_id, part.level, part.event_hour, &part.part_id)?;
        let bytes = store
            .get(&keys.provenance())
            .await?
            .with_context(|| format!("adopted part {} has no provenance record", part.part_id))?;
        if sha256_hex(&bytes) != part.provenance_sha256 {
            bail!("adopted part {} record differs from its log entry", part.part_id);
        }
        let signed = SignedProvenance::verify_bytes(&bytes, tenant_id, trusted)?;
        part.check_record(&signed.record, &part.provenance_sha256)?;
        let PartInputs::Adopted { objects, .. } = &signed.record.inputs else {
            bail!("unsorted live part {} is not an adopted part", part.part_id);
        };
        let key = objects[0].key.clone();
        if adopted.insert(key.clone(), AdoptedPart { part: part.clone(), record: signed.record }).is_some() {
            bail!("object {key} is adopted twice in the live set");
        }
    }
    Ok(adopted)
}

/// Every live adopted part must come from the plan's generation (one anchor
/// per tenant; a second generation would mix stamp ledgers).
fn check_single_generation(adopted: &BTreeMap<String, AdoptedPart>, plan: &AdoptionPlan) -> Result<()> {
    for (key, part) in adopted {
        let PartInputs::Adopted { anchor, .. } = &part.record.inputs else { unreachable!() };
        if anchor.generation_id != plan.anchor.generation_id {
            bail!(
                "object {key} is adopted from generation {}, not the plan's {}; refusing to mix generations",
                anchor.generation_id,
                plan.anchor.generation_id
            );
        }
    }
    Ok(())
}

/// Additive union of two Arrow schemas (fields by name, structs and lists
/// recursively, nullable if either is). A leaf type change is refused.
pub fn schema_union(left: &ArrowSchema, right: &ArrowSchema) -> Result<ArrowSchema> {
    Ok(ArrowSchema::new(union_fields(left.fields(), right.fields())?))
}

fn strip(field: &Field) -> Field {
    Field::new(field.name(), strip_type(field.data_type()), field.is_nullable())
}

fn strip_type(data_type: &DataType) -> DataType {
    match data_type {
        DataType::Struct(fields) => DataType::Struct(fields.iter().map(|f| strip(f)).collect()),
        DataType::List(child) => DataType::List(Arc::new(strip(child))),
        DataType::LargeList(child) => DataType::LargeList(Arc::new(strip(child))),
        other => other.clone(),
    }
}

fn union_fields(left: &Fields, right: &Fields) -> Result<Vec<Field>> {
    let mut out = left.iter().map(|f| strip(f)).collect::<Vec<_>>();
    for field in right.iter() {
        match out.iter().position(|f| f.name() == field.name()) {
            None => out.push(strip(field)),
            Some(index) => {
                let current = &out[index];
                let data_type = union_type(current.data_type(), field.data_type())
                    .with_context(|| format!("field `{}` changes type", field.name()))?;
                out[index] = Field::new(field.name(), data_type, current.is_nullable() || field.is_nullable());
            }
        }
    }
    Ok(out)
}

fn union_type(left: &DataType, right: &DataType) -> Result<DataType> {
    Ok(match (left, right) {
        (DataType::Struct(a), DataType::Struct(b)) => DataType::Struct(union_fields(a, b)?.into()),
        (DataType::List(a), DataType::List(b)) => {
            DataType::List(Arc::new(Field::new(a.name(), union_type(a.data_type(), b.data_type())?, a.is_nullable() || b.is_nullable())))
        }
        (DataType::LargeList(a), DataType::LargeList(b)) => DataType::LargeList(Arc::new(Field::new(
            a.name(),
            union_type(a.data_type(), b.data_type())?,
            a.is_nullable() || b.is_nullable(),
        ))),
        (a, b) if strip_type(a) == strip_type(b) => strip_type(a),
        (a, b) => bail!("incompatible types {a} and {b}"),
    })
}

fn peak_rss_kib() -> u64 {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| s.lines().find(|l| l.starts_with("VmHWM:")).map(str::to_string))
        .and_then(|l| l.split_whitespace().nth(1).and_then(|v| v.parse().ok()))
        .unwrap_or(0)
}

fn cpu_seconds() -> f64 {
    // SAFETY: getrusage writes into the provided struct only.
    unsafe {
        let mut usage: libc::rusage = std::mem::zeroed();
        if libc::getrusage(libc::RUSAGE_SELF, &mut usage) != 0 {
            return 0.0;
        }
        let tv = |t: libc::timeval| t.tv_sec as f64 + t.tv_usec as f64 / 1e6;
        tv(usage.ru_utime) + tv(usage.ru_stime)
    }
}

/// One built object: sidecars uploaded, record not yet owner-signed.
struct Pending {
    record: ProvenanceRecord,
    keys: PartKeys,
    schema: Arc<ArrowSchema>,
}

fn part_hints(record: &ProvenanceRecord) -> WriteHints {
    WriteHints {
        class: WriterClass::LakePart,
        // The key's date-path hour: a day part declares its first hour.
        event_hour: record.event_hour,
        min_time_ms: record.min_time_us.div_euclid(1_000),
        max_time_ms: record.max_time_us.div_euclid(1_000),
    }
}

#[allow(clippy::too_many_arguments)]
fn record_for(
    plan: &AdoptionPlan,
    object: &PlannedObject,
    built: &BuiltSidecars,
    part_id: &PartId,
    created_at_ms: i64,
    signer_key_id: &str,
    writer_build: &str,
    file_digests: &BTreeMap<String, (String, u64)>,
) -> Result<ProvenanceRecord> {
    let digest = |name: &str| -> Result<(String, u64)> {
        file_digests.get(name).cloned().with_context(|| format!("sidecar {name} was not staged"))
    };
    let tokens_name = tokens_file_name(0);
    let (tokens_sha, tokens_bytes) = digest(&tokens_name)?;
    let partials = built
        .partials
        .iter()
        .map(|(kind, name, rows)| {
            let (sha256, bytes) = digest(name)?;
            Ok(PartialDigest { kind: *kind, name: (*name).to_string(), bytes, sha256, rows: *rows })
        })
        .collect::<Result<Vec<_>>>()?;
    let record = ProvenanceRecord {
        request_hours: None,
        format: PROVENANCE_FORMAT.to_string(),
        signer_key_id: signer_key_id.to_string(),
        tenant_id: plan.tenant_id.clone(),
        part_id: part_id.clone(),
        level: built.level,
        created_at_ms,
        event_hour: built.event_hour,
        event_day: built.event_day,
        rows: built.rows,
        min_time_us: built.min_time_us,
        max_time_us: built.max_time_us,
        schema_fingerprint: built.schema_fingerprint.clone(),
        merkle_root: built.merkle_root.clone(),
        hours: built.hours.clone(),
        files: PartFiles {
            // Adopt by reference (contract 8.1): the one data file is the
            // original object at its bucket key, never copied or split.
            data: vec![DataFileDigest {
                uid_blooms: None,
                entity_blooms: None,
                parquet_ranges: None,
                entity_locators: None,
                class_id: None,
                name: object.key.clone(),
                bytes: object.stamp.size_bytes,
                sha256: object.stamp.sha256.clone(),
                rows: built.rows,
                row_groups: built.row_groups,
                min_time_us: built.min_time_us,
                max_time_us: built.max_time_us,
                log_sources: None,
                tokens: FileDigest { name: tokens_name, bytes: tokens_bytes, sha256: tokens_sha },
            }],
            partials,
        },
        inputs: PartInputs::Adopted {
            anchor: plan.anchor.clone(),
            objects: vec![AdoptedObject {
                key: object.key.clone(),
                bytes: object.stamp.size_bytes,
                sha256: object.stamp.sha256.clone(),
                rows: built.rows,
                stamp_sha256: object.stamp_sha256.clone(),
            }],
        },
        admission: None,
        lowercased_at_rest: Vec::new(),
        dedup: DedupStats { rows_in: built.rows, duplicates_dropped: 0, window: DedupWindow::Exact },
        writer: WriterInfo { role: "adopt".to_string(), build: writer_build.to_string() },
    };
    record.validate()?;
    Ok(record)
}

/// Upload one built object's sidecars under a fresh part id and return its
/// unsigned record. Nothing is live until an `adopt` entry names the part.
async fn upload_sidecars(
    store: &dyn ObjectStore,
    plan: &AdoptionPlan,
    object: &PlannedObject,
    built: &BuiltSidecars,
    signer_key_id: &str,
    now_ms: i64,
    writer_build: &str,
) -> Result<(ProvenanceRecord, PartKeys)> {
    let part_id = PartId::new(now_ms)?;
    let keys = PartKeys::new(&plan.tenant_id, built.level, built.event_hour, &part_id)?;
    // Digest from disk first (streaming), then upload one file at a time:
    // at most one sidecar is in memory (the store API takes whole bytes).
    let mut digests = BTreeMap::new();
    let files = built.files();
    for (name, path) in &files {
        let checked = path.clone();
        let (sha256, bytes) = tokio::task::spawn_blocking(move || super::source::file_sha256(&checked)).await??;
        if bytes == 0 || bytes > MAX_OBJECT_BYTES {
            bail!("sidecar {name} is {bytes} bytes, outside the object bounds");
        }
        digests.insert(name.clone(), (sha256, bytes));
    }
    let record = record_for(plan, object, built, &part_id, now_ms, signer_key_id, writer_build, &digests)?;
    let hints = part_hints(&record);
    for (name, path) in files {
        let bytes = tokio::fs::read(&path).await.with_context(|| format!("read staged {}", path.display()))?;
        if sha256_hex(&bytes) != digests[&name].0 {
            bail!("staged sidecar {name} changed before upload");
        }
        if !store.put_if_absent_with(&keys.file(&name), &bytes, &hints).await? {
            bail!("sidecar {} already exists for a fresh part id", keys.file(&name));
        }
    }
    Ok((record, keys))
}

/// Run (or resume) adoption of `plan` into the tenant's part log.
pub async fn run_adoption(
    store: &dyn ObjectStore,
    source: &dyn AdoptSource,
    plan: &AdoptionPlan,
    signer: &AdoptSigner<'_>,
    options: &AdoptOptions,
    now_ms: &(dyn Fn() -> i64 + Send + Sync),
) -> Result<AdoptReport> {
    let started = Instant::now();
    let cpu_start = cpu_seconds();
    if options.batch_parts == 0 || options.batch_parts > MAX_BATCH_PARTS {
        bail!("batch_parts must be 1..={MAX_BATCH_PARTS}");
    }
    if options.sign_batch == 0 || options.sign_batch > SIGN_BATCH_MAX {
        bail!("sign_batch must be 1..={SIGN_BATCH_MAX}");
    }
    if let Some(object) = plan.objects.iter().find(|o| o.stamp.size_bytes > MAX_OBJECT_BYTES) {
        bail!(
            "object {} is {} bytes, above the {MAX_OBJECT_BYTES}-byte object cap; adoption never splits or rewrites",
            object.key,
            object.stamp.size_bytes
        );
    }
    let hook = |stage: AdoptStage<'_>| -> Result<()> {
        match &options.hooks {
            Some(hooks) => hooks.at(&stage),
            None => Ok(()),
        }
    };
    let mut adopted = adopted_parts(store, &plan.tenant_id, signer.trusted).await?;
    check_single_generation(&adopted, plan)?;
    let mut report = AdoptReport {
        tenant_id: plan.tenant_id.clone(),
        generation_id: plan.anchor.generation_id.clone(),
        objects_in_plan: plan.objects.len(),
        ..AdoptReport::default()
    };
    let mut pending_objects = Vec::new();
    for object in &plan.objects {
        match adopted.get(&object.key) {
            Some(existing) => {
                if existing.record.files.data[0].sha256 != object.stamp.sha256 {
                    bail!("object {} is adopted with different bytes than the signed stamp", object.key);
                }
                report.already_adopted += 1;
            }
            None => pending_objects.push(object),
        }
    }
    std::fs::create_dir_all(&options.work_dir)?;
    let mut writer: Option<PartLogWriter<'_>> = None;
    let mut batch: Vec<Pending> = Vec::new();
    let mut batch_index = 0_usize;
    let limit = options.max_objects.unwrap_or(usize::MAX);
    let t0_hour = plan.t0_hour();
    for object in pending_objects {
        if report.adopted_now + batch.len() >= limit {
            break;
        }
        // Skip, without reading, objects whose key partition is at or after T0.
        if super::plan::key_event_hour(&object.key).is_some_and(|hour| hour >= t0_hour) {
            report.skipped_at_or_after_t0.push(object.key.clone());
            continue;
        }
        // The log may have moved since the snapshot (another adopter before
        // this writer opened): never adopt a key twice.
        if adopted.contains_key(&object.key) {
            report.already_adopted += 1;
            continue;
        }
        let materialized = source.materialize(object, &options.work_dir).await?;
        let staging = options.work_dir.join(format!("staging-{}", uuid::Uuid::new_v4().simple()));
        let data = materialized.path.clone();
        let budgets = options.budgets;
        let staging_for_build = staging.clone();
        let build_started = Instant::now();
        let expected = (object.stamp.sha256.clone(), object.stamp.size_bytes);
        let built = tokio::task::spawn_blocking(move || -> Result<BuiltSidecars> {
            let built = build_adopted_sidecars(&data, &staging_for_build, &budgets)?;
            // Re-verify after the build: the record pins these exact bytes,
            // so they must be the bytes the sidecars were built from.
            if super::source::file_sha256(&data)? != expected {
                bail!("object changed while its sidecars were built");
            }
            Ok(built)
        })
        .await?
        .with_context(|| format!("build sidecars for {}", object.key))?;
        drop(materialized);
        let build_seconds = build_started.elapsed().as_secs_f64();
        if built.min_time_us >= plan.t0_us {
            report.skipped_at_or_after_t0.push(object.key.clone());
            std::fs::remove_dir_all(&staging)?;
            continue;
        }
        if built.max_time_us >= plan.t0_us {
            bail!("object {} straddles T0; T0 must be an hour boundary the object respects", object.key);
        }
        if built.level != Level::Hour {
            bail!(
                "object {} spans {} event hours; generation objects are event_hour-partitioned, so adoption \
                 takes only single-hour objects (contract 8.1)",
                object.key,
                built.hours.len()
            );
        }
        if writer.is_none() {
            let opened = PartLogWriter::open(
                store,
                &plan.tenant_id,
                signer.writer_epoch,
                &schema_union(&ArrowSchema::empty(), &built.schema)?,
                now_ms(),
            )
            .await?;
            // Re-derive the adopted set from the log the writer will append
            // to, not the earlier snapshot.
            adopted = adopted_in(store, &plan.tenant_id, signer.trusted, opened.live()).await?;
            check_single_generation(&adopted, plan)?;
            writer = Some(opened);
            if adopted.contains_key(&object.key) {
                report.already_adopted += 1;
                std::fs::remove_dir_all(&staging)?;
                continue;
            }
        }
        let (record, keys) =
            upload_sidecars(store, plan, object, &built, signer.signer.key_id(), now_ms(), &options.writer_build).await?;
        hook(AdoptStage::PartUploaded { key: &object.key, part_id: &record.part_id })?;
        report.objects.push(ObjectReport {
            key: object.key.clone(),
            part_id: record.part_id.to_string(),
            level: built.level.code().to_string(),
            rows: built.rows,
            bytes: object.stamp.size_bytes,
            row_groups: built.row_groups,
            hours: built.hours.len(),
            blooms_missing: built.blooms_missing.len(),
            duplicate_uids: built.duplicate_uids,
            leaf_runs: built.leaf_runs,
            partial_runs: built.partial_runs,
            build_seconds,
        });
        report.bytes_read += object.stamp.size_bytes;
        std::fs::remove_dir_all(&staging)?;
        batch.push(Pending { record, keys, schema: Arc::clone(&built.schema) });
        if batch.len() >= options.batch_parts {
            let writer = writer.as_mut().expect("writer opened");
            commit_batch(store, writer, signer, options, &mut batch, &mut adopted, batch_index, &mut report, now_ms, &hook)
                .await?;
            batch_index += 1;
        }
    }
    if !batch.is_empty() {
        let writer = writer.as_mut().expect("writer opened");
        commit_batch(store, writer, signer, options, &mut batch, &mut adopted, batch_index, &mut report, now_ms, &hook)
            .await?;
    }
    report.remaining = report
        .objects_in_plan
        .saturating_sub(report.already_adopted + report.adopted_now + report.skipped_at_or_after_t0.len());
    report.head_seq = match &writer {
        Some(writer) => writer.live().head().map(|(seq, _, _)| seq),
        None => load_log(store, &plan.tenant_id).await?.head().map(|(seq, _, _)| seq),
    };
    report.wall_seconds = started.elapsed().as_secs_f64();
    report.cpu_seconds = cpu_seconds() - cpu_start;
    report.peak_rss_kib = peak_rss_kib();
    Ok(report)
}

/// Owner-sign the batch's records (chunks of `sign_batch` <= 16, contract
/// 4.4), verify each signature, store each `provenance.json`, then commit one
/// `adopt` entry (preceded by a `schema` entry when the read schema grows).
#[allow(clippy::too_many_arguments)]
async fn commit_batch(
    store: &dyn ObjectStore,
    writer: &mut PartLogWriter<'_>,
    signer: &AdoptSigner<'_>,
    options: &AdoptOptions,
    batch: &mut Vec<Pending>,
    adopted: &mut BTreeMap<String, AdoptedPart>,
    batch_index: usize,
    report: &mut AdoptReport,
    now_ms: &(dyn Fn() -> i64 + Send + Sync),
    hook: &(dyn Fn(AdoptStage<'_>) -> Result<()> + Sync),
) -> Result<()> {
    let tenant_id = writer.tenant_id().to_string();
    // Refuse to append any key the log already holds or the batch repeats.
    let mut keys = BTreeSet::new();
    for pending in batch.iter() {
        let key = &pending.record.files.data[0].name;
        if adopted.contains_key(key) || !keys.insert(key.clone()) {
            bail!("object {key} is already adopted; refusing a second adopt");
        }
    }
    let mut parts = Vec::with_capacity(batch.len());
    let mut signed_records = Vec::with_capacity(batch.len());
    for chunk in batch.chunks(options.sign_batch) {
        let records = chunk.iter().map(|p| p.record.clone()).collect::<Vec<_>>();
        let signatures = signer.signer.sign(&tenant_id, &records).await.context("owner lake-parts:sign")?;
        if signatures.len() != records.len() {
            bail!("owner returned {} signatures for {} records", signatures.len(), records.len());
        }
        for ((pending, record), signature) in chunk.iter().zip(records).zip(signatures) {
            let signed = SignedProvenance::assemble(record, signature, signer.trusted)?;
            let bytes = signed.to_bytes()?;
            if bytes.len() > MAX_PROVENANCE_BYTES {
                bail!("provenance record exceeds {MAX_PROVENANCE_BYTES} bytes");
            }
            if !store.put_if_absent_with(&pending.keys.provenance(), &bytes, &part_hints(&signed.record)).await? {
                bail!("provenance already exists for a fresh part id");
            }
            let part = PartRef::from_record(&signed.record, &sha256_hex(&bytes), false);
            signed_records.push(AdoptedPart { part: part.clone(), record: signed.record });
            parts.push(part);
        }
    }
    // The log's read schema must cover every adopted part (additive only).
    let current = writer.live().schema().context("part log has no schema")?.to_arrow()?;
    let mut union = schema_union(&current, &ArrowSchema::empty())?;
    for pending in batch.iter() {
        union = schema_union(&union, &pending.schema)?;
    }
    if schema_fingerprint(&union)? != schema_fingerprint(&current)? {
        writer.append(LogOp::Schema { schema: LogSchema::from_arrow(&union)? }, now_ms()).await?;
        report.schema_entries += 1;
    }
    hook(AdoptStage::BeforeAppend { batch: batch_index, parts: parts.len() })?;
    let rows: u64 = parts.iter().map(|p| p.rows).sum();
    let count = parts.len();
    let crate::parts::part_log::AppendOutcome::Committed { seq, .. } =
        writer.append(LogOp::Adopt { parts }, now_ms()).await?;
    report.adopt_entries += 1;
    for adopted_part in signed_records {
        adopted.insert(adopted_part.record.files.data[0].name.clone(), adopted_part);
    }
    report.adopted_now += count;
    report.rows_adopted += rows;
    batch.clear();
    hook(AdoptStage::AfterAppend { batch: batch_index, seq })?;
    Ok(())
}
