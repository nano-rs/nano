// SPDX-License-Identifier: AGPL-3.0-or-later
//! NAN-3801: counts-only backfill.
//!
//! A count rewrite re-encodes the whole part (decode, row digests, Parquet,
//! token index, blooms, every partial) only to add entity counts: ~1 ms a
//! row live. Counts depend on just a handful of leaves (`time`,
//! `metadata.log_source` and the entity-kind fields), so this module reads
//! those column chunks alone and feeds the same [`Builder`] the writer uses.
//! The output is a count file in the EntityRanges schema and encoding
//! (coverage row + count rows, v2 footer hint), byte-for-byte what
//! [`super::partials::replace_entity_counts`] emits for the count namespace,
//! so readers decode it with the existing count path.
//!
//! Exactness: counts are sums per `(kind, hour, mask, value, source)` cell,
//! independent of row order, and the builder treats an absent leaf and a
//! null one alike. Schema evolution is additive (a leaf never changes type),
//! so the projected original batches give the builder the same values the
//! full rewrite's aligned batches do. `count_record_matches_a_full_count_rewrite`
//! pins that.

use anyhow::{ensure, Context, Result};
use arrow_array::RecordBatch;
use parquet::arrow::arrow_reader::{ArrowReaderMetadata, ParquetRecordBatchReaderBuilder};
use parquet::arrow::ProjectionMask;
use std::path::{Path, PathBuf};

use crate::parts::entity_counts::{Builder, KINDS};
use crate::parts::format::PartKeys;
use crate::parts::parquet_ranges::ParquetRangeDigest;
use crate::parts::part_log::{ObjectStore, PartRef, MAX_RANGE_GET_BYTES};
use crate::parts::provenance::{PartSigner, ProvenanceRecord, TenantKeySet};

/// Decoded rows per projected batch.
const BATCH_ROWS: usize = 8_192;

/// File name of a count file inside a work directory.
pub const COUNT_FILE: &str = "counts.parquet";

/// Every leaf the count builder reads.
pub fn count_leaves() -> Vec<&'static str> {
    let mut leaves = vec!["time", "metadata.log_source"];
    leaves.extend(KINDS.iter().flat_map(|fields| fields.iter().copied()));
    leaves
}

/// The projection of `metadata` that reads only [`count_leaves`].
pub fn count_projection(metadata: &ArrowReaderMetadata) -> ProjectionMask {
    let leaves = count_leaves();
    let schema = metadata.metadata().file_metadata().schema_descr();
    let indices = schema.columns().iter().enumerate()
        .filter(|(_, column)| leaves.contains(&column.path().string().as_str()))
        .map(|(index, _)| index)
        .collect::<Vec<_>>();
    ProjectionMask::leaves(schema, indices)
}

/// One part's counts, written and digested.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CountFile {
    pub path: PathBuf,
    pub bytes: u64,
    pub sha256: String,
    /// Rows counted (must equal the part's signed row count).
    pub rows: u64,
    /// Count rows written, coverage row included.
    pub count_rows: u64,
    /// Entity kinds whose counts are complete (the v2 footer hint).
    pub coverage_mask: u8,
}

/// Accumulates projected batches of one part, then writes its count file.
pub struct CountAccumulator {
    builder: Option<Builder>,
    rows: u64,
    error: Option<String>,
}

impl CountAccumulator {
    /// `spill_dir`: where the builder's bounded spill may live. It is
    /// created here: the builder spills mid-scan once its buffer fills, long
    /// before [`Self::finish`] (r52 tenant-a: "entity counts dropped: No such
    /// file or directory … out/.entity-counts-*" on every large part).
    pub fn new(spill_dir: &Path) -> Result<Self> {
        std::fs::create_dir_all(spill_dir).with_context(|| format!("count spill directory {}", spill_dir.display()))?;
        Ok(Self { builder: Some(Builder::in_directory(spill_dir)), rows: 0, error: None })
    }

    /// Add one projected batch. A builder error drops all coverage, exactly
    /// as the writer drops "optional entity count coverage".
    pub fn add(&mut self, batch: &RecordBatch) {
        self.rows += batch.num_rows() as u64;
        if let Some(builder) = &mut self.builder {
            if let Err(error) = builder.add_batch(batch) {
                self.error = Some(format!("{error:#}"));
                self.builder = None;
            }
        }
    }

    /// Write the count file at `dir/`[`COUNT_FILE`]. `expected_rows`: the
    /// part's signed row count; a short or long read fails the build.
    pub fn finish(self, dir: &Path, expected_rows: u64) -> Result<CountFile> {
        ensure!(self.rows == expected_rows, "count scan read {} rows of a {expected_rows}-row part", self.rows);
        let builder = match (self.builder, self.error) {
            (Some(builder), None) => builder,
            (_, error) => anyhow::bail!("entity counts dropped: {}", error.unwrap_or_default()),
        };
        std::fs::create_dir_all(dir)?;
        let path = dir.join(COUNT_FILE);
        // The count namespace of an otherwise empty EntityRanges partial:
        // the same writer, properties and footer hint as a full rewrite.
        super::partials::write_sorted::<super::partials::EntityRangeRow>(Vec::new(), &path)?;
        let count_rows = super::partials::replace_entity_counts(&path, builder.into_sorted_rows()?)?;
        ensure!(count_rows > 0, "no entity kind kept its counts");
        let coverage_mask = footer_coverage_mask(&path)?.context("count file has no v2 coverage hint")?;
        let (bytes, sha256) = super::writer::file_digest(&path)?;
        Ok(CountFile { path, bytes, sha256, rows: self.rows, count_rows, coverage_mask })
    }
}

/// Count a part from local data files, reading only [`count_leaves`].
pub fn count_local_files(files: &[PathBuf], work_dir: &Path, expected_rows: u64) -> Result<CountFile> {
    let mut counts = CountAccumulator::new(work_dir)?;
    for path in files {
        let file = std::fs::File::open(path).with_context(|| format!("open {}", path.display()))?;
        let metadata = ArrowReaderMetadata::load(&file, Default::default())?;
        let mask = count_projection(&metadata);
        let reader = ParquetRecordBatchReaderBuilder::new_with_metadata(file, metadata)
            .with_projection(mask)
            .with_batch_size(BATCH_ROWS)
            .build()?;
        for batch in reader {
            let batch = batch?;
            super::merge_quota::charge_input(batch.num_rows() as u64, super::merge_quota::batch_bytes(&batch));
            counts.add(&batch);
        }
    }
    counts.finish(work_dir, expected_rows)
}

/// The v2 coverage mask of a local EntityRanges/count file's footer.
pub fn footer_coverage_mask(path: &Path) -> Result<Option<u8>> {
    use parquet::file::reader::FileReader;
    let file = parquet::file::reader::SerializedFileReader::new(std::fs::File::open(path)?)?;
    Ok(file.metadata().file_metadata().key_value_metadata().and_then(|items| items.iter()
        .find(|item| item.key == crate::parts::entity_counts::V2_COVERAGE_PATH)
        .and_then(|item| item.value.as_deref().and_then(|value| value.parse::<u8>().ok())))
        .filter(|mask| *mask > 0 && *mask < 16))
}

/// Concurrent ranged GETs of one part's count columns.
const RANGE_FETCH_CONCURRENCY: usize = 16;

/// Peak fetch buffers of one part's count inputs: every range in flight
/// holds at most one [`MAX_RANGE_GET_BYTES`] chunk, however large the
/// column chunk (64 MiB).
pub const MAX_FETCH_BUFFER_BYTES: u64 = RANGE_FETCH_CONCURRENCY as u64 * MAX_RANGE_GET_BYTES;

/// Read `range` of `key` as consecutive ranged GETs of at most
/// [`MAX_RANGE_GET_BYTES`] (the S3 store refuses larger ones), handing each
/// chunk to `sink(offset, bytes)` in order. Each GET is one remote transfer
/// charged to the compaction lane. `Ok(false)`: the object is missing.
pub(super) async fn read_range_chunked(
    store: &dyn ObjectStore, key: &str, range: std::ops::Range<u64>,
    mut sink: impl FnMut(u64, &[u8]) -> Result<()>,
) -> Result<bool> {
    ensure!(range.start < range.end, "empty object range {}..{}", range.start, range.end);
    let mut offset = range.start;
    while offset < range.end {
        let end = range.end.min(offset + MAX_RANGE_GET_BYTES);
        let Some(bytes) = super::merge_quota::remote_transfer(true, end - offset, store.get_range(key, offset..end)).await? else {
            ensure!(offset == range.start, "object {key} vanished mid-read at {offset}");
            return Ok(false);
        };
        ensure!(bytes.len() as u64 == end - offset, "short ranged read {offset}..{end} of {key}: {} bytes", bytes.len());
        sink(offset, &bytes)?;
        offset = end;
    }
    Ok(true)
}

/// [`read_range_chunked`] into one buffer of at most `max_bytes`.
pub(super) async fn read_range_bounded(
    store: &dyn ObjectStore, key: &str, range: std::ops::Range<u64>, max_bytes: u64,
) -> Result<Option<Vec<u8>>> {
    let bytes = range.end.checked_sub(range.start).context("invalid object range")?;
    ensure!(bytes <= max_bytes, "object range of {bytes} bytes exceeds its {max_bytes} byte cap");
    if bytes == 0 { return Ok(Some(Vec::new())) }
    let mut body = Vec::with_capacity(usize::try_from(bytes)?);
    let found = read_range_chunked(store, key, range, |_, chunk| { body.extend_from_slice(chunk); Ok(()) }).await?;
    Ok(found.then_some(body))
}

/// Bytes fetched for one part's count inputs.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct FetchStats {
    pub bytes: u64,
    /// Data files read whole (no signed range manifest).
    pub whole_files: usize,
}

/// Materialize every data file of `record` under `dir` with only what the
/// count scan reads. A file with a signed range manifest becomes a sparse
/// file holding the verified footer and the verified chunks of
/// [`count_leaves`]; every chunk the projection touches must be one of them
/// (a gap would read zeros, so it refuses). A file without a manifest is
/// downloaded whole and checked against its signed digest.
pub async fn fetch_count_inputs(
    store: &dyn ObjectStore, keys: &PartKeys, record: &ProvenanceRecord, dir: &Path,
) -> Result<(Vec<PathBuf>, FetchStats)> {
    use futures::{StreamExt, TryStreamExt};
    std::fs::create_dir_all(dir)?;
    let leaves = count_leaves();
    let mut stats = FetchStats::default();
    let mut paths = Vec::with_capacity(record.files.data.len());
    for (index, data) in record.files.data.iter().enumerate() {
        let remote = record.data_key(keys, index).context("data file index")?;
        let path = dir.join(crate::parts::format::data_file_name(index));
        let _ = std::fs::remove_file(&path);
        let Some(manifest) = &data.parquet_ranges else {
            let ok = super::merge_quota::remote_download(true, data.bytes, &path, store.get_to_file(&remote, &path)).await?;
            ensure!(ok, "data file {} is missing", data.name);
            let (bytes, sha256) = super::writer::file_digest(&path)?;
            ensure!(bytes == data.bytes && sha256 == data.sha256, "data file {} does not match its record", data.name);
            stats.bytes += bytes;
            stats.whole_files += 1;
            paths.push(path);
            continue;
        };
        let body = super::merge_quota::remote_transfer(true, manifest.bytes, store.get(&keys.file(&manifest.name))).await?
            .with_context(|| format!("range manifest {} is missing", manifest.name))?;
        ensure!(body.len() as u64 == manifest.bytes && crate::parts::sha256_hex(&body) == manifest.sha256,
            "range manifest {} does not match its record", manifest.name);
        stats.bytes += manifest.bytes;
        let ranges: Vec<ParquetRangeDigest> = serde_json::from_slice(&body)?;
        crate::parts::parquet_ranges::validate(&ranges, data.bytes, data.row_groups)?;
        let wanted = ranges.iter()
            .filter(|range| range.column.as_deref().is_none_or(|column| leaves.contains(&column)))
            .cloned().collect::<Vec<_>>();
        {
            let file = std::fs::File::create(&path)?;
            file.set_len(data.bytes)?;
        }
        // Stream each range into the sparse file in chunks of at most
        // MAX_RANGE_GET_BYTES, hashing as they land: a column chunk of any
        // size is fetched (r52 tenant-a: chunks over the S3 store's 4 MiB ranged
        // GET cap failed every rewrite) and memory stays bounded by
        // MAX_FETCH_BUFFER_BYTES. Bytes land before their digest is checked;
        // a mismatch fails the part and the work directory is removed.
        let sparse_file = std::fs::OpenOptions::new().write(true).open(&path)?;
        let sparse = &sparse_file;
        let written = futures::stream::iter(wanted.iter().cloned().map(|range| {
            let remote = remote.clone();
            async move {
                use sha2::Digest;
                use std::os::unix::fs::FileExt;
                let end = range.offset + range.bytes;
                let mut hasher = sha2::Sha256::new();
                let found = read_range_chunked(store, &remote, range.offset..end, |offset, bytes| {
                    hasher.update(bytes);
                    sparse.write_all_at(bytes, offset).map_err(anyhow::Error::from)
                }).await?;
                ensure!(found, "data file range {}..{end} is missing", range.offset);
                ensure!(hex::encode(hasher.finalize()) == range.sha256,
                    "data file range {}..{end} does not match its signed digest", range.offset);
                Ok::<_, anyhow::Error>(range.bytes)
            }
        })).buffer_unordered(RANGE_FETCH_CONCURRENCY).try_fold(0_u64, |written, bytes| futures::future::ready(Ok(written + bytes))).await?;
        stats.bytes += written;
        drop(sparse_file);
        // Every column chunk the projection reads must be a verified range.
        let file = std::fs::File::open(&path)?;
        let metadata = ArrowReaderMetadata::load(&file, Default::default())?;
        let parquet = metadata.metadata();
        ensure!(parquet.num_row_groups() as u32 == data.row_groups && parquet.file_metadata().num_rows() as u64 == data.rows,
            "data file {} footer differs from its record", data.name);
        let verified = wanted.iter().filter_map(|range| range.row_group.map(|group| (group, range.offset, range.bytes)))
            .collect::<std::collections::HashSet<_>>();
        for (group, row_group) in parquet.row_groups().iter().enumerate() {
            for column in row_group.columns().iter().filter(|column| leaves.contains(&column.column_path().string().as_str())) {
                let (offset, bytes) = column.byte_range();
                ensure!(verified.contains(&(group as u32, offset, bytes)),
                    "data file {} column {} of row group {group} has no signed range", data.name, column.column_path().string());
            }
        }
        paths.push(path);
    }
    Ok((paths, stats))
}

/// What one counts-only backfill of a part did.
#[derive(Debug, Clone)]
pub struct CountsOnlyDone {
    pub record: crate::parts::count_record::SignedCountRecord,
    pub fetched: FetchStats,
    /// A valid record was already stored (an earlier attempt or process).
    pub existing: bool,
}

/// The stored count record of `part`, verified, if any.
pub async fn stored_count_record(
    store: &dyn ObjectStore, keys: &PartKeys, part: &PartRef, tenant_id: &str, trusted: &TenantKeySet,
) -> Result<Option<crate::parts::count_record::SignedCountRecord>> {
    use crate::parts::count_record::{SignedCountRecord, COUNT_RECORD_FILE, MAX_SIGNED_COUNT_RECORD_BYTES};
    let Some(bytes) = super::merge_quota::remote_transfer(true, MAX_SIGNED_COUNT_RECORD_BYTES as u64,
        store.get(&keys.file(COUNT_RECORD_FILE))).await? else { return Ok(None) };
    SignedCountRecord::verify_bytes(&bytes, part, tenant_id, trusted).map(Some)
        .context("stored count record does not verify")
}

/// NAN-3801: count `part` from its count columns alone and publish the
/// owner-signed count record beside it. The part itself is untouched.
/// Returns [`crate::parts::provenance::CountSigningUnsupported`] (in the
/// chain) when the owner cannot sign count records; the caller then runs
/// the full count rewrite.
#[allow(clippy::too_many_arguments)]
pub async fn backfill_counts(
    store: &dyn ObjectStore, signer: &dyn PartSigner, trusted: &TenantKeySet, tenant_id: &str,
    work_dir: &Path, part: &PartRef, record: &ProvenanceRecord, now_ms: i64,
) -> Result<CountsOnlyDone> {
    use crate::parts::count_record::{count_file_name, CountRecord, SignedCountRecord, COUNT_RECORD_FILE};
    let keys = PartKeys::new(tenant_id, part.level, part.event_hour, &part.part_id)?;
    if let Some(record) = stored_count_record(store, &keys, part, tenant_id, trusted).await? {
        return Ok(CountsOnlyDone { record, fetched: FetchStats::default(), existing: true });
    }
    // One lane with the count rewrites: fetch, scan and publish.
    let _lane = super::merge_quota::reserve_count_backfill().await?;
    let dir = work_dir.join("counts-only").join(part.part_id.as_str());
    let _ = std::fs::remove_dir_all(&dir);
    struct Cleanup(PathBuf);
    impl Drop for Cleanup {
        fn drop(&mut self) { let _ = std::fs::remove_dir_all(&self.0); }
    }
    let _cleanup = Cleanup(dir.clone());
    let (files, fetched) = fetch_count_inputs(store, &keys, record, &dir.join("data")).await?;
    let (out, rows) = (dir.join("out"), part.rows);
    let counted = super::merge_lanes::compute(move || {
        super::merge_quota::with_count_backfill(true, || count_local_files(&files, &out, rows))
    }).await??;
    let file = crate::parts::provenance::FileDigest {
        name: count_file_name(&counted.sha256)?, bytes: counted.bytes, sha256: counted.sha256.clone(),
    };
    let hints = super::writer::part_hints(record);
    super::merge_quota::remote_transfer(true, counted.bytes,
        store.put_file_if_absent_with(&keys.file(&file.name), &counted.path, &counted.sha256, counted.bytes, &hints)).await?;
    let unsigned = CountRecord::new(part, tenant_id, signer.key_id(), counted.coverage_mask, counted.count_rows, file, now_ms)?;
    let signature = signer.sign_counts(tenant_id, std::slice::from_ref(&unsigned)).await?
        .into_iter().next().context("owner returned no count signature")?;
    let signed = SignedCountRecord::assemble(unsigned, signature, trusted)?;
    let bytes = signed.to_bytes()?;
    let created = super::merge_quota::remote_transfer(true, bytes.len() as u64,
        store.put_if_absent_with(&keys.file(COUNT_RECORD_FILE), &bytes, &hints)).await?;
    if !created {
        // Another writer won the fixed name: theirs is authoritative if valid.
        let record = stored_count_record(store, &keys, part, tenant_id, trusted).await?
            .context("count record raced and the stored one is missing")?;
        return Ok(CountsOnlyDone { record, fetched, existing: true });
    }
    Ok(CountsOnlyDone { record: signed, fetched, existing: false })
}

/// Process-wide counts-only progress (per-process; a restart resets it).
static COUNTED_PARTS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
static COUNTED_ROWS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
static COUNTED_FETCHED_BYTES: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
/// Set once the owner refused the count route; this process then uses full
/// rewrites until it restarts (an owner release adds the route).
static SIGNING_UNSUPPORTED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

pub(super) fn note_counted(part: &PartRef, done: &CountsOnlyDone) {
    use std::sync::atomic::Ordering::Relaxed;
    COUNTED_PARTS.fetch_add(1, Relaxed);
    COUNTED_ROWS.fetch_add(part.rows, Relaxed);
    COUNTED_FETCHED_BYTES.fetch_add(done.fetched.bytes, Relaxed);
}

/// `(parts, rows, fetched bytes)` counted by this process.
pub fn counted_totals() -> (u64, u64, u64) {
    use std::sync::atomic::Ordering::Relaxed;
    (COUNTED_PARTS.load(Relaxed), COUNTED_ROWS.load(Relaxed), COUNTED_FETCHED_BYTES.load(Relaxed))
}

pub fn count_signing_unsupported() -> bool {
    SIGNING_UNSUPPORTED.load(std::sync::atomic::Ordering::Relaxed)
}

pub(super) fn is_unsupported(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| cause.is::<crate::parts::provenance::CountSigningUnsupported>())
}

pub(super) fn mark_count_signing_unsupported(error: &anyhow::Error) {
    if !SIGNING_UNSUPPORTED.swap(true, std::sync::atomic::Ordering::Relaxed) {
        tracing::warn!(error = %format!("{error:#}"), "owner cannot sign count records; count backfill uses full rewrites in this process");
    }
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;
    use crate::parts::levels::Level;
    use crate::parts::provenance::{tests::{SIGNER, TENANT}, InputPart, PartInputs};
    use super::super::partials::{EntityRangeRow, PartialRow};
    use super::super::writer::{local_data_files, PartDraft, PartWriter, PartialSource};

    pub(crate) const HOUR: i32 = 497_000;

    pub(crate) fn read_rows(path: &Path) -> Vec<EntityRangeRow> {
        let mut rows = Vec::new();
        for batch in ParquetRecordBatchReaderBuilder::try_new(std::fs::File::open(path).unwrap()).unwrap().build().unwrap() {
            rows.extend(EntityRangeRow::from_batch(&batch.unwrap()).unwrap());
        }
        rows
    }

    pub(crate) fn footer_hint(path: &Path) -> Option<String> {
        use parquet::file::reader::FileReader;
        let file = parquet::file::reader::SerializedFileReader::new(std::fs::File::open(path).unwrap()).unwrap();
        file.metadata().file_metadata().key_value_metadata().and_then(|items| items.iter()
            .find(|item| item.key == crate::parts::entity_counts::V2_COVERAGE_PATH).and_then(|item| item.value.clone()))
    }

    /// OCSF-ish rows over every count kind: repeats, nulls, several
    /// sources, a device object on some rows only.
    pub(crate) fn events(n: usize) -> Vec<serde_json::Value> {
        (0..n).map(|i| {
            let source = ["sysmon", "okta", "zeek"][i % 3];
            let mut event = serde_json::json!({
                "time": chrono::DateTime::from_timestamp(i64::from(HOUR) * 3_600 + (i as i64 % 3_600), (i % 1000) as u32 * 1_000).unwrap().to_rfc3339(),
                "metadata": {"uid": format!("u{i:08}"), "log_source": source},
                "message": format!("event {i}"),
                "src_endpoint": {"ip": format!("10.0.{}.{}", i % 7, i % 13), "hostname": format!("host-{}", i % 11)},
                "dst_endpoint": {"ip": format!("192.168.1.{}", i % 5)},
                "user": {"name": format!("user{}", i % 17)},
                "actor": {"user": {"email_addr": format!("a{}@example.com", i % 3)}},
            });
            if i % 9 == 0 { event["src_endpoint"]["ip"] = serde_json::Value::Null; }
            if i % 23 == 0 { event["device"] = serde_json::json!({"ip": "172.16.0.1", "hostname": "dc01"}); }
            event
        }).collect()
    }

    /// One hour part written with the process's count setting.
    pub(crate) fn write_part(dir: &Path, rows: &[serde_json::Value]) -> (PartRef, PathBuf, arrow_schema::SchemaRef) {
        let refs = rows.iter().collect::<Vec<_>>();
        let schema = std::sync::Arc::new(super::super::schema::infer_schema(&refs).unwrap());
        let batch = super::super::writer::sort_by_time_uid(&super::super::schema::decode(schema.clone(), &refs).unwrap()).unwrap();
        let draft = PartDraft {
            tenant_id: TENANT.into(), signer_key_id: SIGNER.into(), level: Level::Hour, event_hour: HOUR,
            schema_fingerprint: crate::parts::format::schema_fingerprint(&schema).unwrap(), schema: schema.clone(),
            inputs: PartInputs::Parts { parts: vec![InputPart { part_id: crate::parts::format::PartId::new(1).unwrap(),
                level: Level::Minute, provenance_sha256: "0".repeat(64), rows: batch.num_rows() as u64, merkle_root: "0".repeat(64) }] },
            admission: None, rows_in: batch.num_rows() as u64, duplicates_dropped: 0, window: crate::parts::DedupWindow::Exact, build: "test".into(),
        };
        std::fs::create_dir_all(dir).unwrap();
        let mut writer = PartWriter::create(dir, draft, PartialSource::FromRows, 1, batch.num_rows() as u64).unwrap();
        writer.write(&batch).unwrap();
        let finished = writer.finish().unwrap();
        (PartRef::from_record(&finished.record, &"0".repeat(64), true), finished.dir, schema)
    }

    #[test]
    fn a_short_scan_or_a_dropped_builder_never_yields_a_record() {
        let dir = tempfile::tempdir().unwrap();
        let (old, old_dir, _) = write_part(&dir.path().join("old"), &events(500));
        let files = local_data_files(&old_dir).unwrap();
        let error = count_local_files(&files, &dir.path().join("c1"), old.rows + 1).unwrap_err();
        assert!(error.to_string().contains("rows of a"), "{error:#}");
        let mut counts = CountAccumulator::new(dir.path()).unwrap();
        counts.error = Some("injected".into());
        counts.builder = None;
        assert!(counts.finish(&dir.path().join("c2"), 0).unwrap_err().to_string().contains("injected"));
    }

    /// A store with the S3 store's ranged-GET cap (same refusal), recording
    /// the largest range requested.
    pub(crate) struct CappedRanges<'a> {
        pub inner: &'a dyn ObjectStore,
        pub largest: std::sync::atomic::AtomicU64,
        pub gets: std::sync::atomic::AtomicU64,
    }
    impl<'a> CappedRanges<'a> {
        pub fn new(inner: &'a dyn ObjectStore) -> Self {
            Self { inner, largest: Default::default(), gets: Default::default() }
        }
    }
    #[async_trait::async_trait]
    impl ObjectStore for CappedRanges<'_> {
        async fn get_range(&self, key: &str, range: std::ops::Range<u64>) -> Result<Option<Vec<u8>>> {
            let bytes = range.end - range.start;
            self.largest.fetch_max(bytes, std::sync::atomic::Ordering::SeqCst);
            self.gets.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            ensure!(bytes > 0 && bytes <= MAX_RANGE_GET_BYTES, "export object range exceeds budget");
            self.inner.get_range(key, range).await
        }
        async fn get(&self, key: &str) -> Result<Option<Vec<u8>>> { self.inner.get(key).await }
        async fn put_if_absent(&self, key: &str, bytes: &[u8]) -> Result<bool> { self.inner.put_if_absent(key, bytes).await }
        async fn put(&self, key: &str, bytes: &[u8]) -> Result<()> { self.inner.put(key, bytes).await }
        async fn delete(&self, key: &str) -> Result<()> { self.inner.delete(key).await }
        async fn list(&self, prefix: &str) -> Result<Vec<String>> { self.inner.list(prefix).await }
    }

    /// NAN-3801 r52: ranges over the S3 store's 4 MiB GET cap are read as
    /// consecutive capped GETs, byte-exact, with a missing object reported.
    #[tokio::test]
    async fn chunked_range_reads_stay_under_the_store_cap() {
        let dir = tempfile::tempdir().unwrap();
        let local = crate::parts::part_log::LocalObjectStore::new(dir.path()).unwrap();
        let body = (0..(2 * MAX_RANGE_GET_BYTES + 12_345)).map(|i| (i * 31 % 251) as u8).collect::<Vec<_>>();
        local.put("big", &body).await.unwrap();
        let store = CappedRanges::new(&local);
        let total = body.len() as u64;
        assert!(store.get_range("big", 0..total).await.unwrap_err().to_string().contains("exceeds budget"), "fixture: one GET is refused");
        store.largest.store(0, std::sync::atomic::Ordering::SeqCst);
        let read = read_range_bounded(&store, "big", 7..total - 3, total).await.unwrap().unwrap();
        assert_eq!(read, body[7..body.len() - 3]);
        assert!(store.largest.load(std::sync::atomic::Ordering::SeqCst) <= MAX_RANGE_GET_BYTES);
        let mut offsets = Vec::new();
        assert!(read_range_chunked(&store, "big", 0..total, |offset, bytes| { offsets.push((offset, bytes.len() as u64)); Ok(()) }).await.unwrap());
        assert_eq!(offsets, vec![(0, MAX_RANGE_GET_BYTES), (MAX_RANGE_GET_BYTES, MAX_RANGE_GET_BYTES), (2 * MAX_RANGE_GET_BYTES, 12_345)]);
        assert!(!read_range_chunked(&store, "absent", 0..total, |_, _| Ok(())).await.unwrap());
        assert!(read_range_bounded(&store, "big", 0..total, MAX_RANGE_GET_BYTES).await.is_err(), "the caller's cap still bounds memory");
        assert_eq!(read_range_bounded(&store, "big", 5..5, 8).await.unwrap(), Some(Vec::new()));
        assert_eq!(MAX_FETCH_BUFFER_BYTES, 64 * 1024 * 1024);
    }

    /// NAN-3801 r52: "entity counts dropped: No such file or directory …
    /// out/.entity-counts-*". The builder spills into the output directory
    /// once its buffer fills, mid-scan, but `out/` was only created in
    /// `finish`. The accumulator now creates it up front; the spill is
    /// removed when the builder is consumed, and backfill_counts removes
    /// the whole per-part directory.
    #[test]
    fn count_spill_lands_in_a_fresh_out_dir_and_is_removed() {
        let dir = tempfile::tempdir().unwrap();
        let (old, old_dir, _) = write_part(&dir.path().join("old"), &events(3_000));
        let files = local_data_files(&old_dir).unwrap();
        let out = dir.path().join("counts-only").join("part").join("out");
        assert!(!out.exists());
        let spills = |dir: &Path| std::fs::read_dir(dir).map(|entries| entries.filter(|entry|
            entry.as_ref().unwrap().file_name().to_string_lossy().starts_with(".entity-counts-")).count()).unwrap_or(0);
        let mut counts = CountAccumulator::new(&out).unwrap();
        let mut batches = 0;
        for path in &files {
            let file = std::fs::File::open(path).unwrap();
            let metadata = ArrowReaderMetadata::load(&file, Default::default()).unwrap();
            let mask = count_projection(&metadata);
            for batch in ParquetRecordBatchReaderBuilder::new_with_metadata(file, metadata).with_projection(mask)
                .with_batch_size(500).build().unwrap() {
                // Every batch spills, as a large part's do once the buffer fills.
                counts.builder.as_mut().unwrap().force_flush_on_next_batch();
                counts.add(&batch.unwrap());
                batches += 1;
            }
        }
        assert!(batches > 1);
        assert!(counts.error.is_none(), "{:?}", counts.error);
        assert_eq!(spills(&out), 1, "the mid-scan spill lives in out/");
        let spilled = counts.finish(&out, old.rows).unwrap();
        assert_eq!(spills(&out), 0, "the spill is gone once the count file is written");
        let plain = count_local_files(&files, &dir.path().join("plain"), old.rows).unwrap();
        assert_eq!(read_rows(&spilled.path), read_rows(&plain.path), "spilling changes no count");
        assert_eq!(spilled.coverage_mask, plain.coverage_mask);
    }

    #[test]
    fn projection_reads_only_the_count_leaves() {
        let dir = tempfile::tempdir().unwrap();
        let (_, old_dir, _) = write_part(&dir.path().join("old"), &events(100));
        let file = std::fs::File::open(&local_data_files(&old_dir).unwrap()[0]).unwrap();
        let metadata = ArrowReaderMetadata::load(&file, Default::default()).unwrap();
        let reader = ParquetRecordBatchReaderBuilder::new_with_metadata(file, metadata.clone())
            .with_projection(count_projection(&metadata)).build().unwrap();
        fn walk(prefix: &str, field: &arrow_schema::Field, out: &mut Vec<String>) {
            let name = if prefix.is_empty() { field.name().clone() } else { format!("{prefix}.{}", field.name()) };
            match field.data_type() {
                arrow_schema::DataType::Struct(children) => children.iter().for_each(|child| walk(&name, child, out)),
                _ => out.push(name),
            }
        }
        let mut leaves = Vec::new();
        arrow_array::RecordBatchReader::schema(&reader).fields().iter().for_each(|field| walk("", field, &mut leaves));
        assert!(leaves.iter().all(|leaf| count_leaves().contains(&leaf.as_str())), "{leaves:?}");
        assert!(leaves.contains(&"time".to_string()) && leaves.contains(&"src_endpoint.ip".to_string()));
        assert!(!leaves.contains(&"message".to_string()));
    }
}
