// SPDX-License-Identifier: AGPL-3.0-or-later

//! Aggregate partials for adopted parts (contract 3.2–3.4), built with
//! bounded memory.
//!
//! The row rules and file shapes are the ingest rules (phase 2's
//! `part_ingest::partials`, NAN-2868): same keys, same merge functions, same
//! sort order, so an adopted partial merges with an ingest partial by the
//! contract's keyed merge. The only difference is memory: an adopted object
//! can be a whole compacted hour or day, so each aggregator spills sorted
//! runs once it holds `cap` keys and k-way merges them at the end.
//!
//! TODO(NAN-2868 convergence): when phase 2 lands `part_ingest::partials`,
//! replace the row types and `merge_sorted` here with those and keep only
//! the spilling aggregator; `parts_adopt::tests::adopted_partials_merge_with_ingest_shape`
//! pins the equivalence until then.

use anyhow::{bail, Context, Result};
use arrow_array::builder::{ListBuilder, UInt64Builder};
use arrow_array::{
    Array, ArrayRef, Date32Array, Int64Array, ListArray, RecordBatch, StringArray,
    TimestampMicrosecondArray, UInt16Array, UInt64Array, UInt8Array,
};
use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;
use parquet::arrow::ArrowWriter;
use parquet::basic::{Compression, ZstdLevel};
use parquet::file::properties::WriterProperties;
use std::cmp::Ordering;
use std::collections::hash_map::Entry;
use std::collections::{BinaryHeap, HashMap};
use std::fs::File;
use std::hash::Hash;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::generation::{count_rollup_batch_counts, event_time_us_from_array, CompiledStringPath};
use crate::parts::format::{ENTITY_RANGE_PATHS, UID_PATH};
use crate::parts::sidecar::{
    entity_ranges_schema, host_fingerprint, merge_host_fingerprints, prevalence_schema, rollup_schema,
    PREVALENCE_HOST_CAP,
};
use crate::parts::DAY_US;

const PARTIAL_BATCH_ROWS: usize = 8_192;

fn partial_properties() -> Result<WriterProperties> {
    Ok(WriterProperties::builder()
        .set_compression(Compression::ZSTD(ZstdLevel::try_new(6)?))
        .set_max_row_group_row_count(Some(65_536))
        .build())
}

/// One keyed, exactly-mergeable partial row.
pub trait PartialRow: Sized {
    type Key: Ord + Hash + Clone;
    fn key(&self) -> &Self::Key;
    fn combine(&mut self, other: Self);
    fn schema() -> Arc<arrow_schema::Schema>;
    fn from_batch(batch: &RecordBatch) -> Result<Vec<Self>>;
    fn to_batch(rows: &[Self]) -> Result<RecordBatch>;
}

/// Write rows (one per key) sorted by key. Returns rows written.
pub fn write_sorted<T: PartialRow>(mut rows: Vec<T>, path: &Path) -> Result<u64> {
    rows.sort_by(|a, b| a.key().cmp(b.key()));
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut writer = ArrowWriter::try_new(File::create(path)?, T::schema(), Some(partial_properties()?))?;
    for chunk in rows.chunks(PARTIAL_BATCH_ROWS) {
        writer.write(&T::to_batch(chunk)?)?;
    }
    writer.close()?;
    Ok(rows.len() as u64)
}

/// Streams the rows of one sorted partial file.
pub struct SortedReader<T: PartialRow> {
    reader: parquet::arrow::arrow_reader::ParquetRecordBatchReader,
    buffer: std::vec::IntoIter<T>,
}

impl<T: PartialRow> SortedReader<T> {
    pub fn open(path: &Path) -> Result<Self> {
        let reader = ParquetRecordBatchReaderBuilder::try_new(File::open(path)?)?
            .with_batch_size(PARTIAL_BATCH_ROWS)
            .build()?;
        Ok(Self { reader, buffer: Vec::new().into_iter() })
    }

    #[allow(clippy::should_implement_trait)]
    pub fn next(&mut self) -> Result<Option<T>> {
        loop {
            if let Some(row) = self.buffer.next() {
                return Ok(Some(row));
            }
            match self.reader.next() {
                Some(batch) => self.buffer = T::from_batch(&batch?)?.into_iter(),
                None => return Ok(None),
            }
        }
    }
}

struct HeapItem<T: PartialRow> {
    row: T,
    input: usize,
}

impl<T: PartialRow> PartialEq for HeapItem<T> {
    fn eq(&self, other: &Self) -> bool {
        self.row.key() == other.row.key() && self.input == other.input
    }
}
impl<T: PartialRow> Eq for HeapItem<T> {}
impl<T: PartialRow> PartialOrd for HeapItem<T> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}
impl<T: PartialRow> Ord for HeapItem<T> {
    fn cmp(&self, other: &Self) -> Ordering {
        // Min-heap on (key, input).
        other.row.key().cmp(self.row.key()).then(other.input.cmp(&self.input))
    }
}

/// k-way merge of sorted partial files into one sorted file, combining equal
/// keys. Memory: one decoded batch per input plus one output batch.
pub fn merge_sorted<T: PartialRow>(inputs: &[&Path], output: &Path) -> Result<u64> {
    let mut readers = inputs.iter().map(|p| SortedReader::<T>::open(p)).collect::<Result<Vec<_>>>()?;
    let mut heap = BinaryHeap::new();
    for (input, reader) in readers.iter_mut().enumerate() {
        if let Some(row) = reader.next()? {
            heap.push(HeapItem { row, input });
        }
    }
    if let Some(parent) = output.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut writer = ArrowWriter::try_new(File::create(output)?, T::schema(), Some(partial_properties()?))?;
    let mut pending: Vec<T> = Vec::with_capacity(PARTIAL_BATCH_ROWS);
    let mut rows = 0_u64;
    while let Some(HeapItem { row, input }) = heap.pop() {
        if let Some(next) = readers[input].next()? {
            if next.key() < row.key() {
                bail!("partial input is not sorted by key");
            }
            heap.push(HeapItem { row: next, input });
        }
        match pending.last_mut() {
            Some(last) if last.key() == row.key() => last.combine(row),
            _ => {
                if pending.len() >= PARTIAL_BATCH_ROWS {
                    // Keep the last row: the next input row may combine into it.
                    let keep = pending.pop().expect("nonempty");
                    rows += pending.len() as u64;
                    writer.write(&T::to_batch(&pending)?)?;
                    pending.clear();
                    pending.push(keep);
                }
                pending.push(row);
            }
        }
    }
    rows += pending.len() as u64;
    if !pending.is_empty() {
        writer.write(&T::to_batch(&pending)?)?;
    }
    writer.close()?;
    Ok(rows)
}

/// Keyed aggregation that holds at most `cap` keys in memory and spills
/// sorted runs past that. `finish` writes one sorted, combined file.
pub struct SpillingAggregator<T: PartialRow> {
    map: HashMap<T::Key, T>,
    cap: usize,
    runs: Vec<PathBuf>,
    dir: PathBuf,
    name: &'static str,
}

impl<T: PartialRow> SpillingAggregator<T> {
    pub fn new(dir: &Path, name: &'static str, cap: usize) -> Self {
        Self { map: HashMap::new(), cap: cap.max(1), runs: Vec::new(), dir: dir.to_path_buf(), name }
    }

    pub fn add(&mut self, row: T) -> Result<()> {
        match self.map.entry(row.key().clone()) {
            Entry::Occupied(mut existing) => existing.get_mut().combine(row),
            Entry::Vacant(slot) => {
                slot.insert(row);
            }
        }
        if self.map.len() >= self.cap {
            self.spill()?;
        }
        Ok(())
    }

    /// Mutable access to the row of `key`, creating it with `init`.
    pub fn upsert(&mut self, key: &T::Key, init: impl FnOnce() -> T, update: impl FnOnce(&mut T)) -> Result<()> {
        if let Some(row) = self.map.get_mut(key) {
            update(row);
            return Ok(());
        }
        let mut row = init();
        update(&mut row);
        self.map.insert(key.clone(), row);
        if self.map.len() >= self.cap {
            self.spill()?;
        }
        Ok(())
    }

    fn spill(&mut self) -> Result<()> {
        let path = self.dir.join(format!(".{}-run-{:05}.parquet", self.name, self.runs.len()));
        write_sorted(self.map.drain().map(|(_, row)| row).collect(), &path)?;
        self.runs.push(path);
        Ok(())
    }

    pub fn spilled_runs(&self) -> usize {
        self.runs.len()
    }

    pub fn finish(mut self, output: &Path) -> Result<u64> {
        if self.runs.is_empty() {
            return write_sorted(self.map.drain().map(|(_, row)| row).collect(), output);
        }
        if !self.map.is_empty() {
            self.spill()?;
        }
        let refs = self.runs.iter().map(PathBuf::as_path).collect::<Vec<_>>();
        let rows = merge_sorted::<T>(&refs, output)?;
        for run in &self.runs {
            std::fs::remove_file(run).with_context(|| format!("remove partial run {}", run.display()))?;
        }
        Ok(rows)
    }
}

fn strings(array: &ArrayRef) -> Result<StringArray> {
    Ok(array.as_any().downcast_ref::<StringArray>().context("partial string column is not Utf8")?.clone())
}

fn column<'a, A: 'static>(batch: &'a RecordBatch, name: &str) -> Result<&'a A> {
    batch
        .column_by_name(name)
        .with_context(|| format!("partial column {name} is missing"))?
        .as_any()
        .downcast_ref::<A>()
        .with_context(|| format!("partial column {name} has the wrong type"))
}

// ---------------------------------------------------------------------------
// Rollup (3.2)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RollupRow {
    /// (bucket_start_us, field_id, source_type, value)
    pub key: (i64, u16, String, Option<String>),
    pub events: u64,
}

impl PartialRow for RollupRow {
    type Key = (i64, u16, String, Option<String>);
    fn key(&self) -> &Self::Key {
        &self.key
    }
    fn combine(&mut self, other: Self) {
        self.events += other.events;
    }
    fn schema() -> Arc<arrow_schema::Schema> {
        rollup_schema()
    }
    fn from_batch(batch: &RecordBatch) -> Result<Vec<Self>> {
        let bucket = column::<Int64Array>(batch, "bucket_start_us")?;
        let field = column::<UInt16Array>(batch, "field_id")?;
        let source = strings(batch.column_by_name("source_type").context("source_type")?)?;
        let value = strings(batch.column_by_name("value").context("value")?)?;
        let events = column::<UInt64Array>(batch, "events")?;
        Ok((0..batch.num_rows())
            .map(|i| RollupRow {
                key: (
                    bucket.value(i),
                    field.value(i),
                    source.value(i).to_string(),
                    (!value.is_null(i)).then(|| value.value(i).to_string()),
                ),
                events: events.value(i),
            })
            .collect())
    }
    fn to_batch(rows: &[Self]) -> Result<RecordBatch> {
        Ok(RecordBatch::try_new(
            Self::schema(),
            vec![
                Arc::new(Int64Array::from_iter_values(rows.iter().map(|r| r.key.0))),
                Arc::new(UInt16Array::from_iter_values(rows.iter().map(|r| r.key.1))),
                Arc::new(StringArray::from_iter_values(rows.iter().map(|r| r.key.2.as_str()))),
                Arc::new(StringArray::from_iter(rows.iter().map(|r| r.key.3.as_deref()))),
                Arc::new(UInt64Array::from_iter_values(rows.iter().map(|r| r.events))),
            ],
        )?)
    }
}

// ---------------------------------------------------------------------------
// Prevalence (3.3)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrevalenceRow {
    /// (kind, scope, entity, day)
    pub key: (String, String, String, i32),
    pub hosts: Vec<u64>,
    pub is_private: u8,
    pub first_seen: i64,
    pub last_seen: i64,
    pub daily_count: u64,
}

impl PartialRow for PrevalenceRow {
    type Key = (String, String, String, i32);
    fn key(&self) -> &Self::Key {
        &self.key
    }
    fn combine(&mut self, other: Self) {
        self.hosts = merge_host_fingerprints(&self.hosts, &other.hosts);
        self.is_private = self.is_private.max(other.is_private);
        self.first_seen = self.first_seen.min(other.first_seen);
        self.last_seen = self.last_seen.max(other.last_seen);
        self.daily_count += other.daily_count;
    }
    fn schema() -> Arc<arrow_schema::Schema> {
        prevalence_schema()
    }
    fn from_batch(batch: &RecordBatch) -> Result<Vec<Self>> {
        let kind = strings(batch.column_by_name("kind").context("kind")?)?;
        let scope = strings(batch.column_by_name("scope").context("scope")?)?;
        let entity = strings(batch.column_by_name("entity").context("entity")?)?;
        let day = column::<Date32Array>(batch, "day")?;
        let hosts = column::<ListArray>(batch, "host_fingerprints")?;
        let host_cap = column::<UInt16Array>(batch, "host_cap")?;
        let private = column::<UInt8Array>(batch, "is_private")?;
        let first = column::<TimestampMicrosecondArray>(batch, "first_seen")?;
        let last = column::<TimestampMicrosecondArray>(batch, "last_seen")?;
        let count = column::<UInt64Array>(batch, "daily_count")?;
        (0..batch.num_rows())
            .map(|i| {
                anyhow::ensure!(
                    host_cap.value(i) as usize == PREVALENCE_HOST_CAP,
                    "prevalence partial uses an incompatible host cap"
                );
                let list = hosts.value(i);
                let list = list.as_any().downcast_ref::<UInt64Array>().context("host list type")?;
                Ok(PrevalenceRow {
                    key: (kind.value(i).into(), scope.value(i).into(), entity.value(i).into(), day.value(i)),
                    hosts: list.values().to_vec(),
                    is_private: private.value(i),
                    first_seen: first.value(i),
                    last_seen: last.value(i),
                    daily_count: count.value(i),
                })
            })
            .collect()
    }
    fn to_batch(rows: &[Self]) -> Result<RecordBatch> {
        let mut hosts = ListBuilder::new(UInt64Builder::new())
            .with_field(Arc::new(arrow_schema::Field::new("item", arrow_schema::DataType::UInt64, false)));
        for row in rows {
            hosts.values().append_slice(&row.hosts);
            hosts.append(true);
        }
        Ok(RecordBatch::try_new(
            Self::schema(),
            vec![
                Arc::new(StringArray::from_iter_values(rows.iter().map(|r| r.key.0.as_str()))),
                Arc::new(StringArray::from_iter_values(rows.iter().map(|r| r.key.1.as_str()))),
                Arc::new(StringArray::from_iter_values(rows.iter().map(|r| r.key.2.as_str()))),
                Arc::new(Date32Array::from_iter_values(rows.iter().map(|r| r.key.3))),
                Arc::new(hosts.finish()),
                Arc::new(UInt16Array::from_iter_values(rows.iter().map(|_| PREVALENCE_HOST_CAP as u16))),
                Arc::new(UInt8Array::from_iter_values(rows.iter().map(|r| r.is_private))),
                Arc::new(TimestampMicrosecondArray::from_iter_values(rows.iter().map(|r| r.first_seen)).with_timezone("+00:00")),
                Arc::new(TimestampMicrosecondArray::from_iter_values(rows.iter().map(|r| r.last_seen)).with_timezone("+00:00")),
                Arc::new(UInt64Array::from_iter_values(rows.iter().map(|r| r.daily_count))),
            ],
        )?)
    }
}

// ---------------------------------------------------------------------------
// Entity time ranges (3.4)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntityRangeRow {
    /// (path, raw value)
    pub key: (String, String),
    pub first_time: i64,
    pub last_time: i64,
    pub events: u64,
}

impl PartialRow for EntityRangeRow {
    type Key = (String, String);
    fn key(&self) -> &Self::Key {
        &self.key
    }
    fn combine(&mut self, other: Self) {
        self.first_time = self.first_time.min(other.first_time);
        self.last_time = self.last_time.max(other.last_time);
        self.events += other.events;
    }
    fn schema() -> Arc<arrow_schema::Schema> {
        entity_ranges_schema()
    }
    fn from_batch(batch: &RecordBatch) -> Result<Vec<Self>> {
        let path = strings(batch.column_by_name("path").context("path")?)?;
        let value = strings(batch.column_by_name("value").context("value")?)?;
        let first = column::<TimestampMicrosecondArray>(batch, "first_time")?;
        let last = column::<TimestampMicrosecondArray>(batch, "last_time")?;
        let events = column::<UInt64Array>(batch, "events")?;
        Ok((0..batch.num_rows())
            .map(|i| EntityRangeRow {
                key: (path.value(i).into(), value.value(i).into()),
                first_time: first.value(i),
                last_time: last.value(i),
                events: events.value(i),
            })
            .collect())
    }
    fn to_batch(rows: &[Self]) -> Result<RecordBatch> {
        Ok(RecordBatch::try_new(
            Self::schema(),
            vec![
                Arc::new(StringArray::from_iter_values(rows.iter().map(|r| r.key.0.as_str()))),
                Arc::new(StringArray::from_iter_values(rows.iter().map(|r| r.key.1.as_str()))),
                Arc::new(TimestampMicrosecondArray::from_iter_values(rows.iter().map(|r| r.first_time)).with_timezone("+00:00")),
                Arc::new(TimestampMicrosecondArray::from_iter_values(rows.iter().map(|r| r.last_time)).with_timezone("+00:00")),
                Arc::new(UInt64Array::from_iter_values(rows.iter().map(|r| r.events))),
            ],
        )?)
    }
}

// ---------------------------------------------------------------------------
// Row accumulation (same rules as ingest L0 partials)
// ---------------------------------------------------------------------------

const OBSERVATION_IP_PATHS: &[&str] = &["src_endpoint.ip", "dst_endpoint.ip"];
/// NAN-3039: the shared prevalence-indexed domain list (`ocsf_domains`).
const OBSERVATION_DOMAIN_PATHS: &[&str] = crate::ocsf_domains::PREVALENCE_DOMAIN_PATHS;
const OBSERVATION_HASH_VALUE_PATHS: &[&str] =
    &["file.hashes.value", "process.file.hashes.value", "actor.process.file.hashes.value"];
/// NAN-3213: the same observer identity as ingest L0 partials.
const OBSERVATION_OBSERVER_PATHS: &[&str] = crate::ocsf_domains::PREVALENCE_OBSERVER_PATHS;

fn is_private_v4(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            o[0] == 10 || (o[0] == 172 && (16..=31).contains(&o[1])) || (o[0] == 192 && o[1] == 168)
        }
        IpAddr::V6(_) => false,
    }
}

fn first_host(paths: &[Option<CompiledStringPath>], row: usize) -> String {
    paths
        .iter()
        .flatten()
        .flat_map(|path| path.strings(row).into_iter().next())
        .find(|value| !value.is_empty())
        .map(|value| value.trim().to_lowercase())
        .unwrap_or_else(|| "unknown".to_string())
}

/// Per-aggregator key caps (the memory bound of one partial).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PartialCaps {
    pub rollup_keys: usize,
    pub prevalence_keys: usize,
    pub entity_keys: usize,
}

impl Default for PartialCaps {
    fn default() -> Self {
        // ~150-250 B per resident key: about 60 MB per aggregator at the cap.
        Self { rollup_keys: 262_144, prevalence_keys: 262_144, entity_keys: 262_144 }
    }
}

/// Accumulates every row-derived partial of one adopted part, spilling to
/// `dir` past the caps.
pub struct RowPartials {
    rollup: SpillingAggregator<RollupRow>,
    prevalence: SpillingAggregator<PrevalenceRow>,
    entities: SpillingAggregator<EntityRangeRow>,
    source_types: HashMap<String, Arc<str>>,
    rows: u64,
    /// NAN-3226: the internal-suffix set pinned for this adopted part.
    internal_domains: Arc<nanosiem_core::internal_domains::InternalDomains>,
}

impl RowPartials {
    pub fn new(dir: &Path, caps: PartialCaps) -> Self {
        Self {
            rollup: SpillingAggregator::new(dir, "rollup", caps.rollup_keys),
            prevalence: SpillingAggregator::new(dir, "prevalence", caps.prevalence_keys),
            entities: SpillingAggregator::new(dir, "entity-ranges", caps.entity_keys),
            source_types: HashMap::new(),
            rows: 0,
            internal_domains: crate::ocsf_domains::current_internal_domains(),
        }
    }

    pub fn add_batch(&mut self, batch: &RecordBatch) -> Result<()> {
        for ((bucket, field, source, value), count) in count_rollup_batch_counts(batch, &mut self.source_types)? {
            self.rollup.add(RollupRow { key: (bucket, field, source.to_string(), value), events: count })?;
        }
        self.rows += batch.num_rows() as u64;
        let time = batch.column_by_name("time").context("part batch has no time")?;
        let compile = |paths: &[&str]| paths.iter().map(|p| CompiledStringPath::new(batch, p)).collect::<Vec<_>>();
        let scope_path = CompiledStringPath::new(batch, "metadata.log_source");
        let ip_paths = compile(OBSERVATION_IP_PATHS);
        let domain_paths = compile(OBSERVATION_DOMAIN_PATHS);
        let hash_paths = compile(OBSERVATION_HASH_VALUE_PATHS);
        let observer_paths = compile(OBSERVATION_OBSERVER_PATHS);
        let entity_paths = ENTITY_RANGE_PATHS
            .iter()
            .filter(|p| **p != UID_PATH)
            .map(|p| (*p, CompiledStringPath::new(batch, p)))
            .collect::<Vec<_>>();
        for row in 0..batch.num_rows() {
            let Some(time_us) = event_time_us_from_array(time.as_ref(), row) else { continue };
            let day = i32::try_from(time_us.div_euclid(DAY_US))?;
            let scope = scope_path
                .as_ref()
                .and_then(|p| p.strings(row).into_iter().next())
                .unwrap_or_default()
                .to_lowercase();
            let prevalence = &mut self.prevalence;
            let mut observe = |kind: &str, entity: String, host: &str, private: u8| -> Result<()> {
                let key = (kind.to_string(), scope.clone(), entity, day);
                let fingerprint = host_fingerprint(host);
                prevalence.upsert(
                    &key,
                    || PrevalenceRow {
                        key: key.clone(),
                        hosts: Vec::new(),
                        is_private: 0,
                        first_seen: time_us,
                        last_seen: time_us,
                        daily_count: 0,
                    },
                    |entry| {
                        if let Err(position) = entry.hosts.binary_search(&fingerprint) {
                            entry.hosts.insert(position, fingerprint);
                            entry.hosts.truncate(PREVALENCE_HOST_CAP);
                        }
                        entry.is_private = entry.is_private.max(private);
                        entry.first_seen = entry.first_seen.min(time_us);
                        entry.last_seen = entry.last_seen.max(time_us);
                        entry.daily_count += 1;
                    },
                )
            };
            let observer = first_host(&observer_paths, row);
            for path in ip_paths.iter().flatten() {
                for value in path.strings(row) {
                    let entity = value.trim().to_lowercase();
                    if value.is_empty() {
                        continue;
                    }
                    if let Ok(ip) = entity.parse::<IpAddr>() {
                        observe("ip", entity, &observer, u8::from(is_private_v4(&ip)))?;
                    }
                }
            }
            for path in domain_paths.iter().flatten() {
                for value in path.strings(row) {
                    let entity = value.trim().to_lowercase();
                    if value.is_empty() || !crate::ocsf_domains::is_prevalence_domain_with(&entity, &self.internal_domains) {
                        continue;
                    }
                    observe("domain", entity, &observer, 0)?;
                }
            }
            for path in hash_paths.iter().flatten() {
                for value in path.strings(row) {
                    if matches!(value.len(), 32 | 40 | 64) && value.bytes().all(|b| b.is_ascii_hexdigit()) {
                        observe("hash", value.trim().to_lowercase(), &observer, 0)?;
                    }
                }
            }
            for (name, path) in &entity_paths {
                let Some(path) = path else { continue };
                for value in path.strings(row) {
                    if value.is_empty() {
                        continue;
                    }
                    let key = ((*name).to_string(), value);
                    self.entities.upsert(
                        &key,
                        || EntityRangeRow { key: key.clone(), first_time: time_us, last_time: time_us, events: 0 },
                        |entry| {
                            entry.first_time = entry.first_time.min(time_us);
                            entry.last_time = entry.last_time.max(time_us);
                            entry.events += 1;
                        },
                    )?;
                }
            }
        }
        Ok(())
    }

    pub fn spilled_runs(&self) -> usize {
        self.rollup.spilled_runs() + self.prevalence.spilled_runs() + self.entities.spilled_runs()
    }

    /// Write the partial files under `part_dir`; returns (kind, relative
    /// name, rows). Checks the rollup invariant (field 0 sums to the rows).
    pub fn write(self, part_dir: &Path) -> Result<Vec<(crate::parts::provenance::PartialKind, &'static str, u64)>> {
        use crate::parts::format::{PARTIAL_ENTITY_RANGES_FILE, PARTIAL_PREVALENCE_FILE, PARTIAL_ROLLUP_FILE};
        use crate::parts::provenance::PartialKind;
        let rows = self.rows;
        let rollup_path = part_dir.join(PARTIAL_ROLLUP_FILE);
        let rollup_rows = self.rollup.finish(&rollup_path)?;
        if rollup_field0_events(&rollup_path)? != rows {
            bail!("adopted rollup field 0 does not sum to the part's rows");
        }
        let prevalence_rows = self.prevalence.finish(&part_dir.join(PARTIAL_PREVALENCE_FILE))?;
        let entity_rows = self.entities.finish(&part_dir.join(PARTIAL_ENTITY_RANGES_FILE))?;
        Ok(vec![
            (PartialKind::Rollup, PARTIAL_ROLLUP_FILE, rollup_rows),
            (PartialKind::Prevalence, PARTIAL_PREVALENCE_FILE, prevalence_rows),
            (PartialKind::EntityRanges, PARTIAL_ENTITY_RANGES_FILE, entity_rows),
        ])
    }
}

/// Sum of `events` for rollup `field_id = 0` (the writer's row-count check).
pub fn rollup_field0_events(path: &Path) -> Result<u64> {
    let mut reader = SortedReader::<RollupRow>::open(path)?;
    let mut total = 0;
    while let Some(row) = reader.next()? {
        if row.key.1 == 0 {
            total += row.events;
        }
    }
    Ok(total)
}

/// Merge partial directories (`partials/*.parquet` under each) into
/// `output_dir` by the contract's keyed merges. What a merged part does with
/// its inputs' partials; used here to prove adopted partials merge with
/// ingest partials.
pub fn merge_partial_dirs(inputs: &[&Path], output_dir: &Path) -> Result<()> {
    fn refs(paths: &[PathBuf]) -> Vec<&Path> {
        paths.iter().map(PathBuf::as_path).collect()
    }
    use crate::parts::format::{PARTIAL_ENTITY_RANGES_FILE, PARTIAL_PREVALENCE_FILE, PARTIAL_ROLLUP_FILE};
    let files = |name: &str| inputs.iter().map(|dir| dir.join(name)).collect::<Vec<_>>();
    let rollup = files(PARTIAL_ROLLUP_FILE);
    merge_sorted::<RollupRow>(&refs(&rollup), &output_dir.join(PARTIAL_ROLLUP_FILE))?;
    let prevalence = files(PARTIAL_PREVALENCE_FILE);
    merge_sorted::<PrevalenceRow>(&refs(&prevalence), &output_dir.join(PARTIAL_PREVALENCE_FILE))?;
    let entities = files(PARTIAL_ENTITY_RANGES_FILE);
    merge_sorted::<EntityRangeRow>(&refs(&entities), &output_dir.join(PARTIAL_ENTITY_RANGES_FILE))?;
    Ok(())
}

/// Read every row of a sorted partial file (tests and parity tooling).
pub fn read_all<T: PartialRow>(path: &Path) -> Result<Vec<T>> {
    let mut reader = SortedReader::<T>::open(path)?;
    let mut rows = Vec::new();
    while let Some(row) = reader.next()? {
        rows.push(row);
    }
    Ok(rows)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rollup(bucket: i64, value: &str, events: u64) -> RollupRow {
        RollupRow { key: (bucket, 0, "s".into(), Some(value.into())), events }
    }

    #[test]
    fn spilling_aggregator_equals_in_memory_aggregation() {
        let dir = tempfile::tempdir().unwrap();
        let mut spilled = SpillingAggregator::<RollupRow>::new(dir.path(), "r", 7);
        let mut memory = SpillingAggregator::<RollupRow>::new(dir.path(), "m", usize::MAX);
        for i in 0..1_000_i64 {
            spilled.add(rollup(i % 97, "x", 1)).unwrap();
            memory.add(rollup(i % 97, "x", 1)).unwrap();
        }
        assert!(spilled.spilled_runs() > 10);
        let a = dir.path().join("a.parquet");
        let b = dir.path().join("b.parquet");
        assert_eq!(spilled.finish(&a).unwrap(), 97);
        memory.finish(&b).unwrap();
        assert_eq!(read_all::<RollupRow>(&a).unwrap(), read_all::<RollupRow>(&b).unwrap());
        assert_eq!(rollup_field0_events(&a).unwrap(), 1_000);
        // Runs are cleaned up.
        assert!(std::fs::read_dir(dir.path()).unwrap().all(|e| !e.unwrap().file_name().to_string_lossy().starts_with('.')));
    }

    #[test]
    fn merge_refuses_unsorted_input() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("u.parquet");
        let mut writer = ArrowWriter::try_new(File::create(&path).unwrap(), rollup_schema(), None).unwrap();
        writer.write(&RollupRow::to_batch(&[rollup(5, "x", 1), rollup(1, "x", 1)]).unwrap()).unwrap();
        writer.close().unwrap();
        assert!(merge_sorted::<RollupRow>(&[&path], &dir.path().join("o.parquet")).is_err());
    }
}
