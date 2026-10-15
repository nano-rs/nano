// SPDX-License-Identifier: AGPL-3.0-or-later

//! Aggregate partials (contract 3.2–3.4): built from rows for L0 parts and
//! merged as sorted streams for every merged level.
//!
//! Every partial file is written sorted by its key, so a merge is a k-way
//! merge that holds one decoded batch per input and never the whole partial.

use anyhow::{ensure, Context, Result};
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
use std::collections::{BinaryHeap, HashMap};
use std::fs::File;
use std::net::IpAddr;
use std::path::Path;
use std::sync::Arc;

use crate::generation::{count_rollup_batch_counts, event_time_us_from_array, CompiledStringPath};
use crate::part_query::risk::{risk_partial_rows, CompactFinding, RiskPartialRow};
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
    type Key: Ord + Clone;
    fn key(&self) -> &Self::Key;
    fn combine(&mut self, other: Self);
    fn schema() -> Arc<arrow_schema::Schema>;
    fn from_batch(batch: &RecordBatch) -> Result<Vec<Self>>;
    fn to_batch(rows: &[Self]) -> Result<RecordBatch>;
}

/// Write rows (already combined per key) sorted by key. Returns rows written.
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

/// Write one bounded local spill run. Never used by the signed part writer.
pub fn write_sorted_capped<T: PartialRow>(mut rows: Vec<T>, path: &Path, batch_rows: usize, max_bytes: u64) -> Result<u64> {
    ensure!(batch_rows > 0 && batch_rows <= PARTIAL_BATCH_ROWS, "invalid spill batch size");
    rows.sort_by(|a, b| a.key().cmp(b.key()));
    let properties = WriterProperties::builder()
        .set_compression(Compression::ZSTD(ZstdLevel::try_new(6)?))
        .set_max_row_group_row_count(Some(batch_rows)).build();
    let sink = CappedPartialOutput { file: File::create(path)?, remaining: max_bytes };
    let mut writer = ArrowWriter::try_new(sink, T::schema(), Some(properties))?;
    for chunk in rows.chunks(batch_rows) { writer.write(&T::to_batch(chunk)?)?; }
    writer.close()?;
    Ok(rows.len() as u64)
}

struct SortedReader<T: PartialRow> {
    reader: parquet::arrow::arrow_reader::ParquetRecordBatchReader,
    buffer: std::vec::IntoIter<T>,
}

impl<T: PartialRow> SortedReader<T> {
    fn open(path: &Path) -> Result<Self> { Self::open_with_batch(path, PARTIAL_BATCH_ROWS) }

    fn open_with_batch(path: &Path, batch_rows: usize) -> Result<Self> {
        let reader = ParquetRecordBatchReaderBuilder::try_new(File::open(path)?)?
            .with_batch_size(batch_rows)
            .build()?;
        Ok(Self { reader, buffer: Vec::new().into_iter() })
    }

    fn next(&mut self) -> Result<Option<T>> {
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

/// k-way merge of sorted partial files into one sorted file. Memory: one
/// batch per input plus one output batch. Returns rows written.
pub fn merge_sorted<T: PartialRow>(inputs: &[&Path], output: &Path) -> Result<u64> {
    merge_sorted_with::<T>(inputs, output, PARTIAL_BATCH_ROWS, partial_properties()?, u64::MAX, |_| true)
}

/// A local-cache spill merge: bound input/output batches, Parquet buffering
/// and output bytes. Ordinary signed compaction retains its existing layout.
pub fn merge_sorted_capped<T: PartialRow>(inputs: &[&Path], output: &Path, batch_rows: usize, max_bytes: u64) -> Result<u64> {
    ensure!(batch_rows > 0 && batch_rows <= PARTIAL_BATCH_ROWS, "invalid spill batch size");
    let properties = WriterProperties::builder()
        .set_compression(Compression::ZSTD(ZstdLevel::try_new(6)?))
        .set_max_row_group_row_count(Some(batch_rows)).build();
    merge_sorted_with::<T>(inputs, output, batch_rows, properties, max_bytes, |_| true)
}

#[derive(Debug, thiserror::Error)]
#[error("local partial spill exceeds its byte envelope")]
pub struct PartialSpillLimit;

struct CappedPartialOutput {
    file: File,
    remaining: u64,
}

impl std::io::Write for CappedPartialOutput {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if bytes.len() as u64 > self.remaining {
            return Err(std::io::Error::other(PartialSpillLimit));
        }
        let written = std::io::Write::write(&mut self.file, bytes)?;
        self.remaining -= written as u64;
        Ok(written)
    }
    fn flush(&mut self) -> std::io::Result<()> { std::io::Write::flush(&mut self.file) }
}

fn merge_sorted_with<T: PartialRow>(inputs: &[&Path], output: &Path, batch_rows: usize, properties: WriterProperties, max_bytes: u64, retain: impl Fn(&T) -> bool) -> Result<u64> {
    let mut readers = inputs.iter().map(|p| SortedReader::<T>::open_with_batch(p, batch_rows)).collect::<Result<Vec<_>>>()?;
    let mut heap = BinaryHeap::new();
    for (input, reader) in readers.iter_mut().enumerate() {
        if let Some(row) = reader.next()? {
            heap.push(HeapItem { row, input });
        }
    }
    if let Some(parent) = output.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let sink = CappedPartialOutput { file: File::create(output)?, remaining: max_bytes };
    let mut writer = ArrowWriter::try_new(sink, T::schema(), Some(properties))?;
    let mut pending: Vec<T> = Vec::with_capacity(batch_rows);
    let mut rows = 0_u64;
    while let Some(HeapItem { row, input }) = heap.pop() {
        if let Some(next) = readers[input].next()? {
            heap.push(HeapItem { row: next, input });
        }
        if !retain(&row) { continue; }
        match pending.last_mut() {
            Some(last) if last.key() == row.key() => last.combine(row),
            _ => {
                if pending.len() >= batch_rows {
                    // Keep the last row: the next input row may still combine into it.
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

fn strings(array: &ArrayRef) -> Result<StringArray> {
    let cast = arrow_cast::cast(array.as_ref(), &arrow_schema::DataType::Utf8)?;
    Ok(cast.as_any().downcast_ref::<StringArray>().context("string column")?.clone())
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

impl PartialRow for RiskPartialRow {
    type Key = (String, String, String, i64);

    fn key(&self) -> &Self::Key {
        // Risk rows are already grouped by this key. Keep an owned key in the
        // row so the streaming merger can compare without allocation.
        &self.key
    }

    fn combine(&mut self, other: Self) {
        self.findings += other.findings;
        self.risk_score_sum = self.risk_score_sum.saturating_add(other.risk_score_sum);
        self.max_severity_id = self.max_severity_id.max(other.max_severity_id);
    }

    fn schema() -> Arc<arrow_schema::Schema> {
        use arrow_schema::{DataType, Field, Schema};
        Arc::new(Schema::new(vec![
            Field::new("entity", DataType::Utf8, false),
            Field::new("entity_type", DataType::Utf8, false),
            Field::new("rule_id", DataType::Utf8, false),
            Field::new("bucket_start_us", DataType::Int64, false),
            Field::new("findings", DataType::UInt64, false),
            Field::new("risk_score_sum", DataType::Int64, false),
            Field::new("max_severity_id", DataType::Int32, false),
        ]))
    }

    fn from_batch(batch: &RecordBatch) -> Result<Vec<Self>> {
        let entity = strings(batch.column_by_name("entity").context("entity")?)?;
        let entity_type = strings(batch.column_by_name("entity_type").context("entity_type")?)?;
        let rule_id = strings(batch.column_by_name("rule_id").context("rule_id")?)?;
        let bucket = column::<Int64Array>(batch, "bucket_start_us")?;
        let findings = column::<UInt64Array>(batch, "findings")?;
        let scores = column::<Int64Array>(batch, "risk_score_sum")?;
        let severity = column::<arrow_array::Int32Array>(batch, "max_severity_id")?;
        Ok((0..batch.num_rows())
            .map(|i| RiskPartialRow {
                key: (
                    entity.value(i).into(),
                    entity_type.value(i).into(),
                    rule_id.value(i).into(),
                    bucket.value(i),
                ),
                entity: entity.value(i).into(),
                entity_type: entity_type.value(i).into(),
                rule_id: rule_id.value(i).into(),
                bucket_start_us: bucket.value(i),
                findings: findings.value(i),
                risk_score_sum: scores.value(i),
                max_severity_id: severity.value(i),
            })
            .collect())
    }

    fn to_batch(rows: &[Self]) -> Result<RecordBatch> {
        Ok(RecordBatch::try_new(
            Self::schema(),
            vec![
                Arc::new(StringArray::from_iter_values(
                    rows.iter().map(|r| r.entity.as_str()),
                )),
                Arc::new(StringArray::from_iter_values(
                    rows.iter().map(|r| r.entity_type.as_str()),
                )),
                Arc::new(StringArray::from_iter_values(
                    rows.iter().map(|r| r.rule_id.as_str()),
                )),
                Arc::new(Int64Array::from_iter_values(
                    rows.iter().map(|r| r.bucket_start_us),
                )),
                Arc::new(UInt64Array::from_iter_values(
                    rows.iter().map(|r| r.findings),
                )),
                Arc::new(Int64Array::from_iter_values(
                    rows.iter().map(|r| r.risk_score_sum),
                )),
                Arc::new(arrow_array::Int32Array::from_iter_values(
                    rows.iter().map(|r| r.max_severity_id),
                )),
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
                ensure!(
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

/// Replace only the producer count namespace, streaming ordinary rows.
/// This also strips inherited counts when the writer flag is off or overflows.
pub(super) fn replace_entity_counts(
    path: &Path,
    mut counts: crate::parts::entity_counts::SortedCounts,
) -> Result<u64> {
    let mut pending = counts.next()?;
    let mut input = SortedReader::<EntityRangeRow>::open(path)?;
    let temporary = path.with_extension("counts.tmp");
    let mut writer = ArrowWriter::try_new(
        File::create(&temporary)?,
        EntityRangeRow::schema(),
        Some(
            WriterProperties::builder()
                .set_compression(Compression::ZSTD(ZstdLevel::try_new(6)?))
                .set_max_row_group_row_count(Some(if pending.is_some() { 256 } else { PARTIAL_BATCH_ROWS }))
                .build(),
        ),
    )?;
    // Backward-compatible, digest-bound footer hint: count eligibility can
    // be checked with bounded ranged reads before leasing/decompressing this
    // whole sidecar. Coverage rows remain the decoder's sole authority.
    if let Some(coverage) = pending.as_ref().filter(|row| row.key.0 == crate::parts::entity_counts::V2_COVERAGE_PATH) {
        writer.append_key_value_metadata(parquet::file::metadata::KeyValue::new(
            crate::parts::entity_counts::V2_COVERAGE_PATH.to_string(), coverage.key.1.clone(),
        ));
    }
    let mut buffer = Vec::with_capacity(PARTIAL_BATCH_ROWS);
    let mut written = 0;
    let mut buffered_bytes = 0;
    while let Some(row) = input.next()? {
        if crate::parts::entity_counts::is_count_path(&row.key.0) {
            continue;
        }
        while pending.as_ref().is_some_and(|count| count.key < row.key) {
            let count = pending.take().expect("pending");
            buffered_bytes += 256 + count.key.0.len() + count.key.1.len() * 2;
            buffer.push(count);
            pending = counts.next()?;
            if buffer.len() >= PARTIAL_BATCH_ROWS || buffered_bytes >= 2 * 1024 * 1024 {
                writer.write(&EntityRangeRow::to_batch(&buffer)?)?;
                if writer.memory_size() >= 8 * 1024 * 1024 {
                    writer.flush()?;
                }
                written += buffer.len() as u64;
                buffer.clear();
                buffered_bytes = 0;
            }
        }
        buffered_bytes += 256 + row.key.0.len() + row.key.1.len() * 2;
        buffer.push(row);
        if buffer.len() >= PARTIAL_BATCH_ROWS || buffered_bytes >= 2 * 1024 * 1024 {
            writer.write(&EntityRangeRow::to_batch(&buffer)?)?;
            if writer.memory_size() >= 8 * 1024 * 1024 {
                writer.flush()?;
            }
            written += buffer.len() as u64;
            buffer.clear();
            buffered_bytes = 0;
        }
    }
    while let Some(count) = pending.take() {
        buffered_bytes += 256 + count.key.0.len() + count.key.1.len() * 2;
        buffer.push(count);
        pending = counts.next()?;
        if buffer.len() >= PARTIAL_BATCH_ROWS || buffered_bytes >= 2 * 1024 * 1024 {
            writer.write(&EntityRangeRow::to_batch(&buffer)?)?;
            if writer.memory_size() >= 8 * 1024 * 1024 {
                writer.flush()?;
            }
            written += buffer.len() as u64;
            buffer.clear();
            buffered_bytes = 0;
        }
    }
    if !buffer.is_empty() {
        writer.write(&EntityRangeRow::to_batch(&buffer)?)?;
        if writer.memory_size() >= 8 * 1024 * 1024 {
            writer.flush()?;
        }
        written += buffer.len() as u64;
    }
    writer.close()?;
    ensure!(
        std::fs::metadata(&temporary)?.len() <= crate::parts::format::MAX_OBJECT_BYTES,
        "entity partial exceeds object cap"
    );
    drop(input);
    std::fs::rename(temporary, path)?;
    Ok(written)
}

// ---------------------------------------------------------------------------
// Row accumulation (L0)
// ---------------------------------------------------------------------------

const OBSERVATION_IP_PATHS: &[&str] = &["src_endpoint.ip", "dst_endpoint.ip"];
/// NAN-3039: the shared prevalence-indexed domain list (`ocsf_domains`).
const OBSERVATION_DOMAIN_PATHS: &[&str] = crate::ocsf_domains::PREVALENCE_DOMAIN_PATHS;
const OBSERVATION_HASH_VALUE_PATHS: &[&str] =
    &["file.hashes.value", "process.file.hashes.value", "actor.process.file.hashes.value"];
/// NAN-3213: one observer identity for every artifact kind (the event's
/// device, else its source endpoint), never the artifact's peer.
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

/// Accumulates every row-derived partial of one part.
#[derive(Default)]
pub struct RowPartials {
    rollup: HashMap<(i64, u16, String, Option<String>), u64>,
    prevalence: HashMap<(String, String, String, i32), PrevalenceRow>,
    entities: HashMap<(String, String), EntityRangeRow>,
    source_types: HashMap<String, Arc<str>>,
    risk: Vec<CompactFinding>,
    findings_only: bool,
    /// NAN-3058 identity observations (reserved entity-range path), when the
    /// process has the `lean_identity_observations_v1` flag on.
    identity: Option<crate::identity_observations::IdentityAccumulator>,
    cloud_facets: Option<crate::cloud_facet_summaries::Accumulator>,
    asset_facets: Option<crate::cloud_facet_summaries::Accumulator>,
    /// NAN-3226: the internal-suffix set pinned for this whole part (the
    /// process tenant's list at writer creation; built-ins by default).
    internal_domains: Arc<nanosiem_core::internal_domains::InternalDomains>,
}

fn identity_accumulator() -> Option<crate::identity_observations::IdentityAccumulator> {
    crate::identity_observations::enabled()
        .then(|| crate::identity_observations::IdentityAccumulator::new(crate::identity_observations::INGEST_BYTES_CAP))
}

fn cloud_facet_accumulator() -> Option<crate::cloud_facet_summaries::Accumulator> {
    crate::cloud_facet_summaries::enabled().then(|| crate::cloud_facet_summaries::Accumulator::new(crate::cloud_facet_summaries::CAP_BYTES))
}

fn asset_facet_accumulator() -> Option<crate::cloud_facet_summaries::Accumulator> {
    crate::asset_facet_summaries::enabled().then(|| crate::cloud_facet_summaries::Accumulator::asset(crate::cloud_facet_summaries::CAP_BYTES))
}

impl RowPartials {
    pub fn new() -> Self {
        Self {
            identity: identity_accumulator(),
            cloud_facets: cloud_facet_accumulator(),
            asset_facets: asset_facet_accumulator(),
            internal_domains: crate::ocsf_domains::current_internal_domains(),
            ..Self::default()
        }
    }

    pub fn new_findings() -> Self {
        Self {
            findings_only: true,
            identity: identity_accumulator(),
            cloud_facets: cloud_facet_accumulator(),
            asset_facets: asset_facet_accumulator(),
            internal_domains: crate::ocsf_domains::current_internal_domains(),
            ..Self::default()
        }
    }

    /// Pin an explicit internal-suffix set (tests; production pins the
    /// process tenant's set at construction).
    #[cfg(test)]
    pub fn with_internal_domains(mut self, internal: nanosiem_core::internal_domains::InternalDomains) -> Self {
        self.internal_domains = Arc::new(internal);
        self
    }

    /// Derive identity observations under `cap_bytes` regardless of the
    /// process flag (tests; the flag is process-global).
    #[cfg(test)]
    pub fn with_identity(mut self, cap_bytes: usize) -> Self {
        self.identity = Some(crate::identity_observations::IdentityAccumulator::new(cap_bytes));
        self
    }

    pub fn add_batch(&mut self, batch: &RecordBatch) -> Result<()> {
        if let Some(asset_facets) = &mut self.asset_facets {
            asset_facets.add_batch(batch)?;
        }
        if let Some(cloud_facets) = &mut self.cloud_facets {
            cloud_facets.add_batch(batch)?;
        }
        if let Some(identity) = &mut self.identity {
            identity.add_batch(batch)?;
        }
        for ((bucket, field, source, value), count) in count_rollup_batch_counts(batch, &mut self.source_types)? {
            *self.rollup.entry((bucket, field, source.to_string(), value)).or_default() += count;
        }
        let time = batch.column_by_name("time").context("part batch has no time")?;
        let compile = |paths: &[&str]| paths.iter().map(|p| CompiledStringPath::new(batch, p)).collect::<Vec<_>>();
        let scope_path = CompiledStringPath::new(batch, "metadata.log_source");
        let uid_path = CompiledStringPath::new(batch, "metadata.uid");
        let compact_path = CompiledStringPath::new(batch, "unmapped.nano_compact_finding");
        let trusted_path = CompiledStringPath::new(batch, "unmapped.nano_finding_outbox_trusted");
        let class_uid_cast = if self.findings_only {
            Some(arrow_cast::cast(
                batch.column_by_name("class_uid").context("finding part has no class_uid")?.as_ref(),
                &arrow_schema::DataType::Int64,
            )?)
        } else {
            None
        };
        let class_uid = class_uid_cast.as_ref().map(|array| {
            array.as_any().downcast_ref::<Int64Array>().context("finding class_uid is not numeric")
        }).transpose()?;
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
            if self.findings_only {
                let class_uid = class_uid.expect("finding mode has class_uid");
                anyhow::ensure!(
                    !class_uid.is_null(row) && class_uid.value(row) == 2004,
                    "finding part contains a non-finding event"
                );
                let path = compact_path
                    .as_ref()
                    .context("finding part has no compact finding leaf")?;
                anyhow::ensure!(trusted_path.as_ref().is_some_and(|path| path.strings(row) == vec!["v1".to_string()]),
                    "finding row lacks the authenticated outbox marker");
                let values = path.strings(row);
                anyhow::ensure!(
                    values.len() == 1,
                    "finding row must have exactly one compact finding"
                );
                for value in values {
                    let finding: CompactFinding = serde_json::from_str(&value)
                        .context("malformed compact finding in signed part")?;
                    anyhow::ensure!(
                        !finding.id.is_empty() && finding.timestamp_us == time_us,
                        "compact finding identity or timestamp is invalid"
                    );
                    anyhow::ensure!(
                        uid_path.as_ref().is_some_and(|path| path.strings(row) == vec![finding.id.clone()]),
                        "compact finding id differs from the signed row uid"
                    );
                    self.risk.push(finding);
                }
            }
            let day = i32::try_from(time_us.div_euclid(DAY_US))?;
            let scope = scope_path
                .as_ref()
                .and_then(|p| p.strings(row).into_iter().next())
                .unwrap_or_default()
                .to_lowercase();
            let mut observe = |kind: &str, entity: String, host: &str, private: u8| {
                let key = (kind.to_string(), scope.clone(), entity, day);
                let fingerprint = host_fingerprint(host);
                let entry = self.prevalence.entry(key.clone()).or_insert_with(|| PrevalenceRow {
                    key,
                    hosts: Vec::new(),
                    is_private: 0,
                    first_seen: time_us,
                    last_seen: time_us,
                    daily_count: 0,
                });
                if let Err(position) = entry.hosts.binary_search(&fingerprint) {
                    entry.hosts.insert(position, fingerprint);
                    entry.hosts.truncate(PREVALENCE_HOST_CAP);
                }
                entry.is_private = entry.is_private.max(private);
                entry.first_seen = entry.first_seen.min(time_us);
                entry.last_seen = entry.last_seen.max(time_us);
                entry.daily_count += 1;
            };
            let observer = first_host(&observer_paths, row);
            for path in ip_paths.iter().flatten() {
                for value in path.strings(row) {
                    let entity = value.trim().to_lowercase();
                    if value.is_empty() {
                        continue;
                    }
                    if let Ok(ip) = entity.parse::<IpAddr>() {
                        observe("ip", entity, &observer, u8::from(is_private_v4(&ip)));
                    }
                }
            }
            for path in domain_paths.iter().flatten() {
                for value in path.strings(row) {
                    let entity = value.trim().to_lowercase();
                    if value.is_empty() || !crate::ocsf_domains::is_prevalence_domain_with(&entity, &self.internal_domains) {
                        continue;
                    }
                    observe("domain", entity, &observer, 0);
                }
            }
            for path in hash_paths.iter().flatten() {
                for value in path.strings(row) {
                    if matches!(value.len(), 32 | 40 | 64) && value.bytes().all(|b| b.is_ascii_hexdigit()) {
                        observe("hash", value.trim().to_lowercase(), &observer, 0);
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
                    let entry = self.entities.entry(key.clone()).or_insert_with(|| EntityRangeRow {
                        key,
                        first_time: time_us,
                        last_time: time_us,
                        events: 0,
                    });
                    entry.first_time = entry.first_time.min(time_us);
                    entry.last_time = entry.last_time.max(time_us);
                    entry.events += 1;
                }
            }
        }
        Ok(())
    }

    /// Write the partial files; returns (kind, relative name, rows).
    pub fn write(self, part_dir: &Path) -> Result<Vec<(crate::parts::provenance::PartialKind, &'static str, u64)>> {
        use crate::parts::format::{PARTIAL_ENTITY_RANGES_FILE, PARTIAL_PREVALENCE_FILE, PARTIAL_ROLLUP_FILE, PARTIAL_RISK_FILE};
        use crate::parts::provenance::PartialKind;
        let rollup = self
            .rollup
            .into_iter()
            .map(|(key, events)| RollupRow { key, events })
            .collect::<Vec<_>>();
        let rollup_rows = write_sorted(rollup, &part_dir.join(PARTIAL_ROLLUP_FILE))?;
        let prevalence_rows =
            write_sorted(self.prevalence.into_values().collect(), &part_dir.join(PARTIAL_PREVALENCE_FILE))?;
        let mut entities = self.entities.into_values().collect::<Vec<_>>();
        if let Some(identity) = self.identity {
            entities.extend(identity.into_rows().into_iter().map(|(value, range)| EntityRangeRow {
                key: (crate::identity_observations::IDENTITY_PATH.to_string(), value),
                first_time: range.first_us,
                last_time: range.last_us,
                events: range.events,
            }));
        }
        if let Some(asset_facets) = self.asset_facets {
            entities.extend(asset_facets.into_rows());
        }
        if let Some(cloud_facets) = self.cloud_facets {
            entities.extend(cloud_facets.into_rows());
        }
        let entity_rows = write_sorted(entities, &part_dir.join(PARTIAL_ENTITY_RANGES_FILE))?;
        let mut files = vec![
            (PartialKind::Rollup, PARTIAL_ROLLUP_FILE, rollup_rows),
            (
                PartialKind::Prevalence,
                PARTIAL_PREVALENCE_FILE,
                prevalence_rows,
            ),
            (
                PartialKind::EntityRanges,
                PARTIAL_ENTITY_RANGES_FILE,
                entity_rows,
            ),
        ];
        if !self.risk.is_empty() {
            let rows = write_sorted(
                risk_partial_rows(&self.risk),
                &part_dir.join(PARTIAL_RISK_FILE),
            )?;
            files.push((PartialKind::Risk, PARTIAL_RISK_FILE, rows));
        }
        Ok(files)
    }
}

fn refs(paths: &[std::path::PathBuf]) -> Vec<&Path> {
    paths.iter().map(|p| p.as_path()).collect()
}

/// Merge the partial files of merge inputs into `part_dir`.
pub fn merge_partials(
    inputs: &[&Path],
    part_dir: &Path,
) -> Result<Vec<(crate::parts::provenance::PartialKind, &'static str, u64)>> {
    use crate::parts::format::{PARTIAL_ENTITY_RANGES_FILE, PARTIAL_PREVALENCE_FILE, PARTIAL_ROLLUP_FILE, PARTIAL_RISK_FILE};
    use crate::parts::provenance::PartialKind;
    let files = |name: &str| inputs.iter().map(|dir| dir.join(name)).collect::<Vec<_>>();
    let rollup_inputs = files(PARTIAL_ROLLUP_FILE);
    let prevalence_inputs = files(PARTIAL_PREVALENCE_FILE);
    let entity_inputs = files(PARTIAL_ENTITY_RANGES_FILE);
    let rollup_rows = merge_sorted::<RollupRow>(&refs(&rollup_inputs), &part_dir.join(PARTIAL_ROLLUP_FILE))?;
    let prevalence_rows =
        merge_sorted::<PrevalenceRow>(&refs(&prevalence_inputs), &part_dir.join(PARTIAL_PREVALENCE_FILE))?;
    let entity_rows =
        // Count evidence is re-derived by PartWriter from final rows; never
        // sum input coverage promises (including mixed legacy inputs).
        merge_sorted_with::<EntityRangeRow>(&refs(&entity_inputs), &part_dir.join(PARTIAL_ENTITY_RANGES_FILE),
            PARTIAL_BATCH_ROWS, partial_properties()?, u64::MAX,
            |row| !crate::parts::entity_counts::is_count_path(&row.key.0))?;
    let risk_inputs = files(PARTIAL_RISK_FILE)
        .into_iter()
        .filter(|path| path.is_file())
        .collect::<Vec<_>>();
    let mut files = vec![
        (PartialKind::Rollup, PARTIAL_ROLLUP_FILE, rollup_rows),
        (
            PartialKind::Prevalence,
            PARTIAL_PREVALENCE_FILE,
            prevalence_rows,
        ),
        (
            PartialKind::EntityRanges,
            PARTIAL_ENTITY_RANGES_FILE,
            entity_rows,
        ),
    ];
    if !risk_inputs.is_empty() {
        let rows =
            merge_sorted::<RiskPartialRow>(&refs(&risk_inputs), &part_dir.join(PARTIAL_RISK_FILE))?;
        files.push((PartialKind::Risk, PARTIAL_RISK_FILE, rows));
    }
    Ok(files)
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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn rollup(bucket: i64, value: &str, events: u64) -> RollupRow {
        RollupRow { key: (bucket, 0, "s".into(), Some(value.into())), events }
    }

    #[test]
    fn k_way_merge_sums_equal_keys_across_batches() {
        let dir = tempfile::tempdir().unwrap();
        let a = dir.path().join("a.parquet");
        let b = dir.path().join("b.parquet");
        let mut rows_a = (0..20_000).map(|i| rollup(i, "x", 1)).collect::<Vec<_>>();
        rows_a.push(rollup(5, "y", 2));
        write_sorted(rows_a, &a).unwrap();
        write_sorted((10_000..30_000).map(|i| rollup(i, "x", 3)).collect(), &b).unwrap();
        let out = dir.path().join("out.parquet");
        let rows = merge_sorted::<RollupRow>(&[&a, &b], &out).unwrap();
        assert_eq!(rows, 30_001);
        assert_eq!(rollup_field0_events(&out).unwrap(), 20_000 + 2 + 20_000 * 3);
        let mut reader = SortedReader::<RollupRow>::open(&out).unwrap();
        let mut last = None;
        while let Some(row) = reader.next().unwrap() {
            if let Some(last) = &last {
                assert!(row.key > *last);
            }
            if row.key.0 == 15_000 {
                assert_eq!(row.events, 4);
            }
            last = Some(row.key);
        }
    }

    #[test]
    fn prevalence_rows_merge_exactly() {
        let dir = tempfile::tempdir().unwrap();
        let row = |hosts: Vec<u64>, first, last, count| PrevalenceRow {
            key: ("ip".into(), "s".into(), "10.0.0.1".into(), 1),
            hosts,
            is_private: 1,
            first_seen: first,
            last_seen: last,
            daily_count: count,
        };
        let a = dir.path().join("a.parquet");
        let b = dir.path().join("b.parquet");
        write_sorted(vec![row(vec![1, 5], 10, 20, 2)], &a).unwrap();
        write_sorted(vec![row(vec![2, 5], 5, 15, 3)], &b).unwrap();
        let out = dir.path().join("o.parquet");
        merge_sorted::<PrevalenceRow>(&[&a, &b], &out).unwrap();
        let merged = SortedReader::<PrevalenceRow>::open(&out).unwrap().next().unwrap().unwrap();
        assert_eq!(merged, row(vec![1, 2, 5], 5, 20, 5));
    }
    #[test]
    fn only_compact_findings_make_risk_partials_and_merges_preserve_them() {
        let dir = tempfile::tempdir().unwrap();
        let timestamp = chrono::DateTime::parse_from_rfc3339("2026-09-26T12:00:00Z").unwrap();
        let time_us = timestamp.timestamp_micros();
        let compact = CompactFinding {
            id: "finding-1".into(),
            timestamp_us: time_us,
            entity: "alice".into(),
            stamped_entity_type: "user".into(),
            risk_score: 75,
            rule_id: "rule-1".into(),
            rule_name: "Rule 1".into(),
            severity: "high".into(),
            origin_source_types: vec!["endpoint".into()],
            mitre_tactics: vec![],
        };
        let finding = json!({
            "time": timestamp.to_rfc3339(), "class_uid": 2004,
            "metadata": {"uid": "finding-1", "log_source": "findings"},
            "unmapped": {"nano_compact_finding": serde_json::to_string(&compact).unwrap(),
                "nano_finding_outbox_trusted": "v1"}
        });
        let event_with_risk_field = json!({
            "time": timestamp.to_rfc3339(), "class_uid": 1007, "risk_score": 99,
            "metadata": {"uid": "event-1", "log_source": "endpoint"}
        });
        let values = [&finding, &event_with_risk_field];
        let schema = Arc::new(crate::part_ingest::schema::infer_schema(&values).unwrap());
        let batch = crate::part_ingest::schema::decode(schema, &values).unwrap();
        let ordinary = dir.path().join("untrusted-source-part");
        let mut ordinary_partials = RowPartials::new();
        ordinary_partials.add_batch(&batch).unwrap();
        ordinary_partials.write(&ordinary).unwrap();
        assert!(!ordinary
            .join(crate::parts::format::PARTIAL_RISK_FILE)
            .exists());
        let mut partials = RowPartials::new_findings();
        assert!(
            partials.add_batch(&batch).is_err(),
            "a finding part refuses ordinary source events"
        );
        let mut partials = RowPartials::new_findings();
        let finding_schema =
            Arc::new(crate::part_ingest::schema::infer_schema(&[&finding]).unwrap());
        partials
            .add_batch(&crate::part_ingest::schema::decode(finding_schema, &[&finding]).unwrap())
            .unwrap();
        let first = dir.path().join("finding-part");
        let written = partials.write(&first).unwrap();
        assert!(written.iter().any(|(kind, _, rows)| *kind
            == crate::parts::provenance::PartialKind::Risk
            && *rows == 1));
        let risk = SortedReader::<RiskPartialRow>::open(
            &first.join(crate::parts::format::PARTIAL_RISK_FILE),
        )
        .unwrap()
        .next()
        .unwrap()
        .unwrap();
        assert_eq!(
            (risk.entity.as_str(), risk.findings, risk.risk_score_sum),
            ("alice", 1, 75)
        );
        let second = dir.path().join("ordinary-part");
        let mut other = RowPartials::new();
        other
            .add_batch(
                &crate::part_ingest::schema::decode(
                    Arc::new(
                        crate::part_ingest::schema::infer_schema(&[&event_with_risk_field])
                            .unwrap(),
                    ),
                    &[&event_with_risk_field],
                )
                .unwrap(),
            )
            .unwrap();
        other.write(&second).unwrap();
        assert!(!second
            .join(crate::parts::format::PARTIAL_RISK_FILE)
            .exists());
        let merged = dir.path().join("merged");
        let files = merge_partials(&[&first, &second], &merged).unwrap();
        assert!(files.iter().any(|(kind, _, rows)| *kind
            == crate::parts::provenance::PartialKind::Risk
            && *rows == 1));
    }

    #[test]
    fn legacy_host_cap_is_rejected_before_stamping() {
        let row = PrevalenceRow {
            key: ("ip".into(), "source".into(), "8.8.8.8".into(), 1),
            hosts: vec![1, 2],
            is_private: 0,
            first_seen: 1,
            last_seen: 2,
            daily_count: 2,
        };
        let batch = PrevalenceRow::to_batch(&[row]).unwrap();
        let mut columns = batch.columns().to_vec();
        columns[5] = Arc::new(UInt16Array::from(vec![65]));
        let legacy = RecordBatch::try_new(batch.schema(), columns).unwrap();
        assert!(PrevalenceRow::from_batch(&legacy).is_err());
    }

    fn identity_part(dir: &Path, events: &[serde_json::Value], cap: usize) -> std::path::PathBuf {
        let refs = events.iter().collect::<Vec<_>>();
        let schema = Arc::new(crate::part_ingest::schema::infer_schema(&refs).unwrap());
        let batch = crate::part_ingest::schema::decode(schema, &refs).unwrap();
        let mut partials = RowPartials::new().with_identity(cap);
        partials.add_batch(&batch).unwrap();
        partials.write(dir).unwrap();
        dir.join(crate::parts::format::PARTIAL_ENTITY_RANGES_FILE)
    }

    fn identity_rows(path: &Path) -> Vec<EntityRangeRow> {
        let mut reader = SortedReader::<EntityRangeRow>::open(path).unwrap();
        let mut out = Vec::new();
        while let Some(row) = reader.next().unwrap() {
            if row.key.0 == crate::identity_observations::IDENTITY_PATH {
                out.push(row);
            }
        }
        out
    }

    #[test]
    fn identity_observations_ride_the_entity_partial_and_merge_exactly() {
        let dir = tempfile::tempdir().unwrap();
        let event = |t: &str, uid: &str, ip: &str, host: &str| json!({"time": t, "metadata": {"uid": uid, "log_source": "windows_sysmon"},
            "src_endpoint": {"ip": ip, "hostname": host}, "actor": {"user": {"name": "jhernandez"}}});
        let a = identity_part(&dir.path().join("a"), &[
            event("2026-09-26T00:00:00Z", "a1", "10.1.3.7", "ws-it-052.corp.local"),
            event("2026-09-26T00:10:00Z", "a2", "10.1.3.7", "ws-it-052.corp.local"),
            event("2026-09-26T00:11:00Z", "a3", "8.8.8.8", "ws-it-052.corp.local"),
        ], crate::identity_observations::INGEST_BYTES_CAP);
        let b = identity_part(&dir.path().join("b"), &[
            event("2026-09-26T00:20:00Z", "b1", "10.1.3.7", "ws-it-052.corp.local"),
        ], crate::identity_observations::INGEST_BYTES_CAP);
        let rows = identity_rows(&a);
        assert_eq!(rows.len(), 2, "coverage + one hourly observation: {rows:?}");
        assert_eq!((rows[0].key.1.as_str(), rows[0].events), ("", 3), "coverage counts every row");
        let (observation, _) = crate::identity_observations::decode_value(&rows[1].key.1).unwrap();
        assert_eq!((observation.hostname.as_str(), observation.user.as_str()), ("ws-it-052", "jhernandez"));
        assert_eq!(rows[1].events, 2);

        let out = dir.path().join("merged.parquet");
        merge_sorted::<EntityRangeRow>(&[&a, &b], &out).unwrap();
        let merged = identity_rows(&out);
        assert_eq!(merged.len(), 2);
        assert_eq!(merged[0].events, 4, "merged coverage = 3 + 1 rows");
        assert_eq!(merged[1].events, 3, "same (ip, hour, host, user, source) combined");
        assert_eq!(merged[1].last_time - merged[1].first_time, 20 * 60 * 1_000_000);
    }

    #[test]
    fn a_part_over_the_identity_cap_is_left_unindexed_not_partial() {
        let dir = tempfile::tempdir().unwrap();
        let events = (0..200)
            .map(|i| json!({"time": "2026-09-26T00:00:00Z", "metadata": {"uid": format!("u{i}"), "log_source": "s"},
                "src_endpoint": {"ip": format!("10.0.0.{i}"), "hostname": format!("host-{i}")}}))
            .collect::<Vec<_>>();
        let path = identity_part(dir.path(), &events, 2_048);
        assert!(identity_rows(&path).is_empty(), "no observation rows and no coverage row");
    }

    fn prevalence_rows(events: &[serde_json::Value]) -> Vec<PrevalenceRow> {
        let refs = events.iter().collect::<Vec<_>>();
        let schema = Arc::new(crate::part_ingest::schema::infer_schema(&refs).unwrap());
        let batch = crate::part_ingest::schema::decode(schema, &refs).unwrap();
        let mut partials = RowPartials::new();
        partials.add_batch(&batch).unwrap();
        partials.prevalence.into_values().collect()
    }

    /// NAN-3694: the asset identities get blooms but no entity-range rows;
    /// a reader answers an inside part from this partial alone, and parts
    /// written before them carry none.
    #[test]
    fn entity_range_rows_cover_only_entity_range_paths() {
        let event = json!({"time": "2026-09-26T00:00:00Z", "metadata": {"uid": "u1", "log_source": "s"},
            "src_endpoint": {"ip": "10.1.3.7"}, "device": {"ip": "10.1.4.63", "uid": "dev-1"},
            "user": {"name": "jhernandez", "email_addr": "jh@corp.local"},
            "actor": {"user": {"email_addr": "jh@corp.local"}, "process": {"user": {"name": "CORP\\jh"}}}});
        let refs = [&event];
        let schema = Arc::new(crate::part_ingest::schema::infer_schema(&refs).unwrap());
        let batch = crate::part_ingest::schema::decode(schema, &refs).unwrap();
        let mut partials = RowPartials::new();
        partials.add_batch(&batch).unwrap();
        let paths = partials.entities.keys().map(|(path, _)| path.as_str()).collect::<std::collections::BTreeSet<_>>();
        assert_eq!(paths, ["src_endpoint.ip", "user.name"].into_iter().collect(), "{paths:?}");
        for path in ["device.ip", "device.uid", "user.email_addr", "actor.user.email_addr", "actor.process.user.name"] {
            assert!(crate::parts::format::BLOOM_PATHS.contains(&path), "{path} has a bloom");
            assert!(!crate::parts::format::ENTITY_RANGE_PATHS.contains(&path), "{path} has no range rows");
        }
        for path in crate::parts::format::ENTITY_RANGE_PATHS {
            assert!(crate::parts::format::BLOOM_PATHS.contains(path) && *path != UID_PATH, "{path}");
        }
    }

    fn row<'a>(rows: &'a [PrevalenceRow], kind: &str, entity: &str) -> Option<&'a PrevalenceRow> {
        rows.iter().find(|row| row.key.0 == kind && row.key.2 == entity)
    }

    /// NAN-3213 (10.1.3.149 showed "1,000+ hosts"): a workstation source IP is
    /// observed by the workstation, not by every destination it contacted.
    #[test]
    fn source_ip_host_count_is_observing_devices_not_destinations() {
        let events = (0..50)
            .map(|i| json!({"time":"2026-09-26T00:00:00Z","metadata":{"uid":format!("u{i}"),"log_source":"s"},
                "src_endpoint":{"ip":"10.1.3.149","hostname":"ws-legal-066.corp.local"},
                "dst_endpoint":{"ip":format!("203.0.113.{i}"),"hostname":format!("dest-{i}.example.com")}}))
            .collect::<Vec<_>>();
        let rows = prevalence_rows(&events);
        let src = row(&rows, "ip", "10.1.3.149").unwrap();
        assert_eq!(src.hosts, vec![host_fingerprint("ws-legal-066.corp.local")], "one observing device, not 50 peers");
        // Destinations are observed by the same single workstation.
        assert_eq!(row(&rows, "ip", "203.0.113.7").unwrap().hosts, src.hosts);
        assert_eq!(row(&rows, "domain", "dest-7.example.com").unwrap().hosts, src.hosts);

        // Two devices sharing an IP (DHCP churn) are two observers; device wins
        // over the endpoint hostname, and a bare network row falls back to its
        // source IP rather than to its destination.
        let rows = prevalence_rows(&[
            json!({"time":"2026-09-26T00:00:00Z","metadata":{"uid":"a","log_source":"s"},
                "device":{"hostname":"ws-a"},"src_endpoint":{"ip":"10.0.0.9","hostname":"ignored"},"dst_endpoint":{"ip":"8.8.8.8"}}),
            json!({"time":"2026-09-26T00:00:01Z","metadata":{"uid":"b","log_source":"s"},
                "device":{"hostname":"ws-b"},"src_endpoint":{"ip":"10.0.0.9"},"dst_endpoint":{"ip":"8.8.8.8"}}),
            json!({"time":"2026-09-26T00:00:02Z","metadata":{"uid":"c","log_source":"s"},
                "src_endpoint":{"ip":"10.0.0.10"},"dst_endpoint":{"ip":"8.8.8.8","hostname":"dns.google"}}),
        ]);
        assert_eq!(row(&rows, "ip", "10.0.0.9").unwrap().hosts.len(), 2);
        let mut expected = vec![host_fingerprint("ws-a"), host_fingerprint("ws-b"), host_fingerprint("10.0.0.10")];
        expected.sort_unstable();
        assert_eq!(row(&rows, "ip", "8.8.8.8").unwrap().hosts, expected);
        assert_eq!(row(&rows, "ip", "10.0.0.10").unwrap().hosts, vec![host_fingerprint("10.0.0.10")]);
    }

    /// NAN-3213 (ws-legal-066.corp.local showed as a 1-host "subdomain"): the
    /// event's own hostname is the observer, never a domain artifact; real DNS /
    /// URL / destination names still are.
    #[test]
    fn hostnames_are_observers_not_domains() {
        let rows = prevalence_rows(&[
            json!({"time":"2026-09-26T00:00:00Z","metadata":{"uid":"a","log_source":"s"},
                "device":{"hostname":"ws-legal-066.corp.local"},
                "src_endpoint":{"ip":"10.1.3.149","hostname":"ws-legal-066.corp.local"},
                "dst_endpoint":{"hostname":"fileserver.corp.local"},
                "query":{"hostname":"a.b.login.example.com"},
                "url":{"hostname":"cdn.example.net"}}),
        ]);
        assert!(row(&rows, "domain", "ws-legal-066.corp.local").is_none(), "{rows:?}");
        assert!(row(&rows, "domain", "fileserver.corp.local").is_none(), "internal TLD is not a domain");
        let observer = vec![host_fingerprint("ws-legal-066.corp.local")];
        assert_eq!(row(&rows, "domain", "a.b.login.example.com").unwrap().hosts, observer);
        assert_eq!(row(&rows, "domain", "cdn.example.net").unwrap().hosts, observer);
        assert!(rows.iter().filter(|r| r.key.0 == "domain").all(|r| !r.hosts.contains(&host_fingerprint(&r.key.2))),
            "no domain is observed by itself");
    }

    /// NAN-3226: a tenant's internal suffixes (here `prod`) are never domain
    /// artifacts, on label boundaries, unioned with the built-ins; another
    /// tenant's part (different list) still indexes the same name.
    #[test]
    fn tenant_internal_suffixes_are_not_domain_artifacts() {
        let events = vec![json!({"time":"2026-09-26T00:00:00Z","metadata":{"uid":"a","log_source":"s"},
            "device":{"hostname":"ws-1"},
            "dst_endpoint":{"hostname":"db1.prod"},
            "query":{"hostname":"api.myprod.com"},
            "url":{"hostname":"fs.corp.local"}})];
        let refs = events.iter().collect::<Vec<_>>();
        let schema = Arc::new(crate::part_ingest::schema::infer_schema(&refs).unwrap());
        let batch = crate::part_ingest::schema::decode(schema, &refs).unwrap();
        let rows_with = |internal: nanosiem_core::internal_domains::InternalDomains| {
            let mut partials = RowPartials::new().with_internal_domains(internal);
            partials.add_batch(&batch).unwrap();
            partials.prevalence.into_values().collect::<Vec<_>>()
        };
        let tenant_a = rows_with(nanosiem_core::internal_domains::InternalDomains::with_tenant(["prod"]));
        assert!(row(&tenant_a, "domain", "db1.prod").is_none(), "{tenant_a:?}");
        assert!(row(&tenant_a, "domain", "fs.corp.local").is_none(), "built-ins stay");
        assert!(row(&tenant_a, "domain", "api.myprod.com").is_some(), "label boundary");
        let tenant_b = rows_with(nanosiem_core::internal_domains::InternalDomains::with_tenant(["cloud"]));
        assert!(row(&tenant_b, "domain", "db1.prod").is_some(), "tenant B does not inherit tenant A's list");
    }

    /// Prevalence rows stay keyed by the event's own log-source scope; the
    /// observer change does not merge rows across scopes (per-tenant parts
    /// are written per tenant, so this is the finest boundary inside one).
    #[test]
    fn prevalence_scope_isolation_is_unchanged() {
        let rows = prevalence_rows(&[
            json!({"time":"2026-09-26T00:00:00Z","metadata":{"uid":"a","log_source":"Alpha"},
                "device":{"hostname":"ws-a"},"dst_endpoint":{"ip":"8.8.8.8"}}),
            json!({"time":"2026-09-26T00:00:01Z","metadata":{"uid":"b","log_source":"beta"},
                "device":{"hostname":"ws-b"},"dst_endpoint":{"ip":"8.8.8.8"}}),
        ]);
        let scoped = rows.iter().filter(|r| r.key.2 == "8.8.8.8").map(|r| (r.key.1.as_str(), r.hosts.clone())).collect::<Vec<_>>();
        assert_eq!(scoped.len(), 2);
        assert!(scoped.contains(&("alpha", vec![host_fingerprint("ws-a")])));
        assert!(scoped.contains(&("beta", vec![host_fingerprint("ws-b")])));
    }
}
