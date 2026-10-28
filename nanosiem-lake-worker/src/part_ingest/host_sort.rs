// SPDX-License-Identifier: AGPL-3.0-or-later

//! Host-sorted endpoint hour files (NAN-3412).
//!
//! Every endpoint file of an `h` part (sysmon, Windows event log) holds every
//! one of a tenant's hosts, scattered through the file in time order, so the
//! row-group statistics of `device.hostname` span the whole host range and a
//! single-host query keeps most row groups (live on the load-test tenant: 34-36 of 54).
//!
//! Behind [`ENABLE_ENV`] (default off), the sealed-hour merge writes the
//! endpoint families' files ordered by `(device.hostname, time, metadata.uid)`
//! in small row groups instead, so each host's rows sit in one or two row
//! groups and the existing min/max statistics (and blooms) prune the rest.
//!
//! The sort is external and bounded: the merge stream is still produced in
//! global `(time, uid)` order (dedup and the logical Merkle root are
//! unchanged), the family spool counts rows per host, and at the end each
//! family stream is routed into host-range buckets of at most about
//! `bucket_rows` rows (a host above that is a bucket of its own, already in
//! `(time, uid)` order, and streams through without being held). Only
//! multi-host buckets are loaded and sorted in memory.
//!
//! Every such file carries [`ROW_ORDER_KEY`] in its Parquet footer (covered by
//! the file's signed digest). Everything else keeps assuming `(time, uid)`
//! order, so a merge that reads a host-sorted file back (a late-data rewrite,
//! reindex or sidecar backfill of a sealed hour) first restores it to time
//! order with [`restore_time_order`], the same bounded bucket sort keyed on
//! time.

use anyhow::{ensure, Context, Result};
use arrow_array::{Array, ArrayRef, RecordBatch, StringArray, StructArray, UInt32Array};
use arrow_ipc::{reader::StreamReader, writer::StreamWriter};
use arrow_schema::SchemaRef;
use std::collections::BTreeMap;
use std::fs::File;
use std::path::{Path, PathBuf};

use super::writer::uid_strings;
use crate::generation::event_time_us_from_array;

/// Cell switch. Unset, `0`, or anything unrecognized: off (byte-identical
/// output). `1`/`true`: on with [`DEFAULT_GROUP_ROWS`]-row groups; one of
/// [`GROUP_ROW_CHOICES`]: on with that group size.
pub const ENABLE_ENV: &str = "NANO_LAKE_ENDPOINT_HOST_SORT";
/// Row-group rows of a host-sorted file unless the switch names another.
pub const DEFAULT_GROUP_ROWS: usize = 8_192;
/// Accepted explicit group sizes.
pub const GROUP_ROW_CHOICES: [usize; 4] = [4_096, 8_192, 16_384, 32_768];
/// `metadata.log_source` values of the endpoint streams: Sysmon and the
/// Windows event log (Security).
pub const ENDPOINT_SOURCES: &[&str] = &["windows_sysmon", "windows_event"];
/// The sort's leading column.
pub const HOST_PATH: &str = "device.hostname";
/// Parquet footer key naming a file's row order when it is not `(time, uid)`.
pub const ROW_ORDER_KEY: &str = "nano.part.row_order";
/// [`ROW_ORDER_KEY`] value of a host-sorted file.
pub const HOST_ROW_ORDER: &str = "device.hostname,time,metadata.uid";

/// Row-group rows for host-sorted endpoint files, or `None` when off.
pub fn group_rows() -> Option<usize> {
    group_rows_from(std::env::var(ENABLE_ENV).ok().as_deref())
}

pub fn group_rows_from(value: Option<&str>) -> Option<usize> {
    let value = value?.trim();
    if value == "1" || value.eq_ignore_ascii_case("true") {
        return Some(DEFAULT_GROUP_ROWS);
    }
    value.parse::<usize>().ok().filter(|rows| GROUP_ROW_CHOICES.contains(rows))
}

pub fn is_endpoint_source(source: &str) -> bool {
    ENDPOINT_SOURCES.contains(&source)
}

/// `device.hostname` of every row as Utf8; null where `device` or its
/// `hostname` is null or absent.
pub fn host_strings(batch: &RecordBatch) -> Result<StringArray> {
    let Some(device) = batch.column_by_name("device") else {
        return Ok(StringArray::new_null(batch.num_rows()));
    };
    let device = device.as_any().downcast_ref::<StructArray>().context("device is not a struct")?;
    let Some(hostname) = device.column_by_name("hostname") else {
        return Ok(StringArray::new_null(batch.num_rows()));
    };
    let cast = arrow_cast::cast(hostname.as_ref(), &arrow_schema::DataType::Utf8)?;
    let values = cast.as_any().downcast_ref::<StringArray>().context("hostname cast")?;
    if device.null_count() == 0 {
        return Ok(values.clone());
    }
    Ok((0..values.len()).map(|row| (!device.is_null(row) && !values.is_null(row)).then(|| values.value(row))).collect())
}

/// Writer properties of a local `(time, uid)` restore of `source`: cheap
/// zstd, and the source footer's key-value metadata minus [`ROW_ORDER_KEY`]
/// (the copy is time-ordered) and the Arrow schema (the writer adds its own).
/// The rest must survive: NAN-4664's indicator marker is how a merge knows to
/// drop the derived `nano_ioc_*` columns; without it every batch misses the
/// merge schema and round-trips through JSON in `align` (NAN-4688).
pub fn restore_properties(source: &parquet::file::metadata::FileMetaData) -> Result<parquet::file::properties::WriterProperties> {
    let kept = source.key_value_metadata().map(|pairs| pairs.iter()
        .filter(|pair| pair.key != ROW_ORDER_KEY && pair.key != "ARROW:schema").cloned().collect::<Vec<_>>())
        .filter(|pairs| !pairs.is_empty());
    Ok(parquet::file::properties::WriterProperties::builder()
        // Local scratch only: the cheapest zstd keeps the copy near the
        // signed file's size on disk.
        .set_compression(parquet::basic::Compression::ZSTD(parquet::basic::ZstdLevel::try_new(1)?))
        .set_max_row_group_row_count(Some(crate::parts::format::ROW_GROUP_ROWS))
        .set_key_value_metadata(kept)
        .build())
}

/// The value of `ROW_ORDER_KEY` in a Parquet file's footer, if any.
pub fn file_row_order(path: &Path) -> Result<Option<String>> {
    use parquet::file::reader::{FileReader, SerializedFileReader};
    let reader = SerializedFileReader::new(File::open(path)?)?;
    Ok(reader.metadata().file_metadata().key_value_metadata()
        .and_then(|pairs| pairs.iter().find(|pair| pair.key == ROW_ORDER_KEY).and_then(|pair| pair.value.clone())))
}

/// Whether a data file is host-sorted (anything but `(time, uid)` order).
pub fn is_host_sorted(path: &Path) -> Result<bool> {
    Ok(file_row_order(path)?.is_some())
}

/// Rows per `device.hostname` of one family stream.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HostCounts {
    /// Rows without a hostname (they sort first).
    pub nulls: u64,
    pub hosts: BTreeMap<String, u64>,
}

impl HostCounts {
    pub fn add(&mut self, host: Option<&str>) {
        match host {
            None => self.nulls += 1,
            Some(host) => match self.hosts.get_mut(host) {
                Some(count) => *count += 1,
                None => { self.hosts.insert(host.to_owned(), 1); }
            },
        }
    }

    pub fn rows(&self) -> u64 {
        self.nulls + self.hosts.values().sum::<u64>()
    }
}

/// Contiguous host ranges, each holding about `bucket_rows` rows; a host at
/// or above that is a bucket of its own.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostBuckets {
    /// Lowest host of each bucket (`None`: null hostname, sorts first).
    lower: Vec<Option<String>>,
    /// Whether the bucket holds a single host (already `(time, uid)` order).
    single: Vec<bool>,
}

impl HostBuckets {
    pub fn plan(counts: &HostCounts, bucket_rows: usize) -> Self {
        let bucket_rows = bucket_rows.max(1) as u64;
        let (mut lower, mut single) = (Vec::new(), Vec::new());
        let mut open = 0_u64;
        let nulls = (counts.nulls > 0).then_some((None, &counts.nulls));
        for (host, rows) in nulls.into_iter().chain(counts.hosts.iter().map(|(host, rows)| (Some(host), rows))) {
            let host = host.cloned();
            if *rows >= bucket_rows {
                lower.push(host);
                single.push(true);
                open = 0;
                continue;
            }
            if open == 0 || open + rows > bucket_rows {
                lower.push(host);
                single.push(false);
                open = 0;
            }
            open += rows;
        }
        Self { lower, single }
    }

    pub fn len(&self) -> usize {
        self.lower.len()
    }

    pub fn is_empty(&self) -> bool {
        self.lower.is_empty()
    }

    fn bucket_of(&self, host: Option<&str>) -> usize {
        self.lower.partition_point(|lower| lower.as_deref() <= host).saturating_sub(1)
    }
}

/// Spill `batches` into `buckets` IPC streams under `dir` by `bucket_of`
/// (row order within a bucket is the input order). Returns each bucket's
/// stream path, `None` for an empty bucket.
pub(super) fn spill<I, F>(dir: &Path, schema: &SchemaRef, batches: I, buckets: usize, mut bucket_of: F) -> Result<Vec<Option<PathBuf>>>
where
    I: Iterator<Item = Result<RecordBatch>>,
    F: FnMut(&RecordBatch) -> Result<Vec<usize>>,
{
    let mut writers: Vec<Option<(PathBuf, StreamWriter<File>)>> = (0..buckets).map(|_| None).collect();
    for batch in batches {
        let batch = batch?;
        if batch.num_rows() == 0 {
            continue;
        }
        super::merge_quota::charge_checked(batch.num_rows() as u64, super::merge_quota::batch_bytes(&batch))?;
        let assigned = bucket_of(&batch)?;
        let mut rows: BTreeMap<usize, Vec<u32>> = BTreeMap::new();
        for (row, bucket) in assigned.into_iter().enumerate() {
            rows.entry(bucket).or_default().push(u32::try_from(row)?);
        }
        for (bucket, indices) in rows {
            ensure!(bucket < buckets, "bucket out of range");
            let slot = &mut writers[bucket];
            if slot.is_none() {
                let path = dir.join(format!("{bucket}.arrow"));
                *slot = Some((path.clone(), StreamWriter::try_new(File::create(&path)?, schema)?));
            }
            let selected = if indices.len() == batch.num_rows() { batch.clone() } else {
                let indices = UInt32Array::from(indices);
                let columns = batch.columns().iter().map(|column| arrow_select::take::take(column.as_ref(), &indices, None))
                    .collect::<std::result::Result<Vec<_>, _>>()?;
                RecordBatch::try_new(batch.schema(), columns)?
            };
            slot.as_mut().expect("opened").1.write(&selected)?;
        }
    }
    writers.into_iter().map(|slot| slot.map(|(path, mut writer)| { writer.finish()?; Ok(path) }).transpose()).collect()
}

pub(super) fn read_stream(path: &Path) -> Result<impl Iterator<Item = Result<RecordBatch>>> {
    Ok(StreamReader::try_new(File::open(path)?, None)?.map(|batch| batch.map_err(anyhow::Error::from)))
}

/// Load a whole bucket, sort it by `columns(batch)` and hand it to `sink`.
fn sort_bucket<C, S>(path: &Path, schema: &SchemaRef, columns: C, sink: &mut S) -> Result<()>
where
    C: Fn(&RecordBatch) -> Result<Vec<ArrayRef>>,
    S: FnMut(&RecordBatch) -> Result<()>,
{
    use arrow_ord::sort::{lexsort_to_indices, SortColumn};
    let mut batches = Vec::new();
    let mut bytes = 0_u64;
    for batch in read_stream(path)? {
        let batch = batch?;
        super::merge_quota::charge_checked(batch.num_rows() as u64, super::merge_quota::batch_bytes(&batch))?;
        bytes = bytes.saturating_add(super::merge_quota::batch_bytes(&batch));
        batches.push(batch);
    }
    // Check while collecting, and reserve the whole concatenated bucket's
    // copies before concat/sort. A check after collect cannot stop its peak.
    super::merge_quota::memory_guard_bytes(bytes)?;
    let batch = arrow_select::concat::concat_batches(schema, &batches)?;
    drop(batches);
    if batch.num_rows() == 0 {
        return Ok(());
    }
    let keys = columns(&batch)?;
    let indices = lexsort_to_indices(&keys.into_iter().map(|values| SortColumn { values, options: None }).collect::<Vec<_>>(), None)?;
    let sorted = batch.columns().iter().map(|column| arrow_select::take::take(column.as_ref(), &indices, None))
        .collect::<std::result::Result<Vec<_>, _>>()?;
    drop(batch);
    let sorted = RecordBatch::try_new(schema.clone(), sorted)?;
    let mut offset = 0;
    while offset < sorted.num_rows() {
        let take = 4_096.min(sorted.num_rows() - offset);
        sink(&sorted.slice(offset, take))?;
        offset += take;
    }
    Ok(())
}

fn time_column(batch: &RecordBatch) -> Result<ArrayRef> {
    Ok(batch.column_by_name("time").context("batch has no time")?.clone())
}

/// Write the rows of a `(time, uid)`-ordered family stream to `sink` in
/// `(device.hostname, time, uid)` order. `counts` are the stream's rows per
/// host. Spill files live under `work_dir` and are removed on return.
pub fn host_sort_stream<S>(work_dir: &Path, schema: &SchemaRef, stream: &Path, counts: &HostCounts, bucket_rows: usize, mut sink: S) -> Result<()>
where
    S: FnMut(&RecordBatch) -> Result<()>,
{
    let plan = HostBuckets::plan(counts, bucket_rows);
    if plan.is_empty() {
        return Ok(());
    }
    let dir = tempfile::Builder::new().prefix(".host-sort-").tempdir_in(work_dir)?;
    let buckets = spill(dir.path(), schema, read_stream(stream)?, plan.len(), |batch| {
        let hosts = host_strings(batch)?;
        Ok((0..batch.num_rows()).map(|row| plan.bucket_of((!hosts.is_null(row)).then(|| hosts.value(row)))).collect())
    })?;
    for (bucket, path) in buckets.into_iter().enumerate() {
        let Some(path) = path else { continue };
        if plan.single[bucket] {
            // One host: the input order, `(time, uid)`, is already the sort order.
            for batch in read_stream(&path)? {
                let batch = batch?;
                super::merge_quota::charge_checked(batch.num_rows() as u64, super::merge_quota::batch_bytes(&batch))?;
                sink(&batch)?;
            }
        } else {
            sort_bucket(&path, schema, |batch| Ok(vec![
                std::sync::Arc::new(host_strings(batch)?) as ArrayRef,
                time_column(batch)?,
                std::sync::Arc::new(uid_strings(batch)?) as ArrayRef,
            ]), &mut sink)?;
        }
        std::fs::remove_file(&path)?;
    }
    Ok(())
}

/// Rewrite a host-sorted data file `source` as a `(time, uid)`-ordered
/// local Parquet file `target` (a merge input only, never
/// published). Bounded like [`host_sort_stream`]: a narrow pass reads the
/// time column to cut time buckets of about `bucket_rows` rows (rows that
/// share one timestamp stay in one bucket), the rows are spilled by bucket,
/// and each bucket is sorted on its own.
pub fn restore_time_order(work_dir: &Path, source: &Path, target: &Path, bucket_rows: usize) -> Result<u64> {
    use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;
    use parquet::arrow::{ArrowWriter, ProjectionMask};
    let builder = ParquetRecordBatchReaderBuilder::try_new(File::open(source)?)?;
    let schema = builder.schema().clone();
    let properties = restore_properties(builder.metadata().file_metadata())?;
    let time_leaf = (0..builder.parquet_schema().num_columns())
        .find(|i| builder.parquet_schema().column(*i).path().string() == "time")
        .context("host-sorted file has no time column")?;
    let mask = ProjectionMask::leaves(builder.parquet_schema(), [time_leaf]);
    let mut times = Vec::new();
    for batch in builder.with_projection(mask).with_batch_size(65_536).build()? {
        let batch = batch?;
        let time = time_column(&batch)?;
        for row in 0..batch.num_rows() {
            times.push(event_time_us_from_array(time.as_ref(), row).context("row has no time")?);
        }
    }
    let rows = times.len() as u64;
    times.sort_unstable();
    let bucket_rows = bucket_rows.max(1);
    let mut lower: Vec<i64> = Vec::new();
    for chunk in times.chunks(bucket_rows) {
        if lower.last().is_none_or(|last| chunk[0] > *last) {
            lower.push(chunk[0]);
        }
    }
    drop(times);
    let mut writer = ArrowWriter::try_new(File::create(target)?, schema.clone(), Some(properties))?;
    let mut written = 0_u64;
    if !lower.is_empty() {
        let dir = tempfile::Builder::new().prefix(".time-order-").tempdir_in(work_dir)?;
        let reader = ParquetRecordBatchReaderBuilder::try_new(File::open(source)?)?.with_batch_size(4_096).build()?;
        let buckets = spill(dir.path(), &schema, reader.map(|batch| batch.map_err(anyhow::Error::from)), lower.len(), |batch| {
            let time = time_column(batch)?;
            (0..batch.num_rows()).map(|row| {
                let time = event_time_us_from_array(time.as_ref(), row).context("row has no time")?;
                Ok(lower.partition_point(|lower| *lower <= time).saturating_sub(1))
            }).collect()
        })?;
        for path in buckets.into_iter().flatten() {
            sort_bucket(&path, &schema, |batch| Ok(vec![time_column(batch)?, std::sync::Arc::new(uid_strings(batch)?) as ArrayRef]), &mut |batch| {
                written += batch.num_rows() as u64;
                writer.write(batch)?;
                Ok(())
            })?;
            std::fs::remove_file(&path)?;
        }
    }
    writer.close()?;
    ensure!(written == rows, "time-order restore lost rows");
    Ok(rows)
}

#[cfg(test)]
#[path = "host_sort_native_tests.rs"]
mod native;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_guard_stops_a_sort_bucket_before_collecting_the_remaining_stream() {
        use super::super::merge_quota::{is_memory_pressure, memory_guard_scope, MEMORY_PROBE_FOR_TEST};
        fn full() -> Option<(u64, u64)> { Some((99, 100)) }
        let batch = RecordBatch::try_from_iter([("time", std::sync::Arc::new(arrow_array::Int64Array::from(vec![1_i64])) as ArrayRef)]).unwrap();
        let mut ipc = Vec::new();
        {
            let mut writer = StreamWriter::try_new(&mut ipc, &batch.schema()).unwrap();
            writer.write(&batch).unwrap();
            // No end marker: the next message below is deliberately invalid.
        }
        ipc.extend_from_slice(&[0xff; 8]);
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bucket.arrow");
        std::fs::write(&path, ipc).unwrap();
        MEMORY_PROBE_FOR_TEST.set(Some(full));
        let result = {
            let _scope = memory_guard_scope();
            sort_bucket(&path, &batch.schema(), |_| panic!("must stop before sorting"), &mut |_| panic!("must not emit"))
        };
        MEMORY_PROBE_FOR_TEST.set(None);
        assert!(is_memory_pressure(&result.unwrap_err()), "stop at the first batch, before reading the invalid tail");
    }

    #[test]
    fn switch_is_default_off_and_bounded() {
        assert_eq!(group_rows_from(None), None);
        assert_eq!(group_rows_from(Some("")), None);
        assert_eq!(group_rows_from(Some("0")), None);
        assert_eq!(group_rows_from(Some("false")), None);
        assert_eq!(group_rows_from(Some("1000")), None);
        assert_eq!(group_rows_from(Some("1")), Some(DEFAULT_GROUP_ROWS));
        assert_eq!(group_rows_from(Some("true")), Some(DEFAULT_GROUP_ROWS));
        assert_eq!(group_rows_from(Some("16384")), Some(16_384));
        assert!(is_endpoint_source("windows_sysmon") && is_endpoint_source("windows_event"));
        assert!(!is_endpoint_source("apache"));
    }

    fn keys(batch: &RecordBatch) -> Vec<(Option<String>, i64, String)> {
        let hosts = host_strings(batch).unwrap();
        let uids = uid_strings(batch).unwrap();
        let time = batch.column_by_name("time").unwrap();
        (0..batch.num_rows()).map(|row| ((!hosts.is_null(row)).then(|| hosts.value(row).to_string()),
            event_time_us_from_array(time.as_ref(), row).unwrap(), uids.value(row).to_string())).collect()
    }

    /// Small buckets: single-host buckets stream through, multi-host buckets
    /// sort, and restoring time order inverts it exactly (including rows
    /// that share a timestamp across buckets' cut points).
    #[test]
    fn bounded_host_sort_and_time_restore_round_trip() {
        use std::sync::Arc;
        use super::super::schema::{decode, infer_schema};
        use super::super::writer::sort_by_time_uid;
        let events = (0..1_000_usize).map(|row| {
            let mut event = serde_json::json!({
                "time": chrono::DateTime::from_timestamp_micros((row / 3) as i64 * 1_000).unwrap().to_rfc3339(),
                "metadata": { "uid": format!("u{row:05}") },
            });
            match row {
                _ if row % 4 == 0 => event["device"] = serde_json::json!({ "hostname": "big" }),
                _ if row % 29 == 0 => {}
                _ => event["device"] = serde_json::json!({ "hostname": format!("h{:02}", row % 41) }),
            }
            event
        }).collect::<Vec<_>>();
        let refs = events.iter().collect::<Vec<_>>();
        let schema = Arc::new(infer_schema(&refs).unwrap());
        let batch = sort_by_time_uid(&decode(schema.clone(), &refs).unwrap()).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let stream = dir.path().join("family.arrow");
        let mut writer = StreamWriter::try_new(File::create(&stream).unwrap(), &schema).unwrap();
        let mut counts = HostCounts::default();
        let input = keys(&batch);
        for offset in (0..batch.num_rows()).step_by(128) {
            writer.write(&batch.slice(offset, 128.min(batch.num_rows() - offset))).unwrap();
        }
        writer.finish().unwrap();
        input.iter().for_each(|(host, _, _)| counts.add(host.as_deref()));
        assert!(HostBuckets::plan(&counts, 50).single.iter().any(|single| *single));
        let mut output = Vec::new();
        let target = dir.path().join("sorted.parquet");
        let mut parquet = parquet::arrow::ArrowWriter::try_new(File::create(&target).unwrap(), schema.clone(), None).unwrap();
        host_sort_stream(dir.path(), &schema, &stream, &counts, 50, |batch| {
            output.extend(keys(batch));
            parquet.write(batch)?;
            Ok(())
        }).unwrap();
        parquet.close().unwrap();
        assert!(output.windows(2).all(|w| w[0] < w[1]), "strict (host, time, uid) order");
        let mut expected = input.clone();
        expected.sort();
        assert_eq!(output, expected);

        let restored = dir.path().join("restored.parquet");
        assert_eq!(restore_time_order(dir.path(), &target, &restored, 37).unwrap(), 1_000);
        let mut back = Vec::new();
        for batch in parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder::try_new(File::open(&restored).unwrap()).unwrap().build().unwrap() {
            back.extend(keys(&batch.unwrap()));
        }
        assert_eq!(back, input, "exact (time, uid) order");
        // Only the published writer tags files; spill files are gone.
        assert_eq!(file_row_order(&restored).unwrap(), None);
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 3);
    }

    #[test]
    fn bucket_plan_isolates_heavy_hosts_and_packs_the_rest() {
        let mut counts = HostCounts::default();
        for (host, rows) in [(None, 2), (Some("a"), 3), (Some("b"), 20), (Some("c"), 4), (Some("d"), 4), (Some("e"), 4)] {
            (0..rows).for_each(|_| counts.add(host));
        }
        assert_eq!(counts.rows(), 37);
        let plan = HostBuckets::plan(&counts, 10);
        assert_eq!(plan.lower, vec![None, Some("b".into()), Some("c".into()), Some("e".into())]);
        assert_eq!(plan.single, vec![false, true, false, false]);
        assert_eq!(plan.bucket_of(None), 0);
        assert_eq!(plan.bucket_of(Some("a")), 0);
        assert_eq!(plan.bucket_of(Some("b")), 1);
        assert_eq!(plan.bucket_of(Some("d")), 2);
        assert_eq!(plan.bucket_of(Some("e")), 3);
        assert_eq!(plan.bucket_of(Some("zzz")), 3);
    }
}
