// SPDX-License-Identifier: AGPL-3.0-or-later

//! Class-sorted hour family files (NAN-4664).
//!
//! An hour part's source family (or overflow) file holds every OCSF class of
//! its rows, interleaved in `(time, uid)` order, so every row group's
//! `class_uid` min/max spans the whole class range and a `class_uid = N` /
//! `class_uid IN (…)` filter skips nothing inside the file. (A dedicated
//! `(source, class)` family file, NAN-3437, already holds one class.)
//!
//! The sealed-hour merge now writes each multi-class family ordered by
//! `(class_uid, time, metadata.uid)`, so each class is one contiguous run of
//! row groups and chDB's Parquet filter push-down
//! (`input_format_parquet_filter_push_down=1` on every event plan) skips the
//! row groups of other classes from their min/max statistics; parts carry
//! page statistics on every column.
//!
//! The sort is external and needs no in-memory sort at all: the merge
//! stream arrives in global `(time, uid)` order, so the rows of ONE class are
//! already in `(time, uid)` order. The family is spilled to one IPC stream per
//! class (null class first, then ascending) and the streams are replayed in
//! class order. Memory is one batch per open spill writer, as for the family
//! spool itself; disk is one more copy of the family's rows under the merge
//! scratch directory.
//!
//! Every such file carries [`super::host_sort::ROW_ORDER_KEY`] =
//! [`CLASS_ROW_ORDER`] in its Parquet footer (covered by the file's signed
//! digest). A merge that reads one back restores `(time, uid)` order first
//! ([`super::host_sort::restore_time_order`] runs on any file that names a
//! row order), exactly as for host-sorted files.

use anyhow::{ensure, Context, Result};
use arrow_array::{Array, Int64Array, RecordBatch};
use arrow_schema::{DataType, SchemaRef};
use std::collections::BTreeMap;
use std::fs::File;
use std::path::Path;

use super::host_sort::{read_stream, spill};

/// [`super::host_sort::ROW_ORDER_KEY`] value of a class-sorted file.
pub const CLASS_ROW_ORDER: &str = "class_uid,time,metadata.uid";
/// The sort's leading column.
pub const CLASS_PATH: &str = "class_uid";

/// `class_uid` of every row as i64; `None` where null, absent, or not an
/// integer (such rows sort first, with the nulls).
pub fn class_keys(batch: &RecordBatch) -> Result<Vec<Option<i64>>> {
    let Some(column) = batch.column_by_name(CLASS_PATH) else {
        return Ok(vec![None; batch.num_rows()]);
    };
    if !column.data_type().is_integer() {
        return Ok(vec![None; batch.num_rows()]);
    }
    let cast = arrow_cast::cast(column.as_ref(), &DataType::Int64)?;
    let values = cast.as_any().downcast_ref::<Int64Array>().context("class_uid cast")?;
    Ok((0..values.len()).map(|row| (!values.is_null(row)).then(|| values.value(row))).collect())
}

/// Rows per `class_uid` of one family stream (`None`: null / non-integer).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ClassCounts {
    pub classes: BTreeMap<Option<i64>, u64>,
}

impl ClassCounts {
    pub fn add_batch(&mut self, keys: &[Option<i64>], rows: impl Iterator<Item = usize>) {
        for row in rows {
            *self.classes.entry(keys[row]).or_default() += 1;
        }
    }

    pub fn rows(&self) -> u64 {
        self.classes.values().sum()
    }

    /// More than one class: class order differs from time order.
    pub fn mixed(&self) -> bool {
        self.classes.len() > 1
    }
}

/// A class with at least this many rows in a family gets row groups of its
/// own: the writer ends the open group before its first row and after its
/// last ([`ClassSortEvent::RunBoundary`]). Smaller classes share groups with
/// their class-order neighbours (their groups' `class_uid` min/max still
/// span only that contiguous class range).
pub const ISOLATED_CLASS_ROWS: u64 = 8_192;

/// Most distinct `class_uid` values a family may hold and be class-sorted:
/// the spill keeps one open file per class. OCSF defines well under this;
/// a family of junk class values keeps the time-sorted layout instead of
/// failing the sorted attempt on file descriptors.
pub const MAX_SORT_CLASSES: usize = 256;

/// What [`class_sort_stream`] hands its sink.
pub enum ClassSortEvent<'a> {
    Rows(&'a RecordBatch),
    /// End the open row group here (a large class starts or ends).
    RunBoundary,
}

/// Write the rows of a `(time, uid)`-ordered family stream to `sink` in
/// `(class_uid, time, uid)` order. `counts` are the stream's rows per class.
/// Spill files live under `work_dir` and are removed on return.
pub fn class_sort_stream<S>(work_dir: &Path, schema: &SchemaRef, stream: &Path, counts: &ClassCounts, mut sink: S) -> Result<u64>
where
    S: FnMut(ClassSortEvent<'_>) -> Result<()>,
{
    let order = counts.classes.keys().copied().collect::<Vec<_>>();
    if order.is_empty() {
        return Ok(0);
    }
    let dir = tempfile::Builder::new().prefix(".class-sort-").tempdir_in(work_dir)?;
    let buckets = spill(dir.path(), schema, read_stream(stream)?, order.len(), |batch| {
        class_keys(batch)?
            .into_iter()
            .map(|class| order.binary_search(&class).map_err(|_| anyhow::anyhow!("class missing from the family counts")))
            .collect()
    })?;
    let mut written = 0_u64;
    for (bucket, path) in buckets.into_iter().enumerate() {
        let Some(path) = path else { continue };
        let isolated = counts.classes.get(&order[bucket]).is_some_and(|rows| *rows >= ISOLATED_CLASS_ROWS);
        if isolated {
            sink(ClassSortEvent::RunBoundary)?;
        }
        let mut bucket_rows = 0_u64;
        // One class: the input order, `(time, uid)`, is already the sort order.
        for batch in read_stream(&path)? {
            let batch = batch?;
            super::merge_quota::charge_checked(batch.num_rows() as u64, super::merge_quota::batch_bytes(&batch))?;
            bucket_rows += batch.num_rows() as u64;
            sink(ClassSortEvent::Rows(&batch))?;
        }
        if isolated {
            sink(ClassSortEvent::RunBoundary)?;
        }
        ensure!(Some(&bucket_rows) == counts.classes.get(&order[bucket]), "class-sorted family lost or duplicated rows");
        written += bucket_rows;
        std::fs::remove_file(&path)?;
    }
    ensure!(written == counts.rows(), "class-sorted family lost or duplicated rows");
    Ok(written)
}

/// Most class runs [`restore_class_runs`] merges at once (one open reader
/// each); a file with more is restored by the bucket sort instead.
pub const MAX_RESTORE_RUNS: usize = 64;

/// NAN-4688: restore a [`CLASS_ROW_ORDER`] file to `(time, uid)` order by
/// merging its class runs, each already in `(time, uid)` order: one narrow
/// pass over `class_uid`, `time` and `metadata.uid` finds the runs and
/// verifies that order, then one reader per run streams through a k-way
/// merge. No spill and no sort, unlike
/// [`super::host_sort::restore_time_order`], whose output (a local,
/// unpublished merge input) this matches row for row.
///
/// `Ok(None)` (nothing written) when the file is not made of strictly
/// time-ordered class runs or has more than [`super::merge::restore_runs_cap`]
/// ([`MAX_RESTORE_RUNS`] at full merge shape, NAN-4755); the caller
/// then uses the bucket sort. `batch_budget_rows` bounds the decoded rows
/// held across the run readers.
pub fn restore_class_runs(source: &Path, target: &Path, batch_budget_rows: usize) -> Result<Option<u64>> {
    use parquet::arrow::arrow_reader::{ParquetRecordBatchReaderBuilder, RowSelection, RowSelector};
    use parquet::arrow::{ArrowWriter, ProjectionMask};
    use crate::generation::event_time_us_from_array;
    let builder = ParquetRecordBatchReaderBuilder::try_new(File::open(source)?)?;
    let schema = builder.schema().clone();
    let properties = super::host_sort::restore_properties(builder.metadata().file_metadata())?;
    let leaves = (0..builder.parquet_schema().num_columns())
        .filter(|i| matches!(builder.parquet_schema().column(*i).path().string().as_str(), "class_uid" | "time" | "metadata.uid"))
        .collect::<Vec<_>>();
    let mask = ProjectionMask::leaves(builder.parquet_schema(), leaves);
    // Runs as (first row, rows); classes strictly ascending, nulls first,
    // and strict (time, uid) order inside each run.
    let mut runs: Vec<(usize, usize)> = Vec::new();
    let mut current: Option<Option<i64>> = None;
    let (mut last_time, mut last_uid) = (i64::MIN, String::new());
    let mut row_index = 0_usize;
    for batch in builder.with_projection(mask).with_batch_size(65_536).build()? {
        let batch = batch?;
        let classes = class_keys(&batch)?;
        let time = batch.column_by_name("time").context("class-sorted file has no time")?;
        let uids = super::writer::uid_strings(&batch)?;
        for row in 0..batch.num_rows() {
            let class = classes[row];
            let time_us = event_time_us_from_array(time.as_ref(), row).context("row has no time")?;
            let uid = uids.value(row);
            match current {
                Some(open) if open == class => {
                    if (time_us, uid) <= (last_time, last_uid.as_str()) {
                        return Ok(None);
                    }
                    runs.last_mut().expect("open run").1 += 1;
                }
                Some(open) if class < open => return Ok(None),
                _ => {
                    if runs.len() == super::merge::restore_runs_cap() {
                        return Ok(None);
                    }
                    current = Some(class);
                    runs.push((row_index, 1));
                }
            }
            last_time = time_us;
            last_uid.clear();
            last_uid.push_str(uid);
            row_index += 1;
        }
    }
    let total = row_index as u64;
    let mut writer = ArrowWriter::try_new(File::create(target)?, schema.clone(), Some(properties))?;
    struct Run {
        reader: parquet::arrow::arrow_reader::ParquetRecordBatchReader,
        batch: RecordBatch,
        times: Vec<i64>,
        uids: arrow_array::StringArray,
        row: usize,
    }
    let next = |reader: &mut parquet::arrow::arrow_reader::ParquetRecordBatchReader| -> Result<Option<(RecordBatch, Vec<i64>, arrow_array::StringArray)>> {
        let Some(batch) = reader.next().transpose()? else { return Ok(None) };
        super::merge_quota::charge_checked(batch.num_rows() as u64, super::merge_quota::batch_bytes(&batch))?;
        let time = batch.column_by_name("time").context("class-sorted file has no time")?;
        let times = (0..batch.num_rows()).map(|row| event_time_us_from_array(time.as_ref(), row).context("row has no time")).collect::<Result<Vec<_>>>()?;
        let uids = super::writer::uid_strings(&batch)?;
        Ok(Some((batch, times, uids)))
    };
    let run_rows = (batch_budget_rows / runs.len().max(1)).clamp(256, 8_192);
    let mut open: Vec<Option<Run>> = Vec::with_capacity(runs.len());
    for (start, rows) in &runs {
        let selection = RowSelection::from(vec![RowSelector::skip(*start), RowSelector::select(*rows)]);
        let mut reader = ParquetRecordBatchReaderBuilder::try_new(File::open(source)?)?
            .with_row_selection(selection).with_batch_size(run_rows).build()?;
        open.push(next(&mut reader)?.map(|(batch, times, uids)| Run { reader, batch, times, uids, row: 0 }));
    }
    let mut pending: Vec<(usize, usize)> = Vec::with_capacity(8_192);
    let mut written = 0_u64;
    let flush = |open: &[Option<Run>], pending: &mut Vec<(usize, usize)>, writer: &mut ArrowWriter<File>, written: &mut u64| -> Result<()> {
        if pending.is_empty() {
            return Ok(());
        }
        // Exhausted runs keep their last batch until this flush.
        let batches = open.iter().map(|run| run.as_ref().map(|run| &run.batch)).collect::<Vec<_>>();
        let slots = batches.iter().enumerate().filter_map(|(i, batch)| batch.map(|_| i)).collect::<Vec<_>>();
        let refs = slots.iter().map(|i| batches[*i].expect("slot")).collect::<Vec<_>>();
        let indices = pending.iter().map(|(run, row)| (slots.binary_search(run).expect("pending run is open"), *row)).collect::<Vec<_>>();
        let merged = arrow_select::interleave::interleave_record_batch(&refs, &indices)?;
        *written += merged.num_rows() as u64;
        writer.write(&merged)?;
        pending.clear();
        Ok(())
    };
    loop {
        let mut best: Option<usize> = None;
        for (i, run) in open.iter().enumerate() {
            let Some(run) = run else { continue };
            if run.row == run.batch.num_rows() { continue; }
            let key = (run.times[run.row], run.uids.value(run.row));
            if best.is_none_or(|b| {
                let other = open[b].as_ref().expect("best is open");
                key < (other.times[other.row], other.uids.value(other.row))
            }) {
                best = Some(i);
            }
        }
        let Some(best) = best else { break };
        let run = open[best].as_mut().expect("best is open");
        pending.push((best, run.row));
        run.row += 1;
        let exhausted = run.row == run.batch.num_rows();
        if exhausted || pending.len() == 8_192 {
            flush(&open, &mut pending, &mut writer, &mut written)?;
        }
        if exhausted {
            let run = open[best].as_mut().expect("best is open");
            match next(&mut run.reader)? {
                Some((batch, times, uids)) => {
                    run.batch = batch;
                    run.times = times;
                    run.uids = uids;
                    run.row = 0;
                }
                None => open[best] = None,
            }
        }
    }
    flush(&open, &mut pending, &mut writer, &mut written)?;
    writer.close()?;
    ensure!(written == total, "class-run restore lost rows");
    Ok(Some(total))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::generation::event_time_us_from_array;
    use arrow_ipc::writer::StreamWriter;
    use std::fs::File;

    fn keys(batch: &RecordBatch) -> Vec<(Option<i64>, i64, String)> {
        let classes = class_keys(batch).unwrap();
        let uids = super::super::writer::uid_strings(batch).unwrap();
        let time = batch.column_by_name("time").unwrap();
        (0..batch.num_rows())
            .map(|row| (classes[row], event_time_us_from_array(time.as_ref(), row).unwrap(), uids.value(row).to_string()))
            .collect()
    }

    /// Mutation guard for the durable layout: the output is a permutation of
    /// the input (no row lost or duplicated, every column carried with its
    /// row) in strict `(class_uid, time, uid)` order, nulls first.
    #[test]
    fn class_sort_is_an_ordered_permutation() {
        use super::super::schema::{decode, infer_schema};
        use super::super::writer::sort_by_time_uid;
        use std::sync::Arc;
        let events = (0..2_000_usize)
            .map(|row| {
                let mut event = serde_json::json!({
                    "time": chrono::DateTime::from_timestamp_micros((row / 3) as i64 * 1_000).unwrap().to_rfc3339(),
                    "metadata": { "uid": format!("u{row:05}") },
                    "message": format!("row {row}"),
                });
                if row % 17 != 0 {
                    event["class_uid"] = serde_json::json!([1007, 4001, 3002, 1001, 6003][row % 5]);
                }
                event
            })
            .collect::<Vec<_>>();
        let refs = events.iter().collect::<Vec<_>>();
        let schema = Arc::new(infer_schema(&refs).unwrap());
        let batch = sort_by_time_uid(&decode(schema.clone(), &refs).unwrap()).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let stream = dir.path().join("family.arrow");
        let mut writer = StreamWriter::try_new(File::create(&stream).unwrap(), &schema).unwrap();
        let mut counts = ClassCounts::default();
        for offset in (0..batch.num_rows()).step_by(97) {
            let slice = batch.slice(offset, 97.min(batch.num_rows() - offset));
            counts.add_batch(&class_keys(&slice).unwrap(), 0..slice.num_rows());
            writer.write(&slice).unwrap();
        }
        writer.finish().unwrap();
        assert!(counts.mixed());
        let input = keys(&batch);
        let messages = |batch: &RecordBatch| -> Vec<(String, String)> {
            let uids = super::super::writer::uid_strings(batch).unwrap();
            let message = batch.column_by_name("message").unwrap().as_any().downcast_ref::<arrow_array::StringArray>().unwrap();
            (0..batch.num_rows()).map(|row| (uids.value(row).to_string(), message.value(row).to_string())).collect()
        };
        let mut output = Vec::new();
        let mut carried = Vec::new();
        let mut boundaries = 0;
        let written = class_sort_stream(dir.path(), &schema, &stream, &counts, |event| {
            match event {
                ClassSortEvent::Rows(batch) => {
                    output.extend(keys(batch));
                    carried.extend(messages(batch));
                }
                ClassSortEvent::RunBoundary => boundaries += 1,
            }
            Ok(())
        })
        .unwrap();
        // 2,000 rows: no class reaches the isolation floor.
        assert_eq!(boundaries, 0);
        assert_eq!(written, 2_000);
        assert!(output.windows(2).all(|pair| pair[0] < pair[1]), "strict (class, time, uid) order");
        assert_eq!(output.first().unwrap().0, None, "null class first");
        let mut expected = input;
        expected.sort();
        assert_eq!(output, expected, "a permutation of the input");
        let mut carried_sorted = carried.clone();
        carried_sorted.sort();
        let mut original = messages(&batch);
        original.sort();
        assert_eq!(carried_sorted, original, "every column moves with its row");
        // Spill files are gone; only the input stream remains.
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
    }

    /// A count that disagrees with the stream fails the write instead of
    /// silently dropping or inventing rows.
    #[test]
    fn class_sort_refuses_counts_that_do_not_match_the_stream() {
        use super::super::schema::{decode, infer_schema};
        use std::sync::Arc;
        let events = (0..10_usize)
            .map(|row| serde_json::json!({
                "time": "2026-10-26T00:00:00Z", "class_uid": 1007 + (row % 2) as i64,
                "metadata": { "uid": format!("u{row}") },
            }))
            .collect::<Vec<_>>();
        let refs = events.iter().collect::<Vec<_>>();
        let schema = Arc::new(infer_schema(&refs).unwrap());
        let batch = decode(schema.clone(), &refs).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let stream = dir.path().join("family.arrow");
        let mut writer = StreamWriter::try_new(File::create(&stream).unwrap(), &schema).unwrap();
        writer.write(&batch).unwrap();
        writer.finish().unwrap();
        let mut short = ClassCounts::default();
        short.classes.insert(Some(1007), 5);
        assert!(class_sort_stream(dir.path(), &schema, &stream, &short, |_event| Ok(())).is_err(), "unknown class");
        short.classes.insert(Some(1008), 4);
        assert!(class_sort_stream(dir.path(), &schema, &stream, &short, |_event| Ok(())).is_err(), "miscounted class");
    }
}
