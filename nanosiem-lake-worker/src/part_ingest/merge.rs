// SPDX-License-Identifier: AGPL-3.0-or-later

//! Streaming tiered merges (contract 6.3).
//!
//! Every input file is sorted by `(time, uid)`, so a merge is a k-way merge
//! over row-group batches: memory is one decoded batch per open file plus
//! one output row group, never the part. A full re-sort of one 300-eps hour
//! measured above 1.86 GiB; this path never sorts.

use anyhow::{ensure, Context, Result};
use arrow_array::{Array, RecordBatch, StringArray, UInt16Array, UInt32Array, UInt64Array};
use arrow_ipc::{reader::StreamReader, writer::StreamWriter};
use arrow_schema::SchemaRef;
use parquet::arrow::arrow_reader::{ParquetRecordBatchReader, ParquetRecordBatchReaderBuilder};
use std::cmp::Reverse;
use std::collections::{BTreeMap, BTreeSet, BinaryHeap};
use std::fs::File;
use std::path::{Path, PathBuf};

use super::schema::align;
use super::writer::{local_data_files, log_source_strings, uid_strings, FinishedPart, PartDraft, PartWriter, PartialSource};
use crate::generation::event_time_us_from_array;
use crate::parts::levels::Level;
use crate::parts::part_log::PartRef;
use crate::parts::provenance::{row_digests_for_merge, InputPart, MerkleBuilder, PartInputs, SignedProvenance};
use crate::parts::DedupWindow;

/// NAN-3867: a per-batch row filter applied to every input batch before the
/// k-way merge sees it (the lean erasure rewrite: drop the subject's rows,
/// redact free-text mentions in the kept ones). It must keep the batch's
/// `(time, uid)` order (dropping rows and rewriting non-key columns does).
pub trait RowFilter: Send + Sync {
    /// The kept, possibly rewritten, batch and `(rows removed, rows rewritten)`.
    fn apply(&self, batch: RecordBatch) -> Result<(RecordBatch, u64, u64)>;
}

/// Rows a [`RowFilter`] removed and rewrote over one merge pass.
#[derive(Default)]
struct FilterTally {
    removed: std::sync::atomic::AtomicU64,
    rewritten: std::sync::atomic::AtomicU64,
}

#[derive(Clone)]
struct ActiveFilter {
    filter: std::sync::Arc<dyn RowFilter>,
    tally: std::sync::Arc<FilterTally>,
}

/// One merge input: its log reference and its verified local directory.
#[derive(Debug, Clone)]
pub struct MergeInput {
    pub part: PartRef,
    pub dir: PathBuf,
}

struct Cursor {
    /// Remaining data files of the input, in order; `reader` reads the head.
    files: std::collections::VecDeque<PathBuf>,
    batch_rows: usize,
    reader: Option<ParquetRecordBatchReader>,
    /// NAN-4664: the head file carries derived indicator columns (its
    /// footer marker); they are dropped here and re-derived by the writer.
    reader_marked: bool,
    batch: Option<RecordBatch>,
    times: Vec<i64>,
    uids: Option<StringArray>,
    row: usize,
    filter: Option<ActiveFilter>,
}

impl Cursor {
    fn open(files: Vec<PathBuf>, batch_rows: usize, filter: Option<ActiveFilter>) -> Result<Self> {
        let files = files.into_iter().collect();
        Ok(Self { files, batch_rows, reader: None, reader_marked: false, batch: None, times: Vec::new(), uids: None, row: 0, filter })
    }

    fn next_batch(&mut self) -> Result<Option<RecordBatch>> {
        loop {
            if let Some(reader) = &mut self.reader {
                if let Some(batch) = reader.next() {
                    let batch = batch?;
                    // NAN-4664: derived columns are rebuilt by the writer.
                    return Ok(Some(if self.reader_marked { crate::parts::indicators::strip(batch)? } else { batch }));
                }
                self.reader = None;
            }
            let Some(path) = self.files.pop_front() else { return Ok(None) };
            let builder = ParquetRecordBatchReaderBuilder::try_new(File::open(&path)?)?;
            self.reader_marked = crate::parts::indicators::has_any_marker(builder.metadata().file_metadata());
            self.reader = Some(builder.with_batch_size(self.batch_rows).build()?);
        }
    }

    /// Load the next batch; false at end of input.
    fn advance(&mut self, schema: &SchemaRef) -> Result<bool> {
        loop {
            match self.next_batch()? {
                None => {
                    self.batch = None;
                    return Ok(false);
                }
                Some(batch) => {
                    super::merge_quota::charge_input_checked(batch.num_rows() as u64, super::merge_quota::batch_bytes(&batch))?;
                    let mut batch = align(batch, schema)?;
                    if let Some(active) = &self.filter {
                        let (kept, removed, rewritten) = active.filter.apply(batch)?;
                        ensure!(kept.schema() == *schema, "merge row filter changed the batch schema");
                        active.tally.removed.fetch_add(removed, std::sync::atomic::Ordering::Relaxed);
                        active.tally.rewritten.fetch_add(rewritten, std::sync::atomic::Ordering::Relaxed);
                        batch = kept;
                    }
                    // NAN-3864: a merge of an owed hour stamps the rows that
                    // were committed unstamped (no-op without one).
                    let batch = super::restamp::apply_active(batch)?;
                    if batch.num_rows() == 0 {
                        continue;
                    }
                    let time = batch.column_by_name("time").context("merge input has no time")?;
                    self.times = (0..batch.num_rows())
                        .map(|i| event_time_us_from_array(time.as_ref(), i).context("merge row has no time"))
                        .collect::<Result<_>>()?;
                    self.uids = Some(uid_strings(&batch)?);
                    self.batch = Some(batch);
                    self.row = 0;
                    return Ok(true);
                }
            }
        }
    }

    fn key(&self) -> (i64, &str) {
        (self.times[self.row], self.uids.as_ref().expect("loaded").value(self.row))
    }
}

pub struct MergeResult {
    pub finished: FinishedPart,
    pub duplicates_dropped: u64,
    /// NAN-3867: input rows a [`RowFilter`] removed (0 for a plain merge).
    pub filtered_out: u64,
    /// NAN-3867: kept rows a [`RowFilter`] rewrote (0 for a plain merge).
    pub filter_rewritten: u64,
}

/// What [`merge_parts_filtered`] produced: the output part, or nothing when
/// the filter removed every input row (a part may not be empty).
pub enum FilteredMerge {
    Part(MergeResult),
    Empty { rows_removed: u64 },
}

/// Decoded input rows a merge holds across its open readers, sized from
/// the process memory budget ([`set_memory_budget`]): at most
/// [`MERGE_DECODE_SHARE`] of it at [`MERGE_ROW_BYTES`] a row, within
/// 2,048..=32,768 rows (32,768 before NAN-3056).
static DECODE_WINDOW_ROWS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(32_768);
/// Share of memory.max one merge's decode window may take.
pub const MERGE_DECODE_SHARE: f64 = 0.05;
/// Upper bound of a decoded OCSF row (Arrow; measured ~6.4 KB, up to ~10 KB).
pub const MERGE_ROW_BYTES: u64 = 10 * 1024;

/// Size the merge decode window from the process memory cap (the cell's
/// ingest budget). 0 keeps the default.
pub fn set_memory_budget(memory_cap_bytes: u64) {
    DECODE_WINDOW_ROWS.store(decode_window_rows_for(memory_cap_bytes), std::sync::atomic::Ordering::Relaxed);
    MEMORY_CAP_BYTES.store(memory_cap_bytes, std::sync::atomic::Ordering::Relaxed);
}

/// The process memory cap given to [`set_memory_budget`] (0: unknown). The
/// history lanes size their concurrency from it (NAN-3187).
static MEMORY_CAP_BYTES: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

pub fn memory_cap_bytes() -> Option<u64> {
    Some(MEMORY_CAP_BYTES.load(std::sync::atomic::Ordering::Relaxed)).filter(|cap| *cap > 0)
}

pub fn decode_window_rows_for(memory_cap_bytes: u64) -> usize {
    if memory_cap_bytes == 0 {
        return 32_768;
    }
    ((memory_cap_bytes as f64 * MERGE_DECODE_SHARE / MERGE_ROW_BYTES as f64) as usize).clamp(2_048, 32_768)
}

/// Working-budget bytes one running merge is charged (its decode window at
/// [`MERGE_ROW_BYTES`] a row; measured: a minute merge of 8 16.7k-row L0
/// parts peaked at 136 MiB with a 32,768-row window, under half of this).
pub fn merge_reserve_bytes() -> u64 {
    decode_window_rows() as u64 * MERGE_ROW_BYTES
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) struct InitialMergeShape {
    pub shift: u8,
    pub max_inputs: Option<usize>,
}

/// Shape and fan-in are one first-attempt decision. A full hour that does
/// not fit even at the smallest shape uses the same halving ladder as a
/// guard-stopped attempt, without first spending time on that attempt.
pub(super) fn initial_shape(merge: &crate::parts::levels::PlannedMerge, headroom: Option<u64>, reserved: u64,
    minimum_shift: u8) -> InitialMergeShape {
    if merge.output_level != Level::Hour || headroom.is_none() {
        return InitialMergeShape::default();
    }
    let room = headroom.unwrap().saturating_sub(reserved);
    let smallest = super::merge_attempts::MAX_SHIFT;
    for shift in minimum_shift.min(smallest)..=smallest {
        if shape_estimate(&merge.inputs, shift) <= room {
            return InitialMergeShape { shift, max_inputs: None };
        }
    }
    let splittable = merge.inputs.iter().filter(|part| matches!(part.level, Level::L0 | Level::Minute)).count();
    if splittable <= 2 {
        return InitialMergeShape { shift: smallest, max_inputs: None };
    }
    let mut cap = (splittable / 2).max(2);
    loop {
        // Use actual time-ordered chunks, including the largest/skewed
        // one. Averaging bytes or rows per input can admit an unsafe chunk.
        let chunks = crate::parts::levels::split_merge(merge.clone(), cap);
        if cap == 2 || chunks.iter().all(|chunk| shape_estimate(&chunk.inputs, smallest) <= room) {
            return InitialMergeShape { shift: smallest, max_inputs: Some(cap) };
        }
        cap = (cap / 2).max(2);
    }
}

pub(super) fn starting_shape(merge: &crate::parts::levels::PlannedMerge, headroom: Option<u64>, reserved: u64) -> u8 {
    initial_shape(merge, headroom, reserved, 0).shift
}

/// Live 116k-row/5-input hours stopped at shift 1 and committed at 2;
/// 124k/39 and 131k/53 stopped even at shift 3, then committed with fan-in
/// 19 and 13. The old 10 KiB row allowance and capped-reader-only charge
/// missed both: use twice the row allowance and two writer-sized buffer
/// reservations per input, in addition to the currently open readers.
/// Input/partial state survives reader rotation, so that term must not be
/// capped by open_inputs_cap or halved with the decode window.
/// These are estimates; the running guard and durable retry ladder remain.
fn shape_estimate(inputs: &[PartRef], shift: u8) -> u64 {
    let rows = inputs.iter().fold(0_u64, |sum, part| sum.saturating_add(part.rows));
    let bytes = inputs.iter().fold(0_u64, |sum, part| sum.saturating_add(part.data_bytes));
    let row_bytes = 2 * MERGE_ROW_BYTES;
    let decoded = rows.saturating_mul(row_bytes)
        .max((bytes as f64 * super::ingest::INITIAL_ARROW_PER_SOURCE_BYTE) as u64)
        .min(crate::parts::format::ROW_GROUP_ROWS as u64 * MAX_OPEN_INPUTS as u64 * row_bytes);
    let copies = (decoded as f64 * super::memory::BUILD_BYTES_PER_BUFFER_BYTE * super::memory::CALIBRATION_MARGIN) as u64;
    let readers = inputs.len().min((MAX_OPEN_INPUTS >> shift).max(2)) as u64;
    let input_buffers = (inputs.len() as u64).saturating_mul(2 * super::memory::L0_WRITER_BYTES);
    (copies >> shift).saturating_add(input_buffers).saturating_add((readers + 1) * super::memory::L0_WRITER_BYTES)
}

#[cfg(test)]
#[path = "merge_shape_tests.rs"]
mod shape_tests;

fn decode_window_rows() -> usize {
    (DECODE_WINDOW_ROWS.load(std::sync::atomic::Ordering::Relaxed) >> shape_shift()).max(512)
}

thread_local! {
    /// NAN-4755: the shape step of the merge running on this thread.
    static SHAPE_SHIFT: std::cell::Cell<u8> = const { std::cell::Cell::new(0) };
}

/// NAN-4755: run `work` (one merge, on its compute thread) at shape step
/// `shift` (see [`super::merge_attempts`]) with the memory guard armed.
/// Each step halves the decode window, the open input readers (at least 2)
/// and the class runs a restore opens at once (at least 8), so a merge that
/// ran out of memory reruns with about half the working set.
pub fn with_shape<T>(shift: u8, work: impl FnOnce() -> T) -> T {
    let previous = SHAPE_SHIFT.replace(shift.min(super::merge_attempts::MAX_SHIFT));
    let _guard = super::merge_quota::memory_guard_scope();
    let out = work();
    SHAPE_SHIFT.set(previous);
    out
}

fn shape_shift() -> u8 {
    SHAPE_SHIFT.get()
}

/// Most input readers this thread's merge opens at once ([`MAX_OPEN_INPUTS`]
/// at full size, halved per shape step, at least 2).
pub fn open_inputs_cap() -> usize {
    (MAX_OPEN_INPUTS >> shape_shift()).max(2)
}

/// Most class runs a restore of this thread's merge reads at once
/// ([`super::class_sort::MAX_RESTORE_RUNS`] at full size, halved per shape
/// step, at least 8); a file with more is bucket-sorted instead.
pub fn restore_runs_cap() -> usize {
    (super::class_sort::MAX_RESTORE_RUNS >> shape_shift()).max(8)
}

/// Rows one host-sort bucket holds in memory (NAN-3412): half the merge
/// decode window, which the main k-way merge no longer uses by then.
/// The row order of an hour merge's family files (NAN-3412, NAN-4664).
/// [`HourOrder::TIME`] is the `(time, uid)` layout every reader assumes;
/// the others are written tagged with their order and read back through
/// [`super::host_sort::restore_time_order`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) struct HourOrder {
    /// Endpoint families in `(device.hostname, time, uid)` order, in groups
    /// of this many rows.
    pub host_sort: Option<usize>,
    /// Every other multi-class family in `(class_uid, time, uid)` order.
    pub class_sort: bool,
}

impl HourOrder {
    pub const TIME: Self = Self { host_sort: None, class_sort: false };

    pub const fn host(group_rows: usize) -> Self {
        Self { host_sort: Some(group_rows), class_sort: false }
    }

    fn is_time(self) -> bool {
        self == Self::TIME
    }
}

/// NAN-4664: a family is class-sorted only while its file stays well under
/// one data file (a class-sorted family cannot roll). Estimated from the
/// inputs' compressed bytes per row (L0/minute inputs compress worse than
/// the zstd-9 hour output, so the estimate is high).
const CLASS_SORT_MAX_FAMILY_BYTES: u64 = crate::parts::format::DATA_FILE_SPLIT_BYTES / 2;

fn class_sort_max_rows(inputs: &[MergeInput]) -> u64 {
    let rows = inputs.iter().map(|input| input.part.rows).sum::<u64>();
    let bytes = inputs.iter().map(|input| input.part.data_bytes).sum::<u64>().max(1);
    u64::try_from(u128::from(rows) * u128::from(CLASS_SORT_MAX_FAMILY_BYTES) / u128::from(bytes)).unwrap_or(u64::MAX)
}

fn host_sort_bucket_rows() -> usize {
    (decode_window_rows() / 2).max(1_024 >> shape_shift())
}

/// Most input readers open at once. Every open Parquet reader holds decoded
/// dictionary and page state for the wide OCSF schema (NAN-2868 merge-probe:
/// a 57-way hour seal peaked at 1.30 GB VmHWM with every reader open), so
/// the merge peak is bounded by construction, not by typical overlap.
pub const MAX_OPEN_INPUTS: usize = 8;

/// Seven dedicated families plus one mixed long-tail file stream.
const MAX_DEDICATED_FAMILIES: usize = 7;
const FAMILY_CANDIDATES: usize = 16;
/// NAN-3188: dedicated `(source, class_uid)` families of the compaction
/// layout, plus one overflow stream. Chosen by row volume over the merge
/// inputs ([`choose_class_families`]), so a large class seen late in the hour
/// still gets its own (class-prunable) file. The source-only layout keeps
/// [`MAX_DEDICATED_FAMILIES`].
const MAX_DEDICATED_CLASS_FAMILIES: usize = 15;

/// NAN-3437: hour merges write dedicated `(source, class_uid)` family files
/// in the DEFAULT layout (row groups, file roll, one merge pass),
/// independent of the experimental `NANO_LAKE_COMPACTION_LAYOUT` and its
/// second pass / storage gate. NAN-4688: always on (it was the
/// `NANO_LAKE_CLASS_FAMILIES=1` opt-in, already set on every live
/// deployment); the planner prunes other-class files by their signed
/// `class_id` (`prune::file_family_may_match`).
///
/// A `(source, class)` needs at least this many
/// rows in the merge to get its own file; smaller classes stay in their
/// source's rest file. With [`MAX_DEDICATED_CLASS_FAMILIES`] dedicated
/// files, at most [`MAX_DEDICATED_FAMILIES`] source rest files and one
/// overflow, an hour has at most 23 families (each rolling at the default
/// file size) however many classes it holds.
pub(super) const CLASS_FAMILY_MIN_ROWS: u64 = 8_192;

#[cfg(test)]
thread_local! {
    /// Tests may turn the class split off per thread, to compare against
    /// (and re-merge) the source-family layout that older hours still have.
    static CLASS_FAMILIES_OVERRIDE: std::cell::Cell<Option<bool>> = const { std::cell::Cell::new(None) };
}

fn class_families_enabled() -> bool {
    #[cfg(test)]
    if let Some(enabled) = CLASS_FAMILIES_OVERRIDE.with(std::cell::Cell::get) {
        return enabled;
    }
    true
}

/// `class_uid` of `row` as i64 (`None` when null or of an unexpected type).
pub(super) fn class_at(column: Option<&arrow_array::ArrayRef>, row: usize) -> Option<i64> {
    let column = column?;
    if column.is_null(row) { return None; }
    match column.data_type() {
        arrow_schema::DataType::Int64 => column.as_any().downcast_ref::<arrow_array::Int64Array>().map(|values| values.value(row)),
        arrow_schema::DataType::Int32 => column.as_any().downcast_ref::<arrow_array::Int32Array>().map(|values| i64::from(values.value(row))),
        arrow_schema::DataType::UInt32 => column.as_any().downcast_ref::<arrow_array::UInt32Array>().map(|values| i64::from(values.value(row))),
        arrow_schema::DataType::UInt64 => column.as_any().downcast_ref::<arrow_array::UInt64Array>().and_then(|values| i64::try_from(values.value(row)).ok()),
        _ => None,
    }
}

/// Add each row's `(metadata.log_source, class_uid)` to `counts`; rows
/// missing either stay in the overflow stream and are not counted.
pub(super) fn count_source_classes(batch: &RecordBatch, counts: &mut ClassCounts) -> Result<()> {
    let Some(classes) = batch.column_by_name("class_uid") else { return Ok(()) };
    let sources = log_source_strings(batch)?;
    for row in 0..batch.num_rows() {
        if sources.is_null(row) { continue; }
        let Some(class) = class_at(Some(classes), row) else { continue };
        let source = sources.value(row);
        // Look the source up borrowed: one allocation per family, not per row.
        let classes = match counts.get_mut(source) {
            Some(classes) => classes,
            None => counts.entry(source.to_owned()).or_default(),
        };
        *classes.entry(class).or_default() += 1;
    }
    Ok(())
}

/// Rows per `metadata.log_source`, then per `class_uid`.
pub(super) type ClassCounts = BTreeMap<String, BTreeMap<i64, u64>>;

/// The largest `(source, class)` families, ties broken by key, so the
/// selection is a pure function of the merged rows.
fn rank_class_families(counts: ClassCounts) -> BTreeSet<(String, i64)> {
    rank_class_families_above(counts, 0)
}

/// [`rank_class_families`] over the families of at least `min_rows` rows.
fn rank_class_families_above(counts: ClassCounts, min_rows: u64) -> BTreeSet<(String, i64)> {
    ranked_class_families(counts, min_rows, MAX_DEDICATED_CLASS_FAMILIES).into_iter().map(|(family, _)| family).collect()
}

/// The `limit` largest `(source, class)` families of at least `min_rows`
/// rows with their counts, largest first (ties by key): a pure function of
/// the counted rows. NAN-4750: the L0 flush picks its class drafts with it.
pub(super) fn ranked_class_families(counts: ClassCounts, min_rows: u64, limit: usize) -> Vec<((String, i64), u64)> {
    let mut ranked = counts.into_iter()
        .flat_map(|(source, classes)| classes.into_iter().map(move |(class, rows)| ((source.clone(), class), rows)))
        .filter(|(_, rows)| *rows >= min_rows)
        .collect::<Vec<_>>();
    ranked.sort_by(|(left, left_count), (right, right_count)| right_count.cmp(left_count).then_with(|| left.cmp(right)));
    ranked.truncate(limit);
    ranked
}

/// NAN-3188: exact row counts per `(source, class)` over every input data
/// file, reading only the `class_uid` and `metadata.log_source` leaves (two
/// narrow dictionary/int columns, not the ~10 KB decoded row). Before this
/// the first families seen in time order won, so a large class whose first
/// row came late landed in the unprunable overflow file.
fn choose_class_families(inputs: &[MergeInput]) -> Result<BTreeSet<(String, i64)>> {
    Ok(rank_class_families(count_input_classes(inputs)?))
}

/// Exact rows per `(source, class)` over every input data file.
fn count_input_classes(inputs: &[MergeInput]) -> Result<ClassCounts> {
    use parquet::arrow::ProjectionMask;
    let mut counts = ClassCounts::new();
    for input in inputs {
        for path in local_data_files(&input.dir)? {
            let builder = ParquetRecordBatchReaderBuilder::try_new(File::open(&path)?)?;
            let schema = builder.parquet_schema();
            let find = |name: &str| (0..schema.num_columns()).find(|i| schema.column(*i).path().string() == name);
            let (Some(class_leaf), Some(source_leaf)) = (find("class_uid"), find("metadata.log_source")) else { continue };
            let mask = ProjectionMask::leaves(schema, [class_leaf, source_leaf]);
            for batch in builder.with_projection(mask).with_batch_size(65_536).build()? {
                count_source_classes(&batch?, &mut counts)?;
            }
        }
    }
    Ok(counts)
}

/// Bounded weighted heavy-hitter selection from the inputs' field-zero
/// rollups. That field counts every row once, grouped by source. The sketch
/// keeps frequent families even if they first appear late in the hour.
fn choose_families(inputs: &[MergeInput]) -> Result<BTreeSet<String>> {
    let mut counts: BTreeMap<String, u64> = BTreeMap::new();
    for input in inputs {
        let path = input.dir.join(crate::parts::format::PARTIAL_ROLLUP_FILE);
        let mut reader = ParquetRecordBatchReaderBuilder::try_new(File::open(path)?)?.with_batch_size(4_096).build()?;
        for batch in &mut reader {
            let batch = batch?;
            let fields = batch.column_by_name("field_id").context("rollup has no field_id")?
                .as_any().downcast_ref::<UInt16Array>().context("rollup field_id is not UInt16")?;
            let sources = batch.column_by_name("source_type").context("rollup has no source_type")?
                .as_any().downcast_ref::<StringArray>().context("rollup source_type is not Utf8")?;
            let events = batch.column_by_name("events").context("rollup has no events")?
                .as_any().downcast_ref::<UInt64Array>().context("rollup events is not UInt64")?;
            for row in 0..batch.num_rows() {
                if fields.value(row) != 0 || sources.is_null(row) { continue; }
                let source = sources.value(row);
                let weight = events.value(row);
                if let Some(count) = counts.get_mut(source) {
                    *count = count.saturating_add(weight);
                } else if counts.len() < FAMILY_CANDIDATES {
                    counts.insert(source.to_owned(), weight);
                } else {
                    let (least, count) = counts.iter().min_by_key(|(source, count)| (**count, *source))
                        .map(|(source, count)| (source.clone(), *count)).expect("nonempty sketch");
                    counts.remove(&least);
                    counts.insert(source.to_owned(), count.saturating_add(weight));
                }
            }
        }
    }
    let mut ranked = counts.into_iter().collect::<Vec<_>>();
    ranked.sort_by(|(left_source, left_count), (right_source, right_count)|
        right_count.cmp(left_count).then_with(|| left_source.cmp(right_source)));
    Ok(ranked.into_iter().take(MAX_DEDICATED_FAMILIES).map(|(source, _)| source).collect())
}

#[derive(Clone, Eq, PartialEq, Ord, PartialOrd)]
enum Family { Named(String), SourceClass(String, i64), Overflow }

/// Spill the already time-sorted merge stream into a bounded number of family
/// streams (dedicated families plus one overflow). IPC writers buffer only
/// the current batch, not a row group.
struct FamilySpool {
    dir: tempfile::TempDir,
    chosen: BTreeSet<String>,
    streams: BTreeMap<Family, (PathBuf, StreamWriter<File>)>,
    schema: SchemaRef,
    merkle: MerkleBuilder,
    class_clustering: bool,
    class_families: BTreeSet<(String, i64)>,
    /// NAN-3437: rows of a non-dedicated class go to their source's family
    /// (when the source is chosen) instead of the shared overflow.
    source_rest: bool,
    /// NAN-3412: `(group_rows, bucket_rows)` when endpoint families are
    /// written host-sorted ([`super::host_sort`]).
    host_sort: Option<(usize, usize)>,
    /// Rows per `device.hostname` of each endpoint family (host sort only).
    host_counts: BTreeMap<Family, super::host_sort::HostCounts>,
    /// NAN-4664: most rows a family may hold and still be class-sorted;
    /// `None`: class sort off.
    class_sort_max_rows: Option<u64>,
    /// Rows per `class_uid` of each family that is not host-sorted (class
    /// sort only).
    class_counts: BTreeMap<Family, super::class_sort::ClassCounts>,
}

impl FamilySpool {
    fn new(work_dir: &Path, schema: SchemaRef, chosen: BTreeSet<String>) -> Result<Self> {
        ensure!(chosen.len() <= MAX_DEDICATED_FAMILIES, "too many selected families");
        Ok(Self { dir: tempfile::Builder::new().prefix(".family-").tempdir_in(work_dir)?, chosen, streams: BTreeMap::new(), schema, merkle: MerkleBuilder::new(), class_clustering: false, class_families: BTreeSet::new(), source_rest: false, host_sort: None, host_counts: BTreeMap::new(), class_sort_max_rows: None, class_counts: BTreeMap::new() })
    }

    /// Cluster by `(source, class)` into exactly these dedicated families.
    fn set_class_families(&mut self, families: BTreeSet<(String, i64)>) -> Result<()> {
        ensure!(families.len() <= MAX_DEDICATED_CLASS_FAMILIES, "too many selected class families");
        self.class_clustering = true;
        self.class_families = families;
        Ok(())
    }

    /// NAN-3437: [`Self::set_class_families`], with every other row of a
    /// chosen source kept in that source's family (source-prunable as in
    /// the source-only layout) rather than the mixed overflow.
    fn set_class_families_with_source_rest(&mut self, families: BTreeSet<(String, i64)>) -> Result<()> {
        self.set_class_families(families)?;
        self.source_rest = true;
        Ok(())
    }

    /// The family of a row of `source` that has no dedicated class family.
    fn rest_family(&self, source: &str) -> Family {
        if self.source_rest && self.chosen.contains(source) { Family::Named(source.to_owned()) } else { Family::Overflow }
    }

    /// Write endpoint families host-sorted (NAN-3412) in `group_rows`-row
    /// groups, sorting at most about `bucket_rows` rows at a time.
    fn set_host_sort(&mut self, group_rows: usize, bucket_rows: usize) {
        self.host_sort = Some((group_rows, bucket_rows));
    }

    /// Write every multi-class family that is not host-sorted in
    /// `(class_uid, time, uid)` order (NAN-4664), up to `max_rows` rows a
    /// family.
    fn set_class_sort(&mut self, max_rows: u64) {
        self.class_sort_max_rows = Some(max_rows);
    }

    /// Whether `family` is written class-sorted.
    fn class_sorted(&self, family: &Family) -> bool {
        !self.host_sorted(family)
            && self.class_sort_max_rows.is_some_and(|max_rows| self.class_counts.get(family)
                .is_some_and(|counts| counts.mixed() && counts.rows() <= max_rows
                    && counts.classes.len() <= super::class_sort::MAX_SORT_CLASSES))
    }

    fn host_sorted(&self, family: &Family) -> bool {
        self.host_sort.is_some() && match family {
            Family::Named(source) | Family::SourceClass(source, _) => super::host_sort::is_endpoint_source(source),
            Family::Overflow => false,
        }
    }

    fn write(&mut self, batch: &RecordBatch) -> Result<()> {
        // NAN-4755: each merged batch is copied per family and IPC-encoded
        // here: the merge's working set peaks in this write, not in decode.
        super::merge_quota::memory_guard_bytes(super::merge_quota::batch_bytes(batch))?;
        let sources = log_source_strings(batch)?;
        let classes = batch.column_by_name("class_uid");
        let uids = uid_strings(batch)?;
        for (row, digest) in row_digests_for_merge(batch)?.iter().enumerate() {
            self.merkle.push_row(uids.value(row), digest);
        }
        let mut groups: BTreeMap<Family, Vec<u32>> = BTreeMap::new();
        for row in 0..batch.num_rows() {
            let family = if self.class_clustering {
                // NAN-3188: the families are fixed before the first row
                // ([`choose_class_families`]); everything else overflows.
                match (sources.is_null(row), class_at(classes, row)) {
                    (false, Some(class)) => {
                        let key = (sources.value(row).to_owned(), class);
                        if self.class_families.contains(&key) { Family::SourceClass(key.0, key.1) } else { self.rest_family(&key.0) }
                    }
                    (false, None) => self.rest_family(sources.value(row)),
                    _ => Family::Overflow,
                }
            } else if sources.is_null(row) { Family::Overflow } else {
                let source = sources.value(row);
                if self.chosen.contains(source) { Family::Named(source.to_owned()) }
                else { Family::Overflow }
            };
            groups.entry(family).or_default().push(u32::try_from(row)?);
        }
        if groups.keys().any(|family| self.host_sorted(family)) {
            let hosts = super::host_sort::host_strings(batch)?;
            for (family, rows) in &groups {
                if !self.host_sorted(family) { continue; }
                let counts = self.host_counts.entry(family.clone()).or_default();
                for row in rows.iter().map(|row| *row as usize) {
                    counts.add((!hosts.is_null(row)).then(|| hosts.value(row)));
                }
            }
        }
        if self.class_sort_max_rows.is_some() && groups.keys().any(|family| !self.host_sorted(family)) {
            let classes = super::class_sort::class_keys(batch)?;
            for (family, rows) in &groups {
                if self.host_sorted(family) { continue; }
                self.class_counts.entry(family.clone()).or_default()
                    .add_batch(&classes, rows.iter().map(|row| *row as usize));
            }
        }
        for (family, rows) in groups {
            if !self.streams.contains_key(&family) {
                let path = self.dir.path().join(format!("{}.arrow", self.streams.len()));
                let stream = StreamWriter::try_new(File::create(&path)?, &self.schema)?;
                self.streams.insert(family.clone(), (path, stream));
            }
            let indices = UInt32Array::from(rows);
            let columns = batch.columns().iter().map(|column| arrow_select::take::take(column.as_ref(), &indices, None))
                .collect::<std::result::Result<Vec<_>, _>>()?;
            let selected = RecordBatch::try_new(batch.schema(), columns)?;
            self.streams.get_mut(&family).expect("stream created").1.write(&selected)?;
        }
        Ok(())
    }

    fn finish_into(mut self, writer: &mut PartWriter) -> Result<String> {
        for (_, stream) in self.streams.values_mut() { stream.finish()?; }
        for (family, (path, _)) in std::mem::take(&mut self.streams) {
            if let (true, Some((group_rows, bucket_rows))) = (self.host_sorted(&family), self.host_sort) {
                let (source, class) = match &family {
                    Family::Named(source) => (source.as_str(), None),
                    Family::SourceClass(source, class) => (source.as_str(), Some(*class)),
                    Family::Overflow => unreachable!("overflow is never host-sorted"),
                };
                writer.start_host_sorted_family(source, class, group_rows)?;
                let counts = self.host_counts.remove(&family).unwrap_or_default();
                super::host_sort::host_sort_stream(self.dir.path(), &self.schema, &path, &counts, bucket_rows,
                    |batch| writer.write(batch))?;
                std::fs::remove_file(&path)?;
                continue;
            }
            if self.class_sorted(&family) {
                let (source, class) = match &family {
                    Family::Named(source) => (Some(source.as_str()), None),
                    Family::SourceClass(source, class) => (Some(source.as_str()), Some(*class)),
                    Family::Overflow => (None, None),
                };
                writer.start_class_sorted_family(source, class)?;
                let counts = self.class_counts.remove(&family).unwrap_or_default();
                super::class_sort::class_sort_stream(self.dir.path(), &self.schema, &path, &counts, |event| match event {
                    super::class_sort::ClassSortEvent::Rows(batch) => writer.write(batch),
                    super::class_sort::ClassSortEvent::RunBoundary => writer.end_class_run(),
                })?;
                std::fs::remove_file(&path)?;
                continue;
            }
            match &family {
                Family::Named(value) => writer.start_log_source(Some(value))?,
                Family::SourceClass(source, class) => writer.start_source_class(Some(source), Some(*class))?,
                Family::Overflow => writer.start_log_source(None)?,
            }
            let mut reader = StreamReader::try_new(File::open(path)?, None)?;
            for batch in &mut reader {
                let batch = batch?;
                super::merge_quota::charge_checked(batch.num_rows() as u64, super::merge_quota::batch_bytes(&batch))?;
                writer.write(&batch)?;
            }
        }
        self.merkle.root_hex().context("empty family spool")
    }
}

/// The most input time ranges that overlap at any instant.
pub fn max_overlap(inputs: &[MergeInput]) -> usize {
    let mut events = Vec::with_capacity(inputs.len() * 2);
    for input in inputs {
        events.push((input.part.min_time_us, 0_u8)); // open sorts before close at a tie
        events.push((input.part.max_time_us, 1_u8));
    }
    events.sort_unstable();
    let (mut open, mut peak) = (0_usize, 0_usize);
    for (_, kind) in events {
        if kind == 0 {
            open += 1;
            peak = peak.max(open);
        } else {
            open -= 1;
        }
    }
    peak
}

/// Merge `inputs` into one part of `level` under `schema` (the newest of
/// the inputs' schemas).
///
/// Inputs open lazily in `min_time_us` order, so only time-overlapping
/// inputs are open together. When more than [`MAX_OPEN_INPUTS`] overlap,
/// the inputs are first merged in groups of that size into local,
/// unpublished intermediates (in `min_time_us` order), repeated until at
/// most [`MAX_OPEN_INPUTS`] overlap; the published record still names the
/// original inputs.
#[allow(clippy::too_many_arguments)]
pub fn merge_parts(
    work_dir: &Path,
    tenant_id: &str,
    level: Level,
    event_hour: i32,
    inputs: &[MergeInput],
    schema: SchemaRef,
    schema_fingerprint: &str,
    signer_key_id: &str,
    build: &str,
    now_ms: i64,
) -> Result<MergeResult> {
    merge_parts_with(work_dir, tenant_id, level, event_hour, inputs, schema, schema_fingerprint, signer_key_id, build, now_ms, None)?
        .context("a plain merge cannot be empty")
}

/// NAN-3867: [`merge_parts`] with every input batch passed through `filter`
/// first (the lean erasure rewrite). Partials are always rebuilt from the
/// output rows, so no derived partial (prevalence, rollup, entity ranges,
/// identity, facets, counts, risk) keeps a removed or rewritten value. The
/// output record's `dedup` still names the inputs' rows; the removed rows are
/// accounted to the `rewrite` log entry that publishes it.
#[allow(clippy::too_many_arguments)]
pub fn merge_parts_filtered(
    work_dir: &Path,
    tenant_id: &str,
    level: Level,
    event_hour: i32,
    inputs: &[MergeInput],
    schema: SchemaRef,
    schema_fingerprint: &str,
    signer_key_id: &str,
    build: &str,
    now_ms: i64,
    filter: std::sync::Arc<dyn RowFilter>,
) -> Result<FilteredMerge> {
    let rows_in = inputs.iter().map(|input| input.part.rows).sum::<u64>();
    Ok(match merge_parts_with(work_dir, tenant_id, level, event_hour, inputs, schema, schema_fingerprint, signer_key_id, build, now_ms, Some(filter))? {
        Some(result) => FilteredMerge::Part(result),
        None => FilteredMerge::Empty { rows_removed: rows_in },
    })
}

/// `None` only with a filter that removed every row.
#[allow(clippy::too_many_arguments)]
fn merge_parts_with(
    work_dir: &Path,
    tenant_id: &str,
    level: Level,
    event_hour: i32,
    inputs: &[MergeInput],
    schema: SchemaRef,
    schema_fingerprint: &str,
    signer_key_id: &str,
    build: &str,
    now_ms: i64,
    filter: Option<std::sync::Arc<dyn RowFilter>>,
) -> Result<Option<MergeResult>> {
    let _quota = super::merge_quota::acquire_for(level)?;
    super::merge_quota::set_rewrite_rows(inputs.iter().map(|input| input.part.rows).sum());
    ensure!(!inputs.is_empty(), "merge has no inputs");
    ensure!(inputs.iter().all(|i| i.part.sorted), "unsorted parts cannot be merge inputs");
    let mut current = inputs.to_vec();
    let mut duplicates = 0_u64;
    let (mut filtered_out, mut filter_rewritten) = (0_u64, 0_u64);
    let scratch = work_dir.join(format!(".merge-{}", uuid::Uuid::new_v4().simple()));
    let result = (|| -> Result<Option<MergeResult>> {
        // A previously clustered H part may be rewritten with late data or
        // merged into a day. Split its independently sorted files into
        // virtual inputs so the existing overlap cap also caps open readers.
        let mut expanded = Vec::new();
        // A filtered merge drops or rewrites rows: no input partial may be
        // merged forward.
        let mut force_row_partials = filter.is_some();
        for input in &current {
            let provenance = input.dir.join(crate::parts::format::PROVENANCE_FILE);
            if matches!(input.part.level, Level::Minute | Level::Hour) && provenance.exists() {
                let signed: SignedProvenance = serde_json::from_slice(&std::fs::read(&provenance)?)?;
                signed.record.validate()?;
                ensure!(signed.record.part_id == input.part.part_id, "merge input provenance names another part");
                // NAN-4664: an hour of overflow rows only (no
                // `metadata.log_source`) is one untagged-source family file
                // that may still be class-sorted; any row-order tag needs
                // the per-file restore below, or the k-way merge reads it
                // out of time order and the hour never merges again.
                let tagged = signed.record.files.data.iter()
                    .map(|file| super::host_sort::is_host_sorted(&input.dir.join(&file.name)))
                    .collect::<Result<Vec<_>>>()?.contains(&true);
                if tagged || signed.record.files.data.iter().any(|file| file.log_sources.is_some()) {
                    // NAN-4688: a class-sorted minute part is one data file,
                    // so its virtual input holds exactly the part's rows and
                    // its partials still merge as they are (no row rebuild).
                    let whole_minute = input.part.level == Level::Minute && signed.record.files.data.len() == 1
                        && input.dir.join(crate::parts::format::PARTIAL_ROLLUP_FILE).is_file();
                    force_row_partials |= !whole_minute;
                    for file in &signed.record.files.data {
                        let dir = scratch.join(format!("virtual-{}", expanded.len()));
                        std::fs::create_dir_all(&dir)?;
                        let source = std::fs::canonicalize(input.dir.join(&file.name))?;
                        let target = dir.join(crate::parts::format::data_file_name(0));
                        if let Some(order) = super::host_sort::file_row_order(&source)? {
                            // NAN-3412: the k-way merge reads inputs in
                            // `(time, uid)` order; restore it locally first.
                            // NAN-4688: a class-sorted file merges its class
                            // runs (no spill, no sort); anything else, or a
                            // file that is not clean class runs, bucket-sorts.
                            let runs = if order == super::class_sort::CLASS_ROW_ORDER {
                                super::class_sort::restore_class_runs(&source, &target, host_sort_bucket_rows())?
                            } else {
                                None
                            };
                            if runs.is_none() {
                                super::host_sort::restore_time_order(&scratch, &source, &target, host_sort_bucket_rows())?;
                            }
                        } else {
                            std::os::unix::fs::symlink(source, target)?;
                        }
                        if whole_minute {
                            let partials = std::fs::canonicalize(input.dir.join(crate::parts::format::PARTIAL_ROLLUP_FILE))?;
                            std::os::unix::fs::symlink(partials.parent().context("partials directory")?, dir.join(
                                Path::new(crate::parts::format::PARTIAL_ROLLUP_FILE).parent().context("partials directory")?))?;
                        }
                        let mut part = input.part.clone();
                        part.part_id = crate::parts::format::PartId::new(now_ms)?;
                        part.rows = file.rows;
                        part.min_time_us = file.min_time_us;
                        part.max_time_us = file.max_time_us;
                        part.data_bytes = file.bytes;
                        part.row_groups = file.row_groups;
                        part.data_files = 1;
                        expanded.push(MergeInput { part, dir });
                    }
                    continue;
                }
            }
            expanded.push(input.clone());
        }
        current = expanded;
        let mut pass = 0;
        let open_cap = open_inputs_cap();
        while current.len() > open_cap && max_overlap(&current) > open_cap {
            pass += 1;
            current.sort_by_key(|i| (i.part.min_time_us, i.part.max_time_us));
            let mut next = Vec::new();
            for group in current.chunks(open_cap) {
                if group.len() == 1 {
                    next.push(group[0].clone());
                    continue;
                }
                let dir = scratch.join(format!("pass-{pass}"));
                std::fs::create_dir_all(&dir)?;
                let Some(merged) = merge_streaming(
                    &dir, tenant_id, level, event_hour, group, group, schema.clone(), schema_fingerprint, signer_key_id,
                    build, now_ms, false, force_row_partials, true, HourOrder::TIME, filter.clone(),
                )? else {
                    // Every row of this group was filtered out.
                    filtered_out += group.iter().map(|input| input.part.rows).sum::<u64>();
                    continue;
                };
                duplicates += merged.duplicates_dropped;
                filtered_out += merged.filtered_out;
                filter_rewritten += merged.filter_rewritten;
                let record = &merged.finished.record;
                next.push(MergeInput {
                    part: PartRef::from_record(record, &"0".repeat(64), true),
                    dir: merged.finished.dir.clone(),
                });
            }
            current = next;
        }
        if current.is_empty() {
            return Ok(None);
        }
        let cluster_output = level == Level::Hour || (level == Level::Minute && std::env::var("NANO_LAKE_COMPACTION_LAYOUT").is_ok());
        // NAN-4664: every sealed hour writes its multi-class families
        // class-sorted, so `class_uid` row-group statistics prune; endpoint
        // families are host-sorted instead when NAN-3412 is on.
        // NAN-4688: a minute part (the open hour, which agents hunt most) is
        // class-sorted too, in its one data file: no extra objects.
        let order = HourOrder {
            host_sort: (level == Level::Hour).then(super::host_sort::group_rows).flatten(),
            class_sort: matches!(level, Level::Hour | Level::Minute),
        };
        // The minute class sort runs through the family spool as a single
        // (overflow) family; its time-sorted fallback keeps today's layout.
        let sorted_cluster_output = cluster_output || level == Level::Minute;
        // NAN-3412: the host/class-sorted layout is an optimization. It is
        // written under the scratch directory (removed below, so a failed
        // attempt leaves nothing) and moved into `work_dir` once finished;
        // any failure (e.g. a family past one data file) redoes the merge in
        // the time-sorted layout instead of wedging the hour.
        let attempt = match order {
            order if !order.is_time() => {
                let dir = scratch.join("hour-sorted");
                std::fs::create_dir_all(&dir)?;
                match merge_streaming(
                    &dir, tenant_id, level, event_hour, &current, inputs, schema.clone(), schema_fingerprint, signer_key_id,
                    build, now_ms, sorted_cluster_output, force_row_partials, false, order, filter.clone(),
                ).and_then(|merged| merged.context("hour-sorted filtered merge is empty")).and_then(|mut merged| {
                    let target = work_dir.join(merged.finished.dir.file_name().context("merge output has no directory name")?);
                    std::fs::rename(&merged.finished.dir, &target)?;
                    merged.finished.dir = target;
                    Ok(merged)
                }) {
                    Ok(merged) => Some(merged),
                    // NAN-4755: out of memory is not a layout problem: the
                    // time-sorted redo would run into the same limit.
                    Err(error) if super::merge_quota::is_memory_pressure(&error) => return Err(error),
                    Err(error) => {
                        tracing::warn!(error = %format!("{error:#}"), event_hour, "host/class-sorted hour merge failed; writing time-sorted layout");
                        None
                    }
                }
            }
            _ => None,
        };
        let mut merged = match attempt {
            Some(merged) => merged,
            None => match merge_streaming(
                work_dir, tenant_id, level, event_hour, &current, inputs, schema.clone(), schema_fingerprint, signer_key_id,
                build, now_ms, cluster_output, force_row_partials, false, HourOrder::TIME, filter.clone(),
            )? {
                Some(merged) => merged,
                None => return Ok(None),
            },
        };
        duplicates += merged.duplicates_dropped;
        filtered_out += merged.filtered_out;
        filter_rewritten += merged.filter_rewritten;
        let record = &mut merged.finished.record;
        record.dedup.duplicates_dropped = duplicates;
        ensure!(
            record.rows + duplicates + filtered_out == inputs.iter().map(|i| i.part.rows).sum::<u64>(),
            "merge output rows do not reconcile with its inputs"
        );
        record.validate()?;
        merged.duplicates_dropped = duplicates;
        merged.filtered_out = filtered_out;
        merged.filter_rewritten = filter_rewritten;
        Ok(Some(merged))
    })();
    super::merge_quota::charge(0, 0);
    let _ = std::fs::remove_dir_all(&scratch);
    result
}

/// One streaming k-way merge of `cursor_inputs`, recording `recorded_inputs`
/// as the part's inputs (they differ only when intermediates were used).
///
/// Partials normally merge from the inputs' partial files. Those count every
/// input row, so when the merge drops duplicate rows the pass is redone with
/// partials rebuilt from the output rows (rare: duplicates only slip past the
/// ingest window under a fencing race).
#[allow(clippy::too_many_arguments)]
fn merge_streaming(
    work_dir: &Path,
    tenant_id: &str,
    level: Level,
    event_hour: i32,
    cursor_inputs: &[MergeInput],
    recorded_inputs: &[MergeInput],
    schema: SchemaRef,
    schema_fingerprint: &str,
    signer_key_id: &str,
    build: &str,
    now_ms: i64,
    cluster_output: bool,
    force_row_partials: bool,
    intermediate: bool,
    order: HourOrder,
    filter: Option<std::sync::Arc<dyn RowFilter>>,
) -> Result<Option<MergeResult>> {
    let Some(result) = merge_streaming_mode(work_dir, tenant_id, level, event_hour, cursor_inputs,
        recorded_inputs, schema.clone(), schema_fingerprint, signer_key_id, build, now_ms,
        cluster_output, force_row_partials, intermediate, false, order, filter.clone())? else {
        return Ok(None);
    };
    if intermediate || std::env::var("NANO_LAKE_COMPACTION_LAYOUT").is_err() {
        return Ok(Some(result));
    }
    let settings = crate::parts::format::ParquetSettings::for_level(level).compaction_layout(
        level, std::env::var("NANO_LAKE_COMPACTION_LAYOUT").ok().as_deref(),
    )?;
    if !crate::parts::format::ParquetSettings::cluster_worthwhile(cursor_inputs.iter().map(|input| input.part.rows).sum(), settings.row_group_rows) {
        // The small-part floor already selected the unchanged legacy layout.
        return Ok(Some(result));
    }
    // Compare actual compressed output, not an estimate of dictionary savings.
    // Both passes consume the same verified inputs and compaction quotas.
    let baseline = merge_streaming_mode(work_dir, tenant_id, level, event_hour, cursor_inputs,
        recorded_inputs, schema, schema_fingerprint, signer_key_id, build, now_ms,
        level == Level::Hour, force_row_partials, intermediate, true, HourOrder::TIME, filter)?
        .context("layout baseline of a non-empty filtered merge is empty")?;
    ensure!(result.finished.record.rows == baseline.finished.record.rows
        && result.finished.record.merkle_root == baseline.finished.record.merkle_root
        && result.duplicates_dropped == baseline.duplicates_dropped,
        "layout comparison changed logical output");
    let experimental_bytes = result.finished.record.files.data_bytes();
    let baseline_bytes = baseline.finished.record.files.data_bytes();
    if experimental_bytes as u128 * 100 > baseline_bytes as u128 * 105 {
        tracing::info!(experimental_bytes, baseline_bytes, "compaction layout exceeded storage cost ceiling; keeping baseline");
        std::fs::remove_dir_all(&result.finished.dir)?;
        Ok(Some(baseline))
    } else {
        std::fs::remove_dir_all(&baseline.finished.dir)?;
        Ok(Some(result))
    }
}

#[allow(clippy::too_many_arguments)]
fn merge_streaming_mode(
    work_dir: &Path,
    tenant_id: &str,
    level: Level,
    event_hour: i32,
    cursor_inputs: &[MergeInput],
    recorded_inputs: &[MergeInput],
    schema: SchemaRef,
    schema_fingerprint: &str,
    signer_key_id: &str,
    build: &str,
    now_ms: i64,
    cluster_output: bool,
    force_row_partials: bool,
    intermediate: bool,
    legacy_layout: bool,
    order: HourOrder,
    filter: Option<std::sync::Arc<dyn RowFilter>>,
) -> Result<Option<MergeResult>> {
    let merged_partials = if force_row_partials || filter.is_some() { PartialSource::FromRows } else {
        PartialSource::Merge(cursor_inputs.iter().map(|i| i.dir.clone()).collect())
    };
    match merge_pass(
        work_dir, tenant_id, level, event_hour, cursor_inputs, recorded_inputs, schema.clone(), schema_fingerprint,
        signer_key_id, build, now_ms, merged_partials, cluster_output, intermediate, legacy_layout, order, filter.clone(),
    )? {
        PassOutcome::Done(result) => Ok(Some(result)),
        PassOutcome::Empty => Ok(None),
        PassOutcome::HadDuplicates => match merge_pass(
            work_dir, tenant_id, level, event_hour, cursor_inputs, recorded_inputs, schema, schema_fingerprint,
            signer_key_id, build, now_ms, PartialSource::FromRows, cluster_output, intermediate, legacy_layout, order, filter,
        )? {
            PassOutcome::Done(result) => Ok(Some(result)),
            PassOutcome::Empty => Ok(None),
            PassOutcome::HadDuplicates => anyhow::bail!("merge partial rebuild did not finish"),
        },
    }
}

enum PassOutcome {
    Done(MergeResult),
    /// Duplicates were dropped while partials were being merged from files.
    HadDuplicates,
    /// NAN-3867: a row filter removed every input row.
    Empty,
}

#[allow(clippy::too_many_arguments)]
fn merge_pass(
    work_dir: &Path,
    tenant_id: &str,
    level: Level,
    event_hour: i32,
    cursor_inputs: &[MergeInput],
    recorded_inputs: &[MergeInput],
    schema: SchemaRef,
    schema_fingerprint: &str,
    signer_key_id: &str,
    build: &str,
    now_ms: i64,
    partial_source: PartialSource,
    cluster_output: bool,
    intermediate: bool,
    legacy_layout: bool,
    order: HourOrder,
    filter: Option<std::sync::Arc<dyn RowFilter>>,
) -> Result<PassOutcome> {
    let inputs = cursor_inputs;
    let tally = std::sync::Arc::new(FilterTally::default());
    let active = filter.map(|filter| ActiveFilter { filter, tally: std::sync::Arc::clone(&tally) });
    let merging_partial_files = matches!(partial_source, PartialSource::Merge(_));
    let rows_in: u64 = inputs.iter().map(|i| i.part.rows).sum();
    // Decoded OCSF rows are ~5–10 KB wide: hold at most ~32k decoded input
    // rows in total across the (at most MAX_OPEN_INPUTS) open readers.
    let open_cap = open_inputs_cap();
    let batch_rows = (decode_window_rows() / inputs.len().min(open_cap)).clamp(256 >> shape_shift(), 8_192);
    let draft = PartDraft {
        tenant_id: tenant_id.to_string(),
        signer_key_id: signer_key_id.to_string(),
        level,
        event_hour,
        schema: schema.clone(),
        schema_fingerprint: schema_fingerprint.to_string(),
        inputs: PartInputs::Parts {
            parts: recorded_inputs
                .iter()
                .map(|i| InputPart {
                    part_id: i.part.part_id.clone(),
                    level: i.part.level,
                    provenance_sha256: i.part.provenance_sha256.clone(),
                    rows: i.part.rows,
                    merkle_root: i.part.merkle_root.clone(),
                })
                .collect(),
        },
        admission: None,
        rows_in: recorded_inputs.iter().map(|i| i.part.rows).sum(),
        duplicates_dropped: 0,
        window: DedupWindow::Exact,
        build: build.to_string(),
    };
    let base = crate::parts::format::ParquetSettings::for_level(level);
    let settings = if legacy_layout { base } else { base.compaction_layout(
        level, std::env::var("NANO_LAKE_COMPACTION_LAYOUT").ok().as_deref(),
    )?.for_compaction_rows(level, rows_in) };
    let class_clustering = !legacy_layout && std::env::var("NANO_LAKE_COMPACTION_LAYOUT").is_ok()
        && crate::parts::format::ParquetSettings::cluster_worthwhile(rows_in, settings.row_group_rows);
    // NAN-4688: a final minute part may be class-sorted as one family.
    let minute_class_sort = level == Level::Minute && order.class_sort && !intermediate && !legacy_layout;
    let cluster_output = cluster_output && (level == Level::Hour || class_clustering || minute_class_sort);
    // NAN-3437: class families of a final hour output in the layout above
    // (the default one unless the experiment is set), in this one pass.
    let class_families = !class_clustering && cluster_output && level == Level::Hour && !intermediate
        && !legacy_layout && class_families_enabled();
    let mut writer = PartWriter::create_with(work_dir, draft, partial_source, now_ms, rows_in, settings)?;
    if intermediate {
        writer.without_row_digests();
    }
    // A class-sorted minute part keeps its one data file: no source
    // families, every row in the one overflow family.
    let mut spool = cluster_output.then(|| if level == Level::Minute && !class_clustering { Ok(BTreeSet::new()) } else { choose_families(recorded_inputs) }
        .and_then(|chosen| FamilySpool::new(work_dir, schema.clone(), chosen))).transpose()?;
    if let Some(spool) = &mut spool {
        if class_clustering {
            // The pre-count only picks file families: if it cannot read an
            // input, every row overflows (one unprunable file family) rather
            // than failing the merge.
            let families = choose_class_families(inputs).unwrap_or_else(|error| {
                tracing::warn!(error = %format!("{error:#}"), "class family pre-count failed; clustering into overflow only");
                BTreeSet::new()
            });
            spool.set_class_families(families)?;
        } else if class_families {
            // As above: a failed pre-count only loses the class split; the
            // hour still gets the source-family layout.
            let families = count_input_classes(inputs)
                .map(|counts| rank_class_families_above(counts, CLASS_FAMILY_MIN_ROWS))
                .unwrap_or_else(|error| {
                    tracing::warn!(error = %format!("{error:#}"), "class family pre-count failed; writing source families only");
                    BTreeSet::new()
                });
            spool.set_class_families_with_source_rest(families)?;
        }
        let final_hour = level == Level::Hour && !intermediate && !legacy_layout;
        if let Some(group_rows) = order.host_sort.filter(|_| final_hour) {
            spool.set_host_sort(group_rows, host_sort_bucket_rows());
        }
        if order.class_sort && (final_hour || minute_class_sort) {
            spool.set_class_sort(class_sort_max_rows(inputs));
        }
    }
    let streams = inputs.iter().map(|input| Ok((local_data_files(&input.dir)?, input.part.min_time_us)))
        .collect::<Result<Vec<_>>>()?;
    // Lazy opening: inputs in min_time order; an input opens only once the
    // merge frontier reaches its first row time.
    let mut order = (0..streams.len()).collect::<Vec<_>>();
    order.sort_by_key(|&i| (streams[i].1, i));
    let mut next_to_open = 0_usize;
    let mut cursors: Vec<Option<Cursor>> = (0..streams.len()).map(|_| None).collect();
    let mut heap = BinaryHeap::new();
    let mut open_now = 0_usize;
    let mut picks: Vec<(usize, usize)> = Vec::with_capacity(batch_rows);
    let mut last: Option<(i64, String)> = None;
    let mut duplicates = 0_u64;
    let mut emitted = 0_u64;
    let flush = |picks: &mut Vec<(usize, usize)>, cursors: &[Option<Cursor>], writer: &mut PartWriter, spool: &mut Option<FamilySpool>| -> Result<()> {
        if picks.is_empty() {
            return Ok(());
        }
        let mut slots = Vec::new();
        let mut slot_of = vec![usize::MAX; cursors.len()];
        for (index, cursor) in cursors.iter().enumerate() {
            if let Some(batch) = cursor.as_ref().and_then(|c| c.batch.as_ref()) {
                slot_of[index] = slots.len();
                slots.push(batch);
            }
        }
        let indices = picks.iter().map(|(c, r)| (slot_of[*c], *r)).collect::<Vec<_>>();
        let out = arrow_select::interleave::interleave_record_batch(&slots, &indices)?;
        if let Some(spool) = spool { spool.write(&out)?; } else { writer.write(&out)?; }
        picks.clear();
        Ok(())
    };
    loop {
        // Open every input whose first row could precede the heap's minimum.
        while next_to_open < order.len() {
            let index = order[next_to_open];
            let frontier = heap.peek().map(|Reverse((t, _, _)): &Reverse<(i64, String, usize)>| *t);
            if frontier.is_some_and(|t| streams[index].1 > t) {
                break;
            }
            next_to_open += 1;
            let mut cursor = Cursor::open(streams[index].0.clone(), batch_rows, active.clone())?;
            if cursor.advance(&schema)? {
                let (t, u) = cursor.key();
                heap.push(Reverse((t, u.to_string(), index)));
                open_now += 1;
                ensure!(open_now <= open_cap, "merge exceeded the open reader cap");
                cursors[index] = Some(cursor);
            }
        }
        let Some(Reverse((time, uid, index))) = heap.pop() else { break };
        let row = cursors[index].as_ref().expect("open").row;
        if last.as_ref().is_some_and(|(t, u)| *t == time && *u == uid) {
            duplicates += 1;
        } else {
            picks.push((index, row));
            emitted += 1;
            last = Some((time, uid));
        }
        if picks.len() >= batch_rows {
            flush(&mut picks, &cursors, &mut writer, &mut spool)?;
        }
        let cursor = cursors[index].as_mut().expect("open");
        cursor.row += 1;
        let batch_len = cursor.batch.as_ref().map_or(0, RecordBatch::num_rows);
        if cursor.row >= batch_len {
            // Rows picked from this batch must be written before it is replaced.
            flush(&mut picks, &cursors, &mut writer, &mut spool)?;
            let cursor = cursors[index].as_mut().expect("open");
            if !cursor.advance(&schema)? {
                cursors[index] = None; // exhausted: release the reader
                open_now -= 1;
                continue;
            }
        }
        let cursor = cursors[index].as_ref().expect("open");
        let (t, u) = cursor.key();
        heap.push(Reverse((t, u.to_string(), index)));
    }
    flush(&mut picks, &cursors, &mut writer, &mut spool)?;
    let filtered_out = tally.removed.load(std::sync::atomic::Ordering::Relaxed);
    let filter_rewritten = tally.rewritten.load(std::sync::atomic::Ordering::Relaxed);
    if emitted == 0 {
        // Only a filter can empty a merge; a part may not be empty.
        ensure!(active.is_some() && filtered_out + duplicates == rows_in, "merge produced no rows");
        let dir = writer.dir().to_path_buf();
        drop(spool);
        drop(writer);
        let _ = std::fs::remove_dir_all(dir);
        return Ok(PassOutcome::Empty);
    }
    let logical_merkle = spool.map(|spool| spool.finish_into(&mut writer)).transpose()?;
    if let Some(root) = logical_merkle { writer.set_logical_merkle_root(root)?; }
    ensure!(writer.rows() + duplicates + filtered_out == rows_in, "merge output rows do not reconcile with its inputs");
    if duplicates > 0 && merging_partial_files {
        let dir = writer.dir().to_path_buf();
        drop(writer);
        let _ = std::fs::remove_dir_all(dir);
        return Ok(PassOutcome::HadDuplicates);
    }
    let mut finished = writer.finish()?;
    let mut common: Option<BTreeSet<String>> = None;
    for input in recorded_inputs {
        let path = input.dir.join(crate::parts::format::PROVENANCE_FILE);
        let fields = match std::fs::read(path) {
            Ok(bytes) => {
                let signed: SignedProvenance = serde_json::from_slice(&bytes).context("parse merge input provenance")?;
                ensure!(signed.record.part_id == input.part.part_id, "merge input provenance names another part");
                signed.record.lowercased_at_rest.into_iter().collect::<BTreeSet<_>>()
            }
            // Local synthetic merge inputs may not have a signed record;
            // the safe guarantee for such inputs is the empty set.
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => BTreeSet::new(),
            Err(error) => return Err(error.into()),
        };
        common = Some(match common { Some(prior) => prior.intersection(&fields).cloned().collect(), None => fields });
    }
    finished.record.lowercased_at_rest = common.unwrap_or_default().into_iter().collect();
    finished.record.validate()?;
    Ok(PassOutcome::Done(MergeResult { finished, duplicates_dropped: duplicates, filtered_out, filter_rewritten }))
}

#[cfg(test)]
pub(crate) fn cluster_fixture(work_dir: &Path, batch: &RecordBatch, writer: &mut PartWriter, classes: bool) -> Result<()> {
    let sources = log_source_strings(batch)?;
    let chosen = sources.iter().flatten().map(str::to_owned).collect::<BTreeSet<_>>().into_iter().take(MAX_DEDICATED_FAMILIES).collect();
    let mut spool = FamilySpool::new(work_dir, batch.schema(), chosen)?;
    if classes {
        let mut counts = ClassCounts::new();
        count_source_classes(batch, &mut counts)?;
        spool.set_class_families(rank_class_families(counts))?;
    }
    for offset in (0..batch.num_rows()).step_by(4096) { spool.write(&batch.slice(offset, 4096.min(batch.num_rows() - offset)))?; }
    let root = spool.finish_into(writer)?;
    writer.set_logical_merkle_root(root)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parts::format::PartId;

    #[test]
    fn sliced_ipc_batches_do_not_falsely_stop_either_merge_write_path() {
        use super::super::merge_quota::{batch_bytes, memory_guard_scope, MEMORY_PROBE_FOR_TEST};
        use super::super::schema::{decode, infer_schema};
        use crate::parts::provenance::tests::{TENANT, SIGNER};
        use std::sync::Arc;
        const LIMIT: u64 = 8 * 1024 * 1024;
        fn memory() -> Option<(u64, u64)> { Some((0, LIMIT)) }
        let events = (0..4_096).map(|row| serde_json::json!({
            "time": "2026-10-28T00:00:00Z",
            "metadata": { "uid": format!("u{row:05}"), "log_source": "sysmon" },
            "message": "m".repeat(1_024),
        })).collect::<Vec<_>>();
        let refs = events.iter().collect::<Vec<_>>();
        let schema = Arc::new(infer_schema(&refs).unwrap());
        let rows = decode(schema.clone(), &refs).unwrap();
        let mut ipc = Vec::new();
        {
            let mut stream = StreamWriter::try_new(&mut ipc, &schema).unwrap();
            stream.write(&rows).unwrap();
            stream.finish().unwrap();
        }
        let decoded = StreamReader::try_new(std::io::Cursor::new(ipc), None).unwrap().next().unwrap().unwrap();
        let slice = decoded.slice(2_048, 16);
        assert!(slice.get_array_memory_size() as u64 * 2 > LIMIT,
            "fixture must falsely stop with the retained-buffer measure");
        assert!(batch_bytes(&slice) * 2 < LIMIT / 100,
            "the slice itself needs well under the limit");
        let dir = tempfile::tempdir().unwrap();
        let mut spool = FamilySpool::new(dir.path(), schema.clone(), BTreeSet::new()).unwrap();
        let draft = PartDraft {
            tenant_id: TENANT.into(), signer_key_id: SIGNER.into(), level: Level::Hour, event_hour: 498_096,
            schema: schema.clone(), schema_fingerprint: crate::parts::format::schema_fingerprint(&schema).unwrap(),
            inputs: PartInputs::Parts { parts: vec![InputPart { part_id: PartId::new(1).unwrap(), level: Level::L0,
                provenance_sha256: "0".repeat(64), rows: 16, merkle_root: "0".repeat(64) }] },
            admission: None, rows_in: 16, duplicates_dropped: 0, window: DedupWindow::Exact, build: "test".into(),
        };
        let mut writer = PartWriter::create(dir.path(), draft, PartialSource::FromRows, 2, 16).unwrap();
        MEMORY_PROBE_FOR_TEST.set(Some(memory));
        // A fresh scope forces each site's first check, independent of cadence.
        let spooled = { let _guard = memory_guard_scope(); spool.write(&slice) };
        let written = { let _guard = memory_guard_scope(); writer.write(&slice) };
        MEMORY_PROBE_FOR_TEST.set(None);
        spooled.expect("a small IPC slice fits the family spool");
        written.expect("a small IPC slice fits the part writer");
        assert_eq!(writer.rows(), 16);
    }

    #[test]
    fn family_spool_caps_dedicated_sources() {
        use arrow_array::{ArrayRef, StructArray};
        use arrow_schema::{DataType, Field, Schema};
        use std::sync::Arc;
        let metadata = StructArray::from(vec![
            (Arc::new(Field::new("uid", DataType::Utf8, false)),
                Arc::new(StringArray::from(vec!["u0", "u1", "u2", "u3", "u4", "u5", "u6", "u7", "u8"])) as ArrayRef),
            (Arc::new(Field::new("log_source", DataType::Utf8, false)),
                Arc::new(StringArray::from(vec!["s0", "s1", "s2", "s3", "s4", "s5", "s6", "s7", "s8"])) as ArrayRef),
        ]);
        let schema = Arc::new(Schema::new(vec![Field::new("metadata", metadata.data_type().clone(), false)]));
        let batch = RecordBatch::try_new(schema.clone(), vec![Arc::new(metadata)]).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let chosen = (0..MAX_DEDICATED_FAMILIES).map(|i| format!("s{i}")).collect();
        let mut spool = FamilySpool::new(dir.path(), schema, chosen).unwrap();
        spool.write(&batch).unwrap();
        assert_eq!(spool.chosen.len(), MAX_DEDICATED_FAMILIES);
        assert_eq!(spool.streams.len(), MAX_DEDICATED_FAMILIES + 1);
        assert!(spool.streams.contains_key(&Family::Overflow));
    }

    /// NAN-3188: class families are the largest `(source, class)` pairs by
    /// rows over the inputs, not the first seen: a big class whose first row
    /// arrives after more than MAX_DEDICATED_CLASS_FAMILIES small ones still
    /// gets a dedicated (class-prunable) file. Ties break by key.
    #[test]
    fn class_families_are_chosen_by_volume_not_arrival() {
        use std::sync::Arc;
        use super::super::schema::{decode, infer_schema};
        use super::super::writer::{sort_by_time_uid, PartDraft};
        use crate::parts::provenance::tests::{TENANT, SIGNER};
        // 20 small classes (5 rows each) first, then one late class of 400.
        let mut events = Vec::new();
        for small in 0..20 {
            for row in 0..5 {
                events.push((1_000 + small, small * 5 + row));
            }
        }
        for row in 0..400 {
            events.push((4_001, 100 + row));
        }
        let events = events.into_iter().map(|(class, second)| serde_json::json!({
            "time": chrono::DateTime::from_timestamp(second as i64, 0).unwrap().to_rfc3339(),
            "class_uid": class,
            "metadata": { "uid": format!("u{second:05}"), "log_source": "sysmon" },
        })).collect::<Vec<_>>();
        let refs = events.iter().collect::<Vec<_>>();
        let schema = Arc::new(infer_schema(&refs).unwrap());
        let rows = sort_by_time_uid(&decode(schema.clone(), &refs).unwrap()).unwrap();
        let dir = tempfile::tempdir().unwrap();
        // A real merge input: the pre-count reads its data file's two leaves.
        let draft = PartDraft {
            tenant_id: TENANT.into(), signer_key_id: SIGNER.into(), level: Level::Minute, event_hour: 0,
            schema: schema.clone(), schema_fingerprint: crate::parts::format::schema_fingerprint(&schema).unwrap(),
            inputs: PartInputs::Parts { parts: vec![InputPart { part_id: PartId::new(1).unwrap(), level: Level::L0, provenance_sha256: "0".repeat(64), rows: 500, merkle_root: "0".repeat(64) }] },
            admission: None, rows_in: 500, duplicates_dropped: 0, window: DedupWindow::Exact, build: "test".into(),
        };
        let mut writer = PartWriter::create(dir.path(), draft, PartialSource::FromRows, 2, 500).unwrap();
        writer.write(&rows).unwrap();
        let part = writer.finish().unwrap();
        let inputs = [MergeInput { part: PartRef::from_record(&part.record, &"0".repeat(64), true), dir: part.dir.clone() }];
        let chosen = choose_class_families(&inputs).unwrap();
        assert_eq!(chosen.len(), MAX_DEDICATED_CLASS_FAMILIES);
        assert!(chosen.contains(&("sysmon".to_string(), 4_001)), "late large class is dedicated: {chosen:?}");
        // The 14 remaining slots go to the smallest keys among the 5-row ties.
        let expected = std::iter::once(("sysmon".to_string(), 4_001))
            .chain((1_000..1_014).map(|class| ("sysmon".to_string(), class)))
            .collect::<BTreeSet<_>>();
        assert_eq!(chosen, expected);
        assert_eq!(choose_class_families(&inputs).unwrap(), chosen, "deterministic");

        // The spool routes exactly those families; the rest overflow.
        let mut spool = FamilySpool::new(dir.path(), schema, BTreeSet::new()).unwrap();
        spool.set_class_families(chosen).unwrap();
        spool.write(&rows).unwrap();
        assert_eq!(spool.streams.len(), MAX_DEDICATED_CLASS_FAMILIES + 1);
        assert!(spool.streams.contains_key(&Family::SourceClass("sysmon".into(), 4_001)));
        assert!(spool.streams.contains_key(&Family::Overflow));
        assert!(!spool.streams.contains_key(&Family::SourceClass("sysmon".into(), 1_019)));
    }

    #[tokio::test]
    async fn source_class_files_preserve_rows_root_and_rewrite_order() {
        use std::sync::Arc;
        use super::super::schema::{decode, infer_schema};
        use super::super::writer::{publish_parts, sort_by_time_uid};
        use crate::parts::provenance::tests::{signer, TENANT, SIGNER};
        let dir = tempfile::tempdir().unwrap();
        let events = (0..90).map(|row| serde_json::json!({
            "time": chrono::DateTime::from_timestamp(row, 0).unwrap().to_rfc3339(),
            "class_uid": 1000 + row % 3,
            "metadata": { "uid": format!("u{row:04}"), "log_source": "sysmon" },
            "message": format!("event {row}"),
        })).collect::<Vec<_>>();
        let refs = events.iter().collect::<Vec<_>>();
        let schema = Arc::new(infer_schema(&refs).unwrap());
        let rows = sort_by_time_uid(&decode(schema.clone(), &refs).unwrap()).unwrap();
        let draft = PartDraft {
            tenant_id: TENANT.into(), signer_key_id: SIGNER.into(), level: Level::Hour, event_hour: 0,
            schema: schema.clone(), schema_fingerprint: crate::parts::format::schema_fingerprint(&schema).unwrap(),
            inputs: PartInputs::Parts { parts: vec![InputPart { part_id: crate::parts::format::PartId::new(1).unwrap(), level: Level::Minute, provenance_sha256: "0".repeat(64), rows: 90, merkle_root: "0".repeat(64) }] },
            admission: None, rows_in: 90, duplicates_dropped: 0, window: DedupWindow::Exact, build: "test".into(),
        };
        let mut writer = PartWriter::create(dir.path(), draft.clone(), PartialSource::FromRows, 2, 90).unwrap();
        let mut spool = FamilySpool::new(dir.path(), schema.clone(), BTreeSet::new()).unwrap();
        let mut counts = ClassCounts::new();
        count_source_classes(&rows, &mut counts).unwrap();
        spool.set_class_families(rank_class_families(counts)).unwrap();
        // Batch boundaries do not change the family assignment or sort order.
        spool.write(&rows.slice(0, 43)).unwrap();
        spool.write(&rows.slice(43, 47)).unwrap();
        let root = spool.finish_into(&mut writer).unwrap();
        writer.set_logical_merkle_root(root).unwrap();
        let clustered = writer.finish().unwrap();
        assert_eq!(clustered.record.files.data.len(), 3);
        for file in &clustered.record.files.data {
            assert_eq!(file.rows, 30);
            assert!(file.class_id.is_some());
            let reader = ParquetRecordBatchReaderBuilder::try_new(File::open(clustered.dir.join(&file.name)).unwrap()).unwrap().build().unwrap();
            for batch in reader {
                let batch = batch.unwrap();
                let classes = batch.column_by_name("class_uid").unwrap().as_any().downcast_ref::<arrow_array::Int64Array>().unwrap();
                assert!(classes.iter().all(|value| value == file.class_id));
            }
        }
        let mut direct = PartWriter::create(dir.path(), draft, PartialSource::FromRows, 3, 90).unwrap();
        direct.write(&rows).unwrap();
        let direct = direct.finish().unwrap();
        assert_eq!(direct.record.merkle_root, clustered.record.merkle_root);
        let store = crate::parts::part_log::LocalObjectStore::new(dir.path().join("store")).unwrap();
        let owner = signer(1);
        let part = publish_parts(&store, &owner, &owner.trusted(), &[clustered]).await.unwrap().remove(0);
        let merged = merge_parts(dir.path(), TENANT, Level::Minute, 0,
            &[MergeInput { dir: dir.path().join(part.part_id.as_str()), part }], schema.clone(),
            &crate::parts::format::schema_fingerprint(&schema).unwrap(), SIGNER, "test", 4).unwrap();
        assert_eq!(merged.finished.record.rows, 90);
        assert_eq!(merged.finished.record.merkle_root, direct.record.merkle_root);
    }

    /// Exercises both physical encodings on enough rows to pass admission.
    #[test]
    #[ignore]
    fn production_layout_compares_compressed_bytes_and_preserves_root() {
        use std::sync::Arc;
        use super::super::schema::{decode, infer_schema};
        use super::super::writer::sort_by_time_uid;
        use crate::parts::provenance::tests::{TENANT, SIGNER};
        assert_eq!(std::env::var("NANO_LAKE_COMPACTION_LAYOUT").unwrap(), "8192:67108864");
        let dir = tempfile::tempdir().unwrap();
        let events = (0..65_536).map(|row| serde_json::json!({
            "time": chrono::DateTime::from_timestamp(row / 20, 0).unwrap().to_rfc3339(),
            "class_uid": 1000 + row % 16,
            "metadata": { "uid": format!("u{row:06}"), "log_source": "sysmon" },
            "device": { "hostname": format!("host-{}", row % 700) },
            "message": format!("event {} {}", row, "same payload ".repeat(30)),
        })).collect::<Vec<_>>();
        let refs = events.iter().collect::<Vec<_>>();
        let schema = Arc::new(infer_schema(&refs).unwrap());
        let fingerprint = crate::parts::format::schema_fingerprint(&schema).unwrap();
        let rows = sort_by_time_uid(&decode(schema.clone(), &refs).unwrap()).unwrap();
        let draft = PartDraft {
            tenant_id: TENANT.into(), signer_key_id: SIGNER.into(), level: Level::Minute, event_hour: 0,
            schema: schema.clone(), schema_fingerprint: fingerprint.clone(),
            inputs: PartInputs::Parts { parts: vec![InputPart { part_id: crate::parts::format::PartId::new(1).unwrap(), level: Level::L0, provenance_sha256: "0".repeat(64), rows: 65_536, merkle_root: "0".repeat(64) }] },
            admission: None, rows_in: 65_536, duplicates_dropped: 0, window: DedupWindow::Exact, build: "test".into(),
        };
        let mut writer = PartWriter::create(dir.path(), draft, PartialSource::FromRows, 2, 65_536).unwrap();
        writer.write(&rows).unwrap();
        let part = writer.finish().unwrap();
        let inputs = [MergeInput { part: PartRef::from_record(&part.record, &"0".repeat(64), true), dir: part.dir }];
        let baseline = merge_streaming_mode(dir.path(), TENANT, Level::Hour, 0, &inputs, &inputs,
            schema.clone(), &fingerprint, SIGNER, "test", 3, true, true, false, true, HourOrder::TIME, None).unwrap().unwrap();
        let output = merge_streaming(dir.path(), TENANT, Level::Hour, 0, &inputs, &inputs,
            schema, &fingerprint, SIGNER, "test", 4, true, true, false, HourOrder::TIME, None).unwrap().unwrap();
        assert_eq!(output.finished.record.rows, 65_536);
        assert_eq!(output.finished.record.merkle_root, baseline.finished.record.merkle_root);
        assert!(output.finished.record.files.data_bytes() as u128 * 100 <= baseline.finished.record.files.data_bytes() as u128 * 105);
        let mut seen = Vec::new();
        for file in &output.finished.record.files.data {
            for batch in ParquetRecordBatchReaderBuilder::try_new(File::open(output.finished.dir.join(&file.name)).unwrap()).unwrap().build().unwrap() {
                seen.extend(uid_strings(&batch.unwrap()).unwrap().iter().flatten().map(str::to_owned));
            }
        }
        seen.sort();
        assert_eq!(seen, (0..65_536).map(|row| format!("u{row:06}")).collect::<Vec<_>>());
        eprintln!("production-cost-gate baseline_bytes={} output_bytes={} files={} class_files={}",
            baseline.finished.record.files.data_bytes(), output.finished.record.files.data_bytes(),
            output.finished.record.files.data.len(), output.finished.record.files.data.iter().filter(|file| file.class_id.is_some()).count());
    }

    /// NAN-3412 fixture: 24,000 rows over hour 0, two thirds sysmon (one
    /// heavy host, one rare host, host-less rows, 300 others), the rest
    /// apache (not an endpoint source).
    fn host_sort_fixture(dir: &Path) -> (SchemaRef, String, MergeInput) {
        host_sort_fixture_rows(dir, 24_000)
    }

    fn host_sort_fixture_rows(dir: &Path, rows: usize) -> (SchemaRef, String, MergeInput) {
        use std::sync::Arc;
        use super::super::schema::{decode, infer_schema};
        use super::super::writer::sort_by_time_uid;
        use crate::parts::provenance::tests::{TENANT, SIGNER};
        let events = (0..rows).map(|row| {
            let source = if row % 3 == 2 { "apache" } else { "windows_sysmon" };
            let host = match row {
                _ if row % 5 == 0 => Some("ws-heavy.corp.local".to_string()),
                1_003 | 9_004 | 23_998 => Some("ws-rare.corp.local".to_string()),
                _ if row % 97 == 0 => None,
                _ => Some(format!("ws-{:03}.corp.local", (row * 7) % 300)),
            };
            let mut event = serde_json::json!({
                // Ties on time are broken by uid.
                "time": chrono::DateTime::from_timestamp_micros(((row / 2) * (7_200_000_000 / rows)) as i64).unwrap().to_rfc3339(),
                "class_uid": 1001 + (row % 2) as i64,
                "metadata": { "uid": format!("u{row:06}"), "log_source": source },
                "message": format!("event {row}"),
                "raw_data": format!("raw event {row} {}", hex::encode(<sha2::Sha256 as sha2::Digest>::digest(row.to_le_bytes()))),
            });
            if let Some(host) = host { event["device"] = serde_json::json!({ "hostname": host }); }
            event
        }).collect::<Vec<_>>();
        let refs = events.iter().collect::<Vec<_>>();
        let schema = Arc::new(infer_schema(&refs).unwrap());
        let fingerprint = crate::parts::format::schema_fingerprint(&schema).unwrap();
        let batch = sort_by_time_uid(&decode(schema.clone(), &refs).unwrap()).unwrap();
        let draft = PartDraft {
            tenant_id: TENANT.into(), signer_key_id: SIGNER.into(), level: Level::Minute, event_hour: 0,
            schema: schema.clone(), schema_fingerprint: fingerprint.clone(),
            inputs: PartInputs::Parts { parts: vec![InputPart { part_id: PartId::new(1).unwrap(), level: Level::L0, provenance_sha256: "0".repeat(64), rows: rows as u64, merkle_root: "0".repeat(64) }] },
            admission: None, rows_in: rows as u64, duplicates_dropped: 0, window: DedupWindow::Exact, build: "test".into(),
        };
        let mut writer = PartWriter::create(dir, draft, PartialSource::FromRows, 2, rows as u64).unwrap();
        writer.write(&batch).unwrap();
        let part = writer.finish().unwrap();
        (schema, fingerprint, MergeInput { part: PartRef::from_record(&part.record, &"0".repeat(64), true), dir: part.dir })
    }

    /// `(host, time, uid)` of every row of one data file, in file order.
    fn file_rows(path: &Path) -> Vec<(Option<String>, i64, String)> {
        let mut out = Vec::new();
        for batch in ParquetRecordBatchReaderBuilder::try_new(File::open(path).unwrap()).unwrap().build().unwrap() {
            let batch = batch.unwrap();
            let hosts = super::super::host_sort::host_strings(&batch).unwrap();
            let uids = uid_strings(&batch).unwrap();
            let time = batch.column_by_name("time").unwrap();
            for row in 0..batch.num_rows() {
                out.push(((!hosts.is_null(row)).then(|| hosts.value(row).to_string()),
                    event_time_us_from_array(time.as_ref(), row).unwrap(), uids.value(row).to_string()));
            }
        }
        out
    }

    /// What a reader returns for `device.hostname=host` over `[from, to]`,
    /// newest first, at most `head` rows (plus the total count). Row groups
    /// whose `device.hostname` or `time` statistics exclude the predicate
    /// are skipped, as the Parquet reader's filter push-down does; the
    /// second value counts the row groups read.
    fn pruned_query(dir: &Path, host: Option<&str>, from: i64, to: i64, head: usize) -> (Vec<String>, usize, usize) {
        use parquet::file::reader::{FileReader, SerializedFileReader};
        use parquet::file::statistics::Statistics;
        let (mut hits, mut kept) = (Vec::new(), 0);
        for path in local_data_files(dir).unwrap() {
            let reader = SerializedFileReader::new(File::open(&path).unwrap()).unwrap();
            let columns = reader.metadata().file_metadata().schema_descr().columns().to_vec();
            let index = |name: &str| columns.iter().position(|column| column.path().string() == name);
            let mut groups = Vec::new();
            for (group, metadata) in reader.metadata().row_groups().iter().enumerate() {
                let host_excluded = host.zip(index("device.hostname")).is_some_and(|(host, column)| match metadata.column(column).statistics() {
                    Some(Statistics::ByteArray(stats)) => stats.min_opt().zip(stats.max_opt())
                        .is_some_and(|(min, max)| host.as_bytes() < min.data() || host.as_bytes() > max.data())
                        || stats.min_opt().is_none(),
                    _ => false,
                });
                let time_excluded = index("time").is_some_and(|column| match metadata.column(column).statistics() {
                    Some(Statistics::Int64(stats)) => stats.min_opt().zip(stats.max_opt()).is_some_and(|(min, max)| *max < from || *min > to),
                    _ => false,
                });
                if !host_excluded && !time_excluded { groups.push(group); }
            }
            kept += groups.len();
            if groups.is_empty() { continue; }
            let reader = ParquetRecordBatchReaderBuilder::try_new(File::open(&path).unwrap()).unwrap().with_row_groups(groups).build().unwrap();
            for batch in reader {
                let batch = batch.unwrap();
                let hosts = super::super::host_sort::host_strings(&batch).unwrap();
                let uids = uid_strings(&batch).unwrap();
                let time = batch.column_by_name("time").unwrap();
                for row in 0..batch.num_rows() {
                    let t = event_time_us_from_array(time.as_ref(), row).unwrap();
                    let h = (!hosts.is_null(row)).then(|| hosts.value(row));
                    if (host.is_none() || h == host) && (from..=to).contains(&t) { hits.push((t, uids.value(row).to_string())); }
                }
            }
        }
        let count = hits.len();
        hits.sort_by(|a, b| b.cmp(a));
        (hits.into_iter().take(head).map(|(_, uid)| uid).collect(), count, kept)
    }

    /// NAN-3412: the host-sorted hour holds exactly the rows (and logical
    /// root) of the time-sorted one; only endpoint files change order; each
    /// returns identical host / time-range / head / newest-first answers;
    /// row-group statistics confine a host to a few groups; and a later
    /// rewrite of the hour restores time order for the k-way merge.
    #[tokio::test]
    async fn host_sorted_endpoint_hour_matches_time_sorted_and_prunes() {
        use crate::parts::provenance::tests::{signer, TENANT, SIGNER};
        use super::super::host_sort::{file_row_order, HOST_ROW_ORDER};
        use super::super::writer::publish_parts;
        let dir = tempfile::tempdir().unwrap();
        let (schema, fingerprint, input) = host_sort_fixture(dir.path());
        let inputs = [input];
        let off = merge_streaming(dir.path(), TENANT, Level::Hour, 0, &inputs, &inputs, schema.clone(), &fingerprint,
            SIGNER, "test", 3, true, false, false, HourOrder::TIME, None).unwrap().unwrap().finished;
        let on = merge_streaming(dir.path(), TENANT, Level::Hour, 0, &inputs, &inputs, schema.clone(), &fingerprint,
            SIGNER, "test", 4, true, false, false, HourOrder::host(1_024), None).unwrap().unwrap().finished;
        assert_eq!(on.record.rows, 24_000);
        assert_eq!(on.record.merkle_root, off.record.merkle_root, "same logical rows");
        assert_eq!(on.record.hours[0].merkle_root, off.record.hours[0].merkle_root);
        assert_eq!((on.record.min_time_us, on.record.max_time_us), (off.record.min_time_us, off.record.max_time_us));
        let mut all_off = Vec::new();
        let mut all_on = Vec::new();
        for (record, part_dir, rows) in [(&off.record, &off.dir, &mut all_off), (&on.record, &on.dir, &mut all_on)] {
            for file in &record.files.data {
                let path = part_dir.join(&file.name);
                let file_rows = file_rows(&path);
                let host_sorted = file.log_sources.as_deref() == Some(&["windows_sysmon".to_string()][..]) && record.part_id == on.record.part_id;
                assert_eq!(file_row_order(&path).unwrap().as_deref(), host_sorted.then_some(HOST_ROW_ORDER), "{}", file.name);
                if host_sorted {
                    assert!(file_rows.windows(2).all(|w| w[0] < w[1]), "strict (host, time, uid) order");
                    assert!(file.row_groups >= 16, "small row groups: {}", file.row_groups);
                } else {
                    assert!(file_rows.windows(2).all(|w| (w[0].1, &w[0].2) < (w[1].1, &w[1].2)), "strict (time, uid) order");
                }
                // The signed bounds stay exact for any row order.
                assert_eq!(file.min_time_us, file_rows.iter().map(|r| r.1).min().unwrap());
                assert_eq!(file.max_time_us, file_rows.iter().map(|r| r.1).max().unwrap());
                assert_eq!(file.rows as usize, file_rows.len());
                rows.extend(file_rows);
            }
        }
        all_off.sort();
        all_on.sort();
        assert_eq!(all_on, all_off, "identical row sets");
        // The apache file is untouched: same rows in the same order.
        let apache = |record: &crate::parts::provenance::ProvenanceRecord, part_dir: &Path| record.files.data.iter()
            .find(|file| file.log_sources.as_deref() == Some(&["apache".to_string()][..]))
            .map(|file| file_rows(&part_dir.join(&file.name))).unwrap();
        assert_eq!(apache(&on.record, &on.dir), apache(&off.record, &off.dir));

        let (start, end) = (on.record.min_time_us, on.record.max_time_us);
        let mid = start + (end - start) / 2;
        let windows = [(start, end), (start, mid), (mid - 600_000_000, mid + 600_000_000), (end - 60_000_000, end)];
        for host in [Some("ws-rare.corp.local"), Some("ws-heavy.corp.local"), Some("ws-017.corp.local"), Some("ws-absent.corp.local"), None] {
            for (from, to) in windows {
                for head in [1, 50, 100_000] {
                    let (want, want_count, _) = pruned_query(&off.dir, host, from, to, head);
                    let (got, got_count, _) = pruned_query(&on.dir, host, from, to, head);
                    assert_eq!(got, want, "{host:?} [{from}, {to}] head {head}");
                    assert_eq!(got_count, want_count, "{host:?} [{from}, {to}] count");
                }
            }
        }
        let (rare, count, kept) = pruned_query(&on.dir, Some("ws-rare.corp.local"), start, end, 100);
        assert_eq!((rare, count), (vec!["u023998".to_string(), "u009004".into(), "u001003".into()], 3));
        let groups = on.record.files.data.iter().map(|file| file.row_groups as usize).sum::<usize>();
        // The rare host's rows sit in one or two row groups of the sysmon
        // file; it lies outside the apache file's host range.
        assert!(kept <= 2, "rare host keeps {kept} of {groups} row groups");
        let (_, heavy, kept_heavy) = pruned_query(&on.dir, Some("ws-heavy.corp.local"), start, end, 1);
        assert_eq!(heavy, 24_000 / 5);
        let sysmon_heavy = (0..24_000).filter(|row| row % 5 == 0 && row % 3 != 2).count();
        assert!(kept_heavy <= sysmon_heavy.div_ceil(1_024) + 3, "heavy host keeps {kept_heavy} of {groups}");
        let (_, _, kept_time_sorted) = pruned_query(&off.dir, Some("ws-rare.corp.local"), start, end, 100);
        let sysmon_groups = |record: &crate::parts::provenance::ProvenanceRecord| record.files.data.iter()
            .filter(|file| file.log_sources.as_deref() == Some(&["windows_sysmon".to_string()][..]))
            .map(|file| file.row_groups as usize).sum::<usize>();
        assert_eq!(kept_time_sorted, sysmon_groups(&off.record), "every time-sorted sysmon group spans every host");

        // A later rewrite of the published host-sorted hour (late data,
        // reindex, sidecar backfill) restores time order for the merge.
        let store = crate::parts::part_log::LocalObjectStore::new(dir.path().join("store")).unwrap();
        let owner = signer(1);
        let part = publish_parts(&store, &owner, &owner.trusted(), &[on]).await.unwrap().remove(0);
        let rewrite = merge_parts(dir.path(), TENANT, Level::Hour, 0,
            &[MergeInput { dir: dir.path().join(part.part_id.as_str()), part }], schema, &fingerprint, SIGNER, "test", 5).unwrap();
        assert_eq!(rewrite.duplicates_dropped, 0);
        assert_eq!(rewrite.finished.record.rows, 24_000);
        assert_eq!(rewrite.finished.record.merkle_root, off.record.merkle_root);
        let mut all_rewrite = Vec::new();
        for file in &rewrite.finished.record.files.data {
            let path = rewrite.finished.dir.join(&file.name);
            // Host sort unset: no host order. NAN-4664: the two-class
            // families are class-sorted, so each class run is time-ordered.
            assert_eq!(file_row_order(&path).unwrap().as_deref(), Some(super::super::class_sort::CLASS_ROW_ORDER), "{}", file.name);
            let classes = class_file_rows(&path);
            assert!(classes.windows(2).all(|w| w[0] < w[1]), "strict (class, time, uid) order");
            all_rewrite.extend(file_rows(&path));
        }
        all_rewrite.sort();
        assert_eq!(all_rewrite, all_off);
    }

    /// `(class_uid, time, uid)` of every row of one data file, in file order.
    fn class_file_rows(path: &Path) -> Vec<(Option<i64>, i64, String)> {
        let mut out = Vec::new();
        for batch in ParquetRecordBatchReaderBuilder::try_new(File::open(path).unwrap()).unwrap().build().unwrap() {
            let batch = batch.unwrap();
            let classes = super::super::class_sort::class_keys(&batch).unwrap();
            let uids = uid_strings(&batch).unwrap();
            let time = batch.column_by_name("time").unwrap();
            for row in 0..batch.num_rows() {
                out.push((classes[row], event_time_us_from_array(time.as_ref(), row).unwrap(), uids.value(row).to_string()));
            }
        }
        out
    }

    /// NAN-4664 synthetic OCSF hour: four sources, eleven classes with a
    /// realistic skew (process and network activity dominate), class-specific
    /// fields, arrival interleaved in time. No tenant data.
    fn class_sort_fixture(dir: &Path, rows: usize) -> (SchemaRef, String, MergeInput) {
        class_sort_fixture_with(dir, rows, true)
    }

    /// `with_source = false`: no row carries `metadata.log_source`, so the
    /// whole hour is the overflow family.
    fn class_sort_fixture_with(dir: &Path, rows: usize, with_source: bool) -> (SchemaRef, String, MergeInput) {
        use std::sync::Arc;
        use super::super::schema::{decode, infer_schema};
        use super::super::writer::sort_by_time_uid;
        use crate::parts::provenance::tests::{TENANT, SIGNER};
        // (source, class, weight)
        const MIX: &[(&str, i64, usize)] = &[
            ("windows_sysmon", 1007, 30), ("windows_sysmon", 4001, 22), ("windows_sysmon", 1001, 8),
            ("windows_sysmon", 4003, 6), ("windows_sysmon", 1006, 3), ("windows_event", 3002, 9),
            ("windows_event", 1007, 4), ("windows_event", 3005, 2), ("aws_cloudtrail", 6003, 8),
            ("aws_cloudtrail", 3002, 2), ("zeek", 4001, 4), ("zeek", 4003, 1), ("zeek", 4002, 1),
        ];
        let total: usize = MIX.iter().map(|(_, _, weight)| weight).sum();
        let pick = |row: usize| {
            let mut slot = (row.wrapping_mul(2_654_435_761) >> 7) % total;
            for entry in MIX { if slot < entry.2 { return *entry; } slot -= entry.2; }
            unreachable!()
        };
        let events = (0..rows).map(|row| {
            let (source, class, _) = pick(row);
            let host = format!("ws-{:03}.corp.local", (row * 7) % 250);
            let mut event = serde_json::json!({
                "time": chrono::DateTime::from_timestamp_micros((row as i64) * (3_599_000_000 / rows as i64)).unwrap().to_rfc3339(),
                "class_uid": class,
                "category_uid": class / 1000,
                "activity_id": 1 + (row % 3) as i64,
                "severity_id": 1,
                "metadata": { "uid": format!("u{row:07}"), "log_source": source, "product": { "name": source } },
                "device": { "hostname": host },
                "message": format!("{source} {class} event {}", row % 1_000),
            });
            if !with_source {
                event["metadata"] = serde_json::json!({ "uid": format!("u{row:07}") });
            }
            match class {
                1007 => {
                    event["process"] = serde_json::json!({ "name": (["powershell.exe", "cmd.exe", "svchost.exe", "chrome.exe"][row % 4]),
                        "cmd_line": format!("C:\\Windows\\System32\\x.exe -arg {}", row % 300), "pid": (row % 9_000) as i64 });
                    event["actor"] = serde_json::json!({ "user": { "name": format!("user{}", row % 40) } });
                }
                4001 | 4002 => {
                    event["src_endpoint"] = serde_json::json!({ "ip": format!("10.0.{}.{}", row % 20, row % 250), "port": (49_152 + row % 10_000) as i64 });
                    event["dst_endpoint"] = serde_json::json!({ "ip": format!("203.0.113.{}", row % 200), "port": ([443, 80, 445, 53][row % 4]) });
                }
                4003 => { event["query"] = serde_json::json!({ "hostname": format!("host{}.example.com", row % 500) }); }
                1001 | 1006 => { event["file"] = serde_json::json!({ "path": format!("C:\\Users\\u{}\\f{}.txt", row % 40, row % 900), "name": format!("f{}.txt", row % 900) }); }
                3002 | 3005 => {
                    event["user"] = serde_json::json!({ "name": format!("user{}", row % 40) });
                    event["status_id"] = serde_json::json!(1 + (row % 2) as i64);
                }
                _ => { event["api"] = serde_json::json!({ "operation": (["GetObject", "PutObject", "AssumeRole"][row % 3]) }); }
            }
            event
        }).collect::<Vec<_>>();
        let refs = events.iter().collect::<Vec<_>>();
        // Without sources the column still exists (null in every row), as
        // in a tenant schema that has seen `metadata.log_source` before.
        let template = serde_json::json!({ "metadata": { "log_source": "template" } });
        let schema = Arc::new(infer_schema(&refs.iter().copied().chain((!with_source).then_some(&template)).collect::<Vec<_>>()).unwrap());
        let fingerprint = crate::parts::format::schema_fingerprint(&schema).unwrap();
        let batch = sort_by_time_uid(&decode(schema.clone(), &refs).unwrap()).unwrap();
        let draft = PartDraft {
            tenant_id: TENANT.into(), signer_key_id: SIGNER.into(), level: Level::Minute, event_hour: 0,
            schema: schema.clone(), schema_fingerprint: fingerprint.clone(),
            inputs: PartInputs::Parts { parts: vec![InputPart { part_id: PartId::new(1).unwrap(), level: Level::L0, provenance_sha256: "0".repeat(64), rows: rows as u64, merkle_root: "0".repeat(64) }] },
            admission: None, rows_in: rows as u64, duplicates_dropped: 0, window: DedupWindow::Exact, build: "test".into(),
        };
        let mut writer = PartWriter::create(dir, draft, PartialSource::FromRows, 2, rows as u64).unwrap();
        writer.write(&batch).unwrap();
        let part = writer.finish().unwrap();
        (schema, fingerprint, MergeInput { part: PartRef::from_record(&part.record, &"0".repeat(64), true), dir: part.dir })
    }

    /// `(row groups, row groups chDB's min/max push-down keeps for
    /// class_uid ∈ classes, rows in the kept groups, matching rows)` over a
    /// part directory. The keep rule is ClickHouse's KeyCondition on
    /// row-group statistics: a group survives unless every class lies
    /// outside its `[min, max]`.
    fn class_pruning(dir: &Path, classes: &[i64]) -> (usize, usize, u64, u64) {
        class_pruning_files(&local_data_files(dir).unwrap(), classes)
    }

    /// [`class_pruning`] over the given data files.
    fn class_pruning_files(paths: &[PathBuf], classes: &[i64]) -> (usize, usize, u64, u64) {
        use parquet::file::reader::{FileReader, SerializedFileReader};
        use parquet::file::statistics::Statistics;
        let (mut groups, mut kept, mut kept_rows, mut matching) = (0, 0, 0, 0);
        for path in paths {
            let reader = SerializedFileReader::new(File::open(path).unwrap()).unwrap();
            let column = reader.metadata().file_metadata().schema_descr().columns().iter()
                .position(|column| column.path().string() == "class_uid").unwrap();
            for metadata in reader.metadata().row_groups() {
                groups += 1;
                let bounds = match metadata.column(column).statistics() {
                    Some(Statistics::Int64(stats)) => stats.min_opt().copied().zip(stats.max_opt().copied()),
                    Some(Statistics::Int32(stats)) => stats.min_opt().map(|v| i64::from(*v)).zip(stats.max_opt().map(|v| i64::from(*v))),
                    other => panic!("class_uid has no integer row-group statistics: {other:?}"),
                };
                let (min, max) = bounds.expect("class_uid min/max present");
                if classes.iter().any(|class| (min..=max).contains(class)) {
                    kept += 1;
                    kept_rows += metadata.num_rows() as u64;
                }
            }
            matching += class_file_rows(path).iter().filter(|row| row.0.is_some_and(|class| classes.contains(&class))).count() as u64;
        }
        (groups, kept, kept_rows, matching)
    }

    /// NAN-4664: a sealed hour (production `merge_parts` path) writes its
    /// multi-class families in `(class_uid, time, uid)` order: the same rows
    /// and logical root as the time-sorted layout, no row lost or
    /// duplicated, strict order in every tagged file, `class_uid` page
    /// statistics, far fewer row groups kept for a class filter, and a later
    /// rewrite (late data, reindex, erasure) still merges it exactly.
    #[tokio::test]
    async fn class_sorted_hour_matches_time_sorted_and_prunes() {
        use crate::parts::provenance::tests::{signer, TENANT, SIGNER};
        use super::super::class_sort::CLASS_ROW_ORDER;
        use super::super::host_sort::file_row_order;
        use super::super::writer::publish_parts;
        const ROWS: usize = 200_000;
        let dir = tempfile::tempdir().unwrap();
        let (schema, fingerprint, input) = class_sort_fixture(dir.path(), ROWS);
        let inputs = [input];
        let off = merge_streaming(dir.path(), TENANT, Level::Hour, 0, &inputs, &inputs, schema.clone(), &fingerprint,
            SIGNER, "test", 3, true, false, false, HourOrder::TIME, None).unwrap().unwrap().finished;
        let on = merge_parts(dir.path(), TENANT, Level::Hour, 0, &inputs, schema.clone(), &fingerprint, SIGNER, "test", 4)
            .unwrap().finished;
        assert_eq!(on.record.rows, ROWS as u64);
        assert_eq!(on.record.merkle_root, off.record.merkle_root, "same logical rows");
        assert_eq!(on.record.hours[0].merkle_root, off.record.hours[0].merkle_root);
        assert_eq!(on.record.files.data.len(), off.record.files.data.len(), "same families");
        let (mut all_on, mut all_off) = (Vec::new(), Vec::new());
        for file in &on.record.files.data {
            let path = on.dir.join(&file.name);
            let rows = class_file_rows(&path);
            // NAN-4688: class families are on by default; a dedicated
            // `(source, class)` file holds one class and stays time-sorted.
            if rows.iter().map(|row| row.0).collect::<BTreeSet<_>>().len() == 1 {
                assert_eq!(file_row_order(&path).unwrap(), None, "{}", file.name);
                assert!(rows.windows(2).all(|w| (w[0].1, &w[0].2) < (w[1].1, &w[1].2)), "strict (time, uid) order in {}", file.name);
            } else {
                assert_eq!(file_row_order(&path).unwrap().as_deref(), Some(CLASS_ROW_ORDER), "{}: a multi-class family", file.name);
                assert!(rows.windows(2).all(|w| w[0] < w[1]), "strict (class, time, uid) order in {}", file.name);
            }
            assert_eq!(file.rows as usize, rows.len());
            assert_eq!(file.min_time_us, rows.iter().map(|r| r.1).min().unwrap());
            assert_eq!(file.max_time_us, rows.iter().map(|r| r.1).max().unwrap());
            // Page statistics (column index) on class_uid, not only chunk stats.
            let reader = ParquetRecordBatchReaderBuilder::try_new_with_options(File::open(&path).unwrap(),
                parquet::arrow::arrow_reader::ArrowReaderOptions::new().with_page_index_policy(parquet::file::metadata::PageIndexPolicy::Required)).unwrap();
            let column = reader.parquet_schema().columns().iter().position(|c| c.path().string() == "class_uid").unwrap();
            let index = reader.metadata().column_index().expect("page index written");
            assert!(index.iter().all(|group| !matches!(group[column], parquet::file::page_index::column_index::ColumnIndexMetaData::NONE)),
                "class_uid has page statistics in {}", file.name);
            all_on.extend(rows);
        }
        for file in &off.record.files.data {
            let path = off.dir.join(&file.name);
            assert_eq!(file_row_order(&path).unwrap(), None);
            all_off.extend(class_file_rows(&path));
        }
        let unique = all_on.iter().map(|row| row.2.clone()).collect::<BTreeSet<_>>();
        assert_eq!(unique.len(), ROWS, "no row duplicated or lost");
        all_on.sort();
        all_off.sort();
        assert_eq!(all_on, all_off, "identical row sets");

        let bytes = |record: &crate::parts::provenance::ProvenanceRecord| record.files.data_bytes() as f64 / record.rows as f64;
        let (time_bpr, class_bpr) = (bytes(&off.record), bytes(&on.record));
        eprintln!("NAN-4664 bytes/row: (time, uid) {time_bpr:.1}, (class_uid, time, uid) {class_bpr:.1} ({:+.1}%)",
            (class_bpr / time_bpr - 1.0) * 100.0);
        for classes in [&[1007][..], &[4001], &[3002], &[6003], &[3002, 1007], &[4003, 4002]] {
            let (groups_off, kept_off, rows_off, matching) = class_pruning(&off.dir, classes);
            let (groups_on, kept_on, rows_on, matching_on) = class_pruning(&on.dir, classes);
            assert_eq!(matching_on, matching, "{classes:?}: same matching rows");
            assert!(kept_on <= kept_off, "{classes:?}: {kept_on} > {kept_off}");
            eprintln!("NAN-4664 class_uid IN {classes:?}: time-sorted keeps {kept_off}/{groups_off} groups ({rows_off} rows), \
                class-sorted keeps {kept_on}/{groups_on} ({rows_on} rows); {matching} rows match");
        }
        // A 30% class keeps few groups beyond its own rows; a 2% class keeps
        // at most the groups its run touches in each family file.
        let (_, kept, kept_rows, matching) = class_pruning(&on.dir, &[1007]);
        assert!(kept_rows < matching * 2, "1007 reads {kept_rows} rows for {matching}");
        // NAN-4688: with class families on by default the time-sorted hour
        // already has the class's own file, so the strict comparison is
        // against the pre-class-family layout (hours written before it).
        let legacy = with_class_families(Some(false), || merge_streaming(dir.path(), TENANT, Level::Hour, 0, &inputs, &inputs,
            schema.clone(), &fingerprint, SIGNER, "test", 6, true, false, false, HourOrder::TIME, None)).unwrap().unwrap().finished;
        assert!(kept < class_pruning(&legacy.dir, &[1007]).1, "1007 prunes groups");
        let (_, _, kept_rows, matching) = class_pruning(&on.dir, &[6003]);
        assert!(kept_rows <= matching + 2 * 65_536, "6003 reads {kept_rows} rows for {matching}");

        // A later rewrite of the published class-sorted hour restores time
        // order for the k-way merge and re-sorts the same rows.
        let store = crate::parts::part_log::LocalObjectStore::new(dir.path().join("store")).unwrap();
        let owner = signer(1);
        let part = publish_parts(&store, &owner, &owner.trusted(), &[on]).await.unwrap().remove(0);
        let rewrite = merge_parts(dir.path(), TENANT, Level::Hour, 0,
            &[MergeInput { dir: dir.path().join(part.part_id.as_str()), part }], schema, &fingerprint, SIGNER, "test", 5).unwrap();
        assert_eq!(rewrite.duplicates_dropped, 0);
        assert_eq!(rewrite.finished.record.rows, ROWS as u64);
        assert_eq!(rewrite.finished.record.merkle_root, off.record.merkle_root);
        let mut all_rewrite = Vec::new();
        for file in &rewrite.finished.record.files.data {
            let rows = class_file_rows(&rewrite.finished.dir.join(&file.name));
            assert!(rows.windows(2).all(|w| w[0] < w[1]));
            all_rewrite.extend(rows);
        }
        all_rewrite.sort();
        assert_eq!(all_rewrite, all_off);
    }

    /// NAN-4664 review: an hour whose rows carry no `metadata.log_source` is
    /// one overflow file (no `log_sources` in the record) that is still
    /// class-sorted. A later rewrite (late data, reindex, erasure) must
    /// restore its time order first, or the k-way merge reads it out of order
    /// and the hour can never merge again.
    #[tokio::test]
    async fn class_sorted_overflow_only_hour_merges_again() {
        use crate::parts::provenance::tests::{signer, TENANT, SIGNER};
        use super::super::class_sort::CLASS_ROW_ORDER;
        use super::super::host_sort::file_row_order;
        use super::super::writer::publish_parts;
        const ROWS: usize = 30_000;
        let dir = tempfile::tempdir().unwrap();
        let (schema, fingerprint, input) = class_sort_fixture_with(dir.path(), ROWS, false);
        let inputs = [input];
        let off = merge_streaming(dir.path(), TENANT, Level::Hour, 0, &inputs, &inputs, schema.clone(), &fingerprint,
            SIGNER, "test", 3, true, false, false, HourOrder::TIME, None).unwrap().unwrap().finished;
        let on = merge_parts(dir.path(), TENANT, Level::Hour, 0, &inputs, schema.clone(), &fingerprint, SIGNER, "test", 4)
            .unwrap().finished;
        assert_eq!(on.record.files.data.len(), 1, "overflow only");
        assert!(on.record.files.data[0].log_sources.is_none());
        assert_eq!(file_row_order(&on.dir.join(&on.record.files.data[0].name)).unwrap().as_deref(), Some(CLASS_ROW_ORDER));
        let store = crate::parts::part_log::LocalObjectStore::new(dir.path().join("store")).unwrap();
        let owner = signer(1);
        let part = publish_parts(&store, &owner, &owner.trusted(), &[on]).await.unwrap().remove(0);
        let rewrite = merge_parts(dir.path(), TENANT, Level::Hour, 0,
            &[MergeInput { dir: dir.path().join(part.part_id.as_str()), part }], schema, &fingerprint, SIGNER, "test", 5).unwrap();
        assert_eq!(rewrite.duplicates_dropped, 0);
        assert_eq!(rewrite.finished.record.rows, ROWS as u64);
        assert_eq!(rewrite.finished.record.merkle_root, off.record.merkle_root);
        let mut all_rewrite = Vec::new();
        for file in &rewrite.finished.record.files.data {
            let rows = class_file_rows(&rewrite.finished.dir.join(&file.name));
            assert!(rows.windows(2).all(|w| w[0] < w[1]));
            all_rewrite.extend(rows);
        }
        let mut all_off = off.record.files.data.iter().flat_map(|file| class_file_rows(&off.dir.join(&file.name))).collect::<Vec<_>>();
        all_rewrite.sort();
        all_off.sort();
        assert_eq!(all_rewrite, all_off);
    }

    /// A single-class family keeps the time-sorted layout (no tag, byte-
    /// identical order), and a family over the class-sort row cap too.
    #[test]
    fn class_sort_skips_single_class_and_oversized_families() {
        use crate::parts::provenance::tests::{TENANT, SIGNER};
        use super::super::host_sort::file_row_order;
        let dir = tempfile::tempdir().unwrap();
        let (schema, fingerprint, input) = class_sort_fixture(dir.path(), 20_000);
        let inputs = [input];
        let mut spool = FamilySpool::new(dir.path(), schema.clone(), BTreeSet::from(["windows_sysmon".to_string()])).unwrap();
        spool.set_class_sort(1);
        let rows = class_file_rows(&local_data_files(&inputs[0].dir).unwrap()[0]);
        assert!(rows.len() > 1);
        let family = Family::Named("windows_sysmon".into());
        let mut counts = super::super::class_sort::ClassCounts::default();
        counts.add_batch(&[Some(1007), Some(4001)], 0..2);
        spool.class_counts.insert(family.clone(), counts);
        assert!(!spool.class_sorted(&family), "over the row cap");
        spool.set_class_sort(u64::MAX);
        assert!(spool.class_sorted(&family));
        let mut single = super::super::class_sort::ClassCounts::default();
        single.add_batch(&[Some(1007), Some(1007)], 0..2);
        spool.class_counts.insert(family.clone(), single);
        assert!(!spool.class_sorted(&family), "one class");
        let mut junk = super::super::class_sort::ClassCounts::default();
        let keys = (0..=super::super::class_sort::MAX_SORT_CLASSES as i64).map(Some).collect::<Vec<_>>();
        junk.add_batch(&keys, 0..keys.len());
        spool.class_counts.insert(family.clone(), junk);
        assert!(!spool.class_sorted(&family), "too many distinct classes");
        // The estimate scales the inputs' bytes per row to half a data file.
        let max = class_sort_max_rows(&inputs);
        let per_row = inputs[0].part.data_bytes as f64 / inputs[0].part.rows as f64;
        assert!(((max as f64 * per_row) - CLASS_SORT_MAX_FAMILY_BYTES as f64).abs() / (CLASS_SORT_MAX_FAMILY_BYTES as f64) < 0.01);
        // NAN-4688: a multi-class minute part is one class-sorted file.
        let merged = merge_parts(dir.path(), TENANT, Level::Minute, 0, &inputs, schema, &fingerprint, SIGNER, "test", 9).unwrap();
        assert_eq!(merged.finished.record.files.data.len(), 1);
        for file in &merged.finished.record.files.data {
            assert_eq!(file_row_order(&merged.finished.dir.join(&file.name)).unwrap().as_deref(),
                Some(super::super::class_sort::CLASS_ROW_ORDER), "minute parts are class-sorted");
        }
    }

    /// NAN-4688 acceptance on the production merge path (`merge_parts`, real
    /// publish, real planner file stage): a `class_uid` hunt skips other-class
    /// data in BOTH the open hour (its minute parts: class-sorted single
    /// files, so other classes' row groups fall to chDB's min/max push-down)
    /// and the sealed hour (class-family files the planner drops by their
    /// signed `class_id`). Same rows, uids, logical Merkle roots and dedupe
    /// as the time-sorted layout at every step, and the sealed hour merges
    /// cleanly from class-sorted minute inputs.
    #[tokio::test]
    async fn class_uid_hunt_skips_other_classes_in_open_and_sealed_hours() {
        use crate::part_query::prune::file_family_may_match;
        use crate::parts::provenance::tests::{signer, TENANT, SIGNER};
        use crate::planner::CandidateHint;
        use super::super::class_sort::CLASS_ROW_ORDER;
        use super::super::host_sort::file_row_order;
        use super::super::writer::publish_parts;
        const ROWS: usize = 120_000;
        let dir = tempfile::tempdir().unwrap();
        let store = crate::parts::part_log::LocalObjectStore::new(dir.path().join("store")).unwrap();
        let owner = signer(1);
        let (schema, fingerprint, input) = class_sort_fixture(dir.path(), ROWS);
        let all_input = class_file_rows(&local_data_files(&input.dir).unwrap()[0]);
        let mut expected = all_input.clone();
        expected.sort();
        // The input again under other part ids: two copies of every row, so
        // the merge must drop exactly ROWS duplicates (the same dedupe as the
        // time-sorted layout).
        let copy = |id: i64| {
            let mut again = input.clone();
            again.part.part_id = crate::parts::format::PartId::new(id).unwrap();
            again
        };
        let inputs = [input.clone(), copy(77)];

        // Open hour: the minute merge.
        let minute_time = merge_streaming(dir.path(), TENANT, Level::Minute, 0, &inputs, &inputs, schema.clone(), &fingerprint,
            SIGNER, "test", 3, false, false, false, HourOrder::TIME, None).unwrap().unwrap();
        let minute = merge_parts(dir.path(), TENANT, Level::Minute, 0, &inputs, schema.clone(), &fingerprint, SIGNER, "test", 4).unwrap();
        assert_eq!(minute.duplicates_dropped, minute_time.duplicates_dropped);
        assert_eq!(minute.duplicates_dropped, ROWS as u64, "same dedupe");
        let (minute, minute_time) = (minute.finished, minute_time.finished);
        assert_eq!(minute.record.rows, ROWS as u64);
        assert_eq!(minute.record.merkle_root, minute_time.record.merkle_root, "same logical rows");
        assert_eq!(minute.record.hours[0].merkle_root, minute_time.record.hours[0].merkle_root);
        assert_eq!(minute.record.files.data.len(), 1, "no extra objects: one data file");
        assert_eq!(minute.record.files.all().len(), minute_time.record.files.all().len(), "no extra objects: same file set");
        // The partials (rollup, prevalence, entity ranges, …) do not depend
        // on the row order: byte-identical to the time-sorted minute's.
        let partials = |record: &crate::parts::provenance::ProvenanceRecord| record.files.partials.iter()
            .map(|p| (p.name.clone(), p.rows, p.sha256.clone())).collect::<Vec<_>>();
        assert_eq!(partials(&minute.record), partials(&minute_time.record), "same minute partials");
        let file = &minute.record.files.data[0];
        let path = minute.dir.join(&file.name);
        assert_eq!(file_row_order(&path).unwrap().as_deref(), Some(CLASS_ROW_ORDER));
        let rows = class_file_rows(&path);
        assert!(rows.windows(2).all(|w| w[0] < w[1]), "strict (class, time, uid) order");
        assert_eq!((file.min_time_us, file.max_time_us), (minute_time.record.files.data[0].min_time_us, minute_time.record.files.data[0].max_time_us));
        assert_eq!((minute.record.min_time_us, minute.record.max_time_us), (minute_time.record.min_time_us, minute_time.record.max_time_us));
        let mut sorted = rows.clone();
        sorted.sort();
        assert_eq!(sorted, expected, "the same rows and uids, none lost or duplicated");
        for classes in [&[1007][..], &[4001], &[3002], &[6003]] {
            let (groups_time, kept_time, rows_time, matching) = class_pruning(&minute_time.dir, classes);
            let (groups, kept, kept_rows, matching_sorted) = class_pruning(&minute.dir, classes);
            assert_eq!(matching_sorted, matching);
            eprintln!("NAN-4688 minute class_uid IN {classes:?}: time-sorted keeps {kept_time}/{groups_time} groups ({rows_time} rows), \
                class-sorted keeps {kept}/{groups} ({kept_rows} rows); {matching} rows match");
            assert_eq!(kept_time, groups_time, "{classes:?}: time order prunes nothing");
            assert!(kept < groups, "{classes:?}: the class sort skips other classes' row groups");
            assert!(kept_rows < matching + 2 * crate::parts::format::ROW_GROUP_ROWS as u64, "{classes:?}: {kept_rows} rows read for {matching}");
            // NAN-4772: the planner's footer evidence (what every selection
            // probes) proves the file empty exactly when its statistics
            // keep no group, and leaves a file that may hold the class to
            // chDB's own row-group skipping (no row fence).
            if let [class] = classes {
                let hints = [CandidateHint::Class { value: *class }];
                let evidence = crate::part_query::prune::FileMetadataCache::default()
                    .evidence(&path, &file.sha256, &hints, None, false, true, None).unwrap();
                if kept == 0 {
                    assert_eq!(matching, 0);
                    assert_eq!(evidence.0, Some(vec![false; groups]), "{class}: no group can hold it");
                } else {
                    assert_eq!(evidence.0, None, "{class}: a file that may hold the class is read");
                }
            }
        }
        // A class the open-hour minute part does not hold (its statistics
        // span 1001..6003): the file is proven empty and never handed to
        // chDB.
        let groups = file.row_groups as usize;
        for absent in [1, 9_999] {
            let evidence = crate::part_query::prune::FileMetadataCache::default()
                .evidence(&path, &file.sha256, &[CandidateHint::Class { value: absent }], None, false, true, None).unwrap();
            assert_eq!(evidence.0, Some(vec![false; groups]), "{absent}");
        }

        // Sealed hour: the hour merge of the published (class-sorted) minute
        // part, against the hour merged from the time-sorted minute part.
        let published = publish_parts(&store, &owner, &owner.trusted(), &[minute]).await.unwrap().remove(0);
        let hour = merge_parts(dir.path(), TENANT, Level::Hour, 0,
            &[MergeInput { dir: dir.path().join(published.part_id.as_str()), part: published }], schema.clone(), &fingerprint, SIGNER, "test", 5)
            .unwrap();
        let published_time = publish_parts(&store, &owner, &owner.trusted(), &[minute_time]).await.unwrap().remove(0);
        let hour_time = merge_parts(dir.path(), TENANT, Level::Hour, 0,
            &[MergeInput { dir: dir.path().join(published_time.part_id.as_str()), part: published_time }], schema, &fingerprint, SIGNER, "test", 6)
            .unwrap();
        assert_eq!(hour.duplicates_dropped, 0);
        let (hour, hour_time) = (hour.finished, hour_time.finished);
        assert_eq!(hour.record.rows, ROWS as u64);
        assert_eq!(hour.record.merkle_root, hour_time.record.merkle_root);
        // The class-sorted minute input merged its own partials forward (one
        // data file = the whole part); the result equals the time-sorted
        // minute input's hour partials exactly.
        assert_eq!(partials(&hour.record), partials(&hour_time.record), "same hour partials");
        let shape = |record: &crate::parts::provenance::ProvenanceRecord| record.files.data.iter()
            .map(|file| (file.log_sources.clone(), file.class_id, file.rows, file.min_time_us, file.max_time_us)).collect::<Vec<_>>();
        assert_eq!(shape(&hour.record), shape(&hour_time.record), "same families and time bounds from either minute layout");
        let mut hour_rows = hour.record.files.data.iter().flat_map(|file| class_file_rows(&hour.dir.join(&file.name))).collect::<Vec<_>>();
        hour_rows.sort();
        assert_eq!(hour_rows, expected);
        // The planner's signed file stage drops other-class files; it never
        // drops a file that holds a row of the hunted class. In the files it
        // keeps (the class's own file, and the class-sorted rest files of
        // the other sources), row-group statistics skip the other classes.
        for class in [1007_i64, 4001, 3002] {
            let hints = [CandidateHint::Class { value: class }];
            let (mut pruned, mut kept_rows, mut kept_files) = (0, 0_u64, Vec::new());
            for file in &hour.record.files.data {
                let holds = class_file_rows(&hour.dir.join(&file.name)).iter().any(|row| row.0 == Some(class));
                if file_family_may_match(file.log_sources.as_deref(), file.class_id, &hints) {
                    kept_rows += file.rows;
                    kept_files.push(hour.dir.join(&file.name));
                } else {
                    assert!(!holds, "{class}: pruned {} holds its rows", file.name);
                    pruned += 1;
                }
            }
            let (groups, kept_groups, read_rows, matching) = class_pruning_files(&kept_files, &[class]);
            let (all_groups, _, _, all_matching) = class_pruning(&hour.dir, &[class]);
            assert_eq!(matching, all_matching, "{class}: every matching row is in a kept file");
            eprintln!("NAN-4688 hour class_uid={class}: {pruned}/{} files pruned ({kept_rows}/{ROWS} rows kept); \
                row groups read {kept_groups}/{groups} of the kept files ({all_groups} in the hour), {read_rows} rows read for {matching}",
                hour.record.files.data.len());
            assert!(pruned > 0, "{class}: the sealed hour prunes other-class files");
            assert!(read_rows < matching + kept_files.len() as u64 * crate::parts::format::ROW_GROUP_ROWS as u64,
                "{class}: {read_rows} rows read for {matching}");
            assert!(read_rows < ROWS as u64 / 2, "{class}: {read_rows} rows read");
        }
    }

    /// NAN-4688: the class-run restore of a class-sorted file gives exactly
    /// the bucket-sort restore's rows in the same order (every column, as
    /// JSON), with a tiny per-run batch so runs refill mid-merge; it declines
    /// (writes nothing) for a file that is not clean class runs.
    #[test]
    fn class_run_restore_matches_the_bucket_sort_restore() {
        use crate::parts::provenance::tests::{TENANT, SIGNER};
        use super::super::class_sort::restore_class_runs;
        use super::super::host_sort::restore_time_order;
        let dir = tempfile::tempdir().unwrap();
        let (schema, fingerprint, input) = class_sort_fixture(dir.path(), 30_000);
        let minute = merge_parts(dir.path(), TENANT, Level::Minute, 0, &[input.clone()], schema, &fingerprint, SIGNER, "test", 4)
            .unwrap().finished;
        let source = minute.dir.join(&minute.record.files.data[0].name);
        let json_rows = |path: &Path| {
            let mut out = Vec::new();
            for batch in ParquetRecordBatchReaderBuilder::try_new(File::open(path).unwrap()).unwrap().build().unwrap() {
                let batch = batch.unwrap();
                let mut writer = arrow_json::ArrayWriter::new(Vec::new());
                writer.write(&batch).unwrap();
                writer.finish().unwrap();
                out.extend(serde_json::from_slice::<Vec<serde_json::Value>>(&writer.into_inner()).unwrap());
            }
            out
        };
        let (runs, buckets) = (dir.path().join("runs.parquet"), dir.path().join("buckets.parquet"));
        assert_eq!(restore_class_runs(&source, &runs, 300).unwrap(), Some(30_000));
        assert_eq!(restore_time_order(dir.path(), &source, &buckets, 1_000).unwrap(), 30_000);
        let restored = json_rows(&runs);
        assert_eq!(restored, json_rows(&buckets), "same rows in the same order");
        // Both copies keep the source footer (the NAN-4664 indicator marker
        // makes the merge strip `nano_ioc_*`; without it every batch takes
        // `align`'s JSON round trip) and drop the row-order tag.
        let footer = |path: &Path| ParquetRecordBatchReaderBuilder::try_new(File::open(path).unwrap()).unwrap()
            .metadata().file_metadata().clone();
        assert!(crate::parts::indicators::has_any_marker(&footer(&source)), "fixture writes indicator columns");
        for copy in [&runs, &buckets] {
            assert!(crate::parts::indicators::has_any_marker(&footer(copy)), "restore keeps the indicator marker");
            assert_eq!(super::super::host_sort::file_row_order(copy).unwrap(), None, "restore drops the row-order tag");
        }
        let keys = file_rows(&runs).into_iter().map(|(_, time, uid)| (time, uid)).collect::<Vec<_>>();
        assert!(keys.windows(2).all(|w| w[0] < w[1]), "strict (time, uid) order");
        // A time-sorted file is not class runs: declined, nothing written.
        let time_sorted = local_data_files(&input.dir).unwrap().remove(0);
        let declined = dir.path().join("declined.parquet");
        assert_eq!(restore_class_runs(&time_sorted, &declined, 300).unwrap(), None);
        assert!(!declined.exists());
    }

    /// Merge CPU and wall time of the minute class sort against the
    /// time-sorted minute layout, and of the hour merge from either minute
    /// layout (NAN-4688). Local scale only.
    /// `cargo test --release ... nan4688_merge_cost -- --ignored --nocapture`
    #[tokio::test]
    #[ignore]
    async fn nan4688_merge_cost() {
        use crate::parts::provenance::tests::{signer, TENANT, SIGNER};
        use super::super::writer::publish_parts;
        fn cpu_s() -> f64 {
            let mut usage = std::mem::MaybeUninit::<libc::rusage>::zeroed();
            // SAFETY: getrusage writes the struct it is given.
            unsafe { libc::getrusage(libc::RUSAGE_SELF, usage.as_mut_ptr()) };
            let usage = unsafe { usage.assume_init() };
            let tv = |t: libc::timeval| t.tv_sec as f64 + t.tv_usec as f64 / 1e6;
            tv(usage.ru_utime) + tv(usage.ru_stime)
        }
        let dir = tempfile::tempdir().unwrap();
        let store = crate::parts::part_log::LocalObjectStore::new(dir.path().join("store")).unwrap();
        let owner = signer(1);
        let (schema, fingerprint, input) = class_sort_fixture(dir.path(), 240_000);
        let inputs = [input];
        for round in 0..3_i64 {
            for sorted in [false, true] {
                let (wall, cpu) = (std::time::Instant::now(), cpu_s());
                let minute = if sorted {
                    merge_parts(dir.path(), TENANT, Level::Minute, 0, &inputs, schema.clone(), &fingerprint, SIGNER, "test", 10 + round).unwrap().finished
                } else {
                    merge_streaming(dir.path(), TENANT, Level::Minute, 0, &inputs, &inputs, schema.clone(), &fingerprint,
                        SIGNER, "test", 10 + round, false, false, false, HourOrder::TIME, None).unwrap().unwrap().finished
                };
                let (minute_wall, minute_cpu) = (wall.elapsed().as_secs_f64(), cpu_s() - cpu);
                let bytes = minute.record.files.data_bytes();
                let part = publish_parts(&store, &owner, &owner.trusted(), &[minute]).await.unwrap().remove(0);
                let (wall, cpu) = (std::time::Instant::now(), cpu_s());
                let hour = merge_parts(dir.path(), TENANT, Level::Hour, 0,
                    &[MergeInput { dir: dir.path().join(part.part_id.as_str()), part }], schema.clone(), &fingerprint, SIGNER, "test", 20 + round)
                    .unwrap().finished;
                eprintln!("NAN-4688 round {round} minute_sorted={sorted}: minute merge {minute_wall:.2}s wall {minute_cpu:.2}s cpu {bytes} B; \
                    hour merge {:.2}s wall {:.2}s cpu, {} files", wall.elapsed().as_secs_f64(), cpu_s() - cpu, hour.record.files.data.len());
            }
        }
    }

    /// Merge CPU of the host-sorted layout against the time-sorted one on
    /// one hour of 240,000 rows (two thirds sysmon over ~300 hosts).
    /// `cargo test --release ... host_sort_merge_cost -- --ignored --nocapture`
    #[test]
    #[ignore]
    fn host_sort_merge_cost() {
        use crate::parts::provenance::tests::{TENANT, SIGNER};
        let dir = tempfile::tempdir().unwrap();
        let (schema, fingerprint, input) = host_sort_fixture_rows(dir.path(), 240_000);
        let inputs = [input];
        for (round, host_sort) in [HourOrder::TIME, HourOrder::host(8_192), HourOrder::TIME, HourOrder::host(8_192)].into_iter().enumerate() {
            let started = std::time::Instant::now();
            let merged = merge_streaming(dir.path(), TENANT, Level::Hour, 0, &inputs, &inputs, schema.clone(), &fingerprint,
                SIGNER, "test", 10 + round as i64, true, false, false, host_sort, None).unwrap().unwrap().finished;
            eprintln!("host_sort={host_sort:?} merge {:.2}s bytes={} groups={}", started.elapsed().as_secs_f64(),
                merged.record.files.data_bytes(), merged.record.files.data.iter().map(|file| file.row_groups).sum::<u32>());
        }
    }

    #[test]
    fn host_sorted_writer_rejects_rows_out_of_host_order() {
        use crate::parts::provenance::tests::TENANT;
        let dir = tempfile::tempdir().unwrap();
        let (schema, fingerprint, input) = host_sort_fixture(dir.path());
        let draft = PartDraft {
            tenant_id: TENANT.into(), signer_key_id: "s".into(), level: Level::Hour, event_hour: 0,
            schema, schema_fingerprint: fingerprint,
            inputs: PartInputs::Parts { parts: vec![] }, admission: None, rows_in: 24_000, duplicates_dropped: 0,
            window: DedupWindow::Exact, build: "test".into(),
        };
        let mut writer = PartWriter::create(dir.path(), draft, PartialSource::FromRows, 9, 24_000).unwrap();
        writer.start_host_sorted_family("windows_sysmon", None, 1_024).unwrap();
        // The input is time-sorted, which is not host order.
        let batch = ParquetRecordBatchReaderBuilder::try_new(File::open(local_data_files(&input.dir).unwrap()[0].clone()).unwrap())
            .unwrap().with_batch_size(512).build().unwrap().next().unwrap().unwrap();
        let batch = crate::parts::indicators::strip(batch).unwrap();
        let error = writer.write(&batch).unwrap_err();
        assert!(format!("{error:#}").contains("device.hostname"), "{error:#}");
    }

    /// NAN-3437 fixture: 60,000 rows over hour 0. windows_sysmon holds two
    /// big classes, one mid class and 30 tiny ones; aws_cloudtrail one
    /// mid class; apache one class below the family floor.
    fn class_family_fixture(dir: &Path) -> (SchemaRef, String, MergeInput) {
        use std::sync::Arc;
        use super::super::schema::{decode, infer_schema};
        use super::super::writer::sort_by_time_uid;
        use crate::parts::provenance::tests::{TENANT, SIGNER};
        let rows = 60_000_usize;
        let events = (0..rows).map(|row| {
            let (source, class) = match row % 20 {
                0..=7 => ("windows_sysmon", 201_002),
                8..=12 => ("windows_sysmon", 201_001),
                13 => ("windows_sysmon", 201_005 + (row / 20 % 30) as i64),
                14..=16 => ("aws_cloudtrail", 6_003),
                17 if row % 3 == 0 => ("apache", 4_002),
                _ => ("windows_sysmon", 201_003),
            };
            serde_json::json!({
                "time": chrono::DateTime::from_timestamp_micros((row as i64) * 60_000).unwrap().to_rfc3339(),
                "class_uid": class,
                "activity_id": 1 + (row % 3) as i64,
                "metadata": { "uid": format!("u{row:06}"), "log_source": source },
                "device": { "hostname": format!("ws-{:03}.corp.local", (row * 7) % 300) },
                "message": format!("event {row} class {class}"),
                "raw_data": format!("raw {row} {}", hex::encode(<sha2::Sha256 as sha2::Digest>::digest(row.to_le_bytes()))),
            })
        }).collect::<Vec<_>>();
        let refs = events.iter().collect::<Vec<_>>();
        let schema = Arc::new(infer_schema(&refs).unwrap());
        let fingerprint = crate::parts::format::schema_fingerprint(&schema).unwrap();
        let batch = sort_by_time_uid(&decode(schema.clone(), &refs).unwrap()).unwrap();
        let draft = PartDraft {
            tenant_id: TENANT.into(), signer_key_id: SIGNER.into(), level: Level::Minute, event_hour: 0,
            schema: schema.clone(), schema_fingerprint: fingerprint.clone(),
            inputs: PartInputs::Parts { parts: vec![InputPart { part_id: PartId::new(1).unwrap(), level: Level::L0, provenance_sha256: "0".repeat(64), rows: rows as u64, merkle_root: "0".repeat(64) }] },
            admission: None, rows_in: rows as u64, duplicates_dropped: 0, window: DedupWindow::Exact, build: "test".into(),
        };
        let mut writer = PartWriter::create_with(dir, draft, PartialSource::FromRows, 2, rows as u64,
            crate::parts::format::ParquetSettings::for_level(Level::Minute)).unwrap();
        writer.write(&batch).unwrap();
        let part = writer.finish().unwrap();
        (schema, fingerprint, MergeInput { part: PartRef::from_record(&part.record, &"0".repeat(64), true), dir: part.dir })
    }

    /// A digest of everything about a merged part's physical layout except
    /// its random part id: the logical root, and per data file its family
    /// label, bounds, row groups (rows and compressed column-chunk sizes,
    /// i.e. the data pages byte for byte up to the footer) and uid order.
    fn layout_digest(finished: &super::super::writer::FinishedPart) -> String {
        use parquet::file::reader::{FileReader, SerializedFileReader};
        use sha2::Digest;
        let mut hash = sha2::Sha256::new();
        hash.update(format!("root={} rows={}\n", finished.record.merkle_root, finished.record.rows));
        for file in &finished.record.files.data {
            hash.update(format!("{} {:?} {:?} {} {} {} {}\n", file.name, file.log_sources, file.class_id, file.rows,
                file.row_groups, file.min_time_us, file.max_time_us));
            let path = finished.dir.join(&file.name);
            let reader = SerializedFileReader::new(File::open(&path).unwrap()).unwrap();
            // NAN-4664: the derived indicator columns are not part of the
            // pre-switch layout this pins.
            for group in reader.metadata().row_groups() {
                hash.update(format!("rg {} {}\n", group.num_rows(),
                    group.columns().iter().filter(|c| !nanosiem_core::search::lake_indicators::is_indicator_column(c.column_path().string().as_str()))
                        .map(|c| c.compressed_size().to_string()).collect::<Vec<_>>().join(",")));
            }
            for batch in ParquetRecordBatchReaderBuilder::try_new(File::open(&path).unwrap()).unwrap().build().unwrap() {
                for uid in uid_strings(&batch.unwrap()).unwrap().iter().flatten() { hash.update(uid); hash.update(b"\n"); }
            }
        }
        hex::encode(hash.finalize())
    }

    /// NAN-3437 pre-switch layout. This digest was captured from the merge
    /// code BEFORE the switch existed (nanosiem ac91ab0b7, this fixture,
    /// `NANO_LAKE_COMPACTION_LAYOUT` / `NANO_LAKE_ENDPOINT_HOST_SORT` unset):
    /// with the class split off (as for hours written before NAN-4688), an
    /// hour merge must still write exactly that layout (one source-family
    /// file per source, no class labels).
    const PRE_SWITCH_HOUR_LAYOUT: &str = "9373e0c14dec314f8f0a110da526310df6cd56f73451b55178c9ec7b9501fca6";

    /// NAN-4688: class families are the default, with no switch: an hour
    /// merge with nothing set writes exactly the class-split layout.
    #[test]
    fn class_families_are_the_default_hour_layout() {
        use crate::parts::provenance::tests::{TENANT, SIGNER};
        for name in ["NANO_LAKE_COMPACTION_LAYOUT", "NANO_LAKE_ENDPOINT_HOST_SORT"] {
            assert!(std::env::var(name).is_err(), "{name} must be unset for the default-layout proof");
        }
        let dir = tempfile::tempdir().unwrap();
        let (schema, fingerprint, input) = class_family_fixture(dir.path());
        let inputs = [input];
        let default = merge_parts(dir.path(), TENANT, Level::Hour, 0, &inputs, schema.clone(), &fingerprint, SIGNER, "test", 7).unwrap();
        let forced = with_class_families(Some(true), || merge_parts(dir.path(), TENANT, Level::Hour, 0, &inputs, schema,
            &fingerprint, SIGNER, "test", 7)).unwrap();
        assert_eq!(layout_digest(&default.finished), layout_digest(&forced.finished));
        assert!(default.finished.record.files.data.iter().any(|file| file.class_id.is_some()), "dedicated class files by default");
    }

    /// NAN-4664: the default hour has the time-sorted hour's families, rows
    /// and logical root; each multi-class family is tagged and strictly
    /// `(class_uid, time, uid)`-ordered, a single-class one is untouched.
    fn assert_default_hour_order(merged: &FinishedPart, time_sorted: &FinishedPart) {
        use super::super::class_sort::CLASS_ROW_ORDER;
        use super::super::host_sort::file_row_order;
        assert_eq!(merged.record.merkle_root, time_sorted.record.merkle_root);
        let shape = |part: &FinishedPart| part.record.files.data.iter()
            .map(|file| (file.log_sources.clone(), file.class_id, file.rows)).collect::<Vec<_>>();
        assert_eq!(shape(merged), shape(time_sorted));
        for (file, before) in merged.record.files.data.iter().zip(&time_sorted.record.files.data) {
            let path = merged.dir.join(&file.name);
            let rows = class_file_rows(&path);
            let classes = rows.iter().map(|row| row.0).collect::<BTreeSet<_>>();
            if classes.len() > 1 {
                assert_eq!(file_row_order(&path).unwrap().as_deref(), Some(CLASS_ROW_ORDER), "{}", file.name);
                assert!(rows.windows(2).all(|w| w[0] < w[1]), "strict (class, time, uid) order in {}", file.name);
            } else {
                assert_eq!(file_row_order(&path).unwrap(), None, "{}", file.name);
                assert_eq!(rows, class_file_rows(&time_sorted.dir.join(&before.name)), "{} untouched", file.name);
            }
        }
    }

    /// Runs `body` with the NAN-3437 switch forced for this thread only.
    fn with_class_families<T>(enabled: Option<bool>, body: impl FnOnce() -> T) -> T {
        CLASS_FAMILIES_OVERRIDE.with(|cell| cell.set(enabled));
        let out = body();
        CLASS_FAMILIES_OVERRIDE.with(|cell| cell.set(None));
        out
    }

    /// The class split off (hours written before NAN-4688) writes the
    /// pre-switch layout.
    #[test]
    fn class_families_off_keeps_the_pre_switch_hour_layout() {
        use crate::parts::provenance::tests::{TENANT, SIGNER};
        let dir = tempfile::tempdir().unwrap();
        let (schema, fingerprint, input) = class_family_fixture(dir.path());
        let inputs = [input];
        let time_sorted = with_class_families(Some(false), || merge_streaming(dir.path(), TENANT, Level::Hour, 0, &inputs,
            &inputs, schema.clone(), &fingerprint, SIGNER, "test", 7, true, false, false, HourOrder::TIME, None))
            .unwrap().unwrap().finished;
        assert_eq!(layout_digest(&time_sorted), PRE_SWITCH_HOUR_LAYOUT);
        let merged = with_class_families(Some(false), || merge_parts(dir.path(), TENANT, Level::Hour, 0, &inputs, schema,
            &fingerprint, SIGNER, "test", 7)).unwrap();
        assert_default_hour_order(&merged.finished, &time_sorted);
    }

    /// Dedicated class families: largest first, at most
    /// MAX_DEDICATED_CLASS_FAMILIES, none under CLASS_FAMILY_MIN_ROWS.
    #[test]
    fn class_families_are_capped_and_floored() {
        let mut counts = ClassCounts::new();
        for class in 0..40_i64 {
            counts.entry("windows_sysmon".into()).or_default().insert(class, 1_000 * (class as u64 + 1));
        }
        counts.entry("apache".into()).or_default().insert(4_002, CLASS_FAMILY_MIN_ROWS - 1);
        let chosen = rank_class_families_above(counts.clone(), CLASS_FAMILY_MIN_ROWS);
        assert_eq!(chosen, (25..40).map(|class| ("windows_sysmon".to_string(), class)).collect());
        let mut few = ClassCounts::new();
        few.entry("windows_sysmon".into()).or_default().extend([(1, CLASS_FAMILY_MIN_ROWS), (2, 10), (3, CLASS_FAMILY_MIN_ROWS - 1)]);
        assert_eq!(rank_class_families_above(few, CLASS_FAMILY_MIN_ROWS), [("windows_sysmon".to_string(), 1)].into());
    }

    /// NAN-3437: with the switch on, one hour merge pass writes the large
    /// `(source, class)` families as their own class-labelled files in the
    /// default layout, keeps small classes in their source's file, holds the
    /// same logical rows, prunes by class in the planner's file stage, and
    /// survives a later rewrite of the hour with the switch on or off.
    #[tokio::test]
    async fn class_families_split_hour_merges_in_one_default_pass() {
        use crate::part_query::prune::file_family_may_match;
        use crate::parts::provenance::tests::{signer, TENANT, SIGNER};
        use crate::planner::CandidateHint;
        use super::super::writer::publish_parts;
        let dir = tempfile::tempdir().unwrap();
        let (schema, fingerprint, input) = class_family_fixture(dir.path());
        let inputs = [input];
        let off = with_class_families(Some(false), || merge_parts(dir.path(), TENANT, Level::Hour, 0, &inputs, schema.clone(),
            &fingerprint, SIGNER, "test", 6)).unwrap().finished;
        let on = with_class_families(Some(true), || merge_parts(dir.path(), TENANT, Level::Hour, 0, &inputs, schema.clone(),
            &fingerprint, SIGNER, "test", 7)).unwrap().finished;
        let families = |record: &crate::parts::provenance::ProvenanceRecord| record.files.data.iter()
            .map(|file| (file.log_sources.clone().unwrap().join(","), file.class_id, file.rows)).collect::<Vec<_>>();
        // 201003 (8,000 rows) and 30 tiny classes fall under the floor and
        // stay in the sysmon source file; apache stays a source family.
        assert_eq!(families(&on.record), vec![
            ("apache".to_string(), None, 1_000),
            ("windows_sysmon".to_string(), None, 11_000),
            ("aws_cloudtrail".to_string(), Some(6_003), 9_000),
            ("windows_sysmon".to_string(), Some(201_001), 15_000),
            ("windows_sysmon".to_string(), Some(201_002), 24_000),
        ]);
        assert_eq!(on.record.rows, 60_000);
        assert_eq!(on.record.merkle_root, off.record.merkle_root, "same logical rows");
        // Default layout: the default row groups, one file per family.
        let default_rows = crate::parts::format::ParquetSettings::for_level(Level::Hour).row_group_rows;
        for file in &on.record.files.data {
            assert_eq!(file.row_groups as u64, file.rows.div_ceil(default_rows as u64), "{}", file.name);
            let path = on.dir.join(&file.name);
            if file.class_id.is_some() {
                let rows = file_rows(&path);
                assert!(rows.windows(2).all(|w| (w[0].1, &w[0].2) < (w[1].1, &w[1].2)), "strict (time, uid) order");
            } else {
                // NAN-4664: a multi-class rest file is class-sorted.
                let rows = class_file_rows(&path);
                assert!(rows.windows(2).all(|w| w[0] < w[1]), "strict (class, time, uid) order");
            }
            for batch in ParquetRecordBatchReaderBuilder::try_new(File::open(&path).unwrap()).unwrap().build().unwrap() {
                let batch = batch.unwrap();
                let classes = batch.column_by_name("class_uid").unwrap();
                let sources = log_source_strings(&batch).unwrap();
                for row in 0..batch.num_rows() {
                    assert_eq!(Some(sources.value(row).to_string()), file.log_sources.clone().map(|s| s[0].clone()));
                    let class = class_at(Some(classes), row).unwrap();
                    match file.class_id {
                        Some(id) => assert_eq!(class, id),
                        None => assert!(![6_003, 201_001, 201_002].contains(&class), "dedicated class {class} in a rest file"),
                    }
                }
            }
        }

        // Reader side: the planner's signed per-file family stage (the
        // compiler's `class_uid = N` / log-source hints) keeps only the
        // matching class file plus the class-less files of that source.
        let kept = |record: &crate::parts::provenance::ProvenanceRecord, hints: &[CandidateHint]| record.files.data.iter()
            .filter(|file| file_family_may_match(file.log_sources.as_deref(), file.class_id, hints))
            .map(|file| (file.log_sources.clone().unwrap().join(","), file.class_id)).collect::<Vec<_>>();
        let sysmon6 = [CandidateHint::SourceFamily { value: "windows_sysmon".into() }, CandidateHint::Class { value: 201_002 }];
        assert_eq!(kept(&on.record, &sysmon6), vec![("windows_sysmon".to_string(), None), ("windows_sysmon".to_string(), Some(201_002))]);
        assert_eq!(kept(&on.record, &[CandidateHint::Class { value: 6_003 }]),
            vec![("apache".to_string(), None), ("windows_sysmon".to_string(), None), ("aws_cloudtrail".to_string(), Some(6_003))]);
        let read = |record: &crate::parts::provenance::ProvenanceRecord, hints: &[CandidateHint]| record.files.data.iter()
            .filter(|file| file_family_may_match(file.log_sources.as_deref(), file.class_id, hints)).map(|file| file.rows).sum::<u64>();
        assert_eq!(read(&off.record, &sysmon6), 50_000, "source-only layout reads every sysmon row");
        assert_eq!(read(&on.record, &sysmon6), 35_000);

        // Rewrites of the published class-family hour (late data, reindex):
        // switch on keeps the split, off restores the pre-switch layout.
        let store = crate::parts::part_log::LocalObjectStore::new(dir.path().join("store")).unwrap();
        let owner = signer(1);
        let on_record = on.record.clone();
        let part = publish_parts(&store, &owner, &owner.trusted(), &[on]).await.unwrap().remove(0);
        let published = [MergeInput { dir: dir.path().join(part.part_id.as_str()), part }];
        let again = with_class_families(Some(true), || merge_parts(dir.path(), TENANT, Level::Hour, 0, &published, schema.clone(),
            &fingerprint, SIGNER, "test", 8)).unwrap().finished;
        assert_eq!(again.record.merkle_root, off.record.merkle_root);
        assert_eq!(families(&again.record), families(&on_record));
        let back = with_class_families(Some(false), || merge_parts(dir.path(), TENANT, Level::Hour, 0, &published, schema,
            &fingerprint, SIGNER, "test", 9)).unwrap().finished;
        assert_eq!(back.record.merkle_root, off.record.merkle_root);
        assert_eq!(families(&back.record), families(&off.record));
    }

    /// Rough local merge cost of the switch on one synthetic hour: a
    /// correctness-scale check only, never evidence of live speed.
    /// `cargo test --release ... class_families_merge_cost -- --ignored --nocapture`
    #[test]
    #[ignore]
    fn class_families_merge_cost() {
        use crate::parts::provenance::tests::{TENANT, SIGNER};
        let dir = tempfile::tempdir().unwrap();
        let (schema, fingerprint, input) = class_family_fixture(dir.path());
        let inputs = [input];
        for (round, enabled) in [false, true, false, true, false, true].into_iter().enumerate() {
            let cpu = cpu_seconds();
            let started = std::time::Instant::now();
            let merged = with_class_families(Some(enabled), || merge_parts(dir.path(), TENANT, Level::Hour, 0, &inputs,
                schema.clone(), &fingerprint, SIGNER, "test", 10 + round as i64)).unwrap().finished;
            eprintln!("class_families={enabled} wall {:.2}s cpu {:.2}s bytes={} files={}", started.elapsed().as_secs_f64(),
                cpu_seconds() - cpu, merged.record.files.data_bytes(), merged.record.files.data.len());
            std::fs::remove_dir_all(&merged.dir).unwrap();
        }
    }

    fn cpu_seconds() -> f64 {
        let stat = std::fs::read_to_string("/proc/self/stat").unwrap();
        let fields = stat.rsplit_once(") ").unwrap().1.split(' ').collect::<Vec<_>>();
        (fields[11].parse::<f64>().unwrap() + fields[12].parse::<f64>().unwrap()) / 100.0
    }

    fn input(min: i64, max: i64) -> MergeInput {
        MergeInput {
            part: PartRef {
                request_hours: None,
                part_id: PartId::new(1).unwrap(),
                level: Level::L0,
                event_hour: 0,
                event_day: None,
                rows: 1,
                min_time_us: min,
                max_time_us: max,
                schema_fingerprint: "0".repeat(64),
                provenance_sha256: "0".repeat(64),
                merkle_root: "0".repeat(64),
                sorted: true,
                data_bytes: 1,
                row_groups: 1,
                data_files: 1,
            },
            dir: PathBuf::new(),
        }
    }

    #[test]
    fn overlap_counts_concurrent_ranges() {
        let disjoint = (0..60).map(|i| input(i * 10, i * 10 + 9)).collect::<Vec<_>>();
        assert_eq!(max_overlap(&disjoint), 1);
        let nested = (0..20).map(|i| input(0, 100 + i)).collect::<Vec<_>>();
        assert_eq!(max_overlap(&nested), 20);
    }
}
