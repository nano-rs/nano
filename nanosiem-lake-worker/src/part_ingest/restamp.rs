// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-3864: prevalence restamp of rows committed without stamps.
//!
//! Ingest never waits for prevalence. While the tenant state is not at the
//! part-log head (catching up after a reopen, rebuilding, resetting, a
//! lookup slower than the stamp wait, or a stalled store), admitted rows
//! are written with no `prevalence_*` values: a stamp is permanent, and a
//! count read from a state that is missing the last N `Add`s would invent
//! rarity ("absent from the baseline" reads as "brand new"). Before this
//! module those rows stayed null for their whole retention. On tenant-a
//! (2026-10-14) that was ~16.5 h of events, 05Z to 21:35Z: the state reopened
//! every ~5 min (each reopen restarted `CatchingUp`) and never reached the
//! head, so `stamp_lookup` returned `None` for every batch.
//!
//! The contract now: ingest still never waits, and a row is never null
//! forever while the tenant has a prevalence grant.
//!
//! - Admission records the event hour of every batch it commits unstamped as
//!   **owed** ([`OwedHours`]). The set is written to the tenant bucket as
//!   immutable snapshots under `log/checkpoints/prevalence-restamp-v1/`
//!   (like count-backfill windows), never into the prevalence state: the
//!   set exists for the spells when that state does not answer, so a roll or
//!   ZDR handover during one must not forget it.
//! - Once the state is at the log head (`Stamping`, nothing pending), the
//!   hour seal (`m` → `h`) of an owed hour restamps its unstamped rows as it
//!   rewrites them (it rewrites every row anyway, so this costs only the
//!   lookups). L0 and minute merges never look up: they are on the freshness
//!   path, and the hour stays owed until its seal regardless. An owed hour
//!   that is already one sealed `h` part is rewritten once more, one hour at
//!   a time, only while ingest is not catching up (the old-hour reindex
//!   rules).
//! - Day merges (`day_merges`, off) do not restamp: an owed hour folded into
//!   a `d` part stays owed until the orphan prune drops it (NAN-3871).
//! - Restamped values read the state when the restamp runs. They include the
//!   row's own observation and any later ones within the window, so a count
//!   is at or above the arrival count: a late restamp can hide rarity, never
//!   invent it, as long as the row's own observation is still inside the
//!   state's window. That holds for hours owed by admission (restamped within
//!   hours) and is enforced for the operator window, whose start may be at
//!   most [`RESTAMP_MAX_AGE_MS`] (7 days) old, far inside the 30-day window:
//!   restamping older rows would read their artifacts as expired and stamp
//!   `prevalence_min = 1`. Rows that were stamped on arrival are never
//!   changed.
//!
//! Only the five scalar columns are restamped (the filterable contract the
//! rarity slider, detections and charts read). The `enrichments[]` detail is
//! not added to restamped rows.

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result};
use arrow_array::cast::AsArray;
use arrow_array::{Array, ArrayRef, RecordBatch, StringArray, UInt64Array};
use arrow_schema::DataType;
use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;
use parquet::arrow::ProjectionMask;
use serde_json::{json, Map, Value};

use super::prevalence::{stamp_columns, stamp_scalars};

/// The OCSF leaves the scalar stamps read (`column_artifacts`), as paths
/// below the top-level column. Hash lists keep their element fields.
const ARTIFACT_LEAVES: [&[&str]; 5] = [
    &["file", "hashes"],
    &["process", "file", "hashes"],
    &["dst_endpoint", "hostname"],
    &["dst_endpoint", "ip"],
    &["query", "hostname"],
];

/// The stamp every stamped row carries; null or absent = unstamped.
const MIN_COLUMN: &str = "prevalence_min";

/// Gap between two sealed-hour restamp rewrites (the reindex spacing).
pub const RESTAMP_SPACING_MS: i64 = super::reindex::REINDEX_SPACING_MS;

/// Stall bound for one restamp point read. A large hour may take longer
/// overall as long as its budgeted lookup stream keeps making progress.
pub const RESTAMP_LOOKUP_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(120);

/// Lookup work per budget slice. Routine merges publish completed rows
/// after one slice and keep the hour owed; sealed rewrites resume the same
/// stream, outside the ingest tick, without discarding completed lookups.
pub const RESTAMP_MERGE_LOOKUP_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// Consecutive failed sealed-hour restamps before an hour is given up
/// (logged and counted; never retried until an operator re-admits it).
pub const MAX_RESTAMP_ATTEMPTS: u32 = 6;

/// Oldest start an operator restamp window may have. Restamped values read
/// the state now; a row older than the state's window would no longer be
/// counted and would be stamped as never seen (`prevalence_min = 1`). Seven
/// days keeps every restamped row well inside the 30-day window.
pub const RESTAMP_MAX_AGE_MS: i64 = 7 * 86_400_000;

/// Hours owed a restamp with no live part left are dropped once they are
/// this old (their rows are gone; a younger hour may still be in a flush).
pub const OWED_ORPHAN_AGE_HOURS: i32 = 48;

/// Event hours holding rows committed without prevalence stamps.
///
/// Each hour carries a mark serial, bumped whenever another unstamped batch
/// for it is admitted: a restamp clears the hour only if no batch was
/// admitted unstamped after the restamp started.
#[derive(Debug, Default, Clone)]
pub struct OwedHours {
    hours: BTreeMap<i32, u64>,
    serial: u64,
    /// The stored snapshot is behind this set.
    dirty: bool,
}

impl OwedHours {
    pub fn from_hours(hours: impl IntoIterator<Item = i32>) -> Self {
        let mut owed = Self::default();
        owed.extend(hours);
        owed.dirty = false;
        owed
    }

    /// Record unstamped rows in `hours`. True when an hour is new.
    pub fn mark(&mut self, hours: impl IntoIterator<Item = i32>) -> bool {
        let mut added = false;
        for hour in hours {
            self.serial += 1;
            added |= self.hours.insert(hour, self.serial).is_none();
        }
        self.dirty |= added;
        added
    }

    /// Union hours loaded from the stored snapshot (no new marks).
    pub fn extend(&mut self, hours: impl IntoIterator<Item = i32>) {
        for hour in hours {
            if !self.hours.contains_key(&hour) {
                self.serial += 1;
                self.hours.insert(hour, self.serial);
                self.dirty = true;
            }
        }
    }

    pub fn contains(&self, hour: i32) -> bool {
        self.hours.contains_key(&hour)
    }

    /// The hour's mark serial (to clear it only if unchanged).
    pub fn serial_of(&self, hour: i32) -> Option<u64> {
        self.hours.get(&hour).copied()
    }

    /// Clear `hour` if it was not marked again after `serial` was read.
    pub fn clear_if(&mut self, hour: i32, serial: u64) -> bool {
        if self.hours.get(&hour) == Some(&serial) {
            self.hours.remove(&hour);
            self.dirty = true;
            return true;
        }
        false
    }

    pub fn remove(&mut self, hour: i32) -> bool {
        let removed = self.hours.remove(&hour).is_some();
        self.dirty |= removed;
        removed
    }

    pub fn hours(&self) -> impl DoubleEndedIterator<Item = i32> + '_ {
        self.hours.keys().copied()
    }

    pub fn len(&self) -> usize {
        self.hours.len()
    }

    pub fn is_empty(&self) -> bool {
        self.hours.is_empty()
    }

    pub fn dirty(&self) -> bool {
        self.dirty
    }

    pub fn mark_saved(&mut self) {
        self.dirty = false;
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(&self.hours.keys().collect::<Vec<_>>()).expect("hours serialize")
    }

    pub fn parse(bytes: &[u8]) -> Result<Vec<i32>> {
        serde_json::from_slice(bytes).context("decode owed restamp hours")
    }
}

/// What a restamp did, filled in by the merge task.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RestampResult {
    /// Lookups ran; `rows` unstamped rows were stamped.
    Applied { rows: u64, complete: bool },
    /// The inputs held no unstamped row.
    NothingOwed,
    /// The lookups failed or timed out: the hour stays owed.
    LookupFailed(String),
    /// The merge schema has no stamp columns (the tenant never stamped):
    /// nothing can be written, the hour is dropped.
    Unsupported,
}

/// Shared between the ingest loop and a merge task.
#[derive(Debug, Default)]
pub struct RestampOutcome {
    result: Mutex<Option<RestampResult>>,
}

impl RestampOutcome {
    pub fn set(&self, result: RestampResult) {
        *self.result.lock().expect("restamp outcome lock") = Some(result);
    }

    pub fn get(&self) -> Option<RestampResult> {
        self.result.lock().expect("restamp outcome lock").clone()
    }
}

/// A sealed-hour restamp found nothing to do, or could not look up: the
/// rewrite is skipped (not a merge failure, never quarantined).
#[derive(Debug, thiserror::Error)]
pub enum RestampSkip {
    #[error("prevalence restamp: no unstamped rows in hour {0}")]
    NothingOwed(i32),
    #[error("prevalence restamp of hour {hour} deferred: {reason}")]
    Deferred { hour: i32, reason: String },
}

/// Artifact → host-count scalar for one restamp.
#[derive(Debug, Default)]
pub struct RestampMap {
    scalars: HashMap<String, u64>,
    restamped: AtomicU64,
    complete: bool,
}

impl RestampMap {
    pub fn new(scalars: HashMap<String, u64>) -> Self {
        Self::with_completion(scalars, true)
    }

    pub(super) fn with_completion(scalars: HashMap<String, u64>, complete: bool) -> Self {
        Self { scalars, restamped: AtomicU64::new(0), complete }
    }

    pub(super) fn complete(&self) -> bool {
        self.complete
    }

    pub fn restamped_rows(&self) -> u64 {
        self.restamped.load(Ordering::Relaxed)
    }
}

thread_local! {
    static ACTIVE: RefCell<Option<Arc<RestampMap>>> = const { RefCell::new(None) };
}

/// Run `work` (a synchronous merge) with `map` restamping every batch its
/// cursors read. The previous value is restored even on panic.
pub fn with_restamp<T>(map: Option<Arc<RestampMap>>, work: impl FnOnce() -> T) -> T {
    struct Restore(Option<Arc<RestampMap>>);
    impl Drop for Restore {
        fn drop(&mut self) {
            let previous = self.0.take();
            ACTIVE.with(|active| *active.borrow_mut() = previous);
        }
    }
    let previous = ACTIVE.with(|active| std::mem::replace(&mut *active.borrow_mut(), map));
    let _restore = Restore(previous);
    work()
}

/// Merge hook: restamp `batch` with the restamp active on this thread.
pub(super) fn apply_active(batch: RecordBatch) -> Result<RecordBatch> {
    match ACTIVE.with(|active| active.borrow().clone()) {
        Some(map) => restamp_batch(batch, &map),
        None => Ok(batch),
    }
}

/// Rows of `batch` without a stamp.
fn unstamped_rows(batch: &RecordBatch) -> Vec<u32> {
    match batch.column_by_name(MIN_COLUMN) {
        None => (0..batch.num_rows() as u32).collect(),
        Some(column) => (0..batch.num_rows()).filter(|row| column.is_null(*row)).map(|row| row as u32).collect(),
    }
}

/// One artifact leaf resolved in a batch: the arrays from the top-level
/// column down (each level's validity counts) and the leaf.
struct Leaf {
    chain: Vec<ArrayRef>,
}

impl Leaf {
    fn resolve(batch: &RecordBatch, path: &[&str]) -> Option<Self> {
        let mut chain = vec![batch.column_by_name(path[0])?.clone()];
        for name in &path[1..] {
            let next = chain.last()?.as_struct_opt()?.column_by_name(name)?.clone();
            chain.push(next);
        }
        Some(Self { chain })
    }

    fn valid(&self, row: usize) -> bool {
        self.chain.iter().all(|array| array.is_valid(row))
    }

    fn leaf(&self) -> &ArrayRef {
        self.chain.last().expect("a resolved leaf")
    }
}

fn utf8(array: &ArrayRef) -> Option<StringArray> {
    let cast = arrow_cast::cast(array.as_ref(), &DataType::Utf8).ok()?;
    cast.as_string_opt::<i32>().cloned()
}

/// The OCSF hash entries of a hashes list at `row` (`algorithm`, `value`).
fn hashes_at(list: &ArrayRef, row: usize) -> Option<Value> {
    let values = match list.data_type() {
        DataType::List(_) => list.as_list::<i32>().value(row),
        DataType::LargeList(_) => list.as_list::<i64>().value(row),
        _ => return None,
    };
    let entries = values.as_struct_opt()?;
    let algorithm = entries.column_by_name("algorithm").and_then(utf8);
    let value = entries.column_by_name("value").and_then(utf8)?;
    let out = (0..entries.len())
        .filter(|index| entries.is_valid(*index) && value.is_valid(*index))
        .map(|index| {
            let mut entry = Map::new();
            entry.insert("value".into(), json!(value.value(index)));
            if let Some(algorithm) = algorithm.as_ref().filter(|algorithm| algorithm.is_valid(index)) {
                entry.insert("algorithm".into(), json!(algorithm.value(index)));
            }
            Value::Object(entry)
        })
        .collect::<Vec<_>>();
    Some(Value::Array(out))
}

fn insert_path(object: &mut Map<String, Value>, path: &[&str], value: Value) {
    let mut node = object;
    for name in &path[..path.len() - 1] {
        node = node
            .entry((*name).to_owned())
            .or_insert_with(|| Value::Object(Map::new()))
            .as_object_mut()
            .expect("restamp projection nodes are objects");
    }
    node.insert(path[path.len() - 1].to_owned(), value);
}

/// The artifact leaves of `rows`, as the minimal OCSF objects
/// `column_artifacts` reads (so the restamp extracts exactly what the
/// ingest stamp extracts).
fn artifact_objects(batch: &RecordBatch, rows: &[u32]) -> Vec<Map<String, Value>> {
    let leaves = ARTIFACT_LEAVES
        .iter()
        .map(|path| {
            let leaf = Leaf::resolve(batch, path);
            let strings = leaf.as_ref().filter(|_| !path.ends_with(&["hashes"])).and_then(|leaf| utf8(leaf.leaf()));
            (*path, leaf, strings)
        })
        .collect::<Vec<_>>();
    rows.iter()
        .map(|row| {
            let row = *row as usize;
            let mut object = Map::new();
            for (path, leaf, strings) in &leaves {
                let Some(leaf) = leaf.as_ref().filter(|leaf| leaf.valid(row)) else { continue };
                let value = if path.ends_with(&["hashes"]) {
                    hashes_at(leaf.leaf(), row)
                } else {
                    strings.as_ref().map(|strings| json!(strings.value(row)))
                };
                if let Some(value) = value {
                    insert_path(&mut object, path, value);
                }
            }
            object
        })
        .collect()
}

/// The distinct artifacts the unstamped rows of `batch` stamp from.
fn batch_artifacts(batch: &RecordBatch, artifacts: &mut BTreeSet<String>) -> u64 {
    let rows = unstamped_rows(batch);
    for object in artifact_objects(batch, &rows) {
        artifacts.extend(crate::prevalence_stamp::column_artifacts(&object).into_iter().map(|(_, artifact)| artifact));
    }
    rows.len() as u64
}

/// Unstamped rows in `files` and the artifacts they stamp from. Reads only
/// the stamp and artifact leaves.
pub fn unstamped_artifacts(files: &[PathBuf]) -> Result<(u64, BTreeSet<String>)> {
    let mut artifacts = BTreeSet::new();
    let mut rows = 0;
    for path in files {
        let builder = ParquetRecordBatchReaderBuilder::try_new(std::fs::File::open(path)?)
            .with_context(|| format!("open {} for the prevalence restamp scan", path.display()))?;
        let schema = builder.parquet_schema();
        let wanted = (0..schema.num_columns())
            .filter(|index| {
                let parts = schema.column(*index).path().parts().to_vec();
                parts == [MIN_COLUMN] || ARTIFACT_LEAVES.iter().any(|leaf| {
                    parts.len() >= leaf.len() && parts.iter().zip(leaf.iter()).all(|(part, name)| part == name)
                })
            })
            .collect::<Vec<_>>();
        let mask = ProjectionMask::leaves(schema, wanted);
        for batch in builder.with_projection(mask).with_batch_size(8_192).build()? {
            rows += batch_artifacts(&batch?, &mut artifacts);
        }
    }
    Ok((rows, artifacts))
}

/// Stamp the unstamped rows of `batch` from `map`. A row with an artifact
/// the map lacks stays unstamped; stamped rows are never changed. Without
/// the stamp columns in the schema the batch is returned as is.
pub fn restamp_batch(batch: RecordBatch, map: &RestampMap) -> Result<RecordBatch> {
    let schema = batch.schema();
    let Some(indices) = stamp_columns().iter().map(|name| schema.index_of(name).ok()).collect::<Option<Vec<_>>>() else {
        return Ok(batch);
    };
    let rows = unstamped_rows(&batch);
    if rows.is_empty() {
        return Ok(batch);
    }
    let mut stamped = BTreeMap::<u32, [u64; 5]>::new();
    for (row, object) in rows.iter().zip(artifact_objects(&batch, &rows)) {
        let artifacts = crate::prevalence_stamp::column_artifacts(&object);
        if artifacts.iter().any(|(_, artifact)| !map.scalars.contains_key(artifact)) {
            continue;
        }
        stamped.insert(*row, stamp_scalars(&object, |artifact| map.scalars[artifact]));
    }
    if stamped.is_empty() {
        return Ok(batch);
    }
    let mut columns = batch.columns().to_vec();
    for (slot, index) in indices.iter().enumerate() {
        let field = schema.field(*index);
        let current = arrow_cast::cast(columns[*index].as_ref(), &DataType::UInt64)?;
        let current = current.as_primitive::<arrow_array::types::UInt64Type>();
        let merged = (0..batch.num_rows())
            .map(|row| match stamped.get(&(row as u32)) {
                Some(values) => Some(values[slot]),
                None => current.is_valid(row).then(|| current.value(row)),
            })
            .collect::<UInt64Array>();
        columns[*index] = arrow_cast::cast(&merged, field.data_type())?;
    }
    map.restamped.fetch_add(stamped.len() as u64, Ordering::Relaxed);
    Ok(RecordBatch::try_new(schema, columns)?)
}

/// Whether `schema` can hold a restamp.
pub fn schema_supports(schema: &arrow_schema::Schema) -> bool {
    stamp_columns().iter().all(|name| schema.index_of(name).is_ok())
}

#[cfg(test)]
mod tests {
    use super::*;
    use arrow_array::UInt16Array;
    use arrow_schema::{Field, Fields, Schema};

    fn batch(rows: &[(Option<&str>, Option<u16>)]) -> RecordBatch {
        let ip = Arc::new(StringArray::from(rows.iter().map(|(ip, _)| *ip).collect::<Vec<_>>())) as ArrayRef;
        let dst = arrow_array::StructArray::from(vec![(Arc::new(Field::new("ip", DataType::Utf8, true)), ip)]);
        let mut fields = vec![Field::new("dst_endpoint", DataType::Struct(Fields::from(vec![Field::new("ip", DataType::Utf8, true)])), true)];
        let mut columns: Vec<ArrayRef> = vec![Arc::new(dst)];
        for name in stamp_columns() {
            fields.push(Field::new(*name, DataType::UInt16, true));
            columns.push(Arc::new(rows.iter().map(|(_, stamp)| *stamp).collect::<UInt16Array>()));
        }
        RecordBatch::try_new(Arc::new(Schema::new(fields)), columns).unwrap()
    }

    fn column(batch: &RecordBatch, name: &str) -> Vec<Option<u16>> {
        let array = batch.column_by_name(name).unwrap().as_primitive::<arrow_array::types::UInt16Type>();
        (0..array.len()).map(|row| array.is_valid(row).then(|| array.value(row))).collect()
    }

    #[test]
    fn restamp_fills_only_unstamped_rows_with_the_ingest_scalars() {
        let input = batch(&[(Some("8.8.8.8"), None), (Some("1.1.1.1"), Some(7)), (None, None), (Some("10.0.0.1"), None)]);
        let map = RestampMap::new(HashMap::from([("8.8.8.8".to_string(), 3), ("1.1.1.1".to_string(), 1)]));
        let out = restamp_batch(input, &map).unwrap();
        // Row 0: dest ip 3. Row 1: stamped on arrival, unchanged. Row 2: no
        // artifact (N/A, min "common"). Row 3: private IP, untracked (N/A).
        assert_eq!(column(&out, "prevalence_dest_ip"), vec![Some(3), Some(7), Some(65_535), Some(65_535)]);
        assert_eq!(column(&out, "prevalence_min"), vec![Some(3), Some(7), Some(9_999), Some(9_999)]);
        assert_eq!(column(&out, "prevalence_file_hash"), vec![Some(65_535), Some(7), Some(65_535), Some(65_535)]);
        assert_eq!(map.restamped_rows(), 3);
    }

    #[test]
    fn a_row_whose_artifact_was_not_looked_up_stays_unstamped() {
        let input = batch(&[(Some("8.8.8.8"), None), (Some("9.9.9.9"), None)]);
        let map = RestampMap::with_completion(HashMap::from([("8.8.8.8".to_string(), 2)]), false);
        assert!(!map.complete(), "a budget yield must keep the hour owed");
        let out = restamp_batch(input, &map).unwrap();
        assert_eq!(column(&out, "prevalence_min"), vec![Some(2), None]);
        assert_eq!(map.restamped_rows(), 1);
    }

    #[test]
    fn restamp_matches_the_ingest_stamp_for_the_same_event() {
        // The ingest stamp and the restamp share `stamp_scalars`; the restamp
        // reads its artifacts back from Arrow. Same event, same scalars.
        let event = json!({"time": "2026-10-14T12:00:00Z", "dst_endpoint": {"ip": "8.8.8.8", "hostname": "Evil.Example"},
            "file": {"hashes": [{"algorithm": "SHA-256", "value": "AB".repeat(32)}]}});
        let scalars = HashMap::from([("8.8.8.8".to_string(), 4), ("evil.example".to_string(), 2), ("ab".repeat(32), 1)]);
        let expected = stamp_scalars(event.as_object().unwrap(), |artifact| scalars[artifact]);
        let mut events = vec![event.clone()];
        events[0]["prevalence_min"] = Value::Null;
        let schema = super::super::schema::infer_schema(&[&event]).unwrap();
        let mut fields = schema.fields().iter().cloned().collect::<Vec<_>>();
        for name in stamp_columns() {
            fields.push(Arc::new(Field::new(*name, DataType::UInt16, true)));
        }
        let schema = Arc::new(Schema::new(fields));
        let input = super::super::schema::decode(schema, &[&events[0]]).unwrap();
        let out = restamp_batch(input, &RestampMap::new(scalars)).unwrap();
        let got = stamp_columns().iter().map(|name| column(&out, name)[0].map(u64::from)).collect::<Vec<_>>();
        assert_eq!(got, expected.iter().map(|value| Some(*value)).collect::<Vec<_>>());
        assert_eq!(expected[..2], [1, 65_535], "file hash 1, process hash N/A");
    }

    #[test]
    fn without_stamp_columns_the_batch_is_unchanged() {
        let ip = Arc::new(StringArray::from(vec![Some("8.8.8.8")])) as ArrayRef;
        let dst = arrow_array::StructArray::from(vec![(Arc::new(Field::new("ip", DataType::Utf8, true)), ip)]);
        let schema = Schema::new(vec![Field::new("dst_endpoint", DataType::Struct(Fields::from(vec![Field::new("ip", DataType::Utf8, true)])), true)]);
        assert!(!schema_supports(&schema));
        let input = RecordBatch::try_new(Arc::new(schema), vec![Arc::new(dst)]).unwrap();
        let map = RestampMap::new(HashMap::from([("8.8.8.8".to_string(), 2)]));
        let out = restamp_batch(input.clone(), &map).unwrap();
        assert_eq!(out, input);
        assert_eq!(map.restamped_rows(), 0);
    }

    #[test]
    fn the_scan_finds_only_unstamped_rows_artifacts() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("data.parquet");
        let input = batch(&[(Some("8.8.8.8"), None), (Some("1.1.1.1"), Some(7)), (Some("8.8.4.4"), None)]);
        let mut writer = parquet::arrow::ArrowWriter::try_new(std::fs::File::create(&path).unwrap(), input.schema(), None).unwrap();
        writer.write(&input).unwrap();
        writer.close().unwrap();
        let (rows, artifacts) = unstamped_artifacts(&[path]).unwrap();
        assert_eq!(rows, 2);
        assert_eq!(artifacts.into_iter().collect::<Vec<_>>(), vec!["8.8.4.4".to_string(), "8.8.8.8".to_string()]);
    }

    #[test]
    fn with_restamp_is_scoped_to_the_call_and_restored_after_a_panic() {
        let map = Arc::new(RestampMap::new(HashMap::from([("8.8.8.8".to_string(), 2)])));
        let input = batch(&[(Some("8.8.8.8"), None)]);
        assert_eq!(column(&apply_active(input.clone()).unwrap(), "prevalence_min"), vec![None]);
        let out = with_restamp(Some(map.clone()), || apply_active(input.clone()).unwrap());
        assert_eq!(column(&out, "prevalence_min"), vec![Some(2)]);
        let _ = std::panic::catch_unwind(|| with_restamp(Some(map.clone()), || panic!("injected")));
        assert_eq!(column(&apply_active(input).unwrap(), "prevalence_min"), vec![None], "no restamp leaks past its merge");
    }

    /// Convergence model (memory: catch-up fixes need a backlog x cost
    /// proof). tenant-a 2026-10-14: the fold was behind from ~05Z to the r52
    /// roll at 21:35Z, then at the head 76 s after the reopen (49 entries in
    /// 4.6 s). Hours ingested while behind are owed; once the fold is at the
    /// head no new hour is owed (every batch stamps), so the owed set only
    /// shrinks: unsealed hours ride their seal merge (no extra rewrite),
    /// sealed ones drain one rewrite at a time. Per-step cost from tenant-a: an
    /// hour merge of 867k rows took 76 s (cold, right after the roll);
    /// this historical NAN-3864 model charges 120 s for lookups. NAN-4472's
    /// production-path test also charges streaming GETs and the much slower
    /// the large-tenant rewrite. Ingest is never in the loop: sealed restamps run only
    /// while ingest is not catching up.
    #[test]
    fn the_b12_gap_drains_in_bounded_time_and_never_grows_once_caught_up() {
        const MIN: i64 = 60_000;
        let rows_per_hour = 1_000_000_u64;
        let rewrite_ms = |rows: u64| (rows as f64 / (867_498.0 / 76.0) * 1_000.0) as i64;
        let lookup_ms = 120_000; // NAN-3864's historical per-hour charge
        let behind_from = 5 * 60 * MIN; // 05:00Z
        let at_head = (21 * 60 + 36) * MIN; // 21:36Z
        let mut owed = OwedHours::default();
        let mut sealed = BTreeSet::new();
        let (mut busy_until, mut not_before, mut rewrites) = (0_i64, 0_i64, 0_u32);
        let mut previous = usize::MAX;
        let (mut drained_at, mut sealed_drained_at) = (None, None);
        let mut now = 0_i64;
        while now < 48 * 60 * MIN {
            let hour = (now / (60 * MIN)) as i32;
            // Ingest: every minute's batch, unstamped while the fold is behind.
            if (behind_from..at_head).contains(&now) {
                owed.mark([hour]);
            }
            // Hours seal ~1 h after they end (hour_seal); an owed hour sealed
            // while the fold is at the head was restamped by its seal merge.
            if now % (60 * MIN) == 0 && hour >= 2 {
                let sealing = hour - 2;
                if now >= at_head {
                    let serial = owed.serial_of(sealing);
                    if let Some(serial) = serial { owed.clear_if(sealing, serial); }
                } else if owed.contains(sealing) {
                    sealed.insert(sealing);
                }
            }
            // The sealed restamp planner: one at a time, spaced, at the head.
            if now >= at_head && now >= busy_until && now >= not_before {
                let next = owed.hours().rev().find(|hour| sealed.contains(hour));
                if let Some(hour) = next {
                    let serial = owed.serial_of(hour).unwrap();
                    busy_until = now + lookup_ms + rewrite_ms(rows_per_hour);
                    not_before = busy_until + RESTAMP_SPACING_MS;
                    owed.clear_if(hour, serial);
                    sealed.remove(&hour);
                    rewrites += 1;
                }
            }
            if now >= at_head {
                assert!(owed.len() <= previous, "the owed set grew after the fold reached the head");
                previous = owed.len();
                if owed.is_empty() && drained_at.is_none() {
                    drained_at = Some(now);
                }
                if sealed.is_empty() && sealed_drained_at.is_none() {
                    sealed_drained_at = Some(now);
                }
            }
            now += MIN;
        }
        let drained_at = drained_at.expect("the gap drains");
        let sealed_drained_at = sealed_drained_at.expect("the sealed backlog drains");
        // 05Z..19Z: 15 hours already sealed at the roll, rewritten one at a
        // time: 15 x (120 s + 87 s + 30 s) = ~60 min worst case.
        assert_eq!(rewrites, 15);
        assert!(sealed_drained_at - at_head <= 70 * MIN, "sealed backlog drained {} min after the head",
            (sealed_drained_at - at_head) / MIN);
        // 20Z and 21Z ride their own seal merges (no extra rewrite): the last
        // one seals at 23:00Z.
        assert_eq!(drained_at, 23 * 60 * MIN);
    }

    #[test]
    fn owed_hours_clear_only_when_not_marked_again() {
        let mut owed = OwedHours::default();
        assert!(owed.mark([10, 11]));
        assert!(owed.dirty());
        owed.mark_saved();
        let serial = owed.serial_of(10).unwrap();
        // A late unstamped batch for hour 10 lands while its restamp runs.
        assert!(!owed.mark([10]), "not a new hour");
        assert!(!owed.clear_if(10, serial), "re-marked: stays owed");
        assert!(owed.clear_if(11, owed.serial_of(11).unwrap()));
        assert_eq!(owed.hours().collect::<Vec<_>>(), vec![10]);
        assert!(owed.dirty());
        let restored = OwedHours::from_hours(OwedHours::parse(&owed.to_bytes()).unwrap());
        assert_eq!(restored.hours().collect::<Vec<_>>(), vec![10]);
        assert!(!restored.dirty());
    }
}
