// SPDX-License-Identifier: AGPL-3.0-or-later
//! Exact hourly OR counts in the existing signed entity-range sidecar.
//! No query fast path is enabled here. Coverage must come from a leased,
//! authenticated partial and its signed part row/time bounds.
use anyhow::{ensure, Context, Result};
use arrow_array::{
    Array, ArrayRef, LargeStringArray, RecordBatch, StringArray, StringViewArray, StructArray,
};
use arrow_schema::DataType;
use std::collections::BTreeMap;

use crate::generation::event_time_us_from_array;
use crate::part_ingest::partials::EntityRangeRow;
use crate::parts::HOUR_US;

pub const PATH: &str = "nano.entity_counts.v1";
/// Undeployed v2: JSON keys sort by (kind, value, nullable source, hour, mask).
/// NULL sources are distinct from empty and literal unknown source strings.
pub const V2_PATH: &str = "nano.entity_counts.source.v2";
pub const V2_COVERAGE_PATH: &str = "nano.entity_counts.coverage.source.v2";
pub const COVERAGE_PATH: &str = "nano.entity_counts.coverage.v1";
pub const MAX_VALUE_BYTES: usize = 2048;
const BUFFER_BYTES: usize = 8 * 1024 * 1024;
const SPILL_BYTES: usize = 512 * 1024 * 1024;
/// Frozen kind-local v1 masks, independent of BLOOM_PATHS ordering.
pub const KINDS: &[&[&str]] = &[
    &["src_endpoint.ip", "dst_endpoint.ip", "device.ip"],
    &["user.name", "user.uid", "actor.user.name", "actor.user.uid"],
    &["user.email_addr", "actor.user.email_addr"],
    &[
        "device.hostname",
        "src_endpoint.hostname",
        "dst_endpoint.hostname",
    ],
];
const ALL_KINDS: u64 = (1 << KINDS.len()) - 1;
const CELL_LIMITS: [usize; 4] = [750_000, 360_000, 8192, 17_000];
const BYTE_LIMITS: [usize; 4] = [
    384 * 1024 * 1024,
    256 * 1024 * 1024,
    8 * 1024 * 1024,
    8 * 1024 * 1024,
];
fn charge(value: &str) -> usize {
    256 + value.len() * 8
}
fn kind_for_mask(kind: usize, mask: u64) -> bool {
    KINDS
        .get(kind)
        .is_some_and(|fields| mask != 0 && mask < (1 << fields.len()))
}

pub fn enabled(value: Option<&str>) -> bool {
    value == Some("1")
}
pub fn is_count_path(path: &str) -> bool {
    matches!(path, PATH | COVERAGE_PATH | V2_PATH | V2_COVERAGE_PATH)
}

type CellKey = (usize, i64, u64, String, Option<String>);

fn decode_key(path: &str, key: &str) -> Result<CellKey> {
    if path == V2_PATH {
        let (kind, value, source, hour, mask): (usize, String, Option<String>, i64, u64) = serde_json::from_str(key)?;
        Ok((kind, hour, mask, value, source))
    } else {
        let (kind, hour, mask, value) = serde_json::from_str(key)?;
        Ok((kind, hour, mask, value, None))
    }
}

/// Absent leaves are known nulls. Repeated and non-string leaves are unknown.
fn scalar_or_absent(batch: &RecordBatch, path: &str) -> bool {
    let mut names = path.split('.');
    let root_name = names.next().unwrap();
    let Some(root) = batch
        .schema()
        .fields()
        .iter()
        .find(|f| f.name() == root_name)
        .cloned()
    else {
        return true;
    };
    let mut kind = root.data_type();
    for name in names {
        match kind {
            DataType::Struct(fields) => match fields.iter().find(|f| f.name() == name) {
                Some(field) => kind = field.data_type(),
                None => return true,
            },
            DataType::Null => return true,
            _ => return false,
        }
    }
    matches!(
        kind,
        DataType::Utf8 | DataType::LargeUtf8 | DataType::Utf8View | DataType::Null
    )
}

/// Borrow scalar strings so a pathological value is checked before copying.
struct ScalarColumn {
    leaf: ArrayRef,
    parents: Vec<ArrayRef>,
}
impl ScalarColumn {
    fn new(batch: &RecordBatch, path: &str) -> Option<Self> {
        let mut names = path.split('.');
        let mut leaf = batch.column_by_name(names.next()?)?.clone();
        let mut parents = Vec::new();
        for name in names {
            let structure = leaf.as_any().downcast_ref::<StructArray>()?;
            let child = structure.column_by_name(name)?.clone();
            parents.push(leaf);
            leaf = child;
        }
        Some(Self { leaf, parents })
    }
    fn value(&self, row: usize) -> Option<&str> {
        if self.leaf.is_null(row) || self.parents.iter().any(|parent| parent.is_null(row)) {
            return None;
        }
        if let Some(array) = self.leaf.as_any().downcast_ref::<StringArray>() {
            return Some(array.value(row));
        }
        if let Some(array) = self.leaf.as_any().downcast_ref::<LargeStringArray>() {
            return Some(array.value(row));
        }
        self.leaf
            .as_any()
            .downcast_ref::<StringViewArray>()
            .map(|array| array.value(row))
    }
}

/// Small in-memory aggregate plus a bounded, writer-local sorted spill.
#[derive(Default)]
pub struct Builder {
    cells: BTreeMap<CellKey, u64>,
    charged: usize,
    rows: u64,
    covered: Option<u64>,
    min: Option<i64>,
    max: Option<i64>,
    spill: Option<Spill>,
    spill_dir: Option<std::path::PathBuf>,
    budgets: Budgets,
    kind_cells: [usize; 4],
    kind_bytes: [usize; 4],
}
struct Budgets {
    cells: [usize; 4],
    bytes: [usize; 4],
}
impl Default for Budgets {
    fn default() -> Self {
        Self {
            cells: CELL_LIMITS,
            bytes: BYTE_LIMITS,
        }
    }
}
struct Spill {
    // Connection closes before the temporary file is removed.
    db: rusqlite::Connection,
    _file: tempfile::NamedTempFile,
}
impl Spill {
    fn new(directory: Option<&std::path::Path>) -> Result<Self> {
        let file = match directory {
            Some(directory) => tempfile::Builder::new()
                .prefix(".entity-counts-")
                .tempfile_in(directory)?,
            None => tempfile::NamedTempFile::new()?,
        };
        let db = rusqlite::Connection::open(file.path())?;
        // Optional indexing must not wait on SQLite locks.
        db.busy_timeout(std::time::Duration::ZERO)?;
        db.execute_batch(
            "PRAGMA page_size=4096; PRAGMA cache_size=-8192;
            PRAGMA mmap_size=0; PRAGMA journal_mode=OFF; PRAGMA synchronous=OFF;
            PRAGMA temp_store=FILE; PRAGMA max_page_count=131072;
            CREATE TABLE cells(kind INTEGER, key TEXT PRIMARY KEY, hour INTEGER,
                count INTEGER NOT NULL) WITHOUT ROWID;",
        )?;
        Ok(Self { db, _file: file })
    }
}
impl Builder {
    #[cfg(test)]
    pub(crate) fn force_flush_on_next_batch(&mut self) {
        self.charged = BUFFER_BYTES;
    }
    pub fn in_directory(directory: &std::path::Path) -> Self {
        Self {
            spill_dir: Some(directory.to_owned()),
            ..Self::default()
        }
    }
    fn abandon(&mut self, kind: usize) -> Result<()> {
        self.covered = Some(self.covered.unwrap_or(ALL_KINDS) & !(1 << kind));
        self.cells.retain(|(k, _, _, _, _), _| *k != kind);
        self.charged = self
            .cells
            .keys()
            .map(|(_, _, _, value, source)| charge(value) + source.as_ref().map_or(0, |s| charge(s)))
            .sum();
        if let Some(spill) = &self.spill {
            spill
                .db
                .execute("DELETE FROM cells WHERE kind=?", [kind as i64])?;
        }
        self.kind_cells[kind] = 0;
        self.kind_bytes[kind] = 0;
        Ok(())
    }
    fn flush(&mut self) -> Result<()> {
        if self.cells.is_empty() {
            return Ok(());
        }
        if self.spill.is_none() {
            self.spill = Some(Spill::new(self.spill_dir.as_deref())?);
        }
        let transaction = self.spill.as_mut().unwrap().db.transaction()?;
        let mut overflow = 0_u64;
        {
            let mut insert =
                transaction.prepare_cached("INSERT OR IGNORE INTO cells VALUES(?,?,?,?)")?;
            let mut update =
                transaction.prepare_cached("UPDATE cells SET count=count+? WHERE key=?")?;
            for ((kind, hour, mask, value, source), count) in std::mem::take(&mut self.cells) {
                if overflow & (1 << kind) != 0 {
                    continue;
                }
                let cost = charge(&value) + source.as_ref().map_or(0, |s| charge(s));
                let key = serde_json::to_string(&(kind, value, source, hour, mask))?;
                let count = i64::try_from(count).context("spill count exceeds signed range")?;
                if insert.execute(rusqlite::params![kind as i64, key, hour, count])? == 1 {
                    self.kind_cells[kind] += 1;
                    self.kind_bytes[kind] += cost;
                    if self.kind_cells[kind] > self.budgets.cells[kind]
                        || self.kind_bytes[kind] > self.budgets.bytes[kind]
                    {
                        overflow |= 1 << kind;
                    }
                } else {
                    update.execute(rusqlite::params![count, key])?;
                }
            }
        }
        transaction.commit()?;
        self.charged = 0;
        for kind in 0..KINDS.len() {
            if overflow & (1 << kind) != 0 {
                self.abandon(kind)?;
            }
        }
        ensure!(
            self.spill
                .as_ref()
                .unwrap()
                ._file
                .as_file()
                .metadata()?
                .len()
                <= SPILL_BYTES as u64,
            "count spill exceeds disk cap"
        );
        Ok(())
    }
    pub fn add_batch(&mut self, batch: &RecordBatch) -> Result<()> {
        self.covered.get_or_insert(ALL_KINDS);
        ensure!(scalar_or_absent(batch, "metadata.log_source"), "unknown count source type");
        let source = ScalarColumn::new(batch, "metadata.log_source");
        for (kind, fields) in KINDS.iter().enumerate() {
            if fields.iter().any(|path| !scalar_or_absent(batch, path)) {
                self.abandon(kind)?;
            }
        }
        let paths = KINDS
            .iter()
            .map(|fields| {
                fields
                    .iter()
                    .map(|path| ScalarColumn::new(batch, path))
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        let time = batch
            .column_by_name("time")
            .context("count index has no time")?;
        for row in 0..batch.num_rows() {
            let source = source.as_ref().and_then(|column| column.value(row));
            ensure!(source.is_none_or(|s| s.is_ascii() && s.len() <= MAX_VALUE_BYTES), "unsupported count source");
            let source = source.map(str::to_ascii_lowercase);
            let time =
                event_time_us_from_array(time.as_ref(), row).context("count row has no time")?;
            self.rows = self.rows.checked_add(1).context("count rows overflow")?;
            self.min = Some(self.min.map_or(time, |min| min.min(time)));
            self.max = Some(self.max.map_or(time, |max| max.max(time)));
            for (kind, fields) in KINDS.iter().enumerate() {
                if self.covered.unwrap() & (1 << kind) == 0 {
                    continue;
                }
                let mut values = BTreeMap::<String, u64>::new();
                let mut invalid = false;
                for (bit, path) in fields.iter().enumerate() {
                    if let Some(value) = paths[kind][bit]
                        .as_ref()
                        .and_then(|column| column.value(row))
                    {
                        if !value.is_ascii() || value.len() > MAX_VALUE_BYTES {
                            invalid = true;
                            break;
                        }
                        *values
                            .entry(crate::parts::entity_locators::normalized(path, value))
                            .or_default() |= 1 << bit;
                    }
                }
                if invalid {
                    self.abandon(kind)?;
                    continue;
                }
                for (value, mask) in values {
                    let key = (kind, time.div_euclid(HOUR_US), mask, value, source.clone());
                    if !self.cells.contains_key(&key) {
                        self.charged += charge(&key.3) + key.4.as_ref().map_or(0, |s| charge(s));
                    }
                    let count = self.cells.entry(key).or_default();
                    *count = count.checked_add(1).context("entity count overflow")?;
                }
                if self.charged >= BUFFER_BYTES {
                    self.flush()?;
                }
            }
        }
        Ok(())
    }
    pub fn into_sorted_rows(mut self) -> Result<SortedCounts> {
        self.flush()?;
        let coverage = if self.rows > 0 && self.covered.unwrap_or(0) != 0 {
            Some(EntityRangeRow {
                key: (
                    V2_COVERAGE_PATH.into(),
                    serde_json::to_string(&self.covered.unwrap())?,
                ),
                first_time: self.min.unwrap(),
                last_time: self.max.unwrap(),
                events: self.rows,
            })
        } else {
            None
        };
        Ok(SortedCounts {
            builder: self,
            coverage,
            last: None,
        })
    }
    #[cfg(test)]
    pub fn into_rows(self) -> Result<Vec<EntityRangeRow>> {
        let mut sorted = self.into_sorted_rows()?;
        let mut rows = Vec::new();
        while let Some(row) = sorted.next()? {
            rows.push(row);
        }
        Ok(rows)
    }
}
/// Streaming keyset scan: neither sorting nor output materialization grows
/// with the part's cardinality. SQLite primary-key order matches partial keys.
pub struct SortedCounts {
    builder: Builder,
    coverage: Option<EntityRangeRow>,
    last: Option<String>,
}
impl SortedCounts {
    pub fn next(&mut self) -> Result<Option<EntityRangeRow>> {
        if let Some(coverage) = self.coverage.take() {
            return Ok(Some(coverage));
        }
        let Some(spill) = &self.builder.spill else {
            return Ok(None);
        };
        use rusqlite::OptionalExtension;
        let mut statement = spill.db.prepare_cached(
            "SELECT key,hour,count FROM cells WHERE key > ? ORDER BY key LIMIT 1",
        )?;
        let row = statement
            .query_row([self.last.as_deref().unwrap_or("")], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                ))
            })
            .optional()?;
        let Some((key, hour, count)) = row else {
            return Ok(None);
        };
        let start = hour.checked_mul(HOUR_US).context("count hour overflow")?;
        self.last = Some(key.clone());
        Ok(Some(EntityRangeRow {
            key: (V2_PATH.into(), key),
            first_time: start,
            last_time: start,
            events: u64::try_from(count).context("negative spill count")?,
        }))
    }
}

/// Decoded v1/v2 evidence. Only `from_rows` constructs a covered index.
#[derive(Clone)]
pub struct Index {
    mask: u64,
    source_dimension: bool,
    cells: BTreeMap<CellKey, u64>,
}
impl Index {
    /// Call only with rows from a verified signed partial, using the same
    /// part's signed row count and bounds. Missing coverage stays unknown.
    pub fn from_rows(
        rows: impl IntoIterator<Item = EntityRangeRow>,
        signed_rows: u64,
        min: i64,
        max: i64,
    ) -> Result<Option<Self>> {
        Self::from_selected_rows(rows.into_iter().map(Ok), signed_rows, min, max)
    }

    /// Stream only the requested kind from a currently leased signed sidecar.
    /// Other namespaces and kinds never enter the decoded cell map.
    pub fn from_kind_file(
        path: &std::path::Path,
        kind: usize,
        signed_rows: u64,
        min: i64,
        max: i64,
    ) -> Result<Option<Self>> {
        Self::from_kind_file_before(path, kind, signed_rows, min, max, None)
    }

    pub(crate) fn from_kind_file_before(
        path: &std::path::Path,
        kind: usize,
        signed_rows: u64,
        min: i64,
        max: i64,
        deadline: Option<std::time::Instant>,
    ) -> Result<Option<Self>> {
        Self::from_reader(std::fs::File::open(path)?, kind, None, None, signed_rows, min, max, deadline)
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn from_reader<R: parquet::file::reader::ChunkReader + 'static>(
        source: R, kind: usize, value: Option<String>, groups: Option<Vec<usize>>,
        signed_rows: u64, min: i64, max: i64, deadline: Option<std::time::Instant>,
    ) -> Result<Option<Self>> {
        use arrow_array::{TimestampMicrosecondArray, UInt64Array};
        use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;
        ensure!(kind < KINDS.len(), "unknown count kind");
        let mut builder = ParquetRecordBatchReaderBuilder::try_new(source)?.with_batch_size(256);
        if let Some(groups) = groups { builder = builder.with_row_groups(groups); }
        let reader = builder.build()?;
        let point = value.is_some();
        let rows = reader.flat_map(move |batch| -> Vec<Result<EntityRangeRow>> {
            let decode = || -> Result<Vec<Result<EntityRangeRow>>> {
                ensure!(deadline.is_none_or(|at| std::time::Instant::now() < at), "count index budget expired");
                let batch = batch?;
                let paths = batch
                    .column_by_name("path")
                    .context("count path")?
                    .as_any()
                    .downcast_ref::<StringArray>()
                    .context("count path type")?;
                let values = batch
                    .column_by_name("value")
                    .context("count value")?
                    .as_any()
                    .downcast_ref::<StringArray>()
                    .context("count value type")?;
                let first = batch
                    .column_by_name("first_time")
                    .context("count first")?
                    .as_any()
                    .downcast_ref::<TimestampMicrosecondArray>()
                    .context("count first type")?;
                let last = batch
                    .column_by_name("last_time")
                    .context("count last")?
                    .as_any()
                    .downcast_ref::<TimestampMicrosecondArray>()
                    .context("count last type")?;
                let events = batch
                    .column_by_name("events")
                    .context("count events")?
                    .as_any()
                    .downcast_ref::<UInt64Array>()
                    .context("count events type")?;
                let mut rows = Vec::new();
                for i in 0..batch.num_rows() {
                    ensure!(!paths.is_null(i) && !values.is_null(i), "null count key");
                    if !is_count_path(paths.value(i)) {
                        continue;
                    }
                    ensure!(
                        values.value(i).len() <= MAX_VALUE_BYTES * 12 + 128,
                        "count key too long"
                    );
                    if matches!(paths.value(i), PATH | V2_PATH) {
                        let (cell_kind, _, _, cell_value, _): (usize, i64, u64, String, Option<String>) =
                            decode_key(paths.value(i), values.value(i))?;
                        ensure!(cell_kind < KINDS.len(), "unknown count kind");
                        if cell_kind != kind || value.as_ref().is_some_and(|v| v != &cell_value) {
                            continue;
                        }
                    }
                    ensure!(
                        !first.is_null(i) && !last.is_null(i) && !events.is_null(i),
                        "null count bounds"
                    );
                    rows.push(Ok(EntityRangeRow {
                        key: (paths.value(i).into(), values.value(i).into()),
                        first_time: first.value(i),
                        last_time: last.value(i),
                        events: events.value(i),
                    }));
                }
                Ok(rows)
            };
            match decode() {
                Ok(rows) => rows,
                Err(error) => vec![Err(error)],
            }
        });
        let mut point_bytes = 0_usize;
        let rows = rows.map(|row| {
            let row = row?;
            if point {
                point_bytes = point_bytes.checked_add(charge(&row.key.1)).context("point charge overflow")?;
                ensure!(point_bytes <= 2 * 1024 * 1024, "point count exceeds memory envelope");
            }
            Ok(row)
        });
        let mut index = Self::from_selected_rows(rows, signed_rows, min, max)?;
        if let Some(index) = &mut index {
            index.mask &= 1 << kind;
        }
        Ok(index)
    }

    fn from_selected_rows(
        rows: impl IntoIterator<Item = Result<EntityRangeRow>>,
        signed_rows: u64,
        min: i64,
        max: i64,
    ) -> Result<Option<Self>> {
        ensure!(signed_rows > 0 && min <= max, "invalid signed count bounds");
        let mut coverage = None;
        let mut cell_version = None;
        let mut cells = BTreeMap::new();
        let mut charged = [0_usize; 4];
        let mut kind_cells = [0_usize; 4];
        let mut totals = BTreeMap::<(usize, String), u64>::new();
        for row in rows {
            let row = row?;
            if !is_count_path(&row.key.0) {
                continue;
            }
            ensure!(
                row.key.1.len() <= MAX_VALUE_BYTES * 12 + 128,
                "count key too long"
            );
            if matches!(row.key.0.as_str(), COVERAGE_PATH | V2_COVERAGE_PATH) {
                ensure!(
                    coverage.is_none()
                        && row.events == signed_rows
                        && row.first_time == min
                        && row.last_time == max,
                    "count coverage differs from signed part"
                );
                let mask: u64 = serde_json::from_str(&row.key.1)?;
                ensure!(
                    mask != 0 && mask & !ALL_KINDS == 0,
                    "unsupported count coverage mask"
                );
                coverage = Some((mask, row.key.0 == V2_COVERAGE_PATH));
                continue;
            }
            let version = row.key.0 == V2_PATH;
            ensure!(cell_version.is_none_or(|old| old == version), "mixed count versions");
            cell_version = Some(version);
            let (kind, hour, mask, value, source): (usize, i64, u64, String, Option<String>) =
                decode_key(&row.key.0, &row.key.1)?;
            ensure!(source.as_ref().is_none_or(|s| s.is_ascii() && s.len() <= MAX_VALUE_BYTES && s == &s.to_ascii_lowercase()), "unsupported count source");
            let start = hour.checked_mul(HOUR_US).context("count hour overflow")?;
            ensure!(
                hour >= min.div_euclid(HOUR_US)
                    && hour <= max.div_euclid(HOUR_US)
                    && row.first_time == start
                    && row.last_time == start
                    && row.events > 0
                    && row.events <= signed_rows,
                "invalid count cell bounds"
            );
            ensure!(
                value.is_ascii() && value.len() <= MAX_VALUE_BYTES && kind_for_mask(kind, mask),
                "unsupported count cell"
            );
            // Every non-raw field must contain its already-folded spelling.
            ensure!(
                KINDS[kind]
                    .iter()
                    .enumerate()
                    .all(|(bit, path)| mask & (1 << bit) == 0
                        || crate::parts::entity_locators::normalized(path, &value) == value),
                "count normalization differs"
            );
            charged[kind] = charged[kind]
                .checked_add(charge(&value) + source.as_ref().map_or(0, |s| charge(s)))
                .context("count charge overflow")?;
            kind_cells[kind] += 1;
            ensure!(
                charged[kind] <= BYTE_LIMITS[kind] && kind_cells[kind] <= CELL_LIMITS[kind],
                "count index exceeds kind envelope"
            );
            let total = totals.entry((kind, value.clone())).or_default();
            *total = total
                .checked_add(row.events)
                .context("count total overflow")?;
            ensure!(*total <= signed_rows, "count cohorts exceed signed rows");
            ensure!(
                cells
                    .insert((kind, hour, mask, value, source), row.events)
                    .is_none(),
                "duplicate count cell"
            );
        }
        let Some((mask, source_dimension)) = coverage else {
            return Ok(None);
        };
        ensure!(
            cells.keys().all(|(kind, _, _, _, _)| mask & (1 << kind) != 0),
            "cell outside count coverage"
        );
        ensure!(cell_version.is_none_or(|version| version == source_dimension), "count coverage version differs");
        Ok(Some(Self { mask, source_dimension, cells }))
    }
    pub(crate) fn has_source_dimension(&self) -> bool { self.source_dimension }

    /// Retain all hourly cohorts for one literal, independent of query bounds.
    pub(crate) fn select_value(mut self, kind: usize, value: &str) -> Self {
        self.mask &= 1 << kind;
        self.cells.retain(|(k, _, _, v, _), _| *k == kind && v == value);
        self
    }

    pub(crate) fn memo_bytes(&self) -> usize {
        std::mem::size_of::<Self>() + self.cells.keys()
            .map(|(_, _, _, value, source)| charge(value) + source.as_ref().map_or(0, |s| charge(s))).sum::<usize>()
    }

    /// Half-open UTC-hour-aligned window; OR legs must compare the same
    /// ASCII literal. Other predicates and partial hours require native SQL.
    pub fn count_from_index(&self, window: (i64, i64), pivot: &[(&str, &str)]) -> Option<u64> {
        self.count_allowed(window, pivot, &std::collections::BTreeSet::new())
    }

    pub(crate) fn count_allowed(&self, window: (i64, i64), pivot: &[(&str, &str)], denied: &std::collections::BTreeSet<String>) -> Option<u64> {
        if !denied.is_empty() && !self.source_dimension { return None; }
        let (from, to) = window;
        if from > to || from.rem_euclid(HOUR_US) != 0 || to.rem_euclid(HOUR_US) != 0 {
            return None;
        }
        let value = pivot.first()?.1;
        if !value.is_ascii() || value.len() > MAX_VALUE_BYTES {
            return None;
        }
        let value = value.to_ascii_lowercase();
        let kind = KINDS
            .iter()
            .position(|fields| fields.contains(&pivot[0].0))?;
        let mut bits = 0;
        for (path, literal) in pivot {
            if !literal.is_ascii() || literal.to_ascii_lowercase() != value {
                return None;
            }
            let bit = KINDS[kind].iter().position(|field| field == path)?;
            bits |= 1 << bit;
        }
        if self.mask & (1 << kind) == 0 {
            return None;
        }
        self.cells
            .iter()
            .filter(|((cell_kind, hour, mask, entity, source), _)| {
                *cell_kind == kind
                    && (denied.is_empty() || source.as_ref().is_some_and(|s| !denied.contains(s)))
                    && *hour >= from.div_euclid(HOUR_US)
                    && *hour < to.div_euclid(HOUR_US)
                    && mask & bits != 0
                    && entity == &value
            })
            .try_fold(0_u64, |sum, (_, count)| sum.checked_add(*count))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::generation::CompiledStringPath;
    use crate::part_ingest::schema::{decode, infer_schema};
    use std::sync::Arc;

    fn fixture() -> RecordBatch {
        let events = (0..240).map(|row| serde_json::json!({
            "time": chrono::DateTime::from_timestamp((row / 80) * 3600 + row % 80, 0).unwrap().to_rfc3339(),
            "user": {"name": if row % 3 == 0 { "ALIce" } else { "bob" }, "email_addr": "ALIce", "uid": "ALICE"},
            "actor": {"user": {"name": if row % 2 == 0 { "Alice" } else { "carol" }, "uid": "Alice", "email_addr": "alice"}},
            "device": {"hostname": if row % 2 == 0 { "HOST" } else { "host" }},
            "src_endpoint": {"ip": if row % 5 == 0 { "10.0.0.1" } else { "" }, "hostname": "host"},
            "dst_endpoint": {"ip": if row % 7 == 0 { "10.0.0.1" } else { "10.0.0.2" }}
        })).collect::<Vec<_>>();
        let refs = events.iter().collect::<Vec<_>>();
        decode(Arc::new(infer_schema(&refs).unwrap()), &refs).unwrap()
    }
    fn build_index(batch: &RecordBatch) -> (Vec<EntityRangeRow>, Index) {
        let mut builder = Builder::default();
        // Deliberately split batches to verify aggregation across batches.
        for from in (0..batch.num_rows()).step_by(17) {
            builder
                .add_batch(&batch.slice(from, 17.min(batch.num_rows() - from)))
                .unwrap();
        }
        let rows = builder.into_rows().unwrap();
        let time = batch.column_by_name("time").unwrap();
        let bounds = (0..batch.num_rows())
            .map(|row| event_time_us_from_array(time.as_ref(), row).unwrap())
            .collect::<Vec<_>>();
        let index = Index::from_rows(
            rows.clone(),
            batch.num_rows() as u64,
            *bounds.iter().min().unwrap(),
            *bounds.iter().max().unwrap(),
        )
        .unwrap()
        .unwrap();
        (rows, index)
    }
    #[test]
    fn entity_counts_brute_force_or_case_and_random_aligned_windows() {
        let batch = fixture();
        let (_, index) = build_index(&batch);
        let pivots = [
            vec![("user.name", "ALICE"), ("actor.user.name", "Alice")],
            vec![
                ("user.email_addr", "alice"),
                ("actor.user.email_addr", "alice"),
            ],
            vec![
                ("src_endpoint.ip", "10.0.0.1"),
                ("dst_endpoint.ip", "10.0.0.1"),
                ("device.ip", "10.0.0.1"),
            ],
            vec![
                ("device.hostname", "HOST"),
                ("src_endpoint.hostname", "host"),
            ],
            vec![
                ("user.name", "alice"),
                ("user.uid", "alice"),
                ("actor.user.name", "ALICE"),
                ("actor.user.uid", "alice"),
            ],
            vec![("src_endpoint.ip", "")],
            vec![("user.name", "absent")],
        ];
        for pivot in &pivots {
            for from in -1..=3 {
                for to in from..=4 {
                    let window = (from * HOUR_US, to * HOUR_US);
                    let expected = (0..batch.num_rows()).filter(|row| {
                        let time = event_time_us_from_array(batch.column_by_name("time").unwrap().as_ref(), *row).unwrap();
                        time >= window.0 && time < window.1 && pivot.iter().any(|(path, literal)| {
                            CompiledStringPath::new(&batch, path).is_some_and(|compiled| compiled.strings(*row).iter().any(|value| {
                                if crate::part_query::prune::INGEST_LOWERCASED_BLOOM_PATHS.contains(path) { value == &literal.to_ascii_lowercase() }
                                else { value.eq_ignore_ascii_case(literal) }
                            }))
                        })
                    }).count() as u64;
                    assert_eq!(index.count_from_index(window, pivot), Some(expected));
                }
            }
        }
        assert_eq!(index.count_from_index((1, HOUR_US), &pivots[0]), None);
        assert_eq!(
            index.count_from_index((0, HOUR_US), &[("user.name", "Älice")]),
            None
        );
        assert_eq!(
            index.count_from_index((0, HOUR_US), &[("unknown", "alice")]),
            None
        );
        assert_eq!(
            index.count_from_index(
                (0, HOUR_US),
                &[("user.name", "alice"), ("actor.user.name", "bob")]
            ),
            None
        );
        assert_eq!(index.count_from_index((HOUR_US, 0), &pivots[0]), None);
    }
    #[test]
    fn entity_counts_source_denies_or_masks_case_and_nulls() {
        let sources = [Some("audit"), Some("AUDIT"), Some("sysmon"), Some("unknown"), Some(""), None];
        let events = sources.iter().enumerate().map(|(i, source)| serde_json::json!({
            "time": "1970-01-01T00:00:00Z",
            "metadata": {"log_source": source},
            "user": {"name": "ALICE"},
            "actor": {"user": {"name": if i % 2 == 0 {"Alice"} else {"bob"}}}
        })).collect::<Vec<_>>();
        let refs = events.iter().collect::<Vec<_>>();
        let batch = decode(Arc::new(infer_schema(&refs).unwrap()), &refs).unwrap();
        let (_, index) = build_index(&batch);
        let pivot = [("user.name", "ALICE"), ("actor.user.name", "Alice")];
        assert_eq!(index.count_from_index((0, HOUR_US), &pivot), Some(6));
        let denied = std::collections::BTreeSet::from(["audit".to_owned()]);
        // NULL != audit is NULL and does not pass WHERE. The literal unknown
        // and the empty scalar string do pass it; overlapping OR legs count once.
        assert_eq!(index.count_allowed((0, HOUR_US), &pivot, &denied), Some(3));
        let denied = std::collections::BTreeSet::from(["audit".to_owned(), "sysmon".to_owned()]);
        assert_eq!(index.count_allowed((0, HOUR_US), &pivot, &denied), Some(2));
    }

    #[test]
    fn entity_counts_v1_v2_compatibility() {
        let (v2, index) = build_index(&fixture());
        let mut wrong_version = v2.clone();
        wrong_version[0].key.0 = COVERAGE_PATH.into();
        assert!(Index::from_rows(wrong_version, 240, 0, 2 * HOUR_US + 239 % 80 * 1_000_000).is_err());
        let v1 = v2.into_iter().map(|mut row| {
            if row.key.0 == V2_COVERAGE_PATH { row.key.0 = COVERAGE_PATH.into(); }
            else if row.key.0 == V2_PATH {
                let (kind, hour, mask, value, _) = decode_key(&row.key.0, &row.key.1).unwrap();
                let key = (kind, hour, mask, value);
                row.key = (PATH.into(), serde_json::to_string(&key).unwrap());
            }
            row
        }).collect::<Vec<_>>();
        let legacy = Index::from_rows(v1, 240, 0, 2 * HOUR_US + 239 % 80 * 1_000_000).unwrap().unwrap();
        for literal in ["10.0.0.1", "absent"] {
            let pivot = [("src_endpoint.ip", literal), ("dst_endpoint.ip", literal)];
            assert_eq!(legacy.count_from_index((0, 3 * HOUR_US), &pivot), index.count_from_index((0, 3 * HOUR_US), &pivot));
        }
    }

    #[test]
    fn entity_counts_missing_corrupt_and_wrong_part_coverage_are_unknown() {
        let batch = fixture();
        let (rows, _) = build_index(&batch);
        let min = 0;
        let max = 2 * HOUR_US + 239 % 80 * 1_000_000;
        assert!(Index::from_rows(Vec::new(), 240, min, max)
            .unwrap()
            .is_none());
        assert!(Index::from_rows(rows.clone(), 241, min, max).is_err());
        assert!(Index::from_rows(rows.clone(), 240, min + 1, max).is_err());
        let mut duplicate = rows.clone();
        duplicate.push(rows[1].clone());
        assert!(Index::from_rows(duplicate, 240, min, max).is_err());
        let mut corrupt = rows.clone();
        corrupt[1].events = u64::MAX;
        assert!(Index::from_rows(corrupt, 240, min, max).is_err());
        for key in ["[99,0,1,\"alice\"]", "[0,0,8,\"alice\"]"] {
            let mut corrupt = rows.clone();
            corrupt[1].key.1 = key.into();
            assert!(Index::from_rows(corrupt, 240, min, max).is_err());
        }
        let mut corrupt = rows;
        corrupt[0].key.1 = u64::MAX.to_string();
        assert!(Index::from_rows(corrupt, 240, min, max).is_err());
    }
    #[test]
    fn entity_counts_unicode_long_values_and_repeated_fields_fall_back() {
        let make = |value: serde_json::Value| {
            let events = [value];
            let refs = events.iter().collect::<Vec<_>>();
            decode(Arc::new(infer_schema(&refs).unwrap()), &refs).unwrap()
        };
        for value in ["Älice".to_string(), "x".repeat(MAX_VALUE_BYTES + 1)] {
            let batch =
                make(serde_json::json!({"time": "1970-01-01T00:00:00Z", "user": {"name": value}}));
            let mut builder = Builder::default();
            builder.add_batch(&batch).unwrap();
            let rows = builder.into_rows().unwrap();
            assert_eq!(serde_json::from_str::<u64>(&rows[0].key.1).unwrap() & 2, 0);
        }
        let batch = make(
            serde_json::json!({"time": "1970-01-01T00:00:00Z", "user": {"name": ["alice", "bob"]}, "src_endpoint": {"ip": "10.0.0.1"}}),
        );
        let (_, index) = build_index(&batch);
        assert_eq!(
            index.count_from_index((0, HOUR_US), &[("user.name", "alice")]),
            None
        );
        assert_eq!(
            index.count_from_index((0, HOUR_US), &[("src_endpoint.ip", "10.0.0.1")]),
            Some(1)
        );
        let batch =
            make(serde_json::json!({"time": "1969-12-31T23:59:59Z", "user": {"name": null}}));
        let (_, index) = build_index(&batch);
        assert_eq!(
            index.count_from_index((-HOUR_US, 0), &[("user.name", "")]),
            Some(0)
        );
    }

    #[test]
    fn entity_counts_kind_overflow_preserves_other_kinds_and_flag_defaults_off() {
        assert!(!enabled(None));
        assert!(!enabled(Some("true")));
        assert!(!enabled(Some("0")));
        assert!(enabled(Some("1")));
        let events = (0..4096)
            .map(|row| {
                serde_json::json!({
                    "time": "1970-01-01T00:00:00Z", "src_endpoint": {"ip": format!("10.{row}")},
                    "user": {"name": "ALICE"}
                })
            })
            .collect::<Vec<_>>();
        let refs = events.iter().collect::<Vec<_>>();
        let batch = decode(Arc::new(infer_schema(&refs).unwrap()), &refs).unwrap();
        for byte_overflow in [false, true] {
            let mut builder = Builder::default();
            if byte_overflow {
                builder.budgets.bytes[0] = 1024;
            } else {
                builder.budgets.cells[0] = 128;
            }
            builder.add_batch(&batch).unwrap();
            let rows = builder.into_rows().unwrap();
            let index = Index::from_rows(rows, 4096, 0, 0).unwrap().unwrap();
            assert_eq!(
                index.count_from_index((0, HOUR_US), &[("src_endpoint.ip", "10.1")]),
                None
            );
            assert_eq!(
                index.count_from_index((0, HOUR_US), &[("user.name", "alice")]),
                Some(4096)
            );
            assert_eq!(
                index.count_from_index(
                    (0, HOUR_US),
                    &[("user.name", "alice"), ("user.email_addr", "alice")]
                ),
                None
            );
        }
        assert!(KINDS
            .iter()
            .flat_map(|fields| fields.iter())
            .all(|path| crate::parts::format::BLOOM_PATHS.contains(path)));
        assert!(!KINDS
            .iter()
            .flat_map(|fields| fields.iter())
            .any(|path| *path == "metadata.uid"));
    }

    #[test]
    fn entity_counts_million_row_hour_with_250k_cells_is_covered() {
        let events = (0..25_000)
            .map(|row| {
                serde_json::json!({
                    "time": "1970-01-01T00:00:00Z", "src_endpoint": {"ip": format!("10.{row}")},
                    "user": {"name": "Alice"}, "metadata": {"uid": format!("event-{row}")}
                })
            })
            .collect::<Vec<_>>();
        let refs = events.iter().collect::<Vec<_>>();
        let batch = decode(Arc::new(infer_schema(&refs).unwrap()), &refs).unwrap();
        let mut builder = Builder::default();
        for group in 0..10 {
            let mut events = events.clone();
            for (row, event) in events.iter_mut().enumerate() {
                event["src_endpoint"]["ip"] = format!("10.{}", group * 25_000 + row).into();
            }
            let refs = events.iter().collect::<Vec<_>>();
            let batch = decode(batch.schema(), &refs).unwrap();
            for _ in 0..4 {
                builder.add_batch(&batch).unwrap();
            }
        }
        builder.flush().unwrap();
        assert_eq!(builder.rows, 1_000_000);
        assert_eq!(builder.kind_cells[0], 250_000);
        assert!(builder.charged < BUFFER_BYTES);
        let index = Index::from_rows(builder.into_rows().unwrap(), 1_000_000, 0, 0)
            .unwrap()
            .unwrap();
        assert_eq!(
            index.count_from_index((0, HOUR_US), &[("src_endpoint.ip", "10.42")]),
            Some(4)
        );
        assert_eq!(
            index.count_from_index((0, HOUR_US), &[("user.name", "alice")]),
            Some(1_000_000)
        );
    }
    #[test]
    fn entity_counts_sorted_spill_is_part_local_and_removed_on_drop() {
        let dir = tempfile::tempdir().unwrap();
        let mut builder = Builder::in_directory(dir.path());
        builder.add_batch(&fixture()).unwrap();
        let mut sorted = builder.into_sorted_rows().unwrap();
        let files = std::fs::read_dir(dir.path()).unwrap().collect::<Vec<_>>();
        assert_eq!(files.len(), 1);
        let spill = files.into_iter().next().unwrap().unwrap().path();
        assert!(spill
            .file_name()
            .unwrap()
            .to_str()
            .unwrap()
            .starts_with(".entity-counts-"));
        let mut previous = None;
        while let Some(row) = sorted.next().unwrap() {
            if let Some(previous) = &previous {
                assert!(previous < &row.key);
            }
            previous = Some(row.key);
        }
        drop(sorted);
        assert!(!spill.exists());
    }
}
