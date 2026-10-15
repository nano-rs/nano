// SPDX-License-Identifier: AGPL-3.0-or-later

//! Build every sidecar of one adopted object in one streaming pass.
//!
//! The object is read one row group at a time, in batches of
//! `BuildBudgets::batch_rows`. Per row group the token filter is built and
//! dropped; partials aggregate into
//! spilling aggregators; Merkle leaves go to a bounded external sort. Peak
//! memory is one decoded batch, one row group's token set, the partial caps
//! and the leaf buffer, independent of the object's size.

use anyhow::{bail, Context, Result};
use arrow_schema::Schema as ArrowSchema;
use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;
use std::collections::BTreeSet;
use std::fs::File;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use super::leaves::LeafSorter;
use super::partials::{PartialCaps, RowPartials};
use crate::generation::{event_time_us_from_array, CompiledStringPath};
use crate::parts::format::{schema_fingerprint, tokens_file_name, BLOOM_PATHS, TIME_COLUMN, UID_PATH};
use crate::parts::provenance::{row_digests, HourDigest, MerkleBuilder, PartialKind};
use crate::parts::sidecar::{TokenGroup, TokenGroupBuilder, TOKEN_FIELDS, TOKEN_INDEX_MAGIC, TOKEN_INDEX_VERSION, TOKENIZER};
use sha2::{Digest, Sha256};
use std::io::Write;
use crate::parts::{event_day_of, event_hour_of, Level};

/// Memory bounds of one object's build (design section 4 budgets).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BuildBudgets {
    /// Rows decoded at once.
    pub batch_rows: usize,
    /// Merkle leaves buffered before a sorted run spills (~90 B each).
    pub leaf_run_leaves: usize,
    pub partial_caps: PartialCaps,
    /// Largest row group accepted. One row group's distinct tokens are held
    /// while its filter is built, so this bounds that set (the token set is
    /// also capped at 2M distinct). tenant1's packer writes 262,144.
    pub max_row_group_rows: u64,
}

impl Default for BuildBudgets {
    fn default() -> Self {
        Self {
            batch_rows: 8_192,
            leaf_run_leaves: 262_144,
            partial_caps: PartialCaps::default(),
            max_row_group_rows: 1_048_576,
        }
    }
}

/// Footer-only shape of an object (no row decoding).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub struct ObjectProfile {
    pub rows: u64,
    pub row_groups: usize,
    pub max_row_group_rows: u64,
    /// Largest row group's uncompressed size.
    pub max_row_group_bytes: u64,
}

pub fn object_profile(data: &Path) -> Result<ObjectProfile> {
    let builder = ParquetRecordBatchReaderBuilder::try_new(File::open(data)?)
        .with_context(|| format!("open adopted object {}", data.display()))?;
    let metadata = builder.metadata();
    Ok(ObjectProfile {
        rows: u64::try_from(metadata.file_metadata().num_rows()).unwrap_or(0),
        row_groups: metadata.num_row_groups(),
        max_row_group_rows: metadata.row_groups().iter().map(|g| g.num_rows().max(0) as u64).max().unwrap_or(0),
        max_row_group_bytes: metadata.row_groups().iter().map(|g| g.total_byte_size().max(0) as u64).max().unwrap_or(0),
    })
}

/// Writes `tokens-{i:05}.nti` one row group at a time: the same bytes as
/// `sidecar::encode_token_index`, without holding every group's filter.
struct TokenIndexWriter {
    out: std::io::BufWriter<File>,
    hasher: Sha256,
    expected: u32,
    written: u32,
}

impl TokenIndexWriter {
    fn create(path: &Path, groups: u32) -> Result<Self> {
        let mut writer = Self { out: std::io::BufWriter::new(File::create(path)?), hasher: Sha256::new(), expected: groups, written: 0 };
        writer.put(TOKEN_INDEX_MAGIC)?;
        writer.put(&TOKEN_INDEX_VERSION.to_le_bytes())?;
        writer.put(&(TOKENIZER.len() as u16).to_le_bytes())?;
        writer.put(TOKENIZER.as_bytes())?;
        writer.put(&groups.to_le_bytes())?;
        Ok(writer)
    }

    fn put(&mut self, bytes: &[u8]) -> Result<()> {
        self.hasher.update(bytes);
        self.out.write_all(bytes)?;
        Ok(())
    }

    fn group(&mut self, group: &TokenGroup) -> Result<()> {
        if !group.bitset.len().is_multiple_of(32) {
            bail!("token filter bitset is not a whole number of blocks");
        }
        self.put(&group.rows.to_le_bytes())?;
        self.put(&group.tokens.to_le_bytes())?;
        self.put(&u32::try_from(group.bitset.len())?.to_le_bytes())?;
        self.put(&group.bitset)?;
        self.written += 1;
        Ok(())
    }

    fn finish(mut self) -> Result<()> {
        if self.written != self.expected {
            bail!("token index wrote {} of {} groups", self.written, self.expected);
        }
        let digest = std::mem::take(&mut self.hasher).finalize();
        self.out.write_all(&digest)?;
        self.out.into_inner().map_err(|e| e.into_error())?.sync_all()?;
        Ok(())
    }
}

/// The sidecars of one adopted object, staged in a local directory.
#[derive(Debug, Clone)]
pub struct BuiltSidecars {
    /// Staging directory; files sit at their part-relative names.
    pub dir: PathBuf,
    pub rows: u64,
    pub min_time_us: i64,
    pub max_time_us: i64,
    pub level: Level,
    /// Event hour (first hour of the day for a day part).
    pub event_hour: i32,
    pub event_day: Option<i32>,
    pub hours: Vec<HourDigest>,
    pub merkle_root: String,
    pub row_groups: u32,
    pub schema: Arc<ArrowSchema>,
    pub schema_fingerprint: String,
    /// (kind, relative name, rows) of each partial file.
    pub partials: Vec<(PartialKind, &'static str, u64)>,
    /// `BLOOM_PATHS` columns present in the object without a Parquet bloom
    /// in some row group. Reported only: a missing bloom means "read the
    /// group" (never a wrong answer); tenant1's packer writes all of them.
    pub blooms_missing: Vec<String>,
    /// Adjacent leaves with equal `(time, uid)` (reported, never dropped).
    pub duplicate_uids: u64,
    pub leaf_runs: usize,
    pub partial_runs: usize,
}

impl BuiltSidecars {
    /// Every staged file: (part-relative name, local path). The token index
    /// of the single data file is `tokens-00000.nti`.
    pub fn files(&self) -> Vec<(String, PathBuf)> {
        let tokens = tokens_file_name(0);
        let mut files = vec![(tokens.clone(), self.dir.join(&tokens))];
        files.extend(self.partials.iter().map(|(_, name, _)| ((*name).to_string(), self.dir.join(name))));
        files
    }
}

/// `BLOOM_PATHS` leaves present in the file whose Parquet bloom is missing
/// from at least one row group.
fn missing_bloom_columns(metadata: &parquet::file::metadata::ParquetMetaData) -> Vec<String> {
    let descr = metadata.file_metadata().schema_descr();
    let mut missing = BTreeSet::new();
    for (index, column) in descr.columns().iter().enumerate() {
        let path = column.path().string();
        if !BLOOM_PATHS.contains(&path.as_str()) {
            continue;
        }
        if metadata.row_groups().iter().any(|group| group.column(index).bloom_filter_offset().is_none()) {
            missing.insert(path);
        }
    }
    // Keep the contract order so the file is deterministic.
    BLOOM_PATHS.iter().filter(|p| missing.contains(**p)).map(|p| (*p).to_string()).collect()
}

struct HourAccumulator {
    event_hour: i32,
    rows: u64,
    min_time_us: i64,
    max_time_us: i64,
    merkle: MerkleBuilder,
}

/// Build the sidecars of the Parquet object at `data` into `staging` (which
/// must not exist). Reads the object once.
pub fn build_adopted_sidecars(data: &Path, staging: &Path, budgets: &BuildBudgets) -> Result<BuiltSidecars> {
    if staging.exists() {
        bail!("adoption staging directory {} already exists", staging.display());
    }
    std::fs::create_dir_all(staging.join(".spill"))?;
    let spill = staging.join(".spill");
    let builder = ParquetRecordBatchReaderBuilder::try_new(File::open(data)?)
        .with_context(|| format!("open adopted object {}", data.display()))?;
    let metadata = Arc::clone(builder.metadata());
    let schema = Arc::clone(builder.schema());
    drop(builder);
    if schema.field_with_name(TIME_COLUMN).is_err() {
        bail!("adopted object has no `time` column");
    }
    let fingerprint = schema_fingerprint(&schema)?;
    let row_groups = u32::try_from(metadata.num_row_groups()).context("row group count overflow")?;
    if row_groups == 0 || metadata.file_metadata().num_rows() <= 0 {
        bail!("adopted object has no rows");
    }
    let blooms_missing = missing_bloom_columns(&metadata);
    if let Some(group) = metadata.row_groups().iter().find(|g| g.num_rows().max(0) as u64 > budgets.max_row_group_rows) {
        bail!(
            "adopted object has a {}-row row group, above the {}-row bound",
            group.num_rows(),
            budgets.max_row_group_rows
        );
    }

    let mut tokens_out = TokenIndexWriter::create(&staging.join(tokens_file_name(0)), row_groups)?;
    let mut partials = RowPartials::new(&spill, budgets.partial_caps);
    let mut leaves = LeafSorter::new(&spill, budgets.leaf_run_leaves);
    let mut rows = 0_u64;
    for group in 0..metadata.num_row_groups() {
        let reader = ParquetRecordBatchReaderBuilder::try_new(File::open(data)?)?
            .with_row_groups(vec![group])
            .with_batch_size(budgets.batch_rows)
            .build()?;
        let mut tokens = TokenGroupBuilder::new();
        let mut group_rows = 0_u64;
        for batch in reader {
            let batch = batch?;
            let time = batch.column_by_name(TIME_COLUMN).context("batch has no time")?;
            let uid_path = CompiledStringPath::new(&batch, UID_PATH);
            let digests = row_digests(&batch)?;
            let token_paths = TOKEN_FIELDS.iter().filter_map(|p| CompiledStringPath::new(&batch, p)).collect::<Vec<_>>();
            for (row, digest) in digests.iter().enumerate() {
                let time_us = event_time_us_from_array(time.as_ref(), row)
                    .context("adopted object holds a row without an event time")?;
                let uid = uid_path.as_ref().and_then(|p| p.strings(row).into_iter().next()).unwrap_or_default();
                leaves.push(time_us, &uid, *digest)?;
                tokens.add_row();
                for path in &token_paths {
                    for text in path.strings(row) {
                        tokens.add_text(&text);
                    }
                }
            }
            partials.add_batch(&batch)?;
            group_rows += batch.num_rows() as u64;
        }
        if group_rows != metadata.row_group(group).num_rows() as u64 {
            bail!("adopted object row group {group} decoded a different row count");
        }
        rows += group_rows;
        tokens_out.group(&tokens.finish()?)?;
    }
    if rows != metadata.file_metadata().num_rows() as u64 {
        bail!("adopted object decoded a different row count than its footer");
    }

    tokens_out.finish()?;
    let partial_runs = partials.spilled_runs();
    let partial_files = partials.write(staging)?;
    let leaf_runs = leaves.spilled_runs();

    // Merkle roots in (time, uid) order: per hour and over the whole part.
    let mut total = MerkleBuilder::new();
    let mut hours: Vec<HourAccumulator> = Vec::new();
    let mut previous: Option<(i64, Box<str>)> = None;
    let mut duplicate_uids = 0_u64;
    leaves.finish(|leaf| {
        let hour = event_hour_of(leaf.time_us);
        if hours.last().is_none_or(|h| h.event_hour != hour) {
            hours.push(HourAccumulator {
                event_hour: hour,
                rows: 0,
                min_time_us: leaf.time_us,
                max_time_us: leaf.time_us,
                merkle: MerkleBuilder::new(),
            });
        }
        let current = hours.last_mut().expect("hour accumulator exists");
        current.rows += 1;
        current.max_time_us = leaf.time_us;
        current.merkle.push_row(&leaf.uid, &leaf.digest);
        total.push_row(&leaf.uid, &leaf.digest);
        if previous.as_ref().is_some_and(|(t, u)| *t == leaf.time_us && *u == leaf.uid) {
            duplicate_uids += 1;
        }
        previous = Some((leaf.time_us, leaf.uid.clone()));
        Ok(())
    })?;
    if total.leaves() != rows {
        bail!("Merkle leaf count differs from the object's rows");
    }
    let first = hours.first().context("adopted object has no rows")?;
    let last = hours.last().expect("nonempty");
    let (min_time_us, max_time_us) = (first.min_time_us, last.max_time_us);
    let (level, event_hour, event_day) = if first.event_hour == last.event_hour {
        (Level::Hour, first.event_hour, None)
    } else if event_day_of(min_time_us) == event_day_of(max_time_us) {
        let day = event_day_of(min_time_us);
        (Level::Day, day * 24, Some(day))
    } else {
        bail!(
            "adopted object spans event days {} to {}; a part covers at most one day",
            event_day_of(min_time_us),
            event_day_of(max_time_us)
        );
    };
    let hours = hours
        .into_iter()
        .map(|h| HourDigest {
            event_hour: h.event_hour,
            rows: h.rows,
            min_time_us: h.min_time_us,
            max_time_us: h.max_time_us,
            merkle_root: h.merkle.root_hex().expect("hour has rows"),
        })
        .collect::<Vec<_>>();
    std::fs::remove_dir_all(&spill)?;
    Ok(BuiltSidecars {
        dir: staging.to_path_buf(),
        rows,
        min_time_us,
        max_time_us,
        level,
        event_hour,
        event_day,
        hours,
        merkle_root: total.root_hex().expect("part has rows"),
        row_groups,
        schema,
        schema_fingerprint: fingerprint,
        partials: partial_files,
        blooms_missing,
        duplicate_uids,
        leaf_runs,
        partial_runs,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parts::sidecar::encode_token_index;

    #[test]
    fn streamed_token_index_equals_the_contract_encoder() {
        let dir = tempfile::tempdir().unwrap();
        let groups = ["mimikatz sekurlsa", "", "GET /index.html 200 ÜNÏ"]
            .iter()
            .map(|text| {
                let mut builder = TokenGroupBuilder::new();
                builder.add_row();
                builder.add_text(text);
                builder.finish().unwrap()
            })
            .collect::<Vec<_>>();
        let path = dir.path().join("t.nti");
        let mut writer = TokenIndexWriter::create(&path, groups.len() as u32).unwrap();
        for group in &groups {
            writer.group(group).unwrap();
        }
        writer.finish().unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), encode_token_index(&groups).unwrap());
        // A short write is refused.
        let mut short = TokenIndexWriter::create(&dir.path().join("s.nti"), 2).unwrap();
        short.group(&groups[0]).unwrap();
        assert!(short.finish().is_err());
    }
}
