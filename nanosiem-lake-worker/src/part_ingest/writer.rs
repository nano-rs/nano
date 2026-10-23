// SPDX-License-Identifier: AGPL-3.0-or-later

//! The part writer: one pass over time-sorted rows produces the data files
//! (`data-{i:05}.parquet`, rolled at 1 GiB on a row-group boundary), one
//! token index per data file, the Merkle roots and (for L0) the row-derived
//! partials, then an unsigned provenance record (contract sections 2–4). The
//! owner signs it (`lake-parts:sign`); [`publish_parts`] uploads.
//!
//! Memory is bounded by one Parquet row group plus one row group's token set,
//! whatever the part size, because callers stream sorted batches in.

use anyhow::{bail, ensure, Context, Result};
use arrow_array::{Array, ArrayRef, RecordBatch, StringArray, StructArray};
use arrow_schema::SchemaRef;
use parquet::arrow::ArrowWriter;
use parquet::file::properties::WriterProperties;
use parquet::file::reader::{FileReader, SerializedFileReader};
use std::fs::File;
use std::path::{Path, PathBuf};
use futures::StreamExt;

use super::partials::{merge_partials, rollup_field0_events, RowPartials};
use crate::generation::{event_time_us_from_array, CompiledStringPath};
use crate::parts::format::{
    data_file_name, tokens_file_name, ParquetSettings, PartId, PartKeys, MAX_DATA_FILES, MAX_OBJECT_BYTES,
    PROVENANCE_FILE,
};
use crate::parts::levels::Level;
use crate::parts::part_log::{ObjectStore, PartRef, WriteHints, WriterClass};
use crate::parts::provenance::{
    sign_within_budget, row_digests, Admission, DataFileDigest, DedupStats, FileDigest, HourDigest, MerkleBuilder, PartFiles,
    PartInputs, PartSigner, PartialDigest, ProvenanceRecord, SignPayload, SignedProvenance, TenantKeySet, WriterInfo,
    PROVENANCE_FORMAT,
};
use crate::parts::sidecar::{encode_token_index, TokenGroup, TokenGroupBuilder, TOKEN_FIELDS};
use crate::parts::{event_day_of, event_hour_of, sha256_hex, DedupWindow};

/// Rows handed to the Parquet writer per call.
const WRITE_SLICE_ROWS: usize = 4_096;
/// A row group ends early once the writer buffers this much for it.
pub const ROW_GROUP_MEMORY_CAP: usize = 96 * 1024 * 1024;

/// Everything a part's record needs besides what the rows determine.
#[derive(Debug, Clone)]
pub struct PartDraft {
    pub tenant_id: String,
    /// The owner key id that will sign the record.
    pub signer_key_id: String,
    pub level: Level,
    /// The part's hour; for a day part the first hour of the day.
    pub event_hour: i32,
    pub schema: SchemaRef,
    pub schema_fingerprint: String,
    pub inputs: PartInputs,
    pub admission: Option<Admission>,
    pub rows_in: u64,
    pub duplicates_dropped: u64,
    pub window: DedupWindow,
    pub build: String,
}

/// Where the part's partials come from.
#[derive(Debug, Clone)]
pub enum PartialSource {
    /// Accumulate from the rows (L0).
    FromRows,
    /// Only the authenticated finding-outbox drain may select this source.
    /// Raw event ingestion cannot create risk contributions by copying
    /// `unmapped.nano_compact_finding` into an event.
    FromFindings,
    /// k-way merge the partial files in these local input part directories.
    Merge(Vec<PathBuf>),
}

struct HourAcc {
    hour: i32,
    rows: u64,
    min: i64,
    max: i64,
    merkle: MerkleBuilder,
}

impl HourAcc {
    fn finish(self, logical_root: Option<&str>) -> Result<HourDigest> {
        Ok(HourDigest {
            event_hour: self.hour,
            rows: self.rows,
            min_time_us: self.min,
            max_time_us: self.max,
            merkle_root: match logical_root { Some(root) => root.to_owned(), None => self.merkle.root_hex().context("empty hour")? },
        })
    }
}

struct OpenFile {
    index: usize,
    writer: ArrowWriter<File>,
    rows: u64,
    min: i64,
    max: i64,
    token_groups: Vec<TokenGroup>,
    log_sources: Option<Vec<String>>,
}

struct ClosedFile {
    index: usize,
    rows: u64,
    min: i64,
    max: i64,
    row_groups: u32,
    uid_blooms: Option<FileDigest>,
    entity_blooms: Option<FileDigest>,
    entity_locators: Option<FileDigest>,
    class_id: Option<i64>,
    log_sources: Option<Vec<String>>,
}

pub struct PartWriter {
    draft: PartDraft,
    part_id: PartId,
    created_ms: i64,
    dir: PathBuf,
    settings: ParquetSettings,
    properties: WriterProperties,
    current: Option<OpenFile>,
    closed: Vec<ClosedFile>,
    token_group: TokenGroupBuilder,
    /// v2 block rows for every token index of this part (NAN-3032), fixed at
    /// creation so one file never mixes v1 and v2 groups.
    token_block_rows: Option<u32>,
    /// Fixed at creation so a part never mixes rollout formats.
    uid_sidecar_write: bool,
    parquet_range_write: bool,
    entity_sidecar_fields: Vec<String>,
    rows_in_group: usize,
    rows: u64,
    merkle: MerkleBuilder,
    hour: Option<HourAcc>,
    hours: Vec<HourDigest>,
    last: Option<(i64, String)>,
    active_log_source: Option<String>,
    active_class_id: Option<i64>,
    entity_locator_write: bool,
    entity_counts: Option<crate::parts::entity_counts::Builder>,
    family_mode: bool,
    /// NAN-3412: row-group rows of the active family when it is written in
    /// `(device.hostname, time, uid)` order; `None`: `(time, uid)` order.
    host_sorted_group_rows: Option<usize>,
    /// The last row's hostname of a host-sorted family.
    last_host: Option<Option<String>>,
    logical_merkle_root: Option<String>,
    min: i64,
    max: i64,
    partials: Option<RowPartials>,
    partial_source: PartialSource,
}

/// A finished, unsigned part on local disk.
pub struct FinishedPart {
    pub dir: PathBuf,
    pub record: ProvenanceRecord,
}

/// Exact entity locators: opt-in, never on L0, and never on wide-group
/// layouts (NAN-3156). A 262,144-row group's offsets are megabytes per
/// field; measured on real parts they cost more select time than they
/// saved, while the bloom sidecar and chDB's own row-group blooms already
/// skip groups without a sparse value.
pub(super) fn entity_locator_write_enabled(level: Level, settings: &ParquetSettings, value: Option<&str>) -> bool {
    level != Level::L0 && value == Some("1") && settings.row_group_rows <= crate::parts::format::ROW_GROUP_ROWS
}

/// Physical scalar fields with existing Parquet blooms; unknown fields are ignored.
pub(super) fn entity_sidecar_fields(value: Option<&str>) -> Vec<String> {
    let mut fields = value.map(|value| value.split(',').map(str::trim).collect::<Vec<_>>())
        .unwrap_or_else(|| crate::parts::format::BLOOM_PATHS.to_vec());
    fields.retain(|field| *field != crate::parts::format::UID_PATH && crate::parts::format::BLOOM_PATHS.contains(field));
    fields.sort_unstable();
    fields.dedup();
    fields.into_iter().map(str::to_owned).collect()
}

/// Explicit opt-in only; absent, false, and unrecognized values keep legacy writes.
pub(super) fn uid_sidecar_write_enabled(value: Option<&str>) -> bool {
    value.is_some_and(|value| value == "1" || value.eq_ignore_ascii_case("true"))
}

impl PartWriter {
    /// `work_dir/{part_id}` becomes the part's local directory.
    pub fn create(work_dir: &Path, draft: PartDraft, partial_source: PartialSource, now_ms: i64, expected_rows: u64) -> Result<Self> {
        let settings = ParquetSettings::for_level(draft.level).compaction_layout(
            draft.level, std::env::var("NANO_LAKE_COMPACTION_LAYOUT").ok().as_deref(),
        )?.for_compaction_rows(draft.level, expected_rows);
        Self::create_with(work_dir, draft, partial_source, now_ms, expected_rows, settings)
    }

    /// [`Self::create`] with explicit settings (tests shrink the file cap).
    pub fn create_with(
        work_dir: &Path,
        draft: PartDraft,
        partial_source: PartialSource,
        now_ms: i64,
        expected_rows: u64,
        settings: ParquetSettings,
    ) -> Result<Self> {
        if draft.level == Level::Day {
            ensure!(draft.event_hour.rem_euclid(24) == 0, "day part hour must start its day");
        }
        ensure!(settings.max_file_bytes <= MAX_OBJECT_BYTES / 2, "data file split must leave room under the object cap");
        let part_id = PartId::new(now_ms)?;
        let dir = work_dir.join(part_id.as_str());
        std::fs::create_dir_all(&dir)?;
        let properties = settings.writer_properties(
            expected_rows,
            &part_id,
            draft.level,
            &draft.tenant_id,
            &draft.schema_fingerprint,
        )?;
        let partials = match partial_source {
            PartialSource::FromRows => Some(RowPartials::new()),
            PartialSource::FromFindings => Some(RowPartials::new_findings()),
            PartialSource::Merge(_) => None,
        };
        let token_block_rows = crate::parts::block_index::enabled().then_some(crate::parts::block_index::BLOCK_ROWS);
        let entity_locator_write = entity_locator_write_enabled(
            draft.level, &settings, std::env::var("NANO_LAKE_ENTITY_LOCATOR_WRITE").ok().as_deref(),
        );
        let entity_counts = {
            let enabled = crate::parts::entity_counts::enabled(std::env::var("NANO_LAKE_ENTITY_COUNT_WRITE").ok().as_deref());
            #[cfg(test)]
            let enabled = tests::ENTITY_COUNT_WRITE_OVERRIDE.with(|value| value.get().unwrap_or(enabled));
            enabled.then(|| crate::parts::entity_counts::Builder::in_directory(&dir))
        };
        Ok(Self {
            draft,
            part_id,
            created_ms: now_ms,
            dir,
            settings,
            properties,
            current: None,
            closed: Vec::new(),
            token_group: TokenGroupBuilder::for_writer(token_block_rows),
            token_block_rows,
            parquet_range_write: uid_sidecar_write_enabled(std::env::var("NANO_LAKE_PARQUET_RANGE_WRITE").ok().as_deref()),
            uid_sidecar_write: uid_sidecar_write_enabled(std::env::var("NANO_LAKE_UID_SIDECAR_WRITE").ok().as_deref()),
            entity_sidecar_fields: entity_sidecar_fields(std::env::var("NANO_LAKE_ENTITY_SIDECAR_FIELDS").ok().as_deref()),
            rows_in_group: 0,
            rows: 0,
            merkle: MerkleBuilder::new(),
            hour: None,
            hours: Vec::new(),
            last: None,
            active_log_source: None,
            active_class_id: None,
            entity_locator_write,
            entity_counts,
            family_mode: false,
            host_sorted_group_rows: None,
            last_host: None,
            logical_merkle_root: None,
            min: i64::MAX,
            max: i64::MIN,
            partials,
            partial_source,
        })
    }

    pub fn part_id(&self) -> &PartId {
        &self.part_id
    }

    fn new_token_group(&self) -> TokenGroupBuilder {
        TokenGroupBuilder::for_writer(self.token_block_rows)
    }

    pub fn rows(&self) -> u64 {
        self.rows
    }

    /// The part's local directory.
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    fn open_file(&mut self) -> Result<&mut OpenFile> {
        if self.current.is_none() {
            let index = self.closed.len();
            ensure!(index < MAX_DATA_FILES, "part exceeds {MAX_DATA_FILES} data files");
            let properties = match self.host_sorted_group_rows {
                // Blooms are sized per row group: size them for the small groups.
                Some(group_rows) => ParquetSettings { row_group_rows: group_rows, ..self.settings }.writer_properties(
                    self.draft.rows_in, &self.part_id, self.draft.level, &self.draft.tenant_id, &self.draft.schema_fingerprint,
                )?,
                None => self.properties.clone(),
            };
            let mut writer = ArrowWriter::try_new(
                File::create(self.dir.join(data_file_name(index)))?,
                self.draft.schema.clone(),
                Some(properties),
            )?;
            if self.host_sorted_group_rows.is_some() {
                writer.append_key_value_metadata(parquet::file::metadata::KeyValue::new(
                    super::host_sort::ROW_ORDER_KEY.to_string(), super::host_sort::HOST_ROW_ORDER.to_string(),
                ));
            }
            self.current = Some(OpenFile { index, writer, rows: 0, min: i64::MAX, max: i64::MIN, token_groups: Vec::new(), log_sources: self.active_log_source.as_ref().map(|s| vec![s.clone()]) });
        }
        Ok(self.current.as_mut().expect("opened"))
    }

    /// Close the open data file, write its token index, record it.
    fn close_file(&mut self) -> Result<()> {
        let Some(mut file) = self.current.take() else { return Ok(()) };
        if self.rows_in_group > 0 {
            let fresh = self.new_token_group();
            let group = std::mem::replace(&mut self.token_group, fresh);
            file.token_groups.push(group.finish()?);
            self.rows_in_group = 0;
        }
        file.writer.close()?;
        let reader = SerializedFileReader::new(File::open(self.dir.join(data_file_name(file.index)))?)?;
        let row_groups = reader.metadata().row_groups();
        ensure!(row_groups.len() == file.token_groups.len(), "token groups do not match Parquet row groups");
        for (group, tokens) in row_groups.iter().zip(&file.token_groups) {
            ensure!(group.num_rows() as u64 == tokens.rows, "token group rows do not match its row group");
        }
        std::fs::write(self.dir.join(tokens_file_name(file.index)), encode_token_index(&file.token_groups)?)?;
        let uid_index = if self.uid_sidecar_write {
            reader.metadata().file_metadata().schema_descr().columns()
                .iter().position(|column| column.path().string() == crate::parts::format::UID_PATH)
        } else {
            None
        };
        let uid_blooms: Option<Vec<Option<String>>> = uid_index.map(|index| (0..row_groups.len()).map(|group| {
            let file = File::open(self.dir.join(data_file_name(file.index))).ok()?;
            let bloom = parquet::bloom_filter::Sbbf::read_from_column_chunk(row_groups[group].column(index), &file).ok()??;
            let mut bytes = Vec::new();
            bloom.write_bitset(&mut bytes).ok()?;
            Some(hex::encode(bytes))
        }).collect());
        let uid_blooms = match uid_blooms {
            Some(blooms) => {
                let name = format!("uids-{:05}.json", file.index);
                std::fs::write(self.dir.join(&name), serde_json::to_vec(&blooms)?)?;
                let (bytes, sha256) = file_digest(&self.dir.join(&name))?;
                Some(FileDigest { name, bytes, sha256 })
            }
            None => None,
        };
        let entity_blooms = if self.uid_sidecar_write && !self.entity_sidecar_fields.is_empty() {
            let mut blooms = std::collections::BTreeMap::new();
            let data_source = File::open(self.dir.join(data_file_name(file.index)))?;
            for path in &self.entity_sidecar_fields {
                let Some(index) = reader.metadata().file_metadata().schema_descr().columns()
                    .iter().position(|column| column.path().string() == *path && column.max_rep_level() == 0) else { continue };
                let groups: Vec<Option<String>> = row_groups.iter().map(|group| {
                    let bloom = parquet::bloom_filter::Sbbf::read_from_column_chunk(group.column(index), &data_source).ok()??;
                    let mut bytes = Vec::new();
                    bloom.write_bitset(&mut bytes).ok()?;
                    Some(hex::encode(bytes))
                }).collect();
                blooms.insert(path.clone(), groups);
            }
            // NAN-3694: folded (lowercase) blooms beside the raw copies.
            blooms.extend(self.folded_entity_blooms(file.index, row_groups.len())?);
            let name = format!("entities-{:05}.json", file.index);
            std::fs::write(self.dir.join(&name), serde_json::to_vec(&blooms)?)?;
            let (bytes, sha256) = file_digest(&self.dir.join(&name))?;
            Some(FileDigest { name, bytes, sha256 })
        } else { None };
        let entity_locators = if self.entity_locator_write { self.write_entity_locators(file.index)? } else { None };
        self.closed.push(ClosedFile {
            index: file.index,
            rows: file.rows,
            min: file.min,
            max: file.max,
            row_groups: u32::try_from(file.token_groups.len())?,
            uid_blooms,
            entity_blooms,
            entity_locators,
            class_id: self.active_class_id,
            log_sources: file.log_sources,
        });
        Ok(())
    }

    /// Start another source family in an hour part. Its files have their own
    /// `(time, uid)` order. The merge supplies its logical global-order
    /// Merkle root before publication.
    pub fn start_log_source(&mut self, source: Option<&str>) -> Result<()> {
        ensure!(matches!(self.draft.level, Level::Minute | Level::Hour), "family files are only written by minute/hour merges");
        self.close_file()?;
        self.active_log_source = source.map(str::to_string);
        self.active_class_id = None;
        self.family_mode = true;
        self.host_sorted_group_rows = None;
        self.last = None;
        self.last_host = None;
        Ok(())
    }

    /// NAN-3412: start a source/class family of an hour part whose rows
    /// arrive in `(device.hostname, time, uid)` order, written in
    /// `group_rows`-row groups to one data file tagged
    /// [`super::host_sort::ROW_ORDER_KEY`]. The file never rolls (the signed
    /// record requires a family's files in time order); a family past
    /// [`crate::parts::format::DATA_FILE_SPLIT_BYTES`] fails the write.
    pub fn start_host_sorted_family(&mut self, source: &str, class_id: Option<i64>, group_rows: usize) -> Result<()> {
        ensure!(self.draft.level == Level::Hour, "host-sorted families are only written by hour merges");
        ensure!((1..=crate::parts::format::ROW_GROUP_ROWS).contains(&group_rows), "host-sorted group rows out of range");
        self.start_source_class(Some(source), class_id)?;
        self.host_sorted_group_rows = Some(group_rows);
        Ok(())
    }

    /// Each source/class family retains its independent time/UID order.
    pub fn start_source_class(&mut self, source: Option<&str>, class_id: Option<i64>) -> Result<()> {
        self.start_log_source(source)?;
        self.active_class_id = class_id;
        Ok(())
    }

    /// NAN-3694: per row group, a bloom over the ASCII-lowercased values of
    /// each foldable sidecar field (`prune::foldable`) stored as a scalar
    /// string column, keyed `lower:<path>`. Sized by the group's distinct
    /// folded values at the part bloom fpp. Readers probe it with the
    /// lowercased literal whatever its length. A group whose values are all
    /// already lowercase (or that holds none) gets the `=` marker instead: its
    /// raw bloom is then exact for the lowercased literal.
    fn folded_entity_blooms(&self, index: usize, groups: usize) -> Result<std::collections::BTreeMap<String, Vec<Option<String>>>> {
        use crate::part_query::prune::{folded_bloom_key, foldable};
        use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;
        let path = self.dir.join(data_file_name(index));
        let builder = ParquetRecordBatchReaderBuilder::try_new(File::open(&path)?)?;
        let eligible = self.entity_sidecar_fields.iter().filter(|field| foldable(field) && builder.parquet_schema().columns().iter().any(|column|
            column.path().string() == **field && column.max_rep_level() == 0
                && column.physical_type() == parquet::basic::Type::BYTE_ARRAY
                && column.logical_type_ref() == Some(&parquet::basic::LogicalType::String))).cloned().collect::<Vec<_>>();
        let mut out = std::collections::BTreeMap::new();
        if eligible.is_empty() { return Ok(out); }
        let columns = builder.parquet_schema().columns().iter().enumerate().filter_map(|(index, column)|
            eligible.iter().any(|field| column.path().string() == field.as_str()).then_some(index)).collect::<Vec<_>>();
        let mut folded: std::collections::BTreeMap<&String, Vec<Option<String>>> = eligible.iter().map(|field| (field, Vec::with_capacity(groups))).collect();
        for group in 0..groups {
            let projection = parquet::arrow::ProjectionMask::leaves(builder.parquet_schema(), columns.clone());
            let reader = ParquetRecordBatchReaderBuilder::try_new(File::open(&path)?)?
                .with_projection(projection).with_row_groups(vec![group]).with_batch_size(4096).build()?;
            let mut values: std::collections::BTreeMap<&String, std::collections::HashSet<Vec<u8>>> =
                eligible.iter().map(|field| (field, std::collections::HashSet::new())).collect();
            // Fields with a value that lowercasing changes in this group.
            let mut mixed: std::collections::BTreeSet<&String> = std::collections::BTreeSet::new();
            for batch in reader {
                let batch = batch?;
                super::merge_quota::charge(batch.num_rows() as u64, super::merge_quota::batch_bytes(&batch));
                for field in &eligible {
                    let Some(compiled) = CompiledStringPath::new(&batch, field) else { continue };
                    let set = values.get_mut(field).expect("eligible field");
                    for row in 0..batch.num_rows() {
                        for value in compiled.strings(row) {
                            let lowered = value.as_bytes().to_ascii_lowercase();
                            if lowered != value.as_bytes() {
                                mixed.insert(field);
                            }
                            set.insert(lowered);
                        }
                    }
                }
            }
            for field in &eligible {
                // Already lowercase throughout: the raw bloom is exact for a
                // lowercased literal, so only the marker is written.
                if !mixed.contains(field) {
                    folded.get_mut(field).expect("eligible field").push(Some(crate::part_query::prune::FOLDED_SAME_AS_RAW.to_string()));
                    continue;
                }
                let set = &values[field];
                let mut bloom = parquet::bloom_filter::Sbbf::new_with_ndv_fpp(set.len().max(1) as u64, crate::parts::format::BLOOM_FPP)?;
                set.iter().for_each(|value| bloom.insert(value.as_slice()));
                let mut bytes = Vec::new();
                bloom.write_bitset(&mut bytes)?;
                folded.get_mut(field).expect("eligible field").push(Some(hex::encode(bytes)));
            }
        }
        for (field, groups) in folded {
            out.insert(folded_bloom_key(field), groups);
        }
        Ok(out)
    }

    fn write_entity_locators(&self, index: usize) -> Result<Option<FileDigest>> {
        use crate::parts::entity_locators::{EntityLocators, Group, normalized, MAX_BYTES, MAX_GROUP_BYTES};
        use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;
        let path = self.dir.join(data_file_name(index));
        let metadata = ParquetRecordBatchReaderBuilder::try_new(File::open(&path)?)?;
        let mut output = EntityLocators { version: 1, groups: Vec::new() };
        let mut bytes = 0;
        for group in 0..metadata.metadata().num_row_groups() {
            let mut fields = std::collections::BTreeMap::new();
            let mut rows = 0_u32;
            let eligible = self.entity_sidecar_fields.iter().filter(|path| metadata.parquet_schema().columns().iter().any(|column|
                column.path().string() == **path && column.max_rep_level() == 0
                    && column.physical_type() == parquet::basic::Type::BYTE_ARRAY
                    && column.logical_type() == Some(parquet::basic::LogicalType::String))).collect::<Vec<_>>();
            if eligible.is_empty() { return Ok(None); }
            let columns = metadata.parquet_schema().columns().iter().enumerate().filter_map(|(index, column)|
                eligible.iter().any(|path| column.path().string() == path.as_str()).then_some(index)).collect::<Vec<_>>();
            let projection = parquet::arrow::ProjectionMask::leaves(metadata.parquet_schema(), columns);
            let mut reader = ParquetRecordBatchReaderBuilder::try_new(File::open(&path)?)?.with_projection(projection).with_row_groups(vec![group]).with_batch_size(4096).build()?;
            let mut unknown = std::collections::BTreeSet::new();
            for batch in &mut reader {
                let batch = batch?;
                super::merge_quota::charge(batch.num_rows() as u64, super::merge_quota::batch_bytes(&batch));
                for path in &eligible {
                    if unknown.contains(*path) { continue; }
                    let Some(compiled) = CompiledStringPath::new(&batch, path) else { unknown.insert((*path).clone()); continue };
                    let values = fields.entry((*path).clone()).or_insert_with(std::collections::BTreeMap::<String, Vec<u32>>::new);
                    for row in 0..batch.num_rows() {
                        for value in compiled.strings(row) {
                            if !value.is_ascii() { unknown.insert((*path).clone()); break; }
                            values.entry(normalized(path, &value)).or_default().push(rows + row as u32);
                        }
                    }
                }
                rows += u32::try_from(batch.num_rows())?;
                // Bound temporary allocations before accumulating the next batch.
                if fields.values().map(|values| values.iter().map(|(value, offsets)| value.len() + offsets.len() * 4 + 64).sum::<usize>()).sum::<usize>() > MAX_GROUP_BYTES {
                    unknown.extend(eligible.iter().map(|path| (*path).clone()));
                    fields.clear();
                }
            }
            for path in unknown { fields.remove(&path); }
            let group = Group { rows, fields };
            bytes += serde_json::to_vec(&group)?.len();
            if bytes > MAX_BYTES / 2 { return Ok(None); }
            output.groups.push(group);
        }
        // A locator that knows no field in any group answers nothing, yet
        // its presence used to shadow the bloom sidecar: write none.
        if output.groups.iter().all(|group| group.fields.is_empty()) { return Ok(None); }
        let encoded = serde_json::to_vec(&output)?;
        if encoded.len() > MAX_BYTES { return Ok(None); }
        let name = format!("locators-{index:05}.json");
        std::fs::write(self.dir.join(&name), encoded)?;
        let (bytes, sha256) = file_digest(&self.dir.join(&name))?;
        Ok(Some(FileDigest { name, bytes, sha256 }))
    }

    /// A local, never-published intermediate (a merge pass over more than
    /// `MAX_OPEN_INPUTS` overlapping inputs): skip the per-row digests, the
    /// costliest per-row work. Its Merkle roots are placeholders; the final
    /// pass digests every output row itself (NAN-3056).
    pub fn without_row_digests(&mut self) {
        self.family_mode = true;
        self.logical_merkle_root = Some("0".repeat(64));
    }

    /// Set the logical global-order root computed before family routing.
    pub fn set_logical_merkle_root(&mut self, root: String) -> Result<()> {
        ensure!(self.family_mode, "logical root requires family mode");
        self.logical_merkle_root = Some(root);
        Ok(())
    }

    /// Append a batch whose rows are sorted by `(time, uid)` and strictly
    /// after the preceding batch in this file family.
    pub fn write(&mut self, batch: &RecordBatch) -> Result<()> {
        if batch.num_rows() == 0 {
            return Ok(());
        }
        ensure!(batch.schema().fields() == self.draft.schema.fields(), "part batch schema differs from the part schema");
        let time = batch.column_by_name("time").context("part batch has no time")?.clone();
        let uids = uid_strings(batch)?;
        let hosts = self.host_sorted_group_rows.map(|_| super::host_sort::host_strings(batch)).transpose()?;
        let host_at = |row: usize| hosts.as_ref().and_then(|hosts| (!hosts.is_null(row)).then(|| hosts.value(row)));
        let digests = match (self.family_mode, self.draft.level) {
            (true, _) => None,
            // Merge outputs digest on the bounded merge pool; L0 flushes
            // (the tick) stay serial on their own thread.
            (false, Level::L0) => Some(row_digests(batch)?),
            (false, _) => Some(crate::parts::provenance::row_digests_for_merge(batch)?),
        };
        // `(path, is a keyword body column)`: body values also feed the v3
        // token counts (`message`, `raw_data`; see `parts::token_counts`).
        let token_paths = TOKEN_FIELDS
            .iter()
            .filter_map(|path| {
                CompiledStringPath::new(batch, path).map(|compiled| (compiled, crate::parts::token_counts::BODY_COLUMNS.contains(path)))
            })
            .collect::<Vec<_>>();
        let times = (0..batch.num_rows())
            .map(|row| event_time_us_from_array(time.as_ref(), row).context("part row has no time"))
            .collect::<Result<Vec<_>>>()?;
        for row in 0..batch.num_rows() {
            let time_us = times[row];
            ensure!(!uids.is_null(row), "part row has no metadata.uid");
            let uid = uids.value(row);
            if hosts.is_some() {
                let host = host_at(row);
                let ordered = if row == 0 {
                    self.last.as_ref().zip(self.last_host.as_ref())
                        .is_none_or(|((t, u), h)| (host, time_us, uid) > (h.as_deref(), *t, u.as_str()))
                } else {
                    (host, time_us, uid) > (host_at(row - 1), times[row - 1], uids.value(row - 1))
                };
                ensure!(ordered, "host-sorted part rows are not strictly sorted by (device.hostname, time, uid)");
            } else {
                let ordered = if row == 0 {
                    self.last.as_ref().is_none_or(|(t, u)| (time_us, uid) > (*t, u.as_str()))
                } else {
                    (time_us, uid) > (times[row - 1], uids.value(row - 1))
                };
                ensure!(ordered, "part rows are not strictly sorted by (time, uid)");
            }
            let hour = event_hour_of(time_us);
            match self.draft.level {
                Level::Day => ensure!(event_day_of(time_us) * 24 == self.draft.event_hour, "row outside the day part"),
                _ => ensure!(hour == self.draft.event_hour, "row outside the hour part"),
            }
            if self.hour.as_ref().map(|h| h.hour) != Some(hour) {
                if let Some(done) = self.hour.take() {
                    self.hours.push(done.finish(self.logical_merkle_root.as_deref())?);
                }
                self.hour = Some(HourAcc { hour, rows: 0, min: time_us, max: time_us, merkle: MerkleBuilder::new() });
            }
            let acc = self.hour.as_mut().expect("hour set");
            acc.rows += 1;
            acc.min = acc.min.min(time_us);
            acc.max = acc.max.max(time_us);
            if let Some(digests) = &digests {
                acc.merkle.push_row(uid, &digests[row]);
                self.merkle.push_row(uid, &digests[row]);
            }
            self.min = self.min.min(time_us);
            self.max = self.max.max(time_us);
        }
        self.last = Some((times[batch.num_rows() - 1], uids.value(batch.num_rows() - 1).to_string()));
        if hosts.is_some() {
            self.last_host = Some(host_at(batch.num_rows() - 1).map(str::to_owned));
        }
        // Write in slices of at most WRITE_SLICE_ROWS that never cross a
        // row-group boundary. A group ends at `row_group_rows` rows, or early
        // once the writer's buffered group reaches ROW_GROUP_MEMORY_CAP (wide
        // OCSF rows), so a file can roll exactly between groups and the
        // writer's memory stays bounded.
        let group_rows = self.host_sorted_group_rows.unwrap_or(self.settings.row_group_rows);
        let mut offset = 0;
        while offset < batch.num_rows() {
            let take = (group_rows - self.rows_in_group).min(WRITE_SLICE_ROWS).min(batch.num_rows() - offset);
            let slice = batch.slice(offset, take);
            for row in offset..offset + take {
                self.token_group.add_row_at(times[row]);
                for (path, body) in &token_paths {
                    for text in path.strings(row) {
                        self.token_group.add_text(&text);
                        if *body {
                            self.token_group.add_body(&text);
                        }
                    }
                }
            }
            // Exact bounds: a host-sorted slice is not in time order (for a
            // time-sorted one these are its first and last rows).
            let (first, last) = times[offset..offset + take].iter()
                .fold((i64::MAX, i64::MIN), |(min, max), time| (min.min(*time), max.max(*time)));
            let file = self.open_file()?;
            file.writer.write(&slice)?;
            file.rows += take as u64;
            file.min = file.min.min(first);
            file.max = file.max.max(last);
            self.rows_in_group += take;
            self.rows += take as u64;
            offset += take;
            let file = self.current.as_mut().expect("open");
            let full = self.rows_in_group == group_rows || file.writer.memory_size() >= ROW_GROUP_MEMORY_CAP;
            if full {
                file.writer.flush()?;
                let fresh = TokenGroupBuilder::for_writer(self.token_block_rows);
                let group = std::mem::replace(&mut self.token_group, fresh);
                file.token_groups.push(group.finish()?);
                self.rows_in_group = 0;
                if self.host_sorted_group_rows.is_some() {
                    ensure!((file.writer.bytes_written() as u64) < crate::parts::format::DATA_FILE_SPLIT_BYTES,
                        "host-sorted family exceeds one data file");
                } else if file.writer.bytes_written() as u64 >= self.settings.max_file_bytes {
                    self.close_file()?;
                }
            }
        }
        if let Some(counts) = &mut self.entity_counts {
            if let Err(error) = counts.add_batch(batch) {
                tracing::warn!(reason = %error, "dropping optional entity count coverage during accumulation");
                self.entity_counts = None;
            }
        }
        if let Some(partials) = &mut self.partials {
            partials.add_batch(batch)?;
        }
        Ok(())
    }

    /// Close every file and build the unsigned record.
    pub fn finish(mut self) -> Result<FinishedPart> {
        ensure!(self.rows > 0, "a part must hold rows");
        if let Some(done) = self.hour.take() {
            self.hours.push(done.finish(self.logical_merkle_root.as_deref())?);
        }
        self.close_file()?;
        let mut partial_files = match (&self.partial_source, self.partials.take()) {
            (PartialSource::FromRows | PartialSource::FromFindings, Some(partials)) => partials.write(&self.dir)?,
            (PartialSource::Merge(inputs), _) => {
                let refs = inputs.iter().map(PathBuf::as_path).collect::<Vec<_>>();
                merge_partials(&refs, &self.dir)?
            }
            _ => bail!("part partial source is inconsistent"),
        };
        // Rebuild from final emitted rows, including compaction dedupe and
        // family ordering. Never inherit input coverage promises.
        if let Some(builder) = self.entity_counts.take() {
            let entity_path = self.dir.join(crate::parts::format::PARTIAL_ENTITY_RANGES_FILE);
            // Replacement commits by rename only after the complete stream
            // succeeds. On failure the ordinary partial remains untouched.
            let result = builder.into_sorted_rows().and_then(|count_rows|
                super::partials::replace_entity_counts(&entity_path, count_rows));
            match result {
                Ok(entity_rows) => {
                    for (kind, _, rows) in &mut partial_files {
                        if *kind == crate::parts::provenance::PartialKind::EntityRanges { *rows = entity_rows; }
                    }
                }
                Err(error) => {
                    tracing::warn!(reason = %error, "dropping optional entity count coverage during finalization");
                    let _ = std::fs::remove_file(entity_path.with_extension("counts.tmp"));
                }
            }
        }
        let rollup = self.dir.join(crate::parts::format::PARTIAL_ROLLUP_FILE);
        ensure!(rollup_field0_events(&rollup)? == self.rows, "rollup partial does not count every row");
        let digest = |name: &str| -> Result<(u64, String)> {
            let (bytes, sha) = file_digest(&self.dir.join(name))?;
            ensure!(bytes > 0 && bytes <= MAX_OBJECT_BYTES, "part file {name} is outside the object size cap");
            Ok((bytes, sha))
        };
        let mut data = Vec::with_capacity(self.closed.len());
        for file in &self.closed {
            let (bytes, sha256) = digest(&data_file_name(file.index))?;
            let (token_bytes, token_sha) = digest(&tokens_file_name(file.index))?;
            data.push(DataFileDigest {
                name: data_file_name(file.index),
                bytes,
                sha256,
                rows: file.rows,
                row_groups: file.row_groups,
                min_time_us: file.min,
                max_time_us: file.max,
                log_sources: file.log_sources.clone(),
                uid_blooms: file.uid_blooms.clone(),
                entity_blooms: file.entity_blooms.clone(),
                parquet_ranges: if self.parquet_range_write {
                    let ranges = crate::parts::parquet_ranges::build(&self.dir.join(data_file_name(file.index)))?;
                    let body = serde_json::to_vec(&ranges)?;
                    ensure!(body.len() as u64 <= crate::parts::parquet_ranges::MAX_MANIFEST_BYTES, "range manifest exceeds size cap");
                    let name = format!("ranges-{:05}.json", file.index);
                    std::fs::write(self.dir.join(&name), &body)?;
                    Some(FileDigest { name, bytes: body.len() as u64, sha256: sha256_hex(&body) })
                } else { None },
                entity_locators: file.entity_locators.clone(),
                class_id: file.class_id,
                tokens: FileDigest { name: tokens_file_name(file.index), bytes: token_bytes, sha256: token_sha },
            });
        }
        let mut partials = Vec::new();
        for (kind, name, rows) in partial_files {
            let (bytes, sha256) = digest(name)?;
            partials.push(PartialDigest { kind, name: name.to_string(), bytes, sha256, rows });
        }
        let draft = self.draft;
        let lowercased_at_rest = draft.admission.as_ref().filter(|admission| {
            admission.admission_contract == crate::parts::provenance::ADMISSION_CONTRACT
        }).map_or_else(Vec::new, |_| {
            crate::parts::provenance::LOWERCASED_AT_REST.iter().map(|path| (*path).to_string()).collect()
        });
        let record = ProvenanceRecord {
            format: PROVENANCE_FORMAT.to_string(),
            signer_key_id: draft.signer_key_id,
            tenant_id: draft.tenant_id,
            part_id: self.part_id,
            level: draft.level,
            created_at_ms: self.created_ms,
            event_hour: draft.event_hour,
            event_day: (draft.level == Level::Day).then(|| draft.event_hour / 24),
            rows: self.rows,
            min_time_us: self.min,
            max_time_us: self.max,
            schema_fingerprint: draft.schema_fingerprint,
            merkle_root: match &self.logical_merkle_root { Some(root) => root.clone(), None => self.merkle.root_hex().context("empty part")? },
            hours: self.hours,
            files: PartFiles { data, partials },
            inputs: draft.inputs,
            admission: draft.admission,
            lowercased_at_rest,
            dedup: DedupStats { rows_in: draft.rows_in, duplicates_dropped: draft.duplicates_dropped, window: draft.window },
            writer: WriterInfo { role: "ingest".into(), build: draft.build },
        };
        record.validate()?;
        Ok(FinishedPart { dir: self.dir, record })
    }
}

/// Streaming SHA-256 and size of a local file.
pub fn file_digest(path: &Path) -> Result<(u64, String)> {
    use sha2::{Digest, Sha256};
    use std::io::Read;
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0_u8; 1 << 20];
    let mut total = 0_u64;
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        total += read as u64;
        hasher.update(&buffer[..read]);
    }
    Ok((total, hex::encode(hasher.finalize())))
}

/// The local data files of a part directory, in index order.
pub fn local_data_files(dir: &Path) -> Result<Vec<PathBuf>> {
    let mut files = Vec::new();
    for index in 0..MAX_DATA_FILES {
        let path = dir.join(data_file_name(index));
        if !path.exists() {
            break;
        }
        files.push(path);
    }
    ensure!(!files.is_empty(), "part directory {} has no data files", dir.display());
    Ok(files)
}

/// `metadata.uid` as a Utf8 array.
pub fn uid_strings(batch: &RecordBatch) -> Result<StringArray> {
    let metadata = batch
        .column_by_name("metadata")
        .context("batch has no metadata")?
        .as_any()
        .downcast_ref::<StructArray>()
        .context("metadata is not a struct")?;
    let uid: &ArrayRef = metadata.column_by_name("uid").context("metadata has no uid")?;
    let cast = arrow_cast::cast(uid.as_ref(), &arrow_schema::DataType::Utf8)?;
    Ok(cast.as_any().downcast_ref::<StringArray>().context("uid cast")?.clone())
}

/// Nullable `metadata.log_source` as a Utf8 array.
pub fn log_source_strings(batch: &RecordBatch) -> Result<StringArray> {
    let metadata = batch.column_by_name("metadata").context("batch has no metadata")?
        .as_any().downcast_ref::<StructArray>().context("metadata is not a struct")?;
    Ok(metadata.column_by_name("log_source").context("metadata has no log_source")?
        .as_any().downcast_ref::<StringArray>().context("metadata.log_source is not Utf8")?.clone())
}

/// Sort a batch by `(time, metadata.uid)`.
pub fn sort_by_time_uid(batch: &RecordBatch) -> Result<RecordBatch> {
    use arrow_ord::sort::{lexsort_to_indices, SortColumn};
    if batch.num_rows() < 2 {
        return Ok(batch.clone());
    }
    let time = batch.column_by_name("time").context("batch has no time")?.clone();
    let uid: ArrayRef = std::sync::Arc::new(uid_strings(batch)?);
    let indices = lexsort_to_indices(
        &[SortColumn { values: time, options: None }, SortColumn { values: uid, options: None }],
        None,
    )?;
    let columns = batch
        .columns()
        .iter()
        .map(|c| arrow_select::take::take(c.as_ref(), &indices, None))
        .collect::<std::result::Result<Vec<_>, _>>()?;
    Ok(RecordBatch::try_new(batch.schema(), columns)?)
}

pub(crate) fn part_hints(record: &ProvenanceRecord) -> WriteHints {
    WriteHints {
        class: WriterClass::LakePart,
        event_hour: record.event_hour,
        min_time_ms: record.min_time_us.div_euclid(1_000),
        max_time_ms: record.max_time_us.div_euclid(1_000),
    }
}

/// Identify only the unpublished event hour owning a native unresolved PUT.
/// Derive keys from trusted finished records, never from the error's tenant
/// or path. Other hours can retain their already registered immutable files.
pub(super) fn unresolved_publication_hour(finished: &[FinishedPart], error: &anyhow::Error) -> Result<Option<i32>> {
    let Some(unresolved) = error.downcast_ref::<super::native_writer::NativePutUnresolved>() else {
        return Ok(None);
    };
    for part in finished {
        let record = &part.record;
        let keys = PartKeys::new(&record.tenant_id, record.level, record.event_hour, &record.part_id)?;
        let matches_file = record.files.all().iter().any(|(name, _, _)| keys.file(name) == unresolved.key);
        let matches_pending = SignPayload::for_record(record)?.record_ref
            .is_some_and(|reference| reference.key == unresolved.key);
        if matches_file || keys.provenance() == unresolved.key || matches_pending {
            return Ok(Some(record.event_hour));
        }
    }
    anyhow::bail!("unresolved native publication does not belong to finished output")
}

// Retry only classified transient publication failures. Native writes journal
// their identity and replay unresolved intents before another PUT, so retrying
// this same immutable key never starts an unrelated publication.
fn publication_retryable(error: &anyhow::Error) -> bool {
    #[cfg(feature = "enterprise")]
    if let Some(failure) = error.downcast_ref::<crate::enterprise_shared_writer_retry::WriterPlaneFailure>() {
        return failure.class == crate::enterprise_shared_writer_retry::WriterFailureClass::Retryable;
    }
    if let Some(refused) = error.downcast_ref::<super::native_writer::OwnerRefused>() {
        return refused.status == 429 || (500..600).contains(&refused.status);
    }
    error.downcast_ref::<super::r2_put::TransientPutError>().is_some()
        || error.downcast_ref::<reqwest::Error>().is_some_and(|e| e.is_timeout() || e.is_connect() || e.is_body() || e.is_request())
}

async fn retry_publication<T, F, Fut>(mut write: F) -> Result<T>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<T>>,
{
    for attempt in 0..4_u32 {
        match write().await {
            Err(error) if attempt < 3 && publication_retryable(&error) => {
                // Bounded to three backoffs (1.75 seconds total). Never print
                // provider bodies, credentials, or signed storage locations.
                tracing::warn!(attempt = attempt + 1, "retrying transient immutable part publication");
                tokio::time::sleep(std::time::Duration::from_millis(250 << attempt)).await;
            }
            result => return result,
        }
    }
    unreachable!()
}

async fn put_publication_bytes(store: &dyn ObjectStore, key: &str, bytes: &[u8], hints: &WriteHints, compacting: bool) -> Result<()> {
    retry_publication(|| async {
        if !super::merge_quota::remote_transfer(compacting, bytes.len() as u64,
            store.put_if_absent_with(key, bytes, hints)).await? {
            ensure!(store.get(key).await?.as_deref() == Some(bytes), "existing publication content differs");
        }
        Ok(())
    }).await
}

/// Upload a finished part's files (conditional creates). Not yet live.
pub async fn upload_part_files(store: &dyn ObjectStore, finished: &FinishedPart) -> Result<()> {
    upload_part_files_with_quota(store, finished, false).await
}
async fn upload_part_files_with_quota(store: &dyn ObjectStore, finished: &FinishedPart, compacting: bool) -> Result<()> {
    settle_all(part_file_uploads(store, finished, compacting)?).await.map(|_| ())
}

/// The conditional-create uploads of one finished part's files (not started).
fn part_file_uploads<'a>(store: &'a dyn ObjectStore, finished: &'a FinishedPart, compacting: bool)
    -> Result<Vec<impl std::future::Future<Output = Result<()>> + 'a>> {
    let record = &finished.record;
    let keys = PartKeys::new(&record.tenant_id, record.level, record.event_hour, &record.part_id)?;
    let hints = part_hints(record);
    let files = record.files.all().into_iter().collect::<Vec<_>>();
    for (name, _, bytes) in &files {
        ensure!(*bytes <= MAX_OBJECT_BYTES, "part file {name} exceeds the object cap");
    }
    // A loop, not an iterator closure: closures returning borrowing async
    // blocks are not general enough for the spawned merge/ingest futures.
    let mut uploads = Vec::with_capacity(files.len());
    for (name, sha, bytes) in files {
        let key = keys.file(name);
        uploads.push(async move {
            let path = finished.dir.join(name);
            retry_publication(|| async {
                if !super::merge_quota::remote_transfer(compacting, bytes,
                    store.put_file_if_absent_with(&key, &path, sha, bytes, &hints)).await? {
                    // Verify an immutable collision using a spill file, keeping
                    // memory bounded even for a maximum-size Parquet object.
                    let existing = tempfile::NamedTempFile::new_in(&finished.dir)?;
                    ensure!(store.get_to_file(&key, existing.path()).await?, "existing part file disappeared");
                    let mut file = File::open(existing.path())?;
                    use sha2::Digest;
                    let mut digest = sha2::Sha256::new();
                    use std::io::Read;
                    let mut buffer = [0_u8; 64 * 1024];
                    loop {
                        let count = file.read(&mut buffer)?;
                        if count == 0 { break; }
                        digest.update(&buffer[..count]);
                    }
                    ensure!(file.metadata()?.len() == bytes && hex::encode(digest.finalize()) == sha,
                        "existing part file content differs");
                }
                Ok(())
            }).await?;
            if !compacting {
                // A many-hour foreground flush may publish thousands of files
                // before its single Add can commit. Real completed uploads
                // defer the soft watchdog; its hard bound still applies.
                super::stall_watchdog::note_progress();
            }
            Ok(())
        });
    }
    Ok(uploads)
}

/// Owner-registered writes in flight at once per publish. Wide-history
/// catch-up needs enough independent files to hide authorize/PUT/complete
/// latency. NativePartWriter separately paces owner RPCs across publications
/// (including retries), so a larger window cannot bypass the owner budget.
pub const PUBLISH_CONCURRENCY: usize = 32;

/// Run `writes` up to [`PUBLISH_CONCURRENCY`] at a time. After observing an
/// error, start no more queued writes and settle every in-flight write before
/// reporting that error. Never drop an in-flight write: a
/// native write cancelled between authorize and PUT leaves an unresolved
/// intent that refuses a retry of its key.
async fn settle_all<T, F: std::future::Future<Output = Result<T>>>(writes: Vec<F>) -> Result<Vec<T>> {
    use futures::{FutureExt, StreamExt};
    let mut queued = writes.into_iter().enumerate()
        .map(|(index, write)| write.map(move |result| (index, result)));
    let mut running = futures::stream::FuturesUnordered::new();
    for write in queued.by_ref().take(PUBLISH_CONCURRENCY) {
        running.push(write);
    }
    let mut results = Vec::new();
    let mut failure = None;
    while let Some((index, result)) = running.next().await {
        match result {
            Ok(value) => results.push((index, value)),
            Err(error) if failure.is_none() => failure = Some(error),
            Err(_) => {},
        }
        if failure.is_none() {
            if let Some(write) = queued.next() {
                running.push(write);
            }
        }
    }
    if let Some(error) = failure {
        return Err(error);
    }
    results.sort_by_key(|(index, _)| *index);
    Ok(results.into_iter().map(|(_, value)| value).collect())
}

/// Upload, owner-sign (≤16 parts and ≤ `SIGN_REQUEST_BUDGET_BYTES` per call),
/// verify and store the provenance of
/// each finished part. Returns the log references, in order. Nothing is
/// live until the caller's log entry names them.
pub async fn publish_parts(
    store: &dyn ObjectStore,
    signer: &dyn PartSigner,
    trusted: &TenantKeySet,
    finished: &[FinishedPart],
) -> Result<Vec<PartRef>> {
    publish_parts_with_quota(store, signer, trusted, finished, false, true).await
}

pub async fn publish_compacted_parts(
    store: &dyn ObjectStore, signer: &dyn PartSigner, trusted: &TenantKeySet,
    finished: &[FinishedPart],
) -> Result<Vec<PartRef>> {
    publish_parts_with_quota(store, signer, trusted, finished, true, true).await
}

/// Historical coverage output must not evict the foreground producer cache.
/// Publication, signing and object keys are identical to ordinary compaction.
pub(super) async fn publish_backfilled_parts(
    store: &dyn ObjectStore, signer: &dyn PartSigner, trusted: &TenantKeySet,
    finished: &[FinishedPart],
) -> Result<Vec<PartRef>> {
    publish_parts_with_quota(store, signer, trusted, finished, true, false).await
}

/// Producer-cache warms of one publication in flight at once (each is a
/// local copy + SHA-256 + fsync on a blocking thread).
const WARM_CONCURRENCY: usize = 8;

/// One producer-cache warm; a failure only costs readers a local hit.
async fn warm_one(store: &dyn ObjectStore, key: String, path: PathBuf, digest: String, size: u64) -> bool {
    match store.warm_signed_file(&key, &path, &digest, size).await {
        Ok(warmed) => warmed,
        Err(error) => {
            tracing::warn!(%error, "producer cache warm failed; readers can fetch from R2");
            false
        }
    }
}

async fn publish_parts_with_quota(
    store: &dyn ObjectStore, signer: &dyn PartSigner, trusted: &TenantKeySet,
    finished: &[FinishedPart], compacting: bool, warm_cache: bool,
) -> Result<Vec<PartRef>> {
    if compacting {
        // Parts upload one after another (each part's files concurrently),
        // so a multi-part merge output never holds more than one part's writes.
        for part in finished {
            upload_part_files_with_quota(store, part, compacting).await?;
        }
    } else {
        // An ingest flush (NAN-3183: a catch-up flush is several L0 parts
        // written in parallel): every file of every part shares the
        // PUBLISH_CONCURRENCY window, so parts do not wait on each other.
        let mut uploads = Vec::new();
        for part in finished {
            uploads.extend(part_file_uploads(store, part, compacting)?);
        }
        settle_all(uploads).await?;
    }
    // Large records are signed by reference: stage their canonical bytes at
    // `{part_dir}/provenance.pending.json` first (contract 4.4).
    let payloads = finished.iter().map(|part| SignPayload::for_record(&part.record)).collect::<Result<Vec<_>>>()?;
    let mut staged = Vec::new();
    for (part, payload) in finished.iter().zip(&payloads) {
        let Some(reference) = payload.record_ref.as_ref() else { continue };
        staged.push(async move {
            put_publication_bytes(store, &reference.key, &payload.canonical, &part_hints(&part.record), compacting).await?;
            Ok(())
        });
    }
    settle_all(staged).await?;
    let mut refs = Vec::with_capacity(finished.len());
    let Some(first) = finished.first() else { return Ok(refs) };
    // Byte-bounded calls (NAN-3006): a count-only split of a multi-hour
    // flush overran the owner's 64 KiB body fence.
    let records = finished.iter().map(|f| f.record.clone()).collect::<Vec<_>>();
    let signatures = sign_within_budget(signer, &first.record.tenant_id, &records).await?;
    ensure!(signatures.len() == records.len(), "owner returned a partial signature batch");
    if !crate::producer_cache::index_enabled() {
        // NAN-3610 flag off: today's path, part by part, file by file.
        let mut puts = Vec::with_capacity(finished.len());
        for (part, signature) in finished.iter().zip(signatures) {
            let signed = SignedProvenance::assemble(part.record.clone(), signature, trusted)?;
            let bytes = signed.to_bytes()?;
            let keys = PartKeys::new(&part.record.tenant_id, part.record.level, part.record.event_hour, &part.record.part_id)?;
            let mut warmed = 0_u64;
            for (name, digest, size) in signed.record.files.all().into_iter().filter(|_| warm_cache) {
                match store.warm_signed_file(&keys.file(name), &part.dir.join(name), digest, size).await {
                    Ok(true) => warmed += 1,
                    Ok(false) => {},
                    Err(error) => tracing::warn!(%error, "producer cache warm failed; readers can fetch from R2"),
                }
            }
            tracing::info!(warmed_objects = warmed, reader_cache_warm_on_write_objects = crate::producer_cache::READER_CACHE_WARM_ON_WRITE_OBJECTS.load(std::sync::atomic::Ordering::Relaxed), "reader cache warmed before publication");
            std::fs::write(part.dir.join(PROVENANCE_FILE), &bytes)?;
            refs.push(PartRef::from_record(&part.record, &sha256_hex(&bytes), true));
            let (key, hints) = (keys.provenance(), part_hints(&part.record));
            puts.push(async move {
                put_publication_bytes(store, &key, &bytes, &hints, compacting).await?;
                Ok(())
            });
        }
        // Every provenance is signed and verified above; the writes are
        // independent objects (NAN-3183: one owner round trip each).
        settle_all(puts).await?;
        return Ok(refs);
    }
    // NAN-3610 flag on (`NANO_LAKE_PRODUCER_CACHE_INDEX`).
    let mut signed_parts = Vec::with_capacity(finished.len());
    for (part, signature) in finished.iter().zip(signatures) {
        let signed = SignedProvenance::assemble(part.record.clone(), signature, trusted)?;
        let keys = PartKeys::new(&part.record.tenant_id, part.record.level, part.record.event_hour, &part.record.part_id)?;
        signed_parts.push((part, signed, keys));
    }
    // Warm every signed file of every part concurrently (NAN-3610: one by
    // one they were ~2.7 s per part on the flush's critical path). A failed
    // or skipped warm only costs a reader its local hit: it fetches from R2.
    let warm_started = std::time::Instant::now();
    let mut jobs = signed_parts.iter().filter(|_| warm_cache).flat_map(|(part, signed, keys)| {
        signed.record.files.all().into_iter()
            .map(|(name, digest, size)| (keys.file(name), part.dir.join(name), digest.to_string(), size))
            .collect::<Vec<_>>()
    }).collect::<Vec<_>>().into_iter();
    let (mut running, mut warmed) = (futures::stream::FuturesUnordered::new(), 0_u64);
    loop {
        while running.len() < WARM_CONCURRENCY {
            let Some((key, path, digest, size)) = jobs.next() else { break };
            running.push(warm_one(store, key, path, digest, size));
        }
        let Some(done) = running.next().await else { break };
        warmed += u64::from(done);
    }
    tracing::info!(parts = signed_parts.len(), warmed_objects = warmed, warm_ms = warm_started.elapsed().as_millis() as u64,
        reader_cache_warm_on_write_objects = crate::producer_cache::READER_CACHE_WARM_ON_WRITE_OBJECTS.load(std::sync::atomic::Ordering::Relaxed),
        "reader cache warmed before publication");
    let mut puts = Vec::with_capacity(finished.len());
    for (part, signed, keys) in signed_parts {
        let bytes = signed.to_bytes()?;
        std::fs::write(part.dir.join(PROVENANCE_FILE), &bytes)?;
        refs.push(PartRef::from_record(&part.record, &sha256_hex(&bytes), true));
        let (key, hints) = (keys.provenance(), part_hints(&part.record));
        puts.push(async move {
            put_publication_bytes(store, &key, &bytes, &hints, compacting).await?;
            Ok(())
        });
    }
    // Every provenance is signed and verified above; the writes are
    // independent objects (NAN-3183: one owner round trip each).
    settle_all(puts).await?;
    Ok(refs)
}


#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn publication_retry_is_bounded_and_only_transient() {
        let mut attempts = 0;
        let result = retry_publication(|| {
            attempts += 1;
            let attempt = attempts;
            async move {
                if attempt < 3 {
                    Err(super::super::native_writer::OwnerRefused { status: 503 }.into())
                } else { Ok(()) }
            }
        }).await;
        assert!(result.is_ok());
        assert_eq!(attempts, 3);
        let mut attempts = 0;
        let result: Result<()> = retry_publication(|| {
            attempts += 1;
            async { Err(super::super::native_writer::OwnerRefused { status: 413 }.into()) }
        }).await;
        assert!(result.is_err());
        assert_eq!(attempts, 1);
        let mut attempts = 0;
        let result: Result<()> = retry_publication(|| {
            attempts += 1;
            async { Err(super::super::native_writer::OwnerRefused { status: 429 }.into()) }
        }).await;
        assert!(result.is_err());
        assert_eq!(attempts, 4);
    }

    #[tokio::test]
    async fn publication_same_finished_part_can_resume_without_new_ids() {
        let dir = tempfile::tempdir().unwrap();
        let rows = batch(8, 1_000);
        let mut writer = PartWriter::create(dir.path(), draft(rows.schema(), Level::L0, sources()), PartialSource::FromRows, 1, 1_000).unwrap();
        writer.write(&rows).unwrap();
        let finished = writer.finish().unwrap();
        let store = crate::parts::part_log::LocalObjectStore::new(dir.path().join("store")).unwrap();
        let signer = signer(1);
        let first = publish_parts(&store, &signer, &signer.trusted(), std::slice::from_ref(&finished)).await.unwrap();
        let resumed = publish_parts(&store, &signer, &signer.trusted(), std::slice::from_ref(&finished)).await.unwrap();
        assert_eq!(first[0].part_id, resumed[0].part_id);
        assert_eq!(first[0].provenance_sha256, resumed[0].provenance_sha256);
        assert_eq!(first[0].rows, 8);
        let keys = PartKeys::new(&finished.record.tenant_id, finished.record.level,
            finished.record.event_hour, &finished.record.part_id).unwrap();
        let name = finished.record.files.all()[0].0;
        // Simulate corruption of an immutable remote file. A matching key
        // alone must never be treated as a successfully resumed upload.
        let remote = dir.path().join("store").join(keys.file(name));
        // LocalObjectStore hard-links uploads: detach the remote name before
        // corrupting it so the immutable local source remains unchanged.
        std::fs::remove_file(&remote).unwrap();
        std::fs::write(remote, b"corrupt").unwrap();
        let error = publish_parts(&store, &signer, &signer.trusted(), std::slice::from_ref(&finished)).await.unwrap_err();
        assert!(error.to_string().contains("existing part file content differs"));
    }

    #[test]
    fn unresolved_publication_maps_only_owned_immutable_keys() {
        let dir = tempfile::tempdir().unwrap();
        let rows = batch(8, 1_000);
        let mut writer = PartWriter::create(dir.path(), draft(rows.schema(), Level::L0, sources()), PartialSource::FromRows, 1, 1_000).unwrap();
        writer.write(&rows).unwrap();
        let mut finished = writer.finish().unwrap();
        let keys = PartKeys::new(TENANT, finished.record.level, finished.record.event_hour, &finished.record.part_id).unwrap();
        // Inflate writer metadata only, to force canonical signing by reference.
        finished.record.writer.build = "x".repeat(100_000);
        let pending = SignPayload::for_record(&finished.record).unwrap().record_ref.unwrap().key;
        for key in [keys.file(finished.record.files.all()[0].0), keys.provenance(), pending] {
            let error = super::super::native_writer::NativePutUnresolved { key }.into();
            assert_eq!(unresolved_publication_hour(std::slice::from_ref(&finished), &error).unwrap(), Some(finished.record.event_hour));
        }
        for key in [keys.file("unowned"), keys.provenance().replace(TENANT, "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")] {
            let error = super::super::native_writer::NativePutUnresolved { key }.into();
            assert!(unresolved_publication_hour(std::slice::from_ref(&finished), &error).is_err());
        }
        assert_eq!(unresolved_publication_hour(std::slice::from_ref(&finished), &anyhow::anyhow!("other failure")).unwrap(), None);
    }

    #[tokio::test]
    async fn publication_existing_bytes_must_match() {
        let dir = tempfile::tempdir().unwrap();
        let store = crate::parts::part_log::LocalObjectStore::new(dir.path()).unwrap();
        let hints = WriteHints { class: WriterClass::LakePart, event_hour: 0, min_time_ms: 0, max_time_ms: 1 };
        put_publication_bytes(&store, "immutable", b"signed", &hints, false).await.unwrap();
        put_publication_bytes(&store, "immutable", b"signed", &hints, false).await.unwrap();
        assert!(put_publication_bytes(&store, "immutable", b"different", &hints, false).await.is_err());
    }

    use crate::part_ingest::merge::{merge_parts, MergeInput};
    use crate::part_ingest::schema::{decode, infer_schema};
    use crate::parts::provenance::tests::{signer, TENANT};
    use crate::parts::provenance::SourceObject;
    use std::sync::Arc;

    const HOUR: i32 = 497_314;

    /// Peak resident bytes of this process since the last reset.
    fn vm_hwm() -> u64 {
        let status = std::fs::read_to_string("/proc/self/status").unwrap();
        let kb = status.lines().find(|l| l.starts_with("VmHWM:")).unwrap().split_whitespace().nth(1).unwrap();
        kb.parse::<u64>().unwrap() * 1024
    }

    fn vm_rss() -> u64 {
        let status = std::fs::read_to_string("/proc/self/status").unwrap();
        let kb = status.lines().find(|l| l.starts_with("VmRSS:")).unwrap().split_whitespace().nth(1).unwrap();
        kb.parse::<u64>().unwrap() * 1024
    }

    fn reset_hwm() {
        let _ = std::fs::write("/proc/self/clear_refs", "5");
    }

    /// OCSF-like rows at real tenant width (~6 KB decoded: a 3.5 KB raw
    /// event, a message, process/endpoint/actor objects, vendor leaves).
    fn wide_events(range: std::ops::Range<usize>, span_s: i64) -> Vec<serde_json::Value> {
        range.map(|i| {
            let t = i64::from(HOUR) * 3_600 + (i as i64 % span_s);
            let mut unmapped = serde_json::Map::new();
            for k in 0..24 {
                unmapped.insert(format!("vendor_{}", (i * 31 + k * 97) % 400), serde_json::json!(format!("v{i}-{k}-abcdefghij")));
            }
            serde_json::json!({
                "time": chrono::DateTime::from_timestamp(t, (i % 1_000_000) as u32 * 1000).unwrap().to_rfc3339(),
                "class_uid": 1007, "activity_id": (i % 5) as i64, "severity_id": 1,
                "metadata": {"uid": format!("u-{i:09}"), "log_source": format!("src-{}", i % 11),
                    "product": {"name": "Sysmon", "vendor_name": "Microsoft"}, "version": "1.1.0"},
                "src_endpoint": {"ip": format!("10.{}.{}.{}", i % 7, i % 250, i % 200), "hostname": format!("host-{}.corp.local", i % 700), "port": (i % 65000) as i64},
                "dst_endpoint": {"ip": format!("52.1.{}.{}", i % 250, i % 13), "hostname": format!("svc{}.example.com", i % 900), "port": 443},
                "process": {"name": "powershell.exe", "pid": (i % 30000) as i64,
                    "cmd_line": format!("powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\\Users\\u{}\\AppData\\Local\\Temp\\{i}.ps1", i % 400),
                    "file": {"path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "hashes": [{"algorithm_id": 3, "value": format!("{:064x}", i as u128 * 7919)}]},
                    "parent_process": {"name": "explorer.exe", "pid": 4412, "cmd_line": "C:\\Windows\\explorer.exe"}},
                "actor": {"user": {"name": format!("user{}", i % 400), "domain": "CORP"}},
                "message": format!("Process Create: RuleName: - UtcTime: {t} ProcessGuid: {{{i:08x}-1111-2222-3333-444444444444}} Image: powershell.exe CommandLine: token{} other{}", i % 97, i % 1013),
                "raw_data": format!("<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><EventID>1</EventID><Computer>host-{}.corp.local</Computer></System><EventData>{}</EventData></Event>", i % 700, format!("<Data Name='F{i}'>value {i} lorem ipsum dolor sit amet consectetur</Data>").repeat(45)),
                "unmapped": unmapped,
            })
        }).collect()
    }

    /// NAN-3056: peak memory of an hour seal at real row width, against the
    /// ingest[T] 4.5 GiB cgroup. Run in release:
    /// NAN3056_ROWS=1000000 cargo test --release -p nanosiem-lake-worker --lib hour_merge_memory -- --ignored --nocapture
    #[test]
    #[ignore]
    fn hour_merge_memory_at_tenant_width() {
        let rows: usize = std::env::var("NAN3056_ROWS").ok().and_then(|v| v.parse().ok()).unwrap_or(120_000);
        let parts: usize = 60; // an hour of minute parts
        let dir = tempfile::tempdir().unwrap();
        let schema = Arc::new(infer_schema(&wide_events(0..2_000, 3_600).iter().collect::<Vec<_>>()).unwrap());
        let per = rows / parts;
        let mut inputs = Vec::new();
        let mut decoded_per_row = 0.0;
        for k in 0..parts {
            // Minute parts: time-disjoint slices of the hour.
            let events = wide_events(k * per..(k + 1) * per, 3_600)
                .into_iter()
                .map(|mut e| {
                    let t = i64::from(HOUR) * 3_600 + (k as i64 * 60) + (e["metadata"]["uid"].as_str().unwrap()[2..].parse::<i64>().unwrap() % 60);
                    e["time"] = serde_json::json!(chrono::DateTime::from_timestamp(t, 0).unwrap().to_rfc3339());
                    e
                })
                .collect::<Vec<_>>();
            let batch = sort_by_time_uid(&decode(schema.clone(), &events.iter().collect::<Vec<_>>()).unwrap()).unwrap();
            decoded_per_row = batch.get_array_memory_size() as f64 / batch.num_rows() as f64;
            let mut writer = PartWriter::create(dir.path(), draft(schema.clone(), Level::L0, sources()), PartialSource::FromRows, k as i64 + 1, per as u64).unwrap();
            writer.write(&batch).unwrap();
            let finished = writer.finish().unwrap();
            inputs.push(MergeInput { part: PartRef::from_record(&finished.record, &"0".repeat(64), true), dir: finished.dir.clone() });
        }
        // ingest[T]'s cgroup: 4.5 GiB. One background hour merge runs while
        // the tick flushes a full, budget-bounded admission buffer.
        const MEMORY_MAX: u64 = 4_831_838_208;
        crate::part_ingest::merge::set_memory_budget(MEMORY_MAX);
        let budget = crate::part_ingest::ingest::buffer_budget_for(MEMORY_MAX);
        let baseline = vm_rss();
        reset_hwm();
        let started = std::time::Instant::now();
        let merge = {
            let (dir, inputs, schema) = (dir.path().to_path_buf(), inputs.clone(), schema.clone());
            std::thread::spawn(move || {
                let merged = merge_parts(&dir, TENANT, Level::Hour, HOUR, &inputs, schema.clone(),
                    &crate::parts::format::schema_fingerprint(&schema).unwrap(), crate::parts::provenance::tests::SIGNER, "test", 1_000).unwrap();
                (merged.finished.record.rows, started.elapsed().as_secs_f64())
            })
        };
        // The flush: the buffer at its byte budget, decoded, sorted, written.
        let mut held = Vec::new();
        let mut held_bytes = 0;
        let mut next = 10_000_000;
        while held_bytes < budget {
            for event in wide_events(next..next + 1_000, 3_600) {
                held_bytes += crate::part_ingest::ingest::value_heap_bytes(&event);
                held.push(event);
            }
            next += 1_000;
        }
        let batch = sort_by_time_uid(&decode(schema.clone(), &held.iter().collect::<Vec<_>>()).unwrap()).unwrap();
        let mut writer = PartWriter::create(dir.path(), draft(schema.clone(), Level::L0, sources()), PartialSource::FromRows, 9_999, batch.num_rows() as u64).unwrap();
        writer.write(&batch).unwrap();
        let flushed = writer.finish().unwrap().record.rows;
        let flush_s = started.elapsed().as_secs_f64();
        drop((batch, held));
        let (merged_rows, merge_s) = merge.join().unwrap();
        let peak = vm_hwm();
        // The same hour with serial digests (before NAN-3056's merge pool).
        crate::parts::provenance::set_parallel_merge_digests(false);
        let serial = std::time::Instant::now();
        merge_parts(dir.path(), TENANT, Level::Hour, HOUR, &inputs, schema.clone(),
            &crate::parts::format::schema_fingerprint(&schema).unwrap(), crate::parts::provenance::tests::SIGNER, "test", 2_000).unwrap();
        let serial_s = serial.elapsed().as_secs_f64();
        crate::parts::provenance::set_parallel_merge_digests(true);
        let pooled = std::time::Instant::now();
        merge_parts(dir.path(), TENANT, Level::Hour, HOUR, &inputs, schema.clone(),
            &crate::parts::format::schema_fingerprint(&schema).unwrap(), crate::parts::provenance::tests::SIGNER, "test", 3_000).unwrap();
        println!("hour merge alone: serial digests {serial_s:.1} s, 2-thread merge digest pool {:.1} s ({merge_s:.1} s beside the flush)",
            pooled.elapsed().as_secs_f64());
        assert_eq!(merged_rows as usize, per * parts);
        println!("hour merge {merged_rows} rows ({:.1} KB decoded/row) in {merge_s:.1} s, concurrent flush of {flushed} rows ({} MiB budget) in {flush_s:.1} s: baseline RSS {} MiB, peak {} MiB (+{} MiB), memory.max {} MiB",
            decoded_per_row / 1024.0, budget >> 20, baseline >> 20, peak >> 20, peak.saturating_sub(baseline) >> 20, MEMORY_MAX >> 20);
        // Headroom for the process base, the uid window and admission.
        assert!(peak < MEMORY_MAX / 2, "merge + flush peak {} MiB is over half of memory.max", peak >> 20);
    }

    fn batch(n: usize, offset: usize) -> RecordBatch {
        let events = (0..n)
            .map(|i| {
                let t = i64::from(HOUR) * 3_600 + ((i + offset) as i64 % 3_000);
                serde_json::json!({
                    "time": chrono::DateTime::from_timestamp(t, (i + offset) as u32 * 1000).unwrap().to_rfc3339(),
                    "metadata": {"uid": format!("u-{:06}", i + offset), "log_source": "s"},
                    "message": format!("event {} token{}", i + offset, (i + offset) % 17),
                    "src_endpoint": {"ip": format!("10.0.0.{}", (i + offset) % 200)}
                })
            })
            .collect::<Vec<_>>();
        let refs = events.iter().collect::<Vec<_>>();
        let schema = Arc::new(infer_schema(&refs).unwrap());
        sort_by_time_uid(&decode(schema, &refs).unwrap()).unwrap()
    }

    fn draft(schema: SchemaRef, level: Level, inputs: PartInputs) -> PartDraft {
        let admission = (level == Level::L0).then(|| Admission {
            ocsf_version: "1.9.0".into(),
            admission_contract: "t".into(),
            feed_pins: Default::default(),
        });
        PartDraft {
            tenant_id: TENANT.into(),
            signer_key_id: crate::parts::provenance::tests::SIGNER.into(),
            level,
            event_hour: HOUR,
            schema_fingerprint: crate::parts::format::schema_fingerprint(&schema).unwrap(),
            schema,
            inputs,
            admission,
            rows_in: 0,
            duplicates_dropped: 0,
            window: DedupWindow::Exact,
            build: "test".into(),
        }
    }

    fn sources() -> PartInputs {
        PartInputs::Sources {
            sources: vec![SourceObject { key: "k".into(), version: "1".into(), bytes: 1, sha256: "0".repeat(64), rows: 1, edge_sha256: None }],
            edge_log: None,
        }
    }

    #[tokio::test]
    async fn parquet_ranges_are_optional_signed_and_match_closed_writer_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let rows = batch(100, 0);
        let signer = signer(7);
        for enabled in [false, true] {
            let mut writer = PartWriter::create(dir.path(), draft(rows.schema(), Level::L0, sources()), PartialSource::FromRows, 1, 100).unwrap();
            writer.parquet_range_write = enabled;
            writer.write(&rows).unwrap();
            let part = writer.finish().unwrap();
            let data = &part.record.files.data[0];
            assert_eq!(data.parquet_ranges.is_some(), enabled);
            let canonical = part.record.canonical_bytes().unwrap();
            if !enabled { assert!(!String::from_utf8_lossy(&canonical).contains("parquet_ranges")); }
            let signature = signer.sign(TENANT, std::slice::from_ref(&part.record)).await.unwrap().remove(0);
            let signed = SignedProvenance::assemble(part.record.clone(), signature, &signer.trusted()).unwrap();
            SignedProvenance::verify_bytes(&signed.to_bytes().unwrap(), TENANT, &signer.trusted()).unwrap();
            if enabled {
                let bytes = std::fs::read(part.dir.join(&data.name)).unwrap();
                let manifest = data.parquet_ranges.as_ref().unwrap();
                let body = std::fs::read(part.dir.join(&manifest.name)).unwrap();
                assert_eq!(sha256_hex(&body), manifest.sha256);
                let ranges: Vec<crate::parts::parquet_ranges::ParquetRangeDigest> = serde_json::from_slice(&body).unwrap();
                for range in &ranges {
                    assert_eq!(sha256_hex(&bytes[range.offset as usize..(range.offset + range.bytes) as usize]), range.sha256);
                }
                let mut tampered = signed;
                tampered.record.files.data[0].parquet_ranges.as_mut().unwrap().sha256 = "f".repeat(64);
                assert!(SignedProvenance::verify_bytes(&tampered.to_bytes().unwrap(), TENANT, &signer.trusted()).is_err());
            }
        }
    }

    /// Run alone with both coverage opt-ins; production flags remain off.
    #[tokio::test]
    #[ignore]
    async fn coverage_remerge_signs_new_part_and_resumes_without_rewriting() {
        use super::super::ingest::probe_and_fetch_for_reindex;
        use crate::parts::part_log::LocalObjectStore;
        assert!(super::super::reindex::sidecar_enabled());
        let dir = tempfile::tempdir().unwrap();
        let store: &'static LocalObjectStore = Box::leak(Box::new(LocalObjectStore::new(dir.path().join("store")).unwrap()));
        let rows = batch(600, 0);
        let owner = signer(7);
        let mut source = PartWriter::create(dir.path(), draft(rows.schema(), Level::L0, sources()), PartialSource::FromRows, 0, 600).unwrap();
        source.uid_sidecar_write = false;
        source.write(&rows).unwrap();
        let source = publish_parts(store, &owner, &owner.trusted(), &[source.finish().unwrap()]).await.unwrap().remove(0);
        let inputs = PartInputs::Parts { parts: vec![crate::parts::provenance::InputPart {
            part_id: source.part_id.clone(), level: source.level,
            provenance_sha256: source.provenance_sha256.clone(), rows: source.rows, merkle_root: source.merkle_root.clone(),
        }] };
        let mut writer = PartWriter::create(dir.path(), draft(rows.schema(), Level::Hour, inputs), PartialSource::FromRows, 1, 600).unwrap();
        writer.uid_sidecar_write = false;
        writer.write(&rows).unwrap();
        let legacy = writer.finish().unwrap();
        let old = publish_parts(store, &owner, &owner.trusted(), &[legacy]).await.unwrap().remove(0);
        let cache = dir.path().join("cache");
        let local = probe_and_fetch_for_reindex(store, TENANT.into(), owner.trusted(), cache.clone(), old.clone()).await.unwrap().unwrap();
        let merged = merge_parts(dir.path(), TENANT, Level::Hour, HOUR,
            &[MergeInput { part: old.clone(), dir: local }], rows.schema(), &old.schema_fingerprint,
            &crate::parts::provenance::tests::SIGNER, "coverage-test", 2).unwrap();
        assert_eq!(merged.finished.record.rows, old.rows);
        assert_eq!(merged.finished.record.merkle_root, old.merkle_root);
        assert_ne!(merged.finished.record.part_id, old.part_id);
        assert!(super::super::reindex::sidecars_are_current(&merged.finished.record, true));
        let data = &merged.finished.record.files.data[0];
        let actual = parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder::try_new(File::open(merged.finished.dir.join(&data.name)).unwrap()).unwrap().build().unwrap()
            .flat_map(|batch| uid_strings(&batch.unwrap()).unwrap().into_iter().flatten().map(str::to_owned).collect::<Vec<_>>()).collect::<Vec<_>>();
        assert_eq!(actual, uid_strings(&rows).unwrap().into_iter().flatten().map(str::to_owned).collect::<Vec<_>>());
        let output = publish_compacted_parts(store, &owner, &owner.trusted(), &[merged.finished]).await.unwrap().remove(0);
        for _ in 0..2 {
            assert!(probe_and_fetch_for_reindex(store, TENANT.into(), owner.trusted(), cache.clone(), output.clone()).await.unwrap().is_none());
        }
        use crate::parts::part_log::{PartLogWriter, LogOp, load_log};
        let mut log = PartLogWriter::open(store, TENANT, 1, rows.schema().as_ref(), 1).await.unwrap();
        let receipt = crate::parts::part_log::SourceRef { key: "k".into(), version: "1".into(), sha256: "0".repeat(64) };
        log.append(LogOp::Add { parts: vec![source.clone()], consumed: vec![receipt], edge_log: None }, 2).await.unwrap();
        log.append(LogOp::Merge { output: old.clone(), supersedes: vec![source.part_id] }, 3).await.unwrap();
        log.append(LogOp::Merge { output: output.clone(), supersedes: vec![old.part_id.clone()] }, 4).await.unwrap();
        let restarted = load_log(store, TENANT).await.unwrap();
        assert!(restarted.get(&old.part_id).is_none());
        assert!(restarted.is_removed(&old.part_id));
        assert!(restarted.get(&output.part_id).is_some());
        let keys = PartKeys::new(TENANT, output.level, HOUR, &output.part_id).unwrap();
        let provenance = store.get(&keys.provenance()).await.unwrap().unwrap();
        let signed = SignedProvenance::verify_bytes(&provenance, TENANT, &owner.trusted()).unwrap();
        output.check_record(&signed.record, &sha256_hex(&provenance)).unwrap();
    }

    #[test]
    fn uid_sidecar_rollout_defaults_off_and_preserves_legacy_provenance() {
        assert!(!uid_sidecar_write_enabled(None));
        for value in ["", "0", "false", "yes", "invalid"] {
            assert!(!uid_sidecar_write_enabled(Some(value)));
        }
        for value in ["1", "true", "TRUE"] {
            assert!(uid_sidecar_write_enabled(Some(value)));
        }
        let dir = tempfile::tempdir().unwrap();
        let rows = batch(100, 0);
        for enabled in [false, true] {
            let mut writer = PartWriter::create(dir.path(), draft(rows.schema(), Level::L0, sources()), PartialSource::FromRows, 1, 100).unwrap();
            writer.uid_sidecar_write = enabled;
            writer.write(&rows).unwrap();
            let part = writer.finish().unwrap();
            let file = &part.record.files.data[0];
            assert_eq!(file.uid_blooms.is_some(), enabled);
            assert_eq!(file.entity_blooms.is_some(), enabled);
            assert_eq!(part.dir.join("entities-00000.json").exists(), enabled);
            assert_eq!(part.dir.join("uids-00000.json").exists(), enabled);
            let bytes = serde_json::to_vec(&part.record).unwrap();
            let decoded: ProvenanceRecord = serde_json::from_slice(&bytes).unwrap();
            assert_eq!(serde_json::to_vec(&decoded).unwrap(), bytes, "readers round-trip both formats");
            if !enabled {
                // The pre-#5078 data-file shape, in its original serialization order.
                #[derive(serde::Serialize)]
                struct LegacyDataFile<'a> {
                    name: &'a str,
                    bytes: u64,
                    sha256: &'a str,
                    rows: u64,
                    row_groups: u32,
                    min_time_us: i64,
                    max_time_us: i64,
                    #[serde(skip_serializing_if = "Option::is_none")]
                    log_sources: &'a Option<Vec<String>>,
                    tokens: &'a FileDigest,
                }
                let legacy = LegacyDataFile { name: &file.name, bytes: file.bytes, sha256: &file.sha256,
                    rows: file.rows, row_groups: file.row_groups, min_time_us: file.min_time_us,
                    max_time_us: file.max_time_us, log_sources: &file.log_sources, tokens: &file.tokens };
                assert_eq!(serde_json::to_vec(file).unwrap(), serde_json::to_vec(&legacy).unwrap());
                let mut legacy_record = serde_json::to_value(&part.record).unwrap();
                legacy_record["files"]["data"][0] = serde_json::to_value(&legacy).unwrap();
                let mut canonical = Vec::new();
                crate::parts::provenance::write_canonical_json(&legacy_record, &mut canonical).unwrap();
                assert_eq!(part.record.canonical_bytes().unwrap(), canonical, "owner signing bytes match pre-#5078 provenance");
                assert!(!String::from_utf8(bytes).unwrap().contains("uid_blooms"));
            }
        }
    }

    /// Scaled mixed-level, wide-OCSF benchmark; local transport only. This
    /// deliberately does not certify R2 p95 or production merge coverage.
    #[test]
    #[ignore]
    fn mixed_level_physical_layout_benchmark() {
        use crate::parts::entity_locators::EntityLocators;
        use crate::planner::CandidateHint;
        let mut events = wide_events(0..12_000, 3600);
        for (row, event) in events.iter_mut().enumerate() {
            event["class_uid"] = serde_json::json!(1000 + row % 4);
            event["device"] = serde_json::json!({"hostname": format!("host-{}.corp.local", row % 700)});
        }
        let schema = Arc::new(infer_schema(&events.iter().collect::<Vec<_>>()).unwrap());
        let mut baseline_roots = Vec::new();
        let mut baseline_bytes = 0;
        let mut baseline_decoded = 0;
        for experimental in [false, true] {
            let start = std::time::Instant::now();
            let dir = tempfile::tempdir().unwrap();
            let (mut bytes, mut files, mut groups, mut kept, mut decoded, mut locator_bytes) = (0_u64, 0_usize, 0_u32, 0_usize, 0_usize, 0_u64);
            let mut rows_seen = Vec::new();
            let mut offset = 0;
            // Twelve 250-row L0s, four 750-row M parts, two 3000-row hours.
            for (part_index, (level, count)) in std::iter::repeat_n((Level::L0, 250), 12)
                .chain(std::iter::repeat_n((Level::Minute, 750), 4))
                .chain(std::iter::repeat_n((Level::Hour, 3000), 2)).enumerate() {
                let slice = &events[offset..offset + count];
                let rows = sort_by_time_uid(&decode(schema.clone(), &slice.iter().collect::<Vec<_>>()).unwrap()).unwrap();
                offset += count;
                let mut spec = draft(schema.clone(), level, sources());
                if level != Level::L0 {
                    spec.admission = None;
                    spec.inputs = PartInputs::Parts { parts: vec![crate::parts::provenance::InputPart {
                        part_id: PartId::new(1).unwrap(), level: Level::L0, provenance_sha256: "0".repeat(64), rows: count as u64, merkle_root: "0".repeat(64),
                    }] };
                }
                spec.rows_in = count as u64;
                let settings = ParquetSettings { zstd_level: 3, row_group_rows: if experimental && level != Level::L0 { 8192 } else { 65536 }, max_file_bytes: 64 * 1024 * 1024 }.for_compaction_rows(level, count as u64);
                let cluster = experimental && ParquetSettings::cluster_worthwhile(count as u64, settings.row_group_rows);
                let mut writer = PartWriter::create_with(dir.path(), spec, PartialSource::FromRows, part_index as i64 + 1, count as u64, settings).unwrap();
                writer.entity_locator_write = experimental && level != Level::L0;
                writer.entity_sidecar_fields = vec!["device.hostname".into()];
                if level == Level::Hour || (cluster && level == Level::Minute) {
                    crate::part_ingest::merge::cluster_fixture(dir.path(), &rows, &mut writer, cluster).unwrap();
                } else { writer.write(&rows).unwrap(); }
                let part = writer.finish().unwrap();
                if experimental { assert_eq!(part.record.merkle_root, baseline_roots[part_index]); }
                else { baseline_roots.push(part.record.merkle_root.clone()); }
                bytes += part.record.files.data.iter().map(|file| file.bytes).sum::<u64>();
                files += part.record.files.data.len();
                groups += part.record.files.row_groups();
                let hints = [CandidateHint::Entity { source_path: "device.hostname".into(), value: "HOST-5.CORP.LOCAL".into() }];
                for file in &part.record.files.data {
                    let mask = if let Some(locator) = &file.entity_locators {
                        locator_bytes += locator.bytes;
                        EntityLocators::decode(&std::fs::read(part.dir.join(&locator.name)).unwrap(), file.row_groups as usize, file.rows).unwrap().group_mask(&hints)
                    } else { vec![true; file.row_groups as usize] };
                    let selected = mask.iter().enumerate().filter_map(|(index, keep)| keep.then_some(index)).collect::<Vec<_>>();
                    kept += selected.len();
                    if selected.is_empty() { continue; }
                    for batch in parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder::try_new(File::open(part.dir.join(&file.name)).unwrap()).unwrap().with_row_groups(selected).build().unwrap() {
                        let batch = batch.unwrap();
                        decoded += batch.num_rows();
                        let hosts = CompiledStringPath::new(&batch, "device.hostname").unwrap();
                        let uids = uid_strings(&batch).unwrap();
                        for row in 0..batch.num_rows() {
                            if hosts.strings(row).iter().any(|host| host.eq_ignore_ascii_case("host-5.corp.local")) { rows_seen.push(uids.value(row).to_owned()); }
                        }
                    }
                }
            }
            if experimental {
                assert!(bytes <= baseline_bytes * 105 / 100, "data-byte cost gate");
                assert!(bytes + locator_bytes <= baseline_bytes * 105 / 100, "data plus locator cost gate");
                assert!(decoded < baseline_decoded, "selectivity must retain its pruning win");
            } else { baseline_bytes = bytes; baseline_decoded = decoded; }
            rows_seen.sort();
            let expected = events.iter().filter(|event| event["device"]["hostname"] == "host-5.corp.local").map(|event| event["metadata"]["uid"].as_str().unwrap().to_owned()).collect::<Vec<_>>();
            assert_eq!(rows_seen, expected, "mixed-level same rows and exact count");
            eprintln!("mixed-layout experimental={experimental} l0=12 m=4 h=2 rows=12000 files={files} groups={groups} data_bytes={bytes} locator_bytes={locator_bytes} kept_groups={kept} decoded_rows={decoded} matches={} elapsed_ms={}", rows_seen.len(), start.elapsed().as_millis());
        }
    }

    /// NAN-3156: a merged hour part written with gen1's 262,144-row groups
    /// keeps that group size. A locator whose every group overflowed its
    /// byte budget (all fields unknown) is not written at all: it answered
    /// nothing, yet its presence hid the bloom sidecar from the reader.
    /// The bloom sidecar prunes both the dense and the sparse field.
    #[test]
    fn wide_hour_groups_write_blooms_and_no_empty_locator() {
        use crate::part_query::prune::{entity_summary_mask, EntityBlooms};
        use crate::planner::CandidateHint;
        // Above the 8 x 65,536-row fragmentation floor, like a 300-eps hour.
        const ROWS: usize = 600_000;
        let wide = crate::parts::format::MAX_ROW_GROUP_ROWS;
        let dir = tempfile::tempdir().unwrap();
        let events = (0..ROWS).map(|i| serde_json::json!({
            "time": chrono::DateTime::from_timestamp(i64::from(HOUR) * 3600 + (i * 3599 / ROWS) as i64, (i % 1000) as u32 * 1000).unwrap().to_rfc3339(),
            "metadata": {"uid": format!("u-{i:07}"), "log_source": "s"},
            // Dense and high-cardinality: megabytes of offsets per group.
            "src_endpoint": {"ip": format!("10.{}.{}.{}", i / 65_536, (i / 256) % 256, i % 256)},
            "device": {"hostname": format!("ws-{}.corp.local", i % 40)},
            // Sparse: one row in 50,000.
            "user": {"name": if i % 50_000 == 7 { Some(format!("rare-{i}")) } else { None }},
        })).collect::<Vec<_>>();
        let refs = events.iter().collect::<Vec<_>>();
        let rows = sort_by_time_uid(&decode(Arc::new(infer_schema(&refs).unwrap()), &refs).unwrap()).unwrap();
        let mut spec = draft(rows.schema(), Level::Hour, PartInputs::Parts { parts: vec![crate::parts::provenance::InputPart {
            part_id: PartId::new(1).unwrap(), level: Level::L0, provenance_sha256: "0".repeat(64), rows: ROWS as u64, merkle_root: "0".repeat(64),
        }] });
        spec.rows_in = ROWS as u64;
        let settings = ParquetSettings::for_level(Level::Hour).compaction_layout(Level::Hour, Some("262144:268435456")).unwrap()
            .for_compaction_rows(Level::Hour, ROWS as u64);
        assert_eq!(settings.row_group_rows, wide);
        let mut writer = PartWriter::create_with(dir.path(), spec, PartialSource::FromRows, 1, ROWS as u64, settings).unwrap();
        writer.uid_sidecar_write = true;
        // Production wide layouts never write locators (see
        // `wide_layouts_write_no_entity_locators`); forced on here to prove
        // that an all-unknown locator is not published.
        writer.entity_locator_write = true;
        writer.entity_sidecar_fields = entity_sidecar_fields(Some("device.hostname,src_endpoint.ip,user.name"));
        writer.write(&rows).unwrap();
        let part = writer.finish().unwrap();
        assert_eq!(part.record.files.data.len(), 1);
        let file = &part.record.files.data[0];
        let metadata = parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder::try_new(File::open(part.dir.join(&file.name)).unwrap()).unwrap();
        let groups = metadata.metadata().row_groups().iter().map(|group| group.num_rows() as usize).collect::<Vec<_>>();
        assert_eq!(groups, vec![wide, wide, ROWS - 2 * wide]);
        assert_eq!(file.row_groups, 3);
        assert!(file.entity_locators.is_none(), "an all-unknown locator is not written");
        assert!(!part.dir.join("locators-00000.json").exists());
        let hint = |path: &str, value: &str| CandidateHint::Entity { source_path: path.into(), value: value.into() };
        let blooms: EntityBlooms = serde_json::from_slice(&std::fs::read(part.dir.join(&file.entity_blooms.as_ref().unwrap().name)).unwrap()).unwrap();
        let ip = events[ROWS - 1]["src_endpoint"]["ip"].as_str().unwrap().to_owned();
        assert_eq!(entity_summary_mask(Some(&blooms), 3, &[hint("src_endpoint.ip", &ip)]), Some(vec![false, false, true]));
        let rare = events[7]["user"]["name"].as_str().unwrap().to_owned();
        assert_eq!(entity_summary_mask(Some(&blooms), 3, &[hint("user.name", &rare)]), Some(vec![true, false, false]));
        // Every row reads back exactly once.
        let mut seen = std::collections::BTreeSet::new();
        for batch in metadata.build().unwrap() {
            let batch = batch.unwrap();
            seen.extend(uid_strings(&batch).unwrap().iter().flatten().map(str::to_owned));
        }
        assert_eq!(seen, (0..ROWS).map(|i| format!("u-{i:07}")).collect());
    }

    fn hour_part(dir: &Path, events: &[serde_json::Value], fields: Option<&str>) -> FinishedPart {
        let refs = events.iter().collect::<Vec<_>>();
        let rows = sort_by_time_uid(&decode(Arc::new(infer_schema(&refs).unwrap()), &refs).unwrap()).unwrap();
        let mut spec = draft(rows.schema(), Level::Hour, PartInputs::Parts { parts: vec![crate::parts::provenance::InputPart {
            part_id: PartId::new(1).unwrap(), level: Level::L0, provenance_sha256: "0".repeat(64), rows: events.len() as u64, merkle_root: "0".repeat(64),
        }] });
        spec.rows_in = events.len() as u64;
        let settings = ParquetSettings::for_level(Level::Hour).compaction_layout(Level::Hour, Some("262144:268435456")).unwrap()
            .for_compaction_rows(Level::Hour, events.len() as u64);
        let mut writer = PartWriter::create_with(dir, spec, PartialSource::FromRows, 1, events.len() as u64, settings).unwrap();
        writer.uid_sidecar_write = true;
        writer.entity_sidecar_fields = entity_sidecar_fields(fields);
        writer.write(&rows).unwrap();
        writer.finish().unwrap()
    }

    /// NAN-3694: the entity sidecar carries a folded bloom per foldable
    /// field and row group; a long mixed-case email prunes by it, a group
    /// holding the value in any case is never pruned, and ingest-lowercased
    /// fields get none.
    #[test]
    fn entity_sidecar_folds_long_mixed_case_values() {
        use crate::part_query::prune::{entity_summary_mask, folded_bloom_key, EntityBlooms};
        use crate::planner::CandidateHint;
        const ROWS: usize = 3_000;
        let dir = tempfile::tempdir().unwrap();
        let events = (0..ROWS).map(|i| serde_json::json!({
            "time": chrono::DateTime::from_timestamp(i64::from(HOUR) * 3600 + i as i64, 0).unwrap().to_rfc3339(),
            "metadata": {"uid": format!("u-{i:07}"), "log_source": "s"},
            "src_endpoint": {"ip": format!("10.0.{}.{}", i / 256, i % 256)},
            "user": {"email_addr": if i == 1_234 { "Alice.Smith@Example.COM".to_string() } else { format!("Person.{i}@Example.com") }},
            "actor": {"user": {"name": format!("corp.local\\serviceaccount{i}")}},
        })).collect::<Vec<_>>();
        let part = hour_part(dir.path(), &events, None);
        let file = &part.record.files.data[0];
        let blooms: EntityBlooms = serde_json::from_slice(&std::fs::read(part.dir.join(&file.entity_blooms.as_ref().unwrap().name)).unwrap()).unwrap();
        let groups = file.row_groups as usize;
        assert!(blooms.contains_key(&folded_bloom_key("user.email_addr")));
        assert!(!blooms.contains_key(&folded_bloom_key("src_endpoint.ip")), "ingest-lowercased: the raw bloom is exact");
        let hint = |value: &str| CandidateHint::Entity { source_path: "user.email_addr".into(), value: value.into() };
        // Present in some group in a different case: that group is kept.
        let mask = entity_summary_mask(Some(&blooms), groups, &[hint("alice.smith@example.com")]).unwrap();
        assert!(mask.iter().any(|keep| *keep));
        // Absent: every group pruned (one group here; a 1e-4 false positive
        // would only keep it).
        let absent = entity_summary_mask(Some(&blooms), groups, &[hint("Nobody.Here@Example.com")]).unwrap();
        assert!(!absent.iter().any(|keep| *keep), "{absent:?}");
        // An all-lowercase field writes the "=" marker; its raw bloom answers.
        let marker = &blooms[&folded_bloom_key("actor.user.name")];
        assert!(marker.iter().all(|group| group.as_deref() == Some(crate::part_query::prune::FOLDED_SAME_AS_RAW)), "{marker:?}");
        let name = |value: &str| CandidateHint::Entity { source_path: "actor.user.name".into(), value: value.into() };
        assert!(entity_summary_mask(Some(&blooms), groups, &[name("CORP.LOCAL\\ServiceAccount77")]).unwrap().iter().any(|keep| *keep));
        assert!(!entity_summary_mask(Some(&blooms), groups, &[name("CORP.LOCAL\\NoSuchAccount")]).unwrap().iter().any(|keep| *keep));
        // Without the folded key the long value is unknown (today's answer).
        let mut raw_only = blooms.clone();
        raw_only.remove(&folded_bloom_key("user.email_addr"));
        assert_eq!(entity_summary_mask(Some(&raw_only), groups, &[hint("Nobody.Here@Example.com")]), Some(vec![true; groups]));
    }

    /// NAN-3694 size check (ignored; prints): sidecar bytes of a tenant-a-like
    /// windows_sysmon hour slice with and without folded blooms. Shape from
    /// the load-test tenant `dc()` over one hour: 832,455 rows, actor.process.uid
    /// 817,119, process.uid 70,200, actor.user.name 624,
    /// actor.process.user.name 623, process.name 87, file.hashes.value 1,946.
    #[test]
    #[ignore]
    fn folded_sidecar_size_on_a_b12_like_hour() {
        const ROWS: usize = 832_455;
        let dir = tempfile::tempdir().unwrap();
        let events = (0..ROWS).map(|i| serde_json::json!({
            "time": chrono::DateTime::from_timestamp(i64::from(HOUR) * 3600 + (i * 3599 / ROWS) as i64, (i % 1000) as u32 * 1000).unwrap().to_rfc3339(),
            "metadata": {"uid": format!("u-{i:07}"), "log_source": "windows_sysmon"},
            "device": {"hostname": format!("ws-{}.corp.local", i % 600)},
            "src_endpoint": {"ip": format!("10.1.{}.{}", (i / 256) % 16, i % 256)},
            "process": {"name": format!("proc{}.exe", i % 87), "uid": format!("{{{:08x}-0000-0000-0000-{:012x}}}", i % 70_200, i % 70_200)},
            // tenant-a stores sysmon GUIDs, user and image names lowercase; the
            // run-as name keeps its `CORP.LOCAL\` casing.
            "actor": {
                "user": {"name": format!("user{}", i % 624)},
                "process": {"name": format!("parent{}.exe", i % 89), "uid": format!("{{{:08x}-1111-0000-0000-{:012x}}}", i, i),
                    "user": {"name": format!("CORP.LOCAL\\User{}", i % 623)}},
            },
        })).collect::<Vec<_>>();
        let measure = |fields: &str| {
            let dir = dir.path().join(fields.len().to_string());
            let part = hour_part(&dir, &events, Some(fields));
            part.record.files.data.iter().map(|file| {
                let name = &file.entity_blooms.as_ref().unwrap().name;
                let mut blooms: crate::part_query::prune::EntityBlooms = serde_json::from_slice(&std::fs::read(part.dir.join(name)).unwrap()).unwrap();
                let per_key = blooms.iter().map(|(key, groups)| (key.clone(), serde_json::to_vec(groups).unwrap().len())).collect::<Vec<_>>();
                blooms.retain(|key, _| !key.starts_with(crate::part_query::prune::FOLDED_BLOOM_PREFIX));
                (file.bytes, file.row_groups, file.entity_blooms.as_ref().unwrap().bytes, serde_json::to_vec(&blooms).unwrap().len(), per_key)
            }).collect::<Vec<_>>()
        };
        let fields = "device.hostname,src_endpoint.ip,process.name,process.uid,actor.user.name,actor.process.name,actor.process.uid,actor.process.user.name";
        for (data, groups, after, before, per_key) in measure(fields) {
            println!("data_bytes={data} row_groups={groups} sidecar_before={before} sidecar_after={after}");
            for (key, bytes) in per_key { println!("  {key}: {bytes}"); }
        }
    }

    #[test]
    fn wide_layouts_write_no_entity_locators() {
        let base = ParquetSettings::for_level(Level::Hour);
        let wide = base.compaction_layout(Level::Hour, Some("262144:268435456")).unwrap();
        let small = base.compaction_layout(Level::Hour, Some("8192:67108864")).unwrap();
        assert!(entity_locator_write_enabled(Level::Hour, &base, Some("1")));
        assert!(entity_locator_write_enabled(Level::Hour, &small, Some("1")));
        assert!(!entity_locator_write_enabled(Level::Hour, &wide, Some("1")));
        assert!(!entity_locator_write_enabled(Level::Hour, &base, None));
        assert!(!entity_locator_write_enabled(Level::Hour, &base, Some("0")));
        assert!(!entity_locator_write_enabled(Level::L0, &ParquetSettings::for_level(Level::L0), Some("1")));
    }

    #[test]
    fn entity_sidecars_same_rows_and_counts_as_unpruned_random_and_chains() {
        use crate::planner::CandidateHint;
        use crate::part_query::prune::{EntityBlooms, entity_summary_mask};
        let dir = tempfile::tempdir().unwrap();
        let events = (0..600).map(|i| serde_json::json!({
            "time": chrono::DateTime::from_timestamp(i64::from(HOUR) * 3600 + i, 0).unwrap().to_rfc3339(),
            "metadata": {"uid": format!("u-{i:06}"), "log_source": "s"},
            "src_endpoint": {"ip": format!("10.0.{}.{}", i / 100, i % 5)},
            "device": {"hostname": format!("ws-support-{}.corp.local", i / 100)},
            "user": {"name": if i % 9 == 0 { None } else { Some(if i % 2 == 0 { "Alice" } else { "bob" }) }}
        })).collect::<Vec<_>>();
        let refs = events.iter().collect::<Vec<_>>();
        let rows = sort_by_time_uid(&decode(Arc::new(infer_schema(&refs).unwrap()), &refs).unwrap()).unwrap();
        for (group_rows, file_bytes) in [(50, 1), (100, 1), (50, MAX_OBJECT_BYTES / 2)] {
            let settings = ParquetSettings { zstd_level: 3, row_group_rows: group_rows, max_file_bytes: file_bytes };
            let mut writer = PartWriter::create_with(dir.path(), draft(rows.schema(), Level::L0, sources()), PartialSource::FromRows, 1, 600, settings).unwrap();
            writer.uid_sidecar_write = true;
            writer.entity_locator_write = true;
            writer.entity_sidecar_fields = entity_sidecar_fields(Some("device.hostname,src_endpoint.ip,user.name"));
            writer.write(&rows).unwrap();
            let part = writer.finish().unwrap();
            let entity_cache = crate::part_query::entity_cache::EntityCache::default();
            let collect = |hints: &[CandidateHint], mode: u8| {
                let mut ids = Vec::new();
                for file in &part.record.files.data {
                    let evidence = std::fs::read(part.dir.join(&file.entity_blooms.as_ref().unwrap().name)).unwrap();
                    let blooms: EntityBlooms = serde_json::from_slice(&evidence).unwrap();
                    let signed = file.entity_locators.as_ref().unwrap();
                    let locator = entity_cache.get(&part.dir.join(&signed.name), &signed.sha256, file.row_groups as usize, file.rows).unwrap();
                    if mode == 2 {
                        for (group_index, group) in locator.groups.iter().enumerate() {
                            let expected_mask = crate::parts::entity_locators::EntityLocators::row_mask(group, hints);
                            let mut reader = parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder::try_new(File::open(part.dir.join(&file.name)).unwrap()).unwrap().with_row_groups(vec![group_index]).with_batch_size(65_536).build().unwrap();
                            let actual_rows = reader.next().unwrap().unwrap();
                            assert!(reader.next().is_none());
                            for (row, uid) in uid_strings(&actual_rows).unwrap().iter().enumerate() {
                                let index: usize = uid.unwrap().strip_prefix("u-").unwrap().parse().unwrap();
                                let exact = hints.iter().all(|hint| match hint {
                                    CandidateHint::Entity { source_path, value } => {
                                        let actual = source_path.split('.').fold(Some(&events[index]), |value, key| value.and_then(|value| value.get(key))).and_then(|value| value.as_str());
                                        actual.is_some_and(|actual| if crate::part_query::prune::INGEST_LOWERCASED_BLOOM_PATHS.contains(&source_path.as_str()) { actual == value.to_ascii_lowercase() } else { actual.eq_ignore_ascii_case(value) })
                                    }
                                    _ => unreachable!(),
                                });
                                assert_eq!(expected_mask[row], exact, "exact row offset for group {group_index}, row {row}");
                            }
                        }
                    }
                    let mask = match mode {
                        1 => entity_summary_mask(Some(&blooms), file.row_groups as usize, hints).unwrap(),
                        2 => locator.group_mask(hints),
                        _ => vec![true; file.row_groups as usize],
                    };
                    let groups = mask.iter().enumerate().filter_map(|(index, keep)| keep.then_some(index)).collect::<Vec<_>>();
                    if groups.is_empty() { continue; }
                    let reader = parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder::try_new(File::open(part.dir.join(&file.name)).unwrap()).unwrap().with_row_groups(groups).build().unwrap();
                    for rows in reader {
                        let rows = rows.unwrap();
                        for uid in uid_strings(&rows).unwrap().into_iter().flatten() {
                            let index: usize = uid.strip_prefix("u-").unwrap().parse().unwrap();
                            let event = &events[index];
                            if hints.iter().all(|hint| match hint {
                                CandidateHint::Entity { source_path, value } => {
                                    let actual = source_path.split('.').fold(Some(event), |value, key| value.and_then(|value| value.get(key))).and_then(|value| value.as_str());
                                    actual.is_some_and(|actual| if crate::part_query::prune::INGEST_LOWERCASED_BLOOM_PATHS.contains(&source_path.as_str()) { actual == value.to_ascii_lowercase() } else { actual.eq_ignore_ascii_case(value) })
                                }
                                _ => unreachable!(),
                            }) { ids.push(uid.to_owned()); }
                        }
                    }
                }
                ids
            };
            let mut seed = 3077_u64;
            for trial in 0..120 {
                seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
                let host = (seed >> 32) % 8;
                let candidates = [
                    CandidateHint::Entity { source_path: "device.hostname".into(), value: format!("WS-SUPPORT-{host}.CORP.LOCAL") },
                    CandidateHint::Entity { source_path: "src_endpoint.ip".into(), value: format!("10.0.{host}.{}", seed % 5) },
                    CandidateHint::Entity { source_path: "user.name".into(), value: if seed % 2 == 0 { "ALICE" } else { "Bob" }.into() },
                ];
                let hints = &candidates[..1 + trial % 3];
                let expected = collect(hints, 0);
                let actual = collect(hints, 1);
                let exact = collect(hints, 2);
                assert_eq!(exact, expected, "exact locators same rows/count for trial {trial}");
                assert_eq!(actual.len(), expected.len(), "exact count for trial {trial}");
                assert_eq!(actual, expected, "same rows for trial {trial}");
            }
            let absent = [CandidateHint::Entity { source_path: "device.hostname".into(), value: "absent.corp.local".into() }];
            assert!(part.record.files.data.iter().all(|file| {
                let blooms: EntityBlooms = serde_json::from_slice(&std::fs::read(part.dir.join(&file.entity_blooms.as_ref().unwrap().name)).unwrap()).unwrap();
                !entity_summary_mask(Some(&blooms), file.row_groups as usize, &absent).unwrap().iter().any(|keep| *keep)
            }), "absent host skips every data file before download");
            eprintln!("layout fixture group_rows={group_rows} split_bytes={file_bytes} files={} groups={} bytes={}",
                part.record.files.data.len(), part.record.files.row_groups(),
                part.record.files.data.iter().map(|file| file.bytes).sum::<u64>());
        }
        assert_eq!(entity_sidecar_fields(Some("unknown,device.hostname,device.hostname")), vec!["device.hostname"]);
    }

    #[test]
    fn entity_sidecar_defaults_include_hash_pivots() {
        let fields = entity_sidecar_fields(None);
        for path in ["file_hash", "process_hash", "file.hashes.value",
            "process.file.hashes.value", "actor.process.file.hashes.value"] {
            assert!(fields.iter().any(|field| field == path));
        }
        assert!(!fields.iter().any(|field| field == crate::parts::format::UID_PATH));
        assert!(entity_sidecar_fields(Some("unknown,file.hashes,file_hash,file_hash")) == vec!["file_hash"]);
    }

    #[test]
    fn hash_sidecars_include_scalars_and_exclude_repeated_leaves() {
        use crate::part_query::prune::EntityBlooms;
        let events = vec![serde_json::json!({
            "time": chrono::DateTime::from_timestamp(i64::from(HOUR) * 3600, 0).unwrap().to_rfc3339(),
            "metadata": {"uid": "hash-row", "log_source": "s"},
            "file_hash": "abcd", "process_hash": "ef01",
            "file": {"hashes": {"value": "abcd"}},
            "process": {"file": {"hashes": [{"value": "ef01"}]}}
        })];
        let refs = events.iter().collect::<Vec<_>>();
        let rows = decode(Arc::new(infer_schema(&refs).unwrap()), &refs).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let mut writer = PartWriter::create(dir.path(), draft(rows.schema(), Level::L0, sources()), PartialSource::FromRows, 1, 1).unwrap();
        writer.uid_sidecar_write = true;
        writer.write(&rows).unwrap();
        let part = writer.finish().unwrap();
        let file = &part.record.files.data[0];
        let blooms: EntityBlooms = serde_json::from_slice(&std::fs::read(part.dir.join(&file.entity_blooms.as_ref().unwrap().name)).unwrap()).unwrap();
        for path in ["file_hash", "process_hash", "file.hashes.value"] {
            assert!(blooms.get(path).is_some_and(|groups| groups.iter().all(Option::is_some)));
        }
        assert!(!blooms.contains_key("process.file.hashes.value"));
    }

    #[test]
    fn uid_point_fixture_reads_one_part_and_one_group() {
        let dir = tempfile::tempdir().unwrap();
        let settings = ParquetSettings { zstd_level: 3, row_group_rows: 100, max_file_bytes: MAX_OBJECT_BYTES / 2 };
        let mut parts = Vec::new();
        for index in 0..4 {
            let rows = batch(1_000, index * 1_000);
            let mut writer = PartWriter::create_with(dir.path(), draft(rows.schema(), Level::L0, sources()), PartialSource::FromRows, index as i64 + 1, 3_000, settings.clone()).unwrap();
            writer.uid_sidecar_write = true;
            writer.write(&rows).unwrap();
            parts.push(writer.finish().unwrap());
        }
        let target = "u-001500";
        let hints = [crate::planner::CandidateHint::Entity { source_path: "metadata.uid".into(), value: target.into() }];
        let (mut fetched_parts, mut read_groups, mut matches) = (0, 0, 0);
        for part in &parts {
            for file in &part.record.files.data {
                let blooms: Vec<Option<String>> = serde_json::from_slice(&std::fs::read(part.dir.join(&file.uid_blooms.as_ref().unwrap().name)).unwrap()).unwrap();
                let mask = crate::part_query::prune::uid_summary_mask(Some(&blooms), file.row_groups as usize, &hints).unwrap();
                // NAN-4292: the reader's positioned probe answers the same
                // over the writer's sidecar.
                let uid = file.uid_blooms.as_ref().unwrap();
                let probed = crate::part_query::uid_probe::UidLayouts::default().mask(&part.dir.join(&uid.name), &uid.sha256, file.row_groups as usize, &hints);
                assert_eq!(probed.as_ref(), Some(&mask));
                let groups = mask.iter().enumerate().filter_map(|(index, keep)| keep.then_some(index)).collect::<Vec<_>>();
                if groups.is_empty() { continue; }
                fetched_parts += 1;
                read_groups += groups.len();
                let reader = parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder::try_new(File::open(part.dir.join(&file.name)).unwrap()).unwrap().with_row_groups(groups).build().unwrap();
                for rows in reader {
                    matches += uid_strings(&rows.unwrap()).unwrap().iter().filter(|uid| *uid == Some(target)).count();
                }
            }
        }
        assert_eq!((fetched_parts, read_groups, matches), (1, 1, 1));
        assert_eq!(parts.iter().map(|part| part.record.files.row_groups()).sum::<u32>(), 40, "the unpruned fixture has four parts and forty groups");
    }

    #[tokio::test]
    async fn parts_split_into_files_on_row_group_boundaries_and_merge_back() {
        let dir = tempfile::tempdir().unwrap();
        let rows = batch(3_000, 0);
        let settings = ParquetSettings { zstd_level: 3, row_group_rows: 1_000, max_file_bytes: 1 };
        let mut writer =
            PartWriter::create_with(dir.path(), draft(rows.schema(), Level::L0, sources()), PartialSource::FromRows, 1, 3_000, settings)
                .unwrap();
        writer.uid_sidecar_write = true;
        // Uneven batches: boundaries must still land every 1,000 rows.
        writer.write(&rows.slice(0, 700)).unwrap();
        writer.write(&rows.slice(700, 1_800)).unwrap();
        writer.write(&rows.slice(2_500, 500)).unwrap();
        let finished = writer.finish().unwrap();
        let data = &finished.record.files.data;
        assert_eq!(data.len(), 3, "one file per row group at a 1-byte cap");
        assert!(data.iter().all(|f| f.rows == 1_000 && f.row_groups == 1));
        assert!(data.windows(2).all(|w| w[0].max_time_us <= w[1].min_time_us));
        assert_eq!(local_data_files(&finished.dir).unwrap().len(), 3);
        let hint = [crate::planner::CandidateHint::Entity { source_path: "metadata.uid".into(), value: "u-001500".into() }];
        let masks = data.iter().map(|file| crate::part_query::prune::uid_summary_mask(Some(&serde_json::from_slice::<Vec<Option<String>>>(&std::fs::read(finished.dir.join(&file.uid_blooms.as_ref().unwrap().name)).unwrap()).unwrap()), file.row_groups as usize, &hint).unwrap()).collect::<Vec<_>>();
        assert_eq!(masks, vec![vec![false], vec![true], vec![false]], "UID lookup keeps one file and one row group before data downloads");

        // A plain single-file part of the same rows has the same Merkle root.
        let mut single = PartWriter::create(dir.path(), draft(rows.schema(), Level::L0, sources()), PartialSource::FromRows, 2, 3_000).unwrap();
        single.write(&rows).unwrap();
        let single = single.finish().unwrap();
        assert_eq!(single.record.files.data.len(), 1);
        assert_eq!(single.record.merkle_root, finished.record.merkle_root);

        // Publish (owner-signed), then merge the multi-file part with another.
        let store = crate::parts::part_log::LocalObjectStore::new(dir.path().join("store")).unwrap();
        let signer = signer(1);
        let refs = publish_parts(&store, &signer, &signer.trusted(), &[finished]).await.unwrap();
        assert_eq!(refs[0].data_files, 3);
        let more = batch(500, 3_000);
        let mut other = PartWriter::create(dir.path(), draft(more.schema(), Level::L0, sources()), PartialSource::FromRows, 3, 500).unwrap();
        other.write(&more).unwrap();
        let other = other.finish().unwrap();
        let other_ref = publish_parts(&store, &signer, &signer.trusted(), &[other]).await.unwrap().remove(0);
        let inputs = vec![
            MergeInput { part: refs[0].clone(), dir: dir.path().join(refs[0].part_id.as_str()) },
            MergeInput { part: other_ref.clone(), dir: dir.path().join(other_ref.part_id.as_str()) },
        ];
        let schema = more.schema();
        let merged = merge_parts(
            dir.path(), TENANT, Level::Minute, HOUR, &inputs, schema.clone(),
            &crate::parts::format::schema_fingerprint(&schema).unwrap(), crate::parts::provenance::tests::SIGNER, "test", 4,
        )
        .unwrap();
        assert_eq!(merged.finished.record.rows, 3_500);
        assert_eq!(merged.duplicates_dropped, 0);
        // Same rows written directly give the same root: order/split independence.
        let all = sort_by_time_uid(&arrow_select::concat::concat_batches(&schema, &[crate::part_ingest::schema::align(rows, &schema).unwrap(), more]).unwrap()).unwrap();
        let mut direct = PartWriter::create(dir.path(), draft(schema, Level::L0, sources()), PartialSource::FromRows, 5, 3_500).unwrap();
        direct.write(&all).unwrap();
        assert_eq!(direct.finish().unwrap().record.merkle_root, merged.finished.record.merkle_root);
    }

    #[test]
    fn many_overlapping_inputs_merge_through_intermediates_with_the_same_root() {
        use crate::part_ingest::merge::{max_overlap, MAX_OPEN_INPUTS};
        let dir = tempfile::tempdir().unwrap();
        // 20 parts whose times all interleave across the same range.
        let all = batch(2_000, 0);
        let schema = all.schema();
        let mut inputs = Vec::new();
        for k in 0..20 {
            let indices = arrow_array::UInt32Array::from_iter_values((k..2_000).step_by(20).map(|i| i as u32));
            let columns = all
                .columns()
                .iter()
                .map(|c| arrow_select::take::take(c.as_ref(), &indices, None).unwrap())
                .collect::<Vec<_>>();
            let part_rows = RecordBatch::try_new(schema.clone(), columns).unwrap();
            let mut writer =
                PartWriter::create(dir.path(), draft(schema.clone(), Level::L0, sources()), PartialSource::FromRows, 10 + k as i64, 100).unwrap();
            writer.write(&part_rows).unwrap();
            let finished = writer.finish().unwrap();
            inputs.push(MergeInput { part: PartRef::from_record(&finished.record, &"1".repeat(64), true), dir: finished.dir });
        }
        assert!(max_overlap(&inputs) > MAX_OPEN_INPUTS);
        let merged = merge_parts(
            dir.path(), TENANT, Level::Minute, HOUR, &inputs, schema.clone(),
            &crate::parts::format::schema_fingerprint(&schema).unwrap(), crate::parts::provenance::tests::SIGNER, "test", 99,
        )
        .unwrap();
        let record = &merged.finished.record;
        assert_eq!(record.rows, 2_000);
        // The record names the 20 original inputs, not the intermediates.
        let PartInputs::Parts { parts } = &record.inputs else { panic!() };
        assert_eq!(parts.len(), 20);
        let mut direct = PartWriter::create(dir.path(), draft(schema, Level::L0, sources()), PartialSource::FromRows, 100, 2_000).unwrap();
        direct.write(&all).unwrap();
        assert_eq!(direct.finish().unwrap().record.merkle_root, record.merkle_root);
        // No scratch intermediates are left behind.
        assert!(std::fs::read_dir(dir.path()).unwrap().all(|e| !e.unwrap().file_name().to_string_lossy().starts_with(".merge-")));
    }

    /// NAN-3772 local fixture estimate: one count rewrite of real tenant-a rows
    /// (an hour part from the NAN-3715 layout capture) through the full
    /// production path (h layout + provenance, then a single-input count
    /// rewrite under the backfill pace at full and floor share), and the
    /// seven-day tenant-a window (213 parts, ~154M rows) extrapolated from it.
    /// NAN3772_HOUR_DIR=<dir holding one hour part> [NAN3772_ROWS=200000]
    /// cargo test --release -p nanosiem-lake-worker --lib count_rewrite_cost -- --ignored --nocapture
    #[test]
    #[ignore]
    fn count_rewrite_cost() {
        use crate::parts::part_log::LocalObjectStore;
        use crate::parts::provenance::{InputPart, LocalPartSigner};
        use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;
        let source = PathBuf::from(std::env::var("NAN3772_HOUR_DIR").expect("NAN3772_HOUR_DIR"));
        let limit: usize = std::env::var("NAN3772_ROWS").ok().and_then(|v| v.parse().ok()).unwrap_or(200_000);
        let cpu_seconds = || {
            let stat = std::fs::read_to_string("/proc/self/stat").unwrap();
            let fields = stat.rsplit_once(") ").unwrap().1.split(' ').map(str::to_owned).collect::<Vec<_>>();
            (fields[11].parse::<f64>().unwrap() + fields[12].parse::<f64>().unwrap()) / 100.0
        };
        let mut files = std::fs::read_dir(&source).unwrap().map(|e| e.unwrap().path())
            .filter(|p| p.extension().is_some_and(|e| e == "parquet")).collect::<Vec<_>>();
        files.sort();
        // Spread the sample over every family file of the hour.
        let per_file = limit.div_ceil(files.len());
        let mut batches = Vec::new();
        for file in &files {
            let mut taken = 0;
            for batch in ParquetRecordBatchReaderBuilder::try_new(File::open(file).unwrap()).unwrap().with_batch_size(8_192).build().unwrap() {
                let batch = batch.unwrap();
                let take = batch.num_rows().min(per_file - taken);
                batches.push(batch.slice(0, take));
                taken += take;
                if taken >= per_file { break; }
            }
        }
        let schema = Arc::new(arrow_schema::Schema::try_merge(batches.iter().map(|b| b.schema().as_ref().clone()
            .with_metadata(Default::default()))).unwrap());
        let batches = batches.into_iter().map(|b| super::super::schema::align(b, &schema).unwrap()).collect::<Vec<_>>();
        let all = sort_by_time_uid(&arrow_select::concat::concat_batches(&schema, &batches).unwrap()).unwrap();
        drop(batches);
        let rows = all.num_rows() as u64;
        let fingerprint = crate::parts::format::schema_fingerprint(&schema).unwrap();
        let first_us = crate::generation::event_time_us_from_array(all.column_by_name("time").unwrap().as_ref(), 0).unwrap();
        let hour = first_us.div_euclid(crate::parts::HOUR_US) as i32;
        let dir = tempfile::tempdir().unwrap();
        let draft = PartDraft {
            tenant_id: TENANT.into(), signer_key_id: crate::parts::provenance::tests::SIGNER.into(), level: Level::Minute, event_hour: hour,
            schema: schema.clone(), schema_fingerprint: fingerprint.clone(),
            inputs: PartInputs::Parts { parts: vec![InputPart { part_id: crate::parts::format::PartId::new(1).unwrap(), level: Level::L0,
                provenance_sha256: "0".repeat(64), rows, merkle_root: "0".repeat(64) }] },
            admission: None, rows_in: rows, duplicates_dropped: 0, window: DedupWindow::Exact, build: "test".into(),
        };
        let mut writer = PartWriter::create(dir.path(), draft, PartialSource::FromRows, 2, rows).unwrap();
        writer.write(&all).unwrap();
        drop(all);
        let minute = writer.finish().unwrap();
        let input = MergeInput { part: PartRef::from_record(&minute.record, &"0".repeat(64), true), dir: minute.dir.clone() };
        // The legacy hour as production wrote it, signed (so the rewrite
        // expands its family files like a live part).
        let started = std::time::Instant::now();
        let hour_part = merge_parts(dir.path(), TENANT, Level::Hour, hour, &[input], schema.clone(), &fingerprint,
            crate::parts::provenance::tests::SIGNER, "test", 3).unwrap().finished;
        eprintln!("rows={rows} files={} h-merge wall {:.2}s", hour_part.record.files.data.len(), started.elapsed().as_secs_f64());
        let store: &'static LocalObjectStore = Box::leak(Box::new(LocalObjectStore::new(dir.path().join("store")).unwrap()));
        let signer = LocalPartSigner::new(crate::parts::provenance::tests::SIGNER, ed25519_dalek::SigningKey::from_bytes(&[7; 32])).unwrap();
        let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        let old = runtime.block_on(publish_compacted_parts(store, &signer, &signer.trusted(), std::slice::from_ref(&hour_part))).unwrap().remove(0);
        let _share = super::super::merge_quota::lock_backfill_share_for_test();
        ENTITY_COUNT_WRITE_OVERRIDE.with(|value| value.set(Some(true)));
        let mut full_wall = 0.0;
        for (round, share) in [super::super::merge_quota::BACKFILL_SHARE_ONE_CORE_PERMILLE, super::super::merge_quota::BACKFILL_SHARE_ONE_CORE_PERMILLE, 250]
            .into_iter().enumerate() {
            super::super::merge_quota::set_backfill_share_for_test(share);
            let (cpu, started) = (cpu_seconds(), std::time::Instant::now());
            let merged = super::super::merge_quota::with_count_backfill(true, || merge_parts(dir.path(), TENANT, Level::Hour, hour,
                &[MergeInput { part: old.clone(), dir: hour_part.dir.clone() }], schema.clone(), &fingerprint,
                crate::parts::provenance::tests::SIGNER, "test", 10 + round as i64)).unwrap().finished;
            let (wall, cpu) = (started.elapsed().as_secs_f64(), cpu_seconds() - cpu);
            assert_eq!(merged.record.rows, rows);
            if round == 1 { full_wall = wall; }
            eprintln!("count rewrite share={share}‰ wall {wall:.2}s cpu {cpu:.2}s = {:.1} µs/row wall, {:.1} µs/row cpu",
                wall * 1e6 / rows as f64, cpu * 1e6 / rows as f64);
            std::fs::remove_dir_all(&merged.dir).unwrap();
        }
        ENTITY_COUNT_WRITE_OVERRIDE.with(|value| value.set(None));
        super::super::merge_quota::set_backfill_share_for_test(250);
        let window_rows = 154_000_000.0;
        eprintln!("7d tenant-a window (213 parts, ~154M rows) at full share, one rewrite at a time: {:.1} h of rewrite wall (this host)",
            full_wall / rows as f64 * window_rows / 3600.0);
    }

    /// NAN-3801 acceptance parity: for a part written WITHOUT counts, the
    /// counts-only record equals, row for row, the count namespace a full
    /// count rewrite (merge_parts of that part with counts on) produces,
    /// with the same footer coverage hint.
    #[test]
    fn count_record_matches_a_full_count_rewrite() {
        use super::super::count_record::{count_local_files, tests as fixture};
        struct Reset;
        impl Drop for Reset { fn drop(&mut self) { ENTITY_COUNT_WRITE_OVERRIDE.with(|value| value.set(None)); } }
        let _reset = Reset;
        let dir = tempfile::tempdir().unwrap();
        let rows = fixture::events(20_000);
        ENTITY_COUNT_WRITE_OVERRIDE.with(|value| value.set(Some(false)));
        let (old, old_dir, schema) = fixture::write_part(&dir.path().join("old"), &rows);
        let entity = crate::parts::format::PARTIAL_ENTITY_RANGES_FILE;
        let count_rows_of = |path: &std::path::Path| fixture::read_rows(path).into_iter()
            .filter(|row| crate::parts::entity_counts::is_count_path(&row.key.0)).collect::<Vec<_>>();
        assert!(count_rows_of(&old_dir.join(entity)).is_empty(), "fixture: the old part has no counts");

        ENTITY_COUNT_WRITE_OVERRIDE.with(|value| value.set(Some(true)));
        let rewrite_dir = dir.path().join("rewrite");
        std::fs::create_dir_all(&rewrite_dir).unwrap();
        let rewritten = merge_parts(&rewrite_dir, TENANT, Level::Hour, fixture::HOUR,
            &[MergeInput { part: old.clone(), dir: old_dir.clone() }], schema.clone(),
            &crate::parts::format::schema_fingerprint(&schema).unwrap(), crate::parts::provenance::tests::SIGNER, "test", 1_000)
            .unwrap().finished;
        assert_eq!(rewritten.record.rows, old.rows);
        let full = count_rows_of(&rewritten.dir.join(entity));
        assert!(full.len() > 100, "fixture: the full rewrite counts several kinds");

        let record = count_local_files(&local_data_files(&old_dir).unwrap(), &dir.path().join("counts"), old.rows).unwrap();
        assert_eq!(record.rows, old.rows);
        let only = fixture::read_rows(&record.path);
        assert!(only.iter().all(|row| crate::parts::entity_counts::is_count_path(&row.key.0)), "a count file holds counts only");
        assert_eq!(only, full, "counts-only rows equal the full rewrite's count rows");
        assert_eq!(record.count_rows, full.len() as u64);
        assert!(fixture::footer_hint(&record.path).is_some());
        assert_eq!(fixture::footer_hint(&record.path), fixture::footer_hint(&rewritten.dir.join(entity)));
        assert_eq!(file_digest(&record.path).unwrap(), (record.bytes, record.sha256.clone()));
    }

    /// NAN-3801 fixture: an hour part without counts, published to `store`,
    /// split into several data files with (or without) signed range manifests.
    async fn counts_only_fixture(store: &crate::parts::part_log::LocalObjectStore,
        signer: &crate::parts::provenance::LocalPartSigner, dir: &std::path::Path, rows: usize, ranges: bool, now_ms: i64,
    ) -> (PartRef, FinishedPart, SchemaRef) {
        let settings = ParquetSettings { zstd_level: 3, row_group_rows: 2_000, max_file_bytes: 1 };
        counts_only_fixture_with(store, signer, dir, &super::super::count_record::tests::events(rows), ranges, now_ms, settings).await
    }

    async fn counts_only_fixture_with(store: &dyn ObjectStore,
        signer: &crate::parts::provenance::LocalPartSigner, dir: &std::path::Path, events: &[serde_json::Value], ranges: bool, now_ms: i64,
        settings: ParquetSettings,
    ) -> (PartRef, FinishedPart, SchemaRef) {
        use super::super::count_record::tests as fixture;
        let refs = events.iter().collect::<Vec<_>>();
        let schema = std::sync::Arc::new(super::super::schema::infer_schema(&refs).unwrap());
        let batch = sort_by_time_uid(&super::super::schema::decode(schema.clone(), &refs).unwrap()).unwrap();
        let inputs = PartInputs::Parts { parts: vec![crate::parts::provenance::InputPart {
            part_id: PartId::new(1).unwrap(), level: Level::Minute, provenance_sha256: "0".repeat(64),
            rows: batch.num_rows() as u64, merkle_root: "0".repeat(64) }] };
        let mut draft = draft(schema.clone(), Level::Hour, inputs);
        draft.event_hour = fixture::HOUR;
        draft.rows_in = batch.num_rows() as u64;
        std::fs::create_dir_all(dir).unwrap();
        let mut writer = PartWriter::create_with(dir, draft, PartialSource::FromRows, now_ms, batch.num_rows() as u64, settings).unwrap();
        writer.parquet_range_write = ranges;
        writer.write(&batch).unwrap();
        let finished = writer.finish().unwrap();
        let part = publish_compacted_parts(store, signer, &signer.trusted(), std::slice::from_ref(&finished)).await.unwrap().remove(0);
        (part, finished, schema)
    }

    /// A signer for an owner release without the count route.
    struct NoCountRoute(crate::parts::provenance::LocalPartSigner);
    #[async_trait::async_trait]
    impl PartSigner for NoCountRoute {
        fn key_id(&self) -> &str { self.0.key_id() }
        async fn sign(&self, tenant_id: &str, records: &[ProvenanceRecord]) -> Result<Vec<crate::parts::provenance::Ed25519Signature>> {
            self.0.sign(tenant_id, records).await
        }
    }

    #[tokio::test]
    async fn counts_only_backfill_publishes_a_signed_record_from_verified_ranges() {
        use super::super::count_record::{backfill_counts, count_local_files, is_unsupported, stored_count_record, tests as fixture};
        use crate::parts::count_record::COUNT_RECORD_FILE;
        use crate::parts::part_log::LocalObjectStore;
        struct Restore(Option<bool>);
        impl Drop for Restore {
            fn drop(&mut self) { ENTITY_COUNT_WRITE_OVERRIDE.with(|value| value.set(self.0)); }
        }
        let _restore = Restore(ENTITY_COUNT_WRITE_OVERRIDE.with(|value| value.replace(Some(false))));
        let dir = tempfile::tempdir().unwrap();
        let store = LocalObjectStore::new(dir.path().join("store")).unwrap();
        let signer = crate::parts::provenance::LocalPartSigner::new(crate::parts::provenance::tests::SIGNER,
            ed25519_dalek::SigningKey::from_bytes(&[7; 32])).unwrap();
        let trusted = signer.trusted();
        let rows = 60_000;
        for ranges in [true, false] {
            let (part, finished, _) = counts_only_fixture(&store, &signer, &dir.path().join(format!("w{ranges}")), rows, ranges,
                1_800_000_000_000 + i64::from(ranges)).await;
            assert!(finished.record.files.data.len() > 1, "fixture: several data files");
            let keys = PartKeys::new(TENANT, part.level, part.event_hour, &part.part_id).unwrap();
            let started = std::time::Instant::now();
            let done = backfill_counts(&store, &signer, &trusted, TENANT, &dir.path().join("work"), &part, &finished.record, 9).await.unwrap();
            let elapsed = started.elapsed();
            assert!(!done.existing);
            if ranges {
                assert_eq!(done.fetched.whole_files, 0);
                assert!(done.fetched.bytes < part.data_bytes, "projected read: {} of {} bytes", done.fetched.bytes, part.data_bytes);
            } else {
                assert_eq!(done.fetched.whole_files, finished.record.files.data.len());
            }
            eprintln!("counts-only (ranges={ranges}): {rows} rows in {elapsed:?} ({:.0} rows/s), fetched {} of {} data bytes",
                rows as f64 / elapsed.as_secs_f64(), done.fetched.bytes, part.data_bytes);
            // The stored record verifies, binds the part, and names a stored
            // count file whose rows equal a local count of the same part
            // (which `count_record_matches_a_full_count_rewrite` pins to the
            // full rewrite's count rows).
            let stored = stored_count_record(&store, &keys, &part, TENANT, &trusted).await.unwrap().unwrap();
            assert_eq!(stored, done.record);
            let record = &stored.record;
            assert_eq!((record.rows, record.provenance_sha256.as_str()), (part.rows, part.provenance_sha256.as_str()));
            let count_file = dir.path().join(format!("count-{ranges}.parquet"));
            std::fs::write(&count_file, store.get(&keys.file(&record.file.name)).await.unwrap().unwrap()).unwrap();
            assert_eq!(file_digest(&count_file).unwrap(), (record.file.bytes, record.file.sha256.clone()));
            let local = count_local_files(&local_data_files(&finished.dir).unwrap(), &dir.path().join(format!("local-{ranges}")), part.rows).unwrap();
            assert_eq!(fixture::read_rows(&count_file), fixture::read_rows(&local.path));
            assert_eq!(record.count_rows, local.count_rows);
            assert_eq!(record.coverage_mask, local.coverage_mask);
            // Idempotent: the stored record is reused, nothing is rewritten.
            let again = backfill_counts(&store, &signer, &trusted, TENANT, &dir.path().join("work"), &part, &finished.record, 10).await.unwrap();
            assert!(again.existing);
            assert_eq!(again.record, stored);
            // Another tenant's reader refuses the record.
            assert!(stored_count_record(&store, &keys, &part, "00000000-0000-4000-8000-000000000001", &trusted).await.is_err());
        }

        // An owner without the count route: a typed refusal, no record.
        let (part, finished, _) = counts_only_fixture(&store, &signer, &dir.path().join("w-unsupported"), 5_000, true, 1_800_000_000_100).await;
        let keys = PartKeys::new(TENANT, part.level, part.event_hour, &part.part_id).unwrap();
        let error = backfill_counts(&store, &NoCountRoute(crate::parts::provenance::LocalPartSigner::new(crate::parts::provenance::tests::SIGNER,
            ed25519_dalek::SigningKey::from_bytes(&[7; 32])).unwrap()), &trusted, TENANT, &dir.path().join("work"), &part, &finished.record, 11)
            .await.unwrap_err();
        assert!(is_unsupported(&error), "{error:#}");
        assert!(store.get(&keys.file(COUNT_RECORD_FILE)).await.unwrap().is_none());

        // A stored count column chunk that differs from its signed range is refused.
        let (part, finished, _) = counts_only_fixture(&store, &signer, &dir.path().join("w-corrupt"), 5_000, true, 1_800_000_000_200).await;
        let keys = PartKeys::new(TENANT, part.level, part.event_hour, &part.part_id).unwrap();
        let data_key = keys.file(&finished.record.files.data[0].name);
        let manifest = finished.record.files.data[0].parquet_ranges.as_ref().unwrap();
        let ranges: Vec<crate::parts::parquet_ranges::ParquetRangeDigest> =
            serde_json::from_slice(&std::fs::read(finished.dir.join(&manifest.name)).unwrap()).unwrap();
        let time = ranges.iter().find(|range| range.column.as_deref() == Some("time")).unwrap();
        let path = store.path(&data_key).unwrap();
        let mut bytes = std::fs::read(&path).unwrap();
        bytes[(time.offset + time.bytes / 2) as usize] ^= 0xff;
        std::fs::write(&path, bytes).unwrap();
        let error = backfill_counts(&store, &signer, &trusted, TENANT, &dir.path().join("work"), &part, &finished.record, 12).await.unwrap_err();
        assert!(format!("{error:#}").contains("does not match its signed digest"), "{error:#}");
        assert!(store.get(&keys.file(COUNT_RECORD_FILE)).await.unwrap().is_none());
    }

    /// NAN-3801 r52 tenant-a: every counts-only rewrite of a real hour failed
    /// "export object range exceeds budget": its count column chunks are
    /// larger than the S3 store's 4 MiB ranged GET. A part whose count
    /// column chunk is over the cap now backfills through capped GETs, with
    /// the same counts as a local scan, and leaves no work files behind.
    #[tokio::test]
    async fn counts_only_backfill_streams_column_chunks_over_the_range_cap() {
        use super::super::count_record::{backfill_counts, count_leaves, count_local_files, tests as fixture};
        use crate::parts::part_log::{LocalObjectStore, MAX_RANGE_GET_BYTES};
        use sha2::Digest;
        struct Restore(Option<bool>);
        impl Drop for Restore {
            fn drop(&mut self) { ENTITY_COUNT_WRITE_OVERRIDE.with(|value| value.set(self.0)); }
        }
        let _restore = Restore(ENTITY_COUNT_WRITE_OVERRIDE.with(|value| value.replace(Some(false))));
        let dir = tempfile::tempdir().unwrap();
        let local = LocalObjectStore::new(dir.path().join("store")).unwrap();
        let store = fixture::CappedRanges::new(&local);
        let signer = crate::parts::provenance::LocalPartSigner::new(crate::parts::provenance::tests::SIGNER,
            ed25519_dalek::SigningKey::from_bytes(&[7; 32])).unwrap();
        let trusted = signer.trusted();
        // One 65,536-row group whose user.name values are unique 192-hex-char
        // strings: a ~6 MiB compressed column chunk.
        let rows = crate::parts::format::ROW_GROUP_ROWS;
        let mut events = fixture::events(rows);
        for (i, event) in events.iter_mut().enumerate() {
            let a = hex::encode(sha2::Sha256::digest(i.to_le_bytes()));
            let b = hex::encode(sha2::Sha256::digest((i + rows).to_le_bytes()));
            let c = hex::encode(sha2::Sha256::digest((i + 2 * rows).to_le_bytes()));
            event["user"]["name"] = serde_json::json!(format!("{a}{b}{c}"));
        }
        let settings = ParquetSettings { zstd_level: 1, row_group_rows: rows, ..ParquetSettings::for_level(Level::Hour) };
        let (part, finished, _) = counts_only_fixture_with(&store, &signer, &dir.path().join("w"), &events, true, 1_800_000_000_000, settings).await;
        let manifest = finished.record.files.data[0].parquet_ranges.as_ref().unwrap();
        let ranges: Vec<crate::parts::parquet_ranges::ParquetRangeDigest> =
            serde_json::from_slice(&std::fs::read(finished.dir.join(&manifest.name)).unwrap()).unwrap();
        let largest = ranges.iter().filter(|range| range.column.as_deref().is_some_and(|column| count_leaves().contains(&column)))
            .map(|range| range.bytes).max().unwrap();
        assert!(largest > MAX_RANGE_GET_BYTES, "fixture: a count column chunk over the cap ({largest} bytes)");
        let work = dir.path().join("work");
        let done = backfill_counts(&store, &signer, &trusted, TENANT, &work, &part, &finished.record, 9).await.unwrap();
        assert!(!done.existing);
        assert_eq!(done.fetched.whole_files, 0);
        assert!(store.largest.load(std::sync::atomic::Ordering::SeqCst) <= MAX_RANGE_GET_BYTES, "no GET over the store cap");
        let keys = PartKeys::new(TENANT, part.level, part.event_hour, &part.part_id).unwrap();
        let count_file = dir.path().join("count.parquet");
        std::fs::write(&count_file, local.get(&keys.file(&done.record.record.file.name)).await.unwrap().unwrap()).unwrap();
        let plain = count_local_files(&local_data_files(&finished.dir).unwrap(), &dir.path().join("plain"), part.rows).unwrap();
        assert_eq!(fixture::read_rows(&count_file), fixture::read_rows(&plain.path));
        assert_eq!(done.record.record.coverage_mask, plain.coverage_mask);
        assert_eq!(std::fs::read_dir(work.join("counts-only")).unwrap().count(), 0, "the per-part work directory is removed");
    }

    #[tokio::test]
    async fn coverage_probe_counts_only_then_reads_the_record_as_current() {
        use crate::parts::count_record::COUNT_RECORD_FILE;
        use crate::parts::part_log::LocalObjectStore;
        use crate::parts::provenance::LocalPartSigner;
        struct Restore(Option<bool>);
        impl Drop for Restore {
            fn drop(&mut self) { ENTITY_COUNT_WRITE_OVERRIDE.with(|value| value.set(self.0)); }
        }
        let _restore = Restore(ENTITY_COUNT_WRITE_OVERRIDE.with(|value| value.replace(Some(false))));
        let dir = tempfile::tempdir().unwrap();
        let store: &'static LocalObjectStore = Box::leak(Box::new(LocalObjectStore::new(dir.path().join("store")).unwrap()));
        let signer: &'static LocalPartSigner = Box::leak(Box::new(LocalPartSigner::new(crate::parts::provenance::tests::SIGNER,
            ed25519_dalek::SigningKey::from_bytes(&[7; 32])).unwrap()));
        let (part, _, _) = counts_only_fixture(store, signer, &dir.path().join("w"), 5_000, true, 1_800_000_000_000).await;
        let keys = PartKeys::new(TENANT, part.level, part.event_hour, &part.part_id).unwrap();
        let probe = |signer: Option<&'static dyn PartSigner>| super::super::ingest::probe_and_fetch_for_coverage(
            store, TENANT.to_owned(), signer_trusted(), dir.path().join("work"), part.clone(), true, signer, 5);
        fn signer_trusted() -> crate::parts::provenance::TenantKeySet {
            LocalPartSigner::new(crate::parts::provenance::tests::SIGNER, ed25519_dalek::SigningKey::from_bytes(&[7; 32])).unwrap().trusted()
        }
        // Without a count signer the probe asks for the full rewrite.
        assert!(probe(None).await.unwrap().is_some());
        // With one, it publishes the record and reports the part current.
        assert!(probe(Some(signer)).await.unwrap().is_none());
        assert!(store.get(&keys.file(COUNT_RECORD_FILE)).await.unwrap().is_some());
        // Later probes read the stored record as current, signer or not.
        assert!(probe(None).await.unwrap().is_none());
    }

    thread_local! {
        pub(super) static ENTITY_COUNT_WRITE_OVERRIDE: std::cell::Cell<Option<bool>> = const { std::cell::Cell::new(None) };
    }

    fn count_rows(part: &FinishedPart) -> Vec<super::super::partials::EntityRangeRow> {
        use super::super::partials::{EntityRangeRow, PartialRow};
        let path = part.dir.join(crate::parts::format::PARTIAL_ENTITY_RANGES_FILE);
        parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder::try_new(File::open(path).unwrap()).unwrap().build().unwrap()
            .flat_map(|batch| EntityRangeRow::from_batch(&batch.unwrap()).unwrap()).collect()
    }

    #[cfg(feature = "enterprise")]
    #[test]
    fn entity_counts_every_emitted_key_passes_existing_fences() {
        use crate::parts::entity_counts::Builder;
        use nanosiem_core::lake_part_writer_key::key_matches;
        // Assemble the deployed PG filename expression from the original SQL
        // and its existing sidecar splice, rather than maintaining a third fence.
        let original = include_str!("../../../migrations/postgres-enterprise/9003460_lake_part_writer_classes.sql");
        let branch = original.split("lake_part := regexp_match(lake_rest,\n                '^parts/").nth(1).unwrap();
        let branch = format!("'^parts/{}", branch.split("IF lake_part IS NULL").next().unwrap());
        let literals = regex::Regex::new("'([^']*)'").unwrap();
        let mut expression = literals.captures_iter(&branch).map(|c| c[1].to_string()).collect::<String>();
        let splice = include_str!("../../../migrations/postgres-enterprise/9010420_native_lake_part_sidecar_writer_authority.sql");
        let replacement = splice.split("$new$").nth(1).unwrap();
        let sidecars = literals.captures_iter(replacement).find(|c| c[1].starts_with("|(ranges|locators|entities|uids)")).unwrap();
        expression.truncate(expression.len() - 2); // replace the closing )$
        let base = expression.clone();
        let tenant = "6f1c1e8a-2b3c-4d5e-8f90-0123456789ab";
        expression.push_str(&sidecars[1]);
        let pg = regex::Regex::new(&expression).unwrap();
        // NAN-3801: the count files, through 9013585's splice of the same branch.
        let counts_splice = include_str!("../../../migrations/postgres-enterprise/9013585_lake_part_counts_v2_files.sql");
        let counts_branch = literals.captures_iter(counts_splice.split("$new$").nth(1).unwrap())
            .map(|c| c[1].to_string()).collect::<String>();
        assert!(counts_branch.starts_with(&sidecars[1][..sidecars[1].len() - 2]), "9013585 keeps the sidecar branch");
        let pg_counts = regex::Regex::new(&format!("{base}{counts_branch}")).unwrap();
        let counts_keys = PartKeys::new(tenant, Level::Hour, HOUR, &crate::parts::format::PartId::new(1_790_341_200_123).unwrap()).unwrap();
        for name in [crate::parts::count_record::COUNT_RECORD_FILE.to_string(),
            crate::parts::count_record::count_file_name(&"0123456789abcdef".repeat(4)).unwrap()] {
            let key = counts_keys.file(&name);
            assert!(key_matches(&key, "lake_part", "lake_part_file", tenant, i64::from(HOUR)), "Rust fence: {key}");
            let relative = key.strip_prefix(&format!("lake/parts/v1/tenant={tenant}/")).unwrap();
            assert!(pg_counts.is_match(relative), "PG fence: {key}");
            assert!(!pg.is_match(relative), "fixture: the pre-9013585 fence refuses {key}");
            assert!(crate::lake_part_gc::request::parse_part_file_key(&key).is_some(), "GC fence: {key}");
        }
        let dir = tempfile::tempdir().unwrap();
        let rows = batch(300, 0);
        let mut baseline = std::collections::BTreeMap::new();
        for counts in [false, true] {
            for data_ranges in [false, true] {
                let settings = ParquetSettings { zstd_level: 3, row_group_rows: 150, max_file_bytes: 1 };
                let mut writer = PartWriter::create_with(dir.path(), draft(rows.schema(), Level::L0, sources()), PartialSource::FromRows, 700 + i64::from(counts) * 2 + i64::from(data_ranges), 300, settings).unwrap();
                writer.entity_counts = counts.then(Builder::default);
                writer.parquet_range_write = data_ranges;
                writer.write(&rows).unwrap();
                let part = writer.finish().unwrap();
                let keys = PartKeys::new(tenant, part.record.level, part.record.event_hour, &part.record.part_id).unwrap();
                let mut names = part.record.files.all().into_iter().map(|(name, _, _)| name.to_string()).collect::<Vec<_>>();
                names.push("provenance.json".into());
                names.push(crate::parts::format::provenance_pending_file(&sha256_hex(&part.record.canonical_bytes().unwrap())));
                let mut unique = std::collections::BTreeSet::new();
                for name in names {
                    assert!(unique.insert(name.clone()), "duplicate physical key {name}");
                    let key = keys.file(&name);
                    assert!(key_matches(&key, "lake_part", "lake_part_file", tenant, i64::from(HOUR)), "Rust fence: {key}");
                    let relative = key.strip_prefix(&format!("lake/parts/v1/tenant={tenant}/")).unwrap();
                    assert!(pg.is_match(relative), "PG fence: {key}");
                    assert!(crate::lake_part_gc::request::parse_part_file_key(&key).is_some(), "GC fence: {key}");
                }
                assert_eq!(part.record.files.data[0].parquet_ranges.is_some(), data_ranges);
                assert_eq!(part.record.files.data.len(), 2);
                assert_eq!(part.record.files.data[1].parquet_ranges.is_some(), data_ranges);
                assert!(part.record.files.partials.len() <= 4);
                let emitted = part.record.files.all().into_iter().map(|(name, _, _)| name.to_owned()).collect::<std::collections::BTreeSet<_>>();
                if counts { assert_eq!(emitted, baseline[&data_ranges], "count writer must emit no new keys"); }
                else { baseline.insert(data_ranges, emitted); }
            }
        }
    }

    #[tokio::test]
    async fn entity_counts_writer_signed_inventory_old_reader_and_flag_off() {
        use crate::parts::entity_counts::{Builder, Index, is_count_path};
        let dir = tempfile::tempdir().unwrap();
        let rows = batch(300, 0);
        let mut legacy = PartWriter::create(dir.path(), draft(rows.schema(), Level::L0, sources()), PartialSource::FromRows, 601, 300).unwrap();
        legacy.entity_counts = None;
        legacy.write(&rows).unwrap();
        let legacy = legacy.finish().unwrap();
        let mut indexed = PartWriter::create(dir.path(), draft(rows.schema(), Level::L0, sources()), PartialSource::FromRows, 602, 300).unwrap();
        indexed.entity_counts = Some(Builder::default());
        indexed.write(&rows).unwrap();
        let indexed = indexed.finish().unwrap();
        assert!(count_rows(&legacy).iter().all(|row| !is_count_path(&row.key.0)));
        // Old Parquet readers ignore arbitrary key/value metadata; the
        // manifest and row schema stay unchanged. The optional footer mask
        // mirrors the existing coverage row only on successful emission.
        let hint = |part: &FinishedPart| {
            let file = parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder::try_new(File::open(part.dir.join(crate::parts::format::PARTIAL_ENTITY_RANGES_FILE)).unwrap()).unwrap();
            file.metadata().file_metadata().key_value_metadata().and_then(|items| items.iter().find(|item| item.key == crate::parts::entity_counts::V2_COVERAGE_PATH)).and_then(|item| item.value.clone())
        };
        assert_eq!(hint(&legacy), None);
        assert_eq!(hint(&indexed), count_rows(&indexed).into_iter().find(|row| row.key.0 == crate::parts::entity_counts::V2_COVERAGE_PATH).map(|row| row.key.1));
        let all = count_rows(&indexed);
        let index = Index::from_rows(all.clone(), indexed.record.rows, indexed.record.min_time_us, indexed.record.max_time_us).unwrap().unwrap();
        let from = i64::from(HOUR) * crate::parts::HOUR_US;
        assert_eq!(index.count_from_index((from, from + crate::parts::HOUR_US), &[("src_endpoint.ip", "10.0.0.1")]), Some(2));
        // Pre-change reader selects exact ordinary paths, ignoring reserved
        // namespaces. All its range answers remain byte-for-byte equivalent.
        let ordinary = |part: &FinishedPart| count_rows(part).into_iter().filter(|row| crate::parts::format::ENTITY_RANGE_PATHS.contains(&row.key.0.as_str())).collect::<Vec<_>>();
        assert_eq!(ordinary(&legacy), ordinary(&indexed));
        let digest = indexed.record.files.partials.iter().find(|partial| partial.kind == crate::parts::provenance::PartialKind::EntityRanges).unwrap();
        assert_eq!(file_digest(&indexed.dir.join(&digest.name)).unwrap(), (digest.bytes, digest.sha256.clone()));
        assert!(indexed.record.files.all().iter().any(|(name, sha, _)| *name == digest.name && *sha == digest.sha256));
        // No new manifest field/kind: use the unchanged strict parser.
        let encoded = serde_json::to_vec(&indexed.record).unwrap();
        let decoded: ProvenanceRecord = serde_json::from_slice(&encoded).unwrap();
        decoded.validate().unwrap();
        assert_eq!(decoded.files.partials.len(), legacy.record.files.partials.len());
        let signer = signer(7);
        let signature = signer.sign(TENANT, std::slice::from_ref(&indexed.record)).await.unwrap().remove(0);
        let mut signed = SignedProvenance::assemble(indexed.record.clone(), signature, &signer.trusted()).unwrap();
        let signed_bytes = signed.to_bytes().unwrap();
        SignedProvenance::verify_bytes(&signed_bytes, TENANT, &signer.trusted()).unwrap();
        assert!(SignedProvenance::verify_bytes(&signed_bytes, "00000000-0000-0000-0000-000000000002", &signer.trusted()).is_err());
        signed.record.files.partials.iter_mut().find(|partial| partial.kind == crate::parts::provenance::PartialKind::EntityRanges).unwrap().sha256 = "f".repeat(64);
        assert!(SignedProvenance::verify_bytes(&signed.to_bytes().unwrap(), TENANT, &signer.trusted()).is_err());
    }

    #[test]
    fn entity_counts_spill_and_output_failures_do_not_fail_part_write() {
        use crate::parts::entity_counts::{Builder, Index, is_count_path};
        for failure in 0..3 {
            let dir = tempfile::tempdir().unwrap();
            let rows = batch(300, 0);
            let mut writer = PartWriter::create(dir.path(), draft(rows.schema(), Level::L0, sources()), PartialSource::FromRows, 610 + failure, 300).unwrap();
            let missing = dir.path().join("missing-spill-directory");
            let mut builder = Builder::in_directory(&missing);
            if failure == 1 {
                // Force the spill creation error during write, rather than finish.
                builder.force_flush_on_next_batch();
            }
            if failure == 2 {
                builder = Builder::in_directory(&writer.dir);
                // A blocked output path fails after coverage has been read
                // from SQLite; the original partial must still be preserved.
                std::fs::create_dir_all(writer.dir.join(crate::parts::format::PARTIAL_ENTITY_RANGES_FILE).with_extension("counts.tmp")).unwrap();
            }
            writer.entity_counts = Some(builder);
            writer.write(&rows).unwrap();
            if failure == 1 { assert!(writer.entity_counts.is_none()); }
            // A later batch must not recreate coverage after a write failure.
            writer.write(&batch(300, 300)).unwrap();
            let part = writer.finish().unwrap();
            assert_eq!(part.record.rows, 600);
            part.record.validate().unwrap();
            let all = count_rows(&part);
            assert!(all.iter().all(|row| !is_count_path(&row.key.0)));
            assert!(Index::from_rows(all, part.record.rows, part.record.min_time_us, part.record.max_time_us).unwrap().is_none());
            let digest = part.record.files.partials.iter().find(|partial| partial.kind == crate::parts::provenance::PartialKind::EntityRanges).unwrap();
            assert_eq!(file_digest(&part.dir.join(&digest.name)).unwrap(), (digest.bytes, digest.sha256.clone()));
        }
    }

    #[tokio::test]
    async fn count_backfill_signed_hour_probe_is_idempotent_and_tenant_bound() {
        use crate::parts::part_log::LocalObjectStore;
        use crate::parts::provenance::LocalPartSigner;
        struct Restore(Option<bool>);
        impl Drop for Restore {
            fn drop(&mut self) { ENTITY_COUNT_WRITE_OVERRIDE.with(|value| value.set(self.0)); }
        }
        let _restore = Restore(ENTITY_COUNT_WRITE_OVERRIDE.with(|value| value.replace(Some(false))));
        let dir = tempfile::tempdir().unwrap();
        let store: &'static LocalObjectStore = Box::leak(Box::new(LocalObjectStore::new(dir.path().join("store")).unwrap()));
        let signer = LocalPartSigner::new(crate::parts::provenance::tests::SIGNER, ed25519_dalek::SigningKey::from_bytes(&[7; 32])).unwrap();
        let rows = batch(500, 0);
        let schema = rows.schema();
        let mut source_writer = PartWriter::create(dir.path(), draft(schema.clone(), Level::L0, sources()), PartialSource::FromRows, 699, 500).unwrap();
        source_writer.write(&rows).unwrap();
        let source = publish_parts(store, &signer, &signer.trusted(), &[source_writer.finish().unwrap()]).await.unwrap().remove(0);
        let inputs = PartInputs::Parts { parts: vec![crate::parts::provenance::InputPart {
            part_id: source.part_id.clone(), level: source.level, provenance_sha256: source.provenance_sha256.clone(), rows: source.rows, merkle_root: source.merkle_root.clone(),
        }] };
        let mut writer = PartWriter::create(dir.path(), draft(schema.clone(), Level::Hour, inputs), PartialSource::FromRows, 700, 500).unwrap();
        writer.write(&rows).unwrap();
        let legacy = writer.finish().unwrap();
        let old = publish_compacted_parts(store, &signer, &signer.trusted(), std::slice::from_ref(&legacy)).await.unwrap().remove(0);
        use crate::parts::part_log::{PartLogWriter, LogOp, load_log};
        let mut log = PartLogWriter::open(store, TENANT, 1, schema.as_ref(), 699).await.unwrap();
        let receipt = crate::parts::part_log::SourceRef { key: "k".into(), version: "1".into(), sha256: "0".repeat(64) };
        log.append(LogOp::Add { parts: vec![source.clone()], consumed: vec![receipt], edge_log: None }, 699).await.unwrap();
        log.append(LogOp::Merge { output: old.clone(), supersedes: vec![source.part_id] }, 700).await.unwrap();
        let probe = |part: PartRef, tenant: &str| super::super::ingest::probe_and_fetch_for_coverage(
            store, tenant.to_owned(), signer.trusted(), dir.path().join("work"), part, true, None, 0);
        assert!(probe(old.clone(), TENANT).await.unwrap().is_some());
        ENTITY_COUNT_WRITE_OVERRIDE.with(|value| value.set(Some(true)));
        let merged = super::super::merge_quota::with_count_backfill(true, || {
            merge_parts(dir.path(), TENANT, Level::Hour, HOUR,
                &[MergeInput { part: old.clone(), dir: legacy.dir.clone() }], schema.clone(),
                &crate::parts::format::schema_fingerprint(&schema).unwrap(), crate::parts::provenance::tests::SIGNER, "test", 701)
        }).unwrap();
        assert_eq!(merged.finished.record.merkle_root, legacy.record.merkle_root);
        assert_eq!(merged.finished.record.rows, 500);
        let index = crate::parts::entity_counts::Index::from_rows(count_rows(&merged.finished),
            500, merged.finished.record.min_time_us, merged.finished.record.max_time_us).unwrap().unwrap();
        let from = i64::from(HOUR) * crate::parts::HOUR_US;
        let native_count = merged.finished.record.files.data.iter().map(|data| {
            parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder::try_new(File::open(merged.finished.dir.join(&data.name)).unwrap()).unwrap().build().unwrap()
                .map(|batch| {
                    let batch = batch.unwrap();
                    let endpoint = batch.column_by_name("src_endpoint").unwrap().as_any().downcast_ref::<arrow_array::StructArray>().unwrap();
                    let ips = endpoint.column_by_name("ip").unwrap();
                    (0..batch.num_rows()).filter(|row| arrow_cast::display::array_value_to_string(ips.as_ref(), *row).unwrap() == "10.0.0.1").count() as u64
                }).sum::<u64>()
        }).sum::<u64>();
        assert_eq!(native_count, 3);
        assert_eq!(index.count_from_index((from, from + crate::parts::HOUR_US), &[("src_endpoint.ip", "10.0.0.1")]), Some(native_count));
        struct ColdPublish<'a> {
            inner: &'a dyn ObjectStore,
            writes: std::sync::Mutex<std::collections::BTreeSet<String>>,
            warms: std::sync::atomic::AtomicUsize,
        }
        #[async_trait::async_trait]
        impl ObjectStore for ColdPublish<'_> {
            async fn warm_signed_file(&self, _: &str, _: &Path, _: &str, _: u64) -> Result<bool> {
                self.warms.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                Ok(false)
            }
            async fn get(&self, key: &str) -> Result<Option<Vec<u8>>> { self.inner.get(key).await }
            async fn put_if_absent(&self, key: &str, bytes: &[u8]) -> Result<bool> {
                self.writes.lock().unwrap().insert(key.into());
                self.inner.put_if_absent(key, bytes).await
            }
            async fn put(&self, key: &str, bytes: &[u8]) -> Result<()> { self.inner.put(key, bytes).await }
            async fn delete(&self, key: &str) -> Result<()> { self.inner.delete(key).await }
            async fn list(&self, prefix: &str) -> Result<Vec<String>> { self.inner.list(prefix).await }
        }
        let cold = ColdPublish { inner: store, writes: Default::default(), warms: Default::default() };
        let expected_files = merged.finished.record.files.all().iter().map(|(name, _, _)| name.to_string()).collect::<std::collections::BTreeSet<_>>();
        let new = publish_backfilled_parts(&cold, &signer, &signer.trusted(), &[merged.finished]).await.unwrap().remove(0);
        assert!(probe(new.clone(), TENANT).await.unwrap().is_none());
        assert!(probe(new.clone(), TENANT).await.unwrap().is_none(), "repeat and restart probes skip published coverage");
        assert!(probe(new.clone(), "00000000-0000-4000-8000-000000000099").await.is_err());
        assert!(load_log(store, TENANT).await.unwrap().get(&old.part_id).is_some(), "old stays live until Merge commits");
        log.append(LogOp::Merge { output: new.clone(), supersedes: vec![old.part_id.clone()] }, 701).await.unwrap();
        let restarted = load_log(store, TENANT).await.unwrap();
        assert!(restarted.get(&old.part_id).is_none());
        assert!(restarted.is_removed(&old.part_id));
        assert!(restarted.get(&new.part_id).is_some());
        let keys = PartKeys::new(TENANT, new.level, new.event_hour, &new.part_id).unwrap();
        let expected_keys = expected_files.iter().map(|name| keys.file(name)).chain(std::iter::once(keys.provenance())).collect::<std::collections::BTreeSet<_>>();
        assert_eq!(*cold.writes.lock().unwrap(), expected_keys, "no new writer keys");
        assert_eq!(cold.warms.load(std::sync::atomic::Ordering::SeqCst), 0, "historical writes preserve the producer cache");
        for file in expected_files {
            assert!(store.get(&keys.file(&file)).await.unwrap().is_some(), "normal writer key missing: {file}");
        }
        let old_keys = PartKeys::new(TENANT, old.level, old.event_hour, &old.part_id).unwrap();
        assert!(store.get(&old_keys.provenance()).await.unwrap().is_some(), "publishing never collects the old generation");
    }

    #[test]
    fn entity_counts_compaction_rederives_deduped_counts_and_strips_when_off() {
        use crate::parts::entity_counts::{Index, is_count_path};
        // Thread-local test override avoids racing process-wide writer flags.
        struct Restore(Option<bool>);
        impl Drop for Restore {
            fn drop(&mut self) { ENTITY_COUNT_WRITE_OVERRIDE.with(|value| value.set(self.0)); }
        }
        let _restore = Restore(ENTITY_COUNT_WRITE_OVERRIDE.with(|value| value.replace(Some(true))));
        let dir = tempfile::tempdir().unwrap();
        let rows = batch(500, 0);
        let schema = rows.schema();
        let mut inputs = Vec::new();
        for (k, (from, len)) in [(0, 300), (200, 300)].into_iter().enumerate() {
            let mut writer = PartWriter::create(dir.path(), draft(schema.clone(), Level::L0, sources()), PartialSource::FromRows, 700 + k as i64, len as u64).unwrap();
            if k == 1 { writer.entity_counts = None; } // Mixed legacy/indexed inputs.
            writer.write(&rows.slice(from, len)).unwrap();
            let finished = writer.finish().unwrap();
            inputs.push(MergeInput { part: PartRef::from_record(&finished.record, &"1".repeat(64), true), dir: finished.dir });
        }
        let merge = |now| merge_parts(dir.path(), TENANT, Level::Minute, HOUR, &inputs, schema.clone(),
            &crate::parts::format::schema_fingerprint(&schema).unwrap(), crate::parts::provenance::tests::SIGNER, "test", now).unwrap();
        let merged = merge(710);
        assert_eq!(merged.duplicates_dropped, 100);
        let record = &merged.finished.record;
        let index = Index::from_rows(count_rows(&merged.finished), record.rows, record.min_time_us, record.max_time_us).unwrap().unwrap();
        let from = i64::from(HOUR) * crate::parts::HOUR_US;
        assert_eq!(index.count_from_index((from, from + crate::parts::HOUR_US), &[("src_endpoint.ip", "10.0.0.1")]), Some(3));
        ENTITY_COUNT_WRITE_OVERRIDE.with(|value| value.set(Some(false)));
        let off = merge(711);
        assert!(count_rows(&off.finished).iter().all(|row| !is_count_path(&row.key.0)));
    }

    #[test]
    fn merge_that_drops_duplicates_rebuilds_partials_from_rows() {
        let dir = tempfile::tempdir().unwrap();
        let rows = batch(500, 0);
        let schema = rows.schema();
        let mut inputs = Vec::new();
        // Two inputs share rows 200..300 (a duplicate that slipped past the window).
        for (k, (from, len)) in [(0usize, 300usize), (200, 300)].into_iter().enumerate() {
            let mut writer =
                PartWriter::create(dir.path(), draft(schema.clone(), Level::L0, sources()), PartialSource::FromRows, 200 + k as i64, 300).unwrap();
            writer.write(&rows.slice(from, len)).unwrap();
            let finished = writer.finish().unwrap();
            inputs.push(MergeInput { part: PartRef::from_record(&finished.record, &"1".repeat(64), true), dir: finished.dir });
        }
        let merged = merge_parts(
            dir.path(), TENANT, Level::Minute, HOUR, &inputs, schema.clone(),
            &crate::parts::format::schema_fingerprint(&schema).unwrap(), crate::parts::provenance::tests::SIGNER, "test", 300,
        )
        .unwrap();
        assert_eq!(merged.duplicates_dropped, 100);
        assert_eq!(merged.finished.record.rows, 500);
        let rollup = merged.finished.dir.join(crate::parts::format::PARTIAL_ROLLUP_FILE);
        assert_eq!(crate::part_ingest::partials::rollup_field0_events(&rollup).unwrap(), 500);
    }

    /// Catch-up throughput: publish writes run PUBLISH_CONCURRENCY at a time,
    /// keep input order, and a failure stops the queued backlog while every
    /// already-started write settles (none is cancelled mid-flight).
    #[tokio::test]
    async fn settle_all_runs_writes_concurrently_and_never_cancels_on_failure() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let (live, peak, done, started) = (Arc::new(AtomicUsize::new(0)), Arc::new(AtomicUsize::new(0)), Arc::new(AtomicUsize::new(0)), Arc::new(AtomicUsize::new(0)));
        let writes = (0..PUBLISH_CONCURRENCY * 3).map(|i| {
            let (live, peak, done, started) = (live.clone(), peak.clone(), done.clone(), started.clone());
            async move {
                started.fetch_add(1, Ordering::SeqCst);
                let now = live.fetch_add(1, Ordering::SeqCst) + 1;
                peak.fetch_max(now, Ordering::SeqCst);
                tokio::time::sleep(std::time::Duration::from_millis(if i == 0 { 1 } else { 30 })).await;
                live.fetch_sub(1, Ordering::SeqCst);
                if i == 0 { anyhow::bail!("first write fails") }
                done.fetch_add(1, Ordering::SeqCst);
                Ok(i)
            }
        }).collect::<Vec<_>>();
        assert!(settle_all(writes).await.unwrap_err().to_string().contains("first write fails"));
        assert_eq!(started.load(Ordering::SeqCst), PUBLISH_CONCURRENCY, "queued writes never start after the first failure");
        assert_eq!(done.load(Ordering::SeqCst), PUBLISH_CONCURRENCY - 1, "every delayed in-flight write finishes after the failure");
        assert_eq!(live.load(Ordering::SeqCst), 0, "no in-flight write was cancelled");
        assert_eq!(peak.load(Ordering::SeqCst), PUBLISH_CONCURRENCY);
        let ordered = settle_all((0..12_u64).map(|i| async move {
            tokio::time::sleep(std::time::Duration::from_millis(12 - i)).await;
            Ok::<_, anyhow::Error>(i)
        }).collect::<Vec<_>>()).await.unwrap();
        assert_eq!(ordered, (0..12).collect::<Vec<_>>());
    }
}
