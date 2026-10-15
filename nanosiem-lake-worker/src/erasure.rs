// SPDX-License-Identifier: AGPL-3.0-or-later

//! Data-subject erasure on the tenant's hour-partitioned OCSF Iceberg table
//! (NAN-2361 wave 4, the platform half of the 9000422 erasure ledger).
//!
//! The lake is append-only Parquet in R2 behind an Iceberg catalog; nothing on
//! the query path masks rows, and hydration refuses Iceberg delete files. The
//! only erasure the serving side honors is therefore a REWRITE: every live
//! data file that holds a row belonging to the subject is re-encoded without
//! those rows, the replacement is published through the tenant's authorized
//! writer under the committed-hot-tail key family, and one Iceberg
//! `overwrite` snapshot swaps predecessor for successor (deleted + added
//! entries in the same manifest). The snapshot carries
//! `nano.generation-ready=true`, so the generation manager promotes it like a
//! compaction or retention commit and the tenant's query workers stop
//! serving the subject's rows when that generation activates. Predecessor
//! objects become unreachable from the new snapshot and follow the existing
//! snapshot-expiry / physical-GC lifecycle exactly as retention's removed
//! files do.
//!
//! Boundaries kept on purpose:
//! * only live Parquet data files with the canonical `event_hour` partition
//!   are rewritten; an Iceberg delete manifest fails the pass (same rule as
//!   retention);
//! * the row match is exact, case-insensitive equality on the OCSF identity
//!   leaves listed in [`ErasureIdentifierType::column_paths`] — the same
//!   columns the dedicated ClickHouse erasure (`nanosiem-core::gdpr`) matches
//!   on. Free-text mentions are a separate, per-request option
//!   ([`FreeTextRedaction`], `redact_free_text`, default on, wave 6): when
//!   set, every kept row whose `message` or any string leaf under `unmapped`
//!   contains the subject (case-insensitive substring, the dedicated path's
//!   `replaceRegexpAll('(?i)…')` contract) has those mentions replaced by
//!   the request's tenant-scoped `identifier_hash` — the same pseudonym the
//!   ledger exposes — inside the same rewrite pass; a file with only free-text
//!   hits is rewritten like one with identity hits. Footer statistics cannot
//!   prune a substring match, so a redacting pass downloads every object in
//!   its window;
//! * a file whose every row belongs to the subject is dropped, not replaced
//!   with an empty Parquet object.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs::File;
use std::path::Path;
use std::sync::Arc;

use anyhow::{bail, Context, Result};
use arrow_array::{Array, ArrayRef, BooleanArray, RecordBatch, StringArray, StructArray};
use arrow_schema::{DataType, Schema as ArrowSchema};
use arrow_select::filter::filter_record_batch;
use iceberg::spec::{
    DataContentType, DataFile, DataFileBuilder, DataFileFormat, FormatVersion, Literal,
    ManifestContentType, ManifestEntry, ManifestFile, ManifestListWriter, ManifestWriterBuilder,
    Operation, PrimitiveLiteral, Snapshot, SnapshotRef, SnapshotReference, SnapshotRetention,
    Struct, Summary, Transform, MAIN_BRANCH,
};
use iceberg::table::Table;
use iceberg::{Catalog, TableIdent, TableRequirement, TableUpdate};
use iceberg_catalog_rest::RestCatalog;
use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;
use parquet::arrow::ArrowWriter;
use parquet::basic::{Compression, ZstdLevel};
use parquet::file::properties::WriterProperties;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::iceberg::{
    align_staged_batch, batch_time_bounds_ms, content_addressed_staged_path, is_lower_sha256,
    sort_pack_buffer, CatalogConfig, StagedEventFile, GENERATION_READY_PROPERTY,
    GENERATION_READY_VALUE, OCSF_VERSION,
};
use crate::rest_commit::{CommitOutcome, RestTableCommitClient};

const MILLIS_PER_HOUR: i64 = 3_600_000;
const MAX_COMMIT_ATTEMPTS: usize = 5;
const PACK_SORT_BUFFER_ROWS: usize = 131_072;
pub const ERASURE_COMPRESSION_LEVEL: i32 = 9;
pub const ERASURE_ORDER_PROPERTY: &str = "nano.erasure-order";
pub const ERASURE_PASS_PROPERTY: &str = "nano.erasure-pass-sha256";
pub const ERASURE_WRITER: &str = "rust-erasure";
/// Hard ceiling on the identifier so a hostile ledger row cannot make the
/// matcher allocate without bound (mirrors the 9000422 column check).
pub const MAX_IDENTIFIER_CHARS: usize = 320;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErasureIdentifierType {
    Username,
    Email,
    Ip,
}

impl ErasureIdentifierType {
    pub fn parse(value: &str) -> Result<Self> {
        match value {
            "username" => Ok(Self::Username),
            "email" => Ok(Self::Email),
            "ip" => Ok(Self::Ip),
            other => bail!("unsupported erasure identifier type {other:?}"),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Username => "username",
            Self::Email => "email",
            Self::Ip => "ip",
        }
    }

    /// Dotted OCSF paths whose leaf identifies the subject. This is exactly
    /// the OCSF contract of the dedicated ClickHouse erasure
    /// (`nanosiem-core::gdpr`: `user.name` / `actor.user.name` for a
    /// username or email subject, `src_endpoint.ip` / `dst_endpoint.ip` for
    /// an IP) plus the mail envelope leaves the UDM path covers through
    /// `sender` / `recipient`. Every path here is one the ingest normalizer
    /// lowercases (`iceberg.rs::normalize_source_semantics`), which is what
    /// makes Parquet min/max pruning ([`footer_may_contain_subject`]) sound:
    /// a column that may carry mixed case could hide a case-variant inside a
    /// range the lowercased subject falls outside of. Do not add a path
    /// here without adding it to the normalizer first.
    pub fn column_paths(self) -> &'static [&'static str] {
        match self {
            Self::Username => &["user.name", "actor.user.name"],
            Self::Email => &["email.from", "email.to", "user.name", "actor.user.name"],
            Self::Ip => &["src_endpoint.ip", "dst_endpoint.ip"],
        }
    }

    /// NAN-3867: the lean-lake selector. The gen1 paths plus the OCSF 1.x
    /// `user.email_addr` / `actor.user.email_addr` leaves for an email. Lean
    /// pruning never uses Parquet min/max statistics, so these need not be
    /// ingest-lowercased (the row match is case-insensitive). The IP selector
    /// stays the gen1 endpoint pair: both are entity-range paths, so an IP
    /// erasure prunes every part that never saw the address.
    pub fn lean_column_paths(self) -> &'static [&'static str] {
        match self {
            Self::Username => &["user.name", "actor.user.name"],
            Self::Email => &[
                "email.from", "email.to", "user.name", "actor.user.name",
                "user.email_addr", "actor.user.email_addr",
            ],
            Self::Ip => &["src_endpoint.ip", "dst_endpoint.ip"],
        }
    }
}

/// A normalized (trimmed, lowercased) subject identifier.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ErasureSubject {
    pub identifier_type: ErasureIdentifierType,
    value: String,
}

impl ErasureSubject {
    pub fn new(identifier_type: ErasureIdentifierType, value: &str) -> Result<Self> {
        let value = value.trim().to_lowercase();
        if value.is_empty()
            || value.chars().count() > MAX_IDENTIFIER_CHARS
            || value.chars().any(char::is_control)
        {
            bail!("erasure identifier is empty, oversized, or carries control characters");
        }
        if identifier_type == ErasureIdentifierType::Ip
            && value.parse::<std::net::IpAddr>().is_err()
        {
            bail!("erasure ip identifier is not an IP address");
        }
        Ok(Self {
            identifier_type,
            value,
        })
    }

    pub fn value(&self) -> &str {
        &self.value
    }

    fn matches(&self, candidate: &str) -> bool {
        if candidate.len() == self.value.len() && candidate.eq_ignore_ascii_case(&self.value) {
            return true;
        }
        // Non-ASCII usernames/emails: lowercase once, compare exactly.
        candidate.chars().any(|c| !c.is_ascii()) && candidate.to_lowercase() == self.value
    }
}

/// Resolve a dotted path through nested Arrow structs to a string leaf, or
/// to a list of strings (`email.to` is an OCSF string array). `None` when the
/// schema does not carry the path (absent optional OCSF object) or the leaf
/// is not a string type.
pub fn resolve_string_leaf(batch: &RecordBatch, path: &str) -> Option<ArrayRef> {
    let mut parts = path.split('.');
    let head = parts.next()?;
    let index = batch.schema().index_of(head).ok()?;
    let mut current: ArrayRef = Arc::clone(batch.column(index));
    for part in parts {
        let structure = current.as_any().downcast_ref::<StructArray>()?;
        current = Arc::clone(structure.column_by_name(part)?);
    }
    match current.data_type() {
        DataType::Utf8 | DataType::LargeUtf8 | DataType::Utf8View => Some(current),
        DataType::List(field) | DataType::LargeList(field)
            if matches!(
                field.data_type(),
                DataType::Utf8 | DataType::LargeUtf8 | DataType::Utf8View
            ) =>
        {
            Some(current)
        }
        _ => None,
    }
}

fn row_matches(array: &ArrayRef, row: usize, subject: &ErasureSubject) -> bool {
    if array.is_null(row) {
        return false;
    }
    match array.data_type() {
        DataType::List(_) => array
            .as_any()
            .downcast_ref::<arrow_array::ListArray>()
            .is_some_and(|lists| {
                let element = lists.value(row);
                (0..element.len()).any(|index| {
                    leaf_value(&element, index).is_some_and(|value| subject.matches(value))
                })
            }),
        DataType::LargeList(_) => array
            .as_any()
            .downcast_ref::<arrow_array::LargeListArray>()
            .is_some_and(|lists| {
                let element = lists.value(row);
                (0..element.len()).any(|index| {
                    leaf_value(&element, index).is_some_and(|value| subject.matches(value))
                })
            }),
        _ => leaf_value(array, row).is_some_and(|value| subject.matches(value)),
    }
}

fn leaf_value(array: &ArrayRef, row: usize) -> Option<&str> {
    if array.is_null(row) {
        return None;
    }
    match array.data_type() {
        DataType::Utf8 => array
            .as_any()
            .downcast_ref::<StringArray>()
            .map(|values| values.value(row)),
        DataType::LargeUtf8 => array
            .as_any()
            .downcast_ref::<arrow_array::LargeStringArray>()
            .map(|values| values.value(row)),
        DataType::Utf8View => array
            .as_any()
            .downcast_ref::<arrow_array::StringViewArray>()
            .map(|values| values.value(row)),
        _ => None,
    }
}

/// Per-row keep mask for a batch: `false` for every row that belongs to the
/// subject on any identity leaf. Returns the mask and the removed count.
pub fn subject_keep_mask(batch: &RecordBatch, subject: &ErasureSubject) -> (BooleanArray, u64) {
    subject_keep_mask_on(batch, subject, subject.identifier_type.column_paths())
}

/// [`subject_keep_mask`] over an explicit selector (NAN-3867 lean paths).
pub fn subject_keep_mask_on(batch: &RecordBatch, subject: &ErasureSubject, paths: &[&str]) -> (BooleanArray, u64) {
    let leaves = paths
        .iter()
        .filter_map(|path| resolve_string_leaf(batch, path))
        .collect::<Vec<_>>();
    let rows = batch.num_rows();
    let mut keep = Vec::with_capacity(rows);
    let mut removed = 0_u64;
    for row in 0..rows {
        let hit = leaves.iter().any(|leaf| row_matches(leaf, row, subject));
        if hit {
            removed += 1;
        }
        keep.push(!hit);
    }
    (BooleanArray::from(keep), removed)
}

/// Parquet footer pruning: `false` only when the row-group statistics of
/// every present identity column prove the (lowercased) subject lies outside
/// their [min, max] in every row group, or when the file carries none of the
/// identity columns at all. Missing or inexact statistics keep the file.
/// Sound because every identity path is ingest-lowercased (see
/// [`ErasureIdentifierType::column_paths`]).
pub fn footer_may_contain_subject(
    metadata: &parquet::file::metadata::ParquetMetaData,
    subject: &ErasureSubject,
) -> bool {
    let wanted = subject
        .identifier_type
        .column_paths()
        .iter()
        .map(|path| path.split('.').collect::<Vec<_>>())
        .collect::<Vec<_>>();
    let schema = metadata.file_metadata().schema_descr();
    let identity_columns = (0..schema.num_columns())
        .filter(|index| {
            let column = schema.column(*index);
            let parts = column
                .path()
                .parts()
                .iter()
                .map(String::as_str)
                .filter(|part| *part != "list" && *part != "element" && *part != "item")
                .collect::<Vec<_>>();
            wanted.iter().any(|want| *want == parts)
        })
        .collect::<Vec<_>>();
    if identity_columns.is_empty() {
        return false;
    }
    let needle = subject.value().as_bytes();
    for row_group in metadata.row_groups() {
        for index in &identity_columns {
            let Some(statistics) = row_group.column(*index).statistics() else {
                return true;
            };
            let (Some(min), Some(max)) = (statistics.min_bytes_opt(), statistics.max_bytes_opt())
            else {
                return true;
            };
            if needle >= min && needle <= max {
                return true;
            }
        }
    }
    false
}

#[derive(Debug)]
pub struct ErasureRewrite {
    pub rows_in: u64,
    pub rows_removed: u64,
    /// Kept rows whose free-text columns mentioned the subject and were
    /// rewritten (0 unless [`FreeTextRedaction`] was requested).
    pub rows_redacted: u64,
    /// `None` when nothing changed, or when every row belonged to the
    /// subject: the source file is then simply deleted from the successor
    /// snapshot (`rows_removed > 0`).
    pub replacement: Option<StagedEventFile>,
}

impl ErasureRewrite {
    /// The source object must be swapped (or dropped) in the successor.
    pub fn changed(&self) -> bool {
        self.rows_removed > 0 || self.rows_redacted > 0
    }
}

/// Free-text columns the redaction pass rewrites: the OCSF `message` string
/// and every string leaf under the `unmapped` struct (nested structs and
/// string lists included).
pub const FREE_TEXT_COLUMNS: [&str; 2] = ["message", "unmapped"];

/// NAN-3867: lean parts also keep the original event in `raw_data`.
pub const LEAN_FREE_TEXT_COLUMNS: [&str; 3] = ["message", "raw_data", "unmapped"];

/// Per-request free-text redaction contract (`redact_free_text`).
#[derive(Clone, Debug)]
pub struct FreeTextRedaction {
    matcher: regex::Regex,
    /// NAN-3867 lean: only mentions whose neighbors are not alphanumeric
    /// (the ingest tokenizer's split rule), so every redacted mention is a
    /// whole token sequence the part's token index recorded.
    word_bounded: bool,
    /// Replacement token: the request's `identifier_hash` (sha256 over
    /// tenant + type + normalized value), so mentions become the same
    /// pseudonym the tenant's ledger shows.
    token: String,
}

impl FreeTextRedaction {
    pub fn new(subject: &ErasureSubject, identifier_hash: &str) -> Result<Self> {
        if identifier_hash.len() != 64 || !is_lower_sha256(identifier_hash) {
            bail!("free-text redaction token must be the request identifier hash");
        }
        let matcher = regex::RegexBuilder::new(&regex::escape(subject.value()))
            .case_insensitive(true)
            .size_limit(1 << 20)
            .build()
            .context("build free-text redaction matcher")?;
        Ok(Self {
            matcher,
            word_bounded: false,
            token: identifier_hash.to_string(),
        })
    }

    /// [`Self::new`] matching only token-bounded mentions (lean parts).
    pub fn new_word_bounded(subject: &ErasureSubject, identifier_hash: &str) -> Result<Self> {
        Ok(Self { word_bounded: true, ..Self::new(subject, identifier_hash)? })
    }

    pub fn token(&self) -> &str {
        &self.token
    }

    fn redact_str(&self, value: &str) -> Option<String> {
        if !self.matcher.is_match(value) {
            return None;
        }
        if !self.word_bounded {
            return Some(self.matcher.replace_all(value, self.token.as_str()).into_owned());
        }
        let bounded = |m: &regex::Match<'_>| {
            !value[..m.start()].chars().next_back().is_some_and(char::is_alphanumeric)
                && !value[m.end()..].chars().next().is_some_and(char::is_alphanumeric)
        };
        let mut out = String::with_capacity(value.len());
        let mut last = 0;
        let mut hit = false;
        for m in self.matcher.find_iter(value).filter(bounded) {
            out.push_str(&value[last..m.start()]);
            out.push_str(&self.token);
            last = m.end();
            hit = true;
        }
        if !hit {
            return None;
        }
        out.push_str(&value[last..]);
        Some(out)
    }

    /// Rewrite one array: string leaves are redacted, structs and string
    /// lists recurse, everything else passes through. Returns the array and
    /// the per-row "changed" flags.
    fn redact_array(&self, array: &ArrayRef, changed: &mut [bool]) -> Result<ArrayRef> {
        match array.data_type() {
            DataType::Utf8 => {
                let values = array
                    .as_any()
                    .downcast_ref::<StringArray>()
                    .context("utf8 leaf")?;
                let mut hit = false;
                let rewritten = values
                    .iter()
                    .enumerate()
                    .map(|(row, value)| {
                        value.map(|value| match self.redact_str(value) {
                            Some(redacted) => {
                                hit = true;
                                if row < changed.len() {
                                    changed[row] = true;
                                }
                                redacted
                            }
                            None => value.to_string(),
                        })
                    })
                    .collect::<Vec<Option<String>>>();
                if !hit {
                    return Ok(Arc::clone(array));
                }
                Ok(Arc::new(StringArray::from(rewritten)) as ArrayRef)
            }
            DataType::LargeUtf8 => {
                let values = array
                    .as_any()
                    .downcast_ref::<arrow_array::LargeStringArray>()
                    .context("large utf8 leaf")?;
                let mut hit = false;
                let rewritten = values
                    .iter()
                    .enumerate()
                    .map(|(row, value)| {
                        value.map(|value| match self.redact_str(value) {
                            Some(redacted) => {
                                hit = true;
                                if row < changed.len() {
                                    changed[row] = true;
                                }
                                redacted
                            }
                            None => value.to_string(),
                        })
                    })
                    .collect::<Vec<Option<String>>>();
                if !hit {
                    return Ok(Arc::clone(array));
                }
                Ok(Arc::new(arrow_array::LargeStringArray::from(rewritten)) as ArrayRef)
            }
            DataType::Struct(fields) => {
                let structure = array
                    .as_any()
                    .downcast_ref::<StructArray>()
                    .context("struct column")?;
                let mut columns = Vec::with_capacity(fields.len());
                let mut any = false;
                for (index, child) in structure.columns().iter().enumerate() {
                    let rewritten = self.redact_array(child, changed)?;
                    any |= !Arc::ptr_eq(&rewritten, child);
                    let _ = index;
                    columns.push(rewritten);
                }
                if !any {
                    return Ok(Arc::clone(array));
                }
                Ok(Arc::new(StructArray::try_new(
                    fields.clone(),
                    columns,
                    structure.nulls().cloned(),
                )?) as ArrayRef)
            }
            DataType::List(field)
                if matches!(field.data_type(), DataType::Utf8 | DataType::LargeUtf8) =>
            {
                let lists = array
                    .as_any()
                    .downcast_ref::<arrow_array::ListArray>()
                    .context("string list column")?;
                // Map element rows back to list rows for the changed flags.
                let offsets = lists.offsets();
                let mut element_changed = vec![false; lists.values().len()];
                let rewritten_values = self.redact_array(lists.values(), &mut element_changed)?;
                if Arc::ptr_eq(&rewritten_values, lists.values()) {
                    return Ok(Arc::clone(array));
                }
                for row in 0..lists.len() {
                    let start = offsets[row] as usize;
                    let end = offsets[row + 1] as usize;
                    if element_changed[start..end].iter().any(|flag| *flag) && row < changed.len() {
                        changed[row] = true;
                    }
                }
                Ok(Arc::new(arrow_array::ListArray::try_new(
                    field.clone(),
                    offsets.clone(),
                    rewritten_values,
                    lists.nulls().cloned(),
                )?) as ArrayRef)
            }
            _ => Ok(Arc::clone(array)),
        }
    }

    /// Redact the free-text columns of a batch. Returns the (possibly same)
    /// batch and the number of rows that changed.
    pub fn redact_batch(&self, batch: &RecordBatch) -> Result<(RecordBatch, u64)> {
        self.redact_columns(batch, &FREE_TEXT_COLUMNS)
    }

    /// [`Self::redact_batch`] over explicit top-level columns.
    pub fn redact_columns(&self, batch: &RecordBatch, names: &[&str]) -> Result<(RecordBatch, u64)> {
        let mut changed = vec![false; batch.num_rows()];
        let mut columns = batch.columns().to_vec();
        let mut any = false;
        for name in names.iter().copied() {
            let Ok(index) = batch.schema().index_of(name) else {
                continue;
            };
            let rewritten = self.redact_array(&columns[index], &mut changed)?;
            if !Arc::ptr_eq(&rewritten, &columns[index]) {
                any = true;
                columns[index] = rewritten;
            }
        }
        let rows = changed.iter().filter(|flag| **flag).count() as u64;
        if !any {
            return Ok((batch.clone(), 0));
        }
        Ok((RecordBatch::try_new(batch.schema(), columns)?, rows))
    }
}

/// Re-encode one Parquet object without the subject's rows. The output uses
/// the table's current Arrow schema (additive alignment like the tail packer),
/// pack sort order, zstd-9, and a content-addressed committed-hot-tail key
/// under `data/tail/…/pack-<logical>-<sha256>.parquet` so the existing
/// writer-authority key contract admits it. `logical_sha256` identifies the
/// (order, source object) pair so retries land on the same key.
pub fn rewrite_parquet_without_subject(
    arrow_schema: Arc<ArrowSchema>,
    tenant_id: &str,
    event_hour: i32,
    logical_sha256: &str,
    source: &Path,
    subject: &ErasureSubject,
    redaction: Option<&FreeTextRedaction>,
) -> Result<ErasureRewrite> {
    if tenant_id.is_empty() || !is_lower_sha256(logical_sha256) {
        bail!("erasure rewrite identity is invalid");
    }
    let properties = WriterProperties::builder()
        .set_compression(Compression::ZSTD(ZstdLevel::try_new(
            ERASURE_COMPRESSION_LEVEL,
        )?))
        .set_max_row_group_row_count(Some(262_144))
        .build();
    let mut writer = ArrowWriter::try_new(Vec::new(), arrow_schema.clone(), Some(properties))?;
    let mut sort_buffer: Vec<RecordBatch> = Vec::new();
    let mut buffered_rows = 0_usize;
    let mut rows_in = 0_u64;
    let mut rows_out = 0_u64;
    let mut rows_removed = 0_u64;
    let mut rows_redacted = 0_u64;
    let mut min_time_ms = i64::MAX;
    let mut max_time_ms = i64::MIN;
    let reader = ParquetRecordBatchReaderBuilder::try_new(File::open(source)?)?
        .with_batch_size(8_192)
        .build()?;
    for batch in reader {
        let batch = batch?;
        rows_in = rows_in
            .checked_add(u64::try_from(batch.num_rows())?)
            .context("erasure source row count overflow")?;
        for batch in align_staged_batch(batch, arrow_schema.clone())? {
            let (keep, removed) = subject_keep_mask(&batch, subject);
            rows_removed = rows_removed
                .checked_add(removed)
                .context("erasure removed row count overflow")?;
            let kept = if removed == 0 {
                batch
            } else if removed == u64::try_from(batch.num_rows())? {
                continue;
            } else {
                filter_record_batch(&batch, &keep)?
            };
            if kept.num_rows() == 0 {
                continue;
            }
            let kept = match redaction {
                Some(redaction) => {
                    let (redacted, rows) = redaction.redact_batch(&kept)?;
                    rows_redacted = rows_redacted
                        .checked_add(rows)
                        .context("erasure redacted row count overflow")?;
                    redacted
                }
                None => kept,
            };
            let (batch_min, batch_max) = batch_time_bounds_ms(&kept)?;
            min_time_ms = min_time_ms.min(batch_min);
            max_time_ms = max_time_ms.max(batch_max);
            rows_out = rows_out
                .checked_add(u64::try_from(kept.num_rows())?)
                .context("erasure output row count overflow")?;
            buffered_rows += kept.num_rows();
            sort_buffer.push(kept);
            if buffered_rows >= PACK_SORT_BUFFER_ROWS {
                let merged = arrow_select::concat::concat_batches(&arrow_schema, &sort_buffer)?;
                writer.write(&sort_pack_buffer(&merged)?)?;
                sort_buffer.clear();
                buffered_rows = 0;
            }
        }
    }
    if buffered_rows > 0 {
        let merged = arrow_select::concat::concat_batches(&arrow_schema, &sort_buffer)?;
        writer.write(&sort_pack_buffer(&merged)?)?;
        sort_buffer.clear();
    }
    if rows_in != rows_out + rows_removed {
        bail!("erasure rewrite lost rows: in={rows_in} out={rows_out} removed={rows_removed}");
    }
    if rows_removed == 0 && rows_redacted == 0 {
        return Ok(ErasureRewrite {
            rows_in,
            rows_removed: 0,
            rows_redacted: 0,
            replacement: None,
        });
    }
    if rows_out == 0 {
        return Ok(ErasureRewrite {
            rows_in,
            rows_removed,
            rows_redacted,
            replacement: None,
        });
    }
    if min_time_ms == i64::MAX || max_time_ms == i64::MIN || min_time_ms > max_time_ms {
        bail!("erasure replacement has invalid event-time bounds");
    }
    let bytes = writer.into_inner()?;
    if bytes.is_empty() {
        bail!("erasure replacement is an empty Parquet object");
    }
    let sha256 = hex::encode(Sha256::digest(&bytes));
    let relative_path =
        content_addressed_staged_path(tenant_id, event_hour, "pack", logical_sha256, &sha256)?;
    Ok(ErasureRewrite {
        rows_in,
        rows_removed,
        rows_redacted,
        replacement: Some(StagedEventFile {
            event_hour,
            min_time_ms,
            max_time_ms,
            relative_path,
            bytes,
            rows: rows_out,
            duplicate_rows_removed: 0,
            sha256,
        }),
    })
}

/// Logical identity of one (order, source object) rewrite; stable across
/// retries so the replacement key is deterministic.
pub fn rewrite_logical_sha256(order_id: &str, source_path: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"nano-erasure-rewrite-v1\0");
    for value in [order_id, source_path] {
        hasher.update((value.len() as u64).to_be_bytes());
        hasher.update(value.as_bytes());
    }
    hex::encode(hasher.finalize())
}

/// A live data file of the current snapshot, as the executor sees it.
#[derive(Clone, Debug)]
pub struct LiveDataFile {
    pub hour: i32,
    /// Iceberg data sequence number of the live entry; a later pass uses it
    /// to scan only files registered after an earlier full scan.
    pub sequence_number: i64,
    pub data_file: DataFile,
}

impl LiveDataFile {
    pub fn path(&self) -> &str {
        self.data_file.file_path()
    }

    /// Whole-hour bounds in milliseconds.
    pub fn hour_bounds_ms(&self) -> (i64, i64) {
        let start = i64::from(self.hour) * MILLIS_PER_HOUR;
        (start, start + MILLIS_PER_HOUR - 1)
    }
}

/// Live Parquet data files of the current snapshot with their partition
/// hour. Delete manifests and non-canonical partitions fail the pass.
pub async fn live_data_files(
    table: &Table,
    tenant_id: &str,
    table_location: &str,
) -> Result<Vec<LiveDataFile>> {
    verify_event_table_boundary(table, tenant_id, table_location)?;
    let Some(current_snapshot) = table.metadata().current_snapshot().cloned() else {
        return Ok(Vec::new());
    };
    let loaded = load_live_manifests(table, &current_snapshot).await?;
    Ok(loaded.live)
}

/// Files whose hour partition overlaps `[floor_ms, cutoff_ms]`.
pub fn files_in_window(files: &[LiveDataFile], floor_ms: i64, cutoff_ms: i64) -> Vec<LiveDataFile> {
    files
        .iter()
        .filter(|file| {
            let (start, end) = file.hour_bounds_ms();
            end >= floor_ms && start <= cutoff_ms
        })
        .cloned()
        .collect()
}

/// One source object the executor rewrote (or found entirely subject-owned).
#[derive(Clone, Debug)]
pub struct ErasureReplacement {
    pub source_path: String,
    pub rows_removed: u64,
    /// `None` = drop the source file outright.
    pub replacement: Option<ReplacementObject>,
}

#[derive(Clone, Debug)]
pub struct ReplacementObject {
    /// Full object path inside the table location (`<location>/<relative>`).
    pub path: String,
    pub bytes: u64,
    pub rows: u64,
    pub sha256: String,
    pub event_hour: i32,
}

#[derive(Debug)]
pub struct PreparedErasureCommit {
    pub base_snapshot_id: i64,
    pub snapshot_id: i64,
    pub pass_sha256: String,
    pub removed_files: usize,
    pub added_files: usize,
    pub rows_removed: u64,
    pub removed_paths: Vec<String>,
    requirements: Vec<TableRequirement>,
    updates: Vec<TableUpdate>,
}

impl PreparedErasureCommit {
    /// The catalog envelope (requirements, updates) of the prepared pass, for
    /// callers that commit through their own catalog transport.
    pub fn into_commit_parts(self) -> (Vec<TableRequirement>, Vec<TableUpdate>) {
        (self.requirements, self.updates)
    }
}

struct LoadedManifest {
    descriptor: ManifestFile,
    entries: Vec<ManifestEntry>,
}

struct LoadedSnapshot {
    live: Vec<LiveDataFile>,
    manifests: Vec<LoadedManifest>,
}

async fn load_live_manifests(
    table: &Table,
    current_snapshot: &SnapshotRef,
) -> Result<LoadedSnapshot> {
    let manifest_list = table
        .manifest_list_reader(current_snapshot)
        .load()
        .await
        .context("load current Iceberg manifest list for erasure")?;
    let required_prefix = format!(
        "{}/data/",
        table.metadata().location().trim_end_matches('/')
    );
    let mut manifests = Vec::new();
    let mut live = Vec::new();
    let mut live_paths = HashSet::new();
    for descriptor in manifest_list.consume_entries() {
        if descriptor.content != ManifestContentType::Data {
            bail!("erasure does not support Iceberg delete manifests");
        }
        verify_partition_spec(table, descriptor.partition_spec_id)?;
        let manifest = descriptor
            .load_manifest(table.file_io())
            .await
            .with_context(|| format!("load Iceberg manifest {}", descriptor.manifest_path))?;
        let entries = manifest
            .entries()
            .iter()
            .map(|entry| entry.as_ref().clone())
            .collect::<Vec<_>>();
        for entry in entries.iter().filter(|entry| entry.is_alive()) {
            if entry.content_type() != DataContentType::Data
                || entry.file_format() != DataFileFormat::Parquet
            {
                bail!("erasure accepts only live Parquet data files");
            }
            let path = entry.file_path();
            if !path.starts_with(&required_prefix)
                || path.len() > 4_096
                || path.chars().any(char::is_control)
            {
                bail!("erasure found a data file outside the assigned table");
            }
            if !live_paths.insert(path.to_string()) {
                bail!("erasure found a data file live more than once");
            }
            live.push(LiveDataFile {
                hour: event_hour(entry)?,
                sequence_number: entry.sequence_number().unwrap_or(0),
                data_file: entry.data_file().clone(),
            });
        }
        manifests.push(LoadedManifest {
            descriptor,
            entries,
        });
    }
    Ok(LoadedSnapshot { live, manifests })
}

/// Build the manifest rewrite and commit envelope for one erasure pass
/// without advancing the catalog. Sources no longer alive in the current
/// snapshot (removed by retention meanwhile) are skipped; `None` when nothing
/// is left to swap.
pub async fn prepare_erasure_commit(
    table: &Table,
    tenant_id: &str,
    table_location: &str,
    order_id: &str,
    replacements: &[ErasureReplacement],
) -> Result<Option<PreparedErasureCommit>> {
    if order_id.is_empty() || order_id.len() > 64 || replacements.len() > 200_000 {
        bail!("erasure pass identity or size is out of bounds");
    }
    verify_event_table_boundary(table, tenant_id, table_location)?;
    let Some(current_snapshot) = table.metadata().current_snapshot().cloned() else {
        return Ok(None);
    };
    let loaded = load_live_manifests(table, &current_snapshot).await?;
    let live_paths = loaded
        .live
        .iter()
        .map(|file| (file.path().to_string(), file.hour))
        .collect::<HashMap<_, _>>();
    let mut by_source = BTreeMap::new();
    for replacement in replacements {
        let Some(hour) = live_paths.get(&replacement.source_path) else {
            continue;
        };
        if let Some(object) = &replacement.replacement {
            if object.event_hour != *hour {
                bail!("erasure replacement hour differs from its source partition");
            }
            if object.rows == 0 || object.bytes == 0 || !is_lower_sha256(&object.sha256) {
                bail!("erasure replacement object identity is invalid");
            }
            let required_prefix = format!(
                "{}/data/tail/",
                table.metadata().location().trim_end_matches('/')
            );
            if !object.path.starts_with(&required_prefix) {
                bail!("erasure replacement is outside the committed-hot-tail key family");
            }
        }
        if by_source
            .insert(replacement.source_path.clone(), replacement.clone())
            .is_some()
        {
            bail!("erasure pass lists one source object twice");
        }
    }
    if by_source.is_empty() {
        return Ok(None);
    }
    let pass_sha256 = pass_digest(
        table,
        tenant_id,
        order_id,
        current_snapshot.snapshot_id(),
        &by_source,
    );
    let snapshot_id = snapshot_id_for_digest(table, &pass_sha256)?;
    let next_sequence_number = table.metadata().next_sequence_number();
    let short_digest = &pass_sha256[..24];
    let mut rewritten_manifests = Vec::with_capacity(loaded.manifests.len());
    let mut removed_paths = Vec::new();
    let mut added_files = 0_usize;
    let mut rows_removed = 0_u64;
    let mut removed_rows_total = 0_u64;
    let mut removed_bytes_total = 0_u64;
    let mut added_rows_total = 0_u64;
    let mut added_bytes_total = 0_u64;
    let mut changed_hours = HashSet::new();
    for (index, loaded_manifest) in loaded.manifests.into_iter().enumerate() {
        let touches = loaded_manifest
            .entries
            .iter()
            .any(|entry| entry.is_alive() && by_source.contains_key(entry.file_path()));
        if !touches {
            rewritten_manifests.push(loaded_manifest.descriptor);
            continue;
        }
        let spec = table
            .metadata()
            .partition_spec_by_id(loaded_manifest.descriptor.partition_spec_id)
            .context("erasure manifest references an unknown partition spec")?
            .as_ref()
            .clone();
        let manifest_path = format!(
            "{}/metadata/nano-erasure-{short_digest}-m{index:05}.avro",
            table.metadata().location().trim_end_matches('/')
        );
        let output = table.file_io().new_output(&manifest_path)?;
        let mut writer = ManifestWriterBuilder::new(
            output,
            Some(snapshot_id),
            table.metadata().current_schema().clone(),
            spec,
        )
        .build_v2_data();
        for entry in loaded_manifest
            .entries
            .into_iter()
            .filter(ManifestEntry::is_alive)
        {
            let sequence_number = entry
                .sequence_number()
                .context("live erasure source lacks a data sequence number")?;
            let file_sequence_number = entry
                .file_sequence_number
                .context("live erasure source lacks a file sequence number")?;
            match by_source.get(entry.file_path()) {
                Some(replacement) => {
                    let hour = event_hour(&entry)?;
                    changed_hours.insert(hour);
                    removed_paths.push(entry.file_path().to_string());
                    removed_rows_total += entry.data_file().record_count();
                    removed_bytes_total += entry.data_file().file_size_in_bytes();
                    rows_removed += replacement.rows_removed;
                    writer.add_delete_file(
                        entry.data_file().clone(),
                        sequence_number,
                        Some(file_sequence_number),
                    )?;
                    if let Some(object) = &replacement.replacement {
                        let data_file = DataFileBuilder::default()
                            .content(DataContentType::Data)
                            .file_path(object.path.clone())
                            .file_format(DataFileFormat::Parquet)
                            .partition_spec_id(table.metadata().default_partition_spec_id())
                            .partition(Struct::from_iter([Some(Literal::int(object.event_hour))]))
                            .record_count(object.rows)
                            .file_size_in_bytes(object.bytes)
                            .build()
                            .context("build erasure replacement data file")?;
                        writer.add_file(data_file, next_sequence_number)?;
                        added_files += 1;
                        added_rows_total += object.rows;
                        added_bytes_total += object.bytes;
                    }
                }
                None => writer.add_existing_file(
                    entry.data_file().clone(),
                    entry
                        .snapshot_id()
                        .context("live erasure source lacks a snapshot ID")?,
                    sequence_number,
                    Some(file_sequence_number),
                )?,
            }
        }
        rewritten_manifests.push(writer.write_manifest_file().await?);
    }
    if removed_paths.is_empty() {
        return Ok(None);
    }

    let manifest_list_path = format!(
        "{}/metadata/snap-{snapshot_id}-nano-erasure-{short_digest}.avro",
        table.metadata().location().trim_end_matches('/')
    );
    let manifest_list_output = table
        .file_io()
        .new_output(&manifest_list_path)?
        .writer()
        .await?;
    let mut manifest_list_writer = ManifestListWriter::v2(
        manifest_list_output,
        snapshot_id,
        Some(current_snapshot.snapshot_id()),
        next_sequence_number,
    );
    manifest_list_writer.add_manifests(rewritten_manifests.into_iter())?;
    manifest_list_writer.close().await?;

    let total_rows = loaded
        .live
        .iter()
        .map(|file| file.data_file.record_count())
        .sum::<u64>();
    let total_bytes = loaded
        .live
        .iter()
        .map(|file| file.data_file.file_size_in_bytes())
        .sum::<u64>();
    let summary_properties = HashMap::from([
        ("nano.writer".to_string(), ERASURE_WRITER.to_string()),
        ("nano.ocsf-version".to_string(), OCSF_VERSION.to_string()),
        ("nano.tenant-id".to_string(), tenant_id.to_string()),
        (
            GENERATION_READY_PROPERTY.to_string(),
            GENERATION_READY_VALUE.to_string(),
        ),
        (ERASURE_ORDER_PROPERTY.to_string(), order_id.to_string()),
        (ERASURE_PASS_PROPERTY.to_string(), pass_sha256.clone()),
        ("added-data-files".to_string(), added_files.to_string()),
        ("added-records".to_string(), added_rows_total.to_string()),
        (
            "added-files-size".to_string(),
            added_bytes_total.to_string(),
        ),
        (
            "deleted-data-files".to_string(),
            removed_paths.len().to_string(),
        ),
        (
            "deleted-records".to_string(),
            removed_rows_total.to_string(),
        ),
        (
            "removed-files-size".to_string(),
            removed_bytes_total.to_string(),
        ),
        (
            "nano.erasure-rows-removed".to_string(),
            rows_removed.to_string(),
        ),
        (
            "total-data-files".to_string(),
            (loaded.live.len() - removed_paths.len() + added_files).to_string(),
        ),
        (
            "total-records".to_string(),
            (total_rows.saturating_sub(removed_rows_total) + added_rows_total).to_string(),
        ),
        (
            "total-files-size".to_string(),
            (total_bytes.saturating_sub(removed_bytes_total) + added_bytes_total).to_string(),
        ),
        (
            "changed-partition-count".to_string(),
            changed_hours.len().to_string(),
        ),
    ]);
    let snapshot = Snapshot::builder()
        .with_snapshot_id(snapshot_id)
        .with_parent_snapshot_id(Some(current_snapshot.snapshot_id()))
        .with_sequence_number(next_sequence_number)
        .with_timestamp_ms(chrono::Utc::now().timestamp_millis())
        .with_manifest_list(manifest_list_path)
        .with_summary(Summary {
            operation: Operation::Overwrite,
            additional_properties: summary_properties,
        })
        .with_schema_id(table.metadata().current_schema_id())
        .build();
    let requirements = vec![
        TableRequirement::UuidMatch {
            uuid: table.metadata().uuid(),
        },
        TableRequirement::RefSnapshotIdMatch {
            r#ref: MAIN_BRANCH.to_string(),
            snapshot_id: Some(current_snapshot.snapshot_id()),
        },
    ];
    let updates = vec![
        TableUpdate::AddSnapshot { snapshot },
        TableUpdate::SetSnapshotRef {
            ref_name: MAIN_BRANCH.to_string(),
            reference: SnapshotReference::new(
                snapshot_id,
                SnapshotRetention::branch(None, None, None),
            ),
        },
    ];
    Ok(Some(PreparedErasureCommit {
        base_snapshot_id: current_snapshot.snapshot_id(),
        snapshot_id,
        pass_sha256,
        removed_files: removed_paths.len(),
        added_files,
        rows_removed,
        removed_paths,
        requirements,
        updates,
    }))
}

#[derive(Clone, Debug, Serialize)]
pub struct ErasureCommitResult {
    pub status: &'static str,
    pub base_snapshot_id: Option<i64>,
    pub snapshot_id: Option<i64>,
    pub removed_files: usize,
    pub added_files: usize,
    pub rows_removed: u64,
    pub metadata_location: String,
    /// `nano.erasure-pass-sha256` of the committed snapshot (empty on
    /// `no_change`); the purge ledger binds predecessors to it.
    pub pass_sha256: String,
    #[serde(skip)]
    pub removed_paths: Vec<String>,
}

/// Commit one erasure pass with the retention module's optimistic REST
/// ceremony: table UUID + `main` ref fence, replan on conflict, and
/// reconcile an unknown transport outcome by proving the deterministic
/// snapshot landed before ever replaying it.
pub async fn commit_erasure_pass(
    catalog: &RestCatalog,
    catalog_config: &CatalogConfig,
    table_id: &TableIdent,
    tenant_id: &str,
    table_location: &str,
    order_id: &str,
    replacements: &[ErasureReplacement],
) -> Result<ErasureCommitResult> {
    let commit_client = RestTableCommitClient::new(catalog_config, table_id).await?;
    for _ in 0..MAX_COMMIT_ATTEMPTS {
        let table = catalog
            .load_table(table_id)
            .await
            .context("load Iceberg event table for erasure")?;
        let metadata_location = table
            .metadata_location_result()
            .context("erasure table has no metadata location")?
            .to_string();
        let Some(prepared) =
            prepare_erasure_commit(&table, tenant_id, table_location, order_id, replacements)
                .await?
        else {
            return Ok(ErasureCommitResult {
                status: "no_change",
                base_snapshot_id: table.metadata().current_snapshot_id(),
                snapshot_id: table.metadata().current_snapshot_id(),
                removed_files: 0,
                added_files: 0,
                rows_removed: 0,
                metadata_location,
                pass_sha256: String::new(),
                removed_paths: Vec::new(),
            });
        };
        let commit = commit_client
            .commit(prepared.requirements.clone(), prepared.updates.clone())
            .await;
        let outcome = match commit {
            Ok(outcome) => outcome,
            Err(commit_error) => match catalog.load_table(table_id).await {
                Ok(refreshed) if erasure_snapshot_matches(refreshed.metadata(), &prepared) => {
                    return Ok(committed_result(
                        "committed_reconciled",
                        refreshed.metadata_location_result()?.to_string(),
                        prepared,
                    ));
                }
                Ok(_) => {
                    return Err(commit_error)
                        .context("Iceberg erasure commit state is unknown and its snapshot was not observable");
                }
                Err(reload_error) => {
                    return Err(commit_error).context(format!(
                        "Iceberg erasure commit state is unknown and catalog reconciliation failed: {reload_error}"
                    ));
                }
            },
        };
        match outcome {
            CommitOutcome::Conflict => continue,
            CommitOutcome::Committed(response) => {
                if !erasure_snapshot_matches(&response.metadata, &prepared) {
                    bail!("Iceberg erasure commit response omitted its snapshot fences");
                }
                return Ok(committed_result(
                    "committed",
                    response.metadata_location,
                    prepared,
                ));
            }
        }
    }
    bail!("Iceberg erasure exhausted optimistic commit retries")
}

fn committed_result(
    status: &'static str,
    metadata_location: String,
    prepared: PreparedErasureCommit,
) -> ErasureCommitResult {
    ErasureCommitResult {
        status,
        base_snapshot_id: Some(prepared.base_snapshot_id),
        snapshot_id: Some(prepared.snapshot_id),
        removed_files: prepared.removed_files,
        added_files: prepared.added_files,
        rows_removed: prepared.rows_removed,
        metadata_location,
        pass_sha256: prepared.pass_sha256,
        removed_paths: prepared.removed_paths,
    }
}

fn erasure_snapshot_matches(
    metadata: &iceberg::spec::TableMetadata,
    prepared: &PreparedErasureCommit,
) -> bool {
    metadata.current_snapshot_id() == Some(prepared.snapshot_id)
        && metadata
            .snapshot_by_id(prepared.snapshot_id)
            .is_some_and(|snapshot| {
                let properties = &snapshot.summary().additional_properties;
                snapshot.summary().operation == Operation::Overwrite
                    && properties.get(ERASURE_PASS_PROPERTY).map(String::as_str)
                        == Some(prepared.pass_sha256.as_str())
                    && properties
                        .get(GENERATION_READY_PROPERTY)
                        .map(String::as_str)
                        == Some(GENERATION_READY_VALUE)
            })
}

fn pass_digest(
    table: &Table,
    tenant_id: &str,
    order_id: &str,
    base_snapshot_id: i64,
    by_source: &BTreeMap<String, ErasureReplacement>,
) -> String {
    let mut hasher = Sha256::new();
    for value in [
        "nano-erasure-pass-v1".to_string(),
        table.metadata().uuid().to_string(),
        tenant_id.to_string(),
        order_id.to_string(),
        base_snapshot_id.to_string(),
    ] {
        hasher.update(value.len().to_be_bytes());
        hasher.update(value.as_bytes());
    }
    for (source, replacement) in by_source {
        let (path, sha, rows) = replacement
            .replacement
            .as_ref()
            .map(|object| (object.path.as_str(), object.sha256.as_str(), object.rows))
            .unwrap_or(("", "", 0));
        for value in [
            source.clone(),
            replacement.rows_removed.to_string(),
            path.to_string(),
            sha.to_string(),
            rows.to_string(),
        ] {
            hasher.update(value.len().to_be_bytes());
            hasher.update(value.as_bytes());
        }
    }
    hex::encode(hasher.finalize())
}

fn snapshot_id_for_digest(table: &Table, digest: &str) -> Result<i64> {
    let bytes = hex::decode(digest)?;
    let mut snapshot_id = i64::from_be_bytes(bytes[..8].try_into()?) & i64::MAX;
    if snapshot_id == 0 {
        snapshot_id = 1;
    }
    if table.metadata().snapshot_by_id(snapshot_id).is_some() {
        bail!("deterministic erasure snapshot ID collides with table history");
    }
    Ok(snapshot_id)
}

fn verify_event_table_boundary(table: &Table, tenant_id: &str, table_location: &str) -> Result<()> {
    if tenant_id.is_empty()
        || tenant_id.len() > 512
        || tenant_id.chars().any(char::is_control)
        || table_location.len() > 2_048
        || table_location.chars().any(char::is_control)
    {
        bail!("erasure table boundary is invalid");
    }
    if table.metadata().format_version() != FormatVersion::V2 {
        bail!("erasure requires an Iceberg v2 table");
    }
    if table.metadata().location().trim_end_matches('/') != table_location.trim_end_matches('/') {
        bail!("Iceberg erasure table location changed");
    }
    if table
        .metadata()
        .properties()
        .get("nano.tenant-id")
        .map(String::as_str)
        != Some(tenant_id)
    {
        bail!("Iceberg erasure tenant binding changed");
    }
    verify_partition_spec(table, table.metadata().default_partition_spec_id())
}

fn verify_partition_spec(table: &Table, spec_id: i32) -> Result<()> {
    let spec = table
        .metadata()
        .partition_spec_by_id(spec_id)
        .context("erasure manifest references an unknown partition spec")?;
    let time_id = table
        .metadata()
        .current_schema()
        .field_by_name("time")
        .context("erasure table has no canonical time field")?
        .id;
    if spec.fields().len() != 1
        || spec.fields()[0].name != "event_hour"
        || spec.fields()[0].source_id != time_id
        || spec.fields()[0].transform != Transform::Hour
    {
        bail!("erasure requires exactly the canonical time/hour event_hour partition");
    }
    Ok(())
}

fn event_hour(entry: &ManifestEntry) -> Result<i32> {
    match entry.data_file().partition().fields() {
        [Some(Literal::Primitive(PrimitiveLiteral::Int(hour)))] => Ok(*hour),
        _ => bail!("erasure found an invalid event_hour partition value"),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use arrow_array::{ArrayRef, StringArray, StructArray, TimestampMicrosecondArray};
    use arrow_schema::{Field, Schema};
    use iceberg::memory::{MemoryCatalogBuilder, MEMORY_CATALOG_WAREHOUSE};
    use iceberg::spec::{
        NestedField, Schema as IcebergSchema, Type, UnboundPartitionField, UnboundPartitionSpec,
    };
    use iceberg::transaction::{ApplyTransactionAction, Transaction};
    use iceberg::{CatalogBuilder, NamespaceIdent, TableCreation};
    use tempfile::TempDir;

    use super::*;

    struct FixtureRow {
        uid: &'static str,
        time_us: i64,
        user: &'static str,
        actor_user: &'static str,
        src_ip: &'static str,
        email_from: &'static str,
    }

    fn fixture_batch(rows: &[FixtureRow]) -> RecordBatch {
        let utf8 = |values: Vec<&str>| Arc::new(StringArray::from(values)) as ArrayRef;
        let metadata = StructArray::from(vec![(
            Arc::new(Field::new("uid", DataType::Utf8, false)),
            utf8(rows.iter().map(|r| r.uid).collect()),
        )]);
        let user = StructArray::from(vec![(
            Arc::new(Field::new("name", DataType::Utf8, true)),
            utf8(rows.iter().map(|r| r.user).collect()),
        )]);
        let actor_user = StructArray::from(vec![(
            Arc::new(Field::new("name", DataType::Utf8, true)),
            utf8(rows.iter().map(|r| r.actor_user).collect()),
        )]);
        let actor = StructArray::from(vec![(
            Arc::new(Field::new("user", actor_user.data_type().clone(), true)),
            Arc::new(actor_user) as ArrayRef,
        )]);
        let src_endpoint = StructArray::from(vec![(
            Arc::new(Field::new("ip", DataType::Utf8, true)),
            utf8(rows.iter().map(|r| r.src_ip).collect()),
        )]);
        let email = StructArray::from(vec![(
            Arc::new(Field::new("from", DataType::Utf8, true)),
            utf8(rows.iter().map(|r| r.email_from).collect()),
        )]);
        let time =
            TimestampMicrosecondArray::from(rows.iter().map(|r| r.time_us).collect::<Vec<_>>())
                .with_timezone("UTC");
        let message = utf8(rows.iter().map(|r| r.uid).collect());
        let schema = Arc::new(Schema::new(vec![
            Field::new("time", time.data_type().clone(), false),
            Field::new("metadata", metadata.data_type().clone(), false),
            Field::new("user", user.data_type().clone(), true),
            Field::new("actor", actor.data_type().clone(), true),
            Field::new("src_endpoint", src_endpoint.data_type().clone(), true),
            Field::new("email", email.data_type().clone(), true),
            Field::new("message", DataType::Utf8, true),
        ]));
        RecordBatch::try_new(
            schema,
            vec![
                Arc::new(time),
                Arc::new(metadata),
                Arc::new(user),
                Arc::new(actor),
                Arc::new(src_endpoint),
                Arc::new(email),
                message,
            ],
        )
        .unwrap()
    }

    fn fixture_rows() -> Vec<FixtureRow> {
        vec![
            FixtureRow {
                uid: "e1",
                time_us: 3_600_000_000 * 10 + 1_000,
                user: "alice",
                actor_user: "svc",
                src_ip: "10.0.0.1",
                email_from: "alice@example.com",
            },
            FixtureRow {
                uid: "e2",
                time_us: 3_600_000_000 * 10 + 2_000,
                user: "bob",
                actor_user: "Alice",
                src_ip: "10.0.0.2",
                email_from: "bob@example.com",
            },
            FixtureRow {
                uid: "e3",
                time_us: 3_600_000_000 * 10 + 3_000,
                user: "carol",
                actor_user: "svc",
                src_ip: "10.0.0.3",
                email_from: "carol@example.com",
            },
            FixtureRow {
                uid: "e4",
                time_us: 3_600_000_000 * 10 + 4_000,
                user: "dave",
                actor_user: "svc",
                src_ip: "10.0.0.1",
                email_from: "alice@example.com",
            },
        ]
    }

    fn write_fixture(path: &Path, rows: &[FixtureRow]) -> Arc<Schema> {
        let batch = fixture_batch(rows);
        let schema = batch.schema();
        let mut writer =
            ArrowWriter::try_new(File::create(path).unwrap(), schema.clone(), None).unwrap();
        writer.write(&batch).unwrap();
        writer.close().unwrap();
        schema
    }

    fn read_uids(bytes: &[u8]) -> Vec<String> {
        let reader = ParquetRecordBatchReaderBuilder::try_new(bytes::Bytes::copy_from_slice(bytes))
            .unwrap()
            .build()
            .unwrap();
        let mut uids = Vec::new();
        for batch in reader {
            let batch = batch.unwrap();
            let leaf = resolve_string_leaf(&batch, "metadata.uid").unwrap();
            for row in 0..batch.num_rows() {
                uids.push(leaf_value(&leaf, row).unwrap().to_string());
            }
        }
        uids
    }

    #[test]
    fn subject_normalization_is_bounded_and_typed() {
        assert_eq!(
            ErasureSubject::new(ErasureIdentifierType::Email, "  Bob@Example.COM ")
                .unwrap()
                .value(),
            "bob@example.com"
        );
        assert!(ErasureSubject::new(ErasureIdentifierType::Ip, "10.0.0").is_err());
        assert!(ErasureSubject::new(ErasureIdentifierType::Username, "").is_err());
        assert!(ErasureSubject::new(ErasureIdentifierType::Username, "a\u{7}b").is_err());
        assert!(ErasureSubject::new(ErasureIdentifierType::Username, &"x".repeat(321)).is_err());
        assert_eq!(
            ErasureIdentifierType::parse("ip").unwrap(),
            ErasureIdentifierType::Ip
        );
        assert!(ErasureIdentifierType::parse("phone").is_err());
    }

    #[test]
    fn keep_mask_matches_every_identity_leaf_case_insensitively() {
        let batch = fixture_batch(&fixture_rows());
        let alice = ErasureSubject::new(ErasureIdentifierType::Username, "ALICE").unwrap();
        let (keep, removed) = subject_keep_mask(&batch, &alice);
        // e1 via user.name, e2 via actor.user.name ("Alice").
        assert_eq!(removed, 2);
        assert_eq!(
            keep.iter().map(|v| v.unwrap()).collect::<Vec<_>>(),
            vec![false, false, true, true]
        );

        let ip = ErasureSubject::new(ErasureIdentifierType::Ip, "10.0.0.1").unwrap();
        let (_, removed) = subject_keep_mask(&batch, &ip);
        assert_eq!(removed, 2, "e1 and e4 share the source ip");

        let email = ErasureSubject::new(ErasureIdentifierType::Email, "alice@example.com").unwrap();
        let (keep, removed) = subject_keep_mask(&batch, &email);
        assert_eq!(removed, 2);
        assert_eq!(
            keep.iter().map(|v| v.unwrap()).collect::<Vec<_>>(),
            vec![false, true, true, false]
        );

        let nobody = ErasureSubject::new(ErasureIdentifierType::Username, "mallory").unwrap();
        assert_eq!(subject_keep_mask(&batch, &nobody).1, 0);
    }

    #[test]
    fn absent_identity_paths_never_match_or_fail() {
        let batch = fixture_batch(&fixture_rows());
        assert!(resolve_string_leaf(&batch, "dst_endpoint.ip").is_none());
        assert!(resolve_string_leaf(&batch, "user.name.extra").is_none());
        assert!(
            resolve_string_leaf(&batch, "time").is_none(),
            "non-string leaves are ignored"
        );
        let subject = ErasureSubject::new(ErasureIdentifierType::Ip, "10.0.0.1").unwrap();
        // dst_endpoint.ip / device.ip are absent from the fixture; src_endpoint.ip still matches.
        assert_eq!(subject_keep_mask(&batch, &subject).1, 2);
    }

    #[test]
    fn list_leaves_match_any_element() {
        use arrow_array::builder::{ListBuilder, StringBuilder};
        let mut to = ListBuilder::new(StringBuilder::new());
        to.values().append_value("ops@example.com");
        to.values().append_value("Alice@Example.com");
        to.append(true);
        to.values().append_value("bob@example.com");
        to.append(true);
        to.append(false);
        let to = to.finish();
        let email = StructArray::from(vec![(
            Arc::new(Field::new("to", to.data_type().clone(), true)),
            Arc::new(to) as ArrayRef,
        )]);
        let schema = Arc::new(Schema::new(vec![Field::new(
            "email",
            email.data_type().clone(),
            true,
        )]));
        let batch = RecordBatch::try_new(schema, vec![Arc::new(email)]).unwrap();
        let subject =
            ErasureSubject::new(ErasureIdentifierType::Email, "alice@example.com").unwrap();
        let (keep, removed) = subject_keep_mask(&batch, &subject);
        assert_eq!(removed, 1);
        assert_eq!(
            keep.iter().map(|v| v.unwrap()).collect::<Vec<_>>(),
            vec![false, true, true]
        );
    }

    #[test]
    fn footer_statistics_prune_only_when_every_identity_range_excludes_the_subject() {
        let directory = TempDir::new().unwrap();
        let source = directory.path().join("source.parquet");
        write_fixture(&source, &fixture_rows());
        let metadata = parquet::file::metadata::ParquetMetaDataReader::new()
            .parse_and_finish(&File::open(&source).unwrap())
            .unwrap();
        let inside = ErasureSubject::new(ErasureIdentifierType::Username, "carol").unwrap();
        assert!(footer_may_contain_subject(&metadata, &inside));
        // "alice".."dave" on user.name, "svc".."svc" (and "Alice") on actor.user.name.
        let below = ErasureSubject::new(ErasureIdentifierType::Username, "aaron").unwrap();
        assert!(
            footer_may_contain_subject(&metadata, &below),
            "actor.user.name holds 'Alice' < 'aaron' ... range keeps it"
        );
        let above = ErasureSubject::new(ErasureIdentifierType::Username, "zed").unwrap();
        assert!(
            !footer_may_contain_subject(&metadata, &above),
            "zed is above every identity max"
        );
        let ip_inside = ErasureSubject::new(ErasureIdentifierType::Ip, "10.0.0.2").unwrap();
        assert!(footer_may_contain_subject(&metadata, &ip_inside));
        let ip_above = ErasureSubject::new(ErasureIdentifierType::Ip, "192.168.0.1").unwrap();
        assert!(!footer_may_contain_subject(&metadata, &ip_above));
        // A file without any identity column can never hold the subject.
        let bare = directory.path().join("bare.parquet");
        let time = TimestampMicrosecondArray::from(vec![1_i64]).with_timezone("UTC");
        let schema = Arc::new(Schema::new(vec![Field::new(
            "time",
            time.data_type().clone(),
            false,
        )]));
        let batch = RecordBatch::try_new(schema.clone(), vec![Arc::new(time)]).unwrap();
        let mut writer = ArrowWriter::try_new(File::create(&bare).unwrap(), schema, None).unwrap();
        writer.write(&batch).unwrap();
        writer.close().unwrap();
        let bare_metadata = parquet::file::metadata::ParquetMetaDataReader::new()
            .parse_and_finish(&File::open(&bare).unwrap())
            .unwrap();
        assert!(!footer_may_contain_subject(&bare_metadata, &inside));
    }

    #[test]
    fn rewrite_drops_only_the_subject_rows_and_is_deterministic() {
        let directory = TempDir::new().unwrap();
        let source = directory.path().join("source.parquet");
        let schema = write_fixture(&source, &fixture_rows());
        let subject = ErasureSubject::new(ErasureIdentifierType::Username, "alice").unwrap();
        let logical = rewrite_logical_sha256("order-1", "s3://x/data/source.parquet");
        let first = rewrite_parquet_without_subject(
            schema.clone(),
            "tenant-a",
            10,
            &logical,
            &source,
            &subject,
            None,
        )
        .unwrap();
        assert_eq!(first.rows_in, 4);
        assert_eq!(first.rows_removed, 2);
        let replacement = first.replacement.as_ref().unwrap();
        assert_eq!(replacement.rows, 2);
        assert_eq!(replacement.event_hour, 10);
        assert_eq!(read_uids(&replacement.bytes), vec!["e3", "e4"]);
        assert!(replacement
            .relative_path
            .starts_with("data/tail/tenant_sha256="));
        assert!(replacement
            .relative_path
            .contains(&format!("/event_hour=10/pack-{logical}-")));
        assert_eq!(replacement.min_time_ms, 36_000_003);
        assert_eq!(replacement.max_time_ms, 36_000_004);

        let second =
            rewrite_parquet_without_subject(schema, "tenant-a", 10, &logical, &source, &subject, None)
                .unwrap();
        assert_eq!(
            second.replacement.unwrap().sha256,
            replacement.sha256,
            "retries land on the same key"
        );
    }

    #[test]
    fn rewrite_reports_unchanged_and_fully_erased_objects() {
        let directory = TempDir::new().unwrap();
        let source = directory.path().join("source.parquet");
        let schema = write_fixture(&source, &fixture_rows());
        let logical = rewrite_logical_sha256("order-1", "src");
        let nobody = ErasureSubject::new(ErasureIdentifierType::Username, "mallory").unwrap();
        let untouched =
            rewrite_parquet_without_subject(schema.clone(), "t", 10, &logical, &source, &nobody, None)
                .unwrap();
        assert_eq!(untouched.rows_removed, 0);
        assert!(untouched.replacement.is_none());

        let only_alice = directory.path().join("alice.parquet");
        let schema = write_fixture(&only_alice, &fixture_rows()[..1]);
        let alice = ErasureSubject::new(ErasureIdentifierType::Username, "alice").unwrap();
        let erased =
            rewrite_parquet_without_subject(schema, "t", 10, &logical, &only_alice, &alice, None)
                .unwrap();
        assert_eq!((erased.rows_in, erased.rows_removed), (1, 1));
        assert!(
            erased.replacement.is_none(),
            "an all-subject object is dropped, not replaced"
        );
    }

    fn read_messages(bytes: &[u8]) -> Vec<String> {
        let reader = ParquetRecordBatchReaderBuilder::try_new(bytes::Bytes::copy_from_slice(bytes))
            .unwrap()
            .build()
            .unwrap();
        let mut out = Vec::new();
        for batch in reader {
            let batch = batch.unwrap();
            let messages = resolve_string_leaf(&batch, "message").unwrap();
            for row in 0..batch.num_rows() {
                out.push(leaf_value(&messages, row).unwrap().to_string());
            }
        }
        out
    }

    #[test]
    fn free_text_redaction_rewrites_mentions_in_kept_rows_only_when_requested() {
        // Rows: e1 (alice, identity hit), e2 (bob, message mentions ALICE),
        // e3 (carol, unmapped mentions alice@example.com), e4 (dave, clean).
        let utf8 = |values: Vec<&str>| Arc::new(StringArray::from(values)) as ArrayRef;
        let time = TimestampMicrosecondArray::from(vec![1_i64, 2, 3, 4]).with_timezone("UTC");
        let user = StructArray::from(vec![(
            Arc::new(Field::new("name", DataType::Utf8, true)),
            utf8(vec!["alice", "bob", "carol", "dave"]),
        )]);
        let unmapped_inner = StructArray::from(vec![(
            Arc::new(Field::new("note", DataType::Utf8, true)),
            utf8(vec!["", "", "sent by Alice@Example.com today", "nothing"]),
        )]);
        let unmapped = StructArray::from(vec![
            (
                Arc::new(Field::new("raw", DataType::Utf8, true)),
                utf8(vec!["x", "y", "z", "w"]),
            ),
            (
                Arc::new(Field::new("detail", unmapped_inner.data_type().clone(), true)),
                Arc::new(unmapped_inner) as ArrayRef,
            ),
        ]);
        let message = utf8(vec![
            "login alice",
            "failed login for ALICE from 10.0.0.9",
            "carol ok",
            "dave ok",
        ]);
        let schema = Arc::new(Schema::new(vec![
            Field::new("time", time.data_type().clone(), false),
            Field::new("user", user.data_type().clone(), true),
            Field::new("message", DataType::Utf8, true),
            Field::new("unmapped", unmapped.data_type().clone(), true),
        ]));
        let batch = RecordBatch::try_new(
            schema.clone(),
            vec![Arc::new(time), Arc::new(user), message, Arc::new(unmapped)],
        )
        .unwrap();
        let token = "7".repeat(64);
        let subject = ErasureSubject::new(ErasureIdentifierType::Username, "Alice").unwrap();
        let redaction = FreeTextRedaction::new(&subject, &token).unwrap();
        let (redacted, rows) = redaction.redact_batch(&batch).unwrap();
        assert_eq!(rows, 3, "e1 (message), e2 (message) and e3 (unmapped) change");
        let messages = resolve_string_leaf(&redacted, "message").unwrap();
        assert_eq!(leaf_value(&messages, 1).unwrap(), format!("failed login for {token} from 10.0.0.9"));
        assert_eq!(leaf_value(&messages, 3).unwrap(), "dave ok");
        let note = resolve_string_leaf(&redacted, "unmapped.detail.note").unwrap();
        assert_eq!(leaf_value(&note, 2).unwrap(), format!("sent by {token}@Example.com today"));
        assert_eq!(leaf_value(&note, 3).unwrap(), "nothing");
        // Untouched columns keep the same buffers.
        assert!(Arc::ptr_eq(redacted.column(1), batch.column(1)));
        // No mention: same batch, zero rows.
        let nobody = ErasureSubject::new(ErasureIdentifierType::Username, "zed").unwrap();
        let (same, rows) = FreeTextRedaction::new(&nobody, &token).unwrap().redact_batch(&batch).unwrap();
        assert_eq!(rows, 0);
        assert!(Arc::ptr_eq(same.column(2), batch.column(2)));
        assert!(FreeTextRedaction::new(&subject, "short").is_err());

        // Through the Parquet rewrite: identity hit removed, mentions
        // redacted, clean rows untouched; without the option only the
        // identity row goes and mentions survive.
        let directory = TempDir::new().unwrap();
        let source = directory.path().join("free-text.parquet");
        let mut writer = ArrowWriter::try_new(File::create(&source).unwrap(), schema.clone(), None).unwrap();
        writer.write(&batch).unwrap();
        writer.close().unwrap();
        let logical = rewrite_logical_sha256("order", "src");
        let with = rewrite_parquet_without_subject(schema.clone(), "t", 0, &logical, &source, &subject, Some(&redaction)).unwrap();
        assert_eq!((with.rows_in, with.rows_removed, with.rows_redacted), (4, 1, 2));
        assert!(with.changed());
        let messages = read_messages(&with.replacement.as_ref().unwrap().bytes);
        assert_eq!(messages, vec![format!("failed login for {token} from 10.0.0.9"), "carol ok".to_string(), "dave ok".to_string()]);
        let without = rewrite_parquet_without_subject(schema.clone(), "t", 0, &logical, &source, &subject, None).unwrap();
        assert_eq!((without.rows_removed, without.rows_redacted), (1, 0));
        assert_eq!(read_messages(&without.replacement.as_ref().unwrap().bytes)[0], "failed login for ALICE from 10.0.0.9");
        // Mentions only (no identity hit) still rewrite the file when requested.
        let (only_mentions, _) = (
            rewrite_parquet_without_subject(schema.clone(), "t", 0, &logical, &source, &nobody, None).unwrap(),
            (),
        );
        assert!(!only_mentions.changed());
        let bob = ErasureSubject::new(ErasureIdentifierType::Username, "10.0.0.9").unwrap();
        let mention_only = rewrite_parquet_without_subject(schema, "t", 0, &logical, &source, &bob, Some(&FreeTextRedaction::new(&bob, &token).unwrap())).unwrap();
        assert_eq!((mention_only.rows_removed, mention_only.rows_redacted), (0, 1));
        assert!(mention_only.changed() && mention_only.replacement.is_some());
    }

    #[test]
    fn window_selection_uses_partition_hours() {
        let file = |hour: i32| LiveDataFile {
            hour,
            sequence_number: 1,
            data_file: DataFileBuilder::default()
                .content(DataContentType::Data)
                .file_path(format!("s3://t/data/h{hour}.parquet"))
                .file_format(DataFileFormat::Parquet)
                .partition(Struct::from_iter([Some(Literal::int(hour))]))
                .record_count(1)
                .file_size_in_bytes(1)
                .partition_spec_id(0)
                .build()
                .unwrap(),
        };
        let files = vec![file(9), file(10), file(11), file(12)];
        let selected = files_in_window(&files, 10 * MILLIS_PER_HOUR + 5, 11 * MILLIS_PER_HOUR + 5);
        assert_eq!(
            selected.iter().map(|f| f.hour).collect::<Vec<_>>(),
            vec![10, 11]
        );
        assert!(files_in_window(&files, 13 * MILLIS_PER_HOUR, 14 * MILLIS_PER_HOUR).is_empty());
    }

    async fn table_with_files(hours: &[i32]) -> (TempDir, impl Catalog, Table, TableIdent) {
        let directory = TempDir::new().unwrap();
        let catalog = MemoryCatalogBuilder::default()
            .load(
                "erasure-test",
                HashMap::from([(
                    MEMORY_CATALOG_WAREHOUSE.to_string(),
                    directory.path().display().to_string(),
                )]),
            )
            .await
            .unwrap();
        let namespace = NamespaceIdent::new("nano".to_string());
        catalog
            .create_namespace(&namespace, HashMap::new())
            .await
            .unwrap();
        let table_id = TableIdent::new(namespace.clone(), "events".to_string());
        let schema = IcebergSchema::builder()
            .with_fields(vec![Arc::new(NestedField::required(
                1,
                "time",
                Type::Primitive(iceberg::spec::PrimitiveType::Timestamptz),
            ))])
            .build()
            .unwrap();
        let partition = UnboundPartitionSpec::builder()
            .with_spec_id(0)
            .add_partition_fields([UnboundPartitionField::builder()
                .source_id(1)
                .field_id(1_000)
                .name("event_hour".to_string())
                .transform(Transform::Hour)
                .build()])
            .unwrap()
            .build();
        let table = catalog
            .create_table(
                &namespace,
                TableCreation::builder()
                    .name("events".to_string())
                    .location(format!("{}/events", directory.path().display()))
                    .schema(schema)
                    .partition_spec(partition)
                    .properties(HashMap::from([(
                        "nano.tenant-id".to_string(),
                        "tenant-a".to_string(),
                    )]))
                    .build(),
            )
            .await
            .unwrap();
        let location = table.metadata().location().to_string();
        let files = hours
            .iter()
            .enumerate()
            .map(|(index, hour)| {
                DataFileBuilder::default()
                    .content(DataContentType::Data)
                    .file_path(format!("{location}/data/hour-{hour}-{index}.parquet"))
                    .file_format(DataFileFormat::Parquet)
                    .partition(Struct::from_iter([Some(Literal::int(*hour))]))
                    .record_count(10)
                    .file_size_in_bytes(100)
                    .partition_spec_id(0)
                    .build()
                    .unwrap()
            })
            .collect::<Vec<_>>();
        let transaction = Transaction::new(&table);
        let table = transaction
            .fast_append()
            .add_data_files(files)
            .apply(transaction)
            .unwrap()
            .commit(&catalog)
            .await
            .unwrap();
        (directory, catalog, table, table_id)
    }

    #[tokio::test]
    async fn prepared_commit_swaps_predecessor_for_successor_in_one_overwrite_snapshot() {
        let (_directory, _catalog, table, _table_id) = table_with_files(&[10, 10, 11]).await;
        let location = table.metadata().location().to_string();
        let live = live_data_files(&table, "tenant-a", &location)
            .await
            .unwrap();
        assert_eq!(live.len(), 3);
        let source = live[0].path().to_string();
        let dropped = live[2].path().to_string();
        let replacements = vec![
            ErasureReplacement {
                source_path: source.clone(),
                rows_removed: 3,
                replacement: Some(ReplacementObject {
                    path: format!(
                        "{location}/data/tail/tenant_sha256=ab/event_hour=10/pack-{}-{}.parquet",
                        "0".repeat(64),
                        "1".repeat(64)
                    ),
                    bytes: 70,
                    rows: 7,
                    sha256: "1".repeat(64),
                    event_hour: 10,
                }),
            },
            ErasureReplacement {
                source_path: dropped.clone(),
                rows_removed: 10,
                replacement: None,
            },
            ErasureReplacement {
                source_path: format!("{location}/data/retained-elsewhere.parquet"),
                rows_removed: 1,
                replacement: None,
            },
        ];
        let prepared =
            prepare_erasure_commit(&table, "tenant-a", &location, "order-1", &replacements)
                .await
                .unwrap()
                .expect("a pass with live sources produces a commit");
        assert_eq!(prepared.removed_files, 2, "the unknown source is skipped");
        assert_eq!(prepared.added_files, 1);
        assert_eq!(prepared.rows_removed, 13);
        assert_eq!(
            prepared.base_snapshot_id,
            table.metadata().current_snapshot_id().unwrap()
        );
        assert!(
            prepared.removed_paths.contains(&source) && prepared.removed_paths.contains(&dropped)
        );
        assert_eq!(prepared.requirements.len(), 2);
        let TableUpdate::AddSnapshot { snapshot } = &prepared.updates[0] else {
            panic!("first update adds the snapshot")
        };
        assert_eq!(snapshot.summary().operation, Operation::Overwrite);
        let properties = &snapshot.summary().additional_properties;
        assert_eq!(
            properties
                .get(GENERATION_READY_PROPERTY)
                .map(String::as_str),
            Some("true")
        );
        assert_eq!(
            properties.get(ERASURE_ORDER_PROPERTY).map(String::as_str),
            Some("order-1")
        );
        assert_eq!(
            properties.get("deleted-data-files").map(String::as_str),
            Some("2")
        );
        assert_eq!(
            properties.get("added-data-files").map(String::as_str),
            Some("1")
        );
        assert_eq!(
            properties.get("total-data-files").map(String::as_str),
            Some("2")
        );
        assert_eq!(
            properties.get("total-records").map(String::as_str),
            Some("17")
        );

        // Deterministic identity: the same pass on the same base yields the same snapshot id.
        let again = prepare_erasure_commit(&table, "tenant-a", &location, "order-1", &replacements)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(again.snapshot_id, prepared.snapshot_id);
        assert_eq!(again.pass_sha256, prepared.pass_sha256);

        // Verify the written manifest list: 2 deleted + 1 added + 1 existing entries.
        let snapshot_manifests = table
            .manifest_list_reader(&Arc::new(snapshot.clone()))
            .load()
            .await
            .unwrap();
        let mut deleted = 0;
        let mut added = 0;
        let mut existing = 0;
        for descriptor in snapshot_manifests.consume_entries() {
            let manifest = descriptor.load_manifest(table.file_io()).await.unwrap();
            for entry in manifest.entries() {
                match entry.status() {
                    iceberg::spec::ManifestStatus::Deleted => deleted += 1,
                    iceberg::spec::ManifestStatus::Added => added += 1,
                    iceberg::spec::ManifestStatus::Existing => existing += 1,
                }
            }
        }
        assert_eq!((deleted, added, existing), (2, 1, 1));
    }

    #[tokio::test]
    async fn prepared_commit_refuses_mismatched_replacements_and_empty_passes() {
        let (_directory, _catalog, table, _table_id) = table_with_files(&[10]).await;
        let location = table.metadata().location().to_string();
        let live = live_data_files(&table, "tenant-a", &location)
            .await
            .unwrap();
        let wrong_hour = vec![ErasureReplacement {
            source_path: live[0].path().to_string(),
            rows_removed: 1,
            replacement: Some(ReplacementObject {
                path: format!("{location}/data/tail/x.parquet"),
                bytes: 1,
                rows: 1,
                sha256: "2".repeat(64),
                event_hour: 11,
            }),
        }];
        assert!(
            prepare_erasure_commit(&table, "tenant-a", &location, "o", &wrong_hour)
                .await
                .is_err()
        );
        let outside = vec![ErasureReplacement {
            source_path: live[0].path().to_string(),
            rows_removed: 1,
            replacement: Some(ReplacementObject {
                path: format!("{location}/data/not-tail.parquet"),
                bytes: 1,
                rows: 1,
                sha256: "2".repeat(64),
                event_hour: 10,
            }),
        }];
        assert!(
            prepare_erasure_commit(&table, "tenant-a", &location, "o", &outside)
                .await
                .is_err()
        );
        assert!(
            prepare_erasure_commit(&table, "tenant-a", &location, "o", &[])
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            prepare_erasure_commit(&table, "tenant-b", &location, "o", &[])
                .await
                .is_err(),
            "tenant binding is fenced"
        );
    }
}
