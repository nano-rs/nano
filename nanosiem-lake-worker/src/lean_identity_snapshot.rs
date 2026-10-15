// SPDX-License-Identifier: AGPL-3.0-or-later

//! Tenant identity directory in the tenant's own R2 enrichment prefix
//! (NAN-3489 decision 2, NAN-3500).
//!
//! Layout, relative to a store rooted at `lake/enrichment/v1/tenant_id=<T>/`:
//!
//! ```text
//! identity/current.json                  mutable pointer to the latest manifest
//! identity/revisions/<uuidv7>.json       immutable manifest (snapshot + ordered deltas)
//! identity/snapshots/<sha256>.parquet    compacted directory, content-addressed
//! identity/deltas/<sha256>.parquet       append-only changes since that snapshot
//! ```
//!
//! Every Parquet file holds typed, flat [`IdentityRow`] columns sorted by
//! `(feed_id, external_id)`. All merges are streaming k-way merges over sorted
//! files, so memory stays proportional to one row group per input rather than
//! to the directory size (500k+ account directories are the design target).
//!
//! Row precedence inside one key: the highest `version` wins; on a tie the
//! later input (a later delta, a staged replacement) wins. A winning
//! tombstone (`deleted = true`) removes the key. Cross-feed precedence
//! (pull > push > observed) is applied by readers, not here: the store keeps
//! every feed's row with its provenance.
//!
//! One writer per tenant (the lean enrichment coordinator) publishes; it
//! writes immutable content first, then the revision record, then the
//! pointer. Readers pin a manifest revision. Every manifest names its tenant
//! and is refused by a store bound to a different tenant.

use anyhow::{bail, ensure, Context, Result};
use arrow_array::builder::{BooleanBuilder, Int64Builder, ListBuilder, StringBuilder};
use arrow_array::{Array, BooleanArray, Int64Array, ListArray, RecordBatch, StringArray};
use arrow_schema::{DataType, Field, Schema, SchemaRef};
use parquet::arrow::arrow_reader::{ParquetRecordBatchReader, ParquetRecordBatchReaderBuilder};
use parquet::arrow::ArrowWriter;
use parquet::basic::{Compression, ZstdLevel};
use parquet::file::properties::WriterProperties;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};
use uuid::Uuid;

use crate::parts::part_log::ObjectStore;

const NAMESPACE: &str = "identity";
const MANIFEST_SCHEMA_VERSION: u32 = 1;
/// Rows per Parquet row group and per in-memory encode/decode batch.
const BATCH_ROWS: usize = 65_536;

/// Ceiling on one tenant's merged directory.
pub const IDENTITY_MAX_ROWS: u64 = 5_000_000;
/// Ceiling on any one identity Parquet object (snapshot, delta, staged chunk).
pub const IDENTITY_MAX_FILE_BYTES: u64 = 1024 * 1024 * 1024;
/// Ceiling on rows in one delta or one staged replacement chunk.
pub const IDENTITY_MAX_BATCH_ROWS: usize = 100_000;
/// Compact once a manifest carries more than this many deltas…
pub const COMPACT_AFTER_DELTAS: usize = 32;
/// …or more than this many delta bytes.
pub const COMPACT_AFTER_DELTA_BYTES: u64 = 64 * 1024 * 1024;

const MAX_TEXT_BYTES: usize = 4096;
const MAX_GROUPS: usize = 4096;
/// Accepted `account_status` values. Stored as plain text, so widening the
/// set never changes the file schema: files written before still read.
/// NAN-3503 contract additions: `staged` (provisioned, not yet activated),
/// `locked` (temporarily locked out), `deprovisioned` (removed by the IdP,
/// kept for audit). `disabled` is unchanged.
const ACCOUNT_STATUSES: [&str; 10] = [
    "",
    "active",
    "disabled",
    "suspended",
    "deleted",
    "anonymized",
    "unknown",
    "staged",
    "locked",
    "deprovisioned",
];

/// Typed refusals the coordinator maps to HTTP statuses.
#[derive(Debug, thiserror::Error)]
pub enum IdentityStoreError {
    #[error("identity revision changed")]
    Conflict,
    #[error("identity input refused: {0}")]
    Invalid(String),
    #[error("identity input exceeds a cap: {0}")]
    TooLarge(String),
}

/// Where a row came from. Cross-feed precedence defaults to
/// `Pull > Push > Observed` (NAN-3489 decision 3) and is applied by readers.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(rename_all = "snake_case")]
pub enum SourceKind {
    Pull,
    Push,
    Observed,
}

impl SourceKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pull => "pull",
            Self::Push => "push",
            Self::Observed => "observed",
        }
    }

    fn parse(value: &str) -> Result<Self> {
        Ok(match value {
            "pull" => Self::Pull,
            "push" => Self::Push,
            "observed" => Self::Observed,
            _ => bail!("identity source_kind is invalid"),
        })
    }
}

/// One identity record with its provenance. Times are epoch milliseconds.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct IdentityRow {
    pub feed_id: String,
    pub external_id: String,
    pub source_kind: SourceKind,
    pub version: i64,
    #[serde(default)]
    pub deleted: bool,
    #[serde(default)]
    pub snapshot_id: Option<String>,
    #[serde(default)]
    pub observed_at: Option<i64>,
    #[serde(default)]
    pub username: String,
    #[serde(default)]
    pub upn: String,
    #[serde(default)]
    pub email: String,
    #[serde(default)]
    pub display_name: String,
    #[serde(default)]
    pub first_name: String,
    #[serde(default)]
    pub last_name: String,
    #[serde(default)]
    pub department: String,
    #[serde(default)]
    pub title: String,
    #[serde(default)]
    pub manager_upn: String,
    #[serde(default)]
    pub manager_display_name: String,
    #[serde(default)]
    pub company: String,
    #[serde(default)]
    pub office_location: String,
    #[serde(default)]
    pub city: String,
    #[serde(default)]
    pub country: String,
    #[serde(default)]
    pub groups: Vec<String>,
    #[serde(default)]
    pub account_enabled: Option<bool>,
    #[serde(default)]
    pub account_status: String,
    #[serde(default)]
    pub mfa_enabled: Option<bool>,
    #[serde(default)]
    pub last_sign_in_at: Option<i64>,
    #[serde(default)]
    pub created_in_directory_at: Option<i64>,
    #[serde(default)]
    pub phone: String,
    #[serde(default)]
    pub employee_id: String,
    #[serde(default)]
    pub employee_type: String,
    #[serde(default)]
    pub last_observed_at: Option<i64>,
    /// Directory admin (Google `isAdmin`, a privileged Entra role, an Okta
    /// admin group). Membership sub-feeds set it from `privileged`; readers
    /// OR it across one provider's sub-feeds (NAN-3503). Files written before
    /// this column existed read it as `None`.
    #[serde(default)]
    pub is_admin: Option<bool>,
}

/// Text columns in schema order, after the provenance columns.
macro_rules! text_columns {
    ($m:ident) => {
        $m!(
            username,
            upn,
            email,
            display_name,
            first_name,
            last_name,
            department,
            title,
            manager_upn,
            manager_display_name,
            company,
            office_location,
            city,
            country
        )
    };
}

macro_rules! tail_text_columns {
    ($m:ident) => {
        $m!(phone, employee_id, employee_type)
    };
}

impl IdentityRow {
    /// A row with only its key and provenance set.
    pub fn new(feed_id: &str, external_id: &str, source_kind: SourceKind, version: i64) -> Self {
        Self {
            feed_id: feed_id.into(),
            external_id: external_id.into(),
            source_kind,
            version,
            deleted: false,
            snapshot_id: None,
            observed_at: None,
            username: String::new(),
            upn: String::new(),
            email: String::new(),
            display_name: String::new(),
            first_name: String::new(),
            last_name: String::new(),
            department: String::new(),
            title: String::new(),
            manager_upn: String::new(),
            manager_display_name: String::new(),
            company: String::new(),
            office_location: String::new(),
            city: String::new(),
            country: String::new(),
            groups: Vec::new(),
            account_enabled: None,
            account_status: String::new(),
            mfa_enabled: None,
            last_sign_in_at: None,
            created_in_directory_at: None,
            phone: String::new(),
            employee_id: String::new(),
            employee_type: String::new(),
            last_observed_at: None,
            is_admin: None,
        }
    }

    fn key(&self) -> (&str, &str) {
        (&self.feed_id, &self.external_id)
    }

    /// Reject anything a reader could not safely key, filter or render.
    pub fn validate(&self) -> Result<()> {
        validate_feed_id(&self.feed_id)?;
        ensure!(
            valid_text(&self.external_id)
                && !self.external_id.is_empty()
                && self.external_id.len() <= 1024,
            "identity external_id is invalid"
        );
        ensure!(self.version > 0, "identity version must be positive");
        if let Some(snapshot) = &self.snapshot_id {
            ensure!(
                valid_token(snapshot, 128),
                "identity snapshot_id is invalid"
            );
        }
        macro_rules! check {
            ($($field:ident),*) => {$(
                ensure!(valid_text(&self.$field), concat!("identity ", stringify!($field), " is invalid"));
            )*};
        }
        text_columns!(check);
        tail_text_columns!(check);
        ensure!(
            ACCOUNT_STATUSES.contains(&self.account_status.as_str()),
            "identity account_status is invalid"
        );
        ensure!(
            self.groups.len() <= MAX_GROUPS && self.groups.iter().all(|group| valid_text(group)),
            "identity groups are invalid"
        );
        Ok(())
    }

    /// Patch semantics for a delta row (NAN-3503): every empty text column,
    /// unset option and empty group list takes `current`'s value; key and
    /// provenance stay this row's. An absent field means "unchanged", so a
    /// patch cannot clear a column (the next full run does).
    pub fn fill_from(&mut self, current: &IdentityRow) {
        macro_rules! text {
            ($($field:ident),*) => {$(
                if self.$field.is_empty() {
                    self.$field.clone_from(&current.$field);
                }
            )*};
        }
        text_columns!(text);
        tail_text_columns!(text);
        text!(account_status, groups);
        macro_rules! option {
            ($($field:ident),*) => {$(
                if self.$field.is_none() {
                    self.$field = current.$field;
                }
            )*};
        }
        option!(
            account_enabled,
            mfa_enabled,
            last_sign_in_at,
            created_in_directory_at,
            last_observed_at,
            is_admin
        );
    }

    /// What a report's `manager_upn` names: upn, else email, else username.
    pub fn reference(&self) -> Option<&str> {
        [&self.upn, &self.email, &self.username]
            .into_iter()
            .find(|value| !value.is_empty())
            .map(String::as_str)
    }
}

/// A delta row's manager named by id only (NAN-3503): the coordinator
/// resolves it against the same request, then the current directory, into
/// the row's `manager_upn`. A delta run sees only changed users, so the
/// connector cannot resolve an unchanged manager itself.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ManagerRef {
    pub feed_id: String,
    pub external_id: String,
    pub manager_external_id: String,
}

fn valid_text(value: &str) -> bool {
    value.len() <= MAX_TEXT_BYTES && !value.chars().any(char::is_control)
}

fn valid_token(value: &str, max: usize) -> bool {
    !value.is_empty()
        && value.len() <= max
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_.:-".contains(&b))
}

/// Feed ids are path components on the coordinator (staging directories), so
/// they must also start with an ASCII letter or digit (no `.`/`..`).
pub fn validate_feed_id(feed_id: &str) -> Result<()> {
    ensure!(
        valid_token(feed_id, 256) && feed_id.as_bytes()[0].is_ascii_alphanumeric(),
        "identity feed_id is invalid"
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// Parquet codec
// ---------------------------------------------------------------------------

/// The current file schema: the legacy schema plus a trailing nullable
/// `is_admin` column (NAN-3503).
fn schema() -> SchemaRef {
    static SCHEMA: OnceLock<SchemaRef> = OnceLock::new();
    SCHEMA
        .get_or_init(|| {
            let mut fields: Vec<Field> = legacy_schema()
                .fields()
                .iter()
                .map(|field| field.as_ref().clone())
                .collect();
            fields.push(Field::new("is_admin", DataType::Boolean, true));
            Arc::new(Schema::new(fields))
        })
        .clone()
}

/// The schema before `is_admin`. Readers accept both; writers emit it while
/// no row of the file carries `is_admin`, so directories that never set the
/// column keep byte-identical (content-addressed) files and stay readable by
/// readers that predate it.
fn legacy_schema() -> SchemaRef {
    static SCHEMA: OnceLock<SchemaRef> = OnceLock::new();
    SCHEMA
        .get_or_init(|| {
            let mut fields = vec![
                Field::new("feed_id", DataType::Utf8, false),
                Field::new("external_id", DataType::Utf8, false),
                Field::new("source_kind", DataType::Utf8, false),
                Field::new("version", DataType::Int64, false),
                Field::new("deleted", DataType::Boolean, false),
                Field::new("snapshot_id", DataType::Utf8, true),
                Field::new("observed_at", DataType::Int64, true),
            ];
            macro_rules! text {
                ($($field:ident),*) => {$(
                    fields.push(Field::new(stringify!($field), DataType::Utf8, false));
                )*};
            }
            text_columns!(text);
            fields.push(Field::new(
                "groups",
                DataType::List(Arc::new(Field::new("item", DataType::Utf8, true))),
                false,
            ));
            fields.push(Field::new("account_enabled", DataType::Boolean, true));
            fields.push(Field::new("account_status", DataType::Utf8, false));
            fields.push(Field::new("mfa_enabled", DataType::Boolean, true));
            fields.push(Field::new("last_sign_in_at", DataType::Int64, true));
            fields.push(Field::new("created_in_directory_at", DataType::Int64, true));
            tail_text_columns!(text);
            fields.push(Field::new("last_observed_at", DataType::Int64, true));
            Arc::new(Schema::new(fields))
        })
        .clone()
}

fn file_schema(with_is_admin: bool) -> SchemaRef {
    if with_is_admin {
        schema()
    } else {
        legacy_schema()
    }
}

fn encode(rows: &[IdentityRow], with_is_admin: bool) -> Result<RecordBatch> {
    ensure!(
        with_is_admin || rows.iter().all(|row| row.is_admin.is_none()),
        "identity is_admin requires the current file schema"
    );
    let strings = |get: &dyn Fn(&IdentityRow) -> &str| -> Arc<dyn Array> {
        Arc::new(StringArray::from_iter_values(rows.iter().map(get)))
    };
    let optional_strings = |get: &dyn Fn(&IdentityRow) -> Option<&str>| -> Arc<dyn Array> {
        Arc::new(rows.iter().map(get).collect::<StringArray>())
    };
    let ints = |get: &dyn Fn(&IdentityRow) -> Option<i64>| -> Arc<dyn Array> {
        let mut builder = Int64Builder::with_capacity(rows.len());
        for row in rows {
            builder.append_option(get(row));
        }
        Arc::new(builder.finish())
    };
    let bools = |get: &dyn Fn(&IdentityRow) -> Option<bool>| -> Arc<dyn Array> {
        let mut builder = BooleanBuilder::with_capacity(rows.len());
        for row in rows {
            builder.append_option(get(row));
        }
        Arc::new(builder.finish())
    };
    let mut columns: Vec<Arc<dyn Array>> = vec![
        strings(&|row| &row.feed_id),
        strings(&|row| &row.external_id),
        strings(&|row| row.source_kind.as_str()),
        Arc::new(Int64Array::from_iter_values(
            rows.iter().map(|row| row.version),
        )),
        Arc::new(BooleanArray::from(
            rows.iter().map(|row| row.deleted).collect::<Vec<_>>(),
        )),
        optional_strings(&|row| row.snapshot_id.as_deref()),
        ints(&|row| row.observed_at),
    ];
    macro_rules! text {
        ($($field:ident),*) => {$(
            columns.push(strings(&|row| &row.$field));
        )*};
    }
    text_columns!(text);
    let mut groups = ListBuilder::new(StringBuilder::new()).with_field(Arc::new(Field::new(
        "item",
        DataType::Utf8,
        true,
    )));
    for row in rows {
        for group in &row.groups {
            groups.values().append_value(group);
        }
        groups.append(true);
    }
    columns.push(Arc::new(groups.finish()));
    columns.push(bools(&|row| row.account_enabled));
    columns.push(strings(&|row| &row.account_status));
    columns.push(bools(&|row| row.mfa_enabled));
    columns.push(ints(&|row| row.last_sign_in_at));
    columns.push(ints(&|row| row.created_in_directory_at));
    tail_text_columns!(text);
    columns.push(ints(&|row| row.last_observed_at));
    if with_is_admin {
        columns.push(bools(&|row| row.is_admin));
    }
    Ok(RecordBatch::try_new(file_schema(with_is_admin), columns)?)
}

/// Typed column views over one decoded batch.
struct Columns<'a> {
    batch: &'a RecordBatch,
    has_is_admin: bool,
}

/// Whether `fields` is the current schema (`Some(true)`), the legacy schema
/// without `is_admin` (`Some(false)`), or neither.
fn schema_has_is_admin(fields: &arrow_schema::Fields) -> Option<bool> {
    if fields == schema().fields() {
        Some(true)
    } else if fields == legacy_schema().fields() {
        Some(false)
    } else {
        None
    }
}

impl<'a> Columns<'a> {
    fn new(batch: &'a RecordBatch) -> Result<Self> {
        let has_is_admin = schema_has_is_admin(batch.schema().fields())
            .context("identity Parquet schema differs from the expected schema")?;
        Ok(Self {
            batch,
            has_is_admin,
        })
    }

    fn column<T: 'static>(&self, name: &str) -> &'a T {
        // The schema equality check in `new` makes these downcasts total.
        self.batch
            .column_by_name(name)
            .and_then(|column| column.as_any().downcast_ref::<T>())
            .expect("identity schema checked")
    }

    fn text(&self, name: &str, index: usize) -> String {
        self.column::<StringArray>(name).value(index).to_string()
    }

    fn optional_text(&self, name: &str, index: usize) -> Option<String> {
        let column = self.column::<StringArray>(name);
        (!column.is_null(index)).then(|| column.value(index).to_string())
    }

    fn optional_int(&self, name: &str, index: usize) -> Option<i64> {
        let column = self.column::<Int64Array>(name);
        (!column.is_null(index)).then(|| column.value(index))
    }

    fn optional_bool(&self, name: &str, index: usize) -> Option<bool> {
        let column = self.column::<BooleanArray>(name);
        (!column.is_null(index)).then(|| column.value(index))
    }

    fn row(&self, index: usize) -> Result<IdentityRow> {
        let mut row = IdentityRow::new(
            self.column::<StringArray>("feed_id").value(index),
            self.column::<StringArray>("external_id").value(index),
            SourceKind::parse(self.column::<StringArray>("source_kind").value(index))?,
            self.column::<Int64Array>("version").value(index),
        );
        row.deleted = self.column::<BooleanArray>("deleted").value(index);
        row.snapshot_id = self.optional_text("snapshot_id", index);
        row.observed_at = self.optional_int("observed_at", index);
        macro_rules! text {
            ($($field:ident),*) => {$(
                row.$field = self.text(stringify!($field), index);
            )*};
        }
        text_columns!(text);
        tail_text_columns!(text);
        let groups = self.column::<ListArray>("groups").value(index);
        let groups = groups
            .as_any()
            .downcast_ref::<StringArray>()
            .context("identity groups have the wrong Parquet type")?;
        row.groups = (0..groups.len())
            .filter(|i| !groups.is_null(*i))
            .map(|i| groups.value(i).to_string())
            .collect();
        row.account_enabled = self.optional_bool("account_enabled", index);
        row.account_status = self.text("account_status", index);
        row.mfa_enabled = self.optional_bool("mfa_enabled", index);
        row.last_sign_in_at = self.optional_int("last_sign_in_at", index);
        row.created_in_directory_at = self.optional_int("created_in_directory_at", index);
        row.last_observed_at = self.optional_int("last_observed_at", index);
        if self.has_is_admin {
            row.is_admin = self.optional_bool("is_admin", index);
        }
        Ok(row)
    }
}

fn decode(batch: &RecordBatch) -> Result<Vec<IdentityRow>> {
    let columns = Columns::new(batch)?;
    (0..batch.num_rows())
        .map(|index| columns.row(index))
        .collect()
}

/// A content-addressed identity file: digest, size and row count.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct FileRef {
    pub sha256: String,
    pub bytes: u64,
    pub rows: u64,
}

impl FileRef {
    fn check(&self) -> Result<()> {
        ensure!(
            self.sha256.len() == 64
                && self
                    .sha256
                    .bytes()
                    .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')),
            "identity file digest is invalid"
        );
        ensure!(
            self.bytes > 0 && self.bytes <= IDENTITY_MAX_FILE_BYTES,
            "identity file size is invalid"
        );
        ensure!(
            self.rows <= IDENTITY_MAX_ROWS,
            "identity file row count is invalid"
        );
        Ok(())
    }
}

/// Buffered writer producing one sorted identity Parquet file.
struct SortedWriter {
    path: PathBuf,
    writer: ArrowWriter<File>,
    with_is_admin: bool,
    buffer: Vec<IdentityRow>,
    rows: u64,
    last: Option<(String, String)>,
}

impl SortedWriter {
    fn create(path: &Path, with_is_admin: bool) -> Result<Self> {
        let properties = WriterProperties::builder()
            .set_compression(Compression::ZSTD(ZstdLevel::try_new(3)?))
            .set_max_row_group_row_count(Some(BATCH_ROWS))
            .build();
        Ok(Self {
            path: path.to_path_buf(),
            writer: ArrowWriter::try_new(
                File::create(path)?,
                file_schema(with_is_admin),
                Some(properties),
            )?,
            with_is_admin,
            buffer: Vec::with_capacity(BATCH_ROWS),
            rows: 0,
            last: None,
        })
    }

    fn push(&mut self, row: IdentityRow) -> Result<()> {
        if let Some((feed, external)) = &self.last {
            ensure!(
                (feed.as_str(), external.as_str()) < row.key(),
                "identity rows are not strictly ascending by (feed_id, external_id)"
            );
        }
        self.rows += 1;
        ensure!(
            self.rows <= IDENTITY_MAX_ROWS,
            "identity directory exceeds its row cap"
        );
        self.last = Some((row.feed_id.clone(), row.external_id.clone()));
        self.buffer.push(row);
        if self.buffer.len() >= BATCH_ROWS {
            self.flush()?;
        }
        Ok(())
    }

    fn flush(&mut self) -> Result<()> {
        if !self.buffer.is_empty() {
            self.writer.write(&encode(&self.buffer, self.with_is_admin)?)?;
            self.buffer.clear();
        }
        Ok(())
    }

    fn finish(mut self) -> Result<FileRef> {
        self.flush()?;
        self.writer.close()?;
        File::open(&self.path)?.sync_all()?;
        let (sha256, bytes) = hash_file(&self.path)?;
        ensure!(
            bytes <= IDENTITY_MAX_FILE_BYTES,
            "identity file exceeds its size cap"
        );
        Ok(FileRef {
            sha256,
            bytes,
            rows: self.rows,
        })
    }
}

fn hash_file(path: &Path) -> Result<(String, u64)> {
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0u8; 1 << 20];
    let mut bytes = 0u64;
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        bytes += read as u64;
        hasher.update(&buffer[..read]);
    }
    Ok((hex::encode(hasher.finalize()), bytes))
}

/// Validate, sort and de-duplicate one batch of rows, then write it as one
/// sorted file (a delta or a staged replacement chunk). Duplicate keys keep
/// the highest version, the later row on a tie.
pub fn write_sorted_rows(path: &Path, mut rows: Vec<IdentityRow>) -> Result<FileRef> {
    if rows.is_empty() {
        return Err(IdentityStoreError::Invalid("identity batch is empty".into()).into());
    }
    if rows.len() > IDENTITY_MAX_BATCH_ROWS {
        return Err(IdentityStoreError::TooLarge(format!(
            "identity batch exceeds the {IDENTITY_MAX_BATCH_ROWS} row cap"
        ))
        .into());
    }
    for row in &rows {
        row.validate()
            .map_err(|error| IdentityStoreError::Invalid(error.to_string()))?;
    }
    // Stable sort keeps arrival order within a key; the dedup below then
    // keeps the last of the highest versions.
    rows.sort_by(|a, b| a.key().cmp(&b.key()));
    let with_is_admin = rows.iter().any(|row| row.is_admin.is_some());
    let mut writer = SortedWriter::create(path, with_is_admin)?;
    let mut pending: Option<IdentityRow> = None;
    for row in rows {
        match pending.take() {
            Some(current) if current.key() == row.key() => {
                pending = Some(if row.version >= current.version {
                    row
                } else {
                    current
                });
            }
            Some(current) => {
                writer.push(current)?;
                pending = Some(row);
            }
            None => pending = Some(row),
        }
    }
    if let Some(row) = pending {
        writer.push(row)?;
    }
    writer.finish()
}

/// One sorted input of a merge. Ascending order is verified as rows stream.
struct RowStream {
    reader: ParquetRecordBatchReader,
    buffer: std::vec::IntoIter<IdentityRow>,
    head: Option<IdentityRow>,
    previous: Option<(String, String)>,
    /// Rows of the replaced/deleted feed from this input are discarded.
    droppable: bool,
    /// The file carries the `is_admin` column.
    has_is_admin: bool,
}

impl RowStream {
    fn open(path: &Path, droppable: bool) -> Result<Self> {
        let builder = ParquetRecordBatchReaderBuilder::try_new(File::open(path)?)?;
        let has_is_admin = schema_has_is_admin(builder.schema().fields())
            .context("identity Parquet schema differs from the expected schema")?;
        let reader = builder.with_batch_size(BATCH_ROWS).build()?;
        let mut stream = Self {
            reader,
            buffer: Vec::new().into_iter(),
            head: None,
            previous: None,
            droppable,
            has_is_admin,
        };
        stream.advance()?;
        Ok(stream)
    }

    fn advance(&mut self) -> Result<Option<IdentityRow>> {
        let taken = self.head.take();
        loop {
            if let Some(row) = self.buffer.next() {
                if let Some((feed, external)) = &self.previous {
                    ensure!(
                        (feed.as_str(), external.as_str()) < row.key(),
                        "identity file is not strictly ascending"
                    );
                }
                self.previous = Some((row.feed_id.clone(), row.external_id.clone()));
                self.head = Some(row);
                break;
            }
            match self.reader.next() {
                Some(batch) => self.buffer = decode(&batch?)?.into_iter(),
                None => break,
            }
        }
        Ok(taken)
    }
}

/// Streaming k-way merge of sorted identity files into one sorted file
/// without tombstones. Inputs are ordered by precedence: on equal versions the
/// later input wins. `drop_feed` discards that feed's rows from every
/// `droppable` input (a feed replacement or deletion).
fn merge_files(inputs: &[(PathBuf, bool)], drop_feed: Option<&str>, out: &Path) -> Result<FileRef> {
    let mut streams = inputs
        .iter()
        .map(|(path, droppable)| RowStream::open(path, *droppable))
        .collect::<Result<Vec<_>>>()?;
    // Only an input with the column can contribute an `is_admin` value.
    let with_is_admin = streams.iter().any(|stream| stream.has_is_admin);
    let mut writer = SortedWriter::create(out, with_is_admin)?;
    loop {
        let Some(min) = streams
            .iter()
            .filter_map(|stream| {
                stream
                    .head
                    .as_ref()
                    .map(|row| (row.feed_id.clone(), row.external_id.clone()))
            })
            .min()
        else {
            break;
        };
        let mut best: Option<IdentityRow> = None;
        for stream in &mut streams {
            let matches = stream
                .head
                .as_ref()
                .is_some_and(|row| row.feed_id == min.0 && row.external_id == min.1);
            if !matches {
                continue;
            }
            let row = stream.advance()?.expect("matched head");
            if stream.droppable && drop_feed == Some(row.feed_id.as_str()) {
                continue;
            }
            if best
                .as_ref()
                .is_none_or(|current| row.version >= current.version)
            {
                best = Some(row);
            }
        }
        if let Some(row) = best.filter(|row| !row.deleted) {
            writer.push(row)?;
        }
    }
    writer.finish()
}

// ---------------------------------------------------------------------------
// Manifest and object layout
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum FileKind {
    Snapshot,
    Delta,
}

impl FileKind {
    fn dir(self) -> &'static str {
        match self {
            Self::Snapshot => "snapshots",
            Self::Delta => "deltas",
        }
    }
}

fn object_key(kind: FileKind, sha256: &str) -> String {
    format!("{NAMESPACE}/{}/{sha256}.parquet", kind.dir())
}

fn pointer_key() -> String {
    format!("{NAMESPACE}/current.json")
}

fn revision_key(revision: Uuid) -> String {
    format!("{NAMESPACE}/revisions/{revision}.json")
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(deny_unknown_fields)]
pub struct RetiredFile {
    pub kind: FileKind,
    pub sha256: String,
}

/// One immutable directory revision: a base snapshot plus ordered deltas.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct IdentityManifest {
    pub schema_version: u32,
    pub tenant_id: Uuid,
    pub revision: Uuid,
    pub snapshot: Option<FileRef>,
    pub deltas: Vec<FileRef>,
    /// Files the previous revision referenced and this one does not. They are
    /// deleted when the *next* revision is published, so a reader pinned to
    /// the previous revision keeps one generation of grace.
    #[serde(default)]
    pub retired: Vec<RetiredFile>,
}

impl IdentityManifest {
    fn check(&self, tenant_id: Uuid) -> Result<()> {
        ensure!(
            self.schema_version == MANIFEST_SCHEMA_VERSION,
            "identity manifest schema version is unsupported"
        );
        ensure!(
            self.tenant_id == tenant_id,
            "identity manifest tenant differs from process tenant"
        );
        if let Some(snapshot) = &self.snapshot {
            snapshot.check()?;
        }
        for delta in &self.deltas {
            delta.check()?;
        }
        ensure!(
            self.deltas.len() <= 4 * COMPACT_AFTER_DELTAS,
            "identity manifest has too many deltas"
        );
        Ok(())
    }

    fn referenced(&self) -> BTreeSet<RetiredFile> {
        let mut files = BTreeSet::new();
        if let Some(snapshot) = &self.snapshot {
            files.insert(RetiredFile {
                kind: FileKind::Snapshot,
                sha256: snapshot.sha256.clone(),
            });
        }
        for delta in &self.deltas {
            files.insert(RetiredFile {
                kind: FileKind::Delta,
                sha256: delta.sha256.clone(),
            });
        }
        files
    }

    /// Upper bound on live rows (deltas may update or delete snapshot rows).
    pub fn row_upper_bound(&self) -> u64 {
        self.snapshot.as_ref().map_or(0, |s| s.rows)
            + self.deltas.iter().map(|d| d.rows).sum::<u64>()
    }

    pub fn needs_compaction(&self) -> bool {
        self.deltas.len() > COMPACT_AFTER_DELTAS
            || self.deltas.iter().map(|d| d.bytes).sum::<u64>() > COMPACT_AFTER_DELTA_BYTES
    }
}

/// What a publication did, for callers and logs.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct IdentityPublication {
    pub manifest: IdentityManifest,
    /// False when the requested change produced the current content again.
    pub changed: bool,
    pub compacted: bool,
}

// ---------------------------------------------------------------------------
// Store
// ---------------------------------------------------------------------------

/// The tenant identity store. `objects` must be rooted at exactly this
/// tenant's enrichment prefix; the coordinator is its only writer.
pub struct IdentityStore<'a> {
    tenant_id: Uuid,
    objects: &'a dyn ObjectStore,
    scratch: PathBuf,
    publication_lock: tokio::sync::Mutex<()>,
}

impl<'a> IdentityStore<'a> {
    pub fn new(tenant_id: Uuid, objects: &'a dyn ObjectStore, scratch: &Path) -> Result<Self> {
        ensure!(!tenant_id.is_nil(), "identity store tenant is nil");
        ensure!(
            scratch.is_absolute(),
            "identity scratch directory must be absolute"
        );
        let scratch = scratch.join(NAMESPACE);
        std::fs::create_dir_all(&scratch)?;
        Ok(Self {
            tenant_id,
            objects,
            scratch,
            publication_lock: tokio::sync::Mutex::new(()),
        })
    }

    pub fn scratch(&self) -> &Path {
        &self.scratch
    }

    pub async fn current(&self) -> Result<Option<IdentityManifest>> {
        let Some(bytes) = self.objects.get(&pointer_key()).await? else {
            return Ok(None);
        };
        ensure!(bytes.len() <= 64 * 1024, "identity pointer is oversized");
        let manifest: IdentityManifest = serde_json::from_slice(&bytes)?;
        manifest.check(self.tenant_id)?;
        Ok(Some(manifest))
    }

    /// Pin one revision: the durable revision record must equal `expected`.
    async fn pin(&self, expected: &IdentityManifest) -> Result<()> {
        expected.check(self.tenant_id)?;
        let recorded = self
            .objects
            .get(&revision_key(expected.revision))
            .await?
            .context("pinned identity revision is missing")?;
        let recorded: IdentityManifest = serde_json::from_slice(&recorded)?;
        ensure!(
            &recorded == expected,
            "pinned identity revision differs from the durable record"
        );
        Ok(())
    }

    /// Download one referenced file into the scratch cache once, verifying
    /// its size and digest before it becomes a cache hit.
    async fn fetch(&self, kind: FileKind, file: &FileRef) -> Result<PathBuf> {
        file.check()?;
        let path = self
            .scratch
            .join(format!("{}-{}.parquet", kind.dir(), file.sha256));
        if path.exists() && std::fs::metadata(&path)?.len() == file.bytes {
            return Ok(path);
        }
        let temporary = self.scratch.join(format!(".fetch-{}", Uuid::new_v4()));
        if !self
            .objects
            .get_to_file(&object_key(kind, &file.sha256), &temporary)
            .await?
        {
            bail!("pinned identity {} is missing", kind.dir());
        }
        let hashed = temporary.clone();
        let (sha256, bytes) = tokio::task::spawn_blocking(move || hash_file(&hashed))
            .await
            .context("identity hash task")??;
        if sha256 != file.sha256 || bytes != file.bytes {
            let _ = std::fs::remove_file(&temporary);
            bail!("identity {} differs from its manifest entry", kind.dir());
        }
        std::fs::rename(&temporary, &path)?;
        Ok(path)
    }

    async fn inputs(&self, manifest: &IdentityManifest) -> Result<Vec<(PathBuf, bool)>> {
        let mut inputs = Vec::with_capacity(1 + manifest.deltas.len());
        if let Some(snapshot) = &manifest.snapshot {
            inputs.push((self.fetch(FileKind::Snapshot, snapshot).await?, true));
        }
        for delta in &manifest.deltas {
            inputs.push((self.fetch(FileKind::Delta, delta).await?, true));
        }
        Ok(inputs)
    }

    async fn upload(&self, kind: FileKind, path: &Path, file: &FileRef) -> Result<()> {
        let body = std::fs::read(path)?;
        ensure!(
            body.len() as u64 == file.bytes,
            "identity file changed before upload"
        );
        // Content-addressed: an existing object under this digest has these bytes.
        self.objects
            .put_if_absent(&object_key(kind, &file.sha256), &body)
            .await?;
        Ok(())
    }

    /// Write the revision record, advance the pointer, then delete the files
    /// the previous revision had already retired.
    async fn publish(
        &self,
        previous: Option<&IdentityManifest>,
        snapshot: Option<FileRef>,
        deltas: Vec<FileRef>,
    ) -> Result<IdentityManifest> {
        let mut manifest = IdentityManifest {
            schema_version: MANIFEST_SCHEMA_VERSION,
            tenant_id: self.tenant_id,
            revision: Uuid::now_v7(),
            snapshot,
            deltas,
            retired: Vec::new(),
        };
        let referenced = manifest.referenced();
        if let Some(previous) = previous {
            manifest.retired = previous
                .referenced()
                .into_iter()
                .filter(|file| !referenced.contains(file))
                .collect();
        }
        manifest.check(self.tenant_id)?;
        let body = serde_json::to_vec(&manifest)?;
        ensure!(
            self.objects
                .put_if_absent(&revision_key(manifest.revision), &body)
                .await?,
            "identity revision collision"
        );
        self.objects.put(&pointer_key(), &body).await?;
        if let Some(previous) = previous {
            for file in &previous.retired {
                if referenced.contains(file) {
                    continue;
                }
                if let Err(error) = self
                    .objects
                    .delete(&object_key(file.kind, &file.sha256))
                    .await
                {
                    tracing::warn!(error = %error, sha256 = %file.sha256, "retired identity file was not deleted");
                }
            }
        }
        Ok(manifest)
    }

    fn check_expected(current: &Option<IdentityManifest>, expected: Option<Uuid>) -> Result<()> {
        if current.as_ref().map(|m| m.revision) != expected {
            return Err(IdentityStoreError::Conflict.into());
        }
        Ok(())
    }

    /// Append one delta (adds, updates and tombstones of any feeds). Compacts
    /// when the manifest crosses the delta thresholds.
    pub async fn append_delta(
        &self,
        expected: Option<Uuid>,
        rows: Vec<IdentityRow>,
    ) -> Result<IdentityPublication> {
        let _guard = self.publication_lock.lock().await;
        let current = self.current().await?;
        Self::check_expected(&current, expected)?;
        let temporary = self
            .scratch
            .join(format!(".delta-{}.parquet", Uuid::new_v4()));
        let result = async {
            let delta = write_sorted_rows(&temporary, rows)?;
            let mut deltas = current
                .as_ref()
                .map(|m| m.deltas.clone())
                .unwrap_or_default();
            if current.as_ref().map_or(0, |m| m.row_upper_bound()) + delta.rows
                > IDENTITY_MAX_ROWS + IDENTITY_MAX_BATCH_ROWS as u64
            {
                return Err(
                    IdentityStoreError::TooLarge("identity directory row cap".into()).into(),
                );
            }
            self.upload(FileKind::Delta, &temporary, &delta).await?;
            deltas.push(delta);
            let snapshot = current.as_ref().and_then(|m| m.snapshot.clone());
            let manifest = self.publish(current.as_ref(), snapshot, deltas).await?;
            if manifest.needs_compaction() {
                // The delta is already durable; a failed compaction is retried
                // on the next append instead of failing this one (a caller
                // retry would only replay an idempotent delta).
                match self.compact_locked(&manifest).await {
                    Ok(compacted) => {
                        return Ok(IdentityPublication {
                            manifest: compacted,
                            changed: true,
                            compacted: true,
                        })
                    }
                    Err(error) => {
                        tracing::warn!(error = %format!("{error:#}"), "identity compaction failed; retried on the next append")
                    }
                }
            }
            Ok(IdentityPublication {
                manifest,
                changed: true,
                compacted: false,
            })
        }
        .await;
        let _ = std::fs::remove_file(&temporary);
        result
    }

    /// Prepare delta `rows` against the `current` revision (NAN-3503):
    /// with `patch`, every live row is filled from the current row of its
    /// key ([`IdentityRow::fill_from`]); each [`ManagerRef`] then sets its
    /// row's `manager_upn` to the manager's reference, taken from the same
    /// request first, else from `current`. An unresolvable manager leaves
    /// `manager_upn` as sent (with `patch`, the current value). Tombstones
    /// pass through unchanged. Only the keys involved are kept in memory;
    /// the merged view is streamed.
    pub async fn prepare_delta(
        &self,
        current: Option<&IdentityManifest>,
        mut rows: Vec<IdentityRow>,
        patch: bool,
        refs: &[ManagerRef],
    ) -> Result<Vec<IdentityRow>> {
        let invalid = |what: &str| IdentityStoreError::Invalid(what.into());
        if refs.len() > rows.len() {
            return Err(invalid("more manager references than rows").into());
        }
        let mut live: std::collections::HashMap<(String, String), Vec<usize>> =
            std::collections::HashMap::new();
        let mut gone: std::collections::HashSet<(String, String)> = Default::default();
        for (index, row) in rows.iter().enumerate() {
            let key = (row.feed_id.clone(), row.external_id.clone());
            if row.deleted {
                gone.insert(key);
            } else {
                live.entry(key).or_default().push(index);
            }
        }
        for r in refs {
            if validate_feed_id(&r.feed_id).is_err()
                || !valid_text(&r.manager_external_id)
                || r.manager_external_id.is_empty()
                || r.manager_external_id.len() > 1024
            {
                return Err(invalid("a manager reference is invalid").into());
            }
            if !live.contains_key(&(r.feed_id.clone(), r.external_id.clone())) {
                return Err(invalid("a manager reference names no live row of the request").into());
            }
        }
        let mut wanted: std::collections::HashSet<(String, String)> = Default::default();
        if patch {
            wanted.extend(live.keys().cloned());
        }
        for r in refs {
            let key = (r.feed_id.clone(), r.manager_external_id.clone());
            if !live.contains_key(&key) && !gone.contains(&key) {
                wanted.insert(key);
            }
        }
        let mut existing: std::collections::HashMap<(String, String), IdentityRow> =
            std::collections::HashMap::new();
        if let (Some(manifest), false) = (current, wanted.is_empty()) {
            let path = self.materialize(manifest).await?;
            existing = tokio::task::spawn_blocking(move || {
                let mut found = std::collections::HashMap::new();
                for_each_merged_row(&path, |row| {
                    let key = (row.feed_id.clone(), row.external_id.clone());
                    if wanted.contains(&key) {
                        found.insert(key, row);
                    }
                })?;
                Ok::<_, anyhow::Error>(found)
            })
            .await
            .context("identity patch task")??;
        }
        if patch {
            for (key, indexes) in &live {
                if let Some(old) = existing.get(key) {
                    for index in indexes {
                        rows[*index].fill_from(old);
                    }
                }
            }
        }
        let mut resolved = Vec::new();
        for r in refs {
            let manager = (r.feed_id.clone(), r.manager_external_id.clone());
            let reference = match live.get(&manager) {
                Some(indexes) => indexes
                    .last()
                    .and_then(|index| rows[*index].reference())
                    .map(str::to_string),
                None => existing
                    .get(&manager)
                    .and_then(|row| row.reference())
                    .map(str::to_string),
            };
            if let Some(reference) = reference {
                resolved.push(((r.feed_id.clone(), r.external_id.clone()), reference));
            }
        }
        for (key, reference) in resolved {
            for index in &live[&key] {
                rows[*index].manager_upn.clone_from(&reference);
            }
        }
        Ok(rows)
    }

    /// Fold every delta into a new snapshot.
    pub async fn compact(&self, expected: Option<Uuid>) -> Result<IdentityPublication> {
        let _guard = self.publication_lock.lock().await;
        let current = self.current().await?;
        Self::check_expected(&current, expected)?;
        let Some(current) = current else {
            bail!("identity directory is empty");
        };
        if current.deltas.is_empty() {
            return Ok(IdentityPublication {
                manifest: current,
                changed: false,
                compacted: false,
            });
        }
        let manifest = self.compact_locked(&current).await?;
        Ok(IdentityPublication {
            manifest,
            changed: true,
            compacted: true,
        })
    }

    async fn compact_locked(&self, current: &IdentityManifest) -> Result<IdentityManifest> {
        self.rewrite(current, None, &[])
            .await
            .map(|(manifest, _)| manifest)
    }

    /// Make `feed_id`'s rows exactly the rows in `staged` (sorted chunk files
    /// from [`write_sorted_rows`]); other feeds are untouched. Producing the
    /// current content again publishes nothing.
    pub async fn replace_feed(
        &self,
        expected: Option<Uuid>,
        feed_id: &str,
        staged: &[PathBuf],
    ) -> Result<IdentityPublication> {
        validate_feed_id(feed_id)
            .map_err(|error| IdentityStoreError::Invalid(error.to_string()))?;
        let _guard = self.publication_lock.lock().await;
        let current = self.current().await?;
        Self::check_expected(&current, expected)?;
        for chunk in staged {
            let mut stream = RowStream::open(chunk, false)?;
            while let Some(row) = stream.advance()? {
                if row.feed_id != feed_id {
                    return Err(IdentityStoreError::Invalid(
                        "staged identity rows belong to another feed".into(),
                    )
                    .into());
                }
            }
        }
        let base = current.clone().unwrap_or_else(|| self.empty_manifest());
        let (manifest, changed) = self.rewrite(&base, Some(feed_id), staged).await?;
        let compacted = changed;
        Ok(IdentityPublication {
            manifest,
            changed,
            compacted,
        })
    }

    /// Remove every row of `feed_id`.
    pub async fn delete_feed(
        &self,
        expected: Option<Uuid>,
        feed_id: &str,
    ) -> Result<IdentityPublication> {
        self.replace_feed(expected, feed_id, &[]).await
    }

    fn empty_manifest(&self) -> IdentityManifest {
        IdentityManifest {
            schema_version: MANIFEST_SCHEMA_VERSION,
            tenant_id: self.tenant_id,
            revision: Uuid::nil(),
            snapshot: None,
            deltas: Vec::new(),
            retired: Vec::new(),
        }
    }

    /// Merge `base` (+ `extra` inputs) into a new snapshot and publish it,
    /// unless the result equals `base`'s snapshot with no deltas.
    async fn rewrite(
        &self,
        base: &IdentityManifest,
        drop_feed: Option<&str>,
        extra: &[PathBuf],
    ) -> Result<(IdentityManifest, bool)> {
        let mut inputs = self.inputs(base).await?;
        inputs.extend(extra.iter().map(|path| (path.clone(), false)));
        let temporary = self
            .scratch
            .join(format!(".snapshot-{}.parquet", Uuid::new_v4()));
        let result = async {
            let snapshot = merge_files(&inputs, drop_feed, &temporary)?;
            let previous = (!base.revision.is_nil()).then_some(base);
            if previous.is_some()
                && base.deltas.is_empty()
                && base.snapshot.as_ref().map(|s| &s.sha256) == Some(&snapshot.sha256)
            {
                return Ok((base.clone(), false));
            }
            if previous.is_none() && snapshot.rows == 0 {
                bail!("identity replacement produced an empty directory with no prior revision");
            }
            self.upload(FileKind::Snapshot, &temporary, &snapshot)
                .await?;
            let manifest = self.publish(previous, Some(snapshot), Vec::new()).await?;
            Ok((manifest, true))
        }
        .await;
        let _ = std::fs::remove_file(&temporary);
        result
    }

    /// Materialize a pinned revision as one merged, tombstone-free Parquet
    /// file and open it for reads. The file is cached per revision and is the
    /// `file(…, Parquet)` input for chDB joins.
    pub async fn load_view(&self, manifest: &IdentityManifest) -> Result<IdentityView> {
        let path = self.materialize(manifest).await?;
        IdentityView::open(manifest.revision, &path)
    }

    /// The pinned revision as one merged, tombstone-free, sorted Parquet file
    /// in the scratch cache (built once per revision). Stream it with
    /// [`for_each_merged_row`] when the whole view need not be resident.
    pub async fn materialize(&self, manifest: &IdentityManifest) -> Result<PathBuf> {
        self.pin(manifest).await?;
        let path = self
            .scratch
            .join(format!("view-{}.parquet", manifest.revision));
        if !path.exists() {
            let inputs = self.inputs(manifest).await?;
            let temporary = self
                .scratch
                .join(format!(".view-{}.parquet", Uuid::new_v4()));
            // CPU- and file-bound for seconds on a large directory: never on
            // an async worker thread.
            let (merge_temporary, merge_path) = (temporary.clone(), path.clone());
            let merged = tokio::task::spawn_blocking(move || {
                merge_files(&inputs, None, &merge_temporary)?;
                std::fs::rename(&merge_temporary, &merge_path)?;
                Ok::<_, anyhow::Error>(())
            })
            .await
            .context("identity merge task");
            if let Err(error) = merged.and_then(|merged| merged) {
                let _ = std::fs::remove_file(&temporary);
                return Err(error);
            }
        }
        self.prune_scratch(manifest);
        Ok(path)
    }

    /// Drop cached files this revision no longer references.
    fn prune_scratch(&self, manifest: &IdentityManifest) {
        let keep: BTreeSet<String> = manifest
            .referenced()
            .into_iter()
            .map(|file| format!("{}-{}.parquet", file.kind.dir(), file.sha256))
            .chain([format!("view-{}.parquet", manifest.revision)])
            .collect();
        let Ok(entries) = std::fs::read_dir(&self.scratch) else {
            return;
        };
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            let cached = name.starts_with("view-")
                || name.starts_with("snapshots-")
                || name.starts_with("deltas-");
            if cached && !keep.contains(&name) {
                let _ = std::fs::remove_file(entry.path());
            }
        }
    }
}

/// Stream every row of a merged identity file (from
/// [`IdentityStore::materialize`]) in key order, one row group resident at a
/// time.
pub fn for_each_merged_row(path: &Path, mut each: impl FnMut(IdentityRow)) -> Result<()> {
    let mut stream = RowStream::open(path, false)?;
    while let Some(row) = stream.advance()? {
        each(row);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Read view
// ---------------------------------------------------------------------------

/// Filters for [`IdentityView::list`].
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ListFilter {
    #[serde(default)]
    pub search: Option<String>,
    #[serde(default)]
    pub feed_id: Option<String>,
    #[serde(default)]
    pub source_kind: Option<SourceKind>,
    #[serde(default)]
    pub account_status: Option<String>,
}

#[derive(Clone, Debug, Default, Serialize, PartialEq, Eq)]
pub struct IdentityStats {
    pub total: u64,
    pub by_feed: BTreeMap<String, u64>,
    pub by_source_kind: BTreeMap<String, u64>,
    pub by_account_status: BTreeMap<String, u64>,
}

/// A merged, tombstone-free directory revision held column-wise in memory.
pub struct IdentityView {
    revision: Uuid,
    path: PathBuf,
    batches: Vec<RecordBatch>,
    /// Cumulative row offsets: `offsets[i]` is the first global row of batch `i`.
    offsets: Vec<usize>,
    rows: usize,
}

impl IdentityView {
    fn open(revision: Uuid, path: &Path) -> Result<Self> {
        let reader = ParquetRecordBatchReaderBuilder::try_new(File::open(path)?)?
            .with_batch_size(BATCH_ROWS)
            .build()?;
        let mut batches = Vec::new();
        let mut offsets = Vec::new();
        let mut rows = 0usize;
        for batch in reader {
            let batch = batch?;
            Columns::new(&batch)?;
            offsets.push(rows);
            rows += batch.num_rows();
            batches.push(batch);
        }
        Ok(Self {
            revision,
            path: path.to_path_buf(),
            batches,
            offsets,
            rows,
        })
    }

    pub fn revision(&self) -> Uuid {
        self.revision
    }

    /// The merged Parquet file, for chDB `file(…, Parquet)` joins.
    pub fn merged_path(&self) -> &Path {
        &self.path
    }

    pub fn len(&self) -> usize {
        self.rows
    }

    pub fn is_empty(&self) -> bool {
        self.rows == 0
    }

    fn locate(&self, global: usize) -> (usize, usize) {
        let batch = self.offsets.partition_point(|offset| *offset <= global) - 1;
        (batch, global - self.offsets[batch])
    }

    fn text_at(&self, global: usize, name: &str) -> &str {
        let (batch, index) = self.locate(global);
        self.batches[batch]
            .column_by_name(name)
            .and_then(|column| column.as_any().downcast_ref::<StringArray>())
            .expect("identity schema checked")
            .value(index)
    }

    pub fn row(&self, global: usize) -> Result<IdentityRow> {
        ensure!(global < self.rows, "identity row index out of range");
        let (batch, index) = self.locate(global);
        Columns::new(&self.batches[batch])?.row(index)
    }

    /// Exact key lookup (rows are sorted, so this is a binary search).
    pub fn get(&self, feed_id: &str, external_id: &str) -> Result<Option<IdentityRow>> {
        let target = (feed_id, external_id);
        let (mut low, mut high) = (0usize, self.rows);
        while low < high {
            let mid = (low + high) / 2;
            let key = (
                self.text_at(mid, "feed_id"),
                self.text_at(mid, "external_id"),
            );
            match key.cmp(&target) {
                Ordering::Less => low = mid + 1,
                Ordering::Greater => high = mid,
                Ordering::Equal => return self.row(mid).map(Some),
            }
        }
        Ok(None)
    }

    /// Every row (any feed) whose email, upn or username equals `value`,
    /// case-insensitively. These rows are the inputs to the provenance merge.
    pub fn lookup(&self, value: &str) -> Result<Vec<IdentityRow>> {
        let value = value.trim();
        if value.is_empty() {
            return Ok(Vec::new());
        }
        let mut found = Vec::new();
        for (batch_index, batch) in self.batches.iter().enumerate() {
            let column = |name: &str| {
                batch
                    .column_by_name(name)
                    .and_then(|column| column.as_any().downcast_ref::<StringArray>())
                    .expect("identity schema checked")
            };
            let (email, upn, username) = (column("email"), column("upn"), column("username"));
            for index in 0..batch.num_rows() {
                if email.value(index).eq_ignore_ascii_case(value)
                    || upn.value(index).eq_ignore_ascii_case(value)
                    || username.value(index).eq_ignore_ascii_case(value)
                {
                    found.push(self.row(self.offsets[batch_index] + index)?);
                }
            }
        }
        Ok(found)
    }

    /// Filtered page plus the filtered total.
    pub fn list(
        &self,
        filter: &ListFilter,
        offset: usize,
        limit: usize,
    ) -> Result<(usize, Vec<IdentityRow>)> {
        let search = filter
            .search
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_lowercase);
        let mut total = 0usize;
        let mut page = Vec::new();
        for (batch_index, batch) in self.batches.iter().enumerate() {
            let column = |name: &str| {
                batch
                    .column_by_name(name)
                    .and_then(|column| column.as_any().downcast_ref::<StringArray>())
                    .expect("identity schema checked")
            };
            let feed = column("feed_id");
            let kind = column("source_kind");
            let status = column("account_status");
            let searched = [
                column("username"),
                column("upn"),
                column("email"),
                column("display_name"),
                column("external_id"),
            ];
            for index in 0..batch.num_rows() {
                if filter
                    .feed_id
                    .as_deref()
                    .is_some_and(|f| feed.value(index) != f)
                    || filter
                        .source_kind
                        .is_some_and(|k| kind.value(index) != k.as_str())
                    || filter
                        .account_status
                        .as_deref()
                        .is_some_and(|s| status.value(index) != s)
                {
                    continue;
                }
                if let Some(search) = &search {
                    if !searched
                        .iter()
                        .any(|column| column.value(index).to_lowercase().contains(search.as_str()))
                    {
                        continue;
                    }
                }
                if total >= offset && page.len() < limit {
                    page.push(self.row(self.offsets[batch_index] + index)?);
                }
                total += 1;
            }
        }
        Ok((total, page))
    }

    pub fn stats(&self) -> IdentityStats {
        let mut stats = IdentityStats {
            total: self.rows as u64,
            ..Default::default()
        };
        for batch in &self.batches {
            let column = |name: &str| {
                batch
                    .column_by_name(name)
                    .and_then(|column| column.as_any().downcast_ref::<StringArray>())
                    .expect("identity schema checked")
            };
            let (feed, kind, status) = (
                column("feed_id"),
                column("source_kind"),
                column("account_status"),
            );
            for index in 0..batch.num_rows() {
                *stats
                    .by_feed
                    .entry(feed.value(index).to_string())
                    .or_default() += 1;
                *stats
                    .by_source_kind
                    .entry(kind.value(index).to_string())
                    .or_default() += 1;
                *stats
                    .by_account_status
                    .entry(status.value(index).to_string())
                    .or_default() += 1;
            }
        }
        stats
    }
}

#[cfg(test)]
#[path = "lean_identity_snapshot_tests.rs"]
mod tests;
