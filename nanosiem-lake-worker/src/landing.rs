// SPDX-License-Identifier: AGPL-3.0-or-later

//! OCSF bucket drop (NAN-3807, open core).
//!
//! A sender that already maps to OCSF 1.9 (Tenzir) writes plain OCSF files
//! straight into the install's object store:
//!
//! ```text
//! landing-ocsf-v1/tenant_id=<T>/source=<source_id>/<any path>.parquet | .ndjson[.gz] | .jsonl[.gz]
//! ```
//!
//! Each source has its own write-only object-store user whose policy allows
//! `s3:PutObject` under its own folder only, so the folder decides the
//! source (NAN-3806: the credential decides, never the rows).
//!
//! The landing converter turns every landed file into ordinary bronze:
//!
//! 1. **Claim.** Every object listed under the landing prefix is claimed once
//!    per `(key, etag)` in the Postgres ledger (`landing_files`), with a lease.
//!    There is no time watermark, so a late or out-of-order key is still
//!    picked up. The same `(key, etag)` written again after it finished is
//!    deleted without reconverting.
//! 2. **Convert.** Rows are read the way bronze admission reads Parquet (Arrow
//!    → newline-delimited JSON) and run through Vector's own
//!    `ocsf_lake_storage_prepare` VRL ([`LandingOcsfStage`]), with the folder's
//!    source, the tenant, the source's credential id and the `landing_bucket`
//!    lane stamped. A row without `metadata.uid` gets one derived from the
//!    file's SHA-256 and its ordinal, so a reconverted or re-uploaded file
//!    yields the same uids. Steps 2-4 stream [`ROW_CHUNK`] rows at a time
//!    (NAN-4319): memory does not grow with the file's row count.
//! 3. **Pre-check.** Each row goes through the same checks bronze admission
//!    runs ([`crate::bronze::precheck_source_row`]: strict OCSF 1.9 included).
//!    Refused rows are counted by value-free reason and left out.
//! 4. **Write.** The accepted rows become bronze objects per bronze shard of
//!    at most [`MAX_OBJECT_ROWS`] rows / [`MAX_OBJECT_EVENT_BYTES`] (Vector's
//!    bronze batch), `bronze-v2/[shard=N/]tenant_id=<T>/<unix secs>-<uuid>.parquet`, with the
//!    fixed bronze row contract (`time` + `_nano_bronze_event`). Part ingest
//!    then admits it like any Vector object: IPinfo / IOC / identity /
//!    prevalence / platform stamping, the uid window, parts.
//! 5. **Finish.** The landed object is deleted (accepted) or moved under
//!    `landing-ocsf-v1-refused/` (refused whole), and the ledger row records
//!    rows accepted / refused and the first reason.
//!
//! A bad file is refused whole and moved aside; an object-store or database
//! outage leaves the lease to expire and the file is retried; a file that
//! keeps failing is refused after [`MAX_ATTEMPTS`]. One file never blocks
//! another: a tick handles up to [`landing_concurrency`] files at once, each
//! converted on a blocking thread (NAN-4682), every one under its own claim.
//!
//! Hosted tenants (NAN-3885 / NAN-4137) run the same conversion in the
//! `landing[T]` lake-cell child behind two traits: [`Discover`] (here the
//! prefix listing plus the Postgres ledger; hosted, a lease from the
//! tenant's landing-ledger Durable Object) and [`Emit`] (here `bronze-v2/`
//! objects; hosted, appends to the tenant edge log). See
//! [`crate::landing_hosted`].

use anyhow::{Context, Result};
use arrow_array::cast::AsArray;
use arrow_array::types::UInt8Type;
use arrow_array::{
    Array, ArrayRef, FixedSizeListArray, LargeListArray, ListArray, MapArray, RecordBatch, RecordBatchOptions,
    StringArray, StructArray, TimestampMicrosecondArray,
};
use arrow_json::LineDelimitedWriter;
use arrow_schema::{ArrowError, DataType, Field, FieldRef, Fields, Schema, TimeUnit};
use async_trait::async_trait;
use bytes::Bytes;
use chrono::{DateTime, NaiveDateTime, Utc};
use nanosiem_core::parsers::landing_ocsf::{BronzeRow, LandingOcsfStage, StageContext};
use nanosiem_core::parsers::lake_bronze_row::{BRONZE_EVENT_COLUMN, BRONZE_TIME_COLUMN};
use opendal::Operator;
use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;
use parquet::arrow::ArrowWriter;
use parquet::basic::{Compression, ZstdLevel};
use parquet::file::properties::WriterProperties;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::io::{BufRead, Read};
use std::net::Ipv6Addr;
use std::sync::Arc;
use uuid::Uuid;

use crate::bronze::{decode_bronze_row, precheck_source_row, RowRefusal, MAX_BRONZE_ROWS};

/// The landing prefix (bucket-relative, no leading slash).
pub const LANDING_PREFIX: &str = "landing-ocsf-v1/";
/// Where a file refused whole is moved (outside every sender's policy).
pub const REFUSED_PREFIX: &str = "landing-ocsf-v1-refused/";
/// The bronze prefix part ingest lists.
pub const BRONZE_PREFIX: &str = "bronze-v2/";
/// Largest landed object read (compressed size on the store).
pub const MAX_LANDING_BYTES: u64 = 256 * 1024 * 1024;
/// Largest decoded NDJSON body.
pub const MAX_DECODED_BYTES: u64 = 1024 * 1024 * 1024;
/// Most rows one landed file may carry. Conversion streams and cuts the
/// file into bronze objects of at most [`MAX_OBJECT_ROWS`] (NAN-4319), so
/// this bounds conversion time, not memory: 8 bronze admissions' worth.
pub const MAX_LANDING_ROWS: usize = 8 * MAX_BRONZE_ROWS;
/// Claims of one file before it is refused whole (`attempts_exhausted`).
pub const MAX_ATTEMPTS: i32 = 5;
/// zstd level of written bronze, as Vector's sink default.
const BRONZE_ZSTD_LEVEL: i32 = 6;

/// One landing source, as the ledger knows it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LandingSource {
    pub source_id: Uuid,
    pub route_key: String,
    pub credential_id: Uuid,
    pub active: bool,
}

/// A landed object's key, parsed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LandingKey {
    pub source_id: Uuid,
    pub format: FileFormat,
    /// The OCSF class a Hive-style `class_uid=<N>` folder below the source
    /// folder names (NAN-4337), validated: a known OCSF 1.9 class.
    pub partition_class_uid: Option<u32>,
}

/// A Hive partition folder for `class_uid` (NAN-4337). Tenzir's `to_s3 ...
/// partition_by=[class_uid]` writes `.../class_uid=4003/events-....parquet`
/// and drops the column from the file, the way Athena / Spark expect Hive
/// partition columns to be read back from the path.
const PARTITION_CLASS_UID: &str = "class_uid=";

/// The `class_uid` a landed file's path (below its source folder, already
/// checked free of empty, `.` and `..` segments) carries as a Hive partition.
/// Only folders count, never the file name. `Err` is the value-free refusal
/// reason: more than one such folder, or a value that is not a known OCSF
/// class (digits only, no sign, at most six of them).
fn partition_class_uid(path: &str) -> std::result::Result<Option<u32>, &'static str> {
    let Some((folders, _file)) = path.rsplit_once('/') else { return Ok(None) };
    let mut values = folders.split('/').filter_map(|folder| folder.strip_prefix(PARTITION_CLASS_UID));
    let Some(value) = values.next() else { return Ok(None) };
    if values.next().is_some() {
        return Err("class_uid_partition_ambiguous");
    }
    if value.is_empty() || value.len() > 6 || !value.bytes().all(|b| b.is_ascii_digit()) {
        return Err("class_uid_partition_invalid");
    }
    let class: u32 = value.parse().map_err(|_| "class_uid_partition_invalid")?;
    if !nanosiem_core::parsers::is_known_ocsf_class(i64::from(class)) {
        return Err("class_uid_partition_invalid");
    }
    Ok(Some(class))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileFormat {
    Parquet,
    Ndjson { gzip: bool },
}

/// Parse `landing-ocsf-v1/tenant_id=<T>/source=<uuid>/<path>.<ext>`.
/// `Err` carries the value-free refusal reason. A `class_uid=<N>` folder in
/// `<path>` is read as a Hive partition ([`LandingKey::partition_class_uid`]).
pub fn parse_key(key: &str, tenant_id: &str) -> std::result::Result<LandingKey, &'static str> {
    let rest = key
        .strip_prefix(LANDING_PREFIX)
        .and_then(|rest| rest.strip_prefix("tenant_id="))
        .ok_or("key_outside_landing")?;
    let (tenant, rest) = rest.split_once('/').ok_or("key_malformed")?;
    if tenant != tenant_id {
        return Err("tenant_mismatch");
    }
    let (source, path) = rest
        .strip_prefix("source=")
        .and_then(|rest| rest.split_once('/'))
        .ok_or("key_malformed")?;
    let source_id = Uuid::parse_str(source)
        .ok()
        .filter(|id| id.hyphenated().to_string() == source)
        .ok_or("source_malformed")?;
    if path.is_empty() || path.len() > 1_024 || path.split('/').any(|part| part.is_empty() || part == "." || part == "..") {
        return Err("key_malformed");
    }
    let lower = path.to_ascii_lowercase();
    let format = if lower.ends_with(".parquet") {
        FileFormat::Parquet
    } else if [".ndjson", ".jsonl", ".json"].iter().any(|ext| lower.ends_with(ext)) {
        FileFormat::Ndjson { gzip: false }
    } else if [".ndjson.gz", ".jsonl.gz", ".json.gz"].iter().any(|ext| lower.ends_with(ext)) {
        FileFormat::Ndjson { gzip: true }
    } else {
        return Err("format_unsupported");
    };
    let partition_class_uid = partition_class_uid(path)?;
    Ok(LandingKey { source_id, format, partition_class_uid })
}

/// The key a refused file is moved to.
pub fn refused_key(key: &str) -> String {
    format!("{REFUSED_PREFIX}{}", key.strip_prefix(LANDING_PREFIX).unwrap_or(key))
}

/// A landed file converted to bronze.
#[derive(Debug)]
pub struct Converted {
    /// `(object key, Parquet bytes, rows)` per bronze shard.
    pub objects: Vec<(String, Vec<u8>, u64)>,
    pub rows_accepted: u64,
    pub rows_refused: u64,
    pub first_refusal: Option<RowRefusal>,
    /// Where [`Self::first_refusal`] happened: its row's `class_uid` and the
    /// attribute path (NAN-4321). Value-free.
    pub first_refusal_detail: Option<RefusalDetail>,
    /// Rows that had no `class_uid` column and took it from the key's Hive
    /// `class_uid=<N>` folder (NAN-4337).
    pub rows_class_from_path: u64,
    pub content_sha256: String,
    /// NAN-4336: accepted rows whose `time` was more than 5 min past the
    /// conversion (ingest) time and was clamped to it
    /// ([`crate::bronze::clamp_future_event_time`]).
    pub rows_time_clamped: u64,
}

/// Value-free context of a refusal (NAN-4321): the refused row's OCSF
/// `class_uid` and the bounded attribute path the check named. Never a row
/// value, so it may go to the ledger, logs and the tenant's status view.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefusalDetail {
    pub class_uid: Option<u32>,
    /// An OCSF attribute path (schema names and array indexes only, at most
    /// 128 characters: [`RowRefusal::field`]).
    pub field: Option<String>,
}

impl RefusalDetail {
    /// The detail of one row refusal; `None` when nothing is known.
    pub fn of(refusal: &RowRefusal, class_uid: Option<u32>) -> Option<Self> {
        let detail = Self { class_uid, field: refusal.field.clone() };
        (detail.class_uid.is_some() || detail.field.is_some()).then_some(detail)
    }

    /// `class_uid=4001 field=user` (either part may be absent).
    pub fn render(&self) -> String {
        let class = self.class_uid.map(|class| format!("class_uid={class}"));
        let field = self.field.as_deref().map(|field| format!("field={field}"));
        class.into_iter().chain(field).collect::<Vec<_>>().join(" ")
    }
}

/// A row's OCSF `class_uid` when it is a plausible one (a number, at most
/// six digits): reported with refusals, never trusted for anything else.
fn class_uid_of(row: &Value) -> Option<u32> {
    row.get("class_uid").and_then(Value::as_u64).filter(|class| *class <= 999_999).map(|class| class as u32)
}

/// The top-level attributes every OCSF event carries at least one of. A row
/// with none of them is not OCSF at all (NAN-4321: such a file was refused
/// as `raw_data_missing`, which sent senders looking for the wrong thing).
const OCSF_MARKERS: &[&str] = &["class_uid", "category_uid", "type_uid", "activity_id", "metadata"];

fn looks_like_ocsf(row: &Value) -> bool {
    OCSF_MARKERS.iter().any(|marker| row.get(marker).is_some())
}

/// A file refused whole, with its value-free reason.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("landed file refused: {reason}")]
pub struct FileRefusal {
    pub reason: &'static str,
    /// Rows of the file refused with it (0 when it was refused before its
    /// rows were read).
    pub rows: u64,
    /// Where the (first) row refusal behind it happened, when it came from rows.
    pub detail: Option<RefusalDetail>,
}

impl FileRefusal {
    pub fn new(reason: &'static str) -> Self {
        Self { reason, rows: 0, detail: None }
    }
}

fn refuse<T>(reason: &'static str) -> std::result::Result<T, FileRefusal> {
    Err(FileRefusal::new(reason))
}

/// Rows decoded at a time (NAN-4319): a landed file is read, staged and
/// pre-checked in chunks of this many rows, never as a whole.
pub const ROW_CHUNK: usize = 2_048;

/// Visit a landed file's rows as JSON objects in chunks of at most
/// [`ROW_CHUNK`], exactly as bronze admission reads Parquet (Arrow's
/// line-delimited JSON writer: nulls omitted). A non-object line is kept as
/// `Value::Null` (its place counts for the ordinal). Peak memory is one
/// chunk plus one Parquet record batch, whatever the file's row count
/// (NAN-4319).
pub(crate) fn visit_rows(
    bytes: &[u8],
    format: FileFormat,
    mut visit: impl FnMut(Vec<Value>) -> std::result::Result<(), FileRefusal>,
) -> std::result::Result<usize, FileRefusal> {
    let mut seen = 0_usize;
    let mut chunk = Vec::with_capacity(ROW_CHUNK);
    let mut push = |chunk: &mut Vec<Value>, line: &[u8], seen: &mut usize| -> std::result::Result<(), FileRefusal> {
        if *seen >= MAX_LANDING_ROWS {
            return refuse("too_many_rows");
        }
        *seen += 1;
        match serde_json::from_slice::<Value>(line) {
            Ok(value @ Value::Object(_)) => chunk.push(value),
            // A non-object line is a row the stage refuses; keep its place.
            Ok(_) | Err(_) => chunk.push(Value::Null),
        }
        if chunk.len() >= ROW_CHUNK {
            visit(std::mem::replace(chunk, Vec::with_capacity(ROW_CHUNK)))?;
        }
        Ok(())
    };
    match format {
        FileFormat::Parquet => {
            let reader = ParquetRecordBatchReaderBuilder::try_new(Bytes::copy_from_slice(bytes))
                .and_then(|builder| builder.with_batch_size(ROW_CHUNK).build())
                .or_else(|_| refuse("parquet_unreadable"))?;
            for batch in reader {
                let batch = batch.or_else(|_| refuse("parquet_unreadable"))?;
                let batch = decode_tenzir_extensions(batch).or_else(|_| refuse("parquet_unreadable"))?;
                if seen + batch.num_rows() > MAX_LANDING_ROWS {
                    return refuse("too_many_rows");
                }
                let mut writer = LineDelimitedWriter::new(Vec::new());
                writer.write(&batch).or_else(|_| refuse("parquet_unreadable"))?;
                writer.finish().or_else(|_| refuse("parquet_unreadable"))?;
                drop(batch);
                for line in writer.into_inner().split(|b| *b == b'\n').filter(|l| !l.is_empty()) {
                    push(&mut chunk, line, &mut seen)?;
                }
            }
        }
        FileFormat::Ndjson { gzip } => {
            let source: Box<dyn Read> = if gzip {
                Box::new(flate2::read::GzDecoder::new(bytes))
            } else {
                Box::new(bytes)
            };
            let mut reader = std::io::BufReader::new(source.take(MAX_DECODED_BYTES + 1));
            let mut decoded = 0_u64;
            let mut line = Vec::new();
            loop {
                line.clear();
                let read = reader.read_until(b'\n', &mut line).or_else(|_| refuse("ndjson_unreadable"))?;
                if read == 0 {
                    break;
                }
                decoded += read as u64;
                if decoded > MAX_DECODED_BYTES {
                    return refuse("file_too_large");
                }
                let text = line.strip_suffix(b"\n").unwrap_or(&line);
                let text = text.strip_suffix(b"\r").unwrap_or(text);
                if text.iter().all(u8::is_ascii_whitespace) {
                    continue;
                }
                push(&mut chunk, text, &mut seen)?;
            }
        }
    }
    if !chunk.is_empty() {
        visit(chunk)?;
    }
    if seen == 0 {
        return refuse("no_rows");
    }
    Ok(seen)
}

/// Read a landed file's rows as JSON objects, exactly as bronze admission
/// reads Parquet (Arrow's line-delimited JSON writer: nulls omitted). Holds
/// every row: tests and small files only; conversion streams
/// ([`visit_rows`]).
pub fn read_rows(bytes: &[u8], format: FileFormat) -> std::result::Result<Vec<Value>, FileRefusal> {
    let mut rows = Vec::new();
    visit_rows(bytes, format, |chunk| {
        rows.extend(chunk);
        Ok(())
    })?;
    Ok(rows)
}

/// Arrow extension-name metadata key (and its companion) on a field.
const EXTENSION_NAME: &str = "ARROW:extension:name";
const EXTENSION_METADATA: &str = "ARROW:extension:metadata";

/// What a Tenzir extension-typed field turns into for the JSON writer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TenzirExtension {
    /// `tenzir.ip`: FixedSizeBinary(16), IPv4 stored IPv4-mapped.
    Ip,
    /// `tenzir.subnet`: struct{address: tenzir.ip, length: uint8}.
    Subnet,
}

fn tenzir_extension(field: &Field) -> Option<TenzirExtension> {
    let name = field.metadata().get(EXTENSION_NAME)?;
    match (name.as_str(), field.data_type()) {
        ("tenzir.ip" | "vast.ip", DataType::FixedSizeBinary(16)) => Some(TenzirExtension::Ip),
        ("tenzir.subnet" | "vast.subnet", DataType::Struct(children))
            if children.len() == 2
                && children[0].data_type() == &DataType::FixedSizeBinary(16)
                && children[1].data_type() == &DataType::UInt8 =>
        {
            Some(TenzirExtension::Subnet)
        }
        _ => None,
    }
}

/// Text of one Tenzir IP: dotted quad for IPv4-mapped, canonical IPv6
/// otherwise.
fn tenzir_ip_text(bytes: &[u8]) -> Option<String> {
    let octets: [u8; 16] = bytes.try_into().ok()?;
    let ip = Ipv6Addr::from(octets);
    Some(match ip.to_ipv4_mapped() {
        Some(v4) => v4.to_string(),
        None => ip.to_string(),
    })
}

/// Text of one Tenzir subnet. Tenzir stores an IPv4 subnet's length in its
/// IPv6-mapped form (`/24` is stored as 120); a mapped address with a length
/// under 96 is a real IPv6 network (as Tenzir's own Python decoder reads it).
fn tenzir_subnet_text(address: &[u8], length: u8) -> Option<String> {
    let octets: [u8; 16] = address.try_into().ok()?;
    let ip = Ipv6Addr::from(octets);
    Some(match ip.to_ipv4_mapped() {
        Some(v4) if (96..=128).contains(&length) => format!("{v4}/{}", length - 96),
        _ if length <= 128 => format!("{ip}/{length}"),
        _ => return None,
    })
}

/// The field with its extension tag dropped and its type made Utf8.
fn as_text_field(field: &Field) -> FieldRef {
    let mut metadata = field.metadata().clone();
    metadata.remove(EXTENSION_NAME);
    metadata.remove(EXTENSION_METADATA);
    Arc::new(Field::new(field.name(), DataType::Utf8, field.is_nullable()).with_metadata(metadata))
}

/// Rewrite one column whose (possibly nested) fields carry Tenzir extension
/// types. `None` when nothing in it changes.
fn decode_tenzir_column(field: &FieldRef, array: &ArrayRef) -> std::result::Result<Option<(FieldRef, ArrayRef)>, ArrowError> {
    match tenzir_extension(field) {
        Some(TenzirExtension::Ip) => {
            let ips = array.as_fixed_size_binary();
            let text: StringArray = (0..ips.len())
                .map(|i| if ips.is_null(i) { None } else { tenzir_ip_text(ips.value(i)) })
                .collect();
            return Ok(Some((as_text_field(field), Arc::new(text))));
        }
        Some(TenzirExtension::Subnet) => {
            let subnets = array.as_struct();
            let addresses = subnets.column(0).as_fixed_size_binary();
            let lengths = subnets.column(1).as_primitive::<UInt8Type>();
            let text: StringArray = (0..subnets.len())
                .map(|i| {
                    if subnets.is_null(i) || addresses.is_null(i) || lengths.is_null(i) {
                        None
                    } else {
                        tenzir_subnet_text(addresses.value(i), lengths.value(i))
                    }
                })
                .collect();
            return Ok(Some((as_text_field(field), Arc::new(text))));
        }
        None => {}
    }
    let rebuilt: ArrayRef = match field.data_type() {
        DataType::Struct(children) => {
            let structs = array.as_struct();
            let Some((fields, columns)) = decode_tenzir_children(children, structs.columns())? else {
                return Ok(None);
            };
            Arc::new(StructArray::try_new(fields, columns, structs.nulls().cloned())?)
        }
        DataType::List(item) => {
            let list = array.as_list::<i32>();
            let Some((item, values)) = decode_tenzir_column(item, list.values())? else {
                return Ok(None);
            };
            Arc::new(ListArray::try_new(item, list.offsets().clone(), values, list.nulls().cloned())?)
        }
        DataType::LargeList(item) => {
            let list = array.as_list::<i64>();
            let Some((item, values)) = decode_tenzir_column(item, list.values())? else {
                return Ok(None);
            };
            Arc::new(LargeListArray::try_new(item, list.offsets().clone(), values, list.nulls().cloned())?)
        }
        DataType::FixedSizeList(item, size) => {
            let list = array.as_fixed_size_list();
            let Some((item, values)) = decode_tenzir_column(item, list.values())? else {
                return Ok(None);
            };
            Arc::new(FixedSizeListArray::try_new(item, *size, values, list.nulls().cloned())?)
        }
        DataType::Map(entries_field, sorted) => {
            let map = array.as_map();
            let entries: ArrayRef = Arc::new(map.entries().clone());
            let Some((entries_field, entries)) = decode_tenzir_column(entries_field, &entries)? else {
                return Ok(None);
            };
            Arc::new(MapArray::try_new(
                entries_field,
                map.offsets().clone(),
                entries.as_struct().clone(),
                map.nulls().cloned(),
                *sorted,
            )?)
        }
        _ => return Ok(None),
    };
    let field = Arc::new(field.as_ref().clone().with_data_type(rebuilt.data_type().clone()));
    Ok(Some((field, rebuilt)))
}

/// Rewrite a set of sibling columns; `None` when none of them changes.
#[allow(clippy::type_complexity)]
fn decode_tenzir_children(
    fields: &Fields,
    columns: &[ArrayRef],
) -> std::result::Result<Option<(Fields, Vec<ArrayRef>)>, ArrowError> {
    let mut changed = false;
    let mut out_fields = Vec::with_capacity(fields.len());
    let mut out_columns = Vec::with_capacity(columns.len());
    for (field, column) in fields.iter().zip(columns) {
        match decode_tenzir_column(field, column)? {
            Some((field, column)) => {
                changed = true;
                out_fields.push(field);
                out_columns.push(column);
            }
            None => {
                out_fields.push(field.clone());
                out_columns.push(column.clone());
            }
        }
    }
    Ok(changed.then(|| (Fields::from(out_fields), out_columns)))
}

/// Tenzir's `write_parquet` keeps its Arrow extension types (NAN-4301):
/// `tenzir.ip` is 16 raw bytes and `tenzir.subnet` a struct of those plus a
/// length, which Arrow's JSON writer would emit as hex / an object and the
/// strict OCSF `ip_t` / `subnet_t` checks would refuse. Rewrite them, at any
/// depth (struct, list, map), to the text OCSF expects; nulls stay null.
/// `tenzir.enumeration` is a string dictionary the JSON writer already
/// writes as its text, so it is left alone.
fn decode_tenzir_extensions(batch: RecordBatch) -> std::result::Result<RecordBatch, ArrowError> {
    let schema = batch.schema();
    let Some((fields, columns)) = decode_tenzir_children(schema.fields(), batch.columns())? else {
        return Ok(batch);
    };
    let schema = Arc::new(Schema::new_with_metadata(fields, schema.metadata().clone()));
    RecordBatch::try_new_with_options(schema, columns, &RecordBatchOptions::new().with_row_count(Some(batch.num_rows())))
}

/// OCSF `time` is epoch milliseconds. A typed Tenzir time column arrives as
/// an RFC 3339 (or zone-less ISO 8601, read as UTC) string; turn it into ms
/// so the stage keeps the event time instead of falling back to now.
fn normalize_time(row: &mut Value) {
    let Some(Value::String(text)) = row.get("time") else { return };
    let ms = DateTime::parse_from_rfc3339(text)
        .map(|t| t.with_timezone(&Utc))
        .or_else(|_| NaiveDateTime::parse_from_str(text, "%Y-%m-%dT%H:%M:%S%.f").map(|t| t.and_utc()))
        .ok()
        .map(|t| t.timestamp_millis());
    if let Some(ms) = ms {
        row["time"] = Value::from(ms);
    }
}

/// Encode bronze rows as Vector's sink does (`schema_mode = "auto_infer"`
/// over the fixed bronze row contract: `_nano_bronze_event` Utf8, `time`
/// Timestamp(µs, UTC), zstd).
pub fn encode_bronze(rows: &[&BronzeRow]) -> Result<Vec<u8>> {
    encode_bronze_batch(&bronze_batch(rows)?)
}

/// The bronze record batch [`encode_bronze`] writes: the fixed bronze row
/// contract over `rows`, in order.
fn bronze_batch(rows: &[&BronzeRow]) -> Result<RecordBatch> {
    let schema = Arc::new(Schema::new(vec![
        Field::new(BRONZE_EVENT_COLUMN, DataType::Utf8, true),
        Field::new(BRONZE_TIME_COLUMN, DataType::Timestamp(TimeUnit::Microsecond, Some("UTC".into())), true),
    ]));
    let events = StringArray::from_iter_values(rows.iter().map(|row| row.event_json.as_str()));
    let times = TimestampMicrosecondArray::from_iter_values(rows.iter().map(|row| row.time_micros)).with_timezone("UTC");
    Ok(RecordBatch::try_new(schema, vec![Arc::new(events) as ArrayRef, Arc::new(times) as ArrayRef])?)
}

/// One bronze record batch read the way admission reads a bronze object:
/// Arrow's line-delimited JSON writer, then [`decode_bronze_row`] per row.
fn admitted_rows(batch: &RecordBatch, out: &mut Vec<Result<Value>>) -> Result<()> {
    let mut writer = LineDelimitedWriter::new(Vec::new());
    writer.write(batch)?;
    writer.finish()?;
    for line in writer.into_inner().split(|b| *b == b'\n').filter(|l| !l.is_empty()) {
        out.push(serde_json::from_slice::<Value>(line).map_err(anyhow::Error::from).and_then(decode_bronze_row));
    }
    Ok(())
}

/// NAN-4682: what admission will read back for `rows`, without the Parquet
/// round trip. The bronze columns are a Utf8 string and a
/// `Timestamp(µs, "UTC")`, both stored losslessly by Parquet (the Arrow
/// schema, time zone included, travels in the file), so the batch admission
/// decodes is this very batch: rendering it with the same JSON writer gives
/// the same values. `landing_precheck_in_memory_matches_the_parquet_round_trip`
/// proves it over the fixture corpus.
fn precheck_view(rows: &[&BronzeRow]) -> Result<Vec<Result<Value>>> {
    let mut out = Vec::with_capacity(rows.len());
    admitted_rows(&bronze_batch(rows)?, &mut out)?;
    Ok(out)
}

/// How the pre-check reads back prepared rows. Production reads the
/// in-memory batch ([`precheck_view`]); the Parquet round trip it replaced
/// (NAN-4682) stays as the reference the equivalence test compares with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Precheck {
    InMemory,
    #[cfg_attr(not(test), allow(dead_code))]
    ParquetRoundTrip,
}

/// Encode one bronze record batch (the fixed bronze row contract) exactly
/// as [`encode_bronze`] does. The hosted emitter re-encodes slices of a
/// converted object with it to fit edge-log segments (NAN-4137).
pub fn encode_bronze_batch(batch: &RecordBatch) -> Result<Vec<u8>> {
    let properties = WriterProperties::builder()
        .set_compression(Compression::ZSTD(ZstdLevel::try_new(BRONZE_ZSTD_LEVEL)?))
        .build();
    let mut out = Vec::new();
    let mut writer = ArrowWriter::try_new(&mut out, batch.schema(), Some(properties))?;
    writer.write(batch)?;
    writer.close()?;
    Ok(out)
}

/// Read back an encoded bronze object the way admission does: one decoded
/// event per row, in order.
pub(crate) fn decode_bronze(bytes: &[u8]) -> Result<Vec<Result<Value>>> {
    let reader = ParquetRecordBatchReaderBuilder::try_new(Bytes::copy_from_slice(bytes))?.build()?;
    let mut out = Vec::new();
    for batch in reader {
        admitted_rows(&batch?, &mut out)?;
    }
    Ok(out)
}

/// The bronze object key Vector's sink would write now.
pub fn bronze_key(partition: &str, tenant_id: &str, now: DateTime<Utc>) -> String {
    format!("{BRONZE_PREFIX}{partition}tenant_id={tenant_id}/{}-{}.parquet", now.timestamp(), Uuid::new_v4())
}

/// Most rows one emitted bronze object carries (NAN-4319), as Vector's
/// bronze sink batches (`VECTOR_LAKE_BATCH_MAX_EVENTS` default). ingest[T]
/// admits an object whole, so a landed file is cut into Vector-shaped
/// objects: a 50k-row Tenzir file as one object OOM-killed ingest.
pub const MAX_OBJECT_ROWS: usize = 10_000;
/// Most `_nano_bronze_event` bytes one emitted bronze object carries, as
/// Vector's bronze sink batches (`VECTOR_LAKE_BATCH_MAX_BYTES` default).
pub const MAX_OBJECT_EVENT_BYTES: usize = 32 * 1024 * 1024;

/// One bronze shard's rows not yet encoded (at most one object's worth).
#[derive(Default)]
struct PendingObject {
    rows: Vec<BronzeRow>,
    event_bytes: usize,
}

/// Convert one landed file. `Err` refuses the file whole.
///
/// Streams (NAN-4319): rows are read, staged and pre-checked [`ROW_CHUNK`]
/// at a time, and accepted rows are encoded into bronze objects of at most
/// [`MAX_OBJECT_ROWS`] rows / [`MAX_OBJECT_EVENT_BYTES`] event bytes as they
/// fill. Peak memory is one chunk plus one pending object per bronze shard,
/// independent of the file's row count; only the encoded (compressed)
/// objects are kept until the emit.
pub fn convert_file(
    bytes: &[u8],
    format: FileFormat,
    stage: &LandingOcsfStage,
    tenant_id: &str,
    source: &LandingSource,
    now: DateTime<Utc>,
) -> std::result::Result<Converted, FileRefusal> {
    convert_landed(bytes, format, None, stage, tenant_id, source, now)
}

/// Apply the key's Hive `class_uid` partition to one row (NAN-4337): a row
/// without the column takes it (`Ok(true)`); a row whose own `class_uid`
/// disagrees with the folder refuses the whole file, since the sender's
/// path and data contradict each other.
fn apply_partition_class(row: &mut Value, partition: Option<u32>) -> std::result::Result<bool, FileRefusal> {
    let (Some(class), Some(object)) = (partition, row.as_object_mut()) else { return Ok(false) };
    match object.get("class_uid") {
        None | Some(Value::Null) => {
            object.insert("class_uid".to_string(), Value::from(class));
            Ok(true)
        }
        Some(value) if value.as_u64() == Some(u64::from(class)) => Ok(false),
        Some(_) => Err(FileRefusal {
            reason: "class_uid_partition_conflict",
            rows: 0,
            detail: Some(RefusalDetail { class_uid: Some(class), field: Some("class_uid".to_string()) }),
        }),
    }
}

/// [`convert_file`] for a landed key: `partition_class_uid` is the key's
/// Hive `class_uid=<N>` folder ([`LandingKey::partition_class_uid`]).
pub fn convert_landed(
    bytes: &[u8],
    format: FileFormat,
    partition_class_uid: Option<u32>,
    stage: &LandingOcsfStage,
    tenant_id: &str,
    source: &LandingSource,
    now: DateTime<Utc>,
) -> std::result::Result<Converted, FileRefusal> {
    convert_landed_with(bytes, format, partition_class_uid, stage, tenant_id, source, now, Precheck::InMemory)
}

/// [`convert_landed`] with the pre-check read-back chosen (tests compare the
/// two; production is always [`Precheck::InMemory`]).
#[allow(clippy::too_many_arguments)]
pub(crate) fn convert_landed_with(
    bytes: &[u8],
    format: FileFormat,
    partition_class_uid: Option<u32>,
    stage: &LandingOcsfStage,
    tenant_id: &str,
    source: &LandingSource,
    now: DateTime<Utc>,
    precheck: Precheck,
) -> std::result::Result<Converted, FileRefusal> {
    let content_sha256 = hex::encode(Sha256::digest(bytes));
    // NAN-4682: one VRL runtime for the whole file, cleared after each row.
    let mut runner = stage.runner();
    let credential = source.credential_id.hyphenated().to_string();
    let mut rows_refused = 0_u64;
    let mut rows_accepted = 0_u64;
    let mut rows_class_from_path = 0_u64;
    // NAN-4336: future-dated rows clamp to the conversion time (the same
    // rule ingest[T] applies to every source), counted for the ledger.
    let ingest_ms = now.timestamp_millis();
    let mut rows_time_clamped = 0_u64;
    // Every refused row is counted; the first one's reason and detail are
    // kept (NAN-4321: rows of an accepted file used to vanish unreported).
    let mut first_refusal: Option<(RowRefusal, Option<u32>)> = None;
    let mut ordinal = 0_usize;
    let mut pending: BTreeMap<String, PendingObject> = BTreeMap::new();
    let mut objects = Vec::new();
    let encode = |partition: &str, object: PendingObject, objects: &mut Vec<(String, Vec<u8>, u64)>| {
        let rows = object.rows.iter().collect::<Vec<_>>();
        let bytes = encode_bronze(&rows).or_else(|_| refuse("bronze_encode_failed"))?;
        objects.push((bronze_key(partition, tenant_id, now), bytes, rows.len() as u64));
        Ok::<_, FileRefusal>(())
    };
    visit_rows(bytes, format, |chunk| {
        let mut note = |refusal: RowRefusal, class_uid: Option<u32>| {
            rows_refused += 1;
            first_refusal.get_or_insert((refusal, class_uid));
        };
        let mut prepared = Vec::with_capacity(chunk.len());
        let mut classes = Vec::with_capacity(chunk.len());
        let mut clamped = Vec::with_capacity(chunk.len());
        for mut row in chunk {
            let this = ordinal;
            ordinal += 1;
            if !row.is_object() {
                note(RowRefusal::new("event_not_object", None), None);
                continue;
            }
            if !looks_like_ocsf(&row) {
                note(RowRefusal::new("not_ocsf", None), None);
                continue;
            }
            if apply_partition_class(&mut row, partition_class_uid)? {
                rows_class_from_path += 1;
            }
            let class_uid = class_uid_of(&row);
            normalize_time(&mut row);
            let row_clamped = crate::bronze::clamp_future_event_time(&mut row, ingest_ms);
            let ctx = StageContext {
                tenant_id,
                source_type: &source.route_key,
                credential_id: &credential,
                event_key: Some(format!("{content_sha256}:{this}")),
            };
            match runner.prepare(row, &ctx) {
                Ok(bronze) => {
                    prepared.push(bronze);
                    classes.push(class_uid);
                    clamped.push(row_clamped);
                }
                Err(_) => note(RowRefusal::new("storage_stage_dropped", None), class_uid),
            }
        }
        if prepared.is_empty() {
            return Ok(());
        }
        // Pre-check exactly what admission will read ([`precheck_view`]).
        let all = prepared.iter().collect::<Vec<_>>();
        let decoded = match precheck {
            Precheck::InMemory => precheck_view(&all),
            Precheck::ParquetRoundTrip => encode_bronze(&all).and_then(|encoded| decode_bronze(&encoded)),
        }
        .or_else(|_| refuse("bronze_encode_failed"))?;
        drop(all);
        if decoded.len() != prepared.len() {
            return refuse("bronze_encode_failed");
        }
        // Each row stands alone: a file mixing classes keeps every valid
        // row of every class, and each refused row is counted with its class.
        for (((row, event), class_uid), row_clamped) in prepared.into_iter().zip(decoded).zip(classes).zip(clamped) {
            let verdict = event
                .map_err(|error| crate::bronze::classify_row_refusal(&error))
                .and_then(|event| precheck_source_row(event, tenant_id));
            if let Err(refusal) = verdict {
                note(refusal, class_uid);
                continue;
            }
            rows_accepted += 1;
            rows_time_clamped += u64::from(row_clamped);
            let object = pending.entry(row.partition.clone()).or_default();
            if !object.rows.is_empty()
                && (object.rows.len() >= MAX_OBJECT_ROWS || object.event_bytes + row.event_json.len() > MAX_OBJECT_EVENT_BYTES)
            {
                let full = std::mem::take(object);
                encode(&row.partition, full, &mut objects)?;
            }
            let object = pending.entry(row.partition.clone()).or_default();
            object.event_bytes += row.event_json.len();
            object.rows.push(row);
        }
        Ok(())
    })?;
    for (partition, object) in std::mem::take(&mut pending) {
        if !object.rows.is_empty() {
            encode(&partition, object, &mut objects)?;
        }
    }
    let first_refusal_detail = first_refusal.as_ref().and_then(|(refusal, class_uid)| RefusalDetail::of(refusal, *class_uid));
    let first_refusal = first_refusal.map(|(refusal, _)| refusal);
    if rows_accepted == 0 {
        return Err(FileRefusal {
            reason: first_refusal.map_or("no_rows", |r| r.reason),
            rows: rows_refused,
            detail: first_refusal_detail,
        });
    }
    Ok(Converted { objects, rows_accepted, rows_refused, first_refusal, first_refusal_detail, rows_class_from_path, content_sha256, rows_time_clamped })
}

/// How a claim came out.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Claim {
    /// This converter owns the file now (`id`, attempt number).
    Owned { id: i64, attempt: i32 },
    /// Already accepted or refused: the object reappeared (same key, etag).
    Finished { id: i64 },
    /// Another converter's lease is still live.
    Leased,
}

/// The listed-and-claimed ledger (`landing_files` / `landing_sources`).
#[async_trait]
pub trait Ledger: Send + Sync {
    async fn source(&self, source_id: Uuid) -> Result<Option<LandingSource>>;
    async fn claim(&self, key: &str, etag: &str, size: u64, source_id: Option<Uuid>) -> Result<Claim>;
    async fn accepted(&self, id: i64, converted: &Converted, bronze_keys: &str) -> Result<()>;
    async fn refused(&self, id: i64, reason: &str, rows_refused: u64, content_sha256: Option<&str>) -> Result<()>;
    async fn redelivered(&self, id: i64) -> Result<()>;
    /// NAN-4629: the file is refused but stays where it landed (no copy could
    /// be kept, so it is never deleted). The ledger must never hand it out
    /// again: not as a claim, not as a redelivery (which deletes). A ledger
    /// that cannot record this refuses, and the file stays untouched.
    async fn refused_in_place(&self, _id: i64, _reason: &str, _rows_refused: u64, _content_sha256: Option<&str>) -> Result<()> {
        anyhow::bail!("this landing ledger cannot keep a refused file in place")
    }
    /// NAN-4629: the ledger is the work queue. `Some` replaces listing the
    /// landing folder: the ledger's own (leased) lister recorded the objects
    /// and every node claims from what it recorded. `None` (the default): the
    /// caller lists the folder itself.
    async fn pending(&self, _store: &Operator, _tenant_id: &str, _max: usize) -> Result<Option<(usize, Vec<Candidate>)>> {
        Ok(None)
    }
    /// NAN-4629: age of the oldest landed file not yet finished, when the
    /// ledger can tell (the backlog-age health field).
    async fn backlog_age(&self) -> Result<Option<std::time::Duration>> {
        Ok(None)
    }
}

/// NAN-4629 (coordinator Q-F): a landed file unfinished for longer than this
/// raises the `landing_backlog_age` alert. Files are never dropped for age.
pub const BACKLOG_ALERT_AFTER: std::time::Duration = std::time::Duration::from_secs(15 * 60);

/// What one tick did (for logs and tests).
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct TickReport {
    pub listed: usize,
    pub accepted: usize,
    pub refused: usize,
    pub redelivered: usize,
    pub skipped: usize,
    pub failed: usize,
    /// Hosted (NAN-4137): files handed back unfinished because the output
    /// (the tenant edge log) applied backpressure. No attempt is spent; the
    /// tick stops at the first one. Always 0 on open core.
    pub held: usize,
    /// NAN-4629: age of the oldest unfinished landed file after this tick,
    /// in seconds (`None`: nothing pending, or the ledger cannot tell).
    pub backlog_age_secs: Option<u64>,
}

// ------------------------------------------------------------ discover / emit
//
// NAN-4137: one conversion engine, two deployments.
//
// | step     | open core (`Converter`)                 | hosted (`landing[T]`, `landing_hosted`)          |
// |----------|-----------------------------------------|--------------------------------------------------|
// | discover | list the landing prefix, claim per      | lease files from the tenant's landing ledger DO  |
// |          | `(key, etag)` in Postgres               | (epoch-fenced)                                   |
// | emit     | one `bronze-v2/` object per shard       | edge-log appends of at most 8 MiB each           |
// | finish   | delete, then record in Postgres         | commit to the DO, then delete                    |
//
// Everything between (key parsing, the source check, size caps, read,
// `convert_file`, refusal reasons, attempts) is the same code for both.

/// One landed file a [`Discover`] found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Candidate {
    pub key: String,
    /// The listing's etag (open core) or the ledger's (hosted).
    pub etag: Option<String>,
    pub size: u64,
    /// Hosted: the ledger already leased this file to this converter.
    pub leased: Option<LeasedFile>,
}

/// A file the hosted ledger leased (its claim is the lease).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeasedFile {
    /// The ledger's sequence for the file.
    pub id: i64,
    pub attempt: i32,
    /// The consumer epoch that leased it (every write about it carries it).
    pub epoch: u64,
    /// When the file landed (ms since the epoch), if the ledger said.
    pub landed_at_ms: Option<i64>,
    /// The source the Worker resolved from the sender's key. The folder in
    /// the key must name the same source, or the file is refused.
    pub source: Option<LandingSource>,
}

/// A candidate after its claim.
#[derive(Debug)]
pub struct Claimed {
    pub claim: Claim,
    pub size: u64,
    /// Bytes already read while resolving the claim (open core: a store
    /// that reports no etag is claimed by content digest).
    pub preloaded: Option<Vec<u8>>,
}

/// Where landed files come from and where their outcomes go.
#[async_trait]
pub trait Discover: Send + Sync {
    /// The files to look at this tick, in order, and how many were seen.
    async fn discover(&self, store: &Operator, tenant_id: &str, max: usize) -> Result<(usize, Vec<Candidate>)>;
    /// Claim one candidate (`source_id`: the folder's, when the key parses).
    async fn claim(&self, store: &Operator, candidate: &Candidate, source_id: Option<Uuid>) -> Result<Claimed>;
    /// The source named by the key's folder.
    async fn source(&self, candidate: &Candidate, source_id: Uuid) -> Result<Option<LandingSource>>;
    /// The rows are durable downstream (`emitted`): finish the file.
    async fn finish_accepted(&self, store: &Operator, candidate: &Candidate, id: i64, converted: &Converted, emitted: &str) -> Result<()>;
    /// The file is refused whole: keep it aside as `copy` says, delete the
    /// original only once a copy exists, and record the reason.
    async fn finish_refused(
        &self,
        store: &Operator,
        candidate: &Candidate,
        id: i64,
        refusal: &FileRefusal,
        sha: Option<&str>,
        copy: RefusedCopy,
    ) -> Result<()>;
    /// An already finished file reappeared.
    async fn finish_redelivered(&self, store: &Operator, candidate: &Candidate, id: i64) -> Result<()>;
    /// Hand an unfinished file back without spending an attempt (the output
    /// applied [`Backpressure`]).
    async fn release(&self, _candidate: &Candidate, _id: i64) -> Result<()> {
        Ok(())
    }
    /// The file was not finished (a transient store, ledger or output
    /// failure). Open core: its claim's lease expires and a later tick
    /// retries it. Hosted: the ledger is told to land it again.
    async fn failed(&self, _store: &Operator, _candidate: &Candidate) -> Result<()> {
        Ok(())
    }
}

/// NAN-4629: what happens to a refused landed file's bytes. A refused file is
/// deleted from the landing folder only once a copy of it exists.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefusedCopy {
    /// The discoverer copies it aside (open core: under [`REFUSED_PREFIX`] in
    /// the landing store), then deletes the original.
    MoveAside,
    /// The output already holds a copy (or the original is already gone):
    /// delete the original.
    Kept,
    /// No copy could be made: the file stays where it landed, recorded as
    /// refused (`landing_refused_in_place` alert). Never deleted.
    InPlace,
}

/// Where converted rows go.
#[async_trait]
pub trait Emit: Send + Sync {
    /// Make `converted` durable downstream. Returns what the ledger records
    /// (comma-separated object keys or segment sequences). An error that is
    /// [`Backpressure`] holds the file without spending an attempt; one that
    /// is a [`FileRefusal`] refuses it whole (decide that before writing).
    async fn emit(&self, store: &Operator, tenant_id: &str, candidate: &Candidate, converted: &Converted) -> Result<String>;
    /// Keep a copy of a refused landed file for the operator before the
    /// original is deleted (see [`RefusedCopy`]). Default: the discoverer
    /// moves it aside.
    async fn keep_refused(&self, _landing: &Operator, _key: &str) -> Result<RefusedCopy> {
        Ok(RefusedCopy::MoveAside)
    }
}

/// The output is full (the tenant edge log refuses appends with 503 while
/// its backlog is over its cap, e.g. under an over-commit hold): hold the
/// file where it is, never refuse it for this.
#[derive(Debug, Clone, Copy, thiserror::Error)]
#[error("landing output is applying backpressure; the file is held")]
pub struct Backpressure;

/// The discoverer lost its authority to finish files (hosted: a newer
/// consumer holds the landing ledger lease). The tick stops and returns it;
/// nothing is committed under a stale epoch.
#[derive(Debug, Clone, Copy, thiserror::Error)]
#[error("landing ledger lease is held by a newer consumer (fenced)")]
pub struct Fenced;

/// Open core: claim by listing the tenant's landing folder.
pub struct PrefixDiscover<'a, L: Ledger> {
    pub ledger: &'a L,
}

#[async_trait]
impl<L: Ledger> Discover for PrefixDiscover<'_, L> {
    async fn discover(&self, store: &Operator, tenant_id: &str, max: usize) -> Result<(usize, Vec<Candidate>)> {
        if let Some(found) = self.ledger.pending(store, tenant_id, max).await? {
            return Ok(found);
        }
        let prefix = format!("{LANDING_PREFIX}tenant_id={tenant_id}/");
        let entries = store.list_with(&prefix).recursive(true).await.context("list landing prefix")?;
        let mut objects = entries
            .into_iter()
            .filter(|entry| !entry.path().ends_with('/'))
            .collect::<Vec<_>>();
        objects.sort_by(|a, b| a.path().cmp(b.path()));
        let listed = objects.len();
        let candidates = objects
            .into_iter()
            .take(max)
            .map(|entry| Candidate {
                key: entry.path().to_string(),
                etag: entry.metadata().etag().map(str::to_string),
                size: entry.metadata().content_length(),
                leased: None,
            })
            .collect();
        Ok((listed, candidates))
    }

    async fn claim(&self, store: &Operator, candidate: &Candidate, source_id: Option<Uuid>) -> Result<Claimed> {
        let key = candidate.key.as_str();
        let (etag, size, preloaded) = landed_etag(store, key, candidate.etag.as_deref(), candidate.size).await?;
        let claim = self.ledger.claim(key, &etag, size, source_id).await?;
        Ok(Claimed { claim, size, preloaded })
    }

    async fn source(&self, _candidate: &Candidate, source_id: Uuid) -> Result<Option<LandingSource>> {
        self.ledger.source(source_id).await
    }

    async fn finish_accepted(&self, store: &Operator, candidate: &Candidate, id: i64, converted: &Converted, emitted: &str) -> Result<()> {
        // Bronze is durable before the landed object goes: a crash here only
        // means a reconversion, whose rows the uid window drops.
        store.delete(&candidate.key).await.context("delete converted landed object")?;
        self.ledger.accepted(id, converted, emitted).await
    }

    async fn finish_refused(
        &self,
        store: &Operator,
        candidate: &Candidate,
        id: i64,
        refusal: &FileRefusal,
        sha: Option<&str>,
        copy: RefusedCopy,
    ) -> Result<()> {
        match copy {
            RefusedCopy::InPlace => return self.ledger.refused_in_place(id, refusal.reason, refusal.rows, sha).await,
            RefusedCopy::MoveAside => move_aside(store, &candidate.key).await?,
            RefusedCopy::Kept => {}
        }
        store.delete(&candidate.key).await.context("delete refused landed object")?;
        self.ledger.refused(id, refusal.reason, refusal.rows, sha).await
    }

    async fn finish_redelivered(&self, store: &Operator, candidate: &Candidate, id: i64) -> Result<()> {
        store.delete(&candidate.key).await.context("delete redelivered landed object")?;
        self.ledger.redelivered(id).await
    }
}

/// The (etag, size) a landed object is claimed under, and its bytes when
/// they had to be read. Listings normally carry the etag; stat when they do
/// not, and fall back to the content digest for a store that reports none.
async fn landed_etag(store: &Operator, key: &str, listed: Option<&str>, listed_size: u64) -> Result<(String, u64, Option<Vec<u8>>)> {
    if let Some(etag) = listed.map(|etag| etag.trim_matches('"')).filter(|etag| !etag.is_empty()) {
        return Ok((etag.to_string(), listed_size, None));
    }
    let meta = store.stat(key).await.context("stat landed object")?;
    if let Some(etag) = meta.etag().map(|etag| etag.trim_matches('"')).filter(|etag| !etag.is_empty()) {
        return Ok((etag.to_string(), meta.content_length(), None));
    }
    if meta.content_length() > MAX_LANDING_BYTES {
        return Ok((format!("size:{}", meta.content_length()), meta.content_length(), None));
    }
    let bytes = store.read(key).await.context("read landed object")?.to_vec();
    let digest = format!("sha256:{}", hex::encode(Sha256::digest(&bytes)));
    let size = bytes.len() as u64;
    Ok((digest, size, Some(bytes)))
}

/// Copy a refused landed object under [`REFUSED_PREFIX`] (the caller
/// deletes the original).
pub async fn move_aside(store: &Operator, key: &str) -> Result<()> {
    let target = refused_key(key);
    match store.copy(key, &target).await {
        Ok(_) => Ok(()),
        // A store without server-side copy: move it through this process.
        Err(error) if error.kind() == opendal::ErrorKind::Unsupported => {
            let body = store.read(key).await.context("read refused landed object")?;
            store.write(&target, body).await.context("move refused landed object aside")?;
            Ok(())
        }
        Err(error) => Err(anyhow::Error::from(error).context("move refused landed object aside")),
    }
}

/// Open core: one `bronze-v2/` object per bronze shard, written to the
/// same store; part ingest lists them like any Vector object.
pub struct BronzeObjects;

#[async_trait]
impl Emit for BronzeObjects {
    async fn emit(&self, store: &Operator, _tenant_id: &str, _candidate: &Candidate, converted: &Converted) -> Result<String> {
        // NAN-4682: the objects go up concurrently (bounded); `emit` returns
        // only once every one is durable, so the file is never finished early.
        use futures::{StreamExt, TryStreamExt};
        let writes = converted
            .objects
            .iter()
            .map(|(bronze_key, body, _)| async move {
                store.write(bronze_key, body.clone()).await.context("write bronze object").map(|_| ())
            })
            .collect::<Vec<_>>();
        futures::stream::iter(writes)
            .buffer_unordered(MAX_CONCURRENT_BRONZE_PUTS)
            .try_collect::<Vec<()>>()
            .await?;
        Ok(converted.objects.iter().map(|(key, _, _)| key.as_str()).collect::<Vec<_>>().join(","))
    }
}

/// Sovereign (NAN-4629, coordinator Q-B): bronze is handed to the consumer
/// store (C13 publication through [`crate::parts::part_log::ObjectStore`],
/// e.g. the supervisor's `SovereignPartStore`) with an immutable create, so
/// it is published, never written raw next to the landing folder.
pub struct PublishedBronze<S: crate::parts::part_log::ObjectStore> {
    pub store: S,
}

#[async_trait]
impl<S: crate::parts::part_log::ObjectStore> Emit for PublishedBronze<S> {
    async fn emit(&self, _landing: &Operator, _tenant_id: &str, _candidate: &Candidate, converted: &Converted) -> Result<String> {
        // `false`: the key already exists (a retried emit after a lost
        // reply). Bronze keys carry a fresh suffix per conversion, so it is
        // this conversion's own object; a reconversion writes new keys whose
        // rows the uid window drops. NAN-4682: published concurrently
        // (bounded); `emit` returns once every one is published.
        use futures::{StreamExt, TryStreamExt};
        let puts = converted
            .objects
            .iter()
            .map(|(bronze_key, body, _)| async move {
                self.store.put_if_absent(bronze_key, body).await.context("publish bronze object").map(|_| ())
            })
            .collect::<Vec<_>>();
        futures::stream::iter(puts)
            .buffer_unordered(MAX_CONCURRENT_BRONZE_PUTS)
            .try_collect::<Vec<()>>()
            .await?;
        Ok(converted.objects.iter().map(|(key, _, _)| key.as_str()).collect::<Vec<_>>().join(","))
    }

    /// The refused copy is published too (the converter's own object-store
    /// principal may only list, read and delete the landing folder). A file
    /// the consumer store cannot take (empty, or over its write bound) is
    /// never deleted: it stays where it landed ([`RefusedCopy::InPlace`]).
    async fn keep_refused(&self, landing: &Operator, key: &str) -> Result<RefusedCopy> {
        let size = match landing.stat(key).await {
            Ok(meta) => meta.content_length(),
            Err(error) if error.kind() == opendal::ErrorKind::NotFound => return Ok(RefusedCopy::Kept),
            Err(error) => return Err(anyhow::Error::from(error).context("stat refused landed file")),
        };
        if size == 0 || size > MAX_PUBLISHED_REFUSED_BYTES {
            return Ok(RefusedCopy::InPlace);
        }
        let bytes = landing.read(key).await.context("read refused landed file")?.to_vec();
        let target = refused_key(key);
        if self.store.put_if_absent(&target, &bytes).await.context("publish refused landed file")? {
            return Ok(RefusedCopy::Kept);
        }
        // The key is taken: a retry of this same refusal (same bytes), or an
        // earlier refused file under the same landed key. Never drop the
        // second one: keep it beside the first, named by its content digest.
        if self.store.get(&target).await.context("read published refused file")?.as_deref() == Some(bytes.as_slice()) {
            return Ok(RefusedCopy::Kept);
        }
        let digest = hex::encode(Sha256::digest(&bytes));
        self.store
            .put_if_absent(&format!("{target}.sha256-{digest}"), &bytes)
            .await
            .context("publish refused landed file")?;
        Ok(RefusedCopy::Kept)
    }
}

/// Largest refused landed file [`PublishedBronze`] publishes a copy of: the
/// C13 consumer store's write bound (`MAX_CONSUMER_WRITE`, 64 MiB). A larger
/// one is refused in place, never deleted.
pub const MAX_PUBLISHED_REFUSED_BYTES: u64 = 64 * 1024 * 1024;

/// The converter: one object store, one tenant, one ledger, one output
/// ([`BronzeObjects`] on open core, [`PublishedBronze`] on sovereign).
pub struct Converter<L: Ledger, E: Emit = BronzeObjects> {
    pub store: Operator,
    pub ledger: L,
    pub stage: LandingOcsfStage,
    pub tenant_id: String,
    /// Most objects handled per tick.
    pub max_files_per_tick: usize,
    pub emit: E,
}

impl<L: Ledger, E: Emit> Converter<L, E> {
    /// Handle every unfinished landed object of the tenant (listed by this
    /// converter, or by the ledger's lister), then report the backlog age.
    pub async fn tick(&self) -> Result<TickReport> {
        let discover = PrefixDiscover { ledger: &self.ledger };
        let mut report = Engine {
            store: &self.store,
            discover: &discover,
            emit: &self.emit,
            stage: &self.stage,
            tenant_id: &self.tenant_id,
            max_files_per_tick: self.max_files_per_tick,
        }
        .tick()
        .await?;
        match self.ledger.backlog_age().await {
            Ok(age) => {
                report.backlog_age_secs = age.map(|age| age.as_secs());
                if let Some(age) = age.filter(|age| *age > BACKLOG_ALERT_AFTER) {
                    tracing::error!(
                        alert = "landing_backlog_age",
                        tenant_id = %self.tenant_id,
                        backlog_age_secs = age.as_secs(),
                        threshold_secs = BACKLOG_ALERT_AFTER.as_secs(),
                        "a landed file has waited longer than the backlog threshold"
                    );
                }
            }
            Err(error) => tracing::warn!(error = %format!("{error:#}"), "landing backlog age unavailable"),
        }
        Ok(report)
    }
}

/// NAN-4682: landed files one converter handles at once: the machine's
/// cores, at least 4 (claims, reads and uploads overlap the conversions) and
/// at most 8.
pub fn landing_concurrency() -> usize {
    std::thread::available_parallelism().map_or(4, usize::from).clamp(4, 8)
}

/// NAN-4682: most landed bytes (listed object sizes) in flight at once. It is
/// [`MAX_LANDING_BYTES`], the largest file the serial converter held, so
/// concurrency never raises peak memory past the serial worst case.
pub const MAX_IN_FLIGHT_LANDED_BYTES: u64 = MAX_LANDING_BYTES;

/// NAN-4682: bronze objects of one file written at once.
pub const MAX_CONCURRENT_BRONZE_PUTS: usize = 8;

/// One tick's wiring: a store, a [`Discover`], an [`Emit`] and the stage.
pub struct Engine<'a, D: Discover, E: Emit> {
    pub store: &'a Operator,
    pub discover: &'a D,
    pub emit: &'a E,
    pub stage: &'a LandingOcsfStage,
    pub tenant_id: &'a str,
    /// Most files handled per tick.
    pub max_files_per_tick: usize,
}

impl<D: Discover, E: Emit> Engine<'_, D, E> {
    /// Discover and handle every unfinished file. One file never blocks
    /// another: a transient failure leaves it for a later tick.
    ///
    /// NAN-4682: up to [`landing_concurrency`] files are handled at once,
    /// each converted on a blocking thread. Every file is still claimed,
    /// converted, emitted and finished by its own `handle`, in that order,
    /// exactly as before: the claim (Postgres `(key, etag)` row, or the
    /// hosted ledger's lease) is what makes one file one owner, and it does
    /// not depend on the order files are handled in. Two candidates with
    /// the same key (an object overwritten between listings) never run at
    /// once; they keep their listed order. At most
    /// [`MAX_IN_FLIGHT_LANDED_BYTES`] of landed objects are in flight (a
    /// larger file runs alone), so peak memory stays the serial worst case.
    /// A held file (output backpressure) or a fenced lease stops new files
    /// from starting; files already started finish first.
    pub async fn tick(&self) -> Result<TickReport> {
        let mut report = TickReport::default();
        let (listed, candidates) = self.discover.discover(self.store, self.tenant_id, self.max_files_per_tick).await?;
        report.listed = listed;
        let limit = landing_concurrency();
        let mut queue: std::collections::VecDeque<Candidate> = candidates.into();
        let mut running = futures::stream::FuturesUnordered::new();
        let mut keys_running: std::collections::HashSet<String> = std::collections::HashSet::new();
        let mut bytes_running = 0_u64;
        let mut stopped = false;
        let mut fenced: Option<anyhow::Error> = None;
        loop {
            while !stopped && running.len() < limit {
                // The first queued file whose key is not running (same-key
                // files keep their order: an earlier one is always running).
                let Some(position) = queue.iter().position(|c| !keys_running.contains(&c.key)) else { break };
                let size = queue[position].size.min(MAX_IN_FLIGHT_LANDED_BYTES);
                if !running.is_empty() && bytes_running + size > MAX_IN_FLIGHT_LANDED_BYTES {
                    break;
                }
                let candidate = queue.remove(position).expect("position is in the queue");
                keys_running.insert(candidate.key.clone());
                bytes_running += size;
                running.push(async move {
                    let outcome = self.handle(&candidate).await;
                    // A transient failure is handed back inside this file's
                    // own future, so it never stalls the other files.
                    let handback = match &outcome {
                        Err(error) if error.downcast_ref::<Fenced>().is_none() => {
                            tracing::warn!(error = %format!("{error:#}"), "landing file not finished; retrying it later");
                            Some(self.discover.failed(self.store, &candidate).await)
                        }
                        _ => None,
                    };
                    (candidate, size, outcome, handback)
                });
            }
            let Some((candidate, size, outcome, handback)) = futures::StreamExt::next(&mut running).await else { break };
            keys_running.remove(&candidate.key);
            bytes_running -= size;
            match outcome {
                Ok(Outcome::Accepted) => report.accepted += 1,
                Ok(Outcome::Refused) => report.refused += 1,
                Ok(Outcome::Redelivered) => report.redelivered += 1,
                Ok(Outcome::Skipped) => report.skipped += 1,
                Ok(Outcome::Held) => {
                    report.held += 1;
                    stopped = true;
                }
                Err(error) if error.downcast_ref::<Fenced>().is_some() => {
                    stopped = true;
                    fenced.get_or_insert(error);
                }
                Err(_) => {
                    // Transient (store, database or output): open core lets
                    // the lease expire; hosted hands the file back to the
                    // ledger. A later tick retries it; the rest go on.
                    report.failed += 1;
                    match handback.unwrap_or(Ok(())) {
                        Ok(()) => {}
                        Err(error) if error.downcast_ref::<Fenced>().is_some() => {
                            stopped = true;
                            fenced.get_or_insert(error);
                        }
                        Err(error) => tracing::warn!(error = %format!("{error:#}"), "landing file hand-back failed"),
                    }
                }
            }
        }
        match fenced {
            Some(error) => Err(error),
            None => Ok(report),
        }
    }

    async fn handle(&self, candidate: &Candidate) -> Result<Outcome> {
        let key = candidate.key.as_str();
        let parsed = parse_key(key, self.tenant_id);
        let source_id = parsed.as_ref().ok().map(|k| k.source_id);
        let Claimed { claim, size, preloaded } = self.discover.claim(self.store, candidate, source_id).await?;
        let (id, attempt) = match claim {
            Claim::Owned { id, attempt } => (id, attempt),
            Claim::Leased => return Ok(Outcome::Skipped),
            Claim::Finished { id } => {
                self.discover.finish_redelivered(self.store, candidate, id).await?;
                tracing::info!(source_id = ?source_id, "landed file redelivered after it finished; deleted without reconverting");
                return Ok(Outcome::Redelivered);
            }
        };
        if attempt > MAX_ATTEMPTS {
            return self.refuse_whole(candidate, id, FileRefusal::new("attempts_exhausted"), None).await;
        }
        let parsed = match parsed {
            Ok(parsed) => parsed,
            Err(reason) => return self.refuse_whole(candidate, id, FileRefusal::new(reason), None).await,
        };
        let source = match self.discover.source(candidate, parsed.source_id).await? {
            Some(source) if source.active => source,
            Some(_) => return self.refuse_whole(candidate, id, FileRefusal::new("source_revoked"), None).await,
            None => return self.refuse_whole(candidate, id, FileRefusal::new("source_unknown"), None).await,
        };
        if size > MAX_LANDING_BYTES {
            return self.refuse_whole(candidate, id, FileRefusal::new("file_too_large"), None).await;
        }
        let bytes = match preloaded {
            Some(bytes) => bytes,
            None => self.store.read(key).await.context("read landed object")?.to_vec(),
        };
        if bytes.len() as u64 > MAX_LANDING_BYTES {
            return self.refuse_whole(candidate, id, FileRefusal::new("file_too_large"), None).await;
        }
        // NAN-4682: the conversion is CPU work; it runs on a blocking thread
        // so files convert in parallel and the runtime keeps serving I/O.
        let (stage, tenant_id, landed) = (self.stage.clone(), self.tenant_id.to_string(), source.clone());
        let (format, partition_class_uid) = (parsed.format, parsed.partition_class_uid);
        let (bytes, converted) = tokio::task::spawn_blocking(move || {
            let converted = convert_landed(&bytes, format, partition_class_uid, &stage, &tenant_id, &landed, Utc::now());
            (bytes, converted)
        })
        .await
        .context("landing conversion task")?;
        let converted = match converted {
            Ok(converted) => converted,
            Err(refusal) => {
                let sha = hex::encode(Sha256::digest(&bytes));
                return self.refuse_whole(candidate, id, refusal, Some(&sha)).await;
            }
        };
        drop(bytes);
        let emitted = match self.emit.emit(self.store, self.tenant_id, candidate, &converted).await {
            Ok(emitted) => emitted,
            Err(error) if error.downcast_ref::<Backpressure>().is_some() => {
                self.discover.release(candidate, id).await?;
                tracing::info!(source_id = %source.source_id, "landing output is full; file held for a later tick");
                return Ok(Outcome::Held);
            }
            // The output cannot take this file at all (hosted: a row larger
            // than one edge segment). Decided before anything is appended.
            Err(error) => match error.downcast_ref::<FileRefusal>() {
                Some(refusal) => {
                    let refusal = refusal.clone();
                    return self.refuse_whole(candidate, id, refusal, Some(&converted.content_sha256)).await;
                }
                None => return Err(error),
            },
        };
        self.discover.finish_accepted(self.store, candidate, id, &converted, &emitted).await?;
        tracing::info!(
            source_id = %source.source_id,
            rows_accepted = converted.rows_accepted,
            rows_refused = converted.rows_refused,
            first_row_reason = converted.first_refusal.as_ref().map_or("", |r| r.reason),
            first_row_detail = converted.first_refusal_detail.as_ref().map(RefusalDetail::render).unwrap_or_default(),
            rows_class_from_path = converted.rows_class_from_path,
            bronze_objects = converted.objects.len(),
            "landed file converted to bronze"
        );
        Ok(Outcome::Accepted)
    }

    async fn refuse_whole(&self, candidate: &Candidate, id: i64, refusal: FileRefusal, sha: Option<&str>) -> Result<Outcome> {
        let copy = self.emit.keep_refused(self.store, &candidate.key).await?;
        self.discover.finish_refused(self.store, candidate, id, &refusal, sha, copy).await?;
        if copy == RefusedCopy::InPlace {
            tracing::error!(
                alert = "landing_refused_in_place",
                tenant_id = %self.tenant_id,
                reason = refusal.reason,
                size_bytes = candidate.size,
                "landed file refused and no copy could be kept: it stays where it landed and is never deleted; \
                 an operator must fix and re-send or remove it"
            );
            return Ok(Outcome::Refused);
        }
        tracing::warn!(
            reason = refusal.reason,
            rows_refused = refusal.rows,
            detail = refusal.detail.as_ref().map(RefusalDetail::render).unwrap_or_default(),
            "landed file refused whole; moved under {REFUSED_PREFIX}"
        );
        Ok(Outcome::Refused)
    }
}

enum Outcome {
    Accepted,
    Refused,
    Redelivered,
    Skipped,
    Held,
}

/// The Postgres ledger (`landing_sources` / `landing_files` / `landing_listers`,
/// migrations 364 and 374). Bound to ONE tenant: every query it makes is
/// filtered by `tenant_id`, so a converter never sees, claims or finishes
/// another tenant's file or source (several tenants may share the database).
pub struct PgLedger {
    pub pool: sqlx::PgPool,
    /// How long one claim owns a file before another tick may retry it.
    pub lease: std::time::Duration,
    /// The tenant this ledger serves (the converter's `tenant_id`).
    pub tenant_id: String,
    /// This converter node (holder id of the tenant's lister lease).
    pub node: Uuid,
}

/// Finished ledger rows kept for the status view.
pub const LEDGER_RETENTION_DAYS: i32 = 30;

/// How long one node holds a tenant's lister lease without renewing it. The
/// holder renews it every tick; another node takes over once it lapses.
pub const LISTER_LEASE: std::time::Duration = std::time::Duration::from_secs(60);

/// One listed landed object, as the lister records it.
struct ListedObject {
    key: String,
    etag: String,
    size: i64,
    source_id: Option<Uuid>,
    landed_at: Option<DateTime<Utc>>,
}

impl PgLedger {
    /// A ledger for `tenant_id` with a fresh node id.
    pub fn new(pool: sqlx::PgPool, lease: std::time::Duration, tenant_id: impl Into<String>) -> Self {
        Self { pool, lease, tenant_id: tenant_id.into(), node: Uuid::new_v4() }
    }

    /// Drop this tenant's finished rows past [`LEDGER_RETENTION_DAYS`], and
    /// claims abandoned for a week (the object was finished but the ledger
    /// write failed). A redelivery of a pruned file is converted again; its
    /// rows keep their uids, so the lake's uid window drops them while it
    /// still covers them.
    pub async fn prune(&self) -> Result<u64> {
        let done = sqlx::query(
            "DELETE FROM landing_files \
              WHERE tenant_id = $2 AND NOT refused_in_place \
                AND ((state IN ('accepted', 'refused') AND finished_at < NOW() - make_interval(days => $1)) \
                  OR (state = 'claimed' AND lease_until < NOW() - INTERVAL '7 days'))",
        )
        .bind(LEDGER_RETENTION_DAYS)
        .bind(&self.tenant_id)
        .execute(&self.pool)
        .await
        .context("prune landing ledger")?;
        Ok(done.rows_affected())
    }

    /// Rows written before migration 374 have no tenant. Files take the
    /// tenant of their key's folder (only this tenant's folder is adopted).
    /// A source takes this tenant only on evidence that it is this tenant's:
    /// none of its files lies outside this tenant's folder, and either one
    /// lies inside it, or the whole database shows no other tenant (no other
    /// tenant's source, no file outside this folder). Whichever tenant's
    /// converter starts first, it never adopts another tenant's source. A
    /// source with no files on a multi-tenant install stays unadopted (its
    /// files are refused `source_unknown`) until an operator sets it.
    pub async fn adopt_legacy_rows(&self) -> Result<(u64, u64)> {
        let folder = format!("{LANDING_PREFIX}tenant_id={}/", self.tenant_id);
        let files = sqlx::query(
            "UPDATE landing_files SET tenant_id = $1 \
              WHERE tenant_id IS NULL AND starts_with(object_key, $2)",
        )
        .bind(&self.tenant_id)
        .bind(&folder)
        .execute(&self.pool)
        .await
        .context("adopt pre-374 landing files")?;
        let sources = sqlx::query(
            "UPDATE landing_sources s SET tenant_id = $1 \
              WHERE s.tenant_id IS NULL \
                AND NOT EXISTS (SELECT 1 FROM landing_files f \
                                 WHERE f.source_id = s.source_id AND NOT starts_with(f.object_key, $2)) \
                AND (EXISTS (SELECT 1 FROM landing_files f \
                              WHERE f.source_id = s.source_id AND starts_with(f.object_key, $2)) \
                     OR (NOT EXISTS (SELECT 1 FROM landing_sources o WHERE o.tenant_id IS NOT NULL AND o.tenant_id <> $1) \
                         AND NOT EXISTS (SELECT 1 FROM landing_files f WHERE NOT starts_with(f.object_key, $2))))",
        )
        .bind(&self.tenant_id)
        .bind(&folder)
        .execute(&self.pool)
        .await
        .context("adopt pre-374 landing sources")?;
        Ok((files.rows_affected(), sources.rows_affected()))
    }

    /// Take or renew the tenant's lister lease. `true`: this node lists.
    pub async fn hold_lister(&self) -> Result<bool> {
        let held: Option<(Uuid,)> = sqlx::query_as(
            "INSERT INTO landing_listers (tenant_id, holder, lease_until) \
             VALUES ($1, $2, NOW() + make_interval(secs => $3)) \
             ON CONFLICT (tenant_id) DO UPDATE \
                SET holder = EXCLUDED.holder, lease_until = EXCLUDED.lease_until \
              WHERE landing_listers.holder = EXCLUDED.holder OR landing_listers.lease_until < NOW() \
             RETURNING holder",
        )
        .bind(&self.tenant_id)
        .bind(self.node)
        .bind(LISTER_LEASE.as_secs_f64())
        .fetch_optional(&self.pool)
        .await
        .context("hold landing lister lease")?;
        Ok(held.is_some_and(|(holder,)| holder == self.node))
    }

    /// The lease holder's step: list the tenant's landing folder once and
    /// record every object as a `listed` row (a known (key, etag) is left as
    /// it is). A `listed` row whose object is gone from a complete listing is
    /// dropped (deleted or overwritten out of band; nothing claimed it).
    /// Returns how many objects the listing held.
    pub async fn list_into_ledger(&self, store: &Operator) -> Result<usize> {
        let started: DateTime<Utc> = sqlx::query_scalar("SELECT NOW()").fetch_one(&self.pool).await.context("ledger clock")?;
        let prefix = format!("{LANDING_PREFIX}tenant_id={}/", self.tenant_id);
        let entries = store.list_with(&prefix).recursive(true).await.context("list landing prefix")?;
        let mut objects = Vec::new();
        for entry in entries.into_iter().filter(|entry| !entry.path().ends_with('/')) {
            let key = entry.path().to_string();
            let meta = entry.metadata();
            let (etag, size, _) = landed_etag(store, &key, meta.etag(), meta.content_length()).await?;
            let landed_at = meta.last_modified().map(|at| DateTime::<Utc>::from(std::time::SystemTime::from(at)));
            let source_id = parse_key(&key, &self.tenant_id).ok().map(|parsed| parsed.source_id);
            objects.push(ListedObject { key, etag, size: to_i64(size), source_id, landed_at });
        }
        objects.sort_by(|a, b| a.key.cmp(&b.key));
        let listed = objects.len();
        let keys: Vec<&str> = objects.iter().map(|o| o.key.as_str()).collect();
        let etags: Vec<&str> = objects.iter().map(|o| o.etag.as_str()).collect();
        let sizes: Vec<i64> = objects.iter().map(|o| o.size).collect();
        let sources: Vec<Option<Uuid>> = objects.iter().map(|o| o.source_id).collect();
        let landed: Vec<Option<DateTime<Utc>>> = objects.iter().map(|o| o.landed_at).collect();
        let mut tx = self.pool.begin().await.context("begin listing")?;
        sqlx::query(
            "INSERT INTO landing_files (tenant_id, object_key, etag, source_id, size_bytes, state, attempts, landed_at) \
             SELECT $1, o.key, o.etag, \
                    (SELECT s.source_id FROM landing_sources s WHERE s.source_id = o.source_id AND s.tenant_id = $1), \
                    o.size, 'listed', 0, o.landed_at \
               FROM UNNEST($2::text[], $3::text[], $4::bigint[], $5::uuid[], $6::timestamptz[]) WITH ORDINALITY \
                    AS o(key, etag, size, source_id, landed_at, ord) \
              ORDER BY o.ord \
             ON CONFLICT (object_key, etag) DO NOTHING",
        )
        .bind(&self.tenant_id)
        .bind(&keys)
        .bind(&etags)
        .bind(&sizes)
        .bind(&sources)
        .bind(&landed)
        .execute(&mut *tx)
        .await
        .context("record listed landed files")?;
        sqlx::query(
            "DELETE FROM landing_files f \
              WHERE f.tenant_id = $1 AND f.state = 'listed' AND f.first_seen_at < $2 \
                AND NOT EXISTS (SELECT 1 FROM UNNEST($3::text[], $4::text[]) AS o(key, etag) \
                                 WHERE o.key = f.object_key AND o.etag = f.etag)",
        )
        .bind(&self.tenant_id)
        .bind(started)
        .bind(&keys)
        .bind(&etags)
        .execute(&mut *tx)
        .await
        .context("drop listed rows whose object is gone")?;
        sqlx::query("UPDATE landing_listers SET listed_at = NOW() WHERE tenant_id = $1 AND holder = $2")
            .bind(&self.tenant_id)
            .bind(self.node)
            .execute(&mut *tx)
            .await
            .context("record listing time")?;
        tx.commit().await.context("commit listing")?;
        Ok(listed)
    }
}

/// Deletes a landing source's object-store credential: its write-only user
/// and its policy (`landing-<source_id>`). Removing what is already gone is
/// success.
#[async_trait]
pub trait CredentialRemover: Send + Sync {
    async fn remove(&self, object_user: &str, source_id: Uuid) -> Result<()>;
}

/// A landing source whose log source no longer exists.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OrphanedSource {
    pub source_id: Uuid,
    pub object_user: String,
    /// Already revoked (`lake_landing_ingest revoke`): its user is gone.
    pub revoked: bool,
}

impl PgLedger {
    /// This tenant's landing sources whose log source was deleted (no foreign
    /// key ties them, migration 364). Each still owns an object-store user
    /// until revoked.
    pub async fn orphaned_sources(&self) -> Result<Vec<OrphanedSource>> {
        let rows: Vec<(Uuid, String, String)> = sqlx::query_as(
            "SELECT ls.source_id, ls.object_user, ls.state FROM landing_sources ls \
              WHERE ls.tenant_id = $1 \
                AND NOT EXISTS (SELECT 1 FROM log_sources s WHERE s.id = ls.source_id) \
              ORDER BY ls.source_id",
        )
        .bind(&self.tenant_id)
        .fetch_all(&self.pool)
        .await
        .context("list orphaned landing sources")?;
        Ok(rows
            .into_iter()
            .map(|(source_id, object_user, state)| OrphanedSource { source_id, object_user, revoked: state == "revoked" })
            .collect())
    }

    /// Revoke every orphaned landing source: delete its object-store user and
    /// policy, then its row (its ledger rows keep their history with
    /// `source_id` NULL). A source whose credential could not be removed keeps
    /// its row and is retried on the next sweep. Returns the sources revoked.
    pub async fn revoke_orphans(&self, remover: &dyn CredentialRemover) -> Result<Vec<Uuid>> {
        let mut revoked = Vec::new();
        for orphan in self.orphaned_sources().await? {
            if !orphan.revoked {
                if let Err(error) = remover.remove(&orphan.object_user, orphan.source_id).await {
                    tracing::warn!(source_id = %orphan.source_id, error = %format!("{error:#}"),
                        "orphaned landing source: removing its object-store user failed; retrying next sweep");
                    continue;
                }
            }
            sqlx::query(
                "DELETE FROM landing_sources ls WHERE ls.source_id = $1 AND ls.tenant_id = $2 \
                   AND NOT EXISTS (SELECT 1 FROM log_sources s WHERE s.id = ls.source_id)",
            )
            .bind(orphan.source_id)
            .bind(&self.tenant_id)
            .execute(&self.pool)
            .await
            .context("delete orphaned landing source")?;
            tracing::info!(source_id = %orphan.source_id, "landing source of a deleted log source revoked: object-store user and policy deleted");
            revoked.push(orphan.source_id);
        }
        Ok(revoked)
    }
}

fn to_i64(value: u64) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

#[async_trait]
impl Ledger for PgLedger {
    async fn source(&self, source_id: Uuid) -> Result<Option<LandingSource>> {
        // Active only while its log source exists: no foreign key ties the two
        // (migration 364), so a deleted log source stops intake here at once,
        // before the orphan sweep revokes its key. Another tenant's source is
        // unknown here (migration 374).
        let row: Option<(Uuid, String, Uuid, String, bool)> = sqlx::query_as(
            "SELECT ls.source_id, ls.route_key, ls.credential_id, ls.state, \
                    EXISTS (SELECT 1 FROM log_sources s WHERE s.id = ls.source_id) \
               FROM landing_sources ls WHERE ls.source_id = $1 AND ls.tenant_id = $2",
        )
        .bind(source_id)
        .bind(&self.tenant_id)
        .fetch_optional(&self.pool)
        .await
        .context("read landing source")?;
        Ok(row.map(|(source_id, route_key, credential_id, state, log_source_exists)| LandingSource {
            source_id,
            route_key,
            credential_id,
            active: state == "active" && log_source_exists,
        }))
    }

    async fn claim(&self, key: &str, etag: &str, size: u64, source_id: Option<Uuid>) -> Result<Claim> {
        let lease_secs = i32::try_from(self.lease.as_secs().max(1)).unwrap_or(i32::MAX);
        // New: insert as claimed. Listed, or claimed with an expired lease:
        // take it. Another tenant's row is never taken (its key is in another
        // folder, and the tenant must match). Anything else: no row comes
        // back and the state is read below.
        let owned: Option<(i64, i32)> = sqlx::query_as(
            "INSERT INTO landing_files (tenant_id, object_key, etag, source_id, size_bytes, state, attempts, lease_until) \
             VALUES ($6, $1, $2, (SELECT source_id FROM landing_sources WHERE source_id = $3 AND tenant_id = $6), $4, \
                     'claimed', 1, NOW() + make_interval(secs => $5)) \
             ON CONFLICT (object_key, etag) DO UPDATE \
                SET state = 'claimed', \
                    attempts = landing_files.attempts + 1, \
                    lease_until = NOW() + make_interval(secs => $5) \
              WHERE landing_files.tenant_id = EXCLUDED.tenant_id \
                AND (landing_files.state = 'listed' \
                     OR (landing_files.state = 'claimed' AND landing_files.lease_until < NOW())) \
             RETURNING id, attempts",
        )
        .bind(key)
        .bind(etag)
        .bind(source_id)
        .bind(to_i64(size))
        .bind(f64::from(lease_secs))
        .bind(&self.tenant_id)
        .fetch_optional(&self.pool)
        .await
        .context("claim landed file")?;
        if let Some((id, attempt)) = owned {
            return Ok(Claim::Owned { id, attempt });
        }
        let existing: Option<(i64, String, bool)> = sqlx::query_as(
            "SELECT id, state, refused_in_place FROM landing_files WHERE object_key = $1 AND etag = $2 AND tenant_id = $3",
        )
        .bind(key)
        .bind(etag)
        .bind(&self.tenant_id)
        .fetch_optional(&self.pool)
        .await
        .context("read landed file claim")?;
        Ok(match existing {
            // Refused in place: still where it landed by design. Never a
            // redelivery (that deletes it) and never claimed again.
            Some((_, _, true)) => Claim::Leased,
            Some((id, state, false)) if state == "accepted" || state == "refused" => Claim::Finished { id },
            _ => Claim::Leased,
        })
    }

    async fn accepted(&self, id: i64, converted: &Converted, bronze_keys: &str) -> Result<()> {
        sqlx::query(
            "UPDATE landing_files SET state = 'accepted', rows_accepted = $2, rows_refused = $3, \
                    reason = $4, content_sha256 = $5, bronze_key = $6, lease_until = NULL, finished_at = NOW() \
              WHERE id = $1 AND tenant_id = $7",
        )
        .bind(id)
        .bind(to_i64(converted.rows_accepted))
        .bind(to_i64(converted.rows_refused))
        .bind(converted.first_refusal.as_ref().map(|refusal| refusal.reason))
        .bind(&converted.content_sha256)
        .bind(bronze_keys)
        .bind(&self.tenant_id)
        .execute(&self.pool)
        .await
        .context("record accepted landed file")?;
        Ok(())
    }

    async fn refused(&self, id: i64, reason: &str, rows_refused: u64, content_sha256: Option<&str>) -> Result<()> {
        sqlx::query(
            "UPDATE landing_files SET state = 'refused', rows_refused = $3, reason = $2, \
                    content_sha256 = COALESCE($4, content_sha256), lease_until = NULL, finished_at = NOW() \
              WHERE id = $1 AND tenant_id = $5",
        )
        .bind(id)
        .bind(reason)
        .bind(to_i64(rows_refused))
        .bind(content_sha256)
        .bind(&self.tenant_id)
        .execute(&self.pool)
        .await
        .context("record refused landed file")?;
        Ok(())
    }

    async fn refused_in_place(&self, id: i64, reason: &str, rows_refused: u64, content_sha256: Option<&str>) -> Result<()> {
        sqlx::query(
            "UPDATE landing_files SET state = 'refused', refused_in_place = TRUE, rows_refused = $3, reason = $2, \
                    content_sha256 = COALESCE($4, content_sha256), lease_until = NULL, finished_at = NOW() \
              WHERE id = $1 AND tenant_id = $5",
        )
        .bind(id)
        .bind(reason)
        .bind(to_i64(rows_refused))
        .bind(content_sha256)
        .bind(&self.tenant_id)
        .execute(&self.pool)
        .await
        .context("record landed file refused in place")?;
        Ok(())
    }

    async fn redelivered(&self, id: i64) -> Result<()> {
        sqlx::query("UPDATE landing_files SET redeliveries = redeliveries + 1 WHERE id = $1 AND tenant_id = $2")
            .bind(id)
            .bind(&self.tenant_id)
            .execute(&self.pool)
            .await
            .context("record redelivered landed file")?;
        Ok(())
    }

    async fn pending(&self, store: &Operator, tenant_id: &str, max: usize) -> Result<Option<(usize, Vec<Candidate>)>> {
        anyhow::ensure!(tenant_id == self.tenant_id, "landing ledger is bound to another tenant");
        // Only the lease holder lists (one LIST per tick per tenant, not per
        // node). A failed listing leaves the rows already recorded claimable.
        match self.hold_lister().await {
            Ok(true) => {
                if let Err(error) = self.list_into_ledger(store).await {
                    tracing::warn!(error = %format!("{error:#}"), "landing listing failed; claiming what the ledger holds");
                }
            }
            Ok(false) => {}
            Err(error) => tracing::warn!(error = %format!("{error:#}"), "landing lister lease unavailable"),
        }
        let limit = i64::try_from(max).unwrap_or(i64::MAX);
        let rows: Vec<(String, String, i64)> = sqlx::query_as(
            "SELECT object_key, etag, size_bytes FROM landing_files \
              WHERE tenant_id = $1 \
                AND (state = 'listed' OR (state = 'claimed' AND lease_until < NOW())) \
              ORDER BY id LIMIT $2",
        )
        .bind(&self.tenant_id)
        .bind(limit)
        .fetch_all(&self.pool)
        .await
        .context("read claimable landed files")?;
        let open: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM landing_files WHERE tenant_id = $1 AND state IN ('listed', 'claimed')",
        )
        .bind(&self.tenant_id)
        .fetch_one(&self.pool)
        .await
        .context("count unfinished landed files")?;
        let candidates = rows
            .into_iter()
            .map(|(key, etag, size)| Candidate { key, etag: Some(etag), size: u64::try_from(size).unwrap_or(0), leased: None })
            .collect();
        Ok(Some((usize::try_from(open).unwrap_or(usize::MAX), candidates)))
    }

    async fn backlog_age(&self) -> Result<Option<std::time::Duration>> {
        let age: Option<f64> = sqlx::query_scalar(
            "SELECT EXTRACT(EPOCH FROM NOW() - MIN(COALESCE(landed_at, first_seen_at)))::float8 \
               FROM landing_files WHERE tenant_id = $1 AND state IN ('listed', 'claimed')",
        )
        .bind(&self.tenant_id)
        .fetch_one(&self.pool)
        .await
        .context("read landing backlog age")?;
        Ok(age.map(|secs| std::time::Duration::from_secs_f64(secs.max(0.0))))
    }
}

/// NAN-4629 (coordinator Q-A): the converter's own object-store policy for
/// one tenant, separate from every sender key and every consumer grant. It
/// may list, read and delete what landed in the tenant's landing folder and
/// nothing else: no put anywhere (bronze and the refused copy are published
/// through the consumer store, [`PublishedBronze`]), no other tenant, no
/// other source's key material. On RustFS it is the converter user's one
/// policy; on BYO S3 it is the IAM policy template for the converter
/// principal. Same statements as the H03 `Purpose::LandingConvert` grant.
pub fn converter_policy(bucket: &str, tenant_id: &str) -> Value {
    let folder = format!("{LANDING_PREFIX}tenant_id={tenant_id}/");
    serde_json::json!({
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["s3:ListBucket"],
                "Resource": [format!("arn:aws:s3:::{bucket}")],
                "Condition": {"StringLike": {"s3:prefix": [folder.clone(), format!("{folder}*")]}}
            },
            {
                "Effect": "Allow",
                "Action": ["s3:GetObject", "s3:DeleteObject"],
                "Resource": [format!("arn:aws:s3:::{bucket}/{folder}*")]
            }
        ]
    })
}

/// The write-only object-store policy of one landing source.
pub fn source_policy(bucket: &str, tenant_id: &str, source_id: Uuid) -> Value {
    serde_json::json!({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Action": ["s3:PutObject"],
            "Resource": [format!("arn:aws:s3:::{bucket}/{LANDING_PREFIX}tenant_id={tenant_id}/source={}/*", source_id.hyphenated())]
        }]
    })
}

#[cfg(test)]
#[path = "landing_tests.rs"]
mod tests;
