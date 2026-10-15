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
//!    yields the same uids.
//! 3. **Pre-check.** Each row goes through the same checks bronze admission
//!    runs ([`crate::bronze::precheck_source_row`]: strict OCSF 1.9 included).
//!    Refused rows are counted by value-free reason and left out.
//! 4. **Write.** The accepted rows become one bronze object per bronze shard,
//!    `bronze-v2/[shard=N/]tenant_id=<T>/<unix secs>-<uuid>.parquet`, with the
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
//! another.

use anyhow::{Context, Result};
use arrow_array::{ArrayRef, RecordBatch, StringArray, TimestampMicrosecondArray};
use arrow_json::LineDelimitedWriter;
use arrow_schema::{DataType, Field, Schema, TimeUnit};
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
use std::io::Read;
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
/// Most rows one landed file may carry (one bronze admission's bound).
pub const MAX_LANDING_ROWS: usize = MAX_BRONZE_ROWS;
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
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileFormat {
    Parquet,
    Ndjson { gzip: bool },
}

/// Parse `landing-ocsf-v1/tenant_id=<T>/source=<uuid>/<path>.<ext>`.
/// `Err` carries the value-free refusal reason.
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
    Ok(LandingKey { source_id, format })
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
    pub content_sha256: String,
}

/// A file refused whole, with its value-free reason.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("landed file refused: {reason}")]
pub struct FileRefusal {
    pub reason: &'static str,
}

fn refuse<T>(reason: &'static str) -> std::result::Result<T, FileRefusal> {
    Err(FileRefusal { reason })
}

/// Read a landed file's rows as JSON objects, exactly as bronze admission
/// reads Parquet (Arrow's line-delimited JSON writer: nulls omitted).
pub fn read_rows(bytes: &[u8], format: FileFormat) -> std::result::Result<Vec<Value>, FileRefusal> {
    let mut rows = Vec::new();
    fn push(rows: &mut Vec<Value>, line: &[u8]) -> std::result::Result<(), FileRefusal> {
        if rows.len() >= MAX_LANDING_ROWS {
            return refuse("too_many_rows");
        }
        match serde_json::from_slice::<Value>(line) {
            Ok(value @ Value::Object(_)) => rows.push(value),
            // A non-object line is a row the stage refuses; keep its place.
            Ok(_) | Err(_) => rows.push(Value::Null),
        }
        Ok(())
    }
    match format {
        FileFormat::Parquet => {
            let reader = ParquetRecordBatchReaderBuilder::try_new(Bytes::copy_from_slice(bytes))
                .and_then(|builder| builder.with_batch_size(8_192).build())
                .or_else(|_| refuse("parquet_unreadable"))?;
            for batch in reader {
                let batch = batch.or_else(|_| refuse("parquet_unreadable"))?;
                if rows.len() + batch.num_rows() > MAX_LANDING_ROWS {
                    return refuse("too_many_rows");
                }
                let mut writer = LineDelimitedWriter::new(Vec::new());
                writer.write(&batch).or_else(|_| refuse("parquet_unreadable"))?;
                writer.finish().or_else(|_| refuse("parquet_unreadable"))?;
                for line in writer.into_inner().split(|b| *b == b'\n').filter(|l| !l.is_empty()) {
                    push(&mut rows, line)?;
                }
            }
        }
        FileFormat::Ndjson { gzip } => {
            let mut decoded = Vec::new();
            let source: Box<dyn Read> = if gzip {
                Box::new(flate2::read::GzDecoder::new(bytes))
            } else {
                Box::new(bytes)
            };
            source
                .take(MAX_DECODED_BYTES + 1)
                .read_to_end(&mut decoded)
                .or_else(|_| refuse("ndjson_unreadable"))?;
            if decoded.len() as u64 > MAX_DECODED_BYTES {
                return refuse("file_too_large");
            }
            for line in decoded.split(|b| *b == b'\n') {
                let line = line.strip_suffix(b"\r").unwrap_or(line);
                if line.iter().all(u8::is_ascii_whitespace) {
                    continue;
                }
                push(&mut rows, line)?;
            }
        }
    }
    if rows.is_empty() {
        return refuse("no_rows");
    }
    Ok(rows)
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
    let schema = Arc::new(Schema::new(vec![
        Field::new(BRONZE_EVENT_COLUMN, DataType::Utf8, true),
        Field::new(BRONZE_TIME_COLUMN, DataType::Timestamp(TimeUnit::Microsecond, Some("UTC".into())), true),
    ]));
    let events = StringArray::from_iter_values(rows.iter().map(|row| row.event_json.as_str()));
    let times = TimestampMicrosecondArray::from_iter_values(rows.iter().map(|row| row.time_micros)).with_timezone("UTC");
    let batch = RecordBatch::try_new(schema.clone(), vec![Arc::new(events) as ArrayRef, Arc::new(times) as ArrayRef])?;
    let properties = WriterProperties::builder()
        .set_compression(Compression::ZSTD(ZstdLevel::try_new(BRONZE_ZSTD_LEVEL)?))
        .build();
    let mut out = Vec::new();
    let mut writer = ArrowWriter::try_new(&mut out, schema, Some(properties))?;
    writer.write(&batch)?;
    writer.close()?;
    Ok(out)
}

/// Read back an encoded bronze object the way admission does: one decoded
/// event per row, in order.
fn decode_bronze(bytes: &[u8]) -> Result<Vec<Result<Value>>> {
    let reader = ParquetRecordBatchReaderBuilder::try_new(Bytes::copy_from_slice(bytes))?.build()?;
    let mut out = Vec::new();
    for batch in reader {
        let mut writer = LineDelimitedWriter::new(Vec::new());
        writer.write(&batch?)?;
        writer.finish()?;
        for line in writer.into_inner().split(|b| *b == b'\n').filter(|l| !l.is_empty()) {
            out.push(serde_json::from_slice::<Value>(line).map_err(anyhow::Error::from).and_then(decode_bronze_row));
        }
    }
    Ok(out)
}

/// The bronze object key Vector's sink would write now.
pub fn bronze_key(partition: &str, tenant_id: &str, now: DateTime<Utc>) -> String {
    format!("{BRONZE_PREFIX}{partition}tenant_id={tenant_id}/{}-{}.parquet", now.timestamp(), Uuid::new_v4())
}

/// Convert one landed file. `Err` refuses the file whole.
pub fn convert_file(
    bytes: &[u8],
    format: FileFormat,
    stage: &LandingOcsfStage,
    tenant_id: &str,
    source: &LandingSource,
    now: DateTime<Utc>,
) -> std::result::Result<Converted, FileRefusal> {
    let content_sha256 = hex::encode(Sha256::digest(bytes));
    let rows = read_rows(bytes, format)?;
    let credential = source.credential_id.hyphenated().to_string();
    let mut prepared = Vec::with_capacity(rows.len());
    let mut rows_refused = 0_u64;
    let mut first_refusal: Option<RowRefusal> = None;
    let mut note = |refusal: RowRefusal, refused: &mut u64| {
        *refused += 1;
        first_refusal.get_or_insert(refusal);
    };
    for (ordinal, mut row) in rows.into_iter().enumerate() {
        if !row.is_object() {
            note(RowRefusal::new("event_not_object", None), &mut rows_refused);
            continue;
        }
        normalize_time(&mut row);
        let ctx = StageContext {
            tenant_id,
            source_type: &source.route_key,
            credential_id: &credential,
            event_key: Some(format!("{content_sha256}:{ordinal}")),
        };
        match stage.prepare(row, &ctx) {
            Ok(bronze) => prepared.push(bronze),
            Err(_) => note(RowRefusal::new("storage_stage_dropped", None), &mut rows_refused),
        }
    }
    // Pre-check exactly what admission will read: encode, decode, check.
    let mut accepted: Vec<&BronzeRow> = Vec::with_capacity(prepared.len());
    if !prepared.is_empty() {
        let all = prepared.iter().collect::<Vec<_>>();
        let encoded = encode_bronze(&all).or_else(|_| refuse("bronze_encode_failed"))?;
        let decoded = decode_bronze(&encoded).or_else(|_| refuse("bronze_encode_failed"))?;
        if decoded.len() != prepared.len() {
            return refuse("bronze_encode_failed");
        }
        for (row, event) in prepared.iter().zip(decoded) {
            let verdict = event
                .map_err(|error| crate::bronze::classify_row_refusal(&error))
                .and_then(|event| precheck_source_row(event, tenant_id));
            match verdict {
                Ok(()) => accepted.push(row),
                Err(refusal) => note(refusal, &mut rows_refused),
            }
        }
    }
    if accepted.is_empty() {
        return Err(FileRefusal { reason: first_refusal.map_or("no_rows", |r| r.reason) });
    }
    let mut by_partition: BTreeMap<&str, Vec<&BronzeRow>> = BTreeMap::new();
    for row in &accepted {
        by_partition.entry(row.partition.as_str()).or_default().push(row);
    }
    let mut objects = Vec::with_capacity(by_partition.len());
    for (partition, rows) in by_partition {
        let bytes = encode_bronze(&rows).or_else(|_| refuse("bronze_encode_failed"))?;
        objects.push((bronze_key(partition, tenant_id, now), bytes, rows.len() as u64));
    }
    Ok(Converted {
        objects,
        rows_accepted: accepted.len() as u64,
        rows_refused,
        first_refusal,
        content_sha256,
    })
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
}

/// What one tick did (for logs and tests).
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct TickReport {
    pub listed: usize,
    pub accepted: usize,
    pub refused: usize,
    pub redelivered: usize,
    pub skipped: usize,
    pub failed: usize,
}

/// The converter: one object store, one tenant, one ledger.
pub struct Converter<L: Ledger> {
    pub store: Operator,
    pub ledger: L,
    pub stage: LandingOcsfStage,
    pub tenant_id: String,
    /// Most objects handled per tick.
    pub max_files_per_tick: usize,
}

impl<L: Ledger> Converter<L> {
    /// List the tenant's landing folder and handle every unfinished object.
    pub async fn tick(&self) -> Result<TickReport> {
        let prefix = format!("{LANDING_PREFIX}tenant_id={}/", self.tenant_id);
        let mut report = TickReport::default();
        let entries = self.store.list_with(&prefix).recursive(true).await.context("list landing prefix")?;
        let mut objects = entries
            .into_iter()
            .filter(|entry| !entry.path().ends_with('/'))
            .collect::<Vec<_>>();
        objects.sort_by(|a, b| a.path().cmp(b.path()));
        report.listed = objects.len();
        for entry in objects.into_iter().take(self.max_files_per_tick) {
            let key = entry.path().to_string();
            match self.handle(&key, entry.metadata().etag(), entry.metadata().content_length()).await {
                Ok(Outcome::Accepted) => report.accepted += 1,
                Ok(Outcome::Refused) => report.refused += 1,
                Ok(Outcome::Redelivered) => report.redelivered += 1,
                Ok(Outcome::Skipped) => report.skipped += 1,
                Err(error) => {
                    // Transient (store or database): the lease expires and a
                    // later tick retries this file; the rest go on.
                    tracing::warn!(error = %format!("{error:#}"), "landing file not finished; retrying after its lease");
                    report.failed += 1;
                }
            }
        }
        Ok(report)
    }

    async fn handle(&self, key: &str, listed_etag: Option<&str>, listed_size: u64) -> Result<Outcome> {
        // Listings normally carry the etag; stat when they do not, and fall
        // back to the content digest for a store that reports none.
        let mut preloaded: Option<Vec<u8>> = None;
        let (etag, size) = match listed_etag.map(|etag| etag.trim_matches('"')) {
            Some(etag) if !etag.is_empty() => (etag.to_string(), listed_size),
            _ => {
                let meta = self.store.stat(key).await.context("stat landed object")?;
                match meta.etag().map(|etag| etag.trim_matches('"')).filter(|etag| !etag.is_empty()) {
                    Some(etag) => (etag.to_string(), meta.content_length()),
                    None => {
                        if meta.content_length() > MAX_LANDING_BYTES {
                            (format!("size:{}", meta.content_length()), meta.content_length())
                        } else {
                            let bytes = self.store.read(key).await.context("read landed object")?.to_vec();
                            let digest = format!("sha256:{}", hex::encode(Sha256::digest(&bytes)));
                            let size = bytes.len() as u64;
                            preloaded = Some(bytes);
                            (digest, size)
                        }
                    }
                }
            }
        };
        let parsed = parse_key(key, &self.tenant_id);
        let source_id = parsed.as_ref().ok().map(|k| k.source_id);
        let (id, attempt) = match self.ledger.claim(key, &etag, size, source_id).await? {
            Claim::Owned { id, attempt } => (id, attempt),
            Claim::Leased => return Ok(Outcome::Skipped),
            Claim::Finished { id } => {
                self.store.delete(key).await.context("delete redelivered landed object")?;
                self.ledger.redelivered(id).await?;
                tracing::info!(source_id = ?source_id, "landed file redelivered after it finished; deleted without reconverting");
                return Ok(Outcome::Redelivered);
            }
        };
        if attempt > MAX_ATTEMPTS {
            return self.refuse_whole(id, key, "attempts_exhausted", 0, None).await;
        }
        let parsed = match parsed {
            Ok(parsed) => parsed,
            Err(reason) => return self.refuse_whole(id, key, reason, 0, None).await,
        };
        let source = match self.ledger.source(parsed.source_id).await? {
            Some(source) if source.active => source,
            Some(_) => return self.refuse_whole(id, key, "source_revoked", 0, None).await,
            None => return self.refuse_whole(id, key, "source_unknown", 0, None).await,
        };
        if size > MAX_LANDING_BYTES {
            return self.refuse_whole(id, key, "file_too_large", 0, None).await;
        }
        let bytes = match preloaded {
            Some(bytes) => bytes,
            None => self.store.read(key).await.context("read landed object")?.to_vec(),
        };
        if bytes.len() as u64 > MAX_LANDING_BYTES {
            return self.refuse_whole(id, key, "file_too_large", 0, None).await;
        }
        let converted = match convert_file(&bytes, parsed.format, &self.stage, &self.tenant_id, &source, Utc::now()) {
            Ok(converted) => converted,
            Err(FileRefusal { reason }) => {
                let sha = hex::encode(Sha256::digest(&bytes));
                return self.refuse_whole(id, key, reason, 0, Some(&sha)).await;
            }
        };
        let mut keys = Vec::with_capacity(converted.objects.len());
        for (bronze_key, body, _) in &converted.objects {
            self.store.write(bronze_key, body.clone()).await.context("write bronze object")?;
            keys.push(bronze_key.as_str());
        }
        // Bronze is durable before the landed object goes: a crash here only
        // means a reconversion, whose rows the uid window drops.
        self.store.delete(key).await.context("delete converted landed object")?;
        self.ledger.accepted(id, &converted, &keys.join(",")).await?;
        tracing::info!(
            source_id = %source.source_id,
            rows_accepted = converted.rows_accepted,
            rows_refused = converted.rows_refused,
            first_row_reason = converted.first_refusal.as_ref().map_or("", |r| r.reason),
            bronze_objects = converted.objects.len(),
            "landed file converted to bronze"
        );
        Ok(Outcome::Accepted)
    }

    async fn refuse_whole(&self, id: i64, key: &str, reason: &'static str, rows: u64, sha: Option<&str>) -> Result<Outcome> {
        let target = refused_key(key);
        match self.store.copy(key, &target).await {
            Ok(_) => {}
            // A store without server-side copy: move it through this process.
            Err(error) if error.kind() == opendal::ErrorKind::Unsupported => {
                let body = self.store.read(key).await.context("read refused landed object")?;
                self.store.write(&target, body).await.context("move refused landed object aside")?;
            }
            Err(error) => return Err(anyhow::Error::from(error).context("move refused landed object aside")),
        }
        self.store.delete(key).await.context("delete refused landed object")?;
        self.ledger.refused(id, reason, rows, sha).await?;
        tracing::warn!(reason, "landed file refused whole; moved under {REFUSED_PREFIX}");
        Ok(Outcome::Refused)
    }
}

enum Outcome {
    Accepted,
    Refused,
    Redelivered,
    Skipped,
}

/// The Postgres ledger (`landing_sources` / `landing_files`, migration 364).
pub struct PgLedger {
    pub pool: sqlx::PgPool,
    /// How long one claim owns a file before another tick may retry it.
    pub lease: std::time::Duration,
}

/// Finished ledger rows kept for the status view.
pub const LEDGER_RETENTION_DAYS: i32 = 30;

impl PgLedger {
    /// Drop finished rows past [`LEDGER_RETENTION_DAYS`], and claims abandoned
    /// for a week (the object was finished but the ledger write failed). A
    /// redelivery of a pruned file is converted again; its rows keep their
    /// uids, so the lake's uid window drops them while it still covers them.
    pub async fn prune(&self) -> Result<u64> {
        let done = sqlx::query(
            "DELETE FROM landing_files \
              WHERE (state <> 'claimed' AND finished_at < NOW() - make_interval(days => $1)) \
                 OR (state = 'claimed' AND lease_until < NOW() - INTERVAL '7 days')",
        )
        .bind(LEDGER_RETENTION_DAYS)
        .execute(&self.pool)
        .await
        .context("prune landing ledger")?;
        Ok(done.rows_affected())
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
    /// Landing sources whose log source was deleted (no foreign key ties them,
    /// migration 364). Each still owns an object-store user until revoked.
    pub async fn orphaned_sources(&self) -> Result<Vec<OrphanedSource>> {
        let rows: Vec<(Uuid, String, String)> = sqlx::query_as(
            "SELECT ls.source_id, ls.object_user, ls.state FROM landing_sources ls \
              WHERE NOT EXISTS (SELECT 1 FROM log_sources s WHERE s.id = ls.source_id) \
              ORDER BY ls.source_id",
        )
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
                "DELETE FROM landing_sources ls WHERE ls.source_id = $1 \
                   AND NOT EXISTS (SELECT 1 FROM log_sources s WHERE s.id = ls.source_id)",
            )
            .bind(orphan.source_id)
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
        // before the orphan sweep revokes its key.
        let row: Option<(Uuid, String, Uuid, String, bool)> = sqlx::query_as(
            "SELECT ls.source_id, ls.route_key, ls.credential_id, ls.state, \
                    EXISTS (SELECT 1 FROM log_sources s WHERE s.id = ls.source_id) \
               FROM landing_sources ls WHERE ls.source_id = $1",
        )
        .bind(source_id)
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
        // New: insert as claimed. Claimed with an expired lease: take it over.
        // Anything else: no row comes back and the state is read below.
        let owned: Option<(i64, i32)> = sqlx::query_as(
            "INSERT INTO landing_files (object_key, etag, source_id, size_bytes, state, attempts, lease_until) \
             VALUES ($1, $2, (SELECT source_id FROM landing_sources WHERE source_id = $3), $4, 'claimed', 1, \
                     NOW() + make_interval(secs => $5)) \
             ON CONFLICT (object_key, etag) DO UPDATE \
                SET attempts = landing_files.attempts + 1, \
                    lease_until = NOW() + make_interval(secs => $5) \
              WHERE landing_files.state = 'claimed' AND landing_files.lease_until < NOW() \
             RETURNING id, attempts",
        )
        .bind(key)
        .bind(etag)
        .bind(source_id)
        .bind(to_i64(size))
        .bind(f64::from(lease_secs))
        .fetch_optional(&self.pool)
        .await
        .context("claim landed file")?;
        if let Some((id, attempt)) = owned {
            return Ok(Claim::Owned { id, attempt });
        }
        let existing: Option<(i64, String)> =
            sqlx::query_as("SELECT id, state FROM landing_files WHERE object_key = $1 AND etag = $2")
                .bind(key)
                .bind(etag)
                .fetch_optional(&self.pool)
                .await
                .context("read landed file claim")?;
        Ok(match existing {
            Some((id, state)) if state != "claimed" => Claim::Finished { id },
            _ => Claim::Leased,
        })
    }

    async fn accepted(&self, id: i64, converted: &Converted, bronze_keys: &str) -> Result<()> {
        sqlx::query(
            "UPDATE landing_files SET state = 'accepted', rows_accepted = $2, rows_refused = $3, \
                    reason = $4, content_sha256 = $5, bronze_key = $6, lease_until = NULL, finished_at = NOW() \
              WHERE id = $1",
        )
        .bind(id)
        .bind(to_i64(converted.rows_accepted))
        .bind(to_i64(converted.rows_refused))
        .bind(converted.first_refusal.as_ref().map(|refusal| refusal.reason))
        .bind(&converted.content_sha256)
        .bind(bronze_keys)
        .execute(&self.pool)
        .await
        .context("record accepted landed file")?;
        Ok(())
    }

    async fn refused(&self, id: i64, reason: &str, rows_refused: u64, content_sha256: Option<&str>) -> Result<()> {
        sqlx::query(
            "UPDATE landing_files SET state = 'refused', rows_refused = $3, reason = $2, \
                    content_sha256 = COALESCE($4, content_sha256), lease_until = NULL, finished_at = NOW() \
              WHERE id = $1",
        )
        .bind(id)
        .bind(reason)
        .bind(to_i64(rows_refused))
        .bind(content_sha256)
        .execute(&self.pool)
        .await
        .context("record refused landed file")?;
        Ok(())
    }

    async fn redelivered(&self, id: i64) -> Result<()> {
        sqlx::query("UPDATE landing_files SET redeliveries = redeliveries + 1 WHERE id = $1")
            .bind(id)
            .execute(&self.pool)
            .await
            .context("record redelivered landed file")?;
        Ok(())
    }
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
