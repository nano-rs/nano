// SPDX-License-Identifier: AGPL-3.0-or-later

//! Hosted-shared OTLP handoff drain (NAN-2361 wave 6).
//!
//! On the hosted-shared lake the tenant Worker cannot reach a
//! `lake_otel_ingest` listener: the container has no egress except the
//! Worker's own outbound hosts, and the primary-Iceberg publisher
//! (`publish_otel_rows`) is release-blocked there
//! (`shared_mode::require_serialized_primary_iceberg_authority`).
//! Instead:
//!
//! 1. Vector's `otlp_lake_spans` / `otlp_lake_metrics` sinks POST their
//!    `nano-otlp-lake-v1` NDJSON batches to the Worker's `otel.internal`
//!    outbound host, which lands each batch as one immutable object under the
//!    Vector-owned prefix `otel-handoff-v1/tenant_uuid=<uuid>/dataset=<d>/…`
//!    (same immutable-object path as `raw-handoff-v1/`; owner writers refuse
//!    the prefix).
//! 2. This drain (the tenant's `lake_otel_ingest` process, bound to the
//!    `otel_publish` data-path principal from migration 9000760) lists those
//!    objects, reads each one exactly (byte length + strong ETag + SHA-256),
//!    normalizes the rows through the same `normalize_otel_row` contract as the
//!    dedicated path, encodes them into the native OTLP Iceberg v1 Parquet
//!    shape, and publishes them as STAGED HOT-TAIL objects for the tenant's
//!    `otel_spans` / `otel_metrics` table locations through the existing
//!    owner-authorized serialized writer, an [`OtelHotTailSink`] the hosted
//!    build provides (writer class `staged_hot_tail`, hour-scoped
//!    purge-whole; no new class).
//! 3. The batch is acknowledged in `lake_otel_handoff_batches` in the SAME
//!    transaction that records the hot-tail objects in
//!    `lake_hot_tail_objects` and bumps the tail revision, so a crash can
//!    expose neither half by itself and a replayed cycle is exactly-once.
//!
//! The query side (`lake_otel_ingest` in hosted mode) serves the Search routes
//! from the committed OTLP Iceberg table (NAN-2361 wave 7: the tail packer /
//! compactor carry an OTLP identity profile and pin the table's metadata
//! location on the tail revision row after every registration, see
//! [`CommittedTablePin`]) unioned with a local mirror of the objects still
//! staged. The mirror is bounded ([`MirrorPolicy`]): objects outside the
//! tenant's retention window are never mirrored and the newest event hours
//! win when the byte cap is reached (a time-series LRU — the drain always
//! writes the newest hours, so the hot set is the tail). Boot hydration is
//! fail-closed: a staged object the ledger names that cannot be read EXACTLY
//! (byte length, strong ETag, SHA-256) aborts startup instead of serving a
//! partial dataset.

use crate::object_identity;
use crate::iceberg::content_addressed_staged_path;
use crate::otel_iceberg::{
    decode_otel_batch, json_batches, normalize_otel_row, otel_arrow_schema, OtelDataset,
    OtelLakeRow,
};
use anyhow::{bail, Context, Result};
use arrow_schema::Schema as ArrowSchema;
use chrono::{DateTime, Utc};
use futures::{StreamExt, TryStreamExt};
use opendal::{EntryMode, Operator};
use parquet::arrow::ArrowWriter;
use parquet::basic::{Compression, ZstdLevel};
use parquet::file::properties::WriterProperties;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use uuid::Uuid;

/// Vector-owned handoff prefix. Mirrors `raw-handoff-v1/`: written only by the
/// tenant Worker's immutable-object path, never by an owner-plane writer.
pub const OTEL_HANDOFF_PREFIX: &str = "otel-handoff-v1/";
/// `lake_hot_tail_objects.bronze_store_id` for every drained OTLP object. The
/// `otel_publish` INSERT policy (9000760) admits exactly this store id.
pub const OTEL_HANDOFF_STORE_ID: &str = "otel-handoff-v1";
/// One handoff object is one Vector sink batch (5 MiB / 5000 events by
/// default); 64 MiB is the Worker-side ceiling and the ledger CHECK.
pub const OTEL_HANDOFF_MAX_OBJECT_BYTES: u64 = 64 * 1024 * 1024;
/// Rows admitted into one staged-tail publication per drain cycle.
pub const DEFAULT_DRAIN_MAX_ROWS: usize = 50_000;
/// Handoff objects examined per drain cycle.
pub const DEFAULT_DRAIN_MAX_OBJECTS: usize = 256;
/// Handoff objects fetched (HEAD + exact GET + decode) concurrently inside one
/// drain cycle (NAN-3290). Each fetch is a pair of R2 round trips, so a serial
/// cycle of 256 objects is latency-bound (~40 s); 16 in flight cuts that to a
/// few seconds. Results are still consumed in the cycle's deterministic order.
pub const DEFAULT_DRAIN_FETCH_CONCURRENCY: usize = 16;
/// Upper bound on [`DEFAULT_DRAIN_FETCH_CONCURRENCY`] overrides: every
/// in-flight fetch can hold one decoded handoff object in memory.
pub const MAX_DRAIN_FETCH_CONCURRENCY: usize = 64;
/// A normal cycle never lists receipt hours older than this lookback (the
/// Worker keys objects by receipt hour, so the listing is time-ordered);
/// acknowledged objects older than it never cost a listing page again.
/// NAN-3359: inside the lookback a normal cycle starts even later, at the
/// per-dataset undrained-hour watermark (see [`normal_cycle_start_hour`]).
pub const DEFAULT_DRAIN_LOOKBACK_HOURS: u32 = 48;
/// Every this many cycles (and on the first cycle) the whole prefix is
/// scanned so an object that arrived after an outage longer than the lookback
/// is still drained.
pub const FULL_SCAN_EVERY_CYCLES: u64 = 720;
/// Hard ceiling on one full-prefix scan.
pub const FULL_SCAN_ENTRY_CEILING: usize = 262_144;
const LEDGER_PAGE: usize = 512;
/// NAN-3886 (lean): keys per backfill-sweep list call (one R2 ListObjectsV2
/// page).
pub const LEAN_SWEEP_PAGE_KEYS: usize = 1_000;
/// NAN-3886 (lean): object-list calls one cycle's backfill sweep may make
/// (plus one receipt-hour listing). A backlogged cycle usually needs one: a
/// page of undrained keys already fills `max_objects`.
pub const LEAN_SWEEP_LIST_CALLS_PER_CYCLE: usize = 8;
/// NAN-3886 (lean): an idle drain re-sweeps every receipt hour below the live
/// window this often, the safety net for objects that land in an hour the
/// live window no longer lists (the gen1 cadence: 720 cycles of 10 s).
pub const LEAN_SWEEP_INTERVAL: std::time::Duration = std::time::Duration::from_secs(2 * 3_600);
/// NAN-3886 (lean): the live window never reaches further back than this
/// many hours before the current one. Older hours still owed (a restart
/// after a long outage, a live backlog that outlasted the window) are handed
/// to a bounded sweep instead of being re-listed by every cycle (one live tenant relisted
/// a 48 h window of ~115k span keys per backlogged cycle).
pub const LEAN_LIVE_WINDOW_HOURS: i32 = 2;

/// NAN-3886: where the lean drain stands, per dataset, persisted next to the
/// drain markers (`<mirror>/.drained/<dataset>.scan.json`) so a restarted
/// process over the same mirror resumes instead of re-listing the prefix.
///
/// Every cycle lists the LIVE window (`watermark_hour`..now, the NAN-3359
/// watermark, never more than [`LEAN_LIVE_WINDOW_HOURS`] back) newest
/// first. Receipt hours below it are covered by the SWEEP: it walks the
/// hours that exist from right below the live window down to the mirror
/// floor (periodic, every [`LEAN_SWEEP_INTERVAL`] and on a fresh mirror) or
/// to the old watermark (a hand-off of hours the live window dropped),
/// newest hour first, one bounded page at a time; its position survives
/// across cycles and restarts.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, serde::Deserialize)]
pub struct LeanScanState {
    /// Oldest receipt hour that may still hold an undrained object
    /// ([`next_watermark_hour`]); the live window starts here.
    pub watermark_hour: Option<i32>,
    /// The backfill sweep in progress, if any.
    pub sweep: Option<LeanSweepCursor>,
    /// Unix seconds when the last sweep reached the mirror floor.
    pub last_sweep_completed_unix: Option<i64>,
    /// Coverage (NAN-3894): every handoff object of a receipt hour at or
    /// after this one is drained into the mirror, except `unproven_hours`.
    /// `None` until a periodic sweep has reached the mirror floor: a fresh
    /// or rebuilt mirror attests nothing.
    #[serde(default)]
    pub covered_since_hour: Option<i32>,
    /// Receipt hours that may still hold an undrained object below the live
    /// window: hours a hand-off gave to a sweep that has not passed them yet,
    /// and hours where a sweep passed over a failed exact read.
    #[serde(default)]
    pub unproven_hours: BTreeSet<i32>,
    /// Unix seconds (cycle start) of the last cycle that proved the whole
    /// live window drained, with no retry left behind.
    #[serde(default)]
    pub live_proven_unix: Option<i64>,
    /// The last cycle left undrained objects behind.
    #[serde(default)]
    pub backlogged: bool,
}

/// Position of the lean backfill sweep: every key of a receipt hour above
/// `hour` (down from where the sweep began), and every key of `hour` up to
/// and including `start_after`, is drained, rejected, or was retried.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, serde::Deserialize)]
pub struct LeanSweepCursor {
    pub hour: i32,
    pub start_after: Option<String>,
    /// `None`: a periodic sweep, down to the mirror floor. `Some(h)`: a
    /// hand-off sweep covering only the hours the live window dropped,
    /// down to `h` (everything below it was already proven).
    #[serde(default)]
    pub stop_hour: Option<i32>,
    /// Hours this sweep passed over with a failed exact read (they stay in
    /// `unproven_hours` until a later sweep drains them).
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub retried: BTreeSet<i32>,
}

impl LeanSweepCursor {
    fn top(hour: i32, stop_hour: Option<i32>) -> Self {
        Self { hour, start_after: None, stop_hour, retried: BTreeSet::new() }
    }
}

/// One undrained key the sweep found, with the cursor that re-lists it.
struct SweepItem {
    key: String,
    hour: i32,
    before: LeanSweepCursor,
}

/// What one sweep pass listed: the undrained keys (newest hour first, keys
/// ascending inside an hour) and where the sweep stands once all of them
/// are examined (`None`: it reached the mirror floor).
struct SweepPass {
    items: Vec<SweepItem>,
    end: Option<LeanSweepCursor>,
    seen: usize,
    /// The lowest hour this pass may reach (mirror floor or hand-off stop).
    floor: i32,
}

/// What [`OtelHandoffDrain::drain_pending`] did with a cycle's pending keys.
struct FoldOutcome {
    /// Pending keys consumed in order (fetched and folded); the rest were
    /// cut by `max_rows`.
    examined: usize,
    /// Indexes (into the pending list) whose exact read failed.
    retries: Vec<usize>,
    /// At least one batch was acknowledged.
    acknowledged: bool,
}

/// `event_table` value recorded for each dataset's hot-tail objects.
pub fn otel_event_table(dataset: OtelDataset) -> &'static str {
    match dataset {
        OtelDataset::Spans => "otel_spans",
        OtelDataset::Metrics => "otel_metrics",
    }
}

/// `otel-handoff-v1/tenant_uuid=<uuid>/dataset=<spans|metrics>/`
pub fn handoff_prefix(tenant_uuid: Uuid, dataset: OtelDataset) -> String {
    format!(
        "{OTEL_HANDOFF_PREFIX}tenant_uuid={tenant_uuid}/dataset={}/",
        dataset.as_str()
    )
}

/// The Worker's key for one accepted batch:
/// `<prefix>hour=<YYYYMMDDHH>/<sha256>.ndjson` (receipt hour, not event hour —
/// the Worker does not parse the batch).
pub fn handoff_object_key(
    tenant_uuid: Uuid,
    dataset: OtelDataset,
    received_at: DateTime<Utc>,
    content_sha256: &str,
) -> Result<String> {
    if !is_lower_sha256(content_sha256) {
        bail!("OTLP handoff object identity is not a lowercase SHA-256");
    }
    Ok(format!(
        "{}hour={}/{content_sha256}.ndjson",
        handoff_prefix(tenant_uuid, dataset),
        received_at.format("%Y%m%d%H")
    ))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OtelHandoffKey {
    pub tenant_uuid: Uuid,
    pub dataset: OtelDataset,
    pub receipt_hour: String,
    pub content_sha256: String,
}

/// Parse and fence a listed key: it must sit under this tenant's prefix, name
/// exactly one receipt hour and one lowercase SHA-256, and carry no traversal.
pub fn parse_handoff_key(key: &str, tenant_uuid: Uuid) -> Result<OtelHandoffKey> {
    if key.len() > 1_024 || key.chars().any(char::is_control) || key.contains("..") {
        bail!("OTLP handoff key violates its bounded shape");
    }
    let rest = key
        .strip_prefix(&format!("{OTEL_HANDOFF_PREFIX}tenant_uuid={tenant_uuid}/"))
        .context("OTLP handoff key is outside this tenant's prefix")?;
    let segments = rest.split('/').collect::<Vec<_>>();
    let [dataset, hour, file] = segments.as_slice() else {
        bail!("OTLP handoff key must be dataset=/hour=/<sha256>.ndjson");
    };
    let dataset = match dataset.strip_prefix("dataset=") {
        Some("spans") => OtelDataset::Spans,
        Some("metrics") => OtelDataset::Metrics,
        _ => bail!("OTLP handoff key names an unknown dataset"),
    };
    let hour = hour
        .strip_prefix("hour=")
        .filter(|value| value.len() == 10 && value.bytes().all(|byte| byte.is_ascii_digit()))
        .context("OTLP handoff key receipt hour is invalid")?;
    let sha256 = file
        .strip_suffix(".ndjson")
        .filter(|value| is_lower_sha256(value))
        .context("OTLP handoff object name is not a lowercase SHA-256")?;
    Ok(OtelHandoffKey {
        tenant_uuid,
        dataset,
        receipt_hour: hour.to_string(),
        content_sha256: sha256.to_string(),
    })
}

/// `YYYYMMDDHH` receipt hour of a handoff key as hours since the epoch.
pub fn receipt_epoch_hour(receipt_hour: &str) -> Option<i32> {
    let start = chrono::NaiveDateTime::parse_from_str(&format!("{receipt_hour}0000"), "%Y%m%d%H%M%S").ok()?;
    i32::try_from(start.and_utc().timestamp().div_euclid(3_600)).ok()
}

/// `YYYYMMDDHH` label of an epoch hour (the inverse of [`receipt_epoch_hour`]).
pub fn receipt_hour_label(hour: i32) -> Result<String> {
    let at = DateTime::<Utc>::from_timestamp(i64::from(hour) * 3_600, 0).context("OTLP receipt hour is out of range")?;
    Ok(at.format("%Y%m%d%H").to_string())
}

/// The distinct receipt hours named by `hour=<H>` right under `prefix` in
/// `paths` (object keys or `hour=<H>/` directory paths), newest first.
pub fn receipt_hours_under<'a>(prefix: &str, paths: impl IntoIterator<Item = &'a str>) -> Vec<i32> {
    let mut hours = paths
        .into_iter()
        .filter_map(|path| path.strip_prefix(prefix))
        .filter_map(|rest| rest.split('/').next())
        .filter_map(|segment| segment.strip_prefix("hour="))
        .filter(|label| label.len() == 10 && label.bytes().all(|byte| byte.is_ascii_digit()))
        .filter_map(receipt_epoch_hour)
        .collect::<Vec<_>>();
    hours.sort_unstable_by(|a, b| b.cmp(a));
    hours.dedup();
    hours
}

fn is_lower_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// One staged Parquet object (exactly one event hour) ready for the writer.
#[derive(Debug, Clone)]
pub struct StagedOtelObject {
    pub dataset: OtelDataset,
    pub event_hour: i32,
    pub min_time_ms: i64,
    pub max_time_ms: i64,
    /// Relative to the table root: `data/tail/tenant_sha256=…/event_hour=…/batch-<logical>-<sha>.parquet`.
    pub relative_path: String,
    pub bytes: Vec<u8>,
    pub rows: u64,
    pub sha256: String,
}

/// Content identity of one drain publication: sha256 over the sorted row uids.
pub fn drain_batch_sha256(rows: &[OtelLakeRow]) -> String {
    let mut uids = rows.iter().map(|row| row.row_uid.as_str()).collect::<Vec<_>>();
    uids.sort_unstable();
    uids.dedup();
    let mut digest = Sha256::new();
    digest.update(b"nano:otel-handoff-drain:v1\0");
    for uid in uids {
        digest.update((uid.len() as u64).to_be_bytes());
        digest.update(uid.as_bytes());
    }
    hex::encode(digest.finalize())
}

/// Encode normalized rows into one staged Parquet object per event hour in the
/// native OTLP Iceberg v1 Arrow schema (the same schema `publish_otel_rows`
/// writes on the dedicated path, so the query planners read both alike).
pub fn encode_staged_otel_objects(
    dataset: OtelDataset,
    tenant_uuid: Uuid,
    rows: &[OtelLakeRow],
    logical_sha256: &str,
) -> Result<Vec<StagedOtelObject>> {
    if rows.is_empty() {
        bail!("OTLP drain publication has no rows");
    }
    let mut by_hour = BTreeMap::<i32, Vec<&OtelLakeRow>>::new();
    for row in rows {
        if row.dataset != dataset {
            bail!("OTLP drain publication mixes datasets");
        }
        by_hour.entry(row.event_hour).or_default().push(row);
    }
    let schema: Arc<ArrowSchema> = Arc::new(otel_arrow_schema(dataset));
    let properties = WriterProperties::builder()
        .set_compression(Compression::ZSTD(ZstdLevel::try_new(6)?))
        .set_max_row_group_row_count(Some(16_384))
        .build();
    let time_field = dataset.time_field();
    let tenant = tenant_uuid.to_string();
    let mut output = Vec::with_capacity(by_hour.len());
    for (event_hour, hour_rows) in by_hour {
        let mut min_time_ms = i64::MAX;
        let mut max_time_ms = i64::MIN;
        let values = hour_rows
            .iter()
            .map(|row| {
                let time = row
                    .row
                    .get(time_field)
                    .and_then(serde_json::Value::as_str)
                    .and_then(|value| DateTime::parse_from_rfc3339(value).ok())
                    .context("OTLP row carries no parseable event time")?;
                let millis = time.timestamp_millis();
                min_time_ms = min_time_ms.min(millis);
                max_time_ms = max_time_ms.max(millis);
                Ok(row.row.clone())
            })
            .collect::<Result<Vec<_>>>()?;
        let hour_floor = i64::from(event_hour) * 3_600_000;
        if min_time_ms < hour_floor || max_time_ms >= hour_floor + 3_600_000 {
            bail!("OTLP row event time escaped its event hour");
        }
        let mut writer = ArrowWriter::try_new(Vec::new(), schema.clone(), Some(properties.clone()))?;
        for batch in json_batches(schema.clone(), &values)? {
            writer.write(&batch)?;
        }
        let bytes = writer.into_inner()?;
        if bytes.is_empty() {
            bail!("OTLP drain produced an empty Parquet object");
        }
        let sha256 = hex::encode(Sha256::digest(&bytes));
        let relative_path =
            content_addressed_staged_path(&tenant, event_hour, "batch", logical_sha256, &sha256)?;
        output.push(StagedOtelObject {
            dataset,
            event_hour,
            min_time_ms,
            max_time_ms,
            relative_path,
            bytes,
            rows: hour_rows.len() as u64,
            sha256,
        });
    }
    Ok(output)
}

/// Read side of the tenant bucket. Production is the tenant's read
/// credential over R2 (`opendal` S3 operator, exact reads through
/// `object_identity::read_exact`); tests substitute an in-memory store
/// that carries strong ETags.
pub trait OtelHandoffSource: Send + Sync {
    /// Current object keys under `prefix` (files only), lexically after
    /// `start_after` when given, at most `limit` entries.
    fn list<'a>(
        &'a self,
        prefix: &'a str,
        start_after: Option<&'a str>,
        limit: usize,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<String>>> + Send + 'a>>;
    /// NAN-3886: the receipt hours (hours since the epoch) that hold at least
    /// one object directly under the dataset prefix `prefix`
    /// (`.../dataset=<d>/`). Production lists the `hour=<H>/` common
    /// prefixes with a delimiter (one LIST page covers ~41 days of hours);
    /// the default derives them from ONE recursive [`Self::list`] call,
    /// which is what the in-memory test doubles use.
    fn list_receipt_hours<'a>(&'a self, prefix: &'a str) -> Pin<Box<dyn Future<Output = Result<Vec<i32>>> + Send + 'a>> {
        Box::pin(async move {
            let keys = self.list(prefix, None, FULL_SCAN_ENTRY_CEILING).await?;
            Ok(receipt_hours_under(prefix, keys.iter().map(String::as_str)))
        })
    }
    /// `(content_length, strong_etag)` of one object.
    fn head<'a>(&'a self, key: &'a str) -> Pin<Box<dyn Future<Output = Result<(u64, String)>> + Send + 'a>>;
    /// The exact bytes, fenced by byte length, SHA-256 and strong ETag.
    fn read_exact<'a>(
        &'a self,
        key: &'a str,
        expected_bytes: u64,
        expected_sha256: &'a str,
        expected_etag: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<u8>>> + Send + 'a>>;
    /// Delete one object (lean retention expiry only, `crate::otel_lean`).
    /// The gen1 drain never deletes: its GC goes through the owner-authorized
    /// delete authority (`otel_handoff_gc`).
    fn delete<'a>(&'a self, key: &'a str) -> Pin<Box<dyn Future<Output = Result<()>> + Send + 'a>> {
        Box::pin(async move { bail!("this OTLP handoff source does not delete ({key})") })
    }
}

impl OtelHandoffSource for Operator {
    fn list<'a>(
        &'a self,
        prefix: &'a str,
        start_after: Option<&'a str>,
        limit: usize,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<String>>> + Send + 'a>> {
        Box::pin(async move {
            let mut listing = self.lister_with(prefix).recursive(true);
            if let Some(cursor) = start_after {
                listing = listing.start_after(cursor);
            }
            let mut lister = listing
                .await
                .context("list enterprise_shared R2 OTLP handoff objects")?;
            let mut keys = Vec::new();
            while let Some(entry) = lister.try_next().await? {
                let metadata = entry.metadata();
                if metadata.mode() != EntryMode::FILE || metadata.is_deleted() {
                    continue;
                }
                keys.push(entry.path().to_string());
                if keys.len() >= limit {
                    break;
                }
            }
            Ok(keys)
        })
    }

    fn list_receipt_hours<'a>(&'a self, prefix: &'a str) -> Pin<Box<dyn Future<Output = Result<Vec<i32>>> + Send + 'a>> {
        Box::pin(async move {
            // Non-recursive: S3 ListObjectsV2 with delimiter `/`, so each
            // `hour=<H>/` common prefix is one entry, not its objects.
            let mut lister = self
                .lister_with(prefix)
                .await
                .context("list OTLP handoff receipt hours")?;
            let mut paths = Vec::new();
            while let Some(entry) = lister.try_next().await? {
                if entry.metadata().mode() == EntryMode::DIR {
                    paths.push(entry.path().to_string());
                }
            }
            Ok(receipt_hours_under(prefix, paths.iter().map(String::as_str)))
        })
    }

    fn head<'a>(&'a self, key: &'a str) -> Pin<Box<dyn Future<Output = Result<(u64, String)>> + Send + 'a>> {
        Box::pin(async move {
            let metadata = self.stat(key).await.context("HEAD OTLP handoff object")?;
            let etag = object_identity::strong_etag(&metadata)?.to_string();
            Ok((metadata.content_length(), etag))
        })
    }

    fn read_exact<'a>(
        &'a self,
        key: &'a str,
        expected_bytes: u64,
        expected_sha256: &'a str,
        expected_etag: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<u8>>> + Send + 'a>> {
        Box::pin(async move {
            let (body, _) = object_identity::read_exact(
                self,
                key,
                expected_bytes,
                Some(expected_sha256),
                Some(expected_etag),
            )
            .await?;
            Ok(body)
        })
    }

    fn delete<'a>(&'a self, key: &'a str) -> Pin<Box<dyn Future<Output = Result<()>> + Send + 'a>> {
        Box::pin(async move {
            Operator::delete(self, key).await.context("delete OTLP handoff object")?;
            Ok(())
        })
    }
}

/// Provider identity of one published staged object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublishedOtelObject {
    pub version_id: String,
    pub etag: String,
    pub deletion_unit_id: Uuid,
    pub writer_authority_sha256: String,
}

/// One staged OTLP hot-tail object as the owner-authorized writer receives
/// it: the logical tenant key routes authorization, the tenant UUID pins the
/// physical partition, and the event hour is the Iceberg hour transform.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StagedTailPublication {
    pub tenant_id: String,
    pub partition_tenant_id: String,
    pub object_bucket: String,
    pub object_key: String,
    pub event_hour: i32,
    pub min_time_ms: i64,
    pub max_time_ms: i64,
    pub content_length: u64,
    pub content_sha256: String,
}

impl StagedTailPublication {
    /// The staged hot-tail writer contract: one exact UTC hour, a bounded
    /// non-empty object with a lowercase SHA-256, and a key under the
    /// partition's `data/tail/tenant_sha256=<…>/event_hour=<h>/` directory.
    pub fn validate(&self) -> Result<()> {
        let hour_start_ms = i64::from(self.event_hour)
            .checked_mul(3_600)
            .context("enterprise_shared hot-tail event hour overflow")?
            .checked_mul(1_000)
            .context("enterprise_shared hot-tail event hour is invalid")?;
        DateTime::<Utc>::from_timestamp_millis(hour_start_ms)
            .context("enterprise_shared hot-tail event hour is invalid")?;
        DateTime::<Utc>::from_timestamp_millis(self.min_time_ms)
            .context("enterprise_shared hot-tail minimum event time is invalid")?;
        DateTime::<Utc>::from_timestamp_millis(self.max_time_ms)
            .context("enterprise_shared hot-tail maximum event time is invalid")?;
        let partition = &self.partition_tenant_id;
        let key = &self.object_key;
        if self.tenant_id.is_empty()
            || partition.is_empty()
            || partition.len() > 256
            || partition.chars().any(char::is_control)
            || self.object_bucket.is_empty()
            || !(8..=1_024).contains(&key.len())
            || key.starts_with('/')
            || key.ends_with('/')
            || key.chars().any(char::is_control)
            || key.split('/').any(|part| part.is_empty() || part == "." || part == "..")
            || self.content_length == 0
            || self.content_length > 2 * 1024 * 1024 * 1024
            || !(is_lower_sha256(&self.content_sha256) && self.content_sha256 != "0".repeat(64))
            || self.min_time_ms > self.max_time_ms
            || self.min_time_ms < hour_start_ms
            || self.max_time_ms >= hour_start_ms + 3_600_000
        {
            bail!("enterprise_shared publication request is malformed");
        }
        let marker = format!(
            "/data/tail/tenant_sha256={}/event_hour={}/",
            hex::encode(Sha256::digest(partition.as_bytes())),
            self.event_hour
        );
        let key_matches = key.split_once(&marker).is_some_and(|(_, file)| {
            !file.contains('/') && file.len() > ".parquet".len() && file.ends_with(".parquet")
        });
        if !key_matches {
            bail!("enterprise_shared publication key/class identity is malformed");
        }
        Ok(())
    }
}

/// Where staged OTLP objects go. Production is the owner-authorized
/// serialized writer (hosted build); tests substitute an in-memory sink that
/// lands the bytes at the same key so the read side is proved against a fake
/// R2. The lean drain has no sink: its local mirror is the store.
pub trait OtelHotTailSink: Send + Sync {
    fn publish<'a>(
        &'a self,
        publication: &'a StagedTailPublication,
        bytes: Vec<u8>,
    ) -> Pin<Box<dyn Future<Output = Result<PublishedOtelObject>> + Send + 'a>>;
}

/// One drained handoff object, as acknowledged in the ledger.
#[derive(Debug, Clone, Serialize)]
pub struct DrainedHandoffBatch {
    pub dataset: OtelDataset,
    pub object_key: String,
    pub object_sha256: String,
    pub object_bytes: u64,
    pub object_etag: String,
    pub rows_decoded: u32,
    pub rows_rejected: u32,
    /// `None` when every row was rejected: the object is acknowledged as
    /// `rejected` (with `last_error`) so a malformed batch cannot poison the
    /// drain forever, exactly the lesson `dedupe_otel_batch` records.
    pub tail_batch_sha256: Option<String>,
    pub last_error: Option<String>,
}

/// One published hot-tail object, as recorded in `lake_hot_tail_objects`.
#[derive(Debug, Clone, Serialize)]
pub struct AcknowledgedTailObject {
    pub dataset: OtelDataset,
    pub table_location_prefix: String,
    pub batch_sha256: String,
    pub event_hour: i32,
    pub object_uri: String,
    pub version_id: String,
    pub etag: String,
    pub bytes: u64,
    pub sha256: String,
    pub rows: u64,
    pub min_time_ms: i64,
    pub max_time_ms: i64,
    pub deletion_unit_id: Uuid,
    pub writer_authority_sha256: String,
}

/// Everything one drain cycle commits atomically.
#[derive(Debug, Clone, Serialize)]
pub struct DrainAcknowledgement {
    pub dataset: OtelDataset,
    pub objects: Vec<AcknowledgedTailObject>,
    pub batches: Vec<DrainedHandoffBatch>,
}

/// A staged object already recorded for this table (used to re-hydrate the
/// query mirror after a restart).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LedgerTailObject {
    pub event_hour: i32,
    pub object_uri: String,
    pub etag: String,
    pub bytes: u64,
    pub sha256: String,
}

/// The exactly-once ledger. PostgreSQL in production (the `otel_publish`
/// data-path principal), in-memory in tests.
pub trait OtelHandoffLedger: Send + Sync {
    /// Keys under this tenant/dataset already acknowledged (drained or rejected).
    fn drained_keys<'a>(
        &'a self,
        dataset: OtelDataset,
        candidates: &'a [String],
    ) -> Pin<Box<dyn Future<Output = Result<Vec<String>>> + Send + 'a>>;
    /// Record hot-tail objects + batch acknowledgements + revision bump + heartbeat, atomically.
    fn acknowledge<'a>(
        &'a self,
        acknowledgement: &'a DrainAcknowledgement,
    ) -> Pin<Box<dyn Future<Output = Result<()>> + Send + 'a>>;
    /// Every object still STAGED for this table prefix — the drain's own
    /// objects and the packs the tail packer superseded them with (a
    /// superseded or compacted object is no longer served from the mirror).
    fn staged_objects<'a>(
        &'a self,
        dataset: OtelDataset,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<LedgerTailObject>>> + Send + 'a>>;
    /// Presence heartbeat with nothing drained this cycle.
    fn heartbeat<'a>(&'a self) -> Pin<Box<dyn Future<Output = Result<()>> + Send + 'a>>;
    /// The committed-table pin the compactor recorded (wave 7), if any.
    fn committed_pin<'a>(
        &'a self,
        _dataset: OtelDataset,
    ) -> Pin<Box<dyn Future<Output = Result<Option<CommittedTablePin>>> + Send + 'a>> {
        Box::pin(async { Ok(None) })
    }
    /// The tenant's locked retention window in days, when the session can
    /// read it (`nano_shared.read_lake_purge_policy`, 9000841).
    fn retention_days<'a>(&'a self) -> Pin<Box<dyn Future<Output = Result<Option<u32>>> + Send + 'a>> {
        Box::pin(async { Ok(None) })
    }
}

pub use crate::tail_ledger::CommittedTablePin;

/// Bounds of the local query mirror (wave 7).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MirrorPolicy {
    /// Byte cap over every mirrored object of both datasets. When exceeded,
    /// the oldest event hours are evicted first (newest hours are the hot
    /// set the drain keeps writing).
    pub max_bytes: u64,
    /// Event hours older than this are never mirrored; the ledger's
    /// retention window (`retention_days`) tightens it when known.
    pub max_age_hours: u32,
}

impl MirrorPolicy {
    pub const DEFAULT_MAX_BYTES: u64 = 8 * 1024 * 1024 * 1024;
    /// NAN-3894: the OTLP retention floor (31 d), so the mirror holds the
    /// longest SLO window plus the coverage skew hour.
    pub const DEFAULT_MAX_AGE_HOURS: u32 = crate::otel_lean::OTEL_MIN_RETENTION_DAYS * 24;

    pub fn validate(&self) -> Result<()> {
        if !(64 * 1024 * 1024..=4 * 1024 * 1024 * 1024 * 1024).contains(&self.max_bytes)
            || self.max_age_hours == 0
            || self.max_age_hours > 24 * 400
        {
            bail!("OTLP mirror policy is outside its bounded shape");
        }
        Ok(())
    }
}

impl Default for MirrorPolicy {
    fn default() -> Self {
        Self { max_bytes: Self::DEFAULT_MAX_BYTES, max_age_hours: Self::DEFAULT_MAX_AGE_HOURS }
    }
}

/// Tenant / table binding of one drain.
#[derive(Debug, Clone)]
pub struct OtelDrainBinding {
    pub tenant_uuid: Uuid,
    /// Nano Main's stable logical tenant key (owner authorization routes by
    /// it); object paths and rows use the UUID.
    pub logical_tenant_key: String,
    pub bucket: String,
    pub spans_location: String,
    pub metrics_location: String,
    pub drain_identity: String,
    pub max_rows: usize,
    pub max_objects: usize,
    pub lookback_hours: u32,
}

impl OtelDrainBinding {
    pub fn validate(&self) -> Result<()> {
        if self.tenant_uuid.is_nil()
            || self.logical_tenant_key.is_empty()
            || self.logical_tenant_key.len() > 256
            || self.logical_tenant_key.chars().any(char::is_control)
            || self.bucket != format!("nano-shared-r2-{}", self.tenant_uuid)
            || self.drain_identity.is_empty()
            || self.drain_identity.len() > 128
            || !self
                .drain_identity
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
            || self.max_rows == 0
            || self.max_rows > 250_000
            || self.max_objects == 0
            || self.max_objects > 4_096
            || self.lookback_hours == 0
            || self.lookback_hours > 24 * 90
        {
            bail!("enterprise_shared OTLP drain binding is not exact");
        }
        for location in [&self.spans_location, &self.metrics_location] {
            let prefix = format!("s3://{}/", self.bucket);
            if !location.starts_with(&prefix)
                || location.ends_with('/')
                || location.len() > 2_048
                || location.chars().any(char::is_control)
                || location[prefix.len()..]
                    .split('/')
                    .any(|part| part.is_empty() || part == "." || part == "..")
            {
                bail!("enterprise_shared OTLP table location is outside the tenant bucket");
            }
        }
        if self.spans_location == self.metrics_location {
            bail!("enterprise_shared OTLP spans and metrics tables share one location");
        }
        Ok(())
    }

    pub fn table_location(&self, dataset: OtelDataset) -> &str {
        match dataset {
            OtelDataset::Spans => &self.spans_location,
            OtelDataset::Metrics => &self.metrics_location,
        }
    }

    /// `lake_hot_tail_objects.table_location_prefix` (trailing slash).
    pub fn table_location_prefix(&self, dataset: OtelDataset) -> String {
        format!("{}/", self.table_location(dataset))
    }

    fn table_key(&self, dataset: OtelDataset) -> &str {
        self.table_location(dataset)[format!("s3://{}/", self.bucket).len()..].trim_end_matches('/')
    }
}

#[derive(Debug, Clone, Default, Serialize, PartialEq, Eq)]
pub struct DrainCycleReport {
    pub objects_seen: usize,
    pub objects_drained: usize,
    pub objects_rejected: usize,
    pub rows_published: u64,
    pub rows_rejected: u64,
    pub tail_objects_published: usize,
    /// Gen1: this cycle listed the whole prefix instead of only the lookback
    /// window. Always false on lean (NAN-3886): the lean drain never lists
    /// the whole prefix in one cycle; see `sweep`.
    pub full_scan: bool,
    /// NAN-3290: the cycle made progress AND left undrained objects behind
    /// (it hit `max_objects` or `max_rows`). The drain loop runs the next
    /// cycle for this dataset immediately instead of sleeping.
    pub backlogged: bool,
    /// NAN-3886 (lean): this cycle advanced the persisted backfill sweep
    /// over the receipt hours below the live window.
    pub sweep: bool,
    /// NAN-3886 (lean): `list` / `list_receipt_hours` calls this cycle made.
    pub list_calls: usize,
}

/// NAN-3359: the first receipt hour a NORMAL (non-full-scan) cycle lists.
///
/// Why: the lean drain runs a cycle per dataset every 10 s, and listing the
/// whole 48 h lookback each time re-read every acknowledged key of the last
/// two days at 1000 keys per R2 ListObjects page (Class A, $4.50/M). The
/// otel-handoff prefix started filling at 09Z 2026-10-08 (spans ~2.4k
/// objects/h, metrics ~0.3k/h); the tenant bucket went from ~300 LIST/h on
/// 10-06 to 6,150 LIST/h at 15Z 10-08, on course for ~47k LIST/h (~1.1M/day)
/// once the 48 h window filled.
///
/// The start hour is the LATEST of:
/// * the lookback floor (`now_hour - lookback_hours`) — unchanged contract;
/// * the lean mirror floor — keys below it are skipped unread anyway;
/// * the watermark: the oldest receipt hour that may still hold an undrained
///   object (see [`next_watermark_hour`]). It is at most `now_hour - 1` of
///   the cycle that set it, so the current and previous receipt hours are
///   ALWAYS listed: the Worker writes a key during, or seconds after, its
///   receipt hour, so no new object can land below the watermark and the
///   arrival→searchable path is never delayed.
///
/// `None` watermark (no completed cycle yet) is today's lookback cycle. The
/// first cycle and every [`FULL_SCAN_EVERY_CYCLES`]th (plus owed backlog
/// scans) remain full scans and ignore the watermark: they are the safety net
/// for stragglers and for outages longer than the window.
pub fn normal_cycle_start_hour(
    now_hour: i32,
    lookback_hours: u32,
    lean_floor_hour: Option<i32>,
    watermark_hour: Option<i32>,
) -> i32 {
    let lookback_hour = now_hour.saturating_sub(i32::try_from(lookback_hours).unwrap_or(i32::MAX));
    [Some(lookback_hour), lean_floor_hour, watermark_hour]
        .into_iter()
        .flatten()
        .max()
        .unwrap_or(lookback_hour)
}

/// What one drain cycle proved about the hours it listed (NAN-3359).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CycleCoverage {
    /// Every listed candidate was ledger-checked and every pending object
    /// examined. Only objects whose exact read failed (left for retry) are
    /// still undrained; this is the oldest of their receipt hours.
    Complete { oldest_retry_hour: Option<i32> },
    /// The cycle stopped early (`max_objects` saturated the ledger check, or
    /// `max_rows` cut the fold): objects at or after this hour may still be
    /// pending. `None` = nothing known beyond the previous watermark.
    Incomplete { oldest_unproven_hour: Option<i32> },
}

/// The watermark the next normal cycle starts from (NAN-3359).
///
/// * A complete cycle sets it to the oldest hour still holding a retry, else
///   `now_hour - 1` (the previous hour stays listed for late writers).
/// * An incomplete (backlogged) cycle never ADVANCES it: it keeps the
///   previous watermark, lowered to the oldest hour it could not prove
///   drained. With no previous watermark it stays `None` (full lookback).
pub fn next_watermark_hour(previous: Option<i32>, now_hour: i32, coverage: CycleCoverage) -> Option<i32> {
    match coverage {
        CycleCoverage::Complete { oldest_retry_hour } => {
            let live_floor = now_hour.saturating_sub(1);
            Some(oldest_retry_hour.map_or(live_floor, |hour| hour.min(live_floor)))
        }
        CycleCoverage::Incomplete { oldest_unproven_hour } => {
            previous.map(|watermark| oldest_unproven_hour.map_or(watermark, |hour| hour.min(watermark)))
        }
    }
}

/// Newest receipt hour first, keys ascending inside an hour (NAN-3290), as
/// `(epoch_hours, keys)`. Safe for the query side: the mirror and the
/// committed table are disjoint by OBJECT (reconcile_mirror prunes every
/// object the ledger no longer stages before the pin is refreshed), never by
/// a time or receipt-order watermark, and the exactly-once ledger is per
/// key. An unparseable hour counts as the oldest possible (the lookback floor
/// then binds the watermark).
fn newest_first(mut candidates: Vec<(String, String)>) -> (Vec<i32>, Vec<String>) {
    candidates.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| a.1.cmp(&b.1)));
    candidates
        .into_iter()
        .map(|(hour, key)| (receipt_epoch_hour(&hour).unwrap_or(i32::MIN), key))
        .unzip()
}

/// NAN-3359: what a cycle proved about the hours it listed. Saturated:
/// candidates after the ledger cut-off (older hours, newest-first order) were
/// never checked. Cut by max_rows: the unexamined pending objects and the
/// retries are still pending. Otherwise only the retries are.
fn cycle_coverage(
    saturated: bool,
    oldest_listed_hour: Option<i32>,
    pending_hours: &[i32],
    examined: usize,
    oldest_retry_hour: Option<i32>,
) -> CycleCoverage {
    if saturated {
        CycleCoverage::Incomplete { oldest_unproven_hour: oldest_listed_hour }
    } else if examined < pending_hours.len() {
        let unexamined = pending_hours[examined..].iter().copied().min();
        CycleCoverage::Incomplete {
            oldest_unproven_hour: [unexamined, oldest_retry_hour].into_iter().flatten().min(),
        }
    } else {
        CycleCoverage::Complete { oldest_retry_hour }
    }
}

/// Per-dataset listing state of one gen1 drain (NAN-3290). The lean drain
/// keeps [`LeanScanState`] instead.
#[derive(Debug, Default, Clone, Copy)]
struct ScanState {
    /// Cycles run for this dataset (the periodic full scan is per dataset:
    /// a single counter shared by both datasets made every full scan land on
    /// the dataset drained first — metrics never got one).
    cycles: u64,
    /// A full scan was backlogged: objects older than the lookback window
    /// may still be pending, so full scans continue until one is not.
    full_scan_owed: bool,
    /// The last cycle was backlogged inside the window it listed. While true,
    /// owed full scans wait and cheap lookback cycles (newest first) restore
    /// freshness before the older hours are backfilled.
    recent_backlog: bool,
    /// NAN-3359: oldest receipt hour that may still hold an undrained
    /// object, as of the last successful cycle ([`next_watermark_hour`]).
    /// In memory only: a gen1 restart begins with a full scan.
    watermark_hour: Option<i32>,
}

impl ScanState {
    /// `(full_scan, watermark_hour)` for the cycle about to run.
    fn begin(&mut self) -> (bool, Option<i32>) {
        let full_scan = self.cycles.is_multiple_of(FULL_SCAN_EVERY_CYCLES)
            || (self.full_scan_owed && !self.recent_backlog);
        self.cycles = self.cycles.wrapping_add(1);
        (full_scan, self.watermark_hour)
    }

    fn finish(&mut self, full_scan: bool, backlogged: bool, watermark_hour: Option<i32>) {
        if full_scan {
            self.full_scan_owed = backlogged;
        }
        self.recent_backlog = backlogged;
        self.watermark_hour = watermark_hour;
    }
}

/// One fetched handoff object, ready to be folded into the cycle in order.
enum FetchedHandoff {
    /// The exact read failed (content / ETag mismatch, object still
    /// landing): left unacknowledged for the next cycle.
    Retry,
    /// Acknowledged without rows (size outside bounds, undecodable batch, or
    /// every row failed normalization). `rows_rejected` is the per-row
    /// rejection count already recorded on the batch.
    Rejected(DrainedHandoffBatch),
    /// At least one normalized row.
    Accepted(DrainedHandoffBatch, Vec<OtelLakeRow>),
}

/// Pacing of the drain loop (NAN-3290 catch-up mode). Each dataset is drained
/// when its interval has elapsed OR its last cycle was backlogged; the loop
/// sleeps only while no dataset is backlogged. Both datasets are visited every
/// loop iteration, so a backlogged dataset never starves the other one, and
/// the caller's maintenance / credential-reload timers are checked every
/// iteration too.
#[derive(Debug, Clone)]
pub struct DrainPacer {
    interval: std::time::Duration,
    next_due: [std::time::Instant; 2],
    backlogged: [bool; 2],
}

impl DrainPacer {
    pub fn new(interval: std::time::Duration, now: std::time::Instant) -> Self {
        Self { interval, next_due: [now; 2], backlogged: [false; 2] }
    }

    fn slot(dataset: OtelDataset) -> usize {
        match dataset {
            OtelDataset::Spans => 0,
            OtelDataset::Metrics => 1,
        }
    }

    /// Whether `dataset` should be drained in this loop iteration.
    pub fn due(&self, dataset: OtelDataset, now: std::time::Instant) -> bool {
        let slot = Self::slot(dataset);
        self.backlogged[slot] || now >= self.next_due[slot]
    }

    /// Record one cycle's outcome (`backlogged = false` for a failed cycle,
    /// so a failing drain backs off at the normal interval).
    pub fn record(&mut self, dataset: OtelDataset, now: std::time::Instant, backlogged: bool) {
        let slot = Self::slot(dataset);
        self.backlogged[slot] = backlogged;
        self.next_due[slot] = now + self.interval;
    }

    /// True while any dataset is catching up.
    pub fn catching_up(&self) -> bool {
        self.backlogged.iter().any(|backlogged| *backlogged)
    }

    /// How long the loop sleeps before its next iteration: zero while any
    /// dataset is backlogged, else until the next dataset is due.
    pub fn pause(&self, now: std::time::Instant) -> std::time::Duration {
        if self.catching_up() {
            return std::time::Duration::ZERO;
        }
        self.next_due
            .iter()
            .min()
            .map_or(self.interval, |due| due.saturating_duration_since(now))
    }
}

pub struct OtelHandoffDrain {
    binding: OtelDrainBinding,
    source: Arc<dyn OtelHandoffSource>,
    /// `None` is the lean-lake drain (NAN-3243): no owner writer, no staged
    /// hot tail, no Iceberg. The local mirror IS the query store and the
    /// handoff objects in R2 stay the durable copy (see `crate::otel_lean`).
    sink: Option<Arc<dyn OtelHotTailSink>>,
    ledger: Arc<dyn OtelHandoffLedger>,
    mirror: Option<PathBuf>,
    mirror_policy: MirrorPolicy,
    /// Listing state per dataset (index: [`DrainPacer::slot`]). Gen1 only.
    scan: std::sync::Mutex<[ScanState; 2]>,
    /// NAN-3886: lean listing state per dataset, loaded from the mirror on
    /// first use and persisted after every cycle that changes it.
    lean_scan: std::sync::Mutex<[Option<LeanScanState>; 2]>,
    /// Handoff objects fetched concurrently per cycle (NAN-3290).
    fetch_concurrency: usize,
    /// The committed-table pins observed at the last hydration / drain
    /// cycle, per dataset, for the query side (no ledger round-trip per
    /// query).
    pins: std::sync::RwLock<BTreeMap<&'static str, CommittedTablePin>>,
}

impl OtelHandoffDrain {
    pub fn new(
        binding: OtelDrainBinding,
        source: Arc<dyn OtelHandoffSource>,
        sink: Arc<dyn OtelHotTailSink>,
        ledger: Arc<dyn OtelHandoffLedger>,
        mirror: Option<PathBuf>,
    ) -> Result<Self> {
        Self::with_mirror_policy(binding, source, sink, ledger, mirror, MirrorPolicy::default())
    }

    /// NAN-3243: the lean-lake drain. Handoff objects are decoded,
    /// normalized and encoded exactly as on gen1, but land ONLY in the local
    /// query mirror; `ledger` is [`crate::otel_lean::LeanOtelHandoffLedger`]
    /// (local drain markers + the `otel_publish` presence heartbeat). Keys
    /// whose receipt hour is older than the mirror floor are skipped unread:
    /// their rows could only be pruned again.
    pub fn lean(
        binding: OtelDrainBinding,
        source: Arc<dyn OtelHandoffSource>,
        ledger: Arc<dyn OtelHandoffLedger>,
        mirror: PathBuf,
        mirror_policy: MirrorPolicy,
    ) -> Result<Self> {
        Self::build(binding, source, None, ledger, Some(mirror), mirror_policy)
    }

    /// True for the lean-lake (mirror-only) drain.
    pub fn is_lean(&self) -> bool {
        self.sink.is_none()
    }

    pub fn with_mirror_policy(
        binding: OtelDrainBinding,
        source: Arc<dyn OtelHandoffSource>,
        sink: Arc<dyn OtelHotTailSink>,
        ledger: Arc<dyn OtelHandoffLedger>,
        mirror: Option<PathBuf>,
        mirror_policy: MirrorPolicy,
    ) -> Result<Self> {
        Self::build(binding, source, Some(sink), ledger, mirror, mirror_policy)
    }

    fn build(
        binding: OtelDrainBinding,
        source: Arc<dyn OtelHandoffSource>,
        sink: Option<Arc<dyn OtelHotTailSink>>,
        ledger: Arc<dyn OtelHandoffLedger>,
        mirror: Option<PathBuf>,
        mirror_policy: MirrorPolicy,
    ) -> Result<Self> {
        binding.validate()?;
        if sink.is_none() && mirror.is_none() {
            bail!("a mirror-only OTLP drain needs its query mirror");
        }
        mirror_policy.validate()?;
        if let Some(mirror) = &mirror {
            if !mirror.is_absolute() {
                bail!("OTLP query mirror directory must be absolute");
            }
            std::fs::create_dir_all(mirror).context("create OTLP query mirror directory")?;
        }
        Ok(Self {
            binding,
            source,
            sink,
            ledger,
            mirror,
            mirror_policy,
            scan: std::sync::Mutex::new([ScanState::default(); 2]),
            lean_scan: std::sync::Mutex::new([None, None]),
            fetch_concurrency: DEFAULT_DRAIN_FETCH_CONCURRENCY,
            pins: std::sync::RwLock::new(BTreeMap::new()),
        })
    }

    pub fn mirror_policy(&self) -> MirrorPolicy {
        self.mirror_policy
    }

    /// Fetch up to `concurrency` handoff objects at once per cycle
    /// (1..=[`MAX_DRAIN_FETCH_CONCURRENCY`]; default
    /// [`DEFAULT_DRAIN_FETCH_CONCURRENCY`]). 1 is the serial drain.
    pub fn with_fetch_concurrency(mut self, concurrency: usize) -> Result<Self> {
        if !(1..=MAX_DRAIN_FETCH_CONCURRENCY).contains(&concurrency) {
            bail!("OTLP drain fetch concurrency must be 1..={MAX_DRAIN_FETCH_CONCURRENCY}");
        }
        self.fetch_concurrency = concurrency;
        Ok(self)
    }

    /// The committed-table pin the query side reads (refreshed every cycle).
    pub fn committed_pin(&self, dataset: OtelDataset) -> Option<CommittedTablePin> {
        self.pins.read().ok()?.get(dataset.as_str()).cloned()
    }

    async fn refresh_pin(&self, dataset: OtelDataset) -> Result<()> {
        let pin = self.ledger.committed_pin(dataset).await?;
        if let Some(pin) = pin.as_ref() {
            let prefix = self.binding.table_location_prefix(dataset);
            if !pin.metadata_location.starts_with(&prefix) {
                bail!("committed OTLP table pin is outside the table location");
            }
        }
        let mut pins = self.pins.write().map_err(|_| anyhow::anyhow!("OTLP pin registry poisoned"))?;
        match pin {
            Some(pin) => {
                pins.insert(dataset.as_str(), pin);
            }
            None => {
                pins.remove(dataset.as_str());
            }
        }
        Ok(())
    }

    /// Oldest event hour the mirror keeps: the tenant's retention window when
    /// the ledger can read it, else the policy's age bound (whichever is
    /// tighter).
    async fn mirror_floor_hour(&self, now: DateTime<Utc>) -> Result<i32> {
        let mut max_age_hours = self.mirror_policy.max_age_hours;
        if let Some(days) = self.ledger.retention_days().await? {
            max_age_hours = max_age_hours.min(days.saturating_mul(24).max(1));
        }
        let floor = now - chrono::Duration::hours(i64::from(max_age_hours));
        Ok(i32::try_from(floor.timestamp().div_euclid(3_600))?)
    }

    /// The listing cursor for a normal cycle: every key of a receipt hour
    /// older than the lookback sorts before it.
    pub fn lookback_cursor(prefix: &str, now: DateTime<Utc>, lookback_hours: u32) -> String {
        let floor = now - chrono::Duration::hours(i64::from(lookback_hours));
        format!("{prefix}hour={}", floor.format("%Y%m%d%H"))
    }

    /// The listing cursor that sorts every key of a receipt hour below
    /// `floor_hour` (hours since the epoch) before it.
    pub fn floor_cursor(prefix: &str, floor_hour: i32) -> Result<String> {
        let floor = DateTime::<Utc>::from_timestamp(i64::from(floor_hour) * 3_600, 0)
            .context("OTLP mirror floor hour is out of range")?;
        // `start_after` is exclusive and every key of hour H is
        // `hour=H/<sha>`, which sorts after the bare `hour=H`.
        Ok(format!("{prefix}hour={}", floor.format("%Y%m%d%H")))
    }

    pub fn binding(&self) -> &OtelDrainBinding {
        &self.binding
    }

    /// Local path of one staged object inside the query mirror. Keeps the
    /// `event_hour=` segment so the planner's window pruning applies.
    pub fn mirror_path(mirror: &Path, dataset: OtelDataset, event_hour: i32, sha256: &str) -> PathBuf {
        mirror
            .join(dataset.as_str())
            .join(format!("event_hour={event_hour}"))
            .join(format!("{sha256}.parquet"))
    }

    /// Drain up to `max_objects` handoff objects of one dataset into one
    /// staged-tail publication. Returns what happened; `Ok` with zero objects
    /// seen is the idle case.
    ///
    /// NAN-3290: pending objects are taken NEWEST RECEIPT HOUR FIRST (so an
    /// empty mirror after a restart serves the live hours within the first
    /// cycle and older hours backfill after), fetched with bounded
    /// concurrency, and folded into the publication in that same
    /// deterministic order. Gen1: a backlogged full scan keeps later cycles
    /// scanning past the lookback window until the backlog is gone. Lean
    /// (NAN-3886): the live window plus a persisted, paged backfill sweep;
    /// see [`LeanScanState`].
    pub async fn drain_once(&self, dataset: OtelDataset) -> Result<DrainCycleReport> {
        if self.is_lean() {
            return self.drain_once_lean(dataset).await;
        }
        let slot = DrainPacer::slot(dataset);
        let (full_scan, watermark) = self.with_scan_state(|states| states[slot].begin())?;
        // A failed cycle leaves the watermark where it was (nothing drained).
        let (report, watermark) = self.drain_cycle(dataset, full_scan, watermark).await?;
        self.with_scan_state(|states| states[slot].finish(full_scan, report.backlogged, watermark))?;
        Ok(report)
    }

    fn with_scan_state<T>(&self, apply: impl FnOnce(&mut [ScanState; 2]) -> T) -> Result<T> {
        let mut states = self
            .scan
            .lock()
            .map_err(|_| anyhow::anyhow!("OTLP drain scan state poisoned"))?;
        Ok(apply(&mut states))
    }

    /// Prune what the packer/compactor moved out of `staged` BEFORE the new
    /// pin becomes visible: the query side unions the committed table with
    /// the mirror positionally, so a committed object that is still mirrored
    /// would be served twice.
    async fn settle_mirror(&self, dataset: OtelDataset) -> Result<()> {
        if self.mirror.is_some() {
            self.reconcile_mirror(dataset).await?;
            self.refresh_pin(dataset).await?;
        }
        Ok(())
    }

    /// One gen1 cycle. Returns the report and the next normal-cycle
    /// watermark ([`next_watermark_hour`]).
    async fn drain_cycle(
        &self,
        dataset: OtelDataset,
        full_scan: bool,
        watermark: Option<i32>,
    ) -> Result<(DrainCycleReport, Option<i32>)> {
        let now = Utc::now();
        let now_hour = i32::try_from(now.timestamp().div_euclid(3_600))?;
        let mut report = DrainCycleReport { full_scan, ..DrainCycleReport::default() };
        self.settle_mirror(dataset).await?;
        let prefix = handoff_prefix(self.binding.tenant_uuid, dataset);
        // NAN-3359: a normal cycle lists only the receipt hours that can still
        // hold undrained objects (always including the current and previous
        // hour); a full scan lists the whole prefix.
        let cursor = if full_scan {
            None
        } else {
            Some(Self::floor_cursor(
                &prefix,
                normal_cycle_start_hour(now_hour, self.binding.lookback_hours, None, watermark),
            )?)
        };
        report.list_calls += 1;
        let listed = self
            .source
            .list(&prefix, cursor.as_deref(), FULL_SCAN_ENTRY_CEILING)
            .await?;
        let candidates = self.dataset_candidates(dataset, listed)?;
        report.objects_seen = candidates.len();
        let (hours, candidates) = newest_first(candidates);
        let oldest_listed_hour = hours.iter().copied().min();
        let (pending, pending_hours, saturated) = self
            .pending_newest_first(dataset, &candidates, &hours, self.binding.max_objects)
            .await?;
        let pending_count = pending.len();
        let fold = self.drain_pending(dataset, pending, &pending_hours, &mut report).await?;
        let oldest_retry_hour = fold.retries.iter().map(|index| pending_hours[*index]).min();
        report.backlogged = (saturated || fold.examined < pending_count) && fold.acknowledged;
        let coverage = cycle_coverage(saturated, oldest_listed_hour, &pending_hours, fold.examined, oldest_retry_hour);
        Ok((report, next_watermark_hour(watermark, now_hour, coverage)))
    }

    /// `(receipt_hour, key)` of every listed key of `dataset`; foreign
    /// objects are logged and skipped, a key of the other dataset fails.
    fn dataset_candidates(&self, dataset: OtelDataset, listed: Vec<String>) -> Result<Vec<(String, String)>> {
        let mut candidates = Vec::with_capacity(listed.len());
        for key in listed {
            match parse_handoff_key(&key, self.binding.tenant_uuid) {
                Ok(parsed) if parsed.dataset == dataset => candidates.push((parsed.receipt_hour, key)),
                Ok(_) => bail!("OTLP handoff listing crossed its dataset prefix"),
                Err(error) => {
                    tracing::warn!(key, %error, "ignoring foreign object under the OTLP handoff prefix");
                }
            }
        }
        Ok(candidates)
    }

    /// The undrained keys among `candidates` (already newest first), at most
    /// `limit`, with their receipt hours. The ledger check is paged so a
    /// long-lived prefix costs one bounded query per page instead of one
    /// unbounded ANY($2). `true` = saturated: there may be more pending
    /// than this cycle takes.
    async fn pending_newest_first(
        &self,
        dataset: OtelDataset,
        candidates: &[String],
        hours: &[i32],
        limit: usize,
    ) -> Result<(Vec<String>, Vec<i32>, bool)> {
        let mut pending = Vec::new();
        let mut pending_hours = Vec::new();
        for (page_index, page) in candidates.chunks(LEDGER_PAGE).enumerate() {
            let drained = self.ledger.drained_keys(dataset, page).await?;
            for (offset, key) in page.iter().enumerate() {
                if !drained.contains(key) {
                    pending.push(key.clone());
                    pending_hours.push(hours[page_index * LEDGER_PAGE + offset]);
                }
            }
            if pending.len() >= limit {
                break;
            }
        }
        let saturated = pending.len() >= limit;
        pending.truncate(limit);
        pending_hours.truncate(limit);
        Ok((pending, pending_hours, saturated))
    }

    // ---- NAN-3886: the lean drain -----------------------------------------

    fn with_lean_scan<T>(&self, apply: impl FnOnce(&mut [Option<LeanScanState>; 2]) -> T) -> Result<T> {
        let mut states = self
            .lean_scan
            .lock()
            .map_err(|_| anyhow::anyhow!("lean OTLP drain scan state poisoned"))?;
        Ok(apply(&mut states))
    }

    /// The lean scan state of `dataset` this drain is working from.
    pub fn lean_scan_state(&self, dataset: OtelDataset) -> Result<Option<LeanScanState>> {
        self.with_lean_scan(|states| states[DrainPacer::slot(dataset)].clone())
    }

    /// The lean state this drain works from, or (before its first cycle)
    /// the one persisted in the mirror.
    fn lean_state_or_persisted(&self, dataset: OtelDataset) -> Result<Option<(PathBuf, LeanScanState)>> {
        let (true, Some(mirror)) = (self.is_lean(), self.mirror.as_ref()) else {
            return Ok(None);
        };
        let state = match self.lean_scan_state(dataset)? {
            Some(state) => state,
            None => crate::otel_lean::load_lean_scan_state(mirror, dataset),
        };
        Ok(Some((mirror.clone(), state)))
    }

    /// NAN-3894: what this lean mirror attests for `dataset` (`None` on gen1).
    pub fn lean_coverage(&self, dataset: OtelDataset) -> Result<Option<crate::otel_lean::LeanCoverage>> {
        let Some((mirror, state)) = self.lean_state_or_persisted(dataset)? else {
            return Ok(None);
        };
        let evicted = crate::otel_lean::newest_evicted_hour(&mirror, dataset)?;
        Ok(Some(crate::otel_lean::lean_coverage(dataset, &state, evicted, Utc::now())))
    }

    /// NAN-3894: true only when this lean mirror holds every row of
    /// `[start, end)` ([`crate::otel_lean::lean_window_complete`]). Any
    /// error or a gen1 drain is `false`: absence never proves coverage.
    pub fn lean_window_complete(&self, dataset: OtelDataset, start: DateTime<Utc>, end: DateTime<Utc>) -> bool {
        let Ok(Some((mirror, state))) = self.lean_state_or_persisted(dataset) else {
            return false;
        };
        let Ok(evicted) = crate::otel_lean::newest_evicted_hour(&mirror, dataset) else {
            return false;
        };
        crate::otel_lean::lean_window_complete(&state, evicted, start, end, Utc::now())
    }

    async fn drain_once_lean(&self, dataset: OtelDataset) -> Result<DrainCycleReport> {
        let mirror = self.mirror.clone().context("a lean OTLP drain needs its query mirror")?;
        let slot = DrainPacer::slot(dataset);
        // First cycle of this process: resume where the previous process
        // over the same mirror stopped.
        let (previous, persisted) = match self.with_lean_scan(|states| states[slot].clone())? {
            Some(state) => (state, true),
            None => (crate::otel_lean::load_lean_scan_state(&mirror, dataset), false),
        };
        let (report, next) = self.drain_cycle_lean(dataset, &mirror, previous.clone()).await?;
        if next != previous || !persisted {
            // Best effort: the drain markers carry exactly-once; a lost state
            // file only costs one re-sweep after the next restart.
            if let Err(error) = crate::otel_lean::save_lean_scan_state(&mirror, dataset, &next) {
                tracing::warn!(dataset = dataset.as_str(), error = %format!("{error:#}"), "lean OTLP drain scan state not persisted");
            }
        }
        self.with_lean_scan(|states| states[slot] = Some(next))?;
        Ok(report)
    }

    /// One lean cycle: the live window (newest first), then — when the live
    /// window left room under `max_objects` — the backfill sweep, resumed
    /// from its persisted cursor. Returns the report and the next state.
    async fn drain_cycle_lean(
        &self,
        dataset: OtelDataset,
        mirror: &Path,
        mut state: LeanScanState,
    ) -> Result<(DrainCycleReport, LeanScanState)> {
        let now = Utc::now();
        let now_hour = i32::try_from(now.timestamp().div_euclid(3_600))?;
        let mut report = DrainCycleReport::default();
        // A cycle that died between its first mirror write and its last
        // marker is rolled back before anything reads the mirror.
        let rolled_back = crate::otel_lean::recover_drain_journal(mirror, dataset, self.binding.tenant_uuid)?;
        if rolled_back > 0 {
            tracing::warn!(dataset = dataset.as_str(), rolled_back, "rolled back an interrupted lean OTLP drain cycle");
        }
        self.settle_mirror(dataset).await?;
        // A key whose receipt hour is below the mirror floor holds only rows
        // the mirror would prune again (event time <= receipt time).
        let floor = self.mirror_floor_hour(now).await?;
        let prefix = handoff_prefix(self.binding.tenant_uuid, dataset);
        // No state yet (a fresh mirror): the live window is the current and
        // previous hour, and the sweep starts right below it, so the newest
        // hours fill first and older hours backfill newest first.
        let mut watermark = *state.watermark_hour.get_or_insert(now_hour.saturating_sub(1));
        let live_start = normal_cycle_start_hour(now_hour, self.binding.lookback_hours, Some(floor), Some(watermark))
            .max(now_hour.saturating_sub(LEAN_LIVE_WINDOW_HOURS));
        let top = live_start.saturating_sub(1);
        if watermark < live_start {
            // Hours [max(watermark, floor), live_start) are still owed but
            // the live window no longer lists them: hand them to a sweep
            // that stops at the old watermark (everything below it was
            // proven), and move the watermark up to the live window.
            let stop = watermark.max(floor);
            if stop < live_start {
                state.unproven_hours.extend(stop..live_start);
                state.sweep = Some(match state.sweep.take() {
                    // A sweep in progress may already be below the owed
                    // hours: restart it from the top, keeping its reach.
                    Some(LeanSweepCursor { stop_hour: None, .. }) => LeanSweepCursor::top(top, None),
                    Some(LeanSweepCursor { stop_hour: Some(previous), .. }) => {
                        LeanSweepCursor::top(top, Some(previous.min(stop)))
                    }
                    None => LeanSweepCursor::top(top, Some(stop)),
                });
            }
            watermark = live_start;
        }
        if state.sweep.is_none() {
            let interval = i64::try_from(LEAN_SWEEP_INTERVAL.as_secs()).unwrap_or(i64::MAX);
            let due = state
                .last_sweep_completed_unix
                .is_none_or(|at| now.timestamp().saturating_sub(at) >= interval);
            if due {
                state.sweep = Some(LeanSweepCursor::top(top, None));
            }
        }
        // The sweep never lists an hour the live window lists.
        if let Some(cursor) = state.sweep.as_mut() {
            if cursor.hour >= live_start {
                *cursor = LeanSweepCursor::top(top, cursor.stop_hour);
            }
        }

        report.list_calls += 1;
        let listed = self
            .source
            .list(&prefix, Some(&Self::floor_cursor(&prefix, live_start)?), FULL_SCAN_ENTRY_CEILING)
            .await?;
        let live = self.dataset_candidates(dataset, listed)?;
        report.objects_seen = live.len();
        let (live_hours, live_keys) = newest_first(live);
        let oldest_live_hour = live_hours.iter().copied().min();
        let (mut pending, mut pending_hours, live_saturated) = self
            .pending_newest_first(dataset, &live_keys, &live_hours, self.binding.max_objects)
            .await?;
        let live_count = pending.len();

        // Freshness first: the sweep only gets what the live window left.
        let mut sweep = None;
        let periodic = state.sweep.as_ref().is_some_and(|cursor| cursor.stop_hour.is_none());
        if let (false, Some(cursor)) = (live_saturated, state.sweep.clone()) {
            let pass = self
                .sweep_pass(dataset, &prefix, floor, cursor, self.binding.max_objects - live_count, &mut report)
                .await?;
            report.sweep = true;
            report.objects_seen += pass.seen;
            for item in &pass.items {
                pending.push(item.key.clone());
                pending_hours.push(item.hour);
            }
            sweep = Some(pass);
        }

        let pending_count = pending.len();
        let fold = self.drain_pending(dataset, pending, &pending_hours, &mut report).await?;

        // The live window moves the watermark exactly as on gen1 (NAN-3359).
        let live_examined = fold.examined.min(live_count);
        let live_retry_hour = fold
            .retries
            .iter()
            .filter(|index| **index < live_count)
            .map(|index| pending_hours[*index])
            .min();
        let coverage = cycle_coverage(
            live_saturated,
            oldest_live_hour,
            &pending_hours[..live_count],
            live_examined,
            live_retry_hour,
        );
        state.watermark_hour = next_watermark_hour(Some(watermark), now_hour, coverage);
        if coverage == (CycleCoverage::Complete { oldest_retry_hour: None }) {
            state.live_proven_unix = Some(now.timestamp());
        }

        // The sweep advances past everything it proved: up to its first
        // undrained key the fold did not reach (cut by `max_rows`). A key
        // whose exact read failed is passed over; the next sweep retries it.
        let mut sweep_found = false;
        if let Some(pass) = sweep {
            let sweep_examined = fold.examined.saturating_sub(live_count);
            sweep_found = !pass.items.is_empty();
            let previous = state.sweep.take().context("a sweep pass ran without a sweep")?;
            let mut retried = previous.retried.clone();
            retried.extend(
                fold.retries
                    .iter()
                    .filter(|index| **index >= live_count)
                    .map(|index| pending_hours[*index]),
            );
            state.unproven_hours.extend(retried.iter().copied());
            let next = match pass.items.get(sweep_examined) {
                Some(item) => Some(item.before.clone()),
                None => pass.end,
            };
            // Coverage: every hour the sweep has fully passed is proven,
            // except the hours where it passed over a failed read.
            let passed_below = next.as_ref().map_or(pass.floor.saturating_sub(1), |cursor| cursor.hour);
            state
                .unproven_hours
                .retain(|hour| !(passed_below < *hour && *hour <= previous.hour) || retried.contains(hour));
            state.sweep = next.map(|cursor| LeanSweepCursor { retried, ..cursor });
            if state.sweep.is_none() {
                if periodic {
                    state.last_sweep_completed_unix = Some(now.timestamp());
                    // Everything from the mirror floor up is now drained
                    // (the live window proved the hours above the sweep).
                    state.covered_since_hour = Some(pass.floor);
                }
                tracing::info!(dataset = dataset.as_str(), periodic, "lean OTLP backfill sweep completed");
            }
        }
        // Hours below the mirror floor are pruned: coverage starts there.
        if let Some(covered) = state.covered_since_hour.as_mut() {
            *covered = (*covered).max(floor);
        }
        state.unproven_hours.retain(|hour| *hour >= floor);
        report.backlogged = fold.acknowledged
            && (live_saturated || fold.examined < pending_count || (sweep_found && state.sweep.is_some()));
        state.backlogged = report.backlogged || live_saturated || fold.examined < pending_count;
        Ok((report, state))
    }

    /// Continue the lean backfill sweep from `cursor`: the receipt hours that
    /// exist (one delimiter listing), newest first, from `cursor.hour` down
    /// to `floor`, one page per list call, at most
    /// [`LEAN_SWEEP_LIST_CALLS_PER_CYCLE`] calls, stopping once `budget`
    /// undrained keys are found.
    async fn sweep_pass(
        &self,
        dataset: OtelDataset,
        prefix: &str,
        floor: i32,
        cursor: LeanSweepCursor,
        budget: usize,
        report: &mut DrainCycleReport,
    ) -> Result<SweepPass> {
        report.list_calls += 1;
        let top = cursor.hour;
        let stop_hour = cursor.stop_hour;
        let floor = stop_hour.map_or(floor, |stop| stop.max(floor));
        let at = |hour: i32, start_after: Option<String>| LeanSweepCursor { hour, start_after, stop_hour, retried: BTreeSet::new() };
        let hours = self
            .source
            .list_receipt_hours(prefix)
            .await?
            .into_iter()
            .filter(|hour| (floor..=top).contains(hour))
            .collect::<Vec<_>>();
        let mut position = cursor;
        let mut items = Vec::new();
        let mut seen = 0usize;
        let mut calls = 0usize;
        for hour in hours {
            if hour < position.hour {
                position = at(hour, None);
            }
            let hour_prefix = format!("{prefix}hour={}/", receipt_hour_label(hour)?);
            loop {
                if calls >= LEAN_SWEEP_LIST_CALLS_PER_CYCLE || items.len() >= budget {
                    return Ok(SweepPass { items, end: Some(position), seen, floor });
                }
                calls += 1;
                report.list_calls += 1;
                let keys = self
                    .source
                    .list(&hour_prefix, position.start_after.as_deref(), LEAN_SWEEP_PAGE_KEYS)
                    .await?;
                let exhausted = keys.len() < LEAN_SWEEP_PAGE_KEYS;
                seen += keys.len();
                let mut candidates = Vec::with_capacity(keys.len());
                for key in &keys {
                    match parse_handoff_key(key, self.binding.tenant_uuid) {
                        Ok(parsed) if parsed.dataset == dataset => candidates.push(key.clone()),
                        Ok(_) => bail!("OTLP handoff listing crossed its dataset prefix"),
                        Err(error) => {
                            tracing::warn!(key, %error, "ignoring foreign object under the OTLP handoff prefix");
                        }
                    }
                }
                let mut drained = std::collections::HashSet::new();
                for page in candidates.chunks(LEDGER_PAGE) {
                    drained.extend(self.ledger.drained_keys(dataset, page).await?);
                }
                let candidates = candidates.into_iter().collect::<std::collections::HashSet<_>>();
                for key in keys {
                    if candidates.contains(&key) && !drained.contains(&key) {
                        if items.len() >= budget {
                            return Ok(SweepPass { items, end: Some(position), seen, floor });
                        }
                        items.push(SweepItem { key: key.clone(), hour, before: position.clone() });
                    }
                    position = at(hour, Some(key));
                }
                if exhausted {
                    break;
                }
            }
            position = at(hour.saturating_sub(1), None);
        }
        Ok(SweepPass { items, end: None, seen, floor })
    }

    /// Fetch and fold `pending` (in order, until `max_rows`), write the
    /// mirror / publish the staged tail, and acknowledge — or heartbeat when
    /// nothing is acknowledged.
    ///
    /// Lean (NAN-3886): the mirror files and drain markers of one cycle are
    /// written under a drain journal, so a crash between the first Parquet
    /// write and the last marker is rolled back (files and markers) instead
    /// of leaving rows that a re-drain with a different batch composition
    /// would duplicate.
    async fn drain_pending(
        &self,
        dataset: OtelDataset,
        pending: Vec<String>,
        pending_hours: &[i32],
        report: &mut DrainCycleReport,
    ) -> Result<FoldOutcome> {
        let tenant = self.binding.tenant_uuid.to_string();
        let mut examined = 0usize;
        let mut rows = Vec::<OtelLakeRow>::new();
        let mut batches = Vec::<DrainedHandoffBatch>::new();
        let mut publication_batches = Vec::<usize>::new();
        let mut retries = Vec::<usize>::new();
        debug_assert_eq!(pending.len(), pending_hours.len());
        {
            // `buffered` keeps at most `fetch_concurrency` fetches in flight
            // and yields their results in `pending` order, so the fold below
            // is exactly the serial drain's: same max_rows cut-off, same
            // batch order, and an error is raised only when the fold reaches
            // the object (a failed fetch past the cut-off is dropped unseen).
            let mut fetches = futures::stream::iter(
                pending
                    .into_iter()
                    .map(|key| self.fetch_handoff(dataset, &tenant, key)),
            )
            .buffered(self.fetch_concurrency);
            while rows.len() < self.binding.max_rows {
                let Some(fetched) = fetches.next().await else {
                    break;
                };
                let index = examined;
                examined += 1;
                match fetched? {
                    FetchedHandoff::Retry => retries.push(index),
                    FetchedHandoff::Rejected(batch) => {
                        report.rows_rejected += u64::from(batch.rows_rejected);
                        report.objects_rejected += 1;
                        batches.push(batch);
                    }
                    FetchedHandoff::Accepted(batch, accepted) => {
                        report.rows_rejected += u64::from(batch.rows_rejected);
                        rows.extend(accepted);
                        publication_batches.push(batches.len());
                        batches.push(batch);
                    }
                }
            }
        }
        if batches.is_empty() {
            self.ledger.heartbeat().await?;
            return Ok(FoldOutcome { examined, retries, acknowledged: false });
        }
        // The newest event hour already resident, before this cycle writes:
        // the cap protects the hour just written only when it is the newest
        // (a backfilled OLDER hour must not push newer hours out — newest
        // hours win when the cap binds, whatever order they were drained in).
        let resident_newest_hour = match &self.mirror {
            Some(mirror) if !rows.is_empty() => mirror_objects(mirror, dataset)?.last().map(|(hour, _, _)| *hour),
            _ => None,
        };
        let mut staged = Vec::new();
        let mut logical = String::new();
        if !rows.is_empty() {
            // Collapse identical row identities across handoff objects (a
            // retried sink batch lands twice under two receipt keys).
            let (deduped, collapsed) = crate::otel_iceberg::dedupe_otel_batch(&rows);
            if collapsed > 0 {
                tracing::info!(collapsed, "collapsed duplicate OTLP row identities across handoff objects");
            }
            logical = drain_batch_sha256(&deduped);
            for index in &publication_batches {
                batches[*index].tail_batch_sha256 = Some(logical.clone());
            }
            staged = encode_staged_otel_objects(dataset, self.binding.tenant_uuid, &deduped, &logical)?;
        }
        drop(rows);
        let journal = match (&self.mirror, self.is_lean()) {
            (Some(mirror), true) => {
                // Content-addressed: a path that already exists holds these
                // exact bytes from an earlier, fully acknowledged cycle and
                // is not this cycle's to roll back.
                let new_files = staged
                    .iter()
                    .map(|file| Self::mirror_path(mirror, dataset, file.event_hour, &file.sha256))
                    .filter(|path| !path.exists())
                    .collect::<Vec<_>>();
                let keys = batches.iter().map(|batch| batch.object_key.clone()).collect::<Vec<_>>();
                crate::otel_lean::begin_drain_journal(mirror, dataset, &new_files, &keys)?;
                Some(mirror.clone())
            }
            _ => None,
        };
        let committed = self
            .commit_cycle(dataset, staged, &logical, batches, resident_newest_hour, report)
            .await;
        if let Some(mirror) = journal {
            match &committed {
                Ok(()) => crate::otel_lean::finish_drain_journal(&mirror, dataset)?,
                Err(_) => {
                    if let Err(error) =
                        crate::otel_lean::recover_drain_journal(&mirror, dataset, self.binding.tenant_uuid)
                    {
                        tracing::error!(dataset = dataset.as_str(), error = %format!("{error:#}"), "lean OTLP drain cycle failed and its rollback failed; retried next cycle");
                    }
                }
            }
        }
        committed?;
        report.objects_drained = publication_batches.len();
        Ok(FoldOutcome { examined, retries, acknowledged: true })
    }

    /// Write the cycle's staged objects (mirror and/or owner writer), enforce
    /// the mirror cap, and acknowledge every batch.
    async fn commit_cycle(
        &self,
        dataset: OtelDataset,
        staged: Vec<StagedOtelObject>,
        logical: &str,
        batches: Vec<DrainedHandoffBatch>,
        resident_newest_hour: Option<i32>,
        report: &mut DrainCycleReport,
    ) -> Result<()> {
        let tenant = self.binding.tenant_uuid.to_string();
        let mut newest_written_hour: Option<i32> = None;
        let mut objects = Vec::new();
        let table_key = self.binding.table_key(dataset).to_string();
        for file in staged {
            let key = format!("{table_key}/{}", file.relative_path);
            validate_staged_key(&key, &table_key, &tenant, &file)?;
            let publication = StagedTailPublication {
                tenant_id: self.binding.logical_tenant_key.clone(),
                partition_tenant_id: tenant.clone(),
                object_bucket: self.binding.bucket.clone(),
                object_key: key.clone(),
                event_hour: file.event_hour,
                min_time_ms: file.min_time_ms,
                max_time_ms: file.max_time_ms,
                content_length: u64::try_from(file.bytes.len())?,
                content_sha256: file.sha256.clone(),
            };
            crate::shared_mode::hooks().validate_staged_tail(&publication)?;
            let published = match &self.sink {
                Some(sink) => Some(sink.publish(&publication, file.bytes.clone()).await?),
                None => None,
            };
            if let Some(mirror) = &self.mirror {
                let path = Self::mirror_path(mirror, dataset, file.event_hour, &file.sha256);
                if self.is_lean() {
                    // The markers that follow must never outlive the rows.
                    write_mirror_object_synced(&path, &file.bytes)?;
                } else {
                    write_mirror_object(&path, &file.bytes)?;
                }
                newest_written_hour = Some(newest_written_hour.map_or(file.event_hour, |h: i32| h.max(file.event_hour)));
            }
            let Some(published) = published else {
                // Lean: the mirror is the store; nothing is staged.
                report.rows_published += file.rows;
                continue;
            };
            objects.push(AcknowledgedTailObject {
                dataset,
                table_location_prefix: self.binding.table_location_prefix(dataset),
                batch_sha256: logical.to_string(),
                event_hour: file.event_hour,
                object_uri: format!("{}/{}", self.binding.table_location(dataset), file.relative_path),
                version_id: published.version_id,
                etag: published.etag,
                bytes: u64::try_from(file.bytes.len())?,
                sha256: file.sha256,
                rows: file.rows,
                min_time_ms: file.min_time_ms,
                max_time_ms: file.max_time_ms,
                deletion_unit_id: published.deletion_unit_id,
                writer_authority_sha256: published.writer_authority_sha256,
            });
            report.rows_published += file.rows;
        }
        report.tail_objects_published = objects.len();
        if let (Some(mirror), Some(hour)) = (&self.mirror, newest_written_hour) {
            let protect = resident_newest_hour
                .is_none_or(|resident| hour >= resident)
                .then_some((dataset, hour));
            if self.is_lean() {
                // NAN-3894: the eviction is recorded (durably) BEFORE any
                // file goes, so coverage never attests an evicted hour.
                enforce_mirror_cap_with(mirror, self.mirror_policy.max_bytes, protect, |evicting| {
                    crate::otel_lean::record_mirror_eviction(mirror, evicting)
                })?;
            } else {
                enforce_mirror_cap(mirror, self.mirror_policy.max_bytes, protect)?;
            }
        }
        self.ledger
            .acknowledge(&DrainAcknowledgement {
                dataset,
                objects,
                batches,
            })
            .await
            .context("acknowledge OTLP handoff drain cycle")
    }

    /// HEAD, exact GET, decode and normalize one pending handoff object.
    /// `Err` (unparseable key, failed HEAD) fails the cycle when the in-order
    /// fold reaches this object, exactly as the serial drain did.
    async fn fetch_handoff(&self, dataset: OtelDataset, tenant: &str, key: String) -> Result<FetchedHandoff> {
        let parsed = parse_handoff_key(&key, self.binding.tenant_uuid)?;
        let (size, etag) = self.source.head(&key).await?;
        let mut batch = DrainedHandoffBatch {
            dataset,
            object_key: key,
            object_sha256: parsed.content_sha256,
            object_bytes: size,
            object_etag: etag,
            rows_decoded: 0,
            rows_rejected: 0,
            tail_batch_sha256: None,
            last_error: None,
        };
        if size == 0 || size > OTEL_HANDOFF_MAX_OBJECT_BYTES {
            batch.last_error = Some(format!("handoff object size {size} is outside 1..={OTEL_HANDOFF_MAX_OBJECT_BYTES}"));
            return Ok(FetchedHandoff::Rejected(batch));
        }
        let body = match self
            .source
            .read_exact(&batch.object_key, size, &batch.object_sha256, &batch.object_etag)
            .await
        {
            Ok(body) => body,
            Err(error) => {
                // A content/ETag mismatch is not a poison pill: the object
                // may still be landing. Leave it unacknowledged for the
                // next cycle and log.
                tracing::warn!(key = batch.object_key, %error, "OTLP handoff object failed its exact read; retrying next cycle");
                return Ok(FetchedHandoff::Retry);
            }
        };
        let decoded = match decode_otel_batch(&body, dataset, self.binding.max_rows) {
            Ok(decoded) => decoded,
            Err(error) => {
                batch.last_error = Some(bounded_error(&error));
                return Ok(FetchedHandoff::Rejected(batch));
            }
        };
        drop(body);
        let mut rows = Vec::with_capacity(decoded.len());
        let mut rejected = 0_u32;
        let mut first_error = None;
        for value in &decoded {
            match normalize_otel_row(dataset, tenant, value) {
                Ok(row) => rows.push(row),
                Err(error) => {
                    rejected += 1;
                    if first_error.is_none() {
                        first_error = Some(bounded_error(&error));
                    }
                }
            }
        }
        batch.rows_decoded = u32::try_from(rows.len()).context("OTLP handoff object decoded too many rows")?;
        batch.rows_rejected = rejected;
        batch.last_error = first_error;
        Ok(if rows.is_empty() {
            FetchedHandoff::Rejected(batch)
        } else {
            FetchedHandoff::Accepted(batch, rows)
        })
    }

    /// Bring the mirror's object set in line with the ledger: remove every
    /// local object the ledger no longer lists as STAGED for this table
    /// (superseded by a pack, compacted into Iceberg) or whose event hour is
    /// outside the age bound. Returns the staged objects inside the window
    /// (newest hour first) and the number pruned. Runs every drain cycle and
    /// at boot.
    pub async fn reconcile_mirror(&self, dataset: OtelDataset) -> Result<(Vec<LedgerTailObject>, usize)> {
        let Some(mirror) = &self.mirror else {
            return Ok((Vec::new(), 0));
        };
        let floor_hour = self.mirror_floor_hour(Utc::now()).await?;
        let mut staged = self.ledger.staged_objects(dataset).await?;
        staged.retain(|object| object.event_hour >= floor_hour);
        // Newest hours first: they are what the tail serves; older staged
        // hours drop off first when the cap binds.
        staged.sort_by(|a, b| b.event_hour.cmp(&a.event_hour).then_with(|| a.object_uri.cmp(&b.object_uri)));
        let keep = staged
            .iter()
            .map(|object| Self::mirror_path(mirror, dataset, object.event_hour, &object.sha256))
            .collect::<std::collections::BTreeSet<_>>();
        let mut pruned = 0usize;
        for (_, path, _) in mirror_objects(mirror, dataset)? {
            if !keep.contains(&path) {
                std::fs::remove_file(&path).with_context(|| format!("prune mirrored OTLP object {}", path.display()))?;
                pruned += 1;
            }
        }
        if pruned > 0 {
            tracing::info!(dataset = dataset.as_str(), pruned, "OTLP query mirror pruned objects the tail ledger no longer stages");
        }
        Ok((staged, pruned))
    }

    /// Re-hydrate the query mirror from the ledger (fail-closed):
    ///
    /// 1. the committed-table pin is refreshed;
    /// 2. every local object the ledger no longer lists as STAGED for this
    ///    table (superseded by a pack, compacted into Iceberg) or whose
    ///    event hour is outside the retention window is removed;
    /// 3. every staged object inside the window that is missing locally is
    ///    read EXACTLY (byte length, strong ETag, SHA-256) from R2, newest
    ///    event hour first, until the byte cap is reached — a mismatch is an
    ///    error, never a partial mirror;
    /// 4. the cap is enforced (oldest hours evicted).
    ///
    /// Returns the number fetched.
    pub async fn hydrate_mirror(&self, dataset: OtelDataset) -> Result<usize> {
        let Some(mirror) = &self.mirror else {
            return Ok(0);
        };
        self.refresh_pin(dataset).await?;
        let table_prefix = self.binding.table_location_prefix(dataset);
        let (staged, pruned) = self.reconcile_mirror(dataset).await?;
        let mut resident_bytes = mirror_total_bytes(mirror)?;
        let mut fetched = 0;
        let mut skipped_by_cap = 0usize;
        for object in staged {
            let path = Self::mirror_path(mirror, dataset, object.event_hour, &object.sha256);
            if path.is_file() && std::fs::metadata(&path)?.len() == object.bytes {
                continue;
            }
            if resident_bytes.saturating_add(object.bytes) > self.mirror_policy.max_bytes {
                skipped_by_cap += 1;
                continue;
            }
            let key = object
                .object_uri
                .strip_prefix(&table_prefix)
                .map(|relative| format!("{}/{relative}", self.binding.table_key(dataset)))
                .context("staged OTLP object is outside its table location")?;
            let body = self
                .source
                .read_exact(&key, object.bytes, &object.sha256, &object.etag)
                .await
                .with_context(|| format!("hydrate staged OTLP object {}", object.object_uri))?;
            write_mirror_object(&path, &body)?;
            resident_bytes = resident_bytes.saturating_add(object.bytes);
            fetched += 1;
        }
        enforce_mirror_cap(mirror, self.mirror_policy.max_bytes, None)?;
        if pruned > 0 || skipped_by_cap > 0 {
            tracing::info!(
                dataset = dataset.as_str(),
                pruned,
                skipped_by_cap,
                cap_bytes = self.mirror_policy.max_bytes,
                "OTLP query mirror reconciled with the tail ledger"
            );
        }
        if skipped_by_cap > 0 {
            tracing::warn!(
                dataset = dataset.as_str(),
                skipped_by_cap,
                "staged OTLP objects exceed the mirror byte cap and are not queryable until packed and committed"
            );
        }
        Ok(fetched)
    }
}

/// Bytes resident across both datasets of the mirror.
pub fn mirror_total_bytes(mirror: &Path) -> Result<u64> {
    let mut total = 0_u64;
    for dataset in [OtelDataset::Spans, OtelDataset::Metrics] {
        for (_, _, bytes) in mirror_objects(mirror, dataset)? {
            total = total.checked_add(bytes).context("OTLP mirror byte total overflowed")?;
        }
    }
    Ok(total)
}

/// Evict the oldest event hours (across both datasets) until the mirror is
/// within `max_bytes`. `protect` names the hour just written by the drain so
/// a single oversized hour is never evicted right after landing (the cap
/// is then exceeded and logged rather than the newest data dropped).
pub fn enforce_mirror_cap(mirror: &Path, max_bytes: u64, protect: Option<(OtelDataset, i32)>) -> Result<usize> {
    enforce_mirror_cap_with(mirror, max_bytes, protect, |_| Ok(()))
}

/// [`enforce_mirror_cap`] that hands `record` every `(dataset, event_hour)`
/// it is about to evict from, before the first file is removed.
pub fn enforce_mirror_cap_with(
    mirror: &Path,
    max_bytes: u64,
    protect: Option<(OtelDataset, i32)>,
    record: impl FnOnce(&[(OtelDataset, i32)]) -> Result<()>,
) -> Result<usize> {
    let mut objects = Vec::new();
    for dataset in [OtelDataset::Spans, OtelDataset::Metrics] {
        for (event_hour, path, bytes) in mirror_objects(mirror, dataset)? {
            objects.push((event_hour, dataset, path, bytes));
        }
    }
    let mut total = objects.iter().map(|(_, _, _, bytes)| *bytes).sum::<u64>();
    if total <= max_bytes {
        return Ok(0);
    }
    // Oldest hour first; within an hour, larger objects first.
    objects.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| b.3.cmp(&a.3)));
    let mut victims = Vec::new();
    for (event_hour, dataset, path, bytes) in objects {
        if total <= max_bytes {
            break;
        }
        if protect == Some((dataset, event_hour)) {
            continue;
        }
        total = total.saturating_sub(bytes);
        victims.push((dataset, event_hour, path));
    }
    if !victims.is_empty() {
        record(&victims.iter().map(|(dataset, hour, _)| (*dataset, *hour)).collect::<Vec<_>>())?;
    }
    let mut evicted = 0usize;
    for (_, _, path) in victims {
        std::fs::remove_file(&path).with_context(|| format!("evict mirrored OTLP object {}", path.display()))?;
        evicted += 1;
    }
    if total > max_bytes {
        tracing::warn!(resident_bytes = total, cap_bytes = max_bytes, "OTLP mirror exceeds its cap by the newest hour alone");
    }
    if evicted > 0 {
        tracing::info!(evicted, resident_bytes = total, cap_bytes = max_bytes, "OTLP mirror evicted oldest hours to honor its cap");
    }
    Ok(evicted)
}

fn bounded_error(error: &anyhow::Error) -> String {
    let text = format!("{error:#}");
    text.chars().take(512).collect()
}

pub(crate) fn write_mirror_object(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path.parent().context("mirror path has no parent")?;
    std::fs::create_dir_all(parent)?;
    let temporary = parent.join(format!(".{}.tmp", Uuid::now_v7()));
    std::fs::write(&temporary, bytes)?;
    std::fs::rename(&temporary, path)?;
    Ok(())
}

/// [`write_mirror_object`] that survives a node crash, not only a process
/// crash (NAN-3886: the lean mirror lives on a PersistentVolumeClaim): the
/// bytes and the directory entry are synced before it returns.
pub(crate) fn write_mirror_object_synced(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path.parent().context("mirror path has no parent")?;
    std::fs::create_dir_all(parent)?;
    let temporary = parent.join(format!(".{}.tmp", Uuid::now_v7()));
    {
        let mut file = std::fs::File::create(&temporary)?;
        std::io::Write::write_all(&mut file, bytes)?;
        file.sync_all()?;
    }
    std::fs::rename(&temporary, path)?;
    std::fs::File::open(parent)?.sync_all()?;
    Ok(())
}

/// Same fence `lake_bronze_publish` applies to every staged object before it
/// is handed to the writer: tenant-partitioned tail prefix, content-addressed
/// name, no traversal, non-empty.
fn validate_staged_key(key: &str, table_key: &str, tenant_id: &str, file: &StagedOtelObject) -> Result<()> {
    let tenant_sha256 = hex::encode(Sha256::digest(tenant_id.as_bytes()));
    let required_prefix = format!("{table_key}/data/tail/tenant_sha256={tenant_sha256}/");
    let content_suffix = format!("-{}.parquet", file.sha256);
    if !key.starts_with(&required_prefix)
        || !key.ends_with(&content_suffix)
        || key.len() > 2_048
        || key.chars().any(char::is_control)
        || key.split('/').any(|part| part == "." || part == "..")
        || file.bytes.is_empty()
        || file.rows == 0
        || hex::encode(Sha256::digest(&file.bytes)) != file.sha256
    {
        bail!("staged OTLP tail object violates its assigned content boundary");
    }
    Ok(())
}

/// Enumerate the query mirror for one dataset: `(event_hour, path, bytes)`.
pub fn mirror_objects(mirror: &Path, dataset: OtelDataset) -> Result<Vec<(i32, PathBuf, u64)>> {
    let root = mirror.join(dataset.as_str());
    let mut objects = Vec::new();
    let Ok(hours) = std::fs::read_dir(&root) else {
        return Ok(objects);
    };
    for hour in hours {
        let hour = hour?;
        let name = hour.file_name();
        let Some(event_hour) = name
            .to_str()
            .and_then(|value| value.strip_prefix("event_hour="))
            .and_then(|value| value.parse::<i32>().ok())
        else {
            continue;
        };
        for file in std::fs::read_dir(hour.path())? {
            let file = file?;
            let path = file.path();
            if path.extension().and_then(|value| value.to_str()) != Some("parquet") {
                continue;
            }
            let bytes = file.metadata()?.len();
            if bytes == 0 {
                continue;
            }
            objects.push((event_hour, path, bytes));
        }
    }
    objects.sort();
    Ok(objects)
}

/// The query-side view of one dataset's mirror: a `SnapshotCache` whose
/// brace-glob names every mirrored staged object (paths keep their
/// `event_hour=` segment, so the planner's window pruning applies). `None`
/// when nothing has been drained yet — the service answers an empty dataset.
pub fn mirror_snapshot_cache(mirror: &Path, dataset: OtelDataset) -> Result<Option<crate::planner::SnapshotCache>> {
    let objects = mirror_objects(mirror, dataset)?;
    if objects.is_empty() {
        return Ok(None);
    }
    let root = mirror.join(dataset.as_str());
    let root_text = root
        .to_str()
        .context("OTLP mirror root is not UTF-8")?
        .to_string();
    let mut relatives = Vec::with_capacity(objects.len());
    let mut bytes = 0_u64;
    let mut cache_objects = BTreeMap::new();
    for (_, path, size) in &objects {
        let relative = path
            .strip_prefix(&root)
            .context("OTLP mirror object escaped its root")?
            .to_str()
            .context("OTLP mirror path is not UTF-8")?
            .to_string();
        if relative.chars().any(|character| character.is_control() || matches!(character, '{' | '}' | ',')) {
            bail!("OTLP mirror path violates the local-file contract");
        }
        bytes = bytes.checked_add(*size).context("OTLP mirror byte total overflowed")?;
        cache_objects.insert(
            path.to_string_lossy().into_owned(),
            crate::planner::SnapshotCacheObject {
                version_id: "mirror".to_string(),
                bytes: *size,
                path: path.clone(),
            },
        );
        relatives.push(relative);
    }
    relatives.sort();
    let source_spec = if relatives.len() == 1 {
        format!("{root_text}/{}", relatives[0])
    } else {
        format!("{root_text}/{{{}}}", relatives.join(","))
    };
    Ok(Some(crate::planner::SnapshotCache {
        source_spec,
        objects: cache_objects,
        bytes,
        read_schema: None,
        bootstrap: false,
    }))
}

/// PostgreSQL ledger for the `otel_publish` data-path principal.
pub struct PostgresOtelHandoffLedger {
    pool: sqlx::PgPool,
    binding: OtelDrainBinding,
}

impl PostgresOtelHandoffLedger {
    pub fn new(pool: sqlx::PgPool, binding: OtelDrainBinding) -> Result<Self> {
        binding.validate()?;
        Ok(Self { pool, binding })
    }
}

impl OtelHandoffLedger for PostgresOtelHandoffLedger {
    fn drained_keys<'a>(
        &'a self,
        _dataset: OtelDataset,
        candidates: &'a [String],
    ) -> Pin<Box<dyn Future<Output = Result<Vec<String>>> + Send + 'a>> {
        Box::pin(async move {
            let rows = sqlx::query_scalar::<_, String>(
                "SELECT object_key FROM lake_otel_handoff_batches \
                 WHERE tenant_id = $1 AND object_key = ANY($2)",
            )
            .bind(self.binding.tenant_uuid.to_string())
            .bind(candidates)
            .fetch_all(&self.pool)
            .await
            .context("read acknowledged OTLP handoff batches")?;
            Ok(rows)
        })
    }

    fn acknowledge<'a>(
        &'a self,
        acknowledgement: &'a DrainAcknowledgement,
    ) -> Pin<Box<dyn Future<Output = Result<()>> + Send + 'a>> {
        Box::pin(async move {
            let tenant = self.binding.tenant_uuid.to_string();
            let mut transaction = self.pool.begin().await?;
            for object in &acknowledgement.objects {
                let inserted = sqlx::query(
                    "INSERT INTO lake_hot_tail_objects \
                     (tenant_id, event_table, table_location_prefix, bronze_store_id, batch_sha256, \
                      event_hour, object_uri, version_id, object_etag, object_bytes, object_sha256, rows, \
                      min_time_ms, max_time_ms, deletion_unit_id, writer_authority_sha256) \
                     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16) \
                     ON CONFLICT (tenant_id, table_location_prefix, bronze_store_id, batch_sha256, event_hour) \
                     DO NOTHING",
                )
                .bind(&tenant)
                .bind(otel_event_table(object.dataset))
                .bind(&object.table_location_prefix)
                .bind(OTEL_HANDOFF_STORE_ID)
                .bind(&object.batch_sha256)
                .bind(object.event_hour)
                .bind(&object.object_uri)
                .bind(&object.version_id)
                .bind(&object.etag)
                .bind(i64::try_from(object.bytes)?)
                .bind(&object.sha256)
                .bind(i64::try_from(object.rows)?)
                .bind(object.min_time_ms)
                .bind(object.max_time_ms)
                .bind(object.deletion_unit_id)
                .bind(&object.writer_authority_sha256)
                .execute(&mut *transaction)
                .await
                .context("record staged OTLP tail object")?;
                if inserted.rows_affected() == 0 {
                    // The same content identity already landed (a retried
                    // cycle after a crash between publish and acknowledge);
                    // the replayed object must be byte-identical.
                    let existing = sqlx::query_scalar::<_, String>(
                        "SELECT object_sha256 FROM lake_hot_tail_objects WHERE tenant_id = $1 \
                         AND table_location_prefix = $2 AND bronze_store_id = $3 \
                         AND batch_sha256 = $4 AND event_hour = $5",
                    )
                    .bind(&tenant)
                    .bind(&object.table_location_prefix)
                    .bind(OTEL_HANDOFF_STORE_ID)
                    .bind(&object.batch_sha256)
                    .bind(object.event_hour)
                    .fetch_one(&mut *transaction)
                    .await?;
                    if existing != object.sha256 {
                        bail!("staged OTLP tail ledger conflicts with the exact retry identity");
                    }
                }
            }
            for batch in &acknowledgement.batches {
                let status = if batch.tail_batch_sha256.is_some() { "drained" } else { "rejected" };
                sqlx::query(
                    "INSERT INTO lake_otel_handoff_batches \
                     (tenant_id, dataset, object_key, object_sha256, object_bytes, object_etag, \
                      rows_decoded, rows_rejected, tail_batch_sha256, status, last_error) \
                     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11) \
                     ON CONFLICT (tenant_id, object_key) DO NOTHING",
                )
                .bind(&tenant)
                .bind(batch.dataset.as_str())
                .bind(&batch.object_key)
                .bind(&batch.object_sha256)
                .bind(i64::try_from(batch.object_bytes)?)
                .bind(&batch.object_etag)
                .bind(i32::try_from(batch.rows_decoded)?)
                .bind(i32::try_from(batch.rows_rejected)?)
                .bind(&batch.tail_batch_sha256)
                .bind(status)
                .bind(&batch.last_error)
                .execute(&mut *transaction)
                .await
                .context("acknowledge OTLP handoff batch")?;
            }
            if !acknowledgement.objects.is_empty() {
                crate::tail_ledger::bump_hot_tail_revision(
                    &mut transaction,
                    &tenant,
                    &self.binding.table_location_prefix(acknowledgement.dataset),
                )
                .await?;
            }
            let batches_drained = acknowledgement
                .batches
                .iter()
                .filter(|batch| batch.tail_batch_sha256.is_some())
                .count();
            let rows_drained = acknowledgement.objects.iter().map(|object| object.rows).sum::<u64>();
            sqlx::query("SELECT nano_shared.record_lake_otel_drain_heartbeat($1, $2, $3, $4, $5)")
                .bind(&self.binding.drain_identity)
                .bind(&self.binding.spans_location)
                .bind(&self.binding.metrics_location)
                .bind(i64::try_from(batches_drained)?)
                .bind(i64::try_from(rows_drained)?)
                .execute(&mut *transaction)
                .await
                .context("record OTLP drain heartbeat")?;
            transaction.commit().await?;
            Ok(())
        })
    }

    fn staged_objects<'a>(
        &'a self,
        dataset: OtelDataset,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<LedgerTailObject>>> + Send + 'a>> {
        Box::pin(async move {
            use sqlx::Row;
            // Every staged object of the table: the drain's own objects and
            // the packs that superseded them (wave 7).
            let rows = sqlx::query(
                "SELECT event_hour, object_uri, object_etag, object_bytes, object_sha256 \
                 FROM lake_hot_tail_objects WHERE tenant_id = $1 AND table_location_prefix = $2 \
                 AND status = 'staged' ORDER BY event_hour, object_uri",
            )
            .bind(self.binding.tenant_uuid.to_string())
            .bind(self.binding.table_location_prefix(dataset))
            .fetch_all(&self.pool)
            .await
            .context("list staged OTLP tail objects")?;
            rows.into_iter()
                .map(|row| {
                    Ok(LedgerTailObject {
                        event_hour: row.try_get("event_hour")?,
                        object_uri: row.try_get("object_uri")?,
                        etag: row
                            .try_get::<Option<String>, _>("object_etag")?
                            .context("staged OTLP tail ledger omitted its ETag")?,
                        bytes: u64::try_from(row.try_get::<i64, _>("object_bytes")?)?,
                        sha256: row.try_get("object_sha256")?,
                    })
                })
                .collect()
        })
    }

    fn heartbeat<'a>(&'a self) -> Pin<Box<dyn Future<Output = Result<()>> + Send + 'a>> {
        Box::pin(async move {
            sqlx::query("SELECT nano_shared.record_lake_otel_drain_heartbeat($1, $2, $3, 0, 0)")
                .bind(&self.binding.drain_identity)
                .bind(&self.binding.spans_location)
                .bind(&self.binding.metrics_location)
                .execute(&self.pool)
                .await
                .context("record OTLP drain heartbeat")?;
            Ok(())
        })
    }

    fn committed_pin<'a>(
        &'a self,
        dataset: OtelDataset,
    ) -> Pin<Box<dyn Future<Output = Result<Option<CommittedTablePin>>> + Send + 'a>> {
        Box::pin(async move {
            crate::tail_ledger::load_committed_table_pin(
                &self.pool,
                &self.binding.tenant_uuid.to_string(),
                &self.binding.table_location_prefix(dataset),
            )
            .await
            .context("read committed OTLP table pin")
        })
    }

    fn retention_days<'a>(&'a self) -> Pin<Box<dyn Future<Output = Result<Option<u32>>> + Send + 'a>> {
        Box::pin(async move {
            let days: Option<i32> = sqlx::query_scalar(
                "SELECT retention_days FROM nano_shared.read_lake_purge_policy()",
            )
            .fetch_optional(&self.pool)
            .await
            .context("read tenant retention window for the OTLP mirror")?;
            Ok(days.and_then(|days| u32::try_from(days).ok()).filter(|days| *days > 0))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::sync::Mutex;

    const TENANT: &str = "23610000-0000-4000-8000-000000000006";

    fn tenant() -> Uuid {
        Uuid::parse_str(TENANT).unwrap()
    }

    fn binding() -> OtelDrainBinding {
        OtelDrainBinding {
            tenant_uuid: tenant(),
            logical_tenant_key: "tenant6".into(),
            bucket: format!("nano-shared-r2-{TENANT}"),
            spans_location: format!("s3://nano-shared-r2-{TENANT}/__r2_data_catalog/t6/otel_spans"),
            metrics_location: format!("s3://nano-shared-r2-{TENANT}/__r2_data_catalog/t6/otel_metrics"),
            drain_identity: "nano-tenant-t6-lake-otel-ingest".into(),
            max_rows: 1_000,
            max_objects: 8,
            lookback_hours: 48,
        }
    }

    /// A fake R2 with strong ETags (the in-memory opendal service emits none).
    #[derive(Default)]
    struct FakeR2 {
        objects: Mutex<BTreeMap<String, Vec<u8>>>,
        /// Every `start_after` cursor the drain listed with.
        lists: Mutex<Vec<Option<String>>>,
        /// Keys returned by each list call (NAN-3359 page accounting).
        listed_keys: Mutex<Vec<usize>>,
        /// Keys whose HEAD fails (transport error) / whose exact read fails.
        fail_heads: Mutex<std::collections::BTreeSet<String>>,
        fail_reads: Mutex<std::collections::BTreeSet<String>>,
        /// Fetches currently in flight, and the most ever seen at once.
        in_flight: std::sync::atomic::AtomicUsize,
        max_in_flight: std::sync::atomic::AtomicUsize,
    }

    impl FakeR2 {
        fn etag_for(bytes: &[u8]) -> String {
            format!("\"{}\"", &hex::encode(Sha256::digest(bytes))[..32])
        }
        fn put(&self, key: &str, bytes: Vec<u8>) {
            self.objects.lock().unwrap().insert(key.to_string(), bytes);
        }
        /// Yield a key-dependent number of times so concurrent fetches
        /// complete out of submission order.
        async fn jitter(&self, key: &str) {
            use std::sync::atomic::Ordering;
            let now = self.in_flight.fetch_add(1, Ordering::SeqCst) + 1;
            self.max_in_flight.fetch_max(now, Ordering::SeqCst);
            for _ in 0..(Sha256::digest(key.as_bytes())[0] % 7) {
                tokio::task::yield_now().await;
            }
            self.in_flight.fetch_sub(1, Ordering::SeqCst);
        }
    }

    impl OtelHandoffSource for FakeR2 {
        fn list<'a>(
            &'a self,
            prefix: &'a str,
            start_after: Option<&'a str>,
            limit: usize,
        ) -> Pin<Box<dyn Future<Output = Result<Vec<String>>> + Send + 'a>> {
            Box::pin(async move {
                self.lists.lock().unwrap().push(start_after.map(str::to_string));
                let keys: Vec<String> = self
                    .objects
                    .lock()
                    .unwrap()
                    .keys()
                    .filter(|key| key.starts_with(prefix))
                    .filter(|key| start_after.is_none_or(|cursor| key.as_str() > cursor))
                    .take(limit)
                    .cloned()
                    .collect();
                self.listed_keys.lock().unwrap().push(keys.len());
                Ok(keys)
            })
        }
        fn head<'a>(&'a self, key: &'a str) -> Pin<Box<dyn Future<Output = Result<(u64, String)>> + Send + 'a>> {
            Box::pin(async move {
                self.jitter(key).await;
                if self.fail_heads.lock().unwrap().contains(key) {
                    bail!("HEAD transport failure");
                }
                let objects = self.objects.lock().unwrap();
                let bytes = objects.get(key).context("absent")?;
                Ok((bytes.len() as u64, Self::etag_for(bytes)))
            })
        }
        fn read_exact<'a>(
            &'a self,
            key: &'a str,
            expected_bytes: u64,
            expected_sha256: &'a str,
            expected_etag: &'a str,
        ) -> Pin<Box<dyn Future<Output = Result<Vec<u8>>> + Send + 'a>> {
            Box::pin(async move {
                self.jitter(key).await;
                if self.fail_reads.lock().unwrap().contains(key) {
                    bail!("exact read failure");
                }
                let objects = self.objects.lock().unwrap();
                let bytes = objects.get(key).context("absent")?;
                if bytes.len() as u64 != expected_bytes
                    || hex::encode(Sha256::digest(bytes)) != expected_sha256
                    || Self::etag_for(bytes) != expected_etag
                {
                    bail!("enterprise_shared R2 object failed its byte length or SHA-256 fence");
                }
                Ok(bytes.clone())
            })
        }
    }

    /// Fake owner writer: records every owner-authorized request and lands the
    /// bytes at the requested key in the same fake R2.
    struct FakeSink {
        store: Arc<FakeR2>,
        requests: Mutex<Vec<StagedTailPublication>>,
    }

    impl OtelHotTailSink for FakeSink {
        fn publish<'a>(
            &'a self,
            request: &'a StagedTailPublication,
            bytes: Vec<u8>,
        ) -> Pin<Box<dyn Future<Output = Result<PublishedOtelObject>> + Send + 'a>> {
            Box::pin(async move {
                assert_eq!(bytes.len() as u64, request.content_length);
                assert_eq!(hex::encode(Sha256::digest(&bytes)), request.content_sha256);
                request.validate().expect("staged hot-tail publication is exact");
                self.requests.lock().unwrap().push(request.clone());
                let etag = FakeR2::etag_for(&bytes);
                self.store.put(&request.object_key, bytes);
                Ok(PublishedOtelObject {
                    version_id: "v1".into(),
                    etag,
                    deletion_unit_id: Uuid::now_v7(),
                    writer_authority_sha256: "a".repeat(64),
                })
            })
        }
    }

    #[derive(Default)]
    struct MemoryLedger {
        acknowledged: Mutex<Vec<DrainAcknowledgement>>,
        heartbeats: Mutex<usize>,
        /// Object URIs the packer/compactor moved out of `staged` (wave 7).
        not_staged: Mutex<std::collections::BTreeSet<String>>,
        pin: Mutex<Option<CommittedTablePin>>,
        retention_days: Mutex<Option<u32>>,
    }

    impl OtelHandoffLedger for MemoryLedger {
        fn drained_keys<'a>(
            &'a self,
            _dataset: OtelDataset,
            candidates: &'a [String],
        ) -> Pin<Box<dyn Future<Output = Result<Vec<String>>> + Send + 'a>> {
            Box::pin(async move {
                let acknowledged = self.acknowledged.lock().unwrap();
                Ok(candidates
                    .iter()
                    .filter(|key| {
                        acknowledged
                            .iter()
                            .any(|ack| ack.batches.iter().any(|batch| &batch.object_key == *key))
                    })
                    .cloned()
                    .collect())
            })
        }
        fn acknowledge<'a>(
            &'a self,
            acknowledgement: &'a DrainAcknowledgement,
        ) -> Pin<Box<dyn Future<Output = Result<()>> + Send + 'a>> {
            Box::pin(async move {
                self.acknowledged.lock().unwrap().push(acknowledgement.clone());
                Ok(())
            })
        }
        fn staged_objects<'a>(
            &'a self,
            dataset: OtelDataset,
        ) -> Pin<Box<dyn Future<Output = Result<Vec<LedgerTailObject>>> + Send + 'a>> {
            Box::pin(async move {
                Ok(self
                    .acknowledged
                    .lock()
                    .unwrap()
                    .iter()
                    .flat_map(|ack| ack.objects.iter())
                    .filter(|object| object.dataset == dataset)
                    .filter(|object| !self.not_staged.lock().unwrap().contains(&object.object_uri))
                    .map(|object| LedgerTailObject {
                        event_hour: object.event_hour,
                        object_uri: object.object_uri.clone(),
                        etag: object.etag.clone(),
                        bytes: object.bytes,
                        sha256: object.sha256.clone(),
                    })
                    .collect())
            })
        }
        fn heartbeat<'a>(&'a self) -> Pin<Box<dyn Future<Output = Result<()>> + Send + 'a>> {
            Box::pin(async move {
                *self.heartbeats.lock().unwrap() += 1;
                Ok(())
            })
        }
        fn committed_pin<'a>(
            &'a self,
            _dataset: OtelDataset,
        ) -> Pin<Box<dyn Future<Output = Result<Option<CommittedTablePin>>> + Send + 'a>> {
            Box::pin(async move { Ok(self.pin.lock().unwrap().clone()) })
        }
        fn retention_days<'a>(&'a self) -> Pin<Box<dyn Future<Output = Result<Option<u32>>> + Send + 'a>> {
            Box::pin(async move { Ok(*self.retention_days.lock().unwrap()) })
        }
    }

    fn span_envelope(trace: &str, span: &str, start_nanos: u64) -> serde_json::Value {
        json!({
            "schema_version": "nano-otlp-lake-v1",
            "dataset": "spans",
            "source_type": "otlp_trace",
            "ingest_time_unix_nano": start_nanos + 5_000,
            "event": {
                "traceId": trace,
                "spanId": span,
                "startTimeUnixNano": start_nanos.to_string(),
                "endTimeUnixNano": (start_nanos + 1_000_000).to_string(),
                "name": "GET /health",
                "kind": 2,
                "attributes": [{"key": "http.route", "value": {"stringValue": "/health"}}],
                "resource": {"attributes": [{"key": "service.name", "value": {"stringValue": "api"}}]}
            }
        })
    }

    fn ndjson(rows: &[serde_json::Value]) -> Vec<u8> {
        let mut out = Vec::new();
        for row in rows {
            serde_json::to_writer(&mut out, row).unwrap();
            out.push(b'\n');
        }
        out
    }

    async fn land_handoff(store: &FakeR2, dataset: OtelDataset, body: Vec<u8>) -> String {
        let sha = hex::encode(Sha256::digest(&body));
        let key = handoff_object_key(tenant(), dataset, Utc::now(), &sha).unwrap();
        store.put(&key, body);
        key
    }

    fn harness(mirror: Option<PathBuf>) -> (OtelHandoffDrain, Arc<FakeR2>, Arc<FakeSink>, Arc<MemoryLedger>) {
        let store = Arc::new(FakeR2::default());
        let sink = Arc::new(FakeSink {
            store: store.clone(),
            requests: Mutex::new(Vec::new()),
        });
        let ledger = Arc::new(MemoryLedger::default());
        let drain = OtelHandoffDrain::new(binding(), store.clone(), sink.clone(), ledger.clone(), mirror).unwrap();
        (drain, store, sink, ledger)
    }

    #[test]
    fn handoff_keys_round_trip_and_reject_foreign_shapes() {
        let at = DateTime::parse_from_rfc3339("2026-09-17T03:00:00Z").unwrap().with_timezone(&Utc);
        let key = handoff_object_key(tenant(), OtelDataset::Metrics, at, &"b".repeat(64)).unwrap();
        assert_eq!(
            key,
            format!("otel-handoff-v1/tenant_uuid={TENANT}/dataset=metrics/hour=2026091703/{}.ndjson", "b".repeat(64))
        );
        let parsed = parse_handoff_key(&key, tenant()).unwrap();
        assert_eq!(parsed.dataset, OtelDataset::Metrics);
        assert_eq!(parsed.receipt_hour, "2026091703");
        assert!(parse_handoff_key(&key, Uuid::now_v7()).is_err(), "foreign tenant");
        assert!(parse_handoff_key(&key.replace("metrics", "logs"), tenant()).is_err());
        assert!(parse_handoff_key(&key.replace(".ndjson", ".parquet"), tenant()).is_err());
        assert!(parse_handoff_key(&key.replace("hour=2026091703", "hour=../x"), tenant()).is_err());
        assert!(handoff_object_key(tenant(), OtelDataset::Spans, at, "B").is_err());
    }

    #[test]
    fn drain_binding_is_exact() {
        assert!(binding().validate().is_ok());
        let mut foreign = binding();
        foreign.bucket = "nano-shared-r2-other".into();
        assert!(foreign.validate().is_err());
        let mut escaped = binding();
        escaped.spans_location = format!("s3://nano-shared-r2-{TENANT}/../x");
        assert!(escaped.validate().is_err());
        let mut same = binding();
        same.metrics_location = same.spans_location.clone();
        assert!(same.validate().is_err());
        assert_eq!(
            binding().table_location_prefix(OtelDataset::Spans),
            format!("s3://nano-shared-r2-{TENANT}/__r2_data_catalog/t6/otel_spans/")
        );
    }

    #[tokio::test]
    async fn handoff_objects_drain_into_staged_hot_tail_objects_and_are_acknowledged_once() {
        let mirror = tempfile::tempdir().unwrap();
        let (drain, store, sink, ledger) = harness(Some(mirror.path().to_path_buf()));
        let hour_a = 1_789_600_000_000_000_000_u64; // 2026-09-16T19:06:40Z
        let hour_b = hour_a + 3_600_000_000_000; // next hour
        let first = land_handoff(&store, OtelDataset::Spans, ndjson(&[
            span_envelope(&"1".repeat(32), &"a".repeat(16), hour_a),
            span_envelope(&"1".repeat(32), &"b".repeat(16), hour_a + 10),
        ])).await;
        let second = land_handoff(&store, OtelDataset::Spans, ndjson(&[
            span_envelope(&"2".repeat(32), &"c".repeat(16), hour_b),
            // Retried sink delivery: identical span identity as the first object.
            span_envelope(&"1".repeat(32), &"a".repeat(16), hour_a),
        ])).await;
        // A metrics object under the other dataset prefix is not touched.
        land_handoff(&store, OtelDataset::Metrics, b"{}".to_vec()).await;

        let report = drain.drain_once(OtelDataset::Spans).await.unwrap();
        assert_eq!(report.objects_seen, 2);
        assert_eq!(report.objects_drained, 2);
        assert_eq!(report.objects_rejected, 0);
        assert_eq!(report.rows_published, 3, "duplicate identity collapsed");
        assert_eq!(report.tail_objects_published, 2, "one staged object per event hour");

        let requests = sink.requests.lock().unwrap();
        assert_eq!(requests.len(), 2);
        let tenant_sha = hex::encode(Sha256::digest(TENANT.as_bytes()));
        for request in requests.iter() {
            assert_eq!(request.object_bucket, format!("nano-shared-r2-{TENANT}"));
            assert!(request.object_key.starts_with(&format!(
                "__r2_data_catalog/t6/otel_spans/data/tail/tenant_sha256={tenant_sha}/event_hour="
            )), "{}", request.object_key);
            assert!(request.object_key.ends_with(".parquet"));
            assert_eq!(request.tenant_id, "tenant6");
        }
        drop(requests);

        let acknowledged = ledger.acknowledged.lock().unwrap();
        assert_eq!(acknowledged.len(), 1);
        let ack = &acknowledged[0];
        assert_eq!(ack.objects.len(), 2);
        assert_eq!(ack.batches.len(), 2);
        assert!(ack.batches.iter().all(|batch| batch.tail_batch_sha256.is_some()));
        assert!(ack.batches.iter().any(|batch| batch.object_key == first));
        assert!(ack.batches.iter().any(|batch| batch.object_key == second));
        assert_eq!(ack.objects.iter().map(|object| object.rows).sum::<u64>(), 3);
        for object in &ack.objects {
            assert!(object.object_uri.starts_with(&format!("s3://nano-shared-r2-{TENANT}/__r2_data_catalog/t6/otel_spans/data/tail/")));
            assert_eq!(object.table_location_prefix, binding().table_location_prefix(OtelDataset::Spans));
            let hour_floor = i64::from(object.event_hour) * 3_600_000;
            assert!(object.min_time_ms >= hour_floor && object.max_time_ms < hour_floor + 3_600_000);
        }
        drop(acknowledged);

        // The mirror holds exactly the published objects, under event_hour= segments.
        let mirrored = mirror_objects(mirror.path(), OtelDataset::Spans).unwrap();
        assert_eq!(mirrored.len(), 2);
        assert!(mirrored.iter().all(|(_, path, _)| path.to_str().unwrap().contains("event_hour=")));
        let cache = mirror_snapshot_cache(mirror.path(), OtelDataset::Spans).unwrap().unwrap();
        assert_eq!(cache.objects.len(), 2);
        assert!(cache.source_spec.starts_with(mirror.path().join("spans").to_str().unwrap()));
        assert!(cache.source_spec.contains("{event_hour="), "{}", cache.source_spec);
        assert_eq!(cache.bytes, mirrored.iter().map(|(_, _, bytes)| bytes).sum::<u64>());
        assert!(mirror_snapshot_cache(mirror.path(), OtelDataset::Metrics).unwrap().is_none());

        // A second cycle is idle: both handoff objects are acknowledged.
        let report = drain.drain_once(OtelDataset::Spans).await.unwrap();
        assert_eq!(report.objects_seen, 2);
        assert_eq!(report.objects_drained, 0);
        assert_eq!(ledger.acknowledged.lock().unwrap().len(), 1);
        assert_eq!(*ledger.heartbeats.lock().unwrap(), 1);
    }

    #[tokio::test]
    async fn malformed_handoff_objects_are_acknowledged_as_rejected_not_retried_forever() {
        let (drain, store, sink, ledger) = harness(None);
        let bad = land_handoff(&store, OtelDataset::Metrics, b"not json\n".to_vec()).await;
        // Well-formed envelope, row that fails normalization (no name/time).
        let empty_row = land_handoff(&store, OtelDataset::Metrics, ndjson(&[json!({
            "schema_version": "nano-otlp-lake-v1", "dataset": "metrics", "event": {}
        })])).await;
        // A row that tries to select its tenant is refused at decode.
        let tenant_selecting = land_handoff(&store, OtelDataset::Metrics, ndjson(&[json!({
            "schema_version": "nano-otlp-lake-v1", "dataset": "metrics", "tenant_uid": "x", "event": {}
        })])).await;
        let report = drain.drain_once(OtelDataset::Metrics).await.unwrap();
        assert_eq!(report.objects_seen, 3);
        assert_eq!(report.objects_rejected, 3);
        assert_eq!(report.objects_drained, 0);
        assert!(sink.requests.lock().unwrap().is_empty(), "nothing published");
        let acknowledged = ledger.acknowledged.lock().unwrap();
        assert_eq!(acknowledged.len(), 1);
        assert!(acknowledged[0].objects.is_empty());
        let batches = &acknowledged[0].batches;
        assert_eq!(batches.len(), 3);
        for key in [&bad, &empty_row, &tenant_selecting] {
            let batch = batches.iter().find(|batch| &batch.object_key == key).unwrap();
            assert!(batch.tail_batch_sha256.is_none());
            assert!(batch.last_error.is_some());
            assert_eq!(batch.rows_decoded, 0);
        }
        drop(acknowledged);
        let report = drain.drain_once(OtelDataset::Metrics).await.unwrap();
        assert_eq!(report.objects_rejected, 0, "rejected objects are not re-examined");
    }

    #[tokio::test]
    async fn mirror_hydrates_from_the_ledger_with_exact_reads() {
        let first_mirror = tempfile::tempdir().unwrap();
        let (drain, store, sink, ledger) = harness(Some(first_mirror.path().to_path_buf()));
        let start = 1_789_600_000_000_000_000_u64;
        land_handoff(&store, OtelDataset::Spans, ndjson(&[span_envelope(&"3".repeat(32), &"d".repeat(16), start)])).await;
        drain.drain_once(OtelDataset::Spans).await.unwrap();
        assert_eq!(sink.requests.lock().unwrap().len(), 1);

        // A fresh process with an empty mirror re-hydrates from the ledger.
        let second_mirror = tempfile::tempdir().unwrap();
        let restarted = OtelHandoffDrain::new(binding(), store.clone(), sink.clone(), ledger.clone(), Some(second_mirror.path().to_path_buf())).unwrap();
        assert_eq!(restarted.hydrate_mirror(OtelDataset::Spans).await.unwrap(), 1);
        assert_eq!(restarted.hydrate_mirror(OtelDataset::Spans).await.unwrap(), 0, "already present");
        let mirrored = mirror_objects(second_mirror.path(), OtelDataset::Spans).unwrap();
        assert_eq!(mirrored.len(), 1);
        let original = mirror_objects(first_mirror.path(), OtelDataset::Spans).unwrap();
        assert_eq!(std::fs::read(&mirrored[0].1).unwrap(), std::fs::read(&original[0].1).unwrap());

        // A tampered R2 object fails the exact read and is not mirrored.
        let ack = ledger.acknowledged.lock().unwrap()[0].objects[0].clone();
        let key = ack.object_uri.strip_prefix(&format!("s3://nano-shared-r2-{TENANT}/")).unwrap().to_string();
        store.put(&key, b"tampered".to_vec());
        let third_mirror = tempfile::tempdir().unwrap();
        let tampered = OtelHandoffDrain::new(binding(), store.clone(), sink, ledger, Some(third_mirror.path().to_path_buf())).unwrap();
        assert!(tampered.hydrate_mirror(OtelDataset::Spans).await.is_err());
        assert!(mirror_objects(third_mirror.path(), OtelDataset::Spans).unwrap().is_empty());
    }

    #[tokio::test]
    async fn listing_uses_a_lookback_cursor_after_the_first_full_scan_and_still_progresses_past_acknowledged_objects() {
        let (drain, store, _sink, ledger) = harness(None);
        let prefix = handoff_prefix(tenant(), OtelDataset::Spans);
        let cursor = OtelHandoffDrain::lookback_cursor(&prefix, Utc::now(), 48);
        assert!(cursor.starts_with(&format!("{prefix}hour=")));
        // Many already-acknowledged objects under old receipt hours, more than
        // any per-cycle object bound: the drain must still reach a new one.
        for index in 0..40 {
            let body = format!("old-{index}\n").into_bytes();
            let sha = hex::encode(Sha256::digest(&body));
            let key = format!("{prefix}hour=2026010100/{sha}.ndjson");
            store.put(&key, body);
            ledger.acknowledged.lock().unwrap().push(DrainAcknowledgement {
                dataset: OtelDataset::Spans,
                objects: Vec::new(),
                batches: vec![DrainedHandoffBatch {
                    dataset: OtelDataset::Spans,
                    object_key: key,
                    object_sha256: sha,
                    object_bytes: 6,
                    object_etag: "\"e\"".into(),
                    rows_decoded: 0,
                    rows_rejected: 0,
                    tail_batch_sha256: None,
                    last_error: Some("old".into()),
                }],
            });
        }
        let start = 1_789_600_000_000_000_000_u64;
        let now_hour = i32::try_from(Utc::now().timestamp().div_euclid(3_600)).unwrap();
        let fresh = land_handoff(&store, OtelDataset::Spans, ndjson(&[span_envelope(&"5".repeat(32), &"a".repeat(16), start)])).await;
        // Cycle 1: full scan (no cursor), sees all 41, drains the fresh one.
        let report = drain.drain_once(OtelDataset::Spans).await.unwrap();
        assert_eq!(report.objects_seen, 41);
        assert_eq!(report.objects_drained, 1);
        assert!(ledger.acknowledged.lock().unwrap().iter().any(|ack| ack.batches.iter().any(|batch| batch.object_key == fresh)));
        // Cycle 2: a normal cycle; the 40 old objects are not even listed.
        // NAN-3359: nothing is pending, so it starts at the previous receipt
        // hour (the watermark), later than the 48 h lookback cursor.
        let report = drain.drain_once(OtelDataset::Spans).await.unwrap();
        assert_eq!(report.objects_seen, 1);
        assert_eq!(report.objects_drained, 0);
        let lists = store.lists.lock().unwrap();
        assert_eq!(lists[0], None, "first cycle is a full scan");
        let watermark = OtelHandoffDrain::floor_cursor(&prefix, now_hour - 1).unwrap();
        assert_eq!(lists[1].as_deref(), Some(watermark.as_str()));
        assert!(watermark > cursor, "never earlier than the lookback");
    }

    // ---- NAN-3359: normal cycles list only undrained receipt hours ------

    #[test]
    fn the_normal_cycle_start_hour_is_the_latest_of_lookback_floor_and_watermark() {
        let now = 500_000;
        // No watermark yet: the 48 h lookback, exactly as before.
        assert_eq!(normal_cycle_start_hour(now, 48, None, None), now - 48);
        // Idle watermark: previous + current hour only.
        assert_eq!(normal_cycle_start_hour(now, 48, None, Some(now - 1)), now - 1);
        // A watermark older than the lookback never widens the listing.
        assert_eq!(normal_cycle_start_hour(now, 48, None, Some(now - 500)), now - 48);
        // The lean mirror floor binds when it is later than the lookback.
        assert_eq!(normal_cycle_start_hour(now, 48, Some(now - 24), None), now - 24);
        assert_eq!(normal_cycle_start_hour(now, 48, Some(now - 24), Some(now - 30)), now - 24);
        assert_eq!(normal_cycle_start_hour(now, 48, Some(now - 720), Some(now - 5)), now - 5);
        // floor_cursor(start) is the old lookback cursor for the same hour.
        let prefix = handoff_prefix(tenant(), OtelDataset::Spans);
        let at = Utc::now();
        let hour = i32::try_from(at.timestamp().div_euclid(3_600)).unwrap();
        assert_eq!(
            OtelHandoffDrain::floor_cursor(&prefix, normal_cycle_start_hour(hour, 48, None, None)).unwrap(),
            OtelHandoffDrain::lookback_cursor(&prefix, at, 48)
        );
    }

    #[test]
    fn the_watermark_advances_only_on_a_complete_cycle() {
        let now = 500_000;
        let complete = |retry| CycleCoverage::Complete { oldest_retry_hour: retry };
        let incomplete = |hour| CycleCoverage::Incomplete { oldest_unproven_hour: hour };
        // Idle: previous hour (late Worker writers) and the current hour.
        assert_eq!(next_watermark_hour(None, now, complete(None)), Some(now - 1));
        assert_eq!(next_watermark_hour(Some(now - 30), now, complete(None)), Some(now - 1));
        // A retry in H-5 holds the watermark at H-5.
        assert_eq!(next_watermark_hour(Some(now - 1), now, complete(Some(now - 5))), Some(now - 5));
        // A retry in the current hour never lifts it above H-1.
        assert_eq!(next_watermark_hour(None, now, complete(Some(now))), Some(now - 1));
        // Backlogged: never advances, may only move older.
        assert_eq!(next_watermark_hour(Some(now - 5), now, incomplete(Some(now))), Some(now - 5));
        assert_eq!(next_watermark_hour(Some(now - 5), now, incomplete(Some(now - 9))), Some(now - 9));
        assert_eq!(next_watermark_hour(Some(now - 5), now, incomplete(None)), Some(now - 5));
        // No watermark yet: a backlogged cycle keeps the full lookback.
        assert_eq!(next_watermark_hour(None, now, incomplete(Some(now))), None);
    }

    #[test]
    fn the_full_scan_cadence_is_unchanged_by_the_watermark() {
        let mut state = ScanState::default();
        let mut full = Vec::new();
        for cycle in 0..(FULL_SCAN_EVERY_CYCLES * 3) {
            let (full_scan, _) = state.begin();
            if full_scan {
                full.push(cycle);
            }
            state.finish(full_scan, false, Some(1));
        }
        assert_eq!(full, vec![0, FULL_SCAN_EVERY_CYCLES, FULL_SCAN_EVERY_CYCLES * 2]);
        // An owed (backlogged) full scan still runs as soon as the recent
        // backlog clears, whatever the watermark.
        let mut state = ScanState::default();
        assert!(state.begin().0);
        state.finish(true, true, None);
        assert!(!state.begin().0, "recent backlog: cheap normal cycle first");
        state.finish(false, false, Some(7));
        assert_eq!(state.begin(), (true, Some(7)));
    }

    #[tokio::test]
    async fn a_pending_hour_holds_the_cursor_until_drained_and_a_backlog_never_advances_it() {
        let (drain, store, _sink, ledger) = harness(None);
        let prefix = handoff_prefix(tenant(), OtelDataset::Spans);
        let now = Utc::now();
        let hour = epoch_hour(now);
        let cursor_at = |h: i32| Some(OtelHandoffDrain::floor_cursor(&prefix, h).unwrap());
        let stuck = land_at(&store, now - chrono::Duration::hours(5), "stuck", 1);
        land_at(&store, now, "live", 1);
        store.fail_reads.lock().unwrap().insert(stuck.clone());

        // Cycle 1 (full scan): drains the live object, the H-5 read fails.
        let first = drain.drain_once(OtelDataset::Spans).await.unwrap();
        assert_eq!((first.full_scan, first.objects_drained, first.backlogged), (true, 1, false));
        // Cycle 2: listed from H-5 (not from H-48, not from H-1).
        let second = drain.drain_once(OtelDataset::Spans).await.unwrap();
        assert_eq!((second.objects_seen, second.objects_drained), (2, 0));
        assert_eq!(store.lists.lock().unwrap()[1], cursor_at(hour - 5));

        // The read recovers while a burst larger than max_objects (8) lands
        // in the live hour: the backlogged cycles keep the H-5 cursor.
        store.fail_reads.lock().unwrap().clear();
        for index in 0..20 {
            land_at(&store, now, &format!("burst-{index}"), 1);
        }
        let mut trace = Vec::new();
        loop {
            let report = drain.drain_once(OtelDataset::Spans).await.unwrap();
            trace.push((report.full_scan, report.objects_drained, report.backlogged));
            if !report.backlogged {
                break;
            }
            assert!(trace.len() < 10, "{trace:?}");
        }
        assert_eq!(trace, vec![(false, 8, true), (false, 8, true), (false, 5, false)]);
        assert!(acknowledged_keys(&ledger).contains(&stuck), "the straggler drained last (oldest hour)");
        let lists = store.lists.lock().unwrap().clone();
        assert_eq!(&lists[2..5], &[cursor_at(hour - 5), cursor_at(hour - 5), cursor_at(hour - 5)]);
        // Everything drained: back to the previous + current hour.
        drain.drain_once(OtelDataset::Spans).await.unwrap();
        assert_eq!(store.lists.lock().unwrap()[5], cursor_at(hour - 1));
    }

    /// Page accounting with the production shape scaled 10x down: 20 receipt
    /// hours x 240 acknowledged keys, 100 keys per list page (production:
    /// 2,400 spans objects/h, 1,000 keys per R2 ListObjects page).
    #[tokio::test]
    async fn an_idle_normal_cycle_lists_two_hours_instead_of_the_whole_window() {
        const KEYS_PER_HOUR: usize = 240;
        const PAGE: usize = 100;
        let (drain, store, _sink, ledger) = harness(None);
        let prefix = handoff_prefix(tenant(), OtelDataset::Spans);
        let now = Utc::now();
        let mut batches = Vec::new();
        for age in 0..20 {
            let receipt = (now - chrono::Duration::hours(age)).format("%Y%m%d%H");
            for index in 0..KEYS_PER_HOUR {
                let body = format!("{age}-{index}\n").into_bytes();
                let sha = hex::encode(Sha256::digest(&body));
                let key = format!("{prefix}hour={receipt}/{sha}.ndjson");
                store.put(&key, body);
                batches.push(DrainedHandoffBatch {
                    dataset: OtelDataset::Spans,
                    object_key: key,
                    object_sha256: sha,
                    object_bytes: 1,
                    object_etag: "\"e\"".into(),
                    rows_decoded: 0,
                    rows_rejected: 0,
                    tail_batch_sha256: None,
                    last_error: None,
                });
            }
        }
        ledger.acknowledged.lock().unwrap().push(DrainAcknowledgement {
            dataset: OtelDataset::Spans,
            objects: Vec::new(),
            batches,
        });
        for _ in 0..3 {
            drain.drain_once(OtelDataset::Spans).await.unwrap();
        }
        let pages = store
            .listed_keys
            .lock()
            .unwrap()
            .iter()
            .map(|keys| keys.div_ceil(PAGE).max(1))
            .collect::<Vec<_>>();
        // Cycle 1 is the full scan (same as before: 4,800 keys, 48 pages).
        // Before NAN-3359 every normal cycle re-listed the window too (48
        // pages); now an idle cycle lists only H-1 and H (480 keys, 5 pages).
        assert_eq!(pages, vec![48, 5, 5]);
        assert_eq!(store.listed_keys.lock().unwrap()[1..], [2 * KEYS_PER_HOUR, 2 * KEYS_PER_HOUR]);
    }

    /// NAN-2361 wave 7: the mirror follows the ledger — an object the packer
    /// superseded or the compactor committed is pruned on hydration, an
    /// object outside the retention window is never fetched, and the
    /// committed-table pin is cached for the query side.
    #[tokio::test]
    async fn mirror_prunes_unstaged_objects_bounds_to_retention_and_caches_the_pin() {
        let mirror = tempfile::tempdir().unwrap();
        let (drain, store, sink, ledger) = harness(Some(mirror.path().to_path_buf()));
        let now_nanos = u64::try_from(Utc::now().timestamp_nanos_opt().unwrap()).unwrap();
        let old_nanos = now_nanos - 40 * 24 * 3_600 * 1_000_000_000;
        land_handoff(&store, OtelDataset::Spans, ndjson(&[span_envelope(&"4".repeat(32), &"e".repeat(16), now_nanos)])).await;
        land_handoff(&store, OtelDataset::Spans, ndjson(&[span_envelope(&"5".repeat(32), &"f".repeat(16), old_nanos)])).await;
        drain.drain_once(OtelDataset::Spans).await.unwrap();
        assert_eq!(mirror_objects(mirror.path(), OtelDataset::Spans).unwrap().len(), 2, "two event hours staged");

        // The compactor committed the old hour and pinned the table.
        let objects = ledger.acknowledged.lock().unwrap().iter().flat_map(|ack| ack.objects.clone()).collect::<Vec<_>>();
        let old = objects.iter().min_by_key(|object| object.event_hour).unwrap().clone();
        ledger.not_staged.lock().unwrap().insert(old.object_uri.clone());
        let pin = CommittedTablePin {
            table_uuid: Uuid::new_v4(),
            metadata_location: format!("{}metadata/00001-x.metadata.json", binding().table_location_prefix(OtelDataset::Spans)),
            snapshot_id: 7,
        };
        *ledger.pin.lock().unwrap() = Some(pin.clone());
        assert_eq!(drain.committed_pin(OtelDataset::Spans), None, "pin is read on hydration/drain, not on construction");
        assert_eq!(drain.hydrate_mirror(OtelDataset::Spans).await.unwrap(), 0);
        let remaining = mirror_objects(mirror.path(), OtelDataset::Spans).unwrap();
        assert_eq!(remaining.len(), 1, "the committed object left the mirror");
        assert_eq!(remaining[0].0, objects.iter().max_by_key(|object| object.event_hour).unwrap().event_hour);
        assert_eq!(drain.committed_pin(OtelDataset::Spans), Some(pin));

        // A fresh mirror with a 30-day retention window never fetches a
        // 40-day-old staged object, even if the ledger still listed it.
        ledger.not_staged.lock().unwrap().clear();
        *ledger.retention_days.lock().unwrap() = Some(30);
        let fresh = tempfile::tempdir().unwrap();
        let restarted = OtelHandoffDrain::new(binding(), store.clone(), sink.clone(), ledger.clone(), Some(fresh.path().to_path_buf())).unwrap();
        assert_eq!(restarted.hydrate_mirror(OtelDataset::Spans).await.unwrap(), 1);
        assert_eq!(mirror_objects(fresh.path(), OtelDataset::Spans).unwrap().len(), 1);

        // A pin outside the table location is refused (fail closed).
        *ledger.pin.lock().unwrap() = Some(CommittedTablePin {
            table_uuid: Uuid::new_v4(),
            metadata_location: format!("s3://nano-shared-r2-{TENANT}/elsewhere/metadata/v1.json"),
            snapshot_id: 8,
        });
        assert!(restarted.hydrate_mirror(OtelDataset::Spans).await.is_err());
    }

    /// NAN-2361 wave 7 (review P1): once the compactor commits an object and
    /// pins the table, the very next DRAIN CYCLE prunes it from the mirror —
    /// not only a restart — so the committed table and the mirror never both
    /// serve the same rows.
    #[tokio::test]
    async fn drain_cycle_prunes_committed_objects_before_publishing_the_pin() {
        let mirror = tempfile::tempdir().unwrap();
        let (drain, store, _sink, ledger) = harness(Some(mirror.path().to_path_buf()));
        land_handoff(&store, OtelDataset::Spans, ndjson(&[span_envelope(&"9".repeat(32), &"b".repeat(16), 1_789_600_000_000_000_000)])).await;
        drain.drain_once(OtelDataset::Spans).await.unwrap();
        assert_eq!(mirror_objects(mirror.path(), OtelDataset::Spans).unwrap().len(), 1);
        let object = ledger.acknowledged.lock().unwrap()[0].objects[0].clone();
        ledger.not_staged.lock().unwrap().insert(object.object_uri.clone());
        *ledger.pin.lock().unwrap() = Some(CommittedTablePin {
            table_uuid: Uuid::new_v4(),
            metadata_location: format!("{}metadata/00002-y.metadata.json", binding().table_location_prefix(OtelDataset::Spans)),
            snapshot_id: 9,
        });
        // Nothing new to drain; the cycle still reconciles.
        drain.drain_once(OtelDataset::Spans).await.unwrap();
        assert!(mirror_objects(mirror.path(), OtelDataset::Spans).unwrap().is_empty());
        assert_eq!(drain.committed_pin(OtelDataset::Spans).map(|p| p.snapshot_id), Some(9));
    }

    /// NAN-2361 wave 7: the byte cap evicts the oldest event hours first and
    /// never the hour the drain just wrote.
    #[tokio::test]
    async fn mirror_cap_evicts_oldest_hours_and_protects_the_hour_just_written() {
        let mirror = tempfile::tempdir().unwrap();
        let store = Arc::new(FakeR2::default());
        let sink = Arc::new(FakeSink { store: store.clone(), requests: Mutex::new(Vec::new()) });
        let ledger = Arc::new(MemoryLedger::default());
        let policy = MirrorPolicy { max_bytes: 64 * 1024 * 1024, max_age_hours: 24 * 30 };
        let drain = OtelHandoffDrain::with_mirror_policy(binding(), store.clone(), sink.clone(), ledger.clone(), Some(mirror.path().to_path_buf()), policy).unwrap();
        assert!(MirrorPolicy { max_bytes: 1, max_age_hours: 1 }.validate().is_err());
        let base = 1_789_600_000_000_000_000_u64;
        let hour = 3_600_000_000_000_u64;
        for (index, trace) in ["6", "7", "8"].iter().enumerate() {
            land_handoff(&store, OtelDataset::Spans, ndjson(&[span_envelope(&trace.repeat(32), &"a".repeat(16), base + index as u64 * hour)])).await;
        }
        drain.drain_once(OtelDataset::Spans).await.unwrap();
        let objects = mirror_objects(mirror.path(), OtelDataset::Spans).unwrap();
        assert_eq!(objects.len(), 3);
        let newest_hour = objects.iter().map(|o| o.0).max().unwrap();
        let total = objects.iter().map(|o| o.2).sum::<u64>();
        let oldest_bytes = objects.iter().min_by_key(|o| o.0).unwrap().2;
        // Cap that fits everything but the oldest hour: exactly that hour goes.
        let evicted = enforce_mirror_cap(mirror.path(), total - oldest_bytes, Some((OtelDataset::Spans, newest_hour))).unwrap();
        assert_eq!(evicted, 1);
        let left = mirror_objects(mirror.path(), OtelDataset::Spans).unwrap();
        assert_eq!(left.iter().map(|o| o.0).min().unwrap(), objects[1].0);
        // A cap smaller than the protected newest hour keeps that hour and warns.
        enforce_mirror_cap(mirror.path(), 1, Some((OtelDataset::Spans, newest_hour))).unwrap();
        let left = mirror_objects(mirror.path(), OtelDataset::Spans).unwrap();
        assert_eq!(left.len(), 1);
        assert_eq!(left[0].0, newest_hour);
        assert_eq!(drain.mirror_policy(), policy);
    }

    #[test]
    fn staged_objects_carry_the_native_otel_schema_and_one_hour_each() {
        let tenant = tenant();
        let start = 1_789_600_000_000_000_000_u64;
        let rows = [
            span_envelope(&"4".repeat(32), &"e".repeat(16), start),
            span_envelope(&"4".repeat(32), &"f".repeat(16), start + 3_600_000_000_000),
        ]
        .iter()
        .map(|value| normalize_otel_row(OtelDataset::Spans, &tenant.to_string(), value).unwrap())
        .collect::<Vec<_>>();
        let staged = encode_staged_otel_objects(OtelDataset::Spans, tenant, &rows, &"c".repeat(64)).unwrap();
        assert_eq!(staged.len(), 2);
        for file in &staged {
            let reader = parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder::try_new(
                bytes::Bytes::from(file.bytes.clone()),
            )
            .unwrap();
            let schema = reader.schema().clone();
            assert!(schema.column_with_name("tenant_uid").is_some());
            assert!(schema.column_with_name("start_time").is_some());
            assert!(schema.column_with_name("raw_otlp_json").is_some());
            assert_eq!(schema.fields().len(), otel_arrow_schema(OtelDataset::Spans).fields().len());
            assert!(file.relative_path.contains(&format!("event_hour={}", file.event_hour)));
        }
        assert!(encode_staged_otel_objects(OtelDataset::Metrics, tenant, &rows, &"c".repeat(64)).is_err(), "dataset mismatch");
    }

    // ---- NAN-3290: catch-up after an empty-mirror restart ----------------

    /// Land one spans handoff object received at `at` holding `rows` spans
    /// that start inside that receipt hour.
    fn land_at(store: &FakeR2, at: DateTime<Utc>, tag: &str, rows: u64) -> String {
        let hour_start = u64::try_from(at.timestamp().div_euclid(3_600) * 3_600).unwrap();
        let base = hour_start * 1_000_000_000 + 1_000;
        let trace = &hex::encode(Sha256::digest(tag.as_bytes()))[..32];
        let body = ndjson(
            &(0..rows)
                .map(|row| span_envelope(trace, &format!("{row:016x}"), base + row * 1_000))
                .collect::<Vec<_>>(),
        );
        let key = handoff_object_key(tenant(), OtelDataset::Spans, at, &hex::encode(Sha256::digest(&body))).unwrap();
        store.put(&key, body);
        key
    }

    fn epoch_hour(at: DateTime<Utc>) -> i32 {
        i32::try_from(at.timestamp().div_euclid(3_600)).unwrap()
    }

    fn acknowledged_keys(ledger: &MemoryLedger) -> Vec<String> {
        ledger
            .acknowledged
            .lock()
            .unwrap()
            .iter()
            .flat_map(|ack| ack.batches.iter().map(|batch| batch.object_key.clone()))
            .collect()
    }

    #[tokio::test]
    async fn an_empty_mirror_backlog_serves_the_newest_receipt_hour_first_then_backfills() {
        let mirror = tempfile::tempdir().unwrap();
        let (drain, store, _sink, ledger) = harness(Some(mirror.path().to_path_buf()));
        let now = Utc::now();
        // 4 receipt hours x 5 objects = 20 > max_objects (8).
        let mut by_hour = BTreeMap::<i32, Vec<String>>::new();
        for age in 0..4 {
            let at = now - chrono::Duration::hours(age);
            for index in 0..5 {
                by_hour
                    .entry(epoch_hour(at))
                    .or_default()
                    .push(land_at(&store, at, &format!("{age}-{index}"), 2));
            }
        }
        let newest = *by_hour.keys().next_back().unwrap();
        let oldest = *by_hour.keys().next().unwrap();

        let first = drain.drain_once(OtelDataset::Spans).await.unwrap();
        assert_eq!((first.objects_seen, first.objects_drained), (20, 8));
        assert!(first.full_scan && first.backlogged, "{first:?}");
        let resident = mirror_objects(mirror.path(), OtelDataset::Spans)
            .unwrap()
            .into_iter()
            .map(|(hour, _, _)| hour)
            .collect::<std::collections::BTreeSet<_>>();
        assert!(resident.contains(&newest), "the live hour is served after the first cycle");
        assert!(!resident.contains(&oldest), "the oldest hour waits for the backfill");
        let drained = acknowledged_keys(&ledger);
        assert!(by_hour[&newest].iter().all(|key| drained.contains(key)));

        // Catch-up: backlogged cycles run back to back until the backlog is gone.
        let mut cycles = 1;
        loop {
            let report = drain.drain_once(OtelDataset::Spans).await.unwrap();
            cycles += 1;
            if !report.backlogged && report.objects_drained == 0 {
                break;
            }
            assert!(cycles < 10, "catch-up did not converge");
        }
        let mut drained = acknowledged_keys(&ledger);
        drained.sort();
        let mut expected = by_hour.values().flatten().cloned().collect::<Vec<_>>();
        expected.sort();
        assert_eq!(drained, expected, "every object drained exactly once");
        let resident = mirror_objects(mirror.path(), OtelDataset::Spans)
            .unwrap()
            .into_iter()
            .map(|(hour, _, _)| hour)
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(resident, by_hour.keys().copied().collect());
    }

    #[tokio::test]
    async fn a_backlogged_full_scan_keeps_scanning_past_the_lookback_until_the_backlog_is_gone() {
        let (drain, store, _sink, ledger) = harness(None);
        let now = Utc::now();
        let mut old = Vec::new();
        for index in 0..10 {
            old.push(land_at(&store, now - chrono::Duration::hours(72), &format!("old-{index}"), 1));
            land_at(&store, now, &format!("new-{index}"), 1);
        }
        let mut trace = Vec::new();
        for _ in 0..6 {
            let report = drain.drain_once(OtelDataset::Spans).await.unwrap();
            trace.push((report.full_scan, report.objects_drained, report.backlogged));
        }
        assert_eq!(
            trace,
            vec![
                (true, 8, true),   // full scan, newest first
                (false, 2, false), // lookback finishes the live hours
                (true, 8, true),   // owed full scan backfills past the lookback
                (false, 0, false),
                (true, 2, false),  // backlog gone: full scans stop
                (false, 0, false),
            ]
        );
        let drained = acknowledged_keys(&ledger);
        assert_eq!(drained.len(), 20);
        assert!(old.iter().all(|key| drained.contains(key)));
        // Every dataset gets its own first full scan (a shared counter gave
        // every full scan to whichever dataset drained first).
        assert!(drain.drain_once(OtelDataset::Metrics).await.unwrap().full_scan);
    }

    fn small_binding(max_rows: usize) -> OtelDrainBinding {
        OtelDrainBinding { max_rows, ..binding() }
    }

    async fn drain_until_idle(
        store: Arc<FakeR2>,
        concurrency: usize,
    ) -> (Vec<DrainCycleReport>, Vec<serde_json::Value>, Vec<(i32, std::ffi::OsString)>) {
        let mirror = tempfile::tempdir().unwrap();
        let sink = Arc::new(FakeSink { store: store.clone(), requests: Mutex::new(Vec::new()) });
        let ledger = Arc::new(MemoryLedger::default());
        let drain = OtelHandoffDrain::new(small_binding(10), store, sink, ledger.clone(), Some(mirror.path().to_path_buf()))
            .unwrap()
            .with_fetch_concurrency(concurrency)
            .unwrap();
        let mut reports = Vec::new();
        for _ in 0..20 {
            let report = drain.drain_once(OtelDataset::Spans).await.unwrap();
            let idle = !report.backlogged && report.objects_drained == 0 && report.objects_rejected == 0;
            reports.push(report);
            if idle {
                break;
            }
        }
        let acks = ledger
            .acknowledged
            .lock()
            .unwrap()
            .iter()
            .map(|ack| {
                serde_json::json!({
                    "batches": ack.batches,
                    "objects": ack.objects.iter().map(|object| serde_json::json!([
                        object.event_hour, object.object_uri, object.sha256, object.rows, object.batch_sha256,
                    ])).collect::<Vec<_>>(),
                })
            })
            .collect();
        let files = mirror_objects(mirror.path(), OtelDataset::Spans)
            .unwrap()
            .into_iter()
            .map(|(hour, path, _)| (hour, path.file_name().unwrap().to_owned()))
            .collect();
        (reports, acks, files)
    }

    #[tokio::test]
    async fn concurrent_fetch_acknowledges_and_publishes_exactly_what_a_serial_drain_does() {
        use std::sync::atomic::Ordering;
        let store = Arc::new(FakeR2::default());
        let now = Utc::now();
        let mut keys = Vec::new();
        for age in 0..3 {
            for index in 0..6 {
                keys.push(land_at(&store, now - chrono::Duration::hours(age), &format!("{age}-{index}"), 3));
            }
        }
        // A malformed object, a row that fails normalization, and an object
        // whose exact read keeps failing (left pending every cycle).
        for body in [b"not json\n".to_vec(), ndjson(&[json!({"schema_version": "nano-otlp-lake-v1", "dataset": "spans", "event": {}})])] {
            let key = handoff_object_key(tenant(), OtelDataset::Spans, now - chrono::Duration::hours(1), &hex::encode(Sha256::digest(&body))).unwrap();
            store.put(&key, body);
        }
        store.fail_reads.lock().unwrap().insert(keys[3].clone());

        let serial = drain_until_idle(store.clone(), 1).await;
        assert_eq!(store.max_in_flight.swap(0, Ordering::SeqCst), 1, "serial drain");
        let concurrent = drain_until_idle(store.clone(), 16).await;
        assert!(store.max_in_flight.load(Ordering::SeqCst) > 1, "fetches overlapped");

        assert_eq!(serial.0, concurrent.0, "cycle reports");
        assert_eq!(serial.1, concurrent.1, "ledger acknowledgements, in order");
        assert_eq!(serial.2, concurrent.2, "mirrored objects");
        // max_rows (10) cut the cycles at 4 three-row objects, so several
        // cycles ran; every object but the unreadable one was acknowledged.
        assert!(serial.0.len() > 3, "{:?}", serial.0);
        let acknowledged = serial.1.iter().map(|ack| ack["batches"].as_array().unwrap().len()).sum::<usize>();
        assert_eq!(acknowledged, keys.len() + 2 - 1);
        assert_eq!(serial.0.iter().map(|report| report.rows_published).sum::<u64>(), 3 * (keys.len() as u64 - 1));
    }

    #[tokio::test]
    async fn a_failed_head_fails_the_cycle_only_when_the_fold_reaches_it() {
        let store = Arc::new(FakeR2::default());
        let sink = Arc::new(FakeSink { store: store.clone(), requests: Mutex::new(Vec::new()) });
        let ledger = Arc::new(MemoryLedger::default());
        let drain = OtelHandoffDrain::new(small_binding(10), store.clone(), sink, ledger.clone(), None).unwrap();
        let now = Utc::now();
        for index in 0..6 {
            land_at(&store, now, &format!("live-{index}"), 3);
        }
        // Past the max_rows cut-off (oldest hour sorts last): fetched, never folded.
        let unreachable = land_at(&store, now - chrono::Duration::hours(2), "old", 3);
        store.fail_heads.lock().unwrap().insert(unreachable);
        let report = drain.drain_once(OtelDataset::Spans).await.unwrap();
        assert_eq!((report.objects_drained, report.backlogged), (4, true));
        // Reached by the fold: the whole cycle fails and nothing is acknowledged.
        let reachable = land_at(&store, now, "live-failing", 3);
        store.fail_heads.lock().unwrap().insert(reachable);
        assert!(drain.drain_once(OtelDataset::Spans).await.is_err());
        assert_eq!(ledger.acknowledged.lock().unwrap().len(), 1);
    }

    #[test]
    fn the_pacer_runs_backlogged_datasets_back_to_back_without_starving_the_other() {
        let interval = std::time::Duration::from_secs(10);
        let start = std::time::Instant::now();
        let mut pacer = DrainPacer::new(interval, start);
        assert!(pacer.due(OtelDataset::Spans, start) && pacer.due(OtelDataset::Metrics, start));
        pacer.record(OtelDataset::Spans, start, true);
        pacer.record(OtelDataset::Metrics, start, false);
        assert!(pacer.catching_up());
        assert_eq!(pacer.pause(start), std::time::Duration::ZERO);
        assert!(pacer.due(OtelDataset::Spans, start), "backlogged: immediately due");
        assert!(!pacer.due(OtelDataset::Metrics, start), "idle: waits its interval");
        assert!(pacer.due(OtelDataset::Metrics, start + interval), "still drained on its interval");
        pacer.record(OtelDataset::Spans, start, false);
        assert_eq!(pacer.pause(start), interval);
        assert_eq!(pacer.pause(start + interval * 2), std::time::Duration::ZERO);
    }
}
