// SPDX-License-Identifier: AGPL-3.0-or-later

//! Tenant-private, durable ingest-time prevalence. The signed part log remains
//! the publication authority; each committed partial advances this state once.
//!
//! The state is one SlateDB DB per tenant at
//! `lake/prevalence-state/v1/tenant=<uuid>/db/`. SlateDB is already durable on
//! object storage, and opening it bumps the manifest writer epoch and writes a
//! fencing WAL, so a stale writer (an old cell after a move) fails its next
//! write. The replay cursor lives in the DB itself, written atomically with
//! the rows it covers. See docs-internal/NAN-2915-lean-prevalence-realtime.md,
//! "Restore design".
//!
//! Each entity's value is a rolling 30-day window (NAN-3160): per-day
//! occurrences plus every retained host fingerprint with the latest UTC day
//! it was seen. Ingest stamps |hosts seen in the 30 UTC days ending with the
//! watermark's day| from one point read; days before that are dropped on the
//! next merge. See [`WindowState`].

use anyhow::{ensure, Context, Result};
use futures::{stream, StreamExt};
use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use slatedb::config::{
    CompressionCodec, FlushOptions, FlushType, GarbageCollectorOptions, ObjectStoreCacheOptions, PutOptions, Settings, Ttl,
    ReadOptions, WriteOptions,
};
use slatedb::db_cache::foyer::{FoyerCache, FoyerCacheOptions};
use slatedb::db_cache::{DbCache, SplitCache};
#[cfg(test)]
use slatedb::object_store::memory::InMemory;
use slatedb::object_store::{
    aws::AmazonS3Builder, local::LocalFileSystem, prefix::PrefixStore, ObjectStore,
};
use slatedb::{Db, WriteBatch};
use std::collections::BTreeMap;
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use super::partials::{PartialRow, PrevalenceRow};
use super::prevalence_owner_store::{OwnerStore, PrevalenceAccess};
use crate::parts::part_log::PartRef;
use crate::parts::sidecar::PREVALENCE_HOST_CAP;
use crate::parts::DAY_US;
use crate::prevalence_stamp::{
    column_artifacts, new_artifact_entry, observed_entry, stampable_artifacts,
};

const INACTIVE_TTL_US: i64 = 30 * DAY_US;
const NA: u64 = 65_535;
const COMMON: u64 = 9_999;
const SCHEMA_KEY: &[u8] = b"\0nano:prevalence:schema";
const WATERMARK_KEY: &[u8] = b"\0nano:prevalence:watermark";
const APPLIED_KEY: &[u8] = b"\0nano:prevalence:applied";
/// The rebuild's part list, fixed when it starts: a restart resumes the same
/// list at the cursor even though the log head has moved on.
const REBUILD_PARTS_KEY: &[u8] = b"\0nano:prevalence:rebuild-parts";
/// NAN-3781: present while the state is being emptied for a rebuild from the
/// live set ([`IngestPrevalence::begin_reset`]). Written first and deleted
/// last, so a crash mid-reset resumes the reset on the next open instead of
/// rebuilding on top of half-deleted counts.
const RESET_KEY: &[u8] = b"\0nano:prevalence:reset";
/// Keys tombstoned per durable reset write.
const RESET_CHUNK_KEYS: usize = 8_192;
const CHUNK_ROWS: usize = 8_192;
/// A part's `max_time` comes from untrusted event times. One far-future row
/// must not push the persisted watermark ahead and expire every entity, so
/// the watermark never runs more than this ahead of the wall clock.
const MAX_FUTURE_SKEW_US: i64 = DAY_US;
/// Concurrent SlateDB point reads per admission batch when stamping.
const STAMP_READS: usize = 256;
/// Keep main's request granularity for every SST read, including dense
/// restamps, catch-up, reset scans and compaction. Recent windows live in
/// a separate bounded cache inside the existing data-cache memory budget.
const OBJECT_CACHE_PART_BYTES: usize = 4 * 1024 * 1024;
/// NAN-4592: the smallest local disk cache a remote prevalence state gets (and
/// what every state got before: a fixed 256 MiB).
pub const OBJECT_CACHE_FLOOR_BYTES: u64 = 256 * 1024 * 1024;
/// NAN-4592: disk cache per byte of the state's SSTs measured at open: the
/// state plus room for its growth and for the parts of SSTs that
/// `maintenance[T]` compacts away until the evictor drops them.
pub const OBJECT_CACHE_STATE_FACTOR: u64 = 2;

/// NAN-4592: the local disk (object) cache for a remote state whose SSTs
/// measured `state_bytes` at open (`None`: not measured), within the tenant's
/// `cap_bytes`.
///
/// The large tenant (hosted, 2026-10-26 12:15-13:46Z): with the fixed 256 MiB cache
/// against a ~3 GiB state, point reads for random keys missed the disk
/// almost always. A miss fetches the whole 4 MiB part holding the block, so
/// 91 min of stamps cost ~44k R2 GETs / 87 GB on the stamp path (filters
/// and indexes) plus ~49k GETs / ~200 GB of data blocks (counted as
/// "maintenance": SlateDB fetches blocks on spawned tasks that lose the
/// read-path scope), and 28% of admission batches overran the 5 s wait. A
/// cache the size of the state fetches each part once per SST.
pub fn object_cache_bytes(state_bytes: Option<u64>, cap_bytes: u64) -> u64 {
    let wanted = state_bytes
        .map_or(OBJECT_CACHE_FLOOR_BYTES, |bytes| bytes.saturating_mul(OBJECT_CACHE_STATE_FACTOR))
        .max(OBJECT_CACHE_FLOOR_BYTES);
    // A cap below the floor (tests) wins; production caps start at the floor.
    wanted.min(cap_bytes)
}

/// NAN-4592: bytes of the state's compacted SSTs (one LIST of this tenant's
/// own `db/compacted/`; SSTs compacted away but not yet collected count too).
async fn measure_state_bytes(store: &Arc<dyn ObjectStore>) -> Result<u64> {
    let prefix = slatedb::object_store::path::Path::from("db/compacted");
    let mut listing = store.list(Some(&prefix));
    let mut bytes = 0_u64;
    while let Some(meta) = listing.next().await {
        bytes = bytes.saturating_add(meta?.size);
    }
    Ok(bytes)
}

/// Only remove our cache below real directories in the tenant-private work
/// root. `remove_dir_all` does not follow the cache itself or nested symlinks,
/// but would follow a symlink in a parent. IngestService holds its appender
/// lock throughout open/close; nothing concurrently renames these parents.
fn remove_stale_local_cache(work_dir: &Path, tenant_id: &str) -> Result<()> {
    let prevalence = work_dir.join("prevalence");
    let tenant = prevalence.join(tenant_id);
    for parent in [&prevalence, &tenant] {
        ensure!(std::fs::symlink_metadata(parent)?.is_dir(),
            "refusing prevalence cache cleanup through a non-directory or symlink: {}", parent.display());
    }
    std::fs::remove_dir_all(tenant.join("object-cache"))?;
    Ok(())
}
/// Nominal analytical budget; production adapts between 16 and 128 lanes.
#[cfg(test)]
const RESTAMP_READS: usize = 64;
/// NAN-3879: concurrent SlateDB point reads per apply chunk / catch-up
/// batch. In production (2026-10-15): cold prior reads go to R2 (~0.1 s each), so at
/// 64 a flush of ~11k rows (~3.5k keys) read for ~5.5 s and overran the
/// 5 s ingest wait 96% of the time (2% at ~5k rows). Reads are independent
/// gets of one snapshot; 256 makes the same flush ~1.4 s cold.
pub(crate) const APPLY_READS: usize = 256;
const STAMP_COLUMNS: [&str; 5] = [
    "prevalence_file_hash",
    "prevalence_process_hash",
    "prevalence_dest_domain",
    "prevalence_dest_ip",
    "prevalence_min",
];

fn watermark_ceiling_us() -> i64 {
    chrono::Utc::now().timestamp_micros().saturating_add(MAX_FUTURE_SKEW_US)
}

fn is_our_stamp(entry: &Value) -> bool {
    entry.get("name") == Some(&json!("prevalence")) && entry.get("provider") == Some(&json!("nano"))
}

/// Ingest without prevalence state: drop any `prevalence_*` column value and
/// nano prevalence enrichment the source supplied, so a forged value never
/// reaches the signed part as if nano had stamped it. Search reads the
/// missing columns as N/A.
/// The five scalar stamp values of `event`, in [`STAMP_COLUMNS`] order, with
/// `value_of` giving an artifact's host-count scalar. One definition for the
/// ingest stamp and the NAN-3864 restamp, so the two never drift.
pub(super) fn stamp_scalars(event: &serde_json::Map<String, Value>, value_of: impl Fn(&str) -> u64) -> [u64; 5] {
    let mut columns = BTreeMap::<&str, u64>::new();
    for (column, artifact) in column_artifacts(event) {
        let value = value_of(&artifact);
        columns.entry(column).and_modify(|n| *n = (*n).min(value)).or_insert(value);
    }
    let mut out = [NA; 5];
    for (slot, column) in out.iter_mut().zip(&STAMP_COLUMNS[..4]) {
        *slot = columns.get(column).copied().unwrap_or(NA);
    }
    out[4] = columns.values().copied().min().unwrap_or(COMMON);
    out
}

/// The scalar stamp columns, `prevalence_min` last.
pub(super) fn stamp_columns() -> &'static [&'static str; 5] {
    &STAMP_COLUMNS
}

pub(super) fn strip_stamps(event: &mut Value) {
    let Some(object) = event.as_object_mut() else { return };
    for column in STAMP_COLUMNS {
        object.remove(column);
    }
    if let Some(entries) = object.get_mut("enrichments").and_then(Value::as_array_mut) {
        entries.retain(|entry| !is_our_stamp(entry));
    }
}

pub(super) fn key(kind: &str, artifact: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(kind.len() + artifact.len() + 2);
    out.push(b'e');
    out.extend_from_slice(kind.as_bytes());
    out.push(0);
    out.extend_from_slice(artifact.as_bytes());
    out
}

fn validate_row(row: &PrevalenceRow) -> Result<()> {
    ensure!(row.hosts.len() <= PREVALENCE_HOST_CAP
        && row.hosts.windows(2).all(|pair| pair[0] < pair[1]),
        "prevalence partial host set is not bounded and sorted unique");
    ensure!(row.key.0.len().saturating_add(row.key.2.len()).saturating_add(2) <= u16::MAX as usize,
        "prevalence key exceeds SlateDB limit");
    Ok(())
}

fn digest_file(path: &Path) -> Result<String> {
    let mut file = File::open(path)?;
    let mut hash = Sha256::new();
    let mut chunk = [0_u8; 64 * 1024];
    loop {
        let size = file.read(&mut chunk)?;
        if size == 0 { break; }
        hash.update(&chunk[..size]);
    }
    Ok(hex::encode(hash.finalize()))
}

/// A partial written before the 1,000-host format (no `host_cap`, or the old
/// 65 cap). Its truncated host sets cannot be counted exactly.
fn is_legacy_partial(path: &Path) -> Result<bool> {
    let builder = ParquetRecordBatchReaderBuilder::try_new(File::open(path)?)?;
    if builder.schema().field_with_name("host_cap").is_err() {
        return Ok(true);
    }
    let Some(batch) = builder.with_batch_size(1).with_limit(1).build()?.next().transpose()? else {
        return Ok(false);
    };
    let cap = batch
        .column_by_name("host_cap")
        .and_then(|column| column.as_any().downcast_ref::<arrow_array::UInt16Array>())
        .context("prevalence partial host_cap type")?;
    Ok(cap.len() == 1 && cap.value(0) as usize != PREVALENCE_HOST_CAP)
}

/// The rolling window: the 30 UTC days ending with the watermark's day. A
/// host seen only before them is no longer counted. Bounds every value.
const WINDOW_DAYS: usize = (INACTIVE_TTL_US / DAY_US) as usize;
/// v1: one cumulative host set per entity (no days; pre NAN-3160).
const VALUE_V1: u8 = 1;
/// v2: per-entity day -> occurrences and fingerprint -> latest day seen.
const VALUE_V2: u8 = 2;
const V2_HEADER: usize = 1 + 8 + 8 + 2;

/// The first UTC day of the window ending at `watermark_us`. It is never
/// below the day of `watermark - 30 days`, so the exact inactive-entity
/// gate (`last_seen > watermark - 30 days`) stays the outer bound.
fn floor_day(watermark_us: i64) -> i32 {
    day_of(watermark_us).saturating_sub(WINDOW_DAYS as i32 - 1)
}

fn day_of(time_us: i64) -> i32 {
    i32::try_from(time_us.div_euclid(DAY_US)).unwrap_or(if time_us < 0 { i32::MIN } else { i32::MAX })
}

/// One entity's rolling 30-day prevalence state (NAN-3160).
///
/// `hosts` keeps each host fingerprint with the latest UTC day it was seen,
/// so the window's host set is a filter on day; there is no cumulative set
/// that never sheds a host. The 1,000-host cap is a bottom-k sketch (the
/// smallest fingerprints): a host is kept only while fewer than 1,000 kept
/// hosts with a smaller fingerprint were seen on its day or later. That
/// retains the exact bottom-1,000 for every cutoff inside the window, so a
/// count below 1,000 is exact and saturation is reported exactly when the
/// window holds 1,000 or more hosts. Bounded by `WINDOW_DAYS` x 1,000 hosts.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(super) struct WindowState {
    pub first_seen: i64,
    pub last_seen: i64,
    /// Ascending unique day -> occurrences that day.
    pub days: Vec<(i32, u64)>,
    /// Ascending unique fingerprint -> latest day seen.
    pub hosts: Vec<(u64, i32)>,
}

impl WindowState {
    /// One partial row, its day clamped to the watermark day: a far-future
    /// event time cannot add days beyond the window.
    fn from_row(row: &PrevalenceRow, top_day: i32) -> Self {
        let day = row.key.3.min(top_day);
        Self {
            first_seen: row.first_seen,
            last_seen: row.last_seen,
            days: vec![(day, row.daily_count)],
            hosts: row.hosts.iter().map(|host| (*host, day)).collect(),
        }
    }

    /// A pre-NAN-3160 value has no days: its hosts are placed on the day of
    /// its `last_seen`, the latest any of them can have been seen. They then
    /// age out of the window like any other day (never undercounting).
    fn from_v1(row: PrevalenceRow) -> Self {
        let day = day_of(row.last_seen);
        Self {
            first_seen: row.first_seen,
            last_seen: row.last_seen,
            days: vec![(day, row.daily_count)],
            hosts: row.hosts.into_iter().map(|host| (host, day)).collect(),
        }
    }

    fn absorb(&mut self, other: &Self) {
        self.first_seen = self.first_seen.min(other.first_seen);
        self.last_seen = self.last_seen.max(other.last_seen);
        let mut days = Vec::with_capacity(self.days.len() + other.days.len());
        let (mut i, mut j) = (0, 0);
        while i < self.days.len() || j < other.days.len() {
            match (self.days.get(i), other.days.get(j)) {
                (Some(a), Some(b)) if a.0 == b.0 => {
                    days.push((a.0, a.1.saturating_add(b.1)));
                    i += 1;
                    j += 1;
                }
                (Some(a), Some(b)) if a.0 < b.0 => { days.push(*a); i += 1; }
                (Some(_), Some(b)) => { days.push(*b); j += 1; }
                (Some(a), None) => { days.push(*a); i += 1; }
                (None, Some(b)) => { days.push(*b); j += 1; }
                (None, None) => unreachable!(),
            }
        }
        self.days = days;
        let mut hosts = Vec::with_capacity(self.hosts.len() + other.hosts.len());
        let (mut i, mut j) = (0, 0);
        while i < self.hosts.len() || j < other.hosts.len() {
            match (self.hosts.get(i), other.hosts.get(j)) {
                (Some(a), Some(b)) if a.0 == b.0 => {
                    hosts.push((a.0, a.1.max(b.1)));
                    i += 1;
                    j += 1;
                }
                (Some(a), Some(b)) if a.0 < b.0 => { hosts.push(*a); i += 1; }
                (Some(_), Some(b)) => { hosts.push(*b); j += 1; }
                (Some(a), None) => { hosts.push(*a); i += 1; }
                (None, Some(b)) => { hosts.push(*b); j += 1; }
                (None, None) => unreachable!(),
            }
        }
        self.hosts = hosts;
    }

    /// Drop days before `floor` and apply the per-cutoff bottom-k bound.
    /// Days above `top` are clamped to it.
    fn prune(&mut self, floor: i32, top: i32) {
        let top = top.max(floor);
        let mut days = Vec::<(i32, u64)>::with_capacity(self.days.len());
        for &(day, count) in &self.days {
            if day < floor {
                continue;
            }
            let day = day.min(top);
            match days.last_mut() {
                Some(last) if last.0 == day => last.1 = last.1.saturating_add(count),
                _ => days.push((day, count)),
            }
        }
        self.days = days;
        let span = usize::try_from(i64::from(top) - i64::from(floor) + 1).unwrap_or(1).min(WINDOW_DAYS);
        // kept[i]: kept hosts so far (smaller fingerprints) whose day is
        // `top - i`; a host's dominators are those on its day or later.
        let mut kept = vec![0_usize; span];
        self.hosts.retain_mut(|(_, day)| {
            if *day < floor {
                return false;
            }
            *day = (*day).min(top);
            let index = usize::try_from(i64::from(top) - i64::from(*day)).unwrap_or(0).min(span - 1);
            let dominated: usize = kept[..=index].iter().sum();
            if dominated >= PREVALENCE_HOST_CAP {
                return false;
            }
            kept[index] += 1;
            true
        });
    }

    /// The window ending at the watermark whose first day is `floor`, in
    /// the stamp's row shape: the bottom-1,000 hosts seen on `floor` or
    /// later and the occurrences on those days.
    fn window(&self, kind: &str, artifact: &str, floor: i32) -> PrevalenceRow {
        let hosts = self
            .hosts
            .iter()
            .filter(|(_, day)| *day >= floor)
            .map(|(host, _)| *host)
            .take(PREVALENCE_HOST_CAP)
            .collect();
        let daily_count = self
            .days
            .iter()
            .filter(|(day, _)| *day >= floor)
            .fold(0_u64, |sum, (_, count)| sum.saturating_add(*count));
        PrevalenceRow {
            key: (kind.into(), String::new(), artifact.into(), 0),
            hosts,
            is_private: 0,
            first_seen: self.first_seen,
            last_seen: self.last_seen,
            daily_count,
        }
    }
}

pub(super) fn encode(state: &WindowState) -> Vec<u8> {
    let mut out = Vec::with_capacity(V2_HEADER + state.days.len() * 12 + 4 + state.hosts.len() * 12);
    out.push(VALUE_V2);
    out.extend_from_slice(&state.first_seen.to_le_bytes());
    out.extend_from_slice(&state.last_seen.to_le_bytes());
    out.extend_from_slice(&(state.days.len() as u16).to_le_bytes());
    for (day, count) in &state.days {
        out.extend_from_slice(&day.to_le_bytes());
        out.extend_from_slice(&count.to_le_bytes());
    }
    out.extend_from_slice(&(state.hosts.len() as u32).to_le_bytes());
    for (host, day) in &state.hosts {
        out.extend_from_slice(&host.to_le_bytes());
        out.extend_from_slice(&day.to_le_bytes());
    }
    out
}

/// Decode a v2 value, or a v1 value written before NAN-3160 (read as its
/// hosts all seen on its last day; rewritten as v2 the next time the entity
/// is merged). No rebuild and no stamping gap on upgrade.
pub(super) fn decode(bytes: &[u8]) -> Result<WindowState> {
    match bytes.first() {
        Some(&VALUE_V1) => decode_v1(bytes).map(WindowState::from_v1),
        Some(&VALUE_V2) => decode_v2(bytes),
        _ => anyhow::bail!("invalid prevalence value version"),
    }
}

fn decode_v2(bytes: &[u8]) -> Result<WindowState> {
    ensure!(bytes.len() >= V2_HEADER, "invalid prevalence value");
    let day_count = u16::from_le_bytes(bytes[17..19].try_into()?) as usize;
    ensure!(day_count <= WINDOW_DAYS, "prevalence value has too many days");
    let hosts_at = V2_HEADER + day_count * 12;
    ensure!(bytes.len() >= hosts_at + 4, "invalid prevalence value");
    let host_count = u32::from_le_bytes(bytes[hosts_at..hosts_at + 4].try_into()?) as usize;
    ensure!(
        host_count <= WINDOW_DAYS * PREVALENCE_HOST_CAP && bytes.len() == hosts_at + 4 + host_count * 12,
        "invalid prevalence host set"
    );
    let days: Vec<(i32, u64)> = bytes[V2_HEADER..hosts_at]
        .chunks_exact(12)
        .map(|v| (i32::from_le_bytes(v[..4].try_into().expect("four bytes")), u64::from_le_bytes(v[4..].try_into().expect("eight bytes"))))
        .collect();
    let hosts: Vec<(u64, i32)> = bytes[hosts_at + 4..]
        .chunks_exact(12)
        .map(|v| (u64::from_le_bytes(v[..8].try_into().expect("eight bytes")), i32::from_le_bytes(v[8..].try_into().expect("four bytes"))))
        .collect();
    ensure!(days.windows(2).all(|pair| pair[0].0 < pair[1].0), "prevalence days are not sorted unique");
    ensure!(hosts.windows(2).all(|pair| pair[0].0 < pair[1].0), "prevalence host set is not sorted unique");
    Ok(WindowState {
        first_seen: i64::from_le_bytes(bytes[1..9].try_into()?),
        last_seen: i64::from_le_bytes(bytes[9..17].try_into()?),
        days,
        hosts,
    })
}

/// The pre-NAN-3160 format: 27 bytes plus 8 per host.
fn decode_v1(bytes: &[u8]) -> Result<PrevalenceRow> {
    ensure!(
        bytes.len() >= 27 && bytes[0] == VALUE_V1,
        "invalid prevalence value version"
    );
    let count = u16::from_le_bytes(bytes[25..27].try_into()?) as usize;
    ensure!(
        count <= PREVALENCE_HOST_CAP && bytes.len() == 27 + count * 8,
        "invalid prevalence host set"
    );
    let hosts: Vec<u64> = bytes[27..]
        .chunks_exact(8)
        .map(|v| u64::from_le_bytes(v.try_into().expect("eight bytes")))
        .collect();
    ensure!(hosts.windows(2).all(|pair| pair[0] < pair[1]), "prevalence host set is not sorted unique");
    Ok(PrevalenceRow {
        key: (String::new(), String::new(), String::new(), 0),
        hosts,
        is_private: 0,
        first_seen: i64::from_le_bytes(bytes[1..9].try_into()?),
        last_seen: i64::from_le_bytes(bytes[9..17].try_into()?),
        daily_count: u64::from_le_bytes(bytes[17..25].try_into()?),
    })
}

/// WALs an open of the DB under `store` would replay: the newest WAL id
/// minus the manifest's `replay_after_wal_id` (NAN-3554 tests).
#[cfg(test)]
pub(crate) async fn wal_replay_backlog(store: Arc<dyn ObjectStore>) -> u64 {
    use futures::StreamExt;
    fn find(value: &serde_json::Value) -> Option<u64> {
        match value {
            serde_json::Value::Object(map) => map.get("replay_after_wal_id").and_then(|v| v.as_u64())
                .or_else(|| map.values().find_map(find)),
            serde_json::Value::Array(items) => items.iter().find_map(find),
            _ => None,
        }
    }
    let admin = slatedb::admin::AdminBuilder::new("db", store.clone()).build();
    let manifest = admin.read_manifest(None).await.unwrap().expect("a manifest");
    let replay_after = find(&serde_json::to_value(&manifest).unwrap()).expect("replay_after_wal_id");
    let newest = store
        .list(Some(&slatedb::object_store::path::Path::from("db/wal")))
        .filter_map(|meta| async move {
            meta.ok()?.location.filename()?.strip_suffix(".sst")?.parse::<u64>().ok()
        })
        .collect::<Vec<_>>()
        .await
        .into_iter()
        .max()
        .unwrap_or(0);
    newest.saturating_sub(replay_after)
}

/// The pre-NAN-3160 encoder, kept for upgrade tests.
#[cfg(test)]
pub(super) fn encode_v1(row: &PrevalenceRow) -> Vec<u8> {
    let mut out = Vec::with_capacity(27 + row.hosts.len() * 8);
    out.push(VALUE_V1);
    out.extend_from_slice(&row.first_seen.to_le_bytes());
    out.extend_from_slice(&row.last_seen.to_le_bytes());
    out.extend_from_slice(&row.daily_count.to_le_bytes());
    out.extend_from_slice(&(row.hosts.len() as u16).to_le_bytes());
    for host in &row.hosts {
        out.extend_from_slice(&host.to_le_bytes());
    }
    out
}

fn valid_part_id(part_id: &str) -> bool {
    !part_id.is_empty()
        && part_id.len() <= 256
        && part_id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// NAN-3849: the most partial rows one catch-up batch folds before its one
/// read pass (an upper bound on its distinct keys: 8 of the per-entry
/// apply's 8,192-row chunks). Bounds the batch's memory and its one write.
pub const CATCH_UP_BATCH_ROWS: u64 = 65_536;

/// NAN-3849: the most committed entries one catch-up batch applies. Sized
/// so a batch's reads (~2.5 min at tenant-a's measured per-read cost) finish well
/// inside the ~5 min credential rotation, which reopens the state and
/// aborts reads in flight.
pub const CATCH_UP_BATCH_ENTRIES: usize = 32;

/// NAN-4460: how many times [`CATCH_UP_BATCH_ENTRIES`] / [`CATCH_UP_BATCH_ROWS`]
/// one catch-up batch may grow while the backlog is long.
///
/// The large tenant (hosted, 2026-10-23, after a 62 h outage): a 26-entry batch read
/// ~42k keys in 15-24 s and committed every ~30 s. The cell's ingress held at
/// ~160 MB/s throughout. The reason: a cold point read fills a whole 4 MiB part
/// of the state's object cache (SlateDB's `part_size_bytes`), and that cache
/// (256 MiB) is far smaller than the state. So once a batch's keys outnumber the
/// state's parts, its reads re-download about the whole state, however many
/// keys it has. A batch's read cost is then fixed and its cost per entry falls
/// as 1/entries. At scale 1 the catch-up drained ~44 entries a minute, a ~5 h
/// ETA for 16,883 entries.
pub const CATCH_UP_MAX_SCALE: usize = 8;

/// NAN-4460: bytes of peak heap one partial row of a catch-up batch may cost
/// (fold, prior reads, the write batch and its memtable copy). Measured: 763
/// B/row on a large-tenant-shaped batch over multi-day priors
/// (`catch_up_batch_heap_per_row_stays_under_the_budget`, which keeps 25%
/// headroom over the measurement).
pub const CATCH_UP_ROW_BYTES: u64 = 1024;

/// NAN-4460: share of the ingest process's memory cap one catch-up batch
/// may hold at its peak (one batch at a time; a merge's decode window takes
/// 5%).
pub const CATCH_UP_MEMORY_SHARE: f64 = 0.10;

/// NAN-4460: the most partial rows a catch-up batch may fold for an ingest
/// process with `memory_cap_bytes` (0: unknown). Never below today's
/// [`CATCH_UP_BATCH_ROWS`] and never above [`CATCH_UP_MAX_SCALE`] times it.
pub fn catch_up_max_rows_for(memory_cap_bytes: u64) -> u64 {
    let ceiling = CATCH_UP_BATCH_ROWS * CATCH_UP_MAX_SCALE as u64;
    if memory_cap_bytes == 0 {
        return CATCH_UP_BATCH_ROWS;
    }
    ((memory_cap_bytes as f64 * CATCH_UP_MEMORY_SHARE / CATCH_UP_ROW_BYTES as f64) as u64)
        .clamp(CATCH_UP_BATCH_ROWS, ceiling)
}

/// NAN-4460: the batch scale a backlog of `behind_entries` warrants. The scale
/// doubles only while at least two full batches at the doubled scale are behind,
/// so a restart-sized backlog keeps today's batches and its stamping latency.
pub fn catch_up_scale_for_backlog(behind_entries: u64, base_entries: usize) -> usize {
    let base = base_entries.max(1) as u64;
    let mut scale = 1_usize;
    while scale < CATCH_UP_MAX_SCALE && behind_entries >= base.saturating_mul(scale as u64 * 2).saturating_mul(2) {
        scale *= 2;
    }
    scale
}

/// NAN-4464: the cell's room for a larger catch-up batch, sampled after each
/// committed batch ([`super::merge_quota::catch_up_headroom`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CatchUpHeadroom {
    /// Ingest lag well inside its bound and no CPU throttling or R2 strain:
    /// the scale may grow toward what the backlog warrants.
    Room,
    /// Ingest lag close to its bound: keep the current scale.
    Hold,
    /// Ingest lag past its bound, or CPU throttling / R2 strain: halve.
    Pressured,
}

/// NAN-4464: share of the ingest lag bound (`IngestConfig::lag_alert_ms`)
/// above which a catch-up batch stops growing (it halves past the bound).
pub const CATCH_UP_LAG_HOLD_SHARE: f64 = 0.75;

/// NAN-4460: the next batch's scale after one batch committed. AIMD-style:
/// - pressure (ingest lag past its bound, CPU throttling, R2 strain) halves
///   it, down to today's batch;
/// - lag near its bound holds it;
/// - otherwise it doubles toward what the backlog warrants;
/// - it drops at once when the backlog no longer warrants it.
/// Each step follows a committed batch (~30 s on the large tenant), so 1 -> 8 takes three
/// batches.
pub fn next_catch_up_scale(current: usize, behind_entries: u64, base_entries: usize, headroom: CatchUpHeadroom) -> usize {
    let target = catch_up_scale_for_backlog(behind_entries, base_entries);
    let current = current.clamp(1, CATCH_UP_MAX_SCALE);
    let next = match headroom {
        CatchUpHeadroom::Pressured => current / 2,
        CatchUpHeadroom::Hold => current,
        CatchUpHeadroom::Room if current < target => current * 2,
        CatchUpHeadroom::Room => target,
    };
    next.clamp(1, target)
}

/// NAN-3849: one committed `Add` entry of a catch-up batch
/// ([`IngestPrevalence::apply_entries_batch`]).
#[derive(Debug, Clone)]
pub struct BatchEntry {
    pub seq: u64,
    pub sha256: String,
    /// Every part of the entry in log order: (part id, its verified local
    /// prevalence partial, the part's max event time in microseconds).
    pub parts: Vec<(String, PathBuf, i64)>,
}

/// What one catch-up batch did, for its log line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BatchApplied {
    pub entries: usize,
    pub parts: usize,
    pub rows: u64,
    /// Distinct keys read and written (one point read each).
    pub keys: usize,
    pub fold_ms: u64,
    pub read_ms: u64,
    pub write_ms: u64,
}

/// Rows in a prevalence partial, from its footer (no row is decoded).
pub fn partial_rows(path: &Path) -> Result<u64> {
    let builder = ParquetRecordBatchReaderBuilder::try_new(File::open(path)?)?;
    Ok(u64::try_from(builder.metadata().file_metadata().num_rows()).unwrap_or(0))
}

/// Replay cursor: how far the state has applied the signed part log.
/// `next_part == parts` means entry `seq` is fully applied.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Applied {
    pub seq: u64,
    pub entry_sha256: String,
    /// The entry is the whole live set at `seq` (a rebuild of a lost DB),
    /// not one `Add`.
    pub rebuild: bool,
    pub parts: u32,
    pub next_part: u32,
    pub next_chunk: u32,
    /// Digest of the partial being applied, once any chunk of it is in.
    pub part_sha256: Option<String>,
}

impl Applied {
    pub fn is_complete(&self) -> bool {
        self.next_part == self.parts
    }
}

/// One committed log entry's contribution: the L0 parts of an `Add`, or, for
/// a rebuild, the whole live set at the head in (max_time, part id) order.
#[derive(Debug, Clone, Copy)]
pub struct EntryRef<'a> {
    pub seq: u64,
    pub sha256: &'a str,
    pub rebuild: bool,
    pub parts: u32,
}

pub struct IngestPrevalence {
    tenant_id: String,
    db: Db,
    point_cache: Arc<super::prevalence_io::ValueCache>,
    read_counters: Arc<super::prevalence_io::ReadCounters>,
    restamp_budget: Arc<super::prevalence_io::RestampBudget>,
    main_read_policy: bool,
    watermark_us: Option<i64>,
    created: bool,
    physical_ttl: bool,
    local_root: Option<PathBuf>,
    /// The last durable (WAL-flushed) commit: a rebuild flushes on a
    /// cadence instead of per chunk (see [`REBUILD_FLUSH_EVERY`]).
    last_flush: std::time::Instant,
    /// WAL flushes since this writer last flushed its memtable to L0, and
    /// when that was (NAN-3554). Every WAL after the last L0 flush is
    /// replayed by the next open; see [`MEMTABLE_FLUSH_EVERY`].
    wal_flushes_since_l0: u32,
    last_l0_flush: std::time::Instant,
    /// The open replayed WAL into the memtable (unknown size): the first
    /// cadence check flushes it.
    replayed_unflushed: bool,
    /// NAN-3781: [`RESET_KEY`] is present (a reset is in progress), and the
    /// last key the reset tombstoned in this process (where its scan resumes).
    reset_pending: bool,
    reset_after: Option<Vec<u8>>,
    /// `host_count < N` is stamped `is_rare` (NAN-3492): the tenant's
    /// threshold from its assignment ([`crate::prevalence::assignment_rarity_threshold`]),
    /// the hosted default until [`Self::set_rarity_threshold`].
    rarity_threshold: u64,
    /// NAN-3811: the point reads of the chunk being applied, run as their own
    /// task (see [`ChunkReads`]); kept across a step the ingest wait drops.
    chunk_reads: Option<ChunkReads>,
    /// NAN-3811: point reads finished by apply-chunk read tasks, ever (this
    /// writer). The ingest loop's stall clock restarts while it advances.
    chunk_reads_done: Arc<std::sync::atomic::AtomicU64>,
    durable_commits: u64,
    /// NAN-3849: the granted store under `db`, for in-place credential
    /// refreshes; `None` for a local state.
    owner: Option<Arc<OwnerStore>>,
    #[cfg(test)]
    crash_after_writes: Option<u32>,
    /// Test hook: each apply-chunk point read sleeps this long first.
    #[cfg(test)]
    read_delay: Option<std::time::Duration>,
    /// Test hook (NAN-4592): each admission batch's lookup
    /// ([`PrevalenceLookup::observe`]) sleeps this long before its reads; a
    /// restamp's lookups are not delayed.
    #[cfg(test)]
    pub(crate) stamp_delay: Option<std::time::Duration>,
    /// NAN-4592: the state's SST bytes measured at open (`None`: a local
    /// state, or the measurement failed) and the disk cache sized from them.
    measured_state_bytes: Option<u64>,
    object_cache_bytes: u64,
}

/// One apply chunk's prior values: `(key, the chunk's state, prior state)`.
type ChunkRead = (Vec<u8>, WindowState, Option<WindowState>);

/// Which chunk a [`ChunkReads`] belongs to: the entry, the part (and its
/// digest, so another file never reuses it) and the chunk ordinal.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ChunkKey {
    /// NAN-3849: the first entry of a multi-entry catch-up batch (`seq`
    /// for a single-entry chunk), so a batch's reads are never reused for
    /// a batch with another composition.
    first_seq: u64,
    seq: u64,
    entry_sha256: String,
    rebuild: bool,
    index: u32,
    part_sha256: String,
    chunk: u32,
}

/// NAN-3811 (tenant-a 2026-10-14 09:26Z): an apply chunk does up to 8,192 point
/// reads before its one write. Once the state's working set outgrew the
/// local object cache those reads went to R2 and a chunk took longer than
/// the ingest wait (5 s). The wait dropped the step mid-chunk, which threw
/// the reads away, so the next tick started the same chunk from nothing and
/// no step ever finished; after `prevalence_op_timeout` (45 s) the state was
/// dropped and reopened, and the loop repeated for hours while prevalence
/// fell 1 s behind per second. The reads now run as their own task, owned
/// by the state: a dropped step leaves it running, the next step with the
/// same [`ChunkKey`] picks up its result, and the chunk commits. Valid
/// because only the cursor-ordered apply writes these keys, and the task is
/// spawned after the previous chunk's write landed. Dropping the state (a
/// stall, a rotation, a close) aborts it.
struct ChunkReads {
    key: ChunkKey,
    /// NAN-3879: the replay cursor the reads started at. Every write to an
    /// entity key carries the cursor (a reset discards these reads first),
    /// so priors read at one cursor are exact while it has not moved.
    basis: Option<Applied>,
    state: ChunkReadState,
}

impl ChunkReads {
    /// Take the reads out (running or done) without aborting them.
    fn take_state(mut self) -> ChunkReadState {
        std::mem::replace(&mut self.state, ChunkReadState::Ready(Vec::new()))
    }
}

/// A read task adopted by another chunk's reads: aborted with its adopter.
struct AdoptedReads(tokio::task::JoinHandle<Result<Vec<ChunkRead>>>);

impl Drop for AdoptedReads {
    fn drop(&mut self) {
        self.0.abort();
    }
}

enum ChunkReadState {
    Running(tokio::task::JoinHandle<Result<Vec<ChunkRead>>>),
    Ready(Vec<ChunkRead>),
}

impl Drop for ChunkReads {
    fn drop(&mut self) {
        if let ChunkReadState::Running(handle) = &self.state {
            handle.abort();
        }
    }
}

/// A rebuild commits each chunk (rows + cursor, one WriteBatch, so a crash
/// resumes at a consistent chunk) but makes it durable at most this often,
/// and always at the end of the rebuild. Every durable commit is an owner
/// round trip (authorize, conditional create, HEAD, complete); per 8,192-row
/// chunk they bounded a live rebuild at ~1 part a minute (a lean test tenant,
/// 2026-09-30). The WAL still flushes by size on its own. Stamping does not
/// start until the rebuild completes, so nothing depends on a chunk's
/// durability before then; a crash only redoes the chunks since the last
/// flush.
pub const REBUILD_FLUSH_EVERY: std::time::Duration = std::time::Duration::from_secs(5);

/// NAN-3554: an open replays every WAL written since the last memtable
/// flush to L0. A low-write tenant (tenant-a: ~65 KB of WAL a minute) fills the
/// 32 MiB memtable only every few hours, and `close_wal_only` (each 5-minute
/// credential rotation) never flushed it, so the replay backlog grew without
/// bound: 470 WALs took > 60 s to replay cold, past the 45 s open budget, and
/// every restart then livelocked. A dirty memtable is flushed to L0 at least
/// this often, or after [`MEMTABLE_FLUSH_AFTER_WALS`] WAL flushes, whichever
/// comes first, so the backlog an open replays stays bounded. A high-write
/// tenant fills its memtable by size well within this window, so the cadence
/// adds at most one small extra L0 per window there.
pub const MEMTABLE_FLUSH_EVERY: std::time::Duration = std::time::Duration::from_secs(10 * 60);

/// See [`MEMTABLE_FLUSH_EVERY`]: the WAL-count bound on the replay backlog.
pub const MEMTABLE_FLUSH_AFTER_WALS: u32 = 256;

/// A memtable flush waits on L0 room (the compactor: `maintenance[T]` for a
/// granted state, the embedded one for a local state). Close and rotation
/// never wait on it longer than this; a flush that does not finish leaves
/// the WAL to replay, as before NAN-3554.
pub const MEMTABLE_FLUSH_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(20);

/// NAN-3781: the garbage collector beside the embedded compactor of a local
/// state. Compaction supersedes L0 SSTs and every L0 flush obsoletes the WAL
/// before it; without collection both stay on the cell's disk forever (CT
/// 106: 2,953 WAL files in six hours). Every directory is collected each
/// minute; WAL fences stay in dry run. This writer is the state's only
/// reader, so nothing holds an older manifest.
///
/// Boundary files are off: advancing them is a conditional overwrite
/// (`PutMode::Update`, If-Match), which `LocalFileSystem` does not implement,
/// so the manifest and compactions collectors failed every minute on CT 106
/// (`NotImplemented put_opts PutMode::Update`). SlateDB documents turning
/// them off for such stores; the boundary only guards against a writer that
/// is suspended past `min_age` and then resumes. A local state has one writer
/// process (the supervisor replaces it; it never runs two), and its manifest
/// and compactions files are kept an hour ([`LOCAL_GC_METADATA_MIN_AGE`]).
fn local_gc_options() -> GarbageCollectorOptions {
    let metadata = Some(slatedb::config::GarbageCollectorDirectoryOptions {
        min_age: LOCAL_GC_METADATA_MIN_AGE,
        ..slatedb::config::GarbageCollectorDirectoryOptions::default()
    });
    GarbageCollectorOptions {
        manifest_options: metadata,
        compactions_options: metadata,
        boundary_files_enabled: false,
        ..GarbageCollectorOptions::default()
    }
}

/// See [`local_gc_options`]: how long superseded manifest and compactions
/// files of a local state are kept (SlateDB's default is five minutes).
const LOCAL_GC_METADATA_MIN_AGE: std::time::Duration = std::time::Duration::from_secs(60 * 60);

/// NAN-3781: the embedded compactor of a local state: `maintenance[T]`'s
/// bounded compactor (one job, one subcompaction, 64 MiB outputs), polling
/// at most every 5 s while idle instead of 60 s. The 60 s ceiling saves remote
/// metadata reads on hosted object storage (NAN-3747); a local manifest read
/// is a file read, and a burst gets its L0 room back sooner.
///
/// NAN-4723: the job, subcompaction and fetch counts come from the role's
/// placement ([`LocalStateSizing`]); the floor is the bounded compactor above.
fn local_compactor_options(sizing: LocalStateSizing) -> slatedb::config::CompactorOptions {
    let mut options = super::maintenance::compactor_options();
    options.idle_poll_interval = Some(LOCAL_COMPACTOR_IDLE_POLL);
    options.max_concurrent_compactions = sizing.compactions;
    if let Some(worker) = options.worker.as_mut() {
        worker.idle_compactions_poll_interval = Some(LOCAL_COMPACTOR_IDLE_POLL);
        worker.max_concurrent_compactions = sizing.compactions;
        worker.max_subcompactions = sizing.subcompactions;
        worker.max_fetch_tasks = sizing.fetch_tasks;
    }
    options
}

/// NAN-4723: how a state on the local filesystem (open core, the lab: the
/// writer compacts it itself, NAN-3781) is sized from the ingest role's
/// placement. No knob: the role's CPU limit and memory cap decide it.
///
/// The NAN-4689 soak (12.5k eps fed, a 16-core ingest placement) ran the
/// hosted `maintenance[T]` shape: one compaction job. A sorted-run merge
/// (`[3, 2, 1, 0] -> SR(0)`) then held the only slot while flushes filled
/// L0 to `l0_max_ssts` (8); memtable flushes stopped, imm memtables and WAL
/// passed `max_unflushed_bytes` (128 MiB) and every prevalence write waited
/// (backpressure 36x/h), so applies and stamps overran and commit eps fell
/// from ~13k to ~10k. CPU was not the limit (3.2 of 16 cores).
///
/// - one compaction job per 4 cores, 1..=4: an L0 compaction no longer
///   waits behind a sorted-run merge. The cores are the role's CPU limit,
///   capped by what the process can actually run on (`cell`): a placement
///   limit can exceed the host (the soak placed 16 cores on a 7-core cell);
/// - compaction memory is bounded like the unflushed budget (1/8 of the
///   memory cap, 128..=512 MiB): every concurrent merge stream (a job, or
///   one subcompaction of it) holds ~[`Self::STREAM_BYTES`] (input
///   read-ahead of up to 8 sources x 2 fetches x 1 MiB, plus the output
///   writer and its one pending close). Jobs and subcompactions shrink to fit
///   it; read-ahead per input stays the bounded compactor's (2 fetches),
///   since it is per input SST, not per job;
/// - L0 room doubles once more than one job runs (8 -> 16, total and per
///   key): a burst lands in L0 while a job is busy instead of stopping
///   flushes. Point reads stay bloom-filtered per L0 SST;
/// - the unflushed (WAL + memtable) budget is 1/8 of the process memory cap
///   within 128..=512 MiB, beside the admission buffer (30%), the catch-up
///   batch (10%) and the merge decode window (5%).
///
/// A granted (hosted) state is compacted by `maintenance[T]` under its fixed
/// budget and keeps [`LocalStateSizing::FLOOR`]'s L0 and memory settings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LocalStateSizing {
    /// Concurrent compaction jobs (coordinator and embedded worker).
    pub compactions: usize,
    /// Key-range splits of one compaction job.
    pub subcompactions: usize,
    /// Input block fetches in flight per job.
    pub fetch_tasks: usize,
    /// `l0_max_ssts` and `l0_max_ssts_per_key`.
    pub l0_max_ssts: usize,
    /// `max_unflushed_bytes`.
    pub max_unflushed_bytes: usize,
}

impl LocalStateSizing {
    /// The pre-NAN-4723 shape, and an unknown placement's: one job, L0 cap
    /// 8, 128 MiB unflushed. Also what a granted state keeps.
    pub const FLOOR: Self = Self {
        compactions: 1,
        subcompactions: 1,
        fetch_tasks: 2,
        l0_max_ssts: 8,
        max_unflushed_bytes: 128 * 1024 * 1024,
    };
    /// Most compaction jobs (and subcompactions) any placement gets.
    pub const MAX_COMPACTIONS: usize = 4;
    /// Cores per compaction job.
    pub const CORES_PER_COMPACTION: u32 = 4;
    /// Share of the process memory cap the unflushed WAL + memtables may hold.
    pub const UNFLUSHED_MEMORY_SHARE: u64 = 8;
    /// Most unflushed bytes any placement gets.
    pub const MAX_UNFLUSHED_BYTES: usize = 512 * 1024 * 1024;
    /// Memory one concurrent compaction merge stream may hold: input
    /// read-ahead (at most `max_compaction_sources` = 8 inputs x
    /// [`Self::FLOOR`]'s 2 fetches x 1 MiB = 16 MiB) plus the output SST
    /// writer and its one pending close, rounded up.
    pub const STREAM_BYTES: usize = 64 * 1024 * 1024;

    /// The sizing for an ingest role placed with `cpu_millis` (its CPU
    /// limit, already capped at the cores the process can use) and
    /// `memory_cap_bytes` (0: unknown -> the floor's memory).
    pub fn for_placement(cpu_millis: u32, memory_cap_bytes: u64) -> Self {
        let cores = cpu_millis / 1_000;
        let budget = usize::try_from(memory_cap_bytes / Self::UNFLUSHED_MEMORY_SHARE)
            .unwrap_or(usize::MAX)
            .clamp(Self::FLOOR.max_unflushed_bytes, Self::MAX_UNFLUSHED_BYTES);
        // Concurrent merge streams the compaction memory budget holds.
        let streams = (budget / Self::STREAM_BYTES).max(1);
        let compactions = ((cores / Self::CORES_PER_COMPACTION) as usize)
            .min(streams)
            .clamp(1, Self::MAX_COMPACTIONS);
        let subcompactions = (streams / compactions).clamp(1, compactions);
        let l0_max_ssts = if compactions > 1 { 2 * Self::FLOOR.l0_max_ssts } else { Self::FLOOR.l0_max_ssts };
        Self {
            compactions,
            subcompactions,
            fetch_tasks: Self::FLOOR.fetch_tasks,
            l0_max_ssts,
            max_unflushed_bytes: budget,
        }
    }

    /// The CPU the sizing may count on: the role's limit, capped at the
    /// cores this process can actually run on (cgroup quota and affinity,
    /// [`std::thread::available_parallelism`]). 0 stays unknown.
    pub fn usable_cpu_millis(limit_millis: u32) -> u32 {
        let usable = std::thread::available_parallelism()
            .map_or(u32::MAX, |cores| u32::try_from(cores.get()).unwrap_or(u32::MAX).saturating_mul(1_000));
        limit_millis.min(usable)
    }
}

impl Default for LocalStateSizing {
    fn default() -> Self {
        Self::FLOOR
    }
}

/// The SlateDB settings of a tenant prevalence state. `embedded`: the state
/// is on this process's own disk and compacted here, sized by the placement
/// (NAN-4723); `None`: a granted state, compacted by `maintenance[T]`.
fn state_settings(embedded: Option<LocalStateSizing>) -> Settings {
    let sizing = embedded.unwrap_or(LocalStateSizing::FLOOR);
    Settings {
        flush_interval: None,
        // The compactor starts before the WAL replay, so a state that
        // already stalled at `l0_max_ssts` drains on its next open.
        compactor_options: embedded.map(local_compactor_options),
        garbage_collector_options: embedded.map(|_| local_gc_options()),
        manifest_poll_interval: std::time::Duration::from_secs(30),
        idle_manifest_poll_interval: Some(std::time::Duration::from_secs(300)),
        manifest_update_timeout: std::time::Duration::from_secs(30),
        l0_sst_size_bytes: 32 * 1024 * 1024,
        l0_max_ssts: sizing.l0_max_ssts,
        l0_max_ssts_per_key: sizing.l0_max_ssts,
        max_unflushed_bytes: sizing.max_unflushed_bytes,
        compression_codec: Some(CompressionCodec::Zstd),
        object_store_max_retries: Some(3),
        ..Settings::default()
    }
}

/// See [`local_compactor_options`].
const LOCAL_COMPACTOR_IDLE_POLL: std::time::Duration = std::time::Duration::from_secs(5);

/// The distinct artifacts an admission batch's stamps read.
pub fn stamp_artifacts<'e>(events: impl IntoIterator<Item = &'e Value>) -> Result<std::collections::BTreeSet<String>> {
    let mut artifacts = std::collections::BTreeSet::<String>::new();
    for event in events {
        let object = event
            .as_object()
            .ok_or_else(|| anyhow::anyhow!("OCSF event is not an object"))?;
        artifacts.extend(column_artifacts(object).into_iter().map(|(_, artifact)| artifact));
        artifacts.extend(stampable_artifacts(object).into_iter().map(|(_, artifact)| artifact));
    }
    Ok(artifacts)
}

/// NAN-4749: [`stamp_artifacts`] of admission rows, in
/// [`super::schema::DECODE_CHUNK_ROWS`] chunks on the rayon pool (the same
/// set: a union of the chunks' sets).
pub fn stamp_artifacts_of(rows: &[crate::iceberg::EventRow]) -> Result<std::collections::BTreeSet<String>> {
    use rayon::prelude::*;
    if rows.len() <= super::schema::DECODE_CHUNK_ROWS {
        return stamp_artifacts(rows.iter().map(|row| &row.ocsf_event));
    }
    rows.par_chunks(super::schema::DECODE_CHUNK_ROWS)
        .map(|chunk| stamp_artifacts(chunk.iter().map(|row| &row.ocsf_event)))
        .try_reduce(std::collections::BTreeSet::new, |mut all, chunk| {
            all.extend(chunk);
            Ok(all)
        })
}

/// See [`IngestPrevalence::lookup`]. Read-only: a dropped or abandoned
/// lookup never changes the state.
#[derive(Clone)]
pub struct PrevalenceLookup {
    db: Db,
    point_cache: Arc<super::prevalence_io::ValueCache>,
    read_counters: Arc<super::prevalence_io::ReadCounters>,
    restamp_budget: Arc<super::prevalence_io::RestampBudget>,
    main_read_policy: bool,
    watermark_us: Option<i64>,
    rarity_threshold: u64,
    #[cfg(test)]
    read_delay: Option<std::time::Duration>,
    #[cfg(test)]
    observe_delay: Option<std::time::Duration>,
}

/// What [`PrevalenceLookup::observe`] read, ready to stamp the batch.
pub struct Observed {
    rows: BTreeMap<String, Option<PrevalenceRow>>,
    rarity_threshold: u64,
}

impl PrevalenceLookup {
    /// Read every artifact once, with bounded concurrency.
    pub async fn observe(self, artifacts: std::collections::BTreeSet<String>) -> Result<Observed> {
        let _foreground = self.restamp_budget.foreground();
        #[cfg(test)]
        if let Some(delay) = self.observe_delay { tokio::time::sleep(delay).await; }
        let this = &self;
        let rows = stream::iter(artifacts.into_iter().map(|artifact| async move {
            let row = this.observation(IngestPrevalence::kind(&artifact), &artifact, true).await?;
            Ok::<_, anyhow::Error>((artifact, row))
        }))
        .buffer_unordered(if self.main_read_policy { 64 } else { STAMP_READS })
        .collect::<Vec<_>>()
        .await
        .into_iter()
        .collect::<Result<BTreeMap<String, Option<PrevalenceRow>>>>()?;
        Ok(Observed { rows, rarity_threshold: self.rarity_threshold })
    }

    /// One point read: the entity's window ending at the watermark. Hosts
    /// and occurrences on days before the window are not counted, so an
    /// entity active for more than 30 days reports only its recent spread.
    async fn observation(&self, kind: &str, artifact: &str, cache_blocks: bool) -> Result<Option<PrevalenceRow>> {
        #[cfg(test)]
        if let Some(delay) = self.read_delay { tokio::time::sleep(delay).await; }
        let Some(watermark) = self.watermark_us else {
            return Ok(None);
        };
        let k = key(kind, artifact);
        let bytes = if cache_blocks {
            super::prevalence_io::read(&self.db, &self.point_cache, &self.read_counters,
                super::prevalence_io::ReadPath::Stamp, &k).await?
        } else {
            self.read_counters.db_read(super::prevalence_io::ReadPath::Restamp);
            super::prevalence_io::scope(super::prevalence_io::ReadPath::Restamp,
                self.db.get_with_options(k, &ReadOptions::default().with_cache_blocks(self.main_read_policy))).await?
        };
        let Some(state) = bytes.map(|bytes| decode(&bytes)).transpose()? else { return Ok(None) };
        if state.last_seen <= watermark.saturating_sub(INACTIVE_TTL_US) {
            return Ok(None);
        }
        let row = state.window(kind, artifact, floor_day(watermark));
        Ok((!row.hosts.is_empty()).then_some(row))
    }

    /// Keep completed scalars when a routine merge's budget expires. A
    /// sealed rewrite resumes the same stream after every budget slice;
    /// only a store making no progress for the stall timeout fails it.
    /// Missing scalars stay unstamped, never become invented rarity.
    pub(super) async fn observe_restamp(self, artifacts: std::collections::BTreeSet<String>, sealed: bool)
        -> Result<(std::collections::HashMap<String, u64>, bool)> {
        let this = &self;
        let total = artifacts.len();
        let mut artifacts = artifacts.into_iter();
        let mut reads = futures::stream::FuturesUnordered::new();
        let read = |artifact: String| async move {
            let row = tokio::time::timeout(super::restamp::RESTAMP_LOOKUP_TIMEOUT,
                this.observation(IngestPrevalence::kind(&artifact), &artifact, false)).await
                .context("prevalence restamp point read stalled")??;
            Ok::<_, anyhow::Error>((artifact, IngestPrevalence::scalar(row.as_ref())))
        };
        let mut scalars = std::collections::HashMap::new();
        let mut deadline = tokio::time::Instant::now() + super::restamp::RESTAMP_MERGE_LOOKUP_TIMEOUT;
        loop {
            while reads.len() < self.restamp_budget.lanes() {
                let Some(artifact) = artifacts.next() else { break };
                reads.push(read(artifact));
            }
            if scalars.len() == total {
                return Ok((scalars, true));
            }
            // timeout_at polls a ready future before its timer. Check the
            // clock too, so a fully cached hour still respects the budget.
            if tokio::time::Instant::now() >= deadline {
                if !sealed { return Ok((scalars, false)) }
                tokio::task::yield_now().await;
                deadline = tokio::time::Instant::now() + super::restamp::RESTAMP_MERGE_LOOKUP_TIMEOUT;
            }
            match tokio::time::timeout_at(deadline, reads.next()).await {
                Ok(Some(row)) => {
                    let (artifact, scalar) = row?;
                    scalars.insert(artifact, scalar);
                    if scalars.len() % 256 == 0 {
                        tokio::task::yield_now().await;
                    }
                }
                Ok(None) => return Ok((scalars, true)),
                Err(_) if !sealed => return Ok((scalars, false)),
                Err(_) => {
                    tracing::info!(artifacts = scalars.len(), "prevalence restamp lookup budget yielded; resuming");
                    tokio::task::yield_now().await;
                    deadline = tokio::time::Instant::now() + super::restamp::RESTAMP_MERGE_LOOKUP_TIMEOUT;
                }
            }
        }
    }
}

impl Observed {
    /// NAN-3864: each artifact's host-count scalar, as the ingest stamp
    /// derives it (an unseen artifact is 1).
    pub fn scalars(&self) -> std::collections::HashMap<String, u64> {
        self.rows.iter().map(|(artifact, row)| (artifact.clone(), IngestPrevalence::scalar(row.as_ref()))).collect()
    }

    /// Stamp the batch from what was read. All or nothing per event.
    pub fn stamp<'e>(&self, events: impl IntoIterator<Item = &'e mut Value>) -> Result<()> {
        for event in events {
            IngestPrevalence::stamp_from(&self.rows, event, self.rarity_threshold)?;
        }
        Ok(())
    }
}

impl IngestPrevalence {
    #[cfg(test)]
    pub async fn new(tenant_id: &str) -> Self {
        Self::open_store(tenant_id, Arc::new(InMemory::new()), "db", None, false, None, None)
            .await
            .unwrap()
    }

    /// Open the tenant DB on a caller-supplied store (tests share one store
    /// between two writers to prove fencing).
    #[cfg(test)]
    pub async fn open_shared(tenant_id: &str, store: Arc<dyn ObjectStore>) -> Result<Self> {
        Self::open_store(tenant_id, store, "db", None, false, None, None).await
    }

    /// Without a grant (open core's trusted-local cell, the lab) the state
    /// lives on the local filesystem and this process compacts it itself
    /// ([`Self::open_with_reads`]). Hosted cells pass the owner grant and the
    /// `maintenance[T]` role compacts.
    pub async fn open(
        tenant_id: &str,
        work_dir: &Path,
        access: Option<&PrevalenceAccess>,
    ) -> Result<Self> {
        Self::open_with_reads(tenant_id, work_dir, access, None).await
    }

    /// [`Self::open`], reading a granted state through `reads` (already
    /// scoped to the tenant prefix) instead of the grant's S3 endpoint.
    pub async fn open_with_reads(
        tenant_id: &str,
        work_dir: &Path,
        access: Option<&PrevalenceAccess>,
        reads: Option<Arc<dyn ObjectStore>>,
    ) -> Result<Self> {
        Self::open_sized(tenant_id, work_dir, access, reads, OBJECT_CACHE_FLOOR_BYTES, LocalStateSizing::FLOOR).await
    }

    /// [`Self::open_with_reads`] with the tenant's disk-cache cap (NAN-4592,
    /// the production open: `spawn_prevalence_open`). A remote state (a
    /// grant, or `reads`) sizes its disk cache from the state's measured
    /// SSTs within `cache_cap_bytes` ([`object_cache_bytes`]); a state on the
    /// local filesystem has no disk cache (it is already local, NAN-4765).
    ///
    /// NAN-4723: a state on the local filesystem (compacted in-process) is
    /// sized by `local_sizing`, the ingest role's placement
    /// ([`LocalStateSizing::for_placement`]); a granted state ignores it.
    pub async fn open_sized(
        tenant_id: &str,
        work_dir: &Path,
        access: Option<&PrevalenceAccess>,
        reads: Option<Arc<dyn ObjectStore>>,
        cache_cap_bytes: u64,
        local_sizing: LocalStateSizing,
    ) -> Result<Self> {
        ensure!(
            uuid::Uuid::parse_str(tenant_id).is_ok_and(|id| id.to_string() == tenant_id),
            "prevalence tenant must be a canonical UUID"
        );
        let root = format!("lake/prevalence-state/v1/tenant={tenant_id}/");
        let cache = work_dir
            .join("prevalence")
            .join(tenant_id)
            .join("object-cache");
        // NAN-3781: only the state this process keeps on its own disk is
        // compacted in-process; a granted state is compacted by
        // `maintenance[T]` (the owner refuses `compactions/*` from ingest).
        let mut embedded_compaction = None;
        let mut owner_store = None;
        let store: Arc<dyn ObjectStore> = match access {
            Some(access) => {
                let location = &access.read;
                ensure!(
                    location.prefix == root,
                    "prevalence credential prefix differs from tenant"
                );
                ensure!(access.owner.tenant_id == tenant_id, "prevalence owner tenant differs");
                let reads = match reads {
                    Some(reads) => reads,
                    None => Self::s3_reads(location, &root)?,
                };
                let owner = Arc::new(OwnerStore::new(reads, access.clone(), &work_dir.join("prevalence").join(tenant_id).join("owner-pending"))?);
                owner_store = Some(owner.clone());
                owner
            }
            // Without a grant the state is local; tests may supply the
            // store (e.g. one whose writes never complete).
            None => match reads {
                Some(store) => store,
                None => {
                    let directory = work_dir.join("prevalence").join(tenant_id);
                    std::fs::create_dir_all(&directory)?;
                    embedded_compaction = Some(local_sizing);
                    Arc::new(LocalFileSystem::new_with_prefix(&directory)?)
                }
            },
        };
        // NAN-4592: only a remote state's reads cost R2 GETs. The cache
        // directory is this tenant's own (`prevalence/<tenant>/object-cache`)
        // and every SST path is under the tenant's prefix: nothing is shared.
        //
        // NAN-4765: a state on the local filesystem gets no disk cache. Its
        // SSTs are already on this disk (and in the page cache); a disk
        // cache in front of them only copied them. Every block miss read
        // the whole 4 MiB cache part holding it, and wrote that part a
        // second time under `object-cache/`. Every flush and compaction
        // output was written twice, and the evictor deleted parts as fast
        // as they landed. The NAN-4689 v3 soak (12.5k eps, a 9.7 GB local
        // state after 1 h against the 256 MiB cache) read 81 GB of state
        // parts in that hour, and the rate rose with the state: about 3
        // MB/s at minute 5, then 37 MB/s at minute 55. Host io full60
        // reached 35% and the SlateDB "evictor queue full" warnings ran
        // into the thousands per 30 s. Commit eps fell from 12.5k to 7.4k
        // and stayed there after the hour roll had emptied the uid window.
        // Without the cache, a point read fetches only its block.
        let (measured, cache_bytes) = if embedded_compaction.is_some() {
            // An earlier version's cache is dead weight (up to the 256 MiB
            // floor) and is never read again.
            match remove_stale_local_cache(work_dir, tenant_id) {
                Ok(()) => tracing::info!(tenant = %tenant_id, "removed the unused disk cache of a local prevalence state"),
                Err(error) if error.downcast_ref::<std::io::Error>().is_some_and(|e| e.kind() == std::io::ErrorKind::NotFound) => {}
                Err(error) => tracing::warn!(tenant = %tenant_id, error = %error,
                    "could not remove the unused disk cache of a local prevalence state"),
            }
            (None, 0)
        } else {
            std::fs::create_dir_all(&cache)?;
            let measured = match measure_state_bytes(&store).await {
                Ok(bytes) => Some(bytes),
                Err(error) => {
                    tracing::warn!(tenant = %tenant_id, error = %format!("{error:#}"),
                        "prevalence state size unknown; its disk cache keeps the floor");
                    None
                }
            };
            let bytes = object_cache_bytes(measured, cache_cap_bytes);
            tracing::info!(tenant = %tenant_id, state_bytes = measured, cache_bytes = bytes, cap_bytes = cache_cap_bytes,
                "prevalence disk cache sized from the state");
            (measured, bytes)
        };
        let local_root = work_dir.join("prevalence").join(tenant_id);
        let cache_dir = embedded_compaction.is_none().then_some((cache.as_path(), cache_bytes));
        let mut state = Self::open_store(tenant_id, store, "db", cache_dir, access.is_some(),
            Some(local_root), embedded_compaction)
            .await?;
        state.owner = owner_store;
        state.measured_state_bytes = measured;
        Ok(state)
    }

    /// NAN-3849: take a refreshed grant without reopening: the owner bearer
    /// and the read side are swapped under the open store
    /// ([`OwnerStore::refresh_in_place`]). `Ok(false)`: not possible (no
    /// granted store, or the grant moved to another generation, epoch,
    /// owner, bucket or prefix); the caller reopens as before.
    pub fn refresh_credential_in_place(&mut self, access: &PrevalenceAccess, reads: Option<Arc<dyn ObjectStore>>)
        -> Result<bool> {
        let Some(owner) = &self.owner else { return Ok(false) };
        // NAN-3873: a fresh credential cannot revive a writer SlateDB has
        // closed; keeping it open is what wedged tenant-a. Reopen instead.
        if let Some(reason) = self.closed() {
            tracing::warn!(tenant = %self.tenant_id, reason = ?reason,
                "prevalence state was closed by the store after a failure; reopening instead of refreshing in place");
            return Ok(false);
        }
        let root = format!("lake/prevalence-state/v1/tenant={}/", self.tenant_id);
        if access.read.prefix != root || access.owner.tenant_id != self.tenant_id {
            return Ok(false);
        }
        let reads = match reads {
            Some(reads) => reads,
            None => Self::s3_reads(&access.read, &root)?,
        };
        match owner.refresh_in_place(&access.read, &access.owner, reads) {
            Ok(()) => Ok(true),
            Err(error) => {
                tracing::info!(tenant = %self.tenant_id, reason = %format!("{error:#}"),
                    "prevalence grant changed beyond a credential refresh; reopening the state");
                Ok(false)
            }
        }
    }

    pub(crate) fn s3_reads(location: &super::s3_store::S3Location, root: &str) -> Result<Arc<dyn ObjectStore>> {
        ensure!(location.endpoint.starts_with("https://") || cfg!(test),
            "prevalence object-store endpoint must use HTTPS");
        let mut builder = AmazonS3Builder::new()
            .with_bucket_name(&location.bucket)
            .with_region(&location.region)
            .with_endpoint(&location.endpoint)
            .with_allow_http(location.endpoint.starts_with("http://"))
            .with_access_key_id(&location.access_key_id)
            .with_secret_access_key(&location.secret_access_key);
        if let Some(token) = &location.session_token {
            builder = builder.with_token(token);
        }
        Ok(Arc::new(PrefixStore::new(Arc::new(builder.build()?), root)))
    }

    /// `embedded_compaction` (NAN-3781): run SlateDB's compactor and garbage
    /// collector inside this writer, sized as given (NAN-4723). Set only for a state on the local
    /// filesystem with no grant (open core): nothing else compacts it, and
    /// without a compactor L0 reaches `l0_max_ssts` (8), every memtable
    /// flush then waits forever, and writes stop at `max_unflushed_bytes`.
    /// The 10-minute cadence flush ([`MEMTABLE_FLUSH_EVERY`]) adds one L0 per
    /// window, so a quiet open-core tenant hit that about 80 minutes after
    /// its state was created (CT 106, 2026-10-13). A granted state is
    /// compacted by `maintenance[T]`.
    async fn open_store(
        tenant_id: &str,
        store: Arc<dyn ObjectStore>,
        path: &str,
        cache_dir: Option<(&Path, u64)>,
        physical_ttl: bool,
        local_root: Option<PathBuf>,
        embedded_compaction: Option<LocalStateSizing>,
    ) -> Result<Self> {
        let main_read_policy = super::prevalence_io::main_policy();
        let point_cache = Arc::new(super::prevalence_io::ValueCache::new(!main_read_policy));
        let read_counters = Arc::new(super::prevalence_io::ReadCounters::default());
        let restamp_budget = Arc::new(super::prevalence_io::RestampBudget::default());
        let store: Arc<dyn ObjectStore> = Arc::new(super::prevalence_io::MeteredStore { inner: store, counters: read_counters.clone() });
        let blocks: Arc<dyn DbCache> = Arc::new(FoyerCache::new_with_opts(FoyerCacheOptions {
            max_capacity: if main_read_policy { 32 * 1024 * 1024 } else { super::prevalence_io::VALUE_CACHE_BYTES as u64 },
            shards: 8,
        }));
        let metadata: Arc<dyn DbCache> = Arc::new(FoyerCache::new_with_opts(FoyerCacheOptions {
            max_capacity: 64 * 1024 * 1024,
            shards: 8,
        }));
        let cache: Arc<dyn DbCache> = Arc::new(
            SplitCache::new()
                .with_block_cache(Some(blocks))
                .with_meta_cache(Some(metadata))
                .build(),
        );
        let mut settings = state_settings(embedded_compaction);
        settings.object_store_cache_options = ObjectStoreCacheOptions {
            root_folder: cache_dir.map(|(dir, _)| dir.to_path_buf()),
            max_cache_size_bytes: cache_dir.map(|(_, bytes)| usize::try_from(bytes).unwrap_or(usize::MAX)),
            cache_on_flush: cache_dir.is_some(),
            cache_on_compaction: cache_dir.is_some(),
            part_size_bytes: OBJECT_CACHE_PART_BYTES,
            ..ObjectStoreCacheOptions::default()
        };
        let db = Db::builder(path, store)
            .with_db_cache(Arc::new(super::prevalence_io::MeasuredCache { inner: cache, counters: read_counters.clone() }))
            .with_settings(settings)
            .build()
            .await
            .context("open tenant prevalence SlateDB")?;
        let marker = format!("v1:{tenant_id}");
        let created = match db.get(SCHEMA_KEY).await? {
            Some(value) => {
                ensure!(
                    value.as_ref() == marker.as_bytes(),
                    "prevalence database tenant or schema differs"
                );
                false
            }
            None => true,
        };
        let watermark_us = db
            .get(WATERMARK_KEY)
            .await?
            .map(|bytes| -> Result<i64> {
                ensure!(bytes.len() == 8, "invalid prevalence watermark");
                Ok(i64::from_le_bytes(bytes.as_ref().try_into()?).min(watermark_ceiling_us()))
            })
            .transpose()?;
        let reset_pending = db.get(RESET_KEY).await?.is_some();
        Ok(Self {
            tenant_id: tenant_id.into(),
            db,
            point_cache, read_counters, restamp_budget, main_read_policy,
            watermark_us,
            created,
            reset_pending,
            reset_after: None,
            physical_ttl,
            local_root,
            last_flush: std::time::Instant::now(),
            wal_flushes_since_l0: 0,
            last_l0_flush: std::time::Instant::now(),
            replayed_unflushed: true,
            rarity_threshold: crate::prevalence::DEFAULT_RARITY_THRESHOLD,
            chunk_reads: None,
            chunk_reads_done: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            durable_commits: 0,
            owner: None,
            #[cfg(test)]
            crash_after_writes: None,
            #[cfg(test)]
            read_delay: None,
            #[cfg(test)]
            stamp_delay: None,
            measured_state_bytes: None,
            object_cache_bytes: cache_dir.map_or(0, |(_, bytes)| bytes),
        })
    }

    /// Test hook: `n` durable commits of filler keys (one WAL each).
    #[cfg(test)]
    pub(crate) async fn write_test_wals(&mut self, n: u32) -> Result<()> {
        for i in 0..n {
            let mut writes = WriteBatch::new();
            writes.put(format!("zz-test/{i:08}").as_bytes(), vec![7_u8; 256]);
            self.commit(writes, true).await?;
        }
        Ok(())
    }

    /// Test hook: whether filler key `i` of [`Self::write_test_wals`] is present.
    #[cfg(test)]
    pub(crate) async fn has_test_key(&self, i: u32) -> bool {
        self.db.get(format!("zz-test/{i:08}").as_bytes()).await.unwrap().is_some()
    }

    /// Test hook: what the pre-NAN-3554 close did (WAL only, no L0 flush).
    #[cfg(test)]
    pub(crate) async fn close_wal_only_for_test(self) -> Result<()> {
        self.db.close_wal_only().await?;
        Ok(())
    }

    /// Test hook: force the cadence check's clock.
    #[cfg(test)]
    pub(crate) fn age_last_l0_flush(&mut self, by: std::time::Duration) {
        self.last_l0_flush = std::time::Instant::now() - by;
    }

    /// The threshold ingest stamps `is_rare` against (see the field).
    pub fn set_rarity_threshold(&mut self, threshold: u64) {
        self.rarity_threshold = threshold;
    }

    /// True when the tenant DB has no schema marker: a first start or a lost
    /// DB. The caller either initializes it at the log head (no live parts)
    /// or rebuilds it from the signed live set.
    pub fn is_new(&self) -> bool {
        self.created
    }

    /// The replay cursor, written in the same SlateDB batch as every chunk of
    /// state it describes. `None` only for a DB that has never applied or
    /// initialized anything.
    pub async fn applied(&self) -> Result<Option<Applied>> {
        self.db
            .get(APPLIED_KEY)
            .await?
            .map(|bytes| -> Result<Applied> {
                let cursor: Applied = serde_json::from_slice(&bytes).context("decode prevalence cursor")?;
                ensure!(
                    crate::parts::is_sha256_hex(&cursor.entry_sha256)
                        && cursor.next_part <= cursor.parts
                        && (cursor.next_chunk == 0 || cursor.part_sha256.is_some()),
                    "invalid prevalence replay cursor"
                );
                Ok(cursor)
            })
            .transpose()
    }

    /// Start a tenant DB whose signed log has no live part: nothing to
    /// count, so the state is complete at `head`.
    pub async fn initialize_at(&mut self, seq: u64, entry_sha256: &str) -> Result<()> {
        self.initialize_rebuild(&EntryRef { seq, sha256: entry_sha256, rebuild: true, parts: 0 }, &[]).await
    }

    /// Checkpoint a verified span with no non-empty Adds. The caller checks
    /// the signed log chain; rows do not change, but its durable cursor must
    /// advance so long merge-only spans cannot replay forever after a cut.
    pub(crate) async fn checkpoint_scanned(&mut self, seq: u64, sha256: &str) -> Result<()> {
        let cursor = self.applied().await?.context("prevalence state has no replay cursor")?;
        ensure!(cursor.is_complete() && seq > cursor.seq && crate::parts::is_sha256_hex(sha256),
            "invalid prevalence scan checkpoint");
        let next = Applied {
            seq, entry_sha256: sha256.to_owned(), rebuild: false,
            parts: 0, next_part: 0, next_chunk: 0, part_sha256: None,
        };
        let mut writes = WriteBatch::new();
        writes.put(APPLIED_KEY, serde_json::to_vec(&next)?);
        self.commit_metadata(writes, true).await
    }

    /// The part list an interrupted rebuild resumes.
    pub async fn rebuild_parts(&self) -> Result<Option<Vec<PartRef>>> {
        self.db
            .get(REBUILD_PARTS_KEY)
            .await?
            .map(|bytes| serde_json::from_slice(&bytes).context("decode prevalence rebuild part list"))
            .transpose()
    }

    /// NAN-3867: durably delete one entity's window (data-subject erasure of
    /// an IP). The key holds the entity itself; its value only per-day counts
    /// and hashed host fingerprints. `Ok(true)` when a key was present. The
    /// caller runs it only after every `add` up to its last erasure rewrite
    /// was applied, so no replay of a pre-erasure part can re-add it.
    pub async fn erase_artifact(&mut self, kind: &str, artifact: &str) -> Result<bool> {
        self.point_cache.invalidate();
        let key = key(kind, artifact);
        if self.db.get(&key).await?.is_none() {
            return Ok(false);
        }
        let mut writes = WriteBatch::new();
        writes.delete(&key);
        self.commit(writes, true).await.context("durably erase a prevalence entity")?;
        Ok(true)
    }

    /// Create the tenant DB for a rebuild of the live set at `entry.seq`.
    /// The schema marker and the rebuild cursor land in one batch, so a
    /// crash leaves either no DB or a resumable rebuild.
    /// NAN-3781: a reset for a rebuild from the live set is in progress
    /// (possibly started by a previous process): finish it with
    /// [`Self::continue_reset`] before anything else reads or writes the state.
    pub fn reset_pending(&self) -> bool {
        self.reset_pending
    }

    /// NAN-3781: start emptying the state so it can be rebuilt from the live
    /// part set. Used when catch-up cannot replay the log: an `Add` after the
    /// cursor names a part that was merged away and whose partial was deleted
    /// while the state was unavailable. Its rows live on only in the merged
    /// successor, whose partial also holds rows the state already counted, so
    /// applying it would double-count; a rebuild from the live set is exact.
    /// Every store accepts it (deletes are tombstone writes, so it works
    /// through the owner protocol too). The marker is durable before any key
    /// is deleted.
    pub async fn begin_reset(&mut self) -> Result<()> {
        self.chunk_reads = None;
        if !self.reset_pending {
            let mut writes = WriteBatch::new();
            writes.put(RESET_KEY, b"1");
            self.commit(writes, true).await.context("durably mark the prevalence state for reset")?;
            self.reset_pending = true;
            self.reset_after = None;
        }
        Ok(())
    }

    /// Tombstone the state's keys in durable chunks until it is empty
    /// (`Ok(true)`: the state is new and [`Self::initialize_rebuild`] may
    /// run) or `deadline` passes (`Ok(false)`: the next call resumes).
    pub async fn continue_reset(&mut self, deadline: Option<std::time::Instant>) -> Result<bool> {
        ensure!(self.reset_pending, "no prevalence reset in progress");
        self.chunk_reads = None;
        loop {
            let mut iter = match &self.reset_after {
                None => self.db.scan(..).await?,
                Some(after) => {
                    let mut from = after.clone();
                    from.push(0);
                    self.db.scan(from..).await?
                }
            };
            let mut writes = WriteBatch::new();
            let (mut deleted, mut last, mut exhausted) = (0_usize, None, false);
            while deleted < RESET_CHUNK_KEYS {
                match iter.next().await? {
                    Some(entry) => {
                        if entry.key.as_ref() != RESET_KEY {
                            writes.delete(entry.key.as_ref());
                            deleted += 1;
                        }
                        last = Some(entry.key.to_vec());
                    }
                    None => {
                        exhausted = true;
                        break;
                    }
                }
            }
            drop(iter);
            if exhausted {
                // The marker goes with the last chunk: the state is empty.
                writes.delete(RESET_KEY);
                self.commit(writes, true).await.context("finish the prevalence reset")?;
                self.reset_pending = false;
                self.reset_after = None;
                self.created = true;
                self.watermark_us = None;
                return Ok(true);
            }
            self.commit(writes, true).await.context("tombstone prevalence keys for the reset")?;
            self.reset_after = last;
            if deadline.is_some_and(|deadline| std::time::Instant::now() >= deadline) {
                return Ok(false);
            }
        }
    }

    pub async fn initialize_rebuild(&mut self, entry: &EntryRef<'_>, parts: &[PartRef]) -> Result<()> {
        ensure!(self.created, "prevalence state already exists");
        self.chunk_reads = None;
        ensure!(parts.len() == entry.parts as usize, "prevalence rebuild part list differs from its entry");
        ensure!(entry.rebuild && crate::parts::is_sha256_hex(entry.sha256), "invalid prevalence rebuild entry");
        let cursor = Applied {
            seq: entry.seq,
            entry_sha256: entry.sha256.into(),
            rebuild: true,
            parts: entry.parts,
            next_part: 0,
            next_chunk: 0,
            part_sha256: None,
        };
        let mut writes = WriteBatch::new();
        writes.put(SCHEMA_KEY, format!("v1:{}", self.tenant_id).as_bytes());
        writes.put(APPLIED_KEY, serde_json::to_vec(&cursor)?);
        writes.put(REBUILD_PARTS_KEY, serde_json::to_vec(parts)?);
        self.commit(writes, true).await.context("durably initialize prevalence state")?;
        self.created = false;
        Ok(())
    }

    /// Close the writer (its credential is being withdrawn). The memtable
    /// is flushed to L0 first (bounded), so the next open replays only the
    /// WAL written after this point (NAN-3554).
    pub async fn close(mut self) -> Result<()> {
        self.flush_memtable_bounded("close").await;
        self.db.close_wal_only().await.context("close prevalence writer")?;
        Ok(())
    }

    /// Flush the memtable to an L0 SST so `replay_after_wal_id` advances
    /// past every WAL written so far.
    pub async fn flush_memtable(&mut self) -> Result<()> {
        self.db
            .flush_with_options(FlushOptions { flush_type: FlushType::MemTable })
            .await
            .context("flush prevalence memtable to L0")?;
        self.wal_flushes_since_l0 = 0;
        self.replayed_unflushed = false;
        self.last_l0_flush = std::time::Instant::now();
        self.last_flush = std::time::Instant::now();
        Ok(())
    }

    /// [`Self::flush_memtable`] within [`MEMTABLE_FLUSH_TIMEOUT`]; a
    /// failure is logged and leaves the WAL to replay. Returns whether it
    /// flushed.
    /// A failure backs the cadence off a full [`MEMTABLE_FLUSH_EVERY`]
    /// window (the memtable stays dirty), so a flush blocked on L0 room
    /// costs one bounded wait per window, never one per tick.
    pub async fn flush_memtable_bounded(&mut self, why: &str) -> bool {
        self.flush_memtable_within(MEMTABLE_FLUSH_TIMEOUT, why).await
    }

    /// [`Self::flush_memtable_bounded`] with a shorter wait (the ingest
    /// loop's prevalence budget, NAN-3774). Dropping the flush future is
    /// safe: SlateDB finishes or abandons the flush on its own, and the WAL
    /// stays replayable either way.
    pub async fn flush_memtable_within(&mut self, wait: std::time::Duration, why: &str) -> bool {
        let wait = wait.min(MEMTABLE_FLUSH_TIMEOUT);
        let outcome = tokio::time::timeout(wait, self.flush_memtable()).await;
        if !matches!(outcome, Ok(Ok(()))) {
            self.last_l0_flush = std::time::Instant::now();
            self.wal_flushes_since_l0 = 0;
            self.replayed_unflushed = true;
        }
        match outcome {
            Ok(Ok(())) => true,
            Ok(Err(error)) => {
                tracing::warn!(tenant = %self.tenant_id, error = %format!("{error:#}"), why,
                    "prevalence memtable flush failed; the next open replays its WAL");
                false
            }
            Err(_) => {
                tracing::warn!(tenant = %self.tenant_id, timeout_secs = wait.as_secs(), why,
                    "prevalence memtable flush timed out (L0 full?); the next open replays its WAL");
                false
            }
        }
    }

    /// The cadence flush is due: the memtable holds WAL that the next open
    /// would replay, and either [`MEMTABLE_FLUSH_EVERY`] has passed since
    /// the last L0 flush or [`MEMTABLE_FLUSH_AFTER_WALS`] WALs were written.
    pub fn memtable_flush_due(&self) -> bool {
        let dirty = self.replayed_unflushed || self.wal_flushes_since_l0 > 0;
        dirty
            && (self.wal_flushes_since_l0 >= MEMTABLE_FLUSH_AFTER_WALS
                || self.last_l0_flush.elapsed() >= MEMTABLE_FLUSH_EVERY)
    }

    /// SlateDB holds its S3 client for the writer lifetime. Close the old
    /// writer before opening the refreshed credential on the same prefix.
    pub async fn rotate_credential(
        &mut self,
        work_dir: &Path,
        access: &PrevalenceAccess,
    ) -> Result<()> {
        self.rotate_credential_with_reads(work_dir, access, None).await
    }

    /// [`Self::rotate_credential`] with [`Self::open_with_reads`]'s read store.
    pub async fn rotate_credential_with_reads(
        &mut self,
        work_dir: &Path,
        access: &PrevalenceAccess,
        reads: Option<Arc<dyn ObjectStore>>,
    ) -> Result<()> {
        // NAN-3554: flush first so the reopen below (and every later one)
        // replays only the WAL written since this rotation.
        self.flush_memtable_bounded("credential rotation").await;
        self.db
            .close_wal_only()
            .await
            .context("close prevalence writer for credential rotation")?;
        let next = Self::open_with_reads(&self.tenant_id, work_dir, Some(access), reads).await?;
        ensure!(
            !next.is_new(),
            "prevalence state disappeared during credential rotation"
        );
        *self = next;
        Ok(())
    }

    pub fn advance_watermark(&mut self, max_time_us: i64) {
        self.watermark_us = Some(
            self.watermark_us
                .map_or(max_time_us, |old| old.max(max_time_us)),
        );
    }

    /// Where `entry` stands against the cursor: `None` when it is already
    /// applied, otherwise the first part ordinal still to apply. Entries
    /// apply strictly in log order; an earlier incomplete entry refuses.
    pub async fn pending_from(&self, entry: &EntryRef<'_>) -> Result<Option<u32>> {
        Ok(self.position(entry).await?.map(|(part, _, _)| part))
    }

    async fn position(&self, entry: &EntryRef<'_>) -> Result<Option<(u32, u32, Option<String>)>> {
        let Some(cursor) = self.applied().await? else {
            return Ok((entry.parts > 0).then_some((0, 0, None)));
        };
        if entry.seq < cursor.seq {
            return Ok(None);
        }
        if entry.seq == cursor.seq {
            ensure!(
                cursor.entry_sha256 == entry.sha256
                    && cursor.rebuild == entry.rebuild
                    && cursor.parts == entry.parts,
                "prevalence state diverged from part-log entry {}",
                entry.seq
            );
            return Ok((cursor.next_part < cursor.parts)
                .then(|| (cursor.next_part, cursor.next_chunk, cursor.part_sha256.clone())));
        }
        ensure!(
            cursor.next_part == cursor.parts,
            "prevalence entry {} is incomplete; replay it before entry {}",
            cursor.seq,
            entry.seq
        );
        Ok((entry.parts > 0).then_some((0, 0, None)))
    }

    /// Apply one committed part of a committed log entry. Each chunk of rows
    /// and the advanced cursor share one durable SlateDB write, so a crash at
    /// any point resumes at the exact next chunk: replay never counts an
    /// occurrence or host twice. A different digest for a part that is
    /// already partly applied is fatal.
    pub async fn apply_part(
        &mut self,
        tenant_id: &str,
        entry: &EntryRef<'_>,
        index: u32,
        part_id: &str,
        path: &Path,
        max_time_us: i64,
    ) -> Result<()> {
        let complete = self.apply_part_until(tenant_id, entry, index, part_id, path, max_time_us, None).await?;
        ensure!(complete, "unbounded prevalence apply stopped early");
        Ok(())
    }

    /// [`Self::apply_part`] that yields after the chunk that passes
    /// `deadline` (at least one chunk per call). `Ok(false)`: the part is
    /// not finished; the cursor resumes it at the next chunk.
    #[allow(clippy::too_many_arguments)]
    pub async fn apply_part_until(
        &mut self,
        tenant_id: &str,
        entry: &EntryRef<'_>,
        index: u32,
        part_id: &str,
        path: &Path,
        max_time_us: i64,
        deadline: Option<std::time::Instant>,
    ) -> Result<bool> {
        ensure!(
            tenant_id == self.tenant_id,
            "prevalence part belongs to another tenant"
        );
        ensure!(!self.created, "prevalence state is not initialized");
        ensure!(valid_part_id(part_id), "invalid prevalence part id");
        ensure!(crate::parts::is_sha256_hex(entry.sha256) && index < entry.parts,
            "invalid prevalence entry reference");
        let Some((next_part, next_chunk, applied_digest)) = self.position(entry).await? else {
            return Ok(true);
        };
        if index < next_part {
            return Ok(true);
        }
        ensure!(index == next_part, "prevalence parts must apply in log order");
        let digest = digest_file(path)?;
        if let Some(applied) = applied_digest {
            ensure!(applied == digest, "prevalence part {part_id} was replayed with different content");
        }
        // A lost-DB rebuild can meet parts written before the 1,000-host
        // format. Skipping one undercounts (safe: artifacts look rarer);
        // failing would crash-loop ingest on every start.
        let legacy = entry.rebuild && is_legacy_partial(path)?;
        if legacy {
            tracing::warn!(tenant = %self.tenant_id, part_id, "rebuild skips a legacy host-cap prevalence partial");
        }
        // Resume at the next chunk without decoding the applied ones.
        let reader = ParquetRecordBatchReaderBuilder::try_new(File::open(path)?)?
            .with_batch_size(CHUNK_ROWS)
            .with_offset(next_chunk as usize * CHUNK_ROWS)
            .build()?;
        self.advance_watermark(max_time_us.min(watermark_ceiling_us()));
        let watermark = self.watermark_us.expect("set above");
        let floor = watermark.saturating_sub(INACTIVE_TTL_US);
        let (first_day, top_day) = (floor_day(watermark), day_of(watermark));
        let mut cursor = Applied {
            seq: entry.seq,
            entry_sha256: entry.sha256.into(),
            rebuild: entry.rebuild,
            parts: entry.parts,
            next_part: index,
            next_chunk: 0,
            part_sha256: Some(digest),
        };
        let mut batches = reader.enumerate().filter(|_| !legacy).peekable();
        while let Some((offset, batch)) = batches.next() {
            let chunk = u32::try_from(offset)
                .ok()
                .and_then(|offset| offset.checked_add(next_chunk))
                .context("prevalence partial has too many chunks")?;
            let batch = batch?;
            let rows = PrevalenceRow::from_batch(&batch)?;
            let mut batch_rows = BTreeMap::<Vec<u8>, WindowState>::new();
            for row in rows {
                validate_row(&row)?;
                if row.last_seen <= floor || row.is_private != 0 {
                    continue;
                }
                let key = key(&row.key.0, &row.key.2);
                let state = WindowState::from_row(&row, top_day);
                batch_rows
                    .entry(key)
                    .and_modify(|prior| prior.absorb(&state))
                    .or_insert(state);
            }
            // One bounded lane of point reads per chunk, in a task that
            // outlives a dropped step (NAN-3811, see [`ChunkReads`]).
            let chunk_key = ChunkKey {
                first_seq: entry.seq,
                seq: entry.seq,
                entry_sha256: entry.sha256.to_owned(),
                rebuild: entry.rebuild,
                index,
                part_sha256: cursor.part_sha256.clone().unwrap_or_default(),
                chunk,
            };
            let reads = self.read_chunk(chunk_key, batch_rows).await?;
            let mut writes = WriteBatch::new();
            let mut updates = Vec::with_capacity(reads.len());
            for (key, row, prior) in reads {
                let mut value = match prior.filter(|old| old.last_seen > floor) {
                    Some(mut prior) => {
                        prior.absorb(&row);
                        prior
                    }
                    None => row,
                };
                // Shed days (and their hosts) that left the 30-day window.
                value.prune(first_day, top_day);
                updates.push(self.put_state(&mut writes, key, &value));
            }
            cursor.next_chunk = chunk + 1;
            writes.put(APPLIED_KEY, serde_json::to_vec(&cursor)?);
            writes.put(
                WATERMARK_KEY,
                self.watermark_us.expect("set above").to_le_bytes(),
            );
            #[cfg(test)]
            self.maybe_crash()?;
            // One WAL flush per committed entry, at its last part's cursor
            // (below): WAL order makes every earlier chunk durable with it,
            // and a crash before it replays the entry from the durable
            // cursor, exactly like a rebuild step. NAN-3183: a durable flush
            // per chunk and per part was an owner round trip each (~0.45 s),
            // serial in every flush commit.
            let durable = self.last_flush.elapsed() >= REBUILD_FLUSH_EVERY;
            self.commit_with_values(writes, durable, Some(&updates)).await.context("durably apply committed prevalence chunk")?;
            // The chunk landed: its reads are spent (the next chunk reads
            // after this write).
            self.chunk_reads = None;
            if deadline.is_some_and(|deadline| std::time::Instant::now() >= deadline) && batches.peek().is_some() {
                return Ok(false);
            }
        }
        cursor.next_part = index + 1;
        cursor.next_chunk = 0;
        cursor.part_sha256 = None;
        let mut writes = WriteBatch::new();
        writes.put(APPLIED_KEY, serde_json::to_vec(&cursor)?);
        #[cfg(test)]
        self.maybe_crash()?;
        // The final part of an entry (a rebuild's too) is durable before
        // stamping.
        let durable = index + 1 == entry.parts || self.last_flush.elapsed() >= REBUILD_FLUSH_EVERY;
        self.commit_metadata(writes, durable).await.context("durably complete prevalence part")?;
        Ok(true)
    }

    /// Apply a partial as the next single-part entry. For tests and the
    /// offline resource probe only; ingest applies real log entries.
    #[doc(hidden)]
    pub async fn absorb_part_with_id(
        &mut self,
        tenant_id: &str,
        part_id: &str,
        path: &Path,
        max_time_us: i64,
    ) -> Result<()> {
        if self.created {
            self.initialize_at(0, &"0".repeat(64)).await?;
        }
        let seq = self.applied().await?.map_or(1, |cursor| cursor.seq + 1);
        let sha = digest_file(path)?;
        let entry = EntryRef { seq, sha256: &sha, rebuild: false, parts: 1 };
        self.apply_part(tenant_id, &entry, 0, part_id, path, max_time_us).await
    }

    #[cfg(test)]
    pub async fn absorb_part(&mut self, tenant_id: &str, path: &Path, max_time_us: i64) -> Result<()> {
        let part_id = path.file_stem().context("prevalence part has no file stem")?.to_string_lossy().into_owned();
        self.absorb_part_with_id(tenant_id, &part_id, path, max_time_us).await
    }

    /// Stage one entity's state, with its physical TTL when enabled.
    fn put_state(&self, writes: &mut WriteBatch, key: Vec<u8>, value: &WindowState) -> (Vec<u8>, bytes::Bytes) {
        let encoded = bytes::Bytes::from(encode(value));
        if self.physical_ttl {
            // SlateDB TTL uses milliseconds. Round expiry upward so
            // the exact microsecond read gate remains authoritative.
            let expiry_us = value.last_seen.saturating_add(INACTIVE_TTL_US);
            let expiry_ms = expiry_us.div_euclid(1_000)
                .saturating_add(i64::from(expiry_us.rem_euclid(1_000) != 0));
            writes.put_bytes_with_options(bytes::Bytes::copy_from_slice(&key), encoded.clone(), &PutOptions { ttl: Ttl::ExpireAt(expiry_ms) });
        } else {
            writes.put_bytes(bytes::Bytes::copy_from_slice(&key), encoded.clone());
        }
        (key, encoded)
    }

    /// NAN-3849: apply several whole committed `Add` entries, in log order,
    /// as ONE read pass and ONE atomic write.
    ///
    /// tenant-a (2026-10-14, after r51): the per-entry catch-up applied ~4
    /// entries a minute against ~2.6 committed a minute, so a 620-entry
    /// backlog took hours and L0 merges waited on it. Each entry paid its
    /// own point reads (most of its keys recur in the next entries: the same
    /// IPs, domains and hashes every flush), its own durable WAL flush (an
    /// owner round trip) and its own cursor bookkeeping. A batch folds the
    /// entries' rows in memory first (exactly as their sequential applies
    /// would combine them), reads each distinct key once, and writes every
    /// value with the cursor at the last entry's end in one `WriteBatch`: a
    /// crash before it lands applies none of the batch, after it all of it,
    /// so replay still never counts an entry twice.
    ///
    /// The reads run as the state's own task ([`Self::read_chunk`], keyed by
    /// the batch's first and last entry): a step cut at the ingest wait
    /// leaves them running and the next step with the same batch commits
    /// them, so the reads proceed between ticks instead of only inside them.
    ///
    /// Every row is filtered and clamped at its own part's watermark as the
    /// sequential apply does; the stored prior and the window prune use the
    /// batch's final watermark (the sequential result differs at most in the
    /// `first_seen` of an entity whose prior is exactly at the 30-day
    /// inactivity boundary inside the batch's watermark spread).
    pub async fn apply_entries_batch(&mut self, tenant_id: &str, batch: &[BatchEntry]) -> Result<BatchApplied> {
        self.apply_entries_batch_within(tenant_id, batch, None).await?
            .context("a catch-up batch without a read deadline always applies")
    }

    /// [`Self::apply_entries_batch`], waiting for the batch's reads at most
    /// until `patience`. `Ok(None)`: they are still running (in
    /// [`Self::chunk_reads`], like a step the ingest wait drops); the same
    /// batch picks them up later and commits.
    ///
    /// NAN-4464 (a large hosted tenant, 2026-10-23): a batch's reads take 15-24 s
    /// (they re-download ~the state). The step waited for them until the 5 s
    /// ingest wait cut it, on every tick, so ingest lost 5 s of each ~5.5 s
    /// tick while a batch read. The finished reads then waited for whichever
    /// step came next, usually the one after an ingest flush (~30 s apart).
    /// With a patience deadline the step returns while the reads run, and
    /// the caller skips its steps until they finish
    /// ([`Self::catch_up_reads_in_flight`]).
    pub async fn apply_entries_batch_within(&mut self, tenant_id: &str, batch: &[BatchEntry],
        patience: Option<std::time::Instant>) -> Result<Option<BatchApplied>> {
        ensure!(tenant_id == self.tenant_id, "prevalence part belongs to another tenant");
        ensure!(!self.created, "prevalence state is not initialized");
        let (first, last) = (batch.first().context("empty prevalence batch")?, batch.last().context("empty prevalence batch")?);
        let cursor = self.applied().await?.context("prevalence state has no replay cursor")?;
        ensure!(cursor.is_complete(), "prevalence entry {} is incomplete; replay it before a batch", cursor.seq);
        let mut previous = cursor.seq;
        for entry in batch {
            ensure!(entry.seq > previous, "prevalence batch entries must follow the cursor in log order");
            ensure!(crate::parts::is_sha256_hex(&entry.sha256) && !entry.parts.is_empty(),
                "invalid prevalence entry reference");
            ensure!(u32::try_from(entry.parts.len()).is_ok(), "too many parts in one add");
            for (part_id, _, _) in &entry.parts {
                ensure!(valid_part_id(part_id), "invalid prevalence part id");
            }
            previous = entry.seq;
        }
        let chunk_key = ChunkKey {
            first_seq: first.seq,
            seq: last.seq,
            entry_sha256: last.sha256.clone(),
            rebuild: false,
            index: u32::MAX,
            part_sha256: String::new(),
            chunk: u32::try_from(batch.len()).unwrap_or(u32::MAX),
        };
        // This batch's reads still running: wait for them (within
        // `patience`) before folding its partials again.
        if self.chunk_reads.as_ref().is_some_and(|reads| reads.key == chunk_key && reads.basis.as_ref() == Some(&cursor))
            && !self.await_chunk_reads(patience).await?
        {
            return Ok(None);
        }
        let started = std::time::Instant::now();
        let mut watermark = self.watermark_us;
        let mut folded = BTreeMap::<Vec<u8>, WindowState>::new();
        let (mut rows_total, mut parts_total) = (0_u64, 0_usize);
        for entry in batch {
            for (_, path, max_time_us) in &entry.parts {
                parts_total += 1;
                let clamped = (*max_time_us).min(watermark_ceiling_us());
                let mark = watermark.map_or(clamped, |old| old.max(clamped));
                watermark = Some(mark);
                let floor = mark.saturating_sub(INACTIVE_TTL_US);
                let top_day = day_of(mark);
                let reader = ParquetRecordBatchReaderBuilder::try_new(File::open(path)?)?
                    .with_batch_size(CHUNK_ROWS)
                    .build()?;
                for record in reader {
                    for row in PrevalenceRow::from_batch(&record?)? {
                        validate_row(&row)?;
                        rows_total += 1;
                        if row.last_seen <= floor || row.is_private != 0 {
                            continue;
                        }
                        let state = WindowState::from_row(&row, top_day);
                        match folded.get_mut(&key(&row.key.0, &row.key.2)) {
                            // The sequential apply drops a prior that left the
                            // window at this part's watermark.
                            Some(prior) if prior.last_seen > floor => prior.absorb(&state),
                            Some(prior) => *prior = state,
                            None => {
                                folded.insert(key(&row.key.0, &row.key.2), state);
                            }
                        }
                    }
                }
            }
        }
        let mark = watermark.context("prevalence batch has no watermark")?;
        let floor = mark.saturating_sub(INACTIVE_TTL_US);
        let (first_day, top_day) = (floor_day(mark), day_of(mark));
        let keys = folded.len();
        let fold_ms = started.elapsed().as_millis() as u64;
        let reading = std::time::Instant::now();
        let Some(reads) = self.read_chunk_within(chunk_key, folded, patience).await? else { return Ok(None) };
        let read_ms = reading.elapsed().as_millis() as u64;
        let mut writes = WriteBatch::new();
        let mut updates = Vec::with_capacity(reads.len());
        for (key, row, prior) in reads {
            let mut value = match prior.filter(|old| old.last_seen > floor) {
                Some(mut prior) => {
                    prior.absorb(&row);
                    prior
                }
                None => row,
            };
            value.prune(first_day, top_day);
            updates.push(self.put_state(&mut writes, key, &value));
        }
        let parts = u32::try_from(last.parts.len()).context("too many parts in one add")?;
        let cursor = Applied {
            seq: last.seq,
            entry_sha256: last.sha256.clone(),
            rebuild: false,
            parts,
            next_part: parts,
            next_chunk: 0,
            part_sha256: None,
        };
        writes.put(APPLIED_KEY, serde_json::to_vec(&cursor)?);
        writes.put(WATERMARK_KEY, mark.to_le_bytes());
        #[cfg(test)]
        self.maybe_crash()?;
        let writing = std::time::Instant::now();
        // Durable before stamping, like the last part of a single entry.
        self.commit_with_values(writes, true, Some(&updates)).await.context("durably apply a prevalence catch-up batch")?;
        self.chunk_reads = None;
        self.advance_watermark(mark);
        Ok(Some(BatchApplied {
            entries: batch.len(),
            parts: parts_total,
            rows: rows_total,
            keys,
            fold_ms,
            read_ms,
            write_ms: writing.elapsed().as_millis() as u64,
        }))
    }

    #[cfg(test)]
    pub(crate) async fn seed_io_pressure_for_test(&mut self, keys: usize) -> Result<()> {
        let mark = self.watermark_us.context("seed after real replay")?;
        let day = day_of(mark);
        for first in (0..keys).step_by(8_192) {
            let mut writes = WriteBatch::new();
            for k in first..(first+8_192).min(keys) {
                let artifact = crate::parts::sha256_hex(&(1_000_000_u64+k as u64).to_le_bytes());
                let value = WindowState { first_seen: mark, last_seen: mark, days: vec![(day,4)],
                    hosts: (0..4).map(|h| ((k*4+h) as u64,day)).collect() };
                writes.put(key("hash", &artifact), encode(&value));
            }
            self.commit(writes,true).await?;
        }
        self.flush_memtable().await
    }

    pub(crate) fn update_restamp_headroom(&self, lag_ms: i64, bound_ms: i64, l0_overdue_ms: i64) {
        self.restamp_budget.update(lag_ms, bound_ms, l0_overdue_ms);
    }
    pub(crate) fn read_stats(&self) -> Vec<super::prevalence_io::ReadStats> { self.read_counters.snapshot() }

    /// NAN-3873: whether SlateDB has closed this writer under us. SlateDB
    /// latches the first background error (a WAL or memtable flush the owner
    /// proxy refused or never answered, e.g. during an owner roll) as the
    /// DB's closed result, and from then on every read and write returns that
    /// cached error without touching the store. Retrying such a handle never
    /// recovers (tenant-a went 40 min with zero requests reaching the owner); the
    /// caller must drop it and reopen. Reads the status watch in place (no
    /// manifest clone).
    pub fn closed(&self) -> Option<slatedb::CloseReason> {
        self.db.subscribe().borrow().close_reason
    }

    /// Test-only: close the DB under the open state, as SlateDB does itself
    /// after a fatal background error.
    #[cfg(test)]
    pub async fn close_db_for_test(&self) {
        self.db.close().await.unwrap();
    }

    /// NAN-3811: point reads finished by apply-chunk read tasks so far (this
    /// writer). Advances while a slow chunk is still reading, so the ingest
    /// loop can tell a store that answers slowly from one that does not
    /// answer at all.
    /// Completed WAL durability barriers, never in-memory cache growth.
    pub(crate) fn watchdog_progress(&self) -> u64 {
        self.chunk_reads_done().saturating_add(self.durable_commits)
    }

    pub fn chunk_reads_done(&self) -> u64 {
        self.chunk_reads_done.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// The prior values of one apply chunk's keys. Reuses (or waits on) the
    /// read task a dropped step left for the same chunk; otherwise starts
    /// one. Cancel-safe: dropping this future leaves the task running in
    /// [`Self::chunk_reads`].
    ///
    /// NAN-3879 (production, 2026-10-15): a post-commit apply cut at the ingest wait
    /// left its reads keyed (entry, part, chunk); the next tick's catch-up
    /// batch keys (first entry, `u32::MAX`, entries), so it aborted them and
    /// read every key from R2 again. Reads left at the same cursor are now
    /// adopted by any chunk: their priors are reused key by key and only
    /// the keys they did not cover are read, so a cut apply's reads are
    /// never thrown away.
    async fn read_chunk(&mut self, key: ChunkKey, rows: BTreeMap<Vec<u8>, WindowState>) -> Result<Vec<ChunkRead>> {
        self.read_chunk_within(key, rows, None).await?.context("chunk reads without a deadline always finish")
    }

    /// NAN-4464: [`Self::read_chunk`], waiting at most until `patience`.
    /// `Ok(None)`: the reads keep running in [`Self::chunk_reads`].
    async fn read_chunk_within(&mut self, key: ChunkKey, rows: BTreeMap<Vec<u8>, WindowState>,
        patience: Option<std::time::Instant>) -> Result<Option<Vec<ChunkRead>>> {
        let basis = self.applied().await?;
        let reusable = self.chunk_reads.as_ref().is_some_and(|reads| reads.key == key && reads.basis == basis);
        if !reusable {
            // Reads at another cursor are stale: dropping them aborts them.
            let adopted = self.chunk_reads.take().filter(|reads| reads.basis == basis).map(ChunkReads::take_state);
            let adopted = match adopted {
                Some(ChunkReadState::Running(handle)) => Some(Err(AdoptedReads(handle))),
                Some(ChunkReadState::Ready(rows)) => Some(Ok(rows)),
                None => None,
            };
            let db = self.db.clone();
            let point_cache = self.point_cache.clone();
            let read_counters = self.read_counters.clone();
            let restamp_budget = self.restamp_budget.clone();
            let read_path = if key.index == u32::MAX { super::prevalence_io::ReadPath::CatchUp } else { super::prevalence_io::ReadPath::Apply };
            let done = self.chunk_reads_done.clone();
            #[cfg(test)]
            let delay = self.read_delay;
            let handle = tokio::spawn(async move {
                let _foreground = restamp_budget.foreground();
                let mut known = std::collections::HashMap::new();
                let adopted = match adopted {
                    Some(Ok(rows)) => Some(Ok(rows)),
                    Some(Err(mut task)) => Some((&mut task.0).await.map_err(anyhow::Error::from).and_then(|rows| rows)),
                    None => None,
                };
                // A failed adopted read only means reading those keys here.
                if let Some(Ok(rows)) = adopted {
                    known.extend(rows.into_iter().map(|(key, _, prior)| (key, prior)));
                }
                let (reuse, read): (Vec<_>, Vec<_>) = rows.into_iter().partition(|(key, _)| known.contains_key(key));
                let mut out = reuse.into_iter().map(|(key, row)| {
                    let prior = known.remove(&key).flatten();
                    (key, row, prior)
                }).collect::<Vec<_>>();
                // The fixture has millions of mostly unique keys; serial R2
                // reads would hold an otherwise small partial well beyond the
                // publication SLO.
                let fresh = stream::iter(read.into_iter().map(|(key, row)| {
                    let (db, done, point_cache, read_counters) = (db.clone(), done.clone(), point_cache.clone(), read_counters.clone());
                    async move {
                        #[cfg(test)]
                        if let Some(delay) = delay {
                            tokio::time::sleep(delay).await;
                        }
                        let prior = super::prevalence_io::read(&db, &point_cache, &read_counters, read_path, &key).await?.map(|value| decode(&value)).transpose()?;
                        done.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        Ok::<_, anyhow::Error>((key, row, prior))
                    }
                }))
                .buffer_unordered(APPLY_READS)
                .collect::<Vec<_>>()
                .await
                .into_iter()
                .collect::<Result<Vec<_>>>()?;
                out.extend(fresh);
                Ok(out)
            });
            // Replacing a stale task (another cursor) aborts it.
            self.chunk_reads = Some(ChunkReads { key, basis, state: ChunkReadState::Running(handle) });
        }
        if !self.await_chunk_reads(patience).await? {
            return Ok(None);
        }
        match &self.chunk_reads.as_ref().expect("set above").state {
            ChunkReadState::Ready(rows) => Ok(Some(rows.clone())),
            ChunkReadState::Running(_) => unreachable!("awaited above"),
        }
    }

    /// Wait for the reads in [`Self::chunk_reads`] (at most until
    /// `patience`) and keep their result. `Ok(false)`: still running.
    /// Cancel-safe: the task stays in place until it finishes.
    async fn await_chunk_reads(&mut self, patience: Option<std::time::Instant>) -> Result<bool> {
        let Some(reads) = self.chunk_reads.as_mut() else { return Ok(true) };
        let ChunkReadState::Running(handle) = &mut reads.state else { return Ok(true) };
        let outcome = match patience {
            None => handle.await,
            Some(patience) => match tokio::time::timeout_at(tokio::time::Instant::from_std(patience), &mut *handle).await {
                Ok(outcome) => outcome,
                Err(_) => return Ok(false),
            },
        };
        match outcome {
            Ok(Ok(rows)) => {
                reads.state = ChunkReadState::Ready(rows);
                Ok(true)
            }
            Ok(Err(error)) => {
                self.chunk_reads = None;
                Err(error.context("read prevalence chunk priors"))
            }
            Err(error) => {
                self.chunk_reads = None;
                Err(anyhow::anyhow!("prevalence chunk read task ended: {error}"))
            }
        }
    }

    /// NAN-4464: a chunk's or catch-up batch's reads are still running in
    /// the background (a step returned or was cut before they finished).
    pub fn catch_up_reads_in_flight(&self) -> bool {
        self.chunk_reads.as_ref().is_some_and(|reads| match &reads.state {
            ChunkReadState::Running(handle) => !handle.is_finished(),
            ChunkReadState::Ready(_) => false,
        })
    }

    /// Durable once the WAL SST is on object storage. Memtables still flush
    /// to L0 by size (32 MiB) for the maintenance compactor; a per-write L0
    /// would hit SlateDB's L0 cap and stall until compaction.
    /// Make every committed chunk durable now (the end of a rebuild step:
    /// a restart then resumes exactly where this step stopped).
    pub async fn make_durable(&mut self) -> Result<()> {
        self.db.flush_with_options(FlushOptions { flush_type: FlushType::Wal }).await?;
        self.point_cache.after_durability_barrier();
        self.durable_commits = self.durable_commits.saturating_add(1);
        self.last_flush = std::time::Instant::now();
        self.wal_flushes_since_l0 = self.wal_flushes_since_l0.saturating_add(1);
        Ok(())
    }

    async fn commit(&mut self, writes: WriteBatch, durable: bool) -> Result<()> {
        self.commit_with_values(writes, durable, None).await
    }

    async fn commit_with_values(&mut self, writes: WriteBatch, durable: bool, updates: Option<&[(Vec<u8>, bytes::Bytes)]>) -> Result<()> {
        self.point_cache.before_write(updates);
        self.db.write_with_options(writes, &WriteOptions { await_durable: false, ..WriteOptions::default() }).await?;
        self.point_cache.after_write(updates);
        if durable { self.make_durable().await?; }
        Ok(())
    }

    async fn commit_metadata(&mut self, writes: WriteBatch, durable: bool) -> Result<()> {
        self.db
            .write_with_options(writes, &WriteOptions { await_durable: false, ..WriteOptions::default() })
            .await?;
        if durable { self.make_durable().await?; }
        Ok(())
    }

    #[cfg(test)]
    fn maybe_crash(&mut self) -> Result<()> {
        if let Some(left) = self.crash_after_writes.as_mut() {
            anyhow::ensure!(*left > 0, "injected crash before prevalence write");
            *left -= 1;
        }
        Ok(())
    }

    /// NAN-4592: `(state SST bytes measured at open, disk cache bytes)`.
    pub fn object_cache_sizing(&self) -> (Option<u64>, u64) {
        (self.measured_state_bytes, self.object_cache_bytes)
    }

    pub fn disk_bytes(&self) -> Result<u64> {
        let Some(root) = &self.local_root else { return Ok(0) };
        let mut pending = vec![root.clone()];
        let mut bytes = 0_u64;
        while let Some(directory) = pending.pop() {
            for entry in std::fs::read_dir(directory)? {
                let entry = entry?;
                let kind = entry.file_type()?;
                if kind.is_dir() {
                    pending.push(entry.path());
                } else if kind.is_file() {
                    bytes = bytes.saturating_add(entry.metadata()?.len());
                }
            }
        }
        Ok(bytes)
    }

    pub fn check_parts(&self, tenant_id: &str, parts: &[(&Path, i64)]) -> Result<()> {
        ensure!(
            tenant_id == self.tenant_id,
            "prevalence part belongs to another tenant"
        );
        for (path, _) in parts {
            let reader = ParquetRecordBatchReaderBuilder::try_new(File::open(path)?)?
                .with_batch_size(CHUNK_ROWS)
                .build()?;
            for batch in reader {
                for row in PrevalenceRow::from_batch(&batch?)? {
                    validate_row(&row)?;
                }
            }
        }
        Ok(())
    }


    fn kind(artifact: &str) -> &'static str {
        if artifact.parse::<std::net::IpAddr>().is_ok() {
            "ip"
        } else if matches!(artifact.len(), 32 | 40 | 64)
            && artifact.bytes().all(|b| b.is_ascii_hexdigit())
        {
            "hash"
        } else {
            "domain"
        }
    }

    fn scalar(row: Option<&PrevalenceRow>) -> u64 {
        match row {
            Some(row) if row.hosts.len() >= PREVALENCE_HOST_CAP => COMMON,
            Some(row) => (row.hosts.len() as u64).clamp(1, 9_998),
            None => 1,
        }
    }

    /// Stamp from the committed snapshot available on arrival. No observation
    /// in this admission batch changes another row's stamp.
    pub async fn stamp(&self, event: &mut Value) -> Result<()> {
        self.stamp_all(std::iter::once(event)).await
    }

    /// Stamp an admission batch. Each distinct artifact is read once, with
    /// bounded concurrency, so the hot path never issues serial per-row
    /// object-store reads.
    pub async fn stamp_all<'e>(&self, events: impl IntoIterator<Item = &'e mut Value>) -> Result<()> {
        let mut events = events.into_iter().collect::<Vec<_>>();
        let artifacts = stamp_artifacts(events.iter().map(|event| &**event))?;
        let observed = self.lookup().observe(artifacts).await?;
        observed.stamp(events.iter_mut().map(|event| &mut **event))
    }

    /// NAN-3774: an owned read handle on this state's committed snapshot. Its
    /// lookups run as their own task, so admission waits on them only up to
    /// its budget and a slow read (cold cache, R2 timeouts) never holds the
    /// ingest loop: the batch goes unstamped and the read finishes (warming
    /// the cache) in the background.
    pub fn lookup(&self) -> PrevalenceLookup {
        PrevalenceLookup { db: self.db.clone(), point_cache: self.point_cache.clone(), read_counters: self.read_counters.clone(), restamp_budget: self.restamp_budget.clone(), main_read_policy: self.main_read_policy, watermark_us: self.watermark_us, rarity_threshold: self.rarity_threshold,
            #[cfg(test)]
            read_delay: None,
            #[cfg(test)]
            observe_delay: self.stamp_delay,
        }
    }

    fn stamp_from(observed: &BTreeMap<String, Option<PrevalenceRow>>, event: &mut Value, rarity_threshold: u64) -> Result<()> {
        let lookup = |artifact: &str| observed.get(artifact).and_then(Option::as_ref);
        let object = event
            .as_object_mut()
            .ok_or_else(|| anyhow::anyhow!("OCSF event is not an object"))?;
        for (column, value) in STAMP_COLUMNS.iter().zip(stamp_scalars(object, |artifact| Self::scalar(lookup(artifact)))) {
            object.insert((*column).to_owned(), json!(value));
        }
        let artifacts = stampable_artifacts(object);
        let entries = object
            .entry("enrichments")
            .or_insert_with(|| json!([]))
            .as_array_mut()
            .ok_or_else(|| anyhow::anyhow!("OCSF enrichments is not an array"))?;
        entries.retain(|entry| !is_our_stamp(entry));
        for (_path, artifact) in artifacts {
            if entries.iter().any(|entry| is_our_stamp(entry) && entry.get("value") == Some(&json!(artifact))) {
                continue;
            }
            let entry = match lookup(&artifact) {
                Some(row) => {
                    let result = crate::prevalence::prevalence_result(
                        Self::kind(&artifact),
                        &artifact,
                        row.hosts.len() as u64,
                        row.hosts.len() >= PREVALENCE_HOST_CAP,
                        false,
                        row.first_seen,
                        row.last_seen,
                        row.daily_count,
                        rarity_threshold,
                    )?;
                    observed_entry(&result)
                }
                None => new_artifact_entry(&artifact),
            };
            entries.push(entry);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::part_ingest::partials::write_sorted;
    use crate::parts::sidecar::host_fingerprint;
    use crate::prevalence_stamp::scalar_for;

    const TENANT_A: &str = "11111111-1111-4111-8111-111111111111";
    const TENANT_B: &str = "22222222-2222-4222-8222-222222222222";

    fn row(hosts: &[&str], day: i32) -> PrevalenceRow {
        let mut fingerprints = hosts
            .iter()
            .map(|host| host_fingerprint(host))
            .collect::<Vec<_>>();
        fingerprints.sort_unstable();
        PrevalenceRow {
            key: ("ip".into(), "source-a".into(), "8.8.8.8".into(), day),
            hosts: fingerprints,
            is_private: 0,
            first_seen: day as i64 * DAY_US,
            last_seen: day as i64 * DAY_US,
            daily_count: hosts.len() as u64,
        }
    }

    fn fake_part(n: u64) -> PartRef {
        PartRef {
            part_id: crate::parts::format::PartId::parse(&format!("{:013}-{:016x}", 1_000 + n, n)).unwrap(),
            level: crate::parts::levels::Level::L0,
            event_hour: 10,
            event_day: None,
            rows: 1,
            min_time_us: 1,
            max_time_us: 2,
            schema_fingerprint: "a".repeat(64),
            provenance_sha256: "b".repeat(64),
            merkle_root: "c".repeat(64),
            sorted: true,
            data_bytes: 1,
            row_groups: 1,
            data_files: 1,
        }
    }

    fn event(ip: &str) -> Value {
        json!({"dst_endpoint":{"ip":ip},"src_endpoint":{"hostname":"host-a"}})
    }

    fn scalar(event: &Value, name: &str) -> u64 {
        event[name].as_u64().expect("stamp scalar")
    }

    #[tokio::test]
    async fn committed_snapshot_stamps_immutably_and_restart_rebuilds_it() {
        let temp = tempfile::tempdir().unwrap();
        let part = temp.path().join("prevalence.parquet");
        write_sorted(vec![row(&["one", "two"], 10)], &part).unwrap();
        let mut state = IngestPrevalence::new(TENANT_A).await;
        let mut first = event("8.8.8.8");
        state.stamp(&mut first).await.unwrap();
        assert_eq!(scalar(&first, "prevalence_dest_ip"), 1);
        assert_eq!(scalar(&first, "prevalence_min"), 1);
        state
            .absorb_part(TENANT_A, &part, 10 * DAY_US)
            .await
            .unwrap();
        let mut second = event("8.8.8.8");
        state.stamp(&mut second).await.unwrap();
        assert_eq!(scalar(&second, "prevalence_dest_ip"), 2);
        assert_eq!(scalar(&first, "prevalence_dest_ip"), 1);
        let mut restarted = IngestPrevalence::new(TENANT_A).await;
        restarted
            .absorb_part(TENANT_A, &part, 10 * DAY_US)
            .await
            .unwrap();
        let mut late = event("8.8.8.8");
        restarted.stamp(&mut late).await.unwrap();
        assert_eq!(scalar(&late, "prevalence_dest_ip"), 2);
        assert_eq!(late["enrichments"][0]["data"]["as_of"], "ingest");
    }

    /// Stamp one 2-host and one 4-host artifact at `threshold`; their is_rare.
    async fn is_rare_at(threshold: u64) -> Vec<Value> {
        let temp = tempfile::tempdir().unwrap();
        let mut state = IngestPrevalence::new(TENANT_A).await;
        state.set_rarity_threshold(threshold);
        for (n, hosts) in [&["a", "b"][..], &["c", "d", "e", "f"][..]].into_iter().enumerate() {
            let part = temp.path().join(format!("prevalence-{n}.parquet"));
            let mut observed = row(hosts, 10);
            observed.key.2 = format!("8.8.8.{n}");
            write_sorted(vec![observed], &part).unwrap();
            state.absorb_part(TENANT_A, &part, 10 * DAY_US).await.unwrap();
        }
        let mut rare = Vec::new();
        for (n, hosts) in [(0, 2), (1, 4)] {
            let mut stamped = event(&format!("8.8.8.{n}"));
            state.stamp(&mut stamped).await.unwrap();
            assert_eq!(stamped["enrichments"][0]["data"]["host_count"], hosts);
            rare.push(stamped["enrichments"][0]["data"]["is_rare"].clone());
        }
        rare
    }

    /// NAN-3492: the ingest stamp's `is_rare` uses the tenant's threshold:
    /// 3 with no stored value (4 hosts is common, matching Search), and a
    /// stored value wins.
    #[tokio::test]
    async fn ingest_is_rare_uses_the_tenant_threshold() {
        use crate::prevalence::rarity_threshold_for;
        assert_eq!(rarity_threshold_for(None), 3);
        assert_eq!(rarity_threshold_for(Some(5)), 5, "a stored value wins");
        assert_eq!(rarity_threshold_for(Some(0)), 3, "an out-of-range stored value is ignored");
        assert_eq!(rarity_threshold_for(Some(10_001)), 3, "an out-of-range stored value is ignored");

        assert_eq!(is_rare_at(rarity_threshold_for(None)).await, vec![json!(true), json!(false)]);
        assert_eq!(is_rare_at(rarity_threshold_for(Some(5))).await, vec![json!(true), json!(true)]);
        // Nothing set: the default 3.
        let mut unset = IngestPrevalence::new(TENANT_B).await;
        assert_eq!(unset.rarity_threshold, 3);
        unset.set_rarity_threshold(5);
        assert_eq!(unset.rarity_threshold, 5);
    }

    /// The default is 3 in both modes (hosted: `control_url` set;
    /// trusted-local: absent), and a stored placement value wins in both.
    #[test]
    fn assignment_threshold_is_stored_value_else_3_in_every_mode() {
        use crate::prevalence::assignment_rarity_threshold;
        let assignment = |control_url: Option<&str>, stored: Option<u64>| {
            let mut value = json!({
                "tenant": TENANT_A, "role": "ingest", "cell_id": "c", "tenant_dir": "/d", "parts_dir": "/d/p",
                "state_dir": "/d/s", "tmp_dir": "/d/t", "memory_cap_bytes": 1, "cpu_millis": 1, "eps": 1.0,
                "jail": {"uid": 1, "gid": 1, "rw_paths": [], "ro_paths": [], "system_ro_paths": [], "tcp_connect_ports": [],
                    "cgroup_dir": null, "require_landlock": true, "max_processes": null, "max_open_files": 1}
            });
            if let Some(url) = control_url {
                value["control_url"] = json!(url);
            }
            if let Some(stored) = stored {
                value["prevalence_rarity_threshold"] = json!(stored);
            }
            serde_json::from_value::<nanosiem_lake_cell::contract::Assignment>(value).unwrap()
        };
        let hosted = Some("https://control.example");
        assert_eq!(assignment_rarity_threshold(&assignment(hosted, None)), 3);
        assert_eq!(assignment_rarity_threshold(&assignment(hosted, Some(7))), 7);
        assert_eq!(assignment_rarity_threshold(&assignment(None, None)), 3);
        assert_eq!(assignment_rarity_threshold(&assignment(None, Some(4))), 4);
    }

    #[tokio::test]
    async fn tenant_mismatch_and_private_ip_cannot_inherit_another_tenants_count() {
        let temp = tempfile::tempdir().unwrap();
        let part = temp.path().join("prevalence.parquet");
        write_sorted(vec![row(&["one", "two"], 10)], &part).unwrap();
        let mut other = IngestPrevalence::new(TENANT_B).await;
        assert!(other
            .absorb_part(TENANT_A, &part, 10 * DAY_US)
            .await
            .is_err());
        let mut public = event("8.8.8.8");
        other.stamp(&mut public).await.unwrap();
        assert_eq!(scalar(&public, "prevalence_dest_ip"), 1);
        let mut private = event("172.20.0.1");
        other.stamp(&mut private).await.unwrap();
        assert_eq!(scalar(&private, "prevalence_dest_ip"), NA);
        assert_eq!(scalar(&private, "prevalence_min"), COMMON);
        let mut forged = event("8.8.8.8");
        forged["enrichments"] = json!([{"name":"prevalence","provider":"nano",
            "value":"8.8.8.8","data":{"host_count":9999}}]);
        other.stamp(&mut forged).await.unwrap();
        assert_eq!(forged["enrichments"].as_array().unwrap().len(), 1);
        assert_eq!(forged["enrichments"][0]["data"]["host_count"], 1);
    }

    #[tokio::test]
    async fn erasure_revokes_cached_values_even_when_the_db_key_is_already_absent() {
        let temp = tempfile::tempdir().unwrap();
        let part = temp.path().join("prevalence.parquet");
        write_sorted(vec![row(&["one", "two"], 10)], &part).unwrap();
        let mut state = IngestPrevalence::open(TENANT_A, temp.path(), None).await.unwrap();
        state.absorb_part(TENANT_A, &part, 10 * DAY_US).await.unwrap();
        let mut seen = event("8.8.8.8");
        state.stamp(&mut seen).await.unwrap();
        assert_eq!(scalar(&seen, "prevalence_dest_ip"), 2);
        // Emulate physical expiry below the application cache. Explicit
        // erasure must revoke its value even though no DB row remains.
        let mut expired = WriteBatch::new();
        expired.delete(key("ip", "8.8.8.8"));
        state.db.write_with_options(expired, &WriteOptions { await_durable: false, ..WriteOptions::default() }).await.unwrap();
        state.make_durable().await.unwrap();
        assert!(!state.erase_artifact("ip", "8.8.8.8").await.unwrap());
        state.stamp(&mut seen).await.unwrap();
        assert_eq!(scalar(&seen, "prevalence_dest_ip"), 1);
        state.absorb_part(TENANT_A, &part, 10 * DAY_US).await.unwrap();
        assert!(state.erase_artifact("ip", "8.8.8.8").await.unwrap());
        state.stamp(&mut seen).await.unwrap();
        assert_eq!(scalar(&seen, "prevalence_dest_ip"), 1);
        state.close().await.unwrap();
    }

    /// NAN-3213 end to end: ingest partials built with the observer identity
    /// feed only their own tenant's state; the workstation's hostname is never
    /// looked up as a domain; a destination's count is its observing devices.
    #[tokio::test]
    async fn observer_keyed_partials_stay_tenant_private() {
        let temp = tempfile::tempdir().unwrap();
        let events = ["ws-legal-066.corp.local", "ws-hr-012.corp.local"]
            .iter()
            .enumerate()
            .map(|(i, host)| json!({"time":"1970-01-11T00:00:00Z","metadata":{"uid":format!("u{i}"),"log_source":"s"},
                "src_endpoint":{"ip":format!("10.1.3.{i}"),"hostname":host},"dst_endpoint":{"ip":"8.8.8.8"}}))
            .collect::<Vec<_>>();
        let refs = events.iter().collect::<Vec<_>>();
        let schema = Arc::new(crate::part_ingest::schema::infer_schema(&refs).unwrap());
        let batch = crate::part_ingest::schema::decode(schema, &refs).unwrap();
        let mut partials = super::super::partials::RowPartials::new();
        partials.add_batch(&batch).unwrap();
        let part_dir = temp.path().join("part");
        partials.write(&part_dir).unwrap();
        let part = part_dir.join(crate::parts::format::PARTIAL_PREVALENCE_FILE);

        let mut a = IngestPrevalence::new(TENANT_A).await;
        a.absorb_part(TENANT_A, &part, 10 * DAY_US).await.unwrap();
        let mut seen = json!({"dst_endpoint":{"ip":"8.8.8.8"},"src_endpoint":{"hostname":"ws-legal-066.corp.local"}});
        a.stamp(&mut seen).await.unwrap();
        assert_eq!(scalar(&seen, "prevalence_dest_ip"), 2, "two observing workstations");
        assert!(seen["enrichments"].as_array().unwrap().iter().all(|e| e["value"] != "ws-legal-066.corp.local"),
            "the event's own hostname is not a domain lookup: {seen}");

        let mut b = IngestPrevalence::new(TENANT_B).await;
        assert!(b.absorb_part(TENANT_A, &part, 10 * DAY_US).await.is_err());
        let mut other = json!({"dst_endpoint":{"ip":"8.8.8.8"},"src_endpoint":{"hostname":"host-b"}});
        b.stamp(&mut other).await.unwrap();
        assert_eq!(scalar(&other, "prevalence_dest_ip"), 1, "tenant B inherits nothing from tenant A");
    }

    #[tokio::test]
    async fn clickhouse_threshold_and_gen1_unseen_parity() {
        let temp = tempfile::tempdir().unwrap();
        let part = temp.path().join("prevalence.parquet");
        let hosts = (0..PREVALENCE_HOST_CAP)
            .map(|i| format!("host-{i}"))
            .collect::<Vec<_>>();
        let refs = hosts.iter().map(String::as_str).collect::<Vec<_>>();
        write_sorted(vec![row(&refs, 10)], &part).unwrap();
        let mut state = IngestPrevalence::new(TENANT_A).await;
        state
            .absorb_part(TENANT_A, &part, 10 * DAY_US)
            .await
            .unwrap();
        let mut saturated = event("8.8.8.8");
        state.stamp(&mut saturated).await.unwrap();
        let reference = crate::prevalence::prevalence_result(
            "ip",
            "8.8.8.8",
            PREVALENCE_HOST_CAP as u64,
            true,
            false,
            10 * DAY_US,
            10 * DAY_US,
            PREVALENCE_HOST_CAP as u64,
            5,
        )
        .unwrap();
        assert_eq!(
            scalar(&saturated, "prevalence_dest_ip"),
            scalar_for(Some(&reference))
        );
        assert_eq!(scalar_for(None), 1);
        assert_eq!(
            saturated["enrichments"][0]["data"]["host_count_saturated"],
            true
        );
    }

    #[tokio::test]
    async fn counts_beyond_legacy_bronze_cap_and_across_part_merges() {
        let temp = tempfile::tempdir().unwrap();
        let first = temp.path().join("first.parquet");
        let second = temp.path().join("second.parquet");
        let hosts = (0..999).map(|i| format!("host-{i}")).collect::<Vec<_>>();
        let refs = hosts.iter().map(String::as_str).collect::<Vec<_>>();
        write_sorted(vec![row(&refs[..500], 10)], &first).unwrap();
        write_sorted(vec![row(&refs[499..], 10)], &second).unwrap();
        let mut state = IngestPrevalence::new(TENANT_A).await;
        state
            .absorb_part(TENANT_A, &first, 10 * DAY_US)
            .await
            .unwrap();
        let mut mid = event("8.8.8.8");
        state.stamp(&mut mid).await.unwrap();
        assert_eq!(scalar(&mid, "prevalence_dest_ip"), 500);
        state
            .absorb_part(TENANT_A, &second, 10 * DAY_US)
            .await
            .unwrap();
        let mut below = event("8.8.8.8");
        state.stamp(&mut below).await.unwrap();
        assert_eq!(scalar(&below, "prevalence_dest_ip"), 999);
        assert_eq!(
            below["enrichments"][0]["data"]["host_count_saturated"],
            false
        );

        let third = temp.path().join("third.parquet");
        write_sorted(vec![row(&["host-999"], 10)], &third).unwrap();
        state
            .absorb_part(TENANT_A, &third, 10 * DAY_US)
            .await
            .unwrap();
        let mut common = event("8.8.8.8");
        state.stamp(&mut common).await.unwrap();
        assert_eq!(scalar(&common, "prevalence_dest_ip"), COMMON);
        assert_eq!(scalar(&below, "prevalence_dest_ip"), 999);
    }

    #[tokio::test]
    async fn all_four_fields_are_stamped_and_file_process_share_hash_state() {
        let temp = tempfile::tempdir().unwrap();
        let part = temp.path().join("prevalence.parquet");
        let hash = "a".repeat(64);
        let mut hash_row = row(&["h1", "h2", "h3"], 10);
        hash_row.key.0 = "hash".into();
        hash_row.key.2 = hash.clone();
        let mut domain_row = row(&["h1", "h2"], 10);
        domain_row.key.0 = "domain".into();
        domain_row.key.2 = "evil.example".into();
        let ip_row = row(&["h1", "h2", "h3", "h4"], 10);
        write_sorted(vec![hash_row, domain_row, ip_row], &part).unwrap();
        let mut state = IngestPrevalence::new(TENANT_A).await;
        state
            .absorb_part(TENANT_A, &part, 10 * DAY_US)
            .await
            .unwrap();
        let mut event = json!({
            "file":{"hashes":[{"algorithm":"SHA-256","value":hash}]},
            "process":{"file":{"hashes":[{"algorithm":"SHA-256","value":hash}]}},
            "dst_endpoint":{"hostname":"Evil.Example","ip":"8.8.8.8"}
        });
        state.stamp(&mut event).await.unwrap();
        assert_eq!(scalar(&event, "prevalence_file_hash"), 3);
        assert_eq!(scalar(&event, "prevalence_process_hash"), 3);
        assert_eq!(scalar(&event, "prevalence_dest_domain"), 2);
        assert_eq!(scalar(&event, "prevalence_dest_ip"), 4);
        assert_eq!(scalar(&event, "prevalence_min"), 2);
    }

    #[tokio::test]
    async fn late_rows_use_arrival_snapshot_across_utc_day_boundary() {
        let temp = tempfile::tempdir().unwrap();
        let prior = temp.path().join("prior.parquet");
        let next = temp.path().join("next.parquet");
        write_sorted(vec![row(&["h1"], 100)], &prior).unwrap();
        write_sorted(vec![row(&["h2"], 101)], &next).unwrap();
        let mut state = IngestPrevalence::new(TENANT_A).await;
        state
            .absorb_part(TENANT_A, &next, 101 * DAY_US)
            .await
            .unwrap();
        let mut late = event("8.8.8.8");
        state.stamp(&mut late).await.unwrap();
        assert_eq!(scalar(&late, "prevalence_dest_ip"), 1);
        state
            .absorb_part(TENANT_A, &prior, 100 * DAY_US)
            .await
            .unwrap();
        let mut after_late_commit = event("8.8.8.8");
        state.stamp(&mut after_late_commit).await.unwrap();
        assert_eq!(scalar(&after_late_commit, "prevalence_dest_ip"), 2);
        assert_eq!(scalar(&late, "prevalence_dest_ip"), 1);
        let mut restarted = IngestPrevalence::new(TENANT_A).await;
        restarted
            .absorb_part(TENANT_A, &prior, 100 * DAY_US)
            .await
            .unwrap();
        restarted
            .absorb_part(TENANT_A, &next, 101 * DAY_US)
            .await
            .unwrap();
        let mut replay = event("8.8.8.8");
        restarted.stamp(&mut replay).await.unwrap();
        assert_eq!(scalar(&replay, "prevalence_dest_ip"), 2);
    }

    #[tokio::test]
    async fn cumulative_hosts_expire_only_after_entity_is_inactive_for_30_days() {
        let temp = tempfile::tempdir().unwrap();
        let first = temp.path().join("first.parquet");
        let active = temp.path().join("active.parquet");
        let unrelated = temp.path().join("unrelated.parquet");
        write_sorted(vec![row(&["old"], 10)], &first).unwrap();
        write_sorted(vec![row(&["new"], 39)], &active).unwrap();
        let mut other = row(&["other"], 70);
        other.key.2 = "1.1.1.1".into();
        write_sorted(vec![other], &unrelated).unwrap();
        let mut state = IngestPrevalence::new(TENANT_A).await;
        state
            .absorb_part(TENANT_A, &first, 10 * DAY_US)
            .await
            .unwrap();
        state
            .absorb_part(TENANT_A, &active, 39 * DAY_US)
            .await
            .unwrap();
        let mut within = event("8.8.8.8");
        state.stamp(&mut within).await.unwrap();
        assert_eq!(scalar(&within, "prevalence_dest_ip"), 2);
        state
            .absorb_part(TENANT_A, &unrelated, 70 * DAY_US)
            .await
            .unwrap();
        let mut expired = event("8.8.8.8");
        state.stamp(&mut expired).await.unwrap();
        assert_eq!(scalar(&expired, "prevalence_dest_ip"), 1);
        state
            .absorb_part(TENANT_A, &first, 10 * DAY_US)
            .await
            .unwrap();
        let mut late = event("8.8.8.8");
        state.stamp(&mut late).await.unwrap();
        assert_eq!(scalar(&late, "prevalence_dest_ip"), 1);
    }

    #[tokio::test]
    async fn inactive_ttl_uses_exact_microsecond_boundary() {
        let temp = tempfile::tempdir().unwrap();
        let part = temp.path().join("boundary.parquet");
        write_sorted(vec![row(&["one", "two"], 10)], &part).unwrap();
        let mut state = IngestPrevalence::new(TENANT_A).await;
        state
            .absorb_part(TENANT_A, &part, 10 * DAY_US)
            .await
            .unwrap();
        state.advance_watermark(40 * DAY_US - 1);
        let mut at_boundary = event("8.8.8.8");
        state.stamp(&mut at_boundary).await.unwrap();
        assert_eq!(scalar(&at_boundary, "prevalence_dest_ip"), 2);
        state.advance_watermark(40 * DAY_US);
        let mut after_boundary = event("8.8.8.8");
        state.stamp(&mut after_boundary).await.unwrap();
        assert_eq!(scalar(&after_boundary, "prevalence_dest_ip"), 1);
    }

    #[tokio::test]
    async fn durable_state_reopens_and_entry_replay_does_not_double_count() {
        let temp = tempfile::tempdir().unwrap();
        let part = temp.path().join("part.parquet");
        write_sorted(vec![row(&["one", "two"], 10)], &part).unwrap();
        let mut state = IngestPrevalence::open(TENANT_A, temp.path(), None)
            .await
            .unwrap();
        assert!(state.is_new());
        state.initialize_at(0, &"0".repeat(64)).await.unwrap();
        let sha = "1".repeat(64);
        let entry = EntryRef { seq: 1, sha256: &sha, rebuild: false, parts: 1 };
        state.apply_part(TENANT_A, &entry, 0, "p1", &part, 10 * DAY_US).await.unwrap();
        drop(state);
        let mut restarted = IngestPrevalence::open(TENANT_A, temp.path(), None)
            .await
            .unwrap();
        assert!(!restarted.is_new());
        let cursor = restarted.applied().await.unwrap().unwrap();
        assert_eq!((cursor.seq, cursor.is_complete()), (1, true));
        assert_eq!(restarted.pending_from(&entry).await.unwrap(), None);
        let mut before = event("8.8.8.8");
        restarted.stamp(&mut before).await.unwrap();
        assert_eq!(scalar(&before, "prevalence_dest_ip"), 2);
        assert!(restarted
            .apply_part(TENANT_B, &entry, 0, "p1", &part, 10 * DAY_US)
            .await
            .is_err());
        // Replaying the same committed entry is a no-op.
        restarted.apply_part(TENANT_A, &entry, 0, "p1", &part, 10 * DAY_US).await.unwrap();
        let mut after = event("8.8.8.8");
        restarted.stamp(&mut after).await.unwrap();
        assert_eq!(scalar(&after, "prevalence_dest_ip"), 2);
        assert_eq!(after["enrichments"][0]["data"]["total_occurrences"], 2);
    }

    #[tokio::test]
    async fn crash_between_chunks_resumes_at_the_next_chunk() {
        let temp = tempfile::tempdir().unwrap();
        let part = temp.path().join("part.parquet");
        // 8,192 filler rows fill chunk 0; 8.8.8.8 sorts into chunk 1.
        let mut rows = (0..CHUNK_ROWS)
            .map(|i| {
                let mut filler = row(&["filler"], 10);
                filler.key.2 = format!("1.0.{}.{}", i / 256, i % 256);
                filler
            })
            .collect::<Vec<_>>();
        rows.push(row(&["one", "two"], 10));
        write_sorted(rows, &part).unwrap();
        let store: Arc<dyn ObjectStore> = Arc::new(InMemory::new());
        let mut state = IngestPrevalence::open_shared(TENANT_A, store.clone()).await.unwrap();
        state.initialize_at(0, &"0".repeat(64)).await.unwrap();
        let sha = "2".repeat(64);
        let entry = EntryRef { seq: 1, sha256: &sha, rebuild: false, parts: 1 };
        // Live chunks are durable with their entry's end or on the flush
        // timer (NAN-3183): due now, so chunk 0 is durable before the crash.
        state.last_flush = std::time::Instant::now() - REBUILD_FLUSH_EVERY;
        state.crash_after_writes = Some(1);
        assert!(state.apply_part(TENANT_A, &entry, 0, "p1", &part, 10 * DAY_US).await.is_err());
        let cursor = state.applied().await.unwrap().unwrap();
        assert_eq!((cursor.next_part, cursor.next_chunk), (0, 1));
        drop(state);
        let mut resumed = IngestPrevalence::open_shared(TENANT_A, store).await.unwrap();
        let mut unseen = event("8.8.8.8");
        resumed.stamp(&mut unseen).await.unwrap();
        assert_eq!(scalar(&unseen, "prevalence_dest_ip"), 1);
        // A different partial under the same half-applied entry is refused.
        let changed = temp.path().join("changed.parquet");
        write_sorted(vec![row(&["one"], 10)], &changed).unwrap();
        assert!(resumed.apply_part(TENANT_A, &entry, 0, "p1", &changed, 10 * DAY_US).await.is_err());
        // A later entry cannot jump an incomplete one.
        let later = EntryRef { seq: 2, sha256: &sha, rebuild: false, parts: 1 };
        assert!(resumed.apply_part(TENANT_A, &later, 0, "p2", &part, 10 * DAY_US).await.is_err());
        resumed.apply_part(TENANT_A, &entry, 0, "p1", &part, 10 * DAY_US).await.unwrap();
        let mut seen = event("8.8.8.8");
        resumed.stamp(&mut seen).await.unwrap();
        assert_eq!(scalar(&seen, "prevalence_dest_ip"), 2);
        let mut filler = event("1.0.0.1");
        resumed.stamp(&mut filler).await.unwrap();
        assert_eq!(filler["enrichments"][0]["data"]["total_occurrences"], 1, "chunk 0 applied once");
    }

    /// NAN-3183: a live entry is made durable once, at its last part. A
    /// crash before that loses the whole entry from the state (nothing of it
    /// is durable) and the replay applies every chunk exactly once.
    #[tokio::test]
    async fn crash_before_a_live_entry_is_durable_replays_it_whole_once() {
        let temp = tempfile::tempdir().unwrap();
        let part = temp.path().join("part.parquet");
        let mut rows = (0..CHUNK_ROWS)
            .map(|i| {
                let mut filler = row(&["filler"], 10);
                filler.key.2 = format!("1.0.{}.{}", i / 256, i % 256);
                filler
            })
            .collect::<Vec<_>>();
        rows.push(row(&["one", "two"], 10));
        write_sorted(rows, &part).unwrap();
        let second = temp.path().join("second.parquet");
        write_sorted(vec![row(&["three"], 10)], &second).unwrap();
        let store: Arc<dyn ObjectStore> = Arc::new(InMemory::new());
        let mut state = IngestPrevalence::open_shared(TENANT_A, store.clone()).await.unwrap();
        state.initialize_at(0, &"0".repeat(64)).await.unwrap();
        let sha = "2".repeat(64);
        let entry = EntryRef { seq: 1, sha256: &sha, rebuild: false, parts: 2 };
        state.last_flush = std::time::Instant::now();
        // Both chunks of part 0 and its completion land; part 1 crashes.
        state.crash_after_writes = Some(3);
        state.apply_part(TENANT_A, &entry, 0, "p1", &part, 10 * DAY_US).await.unwrap();
        assert!(state.apply_part(TENANT_A, &entry, 1, "p2", &second, 10 * DAY_US).await.is_err());
        drop(state);
        let mut resumed = IngestPrevalence::open_shared(TENANT_A, store).await.unwrap();
        let cursor = resumed.applied().await.unwrap().unwrap();
        assert_eq!((cursor.seq, cursor.next_part), (0, 0), "nothing of the undurable entry survived");
        let mut unseen = event("8.8.8.8");
        resumed.stamp(&mut unseen).await.unwrap();
        assert_eq!(scalar(&unseen, "prevalence_dest_ip"), 1);
        resumed.apply_part(TENANT_A, &entry, 0, "p1", &part, 10 * DAY_US).await.unwrap();
        resumed.apply_part(TENANT_A, &entry, 1, "p2", &second, 10 * DAY_US).await.unwrap();
        let mut seen = event("8.8.8.8");
        resumed.stamp(&mut seen).await.unwrap();
        // Hosts one, two (part 0) and three (part 1).
        assert_eq!(scalar(&seen, "prevalence_dest_ip"), 3);
        let mut filler = event("1.0.0.1");
        resumed.stamp(&mut filler).await.unwrap();
        assert_eq!(filler["enrichments"][0]["data"]["total_occurrences"], 1, "chunk 0 applied once");
    }

    /// NAN-3811 (tenant-a 2026-10-14): a chunk whose point reads outlast the
    /// ingest wait. Every attempt is cut at the wait, as the tick does; the
    /// reads keep running between attempts and the next attempt commits
    /// them, so the chunk lands with each key read exactly once. Before the
    /// fix every cut threw the reads away and the chunk never finished.
    #[tokio::test]
    async fn an_apply_cut_at_the_ingest_wait_resumes_its_reads_instead_of_restarting() {
        let temp = tempfile::tempdir().unwrap();
        let part = temp.path().join("part.parquet");
        let keys = 300_usize;
        let rows = (0..keys)
            .map(|i| {
                let mut filler = row(&["one"], 10);
                filler.key.2 = format!("1.1.{}.{}", i / 256, i % 256);
                filler
            })
            .collect::<Vec<_>>();
        write_sorted(rows, &part).unwrap();
        let store: Arc<dyn ObjectStore> = Arc::new(InMemory::new());
        let mut state = IngestPrevalence::open_shared(TENANT_A, store).await.unwrap();
        state.initialize_at(0, &"0".repeat(64)).await.unwrap();
        // 300 keys, 64 reads in flight, 150 ms each: ~750 ms of reads per
        // attempt-free chunk, against a 100 ms wait per attempt.
        state.read_delay = Some(std::time::Duration::from_millis(150));
        let sha = "5".repeat(64);
        let entry = EntryRef { seq: 1, sha256: &sha, rebuild: false, parts: 1 };
        let wait = std::time::Duration::from_millis(100);
        let mut attempts = 0;
        loop {
            attempts += 1;
            assert!(attempts <= 40, "the chunk never landed: every cut restarted its reads");
            let attempt = tokio::time::timeout(wait,
                state.apply_part_until(TENANT_A, &entry, 0, "p1", &part, 10 * DAY_US, None)).await;
            match attempt {
                Ok(result) => {
                    assert!(result.unwrap(), "one chunk: the part completes");
                    break;
                }
                // Cut at the wait: the reads must still be advancing.
                Err(_) => assert!(state.chunk_reads.is_some(), "a cut keeps the chunk's reads"),
            }
        }
        assert!(attempts > 1, "the reads outlast one wait (the test exercises a cut)");
        assert_eq!(state.chunk_reads_done(), keys as u64, "every key was read exactly once across the cuts");
        assert!(state.chunk_reads.is_none(), "a committed chunk drops its reads");
        let cursor = state.applied().await.unwrap().unwrap();
        assert_eq!((cursor.seq, cursor.next_part), (1, 1));
        let mut seen = event("1.1.0.7");
        state.stamp(&mut seen).await.unwrap();
        assert_eq!(seen["enrichments"][0]["data"]["total_occurrences"], 1, "applied once");
    }

    /// NAN-3849: `entries` partials of `shared` recurring keys plus `unique`
    /// keys of their own, each seen by that entry's host.
    /// The ingest loop's default wait on one prevalence operation.
    const PREVALENCE_TEST_INGEST_WAIT: std::time::Duration = std::time::Duration::from_secs(5);

    fn backlog(dir: &Path, entries: usize, shared: usize, unique: usize) -> Vec<BatchEntry> {
        (0..entries).map(|n| {
            let host = format!("host-{n}");
            let rows = (0..shared).map(|i| format!("1.2.{}.{}", i / 256, i % 256))
                .chain((0..unique).map(|i| format!("1.3.{n}.{i}")))
                .map(|ip| {
                    let mut row = row(&[host.as_str()], 10);
                    row.key.2 = ip;
                    row
                })
                .collect::<Vec<_>>();
            let path = dir.join(format!("entry-{n}.parquet"));
            write_sorted(rows, &path).unwrap();
            BatchEntry {
                seq: n as u64 + 1,
                sha256: format!("{:064x}", n + 1),
                parts: vec![(format!("p{n}"), path, 10 * DAY_US + n as i64)],
            }
        }).collect()
    }

    async fn stamped(state: &IngestPrevalence, ip: &str) -> (u64, Value) {
        let mut probe = event(ip);
        state.stamp(&mut probe).await.unwrap();
        (scalar(&probe, "prevalence_dest_ip"), probe["enrichments"][0]["data"]["total_occurrences"].clone())
    }

    /// NAN-3849 (tenant-a 2026-10-14 after r51): the per-entry catch-up read
    /// every key of every entry (most recur entry to entry) and made each
    /// entry durable on its own, ~4 entries a minute against ~2.6 committed:
    /// a 620-entry backlog never converged. A batch reads each distinct key
    /// once and lands every entry with one write, with the same state as
    /// the sequential replay.
    #[tokio::test]
    async fn a_catch_up_batch_reads_each_key_once_and_equals_the_sequential_replay() {
        let temp = tempfile::tempdir().unwrap();
        let (entries, shared, unique) = (20, 180, 20);
        let batch = backlog(temp.path(), entries, shared, unique);
        let mut sequential = IngestPrevalence::open_shared(TENANT_A, Arc::new(InMemory::new())).await.unwrap();
        sequential.initialize_at(0, &"0".repeat(64)).await.unwrap();
        for entry in &batch {
            let (id, path, max_time) = &entry.parts[0];
            let reference = EntryRef { seq: entry.seq, sha256: &entry.sha256, rebuild: false, parts: 1 };
            sequential.apply_part(TENANT_A, &reference, 0, id, path, *max_time).await.unwrap();
        }
        let mut batched = IngestPrevalence::open_shared(TENANT_A, Arc::new(InMemory::new())).await.unwrap();
        batched.initialize_at(0, &"0".repeat(64)).await.unwrap();
        let applied = batched.apply_entries_batch(TENANT_A, &batch).await.unwrap();
        // The backlog x fold cost: every entry's keys, against the union.
        assert_eq!(sequential.chunk_reads_done(), (entries * (shared + unique)) as u64);
        assert_eq!(batched.chunk_reads_done(), (shared + entries * unique) as u64, "each distinct key read once");
        assert_eq!((applied.entries, applied.parts, applied.keys), (entries, entries, shared + entries * unique));
        assert_eq!(batched.applied().await.unwrap(), sequential.applied().await.unwrap(), "same cursor: the last entry, complete");
        assert_eq!(batched.watermark_us, sequential.watermark_us);
        for ip in ["1.2.0.0", "1.2.0.179", "1.3.0.0", "1.3.19.19", "1.3.7.3"] {
            assert_eq!(stamped(&batched, ip).await, stamped(&sequential, ip).await, "{ip}");
        }
        assert_eq!(stamped(&batched, "1.2.0.5").await, (entries as u64, json!(entries)), "a recurring key counts every entry once");
        // Replaying the batch after it landed is refused (it is behind the cursor).
        assert!(batched.apply_entries_batch(TENANT_A, &batch).await.is_err());
    }

    /// Seven-hour Add backlog shaped like a large tenant's, including planning, cold reads,
    /// durable owner commits and foreground time (not just key-read speed).
    /// Six 10k-row partials fit the production row cap. Measure their real
    /// fold's distinct reads, then charge each read wave 100 ms and each
    /// durable commit 450 ms while new Adds arrive every 20 s.
    #[tokio::test]
    async fn seven_hour_add_backlog_cost_converges_with_foreground_service() {
        let temp = tempfile::tempdir().unwrap();
        let entries = 6;
        let mut batch = Vec::new();
        for n in 0..entries {
            let rows = (0..10_000).map(|k| {
                let mut value = row(&["host"], 10);
                // 9k recurring artifacts, 1k new per flush.
                let artifact = if k < 9_000 { k } else { 9_000 + n * 1_000 + k - 9_000 };
                value.key.2 = format!("artifact-{artifact:05}");
                value
            }).collect::<Vec<_>>();
            let path = temp.path().join(format!("backlog-{n}.parquet"));
            write_sorted(rows, &path).unwrap();
            batch.push(BatchEntry { seq: n as u64 + 1, sha256: format!("{:064x}", n + 1),
                parts: vec![(format!("p{n}"), path, 10 * DAY_US)] });
        }
        let mut state = IngestPrevalence::open_shared(TENANT_A, Arc::new(InMemory::new())).await.unwrap();
        state.initialize_at(0, &"0".repeat(64)).await.unwrap();
        let applied = state.apply_entries_batch(TENANT_A, &batch).await.unwrap();
        assert_eq!(applied.rows, 60_000);
        assert!(applied.rows <= CATCH_UP_BATCH_ROWS);
        assert_eq!(state.chunk_reads_done(), 15_000);
        assert_eq!(state.applied().await.unwrap().unwrap().seq, 6);
        // Include all 33 planned log GETs even though only six Adds fit.
        let scan = super::super::ingest::PREVALENCE_CATCH_UP_SCAN as f64 + 1.0;
        let lanes = super::super::ingest::PREVALENCE_CATCH_UP_FETCHES as f64;
        let prepare_s = (scan / lanes).ceil() * 0.1 + (12.0 / lanes).ceil() * 0.1;
        let reads_s = (state.chunk_reads_done() as f64 / APPLY_READS as f64).ceil() * 0.1;
        // CPU allowance for decode/fold/encode + durable owner commit.
        let work_s = prepare_s + reads_s + 0.5 + 0.45;
        let foreground_per_step_s = 1.0;
        // A read task survives the 5s wait; each slice yields to foreground.
        let slices = (work_s / 5.0).ceil();
        let batch_s = work_s + slices * foreground_per_step_s;
        let (mut backlog, mut elapsed, mut foreground_calls) = (7.0 * 3_600.0 / 20.0, 0.0, 0.0);
        while backlog >= entries as f64 && elapsed < 3_600.0 {
            backlog += batch_s / 20.0 - entries as f64;
            elapsed += batch_s;
            foreground_calls += slices;
        }
        assert!(backlog < entries as f64, "backlog failed to drain: {backlog} after {elapsed}s");
        assert!(elapsed < 3_600.0, "seven-hour backlog must drain within an hour at the modeled costs");
        assert!(foreground_calls >= elapsed / 6.0, "foreground served at least once each bounded slice");
        state.close().await.unwrap();
    }

    /// NAN-3849: tenant-a's backlog x fold cost, modeled on its measured numbers
    /// (15:46-15:57Z after r51): 2.6 `Add`s a minute committed (28 in
    /// 10.8 min), one ~10k-row part each; the per-entry replay applied ~4.1
    /// a minute (net drain 1.5/min), i.e. one entry per ~11 s tick: every
    /// entry's point reads outlast the 5 s ingest wait, so a step commits the
    /// entry whose reads the previous step started, starts the next, and is
    /// cut. Backlog 620 -> 6.9 h at that rate, falling further behind with
    /// every restart. The batch path reads each distinct key of up to 32
    /// entries once and commits them together. This runs the real code on a
    /// tenant-a-shaped backlog (most artifacts recur flush to flush) and turns the
    /// measured read counts into a catch-up ETA at the measured per-read cost.
    #[tokio::test]
    async fn b12_backlog_converges_with_batches_but_not_per_entry() {
        let temp = tempfile::tempdir().unwrap();
        // Two batches of entries of 400 keys: 300 from a recurring set of 1,200 (a
        // rotating window), 100 seen once.
        let entries = 2 * CATCH_UP_BATCH_ENTRIES;
        let batch = (0..entries).map(|n| {
            let host = format!("host-{}", n % 7);
            let rows = (0..300).map(|i| { let k = (n * 15 + i) % 1_200; format!("1.4.{}.{}", k / 256, k % 256) })
                .chain((0..100).map(|i| format!("1.5.{n}.{i}")))
                .map(|ip| { let mut row = row(&[host.as_str()], 10); row.key.2 = ip; row })
                .collect::<Vec<_>>();
            let path = temp.path().join(format!("tenant-a-{n}.parquet"));
            write_sorted(rows, &path).unwrap();
            BatchEntry { seq: n as u64 + 1, sha256: format!("{:064x}", n + 1), parts: vec![(format!("p{n}"), path, 10 * DAY_US)] }
        }).collect::<Vec<_>>();
        let mut state = IngestPrevalence::open_shared(TENANT_A, Arc::new(InMemory::new())).await.unwrap();
        state.initialize_at(0, &"0".repeat(64)).await.unwrap();
        for chunk in batch.chunks(CATCH_UP_BATCH_ENTRIES) {
            let rows: u64 = chunk.iter().map(|entry| partial_rows(&entry.parts[0].1).unwrap()).sum();
            assert!(rows <= CATCH_UP_BATCH_ROWS, "the row cap does not split these batches");
            state.apply_entries_batch(TENANT_A, chunk).await.unwrap();
        }
        let per_entry_reads = (entries * 400) as f64;
        let batch_reads = state.chunk_reads_done() as f64;
        // Measured: one entry per tick, ~4.1 entries/min, its reads ~all of
        // the step. Per-read cost at that rate:
        let (arrive_per_min, per_entry_per_min, backlog) = (2.6_f64, 4.1_f64, 620.0_f64);
        let read_s = 60.0 / per_entry_per_min / 400.0;
        let per_batch_recurring = (CATCH_UP_BATCH_ENTRIES - 1) * 15 + 300;
        assert_eq!(batch_reads, ((entries / CATCH_UP_BATCH_ENTRIES) * per_batch_recurring + entries * 100) as f64,
            "each distinct key of a batch read once");
        let batch_read_s = batch_reads / (entries / CATCH_UP_BATCH_ENTRIES) as f64 * read_s;
        assert!(batch_read_s < 200.0, "a batch's reads finish well inside a credential rotation: {batch_read_s:.0} s");
        // Drain the backlog while 2.6 Adds/min keep arriving: each batch
        // takes the next (up to 32) entries, costs its distinct reads (the
        // measured shape above; reads run back to back), and the entries
        // committed meanwhile join the backlog.
        let drain = |batch_entries: usize, reads_of: &dyn Fn(usize) -> f64, limit_min: f64| {
            let (mut pending, mut minutes) = (backlog, 0.0_f64);
            while pending >= 1.0 && minutes < limit_min {
                let take = pending.floor().min(batch_entries as f64) as usize;
                let took_min = reads_of(take) * read_s / 60.0;
                minutes += took_min;
                pending += arrive_per_min * took_min - take as f64;
            }
            minutes
        };
        let per_entry_eta_min = drain(1, &|_| 400.0, 24.0 * 60.0);
        let batch_eta_min = drain(CATCH_UP_BATCH_ENTRIES, &|n| ((n.max(1) - 1) * 15 + 300 + n * 100) as f64, 24.0 * 60.0);
        let batch_per_min = CATCH_UP_BATCH_ENTRIES as f64 / (batch_read_s / 60.0);
        println!("tenant-a model: reads per entry {:.0} -> per batch entry {:.1}; per-entry {per_entry_per_min:.1}/min (ETA {:.1} h), \
            batched {batch_per_min:.1}/min (ETA {batch_eta_min:.0} min), arrivals {arrive_per_min}/min throughout",
            per_entry_reads / entries as f64, batch_reads / entries as f64, per_entry_eta_min / 60.0);
        assert!(per_entry_eta_min > 6.0 * 60.0, "the per-entry replay takes hours");
        assert!(batch_eta_min < 60.0, "batched catch-up drains tenant-a's backlog within the hour: {batch_eta_min:.0} min");
    }

    /// NAN-3849: a backlog larger than one batch, with the process dying
    /// mid catch-up: once after a batch committed, once between a batch's
    /// reads and its atomic write. Every entry is in the state exactly once.
    #[tokio::test]
    async fn a_restart_mid_catch_up_applies_every_batch_exactly_once() {
        let temp = tempfile::tempdir().unwrap();
        let backlog = backlog(temp.path(), 9, 50, 5);
        let store: Arc<dyn ObjectStore> = Arc::new(InMemory::new());
        let mut state = IngestPrevalence::open_shared(TENANT_A, store.clone()).await.unwrap();
        state.initialize_at(0, &"0".repeat(64)).await.unwrap();
        state.apply_entries_batch(TENANT_A, &backlog[..3]).await.unwrap();
        // Dies right after the first batch committed.
        drop(state);
        let mut state = IngestPrevalence::open_shared(TENANT_A, store.clone()).await.unwrap();
        assert_eq!(state.applied().await.unwrap().unwrap().seq, 3, "the committed batch survived");
        assert!(state.apply_entries_batch(TENANT_A, &backlog[..3]).await.is_err(), "a landed batch never re-applies");
        // Dies between the second batch's reads and its write.
        state.crash_after_writes = Some(0);
        assert!(state.apply_entries_batch(TENANT_A, &backlog[3..6]).await.is_err());
        assert!(state.chunk_reads_done() > 0, "its reads ran");
        drop(state);
        let mut state = IngestPrevalence::open_shared(TENANT_A, store.clone()).await.unwrap();
        assert_eq!(state.applied().await.unwrap().unwrap().seq, 3, "nothing of the crashed batch landed");
        assert_eq!(stamped(&state, "1.2.0.1").await, (3, json!(3)));
        state.apply_entries_batch(TENANT_A, &backlog[3..6]).await.unwrap();
        state.apply_entries_batch(TENANT_A, &backlog[6..]).await.unwrap();
        drop(state);
        let state = IngestPrevalence::open_shared(TENANT_A, store).await.unwrap();
        let cursor = state.applied().await.unwrap().unwrap();
        assert_eq!((cursor.seq, cursor.is_complete()), (9, true));
        assert_eq!(stamped(&state, "1.2.0.1").await, (9, json!(9)), "every entry counted once across both restarts");
        assert_eq!(stamped(&state, "1.3.4.2").await.1, json!(1));
    }

    /// NAN-3849: a batch lands whole or not at all (one WriteBatch with the
    /// cursor), and a step cut at the ingest wait keeps the batch's reads.
    #[tokio::test]
    async fn a_catch_up_batch_is_atomic_and_survives_cuts() {
        let temp = tempfile::tempdir().unwrap();
        let batch = backlog(temp.path(), 6, 100, 10);
        let store: Arc<dyn ObjectStore> = Arc::new(InMemory::new());
        let mut state = IngestPrevalence::open_shared(TENANT_A, store.clone()).await.unwrap();
        state.initialize_at(0, &"0".repeat(64)).await.unwrap();
        state.crash_after_writes = Some(0);
        assert!(state.apply_entries_batch(TENANT_A, &batch).await.is_err());
        drop(state);
        let mut state = IngestPrevalence::open_shared(TENANT_A, store).await.unwrap();
        assert_eq!(state.applied().await.unwrap().unwrap().seq, 0, "nothing of the crashed batch landed");
        assert_eq!(stamped(&state, "1.2.0.1").await.0, 1, "unseen");
        state.read_delay = Some(std::time::Duration::from_millis(100));
        let mut attempts = 0;
        loop {
            attempts += 1;
            assert!(attempts <= 40, "the batch never landed: every cut restarted its reads");
            match tokio::time::timeout(std::time::Duration::from_millis(60), state.apply_entries_batch(TENANT_A, &batch)).await {
                Ok(Ok(applied)) => break assert_eq!(applied.entries, 6),
                Ok(Err(error)) => {
                    // A cut may land after the atomic cursor write but before
                    // its durability wait returns. The production replay
                    // planner observes that cursor and makes it durable; it
                    // never retries an already-applied batch as a new one.
                    let cursor = state.applied().await.unwrap().unwrap();
                    assert_eq!((cursor.seq, cursor.entry_sha256.as_str(), cursor.is_complete()),
                        (6, batch.last().unwrap().sha256.as_str(), true), "unexpected apply error: {error:#}");
                    state.make_durable().await.unwrap();
                    // Admission advances its lookup window before stamping.
                    state.advance_watermark(batch.iter().flat_map(|entry| entry.parts.iter().map(|(_, _, mark)| *mark)).max().unwrap());
                    break;
                }
                Err(_) => assert!(state.chunk_reads.is_some(), "a cut keeps the batch's reads"),
            }
        }
        assert!(attempts > 1, "the reads outlast one wait (the test exercises a cut)");
        assert_eq!(state.chunk_reads_done(), 160, "every distinct key read exactly once across the cuts");
        let cursor = state.applied().await.unwrap().unwrap();
        assert_eq!((cursor.seq, cursor.is_complete()), (6, true));
        assert_eq!(stamped(&state, "1.2.0.1").await, (6, json!(6)), "applied once");
        // An entry that does not follow the cursor is refused.
        assert!(state.apply_entries_batch(TENANT_A, &batch[..1]).await.is_err());
    }

    /// NAN-4464: with a patience deadline a batch returns while its reads
    /// run (they stay in flight, nothing lands), and the same batch commits
    /// once they finish, reading every key exactly once.
    #[tokio::test]
    async fn a_patient_catch_up_batch_returns_while_its_reads_run_and_commits_after() {
        let temp = tempfile::tempdir().unwrap();
        let batch = backlog(temp.path(), 6, 100, 10);
        let store: Arc<dyn ObjectStore> = Arc::new(InMemory::new());
        let mut state = IngestPrevalence::open_shared(TENANT_A, store).await.unwrap();
        state.initialize_at(0, &"0".repeat(64)).await.unwrap();
        state.read_delay = Some(std::time::Duration::from_millis(100));
        let mut early = 0;
        let applied = loop {
            let started = std::time::Instant::now();
            let patience = started + std::time::Duration::from_millis(20);
            match state.apply_entries_batch_within(TENANT_A, &batch, Some(patience)).await.unwrap() {
                Some(applied) => break applied,
                None => {
                    early += 1;
                    assert!(started.elapsed() < std::time::Duration::from_millis(80), "returns at its patience");
                    assert!(state.catch_up_reads_in_flight(), "its reads keep running");
                    assert_eq!(state.applied().await.unwrap().unwrap().seq, 0, "nothing landed yet");
                    // The caller skips its steps while the reads run.
                    while state.catch_up_reads_in_flight() {
                        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
                    }
                }
            }
        };
        assert_eq!(early, 1, "the step after the reads finish commits without waiting again");
        assert_eq!(applied.entries, 6);
        assert!(!state.catch_up_reads_in_flight());
        assert_eq!(state.chunk_reads_done(), 160, "every distinct key read exactly once");
        assert_eq!(stamped(&state, "1.2.0.1").await, (6, json!(6)), "applied once");
    }

    /// NAN-3811: reads left by a cut belong to their chunk only: another
    /// part (other digest) never reuses them, and a reset discards them.
    #[tokio::test]
    async fn cut_chunk_reads_are_never_reused_for_another_part() {
        let temp = tempfile::tempdir().unwrap();
        let (first, second) = (temp.path().join("first.parquet"), temp.path().join("second.parquet"));
        write_sorted(vec![row(&["one"], 10)], &first).unwrap();
        write_sorted(vec![row(&["one", "two"], 10)], &second).unwrap();
        let store: Arc<dyn ObjectStore> = Arc::new(InMemory::new());
        let mut state = IngestPrevalence::open_shared(TENANT_A, store).await.unwrap();
        state.initialize_at(0, &"0".repeat(64)).await.unwrap();
        state.read_delay = Some(std::time::Duration::from_millis(200));
        let sha = "6".repeat(64);
        let entry = EntryRef { seq: 1, sha256: &sha, rebuild: false, parts: 1 };
        let cut = tokio::time::timeout(std::time::Duration::from_millis(20),
            state.apply_part_until(TENANT_A, &entry, 0, "p1", &first, 10 * DAY_US, None)).await;
        assert!(cut.is_err() && state.chunk_reads.is_some());
        let left = state.chunk_reads.as_ref().unwrap().key.clone();
        state.read_delay = None;
        // The same entry slot with another file (no chunk of it committed
        // yet, so it applies): the cut task keyed the first file and is
        // replaced, never reused.
        state.apply_part(TENANT_A, &entry, 0, "p1", &second, 10 * DAY_US).await.unwrap();
        assert_ne!(left.part_sha256, digest_file(&second).unwrap(), "the cut reads keyed another file");
        let mut seen = event("8.8.8.8");
        state.stamp(&mut seen).await.unwrap();
        assert_eq!(scalar(&seen, "prevalence_dest_ip"), 2, "the second file's own reads were applied");
        state.read_delay = Some(std::time::Duration::from_millis(200));
        let next = EntryRef { seq: 2, sha256: &sha, rebuild: false, parts: 1 };
        let cut = tokio::time::timeout(std::time::Duration::from_millis(20),
            state.apply_part_until(TENANT_A, &next, 0, "p2", &first, 10 * DAY_US, None)).await;
        assert!(cut.is_err() && state.chunk_reads.is_some());
        state.begin_reset().await.unwrap();
        assert!(state.chunk_reads.is_none(), "a reset discards cut reads");
    }

    /// NAN-3879 (production, 2026-10-15): the post-commit apply of entry 1 is cut at
    /// the ingest wait with its reads running; the next tick's catch-up
    /// batches entries 1-2 under another chunk key. It adopts the cut reads
    /// (same cursor) instead of aborting them, so every distinct key is read
    /// from the store exactly once, and the counts are exact.
    #[tokio::test]
    async fn a_catch_up_adopts_the_reads_of_a_cut_apply_at_the_same_cursor() {
        let temp = tempfile::tempdir().unwrap();
        // 100 keys shared by both entries, 10 unique to each: 120 distinct.
        let batch = backlog(temp.path(), 2, 100, 10);
        let store: Arc<dyn ObjectStore> = Arc::new(InMemory::new());
        let mut state = IngestPrevalence::open_shared(TENANT_A, store).await.unwrap();
        state.initialize_at(0, &"0".repeat(64)).await.unwrap();
        state.read_delay = Some(std::time::Duration::from_millis(100));
        let first = &batch[0];
        let entry = EntryRef { seq: first.seq, sha256: &first.sha256, rebuild: false, parts: 1 };
        let (part_id, path, max_time) = &first.parts[0];
        let cut = tokio::time::timeout(std::time::Duration::from_millis(20),
            state.apply_part_until(TENANT_A, &entry, 0, part_id, path, *max_time, None)).await;
        assert!(cut.is_err() && state.chunk_reads.is_some(), "the apply was cut with its reads running");
        // Its reads finish in the background before the next tick.
        tokio::time::sleep(std::time::Duration::from_millis(400)).await;
        assert_eq!(state.chunk_reads_done(), 110, "the cut apply read entry 1's keys");
        let applied = state.apply_entries_batch(TENANT_A, &batch).await.unwrap();
        assert_eq!((applied.entries, applied.keys), (2, 120));
        assert_eq!(state.chunk_reads_done(), 120, "each key read once: the cut apply's 110 reads were adopted");
        assert_eq!(stamped(&state, "1.2.0.1").await, (2, json!(2)), "shared keys counted once per entry");
        assert_eq!(stamped(&state, "1.3.1.4").await, (1, json!(1)));

        // Reads left at another cursor are never adopted: entry 3's cut
        // reads are dropped once entry 3 itself lands by another path.
        let more = backlog(temp.path(), 4, 100, 10);
        let third = &more[2];
        let entry = EntryRef { seq: third.seq, sha256: &third.sha256, rebuild: false, parts: 1 };
        let (part_id, path, max_time) = &third.parts[0];
        let cut = tokio::time::timeout(std::time::Duration::from_millis(20),
            state.apply_part_until(TENANT_A, &entry, 0, part_id, path, *max_time, None)).await;
        assert!(cut.is_err());
        let basis = state.chunk_reads.as_ref().unwrap().basis.clone();
        state.read_delay = None;
        state.apply_part(TENANT_A, &entry, 0, part_id, path, *max_time).await.unwrap();
        assert_ne!(state.applied().await.unwrap(), basis, "the cursor moved");
        let before = state.chunk_reads_done();
        state.apply_entries_batch(TENANT_A, &more[3..]).await.unwrap();
        assert_eq!(state.chunk_reads_done() - before, 110, "entry 4 read all of its keys itself");
        assert_eq!(stamped(&state, "1.2.0.1").await, (4, json!(4)), "exact after both paths");
    }

    /// NAN-3879: apply time against flush size at cold R2 point reads
    /// (~0.1 s each, a production tenant's cold cost) and convergence at its daily peak.
    /// That tenant cycles 0.54M rows/h (01-02Z) to 1.6M rows/h (~445 EPS, 13-15Z)
    /// every day since 10-12. Flushes come every ~20 s; distinct keys run
    /// ~0.32 per flushed row (6,258 rows -> 2,016 keys); the durable write
    /// is ~0.6 s. An ~11k-row flush (~3.5k keys) took ~5.5 s at 64 lanes
    /// and was cut; at APPLY_READS it reads in ~1.4 s. The model checks one
    /// peak flush, a doubled (bunched) one, the hourly apply duty at peak,
    /// and that a backlog drains (backlog x cost against arrivals).
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn an_eleven_thousand_row_flush_applies_within_the_ingest_wait_at_cold_reads() {
        const COLD_READ: std::time::Duration = std::time::Duration::from_millis(100);
        const WRITE: std::time::Duration = std::time::Duration::from_millis(600);
        const KEYS: usize = 3_500;
        const PEAK_ROWS_PER_HOUR: f64 = 1_600_000.0;
        const FLUSHES_PER_HOUR: f64 = 180.0;
        const KEYS_PER_ROW: f64 = 0.32;
        let apply = |keys: usize, lanes: usize| COLD_READ * keys.div_ceil(lanes) as u32 + WRITE;
        assert!(apply(KEYS, 64) > PREVALENCE_TEST_INGEST_WAIT, "the old lane count overran");
        assert!(apply(KEYS, APPLY_READS) < PREVALENCE_TEST_INGEST_WAIT / 2);
        let peak_keys = (PEAK_ROWS_PER_HOUR / FLUSHES_PER_HOUR * KEYS_PER_ROW).ceil() as usize;
        assert!(apply(peak_keys, APPLY_READS) < PREVALENCE_TEST_INGEST_WAIT / 2, "a peak flush ({peak_keys} keys)");
        assert!(apply(2 * peak_keys, APPLY_READS) < PREVALENCE_TEST_INGEST_WAIT, "a bunched peak flush");
        // Apply duty at peak: the share of each hour the state spends applying.
        let duty = apply(peak_keys, APPLY_READS).as_secs_f64() * FLUSHES_PER_HOUR / 3_600.0;
        assert!(duty < 0.15, "peak apply duty {duty:.2}");
        // Convergence: a backlog of a 30 min outage at peak (90 entries),
        // applied one entry at a time with no key sharing (worst case),
        // drains while new entries keep arriving at the peak rate.
        let (mut queued, mut elapsed) = (90.0_f64, 0.0_f64);
        let per_entry = apply(peak_keys, APPLY_READS).as_secs_f64();
        while queued > 0.0 {
            elapsed += per_entry;
            queued += per_entry * FLUSHES_PER_HOUR / 3_600.0 - 1.0;
            assert!(elapsed < 900.0, "the peak backlog did not drain in 15 min");
        }

        let temp = tempfile::tempdir().unwrap();
        let entry = backlog(temp.path(), 1, KEYS, 0).remove(0);
        let store: Arc<dyn ObjectStore> = Arc::new(InMemory::new());
        let mut state = IngestPrevalence::open_shared(TENANT_A, store).await.unwrap();
        state.initialize_at(0, &"0".repeat(64)).await.unwrap();
        state.read_delay = Some(COLD_READ);
        let started = std::time::Instant::now();
        let reference = EntryRef { seq: entry.seq, sha256: &entry.sha256, rebuild: false, parts: 1 };
        let (part_id, path, max_time) = &entry.parts[0];
        tokio::time::timeout(PREVALENCE_TEST_INGEST_WAIT,
            state.apply_part(TENANT_A, &reference, 0, part_id, path, *max_time)).await
            .expect("the apply finished within the ingest wait").unwrap();
        assert!(started.elapsed() < PREVALENCE_TEST_INGEST_WAIT, "{:?}", started.elapsed());
        assert_eq!(state.chunk_reads_done(), KEYS as u64);
    }

    #[tokio::test]
    async fn replay_refuses_a_different_entry_at_the_applied_sequence() {
        let temp = tempfile::tempdir().unwrap();
        let part = temp.path().join("part.parquet");
        write_sorted(vec![row(&["one"], 10)], &part).unwrap();
        let mut state = IngestPrevalence::open(TENANT_A, temp.path(), None)
            .await
            .unwrap();
        state.initialize_at(0, &"0".repeat(64)).await.unwrap();
        let sha = "3".repeat(64);
        let entry = EntryRef { seq: 1, sha256: &sha, rebuild: false, parts: 1 };
        state.apply_part(TENANT_A, &entry, 0, "p1", &part, 10 * DAY_US).await.unwrap();
        let other = "4".repeat(64);
        let forked = EntryRef { seq: 1, sha256: &other, rebuild: false, parts: 1 };
        write_sorted(vec![row(&["one", "two"], 10)], &part).unwrap();
        assert!(state.apply_part(TENANT_A, &forked, 0, "p1", &part, 10 * DAY_US).await.is_err());
        let mut event = event("8.8.8.8");
        state.stamp(&mut event).await.unwrap();
        assert_eq!(scalar(&event, "prevalence_dest_ip"), 1);
    }

    /// A cell move opens the tenant DB on a new writer while the old one may
    /// still be running. SlateDB's open fences the old writer: its next state
    /// write fails, and the new writer sees exactly the durable state.
    #[tokio::test]
    async fn second_writer_fences_the_first() {
        let temp = tempfile::tempdir().unwrap();
        let first_part = temp.path().join("first.parquet");
        let second_part = temp.path().join("second.parquet");
        write_sorted(vec![row(&["one", "two"], 10)], &first_part).unwrap();
        write_sorted(vec![row(&["three"], 10)], &second_part).unwrap();
        let store: Arc<dyn ObjectStore> = Arc::new(InMemory::new());
        let mut old = IngestPrevalence::open_shared(TENANT_A, store.clone()).await.unwrap();
        old.absorb_part(TENANT_A, &first_part, 10 * DAY_US).await.unwrap();

        let mut new = IngestPrevalence::open_shared(TENANT_A, store.clone()).await.unwrap();
        assert!(!new.is_new());
        let error = old.absorb_part(TENANT_A, &second_part, 10 * DAY_US).await.unwrap_err();
        assert!(format!("{error:#}").contains("newer DB client"), "{error:#}");

        let mut stamped = event("8.8.8.8");
        new.stamp(&mut stamped).await.unwrap();
        assert_eq!(scalar(&stamped, "prevalence_dest_ip"), 2, "fenced write is not visible");
        new.absorb_part(TENANT_A, &second_part, 10 * DAY_US).await.unwrap();
        let mut after = event("8.8.8.8");
        new.stamp(&mut after).await.unwrap();
        assert_eq!(scalar(&after, "prevalence_dest_ip"), 3);
        assert_eq!(new.applied().await.unwrap().unwrap().seq, 2);
        // A third open (the next move) fences the second in turn.
        let _third = IngestPrevalence::open_shared(TENANT_A, store).await.unwrap();
        assert!(new.absorb_part(TENANT_A, &first_part, 10 * DAY_US).await.is_err());
    }

    /// Event times are untrusted. One far-future row must not push the
    /// persisted watermark ahead and expire every entity for the tenant.
    #[tokio::test]
    async fn far_future_event_time_cannot_expire_tenant_state() {
        let temp = tempfile::tempdir().unwrap();
        let today = (chrono::Utc::now().timestamp_micros() / DAY_US) as i32;
        let current = temp.path().join("current.parquet");
        let poison = temp.path().join("poison.parquet");
        write_sorted(vec![row(&["one", "two"], today)], &current).unwrap();
        let mut future = row(&["attacker"], today + 36_500);
        future.key.2 = "1.1.1.1".into();
        write_sorted(vec![future], &poison).unwrap();
        let store: Arc<dyn ObjectStore> = Arc::new(InMemory::new());
        let mut state = IngestPrevalence::open_shared(TENANT_A, store.clone()).await.unwrap();
        state.absorb_part(TENANT_A, &current, today as i64 * DAY_US).await.unwrap();
        state.absorb_part(TENANT_A, &poison, (today as i64 + 36_500) * DAY_US).await.unwrap();
        let mut stamped = event("8.8.8.8");
        state.stamp(&mut stamped).await.unwrap();
        assert_eq!(scalar(&stamped, "prevalence_dest_ip"), 2);
        drop(state);
        let reopened = IngestPrevalence::open_shared(TENANT_A, store).await.unwrap();
        let mut stamped = event("8.8.8.8");
        reopened.stamp(&mut stamped).await.unwrap();
        assert_eq!(scalar(&stamped, "prevalence_dest_ip"), 2, "persisted watermark is bounded");
    }

    #[tokio::test]
    async fn batch_stamps_read_each_artifact_once_from_the_arrival_snapshot() {
        let temp = tempfile::tempdir().unwrap();
        let part = temp.path().join("prevalence.parquet");
        write_sorted(vec![row(&["one", "two"], 10)], &part).unwrap();
        let mut state = IngestPrevalence::new(TENANT_A).await;
        state.absorb_part(TENANT_A, &part, 10 * DAY_US).await.unwrap();
        let mut events = vec![event("8.8.8.8"), event("8.8.8.8"), event("9.9.9.9"), event("10.0.0.1")];
        state.stamp_all(events.iter_mut()).await.unwrap();
        let stamps = events.iter().map(|e| scalar(e, "prevalence_dest_ip")).collect::<Vec<_>>();
        assert_eq!(stamps, vec![2, 2, 1, NA]);
        assert!(state.stamp_all([&mut json!("not an object")]).await.is_err());
    }

    /// A store that counts WAL object writes (each one an owner round trip
    /// in production).
    #[derive(Debug)]
    struct WalCounter {
        inner: InMemory,
        wal_puts: std::sync::atomic::AtomicUsize,
    }

    impl std::fmt::Display for WalCounter {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "WalCounter")
        }
    }

    #[async_trait::async_trait]
    impl ObjectStore for WalCounter {
        async fn put_opts(&self, path: &slatedb::object_store::path::Path, payload: slatedb::object_store::PutPayload,
            opts: slatedb::object_store::PutOptions) -> slatedb::object_store::Result<slatedb::object_store::PutResult> {
            if path.as_ref().contains("/wal/") {
                self.wal_puts.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            }
            self.inner.put_opts(path, payload, opts).await
        }
        async fn put_multipart_opts(&self, path: &slatedb::object_store::path::Path, opts: slatedb::object_store::PutMultipartOptions)
            -> slatedb::object_store::Result<Box<dyn slatedb::object_store::MultipartUpload>> {
            self.inner.put_multipart_opts(path, opts).await
        }
        async fn get_opts(&self, path: &slatedb::object_store::path::Path, options: slatedb::object_store::GetOptions)
            -> slatedb::object_store::Result<slatedb::object_store::GetResult> {
            self.inner.get_opts(path, options).await
        }
        fn delete_stream(&self, locations: futures::stream::BoxStream<'static, slatedb::object_store::Result<slatedb::object_store::path::Path>>)
            -> futures::stream::BoxStream<'static, slatedb::object_store::Result<slatedb::object_store::path::Path>> {
            self.inner.delete_stream(locations)
        }
        fn list(&self, prefix: Option<&slatedb::object_store::path::Path>)
            -> futures::stream::BoxStream<'static, slatedb::object_store::Result<slatedb::object_store::ObjectMeta>> {
            self.inner.list(prefix)
        }
        async fn list_with_delimiter(&self, prefix: Option<&slatedb::object_store::path::Path>)
            -> slatedb::object_store::Result<slatedb::object_store::ListResult> {
            self.inner.list_with_delimiter(prefix).await
        }
        async fn copy_opts(&self, from: &slatedb::object_store::path::Path, to: &slatedb::object_store::path::Path,
            options: slatedb::object_store::CopyOptions) -> slatedb::object_store::Result<()> {
            self.inner.copy_opts(from, to, options).await
        }
    }

    /// a lean test tenant (2026-09-30): a rebuild ran at ~1 part a minute, one
    /// durable WAL flush (an owner round trip) per 8,192-row chunk. It now
    /// commits every chunk (resumable) but flushes on a cadence and once at
    /// the end: 12 parts x 3 chunks are a handful of WAL objects, not ~48.
    /// Every row is applied; a restart mid-rebuild still resumes.
    #[tokio::test]
    async fn a_rebuild_flushes_on_a_cadence_not_per_chunk() {
        let temp = tempfile::tempdir().unwrap();
        let store = Arc::new(WalCounter { inner: InMemory::new(), wal_puts: std::sync::atomic::AtomicUsize::new(0) });
        let mut state = IngestPrevalence::open_store(TENANT_A, store.clone(), "db", None, false, None, None).await.unwrap();
        let parts = 12_u64;
        let head = "7".repeat(64);
        let entry = EntryRef { seq: 9, sha256: &head, rebuild: true, parts: parts as u32 };
        state.initialize_rebuild(&entry, &(1..=parts).map(fake_part).collect::<Vec<_>>()).await.unwrap();
        let before = store.wal_puts.load(std::sync::atomic::Ordering::SeqCst);
        for index in 0..parts {
            let path = temp.path().join(format!("part-{index}.parquet"));
            // 3 chunks per part: 2 x 8,192 + 1 rows, distinct artifacts.
            let rows = (0..(2 * CHUNK_ROWS + 1)).map(|n| {
                let mut row = row(&["h1", "h2"], 10);
                row.key.2 = format!("10.{}.{}.{}", index, n / 256, n % 256);
                row
            }).collect::<Vec<_>>();
            write_sorted(rows, &path).unwrap();
            state.apply_part(TENANT_A, &entry, index as u32, &format!("part{index}"), &path, 10 * DAY_US).await.unwrap();
        }
        let wal = store.wal_puts.load(std::sync::atomic::Ordering::SeqCst) - before;
        assert!(state.applied().await.unwrap().unwrap().is_complete());
        // Before: >= parts x (chunks + 1) = 48 durable flushes.
        assert!(wal <= 8, "a rebuild made {wal} WAL writes for {parts} parts");
        // Every row is in the state (the last part's last artifact).
        for artifact in ["10.0.0.0", "10.11.64.0"] {
            assert!(state.db.get(key("ip", artifact)).await.unwrap().is_some(), "{artifact} applied");
        }
        // The rebuild ended durable: a reopen sees it complete.
        state.close().await.unwrap();
        let reopened = IngestPrevalence::open_store(TENANT_A, store.clone(), "db", None, false, None, None).await.unwrap();
        assert!(reopened.applied().await.unwrap().unwrap().is_complete());
    }

    /// Parts written before the 1,000-host format must not crash-loop a
    /// lost-DB rebuild; they are skipped (undercount), never mis-counted.
    #[tokio::test]
    async fn rebuild_skips_legacy_host_cap_partials() {
        let temp = tempfile::tempdir().unwrap();
        let current = temp.path().join("current.parquet");
        let legacy = temp.path().join("legacy.parquet");
        write_sorted(vec![row(&["one", "two"], 10)], &current).unwrap();
        let batch = PrevalenceRow::to_batch(&[row(&["three"], 10)]).unwrap();
        let keep = (0..batch.num_columns())
            .filter(|&i| batch.schema().field(i).name() != "host_cap")
            .collect::<Vec<_>>();
        let batch = batch.project(&keep).unwrap();
        let mut writer = parquet::arrow::ArrowWriter::try_new(File::create(&legacy).unwrap(), batch.schema(), None).unwrap();
        writer.write(&batch).unwrap();
        writer.close().unwrap();
        assert!(is_legacy_partial(&legacy).unwrap() && !is_legacy_partial(&current).unwrap());

        let mut state = IngestPrevalence::new(TENANT_A).await;
        let head = "5".repeat(64);
        let entry = EntryRef { seq: 7, sha256: &head, rebuild: true, parts: 2 };
        state.initialize_rebuild(&entry, &[]).await.unwrap_err();
        state.initialize_rebuild(&entry, &[fake_part(1), fake_part(2)]).await.unwrap();
        state.apply_part(TENANT_A, &entry, 0, "legacy", &legacy, 10 * DAY_US).await.unwrap();
        state.apply_part(TENANT_A, &entry, 1, "current", &current, 10 * DAY_US).await.unwrap();
        assert!(state.applied().await.unwrap().unwrap().is_complete());
        assert_eq!(state.rebuild_parts().await.unwrap().unwrap(), vec![fake_part(1), fake_part(2)]);
        let mut stamped = event("8.8.8.8");
        state.stamp(&mut stamped).await.unwrap();
        assert_eq!(scalar(&stamped, "prevalence_dest_ip"), 2);
        // Outside a rebuild a legacy partial is still refused.
        let add = "6".repeat(64);
        let entry = EntryRef { seq: 8, sha256: &add, rebuild: false, parts: 1 };
        assert!(state.apply_part(TENANT_A, &entry, 0, "legacy", &legacy, 10 * DAY_US).await.is_err());
    }

    fn hosts_row(hosts: Vec<u64>, day: i32) -> PrevalenceRow {
        PrevalenceRow {
            key: ("ip".into(), "source-a".into(), "8.8.8.8".into(), day),
            daily_count: hosts.len() as u64,
            hosts,
            is_private: 0,
            first_seen: day as i64 * DAY_US,
            last_seen: day as i64 * DAY_US,
        }
    }

    /// NAN-3160: an entity active for more than 30 days reports only the
    /// hosts (and occurrences) of the last 30 days; a host seen again keeps
    /// counting from its latest day.
    #[tokio::test]
    async fn long_lived_entity_counts_only_hosts_seen_in_the_last_30_days() {
        let temp = tempfile::tempdir().unwrap();
        let mut state = IngestPrevalence::new(TENANT_A).await;
        let days: [(i32, &[&str]); 4] = [(10, &["old", "again"]), (30, &["mid"]), (40, &["again"]), (45, &["new"])];
        for (day, hosts) in days {
            let part = temp.path().join(format!("day-{day}.parquet"));
            write_sorted(vec![row(hosts, day)], &part).unwrap();
            state.absorb_part(TENANT_A, &part, day as i64 * DAY_US).await.unwrap();
        }
        // Window at day 45 is days 16..=45: mid, again (day 40), new. The
        // cumulative set would also hold "old" (4).
        let mut stamped = event("8.8.8.8");
        state.stamp(&mut stamped).await.unwrap();
        assert_eq!(scalar(&stamped, "prevalence_dest_ip"), 3);
        assert_eq!(stamped["enrichments"][0]["data"]["host_count"], 3);
        assert_eq!(stamped["enrichments"][0]["data"]["total_occurrences"], 3);
        // The window moves with the watermark alone (no new rows): at day
        // 69 (window 40..=69) only "again" and "new" remain.
        state.advance_watermark(69 * DAY_US);
        let mut later = event("8.8.8.8");
        state.stamp(&mut later).await.unwrap();
        assert_eq!(scalar(&later, "prevalence_dest_ip"), 2);
        // The next merge drops the expired days from the stored value.
        let part = temp.path().join("day-69.parquet");
        write_sorted(vec![row(&["new"], 69)], &part).unwrap();
        state.absorb_part(TENANT_A, &part, 69 * DAY_US).await.unwrap();
        let stored = decode(&state.db.get(key("ip", "8.8.8.8")).await.unwrap().unwrap()).unwrap();
        assert_eq!(stored.days.iter().map(|d| d.0).collect::<Vec<_>>(), vec![40, 45, 69]);
        assert_eq!(stored.hosts.len(), 2);
        assert_eq!(stored.first_seen, 10 * DAY_US, "first_seen is the entity's age, not the window's");
    }

    /// Entities younger than 30 days stamp exactly as the cumulative state
    /// did: the union of every host and the sum of every occurrence.
    #[tokio::test]
    async fn entities_younger_than_30_days_keep_cumulative_stamps() {
        let temp = tempfile::tempdir().unwrap();
        let mut state = IngestPrevalence::new(TENANT_A).await;
        let mut seen = std::collections::BTreeSet::new();
        let mut occurrences = 0;
        let mut first = None;
        for day in 100..130 {
            let hosts = [format!("h{}", day % 7), format!("h{}", day % 11 + 7)];
            let refs = hosts.iter().map(String::as_str).collect::<Vec<_>>();
            seen.extend(hosts.iter().cloned());
            occurrences += refs.len();
            let part = temp.path().join(format!("day-{day}.parquet"));
            write_sorted(vec![row(&refs, day)], &part).unwrap();
            state.absorb_part(TENANT_A, &part, day as i64 * DAY_US).await.unwrap();
            let mut stamped = event("8.8.8.8");
            state.stamp(&mut stamped).await.unwrap();
            assert_eq!(scalar(&stamped, "prevalence_dest_ip"), seen.len() as u64, "day {day}");
            assert_eq!(stamped["enrichments"][0]["data"]["total_occurrences"], occurrences);
            let first_seen = stamped["enrichments"][0]["data"]["first_seen"].clone();
            assert_eq!(*first.get_or_insert(first_seen.clone()), first_seen);
        }
    }

    /// Saturation: 1,000 hosts spread over days is COMMON; once the days
    /// that saturated it leave the window the exact remaining count comes
    /// back (the bottom-k pruning kept every host that can still count).
    #[tokio::test]
    async fn saturation_is_windowed_and_desaturates_exactly() {
        let temp = tempfile::tempdir().unwrap();
        let mut state = IngestPrevalence::new(TENANT_A).await;
        // Days 200..=209: 100 hosts each with small fingerprints (1,000
        // total). Day 215: 5 hosts with the largest fingerprints, which the
        // cumulative 1,000-cap set had dropped.
        for day in 200..210 {
            let base = (day - 200) as u64 * 100;
            let part = temp.path().join(format!("day-{day}.parquet"));
            write_sorted(vec![hosts_row((base..base + 100).collect(), day)], &part).unwrap();
            state.absorb_part(TENANT_A, &part, day as i64 * DAY_US).await.unwrap();
        }
        let late = temp.path().join("day-215.parquet");
        write_sorted(vec![hosts_row((u64::MAX - 4..=u64::MAX).collect(), 215)], &late).unwrap();
        state.absorb_part(TENANT_A, &late, 215 * DAY_US).await.unwrap();
        let mut common = event("8.8.8.8");
        state.stamp(&mut common).await.unwrap();
        assert_eq!(scalar(&common, "prevalence_dest_ip"), COMMON);
        assert_eq!(common["enrichments"][0]["data"]["host_count_saturated"], true);
        // Day 238: window 209..=238 holds day 209 (100) + day 215 (5).
        state.advance_watermark(238 * DAY_US);
        let mut partial = event("8.8.8.8");
        state.stamp(&mut partial).await.unwrap();
        assert_eq!(scalar(&partial, "prevalence_dest_ip"), 105);
        assert_eq!(partial["enrichments"][0]["data"]["host_count_saturated"], false);
        state.advance_watermark(239 * DAY_US);
        let mut tail = event("8.8.8.8");
        state.stamp(&mut tail).await.unwrap();
        assert_eq!(scalar(&tail, "prevalence_dest_ip"), 5);
    }

    /// The pruned state matches a brute-force window count for every
    /// cutoff, and stays within WINDOW_DAYS x 1,000 hosts.
    #[test]
    fn window_state_matches_brute_force_for_every_cutoff() {
        let mut seed = 0x9e37_79b9_7f4a_7c15_u64;
        let mut next = move || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        let mut truth = BTreeMap::<u64, i32>::new();
        let mut state: Option<WindowState> = None;
        for day in 0..60 {
            let mut hosts = (0..1_500).map(|_| next() % 6_000).collect::<Vec<_>>();
            hosts.sort_unstable();
            hosts.dedup();
            for host in &hosts {
                truth.insert(*host, day);
            }
            // The partial already holds only the day's bottom 1,000.
            hosts.truncate(PREVALENCE_HOST_CAP);
            let row = WindowState::from_row(&hosts_row(hosts, day), day);
            let first = day - WINDOW_DAYS as i32 + 1;
            let merged = match state.take() {
                Some(mut prior) => {
                    prior.absorb(&row);
                    prior
                }
                None => row,
            };
            let mut merged = merged;
            merged.prune(first, day);
            assert!(merged.hosts.len() <= WINDOW_DAYS * PREVALENCE_HOST_CAP);
            assert!(merged.days.len() <= WINDOW_DAYS);
            assert_eq!(decode(&encode(&merged)).unwrap(), merged);
            for cutoff in first..=day {
                let exact = truth.values().filter(|seen| **seen >= cutoff).count();
                let window = merged.window("ip", "8.8.8.8", cutoff).hosts.len();
                assert_eq!(window, exact.min(PREVALENCE_HOST_CAP), "day {day} cutoff {cutoff}");
            }
            state = Some(merged);
        }
    }

    /// Steady state for a stable saturated host population is ~1,000
    /// fingerprints, not 30 x 1,000.
    #[test]
    fn stable_saturated_entity_stays_near_one_thousand_hosts() {
        let mut state: Option<WindowState> = None;
        for day in 0..90 {
            let row = WindowState::from_row(&hosts_row((0..PREVALENCE_HOST_CAP as u64).collect(), day), day);
            let mut merged = match state.take() {
                Some(mut prior) => {
                    prior.absorb(&row);
                    prior
                }
                None => row,
            };
            merged.prune(day - WINDOW_DAYS as i32 + 1, day);
            assert_eq!(merged.hosts.len(), PREVALENCE_HOST_CAP);
            state = Some(merged);
        }
    }

    /// Upgrade: a v1 value (cumulative hosts, no days) is read as-is until
    /// the entity's next merge rewrites it as v2. No rebuild, no gap; the
    /// legacy hosts then age out from their last-seen day.
    #[tokio::test]
    async fn legacy_v1_values_are_read_then_rewritten_and_age_out() {
        let temp = tempfile::tempdir().unwrap();
        let mut state = IngestPrevalence::new(TENANT_A).await;
        let unrelated = temp.path().join("unrelated.parquet");
        let mut other = row(&["x"], 100);
        other.key.2 = "1.1.1.1".into();
        write_sorted(vec![other], &unrelated).unwrap();
        state.absorb_part(TENANT_A, &unrelated, 100 * DAY_US).await.unwrap();
        let mut legacy = row(&["a", "b", "c"], 100);
        legacy.first_seen = 40 * DAY_US;
        legacy.daily_count = 50;
        let mut writes = WriteBatch::new();
        writes.put(key("ip", "8.8.8.8"), encode_v1(&legacy));
        state.commit(writes, true).await.unwrap();

        let mut read = event("8.8.8.8");
        state.stamp(&mut read).await.unwrap();
        assert_eq!(scalar(&read, "prevalence_dest_ip"), 3);
        assert_eq!(read["enrichments"][0]["data"]["total_occurrences"], 50);

        let part = temp.path().join("day-120.parquet");
        write_sorted(vec![row(&["c", "d"], 120)], &part).unwrap();
        state.absorb_part(TENANT_A, &part, 120 * DAY_US).await.unwrap();
        let value = state.db.get(key("ip", "8.8.8.8")).await.unwrap().unwrap();
        assert_eq!(value[0], VALUE_V2);
        let mut merged = event("8.8.8.8");
        state.stamp(&mut merged).await.unwrap();
        assert_eq!(scalar(&merged, "prevalence_dest_ip"), 4);
        assert_eq!(merged["enrichments"][0]["data"]["total_occurrences"], 52);
        // Day 130: window 101..=130. Legacy a and b (day 100) are gone; c
        // was seen again on day 120.
        state.advance_watermark(130 * DAY_US);
        let mut aged = event("8.8.8.8");
        state.stamp(&mut aged).await.unwrap();
        assert_eq!(scalar(&aged, "prevalence_dest_ip"), 2);
        assert!(decode(&[3, 0, 0]).is_err());
    }

    #[test]
    fn unstamped_ingest_strips_source_supplied_prevalence() {
        let mut forged = event("8.8.8.8");
        forged["prevalence_dest_ip"] = json!(9999);
        forged["prevalence_min"] = json!(9999);
        forged["enrichments"] = json!([
            {"name":"prevalence","provider":"nano","value":"8.8.8.8","data":{"host_count":9999}},
            {"name":"geo","provider":"nano"}
        ]);
        strip_stamps(&mut forged);
        assert!(forged.get("prevalence_dest_ip").is_none() && forged.get("prevalence_min").is_none());
        assert_eq!(forged["enrichments"], json!([{"name":"geo","provider":"nano"}]));
        strip_stamps(&mut json!(null));
    }

    #[tokio::test]
    async fn two_tenants_never_share_a_local_index_even_with_a_common_work_dir() {
        let temp = tempfile::tempdir().unwrap();
        let part = temp.path().join("prevalence.parquet");
        write_sorted(vec![row(&["one", "two"], 10)], &part).unwrap();
        let mut first = IngestPrevalence::open(TENANT_A, temp.path(), None)
            .await
            .unwrap();
        let second = IngestPrevalence::open(TENANT_B, temp.path(), None)
            .await
            .unwrap();
        first
            .absorb_part(TENANT_A, &part, 10 * DAY_US)
            .await
            .unwrap();
        let mut a = event("8.8.8.8");
        first.stamp(&mut a).await.unwrap();
        assert_eq!(scalar(&a, "prevalence_dest_ip"), 2);
        let mut b = event("8.8.8.8");
        second.stamp(&mut b).await.unwrap();
        assert_eq!(scalar(&b, "prevalence_dest_ip"), 1);
        assert!(IngestPrevalence::open("../escape", temp.path(), None)
            .await
            .is_err());
    }

    /// NAN-3554: close flushes the memtable to L0, so the WAL an open
    /// replays stays bounded however many close/reopen cycles run. The
    /// pre-fix close (WAL only) let the backlog grow with every cycle.
    #[tokio::test]
    async fn close_flushes_the_memtable_so_replay_stays_bounded() {
        const CYCLES: u32 = 5;
        const WALS: u32 = 10;
        let store: Arc<dyn ObjectStore> = Arc::new(InMemory::new());
        let mut state = IngestPrevalence::open_shared(TENANT_A, store.clone()).await.unwrap();
        state.initialize_at(0, &"0".repeat(64)).await.unwrap();
        for _ in 0..CYCLES {
            state.write_test_wals(WALS).await.unwrap();
            state.close().await.unwrap();
            state = IngestPrevalence::open_shared(TENANT_A, store.clone()).await.unwrap();
        }
        let bounded = wal_replay_backlog(store.clone()).await;
        assert!(bounded <= 2, "close flushed: only the fence WAL is left to replay, got {bounded}");

        // The pre-fix close: the backlog is every WAL of every cycle.
        let legacy: Arc<dyn ObjectStore> = Arc::new(InMemory::new());
        let mut state = IngestPrevalence::open_shared(TENANT_A, legacy.clone()).await.unwrap();
        state.initialize_at(0, &"0".repeat(64)).await.unwrap();
        for _ in 0..CYCLES {
            state.write_test_wals(WALS).await.unwrap();
            state.close_wal_only_for_test().await.unwrap();
            state = IngestPrevalence::open_shared(TENANT_A, legacy.clone()).await.unwrap();
        }
        let unbounded = wal_replay_backlog(legacy).await;
        assert!(unbounded >= (CYCLES * WALS) as u64, "WAL-only close leaves {unbounded} WALs to replay");
        // Every key survived the flushing close.
        assert!(state.db.get(b"zz-test/00000009").await.unwrap().is_some());
    }

    /// NAN-3781 (CT 106, 2026-10-13): a local state (open core, no grant)
    /// has no `maintenance[T]`. Without its own compactor every cadence
    /// flush added an L0 until `l0_max_ssts` (8); the ninth flush then never
    /// finished and writes stopped at `max_unflushed_bytes`. Twice the cap
    /// of memtable flushes all finish, L0 stays under the cap, and no key is
    /// lost.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_local_state_compacts_itself_past_the_l0_cap() {
        let temp = tempfile::tempdir().unwrap();
        let mut state = IngestPrevalence::open(TENANT_A, temp.path(), None).await.unwrap();
        state.initialize_at(0, &"0".repeat(64)).await.unwrap();
        for flush in 0..16 {
            state.write_test_wals(2).await.unwrap();
            let flushed = tokio::time::timeout(std::time::Duration::from_secs(60), state.flush_memtable()).await;
            assert!(matches!(flushed, Ok(Ok(()))), "memtable flush {flush} stalled: nothing freed L0 room");
        }
        // Flushes past the 8th could only finish because the compactor
        // merged L0 (see the no-compactor test). The last flush may land L0
        // exactly at the cap, which only blocks the *next* flush; the
        // compactor (5 s idle poll) brings it under.
        let local = || -> Arc<dyn ObjectStore> {
            Arc::new(LocalFileSystem::new_with_prefix(temp.path().join("prevalence").join(TENANT_A)).unwrap())
        };
        let l0 = l0_settles_under_cap(local).await;
        assert!(l0 < 8, "L0 settles under l0_max_ssts (was {l0})");
        assert!(state.has_test_key(1).await);
        assert!(state.applied().await.unwrap().is_some(), "the cursor survived compaction");
        tokio::time::timeout(std::time::Duration::from_secs(30), state.close()).await.unwrap().unwrap();
        // The reopen replays nothing a compactor-less writer would block on.
        let reopened = tokio::time::timeout(std::time::Duration::from_secs(30),
            IngestPrevalence::open(TENANT_A, temp.path(), None)).await.unwrap().unwrap();
        assert!(reopened.has_test_key(0).await);
    }

    /// NAN-4723: the production sizing of a local state from the ingest
    /// role's placement, and the settings `open_store` builds from it.
    #[test]
    fn a_local_state_is_sized_from_the_ingest_placement() {
        const MIB: u64 = 1024 * 1024;
        // Unknown placement and the smallest roles: the pre-NAN-4723 shape.
        assert_eq!(LocalStateSizing::for_placement(0, 0), LocalStateSizing::FLOOR);
        assert_eq!(LocalStateSizing::for_placement(250, 205 * MIB), LocalStateSizing::FLOOR);
        assert_eq!(LocalStateSizing::for_placement(3_999, 1024 * MIB), LocalStateSizing::FLOOR);
        // The NAN-4689 soak's ingest role: 16 cores, ~3.2 GB memory cap. The
        // ~405 MiB compaction budget holds 6 streams: 4 jobs, no splits, and
        // read-ahead per input stays the bounded compactor's.
        let soak = LocalStateSizing::for_placement(16_000, 3_244 * MIB);
        assert_eq!(soak, LocalStateSizing {
            compactions: 4, subcompactions: 1, fetch_tasks: 2, l0_max_ssts: 16,
            max_unflushed_bytes: (3_244 * MIB / 8) as usize,
        });
        // 8 cores: two jobs, L0 room doubled.
        let eight = LocalStateSizing::for_placement(8_000, 2048 * MIB);
        assert_eq!((eight.compactions, eight.subcompactions, eight.l0_max_ssts, eight.max_unflushed_bytes),
            (2, 2, 16, 256 * MIB as usize));
        // Many cores, unknown memory: the floor budget holds two streams.
        let unknown = LocalStateSizing::for_placement(16_000, 0);
        assert_eq!((unknown.compactions, unknown.subcompactions, unknown.max_unflushed_bytes),
            (2, 1, 128 * MIB as usize));
        // A 4-core sovereign host (16 GB): one job, as before; only the
        // unflushed budget follows the cap (1/8 of it).
        let small = LocalStateSizing::for_placement(4_000, 4 * 1024 * MIB);
        assert_eq!((small.compactions, small.subcompactions, small.fetch_tasks, small.l0_max_ssts, small.max_unflushed_bytes),
            (1, 1, 2, 8, 512 * MIB as usize));
        // Caps: jobs and unflushed bytes never grow without bound.
        let huge = LocalStateSizing::for_placement(128_000, 64 * 1024 * MIB);
        assert_eq!((huge.compactions, huge.subcompactions, huge.max_unflushed_bytes), (4, 2, 512 * MIB as usize));
        // Every placement's merge streams fit its compaction memory budget
        // (the unflushed share), and read-ahead per input never grows.
        for cpu in [0, 1_000, 4_000, 8_000, 12_000, 16_000, 64_000] {
            for cap in [0, 256 * MIB, 1024 * MIB, 3_244 * MIB, 8 * 1024 * MIB, 64 * 1024 * MIB] {
                let sizing = LocalStateSizing::for_placement(cpu, cap);
                assert!(sizing.compactions * sizing.subcompactions * LocalStateSizing::STREAM_BYTES <= sizing.max_unflushed_bytes,
                    "{cpu}m / {cap} B: {sizing:?}");
                assert_eq!(sizing.fetch_tasks, LocalStateSizing::FLOOR.fetch_tasks);
                assert!(sizing.subcompactions <= sizing.compactions);
            }
        }
        // The usable CPU never exceeds the limit or the process's cores.
        let cores = std::thread::available_parallelism().unwrap().get() as u32;
        assert_eq!(LocalStateSizing::usable_cpu_millis(0), 0);
        assert_eq!(LocalStateSizing::usable_cpu_millis(500), 500.min(cores * 1_000));
        assert_eq!(LocalStateSizing::usable_cpu_millis(u32::MAX), cores * 1_000);

        // The settings a local (embedded) state opens with.
        let settings = state_settings(Some(soak));
        assert_eq!((settings.l0_max_ssts, settings.l0_max_ssts_per_key, settings.max_unflushed_bytes),
            (16, 16, soak.max_unflushed_bytes));
        let compactor = settings.compactor_options.as_ref().expect("a local state compacts itself");
        assert_eq!(compactor.max_concurrent_compactions, 4);
        let worker = compactor.worker.as_ref().expect("the embedded worker runs");
        assert_eq!((worker.max_concurrent_compactions, worker.max_subcompactions, worker.max_fetch_tasks), (4, 1, 2));
        assert_eq!(worker.max_sst_size, super::super::maintenance::MAX_COMPACTED_SST_BYTES);
        assert!(settings.garbage_collector_options.is_some());
        // A granted state: maintenance[T] compacts; L0 and memory stay at the floor.
        let granted = state_settings(None);
        assert!(granted.compactor_options.is_none() && granted.garbage_collector_options.is_none());
        assert_eq!((granted.l0_max_ssts, granted.l0_max_ssts_per_key, granted.max_unflushed_bytes), (8, 8, 128 * MIB as usize));
        // The floor's local compactor is exactly maintenance[T]'s bounded one.
        let floor = local_compactor_options(LocalStateSizing::FLOOR);
        let bounded = super::super::maintenance::compactor_options();
        assert_eq!(floor.max_concurrent_compactions, bounded.max_concurrent_compactions);
        let (fw, bw) = (floor.worker.unwrap(), bounded.worker.unwrap());
        assert_eq!((fw.max_concurrent_compactions, fw.max_subcompactions, fw.max_fetch_tasks),
            (bw.max_concurrent_compactions, bw.max_subcompactions, bw.max_fetch_tasks));
    }

    /// NAN-4723, through the production open (`open_sized`, as
    /// `spawn_prevalence_open` calls it): a local state sized for the soak
    /// placement takes 24 memtable flushes (three times the old L0 cap)
    /// without one stalling, settles L0 under its own cap, and loses no key.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_placement_sized_local_state_takes_flush_bursts_past_the_old_cap() {
        let temp = tempfile::tempdir().unwrap();
        let sizing = LocalStateSizing::for_placement(16_000, 3 * 1024 * 1024 * 1024);
        assert_eq!(sizing.l0_max_ssts, 16);
        let mut state = IngestPrevalence::open_sized(TENANT_A, temp.path(), None, None, OBJECT_CACHE_FLOOR_BYTES, sizing)
            .await.unwrap();
        state.initialize_at(0, &"0".repeat(64)).await.unwrap();
        for flush in 0..24 {
            state.write_test_wals(2).await.unwrap();
            let flushed = tokio::time::timeout(std::time::Duration::from_secs(60), state.flush_memtable()).await;
            assert!(matches!(flushed, Ok(Ok(()))), "memtable flush {flush} stalled");
        }
        let local = || -> Arc<dyn ObjectStore> {
            Arc::new(LocalFileSystem::new_with_prefix(temp.path().join("prevalence").join(TENANT_A)).unwrap())
        };
        let l0 = l0_settles_under_cap(local).await;
        assert!(l0 < 8, "L0 settles (was {l0})");
        assert!(state.has_test_key(0).await && state.has_test_key(1).await);
        assert!(state.applied().await.unwrap().is_some(), "the cursor survived compaction");
        tokio::time::timeout(std::time::Duration::from_secs(30), state.close()).await.unwrap().unwrap();
    }

    /// L0 of the local state at `store`, polled until it is under the cap
    /// (at most 30 s: six idle polls of the embedded compactor).
    async fn l0_settles_under_cap(store: impl Fn() -> Arc<dyn ObjectStore>) -> usize {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
        loop {
            let l0 = super::super::maintenance::l0_count(store()).await.unwrap().expect("a manifest exists");
            if l0 < 8 || std::time::Instant::now() >= deadline {
                return l0;
            }
            tokio::time::sleep(std::time::Duration::from_millis(250)).await;
        }
    }

    /// NAN-3781, CT 106's exact state: a local DB written without a
    /// compactor (before this fix) sits at the L0 cap with unflushed WAL
    /// behind it. The first open with the embedded compactor replays that
    /// WAL, drains L0 and flushes again; no key is lost.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_local_state_stalled_at_the_l0_cap_drains_on_its_next_open() {
        let temp = tempfile::tempdir().unwrap();
        let directory = temp.path().join("prevalence").join(TENANT_A);
        std::fs::create_dir_all(&directory).unwrap();
        let local = || -> Arc<dyn ObjectStore> { Arc::new(LocalFileSystem::new_with_prefix(&directory).unwrap()) };
        let mut stalled = IngestPrevalence::open_store(TENANT_A, local(), "db", None, false, None, None).await.unwrap();
        stalled.initialize_at(0, &"0".repeat(64)).await.unwrap();
        let mut flushed = 0;
        for _ in 0..12 {
            stalled.write_test_wals(1).await.unwrap();
            if !stalled.flush_memtable_within(std::time::Duration::from_secs(3), "test").await {
                break;
            }
            flushed += 1;
        }
        assert_eq!(flushed, 8, "the pre-fix writer stalls at the cap");
        // WAL behind the stall, as on CT 106 (durable, never reached L0).
        stalled.write_test_wals(3).await.unwrap();
        drop(stalled);
        assert_eq!(super::super::maintenance::l0_count(local()).await.unwrap(), Some(8));

        let mut state = tokio::time::timeout(std::time::Duration::from_secs(60),
            IngestPrevalence::open(TENANT_A, temp.path(), None)).await
            .expect("the open must not hang on the full L0").unwrap();
        assert!(state.has_test_key(2).await, "the replayed WAL survived");
        state.write_test_wals(1).await.unwrap();
        let flushed = tokio::time::timeout(std::time::Duration::from_secs(60), state.flush_memtable()).await;
        assert!(matches!(flushed, Ok(Ok(()))), "the first flush after the reopen finishes");
        let l0 = l0_settles_under_cap(local).await;
        assert!(l0 < 8, "L0 drained under the cap (was {l0})");
        tokio::time::timeout(std::time::Duration::from_secs(30), state.close()).await.unwrap().unwrap();
    }

    async fn flush_n(state: &mut IngestPrevalence, n: u32) {
        for _ in 0..n {
            state.write_test_wals(1).await.unwrap();
            tokio::time::timeout(std::time::Duration::from_secs(60), state.flush_memtable()).await.unwrap().unwrap();
        }
    }

    /// NAN-3781 (CT 106 lab): the local state's collectors must all work on
    /// `LocalFileSystem`. With boundary files on, the first boundary advance
    /// is a create (fine) but every later one is a conditional overwrite
    /// (`PutMode::Update`), which `LocalFileSystem` does not implement: the
    /// manifest collector then fails each pass and deletes nothing (CT 106:
    /// an ERROR a minute). The local options (boundaries off) collect.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn local_gc_collects_on_the_local_filesystem() {
        let temp = tempfile::tempdir().unwrap();
        let mut state = IngestPrevalence::open(TENANT_A, temp.path(), None).await.unwrap();
        state.initialize_at(0, &"0".repeat(64)).await.unwrap();
        let root = temp.path().join("prevalence").join(TENANT_A);
        let manifests = || std::fs::read_dir(root.join("db/manifest")).unwrap()
            .filter(|entry| entry.as_ref().unwrap().file_name().to_string_lossy().ends_with(".manifest")).count();
        let local: Arc<dyn ObjectStore> = Arc::new(LocalFileSystem::new_with_prefix(&root).unwrap());
        let admin = slatedb::admin::AdminBuilder::new("db", local).build();
        // Everything old enough, so the collectors have files to delete.
        let now = |mut options: GarbageCollectorOptions| {
            let zero = Some(slatedb::config::GarbageCollectorDirectoryOptions {
                interval: None, min_age: std::time::Duration::ZERO, dry_run: false,
            });
            options.manifest_options = zero;
            options.compactions_options = zero;
            options.wal_options = zero;
            options.compacted_options = zero;
            options
        };
        let with_boundaries = || now(GarbageCollectorOptions::default());
        flush_n(&mut state, 4).await;
        admin.run_gc_once(with_boundaries()).await.unwrap();
        flush_n(&mut state, 4).await;
        let before = manifests();
        assert!(before > 2, "flushes wrote manifests ({before})");
        // The collector logs its error and returns Ok; nothing is deleted.
        let _ = admin.run_gc_once(with_boundaries()).await;
        assert_eq!(manifests(), before, "boundary advance (PutMode::Update) fails on LocalFileSystem");
        admin.run_gc_once(now(local_gc_options())).await.unwrap();
        let after = manifests();
        assert!(after < before, "the local collectors delete old manifests ({before} -> {after})");
        assert!(state.has_test_key(0).await);
        tokio::time::timeout(std::time::Duration::from_secs(30), state.close()).await.unwrap().unwrap();
    }

    /// NAN-3781: the cause, pinned. A writer without a compactor (a granted
    /// state's ingest side, here on a bare store) stalls at the L0 cap.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_state_without_a_compactor_stalls_at_the_l0_cap() {
        let store: Arc<dyn ObjectStore> = Arc::new(InMemory::new());
        let mut state = IngestPrevalence::open_shared(TENANT_A, store.clone()).await.unwrap();
        state.initialize_at(0, &"0".repeat(64)).await.unwrap();
        let mut stalled = None;
        for flush in 0..12 {
            state.write_test_wals(1).await.unwrap();
            if !state.flush_memtable_within(std::time::Duration::from_secs(3), "test").await {
                stalled = Some(flush);
                break;
            }
        }
        assert!(stalled.is_some(), "flushes must stall without a compactor");
        let l0 = super::super::maintenance::l0_count(store).await.unwrap().expect("a manifest exists");
        assert_eq!(l0, 8, "the stall is the L0 cap (l0_max_ssts)");
    }

    /// NAN-3554: the cadence flush is due after `MEMTABLE_FLUSH_EVERY` or
    /// `MEMTABLE_FLUSH_AFTER_WALS` WAL flushes, whichever comes first, and
    /// only when there is something to flush.
    #[tokio::test]
    async fn cadence_flush_is_due_by_time_or_wal_count() {
        let store: Arc<dyn ObjectStore> = Arc::new(InMemory::new());
        let mut state = IngestPrevalence::open_shared(TENANT_A, store.clone()).await.unwrap();
        state.initialize_at(0, &"0".repeat(64)).await.unwrap();
        state.write_test_wals(3).await.unwrap();
        assert!(!state.memtable_flush_due(), "a fresh window is not due");
        state.age_last_l0_flush(MEMTABLE_FLUSH_EVERY);
        assert!(state.memtable_flush_due(), "due by time");
        assert!(wal_replay_backlog(store.clone()).await >= 3);
        assert!(state.flush_memtable_bounded("test").await);
        assert_eq!(wal_replay_backlog(store.clone()).await, 0, "the flush advanced replay_after_wal_id");
        assert!(!state.memtable_flush_due(), "nothing new to flush");
        state.age_last_l0_flush(MEMTABLE_FLUSH_EVERY);
        assert!(!state.memtable_flush_due(), "a clean memtable is never flushed by the clock alone");
        state.age_last_l0_flush(std::time::Duration::ZERO);
        state.write_test_wals(MEMTABLE_FLUSH_AFTER_WALS - 1).await.unwrap();
        assert!(!state.memtable_flush_due());
        state.write_test_wals(1).await.unwrap();
        assert!(state.memtable_flush_due(), "due by WAL count");
    }

    /// NAN-4460: entries of `rows_per_entry` rows shaped like the large tenant's catch-up
    /// batches (2026-10-23: ~0.68 distinct keys a row): `recurring` rows from
    /// a rotating pool shared across entries, the rest new to the entry.
    fn b12_shaped_backlog(dir: &Path, first_seq: u64, entries: usize, rows_per_entry: usize, recurring: usize,
        day: i32) -> Vec<BatchEntry> {
        (0..entries).map(|n| {
            let host = format!("host-{}", n % 11);
            let rows = (0..recurring).map(|i| { let k = (n * 97 + i) % (4 * recurring); format!("10.{}.{}.{}", k / 65_536, k / 256 % 256, k % 256) })
                .chain((0..rows_per_entry - recurring).map(|i| format!("172.{}.{}.{}", n % 256, i / 256, i % 256)))
                .map(|ip| { let mut row = row(&[host.as_str(), "shared-host"], day); row.key.2 = ip; row })
                .collect::<Vec<_>>();
            let seq = first_seq + n as u64;
            let path = dir.join(format!("large-{day}-{seq}.parquet"));
            write_sorted(rows, &path).unwrap();
            BatchEntry { seq, sha256: format!("{seq:064x}"), parts: vec![(format!("p{day}-{seq}"), path, day as i64 * DAY_US)] }
        }).collect()
    }

    /// NAN-4460: measured peak heap of one catch-up batch, per partial row,
    /// on the production open path (object cache, a state that already holds
    /// multi-day priors for the batch's keys). `CATCH_UP_ROW_BYTES`, and so
    /// how far a batch may grow on a given memory cap, rests on this.
    #[test]
    fn catch_up_batch_heap_per_row_stays_under_the_budget() {
        let _workload = super::super::test_resources::PREVALENCE_WORKLOAD.blocking_read();
        let _serial = crate::test_heap::MEASUREMENT.lock().unwrap_or_else(|e| e.into_inner());
        let temp = tempfile::tempdir().unwrap();
        // 26 entries x 2,450 rows: the large tenant's batch (63,700 rows, under the row cap).
        let (entries, per_entry, recurring) = (26, 2_450, 1_000);
        let history = (7..10).map(|day| b12_shaped_backlog(temp.path(), 1 + (day - 7) as u64 * entries as u64,
            entries, per_entry, recurring, day)).collect::<Vec<_>>();
        let batch = b12_shaped_backlog(temp.path(), 1 + 3 * entries as u64, entries, per_entry, recurring, 10);
        let work = temp.path().join("work");
        let (peak, keys, rows) = std::thread::spawn(move || {
            crate::test_heap::track_current_thread(true);
            let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
            let measured = runtime.block_on(async {
                let store: Arc<dyn ObjectStore> = Arc::new(InMemory::new());
                let mut state = IngestPrevalence::open_with_reads(TENANT_A, &work, None, Some(store)).await.unwrap();
                state.initialize_at(0, &"0".repeat(64)).await.unwrap();
                for day in &history {
                    state.apply_entries_batch(TENANT_A, day).await.unwrap();
                }
                state.flush_memtable().await.unwrap();
                let base = crate::test_heap::reset_peak();
                let applied = state.apply_entries_batch(TENANT_A, &batch).await.unwrap();
                let peak = crate::test_heap::peak() - base;
                state.close().await.unwrap();
                (peak, applied.keys, applied.rows)
            });
            drop(runtime);
            crate::test_heap::track_current_thread(false);
            measured
        }).join().unwrap();
        let per_row = peak as f64 / rows as f64;
        eprintln!("catch-up batch: {rows} rows, {keys} keys ({:.2} keys/row), peak heap {:.1} MiB = {per_row:.0} B/row \
            (budget {CATCH_UP_ROW_BYTES} B/row)", keys as f64 / rows as f64, peak as f64 / 1048576.0);
        assert_eq!(rows, (entries * per_entry) as u64);
        assert!((0.55..0.85).contains(&(keys as f64 / rows as f64)), "the large tenant's key density: {keys} keys");
        assert!(per_row * 1.25 <= CATCH_UP_ROW_BYTES as f64, "the row budget keeps 25% over the measured peak: {per_row:.0} B/row");
    }

    /// NAN-4472: retain main's object request granularity; dense catch-up
    /// batches keep their locality and read approximately one state.
    #[tokio::test]
    async fn cold_batches_preserve_main_request_granularity_and_scan_dense_batches_once() {
        let _workload = super::super::test_resources::PREVALENCE_WORKLOAD.read().await;
        #[derive(Debug, Default)]
        struct ReadCounter {
            inner: InMemory,
            sst_bytes: std::sync::atomic::AtomicU64,
            sst_gets: std::sync::atomic::AtomicU64,
            unaligned: std::sync::atomic::AtomicU64,
        }
        impl std::fmt::Display for ReadCounter {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { write!(f, "ReadCounter") }
        }
        #[async_trait::async_trait]
        impl ObjectStore for ReadCounter {
            async fn put_opts(&self, path: &slatedb::object_store::path::Path, payload: slatedb::object_store::PutPayload,
                opts: slatedb::object_store::PutOptions) -> slatedb::object_store::Result<slatedb::object_store::PutResult> {
                self.inner.put_opts(path, payload, opts).await
            }
            async fn put_multipart_opts(&self, path: &slatedb::object_store::path::Path, opts: slatedb::object_store::PutMultipartOptions)
                -> slatedb::object_store::Result<Box<dyn slatedb::object_store::MultipartUpload>> {
                self.inner.put_multipart_opts(path, opts).await
            }
            async fn get_opts(&self, path: &slatedb::object_store::path::Path, options: slatedb::object_store::GetOptions)
                -> slatedb::object_store::Result<slatedb::object_store::GetResult> {
                let head = options.head;
                let mut result = self.inner.get_opts(path, options).await?;
                // InMemory returns a body even for HEAD. A real HEAD must
                // not prefill every disk-cache part on a supposedly cold open.
                if head {
                    result.payload = slatedb::object_store::GetResultPayload::Stream(stream::empty().boxed());
                }
                if !head && path.as_ref().contains("compacted/") {
                    use std::sync::atomic::Ordering::Relaxed;
                    let range = result.range.clone();
                    self.sst_gets.fetch_add(1, Relaxed);
                    self.sst_bytes.fetch_add(range.end - range.start, Relaxed);
                    let part = OBJECT_CACHE_PART_BYTES as u64;
                    if range.start % part != 0 || ((range.end - range.start) % part != 0 && range.end != result.meta.size) {
                        self.unaligned.fetch_add(1, Relaxed);
                    }
                }
                Ok(result)
            }
            fn delete_stream(&self, locations: futures::stream::BoxStream<'static, slatedb::object_store::Result<slatedb::object_store::path::Path>>)
                -> futures::stream::BoxStream<'static, slatedb::object_store::Result<slatedb::object_store::path::Path>> {
                self.inner.delete_stream(locations)
            }
            fn list(&self, prefix: Option<&slatedb::object_store::path::Path>)
                -> futures::stream::BoxStream<'static, slatedb::object_store::Result<slatedb::object_store::ObjectMeta>> {
                self.inner.list(prefix)
            }
            async fn list_with_delimiter(&self, prefix: Option<&slatedb::object_store::path::Path>)
                -> slatedb::object_store::Result<slatedb::object_store::ListResult> {
                self.inner.list_with_delimiter(prefix).await
            }
            async fn copy_opts(&self, from: &slatedb::object_store::path::Path, to: &slatedb::object_store::path::Path,
                options: slatedb::object_store::CopyOptions) -> slatedb::object_store::Result<()> {
                self.inner.copy_opts(from, to, options).await
            }
        }
        use std::sync::atomic::Ordering::Relaxed;
        let temp = tempfile::tempdir().unwrap();
        let counter = Arc::new(ReadCounter::default());
        let store: Arc<dyn ObjectStore> = counter.clone();
        // A state of 256k distinct hashes seen on 4 hosts each (~20 MB of
        // SSTs, several cache parts), flushed to SSTs.
        let keys = 256_000_usize;
        let hash = |k: usize| crate::parts::sha256_hex(&k.to_le_bytes());
        let entry = |dir: &Path, seq: u64, keys: &mut dyn Iterator<Item = usize>| {
            let rows = keys.map(|k| {
                let hosts = (0..4).map(|h| format!("host-{k}-{h}")).collect::<Vec<_>>();
                let mut row = row(&hosts.iter().map(String::as_str).collect::<Vec<_>>(), 10);
                row.key.0 = "hash".into();
                row.key.2 = hash(k);
                row
            }).collect::<Vec<_>>();
            let path = dir.join(format!("e{seq}.parquet"));
            write_sorted(rows, &path).unwrap();
            BatchEntry { seq, sha256: format!("{seq:064x}"), parts: vec![(format!("p{seq}"), path, 10 * DAY_US)] }
        };
        let mut state = IngestPrevalence::open_with_reads(TENANT_A, &temp.path().join("w0"), None, Some(store.clone())).await.unwrap();
        state.initialize_at(0, &"0".repeat(64)).await.unwrap();
        for chunk in 0..4 {
            let batch = vec![entry(temp.path(), chunk as u64 + 1, &mut (chunk * keys / 4..(chunk + 1) * keys / 4))];
            state.apply_entries_batch(TENANT_A, &batch).await.unwrap();
        }
        state.flush_memtable().await.unwrap();
        state.close().await.unwrap();
        let state_bytes: u64 = counter.inner.list(None).filter_map(|meta| async move { meta.ok() })
            .filter(|meta| std::future::ready(meta.location.as_ref().contains("compacted/")))
            .map(|meta| meta.size).collect::<Vec<_>>().await.into_iter().sum();
        // Three batches on fresh production caches, including open: sparse
        // point reads, a small batch, then dense catch-up.
        let mut fetched = Vec::new();
        for (round, wanted) in [16_usize, 1_000, 16_000].into_iter().enumerate() {
            counter.sst_bytes.store(0, Relaxed);
            counter.sst_gets.store(0, Relaxed);
            let mut state = IngestPrevalence::open_with_reads(TENANT_A, &temp.path().join(format!("cold{round}")), None,
                Some(store.clone())).await.unwrap();
            let seq = 5 + round as u64;
            let batch = vec![entry(temp.path(), seq, &mut (0..wanted).map(|i| i * (keys / wanted)))];
            let applied = state.apply_entries_batch(TENANT_A, &batch).await.unwrap();
            assert_eq!(applied.keys, wanted);
            fetched.push((wanted, counter.sst_gets.load(Relaxed), counter.sst_bytes.load(Relaxed)));
            state.close().await.unwrap();
        }
        eprintln!("state {state_bytes} B in SSTs; cold batch reads (keys, GETs, bytes): {fetched:?}");
        assert_eq!(counter.unaligned.load(Relaxed), 0, "SST reads align to cache parts, including coalesced metadata reads and object tails");
        let (sparse, small, large) = (fetched[0].2, fetched[1].2, fetched[2].2);
        assert_eq!(OBJECT_CACHE_PART_BYTES, 4 * 1024 * 1024, "dense paths must retain main request granularity");
        assert!(sparse <= 2 * state_bytes, "cold sparse reads retain main granularity: {sparse}");
        assert!(state_bytes > 3 * 4 * 1024 * 1024, "the state spans several cache parts: {state_bytes}");
        assert!(large as f64 >= state_bytes as f64 * 0.9, "dense catch-up still scans the state: {large} of {state_bytes}");
        assert!(large <= 2 * state_bytes, "dense reads must not repeatedly fetch the state: {large} of {state_bytes}; small {small}");
    }

    /// NAN-4460: the batch scale follows the backlog and halves under
    /// pressure. A short backlog keeps today's batch. The row cap follows the
    /// memory cap and is never below today's.
    #[test]
    fn catch_up_scale_follows_the_backlog_and_backs_off_under_pressure() {
        let base = CATCH_UP_BATCH_ENTRIES;
        assert_eq!(catch_up_scale_for_backlog(0, base), 1);
        assert_eq!(catch_up_scale_for_backlog(127, base), 1, "a restart-sized backlog keeps today's batch");
        assert_eq!(catch_up_scale_for_backlog(128, base), 2);
        assert_eq!(catch_up_scale_for_backlog(511, base), 4);
        assert_eq!(catch_up_scale_for_backlog(16_883, base), CATCH_UP_MAX_SCALE, "the large tenant's backlog");
        // Ramp 1 -> 2 -> 4 -> 8, one step per committed batch.
        let mut scale = 1;
        for expected in [2, 4, 8, 8] {
            scale = next_catch_up_scale(scale, 16_883, base, CatchUpHeadroom::Room);
            assert_eq!(scale, expected);
        }
        assert_eq!(next_catch_up_scale(8, 16_883, base, CatchUpHeadroom::Pressured), 4, "pressure halves");
        assert_eq!(next_catch_up_scale(1, 16_883, base, CatchUpHeadroom::Pressured), 1, "never below today's batch");
        assert_eq!(next_catch_up_scale(2, 16_883, base, CatchUpHeadroom::Hold), 2, "lag near its bound holds");
        assert_eq!(next_catch_up_scale(8, 200, base, CatchUpHeadroom::Hold), 2, "drops at once to what the backlog warrants");
        assert_eq!(next_catch_up_scale(8, 200, base, CatchUpHeadroom::Room), 2);
        assert_eq!(next_catch_up_scale(8, 0, base, CatchUpHeadroom::Room), 1);
        assert_eq!(next_catch_up_scale(usize::MAX, 16_883, base, CatchUpHeadroom::Room), CATCH_UP_MAX_SCALE);
        // NAN-4464: lag against the ingest stall bound (`lag_alert_ms`).
        let headroom = super::super::merge_quota::catch_up_headroom_given;
        assert_eq!(headroom(120_001, 120_000, false), CatchUpHeadroom::Pressured, "lag past its bound is pressure");
        assert_eq!(headroom(98_018, 120_000, false), CatchUpHeadroom::Hold, "lag near its bound holds");
        assert_eq!(headroom(71_910, 120_000, false), CatchUpHeadroom::Room, "the large tenant's healthy lag is room");
        assert_eq!(headroom(0, 120_000, true), CatchUpHeadroom::Pressured, "CPU throttling or R2 strain is pressure");
        assert_eq!(catch_up_max_rows_for(0), CATCH_UP_BATCH_ROWS, "unknown cap: today's rows");
        assert_eq!(catch_up_max_rows_for(512 * 1024 * 1024 / 10 * 4), CATCH_UP_BATCH_ROWS, "a 20 eps tenant keeps today's rows");
        assert_eq!(catch_up_max_rows_for(u64::MAX), CATCH_UP_BATCH_ROWS * CATCH_UP_MAX_SCALE as u64);
    }

    /// NAN-4464 convergence proof for the large tenant's backlog at the cell's real tick
    /// cadence. It drives the real scale controller, lag headroom and row
    /// cap through a tick-by-tick model of the ingest loop, with costs
    /// measured on the large tenant (hosted, 2026-10-23 20:37-20:45Z, the "prevalence
    /// catch-up batch applied", "ingest flush committed" and ingest-wait WARN
    /// lines, plus the cell's eth0 counters):
    /// - ticks run back to back: a tick's ingest phase takes ~0.5 s, a flush
    ///   tick's ~17 s, and a flush lands every ~35 s;
    /// - a batch's reads take >= 15 s (still running at the third 5 s cut
    ///   after the batch started) at ~240 MB/s of ingress, because they
    ///   re-download ~the state
    ///   (`cold_batches_preserve_main_request_granularity_and_scan_dense_batches_once`);
    ///   the model also charges 20 us a key on top;
    /// - a commit (fold ~0.1 s for 63k rows, write 1.05-1.4 s for ~43k keys);
    /// - scale 1: <= 65,536 rows, ~22 `Add` entries (~2,880 rows each) that
    ///   cover ~26 log entries;
    /// - ingest lag 72-98 s with ingest keeping up (4-10 notices pending);
    /// - the log head grows ~3.2 entries a minute;
    /// - net drain before the fix: 8,423 -> 8,136 behind in 6.3 min, ~46/min.
    ///
    /// Before the fix, a step waited on a running batch's reads until the 5 s
    /// ingest wait cut it, every tick, and the 30 s lag backoff pinned the
    /// scale at 1. The model reproduces that rate (calibration), then shows:
    /// - with the fix (steps skip while reads run, lag measured against its
    ///   bound) the large tenant's backlog drains well inside the hour;
    /// - every scale drains faster than ingest appends, even pinned at 1;
    /// - a step's foreground work (plan, fold, write) stays inside the ingest
    ///   wait at every scale;
    /// - ingest gets back the seconds per minute the old waits took.
    #[test]
    fn b12_backlog_drains_inside_the_hour_at_the_real_tick_cadence() {
        use super::super::ingest::{l0_merges_run_beside_prevalence, PREVALENCE_CATCH_UP_SCAN, PREVALENCE_INGEST_WAIT,
            PREVALENCE_L0_YIELD_MS};
        use super::super::merge_quota::catch_up_headroom_given;
        const BACKLOG: f64 = 8_300.0;
        const OBSERVED_NET_PER_MIN: f64 = 46.0;
        const APPEND_PER_MIN: f64 = 3.2;
        const FLUSH_EVERY_S: f64 = 35.0;
        const FLUSH_TICK_S: f64 = 17.0;
        const TICK_S: f64 = 0.5;
        const READ_FIXED_S: f64 = 18.0;
        // NAN-4472: charge a conservative 3 GiB cold sweep at the large tenant's
        // bandwidth plus each 4 MiB part's RTT on the production apply
        // lanes. This is a cost model, not production convergence evidence.
        let sweep_s = 3_072.0 / 130.0
            + (3.0 * 1024.0 * 1024.0 * 1024.0 / OBJECT_CACHE_PART_BYTES as f64 / APPLY_READS as f64).ceil() * 0.1;
        const READ_PER_KEY_S: f64 = 20e-6;
        const KEYS_PER_ROW: f64 = 0.68;
        const ROWS_PER_ADD: f64 = 2_880.0;
        const ENTRIES_PER_ADD: f64 = 1.18;
        const FOLD_PER_ROW_S: f64 = 0.11 / 63_000.0;
        const WRITE_FIXED_S: f64 = 1.0;
        const WRITE_PER_KEY_S: f64 = 8e-6;
        const PLAN_S: f64 = 0.3;
        const LIVE_LAG_MS: [i64; 4] = [71_910, 98_018, 85_000, 76_000];
        const LAG_BOUND_MS: i64 = 120_000;
        let wait = PREVALENCE_INGEST_WAIT.as_secs_f64();
        let max_rows = catch_up_max_rows_for(4_831_838_208);
        // One batch at `scale`: (log entries it covers, read seconds, commit
        // seconds of foreground work).
        let batch = |scale: usize| -> (f64, f64, f64) {
            let rows_cap = (CATCH_UP_BATCH_ROWS * scale as u64).min(max_rows.max(CATCH_UP_BATCH_ROWS)) as f64;
            let adds = (rows_cap / ROWS_PER_ADD).floor().min((CATCH_UP_BATCH_ENTRIES * scale) as f64);
            let entries = (adds * ENTRIES_PER_ADD).min((PREVALENCE_CATCH_UP_SCAN as usize * scale) as f64);
            let rows = adds * ROWS_PER_ADD;
            let keys = rows * KEYS_PER_ROW;
            (entries, READ_FIXED_S + keys * READ_PER_KEY_S, PLAN_S + rows * FOLD_PER_ROW_S + WRITE_FIXED_S + keys * WRITE_PER_KEY_S)
        };
        for scale in (0..=CATCH_UP_MAX_SCALE.trailing_zeros()).map(|bit| 1_usize << bit) {
            let (entries, read, commit) = batch(scale);
            assert!(commit < wait, "scale {scale}: a commit step ({commit:.2} s) fits the ingest wait");
            let cycle = read + commit + FLUSH_TICK_S;
            assert!(entries >= 2.0 * APPEND_PER_MIN * cycle / 60.0,
                "scale {scale}: a batch drains at least twice what ingest appends meanwhile");
        }
        // (minutes to the head, seconds of prevalence steps per minute,
        // largest scale).
        let drain = |fixed: bool| -> (f64, f64, usize) {
            let (mut t, mut behind, mut scale, mut largest) = (0.0_f64, BACKLOG, 1_usize, 1_usize);
            let (mut next_flush, mut stepping, mut batches) = (FLUSH_EVERY_S, 0.0_f64, 0_usize);
            let (entries, read, _) = batch(scale);
            let read_cost = |read: f64| if fixed { read + (sweep_s - READ_FIXED_S).max(0.0) } else { read };
            let (mut covers, mut reads_done) = (entries, t + PLAN_S + read_cost(read));
            while behind > 0.0 && t < 24.0 * 3_600.0 {
                let tick_start = t;
                let step = if t >= reads_done {
                    // Commit, rescale, start the next batch's reads.
                    let (_, _, commit) = batch(scale);
                    behind -= covers;
                    batches += 1;
                    scale = if fixed {
                        let lag = LIVE_LAG_MS[batches % LIVE_LAG_MS.len()];
                        next_catch_up_scale(scale, behind.max(0.0) as u64, CATCH_UP_BATCH_ENTRIES,
                            catch_up_headroom_given(lag, LAG_BOUND_MS, false))
                    } else {
                        // Before: lag >= 72 s against the 30 s backoff.
                        next_catch_up_scale(scale, behind.max(0.0) as u64, CATCH_UP_BATCH_ENTRIES, CatchUpHeadroom::Pressured)
                    };
                    largest = largest.max(scale);
                    let (entries, read, _) = batch(scale);
                    covers = entries;
                    reads_done = t + commit + read_cost(read);
                    // Before: the step then waited on the new reads until cut.
                    if fixed { commit } else { wait }
                } else if fixed {
                    0.0
                } else {
                    wait
                };
                stepping += step;
                t += step;
                if t >= next_flush {
                    t += FLUSH_TICK_S;
                    next_flush = t + FLUSH_EVERY_S;
                } else {
                    t += TICK_S;
                }
                behind += APPEND_PER_MIN * (t - tick_start) / 60.0;
            }
            (t / 60.0, stepping / (t / 60.0), largest)
        };
        let (before, before_stepping, _) = drain(false);
        let (after, after_stepping, largest) = drain(true);
        let modeled = BACKLOG / before;
        eprintln!("the large-tenant model: max_rows {max_rows}; before {before:.0} min ({modeled:.0}/min, {before_stepping:.0} s/min in steps); \
            after (scale to {largest}) {after:.0} min ({after_stepping:.1} s/min in steps)");
        assert!((modeled / OBSERVED_NET_PER_MIN - 1.0).abs() < 0.3,
            "the model reproduces the large tenant before the fix: {modeled:.0}/min vs {OBSERVED_NET_PER_MIN}/min observed");
        assert!(before > 2.0 * 60.0 && before < 24.0 * 60.0, "before: hours, but converging ({before:.0} min)");
        assert_eq!(largest, CATCH_UP_MAX_SCALE, "the large tenant's live lag lets the scale rise");
        assert!(after < 60.0, "the large tenant's 8.3k entries drain inside the hour even charging smaller parts' RTTs: {after:.0} min");
        assert!(after_stepping < before_stepping / 4.0, "ingest gets back the old waits");
        assert!(l0_merges_run_beside_prevalence(PREVALENCE_L0_YIELD_MS), "L0 merges keep their yield bound");
    }
}

#[cfg(test)]
#[path = "prevalence_steady_tests.rs"]
pub(crate) mod steady_tests;
