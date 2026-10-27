// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-4554: the bronze quarantine survives pod replacement.
//!
//! The quarantine ([`super::quarantine`]) lives under ingest[T]'s work dir.
//! On k8s that is the generic EPHEMERAL "data" volume, so every pod
//! replacement (a roll, a node loss) deleted every kept object, and the
//! edge-acknowledged rows it held were gone. Now every change to it is
//! mirrored into the tenant's own bucket, and a fresh work dir restores it:
//!
//! - **Layout.** Under the tenant's `log/checkpoints/bronze-quarantine-v1/`:
//!   `objects/{id}.parquet` (the kept bytes; `id` is their SHA-256, so the
//!   key is content-addressed) and `records/{written_ms:013}-{sha16}.json`,
//!   immutable records of `{kind, tenant_id, id, entry}` where `entry` is the
//!   entry as it is now, or null once it was released (its replay committed).
//!   The newest record of an id is its state. Ingest holds no delete
//!   authority under `log/checkpoints/`, so ingest never deletes there:
//!   every object ever kept stays in the bucket (the local 1 GiB cap does
//!   NOT bound the bucket) until the lake-part GC's sanctioned
//!   `quarantine_expired` delete (NAN-4567) removes it past the restore
//!   horizon. There is no R2 lifecycle rule (the tenant-bucket invariant
//!   stays). Expiry and the size cap apply on restore: an entry past
//!   `expires_at_ms` is never restored, and the caps are applied newest
//!   first BEFORE anything is downloaded. The GC side is
//!   `lake_part_gc::quarantine_expiry`.
//! - **Per tenant.** Only the tenant's own prefix, with the tenant's part
//!   credential. A record naming another tenant, or an object whose bytes do
//!   not hash to its id, is skipped.
//! - **Durable before the ack.** A change is first queued in the local
//!   outbox (`bronze-quarantine/outbox/{id}`, which outlives a process
//!   restart), then mirrored before the flush that acknowledges the refused
//!   object to its source. While the bucket refuses, that flush waits up to
//!   [`MIRROR_HOLD_MS`]; after that it proceeds pod-local (as before this
//!   change) with an error line, so a bucket outage never wedges ingest.
//! - **Restore** runs once per work dir (a `restored-v1` marker; process
//!   restarts in the same pod keep the local copy and skip it). It lists
//!   the horizon, reads the newest [`RESTORE_MAX_RECORDS`] records, then
//!   downloads live entries newest first only while they fit the local caps
//!   and leave [`RESTORE_DISK_RESERVE_BYTES`] free on the volume; otherwise
//!   it stops with [`RESTORE_DISK_LOW`] (health `quarantine_restore_refused`)
//!   and stays pending, retried every [`RESTORE_REFUSED_RETRY_MS`].
//! - **Released stays released** (review P1). A release record carries
//!   `released: true`; the restore keeps a local tombstone for it, and an
//!   operator import of a released id (or of any id while the restore is
//!   pending) is refused, so a replayed object is never admitted again
//!   (uid dedupe covers only the 72 h late tier).
//! - **Backoff.** A failing mirror of one id backs off on its own
//!   (exponential, capped at [`MIRROR_RETRY_MAX_MS`]) and never blocks later
//!   ids; an object PUT that succeeded is not repeated when only its record
//!   failed. A failing restore backs off the same way. Health carries
//!   `quarantine_mirror_failing_ids` and `quarantine_restore_pending` /
//!   `quarantine_restore_error` for the roll gate.
//!
//! CF cost (R2), success path: keeping an object costs 2 class A PUTs
//! (object + record); a replay request, a refusal of a replay, and a release
//! add 1 PUT each. A restore costs 1 LIST per 1,000 records within the
//! horizon, 1 GET per record read and 1 GET per restored object, only on a
//! fresh work dir. While the bucket refuses, each failing id costs at most
//! one PUT attempt per backoff step (≤ 1 per [`MIRROR_RETRY_MAX_MS`] once
//! backed off), and a failing restore at most one pass per backoff step.
//! Storage is every byte ever quarantined until NAN-4567's expiry deletes
//! it (8 d); it is not bounded by the local cap.

use anyhow::{ensure, Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use super::quarantine::{Quarantine, QuarantineEntry, QUARANTINE_TTL_MS};
use crate::parts::format::LogKeys;
use crate::parts::part_log::{ObjectStore, WriteHints, WriterClass};
use crate::parts::{event_hour_of, sha256_hex};

pub(crate) const QUARANTINE_STORE_DIR: &str = "bronze-quarantine-v1/";
const RECORD_KIND: &str = "nano.lake.bronze-quarantine-record.v1";
/// Records older than the TTL (plus a day of slack for clock skew between
/// pods) can only describe expired entries, so the restore skips them.
pub(crate) const RESTORE_HORIZON_MS: i64 = QUARANTINE_TTL_MS + 86_400_000;
/// How long a flush waits for the bucket to take a quarantine change before
/// it proceeds with the change kept pod-local only.
pub const MIRROR_HOLD_MS: i64 = 10 * 60_000;
/// Longest wait between retries of one failing mirror id, or of a failing
/// restore.
pub const MIRROR_RETRY_MAX_MS: i64 = 5 * 60_000;
const MIRROR_RETRY_BASE_MS: i64 = 2_000;

/// The wait before retry `failures` (1-based) of a mirror id or a restore.
pub(crate) fn retry_after_ms(failures: u32) -> i64 {
    MIRROR_RETRY_BASE_MS.saturating_mul(1_i64 << failures.saturating_sub(1).min(20)).min(MIRROR_RETRY_MAX_MS)
}
const RESTORE_PAGE_KEYS: usize = 1_000;
/// Records one restore reads at most: the newest in the horizon (the cap
/// holds at most 1 GiB of objects; a record is written a few times per
/// object). Older ones are listed past, never read.
const RESTORE_MAX_RECORDS: usize = 64 * RESTORE_PAGE_KEYS;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    kind: String,
    tenant_id: String,
    id: String,
    /// The entry now; `None` once released or dropped.
    entry: Option<QuarantineEntry>,
    /// NAN-4554 (review P1): `entry` is `None` because the replay committed
    /// (not an eviction): a restore keeps the release tombstone, so the id
    /// is never imported again. Omitted when false (records stay as before).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    released: bool,
}

pub(crate) fn store_prefix(tenant_id: &str) -> Result<String> {
    Ok(format!("{}{QUARANTINE_STORE_DIR}", LogKeys::new(tenant_id)?.checkpoints_prefix()))
}

fn object_key(tenant_id: &str, id: &str) -> Result<String> {
    ensure!(crate::parts::is_sha256_hex(id), "invalid quarantine id");
    Ok(format!("{}objects/{id}.parquet", store_prefix(tenant_id)?))
}

fn records_prefix(tenant_id: &str) -> Result<String> {
    Ok(format!("{}records/", store_prefix(tenant_id)?))
}

fn record_matches(prefix: &str, key: &str, bytes: &[u8]) -> bool {
    key.strip_prefix(prefix).is_some_and(|name| name.len() == 35
        && name.as_bytes()[..13].iter().all(u8::is_ascii_digit)
        && name[13..] == format!("-{}.json", &sha256_hex(bytes)[..16]))
}

/// A record exactly as restore accepts it: its key names its bytes, and it
/// is the tenant's own, well-formed record.
fn parse_record(tenant: &str, prefix: &str, key: &str, body: &[u8]) -> Option<Record> {
    serde_json::from_slice::<Record>(body).ok().filter(|record| record_matches(prefix, key, body)
        && record.kind == RECORD_KIND && record.tenant_id == tenant
        && crate::parts::is_sha256_hex(&record.id)
        && record.entry.as_ref().is_none_or(|entry| entry.id == record.id && entry.tenant_id == tenant))
}

/// NAN-4567: the id a record at `key` names, when restore would read it
/// (`None` for a foreign, corrupt or mis-keyed record, which restore skips).
pub(crate) fn record_id(tenant_id: &str, key: &str, body: &[u8]) -> Option<String> {
    let prefix = records_prefix(tenant_id).ok()?;
    parse_record(tenant_id, &prefix, key, body).map(|record| record.id)
}

/// Mirror `id`'s current state (its entry and bytes, or its release) into
/// the tenant bucket.
pub(crate) async fn mirror(store: &dyn ObjectStore, quarantine: &Quarantine, id: &str, written_ms: i64) -> Result<()> {
    mirror_once(store, quarantine, id, written_ms, &mut false).await
}

/// [`mirror`], skipping the object PUT when `object_mirrored` says an
/// earlier try already put these (content-addressed) bytes; set once the
/// object PUT succeeds, so a retry after a failed record never re-uploads
/// up to 128 MiB.
pub(crate) async fn mirror_once(store: &dyn ObjectStore, quarantine: &Quarantine, id: &str, written_ms: i64,
    object_mirrored: &mut bool) -> Result<()> {
    ensure!((0..=9_999_999_999_999).contains(&written_ms), "quarantine record time out of range");
    let tenant = quarantine.tenant();
    // An entry whose bytes are gone (evicted by the cap meanwhile) is
    // mirrored as released: nothing is left to replay.
    let entry = match quarantine.get(id)? {
        Some(entry) if quarantine.data_file(id)?.is_some() => Some(entry),
        _ => None,
    };
    if let Some(entry) = &entry {
        let (path, bytes) = quarantine.data_file(id)?.context("quarantined bytes vanished before they were mirrored")?;
        let hints = WriteHints {
            class: WriterClass::LakePart,
            event_hour: event_hour_of(written_ms * 1_000),
            min_time_ms: written_ms,
            max_time_ms: written_ms,
        };
        let key = object_key(tenant, id)?;
        ensure!(entry.bytes == bytes, "quarantine entry {id} disagrees with its bytes");
        if !*object_mirrored {
            // Content-addressed: an existing object holds exactly these bytes.
            store.put_file_if_absent_with(&key, &path, id, bytes, &hints).await
                .with_context(|| format!("mirror quarantined object {id}"))?;
            *object_mirrored = true;
        }
    }
    let released = entry.is_none() && quarantine.released_at(id)?.is_some();
    let record = Record { kind: RECORD_KIND.into(), tenant_id: tenant.into(), id: id.into(), entry, released };
    let body = serde_json::to_vec(&record)?;
    let key = format!("{}{written_ms:013}-{}.json", records_prefix(tenant)?, &sha256_hex(&body)[..16]);
    if !store.put_if_absent(&key, &body).await? {
        ensure!(store.get(&key).await?.as_deref() == Some(body.as_slice()), "quarantine record differs");
    }
    Ok(())
}

/// The write time a record key carries (`records/{written_ms:013}-…`).
fn record_written_ms(prefix: &str, key: &str) -> Option<i64> {
    key.strip_prefix(prefix)?.get(..13)?.parse().ok()
}

/// What [`restore`] did.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Restored {
    pub entries: usize,
    pub skipped: usize,
    /// Live entries not downloaded because the local caps (1 GiB, newest
    /// first; 128 MiB per object) were already met: never fetched.
    pub over_cap: usize,
    /// Records older than the newest [`RESTORE_MAX_RECORDS`] in the horizon:
    /// not read (the newest are; ids only in older records stay in the
    /// bucket, never restored).
    pub records_beyond_bound: usize,
    /// A named reason the restore stopped before it was done, so the roll
    /// can gate on it: [`RESTORE_DISK_LOW`].
    pub refused: Option<&'static str>,
    /// With `records_beyond_bound`: the write time of the oldest record
    /// read (imports of entries older than it are refused).
    pub low_water_ms: Option<i64>,
}

/// The restore stopped: the volume would keep less than
/// [`RESTORE_DISK_RESERVE_BYTES`] free after the next download.
pub const RESTORE_DISK_LOW: &str = "restore_disk_low";
/// Free space a restore always leaves on the work dir's volume (the spool,
/// the parts cache and admission share it).
pub const RESTORE_DISK_RESERVE_BYTES: u64 = 2 << 30;
/// Review P2: a restore that stopped early stays pending and is retried no
/// sooner than this (a pass re-reads the records: ≤ 48 passes a day).
pub const RESTORE_REFUSED_RETRY_MS: i64 = 30 * 60_000;

/// Rebuild a fresh local quarantine from the tenant bucket: the newest
/// record of every id within the horizon, live entries only, newest first
/// and only up to the local caps BEFORE anything is downloaded, and never
/// past [`RESTORE_DISK_RESERVE_BYTES`] of free disk (review P1: the bucket
/// holds every object ever kept until NAN-4567's GC expiry, far more than
/// the 1 GiB local cap).
pub(crate) async fn restore(store: &dyn ObjectStore, quarantine: &Quarantine, now_ms: i64) -> Result<Restored> {
    restore_bounded(store, quarantine, now_ms, &|dir| Ok(fs2::available_space(dir)?), RESTORE_MAX_RECORDS).await
}

/// [`restore`] with the free-space probe and the record bound injected.
pub(crate) async fn restore_bounded(store: &dyn ObjectStore, quarantine: &Quarantine, now_ms: i64,
    free_space: &(dyn Fn(&std::path::Path) -> Result<u64> + Sync), max_records: usize) -> Result<Restored> {
    let tenant = quarantine.tenant().to_string();
    let prefix = records_prefix(&tenant)?;
    let mut after = Some(format!("{prefix}{:013}", now_ms.saturating_sub(RESTORE_HORIZON_MS).max(0)));
    let mut restored = Restored::default();
    // 1. List every record in the horizon (keys sort by write time) and
    //    keep the newest RESTORE_MAX_RECORDS: a long refusal week degrades
    //    to its newest records instead of failing the restore.
    let mut keys = std::collections::VecDeque::new();
    loop {
        let page = store.list_page(&prefix, after.as_deref(), RESTORE_PAGE_KEYS).await?;
        for key in &page {
            ensure!(key.starts_with(&prefix), "quarantine record listing escaped its prefix");
            ensure!(after.as_deref().is_none_or(|after| key.as_str() > after), "quarantine record listing went backwards");
        }
        after = page.last().cloned().or(after);
        let full = page.len() == RESTORE_PAGE_KEYS;
        for key in page {
            keys.push_back(key);
            if keys.len() > max_records {
                keys.pop_front();
                restored.records_beyond_bound += 1;
            }
        }
        if !full {
            break;
        }
    }
    if restored.records_beyond_bound > 0 {
        tracing::warn!(tenant = %tenant, beyond = restored.records_beyond_bound, read = keys.len(),
            "bronze quarantine restore: more records in the horizon than the bound; reading the newest only");
    }
    let mut keys = Vec::from(keys);
    keys.sort_unstable();
    if restored.records_beyond_bound > 0 {
        restored.low_water_ms = Some(keys.first().and_then(|key| record_written_ms(&prefix, key)).unwrap_or(i64::MAX));
    }
    // 2. The newest record per id (small JSON GETs).
    let mut newest: BTreeMap<String, (Option<QuarantineEntry>, bool, i64)> = BTreeMap::new();
    let mut mirrored = std::collections::BTreeSet::new();
    for key in &keys {
        let Some(body) = store.get(key).await? else { continue };
        let record = match parse_record(&tenant, &prefix, key, &body) {
            Some(record) => record,
            None => {
                tracing::warn!(tenant = %tenant, %key, "skipping unreadable or foreign bronze quarantine record");
                restored.skipped += 1;
                continue;
            }
        };
        // Keys sort by write time: a later record supersedes an earlier one.
        mirrored.insert(record.id.clone());
        let written_ms = record_written_ms(&prefix, key).unwrap_or(now_ms);
        newest.insert(record.id, (record.entry, record.released, written_ms));
    }
    // 3. Live entries newest first; the caps apply before any download.
    let mut live = Vec::new();
    for (id, (entry, released, written_ms)) in newest {
        match entry {
            // Released elsewhere (its replay committed): never offered
            // again, and (review P1) never imported again either.
            None => {
                if released {
                    quarantine.tombstone(&id, written_ms)?;
                }
                quarantine.remove_local(&id)?
            }
            // A release here not mirrored yet (a restore retried after a
            // replay committed) wins over the older live record.
            Some(entry) if entry.expires_at_ms > now_ms && quarantine.get(&id)?.is_none()
                && quarantine.released_at(&id)?.is_none() => live.push(entry),
            Some(_) => {}
        }
    }
    live.sort_by(|a, b| b.quarantined_at_ms.cmp(&a.quarantined_at_ms).then_with(|| a.id.cmp(&b.id)));
    let (max_bytes, max_object_bytes) = quarantine.limits();
    let mut used = quarantine.usage()?.1;
    let staging = quarantine.staging_path("restore");
    let mut live = live.into_iter();
    while let Some(entry) = live.next() {
        if entry.bytes > max_object_bytes {
            restored.over_cap += 1;
            continue;
        }
        if used.saturating_add(entry.bytes) > max_bytes {
            // The cap keeps the newest: everything older stays in the bucket.
            restored.over_cap += 1 + live.len();
            break;
        }
        let free = free_space(quarantine.dir())?;
        if free < entry.bytes.saturating_add(RESTORE_DISK_RESERVE_BYTES) {
            tracing::error!(tenant = %tenant, free_bytes = free, needed = entry.bytes, reserve = RESTORE_DISK_RESERVE_BYTES,
                left = 1 + live.len(), "bronze quarantine restore stopped: the work dir's volume is low on space (restore_disk_low)");
            restored.refused = Some(RESTORE_DISK_LOW);
            break;
        }
        let id = entry.id.clone();
        if !store.get_to_file(&object_key(&tenant, &id)?, &staging).await? {
            tracing::warn!(tenant = %tenant, %id, "quarantined object missing from the tenant bucket; entry not restored");
            restored.skipped += 1;
            continue;
        }
        let (bytes, digest) = super::writer::file_digest(&staging)?;
        if digest != id || bytes != entry.bytes {
            let _ = std::fs::remove_file(&staging);
            tracing::warn!(tenant = %tenant, %id, "restored quarantine bytes do not match their id; entry not restored");
            restored.skipped += 1;
            continue;
        }
        quarantine.adopt(&entry, &staging)?;
        used += entry.bytes;
        restored.entries += 1;
    }
    let _ = std::fs::remove_file(&staging);
    if restored.over_cap > 0 {
        tracing::warn!(tenant = %tenant, over_cap = restored.over_cap,
            "bronze quarantine restore: entries beyond the local caps were left in the bucket (newest kept)");
    }
    // The same expiry and cap as the copy that was lost.
    quarantine.sweep(now_ms)?;
    // Entries kept here before this work dir was ever mirrored (an image
    // without NAN-4554) and absent from the bucket: mirror them now.
    for entry in quarantine.list()? {
        if !mirrored.contains(&entry.id) {
            quarantine.enqueue_mirror(&entry.id, now_ms)?;
        }
    }
    Ok(restored)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::part_ingest::quarantine::{Kept, Refusal};
    use crate::parts::part_log::LocalObjectStore;

    const TENANT: &str = "45540000-0000-4000-8000-000000000001";
    const OTHER: &str = "45540000-0000-4000-8000-000000000002";
    const NOW: i64 = 1_800_000_000_000;

    fn refusal() -> Refusal<'static> {
        Refusal { source_key: "bronze/a.parquet", source_version: "1", scope: "object", reason: "admission_invalid",
            detail: "admission_crashed: test", rows_rejected: 7 }
    }

    fn keep(quarantine: &Quarantine, dir: &std::path::Path, body: &[u8], now_ms: i64) -> String {
        let id = sha256_hex(body);
        let path = dir.join(format!("{id}.bin"));
        std::fs::write(&path, body).unwrap();
        assert_eq!(quarantine.keep(&path, &id, &refusal(), now_ms).unwrap(), Kept::New);
        id
    }

    async fn drain(store: &dyn ObjectStore, quarantine: &Quarantine, now_ms: i64) {
        for (offset, (id, _)) in quarantine.outbox().unwrap().into_iter().enumerate() {
            mirror(store, quarantine, &id, now_ms + offset as i64).await.unwrap();
            quarantine.outbox_done(&id).unwrap();
        }
    }

    /// A fresh work dir (pod replacement) gets back exactly the live
    /// entries, bytes verified; a released one never comes back.
    #[tokio::test(flavor = "current_thread")]
    async fn a_fresh_work_dir_restores_live_entries_and_never_a_released_one() {
        let root = tempfile::tempdir().unwrap();
        let store = LocalObjectStore::new(root.path().join("bucket")).unwrap();
        let old = Quarantine::open(&root.path().join("pod-1"), TENANT).unwrap();
        let kept = keep(&old, root.path(), b"poison bytes", NOW);
        let released = keep(&old, root.path(), b"replayed bytes", NOW + 1);
        drain(&store, &old, NOW + 10).await;
        old.request_replay(TENANT, &kept, NOW + 20).unwrap();
        old.release(&released, NOW + 30).unwrap();
        drain(&store, &old, NOW + 40).await;
        assert!(old.outbox().unwrap().is_empty());

        let fresh = Quarantine::open(&root.path().join("pod-2"), TENANT).unwrap();
        assert!(fresh.needs_restore());
        let restored = restore(&store, &fresh, NOW + 50).await.unwrap();
        assert_eq!(restored, Restored { entries: 1, ..Restored::default() });
        let entries = fresh.list().unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!((entries[0].id.as_str(), entries[0].rows_rejected), (kept.as_str(), 7));
        assert_eq!(entries[0].replay_requested_at_ms, Some(NOW + 20), "the newest record wins");
        let copy = root.path().join("copy");
        assert!(fresh.copy_to(&kept, &copy).unwrap());
        assert_eq!(std::fs::read(&copy).unwrap(), b"poison bytes");
        assert!(fresh.get(&released).unwrap().is_none(), "released: never offered again");
        assert!(fresh.released_at(&released).unwrap().is_some_and(|at| (NOW + 40..NOW + 50).contains(&at)), "review P1: the release tombstone is restored at its record time");
        assert!(fresh.released_at(&kept).unwrap().is_none());
        assert!(fresh.outbox().unwrap().is_empty(), "restored entries are already in the bucket");
    }

    /// The same TTL and cap as the lost copy; another tenant's records and
    /// bytes that do not hash to their id are skipped.
    #[tokio::test(flavor = "current_thread")]
    async fn restore_applies_the_ttl_and_cap_and_skips_foreign_or_corrupt_records() {
        let root = tempfile::tempdir().unwrap();
        let store = LocalObjectStore::new(root.path().join("bucket")).unwrap();
        let old = Quarantine::open(&root.path().join("pod-1"), TENANT).unwrap();
        let expired = keep(&old, root.path(), b"old bytes", NOW);
        let live = keep(&old, root.path(), b"new bytes", NOW + QUARANTINE_TTL_MS / 2);
        let corrupt = keep(&old, root.path(), b"bytes that will rot", NOW + QUARANTINE_TTL_MS / 2 + 1);
        drain(&store, &old, NOW + QUARANTINE_TTL_MS / 2 + 10).await;
        // The stored copy of `corrupt` no longer matches its id.
        let key = object_key(TENANT, &corrupt).unwrap();
        std::fs::write(root.path().join("bucket").join(&key), b"tampered").unwrap();
        // A record for another tenant planted under this tenant's prefix.
        let mut foreign = old.get(&live).unwrap().unwrap();
        foreign.tenant_id = OTHER.into();
        let body = serde_json::to_vec(&Record { kind: RECORD_KIND.into(), tenant_id: OTHER.into(), id: live.clone(), entry: Some(foreign), released: false }).unwrap();
        let planted = format!("{}{:013}-{}.json", records_prefix(TENANT).unwrap(), NOW + QUARANTINE_TTL_MS / 2 + 100, &sha256_hex(&body)[..16]);
        assert!(store.put_if_absent(&planted, &body).await.unwrap());

        let now = NOW + QUARANTINE_TTL_MS + 1;
        let fresh = Quarantine::open(&root.path().join("pod-2"), TENANT).unwrap();
        let restored = restore(&store, &fresh, now).await.unwrap();
        assert_eq!(restored.entries, 1, "{restored:?}");
        assert_eq!(restored.skipped, 2, "the foreign record and the tampered bytes");
        assert!(fresh.get(&expired).unwrap().is_none(), "past its TTL");
        assert!(fresh.get(&corrupt).unwrap().is_none());
        assert!(fresh.get(&live).unwrap().is_some());

        // The cap evicts the oldest on restore, as on the original copy.
        let capped = Quarantine::open(&root.path().join("pod-3"), TENANT).unwrap().with_limits(10, 10);
        let more = keep(&old, root.path(), b"fresher!", NOW + QUARANTINE_TTL_MS / 2 + 2);
        drain(&store, &old, NOW + QUARANTINE_TTL_MS / 2 + 200).await;
        restore(&store, &capped, now).await.unwrap();
        assert_eq!(capped.list().unwrap().iter().map(|entry| entry.id.as_str()).collect::<Vec<_>>(), [more.as_str()]);
    }

    /// Entries kept before this work dir was ever mirrored (an image without
    /// NAN-4554, same pod) are queued for the bucket on the first restore.
    #[tokio::test(flavor = "current_thread")]
    async fn entries_kept_before_mirroring_are_queued_on_the_first_restore() {
        let root = tempfile::tempdir().unwrap();
        let store = LocalObjectStore::new(root.path().join("bucket")).unwrap();
        let quarantine = Quarantine::open(&root.path().join("pod-1"), TENANT).unwrap();
        let id = keep(&quarantine, root.path(), b"kept before", NOW);
        // As if written by the old image: nothing queued.
        quarantine.outbox_done(&id).unwrap();
        restore(&store, &quarantine, NOW + 1).await.unwrap();
        assert_eq!(quarantine.outbox().unwrap().into_iter().map(|(id, _)| id).collect::<Vec<_>>(), [id.clone()]);
        drain(&store, &quarantine, NOW + 2).await;
        let fresh = Quarantine::open(&root.path().join("pod-2"), TENANT).unwrap();
        assert_eq!(restore(&store, &fresh, NOW + 3).await.unwrap().entries, 1);
    }

    /// A store that counts object downloads.
    struct CountingStore {
        inner: LocalObjectStore,
        downloads: std::sync::atomic::AtomicUsize,
    }

    #[async_trait::async_trait]
    impl ObjectStore for CountingStore {
        async fn get(&self, key: &str) -> Result<Option<Vec<u8>>> { self.inner.get(key).await }
        async fn get_to_file(&self, key: &str, path: &std::path::Path) -> Result<bool> {
            self.downloads.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            self.inner.get_to_file(key, path).await
        }
        async fn put_if_absent(&self, key: &str, bytes: &[u8]) -> Result<bool> { self.inner.put_if_absent(key, bytes).await }
        async fn put(&self, key: &str, bytes: &[u8]) -> Result<()> { self.inner.put(key, bytes).await }
        async fn delete(&self, key: &str) -> Result<()> { self.inner.delete(key).await }
        async fn list(&self, prefix: &str) -> Result<Vec<String>> { self.inner.list(prefix).await }
        async fn list_page(&self, prefix: &str, after: Option<&str>, limit: usize) -> Result<Vec<String>> {
            self.inner.list_page(prefix, after, limit).await
        }
    }

    /// Review P1: the bucket holds more than the local cap; a restore
    /// applies the cap newest first BEFORE it downloads anything, and stops
    /// with a named reason rather than fill the volume.
    #[tokio::test(flavor = "current_thread")]
    async fn restore_caps_before_downloading_and_never_fills_the_disk() {
        let root = tempfile::tempdir().unwrap();
        let store = CountingStore { inner: LocalObjectStore::new(root.path().join("bucket")).unwrap(), downloads: 0.into() };
        let old = Quarantine::open(&root.path().join("pod-1"), TENANT).unwrap();
        let oldest = keep(&old, root.path(), b"0123456789", NOW);
        let middle = keep(&old, root.path(), b"abcdefghij", NOW + 1);
        let newest = keep(&old, root.path(), b"ABCDEFGHIJ", NOW + 2);
        drain(&store, &old, NOW + 10).await;

        // Room for two of three 10-byte objects: the two newest, and only
        // they are downloaded.
        let fresh = Quarantine::open(&root.path().join("pod-2"), TENANT).unwrap().with_limits(25, 25);
        let restored = restore_bounded(&store, &fresh, NOW + 20, &|_| Ok(u64::MAX), RESTORE_MAX_RECORDS).await.unwrap();
        assert_eq!((restored.entries, restored.over_cap, restored.refused), (2, 1, None), "{restored:?}");
        assert_eq!(store.downloads.load(std::sync::atomic::Ordering::SeqCst), 2, "the over-cap entry is never fetched");
        let mut ids = fresh.list().unwrap().into_iter().map(|entry| entry.id).collect::<Vec<_>>();
        ids.sort();
        let mut want = vec![middle.clone(), newest.clone()];
        want.sort();
        assert_eq!(ids, want);
        assert!(fresh.get(&oldest).unwrap().is_none());

        // The volume is short: nothing is downloaded, the reason is named.
        store.downloads.store(0, std::sync::atomic::Ordering::SeqCst);
        let low = Quarantine::open(&root.path().join("pod-3"), TENANT).unwrap();
        let restored = restore_bounded(&store, &low, NOW + 20, &|_| Ok(RESTORE_DISK_RESERVE_BYTES + 5), RESTORE_MAX_RECORDS).await.unwrap();
        assert_eq!((restored.entries, restored.refused), (0, Some(RESTORE_DISK_LOW)), "{restored:?}");
        assert_eq!(store.downloads.load(std::sync::atomic::Ordering::SeqCst), 0);
        assert!(low.list().unwrap().is_empty());
    }

    /// Review P1: more records in the horizon than the bound degrade to the
    /// newest ones instead of failing the whole restore.
    #[tokio::test(flavor = "current_thread")]
    async fn restore_past_the_record_bound_reads_the_newest_records() {
        let root = tempfile::tempdir().unwrap();
        let store = LocalObjectStore::new(root.path().join("bucket")).unwrap();
        let old = Quarantine::open(&root.path().join("pod-1"), TENANT).unwrap();
        let first = keep(&old, root.path(), b"first", NOW);
        drain(&store, &old, NOW + 10).await;
        let second = keep(&old, root.path(), b"second", NOW + 20);
        let third = keep(&old, root.path(), b"third", NOW + 21);
        drain(&store, &old, NOW + 30).await;
        let fresh = Quarantine::open(&root.path().join("pod-2"), TENANT).unwrap();
        let restored = restore_bounded(&store, &fresh, NOW + 40, &|_| Ok(u64::MAX), 2).await.unwrap();
        assert_eq!((restored.entries, restored.records_beyond_bound), (2, 1), "{restored:?}");
        assert!(fresh.get(&first).unwrap().is_none(), "only in the oldest record: left in the bucket");
        assert!(fresh.get(&second).unwrap().is_some() && fresh.get(&third).unwrap().is_some());
    }

    /// Review P1: a retried mirror whose object PUT already succeeded only
    /// rewrites the record (never re-uploads up to 128 MiB).
    #[tokio::test(flavor = "current_thread")]
    async fn a_retried_mirror_never_reuploads_a_mirrored_object() {
        let root = tempfile::tempdir().unwrap();
        let store = LocalObjectStore::new(root.path().join("bucket")).unwrap();
        let quarantine = Quarantine::open(&root.path().join("pod-1"), TENANT).unwrap();
        let id = keep(&quarantine, root.path(), b"big bytes", NOW);
        let key = object_key(TENANT, &id).unwrap();
        let mut object_mirrored = true; // an earlier try put it
        mirror_once(&store, &quarantine, &id, NOW + 1, &mut object_mirrored).await.unwrap();
        assert!(store.get(&key).await.unwrap().is_none(), "the object PUT was skipped");
        let mut object_mirrored = false;
        mirror_once(&store, &quarantine, &id, NOW + 2, &mut object_mirrored).await.unwrap();
        assert!(object_mirrored && store.get(&key).await.unwrap().is_some());
    }

    #[test]
    fn retry_backoff_doubles_and_caps() {
        assert_eq!((retry_after_ms(1), retry_after_ms(2), retry_after_ms(3)), (2_000, 4_000, 8_000));
        assert_eq!(retry_after_ms(30), MIRROR_RETRY_MAX_MS);
        assert_eq!(retry_after_ms(u32::MAX), MIRROR_RETRY_MAX_MS);
    }
}
