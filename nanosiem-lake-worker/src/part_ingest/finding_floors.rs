// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-4656: durable replay floors for the finding replay proof.
//!
//! A replay proof ([`super::finding_outbox::committed_receipts`]) decides
//! whether a receipt that ingest attempted is already consumed by a part-log
//! `Add`. It used to scan from genesis every time and remember nothing. On
//! 2026-10-26 the ops tenant's proof (57.8k entries, ~11 min) ran longer than
//! ingest's append deadline. Ingest refused, detect retried, and both roles
//! started again from seq 0 every ~12 minutes: ~474k R2 GETs/h and no finding
//! delivered.
//!
//! A floor is one immutable fact: "none of these receipts is consumed by any
//! entry `0..=through_seq`, and entry `through_seq` has this SHA-256". Facts
//! never stop being true (the log is append-only), so the strongest floor
//! per receipt wins and a proof resumes after it. Floors are written:
//! - by ingest at commit, before the `Add` ([`super::ingest::Ingestor::commit_finding`]):
//!   the head the `Add` is appended after, so an interrupted append is
//!   proven by reading only the entries after it;
//! - by the proof itself every [`FLOOR_EVERY`] entries and at the head, for
//!   the receipts it has not found: a proof cut by a deadline or a restart
//!   resumes where it stopped, and detect and ingest share each other's work.
//!
//! Key: `.replay-floors/v1/<unix ms, 13 digits>-<sha256(body)[..32]>.json`,
//! listed like the batch attempt markers ([`super::finding_attempts`]): a
//! floor names receipts that already exist, so readers list from the oldest
//! receipt's Last-Modified (minus [`ATTEMPT_CLOCK_SKEW_MS`]). A floor that is
//! missed or unreadable only makes a proof read more of the log, never less.

use anyhow::{ensure, Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::sync::Arc;

use super::finding_attempts::{ReceiptIdentity, ATTEMPT_CLOCK_SKEW_MS};
use crate::parts::part_log::{ObjectStore, SourceRef, WriteHints, WriterClass};
use crate::parts::{event_hour_of, is_sha256_hex, sha256_hex};

/// Format tag of a replay floor body.
pub const FLOOR_FORMAT: &str = "nano.finding-replay-floor.v1";

/// A proof records its progress every this many entries.
pub const FLOOR_EVERY: u64 = 4_096;

/// Keys per floor LIST page.
const LIST_PAGE_KEYS: usize = 1_000;

/// Concurrent floor body GETs and receipt HEADs.
const FLOOR_IO_CONCURRENCY: usize = 16;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReplayFloor {
    format: String,
    tenant_id: String,
    through_seq: u64,
    entry_sha256: String,
    receipts: Vec<SourceRef>,
}

fn identity(source: &SourceRef) -> ReceiptIdentity {
    (source.key.clone(), source.sha256.clone(), source.version.clone())
}

/// The prefix holding this tenant's replay floors.
pub fn floor_prefix(tenant_id: &str) -> Result<String> {
    crate::parts::format::validate_tenant_uuid(tenant_id)?;
    Ok(format!("{}/tenant={tenant_id}/finding-outbox/receipts/.replay-floors/v1/", crate::parts::format::PARTS_ROOT))
}

fn parse_floor(key: &str, prefix: &str, tenant_id: &str, body: &[u8]) -> Result<ReplayFloor> {
    let name = key.strip_prefix(prefix).context("replay floor is outside its prefix")?;
    let digest = name.strip_suffix(".json").and_then(|stem| stem.split_once('-')).map(|(_, digest)| digest);
    ensure!(digest == Some(&sha256_hex(body)[..32]), "replay floor {key} differs from its key");
    let floor: ReplayFloor = serde_json::from_slice(body).context("replay floor is malformed")?;
    ensure!(floor.format == FLOOR_FORMAT && floor.tenant_id == tenant_id && !floor.receipts.is_empty()
        && is_sha256_hex(&floor.entry_sha256), "replay floor {key} names another format or tenant");
    Ok(floor)
}

/// Floor bodies already read, by key (bodies are immutable).
#[derive(Debug, Default)]
pub struct FloorCache {
    bodies: std::sync::Mutex<BTreeMap<String, Arc<ReplayFloor>>>,
}

impl FloorCache {
    fn get(&self, key: &str) -> Option<Arc<ReplayFloor>> {
        self.bodies.lock().expect("floor cache lock").get(key).cloned()
    }

    /// Bodies held (tests).
    pub fn len(&self) -> usize {
        self.bodies.lock().expect("floor cache lock").len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Record that no receipt in `receipts` is consumed through `through_seq`
/// (whose entry has `entry_sha256`). ONE conditional PUT. The caller must
/// know the fact holds; readers trust it as they trust a checkpoint (the
/// entry is re-read and its digest compared before a proof resumes).
pub async fn put_floor(
    store: &dyn ObjectStore,
    tenant_id: &str,
    through_seq: u64,
    entry_sha256: &str,
    receipts: &[SourceRef],
) -> Result<String> {
    ensure!(!receipts.is_empty(), "a replay floor names no receipt");
    ensure!(is_sha256_hex(entry_sha256), "replay floor entry digest is malformed");
    let prefix = floor_prefix(tenant_id)?;
    let body = serde_json::to_vec(&ReplayFloor {
        format: FLOOR_FORMAT.to_owned(),
        tenant_id: tenant_id.to_owned(),
        through_seq,
        entry_sha256: entry_sha256.to_owned(),
        receipts: receipts.to_vec(),
    })?;
    // Wall clock, not a caller's logical time: the key only places the floor
    // in the reader's Last-Modified listing window.
    let now_ms = chrono::Utc::now().timestamp_millis();
    let key = format!("{prefix}{:013}-{}.json", now_ms.max(0), &sha256_hex(&body)[..32]);
    let hints = WriteHints { class: WriterClass::LakePart,
        event_hour: event_hour_of(now_ms.saturating_mul(1_000)), min_time_ms: now_ms, max_time_ms: now_ms };
    if !store.put_if_absent_with(&key, &body, &hints).await? {
        ensure!(store.get(&key).await?.as_deref() == Some(body.as_slice()), "replay floor key has conflicting bytes");
    }
    Ok(key)
}

/// [`put_floor`] that never fails its caller: a floor that is not written
/// only makes a later proof read more of the log.
pub async fn put_floor_logged(
    store: &dyn ObjectStore,
    tenant_id: &str,
    through_seq: u64,
    entry_sha256: &str,
    receipts: &[SourceRef],
) {
    if receipts.is_empty() {
        return;
    }
    if let Err(error) = put_floor(store, tenant_id, through_seq, entry_sha256, receipts).await {
        tracing::warn!(tenant_id, through_seq, receipts = receipts.len(), error = %format!("{error:#}"),
            "finding replay floor not recorded; a later proof reads more of the part log");
    }
}

/// A listed floor's body. An unreadable or malformed floor is skipped (it
/// can only have shortened a proof); a store error is the caller's.
async fn floor_body(store: &dyn ObjectStore, tenant_id: &str, prefix: &str, key: &str, cache: &FloorCache)
    -> Result<Option<(String, Arc<ReplayFloor>)>> {
    if let Some(floor) = cache.get(key) {
        return Ok(Some((key.to_owned(), floor)));
    }
    let Some(body) = store.get(key).await? else { return Ok(None) };
    match parse_floor(key, prefix, tenant_id, &body) {
        Ok(floor) => Ok(Some((key.to_owned(), Arc::new(floor)))),
        Err(error) => {
            tracing::warn!(tenant_id, key, error = %format!("{error:#}"), "finding replay floor ignored");
            Ok(None)
        }
    }
}

/// The strongest floor recorded for each receipt in `wanted`:
/// identity → (through_seq, entry_sha256). Receipts with no floor are absent.
pub async fn floors_for(
    store: &dyn ObjectStore,
    tenant_id: &str,
    wanted: &[SourceRef],
    cache: &FloorCache,
) -> Result<BTreeMap<ReceiptIdentity, (u64, String)>> {
    use futures::{StreamExt, TryStreamExt};
    let mut floors = BTreeMap::new();
    if wanted.is_empty() {
        return Ok(floors);
    }
    // Futures are built in plain loops (no closures over borrows): this runs
    // inside the cell's spawned replay-proof task, which must be Send.
    let mut heads = Vec::with_capacity(wanted.len());
    for source in wanted {
        heads.push(store.modified_ms(&source.key));
    }
    let modified = futures::stream::iter(heads).buffered(FLOOR_IO_CONCURRENCY).try_collect::<Vec<_>>().await?;
    let since = modified.into_iter().try_fold(i64::MAX, |oldest, at| at.map(|at| oldest.min(at)));
    let prefix = floor_prefix(tenant_id)?;
    let mut after = since.map(|at| format!("{prefix}{:013}", at.saturating_sub(ATTEMPT_CLOCK_SKEW_MS).max(0)));
    let mut listed = Vec::new();
    loop {
        let page = store.list_page(&prefix, after.as_deref(), LIST_PAGE_KEYS).await?;
        let full = page.len() >= LIST_PAGE_KEYS;
        after = page.last().cloned();
        listed.extend(page);
        if !full {
            break;
        }
    }
    let mut fetches = Vec::with_capacity(listed.len());
    for key in &listed {
        fetches.push(floor_body(store, tenant_id, &prefix, key, cache));
    }
    let bodies = futures::stream::iter(fetches).buffered(FLOOR_IO_CONCURRENCY).try_collect::<Vec<_>>().await?;
    let wanted = wanted.iter().map(identity).collect::<std::collections::BTreeSet<_>>();
    let mut kept = BTreeMap::new();
    for (key, floor) in bodies.into_iter().flatten() {
        for source in &floor.receipts {
            let id = identity(source);
            if !wanted.contains(&id) {
                continue;
            }
            let stronger = floors.get(&id).is_none_or(|(seq, _): &(u64, String)| floor.through_seq > *seq);
            if stronger {
                floors.insert(id, (floor.through_seq, floor.entry_sha256.clone()));
            }
        }
        kept.insert(key, floor);
    }
    {
        // Keep this listing's bodies plus anything newer read meanwhile.
        let mut held = cache.bodies.lock().expect("floor cache lock");
        let newest_listed = kept.keys().next_back().cloned();
        held.retain(|key, _| newest_listed.as_ref().is_some_and(|newest| key > newest));
        held.extend(kept);
    }
    Ok(floors)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parts::part_log::LocalObjectStore;

    const TENANT: &str = "00000000-0000-4000-8000-00000000004e";
    const OTHER: &str = "00000000-0000-4000-8000-00000000004f";

    fn receipt(tenant: &str, n: u8) -> SourceRef {
        let sha = sha256_hex(&[n]);
        SourceRef {
            key: format!("lake/parts/v1/tenant={tenant}/finding-outbox/receipts/{sha}.json"),
            version: "nano.finding-outbox-receipt.v1".into(),
            sha256: sha,
        }
    }

    #[tokio::test]
    async fn the_strongest_floor_per_receipt_wins_and_stays_tenant_local() {
        let dir = tempfile::tempdir().unwrap();
        let store = LocalObjectStore::new(dir.path()).unwrap();
        let (a, b, c) = (receipt(TENANT, 1), receipt(TENANT, 2), receipt(TENANT, 3));
        for source in [&a, &b, &c] {
            assert!(store.put_if_absent(&source.key, b"r").await.unwrap());
        }
        let (s10, s40) = (sha256_hex(b"10"), sha256_hex(b"40"));
        put_floor(&store, TENANT, 10, &s10, &[a.clone(), b.clone()]).await.unwrap();
        put_floor(&store, TENANT, 40, &s40, &[b.clone()]).await.unwrap();
        // Another tenant's floor under its own prefix is never read.
        put_floor(&store, OTHER, 99, &s40, &[receipt(OTHER, 1)]).await.unwrap();
        let cache = FloorCache::default();
        let floors = floors_for(&store, TENANT, &[a.clone(), b.clone(), c.clone()], &cache).await.unwrap();
        assert_eq!(floors.get(&identity(&a)), Some(&(10, s10.clone())));
        assert_eq!(floors.get(&identity(&b)), Some(&(40, s40)), "the later floor is the stronger fact");
        assert!(!floors.contains_key(&identity(&c)), "no floor, no bound");
        assert_eq!(cache.len(), 2);
        // A body that differs from its key is ignored, never trusted, and
        // never blocks a proof (it can only have shortened one).
        let forged_body = serde_json::to_vec(&ReplayFloor { format: FLOOR_FORMAT.into(), tenant_id: TENANT.into(),
            through_seq: 1_000, entry_sha256: s10.clone(), receipts: vec![a.clone()] }).unwrap();
        let forged = format!("{}{:013}-{}.json", floor_prefix(TENANT).unwrap(), 1, "0".repeat(32));
        assert!(store.put_if_absent(&forged, &forged_body).await.unwrap());
        let floors = floors_for(&store, TENANT, &[a.clone()], &FloorCache::default()).await.unwrap();
        assert_eq!(floors.get(&identity(&a)), Some(&(10, s10)));
    }
}
