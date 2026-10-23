// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-4181: finding append attempt markers, one per append batch.
//!
//! Ingest records durable intent before every `Add` that consumes finding
//! receipts. A receipt covered by a marker may already be in the log (a lost
//! acknowledgement), so the log decides; a receipt with no marker was never
//! offered and is republished without a scan.
//!
//! The first version wrote one R2 object per receipt
//! (`.ingest-attempts/<sha256(receipt key)>.json`). That is one Class A PUT
//! per finding, paid again on every retry of a stuck batch (a conditional PUT
//! that answers 412 is still billed): one tenant went from 2.3k to 13.5k
//! PUT/h during a findings spike on 2026-10-19. This module writes ONE marker
//! per append instead, under a time-ordered key:
//!
//! `.ingest-attempts/v2/<unix ms, 13 digits>-<sha256(body)[..32]>.json`
//!
//! Readers find the markers that can cover a receipt without a per-receipt
//! key. Receipts are immutable (create-only, never deleted), and an attempt
//! needs the receipt to exist, so every marker that names a receipt was
//! written after that receipt's Last-Modified time. A reader lists the v2
//! markers from the oldest Last-Modified of the receipts it checks (minus
//! [`ATTEMPT_CLOCK_SKEW_MS`]); a store that cannot report Last-Modified lists
//! all of them. Marker bodies are immutable, so [`AttemptCache`] fetches each
//! body at most once.
//!
//! Per-receipt markers written by earlier releases (and by the one-time
//! historical index migration of earlier releases) are still honored, so
//! nothing that was attempted before this change can be republished as
//! fresh.

use anyhow::{ensure, Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use crate::parts::part_log::{ObjectStore, SourceRef, WriteHints, WriterClass};
use crate::parts::{event_hour_of, sha256_hex};

/// Format tag of a batch attempt marker body.
pub const ATTEMPT_BATCH_FORMAT: &str = "nano.finding-attempt-batch.v1";

/// Slack between the store's Last-Modified clock and the ingest clock that
/// names a marker. Only widens the listed window (never correctness).
pub const ATTEMPT_CLOCK_SKEW_MS: i64 = 10 * 60_000;

/// Keys per marker LIST page.
const LIST_PAGE_KEYS: usize = 1_000;

/// Concurrent marker body GETs and receipt HEADs.
const ATTEMPT_IO_CONCURRENCY: usize = 16;

/// Identity of a consumed receipt (key, digest, version).
pub type ReceiptIdentity = (String, String, String);

fn identity(source: &SourceRef) -> ReceiptIdentity {
    (source.key.clone(), source.sha256.clone(), source.version.clone())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AttemptBatch {
    format: String,
    tenant_id: String,
    receipts: Vec<SourceRef>,
}

fn receipts_root(tenant_id: &str) -> Result<String> {
    crate::parts::format::validate_tenant_uuid(tenant_id)?;
    Ok(format!("{}/tenant={tenant_id}/finding-outbox/receipts/", crate::parts::format::PARTS_ROOT))
}

/// The prefix holding this tenant's batch attempt markers.
pub fn batch_prefix(tenant_id: &str) -> Result<String> {
    Ok(format!("{}.ingest-attempts/v2/", receipts_root(tenant_id)?))
}

/// The per-receipt marker key of earlier releases (read-only now).
pub fn legacy_attempt_key(tenant_id: &str, source: &SourceRef) -> Result<String> {
    Ok(format!("{}.ingest-attempts/{}.json", receipts_root(tenant_id)?, sha256_hex(source.key.as_bytes())))
}

fn marker_key(prefix: &str, at_ms: i64, body: &[u8]) -> String {
    format!("{prefix}{:013}-{}.json", at_ms.max(0), &sha256_hex(body)[..32])
}

/// Parse and check a listed marker against its key.
fn parse_marker(key: &str, prefix: &str, tenant_id: &str, body: &[u8]) -> Result<Vec<SourceRef>> {
    let name = key.strip_prefix(prefix).context("finding attempt marker is outside its prefix")?;
    let digest = name.strip_suffix(".json").and_then(|stem| stem.split_once('-')).map(|(_, digest)| digest);
    ensure!(digest == Some(&sha256_hex(body)[..32]), "finding attempt marker {key} differs from its key");
    let batch: AttemptBatch = serde_json::from_slice(body).context("finding attempt marker is malformed")?;
    ensure!(batch.format == ATTEMPT_BATCH_FORMAT && batch.tenant_id == tenant_id && !batch.receipts.is_empty(),
        "finding attempt marker {key} names another format or tenant");
    Ok(batch.receipts)
}

/// Batch marker bodies already read, by key. Bodies are immutable, so each
/// is fetched at most once; the cache keeps only the keys of the latest
/// listing (bounded by the listed window).
#[derive(Debug, Default)]
pub struct AttemptCache {
    bodies: std::sync::Mutex<BTreeMap<String, Arc<Vec<SourceRef>>>>,
}

impl AttemptCache {
    fn get(&self, key: &str) -> Option<Arc<Vec<SourceRef>>> {
        self.bodies.lock().expect("attempt cache lock").get(key).cloned()
    }

    fn insert(&self, key: String, receipts: Arc<Vec<SourceRef>>) {
        self.bodies.lock().expect("attempt cache lock").insert(key, receipts);
    }

    /// Bodies held (tests).
    pub fn len(&self) -> usize {
        self.bodies.lock().expect("attempt cache lock").len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

async fn legacy_marker<'s>(store: &dyn ObjectStore, tenant_id: &str, source: &'s SourceRef)
    -> Result<(&'s SourceRef, Option<Vec<u8>>)> {
    let key = legacy_attempt_key(tenant_id, source)?;
    Ok((source, store.get(&key).await?))
}

async fn marker_body(store: &dyn ObjectStore, tenant_id: &str, prefix: &str, key: &str, cache: &AttemptCache)
    -> Result<(String, Arc<Vec<SourceRef>>)> {
    if let Some(receipts) = cache.get(key) {
        return Ok((key.to_owned(), receipts));
    }
    let body = store.get(key).await?.context("listed finding attempt marker disappeared")?;
    Ok((key.to_owned(), Arc::new(parse_marker(key, prefix, tenant_id, &body)?)))
}

/// Durable intent for one append: ONE conditional PUT whatever the number
/// of receipts. Returns the marker key.
pub async fn put_attempt_batch(
    store: &dyn ObjectStore,
    tenant_id: &str,
    receipts: &[SourceRef],
    now_ms: i64,
    cache: &AttemptCache,
) -> Result<String> {
    ensure!(!receipts.is_empty(), "a finding attempt names no receipt");
    let prefix = batch_prefix(tenant_id)?;
    let body = serde_json::to_vec(&AttemptBatch {
        format: ATTEMPT_BATCH_FORMAT.to_owned(),
        tenant_id: tenant_id.to_owned(),
        receipts: receipts.to_vec(),
    })?;
    let key = marker_key(&prefix, now_ms, &body);
    let hints = WriteHints { class: WriterClass::LakePart,
        event_hour: event_hour_of(now_ms.saturating_mul(1_000)), min_time_ms: now_ms, max_time_ms: now_ms };
    if !store.put_if_absent_with(&key, &body, &hints).await? {
        // Same key: same millisecond and same body digest.
        ensure!(store.get(&key).await?.as_deref() == Some(body.as_slice()), "finding attempt marker differs");
    }
    cache.insert(key.clone(), Arc::new(receipts.to_vec()));
    Ok(key)
}

/// The receipts in `receipts` that any attempt marker (batch or legacy)
/// names: the ones whose fate the part log must decide.
pub async fn attempted_receipts(
    store: &dyn ObjectStore,
    tenant_id: &str,
    receipts: &[SourceRef],
    cache: &AttemptCache,
) -> Result<BTreeSet<ReceiptIdentity>> {
    use futures::{StreamExt, TryStreamExt};
    let mut attempted = BTreeSet::new();
    if receipts.is_empty() {
        return Ok(attempted);
    }
    // Futures are built in plain loops (no closures over borrows): a
    // `.map(|x| async ..)` here is not general enough for the Send bound of
    // the cell's finding_append task.
    // Per-receipt markers of earlier releases.
    let mut reads = Vec::with_capacity(receipts.len());
    for source in receipts {
        reads.push(legacy_marker(store, tenant_id, source));
    }
    let legacy = futures::stream::iter(reads).buffered(ATTEMPT_IO_CONCURRENCY).try_collect::<Vec<_>>().await?;
    for (source, marker) in legacy {
        if let Some(bytes) = marker {
            ensure!(bytes == serde_json::to_vec(source)?, "finding attempt marker differs");
            attempted.insert(identity(source));
        }
    }
    let pending = receipts.iter().filter(|source| !attempted.contains(&identity(source))).collect::<Vec<_>>();
    if pending.is_empty() {
        return Ok(attempted);
    }
    // No marker naming a receipt predates the receipt object.
    let mut heads = Vec::with_capacity(pending.len());
    for source in &pending {
        heads.push(store.modified_ms(&source.key));
    }
    let modified = futures::stream::iter(heads).buffered(ATTEMPT_IO_CONCURRENCY).try_collect::<Vec<_>>().await?;
    let since = modified.into_iter().try_fold(i64::MAX, |oldest, at| at.map(|at| oldest.min(at)));
    let prefix = batch_prefix(tenant_id)?;
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
        fetches.push(marker_body(store, tenant_id, &prefix, key, cache));
    }
    let bodies = futures::stream::iter(fetches).buffered(ATTEMPT_IO_CONCURRENCY).try_collect::<Vec<_>>().await?;
    let wanted = pending.iter().map(|source| identity(source)).collect::<BTreeSet<_>>();
    let mut kept = BTreeMap::new();
    for (key, receipts) in bodies {
        for source in receipts.iter() {
            let id = identity(source);
            if wanted.contains(&id) {
                attempted.insert(id);
            }
        }
        kept.insert(key, receipts);
    }
    {
        // Keep what this listing saw plus anything written meanwhile.
        let mut held = cache.bodies.lock().expect("attempt cache lock");
        let newest_listed = kept.keys().next_back().cloned();
        held.retain(|key, _| newest_listed.as_ref().is_some_and(|newest| key > newest));
        held.extend(kept);
    }
    Ok(attempted)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parts::part_log::LocalObjectStore;
    use std::sync::atomic::{AtomicUsize, Ordering};

    const TENANT: &str = "00000000-0000-4000-8000-0000000004a1";

    /// Counts PUT and LIST requests (the Class A operations).
    struct Counting {
        inner: LocalObjectStore,
        puts: AtomicUsize,
        lists: AtomicUsize,
        gets: AtomicUsize,
    }

    #[async_trait::async_trait]
    impl ObjectStore for Counting {
        async fn get(&self, key: &str) -> Result<Option<Vec<u8>>> {
            self.gets.fetch_add(1, Ordering::SeqCst);
            self.inner.get(key).await
        }
        async fn put_if_absent(&self, key: &str, bytes: &[u8]) -> Result<bool> {
            self.puts.fetch_add(1, Ordering::SeqCst);
            self.inner.put_if_absent(key, bytes).await
        }
        async fn put(&self, key: &str, bytes: &[u8]) -> Result<()> {
            self.puts.fetch_add(1, Ordering::SeqCst);
            self.inner.put(key, bytes).await
        }
        async fn delete(&self, key: &str) -> Result<()> {
            self.inner.delete(key).await
        }
        async fn list(&self, prefix: &str) -> Result<Vec<String>> {
            self.lists.fetch_add(1, Ordering::SeqCst);
            self.inner.list(prefix).await
        }
        async fn modified_ms(&self, key: &str) -> Result<Option<i64>> {
            self.inner.modified_ms(key).await
        }
    }

    fn receipt(n: usize) -> SourceRef {
        let sha = sha256_hex(format!("receipt-{n}").as_bytes());
        SourceRef {
            key: format!("{}/tenant={TENANT}/finding-outbox/receipts/{sha}.json", crate::parts::format::PARTS_ROOT),
            version: "nano.finding-outbox-receipt.v1".into(),
            sha256: sha,
        }
    }

    fn store() -> (tempfile::TempDir, Counting) {
        let dir = tempfile::tempdir().unwrap();
        let inner = LocalObjectStore::new(dir.path().join("store")).unwrap();
        (dir, Counting { inner, puts: AtomicUsize::new(0), lists: AtomicUsize::new(0), gets: AtomicUsize::new(0) })
    }

    async fn store_receipts(store: &Counting, receipts: &[SourceRef]) {
        for source in receipts {
            assert!(store.inner.put_if_absent(&source.key, b"{}").await.unwrap());
        }
    }

    #[tokio::test]
    async fn n_attempted_receipts_cost_one_put_and_are_all_found() {
        for n in [1, 64, 512] {
            let (_dir, store) = store();
            let receipts = (0..n).map(receipt).collect::<Vec<_>>();
            store_receipts(&store, &receipts).await;
            let cache = AttemptCache::default();
            let now_ms = chrono::Utc::now().timestamp_millis();
            put_attempt_batch(&store, TENANT, &receipts, now_ms, &cache).await.unwrap();
            assert_eq!(store.puts.load(Ordering::SeqCst), 1, "{n} findings: one marker PUT, not one per finding");
            // A fresh reader (another process) finds every receipt in O(1)
            // LIST pages.
            let attempted = attempted_receipts(&store, TENANT, &receipts, &AttemptCache::default()).await.unwrap();
            assert_eq!(attempted.len(), n);
            assert_eq!(store.lists.load(Ordering::SeqCst), 1);
            // The writer's own cache answers without fetching its body.
            let gets = store.gets.load(Ordering::SeqCst);
            assert_eq!(attempted_receipts(&store, TENANT, &receipts, &cache).await.unwrap().len(), n);
            assert_eq!(store.gets.load(Ordering::SeqCst) - gets, n, "only the legacy per-receipt probes");
        }
    }

    #[tokio::test]
    async fn unattempted_receipts_and_other_batches_are_not_reported() {
        let (_dir, store) = store();
        let receipts = (0..8).map(receipt).collect::<Vec<_>>();
        store_receipts(&store, &receipts).await;
        let cache = AttemptCache::default();
        let now_ms = chrono::Utc::now().timestamp_millis();
        assert!(attempted_receipts(&store, TENANT, &receipts, &cache).await.unwrap().is_empty());
        put_attempt_batch(&store, TENANT, &receipts[..3], now_ms, &cache).await.unwrap();
        let attempted = attempted_receipts(&store, TENANT, &receipts, &AttemptCache::default()).await.unwrap();
        assert_eq!(attempted, receipts[..3].iter().map(identity).collect());
        // A retry of the same batch is the same marker or a new one: never
        // fewer receipts found.
        put_attempt_batch(&store, TENANT, &receipts[..3], now_ms, &cache).await.unwrap();
        put_attempt_batch(&store, TENANT, &receipts[2..5], now_ms + 1, &cache).await.unwrap();
        let attempted = attempted_receipts(&store, TENANT, &receipts, &cache).await.unwrap();
        assert_eq!(attempted, receipts[..5].iter().map(identity).collect());
    }

    #[tokio::test]
    async fn legacy_per_receipt_markers_are_still_honored() {
        let (_dir, store) = store();
        let receipts = (0..3).map(receipt).collect::<Vec<_>>();
        store_receipts(&store, &receipts).await;
        let key = legacy_attempt_key(TENANT, &receipts[1]).unwrap();
        assert!(store.inner.put_if_absent(&key, &serde_json::to_vec(&receipts[1]).unwrap()).await.unwrap());
        let attempted = attempted_receipts(&store, TENANT, &receipts, &AttemptCache::default()).await.unwrap();
        assert_eq!(attempted, BTreeSet::from([identity(&receipts[1])]));
    }

    #[tokio::test]
    async fn markers_older_than_the_receipts_are_not_listed_but_a_store_without_times_lists_all() {
        let (_dir, store) = store();
        let receipts = (0..2).map(receipt).collect::<Vec<_>>();
        store_receipts(&store, &receipts).await;
        let cache = AttemptCache::default();
        // A marker key from long before the receipts existed cannot name
        // them; it is outside the listed window.
        let old = put_attempt_batch(&store, TENANT, &receipts, 1_000, &cache).await.unwrap();
        assert!(attempted_receipts(&store, TENANT, &receipts, &AttemptCache::default()).await.unwrap().is_empty());
        // A store that reports no Last-Modified lists every marker.
        struct NoTimes<'a>(&'a LocalObjectStore);
        #[async_trait::async_trait]
        impl ObjectStore for NoTimes<'_> {
            async fn get(&self, key: &str) -> Result<Option<Vec<u8>>> { self.0.get(key).await }
            async fn put_if_absent(&self, key: &str, bytes: &[u8]) -> Result<bool> { self.0.put_if_absent(key, bytes).await }
            async fn put(&self, key: &str, bytes: &[u8]) -> Result<()> { self.0.put(key, bytes).await }
            async fn delete(&self, key: &str) -> Result<()> { self.0.delete(key).await }
            async fn list(&self, prefix: &str) -> Result<Vec<String>> { self.0.list(prefix).await }
        }
        let attempted = attempted_receipts(&NoTimes(&store.inner), TENANT, &receipts, &AttemptCache::default()).await.unwrap();
        assert_eq!(attempted.len(), 2, "{old} is listed when receipt times are unknown");
    }

    #[tokio::test]
    async fn a_tampered_marker_is_refused() {
        let (_dir, store) = store();
        let receipts = vec![receipt(0)];
        store_receipts(&store, &receipts).await;
        let prefix = batch_prefix(TENANT).unwrap();
        let now_ms = chrono::Utc::now().timestamp_millis();
        let key = format!("{prefix}{now_ms:013}-{}.json", "0".repeat(32));
        assert!(store.inner.put_if_absent(&key, b"{}").await.unwrap());
        assert!(attempted_receipts(&store, TENANT, &receipts, &AttemptCache::default()).await.is_err());
    }
}
