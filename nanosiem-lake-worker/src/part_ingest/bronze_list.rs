// SPDX-License-Identifier: AGPL-3.0-or-later

//! Trusted-local bronze listing queue (NAN-3492, open core on lean).
//!
//! A self-hosted single-tenant install has no raw-handoff Durable Object to
//! announce bronze objects. Vector keeps its bronze sink (`aws_s3` → Parquet
//! under `bronze-v2/tenant_id=T/` on the local object store), and this queue
//! LISTS that prefix instead, feeding the same [`NoticeQueue`] contract the
//! DO notices use.
//!
//! # Ordering and late objects
//!
//! Vector names every bronze object `{unix seconds}-{uuid}.parquet`, so keys
//! sort by creation time, but a key becomes visible only when its PUT lands:
//! a retried or slow upload can appear *behind* keys already listed. A bare
//! `start_after` cursor would skip it. The queue therefore keeps
//!
//! * a **watermark**: every key `<=` it is consumed and no new key `<=` it
//!   can appear; listing starts after it;
//! * the **acked** keys above the watermark (with their creation time), so a
//!   relist does not redeliver them.
//!
//! The watermark moves up to an acked key `k` only when a listing that
//! STARTED more than `settle` after `k`'s creation time covered `k`, and no
//! key below `k` from that listing is still unacked. Any object with a key
//! below `k` was created no later than `k` (same second at worst), so with
//! `settle` above Vector's upload deadline (request timeout plus
//! `retry_max_duration_secs`) it was visible to that listing and is either
//! acked or still pending.
//!
//! # Crash safety and exactly-once
//!
//! `ack` is called only after the part-log `add` that consumed the object
//! committed, and the state is persisted (temp file, fsync, rename, fsync
//! dir) before `ack` returns. A crash between the commit and the persist
//! redelivers the object; ingest finds it in the part log's consumed set
//! (`PartLogState::consumed`) and acknowledges it without admitting a row,
//! the same replay path the DO notices rely on. Part-level exactly-once is
//! the part log's, not this queue's.
//!
//! An unreadable state file fails closed: restarting from the empty
//! watermark would relist objects older than the part log's consumed
//! window and re-admit their rows.

use anyhow::{bail, ensure, Context, Result};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::Duration;

use super::discovery::{NoticeHandle, NoticeQueue, SourceNotice};

/// State file name inside the ingest state dir.
pub const STATE_FILE: &str = "bronze-list-cursor.json";
const STATE_KIND: &str = "nano.lake.bronze-list-cursor.v1";

/// Default settle window. Vector's bronze sink gives one request 120 s and
/// retries for at most 300 s (`deploy.rs`); 15 minutes leaves margin for
/// clock skew between Vector and the cell.
pub const DEFAULT_SETTLE: Duration = Duration::from_secs(15 * 60);
/// Default pause between listings when the last one found nothing new.
pub const DEFAULT_POLL: Duration = Duration::from_secs(1);
/// Upper bound on objects held listed-but-unacked in memory.
const MAX_DELIVERED: usize = 4_096;
/// Upper bound on acked keys kept above the watermark. Reaching it means the
/// watermark is stuck (an unacked key, or a clock far off); refuse rather
/// than grow without bound.
const MAX_ACKED: usize = 200_000;

/// Listing settings carried by the trusted-local ingest credentials.
#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct BronzeListSettings {
    /// Settle window in seconds (default [`DEFAULT_SETTLE`]).
    #[serde(default)]
    pub settle_secs: Option<u64>,
    /// Idle poll interval in milliseconds (default [`DEFAULT_POLL`]).
    #[serde(default)]
    pub poll_ms: Option<u64>,
}

impl BronzeListSettings {
    pub fn settle(&self) -> Duration {
        self.settle_secs.map_or(DEFAULT_SETTLE, Duration::from_secs)
    }

    pub fn poll(&self) -> Duration {
        self.poll_ms.map_or(DEFAULT_POLL, Duration::from_millis)
    }

    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.settle() >= Duration::from_secs(60),
            "bronze listing settle window must be at least 60 s"
        );
        ensure!(
            self.settle() <= Duration::from_secs(24 * 3600),
            "bronze listing settle window must be at most 24 h"
        );
        ensure!(
            self.poll() >= Duration::from_millis(100) && self.poll() <= Duration::from_secs(60),
            "bronze listing poll interval must be between 100 ms and 60 s"
        );
        Ok(())
    }
}

/// One listed bronze object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListedBronze {
    /// Key relative to the bronze location (as ingest fetches it).
    pub key: String,
    /// ETag without quotes, or empty when the store reports none.
    pub etag: String,
    pub bytes: u64,
    /// Upload time from the listing, when reported.
    pub last_modified_ms: Option<i64>,
}

/// An ordered lister over one prefix.
#[async_trait]
pub trait BronzeLister: Send + Sync {
    /// Up to `limit` objects under `prefix` with keys strictly after
    /// `start_after`, in ascending key order.
    async fn list_after(
        &self,
        prefix: &str,
        start_after: Option<&str>,
        limit: usize,
    ) -> Result<Vec<ListedBronze>>;
}

#[async_trait]
impl<T: BronzeLister + ?Sized> BronzeLister for &T {
    async fn list_after(
        &self,
        prefix: &str,
        start_after: Option<&str>,
        limit: usize,
    ) -> Result<Vec<ListedBronze>> {
        (**self).list_after(prefix, start_after, limit).await
    }
}

#[async_trait]
impl BronzeLister for super::s3_store::S3ObjectStore {
    async fn list_after(
        &self,
        prefix: &str,
        start_after: Option<&str>,
        limit: usize,
    ) -> Result<Vec<ListedBronze>> {
        self.list_page_after(prefix, start_after, limit).await
    }
}

/// The creation time Vector encoded in the key's file name
/// (`{seconds}-{uuid}.parquet`; 13- and 16-digit stamps are read as ms and µs).
pub fn key_time_ms(key: &str) -> Option<i64> {
    let name = key.rsplit('/').next()?;
    let (stamp, _) = name.split_once('-')?;
    if !stamp.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let value: i64 = stamp.parse().ok()?;
    match stamp.len() {
        10 => value.checked_mul(1_000),
        13 => Some(value),
        16 => Some(value / 1_000),
        _ => None,
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct PersistedState {
    kind: String,
    tenant_id: String,
    prefix: String,
    watermark: Option<String>,
    /// Acked keys above the watermark → creation time (ms).
    acked: BTreeMap<String, i64>,
}

#[derive(Debug, Default)]
struct Inner {
    watermark: Option<String>,
    acked: BTreeMap<String, i64>,
    /// Listed and not yet acked, by key.
    delivered: BTreeMap<String, SourceNotice>,
    /// Start time and covered key range of the last complete listing pass.
    last_list: Option<ListPass>,
    /// The last pass found nothing new (idle polls are throttled).
    last_list_empty: bool,
}

#[derive(Debug, Clone)]
struct ListPass {
    started_ms: i64,
    /// Highest key the pass reached; `None` = it reached the end.
    frontier: Option<String>,
}

/// The listing queue for one tenant prefix.
pub struct BronzeListQueue<L: BronzeLister> {
    lister: L,
    tenant_id: String,
    /// Prefix relative to the bronze location, e.g. `tenant_id=T/`.
    prefix: String,
    state_path: PathBuf,
    settle_ms: i64,
    poll_ms: i64,
    page: usize,
    clock: Box<dyn Fn() -> i64 + Send + Sync>,
    inner: Mutex<Inner>,
}

impl<L: BronzeLister> BronzeListQueue<L> {
    /// Open (or create) the queue state under `state_dir`.
    pub fn open(
        lister: L,
        tenant_id: &str,
        state_dir: &Path,
        settings: &BronzeListSettings,
    ) -> Result<Self> {
        Self::open_with_clock(
            lister,
            tenant_id,
            state_dir,
            settings,
            Box::new(|| chrono::Utc::now().timestamp_millis()),
        )
    }

    pub fn open_with_clock(
        lister: L,
        tenant_id: &str,
        state_dir: &Path,
        settings: &BronzeListSettings,
        clock: Box<dyn Fn() -> i64 + Send + Sync>,
    ) -> Result<Self> {
        settings.validate()?;
        ensure!(
            !tenant_id.is_empty() && !tenant_id.contains('/'),
            "bronze listing tenant id is invalid"
        );
        let prefix = format!("tenant_id={tenant_id}/");
        std::fs::create_dir_all(state_dir)?;
        let state_path = state_dir.join(STATE_FILE);
        let mut inner = Inner::default();
        match std::fs::read(&state_path) {
            Ok(bytes) => {
                let state: PersistedState = serde_json::from_slice(&bytes).with_context(|| {
                    format!(
                        "bronze listing state {} does not parse; refusing to relist from the start",
                        state_path.display()
                    )
                })?;
                ensure!(
                    state.kind == STATE_KIND,
                    "bronze listing state has an unknown kind"
                );
                ensure!(
                    state.tenant_id == tenant_id,
                    "bronze listing state belongs to another tenant"
                );
                ensure!(
                    state.prefix == prefix,
                    "bronze listing state names another prefix"
                );
                if let Some(watermark) = &state.watermark {
                    ensure!(
                        watermark.starts_with(&prefix),
                        "bronze listing watermark escapes its prefix"
                    );
                }
                ensure!(
                    state.acked.keys().all(|key| key.starts_with(&prefix)
                        && state.watermark.as_ref().is_none_or(|w| key > w)),
                    "bronze listing state holds an acked key at or below its watermark"
                );
                inner.watermark = state.watermark;
                inner.acked = state.acked;
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error).context("bronze listing state is unreadable"),
        }
        Ok(Self {
            lister,
            tenant_id: tenant_id.to_string(),
            prefix,
            state_path,
            settle_ms: settings.settle().as_millis() as i64,
            poll_ms: settings.poll().as_millis() as i64,
            page: 1_000,
            clock,
            inner: Mutex::new(inner),
        })
    }

    /// The current watermark (every key at or below it is consumed and
    /// settled). Bronze retention may delete keys at or below it.
    pub fn watermark(&self) -> Option<String> {
        self.inner
            .lock()
            .expect("bronze list lock")
            .watermark
            .clone()
    }

    #[cfg(test)]
    fn with_page(mut self, page: usize) -> Self {
        self.page = page;
        self
    }

    fn notice_for(&self, object: &ListedBronze, now_ms: i64) -> SourceNotice {
        SourceNotice {
            tenant_id: self.tenant_id.clone(),
            key: object.key.clone(),
            version: object.etag.clone(),
            bytes: object.bytes,
            sha256: None,
            edge_sha256: None,
            notified_at_ms: key_time_ms(&object.key)
                .or(object.last_modified_ms)
                .unwrap_or(now_ms),
        }
    }

    /// One listing pass from the watermark. Collects new keys until `want`
    /// objects are delivered (or the end). Returns whether it found anything.
    async fn list_pass(&self, want: usize) -> Result<bool> {
        let now = (self.clock)();
        let (mut cursor, room) = {
            let inner = self.inner.lock().expect("bronze list lock");
            (
                inner.watermark.clone(),
                MAX_DELIVERED.saturating_sub(inner.delivered.len()),
            )
        };
        // At least one: a full delivery map still lists to refresh the pass.
        let want = want.min(room).max(1);
        let mut found = false;
        let mut frontier: Option<String>;
        loop {
            let page = self
                .lister
                .list_after(&self.prefix, cursor.as_deref(), self.page)
                .await?;
            let exhausted = page.len() < self.page;
            let mut inner = self.inner.lock().expect("bronze list lock");
            frontier = page
                .last()
                .map(|object| object.key.clone())
                .or(cursor.clone());
            let mut stop = false;
            for object in &page {
                ensure!(
                    object.key.starts_with(&self.prefix),
                    "bronze listing escaped its prefix"
                );
                ensure!(
                    cursor.as_ref().is_none_or(|c| object.key > *c),
                    "bronze listing is not strictly ordered"
                );
                cursor = Some(object.key.clone());
                if !object.key.ends_with(".parquet")
                    || object.key[self.prefix.len()..].contains('/')
                {
                    continue;
                }
                if inner.acked.contains_key(&object.key)
                    || inner.delivered.contains_key(&object.key)
                {
                    continue;
                }
                inner
                    .delivered
                    .insert(object.key.clone(), self.notice_for(object, now));
                found = true;
                if inner.delivered.len() >= want {
                    frontier = Some(object.key.clone());
                    stop = true;
                    break;
                }
            }
            if stop || exhausted {
                if exhausted && !stop {
                    frontier = None;
                }
                inner.last_list = Some(ListPass {
                    started_ms: now,
                    frontier: frontier.clone(),
                });
                inner.last_list_empty = !found;
                return Ok(found);
            }
        }
    }

    /// Advance the watermark over settled, acked keys. Returns whether the
    /// state changed.
    fn advance(inner: &mut Inner, settle_ms: i64) -> bool {
        let Some(pass) = inner.last_list.clone() else {
            return false;
        };
        let mut changed = false;
        loop {
            let Some((key, created)) = inner.acked.iter().next().map(|(k, t)| (k.clone(), *t))
            else {
                break;
            };
            if pass
                .frontier
                .as_ref()
                .is_some_and(|frontier| key > *frontier)
            {
                break;
            }
            if created > pass.started_ms - settle_ms {
                break;
            }
            if inner
                .delivered
                .keys()
                .next()
                .is_some_and(|pending| *pending < key)
            {
                break;
            }
            inner.acked.remove(&key);
            inner.watermark = Some(key);
            changed = true;
        }
        changed
    }

    fn persist(&self, inner: &Inner) -> Result<()> {
        let state = PersistedState {
            kind: STATE_KIND.to_string(),
            tenant_id: self.tenant_id.clone(),
            prefix: self.prefix.clone(),
            watermark: inner.watermark.clone(),
            acked: inner.acked.clone(),
        };
        let bytes = serde_json::to_vec(&state)?;
        let dir = self
            .state_path
            .parent()
            .context("bronze listing state has no directory")?;
        let temp = dir.join(format!(".{STATE_FILE}.tmp"));
        {
            use std::io::Write;
            let mut file = std::fs::File::create(&temp)?;
            file.write_all(&bytes)?;
            file.sync_all()?;
        }
        std::fs::rename(&temp, &self.state_path)?;
        std::fs::File::open(dir)?.sync_all()?;
        Ok(())
    }
}

#[async_trait]
impl<L: BronzeLister> NoticeQueue for BronzeListQueue<L> {
    async fn pending(&self, max: usize) -> Result<Vec<(NoticeHandle, SourceNotice)>> {
        let now = (self.clock)();
        let due = {
            let inner = self.inner.lock().expect("bronze list lock");
            let throttled = inner.last_list_empty
                && inner
                    .last_list
                    .as_ref()
                    .is_some_and(|pass| now - pass.started_ms < self.poll_ms);
            !throttled && inner.delivered.len() < max.max(1)
        };
        if due {
            self.list_pass(max.max(1)).await?;
        }
        let mut inner = self.inner.lock().expect("bronze list lock");
        // A pass with nothing new can still settle acked keys.
        if Self::advance(&mut inner, self.settle_ms) {
            self.persist(&inner)?;
        }
        Ok(inner
            .delivered
            .iter()
            .take(max)
            .map(|(key, notice)| (NoticeHandle(key.clone()), notice.clone()))
            .collect())
    }

    async fn ack(&self, handles: &[NoticeHandle]) -> Result<()> {
        if handles.is_empty() {
            return Ok(());
        }
        let mut inner = self.inner.lock().expect("bronze list lock");
        for handle in handles {
            if !handle.0.starts_with(&self.prefix) {
                bail!("bronze listing handle is outside its prefix");
            }
            if inner.watermark.as_ref().is_some_and(|w| handle.0 <= *w) {
                continue;
            }
            let created = match inner.delivered.remove(&handle.0) {
                Some(notice) => notice.notified_at_ms,
                None => key_time_ms(&handle.0).unwrap_or_else(|| (self.clock)()),
            };
            inner.acked.insert(handle.0.clone(), created);
        }
        Self::advance(&mut inner, self.settle_ms);
        ensure!(
            inner.acked.len() <= MAX_ACKED,
            "bronze listing watermark is stuck: {} acked keys above it",
            inner.acked.len()
        );
        self.persist(&inner)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicI64, Ordering};
    use std::sync::Arc;

    const T: &str = "6f3d1060-0000-4000-8000-0000000c7106";

    #[derive(Clone, Default)]
    struct Fake {
        objects: Arc<Mutex<BTreeMap<String, ListedBronze>>>,
        lists: Arc<AtomicI64>,
    }

    impl Fake {
        fn put(&self, seconds: i64, id: &str) -> String {
            let key = format!("tenant_id={T}/{seconds}-{id}.parquet");
            self.objects.lock().unwrap().insert(
                key.clone(),
                ListedBronze {
                    key: key.clone(),
                    etag: format!("etag-{id}"),
                    bytes: 10,
                    last_modified_ms: Some(seconds * 1000),
                },
            );
            key
        }
    }

    #[async_trait]
    impl BronzeLister for Fake {
        async fn list_after(
            &self,
            prefix: &str,
            start_after: Option<&str>,
            limit: usize,
        ) -> Result<Vec<ListedBronze>> {
            self.lists.fetch_add(1, Ordering::SeqCst);
            Ok(self
                .objects
                .lock()
                .unwrap()
                .values()
                .filter(|o| {
                    o.key.starts_with(prefix) && start_after.is_none_or(|s| o.key.as_str() > s)
                })
                .take(limit)
                .cloned()
                .collect())
        }
    }

    fn queue(fake: &Fake, dir: &Path, clock: Arc<AtomicI64>) -> BronzeListQueue<Fake> {
        let settings = BronzeListSettings {
            settle_secs: Some(60),
            poll_ms: Some(100),
        };
        BronzeListQueue::open_with_clock(
            fake.clone(),
            T,
            dir,
            &settings,
            Box::new(move || clock.load(Ordering::SeqCst)),
        )
        .unwrap()
    }

    fn keys(pending: &[(NoticeHandle, SourceNotice)]) -> Vec<String> {
        pending.iter().map(|(h, _)| h.0.clone()).collect()
    }

    #[test]
    fn key_time_reads_vector_stamps() {
        assert_eq!(
            key_time_ms("tenant_id=x/1728560000-abc.parquet"),
            Some(1_728_560_000_000)
        );
        assert_eq!(
            key_time_ms("1728560000123-abc.parquet"),
            Some(1_728_560_000_123)
        );
        assert_eq!(key_time_ms("tenant_id=x/notime.parquet"), None);
        assert_eq!(key_time_ms("tenant_id=x/12-a.parquet"), None);
    }

    #[tokio::test]
    async fn delivers_in_order_and_survives_restart_without_redelivery() {
        let dir = tempfile::tempdir().unwrap();
        let fake = Fake::default();
        let clock = Arc::new(AtomicI64::new(1_000_000_000));
        let a = fake.put(999_000, "a");
        let b = fake.put(999_001, "b");
        let q = queue(&fake, dir.path(), clock.clone());
        let pending = q.pending(10).await.unwrap();
        assert_eq!(keys(&pending), vec![a.clone(), b.clone()]);
        assert_eq!(pending[0].1.version, "etag-a");
        assert_eq!(pending[0].1.notified_at_ms, 999_000_000);
        q.ack(&[pending[0].0.clone()]).await.unwrap();
        // Restart: a is acked and settled; only b comes back.
        drop(q);
        let q = queue(&fake, dir.path(), clock.clone());
        assert_eq!(keys(&q.pending(10).await.unwrap()), vec![b.clone()]);
        q.ack(&[NoticeHandle(b.clone())]).await.unwrap();
        assert_eq!(q.watermark(), Some(b.clone()));
        drop(q);
        let q = queue(&fake, dir.path(), clock);
        assert!(q.pending(10).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn late_object_behind_acked_keys_is_still_delivered() {
        let dir = tempfile::tempdir().unwrap();
        let fake = Fake::default();
        // "now" is 10 s after the objects: inside the 60 s settle window.
        let clock = Arc::new(AtomicI64::new(1_000_010_000));
        let late_key = format!("tenant_id={T}/1000000-a.parquet");
        let b = fake.put(1_000_000, "b");
        let q = queue(&fake, dir.path(), clock.clone());
        let pending = q.pending(10).await.unwrap();
        q.ack(&[pending[0].0.clone()]).await.unwrap();
        // b is acked but not settled: the watermark stays below it.
        assert_eq!(q.watermark(), None);
        // The slower upload with a smaller key lands now.
        assert_eq!(fake.put(1_000_000, "a"), late_key);
        clock.fetch_add(1_000, Ordering::SeqCst);
        assert_eq!(keys(&q.pending(10).await.unwrap()), vec![late_key.clone()]);
        q.ack(&[NoticeHandle(late_key)]).await.unwrap();
        // After the settle window both settle.
        clock.fetch_add(120_000, Ordering::SeqCst);
        assert!(q.pending(10).await.unwrap().is_empty());
        assert_eq!(q.watermark(), Some(b));
    }

    #[tokio::test]
    async fn watermark_never_passes_an_unacked_key() {
        let dir = tempfile::tempdir().unwrap();
        let fake = Fake::default();
        let clock = Arc::new(AtomicI64::new(2_000_000_000));
        let a = fake.put(1_000_000, "a");
        let b = fake.put(1_000_001, "b");
        let q = queue(&fake, dir.path(), clock.clone());
        q.pending(10).await.unwrap();
        // Ingest flushed b's flush first (a was refused into a later entry).
        q.ack(&[NoticeHandle(b.clone())]).await.unwrap();
        assert_eq!(q.watermark(), None, "a is still pending below b");
        // Crash before a is acked: a is redelivered, b is not.
        drop(q);
        let q = queue(&fake, dir.path(), clock);
        assert_eq!(keys(&q.pending(10).await.unwrap()), vec![a.clone()]);
        q.ack(&[NoticeHandle(a)]).await.unwrap();
        assert_eq!(q.watermark(), Some(b));
    }

    #[tokio::test]
    async fn pages_and_bounds_delivery() {
        let dir = tempfile::tempdir().unwrap();
        let fake = Fake::default();
        let clock = Arc::new(AtomicI64::new(2_000_000_000));
        let all = (0..25)
            .map(|i| fake.put(1_000_000 + i, &format!("k{i:02}")))
            .collect::<Vec<_>>();
        let q = queue(&fake, dir.path(), clock).with_page(4);
        let first = q.pending(10).await.unwrap();
        assert_eq!(keys(&first), all[..10].to_vec());
        q.ack(&first.iter().map(|(h, _)| h.clone()).collect::<Vec<_>>())
            .await
            .unwrap();
        assert_eq!(q.watermark(), Some(all[9].clone()));
        let mut seen = keys(&first);
        loop {
            let next = q.pending(10).await.unwrap();
            if next.is_empty() {
                break;
            }
            q.ack(&next.iter().map(|(h, _)| h.clone()).collect::<Vec<_>>())
                .await
                .unwrap();
            seen.extend(keys(&next));
        }
        assert_eq!(seen, all);
    }

    #[tokio::test]
    async fn idle_listing_is_throttled() {
        let dir = tempfile::tempdir().unwrap();
        let fake = Fake::default();
        let clock = Arc::new(AtomicI64::new(2_000_000_000));
        let q = queue(&fake, dir.path(), clock.clone());
        q.pending(10).await.unwrap();
        q.pending(10).await.unwrap();
        assert_eq!(fake.lists.load(Ordering::SeqCst), 1);
        clock.fetch_add(150, Ordering::SeqCst);
        q.pending(10).await.unwrap();
        assert_eq!(fake.lists.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn corrupt_or_foreign_state_fails_closed() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(STATE_FILE), b"{not json").unwrap();
        let settings = BronzeListSettings::default();
        assert!(BronzeListQueue::open(Fake::default(), T, dir.path(), &settings).is_err());
        let foreign = serde_json::json!({"kind": STATE_KIND, "tenant_id": "other", "prefix": "tenant_id=other/", "watermark": null, "acked": {}});
        std::fs::write(
            dir.path().join(STATE_FILE),
            serde_json::to_vec(&foreign).unwrap(),
        )
        .unwrap();
        assert!(BronzeListQueue::open(Fake::default(), T, dir.path(), &settings).is_err());
    }

    #[tokio::test]
    async fn ignores_non_bronze_and_nested_keys() {
        let dir = tempfile::tempdir().unwrap();
        let fake = Fake::default();
        let ok = fake.put(1_000_000, "a");
        for key in [
            format!("tenant_id={T}/1000001-x.json"),
            format!("tenant_id={T}/nested/1000002-y.parquet"),
        ] {
            fake.objects.lock().unwrap().insert(
                key.clone(),
                ListedBronze {
                    key,
                    etag: String::new(),
                    bytes: 1,
                    last_modified_ms: None,
                },
            );
        }
        let q = queue(&fake, dir.path(), Arc::new(AtomicI64::new(2_000_000_000)));
        assert_eq!(keys(&q.pending(10).await.unwrap()), vec![ok]);
    }

    #[test]
    fn settings_are_bounded() {
        assert!(BronzeListSettings {
            settle_secs: Some(10),
            poll_ms: None
        }
        .validate()
        .is_err());
        assert!(BronzeListSettings {
            settle_secs: None,
            poll_ms: Some(10)
        }
        .validate()
        .is_err());
        assert!(BronzeListSettings::default().validate().is_ok());
    }
}
