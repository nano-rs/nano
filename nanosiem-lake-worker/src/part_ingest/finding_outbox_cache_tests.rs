// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-3096: the finding drain keeps one part-log view across passes instead
//! of re-listing checkpoints and re-reading every entry since the newest one
//! on every pass that publishes findings.

use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::Result;
use arrow_schema::{DataType, Field, Schema, TimeUnit};

use super::DrainLogCache;
use crate::parts::format::PartId;
use crate::parts::levels::Level;
use crate::parts::part_log::{load_log, LocalObjectStore, LogOp, ObjectStore, PartLogWriter, PartRef, SourceRef};

const TENANT: &str = "00000000-0000-4000-8000-000000000001";
const OTHER: &str = "00000000-0000-4000-8000-000000000002";

fn schema() -> Schema {
    Schema::new(vec![
        Field::new("time", DataType::Timestamp(TimeUnit::Microsecond, Some("+00:00".into())), false),
        Field::new("message", DataType::Utf8, true),
    ])
}

fn part(n: u64) -> PartRef {
    PartRef {
        part_id: PartId::parse(&format!("{:013}-{:016x}", 1_000 + n, n)).unwrap(),
        level: Level::L0,
        event_hour: 10,
        event_day: None,
        rows: 5,
        min_time_us: 1,
        max_time_us: 2,
        schema_fingerprint: "a".repeat(64),
        provenance_sha256: "b".repeat(64),
        merkle_root: "c".repeat(64),
        sorted: true,
        data_bytes: 10,
        row_groups: 1,
        data_files: 1,
    }
}

fn source(n: u64) -> SourceRef {
    SourceRef { key: format!("bronze/{n}.parquet"), version: "1".into(), sha256: "d".repeat(64) }
}

/// Counts the R2-billed operations a log read issues.
struct CountingStore<'a> {
    inner: &'a LocalObjectStore,
    entry_gets: AtomicU64,
    lists: AtomicU64,
}

impl<'a> CountingStore<'a> {
    fn new(inner: &'a LocalObjectStore) -> Self {
        Self { inner, entry_gets: AtomicU64::new(0), lists: AtomicU64::new(0) }
    }
    fn take(&self) -> (u64, u64) {
        (self.entry_gets.swap(0, Ordering::SeqCst), self.lists.swap(0, Ordering::SeqCst))
    }
}

#[async_trait::async_trait]
impl ObjectStore for CountingStore<'_> {
    async fn get(&self, key: &str) -> Result<Option<Vec<u8>>> {
        if key.contains("/log/entries/") {
            self.entry_gets.fetch_add(1, Ordering::SeqCst);
        }
        self.inner.get(key).await
    }
    async fn put_if_absent(&self, key: &str, bytes: &[u8]) -> Result<bool> {
        self.inner.put_if_absent(key, bytes).await
    }
    async fn put(&self, key: &str, bytes: &[u8]) -> Result<()> {
        self.inner.put(key, bytes).await
    }
    async fn delete(&self, key: &str) -> Result<()> {
        self.inner.delete(key).await
    }
    async fn list(&self, prefix: &str) -> Result<Vec<String>> {
        self.lists.fetch_add(1, Ordering::SeqCst);
        self.inner.list(prefix).await
    }
}

async fn append_adds(writer: &mut PartLogWriter<'_>, from: u64, count: u64) {
    for n in from..from + count {
        writer
            .append(LogOp::Add { parts: vec![part(n)], consumed: vec![source(n)], edge_log: None }, 2)
            .await
            .unwrap();
    }
}

#[tokio::test]
async fn a_warm_drain_view_reads_only_new_entries_and_never_lists() {
    let dir = tempfile::tempdir().unwrap();
    let local = LocalObjectStore::new(dir.path()).unwrap();
    let mut writer = PartLogWriter::open(&local, TENANT, 1, &schema(), 1).await.unwrap();
    append_adds(&mut writer, 1, 200).await;
    let store = CountingStore::new(&local);
    let mut cache = DrainLogCache::default();

    // Cold: identical to load_log (checkpoint LIST + every entry).
    let cold = cache.take_current(&store, TENANT).await.unwrap();
    let (gets, lists) = store.take();
    assert_eq!(cold.head(), load_log(&local, TENANT).await.unwrap().head());
    assert_eq!(lists, 1);
    assert!(gets > 200, "a cold view reads the whole tail ({gets})");
    cache.keep(cold);

    // Nothing new: one probe of the next entry, no LIST.
    let warm = cache.take_current(&store, TENANT).await.unwrap();
    assert_eq!(store.take(), (1, 0));
    cache.keep(warm);

    // Three appends: windows of 1, 2, then 4 probes beyond the head.
    append_adds(&mut writer, 201, 3).await;
    let advanced = cache.take_current(&store, TENANT).await.unwrap();
    let (gets, lists) = store.take();
    assert_eq!(lists, 0);
    assert_eq!(gets, 7, "catch-up uses doubling windows for 3 appends");
    assert_eq!(advanced.head(), load_log(&local, TENANT).await.unwrap().head());
    assert_eq!(advanced.head().unwrap().0, 203);
    assert_eq!(advanced.schema(), load_log(&local, TENANT).await.unwrap().schema());
    cache.keep(advanced);
    assert_eq!(cache.head_seq(), Some(203));
}

#[tokio::test]
async fn switching_tenants_reloads_from_the_checkpoint() {
    let dir = tempfile::tempdir().unwrap();
    let local = LocalObjectStore::new(dir.path()).unwrap();
    let mut a = PartLogWriter::open(&local, TENANT, 1, &schema(), 1).await.unwrap();
    append_adds(&mut a, 1, 3).await;
    let mut b = PartLogWriter::open(&local, OTHER, 1, &schema(), 1).await.unwrap();
    append_adds(&mut b, 1, 6).await;

    // Switching tenants must reload even when the other log has a longer tail.
    let mut cache = DrainLogCache::default();
    let initial = cache.take_current(&local, TENANT).await.unwrap();
    cache.keep(initial);
    let reloaded = cache.take_current(&local, OTHER).await.unwrap();
    assert_eq!(reloaded.head(), load_log(&local, OTHER).await.unwrap().head());
    assert_eq!(reloaded.head().unwrap().0, 6);
}

#[tokio::test]
async fn a_taken_view_that_is_not_kept_leaves_the_cache_cold() {
    let dir = tempfile::tempdir().unwrap();
    let local = LocalObjectStore::new(dir.path()).unwrap();
    let mut writer = PartLogWriter::open(&local, TENANT, 1, &schema(), 1).await.unwrap();
    append_adds(&mut writer, 1, 2).await;
    let store = CountingStore::new(&local);
    let mut cache = DrainLogCache::default();
    let taken = cache.take_current(&store, TENANT).await.unwrap();
    // A pass that fails after taking the view never calls keep().
    drop(taken);
    assert_eq!(cache.head_seq(), None);
    store.take();
    cache.take_current(&store, TENANT).await.unwrap();
    assert_eq!(store.take().1, 1, "the next pass reloads with a checkpoint LIST");
}

#[tokio::test]
async fn switching_to_a_shorter_tenant_log_reloads_even_without_new_entries() {
    let dir = tempfile::tempdir().unwrap();
    let local = LocalObjectStore::new(dir.path()).unwrap();
    let mut a = PartLogWriter::open(&local, TENANT, 1, &schema(), 1).await.unwrap();
    append_adds(&mut a, 1, 6).await;
    let mut b = PartLogWriter::open(&local, OTHER, 1, &schema(), 1).await.unwrap();
    append_adds(&mut b, 1, 2).await;
    let mut cache = DrainLogCache::default();
    let first = cache.take_current(&local, TENANT).await.unwrap();
    cache.keep(first);
    let other = cache.take_current(&local, OTHER).await.unwrap();
    assert_eq!(other.head(), load_log(&local, OTHER).await.unwrap().head());
}

#[tokio::test]
async fn checkpoint_interval_reloads_historical_metadata() {
    let dir = tempfile::tempdir().unwrap();
    let local = LocalObjectStore::new(dir.path()).unwrap();
    let mut writer = PartLogWriter::open(&local, TENANT, 1, &schema(), 1).await.unwrap();
    let store = CountingStore::new(&local);
    let mut cache = DrainLogCache::default();
    let first = cache.take_current(&store, TENANT).await.unwrap();
    cache.keep(first);
    append_adds(&mut writer, 1, crate::parts::part_log::CHECKPOINT_EVERY).await;
    let advanced = cache.take_current(&store, TENANT).await.unwrap();
    cache.keep(advanced);
    store.take();
    let reloaded = cache.take_current(&store, TENANT).await.unwrap();
    assert_eq!(store.take().1, 1);
    assert_eq!(reloaded.head(), load_log(&local, TENANT).await.unwrap().head());
}

#[tokio::test]
async fn failed_chain_verification_discards_the_cached_view() {
    let dir = tempfile::tempdir().unwrap();
    let local = LocalObjectStore::new(dir.path()).unwrap();
    let mut writer = PartLogWriter::open(&local, TENANT, 1, &schema(), 1).await.unwrap();
    append_adds(&mut writer, 1, 2).await;
    let mut cache = DrainLogCache::default();
    let first = cache.take_current(&local, TENANT).await.unwrap();
    cache.keep(first);
    append_adds(&mut writer, 3, 1).await;
    let key = crate::parts::format::LogKeys::new(TENANT).unwrap().entry(3);
    let original = local.get(&key).await.unwrap().unwrap();
    let mut entry: serde_json::Value = serde_json::from_slice(&original).unwrap();
    entry["prev_sha256"] = serde_json::Value::String("0".repeat(64));
    local.put(&key, &serde_json::to_vec(&entry).unwrap()).await.unwrap();
    assert!(cache.take_current(&local, TENANT).await.is_err());
    assert_eq!(cache.head_seq(), None);
    local.put(&key, &original).await.unwrap();
    let restored = cache.take_current(&local, TENANT).await.unwrap();
    assert_eq!(restored.head(), load_log(&local, TENANT).await.unwrap().head());
}
