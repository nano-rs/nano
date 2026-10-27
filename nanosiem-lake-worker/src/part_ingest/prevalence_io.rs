// SPDX-License-Identifier: AGPL-3.0-or-later
//! Tenant-owned value cache and attributed physical I/O. SST disk parts stay 4 MiB;
//! the disk cache is sized from the state (NAN-4592, `prevalence::object_cache_bytes`).
use bytes::Bytes;
use futures::{StreamExt, TryStreamExt};
use slatedb::{
    object_store::{self, path::Path, ObjectStore},
    Db,
};
use std::collections::{BTreeMap, VecDeque};
use std::future::Future;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering::Relaxed};
use std::sync::{Arc, Mutex};

pub const VALUE_CACHE_BYTES: usize = 16 * 1024 * 1024;
/// The read path a physical read is charged to (a tokio task-local).
///
/// `Maintenance` is also the fallback for reads outside any scope. In the
/// ingest process (which never compacts a granted state) that is mostly SST
/// data blocks for every path: SlateDB fetches blocks on tasks it spawns
/// (`SstIterator::spawn_fetches`), and those lose the scope. Filter and index
/// reads stay attributed to their path (NAN-4592).
#[derive(Clone, Copy, Debug)]
#[repr(usize)]
pub enum ReadPath {
    Stamp,
    Apply,
    CatchUp,
    Restamp,
    Maintenance,
}
impl ReadPath {
    pub const ALL: [Self; 5] = [
        Self::Stamp,
        Self::Apply,
        Self::CatchUp,
        Self::Restamp,
        Self::Maintenance,
    ];
    pub fn name(self) -> &'static str {
        match self {
            Self::Stamp => "stamp",
            Self::Apply => "apply",
            Self::CatchUp => "catch_up",
            Self::Restamp => "restamp",
            Self::Maintenance => "maintenance",
        }
    }
}
tokio::task_local! { static PATH: ReadPath; }
#[cfg(test)]
tokio::task_local! { pub(crate) static MAIN_POLICY: bool; }
pub(crate) fn main_policy() -> bool {
    #[cfg(test)]
    {
        return MAIN_POLICY.try_with(|v| *v).unwrap_or(false);
    }
    #[cfg(not(test))]
    false
}
pub fn current_path() -> ReadPath {
    PATH.try_with(|p| *p).unwrap_or(ReadPath::Maintenance)
}
pub async fn scope<T>(path: ReadPath, future: impl Future<Output = T>) -> T {
    PATH.scope(path, future).await
}

#[derive(Default)]
struct Counts {
    gets: AtomicU64,
    heads: AtomicU64,
    bytes: AtomicU64,
    point_hits: AtomicU64,
    memory_hits: AtomicU64,
    db_reads: AtomicU64,
}
#[derive(Clone, Debug, serde::Serialize)]
pub struct ReadStats {
    pub path: &'static str,
    pub gets: u64,
    pub heads: u64,
    pub bytes: u64,
    pub point_cache_hits: u64,
    pub memory_cache_hits: u64,
    pub db_reads: u64,
}
#[derive(Default)]
pub struct ReadCounters {
    paths: [Counts; 5],
}
impl ReadCounters {
    pub fn db_read(&self, path: ReadPath) {
        self.paths[path as usize].db_reads.fetch_add(1, Relaxed);
    }
    pub fn snapshot(&self) -> Vec<ReadStats> {
        ReadPath::ALL
            .into_iter()
            .map(|p| {
                let c = &self.paths[p as usize];
                ReadStats {
                    path: p.name(),
                    gets: c.gets.load(Relaxed),
                    heads: c.heads.load(Relaxed),
                    bytes: c.bytes.load(Relaxed),
                    point_cache_hits: c.point_hits.load(Relaxed),
                    memory_cache_hits: c.memory_hits.load(Relaxed),
                    db_reads: c.db_reads.load(Relaxed),
                }
            })
            .collect()
    }
}

#[derive(Default)]
struct Values {
    writing: bool,
    epoch: u64,
    serial: u64,
    bytes: usize,
    entries: BTreeMap<Vec<u8>, (u64, Option<Bytes>)>,
    order: VecDeque<(u64, Vec<u8>)>,
}
/// Encoded windows, bounded inside the old 32 MiB data-cache budget. Only
/// admission/apply use this cache; a historical scan cannot evict its values.
pub struct ValueCache {
    inner: Mutex<Values>,
    enabled: bool,
}
fn charge(k: &[u8], v: &Option<Bytes>) -> usize {
    256 + k.len() * 3 + v.as_ref().map_or(0, Bytes::len)
}
impl ValueCache {
    pub fn new(enabled: bool) -> Self {
        Self {
            inner: Mutex::new(Values::default()),
            enabled,
        }
    }
    fn lookup(&self, key: &[u8]) -> (u64, Option<Option<Bytes>>) {
        let v = self.inner.lock().unwrap();
        (
            v.epoch,
            if self.enabled && !v.writing {
                v.entries.get(key).map(|(_, b)| b.clone())
            } else {
                None
            },
        )
    }
    fn put(v: &mut Values, key: Vec<u8>, value: Option<Bytes>) {
        if let Some((_, old)) = v.entries.remove(&key) {
            v.bytes -= charge(&key, &old);
        }
        let bytes = charge(&key, &value);
        if bytes > VALUE_CACHE_BYTES {
            return;
        }
        v.serial = v.serial.wrapping_add(1);
        let serial = v.serial;
        v.bytes += bytes;
        v.entries.insert(key.clone(), (serial, value));
        v.order.push_back((serial, key));
        while v.bytes > VALUE_CACHE_BYTES {
            let Some((s, k)) = v.order.pop_front() else {
                break;
            };
            if v.entries.get(&k).is_some_and(|(seen, _)| *seen == s) {
                let (_, old) = v.entries.remove(&k).unwrap();
                v.bytes -= charge(&k, &old);
            }
        }
        if v.order.len() > 2 * v.entries.len() {
            v.order
                .retain(|(s, k)| v.entries.get(k).is_some_and(|(seen, _)| seen == s));
        }
    }
    /// An erasure also revokes cached values when the DB key has already
    /// expired. Preserve a canceled write's guard until its barrier finishes.
    pub fn invalidate(&self) {
        let mut v = self.inner.lock().unwrap();
        v.epoch = v.epoch.wrapping_add(1);
        v.entries.clear();
        v.order.clear();
        v.bytes = 0;
    }
    pub fn after_durability_barrier(&self) {
        let mut v = self.inner.lock().unwrap();
        if v.writing {
            v.epoch = v.epoch.wrapping_add(1);
            v.entries.clear();
            v.order.clear();
            v.bytes = 0;
            v.writing = false;
        }
    }
    fn observed(&self, epoch: u64, key: &[u8], value: Option<Bytes>) {
        if !self.enabled {
            return;
        }
        let mut v = self.inner.lock().unwrap();
        if v.epoch == epoch && !v.writing {
            Self::put(&mut v, key.to_vec(), value);
        }
    }
    /// Invalidate before the DB mutation, including erasure/reset. A cancelled
    /// write leaves misses, never stale counts. Late reads cannot reinsert priors.
    pub fn before_write(&self, updates: Option<&[(Vec<u8>, Bytes)]>) {
        let mut v = self.inner.lock().unwrap();
        v.epoch = v.epoch.wrapping_add(1);
        v.writing = true;
        if let Some(updates) = updates {
            for (k, _) in updates {
                if let Some((_, old)) = v.entries.remove(k) {
                    v.bytes -= charge(k, &old);
                }
            }
        } else {
            v.entries.clear();
            v.order.clear();
            v.bytes = 0;
        }
    }
    /// The atomic DB write is visible before these values are published. No
    /// await separates the write's completion from this second epoch change.
    pub fn after_write(&self, updates: Option<&[(Vec<u8>, Bytes)]>) {
        let mut v = self.inner.lock().unwrap();
        v.epoch = v.epoch.wrapping_add(1);
        v.writing = false;
        if self.enabled {
            if let Some(updates) = updates {
                for (k, b) in updates {
                    Self::put(&mut v, k.clone(), Some(b.clone()));
                }
            }
        }
    }
}
pub async fn read(
    db: &Db,
    cache: &ValueCache,
    counters: &ReadCounters,
    path: ReadPath,
    key: &[u8],
) -> anyhow::Result<Option<Bytes>> {
    let (epoch, hit) = cache.lookup(key);
    let c = &counters.paths[path as usize];
    if let Some(hit) = hit {
        c.point_hits.fetch_add(1, Relaxed);
        return Ok(hit);
    }
    counters.db_read(path);
    let value = scope(path, db.get(key)).await?;
    cache.observed(epoch, key, value.clone());
    Ok(value)
}
/// Per-state bounded budget: foreground work takes priority immediately;
/// already-running reads drain when the limit falls, without restarting them.
pub struct RestampBudget {
    lanes: AtomicUsize,
    foreground: AtomicUsize,
}
impl Default for RestampBudget {
    fn default() -> Self {
        Self {
            lanes: AtomicUsize::new(32),
            foreground: AtomicUsize::new(0),
        }
    }
}
impl RestampBudget {
    pub fn update(&self, lag: i64, bound: i64, l0_overdue: i64) {
        self.adjust(
            super::merge_quota::catch_up_headroom(lag, bound),
            lag,
            l0_overdue,
        );
    }
    fn adjust(&self, headroom: super::prevalence::CatchUpHeadroom, lag: i64, l0_overdue: i64) {
        use super::prevalence::CatchUpHeadroom;
        let target = if l0_overdue > 0 {
            16
        } else {
            match headroom {
                CatchUpHeadroom::Room => 128,
                CatchUpHeadroom::Hold => 32,
                CatchUpHeadroom::Pressured => 16,
            }
        };
        let old = self.lanes.swap(target, Relaxed);
        if old != target {
            tracing::info!(
                lanes = target,
                previous = old,
                lag_ms = lag,
                l0_overdue_ms = l0_overdue,
                "prevalence restamp read budget adjusted"
            );
        }
    }
    pub fn lanes(&self) -> usize {
        if self.foreground.load(Relaxed) > 0 {
            16
        } else {
            self.lanes.load(Relaxed)
        }
    }
    pub fn foreground(self: &Arc<Self>) -> Foreground {
        self.foreground.fetch_add(1, Relaxed);
        Foreground(self.clone())
    }
}
pub struct Foreground(Arc<RestampBudget>);
impl Drop for Foreground {
    fn drop(&mut self) {
        self.0.foreground.fetch_sub(1, Relaxed);
    }
}

pub struct MeteredStore {
    pub inner: Arc<dyn ObjectStore>,
    pub counters: Arc<ReadCounters>,
}
impl std::fmt::Debug for MeteredStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "TenantPrevalenceIo")
    }
}
impl std::fmt::Display for MeteredStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "TenantPrevalenceIo")
    }
}
#[async_trait::async_trait]
impl ObjectStore for MeteredStore {
    async fn put_opts(
        &self,
        p: &Path,
        b: object_store::PutPayload,
        o: object_store::PutOptions,
    ) -> object_store::Result<object_store::PutResult> {
        self.inner.put_opts(p, b, o).await
    }
    async fn put_multipart_opts(
        &self,
        p: &Path,
        o: object_store::PutMultipartOptions,
    ) -> object_store::Result<Box<dyn object_store::MultipartUpload>> {
        self.inner.put_multipart_opts(p, o).await
    }
    async fn get_opts(
        &self,
        p: &Path,
        o: object_store::GetOptions,
    ) -> object_store::Result<object_store::GetResult> {
        let path = current_path();
        let head = o.head;
        let c = &self.counters.paths[path as usize];
        if head {
            c.heads.fetch_add(1, Relaxed);
        } else {
            c.gets.fetch_add(1, Relaxed);
        }
        let result = self.inner.get_opts(p, o).await?;
        if !head {
            let counters = self.counters.clone();
            let (meta, range, attributes, extensions) = (
                result.meta.clone(),
                result.range.clone(),
                result.attributes.clone(),
                result.extensions.clone(),
            );
            let stream = result
                .into_stream()
                .inspect_ok(move |b| {
                    counters.paths[path as usize]
                        .bytes
                        .fetch_add(b.len() as u64, Relaxed);
                })
                .boxed();
            return Ok(object_store::GetResult {
                meta,
                range,
                attributes,
                extensions,
                payload: object_store::GetResultPayload::Stream(stream),
            });
        }
        Ok(result)
    }
    fn delete_stream(
        &self,
        p: futures::stream::BoxStream<'static, object_store::Result<Path>>,
    ) -> futures::stream::BoxStream<'static, object_store::Result<Path>> {
        self.inner.delete_stream(p)
    }
    fn list(
        &self,
        p: Option<&Path>,
    ) -> futures::stream::BoxStream<'static, object_store::Result<object_store::ObjectMeta>> {
        self.inner.list(p)
    }
    async fn list_with_delimiter(
        &self,
        p: Option<&Path>,
    ) -> object_store::Result<object_store::ListResult> {
        self.inner.list_with_delimiter(p).await
    }
    async fn copy_opts(
        &self,
        a: &Path,
        b: &Path,
        o: object_store::CopyOptions,
    ) -> object_store::Result<()> {
        self.inner.copy_opts(a, b, o).await
    }
}

// Preserve the initiating path inside Foyer loaders, which can be spawned.
// Delegating fetch_* (rather than using the default implementation) retains
// Foyer single-flight deduplication, including cache/in-flight reuse counts.
pub struct MeasuredCache {
    pub inner: Arc<dyn slatedb::db_cache::DbCache>,
    pub counters: Arc<ReadCounters>,
}
fn scoped_loader(
    loader: slatedb::db_cache::CacheLoader,
    path: ReadPath,
    ran: Arc<std::sync::atomic::AtomicBool>,
) -> slatedb::db_cache::CacheLoader {
    Box::new(move || {
        ran.store(true, Relaxed);
        Box::pin(scope(path, loader()))
    })
}
#[async_trait::async_trait]
impl slatedb::db_cache::DbCache for MeasuredCache {
    async fn get_block(
        &self,
        key: &slatedb::db_cache::CachedKey,
    ) -> Result<Option<slatedb::db_cache::CachedEntry>, slatedb::Error> {
        let result = self.inner.get_block(key).await;
        if matches!(result, Ok(Some(_))) {
            self.counters.paths[current_path() as usize]
                .memory_hits
                .fetch_add(1, Relaxed);
        }
        result
    }
    async fn fetch_block(
        &self,
        key: slatedb::db_cache::CachedKey,
        loader: slatedb::db_cache::CacheLoader,
    ) -> Result<slatedb::db_cache::CachedEntry, slatedb::Error> {
        let path = current_path();
        let ran = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let result = self
            .inner
            .fetch_block(key, scoped_loader(loader, path, ran.clone()))
            .await;
        if result.is_ok() && !ran.load(Relaxed) {
            self.counters.paths[path as usize]
                .memory_hits
                .fetch_add(1, Relaxed);
        }
        result
    }
    async fn get_index(
        &self,
        key: &slatedb::db_cache::CachedKey,
    ) -> Result<Option<slatedb::db_cache::CachedEntry>, slatedb::Error> {
        let result = self.inner.get_index(key).await;
        if matches!(result, Ok(Some(_))) {
            self.counters.paths[current_path() as usize]
                .memory_hits
                .fetch_add(1, Relaxed);
        }
        result
    }
    async fn fetch_index(
        &self,
        key: slatedb::db_cache::CachedKey,
        loader: slatedb::db_cache::CacheLoader,
    ) -> Result<slatedb::db_cache::CachedEntry, slatedb::Error> {
        let path = current_path();
        let ran = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let result = self
            .inner
            .fetch_index(key, scoped_loader(loader, path, ran.clone()))
            .await;
        if result.is_ok() && !ran.load(Relaxed) {
            self.counters.paths[path as usize]
                .memory_hits
                .fetch_add(1, Relaxed);
        }
        result
    }
    async fn get_filter(
        &self,
        key: &slatedb::db_cache::CachedKey,
    ) -> Result<Option<slatedb::db_cache::CachedEntry>, slatedb::Error> {
        let result = self.inner.get_filter(key).await;
        if matches!(result, Ok(Some(_))) {
            self.counters.paths[current_path() as usize]
                .memory_hits
                .fetch_add(1, Relaxed);
        }
        result
    }
    async fn fetch_filter(
        &self,
        key: slatedb::db_cache::CachedKey,
        loader: slatedb::db_cache::CacheLoader,
    ) -> Result<slatedb::db_cache::CachedEntry, slatedb::Error> {
        let path = current_path();
        let ran = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let result = self
            .inner
            .fetch_filter(key, scoped_loader(loader, path, ran.clone()))
            .await;
        if result.is_ok() && !ran.load(Relaxed) {
            self.counters.paths[path as usize]
                .memory_hits
                .fetch_add(1, Relaxed);
        }
        result
    }
    async fn get_stats(
        &self,
        key: &slatedb::db_cache::CachedKey,
    ) -> Result<Option<slatedb::db_cache::CachedEntry>, slatedb::Error> {
        let result = self.inner.get_stats(key).await;
        if matches!(result, Ok(Some(_))) {
            self.counters.paths[current_path() as usize]
                .memory_hits
                .fetch_add(1, Relaxed);
        }
        result
    }
    async fn fetch_stats(
        &self,
        key: slatedb::db_cache::CachedKey,
        loader: slatedb::db_cache::CacheLoader,
    ) -> Result<slatedb::db_cache::CachedEntry, slatedb::Error> {
        let path = current_path();
        let ran = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let result = self
            .inner
            .fetch_stats(key, scoped_loader(loader, path, ran.clone()))
            .await;
        if result.is_ok() && !ran.load(Relaxed) {
            self.counters.paths[path as usize]
                .memory_hits
                .fetch_add(1, Relaxed);
        }
        result
    }
    async fn insert(&self, k: slatedb::db_cache::CachedKey, v: slatedb::db_cache::CachedEntry) {
        self.inner.insert(k, v).await
    }
    async fn remove(&self, k: &slatedb::db_cache::CachedKey) {
        self.inner.remove(k).await
    }
    fn entry_count(&self) -> u64 {
        self.inner.entry_count()
    }
    async fn close(&self) -> Result<(), slatedb::Error> {
        self.inner.close().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn value_cache_rejects_late_reads_and_canceled_writes() {
        let cache = ValueCache::new(true);
        let k = b"entity";
        let epoch = cache.lookup(k).0;
        cache.observed(epoch, k, None);
        assert_eq!(cache.lookup(k).1, Some(None));
        let updates = vec![(k.to_vec(), Bytes::from_static(b"committed"))];
        cache.before_write(Some(&updates));
        cache.observed(cache.lookup(k).0, k, Some(Bytes::from_static(b"prior")));
        assert_eq!(
            cache.lookup(k).1,
            None,
            "an in-flight write cannot cache a prior read"
        );
        cache.after_write(Some(&updates));
        cache.observed(epoch, k, None);
        assert_eq!(
            cache.lookup(k).1,
            Some(Some(Bytes::from_static(b"committed")))
        );
        // A write can be canceled after SlateDB accepts it. Invalidated
        // values must stay misses until a durability barrier recovers it.
        cache.before_write(Some(&updates));
        cache.invalidate();
        cache.observed(cache.lookup(k).0, k, Some(Bytes::from_static(b"prior")));
        assert_eq!(cache.lookup(k).1, None);
        cache.after_durability_barrier();
        let epoch = cache.lookup(k).0;
        cache.observed(epoch, k, Some(Bytes::from_static(b"after recovery")));
        assert_eq!(
            cache.lookup(k).1,
            Some(Some(Bytes::from_static(b"after recovery")))
        );
        cache.before_write(None); // erasure/reset
        cache.after_write(None);
        cache.observed(epoch, k, Some(Bytes::from_static(b"erased")));
        assert_eq!(cache.lookup(k).1, None);
    }
    #[test]
    fn value_cache_bounds_payload_and_stale_eviction_records() {
        let cache = ValueCache::new(true);
        let payload = Bytes::from(vec![0u8; 1_048_576]);
        for n in 0..100 {
            let k = format!("entity-{}", n % 20).into_bytes();
            let updates = vec![(k, payload.clone())];
            cache.before_write(Some(&updates));
            cache.after_write(Some(&updates));
            let v = cache.inner.lock().unwrap();
            assert!(v.bytes <= VALUE_CACHE_BYTES);
            assert!(v.order.len() <= 2 * v.entries.len());
        }
        assert!(cache.lookup(b"entity-19").1.is_some());
        assert!(cache.lookup(b"entity-0").1.is_none());
    }
    #[test]
    fn restamp_budget_scales_with_headroom_and_yields_to_foreground_and_l0() {
        use super::super::prevalence::CatchUpHeadroom::*;
        let budget = Arc::new(RestampBudget::default());
        for (headroom, lanes) in [(Room, 128), (Hold, 32), (Pressured, 16)] {
            budget.adjust(headroom, 80_000, 0);
            assert_eq!(budget.lanes(), lanes);
        }
        budget.adjust(Room, 70_000, 0);
        let guard = budget.foreground();
        assert_eq!(budget.lanes(), 16);
        drop(guard);
        assert_eq!(budget.lanes(), 128);
        budget.adjust(Room, 70_000, 1);
        assert_eq!(budget.lanes(), 16);
    }
}
