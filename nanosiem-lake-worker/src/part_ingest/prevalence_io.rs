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
///
/// NAN-4723: the lanes follow their target AIMD-style instead of jumping to
/// it. The NAN-4689 soak flipped 128 <-> 16 180 times an hour: the part-L0
/// overdue signal toggles every few ticks under load, and each flip to 128
/// launched a burst of restamp reads into a prevalence state already in
/// write backpressure. Now pressure halves the lanes at once (never below
/// the target), and the lanes grow back only after [`RESTAMP_RAISE_HOLD`]
/// without any pressure signal (a target under the maximum), by
/// [`RESTAMP_LANE_STEP`] at most every [`RESTAMP_RAISE_EVERY`].
pub struct RestampBudget {
    lanes: AtomicUsize,
    foreground: AtomicUsize,
    /// The last pressure signal, and the last raise.
    changes: std::sync::Mutex<RestampChanges>,
}
#[derive(Default)]
struct RestampChanges {
    cut: Option<std::time::Instant>,
    raised: Option<std::time::Instant>,
}
/// Fewest restamp lanes (pressure, L0 overdue, foreground work).
pub const RESTAMP_MIN_LANES: usize = 16;
/// Most restamp lanes (full headroom).
pub const RESTAMP_MAX_LANES: usize = 128;
/// Lanes added per raise.
pub const RESTAMP_LANE_STEP: usize = 16;
/// Quiet time after a pressure signal before the lanes may grow again.
pub const RESTAMP_RAISE_HOLD: std::time::Duration = std::time::Duration::from_secs(30);
/// Shortest spacing between two raises.
pub const RESTAMP_RAISE_EVERY: std::time::Duration = std::time::Duration::from_secs(5);
impl Default for RestampBudget {
    fn default() -> Self {
        Self {
            lanes: AtomicUsize::new(32),
            foreground: AtomicUsize::new(0),
            changes: std::sync::Mutex::new(RestampChanges::default()),
        }
    }
}
impl RestampBudget {
    pub fn update(&self, lag: i64, bound: i64, l0_overdue: i64) {
        self.adjust(
            super::merge_quota::catch_up_headroom(lag, bound),
            lag,
            l0_overdue,
            std::time::Instant::now(),
        );
    }
    /// The lanes the headroom asks for.
    fn target(headroom: super::prevalence::CatchUpHeadroom, l0_overdue: i64) -> usize {
        use super::prevalence::CatchUpHeadroom;
        if l0_overdue > 0 {
            RESTAMP_MIN_LANES
        } else {
            match headroom {
                CatchUpHeadroom::Room => RESTAMP_MAX_LANES,
                CatchUpHeadroom::Hold => 32,
                CatchUpHeadroom::Pressured => RESTAMP_MIN_LANES,
            }
        }
    }
    fn adjust(&self, headroom: super::prevalence::CatchUpHeadroom, lag: i64, l0_overdue: i64, now: std::time::Instant) {
        let target = Self::target(headroom, l0_overdue);
        let mut changes = self.changes.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let old = self.lanes.load(Relaxed);
        if target < RESTAMP_MAX_LANES && target <= old {
            // Pressure at or below the current lanes (even at the floor
            // already) restarts the hold. A target above them (`Hold`'s 32
            // over a floor of 16) is not pressure: the lanes climb to it
            // after the hold, so every steady signal converges to its target.
            changes.cut = Some(now);
        }
        let next = if target < old {
            // Multiplicative decrease, at once.
            (old / 2).max(target)
        } else if target > old {
            let held = changes.cut.is_none_or(|at| now.saturating_duration_since(at) >= RESTAMP_RAISE_HOLD);
            let spaced = changes.raised.is_none_or(|at| now.saturating_duration_since(at) >= RESTAMP_RAISE_EVERY);
            if held && spaced {
                changes.raised = Some(now);
                (old + RESTAMP_LANE_STEP).min(target)
            } else {
                old
            }
        } else {
            old
        };
        if next != old {
            self.lanes.store(next, Relaxed);
            tracing::info!(
                lanes = next,
                previous = old,
                target,
                lag_ms = lag,
                l0_overdue_ms = l0_overdue,
                "prevalence restamp read budget adjusted"
            );
        }
    }
    pub fn lanes(&self) -> usize {
        if self.foreground.load(Relaxed) > 0 {
            RESTAMP_MIN_LANES
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
    /// NAN-4723: the production budget (`RestampBudget::default`, the one
    /// `open_store` builds) under pressure halves to the floor, holds there
    /// through a flapping signal, and climbs back by steps only after a
    /// quiet hold. Foreground work and an overdue L0 still yield at once.
    #[test]
    fn restamp_budget_cuts_fast_and_grows_back_slowly() {
        use super::super::prevalence::CatchUpHeadroom::*;
        use std::time::Duration;
        let budget = Arc::new(RestampBudget::default());
        let t0 = std::time::Instant::now();
        let at = |secs: u64| t0 + Duration::from_secs(secs);
        assert_eq!(budget.lanes(), 32);
        // Room from the start: one step per RAISE_EVERY, never a jump.
        budget.adjust(Room, 0, 0, at(0));
        assert_eq!(budget.lanes(), 48);
        budget.adjust(Room, 0, 0, at(1));
        assert_eq!(budget.lanes(), 48, "raises are spaced");
        for (n, secs) in (5..=30).step_by(5).enumerate() {
            budget.adjust(Room, 0, 0, at(secs));
            assert_eq!(budget.lanes(), (64 + 16 * n).min(RESTAMP_MAX_LANES));
        }
        assert_eq!(budget.lanes(), RESTAMP_MAX_LANES);
        // Pressure: halve at once on every update, never below the target.
        budget.adjust(Pressured, 80_000, 0, at(31));
        assert_eq!(budget.lanes(), 64);
        budget.adjust(Room, 0, 1, at(32));
        assert_eq!(budget.lanes(), 32, "an overdue L0 cuts as well");
        budget.adjust(Hold, 50_000, 0, at(33));
        assert_eq!(budget.lanes(), 32, "Hold's target is 32: no cut below it");
        budget.adjust(Pressured, 80_000, 0, at(34));
        assert_eq!(budget.lanes(), RESTAMP_MIN_LANES);
        budget.adjust(Pressured, 80_000, 0, at(35));
        assert_eq!(budget.lanes(), RESTAMP_MIN_LANES);
        // The soak's flapping signal: room every other tick. No raise
        // while cuts keep coming (the old budget flipped 16 -> 128 here).
        for secs in 36..90 {
            let overdue = if secs % 2 == 0 { 0 } else { 5_000 };
            budget.adjust(Room, 1_000, overdue, at(secs));
            assert!(budget.lanes() <= 2 * RESTAMP_MIN_LANES, "flapping signal raised to {} at {secs}s", budget.lanes());
        }
        // Quiet: nothing for the hold, then +16 per step.
        let last_cut = 89;
        budget.adjust(Room, 0, 0, at(last_cut + 29));
        assert_eq!(budget.lanes(), RESTAMP_MIN_LANES, "still inside the hold");
        budget.adjust(Room, 0, 0, at(last_cut + 30));
        assert_eq!(budget.lanes(), RESTAMP_MIN_LANES + RESTAMP_LANE_STEP);
        // Foreground ingest work still takes the floor at once.
        let guard = budget.foreground();
        assert_eq!(budget.lanes(), RESTAMP_MIN_LANES);
        drop(guard);
        assert_eq!(budget.lanes(), RESTAMP_MIN_LANES + RESTAMP_LANE_STEP);
    }
    /// NAN-4723: every steady signal converges to its own target, from
    /// above or below, and stays there (bounded to 16..=128 throughout).
    #[test]
    fn restamp_budget_converges_to_a_steady_target() {
        use super::super::prevalence::CatchUpHeadroom::{self, *};
        use std::time::Duration;
        let settle = |budget: &RestampBudget, headroom: CatchUpHeadroom, l0_overdue: i64, from: u64| -> u64 {
            let t0 = std::time::Instant::now();
            for secs in from..from + 300 {
                budget.adjust(headroom, 0, l0_overdue, t0 + Duration::from_secs(secs));
                assert!((RESTAMP_MIN_LANES..=RESTAMP_MAX_LANES).contains(&budget.lanes()));
            }
            from + 300
        };
        let budget = RestampBudget::default();
        let mut t = settle(&budget, Pressured, 0, 0);
        assert_eq!(budget.lanes(), RESTAMP_MIN_LANES);
        // Steady Hold after pressure: climbs from the floor to 32 (it used
        // to be stuck at 16: Hold restarted the hold it waited on).
        t = settle(&budget, Hold, 0, t);
        assert_eq!(budget.lanes(), 32, "steady Hold reaches its target");
        t = settle(&budget, Room, 0, t);
        assert_eq!(budget.lanes(), RESTAMP_MAX_LANES);
        t = settle(&budget, Hold, 0, t);
        assert_eq!(budget.lanes(), 32, "steady Hold from above cuts to its target");
        settle(&budget, Room, 1, t);
        assert_eq!(budget.lanes(), RESTAMP_MIN_LANES, "a steadily overdue L0 holds the floor");
    }
}
