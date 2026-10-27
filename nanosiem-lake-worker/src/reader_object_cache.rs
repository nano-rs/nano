// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-2853: bounded, verified, tenant-scoped reader cache over R2.
//!
//! In bounded mode a reader keeps only a byte-budgeted set of immutable
//! generation objects (event Parquet) on local disk. Before chDB runs, the
//! query calls [`ReaderObjectCache::ensure_local`] with the exact objects its
//! plan names. Hits are leased immediately. Misses are streamed from the
//! tenant's own bucket, fenced by the signed length and SHA-256, and admitted
//! as `{root}/tenant-{id}/objects/{sha256}.bin` (0444). chDB keeps reading
//! local files and never sees R2 or unverified bytes.
//!
//! The design generalizes the hot-tail cache (content-addressed 0444 objects,
//! `persist_noclobber`, cross-process hard-link + flock leases, stale-pin
//! reclaim, per-inode accounting) and the derivative tier (true LRU and
//! in-process single-flight). `Ok` from `ensure_local` always means every
//! requested object is present and leased: a query never reads a subset.
//!
//! Cross-process: the query server and the durable-job runner share one tenant
//! directory. A global flock serializes admission, eviction and lease metadata;
//! downloads never hold it. Each process keeps its own in-flight reservation
//! and LRU clock; objects another process admitted are picked up from disk the
//! next time this process is over budget.

use crate::hot_tail_cache::{parse_s3_uri, shared_r2_operator, valid_sha256};
use anyhow::Context as _;
use fs2::FileExt;
use futures::future::{BoxFuture, FutureExt, Shared};
use futures::{StreamExt as _, TryStreamExt};
use opendal::Operator;
use sha2::{Digest, Sha256};
use std::collections::{BTreeSet, HashMap, HashSet};
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// NAN-3164: one token bucket per hydration pass, shared by every concurrent
/// background download. Bytes are charged as they arrive, so time already
/// spent on the network counts toward the budget: a stream slower than the
/// cap never sleeps, and N streams together never exceed it. (The old pacer
/// slept `chunk / cap` after every chunk on top of the transfer time, so a
/// serial stream ran at `1 / (1/network + 1/cap)`, well under either.)
#[derive(Debug)]
pub struct HydrateBucket {
    rate: AtomicU64,
    state: Mutex<BucketState>,
}
#[derive(Debug)]
struct BucketState {
    /// When the bytes charged so far have been "paid for" at `rate`.
    next: Instant,
    /// Largest chunk seen: the burst credit, so a slower-than-cap stream's
    /// next chunk is already covered by the time it arrives.
    largest_chunk: u64,
}
impl HydrateBucket {
    pub fn new(rate: u64) -> Arc<Self> {
        Arc::new(Self {
            rate: AtomicU64::new(rate),
            state: Mutex::new(BucketState { next: pacing_now(), largest_chunk: 0 }),
        })
    }
    /// Change the aggregate cap (query backoff); takes effect on the next chunk.
    pub fn set_rate(&self, rate: u64) {
        self.rate.store(rate, Ordering::Relaxed);
    }
    pub fn rate(&self) -> u64 {
        self.rate.load(Ordering::Relaxed)
    }
    /// Charge `bytes` received at `now`; returns how long the caller must wait.
    pub fn reserve(&self, bytes: u64, now: Instant) -> Duration {
        let rate = self.rate.load(Ordering::Relaxed);
        if rate == 0 {
            return Duration::ZERO;
        }
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        state.largest_chunk = state.largest_chunk.max(bytes);
        let burst = Duration::from_secs_f64(state.largest_chunk as f64 / rate as f64);
        let floor = now.checked_sub(burst).unwrap_or(now);
        state.next = state.next.max(floor) + Duration::from_secs_f64(bytes as f64 / rate as f64);
        state.next.saturating_duration_since(now)
    }
}

struct HydratePacing {
    /// Per-object: zero once a foreground query joins this download (it then
    /// runs unpaced); otherwise the object's guaranteed share, for deadlines.
    rate: AtomicU64,
    foreground: tokio::sync::Notify,
    bucket: Arc<HydrateBucket>,
}
impl HydratePacing {
    fn new(share: u64, bucket: Arc<HydrateBucket>) -> Self {
        Self { rate: AtomicU64::new(share), foreground: tokio::sync::Notify::new(), bucket }
    }
    async fn pace(&self, bytes: usize) {
        let wake = self.foreground.notified();
        if self.rate.load(Ordering::Relaxed) > 0 {
            let delay = self.bucket.reserve(bytes as u64, pacing_now());
            if !delay.is_zero() {
                tokio::select! {
                    _ = tokio::time::sleep(delay) => {},
                    _ = wake => {},
                }
            }
        }
    }
}

tokio::task_local! { static HYDRATE_RATE: Arc<HydratePacing>; }

tokio::task_local! {
    /// NAN-3272: the cold-byte budget of the durable job whose reads run in
    /// this scope. NAN-3644: it is the job's heavy-read threshold (above it
    /// the job queues for the cell's heavy cold-read slots, taking all of
    /// them) and the job is held to the durable ceiling, not the interactive
    /// one.
    static DURABLE_JOB_COLD_BYTES: u64;
}

/// NAN-3272: run `work` (one durable job attempt) with `budget_bytes` as the
/// per-query heavy-read threshold of every read inside it. The interactive
/// threshold stays the floor; [`ReaderObjectCache::durable_cold_ceiling`]
/// bounds a lease.
pub async fn with_durable_job_cold_budget<F: std::future::Future>(budget_bytes: u64, work: F) -> F::Output {
    DURABLE_JOB_COLD_BYTES.scope(budget_bytes, Box::pin(work)).await
}

/// Charge `bytes` just received to the current background hydration's
/// bucket, if any (sources call this per chunk; foreground reads are free).
pub(crate) async fn pace_background(bytes: usize) {
    if let Ok(pacing) = HYDRATE_RATE.try_with(Arc::clone) {
        pacing.pace(bytes).await;
    }
}

/// The pacing clock: Tokio's, so the bucket and the `tokio::time::sleep` it
/// prescribes read the same time. Identical to `Instant::now()` in
/// production; under a paused test runtime both are virtual (NAN-3866: the
/// rate labs measured wall time and flaked under CPU load).
fn pacing_now() -> Instant {
    tokio::time::Instant::now().into_std()
}

/// One background download paced by its own bucket at `rate`.
pub async fn background_hydrate<T>(rate: u64, work: impl std::future::Future<Output = T>) -> T {
    background_hydrate_shared(HydrateBucket::new(rate), rate, work).await
}

/// One background download charged to a `bucket` shared with its siblings.
/// `share` is the slowest rate this object is guaranteed (cap / concurrency /
/// backoff); it only extends the fetch deadline.
pub async fn background_hydrate_shared<T>(
    bucket: Arc<HydrateBucket>,
    share: u64,
    work: impl std::future::Future<Output = T>,
) -> T {
    HYDRATE_RATE.scope(Arc::new(HydratePacing::new(share.max(1), bucket)), work).await
}

/// NAN-4591: run `work` as unpaced background maintenance (the identity
/// observation backfill): its cache reads yield to foreground reads like
/// hot-window hydration (no admission while a search waits out saturation,
/// never into the cold-read reserve, no saturation wait of its own), and
/// its fetch deadline assumes the foreground floor rate.
pub async fn background_maintenance<T>(work: impl std::future::Future<Output = T>) -> T {
    background_hydrate_shared(HydrateBucket::new(0), FOREGROUND_FETCH_FLOOR_BYTES_PER_SECOND, work).await
}

/// NAN-3644: the slowest foreground cold read the fetch deadline still
/// allows. A lease is fetched as a whole under one deadline; a flat 60 s
/// failed every lease over ~60 s of bandwidth (a cell whose data volume is
/// throttled to 75 MiB/s could not lease ~4.4 GiB at all), so a large read
/// was refused by its own size after all. The deadline now grows with the
/// lease at this floor rate; a stuck fetch is still cut, and the request's
/// own deadline and cancellation still end it sooner.
pub const FOREGROUND_FETCH_FLOOR_BYTES_PER_SECOND: u64 = 16 * 1024 * 1024;

/// NAN-3644: the [`ReaderObjectCache::scratch_dir`] batched cold reads
/// spool into; cleared when the cache opens.
pub const COLD_BATCH_SCRATCH: &str = "cold-batches";

fn fetch_deadline(base: Duration, bytes: u64) -> Duration {
    HYDRATE_RATE.try_with(|rate| {
        let rate = rate.rate.load(Ordering::Relaxed);
        if rate == 0 { base } else { base.saturating_add(Duration::from_secs((bytes / rate).saturating_add(1))) }
    }).unwrap_or_else(|_| base.saturating_add(Duration::from_secs(bytes / FOREGROUND_FETCH_FLOOR_BYTES_PER_SECOND)))
}

pub const READER_CACHE_MODE_ENV: &str = "NANO_LAKE_READER_CACHE_MODE";
pub const READER_CACHE_DIR_ENV: &str = "NANO_LAKE_READER_CACHE_DIR";
pub const READER_CACHE_BYTES_ENV: &str = "NANO_LAKE_READER_CACHE_BYTES";
pub const READER_CACHE_QUERY_BYTES_ENV: &str = "NANO_LAKE_READER_CACHE_QUERY_BYTES";
pub const READER_CACHE_FETCH_CONCURRENCY_ENV: &str = "NANO_LAKE_READER_CACHE_FETCH_CONCURRENCY";
pub const READER_CACHE_FETCH_TIMEOUT_ENV: &str = "NANO_LAKE_READER_CACHE_FETCH_TIMEOUT_SECONDS";
/// NAN-3644: how many heavy cold reads (a lease whose uncached bytes exceed
/// the per-query threshold `query_max_bytes`) one reader runs at once.
/// Further heavy reads queue for a slot instead of being refused.
pub const READER_COLD_HEAVY_CONCURRENCY_ENV: &str = "NANO_LAKE_READER_COLD_HEAVY_CONCURRENCY";
/// One at a time: the safest default. Heavy reads compete for the same R2
/// bandwidth and cache volume, so two of them at once finish no sooner than
/// one after the other, and a single slot leaves the largest interactive
/// ceiling (see [`ReaderObjectCache::interactive_cold_ceiling`]).
pub const DEFAULT_COLD_HEAVY_CONCURRENCY: usize = 1;
const MAX_COLD_HEAVY_CONCURRENCY: usize = 16;

/// The configured heavy cold-read concurrency: `1..=16`, default 1. An
/// invalid value keeps the default (logged), never fails the reader.
pub fn cold_heavy_concurrency_from_env() -> usize {
    parse_cold_heavy_concurrency(std::env::var(READER_COLD_HEAVY_CONCURRENCY_ENV).ok().as_deref())
}

fn parse_cold_heavy_concurrency(value: Option<&str>) -> usize {
    match value.map(str::trim).filter(|value| !value.is_empty()) {
        None => DEFAULT_COLD_HEAVY_CONCURRENCY,
        Some(raw) => match raw.parse::<usize>() {
            Ok(n) if (1..=MAX_COLD_HEAVY_CONCURRENCY).contains(&n) => n,
            _ => {
                tracing::warn!(value = raw, default = DEFAULT_COLD_HEAVY_CONCURRENCY,
                    "{READER_COLD_HEAVY_CONCURRENCY_ENV} must be 1..={MAX_COLD_HEAVY_CONCURRENCY}; using the default");
                DEFAULT_COLD_HEAVY_CONCURRENCY
            }
        },
    }
}

/// NAN-3147: hot-window volume grant granularity for downloads.
const HOT_WINDOW_FENCE_SLAB_BYTES: u64 = 16 * 1024 * 1024;

/// Per-query heavy-read threshold `W_q` (design §8). NAN-3644: a lease over
/// it queues for a heavy slot; it is no longer a refusal.
const DEFAULT_QUERY_MAX_BYTES: u64 = 512 * 1024 * 1024;
const DEFAULT_FETCH_CONCURRENCY: usize = 16;

/// NAN-4277: how many of `fetch_concurrency` download slots background
/// downloads (durable jobs, hot-window hydration) may hold at once: all but a
/// quarter (at least one) kept for interactive reads; 16 → 12.
///
/// All downloads used to share one FIFO queue. On a large hosted tenant (2026-10-20)
/// a 30 d durable `stats` job queued one 1,561-object / 33.9 GB lease, and for
/// the 8.5 min it took every interactive cold read waited behind it: 395-byte
/// objects took 21 s, a 1 h `| head 50` spent 45 s in file preparation and was
/// escalated at the request deadline. The total stays `fetch_concurrency`
/// (same R2 requests and bandwidth); only the order changes.
fn background_fetch_slots(fetch_concurrency: usize) -> usize {
    if fetch_concurrency <= 1 {
        return fetch_concurrency;
    }
    fetch_concurrency - (fetch_concurrency / 4).max(1)
}

/// NAN-4290: how many of one lease's `misses` downloads it submits at once.
///
/// An interactive lease submits every miss (its downloads take the free
/// slots first, NAN-4277). A background lease (a durable job's, or hot-window
/// hydration's) keeps at most [`background_fetch_slots`] submitted and adds
/// the next as one lands. The background slots are FIFO: a 30 d job used to
/// queue its whole 1,561-object lease at once, and a 1 h job's few objects,
/// also a background read, then waited behind all of them. Bounded per lease,
/// concurrent jobs' downloads interleave: the small job waits for at most one
/// round of the big lease's downloads. A single lease still fills every
/// background slot, so its throughput, R2 requests and bytes are unchanged.
fn lease_outstanding_fetches(fetch_concurrency: usize, misses: usize) -> usize {
    let background = HYDRATE_RATE.try_with(|_| ()).is_ok() || DURABLE_JOB_COLD_BYTES.try_with(|_| ()).is_ok();
    let bound = if background { background_fetch_slots(fetch_concurrency) } else { misses };
    bound.max(1)
}
const DEFAULT_FETCH_DEADLINE: Duration = Duration::from_secs(30);
/// NAN-4138: how long a foreground lease waits for cache or hot-window
/// volume capacity before it gives up with `Saturated`. Saturation is
/// transient (leases end; the volume accountant re-walks every 30 s and sees
/// evictions; hourly merges release their scratch), so a read waits it out
/// instead of failing the search (NAN-3644: never refuse cold reads). The
/// wait stages nothing: no reservation, temp file or buffer is held while it
/// sleeps, so it cannot grow memory or the volume. The request's own
/// deadline and cancellation still end it sooner.
pub const SATURATION_WAIT_INTERACTIVE: Duration = Duration::from_secs(120);
/// NAN-4138: a durable job's saturation wait (it has no interactive caller).
pub const SATURATION_WAIT_DURABLE: Duration = Duration::from_secs(600);
const SATURATION_BACKOFF_FIRST: Duration = Duration::from_millis(100);
const SATURATION_BACKOFF_MAX: Duration = Duration::from_secs(2);
/// One in this many trusted hits is re-hashed to catch silent bit-rot.
const REHASH_SAMPLE: u64 = 64;
/// NAN-3403: an object this process hashed less than this long ago is not
/// re-sampled. The 1-in-64 sample was per *hit*, and background passes
/// (arrival prewarm ~5x/min, hot-window hydration every 30 s) hit every
/// hot-window object 2-3 times each: the whole window was re-hashed every
/// few minutes (~1.2 GB/min of reads on an idle load-test tenant query role, all of
/// it evicting the page cache searches need). `0` restores per-hit sampling.
pub const READER_SCRUB_MIN_INTERVAL_ENV: &str = "NANO_LAKE_READER_SCRUB_MIN_INTERVAL_SECONDS";
const DEFAULT_SCRUB_MIN_INTERVAL_SECONDS: i64 = 3600;
/// NAN-3403: verification hashes read with `O_DIRECT` so they neither evict
/// nor pollute the page cache searches read through (falls back to buffered
/// reads where the filesystem refuses it). `0` restores buffered reads.
pub const READER_VERIFY_DIRECT_IO_ENV: &str = "NANO_LAKE_READER_VERIFY_DIRECT_IO";

fn scrub_min_interval_seconds() -> i64 {
    static INTERVAL: std::sync::OnceLock<i64> = std::sync::OnceLock::new();
    *INTERVAL.get_or_init(|| parse_scrub_min_interval(std::env::var(READER_SCRUB_MIN_INTERVAL_ENV).ok().as_deref()))
}

fn parse_scrub_min_interval(value: Option<&str>) -> i64 {
    value.and_then(|value| value.trim().parse::<i64>().ok()).filter(|seconds| *seconds >= 0)
        .unwrap_or(DEFAULT_SCRUB_MIN_INTERVAL_SECONDS)
}

fn verify_direct_io() -> bool {
    static DIRECT: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *DIRECT.get_or_init(|| std::env::var(READER_VERIFY_DIRECT_IO_ENV).ok().as_deref() != Some("0"))
}

/// Is a bit-rot sample of an object this process last hashed at
/// `verified_s` due at `now_s`? Never-hashed objects (indexed from disk) and
/// an unknown clock are always due.
fn scrub_due(verified_s: Option<i64>, now_s: Option<i64>, interval_s: i64) -> bool {
    match (verified_s, now_s) {
        (Some(verified), Some(now)) => interval_s == 0 || now.saturating_sub(verified) >= interval_s,
        _ => true,
    }
}

fn unix_now_seconds() -> Option<i64> {
    SystemTime::now().duration_since(UNIX_EPOCH).ok().and_then(|now| i64::try_from(now.as_secs()).ok())
}

/// SHA-256 of a cached object for verification (NAN-3403): `O_DIRECT`
/// reads, so a re-hash neither evicts other pages nor leaves this file's
/// pages charged to the role. Any refusal falls back to a buffered read.
pub(crate) fn verify_sha256(path: &Path) -> std::io::Result<String> {
    #[cfg(target_os = "linux")]
    if verify_direct_io() {
        if let Some(digest) = sha256_direct(path)? {
            return Ok(digest);
        }
    }
    sha256_buffered(path)
}

fn sha256_buffered(path: &Path) -> std::io::Result<String> {
    use std::io::Read;
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0_u8; 1024 * 1024];
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 { break; }
        hasher.update(&buffer[..count]);
    }
    Ok(hex::encode(hasher.finalize()))
}

/// `Ok(None)`: the filesystem refused direct I/O (open or an unaligned
/// read); the caller hashes buffered instead.
#[cfg(target_os = "linux")]
fn sha256_direct(path: &Path) -> std::io::Result<Option<String>> {
    use std::io::Read;
    use std::os::unix::fs::OpenOptionsExt;
    const ALIGN: usize = 4096;
    const CHUNK: usize = 1024 * 1024;
    let mut file = match OpenOptions::new().read(true).custom_flags(libc::O_DIRECT).open(path) {
        Ok(file) => file,
        Err(error) if error.raw_os_error() == Some(libc::EINVAL) => return Ok(None),
        Err(error) => return Err(error),
    };
    let size = file.metadata()?.len();
    let mut storage = vec![0_u8; CHUNK + ALIGN];
    let offset = storage.as_ptr().align_offset(ALIGN);
    let buffer = &mut storage[offset..offset + CHUNK];
    let mut hasher = Sha256::new();
    let mut read = 0_u64;
    while read < size {
        let count = match file.read(buffer) {
            Ok(0) => break,
            Ok(count) => count,
            Err(error) if error.raw_os_error() == Some(libc::EINVAL) => return Ok(None),
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        };
        hasher.update(&buffer[..count]);
        read += count as u64;
    }
    if read != size {
        // Truncated under us: the buffered path reports what is there.
        return Ok(None);
    }
    Ok(Some(hex::encode(hasher.finalize())))
}
/// A filesystem with second-granularity mtime can report the same stamp for
/// two writes in one tick. Keep hashing until that tick is safely behind us.
const STAMP_COLLISION_WINDOW_SECONDS: i64 = 2;
const MARKER_FILE: &str = "reader-cache.json";
const MARKER_SCHEMA: u32 = 1;
const TEMP_PREFIX: &str = ".fetch-";
const DOWNLOAD_CHUNK_BYTES: usize = 4 * 1024 * 1024;
const OBJECT_MODE: u32 = 0o444;

const SATURATED_TEXT: &str = "reader cache is saturated by leased or protected objects";

/// NAN-4138: whether stringified error text is a [`ReaderCacheError::Saturated`]
/// (transient: callers map it to a retryable 503, never a 500).
pub fn text_is_saturation(text: &str) -> bool {
    text.contains(SATURATED_TEXT)
}

#[derive(thiserror::Error, Debug)]
pub enum ReaderCacheError {
    #[error("reader cache configuration is invalid: {0}")]
    InvalidConfig(String),
    #[error("reader cache object is outside the tenant's authority: {0}")]
    OutsideTenant(String),
    /// NAN-3644: the OOM safety net, not a cold-data refusal. One pass of
    /// this query needs more uncached bytes than the reader can stage at once
    /// (`ceiling_bytes`, derived from the cache size; see
    /// [`ReaderObjectCache::interactive_cold_ceiling`]). `background_bytes`
    /// is what a durable job may stage.
    #[error(
        "query needs {required_bytes} uncached bytes in one pass, over the {ceiling_bytes} bytes \
         this reader can stage at once"
    )]
    ScanTooLarge { required_bytes: u64, ceiling_bytes: u64, background_bytes: u64 },
    #[error("{SATURATED_TEXT}; {needed_bytes} bytes could not be admitted")]
    Saturated { needed_bytes: u64 },
    #[error("cold object fetch exceeded its deadline")]
    FetchTimeout,
    #[error("cold object fetch failed: {0}")]
    Unavailable(String),
    #[error("reader cache object failed its signed length or SHA-256 fence: {0}")]
    Integrity(String),
    #[error("reader cache I/O failed: {0}")]
    Io(#[from] std::io::Error),
    /// A caller broke the bounded-mode contract (a plan naming objects with
    /// no cache configured, or a lease that does not cover the plan). Never
    /// retryable: executing anyway could read an absent or unleased path.
    #[error("reader cache invariant violated: {0}")]
    Invariant(String),
}

impl ReaderCacheError {
    /// Whether retrying the same query later can succeed without changing it.
    pub fn retryable(&self) -> bool {
        matches!(
            self,
            Self::Saturated { .. } | Self::FetchTimeout | Self::Unavailable(_)
        )
    }

    pub fn reason(&self) -> &'static str {
        match self {
            Self::InvalidConfig(_) => "reader_cache_invalid_config",
            Self::OutsideTenant(_) => "reader_cache_outside_tenant",
            Self::ScanTooLarge { .. } => "cold_scan_too_large",
            Self::Saturated { .. } => "reader_cache_saturated",
            Self::FetchTimeout => "reader_cold_fetch_timeout",
            Self::Unavailable(_) => "reader_cold_fetch_unavailable",
            Self::Integrity(_) => "reader_object_integrity",
            Self::Io(_) => "reader_cache_io",
            Self::Invariant(_) => "reader_cache_invariant",
        }
    }

    /// Single-flight waiters each receive their own copy of a shared outcome.
    fn duplicate(&self) -> Self {
        match self {
            Self::InvalidConfig(value) => Self::InvalidConfig(value.clone()),
            Self::OutsideTenant(value) => Self::OutsideTenant(value.clone()),
            Self::ScanTooLarge { required_bytes, ceiling_bytes, background_bytes } => Self::ScanTooLarge {
                required_bytes: *required_bytes,
                ceiling_bytes: *ceiling_bytes,
                background_bytes: *background_bytes,
            },
            Self::Saturated { needed_bytes } => Self::Saturated {
                needed_bytes: *needed_bytes,
            },
            Self::FetchTimeout => Self::FetchTimeout,
            Self::Unavailable(value) => Self::Unavailable(value.clone()),
            Self::Integrity(value) => Self::Integrity(value.clone()),
            Self::Io(error) => Self::Io(std::io::Error::new(error.kind(), error.to_string())),
            Self::Invariant(value) => Self::Invariant(value.clone()),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReaderObjectCacheSettings {
    pub root: PathBuf,
    pub max_bytes: u64,
    pub query_max_bytes: u64,
    pub fetch_concurrency: usize,
    pub fetch_deadline: Duration,
}

impl ReaderObjectCacheSettings {
    /// `Ok(None)` when the mode is unset or `full` (the flag defaults off).
    /// Any other mode, or `bounded` without a valid dir/budget, is an error.
    pub fn from_env() -> Result<Option<Self>, ReaderCacheError> {
        Self::from_lookup(|name| std::env::var(name).ok())
    }

    /// [`Self::from_env`] over an arbitrary variable source (tests, renderers).
    pub fn from_lookup(
        lookup: impl Fn(&str) -> Option<String>,
    ) -> Result<Option<Self>, ReaderCacheError> {
        let get = |name: &str| {
            lookup(name)
                .map(|value| value.trim().to_string())
                .filter(|value| !value.is_empty())
        };
        match get(READER_CACHE_MODE_ENV).as_deref() {
            None | Some("full") => return Ok(None),
            Some("bounded") => {}
            Some(_) => {
                return Err(ReaderCacheError::InvalidConfig(format!(
                    "{READER_CACHE_MODE_ENV} must be full or bounded"
                )))
            }
        }
        let root = get(READER_CACHE_DIR_ENV).map(PathBuf::from).ok_or_else(|| {
            ReaderCacheError::InvalidConfig(format!(
                "{READER_CACHE_DIR_ENV} is required in bounded mode"
            ))
        })?;
        let positive = |name: &str, default: Option<u64>| match (get(name), default) {
            (None, Some(default)) => Ok(default),
            (value, _) => value
                .and_then(|value| value.parse::<u64>().ok())
                .filter(|value| *value > 0)
                .ok_or_else(|| {
                    ReaderCacheError::InvalidConfig(format!("{name} must be a positive integer"))
                }),
        };
        let settings = Self {
            root,
            max_bytes: positive(READER_CACHE_BYTES_ENV, None)?,
            query_max_bytes: positive(READER_CACHE_QUERY_BYTES_ENV, Some(DEFAULT_QUERY_MAX_BYTES))?,
            fetch_concurrency: usize::try_from(positive(
                READER_CACHE_FETCH_CONCURRENCY_ENV,
                Some(DEFAULT_FETCH_CONCURRENCY as u64),
            )?)
            .map_err(|_| {
                ReaderCacheError::InvalidConfig(format!(
                    "{READER_CACHE_FETCH_CONCURRENCY_ENV} is too large"
                ))
            })?,
            fetch_deadline: Duration::from_secs(positive(
                READER_CACHE_FETCH_TIMEOUT_ENV,
                Some(DEFAULT_FETCH_DEADLINE.as_secs()),
            )?),
        };
        settings.validate()?;
        Ok(Some(settings))
    }

    fn validate(&self) -> Result<(), ReaderCacheError> {
        if !self.root.is_absolute() {
            return Err(ReaderCacheError::InvalidConfig(format!(
                "{READER_CACHE_DIR_ENV} must be an absolute path"
            )));
        }
        if self.max_bytes == 0
            || self.query_max_bytes == 0
            || self.fetch_concurrency == 0
            || self.fetch_concurrency > tokio::sync::Semaphore::MAX_PERMITS
            || self.fetch_deadline.is_zero()
        {
            return Err(ReaderCacheError::InvalidConfig(
                "reader cache budgets, concurrency and deadline must be positive".to_string(),
            ));
        }
        Ok(())
    }
}

fn tenant_directory(root: &Path, tenant_id: &str) -> PathBuf {
    root.join(format!("tenant-{tenant_id}"))
}

/// Canonical on-disk path of a verified object. chDB reads exactly this path.
/// `sha256` must be 64 lowercase hex characters; `ensure_local` validates it.
pub fn object_path(root: &Path, tenant_id: &str, sha256: &str) -> PathBuf {
    tenant_directory(root, tenant_id)
        .join("objects")
        .join(format!("{sha256}.bin"))
}

/// One immutable object named by the signed generation's object-stamp ledger.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReaderObjectRef {
    /// Independently signed slice; None means the whole object.
    pub range: Option<std::ops::Range<u64>>,
    pub source_uri: String,
    pub sha256: String,
    pub size_bytes: u64,
}

#[async_trait::async_trait]
pub trait ReaderObjectSource: Send + Sync {
    /// Stream `range` when present, otherwise the whole object, into `sink`. Untrusted:
    /// the cache verifies length and SHA-256 itself.
    async fn stream_object(
        &self,
        object: &ReaderObjectRef,
        sink: &mut (dyn for<'b> FnMut(&'b [u8]) -> anyhow::Result<()> + Send),
    ) -> anyhow::Result<()>;
}

/// Plain ranged GET of `0..size_bytes` against the tenant bucket. The bounded
/// range avoids OpenDAL's implicit HEAD, so a miss costs one Class B op
/// (design §4); the SHA-256 fence, not the ETag, is the integrity check.
pub struct R2ReaderObjectSource {
    operator: Operator,
    bucket: String,
}

impl R2ReaderObjectSource {
    /// `operator` must be scoped to `bucket` and carry `crate::r2_ops::layer()`.
    pub fn new(operator: Operator, bucket: impl Into<String>) -> Self {
        Self {
            operator,
            bucket: bucket.into(),
        }
    }

    /// Build over the tenant's read-only `NANO_LAKE_SHARED_R2_READ_*` secret,
    /// failing closed if the injected access key is not the expected identity.
    pub fn from_shared_read_env(bucket: &str, expected_access_key_id: &str) -> anyhow::Result<Self> {
        Ok(Self::new(
            shared_r2_operator(bucket, expected_access_key_id)?,
            bucket,
        ))
    }
}

#[async_trait::async_trait]
impl ReaderObjectSource for R2ReaderObjectSource {
    async fn stream_object(
        &self,
        object: &ReaderObjectRef,
        sink: &mut (dyn for<'b> FnMut(&'b [u8]) -> anyhow::Result<()> + Send),
    ) -> anyhow::Result<()> {
        let (bucket, key) = parse_s3_uri(&object.source_uri)?;
        if bucket != self.bucket {
            anyhow::bail!("reader object is outside the configured R2 bucket");
        }
        if object.size_bytes == 0 {
            return Ok(());
        }
        let mut stream = self
            .operator
            .reader_with(key)
            .chunk(DOWNLOAD_CHUNK_BYTES)
            .await
            .with_context(|| format!("open reader object {}", object.source_uri))?
            .into_bytes_stream(object.range.clone().unwrap_or(0..object.size_bytes))
            .await
            .context("stream reader object")?;
        while let Some(chunk) = stream.try_next().await.context("read reader object")? {
            pace_background(chunk.len()).await;
            sink(&chunk[..])?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize)]
pub struct ReaderCacheStats {
    pub objects: usize,
    pub stored_bytes: u64,
    pub max_bytes: u64,
    pub hits: u64,
    pub misses: u64,
    pub fetched_bytes: u64,
    pub integrity_failures: u64,
    pub evictions: u64,
    /// Hits whose SHA-256 was recomputed (sampled, first sight, guard drift).
    pub rehashes: u64,
    /// Cumulative per-file stream/disk time, excluding inline SHA-256 work.
    pub fetch_ns: u64,
    /// Cumulative SHA-256 time (downloads plus sampled cache rehashes).
    pub verify_ns: u64,
}

/// The trust guard of a cached object: identity, size, mode and mtime.
///
/// ctime is deliberately NOT part of it (NAN-2996). Every lease hard-links
/// each hit into `pins/<lease>/` and unlinks it on release; both change the
/// inode ctime (link count). With ctime in the guard every leased hit looked
/// tampered on its next use and was re-hashed with SHA-256 on every query,
/// and every progressive chunk. The guard now matches gen1's generation
/// ledger (`generation.rs`) and the hot-tail cache stamp, which have never
/// included ctime; the 1-in-[`REHASH_SAMPLE`] re-hash still catches bit-rot.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct FileStamp {
    dev: u64,
    inode: u64,
    bytes: u64,
    mode: u32,
    modified: (i64, i64),
}

impl FileStamp {
    fn read(path: &Path) -> std::io::Result<Self> {
        let metadata = std::fs::symlink_metadata(path)?;
        if !metadata.is_file() {
            return Err(std::io::Error::other("reader cache object is not a regular file"));
        }
        Ok(Self {
            dev: metadata.dev(),
            inode: metadata.ino(),
            bytes: metadata.len(),
            mode: metadata.mode() & 0o7777,
            modified: (metadata.mtime(), metadata.mtime_nsec()),
        })
    }

    /// A write in the current mtime tick may be indistinguishable from the
    /// recorded stamp on a coarse-timestamp filesystem: keep hashing until
    /// that tick is safely behind us.
    fn modify_time_may_collide(self, now_seconds: Option<i64>) -> bool {
        let Some(now_seconds) = now_seconds else {
            return true;
        };
        now_seconds.saturating_sub(self.modified.0) <= STAMP_COLLISION_WINDOW_SECONDS
    }
}

#[derive(Debug)]
struct Entry {
    stamp: FileStamp,
    /// LRU clock at the last lease release (0 = indexed at open).
    last_access: u64,
    hits: u64,
    /// NAN-3403: Unix seconds when this process last hashed the object
    /// (admission, inline re-hash or scrub); `None` when only indexed from
    /// disk. Bounds the bit-rot sample to one per [`scrub_min_interval_seconds`].
    verified_s: Option<i64>,
}

type FetchFuture = Shared<BoxFuture<'static, Result<(), Arc<ReaderCacheError>>>>;

#[derive(Default)]
struct State {
    entries: HashMap<String, Entry>,
    clock: u64,
    protected: HashSet<String>,
    hot: HashMap<String, i64>,
    /// Objects an in-progress `ensure_local` in this process needs.
    holds: HashMap<String, usize>,
    /// NAN-3165: objects held by a completed, live lease of this process
    /// (verified when that lease was taken), by lease count.
    live: HashMap<String, usize>,
    inflight: HashMap<String, FetchFuture>,
    background_rates: HashMap<String, Arc<HydratePacing>>,
    /// NAN-4277: in-flight background downloads (a durable job's or the
    /// hot window's) still allowed to wait for a background download slot.
    /// A foreground read that needs the same object promotes it.
    background_lanes: HashMap<String, Arc<tokio::sync::Notify>>,
    /// Bytes of downloads in flight in this process.
    reserved: u64,
    /// Sampled bit-rot re-hashes deferred off the lease path (digests).
    scrub: BTreeSet<String>,
}

impl State {
    fn tick(&mut self) -> u64 {
        self.clock += 1;
        self.clock
    }

    /// NAN-4591: bytes of resident hot-window objects.
    fn hot_bytes(&self) -> u64 {
        self.entries
            .iter()
            .filter(|(digest, _)| self.hot.contains_key(*digest))
            .map(|(_, entry)| entry.stamp.bytes)
            .sum()
    }

    fn stored_bytes(&self) -> u64 {
        let mut inodes = BTreeSet::new();
        self.entries
            .values()
            .filter(|entry| inodes.insert((entry.stamp.dev, entry.stamp.inode)))
            .map(|entry| entry.stamp.bytes)
            .sum()
    }
}

#[derive(Default)]
struct Counters {
    hits: AtomicU64,
    misses: AtomicU64,
    fetched_bytes: AtomicU64,
    integrity_failures: AtomicU64,
    evictions: AtomicU64,
    rehashes: AtomicU64,
    fetch_ns: AtomicU64,
    verify_ns: AtomicU64,
}

#[derive(serde::Serialize, serde::Deserialize, PartialEq, Eq)]
struct Marker {
    schema: u32,
    tenant_id: String,
    bucket: String,
    key_prefix: String,
}

struct Inner {
    settings: ReaderObjectCacheSettings,
    tenant_id: String,
    bucket: String,
    key_prefix: String,
    objects: PathBuf,
    pins: PathBuf,
    /// NAN-4222: `reads/<sha256>.bin`, one stable hard link per verified
    /// object that native readers open (see [`ReaderCacheLease::pinned_path`]).
    reads: PathBuf,
    lock_path: PathBuf,
    source: Arc<dyn ReaderObjectSource>,
    permits: tokio::sync::Semaphore,
    /// NAN-4277: the share of `permits` that background downloads (durable
    /// jobs, hot-window hydration) may hold at once, see
    /// [`background_fetch_slots`]. A background download takes one of these
    /// before one of `permits`, so the rest of `permits` always stays free
    /// for interactive reads.
    background_permits: tokio::sync::Semaphore,
    /// NAN-3644: the heavy cold-read slots (see
    /// [`READER_COLD_HEAVY_CONCURRENCY_ENV`]); `heavy_slots` is their count.
    heavy: Arc<tokio::sync::Semaphore>,
    heavy_slots: std::sync::atomic::AtomicUsize,
    state: Mutex<State>,
    counters: Counters,
    hot_capacity: Mutex<Option<crate::local_hot_window::Settings>>,
    /// Bytes charged per hot-window volume grant during a download.
    fence_slab_bytes: AtomicU64,
    /// A background scrub of `State::scrub` is running.
    scrubbing: std::sync::atomic::AtomicBool,
    /// NAN-4138: test override of the saturation wait, in ms
    /// (`u64::MAX`: the interactive/durable defaults).
    saturation_wait_ms: AtomicU64,
    /// NAN-4591: foreground reads waiting out saturation right now. While
    /// any waits, background hydration admits nothing (it defers and its
    /// pass retries later), so freed capacity goes to the search.
    foreground_waiting: std::sync::atomic::AtomicUsize,
    /// NAN-4591: (when, bytes) of objects this process deleted, which the
    /// volume accountant may not have walked yet (see
    /// [`crate::local_hot_window::Settings::capacity_credited`]).
    unwalked_evictions: Mutex<std::collections::VecDeque<(Instant, u64)>>,
    /// Test override of the cold-read reserve (the large tenant's one-fifth regime needs
    /// a cache of at least 5 GiB otherwise).
    #[cfg(test)]
    cold_reserve_override: Mutex<Option<u64>>,
}

#[derive(Clone)]
pub struct ReaderObjectCache {
    inner: Arc<Inner>,
}

impl std::fmt::Debug for ReaderObjectCache {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ReaderObjectCache")
            .field("tenant_id", &self.inner.tenant_id)
            .field("stats", &self.stats())
            .finish_non_exhaustive()
    }
}

/// The one tenant-id rule for the reader-cache namespace: a single safe path
/// component (`tenant-{id}`) with no brace-spec characters. Shared with the
/// config loader's `BoundedReaderCacheLayout` so both sides agree exactly.
pub fn valid_tenant_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

fn valid_token(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        && !value.starts_with('.')
}

fn io_other(message: impl Into<String>) -> ReaderCacheError {
    ReaderCacheError::Io(std::io::Error::other(message.into()))
}

/// The hot-window volume write fence for `growth` bytes. Reaching the volume
/// target is `Saturated`; an unavailable accountant (NAN-3139: the jailed
/// query process cannot open sockets) degrades to no fence, logged.
fn volume_fence(
    policy: &crate::local_hot_window::Settings,
    growth: u64,
) -> Result<Option<nanosiem_lake_cell::volume_usage::WriteGuard>, ReaderCacheError> {
    use nanosiem_lake_cell::volume_usage;
    match volume_usage::reserve_write(&volume_usage::volume_root(&policy.root), policy.max_bytes, growth) {
        Ok(guard) => Ok(Some(guard)),
        Err(error) if volume_usage::is_limit_reached(&error) => {
            Err(ReaderCacheError::Saturated { needed_bytes: growth })
        }
        Err(error) => {
            crate::local_hot_window::warn_accounting_unavailable(&error);
            Ok(None)
        }
    }
}

async fn blocking<T: Send + 'static>(
    operation: impl FnOnce() -> Result<T, ReaderCacheError> + Send + 'static,
) -> Result<T, ReaderCacheError> {
    tokio::task::spawn_blocking(operation)
        .await
        .map_err(|error| io_other(format!("reader cache blocking task failed: {error}")))?
}

impl ReaderObjectCache {
    pub fn set_hot_capacity(&self, settings: crate::local_hot_window::Settings) {
        *self.inner.hot_capacity.lock().unwrap_or_else(|e| e.into_inner()) = Some(settings);
    }

    /// Reconcile even when the window is already warm and no download occurs.
    pub async fn trim_pressure(&self) -> Result<(), ReaderCacheError> {
        let inner = self.inner.clone();
        // Runs on a blocking thread, outside any hydration scope: foreground
        // semantics, so it also evicts cold objects ahead until half the
        // cold-read reserve is free (NAN-4591). Hot objects go only when the
        // volume itself needs the room.
        blocking(move || {
            match inner.reserve(0) {
                Ok(reservation) => drop(reservation),
                Err(ReaderCacheError::Saturated { .. }) => {}, // pinned objects cannot be reclaimed
                Err(error) => return Err(error),
            }
            Ok(())
        }).await
    }

    pub fn query_max_bytes(&self) -> u64 { self.inner.settings.query_max_bytes }

    /// NAN-4591: the share of this cache the hot window leaves to foreground
    /// cold reads ([`crate::local_hot_window::cold_read_reserve`]).
    pub fn cold_read_reserve(&self) -> u64 { self.inner.cold_read_reserve() }

    /// NAN-4591: bytes this process evicted that the volume accountant may
    /// not have walked yet.
    pub fn eviction_credit(&self) -> u64 { self.inner.eviction_credit() }

    /// NAN-4591: bytes of downloads (and scratch) admitted but not yet
    /// indexed in this process.
    pub fn in_flight_bytes(&self) -> u64 { self.inner.state().reserved }

    /// The heavy-read threshold of the current query: the interactive
    /// `query_max_bytes`, or a durable job's own (larger) budget inside
    /// [`with_durable_job_cold_budget`] (NAN-3272). NAN-3644: a lease whose
    /// uncached bytes exceed it queues for a heavy slot; it is never refused
    /// for crossing it.
    pub fn query_cold_budget(&self) -> u64 {
        let interactive = self.inner.settings.query_max_bytes;
        DURABLE_JOB_COLD_BYTES.try_with(|bytes| (*bytes).max(interactive)).unwrap_or(interactive)
    }

    /// NAN-3644: heavy cold reads this reader runs at once.
    pub fn cold_heavy_concurrency(&self) -> usize {
        self.inner.heavy_slots.load(Ordering::Acquire)
    }

    /// NAN-3644: change the heavy cold-read concurrency (boot override,
    /// tests). Slots already held stay valid; shrinking takes effect as they
    /// are returned.
    pub fn set_cold_heavy_concurrency(&self, slots: usize) {
        let slots = slots.clamp(1, MAX_COLD_HEAVY_CONCURRENCY);
        let previous = self.inner.heavy_slots.swap(slots, Ordering::AcqRel);
        if slots > previous {
            self.inner.heavy.add_permits(slots - previous);
        } else if previous > slots {
            let mut owed = previous - slots;
            owed -= self.inner.heavy.forget_permits(owed);
            if owed > 0 {
                // Held slots: forget them as their holders return them.
                let heavy = self.inner.heavy.clone();
                tokio::spawn(async move {
                    if let Ok(permits) = heavy.acquire_many_owned(owed as u32).await {
                        permits.forget();
                    }
                });
            }
        }
    }

    /// NAN-3644: the most uncached bytes one interactive pass may stage, the
    /// OOM safety net that replaced the 2 GiB refusal.
    ///
    /// Derivation. A lease pins every object it names on the cache volume
    /// until the query ends; downloads stream to that volume in 4 MiB chunks
    /// and chDB reads the files from it, so the process heap does not grow
    /// with the cold bytes (the engine's memory is fenced separately by
    /// `QueryMemoryBudget`, independent of scan size). The resource a huge
    /// cold read can exhaust is therefore the cache volume (memory itself
    /// when the volume is tmpfs, whose limit is `max_bytes`). Of the cache's
    /// `max_bytes`, `query_max_bytes` is kept for light queries (the hot
    /// window keeps the same headroom), and the rest is shared by the
    /// `cold_heavy_concurrency` heavy slots, so every admitted heavy read fits
    /// together without one pushing another into `Saturated`. Floored at
    /// `query_max_bytes`: a lease the threshold admits is never over the
    /// ceiling.
    pub fn interactive_cold_ceiling(&self) -> u64 {
        let settings = &self.inner.settings;
        let slots = self.cold_heavy_concurrency().max(1) as u64;
        (settings.max_bytes.saturating_sub(settings.query_max_bytes) / slots).max(settings.query_max_bytes)
    }

    /// NAN-3644: the durable-job ceiling. A heavy durable read takes every
    /// heavy slot, so it may use all the heavy share of the cache.
    pub fn durable_cold_ceiling(&self) -> u64 {
        let settings = &self.inner.settings;
        settings.max_bytes.saturating_sub(settings.query_max_bytes).max(settings.query_max_bytes)
    }

    /// The ceiling of the current read (durable inside
    /// [`with_durable_job_cold_budget`], otherwise interactive).
    pub fn cold_ceiling(&self) -> u64 {
        if DURABLE_JOB_COLD_BYTES.try_with(|_| ()).is_ok() { self.durable_cold_ceiling() } else { self.interactive_cold_ceiling() }
    }

    /// NAN-4138: how long the current foreground read waits out saturation.
    /// NAN-4154: an interactive request waits at most until its own deadline
    /// ([`crate::query_timing::time_left`]): past it the read fails
    /// retryably, its leases drop with the request, and the search service
    /// promotes the query to a durable job (which waits up to
    /// [`SATURATION_WAIT_DURABLE`]). On a large hosted tenant a 120 s interactive
    /// wait outlived the caller's ~45 s timeout and sat on its leases.
    fn saturation_wait(&self) -> Duration {
        let durable = DURABLE_JOB_COLD_BYTES.try_with(|_| ()).is_ok();
        let wait = match self.inner.saturation_wait_ms.load(Ordering::Relaxed) {
            u64::MAX if durable => SATURATION_WAIT_DURABLE,
            u64::MAX => SATURATION_WAIT_INTERACTIVE,
            ms => Duration::from_millis(ms),
        };
        match crate::query_timing::time_left() {
            Some(left) if !durable => wait.min(left),
            _ => wait,
        }
    }

    #[cfg(test)]
    /// Test override of the cold-read reserve.
    #[cfg(test)]
    pub(crate) fn set_cold_read_reserve(&self, bytes: u64) {
        *self.inner.cold_reserve_override.lock().unwrap_or_else(|e| e.into_inner()) = Some(bytes);
    }

    pub(crate) fn set_saturation_wait(&self, wait: Duration) {
        self.inner.saturation_wait_ms.store(u64::try_from(wait.as_millis()).unwrap_or(u64::MAX - 1), Ordering::Relaxed);
    }

    /// NAN-4138: [`Self::reserve_scratch`] that waits out a saturated cache
    /// (bounded, like a foreground lease) instead of refusing the read.
    pub async fn reserve_scratch_waiting(&self, bytes: u64) -> Result<ScratchReservation, ReaderCacheError> {
        // More than the whole cache never fits: no wait.
        let budget = if bytes > self.inner.settings.max_bytes { Duration::ZERO } else { self.saturation_wait() };
        let mut wait = SaturationWait::new(budget);
        // NAN-4591: hold background hydration off while this waits.
        let mut _waiting: Option<ForegroundWaiting<'_>> = None;
        let background = hydrating();
        loop {
            let inner = self.inner.clone();
            match blocking(move || inner.reserve_as(bytes, background, None)).await {
                Ok(reservation) => return Ok(ScratchReservation { _reservation: reservation }),
                Err(error @ ReaderCacheError::Saturated { .. }) => {
                    if !background {
                        _waiting.get_or_insert_with(|| ForegroundWaiting::new(&self.inner.foreground_waiting));
                    }
                    if !wait.wait(&self.inner.tenant_id, bytes).await {
                        return Err(error);
                    }
                }
                Err(error) => return Err(error),
            }
        }
    }

    /// NAN-3644: the heavy slot for one read, waiting in the queue if every
    /// slot is held. Inside a request (`query_timing::measure`) the slot is
    /// the request's: its later selections reuse it and it is released when
    /// the request ends. A durable job takes every slot, so it never shares
    /// the volume with another heavy read. Dropping the future while queued
    /// leaves the queue.
    async fn heavy_slot(&self, budget: Option<&ColdBudget>) -> Result<Arc<tokio::sync::OwnedSemaphorePermit>, ReaderCacheError> {
        let durable = DURABLE_JOB_COLD_BYTES.try_with(|_| ()).is_ok();
        let heavy = self.inner.heavy.clone();
        let tenant_id = self.inner.tenant_id.clone();
        let slots = self.cold_heavy_concurrency();
        let acquire = move || async move {
            let started = Instant::now();
            let available = heavy.available_permits();
            let wanted = if durable { slots } else { 1 };
            if available < wanted {
                tracing::info!(tenant_id = %tenant_id, durable, slots, "reader_cache_cold_queued");
            }
            let permit = heavy.acquire_many_owned(u32::try_from(wanted).unwrap_or(u32::MAX)).await.ok();
            let waited_ms = started.elapsed().as_secs_f64() * 1000.0;
            crate::query_timing::record(|p| p.cold_queue_ms += waited_ms);
            permit
        };
        let closed = || ReaderCacheError::Invariant("heavy cold-read queue is closed".into());
        if let Some(scan) = crate::query_timing::cold_scan() {
            return scan.heavy_permit(acquire).await.ok_or_else(closed);
        }
        match budget {
            Some(budget) => budget.heavy.heavy_permit(acquire).await.ok_or_else(closed),
            None => {
                let scan = crate::query_timing::ColdScan::default();
                scan.heavy_permit(acquire).await.ok_or_else(closed)
            }
        }
    }

    #[cfg(test)]
    fn set_fence_slab_bytes(&self, bytes: u64) {
        self.inner.fence_slab_bytes.store(bytes, Ordering::Relaxed);
    }

    /// Recent producer objects enter residency immediately when imported.
    pub fn mark_hot(&self, digest: String, end_us: i64) {
        self.inner.state().hot.insert(digest, end_us);
    }

    /// Background arrival work may occupy at most an eighth of this cache
    /// and never exceed the foreground cold-fetch budget. Leased objects
    /// remain protected by the normal admission/eviction path.
    pub fn prewarm_max_bytes(&self) -> u64 {
        (self.inner.settings.max_bytes / 8).min(self.inner.settings.query_max_bytes)
    }

    /// Open or create `{root}/tenant-{tenant_id}/`, bound by a marker to
    /// (tenant, bucket, key prefix). A marker for anything else fails closed.
    pub fn open(
        settings: ReaderObjectCacheSettings,
        tenant_id: &str,
        bucket: &str,
        allowed_key_prefix: &str,
        source: Arc<dyn ReaderObjectSource>,
    ) -> Result<Self, ReaderCacheError> {
        settings.validate()?;
        let key_prefix = allowed_key_prefix.trim_matches('/');
        if !valid_tenant_id(tenant_id)
            || !valid_token(bucket)
            || key_prefix.is_empty()
            || key_prefix.chars().any(char::is_control)
            || key_prefix.split('/').any(|part| matches!(part, "" | "." | ".."))
        {
            return Err(ReaderCacheError::InvalidConfig(
                "reader cache tenant, bucket or key prefix is invalid".to_string(),
            ));
        }
        let directory = tenant_directory(&settings.root, tenant_id);
        std::fs::create_dir_all(&directory)?;
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700))?;
        let objects = directory.join("objects");
        let expected = Marker {
            schema: MARKER_SCHEMA,
            tenant_id: tenant_id.to_string(),
            bucket: bucket.to_string(),
            key_prefix: key_prefix.to_string(),
        };
        bind_marker(&directory, &objects, &expected)?;
        let pins = directory.join("pins");
        let reads = directory.join("reads");
        std::fs::create_dir_all(&objects)?;
        std::fs::create_dir_all(&pins)?;
        std::fs::create_dir_all(&reads)?;
        // NAN-3644: batched cold reads spool here for one request's life; a
        // spool left by a process that died mid-request is never read again.
        match std::fs::remove_dir_all(directory.join(COLD_BATCH_SCRATCH)) {
            Err(error) if error.kind() != std::io::ErrorKind::NotFound => {
                tracing::warn!(%error, "could not clear stale cold-batch spools");
            }
            _ => {}
        }
        let heavy_slots = cold_heavy_concurrency_from_env();
        let inner = Arc::new(Inner {
            permits: tokio::sync::Semaphore::new(settings.fetch_concurrency),
            background_permits: tokio::sync::Semaphore::new(background_fetch_slots(settings.fetch_concurrency)),
            heavy: Arc::new(tokio::sync::Semaphore::new(heavy_slots)),
            heavy_slots: std::sync::atomic::AtomicUsize::new(heavy_slots),
            settings,
            tenant_id: tenant_id.to_string(),
            bucket: bucket.to_string(),
            key_prefix: key_prefix.to_string(),
            objects,
            pins,
            reads,
            lock_path: directory.join(".lock"),
            source,
            state: Mutex::default(),
            counters: Counters::default(),
            hot_capacity: Mutex::new(None),
            fence_slab_bytes: AtomicU64::new(HOT_WINDOW_FENCE_SLAB_BYTES),
            scrubbing: std::sync::atomic::AtomicBool::new(false),
            saturation_wait_ms: AtomicU64::new(u64::MAX),
            foreground_waiting: std::sync::atomic::AtomicUsize::new(0),
            unwalked_evictions: Mutex::default(),
            #[cfg(test)]
            cold_reserve_override: Mutex::default(),
        });
        inner.with_global_lock(|| {
            inner.sweep_temporaries()?;
            inner.reclaim_stale_pins()?;
            inner.sweep_read_links()?;
            let mut state = inner.state();
            inner.refresh_index(&mut state, true)
        })?;
        Ok(Self { inner })
    }

    /// NAN-3647: [`Self::open`] for a cache on a persistent volume (the A/B
    /// hot-window volumes). A tree this process cannot adopt (a marker for
    /// another tenant/bucket/prefix, unmarked objects, an unreadable or
    /// corrupt directory) must not keep query[T] from starting: it is set
    /// aside, deleted in the background, and the cache starts cold. A bad
    /// configuration still fails.
    pub fn open_or_reset(
        settings: ReaderObjectCacheSettings,
        tenant_id: &str,
        bucket: &str,
        allowed_key_prefix: &str,
        source: Arc<dyn ReaderObjectSource>,
    ) -> Result<Self, ReaderCacheError> {
        match Self::open(settings.clone(), tenant_id, bucket, allowed_key_prefix, source.clone()) {
            Ok(cache) => Ok(cache),
            Err(error @ ReaderCacheError::InvalidConfig(_)) => Err(error),
            Err(error) => {
                let directory = tenant_directory(&settings.root, tenant_id);
                let aside = settings.root.join(format!("{TEMP_PREFIX}discarded-{}", uuid::Uuid::now_v7()));
                tracing::error!(%error, directory = %directory.display(),
                    "reader cache on the persistent hot-window volume is unusable; discarding it and starting cold");
                match std::fs::rename(&directory, &aside) {
                    Ok(()) => {
                        std::thread::spawn(move || {
                            if let Err(error) = std::fs::remove_dir_all(&aside) {
                                tracing::warn!(%error, path = %aside.display(), "could not delete a discarded reader cache");
                            }
                        });
                    }
                    Err(rename) if rename.kind() == std::io::ErrorKind::NotFound => {}
                    Err(rename) => {
                        tracing::warn!(error = %rename, "could not set the unusable reader cache aside; deleting it in place");
                        std::fs::remove_dir_all(&directory)?;
                    }
                }
                Self::open(settings, tenant_id, bucket, allowed_key_prefix, source)
            }
        }
    }

    /// Admit a producer copy using the same authorization, byte reservation,
    /// signed digest and immutable publication fences as a network download.
    /// The producer inode remains independent from the leased reader inode.
    pub async fn warm_local(&self, object: &ReaderObjectRef, source: &Path) -> Result<(), ReaderCacheError> {
        self.inner.authorize(object)?;
        let (inner, object, source) = (self.inner.clone(), object.clone(), source.to_path_buf());
        let background = hydrating();
        blocking(move || {
            if inner.verified_hit(&object)? { return Ok(()) }
            let reservation = inner.reserve_as(object.size_bytes, background, Some(&object.sha256))?;
            let mut temporary = tempfile::NamedTempFile::new_in(&inner.objects)?;
            let mut input = File::open(source)?;
            if let Some(range) = &object.range {
                use std::io::Seek;
                input.seek(std::io::SeekFrom::Start(range.start))?;
            }
            let limit = if object.range.is_some() { object.size_bytes } else { object.size_bytes.saturating_add(1) };
            let policy = inner.hot_capacity.lock().unwrap_or_else(|e| e.into_inner()).clone();
            let _write_guard = if let Some(policy) = policy {
                let block = temporary.as_file().metadata()?.blksize().max(4096);
                inner.fence(&policy, limit.div_ceil(block).saturating_mul(block))?
            } else { None };
            std::io::copy(&mut std::io::Read::take(input, limit), &mut temporary)?;
            drop(_write_guard);
            if temporary.as_file().metadata()?.len() != object.size_bytes
                || crate::native::file_sha256(temporary.path()).map_err(|error| io_other(error.to_string()))? != object.sha256 {
                inner.counters.integrity_failures.fetch_add(1, Ordering::Relaxed);
                return Err(ReaderCacheError::Integrity("producer copy differs from signed object".into()));
            }
            inner.admit(temporary, &object)?;
            drop(reservation);
            Ok(())
        }).await
    }

    /// Ensure every object is present, verified and leased. `Ok` is never a
    /// subset; any failure drops the partial lease.
    pub async fn ensure_local(
        &self,
        objects: &[ReaderObjectRef],
    ) -> Result<ReaderCacheLease, ReaderCacheError> {
        self.ensure_local_budgeted(objects, None).await
    }

    /// [`Self::ensure_local`] whose cold bytes are drawn from `budget`, one
    /// query's budget shared by several leases (NAN-3133: range manifests,
    /// ranges and whole-file fallbacks of one selection).
    pub async fn ensure_local_within(
        &self,
        objects: &[ReaderObjectRef],
        budget: &ColdBudget,
    ) -> Result<ReaderCacheLease, ReaderCacheError> {
        self.ensure_local_budgeted(objects, Some(budget)).await
    }

    async fn ensure_local_budgeted(
        &self,
        objects: &[ReaderObjectRef],
        budget: Option<&ColdBudget>,
    ) -> Result<ReaderCacheLease, ReaderCacheError> {
        let started = Instant::now();
        let mut unique: Vec<ReaderObjectRef> = Vec::with_capacity(objects.len());
        let mut sizes: HashMap<&str, u64> = HashMap::with_capacity(objects.len());
        for object in objects {
            self.inner.authorize(object)?;
            match sizes.insert(&object.sha256, object.size_bytes) {
                Some(size) if size != object.size_bytes => {
                    return Err(ReaderCacheError::Integrity(format!(
                        "digest {} is named with two sizes",
                        object.sha256
                    )))
                }
                Some(_) => {}
                None => unique.push(object.clone()),
            }
        }
        let _holds = HoldGuard::new(&self.inner, &unique);
        let mut lease = self.inner.new_lease(&unique)?;

        let inner = self.inner.clone();
        let (refs, directory) = (unique.clone(), lease.directory.clone());
        let mut misses = blocking(move || inner.link_hits(&refs, &directory)).await?;
        let hits = unique.len() - misses.len();
        self.inner.counters.hits.fetch_add(hits as u64, Ordering::Relaxed);
        self.inner
            .counters
            .misses
            .fetch_add(misses.len() as u64, Ordering::Relaxed);
        let cold_bytes: u64 = misses.iter().map(|object| object.size_bytes).sum();
        // Storage hydration admits one signed object against total capacity.
        // NAN-3644: a foreground read is never refused for being cold. Over
        // the heavy threshold it queues for a heavy slot; only the ceiling
        // (an OOM safety net derived from the cache size) refuses it.
        let foreground = HYDRATE_RATE.try_with(|_| ()).is_err();
        let mut heavy = None;
        if foreground && cold_bytes > 0 {
            let needed = budget.map_or(cold_bytes, |budget| budget.spent().saturating_add(cold_bytes));
            let ceiling = self.cold_ceiling();
            if needed > ceiling {
                return Err(ReaderCacheError::ScanTooLarge {
                    required_bytes: needed,
                    ceiling_bytes: ceiling,
                    background_bytes: self.durable_cold_ceiling(),
                });
            }
            let threshold = budget.map_or_else(|| self.query_cold_budget(), ColdBudget::limit);
            if needed > threshold {
                heavy = Some(self.heavy_slot(budget).await?);
            }
        }
        if cold_bytes > self.inner.settings.max_bytes {
            return Err(ReaderCacheError::Saturated {
                needed_bytes: cold_bytes,
            });
        }
        // The fetch deadline starts once the read is admitted, not while it
        // waits for a heavy slot.
        let lease_deadline = fetch_deadline(self.inner.settings.fetch_deadline, objects.iter().fold(0_u64, |bytes, object| bytes.saturating_add(object.size_bytes)));
        let mut deadline = tokio::time::Instant::now() + lease_deadline;
        // A shared budget is drawn when the fetch starts and refunded if the
        // lease fails: `spent` counts only bytes a lease actually delivered.
        // The draw re-checks the ceiling atomically: a sibling lease of the
        // same budget may have drawn since the check above.
        let mut charge = match budget.filter(|_| foreground) {
            Some(budget) => {
                let ceiling = self.cold_ceiling();
                if !budget.take_within(cold_bytes, ceiling) {
                    return Err(ReaderCacheError::ScanTooLarge {
                        required_bytes: budget.spent().saturating_add(cold_bytes),
                        ceiling_bytes: ceiling,
                        background_bytes: self.durable_cold_ceiling(),
                    });
                }
                Some(BudgetCharge { budget, bytes: cold_bytes, committed: false })
            }
            None => None,
        };
        // NAN-3644: live progress for the request's search stream.
        let progress = if foreground && cold_bytes > 0 { crate::query_timing::cold_scan() } else { None };
        if let Some(progress) = &progress {
            progress.total_bytes.fetch_add(cold_bytes, Ordering::Relaxed);
        }
        let progress_charge = ProgressCharge { scan: progress.as_deref(), expected: cold_bytes, read: AtomicU64::new(0) };
        let miss_count = misses.len();
        // A second round only runs if another process evicted a fresh object
        // between its admission and our link.
        // NAN-4138: a foreground read that finds the cache (or the hot-window
        // volume) saturated waits for capacity, bounded, instead of failing
        // the search. Background hydration still defers at once: its pass
        // retries later and must not hold capacity hostage.
        let mut saturation = foreground.then(|| SaturationWait::new(self.saturation_wait()));
        // NAN-4591: from its first saturation until the lease is taken, this
        // read holds background hydration off the capacity it waits for.
        let mut _waiting: Option<ForegroundWaiting<'_>> = None;
        let mut rounds = 0;
        while rounds < 2 {
            if misses.is_empty() {
                break;
            }
            let charge = &progress_charge;
            let largest = misses.iter().map(|object| object.size_bytes).max().unwrap_or(0);
            let inner = &self.inner;
            // Collected first: a stream holding the mapping closure is not
            // `Send` for every lifetime, which spawned searches require.
            let fetches: Vec<_> = misses
                .iter()
                .map(|object| async move {
                    inner.fetch_shared(object).await.map_err(|error| error.duplicate())?;
                    charge.read(object.size_bytes);
                    Ok::<_, ReaderCacheError>(())
                })
                .collect();
            let read = futures::stream::iter(fetches)
            .buffer_unordered(lease_outstanding_fetches(inner.settings.fetch_concurrency, misses.len()))
            .try_collect::<Vec<()>>();
            // NAN-3714: the lease deadline is extended while objects keep
            // arriving (each extension: one more object's own deadline); it
            // cuts only a lease that stopped progressing. A large cold read
            // on a link slower than the sizing floor degrades to slower,
            // never to an error.
            let stall = fetch_deadline(self.inner.settings.fetch_deadline, largest);
            match wait_while_progressing(read, deadline, stall, || charge.read.load(Ordering::Relaxed)).await? {
                Ok(_) => rounds += 1,
                Err(error @ ReaderCacheError::Saturated { needed_bytes }) => {
                    let Some(wait) = saturation.as_mut() else { return Err(error) };
                    _waiting.get_or_insert_with(|| ForegroundWaiting::new(&self.inner.foreground_waiting));
                    // Pin what did land; only the rest waits. Nothing is
                    // staged while waiting (the failed fetches dropped their
                    // reservations and temp files).
                    if !wait.wait(&self.inner.tenant_id, needed_bytes).await {
                        return Err(error);
                    }
                    // Waiting is not a stalled transfer.
                    deadline = tokio::time::Instant::now() + lease_deadline;
                }
                Err(error) => return Err(error),
            }
            let inner = self.inner.clone();
            let directory = lease.directory.clone();
            misses = blocking(move || inner.link_present(misses, &directory)).await?;
        }
        if !misses.is_empty() {
            return Err(ReaderCacheError::Unavailable(
                "admitted reader objects were evicted before they could be leased".to_string(),
            ));
        }
        lease.hits = hits;
        lease.misses = miss_count;
        {
            let mut state = self.inner.state();
            for sha256 in &lease.sha256s {
                *state.live.entry(sha256.clone()).or_default() += 1;
            }
        }
        lease.live = true;
        crate::query_timing::record(|p| {
            p.local_object_hits += lease.hits() as u64;
            p.local_object_misses += lease.misses() as u64;
        });
        lease.fetched_bytes = cold_bytes;
        lease.heavy = heavy;
        if let Some(charge) = charge.as_mut() {
            charge.committed = true;
        }
        lease.ensure_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
        self.inner.schedule_scrub();
        if miss_count > 0 {
            tracing::info!(
                tenant_id = %self.inner.tenant_id,
                objects = miss_count,
                bytes = cold_bytes,
                hits,
                ms = lease.ensure_ms,
                "reader_cache_fetch"
            );
        }
        Ok(lease)
    }

    /// Retire superseded objects only when no process holds their canonical
    /// path. Return deferred digests so discovery can retry after leases end.
    pub async fn evict_unleased(&self, digests: Vec<String>) -> Result<Vec<String>, ReaderCacheError> {
        if digests.iter().any(|digest| !valid_sha256(digest)) {
            return Err(ReaderCacheError::InvalidConfig("invalid eviction digest".into()));
        }
        let inner = self.inner.clone();
        blocking(move || inner.with_global_lock(|| {
            let pinned = inner.pinned_inodes()?;
            let mut state = inner.state();
            let mut deferred = Vec::new();
            for digest in digests {
                let path = inner.object_path(&digest);
                let stamp = match FileStamp::read(&path) {
                    Ok(stamp) => stamp,
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => { state.entries.remove(&digest); continue },
                    Err(error) => return Err(error.into()),
                };
                if state.holds.contains_key(&digest) || pinned.contains(&(stamp.dev, stamp.inode)) {
                    deferred.push(digest);
                    continue;
                }
                std::fs::remove_file(path)?;
                inner.drop_read_link(&digest, &pinned)?;
                state.entries.remove(&digest);
                inner.counters.evictions.fetch_add(1, Ordering::Relaxed);
                inner.note_evicted(stamp.bytes);
            }
            Ok(deferred)
        })).await
    }

    /// NAN-3647: evict every indexed object whose digest is not in `keep`,
    /// unless a process holds or pins it (it is then left to pressure
    /// eviction). Returns (objects, bytes) evicted. Used once per process on a
    /// persistent hot-window volume, whose index was rebuilt from disk.
    pub async fn evict_unreferenced(&self, keep: HashSet<String>) -> Result<(usize, u64), ReaderCacheError> {
        let inner = self.inner.clone();
        blocking(move || inner.with_global_lock(|| {
            inner.refresh_index(&mut inner.state(), false)?;
            let pinned = inner.pinned_inodes()?;
            let mut state = inner.state();
            let candidates = state.entries.iter()
                .filter(|(digest, _)| !keep.contains(*digest))
                .map(|(digest, entry)| (digest.clone(), entry.stamp.bytes))
                .collect::<Vec<_>>();
            let (mut objects, mut bytes) = (0_usize, 0_u64);
            for (digest, size) in candidates {
                if state.holds.contains_key(&digest) || state.live.get(&digest).is_some_and(|n| *n > 0) {
                    continue;
                }
                let path = inner.object_path(&digest);
                match FileStamp::read(&path) {
                    Ok(stamp) if pinned.contains(&(stamp.dev, stamp.inode)) => continue,
                    Ok(_) => {}
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => { state.entries.remove(&digest); continue }
                    Err(error) => return Err(error.into()),
                }
                std::fs::remove_file(path)?;
                inner.drop_read_link(&digest, &pinned)?;
                state.entries.remove(&digest);
                inner.counters.evictions.fetch_add(1, Ordering::Relaxed);
                inner.note_evicted(size);
                objects += 1;
                bytes += size;
            }
            Ok((objects, bytes))
        })).await
    }

    /// Hot residency is a soft pin: foreground leases always win under pressure.
    pub fn set_hot(&self, objects: HashMap<String, i64>) {
        self.inner.state().hot = objects;
    }

    pub async fn is_local(&self, object: &ReaderObjectRef) -> Result<bool, ReaderCacheError> {
        self.inner.authorize(object)?;
        let (inner, object) = (self.inner.clone(), object.clone());
        blocking(move || inner.verified_hit(&object)).await
    }

    /// Replace the protected (hot) set. Protected objects are never evicted.
    pub fn set_protected(&self, sha256s: impl IntoIterator<Item = String>) {
        self.inner.state().protected = sha256s.into_iter().collect();
    }

    pub fn stats(&self) -> ReaderCacheStats {
        let state = self.inner.state();
        let counters = &self.inner.counters;
        ReaderCacheStats {
            objects: state.entries.len(),
            stored_bytes: state.stored_bytes(),
            max_bytes: self.inner.settings.max_bytes,
            hits: counters.hits.load(Ordering::Relaxed),
            misses: counters.misses.load(Ordering::Relaxed),
            fetched_bytes: counters.fetched_bytes.load(Ordering::Relaxed),
            integrity_failures: counters.integrity_failures.load(Ordering::Relaxed),
            evictions: counters.evictions.load(Ordering::Relaxed),
            rehashes: counters.rehashes.load(Ordering::Relaxed),
            fetch_ns: counters.fetch_ns.load(Ordering::Relaxed),
            verify_ns: counters.verify_ns.load(Ordering::Relaxed),
        }
    }

    /// Canonical path of `sha256` in this tenant's cache.
    pub fn object_path(&self, sha256: &str) -> PathBuf {
        self.inner.object_path(sha256)
    }

    /// Best-effort background access without cache admission, hashing, or
    /// download locks. Inherited objects must first be verified by a normal
    /// lease. A changed or unsettled stamp is also left to the lease path.
    pub(crate) fn verified_background_path(&self, sha256: &str) -> Option<PathBuf> {
        if !valid_sha256(sha256) { return None; }
        let path = self.object_path(sha256);
        let stamp = FileStamp::read(&path).ok()?;
        if stamp.modify_time_may_collide(unix_now_seconds()) { return None; }
        let state = self.inner.state.try_lock().ok()?;
        let entry = state.entries.get(sha256)?;
        (entry.verified_s.is_some() && entry.stamp == stamp).then_some(path)
    }

    /// A per-tenant scratch directory beside `objects/` and `pins/` (never
    /// indexed, swept or admitted by the cache).
    pub fn scratch_dir(&self, name: &str) -> PathBuf {
        self.inner.objects.parent().map_or_else(|| self.inner.objects.join(name), |tenant| tenant.join(name))
    }

    /// The cache's total capacity.
    pub fn max_bytes(&self) -> u64 {
        self.inner.settings.max_bytes
    }

    /// Reserve `bytes` of capacity (blocking) for a scratch file a query
    /// holds, without writing (a reused sparse file).
    pub fn reserve_scratch(&self, bytes: u64) -> Result<ScratchReservation, ReaderCacheError> {
        Ok(ScratchReservation { _reservation: self.inner.reserve(bytes)? })
    }

    /// Write `bytes` of scratch data (blocking) under the cache's capacity
    /// accounting: a capacity reservation (evicting cold objects like an
    /// admission) held by the returned guard for the scratch file's life,
    /// and, with a hot-window policy, the volume write fence during `write`.
    pub fn scratch_write<T>(
        &self, bytes: u64, write: impl FnOnce() -> std::io::Result<T>,
    ) -> Result<(T, ScratchReservation), ReaderCacheError> {
        let reservation = self.inner.reserve(bytes)?;
        let policy = self.inner.hot_capacity.lock().unwrap_or_else(|e| e.into_inner()).clone();
        let guard = match policy {
            Some(policy) => self.inner.fence(&policy, bytes)?,
            None => None,
        };
        let value = write()?;
        drop(guard);
        Ok((value, ScratchReservation { _reservation: reservation }))
    }
}

fn bind_marker(directory: &Path, objects: &Path, expected: &Marker) -> Result<(), ReaderCacheError> {
    let path = directory.join(MARKER_FILE);
    let mismatch = || {
        ReaderCacheError::OutsideTenant(
            "reader cache directory is bound to a different tenant, bucket or key prefix; purge it"
                .to_string(),
        )
    };
    for _attempt in 0..2 {
        match std::fs::read(&path) {
            Ok(bytes) => {
                let found: Marker = serde_json::from_slice(&bytes).map_err(|_| mismatch())?;
                return if &found == expected { Ok(()) } else { Err(mismatch()) };
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        // Objects without a marker have unknown provenance: never adopt them.
        match std::fs::read_dir(objects) {
            Ok(mut entries) => {
                if entries.next().is_some() {
                    return Err(mismatch());
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        let mut temporary = tempfile::Builder::new()
            .prefix(TEMP_PREFIX)
            .tempfile_in(directory)?;
        serde_json::to_writer(&mut temporary, expected).map_err(std::io::Error::other)?;
        temporary.as_file().sync_all()?;
        match temporary.persist_noclobber(&path) {
            Ok(_) => return Ok(()),
            Err(error) if error.error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error.error.into()),
        }
    }
    Err(mismatch())
}

/// NAN-4591: how long an eviction is credited back against the volume
/// accountant's figure: two of its default 30 s re-walks, after which the
/// walk has seen the deletion. Too short only means the old over-eviction
/// for a moment; too long is caught by the download fence (a refusal clears
/// the credit).
const UNWALKED_EVICTION_WINDOW: Duration = Duration::from_secs(60);

/// NAN-4591: the volume accountant's default re-walk interval
/// (`nanosiem_lake_cell::volume_usage`, 30 s).
const ACCOUNTANT_REWALK: Duration = Duration::from_secs(30);

/// NAN-4591: counts a foreground read as waiting out saturation for as long
/// as it lives (see `Inner::foreground_waiting`).
struct ForegroundWaiting<'a>(&'a std::sync::atomic::AtomicUsize);
impl<'a> ForegroundWaiting<'a> {
    fn new(counter: &'a std::sync::atomic::AtomicUsize) -> Self {
        counter.fetch_add(1, Ordering::AcqRel);
        Self(counter)
    }
}
impl Drop for ForegroundWaiting<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

/// NAN-4591: is the current task background hydration (hot window, arrival
/// prewarm, identity backfill), which must yield to foreground reads?
fn hydrating() -> bool {
    HYDRATE_RATE.try_with(|_| ()).is_ok()
}

impl Inner {
    /// NAN-4591: remember `bytes` deleted now (the accountant counts them
    /// until its next walk).
    fn note_evicted(&self, bytes: u64) {
        if bytes == 0 {
            return;
        }
        let mut log = self.unwalked_evictions.lock().unwrap_or_else(|e| e.into_inner());
        let now = Instant::now();
        while log.front().is_some_and(|(at, _)| now.duration_since(*at) > UNWALKED_EVICTION_WINDOW) {
            log.pop_front();
        }
        log.push_back((now, bytes));
    }

    /// NAN-4591: bytes deleted within [`UNWALKED_EVICTION_WINDOW`].
    fn eviction_credit(&self) -> u64 {
        let mut log = self.unwalked_evictions.lock().unwrap_or_else(|e| e.into_inner());
        let now = Instant::now();
        while log.front().is_some_and(|(at, _)| now.duration_since(*at) > UNWALKED_EVICTION_WINDOW) {
            log.pop_front();
        }
        log.iter().map(|(_, bytes)| bytes).sum()
    }

    /// NAN-4591: the volume fence refused a write. Credit that is older than
    /// one accountant re-walk has most likely been walked already (it would
    /// then overstate the room and stall eviction until it expired), so drop
    /// it. Fresher credit stays: clearing it re-armed the over-eviction
    /// (every saturation retry evicted another read's worth that the fence
    /// could not see either).
    fn expire_walked_credit(&self) {
        let mut log = self.unwalked_evictions.lock().unwrap_or_else(|e| e.into_inner());
        let now = Instant::now();
        while log.front().is_some_and(|(at, _)| now.duration_since(*at) > ACCOUNTANT_REWALK) {
            log.pop_front();
        }
    }

    /// [`volume_fence`], expiring walked credit on a refusal.
    fn fence(
        &self,
        policy: &crate::local_hot_window::Settings,
        growth: u64,
    ) -> Result<Option<nanosiem_lake_cell::volume_usage::WriteGuard>, ReaderCacheError> {
        let fenced = volume_fence(policy, growth);
        if matches!(fenced, Err(ReaderCacheError::Saturated { .. })) {
            self.expire_walked_credit();
        }
        fenced
    }

    /// NAN-4591: the cold-read reserve of this cache (see
    /// [`crate::local_hot_window::cold_read_reserve`]).
    fn cold_read_reserve(&self) -> u64 {
        #[cfg(test)]
        if let Some(bytes) = self.cold_reserve_override.lock().unwrap_or_else(|e| e.into_inner()).as_ref() {
            return *bytes;
        }
        crate::local_hot_window::cold_read_reserve(self.settings.max_bytes, self.settings.query_max_bytes)
    }

    fn state(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn object_path(&self, sha256: &str) -> PathBuf {
        self.objects.join(format!("{sha256}.bin"))
    }

    fn authorize(&self, object: &ReaderObjectRef) -> Result<(), ReaderCacheError> {
        if object.range.as_ref().is_some_and(|range| range.end.checked_sub(range.start) != Some(object.size_bytes) || object.size_bytes == 0) {
            return Err(ReaderCacheError::Integrity("invalid signed object range".into()));
        }
        if !valid_sha256(&object.sha256) {
            return Err(ReaderCacheError::Integrity(
                "reader object digest is not a lowercase SHA-256".to_string(),
            ));
        }
        let outside = || ReaderCacheError::OutsideTenant(object.source_uri.clone());
        let (bucket, key) = parse_s3_uri(&object.source_uri).map_err(|_| outside())?;
        let relative = key
            .strip_prefix(self.key_prefix.as_str())
            .and_then(|rest| rest.strip_prefix('/'))
            .ok_or_else(outside)?;
        if bucket != self.bucket
            || relative
                .split('/')
                .any(|part| matches!(part, "" | "." | ".."))
        {
            return Err(outside());
        }
        Ok(())
    }

    fn with_global_lock<T>(
        &self,
        operation: impl FnOnce() -> Result<T, ReaderCacheError>,
    ) -> Result<T, ReaderCacheError> {
        let lock = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(&self.lock_path)?;
        lock.lock_exclusive()?;
        let result = operation();
        let unlock = FileExt::unlock(&lock);
        let value = result?;
        unlock?;
        Ok(value)
    }

    /// Remove crashed downloads. A live download holds a flock on its temp.
    fn sweep_temporaries(&self) -> Result<(), ReaderCacheError> {
        for entry in std::fs::read_dir(&self.objects)? {
            let path = entry?.path();
            let temporary = path
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with(TEMP_PREFIX));
            if !temporary {
                continue;
            }
            let Ok(file) = File::open(&path) else { continue };
            if file.try_lock_exclusive().is_ok() {
                let _ = std::fs::remove_file(&path);
                let _ = FileExt::unlock(&file);
            }
        }
        Ok(())
    }

    fn reclaim_stale_pins(&self) -> Result<(), ReaderCacheError> {
        for entry in std::fs::read_dir(&self.pins)? {
            let path = entry?.path();
            if !path.is_dir() {
                let _ = std::fs::remove_file(path);
                continue;
            }
            let lease = match OpenOptions::new().read(true).write(true).open(path.join(".lease")) {
                Ok(lease) => lease,
                Err(_) => {
                    std::fs::remove_dir_all(&path)?;
                    continue;
                }
            };
            match lease.try_lock_exclusive() {
                Ok(()) => {
                    FileExt::unlock(&lease)?;
                    std::fs::remove_dir_all(&path)?;
                }
                Err(error) if error.kind() == fs2::lock_contended_error().kind() => {}
                Err(error) => return Err(error.into()),
            }
        }
        Ok(())
    }

    fn read_path(&self, sha256: &str) -> PathBuf {
        self.reads.join(format!("{sha256}.bin"))
    }

    /// NAN-4222: point `reads/<sha256>.bin` at the inode `pin` (a lease's
    /// private hard link of the verified object). chDB keys its Parquet
    /// metadata cache by path, so a stable read path lets every statement
    /// after the first reuse the parsed footer; the per-lease pin path missed
    /// on every statement. An existing link to another inode is replaced
    /// only when no lease pins that inode, so a selected read is never
    /// redirected; otherwise this lease reads through its private pin. Must
    /// run under the global lock. Best effort: a failure leaves the private
    /// path in use.
    fn ensure_read_link(&self, sha256: &str, pin: &Path, pinned: &mut Option<BTreeSet<(u64, u64)>>) {
        let read = self.read_path(sha256);
        let linked = (|| -> Result<(), ReaderCacheError> {
            let target = std::fs::symlink_metadata(pin)?;
            match std::fs::symlink_metadata(&read) {
                Ok(current) if (current.dev(), current.ino()) == (target.dev(), target.ino()) => return Ok(()),
                Ok(current) => {
                    let pinned = match pinned {
                        Some(pinned) => pinned,
                        None => pinned.insert(self.pinned_inodes()?),
                    };
                    if pinned.contains(&(current.dev(), current.ino())) {
                        return Ok(());
                    }
                    std::fs::remove_file(&read)?;
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
            }
            std::fs::hard_link(pin, &read)?;
            Ok(())
        })();
        if let Err(error) = linked {
            tracing::debug!(%error, sha256, "reader cache stable read link not updated; using the lease pin path");
        }
    }

    /// Remove `reads/<sha256>.bin` unless a lease pins its inode. Must run
    /// under the global lock, after the canonical object is removed.
    fn drop_read_link(&self, sha256: &str, pinned: &BTreeSet<(u64, u64)>) -> Result<(), ReaderCacheError> {
        let read = self.read_path(sha256);
        match std::fs::symlink_metadata(&read) {
            Ok(current) if !pinned.contains(&(current.dev(), current.ino())) => match std::fs::remove_file(&read) {
                Ok(()) => Ok(()),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
                Err(error) => Err(error.into()),
            },
            Ok(_) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error.into()),
        }
    }

    /// Remove read links whose canonical object is gone or replaced and whose
    /// inode no lease pins (crashes, integrity evictions, other processes),
    /// so no stale link keeps disk space. Must run under the global lock.
    fn sweep_read_links(&self) -> Result<(), ReaderCacheError> {
        let pinned = self.pinned_inodes()?;
        for entry in std::fs::read_dir(&self.reads)? {
            let path = entry?.path();
            let canonical = path
                .file_name()
                .and_then(|name| name.to_str())
                .and_then(|name| name.strip_suffix(".bin"))
                .filter(|name| valid_sha256(name))
                .map(|sha256| self.object_path(sha256));
            let Ok(current) = std::fs::symlink_metadata(&path) else { continue };
            let live = canonical
                .and_then(|canonical| std::fs::symlink_metadata(canonical).ok())
                .is_some_and(|object| (object.dev(), object.ino()) == (current.dev(), current.ino()));
            if !live && !pinned.contains(&(current.dev(), current.ino())) {
                let _ = std::fs::remove_file(&path);
            }
        }
        Ok(())
    }

    fn pinned_inodes(&self) -> Result<BTreeSet<(u64, u64)>, ReaderCacheError> {
        let mut inodes = BTreeSet::new();
        for lease in std::fs::read_dir(&self.pins)? {
            let lease = lease?.path();
            let Ok(links) = std::fs::read_dir(&lease) else { continue };
            for link in links {
                let link = link?;
                if link.path().extension().and_then(|value| value.to_str()) != Some("bin") {
                    continue;
                }
                if let Ok(metadata) = std::fs::symlink_metadata(link.path()) {
                    inodes.insert((metadata.dev(), metadata.ino()));
                }
            }
        }
        Ok(inodes)
    }

    /// Reconcile the index with `objects/`. Files not written by the cache
    /// (wrong mode, empty, not regular) are deleted. At open every object
    /// starts as the oldest; later discoveries (another process) as newest.
    fn refresh_index(&self, state: &mut State, at_open: bool) -> Result<(), ReaderCacheError> {
        let mut seen = HashSet::new();
        for entry in std::fs::read_dir(&self.objects)? {
            let path = entry?.path();
            let Some(sha256) = path
                .file_name()
                .and_then(|name| name.to_str())
                .and_then(|name| name.strip_suffix(".bin"))
                .filter(|name| valid_sha256(name))
                .map(ToOwned::to_owned)
            else {
                continue;
            };
            let stamp = match FileStamp::read(&path) {
                Ok(stamp) if stamp.mode == OBJECT_MODE && stamp.bytes > 0 => stamp,
                Ok(_) | Err(_) => {
                    let _ = std::fs::remove_file(&path);
                    continue;
                }
            };
            seen.insert(sha256.clone());
            let access = if at_open { 0 } else { state.tick() };
            match state.entries.get_mut(&sha256) {
                Some(entry) if entry.stamp == stamp => {}
                Some(entry) => {
                    entry.stamp = stamp;
                    // A directory refresh observes metadata, not verified
                    // bytes. Background access must wait for verification.
                    entry.verified_s = None;
                },
                None => {
                    state.entries.insert(
                        sha256,
                        Entry {
                            stamp,
                            last_access: access,
                            hits: 0,
                            verified_s: None,
                        },
                    );
                }
            }
        }
        state.entries.retain(|sha256, _| seen.contains(sha256));
        Ok(())
    }

    fn new_lease(self: &Arc<Self>, objects: &[ReaderObjectRef]) -> Result<ReaderCacheLease, ReaderCacheError> {
        let directory = self.pins.join(uuid::Uuid::now_v7().to_string());
        let file = self.with_global_lock(|| {
            std::fs::create_dir(&directory)?;
            let file = OpenOptions::new()
                .create_new(true)
                .read(true)
                .write(true)
                .open(directory.join(".lease"))?;
            file.lock_exclusive()?;
            Ok(file)
        })?;
        Ok(ReaderCacheLease {
            inner: self.clone(),
            directory,
            file: Some(file),
            sha256s: objects.iter().map(|object| object.sha256.clone()).collect(),
            paths: objects.iter().map(|object| self.object_path(&object.sha256)).collect(),
            hits: 0,
            misses: 0,
            fetched_bytes: 0,
            ensure_ms: 0,
            live: false,
            heavy: None,
        })
    }

    /// Classify each object as a verified hit or a miss, then pin every hit.
    fn link_hits(
        &self,
        objects: &[ReaderObjectRef],
        directory: &Path,
    ) -> Result<Vec<ReaderObjectRef>, ReaderCacheError> {
        let mut hits = Vec::new();
        let mut misses = Vec::new();
        for object in objects {
            if self.verified_hit(object)? {
                hits.push(object.clone());
            } else {
                misses.push(object.clone());
            }
        }
        misses.extend(self.link_present(hits, directory)?);
        Ok(misses)
    }

    /// Trust a hit by its stat guard only after its mtime is older than the
    /// filesystem collision window. Re-hash on guard drift, first sight of
    /// another process's admission, recent mtime, and for 1 in 64 older hits.
    fn verified_hit(&self, object: &ReaderObjectRef) -> Result<bool, ReaderCacheError> {
        self.verified_hit_at(object, unix_now_seconds())
    }

    fn verified_hit_at(
        &self,
        object: &ReaderObjectRef,
        now_seconds: Option<i64>,
    ) -> Result<bool, ReaderCacheError> {
        let path = self.object_path(&object.sha256);
        let stamp = match FileStamp::read(&path) {
            Ok(stamp) => stamp,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                self.state().entries.remove(&object.sha256);
                return Ok(false);
            }
            Err(error) => return Err(error.into()),
        };
        let seed = u64::from_str_radix(&object.sha256[..8], 16).unwrap_or(0);
        let mut sampled = false;
        let trusted = {
            let mut state = self.state();
            let access = state.tick();
            let leased = state.live.get(&object.sha256).is_some_and(|n| *n > 0);
            match state.entries.get_mut(&object.sha256) {
                // NAN-3165: an object a live lease of this process already
                // verified is not re-sampled while that lease holds it (the
                // same object is checked ~3x per query stage on hot pivots;
                // 1/64 of those were full-file SHA-256). The stamp guard
                // still applies; the sample runs on the next unleased hit.
                Some(entry) if entry.stamp == stamp && leased => true,
                Some(entry) if entry.stamp == stamp => {
                    entry.hits += 1;
                    // NAN-3403: at most one sample per object per interval,
                    // however many background passes hit it.
                    sampled = (seed.wrapping_add(entry.hits) % REHASH_SAMPLE) == 0
                        && scrub_due(entry.verified_s, now_seconds, scrub_min_interval_seconds());
                    true
                }
                Some(_) => false,
                None => {
                    state.entries.insert(
                        object.sha256.clone(),
                        Entry {
                            stamp,
                            last_access: access,
                            hits: 0,
                            verified_s: None,
                        },
                    );
                    false
                }
            }
        };
        let size_ok = stamp.bytes == object.size_bytes && stamp.mode == OBJECT_MODE;
        let settled = !stamp.modify_time_may_collide(now_seconds);
        // The 1-in-REHASH_SAMPLE bit-rot sample of a settled, stamp-trusted
        // hit runs after the lease, off the query path: inline it was a full
        // SHA-256 of a whole data file in the foreground (~150 MB/s without
        // SHA extensions), 0.4-2 s on 1 query in 2 over ~120-file pivots
        // (live load-test tenant, 10-06). A failed scrub evicts the object as before.
        if size_ok && trusted && settled && sampled {
            self.state().scrub.insert(object.sha256.clone());
            return Ok(true);
        }
        let mut hashed = false;
        if size_ok
            && (trusted && settled || {
                self.counters.rehashes.fetch_add(1, Ordering::Relaxed);
                let started = Instant::now();
                let verified = verify_sha256(&path).is_ok_and(|digest| digest == object.sha256);
                self.counters.verify_ns.fetch_add(started.elapsed().as_nanos().min(u64::MAX as u128) as u64, Ordering::Relaxed);
                hashed = verified;
                verified
            })
        {
            if let Some(entry) = self.state().entries.get_mut(&object.sha256) {
                entry.stamp = stamp;
                if hashed && now_seconds.is_some() { entry.verified_s = now_seconds; }
            }
            return Ok(true);
        }
        self.counters.integrity_failures.fetch_add(1, Ordering::Relaxed);
        tracing::error!(
            tenant_id = %self.tenant_id,
            sha256 = %object.sha256,
            local_bytes = stamp.bytes,
            expected_bytes = object.size_bytes,
            "reader_cache_integrity: local cached object failed its fence; evicting and re-fetching"
        );
        self.with_global_lock(|| {
            if FileStamp::read(&path).is_ok_and(|current| current == stamp) {
                std::fs::remove_file(&path)?;
            }
            self.state().entries.remove(&object.sha256);
            Ok(())
        })?;
        Ok(false)
    }

    /// Run the deferred bit-rot samples in the background, one scrub at a
    /// time per cache. Needs a Tokio runtime (every lease path has one).
    fn schedule_scrub(self: &Arc<Self>) {
        if self.state().scrub.is_empty() || self.scrubbing.swap(true, Ordering::AcqRel) {
            return;
        }
        let inner = self.clone();
        drop(tokio::task::spawn_blocking(move || loop {
            inner.scrub_pending();
            inner.scrubbing.store(false, Ordering::Release);
            // A sample queued after the drain but before the flag cleared.
            if inner.state().scrub.is_empty() || inner.scrubbing.swap(true, Ordering::AcqRel) {
                break;
            }
        }));
    }

    /// Re-hash every queued sample; a digest mismatch evicts the object
    /// (when its stamp is unchanged) so the next lease re-fetches it.
    fn scrub_pending(&self) {
        let pending = std::mem::take(&mut self.state().scrub);
        for sha256 in pending {
            let path = self.object_path(&sha256);
            let Ok(stamp) = FileStamp::read(&path) else { continue };
            self.counters.rehashes.fetch_add(1, Ordering::Relaxed);
            let started = Instant::now();
            let digest = verify_sha256(&path);
            self.counters.verify_ns.fetch_add(started.elapsed().as_nanos().min(u64::MAX as u128) as u64, Ordering::Relaxed);
            if digest.as_deref().is_ok_and(|digest| digest == sha256) {
                if let Some(entry) = self.state().entries.get_mut(&sha256) {
                    if entry.stamp == stamp { entry.verified_s = unix_now_seconds(); }
                }
                continue;
            }
            // Evicted or replaced while hashing: not bit-rot.
            if !FileStamp::read(&path).is_ok_and(|current| current == stamp) {
                continue;
            }
            self.counters.integrity_failures.fetch_add(1, Ordering::Relaxed);
            tracing::error!(
                tenant_id = %self.tenant_id,
                sha256 = %sha256,
                "reader_cache_integrity: sampled re-hash of a cached object failed; evicting"
            );
            let evicted = self.with_global_lock(|| {
                if FileStamp::read(&path).is_ok_and(|current| current == stamp) {
                    std::fs::remove_file(&path)?;
                }
                self.state().entries.remove(&sha256);
                Ok(())
            });
            if let Err(error) = evicted {
                tracing::warn!(%error, sha256 = %sha256, "reader cache scrub eviction failed");
            }
        }
    }

    /// Hard-link present objects into the lease under the global lock; any
    /// that vanished (evicted by another process) are returned as misses.
    fn link_present(
        &self,
        objects: Vec<ReaderObjectRef>,
        directory: &Path,
    ) -> Result<Vec<ReaderObjectRef>, ReaderCacheError> {
        if objects.is_empty() {
            return Ok(objects);
        }
        self.with_global_lock(|| {
            let mut missing = Vec::new();
            let mut pinned = None;
            for object in objects {
                let source = self.object_path(&object.sha256);
                let destination = directory.join(format!("{}.bin", object.sha256));
                match std::fs::hard_link(&source, &destination) {
                    Ok(()) => self.ensure_read_link(&object.sha256, &destination, &mut pinned),
                    Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                        self.ensure_read_link(&object.sha256, &destination, &mut pinned)
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                        self.state().entries.remove(&object.sha256);
                        missing.push(object);
                    }
                    Err(error) => return Err(error.into()),
                }
            }
            Ok(missing)
        })
    }

    /// Join the in-flight fetch for this digest, or start one. The fetch runs
    /// as its own task so a caller hitting its deadline does not waste it.
    fn fetch_shared(self: &Arc<Self>, object: &ReaderObjectRef) -> FetchFuture {
        let hydrating = HYDRATE_RATE.try_with(|_| ()).is_ok();
        // NAN-4277: a read inside neither a durable job nor hydration is an
        // interactive (foreground) read.
        let foreground = !hydrating && DURABLE_JOB_COLD_BYTES.try_with(|_| ()).is_err();
        let mut state = self.state();
        if let Some(fetch) = state.inflight.get(&object.sha256) {
            if !hydrating {
                if let Some(rate) = state.background_rates.get(&object.sha256) { rate.rate.store(0, Ordering::Relaxed); rate.foreground.notify_one(); }
            }
            if foreground {
                if let Some(lane) = state.background_lanes.get(&object.sha256) { lane.notify_one(); }
            }
            return fetch.clone();
        }
        let inner = self.clone();
        let owned = object.clone();
        let rate = HYDRATE_RATE.try_with(Arc::clone).ok();
        if let Some(rate) = &rate { state.background_rates.insert(object.sha256.clone(), rate.clone()); }
        let lane = (!foreground).then(|| Arc::new(tokio::sync::Notify::new()));
        if let Some(lane) = &lane { state.background_lanes.insert(object.sha256.clone(), lane.clone()); }
        let task = tokio::spawn(async move {
            let work = async {
            let outcome = std::panic::AssertUnwindSafe(inner.fetch_object(&owned, lane))
                .catch_unwind()
                .await
                .unwrap_or_else(|_| {
                    Err(ReaderCacheError::Unavailable(
                        "reader cache fetch task panicked".to_string(),
                    ))
                });
            {
                let mut state = inner.state();
                state.inflight.remove(&owned.sha256);
                state.background_rates.remove(&owned.sha256);
                state.background_lanes.remove(&owned.sha256);
            }
            outcome.map_err(Arc::new)
            };
            match rate { Some(rate) => HYDRATE_RATE.scope(rate, work).await, None => work.await }
        });
        let fetch = async move {
            task.await.unwrap_or_else(|error| {
                Err(Arc::new(ReaderCacheError::Unavailable(format!(
                    "reader cache fetch task failed: {error}"
                ))))
            })
        }
        .boxed()
        .shared();
        state.inflight.insert(object.sha256.clone(), fetch.clone());
        fetch
    }

    /// `background`: the promotion signal of a background download (see
    /// [`background_fetch_slots`]); `None` for an interactive read.
    async fn fetch_object(
        self: &Arc<Self>,
        object: &ReaderObjectRef,
        background: Option<Arc<tokio::sync::Notify>>,
    ) -> Result<(), ReaderCacheError> {
        // NAN-3714: the deadline cuts a stalled transfer, not the wait for a
        // download slot. Started before the permit, every object queued behind
        // a large lease's first `fetch_concurrency` downloads timed out in the
        // queue: after a roll, a 7 d entity pivot leasing ~1,200 objects
        // failed its durable job twice with "cold object fetch exceeded its
        // deadline" (HTTP 500) while every transfer was still progressing.
        // A queued object waits on other transfers, each bounded by this same
        // deadline once it holds its slot.
        // NAN-4277: a background download first takes a background slot, so
        // background work never holds every download slot. Promoted (a
        // foreground read needs this object) it stops waiting for one.
        let _background = match background {
            Some(promoted) => tokio::select! {
                biased;
                () = promoted.notified() => None,
                permit = self.background_permits.acquire() => Some(permit.map_err(|_| {
                    ReaderCacheError::Unavailable("reader cache closed".to_string())
                })?),
            },
            None => None,
        };
        let _permit = self
            .permits
            .acquire()
            .await
            .map_err(|_| ReaderCacheError::Unavailable("reader cache closed".to_string()))?;
        tokio::time::timeout(fetch_deadline(self.settings.fetch_deadline, object.size_bytes), async {
            if self.object_path(&object.sha256).exists() {
                // Admitted by another process meanwhile; link_present takes it.
                return Ok(());
            }
            let inner = self.clone();
            let bytes = object.size_bytes;
            // NAN-4591: hydration's limits, unless a foreground read joined
            // (promoted) this download while it queued.
            let background = hydrating() && _background.is_some();
            let digest = object.sha256.clone();
            let reservation = blocking(move || inner.reserve_as(bytes, background, Some(&digest))).await?;
            for attempt in 1..=2 {
                match self.download(object).await {
                    Ok(temporary) => {
                        let inner = self.clone();
                        let owned = object.clone();
                        blocking(move || inner.admit(temporary, &owned)).await?;
                        drop(reservation);
                        return Ok(());
                    }
                    Err(ReaderCacheError::Integrity(message)) => {
                        self.counters.integrity_failures.fetch_add(1, Ordering::Relaxed);
                        tracing::error!(
                            tenant_id = %self.tenant_id,
                            sha256 = %object.sha256,
                            source_uri = %object.source_uri,
                            attempt,
                            error = %message,
                            "reader_cache_integrity: fetched object failed its signed fence"
                        );
                        if attempt == 2 {
                            return Err(ReaderCacheError::Integrity(message));
                        }
                    }
                    Err(error) => return Err(error),
                }
            }
            Err(ReaderCacheError::Integrity(object.sha256.clone()))
        })
        .await
        .map_err(|_| ReaderCacheError::FetchTimeout)?
    }

    /// Stream into a flock-held temp in `objects/`, fenced by length + SHA-256.
    async fn download(&self, object: &ReaderObjectRef) -> Result<tempfile::NamedTempFile, ReaderCacheError> {
        let temporary = tempfile::Builder::new()
            .prefix(TEMP_PREFIX)
            .suffix(".tmp")
            .tempfile_in(&self.objects)?;
        temporary.as_file().lock_exclusive()?;
        let expected = object.size_bytes;
        let mut hasher = Sha256::new();
        let mut received = 0_u64;
        let mut sink_error: Option<ReaderCacheError> = None;
        let mut file = temporary.as_file();
        let fetch_started = Instant::now();
        let mut verify_ns = 0_u64;
        // NAN-3147: fence the hot-window volume once per slab, not per chunk.
        // Each grant charges the object's next slab (block-rounded, capped at
        // its signed length; more bytes are an integrity error); the guard is
        // pure accounting, so holding it across pacing blocks no one.
        let policy = self.hot_capacity.lock().unwrap_or_else(|e| e.into_inner()).clone();
        let block = file.metadata()?.blksize().max(4096);
        let slab = self.fence_slab_bytes.load(Ordering::Relaxed).max(1);
        let mut fenced = 0_u64;
        let mut write_guard = None;
        let result = self
            .source
            .stream_object(object, &mut |chunk: &[u8]| {
                received = received.saturating_add(chunk.len() as u64);
                if received > expected {
                    sink_error = Some(ReaderCacheError::Integrity(format!(
                        "{} exceeded its signed length {expected}",
                        object.sha256
                    )));
                    anyhow::bail!("reader object exceeded its signed length");
                }
                if let Some(policy) = policy.as_ref().filter(|_| received > fenced) {
                    // Release the previous slab first: its bytes are written
                    // (and a standalone fence re-walks the directory).
                    drop(write_guard.take());
                    let target = received
                        .max(fenced.saturating_add(slab).min(expected))
                        .div_ceil(block)
                        .saturating_mul(block);
                    write_guard = self.fence(policy, target - fenced).map_err(|error| {
                        let message = anyhow::anyhow!("hot-window allocation deferred: {error}");
                        sink_error = Some(error);
                        message
                    })?;
                    fenced = target;
                }
                let verify_started = Instant::now();
                hasher.update(chunk);
                verify_ns = verify_ns.saturating_add(verify_started.elapsed().as_nanos().min(u64::MAX as u128) as u64);
                if let Err(error) = file.write_all(chunk) {
                    sink_error = Some(ReaderCacheError::Io(error));
                    anyhow::bail!("write reader cache temporary");
                }
                Ok(())
            })
            .await;
        drop(write_guard);
        let fetch_ns = fetch_started.elapsed().as_nanos().min(u64::MAX as u128) as u64;
        self.counters.fetch_ns.fetch_add(fetch_ns.saturating_sub(verify_ns), Ordering::Relaxed);
        self.counters.verify_ns.fetch_add(verify_ns, Ordering::Relaxed);
        self.counters
            .fetched_bytes
            .fetch_add(received.min(expected), Ordering::Relaxed);
        if let Err(error) = result {
            return Err(sink_error.unwrap_or_else(|| {
                ReaderCacheError::Unavailable(format!("{}: {error:#}", object.source_uri))
            }));
        }
        if received != expected || hex::encode(hasher.finalize()) != object.sha256 {
            return Err(ReaderCacheError::Integrity(format!(
                "{} received {received} of {expected} bytes or a different SHA-256",
                object.sha256
            )));
        }
        Ok(temporary)
    }

    /// Reserve `bytes` for one download, evicting unleased, unprotected
    /// objects in LRU order. Never evicts a pinned, held or protected object.
    ///
    /// NAN-4591, with a hot-window policy:
    /// - Background hydration keeps hot objects within the capacity minus
    ///   the cold-read reserve ([`crate::local_hot_window::cold_read_reserve`])
    ///   and the total within the capacity minus half of it (a new window
    ///   object evicts the oldest hot one, not recent cold reads), and
    ///   admits nothing at all while a foreground read waits out saturation.
    /// - A foreground read also evicts cold (non-hot) objects ahead of need
    ///   until half the reserve is free. The volume accountant counts
    ///   deleted objects until its next ~30 s walk, so its fence admits only
    ///   what was free at that walk; space freed just in time was invisible
    ///   to it, and every cold read at a full cache waited out the walk
    ///   (the large tenant: cold_queue_ms 27-40 s). Hot objects still go only when the
    ///   admission itself needs the room.
    /// - Capacity is estimated with this process's unwalked evictions
    ///   credited back, for every limit including the one hot objects are
    ///   evicted against, so neither one cold read nor the saturation retries
    ///   of a fenced one evict what the accountant cannot see yet; the fence
    ///   stays the hard limit.
    fn reserve(self: &Arc<Self>, bytes: u64) -> Result<Reservation, ReaderCacheError> {
        self.reserve_as(bytes, hydrating(), None)
    }

    /// [`Self::reserve`] for a caller that ran inside (`background`) or
    /// outside background hydration: task-locals do not reach the blocking
    /// threads most admissions run on, so callers there capture it first.
    ///
    /// `object` is the digest being admitted, if any: the background window
    /// limit applies only to window (hot) objects. NAN-4637: a background
    /// read of anything else (the identity observation backfill, scratch)
    /// counted against it and slid the window, evicting hot objects the next
    /// hydration pass downloaded again.
    fn reserve_as(
        self: &Arc<Self>,
        bytes: u64,
        background: bool,
        object: Option<&str>,
    ) -> Result<Reservation, ReaderCacheError> {
        let saturated = || ReaderCacheError::Saturated { needed_bytes: bytes };
        if background && self.foreground_waiting.load(Ordering::Acquire) > 0 {
            return Err(saturated());
        }
        let policy = self.hot_capacity.lock().unwrap_or_else(|e| e.into_inner()).clone();
        let cache_max = self.settings.max_bytes;
        // NAN-3139: a hot-window accounting failure degrades to the plain
        // cache budget; it must never fail ordinary cache admission.
        //
        // NAN-4591 (review of #8001): every limit here uses the CREDITED
        // figure. The accountant counts deleted-but-unwalked bytes as other
        // data, so against its raw figure each saturation retry of a fenced
        // read evicted another read's worth (the hot window first-to-last)
        // without the fence seeing any of it. The credited figure still
        // includes the statvfs headroom, and every write still passes the
        // fence (the accountant itself), so a stale credit can only admit a
        // reservation whose write the fence then refuses: it waits, it never
        // evicts again and never overfills the volume.
        let credited = match &policy {
            Some(policy) => {
                let (stored, in_flight) = {
                    let state = self.state();
                    (state.stored_bytes(), state.reserved)
                };
                match policy.capacities(stored, in_flight, self.eviction_credit()) {
                    Ok((_, credited)) => credited.min(cache_max),
                    Err(error) => {
                        crate::local_hot_window::warn_accounting_unavailable(&error);
                        cache_max
                    }
                }
            }
            None => cache_max,
        };
        let reserve = if policy.is_some() { self.cold_read_reserve() } else { 0 };
        // (admission limit, cold eviction target, hot-window limit).
        // Foreground: the whole cache, cold objects evicted ahead until half
        // the reserve is free. Background: the window (hot objects) up to
        // capacity minus the reserve, and the total up to capacity minus half
        // of it, so recent cold reads keep the other half of the reserve and
        // a new window object slides the window (evicts the oldest hot one)
        // instead of evicting them.
        let (max, evict_to, hot_limit) = if background {
            let total = credited.saturating_sub(reserve / 2);
            let in_window = policy.is_some() && object.is_some_and(|digest| self.state().hot.contains_key(digest));
            (total, total, in_window.then(|| credited.saturating_sub(reserve)))
        } else {
            (credited, credited.saturating_sub(reserve / 2), None)
        };
        if bytes > max || hot_limit.is_some_and(|limit| bytes > limit) {
            return Err(saturated());
        }
        self.with_global_lock(|| {
            let fits = |state: &State, used: u64, limit: u64| {
                used.saturating_add(state.reserved).saturating_add(bytes) <= limit
            };
            let hot_fits = |hot_used: u64| hot_limit.is_none_or(|limit| hot_used.saturating_add(bytes) <= limit);
            {
                let mut state = self.state();
                if fits(&state, state.stored_bytes(), evict_to) && (hot_limit.is_none() || hot_fits(state.hot_bytes())) {
                    state.reserved += bytes;
                    return Ok(());
                }
            }
            // Over the eviction target: refresh from disk (other processes
            // admit and evict in the same directory), then evict.
            let pinned = self.pinned_inodes()?;
            let mut state = self.state();
            self.refresh_index(&mut state, false)?;
            let mut candidates: Vec<(bool, i64, u64, (i64, i64), String)> = state
                .entries
                .iter()
                .filter(|(sha256, entry)| {
                    !state.protected.contains(*sha256)
                        && !state.holds.contains_key(*sha256)
                        && !pinned.contains(&(entry.stamp.dev, entry.stamp.inode))
                })
                .map(|(sha256, entry)| (state.hot.contains_key(sha256), *state.hot.get(sha256).unwrap_or(&0), entry.last_access, entry.stamp.modified, sha256.clone()))
                .collect();
            candidates.sort();
            let mut used = state.stored_bytes();
            let mut hot_used = if hot_limit.is_some() { state.hot_bytes() } else { 0 };
            if let Some(limit) = hot_limit {
                // Background with the window full: slide it first (oldest
                // hot objects, which also free total room), so recent cold
                // reads are evicted only if the total still does not fit.
                let mut over = hot_used.saturating_add(bytes).saturating_sub(limit);
                let mut slide = Vec::new();
                for (index, candidate) in candidates.iter().enumerate() {
                    if over == 0 {
                        break;
                    }
                    if candidate.0 {
                        slide.push(index);
                        over = over.saturating_sub(state.entries.get(&candidate.4).map_or(0, |entry| entry.stamp.bytes));
                    }
                }
                let first = slide.iter().rev().map(|&index| candidates.remove(index)).collect::<Vec<_>>();
                candidates.splice(0..0, first.into_iter().rev());
            }
            for (hot, _, _, _, sha256) in candidates {
                let needed = !fits(&state, used, max);
                let ahead = !hot && !fits(&state, used, evict_to);
                let window_full = !hot_fits(hot_used);
                if !needed && !ahead && !window_full {
                    break;
                }
                if !needed && !ahead && !hot {
                    // Only the window limit binds: keep recent cold reads.
                    continue;
                }
                match std::fs::remove_file(self.object_path(&sha256)) {
                    Ok(()) => {}
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                    Err(error) => return Err(error.into()),
                }
                self.drop_read_link(&sha256, &pinned)?;
                if let Some(entry) = state.entries.remove(&sha256) {
                    self.note_evicted(entry.stamp.bytes);
                    if hot {
                        hot_used = hot_used.saturating_sub(entry.stamp.bytes);
                    }
                }
                self.counters.evictions.fetch_add(1, Ordering::Relaxed);
                used = state.stored_bytes();
            }
            if !fits(&state, used, max) || !hot_fits(hot_used) {
                return Err(saturated());
            }
            state.reserved += bytes;
            Ok(())
        })?;
        Ok(Reservation {
            inner: self.clone(),
            bytes,
        })
    }

    /// Persist a verified temp as the canonical 0444 object.
    fn admit(&self, temporary: tempfile::NamedTempFile, object: &ReaderObjectRef) -> Result<(), ReaderCacheError> {
        temporary.as_file().sync_all()?;
        // Read-only before it gets its canonical name, so no scan ever sees a
        // writable canonical object.
        std::fs::set_permissions(temporary.path(), std::fs::Permissions::from_mode(OBJECT_MODE))?;
        let path = self.object_path(&object.sha256);
        self.with_global_lock(|| {
            match temporary.persist_noclobber(&path) {
                Ok(_) => {}
                Err(error) if error.error.kind() == std::io::ErrorKind::AlreadyExists => {
                    let existing_ok = FileStamp::read(&path)
                        .is_ok_and(|stamp| stamp.bytes == object.size_bytes && stamp.mode == OBJECT_MODE)
                        && crate::native::file_sha256(&path).is_ok_and(|digest| digest == object.sha256);
                    if !existing_ok {
                        self.counters.integrity_failures.fetch_add(1, Ordering::Relaxed);
                        tracing::error!(
                            tenant_id = %self.tenant_id,
                            sha256 = %object.sha256,
                            "reader_cache_integrity: concurrent admission left conflicting bytes; replacing"
                        );
                        std::fs::remove_file(&path)?;
                        error
                            .file
                            .persist_noclobber(&path)
                            .map_err(|error| ReaderCacheError::Io(error.error))?;
                    }
                }
                Err(error) => return Err(error.error.into()),
            }
            let stamp = FileStamp::read(&path)?;
            let mut state = self.state();
            let access = state.tick();
            state.entries.insert(
                object.sha256.clone(),
                Entry {
                    stamp,
                    last_access: access,
                    hits: 0,
                    // Admission verified the bytes (download or local copy fence).
                    verified_s: unix_now_seconds(),
                },
            );
            Ok(())
        })
    }
}

/// In-flight download bytes; released when the download ends either way.
struct Reservation {
    inner: Arc<Inner>,
    bytes: u64,
}

/// Capacity held for a scratch file (see [`ReaderObjectCache::scratch_write`]).
pub struct ScratchReservation {
    _reservation: Reservation,
}

impl std::fmt::Debug for ScratchReservation {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("ScratchReservation").field("bytes", &self._reservation.bytes).finish()
    }
}

/// One query's cold-byte account, drawn by several leases. NAN-3644: `limit`
/// is the heavy-read threshold: once the leases' uncached bytes together
/// exceed it, the next lease queues for a heavy slot (shared by the later
/// leases of this budget). It is never a refusal; the cache's ceiling is.
#[derive(Debug)]
pub struct ColdBudget {
    limit: u64,
    spent: AtomicU64,
    heavy: crate::query_timing::ColdScan,
}

impl ColdBudget {
    pub fn new(limit: u64) -> Self {
        Self { limit, spent: AtomicU64::new(0), heavy: crate::query_timing::ColdScan::default() }
    }

    pub fn limit(&self) -> u64 {
        self.limit
    }

    pub fn spent(&self) -> u64 {
        self.spent.load(Ordering::Relaxed)
    }

    /// Draw `bytes`; false (nothing drawn) when the total would pass
    /// `ceiling` (NAN-3644: the reader's ceiling, not this budget's
    /// threshold, which only decides whether the read is heavy).
    fn take_within(&self, bytes: u64, ceiling: u64) -> bool {
        self.spent.fetch_update(Ordering::AcqRel, Ordering::Acquire, |spent| {
            spent.checked_add(bytes).filter(|total| *total <= ceiling)
        }).is_ok()
    }

    fn refund(&self, bytes: u64) {
        let _ = self.spent.fetch_update(Ordering::AcqRel, Ordering::Acquire, |spent| Some(spent.saturating_sub(bytes)));
    }
}

/// A draw on a [`ColdBudget`], refunded unless its lease succeeded.
struct BudgetCharge<'a> {
    budget: &'a ColdBudget,
    bytes: u64,
    committed: bool,
}

impl Drop for BudgetCharge<'_> {
    fn drop(&mut self) {
        if !self.committed {
            self.budget.refund(self.bytes);
        }
    }
}

/// NAN-4138: one read's bounded wait for cache capacity. Each `wait` sleeps
/// a backoff (100 ms doubling to 2 s) while the budget lasts; it holds
/// nothing while asleep, and dropping the future (cancellation) ends it.
struct SaturationWait {
    started: Option<tokio::time::Instant>,
    budget: Duration,
    backoff: Duration,
    waits: u32,
}

impl SaturationWait {
    fn new(budget: Duration) -> Self {
        Self { started: None, budget, backoff: SATURATION_BACKOFF_FIRST, waits: 0 }
    }

    /// Sleep before the next attempt; false once the budget is spent.
    async fn wait(&mut self, tenant_id: &str, needed_bytes: u64) -> bool {
        let started = *self.started.get_or_insert_with(tokio::time::Instant::now);
        let Some(left) = self.budget.checked_sub(started.elapsed()).filter(|left| !left.is_zero()) else {
            tracing::warn!(tenant_id, needed_bytes, waited_ms = started.elapsed().as_millis() as u64, waits = self.waits,
                "reader_cache_saturated: capacity did not free up within the wait; giving up");
            return false;
        };
        if self.waits == 0 {
            tracing::info!(tenant_id, needed_bytes, budget_ms = self.budget.as_millis() as u64,
                "reader_cache_saturated: waiting for capacity instead of failing the read");
        }
        self.waits += 1;
        let sleep = self.backoff.min(left);
        self.backoff = (self.backoff * 2).min(SATURATION_BACKOFF_MAX);
        tokio::time::sleep(sleep).await;
        crate::query_timing::record(|p| p.cold_queue_ms += sleep.as_secs_f64() * 1000.0);
        true
    }
}

/// NAN-3714: await `work` until `deadline`; at the deadline, if `progress()`
/// grew since the last check, extend it by `stall` and keep waiting. Only a
/// `stall` with no progress at all ends in [`ReaderCacheError::FetchTimeout`].
async fn wait_while_progressing<T>(
    work: impl std::future::Future<Output = T>,
    deadline: tokio::time::Instant,
    stall: Duration,
    progress: impl Fn() -> u64,
) -> Result<T, ReaderCacheError> {
    let mut work = std::pin::pin!(work);
    let (mut deadline, mut seen) = (deadline, progress());
    loop {
        match tokio::time::timeout_at(deadline, work.as_mut()).await {
            Ok(output) => return Ok(output),
            Err(_) => {
                let now = progress();
                if now <= seen {
                    return Err(ReaderCacheError::FetchTimeout);
                }
                seen = now;
                deadline = tokio::time::Instant::now() + stall;
            }
        }
    }
}

/// NAN-3644: a lease's share of its request's cold-progress total, taken
/// back (less what it did read) if the lease fails or is cancelled, so the
/// stream's "X of Y" never waits on bytes nobody will fetch.
struct ProgressCharge<'a> {
    scan: Option<&'a crate::query_timing::ColdScan>,
    expected: u64,
    read: AtomicU64,
}

impl ProgressCharge<'_> {
    fn read(&self, bytes: u64) {
        self.read.fetch_add(bytes, Ordering::Relaxed);
        if let Some(scan) = self.scan {
            scan.read_bytes.fetch_add(bytes, Ordering::Relaxed);
        }
    }
}

impl Drop for ProgressCharge<'_> {
    fn drop(&mut self) {
        if let Some(scan) = self.scan {
            let unread = self.expected.saturating_sub(self.read.load(Ordering::Relaxed));
            if unread > 0 {
                let _ = scan.total_bytes.fetch_update(Ordering::AcqRel, Ordering::Acquire, |total| Some(total.saturating_sub(unread)));
            }
        }
    }
}

impl Drop for Reservation {
    fn drop(&mut self) {
        let mut state = self.inner.state();
        state.reserved = state.reserved.saturating_sub(self.bytes);
    }
}

/// Keeps this call's objects from in-process eviction until they are pinned.
struct HoldGuard {
    inner: Arc<Inner>,
    sha256s: Vec<String>,
}

impl HoldGuard {
    fn new(inner: &Arc<Inner>, objects: &[ReaderObjectRef]) -> Self {
        let sha256s: Vec<String> = objects.iter().map(|object| object.sha256.clone()).collect();
        let mut state = inner.state();
        for sha256 in &sha256s {
            *state.holds.entry(sha256.clone()).or_insert(0) += 1;
        }
        Self {
            inner: inner.clone(),
            sha256s,
        }
    }
}

impl Drop for HoldGuard {
    fn drop(&mut self) {
        let mut state = self.inner.state();
        for sha256 in &self.sha256s {
            if let Some(count) = state.holds.get_mut(sha256) {
                *count -= 1;
                if *count == 0 {
                    state.holds.remove(sha256);
                }
            }
        }
    }
}

/// RAII pin: while alive the leased objects cannot be evicted by any process
/// (hard links under `pins/<lease>/` plus a held flock, as the hot tail).
pub struct ReaderCacheLease {
    inner: Arc<Inner>,
    directory: PathBuf,
    file: Option<File>,
    sha256s: Vec<String>,
    paths: Vec<PathBuf>,
    hits: usize,
    misses: usize,
    fetched_bytes: u64,
    ensure_ms: u64,
    /// Counted in `State::live` (a completed lease).
    live: bool,
    /// NAN-3644: the heavy cold-read slot this lease's fetch took (shared
    /// with its request), held until the pins are released.
    heavy: Option<Arc<tokio::sync::OwnedSemaphorePermit>>,
}

impl ReaderCacheLease {
    pub fn hits(&self) -> usize {
        self.hits
    }

    pub fn misses(&self) -> usize {
        self.misses
    }

    pub fn fetched_bytes(&self) -> u64 {
        self.fetched_bytes
    }

    pub fn ensure_ms(&self) -> u64 {
        self.ensure_ms
    }

    /// The path a reader opens for `sha256`: the stable `reads/<sha256>.bin`
    /// when it is the very inode this lease pins (NAN-4222: chDB's Parquet
    /// metadata cache is keyed by path, so a stable path reuses the parsed
    /// footer across statements), else the statement-private hard link.
    /// Either way canonical replacement or retirement cannot redirect an
    /// already selected read to a different inode: a read link is only ever
    /// replaced while no lease pins its inode, and this lease pins it.
    pub fn pinned_path(&self, sha256: &str) -> PathBuf {
        let private = self.directory.join(format!("{sha256}.bin"));
        let read = self.inner.read_path(sha256);
        match (std::fs::symlink_metadata(&private), std::fs::symlink_metadata(&read)) {
            (Ok(pin), Ok(stable)) if (pin.dev(), pin.ino()) == (stable.dev(), stable.ino()) => read,
            _ => private,
        }
    }

    /// Canonical object paths, de-duplicated, in request order.
    pub fn paths(&self) -> &[PathBuf] {
        &self.paths
    }
}

impl std::fmt::Debug for ReaderCacheLease {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ReaderCacheLease")
            .field("objects", &self.paths.len())
            .field("hits", &self.hits)
            .field("misses", &self.misses)
            .field("fetched_bytes", &self.fetched_bytes)
            .field("ensure_ms", &self.ensure_ms)
            .finish()
    }
}

impl Drop for ReaderCacheLease {
    fn drop(&mut self) {
        if self.live {
            let mut state = self.inner.state();
            for sha256 in &self.sha256s {
                if let Some(count) = state.live.get_mut(sha256) {
                    *count = count.saturating_sub(1);
                    if *count == 0 {
                        state.live.remove(sha256);
                    }
                }
            }
        }
        // Remove the pin tree under the global fence so an eviction scan never
        // walks a half-removed lease.
        let file = self.file.take();
        let removed = self.inner.with_global_lock(|| {
            if let Some(file) = &file {
                FileExt::unlock(file)?;
            }
            match std::fs::remove_dir_all(&self.directory) {
                Ok(()) => Ok(()),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
                Err(error) => Err(error.into()),
            }
        });
        if let Err(error) = removed {
            tracing::warn!(error = %error, "reader cache lease removal failed; reclaimed at next open");
        }
        // LRU is keyed on the last lease release (true access time).
        let mut state = self.inner.state();
        let access = state.tick();
        for sha256 in &self.sha256s {
            if let Some(entry) = state.entries.get_mut(sha256) {
                entry.last_access = access;
            }
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::sync::atomic::{AtomicBool, AtomicUsize};

    const BUCKET: &str = "bucket-a";
    const PREFIX: &str = "tenants/t1/table";

    /// In-memory R2 stand-in with fault injection (after hot_tail_slow_path's FakeR2).
    #[derive(Default)]
    struct FakeSource {
        objects: Mutex<BTreeMap<String, Vec<u8>>>,
        /// Served bytes differ from the stored ones (`Some(n)` = next n reads only).
        corrupt: Mutex<BTreeMap<String, Option<usize>>>,
        overrides: Mutex<BTreeMap<String, Vec<u8>>>,
        down: AtomicBool,
        delay_ms: AtomicU64,
        reads: AtomicUsize,
    }

    #[async_trait::async_trait]
    impl ReaderObjectSource for FakeSource {
        async fn stream_object(
            &self,
            object: &ReaderObjectRef,
            sink: &mut (dyn for<'b> FnMut(&'b [u8]) -> anyhow::Result<()> + Send),
        ) -> anyhow::Result<()> {
            self.reads.fetch_add(1, Ordering::SeqCst);
            let delay = self.delay_ms.load(Ordering::SeqCst);
            if delay > 0 {
                tokio::time::sleep(Duration::from_millis(delay)).await;
            }
            if self.down.load(Ordering::SeqCst) {
                anyhow::bail!("R2 unreachable");
            }
            let mut bytes = match self.overrides.lock().unwrap().get(&object.source_uri) {
                Some(bytes) => bytes.clone(),
                None => self
                    .objects
                    .lock()
                    .unwrap()
                    .get(&object.source_uri)
                    .cloned()
                    .context("NoSuchKey")?,
            };
            let mut corrupt = self.corrupt.lock().unwrap();
            if let Some(remaining) = corrupt.get_mut(&object.source_uri) {
                bytes[0] ^= 0xff;
                if let Some(count) = remaining {
                    *count -= 1;
                    if *count == 0 {
                        corrupt.remove(&object.source_uri);
                    }
                }
            }
            drop(corrupt);
            if let Some(range) = &object.range {
                bytes = bytes[usize::try_from(range.start)?..usize::try_from(range.end)?].to_vec();
            }
            for chunk in bytes.chunks(7) {
                sink(chunk)?;
            }
            Ok(())
        }
    }

    impl FakeSource {
        fn put(&self, name: &str, len: usize) -> ReaderObjectRef {
            let bytes: Vec<u8> = name.bytes().cycle().take(len).collect();
            let object = ReaderObjectRef {
                range: None,
                source_uri: format!("s3://{BUCKET}/{PREFIX}/data/{name}.bin"),
                sha256: hex::encode(Sha256::digest(&bytes)),
                size_bytes: len as u64,
            };
            self.objects.lock().unwrap().insert(object.source_uri.clone(), bytes);
            object
        }

        fn reads(&self) -> usize {
            self.reads.load(Ordering::SeqCst)
        }
    }

    fn settings(root: &Path, max_bytes: u64) -> ReaderObjectCacheSettings {
        ReaderObjectCacheSettings {
            root: root.to_path_buf(),
            max_bytes,
            query_max_bytes: 1 << 20,
            fetch_concurrency: 4,
            fetch_deadline: Duration::from_secs(5),
        }
    }

    fn open(root: &Path, max_bytes: u64, source: &Arc<FakeSource>) -> ReaderObjectCache {
        ReaderObjectCache::open(settings(root, max_bytes), "t1", BUCKET, PREFIX, source.clone())
            .unwrap()
    }

    fn fixture() -> (tempfile::TempDir, Arc<FakeSource>) {
        (tempfile::tempdir().unwrap(), Arc::new(FakeSource::default()))
    }


    // NAN-3866: paused clock -- the rate is measured on the pacing clock, so
    // CPU load (hashing, fsync) cannot pull it under the bound.
    #[tokio::test(start_paused = true)]
    async fn hot_window_lab_multiday_rate_and_large_object_budget() {
        // Three daily objects, each over the foreground cold budget. A source
        // with the same chunk pacing as R2 exercises dedupe's spawned task scope.
        struct PacedSource(Arc<FakeSource>);
        #[async_trait::async_trait]
        impl ReaderObjectSource for PacedSource {
            async fn stream_object(
                &self,
                object: &ReaderObjectRef,
                sink: &mut (dyn for<'b> FnMut(&'b [u8]) -> anyhow::Result<()> + Send),
            ) -> anyhow::Result<()> {
                let bytes = self.0.objects.lock().unwrap()[&object.source_uri].clone();
                for chunk in bytes.chunks(64 * 1024) {
                    if let Ok(pacing) = HYDRATE_RATE.try_with(Arc::clone) {
                        pacing.pace(chunk.len()).await;
                    }
                    sink(chunk)?;
                }
                Ok(())
            }
        }
        let (root, source) = fixture();
        let candidates = (0..3)
            .map(|day| {
                (
                    day * 86_400_000_000_i64,
                    512 * 1024,
                    source.put(&format!("day-{day}"), 512 * 1024),
                )
            })
            .collect();
        let objects = crate::local_hot_window::select(candidates, 0, 4 * 1024 * 1024)
            .into_iter()
            .map(|(_, _, object)| object)
            .collect::<Vec<_>>();
        assert_eq!(objects.len(), 3);
        let mut config = settings(root.path(), 4 * 1024 * 1024);
        config.query_max_bytes = 1024;
        let cache = ReaderObjectCache::open(
            config.clone(),
            "t1",
            BUCKET,
            PREFIX,
            Arc::new(PacedSource(source.clone())),
        )
        .unwrap();
        // NAN-3644: a foreground read over the 1 KiB threshold would now run
        // (queued for a heavy slot); background hydration never takes one.
        assert!(cache.interactive_cold_ceiling() >= 512 * 1024);
        let cap = 1024 * 1024;
        let started = tokio::time::Instant::now();
        for object in &objects {
            drop(
                background_hydrate(cap, cache.ensure_local(std::slice::from_ref(object)))
                    .await
                    .unwrap(),
            );
        }
        let rate = (3 * 512 * 1024) as f64 / started.elapsed().as_secs_f64();
        println!("hot-window lab: three daily parts, rate={rate:.0} B/s, cap={cap} B/s");
        assert!(rate >= cap as f64 * 0.80 && rate <= cap as f64 * 1.05);
        drop(cache);
        let resumed =
            ReaderObjectCache::open(config, "t1", BUCKET, PREFIX, source.clone()).unwrap();
        for object in &objects {
            let lease = resumed
                .ensure_local(std::slice::from_ref(object))
                .await
                .unwrap();
            assert_eq!(lease.fetched_bytes(), 0);
        }
        assert_eq!(source.reads(), 0);
    }
    #[tokio::test]
    async fn hot_window_foreground_interrupts_background_pacing() {
        let pacing = Arc::new(HydratePacing::new(1, HydrateBucket::new(1)));
        let task = { let pacing = pacing.clone(); tokio::spawn(async move { pacing.pace(100).await }) };
        tokio::task::yield_now().await;
        pacing.rate.store(0, Ordering::Relaxed);
        pacing.foreground.notify_one();
        tokio::time::timeout(Duration::from_millis(100), task).await.unwrap().unwrap();
    }

    /// NAN-3164: the bucket charges arrival time, not transfer + sleep.
    #[test]
    fn hydrate_bucket_never_adds_sleep_to_a_slower_stream() {
        let bucket = HydrateBucket::new(32 << 20);
        let chunk = 4 << 20; // 125 ms of tokens at 32 MiB/s
        let mut now = Instant::now();
        let mut slept = Duration::ZERO;
        // A stream delivering 4 MiB every 500 ms (8 MiB/s): never paced.
        for _ in 0..20 {
            now += Duration::from_millis(500);
            slept += bucket.reserve(chunk, now);
        }
        assert_eq!(slept, Duration::ZERO, "slow stream must not be slowed further");
        // Exactly at the cap: 4 MiB every 125 ms, still no sleep.
        for _ in 0..20 {
            now += Duration::from_millis(125);
            slept += bucket.reserve(chunk, now);
        }
        assert!(slept <= Duration::from_millis(1), "{slept:?}");
    }

    #[test]
    fn hydrate_bucket_holds_aggregate_rate_across_streams() {
        let rate = 32 << 20;
        let bucket = HydrateBucket::new(rate);
        let start = Instant::now();
        let mut now = start;
        let mut bytes = 0_u64;
        // Four instant streams interleaving 1 MiB chunks: the waits they are
        // told to take add up to the cap (each waits, then sends again).
        for _ in 0..64 {
            for _stream in 0..4 {
                let wait = bucket.reserve(1 << 20, now);
                bytes += 1 << 20;
                now = now.max(now + wait);
            }
        }
        let rate_seen = bytes as f64 / now.duration_since(start).as_secs_f64();
        assert!(rate_seen <= rate as f64 * 1.05 && rate_seen >= rate as f64 * 0.95, "{rate_seen}");
        // Lowering the rate (query backoff) applies on the next chunk.
        bucket.set_rate(rate / 4);
        let wait = bucket.reserve(1 << 20, now);
        assert!(wait >= Duration::from_millis(100), "{wait:?}");
        bucket.set_rate(0);
        assert_eq!(bucket.reserve(1 << 30, now), Duration::ZERO, "rate 0 is unpaced");
    }

    #[tokio::test]
    async fn background_paths_require_verified_stamps_and_never_wait_for_cache_state() {
        let (root, source) = fixture();
        let cache = open(root.path(), 300, &source);
        let object = source.put("background", 100);
        assert!(cache.verified_background_path(&object.sha256).is_none());
        drop(cache.ensure_local(std::slice::from_ref(&object)).await.unwrap());
        let path = cache.object_path(&object.sha256);
        // Make the mtime settled without sleeping, then verify the new stamp.
        File::open(&path).unwrap().set_times(std::fs::FileTimes::new()
            .set_modified(std::time::UNIX_EPOCH + Duration::from_secs(1))).unwrap();
        drop(cache.ensure_local(std::slice::from_ref(&object)).await.unwrap());
        assert_eq!(cache.verified_background_path(&object.sha256), Some(path.clone()));
        let other_tenant = ReaderObjectCache::open(settings(root.path(), 300), "t2", BUCKET, PREFIX, source.clone()).unwrap();
        assert!(other_tenant.verified_background_path(&object.sha256).is_none(), "a digest verified by t1 is unavailable to t2");
        {
            let _state = cache.inner.state();
            assert!(cache.verified_background_path(&object.sha256).is_none(), "background never waits on cache state");
        }
        let inherited = open(root.path(), 300, &source);
        assert!(inherited.verified_background_path(&object.sha256).is_none(), "disk presence is not verification");
        File::open(&path).unwrap().set_times(std::fs::FileTimes::new()
            .set_modified(std::time::UNIX_EPOCH + Duration::from_secs(2))).unwrap();
        assert!(cache.verified_background_path(&object.sha256).is_none(), "changed stamps require a lease");
        cache.inner.refresh_index(&mut cache.inner.state(), false).unwrap();
        assert!(cache.verified_background_path(&object.sha256).is_none(), "index refresh cannot verify changed bytes");
    }

    #[tokio::test]
    async fn hot_window_evicts_cold_then_oldest_hot_and_keeps_leases() {
        let (root, source) = fixture();
        let cache = open(root.path(), 300, &source);
        let old = source.put("old", 100);
        let new = source.put("new", 100);
        let cold = source.put("cold", 100);
        for object in [&old, &new, &cold] { drop(cache.ensure_local(std::slice::from_ref(object)).await.unwrap()); }
        cache.set_hot(HashMap::from([(old.sha256.clone(), 10), (new.sha256.clone(), 20)]));
        let foreground = source.put("foreground", 100);
        let lease = cache.ensure_local(std::slice::from_ref(&foreground)).await.unwrap();
        assert!(!cache.object_path(&cold.sha256).exists());
        assert!(cache.object_path(&old.sha256).exists());
        let next = source.put("next", 100);
        cache.set_hot(HashMap::from([(old.sha256.clone(), 10), (new.sha256.clone(), 20), (foreground.sha256.clone(), 1)]));
        drop(cache.ensure_local(std::slice::from_ref(&next)).await.unwrap());
        assert!(!cache.object_path(&old.sha256).exists(), "oldest unleased hot object goes first");
        assert!(cache.object_path(&new.sha256).exists());
        assert_eq!(std::fs::read(lease.pinned_path(&foreground.sha256)).unwrap().len(), 100);
    }

    /// NAN-4154: query leases under pressure take every evictable non-hot
    /// object (plain LRU) before any hot-window object; hot parts go only
    /// when nothing else is evictable.
    #[tokio::test]
    async fn lease_pressure_evicts_every_cold_object_before_any_hot_one() {
        let (root, source) = fixture();
        let cache = open(root.path(), 1_000, &source);
        let hot = ["h1", "h2", "h3", "h4"].map(|name| source.put(name, 100));
        let cold = ["c1", "c2", "c3", "c4"].map(|name| source.put(name, 100));
        for object in hot.iter().chain(cold.iter()) {
            drop(cache.ensure_local(std::slice::from_ref(object)).await.unwrap());
        }
        cache.set_hot(hot.iter().enumerate().map(|(end, object)| (object.sha256.clone(), end as i64)).collect());
        // A 7-day query leases four new objects at once: 1,200 bytes wanted
        // of a 1,000-byte cache holding 800, all four cold objects evictable.
        let wanted = ["q1", "q2", "q3", "q4"].map(|name| source.put(name, 100));
        let lease = cache.ensure_local(&wanted).await.unwrap();
        for object in &hot {
            assert!(cache.object_path(&object.sha256).exists(), "a hot-window object was evicted while cold ones were evictable");
        }
        assert!(cold.iter().filter(|object| cache.object_path(&object.sha256).exists()).count() <= 2);
        // Still leased, more pressure: the remaining cold objects go first,
        // then (nothing else evictable) the oldest hot object.
        let more = ["q5", "q6", "q7"].map(|name| source.put(name, 100));
        let _more = cache.ensure_local(&more).await.unwrap();
        assert!(cold.iter().all(|object| !cache.object_path(&object.sha256).exists()));
        assert!(!cache.object_path(&hot[0].sha256).exists(), "oldest hot goes only once nothing else is evictable");
        assert!(cache.object_path(&hot[3].sha256).exists());
        drop(lease);
    }

    /// NAN-4591: while a foreground read waits out saturation, background
    /// hydration admits nothing (it defers at once and its pass retries
    /// later), so the capacity that frees goes to the search, which then
    /// completes within one backoff step.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn background_hydration_yields_while_a_foreground_read_waits() {
        let (root, source) = fixture();
        let cache = open(root.path(), 1_000, &source);
        cache.set_saturation_wait(Duration::from_secs(10));
        let blocker = cache.reserve_scratch(900).unwrap();
        let wanted = source.put("wanted", 300);
        let waiting = tokio::spawn({
            let (cache, wanted) = (cache.clone(), wanted.clone());
            async move { cache.ensure_local(std::slice::from_ref(&wanted)).await }
        });
        let deadline = Instant::now() + Duration::from_secs(5);
        while cache.inner.foreground_waiting.load(Ordering::Acquire) == 0 && Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        assert_eq!(cache.inner.foreground_waiting.load(Ordering::Acquire), 1, "the search is waiting");
        drop(blocker);
        let warming = source.put("warming", 100);
        let deferred = background_hydrate(1 << 30, cache.ensure_local(std::slice::from_ref(&warming))).await;
        assert!(matches!(deferred, Err(ReaderCacheError::Saturated { .. })), "background must defer: {deferred:?}");
        let freed = Instant::now();
        let lease = tokio::time::timeout(Duration::from_secs(5), waiting).await.unwrap().unwrap().unwrap();
        assert!(freed.elapsed() < Duration::from_millis(2_500), "one backoff step, took {:?}", freed.elapsed());
        assert_eq!(lease.fetched_bytes(), 300);
        assert_eq!(cache.inner.foreground_waiting.load(Ordering::Acquire), 0);
        drop(background_hydrate(1 << 30, cache.ensure_local(std::slice::from_ref(&warming))).await.unwrap());
    }

    /// NAN-4591 (review of #8001): cold demand beyond the fence's room
    /// between accountant walks. The accountant never re-walks here, as
    /// between two 30 s walks, so it never sees an eviction. The large tenant's one-fifth
    /// reserve, window full at capacity minus the reserve. The saturation
    /// retries of a fenced read must not evict the hot window, and evictions
    /// stay bounded by the cold bytes requested. (Against the uncredited
    /// figure every retry evicted another read's worth, oldest hot first,
    /// until the cache was empty.)
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn fenced_cold_reads_beyond_the_walk_never_evict_the_hot_window() {
        const MIB: u64 = 1 << 20;
        let (root, source) = fixture();
        let volume = 10 * MIB;
        let _accountant = nanosiem_lake_cell::volume_usage::start_with(
            root.path().to_path_buf(), vec![root.path().to_path_buf()],
            nanosiem_lake_cell::volume_usage::AccountantConfig::every(Duration::from_secs(3600)),
        ).unwrap();
        let cache = open(root.path(), volume, &source);
        cache.set_hot_capacity(crate::local_hot_window::Settings {
            root: root.path().to_path_buf(), hours: 72, bytes_per_second: 0,
            reserve_bytes: Some(0), max_bytes: volume, schedule: Default::default(), persistent: false,
        });
        cache.set_cold_read_reserve(volume / crate::local_hot_window::COLD_READ_RESERVE_DIVISOR);
        // Eight window objects, just under capacity minus the reserve (the
        // volume's directories take a few blocks).
        let hot = (0..8).map(|n| source.put(&format!("hot-{n}"), (MIB - 64 * 1024) as usize)).collect::<Vec<_>>();
        cache.set_hot(hot.iter().enumerate().map(|(end, object)| (object.sha256.clone(), end as i64 + 1)).collect());
        for object in &hot {
            drop(background_hydrate(1 << 30, cache.ensure_local(std::slice::from_ref(object))).await.unwrap());
        }
        let resident = |objects: &[ReaderObjectRef]| objects.iter().filter(|o| cache.object_path(&o.sha256).exists()).count();
        assert_eq!(resident(&hot), 8, "the window fits: {:?}", cache.stats());
        let evictions_before = cache.stats().evictions;
        cache.set_saturation_wait(Duration::from_millis(1_000));
        let mut outcomes = Vec::new();
        for round in 0..4 {
            let cold = (0..2).map(|n| source.put(&format!("cold-{round}-{n}"), MIB as usize)).collect::<Vec<_>>();
            let outcome = cache.ensure_local(&cold).await.map(drop);
            outcomes.push((round, outcome.is_ok(), resident(&hot), cache.stats().evictions - evictions_before));
        }
        assert!(outcomes[0].1, "the reserve takes the first cold read: {outcomes:?}");
        for (round, _, hot_left, _) in &outcomes {
            assert_eq!(*hot_left, 8, "round {round}: a fenced cold read evicted the hot window: {outcomes:?}");
        }
        let (_, _, _, evictions) = outcomes[3];
        assert!(evictions <= 2 * 4, "evictions are bounded by the cold objects requested: {outcomes:?}");
    }

    /// NAN-4591: with a hot-window policy, background hydration never admits
    /// into the cold-read reserve, while a foreground read may use all of it.
    #[tokio::test]
    async fn background_hydration_stops_at_the_cold_read_reserve() {
        let (root, source) = fixture();
        let cache = open(root.path(), 1 << 20, &source);
        cache.set_hot_capacity(crate::local_hot_window::Settings {
            root: root.path().to_path_buf(), hours: 72, bytes_per_second: 0,
            reserve_bytes: Some(0), max_bytes: 1 << 40, schedule: Default::default(), persistent: false,
        });
        let reserve = cache.cold_read_reserve();
        assert_eq!(reserve, 512 << 10, "small caches: half");
        let hot = (0..4).map(|n| source.put(&format!("hot-{n}"), 128 << 10)).collect::<Vec<_>>();
        for object in &hot {
            drop(background_hydrate(1 << 30, cache.ensure_local(std::slice::from_ref(object))).await.unwrap());
        }
        cache.set_hot(hot.iter().enumerate().map(|(end, object)| (object.sha256.clone(), end as i64 + 1)).collect());
        // The window is at capacity minus the reserve: one more background
        // window object evicts the oldest hot one rather than entering the
        // reserve.
        let more = source.put("hot-more", 128 << 10);
        cache.set_hot(hot.iter().chain([&more]).enumerate().map(|(end, object)| (object.sha256.clone(), end as i64 + 1)).collect());
        drop(background_hydrate(1 << 30, cache.ensure_local(std::slice::from_ref(&more))).await.unwrap());
        assert!(cache.stats().stored_bytes <= (1 << 20) - reserve, "{:?}", cache.stats());
        assert!(!cache.object_path(&hot[0].sha256).exists());
        // A foreground read uses the reserve without evicting the window.
        let cold = (0..3).map(|n| source.put(&format!("cold-{n}"), 128 << 10)).collect::<Vec<_>>();
        let lease = cache.ensure_local(&cold).await.unwrap();
        for object in &hot[1..] {
            assert!(cache.object_path(&object.sha256).exists(), "a cold read evicted the window");
        }
        drop(lease);
    }

    /// NAN-4591 (review of #8001): a window object admitted in the
    /// background slides the window (evicts the oldest hot object) instead
    /// of evicting recent cold reads, so a repeated 7 d search finds its
    /// older parts still local after a prewarm or hydration pass.
    #[tokio::test]
    async fn a_sliding_window_keeps_recent_cold_reads() {
        let (root, source) = fixture();
        let cache = open(root.path(), 1 << 20, &source);
        cache.set_hot_capacity(crate::local_hot_window::Settings {
            root: root.path().to_path_buf(), hours: 72, bytes_per_second: 0,
            reserve_bytes: Some(0), max_bytes: 1 << 40, schedule: Default::default(), persistent: false,
        });
        assert_eq!(cache.cold_read_reserve(), 512 << 10);
        let hot = (0..5).map(|n| source.put(&format!("hot-{n}"), 128 << 10)).collect::<Vec<_>>();
        let window = |objects: &[ReaderObjectRef]| {
            objects.iter().enumerate().map(|(end, object)| (object.sha256.clone(), end as i64 + 1)).collect()
        };
        cache.set_hot(window(&hot[..4]));
        for object in &hot[..4] {
            drop(background_hydrate(1 << 30, cache.ensure_local(std::slice::from_ref(object))).await.unwrap());
        }
        let cold = (0..2).map(|n| source.put(&format!("cold-{n}"), 128 << 10)).collect::<Vec<_>>();
        drop(cache.ensure_local(&cold).await.unwrap());
        cache.set_hot(window(&hot));
        drop(background_hydrate(1 << 30, cache.ensure_local(std::slice::from_ref(&hot[4]))).await.unwrap());
        assert!(!cache.object_path(&hot[0].sha256).exists(), "the window slid");
        for object in hot[1..].iter().chain(&cold) {
            assert!(cache.object_path(&object.sha256).exists(), "{:?}", cache.stats());
        }
    }

    /// NAN-4637: a background read of an object outside the window (the
    /// identity observation backfill) with the window full evicts no hot
    /// object. It counted against the window limit and slid the window,
    /// and the next hydration pass downloaded those objects again.
    #[tokio::test]
    async fn background_reads_outside_the_window_never_slide_it() {
        let (root, source) = fixture();
        let cache = open(root.path(), 1 << 20, &source);
        cache.set_hot_capacity(crate::local_hot_window::Settings {
            root: root.path().to_path_buf(), hours: 72, bytes_per_second: 0,
            reserve_bytes: Some(0), max_bytes: 1 << 40, schedule: Default::default(), persistent: false,
        });
        assert_eq!(cache.cold_read_reserve(), 512 << 10);
        let hot = (0..4).map(|n| source.put(&format!("hot-{n}"), 128 << 10)).collect::<Vec<_>>();
        cache.set_hot(hot.iter().enumerate().map(|(end, object)| (object.sha256.clone(), end as i64 + 1)).collect());
        for object in &hot {
            drop(background_hydrate(1 << 30, cache.ensure_local(std::slice::from_ref(object))).await.unwrap());
        }
        // The window is full (capacity minus the reserve). Three backfill
        // reads: the first two fit the background total (capacity minus
        // half the reserve); the third evicts the oldest of them.
        let backfill = (0..3).map(|n| source.put(&format!("identity-{n}"), 128 << 10)).collect::<Vec<_>>();
        for object in &backfill {
            drop(background_maintenance(cache.ensure_local(std::slice::from_ref(object))).await.unwrap());
        }
        for object in &hot {
            assert!(cache.object_path(&object.sha256).exists(), "a backfill read slid the window: {:?}", cache.stats());
        }
        assert!(!cache.object_path(&backfill[0].sha256).exists(), "the total limit still binds, cold first");
        assert!(cache.object_path(&backfill[2].sha256).exists());
    }

    #[tokio::test]
    async fn hot_window_volume_pressure_shrinks_warm_cache_oldest_first() {
        let (root, source) = fixture();
        let cache = open(root.path(), 1 << 20, &source);
        let old = source.put("old", 8192);
        let new = source.put("new", 8192);
        for object in [&old, &new] {
            drop(cache.ensure_local(std::slice::from_ref(object)).await.unwrap());
        }
        cache.set_hot(HashMap::from([(old.sha256.clone(), 10), (new.sha256.clone(), 20)]));
        let usage = nanosiem_lake_cell::volume_usage::directory_bytes(root.path()).unwrap();
        cache.set_hot_capacity(crate::local_hot_window::Settings {
            root: root.path().to_path_buf(), hours: 72, bytes_per_second: 0,
            reserve_bytes: Some(0), max_bytes: usage + 4096, schedule: Default::default(), persistent: false,
        });
        std::fs::write(root.path().join("ingest-scratch"), vec![0; 8192]).unwrap();
        cache.trim_pressure().await.unwrap();
        assert!(!cache.object_path(&old.sha256).exists());
        assert!(cache.object_path(&new.sha256).exists());
        assert!(nanosiem_lake_cell::volume_usage::directory_bytes(root.path()).unwrap() <= usage + 4096);
        // Growth consumes the last headroom; a held newer object must survive.
        let lease = cache.ensure_local(std::slice::from_ref(&new)).await.unwrap();
        std::fs::write(root.path().join("ingest-scratch"), vec![0; 32768]).unwrap();
        cache.trim_pressure().await.unwrap();
        assert!(cache.object_path(&new.sha256).exists());
        let next = source.put("next", 8192);
        cache.set_saturation_wait(Duration::from_millis(200));
        assert!(cache.ensure_local(std::slice::from_ref(&next)).await.is_err());
        drop(lease);
    }

    /// NAN-4138, the live failure: an hourly merge's scratch fills the
    /// hot-window volume and a search's object cannot be admitted. The read
    /// waits; when the scratch goes (merge committed), it completes. The
    /// volume never passes its target while it waits or after.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn search_waits_out_merge_scratch_volume_pressure() {
        let (root, source) = fixture();
        let cache = open(root.path(), 1 << 20, &source);
        let held = source.put("held", 8192);
        let lease = cache.ensure_local(std::slice::from_ref(&held)).await.unwrap();
        let usage = nanosiem_lake_cell::volume_usage::directory_bytes(root.path()).unwrap();
        let limit = usage + 16384;
        cache.set_hot_capacity(crate::local_hot_window::Settings {
            root: root.path().to_path_buf(), hours: 72, bytes_per_second: 0,
            reserve_bytes: Some(0), max_bytes: limit, schedule: Default::default(), persistent: false,
        });
        let scratch = root.path().join("merge-scratch");
        std::fs::write(&scratch, vec![0; 16384]).unwrap();
        cache.set_saturation_wait(Duration::from_secs(30));
        let wanted = source.put("wanted", 8192);
        let waiting = tokio::spawn({
            let (cache, wanted) = (cache.clone(), wanted.clone());
            async move { cache.ensure_local(std::slice::from_ref(&wanted)).await }
        });
        for _ in 0..6 {
            tokio::time::sleep(Duration::from_millis(50)).await;
            assert!(!waiting.is_finished(), "the search waits out the pressure");
            assert!(nanosiem_lake_cell::volume_usage::directory_bytes(root.path()).unwrap() <= limit + 4096);
        }
        std::fs::remove_file(&scratch).unwrap();
        let wanted_lease = tokio::time::timeout(Duration::from_secs(10), waiting).await.unwrap().unwrap().unwrap();
        assert!(wanted_lease.pinned_path(&wanted.sha256).exists());
        assert!(lease.pinned_path(&held.sha256).exists(), "the held object was never evicted");
        assert!(nanosiem_lake_cell::volume_usage::directory_bytes(root.path()).unwrap() <= limit);
    }

    /// NAN-3139: in the jailed query process the volume accountant was
    /// unreachable (seccomp EPERM on socket(AF_UNIX)) and every admission
    /// failed with "reader cache I/O failed". An unreachable accountant must
    /// degrade to the plain cache budget, never fail ordinary admission.
    #[tokio::test]
    async fn hot_window_unreachable_accountant_still_admits_within_budget() {
        let (root, source) = fixture();
        // A stale accountant socket: it exists, but nothing answers.
        drop(std::os::unix::net::UnixListener::bind(
            root.path().join(nanosiem_lake_cell::volume_usage::SOCKET),
        ).unwrap());
        assert!(nanosiem_lake_cell::volume_usage::usage(root.path()).is_err());
        let cache = open(root.path(), 1 << 20, &source);
        cache.set_hot_capacity(crate::local_hot_window::Settings {
            root: root.path().to_path_buf(), hours: 72, bytes_per_second: 0,
            reserve_bytes: Some(0), max_bytes: 1 << 30, schedule: Default::default(), persistent: false,
        });
        cache.trim_pressure().await.unwrap();
        let object = source.put("admitted", 8192);
        drop(cache.ensure_local(std::slice::from_ref(&object)).await.unwrap());
        assert!(cache.object_path(&object.sha256).exists());
        let (_, _scratch) = cache.scratch_write(4096, || Ok(())).unwrap();
        // The cache budget still bounds admission.
        let huge = source.put("huge", (2 << 20) as usize);
        assert!(cache.ensure_local(std::slice::from_ref(&huge)).await.is_err());
    }

    /// A source that streams in small chunks and can pause mid-object.
    struct ChunkedSource {
        bytes: Mutex<BTreeMap<String, Vec<u8>>>,
        chunk: usize,
        paused: Mutex<HashSet<String>>,
        resume: tokio::sync::Notify,
        midway: tokio::sync::Notify,
    }

    impl ChunkedSource {
        fn new(chunk: usize) -> Arc<Self> {
            Arc::new(Self {
                bytes: Mutex::default(),
                chunk,
                paused: Mutex::default(),
                resume: tokio::sync::Notify::new(),
                midway: tokio::sync::Notify::new(),
            })
        }

        fn put(&self, name: &str, size: usize) -> ReaderObjectRef {
            let bytes: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();
            let object = ReaderObjectRef {
                range: None,
                source_uri: format!("s3://{BUCKET}/{PREFIX}/data/{name}.bin"),
                sha256: hex::encode(Sha256::digest(&bytes)),
                size_bytes: size as u64,
            };
            self.bytes.lock().unwrap().insert(object.source_uri.clone(), bytes);
            object
        }
    }

    #[async_trait::async_trait]
    impl ReaderObjectSource for ChunkedSource {
        async fn stream_object(
            &self,
            object: &ReaderObjectRef,
            sink: &mut (dyn for<'b> FnMut(&'b [u8]) -> anyhow::Result<()> + Send),
        ) -> anyhow::Result<()> {
            let bytes = self.bytes.lock().unwrap()[&object.source_uri].clone();
            let pause = self.paused.lock().unwrap().contains(&object.source_uri);
            for (index, chunk) in bytes.chunks(self.chunk).enumerate() {
                if pause && index == 1 {
                    // Mid-download, holding its volume grant.
                    self.midway.notify_one();
                    self.resume.notified().await;
                }
                sink(chunk)?;
            }
            Ok(())
        }
    }

    fn accounted_cache(root: &Path, source: Arc<ChunkedSource>) -> (ReaderObjectCache, nanosiem_lake_cell::volume_usage::Accountant) {
        let accountant = nanosiem_lake_cell::volume_usage::start(root.to_path_buf(), vec![root.to_path_buf()]).unwrap();
        let cache = ReaderObjectCache::open(settings(root, 64 << 20), "t1", BUCKET, PREFIX, source).unwrap();
        cache.set_hot_capacity(crate::local_hot_window::Settings {
            root: root.to_path_buf(), hours: 72, bytes_per_second: 0,
            reserve_bytes: Some(0), max_bytes: 1 << 40, schedule: Default::default(), persistent: false,
        });
        (cache, accountant)
    }

    /// NAN-3147: every 64 KiB chunk of every download asked the cell's
    /// volume accountant (a full-volume walk under a global fence).
    #[tokio::test]
    async fn hot_window_download_fences_once_per_slab_not_per_chunk() {
        let root = tempfile::tempdir().unwrap();
        let source = ChunkedSource::new(4096);
        let (cache, accountant) = accounted_cache(root.path(), source.clone());
        let object = source.put("chunked", 64 * 4096);
        drop(cache.ensure_local(std::slice::from_ref(&object)).await.unwrap());
        assert_eq!(accountant.stats().grants, 1, "one grant for a 64-chunk object under one slab");
        // Larger than a slab: one grant per slab.
        cache.set_fence_slab_bytes(16 * 4096);
        let next = source.put("slabs", 63 * 4096 + 100);
        drop(cache.ensure_local(std::slice::from_ref(&next)).await.unwrap());
        assert_eq!(accountant.stats().grants, 1 + 4);
        // NAN-3866: a grant is released by the accountant's connection thread
        // when it reads EOF on the dropped guard, after `ensure_local` has
        // returned; wait for that event instead of racing it.
        let deadline = Instant::now() + Duration::from_secs(30);
        while accountant.stats().outstanding != 0 && Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        assert_eq!(accountant.stats().outstanding, 0, "grants are released when the download ends");
    }

    /// NAN-3147: a background hydration download holds its volume grant
    /// across pacing; a foreground cold fetch must not queue behind it.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn hot_window_foreground_admission_not_blocked_by_hydration() {
        let root = tempfile::tempdir().unwrap();
        let source = ChunkedSource::new(4096);
        let (cache, accountant) = accounted_cache(root.path(), source.clone());
        let slow = source.put("hydrating", 16 * 4096);
        source.paused.lock().unwrap().insert(slow.source_uri.clone());
        let midway = source.midway.notified();
        let background = {
            let (cache, slow) = (cache.clone(), slow.clone());
            tokio::spawn(async move {
                background_hydrate(1 << 40, cache.ensure_local(std::slice::from_ref(&slow))).await.map(drop)
            })
        };
        midway.await;
        assert_eq!(accountant.stats().outstanding, 16 * 4096, "hydration holds its grant mid-download");
        let foreground = source.put("interactive", 8 * 4096);
        let lease = tokio::time::timeout(Duration::from_secs(2), cache.ensure_local(std::slice::from_ref(&foreground)))
            .await
            .expect("foreground admission blocked behind background hydration")
            .unwrap();
        assert_eq!(lease.fetched_bytes(), 8 * 4096);
        source.resume.notify_one();
        background.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn hot_window_aborts_download_when_other_data_grows_midstream() {
        struct GrowingSource { scratch: PathBuf, bytes: Vec<u8> }
        #[async_trait::async_trait]
        impl ReaderObjectSource for GrowingSource {
            async fn stream_object(&self, _: &ReaderObjectRef,
                sink: &mut (dyn for<'b> FnMut(&'b [u8]) -> anyhow::Result<()> + Send),
            ) -> anyhow::Result<()> {
                sink(&self.bytes[..4096])?;
                std::fs::write(&self.scratch, vec![0; 12288])?;
                sink(&self.bytes[4096..])
            }
        }
        let root = tempfile::tempdir().unwrap();
        let bytes = vec![42; 8192];
        let object = ReaderObjectRef { range: None,
            source_uri: format!("s3://{BUCKET}/{PREFIX}/data/growing.bin"),
            sha256: hex::encode(Sha256::digest(&bytes)), size_bytes: bytes.len() as u64 };
        let source = Arc::new(GrowingSource { scratch: root.path().join("merge-scratch"), bytes });
        let cache = ReaderObjectCache::open(settings(root.path(), 1 << 20), "t1", BUCKET, PREFIX, source).unwrap();
        // NAN-3147: the volume is re-checked per slab; a 4 KiB slab makes
        // the second half of this object a fresh grant.
        cache.set_fence_slab_bytes(4096);
        let limit = nanosiem_lake_cell::volume_usage::directory_bytes(root.path()).unwrap() + 16384;
        cache.set_hot_capacity(crate::local_hot_window::Settings {
            root: root.path().to_path_buf(), hours: 72, bytes_per_second: 0,
            reserve_bytes: Some(0), max_bytes: limit, schedule: Default::default(), persistent: false,
        });
        // The scratch never shrinks here: the bounded wait gives up.
        cache.set_saturation_wait(Duration::from_millis(200));
        assert!(cache.ensure_local(std::slice::from_ref(&object)).await.is_err());
        assert!(!cache.object_path(&object.sha256).exists());
        assert!(nanosiem_lake_cell::volume_usage::directory_bytes(root.path()).unwrap() <= limit);
    }

    #[tokio::test]
    async fn hot_window_resume_rehashes_without_download_and_hits_bypass_cold_budget() {
        let (root, source) = fixture();
        let object = source.put("warm", 200);
        let cache = open(root.path(), 300, &source);
        drop(cache.ensure_local(std::slice::from_ref(&object)).await.unwrap());
        let mut settings = settings(root.path(), 300);
        settings.query_max_bytes = 1;
        let resumed = ReaderObjectCache::open(settings, "t1", BUCKET, PREFIX, source.clone()).unwrap();
        resumed.mark_hot(object.sha256.clone(), 1);
        let lease = resumed.ensure_local(std::slice::from_ref(&object)).await.unwrap();
        assert_eq!(lease.fetched_bytes(), 0);
        assert_eq!(source.reads(), 1);
        assert_eq!(resumed.stats().rehashes, 1, "restart verifies the existing digest");
        // NAN-3644: a cold read over the (1-byte) threshold is no longer
        // refused: it takes a heavy slot and runs.
        let cold = source.put("cold", 2);
        assert_eq!(resumed.ensure_local(&[cold]).await.unwrap().fetched_bytes(), 2);
    }

    #[tokio::test]
    async fn hot_window_signed_range_import_uses_offset_and_rejects_bad_digest() {
        let (root, source) = fixture();
        let cache = open(root.path(), 300, &source);
        let whole = source.put("whole", 100);
        let body = source.objects.lock().unwrap()[&whole.source_uri].clone();
        let path = root.path().join("whole.parquet");
        std::fs::write(&path, &body).unwrap();
        let range = ReaderObjectRef { range: Some(20..40), source_uri: whole.source_uri.clone(), sha256: hex::encode(Sha256::digest(&body[20..40])), size_bytes: 20 };
        cache.warm_local(&range, &path).await.unwrap();
        let lease = cache.ensure_local(std::slice::from_ref(&range)).await.unwrap();
        assert_eq!(std::fs::read(lease.pinned_path(&range.sha256)).unwrap(), body[20..40]);
        assert_eq!(source.reads(), 0);
        let bad = ReaderObjectRef { sha256: "f".repeat(64), ..range };
        assert!(matches!(cache.warm_local(&bad, &path).await, Err(ReaderCacheError::Integrity(_))));
    }

    fn objects_dir_entries(root: &Path) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(tenant_directory(root, "t1").join("objects"))
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        names
    }

    #[tokio::test]
    async fn miss_then_hit_verifies_admits_read_only_and_leases() {
        let (root, source) = fixture();
        let cache = open(root.path(), 10_000, &source);
        let a = source.put("a", 100);
        let lease = cache.ensure_local(std::slice::from_ref(&a)).await.unwrap();
        assert_eq!((lease.hits(), lease.misses(), lease.fetched_bytes()), (0, 1, 100));
        let path = object_path(root.path(), "t1", &a.sha256);
        assert_eq!(lease.paths(), std::slice::from_ref(&path));
        assert_eq!(std::fs::metadata(&path).unwrap().mode() & 0o777, 0o444);
        assert_eq!(crate::native::file_sha256(&path).unwrap(), a.sha256);
        drop(lease);
        let lease = cache.ensure_local(&[a.clone(), a.clone()]).await.unwrap();
        assert_eq!((lease.hits(), lease.misses(), lease.fetched_bytes()), (1, 0, 0));
        assert_eq!(source.reads(), 1);
        let stats = cache.stats();
        assert_eq!((stats.objects, stats.stored_bytes, stats.hits, stats.misses), (1, 100, 1, 1));
    }

    #[tokio::test]
    async fn signed_ranges_fetch_only_selected_bytes_and_reject_tampering() {
        let (root, source) = fixture();
        let cache = open(root.path(), 10_000, &source);
        let whole = source.put("abcdef", 1_000);
        let body = source.objects.lock().unwrap()[&whole.source_uri].clone();
        let range = ReaderObjectRef {
            source_uri: whole.source_uri.clone(), range: Some(100..120), size_bytes: 20,
            sha256: hex::encode(Sha256::digest(&body[100..120])),
        };
        let lease = cache.ensure_local(std::slice::from_ref(&range)).await.unwrap();
        assert_eq!(lease.fetched_bytes(), 20);
        assert_eq!(std::fs::read(&lease.paths()[0]).unwrap(), body[100..120]);
        drop(lease);
        assert_eq!(cache.ensure_local(std::slice::from_ref(&range)).await.unwrap().fetched_bytes(), 0);
        let bad = ReaderObjectRef { range: Some(100..121), ..range.clone() };
        assert!(matches!(cache.ensure_local(&[bad]).await, Err(ReaderCacheError::Integrity(_))));
        let corrupt = ReaderObjectRef { range: Some(200..220), sha256: "f".repeat(64), ..range };
        assert!(matches!(cache.ensure_local(&[corrupt]).await, Err(ReaderCacheError::Integrity(_))));
        assert_eq!(cache.stats().objects, 1, "unverified bytes are never admitted");
    }

    /// NAN-2996: a lease's own hard link / unlink changes only the inode
    /// ctime. Repeated leases of a settled object must trust its stamp, not
    /// re-hash it every time (the live cell re-hashed every file per query).
    #[tokio::test]
    async fn repeated_leases_trust_a_settled_hit_without_rehashing() {
        let (root, source) = fixture();
        let cache = open(root.path(), 10_000, &source);
        let a = source.put("a", 100);
        drop(cache.ensure_local(std::slice::from_ref(&a)).await.unwrap());
        let path = object_path(root.path(), "t1", &a.sha256);
        // A clock past the mtime collision window, as for any object older than 2 s.
        let settled = Some(FileStamp::read(&path).unwrap().modified.0 + STAMP_COLLISION_WINDOW_SECONDS + 1);
        // First check after admission may verify once.
        assert!(cache.inner.verified_hit_at(&a, settled).unwrap());
        let mut rehashed = 0;
        for _ in 0..REHASH_SAMPLE / 2 {
            // Each lease hard-links then unlinks the object: its ctime moves.
            drop(cache.ensure_local(std::slice::from_ref(&a)).await.unwrap());
            let before = cache.stats().rehashes;
            assert!(cache.inner.verified_hit_at(&a, settled).unwrap());
            rehashed += cache.stats().rehashes - before;
        }
        // At most the 1-in-64 bit-rot sample; before the fix: every check.
        assert!(rehashed <= 1, "lease link/unlink forced {rehashed} re-hashes");
        assert_eq!(source.reads(), 1);
    }

    /// NAN-3165: while a live lease of this process holds a verified object,
    /// repeated hits are trusted by their stamp without the 1-in-64 re-hash;
    /// once every lease is released the sample applies again, and a changed
    /// stamp is still re-hashed under a lease.
    #[tokio::test]
    async fn live_lease_skips_the_sampled_rehash_until_released() {
        let (root, source) = fixture();
        let cache = open(root.path(), 10_000, &source);
        let a = source.put("a", 100);
        let lease = cache.ensure_local(std::slice::from_ref(&a)).await.unwrap();
        let path = object_path(root.path(), "t1", &a.sha256);
        let settled = Some(FileStamp::read(&path).unwrap().modified.0 + STAMP_COLLISION_WINDOW_SECONDS + 1);
        let before = cache.stats().rehashes;
        for _ in 0..REHASH_SAMPLE * 3 {
            assert!(cache.inner.verified_hit_at(&a, settled).unwrap());
        }
        assert_eq!(cache.stats().rehashes, before, "no sampled re-hash under a live lease");
        // A collision-window stamp is still re-hashed under a lease.
        assert!(cache.inner.verified_hit_at(&a, None).unwrap());
        assert_eq!(cache.stats().rehashes, before + 1);
        drop(lease);
        assert!(cache.inner.state().live.is_empty(), "released leases leave no live count");
        let before = cache.stats().rehashes;
        // NAN-3403: past the scrub interval since admission verified it.
        let past_interval = settled.map(|now| now + DEFAULT_SCRUB_MIN_INTERVAL_SECONDS);
        for _ in 0..REHASH_SAMPLE * 3 {
            assert!(cache.inner.verified_hit_at(&a, past_interval).unwrap());
        }
        assert_eq!(cache.stats().rehashes, before, "the sample is deferred off the lease path");
        cache.inner.scrub_pending();
        assert!(cache.stats().rehashes > before, "the bit-rot sample resumes without a lease");
    }

    /// The sampled re-hash of a settled hit never runs inline: the hit is
    /// trusted by its stamp and the sample is scrubbed after the lease; a
    /// scrub that finds rotten bytes evicts the object, and the next lease
    /// re-fetches the signed object.
    #[tokio::test]
    async fn sampled_rehash_is_deferred_and_scrub_evicts_rotten_bytes() {
        let (root, source) = fixture();
        let cache = open(root.path(), 10_000, &source);
        let a = source.put("a", 100);
        drop(cache.ensure_local(std::slice::from_ref(&a)).await.unwrap());
        let path = object_path(root.path(), "t1", &a.sha256);
        let settled = Some(FileStamp::read(&path).unwrap().modified.0 + STAMP_COLLISION_WINDOW_SECONDS + 1);
        // Rot the bytes but keep the memoized stamp (same size and mode).
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        std::fs::write(&path, vec![0_u8; 100]).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o444)).unwrap();
        cache.inner.state.lock().unwrap().entries.get_mut(&a.sha256).unwrap().stamp = FileStamp::read(&path).unwrap();
        let before = cache.stats().rehashes;
        // NAN-3403: past the scrub interval since admission verified it.
        let past_interval = settled.map(|now| now + DEFAULT_SCRUB_MIN_INTERVAL_SECONDS);
        for _ in 0..REHASH_SAMPLE {
            assert!(cache.inner.verified_hit_at(&a, past_interval).unwrap(), "a stamp-trusted hit is served");
        }
        assert_eq!(cache.stats().rehashes, before, "no inline re-hash");
        assert!(cache.inner.state().scrub.contains(&a.sha256), "one sample queued");
        cache.inner.scrub_pending();
        assert_eq!(cache.stats().rehashes, before + 1);
        assert_eq!(cache.stats().integrity_failures, 1);
        assert!(!path.exists(), "the rotten object is evicted");
        let lease = cache.ensure_local(std::slice::from_ref(&a)).await.unwrap();
        assert_eq!((lease.hits(), lease.misses()), (0, 1));
        assert_eq!(crate::native::file_sha256(&path).unwrap(), a.sha256);
        assert_eq!(source.reads(), 2);
    }

    /// NAN-3403: background passes (arrival prewarm, hot-window hydration)
    /// hit every hot-window object several times a minute. An object this
    /// process verified within the scrub interval is not re-sampled however
    /// many unleased hits it gets; once the interval has passed, the bit-rot
    /// sample applies again. Before the fix every 64th hit re-hashed the
    /// whole file, so the window was re-read every few minutes.
    #[tokio::test]
    async fn recently_verified_object_is_not_resampled_within_the_scrub_interval() {
        let (root, source) = fixture();
        let cache = open(root.path(), 10_000, &source);
        let a = source.put("a", 100);
        drop(cache.ensure_local(std::slice::from_ref(&a)).await.unwrap());
        let path = object_path(root.path(), "t1", &a.sha256);
        let settled = FileStamp::read(&path).unwrap().modified.0 + STAMP_COLLISION_WINDOW_SECONDS + 1;
        let before = cache.stats().rehashes;
        for _ in 0..REHASH_SAMPLE * 10 {
            assert!(cache.inner.verified_hit_at(&a, Some(settled)).unwrap());
        }
        cache.inner.scrub_pending();
        assert_eq!(cache.stats().rehashes, before, "verified at admission: no sample within the interval");
        let later = Some(settled + DEFAULT_SCRUB_MIN_INTERVAL_SECONDS);
        for _ in 0..REHASH_SAMPLE * 10 {
            assert!(cache.inner.verified_hit_at(&a, later).unwrap());
        }
        cache.inner.scrub_pending();
        assert_eq!(cache.stats().rehashes, before + 1, "one sample once the interval has passed");
        assert_eq!(source.reads(), 1, "trusted hits never re-fetch");
    }

    #[test]
    fn scrub_due_bounds_samples_per_interval() {
        assert!(super::scrub_due(None, Some(100), 3600), "never hashed here: due");
        assert!(super::scrub_due(Some(100), None, 3600), "unknown clock: due");
        assert!(!super::scrub_due(Some(100), Some(3699), 3600));
        assert!(super::scrub_due(Some(100), Some(3700), 3600));
        assert!(super::scrub_due(Some(100), Some(100), 0), "0 restores per-hit sampling");
        assert_eq!(super::parse_scrub_min_interval(None), DEFAULT_SCRUB_MIN_INTERVAL_SECONDS);
        assert_eq!(super::parse_scrub_min_interval(Some("0")), 0);
        assert_eq!(super::parse_scrub_min_interval(Some(" 600 ")), 600);
        assert_eq!(super::parse_scrub_min_interval(Some("-5")), DEFAULT_SCRUB_MIN_INTERVAL_SECONDS);
        assert_eq!(super::parse_scrub_min_interval(Some("soon")), DEFAULT_SCRUB_MIN_INTERVAL_SECONDS);
    }

    /// NAN-3403: the verification hash (direct I/O where the filesystem
    /// allows it, buffered otherwise) equals SHA-256 of the bytes for empty,
    /// sub-block, block-aligned and multi-chunk unaligned sizes.
    #[test]
    fn verify_sha256_matches_the_digest_at_every_size() {
        let dir = tempfile::tempdir().unwrap();
        for size in [0_usize, 1, 4095, 4096, 4097, 1024 * 1024, 2 * 1024 * 1024 + 17] {
            let bytes = (0..size).map(|i| (i * 31 % 251) as u8).collect::<Vec<_>>();
            let path = dir.path().join(format!("{size}.bin"));
            std::fs::write(&path, &bytes).unwrap();
            let expected = hex::encode(Sha256::digest(&bytes));
            assert_eq!(super::verify_sha256(&path).unwrap(), expected, "size {size}");
            assert_eq!(super::sha256_buffered(&path).unwrap(), expected, "size {size}");
        }
        assert!(super::verify_sha256(&dir.path().join("missing.bin")).is_err());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_misses_for_one_digest_share_a_single_read() {
        let (root, source) = fixture();
        let cache = Arc::new(open(root.path(), 10_000, &source));
        let a = source.put("a", 100);
        source.delay_ms.store(150, Ordering::SeqCst);
        let calls = (0..8).map(|_| {
            let (cache, a) = (cache.clone(), a.clone());
            tokio::spawn(async move { cache.ensure_local(&[a]).await })
        });
        let leases: Vec<_> = futures::future::join_all(calls).await;
        for lease in &leases {
            assert!(lease.as_ref().unwrap().is_ok());
        }
        assert_eq!(source.reads(), 1);
    }

    #[tokio::test]
    async fn corrupt_bytes_are_retried_once_then_fail_closed() {
        let (root, source) = fixture();
        let cache = open(root.path(), 10_000, &source);
        let a = source.put("a", 100);
        source.corrupt.lock().unwrap().insert(a.source_uri.clone(), None);
        let error = cache.ensure_local(std::slice::from_ref(&a)).await.unwrap_err();
        assert!(matches!(error, ReaderCacheError::Integrity(_)), "{error}");
        assert_eq!(error.reason(), "reader_object_integrity");
        assert_eq!(source.reads(), 2);
        assert!(!object_path(root.path(), "t1", &a.sha256).exists());
        assert!(objects_dir_entries(root.path()).is_empty());
        assert_eq!(cache.stats().integrity_failures, 2);

        // One transient corruption: the retry admits the good bytes.
        let b = source.put("b", 100);
        source.corrupt.lock().unwrap().insert(b.source_uri.clone(), Some(1));
        cache.ensure_local(&[b]).await.unwrap();
        assert_eq!(source.reads(), 4);
    }

    #[tokio::test]
    async fn short_and_long_bodies_fail_the_length_fence() {
        let (root, source) = fixture();
        let cache = open(root.path(), 10_000, &source);
        for (name, delta) in [("short", -1_i64), ("long", 1)] {
            let object = source.put(name, 50);
            let mut body = source.objects.lock().unwrap()[&object.source_uri].clone();
            if delta < 0 {
                body.pop();
            } else {
                body.push(0);
            }
            source.overrides.lock().unwrap().insert(object.source_uri.clone(), body);
            let error = cache.ensure_local(std::slice::from_ref(&object)).await.unwrap_err();
            assert!(matches!(error, ReaderCacheError::Integrity(_)), "{name}: {error}");
            assert!(!object_path(root.path(), "t1", &object.sha256).exists());
        }
        assert!(objects_dir_entries(root.path()).is_empty());
    }

    #[tokio::test]
    async fn source_down_is_unavailable_and_retryable() {
        let (root, source) = fixture();
        let cache = open(root.path(), 10_000, &source);
        let a = source.put("a", 100);
        source.down.store(true, Ordering::SeqCst);
        let error = cache.ensure_local(&[a]).await.unwrap_err();
        assert!(matches!(error, ReaderCacheError::Unavailable(_)), "{error}");
        assert!(error.retryable());
        assert_eq!(error.reason(), "reader_cold_fetch_unavailable");
    }

    #[tokio::test]
    async fn slow_source_hits_the_deadline() {
        let (root, source) = fixture();
        let mut settings = settings(root.path(), 10_000);
        settings.fetch_deadline = Duration::from_millis(50);
        let cache = ReaderObjectCache::open(settings, "t1", BUCKET, PREFIX, source.clone()).unwrap();
        let a = source.put("a", 100);
        source.delay_ms.store(400, Ordering::SeqCst);
        let error = cache.ensure_local(&[a]).await.unwrap_err();
        assert!(matches!(error, ReaderCacheError::FetchTimeout), "{error}");
        assert_eq!(error.reason(), "reader_cold_fetch_timeout");
        assert!(error.retryable());
    }

    /// NAN-3714: a lease larger than the download slots does not time out
    /// while its transfers progress. One slot and a 150 ms deadline: each
    /// object takes 100 ms, so the fourth waits 300 ms for its slot and the
    /// lease runs 400 ms, past the first lease deadline; before the fix the
    /// queued objects hit their own deadline in the queue and the lease
    /// failed with FetchTimeout (the r38z 7 d pivot job's HTTP 500).
    // NAN-3866: paused Tokio clock -- the source delays, deadlines and the
    // test's own waits are virtual, so CPU load cannot reorder them.
    #[tokio::test(start_paused = true)]
    async fn queued_objects_of_a_progressing_lease_do_not_time_out() {
        let (root, source) = fixture();
        let mut settings = settings(root.path(), 10_000);
        settings.fetch_concurrency = 1;
        settings.fetch_deadline = Duration::from_millis(150);
        let cache = ReaderObjectCache::open(settings, "t1", BUCKET, PREFIX, source.clone()).unwrap();
        let objects: Vec<_> = ["q1", "q2", "q3", "q4"].iter().map(|name| source.put(name, 100)).collect();
        source.delay_ms.store(100, Ordering::SeqCst);
        let lease = cache.ensure_local(&objects).await.unwrap();
        assert_eq!(lease.misses(), 4);
        assert_eq!(source.reads.load(Ordering::SeqCst), 4);
    }

    /// NAN-3714: the progress-extended lease deadline still cuts a lease
    /// with no progress at all, and extends one that keeps progressing.
    #[tokio::test]
    async fn lease_deadline_extends_only_while_progressing() {
        let start = tokio::time::Instant::now();
        let stuck = wait_while_progressing(
            std::future::pending::<()>(),
            start + Duration::from_millis(20),
            Duration::from_millis(20),
            || 0,
        )
        .await;
        assert!(matches!(stuck, Err(ReaderCacheError::FetchTimeout)));
        let ticks = AtomicU64::new(0);
        let progressing = wait_while_progressing(
            async { tokio::time::sleep(Duration::from_millis(120)).await; 7 },
            tokio::time::Instant::now() + Duration::from_millis(20),
            Duration::from_millis(20),
            || ticks.fetch_add(1, Ordering::Relaxed) + 1,
        )
        .await;
        assert_eq!(progressing.unwrap(), 7);
    }

    #[tokio::test]
    async fn durable_job_reads_use_the_durable_ceiling_not_the_interactive_one() {
        let (root, source) = fixture();
        let mut settings = settings(root.path(), 10_000);
        settings.query_max_bytes = 250;
        let cache = ReaderObjectCache::open(settings, "t1", BUCKET, PREFIX, source.clone()).unwrap();
        cache.set_cold_heavy_concurrency(2);
        assert_eq!(cache.query_cold_budget(), 250);
        // (10_000 - 250) shared by two heavy slots; a durable job takes both.
        assert_eq!(cache.interactive_cold_ceiling(), 4_875);
        assert_eq!(cache.durable_cold_ceiling(), 9_750);
        assert_eq!(with_durable_job_cold_budget(1_000, async { cache.query_cold_budget() }).await, 1_000);
        // A job budget never drops below the interactive floor.
        assert_eq!(with_durable_job_cold_budget(10, async { cache.query_cold_budget() }).await, 250);
        let big: Vec<_> = ["d", "e"].iter().map(|name| source.put(name, 3_000)).collect();
        // Interactively 6_000 cold bytes are over the ceiling: refused before
        // any read, typed, with the durable ceiling that would admit it.
        let error = cache.ensure_local(&big).await.unwrap_err();
        assert!(matches!(error, ReaderCacheError::ScanTooLarge { required_bytes: 6_000, ceiling_bytes: 4_875, background_bytes: 9_750 }), "{error}");
        assert_eq!(error.reason(), "cold_scan_too_large");
        assert!(!error.retryable());
        assert_eq!(source.reads(), 0);
        // The same read runs inside a durable job, holding every heavy slot.
        let lease = with_durable_job_cold_budget(1_000, cache.ensure_local(&big)).await.unwrap();
        assert_eq!(lease.fetched_bytes(), 6_000);
        assert_eq!(cache.inner.heavy.available_permits(), 0, "a heavy durable read takes every slot");
        drop(lease);
        assert_eq!(cache.inner.heavy.available_permits(), 2);
    }

    /// NAN-3644: the old 2 GiB refusal is gone. A cold set over the per-query
    /// threshold runs (no `COLD_BUDGET_EXCEEDED`), holding a heavy slot until
    /// its pins are released.
    #[tokio::test]
    async fn cold_set_over_the_threshold_runs_on_a_heavy_slot() {
        let (root, source) = fixture();
        let mut settings = settings(root.path(), 10_000);
        settings.query_max_bytes = 250;
        let cache = ReaderObjectCache::open(settings, "t1", BUCKET, PREFIX, source.clone()).unwrap();
        assert_eq!(cache.cold_heavy_concurrency(), DEFAULT_COLD_HEAVY_CONCURRENCY);
        let objects: Vec<_> = ["a", "b", "c"].iter().map(|name| source.put(name, 100)).collect();
        let lease = cache.ensure_local(&objects).await.unwrap();
        assert_eq!(lease.fetched_bytes(), 300);
        assert_eq!(cache.inner.heavy.available_permits(), 0);
        drop(lease);
        assert_eq!(cache.inner.heavy.available_permits(), 1);
        // A light read never takes the slot.
        let light = source.put("light", 100);
        let held = cache.ensure_local(&[light]).await.unwrap();
        assert_eq!(cache.inner.heavy.available_permits(), 1);
        drop(held);
        // A shared budget crosses its threshold on the lease that pushes it over.
        let budget = ColdBudget::new(250);
        let first = cache.ensure_local_within(&[source.put("f1", 200)], &budget).await.unwrap();
        assert_eq!(cache.inner.heavy.available_permits(), 1);
        let second = cache.ensure_local_within(&[source.put("f2", 200)], &budget).await.unwrap();
        assert_eq!((budget.spent(), cache.inner.heavy.available_permits()), (400, 0));
        drop((first, second));
        drop(budget);
        assert_eq!(cache.inner.heavy.available_permits(), 1);
    }

    #[tokio::test]
    async fn concurrent_heavy_reads_queue_instead_of_reading_at_once() {
        let (root, source) = fixture();
        let mut settings = settings(root.path(), 10_000);
        settings.query_max_bytes = 250;
        let cache = ReaderObjectCache::open(settings, "t1", BUCKET, PREFIX, source.clone()).unwrap();
        let first: Vec<_> = ["a1", "a2", "a3"].iter().map(|name| source.put(name, 100)).collect();
        let second: Vec<_> = ["b1", "b2", "b3"].iter().map(|name| source.put(name, 100)).collect();
        let held = cache.ensure_local(&first).await.unwrap();
        assert_eq!(source.reads(), 3);
        let queued = tokio::spawn({
            let cache = cache.clone();
            async move { crate::query_timing::measure("heavyq-b", async { cache.ensure_local(&second).await.map(|lease| lease.fetched_bytes()) }).await }
        });
        tokio::time::sleep(Duration::from_millis(150)).await;
        assert!(!queued.is_finished(), "the second heavy read waits for the slot");
        assert_eq!(source.reads(), 3, "and reads nothing while it waits");
        let progress = crate::query_timing::cold_progress("heavyq").expect("the queued request is visible");
        assert!(progress.queued);
        drop(held);
        assert_eq!(queued.await.unwrap().unwrap(), 300);
        assert_eq!(source.reads(), 6);
        assert_eq!(cache.inner.heavy.available_permits(), 1, "the request's slot is released when it ends");
        assert!(crate::query_timing::cold_progress("heavyq").is_none());
    }

    // NAN-3866: paused Tokio clock -- the source delays, deadlines and the
    // test's own waits are virtual, so CPU load cannot reorder them.
    #[tokio::test(start_paused = true)]
    async fn heavy_reads_report_progress_on_their_request() {
        let (root, source) = fixture();
        let mut settings = settings(root.path(), 10_000);
        settings.query_max_bytes = 250;
        let cache = ReaderObjectCache::open(settings, "t1", BUCKET, PREFIX, source.clone()).unwrap();
        let objects: Vec<_> = ["p1", "p2", "p3", "p4"].iter().map(|name| source.put(name, 100)).collect();
        source.delay_ms.store(200, Ordering::SeqCst);
        let running = tokio::spawn({
            let cache = cache.clone();
            // A Search chunk request: `{query_id}-stats-…` reports under the query id.
            async move { crate::query_timing::measure("progq-stats-0", async {
                let lease = cache.ensure_local(&objects).await?;
                let seen = crate::query_timing::cold_progress("progq").unwrap();
                drop(lease);
                Ok::<_, ReaderCacheError>(seen)
            }).await }
        });
        tokio::time::sleep(Duration::from_millis(80)).await;
        let during = crate::query_timing::cold_progress("progq").expect("in flight");
        assert_eq!((during.requests, during.cold_bytes_total, during.queued), (1, 400, false));
        assert!(during.cold_bytes_read < 400);
        assert!(crate::query_timing::cold_progress("prog").is_none(), "ids match whole segments only");
        let done = running.await.unwrap().unwrap();
        assert_eq!((done.cold_bytes_read, done.cold_bytes_total), (400, 400));
        assert!(crate::query_timing::cold_progress("progq").is_none());
    }

    #[tokio::test]
    async fn a_batched_read_reports_its_whole_estimate_from_the_start() {
        let (root, source) = fixture();
        let cache = ReaderObjectCache::open(settings(root.path(), 10_000), "t1", BUCKET, PREFIX, source.clone()).unwrap();
        let first = vec![source.put("b1", 100)];
        let seen = crate::query_timing::measure("batchq", async {
            // A batched read announces the refused read's size, then leases
            // its first batch: progress is "100 of 900", not "100 of 100".
            crate::query_timing::plan_cold_bytes(900);
            let lease = cache.ensure_local(&first).await?;
            let seen = crate::query_timing::cold_progress("batchq").unwrap();
            drop(lease);
            Ok::<_, ReaderCacheError>(seen)
        }).await.unwrap();
        assert_eq!((seen.cold_bytes_read, seen.cold_bytes_total), (100, 900));
    }

    #[test]
    fn a_foreground_lease_deadline_grows_with_its_size() {
        let base = Duration::from_secs(60);
        assert_eq!(fetch_deadline(base, 1_000), base, "small leases keep the base deadline");
        // 4.4 GiB at the 16 MiB/s floor: 281 s more, where a flat 60 s
        // failed every such lease on a 75 MiB/s volume.
        let big = 4_400 * 1024 * 1024;
        assert_eq!(fetch_deadline(base, big), base + Duration::from_secs(big / FOREGROUND_FETCH_FLOOR_BYTES_PER_SECOND));
    }

    // NAN-3866: paused Tokio clock -- the source delays, deadlines and the
    // test's own waits are virtual, so CPU load cannot reorder them.
    #[tokio::test(start_paused = true)]
    async fn cancelling_a_queued_or_running_heavy_read_frees_its_slot() {
        let (root, source) = fixture();
        let mut settings = settings(root.path(), 10_000);
        settings.query_max_bytes = 250;
        let cache = ReaderObjectCache::open(settings, "t1", BUCKET, PREFIX, source.clone()).unwrap();
        let held = cache.ensure_local(&["h1", "h2", "h3"].map(|name| source.put(name, 100))).await.unwrap();
        // Queued: cancel while it waits; it never takes the slot or reads.
        let queued = tokio::spawn({
            let (cache, objects) = (cache.clone(), ["q1", "q2", "q3"].map(|name| source.put(name, 100)));
            async move { crate::query_timing::measure("cancel-queued", cache.ensure_local(&objects)).await }
        });
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(crate::query_timing::cold_progress("cancel-queued").unwrap().queued);
        queued.abort();
        assert!(queued.await.unwrap_err().is_cancelled());
        assert!(crate::query_timing::cold_progress("cancel-queued").is_none());
        assert_eq!(source.reads(), 3);
        drop(held);
        assert_eq!(cache.inner.heavy.available_permits(), 1, "the cancelled waiter took nothing");
        // Running: cancel mid-download; the slot comes back at once.
        source.delay_ms.store(500, Ordering::SeqCst);
        let running = tokio::spawn({
            let (cache, objects) = (cache.clone(), ["r1", "r2", "r3"].map(|name| source.put(name, 100)));
            async move { crate::query_timing::measure("cancel-running", cache.ensure_local(&objects)).await }
        });
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(cache.inner.heavy.available_permits(), 0);
        let progress = crate::query_timing::cold_progress("cancel-running").unwrap();
        assert_eq!((progress.cold_bytes_total, progress.queued), (300, false));
        running.abort();
        assert!(running.await.unwrap_err().is_cancelled());
        assert_eq!(cache.inner.heavy.available_permits(), 1);
        // The next heavy read is admitted without waiting.
        source.delay_ms.store(0, Ordering::SeqCst);
        let next = tokio::time::timeout(Duration::from_secs(2),
            cache.ensure_local(&["n1", "n2", "n3"].map(|name| source.put(name, 100)))).await;
        assert_eq!(next.unwrap().unwrap().fetched_bytes(), 300);
    }

    /// NAN-4277: a source whose `slow-*` objects block until the gate opens
    /// (counting the downloads that started); every other object is served
    /// at once.
    struct GatedSource {
        inner: Arc<FakeSource>,
        gate: tokio::sync::Semaphore,
        started: AtomicUsize,
        /// NAN-4290: each slow download consumes one gate permit, so a test
        /// can let exactly `n` of them finish.
        consume: bool,
    }

    #[async_trait::async_trait]
    impl ReaderObjectSource for GatedSource {
        async fn stream_object(
            &self,
            object: &ReaderObjectRef,
            sink: &mut (dyn for<'b> FnMut(&'b [u8]) -> anyhow::Result<()> + Send),
        ) -> anyhow::Result<()> {
            if object.source_uri.contains("/slow-") {
                self.started.fetch_add(1, Ordering::SeqCst);
                let permit = self.gate.acquire().await?;
                if self.consume { permit.forget() }
            }
            self.inner.stream_object(object, sink).await
        }
    }

    fn gated_cache(root: &Path) -> (ReaderObjectCache, Arc<GatedSource>) {
        gated_cache_with(root, false)
    }

    fn gated_cache_with(root: &Path, consume: bool) -> (ReaderObjectCache, Arc<GatedSource>) {
        let source = Arc::new(GatedSource {
            inner: Arc::new(FakeSource::default()),
            gate: tokio::sync::Semaphore::new(0),
            started: AtomicUsize::new(0),
            consume,
        });
        // The production constructor and settings shape: 4 download slots,
        // so background downloads may hold 3.
        let cache = ReaderObjectCache::open(settings(root, 1 << 20), "t1", BUCKET, PREFIX, source.clone()).unwrap();
        (cache, source)
    }

    async fn until_started(source: &GatedSource, count: usize) {
        for _ in 0..500 {
            if source.started.load(Ordering::SeqCst) >= count {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("only {} slow downloads started", source.started.load(Ordering::SeqCst));
    }

    #[test]
    fn background_downloads_keep_a_quarter_of_the_slots_for_interactive_reads() {
        assert_eq!(background_fetch_slots(DEFAULT_FETCH_CONCURRENCY), 12);
        assert_eq!(background_fetch_slots(4), 3);
        assert_eq!(background_fetch_slots(2), 1);
        // One slot cannot be split: background work keeps it.
        assert_eq!(background_fetch_slots(1), 1);
    }

    // NAN-4277 (a large hosted tenant, 2026-10-20): a durable job's large cold lease
    // used to fill the one FIFO download queue, so a 1 h interactive search
    // needing a few cold objects waited for the whole lease (45 s deadline).
    #[tokio::test]
    async fn a_durable_lease_never_holds_every_download_slot() {
        let root = tempfile::tempdir().unwrap();
        let (cache, source) = gated_cache(root.path());
        let durable_objects: Vec<_> = (0..8).map(|i| source.inner.put(&format!("slow-{i}"), 100)).collect();
        let durable = tokio::spawn({
            let cache = cache.clone();
            async move { with_durable_job_cold_budget(1 << 20, cache.ensure_local(&durable_objects)).await }
        });
        until_started(&source, 3).await;
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(source.started.load(Ordering::SeqCst), 3, "background downloads hold 3 of 4 slots");
        // An interactive read is admitted at once on the free slot.
        let interactive = source.inner.put("fresh", 100);
        let lease = tokio::time::timeout(Duration::from_secs(5), cache.ensure_local(std::slice::from_ref(&interactive)))
            .await
            .expect("an interactive read must not queue behind a durable lease")
            .unwrap();
        assert_eq!(lease.fetched_bytes(), 100);
        // The durable lease still completes once its transfers progress.
        source.gate.add_permits(64);
        let lease = tokio::time::timeout(Duration::from_secs(5), durable).await.unwrap().unwrap().unwrap();
        assert_eq!(lease.fetched_bytes(), 800);
    }

    // NAN-4277: an interactive read that needs an object a durable lease has
    // queued (a 30 d scan covers the last hour too) promotes that download
    // instead of waiting for the durable lease to reach it.
    #[tokio::test]
    async fn an_interactive_read_promotes_a_queued_durable_download() {
        let root = tempfile::tempdir().unwrap();
        let (cache, source) = gated_cache(root.path());
        let shared = source.inner.put("recent", 100);
        let mut durable_objects: Vec<_> = (0..4).map(|i| source.inner.put(&format!("slow-{i}"), 100)).collect();
        durable_objects.push(shared.clone());
        let durable = tokio::spawn({
            let cache = cache.clone();
            async move { with_durable_job_cold_budget(1 << 20, cache.ensure_local(&durable_objects)).await }
        });
        until_started(&source, 3).await;
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(source.inner.reads(), 0, "the shared object is still queued behind the durable lease");
        let lease = tokio::time::timeout(Duration::from_secs(5), cache.ensure_local(std::slice::from_ref(&shared)))
            .await
            .expect("the interactive read must promote the queued durable download")
            .unwrap();
        assert_eq!(lease.fetched_bytes(), 100);
        assert_eq!(source.inner.reads(), 1, "one download serves both leases");
        source.gate.add_permits(64);
        let lease = tokio::time::timeout(Duration::from_secs(5), durable).await.unwrap().unwrap().unwrap();
        assert_eq!(lease.fetched_bytes(), 500);
    }

    // NAN-4290: a 30 d aggregate and a 1 h listing run as durable jobs at the
    // same time (the small-job lane). Both leases are background reads. The
    // 30 d lease used to submit all of its downloads at once, so the 1 h
    // lease's objects queued behind every one of them. Now a background lease
    // keeps at most the background share submitted: the 1 h lease waits for
    // one round of the 30 d lease's downloads, not for the whole lease.
    #[tokio::test]
    async fn a_small_durable_lease_waits_one_round_not_the_whole_large_lease() {
        let root = tempfile::tempdir().unwrap();
        let (cache, source) = gated_cache_with(root.path(), true);
        let large_objects: Vec<_> = (0..64).map(|i| source.inner.put(&format!("slow-{i}"), 100)).collect();
        let large = tokio::spawn({
            let cache = cache.clone();
            async move { with_durable_job_cold_budget(1 << 30, cache.ensure_local(&large_objects)).await }
        });
        until_started(&source, 3).await;
        let small_objects: Vec<_> = (0..2).map(|i| source.inner.put(&format!("recent-{i}"), 100)).collect();
        let small = tokio::spawn({
            let cache = cache.clone();
            async move { with_durable_job_cold_budget(1 << 30, cache.ensure_local(&small_objects)).await }
        });
        tokio::time::sleep(Duration::from_millis(50)).await;
        // Exactly one round of the large lease's downloads finishes.
        source.gate.add_permits(3);
        let lease = tokio::time::timeout(Duration::from_secs(5), small)
            .await
            .expect("the small lease must not wait for the whole large lease")
            .unwrap()
            .unwrap();
        assert_eq!(lease.fetched_bytes(), 200);
        assert!(!large.is_finished(), "the large lease is still downloading");
        let started = source.started.load(Ordering::SeqCst);
        assert!(started <= 9, "the large lease never had more than the background share in flight ({started} started)");
        // The large lease still completes, every object fetched once.
        source.gate.add_permits(64);
        let lease = tokio::time::timeout(Duration::from_secs(10), large).await.unwrap().unwrap().unwrap();
        assert_eq!(lease.fetched_bytes(), 6_400);
        assert_eq!(source.started.load(Ordering::SeqCst), 64);
    }

    #[test]
    fn only_background_leases_bound_their_submitted_downloads() {
        // Interactive: every miss at once (its downloads take the free slots).
        assert_eq!(lease_outstanding_fetches(16, 1_561), 1_561);
        assert_eq!(lease_outstanding_fetches(16, 0), 1);
        let durable = DURABLE_JOB_COLD_BYTES.sync_scope(1, || lease_outstanding_fetches(16, 1_561));
        assert_eq!(durable, background_fetch_slots(16));
    }

    #[tokio::test]
    async fn cold_set_over_the_ceiling_is_refused_before_any_read() {
        let (root, source) = fixture();
        let mut settings = settings(root.path(), 1_000);
        settings.query_max_bytes = 250;
        let cache = ReaderObjectCache::open(settings, "t1", BUCKET, PREFIX, source.clone()).unwrap();
        // (max 1_000 - light headroom 250) / one heavy slot.
        assert_eq!(cache.interactive_cold_ceiling(), 750);
        let objects: Vec<_> = ["a", "b"].iter().map(|name| source.put(name, 400)).collect();
        let error = cache.ensure_local(&objects).await.unwrap_err();
        assert!(
            matches!(error, ReaderCacheError::ScanTooLarge { required_bytes: 800, ceiling_bytes: 750, background_bytes: 750 }),
            "{error}"
        );
        assert!(!error.retryable());
        assert_eq!(source.reads(), 0);
        assert_eq!(cache.inner.heavy.available_permits(), 1);
        // A shared budget is held to the same ceiling across its leases.
        let budget = ColdBudget::new(250);
        let first = cache.ensure_local_within(&objects[..1], &budget).await.unwrap();
        let error = cache.ensure_local_within(&[source.put("c", 400)], &budget).await.unwrap_err();
        assert!(matches!(error, ReaderCacheError::ScanTooLarge { required_bytes: 800, ceiling_bytes: 750, .. }), "{error}");
        drop(first);
    }

    #[test]
    fn heavy_concurrency_parses_a_bounded_positive_count() {
        assert_eq!(parse_cold_heavy_concurrency(None), 1);
        assert_eq!(parse_cold_heavy_concurrency(Some("")), 1);
        assert_eq!(parse_cold_heavy_concurrency(Some("3")), 3);
        for bad in ["0", "17", "-1", "two"] {
            assert_eq!(parse_cold_heavy_concurrency(Some(bad)), 1, "{bad}");
        }
    }

    #[tokio::test]
    async fn eviction_is_least_recently_released_first() {
        let (root, source) = fixture();
        let cache = open(root.path(), 300, &source);
        let [a, b, c, d] = ["a", "b", "c", "d"].map(|name| source.put(name, 100));
        for object in [&a, &b, &c, &a] {
            drop(cache.ensure_local(std::slice::from_ref(object)).await.unwrap());
        }
        drop(cache.ensure_local(std::slice::from_ref(&d)).await.unwrap());
        let present = |object: &ReaderObjectRef| object_path(root.path(), "t1", &object.sha256).exists();
        assert!(!present(&b), "the least recently released object is evicted");
        assert!(present(&a) && present(&c) && present(&d));
        let stats = cache.stats();
        assert_eq!((stats.evictions, stats.stored_bytes), (1, 300));
    }

    #[test]
    fn background_prewarm_budget_respects_capacity_and_query_budget() {
        let (root, source) = fixture();
        let cache = open(root.path(), 800, &source);
        assert_eq!(cache.prewarm_max_bytes(), 100);
        let root2 = tempfile::tempdir().unwrap();
        let mut configured = settings(root2.path(), 800);
        configured.query_max_bytes = 50;
        let cache = ReaderObjectCache::open(configured, "t1", "bucket", "prefix", source).unwrap();
        assert_eq!(cache.prewarm_max_bytes(), 50);
    }

    #[tokio::test]
    async fn leased_objects_are_never_evicted() {
        let (root, source) = fixture();
        let cache = open(root.path(), 200, &source);
        let [a, b, c] = ["a", "b", "c"].map(|name| source.put(name, 100));
        let lease = cache.ensure_local(&[a.clone(), b.clone()]).await.unwrap();
        // NAN-4138: a held lease outlasting the bounded wait still ends in
        // a retryable `Saturated`, never in evicting a leased object.
        cache.set_saturation_wait(Duration::from_millis(300));
        let started = Instant::now();
        let error = cache.ensure_local(std::slice::from_ref(&c)).await.unwrap_err();
        assert!(started.elapsed() >= Duration::from_millis(300), "the read waited before giving up");
        assert!(matches!(error, ReaderCacheError::Saturated { needed_bytes: 100 }), "{error}");
        assert!(error.retryable());
        assert!(lease.paths().iter().all(|path| path.exists()));
        drop(lease);
        cache.ensure_local(&[c]).await.unwrap();
        assert_eq!(cache.stats().evictions, 1);
    }

    /// NAN-4154: a request blocked on saturation stops waiting at its own
    /// deadline (not the 120 s interactive wait): the read fails retryably
    /// (503, promoted to a durable job by the search service) and the
    /// request holds 0 leases from then on, its partial lease included.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_saturated_read_past_its_deadline_escalates_holding_no_leases() {
        let (root, source) = fixture();
        let cache = open(root.path(), 300, &source);
        let [a, b, c, d] = ["a", "b", "c", "d"].map(|name| source.put(name, 100));
        // Another query holds two thirds of the cache.
        let other = cache.ensure_local(&[a.clone(), b.clone()]).await.unwrap();
        assert_eq!(pin_dirs(root.path()), 1);
        let started = Instant::now();
        let error = crate::query_timing::measure("nan4154-deadline", async {
            // ~1 s of interactive budget left after the margin.
            crate::query_timing::record(|p| p.execution_seconds = crate::query_timing::DEADLINE_MARGIN.as_secs() + 1);
            // c lands (a partial lease); d waits for capacity that never frees.
            let partial = cache.ensure_local(std::slice::from_ref(&c)).await.unwrap();
            let blocked = cache.ensure_local(std::slice::from_ref(&d)).await;
            drop(partial);
            blocked.map(drop)
        })
        .await
        .unwrap_err();
        assert!(started.elapsed() < Duration::from_secs(10), "waited {:?}, past the request deadline", started.elapsed());
        assert!(started.elapsed() >= Duration::from_millis(500), "it waited for capacity first");
        assert!(matches!(error, ReaderCacheError::Saturated { .. }), "{error}");
        assert!(error.retryable(), "retryable: the search service escalates it");
        assert_eq!(pin_dirs(root.path()), 1, "only the other query's lease is held");
        assert_eq!(temporaries(root.path()), 0);
        // Outside a request (a durable job, background work) the configured wait applies.
        assert_eq!(crate::query_timing::time_left(), None);
        drop(other);
    }

    /// NAN-4138: no files under `pins/` (every lease released).
    fn pin_dirs(root: &Path) -> usize {
        std::fs::read_dir(tenant_directory(root, "t1").join("pins")).unwrap().count()
    }

    fn temporaries(root: &Path) -> usize {
        std::fs::read_dir(tenant_directory(root, "t1").join("objects")).unwrap()
            .filter(|entry| entry.as_ref().unwrap().file_name().to_string_lossy().starts_with(TEMP_PREFIX))
            .count()
    }

    /// NAN-4138 (lean-internal, 10-19): hourly merges and wide reads filled
    /// the hot-window volume and searches failed with 500 "reader cache is
    /// saturated". A foreground read now waits for capacity: it succeeds
    /// once a lease ends, and stages nothing (no reservation, no temp file,
    /// no fetch) while it waits, so the wait cannot grow memory or disk.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn saturated_foreground_read_waits_for_capacity_then_succeeds() {
        let (root, source) = fixture();
        let cache = open(root.path(), 200, &source);
        cache.set_saturation_wait(Duration::from_secs(30));
        let [a, b, c] = ["a", "b", "c"].map(|name| source.put(name, 100));
        let lease = cache.ensure_local(&[a.clone(), b.clone()]).await.unwrap();
        let reads_before = source.reads();
        let waiting = tokio::spawn({
            let (cache, c) = (cache.clone(), c.clone());
            async move { cache.ensure_local(std::slice::from_ref(&c)).await }
        });
        let mut peak_stored = 0;
        for _ in 0..10 {
            tokio::time::sleep(Duration::from_millis(50)).await;
            assert!(!waiting.is_finished(), "a saturated read waits, it does not fail");
            let stats = cache.stats();
            peak_stored = peak_stored.max(stats.stored_bytes);
            assert_eq!(cache.inner.state().reserved, 0, "nothing reserved while waiting");
            assert_eq!(temporaries(root.path()), 0, "no partial download while waiting");
        }
        assert!(peak_stored <= 200, "the cache stayed within its budget: {peak_stored}");
        assert_eq!(source.reads(), reads_before, "the waiting read fetched nothing");
        assert!(lease.paths().iter().all(|path| path.exists()), "leased objects were not evicted");
        drop(lease);
        let lease = tokio::time::timeout(Duration::from_secs(10), waiting).await.unwrap().unwrap().unwrap();
        assert!(lease.pinned_path(&c.sha256).exists());
        assert!(cache.stats().stored_bytes <= 200);
        drop(lease);
        assert_eq!(pin_dirs(root.path()), 0);
    }

    /// NAN-4138: background hydration still defers at once (its pass
    /// retries), so it never queues behind searches for capacity.
    #[tokio::test]
    async fn saturated_background_hydration_defers_without_waiting() {
        let (root, source) = fixture();
        let cache = open(root.path(), 200, &source);
        cache.set_saturation_wait(Duration::from_secs(30));
        let [a, b, c] = ["a", "b", "c"].map(|name| source.put(name, 100));
        let _lease = cache.ensure_local(&[a, b]).await.unwrap();
        let started = Instant::now();
        let error = background_hydrate(0, cache.ensure_local(std::slice::from_ref(&c))).await.unwrap_err();
        assert!(matches!(error, ReaderCacheError::Saturated { .. }), "{error}");
        assert!(started.elapsed() < Duration::from_secs(5));
    }

    /// NAN-4138: a cancelled read (request deadline, client gone) releases
    /// everything it held: its pins, its in-process holds, and, once the
    /// detached download ends, its capacity reservation. Covers a read
    /// cancelled mid-download and one cancelled while waiting on saturation.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn cancelled_reads_release_leases_holds_and_reservations() {
        let (root, source) = fixture();
        let cache = open(root.path(), 300, &source);
        cache.set_saturation_wait(Duration::from_secs(30));
        let [a, b, c, d] = ["a", "b", "c", "d"].map(|name| source.put(name, 100));
        // Cancelled mid-download.
        drop(cache.ensure_local(std::slice::from_ref(&a)).await.unwrap());
        source.delay_ms.store(400, Ordering::SeqCst);
        let cancelled = tokio::time::timeout(Duration::from_millis(50), cache.ensure_local(&[a.clone(), b.clone()])).await;
        assert!(cancelled.is_err(), "the read was cancelled mid-download");
        assert_eq!(pin_dirs(root.path()), 0, "the cancelled lease's pins are gone");
        assert!(cache.inner.state().holds.is_empty(), "no in-process holds remain");
        assert!(cache.inner.state().live.is_empty());
        // The detached download finishes (or fails) and returns its bytes.
        for _ in 0..100 {
            if cache.inner.state().inflight.is_empty() { break }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert_eq!(cache.inner.state().reserved, 0, "the download's reservation was released");
        source.delay_ms.store(0, Ordering::SeqCst);
        // Cancelled while waiting for capacity.
        let lease = cache.ensure_local(&[b.clone(), c.clone(), a.clone()]).await.unwrap();
        let cancelled = tokio::time::timeout(Duration::from_millis(300), cache.ensure_local(std::slice::from_ref(&d))).await;
        assert!(cancelled.is_err(), "the read was still waiting for capacity");
        assert_eq!(pin_dirs(root.path()), 1, "only the live lease remains pinned");
        assert!(cache.inner.state().holds.is_empty());
        assert_eq!(cache.inner.state().reserved, 0);
        drop(lease);
        assert_eq!(pin_dirs(root.path()), 0);
        // Everything released: the cache is fully usable again.
        let lease = cache.ensure_local(std::slice::from_ref(&d)).await.unwrap();
        assert!(lease.pinned_path(&d.sha256).exists());
    }

    /// NAN-4138: a batched cold read's spool reservation waits out
    /// saturation too, and a spool larger than the whole cache is refused at
    /// once (permanent, not transient).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn scratch_reservation_waits_for_capacity() {
        let (root, source) = fixture();
        let cache = open(root.path(), 200, &source);
        cache.set_saturation_wait(Duration::from_secs(30));
        let [a, b] = ["a", "b"].map(|name| source.put(name, 100));
        let lease = cache.ensure_local(&[a, b]).await.unwrap();
        let waiting = tokio::spawn({
            let cache = cache.clone();
            async move { cache.reserve_scratch_waiting(100).await }
        });
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(!waiting.is_finished());
        drop(lease);
        let reservation = tokio::time::timeout(Duration::from_secs(10), waiting).await.unwrap().unwrap().unwrap();
        assert_eq!(cache.inner.state().reserved, 100);
        drop(reservation);
        let started = Instant::now();
        assert!(matches!(cache.reserve_scratch_waiting(201).await, Err(ReaderCacheError::Saturated { .. })));
        assert!(started.elapsed() < Duration::from_secs(5));
    }

    /// NAN-4222: every lease of one verified object hands native readers the
    /// same path (chDB caches parsed Parquet footers by path), the very inode
    /// the lease pins; eviction removes the link with the object.
    #[tokio::test]
    async fn leases_share_a_stable_read_path_on_the_pinned_inode() {
        let (root, source) = fixture();
        let cache = open(root.path(), 400, &source);
        let other = open(root.path(), 400, &source);
        let object = source.put("stable", 100);
        let first = cache.ensure_local(std::slice::from_ref(&object)).await.unwrap();
        let second = other.ensure_local(std::slice::from_ref(&object)).await.unwrap();
        let path = first.pinned_path(&object.sha256);
        assert_eq!(path, second.pinned_path(&object.sha256), "one path across leases and processes");
        assert!(path.starts_with(tenant_directory(root.path(), "t1").join("reads")), "{}", path.display());
        let inode = |path: &Path| { let m = std::fs::metadata(path).unwrap(); (m.dev(), m.ino()) };
        assert_eq!(inode(&path), inode(&cache.object_path(&object.sha256)));
        drop((first, second));
        let third = cache.ensure_local(std::slice::from_ref(&object)).await.unwrap();
        assert_eq!(third.pinned_path(&object.sha256), path, "the path outlives the leases that made it");
        drop(third);
        assert!(other.evict_unleased(vec![object.sha256.clone()]).await.unwrap().is_empty());
        assert!(!path.exists(), "eviction removes the read link with the object");
    }

    /// NAN-4222: a read link is never moved off an inode a live lease still
    /// pins; a lease of the replacement inode reads through its private pin
    /// until then, and the next lease after release relinks.
    #[tokio::test]
    async fn read_link_is_not_redirected_while_its_inode_is_pinned() {
        let (root, source) = fixture();
        let cache = open(root.path(), 400, &source);
        let object = source.put("replaced", 100);
        let old = cache.ensure_local(std::slice::from_ref(&object)).await.unwrap();
        let read = old.pinned_path(&object.sha256);
        let inode = |path: &Path| { let m = std::fs::metadata(path).unwrap(); (m.dev(), m.ino()) };
        let old_inode = inode(&read);
        // Replace the canonical object with a fresh inode of the same bytes
        // (an integrity re-fetch, or another process's re-admission).
        let canonical = cache.object_path(&object.sha256);
        let bytes = std::fs::read(&canonical).unwrap();
        std::fs::remove_file(&canonical).unwrap();
        cache.inner.state().entries.remove(&object.sha256);
        let staged = canonical.with_extension("staged");
        std::fs::write(&staged, &bytes).unwrap();
        std::fs::set_permissions(&staged, std::fs::Permissions::from_mode(OBJECT_MODE)).unwrap();
        std::fs::rename(&staged, &canonical).unwrap();
        let new = cache.ensure_local(std::slice::from_ref(&object)).await.unwrap();
        let path = new.pinned_path(&object.sha256);
        assert_ne!(path, read, "the pinned read link keeps its inode");
        assert_eq!(inode(&read), old_inode);
        assert_eq!(inode(&path), inode(&canonical));
        assert_eq!(old.pinned_path(&object.sha256), read);
        drop((old, new));
        let next = cache.ensure_local(std::slice::from_ref(&object)).await.unwrap();
        assert_eq!(next.pinned_path(&object.sha256), read, "relinked once the old inode is free");
        assert_eq!(inode(&read), inode(&canonical));
    }

    /// NAN-4222: a read link whose object is gone and whose inode no lease
    /// pins is swept at open, so it cannot hold disk space.
    #[tokio::test]
    async fn stale_read_links_are_swept_at_open() {
        let (root, source) = fixture();
        let cache = open(root.path(), 400, &source);
        let object = source.put("orphan", 100);
        let read = cache.ensure_local(std::slice::from_ref(&object)).await.unwrap().pinned_path(&object.sha256);
        std::fs::remove_file(cache.object_path(&object.sha256)).unwrap();
        assert!(read.exists());
        drop(cache);
        let _reopened = open(root.path(), 400, &source);
        assert!(!read.exists());
    }

    #[tokio::test]
    async fn superseded_object_retirement_waits_for_cross_process_lease() {
        let (root, source) = fixture();
        let cache = open(root.path(), 200, &source);
        let other = open(root.path(), 200, &source);
        let object = source.put("retired", 100);
        let lease = cache.ensure_local(std::slice::from_ref(&object)).await.unwrap();
        assert_eq!(other.evict_unleased(vec![object.sha256.clone()]).await.unwrap(), vec![object.sha256.clone()]);
        assert!(cache.object_path(&object.sha256).exists());
        drop(lease);
        assert!(other.evict_unleased(vec![object.sha256.clone()]).await.unwrap().is_empty());
        assert!(!cache.object_path(&object.sha256).exists());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_search_footers_survive_capacity_retirement_and_inode_replacing_refetch() {
        let (root, source) = fixture();
        let schema = Arc::new(arrow_schema::Schema::new(vec![arrow_schema::Field::new("time", arrow_schema::DataType::Int64, false)]));
        let batch = arrow_array::RecordBatch::try_new(schema.clone(), vec![Arc::new(arrow_array::Int64Array::from_iter_values(0..256))]).unwrap();
        let mut body = Vec::new();
        let mut writer = parquet::arrow::ArrowWriter::try_new(&mut body, schema, None).unwrap();
        writer.write(&batch).unwrap();
        writer.close().unwrap();
        let bytes = body.len();
        let cache = Arc::new(open(root.path(), (bytes * 2) as u64, &source));
        let other = Arc::new(open(root.path(), (bytes * 2) as u64, &source));
        let mut a = source.put("selected", bytes);
        a.sha256 = hex::encode(Sha256::digest(&body));
        source.objects.lock().unwrap().insert(a.source_uri.clone(), body);
        let b = source.put("merged", bytes);
        let c = source.put("pressure", bytes);
        let footers = Arc::new(crate::part_query::prune::FileMetadataCache::default());
        let lease = cache.ensure_local(std::slice::from_ref(&a)).await.unwrap();
        let pinned = lease.pinned_path(&a.sha256);
        let expected = std::fs::read(&pinned).unwrap();
        let mut readers = Vec::new();
        for _ in 0..8 {
            let (cache, a, footers) = (cache.clone(), a.clone(), footers.clone());
            readers.push(tokio::spawn(async move {
                for _ in 0..100 {
                    let lease = cache.ensure_local(std::slice::from_ref(&a)).await.unwrap();
                    let summary = footers.summary(&lease.pinned_path(&a.sha256), &a.sha256).unwrap();
                    assert_eq!(summary.ranges, vec![(0, 256)]);
                    tokio::task::yield_now().await;
                }
            }));
        }
        for _ in 0..20 {
            drop(other.ensure_local(std::slice::from_ref(&b)).await.unwrap());
            drop(other.ensure_local(std::slice::from_ref(&c)).await.unwrap());
            assert_eq!(other.evict_unleased(vec![a.sha256.clone()]).await.unwrap(), vec![a.sha256.clone()]);
            assert_eq!(std::fs::read(&pinned).unwrap(), expected);
        }
        for reader in readers { reader.await.unwrap(); }
        assert_eq!(footers.summaries(), 1, "all searches share the verified-content footer");
        // Model another process replacing the canonical name with a verified
        // re-fetch. Existing statements must keep reading their selected inode.
        let canonical = cache.object_path(&a.sha256);
        std::fs::remove_file(&canonical).unwrap();
        drop(other.ensure_local(std::slice::from_ref(&a)).await.unwrap());
        assert_ne!(std::fs::metadata(&canonical).unwrap().ino(), std::fs::metadata(&pinned).unwrap().ino());
        assert_eq!(std::fs::read(&pinned).unwrap(), expected);
        // NAN-4222: the selected path is the stable read link; it stays on the
        // old inode while this lease pins it and moves to the re-fetch after.
        assert_eq!(pinned, cache.inner.read_path(&a.sha256));
        drop(lease);
        let next = cache.ensure_local(std::slice::from_ref(&a)).await.unwrap();
        assert_eq!(next.pinned_path(&a.sha256), pinned);
        assert_eq!(std::fs::metadata(&canonical).unwrap().ino(), std::fs::metadata(&pinned).unwrap().ino());
    }

    #[tokio::test]
    async fn protected_objects_are_never_evicted() {
        let (root, source) = fixture();
        let cache = open(root.path(), 200, &source);
        let [a, b, c] = ["a", "b", "c"].map(|name| source.put(name, 100));
        drop(cache.ensure_local(std::slice::from_ref(&a)).await.unwrap());
        drop(cache.ensure_local(std::slice::from_ref(&b)).await.unwrap());
        cache.set_protected([a.sha256.clone()]);
        drop(cache.ensure_local(std::slice::from_ref(&c)).await.unwrap());
        assert!(object_path(root.path(), "t1", &a.sha256).exists());
        assert!(!object_path(root.path(), "t1", &b.sha256).exists());
        cache.set_protected([a.sha256.clone(), c.sha256.clone()]);
        cache.set_saturation_wait(Duration::ZERO);
        let error = cache.ensure_local(&[b]).await.unwrap_err();
        assert!(matches!(error, ReaderCacheError::Saturated { .. }), "{error}");
    }

    #[tokio::test]
    async fn reopen_indexes_objects_and_sweeps_crash_debris() {
        let (root, source) = fixture();
        let a = source.put("a", 100);
        drop(open(root.path(), 10_000, &source).ensure_local(std::slice::from_ref(&a)).await.unwrap());
        let objects = tenant_directory(root.path(), "t1").join("objects");
        std::fs::write(objects.join(".fetch-crashed.tmp"), b"partial").unwrap();
        let writable = objects.join(format!("{}.bin", "b".repeat(64)));
        std::fs::write(&writable, b"not admitted by the cache").unwrap();
        let stale_pin = tenant_directory(root.path(), "t1").join("pins").join("dead-lease");
        std::fs::create_dir(&stale_pin).unwrap();
        std::fs::write(stale_pin.join(".lease"), b"").unwrap();

        let cache = open(root.path(), 10_000, &source);
        assert_eq!(objects_dir_entries(root.path()), vec![format!("{}.bin", a.sha256)]);
        assert!(!stale_pin.exists());
        assert_eq!(cache.stats().objects, 1);
        let lease = cache.ensure_local(&[a]).await.unwrap();
        assert_eq!((lease.hits(), lease.misses()), (1, 0));
        assert_eq!(source.reads(), 1);
    }

    #[tokio::test]
    async fn tampered_local_bytes_are_evicted_and_refetched() {
        let (root, source) = fixture();
        let cache = open(root.path(), 10_000, &source);
        let a = source.put("a", 100);
        drop(cache.ensure_local(std::slice::from_ref(&a)).await.unwrap());
        let path = object_path(root.path(), "t1", &a.sha256);
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        std::fs::write(&path, vec![0_u8; 100]).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o444)).unwrap();
        let lease = cache.ensure_local(std::slice::from_ref(&a)).await.unwrap();
        assert_eq!((lease.hits(), lease.misses()), (0, 1));
        assert_eq!(crate::native::file_sha256(&path).unwrap(), a.sha256);
        assert_eq!(source.reads(), 2);
    }

    #[tokio::test]
    async fn same_stamp_collision_rehashes_recent_corrupt_bytes() {
        let (root, source) = fixture();
        let cache = open(root.path(), 10_000, &source);
        let object = source.put("collision", 100);
        drop(cache.ensure_local(std::slice::from_ref(&object)).await.unwrap());
        let path = object_path(root.path(), "t1", &object.sha256);
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        std::fs::write(&path, vec![0_u8; 100]).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o444)).unwrap();
        // Model a filesystem that rounds both timestamp observations to the
        // same tick: all metadata in the memoized stamp appears unchanged.
        cache
            .inner
            .state
            .lock()
            .unwrap()
            .entries
            .get_mut(&object.sha256)
            .unwrap()
            .stamp = FileStamp::read(&path).unwrap();
        let observed = FileStamp::read(&path).unwrap();
        assert!(!cache
            .inner
            .verified_hit_at(&object, Some(observed.modified.0))
            .unwrap());
        let lease = cache.ensure_local(std::slice::from_ref(&object)).await.unwrap();
        assert_eq!((lease.hits(), lease.misses()), (0, 1));
        assert_eq!(crate::native::file_sha256(&path).unwrap(), object.sha256);
        assert_eq!(source.reads(), 2);
    }

    #[tokio::test]
    async fn marker_for_another_tenant_or_bucket_fails_closed() {
        let (root, source) = fixture();
        let a = source.put("a", 100);
        drop(open(root.path(), 10_000, &source).ensure_local(&[a]).await.unwrap());
        let settings = settings(root.path(), 10_000);
        let reopen = |tenant: &str, bucket: &str, prefix: &str| {
            ReaderObjectCache::open(settings.clone(), tenant, bucket, prefix, source.clone())
        };
        for (bucket, prefix) in [("bucket-b", PREFIX), (BUCKET, "tenants/t2/table")] {
            let error = reopen("t1", bucket, prefix).unwrap_err();
            assert!(matches!(error, ReaderCacheError::OutsideTenant(_)), "{error}");
        }
        // t1's marker copied into t2's directory is not adopted.
        let t2 = tenant_directory(root.path(), "t2");
        std::fs::create_dir_all(&t2).unwrap();
        std::fs::copy(tenant_directory(root.path(), "t1").join(MARKER_FILE), t2.join(MARKER_FILE))
            .unwrap();
        assert!(matches!(reopen("t2", BUCKET, PREFIX), Err(ReaderCacheError::OutsideTenant(_))));
        // Objects without any marker have unknown provenance.
        std::fs::remove_file(tenant_directory(root.path(), "t1").join(MARKER_FILE)).unwrap();
        assert!(matches!(reopen("t1", BUCKET, PREFIX), Err(ReaderCacheError::OutsideTenant(_))));
        assert!(matches!(reopen("../t1", BUCKET, PREFIX), Err(ReaderCacheError::InvalidConfig(_))));
    }

    #[tokio::test]
    async fn objects_outside_the_tenant_prefix_are_rejected_without_reads() {
        let (root, source) = fixture();
        let cache = open(root.path(), 10_000, &source);
        let good = source.put("a", 100);
        for uri in [
            format!("s3://bucket-b/{PREFIX}/data/a.bin"),
            "s3://bucket-a/tenants/t2/table/data/a.bin".to_string(),
            format!("s3://{BUCKET}/{PREFIX}-evil/data/a.bin"),
            format!("s3://{BUCKET}/{PREFIX}/../../t2/table/a.bin"),
            format!("s3://{BUCKET}/{PREFIX}"),
            format!("https://r2.example/{BUCKET}/{PREFIX}/data/a.bin"),
        ] {
            let object = ReaderObjectRef { source_uri: uri.clone(), ..good.clone() };
            // A good object alongside proves nothing is fetched for the batch.
            let error = cache.ensure_local(&[good.clone(), object]).await.unwrap_err();
            assert!(matches!(error, ReaderCacheError::OutsideTenant(_)), "{uri}: {error}");
            assert_eq!(error.reason(), "reader_cache_outside_tenant");
        }
        assert_eq!(source.reads(), 0);
        let bad_digest = ReaderObjectRef { sha256: "A".repeat(64), ..good };
        assert!(cache.ensure_local(&[bad_digest]).await.is_err());
        assert_eq!(source.reads(), 0);
    }

    #[test]
    fn settings_parse_the_flag_and_fail_closed() {
        let parse = |pairs: &[(&str, &str)]| {
            let map: HashMap<String, String> =
                pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
            ReaderObjectCacheSettings::from_lookup(|name| map.get(name).cloned())
        };
        assert_eq!(parse(&[]).unwrap(), None);
        assert_eq!(parse(&[(READER_CACHE_MODE_ENV, "full")]).unwrap(), None);
        assert_eq!(parse(&[(READER_CACHE_MODE_ENV, " ")]).unwrap(), None);
        for bad in [
            vec![(READER_CACHE_MODE_ENV, "lazy")],
            vec![(READER_CACHE_MODE_ENV, "bounded")],
            vec![(READER_CACHE_MODE_ENV, "bounded"), (READER_CACHE_BYTES_ENV, "100")],
            vec![(READER_CACHE_MODE_ENV, "bounded"), (READER_CACHE_DIR_ENV, "relative"), (READER_CACHE_BYTES_ENV, "100")],
            vec![(READER_CACHE_MODE_ENV, "bounded"), (READER_CACHE_DIR_ENV, "/c"), (READER_CACHE_BYTES_ENV, "0")],
            vec![(READER_CACHE_MODE_ENV, "bounded"), (READER_CACHE_DIR_ENV, "/c"), (READER_CACHE_BYTES_ENV, "x")],
            vec![(READER_CACHE_MODE_ENV, "bounded"), (READER_CACHE_DIR_ENV, "/c"), (READER_CACHE_BYTES_ENV, "9"), (READER_CACHE_FETCH_CONCURRENCY_ENV, "0")],
        ] {
            let error = parse(&bad).unwrap_err();
            assert_eq!(error.reason(), "reader_cache_invalid_config", "{bad:?}");
        }
        let settings = parse(&[
            (READER_CACHE_MODE_ENV, "bounded"),
            (READER_CACHE_DIR_ENV, "/var/cache/reader"),
            (READER_CACHE_BYTES_ENV, "15032385536"),
        ])
        .unwrap()
        .unwrap();
        assert_eq!(
            settings,
            ReaderObjectCacheSettings {
                root: PathBuf::from("/var/cache/reader"),
                max_bytes: 15_032_385_536,
                query_max_bytes: DEFAULT_QUERY_MAX_BYTES,
                fetch_concurrency: DEFAULT_FETCH_CONCURRENCY,
                fetch_deadline: DEFAULT_FETCH_DEADLINE,
            }
        );
    }
}
