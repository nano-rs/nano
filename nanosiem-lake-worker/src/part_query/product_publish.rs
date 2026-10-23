// SPDX-License-Identifier: AGPL-3.0-or-later
//! NAN-3148: product state OFF the query role.
//!
//! Product state (the prevalence explorer windows 1h/24h/7d/30d with their
//! 30-day history, per-artifact detail and the risk ledger) used to be built
//! inside query[T], on query's CPU quota, beside analyst search. With the
//! cell's `product_state_role` it is built by `product[T]` instead (the same
//! binary, its own cgroup leaf and budget) and handed over as files:
//!
//! * **Publisher** (product[T]): builds every state file exactly as the
//!   in-process path did (same functions, same SQL, same content-addressed
//!   names) into its state dir, then publishes `product-manifest.json`, a
//!   versioned index of the current window snapshots and the latest
//!   demand-built entries. The manifest is written to a temporary file and
//!   renamed into place, so a reader sees one whole version or the next.
//! * **Consumer** (query[T]): reads the manifest (re-parsed only when the
//!   file changes, so a new version swaps in atomically), serves the newest
//!   snapshot, marked stale once old, and never builds. A miss it cannot
//!   serve files a small JSON demand in `product/demand/` (the only path it
//!   may write beneath product/) and answers `product_state_warming`.
//!
//! Churn rules (the publisher): one task, so builds never overlap; a cycle
//! runs at most once per [`CYCLE_GAP`] after the previous one ENDED, and is
//! skipped when the verified part-log head has not moved since the last
//! complete cycle (no new, merged or retired parts). Demands are served
//! between windows. NAN-3168: within a cycle each window is rebuilt only
//! when its published snapshot predates the head AND is older than the
//! window's own rebuild interval ([`Cadence`]: 1h every cycle, 24h every
//! 30 min, 7d/30d every 2 h by default); a deferred window keeps serving its
//! last exact snapshot, and every statement runs on the product thread
//! budget (`product_state::THREADS_ENV`). Files the manifest references are touched every tick so
//! the age-based pruning never removes a published snapshot.
//!
//! Without the role (`product_state_role` off, the default) query[T] runs the
//! same publisher IN-PROCESS ([`Mode::InProcess`]): one task on a dedicated
//! nice-19 thread with its own runtime, publishing into query's own state
//! dir, under the same cadence and skip rules. Its request path is a
//! consumer of that dir exactly as above: it never builds, it serves the
//! newest snapshot and files demands for the in-process publisher.

use super::engine::{PartQueryEngine, PartQueryError, QueryResult};
use super::product_state::{self, Work};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};

/// The published index, beside the state files it names.
pub const MANIFEST: &str = "product-manifest.json";
pub const FORMAT: &str = "nano-product-state-v1";
/// query[T]'s inbox beneath product/ (`nanosiem_lake_cell::tenant_dirs::PRODUCT_DEMAND_DIR`).
pub const DEMAND_DIR: &str = "demand";
/// The moving windows every cycle publishes (the explorer's set).
pub const WINDOWS: [&str; 4] = ["1h", "24h", "7d", "30d"];
/// Minimum idle time between the end of one cycle and the start of the next
/// (override: [`CYCLE_ENV`], seconds, at least 60).
pub const CYCLE_GAP: Duration = Duration::from_secs(600);
/// The cadence knob, for the role and the in-process publisher alike.
pub const CYCLE_ENV: &str = "NANO_LAKE_PRODUCT_STATE_CYCLE_SECS";
/// Longest retry delay after a failed cycle (1 s doubling up to this).
const CYCLE_RETRY: Duration = Duration::from_secs(60);
/// The in-process publisher thread's niceness (NAN-3148, flag off).
const IN_PROCESS_NICE: libc::c_int = 19;
/// Stack of the in-process publisher thread (NAN-3141: large build futures).
const IN_PROCESS_STACK_BYTES: usize = 16 * 1024 * 1024;

/// The configured cycle gap.
pub fn cycle_gap() -> Duration {
    std::env::var(CYCLE_ENV).ok().and_then(|value| value.trim().parse::<u64>().ok())
        .map(|secs| Duration::from_secs(secs.max(60)))
        .unwrap_or(CYCLE_GAP)
}

/// Delay before retrying after `failures` consecutive failed cycles.
fn retry_after(failures: u32) -> Duration {
    Duration::from_secs(1u64 << failures.min(6)).min(CYCLE_RETRY)
}
/// A manifest older than this (plus the window's rebuild interval) is served
/// marked `stale`.
pub const STALE_AFTER: Duration = Duration::from_secs(1_800);

/// NAN-3168: each moving window's minimum rebuild interval, its env knob
/// (seconds) and default. A full 24h/7d/30d merge every cycle cost ~45 s of
/// a core each on the load-test tenant; the long windows move little per cycle.
pub const WINDOW_REBUILD: [(&str, &str, u64); 4] = [
    ("1h", "NANO_LAKE_PRODUCT_STATE_REBUILD_1H_SECS", 0),
    ("24h", "NANO_LAKE_PRODUCT_STATE_REBUILD_24H_SECS", 1_800),
    ("7d", "NANO_LAKE_PRODUCT_STATE_REBUILD_7D_SECS", 7_200),
    ("30d", "NANO_LAKE_PRODUCT_STATE_REBUILD_30D_SECS", 7_200),
];
/// Upper bound of a configured rebuild interval (a day).
const MAX_REBUILD_SECS: u64 = 86_400;

/// Per-window minimum rebuild intervals (NAN-3168).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cadence(BTreeMap<String, Duration>);

impl Cadence {
    /// From the process environment ([`WINDOW_REBUILD`]).
    pub fn from_env() -> Self {
        Self::from_lookup(|name| std::env::var(name).ok())
    }

    fn from_lookup(lookup: impl Fn(&str) -> Option<String>) -> Self {
        Self(WINDOW_REBUILD.iter().map(|(window, env, default)| {
            let secs = lookup(env).and_then(|value| value.trim().parse::<u64>().ok()).unwrap_or(*default);
            (window.to_string(), Duration::from_secs(secs.min(MAX_REBUILD_SECS)))
        }).collect())
    }

    /// Every window rebuilt whenever the head moves (the pre-NAN-3168 rule).
    pub fn every_cycle() -> Self {
        Self(WINDOWS.iter().map(|window| (window.to_string(), Duration::ZERO)).collect())
    }

    pub fn interval(&self, window: &str) -> Duration {
        self.0.get(window).copied().unwrap_or_default()
    }

    /// A published window is stale once it is older than its rebuild
    /// interval plus [`STALE_AFTER`].
    pub fn stale_after(&self, window: &str) -> Duration {
        STALE_AFTER + self.interval(window)
    }

    /// Which windows a cycle at part-log `head` rebuilds (and which it
    /// defers), in [`WINDOWS`] order.
    pub fn plan(&self, manifest: &Manifest, head: Option<u64>, now_us: i64) -> Plan {
        let mut plan = Plan::default();
        for window in WINDOWS {
            if window_due(manifest.windows.get(window), head, self.interval(window), now_us) {
                plan.rebuild.push(window);
            } else {
                plan.deferred.push(window);
            }
        }
        plan
    }
}

/// The process's configured cadence (consumers: staleness).
fn cadence() -> &'static Cadence {
    static CADENCE: std::sync::OnceLock<Cadence> = std::sync::OnceLock::new();
    CADENCE.get_or_init(Cadence::from_env)
}

/// One cycle's window plan.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Plan {
    pub rebuild: Vec<&'static str>,
    pub deferred: Vec<&'static str>,
}

/// Whether a window whose newest snapshot is `entry` is rebuilt at `head`:
/// never published; or its snapshot predates `head` (or the head is
/// unknown) and is at least `interval` old.
pub fn window_due(entry: Option<&WindowEntry>, head: Option<u64>, interval: Duration, now_us: i64) -> bool {
    match entry {
        None => true,
        Some(entry) => (head.is_none() || entry.log_head != head) && age(entry.built_at_us, now_us) >= interval,
    }
}
/// A demand-built entry (detail, risk lookback) older than this is not
/// served in place of the exact state; the request warms instead.
pub const LATEST_SERVE_MAX: Duration = Duration::from_secs(3_600);
/// A served latest entry older than this also files a demand to refresh it.
pub const DEMAND_REFRESH: Duration = Duration::from_secs(300);
const MAX_DEMANDS: usize = 64;
/// NAN-3858: a safety net on one detail demand's wall time, not its budget.
/// The scan's own budget ([`super::detail_scan::DETAIL_BUDGET`]) counts only
/// execution: on tenant-the old 10-second wall timeout also counted the wait
/// for the idle slot behind a window build's statement (a 1h window
/// statement alone holds it ~30 s; 7d/30d ones minutes), so every demand
/// filed during a build failed before scanning anything. Waits are bounded
/// by [`super::product_state::MAX_DEFERRAL`] per background statement; this
/// only ends a build that is wedged.
pub(super) const DETAIL_BUILD_WALL: Duration = Duration::from_secs(1_800);
/// NAN-3791: how often a running window build checks the demand inbox.
const DEMAND_POLL: Duration = Duration::from_secs(1);
const MAX_LATEST: usize = 256;
const DAY_US: i64 = 86_400_000_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// product[T]: builds and publishes.
    Publisher,
    /// query[T] with a product role: reads only.
    Consumer,
    /// query[T] without one: its request path reads only (as a consumer);
    /// its own low-priority publisher task builds into the same dir.
    InProcess,
}

type Stamp = (SystemTime, u64, u64);

/// A process's view of published product state (set once on the engine).
#[derive(Debug)]
pub struct Published {
    mode: Mode,
    dir: PathBuf,
    cache: Mutex<Option<(Stamp, Arc<Manifest>)>>,
}

impl Published {
    pub fn publisher(dir: PathBuf) -> Self {
        Self { mode: Mode::Publisher, dir, cache: Mutex::new(None) }
    }

    pub fn consumer(dir: PathBuf) -> Self {
        Self { mode: Mode::Consumer, dir, cache: Mutex::new(None) }
    }

    pub fn in_process(dir: PathBuf) -> Self {
        Self { mode: Mode::InProcess, dir, cache: Mutex::new(None) }
    }

    pub fn mode(&self) -> Mode {
        self.mode
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// The newest published manifest. Re-read only when the file changed:
    /// each publish renames a new inode into place, so the swap is atomic.
    /// A manifest that fails to parse keeps the previous one in service.
    pub fn manifest(&self) -> Option<Arc<Manifest>> {
        use std::os::unix::fs::MetadataExt;
        let metadata = std::fs::metadata(self.dir.join(MANIFEST)).ok();
        let mut cache = self.cache.lock().expect("product manifest cache");
        let Some(metadata) = metadata else { return cache.as_ref().map(|(_, manifest)| manifest.clone()) };
        let stamp = (metadata.modified().unwrap_or(SystemTime::UNIX_EPOCH), metadata.len(), metadata.ino());
        if let Some((seen, manifest)) = cache.as_ref() {
            if *seen == stamp {
                return Some(manifest.clone());
            }
        }
        match read_manifest(&self.dir) {
            Some(manifest) => {
                let manifest = Arc::new(manifest);
                *cache = Some((stamp, manifest.clone()));
                Some(manifest)
            }
            None => cache.as_ref().map(|(_, manifest)| manifest.clone()),
        }
    }

    /// Whether the newest manifest has published `window` (NAN-3271).
    pub fn serves(&self, window: &str) -> bool {
        self.manifest().is_some_and(|manifest| manifest.has_window(window))
    }
}

/// One published window snapshot. File names are relative to the product
/// dir; `window: None` is a window that held no parts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WindowEntry {
    pub from_us: i64,
    pub to_us: i64,
    pub window: Option<String>,
    pub history: Option<String>,
    pub log_head: Option<u64>,
    pub built_at_us: i64,
    /// Footer-only row count: no scan or query is needed to detect first artifacts.
    #[serde(default)]
    pub artifact_rows: Option<u64>,
    /// At most one early rebuild per window, including across publisher restarts.
    #[serde(default)]
    pub warmup_complete: bool,
}

fn first_artifact_due(manifest: &Manifest, window: &str, head: Option<u64>) -> bool {
    let Some(entry) = manifest.windows.get(window) else { return false };
    !entry.warmup_complete
        && entry.artifact_rows == Some(0)
        && head.is_some()
        && entry.log_head != head
        && manifest.windows.get("1h").is_some_and(|recent|
            recent.log_head == head && recent.artifact_rows.is_some_and(|rows| rows > 0))
}

fn artifact_rows(path: Option<&Path>) -> anyhow::Result<u64> {
    use parquet::file::reader::{FileReader, SerializedFileReader};
    let Some(path) = path else { return Ok(0) };
    let reader = SerializedFileReader::new(std::fs::File::open(path)?)?;
    Ok(u64::try_from(reader.metadata().file_metadata().num_rows())?)
}

/// The newest demand- or cycle-built state of one logical key (a detail
/// request identity, a risk lookback).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LatestEntry {
    pub file: String,
    pub from_us: i64,
    pub to_us: i64,
    pub log_head: Option<u64>,
    pub built_at_us: i64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Manifest {
    pub format: String,
    /// Monotonic per publish.
    pub version: u64,
    pub tenant_id: String,
    /// Part-log head of the last COMPLETE cycle (skip key).
    #[serde(default)]
    pub log_head: Option<u64>,
    pub built_at_us: i64,
    #[serde(default)]
    pub windows: BTreeMap<String, WindowEntry>,
    #[serde(default)]
    pub latest: BTreeMap<String, LatestEntry>,
}

impl Manifest {
    pub fn new(tenant_id: &str) -> Self {
        Self { format: FORMAT.into(), tenant_id: tenant_id.into(), ..Default::default() }
    }

    fn files(&self) -> Vec<&str> {
        let windows = self.windows.values().flat_map(|entry| entry.window.iter().chain(entry.history.iter()));
        windows.chain(self.latest.values().map(|entry| &entry.file)).map(String::as_str).collect()
    }

    /// Whether every moving window has been published at least once.
    pub fn complete(&self) -> bool {
        WINDOWS.iter().all(|window| self.has_window(window))
    }

    /// Whether `window` has been published at least once (NAN-3271: a
    /// route asking for one window waits only on that window, never on a
    /// longer one that is still failing to build).
    pub fn has_window(&self, window: &str) -> bool {
        self.windows.contains_key(window)
    }

    fn insert_latest(&mut self, key: String, entry: LatestEntry) {
        self.latest.insert(key, entry);
        while self.latest.len() > MAX_LATEST {
            let oldest = self.latest.iter().min_by_key(|(_, entry)| entry.built_at_us).map(|(key, _)| key.clone());
            match oldest {
                Some(key) => { self.latest.remove(&key); }
                None => break,
            }
        }
    }
}

fn now_us() -> i64 {
    chrono::Utc::now().timestamp_micros()
}

fn age(built_at_us: i64, now_us: i64) -> Duration {
    Duration::from_micros(now_us.saturating_sub(built_at_us).max(0) as u64)
}

/// The freshness facts a consumer response carries.
pub fn freshness(manifest: &Manifest, built_at_us: i64, now_us: i64, stale_after: Duration) -> Value {
    let age = age(built_at_us, now_us);
    json!({"version": manifest.version, "log_head": manifest.log_head, "built_at_us": built_at_us,
           "age_s": age.as_secs(), "stale": age > stale_after})
}

pub fn read_manifest(dir: &Path) -> Option<Manifest> {
    let bytes = std::fs::read(dir.join(MANIFEST)).ok()?;
    match serde_json::from_slice::<Manifest>(&bytes) {
        Ok(manifest) if manifest.format == FORMAT => Some(manifest),
        Ok(manifest) => {
            tracing::warn!(format = %manifest.format, "product manifest has an unknown format; ignored");
            None
        }
        Err(error) => {
            tracing::warn!(%error, "product manifest is unreadable; ignored");
            None
        }
    }
}

/// NAN-3799: windows whose snapshot is older than the span it covers.
pub fn expired_windows(manifest: &Manifest, now_us: i64) -> Vec<String> {
    manifest.windows.iter()
        .filter(|(_, entry)| now_us.saturating_sub(entry.built_at_us) > entry.to_us.saturating_sub(entry.from_us).max(0))
        .map(|(window, _)| window.clone()).collect()
}

/// Publish atomically: write, fsync, rename over the previous version.
pub fn write_manifest(dir: &Path, manifest: &Manifest) -> std::io::Result<()> {
    use std::io::Write;
    let temporary = dir.join(format!(".{MANIFEST}.{}.tmp", uuid::Uuid::new_v4().simple()));
    let result = (|| {
        let mut file = std::fs::File::create(&temporary)?;
        file.write_all(&serde_json::to_vec(manifest).map_err(std::io::Error::other)?)?;
        file.sync_all()?;
        std::fs::rename(&temporary, dir.join(MANIFEST))
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&temporary);
    }
    result
}

/// A manifest-relative name for a file the publisher wrote into `dir`.
fn relative(dir: &Path, path: &Path) -> Option<String> {
    (path.parent() == Some(dir)).then(|| path.file_name()?.to_str().map(str::to_string)).flatten()
}

/// Resolve a manifest-relative name; anything but a plain file name is refused.
fn resolve(dir: &Path, name: &str) -> Option<PathBuf> {
    let plain = !name.is_empty() && !name.contains('/') && name != "." && name != "..";
    plain.then(|| dir.join(name))
}

pub fn detail_key(identity: &str) -> String {
    use sha2::{Digest, Sha256};
    format!("detail:{}", hex::encode(Sha256::digest(identity.as_bytes())))
}

pub fn risk_key(from_us: i64, to_us: i64) -> String {
    format!("risk:{}", to_us - from_us)
}

// ----------------------------------------------------------------- consumer

/// The published state when this call is on a READ path: a consumer, or
/// the in-process mode outside its publisher's build authority.
fn consumer(engine: &PartQueryEngine) -> Option<&Published> {
    engine.product_state().filter(|published| reads_only(published.mode()))
}

/// Whether the current call may only read product state in `mode`.
fn reads_only(mode: Mode) -> bool {
    match mode {
        Mode::Consumer => true,
        Mode::InProcess => !product_state::building(),
        Mode::Publisher => false,
    }
}

pub(super) fn is_consumer(engine: &PartQueryEngine) -> bool {
    consumer(engine).is_some()
}

/// Product state files may be written (touched, pruned) by this process.
pub(super) fn writes(engine: &PartQueryEngine) -> bool {
    !is_consumer(engine)
}

/// NAN-3271: a consumer's route over one moving `window` answers once THAT
/// window is published. Gating on every window let a 7d/30d build that kept
/// failing (chDB time cap) hold a published 24h window at
/// `product_state_warming` forever. Not a consumer: always ready.
pub(super) fn ready_for(engine: &PartQueryEngine, window: &str) -> bool {
    consumer(engine).is_none_or(|published| published.serves(window))
}

/// The newest published snapshot of a moving explorer window.
pub(super) struct PublishedWindow {
    pub window: Option<PathBuf>,
    pub history: Option<PathBuf>,
    pub to_us: i64,
    pub freshness: Value,
}

/// `None`: not a consumer (build/read in-process). `Some(Err(WARMING))`:
/// a consumer with no published snapshot of `window` yet.
pub(super) fn published_window(engine: &PartQueryEngine, window: &str) -> Option<QueryResult<PublishedWindow>> {
    let published = consumer(engine)?;
    let warming = || Err(PartQueryError::Unavailable(product_state::WARMING.into()));
    let Some(manifest) = published.manifest().filter(|manifest| manifest.tenant_id == engine.settings().tenant_id) else { return Some(warming()) };
    let Some(entry) = manifest.windows.get(window) else { return Some(warming()) };
    let stale_after = cadence().stale_after(window);
    let file = |name: &Option<String>| name.as_deref().and_then(|name| resolve(published.dir(), name));
    let (window, history) = (file(&entry.window), file(&entry.history));
    if window.as_ref().is_some_and(|path| !path.is_file()) || history.as_ref().is_some_and(|path| !path.is_file()) {
        tracing::warn!(version = manifest.version, "published product window file is missing; warming");
        return Some(warming());
    }
    let mut state = freshness(&manifest, entry.built_at_us, now_us(), stale_after);
    state["warming"] = json!(!entry.warmup_complete && entry.artifact_rows == Some(0));
    state["retry_after_s"] = json!(cycle_gap().as_secs());
    Some(Ok(PublishedWindow { window, history, to_us: entry.to_us, freshness: state }))
}

/// A consumer's fallback for state it lacks exactly: the newest published
/// entry for `key` if it is younger than [`LATEST_SERVE_MAX`] (filing a
/// refresh demand once it is older than [`DEMAND_REFRESH`]); otherwise the
/// demand is filed and `None` (the caller warms). Never builds.
pub(super) fn latest(engine: &PartQueryEngine, key: &str, work: &Work) -> Option<(PathBuf, LatestEntry)> {
    let published = consumer(engine)?;
    let now = now_us();
    let hit = published.manifest().filter(|manifest| manifest.tenant_id == engine.settings().tenant_id)
        .and_then(|manifest| manifest.latest.get(key).cloned())
        .filter(|entry| age(entry.built_at_us, now) <= LATEST_SERVE_MAX)
        .and_then(|entry| resolve(published.dir(), &entry.file).filter(|path| path.is_file()).map(|path| (path, entry)));
    if hit.as_ref().is_none_or(|(_, entry)| age(entry.built_at_us, now) > DEMAND_REFRESH) {
        demand(published.dir(), work);
    }
    hit
}

// ------------------------------------------------------------------- demand

/// What a consumer may ask the publisher to build.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum Demand {
    Window { from_us: i64, to_us: i64 },
    Detail { request: String, from_us: i64, to_us: i64 },
    Risk { from_us: i64, to_us: i64 },
}

impl Demand {
    /// Part-list work (history, whole-part prevalence) is never demanded:
    /// a window demand rebuilds it, and the cycle maintains it.
    fn from_work(work: &Work) -> Option<Self> {
        match work {
            Work::Window(from_us, to_us) => Some(Self::Window { from_us: *from_us, to_us: *to_us }),
            Work::Detail(request, from_us, to_us) => Some(Self::Detail { request: request.clone(), from_us: *from_us, to_us: *to_us }),
            Work::Risk(from_us, to_us) => Some(Self::Risk { from_us: *from_us, to_us: *to_us }),
            Work::History(_) | Work::Prevalence(_) => None,
        }
    }
}

/// File `work` in `dir`'s demand inbox (deduplicated by content, bounded).
/// Returns whether it is (now) pending.
pub(super) fn demand(dir: &Path, work: &Work) -> bool {
    use sha2::{Digest, Sha256};
    let Some(demand) = Demand::from_work(work) else { return false };
    let inbox = dir.join(DEMAND_DIR);
    let Ok(body) = serde_json::to_vec(&demand) else { return false };
    let path = inbox.join(format!("{}.json", hex::encode(Sha256::digest(&body))));
    if path.is_file() {
        return true;
    }
    let pending = match std::fs::read_dir(&inbox) {
        Ok(entries) => entries.flatten().count(),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => 0,
        Err(_) => usize::MAX,
    };
    if pending >= MAX_DEMANDS {
        tracing::warn!(pending, "product demand inbox is full or unavailable; request warms without a demand");
        return false;
    }
    let temporary = inbox.join(format!(".{}.tmp", uuid::Uuid::new_v4().simple()));
    let written = std::fs::create_dir_all(&inbox).and_then(|_| std::fs::write(&temporary, &body))
        .and_then(|_| std::fs::rename(&temporary, &path));
    if let Err(error) = written {
        let _ = std::fs::remove_file(&temporary);
        tracing::warn!(%error, "product demand not filed");
        return false;
    }
    true
}

/// NAN-3791: whether query[T] could write its demand inbox at startup
/// (`None`: not a consumer or not probed). Reported in query status.
static INBOX_WRITABLE: std::sync::OnceLock<bool> = std::sync::OnceLock::new();

/// NAN-3791: query[T]'s startup self-test of the demand inbox: write and
/// remove one probe entry. On tenant-a every demand failed with EACCES for days
/// (the jail had silently dropped the inbox's Landlock rule) and detail
/// warmed forever with only a WARN per request; now it is an ERROR at boot
/// and `product_demand_inbox_writable: false` in the query status.
pub fn probe_demand_inbox(dir: &Path) -> std::io::Result<()> {
    let inbox = dir.join(DEMAND_DIR);
    let probe = inbox.join(format!(".probe-{}.tmp", uuid::Uuid::new_v4().simple()));
    let result = std::fs::write(&probe, b"probe").and_then(|_| std::fs::remove_file(&probe));
    if result.is_err() {
        let _ = std::fs::remove_file(&probe);
    }
    let _ = INBOX_WRITABLE.set(result.is_ok());
    match &result {
        Ok(()) => tracing::info!(inbox = %inbox.display(), "product demand inbox writable"),
        Err(error) => tracing::error!(inbox = %inbox.display(), %error,
            "product demand inbox is NOT writable: detail/window demands cannot reach product[T]"),
    }
    result
}

pub fn demand_inbox_writable() -> Option<bool> {
    INBOX_WRITABLE.get().copied()
}

/// Pending demands, oldest first. Unreadable entries are removed.
pub(super) fn pending_demands(dir: &Path) -> Vec<(PathBuf, Demand)> {
    let Ok(entries) = std::fs::read_dir(dir.join(DEMAND_DIR)) else { return Vec::new() };
    let mut found = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        let name = entry.file_name().to_string_lossy().into_owned();
        if name.starts_with('.') || !name.ends_with(".json") {
            continue;
        }
        let modified = entry.metadata().and_then(|metadata| metadata.modified()).unwrap_or(SystemTime::UNIX_EPOCH);
        match std::fs::read(&path).ok().and_then(|bytes| serde_json::from_slice::<Demand>(&bytes).ok()) {
            Some(demand) => found.push((modified, path, demand)),
            None => { let _ = std::fs::remove_file(&path); }
        }
    }
    found.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(&b.1)));
    found.into_iter().map(|(_, path, demand)| (path, demand)).collect()
}

// ---------------------------------------------------------------- publisher

/// What product[T] reports in its heartbeat.
#[derive(Debug, Default)]
pub struct PublisherStatus {
    pub busy: AtomicBool,
    pub last_progress_ms: AtomicU64,
    pub version: AtomicU64,
    pub cycles_built: AtomicU64,
    pub cycles_skipped: AtomicU64,
    pub demands_built: AtomicU64,
    pub pending_demands: AtomicU64,
}

impl PublisherStatus {
    fn progressed(&self) {
        self.last_progress_ms.store(chrono::Utc::now().timestamp_millis().max(0) as u64, Ordering::Relaxed);
    }
}

/// What one cycle did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cycle {
    /// Not due yet.
    Idle,
    /// The part-log head has not moved since the last complete cycle.
    Skipped,
    Built,
    Failed,
}

/// The single product-state builder of a product[T] process.
pub struct Publisher {
    engine: Arc<PartQueryEngine>,
    manifest: Manifest,
    last_cycle_end: Option<Instant>,
    next_gap: Duration,
    cycle_gap: Duration,
    cadence: Cadence,
    failures: u32,
    status: Arc<PublisherStatus>,
    /// NAN-4154: [`super::partials::SUPERSEDED_STATE_GRACE`] unless a test sets it.
    state_grace: Duration,
    /// NAN-4154: when each window's latest build in this process started.
    rebuilt_at: std::collections::BTreeMap<&'static str, SystemTime>,
    /// NAN-4154: the state budget, unless a test sets it (volume / divisor).
    state_budget: Option<u64>,
}

/// Run `work` as product-state build authority.
async fn build<T>(engine: &PartQueryEngine, work: impl std::future::Future<Output = QueryResult<T>>) -> anyhow::Result<T> {
    let scoped = engine.pinned_if_needed(product_state::BUILD.scope((), work));
    let result = product_state::with_progress(Box::pin(scoped)).await;
    Ok(result??)
}

impl Publisher {
    /// Resume from the last published manifest (a restart rebuilds nothing
    /// unless the part log moved).
    pub fn new(engine: Arc<PartQueryEngine>, status: Arc<PublisherStatus>) -> anyhow::Result<Self> {
        let published = engine.product_state().filter(|published| published.mode() != Mode::Consumer)
            .ok_or_else(|| anyhow::anyhow!("the product publisher needs a publisher or in-process engine"))?;
        std::fs::create_dir_all(published.dir().join(DEMAND_DIR)).ok();
        let tenant = engine.settings().tenant_id.clone();
        let mut manifest = read_manifest(published.dir()).filter(|manifest| manifest.tenant_id == tenant)
            .unwrap_or_else(|| Manifest::new(&tenant));
        // NAN-3799: the published dir may outlive the pod (persistent hot
        // volume): consumers serve what is found at once, marked stale,
        // while this publisher rebuilds. A window older than its own span
        // no longer overlaps what it claims to cover; withdraw it so the
        // consumer warms instead of answering "last hour" from yesterday.
        let now = now_us();
        let expired = expired_windows(&manifest, now);
        if !expired.is_empty() {
            for window in &expired {
                manifest.windows.remove(window);
            }
            manifest.version += 1;
            manifest.built_at_us = now;
            if let Err(error) = write_manifest(published.dir(), &manifest) {
                tracing::warn!(%error, "product manifest: expired windows not withdrawn");
            }
        }
        if manifest.version > 0 {
            let ages = manifest.windows.iter().map(|(window, entry)| format!("{window}={}s", age(entry.built_at_us, now).as_secs()))
                .collect::<Vec<_>>().join(",");
            tracing::info!(version = manifest.version, windows = %ages, withdrawn = %expired.join(","),
                "product state resumed from the published manifest; serving it while rebuilding");
        }
        status.version.store(manifest.version, Ordering::Relaxed);
        let gap = cycle_gap();
        Ok(Self { engine, manifest, last_cycle_end: None, next_gap: gap, cycle_gap: gap, cadence: Cadence::from_env(), failures: 0, status,
            state_grace: super::partials::SUPERSEDED_STATE_GRACE, rebuilt_at: Default::default(), state_budget: None })
    }

    pub fn manifest(&self) -> &Manifest {
        &self.manifest
    }

    /// Replace the per-window rebuild cadence (tests, benches).
    pub fn set_cadence(&mut self, cadence: Cadence) {
        self.cadence = cadence;
    }

    fn dir(&self) -> PathBuf {
        self.engine.product_dir().to_path_buf()
    }

    /// Forever: demands first, then a due cycle, one at a time.
    pub async fn run(mut self) {
        loop {
            self.tick().await;
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    }

    pub async fn tick(&mut self) -> Cycle {
        self.touch_published();
        self.serve_demands().await;
        let due = self.last_cycle_end.is_none_or(|at| at.elapsed() >= self.next_gap);
        if !due {
            return Cycle::Idle;
        }
        let outcome = self.cycle().await;
        self.last_cycle_end = Some(Instant::now());
        self.next_gap = if outcome == Cycle::Failed {
            let retry = retry_after(self.failures).min(self.cycle_gap);
            self.failures = self.failures.saturating_add(1);
            tracing::warn!(next_retry_ms = retry.as_millis() as u64, failures = self.failures, "product state retry scheduled");
            retry
        } else {
            self.failures = 0;
            self.cycle_gap
        };
        outcome
    }

    /// Keep every published file young, so the age-based pruning of build
    /// leftovers never removes a snapshot a consumer may still read.
    fn touch_published(&self) {
        let dir = self.dir();
        // NAN-3791: each window's explorer state lives beside it unlisted.
        let explorers = self.manifest.windows.values().filter_map(|entry| entry.window.as_deref())
            .filter_map(|name| resolve(&dir, name)).map(|window| super::partials::explorer_path(&window));
        for path in self.manifest.files().into_iter().filter_map(|name| resolve(&dir, name)).chain(explorers) {
            let _ = std::fs::File::open(&path).and_then(|file| file.set_modified(SystemTime::now()));
        }
    }

    fn publish(&mut self, next: Manifest) -> anyhow::Result<()> {
        let mut next = next;
        next.version = self.manifest.version + 1;
        next.built_at_us = now_us();
        write_manifest(&self.dir(), &next)?;
        self.status.version.store(next.version, Ordering::Relaxed);
        self.status.progressed();
        self.manifest = next;
        Ok(())
    }

    /// Serve the consumer's pending demands (bounded per call).
    pub async fn serve_demands(&mut self) -> usize {
        let dir = self.dir();
        let pending = pending_demands(&dir);
        self.status.pending_demands.store(pending.len() as u64, Ordering::Relaxed);
        let mut served = 0;
        for (path, demand) in pending.into_iter().take(MAX_DEMANDS) {
            self.status.busy.store(true, Ordering::Relaxed);
            let started = Instant::now();
            let result = self.build_demand(&demand).await;
            self.status.busy.store(false, Ordering::Relaxed);
            // Served or failed, the demand is spent: the consumer re-files
            // it on its next miss, so a failure never wedges the inbox.
            let _ = std::fs::remove_file(&path);
            match result {
                Ok(()) => {
                    served += 1;
                    self.status.demands_built.fetch_add(1, Ordering::Relaxed);
                    tracing::info!(demand = ?demand, wall_ms = started.elapsed().as_millis() as u64, "product demand built");
                }
                Err(error) => tracing::warn!(demand = ?demand, error = %format!("{error:#}"), "product demand failed"),
            }
        }
        self.status.pending_demands.store(pending_demands(&dir).len() as u64, Ordering::Relaxed);
        served
    }

    async fn build_demand(&mut self, demand: &Demand) -> anyhow::Result<()> {
        let engine = self.engine.clone();
        let dir = self.dir();
        let mut next = self.manifest.clone();
        match demand {
            Demand::Window { from_us, to_us } => {
                build(&engine, super::partials::window_state(&engine, *from_us, *to_us)).await?;
                return Ok(());
            }
            Demand::Detail { request, from_us, to_us } => {
                let request: super::partials::PrevalenceDetailRequest = serde_json::from_str(request)?;
                let mut identity = serde_json::to_value(&request)?;
                if let Some(object) = identity.as_object_mut() {
                    object.remove("request_id");
                }
                let key = detail_key(&identity.to_string());
                // NAN-3766: a build that runs past its first-answer budget
                // hands over a partial answer (coverage.refining); publish it
                // at once so an expanded row shows facets while the walk
                // continues (NAN-3858: and again as it widens). The final
                // answer replaces it below.
                let (first_tx, mut first_rx) = tokio::sync::mpsc::unbounded_channel();
                let work = tokio::time::timeout(DETAIL_BUILD_WALL,
                    build(&engine, super::partials::detail_state_with(&engine, &request, *from_us, *to_us, Some(&first_tx))));
                tokio::pin!(work);
                let built = loop {
                    tokio::select! {
                        // A first answer handed over before the build ends is
                        // published before the final answer replaces it.
                        biased;
                        Some(partial) = first_rx.recv() => {
                            let Some(file) = relative(&dir, &partial) else { continue };
                            let head = engine.head().await.map(|(seq, _)| seq);
                            let mut early = self.manifest.clone();
                            early.insert_latest(key.clone(), LatestEntry { file, from_us: *from_us, to_us: *to_us, log_head: head, built_at_us: now_us() });
                            if let Err(error) = self.publish(early) {
                                tracing::warn!(error = %format!("{error:#}"), "partial prevalence detail not published");
                            }
                        }
                        built = &mut work => break built,
                    }
                };
                let (path, identity) = built.map_err(|_| anyhow::anyhow!("detail build exceeded its {}-second wall cap", DETAIL_BUILD_WALL.as_secs()))??;
                let file = relative(&dir, &path).ok_or_else(|| anyhow::anyhow!("detail state is outside the product dir"))?;
                let head = engine.head().await.map(|(seq, _)| seq);
                let mut next = self.manifest.clone();
                next.insert_latest(detail_key(&identity), LatestEntry { file, from_us: *from_us, to_us: *to_us, log_head: head, built_at_us: now_us() });
                return self.publish(next);
            }
            Demand::Risk { from_us, to_us } => {
                let (from_us, to_us) = (*from_us, *to_us);
                let (path, head) = build(&engine, async {
                    super::risk::ledger(&engine, &dir, from_us, to_us).await.map_err(|error| PartQueryError::Unavailable(format!("{error:#}")))
                }).await?;
                let file = relative(&dir, &path).ok_or_else(|| anyhow::anyhow!("risk ledger is outside the product dir"))?;
                next.insert_latest(risk_key(from_us, to_us), LatestEntry { file, from_us, to_us, log_head: head, built_at_us: now_us() });
            }
        }
        self.publish(next)
    }

    /// Drive `work` to completion, serving pending demands every
    /// [`DEMAND_POLL`] concurrently. The work never borrows the publisher, so
    /// a demand built and published mid-build only adds a `latest` entry;
    /// the window's own publish follows when `work` ends. Demand builds
    /// still take the idle admission slot, so they interleave between the
    /// build's statements and never run beside one; a build statement
    /// defers to a running demand for at most
    /// [`product_state::MAX_DEFERRAL`] (NAN-3858).
    async fn serving_demands<T>(&mut self, work: impl std::future::Future<Output = anyhow::Result<T>>) -> anyhow::Result<T> {
        tokio::pin!(work);
        let mut poll = tokio::time::interval(DEMAND_POLL);
        poll.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                biased;
                done = &mut work => return done,
                _ = poll.tick() => {}
            }
            if pending_demands(&self.dir()).is_empty() {
                continue;
            }
            // Polled together with `work` (never instead of it): a demand
            // waiting on the idle slot needs the build to keep running to
            // release it. NAN-3858: a demand started here runs to its end
            // even when `work` ends first; cutting it off would discard
            // minutes of a long detail walk and start it over.
            let mut finished = None;
            {
                let serve = self.serve_demands();
                tokio::pin!(serve);
                loop {
                    tokio::select! {
                        biased;
                        _ = &mut serve => break,
                        done = &mut work, if finished.is_none() => finished = Some(done),
                    }
                }
            }
            if let Some(done) = finished {
                return done;
            }
        }
    }

    /// One cycle: skip when the part log has not moved, else rebuild the
    /// seven-day risk ledger and every moving window in turn, publishing
    /// after each so the cheap windows never wait on the 30-day one.
    pub async fn cycle(&mut self) -> Cycle {
        let engine = self.engine.clone();
        if let Err(error) = engine.refresh().await {
            tracing::warn!(%error, "product cycle: part log catch-up failed");
            return Cycle::Failed;
        }
        let head = engine.head().await.map(|(seq, _)| seq);
        let mut plan = self.cadence.plan(&self.manifest, head, now_us());
        // Head unmoved and nothing due (every window at this head, or a
        // deferred one not yet due): nothing to do.
        if head.is_some() && head == self.manifest.log_head && plan.rebuild.is_empty() {
            self.status.cycles_skipped.fetch_add(1, Ordering::Relaxed);
            self.status.progressed();
            tracing::debug!(log_head = ?head, version = self.manifest.version, windows_deferred = %plan.deferred.join(","),
                "product cycle skipped: no new parts");
            return Cycle::Skipped;
        }
        let meter = product_state::BuildMeter::start();
        let threads = product_state::build_threads();
        self.status.busy.store(true, Ordering::Relaxed);
        let outcome = self.cycle_steps(head, &mut plan).await;
        self.status.busy.store(false, Ordering::Relaxed);
        match outcome {
            Ok(()) => {
                self.status.cycles_built.fetch_add(1, Ordering::Relaxed);
                tracing::info!(log_head = ?head, version = self.manifest.version, wall_ms = meter.wall_ms(),
                    cpu_ms = meter.cpu_ms(), cpu_scope = product_state::CPU_SCOPE, threads,
                    windows_rebuilt = %plan.rebuild.join(","), windows_skipped = %plan.deferred.join(","),
                    prevalence_raw_scans = engine.fetcher().prevalence_raw_scans(),
                    prevalence_state_merges = super::partials::prevalence_state_merges(),
                    "product state cycle published");
                Cycle::Built
            }
            Err(error) => {
                tracing::warn!(error = %format!("{error:#}"), wall_ms = meter.wall_ms(), cpu_ms = meter.cpu_ms(),
                    cpu_scope = product_state::CPU_SCOPE, threads,
                    "product state build failed; previous snapshots stay published");
                Cycle::Failed
            }
        }
    }

    async fn cycle_steps(&mut self, head: Option<u64>, plan: &mut Plan) -> anyhow::Result<()> {
        let engine = self.engine.clone();
        let dir = self.dir();
        // NAN-4154: nothing this cycle uses is removed for budget.
        let cycle_started = SystemTime::now();
        let anchor = now_us();
        let (from_us, to_us) = (anchor - 7 * DAY_US, anchor);
        let (path, risk_head) = build(&engine, async {
            super::risk::ledger(&engine, &dir, from_us, to_us).await.map_err(|error| PartQueryError::Unavailable(format!("{error:#}")))
        }).await?;
        let mut next = self.manifest.clone();
        let file = relative(&dir, &path).ok_or_else(|| anyhow::anyhow!("risk ledger is outside the product dir"))?;
        next.insert_latest(risk_key(from_us, to_us), LatestEntry { file, from_us, to_us, log_head: risk_head, built_at_us: now_us() });
        self.publish(next)?;
        for window in WINDOWS {
            let warming = first_artifact_due(&self.manifest, window, head);
            if !plan.rebuild.contains(&window) {
                if !warming { continue; }
                plan.rebuild.push(window);
                plan.deferred.retain(|deferred| *deferred != window);
            }
            // A consumer's demand never waits behind the whole cycle.
            self.serve_demands().await;
            let meter = product_state::BuildMeter::start();
            // NAN-4154: every state this build uses is touched after this instant.
            let window_started = SystemTime::now();
            let (from_us, to_us) = super::partials::moving_bounds(window)?;
            // NAN-3791: a 7d/30d window build runs for many minutes at the
            // product thread budget (tenant-a 7d: 1,245 s); serve demands while
            // it runs instead of only between windows.
            let work = build(&engine, super::partials::window_state(&engine, from_us, to_us));
            let (window_path, history_path) = self.serving_demands(work).await?;
            tracing::info!(window, wall_ms = meter.wall_ms(), cpu_ms = meter.cpu_ms(), cpu_scope = product_state::CPU_SCOPE,
                threads = product_state::build_threads(), "product state window rebuilt");
            let name = |path: Option<PathBuf>| -> anyhow::Result<Option<String>> {
                path.map(|path| relative(&dir, &path).ok_or_else(|| anyhow::anyhow!("window state is outside the product dir"))).transpose()
            };
            let rows = artifact_rows(window_path.as_deref())?;
            let warmup_complete = warming || rows > 0
                || self.manifest.windows.get(window).is_some_and(|entry| entry.warmup_complete);
            let entry = WindowEntry { from_us, to_us, window: name(window_path)?, history: name(history_path)?,
                log_head: head, built_at_us: now_us(), artifact_rows: Some(rows), warmup_complete };
            let mut next = self.manifest.clone();
            next.windows.insert(window.to_string(), entry);
            self.publish(next)?;
            self.rebuilt_at.insert(window, window_started);
        }
        let mut next = self.manifest.clone();
        next.log_head = head;
        self.publish(next)?;
        self.sweep_superseded_states();
        self.enforce_state_budget(cycle_started);
        Ok(())
    }

    /// NAN-4154: once this process has rebuilt every window, remove the
    /// maintained states and day histories none of their latest builds used
    /// (see [`sweep_cutoff`]). Runs in the publisher task between cycles, so
    /// no build is in flight.
    fn sweep_superseded_states(&self) {
        let Some(used_before) = sweep_cutoff(&self.rebuilt_at, self.state_grace) else { return };
        let swept = Instant::now();
        let (files, bytes) = super::partials::sweep_superseded_states(&self.dir(), used_before);
        if files > 0 {
            tracing::info!(files, bytes, grace_secs = self.state_grace.as_secs(), wall_ms = swept.elapsed().as_millis() as u64,
                "superseded prevalence states removed after every window was rebuilt");
        }
    }

    /// NAN-4154: hold the maintained states and day histories to
    /// 1/[`super::partials::STATE_BUDGET_DIVISOR`] of the product volume,
    /// least recently used first; nothing used this cycle or within
    /// [`super::partials::STATE_BUDGET_FLOOR`] goes. The superseded-state
    /// sweep needs every window rebuilt first; this bound holds from the
    /// first cycle after a restart and whatever a sweep misses.
    fn enforce_state_budget(&self, cycle_started: SystemTime) {
        let dir = self.dir();
        let budget = match self.state_budget {
            Some(budget) => budget,
            None => match crate::local_hot_window::filesystem_total(&dir) {
                Ok(total) => total / super::partials::STATE_BUDGET_DIVISOR,
                Err(error) => {
                    tracing::warn!(error = %format!("{error:#}"), "product state budget unknown; not enforced this cycle");
                    return;
                }
            },
        };
        let floor = SystemTime::now().checked_sub(super::partials::STATE_BUDGET_FLOOR).unwrap_or(SystemTime::UNIX_EPOCH);
        let keep_after = cycle_started.min(floor);
        let (files, bytes, left) = super::partials::enforce_state_budget(&dir, budget, keep_after);
        if files > 0 {
            tracing::info!(files, bytes, left_bytes = left, budget_bytes = budget,
                "least recently used prevalence states removed to stay within the product state budget");
        } else if left > budget {
            tracing::warn!(left_bytes = left, budget_bytes = budget,
                "product states over budget, all used within the floor; nothing removed");
        }
    }

    /// Replace the state budget (tests).
    pub fn set_state_budget(&mut self, budget_bytes: u64) {
        self.state_budget = Some(budget_bytes);
    }

    /// Replace the superseded-state grace (tests).
    pub fn set_state_grace(&mut self, grace: Duration) {
        self.state_grace = grace;
    }
}

/// NAN-4154: the last-use cutoff of the superseded-state sweep, from the
/// start of each window's latest build in this process. A build touches every
/// maintained state and day history it reads or writes, so a file untouched
/// since the OLDEST of those starts is used by no published window. Windows
/// rebuild in different cycles (7d/30d every 2 h, 1h/24h as the head moves),
/// so this waits for each window once, never for one cycle that rebuilds
/// all. `grace` more is kept (in-between hour and day blocks the next build
/// reuses). None until every window has been rebuilt.
pub fn sweep_cutoff(rebuilt_at: &std::collections::BTreeMap<&'static str, SystemTime>, grace: Duration) -> Option<SystemTime> {
    let oldest = WINDOWS.iter().map(|window| rebuilt_at.get(window).copied()).collect::<Option<Vec<_>>>()?
        .into_iter().min()?;
    oldest.checked_sub(grace)
}

/// NAN-3720: product[T]'s niceness. The role is background work by
/// definition: its own cgroup bounds it, and this keeps it last in line on
/// every core it shares with search (watchdog-only cells without a delegated
/// cgroup, or a process the supervisor has not placed yet).
pub const ROLE_NICE: libc::c_int = 19;

/// Lower every thread of this process to `nice` (NAN-3720). Linux niceness
/// is per thread: threads that exist now are changed here and threads they
/// create later (tokio blocking workers, chDB's pools started from a lane
/// thread) inherit it. Only ever lowers priority (no privilege needed).
/// Returns how many threads were changed.
pub fn lower_process_priority(nice: libc::c_int) -> std::io::Result<usize> {
    let mut changed = 0;
    for entry in std::fs::read_dir("/proc/self/task")? {
        let Some(tid) = entry?.file_name().to_str().and_then(|name| name.parse::<libc::id_t>().ok()) else { continue };
        changed += usize::from(lower_thread_priority(tid, nice).is_ok());
    }
    Ok(changed)
}

/// Raise `tid`'s niceness to at least `nice` (never lowers it).
fn lower_thread_priority(tid: libc::id_t, nice: libc::c_int) -> std::io::Result<()> {
    // SAFETY: plain getpriority/setpriority syscalls on one thread id.
    unsafe {
        *libc::__errno_location() = 0;
        let current = libc::getpriority(libc::PRIO_PROCESS, tid);
        if current == -1 && *libc::__errno_location() != 0 {
            return Err(std::io::Error::last_os_error());
        }
        if current >= nice {
            return Ok(());
        }
        if libc::setpriority(libc::PRIO_PROCESS, tid, nice) != 0 {
            return Err(std::io::Error::last_os_error());
        }
    }
    Ok(())
}

/// NAN-3148 (flag off): run `publisher` on its own nice-19 thread with a
/// single-threaded runtime, so its Rust-side work (fetch, proofs, decode)
/// never takes a query worker thread and loses every CPU contention to
/// search. Native statements still start only when every query slot is
/// idle ([`product_state::idle`]). The caller's tracing dispatcher follows.
pub fn spawn_low_priority(publisher: Publisher) -> std::io::Result<()> {
    let dispatch = tracing::dispatcher::get_default(|dispatch| dispatch.clone());
    std::thread::Builder::new()
        .name("product-state".into())
        .stack_size(IN_PROCESS_STACK_BYTES)
        .spawn(move || {
            // SAFETY: plain syscalls on this thread's own id. Threads it
            // starts (its blocking pool) inherit the niceness.
            unsafe {
                let tid = libc::syscall(libc::SYS_gettid) as libc::id_t;
                libc::setpriority(libc::PRIO_PROCESS, tid, IN_PROCESS_NICE);
            }
            let _ = nanosiem_lake_cell::crash_capture::register_thread();
            tracing::dispatcher::with_default(&dispatch, || {
                match tokio::runtime::Builder::new_current_thread().enable_all().build() {
                    Ok(runtime) => runtime.block_on(publisher.run()),
                    Err(error) => tracing::error!(%error, "product state runtime did not start"),
                }
            });
        })
        .map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manifest(version: u64) -> Manifest {
        let mut manifest = Manifest::new("t");
        manifest.version = version;
        manifest.built_at_us = now_us();
        manifest
    }

    /// NAN-3799: a resumed snapshot older than the span it covers is
    /// withdrawn; one still inside it keeps serving (marked stale).
    #[test]
    fn resumed_windows_older_than_their_span_expire() {
        const HOUR: i64 = 3_600_000_000;
        let now = now_us();
        let mut published = manifest(7);
        for (window, span, age) in [("1h", HOUR, 3 * HOUR), ("24h", 24 * HOUR, 3 * HOUR), ("7d", 168 * HOUR, 30 * HOUR)] {
            published.windows.insert(window.into(), WindowEntry { from_us: now - age - span, to_us: now - age,
                window: None, history: None, log_head: Some(1), built_at_us: now - age, artifact_rows: None, warmup_complete: false });
        }
        assert_eq!(expired_windows(&published, now), vec!["1h".to_string()]);
        assert!(expired_windows(&published, now + 30 * HOUR).contains(&"24h".to_string()));
        assert!(expired_windows(&Manifest::new("t"), now).is_empty());
    }

    /// NAN-3720: product[T] lowers its threads and never raises one back.
    #[test]
    fn product_threads_only_ever_lose_priority() {
        std::thread::spawn(|| {
            let tid = unsafe { libc::syscall(libc::SYS_gettid) } as libc::id_t;
            let nice = || unsafe { libc::getpriority(libc::PRIO_PROCESS, tid) };
            let before = nice();
            let target = (before + 5).min(ROLE_NICE);
            lower_thread_priority(tid, target).unwrap();
            assert_eq!(nice(), target);
            lower_thread_priority(tid, before).unwrap();
            assert_eq!(nice(), target, "never raised back");
            // A thread started now inherits the lowered niceness.
            let child = std::thread::spawn(|| unsafe {
                libc::getpriority(libc::PRIO_PROCESS, libc::syscall(libc::SYS_gettid) as libc::id_t)
            }).join().unwrap();
            assert_eq!(child, target);
        }).join().unwrap();
    }

    #[test]
    fn manifest_swaps_atomically_and_keeps_the_last_good_version() {
        let dir = tempfile::tempdir().unwrap();
        let reader = Published::consumer(dir.path().to_path_buf());
        assert!(reader.manifest().is_none(), "nothing published yet");
        write_manifest(dir.path(), &manifest(1)).unwrap();
        assert_eq!(reader.manifest().unwrap().version, 1);
        // Unchanged file: the cached Arc is served, not re-parsed.
        let first = reader.manifest().unwrap();
        assert!(Arc::ptr_eq(&first, &reader.manifest().unwrap()));
        write_manifest(dir.path(), &manifest(2)).unwrap();
        assert_eq!(reader.manifest().unwrap().version, 2, "a new version swaps in");
        // A torn/corrupt manifest never replaces the serving version.
        std::fs::write(dir.path().join(MANIFEST), b"{not json").unwrap();
        assert_eq!(reader.manifest().unwrap().version, 2);
        // No temporary is left behind by a publish.
        write_manifest(dir.path(), &manifest(3)).unwrap();
        let leftovers = std::fs::read_dir(dir.path()).unwrap().flatten()
            .filter(|entry| entry.file_name().to_string_lossy().ends_with(".tmp")).count();
        assert_eq!(leftovers, 0);
        assert_eq!(reader.manifest().unwrap().version, 3);
    }

    /// NAN-3271: a published 24h window serves while 7d/30d are still
    /// unpublished (their build kept hitting the chDB time cap); only the
    /// unpublished windows answer warming.
    #[test]
    fn a_published_window_serves_while_longer_windows_warm() {
        let dir = tempfile::tempdir().unwrap();
        let reader = Published::consumer(dir.path().to_path_buf());
        assert!(!reader.serves("24h"), "nothing published yet");
        let mut partial = manifest(1);
        for window in ["1h", "24h"] {
            partial.windows.insert(window.into(), WindowEntry { from_us: 0, to_us: 1, window: None, history: None,
                log_head: Some(1), built_at_us: now_us(), artifact_rows: None, warmup_complete: false });
        }
        write_manifest(dir.path(), &partial).unwrap();
        assert!(!partial.complete(), "7d/30d never published");
        assert!(reader.serves("1h"));
        assert!(reader.serves("24h"), "the 24h lookup must not wait on 7d/30d");
        assert!(!reader.serves("7d"));
        assert!(!reader.serves("30d"));
    }

    #[test]
    fn demands_are_deduplicated_bounded_and_parsed_back() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join(DEMAND_DIR)).unwrap();
        assert!(demand(dir.path(), &Work::Risk(0, 10)));
        assert!(demand(dir.path(), &Work::Risk(0, 10)), "already pending");
        assert!(demand(dir.path(), &Work::Window(1, 2)));
        assert!(!demand(dir.path(), &Work::History(Vec::new())));
        let pending = pending_demands(dir.path());
        assert_eq!(pending.len(), 2);
        assert!(pending.iter().any(|(_, d)| *d == Demand::Risk { from_us: 0, to_us: 10 }));
        for i in 0..200 {
            demand(dir.path(), &Work::Risk(i, i + 1_000));
        }
        assert_eq!(pending_demands(dir.path()).len(), MAX_DEMANDS);
        std::fs::write(dir.path().join(DEMAND_DIR).join("junk.json"), b"{}").unwrap();
        let _ = pending_demands(dir.path());
        assert!(!dir.path().join(DEMAND_DIR).join("junk.json").exists(), "malformed demands are dropped");
    }

    #[test]
    fn manifest_names_resolve_only_inside_the_product_dir() {
        let dir = Path::new("/p");
        assert_eq!(resolve(dir, "product-window-x.state"), Some(PathBuf::from("/p/product-window-x.state")));
        assert_eq!(resolve(dir, "../query/x"), None);
        assert_eq!(resolve(dir, ".."), None);
        assert_eq!(relative(dir, Path::new("/p/a.state")).as_deref(), Some("a.state"));
        assert_eq!(relative(dir, Path::new("/q/a.state")), None);
    }

    #[test]
    fn latest_entries_are_bounded_oldest_first() {
        let mut manifest = manifest(1);
        for i in 0..(MAX_LATEST as i64 + 10) {
            manifest.insert_latest(format!("risk:{i}"), LatestEntry { file: "f".into(), from_us: 0, to_us: i, log_head: None, built_at_us: i });
        }
        assert_eq!(manifest.latest.len(), MAX_LATEST);
        assert!(!manifest.latest.contains_key("risk:0"));
        assert!(manifest.latest.contains_key(&format!("risk:{}", MAX_LATEST as i64 + 9)));
    }

    #[test]
    fn retries_back_off_and_the_cadence_knob_has_a_floor() {
        assert_eq!(retry_after(0), Duration::from_secs(1));
        assert_eq!(retry_after(3), Duration::from_secs(8));
        assert_eq!(retry_after(30), CYCLE_RETRY);
        assert_eq!(cycle_gap(), CYCLE_GAP, "default: ten minutes");
    }

    #[tokio::test]
    async fn in_process_reads_like_a_consumer_and_builds_only_under_build_authority() {
        // The mode decides read vs write per call: outside BUILD the request
        // path is a reader; inside it the in-process publisher writes.
        assert!(reads_only(Mode::InProcess), "the request path never builds");
        assert!(product_state::BUILD.scope((), async { !reads_only(Mode::InProcess) }).await, "its publisher does");
        assert!(reads_only(Mode::Consumer));
        assert!(product_state::BUILD.scope((), async { reads_only(Mode::Consumer) }).await, "a consumer never builds");
        assert!(!reads_only(Mode::Publisher));
    }

    #[test]
    fn freshness_marks_old_snapshots_stale() {
        let manifest = manifest(4);
        let now = now_us();
        assert_eq!(freshness(&manifest, now, now, STALE_AFTER)["stale"], json!(false));
        let old = now - (STALE_AFTER.as_micros() as i64) - 1_000_000;
        let marked = freshness(&manifest, old, now, STALE_AFTER);
        assert_eq!(marked["stale"], json!(true));
        assert_eq!(marked["version"], json!(4));
        // NAN-3168: a deferred long window is not stale inside its interval.
        let cadence = Cadence::from_lookup(|_| None);
        assert_eq!(freshness(&manifest, old, now, cadence.stale_after("30d"))["stale"], json!(false));
        assert_eq!(freshness(&manifest, old, now, cadence.stale_after("1h"))["stale"], json!(true));
    }

    const MIN_US: i64 = 60_000_000;

    fn entry(log_head: u64, built_at_us: i64) -> WindowEntry {
        WindowEntry { from_us: 0, to_us: built_at_us, window: Some("w".into()), history: None, log_head: Some(log_head), built_at_us, artifact_rows: Some(1), warmup_complete: true }
    }

    #[test]
    fn empty_startup_warms_on_first_artifacts_once_and_survives_restart() {
        let now = 1_000 * MIN_US;
        let cadence = Cadence::from_lookup(|_| None);
        let mut manifest = Manifest::new("t");
        for window in WINDOWS {
            let mut empty = entry(1, now);
            empty.artifact_rows = Some(0);
            empty.warmup_complete = false;
            manifest.windows.insert(window.into(), empty);
        }
        // Audit-only moved heads must not bypass any long-window cadence.
        for window in ["24h", "7d", "30d"] {
            assert!(!first_artifact_due(&manifest, window, Some(2)));
        }
        // The regular 1h build discovers artifacts on the next tick.
        manifest.windows.insert("1h".into(), entry(2, now + 10 * MIN_US));
        let plan = cadence.plan(&manifest, Some(2), now + 10 * MIN_US);
        for window in ["24h", "7d", "30d"] {
            assert!(!plan.rebuild.contains(&window), "normal cadence still defers {window}");
            assert!(first_artifact_due(&manifest, window, Some(2)), "first artifacts bypass {window} cadence");
            assert!(!first_artifact_due(&manifest, window, None));
            assert!(!first_artifact_due(&manifest, window, Some(3)), "old 1h snapshot is not evidence");
            // Even if a concurrent expiry leaves this build empty, never bypass twice.
            let published = manifest.windows.get_mut(window).unwrap();
            published.warmup_complete = true;
            published.log_head = Some(2);
        }
        let restarted: Manifest = serde_json::from_slice(&serde_json::to_vec(&manifest).unwrap()).unwrap();
        manifest = restarted;
        manifest.windows.insert("1h".into(), entry(3, now + 20 * MIN_US));
        for window in ["24h", "7d", "30d"] {
            assert!(!first_artifact_due(&manifest, window, Some(3)), "persisted bound for {window}");
        }
    }

    #[test]
    fn populated_backlogs_never_gain_extra_long_window_builds() {
        let mut manifest = Manifest::new("t");
        for window in WINDOWS {
            manifest.windows.insert(window.into(), entry(1, 0));
        }
        for head in [2, 1_000, u64::MAX] {
            manifest.windows.insert("1h".into(), entry(head, 1));
            for window in ["24h", "7d", "30d"] {
                assert!(!first_artifact_due(&manifest, window, Some(head)));
            }
        }
        // Old manifests deserialize safely and don't invent empty-state evidence.
        let old = json!({"from_us": 0, "to_us": 1, "window": "w", "history": null,
            "log_head": 1, "built_at_us": 1});
        let old: WindowEntry = serde_json::from_value(old).unwrap();
        assert_eq!(old.artifact_rows, None);
        assert!(!old.warmup_complete);
    }

    #[test]
    fn cadence_defaults_and_env_knobs() {
        let defaults = Cadence::from_lookup(|_| None);
        assert_eq!(defaults.interval("1h"), Duration::ZERO);
        assert_eq!(defaults.interval("24h"), Duration::from_secs(1_800));
        assert_eq!(defaults.interval("7d"), Duration::from_secs(7_200));
        assert_eq!(defaults.interval("30d"), Duration::from_secs(7_200));
        let custom = Cadence::from_lookup(|name| match name {
            "NANO_LAKE_PRODUCT_STATE_REBUILD_24H_SECS" => Some(" 600 ".into()),
            "NANO_LAKE_PRODUCT_STATE_REBUILD_7D_SECS" => Some("junk".into()),
            "NANO_LAKE_PRODUCT_STATE_REBUILD_30D_SECS" => Some("99999999".into()),
            _ => None,
        });
        assert_eq!(custom.interval("24h"), Duration::from_secs(600));
        assert_eq!(custom.interval("7d"), Duration::from_secs(7_200), "unparsable: default");
        assert_eq!(custom.interval("30d"), Duration::from_secs(MAX_REBUILD_SECS), "capped at a day");
        assert!(WINDOWS.iter().all(|window| Cadence::every_cycle().interval(window) == Duration::ZERO));
        assert_eq!(WINDOW_REBUILD.map(|(window, _, _)| window), WINDOWS, "one knob per published window");
    }

    #[test]
    fn a_window_is_due_only_when_behind_the_head_and_past_its_interval() {
        let now = 1_000 * MIN_US;
        let interval = Duration::from_secs(1_800);
        assert!(window_due(None, Some(5), interval, now), "never published");
        assert!(!window_due(Some(&entry(5, now - 60 * MIN_US)), Some(5), interval, now), "already at this head");
        assert!(!window_due(Some(&entry(4, now - 29 * MIN_US)), Some(5), interval, now), "behind, inside its interval");
        assert!(window_due(Some(&entry(4, now - 30 * MIN_US)), Some(5), interval, now), "behind, interval elapsed");
        assert!(window_due(Some(&entry(4, now)), Some(5), Duration::ZERO, now), "zero interval: every moved head");
        assert!(window_due(Some(&entry(4, now - 30 * MIN_US)), None, interval, now), "unknown head: rebuild when due");
    }

    /// Ten-minute cycles with a new part before each: 1h every cycle, 24h
    /// every third, 7d/30d once per 2 h (12 cycles) after the first build.
    #[test]
    fn long_windows_are_not_rebuilt_every_cycle() {
        let cadence = Cadence::from_lookup(|_| None);
        let mut manifest = Manifest::new("t");
        let mut rebuilt = BTreeMap::<&str, usize>::new();
        let start = 10_000 * MIN_US;
        for cycle in 0..24_i64 {
            let (now, head) = (start + cycle * 10 * MIN_US, Some(cycle as u64 + 1));
            let plan = cadence.plan(&manifest, head, now);
            assert_eq!(plan.rebuild.len() + plan.deferred.len(), WINDOWS.len());
            if cycle == 0 {
                assert_eq!(plan.rebuild, WINDOWS.to_vec(), "the first cycle publishes every window");
            }
            assert!(plan.rebuild.contains(&"1h"), "1h follows every moved head (cycle {cycle})");
            for window in &plan.rebuild {
                *rebuilt.entry(window).or_default() += 1;
                manifest.windows.insert(window.to_string(), entry(head.unwrap(), now));
            }
            manifest.log_head = head;
        }
        assert_eq!(rebuilt["1h"], 24);
        assert_eq!(rebuilt["24h"], 8, "every 30 minutes");
        assert_eq!(rebuilt["7d"], 2, "every 2 hours");
        assert_eq!(rebuilt["30d"], 2, "every 2 hours");
        // The pre-NAN-3168 rule rebuilds every window on every moved head.
        let every = Cadence::every_cycle().plan(&manifest, Some(99), start + 1_000 * MIN_US);
        assert_eq!(every.rebuild, WINDOWS.to_vec());
    }

    #[test]
    fn a_deferred_window_catches_up_without_new_parts() {
        let cadence = Cadence::from_lookup(|_| None);
        let now = 10_000 * MIN_US;
        let mut manifest = Manifest::new("t");
        for window in WINDOWS {
            manifest.windows.insert(window.into(), entry(7, now - 5 * MIN_US));
        }
        manifest.windows.insert("30d".into(), entry(6, now - 90 * MIN_US));
        manifest.log_head = Some(7);
        let plan = cadence.plan(&manifest, Some(7), now);
        assert!(plan.rebuild.is_empty(), "30d is behind but inside its interval: {plan:?}");
        let later = cadence.plan(&manifest, Some(7), now + 30 * MIN_US);
        assert_eq!(later.rebuild, vec!["30d"], "due once its interval elapses, head unmoved");
    }

    /// NAN-4154: superseded states are swept only once every window has
    /// been rebuilt (in any cycles), up to the oldest latest build minus the
    /// grace. On a large tenant 1h/24h, 7d and 30d were never rebuilt in one cycle.
    #[test]
    fn the_sweep_waits_for_every_window_and_keeps_the_oldest_builds_inputs() {
        let grace = Duration::from_secs(6 * 3600);
        let t0 = SystemTime::UNIX_EPOCH + Duration::from_secs(10 * 86_400);
        let at = |secs: u64| t0 + Duration::from_secs(secs);
        let mut rebuilt = std::collections::BTreeMap::new();
        assert_eq!(sweep_cutoff(&rebuilt, grace), None, "nothing rebuilt yet");
        // Staggered cycles, as seen live: 7d, then 1h + 30d, then 1h + 24h.
        rebuilt.insert("7d", at(0));
        rebuilt.insert("1h", at(600));
        rebuilt.insert("30d", at(600));
        assert_eq!(sweep_cutoff(&rebuilt, grace), None, "24h never rebuilt in this process");
        rebuilt.insert("1h", at(2400));
        rebuilt.insert("24h", at(2400));
        assert_eq!(sweep_cutoff(&rebuilt, grace), Some(at(0) - grace), "the oldest latest build (7d) bounds it");
        rebuilt.insert("7d", at(7200));
        assert_eq!(sweep_cutoff(&rebuilt, grace), Some(at(600) - grace));
    }
}
