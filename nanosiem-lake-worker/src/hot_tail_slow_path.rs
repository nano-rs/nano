// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-2694: complete query coverage for hot-tail objects beyond the RAM tier.
//!
//! NAN-2651 made an over-bound tail serve only its newest objects and
//! reported the rest as `HOT_TAIL_PARTIAL`. Here the objects that do not fit
//! in the RAM (tmpfs) tier become the tail's **overflow**. They stay fully
//! searchable:
//!
//! 1. **Disk tier.** A background fill seals the newest overflow objects
//!    into the encrypted, persistent [`DiskTier`] (RAM-tier copies are sealed
//!    locally; others are streamed from R2 and verified while sealing).
//! 2. **Query-time staging.** For each interactive query, the overflow
//!    objects that overlap its time window are decrypted from the disk tier,
//!    or fetched from R2 when the disk tier does not have them, into a
//!    per-query directory on **tmpfs**. Every object is verified against the
//!    signed manifest's byte length and SHA-256 before its path is handed to
//!    chDB. The response carries `hot_tail_slow_path` (the HOT_TAIL_SLOW_PATH
//!    warning) with the ranges served from disk and from R2.
//! 3. **Last resort.** Only when R2 is unreachable, the per-query budget or
//!    deadline is exhausted, or the staging area is saturated does the query
//!    fall back to `hot_tail_partial`, with the uncovered range. Watermark
//!    consumers refuse a partial read exactly as before.
//!
//! Memory: chDB counts mmapped Parquet pages toward its cap (NAN-2655), and
//! plaintext may only live in RAM. Staged bytes therefore sit on tmpfs and are
//! bounded twice: per query (`NANO_LAKE_HOT_TAIL_QUERY_SLOW_PATH_BYTES`) and
//! across concurrent queries (`NANO_LAKE_HOT_TAIL_STAGING_BYTES`, with at
//! most `NANO_LAKE_HOT_TAIL_SLOW_PATH_CONCURRENCY` queries staging at once).
//! A query never opens more tail than RAM tier + its staging budget.

use crate::generation::{HotTailManifest, HotTailObject};
use crate::hot_tail_cache::HotTailPartialCoverage;
use crate::hot_tail_disk_tier::{sealed_len, DiskObjectIdentity, DiskTier, DiskTierFull};
use anyhow::{bail, Context, Result};
use futures::StreamExt;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

const STAGE_PARALLELISM: usize = 4;
const DEFAULT_CONCURRENCY: usize = 2;
const DEFAULT_DEADLINE: Duration = Duration::from_secs(30);

pub const SLOW_PATH_REASON: &str = "hot_tail_slow_path";
pub const PARTIAL_REASON_OVER_BUDGET: &str = "slow_path_over_budget";
pub const PARTIAL_REASON_UNAVAILABLE: &str = "slow_path_r2_unavailable";
pub const PARTIAL_REASON_BUSY: &str = "slow_path_busy";

/// Deployment contract for query-time staging.
#[derive(Clone, Debug)]
pub struct SlowPathSettings {
    /// tmpfs directory for verified plaintext handed to chDB.
    pub staging_dir: PathBuf,
    /// Bound across every concurrent query.
    pub staging_max_bytes: u64,
    /// Bound for one query.
    pub query_max_bytes: u64,
    pub concurrency: usize,
    /// Per-query wall-clock budget for staging.
    pub deadline: Duration,
}

impl SlowPathSettings {
    pub fn from_env() -> Result<Option<Self>> {
        let get = |name: &str| {
            std::env::var(name)
                .ok()
                .map(|value| value.trim().to_string())
                .filter(|value| !value.is_empty())
        };
        Self::parse(
            get("NANO_LAKE_HOT_TAIL_STAGING_DIR"),
            get("NANO_LAKE_HOT_TAIL_STAGING_BYTES"),
            get("NANO_LAKE_HOT_TAIL_QUERY_SLOW_PATH_BYTES"),
            get("NANO_LAKE_HOT_TAIL_SLOW_PATH_CONCURRENCY"),
            get("NANO_LAKE_HOT_TAIL_SLOW_PATH_TIMEOUT_SECONDS"),
        )
    }

    fn parse(
        staging_dir: Option<String>,
        staging_max_bytes: Option<String>,
        query_max_bytes: Option<String>,
        concurrency: Option<String>,
        timeout_seconds: Option<String>,
    ) -> Result<Option<Self>> {
        let positive = |name: &str, value: &str| {
            value
                .parse::<u64>()
                .ok()
                .filter(|value| *value > 0)
                .with_context(|| format!("{name} must be a positive integer"))
        };
        let (staging_dir, staging_max_bytes) = match (staging_dir, staging_max_bytes) {
            (None, None) => {
                if query_max_bytes.is_some() || concurrency.is_some() || timeout_seconds.is_some() {
                    bail!("hot-tail slow-path knobs require NANO_LAKE_HOT_TAIL_STAGING_DIR and NANO_LAKE_HOT_TAIL_STAGING_BYTES");
                }
                return Ok(None);
            }
            (Some(directory), Some(bytes)) => (
                PathBuf::from(directory),
                positive("NANO_LAKE_HOT_TAIL_STAGING_BYTES", &bytes)?,
            ),
            _ => bail!(
                "NANO_LAKE_HOT_TAIL_STAGING_DIR and NANO_LAKE_HOT_TAIL_STAGING_BYTES must be set together"
            ),
        };
        if !staging_dir.is_absolute() {
            bail!("NANO_LAKE_HOT_TAIL_STAGING_DIR must be absolute");
        }
        let concurrency = concurrency
            .map(|value| positive("NANO_LAKE_HOT_TAIL_SLOW_PATH_CONCURRENCY", &value))
            .transpose()?
            .map_or(DEFAULT_CONCURRENCY, |value| value as usize);
        let query_max_bytes = query_max_bytes
            .map(|value| positive("NANO_LAKE_HOT_TAIL_QUERY_SLOW_PATH_BYTES", &value))
            .transpose()?
            .unwrap_or(staging_max_bytes / concurrency as u64);
        if query_max_bytes == 0 || query_max_bytes > staging_max_bytes {
            bail!("NANO_LAKE_HOT_TAIL_QUERY_SLOW_PATH_BYTES must be positive and at most NANO_LAKE_HOT_TAIL_STAGING_BYTES");
        }
        let deadline = timeout_seconds
            .map(|value| positive("NANO_LAKE_HOT_TAIL_SLOW_PATH_TIMEOUT_SECONDS", &value))
            .transpose()?
            .map_or(DEFAULT_DEADLINE, Duration::from_secs);
        Ok(Some(Self {
            staging_dir,
            staging_max_bytes,
            query_max_bytes,
            concurrency,
            deadline,
        }))
    }
}

/// Where a signed tail object's bytes come from on the slow path. The
/// production source is the RAM cache's authority (exact R2 key, ETag-bound
/// conditional GET, the tenant's read-only credential); tests substitute an
/// in-memory store. Implementations stream raw bytes; [`fetch_verified`]
/// performs the length and SHA-256 fence.
#[async_trait::async_trait]
pub trait HotTailObjectSource: Send + Sync {
    async fn stream_object(
        &self,
        object: &HotTailObject,
        sink: &mut (dyn for<'b> FnMut(&'b [u8]) -> Result<()> + Send),
    ) -> Result<()>;

    /// A verified plaintext copy already on tmpfs (the RAM tier), which the
    /// disk fill seals instead of downloading. Its bytes are re-hashed.
    fn local_copy(&self, _object: &HotTailObject) -> Option<PathBuf> {
        None
    }
}

/// Stream one object through `sink` and refuse it unless its length and
/// SHA-256 equal the signed manifest's. Callers must discard whatever the
/// sink produced when this returns an error.
pub async fn fetch_verified(
    source: &dyn HotTailObjectSource,
    object: &HotTailObject,
    sink: &mut (dyn for<'b> FnMut(&'b [u8]) -> Result<()> + Send),
) -> Result<()> {
    let digest = object
        .sha256
        .as_deref()
        .context("hot-tail object omitted its signed SHA-256")?;
    let mut hasher = Sha256::new();
    let mut bytes = 0_u64;
    let expected = object.size_bytes;
    source
        .stream_object(object, &mut |chunk: &[u8]| {
            bytes = bytes
                .checked_add(chunk.len() as u64)
                .context("hot-tail read-through byte count overflow")?;
            if bytes > expected {
                bail!("hot-tail read-through exceeded the signed byte length");
            }
            hasher.update(chunk);
            sink(chunk)
        })
        .await?;
    if bytes != expected || hex::encode(hasher.finalize()) != digest {
        bail!("hot-tail read-through object failed its signed length or SHA-256 fence");
    }
    Ok(())
}

/// Signed tail objects beyond the RAM tier, newest first.
#[derive(Clone)]
pub struct HotTailOverflow {
    pub objects: Vec<HotTailObject>,
    /// The complete signed tail.
    pub total_objects: usize,
    pub total_bytes: u64,
    pub ram_max_bytes: u64,
    pub source: Arc<dyn HotTailObjectSource>,
}

impl std::fmt::Debug for HotTailOverflow {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("HotTailOverflow")
            .field("objects", &self.objects.len())
            .field("bytes", &self.bytes())
            .field("total_objects", &self.total_objects)
            .field("total_bytes", &self.total_bytes)
            .finish_non_exhaustive()
    }
}

impl HotTailOverflow {
    /// The objects of `complete` absent from the RAM-tier subset `served`.
    /// `None` when nothing overflows.
    pub fn between(
        complete: &HotTailManifest,
        served: &HotTailManifest,
        ram_max_bytes: u64,
        source: Arc<dyn HotTailObjectSource>,
    ) -> Option<Self> {
        let kept: BTreeSet<&str> = served
            .objects
            .iter()
            .map(|object| object.source_uri.as_str())
            .collect();
        let mut omitted: Vec<(usize, &HotTailObject)> = complete
            .objects
            .iter()
            .enumerate()
            .filter(|(_, object)| !kept.contains(object.source_uri.as_str()))
            .collect();
        if omitted.is_empty() {
            return None;
        }
        omitted.sort_by_key(|(index, object)| {
            std::cmp::Reverse((
                object.max_time_ms.unwrap_or(i64::MIN),
                object.min_time_ms.unwrap_or(i64::MIN),
                *index,
            ))
        });
        Some(Self {
            objects: omitted.into_iter().map(|(_, object)| object.clone()).collect(),
            total_objects: complete.objects.len(),
            total_bytes: complete
                .objects
                .iter()
                .map(|object| object.size_bytes)
                .fold(0_u64, u64::saturating_add),
            ram_max_bytes,
            source,
        })
    }

    pub fn bytes(&self) -> u64 {
        self.objects
            .iter()
            .map(|object| object.size_bytes)
            .fold(0_u64, u64::saturating_add)
    }

    pub fn from_ms(&self) -> Option<i64> {
        self.objects.iter().filter_map(|object| object.min_time_ms).min()
    }

    pub fn through_ms(&self) -> Option<i64> {
        self.objects.iter().filter_map(|object| object.max_time_ms).max()
    }

    /// Coverage when none of the overflow can be served (fail-closed path).
    pub fn uncovered(&self, reason: &str) -> HotTailPartialCoverage {
        let all: Vec<&HotTailObject> = self.objects.iter().collect();
        partial_for(self, &all, 0, reason)
    }

    /// Fold a newer overflow computed against a shrunk served tail into this
    /// one (the served tail's own omitted objects are older still).
    pub fn extended_with(&self, older: &[HotTailObject]) -> Self {
        let mut merged = self.clone();
        let present: BTreeSet<String> = merged
            .objects
            .iter()
            .map(|object| object.source_uri.clone())
            .collect();
        merged.objects.extend(
            older
                .iter()
                .filter(|object| !present.contains(&object.source_uri))
                .cloned(),
        );
        merged
    }
}

/// What the slow path served for one query (the HOT_TAIL_SLOW_PATH block).
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize)]
pub struct HotTailSlowPathCoverage {
    pub objects: usize,
    pub bytes: u64,
    pub disk_objects: usize,
    pub disk_bytes: u64,
    pub r2_objects: usize,
    pub r2_bytes: u64,
    /// Event-time range of everything served beyond the RAM tier.
    pub from_ms: Option<i64>,
    pub through_ms: Option<i64>,
    /// Event-time range of the objects read through from R2.
    pub r2_from_ms: Option<i64>,
    pub r2_through_ms: Option<i64>,
    pub query_budget_bytes: u64,
    pub staging_ms: u64,
}

/// Verified overflow objects staged on tmpfs for exactly one query. Dropping
/// it removes the files and releases the staging budget.
#[derive(Default)]
pub struct StagedOverflow {
    pub objects: Vec<HotTailObject>,
    pub paths: Vec<PathBuf>,
    pub slow_path: Option<HotTailSlowPathCoverage>,
    pub partial: Option<HotTailPartialCoverage>,
    directory: Option<tempfile::TempDir>,
    _permit: Option<OwnedSemaphorePermit>,
    _reservation: Option<StagingReservation>,
}

impl std::fmt::Debug for StagedOverflow {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("StagedOverflow")
            .field("objects", &self.objects.len())
            .field("slow_path", &self.slow_path)
            .field("partial", &self.partial)
            .finish_non_exhaustive()
    }
}

impl StagedOverflow {
    /// Nothing staged; every needed object is `partial` (fail-closed).
    pub fn uncovered(partial: HotTailPartialCoverage) -> Self {
        Self {
            partial: Some(partial),
            ..Self::default()
        }
    }

    pub fn directory(&self) -> Option<&Path> {
        self.directory.as_ref().map(|directory| directory.path())
    }
}

struct StagingReservation {
    counter: Arc<Mutex<u64>>,
    bytes: u64,
}

impl Drop for StagingReservation {
    fn drop(&mut self) {
        let mut staged = self.counter.lock().expect("staging counter");
        *staged = staged.saturating_sub(self.bytes);
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum StagedFrom {
    Disk,
    R2,
}

/// Outcome of one disk fill.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DiskFillReport {
    pub admitted: usize,
    pub admitted_bytes: u64,
    pub already_present: usize,
    pub removed: usize,
    pub failed: usize,
    pub superseded: bool,
    /// Overflow objects that do not fit the disk tier (served from R2).
    pub beyond_disk: usize,
}

pub struct HotTailSlowPath {
    settings: SlowPathSettings,
    disk: Option<Arc<DiskTier>>,
    permits: Arc<Semaphore>,
    staged: Arc<Mutex<u64>>,
    fill_epoch: AtomicU64,
    fill_lock: tokio::sync::Mutex<()>,
}

impl std::fmt::Debug for HotTailSlowPath {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("HotTailSlowPath")
            .field("settings", &self.settings)
            .field("disk", &self.disk)
            .finish_non_exhaustive()
    }
}

impl HotTailSlowPath {
    /// Refuses a staging directory that is not tmpfs/ramfs: staged objects
    /// are plaintext and must never reach node disk.
    pub fn new(settings: SlowPathSettings, disk: Option<Arc<DiskTier>>) -> Result<Arc<Self>> {
        std::fs::create_dir_all(&settings.staging_dir)
            .with_context(|| format!("create {}", settings.staging_dir.display()))?;
        if !is_memory_backed(&settings.staging_dir)? {
            bail!(
                "NANO_LAKE_HOT_TAIL_STAGING_DIR {} is not tmpfs; staged hot-tail plaintext must stay in memory",
                settings.staging_dir.display()
            );
        }
        Ok(Self::new_unchecked(settings, disk))
    }

    /// Test constructor that skips the tmpfs assertion.
    #[doc(hidden)]
    pub fn new_unchecked(settings: SlowPathSettings, disk: Option<Arc<DiskTier>>) -> Arc<Self> {
        let _ = std::fs::create_dir_all(&settings.staging_dir);
        // Per-query directories of a crashed process are plaintext; remove them.
        // Only our own `query-*` directories: a misconfigured staging path
        // must never turn this sweep into deleting someone else's data.
        if let Ok(entries) = std::fs::read_dir(&settings.staging_dir) {
            for entry in entries.flatten() {
                let ours = entry.file_name().to_str().is_some_and(|name| name.starts_with("query-"))
                    && entry.file_type().is_ok_and(|kind| kind.is_dir());
                if ours {
                    let _ = std::fs::remove_dir_all(entry.path());
                }
            }
        }
        Arc::new(Self {
            permits: Arc::new(Semaphore::new(settings.concurrency)),
            settings,
            disk,
            staged: Arc::new(Mutex::new(0)),
            fill_epoch: AtomicU64::new(0),
            fill_lock: tokio::sync::Mutex::new(()),
        })
    }

    pub fn settings(&self) -> &SlowPathSettings {
        &self.settings
    }

    pub fn disk(&self) -> Option<&Arc<DiskTier>> {
        self.disk.as_ref()
    }

    pub fn staged_bytes(&self) -> u64 {
        *self.staged.lock().expect("staging counter")
    }

    /// Stage the overflow objects overlapping `window` (inclusive unix-ms
    /// bounds; `None` = every object) for one query.
    pub async fn stage(
        &self,
        overflow: &HotTailOverflow,
        window: Option<(i64, i64)>,
    ) -> StagedOverflow {
        let started = Instant::now();
        let deadline = tokio::time::Instant::now() + self.settings.deadline;
        let needed: Vec<&HotTailObject> = overflow
            .objects
            .iter()
            .filter(|object| overlaps(object, window))
            .collect();
        if needed.is_empty() {
            return StagedOverflow::default();
        }
        let permit = match tokio::time::timeout_at(deadline, self.permits.clone().acquire_owned()).await {
            Ok(Ok(permit)) => permit,
            _ => {
                return StagedOverflow {
                    partial: Some(partial_for(overflow, &needed, self.settings.query_max_bytes, PARTIAL_REASON_BUSY)),
                    ..StagedOverflow::default()
                }
            }
        };
        // Newest-first prefix that fits both the per-query and the global
        // staging bound. Stop at the first object that does not fit so that
        // any uncovered range is strictly older than everything served.
        let (prefix_len, reservation) = {
            let mut staged = self.staged.lock().expect("staging counter");
            let global_room = self.settings.staging_max_bytes.saturating_sub(*staged);
            let limit = self.settings.query_max_bytes.min(global_room);
            let mut bytes = 0_u64;
            let mut count = 0;
            for object in &needed {
                match bytes.checked_add(object.size_bytes) {
                    Some(next) if next <= limit => {
                        bytes = next;
                        count += 1;
                    }
                    _ => break,
                }
            }
            *staged += bytes;
            (
                count,
                StagingReservation {
                    counter: self.staged.clone(),
                    bytes,
                },
            )
        };
        let directory = match tempfile::Builder::new()
            .prefix("query-")
            .tempdir_in(&self.settings.staging_dir)
        {
            Ok(directory) => directory,
            Err(error) => {
                tracing::error!(error = %error, "hot-tail staging directory unavailable");
                return StagedOverflow {
                    partial: Some(partial_for(overflow, &needed, self.settings.query_max_bytes, PARTIAL_REASON_UNAVAILABLE)),
                    ..StagedOverflow::default()
                };
            }
        };
        // Futures from a named async fn (not closure-built async blocks) keep
        // the stage future `Send` for every caller lifetime.
        let fetches: Vec<_> = needed[..prefix_len]
            .iter()
            .enumerate()
            .map(|(index, object)| {
                self.stage_with_deadline(
                    overflow,
                    (*object).clone(),
                    directory.path().join(format!("{index:04}.parquet")),
                    deadline,
                )
            })
            .collect();
        let results: Vec<Result<(HotTailObject, PathBuf, StagedFrom)>> = futures::stream::iter(fetches)
            .buffered(STAGE_PARALLELISM)
            .collect()
            .await;
        let mut staged = StagedOverflow {
            directory: Some(directory),
            _permit: Some(permit),
            _reservation: Some(reservation),
            ..StagedOverflow::default()
        };
        let mut coverage = HotTailSlowPathCoverage {
            query_budget_bytes: self.settings.query_max_bytes,
            ..HotTailSlowPathCoverage::default()
        };
        let mut failure = None;
        for result in results {
            match (failure.is_none(), result) {
                (true, Ok((object, path, from))) => {
                    coverage.objects += 1;
                    coverage.bytes += object.size_bytes;
                    widen(&mut coverage.from_ms, object.min_time_ms, i64::min);
                    widen(&mut coverage.through_ms, object.max_time_ms, i64::max);
                    match from {
                        StagedFrom::Disk => {
                            coverage.disk_objects += 1;
                            coverage.disk_bytes += object.size_bytes;
                        }
                        StagedFrom::R2 => {
                            coverage.r2_objects += 1;
                            coverage.r2_bytes += object.size_bytes;
                            widen(&mut coverage.r2_from_ms, object.min_time_ms, i64::min);
                            widen(&mut coverage.r2_through_ms, object.max_time_ms, i64::max);
                        }
                    }
                    staged.objects.push(object);
                    staged.paths.push(path);
                }
                // Keep a strict newest-first prefix: once one object fails,
                // later (older) successes are discarded.
                (true, Err(error)) => failure = Some(error),
                (false, Ok((_, path, _))) => {
                    let _ = std::fs::remove_file(path);
                }
                (false, Err(_)) => {}
            }
        }
        coverage.staging_ms = started.elapsed().as_millis() as u64;
        let uncovered = &needed[staged.objects.len()..];
        if !uncovered.is_empty() {
            let reason = if let Some(error) = &failure {
                tracing::error!(
                    error = %error,
                    uncovered_objects = uncovered.len(),
                    "hot-tail slow path could not stage every overflow object; serving partial"
                );
                PARTIAL_REASON_UNAVAILABLE
            } else {
                tracing::warn!(
                    uncovered_objects = uncovered.len(),
                    query_budget_bytes = self.settings.query_max_bytes,
                    "hot-tail slow path is over its per-query budget; serving partial"
                );
                PARTIAL_REASON_OVER_BUDGET
            };
            staged.partial = Some(partial_for(overflow, uncovered, self.settings.query_max_bytes, reason));
        }
        if coverage.objects > 0 {
            tracing::info!(
                event = "hot_tail_slow_path",
                objects = coverage.objects,
                bytes = coverage.bytes,
                disk_objects = coverage.disk_objects,
                r2_objects = coverage.r2_objects,
                staging_ms = coverage.staging_ms,
                "served hot-tail overflow objects beyond the RAM tier"
            );
            staged.slow_path = Some(coverage);
        }
        staged
    }

    async fn stage_with_deadline(
        &self,
        overflow: &HotTailOverflow,
        object: HotTailObject,
        path: PathBuf,
        deadline: tokio::time::Instant,
    ) -> Result<(HotTailObject, PathBuf, StagedFrom)> {
        match tokio::time::timeout_at(deadline, self.stage_one(overflow, &object, &path)).await {
            Ok(Ok(from)) => Ok((object, path, from)),
            Ok(Err(error)) => Err(error),
            Err(_) => Err(anyhow::anyhow!("hot-tail slow-path deadline exceeded")),
        }
    }

    async fn stage_one(
        &self,
        overflow: &HotTailOverflow,
        object: &HotTailObject,
        path: &Path,
    ) -> Result<StagedFrom> {
        if let Some(disk) = self.disk.clone() {
            let identity_object = object.clone();
            let destination = path.to_path_buf();
            let decrypted = tokio::task::spawn_blocking(move || -> Result<bool> {
                let identity = DiskObjectIdentity::of(&identity_object)?;
                if !disk.contains(identity) {
                    return Ok(false);
                }
                let mut file = std::fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(&destination)?;
                match disk.decrypt_into(identity, &mut file) {
                    Ok(()) => Ok(true),
                    Err(error) => {
                        drop(file);
                        let _ = std::fs::remove_file(&destination);
                        tracing::warn!(error = %error, "disk-tier stage failed; reading through from R2");
                        Ok(false)
                    }
                }
            })
            .await
            .context("join disk-tier stage")??;
            if decrypted {
                return Ok(StagedFrom::Disk);
            }
        }
        let parent = path.parent().context("staging path has no parent")?;
        let mut temporary = tempfile::NamedTempFile::new_in(parent)?;
        {
            let file = temporary.as_file_mut();
            fetch_verified(overflow.source.as_ref(), object, &mut |chunk: &[u8]| {
                file.write_all(chunk).context("write staged hot-tail object")
            })
            .await?;
        }
        temporary
            .persist_noclobber(path)
            .map_err(|error| error.error)
            .context("persist staged hot-tail object")?;
        Ok(StagedFrom::R2)
    }

    /// Replace any running fill with one for `overflow` (the latest tail
    /// wins) and run it in the background.
    pub fn schedule_fill(self: &Arc<Self>, overflow: Arc<HotTailOverflow>) {
        if self.disk.is_none() {
            return;
        }
        let epoch = self.fill_epoch.fetch_add(1, Ordering::SeqCst) + 1;
        let slow_path = self.clone();
        tokio::spawn(async move {
            match slow_path.fill_disk(&overflow, epoch).await {
                Ok(report) => tracing::info!(
                    event = "hot_tail_disk_fill",
                    admitted = report.admitted,
                    admitted_bytes = report.admitted_bytes,
                    already_present = report.already_present,
                    removed = report.removed,
                    failed = report.failed,
                    beyond_disk = report.beyond_disk,
                    superseded = report.superseded,
                    "hot-tail disk tier fill finished"
                ),
                Err(error) => tracing::error!(error = %error, "hot-tail disk tier fill failed"),
            }
        });
    }

    /// Make the disk tier hold exactly the newest overflow prefix that fits.
    /// Objects the current signed tail no longer names are deleted first; an
    /// existing object is kept (it is re-verified on every decrypt).
    pub async fn fill_disk(&self, overflow: &HotTailOverflow, epoch: u64) -> Result<DiskFillReport> {
        let Some(disk) = self.disk.clone() else {
            return Ok(DiskFillReport::default());
        };
        let _running = self.fill_lock.lock().await;
        let mut report = DiskFillReport::default();
        if self.fill_epoch.load(Ordering::SeqCst) != epoch {
            report.superseded = true;
            return Ok(report);
        }
        let mut wanted = Vec::new();
        let mut sealed = 0_u64;
        for object in &overflow.objects {
            let next = sealed.saturating_add(sealed_len(object.size_bytes));
            if next > disk.max_bytes() {
                break;
            }
            sealed = next;
            wanted.push(object);
        }
        report.beyond_disk = overflow.objects.len() - wanted.len();
        let identities = wanted
            .iter()
            .map(|object| DiskObjectIdentity::of(object))
            .collect::<Result<Vec<_>>>()?;
        report.removed = disk.retain_only(identities.iter().copied())?;
        for object in wanted {
            if self.fill_epoch.load(Ordering::SeqCst) != epoch {
                report.superseded = true;
                break;
            }
            let identity = DiskObjectIdentity::of(object)?;
            if disk.contains(identity) {
                report.already_present += 1;
                continue;
            }
            match self.admit(&disk, overflow, object).await {
                Ok(()) => {
                    report.admitted += 1;
                    report.admitted_bytes += object.size_bytes;
                }
                Err(error) if error.downcast_ref::<DiskTierFull>().is_some() => {
                    tracing::warn!(error = %error, "hot-tail disk tier full; remaining overflow stays on R2");
                    report.failed += 1;
                    break;
                }
                Err(error) => {
                    tracing::warn!(error = %error, "hot-tail disk tier admission failed; object stays on R2");
                    report.failed += 1;
                }
            }
        }
        Ok(report)
    }

    async fn admit(&self, disk: &Arc<DiskTier>, overflow: &HotTailOverflow, object: &HotTailObject) -> Result<()> {
        if let Some(local) = overflow.source.local_copy(object) {
            let disk = disk.clone();
            let object = object.clone();
            let sealed = tokio::task::spawn_blocking(move || {
                disk.admit_from_file(DiskObjectIdentity::of(&object)?, &local)
            })
            .await
            .context("join disk-tier admission")?;
            match sealed {
                Ok(()) => return Ok(()),
                Err(error) if error.downcast_ref::<DiskTierFull>().is_some() => return Err(error),
                Err(error) => {
                    tracing::debug!(error = %error, "RAM-tier copy unusable; sealing from R2");
                }
            }
        }
        let mut writer = disk.begin(DiskObjectIdentity::of(object)?)?;
        fetch_verified(overflow.source.as_ref(), object, &mut |chunk: &[u8]| writer.update(chunk)).await?;
        writer.finish()
    }
}

fn overlaps(object: &HotTailObject, window: Option<(i64, i64)>) -> bool {
    let Some((start_ms, end_ms)) = window else {
        return true;
    };
    match (object.min_time_ms, object.max_time_ms) {
        (Some(minimum), Some(maximum)) => minimum <= end_ms && maximum >= start_ms,
        // Unknown bounds are always staged; skipping one could hide rows.
        _ => true,
    }
}

fn widen(slot: &mut Option<i64>, value: Option<i64>, pick: fn(i64, i64) -> i64) {
    if let Some(value) = value {
        *slot = Some(slot.map_or(value, |current| pick(current, value)));
    }
}

fn partial_for(
    overflow: &HotTailOverflow,
    uncovered: &[&HotTailObject],
    budget_bytes: u64,
    reason: &str,
) -> HotTailPartialCoverage {
    let uncovered_bytes = uncovered
        .iter()
        .map(|object| object.size_bytes)
        .fold(0_u64, u64::saturating_add);
    HotTailPartialCoverage {
        total_objects: overflow.total_objects,
        served_objects: overflow.total_objects.saturating_sub(uncovered.len()),
        total_bytes: overflow.total_bytes,
        served_bytes: overflow.total_bytes.saturating_sub(uncovered_bytes),
        budget_bytes,
        cache_max_bytes: overflow.ram_max_bytes,
        uncovered_from_ms: uncovered
            .iter()
            .map(|object| object.min_time_ms)
            .collect::<Option<Vec<_>>>()
            .and_then(|times| times.into_iter().min()),
        uncovered_through_ms: uncovered
            .iter()
            .map(|object| object.max_time_ms)
            .collect::<Option<Vec<_>>>()
            .and_then(|times| times.into_iter().max()),
        reason: Some(reason.to_string()),
    }
}

/// Strict tmpfs/ramfs check: an undeterminable filesystem is NOT memory.
pub fn is_memory_backed(path: &Path) -> Result<bool> {
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::ffi::OsStrExt;
        let c_path = std::ffi::CString::new(path.as_os_str().as_bytes())
            .context("staging path contains a NUL byte")?;
        let mut stat = std::mem::MaybeUninit::<libc::statfs>::uninit();
        // SAFETY: `c_path` is NUL-terminated and `stat` is a valid out pointer.
        if unsafe { libc::statfs(c_path.as_ptr(), stat.as_mut_ptr()) } != 0 {
            return Err(std::io::Error::last_os_error())
                .with_context(|| format!("statfs {}", path.display()));
        }
        // SAFETY: statfs returned 0, so it initialised `stat`.
        let kind = unsafe { stat.assume_init() }.f_type as u64;
        const RAMFS_MAGIC: u64 = 0x8584_58f6;
        Ok(kind == libc::TMPFS_MAGIC as u64 || kind == RAMFS_MAGIC)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = path;
        Ok(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hot_tail_disk_tier::DiskTierKey;
    use std::collections::BTreeMap;
    use std::sync::atomic::AtomicUsize;

    /// In-memory stand-in for R2. `corrupt` serves different bytes than the
    /// signed digest; `down` fails every read.
    #[derive(Default)]
    struct FakeR2 {
        objects: Mutex<BTreeMap<String, Vec<u8>>>,
        corrupt: Mutex<BTreeSet<String>>,
        down: std::sync::atomic::AtomicBool,
        reads: AtomicUsize,
        local: Mutex<BTreeMap<String, PathBuf>>,
    }

    #[async_trait::async_trait]
    impl HotTailObjectSource for FakeR2 {
        async fn stream_object(
            &self,
            object: &HotTailObject,
            sink: &mut (dyn for<'b> FnMut(&'b [u8]) -> Result<()> + Send),
        ) -> Result<()> {
            self.reads.fetch_add(1, Ordering::SeqCst);
            if self.down.load(Ordering::SeqCst) {
                bail!("R2 unreachable");
            }
            let mut bytes = self
                .objects
                .lock()
                .unwrap()
                .get(&object.source_uri)
                .cloned()
                .context("NoSuchKey")?;
            if self.corrupt.lock().unwrap().contains(&object.source_uri) {
                bytes[0] ^= 0xff;
            }
            for chunk in bytes.chunks(7) {
                sink(chunk)?;
            }
            Ok(())
        }

        fn local_copy(&self, object: &HotTailObject) -> Option<PathBuf> {
            self.local.lock().unwrap().get(&object.source_uri).cloned()
        }
    }

    fn tail_object(index: i64, bytes: &[u8]) -> HotTailObject {
        HotTailObject {
            source_uri: format!("s3://bucket/t/data/tail/{index:03}.parquet"),
            version_id: "v".to_string(),
            etag: Some(format!("\"etag-{index}\"")),
            size_bytes: bytes.len() as u64,
            rows: 1,
            sha256: Some(hex::encode(Sha256::digest(bytes))),
            min_time_ms: Some(index * 1_000),
            max_time_ms: Some(index * 1_000 + 999),
            committed: false,
        }
    }

    /// Objects 0..count, 100 bytes each; `newest_first` overflow of all.
    fn fixture(count: i64) -> (Arc<FakeR2>, HotTailOverflow) {
        let r2 = Arc::new(FakeR2::default());
        let mut objects = Vec::new();
        for index in 0..count {
            let bytes = vec![b'A' + index as u8; 100];
            let object = tail_object(index, &bytes);
            r2.objects.lock().unwrap().insert(object.source_uri.clone(), bytes);
            objects.push(object);
        }
        objects.reverse();
        let overflow = HotTailOverflow {
            objects,
            total_objects: count as usize + 2,
            total_bytes: (count as u64 + 2) * 100,
            ram_max_bytes: 400,
            source: r2.clone(),
        };
        (r2, overflow)
    }

    fn settings(staging: &Path, query_max_bytes: u64) -> SlowPathSettings {
        SlowPathSettings {
            staging_dir: staging.to_path_buf(),
            staging_max_bytes: 10_000,
            query_max_bytes,
            concurrency: 2,
            deadline: Duration::from_secs(10),
        }
    }

    fn disk(root: &Path, max_bytes: u64) -> Arc<DiskTier> {
        DiskTier::open(root, max_bytes, &DiskTierKey::from_bytes([5; 32]), "tenant-a").unwrap()
    }

    #[tokio::test]
    async fn overflow_on_the_disk_tier_is_served_fully_without_touching_r2() {
        let staging = tempfile::tempdir().unwrap();
        let volume = tempfile::tempdir().unwrap();
        let (r2, overflow) = fixture(4);
        let slow = HotTailSlowPath::new_unchecked(settings(staging.path(), 1_000), Some(disk(volume.path(), 1 << 20)));
        let report = slow.fill_disk(&overflow, 0).await.unwrap();
        assert_eq!((report.admitted, report.beyond_disk), (4, 0));
        let reads_after_fill = r2.reads.load(Ordering::SeqCst);

        let staged = slow.stage(&overflow, None).await;
        assert!(staged.partial.is_none());
        let coverage = staged.slow_path.clone().expect("slow path used");
        assert_eq!((coverage.objects, coverage.disk_objects, coverage.r2_objects), (4, 4, 0));
        assert_eq!((coverage.from_ms, coverage.through_ms), (Some(0), Some(3_999)));
        assert_eq!(r2.reads.load(Ordering::SeqCst), reads_after_fill, "no R2 read at query time");
        for (object, path) in staged.objects.iter().zip(&staged.paths) {
            let bytes = std::fs::read(path).unwrap();
            assert_eq!(hex::encode(Sha256::digest(&bytes)), *object.sha256.as_ref().unwrap());
        }
        assert_eq!(slow.staged_bytes(), 400);
        let directory = staged.directory().unwrap().to_path_buf();
        drop(staged);
        assert!(!directory.exists(), "staged plaintext is removed after the query");
        assert_eq!(slow.staged_bytes(), 0);
    }

    #[tokio::test]
    async fn the_r2_read_through_is_verified_and_a_bad_hash_is_refused() {
        let staging = tempfile::tempdir().unwrap();
        let (r2, overflow) = fixture(3);
        let slow = HotTailSlowPath::new_unchecked(settings(staging.path(), 1_000), None);
        let staged = slow.stage(&overflow, None).await;
        let coverage = staged.slow_path.clone().unwrap();
        assert_eq!((coverage.r2_objects, coverage.disk_objects), (3, 0));
        assert_eq!((coverage.r2_from_ms, coverage.r2_through_ms), (Some(0), Some(2_999)));
        assert!(staged.partial.is_none());
        drop(staged);

        // Object 1 (the middle one) comes back from R2 with different bytes.
        r2.corrupt.lock().unwrap().insert(overflow.objects[1].source_uri.clone());
        let staged = slow.stage(&overflow, None).await;
        assert_eq!(staged.objects.len(), 1, "only the newest object precedes the bad one");
        assert_eq!(staged.objects[0].source_uri, overflow.objects[0].source_uri);
        let partial = staged.partial.clone().expect("a refused object is never served");
        assert_eq!(partial.reason.as_deref(), Some(PARTIAL_REASON_UNAVAILABLE));
        assert_eq!((partial.uncovered_from_ms, partial.uncovered_through_ms), (Some(0), Some(1_999)));
        // The refused bytes never reach a path chDB could open.
        let names: Vec<_> = std::fs::read_dir(staged.directory().unwrap())
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .collect();
        assert_eq!(names, staged.paths);
    }

    #[tokio::test]
    async fn fetch_verified_refuses_short_long_and_forged_objects() {
        let (r2, overflow) = fixture(1);
        let object = overflow.objects[0].clone();
        let mut sink = |_: &[u8]| Ok(());
        fetch_verified(r2.as_ref(), &object, &mut sink).await.unwrap();
        let mut forged = object.clone();
        forged.sha256 = Some("f".repeat(64));
        assert!(fetch_verified(r2.as_ref(), &forged, &mut sink).await.is_err());
        let mut short = object.clone();
        short.size_bytes = 99;
        assert!(fetch_verified(r2.as_ref(), &short, &mut sink).await.is_err());
        let mut long = object;
        long.size_bytes = 101;
        assert!(fetch_verified(r2.as_ref(), &long, &mut sink).await.is_err());
    }

    #[tokio::test]
    async fn per_query_budget_is_enforced_newest_first_and_reported_partial() {
        let staging = tempfile::tempdir().unwrap();
        let (_, overflow) = fixture(5);
        // 250 bytes of budget: the two newest 100-byte objects fit.
        let slow = HotTailSlowPath::new_unchecked(settings(staging.path(), 250), None);
        let staged = slow.stage(&overflow, None).await;
        assert_eq!(
            staged.objects.iter().map(|o| o.min_time_ms.unwrap()).collect::<Vec<_>>(),
            vec![4_000, 3_000]
        );
        let partial = staged.partial.clone().unwrap();
        assert_eq!(partial.reason.as_deref(), Some(PARTIAL_REASON_OVER_BUDGET));
        assert_eq!((partial.uncovered_from_ms, partial.uncovered_through_ms), (Some(0), Some(2_999)));
        assert!(slow.staged_bytes() <= 250);
        // A narrow window inside the budget is complete: no partial.
        drop(staged);
        let staged = slow.stage(&overflow, Some((500, 1_500))).await;
        assert!(staged.partial.is_none());
        assert_eq!(staged.objects.len(), 2);
    }

    #[tokio::test]
    async fn global_staging_bound_and_concurrency_are_enforced() {
        let staging = tempfile::tempdir().unwrap();
        let (_, overflow) = fixture(3);
        let slow = HotTailSlowPath::new_unchecked(
            SlowPathSettings {
                staging_max_bytes: 300,
                query_max_bytes: 300,
                concurrency: 1,
                deadline: Duration::from_millis(200),
                ..settings(staging.path(), 300)
            },
            None,
        );
        let first = slow.stage(&overflow, None).await;
        assert!(first.partial.is_none());
        assert_eq!(slow.staged_bytes(), 300);
        // The one permit is held by `first`: the second query waits out its
        // deadline and is served partial, never unbounded.
        let second = slow.stage(&overflow, None).await;
        assert_eq!(second.partial.unwrap().reason.as_deref(), Some(PARTIAL_REASON_BUSY));
        assert_eq!(slow.staged_bytes(), 300);
        drop(first);
        assert_eq!(slow.staged_bytes(), 0);
        assert!(slow.stage(&overflow, None).await.partial.is_none());
    }

    #[tokio::test]
    async fn partial_is_the_last_resort_only_when_r2_is_down() {
        let staging = tempfile::tempdir().unwrap();
        let volume = tempfile::tempdir().unwrap();
        let (r2, overflow) = fixture(4);
        // The disk tier holds only the two newest objects.
        let tier = disk(volume.path(), sealed_len(100) * 2);
        let slow = HotTailSlowPath::new_unchecked(settings(staging.path(), 1_000), Some(tier));
        let report = slow.fill_disk(&overflow, 0).await.unwrap();
        assert_eq!((report.admitted, report.beyond_disk), (2, 2));
        // R2 up: disk for the newest two, R2 for the rest. Complete.
        let staged = slow.stage(&overflow, None).await;
        let coverage = staged.slow_path.clone().unwrap();
        assert_eq!((coverage.disk_objects, coverage.r2_objects), (2, 2));
        assert_eq!((coverage.r2_from_ms, coverage.r2_through_ms), (Some(0), Some(1_999)));
        assert!(staged.partial.is_none());
        drop(staged);
        // R2 down: the disk tier still serves its range; only the rest is partial.
        r2.down.store(true, Ordering::SeqCst);
        let staged = slow.stage(&overflow, None).await;
        assert_eq!(staged.slow_path.as_ref().unwrap().disk_objects, 2);
        let partial = staged.partial.unwrap();
        assert_eq!(partial.reason.as_deref(), Some(PARTIAL_REASON_UNAVAILABLE));
        assert_eq!((partial.uncovered_from_ms, partial.uncovered_through_ms), (Some(0), Some(1_999)));
        // A window the disk tier covers is still complete with R2 down.
        let staged = slow.stage(&overflow, Some((2_500, 3_500))).await;
        assert!(staged.partial.is_none());
    }

    #[tokio::test]
    async fn disk_fill_prefers_the_local_ram_copy_and_revalidates_against_the_manifest() {
        let staging = tempfile::tempdir().unwrap();
        let volume = tempfile::tempdir().unwrap();
        let ram = tempfile::tempdir().unwrap();
        let (r2, overflow) = fixture(3);
        for object in &overflow.objects {
            let path = ram.path().join(object.sha256.as_ref().unwrap());
            std::fs::write(&path, r2.objects.lock().unwrap()[&object.source_uri].clone()).unwrap();
            r2.local.lock().unwrap().insert(object.source_uri.clone(), path);
        }
        let tier = disk(volume.path(), 1 << 20);
        let slow = HotTailSlowPath::new_unchecked(settings(staging.path(), 1_000), Some(tier.clone()));
        slow.fill_disk(&overflow, 0).await.unwrap();
        assert_eq!(r2.reads.load(Ordering::SeqCst), 0, "demotion seals the RAM copy, no download");
        assert_eq!(tier.object_count(), 3);
        // The next tail drops the oldest object (it was compacted). After a
        // restart the survivor set is revalidated against the new manifest.
        drop(slow);
        drop(tier);
        let tier = disk(volume.path(), 1 << 20);
        assert_eq!(tier.object_count(), 3);
        let mut next = overflow.clone();
        next.objects.pop();
        let slow = HotTailSlowPath::new_unchecked(settings(staging.path(), 1_000), Some(tier.clone()));
        let report = slow.fill_disk(&next, 0).await.unwrap();
        assert_eq!((report.removed, report.already_present, report.admitted), (1, 2, 0));
        assert_eq!(tier.object_count(), 2);
    }

    #[tokio::test]
    async fn a_superseded_fill_stops() {
        let staging = tempfile::tempdir().unwrap();
        let volume = tempfile::tempdir().unwrap();
        let (_, overflow) = fixture(2);
        let slow = HotTailSlowPath::new_unchecked(settings(staging.path(), 1_000), Some(disk(volume.path(), 1 << 20)));
        slow.fill_epoch.store(5, Ordering::SeqCst);
        assert!(slow.fill_disk(&overflow, 4).await.unwrap().superseded);
    }

    #[test]
    fn startup_sweep_removes_only_crashed_query_directories() {
        let staging = tempfile::tempdir().unwrap();
        std::fs::create_dir(staging.path().join("query-crashed")).unwrap();
        std::fs::write(staging.path().join("query-crashed/0000.parquet"), b"plaintext").unwrap();
        std::fs::create_dir(staging.path().join("unrelated")).unwrap();
        std::fs::write(staging.path().join("keep.txt"), b"x").unwrap();
        let _slow = HotTailSlowPath::new_unchecked(settings(staging.path(), 100), None);
        assert!(!staging.path().join("query-crashed").exists());
        assert!(staging.path().join("unrelated").exists());
        assert!(staging.path().join("keep.txt").exists());
    }

    #[test]
    fn settings_require_a_bounded_staging_area() {
        let some = |value: &str| Some(value.to_string());
        assert!(SlowPathSettings::parse(None, None, None, None, None).unwrap().is_none());
        assert!(SlowPathSettings::parse(None, None, some("1"), None, None).is_err());
        assert!(SlowPathSettings::parse(some("/staging"), None, None, None, None).is_err());
        assert!(SlowPathSettings::parse(some("relative"), some("100"), None, None, None).is_err());
        assert!(SlowPathSettings::parse(some("/staging"), some("100"), some("200"), None, None).is_err());
        let parsed = SlowPathSettings::parse(some("/staging"), some("1000"), None, some("4"), some("20"))
            .unwrap()
            .unwrap();
        assert_eq!((parsed.query_max_bytes, parsed.concurrency), (250, 4));
        assert_eq!(parsed.deadline, Duration::from_secs(20));
    }

    #[test]
    fn staging_refuses_a_non_tmpfs_directory() {
        // The repository checkout is on a disk filesystem, never tmpfs.
        let directory = tempfile::tempdir_in(env!("CARGO_MANIFEST_DIR")).unwrap();
        if is_memory_backed(directory.path()).unwrap() {
            return;
        }
        let error = HotTailSlowPath::new(settings(directory.path(), 100), None).unwrap_err();
        assert!(error.to_string().contains("is not tmpfs"), "{error}");
    }
}
