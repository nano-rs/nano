// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-2762: disk discipline for the standalone generation bundle publisher.
//!
//! A publisher cycle holds three things on the generations volume:
//!
//! * the hydrated source snapshot (`<generation>/snapshot/data`, every Parquet
//!   object of the Iceberg snapshot: 18 GB on staging 2026-09-24);
//! * the prior generation's derivatives (`<prior>/derivatives-v1-*`, recovered
//!   from the signed R2 bundle or retained from the last cycle: 25 GB), which
//!   the builders reuse by hard link per object;
//! * the new derivative tree being built, and then its upload staging.
//!
//! The old flow held all three until the bundle was uploaded, so peak disk was
//! `data + prior + new + staging`. The volume was sized for one generation
//! (48 GiB), so it was evicted mid-upload. This module keeps the peak at about
//! one generation plus its delta:
//!
//! 1. before building, it projects the peak from measured sizes. When the
//!    prior prevalence member does not fit, it drops that member (prevalence then
//!    rebuilds from the authoritative snapshot: same output, slower). When the
//!    build cannot fit at all, it defers with a clear decision instead of being
//!    evicted;
//! 2. it releases the prior sidecar members as soon as the sidecar build has
//!    published its tree. Files the new tree reused stay alive through their
//!    hard links;
//! 3. it releases the rest of the prior once prevalence is built;
//! 4. it releases the hydrated source data before upload only when the volume
//!    cannot hold it through upload. The bundle carries only derivatives and
//!    the object-stamp manifest, but the retained source is the next cycle's
//!    hydration reuse source (NAN-2849): the next snapshot hard-links every
//!    unchanged object from it and downloads only the delta. Releasing it
//!    made every cycle re-download the whole snapshot (22 GB, ~7k GETs,
//!    5.5-7 min on tenant1, `reused_objects=0`);
//! 5. before the next hydration, [`plan_hydration_reuse`] checks that the
//!    retained source plus a worst-case full download still fits, and
//!    otherwise releases it first. After hydration the manager releases the
//!    prior's source (the new snapshot holds the shared objects by hard link),
//!    so the overlap only lasts through hydration.
//!
//! Every release keeps what an interrupted cycle needs to resume. The prior
//! derivative directory itself stays as an (emptied) tombstone, so
//! `latest_local_prior_derivatives` still resolves it and the prior is not
//! downloaded again from R2 on resume.

use std::collections::HashSet;
use std::future::Future;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::Serialize;

use crate::generation::ObjectStampManifest;

/// Derivative member built by the prevalence builder rather than the sidecar
/// builder. Mirrors `PREVALENCE_DERIVATIVE_DIRECTORY` in the manager.
pub const PREVALENCE_MEMBER: &str = "prevalence-snapshot-v2";
/// Derivative bytes per source byte assumed when no prior generation exists
/// to measure. Generation 09df2462 carried 25.0 GB of derivatives over about
/// 17 GB of source objects.
pub const NO_PRIOR_DERIVATIVE_RATIO: f64 = 1.5;
/// Share of the derivative bytes produced by the sidecar builder (09df2462:
/// 13.1 of 23.3 GiB); the remainder is prevalence.
pub const NO_PRIOR_SIDECAR_SHARE: f64 = 0.56;
/// A generation never shrinks below its predecessor for estimation purposes,
/// and a corrupt or empty prior stamp manifest must not explode the estimate.
pub const MAX_GROWTH_RATIO: f64 = 4.0;

/// Upload staging prefixes written beside the derivative root by the bundle
/// publisher (`build_archive_shard_blocking`, `build_raw_chunk`, and the
/// checkpoint writers). A dead publisher leaves them behind.
const STAGING_PREFIXES: [&str; 2] = [".nano-generation-bundle-archive-", ".tmp"];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ByteMode {
    /// `st_blocks * 512`: what the kubelet and the filesystem charge.
    Allocated,
    /// `st_size`: deterministic across filesystems (tests).
    Logical,
}

fn entry_bytes(metadata: &std::fs::Metadata, mode: ByteMode) -> u64 {
    match mode {
        ByteMode::Allocated => metadata.blocks().saturating_mul(512),
        ByteMode::Logical => metadata.len(),
    }
}

fn tree_bytes_into(path: &Path, mode: ByteMode, seen: &mut HashSet<(u64, u64)>) -> Result<u64> {
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(0),
        Err(error) => return Err(error).with_context(|| format!("stat {}", path.display())),
    };
    // Hard links are charged once, exactly as the filesystem charges them.
    if !seen.insert((metadata.dev(), metadata.ino())) {
        return Ok(0);
    }
    let mut total = entry_bytes(&metadata, mode);
    if metadata.is_dir() {
        let entries = match std::fs::read_dir(path) {
            Ok(entries) => entries,
            // Concurrent removal of an abandoned candidate is not an error.
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(total),
            Err(error) => return Err(error).with_context(|| format!("list {}", path.display())),
        };
        for entry in entries {
            let entry = entry?;
            total = total.saturating_add(tree_bytes_into(&entry.path(), mode, seen)?);
        }
    }
    Ok(total)
}

/// Bytes charged by the trees under `paths`, counting every inode once and
/// never following symlinks. A missing path contributes zero.
pub fn trees_bytes(paths: &[&Path], mode: ByteMode) -> Result<u64> {
    let mut seen = HashSet::new();
    let mut total = 0_u64;
    for path in paths {
        total = total.saturating_add(tree_bytes_into(path, mode, &mut seen)?);
    }
    Ok(total)
}

pub fn tree_bytes(path: &Path, mode: ByteMode) -> Result<u64> {
    trees_bytes(&[path], mode)
}

fn remove_path(path: &Path) -> Result<()> {
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error).with_context(|| format!("stat {}", path.display())),
    };
    if metadata.is_dir() {
        std::fs::remove_dir_all(path).with_context(|| format!("remove {}", path.display()))
    } else {
        std::fs::remove_file(path).with_context(|| format!("remove {}", path.display()))
    }
}

/// Remove every member of the prior derivative directory except `keep`. The
/// directory itself stays: it is the resume tombstone that stops the next
/// reconcile from recovering the prior from R2 again.
pub fn release_prior_members(prior: &Path, keep: &[&str]) -> Result<u64> {
    let before = tree_bytes(prior, ByteMode::Allocated)?;
    let entries = match std::fs::read_dir(prior) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(0),
        Err(error) => return Err(error).with_context(|| format!("list {}", prior.display())),
    };
    for entry in entries {
        let entry = entry?;
        let name = entry.file_name();
        if keep.iter().any(|kept| name == std::ffi::OsStr::new(kept)) {
            continue;
        }
        remove_path(&entry.path())?;
    }
    std::fs::File::open(prior)?.sync_all()?;
    Ok(before.saturating_sub(tree_bytes(prior, ByteMode::Allocated)?))
}

/// Release the hydrated Iceberg objects of a generation whose derivatives are
/// complete. `object-stamps.json` stays: resume, bundle identity, and the next
/// cycle's prior lookup all read it. A later hydration that names this
/// generation as its prior finds no reusable file and downloads instead.
pub fn release_snapshot_data(snapshot_root: &Path) -> Result<u64> {
    let data = snapshot_root.join("data");
    let before = tree_bytes(&data, ByteMode::Allocated)?;
    remove_path(&data)?;
    if snapshot_root.is_dir() {
        std::fs::File::open(snapshot_root)?.sync_all()?;
    }
    Ok(before)
}

/// Remove upload staging left by a dead publisher. The caller must hold the
/// generation-manager lock, because a live uploader's staging files are
/// indistinguishable from dead ones. Only regular files directly inside a
/// `snapshot-*` generation directory are considered.
pub fn sweep_dead_publisher_staging(generations_root: &Path) -> Result<(usize, u64)> {
    let mut removed = 0_usize;
    let mut bytes = 0_u64;
    let entries = match std::fs::read_dir(generations_root) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok((0, 0)),
        Err(error) => return Err(error).context("list generations root"),
    };
    for generation in entries {
        let generation = generation?;
        if !generation.file_type()?.is_dir()
            || !generation
                .file_name()
                .to_string_lossy()
                .starts_with("snapshot-")
        {
            continue;
        }
        for entry in std::fs::read_dir(generation.path())? {
            let entry = entry?;
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if !STAGING_PREFIXES
                .iter()
                .any(|prefix| name.starts_with(prefix))
            {
                continue;
            }
            let metadata = std::fs::symlink_metadata(entry.path())?;
            if !metadata.is_file() {
                continue;
            }
            bytes = bytes.saturating_add(entry_bytes(&metadata, ByteMode::Allocated));
            std::fs::remove_file(entry.path())?;
            removed += 1;
        }
    }
    Ok((removed, bytes))
}

/// Per-object derivative members the builders reuse by hard link for every
/// source object the new snapshot retains (sidecar builder: entity, keyword,
/// count-rollup; prevalence builder: `parts`). Everything else is treated as
/// rewritten.
const PER_OBJECT_SIDECAR_MEMBERS: [&str; 3] = ["entity-sidecar", "keyword-sidecar", "count-rollup"];
const PER_OBJECT_PREVALENCE_MEMBERS: [&str; 1] = ["parts"];

fn read_stamps(path: &Path) -> Option<ObjectStampManifest> {
    serde_json::from_slice(&std::fs::read(path).ok()?).ok()
}

fn stamps_bytes(manifest: &ObjectStampManifest) -> u64 {
    manifest.objects.iter().fold(0_u64, |total, object| {
        total.saturating_add(object.size_bytes)
    })
}

/// Share of the prior's source bytes that the new snapshot still contains
/// (same relative path and content digest).
fn retained_fraction(prior: &ObjectStampManifest, next: &ObjectStampManifest) -> f64 {
    let total = stamps_bytes(prior);
    if total == 0 {
        return 0.0;
    }
    let next: HashSet<(&str, &str)> = next
        .objects
        .iter()
        .map(|object| (object.relative_path.as_str(), object.sha256.as_str()))
        .collect();
    let retained = prior
        .objects
        .iter()
        .filter(|object| next.contains(&(object.relative_path.as_str(), object.sha256.as_str())))
        .fold(0_u64, |sum, object| sum.saturating_add(object.size_bytes));
    (retained as f64 / total as f64).clamp(0.0, 1.0)
}

/// Everything the projection needs, measured on disk.
#[derive(Clone, Debug, Serialize)]
pub struct PublisherDiskInputs {
    /// Bytes charged by the generations root now (data + prior + partial work).
    pub used_bytes: u64,
    /// `min(declared volume size, filesystem size) - reserve`, further bounded
    /// by the filesystem's free space.
    pub limit_bytes: u64,
    pub capacity_bytes: u64,
    pub reserve_bytes: u64,
    pub filesystem_available_bytes: u64,
    pub snapshot_data_bytes: u64,
    pub source_bytes: u64,
    pub has_prior: bool,
    pub prior_sidecar_bytes: u64,
    pub prior_prevalence_bytes: u64,
    /// Prior bytes the builders will hard-link into the new tree (per-object
    /// members times the retained source fraction). Neither new nor freed.
    pub reusable_sidecar_bytes: u64,
    pub reusable_prevalence_bytes: u64,
    pub growth_ratio: f64,
    pub sidecars_built: bool,
    pub prevalence_built: bool,
    pub upload_staging_bytes: u64,
}

/// Projected peaks for one choice of what to keep.
#[derive(Clone, Debug, Serialize, PartialEq)]
pub struct PublisherDiskPlan {
    pub keep_prior_prevalence: bool,
    /// NAN-2849: keep the hydrated source through upload as the next cycle's
    /// hydration reuse source. The upload peak then carries it.
    pub keep_snapshot_data: bool,
    pub estimated_sidecar_bytes: u64,
    pub estimated_prevalence_bytes: u64,
    pub sidecar_peak_bytes: u64,
    pub prevalence_peak_bytes: u64,
    pub upload_peak_bytes: u64,
    pub projected_peak_bytes: u64,
    pub limit_bytes: u64,
}

#[derive(Clone, Debug, Serialize, PartialEq)]
#[serde(tag = "decision", rename_all = "snake_case")]
pub enum PublisherDiskDecision {
    Proceed(PublisherDiskPlan),
    Defer(PublisherDiskPlan),
}

impl PublisherDiskDecision {
    pub fn plan(&self) -> &PublisherDiskPlan {
        match self {
            Self::Proceed(plan) | Self::Defer(plan) => plan,
        }
    }
}

fn scaled(bytes: u64, factor: f64) -> u64 {
    let value = (bytes as f64 * factor).ceil();
    if value >= u64::MAX as f64 {
        u64::MAX
    } else {
        value as u64
    }
}

fn project(
    inputs: &PublisherDiskInputs,
    keep_prior_prevalence: bool,
    keep_snapshot_data: bool,
) -> PublisherDiskPlan {
    let growth = inputs.growth_ratio.clamp(1.0, MAX_GROWTH_RATIO);
    let no_prior_total = scaled(inputs.source_bytes, NO_PRIOR_DERIVATIVE_RATIO);
    let estimated_sidecar_bytes = if inputs.has_prior && inputs.prior_sidecar_bytes > 0 {
        scaled(inputs.prior_sidecar_bytes, growth)
    } else {
        scaled(no_prior_total, NO_PRIOR_SIDECAR_SHARE)
    };
    let estimated_prevalence_bytes = if inputs.has_prior && inputs.prior_prevalence_bytes > 0 {
        scaled(inputs.prior_prevalence_bytes, growth)
    } else {
        scaled(no_prior_total, 1.0 - NO_PRIOR_SIDECAR_SHARE)
    };
    let dropped = if keep_prior_prevalence {
        0
    } else {
        inputs.prior_prevalence_bytes
    };
    let prior_prevalence = inputs.prior_prevalence_bytes - dropped;
    let reusable_prevalence = if keep_prior_prevalence {
        inputs.reusable_prevalence_bytes
    } else {
        0
    };
    let used = inputs.used_bytes.saturating_sub(dropped);
    // Net model: bytes the new tree hard-links from the prior are neither new
    // nor freed, so each phase costs `new - reused` while it runs and
    // `new - prior` once the prior's member is released.
    let sidecar_peak_bytes = if inputs.sidecars_built {
        used
    } else {
        used.saturating_add(estimated_sidecar_bytes.saturating_sub(inputs.reusable_sidecar_bytes))
    };
    let after_sidecars = if inputs.sidecars_built {
        used.saturating_sub(inputs.prior_sidecar_bytes)
    } else {
        sidecar_peak_bytes.saturating_sub(
            inputs
                .prior_sidecar_bytes
                .saturating_sub(inputs.reusable_sidecar_bytes),
        )
    };
    let prevalence_peak_bytes = if inputs.prevalence_built {
        after_sidecars
    } else {
        after_sidecars
            .saturating_add(estimated_prevalence_bytes.saturating_sub(reusable_prevalence))
    };
    let released_data = if keep_snapshot_data {
        0
    } else {
        inputs.snapshot_data_bytes
    };
    let upload_peak_bytes = prevalence_peak_bytes
        .saturating_sub(prior_prevalence.saturating_sub(reusable_prevalence))
        .saturating_sub(released_data)
        .saturating_add(inputs.upload_staging_bytes);
    let projected_peak_bytes = sidecar_peak_bytes
        .max(prevalence_peak_bytes)
        .max(upload_peak_bytes);
    PublisherDiskPlan {
        keep_prior_prevalence,
        keep_snapshot_data,
        estimated_sidecar_bytes,
        estimated_prevalence_bytes,
        sidecar_peak_bytes,
        prevalence_peak_bytes,
        upload_peak_bytes,
        projected_peak_bytes,
        limit_bytes: inputs.limit_bytes,
    }
}

/// Pick the cheapest plan that fits, in order of what each retention saves:
/// keep the prior prevalence member (saves a full prevalence rebuild) before
/// keeping the hydrated source through upload (saves the next cycle's full
/// snapshot download, NAN-2849). With neither fitting, defer.
pub fn decide(inputs: &PublisherDiskInputs) -> PublisherDiskDecision {
    let prevalence_choices: &[bool] = if inputs.prior_prevalence_bytes == 0 {
        &[true]
    } else {
        &[true, false]
    };
    let mut last = None;
    for &keep_prior_prevalence in prevalence_choices {
        for keep_snapshot_data in [true, false] {
            let plan = project(inputs, keep_prior_prevalence, keep_snapshot_data);
            if plan.projected_peak_bytes <= inputs.limit_bytes {
                return PublisherDiskDecision::Proceed(plan);
            }
            last = Some(plan);
        }
    }
    PublisherDiskDecision::Defer(last.expect("at least one plan is projected"))
}

/// Size limits that do not depend on the cycle.
#[derive(Clone, Copy, Debug)]
pub struct PublisherDiskLimits {
    /// Declared runtime volume size (the emptyDir `sizeLimit`); `None` when
    /// the volume is a real filesystem (PVC) whose `statfs` size is the limit.
    pub declared_volume_bytes: Option<u64>,
    pub reserve_bytes: u64,
    /// Worst-case transient upload staging (`concurrency * shard bytes`).
    pub upload_staging_bytes: u64,
}

/// Paths of one publisher cycle.
#[derive(Clone, Debug)]
pub struct PublisherBuildLayout {
    pub generations_root: PathBuf,
    pub snapshot_root: PathBuf,
    pub derivatives: PathBuf,
    pub prior_derivatives: Option<PathBuf>,
}

impl PublisherBuildLayout {
    fn prevalence_root(&self) -> PathBuf {
        self.derivatives.join(PREVALENCE_MEMBER)
    }
}

/// `(capacity, limit)`: `min(declared volume, filesystem size) - reserve`,
/// further bounded by what the filesystem can still hand out.
fn volume_limit(
    used_bytes: u64,
    limits: &PublisherDiskLimits,
    filesystem: (u64, u64),
) -> (u64, u64) {
    let (filesystem_total, filesystem_available) = filesystem;
    let capacity_bytes = limits
        .declared_volume_bytes
        .map_or(filesystem_total, |declared| declared.min(filesystem_total));
    let limit_bytes = capacity_bytes.saturating_sub(limits.reserve_bytes).min(
        used_bytes
            .saturating_add(filesystem_available)
            .saturating_sub(limits.reserve_bytes),
    );
    (capacity_bytes, limit_bytes)
}

/// Worst-case growth of the next snapshot over its prior, for the hydration
/// overlap check. A cycle adds ~1-2% on tenant1; 25% covers a burst.
pub const HYDRATION_GROWTH_ALLOWANCE: f64 = 1.25;

/// NAN-2849: the pre-hydration disk decision.
#[derive(Clone, Debug, Serialize, PartialEq)]
pub struct HydrationReusePlan {
    pub used_bytes: u64,
    pub limit_bytes: u64,
    /// Allocated bytes of the retained prior source (`<prior>/snapshot/data`).
    pub prior_data_bytes: u64,
    /// Worst case the hydration writes: the prior's source bytes grown by
    /// [`HYDRATION_GROWTH_ALLOWANCE`], as if nothing could be reused.
    pub worst_case_download_bytes: u64,
    /// `used + worst case` with the prior source kept through hydration.
    pub projected_peak_bytes: u64,
    /// Keep the prior source as the reuse source for this hydration.
    pub reuse: bool,
}

/// Decide whether the prior generation's hydrated source can stay resident
/// through the next hydration. With reuse the overlap costs only the delta
/// (unchanged objects are hard links to the same inodes); the check assumes
/// nothing is reusable (a table rewrite) so a full download next to the
/// retained prior can never overrun the volume. When that does not fit the
/// caller releases the prior source first, which is the pre-NAN-2849 flow.
pub fn plan_hydration_reuse(
    generations_root: &Path,
    prior_snapshot_root: &Path,
    limits: &PublisherDiskLimits,
    filesystem: (u64, u64),
) -> Result<HydrationReusePlan> {
    let used_bytes = tree_bytes(generations_root, ByteMode::Allocated)?;
    let (_, limit_bytes) = volume_limit(used_bytes, limits, filesystem);
    let prior_data_bytes = tree_bytes(&prior_snapshot_root.join("data"), ByteMode::Allocated)?;
    let prior_source_bytes = read_stamps(&prior_snapshot_root.join("object-stamps.json"))
        .as_ref()
        .map_or(prior_data_bytes, stamps_bytes)
        .max(prior_data_bytes);
    let worst_case_download_bytes = scaled(prior_source_bytes, HYDRATION_GROWTH_ALLOWANCE);
    let projected_peak_bytes = used_bytes.saturating_add(worst_case_download_bytes);
    Ok(HydrationReusePlan {
        used_bytes,
        limit_bytes,
        prior_data_bytes,
        worst_case_download_bytes,
        projected_peak_bytes,
        reuse: prior_data_bytes > 0 && projected_peak_bytes <= limit_bytes,
    })
}

/// Measure the cycle and project its peak. `filesystem` returns
/// `(total, available)` for the generations root (`statfs`); injected for tests.
pub fn measure(
    layout: &PublisherBuildLayout,
    limits: &PublisherDiskLimits,
    filesystem: (u64, u64),
) -> Result<PublisherDiskInputs> {
    let (_, filesystem_available) = filesystem;
    let used_bytes = tree_bytes(&layout.generations_root, ByteMode::Allocated)?;
    let (capacity_bytes, limit_bytes) = volume_limit(used_bytes, limits, filesystem);
    let next_stamps = read_stamps(&layout.snapshot_root.join("object-stamps.json"));
    let prior_stamps = layout
        .prior_derivatives
        .as_deref()
        .and_then(Path::parent)
        .and_then(|generation| read_stamps(&generation.join("snapshot/object-stamps.json")));
    let source_bytes = next_stamps.as_ref().map_or(0, stamps_bytes);
    let (growth_ratio, retained) = match (&prior_stamps, &next_stamps) {
        (Some(prior), Some(next)) if stamps_bytes(prior) > 0 && source_bytes > 0 => (
            source_bytes as f64 / stamps_bytes(prior) as f64,
            retained_fraction(prior, next),
        ),
        // Unknown lineage: assume no growth and no reuse (overstates).
        _ => (1.0, 0.0),
    };
    let mut reusable_sidecar_bytes = 0_u64;
    let mut reusable_prevalence_bytes = 0_u64;
    let (prior_sidecar_bytes, prior_prevalence_bytes) = match &layout.prior_derivatives {
        Some(prior) => {
            let prevalence_root = prior.join(PREVALENCE_MEMBER);
            let prevalence = tree_bytes(&prevalence_root, ByteMode::Allocated)?;
            let whole = tree_bytes(prior, ByteMode::Allocated)?;
            for member in PER_OBJECT_SIDECAR_MEMBERS {
                reusable_sidecar_bytes = reusable_sidecar_bytes.saturating_add(scaled(
                    tree_bytes(&prior.join(member), ByteMode::Allocated)?,
                    retained,
                ));
            }
            for member in PER_OBJECT_PREVALENCE_MEMBERS {
                reusable_prevalence_bytes = reusable_prevalence_bytes.saturating_add(scaled(
                    tree_bytes(&prevalence_root.join(member), ByteMode::Allocated)?,
                    retained,
                ));
            }
            (whole.saturating_sub(prevalence), prevalence)
        }
        None => (0, 0),
    };
    Ok(PublisherDiskInputs {
        used_bytes,
        limit_bytes,
        capacity_bytes,
        reserve_bytes: limits.reserve_bytes,
        filesystem_available_bytes: filesystem_available,
        snapshot_data_bytes: tree_bytes(&layout.snapshot_root.join("data"), ByteMode::Allocated)?,
        source_bytes,
        has_prior: layout.prior_derivatives.is_some(),
        prior_sidecar_bytes,
        prior_prevalence_bytes,
        reusable_sidecar_bytes,
        reusable_prevalence_bytes,
        growth_ratio,
        sidecars_built: layout.derivatives.is_dir(),
        prevalence_built: layout.prevalence_root().is_dir(),
        upload_staging_bytes: limits.upload_staging_bytes,
    })
}

/// Result of one publisher build under the disk discipline.
#[derive(Debug)]
pub enum PublisherBuildOutcome<S, P> {
    /// Nothing was built; the cycle stays resumable and retries next reconcile.
    Deferred {
        inputs: PublisherDiskInputs,
        decision: PublisherDiskDecision,
    },
    Built {
        inputs: PublisherDiskInputs,
        decision: PublisherDiskDecision,
        sidecars: Option<S>,
        prevalence: Option<P>,
        released_bytes: u64,
    },
}

/// Run the two mandatory builders with the disk discipline described in the
/// module docs. `build_sidecars` must publish `layout.derivatives` atomically
/// (the real builder renames its staged tree); `build_prevalence` must create
/// `layout.derivatives/prevalence-snapshot-v2`. Each receives the prior
/// derivative root to reuse, if any.
pub async fn run_publisher_build<S, SF, P, PF>(
    layout: &PublisherBuildLayout,
    limits: &PublisherDiskLimits,
    filesystem: impl Fn() -> Result<(u64, u64)>,
    on_decision: impl FnOnce(&PublisherDiskInputs, &PublisherDiskDecision),
    build_sidecars: impl FnOnce(Option<PathBuf>) -> SF,
    build_prevalence: impl FnOnce(Option<PathBuf>) -> PF,
) -> Result<PublisherBuildOutcome<S, P>>
where
    SF: Future<Output = Result<S>>,
    PF: Future<Output = Result<P>>,
{
    let inputs = measure(layout, limits, filesystem()?)?;
    let decision = decide(&inputs);
    // Reported before any build so a long build shows its decision.
    on_decision(&inputs, &decision);
    if matches!(decision, PublisherDiskDecision::Defer(_)) {
        return Ok(PublisherBuildOutcome::Deferred { inputs, decision });
    }
    let prior = layout.prior_derivatives.clone();
    let mut released_bytes = 0_u64;
    if let Some(prior) = &prior {
        if !decision.plan().keep_prior_prevalence {
            let prevalence = prior.join(PREVALENCE_MEMBER);
            released_bytes += tree_bytes(&prevalence, ByteMode::Allocated)?;
            remove_path(&prevalence)?;
        }
    }
    let sidecars = if layout.derivatives.exists() {
        None
    } else {
        Some(build_sidecars(prior.clone()).await?)
    };
    if let Some(prior) = &prior {
        released_bytes += release_prior_members(prior, &[PREVALENCE_MEMBER])?;
    }
    let prevalence = if layout.prevalence_root().exists() {
        None
    } else {
        Some(build_prevalence(prior.clone()).await?)
    };
    if let Some(prior) = &prior {
        released_bytes += release_prior_members(prior, &[])?;
    }
    if !decision.plan().keep_snapshot_data {
        released_bytes += release_snapshot_data(&layout.snapshot_root)?;
    }
    Ok(PublisherBuildOutcome::Built {
        inputs,
        decision,
        sidecars,
        prevalence,
        released_bytes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    use std::rc::Rc;

    const MIB: u64 = 1024 * 1024;

    fn write_file(path: &Path, bytes: u64) {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        // Incompressible content so allocated == logical on compressing filesystems.
        let mut state = 0x9e37_79b9_7f4a_7c15_u64 ^ bytes ^ path.as_os_str().len() as u64;
        let mut buffer = vec![0_u8; bytes as usize];
        for chunk in buffer.chunks_mut(8) {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            let word = state.to_le_bytes();
            chunk.copy_from_slice(&word[..chunk.len()]);
        }
        std::fs::write(path, buffer).unwrap();
    }

    /// Sizes (MiB) shaped like staging generation 09df2462 -> its successor,
    /// scaled 1 GiB -> 1 MiB.
    struct Shape {
        data_objects: u64,
        new_objects: u64,
        object_bytes: u64,
        entity_per_object: u64,
        uid_ledger: u64,
        fragment: u64,
        identity: u64,
        count_per_object: u64,
        prevalence_parts_per_object: u64,
        /// Window SSTs (1 MiB each). The real builder hard-links immutable
        /// SSTs and adds the changed ones; `rewrite_windows` models a builder
        /// that rewrites every window instead (worst case).
        prevalence_window_files: u64,
    }

    const SHAPE: Shape = Shape {
        data_objects: 20,
        new_objects: 3,
        object_bytes: 1,
        entity_per_object: 1, // 4.6 GiB entity
        uid_ledger: 3,
        fragment: 1,
        identity: 1,
        count_per_object: 0, // folded into entity for the scaled model
        prevalence_parts_per_object: 0,
        prevalence_window_files: 10,
    };

    struct Fixture {
        _root: tempfile::TempDir,
        layout: PublisherBuildLayout,
    }

    fn stamps(objects: u64, object_bytes: u64, snapshot_id: i64) -> serde_json::Value {
        serde_json::json!({
            "metadata_location": "s3://b/t/metadata/v1.metadata.json",
            "snapshot_id": snapshot_id,
            "table": "tenant.events",
            "objects": (0..objects).map(|index| serde_json::json!({
                "relative_path": format!("data/object-{index:04}.parquet"),
                "source_uri": format!("s3://b/t/data/object-{index:04}.parquet"),
                "version_id": "v1",
                "size_bytes": object_bytes * MIB,
                "sha256": "0".repeat(64),
            })).collect::<Vec<_>>(),
        })
    }

    /// A publisher cycle on a fresh pod: new snapshot data fully hydrated, the
    /// prior generation recovered (derivatives + stamps only, no data).
    fn fixture(shape: &Shape) -> Fixture {
        let root = tempfile::tempdir().unwrap();
        let generations = root.path().join("generations");
        let current = generations.join("snapshot-2-bbbbbbbbbbbbbbbb");
        let prior_generation = generations.join("snapshot-1-aaaaaaaaaaaaaaaa");
        let snapshot_root = current.join("snapshot");
        for index in 0..shape.data_objects {
            write_file(
                &snapshot_root.join(format!("data/object-{index:04}.parquet")),
                shape.object_bytes * MIB,
            );
        }
        std::fs::write(
            snapshot_root.join("object-stamps.json"),
            serde_json::to_vec(&stamps(shape.data_objects, shape.object_bytes, 2)).unwrap(),
        )
        .unwrap();
        let prior_objects = shape.data_objects - shape.new_objects;
        std::fs::create_dir_all(prior_generation.join("snapshot")).unwrap();
        std::fs::write(
            prior_generation.join("snapshot/object-stamps.json"),
            serde_json::to_vec(&stamps(prior_objects, shape.object_bytes, 1)).unwrap(),
        )
        .unwrap();
        let prior = prior_generation.join("derivatives-v1-0123456789abcdef");
        for index in 0..prior_objects {
            write_file(
                &prior.join(format!("entity-sidecar/object-{index:04}.parquet")),
                shape.entity_per_object * MIB,
            );
            if shape.count_per_object > 0 {
                write_file(
                    &prior.join(format!("count-rollup/object-{index:04}.parquet")),
                    shape.count_per_object * MIB,
                );
            }
            if shape.prevalence_parts_per_object > 0 {
                write_file(
                    &prior.join(format!(
                        "{PREVALENCE_MEMBER}/parts/object-{index:04}.parquet"
                    )),
                    shape.prevalence_parts_per_object * MIB,
                );
            }
        }
        write_file(&prior.join("uid-ledger/ledger.bin"), shape.uid_ledger * MIB);
        write_file(
            &prior.join("fragment-sidecar/index.bin"),
            shape.fragment * MIB,
        );
        write_file(
            &prior.join("identity-snapshot/identity.parquet"),
            shape.identity * MIB,
        );
        for index in 0..shape.prevalence_window_files {
            write_file(
                &prior.join(format!("{PREVALENCE_MEMBER}/30d/{index:04}.sst")),
                MIB,
            );
        }
        Fixture {
            layout: PublisherBuildLayout {
                generations_root: generations,
                snapshot_root,
                derivatives: current.join("derivatives-v1-0123456789abcdef"),
                prior_derivatives: Some(prior),
            },
            _root: root,
        }
    }

    fn used(layout: &PublisherBuildLayout) -> u64 {
        tree_bytes(&layout.generations_root, ByteMode::Logical).unwrap()
    }

    /// Reuse by hard link when the prior member exists, otherwise build.
    fn link_or_write(prior: Option<&Path>, relative: &str, target: &Path, bytes: u64) {
        std::fs::create_dir_all(target.parent().unwrap()).unwrap();
        match prior
            .map(|prior| prior.join(relative))
            .filter(|path| path.is_file())
        {
            Some(source) => std::fs::hard_link(source, target).unwrap(),
            None => write_file(target, bytes),
        }
    }

    /// Sidecar builder model: per-object members reuse the prior by hard link;
    /// uid-ledger, fragment and identity are rewritten (grown by the delta).
    fn fake_sidecars(
        shape: &Shape,
        layout: &PublisherBuildLayout,
        prior: Option<PathBuf>,
        peak: &Cell<u64>,
    ) {
        let staged = layout
            .derivatives
            .parent()
            .unwrap()
            .join(".generation-build-test/tree");
        for index in 0..shape.data_objects {
            let relative = format!("entity-sidecar/object-{index:04}.parquet");
            link_or_write(
                prior.as_deref(),
                &relative,
                &staged.join(&relative),
                shape.entity_per_object * MIB,
            );
            if shape.count_per_object > 0 {
                let relative = format!("count-rollup/object-{index:04}.parquet");
                link_or_write(
                    prior.as_deref(),
                    &relative,
                    &staged.join(&relative),
                    shape.count_per_object * MIB,
                );
            }
            peak.set(peak.get().max(used(layout)));
        }
        write_file(
            &staged.join("uid-ledger/ledger.bin"),
            shape.uid_ledger * MIB + MIB,
        );
        write_file(
            &staged.join("fragment-sidecar/index.bin"),
            shape.fragment * MIB,
        );
        write_file(
            &staged.join("identity-snapshot/identity.parquet"),
            shape.identity * MIB,
        );
        peak.set(peak.get().max(used(layout)));
        std::fs::rename(&staged, &layout.derivatives).unwrap();
        std::fs::remove_dir_all(staged.parent().unwrap()).unwrap();
    }

    /// Prevalence builder model: parts and immutable window SSTs reuse the
    /// prior (unless `rewrite_windows`); one new SST carries the delta.
    fn fake_prevalence(
        shape: &Shape,
        layout: &PublisherBuildLayout,
        prior: Option<PathBuf>,
        rewrite_windows: bool,
        peak: &Cell<u64>,
    ) {
        let output = layout.derivatives.join(PREVALENCE_MEMBER);
        let prior = prior.map(|prior| prior.join(PREVALENCE_MEMBER));
        for index in 0..shape.data_objects {
            if shape.prevalence_parts_per_object > 0 {
                let relative = format!("parts/object-{index:04}.parquet");
                link_or_write(
                    prior.as_deref(),
                    &relative,
                    &output.join(&relative),
                    shape.prevalence_parts_per_object * MIB,
                );
            }
        }
        for index in 0..shape.prevalence_window_files {
            let relative = format!("30d/{index:04}.sst");
            let prior = if rewrite_windows {
                None
            } else {
                prior.as_deref()
            };
            link_or_write(prior, &relative, &output.join(&relative), MIB);
            peak.set(peak.get().max(used(layout)));
        }
        write_file(&output.join("30d/delta.sst"), MIB);
        peak.set(peak.get().max(used(layout)));
    }

    fn generous() -> PublisherDiskLimits {
        PublisherDiskLimits {
            declared_volume_bytes: None,
            reserve_bytes: 0,
            upload_staging_bytes: 0,
        }
    }

    fn unbounded_filesystem() -> Result<(u64, u64)> {
        Ok((u64::MAX / 4, u64::MAX / 4))
    }

    struct Run {
        peak: u64,
        bound: u64,
        data_bytes: u64,
        generation_bytes: u64,
        delta_bytes: u64,
        prior_bytes: u64,
        decision: PublisherDiskDecision,
        layout: PublisherBuildLayout,
        _fixture: Fixture,
    }

    /// Run one fresh-pod publisher cycle (source hydrated, prior recovered
    /// without data) through the real driver with modelled builders.
    async fn run_cycle(limits: PublisherDiskLimits, rewrite_windows: bool) -> Run {
        let fixture = fixture(&SHAPE);
        let layout = fixture.layout.clone();
        let data_bytes = tree_bytes(&layout.snapshot_root.join("data"), ByteMode::Logical).unwrap();
        let prior_bytes = tree_bytes(
            layout.prior_derivatives.as_deref().unwrap(),
            ByteMode::Logical,
        )
        .unwrap();
        let peak = Rc::new(Cell::new(used(&layout)));
        let (sidecar_peak, prevalence_peak) = (peak.clone(), peak.clone());
        let (sidecar_layout, prevalence_layout) = (layout.clone(), layout.clone());
        let outcome = run_publisher_build(
            &layout,
            &limits,
            unbounded_filesystem,
            |_, _| {},
            |prior| async move {
                fake_sidecars(&SHAPE, &sidecar_layout, prior, &sidecar_peak);
                Ok(())
            },
            |prior| async move {
                fake_prevalence(
                    &SHAPE,
                    &prevalence_layout,
                    prior,
                    rewrite_windows,
                    &prevalence_peak,
                );
                Ok(())
            },
        )
        .await
        .unwrap();
        let PublisherBuildOutcome::Built { decision, .. } = outcome else {
            panic!("the cycle must build: {outcome:?}");
        };
        // Upload reads only the new tree; record that phase too.
        peak.set(peak.get().max(used(&layout)));
        let generation_bytes = tree_bytes(&layout.derivatives, ByteMode::Logical).unwrap();
        let delta_bytes = generation_bytes.saturating_sub(prior_bytes);
        Run {
            peak: peak.get(),
            bound: data_bytes + generation_bytes + delta_bytes,
            data_bytes,
            generation_bytes,
            delta_bytes,
            prior_bytes,
            decision,
            layout,
            _fixture: fixture,
        }
    }

    fn assert_within_one_generation_plus_delta(run: &Run) {
        assert!(
            run.peak <= run.bound,
            "peak {} MiB exceeds data {} + one generation {} + delta {} = {} MiB (prior {} MiB, {:?})",
            run.peak / MIB,
            run.data_bytes / MIB,
            run.generation_bytes / MIB,
            run.delta_bytes / MIB,
            run.bound / MIB,
            run.prior_bytes / MIB,
            run.decision,
        );
        // Upload holds only the new generation (plus its source when the plan
        // keeps it for the next hydration, NAN-2849): the prior is released.
        let layout = &run.layout;
        let kept = run.decision.plan().keep_snapshot_data;
        assert_eq!(layout.snapshot_root.join("data").exists(), kept);
        assert!(layout.snapshot_root.join("object-stamps.json").is_file());
        let prior = layout.prior_derivatives.as_deref().unwrap();
        assert!(prior.is_dir(), "the prior tombstone stays for resume");
        assert_eq!(std::fs::read_dir(prior).unwrap().count(), 0);
        let source = if kept { run.data_bytes } else { 0 };
        assert!(
            used(layout) <= run.generation_bytes + source + MIB,
            "only the new tree (and its kept source) remains before upload"
        );
    }

    /// NAN-2762 acceptance: an incremental publisher build with a recovered
    /// prior generation peaks at about one generation plus its delta (plus the
    /// source snapshot it must read), never at data + prior + new.
    #[tokio::test]
    async fn incremental_build_with_recovered_prior_peaks_at_one_generation_plus_delta() {
        let run = run_cycle(generous(), false).await;
        assert!(
            run.decision.plan().keep_prior_prevalence,
            "a roomy volume keeps incremental prevalence"
        );
        assert!(
            run.decision.plan().keep_snapshot_data,
            "a roomy volume keeps the source for the next hydration (NAN-2849)"
        );
        assert_within_one_generation_plus_delta(&run);
    }

    /// Worst case: prevalence rewrites every window, and the volume is sized to
    /// exactly one generation plus its delta (plus source). The budget must drop
    /// the prior prevalence rather than overrun the volume.
    #[tokio::test]
    async fn full_window_rewrite_on_a_one_generation_volume_drops_prior_prevalence_and_fits() {
        // data 20 + generation 37 + delta 5 MiB for SHAPE, plus directory slack.
        let limits = PublisherDiskLimits {
            declared_volume_bytes: Some(64 * MIB),
            reserve_bytes: 0,
            upload_staging_bytes: 0,
        };
        let run = run_cycle(limits, true).await;
        assert!(!run.decision.plan().keep_prior_prevalence);
        assert!(
            run.peak <= 64 * MIB,
            "peak {} MiB exceeds the volume",
            run.peak / MIB
        );
        assert_within_one_generation_plus_delta(&run);
    }

    #[tokio::test]
    async fn a_build_that_cannot_fit_defers_before_building() {
        let fixture = fixture(&SHAPE);
        let layout = fixture.layout.clone();
        let used_now = tree_bytes(&layout.generations_root, ByteMode::Allocated).unwrap();
        let limits = PublisherDiskLimits {
            declared_volume_bytes: Some(used_now + MIB),
            reserve_bytes: 0,
            upload_staging_bytes: 0,
        };
        let built = Cell::new(false);
        let outcome = run_publisher_build(
            &layout,
            &limits,
            unbounded_filesystem,
            |_, _| {},
            |_| async {
                built.set(true);
                Ok(())
            },
            |_| async {
                built.set(true);
                Ok(())
            },
        )
        .await
        .unwrap();
        assert!(matches!(outcome, PublisherBuildOutcome::Deferred { .. }));
        assert!(!built.get());
        // Deferral destroys nothing: the cycle stays resumable.
        assert!(layout.snapshot_root.join("data").is_dir());
        assert!(layout
            .prior_derivatives
            .as_deref()
            .unwrap()
            .join(PREVALENCE_MEMBER)
            .is_dir());
    }

    fn inputs() -> PublisherDiskInputs {
        const GIB: u64 = 1024 * MIB;
        // staging 2026-09-24 09:09Z, fresh pod, 48 GiB emptyDir, 1 GiB reserve.
        PublisherDiskInputs {
            used_bytes: 40 * GIB,
            limit_bytes: 47 * GIB,
            capacity_bytes: 48 * GIB,
            reserve_bytes: GIB,
            filesystem_available_bytes: 27 * GIB,
            snapshot_data_bytes: 17 * GIB,
            source_bytes: 18 * GIB,
            has_prior: true,
            prior_sidecar_bytes: 13 * GIB,
            prior_prevalence_bytes: 10 * GIB,
            // entity 4.6 + keyword 3.0 + count-rollup 1.5 GiB, almost all retained.
            reusable_sidecar_bytes: 9 * GIB,
            reusable_prevalence_bytes: GIB,
            growth_ratio: 1.17,
            sidecars_built: false,
            prevalence_built: false,
            upload_staging_bytes: 2 * GIB,
        }
    }

    #[test]
    fn staging_shape_drops_the_prior_prevalence_instead_of_being_evicted() {
        let decision = decide(&inputs());
        let PublisherDiskDecision::Proceed(plan) = decision else {
            panic!("staging shape must proceed without the prior prevalence: {decision:?}");
        };
        assert!(!plan.keep_prior_prevalence);
        assert!(plan.projected_peak_bytes <= plan.limit_bytes);
    }

    #[test]
    fn roomy_volume_keeps_the_prior_prevalence() {
        let mut roomy = inputs();
        roomy.limit_bytes = 127 * 1024 * MIB;
        let PublisherDiskDecision::Proceed(plan) = decide(&roomy) else {
            panic!()
        };
        assert!(plan.keep_prior_prevalence);
        assert!(plan.keep_snapshot_data);
    }

    /// NAN-2849: keeping the source through upload costs its bytes at the
    /// upload peak. A volume that fits the build but not that releases the
    /// source before upload (the NAN-2762 flow) rather than deferring or
    /// dropping the prior prevalence.
    #[test]
    fn a_volume_without_room_for_the_source_at_upload_releases_it_before_upload() {
        let mut shape = inputs();
        shape.limit_bytes = 127 * 1024 * MIB;
        // In the staging shape the build peak dominates, so keeping the
        // source is free at the projected peak (asserted below). A wide upload
        // makes the upload phase the peak.
        let free = project(&shape, true, true);
        assert_eq!(
            free.projected_peak_bytes,
            project(&shape, true, false).projected_peak_bytes
        );
        shape.upload_staging_bytes = 30 * 1024 * MIB;
        let keep = project(&shape, true, true);
        let release = project(&shape, true, false);
        assert_eq!(
            keep.upload_peak_bytes - release.upload_peak_bytes,
            shape.snapshot_data_bytes,
            "keeping the source charges exactly its bytes at upload"
        );
        assert!(release.projected_peak_bytes < keep.projected_peak_bytes);
        shape.limit_bytes = release.projected_peak_bytes;
        let PublisherDiskDecision::Proceed(plan) = decide(&shape) else {
            panic!("the release plan fits exactly")
        };
        assert!(plan.keep_prior_prevalence);
        assert!(!plan.keep_snapshot_data);
    }

    /// NAN-2849 overlap: the prior source stays through hydration only when a
    /// worst-case full download (nothing reusable, +25%) still fits beside it.
    #[test]
    fn hydration_keeps_the_prior_source_only_when_a_full_download_fits_beside_it() {
        let fixture = fixture(&SHAPE);
        // Use the current snapshot as the "prior" of the next hydration: it
        // has data (20 MiB) and matching stamps.
        let prior = &fixture.layout.snapshot_root;
        let generations = &fixture.layout.generations_root;
        let used_now = tree_bytes(generations, ByteMode::Allocated).unwrap();
        let data = tree_bytes(&prior.join("data"), ByteMode::Allocated).unwrap();
        let worst = scaled(
            SHAPE.data_objects * SHAPE.object_bytes * MIB,
            HYDRATION_GROWTH_ALLOWANCE,
        )
        .max(scaled(data, HYDRATION_GROWTH_ALLOWANCE));
        let roomy = PublisherDiskLimits {
            declared_volume_bytes: Some(used_now + worst),
            reserve_bytes: 0,
            upload_staging_bytes: 0,
        };
        let plan =
            plan_hydration_reuse(generations, prior, &roomy, (u64::MAX / 4, u64::MAX / 4)).unwrap();
        assert!(plan.reuse, "{plan:?}");
        assert_eq!(plan.prior_data_bytes, data);
        assert_eq!(plan.projected_peak_bytes, used_now + worst);
        let tight = PublisherDiskLimits {
            declared_volume_bytes: Some(used_now + worst - 1),
            ..roomy
        };
        let plan =
            plan_hydration_reuse(generations, prior, &tight, (u64::MAX / 4, u64::MAX / 4)).unwrap();
        assert!(
            !plan.reuse,
            "a full download beside the prior would overrun"
        );
        // Free space bounds it too, whatever the declared volume.
        let plan =
            plan_hydration_reuse(generations, prior, &roomy, (u64::MAX / 4, worst - 1)).unwrap();
        assert!(!plan.reuse);
        // A prior with no source (recovered bundle) is never "reused".
        let recovered = fixture
            .layout
            .prior_derivatives
            .as_deref()
            .unwrap()
            .parent()
            .unwrap()
            .join("snapshot");
        let plan = plan_hydration_reuse(
            generations,
            &recovered,
            &roomy,
            (u64::MAX / 4, u64::MAX / 4),
        )
        .unwrap();
        assert_eq!(plan.prior_data_bytes, 0);
        assert!(!plan.reuse);
    }

    #[test]
    fn filesystem_free_space_bounds_the_limit() {
        let fixture = fixture(&SHAPE);
        let limits = PublisherDiskLimits {
            declared_volume_bytes: Some(1 << 40),
            reserve_bytes: MIB,
            upload_staging_bytes: 0,
        };
        let measured = measure(&fixture.layout, &limits, (1 << 41, 4 * MIB)).unwrap();
        assert_eq!(measured.capacity_bytes, 1 << 40);
        assert_eq!(measured.limit_bytes, measured.used_bytes + 3 * MIB);
        assert!(measured.growth_ratio > 1.0);
    }

    #[test]
    fn dead_upload_staging_is_swept_but_generation_files_are_not() {
        let fixture = fixture(&SHAPE);
        let generation = fixture.layout.snapshot_root.parent().unwrap();
        write_file(
            &generation.join(".nano-generation-bundle-archive-abc123"),
            MIB,
        );
        write_file(&generation.join(".tmpXYZ"), MIB);
        write_file(
            &generation.join("bundle-publisher-checkpoint-v1-0123456789abcdef.json"),
            1,
        );
        let (removed, bytes) =
            sweep_dead_publisher_staging(&fixture.layout.generations_root).unwrap();
        assert_eq!(removed, 2);
        assert!(bytes >= 2 * MIB);
        assert!(generation
            .join("bundle-publisher-checkpoint-v1-0123456789abcdef.json")
            .is_file());
        assert!(fixture.layout.snapshot_root.join("data").is_dir());
    }
}
