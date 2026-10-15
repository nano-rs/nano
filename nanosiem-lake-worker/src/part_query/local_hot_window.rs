// SPDX-License-Identifier: AGPL-3.0-or-later
//! Background residency over signed part membership; no native statements.
use super::engine::{map_fetch_error, PartQueryEngine, QueryResult};
use super::fetch::PartFile;
use crate::parts::provenance::{PartialKind, ProvenanceRecord};
use std::time::Duration;
// Tokio's clock (std's in production): the pass timings and rate it reports
// follow a paused test runtime, like the pacing sleeps they measure (NAN-3866).
use tokio::time::Instant;

/// Partials hydrated with their part. Rollup-eligible stats and timechart
/// steps read the rollup partial of every part in range; leaving it to the
/// query path cost ~2.9 s of R2 fetches per cold stats step (NAN-3180).
/// Entity pivots (`host=`, `src_endpoint.ip=`, hash equality) seed their
/// progressive walk from the entity-ranges partial of the newest parts
/// (NAN-3158 density); left to queries it was the first object evicted
/// under hot-window pressure, so a settled cell refetched it from R2.
const RESIDENT_PARTIALS: &[PartialKind] = &[PartialKind::Rollup, PartialKind::EntityRanges];

/// NAN-3714: the longest standard search range (30 days). A count or
/// timechart over it plans from the [`RESIDENT_PARTIALS`] of every part in
/// range, so those partials (only: no data files) are kept resident for every
/// live part this old, beyond the hot window's own hours. At Ready they were
/// in R2 for every part older than the window: the first 30 d `stats count`
/// on tenant-a after a roll fetched 27 rollups (4.0 s of a 4.3 s search).
pub const PLAN_HOURS: u64 = 720;

/// NAN-3714: how far into the window from its oldest edge the warm-up
/// hydrates part data before latching warm. A count over the hot window's
/// own range (168 h, the 7 d search) answers the ragged five minutes at its
/// start from the data files there; the pass fills the window newest first,
/// so at Ready those were the last parts in line and the first 7 d count read
/// them from R2 (6.4 s of a 7.8 s search). One hour covers the edge as it
/// moves forward until the post-Ready pass reaches it (tenant-a: ~20 min).
pub const EDGE_US: i64 = 3_600_000_000;

/// The partials a part outside the hot window but inside [`PLAN_HOURS`]
/// keeps resident.
fn plan_files(record: &ProvenanceRecord) -> Vec<(PartFile, &str, u64)> {
    RESIDENT_PARTIALS
        .iter()
        .filter_map(|kind| {
            let file = PartFile::Partial(*kind);
            super::fetch::file_digest(record, file).map(|(_, digest, bytes)| (file, digest, bytes))
        })
        .collect()
}

/// Every object of `record` the hot window keeps resident: each data file
/// with its token index, then the partials in [`RESIDENT_PARTIALS`] that the
/// part carries. (file, sha256, bytes) per object, in hydration order.
///
/// The token index is read for every candidate file by bareword keywords and
/// by hash-array equality (`process.file.hashes.value=…`, `prune::uses_tokens`)
/// before any data is opened. Unlike the entity sidecars (skipped once the
/// data file is resident, NAN-3165), it is never answered from the data file,
/// and as a non-hot object it was evicted first: a cold 24 h hash pivot on a
/// settled cell missed 121 of 167 objects and spent 2.3 s in fetches.
fn resident_files(record: &ProvenanceRecord) -> Vec<(PartFile, &str, u64)> {
    (0..record.files.data.len())
        .flat_map(|index| [PartFile::Data(index), PartFile::Tokens(index)])
        .chain(RESIDENT_PARTIALS.iter().map(|kind| PartFile::Partial(*kind)))
        .filter_map(|file| {
            super::fetch::file_digest(record, file).map(|(_, digest, bytes)| (file, digest, bytes))
        })
        .collect()
}

/// The pass's (part index, file) downloads. Default: part by part, in index
/// order (newest first; the plan-only parts of [`PLAN_HOURS`] last).
/// `partials_first` (NAN-3690): every part's [`RESIDENT_PARTIALS`] first,
/// then (NAN-3714) the rest of the `edge` parts, then the rest part by part.
/// The pass completes downloads in this order, so once any part counts as
/// resident every part's partials and the window's oldest edge are local.
fn hydration_jobs(
    resident: Vec<Vec<PartFile>>,
    edge: &std::collections::BTreeSet<usize>,
    partials_first: bool,
) -> Vec<(usize, PartFile)> {
    let all = resident
        .into_iter()
        .enumerate()
        .flat_map(|(index, files)| files.into_iter().map(move |file| (index, file)));
    if !partials_first {
        return all.collect();
    }
    let (mut partials, rest): (Vec<_>, Vec<_>) = all.partition(|(_, file)| matches!(file, PartFile::Partial(_)));
    let (edge, rest): (Vec<_>, Vec<_>) = rest.into_iter().partition(|(index, _)| edge.contains(index));
    partials.extend(edge);
    partials.extend(rest);
    partials
}

/// NAN-3714: run once by a pass right before it latches warm, with every
/// live part of [`PLAN_HOURS`] (their [`RESIDENT_PARTIALS`] are local by
/// then). The engine fills its in-memory plan state (count-rollup source
/// summaries) here, so the pod does not report warm before it is.
pub(super) type BeforeWarm<'a> =
    dyn Fn(Vec<crate::parts::part_log::PartRef>) -> futures::future::BoxFuture<'a, ()> + Send + Sync + 'a;

/// Bytes a part occupies in the hot window: admission, budget and progress
/// all count the same set of objects, so "window warm" means rollups too.
fn resident_bytes(record: &ProvenanceRecord) -> u64 {
    resident_files(record).iter().map(|(_, _, bytes)| bytes).sum()
}

impl PartQueryEngine {
    /// Storage-only background hydration: newest first, a bounded number of
    /// signed objects in flight under one shared rate cap (NAN-3164), never
    /// holding the discovery mutex during downloads or pacing sleeps.
    pub async fn hydrate_hot_window(
        &self,
        inflight: &std::sync::atomic::AtomicU64,
    ) -> QueryResult<()> {
        if self.fetcher().hot_settings.is_none() {
            return Ok(());
        }
        let pass_started = Instant::now();
        self.refresh().await?;
        let parts = self.hot_live_parts().await;
        let before_warm = self.before_warm_hook();
        hydrate_with(
            self.fetcher(),
            &self.settings().tenant_id,
            parts,
            inflight,
            pass_started,
            &before_warm,
        )
        .await
    }

    fn before_warm_hook<'a>(&'a self) -> impl Fn(Vec<crate::parts::part_log::PartRef>) -> futures::future::BoxFuture<'a, ()> + Send + Sync + 'a {
        move |parts| Box::pin(self.prewarm_plan_memo(parts))
    }

    /// NAN-3714: the count-rollup source summaries (what `* | stats count`,
    /// source histograms and timecharts read per part, NAN-3093) of every
    /// part of [`PLAN_HOURS`], before the pod reports warm. In hot-window
    /// mode the arrival prewarm never reads a rollup (its budget is zero), so
    /// at Ready the memo was empty and the first 7 d count read and folded
    /// 144 local rollups (~1.1 s) that a settled cell answers from memory.
    /// Rollups only (already local): ~1-2 s of one native lane per deny set.
    /// Best effort: a failure is logged and queries fill the memo.
    async fn prewarm_plan_memo(&self, parts: Vec<crate::parts::part_log::PartRef>) {
        let started = Instant::now();
        let Ok(_slot) = self.admission.clone().acquire_owned().await else { return };
        match super::partials::prewarm_source_summaries(self, &parts).await {
            Ok(()) => tracing::info!(
                parts = parts.len(),
                seconds = started.elapsed().as_secs_f64(),
                "count-rollup source summaries prewarmed before warm"
            ),
            Err(error) => tracing::warn!(%error, "count-rollup source summaries not prewarmed before warm; queries fill them"),
        }
    }
}

// Keep the storage-only pass independent of native executors so the lab can
// exercise the same signed-object downloads and volume admission as production.
#[cfg(test)]
async fn hydrate(
    fetcher: &super::fetch::PartFetcher,
    tenant: &str,
    parts: Vec<crate::parts::part_log::PartRef>,
    inflight: &std::sync::atomic::AtomicU64,
    pass_started: Instant,
) -> QueryResult<()> {
    hydrate_with(fetcher, tenant, parts, inflight, pass_started, &|_| Box::pin(async {})).await
}

async fn hydrate_with(
    fetcher: &super::fetch::PartFetcher,
    tenant: &str,
    parts: Vec<crate::parts::part_log::PartRef>,
    inflight: &std::sync::atomic::AtomicU64,
    pass_started: Instant,
    before_warm: &BeforeWarm<'_>,
) -> QueryResult<()> {
    use crate::local_hot_window::{select, Bucket, Coverage};
    let Some(settings) = &fetcher.hot_settings else {
        return Ok(());
    };
    let now = pass_now_us();
    let cutoff = now.saturating_sub(
        i64::try_from(settings.hours)
            .unwrap_or(i64::MAX)
            .saturating_mul(3_600_000_000),
    );
    // NAN-3714: parts this old keep their plan partials resident.
    let plan_cutoff = now.saturating_sub(
        i64::try_from(settings.hours.max(PLAN_HOURS))
            .unwrap_or(i64::MAX)
            .saturating_mul(3_600_000_000),
    );
    let mut candidates = Vec::new();
    let mut plan_only = Vec::new();
    let live = parts
        .iter()
        .map(|p| p.part_id.to_string())
        .collect::<std::collections::BTreeSet<_>>();
    let mut live_digests = std::collections::HashSet::new();
    let mut membership = if settings.persistent {
        crate::local_hot_window::load_membership_or_reset(&settings.root, tenant)
    } else {
        crate::local_hot_window::load_membership(&settings.root, tenant)
    }
    .map_err(map_fetch_error)?;
    let mut sorted = parts;
    sorted.sort_by_key(|part| std::cmp::Reverse(part.max_time_us));
    // Fetch out-of-window provenance only when a pending retirement needs
    // proof that its digest is not shared by a newly discovered live part.
    let reconcile = membership.keys().any(|id| !live.contains(id));
    let mut to_read = Vec::new();
    for part in sorted {
        if !part.overlaps(cutoff, now) && !part.overlaps(plan_cutoff, now) {
            if let Some(digests) = membership.get(&part.part_id.to_string()) {
                live_digests.extend(digests.iter().cloned());
                continue;
            }
            if !reconcile {
                continue;
            }
        }
        to_read.push(part);
    }
    // Signed provenance is small, but serial remote round trips over a
    // multi-day window can spend minutes before the first data download.
    // Preserve newest-first order while bounding metadata requests.
    use futures::StreamExt;
    let mut records = futures::stream::iter(to_read.into_iter().map(|part| async move {
        let record = fetcher.record(&part).await.map_err(map_fetch_error)?;
        Ok::<_, super::engine::PartQueryError>((part, record))
    }))
    .buffered(8);
    while let Some(result) = records.next().await {
        let (part, record) = result?;
        let digests = record
            .files
            .all()
            .iter()
            .map(|(_, digest, _)| digest.to_string())
            .collect::<Vec<_>>();
        live_digests.extend(digests.iter().cloned());
        membership
            .entry(part.part_id.to_string())
            .or_insert(digests);
        if !part.overlaps(cutoff, now) {
            if part.overlaps(plan_cutoff, now) {
                plan_only.push((part.max_time_us, (part, record)));
            }
            continue;
        }
        let bytes = resident_bytes(&record);
        candidates.push((part.max_time_us, bytes, (part, record)));
    }
    for (id, digests) in fetcher.local_range_membership() {
        live_digests.extend(digests.iter().cloned());
        let entry = membership.entry(id).or_default();
        entry.extend(digests);
        entry.sort();
        entry.dedup();
    }
    let removed = crate::local_hot_window::retired(&membership, &live, &live_digests);
    let deferred = fetcher
        .cache()
        .evict_unleased(removed)
        .await
        .map_err(|e| map_fetch_error(e.into()))?;
    membership
        .retain(|id, digests| live.contains(id) || digests.iter().any(|d| deferred.contains(d)));
    crate::local_hot_window::save_membership(&settings.root, tenant, &membership)
        .map_err(map_fetch_error)?;
    // Restore chronological hot membership before trimming, including after
    // restart. Fully warm windows must also shrink as ingest/scratch grows.
    let mut all_hot = std::collections::HashMap::new();
    for (end, _, (_, record)) in &candidates {
        for (_, digest, _) in resident_files(record) {
            all_hot.insert(digest.to_string(), *end);
        }
    }
    for (end, (_, record)) in &plan_only {
        for (_, digest, _) in plan_files(record) {
            all_hot.insert(digest.to_string(), *end);
        }
    }
    // NAN-3647: a persistent (A/B) volume carries the cache of the roll before
    // last. Objects are content-addressed (signed sha256 + size, checked on
    // every hit), so whatever the current catalog still references is reused
    // as is; once per process, drop everything it no longer references
    // (merged-away parts, retired partials, old cold fetches) instead of
    // leaving it to pressure eviction.
    if settings.persistent && !fetcher.hot_reconciled.swap(true, std::sync::atomic::Ordering::Relaxed) {
        let keep = live_digests.iter().chain(all_hot.keys()).cloned().collect::<std::collections::HashSet<_>>();
        let (objects, bytes) = fetcher
            .cache()
            .evict_unreferenced(keep)
            .await
            .map_err(|e| map_fetch_error(e.into()))?;
        let stats = fetcher.cache().stats();
        tracing::info!(evicted_objects = objects, evicted_bytes = bytes, reused_objects = stats.objects,
            reused_bytes = stats.stored_bytes, "persistent hot-window volume reconciled against the live catalog");
    }
    fetcher.cache().set_hot(all_hot);
    fetcher
        .cache()
        .trim_pressure()
        .await
        .map_err(|e| map_fetch_error(e.into()))?;
    let capacity = settings
        .capacity(fetcher.cache().stats().stored_bytes)
        .map_err(map_fetch_error)?;
    // Retain space for on-demand signed ranges and older queries.
    let target = capacity
        .min(fetcher.cache().stats().max_bytes)
        .saturating_sub(fetcher.cache().query_max_bytes());
    let mut buckets = [
        Bucket {
            hours: 1,
            ..Default::default()
        },
        Bucket {
            hours: 24,
            ..Default::default()
        },
        Bucket {
            hours: settings.hours,
            ..Default::default()
        },
    ];
    for (end, bytes, _) in &candidates {
        for bucket in &mut buckets {
            if *end
                >= now.saturating_sub(
                    i64::try_from(bucket.hours)
                        .unwrap_or(i64::MAX)
                        .saturating_mul(3_600_000_000),
                )
            {
                bucket.total_parts += 1;
                bucket.total_bytes += bytes;
            }
        }
    }
    let selected = select(candidates, cutoff, target);
    let previous = fetcher
        .hot_coverage
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone();
    let (previous_hours, previously_warm) = (previous.effective_hours, previous.warm);
    let schedule = &settings.schedule;
    let warm_cutoff = now.saturating_sub(
        i64::try_from(schedule.warm_hours)
            .unwrap_or(i64::MAX)
            .saturating_mul(3_600_000_000),
    );
    let mut hot = std::collections::HashMap::new();
    let mut coverage = Coverage {
        capacity_bytes: target,
        configured_hours: settings.hours,
        buckets,
        discovery_seconds: pass_started.elapsed().as_secs_f64(),
        warm_hours: schedule.warm_hours,
        // Latched: a later pass recounting from zero must not withdraw warm.
        warm_resident: previous.warm_resident,
        // NAN-3647: the warm-up fan-out until the warm hours are resident (gate on only).
        concurrency: schedule.pass_concurrency(previous.warm_resident),
        ..Default::default()
    };
    for (end, bytes, (_, record)) in &selected {
        coverage.selected_bytes += bytes;
        coverage.selected_parts += 1;
        for (_, digest, _) in resident_files(record) {
            hot.insert(digest.to_string(), *end);
        }
    }
    for (end, (_, record)) in &plan_only {
        for (_, digest, _) in plan_files(record) {
            hot.insert(digest.to_string(), *end);
        }
    }
    let selected_ends = selected.iter().map(|(end, _, _)| *end).collect::<Vec<_>>();
    coverage.rate_cap_bytes_per_second =
        crate::local_hot_window::hydrate_rate(settings.bytes_per_second, coverage.selected_bytes);
    fetcher.cache().set_hot(hot);
    let started = Instant::now();
    let rate_cap = coverage.rate_cap_bytes_per_second;
    let mut last_log = Instant::now();
    coverage.update_progress(0.0);
    if !previously_warm {
        coverage.log_progress();
    }
    // NAN-3164: newest first, `concurrency` objects in flight, one token
    // bucket for the pass. `buffered` keeps completions in selection order,
    // so part/bucket accounting and the warm prefix stay exact.
    // NAN-3647: with the warm gate on, the pass runs at the warm-up cap until
    // the warm hours are resident (the pod is not Ready, nothing competes).
    let cap_for = |warm: bool| if warm { rate_cap } else { schedule.cap_before_warm(rate_cap) };
    let bucket = crate::reader_object_cache::HydrateBucket::new(cap_for(coverage.warm_resident));
    let pass_concurrency = coverage.concurrency;
    let warm_flag = std::sync::atomic::AtomicBool::new(coverage.warm_resident);
    let share = (rate_cap
        / (schedule.concurrency.max(1) as u64).saturating_mul(schedule.query_backoff.max(1)))
    .max(1);
    // Indexes [0, selected.len()) are the selected parts, newest first; the
    // NAN-3714 plan-only parts (partials only) follow.
    let targets = selected
        .iter()
        .map(|(_, _, (part, record))| (part, record))
        .chain(plan_only.iter().map(|(_, (part, record))| (part, record)))
        .collect::<Vec<_>>();
    let resident = selected
        .iter()
        .map(|(_, _, (_, record))| resident_files(record).into_iter().map(|(file, _, _)| file).collect::<Vec<_>>())
        .chain(plan_only.iter().map(|(_, (_, record))| plan_files(record).into_iter().map(|(file, _, _)| file).collect()))
        .collect::<Vec<_>>();
    let mut remaining = resident.iter().map(Vec::len).collect::<Vec<_>>();
    // NAN-3714: the selected parts at the window's oldest edge (the 7 d
    // count's ragged start), and every part whose download must finish before
    // a gated pass latches warm: those, and all plan-only partials.
    let edge_cutoff = cutoff.saturating_add(EDGE_US);
    let edge = selected
        .iter()
        .enumerate()
        .filter(|(_, (_, _, (part, _)))| part.min_time_us <= edge_cutoff)
        .map(|(index, _)| index)
        .collect::<std::collections::BTreeSet<_>>();
    let before_latch = if schedule.warm_gate {
        edge.iter().copied().chain(selected.len()..targets.len()).collect::<Vec<_>>()
    } else {
        Vec::new()
    };
    let plan_parts = targets.iter().map(|(part, _)| (*part).clone()).collect::<Vec<_>>();
    // NAN-3690: with the warm gate, a pass that starts before warm fetches
    // every part's partials first (they are small and what summary searches
    // over the whole window read), then (NAN-3714) the window's oldest edge.
    let jobs = hydration_jobs(resident, &edge, schedule.partials_first(coverage.warm_resident));
    struct Outcome {
        index: usize,
        size: u64,
        hit: bool,
        lookup_seconds: f64,
        fetch_seconds: f64,
        result: Result<(), String>,
    }
    let (targets_ref, bucket_ref, warm_ref) = (&targets, &bucket, &warm_flag);
    let fetches = futures::stream::iter(jobs.into_iter().map(|(index, file)| async move {
        let (part, record) = targets_ref[index];
        // Residency is for data files, their token indexes and the
        // RESIDENT_PARTIALS. Entity/UID blooms, locators, ranges and the
        // other partials are fetched by the query paths that read them.
        let (_, digest, size) = super::fetch::file_digest(record, file).expect("selected file");
        let object = crate::reader_object_cache::ReaderObjectRef {
            range: None,
            source_uri: fetcher.file_uri(part, record, file).map_err(map_fetch_error)?,
            sha256: digest.to_string(),
            size_bytes: size,
        };
        let lookup_started = Instant::now();
        let hit = fetcher
            .cache()
            .is_local(&object)
            .await
            .map_err(|e| map_fetch_error(e.into()))?;
        let lookup_seconds = lookup_started.elapsed().as_secs_f64();
        if hit {
            return Ok::<_, super::engine::PartQueryError>(Outcome {
                index, size, hit, lookup_seconds, fetch_seconds: 0.0, result: Ok(()),
            });
        }
        let warm = warm_ref.load(std::sync::atomic::Ordering::Relaxed);
        bucket_ref.set_rate(crate::local_hot_window::effective_rate(
            cap_for(warm),
            inflight.load(std::sync::atomic::Ordering::Relaxed) > 0,
            warm,
            schedule.query_backoff,
        ));
        let fetch_started = Instant::now();
        // One signed object, bounded by total cache capacity, not the query budget.
        let result = crate::reader_object_cache::background_hydrate_shared(
            bucket_ref.clone(),
            share,
            fetcher.hydrate_object(&object),
        )
        .await
        .map(drop)
        .map_err(|error| error.to_string());
        Ok(Outcome {
            index, size, hit, lookup_seconds,
            fetch_seconds: fetch_started.elapsed().as_secs_f64(),
            result,
        })
    }))
    .buffered(pass_concurrency);
    tokio::pin!(fetches);
    let mut completed_prefix = 0_usize;
    loop {
        // Parts whose every object is resident, in selection order.
        while completed_prefix < selected.len() && remaining[completed_prefix] == 0 {
            let (end, bytes, (part, _)) = &selected[completed_prefix];
            for bucket in &mut coverage.buckets {
                if *end
                    >= now.saturating_sub(
                        i64::try_from(bucket.hours)
                            .unwrap_or(i64::MAX)
                            .saturating_mul(3_600_000_000),
                    )
                {
                    bucket.local_parts += 1;
                    bucket.local_bytes += bytes;
                }
            }
            coverage.local_parts += 1;
            coverage.effective_hours = (now.saturating_sub(part.min_time_us).max(0) as f64
                / 3_600_000_000.0)
                .min(settings.hours as f64);
            completed_prefix += 1;
        }
        if !coverage.warm_resident
            && crate::local_hot_window::warm_window_resident(&selected_ends, completed_prefix, warm_cutoff)
            // NAN-3714: and the long-range plan metadata and the oldest edge.
            && before_latch.iter().all(|index| remaining[*index] == 0)
        {
            // NAN-3690: this pass's catalog is as old as its discovery; the
            // writer kept committing (and merging) the newest hours while it
            // ran. Rediscover once and refill them before reporting warm.
            if schedule.rediscover_before_latch(fetcher.hot_caught_up.swap(true, std::sync::atomic::Ordering::Relaxed)) {
                tracing::info!(
                    warm_hours = schedule.warm_hours,
                    bytes_resident = coverage.local_bytes,
                    parts_resident = coverage.local_parts,
                    edge_parts = edge.len(),
                    plan_parts = plan_only.len(),
                    hydrate_seconds = started.elapsed().as_secs_f64(),
                    "local hot-window warm hours resident; rediscovering once before reporting warm"
                );
                fetcher.request_hot_rerun();
                break;
            }
            before_warm(plan_parts.clone()).await;
            coverage.warm_resident = true;
            warm_flag.store(true, std::sync::atomic::Ordering::Relaxed);
            tracing::info!(
                warm_hours = schedule.warm_hours,
                bytes_resident = coverage.local_bytes,
                parts_resident = coverage.local_parts,
                edge_parts = edge.len(),
                plan_parts = plan_only.len(),
                hydrate_seconds = started.elapsed().as_secs_f64(),
                "local hot-window warm hours resident"
            );
        }
        coverage.update_progress(started.elapsed().as_secs_f64());
        *fetcher
            .hot_coverage
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = coverage.clone();
        let next = tokio::select! {
            next = fetches.next() => next,
            _ = tokio::time::sleep_until(last_log + Duration::from_secs(60)) => {
                coverage.log_progress();
                last_log = Instant::now();
                continue;
            }
        };
        let Some(outcome) = next else { break };
        let outcome = outcome?;
        if outcome.index >= selected.len() {
            // NAN-3714: a plan-only partial, outside the window's coverage.
            if let Err(error) = outcome.result {
                tracing::warn!(%error, "plan partial deferred");
                break;
            }
            remaining[outcome.index] -= 1;
            continue;
        }
        coverage.lookup_seconds += outcome.lookup_seconds;
        if outcome.hit {
            coverage.cache_hit_objects += 1;
        } else {
            coverage.cache_miss_objects += 1;
            coverage.fetch_seconds += outcome.fetch_seconds;
            if let Err(error) = outcome.result {
                coverage.deferred_objects += 1;
                tracing::warn!(%error, "hot-window object deferred");
                break;
            }
            coverage.hydrate_bytes += outcome.size;
        }
        coverage.local_bytes += outcome.size;
        remaining[outcome.index] -= 1;
    }
    coverage.update_progress(started.elapsed().as_secs_f64());
    if coverage.effective_hours < previous_hours {
        tracing::info!(
            covered_hours = coverage.effective_hours,
            previous_hours,
            "local hot-window shrunk under volume pressure"
        );
    }
    *fetcher
        .hot_coverage
        .lock()
        .unwrap_or_else(|e| e.into_inner()) = coverage.clone();
    if coverage.warm && !previously_warm {
        coverage.log_progress();
        tracing::info!(
            covered_hours = coverage.effective_hours,
            bytes_resident = coverage.local_bytes,
            parts_resident = coverage.local_parts,
            "local hot-window window warm"
        );
    }
    Ok(())
}

/// The event-time "now" a pass selects its window from: the wall clock. A
/// test pins it to its fixture's "now" (NAN-3866), so fixture and pass agree
/// on the current hour even when a run straddles an hour (or day) rollover.
fn pass_now_us() -> i64 {
    #[cfg(test)]
    if let Some(now) = tests::PINNED_NOW_US.with(std::cell::Cell::get) {
        return now;
    }
    chrono::Utc::now().timestamp_micros()
}

#[cfg(test)]
mod tests {
    std::thread_local! {
        /// libtest runs each test on its own thread, and every test awaits
        /// its fixtures and passes on that thread (the runtime's main task).
        pub(super) static PINNED_NOW_US: std::cell::Cell<Option<i64>> = const { std::cell::Cell::new(None) };
    }
    /// This test's event-time "now": the wall clock at first use, then fixed
    /// for every later fixture and hydration pass of the test.
    fn pinned_now() -> i64 {
        PINNED_NOW_US.with(|pinned| {
            let now = pinned.get().unwrap_or_else(|| chrono::Utc::now().timestamp_micros());
            pinned.set(Some(now));
            now
        })
    }
    use super::super::fetch::{parts_key_prefix, PartFetcher, StoreObjectSource};
    use super::super::log_view::PartLogView;
    use super::*;
    use crate::parts::format::{PartId, PartKeys};
    use crate::parts::part_log::{LocalObjectStore, LogOp, ObjectStore, PartLogWriter, PartRef};
    use crate::parts::provenance::{
        tests::{sample_record, signer, TENANT},
        LocalPartSigner,
        FileDigest, InputPart, PartInputs, PartSigner, PartialDigest, PartialKind,
        SignedProvenance,
    };
    use crate::parts::{sha256_hex, Level};
    use crate::reader_object_cache::{ReaderObjectCache, ReaderObjectCacheSettings};
    use std::sync::{atomic::AtomicU64, Arc};

    // Four days of hourly L0 -> minute -> hour replacements. Objects from
    // every level remain in storage (GC off); creation time is always NOW,
    // including old-event-time reindex output. Large locator inventories
    // model the sidecar amplification without needing native statements.
    #[tokio::test]
    async fn multiday_multilevel_hydration_tracks_live_event_window() {
        let root = tempfile::tempdir().unwrap();
        let source = root.path().join("objects");
        let store = Arc::new(LocalObjectStore::new(&source).unwrap());
        let signer = signer(7);
        let schema = arrow_schema::Schema::new(vec![arrow_schema::Field::new(
            "time",
            arrow_schema::DataType::Timestamp(arrow_schema::TimeUnit::Microsecond, None),
            false,
        )]);
        let now = pinned_now();
        let hour_us = 3_600_000_000_i64;
        let current_hour = now.div_euclid(hour_us);
        let created = now / 1000;
        let mut serial = 0_u64;
        let mut writer = PartLogWriter::open(store.as_ref(), TENANT, 1, &schema, created)
            .await
            .unwrap();
        let mut inventories = Vec::new();
        let mut superseded = std::collections::HashSet::new();
        for age in -1..=96 {
            let event_hour = (current_hour - age) as i32;
            let mut inputs: Vec<PartRef> = Vec::new();
            for level in [Level::L0, Level::Minute, Level::Hour] {
                serial += 1;
                let mut record = sample_record();
                record.part_id = PartId::parse(&format!("{created:013}-{serial:016x}")).unwrap();
                record.created_at_ms = created;
                record.level = level;
                record.event_hour = event_hour;
                // Strictly inside the hour: avoid ambiguous boundary rows.
                record.min_time_us = i64::from(event_hour) * hour_us + 1;
                record.max_time_us = (i64::from(event_hour) + 1) * hour_us - 1;
                record.schema_fingerprint =
                    crate::parts::format::schema_fingerprint(&schema).unwrap();
                record.hours[0].event_hour = event_hour;
                record.hours[0].min_time_us = record.min_time_us;
                record.hours[0].max_time_us = record.max_time_us;
                record.files.data[0].min_time_us = record.min_time_us;
                record.files.data[0].max_time_us = record.max_time_us;
                if let PartInputs::Sources { sources, .. } = &mut record.inputs {
                    sources[0].key = format!("bronze/{serial}.parquet");
                    sources[0].version = "1".into();
                }
                if level != Level::L0 {
                    record.admission = None;
                    record.inputs = PartInputs::Parts {
                        parts: inputs
                            .iter()
                            .map(|p| InputPart {
                                part_id: p.part_id.clone(),
                                level: p.level,
                                provenance_sha256: p.provenance_sha256.clone(),
                                rows: p.rows,
                                merkle_root: p.merkle_root.clone(),
                            })
                            .collect(),
                    };
                }
                let keys = PartKeys::new(TENANT, level, event_hour, &record.part_id).unwrap();
                let mut data = vec![(serial % 251) as u8; 64 * 1024];
                data[..8].copy_from_slice(&serial.to_le_bytes());
                record.files.data[0].bytes = data.len() as u64;
                record.files.data[0].sha256 = sha256_hex(&data);
                store.put(&keys.data(0), &data).await.unwrap();
                let sidecar = |name: &str, bytes: usize| {
                    let mut body = vec![(serial % 251) as u8; bytes];
                    body[..8].copy_from_slice(&serial.to_le_bytes());
                    body[8..40].copy_from_slice(&sha256_hex(name.as_bytes()).as_bytes()[..32]);
                    (
                        FileDigest {
                            name: name.into(),
                            bytes: bytes as u64,
                            sha256: sha256_hex(&body),
                        },
                        body,
                    )
                };
                for (kind, name, bytes) in [
                    (0, "tokens-00000.nti", 32 * 1024),
                    (1, "locators-00000.json", 128 * 1024),
                    (2, "entities-00000.json", 16 * 1024),
                    (3, "uids-00000.json", 8 * 1024),
                    (4, "ranges-00000.json", 4 * 1024),
                ] {
                    let (digest, body) = sidecar(name, bytes);
                    store.put(&keys.file(name), &body).await.unwrap();
                    let file = &mut record.files.data[0];
                    match kind {
                        0 => file.tokens = digest,
                        1 => file.entity_locators = Some(digest),
                        2 => file.entity_blooms = Some(digest),
                        3 => file.uid_blooms = Some(digest),
                        _ => file.parquet_ranges = Some(digest),
                    }
                }
                for kind in [
                    PartialKind::Rollup,
                    PartialKind::Prevalence,
                    PartialKind::EntityRanges,
                    PartialKind::Risk,
                ] {
                    let name = format!("partial-{kind:?}.parquet").to_lowercase();
                    let (digest, body) = sidecar(&name, 4 * 1024);
                    store.put(&keys.file(&name), &body).await.unwrap();
                    record.files.partials.push(PartialDigest {
                        kind,
                        name,
                        bytes: digest.bytes,
                        sha256: digest.sha256,
                        rows: 2,
                    });
                }
                let signature = signer
                    .sign(TENANT, std::slice::from_ref(&record))
                    .await
                    .unwrap()
                    .remove(0);
                let signed =
                    SignedProvenance::assemble(record.clone(), signature, &signer.trusted())
                        .unwrap()
                        .to_bytes()
                        .unwrap();
                store.put(&keys.provenance(), &signed).await.unwrap();
                let part = PartRef::from_record(&record, &sha256_hex(&signed), true);
                if level == Level::L0 {
                    writer
                        .append(
                            LogOp::Add {
                                parts: vec![part.clone()],
                                consumed: vec![crate::parts::part_log::SourceRef {
                                    key: format!("bronze/{serial}.parquet"),
                                    version: "1".into(),
                                    sha256: "0".repeat(64),
                                }],
                                edge_log: None,
                            },
                            created,
                        )
                        .await
                        .unwrap();
                } else {
                    let ids = inputs.iter().map(|p| p.part_id.clone()).collect::<Vec<_>>();
                    superseded.extend(ids.iter().cloned());
                    writer
                        .append(
                            LogOp::Merge {
                                output: part.clone(),
                                supersedes: ids,
                            },
                            created,
                        )
                        .await
                        .unwrap();
                }
                inputs = vec![part.clone()];
                inventories.push((part, record));
            }
        }
        let view = PartLogView::open(store.as_ref(), TENANT, signer.trusted())
            .await
            .unwrap();
        let live = view.live().parts().cloned().collect::<Vec<_>>();
        assert_eq!(live.len(), 98);
        assert!(live
            .iter()
            .all(|p| p.level == Level::Hour && !superseded.contains(&p.part_id)));
        let mut measured = Vec::new();
        for hours in [24, 48, 72] {
            let cache_root = root.path().join(format!("cache-{hours}"));
            let cache = ReaderObjectCache::open(
                ReaderObjectCacheSettings {
                    root: cache_root.clone(),
                    max_bytes: 64 << 20,
                    query_max_bytes: 1 << 20,
                    fetch_concurrency: 4,
                    fetch_deadline: Duration::from_secs(5),
                },
                TENANT,
                "lab",
                &parts_key_prefix(TENANT).unwrap(),
                Arc::new(StoreObjectSource::local(
                    "lab",
                    store.clone(),
                    source.clone(),
                )),
            )
            .unwrap();
            let fetcher = PartFetcher::new(TENANT, "lab", store.clone(), signer.trusted(), cache)
                .unwrap()
                .with_hot_window(Some(crate::local_hot_window::Settings {
                    root: cache_root,
                    hours,
                    bytes_per_second: 1 << 30,
                    reserve_bytes: Some(0),
                    max_bytes: 128 << 20,
                    schedule: Default::default(), persistent: false,
                }));
            let cutoff = now - hours as i64 * hour_us;
            let in_window = live
                .iter()
                .filter(|p| p.overlaps(cutoff, now))
                .cloned()
                .collect::<Vec<_>>();
            let data_bytes: u64 = in_window.iter().map(|p| p.data_bytes).sum();
            // NAN-3180: the rollup and entity-ranges partials and the token
            // index of every in-window part are hydrated with its data files
            // and counted in the budget.
            let sidecar_bytes: u64 = in_window
                .iter()
                .map(|p| {
                    let (_, record) = inventories.iter().find(|(i, _)| i.part_id == p.part_id).unwrap();
                    let partials = record.files.partials.iter()
                        .filter(|d| matches!(d.kind, PartialKind::Rollup | PartialKind::EntityRanges))
                        .map(|d| d.bytes)
                        .sum::<u64>();
                    partials + record.files.data.iter().map(|d| d.tokens.bytes).sum::<u64>()
                })
                .sum();
            assert_eq!(sidecar_bytes, in_window.len() as u64 * (2 * 4 + 32) * 1024);
            let live_bytes = data_bytes + sidecar_bytes;
            let before_bytes: u64 = inventories
                .iter()
                .filter(|(p, _)| {
                    live.iter().any(|l| l.part_id == p.part_id) && p.max_time_us >= cutoff
                })
                .map(|(_, r)| r.files.all().iter().map(|(_, _, bytes)| bytes).sum::<u64>())
                .sum();
            // Replay the previous eager-object plan into a separate cache to
            // measure real transferred bytes, rather than just inventory sizes.
            let baseline_root = root.path().join(format!("baseline-{hours}"));
            let baseline_cache = ReaderObjectCache::open(
                ReaderObjectCacheSettings {
                    root: baseline_root,
                    max_bytes: 64 << 20,
                    query_max_bytes: 1 << 20,
                    fetch_concurrency: 4,
                    fetch_deadline: Duration::from_secs(5),
                },
                TENANT,
                "lab",
                &parts_key_prefix(TENANT).unwrap(),
                Arc::new(StoreObjectSource::local(
                    "lab",
                    store.clone(),
                    source.clone(),
                )),
            )
            .unwrap();
            let baseline = PartFetcher::new(
                TENANT,
                "lab",
                store.clone(),
                signer.trusted(),
                baseline_cache,
            )
            .unwrap();
            for (p, r) in inventories.iter().filter(|(p, _)| {
                live.iter().any(|l| l.part_id == p.part_id) && p.max_time_us >= cutoff
            }) {
                for (name, digest, bytes) in r.files.all() {
                    let object = crate::reader_object_cache::ReaderObjectRef {
                        range: None,
                        source_uri: format!(
                            "s3://lab/{}",
                            baseline.keys_for(p).unwrap().file(name)
                        ),
                        sha256: digest.into(),
                        size_bytes: bytes,
                    };
                    baseline.hydrate_object(&object).await.unwrap();
                }
            }
            // Count actual transfers through the content-addressed cache.
            let before_fetched = baseline.cache().stats().fetched_bytes;
            assert!(before_fetched <= before_bytes);
            hydrate(
                &fetcher,
                TENANT,
                live.clone(),
                &AtomicU64::new(0),
                Instant::now(),
            )
            .await
            .unwrap();
            // NAN-3714: plus the plan partials of the live parts older than
            // the window (all four days are inside PLAN_HOURS), per distinct
            // object (the cache is content-addressed).
            let record_of = |p: &PartRef| &inventories.iter().find(|(i, _)| i.part_id == p.part_id).unwrap().1;
            let in_window_digests = in_window
                .iter()
                .flat_map(|p| resident_files(record_of(p)).into_iter().map(|(_, digest, _)| digest.to_string()))
                .collect::<std::collections::HashSet<_>>();
            let plan_cutoff = now - PLAN_HOURS as i64 * hour_us;
            let plan_bytes: u64 = live
                .iter()
                .filter(|p| !p.overlaps(cutoff, now) && p.overlaps(plan_cutoff, now))
                .flat_map(|p| plan_files(record_of(p)).into_iter().map(|(_, digest, bytes)| (digest.to_string(), bytes)))
                .filter(|(digest, _)| !in_window_digests.contains(digest))
                .collect::<std::collections::HashMap<_, _>>()
                .values()
                .sum();
            let fetched = fetcher.cache().stats().fetched_bytes - plan_bytes;
            assert!(
                fetched <= live_bytes * 12 / 10,
                "{hours}h: {fetched} > 1.2 * {live_bytes}"
            );
            assert_eq!(fetched, live_bytes);
            {
                let coverage = fetcher.hot_coverage.lock().unwrap().clone();
                assert!(coverage.warm);
                assert_eq!(coverage.selected_parts, in_window.len());
                assert_eq!(coverage.selected_bytes, live_bytes, "bytes_target includes rollups");
                assert_eq!(coverage.local_bytes, live_bytes, "bytes_resident includes rollups");
                assert_eq!(coverage.cache_miss_objects as usize, 4 * in_window.len());
                assert_eq!(coverage.buckets[2].total_bytes, live_bytes);
            }
            // NAN-3180 acceptance: the rollup read path of a stats step, and
            // the token-index and entity-ranges reads of a field-equality
            // pivot (`process.file.hashes.value=…`), resolve every object of
            // the window locally (0 misses, 0 bytes).
            use super::super::fetch::FileSet;
            for set in [
                FileSet::Partial(PartialKind::Rollup),
                FileSet::Partial(PartialKind::EntityRanges),
                FileSet::AllTokens,
            ] {
                let before = fetcher.cache().stats();
                let local = fetcher.ensure(&in_window, &[set]).await.unwrap();
                assert_eq!(local.of(set).count(), in_window.len());
                drop(local);
                let after = fetcher.cache().stats();
                assert_eq!(after.misses, before.misses, "{hours}h: {set:?} reads missed the hot window");
                assert_eq!(after.fetched_bytes, before.fetched_bytes);
                assert_eq!(after.hits - before.hits, in_window.len() as u64);
            }
            // A second pass must perform no object downloads.
            hydrate(
                &fetcher,
                TENANT,
                live.clone(),
                &AtomicU64::new(0),
                Instant::now(),
            )
            .await
            .unwrap();
            assert_eq!(fetcher.cache().stats().fetched_bytes, fetched + plan_bytes);
            for (p, r) in &inventories {
                for (name, digest, bytes) in r.files.all() {
                    let object = crate::reader_object_cache::ReaderObjectRef {
                        range: None,
                        source_uri: format!("s3://lab/{}", fetcher.keys_for(p).unwrap().file(name)),
                        sha256: digest.into(),
                        size_bytes: bytes,
                    };
                    let resident = matches!(
                        name,
                        "data-00000.parquet" | "tokens-00000.nti" | "partial-rollup.parquet" | "partial-entityranges.parquet"
                    );
                    // NAN-3714: a live part older than the window keeps its
                    // plan partials (only) resident.
                    let plan = !superseded.contains(&p.part_id)
                        && !p.overlaps(cutoff, now)
                        && p.overlaps(plan_cutoff, now)
                        && matches!(name, "partial-rollup.parquet" | "partial-entityranges.parquet");
                    if !plan && (superseded.contains(&p.part_id) || !p.overlaps(cutoff, now) || !resident) {
                        assert!(
                            !fetcher.cache().is_local(&object).await.unwrap(),
                            "unexpected hydration: {} {name}",
                            p.part_id
                        );
                    }
                }
            }
            println!("{hours}h lab: live={live_bytes}, before={before_fetched}, after={fetched}, ratio={:.4}->{:.4}",
                before_fetched as f64 / live_bytes as f64, fetched as f64 / live_bytes as f64);
            measured.push(fetched);
        }
        // Whole intersecting boundary parts allow one hour of rounding.
        assert!((measured[0] as f64 / measured[2] as f64 - 1.0 / 3.0).abs() < 0.02);
    }

    /// R2 stand-in: a fixed time-to-first-byte and a per-stream bandwidth,
    /// charged to the hydration bucket per chunk exactly like the R2 source.
    struct SlowSource {
        inner: StoreObjectSource,
        ttfb: Duration,
        stream_bytes_per_second: f64,
        order: std::sync::Mutex<Vec<String>>,
    }
    #[async_trait::async_trait]
    impl crate::reader_object_cache::ReaderObjectSource for SlowSource {
        async fn stream_object(
            &self,
            object: &crate::reader_object_cache::ReaderObjectRef,
            sink: &mut (dyn for<'b> FnMut(&'b [u8]) -> anyhow::Result<()> + Send),
        ) -> anyhow::Result<()> {
            self.order.lock().unwrap().push(object.source_uri.clone());
            tokio::time::sleep(self.ttfb).await;
            let mut body = Vec::new();
            self.inner
                .stream_object(object, &mut |chunk: &[u8]| {
                    body.extend_from_slice(chunk);
                    Ok(())
                })
                .await?;
            for chunk in body.chunks(128 * 1024) {
                tokio::time::sleep(Duration::from_secs_f64(
                    chunk.len() as f64 / self.stream_bytes_per_second,
                ))
                .await;
                crate::reader_object_cache::pace_background(chunk.len()).await;
                sink(chunk)?;
            }
            Ok(())
        }
    }

    /// NAN-3164 lab: hourly L0 parts behind a slow fake object store.
    async fn slow_fixture(
        root: &std::path::Path,
        hours: i64,
        part_bytes: usize,
    ) -> (Arc<LocalObjectStore>, std::path::PathBuf, LocalPartSigner, Vec<PartRef>) {
        let source = root.join("objects");
        let store = Arc::new(LocalObjectStore::new(&source).unwrap());
        let signer = signer(9);
        let schema = arrow_schema::Schema::new(vec![arrow_schema::Field::new(
            "time",
            arrow_schema::DataType::Timestamp(arrow_schema::TimeUnit::Microsecond, None),
            false,
        )]);
        let now = pinned_now();
        let hour_us = 3_600_000_000_i64;
        let current_hour = now.div_euclid(hour_us);
        let created = now / 1000;
        let mut writer = PartLogWriter::open(store.as_ref(), TENANT, 1, &schema, created)
            .await
            .unwrap();
        for age in 0..hours {
            let serial = age as u64 + 1;
            let event_hour = (current_hour - age) as i32;
            let mut record = sample_record();
            record.part_id = PartId::parse(&format!("{created:013}-{serial:016x}")).unwrap();
            record.created_at_ms = created;
            record.level = Level::L0;
            record.event_hour = event_hour;
            record.min_time_us = i64::from(event_hour) * hour_us + 1;
            record.max_time_us = ((i64::from(event_hour) + 1) * hour_us - 1).min(now - 1);
            record.schema_fingerprint = crate::parts::format::schema_fingerprint(&schema).unwrap();
            record.hours[0].event_hour = event_hour;
            record.hours[0].min_time_us = record.min_time_us;
            record.hours[0].max_time_us = record.max_time_us;
            record.files.data[0].min_time_us = record.min_time_us;
            record.files.data[0].max_time_us = record.max_time_us;
            if let PartInputs::Sources { sources, .. } = &mut record.inputs {
                sources[0].key = format!("bronze/slow-{serial}.parquet");
                sources[0].version = "1".into();
            }
            let keys = PartKeys::new(TENANT, Level::L0, event_hour, &record.part_id).unwrap();
            let mut data = vec![(serial % 251) as u8; part_bytes];
            data[..8].copy_from_slice(&serial.to_le_bytes());
            record.files.data[0].bytes = data.len() as u64;
            record.files.data[0].sha256 = sha256_hex(&data);
            store.put(&keys.data(0), &data).await.unwrap();
            // Every part carries a token index, hydrated with its data
            // (~1/8 of the data bytes, as on 300 eps hour parts).
            let tokens = serial.to_le_bytes().repeat((part_bytes / 64).max(1));
            store.put(&keys.file("tokens-00000.nti"), &tokens).await.unwrap();
            record.files.data[0].tokens = crate::parts::provenance::FileDigest {
                name: "tokens-00000.nti".into(),
                bytes: tokens.len() as u64,
                sha256: sha256_hex(&tokens),
            };
            let signature = signer
                .sign(TENANT, std::slice::from_ref(&record))
                .await
                .unwrap()
                .remove(0);
            let signed = SignedProvenance::assemble(record.clone(), signature, &signer.trusted())
                .unwrap()
                .to_bytes()
                .unwrap();
            store.put(&keys.provenance(), &signed).await.unwrap();
            let part = PartRef::from_record(&record, &sha256_hex(&signed), true);
            writer
                .append(
                    LogOp::Add {
                        parts: vec![part],
                        consumed: vec![crate::parts::part_log::SourceRef {
                            key: format!("bronze/slow-{serial}.parquet"),
                            version: "1".into(),
                            sha256: "0".repeat(64),
                        }],
                        edge_log: None,
                    },
                    created,
                )
                .await
                .unwrap();
        }
        let view = PartLogView::open(store.as_ref(), TENANT, signer.trusted())
            .await
            .unwrap();
        let live = view.live().parts().cloned().collect::<Vec<_>>();
        assert_eq!(live.len() as i64, hours);
        (store, source, signer, live)
    }

    /// Returns (bytes/s achieved, request order, fetcher).
    async fn run_slow_hydration(
        root: &std::path::Path,
        name: &str,
        fixture: &(Arc<LocalObjectStore>, std::path::PathBuf, LocalPartSigner, Vec<PartRef>),
        cap: u64,
        schedule: crate::local_hot_window::Schedule,
        queries_in_flight: u64,
    ) -> (f64, Vec<String>, PartFetcher) {
        let (store, source, signer, live) = fixture;
        let cache_root = root.join(name);
        let slow = Arc::new(SlowSource {
            inner: StoreObjectSource::local("lab", store.clone(), source.clone()),
            ttfb: Duration::from_millis(40),
            stream_bytes_per_second: 4.0 * 1024.0 * 1024.0,
            order: Default::default(),
        });
        let cache = ReaderObjectCache::open(
            ReaderObjectCacheSettings {
                root: cache_root.clone(),
                max_bytes: 256 << 20,
                query_max_bytes: 1 << 20,
                fetch_concurrency: 16,
                fetch_deadline: Duration::from_secs(30),
            },
            TENANT,
            "lab",
            &parts_key_prefix(TENANT).unwrap(),
            slow.clone(),
        )
        .unwrap();
        let fetcher = PartFetcher::new(TENANT, "lab", store.clone(), signer.trusted(), cache)
            .unwrap()
            .with_hot_window(Some(crate::local_hot_window::Settings {
                root: cache_root,
                hours: 48,
                bytes_per_second: cap,
                reserve_bytes: Some(0),
                max_bytes: 1 << 30,
                schedule, persistent: false,
            }));
        hydrate(&fetcher, TENANT, live.clone(), &AtomicU64::new(queries_in_flight), Instant::now())
            .await
            .unwrap();
        let coverage = fetcher.hot_coverage.lock().unwrap().clone();
        assert!(coverage.warm, "{coverage:?}");
        assert_eq!(coverage.cache_miss_objects as usize, 2 * live.len(), "data + token index per part");
        let rate = coverage.rate_bytes_per_second;
        println!(
            "NAN-3164 lab {name}: concurrency={} cap={cap} B/s rate={rate:.0} B/s ({:.0}% of cap) fetch_seconds={:.2} hydrate_seconds={:.2}",
            coverage.concurrency,
            100.0 * rate / cap as f64,
            coverage.fetch_seconds,
            coverage.hydrate_seconds,
        );
        // Request order of the data files (each part's token index follows it).
        let order = slow.order.lock().unwrap().iter().filter(|uri| uri.contains("/data-")).cloned().collect();
        (rate, order, fetcher)
    }

    /// NAN-3164: against an R2-like store (40 ms TTFB, 4 MiB/s per stream),
    /// one object at a time is stuck at the per-stream rate; the shared
    /// bucket with concurrent downloads reaches the cap, newest hours first,
    /// and queries in flight do not throttle the warm window.
    /// NAN-3866: on a paused clock the measured rate is set by the fake
    /// store's TTFB/stream sleeps and the bucket alone; on wall time CPU load
    /// (hashing, fsync on a busy runner) dragged it under the bound.
    #[tokio::test(start_paused = true)]
    async fn hydration_reaches_cap_newest_first_against_slow_store() {
        let root = tempfile::tempdir().unwrap();
        let fixture = slow_fixture(root.path(), 16, 1 << 20).await;
        let cap = 16 << 20;
        let newest_first = {
            let mut parts = fixture.3.clone();
            parts.sort_by_key(|p| std::cmp::Reverse(p.max_time_us));
            parts.iter().map(|p| p.part_id.to_string()).collect::<Vec<_>>()
        };
        let part_of = |uri: &String| {
            newest_first.iter().position(|id| uri.contains(id.as_str())).expect("known part")
        };
        let serial = crate::local_hot_window::Schedule { concurrency: 1, ..Default::default() };
        let (serial_rate, order, _) =
            run_slow_hydration(root.path(), "serial", &fixture, cap, serial, 0).await;
        assert_eq!(order.iter().map(part_of).collect::<Vec<_>>(), (0..16).collect::<Vec<_>>());
        assert!(serial_rate < cap as f64 * 0.4, "one stream cannot reach the cap: {serial_rate}");

        // Queries in flight, warm window still hydrating: no backoff.
        let parallel = crate::local_hot_window::Schedule {
            concurrency: 8,
            warm_hours: 48,
            ..Default::default()
        };
        let (rate, order, fetcher) =
            run_slow_hydration(root.path(), "parallel", &fixture, cap, parallel, 1).await;
        // Each part is two objects (data + its 1/8-size token index); the
        // token index's 40 ms TTFB is paid at ~1/8 of the data's bytes, which
        // costs a few points of the cap (measured 74-78% on a dev box).
        assert!(rate >= cap as f64 * 0.7, "rate {rate} under 70% of cap {cap}");
        assert!(rate <= cap as f64 * 1.1, "rate {rate} over the cap {cap}");
        let mut first = order.iter().take(8).map(part_of).collect::<Vec<_>>();
        first.sort_unstable();
        assert_eq!(first, (0..8).collect::<Vec<_>>(), "newest hours start first");
        assert!(fetcher.hot_coverage.lock().unwrap().warm_resident);
        assert_eq!(fetcher.hot_window_gate(), Some(crate::local_hot_window::WarmGate::Resident));
    }

    /// The warm latch: once the newest hours were resident, a later pass that
    /// recounts from zero must not withdraw it; a pass that cannot hydrate
    /// leaves the gate hydrating until its timeout.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn warm_latch_survives_later_passes_and_times_out_when_stuck() {
        let root = tempfile::tempdir().unwrap();
        let fixture = slow_fixture(root.path(), 4, 64 * 1024).await;
        let schedule = crate::local_hot_window::Schedule { warm_hours: 2, ..Default::default() };
        let (_, _, fetcher) =
            run_slow_hydration(root.path(), "latch", &fixture, 64 << 20, schedule, 0).await;
        assert!(fetcher.hot_coverage.lock().unwrap().warm_resident);
        hydrate(&fetcher, TENANT, fixture.3.clone(), &AtomicU64::new(0), Instant::now())
            .await
            .unwrap();
        let coverage = fetcher.hot_coverage.lock().unwrap().clone();
        assert!(coverage.warm_resident && coverage.cache_hit_objects == 8 && coverage.cache_miss_objects == 0);

        // Never hydrated (R2 down): hydrating, then timed out; never wedged.
        let (store, _source, signer, _) = &fixture;
        let cold_root = root.path().join("cold");
        let cache = ReaderObjectCache::open(
            ReaderObjectCacheSettings {
                root: cold_root.clone(),
                max_bytes: 1 << 20,
                query_max_bytes: 1 << 20,
                fetch_concurrency: 1,
                fetch_deadline: Duration::from_secs(1),
            },
            TENANT,
            "lab",
            &parts_key_prefix(TENANT).unwrap(),
            Arc::new(StoreObjectSource::new("lab", store.clone())),
        )
        .unwrap();
        let stuck = |timeout| {
            PartFetcher::new(TENANT, "lab", store.clone(), signer.trusted(), cache.clone())
                .unwrap()
                .with_hot_window(Some(crate::local_hot_window::Settings {
                    root: cold_root.clone(),
                    hours: 48,
                    bytes_per_second: 1,
                    reserve_bytes: Some(0),
                    max_bytes: 1 << 30,
                    schedule: crate::local_hot_window::Schedule {
                        warm_timeout: Duration::from_millis(timeout),
                        ..Default::default()
                    }, persistent: false,
                }))
        };
        let waiting = stuck(60_000);
        assert_eq!(waiting.hot_window_gate(), Some(crate::local_hot_window::WarmGate::Hydrating));
        let expired = stuck(0);
        assert_eq!(expired.hot_window_gate(), Some(crate::local_hot_window::WarmGate::TimedOut));
        assert!(expired.hot_window_gate().unwrap().warm());
    }

    /// NAN-3180: one hourly part with a data file, its token index, and the
    /// rollup and entity-ranges partials.
    async fn rollup_part(
        store: &LocalObjectStore,
        signer: &LocalPartSigner,
        serial: u64,
        event_hour: i32,
        input: Option<&PartRef>,
        created: i64,
        now: i64,
    ) -> (PartRef, crate::parts::provenance::ProvenanceRecord) {
        let hour_us = 3_600_000_000_i64;
        let level = if input.is_some() { Level::Minute } else { Level::L0 };
        let mut record = sample_record();
        record.part_id = PartId::parse(&format!("{created:013}-{serial:016x}")).unwrap();
        record.created_at_ms = created;
        record.level = level;
        record.event_hour = event_hour;
        record.min_time_us = i64::from(event_hour) * hour_us + 1;
        record.max_time_us = ((i64::from(event_hour) + 1) * hour_us - 1).min(now - 1);
        let schema = arrow_schema::Schema::new(vec![arrow_schema::Field::new(
            "time",
            arrow_schema::DataType::Timestamp(arrow_schema::TimeUnit::Microsecond, None),
            false,
        )]);
        record.schema_fingerprint = crate::parts::format::schema_fingerprint(&schema).unwrap();
        record.hours[0].event_hour = event_hour;
        record.hours[0].min_time_us = record.min_time_us;
        record.hours[0].max_time_us = record.max_time_us;
        record.files.data[0].min_time_us = record.min_time_us;
        record.files.data[0].max_time_us = record.max_time_us;
        if let PartInputs::Sources { sources, .. } = &mut record.inputs {
            sources[0].key = format!("bronze/rollup-{serial}.parquet");
            sources[0].version = "1".into();
        }
        if let Some(p) = input {
            record.admission = None;
            record.inputs = PartInputs::Parts {
                parts: vec![InputPart {
                    part_id: p.part_id.clone(),
                    level: p.level,
                    provenance_sha256: p.provenance_sha256.clone(),
                    rows: p.rows,
                    merkle_root: p.merkle_root.clone(),
                }],
            };
        }
        let keys = PartKeys::new(TENANT, level, event_hour, &record.part_id).unwrap();
        let mut data = vec![(serial % 251) as u8; 32 * 1024];
        data[..8].copy_from_slice(&serial.to_le_bytes());
        record.files.data[0].bytes = data.len() as u64;
        record.files.data[0].sha256 = sha256_hex(&data);
        store.put(&keys.data(0), &data).await.unwrap();
        let mut tokens = vec![0x5A_u8; 1024];
        tokens[..8].copy_from_slice(&serial.to_le_bytes());
        let name = "tokens-00000.nti".to_string();
        store.put(&keys.file(&name), &tokens).await.unwrap();
        record.files.data[0].tokens =
            FileDigest { name, bytes: tokens.len() as u64, sha256: sha256_hex(&tokens) };
        record.files.partials.clear();
        for (kind, fill) in [(PartialKind::Rollup, 0xA5_u8), (PartialKind::EntityRanges, 0xE5)] {
            let mut body = vec![fill; 2 * 1024];
            body[..8].copy_from_slice(&serial.to_le_bytes());
            let name = format!("partial-{kind:?}.parquet").to_lowercase();
            store.put(&keys.file(&name), &body).await.unwrap();
            record.files.partials.push(PartialDigest {
                kind,
                name,
                bytes: body.len() as u64,
                sha256: sha256_hex(&body),
                rows: 1,
            });
        }
        let signature = signer.sign(TENANT, std::slice::from_ref(&record)).await.unwrap().remove(0);
        let signed = SignedProvenance::assemble(record.clone(), signature, &signer.trusted())
            .unwrap()
            .to_bytes()
            .unwrap();
        store.put(&keys.provenance(), &signed).await.unwrap();
        (PartRef::from_record(&record, &sha256_hex(&signed), true), record)
    }

    fn part_object(
        fetcher: &PartFetcher,
        part: &PartRef,
        record: &crate::parts::provenance::ProvenanceRecord,
        file: PartFile,
    ) -> crate::reader_object_cache::ReaderObjectRef {
        let (_, digest, size) = super::super::fetch::file_digest(record, file).unwrap();
        crate::reader_object_cache::ReaderObjectRef {
            range: None,
            source_uri: fetcher.file_uri(part, record, file).unwrap(),
            sha256: digest.into(),
            size_bytes: size,
        }
    }

    /// NAN-3180: a rollup partial produced after a hydration pass (here by a
    /// merge that replaces an hour) is hydrated by the next pass, and the
    /// superseded part's partial is evicted with its data file. The token
    /// index and entity-ranges partial that a field-equality pivot reads
    /// follow the same lifecycle.
    #[tokio::test]
    async fn later_partials_are_hydrated_and_retired_partials_evicted() {
        let root = tempfile::tempdir().unwrap();
        let source = root.path().join("objects");
        let store = Arc::new(LocalObjectStore::new(&source).unwrap());
        let signer = signer(11);
        let schema = arrow_schema::Schema::new(vec![arrow_schema::Field::new(
            "time",
            arrow_schema::DataType::Timestamp(arrow_schema::TimeUnit::Microsecond, None),
            false,
        )]);
        let now = pinned_now();
        let current_hour = now.div_euclid(3_600_000_000);
        let created = now / 1000;
        let mut writer = PartLogWriter::open(store.as_ref(), TENANT, 1, &schema, created).await.unwrap();
        let mut parts = Vec::new();
        for age in 0..3_i64 {
            let event_hour = (current_hour - age) as i32;
            let (part, record) =
                rollup_part(&store, &signer, age as u64 + 1, event_hour, None, created, now).await;
            writer
                .append(
                    LogOp::Add {
                        parts: vec![part.clone()],
                        consumed: vec![crate::parts::part_log::SourceRef {
                            key: format!("bronze/rollup-{}.parquet", age + 1),
                            version: "1".into(),
                            sha256: "0".repeat(64),
                        }],
                        edge_log: None,
                    },
                    created,
                )
                .await
                .unwrap();
            parts.push((part, record));
        }
        let cache_root = root.path().join("cache");
        let cache = ReaderObjectCache::open(
            ReaderObjectCacheSettings {
                root: cache_root.clone(),
                max_bytes: 64 << 20,
                query_max_bytes: 1 << 20,
                fetch_concurrency: 4,
                fetch_deadline: Duration::from_secs(5),
            },
            TENANT,
            "lab",
            &parts_key_prefix(TENANT).unwrap(),
            Arc::new(StoreObjectSource::local("lab", store.clone(), source.clone())),
        )
        .unwrap();
        let fetcher = PartFetcher::new(TENANT, "lab", store.clone(), signer.trusted(), cache)
            .unwrap()
            .with_hot_window(Some(crate::local_hot_window::Settings {
                root: cache_root,
                hours: 24,
                bytes_per_second: 1 << 30,
                reserve_bytes: Some(0),
                max_bytes: 128 << 20,
                schedule: Default::default(), persistent: false,
            }));
        let live = |store: Arc<LocalObjectStore>, trusted| async move {
            PartLogView::open(store.as_ref(), TENANT, trusted).await.unwrap().live().parts().cloned().collect::<Vec<_>>()
        };
        hydrate(&fetcher, TENANT, live(store.clone(), signer.trusted()).await, &AtomicU64::new(0), Instant::now())
            .await
            .unwrap();
        let sidecars = [
            PartFile::Tokens(0),
            PartFile::Partial(PartialKind::Rollup),
            PartFile::Partial(PartialKind::EntityRanges),
        ];
        for (part, record) in &parts {
            for file in sidecars {
                assert!(
                    fetcher.cache().is_local(&part_object(&fetcher, part, record, file)).await.unwrap(),
                    "{file:?} not hydrated"
                );
            }
        }
        let per_part = 32 * 1024 + 1024 + 2 * 2 * 1024;
        let coverage = fetcher.hot_coverage.lock().unwrap().clone();
        assert_eq!((coverage.selected_bytes, coverage.local_bytes), (3 * per_part, 3 * per_part));
        assert!(coverage.warm);

        // Compaction replaces the newest hour after the pass.
        let (old, old_record) = parts[0].clone();
        let (merged, merged_record) =
            rollup_part(&store, &signer, 101, old.event_hour, Some(&old), created, now).await;
        writer
            .append(LogOp::Merge { output: merged.clone(), supersedes: vec![old.part_id.clone()] }, created)
            .await
            .unwrap();
        let next = live(store.clone(), signer.trusted()).await;
        assert!(next.iter().any(|p| p.part_id == merged.part_id));
        assert!(!next.iter().any(|p| p.part_id == old.part_id));
        hydrate(&fetcher, TENANT, next, &AtomicU64::new(0), Instant::now()).await.unwrap();
        for file in sidecars {
            assert!(
                fetcher.cache().is_local(&part_object(&fetcher, &merged, &merged_record, file)).await.unwrap(),
                "{file:?} produced after hydration is picked up by the next pass"
            );
            assert!(
                !fetcher.cache().is_local(&part_object(&fetcher, &old, &old_record, file)).await.unwrap(),
                "a retired part's {file:?} is evicted with it"
            );
        }
        let coverage = fetcher.hot_coverage.lock().unwrap().clone();
        assert_eq!((coverage.selected_parts, coverage.selected_bytes), (3, 3 * per_part));
        assert_eq!(coverage.local_bytes, 3 * per_part);
        assert!(coverage.warm);
    }

    /// NAN-3647: one "pod" on a persistent hot volume: a fresh cache + fetcher
    /// over `cache_root`, as a new query process on the reused volume sees it.
    fn persistent_pod(
        store: &Arc<LocalObjectStore>,
        source: &std::path::Path,
        signer: &LocalPartSigner,
        cache_root: &std::path::Path,
        persistent: bool,
    ) -> PartFetcher {
        let settings = ReaderObjectCacheSettings {
            root: cache_root.to_path_buf(),
            max_bytes: 64 << 20,
            query_max_bytes: 1 << 20,
            fetch_concurrency: 4,
            fetch_deadline: Duration::from_secs(5),
        };
        let objects = Arc::new(StoreObjectSource::local("lab", store.clone(), source.to_path_buf()));
        let prefix = parts_key_prefix(TENANT).unwrap();
        let cache = if persistent {
            ReaderObjectCache::open_or_reset(settings, TENANT, "lab", &prefix, objects)
        } else {
            ReaderObjectCache::open(settings, TENANT, "lab", &prefix, objects)
        }
        .unwrap();
        PartFetcher::new(TENANT, "lab", store.clone(), signer.trusted(), cache)
            .unwrap()
            .with_hot_window(Some(crate::local_hot_window::Settings {
                root: cache_root.to_path_buf(),
                hours: 24,
                bytes_per_second: 1 << 30,
                reserve_bytes: Some(0),
                max_bytes: 128 << 20,
                schedule: Default::default(),
                persistent,
            }))
    }

    /// NAN-3647 acceptance: a roll lands on the A/B volume the roll before
    /// last left behind. The new pod reuses every object the live catalog
    /// still references (content-addressed: signed sha256 + size), fetches
    /// only the delta (parts written or merged since), and drops what the
    /// catalog no longer references, including objects its own ledger never
    /// listed. A truncated object is refetched, never served.
    #[tokio::test]
    async fn reused_volume_hydrates_only_the_delta_and_drops_unreferenced() {
        let root = tempfile::tempdir().unwrap();
        let source = root.path().join("objects");
        let store = Arc::new(LocalObjectStore::new(&source).unwrap());
        let signer = signer(13);
        let schema = arrow_schema::Schema::new(vec![arrow_schema::Field::new(
            "time",
            arrow_schema::DataType::Timestamp(arrow_schema::TimeUnit::Microsecond, None),
            false,
        )]);
        let now = pinned_now();
        let current_hour = now.div_euclid(3_600_000_000);
        let created = now / 1000;
        let mut writer = PartLogWriter::open(store.as_ref(), TENANT, 1, &schema, created).await.unwrap();
        let add = |part: PartRef, serial: u64| LogOp::Add {
            parts: vec![part],
            consumed: vec![crate::parts::part_log::SourceRef {
                key: format!("bronze/rollup-{serial}.parquet"),
                version: "1".into(),
                sha256: "0".repeat(64),
            }],
            edge_log: None,
        };
        let mut parts = Vec::new();
        for age in 1..5_i64 {
            let serial = age as u64;
            let (part, record) =
                rollup_part(&store, &signer, serial, (current_hour - age) as i32, None, created, now).await;
            writer.append(add(part.clone(), serial), created).await.unwrap();
            parts.push((part, record));
        }
        let live = |store: Arc<LocalObjectStore>, trusted| async move {
            PartLogView::open(store.as_ref(), TENANT, trusted).await.unwrap().live().parts().cloned().collect::<Vec<_>>()
        };
        let per_part = 32 * 1024 + 1024 + 2 * 2 * 1024;
        // Volume A, first pod: cold.
        let volume_a = root.path().join("hot-a/cache");
        let first = persistent_pod(&store, &source, &signer, &volume_a, true);
        hydrate(&first, TENANT, live(store.clone(), signer.trusted()).await, &AtomicU64::new(0), Instant::now())
            .await
            .unwrap();
        assert_eq!(first.cache().stats().fetched_bytes, 4 * per_part);
        // An object nothing references (a cold fetch of a long-gone part).
        let orphan = vec![0x42_u8; 4096];
        let orphan_digest = sha256_hex(&orphan);
        let orphan_path = first.cache().object_path(&orphan_digest);
        std::fs::write(&orphan_path, &orphan).unwrap();
        std::fs::set_permissions(&orphan_path, std::os::unix::fs::PermissionsExt::from_mode(0o444)).unwrap();
        // A torn copy of a still-live object (same digest, wrong size).
        let (torn_part, torn_record) = parts[3].clone();
        let torn = part_object(&first, &torn_part, &torn_record, PartFile::Data(0));
        let torn_path = first.cache().object_path(&torn.sha256);
        let mut permissions = std::fs::metadata(&torn_path).unwrap().permissions();
        std::os::unix::fs::PermissionsExt::set_mode(&mut permissions, 0o644);
        std::fs::set_permissions(&torn_path, permissions).unwrap();
        std::fs::OpenOptions::new().write(true).open(&torn_path).unwrap().set_len(100).unwrap();
        std::fs::set_permissions(&torn_path, std::os::unix::fs::PermissionsExt::from_mode(0o444)).unwrap();
        drop(first);

        // While volume A sat idle (the roll it served was replaced): the
        // newest hour arrived and the oldest hour was merged away.
        let (newest, newest_record) =
            rollup_part(&store, &signer, 50, current_hour as i32, None, created, now).await;
        writer.append(add(newest.clone(), 50), created).await.unwrap();
        let (old, old_record) = parts[0].clone();
        let (merged, merged_record) =
            rollup_part(&store, &signer, 51, old.event_hour, Some(&old), created, now).await;
        writer
            .append(LogOp::Merge { output: merged.clone(), supersedes: vec![old.part_id.clone()] }, created)
            .await
            .unwrap();

        // The next-but-one roll mounts volume A again.
        let second = persistent_pod(&store, &source, &signer, &volume_a, true);
        hydrate(&second, TENANT, live(store.clone(), signer.trusted()).await, &AtomicU64::new(0), Instant::now())
            .await
            .unwrap();
        let coverage = second.hot_coverage.lock().unwrap().clone();
        assert!(coverage.warm && coverage.warm_resident);
        assert_eq!(coverage.selected_parts, 5);
        // Delta only: the two new parts plus the torn data file.
        assert_eq!(second.cache().stats().fetched_bytes, 2 * per_part + 32 * 1024,
            "only parts written since this volume last served (and the torn object) are fetched");
        assert_eq!(coverage.cache_hit_objects, 3 * 4 - 1);
        for (part, record) in [(&newest, &newest_record), (&merged, &merged_record), (&torn_part, &torn_record)] {
            assert!(second.cache().is_local(&part_object(&second, part, record, PartFile::Data(0))).await.unwrap());
        }
        assert!(!second.cache().is_local(&part_object(&second, &old, &old_record, PartFile::Data(0))).await.unwrap(),
            "the merged-away part is evicted");
        assert!(!orphan_path.exists(), "an object the catalog never referenced is evicted");
        assert_eq!(std::fs::metadata(&torn_path).unwrap().len(), torn.size_bytes, "the torn copy was replaced");
        assert_eq!(second.cache().stats().stored_bytes, 5 * per_part);
    }

    /// NAN-3647: a persistent volume this tenant cannot adopt (here: a cache
    /// bound to another bucket, then a corrupt membership ledger) falls back to
    /// a cold cache instead of failing query[T]; off the persistent mode the
    /// strict behavior is unchanged.
    #[tokio::test]
    async fn unusable_persistent_volume_falls_back_cold() {
        let root = tempfile::tempdir().unwrap();
        let (store, source, signer, live) = slow_fixture(root.path(), 3, 16 * 1024).await;
        let volume = root.path().join("hot-b/cache");
        let directory = volume.join(format!("tenant-{TENANT}"));
        std::fs::create_dir_all(directory.join("objects")).unwrap();
        std::fs::write(directory.join("reader-cache.json"),
            br#"{"schema":1,"tenant_id":"00000000-0000-4000-8000-000000000000","bucket":"other","key_prefix":"x"}"#).unwrap();
        std::fs::write(directory.join("objects").join(format!("{}.bin", "a".repeat(64))), b"foreign").unwrap();
        let strict = ReaderObjectCache::open(
            ReaderObjectCacheSettings { root: volume.clone(), max_bytes: 64 << 20, query_max_bytes: 1 << 20,
                fetch_concurrency: 4, fetch_deadline: Duration::from_secs(5) },
            TENANT, "lab", &parts_key_prefix(TENANT).unwrap(),
            Arc::new(StoreObjectSource::local("lab", store.clone(), source.clone())));
        assert!(strict.is_err(), "the strict open still refuses a foreign cache");

        let pod = persistent_pod(&store, &source, &signer, &volume, true);
        assert_eq!(pod.cache().stats().objects, 0, "started cold");
        hydrate(&pod, TENANT, live.clone(), &AtomicU64::new(0), Instant::now()).await.unwrap();
        assert!(pod.hot_coverage.lock().unwrap().warm);
        drop(pod);

        // A ledger torn by a pod killed mid-write.
        std::fs::write(directory.join("hot-membership.json"), b"{\"torn").unwrap();
        let pod = persistent_pod(&store, &source, &signer, &volume, true);
        hydrate(&pod, TENANT, live.clone(), &AtomicU64::new(0), Instant::now()).await.unwrap();
        let coverage = pod.hot_coverage.lock().unwrap().clone();
        assert!(coverage.warm);
        assert_eq!(coverage.cache_miss_objects, 0, "the objects themselves are still reused");
        assert!(crate::local_hot_window::load_membership(&volume, TENANT).is_ok(), "a fresh ledger was written");
    }

    /// NAN-3647: with the gate on, the bound is the gate's own timeout and a
    /// pod that cannot fill its warm hours in time still goes Ready (cold).
    #[tokio::test]
    async fn gated_warm_wait_times_out_ready_cold() {
        let root = tempfile::tempdir().unwrap();
        let (store, source, signer, _) = slow_fixture(root.path(), 2, 16 * 1024).await;
        let gated = |timeout: u64| {
            let mut fetcher = persistent_pod(&store, &source, &signer, &root.path().join("gate/cache"), false);
            let settings = fetcher.hot_settings.as_mut().unwrap();
            settings.schedule = crate::local_hot_window::Schedule::from_lookup(|name| match name {
                crate::local_hot_window::WARM_GATE => Some("1".into()),
                crate::local_hot_window::WARM_GATE_TIMEOUT => Some(timeout.to_string()),
                _ => None,
            })
            .unwrap();
            fetcher
        };
        let waiting = gated(3600);
        assert_eq!(waiting.hot_window_gate(), Some(crate::local_hot_window::WarmGate::Hydrating));
        let expired = gated(0);
        assert_eq!(expired.hot_window_gate(), Some(crate::local_hot_window::WarmGate::TimedOut));
        assert!(expired.hot_window_gate().unwrap().warm(), "a stuck hydration never blocks the roll");
    }

    /// NAN-3690: partials-first is an ordering only; off it is the old
    /// part-by-part order.
    #[test]
    fn hydration_jobs_put_partials_first_only_when_asked() {
        let part = || vec![
            PartFile::Data(0), PartFile::Tokens(0),
            PartFile::Partial(PartialKind::Rollup), PartFile::Partial(PartialKind::EntityRanges),
        ];
        let none = std::collections::BTreeSet::new();
        let off = hydration_jobs(vec![part(), part()], &none, false);
        assert_eq!(off.iter().map(|(i, _)| *i).collect::<Vec<_>>(), [0, 0, 0, 0, 1, 1, 1, 1]);
        assert_eq!(off[0].1, PartFile::Data(0));
        let on = hydration_jobs(vec![part(), part()], &none, true);
        assert_eq!(on, vec![
            (0, PartFile::Partial(PartialKind::Rollup)), (0, PartFile::Partial(PartialKind::EntityRanges)),
            (1, PartFile::Partial(PartialKind::Rollup)), (1, PartFile::Partial(PartialKind::EntityRanges)),
            (0, PartFile::Data(0)), (0, PartFile::Tokens(0)),
            (1, PartFile::Data(0)), (1, PartFile::Tokens(0)),
        ], "every part's partials, newest first, then the rest part by part");
        assert!(hydration_jobs(Vec::new(), &none, true).is_empty());
    }

    /// NAN-3714: with partials first, the oldest-edge parts' data follows the
    /// partials (the plan-only part has partials only) and precedes the rest;
    /// partials-first off ignores the edge (gate off: unchanged).
    #[test]
    fn hydration_jobs_put_the_oldest_edge_right_after_the_partials() {
        let part = || vec![PartFile::Data(0), PartFile::Partial(PartialKind::Rollup)];
        let plan = vec![PartFile::Partial(PartialKind::Rollup)];
        let edge = std::collections::BTreeSet::from([2]);
        let on = hydration_jobs(vec![part(), part(), part(), plan.clone()], &edge, true);
        assert_eq!(on, vec![
            (0, PartFile::Partial(PartialKind::Rollup)), (1, PartFile::Partial(PartialKind::Rollup)),
            (2, PartFile::Partial(PartialKind::Rollup)), (3, PartFile::Partial(PartialKind::Rollup)),
            (2, PartFile::Data(0)), (0, PartFile::Data(0)), (1, PartFile::Data(0)),
        ]);
        let off = hydration_jobs(vec![part(), part(), part(), plan], &edge, false);
        assert_eq!(off.iter().map(|(i, _)| *i).collect::<Vec<_>>(), [0, 0, 1, 1, 2, 2, 3]);
    }

    /// NAN-3690 fixture: `hours` hourly rollup parts (newest first) in a part
    /// log, and a fetcher whose source records the request order.
    async fn partials_fixture<'a>(
        root: &std::path::Path,
        store: &'a Arc<LocalObjectStore>,
        hours: u64,
        warm_gate: bool,
    ) -> (LocalPartSigner, PartLogWriter<'a>, Vec<(PartRef, ProvenanceRecord)>, Arc<SlowSource>, PartFetcher) {
        partials_fixture_ages(root, store, &(0..hours).collect::<Vec<_>>(), warm_gate).await
    }

    /// [`partials_fixture`] with one hourly part per age in hours (newest
    /// first), against the fixture's 24 h hot window and 1 warm hour.
    async fn partials_fixture_ages<'a>(
        root: &std::path::Path,
        store: &'a Arc<LocalObjectStore>,
        ages: &[u64],
        warm_gate: bool,
    ) -> (LocalPartSigner, PartLogWriter<'a>, Vec<(PartRef, ProvenanceRecord)>, Arc<SlowSource>, PartFetcher) {
        let source = root.join("objects");
        let signer = signer(13);
        let schema = arrow_schema::Schema::new(vec![arrow_schema::Field::new(
            "time",
            arrow_schema::DataType::Timestamp(arrow_schema::TimeUnit::Microsecond, None),
            false,
        )]);
        let now = pinned_now();
        let current_hour = now.div_euclid(3_600_000_000);
        let created = now / 1000;
        let mut writer = PartLogWriter::open(store.as_ref(), TENANT, 1, &schema, created).await.unwrap();
        let mut parts = Vec::new();
        for &age in ages {
            let (part, record) =
                rollup_part(store, &signer, age + 1, (current_hour - age as i64) as i32, None, created, now).await;
            writer
                .append(
                    LogOp::Add {
                        parts: vec![part.clone()],
                        consumed: vec![crate::parts::part_log::SourceRef {
                            key: format!("bronze/rollup-{}.parquet", age + 1),
                            version: "1".into(),
                            sha256: "0".repeat(64),
                        }],
                        edge_log: None,
                    },
                    created,
                )
                .await
                .unwrap();
            parts.push((part, record));
        }
        let cache_root = root.join("cache");
        let slow = Arc::new(SlowSource {
            inner: StoreObjectSource::local("lab", store.clone(), source.clone()),
            ttfb: Duration::from_millis(1),
            stream_bytes_per_second: 1e9,
            order: Default::default(),
        });
        let cache = ReaderObjectCache::open(
            ReaderObjectCacheSettings {
                root: cache_root.clone(),
                max_bytes: 64 << 20,
                query_max_bytes: 1 << 20,
                fetch_concurrency: 4,
                fetch_deadline: Duration::from_secs(5),
            },
            TENANT,
            "lab",
            &parts_key_prefix(TENANT).unwrap(),
            slow.clone(),
        )
        .unwrap();
        let schedule = crate::local_hot_window::Schedule::from_lookup(|name| match name {
            crate::local_hot_window::WARM_GATE if warm_gate => Some("1".into()),
            // Only the newest hour gates warm; the rest is "older history".
            crate::local_hot_window::WARM_HOURS => Some("1".into()),
            crate::local_hot_window::CONCURRENCY => Some("1".into()),
            crate::local_hot_window::WARMUP_CONCURRENCY => Some("1".into()),
            _ => None,
        })
        .unwrap();
        let fetcher = PartFetcher::new(TENANT, "lab", store.clone(), signer.trusted(), cache)
            .unwrap()
            .with_hot_window(Some(crate::local_hot_window::Settings {
                root: cache_root,
                hours: 24,
                bytes_per_second: 1 << 30,
                reserve_bytes: Some(0),
                max_bytes: 128 << 20,
                schedule,
                persistent: false,
            }));
        (signer, writer, parts, slow, fetcher)
    }

    async fn live_parts(store: &Arc<LocalObjectStore>, signer: &LocalPartSigner) -> Vec<PartRef> {
        PartLogView::open(store.as_ref(), TENANT, signer.trusted()).await.unwrap().live().parts().cloned().collect()
    }

    /// NAN-3690 acceptance: the gated warm-up fetches the
    /// rollup and entity-ranges partials of every part in the window before
    /// any data file (a 7d count at Ready reads only local rollups), then
    /// rediscovers once before latching warm, so a part the old writer
    /// committed during the warm-up is resident when the pod reports warm.
    #[tokio::test]
    async fn warm_partials_cover_the_window_and_refill_the_newest_hours_before_warm() {
        use crate::local_hot_window::WarmGate;
        let root = tempfile::tempdir().unwrap();
        let store = Arc::new(LocalObjectStore::new(&root.path().join("objects")).unwrap());
        let (signer, mut writer, parts, slow, fetcher) = partials_fixture(root.path(), &store, 4, true).await;
        hydrate(&fetcher, TENANT, live_parts(&store, &signer).await, &AtomicU64::new(0), Instant::now()).await.unwrap();
        let order = slow.order.lock().unwrap().clone();
        assert!(order.len() > 8, "{order:?}");
        assert!(order[..8].iter().all(|uri| uri.contains("/partial-")), "partials first: {order:?}");
        for (part, record) in &parts {
            for kind in [PartialKind::Rollup, PartialKind::EntityRanges] {
                assert!(fetcher.cache().is_local(&part_object(&fetcher, part, record, PartFile::Partial(kind))).await.unwrap());
            }
        }
        // Warm hours resident, but the first pass does not latch: it asks
        // for an immediate rediscovery.
        assert!(!fetcher.hot_coverage.lock().unwrap().warm_resident);
        assert_eq!(fetcher.hot_window_gate(), Some(WarmGate::Hydrating));
        assert!(fetcher.take_hot_rerun());
        assert!(!fetcher.take_hot_rerun(), "cleared on read");

        // The old pod's writer commits a part while this pod warms up.
        let now = pinned_now();
        let (late, late_record) =
            rollup_part(&store, &signer, 50, now.div_euclid(3_600_000_000) as i32, None, now / 1000, now).await;
        writer
            .append(
                LogOp::Add {
                    parts: vec![late.clone()],
                    consumed: vec![crate::parts::part_log::SourceRef {
                        key: "bronze/rollup-50.parquet".into(),
                        version: "1".into(),
                        sha256: "0".repeat(64),
                    }],
                    edge_log: None,
                },
                now / 1000,
            )
            .await
            .unwrap();
        hydrate(&fetcher, TENANT, live_parts(&store, &signer).await, &AtomicU64::new(0), Instant::now()).await.unwrap();
        assert!(fetcher.hot_coverage.lock().unwrap().warm_resident);
        assert_eq!(fetcher.hot_window_gate(), Some(WarmGate::Resident));
        assert!(!fetcher.take_hot_rerun(), "one rediscovery only");
        for file in [PartFile::Data(0), PartFile::Tokens(0), PartFile::Partial(PartialKind::Rollup)] {
            assert!(
                fetcher.cache().is_local(&part_object(&fetcher, &late, &late_record, file)).await.unwrap(),
                "the late part's {file:?} is resident before warm"
            );
        }
        // Later passes keep the latch and never ask for another rerun.
        hydrate(&fetcher, TENANT, live_parts(&store, &signer).await, &AtomicU64::new(0), Instant::now()).await.unwrap();
        assert!(fetcher.hot_coverage.lock().unwrap().warm_resident);
        assert!(!fetcher.take_hot_rerun());
    }

    /// NAN-3690: gate off, the pass order and the latch are unchanged:
    /// part by part, warm on the first pass, no rerun.
    #[tokio::test]
    async fn gate_off_keeps_part_order_and_latches_on_the_first_pass() {
        let root = tempfile::tempdir().unwrap();
        let store = Arc::new(LocalObjectStore::new(&root.path().join("objects")).unwrap());
        let (signer, _writer, _parts, slow, fetcher) = partials_fixture(root.path(), &store, 4, false).await;
        hydrate(&fetcher, TENANT, live_parts(&store, &signer).await, &AtomicU64::new(0), Instant::now()).await.unwrap();
        let order = slow.order.lock().unwrap().clone();
        assert!(order[0].contains("/data-") && order[1].contains("/tokens-") && order[2].contains("/partial-"), "{order:?}");
        assert!(fetcher.hot_coverage.lock().unwrap().warm_resident);
        assert!(!fetcher.take_hot_rerun());
    }

    /// NAN-3714 acceptance: a gated warm-up does not report warm until the
    /// metadata the first 7 d and 30 d counts plan from is resident: the
    /// rollup and entity-ranges partials of every part of [`PLAN_HOURS`]
    /// (beyond the 24 h hot window here; none older), and the data of the
    /// window's oldest hour (the 7 d count's ragged start) right after the
    /// partials. Data outside the window is never hydrated. The before-warm
    /// hook (the engine's memo prewarm) runs once, before the latch, with
    /// every plan part. And a plan partial that cannot be fetched holds warm.
    #[tokio::test]
    async fn warm_gate_waits_for_long_range_plan_metadata() {
        use crate::local_hot_window::WarmGate;
        // 0/1/5 h: newest; 23/24 h: the 24 h window's oldest hour (edge);
        // 100/400 h: plan-only (inside 30 d); 800 h: older than 30 d.
        let ages = [0_u64, 1, 5, 23, 24, 100, 400, 800];
        let root = tempfile::tempdir().unwrap();
        let store = Arc::new(LocalObjectStore::new(&root.path().join("objects")).unwrap());
        let (signer, _writer, parts, slow, fetcher) = partials_fixture_ages(root.path(), &store, &ages, true).await;
        let by_age = |age: u64| &parts[ages.iter().position(|a| *a == age).unwrap()];
        let local = |age: u64, file: PartFile| {
            let (part, record) = by_age(age);
            let object = part_object(&fetcher, part, record, file);
            let cache = fetcher.cache();
            async move { cache.is_local(&object).await.unwrap() }
        };
        let hooked = std::sync::Mutex::new(Vec::<(bool, usize)>::new());
        let hook = |plan: Vec<PartRef>| -> futures::future::BoxFuture<'_, ()> {
            let warm = fetcher.hot_coverage.lock().unwrap().warm_resident;
            hooked.lock().unwrap().push((warm, plan.len()));
            Box::pin(async {})
        };

        // A plan partial that cannot be fetched holds warm.
        let (missing_part, missing_record) = by_age(400);
        let missing = part_object(&fetcher, missing_part, missing_record, PartFile::Partial(PartialKind::Rollup));
        let key = crate::hot_tail_cache::parse_s3_uri(&missing.source_uri).unwrap().1.to_string();
        let body = store.get(&key).await.unwrap().unwrap();
        store.delete(&key).await.unwrap();
        for _ in 0..2 {
            hydrate_with(&fetcher, TENANT, live_parts(&store, &signer).await, &AtomicU64::new(0), Instant::now(), &hook)
                .await
                .unwrap();
            fetcher.take_hot_rerun();
        }
        assert!(!fetcher.hot_coverage.lock().unwrap().warm_resident, "a missing 30 d rollup holds warm");
        assert_eq!(fetcher.hot_window_gate(), Some(WarmGate::Hydrating));
        assert!(hooked.lock().unwrap().is_empty());
        store.put(&key, &body).await.unwrap();
        slow.order.lock().unwrap().clear();

        // First complete pass: plan metadata and the edge, then a rediscovery.
        hydrate_with(&fetcher, TENANT, live_parts(&store, &signer).await, &AtomicU64::new(0), Instant::now(), &hook)
            .await
            .unwrap();
        let order = slow.order.lock().unwrap().clone();
        let partials = order.iter().take_while(|uri| uri.contains("/partial-")).count();
        assert!(order[partials..].iter().all(|uri| !uri.contains("/partial-")), "partials first: {order:?}");
        for age in [0, 1, 5, 23, 24, 100, 400] {
            for kind in [PartialKind::Rollup, PartialKind::EntityRanges] {
                assert!(local(age, PartFile::Partial(kind)).await, "{age} h {kind:?} partial resident");
            }
        }
        for kind in [PartialKind::Rollup, PartialKind::EntityRanges] {
            assert!(!local(800, PartFile::Partial(kind)).await, "older than 30 d stays in R2");
        }
        for age in [100, 400, 800] {
            assert!(!local(age, PartFile::Data(0)).await, "{age} h data is outside the window");
        }
        // The window's oldest hour is fetched right after the partials,
        // before the newer parts' data.
        let data = order[partials..].iter().filter(|uri| uri.contains("/data-")).collect::<Vec<_>>();
        let edge_keys = [23_u64, 24].map(|age| {
            let (part, record) = by_age(age);
            part_object(&fetcher, part, record, PartFile::Data(0)).source_uri
        });
        assert!(data.len() >= 2 && edge_keys.contains(data[0]) && edge_keys.contains(data[1]), "edge data first: {data:?}");
        for age in [23, 24] {
            assert!(local(age, PartFile::Data(0)).await, "{age} h (oldest edge) data resident before warm");
        }
        assert!(!fetcher.hot_coverage.lock().unwrap().warm_resident);
        assert!(fetcher.take_hot_rerun());
        assert!(hooked.lock().unwrap().is_empty(), "no hook before the latch");

        // The rediscovery pass latches warm, after the hook ran once with
        // every part of 30 d (7: the 800 h part is not a plan part).
        hydrate_with(&fetcher, TENANT, live_parts(&store, &signer).await, &AtomicU64::new(0), Instant::now(), &hook)
            .await
            .unwrap();
        assert!(fetcher.hot_coverage.lock().unwrap().warm_resident);
        assert_eq!(fetcher.hot_window_gate(), Some(WarmGate::Resident));
        assert_eq!(*hooked.lock().unwrap(), vec![(false, 7)], "hook once, before warm, with the 30 d parts");
        hydrate_with(&fetcher, TENANT, live_parts(&store, &signer).await, &AtomicU64::new(0), Instant::now(), &hook)
            .await
            .unwrap();
        assert_eq!(hooked.lock().unwrap().len(), 1, "a latched pass does not run the hook again");
    }
}
