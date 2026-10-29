// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-3399: one worker-local merged identity observation index.
//!
//! A lookup read every identity source of its 30-day window: one entity-range
//! partial (or backfill file) per part, 468 on the load-test tenant. A partial is one
//! 65,536-row row group holding every entity path, so the pushed-down key
//! range (NAN-3394) pruned nothing and each file's `path` / `value` columns
//! were decoded in full, twice (lookup, then NAT): ~1.9 s per statement live,
//! growing with the number of parts.
//!
//! This process folds the identity rows of those sources into one Parquet
//! file sorted by `value` in small row groups, each row tagged with its
//! source's id (`src`, this file's own numbering). A lookup then reads:
//!
//! - the merged file, restricted to the sources it covers that are still
//!   live sources of the lookup (`has(live, src)`); the key range prunes it to
//!   a few row groups;
//! - the live sources it does not cover yet (the tail: parts written or
//!   merged since the last build), as before.
//!
//! The relation is exactly the one over the lookup's live sources: rows of a
//! source that left the window, was superseded or was deleted are filtered
//! out, never served. A source file is immutable, so a source is identified
//! by its [`SourceKey`] (a partial's part and content sha256, or a part's
//! backfill file, written once), never by the path this call read it at: a
//! leased partial's path is `pins/{lease}/{sha256}.bin`, new to every lease.
//!
//! The background identity pass ([`merge_once`]) rebuilds the file
//! incrementally (still-live merged rows plus the tail) once the tail or the
//! stale share grows. A build starts only while every query slot is free and
//! no durable job runs; the slot is held only to classify the sources, and
//! the statement itself runs on the read-write lane on one native thread, so
//! a search arriving mid-build is never queued behind it. A failed build
//! backs off ([`FAILURE_BACKOFF`]) instead of re-reading the window every
//! pass.
//!
//! `NANO_LAKE_IDENTITY_MERGED_INDEX=0` is the kill switch: no build, and
//! lookups read every source directly (the pre-NAN-3399 statements).

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use super::engine::{PartQueryEngine, QueryResult};
use super::identity::{Source, SourceKey};
use crate::identity_observations::{IDENTITY_PATH, LOOKBACK_US};

/// Kill switch (default on): `0` turns the merged index off for this process.
pub const FLAG: &str = "NANO_LAKE_IDENTITY_MERGED_INDEX";

/// Whether the merged index is on (anything but a literal `0`).
pub fn enabled() -> bool {
    enabled_from(std::env::var(FLAG).ok().as_deref())
}

fn enabled_from(value: Option<&str>) -> bool {
    value.map(str::trim) != Some("0")
}

/// After a failed build, passes skip the merge this long (a build reads the
/// whole window; a persistent failure must not repeat it every 5-60 s).
pub const FAILURE_BACKOFF: Duration = Duration::from_secs(15 * 60);

/// Merged files live here, beside (never inside) the backfill directory,
/// whose pass deletes every file that is not a live part's.
pub const DIR: &str = "identity-index/merged-v1";
const PREFIX: &str = "merged-";
/// Rebuild once this many live sources are outside the merged file (a
/// lookup decodes each of them in full), or once this many (and at least a
/// quarter) of its sources are no longer live.
pub const REBUILD_FILES: usize = 8;
/// Rows per row group of the merged file: small, so a key range touches a
/// few groups out of thousands.
pub const ROW_GROUP_ROWS: usize = 4_096;
/// The writer closes a row group at a block boundary once it holds
/// [`ROW_GROUP_ROWS`]; small blocks keep groups near that size (a sorted
/// block can otherwise be one 65,409-row group).
const WRITE_BLOCK_ROWS: usize = 1_024;

fn internal(error: impl std::fmt::Display) -> super::engine::PartQueryError {
    super::engine::internal_text(error.to_string())
}

fn ids_param(ids: &[u32]) -> String {
    format!("[{}]", ids.iter().map(u32::to_string).collect::<Vec<_>>().join(","))
}

/// One built merged file and the sources it covers (source key -> `src`
/// id). The file is removed when the last reader drops it.
#[derive(Debug)]
pub struct MergedIndex {
    path: PathBuf,
    sources: BTreeMap<SourceKey, u32>,
}

impl MergedIndex {
    pub fn new(path: PathBuf, sources: BTreeMap<SourceKey, u32>) -> Self {
        Self { path, sources }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn sources(&self) -> &BTreeMap<SourceKey, u32> {
        &self.sources
    }
}

impl Drop for MergedIndex {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

/// The engine's current merged file (none until the first build).
#[derive(Debug, Default)]
pub struct MergedSlot {
    current: Mutex<Option<Arc<MergedIndex>>>,
    swept: AtomicBool,
    build: tokio::sync::Mutex<()>,
    failed_at: Mutex<Option<Instant>>,
}

impl MergedSlot {
    pub fn current(&self) -> Option<Arc<MergedIndex>> {
        self.current.lock().expect("identity merged slot").clone()
    }

    /// The merged file a lookup may read: none while the kill switch is off
    /// (the process value, or this request's `identity_merged_index`
    /// override, NAN-3406; the build itself stays process-level).
    pub fn for_lookup(&self) -> Option<Arc<MergedIndex>> {
        if crate::perf_overrides::identity_merged_index(enabled()) { self.current() } else { None }
    }

    fn replace(&self, next: MergedIndex) {
        let previous = self.current.lock().expect("identity merged slot").replace(Arc::new(next));
        // Removed here, or by the last lookup still reading it.
        drop(previous);
    }

    /// Drop the current file (nothing live left in the window): removed
    /// once no lookup reads it, instead of kept until restart.
    fn clear(&self) {
        let previous = self.current.lock().expect("identity merged slot").take();
        drop(previous);
    }

    fn backing_off(&self, now: Instant) -> bool {
        self.failed_at.lock().expect("identity merged failure").is_some_and(|at| now.saturating_duration_since(at) < FAILURE_BACKOFF)
    }

    fn record_failure(&self, now: Option<Instant>) {
        *self.failed_at.lock().expect("identity merged failure") = now;
    }
}

/// What one statement reads for `files` (a lookup's live sources).
#[derive(Debug)]
pub struct Scan {
    /// Sources read directly.
    pub tail: Vec<Source>,
    /// The merged file and the ids of the live sources it serves.
    pub merged: Option<(Arc<MergedIndex>, Vec<u32>)>,
}

pub fn scan(merged: Option<Arc<MergedIndex>>, files: &[Source]) -> Scan {
    let Some(merged) = merged else {
        return Scan { tail: files.to_vec(), merged: None };
    };
    let mut live = Vec::new();
    let mut tail = Vec::new();
    for file in files {
        match merged.sources.get(&file.key) {
            Some(id) => live.push(*id),
            None => tail.push(file.clone()),
        }
    }
    live.sort_unstable();
    live.dedup();
    let merged = (!live.is_empty()).then_some((merged, live));
    Scan { tail, merged }
}

/// Whether a build over `files` is due.
pub fn needs_rebuild(merged: Option<&MergedIndex>, files: &[Source]) -> bool {
    let Some(merged) = merged else {
        return files.len() >= REBUILD_FILES;
    };
    let tail = files.iter().filter(|file| !merged.sources.contains_key(&file.key)).count();
    let live = files
        .iter()
        .filter(|file| merged.sources.contains_key(&file.key))
        .map(|file| &file.key)
        .collect::<std::collections::BTreeSet<_>>()
        .len();
    let stale = merged.sources.len() - live;
    tail >= REBUILD_FILES || stale >= REBUILD_FILES.max(merged.sources.len() / 4)
}

/// Tail sources of a build, numbered after the previous file's live ones.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BuildTail {
    /// A path spec over the tail sources.
    pub spec: String,
    /// Each tail source's path as given, and as the filesystem resolves it
    /// (chDB's `_path` is either); `src` of the i-th is `first_id + i`.
    pub paths: Vec<String>,
    pub canonical: Vec<String>,
    pub first_id: u32,
}

/// The rows a build writes: the still-live rows of the previous merged file
/// (`(path, old ids, new ids)`, renumbered) plus the tail sources' identity
/// rows, sorted by `(value, src)`. A tail row whose source path is not one
/// of the build's fails the statement instead of being written under a
/// wrong id.
/// `settings` is appended verbatim (it starts with ` SETTINGS`).
pub fn plan_build(
    tail: Option<&BuildTail>, previous: Option<(&str, &[u32], &[u32])>, settings: &str,
) -> QueryResult<(String, Vec<(String, String)>)> {
    let mut arms = Vec::new();
    let mut params = vec![("identity_path".to_string(), IDENTITY_PATH.to_string())];
    if let Some(tail) = tail {
        arms.push(
            "SELECT value, first_time, last_time, \
                    toUInt32(if(has({merge_paths:Array(String)}, _path), indexOf({merge_paths:Array(String)}, _path), \
                                indexOf({merge_canonical:Array(String)}, _path))) AS source_position, \
                    toUInt32({merge_first_id:UInt32} + source_position - 1 \
                             + throwIf(source_position = 0, 'identity merge read a row of an unknown source')) AS merged_src \
             FROM file({merge_sources:String}, Parquet) WHERE path = {identity_path:String} AND value != ''"
                .to_string(),
        );
        params.push(("merge_sources".to_string(), tail.spec.clone()));
        params.push(("merge_paths".to_string(), super::identity::strings_param(&tail.paths)));
        params.push(("merge_canonical".to_string(), super::identity::strings_param(&tail.canonical)));
        params.push(("merge_first_id".to_string(), tail.first_id.to_string()));
    }
    // A failing check is never a filter: a pushed-down filter may run
    // before the arm's own `has` and see rows it drops. The previous file's
    // rows outside `merge_old` are dropped, so `transform` never yields 0.
    if let Some((path, old, new)) = previous {
        if old.len() != new.len() {
            return Err(internal("identity merge renumbering is not one to one"));
        }
        arms.push(
            "SELECT value, first_time, last_time, toUInt32(1) AS source_position, \
                    transform(src, {merge_old:Array(UInt32)}, {merge_new:Array(UInt32)}, toUInt32(0)) AS merged_src \
             FROM file({merge_previous:String}, Parquet) WHERE has({merge_old:Array(UInt32)}, src)"
                .to_string(),
        );
        params.push(("merge_previous".to_string(), path.to_string()));
        params.push(("merge_old".to_string(), ids_param(old)));
        params.push(("merge_new".to_string(), ids_param(new)));
    }
    if arms.is_empty() {
        return Err(internal("identity merge has no input"));
    }
    let sql = format!(
        "INSERT INTO FUNCTION file({{merge_output:String}}, Parquet) \
         SELECT value, first_time, last_time, merged_src AS src FROM ({}) \
         ORDER BY value, src{settings}, output_format_parquet_row_group_size={ROW_GROUP_ROWS}, \
         max_block_size={WRITE_BLOCK_ROWS}",
        arms.join(" UNION ALL ")
    );
    Ok((sql, params))
}

/// What one merge pass did.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct MergeReport {
    pub built: bool,
    /// Sources the current merged file covers after the pass.
    pub sources: usize,
    /// Sources the build read directly.
    pub tail: usize,
}

fn path_text(path: &Path) -> QueryResult<String> {
    path.to_str().map(ToOwned::to_owned).ok_or_else(|| internal("identity source path is not UTF-8"))
}

/// One merge pass over the lookback window ending at `now_us`: rebuild the
/// merged file when [`needs_rebuild`] says so. Single-flight; starts only
/// while every query slot is free and no durable job runs (never delays a
/// search: the slot is released before the statement, which runs on the
/// read-write lane on one native thread). A no-op, beside a one-time sweep of
/// an earlier process's files, while the kill switch is off.
pub async fn merge_once(engine: &PartQueryEngine, state_dir: &Path, now_us: i64) -> QueryResult<MergeReport> {
    let slot = engine.identity_merged();
    let Ok(_build) = slot.build.try_lock() else {
        return Ok(MergeReport::default());
    };
    let dir = state_dir.join(DIR);
    if !slot.swept.swap(true, Ordering::SeqCst) {
        // Files of an earlier process are never read: their coverage lived
        // in that process's memory.
        let _ = std::fs::remove_dir_all(&dir);
    }
    if !enabled() {
        slot.clear();
        return Ok(MergeReport::default());
    }
    let current = slot.current();
    let unchanged = |current: &Option<Arc<MergedIndex>>| MergeReport {
        sources: current.as_ref().map_or(0, |merged| merged.sources.len()),
        ..MergeReport::default()
    };
    if slot.backing_off(Instant::now()) || engine.job_running() {
        return Ok(unchanged(&current));
    }
    let Some(admission) = engine.try_admit_idle() else {
        return Ok(unchanged(&current));
    };
    // NAN-4799: classify without leasing memoized partials; only the tail a
    // due build reads is leased (below).
    let sources = super::identity::index_sources_leasing(engine, state_dir, now_us.saturating_sub(LOOKBACK_US), now_us,
        super::identity::Leasing::Unscanned).await?;
    let mut files = sources.all();
    files.sort_by(|a, b| a.key.cmp(&b.key));
    files.dedup_by(|a, b| a.key == b.key);
    if files.is_empty() {
        // Nothing live in the window: nothing to serve, nothing to keep.
        drop(current);
        slot.clear();
        return Ok(MergeReport::default());
    }
    if !needs_rebuild(current.as_deref(), &files) {
        return Ok(unchanged(&current));
    }
    let mut plan = scan(current, &files);
    let tail_lease = sources.lease_partials(engine, &mut plan.tail).await?;
    // New numbering: the previous file's live sources first, then the tail.
    let mut covered = BTreeMap::new();
    let mut renumber = (Vec::new(), Vec::new());
    if let Some((merged, _)) = &plan.merged {
        for file in &files {
            if let Some(old) = merged.sources.get(&file.key) {
                let new = covered.len() as u32 + 1;
                covered.insert(file.key.clone(), new);
                renumber.0.push(*old);
                renumber.1.push(new);
            }
        }
    }
    let tail = if plan.tail.is_empty() {
        None
    } else {
        let first_id = covered.len() as u32 + 1;
        let mut paths = Vec::with_capacity(plan.tail.len());
        let mut canonical = Vec::with_capacity(plan.tail.len());
        let mut tail_paths = Vec::with_capacity(plan.tail.len());
        for file in &plan.tail {
            // Keyed by identity; read at this lease's path.
            covered.insert(file.key.clone(), covered.len() as u32 + 1);
            paths.push(path_text(&file.path)?);
            canonical.push(path_text(&std::fs::canonicalize(&file.path).unwrap_or_else(|_| file.path.clone()))?);
            tail_paths.push(file.path.clone());
        }
        Some(BuildTail { spec: super::partials::path_set(&tail_paths)?, paths, canonical, first_id })
    };
    let previous = match &plan.merged {
        Some((merged, _)) => Some(path_text(merged.path())?),
        None => None,
    };
    std::fs::create_dir_all(&dir).map_err(internal)?;
    let id = uuid::Uuid::new_v4().simple();
    let temporary = dir.join(format!(".{PREFIX}{id}.tmp"));
    let target = dir.join(format!("{PREFIX}{id}.parquet"));
    let (sql, mut params) = plan_build(
        tail.as_ref(),
        previous.as_deref().map(|path| (path, renumber.0.as_slice(), renumber.1.as_slice())),
        &super::partials::statement_settings(engine),
    )?;
    params.push(("merge_output".to_string(), path_text(&temporary)?));
    // The slot only gated the start: the statement runs on the read-write
    // lane, so a search arriving now is admitted at once.
    drop(admission);
    let started = std::time::Instant::now();
    let result = super::product_state::BUILD
        .scope((), engine.with_job_statements(engine.run_sql(sql, params)))
        .await
        .map_err(internal)
        .and_then(|_| std::fs::rename(&temporary, &target).map_err(internal));
    if let Err(error) = result {
        // Never published: the next read is the previous file or the sources.
        let _ = std::fs::remove_file(&temporary);
        slot.record_failure(Some(Instant::now()));
        return Err(error);
    }
    slot.record_failure(None);
    let report = MergeReport { built: true, sources: covered.len(), tail: plan.tail.len() };
    tracing::info!(sources = report.sources, tail = report.tail, wall_ms = started.elapsed().as_millis() as u64,
        "identity observation index merged");
    drop(plan);
    slot.replace(MergedIndex::new(target, covered));
    drop(tail_lease);
    drop(sources);
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn merged(dir: &Path, sources: &[&str]) -> Arc<MergedIndex> {
        let path = dir.join(format!("merged-{}.parquet", uuid::Uuid::new_v4().simple()));
        std::fs::write(&path, b"").unwrap();
        let sources = sources.iter().enumerate().map(|(n, name)| (source(name).key, n as u32 + 1)).collect();
        Arc::new(MergedIndex::new(path, sources))
    }

    fn part(name: &str) -> crate::parts::format::PartId {
        let digest = crate::parts::sha256_hex(name.as_bytes());
        crate::parts::format::PartId::parse(&format!("{:013}-{}", 1, &digest[..16])).unwrap()
    }

    /// A partial leased under `lease`: the real reader layout
    /// (`pins/{lease}/{sha256}.bin`), a new directory per lease.
    fn source_in(name: &str, lease: &str) -> Source {
        let sha256 = crate::parts::sha256_hex(format!("partial {name}").as_bytes());
        let path = PathBuf::from(format!("/cache/pins/{lease}/{sha256}.bin"));
        Source { key: SourceKey::Partial { part: part(name), sha256 }, path }
    }

    fn source(name: &str) -> Source {
        source_in(name, "lease-0")
    }

    fn sources(names: &[&str]) -> Vec<Source> {
        names.iter().map(|name| source(name)).collect()
    }

    fn sources_in(names: &[&str], lease: &str) -> Vec<Source> {
        names.iter().map(|name| source_in(name, lease)).collect()
    }

    #[test]
    fn sources_found_again_under_a_new_lease_stay_covered() {
        // NAN-3399 follow-up (live, the load-test tenant): every pass leased the window's
        // partials into a new `pins/{lease}/` directory, so a merged index
        // keyed by path matched only the backfill files (3 of ~175): every
        // pass rebuilt from ~172 "new" sources and every lookup read them
        // all directly (lookup 1.15 s, NAT 1.07 s). Coverage is by source
        // identity, not by where this call found the file.
        let dir = tempfile::tempdir().unwrap();
        let names = (0..40).map(|i| format!("s{i}")).collect::<Vec<_>>();
        let refs = names.iter().map(String::as_str).collect::<Vec<_>>();
        let mut built = refs.iter().enumerate().map(|(n, name)| (source_in(name, "build-lease").key, n as u32 + 1))
            .collect::<BTreeMap<_, _>>();
        let backfill = Source { key: SourceKey::Backfill(part("old")), path: PathBuf::from("/state/identity-index/old.parquet") };
        built.insert(backfill.key.clone(), 41);
        let path = dir.path().join("merged-1.parquet");
        std::fs::write(&path, b"").unwrap();
        let current = Arc::new(MergedIndex::new(path, built));
        let mut next = sources_in(&refs, "next-lease");
        next.push(backfill.clone());
        assert!(next.iter().all(|file| !file.path.starts_with("/cache/pins/build-lease")), "every partial path changed");
        assert!(!needs_rebuild(Some(&current), &next), "same sources under new paths: no rebuild");
        let plan = scan(Some(current), &next);
        assert!(plan.tail.is_empty(), "nothing read directly: {:?}", plan.tail);
        let (_, live) = plan.merged.expect("served from the merged file");
        assert_eq!(live, (1..=41).collect::<Vec<_>>());
    }

    #[test]
    fn a_rewritten_partial_of_the_same_part_is_a_new_source() {
        // Same part, new bytes (a new sha256): never served from rows of the
        // old file.
        let dir = tempfile::tempdir().unwrap();
        let current = merged(dir.path(), &["a"]);
        let mut rewritten = source("a");
        if let SourceKey::Partial { sha256, .. } = &mut rewritten.key {
            *sha256 = crate::parts::sha256_hex(b"rewritten");
        }
        let plan = scan(Some(current), std::slice::from_ref(&rewritten));
        assert!(plan.merged.is_none());
        assert_eq!(plan.tail, vec![rewritten]);
    }

    #[test]
    fn a_lookup_reads_the_merged_file_for_covered_sources_and_only_the_tail_directly() {
        // NAN-3399: every lookup decoded every source of the window in full
        // (468 live). With a merged file, only sources it does not cover yet
        // are read directly, and only covered sources still live are served
        // from it.
        let dir = tempfile::tempdir().unwrap();
        let files = sources(&["a", "b", "c", "new"]);
        let without = scan(None, &files);
        assert_eq!(without.tail, files, "no merged file: every source is read");
        let plan = scan(Some(merged(dir.path(), &["a", "gone", "b", "c"])), &files);
        assert_eq!(plan.tail, sources(&["new"]));
        let (_, live) = plan.merged.expect("merged file serves covered sources");
        assert_eq!(live, vec![1, 3, 4], "a source that is no longer live is never served");
        let disjoint = scan(Some(merged(dir.path(), &["gone"])), &files);
        assert!(disjoint.merged.is_none(), "nothing live in the merged file: it is not read");
        assert_eq!(disjoint.tail, files);
    }

    #[test]
    fn rebuilds_when_the_tail_or_the_stale_share_grows() {
        let dir = tempfile::tempdir().unwrap();
        let names = (0..40).map(|i| format!("s{i}")).collect::<Vec<_>>();
        let refs = names.iter().map(String::as_str).collect::<Vec<_>>();
        assert!(!needs_rebuild(None, &sources(&refs[..REBUILD_FILES - 1])), "a few sources are cheap to read directly");
        assert!(needs_rebuild(None, &sources(&refs[..REBUILD_FILES])));
        let current = merged(dir.path(), &refs[..32]);
        assert!(!needs_rebuild(Some(&current), &sources(&refs[..32])));
        assert!(!needs_rebuild(Some(&current), &sources(&refs[..32 + REBUILD_FILES - 1])));
        assert!(needs_rebuild(Some(&current), &sources(&refs[..32 + REBUILD_FILES])), "tail");
        assert!(!needs_rebuild(Some(&current), &sources(&refs[REBUILD_FILES - 1..32])));
        assert!(needs_rebuild(Some(&current), &sources(&refs[REBUILD_FILES..32])), "stale");
    }

    /// NAN-3406: an authorized per-request `identity_merged_index` override
    /// picks the lookup path (merged file or every source directly) either
    /// way; without one the lookup follows the process value.
    #[test]
    fn identity_merged_override_picks_the_lookup_path_per_request() {
        use crate::perf_overrides::{sync_scoped, Overrides};
        let dir = tempfile::tempdir().unwrap();
        let slot = MergedSlot::default();
        let path = dir.path().join("merged-1.parquet");
        std::fs::write(&path, b"x").unwrap();
        let files = sources(&["a", "b"]);
        slot.replace(MergedIndex::new(path, files.iter().enumerate().map(|(n, file)| (file.key.clone(), n as u32 + 1)).collect()));
        let identity = |value: Option<bool>| Overrides { identity_merged_index: value, ..Overrides::default() };
        let off = sync_scoped(identity(Some(false)), || scan(slot.for_lookup(), &files));
        assert!(off.merged.is_none());
        assert_eq!(off.tail, files, "override off: every source read directly");
        let on = sync_scoped(identity(Some(true)), || scan(slot.for_lookup(), &files));
        assert!(on.merged.is_some() && on.tail.is_empty(), "override on: the merged file");
        // No override: the process value (default on).
        assert_eq!(slot.for_lookup().is_some(), enabled());
        assert_eq!(sync_scoped(identity(None), || slot.for_lookup().is_some()), enabled());
    }

    #[test]
    fn a_replaced_merged_file_is_removed_after_its_last_reader() {
        let dir = tempfile::tempdir().unwrap();
        let slot = MergedSlot::default();
        let first = dir.path().join("merged-1.parquet");
        std::fs::write(&first, b"x").unwrap();
        slot.replace(MergedIndex::new(first.clone(), BTreeMap::new()));
        let reader = slot.current().unwrap();
        slot.replace(MergedIndex::new(dir.path().join("merged-2.parquet"), BTreeMap::new()));
        assert!(first.is_file(), "a lookup still reading it keeps it");
        drop(reader);
        assert!(!first.exists());
    }

    #[test]
    fn kill_switch_is_on_unless_literal_zero() {
        assert!(enabled_from(None), "default on");
        assert!(enabled_from(Some("1")));
        assert!(enabled_from(Some("")));
        assert!(!enabled_from(Some("0")));
        assert!(!enabled_from(Some(" 0 ")));
    }

    #[test]
    fn a_failed_build_backs_off_and_a_success_clears_it() {
        let slot = MergedSlot::default();
        let now = Instant::now();
        assert!(!slot.backing_off(now));
        slot.record_failure(Some(now));
        assert!(slot.backing_off(now + Duration::from_secs(60)), "no full-window rebuild every pass after a failure");
        assert!(!slot.backing_off(now + FAILURE_BACKOFF));
        slot.record_failure(None);
        assert!(!slot.backing_off(now));
    }

    #[test]
    fn clearing_the_slot_removes_the_file_after_its_last_reader() {
        // A window with no live sources left must not keep a stale file
        // (and its disk) until restart.
        let dir = tempfile::tempdir().unwrap();
        let slot = MergedSlot::default();
        let file = dir.path().join("merged-1.parquet");
        std::fs::write(&file, b"x").unwrap();
        slot.replace(MergedIndex::new(file.clone(), BTreeMap::new()));
        let reader = slot.current().unwrap();
        slot.clear();
        assert!(slot.current().is_none());
        assert!(file.is_file());
        drop(reader);
        assert!(!file.exists());
    }

    #[test]
    fn build_numbers_tail_rows_and_keeps_only_live_merged_rows() {
        let tail = BuildTail { spec: "/c/{x,y}".into(), paths: vec!["/c/x".into(), "/c/y".into()], canonical: vec!["/r/x".into(), "/r/y".into()], first_id: 3 };
        let (sql, params) = plan_build(Some(&tail), Some(("/s/merged-1.parquet", &[4, 9], &[1, 2])), " SETTINGS max_threads=1").unwrap();
        assert!(sql.starts_with("INSERT INTO FUNCTION file({merge_output:String}, Parquet)"), "{sql}");
        assert!(sql.contains("WHERE path = {identity_path:String} AND value != ''"), "{sql}");
        assert!(sql.contains("WHERE has({merge_old:Array(UInt32)}, src)"), "{sql}");
        assert!(sql.contains("throwIf(source_position = 0"), "an unknown source fails the build: {sql}");
        assert!(sql.contains("ORDER BY value, src SETTINGS max_threads=1, output_format_parquet_row_group_size=4096, max_block_size=1024"), "{sql}");
        let map = params.into_iter().collect::<std::collections::BTreeMap<_, _>>();
        assert_eq!(map["merge_old"], "[4,9]");
        assert_eq!(map["merge_new"], "[1,2]");
        assert_eq!(map["merge_paths"], "['/c/x','/c/y']");
        assert_eq!(map["merge_first_id"], "3");
        assert!(plan_build(None, None, "").is_err());
        assert!(plan_build(None, Some(("/s/m", &[1], &[])), "").is_err());
        let (tail_only, _) = plan_build(Some(&tail), None, "").unwrap();
        assert!(!tail_only.contains("merge_previous"));
    }
}
