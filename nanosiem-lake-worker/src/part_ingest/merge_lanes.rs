// SPDX-License-Identifier: AGPL-3.0-or-later
//! Independent bounded merge lanes; overlapping event hours stay serialized.
use crate::parts::levels::{Level, PlannedMerge};

/// Concurrency and reservations share the role boundary used by the running
/// memory guard. Small roles keep one history operation, including rewrites;
/// the remaining room belongs to minute compaction and admission.
#[derive(Debug, Clone, Copy)]
pub struct MergeCapacity {
    pub cpu_millicores: u32,
    pub memory_bytes: u64,
    pub minute_bytes: u64,
    pub history_bytes: u64,
    pub minute_slots: usize,
    pub history_slots: usize,
}

impl MergeCapacity {
    pub fn read() -> Self {
        #[cfg(test)]
        if let Some(capacity) = CAPACITY_FOR_TEST.get() { return capacity; }
        let memory = MemorySnapshot::read();
        let role = crate::cgroup_memory::process_capacity();
        Self::for_role(guard_limit(memory.cgroup_limit_bytes, memory.limit_bytes).or(Some(role.memory_bytes)),
            role.cpu_millicores)
    }

    pub fn for_role(memory: Option<u64>, cpu_millicores: u32) -> Self {
        const GIB: u64 = 1024 * 1024 * 1024;
        // With no cgroup or assignment ceiling (unlimited labs), use the
        // cell's existing host detector rather than inventing a small cap.
        let memory_bytes = memory.unwrap_or_else(|| crate::cgroup_memory::process_capacity().memory_bytes);
        // Reuse the existing merge-reserve decode window and add a writer.
        // The measured 8-input minute merge peaked at 136 MiB with a
        // 320 MiB window (merge::merge_reserve_bytes); triple-charging the
        // window would cut small roles to one minute slot and fail catch-up.
        let minute_bytes = (super::merge::decode_window_rows_for(memory_bytes) as u64)
            .saturating_mul(super::merge::MERGE_ROW_BYTES)
            .saturating_add(super::memory::L0_WRITER_BYTES);
        // FP measured ~2.6 GB growth per hour merge. 3 GiB bounds the
        // reservation on larger roles; small roles scale down and retain the
        // existing shape/split planner and running guard. Keep 20% for minute
        // compaction and 20% outside the merge pool for admission.
        let history_pool = memory_bytes.saturating_mul(60) / 100;
        let history_bytes = history_pool.min(3 * GIB).max(1);
        let cpu_slots = (cpu_millicores / 2000).max(1) as usize;
        let minute_slots = ((memory_bytes / 5 / minute_bytes).max(1) as usize).min(cpu_slots);
        let history_slots = ((history_pool / history_bytes).max(1) as usize).min(cpu_slots);
        Self { cpu_millicores, memory_bytes, minute_bytes, history_bytes, minute_slots, history_slots }
    }

    fn reservation(&self, level: Level) -> u64 {
        if level == Level::Minute { self.minute_bytes } else { self.history_bytes }
    }

    /// Keep the two minute lanes required by the catch-up service-rate
    /// regression available while long-running history jobs borrow capacity.
    pub fn minute_progress_slots(&self) -> usize {
        self.minute_slots.min(2)
    }

    /// Charge not-yet-resident peaks too: several jobs can be launched on
    /// one tick before memory.current reflects any of their allocations.
    pub fn fits<'a>(&self, level: Level, active: impl Iterator<Item = &'a PlannedMerge>) -> bool {
        let (mut reserved, minutes) = active.fold((self.reservation(level), 0_usize), |(sum, minutes), merge|
            (sum.saturating_add(self.reservation(merge.output_level)), minutes + usize::from(merge.output_level == Level::Minute)));
        if level != Level::Minute {
            reserved = reserved.saturating_add(self.minute_bytes.saturating_mul(
                self.minute_progress_slots().saturating_sub(minutes) as u64));
        }
        reserved <= self.memory_bytes.saturating_mul(80) / 100
    }
}

#[cfg(test)]
thread_local! {
    static CAPACITY_FOR_TEST: std::cell::Cell<Option<MergeCapacity>> = const { std::cell::Cell::new(None) };
}

#[cfg(test)]
pub struct TestCapacity(Option<MergeCapacity>);
#[cfg(test)]
impl Drop for TestCapacity {
    fn drop(&mut self) { CAPACITY_FOR_TEST.set(self.0); }
}
#[cfg(test)]
pub fn test_capacity(capacity: MergeCapacity) -> TestCapacity {
    TestCapacity(CAPACITY_FOR_TEST.replace(Some(capacity)))
}

#[cfg(test)]
#[path = "merge_capacity_tests.rs"]
mod capacity_tests;

/// Supersedes the minute/history concurrency environment overrides: a fixed
/// override cannot safely reserve memory across lanes and count rewrites.
pub fn capacity(level: Level) -> usize {
    let capacity = MergeCapacity::read();
    if level == Level::Minute { capacity.minute_slots } else { capacity.history_slots }
}

/// The order one scheduling pass offers due merges to the lanes (NAN-3400).
///
/// * Minute lane first, newest hour first (unchanged): fresh L0s.
/// * History lane: `h` merges before day merges, then the merge with the
///   most inputs first, then the newest hour. Every input a merge removes is
///   one file fewer for every search over that hour, so a sealed hour left
///   as ~50 minute parts outranks an old hour that a late backfill gave one
///   extra part.
///
/// The history lane used to drain oldest hour first. On the load-test tenant
/// (2026-10-09) a backfill put one late part into ~100 old hours, each
/// rewrite took ~18 min on two lanes, and every hour sealed since then stayed
/// at ~50 parts behind that queue for 8+ hours: the 1d window read 349 files
/// instead of ~25, and 1d search p50 went from 1.2 s to 3.0 s.
#[cfg(test)]
pub fn launch_order(planned: &mut [PlannedMerge]) {
    launch_order_at(planned, i64::MIN);
}

/// [`launch_order`] at `now_ms`. NAN-4750: the `h` merge of a just-closed
/// hour ([`is_fresh_hour_merge`]) goes first in the history lane, ahead of
/// fragmented older hours: it is the hour agents hunt next, and until it
/// merges its rows sit in unlabelled minute parts and mixed L0s that a
/// class-filtered query cannot skip.
pub fn launch_order_at(planned: &mut [PlannedMerge], now_ms: i64) {
    use std::cmp::Reverse;
    planned.sort_by_key(|merge| match merge.output_level {
        Level::Minute => (0_u8, Reverse(0_usize), Reverse(merge.event_hour)),
        Level::Day => (3, Reverse(merge.inputs.len()), Reverse(merge.event_hour)),
        _ if is_fresh_hour_merge(merge, now_ms) => (1, Reverse(0), Reverse(merge.event_hour)),
        _ => (2, Reverse(merge.inputs.len()), Reverse(merge.event_hour)),
    });
}

/// NAN-4750: an hour counts as just closed for this long after its end.
/// It covers the seal (`hour_seal_ms`, 10 min) and the settle defer cap
/// (`sealed_remerge_max_defer_ms`, 30 min) with room to spare, and is short
/// enough that only the latest one or two hours ever qualify.
pub const FRESH_HOUR_MERGE_WINDOW_MS: i64 = 60 * 60_000;

/// NAN-4750: `merge` is the `h` merge of an hour that ended less than
/// [`FRESH_HOUR_MERGE_WINDOW_MS`] before `now_ms`. Such a merge goes first
/// in the history lane ([`launch_order_at`]), may run while rows are
/// buffered (not during a catch-up), and has one lane slot of its own
/// ([`available_at`]), so it never queues behind backfill rewrites.
pub fn is_fresh_hour_merge(merge: &PlannedMerge, now_ms: i64) -> bool {
    if merge.output_level != Level::Hour {
        return false;
    }
    let end_ms = (i64::from(merge.event_hour) + 1) * 3_600_000;
    now_ms >= end_ms && now_ms - end_ms < FRESH_HOUR_MERGE_WINDOW_MS
}

/// NAN-4750: a fresh hour merge may run beside admission (rows buffered)
/// unless ingest is catching up, only while no other fresh hour merge is in
/// flight, and only with the cgroup headroom of a further history merge
/// (`memory_admits`, [`history_memory_admits`]) even when it is the first
/// one: beside a live buffer it must not be the merge that tips the role
/// into an OOM (NAN-4755). Lane and budget gates still apply.
pub fn fresh_runs_beside_admission<'a>(merge: &PlannedMerge, now_ms: i64, catching_up: bool,
    mut in_flight: impl Iterator<Item = &'a PlannedMerge>, memory_admits: impl FnOnce() -> bool) -> bool {
    !catching_up && is_fresh_hour_merge(merge, now_ms) && in_flight.all(|m| !is_fresh_hour_merge(m, now_ms))
        && memory_admits()
}

/// NAN-4674: while ingest catches up (or rows are buffered) history merges
/// wait, except a merge consolidating a fragmented hour
/// ([`crate::parts::levels::is_fragmented_hour_merge`]) when no history
/// merge is in flight: one at a time, beside the minute lane, so admission
/// keeps the rest of the cell. A backfill whose objects span many hours adds
/// a part to every hour it spans on every flush, and the catch-up lasts as
/// long as the backfill: without this, nothing bounded those hours.
pub fn fragmented_runs_beside_admission<'a>(merge: &PlannedMerge, mut in_flight: impl Iterator<Item = &'a PlannedMerge>) -> bool {
    crate::parts::levels::is_fragmented_hour_merge(merge) && in_flight.all(|m| m.output_level == Level::Minute)
}

pub fn overlaps(left: &PlannedMerge, right: &PlannedMerge) -> bool {
    let range = |merge: &PlannedMerge| {
        let first = merge.event_hour;
        let last = if merge.output_level == Level::Day {
            first.saturating_add(23)
        } else {
            first
        };
        (first, last)
    };
    let (a, b) = range(left);
    let (c, d) = range(right);
    a <= d && c <= b
        || left
            .inputs
            .iter()
            .any(|a| right.inputs.iter().any(|b| a.part_id == b.part_id))
}

#[cfg(test)]
pub fn available(merge: &PlannedMerge, active: &[&PlannedMerge]) -> bool {
    available_with(merge, active, capacity(merge.output_level), || {
        history_memory_admits(MemorySnapshot::read())
    })
}

/// [`available`] at `now_ms`. NAN-4750: one fresh hour merge
/// ([`is_fresh_hour_merge`]) at a time gets a history slot beyond
/// [`capacity`], so long backfill rewrites holding both lanes (~15-18 min
/// each) do not delay it; as a further history merge it still needs the
/// memory headroom, and a day merge still runs alone.
pub fn available_at(merge: &PlannedMerge, active: &[&PlannedMerge], now_ms: i64) -> bool {
    let sizing = MergeCapacity::read();
    if !sizing.fits(merge.output_level, active.iter().copied()) { return false; }
    let reserved = sizing.history_slots > 1 && is_fresh_hour_merge(merge, now_ms) && active.iter().all(|m| !is_fresh_hour_merge(m, now_ms));
    available_with(merge, active, capacity(merge.output_level) + usize::from(reserved), || {
        history_memory_admits(MemorySnapshot::read())
    })
}

/// [`available`] with the lane capacity and the memory probe supplied (the
/// probe runs only for a second-or-later concurrent history merge).
pub fn available_with(
    merge: &PlannedMerge,
    active: &[&PlannedMerge],
    capacity: usize,
    memory_admits: impl FnOnce() -> bool,
) -> bool {
    let minute = merge.output_level == Level::Minute;
    let same_lane = active
        .iter()
        .filter(|m| (m.output_level == Level::Minute) == minute)
        .collect::<Vec<_>>();
    if same_lane.len() >= capacity || active.iter().any(|m| overlaps(merge, m)) {
        return false;
    }
    if minute || same_lane.is_empty() {
        return true;
    }
    // A further history lane is only for sealed `h` merges side by side:
    // a day merge (24 hours of inputs) always runs alone.
    merge.output_level == Level::Hour
        && same_lane.iter().all(|m| m.output_level == Level::Hour)
        && memory_admits()
}

/// A further history merge starts only while the cgroup working set plus
/// the role-derived history reservation stays under this share of memory.max.
pub const HISTORY_MEMORY_CEILING: f64 = 0.80;

/// This process's memory: working set (its cgroup's usage minus inactive
/// file cache, as container monitoring counts it; else VmRSS) and limit (the
/// lower of its own cgroup's memory.max and the assignment's memory cap);
/// `None` when unknown.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MemorySnapshot {
    pub working_set_bytes: Option<u64>,
    pub limit_bytes: Option<u64>,
    /// NAN-4796: this process's own cgroup `memory.max` alone (the kernel's
    /// OOM boundary), without the assignment's sizing cap.
    pub cgroup_limit_bytes: Option<u64>,
}

impl MemorySnapshot {
    pub fn read() -> Self {
        Self::read_for(false)
    }

    fn read_for(guard: bool) -> Self {
        Self::read_cgroup(crate::cgroup_memory::for_process(),
            super::merge::memory_cap_bytes(), guard,
            || std::fs::read_to_string("/proc/self/status").ok())
    }

    #[cfg(test)]
    fn read_from(root: &std::path::Path, membership: &str, assignment_cap: Option<u64>, guard: bool,
        status: impl FnOnce() -> Option<String>) -> Self {
        Self::read_cgroup(crate::cgroup_memory::resolve(root, membership, "", None),
            assignment_cap, guard, status)
    }

    fn read_cgroup(cgroup: crate::cgroup_memory::MemoryCgroup, assignment_cap: Option<u64>, guard: bool,
        status: impl FnOnce() -> Option<String>) -> Self {
        let read = |path: &std::path::Path| cgroup.read(path);
        let number = |s: Option<String>| s.and_then(|s| s.trim().parse::<u64>().ok());
        let limit = cgroup.limit();
        let cgroup_limit = limit.as_ref().map(|limit| limit.bytes);
        // Pair an ancestor's ceiling with its usage, which includes sibling
        // charges. Leaf usage against a parent's limit would undercount.
        let dir = limit.as_ref().and_then(|limit| limit.path.parent()).unwrap_or(&cgroup.dir);
        let v1 = cgroup.v1;
        let limit_bytes = match (cgroup_limit, assignment_cap) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        };
        let reclaimable = read(&dir.join("memory.stat"))
            .map(|stat| {
                let value = |field: &str| stat.lines().find_map(|line| line.strip_prefix(field)
                    .and_then(|value| value.trim().parse::<u64>().ok())).unwrap_or(0);
                if guard {
                    // Clean active cache can also be reclaimed: counting it
                    // could keep the start gate closed on an otherwise idle
                    // role forever. Shmem and pinned/dirty pages stay charged.
                    let (cache, shmem, dirty, writeback, unevictable) = if v1 {
                        ("total_cache ", "total_shmem ", "total_dirty ", "total_writeback ", "total_unevictable ")
                    } else { ("file ", "shmem ", "file_dirty ", "file_writeback ", "unevictable ") };
                    return value(cache).saturating_sub(value(shmem)).saturating_sub(value(dirty))
                        .saturating_sub(value(writeback)).saturating_sub(value(unevictable));
                }
                // v1 usage includes descendants; its total_* stat matches
                // that accounting. Preserve the concurrency gate's working set.
                let field = if v1 { "total_inactive_file " } else { "inactive_file " };
                value(field)
            })
            .unwrap_or(0);
        let current = number(read(&dir.join(if v1 { "memory.usage_in_bytes" } else { "memory.current" })));
        let working_set_bytes = current
            .map(|current| current.saturating_sub(reclaimable))
            .or_else(|| {
                // A known cgroup limit with unreadable usage cannot safely
                // admit a merge using the process RSS (other charges exist).
                if cgroup_limit.is_some() { return None; }
                status().and_then(|status| {
                    status
                        .lines()
                        .find_map(|l| l.strip_prefix("VmRSS:"))
                        .and_then(|kb| kb.trim().trim_end_matches("kB").trim().parse::<u64>().ok())
                        .map(|kb| kb * 1024)
                })
            });
        Self {
            working_set_bytes,
            limit_bytes,
            cgroup_limit_bytes: cgroup_limit,
        }
    }
}

/// NAN-4755: (unreclaimable bytes in use, `memory.max`) of this process's
/// cgroup, for the merge memory guard: usage minus clean reclaimable file
/// cache. Shmem, dirty/writeback and unevictable pages remain charged.
/// `None` without any limit (lab, tests).
pub fn cgroup_memory() -> Option<(u64, u64)> {
    guard_view(MemorySnapshot::read_for(true))
}

/// NAN-4796: the guard's (in use, limit) view of a snapshot. The limit is
/// the OOM boundary: the own cgroup's `memory.max`
/// ([`guard_limit`]), not the lower of it and the assignment's sizing cap
/// that the concurrency gate uses.
pub fn guard_view(memory: MemorySnapshot) -> Option<(u64, u64)> {
    let limit = guard_limit(memory.cgroup_limit_bytes, memory.limit_bytes)?;
    Some((memory.working_set_bytes.unwrap_or(limit), limit))
}

/// NAN-4796: the limit the merge memory guard and the history start gate
/// measure against: the role cgroup's own `memory.max` (where the kernel
/// OOM-kills), else the assignment's memory cap (no cgroup limit: lab,
/// watchdog-only cells).
///
/// The assignment cap is a SIZING figure, not a limit: for a low-eps
/// tenant it is 40 % of the eps curve's tenant limit (FP cell-us-1, ops
/// tenant: 1.37 GB beside a 3.41 GB role `memory.max`). Ingest's steady
/// unreclaimable memory alone sat at ~85 % of it, so the NAN-4755 guard
/// stopped every merge regardless of its size, and no smaller shape or
/// fan-in could ever fit: the hour backlog only grew.
pub fn guard_limit(cgroup_limit: Option<u64>, assignment_cap: Option<u64>) -> Option<u64> {
    cgroup_limit.or(assignment_cap)
}

/// Whether one more history merge fits. No cgroup limit (lab, tests): there
/// is no budget to protect, so it fits. A limit with an unreadable usage
/// does not.
pub fn history_memory_admits(memory: MemorySnapshot) -> bool {
    let Some(limit) = guard_limit(memory.cgroup_limit_bytes, memory.limit_bytes) else {
        return true;
    };
    let Some(working_set) = memory.working_set_bytes else {
        return false;
    };
    let reserve = MergeCapacity::for_role(Some(limit), 1000).history_bytes;
    let admits = (working_set.saturating_add(reserve) as f64)
        <= limit as f64 * HISTORY_MEMORY_CEILING;
    if !admits {
        tracing::debug!(
            working_set_bytes = working_set,
            limit_bytes = limit,
            "second history merge deferred: memory headroom"
        );
    }
    admits
}

/// Own OS thread: reducing its priority cannot affect Tokio's ingest threads.
pub async fn compute<T: Send + 'static>(
    work: impl FnOnce() -> T + Send + 'static,
) -> anyhow::Result<T> {
    let (tx, rx) = tokio::sync::oneshot::channel();
    #[cfg(test)]
    let (probe, tracked) = (super::merge_quota::MEMORY_PROBE_FOR_TEST.get(), crate::test_heap::tracking_current_thread());
    std::thread::Builder::new().name("lake-merge".into()).spawn(move || {
        // Tests: the starting thread's memory probe and heap tracking
        // follow the merge onto its thread.
        #[cfg(test)]
        {
            super::merge_quota::MEMORY_PROBE_FOR_TEST.set(probe);
            crate::test_heap::track_current_thread(tracked);
        }
        // SAFETY: Linux setpriority with pid 0 changes only this calling thread.
        if unsafe { libc::setpriority(libc::PRIO_PROCESS, 0, 19) } != 0 {
            tracing::warn!(error = %std::io::Error::last_os_error(), "could not lower merge thread priority");
        }
        let _ = tx.send(work());
    })?;
    rx.await
        .map_err(|_| anyhow::anyhow!("merge compute thread panicked"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nan4810_namespaced_guard_reads_the_supervisors_assigned_leaf() {
        let root = tempfile::tempdir().unwrap();
        let role = std::path::Path::new("tenants/s7/ingest");
        let leaf = root.path().join(role);
        std::fs::create_dir_all(&leaf).unwrap();
        // The inherited mount root is the cell's, not this role's. The
        // namespace makes /proc/self/cgroup say / without remounting it.
        std::fs::write(root.path().join("memory.max"), "16000000000\n").unwrap();
        std::fs::write(leaf.join("memory.max"), "3413114880\n").unwrap();
        std::fs::write(leaf.join("memory.current"), "1183709312\n").unwrap();
        let cg = crate::cgroup_memory::resolve(root.path(), "0::/\n", "", Some(role));
        let memory = MemorySnapshot::read_cgroup(cg, Some(1_365_245_952), true, || None);
        let (used, limit) = guard_view(memory).unwrap();
        assert_eq!((used, limit), (1_183_709_312, 3_413_114_880));
        assert!((used as f64) < super::super::merge_quota::MERGE_START_SHARE * limit as f64);
    }

    #[test]
    fn nan4810_memory_guard_inherits_a_finite_ancestor_limit() {
        let root = tempfile::tempdir().unwrap();
        let parent = root.path().join("tenants/s0");
        let leaf = parent.join("ingest");
        std::fs::create_dir_all(&leaf).unwrap();
        std::fs::write(leaf.join("memory.max"), "max\n").unwrap();
        std::fs::write(leaf.join("memory.current"), "600000000\n").unwrap();
        std::fs::write(parent.join("memory.max"), "3413114880\n").unwrap();
        std::fs::write(parent.join("memory.current"), "1613709312\n").unwrap();
        std::fs::write(parent.join("memory.stat"), "file 430000000\n").unwrap();
        let memory = MemorySnapshot::read_from(root.path(), "0::/tenants/s0/ingest\n",
            Some(1_365_245_952), true, || None);
        assert_eq!(guard_view(memory), Some((1_183_709_312, 3_413_114_880)));
    }

    #[test]
    fn memory_reads_the_own_leaf_on_both_cgroup_versions() {
        for v1 in [false, true] {
            let root = tempfile::tempdir().unwrap();
            let leaf = root.path().join(if v1 { "memory/role/ingest" } else { "role/ingest" });
            std::fs::create_dir_all(&leaf).unwrap();
            let (membership, limit, usage, stat) = if v1 {
                ("0::/unified\n5:cpu,cpuacct:/elsewhere\n7:memory:/role/ingest\n", "memory.limit_in_bytes", "memory.usage_in_bytes",
                    "cache 500\ninactive_file 20\ntotal_cache 500\ntotal_shmem 300\ntotal_dirty 20\ntotal_writeback 30\ntotal_unevictable 10\ntotal_inactive_file 100\n")
            } else {
                ("0::/role/ingest\n", "memory.max", "memory.current", "file 500\nshmem 300\nfile_dirty 20\nfile_writeback 30\nunevictable 10\ninactive_file 100\n")
            };
            std::fs::write(leaf.join(limit), "1000\n").unwrap();
            std::fs::write(leaf.join(usage), "800\n").unwrap();
            std::fs::write(leaf.join("memory.stat"), stat).unwrap();
            let memory = MemorySnapshot::read_from(root.path(), membership, Some(900), false, || None);
            assert_eq!(memory.limit_bytes, Some(900));
            assert_eq!(memory.working_set_bytes, Some(700), "only inactive cache is subtracted, v1={v1}");
            let guarded = MemorySnapshot::read_from(root.path(), membership, Some(900), true, || None);
            assert_eq!(guarded.working_set_bytes, Some(660), "the guard discounts clean cache only, v1={v1}");
            std::fs::write(leaf.join("memory.stat"), if v1 { "total_cache 800\ntotal_inactive_file 10\n" }
                else { "file 800\ninactive_file 10\n" }).unwrap();
            let clean_cache = MemorySnapshot::read_from(root.path(), membership, Some(900), true, || None);
            assert_eq!(clean_cache.working_set_bytes, Some(0), "clean active cache cannot hold the start gate closed");
            // A missing stat is conservative, while a missing usage with
            // a known cgroup limit must never fall back to process RSS.
            std::fs::remove_file(leaf.join("memory.stat")).unwrap();
            assert_eq!(MemorySnapshot::read_from(root.path(), membership, None, true, || None).working_set_bytes, Some(800));
            std::fs::remove_file(leaf.join(usage)).unwrap();
            let unreadable = MemorySnapshot::read_from(root.path(), membership, None, true, || Some("VmRSS: 1 kB\n".into()));
            assert_eq!(unreadable.working_set_bytes, None);
            assert!(!history_memory_admits(unreadable));
        }
    }

    /// NAN-4796 (FP cell-us-1, ops tenant): the role's `memory.max` is
    /// 3.41 GB, the assignment's sizing cap 1.37 GB (40 % of the eps
    /// curve), and ingest's steady unreclaimable memory ~1.18 GB. The
    /// guard must measure against the OOM boundary: 1.18 GB is 35 % of it,
    /// not 86 % of the sizing cap (where every merge was stopped). The
    /// NAN-3187 concurrency gate keeps the lower of the two.
    #[test]
    fn the_guard_measures_the_role_memory_max_not_the_sizing_cap() {
        let root = tempfile::tempdir().unwrap();
        let leaf = root.path().join("tenant/ingest");
        std::fs::create_dir_all(&leaf).unwrap();
        std::fs::write(leaf.join("memory.max"), "3413114880\n").unwrap();
        std::fs::write(leaf.join("memory.current"), "1613709312\n").unwrap();
        std::fs::write(leaf.join("memory.stat"), "file 430000000\nshmem 0\nfile_dirty 0\nfile_writeback 0\nunevictable 0\ninactive_file 300000000\n").unwrap();
        let cap = Some(1_365_245_952);
        let guarded = MemorySnapshot::read_from(root.path(), "0::/tenant/ingest\n", cap, true, || None);
        assert_eq!(guarded.limit_bytes, cap, "concurrency sizing keeps the lower figure");
        assert_eq!(guarded.cgroup_limit_bytes, Some(3_413_114_880));
        let (used, limit) = guard_view(guarded).unwrap();
        assert_eq!((used, limit), (1_183_709_312, 3_413_114_880));
        assert!((used as f64) < limit as f64 * super::super::merge_quota::MERGE_START_SHARE, "a merge may start");
        // Before NAN-4796 the guard read min(memory.max, cap): already past 85 %.
        assert!(used as f64 >= cap.unwrap() as f64 * super::super::merge_quota::MEMORY_GUARD_SHARE);
        // Without a cgroup limit the cap is all there is.
        assert_eq!(guard_limit(None, cap), cap);
        assert_eq!(guard_limit(None, None), None);
    }

    #[test]
    fn an_unlimited_cgroup_uses_the_assignment_cap_and_rss() {
        let root = tempfile::tempdir().unwrap();
        std::fs::write(root.path().join("memory.max"), "max\n").unwrap();
        let memory = MemorySnapshot::read_from(root.path(), "0::/\n", Some(8192), true, || Some("VmRSS: 2 kB\n".into()));
        assert_eq!(memory.limit_bytes, Some(8192));
        assert_eq!(memory.working_set_bytes, Some(2048));
        std::fs::write(root.path().join("memory.current"), "4096\n").unwrap();
        let memory = MemorySnapshot::read_from(root.path(), "0::/\n", None, true, || None);
        assert_eq!(memory.limit_bytes, None, "an unlimited lab cgroup stays unlimited");
    }
    use crate::parts::format::PartId;
    use crate::parts::levels::{plan_merges, MergePolicy};
    use crate::parts::part_log::PartRef;

    fn part(hour: i32, seq: i64, now: i64) -> PartRef {
        PartRef {
            request_hours: None,
            part_id: PartId::parse(&format!("{:013}-{:016x}", now - 120_000, seq)).unwrap(),
            level: Level::L0,
            event_hour: hour,
            event_day: None,
            rows: 3_000,
            min_time_us: i64::from(hour) * 3_600_000_000,
            max_time_us: i64::from(hour) * 3_600_000_000 + 1,
            schema_fingerprint: "0".repeat(64),
            provenance_sha256: "0".repeat(64),
            merkle_root: "0".repeat(64),
            sorted: true,
            data_bytes: 450_000,
            row_groups: 1,
            data_files: 1,
        }
    }

    /// NAN-4674: during catch-up exactly one fragmented-hour `h` merge may
    /// run (beside minute merges only); an ordinary sealed-hour merge still
    /// waits for the catch-up to end, and so does a second fragmented one.
    #[test]
    fn one_fragmented_hour_merge_runs_beside_admission() {
        use crate::parts::levels::{PlannedMerge, FRAGMENTED_HOUR_PARTS};
        let now = 600_000_i64 * 3_600_000;
        let merge = |level: Level, hour: i32, inputs: usize| PlannedMerge {
            output_level: level, event_hour: hour,
            inputs: (0..inputs).map(|i| part(hour, i as i64, now)).collect(),
        };
        let fragmented = merge(Level::Hour, 10, FRAGMENTED_HOUR_PARTS);
        let ordinary = merge(Level::Hour, 11, FRAGMENTED_HOUR_PARTS - 1);
        let minute = merge(Level::Minute, 12, 24);
        assert!(fragmented_runs_beside_admission(&fragmented, std::iter::empty()));
        assert!(fragmented_runs_beside_admission(&fragmented, [&minute, &minute].into_iter()));
        assert!(!fragmented_runs_beside_admission(&ordinary, std::iter::empty()));
        assert!(!fragmented_runs_beside_admission(&minute, std::iter::empty()));
        let other = merge(Level::Hour, 13, FRAGMENTED_HOUR_PARTS);
        assert!(!fragmented_runs_beside_admission(&fragmented, [&minute, &other].into_iter()), "one at a time");
        assert!(!fragmented_runs_beside_admission(&fragmented, [&ordinary].into_iter()), "never beside another history merge");
    }

    #[test]
    fn arrival_300_eps_with_250_part_backlog_drains_beside_history() {
        let start = 500_000_i64 * 3_600_000;
        let mut live = (0..250)
            .map(|i| part(499_999 + (i % 2) as i32, i, start))
            .collect::<Vec<_>>();
        let history = PlannedMerge {
            output_level: Level::Hour,
            event_hour: 499_997,
            inputs: vec![],
        };
        // Model a minute job taking 60 seconds, while the history job takes
        // the entire 15-minute run. Production scheduling/overlap logic is
        // used; this is a service-rate simulation, not a CPU benchmark.
        let mut active = vec![(history, i64::MAX)];
        let mut arrival = 250;
        let mut removed = 0;
        for tick in 0..90 {
            let now = start + tick * 10_000;
            for (merge, end) in &active {
                if *end <= now {
                    let ids = merge.inputs.iter().map(|p| &p.part_id).collect::<Vec<_>>();
                    live.retain(|p| !ids.contains(&&p.part_id));
                    removed += merge.inputs.len();
                }
            }
            active.retain(|(_, end)| *end > now);
            // Ingest advances each 10-second tick, independent of history.
            live.push(part(500_000, arrival, now + 120_000));
            arrival += 1;
            let mut planned = plan_merges(&live, now, &MergePolicy::default());
            planned.sort_by_key(|m| (m.output_level != Level::Minute, -i64::from(m.event_hour)));
            for merge in planned {
                if merge.output_level != Level::Minute {
                    continue;
                }
                let running = active.iter().map(|(m, _)| m).collect::<Vec<_>>();
                if available(&merge, &running) {
                    assert!(running.iter().all(|m| !overlaps(&merge, m)));
                    active.push((merge, now + 60_000));
                }
            }
            assert!(
                active
                    .iter()
                    .filter(|(m, _)| m.output_level == Level::Minute)
                    .count()
                    <= 2
            );
        }
        assert!(removed >= 250, "removed only {removed} backlog inputs");
        assert!(live.len() < 30, "{} L0s left after catch-up", live.len());
        assert_eq!(arrival - 250, 90, "every ingest tick ran");
    }

    #[test]
    fn day_range_and_same_hour_are_exclusive_across_lanes() {
        let day = PlannedMerge {
            output_level: Level::Day,
            event_hour: 48,
            inputs: vec![],
        };
        let mut minute = PlannedMerge {
            output_level: Level::Minute,
            event_hour: 71,
            inputs: vec![],
        };
        assert!(!available(&minute, &[&day]));
        minute.event_hour = 72;
        assert!(available(&minute, &[&day]));
        assert!(!available(&minute, &[&minute]));
    }

    /// NAN-3187: two backfilled sealed hours run two `h` merges at once
    /// when memory allows; a third waits, as does a day merge.
    #[test]
    fn two_sealed_backlog_hours_get_two_concurrent_hour_merges() {
        let now = 500_010_i64 * 3_600_000;
        // Parts created 120 s before `now - 600 s`: quiet (past the debounce).
        let live = (0..3)
            .flat_map(|h| {
                (0..30).map(move |i| part(500_000 + h, h as i64 * 100 + i, now - 600_000))
            })
            .collect::<Vec<_>>();
        let planned = plan_merges(&live, now, &MergePolicy::default());
        assert_eq!(planned.len(), 3, "{planned:?}");
        assert!(planned
            .iter()
            .all(|m| m.output_level == Level::Hour && m.inputs.len() == 30));
        let fits = || true;
        assert!(available_with(&planned[0], &[], 2, fits));
        assert!(
            available_with(&planned[1], &[&planned[0]], 2, fits),
            "second history lane"
        );
        assert!(
            !available_with(&planned[2], &[&planned[0], &planned[1]], 2, fits),
            "capacity 2"
        );
        // The second lane needs memory headroom; the first never waits on it.
        assert!(!available_with(&planned[1], &[&planned[0]], 2, || false));
        assert!(available_with(&planned[0], &[], 2, || false));
        // Same hour never twice; a day merge never beside another history job.
        assert!(!available_with(&planned[0], &[&planned[0]], 2, fits));
        let day = PlannedMerge {
            output_level: Level::Day,
            event_hour: 499_968,
            inputs: vec![],
        };
        assert!(!available_with(&day, &[&planned[0]], 2, fits));
        assert!(!available_with(&planned[0], &[&day], 2, fits));
        // Minute work is independent of the history lanes.
        let minute = PlannedMerge {
            output_level: Level::Minute,
            event_hour: 500_009,
            inputs: vec![],
        };
        assert!(available_with(
            &minute,
            &[&planned[0], &planned[1]],
            2,
            || false
        ));
        // A one-slot capacity serializes history merges.
        assert!(!available_with(&planned[1], &[&planned[0]], 1, fits));
    }

    fn due(level: Level, hour: i32, inputs: usize) -> PlannedMerge {
        let now = 500_200_i64 * 3_600_000;
        PlannedMerge {
            output_level: level,
            event_hour: hour,
            // Part ids are unique per (hour, input): `overlaps` compares them.
            inputs: (0..inputs)
                .map(|i| part(hour, i64::from(hour) * 1_000 + i as i64, now))
                .collect(),
        }
    }

    /// Two-lane history service: one round is one hour merge per lane
    /// (~18 min each on the load-test tenant). Returns the round in which the last of
    /// the fragmented recent hours started.
    fn rounds_until_recent_hours_start(order: fn(&mut [PlannedMerge])) -> usize {
        // The 2026-10-09 load-test tenant backlog: 60 old hours that a backfill gave
        // one late part each (2 inputs), and 8 hours sealed since then that
        // still hold ~50 minute parts each.
        let mut waiting = (0..60)
            .map(|h| due(Level::Hour, 500_000 + h, 2))
            .chain((0..8).map(|h| due(Level::Hour, 500_100 + h, 50)))
            .collect::<Vec<_>>();
        for round in 1..=100 {
            order(&mut waiting);
            let mut started: Vec<PlannedMerge> = Vec::new();
            let mut index = 0;
            while index < waiting.len() {
                let running = started.iter().collect::<Vec<_>>();
                if available_with(&waiting[index], &running, 2, || true) {
                    started.push(waiting.remove(index));
                } else {
                    index += 1;
                }
            }
            assert_eq!(started.len(), 2, "both history lanes busy every round");
            if waiting.iter().all(|m| m.event_hour < 500_100) {
                return round;
            }
        }
        panic!("recent hours never started");
    }

    /// NAN-3400: the most fragmented sealed hours merge first; an old hour
    /// with one late part no longer holds a fresh 50-part hour for hours.
    #[test]
    fn fragmented_recent_hours_merge_before_old_backfill_rewrites() {
        let oldest_first: fn(&mut [PlannedMerge]) = |planned| {
            planned.sort_by_key(|m| {
                (
                    m.output_level != Level::Minute,
                    if m.output_level == Level::Minute {
                        -i64::from(m.event_hour)
                    } else {
                        i64::from(m.event_hour)
                    },
                )
            })
        };
        // Before: the recent hours waited behind all 60 old rewrites
        // (~30 rounds, ~9 h at 18 min a round).
        assert!(rounds_until_recent_hours_start(oldest_first) >= 30);
        // After: they take both lanes first (4 rounds, ~72 min).
        assert_eq!(rounds_until_recent_hours_start(launch_order), 4);
    }

    #[test]
    fn launch_order_keeps_minutes_first_and_days_after_hours() {
        let mut planned = vec![
            due(Level::Day, 499_968, 24),
            due(Level::Hour, 500_001, 2),
            due(Level::Minute, 500_009, 4),
            due(Level::Hour, 500_005, 2),
            due(Level::Hour, 500_003, 40),
            due(Level::Minute, 500_010, 4),
        ];
        launch_order(&mut planned);
        let order = planned
            .iter()
            .map(|m| (m.output_level, m.event_hour))
            .collect::<Vec<_>>();
        assert_eq!(
            order,
            vec![
                // Minute lane: newest first, ahead of every history job.
                (Level::Minute, 500_010),
                (Level::Minute, 500_009),
                // History: most inputs, then newest; a day merge (which runs
                // alone and holds both lanes) only after every hour merge.
                (Level::Hour, 500_003),
                (Level::Hour, 500_005),
                (Level::Hour, 500_001),
                (Level::Day, 499_968),
            ]
        );
    }

    /// NAN-4750: the just-closed hour's `h` merge goes first in the history
    /// lane, gets one slot beyond the lanes' capacity, and may run beside
    /// admission (not during a catch-up), one at a time.
    #[test]
    fn a_just_closed_hour_merges_first_with_its_own_slot() {
        let hour = 500_100;
        let end_ms = (i64::from(hour) + 1) * 3_600_000;
        let now = end_ms + 15 * 60_000;
        let fresh = due(Level::Hour, hour, 30);
        let backfill = [due(Level::Hour, 500_001, 50), due(Level::Hour, 500_002, 60)];
        assert!(is_fresh_hour_merge(&fresh, now));
        assert!(!is_fresh_hour_merge(&fresh, end_ms - 1), "not before the hour ends");
        assert!(!is_fresh_hour_merge(&fresh, end_ms + FRESH_HOUR_MERGE_WINDOW_MS), "only while just closed");
        assert!(!is_fresh_hour_merge(&backfill[0], now));
        assert!(!is_fresh_hour_merge(&due(Level::Minute, hour, 4), now));

        let mut planned = vec![backfill[0].clone(), due(Level::Minute, hour + 1, 4), fresh.clone(), backfill[1].clone()];
        launch_order_at(&mut planned, now);
        assert_eq!(planned.iter().map(|m| (m.output_level, m.event_hour)).collect::<Vec<_>>(), vec![
            (Level::Minute, hour + 1), (Level::Hour, hour), (Level::Hour, 500_002), (Level::Hour, 500_001),
        ]);
        // Without a clock (or an old hour) the order is the NAN-3400 one.
        launch_order(&mut planned);
        assert_eq!(planned[1].event_hour, 500_002);

        // Both history lanes busy with backfill rewrites: the fresh hour
        // still starts (memory permitting); a second fresh hour does not.
        let running = [&backfill[0], &backfill[1]];
        let capacity = capacity(Level::Hour);
        let reserved = |merge: &PlannedMerge, active: &[&PlannedMerge]| {
            let own = is_fresh_hour_merge(merge, now) && active.iter().all(|m| !is_fresh_hour_merge(m, now));
            available_with(merge, active, capacity + usize::from(own), || true)
        };
        let full = (0..capacity).map(|i| due(Level::Hour, 500_010 + i as i32, 2)).collect::<Vec<_>>();
        let full = full.iter().collect::<Vec<_>>();
        assert!(!available_with(&fresh, &full, capacity, || true), "lanes full");
        assert!(reserved(&fresh, &full), "its own slot");
        // The window is one hour wide: only one hour is ever just closed.
        assert!(!is_fresh_hour_merge(&due(Level::Hour, hour - 1, 3), now));
        assert!(!available_with(&fresh, &full, capacity + 1, || false), "still needs memory headroom");

        // Beside admission: not while catching up, one fresh at a time.
        assert!(fresh_runs_beside_admission(&fresh, now, false, running.into_iter(), || true));
        assert!(!fresh_runs_beside_admission(&fresh, now, false, std::iter::empty(), || false),
            "beside admission it always needs the memory headroom (NAN-4755)");
        assert!(!fresh_runs_beside_admission(&fresh, now, true, std::iter::empty(), || true));
        assert!(!fresh_runs_beside_admission(&backfill[0], now, false, std::iter::empty(), || true));
        assert!(!fresh_runs_beside_admission(&fresh, now, false, [&fresh].into_iter(), || true));
    }

    #[test]
    fn history_memory_gate() {
        // This process always has a readable working set (cgroup or VmRSS).
        assert!(MemorySnapshot::read()
            .working_set_bytes
            .is_some_and(|b| b > 0));
        const GIB: u64 = 1024 * 1024 * 1024;
        let limit = 7 * GIB + 3 * GIB / 4; // ingest[T] memory.max on 10-07
        let at = |working_set| MemorySnapshot {
            working_set_bytes: Some(working_set),
            limit_bytes: Some(limit),
            cgroup_limit_bytes: Some(limit),
        };
        // The catch-up peak (6.1 GB) leaves no room for another merge...
        assert!(!history_memory_admits(at(6_100_000_000)));
        // ...steady ingest plus one running hour merge does.
        assert!(history_memory_admits(at(3 * GIB)));
        assert!(!history_memory_admits(MemorySnapshot {
            working_set_bytes: None,
            limit_bytes: Some(limit),
            cgroup_limit_bytes: Some(limit),
        }));
        assert!(history_memory_admits(MemorySnapshot {
            working_set_bytes: None,
            limit_bytes: None,
            cgroup_limit_bytes: None,
        }));
    }

    #[tokio::test]
    async fn history_cpu_permit_does_not_block_minute_or_ingest() {
        let history = super::super::merge_quota::acquire_for(Level::Hour).unwrap();
        let (started, waiting) = tokio::sync::oneshot::channel();
        let (release, held) = std::sync::mpsc::channel();
        let job = tokio::spawn(compute(move || {
            let _minute = super::super::merge_quota::acquire_for(Level::Minute).unwrap();
            started.send(()).unwrap();
            held.recv().unwrap();
        }));
        tokio::time::timeout(std::time::Duration::from_secs(1), waiting)
            .await
            .expect("minute waited behind history")
            .unwrap();
        tokio::time::timeout(
            std::time::Duration::from_millis(100),
            tokio::task::yield_now(),
        )
        .await
        .expect("ingest executor must remain responsive");
        release.send(()).unwrap();
        job.await.unwrap().unwrap();
        drop(history);
    }
}
