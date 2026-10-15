// SPDX-License-Identifier: AGPL-3.0-or-later

//! query[T]'s memory budget, derived from the role's cgroup `memory.max`.
//!
//! The kernel kills the whole process when the cgroup crosses `memory.max`,
//! so every in-process limit is carved out of it:
//!
//! - chDB's engine-wide `max_server_memory_usage` is [`SERVER_PERCENT`] of
//!   the limit. The rest is headroom for what chDB does not track: the Rust
//!   side (result decode, response JSON, sidecars, caches), libchdb's
//!   resident text, thread stacks and allocator slack. The old rule (limit
//!   minus 128 MiB) left almost none, and concurrent queries OOM-killed the
//!   process (2026-09-29).
//! - At most [`QueryMemoryBudget::concurrency`] requests run native work at
//!   once (an admission semaphore queues the rest with a deadline), and each
//!   statement's `max_memory_usage` is the server share divided by that, so
//!   concurrent queries never have to race for the same bytes.
//! - A statement's raw result is capped at [`QueryMemoryBudget::result_bytes`]
//!   before it is decoded into rows.
//!
//! Over any of these a request fails alone with a 503
//! `query_budget_exhausted` (a 429 when the admission deadline passes);
//! the process survives.

use std::path::Path;

pub const MIB: u64 = 1024 * 1024;
pub const GIB: u64 = 1024 * MIB;
/// chDB's share of the role's memory limit.
pub const SERVER_PERCENT: u64 = 75;
/// Memory always left outside chDB, whatever the limit (NAN-3046).
pub const MIN_HEADROOM_BYTES: u64 = 384 * MIB;
/// Native memory each concurrently admitted request is guaranteed.
pub const MIN_QUERY_BYTES_PER_SLOT: u64 = GIB;
pub const MAX_CONCURRENCY: usize = 4;
/// chDB's own floor for a statement (the planner refuses less).
const MIN_QUERY_BYTES: u64 = 64 * MIB;
const MIN_RESULT_BYTES: u64 = 16 * MIB;
const MAX_RESULT_BYTES: u64 = 256 * MIB;
/// Raw result bytes per admitted request = headroom / (this x concurrency).
const RESULT_HEADROOM_DIVISOR: u64 = 12;

/// NAN-3077 size classes (query role): a small lane's statement cap...
pub const SMALL_QUERY_BYTES: u64 = 256 * MIB;
/// ...at most this many small lanes...
pub const MAX_SMALL_LANES: usize = 6;
/// ...and the smallest large lane worth keeping beside them.
pub const MIN_LARGE_QUERY_BYTES: u64 = 512 * MIB;

/// Interactive lanes by size (NAN-3077; gen1's reader ran 4 x 4 GiB lanes on
/// a 10 GiB pod): many small lanes for the 1 h / 24 h searches, pivots and
/// companions an analyst UI fires at once, one large lane for heavy scans
/// (a statement that outgrows a small lane is retried there; beyond it the
/// search service escalates to a durable job). Small statements spill
/// group-by and sort to disk at half their cap.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LaneClasses {
    pub small_lanes: usize,
    pub small_bytes: u64,
    pub large_bytes: u64,
}

impl LaneClasses {
    /// The classes `server_bytes` of chDB memory affords, or `None` when it
    /// cannot hold two small lanes beside a minimal large one (then the
    /// equal-lane budget applies).
    pub fn for_server(server_bytes: u64) -> Option<Self> {
        let spare = server_bytes.checked_sub(MIN_LARGE_QUERY_BYTES)?;
        let small_lanes = usize::try_from(spare / SMALL_QUERY_BYTES).ok()?.min(MAX_SMALL_LANES);
        if small_lanes < 2 {
            return None;
        }
        let large_bytes = server_bytes - small_lanes as u64 * SMALL_QUERY_BYTES;
        Some(Self { small_lanes, small_bytes: SMALL_QUERY_BYTES, large_bytes })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QueryMemoryBudget {
    /// The effective limit: the smaller of the assignment's cap and the
    /// process's cgroup `memory.max` (either may be unknown).
    pub limit_bytes: u64,
    /// chDB `max_server_memory_usage`.
    pub server_bytes: u64,
    /// Requests admitted to native work at once (= read lanes).
    pub concurrency: usize,
    /// chDB `max_memory_usage` per statement.
    pub per_query_bytes: u64,
    /// Largest raw chDB result one statement may hand back for decoding.
    pub result_bytes: u64,
}

impl QueryMemoryBudget {
    /// Derive from the assignment's cap and the cgroup's `memory.max`
    /// (`None`/0 = unknown or unlimited). With neither known the assignment
    /// value (possibly 0) is treated as 3 GiB, the standard query role.
    pub fn derive(assigned_bytes: u64, cgroup_max_bytes: Option<u64>) -> Self {
        let limit_bytes = [Some(assigned_bytes), cgroup_max_bytes]
            .into_iter()
            .flatten()
            .filter(|bytes| *bytes > 0)
            .min()
            .unwrap_or(3 * GIB);
        // The Rust side's fixed overhead (libchdb text, runtime, caches)
        // does not shrink with the limit, so small roles keep at least
        // MIN_HEADROOM_BYTES outside chDB.
        let server_bytes = (limit_bytes / 100 * SERVER_PERCENT)
            .min(limit_bytes.saturating_sub(MIN_HEADROOM_BYTES))
            .max(2 * MIN_QUERY_BYTES);
        let concurrency = usize::try_from(server_bytes / MIN_QUERY_BYTES_PER_SLOT)
            .unwrap_or(MAX_CONCURRENCY)
            .clamp(1, MAX_CONCURRENCY);
        let per_query_bytes = (server_bytes / concurrency as u64).max(MIN_QUERY_BYTES);
        // Decoded rows are ~8-10x their raw JSON (measured: a 64 MiB result
        // peaked ~600 MiB of Rust heap); keep every admitted request's decode
        // and response inside the headroom chDB does not use.
        let headroom = limit_bytes.saturating_sub(server_bytes);
        let result_bytes = (headroom / (RESULT_HEADROOM_DIVISOR * concurrency as u64)).clamp(MIN_RESULT_BYTES, MAX_RESULT_BYTES);
        Self { limit_bytes, server_bytes, concurrency, per_query_bytes, result_bytes }
    }

    /// [`Self::derive`] with size classes (the query role, NAN-3077): the
    /// admission slots are the small lanes plus the large one, and a
    /// statement's default cap is the small one. Falls back to the equal
    /// lanes when the memory cannot hold the classes.
    pub fn with_classes(self) -> (Self, Option<LaneClasses>) {
        let Some(classes) = LaneClasses::for_server(self.server_bytes) else { return (self, None) };
        let concurrency = classes.small_lanes + 1;
        let headroom = self.limit_bytes.saturating_sub(self.server_bytes);
        let result_bytes = (headroom / (RESULT_HEADROOM_DIVISOR * concurrency as u64)).clamp(MIN_RESULT_BYTES, MAX_RESULT_BYTES);
        (Self { concurrency, per_query_bytes: classes.small_bytes, result_bytes, ..self }, Some(classes))
    }

    /// [`Self::derive`] against this process's own cgroup.
    pub fn for_process(assigned_bytes: u64) -> Self {
        let cgroup = cgroup_memory_max(Path::new("/proc/self/cgroup"), Path::new("/sys/fs/cgroup"));
        let budget = Self::derive(assigned_bytes, cgroup);
        tracing::info!(
            assigned_bytes, cgroup_memory_max = ?cgroup, limit_bytes = budget.limit_bytes,
            server_bytes = budget.server_bytes, concurrency = budget.concurrency,
            per_query_bytes = budget.per_query_bytes, result_bytes = budget.result_bytes,
            "query memory budget"
        );
        budget
    }
}

/// The tightest `memory.max` on the process's cgroup v2 path (the cgroup
/// and every ancestor visible under `root`); `None` when unreadable or
/// unlimited everywhere (e.g. the jail hides `/sys/fs/cgroup`).
pub fn cgroup_memory_max(proc_cgroup: &Path, root: &Path) -> Option<u64> {
    let text = std::fs::read_to_string(proc_cgroup).ok()?;
    let relative = text.lines().find_map(|line| line.strip_prefix("0::"))?.trim();
    let mut dir = root.join(relative.trim_start_matches('/'));
    let mut tightest: Option<u64> = None;
    loop {
        if let Ok(value) = std::fs::read_to_string(dir.join("memory.max")) {
            if let Ok(bytes) = value.trim().parse::<u64>() {
                tightest = Some(tightest.map_or(bytes, |t| t.min(bytes)));
            }
        }
        if dir == root || !dir.pop() || !dir.starts_with(root) {
            break;
        }
    }
    tightest.filter(|bytes| *bytes > 0)
}

/// Return freed Rust heap to the kernel (glibc keeps per-thread arenas
/// resident after a large decode, so RSS otherwise ratchets up request by
/// request until the cgroup kills the process).
pub fn release_freed_heap() {
    #[cfg(all(target_os = "linux", target_env = "gnu"))]
    {
        extern "C" {
            fn malloc_trim(pad: usize) -> std::ffi::c_int;
        }
        // SAFETY: glibc's malloc_trim is thread-safe and only releases free memory.
        unsafe { malloc_trim(0) };
    }
}

/// detect[T] running rules (NAN-3047) sizes its engine this far below its
/// role limit. Measured on 1 h of 300 eps OCSF data, 38 rules (22 with a
/// 30 d prevalence stage) at claim concurrency 4 through one lane: an engine
/// derived from the whole 1.5 GiB limit was OOM-killed (chDB's 25% headroom
/// does not cover the fixed Rust/runtime overhead at small sizes); derived
/// from 1.5 GiB inside a 2 GiB limit it peaked at ~1.0 GiB anon (with the
/// per-request heap trim of a single-slot engine, see `AdmissionSlot`), and
/// its 32 MiB result budget fits the heaviest rules' ~26 MB answers, which a
/// 1 GiB engine (21 MiB) refuses.
pub const DETECT_ENGINE_RESERVE_BYTES: u64 = 512 * MIB;

/// The engine cap handed to [`QueryMemoryBudget::derive`] for a detect[T]
/// with role limit `role_limit_bytes` (never below 512 MiB).
pub fn detect_engine_cap(role_limit_bytes: u64) -> u64 {
    role_limit_bytes.saturating_sub(DETECT_ENGINE_RESERVE_BYTES).max(512 * MIB)
}

/// Whether a chDB error is a memory-limit refusal (per statement or total).
pub fn is_memory_limit_error(message: &str) -> bool {
    message.contains("MEMORY_LIMIT_EXCEEDED") || message.contains("memory limit exceeded") || message.contains("Code: 241")
}

/// Whether an error text (possibly wrapped) is any budget refusal: a chDB
/// memory limit or an oversized result (`ExecutorError::ResultTooLarge`).
pub fn is_budget_refusal(message: &str) -> bool {
    is_memory_limit_error(message)
        || message.contains("result memory budget")
        // chDB's `max_result_bytes` refusal (Code 396).
        || message.contains("TOO_MANY_ROWS_OR_BYTES")
        || message.contains("Limit for result exceeded")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn size_classes_by_query_memory() {
        // 3 GiB query role: 6 x 256 MiB small lanes + a 768 MiB large lane.
        let (budget, classes) = QueryMemoryBudget::derive(3 * GIB, Some(3 * GIB)).with_classes();
        let classes = classes.unwrap();
        assert_eq!((classes.small_lanes, classes.small_bytes / MIB), (6, 256));
        assert_eq!(classes.large_bytes, budget.server_bytes - 6 * SMALL_QUERY_BYTES);
        assert!(classes.large_bytes > 760 * MIB);
        assert_eq!(budget.concurrency, 7);
        assert_eq!(budget.per_query_bytes, SMALL_QUERY_BYTES);
        assert_eq!(classes.small_lanes as u64 * classes.small_bytes + classes.large_bytes, budget.server_bytes);
        assert!(budget.result_bytes >= MIN_RESULT_BYTES);
        // 4 GiB: the same small lanes, a 1.5 GiB large lane.
        let (_, four) = QueryMemoryBudget::derive(4 * GIB, None).with_classes();
        assert!(four.unwrap().large_bytes > 1500 * MIB);
        // 2 GiB: fewer small lanes, the minimal large lane.
        let (two_budget, two) = QueryMemoryBudget::derive(2 * GIB, None).with_classes();
        assert_eq!((two.unwrap().small_lanes, two_budget.concurrency), (3, 4));
        assert!(two.unwrap().large_bytes >= MIN_LARGE_QUERY_BYTES);
        // Too small for classes: the equal-lane budget, unchanged.
        let (small, none) = QueryMemoryBudget::derive(GIB, None).with_classes();
        assert!(none.is_none());
        assert_eq!(small, QueryMemoryBudget::derive(GIB, None));
    }

    #[test]
    fn three_gib_query_role() {
        let budget = QueryMemoryBudget::derive(3 * GIB, Some(3 * GIB));
        assert_eq!(budget.limit_bytes, 3 * GIB);
        assert_eq!(budget.server_bytes, 3 * GIB / 100 * 75);
        assert_eq!(budget.concurrency, 2);
        assert_eq!(budget.per_query_bytes, budget.server_bytes / 2);
        // Leaves ~768 MiB outside chDB; results decode inside it.
        assert!(budget.limit_bytes - budget.server_bytes >= 700 * MIB);
        assert_eq!(budget.result_bytes, (budget.limit_bytes - budget.server_bytes) / 24);
        assert_eq!(budget.result_bytes / MIB, 32);
        // Every admitted statement at its cap still fits under chDB's cap.
        assert!(budget.per_query_bytes * budget.concurrency as u64 <= budget.server_bytes);
    }

    /// NAN-3047: detect[T] running rules derives its budget from its own
    /// memory.max, 512 MiB below it. At the proposed 2 GiB: the measured
    /// configuration (engine derived from 1.5 GiB: one lane, claims queue on
    /// the admission semaphore with a 60 s deadline, ~1.1 GiB chDB) with
    /// 2 GiB of kernel limit around it. At the 1.5 GiB floor: 1 GiB engine.
    #[test]
    fn detect_role_budgets() {
        let proposed = QueryMemoryBudget::derive(detect_engine_cap(2 * GIB), Some(2 * GIB));
        assert_eq!(proposed.limit_bytes, 3 * GIB / 2);
        assert_eq!(proposed.concurrency, 1);
        assert_eq!(proposed.server_bytes, 3 * GIB / 2 / 100 * 75);
        assert_eq!(proposed.per_query_bytes, proposed.server_bytes);

        assert_eq!((2 * GIB - proposed.server_bytes) / MIB, 896);
        let floor = QueryMemoryBudget::derive(detect_engine_cap(3 * GIB / 2), Some(3 * GIB / 2));
        assert_eq!((floor.limit_bytes, floor.concurrency), (GIB, 1));
        // The fixed 384 MiB headroom leaves 640 MiB for a 1 GiB engine.
        assert_eq!(floor.per_query_bytes, GIB - MIN_HEADROOM_BYTES);
        assert!(floor.result_bytes >= MIN_RESULT_BYTES);
        // A tiny limit still gets a usable engine cap (the cell never assigns it).
        assert_eq!(detect_engine_cap(256 * MIB), 512 * MIB);
    }

    #[test]
    fn small_roles_keep_a_fixed_headroom() {
        // 25% of 1 GiB is 256 MiB; the floor keeps 384 MiB outside chDB.
        let small = QueryMemoryBudget::derive(GIB, None);
        assert_eq!(small.server_bytes, GIB - MIN_HEADROOM_BYTES);
        // At 3 GiB the 25% share (768 MiB) already exceeds the floor.
        assert_eq!(QueryMemoryBudget::derive(3 * GIB, None).server_bytes, 3 * GIB / 100 * 75);
    }

    #[test]
    fn cgroup_tighter_than_assignment_wins_and_vice_versa() {
        assert_eq!(QueryMemoryBudget::derive(8 * GIB, Some(3 * GIB)).limit_bytes, 3 * GIB);
        assert_eq!(QueryMemoryBudget::derive(3 * GIB, Some(8 * GIB)).limit_bytes, 3 * GIB);
        assert_eq!(QueryMemoryBudget::derive(3 * GIB, None).limit_bytes, 3 * GIB);
        assert_eq!(QueryMemoryBudget::derive(0, Some(2 * GIB)).limit_bytes, 2 * GIB);
        assert_eq!(QueryMemoryBudget::derive(0, None).limit_bytes, 3 * GIB);
    }

    #[test]
    fn scales_and_stays_bounded() {
        let hobby = QueryMemoryBudget::derive(358 * MIB, None);
        assert_eq!(hobby.concurrency, 1);
        assert!(hobby.server_bytes < hobby.limit_bytes);
        assert!(hobby.per_query_bytes >= MIN_QUERY_BYTES);
        let big = QueryMemoryBudget::derive(7 * GIB, None);
        assert_eq!(big.concurrency, 4);
        assert!(big.per_query_bytes * 4 <= big.server_bytes);
        let huge = QueryMemoryBudget::derive(64 * GIB, None);
        assert_eq!(huge.concurrency, MAX_CONCURRENCY);
        assert_eq!(huge.result_bytes, MAX_RESULT_BYTES);
        let mut previous = QueryMemoryBudget::derive(256 * MIB, None);
        for mib in (256..16_384).step_by(128) {
            let budget = QueryMemoryBudget::derive(mib * MIB, None);
            assert!(budget.server_bytes >= previous.server_bytes);
            assert!(budget.server_bytes < budget.limit_bytes);
            if budget.limit_bytes >= MIN_HEADROOM_BYTES + 2 * MIN_QUERY_BYTES {
                assert!(budget.limit_bytes - budget.server_bytes >= MIN_HEADROOM_BYTES, "{mib} MiB keeps the fixed headroom");
            }
            assert!(budget.per_query_bytes * budget.concurrency as u64 <= budget.server_bytes.max(2 * MIN_QUERY_BYTES));
            previous = budget;
        }
    }

    #[test]
    fn reads_the_tightest_cgroup_ancestor() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("cg");
        let leaf = root.join("tenants/s0/query");
        std::fs::create_dir_all(&leaf).unwrap();
        std::fs::write(root.join("tenants/memory.max"), "max\n").unwrap();
        std::fs::write(root.join("tenants/s0/memory.max"), "8321499136\n").unwrap();
        std::fs::write(leaf.join("memory.max"), "3221225472\n").unwrap();
        let proc = dir.path().join("cgroup");
        std::fs::write(&proc, "0::/tenants/s0/query\n").unwrap();
        assert_eq!(cgroup_memory_max(&proc, &root), Some(3 * GIB));
        std::fs::write(leaf.join("memory.max"), "max\n").unwrap();
        assert_eq!(cgroup_memory_max(&proc, &root), Some(8_321_499_136));
        std::fs::write(root.join("tenants/s0/memory.max"), "max\n").unwrap();
        assert_eq!(cgroup_memory_max(&proc, &root), None);
        assert_eq!(cgroup_memory_max(&dir.path().join("missing"), &root), None);
    }

    #[test]
    fn recognizes_chdb_memory_errors() {
        assert!(is_memory_limit_error("Code: 241. DB::Exception: (total) memory limit exceeded: would use 2.78 GiB"));
        assert!(is_memory_limit_error("Memory limit (for query) exceeded: MEMORY_LIMIT_EXCEEDED"));
        assert!(!is_memory_limit_error("Code: 62. Syntax error"));
        assert!(is_budget_refusal("wrapped: query result of 9 bytes exceeds the 1-byte result memory budget"));
        assert!(!is_budget_refusal("Code: 62. Syntax error"));
        assert!(is_budget_refusal("Code: 396. DB::Exception: Limit for result exceeded, max bytes: 64.00 MiB (TOO_MANY_ROWS_OR_BYTES)"));
        assert!(!is_budget_refusal("Code: 307. Limit for bytes to read exceeded (TOO_MANY_BYTES)"));
    }
}
