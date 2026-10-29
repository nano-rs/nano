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
pub const SERVER_PERCENT: u64 = nanosiem_lake_cell::budget::QUERY_SERVER_PERCENT;
/// Memory always left outside chDB, whatever the limit (NAN-3046).
pub const MIN_HEADROOM_BYTES: u64 = nanosiem_lake_cell::budget::QUERY_MIN_HEADROOM_BYTES;
/// Legacy auxiliary-role memory per slot. Query admission uses role cores.
pub const MIN_QUERY_BYTES_PER_SLOT: u64 = GIB;
/// Compatibility ceiling for the small-role runtime and auxiliary lanes.
/// Query admission itself comes from the shared CPU/memory slot model.
const BASE_CONCURRENCY: usize = 4;
/// chDB's own floor for a statement (the planner refuses less).
const MIN_QUERY_BYTES: u64 = nanosiem_lake_cell::budget::QUERY_MIN_STATEMENT_BYTES;
const MIN_RESULT_BYTES: u64 = 16 * MIB;
/// Raw result bytes per admitted request = headroom / (this x concurrency).
const RESULT_HEADROOM_DIVISOR: u64 = nanosiem_lake_cell::resources::RESULT_DECODE_EXPANSION;
/// Native pool/stack safety floors; the remainder can decode responses.
const MIN_HEADROOM_PER_CPU: u64 = 128 * MIB;
const RUNTIME_HEADROOM_PER_CPU: u64 = 64 * MIB;

/// NAN-3077 size classes (query role): a small lane's statement cap...
pub const SMALL_QUERY_BYTES: u64 = 256 * MIB;
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


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QueryMemoryBudget {
    /// The effective limit: the smaller of the assignment's cap and the
    /// process's cgroup `memory.max` (either may be unknown).
    pub limit_bytes: u64,
    /// CPU quota, also bounded by memory for native pools and runtime stacks.
    pub threads: usize,
    /// chDB `max_server_memory_usage`.
    pub server_bytes: u64,
    /// Requests admitted to native work at once (= read lanes).
    pub concurrency: usize,
    /// Equal share per slot; a small size class may apply a tighter cap.
    pub per_query_bytes: u64,
    /// Largest raw chDB result one statement may hand back for decoding.
    pub result_bytes: u64,
}

impl QueryMemoryBudget {
    /// Rust-only paged search uses the same shared decode expansion.
    pub fn rust_paged_result_bytes(memory: u64, concurrency: u32) -> u64 {
        nanosiem_lake_cell::resources::rust_paged_result_bytes(memory, concurrency)
    }

    /// Derive from the assignment's cap and the cgroup's `memory.max`
    /// (`None`/0 = unknown or unlimited). With neither known the assignment
    /// value (possibly 0) is treated as 3 GiB, the standard query role.
    pub fn derive(assigned_bytes: u64, cgroup_max_bytes: Option<u64>) -> Self {
        Self::derive_for_role(assigned_bytes, cgroup_max_bytes, 4_000)
    }

    /// Production role sizing. The caller supplies the effective CPU quota
    /// (assignment intersected with visible cgroup ancestors).
    pub fn derive_for_role(assigned_bytes: u64, cgroup_max_bytes: Option<u64>, cpu_millis: u32) -> Self {
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
        // CPU demand is independent of the memory ingest left behind. The
        // role-derived thread cap stays usable after ingest shifts memory.
        // Memory still bounds slot count and native/runtime stack overhead.
        let threads = (nanosiem_lake_cell::budget::query_threads(cpu_millis) as usize)
            .min((limit_bytes.saturating_sub(server_bytes) / MIN_HEADROOM_PER_CPU).max(1) as usize);
        let concurrency = nanosiem_lake_cell::budget::query_slots(cpu_millis, server_bytes);
        let per_query_bytes = (server_bytes / concurrency as u64).max(MIN_QUERY_BYTES);
        // Decoded rows are ~8-10x their raw JSON (measured: a 64 MiB result
        // peaked ~600 MiB of Rust heap); keep every admitted request's decode
        // and response inside the headroom chDB does not use.
        let headroom = result_headroom(limit_bytes, server_bytes, threads);
        let decoders = concurrency + super::engine::POINT_PERMITS + 1;
        let result_bytes = (headroom / (RESULT_HEADROOM_DIVISOR * decoders as u64)).max(1);
        Self { limit_bytes, threads, server_bytes, concurrency, per_query_bytes, result_bytes }
    }

    /// [`Self::derive`] with size classes (the query role, NAN-3077): the
    /// admission slots are the small lanes plus the large one. The equal
    /// share stays `server_bytes / concurrency`; the planner separately
    /// applies a small statement's tighter class cap. Falls back to equal
    /// lanes when memory cannot hold the classes.
    pub fn with_classes(self) -> (Self, Option<LaneClasses>) {
        // One small statement gets at least the historical 256 MiB, then
        // 1/64 of role memory. Keep the planner's 64 GiB validation ceiling.
        let small_bytes = (self.limit_bytes / 64 / MIB * MIB).clamp(SMALL_QUERY_BYTES, crate::planner::MAX_QUERY_MEMORY_BYTES);
        // Classes divide the CPU-derived admission slots without creating
        // extra slots. Every raw response shares the Rust headroom below.
        let small_lanes = self.concurrency.saturating_sub(1);
        if small_lanes < 2 { return (self, None); }
        let small_bytes = small_bytes.min(self.per_query_bytes);
        let large_bytes = self.server_bytes.saturating_sub(small_lanes as u64 * small_bytes);
        if large_bytes < MIN_LARGE_QUERY_BYTES { return (self, None); }
        let classes = LaneClasses { small_lanes, small_bytes, large_bytes };
        let concurrency = self.concurrency;
        let headroom = result_headroom(self.limit_bytes, self.server_bytes, self.threads);
        // Small jobs already hold an interactive permit. Account for
        // point responses and general jobs too; no result floor may consume
        // more memory than the role can afford at its derived concurrency.
        let decoders = concurrency + super::engine::POINT_PERMITS + self.job_slots(Some(classes)).0;
        let result_bytes = (headroom / (RESULT_HEADROOM_DIVISOR * decoders as u64)).max(1);
        (Self { result_bytes, ..self }, Some(classes))
    }

    /// Detect/product keep their measured equal-lane layout. The query
    /// role opts into CPU-sized admission even when too small for classes.
    pub fn auxiliary_role(self) -> Self {
        let concurrency = (self.server_bytes / MIN_QUERY_BYTES_PER_SLOT).clamp(1, BASE_CONCURRENCY as u64) as usize;
        let per_query_bytes = (self.server_bytes / concurrency as u64).max(MIN_QUERY_BYTES);
        let result_bytes = (self.limit_bytes.saturating_sub(self.server_bytes) / (RESULT_HEADROOM_DIVISOR * concurrency as u64))
            .clamp(MIN_RESULT_BYTES, 256 * MIB);
        Self { concurrency, per_query_bytes, result_bytes, ..self }
    }

    /// [`Self::derive`] against this process's own cgroup.
    pub fn for_process(assigned_bytes: u64) -> Self {
        Self::for_process_role(assigned_bytes, 4_000)
    }

    pub fn for_process_role(assigned_bytes: u64, cpu_millis: u32) -> Self {
        Self::for_cgroup(assigned_bytes, cpu_millis, &crate::cgroup_memory::for_process())
    }

    /// Same production path for a role leaf, a Docker mount, or a fixture.
    pub(crate) fn for_cgroup(assigned_bytes: u64, cpu_millis: u32, cgroup: &crate::cgroup_memory::MemoryCgroup) -> Self {
        let cpu_millis = cgroup.role_cpu_millis(cpu_millis);
        let cgroup = cgroup.limit().map(|limit| limit.bytes);
        let budget = Self::derive_for_role(assigned_bytes, cgroup, cpu_millis);
        tracing::info!(
            assigned_bytes, cpu_millis, threads = budget.threads, cgroup_memory_max = ?cgroup, limit_bytes = budget.limit_bytes,
            server_bytes = budget.server_bytes, concurrency = budget.concurrency,
            per_query_bytes = budget.per_query_bytes, result_bytes = budget.result_bytes,
            "query memory budget"
        );
        budget
    }

    /// One runtime worker per usable CPU, plus one for control/IO. These
    /// futures have 16 MiB stacks; `threads` already charges their memory.
    pub fn runtime_threads(&self) -> usize {
        let workers = if self.limit_bytes <= 4 * GIB { self.threads.min(BASE_CONCURRENCY) } else { self.threads };
        workers + 1
    }

    /// General jobs share the large-memory envelope; small jobs borrow
    /// interactive slots. Eight CPUs per job preserves interactive priority.
    pub fn job_slots(&self, classes: Option<LaneClasses>) -> (usize, usize) {
        let Some(classes) = classes else { return (1, 1) };
        if self.limit_bytes <= 4 * GIB { return (1, 1); }
        let by_cpu = (self.threads / 8).max(1);
        (by_cpu.min((classes.large_bytes / GIB).max(1) as usize), by_cpu.min((classes.small_lanes / 2).max(1)))
    }
}

/// Larger runtimes need stack/cache room beside every decoded response.
/// Small roles retain their established runtime ceiling and fixed reserve.
fn result_headroom(limit: u64, server: u64, threads: usize) -> u64 {
    let headroom = limit.saturating_sub(server);
    if limit <= 4 * GIB { headroom }
    else { headroom.saturating_sub(MIN_HEADROOM_BYTES + threads as u64 * RUNTIME_HEADROOM_PER_CPU) }
}

/// The tightest memory limit on the process's cgroup path (the cgroup
/// and every ancestor visible under `root`); `None` when unreadable or
/// unlimited everywhere (e.g. the jail hides `/sys/fs/cgroup`).
pub fn cgroup_memory_max(proc_cgroup: &Path, root: &Path) -> Option<u64> {
    let text = std::fs::read_to_string(proc_cgroup).ok()?;
    let mountinfo = std::fs::read_to_string(proc_cgroup.with_file_name("mountinfo")).unwrap_or_default();
    crate::cgroup_memory::resolve(root, &text, &mountinfo, None).limit().map(|limit| limit.bytes)
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
    fn nan4825_slots_follow_cores_before_ingest_memory_and_stay_bounded() {
        for gib in [1, 2, 4, 8, 32, 64, 512] {
            for cpu in [500, 4_000, 6_000, 8_000, 16_000, 32_000, 128_000, u32::MAX] {
                let raw = QueryMemoryBudget::derive_for_role(gib * GIB, None, cpu);
                assert!(raw.concurrency >= 2);
                assert_eq!(raw.per_query_bytes, raw.server_bytes / raw.concurrency as u64);
                assert!(raw.per_query_bytes >= MIN_QUERY_BYTES);
                let (budget, classes) = raw.with_classes();
                assert_eq!(budget.concurrency, raw.concurrency, "classes cannot change core-sized admission");
                assert_eq!(budget.per_query_bytes, budget.server_bytes / budget.concurrency as u64);
                assert!(budget.threads <= 128);
                let general = budget.job_slots(classes).0;
                let decoders = budget.concurrency + super::super::engine::POINT_PERMITS + general;
                assert!(budget.result_bytes * RESULT_HEADROOM_DIVISOR * decoders as u64 <= budget.limit_bytes - budget.server_bytes);
                if gib > 4 {
                    let reserve = MIN_HEADROOM_BYTES + budget.threads as u64 * RUNTIME_HEADROOM_PER_CPU;
                    assert!(reserve + budget.result_bytes * RESULT_HEADROOM_DIVISOR * decoders as u64 <= budget.limit_bytes - budget.server_bytes);
                }
                if let Some(classes) = classes {
                    assert_eq!(classes.small_lanes + 1, budget.concurrency);
                    assert_eq!(classes.small_bytes * classes.small_lanes as u64 + classes.large_bytes, budget.server_bytes);
                }
                if gib <= 4 { assert!(budget.runtime_threads() <= 5); }
            }
        }
        // The 8-core host allocates 75% (6 cores) to query. 2 GiB left
        // after ingest no longer turns that role into a single-slot reader.
        for cpu in [6_000, 8_000] {
            let budget = QueryMemoryBudget::derive_for_role(2 * GIB, None, cpu);
            assert!(budget.concurrency >= 3);
            assert_eq!(budget.threads, 4, "keep the memory-bounded thread cap; slots still follow host CPU");
        }
        let placed = nanosiem_lake_cell::trusted_local::size_for(8 * GIB, 8, Some(10_000));
        let budget = QueryMemoryBudget::derive_for_role(placed.query.3, None, placed.query.1);
        assert!(budget.concurrency >= 3);
        assert!(placed.query.3 >= nanosiem_lake_cell::budget::QUERY_MEMORY_FLOOR_BYTES);
    }

    #[test]
    fn size_classes_preserve_the_core_derived_slots() {
        let raw = QueryMemoryBudget::derive_for_role(3 * GIB, None, 8_000);
        let (budget, classes) = raw.with_classes();
        let classes = classes.unwrap();
        assert_eq!((budget.concurrency, classes.small_lanes), (4, 3));
        assert_eq!(classes.small_bytes, SMALL_QUERY_BYTES);
        assert_eq!(classes.small_lanes as u64 * classes.small_bytes + classes.large_bytes, budget.server_bytes);
        let raw = QueryMemoryBudget::derive_for_role(GIB, None, 4_000);
        let (equal, classes) = raw.with_classes();
        assert!(classes.is_none());
        assert_eq!(equal, raw);
        assert_eq!(equal.concurrency, 2);
    }

    #[test]
    fn three_gib_query_role() {
        let budget = QueryMemoryBudget::derive(3 * GIB, Some(3 * GIB));
        assert_eq!(budget.concurrency, 2);
        assert_eq!(budget.per_query_bytes * 2, budget.server_bytes);
        assert!(budget.server_bytes < budget.limit_bytes);
    }

    #[test]
    fn detect_role_budgets() {
        let proposed = QueryMemoryBudget::derive(detect_engine_cap(2 * GIB), Some(2 * GIB)).auxiliary_role();
        assert_eq!(proposed.limit_bytes, 3 * GIB / 2);
        assert_eq!(proposed.concurrency, 1);
        assert_eq!(proposed.per_query_bytes, proposed.server_bytes);
        let floor = QueryMemoryBudget::derive(detect_engine_cap(3 * GIB / 2), Some(3 * GIB / 2)).auxiliary_role();
        assert_eq!((floor.limit_bytes, floor.concurrency), (GIB, 1));
        assert_eq!(floor.per_query_bytes, GIB - MIN_HEADROOM_BYTES);
        assert!(floor.result_bytes >= MIN_RESULT_BYTES);
        assert_eq!(detect_engine_cap(256 * MIB), 512 * MIB);
        assert_eq!(QueryMemoryBudget::derive(128 * GIB, None).auxiliary_role().result_bytes, 256 * MIB);
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
        assert_eq!(hobby.concurrency, 2);
        assert!(hobby.server_bytes < hobby.limit_bytes);
        assert!(hobby.per_query_bytes >= MIN_QUERY_BYTES);
        let big = QueryMemoryBudget::derive(7 * GIB, None);
        assert_eq!(big.concurrency, 2);
        assert!(big.per_query_bytes * 2 <= big.server_bytes);
        let huge = QueryMemoryBudget::derive(128 * GIB, None);
        assert_eq!(huge.concurrency, 2);
        assert!(huge.result_bytes > 256 * MIB, "result memory scales with headroom");
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
