// SPDX-License-Identifier: AGPL-3.0-or-later

//! Per-tenant resource budgets derived from the tenant's ingest rate
//! (design §4, NAN-2865). These are the cgroup limits the supervisor writes
//! and the placement sizes the platform packs cells with.
//!
//! Anchors (design §4.1 / §4.2):
//!
//! | eps   | request CPU / mem | limit CPU / mem |
//! |-------|-------------------|-----------------|
//! | 20    | 0.05 / 350 MiB    | 0.5 / 512 MiB   |
//! | 300   | 0.4 / 2.5 GiB     | 2 / 6.5 GiB     |
//! | 1,200 | 1.0 / 5 GiB       | 4 / 10 GiB      |
//!
//! Between anchors the values are linear in eps; below 20 eps a tenant gets
//! the hobby budget; above 1,200 the 300→1,200 slope continues ("cost scales
//! linearly"). An idle tenant has no processes, so its cost is 0 regardless.

use serde::{Deserialize, Serialize};

pub const MIB: u64 = 1024 * 1024;
pub const GIB: u64 = 1024 * MIB;
/// Query[T] reservation and burst ceiling, paired with the platform.
pub const QUERY_REQUEST_MILLICORES: u32 = 2_000;
pub const QUERY_LIMIT_MILLICORES: u32 = 3_000;
pub const DETECT_REQUEST_HOBBY_MILLICORES: u32 = 100;
pub const DETECT_REQUEST_STANDARD_MILLICORES: u32 = 150;
pub const DETECT_LIMIT_MILLICORES: u32 = 500;
/// maintenance[T] (prevalence SlateDB compactor, `lean_prevalence_maintenance_v1`):
/// one compaction job, one subcompaction, two 1 MiB fetches in flight. Fixed:
/// the compaction rate follows the tenant's L0 production, bounded by the
/// ingest share it can never exceed.
pub const MAINTENANCE_REQUEST_MILLICORES: u32 = 100;
pub const MAINTENANCE_LIMIT_MILLICORES: u32 = 250;
pub const MAINTENANCE_REQUEST_MEMORY_BYTES: u64 = 256 * MIB;
pub const MAINTENANCE_LIMIT_MEMORY_BYTES: u64 = 512 * MIB;
/// product[T] (NAN-3148, `lean_product_state_role_v1`): the tenant's product
/// state builder (prevalence windows, history, detail, risk ledger). Fixed and
/// never placed: a low `cpu.weight` (its request) so analyst search in
/// query[T] wins any contention inside the tenant cgroup, and a one-core
/// ceiling so a 30-day window build can never take more. Memory holds one
/// chDB session aggregating a 30-day window at a time.
pub const PRODUCT_REQUEST_MILLICORES: u32 = 100;
pub const PRODUCT_LIMIT_MILLICORES: u32 = 1_000;
pub const PRODUCT_REQUEST_MEMORY_BYTES: u64 = 512 * MIB;
pub const PRODUCT_LIMIT_MEMORY_BYTES: u64 = 3 * GIB;
/// landing[T] (NAN-4137, `lean_tenzir_landing_v1`): one landed file at a
/// time, at most 256 MiB on the store and 1 GiB decoded (`landing::MAX_*`),
/// converted row by row. Fixed, never placed; its ceilings are added to the
/// tenant's like product[T]'s, so a large file can never squeeze ingest or
/// query.
pub const LANDING_REQUEST_MILLICORES: u32 = 100;
pub const LANDING_LIMIT_MILLICORES: u32 = 1_000;
pub const LANDING_REQUEST_MEMORY_BYTES: u64 = 256 * MIB;
pub const LANDING_LIMIT_MEMORY_BYTES: u64 = 3 * GIB;
pub const QUERY_PLACEMENT_REQUEST_MILLICORES: u32 = 250;
/// The chDB thread count a query process opens with, from its role CPU
/// limit (fixed for the life of the process; NAN-3177).
pub fn query_threads(cpu_millis: u32) -> u32 {
    (cpu_millis / 1000).clamp(1, 8)
}
/// The smallest detect[T] memory limit that runs rule searches itself
/// (`detect_runs_rules`, NAN-3047): the engine is sized 512 MiB below the
/// limit (`part_query::memory_budget::detect_engine_cap`), so this leaves it
/// 1 GiB, enough for low-rate tenants. A 300 eps tenant needs 2 GiB
/// (measured: the OCSF rule set at claim concurrency 4 peaks ~1.0 GiB anon,
/// and its heaviest answers need the 1.5 GiB engine's result budget). Below
/// the floor the tenant keeps the legacy path (query[T]).
pub const DETECT_RULES_MIN_MEMORY_BYTES: u64 = 3 * GIB / 2;

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct TenantBudget {
    pub eps: f64,
    /// Placement request (what the platform packs by).
    pub request_millicores: u32,
    pub request_memory_bytes: u64,
    /// EPS-derived ingest CPU quota; query has a separate fixed quota.
    pub limit_millicores: u32,
    /// cgroup `memory.max` for the tenant (both roles together).
    pub limit_memory_bytes: u64,
    /// cgroup `pids.max` for the tenant.
    pub max_pids: u64,
    /// cgroup `io.weight` (1..10000, default 100).
    pub io_weight: u32,
    /// Engine memory cap handed to query[T] (chDB max_server_memory_usage).
    pub query_memory_cap_bytes: u64,
    /// Engine memory cap handed to ingest[T] (merge sizing).
    pub ingest_memory_cap_bytes: u64,
    /// Local verified-cache budget for the tenant (NAN-2853 cache).
    pub cache_disk_bytes: u64,
}

struct Anchor {
    eps: f64,
    req_cpu: f64,
    req_mem: f64,
    lim_cpu: f64,
    lim_mem: f64,
    disk: f64,
}

const ANCHORS: [Anchor; 3] = [
    Anchor { eps: 20.0, req_cpu: 50.0, req_mem: 350.0 * MIB as f64, lim_cpu: 500.0, lim_mem: 512.0 * MIB as f64, disk: 1.0 * GIB as f64 },
    Anchor { eps: 300.0, req_cpu: 400.0, req_mem: 2.5 * GIB as f64, lim_cpu: 2000.0, lim_mem: 6.5 * GIB as f64, disk: 8.0 * GIB as f64 },
    Anchor { eps: 1200.0, req_cpu: 1000.0, req_mem: 5.0 * GIB as f64, lim_cpu: 4000.0, lim_mem: 10.0 * GIB as f64, disk: 30.0 * GIB as f64 },
];

fn lerp(a: f64, b: f64, t: f64) -> f64 {
    a + (b - a) * t
}

impl TenantBudget {
    /// The budget for a tenant ingesting `eps` events per second on average.
    /// Non-finite or negative input is treated as 0 (hobby budget).
    pub fn from_eps(eps: f64) -> Self {
        let eps = if eps.is_finite() && eps > 0.0 { eps } else { 0.0 };
        let (a, b) = if eps <= ANCHORS[1].eps { (&ANCHORS[0], &ANCHORS[1]) } else { (&ANCHORS[1], &ANCHORS[2]) };
        // Clamp at the hobby floor; extrapolate above the top anchor.
        let t = ((eps.max(ANCHORS[0].eps)) - a.eps) / (b.eps - a.eps);
        let req_cpu = lerp(a.req_cpu, b.req_cpu, t);
        let req_mem = lerp(a.req_mem, b.req_mem, t);
        let lim_cpu = lerp(a.lim_cpu, b.lim_cpu, t);
        let lim_mem = lerp(a.lim_mem, b.lim_mem, t);
        let disk = lerp(a.disk, b.disk, t);

        let limit_memory_bytes = round_up(lim_mem as u64, MIB);
        let max_pids = if eps < 100.0 { 512 } else { 1024 };
        let io_weight = (100.0 + eps.max(ANCHORS[0].eps) / 4.0).clamp(100.0, 1000.0) as u32;
        Self {
            eps,
            request_millicores: req_cpu.round() as u32,
            request_memory_bytes: round_up(req_mem as u64, MIB),
            limit_millicores: lim_cpu.round() as u32,
            limit_memory_bytes,
            max_pids,
            io_weight,
            // query takes most of the tenant cap; ingest's steady state is
            // small and its merge peak is bounded by row-group size (design
            // risk 4). Both are caps inside the tenant's memory.max, so their
            // sum may exceed it.
            query_memory_cap_bytes: round_up(limit_memory_bytes / 10 * 7, MIB),
            // NAN-4749: never below the shared full-flush need at this rate
            // (only 1,093..2,480 eps, where 40 % of the curve is less).
            ingest_memory_cap_bytes: round_up(limit_memory_bytes / 10 * 4, MIB).max(ingest_memory_for_eps(eps)),
            cache_disk_bytes: round_up(disk as u64, MIB),
        }
    }

    /// cgroup v2 `cpu.max` line for this budget with a 100 ms period.
    pub fn cpu_max_line(&self) -> String {
        let period = 100_000u64;
        let quota = (self.limit_millicores as u64 * period / 1000).max(1000);
        format!("{quota} {period}")
    }
}

fn round_up(v: u64, to: u64) -> u64 {
    v.div_ceil(to) * to
}

// ------------------------------------------------- target-rate ingest sizing

/// NAN-4749: ingest[T] memory at which one full catch-up flush
/// ([`crate::contract::IngestFlush::MAX_TARGET_ROWS`] = 65,536 rows, ~206 MiB
/// of wide OCSF Arrow) is written by all four parallel L0 writers beside two
/// running minute merges and the next filling buffer (the worker's memory
/// model: working budget 30 % of this, buffer cap a fifth of that). Below it
/// the flush runs one writer and the buffer seals at its byte cap (17.5k-row
/// parts on the 1.0.11 bakeoff). Pinned against the worker's own model by
/// `part_ingest::ingest::tests::a_target_eps_placement_runs_four_l0_writers`.
///
/// Shared by every placement path (open-core trusted-local, sovereign,
/// hosted): size ingest through [`ingest_memory_for_eps`] /
/// [`ingest_query_for_eps`], never a local copy of the figure.
pub const INGEST_MEMORY_FOR_FULL_FLUSH: u64 = 6 * GIB;
/// Age cap of a catch-up flush, in seconds (the worker's
/// `CATCH_UP_FLUSH_MAX_AGE_MS`, pinned by the same worker test).
pub const CATCH_UP_FLUSH_AGE_SECS: u64 = 30;
/// Rate at which a catch-up flush fills to its row cap before its age cap:
/// at or above it every flush is a full one.
pub const FULL_FLUSH_EPS: u64 = crate::contract::IngestFlush::MAX_TARGET_ROWS / CATCH_UP_FLUSH_AGE_SECS;
/// Rows below which an hour of a flush stays one L0 part (the worker's
/// `L0_PARALLEL_MIN_ROWS`, pinned by the same worker test).
pub const L0_PART_MIN_ROWS: u64 = 16_384;
/// Lowest rate whose catch-up-age flush spans two L0 parts: below it every
/// flush is one part, which one writer writes, so memory buys no writer.
pub const PARALLEL_FLUSH_EPS: u64 = (2 * L0_PART_MIN_ROWS).div_ceil(CATCH_UP_FLUSH_AGE_SECS);
/// Query memory a target-rate shift never goes below.
pub const QUERY_MEMORY_FLOOR_BYTES: u64 = GIB;

/// NAN-4749: THE ingest[T] memory a sustained `eps` needs for parallel L0
/// flushes: [`INGEST_MEMORY_FOR_FULL_FLUSH`] from [`PARALLEL_FLUSH_EPS`]
/// (1,093 eps) up, 0 below it (a one-part flush needs nothing beyond each
/// consumer's own floor). A step, not a ramp: the two merges and the next
/// buffer the worker charges beside a flight are fixed, so a 2-3 part flush
/// needs nearly the full figure (a linear ramp left 2,000 eps, 5.5 GiB, on
/// one writer). One derivation for every product:
/// - hosted and sovereign cells: [`TenantBudget::ingest_memory_cap_bytes`]
///   (the supervisor's `ingest_memory_cap_bytes`) is never below it, and
///   the hosted deployment's ingest role limit ports it;
/// - open-core / sovereign trusted-local init: [`ingest_query_for_eps`].
///
/// Non-finite or negative input is treated as 0.
pub fn ingest_memory_for_eps(eps: f64) -> u64 {
    if eps.is_finite() && eps >= PARALLEL_FLUSH_EPS as f64 { INGEST_MEMORY_FOR_FULL_FLUSH } else { 0 }
}

/// NAN-4749: the (ingest, query) memory limits for a target `eps`, starting
/// from a placement's `ingest` / `query` limits. Ingest grows toward
/// [`ingest_memory_for_eps`] (at most `max_ingest`), and every byte it gains
/// comes out of query, which never drops below [`QUERY_MEMORY_FLOOR_BYTES`]
/// (or its starting value, if lower). The sum is unchanged, so the tenant's
/// memory ceiling and the cell's container limit are too. Limits that
/// already cover the rate come back as given.
pub fn ingest_query_for_eps(ingest: u64, query: u64, eps: u32, max_ingest: u64) -> (u64, u64) {
    let want = ingest_memory_for_eps(eps as f64).min(max_ingest);
    let shift = want.saturating_sub(ingest).min(query.saturating_sub(QUERY_MEMORY_FLOOR_BYTES)) / MIB * MIB;
    (ingest + shift, query - shift)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// NAN-4749: the shared target-rate ingest sizing.
    #[test]
    fn target_rate_ingest_sizing() {
        assert_eq!(FULL_FLUSH_EPS, 2_184);
        assert_eq!(PARALLEL_FLUSH_EPS, 1_093);
        assert_eq!(ingest_memory_for_eps(1_093.0), INGEST_MEMORY_FOR_FULL_FLUSH);
        assert_eq!(ingest_memory_for_eps(FULL_FLUSH_EPS as f64), INGEST_MEMORY_FOR_FULL_FLUSH);
        assert_eq!(ingest_memory_for_eps(1_000_000.0), INGEST_MEMORY_FOR_FULL_FLUSH);
        assert_eq!(ingest_memory_for_eps(1_092.0), 0);
        assert_eq!(ingest_memory_for_eps(f64::NAN), 0);
        assert_eq!(ingest_memory_for_eps(f64::INFINITY), 0);
        assert_eq!(ingest_memory_for_eps(-5.0), 0);
        // The 1.0.11 bakeoff cell (16 GiB): 4 GiB ingest / 8 GiB query -> 6 / 6.
        assert_eq!(ingest_query_for_eps(4 * GIB, 8 * GIB, 10_000, 8 * GIB), (6 * GIB, 6 * GIB));
        // Capped by max_ingest; query keeps its floor; the sum never changes.
        assert_eq!(ingest_query_for_eps(GIB, 2 * GIB, 10_000, 2 * GIB), (2 * GIB, GIB));
        assert_eq!(ingest_query_for_eps(768 * MIB, 1536 * MIB, 10_000, 1536 * MIB), (1280 * MIB, GIB));
        assert_eq!(ingest_query_for_eps(512 * MIB, GIB, 10_000, GIB), (512 * MIB, GIB));
        assert_eq!(ingest_query_for_eps(512 * MIB, 512 * MIB, 10_000, GIB), (512 * MIB, 512 * MIB));
        // Already covered: unchanged.
        assert_eq!(ingest_query_for_eps(16 * GIB, 32 * GIB, 10_000, 32 * GIB), (16 * GIB, 32 * GIB));
        assert_eq!(ingest_query_for_eps(4 * GIB, 8 * GIB, 100, 8 * GIB), (4 * GIB, 8 * GIB));
    }

    /// NAN-4749: the eps budget's ingest cap (hosted + sovereign cells)
    /// never below the shared need; only 1,093..2,480 eps is raised.
    #[test]
    fn the_ingest_cap_is_never_below_the_shared_need() {
        let curve = |eps: f64| round_up(TenantBudget::from_eps(eps).limit_memory_bytes / 10 * 4, MIB);
        let mut raised = Vec::new();
        for eps in (0..=20_000u32).step_by(10) {
            let b = TenantBudget::from_eps(eps as f64);
            assert_eq!(b.ingest_memory_cap_bytes, curve(eps as f64).max(ingest_memory_for_eps(eps as f64)), "{eps} eps");
            if b.ingest_memory_cap_bytes != curve(eps as f64) {
                raised.push(eps);
            }
        }
        assert_eq!((raised.first().copied(), raised.last().copied()), (Some(1_100), Some(2_480)));
        // Every live hosted rate but the 2,000-eps one (2026-10-28: 6, 50, 145, 220 eps)
        // keeps its 40 %-of-the-curve cap; the 1,200 anchor's 4 GiB -> 6 GiB.
        for eps in [6.0, 20.0, 50.0, 145.0, 220.0, 300.0, 1_092.0] {
            assert_eq!(TenantBudget::from_eps(eps).ingest_memory_cap_bytes, curve(eps), "{eps} eps");
        }
        assert_eq!(TenantBudget::from_eps(1_200.0).ingest_memory_cap_bytes, INGEST_MEMORY_FOR_FULL_FLUSH);
        // 2,000 eps (a hosted 2,000-eps tenant whose ingest role limit is
        // 4.5 GiB): 5.24 -> 6 GiB; that role limit binds the supervisor's cap.
        assert_eq!(TenantBudget::from_eps(2_000.0).ingest_memory_cap_bytes, INGEST_MEMORY_FOR_FULL_FLUSH);
    }

    #[test]
    fn anchors_match_design_section_4() {
        let hobby = TenantBudget::from_eps(20.0);
        assert_eq!(hobby.limit_millicores, 500);
        assert_eq!(hobby.limit_memory_bytes, 512 * MIB);
        assert_eq!(hobby.request_millicores, 50);
        assert_eq!(hobby.request_memory_bytes, 350 * MIB);

        let t1 = TenantBudget::from_eps(300.0);
        assert_eq!(t1.limit_millicores, 2000);
        assert_eq!(t1.limit_memory_bytes, 6656 * MIB); // 6.5 GiB ≤ 8 GB
        assert!(t1.limit_memory_bytes <= 8_000_000_000);
        assert_eq!(t1.request_millicores, 400);

        let big = TenantBudget::from_eps(1200.0);
        assert_eq!(big.limit_millicores, 4000);
        assert_eq!(big.limit_memory_bytes, 10 * GIB);
    }

    #[test]
    fn floor_monotone_and_linear_above() {
        assert_eq!(TenantBudget::from_eps(0.0), TenantBudget::from_eps(20.0).with_eps(0.0));
        assert_eq!(TenantBudget::from_eps(f64::NAN).limit_memory_bytes, 512 * MIB);
        let mut prev = TenantBudget::from_eps(0.0);
        for eps in (0..3000).step_by(50) {
            let b = TenantBudget::from_eps(eps as f64);
            assert!(b.limit_memory_bytes >= prev.limit_memory_bytes);
            assert!(b.limit_millicores >= prev.limit_millicores);
            prev = b;
        }
        // Linear continuation above 1,200 eps.
        let a = TenantBudget::from_eps(2100.0);
        assert_eq!(a.limit_millicores, 6000);
    }

    #[test]
    fn cpu_max_line() {
        assert_eq!(TenantBudget::from_eps(20.0).cpu_max_line(), "50000 100000");
        assert_eq!(TenantBudget::from_eps(300.0).cpu_max_line(), "200000 100000");
    }

    impl TenantBudget {
        fn with_eps(mut self, eps: f64) -> Self {
            self.eps = eps;
            self
        }
    }
}
