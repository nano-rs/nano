// SPDX-License-Identifier: AGPL-3.0-or-later

//! Graduated, burstable per-tenant resource enforcement (NAN-2872).
//!
//! A tenant under stress must get resources, not be killed. Every tenant has
//! a **guarantee** (its placement request: the cell is packed so all
//! guarantees fit) and may **burst** into the cell's unused capacity up to a
//! **ceiling**:
//!
//! | resource | guarantee | soft | ceiling |
//! |---|---|---|---|
//! | CPU | `request_millicores` (`cpu.weight` ∝ it) | – | max(budget limit, `cpu_burst_factor` × guarantee) ≤ cell (`cpu.max`) |
//! | memory | `request_memory_bytes` (`memory.low`) | budget limit (warn; `memory.high` target under contention) | `memory_hard_factor` × soft ≤ cell (`memory.max`) |
//!
//! The [`Controller`] is the policy, a pure function of samples so every
//! decision is unit-tested; `watchdog.rs` feeds it from `/proc` and applies
//! its actions (cgroup writes in delegated mode, SIGSTOP/SIGCONT duty cycling
//! and pidfd SIGKILLs in watchdog mode).
//!
//! **Throttle before kill:**
//!
//! 1. Over the guarantee while the cell has headroom: allowed.
//! 2. Over its weighted share while the cell is **contended** (projected CPU
//!    demand ≥ `cpu_contention_enter` × capacity, with hysteresis): CPU
//!    throttled to the share. Shares are a weighted max-min fair split of
//!    the cell (weights = guarantees), never below the guarantee, so a
//!    tenant within its guarantee is never throttled. Under **memory**
//!    contention a tenant over its memory guarantee gets `memory.high`
//!    pressure (delegated) or a CPU throttle to its guarantee (watchdog,
//!    which slows its allocation).
//! 3. Above its CPU ceiling: throttled to the ceiling (the `cpu.max`
//!    semantics), contention or not. CPU never kills.
//! 4. **SIGKILL only** at the tenant's hard memory ceiling, or when cell
//!    memory reaches `memory_kill_ratio` × capacity; then the victim is the
//!    tenant furthest **over its guarantee** (by bytes), and a tenant within
//!    its guarantee is never chosen. With no tenant over its guarantee
//!    nothing is killed and `cell_memory_critical_no_victim` is emitted.
//!
//! **Stress signal:** over the guarantee (CPU demand or memory) for
//! `sustained_pressure_secs` (15 min) emits `tenant_sustained_pressure`, and
//! the tenant status carries observed vs guarantee, so placement/autoscaling
//! can move the tenant later. Signal only; nothing moves.

use crate::budget::{TenantBudget, MIB, QUERY_LIMIT_MILLICORES, QUERY_REQUEST_MILLICORES};
use crate::config::ResourceConfig;
use crate::contract::TenantId;
use serde::Serialize;
use std::collections::HashMap;
use std::path::Path;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

// ------------------------------------------------------------------ capacity

/// What the whole cell (the pod container) may use.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct CellCapacity {
    pub cpu_millicores: u32,
    pub memory_bytes: u64,
    /// Where the numbers came from ("config", "cgroup", "host").
    pub cpu_source: &'static str,
    pub memory_source: &'static str,
}

/// `cpu.max` → millicores; `None` for `max` (unlimited).
pub fn parse_cpu_max(s: &str) -> Option<u32> {
    let mut it = s.split_whitespace();
    let quota: u64 = it.next()?.parse().ok()?;
    let period: u64 = it.next().unwrap_or("100000").parse().ok()?;
    (period > 0).then(|| (quota * 1000 / period).max(1) as u32)
}

/// `memory.max` → bytes; `None` for `max`.
pub fn parse_memory_max(s: &str) -> Option<u64> {
    s.trim().parse().ok()
}

fn mem_total() -> u64 {
    std::fs::read_to_string("/proc/meminfo")
        .ok()
        .and_then(|s| {
            s.lines().find_map(|l| l.strip_prefix("MemTotal:")).and_then(|v| v.split_whitespace().next()?.parse::<u64>().ok())
        })
        .map(|k| k * 1024)
        .unwrap_or(8 * 1024 * MIB)
}

/// Config first, then the container's own cgroup limits (`cgroup_root` is
/// the cell's cgroup directory; readable even when not delegated), then the
/// host.
pub fn detect_capacity(cfg: &ResourceConfig, cgroup_root: Option<&Path>) -> CellCapacity {
    let read = |f: &str| cgroup_root.and_then(|r| std::fs::read_to_string(r.join(f)).ok());
    let (cpu_millicores, cpu_source) = match cfg.cell_cpu_millicores {
        Some(c) => (c, "config"),
        None => match read("cpu.max").and_then(|s| parse_cpu_max(&s)) {
            Some(c) => (c, "cgroup"),
            None => (std::thread::available_parallelism().map(|n| n.get() as u32).unwrap_or(1) * 1000, "host"),
        },
    };
    let (memory_bytes, memory_source) = match cfg.cell_memory_bytes {
        Some(m) => (m, "config"),
        None => match read("memory.max").and_then(|s| parse_memory_max(&s)) {
            Some(m) => (m, "cgroup"),
            None => (mem_total(), "host"),
        },
    };
    CellCapacity { cpu_millicores: cpu_millicores.max(1), memory_bytes: memory_bytes.max(MIB), cpu_source, memory_source }
}

// ------------------------------------------------------------------ limits

/// A tenant's guarantee, soft limit and ceiling.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct TenantLimits {
    pub cpu_guarantee_millicores: u32,
    pub cpu_ceiling_millicores: u32,
    /// `cpu.weight` (1..=10000), proportional to the CPU guarantee.
    pub cpu_weight: u32,
    pub memory_guarantee_bytes: u64,
    pub memory_soft_bytes: u64,
    pub memory_hard_bytes: u64,
    pub max_pids: u64,
    pub io_weight: u32,
}

impl TenantLimits {
    pub fn from_placement(p: &crate::config::TenantPlacement, cap: &CellCapacity, cfg: &ResourceConfig) -> Self {
        let mut limits = Self::derive(&TenantBudget::from_eps(p.eps), cap, cfg);
        let ingest = p.effective_role_budget(crate::contract::Role::Ingest);
        let detect = p.effective_role_budget(crate::contract::Role::Detect);
        let query = p.effective_role_budget(crate::contract::Role::Query);
        let request = ingest.request_millicores.saturating_add(detect.request_millicores).saturating_add(query.request_millicores);
        let ceiling = ingest.limit_millicores.saturating_add(detect.limit_millicores).saturating_add(query.limit_millicores);
        limits.cpu_guarantee_millicores = request;
        limits.cpu_ceiling_millicores = ceiling.max(request);
        limits.cpu_weight = request.clamp(1, 10_000);
        limits.memory_guarantee_bytes = ingest.request_memory_bytes.saturating_add(detect.request_memory_bytes);
        limits.memory_soft_bytes = ingest.limit_memory_bytes.saturating_add(detect.limit_memory_bytes).saturating_add(query.limit_memory_bytes);
        limits.memory_hard_bytes = limits.memory_soft_bytes;
        limits
    }

    pub fn derive(b: &TenantBudget, cap: &CellCapacity, cfg: &ResourceConfig) -> Self {
        let ingest_guarantee = b.request_millicores.max(1);
        let ingest_ceiling = if cfg.cpu_burst_factor == 0.0 {
            cap.cpu_millicores
        } else {
            b.limit_millicores.max((cfg.cpu_burst_factor * ingest_guarantee as f64).round() as u32).min(cap.cpu_millicores)
        }
        .max(ingest_guarantee);
        // The cell capacity is its placement request, not its Kubernetes
        // limit. Query's 3-core burst must remain available above that
        // request, as accounted for by the platform.
        let g = ingest_guarantee.saturating_add(QUERY_REQUEST_MILLICORES);
        let ceiling = ingest_ceiling.saturating_add(QUERY_LIMIT_MILLICORES);
        let mem_g = b.request_memory_bytes;
        let soft = b.limit_memory_bytes.min(cap.memory_bytes).max(mem_g);
        let hard = ((soft as f64 * cfg.memory_hard_factor) as u64).div_ceil(MIB) * MIB;
        Self {
            cpu_guarantee_millicores: g,
            cpu_ceiling_millicores: ceiling,
            cpu_weight: g.clamp(1, 10_000),
            memory_guarantee_bytes: mem_g,
            memory_soft_bytes: soft,
            memory_hard_bytes: hard.min(cap.memory_bytes).max(soft),
            max_pids: b.max_pids,
            io_weight: b.io_weight,
        }
    }
}

/// cgroup v2 `cpu.max` line for `millicores` with a 100 ms period.
pub fn cpu_max_line(millicores: u32) -> String {
    let period = 100_000u64;
    let quota = (millicores as u64 * period / 1000).max(1000);
    format!("{quota} {period}")
}

// ------------------------------------------------------------------ samples, actions, events

/// One tenant as measured this tick.
#[derive(Debug, Clone, PartialEq)]
pub struct TenantSample {
    pub tenant: TenantId,
    pub limits: TenantLimits,
    /// CPU used over the last tick, millicores.
    pub cpu_millicores: f64,
    /// Fraction of the last tick the tenant was held back (1 − duty in
    /// watchdog mode; `throttled_usec` share in delegated mode). Used to
    /// estimate demand while throttled.
    pub throttled_fraction: f64,
    pub memory_bytes: u64,
    /// The tenant's largest process (the kill target).
    pub largest_pid: Option<u32>,
    /// Tasks (threads) across the tenant's processes.
    pub tasks: u64,
}

/// The whole cell (every process in the pod), this tick.
#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub struct CellSample {
    pub cpu_millicores: f64,
    pub memory_bytes: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ThrottleReason {
    /// Over its weighted share while the cell is CPU-contended.
    Contention,
    /// Over its CPU ceiling (`cpu.max` semantics).
    Ceiling,
    /// Over its memory guarantee while the cell is memory-contended
    /// (watchdog mode's stand-in for `memory.high`).
    MemoryPressure,
}

impl ThrottleReason {
    pub fn as_str(self) -> &'static str {
        match self {
            ThrottleReason::Contention => "cpu_contention",
            ThrottleReason::Ceiling => "cpu_ceiling",
            ThrottleReason::MemoryPressure => "memory_pressure",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum KillReason {
    /// The tenant's memory reached its hard ceiling.
    MemoryHardCeiling,
    /// The cell reached `memory_kill_ratio` of its pod limit and this tenant
    /// was the furthest over its guarantee.
    CellMemoryCritical,
    /// Watchdog mode: tasks across all tenant uids passed the cell-wide
    /// ceiling and this tenant was the furthest over its pids share.
    CellPidsCeiling,
    /// NAN-3523: the tenant's local tree passed its hard disk ceiling; its
    /// ingest is killed (see `disk_ceiling`).
    TenantDiskCeiling,
}

impl KillReason {
    pub fn as_str(self) -> &'static str {
        match self {
            KillReason::MemoryHardCeiling => "memory_hard_ceiling",
            KillReason::CellMemoryCritical => "cell_memory_critical",
            KillReason::CellPidsCeiling => "cell_pids_ceiling",
            KillReason::TenantDiskCeiling => "tenant_disk_ceiling",
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum Action {
    /// Hold the tenant to `target_millicores` (delegated: `cpu.max`;
    /// watchdog: duty cycle `duty`).
    CpuThrottle { tenant: TenantId, target_millicores: u32, duty: f64, reason: ThrottleReason },
    /// Back to the ceiling / no duty cycling.
    CpuRelease { tenant: TenantId },
    /// Write `memory.high` (pressure ≤ the soft limit, or back to its
    /// resting value, the hard ceiling).
    MemoryHigh { tenant: TenantId, bytes: u64 },
    Kill { tenant: TenantId, pid: u32, reason: KillReason, observed_bytes: u64, limit_bytes: u64 },
    /// SIGKILL every process of the tenant (a fork bomb is not stopped by
    /// killing one process).
    KillTenant { tenant: TenantId, reason: KillReason, observed: u64, limit: u64 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EventKind {
    Throttled,
    Unthrottled,
    MemoryPressure,
    MemoryPressureReleased,
    SoftLimitExceeded,
    Killed,
    CgroupOomKill,
    TenantSustainedPressure,
    CellMemoryCriticalNoVictim,
    CellPidsCeilingNoVictim,
}

impl EventKind {
    pub fn as_str(self) -> &'static str {
        match self {
            EventKind::Throttled => "throttled",
            EventKind::Unthrottled => "unthrottled",
            EventKind::MemoryPressure => "memory_pressure",
            EventKind::MemoryPressureReleased => "memory_pressure_released",
            EventKind::SoftLimitExceeded => "soft_limit_exceeded",
            EventKind::Killed => "killed",
            EventKind::CgroupOomKill => "cgroup_oom_kill",
            EventKind::TenantSustainedPressure => "tenant_sustained_pressure",
            EventKind::CellMemoryCriticalNoVictim => "cell_memory_critical_no_victim",
            EventKind::CellPidsCeilingNoVictim => "cell_pids_ceiling_no_victim",
        }
    }
}

/// Observed vs guarantee, for placement/autoscaling.
#[derive(Debug, Clone, Copy, PartialEq, Serialize)]
pub struct PressureFacts {
    pub cpu_demand_millicores: f64,
    pub cpu_guarantee_millicores: u32,
    pub memory_bytes: u64,
    pub memory_guarantee_bytes: u64,
    pub over_guarantee_secs: u64,
}

/// A structured limit event: every throttle and kill carries one.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct LimitEvent {
    pub at_unix_ms: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tenant: Option<TenantId>,
    pub kind: EventKind,
    /// Machine-readable reason (`cpu_contention`, `memory_hard_ceiling`, …).
    pub reason: String,
    pub observed: f64,
    pub limit: f64,
    pub unit: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pid: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pressure: Option<PressureFacts>,
}

impl LimitEvent {
    pub fn new(tenant: Option<&TenantId>, kind: EventKind, reason: &str, observed: f64, limit: f64, unit: &'static str) -> Self {
        Self {
            at_unix_ms: SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0),
            tenant: tenant.cloned(),
            kind,
            reason: reason.to_owned(),
            observed,
            limit,
            unit,
            pid: None,
            pressure: None,
        }
    }

    fn with_pid(mut self, pid: u32) -> Self {
        self.pid = Some(pid);
        self
    }

    /// Log it with structured fields.
    pub fn log(&self) {
        let t = self.tenant.as_ref().map(|t| t.as_str()).unwrap_or("");
        match self.kind {
            EventKind::Killed
            | EventKind::CgroupOomKill
            | EventKind::CellMemoryCriticalNoVictim
            | EventKind::CellPidsCeilingNoVictim => tracing::error!(
                tenant = t, event = self.kind.as_str(), reason = %self.reason, observed = self.observed,
                limit = self.limit, unit = self.unit, pid = ?self.pid, "tenant resource limit event"),
            EventKind::Unthrottled | EventKind::MemoryPressureReleased => tracing::info!(
                tenant = t, event = self.kind.as_str(), reason = %self.reason, observed = self.observed,
                limit = self.limit, unit = self.unit, "tenant resource limit event"),
            _ => tracing::warn!(
                tenant = t, event = self.kind.as_str(), reason = %self.reason, observed = self.observed,
                limit = self.limit, unit = self.unit, pressure = ?self.pressure, "tenant resource limit event"),
        }
    }
}

// ------------------------------------------------------------------ controller

/// Relative slack before acting on CPU (and 10 millicores absolute).
const CPU_TOLERANCE: f64 = 0.05;

#[derive(Debug, Clone, Copy, PartialEq, Serialize)]
pub struct ThrottleState {
    pub target_millicores: u32,
    pub duty: f64,
    pub reason: ThrottleReason,
}

#[derive(Debug, Default)]
struct TState {
    demand: Option<f64>,
    throttle: Option<ThrottleState>,
    memory_high: Option<u64>,
    soft_over: bool,
    over_since: Option<Instant>,
    under_since: Option<Instant>,
    pressure_reported: Option<Instant>,
    last_cpu: f64,
    last_memory: u64,
    /// The last pid we ordered killed (not re-ordered while it dies).
    last_kill: Option<(u32, Instant)>,
}

/// How long a kill order is not repeated for the same pid.
const KILL_REPEAT_AFTER: Duration = Duration::from_secs(5);

/// What status/heartbeats show per tenant.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct TenantResourceView {
    pub limits: TenantLimits,
    pub cpu_millicores: f64,
    pub cpu_demand_millicores: f64,
    pub memory_bytes: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub throttle: Option<ThrottleState>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub memory_high_bytes: Option<u64>,
    pub over_guarantee_secs: u64,
    pub sustained_pressure: bool,
}

/// Cell-level view.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct CellResourceView {
    pub capacity: CellCapacity,
    pub cpu_millicores: f64,
    pub cpu_demand_millicores: f64,
    pub memory_bytes: u64,
    pub cpu_contended: bool,
    pub memory_contended: bool,
}

#[derive(Debug, Default)]
pub struct Decision {
    pub actions: Vec<Action>,
    pub events: Vec<LimitEvent>,
}

pub struct Controller {
    cfg: ResourceConfig,
    /// Delegated mode: memory pressure is `memory.high`; watchdog mode: a
    /// CPU throttle to the guarantee.
    delegated: bool,
    cpu_contended: bool,
    mem_contended: bool,
    critical_reported: bool,
    last_critical_kill: Option<Instant>,
    other_cpu: Option<f64>,
    cell: CellSample,
    projected: f64,
    tenants: HashMap<TenantId, TState>,
    limits: HashMap<TenantId, TenantLimits>,
    /// Watchdog mode: tasks allowed across all tenant uids (tenants × 1024 +
    /// 1024); `None` = not enforced (delegated: pids.max does it).
    pids_ceiling: Option<u64>,
    pids_saturated: bool,
    pids_reported: bool,
    last_pids_kill: Option<Instant>,
}

/// Weighted max-min fair split of `capacity` among `(weight, demand)`.
pub fn water_fill(capacity: f64, items: &[(f64, f64)]) -> Vec<f64> {
    let mut alloc = vec![0.0; items.len()];
    let mut active: Vec<usize> = (0..items.len()).collect();
    let mut remaining = capacity.max(0.0);
    while !active.is_empty() && remaining > 0.0 {
        let wsum: f64 = active.iter().map(|i| items[*i].0.max(1e-9)).sum();
        let (sat, rest): (Vec<usize>, Vec<usize>) =
            active.iter().partition(|i| items[**i].1 <= remaining * items[**i].0.max(1e-9) / wsum);
        if sat.is_empty() {
            for i in &rest {
                alloc[*i] = remaining * items[*i].0.max(1e-9) / wsum;
            }
            break;
        }
        for i in sat {
            alloc[i] = items[i].1.max(0.0);
            remaining -= alloc[i];
        }
        active = rest;
    }
    alloc
}

impl Controller {
    pub fn new(cfg: ResourceConfig, delegated: bool) -> Self {
        Self {
            cfg,
            delegated,
            cpu_contended: false,
            mem_contended: false,
            critical_reported: false,
            last_critical_kill: None,
            other_cpu: None,
            cell: CellSample::default(),
            projected: 0.0,
            tenants: HashMap::new(),
            limits: HashMap::new(),
            pids_ceiling: None,
            pids_saturated: false,
            pids_reported: false,
            last_pids_kill: None,
        }
    }

    /// Live adoption of a delegated cgroup: memory pressure becomes
    /// `memory.high` from now on.
    pub fn set_delegated(&mut self, on: bool) {
        self.delegated = on;
    }

    pub fn set_pids_ceiling(&mut self, ceiling: Option<u64>) {
        self.pids_ceiling = ceiling;
        if ceiling.is_none() {
            self.pids_saturated = false;
        }
    }

    /// Tasks across tenant uids are above the cell ceiling: refuse spawns.
    pub fn pids_saturated(&self) -> bool {
        self.pids_saturated
    }

    /// The state enforcement should be in for `t` right now: the CPU
    /// throttle and the `memory.high` pressure value. The watchdog applies
    /// it every tick, idempotently, so nothing (a role restart, a
    /// recreated cgroup, a placement change) can make it drift.
    pub fn desired(&self, t: &TenantId) -> (Option<ThrottleState>, Option<u64>) {
        self.tenants.get(t).map(|s| (s.throttle, s.memory_high)).unwrap_or((None, None))
    }

    pub fn cpu_contended(&self) -> bool {
        self.cpu_contended
    }

    pub fn memory_contended(&self) -> bool {
        self.mem_contended
    }

    pub fn cell_view(&self, capacity: &CellCapacity) -> CellResourceView {
        CellResourceView {
            capacity: capacity.clone(),
            cpu_millicores: self.cell.cpu_millicores,
            cpu_demand_millicores: self.projected,
            memory_bytes: self.cell.memory_bytes,
            cpu_contended: self.cpu_contended,
            memory_contended: self.mem_contended,
        }
    }

    pub fn tenant_view(&self, t: &TenantId, now: Instant) -> Option<TenantResourceView> {
        let st = self.tenants.get(t)?;
        let over = st.over_since.map(|s| now.duration_since(s).as_secs()).unwrap_or(0);
        Some(TenantResourceView {
            limits: *self.limits.get(t)?,
            cpu_millicores: st.last_cpu,
            cpu_demand_millicores: st.demand.unwrap_or(0.0),
            memory_bytes: st.last_memory,
            throttle: st.throttle,
            memory_high_bytes: st.memory_high,
            over_guarantee_secs: over,
            sustained_pressure: over >= self.cfg.sustained_pressure_secs,
        })
    }

    /// One control step. `dt` is the time since the previous step.
    pub fn evaluate(&mut self, now: Instant, dt: Duration, cap: &CellCapacity, cell: &CellSample, ts: &[TenantSample]) -> Decision {
        let mut d = Decision::default();
        let cfg = self.cfg.clone();
        let alpha = if cfg.cpu_smoothing_secs <= 0.0 { 1.0 } else { 1.0 - (-dt.as_secs_f64() / cfg.cpu_smoothing_secs).exp() };
        let ewma = |prev: Option<f64>, x: f64| prev.map(|p| p + alpha * (x - p)).unwrap_or(x);

        // Tenants gone since the last step: release whatever they held.
        let present: std::collections::HashSet<&TenantId> = ts.iter().map(|t| &t.tenant).collect();
        let gone: Vec<TenantId> = self.tenants.keys().filter(|k| !present.contains(k)).cloned().collect();
        for t in gone {
            if let Some(st) = self.tenants.remove(&t) {
                if st.throttle.is_some() {
                    d.actions.push(Action::CpuRelease { tenant: t.clone() });
                }
            }
            self.limits.remove(&t);
        }

        // Demand: what each tenant would use unthrottled.
        let mut demand = Vec::with_capacity(ts.len());
        for t in ts {
            let st = self.tenants.entry(t.tenant.clone()).or_default();
            let raw = t.cpu_millicores / (1.0 - t.throttled_fraction.clamp(0.0, 1.0)).max(cfg.min_duty);
            st.demand = Some(ewma(st.demand, raw));
            st.last_cpu = t.cpu_millicores;
            st.last_memory = t.memory_bytes;
            self.limits.insert(t.tenant.clone(), t.limits);
            demand.push(st.demand.unwrap_or(0.0));
        }
        let tenant_cpu: f64 = ts.iter().map(|t| t.cpu_millicores).sum();
        self.other_cpu = Some(ewma(self.other_cpu, (cell.cpu_millicores - tenant_cpu).max(0.0)));
        let other = self.other_cpu.unwrap_or(0.0);
        let cap_cpu = cap.cpu_millicores as f64;
        let cap_mem = cap.memory_bytes as f64;
        self.projected = other + demand.iter().sum::<f64>();
        self.cell = *cell;

        // Contention, with hysteresis.
        if self.projected >= cfg.cpu_contention_enter * cap_cpu {
            self.cpu_contended = true;
        } else if self.projected < cfg.cpu_contention_exit * cap_cpu {
            self.cpu_contended = false;
        }
        let mem = cell.memory_bytes as f64;
        if mem >= cfg.memory_contention_enter * cap_mem {
            self.mem_contended = true;
        } else if mem < cfg.memory_contention_exit * cap_mem {
            self.mem_contended = false;
        }
        let critical = mem >= cfg.memory_kill_ratio * cap_mem;

        // Weighted shares of what the cell can give tenants.
        let guarantees: f64 = ts.iter().map(|t| t.limits.cpu_guarantee_millicores as f64).sum();
        let available = (cfg.cpu_contention_enter * cap_cpu - other).max(guarantees);
        let items: Vec<(f64, f64)> =
            ts.iter().zip(&demand).map(|(t, dm)| (t.limits.cpu_weight as f64, *dm)).collect();
        let shares = water_fill(available, &items);

        let mut killed: std::collections::HashSet<TenantId> = std::collections::HashSet::new();
        for (i, t) in ts.iter().enumerate() {
            let l = &t.limits;
            let dm = demand[i];
            let st = self.tenants.get_mut(&t.tenant).expect("inserted above");
            let g = l.cpu_guarantee_millicores as f64;
            let slack = |x: f64| x * (1.0 + CPU_TOLERANCE) + 10.0;

            // --- memory: hard ceiling kills, soft warns.
            if t.memory_bytes > l.memory_hard_bytes {
                let dying = |pid: u32| st.last_kill.is_some_and(|(p, at)| p == pid && now.duration_since(at) < KILL_REPEAT_AFTER);
                if t.largest_pid.is_some_and(dying) {
                    // Already ordered; it is on its way out.
                    killed.insert(t.tenant.clone());
                } else if let Some(pid) = t.largest_pid {
                    st.last_kill = Some((pid, now));
                    d.actions.push(Action::Kill {
                        tenant: t.tenant.clone(),
                        pid,
                        reason: KillReason::MemoryHardCeiling,
                        observed_bytes: t.memory_bytes,
                        limit_bytes: l.memory_hard_bytes,
                    });
                    d.events.push(
                        LimitEvent::new(Some(&t.tenant), EventKind::Killed, KillReason::MemoryHardCeiling.as_str(),
                            t.memory_bytes as f64, l.memory_hard_bytes as f64, "bytes")
                        .with_pid(pid),
                    );
                    killed.insert(t.tenant.clone());
                }
            }
            if t.memory_bytes > l.memory_soft_bytes && !st.soft_over {
                st.soft_over = true;
                d.events.push(LimitEvent::new(Some(&t.tenant), EventKind::SoftLimitExceeded, "memory_soft_limit",
                    t.memory_bytes as f64, l.memory_soft_bytes as f64, "bytes"));
            } else if (t.memory_bytes as f64) < l.memory_soft_bytes as f64 * 0.95 {
                st.soft_over = false;
            }

            // --- memory pressure under contention.
            let mem_over_g = t.memory_bytes > l.memory_guarantee_bytes;
            let pressure = self.mem_contended && mem_over_g;
            let mut want: Option<(u32, ThrottleReason)> = None;
            let mut consider = |target: u32, reason: ThrottleReason| {
                if want.is_none_or(|(w, _)| target < w) {
                    want = Some((target, reason));
                }
            };
            if self.delegated {
                match (pressure, st.memory_high) {
                    (true, None) => {
                        // Hold it where it is (never below the guarantee):
                        // no further growth without reclaim.
                        let high = t.memory_bytes.clamp(l.memory_guarantee_bytes, l.memory_soft_bytes).div_ceil(MIB) * MIB;
                        st.memory_high = Some(high);
                        d.actions.push(Action::MemoryHigh { tenant: t.tenant.clone(), bytes: high });
                        d.events.push(LimitEvent::new(Some(&t.tenant), EventKind::MemoryPressure, "memory_contention",
                            t.memory_bytes as f64, l.memory_guarantee_bytes as f64, "bytes"));
                    }
                    (false, Some(_)) => {
                        st.memory_high = None;
                        d.actions.push(Action::MemoryHigh { tenant: t.tenant.clone(), bytes: l.memory_hard_bytes });
                        d.events.push(LimitEvent::new(Some(&t.tenant), EventKind::MemoryPressureReleased,
                            "memory_contention_over", t.memory_bytes as f64, l.memory_hard_bytes as f64, "bytes"));
                    }
                    _ => {}
                }
            } else if pressure && dm > slack(g) {
                // Slowing its CPU slows its allocation; never below the guarantee.
                consider(l.cpu_guarantee_millicores, ThrottleReason::MemoryPressure);
            }

            // --- CPU.
            if dm > slack(l.cpu_ceiling_millicores as f64) {
                consider(l.cpu_ceiling_millicores, ThrottleReason::Ceiling);
            }
            let share = shares[i].max(g).min(l.cpu_ceiling_millicores as f64);
            if self.cpu_contended && dm > slack(share) && dm > g {
                consider(share.round() as u32, ThrottleReason::Contention);
            }
            if killed.contains(&t.tenant) {
                want = None;
            }
            match want {
                Some((target, reason)) => {
                    let duty = if dm > 0.0 { (target as f64 / dm).clamp(cfg.min_duty, 1.0) } else { 1.0 };
                    let changed = match st.throttle {
                        None => true,
                        Some(old) => {
                            old.reason != reason
                                || (old.target_millicores as f64 - target as f64).abs() > old.target_millicores as f64 * 0.05
                                || (old.duty - duty).abs() > 0.02
                        }
                    };
                    let fresh = st.throttle.is_none_or(|o| o.reason != reason);
                    st.throttle = Some(ThrottleState { target_millicores: target, duty, reason });
                    if changed {
                        d.actions.push(Action::CpuThrottle { tenant: t.tenant.clone(), target_millicores: target, duty, reason });
                    }
                    if fresh {
                        let limit = match reason {
                            ThrottleReason::MemoryPressure => l.memory_guarantee_bytes as f64,
                            _ => target as f64,
                        };
                        let (observed, unit) = match reason {
                            ThrottleReason::MemoryPressure => (t.memory_bytes as f64, "bytes"),
                            _ => (dm, "millicores"),
                        };
                        d.events.push(LimitEvent::new(Some(&t.tenant), EventKind::Throttled, reason.as_str(), observed, limit, unit));
                    }
                }
                None => {
                    if let Some(old) = st.throttle.take() {
                        d.actions.push(Action::CpuRelease { tenant: t.tenant.clone() });
                        d.events.push(LimitEvent::new(Some(&t.tenant), EventKind::Unthrottled, old.reason.as_str(), dm,
                            old.target_millicores as f64, "millicores"));
                    }
                }
            }

            // --- sustained pressure (signal only).
            let over = dm > slack(g) || mem_over_g;
            if over {
                st.under_since = None;
                let since = *st.over_since.get_or_insert(now);
                let secs = now.duration_since(since).as_secs();
                let due = st.pressure_reported.is_none_or(|r| now.duration_since(r).as_secs() >= cfg.sustained_pressure_secs);
                if secs >= cfg.sustained_pressure_secs && due {
                    st.pressure_reported = Some(now);
                    let mut e = LimitEvent::new(Some(&t.tenant), EventKind::TenantSustainedPressure, "over_guarantee_sustained",
                        dm, g, "millicores");
                    e.pressure = Some(PressureFacts {
                        cpu_demand_millicores: dm,
                        cpu_guarantee_millicores: l.cpu_guarantee_millicores,
                        memory_bytes: t.memory_bytes,
                        memory_guarantee_bytes: l.memory_guarantee_bytes,
                        over_guarantee_secs: secs,
                    });
                    d.events.push(e);
                }
            } else if st.over_since.is_some() {
                let since = *st.under_since.get_or_insert(now);
                if now.duration_since(since).as_secs() >= cfg.pressure_reset_secs {
                    st.over_since = None;
                    st.under_since = None;
                    st.pressure_reported = None;
                }
            }
        }

        // --- cell memory critical: one victim per cooldown, by overage.
        if critical {
            let cooldown = dt.max(Duration::from_secs(1)) * 2;
            if self.last_critical_kill.is_none_or(|at| now.duration_since(at) >= cooldown) {
                let victim = ts
                    .iter()
                    .filter(|t| !killed.contains(&t.tenant) && t.largest_pid.is_some())
                    .filter(|t| t.memory_bytes > t.limits.memory_guarantee_bytes)
                    .max_by_key(|t| t.memory_bytes - t.limits.memory_guarantee_bytes);
                match victim {
                    Some(v) => {
                        let pid = v.largest_pid.expect("filtered");
                        self.last_critical_kill = Some(now);
                        self.critical_reported = false;
                        d.actions.push(Action::Kill {
                            tenant: v.tenant.clone(),
                            pid,
                            reason: KillReason::CellMemoryCritical,
                            observed_bytes: v.memory_bytes,
                            limit_bytes: v.limits.memory_guarantee_bytes,
                        });
                        d.events.push(
                            LimitEvent::new(Some(&v.tenant), EventKind::Killed, KillReason::CellMemoryCritical.as_str(),
                                v.memory_bytes as f64, v.limits.memory_guarantee_bytes as f64, "bytes")
                            .with_pid(pid),
                        );
                        if let Some(st) = self.tenants.get_mut(&v.tenant) {
                            if st.throttle.take().is_some() {
                                d.actions.push(Action::CpuRelease { tenant: v.tenant.clone() });
                            }
                        }
                    }
                    None if !self.critical_reported => {
                        self.critical_reported = true;
                        d.events.push(LimitEvent::new(None, EventKind::CellMemoryCriticalNoVictim,
                            "every_tenant_within_guarantee", mem, cfg.memory_kill_ratio * cap_mem, "bytes"));
                    }
                    None => {}
                }
            }
        } else {
            self.critical_reported = false;
        }

        // --- cell-wide pids ceiling (watchdog mode only).
        if let Some(ceiling) = self.pids_ceiling {
            let total: u64 = ts.iter().map(|t| t.tasks).sum();
            self.pids_saturated = total > ceiling;
            if self.pids_saturated {
                let cooldown = dt.max(Duration::from_secs(1)) * 2;
                if self.last_pids_kill.is_none_or(|at| now.duration_since(at) >= cooldown) {
                    // Share = the tenant's own pids limit; never a tenant within it.
                    let victim = ts
                        .iter()
                        .filter(|t| !killed.contains(&t.tenant) && t.tasks > t.limits.max_pids)
                        .max_by_key(|t| t.tasks - t.limits.max_pids);
                    match victim {
                        Some(v) => {
                            self.last_pids_kill = Some(now);
                            self.pids_reported = false;
                            d.actions.push(Action::KillTenant {
                                tenant: v.tenant.clone(),
                                reason: KillReason::CellPidsCeiling,
                                observed: v.tasks,
                                limit: v.limits.max_pids,
                            });
                            d.events.push(LimitEvent::new(Some(&v.tenant), EventKind::Killed,
                                KillReason::CellPidsCeiling.as_str(), v.tasks as f64, v.limits.max_pids as f64, "tasks"));
                        }
                        None if !self.pids_reported => {
                            self.pids_reported = true;
                            d.events.push(LimitEvent::new(None, EventKind::CellPidsCeilingNoVictim,
                                "every_tenant_within_its_pids_share", total as f64, ceiling as f64, "tasks"));
                        }
                        None => {}
                    }
                }
            } else {
                self.pids_reported = false;
            }
        }
        d
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::budget::GIB;

    fn cap(cpu: u32, mem: u64) -> CellCapacity {
        CellCapacity { cpu_millicores: cpu, memory_bytes: mem, cpu_source: "config", memory_source: "config" }
    }

    #[test]
    fn rendered_role_budgets_set_additive_parent_guarantee_and_ceiling() {
        let placement: crate::config::TenantPlacement = serde_json::from_value(serde_json::json!({
            "tenant_id":"tenant-a", "eps":300.0,
            "ingest_request_millicores":400,"ingest_limit_millicores":2000,
            "ingest_request_memory_bytes":2684354560u64,"ingest_limit_memory_bytes":6979321856u64,
            "detect_request_millicores":150,"detect_limit_millicores":500,
            "detect_request_memory_bytes":134217728u64,"detect_limit_memory_bytes":268435456u64,
            "query_request_millicores":250,"query_limit_millicores":3000,
            "query_request_memory_bytes":268435456u64,"query_limit_memory_bytes":4892233728u64
        })).unwrap();
        let limits = TenantLimits::from_placement(&placement, &cap(8000, 32 * GIB), &ResourceConfig::default());
        assert_eq!(limits.cpu_guarantee_millicores, 800);
        assert_eq!(limits.cpu_ceiling_millicores, 5500);
        assert_eq!(limits.memory_guarantee_bytes, 2684354560 + 134217728);
        assert_eq!(limits.memory_hard_bytes, 6979321856 + 268435456 + 4892233728);
    }

    fn lim(g_cpu: u32, ceiling: u32, g_mem: u64, soft: u64, hard: u64) -> TenantLimits {
        TenantLimits {
            cpu_guarantee_millicores: g_cpu,
            cpu_ceiling_millicores: ceiling,
            cpu_weight: g_cpu,
            memory_guarantee_bytes: g_mem,
            memory_soft_bytes: soft,
            memory_hard_bytes: hard,
            max_pids: 512,
            io_weight: 100,
        }
    }

    fn sample(t: &str, l: TenantLimits, cpu: f64, mem: u64, pid: u32) -> TenantSample {
        TenantSample {
            tenant: TenantId::new(t).unwrap(),
            limits: l,
            cpu_millicores: cpu,
            throttled_fraction: 0.0,
            memory_bytes: mem,
            largest_pid: Some(pid),
            tasks: 1,
        }
    }

    fn cfg() -> ResourceConfig {
        ResourceConfig { cpu_smoothing_secs: 0.0, ..Default::default() }
    }

    fn cell_of(ts: &[TenantSample]) -> CellSample {
        CellSample { cpu_millicores: ts.iter().map(|t| t.cpu_millicores).sum(), memory_bytes: ts.iter().map(|t| t.memory_bytes).sum() }
    }

    fn kills(d: &Decision) -> Vec<(String, u32, KillReason)> {
        d.actions
            .iter()
            .filter_map(|a| match a {
                Action::Kill { tenant, pid, reason, .. } => Some((tenant.to_string(), *pid, *reason)),
                _ => None,
            })
            .collect()
    }

    fn throttles(d: &Decision) -> Vec<(String, u32, ThrottleReason)> {
        d.actions
            .iter()
            .filter_map(|a| match a {
                Action::CpuThrottle { tenant, target_millicores, reason, .. } => {
                    Some((tenant.to_string(), *target_millicores, *reason))
                }
                _ => None,
            })
            .collect()
    }

    const S: Duration = Duration::from_secs(1);

    #[test]
    fn limits_from_budget_and_cell() {
        let c = cap(8000, 32 * GIB);
        let hobby = TenantLimits::derive(&TenantBudget::from_eps(20.0), &c, &ResourceConfig::default());
        assert_eq!(hobby.cpu_guarantee_millicores, 2050);
        assert_eq!(hobby.cpu_ceiling_millicores, 3500, "ingest and query ceilings are additive");
        assert_eq!(hobby.cpu_weight, 2050);
        assert_eq!(hobby.memory_guarantee_bytes, 350 * MIB);
        assert_eq!(hobby.memory_soft_bytes, 512 * MIB);
        assert_eq!(hobby.memory_hard_bytes, 640 * MIB);
        let big = TenantLimits::derive(&TenantBudget::from_eps(1200.0), &c, &ResourceConfig::default());
        assert_eq!(big.cpu_ceiling_millicores, 7000);
        let at_300 = TenantLimits::derive(&TenantBudget::from_eps(300.0), &c, &ResourceConfig::default());
        assert_eq!(at_300.cpu_guarantee_millicores, 2400);
        assert_eq!(at_300.cpu_ceiling_millicores, 5000);
        // Capped at the cell.
        let small_cell = cap(1000, 4 * GIB);
        let t1 = TenantLimits::derive(&TenantBudget::from_eps(300.0), &small_cell, &ResourceConfig::default());
        assert_eq!(t1.cpu_ceiling_millicores, 4000);
        assert_eq!(t1.memory_soft_bytes, 4 * GIB);
        assert_eq!(t1.memory_hard_bytes, 4 * GIB);
        // factor 0 = the whole cell.
        let whole = TenantLimits::derive(&TenantBudget::from_eps(20.0), &c, &ResourceConfig { cpu_burst_factor: 0.0, ..Default::default() });
        assert_eq!(whole.cpu_ceiling_millicores, 11000);
        assert_eq!(cpu_max_line(500), "50000 100000");
        assert_eq!(cpu_max_line(0), "1000 100000");
    }

    #[test]
    fn capacity_parsing_and_detection() {
        assert_eq!(parse_cpu_max("200000 100000\n"), Some(2000));
        assert_eq!(parse_cpu_max("max 100000"), None);
        assert_eq!(parse_memory_max("8589934592\n"), Some(8 * GIB));
        assert_eq!(parse_memory_max("max\n"), None);
        let d = tempfile::tempdir().unwrap();
        std::fs::write(d.path().join("cpu.max"), "400000 100000\n").unwrap();
        std::fs::write(d.path().join("memory.max"), "max\n").unwrap();
        let c = detect_capacity(&ResourceConfig::default(), Some(d.path()));
        assert_eq!((c.cpu_millicores, c.cpu_source), (4000, "cgroup"));
        assert_eq!(c.memory_source, "host");
        let c = detect_capacity(&ResourceConfig { cell_memory_bytes: Some(GIB), ..Default::default() }, Some(d.path()));
        assert_eq!((c.memory_bytes, c.memory_source), (GIB, "config"));
    }

    #[test]
    fn water_fill_is_weighted_max_min() {
        let a = water_fill(900.0, &[(50.0, 900.0), (400.0, 300.0)]);
        assert!((a[0] - 600.0).abs() < 1e-6 && (a[1] - 300.0).abs() < 1e-6, "{a:?}");
        let b = water_fill(1000.0, &[(1.0, 1000.0), (3.0, 1000.0)]);
        assert!((b[0] - 250.0).abs() < 1e-6 && (b[1] - 750.0).abs() < 1e-6, "{b:?}");
        let c = water_fill(1000.0, &[(1.0, 10.0), (1.0, 20.0)]);
        assert_eq!(c, vec![10.0, 20.0]);
    }

    #[test]
    fn burst_is_allowed_while_the_cell_has_headroom() {
        let mut c = Controller::new(cfg(), false);
        let cp = cap(4000, 16 * GIB);
        // 10× its CPU guarantee and over its memory guarantee, but within
        // the ceilings and the cell is mostly idle.
        let ts = [sample("a", lim(50, 1000, 350 * MIB, 512 * MIB, 640 * MIB), 500.0, 500 * MIB, 11)];
        for _ in 0..5 {
            let d = c.evaluate(Instant::now(), S, &cp, &cell_of(&ts), &ts);
            assert!(d.actions.is_empty(), "{:?}", d.actions);
        }
        assert!(!c.cpu_contended());
    }

    #[test]
    fn throttled_to_its_share_under_contention_and_released_after() {
        let mut c = Controller::new(cfg(), false);
        let cp = cap(1000, 16 * GIB);
        let a = lim(50, 1000, GIB, 2 * GIB, 3 * GIB);
        let b = lim(400, 1000, GIB, 2 * GIB, 3 * GIB);
        let ts = [sample("a", a, 900.0, 0, 11), sample("b", b, 300.0, 0, 21)];
        let d = c.evaluate(Instant::now(), S, &cp, &cell_of(&ts), &ts);
        assert!(c.cpu_contended());
        // a (weight 50) gets what b (weight 400, demand 300) leaves of 900.
        assert_eq!(throttles(&d), vec![("a".into(), 600, ThrottleReason::Contention)]);
        let ev = d.events.iter().find(|e| e.kind == EventKind::Throttled).unwrap();
        assert_eq!((ev.reason.as_str(), ev.observed, ev.limit), ("cpu_contention", 900.0, 600.0));
        match &d.actions[0] {
            Action::CpuThrottle { duty, .. } => assert!((duty - 600.0 / 900.0).abs() < 1e-6),
            other => panic!("{other:?}"),
        }
        // Held: a now runs at 600 with 1/3 of the time stopped → demand
        // stays 900, still contended, no new action.
        let ts2 = [TenantSample { throttled_fraction: 1.0 / 3.0, ..sample("a", a, 600.0, 0, 11) }, sample("b", b, 300.0, 0, 21)];
        let d = c.evaluate(Instant::now(), S, &cp, &cell_of(&ts2), &ts2);
        assert!(throttles(&d).is_empty() && !d.actions.iter().any(|x| matches!(x, Action::CpuRelease { .. })), "{:?}", d.actions);
        // b goes idle: headroom → a released.
        let ts3 = [TenantSample { throttled_fraction: 1.0 / 3.0, ..sample("a", a, 400.0, 0, 11) }, sample("b", b, 0.0, 0, 21)];
        let d = c.evaluate(Instant::now(), S, &cp, &cell_of(&ts3), &ts3);
        assert!(!c.cpu_contended());
        assert!(d.actions.contains(&Action::CpuRelease { tenant: TenantId::new("a").unwrap() }), "{:?}", d.actions);
        assert!(d.events.iter().any(|e| e.kind == EventKind::Unthrottled));
    }

    #[test]
    fn a_tenant_within_its_guarantee_is_never_throttled_or_killed() {
        let mut c = Controller::new(cfg(), false);
        let cp = cap(1000, 4 * GIB);
        let within = lim(500, 1000, 2 * GIB, 3 * GIB, 4 * GIB);
        let hog = lim(100, 1000, 256 * MIB, 512 * MIB, 4 * GIB);
        // Cell CPU and memory both critical; `within` is the biggest user
        // of memory but inside its guarantee.
        let ts = [sample("within", within, 480.0, 2 * GIB - MIB, 11), sample("hog", hog, 900.0, 1900 * MIB, 21)];
        for _ in 0..3 {
            let d = c.evaluate(Instant::now(), S, &cp, &cell_of(&ts), &ts);
            assert!(throttles(&d).iter().all(|(t, ..)| t != "within"), "{:?}", d.actions);
            assert!(kills(&d).iter().all(|(t, ..)| t != "within"), "{:?}", d.actions);
        }
        // With nobody over its guarantee there is no victim at all.
        let mut c = Controller::new(cfg(), false);
        let ts = [sample("within", within, 480.0, 2 * GIB - MIB, 11), sample("w2", within, 480.0, 2 * GIB - MIB, 21)];
        let d = c.evaluate(Instant::now(), S, &cp, &cell_of(&ts), &ts);
        assert!(kills(&d).is_empty());
        assert_eq!(d.events.iter().filter(|e| e.kind == EventKind::CellMemoryCriticalNoVictim).count(), 1);
        let d = c.evaluate(Instant::now(), S, &cp, &cell_of(&ts), &ts);
        assert_eq!(d.events.iter().filter(|e| e.kind == EventKind::CellMemoryCriticalNoVictim).count(), 0, "reported once");
    }

    #[test]
    fn cell_memory_critical_kills_the_largest_overage_not_the_largest_user() {
        let mut c = Controller::new(cfg(), true);
        let cp = cap(8000, 10 * GIB);
        let t = |g: u64| lim(100, 1000, g, 8 * GIB, 9 * GIB);
        let ts = [
            sample("big-within", t(5 * GIB), 0.0, 5 * GIB, 11),            // within guarantee, largest user
            sample("over-small", t(GIB), 0.0, GIB + 512 * MIB, 21),        // 512 MiB over
            sample("over-large", t(512 * MIB), 0.0, 2 * GIB + 512 * MIB, 31), // 2 GiB over
            sample("idle", t(GIB), 0.0, 512 * MIB, 41),
        ];
        let d = c.evaluate(Instant::now(), S, &cp, &cell_of(&ts), &ts);
        assert_eq!(kills(&d), vec![("over-large".into(), 31, KillReason::CellMemoryCritical)]);
        let ev = d.events.iter().find(|e| e.kind == EventKind::Killed).unwrap();
        assert_eq!(ev.pid, Some(31));
        // Cooldown: the next tick (victim still dying) kills nobody else.
        let d = c.evaluate(Instant::now(), S, &cp, &cell_of(&ts), &ts);
        assert!(kills(&d).is_empty());
    }

    #[test]
    fn hard_ceiling_kills_even_with_headroom_soft_only_warns() {
        let mut c = Controller::new(cfg(), false);
        let cp = cap(8000, 64 * GIB);
        let l = lim(50, 500, 350 * MIB, 512 * MIB, 640 * MIB);
        let ts = [sample("a", l, 10.0, 600 * MIB, 11)];
        let d = c.evaluate(Instant::now(), S, &cp, &cell_of(&ts), &ts);
        assert!(kills(&d).is_empty());
        assert_eq!(d.events.iter().filter(|e| e.kind == EventKind::SoftLimitExceeded).count(), 1);
        let ts = [sample("a", l, 10.0, 700 * MIB, 11)];
        let d = c.evaluate(Instant::now(), S, &cp, &cell_of(&ts), &ts);
        assert_eq!(kills(&d), vec![("a".into(), 11, KillReason::MemoryHardCeiling)]);
        let e = d.events.iter().find(|e| e.kind == EventKind::Killed).unwrap();
        assert_eq!((e.observed, e.limit, e.unit), ((700 * MIB) as f64, (640 * MIB) as f64, "bytes"));
        // Not re-ordered while that pid dies; a new largest pid is.
        let d = c.evaluate(Instant::now(), S, &cp, &cell_of(&ts), &ts);
        assert!(kills(&d).is_empty() && d.events.is_empty(), "{:?}", d.actions);
        let ts = [sample("a", l, 10.0, 700 * MIB, 12)];
        assert_eq!(kills(&c.evaluate(Instant::now(), S, &cp, &cell_of(&ts), &ts)).len(), 1);
    }

    #[test]
    fn ceiling_throttles_without_contention() {
        let mut c = Controller::new(cfg(), false);
        let cp = cap(16000, 64 * GIB);
        let l = lim(50, 500, 350 * MIB, 512 * MIB, 640 * MIB);
        let ts = [sample("a", l, 2000.0, 0, 11)];
        let d = c.evaluate(Instant::now(), S, &cp, &cell_of(&ts), &ts);
        assert!(!c.cpu_contended());
        assert_eq!(throttles(&d), vec![("a".into(), 500, ThrottleReason::Ceiling)]);
        match &d.actions[0] {
            Action::CpuThrottle { duty, .. } => assert!((duty - 0.25).abs() < 1e-6),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn memory_pressure_is_memory_high_when_delegated_and_a_cpu_throttle_otherwise() {
        let cp = cap(8000, 10 * GIB);
        let l = lim(100, 1000, GIB, 4 * GIB, 5 * GIB);
        // 9 GiB of 10 used: contended (≥ 85%), not critical (< 95%).
        let ts = [sample("a", l, 400.0, 3 * GIB, 11), sample("b", lim(100, 1000, 6 * GIB, 7 * GIB, 8 * GIB), 50.0, 6 * GIB, 21)];
        let mut del = Controller::new(cfg(), true);
        let d = del.evaluate(Instant::now(), S, &cp, &cell_of(&ts), &ts);
        assert_eq!(d.actions, vec![Action::MemoryHigh { tenant: TenantId::new("a").unwrap(), bytes: 3 * GIB }]);
        assert!(kills(&d).is_empty());
        let mut wd = Controller::new(cfg(), false);
        let d = wd.evaluate(Instant::now(), S, &cp, &cell_of(&ts), &ts);
        assert_eq!(throttles(&d), vec![("a".into(), 100, ThrottleReason::MemoryPressure)]);
        // Contention over → memory.high back to rest (the hard ceiling).
        let calm = [sample("a", l, 400.0, 3 * GIB, 11)];
        let d = del.evaluate(Instant::now(), S, &cp, &cell_of(&calm), &calm);
        assert_eq!(d.actions, vec![Action::MemoryHigh { tenant: TenantId::new("a").unwrap(), bytes: 5 * GIB }]);
    }

    #[test]
    fn sustained_pressure_fires_after_the_window_and_survives_short_dips() {
        let config = ResourceConfig { sustained_pressure_secs: 900, pressure_reset_secs: 60, ..cfg() };
        let mut c = Controller::new(config, false);
        let cp = cap(8000, 64 * GIB);
        let l = lim(100, 2000, GIB, 2 * GIB, 3 * GIB);
        let over = [sample("a", l, 400.0, GIB / 2, 11)];
        let under = [sample("a", l, 50.0, GIB / 2, 11)];
        let t0 = Instant::now();
        let mut fired = vec![];
        for s in 0..=1900u64 {
            let now = t0 + Duration::from_secs(s);
            // A 30 s dip at 600 s must not reset the clock.
            let ts = if (600..630).contains(&s) { &under } else { &over };
            let d = c.evaluate(now, S, &cp, &cell_of(ts), ts);
            for e in d.events.iter().filter(|e| e.kind == EventKind::TenantSustainedPressure) {
                fired.push(s);
                let p = e.pressure.unwrap();
                assert_eq!((p.cpu_guarantee_millicores, p.memory_guarantee_bytes), (100, GIB));
                assert!((p.cpu_demand_millicores - 400.0).abs() < 1e-6);
            }
            // Burst allowed: never throttled or killed.
            assert!(d.actions.is_empty(), "t={s}: {:?}", d.actions);
        }
        assert_eq!(fired, vec![900, 1800], "fires at 15 min and every 15 min after");
        let v = c.tenant_view(&TenantId::new("a").unwrap(), t0 + Duration::from_secs(1900)).unwrap();
        assert!(v.sustained_pressure && v.over_guarantee_secs >= 1900);
        // A long dip resets it.
        for s in 1901..=1980u64 {
            c.evaluate(t0 + Duration::from_secs(s), S, &cp, &cell_of(&under), &under);
        }
        let v = c.tenant_view(&TenantId::new("a").unwrap(), t0 + Duration::from_secs(1980)).unwrap();
        assert!(!v.sustained_pressure && v.over_guarantee_secs == 0);
    }

    #[test]
    fn a_departed_tenant_is_released() {
        let mut c = Controller::new(cfg(), false);
        let cp = cap(16000, 64 * GIB);
        let ts = [sample("a", lim(50, 500, GIB, 2 * GIB, 3 * GIB), 2000.0, 0, 11)];
        c.evaluate(Instant::now(), S, &cp, &cell_of(&ts), &ts);
        let d = c.evaluate(Instant::now(), S, &cp, &CellSample::default(), &[]);
        assert_eq!(d.actions, vec![Action::CpuRelease { tenant: TenantId::new("a").unwrap() }]);
    }

    #[test]
    fn cell_pids_ceiling_kills_the_furthest_over_its_share_and_refuses_spawns() {
        let mut c = Controller::new(cfg(), false);
        c.set_pids_ceiling(Some(2 * 1024 + 1024));
        let cp = cap(8000, 64 * GIB);
        let l = lim(50, 500, GIB, 2 * GIB, 3 * GIB); // max_pids 512
        let t = |name: &str, tasks: u64, pid: u32| TenantSample { tasks, ..sample(name, l, 10.0, MIB, pid) };
        // Under the ceiling: nothing, even with a tenant over its share.
        let ts = [t("a", 900, 11), t("b", 100, 21)];
        let d = c.evaluate(Instant::now(), S, &cp, &cell_of(&ts), &ts);
        assert!(d.actions.is_empty() && !c.pids_saturated());
        // Over: "bomb" (+2000 over its 512) goes, not "busy" (+500) nor "big" (within).
        let ts = [t("big", 500, 11), t("busy", 1012, 21), t("bomb", 2512, 31)];
        let d = c.evaluate(Instant::now(), S, &cp, &cell_of(&ts), &ts);
        assert!(c.pids_saturated());
        assert_eq!(
            d.actions,
            vec![Action::KillTenant { tenant: TenantId::new("bomb").unwrap(), reason: KillReason::CellPidsCeiling, observed: 2512, limit: 512 }]
        );
        // Everyone within their share: no victim, reported once.
        let mut c = Controller::new(cfg(), false);
        c.set_pids_ceiling(Some(1000));
        let ts = [t("x", 500, 11), t("y", 510, 21)];
        let d = c.evaluate(Instant::now(), S, &cp, &cell_of(&ts), &ts);
        assert!(d.actions.is_empty() && c.pids_saturated());
        assert_eq!(d.events.iter().filter(|e| e.kind == EventKind::CellPidsCeilingNoVictim).count(), 1);
        // Not enforced when unset (delegated mode).
        c.set_pids_ceiling(None);
        assert!(!c.pids_saturated());
    }
}
