// SPDX-License-Identifier: AGPL-3.0-or-later

//! The resource watchdog (NAN-2872): measures every tenant from `/proc`
//! each `interval_ms` (default 1 s), runs the [`Controller`] and applies its
//! decisions. It is always on: without cgroup delegation it is the
//! enforcement, and with delegation it is the second layer plus the dynamic
//! policy.
//!
//! Per tick:
//!
//! - one `/proc` scan;
//! - tenant membership by **uid** (every process a tenant starts, including
//!   double-forked orphans, runs as one of its uids) and by ancestry from
//!   its root processes, keyed by (pid, start time);
//! - per-tenant CPU (utime+stime deltas) and memory ([`MemoryMetric`]);
//! - cell memory from the container cgroup's `memory.current` minus
//!   reclaimable file pages (readable without delegation), falling back to
//!   the `/proc` sum.
//!
//! Then the **desired state** is applied to every tenant, idempotently,
//! every tick:
//!
//! - **delegated:** `cpu.max` = throttle target or ceiling; `memory.high` =
//!   pressure value or the ceiling. A recreated cgroup or a placement change
//!   cannot drift, and `cpu.max` covers every process in the cgroup, so
//!   there is no membership race.
//! - **watchdog:** a SIGSTOP/SIGCONT duty cycle per throttled tenant (one
//!   small thread each, period `throttle_period_ms`). The thread refreshes
//!   membership from the tenant's uids every few cycles, so a freshly
//!   forked helper is caught within about 250 ms, not at the next tick.
//!
//! **No long-lived pidfds** (they would scale with tenant processes and
//! exhaust fds). A pid is signalled by opening a pidfd at signal time and
//! verifying the start time ([`PidFd::open_verified`]); a SIGSTOP and its
//! SIGCONT reuse one pidfd, held only for the stop phase.
//!
//! Kills are returned to the caller ([`KillOrder`]), so the supervisor can
//! record why a process it owns died before the signal lands.
//!
//! **Known gap (memfd / shm):** anonymous shared memory that a tenant holds
//! but does not map (e.g. a memfd filled with write()) appears in no
//! process's RSS. It counts toward cell memory (the cgroup's
//! `memory.current`) but cannot be attributed to a tenant in watchdog mode.
//! In delegated mode it is charged to the tenant's cgroup and bounded by
//! `memory.max`.

use crate::config::ResourceConfig;
use crate::contract::TenantId;
use crate::limits::CgroupTree;
use crate::pidfd::PidFd;
use crate::procfs::{self, CpuAccount, ProcKey};
use crate::resources::{
    Action, CellCapacity, CellResourceView, CellSample, Controller, KillReason, LimitEvent, TenantLimits,
    TenantResourceView, TenantSample,
};
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// One tenant to watch.
#[derive(Debug, Clone)]
pub struct TenantSpec {
    pub tenant: TenantId,
    pub limits: TenantLimits,
    /// The tenant's processes the supervisor started, by (pid, start time).
    pub roots: Vec<ProcKey>,
    /// The tenant's uids (every process running as one belongs to it).
    pub uids: Vec<u32>,
    /// Processes being shut down: measured, never stopped by the throttle.
    pub exempt: Vec<ProcKey>,
    /// Uids whose processes are measured but never duty-cycled (NAN-3008:
    /// the tenant's query uid, see `ResourceConfig::query_unthrottled`).
    pub unthrottled_uids: Vec<u32>,
}

/// A kill the caller must carry out (and account for).
#[derive(Debug, Clone)]
pub struct KillOrder {
    pub tenant: TenantId,
    pub pid: u32,
    pub starttime: u64,
    pub reason: KillReason,
    pub observed_bytes: u64,
    pub limit_bytes: u64,
}

impl KillOrder {
    /// SIGKILL, unless the pid now names another process.
    pub fn kill(&self) {
        if let Some(fd) = PidFd::open_verified(self.pid, self.starttime) {
            fd.kill();
        }
    }
}

/// SIGKILL every process in `keys` (start-time verified). Returns how many
/// were signalled.
pub fn kill_all(keys: &[ProcKey]) -> usize {
    keys.iter()
        .filter_map(|(pid, st)| PidFd::open_verified(*pid, *st))
        .map(|fd| fd.kill())
        .count()
}

#[derive(Debug, Default)]
pub struct TickOutput {
    pub samples: Vec<TenantSample>,
    pub cell: CellSample,
    pub kills: Vec<KillOrder>,
    /// Kill every process of these tenants (cell pids ceiling).
    pub kill_tenants: Vec<(TenantId, KillReason)>,
    pub events: Vec<LimitEvent>,
}

// ------------------------------------------------------------------ duty-cycle throttle

/// Membership refresh every this many duty cycles.
const REFRESH_CYCLES: u32 = 3;

struct DutyShared {
    duty_bits: AtomicU64,
    stop: AtomicBool,
    members: Mutex<Vec<ProcKey>>,
    exempt: Mutex<HashSet<ProcKey>>,
    uids: Vec<u32>,
}

struct DutyCycle {
    shared: Arc<DutyShared>,
}

impl DutyCycle {
    fn start(
        tenant: &TenantId,
        duty: f64,
        members: Vec<ProcKey>,
        exempt: HashSet<ProcKey>,
        uids: Vec<u32>,
        period: Duration,
    ) -> Self {
        let shared = Arc::new(DutyShared {
            duty_bits: AtomicU64::new(duty.to_bits()),
            stop: AtomicBool::new(false),
            members: Mutex::new(members),
            exempt: Mutex::new(exempt),
            uids,
        });
        let sh = shared.clone();
        let _ = std::thread::Builder::new()
            .name(format!("throttle-{}", tenant.as_str().chars().take(6).collect::<String>()))
            .spawn(move || {
                let mut n = 0u32;
                while !sh.stop.load(Ordering::SeqCst) {
                    n = n.wrapping_add(1);
                    let duty = f64::from_bits(sh.duty_bits.load(Ordering::SeqCst)).clamp(0.0, 1.0);
                    if duty >= 1.0 {
                        std::thread::sleep(period);
                        continue;
                    }
                    // Stop phase: one verified pidfd per member, held only
                    // until the matching SIGCONT.
                    let off_start = Instant::now();
                    let stop_all = |keys: &[ProcKey]| -> Vec<PidFd> {
                        keys.iter()
                            .filter_map(|(pid, st)| PidFd::open_verified(*pid, *st))
                            .filter(|fd| fd.signal(libc::SIGSTOP).is_ok())
                            .collect()
                    };
                    let members = sh.members.lock().unwrap().clone();
                    let mut held = stop_all(&members);
                    // Membership refresh (catch helpers forked since the last
                    // tick) runs while the tenant is stopped, so a slow /proc
                    // scan never becomes run time for it.
                    if !sh.uids.is_empty() && n.is_multiple_of(REFRESH_CYCLES) {
                        let exempt = sh.exempt.lock().unwrap().clone();
                        let fresh: Vec<ProcKey> = procfs::scan()
                            .iter()
                            .filter(|p| sh.uids.contains(&p.status.uid))
                            .map(|p| p.key())
                            .filter(|k| !exempt.contains(k) && !members.contains(k))
                            .collect();
                        held.extend(stop_all(&fresh));
                        sh.members.lock().unwrap().extend(fresh);
                    }
                    if let Some(rest) = period.mul_f64(1.0 - duty).checked_sub(off_start.elapsed()) {
                        std::thread::sleep(rest);
                    }
                    for fd in &held {
                        let _ = fd.signal(libc::SIGCONT);
                    }
                    drop(held);
                    if sh.stop.load(Ordering::SeqCst) {
                        break;
                    }
                    std::thread::sleep(period.mul_f64(duty));
                }
            });
        Self { shared }
    }

    fn set(&self, duty: f64, members: Vec<ProcKey>, exempt: HashSet<ProcKey>) {
        self.shared.duty_bits.store(duty.to_bits(), Ordering::SeqCst);
        *self.shared.members.lock().unwrap() = members;
        *self.shared.exempt.lock().unwrap() = exempt;
    }

    fn duty(&self) -> f64 {
        f64::from_bits(self.shared.duty_bits.load(Ordering::SeqCst))
    }
}

impl Drop for DutyCycle {
    /// Never blocks: the thread sees the flag, finishes its current cycle
    /// (so everything it stopped is continued) and exits.
    fn drop(&mut self) {
        self.shared.stop.store(true, Ordering::SeqCst);
    }
}

// ------------------------------------------------------------------ cell memory

/// Cell memory from a cgroup directory: `memory.current` minus reclaimable
/// file pages (`active_file` + `inactive_file` of `memory.stat`).
pub fn cgroup_unreclaimable(dir: &std::path::Path) -> Option<u64> {
    let current: u64 = std::fs::read_to_string(dir.join("memory.current")).ok()?.trim().parse().ok()?;
    let stat = dir.join("memory.stat");
    let file = crate::limits::read_kv(&stat, "active_file").unwrap_or(0)
        + crate::limits::read_kv(&stat, "inactive_file").unwrap_or(0);
    Some(current.saturating_sub(file))
}

// ------------------------------------------------------------------ monitor

pub struct Monitor {
    cfg: ResourceConfig,
    capacity: CellCapacity,
    delegated: bool,
    /// The container's cgroup (read for cell memory; delegation not needed).
    cell_cgroup: Option<PathBuf>,
    controller: Controller,
    cpu: CpuAccount,
    tck: u64,
    duty: HashMap<TenantId, DutyCycle>,
    cg_throttled: HashMap<TenantId, (u64, Instant)>,
    last: Option<Instant>,
}

impl Monitor {
    pub fn new(cfg: ResourceConfig, capacity: CellCapacity, delegated: bool) -> Self {
        Self {
            controller: Controller::new(cfg.clone(), delegated),
            cfg,
            capacity,
            delegated,
            cell_cgroup: None,
            cpu: CpuAccount::default(),
            tck: procfs::clk_tck(),
            duty: HashMap::new(),
            cg_throttled: HashMap::new(),
            last: None,
        }
    }

    /// Read cell memory from this cgroup directory (the cell container's).
    pub fn with_cell_cgroup(mut self, dir: Option<PathBuf>) -> Self {
        self.cell_cgroup = dir;
        self
    }

    pub fn capacity(&self) -> &CellCapacity {
        &self.capacity
    }

    pub fn interval(&self) -> Duration {
        Duration::from_millis(self.cfg.interval_ms)
    }

    /// Watchdog mode's cell-wide task ceiling (None = not enforced).
    pub fn set_pids_ceiling(&mut self, ceiling: Option<u64>) {
        self.controller.set_pids_ceiling(ceiling);
    }

    /// Tasks across tenant uids are above the ceiling: refuse new spawns.
    pub fn pids_saturated(&self) -> bool {
        self.controller.pids_saturated()
    }

    /// Switch to delegated enforcement (live adoption): duty cycles stop
    /// (their threads continue everything they stopped) and the next tick
    /// writes the desired state into the cgroups instead.
    pub fn set_delegated(&mut self, on: bool) {
        self.delegated = on;
        self.controller.set_delegated(on);
        if on {
            self.duty.clear();
        }
    }

    pub fn delegated(&self) -> bool {
        self.delegated
    }

    pub fn tenant_view(&self, t: &TenantId) -> Option<TenantResourceView> {
        self.controller.tenant_view(t, Instant::now())
    }

    pub fn cell_view(&self) -> CellResourceView {
        self.controller.cell_view(&self.capacity)
    }

    /// Stop duty-cycling `t` now (before a graceful shutdown: a stopped
    /// process cannot answer `Shutdown`). Non-blocking. The next tick
    /// re-applies the desired state to the tenant's non-exempt processes.
    pub fn release(&mut self, t: &TenantId) {
        self.duty.remove(t);
    }

    /// One watchdog pass.
    pub fn tick(&mut self, specs: &[TenantSpec], cg: Option<&CgroupTree>) -> TickOutput {
        let now = Instant::now();
        let dt = self.last.map(|l| now.duration_since(l)).unwrap_or_else(|| self.interval()).max(Duration::from_millis(1));
        self.last = Some(now);
        let procs = procfs::scan();
        let deltas = self.cpu.update(&procs);
        let groups: Vec<(Vec<ProcKey>, Vec<u32>)> = specs.iter().map(|s| (s.roots.clone(), s.uids.clone())).collect();
        let owner = procfs::assign_members(&procs, &groups);
        let to_mc = |ticks: u64| ticks as f64 * 1e6 / self.tck as f64 / dt.as_micros().max(1) as f64 * 1000.0;

        let mut cpu = vec![0u64; specs.len()];
        let mut mem = vec![0u64; specs.len()];
        let mut tasks = vec![0u64; specs.len()];
        let mut largest: Vec<Option<(ProcKey, u64)>> = vec![None; specs.len()];
        let mut members: Vec<Vec<ProcKey>> = vec![Vec::new(); specs.len()];
        let mut cell = CellSample::default();
        for p in &procs {
            let d = deltas.get(&p.key()).copied().unwrap_or(0);
            cell.cpu_millicores += to_mc(d);
            match owner.get(&p.pid) {
                Some(&i) => {
                    let m = p.memory(self.cfg.memory_metric);
                    cell.memory_bytes += m;
                    cpu[i] += d;
                    mem[i] += m;
                    tasks[i] += p.status.threads;
                    if largest[i].is_none_or(|(_, b)| m > b) {
                        largest[i] = Some((p.key(), m));
                    }
                    if !specs[i].exempt.contains(&p.key()) && !specs[i].unthrottled_uids.contains(&p.status.uid) {
                        members[i].push(p.key());
                    }
                }
                None => cell.memory_bytes += p.memory(procfs::MemoryMetric::Anon),
            }
        }
        // Kernel truth for the cell when its cgroup is readable: it also
        // sees memory no process maps (memfd, shm, kernel).
        if let Some(m) = self.cell_cgroup.as_deref().and_then(cgroup_unreclaimable) {
            cell.memory_bytes = m;
        }

        let mut samples = Vec::with_capacity(specs.len());
        for (i, s) in specs.iter().enumerate() {
            let throttled_fraction = if self.delegated {
                cg.and_then(|c| c.usage(&s.tenant))
                    .map(|u| match self.cg_throttled.insert(s.tenant.clone(), (u.cpu_throttled_usec, now)) {
                        Some((p, at)) => {
                            let wall = now.duration_since(at).as_micros().max(1) as f64;
                            (u.cpu_throttled_usec.saturating_sub(p) as f64 / wall).clamp(0.0, 1.0)
                        }
                        None => 0.0,
                    })
                    .unwrap_or(0.0)
            } else {
                self.duty.get(&s.tenant).map(|d| 1.0 - d.duty()).unwrap_or(0.0)
            };
            samples.push(TenantSample {
                tenant: s.tenant.clone(),
                limits: s.limits,
                cpu_millicores: to_mc(cpu[i]),
                throttled_fraction,
                memory_bytes: mem[i],
                largest_pid: largest[i].map(|((p, _), _)| p),
                tasks: tasks[i],
            });
        }
        self.cg_throttled.retain(|t, _| specs.iter().any(|s| &s.tenant == t));

        let decision = self.controller.evaluate(now, dt, &self.capacity, &cell, &samples);
        let mut out = TickOutput { samples, cell, kills: vec![], kill_tenants: vec![], events: decision.events };
        for a in decision.actions {
            // Throttle/memory actions are covered by the desired-state pass
            // below; only kills are one-shot.
            if let Action::KillTenant { tenant, reason, .. } = &a {
                out.kill_tenants.push((tenant.clone(), *reason));
                continue;
            }
            if let Action::Kill { tenant, pid, reason, observed_bytes, limit_bytes } = a {
                let idx = specs.iter().position(|s| s.tenant == tenant);
                match idx.and_then(|i| largest[i]).filter(|((p, _), _)| *p == pid) {
                    Some(((pid, starttime), _)) => {
                        out.kills.push(KillOrder { tenant, pid, starttime, reason, observed_bytes, limit_bytes })
                    }
                    None => tracing::warn!(%tenant, pid, "kill target no longer the tenant's largest process"),
                }
            }
        }

        // Desired state, every tick, idempotently.
        let mut throttled: HashSet<TenantId> = HashSet::new();
        for (i, s) in specs.iter().enumerate() {
            let (throttle, memory_high) = self.controller.desired(&s.tenant);
            if let Some(cg) = cg.filter(|_| self.delegated) {
                if cg.tenant_dir(&s.tenant).exists() {
                    let cpu = throttle.map(|t| t.target_millicores).unwrap_or(s.limits.cpu_ceiling_millicores);
                    if let Err(e) = cg.set_cpu_max(&s.tenant, cpu) {
                        tracing::debug!(tenant = %s.tenant, error = %e, "cpu.max write failed");
                    }
                    let high = memory_high.unwrap_or(s.limits.memory_hard_bytes);
                    if let Err(e) = cg.set_memory_high(&s.tenant, high) {
                        tracing::debug!(tenant = %s.tenant, error = %e, "memory.high write failed");
                    }
                }
            } else if let Some(th) = throttle {
                throttled.insert(s.tenant.clone());
                let exempt: HashSet<ProcKey> = s.exempt.iter().copied().collect();
                let ms = std::mem::take(&mut members[i]);
                match self.duty.get(&s.tenant) {
                    Some(dc) => dc.set(th.duty, ms, exempt),
                    None => {
                        let period = Duration::from_millis(self.cfg.throttle_period_ms);
                        let dc = DutyCycle::start(&s.tenant, th.duty, ms, exempt, s.uids.iter().copied().filter(|uid| !s.unthrottled_uids.contains(uid)).collect(), period);
                        self.duty.insert(s.tenant.clone(), dc);
                    }
                }
            }
        }
        self.duty.retain(|t, _| throttled.contains(t));
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cell_memory_from_cgroup_excludes_reclaimable_file_pages() {
        let d = tempfile::tempdir().unwrap();
        assert_eq!(cgroup_unreclaimable(d.path()), None);
        std::fs::write(d.path().join("memory.current"), "1000000\n").unwrap();
        std::fs::write(d.path().join("memory.stat"), "anon 500000\nfile 450000\nactive_file 100000\ninactive_file 300000\nshmem 50000\n").unwrap();
        assert_eq!(cgroup_unreclaimable(d.path()), Some(600_000));
    }
}
