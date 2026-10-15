// SPDX-License-Identifier: AGPL-3.0-or-later

//! `/proc` accounting for the resource watchdog (NAN-2872).
//!
//! One [`scan`] per watchdog tick reads `/proc/<pid>/stat` and
//! `/proc/<pid>/status` for every process in the cell's pid namespace (a
//! few dozen in a cell pod: about 100 µs of reads per process). From the
//! scan:
//!
//! - [`assign_members`] maps each process to a tenant: by **uid** (tenant
//!   uids are unique to the tenant, and a jailed process cannot change its
//!   uid), and by **ancestry** from the tenant's root processes. The uid rule
//!   also catches a grandchild that was re-parented away from the tenant's
//!   tree.
//! - [`CpuAccount`] turns cumulative `utime+stime` into per-tick deltas,
//!   keyed by (pid, start time) so a recycled pid never inherits another
//!   process's counters. A child reaped by a tenant process moves its CPU
//!   into the parent's `cutime+cstime`; the account credits back what it
//!   already counted for that child so nothing is counted twice.
//! - [`MemoryMetric`] selects the memory figure: `anon` (RssAnon+RssShmem,
//!   the default: unreclaimable memory, and not double counted across
//!   processes that map the same library), `rss` (VmRSS) or `pss`
//!   (`smaps_rollup`, the most precise; it walks page tables, so it costs
//!   more, and needs ptrace-read access to the target).

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Fields of `/proc/<pid>/stat` the watchdog uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Stat {
    pub ppid: u32,
    /// utime + stime of the process (all its threads), clock ticks.
    pub own_ticks: u64,
    /// cutime + cstime (waited-for children), clock ticks.
    pub child_ticks: u64,
    /// Start time after boot, clock ticks. With the pid, a process identity.
    pub starttime: u64,
    pub state: char,
}

/// Parse `/proc/<pid>/stat`. The comm field may contain spaces and
/// parentheses, so fields are counted from the last `)`.
pub fn parse_stat(s: &str) -> Option<Stat> {
    let rest = s.get(s.rfind(')')? + 2..)?;
    let f: Vec<&str> = rest.split_whitespace().collect();
    // f[0] is field 3 (state); field n is f[n - 3].
    let num = |n: usize| -> Option<u64> { f.get(n - 3)?.parse().ok() };
    Some(Stat {
        state: f.first()?.chars().next()?,
        ppid: num(4)? as u32,
        own_ticks: num(14)? + num(15)?,
        child_ticks: num(16)? + num(17)?,
        starttime: num(22)?,
    })
}

/// Fields of `/proc/<pid>/status` the watchdog uses (bytes).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Status {
    pub uid: u32,
    pub vm_rss: u64,
    pub rss_anon: u64,
    pub rss_shmem: u64,
    /// Tasks (threads) of the process: what pids.max / RLIMIT_NPROC count.
    pub threads: u64,
}

pub fn parse_status(s: &str) -> Option<Status> {
    let kib = |key: &str| -> u64 {
        s.lines()
            .find_map(|l| l.strip_prefix(key))
            .and_then(|v| v.split_whitespace().next()?.parse::<u64>().ok())
            .map(|k| k * 1024)
            .unwrap_or(0)
    };
    let uid = s.lines().find_map(|l| l.strip_prefix("Uid:"))?.split_whitespace().next()?.parse().ok()?;
    let threads = s.lines().find_map(|l| l.strip_prefix("Threads:")).and_then(|v| v.trim().parse().ok()).unwrap_or(1);
    Some(Status { uid, vm_rss: kib("VmRSS:"), rss_anon: kib("RssAnon:"), rss_shmem: kib("RssShmem:"), threads })
}

/// `Pss:` of `/proc/<pid>/smaps_rollup`, bytes.
pub fn parse_pss(s: &str) -> Option<u64> {
    s.lines().find_map(|l| l.strip_prefix("Pss:")).and_then(|v| v.split_whitespace().next()?.parse::<u64>().ok()).map(|k| k * 1024)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MemoryMetric {
    /// RssAnon + RssShmem (default).
    #[default]
    Anon,
    /// VmRSS.
    Rss,
    /// Pss from smaps_rollup; falls back to `anon` where unreadable.
    Pss,
}

/// One process from a scan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcInfo {
    pub pid: u32,
    pub stat: Stat,
    pub status: Status,
}

impl ProcInfo {
    pub fn key(&self) -> (u32, u64) {
        (self.pid, self.stat.starttime)
    }

    /// Memory by `metric` (PSS is read on demand, for tenant members only).
    pub fn memory(&self, metric: MemoryMetric) -> u64 {
        match metric {
            MemoryMetric::Anon => self.status.rss_anon + self.status.rss_shmem,
            MemoryMetric::Rss => self.status.vm_rss,
            MemoryMetric::Pss => std::fs::read_to_string(format!("/proc/{}/smaps_rollup", self.pid))
                .ok()
                .and_then(|s| parse_pss(&s))
                .unwrap_or(self.status.rss_anon + self.status.rss_shmem),
        }
    }
}

/// Read every process under `/proc`. Processes that exit mid-scan are
/// skipped; zombies (no memory, final CPU already counted) too.
pub fn scan() -> Vec<ProcInfo> {
    scan_at(std::path::Path::new("/proc"))
}

pub fn scan_at(proc_root: &std::path::Path) -> Vec<ProcInfo> {
    let Ok(rd) = std::fs::read_dir(proc_root) else { return vec![] };
    let mut out = Vec::new();
    for e in rd.flatten() {
        let Some(pid) = e.file_name().to_str().and_then(|n| n.parse::<u32>().ok()) else { continue };
        let dir = e.path();
        let Some(stat) = std::fs::read_to_string(dir.join("stat")).ok().and_then(|s| parse_stat(&s)) else { continue };
        if stat.state == 'Z' || stat.state == 'X' {
            continue;
        }
        let Some(status) = std::fs::read_to_string(dir.join("status")).ok().and_then(|s| parse_status(&s)) else {
            continue;
        };
        out.push(ProcInfo { pid, stat, status });
    }
    out
}

/// A process identity: (pid, start time). A recycled pid never matches.
pub type ProcKey = (u32, u64);

/// Which tenant (index into the caller's list) owns each process.
///
/// `tenants[i] = (root processes, uids)`. A process belongs to tenant `i`
/// if its real uid is one of `uids` (every process a tenant ever starts,
/// including double-forked orphans, runs as one of its uids), or it is (a
/// descendant of) one of `roots`, matched by (pid, start time).
pub fn assign_members(procs: &[ProcInfo], tenants: &[(Vec<ProcKey>, Vec<u32>)]) -> HashMap<u32, usize> {
    let mut by_uid: HashMap<u32, usize> = HashMap::new();
    let mut by_root: HashMap<ProcKey, usize> = HashMap::new();
    for (i, (roots, uids)) in tenants.iter().enumerate() {
        for u in uids {
            by_uid.insert(*u, i);
        }
        for r in roots {
            by_root.insert(*r, i);
        }
    }
    let info: HashMap<u32, (u32, u64)> = procs.iter().map(|p| (p.pid, (p.stat.ppid, p.stat.starttime))).collect();
    let mut out = HashMap::new();
    for p in procs {
        if let Some(i) = by_uid.get(&p.status.uid) {
            out.insert(p.pid, *i);
            continue;
        }
        // Walk up at most 64 levels (a cycle is impossible in a consistent
        // snapshot, but a torn one must not loop).
        let mut cur = p.pid;
        for _ in 0..64 {
            let Some((ppid, start)) = info.get(&cur) else { break };
            if let Some(i) = by_root.get(&(cur, *start)) {
                out.insert(p.pid, *i);
                break;
            }
            if *ppid == 0 || *ppid == cur {
                break;
            }
            cur = *ppid;
        }
    }
    out
}

/// Every process running as one of `uids`, except `keep` and its
/// descendants (a replacement process that already took over the uid).
/// [`processes_of`] sparing every process in `keep` and their descendants.
pub fn processes_of_keeping(procs: &[ProcInfo], uids: &[u32], keep: &[ProcKey]) -> Vec<ProcKey> {
    let kept = if keep.is_empty() { Default::default() } else { assign_members(procs, &[(keep.to_vec(), vec![])]) };
    procs
        .iter()
        .filter(|p| uids.contains(&p.status.uid) && !kept.contains_key(&p.pid))
        .map(|p| p.key())
        .collect()
}

pub fn processes_of(procs: &[ProcInfo], uids: &[u32], keep: Option<ProcKey>) -> Vec<ProcKey> {
    let kept = keep.map(|k| assign_members(procs, &[(vec![k], vec![])])).unwrap_or_default();
    procs
        .iter()
        .filter(|p| uids.contains(&p.status.uid) && !kept.contains_key(&p.pid))
        .map(|p| p.key())
        .collect()
}

/// Clock ticks per second.
pub fn clk_tck() -> u64 {
    // SAFETY: sysconf is always safe.
    (unsafe { libc::sysconf(libc::_SC_CLK_TCK) }).max(1) as u64
}

/// Per-process CPU deltas between scans.
#[derive(Debug, Default)]
pub struct CpuAccount {
    prev: HashMap<(u32, u64), (u64, u64, u32)>,
    /// CPU already counted for exited children, per parent pid; subtracted
    /// from the parent's next cutime+cstime growth.
    credit: HashMap<u32, u64>,
    primed: bool,
}

impl CpuAccount {
    /// Ticks consumed per process since the previous call. The first call
    /// only primes the account (every delta 0).
    pub fn update(&mut self, procs: &[ProcInfo]) -> HashMap<(u32, u64), u64> {
        // Exited processes first: what we counted for them shows up again
        // in their parent's cutime once reaped (possibly in this very scan).
        let seen: std::collections::HashSet<(u32, u64)> = procs.iter().map(|p| p.key()).collect();
        for (key, (own, child, ppid)) in &self.prev {
            if !seen.contains(key) {
                *self.credit.entry(*ppid).or_default() += own + child;
            }
        }
        let mut out = HashMap::with_capacity(procs.len());
        let mut next = HashMap::with_capacity(procs.len());
        for p in procs {
            let key = p.key();
            let (own, child) = (p.stat.own_ticks, p.stat.child_ticks);
            let delta = match self.prev.get(&key) {
                Some((pown, pchild, _)) => {
                    let mut child_delta = child.saturating_sub(*pchild);
                    if let Some(c) = self.credit.get_mut(&p.pid) {
                        let take = (*c).min(child_delta);
                        child_delta -= take;
                        *c -= take;
                    }
                    own.saturating_sub(*pown) + child_delta
                }
                // New since the last scan: everything it used is new.
                None if self.primed => own,
                None => 0,
            };
            out.insert(key, delta);
            next.insert(key, (own, child, p.stat.ppid));
        }
        // Credit for a parent that is gone, or that never reaps, is dropped.
        let live: std::collections::HashSet<u32> = next.keys().map(|(pid, _)| *pid).collect();
        self.credit.retain(|pid, c| *c > 0 && live.contains(pid));
        self.prev = next;
        self.primed = true;
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[allow(clippy::too_many_arguments)]
    fn stat_line(pid: u32, comm: &str, ppid: u32, ut: u64, st: u64, cut: u64, cst: u64, start: u64) -> String {
        format!(
            "{pid} ({comm}) S {ppid} {pid} {pid} 0 -1 4194560 100 0 0 0 {ut} {st} {cut} {cst} 20 0 4 0 {start} 1000 200 18446744073709551615"
        )
    }

    fn proc_(pid: u32, ppid: u32, uid: u32, own: u64, child: u64, start: u64) -> ProcInfo {
        ProcInfo {
            pid,
            stat: Stat { ppid, own_ticks: own, child_ticks: child, starttime: start, state: 'S' },
            status: Status { uid, vm_rss: 300 << 20, rss_anon: 100 << 20, rss_shmem: 1 << 20, threads: 1 },
        }
    }

    #[test]
    fn parses_stat_with_hostile_comm() {
        let s = stat_line(42, "evil) S 1 (x", 7, 10, 5, 3, 2, 12345);
        let st = parse_stat(&s).unwrap();
        assert_eq!(st, Stat { ppid: 7, own_ticks: 15, child_ticks: 5, starttime: 12345, state: 'S' });
        assert!(parse_stat("garbage").is_none());
        let real = parse_stat(&std::fs::read_to_string("/proc/self/stat").unwrap()).unwrap();
        assert_eq!(real.ppid, std::os::unix::process::parent_id());
    }

    #[test]
    fn parses_status_and_pss() {
        let s = "Name:\tx\nUid:\t20001\t20001\t20001\t20001\nVmRSS:\t  2048 kB\nRssAnon:\t  1024 kB\nRssFile:\t 1000 kB\nRssShmem:\t 24 kB\n";
        let st = parse_status(s).unwrap();
        assert_eq!(st, Status { uid: 20001, vm_rss: 2048 * 1024, rss_anon: 1024 * 1024, rss_shmem: 24 * 1024, threads: 1 });
        assert_eq!(parse_status("Uid:\t1 1 1 1\nThreads:\t17\n").unwrap().threads, 17);
        assert_eq!(parse_pss("Rss: 10 kB\nPss:   7 kB\n"), Some(7 * 1024));
        let me = scan().into_iter().find(|p| p.pid == std::process::id()).expect("self in scan");
        assert!(me.memory(MemoryMetric::Anon) > 0 && me.memory(MemoryMetric::Rss) >= me.memory(MemoryMetric::Anon));
        assert!(me.memory(MemoryMetric::Pss) > 0);
    }

    #[test]
    fn membership_by_uid_and_ancestry() {
        let procs = vec![
            proc_(1, 0, 0, 0, 0, 1),        // supervisor
            proc_(10, 1, 20000, 0, 0, 2),   // tenant a ingest (root)
            proc_(11, 10, 20000, 0, 0, 3),  // its child
            proc_(12, 1, 20001, 0, 0, 4),   // a/query re-parented to 1, matched by uid
            proc_(20, 1, 0, 0, 0, 5),       // b root running as root uid (test harness shape)
            proc_(21, 20, 0, 0, 0, 6),      // b child by ancestry
            proc_(30, 1, 0, 0, 0, 7),       // warm / unrelated
        ];
        let m = assign_members(&procs, &[(vec![(10, 2)], vec![20000, 20001]), (vec![(20, 5)], vec![])]);
        assert_eq!(m.get(&10), Some(&0));
        assert_eq!(m.get(&11), Some(&0));
        assert_eq!(m.get(&12), Some(&0));
        assert_eq!(m.get(&20), Some(&1));
        assert_eq!(m.get(&21), Some(&1));
        assert_eq!(m.get(&1), None);
        assert_eq!(m.get(&30), None);
        // A recycled root pid (other start time) adopts nothing.
        let m = assign_members(&procs, &[(vec![(20, 999)], vec![])]);
        assert!(m.is_empty());
        // processes_of: by uid, sparing a kept replacement and its children.
        let procs2 = vec![
            proc_(40, 1, 20000, 0, 0, 1),  // old orphan
            proc_(41, 1, 20000, 0, 0, 2),  // new root (kept)
            proc_(42, 41, 20000, 0, 0, 3), // its child
            proc_(43, 1, 20002, 0, 0, 4),  // other tenant
        ];
        assert_eq!(processes_of(&procs2, &[20000], Some((41, 2))), vec![(40, 1)]);
        assert_eq!(processes_of(&procs2, &[20000], None).len(), 3);
    }

    #[test]
    fn cpu_deltas_are_keyed_by_identity_and_never_double_count_reaped_children() {
        let mut acc = CpuAccount::default();
        // Prime: nothing counted.
        let d = acc.update(&[proc_(10, 1, 0, 100, 0, 5)]);
        assert_eq!(d[&(10, 5)], 0);
        // Parent +20, child born with 30 ticks.
        let d = acc.update(&[proc_(10, 1, 0, 120, 0, 5), proc_(11, 10, 0, 30, 0, 9)]);
        assert_eq!(d[&(10, 5)], 20);
        assert_eq!(d[&(11, 9)], 30);
        // Child runs 10 more then exits and is reaped: parent's cutime += 40.
        let d = acc.update(&[proc_(10, 1, 0, 120, 0, 5), proc_(11, 10, 0, 40, 0, 9)]);
        assert_eq!(d[&(11, 9)], 10);
        let d = acc.update(&[proc_(10, 1, 0, 125, 40, 5)]);
        // Only the parent's own +5: the child's 40 were already counted.
        assert_eq!(d[&(10, 5)], 5);
        // Recycled pid 11 (new start time) starts from its own counters.
        let d = acc.update(&[proc_(10, 1, 0, 125, 40, 5), proc_(11, 1, 0, 7, 0, 99)]);
        assert_eq!(d[&(11, 99)], 7);
        // A child that ran unseen between two scans is still counted via cutime.
        let d = acc.update(&[proc_(10, 1, 0, 125, 52, 5), proc_(11, 1, 0, 7, 0, 99)]);
        assert_eq!(d[&(10, 5)], 12);
    }

    /// cell26 (2026-09-30): maintenance[T] runs under ingest's uid, and its
    /// exit's leftover sweep killed everything under that uid, ingest
    /// included. Siblings (other live roles on the uid) and their
    /// descendants are now spared; only the exited role's orphans die.
    #[test]
    fn a_role_exit_spares_live_siblings_on_the_same_uid() {
        let uid = 1000;
        let procs = vec![
            proc_(10, 1, uid, 0, 0, 100),  // ingest[T]
            proc_(11, 10, uid, 0, 0, 101), // ingest's child
            proc_(21, 1, uid, 0, 0, 201),  // maintenance's orphan (reparented)
            proc_(30, 1, 2000, 0, 0, 300), // another uid
        ];
        let left = processes_of_keeping(&procs, &[uid], &[(10, 100)]);
        assert_eq!(left, vec![(21, 201)]);
        // Nothing to keep: every process on the uid.
        assert_eq!(processes_of_keeping(&procs, &[uid], &[]).len(), 3);
    }
}
