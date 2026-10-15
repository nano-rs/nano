// SPDX-License-Identifier: AGPL-3.0-or-later

//! OOM-killer ordering for the cell (NAN-3523): the supervisor last, tenant
//! and warm-pool processes first.
//!
//! A pod-level OOM (a burst racing the watchdog, or the kernel's memcg OOM at
//! the container limit) picks the task with the highest `oom_score`. If that
//! is the supervisor, every tenant on the cell dies with it (children carry
//! `PR_SET_PDEATHSIG`). So:
//!
//! - at startup the supervisor asks for [`SUPERVISOR_TARGET`] (-1000, never
//!   chosen). Lowering `oom_score_adj` below its current value needs
//!   `CAP_SYS_RESOURCE`, which the cell does not hold (5A caps: SETUID SETGID
//!   CHOWN FOWNER KILL SYS_NICE SETPCAP (+SYS_ADMIN)), so this usually fails
//!   and the kubelet's QoS value stays. That is reported, not fatal.
//! - every tenant and warm process raises its own value before `exec`
//!   ([`PreExecAdj`]). Raising is always allowed, so this works under any
//!   caps. The target is `max(configured, supervisor + MIN_GAP)`, capped at
//!   1000: tenants always rank above the supervisor, whatever the kubelet
//!   gave the pod.

use serde::Serialize;
use std::sync::OnceLock;

/// What the supervisor asks for itself.
pub const SUPERVISOR_TARGET: i32 = -1000;
/// Tenants rank at least this far above the supervisor. An adj point is
/// worth `limit / 1000` bytes of badness, so 500 outweighs any tenant RSS
/// difference up to half the cell's memory.
pub const MIN_GAP: i32 = 500;
pub const MAX_ADJ: i32 = 1000;

/// `/healthz` and `/v1/status` `supervisor_reserve.oom`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OomReport {
    /// The supervisor's `oom_score_adj` now.
    pub supervisor_adj: i32,
    /// The supervisor reached [`SUPERVISOR_TARGET`].
    pub supervisor_protected: bool,
    /// What every tenant and warm process sets before exec.
    pub tenant_adj: i32,
    /// Why the supervisor could not lower its own value (no CAP_SYS_RESOURCE).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// `/healthz` and `/v1/status` `supervisor_reserve`: how the supervisor is
/// protected from its tenants.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SupervisorReserve {
    pub oom: OomReport,
    /// `init/memory.min` as the kernel reports it (null: not delegated).
    pub init_memory_min_bytes: Option<u64>,
    /// `init/cpu.weight` (null: not delegated).
    pub init_cpu_weight: Option<u32>,
}

impl SupervisorReserve {
    /// Read from the adopted cgroup root (`None`: watchdog mode).
    pub fn read(configured_tenant_adj: i32, cgroup_root: Option<&std::path::Path>) -> Self {
        fn file<T: std::str::FromStr>(root: Option<&std::path::Path>, name: &str) -> Option<T> {
            root.and_then(|r| std::fs::read_to_string(r.join("init").join(name)).ok()).and_then(|v| v.trim().parse().ok())
        }
        Self {
            oom: report(configured_tenant_adj),
            init_memory_min_bytes: file(cgroup_root, "memory.min"),
            init_cpu_weight: file(cgroup_root, "cpu.weight"),
        }
    }
}

static REPORT: OnceLock<OomReport> = OnceLock::new();

fn adj_path(pid: Option<u32>) -> String {
    match pid {
        Some(pid) => format!("/proc/{pid}/oom_score_adj"),
        None => "/proc/self/oom_score_adj".into(),
    }
}

/// A process's `oom_score_adj` (`None`: this process).
pub fn read_adj(pid: Option<u32>) -> std::io::Result<i32> {
    std::fs::read_to_string(adj_path(pid))?.trim().parse().map_err(std::io::Error::other)
}

/// The value tenants and the warm pool raise themselves to.
pub fn tenant_adj(configured: i32, supervisor: i32) -> i32 {
    configured.max(supervisor.saturating_add(MIN_GAP)).min(MAX_ADJ)
}

/// Startup: try to protect the supervisor, then fix the tenant value from
/// what the supervisor really has. Call once, before any child is spawned.
pub fn protect_supervisor(configured_tenant_adj: i32) -> &'static OomReport {
    REPORT.get_or_init(|| {
        let error = std::fs::write(adj_path(None), SUPERVISOR_TARGET.to_string()).err().map(|e| e.to_string());
        let supervisor_adj = read_adj(None).unwrap_or(0);
        let report = OomReport {
            supervisor_adj,
            supervisor_protected: supervisor_adj == SUPERVISOR_TARGET,
            tenant_adj: tenant_adj(configured_tenant_adj, supervisor_adj),
            error: error.filter(|_| supervisor_adj != SUPERVISOR_TARGET),
        };
        if report.supervisor_protected {
            tracing::info!(supervisor_adj, tenant_adj = report.tenant_adj, "supervisor OOM-protected; tenants rank first");
        } else {
            tracing::warn!(supervisor_adj, tenant_adj = report.tenant_adj, error = report.error.as_deref().unwrap_or(""),
                "supervisor oom_score_adj not lowered (no CAP_SYS_RESOURCE); tenants and warm pool raised above it instead");
        }
        report
    })
}

/// The report from [`protect_supervisor`], or (tests, tools that never
/// called it) the same ordering computed from this process's current value.
pub fn report(configured_tenant_adj: i32) -> OomReport {
    REPORT.get().cloned().unwrap_or_else(|| {
        let supervisor_adj = read_adj(None).unwrap_or(0);
        OomReport {
            supervisor_adj,
            supervisor_protected: supervisor_adj == SUPERVISOR_TARGET,
            tenant_adj: tenant_adj(configured_tenant_adj, supervisor_adj),
            error: None,
        }
    })
}

/// A pre-formatted `oom_score_adj` write for `pre_exec` (between fork and
/// exec: no allocation, only open/write/close).
#[derive(Debug, Clone, Copy)]
pub struct PreExecAdj {
    buf: [u8; 8],
    len: usize,
}

const SELF_ADJ: &[u8] = b"/proc/self/oom_score_adj\0";

impl PreExecAdj {
    pub fn new(adj: i32) -> Self {
        let text = adj.clamp(-MAX_ADJ, MAX_ADJ).to_string();
        let mut buf = [0; 8];
        buf[..text.len()].copy_from_slice(text.as_bytes());
        Self { buf, len: text.len() }
    }

    /// Write it for the calling process. Async-signal-safe. Best effort:
    /// returns false when the write failed (the spawn goes on; the
    /// supervisor checks the child's value afterwards).
    pub fn apply(&self) -> bool {
        // SAFETY: open/write/close on a static NUL-terminated path and an
        // owned buffer; no allocation.
        unsafe {
            let fd = libc::open(SELF_ADJ.as_ptr().cast(), libc::O_WRONLY | libc::O_CLOEXEC);
            if fd < 0 {
                return false;
            }
            let n = libc::write(fd, self.buf.as_ptr().cast(), self.len);
            libc::close(fd);
            n == self.len as isize
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tenants_always_rank_above_the_supervisor() {
        // Protected supervisor: the configured value.
        assert_eq!(tenant_adj(500, -1000), 500);
        // Kubelet Burstable value kept (no CAP_SYS_RESOURCE): raised past it.
        assert_eq!(tenant_adj(500, 300), 800);
        assert_eq!(tenant_adj(500, 900), 1000);
        assert_eq!(tenant_adj(500, 1000), 1000);
        assert!(tenant_adj(0, -998) >= -998 + MIN_GAP);
    }

    #[test]
    fn pre_exec_write_raises_a_child_and_never_lowers() {
        let own = read_adj(None).unwrap();
        let target = tenant_adj(500, own);
        let adj = PreExecAdj::new(target);
        assert_eq!(&adj.buf[..adj.len], target.to_string().as_bytes());
        // Fork a child that applies it, then report back via its exit code.
        // SAFETY: the child only calls async-signal-safe functions, then _exit.
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0);
        if pid == 0 {
            let ok = adj.apply();
            let mut b = [0u8; 16];
            // SAFETY: as above.
            let read = unsafe {
                let fd = libc::open(SELF_ADJ.as_ptr().cast(), libc::O_RDONLY);
                let n = libc::read(fd, b.as_mut_ptr().cast(), b.len());
                libc::close(fd);
                n
            };
            let same = read > 0 && b[..read as usize].trim_ascii() == &adj.buf[..adj.len];
            unsafe { libc::_exit(if ok && same { 0 } else { 1 }) };
        }
        let mut status = 0;
        // SAFETY: waiting for our own child.
        assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
        assert!(libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0, "child could not raise its oom_score_adj");
        assert_eq!(read_adj(None).unwrap(), own, "the parent is untouched");
    }

    #[test]
    fn reserve_reads_the_kernel_values() {
        let d = tempfile::tempdir().unwrap();
        std::fs::create_dir(d.path().join("init")).unwrap();
        std::fs::write(d.path().join("init/memory.min"), "268435456\n").unwrap();
        std::fs::write(d.path().join("init/cpu.weight"), "200\n").unwrap();
        let r = SupervisorReserve::read(500, Some(d.path()));
        assert_eq!((r.init_memory_min_bytes, r.init_cpu_weight), (Some(256 << 20), Some(200)));
        let w = SupervisorReserve::read(500, None);
        assert_eq!((w.init_memory_min_bytes, w.init_cpu_weight), (None, None));
        let v = serde_json::to_value(&r).unwrap();
        assert!(v["oom"]["tenant_adj"].is_i64() && v["oom"]["supervisor_protected"].is_boolean());
    }

    #[test]
    fn report_without_startup_is_consistent() {
        let r = report(500);
        assert!(r.tenant_adj >= r.supervisor_adj.saturating_add(MIN_GAP).min(MAX_ADJ));
        assert_eq!(PreExecAdj::new(-5000).len, "-1000".len());
    }
}
