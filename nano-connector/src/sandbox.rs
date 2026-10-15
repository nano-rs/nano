//! Process isolation for the VRL worker.
//!
//! Layers, from always-on to environment-dependent:
//!
//! 1. **Spawn** (`pre_exec`, always): cleared environment, new session,
//!    `no_new_privs`, rlimits (address space, CPU seconds, no file writes, no
//!    core dumps, 8 fds, `RLIMIT_NPROC` 0 so it cannot fork even without
//!    seccomp, a 64 MiB stack so deep VRL nesting fails cleanly).
//! 2. **In the worker, before it reads any tenant input** (always): turns
//!    every fatal signal into a plain `_exit(128 + signal)` (so a crashing,
//!    CPU-limited or seccomp-stopped worker never reaches the core-dump
//!    path, not even a `|systemd-coredump` pipe that ignores
//!    `RLIMIT_CORE`), sets `RLIMIT_CORE 0` again, closes every inherited fd
//!    above 2, sets `PR_SET_DUMPABLE 0`, then installs a seccomp allowlist:
//!    memory, futex, time, randomness and read/write on already-open fds.
//!    File opens fail with EPERM; sockets, exec, fork / clone, ptrace and
//!    cross-process memory access end the process (SIGSYS, exit 159). So the
//!    worker has no filesystem and no network; only the engine's broker
//!    talks to the outside.
//! 3. **cgroup v2** (only where a delegated cgroup is available): one leaf per
//!    worker with `memory.max`, `memory.swap.max 0`, `pids.max 1` and
//!    optionally `cpu.max`.
//!
//! Layers 2 and 3 depend on the host. Each has an [`Enforce`] mode: `Require`
//! fails the run when the layer is missing; `Prefer` runs without it but logs
//! a warning and reports it in [`SandboxReport`]; it is never silent.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use serde::Serialize;

/// What to do when an isolation layer is unavailable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Enforce {
    Off,
    /// Use it when available; otherwise warn and report "degraded".
    Prefer,
    /// Refuse to run a program without it.
    Require,
}

impl Enforce {
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "off" | "0" | "false" => Some(Self::Off),
            "prefer" | "auto" => Some(Self::Prefer),
            "require" | "strict" | "1" | "true" => Some(Self::Require),
            _ => None,
        }
    }
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::Prefer => "prefer",
            Self::Require => "require",
        }
    }
}

/// Isolation settings for VRL workers.
#[derive(Debug, Clone)]
pub struct SandboxPolicy {
    pub seccomp: Enforce,
    pub cgroup: Enforce,
    /// A cgroup v2 directory delegated to this process (writable, with no
    /// processes of its own). Workers get one leaf each beneath it.
    pub cgroup_parent: Option<PathBuf>,
    /// `cpu.max` for each worker leaf, as (quota_us, period_us).
    pub cpu_max: Option<(u64, u64)>,
    /// `memory.max` for each worker leaf (default: the worker's address
    /// space limit).
    pub memory_max: Option<u64>,
}

impl Default for SandboxPolicy {
    fn default() -> Self {
        Self { seccomp: Enforce::Prefer, cgroup: Enforce::Prefer, cgroup_parent: None, cpu_max: Some((100_000, 100_000)), memory_max: None }
    }
}

impl SandboxPolicy {
    /// From the environment:
    /// - `NANO_CONNECTOR_SECCOMP` = off | prefer | require (default prefer)
    /// - `NANO_CONNECTOR_CGROUP` = off | prefer | require (default prefer)
    /// - `NANO_CONNECTOR_CGROUP_PARENT` = delegated cgroup v2 directory
    /// - `NANO_CONNECTOR_SANDBOX=strict` = require both
    ///
    /// Any other value is an error, never a silent fallback: a typo such as
    /// `NANO_CONNECTOR_SECCOMP=required` must not quietly mean `prefer`.
    pub fn from_env() -> Result<Self, String> {
        Self::from_lookup(|k| std::env::var(k).ok())
    }

    /// [`SandboxPolicy::from_env`] over any lookup (tests).
    pub fn from_lookup(get: impl Fn(&str) -> Option<String>) -> Result<Self, String> {
        let mut p = Self::default();
        let set = |k: &str| get(k).filter(|v| !v.trim().is_empty());
        if let Some(v) = set("NANO_CONNECTOR_SANDBOX") {
            match v.trim().to_ascii_lowercase().as_str() {
                "strict" => {
                    p.seccomp = Enforce::Require;
                    p.cgroup = Enforce::Require;
                }
                "default" | "prefer" => {}
                _ => return Err(format!("NANO_CONNECTOR_SANDBOX=`{v}` is not one of: strict, prefer")),
            }
        }
        for (k, slot) in [("NANO_CONNECTOR_SECCOMP", &mut p.seccomp), ("NANO_CONNECTOR_CGROUP", &mut p.cgroup)] {
            if let Some(v) = set(k) {
                *slot = Enforce::parse(&v).ok_or_else(|| format!("{k}=`{v}` is not one of: off, prefer, require"))?;
            }
        }
        p.cgroup_parent = set("NANO_CONNECTOR_CGROUP_PARENT").map(PathBuf::from);
        Ok(p)
    }

    /// The fail-closed policy used when the configured one cannot be read.
    pub fn strict() -> Self {
        Self { seccomp: Enforce::Require, cgroup: Enforce::Require, ..Self::default() }
    }
}

/// What a worker actually got. Logged and returned with every run.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct SandboxReport {
    /// "enforced", "off" or "unavailable: <reason>".
    pub seccomp: String,
    /// "enforced (memory pids cpu)", "off" or "unavailable: <reason>".
    pub cgroup: String,
    /// rlimits, no_new_privs, cleared env, closed fds: always applied.
    pub rlimits: bool,
}

impl SandboxReport {
    pub fn degraded(&self) -> bool {
        !self.seccomp.starts_with("enforced") || !self.cgroup.starts_with("enforced")
    }
}

// ---------------------------------------------------------------------------
// Spawn side
// ---------------------------------------------------------------------------

/// Limits applied with `setrlimit` between fork and exec.
#[derive(Debug, Clone, Copy)]
pub struct Rlimits {
    pub address_space_bytes: u64,
    pub cpu_secs: u64,
    pub stack_bytes: u64,
}

/// Configure `cmd` for a sandboxed child: cleared env, null stderr, rlimits,
/// `no_new_privs`, new session.
pub fn harden_command(cmd: &mut tokio::process::Command, lim: Rlimits) {
    cmd.env_clear().current_dir("/").kill_on_drop(true);
    let Rlimits { address_space_bytes, cpu_secs, stack_bytes } = lim;
    let cpu = cpu_secs.max(1);
    // SAFETY: only async-signal-safe libc calls between fork and exec; no
    // allocation (the closure captures plain integers).
    unsafe {
        cmd.pre_exec(move || {
            let set = |res, soft: u64, hard: u64| {
                let lim = libc::rlimit { rlim_cur: soft as libc::rlim_t, rlim_max: hard as libc::rlim_t };
                if libc::setrlimit(res, &lim) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            };
            set(libc::RLIMIT_AS, address_space_bytes, address_space_bytes)?;
            // Soft limit sends SIGXCPU, the hard limit one second later SIGKILL.
            set(libc::RLIMIT_CPU, cpu, cpu + 1)?;
            set(libc::RLIMIT_FSIZE, 0, 0)?;
            set(libc::RLIMIT_CORE, 0, 0)?;
            set(libc::RLIMIT_NOFILE, 8, 8)?;
            set(libc::RLIMIT_MEMLOCK, 0, 0)?;
            set(libc::RLIMIT_MSGQUEUE, 0, 0)?;
            set(libc::RLIMIT_STACK, stack_bytes, stack_bytes)?;
            // Fork fallback when seccomp is unavailable. Not enforced for
            // root or CAP_SYS_RESOURCE; the jobs pods run unprivileged.
            set(libc::RLIMIT_NPROC, 0, 0)?;
            if libc::setsid() < 0 {
                return Err(std::io::Error::last_os_error());
            }
            if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            // Without a cgroup, the kernel OOM killer should pick a worker,
            // never the runner. Best effort (raising it needs no privilege).
            let fd = libc::open(c"/proc/self/oom_score_adj".as_ptr(), libc::O_WRONLY | libc::O_CLOEXEC);
            if fd >= 0 {
                libc::write(fd, b"1000".as_ptr().cast(), 4);
                libc::close(fd);
            }
            Ok(())
        });
    }
}

// ---------------------------------------------------------------------------
// Worker side
// ---------------------------------------------------------------------------

/// Close every fd above stderr. Runs first thing in the worker, so nothing
/// the parent leaked (a DB socket, a credential file) survives the exec.
/// `close_range` (5.9+), else every fd listed in `/proc/self/fd`, else a
/// close loop up to the fd hard limit. Returns how it was done.
pub fn close_inherited_fds() -> Result<&'static str, String> {
    // SAFETY: close_range / close on our own fd table.
    unsafe {
        if libc::syscall(libc::SYS_close_range, 3u32, u32::MAX, 0u32) == 0 {
            return Ok("close_range");
        }
    }
    if let Ok(dir) = std::fs::read_dir("/proc/self/fd") {
        // Collect first: closing while iterating would close the dir's own fd.
        let fds: Vec<i32> = dir.filter_map(|e| e.ok()?.file_name().to_str()?.parse().ok()).filter(|fd| *fd > 2).collect();
        for fd in fds {
            // SAFETY: as above; EBADF for the (already closed) dir fd is fine.
            unsafe { libc::close(fd) };
        }
        return Ok("proc");
    }
    let mut lim = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
    // SAFETY: getrlimit into a local.
    if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut lim) } != 0 {
        return Err("cannot close inherited fds: no close_range, no /proc and no RLIMIT_NOFILE".into());
    }
    let max = lim.rlim_max.min(1 << 20) as i32;
    for fd in 3..max.max(4096) {
        // SAFETY: as above.
        unsafe { libc::close(fd) };
    }
    Ok("loop")
}

/// Exit code of a worker that stopped on fatal signal `sig`.
pub const fn fatal_exit_code(sig: i32) -> i32 {
    128 + sig
}

/// Signals that would otherwise end the worker with a core dump.
const CORE_SIGNALS: &[i32] =
    &[libc::SIGABRT, libc::SIGSEGV, libc::SIGBUS, libc::SIGILL, libc::SIGFPE, libc::SIGSYS, libc::SIGXCPU, libc::SIGXFSZ, libc::SIGTRAP, libc::SIGQUIT];

extern "C" fn exit_on_fatal_signal(sig: libc::c_int) {
    // SAFETY: _exit is async-signal-safe and never returns.
    unsafe { libc::_exit(fatal_exit_code(sig)) }
}

/// Process-wide hardening for the worker, before seccomp and before any
/// tenant input: no core dumps by any route, no ptrace / `/proc/<pid>/mem`
/// for same-uid processes, no inherited fds.
///
/// `RLIMIT_CORE 0` alone is not enough: when `core_pattern` is a pipe (as
/// with systemd-coredump) the kernel ignores the limit and still hands the
/// crash to the helper, and with `fs.suid_dumpable=2` it does so even for a
/// non-dumpable process. So every core-dumping signal is caught and turned
/// into `_exit(128 + sig)`: the worker exits, it never dumps.
pub fn harden_worker_process() -> Result<(), String> {
    // SAFETY: sigaction with a handler that only calls _exit; SA_ONSTACK so
    // a stack overflow can still run it (std set up the alternate stack).
    unsafe {
        for &sig in CORE_SIGNALS {
            let mut sa: libc::sigaction = std::mem::zeroed();
            sa.sa_sigaction = exit_on_fatal_signal as extern "C" fn(libc::c_int) as usize;
            sa.sa_flags = libc::SA_ONSTACK | libc::SA_NODEFER;
            libc::sigemptyset(&mut sa.sa_mask);
            if libc::sigaction(sig, &sa, std::ptr::null_mut()) != 0 {
                return Err(format!("sigaction({sig}): {}", std::io::Error::last_os_error()));
            }
        }
        let zero = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
        if libc::setrlimit(libc::RLIMIT_CORE, &zero) != 0 {
            return Err(format!("RLIMIT_CORE: {}", std::io::Error::last_os_error()));
        }
        if libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) != 0 {
            return Err(format!("PR_SET_DUMPABLE: {}", std::io::Error::last_os_error()));
        }
    }
    close_inherited_fds().map(|_| ())
}

/// Make the host process non-dumpable (no ptrace, no `/proc/<pid>/mem` or
/// `environ` for other processes of the same uid, such as a worker that
/// escaped a degraded sandbox) and stop it from writing core files that
/// would hold tenant credentials. Call first thing in `main`.
pub fn harden_host_process() -> Result<(), String> {
    // SAFETY: plain prctl / setrlimit on ourselves.
    unsafe {
        if libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) != 0 {
            return Err(format!("PR_SET_DUMPABLE: {}", std::io::Error::last_os_error()));
        }
        let zero = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
        if libc::setrlimit(libc::RLIMIT_CORE, &zero) != 0 {
            return Err(format!("RLIMIT_CORE: {}", std::io::Error::last_os_error()));
        }
    }
    Ok(())
}

/// Syscalls the worker may make. Everything a single-threaded VRL
/// interpreter reading stdin and writing stdout needs, and nothing else.
fn allowed_syscalls() -> Vec<i64> {
    let mut v = vec![
        libc::SYS_read,
        libc::SYS_write,
        libc::SYS_readv,
        libc::SYS_writev,
        libc::SYS_close,
        libc::SYS_fstat,
        libc::SYS_munmap,
        libc::SYS_mremap,
        libc::SYS_brk,
        libc::SYS_madvise,
        libc::SYS_exit,
        libc::SYS_exit_group,
        libc::SYS_rt_sigreturn,
        libc::SYS_rt_sigprocmask,
        libc::SYS_rt_sigaction,
        libc::SYS_sigaltstack,
        libc::SYS_clock_gettime,
        libc::SYS_clock_getres,
        libc::SYS_clock_nanosleep,
        libc::SYS_nanosleep,
        libc::SYS_gettimeofday,
        libc::SYS_getrandom,
        libc::SYS_sched_yield,
        libc::SYS_getpid,
        libc::SYS_gettid,
        libc::SYS_restart_syscall,
    ];
    #[cfg(target_arch = "x86_64")]
    v.push(libc::SYS_time);
    v
}

/// Syscalls that end the worker on sight: the ones an escaped interpreter
/// would need to reach the network, other processes or new code. They trap
/// (SIGSYS) rather than `KILL_PROCESS`: the syscall never runs either way,
/// and the trap lands in [`harden_worker_process`]'s handler, which exits
/// without a core dump (a kill always dumps).
fn fatal_syscalls() -> Vec<i64> {
    let mut v = vec![
        libc::SYS_socket,
        libc::SYS_socketpair,
        libc::SYS_connect,
        libc::SYS_bind,
        libc::SYS_listen,
        libc::SYS_accept,
        libc::SYS_accept4,
        libc::SYS_sendto,
        libc::SYS_sendmsg,
        libc::SYS_sendmmsg,
        libc::SYS_recvfrom,
        libc::SYS_recvmsg,
        libc::SYS_execve,
        libc::SYS_execveat,
        libc::SYS_clone,
        libc::SYS_clone3,
        libc::SYS_ptrace,
        libc::SYS_process_vm_readv,
        libc::SYS_process_vm_writev,
        libc::SYS_pidfd_open,
        libc::SYS_pidfd_getfd,
        libc::SYS_kill,
        libc::SYS_tkill,
        libc::SYS_unshare,
        libc::SYS_setns,
        libc::SYS_mount,
        libc::SYS_bpf,
        libc::SYS_userfaultfd,
        libc::SYS_perf_event_open,
        libc::SYS_io_uring_setup,
        libc::SYS_keyctl,
        libc::SYS_add_key,
        libc::SYS_request_key,
    ];
    #[cfg(target_arch = "x86_64")]
    v.extend([libc::SYS_fork, libc::SYS_vfork]);
    v
}

fn se<E: std::fmt::Display>(e: E) -> String {
    e.to_string()
}

/// Build the worker's seccomp programs (kill list, then allowlist), in the
/// order they must be installed.
pub fn worker_seccomp() -> Result<Vec<seccompiler::BpfProgram>, String> {
    use seccompiler::{SeccompAction, SeccompCmpArgLen, SeccompCmpOp, SeccompCondition, SeccompFilter, SeccompRule, TargetArch};
    let arch = TargetArch::try_from(std::env::consts::ARCH).map_err(|e| e.to_string())?;
    let mut allow: BTreeMap<i64, Vec<SeccompRule>> = BTreeMap::new();
    for s in allowed_syscalls() {
        allow.insert(s, vec![]);
    }
    // Memory may be mapped or reprotected, but never executable: no JIT, no
    // shellcode.
    let no_exec = || -> Result<Vec<SeccompRule>, seccompiler::Error> {
        Ok(vec![SeccompRule::new(vec![SeccompCondition::new(
            2,
            SeccompCmpArgLen::Dword,
            SeccompCmpOp::MaskedEq(libc::PROT_EXEC as u64),
            0,
        )?])?])
    };
    // futex: wait / wake only (± PRIVATE / CLOCK_REALTIME). PI, requeue
    // and WAKE_OP are refused: historic kernel-bug surface nothing here
    // needs.
    let mut futex = Vec::new();
    for op in [libc::FUTEX_WAIT, libc::FUTEX_WAKE, libc::FUTEX_WAIT_BITSET, libc::FUTEX_WAKE_BITSET] {
        futex.push(
            SeccompRule::new(vec![
                SeccompCondition::new(1, SeccompCmpArgLen::Dword, SeccompCmpOp::MaskedEq(u64::from(libc::FUTEX_CMD_MASK as u32)), op as u64)
                    .map_err(se)?,
            ])
            .map_err(se)?,
        );
    }
    allow.insert(libc::SYS_futex, futex);
    allow.insert(libc::SYS_mmap, no_exec().map_err(se)?);
    allow.insert(libc::SYS_mprotect, no_exec().map_err(se)?);
    // abort() signals itself; signalling any other process is not allowed.
    // SAFETY: getpid never fails.
    let pid = unsafe { libc::getpid() } as u64;
    allow.insert(
        libc::SYS_tgkill,
        vec![SeccompRule::new(vec![SeccompCondition::new(0, SeccompCmpArgLen::Dword, SeccompCmpOp::Eq, pid).map_err(se)?])
            .map_err(se)?],
    );
    let allow = SeccompFilter::new(allow, SeccompAction::Errno(libc::EPERM as u32), SeccompAction::Allow, arch).map_err(se)?;

    let mut kill: BTreeMap<i64, Vec<SeccompRule>> = BTreeMap::new();
    for s in fatal_syscalls() {
        kill.insert(s, vec![]);
    }
    let kill = SeccompFilter::new(kill, SeccompAction::Allow, SeccompAction::Trap, arch).map_err(se)?;
    // Order matters: once the allowlist is in, prctl/seccomp themselves are
    // refused, so the kill list goes first.
    Ok(vec![kill.try_into().map_err(se)?, allow.try_into().map_err(se)?])
}

/// Lock down the worker process. Must run while single-threaded and before
/// any tenant input is read. Returns the seccomp status for the report.
pub fn enter_worker_sandbox(seccomp: Enforce) -> Result<String, String> {
    harden_worker_process().map_err(|e| format!("worker hardening failed: {e}"))?;
    install_seccomp(seccomp)
}

/// The seccomp half of [`enter_worker_sandbox`].
pub fn install_seccomp(seccomp: Enforce) -> Result<String, String> {
    if seccomp == Enforce::Off {
        return Ok("off".into());
    }
    let installed = worker_seccomp().and_then(|progs| {
        for p in &progs {
            seccompiler::apply_filter(p).map_err(|e| e.to_string())?;
        }
        Ok(())
    });
    match (installed, seccomp) {
        (Ok(()), _) => Ok("enforced".into()),
        (Err(e), Enforce::Require) => Err(format!("seccomp is required but could not be installed: {e}")),
        (Err(e), _) => Ok(format!("unavailable: {e}")),
    }
}

// ---------------------------------------------------------------------------
// cgroup v2
// ---------------------------------------------------------------------------

/// A delegated cgroup v2 directory that holds one leaf per worker.
#[derive(Debug)]
pub struct CgroupParent {
    dir: PathBuf,
    pub controllers: Vec<String>,
    seq: AtomicU64,
}

impl CgroupParent {
    /// Check that `dir` is a writable cgroup v2 directory and enable the
    /// memory, pids and cpu controllers for its children. memory and pids
    /// are mandatory; cpu is optional (RLIMIT_CPU still applies).
    pub fn probe(dir: &Path) -> Result<Self, String> {
        let controllers = std::fs::read_to_string(dir.join("cgroup.controllers"))
            .map_err(|e| format!("{} is not a cgroup v2 directory: {e}", dir.display()))?;
        let available: Vec<&str> = controllers.split_whitespace().collect();
        let subtree = dir.join("cgroup.subtree_control");
        let mut write_err = None;
        for c in ["memory", "pids", "cpu"] {
            if available.contains(&c) {
                // Fails with EROFS on a read-only cgroupfs (default in
                // containers) and EBUSY when the directory still holds
                // processes (the "no internal processes" rule).
                if let Err(e) = std::fs::write(&subtree, format!("+{c}")) {
                    write_err.get_or_insert(e);
                }
            }
        }
        let enabled: Vec<String> = std::fs::read_to_string(&subtree)
            .map_err(|e| format!("{}: {e}", subtree.display()))?
            .split_whitespace()
            .map(str::to_string)
            .collect();
        for c in ["memory", "pids"] {
            if !enabled.iter().any(|e| e == c) {
                return Err(format!(
                    "controller `{c}` is not delegated to {} ({}; it must be a writable cgroup v2 directory with no processes of its own)",
                    dir.display(),
                    write_err.as_ref().map(|e| e.to_string()).unwrap_or_else(|| "not enabled in cgroup.subtree_control".into()),
                ));
            }
        }
        let probe = dir.join(format!("probe-{}", std::process::id()));
        std::fs::create_dir(&probe).map_err(|e| format!("cannot create a leaf under {}: {e}", dir.display()))?;
        let _ = std::fs::remove_dir(&probe);
        Ok(Self { dir: dir.to_path_buf(), controllers: enabled, seq: AtomicU64::new(0) })
    }

    pub fn has(&self, c: &str) -> bool {
        self.controllers.iter().any(|e| e == c)
    }

    /// One leaf for one worker.
    pub fn leaf(&self, memory_max: u64, cpu_max: Option<(u64, u64)>) -> Result<CgroupLeaf, String> {
        let n = self.seq.fetch_add(1, Ordering::SeqCst);
        let dir = self.dir.join(format!("vrl-{}-{n}", std::process::id()));
        std::fs::create_dir(&dir).map_err(|e| format!("mkdir {}: {e}", dir.display()))?;
        let leaf = CgroupLeaf { dir };
        leaf.write("memory.max", &memory_max.to_string())?;
        let _ = leaf.write("memory.swap.max", "0");
        let _ = leaf.write("memory.oom.group", "1");
        leaf.write("pids.max", "1")?;
        if let (Some((q, p)), true) = (cpu_max, self.has("cpu")) {
            leaf.write("cpu.max", &format!("{q} {p}"))?;
        }
        Ok(leaf)
    }
}

/// A per-worker cgroup, removed when dropped.
#[derive(Debug)]
pub struct CgroupLeaf {
    dir: PathBuf,
}

impl CgroupLeaf {
    fn write(&self, file: &str, v: &str) -> Result<(), String> {
        std::fs::write(self.dir.join(file), v).map_err(|e| format!("{}/{file}: {e}", self.dir.display()))
    }

    pub fn path(&self) -> &Path {
        &self.dir
    }

    /// Move a process into the leaf.
    pub fn add(&self, pid: u32) -> Result<(), String> {
        self.write("cgroup.procs", &pid.to_string())
    }

    /// True when the kernel OOM-killed something in this leaf.
    pub fn oom_killed(&self) -> bool {
        std::fs::read_to_string(self.dir.join("memory.events"))
            .ok()
            .and_then(|s| s.lines().find_map(|l| l.strip_prefix("oom_kill ").and_then(|v| v.trim().parse::<u64>().ok())))
            .is_some_and(|n| n > 0)
    }
}

impl Drop for CgroupLeaf {
    fn drop(&mut self) {
        // The worker was killed by kill_on_drop, possibly not reaped yet;
        // cgroup.kill (5.14+) makes sure, then rmdir is retried briefly off
        // the async thread.
        let _ = std::fs::write(self.dir.join("cgroup.kill"), "1");
        if std::fs::remove_dir(&self.dir).is_ok() {
            return;
        }
        let dir = self.dir.clone();
        std::thread::spawn(move || {
            for _ in 0..50 {
                std::thread::sleep(std::time::Duration::from_millis(20));
                if std::fs::remove_dir(&dir).is_ok() {
                    return;
                }
            }
            tracing::warn!(target: "nano_connector::sandbox", dir = %dir.display(), "could not remove a VRL worker cgroup");
        });
    }
}

/// Describe how a worker died, from its wait status.
pub fn death_reason(status: Option<std::process::ExitStatus>, oom: bool) -> String {
    use std::os::unix::process::ExitStatusExt;
    if oom {
        return "killed by its cgroup memory limit".into();
    }
    // A hardened worker turns fatal signals into exit(128 + sig).
    let sig = status.and_then(|s| s.signal()).or_else(|| status.and_then(|s| s.code()).filter(|c| (129..160).contains(c)).map(|c| c - 128));
    match sig {
        Some(libc::SIGSYS) => "killed by seccomp (forbidden syscall)".into(),
        Some(libc::SIGXCPU) => "killed by its CPU-time limit".into(),
        Some(libc::SIGSEGV) | Some(libc::SIGBUS) => "crashed (stack overflow: program too deeply nested?)".into(),
        Some(libc::SIGABRT) => "aborted (memory limit or stack overflow)".into(),
        Some(libc::SIGKILL) => "killed (memory or CPU limit)".into(),
        Some(sig) => format!("killed by signal {sig}"),
        None => match status.and_then(|s| s.code()) {
            Some(c) => format!("exited with status {c}"),
            None => "exited".into(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_enforce_values_are_errors_not_defaults() {
        let env = |pairs: &'static [(&'static str, &'static str)]| {
            move |k: &str| pairs.iter().find(|(n, _)| *n == k).map(|(_, v)| v.to_string())
        };
        assert_eq!(SandboxPolicy::from_lookup(env(&[])).unwrap().seccomp, Enforce::Prefer);
        assert_eq!(SandboxPolicy::from_lookup(env(&[("NANO_CONNECTOR_SECCOMP", "Require")])).unwrap().seccomp, Enforce::Require);
        let strict = SandboxPolicy::from_lookup(env(&[("NANO_CONNECTOR_SANDBOX", "strict")])).unwrap();
        assert_eq!((strict.seccomp, strict.cgroup), (Enforce::Require, Enforce::Require));
        for (k, v) in [
            ("NANO_CONNECTOR_SECCOMP", "required"),
            ("NANO_CONNECTOR_SECCOMP", "enforce"),
            ("NANO_CONNECTOR_SECCOMP", "on"),
            ("NANO_CONNECTOR_SECCOMP", "yes"),
            ("NANO_CONNECTOR_CGROUP", "requird"),
            ("NANO_CONNECTOR_SANDBOX", "strictt"),
        ] {
            let pairs: &'static [(&'static str, &'static str)] = Box::leak(Box::new([(k, v)]));
            let e = SandboxPolicy::from_lookup(env(pairs)).expect_err(v);
            assert!(e.contains(k), "{e}");
        }
    }

    #[test]
    fn death_reasons_cover_hardened_exits() {
        use std::os::unix::process::ExitStatusExt;
        let exit = |c: i32| Some(std::process::ExitStatus::from_raw(c << 8));
        assert!(death_reason(exit(fatal_exit_code(libc::SIGSYS)), false).contains("seccomp"));
        assert!(death_reason(exit(fatal_exit_code(libc::SIGABRT)), false).contains("aborted"));
        assert!(death_reason(exit(fatal_exit_code(libc::SIGXCPU)), false).contains("CPU"));
        assert_eq!(death_reason(exit(1), false), "exited with status 1");
    }
}
