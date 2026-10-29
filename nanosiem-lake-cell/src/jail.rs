// SPDX-License-Identifier: AGPL-3.0-or-later

//! In-process jail for a tenant process (NAN-2871).
//!
//! [`apply`] runs inside the tenant process after `Assign` and before any
//! tenant data or key is touched. In order, it:
//!
//! 1. refuses to run unless the process is single-threaded (setresuid,
//!    landlock and seccomp are per-thread without TSYNC; a second thread
//!    could keep the old credentials or escape the filters);
//! 2. sets rlimits (no core dumps, fd cap, the RLIMIT_NPROC pids fallback);
//! 3. drops supplementary groups, then gid, then uid (real, effective and
//!    saved) and verifies the drop cannot be undone;
//! 4. sets umask 027, re-arms `PR_SET_PDEATHSIG`, sets `PR_SET_DUMPABLE=0` (no ptrace attach, `/proc/<pid>/{mem,environ,
//!    fd,maps}` unreadable by anyone but root) and `PR_SET_NO_NEW_PRIVS`;
//! 5. applies a landlock ruleset: read-write only beneath the role's own
//!    directories, read-only beneath the given data/feed/system paths and
//!    its own `/proc/<pid>`, no TCP bind, TCP connect only to the listed
//!    ports, and (kernel permitting) no abstract-unix connects, no signals
//!    to processes outside the domain, no pathname-unix connects;
//! 6. installs a seccomp filter that also blocks creating AF_UNIX sockets
//!    and AF_UNIX datagram socketpairs, covering abstract sockets on
//!    kernels without Landlock ABI v6 scoping (see [`seccomp_filter`]).
//!
//! Signals: Landlock signal scoping also needs ABI v6. Without it, kill(2)
//! between tenants is refused by the kernel's uid check alone: every role
//! runs as its own uid and step 3 verifies the process holds no
//! capabilities (no CAP_KILL) once the drop is done.
//!
//! Nothing here allocates after the uid drop in a way that matters; it is
//! plain sequential code for a single-threaded process.

use crate::contract::JailSpec;
use landlock::{
    Access, AccessFs, AccessNet, CompatLevel, Compatible, NetPort, PathBeneath, PathFd, Ruleset, RulesetAttr,
    RulesetCreatedAttr, RulesetStatus, Scope, ABI,
};
use seccompiler::{
    BpfProgram, SeccompAction, SeccompCmpArgLen, SeccompCmpOp, SeccompCondition, SeccompFilter, SeccompRule,
    TargetArch,
};
#[cfg(target_arch = "x86_64")]
use seccompiler::sock_filter;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

#[derive(Debug, thiserror::Error)]
pub enum JailError {
    #[error("process has {0} threads; the jail must be applied while single-threaded")]
    MultiThreaded(usize),
    #[error("{op}: {source}")]
    Os { op: &'static str, source: std::io::Error },
    #[error("credential drop did not stick: {0}")]
    DropFailed(String),
    #[error("landlock: {0}")]
    Landlock(String),
    #[error("landlock is required but not enforced by this kernel ({0})")]
    LandlockUnavailable(String),
    #[error("seccomp: {0}")]
    Seccomp(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JailReport {
    pub uid: u32,
    pub gid: u32,
    /// "full", "partial" or "none".
    pub landlock: String,
    pub seccomp: bool,
    /// The process got its own cgroup namespace (rooted at its role leaf):
    /// `/proc/self/cgroup` shows `/`, never the cell's tenant layout.
    pub cgroupns: bool,
}

fn os(op: &'static str) -> JailError {
    JailError::Os { op, source: std::io::Error::last_os_error() }
}

/// Threads in this process, from `/proc/self/status`.
pub fn thread_count() -> usize {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| {
            s.lines()
                .find_map(|l| l.strip_prefix("Threads:").map(|v| v.trim().parse::<usize>().unwrap_or(0)))
        })
        .unwrap_or(0)
}

/// Apply the jail to the calling (single-threaded) process. Irreversible.
pub fn apply(spec: &JailSpec) -> Result<JailReport, JailError> {
    apply_with(spec, seccomp_filter)
}

/// The native byte-service jail: the same Landlock/cgroup/rlimit jail with
/// [`native_seccomp_filter`], so the child can create no socket at all.
pub fn apply_native(spec: &JailSpec) -> Result<JailReport, JailError> {
    apply_with(spec, native_seccomp_filter)
}

fn apply_with(
    spec: &JailSpec,
    filter: fn() -> Result<Vec<BpfProgram>, seccompiler::Error>,
) -> Result<JailReport, JailError> {
    let threads = thread_count();
    if threads != 1 {
        return Err(JailError::MultiThreaded(threads));
    }
    // Build everything that allocates or opens paths while still privileged
    // enough to open them: the seccomp program and the landlock path fds.
    let bpf = filter().map_err(|e| JailError::Seccomp(e.to_string()))?;
    let own_proc = PathBuf::from(format!("/proc/{}", std::process::id()));
    let ruleset = build_landlock(spec, &own_proc)?;

    // SAFETY: getppid never fails.
    let parent = unsafe { libc::getppid() };
    set_rlimits(spec)?;
    drop_bounding_set();
    // Own cgroup namespace, rooted where the supervisor placed us (our role
    // leaf): hides the cell's cgroup layout. Needs CAP_SYS_ADMIN, which we
    // still have before the drop. Mandatory whenever we have a cgroup
    // (landlock additionally limits reads to our own leaf).
    let cgroupns = match &spec.cgroup_dir {
        // SAFETY: unshare with a constant flag.
        Some(_) if unsafe { libc::unshare(libc::CLONE_NEWCGROUP) } != 0 => return Err(os("unshare(CLONE_NEWCGROUP)")),
        Some(_) => true,
        None => false,
    };
    drop_credentials(spec.uid, spec.gid)?;
    verify_no_capabilities()?;
    // SAFETY: umask always succeeds. Group-readable, never world-readable:
    // ingest's parts are readable by query[T] (same tenant gid) only.
    unsafe { libc::umask(0o027) };

    // SAFETY: plain prctl calls with constant arguments.
    unsafe {
        if libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) != 0 {
            return Err(os("prctl(PR_SET_DUMPABLE)"));
        }
        if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
            return Err(os("prctl(PR_SET_NO_NEW_PRIVS)"));
        }
        // The credential change cleared any parent-death signal; re-arm it
        // so a dead supervisor never leaves orphaned tenant processes, then
        // close the race where the parent died before the prctl.
        if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0) != 0 {
            return Err(os("prctl(PR_SET_PDEATHSIG)"));
        }
        if libc::getppid() != parent {
            libc::_exit(1);
        }
    }

    let status = ruleset.restrict_self().map_err(|e| JailError::Landlock(e.to_string()))?;
    let landlock = match status.ruleset {
        RulesetStatus::FullyEnforced => "full",
        RulesetStatus::PartiallyEnforced => "partial",
        RulesetStatus::NotEnforced => "none",
    }
    .to_owned();
    if spec.require_landlock && landlock == "none" {
        return Err(JailError::LandlockUnavailable(landlock));
    }
    for prog in &bpf {
        seccompiler::apply_filter(prog).map_err(|e| JailError::Seccomp(e.to_string()))?;
    }

    Ok(JailReport { uid: spec.uid, gid: spec.gid, landlock, seccomp: true, cgroupns })
}

fn set_rlimits(spec: &JailSpec) -> Result<(), JailError> {
    // glibc exposes an unsigned enum typedef; musl's ABI uses c_int and does
    // not define __rlimit_resource_t. Keep the native libc constant's type.
    #[cfg(target_env = "gnu")]
    type RlimitResource = libc::__rlimit_resource_t;
    #[cfg(not(target_env = "gnu"))]
    type RlimitResource = libc::c_int;
    fn set(res: RlimitResource, soft: u64, hard: u64, op: &'static str) -> Result<(), JailError> {
        let lim = libc::rlimit { rlim_cur: soft as libc::rlim_t, rlim_max: hard as libc::rlim_t };
        // SAFETY: valid pointer to a stack rlimit.
        if unsafe { libc::setrlimit(res, &lim) } != 0 {
            return Err(os(op));
        }
        Ok(())
    }
    set(libc::RLIMIT_CORE, 0, 0, "setrlimit(RLIMIT_CORE)")?;
    set(libc::RLIMIT_NOFILE, spec.max_open_files, spec.max_open_files, "setrlimit(RLIMIT_NOFILE)")?;
    if let Some(n) = spec.max_processes {
        set(libc::RLIMIT_NPROC, n, n, "setrlimit(RLIMIT_NPROC)")?;
    }
    Ok(())
}

/// Empty the capability bounding set (needs CAP_SETPCAP; best effort). The
/// uid drop already clears permitted/effective caps and `no_new_privs`
/// blocks file caps, so this is defense in depth.
fn drop_bounding_set() {
    let last: i32 = std::fs::read_to_string("/proc/sys/kernel/cap_last_cap")
        .ok()
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(40);
    for cap in 0..=last {
        // SAFETY: prctl with integer args.
        unsafe { libc::prctl(libc::PR_CAPBSET_DROP, cap as libc::c_ulong, 0, 0, 0) };
    }
}

fn drop_credentials(uid: u32, gid: u32) -> Result<(), JailError> {
    if uid == 0 || gid == 0 {
        return Err(JailError::DropFailed("refusing to jail as uid/gid 0".into()));
    }
    // SAFETY: plain credential syscalls; glibc broadcasts setxid to all
    // threads, and we are single-threaded anyway.
    unsafe {
        if libc::setgroups(0, std::ptr::null()) != 0 {
            return Err(os("setgroups([])"));
        }
        if libc::setresgid(gid, gid, gid) != 0 {
            return Err(os("setresgid"));
        }
        if libc::setresuid(uid, uid, uid) != 0 {
            return Err(os("setresuid"));
        }
        let (mut r, mut e, mut s) = (0, 0, 0);
        libc::getresuid(&mut r, &mut e, &mut s);
        if (r, e, s) != (uid, uid, uid) {
            return Err(JailError::DropFailed(format!("resuid is {r}/{e}/{s}")));
        }
        let (mut r, mut e, mut s) = (0, 0, 0);
        libc::getresgid(&mut r, &mut e, &mut s);
        if (r, e, s) != (gid, gid, gid) {
            return Err(JailError::DropFailed(format!("resgid is {r}/{e}/{s}")));
        }
        // Regaining root must fail now.
        if libc::setuid(0) == 0 {
            return Err(JailError::DropFailed("setuid(0) succeeded after the drop".into()));
        }
    }
    Ok(())
}

/// Fail unless the permitted, effective and ambient capability
/// sets are all empty (NAN-3567). On kernels without Landlock ABI v6 the
/// uid check is the only thing that stops one tenant signalling another,
/// and CAP_KILL would bypass it. The bounding set may stay populated when
/// the pod lacks CAP_SETPCAP; with `no_new_privs` it cannot refill these.
fn verify_no_capabilities() -> Result<(), JailError> {
    let status = std::fs::read_to_string("/proc/self/status").map_err(|source| JailError::Os { op: "read /proc/self/status", source })?;
    held_capabilities(&status).map_err(JailError::DropFailed)
}

/// `Ok` when every non-bounding capability set in a `/proc/<pid>/status`
/// body is zero; the error names the sets still holding bits.
fn held_capabilities(status: &str) -> Result<(), String> {
    let mut held = Vec::new();
    for set in ["CapPrm", "CapEff", "CapAmb"] {
        let value = status
            .lines()
            .find_map(|l| l.strip_prefix(set).and_then(|v| v.strip_prefix(':')))
            .map(str::trim)
            .ok_or_else(|| format!("{set} missing from /proc/self/status"))?;
        let bits = u64::from_str_radix(value, 16).map_err(|e| format!("{set} {value:?}: {e}"))?;
        if bits != 0 {
            held.push(format!("{set}={bits:016x}"));
        }
    }
    if held.is_empty() { Ok(()) } else { Err(format!("capabilities still held: {}", held.join(" "))) }
}

/// The ABI this crate was written and tested against. Higher kernels are
/// fine; lower ones enforce a subset (reported as "partial").
const LANDLOCK_ABI: ABI = ABI::V9;

/// Build the ruleset (opening every path fd) before the credential drop;
/// it is enforced with `restrict_self` after `no_new_privs`.
fn build_landlock(spec: &JailSpec, own_proc: &Path) -> Result<landlock::RulesetCreated, JailError> {
    let ll = |e: landlock::RulesetError| JailError::Landlock(e.to_string());
    let abi = LANDLOCK_ABI;
    let rw = AccessFs::from_all(abi);
    let ro = AccessFs::from_read(abi);
    // Device nodes need read+write file access but nothing else.
    let dev = AccessFs::ReadFile | AccessFs::WriteFile;

    let mut ruleset = Ruleset::default()
        .set_compatibility(CompatLevel::BestEffort)
        .handle_access(AccessFs::from_all(abi))
        .map_err(ll)?
        .handle_access(AccessNet::from_all(abi))
        .map_err(ll)?
        .scope(Scope::from_all(abi))
        .map_err(ll)?
        .create()
        .map_err(ll)?;

    // (path, access, required): every read-write path is the tenant's own
    // state and must be granted; read-only and system paths may be absent.
    let mut rules: Vec<(PathBuf, landlock::BitFlags<AccessFs>, bool)> = Vec::new();
    rules.extend(spec.rw_paths.iter().map(|p| (p.clone(), rw, true)));
    rules.extend(spec.ro_paths.iter().chain(spec.system_ro_paths.iter()).map(|p| (p.clone(), ro, false)));
    rules.push((own_proc.to_path_buf(), ro, false));
    for p in ["/proc/meminfo", "/proc/stat", "/proc/cpuinfo", "/proc/loadavg", "/sys/devices/system/cpu"] {
        rules.push((PathBuf::from(p), ro, false));
    }
    for p in ["/dev/null", "/dev/zero", "/dev/urandom", "/dev/random"] {
        rules.push((PathBuf::from(p), dev, false));
    }
    if let Some(cg) = &spec.cgroup_dir {
        rules.push((Path::new("/sys/fs/cgroup").join(cg.strip_prefix("/").unwrap_or(cg)), ro, false));
    }
    for (path, access, required) in rules {
        let Some(fd) = open_rule_path(&path, required, spec.uid, spec.gid)? else { continue };
        // Directory-only rights on a file would make the kernel/crate report
        // a "partial" ruleset; narrow them to what a file can carry.
        let is_dir = std::fs::metadata(&path).map(|m| m.is_dir()).unwrap_or(true);
        let access = if is_dir { access } else { access & AccessFs::from_file(abi) };
        (&mut ruleset).add_rule(PathBeneath::new(fd, access)).map_err(ll)?;
    }
    for port in &spec.tcp_connect_ports {
        (&mut ruleset).add_rule(NetPort::new(*port, AccessNet::ConnectTcp)).map_err(ll)?;
    }
    Ok(ruleset)
}

/// Syscalls denied outright (EPERM) for every tenant process.
fn denied_syscalls() -> Vec<i64> {
    vec![
        // Cross-process inspection and memory access.
        libc::SYS_ptrace,
        libc::SYS_process_vm_readv,
        libc::SYS_process_vm_writev,
        libc::SYS_kcmp,
        libc::SYS_pidfd_getfd,
        libc::SYS_perf_event_open,
        // Kernel attack surface a tenant engine never needs.
        libc::SYS_bpf,
        libc::SYS_userfaultfd,
        libc::SYS_keyctl,
        libc::SYS_add_key,
        libc::SYS_request_key,
        libc::SYS_io_uring_setup,
        libc::SYS_io_uring_enter,
        libc::SYS_io_uring_register,
        libc::SYS_open_by_handle_at,
        libc::SYS_name_to_handle_at,
        // Namespaces and mounts (the route to regaining capabilities).
        libc::SYS_unshare,
        libc::SYS_setns,
        libc::SYS_mount,
        libc::SYS_umount2,
        libc::SYS_pivot_root,
        libc::SYS_chroot,
        libc::SYS_fsopen,
        libc::SYS_fsmount,
        libc::SYS_move_mount,
        libc::SYS_open_tree,
        libc::SYS_mount_setattr,
        // Tenant processes never accept connections: streams arrive by fd.
        libc::SYS_listen,
    ]
}

/// The socket type bits of socket(2)/socketpair(2)'s `type` argument; the
/// rest are flags (SOCK_CLOEXEC, SOCK_NONBLOCK).
const SOCK_TYPE_MASK: u64 = 0xf;

/// NAN-3791: open one Landlock rule path. The cell holds no
/// CAP_DAC_READ_SEARCH, so opening `<T>/product/demand` as the
/// pre-drop uid fails with EACCES on `<T>/product` (0700, the tenant's
/// uid), and the old `!path.exists()` test (also false on EACCES) skipped
/// the rule silently: query[T] then could never write its demand inbox.
/// A path the current credentials cannot reach is retried under the
/// tenant's own fs credentials (what the process holds after the drop).
/// A required (read-write) path that is missing or unreachable refuses
/// the jail; an optional one is skipped (with a warning when unreachable).
fn open_rule_path(path: &Path, required: bool, uid: u32, gid: u32) -> Result<Option<PathFd>, JailError> {
    let first = match PathFd::new(path) {
        Ok(fd) => return Ok(Some(fd)),
        Err(error) => error,
    };
    let retried = crate::tenant_dirs::FsCred::assume(uid, gid).ok().map(|cred| {
        let opened = PathFd::new(path);
        drop(cred);
        opened
    });
    if let Some(Ok(fd)) = retried {
        return Ok(Some(fd));
    }
    let missing = match std::fs::symlink_metadata(path) {
        Err(error) => error.kind() == std::io::ErrorKind::NotFound,
        Ok(_) => false,
    };
    if missing && !required {
        // A missing optional path (e.g. /lib64 on aarch64) is skipped.
        return Ok(None);
    }
    if !required {
        // An optional read-only path the tenant cannot reach grants nothing
        // either way (Landlock only narrows); keep the old skip, loudly.
        tracing::warn!(path = %path.display(), error = %first, "optional jail path cannot be opened; not granted");
        return Ok(None);
    }
    Err(JailError::Landlock(format!(
        "{} ({}): {first}",
        path.display(),
        if missing { "required path is missing" } else { "rule path cannot be opened" }
    )))
}

/// Build the tenant seccomp programs: default allow, deny-list with EPERM.
pub fn seccomp_filter() -> Result<Vec<BpfProgram>, seccompiler::Error> {
    build_seccomp_filter(false)
}

/// Native LandingBytesV1 children use only fds the supervisor passes. Every
/// socket(2) is denied, including AF_INET/AF_INET6: Landlock network rules
/// cover TCP only, so UDP and raw IP would otherwise stay reachable.
/// Connection socketpairs stay allowed as in the shared filter.
pub fn native_seccomp_filter() -> Result<Vec<BpfProgram>, seccompiler::Error> {
    build_seccomp_filter(true)
}

fn build_seccomp_filter(no_sockets: bool) -> Result<Vec<BpfProgram>, seccompiler::Error> {
    let arch = TargetArch::try_from(std::env::consts::ARCH)?;
    let mut rules: BTreeMap<i64, Vec<SeccompRule>> = BTreeMap::new();
    for sys in denied_syscalls() {
        rules.insert(sys, vec![]);
    }
    // Tenant RPC uses a preopened AF_UNIX socketpair passed by the supervisor.
    // A tenant never needs to create a new AF_UNIX socket. Deny the whole
    // family so abstract connects remain impossible on Landlock ABI < 6.
    // AF_INET and AF_INET6 are controlled by the network Landlock rules.
    let fam = |op: SeccompCmpOp, v: u64| SeccompCondition::new(0, SeccompCmpArgLen::Dword, op, v);
    let mut sock_rules = vec![SeccompRule::new(vec![fam(SeccompCmpOp::Gt, 10)?])?];
    for v in [0u64, 1, 3, 4, 5, 6, 7, 8, 9] {
        sock_rules.push(SeccompRule::new(vec![fam(SeccompCmpOp::Eq, v)?])?);
    }
    if no_sockets {
        // An empty rule list matches unconditionally: socket(2) is EPERM.
        sock_rules.clear();
    }
    rules.insert(libc::SYS_socket, sock_rules);
    // socketpair(2) only makes AF_UNIX sockets and tokio's signal driver
    // needs a SOCK_STREAM pair, so it stays allowed for connection types.
    // A datagram pair is not: an unnamed AF_UNIX datagram socket can still
    // sendto() or bind() an abstract address, which Landlock cannot scope
    // before ABI v6 (NAN-3567). Stream and seqpacket pairs are connected at
    // birth, so connect() fails with EISCONN and sendto() ignores the address.
    let ty = |v: u64| SeccompCondition::new(1, SeccompCmpArgLen::Dword, SeccompCmpOp::MaskedEq(SOCK_TYPE_MASK), v);
    let mut pair_rules = Vec::new();
    for v in (0..=SOCK_TYPE_MASK).filter(|v| ![libc::SOCK_STREAM as u64, libc::SOCK_SEQPACKET as u64].contains(v)) {
        pair_rules.push(SeccompRule::new(vec![ty(v)?])?);
    }
    rules.insert(libc::SYS_socketpair, pair_rules);
    // clone(2) with CLONE_NEWUSER (or any namespace flag) is denied; clone3
    // cannot be argument-filtered (flags live in a struct), so it returns
    // ENOSYS below and libc falls back to clone(2).
    let ns_flags = [
        libc::CLONE_NEWUSER,
        libc::CLONE_NEWNS,
        libc::CLONE_NEWNET,
        libc::CLONE_NEWPID,
        libc::CLONE_NEWIPC,
        libc::CLONE_NEWUTS,
        libc::CLONE_NEWCGROUP,
    ];
    let mut clone_rules = Vec::new();
    for f in ns_flags {
        let f = f as u64;
        clone_rules.push(SeccompRule::new(vec![SeccompCondition::new(
            0,
            SeccompCmpArgLen::Qword,
            SeccompCmpOp::MaskedEq(f),
            f,
        )?])?);
    }
    rules.insert(libc::SYS_clone, clone_rules);

    let deny = SeccompFilter::new(rules, SeccompAction::Allow, SeccompAction::Errno(libc::EPERM as u32), arch)?;
    // clone3 → ENOSYS so libc falls back to the filterable clone(2). A
    // separate program: seccomp evaluates every installed filter and the
    // most restrictive result wins.
    let mut c3 = BTreeMap::new();
    c3.insert(libc::SYS_clone3, vec![]);
    let enosys = SeccompFilter::new(c3, SeccompAction::Allow, SeccompAction::Errno(libc::ENOSYS as u32), arch)?;
    let mut programs: Vec<BpfProgram> = vec![deny.try_into()?, enosys.try_into()?];
    #[cfg(target_arch = "x86_64")]
    programs.push(x32_deny_program());
    Ok(programs)
}

/// NAN-4545: x32 syscalls run under `AUDIT_ARCH_X86_64` with
/// `nr | __X32_SYSCALL_BIT`, so seccompiler's per-number `JEQ` rules never
/// match them and the deny-list's default Allow applied to every denied
/// syscall (socket, unshare, mount, ptrace, bpf, io_uring...) on kernels
/// with `CONFIG_X86_X32_ABI`. No cell child is an x32 program, so refuse
/// every syscall number at or above the x32 bit (the libseccomp/Docker
/// pattern). A separate program: seccomp evaluates every installed filter
/// and the most restrictive result wins. Other arches are left to the
/// seccompiler programs, which kill a foreign audit arch.
#[cfg(target_arch = "x86_64")]
fn x32_deny_program() -> BpfProgram {
    const LD_W_ABS: u16 = (libc::BPF_LD | libc::BPF_W | libc::BPF_ABS) as u16;
    const JEQ_K: u16 = (libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K) as u16;
    const JGE_K: u16 = (libc::BPF_JMP | libc::BPF_JGE | libc::BPF_K) as u16;
    const RET_K: u16 = (libc::BPF_RET | libc::BPF_K) as u16;
    const AUDIT_ARCH_X86_64: u32 = 62 | 0x8000_0000 | 0x4000_0000;
    const X32_SYSCALL_BIT: u32 = 0x4000_0000;
    const SECCOMP_RET_ERRNO: u32 = 0x0005_0000;
    const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;
    let op = |code, jt, jf, k| sock_filter { code, jt, jf, k };
    vec![
        op(LD_W_ABS, 0, 0, 4), // seccomp_data.arch
        op(JEQ_K, 0, 3, AUDIT_ARCH_X86_64),
        op(LD_W_ABS, 0, 0, 0), // seccomp_data.nr
        op(JGE_K, 0, 1, X32_SYSCALL_BIT),
        op(RET_K, 0, 0, SECCOMP_RET_ERRNO | libc::EPERM as u32),
        op(RET_K, 0, 0, SECCOMP_RET_ALLOW),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::{FromRawFd, OwnedFd};
    use std::os::linux::net::SocketAddrExt;
    use std::os::unix::net::{SocketAddr, UnixDatagram, UnixListener};

    fn status_with(prm: &str, eff: &str, amb: &str) -> String {
        format!("Name:\tx\nCapInh:\t0000000000000000\nCapPrm:\t{prm}\nCapEff:\t{eff}\nCapBnd:\t00000000002000e9\nCapAmb:\t{amb}\n")
    }

    fn spec_with(rw: Vec<PathBuf>, ro: Vec<PathBuf>) -> JailSpec {
        // SAFETY: plain credential getters.
        let (uid, gid) = unsafe { (libc::geteuid(), libc::getegid()) };
        JailSpec { uid, gid, rw_paths: rw, ro_paths: ro, system_ro_paths: vec![], tcp_connect_ports: vec![],
            cgroup_dir: None, require_landlock: false, max_processes: None, max_open_files: 1024 }
    }

    /// Run the supervisor's real assignment through the kernel rlimit setter.
    /// All irreversible credential/limit changes stay inside a subprocess.
    #[test]
    fn nan4834_startup_can_create_threads_past_the_old_uid_subquota() {
        const CHILD: &str = "NAN4834_JAIL_THREAD_CHILD";
        let mode = std::env::var(CHILD).ok();
        if mode.is_none() {
            for mode in ["old", "fixed"] {
                let output = std::process::Command::new(std::env::current_exe().unwrap())
                    .args(["--exact", "jail::tests::nan4834_startup_can_create_threads_past_the_old_uid_subquota",
                        "--nocapture", "--test-threads=1"])
                    .env(CHILD, mode).output().unwrap();
                assert!(output.status.success(), "{mode}: {}{}", String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr));
                println!("{mode}: {}", String::from_utf8_lossy(&output.stdout));
            }
            return;
        }
        use crate::contract::{NativeChildService::QueryPartsV1, Role, TenantId};
        let cfg = serde_json::from_value(serde_json::json!({
            "cell_id": "cell-a", "data_dir": "/cell/data", "state_dir": "/s",
            "ingest_binary": "/b", "query_binary": "/b", "listen_unix": "/r.sock",
            "router_token_file": "/t", "placement_file": "/p", "dev_key_dir": "/k",
            "extra_ro_paths": ["/cell/release"]
        })).unwrap();
        let tenant = TenantId::new("tenant-a").unwrap();
        let ids = crate::uidmap::ids_for_slot(20_000, 20, 0).unwrap();
        let placement = crate::config::TenantPlacement::legacy(tenant.clone(), 20.0);
        let root = tempfile::tempdir().unwrap();
        std::fs::write(root.path().join("cgroup.controllers"), "cpu memory pids\n").unwrap();
        std::fs::write(root.path().join("cgroup.procs"), "").unwrap();
        let cgroups = crate::limits::CgroupTree::adopt_root(root.path().into(), "/pod/cell".into(), vec![], false).unwrap();
        cgroups.register(&tenant, ids.slot);
        let mut assignment = crate::supervisor::native_role_preflight(&cfg, &tenant, Role::Query, &ids,
            Some(&cgroups), &placement, QueryPartsV1).unwrap();
        let old = mode.as_deref() == Some("old");
        if old {
            // Negative control: only restore the old production assignment's
            // one-third quota; the kernel setter and thread burst are shared.
            assignment.jail.max_processes = Some((crate::budget::TenantBudget::from_eps(placement.eps).max_pids / 3).max(64));
        }
        drop(cgroups);
        drop(root);
        set_rlimits(&assignment.jail).unwrap();
        // RLIMIT_NPROC does not constrain privileged root. A root farm run
        // uses an otherwise unused UID; unprivileged runs keep their UID.
        if unsafe { libc::geteuid() } == 0 {
            let uid = 100_000 + std::process::id();
            drop_credentials(uid, uid).unwrap();
        }
        verify_no_capabilities().unwrap();
        let gate = std::sync::Arc::new((std::sync::Mutex::new(false), std::sync::Condvar::new()));
        let mut threads = Vec::new();
        let mut refusal = None;
        for i in 0..200 {
            let gate = gate.clone();
            match std::thread::Builder::new().stack_size(64 * 1024).spawn(move || {
                let (lock, ready) = &*gate;
                drop(ready.wait_while(lock.lock().unwrap(), |open| !*open).unwrap());
            }) {
                Ok(thread) => threads.push(thread),
                Err(e) => { refusal = Some((i, e)); break; }
            }
        }
        // Keep all 200 alive at once: the old 170 soft/hard limit fails in
        // pthread_create, while the unchanged aggregate allowance is 512.
        let admitted = threads.len();
        *gate.0.lock().unwrap() = true;
        gate.1.notify_all();
        for thread in threads { thread.join().unwrap(); }
        if old {
            let (i, e) = refusal.expect("old UID subquota must refuse a live 200-thread burst");
            assert_eq!(e.raw_os_error(), Some(libc::EAGAIN), "thread {i}: {e}");
            println!("old quota refused thread {i}: {e} (kernel EAGAIN)");
        } else {
            assert!(refusal.is_none(), "startup thread refused: {refusal:?}");
            assert_eq!(admitted, 200);
            println!("fixed quota admitted {admitted} simultaneous threads");
        }
    }

    /// NAN-3791 reproduction: a rule path beneath a directory the jailing
    /// credentials cannot search used to be skipped as if it were missing
    /// (`Path::exists` is false on EACCES), leaving query[T] without its
    /// demand inbox. A required (read-write) path that cannot be opened or
    /// does not exist now refuses the jail; a missing or unreachable
    /// read-only one is still skipped.
    #[test]
    fn an_unreachable_or_missing_required_rule_path_refuses_the_jail() {
        // SAFETY: plain credential getter.
        if unsafe { libc::geteuid() } == 0 {
            eprintln!("skipped: root searches any directory");
            return;
        }
        use std::os::unix::fs::PermissionsExt;
        let root = tempfile::tempdir().unwrap();
        let product = root.path().join("product");
        let demand = product.join("demand");
        std::fs::create_dir_all(&demand).unwrap();
        std::fs::set_permissions(&product, std::fs::Permissions::from_mode(0o000)).unwrap();
        assert!(!demand.exists(), "the old skip test: an unsearchable path looks missing");
        let proc_self = PathBuf::from(format!("/proc/{}", std::process::id()));
        let refused = build_landlock(&spec_with(vec![demand.clone()], vec![]), &proc_self);
        let optional = build_landlock(&spec_with(vec![], vec![demand.clone()]), &proc_self);
        std::fs::set_permissions(&product, std::fs::Permissions::from_mode(0o700)).unwrap();
        match refused {
            Err(JailError::Landlock(message)) => assert!(message.contains("cannot be opened"), "{message}"),
            Err(other) => panic!("unexpected error {other}"),
            Ok(_) => panic!("an unreachable read-write path must refuse the jail"),
        }
        assert!(optional.is_ok(), "an unreachable read-only path is skipped (it grants nothing)");
        let missing = root.path().join("absent");
        match build_landlock(&spec_with(vec![missing.clone()], vec![]), &proc_self) {
            Err(JailError::Landlock(message)) => assert!(message.contains("required path is missing"), "{message}"),
            Err(other) => panic!("unexpected error {other}"),
            Ok(_) => panic!("a missing read-write path must refuse the jail"),
        }
        assert!(build_landlock(&spec_with(vec![demand], vec![missing]), &proc_self).is_ok(),
            "reachable read-write and missing optional read-only paths jail");
    }

    #[test]
    fn held_capabilities_ignores_the_bounding_set_only() {
        let zero = "0000000000000000";
        assert_eq!(held_capabilities(&status_with(zero, zero, zero)), Ok(()));
        // CAP_KILL (bit 5) left effective must refuse the jail.
        let err = held_capabilities(&status_with("0000000000000020", "0000000000000020", zero)).unwrap_err();
        assert!(err.contains("CapPrm=0000000000000020") && err.contains("CapEff=0000000000000020"), "{err}");
        assert!(held_capabilities(&status_with(zero, zero, "0000000000000020")).is_err());
        assert!(held_capabilities("Name:\tx\n").is_err(), "missing sets must fail closed");
    }

    fn socketpair(ty: libc::c_int) -> Result<(OwnedFd, OwnedFd), i32> {
        let mut fds = [0; 2];
        // SAFETY: fds is a valid two-element buffer.
        if unsafe { libc::socketpair(libc::AF_UNIX, ty | libc::SOCK_CLOEXEC, 0, fds.as_mut_ptr()) } != 0 {
            return Err(std::io::Error::last_os_error().raw_os_error().unwrap_or(0));
        }
        // SAFETY: socketpair returned two fresh fds we now own.
        Ok(unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) })
    }

    /// NAN-3567: under the tenant seccomp policy, nothing reaches another
    /// tenant's abstract unix socket. The harness plays tenant B (stream
    /// listener and datagram socket, both abstract); a jailed thread plays
    /// tenant A. Landlock scoping is absent on purpose: this is the 6.8
    /// kernel case, where seccomp is the only guard.
    #[test]
    fn seccomp_blocks_every_route_to_an_abstract_socket() {
        let tag = format!("nan3567-{}", std::process::id());
        let stream_name = SocketAddr::from_abstract_name(format!("{tag}-stream").as_bytes()).unwrap();
        let dgram_name = SocketAddr::from_abstract_name(format!("{tag}-dgram").as_bytes()).unwrap();
        let _listener = UnixListener::bind_addr(&stream_name).unwrap();
        let victim = UnixDatagram::bind_addr(&dgram_name).unwrap();
        victim.set_nonblocking(true).unwrap();
        // Control: the route exists without the filter.
        let (control, _) = UnixDatagram::pair().unwrap();
        control.send_to_addr(b"control", &dgram_name).unwrap();
        let mut buf = [0u8; 16];
        assert_eq!(victim.recv(&mut buf).unwrap(), 7);

        let squat = SocketAddr::from_abstract_name(format!("{tag}-squat").as_bytes()).unwrap();
        let s_name = stream_name.clone();
        let jailed_tag = tag.clone();
        std::thread::spawn(move || {
            // seccomp filters are per-thread without TSYNC: only this thread is jailed.
            // SAFETY: plain prctl on the calling thread.
            assert_eq!(unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) }, 0);
            for program in seccomp_filter().unwrap() {
                seccompiler::apply_filter(&program).unwrap();
            }
            let eperm = Some(libc::EPERM);
            assert_eq!(std::os::unix::net::UnixStream::connect_addr(&s_name).unwrap_err().raw_os_error(), eperm);
            assert_eq!(UnixDatagram::unbound().unwrap_err().raw_os_error(), eperm);
            assert_eq!(UnixDatagram::bind_addr(&squat).unwrap_err().raw_os_error(), eperm);
            // The bypass this fixes: an unnamed datagram pair sending to an
            // abstract address. Every non-connection socketpair type is denied.
            for ty in [libc::SOCK_DGRAM, libc::SOCK_RAW, libc::SOCK_RDM, 10 /* SOCK_PACKET */] {
                assert_eq!(socketpair(ty).unwrap_err(), libc::EPERM, "socketpair type {ty}");
                assert_eq!(socketpair(ty | libc::SOCK_NONBLOCK).unwrap_err(), libc::EPERM, "socketpair type {ty}|NONBLOCK");
            }
            // Connection pairs stay usable (tokio's signal driver) and cannot
            // be re-aimed at the abstract listener.
            for ty in [libc::SOCK_STREAM, libc::SOCK_SEQPACKET] {
                let (a, _b) = socketpair(ty).expect("connection socketpair stays allowed");
                let (addr, len) = abstract_sockaddr(&format!("{jailed_tag}-stream"));
                // SAFETY: valid fd and sockaddr_un.
                let rc = unsafe { libc::connect(std::os::fd::AsRawFd::as_raw_fd(&a), &addr as *const _ as *const libc::sockaddr, len) };
                // EISCONN (already connected) or ECONNREFUSED (type mismatch
                // with the stream listener): either way, no connection.
                let errno = std::io::Error::last_os_error().raw_os_error();
                assert_eq!(rc, -1, "type {ty} connected to the abstract listener");
                assert!(matches!(errno, Some(libc::EISCONN | libc::ECONNREFUSED)), "type {ty}: {errno:?}");
            }
        })
        .join()
        .unwrap();
        assert!(victim.recv(&mut buf).is_err(), "nothing reached tenant B's abstract datagram socket");
    }

    /// H02 CP24 P2-1: a native child gets no IP (or any) socket, while the
    /// shared tenant filter still allows AF_INET for TCP-port Landlock roles.
    #[test]
    fn native_seccomp_refuses_every_socket_family_including_inet() {
        let open = |family: libc::c_int, ty: libc::c_int| {
            // SAFETY: plain socket(2); a returned fd is closed below.
            let fd = unsafe { libc::socket(family, ty | libc::SOCK_CLOEXEC, 0) };
            if fd >= 0 {
                // SAFETY: fd was just returned by socket(2).
                unsafe { libc::close(fd) };
                Ok(())
            } else {
                Err(std::io::Error::last_os_error().raw_os_error())
            }
        };
        std::thread::spawn(move || {
            // SAFETY: plain prctl on the calling thread.
            assert_eq!(unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) }, 0);
            for program in seccomp_filter().unwrap() {
                seccompiler::apply_filter(&program).unwrap();
            }
            // Control: the shared filter leaves UDP/IP to Landlock (TCP only).
            assert_eq!(open(libc::AF_INET, libc::SOCK_DGRAM), Ok(()), "shared filter control");
        })
        .join()
        .unwrap();
        std::thread::spawn(move || {
            // SAFETY: plain prctl on the calling thread.
            assert_eq!(unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) }, 0);
            for program in native_seccomp_filter().unwrap() {
                seccompiler::apply_filter(&program).unwrap();
            }
            let eperm = Err(Some(libc::EPERM));
            for (family, ty) in [
                (libc::AF_INET, libc::SOCK_DGRAM),
                (libc::AF_INET, libc::SOCK_STREAM),
                (libc::AF_INET, libc::SOCK_RAW),
                (libc::AF_INET6, libc::SOCK_DGRAM),
                (libc::AF_INET6, libc::SOCK_STREAM),
                (libc::AF_UNIX, libc::SOCK_STREAM),
                (libc::AF_NETLINK, libc::SOCK_DGRAM),
                (libc::AF_PACKET, libc::SOCK_RAW),
            ] {
                assert_eq!(open(family, ty), eperm, "native socket({family}, {ty})");
            }
            // The supervisor-passed connection pair type stays usable.
            socketpair(libc::SOCK_STREAM).expect("stream socketpair stays allowed");
            assert_eq!(socketpair(libc::SOCK_DGRAM).unwrap_err(), libc::EPERM);
        })
        .join()
        .unwrap();
    }

    /// NAN-4545: an x32 syscall (`nr | 0x40000000`) must not slip past the
    /// per-number deny rules. EPERM from the x32 program, or ENOSYS on a
    /// kernel built without x32; never success.
    #[cfg(target_arch = "x86_64")]
    #[test]
    fn x32_abi_syscalls_cannot_bypass_the_deny_list() {
        const X32: libc::c_long = 0x4000_0000;
        let x32 = |nr: libc::c_long, a: libc::c_long, b: libc::c_long, c: libc::c_long| {
            // SAFETY: raw syscall with integer args; a returned fd is closed.
            let rc = unsafe { libc::syscall(X32 | nr, a, b, c) };
            let errno = std::io::Error::last_os_error().raw_os_error();
            if rc >= 0 && nr == libc::SYS_socket {
                // SAFETY: rc is a fresh fd.
                unsafe { libc::close(rc as libc::c_int) };
            }
            (rc, errno)
        };
        let refused = |(rc, errno): (libc::c_long, Option<i32>)| rc == -1 && matches!(errno, Some(libc::EPERM | libc::ENOSYS));
        // SAFETY: getpid takes no arguments.
        let x32_live = unsafe { libc::syscall(X32 | libc::SYS_getpid) } > 0;
        eprintln!("NAN-4545 x32 ABI live on this kernel: {x32_live}");
        if x32_live {
            // Control: the pre-NAN-4545 programs alone let the x32 socket through.
            std::thread::spawn(move || {
                // SAFETY: plain prctl on the calling thread.
                assert_eq!(unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) }, 0);
                for program in seccomp_filter().unwrap().into_iter().take(2) {
                    seccompiler::apply_filter(&program).unwrap();
                }
                let (rc, _) = x32(libc::SYS_socket, libc::AF_UNIX.into(), libc::SOCK_DGRAM.into(), 0);
                assert!(rc >= 0, "control: without the x32 program the bypass is real");
            })
            .join()
            .unwrap();
        }
        std::thread::spawn(move || {
            // SAFETY: plain prctl on the calling thread.
            assert_eq!(unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) }, 0);
            let programs = seccomp_filter().unwrap();
            assert_eq!(programs.len(), 3, "deny-list, clone3 and x32 programs");
            for program in programs {
                seccompiler::apply_filter(&program).unwrap();
            }
            // AF_UNIX is denied by the native rules, AF_INET goes to Landlock:
            // the x32 path must refuse both, plus a plain deny-list member.
            let socket_unix = x32(libc::SYS_socket, libc::AF_UNIX.into(), libc::SOCK_DGRAM.into(), 0);
            assert!(refused(socket_unix), "x32 socket(AF_UNIX): {socket_unix:?}");
            let socket_inet = x32(libc::SYS_socket, libc::AF_INET.into(), libc::SOCK_DGRAM.into(), 0);
            assert!(refused(socket_inet), "x32 socket(AF_INET): {socket_inet:?}");
            let unshare = x32(libc::SYS_unshare, libc::CLONE_NEWUSER.into(), 0, 0);
            assert!(refused(unshare), "x32 unshare(CLONE_NEWUSER): {unshare:?}");
            // The ordinary x86_64 numbers behave as before.
            // SAFETY: getpid takes no arguments.
            assert!(unsafe { libc::syscall(libc::SYS_getpid) } > 0);
            // SAFETY: raw socket syscall with integer args.
            assert_eq!(unsafe { libc::syscall(libc::SYS_socket, libc::AF_UNIX, libc::SOCK_DGRAM, 0) }, -1);
            assert_eq!(std::io::Error::last_os_error().raw_os_error(), Some(libc::EPERM));
        })
        .join()
        .unwrap();
        // H02 CP28: the native no-socket filter carries the same x32 program.
        std::thread::spawn(move || {
            // SAFETY: plain prctl on the calling thread.
            assert_eq!(unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) }, 0);
            let programs = native_seccomp_filter().unwrap();
            assert_eq!(programs.len(), 3, "native deny-list, clone3 and x32 programs");
            for program in programs {
                seccompiler::apply_filter(&program).unwrap();
            }
            for family in [libc::AF_UNIX, libc::AF_INET, libc::AF_INET6, libc::AF_NETLINK] {
                let socket = x32(libc::SYS_socket, family.into(), libc::SOCK_DGRAM.into(), 0);
                assert!(refused(socket), "native x32 socket({family}): {socket:?}");
            }
            let unshare = x32(libc::SYS_unshare, libc::CLONE_NEWUSER.into(), 0, 0);
            assert!(refused(unshare), "native x32 unshare(CLONE_NEWUSER): {unshare:?}");
        })
        .join()
        .unwrap();
    }

    fn abstract_sockaddr(name: &str) -> (libc::sockaddr_un, libc::socklen_t) {
        // SAFETY: zeroed sockaddr_un is valid.
        let mut a: libc::sockaddr_un = unsafe { std::mem::zeroed() };
        a.sun_family = libc::AF_UNIX as u16;
        for (i, b) in name.bytes().enumerate() {
            a.sun_path[i + 1] = b as libc::c_char;
        }
        (a, (std::mem::size_of::<libc::sa_family_t>() + 1 + name.len()) as libc::socklen_t)
    }
}
