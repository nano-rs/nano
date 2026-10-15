// SPDX-License-Identifier: AGPL-3.0-or-later

//! Per-tenant resource limits (NAN-2871, NAN-2872): the **delegated** cgroup
//! v2 mode, the policy that picks it, and the delegation check.
//!
//! Two layers, always both where the kernel allows:
//!
//! - **Delegated mode** (hard limits): the pod's own cgroup subtree is
//!   writable (a node-side delegator chowned it to the pod). The supervisor
//!   adopts it, as below, and the kernel enforces every tenant's guarantee
//!   and ceilings.
//! - **Watchdog** (`watchdog.rs`): always running. Without delegation it is
//!   the enforcement (the same guarantee/burst/ceiling semantics computed in
//!   userspace from `/proc`); with delegation it is the second layer and
//!   drives the dynamic parts (throttle under contention, `memory.high`
//!   pressure, victim selection by overage).
//!
//! Policy ([`select_mode`]): `auto` adopts delegation when the subtree is
//! delegated and runs watchdog-only otherwise, polling every 5 s and
//! adopting live once the delegator has handed the subtree over; `require`
//! refuses to start without delegation (the renderer sets it when the
//! delegator is present); `off` never touches cgroups.
//!
//! **Delegated but read-only** (the platform's delegator, NAN-2872): the
//! node-side delegator chowns only the cell container's own scope directory
//! and its `cgroup.procs`, `cgroup.threads` and `cgroup.subtree_control`
//! (the directory last, as the done signal), while the container still sees
//! `/sys/fs/cgroup` mounted read-only (EROFS whatever the owner). Ownership
//! by our euid is therefore delegation, and [`make_writable`] gets a
//! writable view with a private `cgroup2` mount at [`PRIVATE_CGROUP_MOUNT`]
//! (nosuid,nodev,noexec; in the pod's cgroup namespace its root is the
//! scope). That is the only method: a bind-remount of `/sys/fs/cgroup`
//! would make the tenants' view writable too (delegator review M4).
//!
//! **Tenant visibility** (delegator review M4): tenant cgroups are named by
//! uid **slot** (`tenants/s<slot>`), never by tenant id; each tenant process
//! gets its own cgroup namespace rooted at its role leaf (best effort), and
//! the jail's landlock grants it read access to its own leaf only, so it can
//! neither list nor read another tenant's cgroup. Tenants never own any
//! cgroup file (no sub-delegation); every limit file stays
//! supervisor-owned.
//!
//! **cgroup v2 layout** (under the cell container's cgroup root):
//!
//! ```text
//! <root>/                   subtree_control: +cpu +memory +pids [+io]
//!   init/                   the supervisor (no-internal-process rule)
//!   warm/                   unassigned warm-pool processes (small cap)
//!   limbo/                  frozen; only during a live adoption
//!   tenants/                cpu.weight 800
//!     s<slot>/              cpu.weight ∝ guarantee, cpu.max = burst ceiling,
//!                           cpu.max.burst, memory.low = guarantee,
//!                           memory.high = ceiling (lowered to ≤ soft under
//!                           memory contention), memory.max = hard ceiling,
//!                           pids.max, io.weight, io.max
//!       ingest/             memory.oom.group=1
//!       query/              memory.oom.group=1
//! ```
//!
//! A tenant's cgroup exists only while it has a process; the reaper removes
//! it, so an idle tenant has no kernel footprint either.

use crate::config::{CgroupPolicy, IoMaxRule};
use crate::contract::{Role, TenantId};
use crate::resources::{cpu_max_line, TenantLimits};
use serde::Serialize;
use std::io;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LimitsMode {
    /// Delegated cgroup v2 subtree: kernel limits + the watchdog.
    CgroupV2,
    /// Watchdog only (no delegation).
    Watchdog,
}

#[derive(Debug, Clone, Default, Serialize, PartialEq)]
pub struct TenantUsage {
    pub memory_bytes: u64,
    pub memory_peak_bytes: u64,
    pub cpu_usage_usec: u64,
    pub cpu_throttled_usec: u64,
    pub pids: u64,
    pub oom_kills: u64,
}

#[derive(Debug, Clone, Default, Serialize, PartialEq)]
pub struct RoleUsage {
    pub cpu_usage_usec: u64,
    pub cpu_throttled_usec: u64,
    pub nr_throttled: u64,
    pub memory_bytes: u64,
    pub oom_kills: u64,
}

// ------------------------------------------------------------------ delegation check + policy

/// Is the cell's cgroup subtree delegated to us? Read-only checks; the
/// probe's `--write` adds a real mkdir/rmdir.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DelegationCheck {
    pub unified: bool,
    /// The cell's cgroup directory (absolute).
    pub root: Option<PathBuf>,
    pub read_only_mount: bool,
    pub owner_uid: Option<u32>,
    /// `root`, `cgroup.procs` and `cgroup.subtree_control` are writable.
    pub writable: bool,
    /// The scope directory and its delegation files are owned by our euid
    /// (the delegator is done), writable or not through this mount.
    pub owned_by_us: bool,
    /// Delegated, but this mount is read-only: needs [`make_writable`].
    pub needs_mount: bool,
    pub controllers: Vec<String>,
    pub memory_controller: bool,
    /// Why it is not delegated (empty when it is).
    pub reasons: Vec<String>,
}

impl DelegationCheck {
    pub fn delegated(&self) -> bool {
        self.reasons.is_empty()
    }
}

/// The cell's cgroup (relative to the mount) from `/proc/self/cgroup`,
/// stripping our own `init` leaf (or the legacy `supervisor` one) after a
/// restart in place.
pub fn own_cgroup_rel(proc_self_cgroup: &str) -> Option<String> {
    let rel = proc_self_cgroup.lines().find_map(|l| l.strip_prefix("0::"))?.trim();
    let rel = rel.strip_suffix("/init").or_else(|| rel.strip_suffix("/supervisor")).unwrap_or(rel);
    Some(if rel.is_empty() { "/".to_owned() } else { rel.to_owned() })
}

fn access_w(p: &Path) -> bool {
    use std::os::unix::ffi::OsStrExt;
    let Ok(c) = std::ffi::CString::new(p.as_os_str().as_bytes()) else { return false };
    // SAFETY: access(2) on a valid C string.
    unsafe { libc::access(c.as_ptr(), libc::W_OK) == 0 }
}

fn mount_read_only(p: &Path) -> bool {
    use std::os::unix::ffi::OsStrExt;
    let Ok(c) = std::ffi::CString::new(p.as_os_str().as_bytes()) else { return true };
    // SAFETY: statvfs into a zeroed struct.
    unsafe {
        let mut s: libc::statvfs = std::mem::zeroed();
        libc::statvfs(c.as_ptr(), &mut s) == 0 && (s.f_flag & libc::ST_RDONLY) != 0
    }
}

/// Check `root` (the cell's cgroup directory).
pub fn check_delegation_at(root: &Path) -> DelegationCheck {
    use std::os::unix::fs::MetadataExt;
    let mut reasons = Vec::new();
    let unified = root.join("cgroup.controllers").exists();
    if !unified {
        reasons.push(format!("{} is not a cgroup v2 directory", root.display()));
    }
    let read_only_mount = mount_read_only(root);
    let owner_uid = std::fs::metadata(root).ok().map(|m| m.uid());
    let writable = !read_only_mount
        && [root.to_path_buf(), root.join("cgroup.procs"), root.join("cgroup.subtree_control")].iter().all(|p| access_w(p));
    // SAFETY: geteuid never fails.
    let euid = unsafe { libc::geteuid() };
    // The directory is chowned last (the delegator's done signal), so check
    // the files too; cgroup.threads may be absent on old kernels / fakes.
    let owned_by_us = unified
        && [root.to_path_buf(), root.join("cgroup.procs"), root.join("cgroup.subtree_control"), root.join("cgroup.threads")]
            .iter()
            .filter(|p| p.exists())
            .all(|p| std::fs::metadata(p).is_ok_and(|m| m.uid() == euid));
    if !writable && !owned_by_us {
        reasons.push(if read_only_mount {
            format!("cgroup mount is read-only and the scope is not delegated to us (owner uid {owner_uid:?})")
        } else {
            format!("cgroup not writable by us (owner uid {owner_uid:?})")
        });
    }
    let needs_mount = !writable && owned_by_us;
    let controllers: Vec<String> = std::fs::read_to_string(root.join("cgroup.controllers"))
        .map(|s| s.split_whitespace().map(str::to_owned).collect())
        .unwrap_or_default();
    let memory_controller = controllers.iter().any(|c| c == "memory");
    if unified {
        for controller in REQUIRED_CONTROLLERS {
            if !controllers.iter().any(|c| c == controller) {
                reasons.push(format!("{controller} controller not available"));
            }
        }
    }
    DelegationCheck {
        unified,
        root: Some(root.to_path_buf()),
        read_only_mount,
        owner_uid,
        writable,
        owned_by_us,
        needs_mount,
        controllers,
        memory_controller,
        reasons,
    }
}

/// Check the calling process's cgroup under `mount`.
pub fn check_delegation(mount: &Path) -> DelegationCheck {
    match std::fs::read_to_string("/proc/self/cgroup").ok().as_deref().and_then(own_cgroup_rel) {
        Some(rel) => check_delegation_at(&mount.join(rel.trim_start_matches('/'))),
        None => DelegationCheck {
            unified: false,
            root: None,
            read_only_mount: false,
            owner_uid: None,
            writable: false,
            owned_by_us: false,
            needs_mount: false,
            controllers: vec![],
            memory_controller: false,
            reasons: vec!["not on the cgroup v2 unified hierarchy".into()],
        },
    }
}

/// The limits mode for `policy` given the delegation check, or why the cell
/// must not start.
pub fn select_mode(policy: CgroupPolicy, check: &DelegationCheck) -> Result<LimitsMode, String> {
    match (policy, check.delegated()) {
        (CgroupPolicy::Off, _) => Ok(LimitsMode::Watchdog),
        (_, true) => Ok(LimitsMode::CgroupV2),
        (CgroupPolicy::Auto, false) => Ok(LimitsMode::Watchdog),
        (CgroupPolicy::Require, false) => {
            Err(format!("cgroup delegation required but not available: {}", check.reasons.join("; ")))
        }
    }
}

/// What actually enforces tenant limits right now (NAN-2993). Reported on
/// `/healthz`, `/v1/status`, `/metrics` and as the `limits_unenforced`
/// signal, so a cell running without kernel limits is never silent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Enforcement {
    /// Kernel cgroup limits per tenant **and per role** (`cpu.max`,
    /// `memory.max`/`high`/`low`, `pids.max`, `memory.oom.group`); the
    /// watchdog is the second layer.
    Kernel,
    /// The userspace watchdog only. Per **tenant** (the sum of its roles):
    /// CPU ceiling/contention throttle by SIGSTOP/SIGCONT duty cycling,
    /// SIGKILL at the hard memory ceiling / cell memory critical, pids kill.
    /// **Not** enforced: any per-role limit (query and ingest share the
    /// tenant sum), memory guarantees (`memory.low`), reclaim pressure
    /// (`memory.high`), kernel OOM isolation, io limits; and nothing faster
    /// than the 1 s sampler (a spike can OOM the whole pod first).
    WatchdogOnly,
}

impl Enforcement {
    pub fn as_str(self) -> &'static str {
        match self {
            Enforcement::Kernel => "kernel",
            Enforcement::WatchdogOnly => "watchdog_only",
        }
    }
}

/// Kernel limits apply only while an adopted tree is still delegated to us.
pub fn enforcement(mode: LimitsMode, withdrawn: bool) -> Enforcement {
    match (mode, withdrawn) {
        (LimitsMode::CgroupV2, false) => Enforcement::Kernel,
        _ => Enforcement::WatchdogOnly,
    }
}

/// Why limits are not kernel-enforced (`None` when they are).
pub fn enforcement_reason(policy: CgroupPolicy, e: Enforcement, withdrawn: bool, reasons: &[String]) -> Option<String> {
    match (e, policy) {
        (Enforcement::Kernel, _) => None,
        (_, CgroupPolicy::Off) => Some("isolation.cgroup is \"off\": watchdog only by configuration".into()),
        _ if withdrawn => Some("the delegator took the cell's cgroup scope back".into()),
        _ if reasons.is_empty() => Some("cgroup delegation not adopted yet".into()),
        _ => Some(format!("no cgroup delegation: {}", reasons.join("; "))),
    }
}

/// Whether the cell starts new tenant processes (NAN-3523). Reported on
/// `/healthz`, `/v1/status`, `/metrics` and as the paging
/// `pooled_admission_refused` signal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Admission {
    /// Tenant processes start on demand.
    Open,
    /// A pooled cell without kernel limits: no new tenant process starts
    /// (retryable 503; running ones keep serving) until delegation is
    /// adopted, because one tenant's memory burst faster than the watchdog
    /// poll would OOM the pod and every tenant on it.
    RefusedUnenforced,
}

impl Admission {
    pub fn as_str(self) -> &'static str {
        match self {
            Admission::Open => "open",
            Admission::RefusedUnenforced => "refused_unenforced",
        }
    }
}

/// Since when admission has been refused, continuously (NAN-3523): the
/// `pooled_admission_refused` page waits [`crate::signals::POOLED_ADMISSION_REFUSED_PAGE`]
/// so a boot race or a delegator restart does not page. Reopening resets it.
#[derive(Debug, Default)]
pub struct RefusalClock {
    since: Option<std::time::Instant>,
}

impl RefusalClock {
    /// Record the state at `now`; how long the refusal has lasted (`None`
    /// while admission is open).
    pub fn observe(&mut self, now: std::time::Instant, a: Admission) -> Option<std::time::Duration> {
        if a == Admission::Open {
            self.since = None;
            return None;
        }
        Some(now.saturating_duration_since(*self.since.get_or_insert(now)))
    }
}

/// Pooled cells fail closed without kernel limits (NAN-3523). A dedicated
/// cell's blast radius is its one tenant, so it stays open on the watchdog;
/// `allow_pooled_watchdog_only` (dev/test opt-out) keeps a pooled one open.
pub fn admission(mode: crate::config::CellMode, e: Enforcement, allow_pooled_watchdog_only: bool) -> Admission {
    match (mode, e) {
        (crate::config::CellMode::Pooled, Enforcement::WatchdogOnly) if !allow_pooled_watchdog_only => Admission::RefusedUnenforced,
        _ => Admission::Open,
    }
}

// ------------------------------------------------------------------ getting a writable view

/// Where the supervisor mounts its private writable cgroup2 view. The pod
/// should mount an emptyDir at `/run/nano-cell-supervisor` (read-only root
/// filesystem); without one the bind-remount fallback is tried.
pub const PRIVATE_CGROUP_MOUNT: &str = "/run/nano-cell-supervisor/cgroup";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MountMethod {
    /// The cgroup mount was writable already (privileged, sandbox).
    AlreadyWritable,
    /// A private `cgroup2` mount at [`PRIVATE_CGROUP_MOUNT`].
    PrivateMount,
}

/// The mount syscalls, behind a trait so the selection logic is testable.
pub trait Mounter {
    fn mount_private(&self, target: &Path) -> io::Result<()>;
    fn unmount(&self, target: &Path) -> io::Result<()>;
}

/// The real syscalls.
pub struct SysMounter;

fn cstr(p: &Path) -> io::Result<std::ffi::CString> {
    use std::os::unix::ffi::OsStrExt;
    std::ffi::CString::new(p.as_os_str().as_bytes()).map_err(io::Error::other)
}

impl Mounter for SysMounter {
    fn mount_private(&self, target: &Path) -> io::Result<()> {
        std::fs::create_dir_all(target)?;
        let t = cstr(target)?;
        // SAFETY: mount(2) with valid C strings and a null data pointer.
        let rc = unsafe {
            libc::mount(
                c"cgroup2".as_ptr(),
                t.as_ptr(),
                c"cgroup2".as_ptr(),
                libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC,
                std::ptr::null(),
            )
        };
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    fn unmount(&self, target: &Path) -> io::Result<()> {
        let t = cstr(target)?;
        // SAFETY: umount2 on a path.
        if unsafe { libc::umount2(t.as_ptr(), libc::MNT_DETACH) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
}

const CGROUP2_SUPER_MAGIC: i64 = 0x6367_7270;

/// Is `p` the root of a cgroup2 mount? (A plain directory that merely
/// contains a `cgroup.controllers` file is not.)
pub fn is_cgroup2(p: &Path) -> bool {
    let Ok(c) = cstr(p) else { return false };
    // SAFETY: statfs into a zeroed struct.
    unsafe {
        let mut s: libc::statfs = std::mem::zeroed();
        libc::statfs(c.as_ptr(), &mut s) == 0 && s.f_type as i64 == CGROUP2_SUPER_MAGIC
    }
}

/// A writable view of the delegated cgroup hierarchy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct WritableMount {
    /// The cgroup2 mount point to adopt under.
    pub mount: PathBuf,
    pub method: MountMethod,
}

/// Both mount attempts, for the probe.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct MountAttempts {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub private_mount: Option<String>,
}

/// Get a writable view of the (delegated) cgroup at `mount`: as is if
/// writable, else a private cgroup2 mount at `private` (the only method).
/// `attempts` records the outcome ("ok" or the error).
pub fn make_writable(
    check: &DelegationCheck,
    mount: &Path,
    private: &Path,
    m: &dyn Mounter,
    attempts: &mut MountAttempts,
) -> Result<WritableMount, String> {
    if check.writable {
        return Ok(WritableMount { mount: mount.to_path_buf(), method: MountMethod::AlreadyWritable });
    }
    if !check.owned_by_us {
        return Err(format!("not delegated: {}", check.reasons.join("; ")));
    }
    // A previous attempt in this mount namespace may have left it mounted.
    let reuse = is_cgroup2(private) && !mount_read_only(private);
    match if reuse { Ok(()) } else { m.mount_private(private) } {
        Ok(()) => {
            attempts.private_mount = Some("ok".into());
            return Ok(WritableMount { mount: private.to_path_buf(), method: MountMethod::PrivateMount });
        }
        Err(e) => attempts.private_mount = Some(format!("{}: {e}", private.display())),
    }
    Err(format!(
        "delegated but no writable view: private cgroup2 mount at {} failed: {}",
        private.display(),
        attempts.private_mount.as_deref().unwrap_or("-")
    ))
}

/// The probe's `--write` proof: get the writable view the supervisor would
/// use, create and remove an empty child cgroup under our cgroup (`rel`),
/// and unmount a private mount made just for the proof. Returns (mkdir
/// worked, attempts, method).
pub fn prove_writable(
    check: &DelegationCheck,
    mount: &Path,
    private: &Path,
    rel: &str,
    m: &dyn Mounter,
) -> (bool, MountAttempts, Option<MountMethod>) {
    let mut attempts = MountAttempts::default();
    let was_mounted = is_cgroup2(private);
    let Ok(wm) = make_writable(check, mount, private, m, &mut attempts) else {
        return (false, attempts, None);
    };
    let d = wm.mount.join(rel.trim_start_matches('/')).join(format!("nano-cell-probe-{}", std::process::id()));
    let ok = std::fs::create_dir(&d).is_ok();
    let _ = std::fs::remove_dir(&d);
    if wm.method == MountMethod::PrivateMount && !was_mounted {
        let _ = m.unmount(private);
    }
    (ok, attempts, Some(wm.method))
}

/// Where a stray process (in `limbo/`, `init/` or `warm/`) belongs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SweepTarget {
    /// Runs as a tenant uid: that tenant's role cgroup.
    Tenant(TenantId, Role),
    /// A supervisor child that is not (yet) a tenant: warm pool.
    Warm,
    /// Neither the supervisor, a supervisor child nor a tenant process.
    Kill,
}

/// A process seen in a cgroup: (pid, uid, ppid).
pub type Stray = (u32, u32, u32);

/// Classify one stray process. `None` = it is the supervisor (stays).
pub fn classify(
    (pid, uid, ppid): Stray,
    self_pid: u32,
    uid_owner: &std::collections::HashMap<u32, (TenantId, Role)>,
    warm: &[u32],
) -> Option<SweepTarget> {
    if pid == self_pid {
        return None;
    }
    Some(match uid_owner.get(&uid) {
        Some((t, r)) => SweepTarget::Tenant(t.clone(), *r),
        None if warm.contains(&pid) || ppid == self_pid => SweepTarget::Warm,
        None => SweepTarget::Kill,
    })
}

/// Plan the moves for strays: every process running as a tenant uid goes
/// to that tenant's role cgroup (including children a tenant forked), warm
/// and other supervisor children to `warm/`, anything else is killed.
pub fn plan_sweep(
    procs: &[Stray],
    self_pid: u32,
    uid_owner: &std::collections::HashMap<u32, (TenantId, Role)>,
    warm: &[u32],
) -> Vec<(u32, SweepTarget)> {
    procs.iter().filter_map(|p| classify(*p, self_pid, uid_owner, warm).map(|t| (p.0, t))).collect()
}

/// Assigned processes that are not in their own role's leaf, to be moved
/// there (NAN-3720). `assigned` is `(pid, role)` per live tenant process;
/// `in_leaf(role)` lists the pids in that role's leaf.
///
/// The uid sweep (`plan_sweep`) can only tell a uid's primary role. Product
/// runs as query's uid, so a product process swept before the supervisor
/// recorded its assignment (spawned just before a live adoption, picked up
/// from `warm/` by the next tick) landed in query's leaf for good: the
/// background state builder then shared interactive search's CPU quota and
/// memory ceiling. Re-homing every tick makes any such placement self-heal.
pub fn plan_rehome(assigned: &[(u32, Role)], in_leaf: impl Fn(Role) -> Vec<u32>) -> Vec<(u32, Role)> {
    let mut leaves: std::collections::HashMap<Role, Vec<u32>> = std::collections::HashMap::new();
    assigned
        .iter()
        .filter(|(pid, role)| !leaves.entry(*role).or_insert_with(|| in_leaf(*role)).contains(pid))
        .copied()
        .collect()
}

// ------------------------------------------------------------------ the delegated tree

/// A delegated cgroup v2 subtree the supervisor owns.
#[derive(Debug, Clone)]
pub struct CgroupTree {
    /// Tenant → uid slot: cgroups are named `s<slot>`, never by tenant id.
    slots: std::sync::Arc<std::sync::RwLock<std::collections::HashMap<TenantId, u32>>>,
    /// Absolute path of the delegated root (e.g. `/sys/fs/cgroup` in a pod
    /// with its own cgroup namespace).
    root: PathBuf,
    /// Path of `root` relative to the cgroup2 mount (for landlock rules).
    rel_root: PathBuf,
    controllers: Vec<String>,
    io_max: Vec<IoMaxRule>,
    /// Why `data_volume` io.max rules are not applied (NAN-3523), if asked
    /// for and unresolvable; surfaced as the `io_max_unresolved` signal.
    io_max_unresolved: Option<String>,
    cpu_max_burst: bool,
}

/// `st_dev` → (major, minor), glibc's `gnu_dev_major` / `gnu_dev_minor`.
pub fn dev_major_minor(dev: u64) -> (u64, u64) {
    let major = ((dev >> 8) & 0xfff) | ((dev >> 32) & 0xffff_f000);
    let minor = (dev & 0xff) | ((dev >> 12) & 0xffff_ff00);
    (major, minor)
}

fn read_dev_file(dir: &Path) -> Result<String, String> {
    let raw = std::fs::read_to_string(dir.join("dev")).map_err(|e| format!("read {}/dev: {e}", dir.display()))?;
    let dev = raw.trim();
    let num = |p: &str| !p.is_empty() && p.len() <= 10 && p.bytes().all(|b| b.is_ascii_digit());
    match dev.split_once(':') {
        Some((a, b)) if num(a) && num(b) => Ok(dev.to_owned()),
        _ => Err(format!("{}/dev is not MAJ:MIN: {dev:?}", dir.display())),
    }
}

/// The whole-disk `MAJ:MIN` for block device `major:minor`, via
/// `<sys_root>/dev/block/MAJ:MIN` (io.max rejects partitions: a partition's
/// sysfs dir sits inside its disk's and has a `partition` file).
pub fn whole_disk_device(sys_root: &Path, major: u64, minor: u64) -> Result<String, String> {
    if major == 0 {
        // Anonymous device: overlayfs, tmpfs (emptyDir medium Memory), NFS…
        return Err(format!("{major}:{minor} is not a block device (overlay/tmpfs/network filesystem)"));
    }
    let link = sys_root.join("dev/block").join(format!("{major}:{minor}"));
    let dir = std::fs::canonicalize(&link).map_err(|e| format!("block device {major}:{minor} not in sysfs ({}): {e}", link.display()))?;
    if dir.join("partition").exists() {
        let disk = dir.parent().ok_or_else(|| format!("partition {} has no parent disk", dir.display()))?;
        read_dev_file(disk)
    } else {
        read_dev_file(&dir)
    }
}

/// The whole disk holding `data_dir` (`stat(data_dir).st_dev`), as `MAJ:MIN`.
pub fn resolve_data_volume_device(data_dir: &Path, sys_root: &Path) -> Result<String, String> {
    use std::os::unix::fs::MetadataExt;
    let dev = std::fs::metadata(data_dir).map_err(|e| format!("stat {}: {e}", data_dir.display()))?.dev();
    let (major, minor) = dev_major_minor(dev);
    whole_disk_device(sys_root, major, minor)
}

const WANTED: [&str; 4] = ["cpu", "memory", "pids", "io"];
/// What `require` insists on.
pub const REQUIRED_CONTROLLERS: [&str; 3] = ["cpu", "memory", "pids"];

/// `init/` `cpu.weight` (tenants/ 800, warm/ 25).
pub const INIT_CPU_WEIGHT: u32 = 200;
/// `init/` `memory.min` never exceeds this fraction of the cell's memory.
pub const INIT_MEMORY_MIN_DIVISOR: u64 = 16;

/// The supervisor's `memory.min`: the configured value, at most 1/16 of the
/// cell (256 MiB needs a ≥ 4 GiB cell).
pub fn init_memory_min(min_bytes: u64, cell_memory_bytes: u64) -> u64 {
    min_bytes.min(cell_memory_bytes / INIT_MEMORY_MIN_DIVISOR)
}

fn write(path: &Path, value: &str) -> io::Result<()> {
    std::fs::write(path, value).map_err(|e| io::Error::new(e.kind(), format!("write {}: {e}", path.display())))
}

pub(crate) fn read_kv(path: &Path, key: &str) -> Option<u64> {
    std::fs::read_to_string(path).ok()?.lines().find_map(|l| {
        let mut it = l.split_whitespace();
        (it.next() == Some(key)).then(|| it.next()?.parse().ok()).flatten()
    })
}

fn read_u64(path: &Path) -> Option<u64> {
    std::fs::read_to_string(path).ok()?.trim().parse().ok()
}

/// Write `cpu.max` = `line` into `dir`, and with `burst` also
/// `cpu.max.burst` = its quota. The kernel rejects (EINVAL) a `cpu.max`
/// quota below the current `cpu.max.burst` and a burst above the current
/// quota (NAN-3842), so a shrinking ceiling lowers the burst first; a
/// growing one raises `cpu.max` first. A kernel without `cpu.max.burst`
/// (unreadable or unwritable file) only gets `cpu.max`.
fn apply_cpu_max(dir: &Path, line: &str, burst: bool, w: &mut dyn FnMut(&Path, &str) -> io::Result<()>) -> io::Result<()> {
    let burst_path = dir.join("cpu.max.burst");
    let quota = line.split_whitespace().next().unwrap_or("0");
    if burst {
        if let (Some(cur), Ok(q)) = (read_u64(&burst_path), quota.parse::<u64>()) {
            if cur > q {
                w(&burst_path, quota)?;
            }
        }
    }
    w(&dir.join("cpu.max"), line)?;
    if burst {
        if let Err(e) = w(&burst_path, quota) {
            tracing::debug!(error = %e, "cpu.max.burst not supported");
        }
    }
    Ok(())
}

impl CgroupTree {
    /// Apply a [`plan_sweep`] plan (tenant cgroups must exist: see
    /// [`CgroupTree::ensure_tenant`]). Returns how many were moved; a
    /// process that exited meanwhile is skipped.
    /// Returns (moved, pids to kill); the caller kills (start-time
    /// verified) the latter.
    pub fn apply_sweep(&self, plan: &[(u32, SweepTarget)]) -> (usize, Vec<u32>) {
        let mut moved = 0;
        let mut kill = Vec::new();
        for (pid, target) in plan {
            let ok = match target {
                SweepTarget::Tenant(t, r) => self.place(*pid, t, *r).is_ok(),
                SweepTarget::Warm => self.place_warm(*pid).is_ok(),
                SweepTarget::Kill => {
                    kill.push(*pid);
                    false
                }
            };
            moved += ok as usize;
        }
        (moved, kill)
    }

    /// Adopt the calling process's cgroup under `mount` as the cell root.
    pub fn adopt(mount: &Path, io_max: Vec<IoMaxRule>, cpu_max_burst: bool, strict: bool) -> io::Result<Self> {
        let own = std::fs::read_to_string("/proc/self/cgroup")?;
        let rel = own_cgroup_rel(&own).ok_or_else(|| io::Error::other("not on the cgroup v2 unified hierarchy"))?;
        let root = mount.join(rel.trim_start_matches('/'));
        let tree = Self::adopt_root(root, PathBuf::from(rel), io_max, cpu_max_burst)?;
        if strict {
            tree.require_controllers()?;
        }
        Ok(tree)
    }

    /// `require` mode: cpu, memory and pids must all be available and
    /// enabled for tenants (a limit that silently does not apply is not a
    /// hard limit).
    pub fn require_controllers(&self) -> io::Result<()> {
        let enabled = std::fs::read_to_string(self.root.join("tenants/cgroup.subtree_control")).unwrap_or_default();
        let missing: Vec<&str> = REQUIRED_CONTROLLERS
            .iter()
            .filter(|c| !self.has(c) || !enabled.split_whitespace().any(|e| e.trim_start_matches('+') == **c))
            .copied()
            .collect();
        if missing.is_empty() {
            Ok(())
        } else {
            Err(io::Error::other(format!("required cgroup controllers not available/enabled: {}", missing.join(", "))))
        }
    }

    /// SIGKILL every process in the tenant's role cgroup (`cgroup.kill`).
    pub fn kill_role(&self, t: &TenantId, role: Role) -> io::Result<()> {
        let leaf = self.tenant_dir(t).join(role.as_str());
        if !leaf.exists() {
            return Ok(());
        }
        write(&leaf.join("cgroup.kill"), "1")
    }

    /// Take ownership of `root`: move every process in it (the supervisor)
    /// into `init/`, enable the controllers we want that are available, and
    /// create `warm/` and `tenants/`. Fails if the subtree is not delegated
    /// to us (read-only mount, EACCES, …).
    pub fn adopt_root(root: PathBuf, rel_root: PathBuf, io_max: Vec<IoMaxRule>, cpu_max_burst: bool) -> io::Result<Self> {
        Self::adopt_root_as(root, rel_root, io_max, cpu_max_burst, std::process::id())
    }

    /// [`CgroupTree::adopt_root`] with the supervisor's pid given (tests).
    ///
    /// Only the supervisor goes to `init/`. Every other process in the root
    /// (a live adoption finds tenant and warm processes there) goes into a
    /// **frozen** `limbo/`, so nothing can fork or run unlimited while the
    /// caller sorts them into their cgroups ([`CgroupTree::limbo_pids`],
    /// [`CgroupTree::remove_limbo`]).
    pub fn adopt_root_as(
        root: PathBuf,
        rel_root: PathBuf,
        io_max: Vec<IoMaxRule>,
        cpu_max_burst: bool,
        self_pid: u32,
    ) -> io::Result<Self> {
        let available = std::fs::read_to_string(root.join("cgroup.controllers"))?;
        let controllers: Vec<String> =
            WANTED.iter().filter(|c| available.split_whitespace().any(|a| a == **c)).map(|c| c.to_string()).collect();
        if !controllers.iter().any(|c| c == "memory") {
            return Err(io::Error::other("memory controller not available in the delegated cgroup"));
        }
        let init = root.join("init");
        let limbo = root.join("limbo");
        for d in [&init, &limbo] {
            if !d.exists() {
                std::fs::create_dir(d)?;
            }
        }
        // Frozen before anything enters: a process moved in stops at once.
        write(&limbo.join("cgroup.freeze"), "1")?;
        write(&init.join("cgroup.procs"), &self_pid.to_string())?;
        // Empty the root (no internal processes, so it may enable
        // controllers). Repeat: a process still in the root can fork a
        // child into it until it is itself frozen in limbo.
        let mut moved = std::collections::HashSet::new();
        for _ in 0..16 {
            let procs = std::fs::read_to_string(root.join("cgroup.procs"))?;
            let fresh: Vec<&str> = procs.split_whitespace().filter(|p| moved.insert(p.to_string())).collect();
            if fresh.is_empty() {
                break;
            }
            for pid in fresh {
                let target = if pid == self_pid.to_string() { &init } else { &limbo };
                // A process that exited meanwhile is fine.
                let _ = write(&target.join("cgroup.procs"), pid);
            }
        }
        let tree = Self { slots: Default::default(), root, rel_root, controllers, io_max, io_max_unresolved: None, cpu_max_burst };
        tree.enable_controllers(&tree.root)?;
        for d in ["warm", "tenants"] {
            let p = tree.root.join(d);
            if !p.exists() {
                std::fs::create_dir(&p)?;
            }
        }
        if tree.has("cpu") {
            // Tenants as a group outweigh the supervisor and the warm pool
            // under contention; the supervisor is light but must not starve.
            // NAN-3523: init/ at 200 (was 100), ~19% of the CPU under full
            // contention instead of ~11%. The router proxies every query
            // byte and the watchdog tick must keep running while tenants
            // burst; weights are work-conserving, so tenants lose nothing
            // while the supervisor is idle.
            let _ = write(&tree.root.join("tenants/cpu.weight"), "800");
            let _ = write(&init.join("cpu.weight"), &INIT_CPU_WEIGHT.to_string());
            let _ = write(&tree.root.join("warm/cpu.weight"), "25");
        }
        tree.enable_controllers(&tree.root.join("tenants"))?;
        Ok(tree)
    }

    /// Resolve `data_volume` io.max rules to the whole disk under
    /// `data_dir` (NAN-3523). Never fails the cell: an unresolvable device
    /// (or no `io` controller) drops those rules with a WARN and is kept
    /// for the `io_max_unresolved` signal.
    pub fn resolve_io_max_data_volume(&mut self, data_dir: &Path, sys_root: &Path) {
        if !self.io_max.iter().any(IoMaxRule::is_data_volume) {
            return;
        }
        let resolved = resolve_data_volume_device(data_dir, sys_root);
        self.apply_data_volume_device(data_dir, resolved);
    }

    fn apply_data_volume_device(&mut self, data_dir: &Path, resolved: Result<String, String>) {
        let resolved = if self.has("io") { resolved } else { Err("io controller not delegated".to_owned()) };
        match resolved {
            Ok(device) => {
                tracing::info!(data_dir = %data_dir.display(), %device, "io.max data_volume rules resolved");
                for rule in self.io_max.iter_mut().filter(|r| r.is_data_volume()) {
                    rule.device = device.clone();
                }
                self.io_max_unresolved = None;
            }
            Err(reason) => {
                tracing::warn!(data_dir = %data_dir.display(), %reason,
                    "io_max_unresolved: data_volume io.max rules not applied; tenant disk bandwidth is unlimited");
                self.io_max.retain(|r| !r.is_data_volume());
                self.io_max_unresolved = Some(reason);
            }
        }
    }

    /// Why requested `data_volume` io.max rules are not applied.
    pub fn io_max_unresolved(&self) -> Option<&str> {
        self.io_max_unresolved.as_deref()
    }

    /// The io.max rules applied to every tenant cgroup.
    pub fn io_max(&self) -> &[IoMaxRule] {
        &self.io_max
    }

    fn has(&self, c: &str) -> bool {
        self.controllers.iter().any(|x| x == c)
    }

    fn pids_in(&self, dir: &str) -> Vec<u32> {
        std::fs::read_to_string(self.root.join(dir).join("cgroup.procs"))
            .unwrap_or_default()
            .split_whitespace()
            .filter_map(|p| p.parse().ok())
            .collect()
    }

    /// Processes still frozen in `limbo/` (a live adoption's leftovers).
    pub fn limbo_pids(&self) -> Vec<u32> {
        self.pids_in("limbo")
    }

    /// Processes in `init/` (should be the supervisor only).
    pub fn init_pids(&self) -> Vec<u32> {
        self.pids_in("init")
    }

    /// Processes in `warm/`.
    pub fn warm_pids(&self) -> Vec<u32> {
        self.pids_in("warm")
    }

    /// Processes in `t`'s `role` leaf (none for an unregistered tenant).
    pub fn role_pids(&self, t: &TenantId, role: Role) -> Vec<u32> {
        let Some(name) = self.name(t) else { return Vec::new() };
        self.pids_in(&format!("tenants/{name}/{}", role.as_str()))
    }

    /// Kill whatever is still in `limbo/` and remove it. Returns how many
    /// processes it had to kill (should be 0: the caller sorted them out).
    pub fn remove_limbo(&self) -> io::Result<usize> {
        let limbo = self.root.join("limbo");
        if !limbo.exists() {
            return Ok(0);
        }
        let left = self.limbo_pids().len();
        if left > 0 {
            write(&limbo.join("cgroup.kill"), "1")?;
            // Killed processes leave the cgroup asynchronously.
            for _ in 0..50 {
                if self.limbo_pids().is_empty() {
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(20));
            }
        }
        std::fs::remove_dir(&limbo)?;
        Ok(left)
    }

    /// Move `pid` to `warm/`.
    pub fn move_to_warm(&self, pid: u32) -> io::Result<()> {
        self.place_warm(pid)
    }

    /// Is the scope still ours (the delegator may withdraw it)?
    pub fn still_delegated(&self) -> bool {
        use std::os::unix::fs::MetadataExt;
        // SAFETY: geteuid never fails.
        let euid = unsafe { libc::geteuid() };
        [self.root.clone(), self.root.join("cgroup.procs"), self.root.join("cgroup.subtree_control")]
            .iter()
            .all(|p| std::fs::metadata(p).is_ok_and(|m| m.uid() == euid) && access_w(p))
    }

    fn enable_controllers(&self, dir: &Path) -> io::Result<()> {
        let all: Vec<String> = self.controllers.iter().map(|c| format!("+{c}")).collect();
        // One write first; if the kernel refuses one (io without a
        // scheduler), fall back to one by one so the rest still apply.
        if write(&dir.join("cgroup.subtree_control"), &all.join(" ")).is_ok() {
            return Ok(());
        }
        for c in all {
            if let Err(e) = write(&dir.join("cgroup.subtree_control"), &c) {
                if c == "+memory" {
                    return Err(e);
                }
                tracing::warn!(dir = %dir.display(), controller = %c, error = %e, "cgroup controller not enabled");
            }
        }
        Ok(())
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn controllers(&self) -> &[String] {
        &self.controllers
    }

    pub fn warm_dir(&self) -> PathBuf {
        self.root.join("warm")
    }

    /// NAN-3523: reserve memory for the supervisor. `memory.min` on `init/`
    /// (a direct child of the container cgroup, so it holds when the
    /// container limit is the reclaim root) keeps its working set out of
    /// reclaim during a tenant burst. Returns the bytes written: `min_bytes`
    /// capped at `cell_memory_bytes / INIT_MEMORY_MIN_DIVISOR`.
    pub fn reserve_init(&self, min_bytes: u64, cell_memory_bytes: u64) -> io::Result<u64> {
        let bytes = init_memory_min(min_bytes, cell_memory_bytes);
        if self.has("memory") {
            write(&self.root.join("init/memory.min"), &bytes.to_string())?;
        }
        Ok(bytes)
    }

    /// Name `t`'s cgroup after its uid slot. Must be called before any other
    /// per-tenant call (an unregistered tenant has no cgroup).
    pub fn register(&self, t: &TenantId, slot: u32) {
        self.slots.write().unwrap().insert(t.clone(), slot);
    }

    fn name(&self, t: &TenantId) -> Option<String> {
        self.slots.read().unwrap().get(t).map(|s| format!("s{s}"))
    }

    /// `tenants/s<slot>`; an unregistered tenant maps to a path that is
    /// never created (every writer refuses it).
    pub fn tenant_dir(&self, t: &TenantId) -> PathBuf {
        self.root.join("tenants").join(self.name(t).unwrap_or_else(|| ".unregistered".into()))
    }

    /// The role leaf, relative to the cgroup2 mount (for the jail).
    pub fn role_rel(&self, t: &TenantId, role: Role) -> PathBuf {
        self.rel_root.join("tenants").join(self.name(t).unwrap_or_else(|| ".unregistered".into())).join(role.as_str())
    }

    /// Create (or update) the tenant's cgroup with `l`'s guarantee and
    /// ceilings. `cpu.max` and `memory.high` are controller-owned (the
    /// watchdog applies the desired throttle / pressure every tick): they are
    /// initialised only when the cgroup is created, never overwritten here.
    pub fn ensure_tenant(&self, t: &TenantId, slot: u32, l: &TenantLimits) -> io::Result<()> {
        match self.slots.read().unwrap().get(t) {
            Some(s) if *s != slot => {
                return Err(io::Error::other(format!("tenant {t} is registered as slot {s}, not {slot}")));
            }
            _ => {}
        }
        self.register(t, slot);
        let dir = self.tenant_dir(t);
        let fresh = !dir.exists();
        if fresh {
            std::fs::create_dir(&dir)?;
        }
        // Order: raise max before high before low, so no intermediate state
        // has low > high or high > max rejected or OOMing.
        write(&dir.join("memory.max"), &l.memory_hard_bytes.to_string())?;
        // memory.high rests at the ceiling (no throttling while the cell
        // has headroom: burst is allowed). The watchdog lowers it toward
        // the soft limit only under memory contention. A static
        // memory.high = soft, with no swap, stalls an allocating tenant for
        // minutes instead of letting it burst or OOM (measured: 900 MiB
        // against high 512 / max 640 MiB wedged > 10 min).
        if fresh {
            write(&dir.join("memory.high"), &l.memory_hard_bytes.to_string())?;
        }
        write(&dir.join("memory.low"), &l.memory_guarantee_bytes.to_string())?;
        // No swap: a tenant at its ceiling hits its own OOM instead of
        // slowing the node down.
        let _ = write(&dir.join("memory.swap.max"), "0");
        if self.has("cpu") {
            write(&dir.join("cpu.weight"), &l.cpu_weight.to_string())?;
            if fresh {
                self.set_cpu_max(t, l.cpu_ceiling_millicores)?;
            }
        }
        if self.has("pids") {
            write(&dir.join("pids.max"), &l.max_pids.to_string())?;
        }
        if self.has("io") {
            if let Err(e) = write(&dir.join("io.weight"), &format!("default {}", l.io_weight)) {
                tracing::debug!(error = %e, "io.weight not settable");
            }
            // An unresolved `data_volume` placeholder is never written.
            for rule in self.io_max.iter().filter(|r| !r.is_data_volume()) {
                if let Err(e) = write(&dir.join("io.max"), &rule.line()) {
                    tracing::warn!(tenant = %t, device = %rule.device, error = %e, "io.max not settable");
                }
            }
        }
        self.enable_controllers(&dir)?;
        for role in Role::ALL {
            let leaf = dir.join(role.as_str());
            if !leaf.exists() {
                std::fs::create_dir(&leaf)?;
            }
            // Kill the whole role process on OOM, never leave it half-dead.
            let _ = write(&leaf.join("memory.oom.group"), "1");
            let _ = write(&leaf.join("memory.swap.max"), "0");
        }
        Ok(())
    }

    /// `cpu.max` (and `cpu.max.burst` = one period of it, if enabled and
    /// supported) for the tenant.
    pub fn set_cpu_max(&self, t: &TenantId, millicores: u32) -> io::Result<()> {
        apply_cpu_max(&self.tenant_dir(t), &cpu_max_line(millicores), self.cpu_max_burst, &mut write)
    }

    /// Pin each role's own ceiling below the aggregate tenant ceiling.
    /// The query quota is fixed; the ingest quota follows the EPS budget.
    pub fn set_role_cpu_max(&self, t: &TenantId, role: Role, millicores: u32) -> io::Result<()> {
        write(&self.tenant_dir(t).join(role.as_str()).join("cpu.max"), &cpu_max_line(millicores))
    }

    pub fn set_role_cpu_weight(&self, t: &TenantId, role: Role, request_millicores: u32) -> io::Result<()> {
        write(&self.tenant_dir(t).join(role.as_str()).join("cpu.weight"), &request_millicores.clamp(1, 10_000).to_string())
    }
    pub fn set_role_memory(&self, t: &TenantId, role: Role, request_bytes: u64, limit_bytes: u64) -> io::Result<()> {
        let leaf = self.tenant_dir(t).join(role.as_str());
        write(&leaf.join("memory.max"), &limit_bytes.to_string())?;
        if role != Role::Query {
            write(&leaf.join("memory.low"), &request_bytes.to_string())?;
        }
        Ok(())
    }

    pub fn set_memory_high(&self, t: &TenantId, bytes: u64) -> io::Result<()> {
        write(&self.tenant_dir(t).join("memory.high"), &bytes.to_string())
    }

    pub fn place(&self, pid: u32, t: &TenantId, role: Role) -> io::Result<()> {
        write(&self.tenant_dir(t).join(role.as_str()).join("cgroup.procs"), &pid.to_string())
    }

    pub fn place_warm(&self, pid: u32) -> io::Result<()> {
        write(&self.warm_dir().join("cgroup.procs"), &pid.to_string())
    }

    /// Set the warm pool's cap (all warm processes together).
    pub fn set_warm_limit(&self, bytes: u64) -> io::Result<()> {
        write(&self.warm_dir().join("memory.max"), &bytes.to_string())?;
        let _ = write(&self.warm_dir().join("memory.swap.max"), "0");
        Ok(())
    }

    pub fn usage(&self, t: &TenantId) -> Option<TenantUsage> {
        let dir = self.tenant_dir(t);
        if !dir.exists() {
            return None;
        }
        Some(TenantUsage {
            memory_bytes: read_u64(&dir.join("memory.current")).unwrap_or(0),
            memory_peak_bytes: read_u64(&dir.join("memory.peak")).unwrap_or(0),
            cpu_usage_usec: read_kv(&dir.join("cpu.stat"), "usage_usec").unwrap_or(0),
            cpu_throttled_usec: read_kv(&dir.join("cpu.stat"), "throttled_usec").unwrap_or(0),
            pids: read_u64(&dir.join("pids.current")).unwrap_or(0),
            // memory.events is hierarchical: includes the role leaves.
            oom_kills: read_kv(&dir.join("memory.events"), "oom_kill").unwrap_or(0),
        })
    }

    pub fn role_usage(&self, t: &TenantId, role: Role) -> Option<RoleUsage> {
        let dir = self.tenant_dir(t).join(role.as_str());
        if !dir.exists() { return None; }
        Some(RoleUsage {
            cpu_usage_usec: read_kv(&dir.join("cpu.stat"), "usage_usec").unwrap_or(0),
            cpu_throttled_usec: read_kv(&dir.join("cpu.stat"), "throttled_usec").unwrap_or(0),
            nr_throttled: read_kv(&dir.join("cpu.stat"), "nr_throttled").unwrap_or(0),
            memory_bytes: read_u64(&dir.join("memory.current")).unwrap_or(0),
            oom_kills: read_kv(&dir.join("memory.events.local"), "oom_kill").unwrap_or(0),
        })
    }

    /// Remove the tenant's cgroup if no process is left in it.
    pub fn remove_tenant_if_empty(&self, t: &TenantId) -> io::Result<bool> {
        let dir = self.tenant_dir(t);
        if !dir.exists() {
            return Ok(true);
        }
        for role in Role::ALL {
            let leaf = dir.join(role.as_str());
            if leaf.exists() {
                let procs = std::fs::read_to_string(leaf.join("cgroup.procs")).unwrap_or_default();
                if !procs.trim().is_empty() {
                    return Ok(false);
                }
                std::fs::remove_dir(&leaf)?;
            }
        }
        std::fs::remove_dir(&dir)?;
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::budget::MIB;

    #[test]
    fn enforcement_is_kernel_only_while_delegated() {
        assert_eq!(enforcement(LimitsMode::CgroupV2, false), Enforcement::Kernel);
        assert_eq!(enforcement(LimitsMode::CgroupV2, true), Enforcement::WatchdogOnly);
        assert_eq!(enforcement(LimitsMode::Watchdog, false), Enforcement::WatchdogOnly);
        assert_eq!(serde_json::to_value(Enforcement::WatchdogOnly).unwrap(), "watchdog_only");
        assert_eq!(Enforcement::Kernel.as_str(), "kernel");
    }

    /// NAN-3523: only a pooled cell without kernel limits refuses.
    #[test]
    fn pooled_cells_fail_closed_without_kernel_limits() {
        use crate::config::CellMode::{Dedicated, Pooled};
        assert_eq!(admission(Pooled, Enforcement::WatchdogOnly, false), Admission::RefusedUnenforced);
        assert_eq!(admission(Pooled, Enforcement::Kernel, false), Admission::Open);
        assert_eq!(admission(Dedicated, Enforcement::WatchdogOnly, false), Admission::Open);
        assert_eq!(admission(Dedicated, Enforcement::Kernel, false), Admission::Open);
        assert_eq!(admission(Pooled, Enforcement::WatchdogOnly, true), Admission::Open);
        // A withdrawn delegation is watchdog-only: refused again.
        assert_eq!(admission(Pooled, enforcement(LimitsMode::CgroupV2, true), false), Admission::RefusedUnenforced);
        assert_eq!(serde_json::to_value(Admission::RefusedUnenforced).unwrap(), "refused_unenforced");
        assert_eq!(Admission::Open.as_str(), "open");
    }

    /// The refusal clock runs only while refused, continuously.
    #[test]
    fn refusal_clock_resets_on_reopen() {
        use std::time::{Duration, Instant};
        let t0 = Instant::now();
        let mut c = RefusalClock::default();
        assert_eq!(c.observe(t0, Admission::Open), None);
        assert_eq!(c.observe(t0, Admission::RefusedUnenforced), Some(Duration::ZERO));
        assert_eq!(c.observe(t0 + Duration::from_secs(31), Admission::RefusedUnenforced), Some(Duration::from_secs(31)));
        assert_eq!(c.observe(t0 + Duration::from_secs(32), Admission::Open), None);
        assert_eq!(c.observe(t0 + Duration::from_secs(40), Admission::RefusedUnenforced), Some(Duration::ZERO));
        assert_eq!(c.observe(t0 + Duration::from_secs(50), Admission::RefusedUnenforced), Some(Duration::from_secs(10)));
    }

    #[test]
    fn enforcement_reason_names_the_gap() {
        let live = vec!["cgroup mount is read-only and the scope is not delegated to us (owner uid Some(65534))".to_owned()];
        assert_eq!(enforcement_reason(CgroupPolicy::Auto, Enforcement::Kernel, false, &live), None);
        let r = enforcement_reason(CgroupPolicy::Auto, Enforcement::WatchdogOnly, false, &live).unwrap();
        assert!(r.starts_with("no cgroup delegation: ") && r.contains("65534"), "{r}");
        assert!(enforcement_reason(CgroupPolicy::Off, Enforcement::WatchdogOnly, false, &live).unwrap().contains("\"off\""));
        assert!(enforcement_reason(CgroupPolicy::Auto, Enforcement::WatchdogOnly, true, &[]).unwrap().contains("took"));
        assert!(enforcement_reason(CgroupPolicy::Auto, Enforcement::WatchdogOnly, false, &[]).is_some());
    }

    #[test]
    fn kv_parse() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("memory.events");
        std::fs::write(&p, "low 0\nhigh 3\nmax 9\noom 2\noom_kill 1\n").unwrap();
        assert_eq!(read_kv(&p, "oom_kill"), Some(1));
        assert_eq!(read_kv(&p, "oom"), Some(2));
        assert_eq!(read_kv(&p, "nope"), None);
    }

    #[test]
    fn own_cgroup_strips_our_leaf() {
        assert_eq!(own_cgroup_rel("0::/\n").as_deref(), Some("/"));
        assert_eq!(own_cgroup_rel("0::/kubepods/pod1/c1/init\n").as_deref(), Some("/kubepods/pod1/c1"));
        assert_eq!(own_cgroup_rel("0::/x/supervisor\n").as_deref(), Some("/x"));
        assert_eq!(own_cgroup_rel("1:memory:/x\n"), None);
    }

    fn check(reasons: &[&str]) -> DelegationCheck {
        DelegationCheck {
            unified: true,
            root: Some("/sys/fs/cgroup".into()),
            read_only_mount: false,
            owner_uid: Some(0),
            writable: reasons.is_empty(),
            owned_by_us: reasons.is_empty(),
            needs_mount: false,
            controllers: vec!["cpu".into(), "memory".into()],
            memory_controller: true,
            reasons: reasons.iter().map(|s| s.to_string()).collect(),
        }
    }

    #[test]
    fn policy_selection() {
        let ok = check(&[]);
        let ro = check(&["cgroup mount is read-only"]);
        assert_eq!(select_mode(CgroupPolicy::Auto, &ok), Ok(LimitsMode::CgroupV2));
        assert_eq!(select_mode(CgroupPolicy::Auto, &ro), Ok(LimitsMode::Watchdog));
        assert_eq!(select_mode(CgroupPolicy::Require, &ok), Ok(LimitsMode::CgroupV2));
        let e = select_mode(CgroupPolicy::Require, &ro).unwrap_err();
        assert!(e.contains("read-only"), "{e}");
        assert_eq!(select_mode(CgroupPolicy::Off, &ok), Ok(LimitsMode::Watchdog));
        assert_eq!(select_mode(CgroupPolicy::Off, &ro), Ok(LimitsMode::Watchdog));
    }

    #[test]
    fn delegation_check_reads_a_directory() {
        let d = tempfile::tempdir().unwrap();
        let c = check_delegation_at(d.path());
        assert!(!c.delegated() && !c.unified);
        std::fs::write(d.path().join("cgroup.controllers"), "cpu io memory pids\n").unwrap();
        std::fs::write(d.path().join("cgroup.procs"), "").unwrap();
        std::fs::write(d.path().join("cgroup.subtree_control"), "").unwrap();
        let c = check_delegation_at(d.path());
        assert!(c.delegated(), "{:?}", c.reasons);
        assert!(c.memory_controller && c.writable);
        std::fs::write(d.path().join("cgroup.controllers"), "cpu pids\n").unwrap();
        assert!(check_delegation_at(d.path()).reasons.contains(&"memory controller not available".to_owned()));
        std::fs::write(d.path().join("cgroup.controllers"), "memory pids\n").unwrap();
        let no_cpu = check_delegation_at(d.path());
        assert_eq!(select_mode(CgroupPolicy::Auto, &no_cpu), Ok(LimitsMode::Watchdog));
        assert!(select_mode(CgroupPolicy::Require, &no_cpu).unwrap_err().contains("cpu controller not available"));
        std::fs::write(d.path().join("cgroup.controllers"), "cpu memory\n").unwrap();
        assert!(check_delegation_at(d.path()).reasons.contains(&"pids controller not available".to_owned()));
        // The real cgroup of this test process (usually not writable here).
        let _ = check_delegation(Path::new("/sys/fs/cgroup"));
    }

    fn fake_root(controllers: &str) -> tempfile::TempDir {
        let d = tempfile::tempdir().unwrap();
        std::fs::write(d.path().join("cgroup.controllers"), controllers).unwrap();
        std::fs::write(d.path().join("cgroup.procs"), "4242\n4343\n").unwrap();
        d
    }

    fn rd(p: &Path) -> String {
        std::fs::read_to_string(p).unwrap_or_else(|e| panic!("{}: {e}", p.display()))
    }

    #[test]
    fn adopt_moves_us_to_init_and_enables_controllers() {
        let d = fake_root("cpuset cpu io memory hugetlb pids rdma misc\n");
        let tree = CgroupTree::adopt_root_as(d.path().to_path_buf(), "/pod/c".into(), vec![], true, 4343).unwrap();
        assert_eq!(tree.controllers(), ["cpu", "memory", "pids", "io"]);
        // Only the supervisor (4343) goes to init/; 4242 is frozen in limbo/.
        assert_eq!(rd(&d.path().join("init/cgroup.procs")), "4343");
        assert_eq!(rd(&d.path().join("limbo/cgroup.procs")), "4242");
        assert_eq!(rd(&d.path().join("cgroup.subtree_control")), "+cpu +memory +pids +io");
        assert_eq!(rd(&d.path().join("tenants/cgroup.subtree_control")), "+cpu +memory +pids +io");
        assert_eq!(rd(&d.path().join("tenants/cpu.weight")), "800");
        assert_eq!(rd(&d.path().join("init/cpu.weight")), "200");
        assert!(d.path().join("warm").is_dir());
        // NAN-3523: the supervisor's memory reserve, capped at 1/16 of the cell.
        assert_eq!(tree.reserve_init(256 * MIB, 8 * 1024 * MIB).unwrap(), 256 * MIB);
        assert_eq!(rd(&d.path().join("init/memory.min")), (256 * MIB).to_string());
        assert_eq!(tree.reserve_init(256 * MIB, 1024 * MIB).unwrap(), 64 * MIB);
        assert_eq!(init_memory_min(0, 1 << 40), 0);
        let t1 = TenantId::new("t1").unwrap();
        tree.register(&t1, 7);
        // Named by slot, never by tenant id.
        assert_eq!(tree.role_rel(&t1, Role::Query), PathBuf::from("/pod/c/tenants/s7/query"));
        let unknown = TenantId::new("t9").unwrap();
        assert!(!tree.role_rel(&unknown, Role::Query).to_string_lossy().contains("t9"));
        let no_mem = fake_root("cpu pids\n");
        assert!(CgroupTree::adopt_root(no_mem.path().to_path_buf(), "/".into(), vec![], true).is_err());
        // `require` insists on cpu + memory + pids.
        tree.require_controllers().unwrap();
        let no_pids = fake_root("cpu memory\n");
        let t2 = CgroupTree::adopt_root(no_pids.path().to_path_buf(), "/".into(), vec![], true).unwrap();
        let e = t2.require_controllers().unwrap_err().to_string();
        assert!(e.contains("pids") && !e.contains("cpu,"), "{e}");
    }

    /// A fake sysfs: nvme0n1 (259:0) with partition p1 (259:1), and dm-0.
    fn fake_sysfs() -> tempfile::TempDir {
        let d = tempfile::tempdir().unwrap();
        let disk = d.path().join("devices/pci0000:00/nvme/nvme0/nvme0n1");
        let part = disk.join("nvme0n1p1");
        let dm = d.path().join("devices/virtual/block/dm-0");
        for dir in [&part, &dm] {
            std::fs::create_dir_all(dir).unwrap();
        }
        std::fs::write(disk.join("dev"), "259:0\n").unwrap();
        std::fs::write(part.join("dev"), "259:1\n").unwrap();
        std::fs::write(part.join("partition"), "1\n").unwrap();
        std::fs::write(dm.join("dev"), "253:0\n").unwrap();
        let block = d.path().join("dev/block");
        std::fs::create_dir_all(&block).unwrap();
        std::os::unix::fs::symlink("../../devices/pci0000:00/nvme/nvme0/nvme0n1", block.join("259:0")).unwrap();
        std::os::unix::fs::symlink("../../devices/pci0000:00/nvme/nvme0/nvme0n1/nvme0n1p1", block.join("259:1")).unwrap();
        std::os::unix::fs::symlink("../../devices/virtual/block/dm-0", block.join("253:0")).unwrap();
        d
    }

    #[test]
    fn dev_t_splits_like_glibc() {
        // makedev(259, 1) = 0x10301; makedev(8, 0) = 0x800.
        assert_eq!(dev_major_minor(0x10301), (259, 1));
        assert_eq!(dev_major_minor(0x800), (8, 0));
        // Minor ≥ 256 spills into bits 20+.
        let makedev = |ma: u64, mi: u64| (mi & 0xff) | ((ma & 0xfff) << 8) | ((mi & !0xff) << 12) | ((ma & !0xfff) << 32);
        assert_eq!(dev_major_minor(makedev(259, 300)), (259, 300));
        assert_eq!(dev_major_minor(makedev(4100, 70000)), (4100, 70000));
        assert_eq!(dev_major_minor(0x2a), (0, 42));
    }

    #[test]
    fn whole_disk_maps_partitions_to_their_disk() {
        let sys = fake_sysfs();
        assert_eq!(whole_disk_device(sys.path(), 259, 1).unwrap(), "259:0", "a partition maps to its disk");
        assert_eq!(whole_disk_device(sys.path(), 259, 0).unwrap(), "259:0");
        assert_eq!(whole_disk_device(sys.path(), 253, 0).unwrap(), "253:0", "dm devices have no partition file");
        let e = whole_disk_device(sys.path(), 0, 42).unwrap_err();
        assert!(e.contains("not a block device"), "{e}");
        let e = whole_disk_device(sys.path(), 8, 0).unwrap_err();
        assert!(e.contains("not in sysfs"), "{e}");
        std::fs::write(sys.path().join("devices/virtual/block/dm-0/dev"), "garbage\n").unwrap();
        assert!(whole_disk_device(sys.path(), 253, 0).unwrap_err().contains("not MAJ:MIN"));
    }

    #[test]
    fn resolve_reads_the_data_dir_st_dev() {
        use std::os::unix::fs::MetadataExt;
        // Give the manifest dir's own st_dev a sysfs entry, as partition 1
        // of a fake disk 7:77 (anonymous on btrfs/tmpfs/overlay: refused).
        let data = Path::new(env!("CARGO_MANIFEST_DIR"));
        let (major, minor) = dev_major_minor(std::fs::metadata(data).unwrap().dev());
        let sys = tempfile::tempdir().unwrap();
        let disk = sys.path().join("devices/fake/disk0");
        let part = disk.join("disk0p1");
        std::fs::create_dir_all(&part).unwrap();
        std::fs::write(disk.join("dev"), "7:77\n").unwrap();
        std::fs::write(part.join("dev"), format!("{major}:{minor}\n")).unwrap();
        std::fs::write(part.join("partition"), "1\n").unwrap();
        std::fs::create_dir_all(sys.path().join("dev/block")).unwrap();
        std::os::unix::fs::symlink(&part, sys.path().join(format!("dev/block/{major}:{minor}"))).unwrap();
        let got = resolve_data_volume_device(data, sys.path());
        if major == 0 {
            assert!(got.unwrap_err().contains("not a block device"));
        } else {
            assert_eq!(got.unwrap(), "7:77");
        }
        assert!(resolve_data_volume_device(Path::new("/nonexistent/nan3523"), sys.path()).unwrap_err().contains("stat"));
    }

    #[test]
    fn data_volume_rules_resolve_or_drop_with_a_reason() {
        let data = Path::new("/data");
        let dv = || IoMaxRule { device: crate::config::IO_MAX_DATA_VOLUME.into(), rbps: Some(100 << 20), wbps: Some(60 << 20), riops: None, wiops: None };
        let fixed = IoMaxRule { device: "8:0".into(), rbps: None, wbps: Some(1), riops: None, wiops: None };
        let adopt = |controllers: &str, rules: Vec<IoMaxRule>| {
            let d = fake_root(controllers);
            let tree = CgroupTree::adopt_root(d.path().to_path_buf(), "/".into(), rules, true).unwrap();
            (d, tree)
        };

        // Resolved: the placeholder becomes the device and is applied.
        let (d, mut tree) = adopt("cpu io memory pids\n", vec![dv()]);
        tree.apply_data_volume_device(data, Ok("259:0".into()));
        assert_eq!(tree.io_max_unresolved(), None);
        tree.ensure_tenant(&TenantId::new("alpha").unwrap(), 0, &limits_for_io()).unwrap();
        assert_eq!(rd(&d.path().join("tenants/s0/io.max")), "259:0 rbps=104857600 wbps=62914560 riops=max wiops=max");

        // Unresolvable: dropped, reason kept, the explicit rule still applies.
        let (d, mut tree) = adopt("cpu io memory pids\n", vec![dv(), fixed.clone()]);
        tree.resolve_io_max_data_volume(data, &d.path().join("no-sysfs"));
        assert!(tree.io_max_unresolved().is_some());
        assert_eq!(tree.io_max(), [fixed.clone()]);
        tree.ensure_tenant(&TenantId::new("alpha").unwrap(), 0, &limits_for_io()).unwrap();
        assert_eq!(rd(&d.path().join("tenants/s0/io.max")), fixed.line());

        // No io controller: unresolved, never a failure.
        let (_d, mut tree) = adopt("cpu memory pids\n", vec![dv()]);
        tree.apply_data_volume_device(data, Ok("259:0".into()));
        assert_eq!(tree.io_max_unresolved(), Some("io controller not delegated"));
        assert!(tree.io_max().is_empty());

        // No data_volume rule: nothing to resolve, nothing reported.
        let (d, mut tree) = adopt("cpu io memory pids\n", vec![fixed.clone()]);
        tree.resolve_io_max_data_volume(Path::new("/nonexistent"), &d.path().join("no-sysfs"));
        assert_eq!(tree.io_max_unresolved(), None);
        assert_eq!(tree.io_max(), [fixed]);

        // Never resolved: ensure_tenant never writes the placeholder.
        let (d, tree) = adopt("cpu io memory pids\n", vec![dv()]);
        tree.ensure_tenant(&TenantId::new("beta").unwrap(), 1, &limits_for_io()).unwrap();
        assert!(!d.path().join("tenants/s1/io.max").exists());
    }

    fn limits_for_io() -> TenantLimits {
        TenantLimits {
            cpu_guarantee_millicores: 50,
            cpu_ceiling_millicores: 500,
            cpu_weight: 50,
            memory_guarantee_bytes: 350 * MIB,
            memory_soft_bytes: 512 * MIB,
            memory_hard_bytes: 640 * MIB,
            max_pids: 512,
            io_weight: 105,
        }
    }

    #[test]
    fn tenant_files_carry_guarantee_soft_and_ceilings() {
        let d = fake_root("cpu io memory pids\n");
        let io = vec![IoMaxRule { device: "259:0".into(), rbps: None, wbps: Some(50 << 20), riops: None, wiops: None }];
        let tree = CgroupTree::adopt_root(d.path().to_path_buf(), "/".into(), io, true).unwrap();
        let t = TenantId::new("alpha").unwrap();
        let l = TenantLimits {
            cpu_guarantee_millicores: 50,
            cpu_ceiling_millicores: 500,
            cpu_weight: 50,
            memory_guarantee_bytes: 350 * MIB,
            memory_soft_bytes: 512 * MIB,
            memory_hard_bytes: 640 * MIB,
            max_pids: 512,
            io_weight: 105,
        };
        tree.ensure_tenant(&t, 0, &l).unwrap();
        assert!(!d.path().join("tenants/alpha").exists(), "the tenant id never names a cgroup");
        let dir = d.path().join("tenants/s0");
        let expect = [
            ("cpu.weight", "50".to_owned()),
            ("cpu.max", "50000 100000".to_owned()),
            ("cpu.max.burst", "50000".to_owned()),
            ("memory.low", (350 * MIB).to_string()),
            ("memory.high", (640 * MIB).to_string()),
            ("memory.max", (640 * MIB).to_string()),
            ("memory.swap.max", "0".to_owned()),
            ("pids.max", "512".to_owned()),
            ("io.weight", "default 105".to_owned()),
            ("io.max", "259:0 rbps=max wbps=52428800 riops=max wiops=max".to_owned()),
            ("cgroup.subtree_control", "+cpu +memory +pids +io".to_owned()),
            ("ingest/memory.oom.group", "1".to_owned()),
            ("query/memory.oom.group", "1".to_owned()),
        ];
        for (f, v) in expect {
            assert_eq!(rd(&dir.join(f)), v, "{f}");
        }
        // Dynamic enforcement.
        tree.set_cpu_max(&t, 120).unwrap();
        assert_eq!(rd(&dir.join("cpu.max")), "12000 100000");
        tree.set_memory_high(&t, 400 * MIB).unwrap();
        assert_eq!(rd(&dir.join("memory.high")), (400 * MIB).to_string());
        // A resize (placement change) never overwrites controller-owned files.
        let bigger = TenantLimits { cpu_ceiling_millicores: 900, memory_hard_bytes: 700 * MIB, memory_guarantee_bytes: 360 * MIB, ..l };
        tree.ensure_tenant(&t, 0, &bigger).unwrap();
        assert_eq!(rd(&dir.join("cpu.max")), "12000 100000");
        assert_eq!(rd(&dir.join("memory.high")), (400 * MIB).to_string());
        assert_eq!(rd(&dir.join("memory.max")), (700 * MIB).to_string());
        assert_eq!(rd(&dir.join("memory.low")), (360 * MIB).to_string());
        tree.kill_role(&t, Role::Query).unwrap();
        assert_eq!(rd(&dir.join("query/cgroup.kill")), "1");
        tree.place(777, &t, Role::Ingest).unwrap();
        assert_eq!(rd(&dir.join("ingest/cgroup.procs")), "777");
        // Usage, incl. the oom_kill counter from memory.events.
        std::fs::write(dir.join("memory.current"), "1048576\n").unwrap();
        std::fs::write(dir.join("cpu.stat"), "usage_usec 5000\nuser_usec 4000\nthrottled_usec 1200\n").unwrap();
        std::fs::write(dir.join("memory.events"), "low 0\nhigh 7\nmax 2\noom 1\noom_kill 1\n").unwrap();
        let u = tree.usage(&t).unwrap();
        assert_eq!((u.memory_bytes, u.cpu_usage_usec, u.cpu_throttled_usec, u.oom_kills), (1 << 20, 5000, 1200, 1));
        // Without the cpu controller no cpu files are written.
        let d2 = fake_root("memory pids\n");
        let tree2 = CgroupTree::adopt_root(d2.path().to_path_buf(), "/".into(), vec![], true).unwrap();
        tree2.ensure_tenant(&t, 0, &l).unwrap();
        assert!(!d2.path().join("tenants/s0/cpu.max").exists());
        assert_eq!(rd(&d2.path().join("tenants/s0/memory.low")), (350 * MIB).to_string());
    }

    /// A writer that enforces the kernel's `cpu.max` / `cpu.max.burst`
    /// invariant (burst <= quota) on a fake cgroup dir, logging write order.
    fn kernel_cpu_writer(log: &mut Vec<String>) -> impl FnMut(&Path, &str) -> io::Result<()> + '_ {
        move |p: &Path, v: &str| {
            let dir = p.parent().unwrap();
            let name = p.file_name().unwrap().to_str().unwrap().to_owned();
            let quota = |s: &str| s.split_whitespace().next().unwrap().parse::<u64>().unwrap();
            let ok = match name.as_str() {
                "cpu.max" => read_u64(&dir.join("cpu.max.burst")).is_none_or(|b| quota(v) >= b),
                "cpu.max.burst" => {
                    let cur = std::fs::read_to_string(dir.join("cpu.max")).map(|s| quota(&s)).unwrap_or(u64::MAX);
                    v.parse::<u64>().unwrap() <= cur
                }
                _ => true,
            };
            log.push(format!("{name}={v}"));
            if !ok {
                return Err(io::Error::from_raw_os_error(22));
            }
            std::fs::write(p, v)
        }
    }

    #[test]
    fn cpu_max_shrinks_and_grows_with_burst_set() {
        let d = tempfile::tempdir().unwrap();
        let dir = d.path();
        // Live cell-us-1 state (NAN-3842): ceiling 10838m with burst = quota.
        std::fs::write(dir.join("cpu.max"), "1083800 100000").unwrap();
        std::fs::write(dir.join("cpu.max.burst"), "1083800").unwrap();
        let mut log = Vec::new();
        // Shrink to 3530m: burst must drop before cpu.max.
        apply_cpu_max(dir, &cpu_max_line(3530), true, &mut kernel_cpu_writer(&mut log)).unwrap();
        assert_eq!(rd(&dir.join("cpu.max")), "353000 100000");
        assert_eq!(rd(&dir.join("cpu.max.burst")), "353000");
        assert_eq!(log, ["cpu.max.burst=353000", "cpu.max=353000 100000", "cpu.max.burst=353000"]);
        // Grow to 8000m: cpu.max first, then burst.
        log.clear();
        apply_cpu_max(dir, &cpu_max_line(8000), true, &mut kernel_cpu_writer(&mut log)).unwrap();
        assert_eq!(rd(&dir.join("cpu.max")), "800000 100000");
        assert_eq!(rd(&dir.join("cpu.max.burst")), "800000");
        assert_eq!(log, ["cpu.max=800000 100000", "cpu.max.burst=800000"]);
        // The old order (cpu.max before burst) is what the kernel refused.
        let mut log = Vec::new();
        let err = kernel_cpu_writer(&mut log)(&dir.join("cpu.max"), "100000 100000").unwrap_err();
        assert_eq!(err.raw_os_error(), Some(22));
        // Burst disabled: only cpu.max is touched.
        let d2 = tempfile::tempdir().unwrap();
        let mut log = Vec::new();
        apply_cpu_max(d2.path(), &cpu_max_line(500), false, &mut kernel_cpu_writer(&mut log)).unwrap();
        assert_eq!(log, ["cpu.max=50000 100000"]);
        assert!(!d2.path().join("cpu.max.burst").exists());
        // Burst unsupported by the kernel: cpu.max still lands, no error.
        let mut no_burst = |p: &Path, v: &str| {
            if p.ends_with("cpu.max.burst") {
                return Err(io::Error::from(io::ErrorKind::NotFound));
            }
            std::fs::write(p, v)
        };
        apply_cpu_max(d2.path(), &cpu_max_line(250), true, &mut no_burst).unwrap();
        assert_eq!(rd(&d2.path().join("cpu.max")), "25000 100000");
    }

    // ---------------------------------------------------------------- mount selection

    #[derive(Default)]
    struct FakeMounter {
        private_ok: bool,
        calls: std::cell::RefCell<Vec<String>>,
    }

    impl Mounter for FakeMounter {
        fn mount_private(&self, target: &Path) -> io::Result<()> {
            self.calls.borrow_mut().push(format!("private {}", target.display()));
            if self.private_ok { Ok(()) } else { Err(io::Error::from_raw_os_error(libc::EPERM)) }
        }
        fn unmount(&self, _: &Path) -> io::Result<()> {
            Ok(())
        }
    }

    /// The delegator's end state: owned by us, but the mount is read-only.
    fn delegated_ro() -> DelegationCheck {
        DelegationCheck { writable: false, owned_by_us: true, needs_mount: true, read_only_mount: true, ..check(&[]) }
    }

    #[test]
    fn make_writable_uses_only_the_private_mount() {
        let d = tempfile::tempdir().unwrap();
        let (mnt, private) = (Path::new("/sys/fs/cgroup"), d.path().join("cg"));
        // Already writable: no mount at all.
        let m = FakeMounter::default();
        let w = make_writable(&check(&[]), mnt, &private, &m, &mut MountAttempts::default()).unwrap();
        assert_eq!(w.method, MountMethod::AlreadyWritable);
        assert!(m.calls.borrow().is_empty());
        // Delegated + RO: private mount first.
        let m = FakeMounter { private_ok: true, ..Default::default() };
        let mut a = MountAttempts::default();
        let w = make_writable(&delegated_ro(), mnt, &private, &m, &mut a).unwrap();
        assert_eq!(w, WritableMount { mount: private.clone(), method: MountMethod::PrivateMount });
        assert_eq!(a.private_mount.as_deref(), Some("ok"));
        assert_eq!(m.calls.borrow().len(), 1);
        // Private refused: no fallback (a bind-remount would make the
        // tenants' view writable too).
        let m = FakeMounter { private_ok: false, ..Default::default() };
        let mut a = MountAttempts::default();
        let e = make_writable(&delegated_ro(), mnt, &private, &m, &mut a).unwrap_err();
        assert!(e.contains("private cgroup2 mount") && e.contains("not permitted"), "{e}");
        assert_eq!(m.calls.borrow().len(), 1);
        // Not delegated (RO, owned by 65534): no mount attempted.
        let m = FakeMounter { private_ok: true, ..Default::default() };
        let not = DelegationCheck { owned_by_us: false, ..delegated_ro() };
        assert!(make_writable(&not, mnt, &private, &m, &mut MountAttempts::default()).is_err());
        assert!(m.calls.borrow().is_empty());
        // A plain directory that merely looks like a cgroup (a
        // cgroup.controllers file) is NOT reused: statfs must say cgroup2.
        std::fs::create_dir_all(&private).unwrap();
        std::fs::write(private.join("cgroup.controllers"), "cpu memory\n").unwrap();
        assert!(!is_cgroup2(&private));
        let m = FakeMounter { private_ok: true, ..Default::default() };
        let w = make_writable(&delegated_ro(), mnt, &private, &m, &mut MountAttempts::default()).unwrap();
        assert_eq!(w.method, MountMethod::PrivateMount);
        assert_eq!(m.calls.borrow().len(), 1, "mounted, not reused");
        // The real cgroup2 mount is recognised.
        assert!(is_cgroup2(Path::new("/sys/fs/cgroup")) || !Path::new("/sys/fs/cgroup/cgroup.controllers").exists());
    }

    #[test]
    fn probe_write_proof_uses_the_supervisor_path_and_cleans_up() {
        let d = tempfile::tempdir().unwrap();
        let private = d.path().join("cg");
        // "Mounting" in the fake = creating a cgroup-looking dir.
        struct DirMounter;
        impl Mounter for DirMounter {
            fn mount_private(&self, t: &Path) -> io::Result<()> {
                std::fs::create_dir_all(t)?;
                std::fs::write(t.join("cgroup.controllers"), "cpu memory pids\n")
            }
            fn unmount(&self, t: &Path) -> io::Result<()> {
                std::fs::remove_dir_all(t)
            }
        }
        let (ok, a, m) = prove_writable(&delegated_ro(), Path::new("/sys/fs/cgroup"), &private, "/", &DirMounter);
        assert!(ok && m == Some(MountMethod::PrivateMount), "{a:?}");
        assert!(!private.exists(), "the proof's private mount is undone");
        let not = DelegationCheck { owned_by_us: false, ..delegated_ro() };
        let (ok, _, m) = prove_writable(&not, Path::new("/sys/fs/cgroup"), &private, "/", &DirMounter);
        assert!(!ok && m.is_none());
    }

    #[test]
    fn ownership_counts_as_delegation_even_when_not_writable() {
        use std::os::unix::fs::PermissionsExt;
        // Owned by us (tempdir) but not writable (mode 0555 / 0444): the
        // delegator's end state seen through a read-only mount.
        let d = tempfile::tempdir().unwrap();
        for f in ["cgroup.controllers", "cgroup.procs", "cgroup.subtree_control", "cgroup.threads"] {
            std::fs::write(d.path().join(f), "cpu memory pids\n").unwrap();
            std::fs::set_permissions(d.path().join(f), std::fs::Permissions::from_mode(0o444)).unwrap();
        }
        std::fs::set_permissions(d.path(), std::fs::Permissions::from_mode(0o555)).unwrap();
        let c = check_delegation_at(d.path());
        // SAFETY: geteuid never fails.
        let root = unsafe { libc::geteuid() } == 0;
        if !root {
            assert!(!c.writable && c.owned_by_us && c.needs_mount && c.delegated(), "{c:?}");
            assert_eq!(select_mode(CgroupPolicy::Require, &c), Ok(LimitsMode::CgroupV2));
        }
        std::fs::set_permissions(d.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    /// NAN-3720: product[T] runs as query's uid. Swept by uid before its
    /// assignment was recorded it lands in `query/` (the load-test tenant: the 30 d
    /// prevalence rebuild charged to interactive search's CPU quota and
    /// memory ceiling); the per-tick re-home moves it to its own leaf and
    /// leaves correctly placed processes alone.
    #[test]
    fn a_product_process_swept_into_query_is_rehomed_to_its_own_leaf() {
        use std::collections::HashMap;
        let d = fake_root("cpu memory pids\n");
        let tree = CgroupTree::adopt_root(d.path().to_path_buf(), "/".into(), vec![], false).unwrap();
        let a = TenantId::new("alpha").unwrap();
        tree.ensure_tenant(&a, 0, &limits_for_io()).unwrap();
        // Query's uid owns both processes; the uid sweep only knows "query".
        let owners: HashMap<u32, (TenantId, Role)> = [(20001, (a.clone(), Role::Query))].into_iter().collect();
        let plan = plan_sweep(&[(41, 20001, 1)], 1, &owners, &[]);
        assert_eq!(plan, vec![(41, SweepTarget::Tenant(a.clone(), Role::Query))]);
        tree.apply_sweep(&plan);
        assert_eq!(tree.role_pids(&a, Role::Query), vec![41], "the bug: product in query's leaf");
        assert!(tree.role_pids(&a, Role::Product).is_empty());

        let assigned = [(41, Role::Product)];
        let moves = plan_rehome(&assigned, |role| tree.role_pids(&a, role));
        assert_eq!(moves, vec![(41, Role::Product)]);
        for (pid, role) in &moves {
            tree.place(*pid, &a, *role).unwrap();
        }
        assert_eq!(tree.role_pids(&a, Role::Product), vec![41]);
        assert!(plan_rehome(&assigned, |role| tree.role_pids(&a, role)).is_empty(), "placed: nothing to do");

        // Correctly placed processes are never moved.
        let leaf = |role| match role { Role::Query => vec![30], Role::Ingest => vec![339, 340], _ => vec![] };
        assert!(plan_rehome(&[(30, Role::Query), (339, Role::Ingest)], leaf).is_empty());
        assert_eq!(plan_rehome(&[(30, Role::Query), (340, Role::Maintenance), (41, Role::Product)], leaf),
            vec![(340, Role::Maintenance), (41, Role::Product)]);
        assert!(TenantId::new("beta").map(|b| tree.role_pids(&b, Role::Query).is_empty()).unwrap(), "unregistered tenant");
    }

    #[test]
    fn live_adoption_freezes_strays_in_limbo_and_sorts_them_out() {
        use std::collections::HashMap;
        // Before adoption everything sits in the scope root.
        let d = fake_root("cpu memory pids\n");
        std::fs::write(d.path().join("cgroup.procs"), "1\n50\n51\n52\n60\n70\n").unwrap();
        let tree = CgroupTree::adopt_root_as(d.path().to_path_buf(), "/".into(), vec![], false, 1).unwrap();
        // Only the supervisor went to init/; the rest to a frozen limbo/
        // (fake files keep the last write).
        assert_eq!(rd(&d.path().join("init/cgroup.procs")), "1");
        assert_eq!(rd(&d.path().join("limbo/cgroup.freeze")), "1");
        assert_eq!(rd(&d.path().join("limbo/cgroup.procs")), "70");
        let a = TenantId::new("alpha").unwrap();
        let limits = TenantLimits {
            cpu_guarantee_millicores: 50,
            cpu_ceiling_millicores: 500,
            cpu_weight: 50,
            memory_guarantee_bytes: 350 * MIB,
            memory_soft_bytes: 512 * MIB,
            memory_hard_bytes: 640 * MIB,
            max_pids: 512,
            io_weight: 100,
        };
        // Lazy slot registration.
        tree.ensure_tenant(&a, 0, &limits).unwrap();
        assert!(tree.ensure_tenant(&a, 5, &limits).is_err(), "a tenant keeps its slot");
        let owners: HashMap<u32, (TenantId, Role)> =
            [(20000, (a.clone(), Role::Ingest)), (20001, (a.clone(), Role::Query))].into_iter().collect();
        // (pid, uid, ppid): 1 supervisor, 50 alpha/ingest, 51 its child,
        // 52 alpha/query re-parented, 60 warm, 61 a supervisor child
        // mid-spawn, 70 unrelated uid-0 process (not ours).
        let procs = [(1, 0, 0), (50, 20000, 1), (51, 20000, 50), (52, 20001, 7), (60, 0, 1), (61, 0, 1), (70, 0, 7)];
        let plan = plan_sweep(&procs, 1, &owners, &[60]);
        assert_eq!(
            plan,
            vec![
                (50, SweepTarget::Tenant(a.clone(), Role::Ingest)),
                (51, SweepTarget::Tenant(a.clone(), Role::Ingest)),
                (52, SweepTarget::Tenant(a.clone(), Role::Query)),
                (60, SweepTarget::Warm),
                (61, SweepTarget::Warm),
                (70, SweepTarget::Kill),
            ]
        );
        assert_eq!(tree.apply_sweep(&plan), (5, vec![70]));
        assert_eq!(rd(&d.path().join("tenants/s0/ingest/cgroup.procs")), "51");
        assert_eq!(rd(&d.path().join("tenants/s0/query/cgroup.procs")), "52");
        assert_eq!(rd(&d.path().join("warm/cgroup.procs")), "61");
        // Fake limbo still "has" 70 (fake files never drain): remove_limbo
        // kills what is left, then removes the cgroup.
        std::fs::write(d.path().join("limbo/cgroup.procs"), "").unwrap();
        for f in ["cgroup.procs", "cgroup.freeze"] {
            std::fs::remove_file(d.path().join("limbo").join(f)).unwrap();
        }
        assert_eq!(tree.remove_limbo().unwrap(), 0);
        assert!(!d.path().join("limbo").exists());
    }
}
