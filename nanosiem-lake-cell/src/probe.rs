// SPDX-License-Identifier: AGPL-3.0-or-later

//! `nanosiem-lake-cell probe`: what isolation this node/pod can enforce.
//!
//! Run it inside the intended cell container (same securityContext) before
//! relying on a mode. It reports landlock ABI, seccomp, cgroup v2
//! delegation, unprivileged user namespaces, capabilities and pidfd support.
//! With `--write` it also proves cgroup writability by creating and removing
//! an empty child cgroup; without it the probe is read-only.
//!
//! It reports the limits **mode** the supervisor would pick for each cgroup
//! policy (`auto`, `require`, `off`) and why, the identity preflight
//! verdict, and the cell capacity. With `--config <cell.json>` it evaluates
//! exactly that config (its policy, uid range, landlock requirement, cgroup
//! mount and resource settings).

use crate::config::{CgroupPolicy, ResourceConfig};
use crate::identity::IdentityReport;
use crate::limits::{DelegationCheck, LimitsMode};
use crate::resources::CellCapacity;
use serde::Serialize;
use std::path::PathBuf;

/// What `probe` evaluates; defaults match a cell config with no overrides.
#[derive(Debug, Clone)]
pub struct ProbeInput {
    pub write: bool,
    pub policy: CgroupPolicy,
    pub cgroup_mount: PathBuf,
    pub uid_base: u32,
    pub uid_slots: u32,
    pub require_landlock: bool,
    pub trusted_local: bool,
    pub resources: ResourceConfig,
}

impl Default for ProbeInput {
    fn default() -> Self {
        Self {
            write: false,
            policy: CgroupPolicy::Auto,
            cgroup_mount: PathBuf::from("/sys/fs/cgroup"),
            uid_base: crate::uidmap::DEFAULT_UID_BASE,
            uid_slots: crate::uidmap::DEFAULT_UID_SLOTS,
            require_landlock: true,
            trusted_local: false,
            resources: ResourceConfig::default(),
        }
    }
}

impl ProbeInput {
    pub fn from_config(cfg: &crate::config::CellConfig, write: bool) -> Self {
        Self {
            write,
            policy: cfg.cgroup_policy(),
            cgroup_mount: cfg.cgroup_mount.clone(),
            uid_base: cfg.uid_base,
            uid_slots: cfg.uid_slots,
            require_landlock: cfg.require_landlock,
            trusted_local: cfg.trusted_local,
            resources: cfg.resources.clone(),
        }
    }
}

/// The mode a policy would run in, or why the cell would refuse to start.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct ModeChoice {
    pub policy: CgroupPolicy,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mode: Option<LimitsMode>,
    pub why: String,
}

/// Mode selection for a policy given the checks (pure; unit-tested).
pub fn choose(policy: CgroupPolicy, check: &DelegationCheck, write_proof: Option<bool>, identity: &IdentityReport) -> ModeChoice {
    if !identity.fatal.is_empty() {
        return ModeChoice { policy, mode: None, why: format!("refuses to start: {}", identity.fatal.join("; ")) };
    }
    // A failed mkdir under --write overrides a writable-looking check.
    let mut check = check.clone();
    if write_proof == Some(false) && check.delegated() {
        check.reasons.push("mkdir of a child cgroup failed".into());
    }
    match crate::limits::select_mode(policy, &check) {
        Ok(LimitsMode::CgroupV2) => ModeChoice {
            policy,
            mode: Some(LimitsMode::CgroupV2),
            why: "delegated cgroup subtree is writable: kernel limits + watchdog".into(),
        },
        Ok(LimitsMode::Watchdog) if policy == CgroupPolicy::Off => {
            ModeChoice { policy, mode: Some(LimitsMode::Watchdog), why: "cgroup: off: watchdog only".into() }
        }
        Ok(LimitsMode::Watchdog) => ModeChoice {
            policy,
            mode: Some(LimitsMode::Watchdog),
            why: format!("no delegation ({}): watchdog only", check.reasons.join("; ")),
        },
        Err(e) => ModeChoice { policy, mode: None, why: format!("refuses to start: {e}") },
    }
}

#[derive(Debug, Serialize)]
pub struct ProbeReport {
    pub kernel: String,
    pub euid: u32,
    pub cap_eff: String,
    pub has_cap_setuid: bool,
    pub has_cap_setgid: bool,
    pub has_cap_chown: bool,
    pub landlock_abi: i32,
    pub seccomp_filter_supported: bool,
    pub cgroup_v2_path: Option<String>,
    pub cgroup_controllers: Vec<String>,
    pub cgroup_writable: Option<bool>,
    /// `--write` only: the private cgroup2 mount attempt ("ok" or the error).
    pub cgroup_mount: Option<crate::limits::MountAttempts>,
    /// `--write` only: how a writable view was obtained.
    pub cgroup_mount_method: Option<crate::limits::MountMethod>,
    pub unprivileged_userns: bool,
    pub max_user_namespaces: Option<u64>,
    pub apparmor_restrict_unprivileged_userns: Option<u64>,
    pub pidfd: bool,
    pub has_cap_fowner: bool,
    pub has_cap_kill: bool,
    /// The mode the supervisor would run in with `cgroup: auto`.
    pub recommended: String,
    pub delegation: DelegationCheck,
    pub identity: IdentityReport,
    /// The configured policy's choice.
    pub selected: ModeChoice,
    /// Every policy's choice (to pick one for the renderer).
    pub modes: Vec<ModeChoice>,
    pub capacity: CellCapacity,
}

fn read_trim(p: &str) -> Option<String> {
    std::fs::read_to_string(p).ok().map(|s| s.trim().to_owned())
}

fn cap_eff() -> u64 {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| s.lines().find_map(|l| l.strip_prefix("CapEff:").map(|v| v.trim().to_owned())))
        .and_then(|h| u64::from_str_radix(&h, 16).ok())
        .unwrap_or(0)
}

/// Must be called while single-threaded (it forks for the userns check).
pub fn run(input: &ProbeInput) -> ProbeReport {
    let write = input.write;
    // SAFETY: uname into a zeroed struct.
    let kernel = unsafe {
        let mut u: libc::utsname = std::mem::zeroed();
        libc::uname(&mut u);
        std::ffi::CStr::from_ptr(u.release.as_ptr()).to_string_lossy().into_owned()
    };
    let caps = cap_eff();
    let bit = |n: u32| caps & (1u64 << n) != 0;
    // SAFETY: plain prctl query.
    let seccomp = unsafe { libc::prctl(libc::PR_GET_SECCOMP, 0, 0, 0, 0) } >= 0
        && std::fs::read_to_string("/proc/self/status").map(|s| s.contains("Seccomp_filters:")).unwrap_or(false);
    let cg_rel = read_trim("/proc/self/cgroup")
        .and_then(|s| s.lines().find_map(|l| l.strip_prefix("0::").map(|v| v.to_owned())));
    let cg_abs = cg_rel.as_ref().map(|r| format!("/sys/fs/cgroup{}", if r == "/" { "" } else { r }));
    let controllers: Vec<String> = cg_abs
        .as_ref()
        .and_then(|p| read_trim(&format!("{p}/cgroup.controllers")))
        .map(|s| s.split_whitespace().map(str::to_owned).collect())
        .unwrap_or_default();
    let delegation = crate::limits::check_delegation(&input.cgroup_mount);
    // --write: prove it the way the supervisor would do it (as is if
    // writable, else the private cgroup2 mount), then undo.
    let (cgroup_writable, cgroup_mount, cgroup_mount_method) = if write {
        let (ok, attempts, method) = crate::limits::prove_writable(
            &delegation,
            &input.cgroup_mount,
            std::path::Path::new(crate::limits::PRIVATE_CGROUP_MOUNT),
            cg_rel.as_deref().unwrap_or("/"),
            &crate::limits::SysMounter,
        );
        (Some(ok), Some(attempts), method)
    } else {
        (None, None, None)
    };
    // SAFETY: fork in a single-threaded process; the child only calls
    // async-signal-safe functions and _exit.
    let userns = unsafe {
        match libc::fork() {
            0 => {
                let rc = libc::unshare(libc::CLONE_NEWUSER);
                libc::_exit(if rc == 0 { 0 } else { 1 });
            }
            -1 => false,
            pid => {
                let mut st = 0;
                libc::waitpid(pid, &mut st, 0);
                libc::WIFEXITED(st) && libc::WEXITSTATUS(st) == 0
            }
        }
    };
    // SAFETY: pidfd_open on ourselves; close the fd right away.
    let pidfd = unsafe {
        let fd = libc::syscall(libc::SYS_pidfd_open, libc::getpid(), 0);
        if fd >= 0 {
            libc::close(fd as i32);
        }
        fd >= 0
    };
    let landlock_abi = crate::supervisor::landlock_abi();
    let identity = crate::identity::check_with_policy(input.uid_base, input.uid_slots, input.require_landlock, input.trusted_local);
    let modes: Vec<ModeChoice> = [CgroupPolicy::Auto, CgroupPolicy::Require, CgroupPolicy::Off]
        .into_iter()
        .map(|p| choose(p, &delegation, cgroup_writable, &identity))
        .collect();
    let selected = choose(input.policy, &delegation, cgroup_writable, &identity);
    let auto = &modes[0];
    let recommended = match auto.mode {
        None => format!("unsupported: {}", auto.why),
        Some(LimitsMode::CgroupV2) => "pooled: cgroup_v2 limits + watchdog".to_owned(),
        // NAN-3523: a pooled cell refuses tenants without kernel limits.
        Some(LimitsMode::Watchdog) => "dedicated: watchdog limits (no cgroup delegation; a pooled cell would refuse tenants)".to_owned(),
    };
    let capacity = crate::resources::detect_capacity(&input.resources, delegation.root.as_deref());
    ProbeReport {
        kernel,
        // SAFETY: geteuid never fails.
        euid: unsafe { libc::geteuid() },
        cap_eff: format!("{caps:016x}"),
        has_cap_setuid: bit(7),
        has_cap_setgid: bit(6),
        has_cap_chown: bit(0),
        landlock_abi,
        seccomp_filter_supported: seccomp,
        cgroup_v2_path: cg_rel,
        cgroup_controllers: controllers,
        cgroup_writable,
        cgroup_mount,
        cgroup_mount_method,
        unprivileged_userns: userns,
        max_user_namespaces: read_trim("/proc/sys/user/max_user_namespaces").and_then(|s| s.parse().ok()),
        apparmor_restrict_unprivileged_userns: read_trim("/proc/sys/kernel/apparmor_restrict_unprivileged_userns")
            .and_then(|s| s.parse().ok()),
        pidfd,
        has_cap_fowner: bit(3),
        has_cap_kill: bit(5),
        recommended,
        delegation,
        identity,
        selected,
        modes,
        capacity,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn check(reasons: &[&str]) -> DelegationCheck {
        DelegationCheck {
            unified: true,
            root: Some("/sys/fs/cgroup".into()),
            read_only_mount: !reasons.is_empty(),
            owner_uid: Some(65534),
            writable: reasons.is_empty(),
            owned_by_us: reasons.is_empty(),
            needs_mount: false,
            controllers: vec!["cpu".into(), "memory".into(), "pids".into()],
            memory_controller: true,
            reasons: reasons.iter().map(|s| s.to_string()).collect(),
        }
    }

    fn ident(fatal: &[&str]) -> IdentityReport {
        crate::identity::IdentityReport {
            euid: 0,
            cap_eff: "0".into(),
            missing_caps: vec![],
            has_cap_sys_nice: false,
            user_namespace: true,
            tenant_uid_range: (20_000, 60_000),
            tenant_ids_mapped: true,
            landlock_abi: 4,
            fatal: fatal.iter().map(|s| s.to_string()).collect(),
        }
    }

    #[test]
    fn the_staging_5a_pod_picks_watchdog_under_auto_and_refuses_require() {
        // /sys/fs/cgroup RO and owned by 65534 (the 5A probe facts).
        let ro = check(&["cgroup mount is read-only"]);
        let auto = choose(CgroupPolicy::Auto, &ro, None, &ident(&[]));
        assert_eq!(auto.mode, Some(LimitsMode::Watchdog));
        assert!(auto.why.contains("read-only"), "{}", auto.why);
        let req = choose(CgroupPolicy::Require, &ro, None, &ident(&[]));
        assert_eq!(req.mode, None);
        assert!(req.why.starts_with("refuses to start"));
        // Delegator present: writable.
        let ok = check(&[]);
        assert_eq!(choose(CgroupPolicy::Auto, &ok, Some(true), &ident(&[])).mode, Some(LimitsMode::CgroupV2));
        assert_eq!(choose(CgroupPolicy::Require, &ok, Some(true), &ident(&[])).mode, Some(LimitsMode::CgroupV2));
        // Writable-looking but mkdir failed under --write: not delegated.
        assert_eq!(choose(CgroupPolicy::Auto, &ok, Some(false), &ident(&[])).mode, Some(LimitsMode::Watchdog));
        assert_eq!(choose(CgroupPolicy::Off, &ok, Some(true), &ident(&[])).mode, Some(LimitsMode::Watchdog));
        // Identity failures refuse every policy.
        let bad = choose(CgroupPolicy::Auto, &ok, None, &ident(&["missing capabilities: KILL"]));
        assert_eq!(bad.mode, None);
        assert!(bad.why.contains("KILL"));
    }

    #[test]
    fn probe_runs_here() {
        let r = run(&ProbeInput::default());
        assert_eq!(r.modes.len(), 3);
        assert!(r.capacity.cpu_millicores > 0);
        serde_json::to_string(&r).unwrap();
    }
}
