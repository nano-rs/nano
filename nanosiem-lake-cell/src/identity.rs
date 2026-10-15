// SPDX-License-Identifier: AGPL-3.0-or-later

//! Supervisor identity preflight (NAN-2872).
//!
//! Every tenant role runs under its own uid/gid inside the pod's user
//! namespace (see `uidmap.rs`; the jail does the `setresuid`/`setresgid`).
//! For that the supervisor needs, and checks at startup:
//!
//! - `CAP_SETUID` + `CAP_SETGID`: the credential drop in the child;
//! - `CAP_CHOWN` + `CAP_FOWNER`: creating and repairing tenant directories
//!   owned by tenant uids;
//! - `CAP_KILL`: signalling processes of other uids (stall/limit kills, the
//!   watchdog's SIGSTOP/SIGCONT throttle). Without it the watchdog cannot
//!   enforce anything, so it is required too;
//! - the tenant uid range mapped in the user namespace (`/proc/self/uid_map`
//!   and `gid_map`), else `setresuid` fails with EINVAL at the first spawn;
//! - landlock: in a user-namespaced pod (mode 5A) a missing landlock ABI is
//!   fatal whatever `require_landlock` says, since uid separation alone
//!   leaves every world-readable path shared.

use serde::Serialize;

pub const CAP_CHOWN: u32 = 0;
pub const CAP_FOWNER: u32 = 3;
pub const CAP_KILL: u32 = 5;
pub const CAP_SETGID: u32 = 6;
pub const CAP_SETUID: u32 = 7;
pub const CAP_SYS_NICE: u32 = 23;

pub const REQUIRED_CAPS: [(u32, &str); 5] =
    [(CAP_SETUID, "SETUID"), (CAP_SETGID, "SETGID"), (CAP_CHOWN, "CHOWN"), (CAP_FOWNER, "FOWNER"), (CAP_KILL, "KILL")];

/// `CapEff:` from `/proc/<pid>/status`.
pub fn parse_cap_eff(status: &str) -> u64 {
    status
        .lines()
        .find_map(|l| l.strip_prefix("CapEff:").map(|v| v.trim().to_owned()))
        .and_then(|h| u64::from_str_radix(&h, 16).ok())
        .unwrap_or(0)
}

pub fn missing_caps(cap_eff: u64) -> Vec<&'static str> {
    REQUIRED_CAPS.iter().filter(|(bit, _)| cap_eff & (1u64 << bit) == 0).map(|(_, n)| *n).collect()
}

/// `/proc/self/uid_map` lines: (inside, outside, count).
pub fn parse_id_map(s: &str) -> Vec<(u64, u64, u64)> {
    s.lines()
        .filter_map(|l| {
            let mut it = l.split_whitespace().map(|x| x.parse::<u64>().ok());
            Some((it.next()??, it.next()??, it.next()??))
        })
        .collect()
}

/// The initial user namespace maps all 2^32 ids onto themselves.
pub fn is_initial_userns(map: &[(u64, u64, u64)]) -> bool {
    map == [(0, 0, 4_294_967_295)]
}

/// Is `[start, start + len)` inside the union of the map's inside ranges?
pub fn range_mapped(map: &[(u64, u64, u64)], start: u64, len: u64) -> bool {
    let mut ranges: Vec<(u64, u64)> = map.iter().map(|(i, _, c)| (*i, i + c)).collect();
    ranges.sort();
    let (mut cur, end) = (start, start + len);
    for (a, b) in ranges {
        if a <= cur && cur < b {
            cur = b;
        }
        if cur >= end {
            return true;
        }
    }
    cur >= end
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct IdentityReport {
    pub euid: u32,
    pub cap_eff: String,
    pub missing_caps: Vec<&'static str>,
    pub has_cap_sys_nice: bool,
    pub user_namespace: bool,
    pub tenant_uid_range: (u32, u32),
    pub tenant_ids_mapped: bool,
    pub landlock_abi: i32,
    /// Fatal problems (empty = ok).
    pub fatal: Vec<String>,
}

/// Evaluate the identity preconditions from raw inputs (pure; unit-tested).
#[allow(clippy::too_many_arguments)]
pub fn evaluate(
    euid: u32,
    cap_eff: u64,
    uid_map: &str,
    gid_map: &str,
    uid_base: u32,
    uid_slots: u32,
    landlock_abi: i32,
    require_landlock: bool,
) -> IdentityReport {
    evaluate_with_policy(euid, cap_eff, uid_map, gid_map, uid_base, uid_slots, landlock_abi, require_landlock, false)
}

/// The sole exception to the hosted user-namespace Landlock requirement is
/// an explicitly configured trusted-local, dedicated cell.
#[allow(clippy::too_many_arguments)]
pub fn evaluate_with_policy(
    euid: u32, cap_eff: u64, uid_map: &str, gid_map: &str,
    uid_base: u32, uid_slots: u32, landlock_abi: i32,
    require_landlock: bool, trusted_local: bool,
) -> IdentityReport {
    let umap = parse_id_map(uid_map);
    let gmap = parse_id_map(gid_map);
    let user_namespace = !is_initial_userns(&umap);
    let len = uid_slots as u64 * 2;
    let mapped = range_mapped(&umap, uid_base as u64, len) && range_mapped(&gmap, uid_base as u64, len);
    let missing = missing_caps(cap_eff);
    let mut fatal = Vec::new();
    if euid != 0 {
        fatal.push(format!("supervisor must run as uid 0 in its user namespace (euid {euid})"));
    }
    if !missing.is_empty() {
        fatal.push(format!("missing capabilities: {}", missing.join(", ")));
    }
    if !mapped {
        fatal.push(format!(
            "tenant ids {uid_base}..{} are not all mapped in this user namespace",
            uid_base as u64 + len
        ));
    }
    if landlock_abi <= 0 && (require_landlock || (user_namespace && !trusted_local)) {
        fatal.push(if user_namespace {
            "landlock unavailable: fatal in a user-namespaced pod (5A)".to_owned()
        } else {
            "landlock is required but unavailable on this kernel".to_owned()
        });
    }
    IdentityReport {
        euid,
        cap_eff: format!("{cap_eff:016x}"),
        missing_caps: missing,
        has_cap_sys_nice: cap_eff & (1u64 << CAP_SYS_NICE) != 0,
        user_namespace,
        tenant_uid_range: (uid_base, (uid_base as u64 + len).min(u32::MAX as u64) as u32),
        tenant_ids_mapped: mapped,
        landlock_abi,
        fatal,
    }
}

/// Evaluate for the running process.
pub fn check(uid_base: u32, uid_slots: u32, require_landlock: bool) -> IdentityReport {
    check_with_policy(uid_base, uid_slots, require_landlock, false)
}

pub fn check_with_policy(uid_base: u32, uid_slots: u32, require_landlock: bool, trusted_local: bool) -> IdentityReport {
    let status = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
    let read = |p: &str| std::fs::read_to_string(p).unwrap_or_default();
    evaluate_with_policy(
        // SAFETY: geteuid never fails.
        unsafe { libc::geteuid() },
        parse_cap_eff(&status),
        &read("/proc/self/uid_map"),
        &read("/proc/self/gid_map"),
        uid_base,
        uid_slots,
        crate::supervisor::landlock_abi(),
        require_landlock,
        trusted_local,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALL: u64 = (1 << CAP_SETUID) | (1 << CAP_SETGID) | (1 << CAP_CHOWN) | (1 << CAP_FOWNER) | (1 << CAP_KILL);
    const HOST: &str = "         0          0 4294967295\n";
    const POD: &str = "         0 1234567890      65536\n";

    #[test]
    fn caps() {
        assert_eq!(parse_cap_eff("Name: x\nCapEff:\t00000000000000e1\n"), 0xe1);
        assert!(missing_caps(ALL).is_empty());
        // The 5A probe pod: SYS_ADMIN only.
        assert_eq!(missing_caps(1 << 21), vec!["SETUID", "SETGID", "CHOWN", "FOWNER", "KILL"]);
        // What the renderer adds today (no KILL): still fatal.
        let rendered = (1 << 21) | (1 << CAP_SETUID) | (1 << CAP_SETGID) | (1 << CAP_CHOWN) | (1 << CAP_FOWNER);
        assert_eq!(missing_caps(rendered), vec!["KILL"]);
    }

    #[test]
    fn id_maps() {
        let m = parse_id_map(POD);
        assert_eq!(m, vec![(0, 1234567890, 65536)]);
        assert!(!is_initial_userns(&m) && is_initial_userns(&parse_id_map(HOST)));
        assert!(range_mapped(&m, 20_000, 40_000));
        assert!(!range_mapped(&m, 20_000, 46_000));
        // Split maps (unshare --map-root-user --map-users=1:…) are unioned.
        let split = parse_id_map("0 1000 1\n1 100000 65535\n");
        assert!(range_mapped(&split, 20_000, 40_000));
        assert!(range_mapped(&split, 0, 65_536));
        assert!(!range_mapped(&split, 0, 65_537));
    }

    #[test]
    fn trusted_local_landlock_is_opportunistic_only() {
        assert!(evaluate_with_policy(0, ALL, POD, POD, 20_000, 100, 0, false, true).fatal.is_empty());
        assert!(!evaluate_with_policy(0, ALL, POD, POD, 20_000, 100, 0, true, true).fatal.is_empty());
        assert!(!evaluate_with_policy(0, 0, POD, POD, 20_000, 100, 0, false, true).fatal.is_empty());
        assert!(!evaluate_with_policy(0, ALL, POD, POD, 65_500, 100, 0, false, true).fatal.is_empty());
        assert!(evaluate_with_policy(0, ALL, POD, POD, 20_000, 100, 4, false, true).fatal.is_empty());
    }

    #[test]
    fn preflight_verdicts() {
        let ok = evaluate(0, ALL, POD, POD, 20_000, 20_000, 4, true);
        assert!(ok.fatal.is_empty(), "{:?}", ok.fatal);
        assert!(ok.user_namespace && ok.tenant_ids_mapped);
        // 5A without landlock: fatal even with require_landlock = false.
        let r = evaluate(0, ALL, POD, POD, 20_000, 20_000, 0, false);
        assert!(r.fatal.iter().any(|f| f.contains("5A")), "{:?}", r.fatal);
        // Host userns, landlock not required: allowed.
        assert!(evaluate(0, ALL, HOST, HOST, 20_000, 20_000, 0, false).fatal.is_empty());
        // Range beyond the pod's 65536 ids.
        let r = evaluate(0, ALL, POD, POD, 40_000, 20_000, 4, true);
        assert!(r.fatal.iter().any(|f| f.contains("not all mapped")), "{:?}", r.fatal);
        let r = evaluate(1000, 0, POD, POD, 20_000, 100, 4, true);
        assert_eq!(r.fatal.len(), 2, "{:?}", r.fatal);
    }
}
