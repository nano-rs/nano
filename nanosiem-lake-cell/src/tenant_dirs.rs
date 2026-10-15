// SPDX-License-Identifier: AGPL-3.0-or-later

//! Tenant directory tree creation and repair under the cell's exact
//! capability set (FRO-737 mode 5A): CHOWN, FOWNER, KILL, SETGID, SETUID,
//! SYS_ADMIN, and nothing else.
//!
//! Without DAC_OVERRIDE / DAC_READ_SEARCH / FSETID the supervisor, although
//! it is uid 0 in its user namespace, can neither read nor search a
//! directory it has handed to a tenant uid, and a `chmod` it performs on a
//! directory whose gid is not its own silently drops the setgid bit. So:
//!
//! - Directories are opened `O_PATH|O_DIRECTORY|O_NOFOLLOW` (no read or
//!   search permission needed on the directory itself; no symlink is ever
//!   followed), and every later operation goes through that fd:
//!   `fchownat(fd, "", AT_EMPTY_PATH)` and `chmod("/proc/self/fd/N")`
//!   (`fchown`/`fchmod` on an `O_PATH` fd are `EBADF`).
//! - A directory the supervisor still owns is filled (children created)
//!   **before** its mode is set and it is chowned to the tenant; `chmod`
//!   runs while the gid is still the supervisor's so setgid sticks, and a
//!   directory `chown` keeps setgid.
//! - A directory already handed to its tenant uid (a restart, or partial
//!   state from an earlier failed pass) is repaired *as that uid*: the
//!   thread's fsuid/fsgid are switched to the owner (CAP_SETUID/SETGID), so
//!   ordinary owner permissions apply — no DAC bypass is needed and the
//!   owner's `chmod` keeps setgid because the fsgid matches.
//! - A directory owned by ANOTHER LIVE TENANT's uid or gid (NAN-3875: the
//!   uid map was lost and slots were handed out in a different order) is
//!   never reclaimed: the walk fails and the tenant does not start
//!   ([`OwnerVerdict::Foreign`]). Zero cross-tenant sharing beats
//!   availability; the operator fixes the map, never the reclaim.
//! - A directory owned by anyone else (root, a stale slot's uid that no
//!   tenant holds, an earlier layout) is reclaimed with CAP_CHOWN first, and its non-tree contents
//!   still owned by that previous uid are re-owned to the directory's final
//!   owner (see [`reown_contents`]).
//! - Mode (and, for setgid directories, group) are fixed **before**
//!   descending, so a directory left 0000/0500 by a crash or a stale slot
//!   cannot block creating its children.
//!
//! fsuid/fsgid are per-thread. Every public entry point runs the whole walk
//! on a fresh, dedicated OS thread that exits when the walk ends, so the
//! switched identity can never be observed by another task or thread even
//! if a future change adds an `.await` or a callback; [`FsCred`] is also
//! `!Send` and restores on drop (including unwind).

use crate::contract::Role;
use crate::uidmap::TenantIds;
use std::collections::BTreeSet;
use std::ffi::CString;
use std::io;
use std::marker::PhantomData;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

/// Directory depth [`reown_contents`] descends before giving up on a
/// subtree (logged, left as is).
const REOWN_MAX_DEPTH: usize = 32;

/// One directory of the tree to ensure, with its final owner and mode.
/// Children of a directory handed to another uid must share that owner:
/// they are repaired as that uid, which cannot chown to anyone else.
#[derive(Debug, Clone)]
pub struct DirSpec {
    name: String,
    uid: u32,
    gid: u32,
    mode: u32,
    children: Vec<DirSpec>,
}

impl DirSpec {
    pub fn new(name: impl Into<String>, uid: u32, gid: u32, mode: u32) -> Self {
        Self { name: name.into(), uid, gid, mode, children: Vec::new() }
    }

    pub fn child(mut self, c: DirSpec) -> Self {
        self.children.push(c);
        self
    }
}

/// The filesystem identity the current thread acts as.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Acting {
    uid: u32,
    gid: u32,
}

fn euid_egid() -> (u32, u32) {
    // SAFETY: geteuid/getegid never fail.
    unsafe { (libc::geteuid(), libc::getegid()) }
}

fn ctx(what: &str, name: &str, e: io::Error) -> io::Error {
    io::Error::new(e.kind(), format!("{what} {name}: {e}"))
}

fn cstr(s: &str) -> io::Result<CString> {
    CString::new(s).map_err(io::Error::other)
}

/// Run `f` on a fresh OS thread and wait for it. The fsuid/fsgid switches
/// in [`ensure_at`] are per-thread; confining them to a thread that exits
/// afterwards makes it structurally impossible for them to leak onto a
/// runtime worker (or anything else) even if a switch were not undone.
fn on_dedicated_thread<T: Send>(f: impl FnOnce() -> io::Result<T> + Send) -> io::Result<T> {
    std::thread::scope(|s| {
        let h = std::thread::Builder::new().name("tenant-dirs".into()).spawn_scoped(s, f)?;
        h.join().unwrap_or_else(|_| Err(io::Error::other("tenant-dirs thread panicked")))
    })
}

/// Open an existing directory by path (the configured, trusted prefix),
/// `O_PATH` so no read permission is needed.
fn open_path_dir(path: &Path) -> io::Result<OwnedFd> {
    let c = CString::new(path.as_os_str().as_bytes()).map_err(io::Error::other)?;
    // SAFETY: open on a valid C string; the fd is owned immediately.
    let fd = unsafe { libc::open(c.as_ptr(), libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC) };
    if fd < 0 {
        let e = io::Error::last_os_error();
        return Err(io::Error::new(e.kind(), format!("{}: {e}", path.display())));
    }
    // SAFETY: fd is a fresh, valid descriptor we own.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// `openat(dir, name, O_PATH|O_NOFOLLOW|extra)`: never follows a symlink at
/// `name` (with `O_DIRECTORY` in `extra`, a symlink is ENOTDIR).
fn open_beneath(dir: BorrowedFd<'_>, name: &CString, extra: libc::c_int) -> io::Result<OwnedFd> {
    // SAFETY: openat on a valid dirfd and C string; the fd is owned immediately.
    let fd = unsafe { libc::openat(dir.as_raw_fd(), name.as_ptr(), libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC | extra) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: fd is a fresh, valid descriptor we own.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

fn fstat(fd: BorrowedFd<'_>) -> io::Result<libc::stat> {
    // SAFETY: zeroed stat is a valid out-buffer; fstat on O_PATH fds is supported.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(fd.as_raw_fd(), &mut st) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(st)
}

/// chown the inode behind an `O_PATH` fd itself (a symlink fd changes the
/// link, never its target).
fn fchown_fd(fd: BorrowedFd<'_>, uid: u32, gid: u32) -> io::Result<()> {
    // SAFETY: empty path + AT_EMPTY_PATH operates on the (O_PATH) fd itself.
    let r = unsafe {
        libc::fchownat(fd.as_raw_fd(), c"".as_ptr(), uid, gid, libc::AT_EMPTY_PATH | libc::AT_SYMLINK_NOFOLLOW)
    };
    if r != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn proc_fd_path(fd: BorrowedFd<'_>) -> String {
    format!("/proc/self/fd/{}", fd.as_raw_fd())
}

/// `chmod` the inode behind an `O_PATH` fd via its `/proc/self/fd` link:
/// the magic link resolves to the inode itself, never re-walking a path a
/// tenant could have swapped.
fn fchmod_fd(fd: BorrowedFd<'_>, mode: u32) -> io::Result<()> {
    let p = cstr(&proc_fd_path(fd))?;
    // SAFETY: chmod on a valid C string.
    if unsafe { libc::chmod(p.as_ptr(), mode as libc::mode_t) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Switch this thread's fsuid/fsgid; restored on drop (LIFO when nested,
/// and on unwind). `!Send`: it cannot be held across an `.await` in a
/// spawned future, and the walk that uses it runs on a dedicated thread.
pub(crate) struct FsCred {
    prev_uid: u32,
    prev_gid: u32,
    _thread_bound: PhantomData<*const ()>,
}

impl FsCred {
    pub(crate) fn assume(uid: u32, gid: u32) -> io::Result<Self> {
        // setfs[ug]id never report errors; a call with an invalid id (-1)
        // returns the current value, which is how a refusal is detected.
        // SAFETY: plain per-thread credential syscalls.
        unsafe {
            let prev_gid = libc::setfsgid(gid) as u32;
            if libc::setfsgid(u32::MAX) as u32 != gid {
                libc::setfsgid(prev_gid);
                return Err(io::Error::new(io::ErrorKind::PermissionDenied, format!("setfsgid({gid}) refused (CAP_SETGID?)")));
            }
            let prev_uid = libc::setfsuid(uid) as u32;
            if libc::setfsuid(u32::MAX) as u32 != uid {
                libc::setfsuid(prev_uid);
                libc::setfsgid(prev_gid);
                return Err(io::Error::new(io::ErrorKind::PermissionDenied, format!("setfsuid({uid}) refused (CAP_SETUID?)")));
            }
            Ok(Self { prev_uid, prev_gid, _thread_bound: PhantomData })
        }
    }
}

impl Drop for FsCred {
    fn drop(&mut self) {
        // Restoring fsuid 0 raises every fs-set capability present in the
        // permitted set back into the effective set (kernel semantics);
        // under the cell's caps effective == permitted, so this is exactly
        // the state before `assume`.
        // SAFETY: plain per-thread credential syscalls.
        unsafe {
            libc::setfsuid(self.prev_uid);
            libc::setfsgid(self.prev_gid);
        }
    }
}

/// What [`ensure_at`] may do with an existing directory, from its owner.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OwnerVerdict {
    /// Owned by the walk's current identity: work in it directly.
    Acting,
    /// Already handed to its final owner: repair it as that owner.
    Final,
    /// Root, a stale/unknown uid, or an earlier layout: reclaim (CAP_CHOWN).
    Reclaim,
    /// Owned (uid or gid) by another tenant the cell holds: refuse.
    Foreign,
}

/// NAN-3875: the owner decision, pure so it is tested without CAP_CHOWN.
/// `foreign` is every id the cell's OTHER tenants hold
/// ([`crate::uidmap::UidMap::foreign_ids`]); a gid is checked too, since
/// tenant roots are group-readable by their tenant gid.
pub fn owner_verdict(st_uid: u32, st_gid: u32, acting_uid: u32, spec_uid: u32, foreign: &BTreeSet<u32>) -> OwnerVerdict {
    if foreign.contains(&st_uid) || foreign.contains(&st_gid) {
        OwnerVerdict::Foreign
    } else if st_uid == acting_uid {
        OwnerVerdict::Acting
    } else if st_uid == spec_uid {
        OwnerVerdict::Final
    } else {
        OwnerVerdict::Reclaim
    }
}

/// Marker carried by every foreign-owner refusal (survives the context the
/// walk adds on the way up); see [`is_foreign_owner`].
const FOREIGN_OWNER_MARK: &str = "is owned by another placed tenant's id";

fn foreign_owner(what: &str, name: &str, uid: u32, gid: u32) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, format!(
        "{what} {name} {FOREIGN_OWNER_MARK} ({uid}:{gid}); refusing to reclaim it"))
}

/// Did a guarded walk refuse because part of the tree belongs to another
/// placed tenant (as opposed to an I/O or permission failure)?
pub fn is_foreign_owner(e: &io::Error) -> bool {
    e.kind() == io::ErrorKind::PermissionDenied && e.to_string().contains(FOREIGN_OWNER_MARK)
}

/// After reclaiming a directory from a foreign owner, hand its contents
/// that still belong to that previous uid (`old_uid`) to the directory's
/// final owner. Runs as the supervisor (we own `dir` with u+rwx now).
///
/// - Entries named in `skip` (tree children) are left to their own spec.
/// - Entries owned by anyone other than `old_uid` are left untouched: the
///   pass never widens who owns a file that was not the stale owner's.
/// - Non-directories with more than one link are skipped: a hard link
///   planted by the previous owner must not hand an inode elsewhere to the
///   new owner.
/// - Symlinks are re-owned themselves (never followed).
/// - Subdirectories are taken over (so we can list them without
///   DAC_READ_SEARCH), recursed, restored to their exact mode, then handed
///   to the final owner.
fn reown_contents(dir: BorrowedFd<'_>, skip: &[&str], old_uid: u32, to: (u32, u32), acting: Acting, depth: usize,
    foreign: &BTreeSet<u32>) -> io::Result<()> {
    let names: Vec<std::ffi::OsString> =
        std::fs::read_dir(proc_fd_path(dir))?.map(|e| e.map(|e| e.file_name())).collect::<io::Result<_>>()?;
    for name in names {
        let Some(n) = name.to_str() else {
            tracing::warn!(name = ?name, "reclaim: skipping non-UTF-8 entry");
            continue;
        };
        if skip.contains(&n) {
            continue;
        }
        let c = cstr(n)?;
        let fd = match open_beneath(dir, &c, 0) {
            Ok(fd) => fd,
            // Raced away (only the supervisor can change this dir now, but
            // be tolerant): nothing to re-own.
            Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
            Err(e) => return Err(ctx("reclaim open", n, e)),
        };
        let st = fstat(fd.as_fd()).map_err(|e| ctx("reclaim stat", n, e))?;
        if foreign.contains(&st.st_uid) || foreign.contains(&st.st_gid) {
            return Err(foreign_owner("reclaim entry", n, st.st_uid, st.st_gid));
        }
        if st.st_uid != old_uid {
            tracing::warn!(entry = n, owner = st.st_uid, stale = old_uid, "reclaim: leaving entry not owned by the stale owner");
            continue;
        }
        if st.st_mode & libc::S_IFMT == libc::S_IFDIR {
            if depth >= REOWN_MAX_DEPTH {
                tracing::warn!(entry = n, "reclaim: directory tree too deep; left as is");
                continue;
            }
            let mode = st.st_mode & 0o7777;
            fchown_fd(fd.as_fd(), acting.uid, acting.gid).map_err(|e| ctx("reclaim chown", n, e))?;
            if mode & 0o700 != 0o700 {
                fchmod_fd(fd.as_fd(), mode | 0o700).map_err(|e| ctx("reclaim chmod", n, e))?;
            }
            reown_contents(fd.as_fd(), &[], old_uid, to, acting, depth + 1, foreign)?;
            // Exact original mode (setgid sticks: the gid is ours), then
            // hand over (a directory chown keeps setgid).
            fchmod_fd(fd.as_fd(), mode).map_err(|e| ctx("reclaim chmod", n, e))?;
            fchown_fd(fd.as_fd(), to.0, to.1).map_err(|e| ctx("reclaim chown", n, e))?;
        } else if st.st_nlink > 1 {
            tracing::warn!(entry = n, links = st.st_nlink, "reclaim: leaving multiply-linked entry with its stale owner");
        } else {
            fchown_fd(fd.as_fd(), to.0, to.1).map_err(|e| ctx("reclaim chown", n, e))?;
        }
    }
    Ok(())
}

/// Ensure `spec` (and its subtree) beneath the directory `parent`, on the
/// calling thread. Only ever reached through [`on_dedicated_thread`] (and
/// directly by the tests that assert credential restore).
fn ensure_at(parent: BorrowedFd<'_>, spec: &DirSpec, acting: Acting, foreign: &BTreeSet<u32>) -> io::Result<()> {
    let name = spec.name.as_str();
    if name.is_empty() || name == "." || name == ".." || name.contains('/') {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, format!("bad directory name {name:?}")));
    }
    if spec.mode & 0o700 != 0o700 {
        // The walk works inside each directory with owner permissions.
        return Err(io::Error::new(io::ErrorKind::InvalidInput, format!("{name}: mode {:o} lacks u+rwx", spec.mode)));
    }
    debug_assert!(
        spec.children.iter().all(|c| spec.uid == acting.uid || (c.uid == spec.uid && c.gid == spec.gid)),
        "{name}: children of a handed-over directory must share its owner"
    );
    let c = cstr(name)?;
    // SAFETY: mkdirat on a valid dirfd and C string.
    if unsafe { libc::mkdirat(parent.as_raw_fd(), c.as_ptr(), 0o700) } != 0 {
        let e = io::Error::last_os_error();
        if e.kind() != io::ErrorKind::AlreadyExists {
            return Err(ctx("mkdir", name, e));
        }
    }
    let fd = open_beneath(parent, &c, libc::O_DIRECTORY)
        .map_err(|e| io::Error::new(e.kind(), format!("open {name}: {e} (not a plain directory?)")))?;
    let st = fstat(fd.as_fd()).map_err(|e| ctx("stat", name, e))?;
    let want_sgid = spec.mode & libc::S_ISGID != 0;

    // Who can work inside this directory with plain owner permissions?
    let _cred;
    let mut reclaimed_from = None;
    let inner = match owner_verdict(st.st_uid, st.st_gid, acting.uid, spec.uid, foreign) {
        // Another live tenant's files (NAN-3875): fail closed, touch nothing.
        OwnerVerdict::Foreign => {
            tracing::error!(dir = name, owner = st.st_uid, group = st.st_gid, want = spec.uid,
                "tenant directory is owned by another tenant's id; refusing to reclaim it");
            return Err(foreign_owner("directory", name, st.st_uid, st.st_gid));
        }
        OwnerVerdict::Acting => acting,
        OwnerVerdict::Final => {
            // Already handed over: act as its owner.
            _cred = FsCred::assume(spec.uid, spec.gid).map_err(|e| ctx("assume owner of", name, e))?;
            Acting { uid: spec.uid, gid: spec.gid }
        }
        OwnerVerdict::Reclaim => {
            // Root, a stale slot no tenant holds, an earlier layout: reclaim (CAP_CHOWN).
            tracing::warn!(dir = name, owner = st.st_uid, want = spec.uid, "reclaiming tenant directory with an unexpected owner");
            fchown_fd(fd.as_fd(), acting.uid, acting.gid).map_err(|e| ctx("reclaim", name, e))?;
            reclaimed_from = Some(st.st_uid);
            acting
        }
    };
    let final_owner = inner.uid == spec.uid && inner.gid == spec.gid;

    // Group and mode before descending: owner rwx is what lets us create
    // and open children, whatever mode a crash or stale slot left behind.
    // setgid survives our chmod only while the gid is one we act as.
    let st = fstat(fd.as_fd()).map_err(|e| ctx("stat", name, e))?;
    if final_owner {
        if st.st_gid != spec.gid {
            fchown_fd(fd.as_fd(), spec.uid, spec.gid).map_err(|e| ctx("chown", name, e))?;
        }
    } else if want_sgid && st.st_gid != inner.gid {
        fchown_fd(fd.as_fd(), inner.uid, inner.gid).map_err(|e| ctx("chown", name, e))?;
    }
    fchmod_fd(fd.as_fd(), spec.mode).map_err(|e| ctx("chmod", name, e))?;

    if let Some(old_uid) = reclaimed_from {
        let skip: Vec<&str> = spec.children.iter().map(|c| c.name.as_str()).collect();
        reown_contents(fd.as_fd(), &skip, old_uid, (spec.uid, spec.gid), inner, 0, foreign).map_err(|e| ctx("reclaim contents of", name, e))?;
    }

    // Children next: once this directory belongs to the tenant, only the
    // tenant's own identity can create entries in it.
    for child in &spec.children {
        ensure_at(fd.as_fd(), child, inner, foreign)?;
    }

    if !final_owner {
        // Hand over (a directory chown keeps setgid).
        fchown_fd(fd.as_fd(), spec.uid, spec.gid).map_err(|e| ctx("chown", name, e))?;
    }

    let st = fstat(fd.as_fd()).map_err(|e| ctx("stat", name, e))?;
    let got = st.st_mode & 0o7777;
    if st.st_uid != spec.uid || st.st_gid != spec.gid || got & !libc::S_ISGID != spec.mode & !libc::S_ISGID {
        return Err(io::Error::other(format!(
            "{name}: ended {}:{} {got:o}, want {}:{} {:o}",
            st.st_uid, st.st_gid, spec.uid, spec.gid, spec.mode
        )));
    }
    if want_sgid && got & libc::S_ISGID == 0 {
        // Not a security property (tenant processes run with the tenant
        // gid), only group inheritance for files created by other means.
        tracing::warn!(dir = name, "setgid bit could not be set; continuing");
    }
    Ok(())
}

/// Create `path` if needed and set owner/mode through an `O_PATH` fd
/// (never following a symlink at the last component). For the
/// supervisor's own directories. Runs on a dedicated thread.
pub fn ensure_dir(path: &Path, uid: u32, gid: u32, mode: u32) -> io::Result<()> {
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, format!("{}: no file name", path.display())))?;
    let parent = match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    };
    let spec = DirSpec::new(name, uid, gid, mode);
    on_dedicated_thread(|| {
        let pfd = open_path_dir(parent)?;
        let (euid, egid) = euid_egid();
        ensure_at(pfd.as_fd(), &spec, Acting { uid: euid, gid: egid }, &BTreeSet::new())
    })
    .map_err(|e| io::Error::new(e.kind(), format!("{}: {e}", path.display())))
}

/// The tenant tree (see the module docs of `uidmap`):
///
/// ```text
/// <tenants>/<T>          supervisor:gid  0750
/// <T>/parts              ingest:gid      02770  (detect stages signed finding parts)
/// <T>/<role>             role:gid        0700
/// <T>/<role>/tmp         role:gid        0700
/// <T>/product/demand     query:gid       0700  (query[T] → product[T] inbox)
/// ```
/// `<T>/product/<this>`: where query[T] asks product[T] for state it lacks.
pub const PRODUCT_DEMAND_DIR: &str = "demand";

pub fn tenant_tree(tenant: &str, ids: &TenantIds) -> DirSpec {
    let (euid, _) = euid_egid();
    // Ingest owns parts/; detect needs group write to stage signed finding
    // parts (NAN-2916). Query shares the gid but Landlock mounts it read-only.
    let mut root = DirSpec::new(tenant, euid, ids.gid, 0o750).child(DirSpec::new("parts", ids.ingest_uid, ids.gid, 0o2770));
    for role in Role::ALL {
        let uid = ids.uid(role);
        let mut dir = DirSpec::new(role.as_str(), uid, ids.gid, 0o700).child(DirSpec::new("tmp", uid, ids.gid, 0o700));
        if role == Role::Product {
            // NAN-3148: query[T]'s demand inbox (its only write beneath
            // product/; Landlock needs the path to exist at jail time).
            dir = dir.child(DirSpec::new(PRODUCT_DEMAND_DIR, uid, ids.gid, 0o700));
        }
        root = root.child(dir);
    }
    root
}

/// Create or repair `<tenants_dir>/<tenant>` (idempotent; repairs partial
/// state left by earlier failed passes). Blocking; runs the walk on a
/// dedicated thread (call it from `spawn_blocking` in async code).
pub fn ensure_tenant_tree(tenants_dir: &Path, tenant: &str, ids: &TenantIds) -> io::Result<()> {
    ensure_tenant_tree_guarded(tenants_dir, tenant, ids, &BTreeSet::new())
}

/// [`ensure_tenant_tree`] that refuses (fails closed, nothing changed in
/// the offending directory) when any directory of the tree is owned by an
/// id in `foreign`: the other tenants' ids (NAN-3875). The supervisor
/// always calls this one.
pub fn ensure_tenant_tree_guarded(tenants_dir: &Path, tenant: &str, ids: &TenantIds, foreign: &BTreeSet<u32>) -> io::Result<()> {
    if [ids.ingest_uid, ids.query_uid, ids.detect_uid, ids.gid].iter().any(|u| foreign.contains(u)) {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, format!("tenant {tenant}: its own ids overlap another tenant's")));
    }
    let spec = tenant_tree(tenant, ids);
    on_dedicated_thread(|| {
        let pfd = open_path_dir(tenants_dir)?;
        let (euid, egid) = euid_egid();
        ensure_at(pfd.as_fd(), &spec, Acting { uid: euid, gid: egid }, foreign)
    })
    .map_err(|e| io::Error::new(e.kind(), format!("tenant {tenant}: {e}")))
}

// ------------------------------------------------------------------ quarantine (NAN-3875)

/// NAN-3875: take a REBUILDABLE tenant tree (the hot-window volume: reader
/// cache and published product windows, NAN-3647/NAN-3799) whose ownership
/// conflicts with another placed tenant out of reach and delete it, so the
/// caller can recreate it fresh. The tree is first renamed (same
/// filesystem, `RENAME_NOREPLACE`, never following a link) into
/// `quarantine_dir`, a supervisor-private 0700 directory no tenant role is
/// granted (Landlock) and no tenant uid can traverse (DAC). Then it is
/// purged there. A purge failure leaves it in quarantine (unreachable) and
/// is retried by [`sweep_quarantine`]; the caller still gets a fresh tree.
/// Never call this for data of record (parts, ingest state).
pub fn quarantine_tenant_tree(tenants_dir: &Path, tenant: &str, quarantine_dir: &Path) -> io::Result<PurgeBytes> {
    use std::sync::atomic::{AtomicU64, Ordering};
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let name = tenant_name(tenant)?;
    let ms = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis()).unwrap_or(0);
    let aside = format!("q{ms}-{}", SEQ.fetch_add(1, Ordering::Relaxed));
    let aside_c = tenant_name(&aside)?;
    on_dedicated_thread(|| {
        let from = open_path_dir(tenants_dir)?;
        let to = open_path_dir(quarantine_dir)?;
        // SAFETY: renameat2 on valid dirfds and C strings; it renames the
        // entry itself (a symlink is moved, never followed).
        let r = unsafe {
            libc::renameat2(from.as_raw_fd(), name.as_ptr(), to.as_raw_fd(), aside_c.as_ptr(), libc::RENAME_NOREPLACE)
        };
        if r != 0 {
            let e = io::Error::last_os_error();
            return Err(io::Error::new(e.kind(), format!("quarantine {tenant}: {e}")));
        }
        Ok(())
    })?;
    tracing::warn!(tenant, quarantined_as = %aside, "rebuildable tenant tree conflicted with another tenant; quarantined, purging");
    purge_tenant_tree(quarantine_dir, &aside)
}

/// Purge whatever an earlier [`quarantine_tenant_tree`] left behind.
pub fn sweep_quarantine(quarantine_dir: &Path) -> io::Result<usize> {
    let mut n = 0;
    for e in std::fs::read_dir(quarantine_dir)? {
        let name = e?.file_name();
        let Some(name) = name.to_str().filter(|n| n.starts_with('q') && crate::contract::TenantId::new(n).is_ok()) else { continue };
        purge_tenant_tree(quarantine_dir, name)?;
        n += 1;
    }
    Ok(n)
}

// ------------------------------------------------------------------ purge (NAN-3000)

/// Directory depth the purge descends before refusing (the tree is left
/// partly removed and the purge is retried and not reported).
const PURGE_MAX_DEPTH: usize = 64;

/// What a purge removed. `tmp_bytes` counts regular files below any
/// directory named `tmp` (the per-role scratch dirs), `cache_bytes`
/// everything else (parts, spill, reader cache, snapshots, role state).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PurgeBytes {
    pub cache_bytes: u64,
    pub tmp_bytes: u64,
    /// Directory entries removed (files, links, directories).
    pub entries: u64,
}

fn unlink_at(dir: BorrowedFd<'_>, name: &CString, flags: libc::c_int) -> io::Result<()> {
    // SAFETY: unlinkat on a valid dirfd and C string; never follows a
    // symlink at `name` (it removes the link itself).
    if unsafe { libc::unlinkat(dir.as_raw_fd(), name.as_ptr(), flags) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Remove the entry `name` beneath `parent` and, for a directory, all of
/// its contents. Never follows a symlink (links are unlinked themselves),
/// never crosses into another filesystem (a mount point below the tenant
/// root is refused), never leaves `parent`'s subtree: every step is an
/// `*at` call on an fd obtained with `O_NOFOLLOW` from its parent.
///
/// A directory not owned by the supervisor (a tenant role uid, a stale
/// slot) is taken over with CAP_CHOWN and set 0700 first, so it can be
/// listed and emptied without DAC_OVERRIDE / DAC_READ_SEARCH (the 5A caps).
fn purge_entry(parent: BorrowedFd<'_>, name: &CString, root_dev: libc::dev_t, depth: usize, in_tmp: bool,
    acting: Acting, acc: &mut PurgeBytes) -> io::Result<()> {
    let shown = name.to_string_lossy();
    let fd = match open_beneath(parent, name, 0) {
        Ok(fd) => fd,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(ctx("purge open", &shown, e)),
    };
    let st = fstat(fd.as_fd()).map_err(|e| ctx("purge stat", &shown, e))?;
    if st.st_mode & libc::S_IFMT != libc::S_IFDIR {
        // Bytes actually freed: a multiply-linked inode (e.g. a hard link
        // to a sibling's file) survives its unlink here and is not counted.
        let freed = st.st_mode & libc::S_IFMT == libc::S_IFREG && st.st_nlink == 1;
        let bytes = if freed { st.st_size.max(0) as u64 } else { 0 };
        unlink_at(parent, name, 0).map_err(|e| ctx("purge unlink", &shown, e))?;
        if in_tmp { acc.tmp_bytes += bytes } else { acc.cache_bytes += bytes }
        acc.entries += 1;
        return Ok(());
    }
    if st.st_dev != root_dev {
        return Err(io::Error::other(format!("purge: {shown} is a mount point inside the tenant tree; refusing to cross it")));
    }
    if depth >= PURGE_MAX_DEPTH {
        return Err(io::Error::other(format!("purge: {shown}: tenant tree deeper than {PURGE_MAX_DEPTH}")));
    }
    if st.st_uid != acting.uid || st.st_gid != acting.gid {
        fchown_fd(fd.as_fd(), acting.uid, acting.gid).map_err(|e| ctx("purge take over", &shown, e))?;
    }
    // Exactly 0700: owner rwx to list and unlink, and no sticky bit.
    if st.st_mode & 0o7777 != 0o700 || st.st_uid != acting.uid {
        fchmod_fd(fd.as_fd(), 0o700).map_err(|e| ctx("purge chmod", &shown, e))?;
    }
    let names: Vec<std::ffi::OsString> = std::fs::read_dir(proc_fd_path(fd.as_fd()))
        .map_err(|e| ctx("purge list", &shown, e))?
        .map(|e| e.map(|e| e.file_name()))
        .collect::<io::Result<_>>()
        .map_err(|e| ctx("purge list", &shown, e))?;
    let tmp_here = in_tmp || name.as_bytes() == b"tmp";
    for child in names {
        let c = CString::new(child.as_bytes()).map_err(io::Error::other)?;
        purge_entry(fd.as_fd(), &c, root_dev, depth + 1, tmp_here, acting, acc)?;
    }
    drop(fd);
    unlink_at(parent, name, libc::AT_REMOVEDIR).map_err(|e| ctx("purge rmdir", &shown, e))?;
    acc.entries += 1;
    Ok(())
}

fn tenant_name(tenant: &str) -> io::Result<CString> {
    // Callers pass a validated `TenantId`; re-check here, since the name is
    // the only thing between this walk and a sibling tenant's tree.
    if crate::contract::TenantId::new(tenant).is_err() {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, format!("bad tenant name {tenant:?}")));
    }
    cstr(tenant)
}

/// Remove `<tenants_dir>/<tenant>` and everything below it (NAN-3000). Only
/// that one entry of `tenants_dir` is touched: sibling tenants, symlink
/// targets and other filesystems are never reached. Idempotent (an absent
/// tree is `Ok` with zero bytes). Blocking; runs on a dedicated thread.
///
/// The tenant's processes must already be gone (drained and verified):
/// the walk is not designed to race a live tenant writing into its tree.
pub fn purge_tenant_tree(tenants_dir: &Path, tenant: &str) -> io::Result<PurgeBytes> {
    let name = tenant_name(tenant)?;
    on_dedicated_thread(|| {
        let pfd = open_path_dir(tenants_dir)?;
        let root_dev = fstat(pfd.as_fd())?.st_dev;
        let (euid, egid) = euid_egid();
        let mut acc = PurgeBytes::default();
        purge_entry(pfd.as_fd(), &name, root_dev, 0, false, Acting { uid: euid, gid: egid }, &mut acc)?;
        Ok(acc)
    })
    .map_err(|e| io::Error::new(e.kind(), format!("purge {tenant}: {e}")))
}

/// Does `<tenants_dir>/<tenant>/<sub>` hold any entry? Read-only: the walk
/// acts as the directory's owner (fsuid/fsgid, on a dedicated thread), so
/// nothing is taken over or re-moded. `Ok(false)` when absent.
pub fn tenant_subdir_nonempty(tenants_dir: &Path, tenant: &str, sub: &str) -> io::Result<bool> {
    let name = tenant_name(tenant)?;
    let sub_c = cstr(sub)?;
    if sub.is_empty() || sub.contains('/') || sub == "." || sub == ".." {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, format!("bad subdirectory {sub:?}")));
    }
    on_dedicated_thread(|| {
        let pfd = open_path_dir(tenants_dir)?;
        let root = match open_beneath(pfd.as_fd(), &name, libc::O_DIRECTORY) {
            Ok(fd) => fd,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(false),
            Err(e) => return Err(e),
        };
        let open_as_owner = |parent: BorrowedFd<'_>, c: &CString| -> io::Result<Option<(OwnedFd, libc::stat)>> {
            match open_beneath(parent, c, libc::O_DIRECTORY) {
                Ok(fd) => {
                    let st = fstat(fd.as_fd())?;
                    Ok(Some((fd, st)))
                }
                Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
                Err(e) => Err(e),
            }
        };
        let root_st = fstat(root.as_fd())?;
        // The tenant root is the supervisor's (0750); `sub` belongs to a role uid.
        let _root_cred = if root_st.st_uid != euid_egid().0 { Some(FsCred::assume(root_st.st_uid, root_st.st_gid)?) } else { None };
        let Some((fd, st)) = open_as_owner(root.as_fd(), &sub_c)? else { return Ok(false) };
        drop(_root_cred);
        let _cred = if st.st_uid != euid_egid().0 { Some(FsCred::assume(st.st_uid, st.st_gid)?) } else { None };
        let mut it = std::fs::read_dir(proc_fd_path(fd.as_fd()))?;
        Ok(it.next().transpose()?.is_some())
    })
}

/// Does `<tenants_dir>/<tenant>` exist (as anything, symlinks included)?
pub fn tenant_tree_present(tenants_dir: &Path, tenant: &str) -> io::Result<bool> {
    let name = tenant_name(tenant)?;
    let pfd = open_path_dir(tenants_dir)?;
    match open_beneath(pfd.as_fd(), &name, 0) {
        Ok(_) => Ok(true),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e),
    }
}

/// The tenant names that have an entry in `tenants_dir` (invalid names are
/// skipped: the supervisor never created them and never touches them).
pub fn tenant_tree_names(tenants_dir: &Path) -> io::Result<Vec<crate::contract::TenantId>> {
    let mut out = Vec::new();
    for e in std::fs::read_dir(tenants_dir)? {
        let name = e?.file_name();
        match name.to_str().map(crate::contract::TenantId::new) {
            Some(Ok(t)) => out.push(t),
            _ => tracing::warn!(entry = ?name, "tenants dir: skipping an entry that is not a tenant id"),
        }
    }
    out.sort();
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    fn meta(p: &Path) -> (u32, u32, u32) {
        let m = std::fs::symlink_metadata(p).unwrap_or_else(|e| panic!("{}: {e}", p.display()));
        assert!(m.is_dir(), "{} is not a directory", p.display());
        (m.uid(), m.gid(), m.mode() & 0o7777)
    }

    fn assert_tree(tenants: &Path, tenant: &str, ids: &TenantIds) {
        fn walk(dir: &Path, s: &DirSpec) {
            let p = dir.join(&s.name);
            assert_eq!(meta(&p), (s.uid, s.gid, s.mode), "{}", p.display());
            for c in &s.children {
                walk(&p, c);
            }
        }
        walk(tenants, &tenant_tree(tenant, ids));
    }

    fn own_ids() -> TenantIds {
        let (u, g) = euid_egid();
        TenantIds { slot: 0, ingest_uid: u, query_uid: u, detect_uid: u, gid: g }
    }

    #[test]
    fn creates_and_repairs_tree_as_plain_owner() {
        let d = tempfile::tempdir().unwrap();
        let ids = own_ids();
        ensure_tenant_tree(d.path(), "t1", &ids).unwrap();
        assert_tree(d.path(), "t1", &ids);
        // NAN-3148: product/ and query[T]'s demand inbox exist before any jail.
        assert_eq!(meta(&d.path().join("t1/product/demand")), (ids.uid(Role::Product), ids.gid, 0o700));
        assert_eq!(ids.uid(Role::Product), ids.query_uid);
        // Partial / drifted state: wrong modes, missing tmp.
        std::fs::set_permissions(d.path().join("t1/parts"), std::fs::Permissions::from_mode(0o750)).unwrap();
        std::fs::remove_dir(d.path().join("t1/ingest/tmp")).unwrap();
        std::fs::set_permissions(d.path().join("t1/query"), std::fs::Permissions::from_mode(0o755)).unwrap();
        ensure_tenant_tree(d.path(), "t1", &ids).unwrap();
        assert_tree(d.path(), "t1", &ids);
        // A directory left without owner write/search (crash, stale slot)
        // is fixed before its children are created.
        std::fs::remove_dir(d.path().join("t1/detect/tmp")).unwrap();
        std::fs::set_permissions(d.path().join("t1/detect"), std::fs::Permissions::from_mode(0o500)).unwrap();
        std::fs::remove_dir(d.path().join("t1/query/tmp")).unwrap();
        std::fs::set_permissions(d.path().join("t1/query"), std::fs::Permissions::from_mode(0o000)).unwrap();
        ensure_tenant_tree(d.path(), "t1", &ids).unwrap();
        assert_tree(d.path(), "t1", &ids);
    }

    /// NAN-3875: reclaim only from root / unknown / stale owners; another
    /// live tenant's uid or gid is refused, whichever role it is.
    #[test]
    fn owner_verdict_never_reclaims_another_tenants_ids() {
        let me = 0; // the supervisor walking
        let foreign: BTreeSet<u32> = [20_002, 20_003, 60_001].into_iter().collect();
        // r56: our parts dir (want 20000) owned by the other tenant's ingest uid.
        assert_eq!(owner_verdict(20_002, 20_002, me, 20_000, &foreign), OwnerVerdict::Foreign);
        assert_eq!(owner_verdict(20_003, 20_002, me, 20_001, &foreign), OwnerVerdict::Foreign);
        assert_eq!(owner_verdict(60_001, 20_002, me, 60_000, &foreign), OwnerVerdict::Foreign);
        // Our supervisor-owned root carrying the other tenant's gid (group r-x).
        assert_eq!(owner_verdict(me, 20_002, me, me, &foreign), OwnerVerdict::Foreign);
        // Legitimate cases.
        assert_eq!(owner_verdict(me, 20_000, me, 20_000, &foreign), OwnerVerdict::Acting);
        assert_eq!(owner_verdict(20_000, 20_000, me, 20_000, &foreign), OwnerVerdict::Final);
        assert_eq!(owner_verdict(20_008, 20_008, me, 20_000, &foreign), OwnerVerdict::Reclaim, "a slot no tenant holds");
        assert_eq!(owner_verdict(1_000, 1_000, me, 20_000, &foreign), OwnerVerdict::Reclaim, "an unknown owner");
        // Unguarded (no other tenants known): the old behaviour.
        assert_eq!(owner_verdict(20_002, 20_002, me, 20_000, &BTreeSet::new()), OwnerVerdict::Reclaim);
    }

    #[test]
    fn guarded_tree_refuses_a_tree_owned_by_another_tenant() {
        let d = tempfile::tempdir().unwrap();
        let ids = own_ids();
        ensure_tenant_tree(d.path(), "t1", &ids).unwrap();
        // The plain test user owns t1's tree; mark our ids as another
        // tenant's (with t2 getting distinct ids): the walk must refuse t1
        // as t2 and change nothing.
        let other = TenantIds { slot: 1, ingest_uid: ids.ingest_uid + 2, query_uid: ids.ingest_uid + 3, detect_uid: ids.detect_uid + 1, gid: ids.gid + 2 };
        let foreign: BTreeSet<u32> = [ids.ingest_uid, ids.gid].into_iter().collect();
        let before = meta(&d.path().join("t1/parts"));
        let e = ensure_tenant_tree_guarded(d.path(), "t1", &other, &foreign).unwrap_err();
        assert!(is_foreign_owner(&e), "{e}");
        assert_eq!(meta(&d.path().join("t1/parts")), before);
        // Ids overlapping another tenant's are refused before any walk.
        let e = ensure_tenant_tree_guarded(d.path(), "t3", &ids, &foreign).unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::InvalidInput);
        assert!(!d.path().join("t3").exists());
    }

    #[test]
    fn quarantine_moves_a_tree_out_of_reach_and_purges_it() {
        let d = tempfile::tempdir().unwrap();
        let (tenants, q) = (d.path().join("tenants"), d.path().join("quarantine"));
        std::fs::create_dir_all(&tenants).unwrap();
        std::fs::create_dir_all(&q).unwrap();
        let ids = own_ids();
        ensure_tenant_tree(&tenants, "t1", &ids).unwrap();
        ensure_tenant_tree(&tenants, "t2", &ids).unwrap();
        std::fs::write(tenants.join("t1/query/cache.bin"), b"x").unwrap();
        let bytes = quarantine_tenant_tree(&tenants, "t1", &q).unwrap();
        assert!(bytes.entries > 0);
        assert!(!tenants.join("t1").exists() && tenants.join("t2/query").is_dir(), "only t1 moved");
        assert_eq!(std::fs::read_dir(&q).unwrap().count(), 0, "purged from quarantine");
        // Recreated fresh afterwards.
        ensure_tenant_tree(&tenants, "t1", &ids).unwrap();
        assert!(!tenants.join("t1/query/cache.bin").exists());
        // A leftover in quarantine is swept; other entries are left alone.
        std::fs::create_dir_all(q.join("q1-0/x")).unwrap();
        std::fs::write(q.join("keep.txt"), b"").unwrap();
        assert_eq!(sweep_quarantine(&q).unwrap(), 1);
        assert!(!q.join("q1-0").exists() && q.join("keep.txt").exists());
        // A symlinked tenant entry is moved as a link, never followed.
        std::os::unix::fs::symlink(tenants.join("t2"), tenants.join("t3")).unwrap();
        quarantine_tenant_tree(&tenants, "t3", &q).unwrap();
        assert!(tenants.join("t2/query").is_dir());
    }

    #[test]
    fn walk_runs_on_a_dedicated_thread() {
        let caller = std::thread::current().id();
        let (id, name) = on_dedicated_thread(|| {
            let t = std::thread::current();
            Ok((t.id(), t.name().map(str::to_owned)))
        })
        .unwrap();
        assert_ne!(id, caller);
        assert_eq!(name.as_deref(), Some("tenant-dirs"));
        let e = on_dedicated_thread::<()>(|| panic!("boom")).unwrap_err();
        assert!(e.to_string().contains("panicked"), "{e}");
    }

    #[test]
    fn rejects_modes_without_owner_rwx() {
        let d = tempfile::tempdir().unwrap();
        let (u, g) = euid_egid();
        let e = ensure_dir(&d.path().join("x"), u, g, 0o500).unwrap_err();
        assert!(e.to_string().contains("lacks u+rwx"), "{e}");
    }

    #[test]
    fn refuses_symlinks() {
        let d = tempfile::tempdir().unwrap();
        let victim = d.path().join("victim");
        std::fs::create_dir(&victim).unwrap();
        std::fs::set_permissions(&victim, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::create_dir(d.path().join("t1")).unwrap();
        std::os::unix::fs::symlink(&victim, d.path().join("t1/parts")).unwrap();
        let e = ensure_tenant_tree(d.path(), "t1", &own_ids()).unwrap_err();
        assert!(e.to_string().contains("not a plain directory"), "{e}");
        assert_eq!(meta(&victim).2, 0o755, "symlink target must be untouched");
        assert!(ensure_tenant_tree(d.path(), "../x", &own_ids()).is_err());
    }

    #[test]
    fn purge_removes_one_tenant_only() {
        let d = tempfile::tempdir().unwrap();
        let tenants = d.path().join("tenants");
        std::fs::create_dir(&tenants).unwrap();
        let ids = own_ids();
        ensure_tenant_tree(&tenants, "t1", &ids).unwrap();
        ensure_tenant_tree(&tenants, "t2", &ids).unwrap();
        let outside = d.path().join("outside");
        std::fs::create_dir(&outside).unwrap();
        std::fs::write(outside.join("keep"), b"outside").unwrap();
        std::fs::write(tenants.join("t2/parts/p"), b"sibling part").unwrap();
        // t1: cache, spill, tmp, a deep reader cache, and every kind of
        // escape: symlinks to the sibling and outside, a hard link to the
        // sibling's file, a dir left 0000 and a sticky dir.
        std::fs::write(tenants.join("t1/parts/p1"), vec![0u8; 1000]).unwrap();
        std::fs::create_dir_all(tenants.join("t1/query/cache/a/b")).unwrap();
        std::fs::write(tenants.join("t1/query/cache/a/b/c"), vec![0u8; 20]).unwrap();
        std::fs::write(tenants.join("t1/query/tmp/scratch"), vec![0u8; 300]).unwrap();
        std::fs::create_dir(tenants.join("t1/ingest/spill")).unwrap();
        std::fs::write(tenants.join("t1/ingest/spill/s"), vec![0u8; 5]).unwrap();
        std::os::unix::fs::symlink(tenants.join("t2"), tenants.join("t1/query/to-t2")).unwrap();
        std::os::unix::fs::symlink(&outside, tenants.join("t1/ingest/tmp/to-outside")).unwrap();
        std::fs::hard_link(tenants.join("t2/parts/p"), tenants.join("t1/parts/hl")).unwrap();
        std::fs::set_permissions(tenants.join("t1/ingest/spill"), std::fs::Permissions::from_mode(0o000)).unwrap();
        std::fs::set_permissions(tenants.join("t1/detect"), std::fs::Permissions::from_mode(0o1700)).unwrap();

        let got = purge_tenant_tree(&tenants, "t1").unwrap();
        assert!(!tenant_tree_present(&tenants, "t1").unwrap());
        assert_eq!(got.tmp_bytes, 300);
        assert_eq!(got.cache_bytes, 1000 + 20 + 5, "the hard link frees nothing");
        assert!(got.entries > 10, "{got:?}");
        // Nothing of the sibling or outside changed.
        assert_tree(&tenants, "t2", &ids);
        assert_eq!(std::fs::read(tenants.join("t2/parts/p")).unwrap(), b"sibling part");
        assert_eq!(std::fs::read(outside.join("keep")).unwrap(), b"outside");
        assert_eq!(tenant_tree_names(&tenants).unwrap().iter().map(|t| t.as_str().to_owned()).collect::<Vec<_>>(), vec!["t2"]);
        // Idempotent, and the tenant can be placed again from scratch.
        assert_eq!(purge_tenant_tree(&tenants, "t1").unwrap(), PurgeBytes::default());
        ensure_tenant_tree(&tenants, "t1", &ids).unwrap();
        assert_tree(&tenants, "t1", &ids);
        // Names that could leave the tenants dir are refused outright.
        for bad in ["..", ".", "", "t2/parts", "../outside", "T1"] {
            assert!(purge_tenant_tree(&tenants, bad).is_err(), "{bad:?} accepted");
        }
        assert_tree(&tenants, "t2", &ids);
    }

    #[test]
    fn subdir_nonempty_is_read_only_and_never_follows_links() {
        let d = tempfile::tempdir().unwrap();
        let tenants = d.path().join("tenants");
        std::fs::create_dir(&tenants).unwrap();
        let ids = own_ids();
        assert!(!tenant_subdir_nonempty(&tenants, "t1", "parts").unwrap(), "absent tenant");
        ensure_tenant_tree(&tenants, "t1", &ids).unwrap();
        assert!(!tenant_subdir_nonempty(&tenants, "t1", "parts").unwrap());
        std::fs::write(tenants.join("t1/parts/p"), b"x").unwrap();
        assert!(tenant_subdir_nonempty(&tenants, "t1", "parts").unwrap());
        assert_tree(&tenants, "t1", &ids);
        // A symlinked `parts` pointing at a full directory is not followed.
        let full = d.path().join("full");
        std::fs::create_dir(&full).unwrap();
        std::fs::write(full.join("f"), b"x").unwrap();
        std::fs::create_dir(tenants.join("t2")).unwrap();
        std::os::unix::fs::symlink(&full, tenants.join("t2/parts")).unwrap();
        assert!(tenant_subdir_nonempty(&tenants, "t2", "parts").is_err());
        assert!(tenant_subdir_nonempty(&tenants, "t1", "../t2").is_err());
    }

    #[test]
    fn purge_of_a_symlinked_tenant_root_removes_only_the_link() {
        let d = tempfile::tempdir().unwrap();
        let tenants = d.path().join("tenants");
        std::fs::create_dir(&tenants).unwrap();
        let victim = d.path().join("victim");
        std::fs::create_dir(&victim).unwrap();
        std::fs::write(victim.join("f"), b"v").unwrap();
        std::os::unix::fs::symlink(&victim, tenants.join("t1")).unwrap();
        let got = purge_tenant_tree(&tenants, "t1").unwrap();
        assert_eq!((got.cache_bytes, got.entries), (0, 1));
        assert!(!tenant_tree_present(&tenants, "t1").unwrap());
        assert_eq!(std::fs::read(victim.join("f")).unwrap(), b"v");
    }

    // ------------------------------------------------------------ 5A caps

    const STAGE: &str = "NANO_CELL_TENANT_DIRS_STAGE";
    const DIR: &str = "NANO_CELL_TENANT_DIRS_DIR";
    const TENANT: &str = "NANO_CELL_TENANT_DIRS_TENANT";
    const MARKER: &str = "NANO_CELL_TENANT_DIRS_MARKER";
    const TEST: &str = "tenant_dirs::tests::cell_5a_capabilities";
    const WHERE: &str = "it needs root holding the cell caps, or unshare + an /etc/subuid range; \
                         CI runs it in the lake-cell-isolation job (NANO_CELL_ISOLATION_REQUIRED=1)";
    /// CHOWN(0) FOWNER(3) KILL(5) SETGID(6) SETUID(7) SYS_ADMIN(21): the
    /// live cell's CapEff 0x2000e9.
    const CELL_CAPS: u64 = 0x2000e9;

    fn live_ids() -> TenantIds {
        TenantIds { slot: 0, ingest_uid: 20000, query_uid: 20001, detect_uid: 60000, gid: 20000 }
    }

    /// Drop this thread's effective, permitted and inheritable sets to
    /// exactly `CELL_CAPS` (irreversible for the thread).
    fn drop_to_cell_caps() {
        #[repr(C)]
        struct Header {
            version: u32,
            pid: i32,
        }
        #[repr(C)]
        #[derive(Clone, Copy)]
        struct Data {
            effective: u32,
            permitted: u32,
            inheritable: u32,
        }
        let lo = CELL_CAPS as u32;
        let hi = (CELL_CAPS >> 32) as u32;
        let h = Header { version: 0x2008_0522, pid: 0 };
        let d = [Data { effective: lo, permitted: lo, inheritable: 0 }, Data { effective: hi, permitted: hi, inheritable: 0 }];
        // SAFETY: capset with a v3 header and a two-element data array.
        let r = unsafe { libc::syscall(libc::SYS_capset, &h as *const Header, d.as_ptr()) };
        assert_eq!(r, 0, "capset: {}", io::Error::last_os_error());
        let status = std::fs::read_to_string("/proc/thread-self/status").unwrap();
        let eff = status.lines().find_map(|l| l.strip_prefix("CapEff:")).map(|v| u64::from_str_radix(v.trim(), 16).unwrap());
        assert_eq!(eff, Some(CELL_CAPS), "CapEff after drop");
    }

    fn thread_caps(field: &str) -> u64 {
        let status = std::fs::read_to_string("/proc/thread-self/status").unwrap();
        status
            .lines()
            .find_map(|l| l.strip_prefix(field))
            .map(|v| u64::from_str_radix(v.trim(), 16).unwrap())
            .unwrap_or_else(|| panic!("{field} missing"))
    }

    /// Current fsuid/fsgid (`-1` is rejected and returns the current value).
    fn fs_ids() -> (u32, u32) {
        // SAFETY: probing calls; an invalid id changes nothing.
        unsafe { (libc::setfsuid(u32::MAX) as u32, libc::setfsgid(u32::MAX) as u32) }
    }

    fn run_dropped(tenants: &Path, tenant: &str) {
        run_stage("dropped", tenants, tenant)
    }

    fn run_stage(stage: &str, tenants: &Path, tenant: &str) {
        let out = std::process::Command::new(std::env::current_exe().unwrap())
            .args([TEST, "--exact", "--nocapture", "--test-threads=1"])
            .env(STAGE, stage)
            .env(DIR, tenants)
            .env(TENANT, tenant)
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "5A-caps {stage} pass for {tenant} failed:\n{}\n{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
    }

    fn set(p: &Path, uid: u32, gid: u32, mode: u32) {
        std::os::unix::fs::chown(p, Some(uid), Some(gid)).unwrap();
        std::fs::set_permissions(p, std::fs::Permissions::from_mode(mode)).unwrap();
    }

    /// Root with full caps (real root, or root in a user namespace):
    /// prepare states, run the tree code in a process holding exactly the
    /// cell's capabilities, verify with full caps.
    fn sandbox_stage() {
        if let Ok(m) = std::env::var(MARKER) {
            std::fs::write(m, b"entered").unwrap();
        }
        let d = tempfile::tempdir().unwrap();
        let tenants = d.path().join("tenants");
        std::fs::create_dir(&tenants).unwrap();
        std::fs::set_permissions(&tenants, std::fs::Permissions::from_mode(0o711)).unwrap();
        let ids = live_ids();

        // From scratch, then again (idempotent over its own result).
        run_dropped(&tenants, "fresh");
        assert_tree(&tenants, "fresh", &ids);
        run_dropped(&tenants, "fresh");
        assert_tree(&tenants, "fresh", &ids);

        // The exact partial state the live cell was left in by the old
        // code: root 0:gid 0750, parts ingest:gid 0750 (setgid lost),
        // ingest ingest:gid 0700 without tmp.
        let t = tenants.join("live");
        std::fs::create_dir(&t).unwrap();
        set(&t, 0, ids.gid, 0o750);
        std::fs::create_dir(t.join("parts")).unwrap();
        set(&t.join("parts"), ids.ingest_uid, ids.gid, 0o750);
        std::fs::create_dir(t.join("ingest")).unwrap();
        set(&t.join("ingest"), ids.ingest_uid, ids.gid, 0o700);
        // Plus drift the old code could not produce but a restart might
        // meet: a foreign-owned role dir, and a tmp with the wrong mode.
        std::fs::create_dir_all(t.join("query/tmp")).unwrap();
        set(&t.join("query/tmp"), ids.query_uid, ids.gid, 0o755);
        set(&t.join("query"), 12345, 12345, 0o700);
        run_dropped(&tenants, "live");
        assert_tree(&tenants, "live", &ids);

        // A tenant-planted symlink inside a tenant-writable dir is refused
        // and its target untouched.
        let victim = d.path().join("victim");
        std::fs::create_dir(&victim).unwrap();
        set(&victim, 0, 0, 0o755);
        std::fs::remove_dir(tenants.join("live/ingest/tmp")).unwrap();
        std::os::unix::fs::symlink(&victim, tenants.join("live/ingest/tmp")).unwrap();
        let out = std::process::Command::new(std::env::current_exe().unwrap())
            .args([TEST, "--exact", "--nocapture", "--test-threads=1"])
            .env(STAGE, "dropped")
            .env(DIR, &tenants)
            .env(TENANT, "live")
            .output()
            .unwrap();
        assert!(!out.status.success(), "symlinked tmp must be refused");
        assert_eq!(meta(&victim), (0, 0, 0o755), "symlink target must be untouched");

        // Stale slot: directories and contents owned by a previous uid.
        // Re-own what the stale uid owns; never anything else, never a
        // multiply-linked inode, never a symlink target.
        const OLD: u32 = 12345;
        let t = tenants.join("stale");
        std::fs::create_dir(&t).unwrap();
        set(&t, 0, ids.gid, 0o750);
        let parts = t.join("parts");
        std::fs::create_dir(&parts).unwrap();
        let file = |p: &Path, uid: u32, mode: u32| {
            std::fs::write(p, b"x").unwrap();
            set(p, uid, uid, mode);
        };
        file(&parts.join("f"), OLD, 0o640);
        file(&parts.join("rootf"), 0, 0o644);
        std::fs::create_dir(parts.join("sub")).unwrap();
        file(&parts.join("sub/g"), OLD, 0o600);
        set(&parts.join("sub"), OLD, OLD, 0o2550);
        let outside = d.path().join("outside");
        file(&outside, OLD, 0o600);
        std::fs::hard_link(&outside, parts.join("hl")).unwrap();
        std::os::unix::fs::symlink(&outside, parts.join("ln")).unwrap();
        std::os::unix::fs::lchown(parts.join("ln"), Some(OLD), Some(OLD)).unwrap();
        set(&parts, OLD, OLD, 0o500);
        let ingest = t.join("ingest");
        std::fs::create_dir_all(ingest.join("tmp")).unwrap();
        file(&ingest.join("tmp/x"), OLD, 0o600);
        set(&ingest.join("tmp"), OLD, OLD, 0o700);
        set(&ingest, OLD, OLD, 0o000);
        // A role dir owned by its (current) uid but left 0000 without tmp.
        std::fs::create_dir(t.join("detect")).unwrap();
        set(&t.join("detect"), ids.detect_uid, ids.gid, 0o000);
        run_dropped(&tenants, "stale");
        assert_tree(&tenants, "stale", &ids);
        let owner = |p: &Path| {
            use std::os::unix::fs::MetadataExt;
            let m = std::fs::symlink_metadata(p).unwrap();
            (m.uid(), m.gid(), m.mode() & 0o7777)
        };
        let ing = ids.ingest_uid;
        assert_eq!(owner(&parts.join("f")), (ing, ids.gid, 0o640));
        assert_eq!(owner(&parts.join("sub")), (ing, ids.gid, 0o2550), "subdir mode restored exactly");
        assert_eq!(owner(&parts.join("sub/g")), (ing, ids.gid, 0o600));
        assert_eq!(owner(&parts.join("rootf")).0, 0, "not the stale owner's: untouched");
        assert_eq!(owner(&outside).0, OLD, "hard-linked inode must keep its owner");
        assert_eq!(owner(&parts.join("ln")).0, ing, "symlink itself re-owned");
        assert_eq!(owner(&ingest.join("tmp/x")), (ing, ids.gid, 0o600));

        // fsuid/fsgid restore on the error and panic paths, on the calling
        // thread, under exactly the cell's caps.
        let r = tenants.join("restore");
        std::fs::create_dir(&r).unwrap();
        std::os::unix::fs::symlink(&victim, r.join("tmp")).unwrap();
        set(&r, ids.query_uid, ids.gid, 0o700);
        run_stage("restore", &tenants, "restore");
        assert_eq!(meta(&victim), (0, 0, 0o755), "symlink target must be untouched");

        // NAN-3000 purge under exactly the cell caps: tenant-uid-owned
        // directories left 0000 / setgid / sticky, files of every role uid,
        // a symlink to a sibling tenant's tree and a hard link to its file.
        // The purged tenant is gone; the sibling ("live"), the victim and
        // the hard-linked inode are untouched.
        let p = tenants.join("fresh");
        let sibling_file = tenants.join("stale/parts/keep");
        file(&sibling_file, ids.ingest_uid, 0o640);
        let put = |rel: &str, uid: u32, mode: u32| file(&p.join(rel), uid, mode);
        put("parts/part-1", ids.ingest_uid, 0o640);
        put("ingest/state.json", ids.ingest_uid, 0o600);
        put("query/tmp/scratch", ids.query_uid, 0o600);
        std::fs::create_dir(p.join("ingest/spill")).unwrap();
        put("ingest/spill/s1", ids.ingest_uid, 0o600);
        set(&p.join("ingest/spill"), ids.ingest_uid, ids.gid, 0o000);
        std::os::unix::fs::symlink(tenants.join("stale"), p.join("query/to-sibling")).unwrap();
        std::os::unix::fs::symlink(&victim, p.join("detect/to-victim")).unwrap();
        std::fs::hard_link(&sibling_file, p.join("parts/hl")).unwrap();
        set(&p.join("query"), ids.query_uid, ids.gid, 0o1000);
        set(&p.join("detect"), ids.detect_uid, ids.gid, 0o000);
        run_stage("purge", &tenants, "fresh");
        assert!(std::fs::symlink_metadata(&p).is_err(), "purged tenant tree still present");
        assert_tree(&tenants, "stale", &ids);
        let sib = std::fs::symlink_metadata(&sibling_file).unwrap();
        assert_eq!((sib.uid(), sib.nlink()), (ids.ingest_uid, 1), "sibling tenant file untouched (one link left)");
        assert_eq!(meta(&victim), (0, 0, 0o755), "symlink target must be untouched");

        println!("RAN: tenant_dirs 5A capability test");
    }

    /// Runs with exactly the cell caps: an error (and a panic) while
    /// acting as a tenant owner leaves fsuid/fsgid and CapEff as before.
    fn restore_stage(tenants: &Path, tenant: &str) {
        let ids = live_ids();
        let before = (fs_ids(), thread_caps("CapEff:"));
        assert_eq!(before, ((0, 0), CELL_CAPS));
        let spec = DirSpec::new(tenant, ids.query_uid, ids.gid, 0o700).child(DirSpec::new("tmp", ids.query_uid, ids.gid, 0o700));
        let pfd = open_path_dir(tenants).unwrap();
        let e = ensure_at(pfd.as_fd(), &spec, Acting { uid: 0, gid: 0 }, &BTreeSet::new()).unwrap_err();
        assert!(e.to_string().contains("not a plain directory"), "{e}");
        assert_eq!((fs_ids(), thread_caps("CapEff:")), before, "restored after an error while switched");

        let r = std::panic::catch_unwind(|| {
            let _c = FsCred::assume(ids.query_uid, ids.gid).unwrap();
            assert_eq!(fs_ids(), (ids.query_uid, ids.gid));
            assert_eq!(thread_caps("CapEff:") & 1, 0, "CAP_CHOWN is dropped while switched");
            panic!("boom");
        });
        assert!(r.is_err());
        assert_eq!((fs_ids(), thread_caps("CapEff:")), before, "restored after a panic while switched");
    }

    #[test]
    fn cell_5a_capabilities() {
        match std::env::var(STAGE).as_deref() {
            Ok(stage @ ("dropped" | "restore" | "purge")) => {
                drop_to_cell_caps();
                let dir = std::env::var(DIR).unwrap();
                let t = std::env::var(TENANT).unwrap();
                if stage == "restore" {
                    restore_stage(Path::new(&dir), &t);
                } else if stage == "purge" {
                    let got = purge_tenant_tree(Path::new(&dir), &t).unwrap();
                    assert!(!tenant_tree_present(Path::new(&dir), &t).unwrap(), "{t} still present after purge");
                    println!("PURGED {t}: {got:?}");
                } else {
                    ensure_tenant_tree(Path::new(&dir), &t, &live_ids()).unwrap();
                    // The volume accountant must work under these exact caps,
                    // across the query/ingest owners, without DAC_READ_SEARCH.
                    let root = Path::new(&dir).to_path_buf();
                    crate::volume_usage::start(root.clone(), vec![root.clone()]).unwrap();
                    crate::volume_usage::usage(&root).expect("account all role-owned directories under the exact cell caps");
                }
                return;
            }
            Ok("sandbox") => return sandbox_stage(),
            _ => {}
        }
        let required = std::env::var("NANO_CELL_ISOLATION_REQUIRED").is_ok();
        if euid_egid().0 == 0 {
            // Root (e.g. the privileged CI container): needs the cell caps
            // in its permitted set to capset down to exactly them.
            if thread_caps("CapPrm:") & CELL_CAPS != CELL_CAPS {
                assert!(!required, "SKIPPED: root lacks the cell caps ({WHERE})");
                eprintln!("SKIPPED: root lacks the cell caps ({WHERE})");
                return;
            }
            return sandbox_stage();
        }
        // Unprivileged: re-run inside `unshare --user --map-root-user`
        // with the tenant ids mapped (root in a userns, full caps there).
        let user = std::env::var("USER").unwrap_or_default();
        let range = std::fs::read_to_string("/etc/subuid").unwrap_or_default().lines().find_map(|l| {
            let mut it = l.split(':');
            (it.next() == Some(user.as_str())).then(|| (it.next().unwrap_or("").to_owned(), it.next().unwrap_or("").to_owned()))
        });
        let Some((start, count)) = range else {
            assert!(!required, "SKIPPED: no /etc/subuid range for {user} ({WHERE})");
            eprintln!("SKIPPED: no /etc/subuid range for {user} ({WHERE})");
            return;
        };
        let count = count.parse::<u32>().unwrap_or(65536).min(65535);
        let marker = tempfile::NamedTempFile::new().unwrap();
        let status = std::process::Command::new("unshare")
            .args(["--user", "--map-root-user"])
            .arg(format!("--map-users=1:{start}:{count}"))
            .arg(format!("--map-groups=1:{start}:{count}"))
            .arg("--")
            .arg(std::env::current_exe().unwrap())
            .args([TEST, "--exact", "--nocapture", "--test-threads=1"])
            .env(STAGE, "sandbox")
            .env(MARKER, marker.path())
            .status();
        let entered = std::fs::read(marker.path()).is_ok_and(|b| b == b"entered");
        match status {
            Ok(s) if entered => assert!(s.success(), "5A-caps tenant dir test failed inside the user namespace: {s}"),
            // unshare/newuidmap could not build the namespace (e.g. a build
            // sandbox without setuid helpers): the test never ran.
            other => {
                assert!(!required, "SKIPPED: could not enter a user namespace: {other:?} ({WHERE})");
                eprintln!("SKIPPED: could not enter a user namespace: {other:?} ({WHERE})");
            }
        }
    }
}
