// SPDX-License-Identifier: AGPL-3.0-or-later
//! Volume accounting without granting tenant processes access to other tenants.
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

pub const SOCKET: &str = ".hot-window-usage.sock";

/// Allocated bytes, including directories, scratch and sidecars. Do not follow
/// symlinks or count a hard-linked inode twice (notably cache lease pins).
pub fn directory_bytes(root: &Path) -> std::io::Result<u64> {
    walk(&[root.to_path_buf()], false)
}

/// One bounded walk of a tenant tree (NAN-3523 per-tenant disk ceiling).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TreeUsage {
    /// Allocated bytes found (a lower bound when `complete` is false).
    pub bytes: u64,
    /// Directory entries visited.
    pub entries: u64,
    /// False: the walk stopped at its entry bound.
    pub complete: bool,
}

/// [`directory_bytes`] listed as each directory's owner (the supervisor has
/// no DAC_OVERRIDE), skipping the subtrees at `skip` (paths relative to
/// `root`) and stopping after `max_entries` entries. Switches the calling
/// thread's fsuid/fsgid per directory (restored on drop): call it only on a
/// dedicated thread, never on a runtime worker.
pub fn owned_tree_usage(root: &Path, skip: &[&Path], max_entries: u64) -> std::io::Result<TreeUsage> {
    walk_bounded(&[root.to_path_buf()], true, skip, max_entries)
}

fn walk(roots: &[PathBuf], as_owner: bool) -> std::io::Result<u64> {
    walk_bounded(roots, as_owner, &[], u64::MAX).map(|usage| usage.bytes)
}

// The supervisor lacks DAC_OVERRIDE. Open directories without following links,
// then list them as their owner on the dedicated accounting thread. Held fds
// avoid following a tenant's symlink or a renamed ancestor during the walk.
fn walk_bounded(roots: &[PathBuf], as_owner: bool, skip: &[&Path], max_entries: u64) -> std::io::Result<TreeUsage> {
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::OpenOptionsExt;
    let open = |path: &Path| {
        std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_PATH | libc::O_DIRECTORY | libc::O_NOFOLLOW)
            .open(path)
    };
    let mut pending = roots
        .iter()
        .map(|root| open(root).map(|dir| (dir, PathBuf::new())))
        .collect::<std::io::Result<Vec<_>>>()?;
    let mut seen = std::collections::HashSet::new();
    let mut bytes = 0_u64;
    let mut entries = 0_u64;
    while let Some((dir, rel)) = pending.pop() {
        let meta = dir.metadata()?;
        if !seen.insert((meta.dev(), meta.ino())) {
            continue;
        }
        bytes = bytes.saturating_add(meta.blocks().saturating_mul(512));
        let _owner = if as_owner {
            Some(crate::tenant_dirs::FsCred::assume(meta.uid(), meta.gid())?)
        } else {
            None
        };
        let path = PathBuf::from(format!("/proc/self/fd/{}", dir.as_raw_fd()));
        for entry in std::fs::read_dir(path)? {
            let entry = entry?;
            if entries >= max_entries {
                return Ok(TreeUsage { bytes, entries, complete: false });
            }
            entries += 1;
            let meta = match std::fs::symlink_metadata(entry.path()) {
                Ok(meta) => meta,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                Err(e) => return Err(e),
            };
            if meta.is_dir() {
                let child = rel.join(entry.file_name());
                if skip.iter().any(|skipped| *skipped == child) {
                    continue;
                }
                match open(&entry.path()) {
                    Ok(dir) => pending.push((dir, child)),
                    Err(e)
                        if matches!(
                            e.raw_os_error(),
                            Some(libc::ENOENT | libc::ENOTDIR | libc::ELOOP)
                        ) => {}
                    Err(e) => return Err(e),
                }
            } else if seen.insert((meta.dev(), meta.ino())) {
                let allocated = meta.blocks().saturating_mul(512);
                // Include delayed allocation as well as already allocated blocks.
                let promised = if meta.is_file() {
                    meta.len()
                        .div_ceil(meta.blksize().max(4096))
                        .saturating_mul(meta.blksize().max(4096))
                } else {
                    0
                };
                bytes = bytes.saturating_add(allocated.max(promised));
            }
        }
    }
    Ok(TreeUsage { bytes, entries, complete: true })
}

/// Standard cell layout: <volume>/tenants/<tenant>/query/cache.
pub fn volume_root(cache: &Path) -> PathBuf {
    cache
        .ancestors()
        .find(|path| path.file_name().is_some_and(|n| n == "tenants"))
        .and_then(Path::parent)
        .unwrap_or(cache)
        .to_path_buf()
}

/// Server replies. Anything below [`ACCOUNTING_FAILED`] is a byte count.
const LIMIT_REACHED: u64 = u64::MAX;
const ACCOUNTING_FAILED: u64 = u64::MAX - 1;
/// `limit` value of a release frame on a persistent (fd-passed) connection:
/// `[RELEASE_LIMIT, granted bytes]`, no reply. Real requests clamp their
/// limit below it. The supervisor and its children are one binary.
const RELEASE_LIMIT: u64 = u64::MAX;

/// How often the supervisor re-walks the accounting roots (NAN-3147).
pub const REWALK_SECONDS_ENV: &str = "NANO_LAKE_VOLUME_USAGE_REWALK_SECONDS";
const DEFAULT_REWALK: std::time::Duration = std::time::Duration::from_secs(30);
/// Bound on how long [`start`] waits for the first walk before serving.
const FIRST_WALK_WAIT: std::time::Duration = std::time::Duration::from_secs(5);

fn limit_reached() -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::StorageFull, "volume usage target reached")
}

/// The volume target is reached: fail this write. Every other accountant
/// error means accounting is unavailable, which callers may degrade around
/// (NAN-3139: a hot-window problem must never fail ordinary cache admission).
pub fn is_limit_reached(error: &std::io::Error) -> bool {
    error.kind() == std::io::ErrorKind::StorageFull
}

/// A write approval: its bytes stay charged against the volume target until
/// the guard drops, after which they count as landed until the next walk sees
/// them. NAN-3147: a guard serializes nothing; holding one across a slow
/// download never blocks another writer's admission.
/// No tenant paths or file contents cross the accountant connection.
pub struct WriteGuard {
    release: Release,
}

enum Release {
    None,
    /// One-shot socket connection: EOF releases the grant.
    Stream(#[allow(dead_code)] std::os::unix::net::UnixStream),
    /// Supervisor-passed connection: a release frame for these bytes.
    Peer(&'static AccountantClient, u64),
    /// Standalone process without an accountant.
    Local(PathBuf, u64),
}

impl Drop for WriteGuard {
    fn drop(&mut self) {
        match std::mem::replace(&mut self.release, Release::None) {
            Release::Peer(client, growth) => client.release(growth),
            Release::Local(root, growth) => {
                let mut local = LOCAL_GRANTS.lock().unwrap_or_else(|e| e.into_inner());
                if let Some(held) = local.get_mut(&root) {
                    *held = held.saturating_sub(growth);
                    if *held == 0 {
                        local.remove(&root);
                    }
                }
            }
            Release::None | Release::Stream(_) => {}
        }
    }
}

fn decode(value: u64) -> std::io::Result<u64> {
    match value {
        LIMIT_REACHED => Err(limit_reached()),
        ACCOUNTING_FAILED => Err(std::io::Error::other("volume accounting failed")),
        bytes => Ok(bytes),
    }
}

fn frame(limit: u64, growth: u64) -> [u8; 16] {
    let mut frame = [0; 16];
    frame[..8].copy_from_slice(&limit.to_le_bytes());
    frame[8..].copy_from_slice(&growth.to_le_bytes());
    frame
}

fn parse(frame: &[u8; 16]) -> (u64, u64) {
    (
        u64::from_le_bytes(frame[..8].try_into().unwrap()),
        u64::from_le_bytes(frame[8..].try_into().unwrap()),
    )
}

fn request(
    root: &Path,
    limit: u64,
    growth: u64,
) -> std::io::Result<(u64, std::os::unix::net::UnixStream)> {
    let mut stream = std::os::unix::net::UnixStream::connect(root.join(SOCKET))?;
    let deadline = Some(std::time::Duration::from_secs(30));
    stream.set_read_timeout(deadline)?;
    stream.set_write_timeout(deadline)?;
    stream.write_all(&frame(limit.min(RELEASE_LIMIT - 1), growth))?;
    let mut bytes = [0; 8];
    stream.read_exact(&mut bytes)?;
    Ok((decode(u64::from_le_bytes(bytes))?, stream))
}

/// Client end of a supervisor-passed, preconnected accountant connection.
///
/// NAN-3139: a jailed tenant process can never create an `AF_UNIX` socket
/// (seccomp returns EPERM) nor connect to a pathname socket (Landlock), so
/// it cannot reach [`SOCKET`]. The supervisor instead hands it one end of a
/// socketpair ([`Accountant::pair`]).
///
/// NAN-3147: the connection's mutex is held for one request/reply round trip
/// (the supervisor answers from memory) or one release frame, never for the
/// life of a grant, so concurrent writers in one process (foreground cold
/// fetches, background hydration, scratch) never queue behind each other.
pub struct AccountantClient {
    stream: std::sync::Mutex<Option<std::os::unix::net::UnixStream>>,
}

impl AccountantClient {
    pub fn new(fd: std::os::fd::OwnedFd) -> std::io::Result<Self> {
        let stream = std::os::unix::net::UnixStream::from(fd);
        let deadline = Some(std::time::Duration::from_secs(30));
        stream.set_read_timeout(deadline)?;
        stream.set_write_timeout(deadline)?;
        Ok(Self { stream: std::sync::Mutex::new(Some(stream)) })
    }

    fn ask(&self, limit: u64, growth: u64) -> std::io::Result<u64> {
        let mut guard = self.stream.lock().unwrap_or_else(|e| e.into_inner());
        let Some(stream) = guard.as_mut() else {
            return Err(std::io::Error::other("volume accountant connection lost"));
        };
        let mut reply = [0; 8];
        let request = frame(limit.min(RELEASE_LIMIT - 1), growth);
        if let Err(error) = stream.write_all(&request).and_then(|()| stream.read_exact(&mut reply)) {
            // A desynchronized connection must never be reused.
            *guard = None;
            return Err(error);
        }
        drop(guard);
        decode(u64::from_le_bytes(reply))
    }

    fn release(&self, growth: u64) {
        let mut guard = self.stream.lock().unwrap_or_else(|e| e.into_inner());
        let failed = guard
            .as_mut()
            .is_some_and(|stream| stream.write_all(&frame(RELEASE_LIMIT, growth)).is_err());
        if failed {
            // Closing releases every grant of this connection server-side.
            *guard = None;
        }
    }

    pub fn usage(&'static self) -> std::io::Result<u64> {
        self.ask(0, 0)
    }

    pub fn reserve_write(&'static self, limit: u64, growth: u64) -> std::io::Result<WriteGuard> {
        self.ask(limit, growth)?;
        // limit == 0 is a plain query: the server charges nothing for it.
        let release = if limit > 0 { Release::Peer(self, growth) } else { Release::None };
        Ok(WriteGuard { release })
    }
}

static INSTALLED: std::sync::OnceLock<AccountantClient> = std::sync::OnceLock::new();

/// Install the fd the supervisor passed with the assignment. Once per process.
pub fn install_accountant(fd: std::os::fd::OwnedFd) -> std::io::Result<()> {
    INSTALLED
        .set(AccountantClient::new(fd)?)
        .map_err(|_| std::io::Error::other("volume accountant already installed"))
}

/// Only an aggregate byte count crosses the jail. A failed accountant fails
/// closed; direct walking is for standalone workers and tests.
pub fn usage(root: &Path) -> std::io::Result<u64> {
    if let Some(client) = INSTALLED.get() {
        return client.usage();
    }
    if !root.join(SOCKET).exists() {
        return directory_bytes(root);
    }
    Ok(request(root, 0, 0)?.0)
}

/// Standalone grants by volume root, charged on top of each fresh walk.
static LOCAL_GRANTS: std::sync::Mutex<std::collections::BTreeMap<PathBuf, u64>> =
    std::sync::Mutex::new(std::collections::BTreeMap::new());

/// Fence an allocation, including concurrent hydration by different tenants.
/// The 20% scratch reserve is still necessary: ingest/merge are independent
/// writers and can create pressure while a hot download is in flight.
pub fn reserve_write(root: &Path, limit: u64, growth: u64) -> std::io::Result<WriteGuard> {
    if let Some(client) = INSTALLED.get() {
        return client.reserve_write(limit, growth);
    }
    if root.join(SOCKET).exists() {
        let (_, stream) = request(root, limit, growth)?;
        return Ok(WriteGuard { release: Release::Stream(stream) });
    }
    // No accountant: walk now, charging this process's outstanding grants.
    let mut local = LOCAL_GRANTS.lock().unwrap_or_else(|e| e.into_inner());
    let held = local.get(root).copied().unwrap_or(0);
    if directory_bytes(root)?.saturating_add(held).saturating_add(growth) > limit {
        return Err(limit_reached());
    }
    if limit == 0 {
        return Ok(WriteGuard { release: Release::None });
    }
    *local.entry(root.to_path_buf()).or_default() += growth;
    Ok(WriteGuard { release: Release::Local(root.to_path_buf(), growth) })
}

/// Rewalk cadence and the age past which a cached figure is not trusted.
#[derive(Clone, Copy, Debug)]
pub struct AccountantConfig {
    pub rewalk_interval: std::time::Duration,
    /// Past this age (walker stuck or failing) every request is answered
    /// "accounting failed", the NAN-3139 degraded mode: callers fall back to
    /// statvfs headroom under the volume target instead of blocking.
    pub max_age: std::time::Duration,
    /// NAN-3289 P2-5: the supervisor's own volume target. A client's limit
    /// is capped to it (never raised past it). `None`: client limits only
    /// (tests, standalone tools).
    pub target_bytes: Option<u64>,
    /// NAN-3289 P2-5: the most one connection (one tenant process) may hold
    /// in outstanding grants at once. `None`: no per-connection cap.
    pub peer_share_bytes: Option<u64>,
}

/// The hot-window volume target the query processes are rendered with
/// (`nanosiem-lake-worker` `local_hot_window::MAX_BYTES`), read by the
/// supervisor itself so the accountant never takes it from a tenant.
pub const HOT_WINDOW_MAX_BYTES_ENV: &str = "NANO_LAKE_LOCAL_HOT_WINDOW_MAX_BYTES";
/// `local_hot_window::DEFAULT_MAX_BYTES`: the target when none is rendered.
pub const DEFAULT_TARGET_BYTES: u64 = 12 * 1024 * 1024 * 1024;
/// One tenant process may hold at most this fraction of the target in
/// outstanding (in-flight) grants.
pub const PEER_SHARE_DIVISOR: u64 = 4;

impl AccountantConfig {
    pub fn from_env() -> Self {
        let rewalk_interval = std::env::var(REWALK_SECONDS_ENV)
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .filter(|seconds| *seconds > 0)
            .map_or(DEFAULT_REWALK, std::time::Duration::from_secs);
        let target = target_from(std::env::var(HOT_WINDOW_MAX_BYTES_ENV).ok().as_deref());
        Self::every(rewalk_interval).with_target(target)
    }

    pub fn every(rewalk_interval: std::time::Duration) -> Self {
        Self { rewalk_interval, max_age: rewalk_interval.saturating_mul(2), target_bytes: None, peer_share_bytes: None }
    }

    /// Cap every grant at `target` and each connection's outstanding grants
    /// at `target / PEER_SHARE_DIVISOR`.
    pub fn with_target(mut self, target: u64) -> Self {
        self.target_bytes = Some(target);
        self.peer_share_bytes = Some((target / PEER_SHARE_DIVISOR).max(1));
        self
    }
}

/// The supervisor's target: the rendered value, else the worker default.
fn target_from(value: Option<&str>) -> u64 {
    value.and_then(|v| v.trim().parse::<u64>().ok()).filter(|v| *v > 0).unwrap_or(DEFAULT_TARGET_BYTES)
}

/// In-memory usage figure (NAN-3147). Grants are O(1) arithmetic here; the
/// filesystem walk happens only on the walker thread, never under this lock.
#[derive(Default)]
struct Ledger {
    /// Bytes found by the last successful walk.
    base: Option<u64>,
    /// When that walk finished.
    walked_at: Option<std::time::Instant>,
    /// `landed` when that walk started: bytes released later may be missing
    /// from `base`, so they stay charged until a later walk.
    landed_at_walk: u64,
    /// Monotonic total of released grant bytes.
    landed: u64,
    /// Granted, not yet released.
    outstanding: u64,
    grants: u64,
    walks: u64,
}

type Walker = dyn Fn(&[PathBuf]) -> std::io::Result<u64> + Send + Sync;

struct Shared {
    roots: Vec<PathBuf>,
    config: AccountantConfig,
    walker: Box<Walker>,
    ledger: std::sync::Mutex<Ledger>,
}

/// The supervisor side: aggregate usage over fixed roots, as each owner.
#[derive(Clone)]
pub struct Accountant {
    shared: std::sync::Arc<Shared>,
}

/// Counters for tests and diagnostics.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct AccountantStats {
    pub walks: u64,
    pub grants: u64,
    pub outstanding: u64,
}

impl Accountant {
    fn ledger(&self) -> std::sync::MutexGuard<'_, Ledger> {
        self.shared.ledger.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// O(1): no filesystem access. Never grants beyond `limit` counting the
    /// last walk, every grant released since that walk began, and every
    /// outstanding grant.
    ///
    /// NAN-3289 P2-5: `limit` and `growth` come from a tenant process and
    /// are not trusted. The effective limit is the lower of the client's and
    /// the supervisor's own volume target (`config.target_bytes`), so a huge
    /// client limit can no longer saturate `outstanding` for every other
    /// tenant; and one connection may hold at most `config.peer_share_bytes`
    /// of outstanding grants (`held` is what it holds now).
    fn answer(&self, limit: u64, growth: u64, held: u64) -> u64 {
        let config = &self.shared.config;
        let limit = match (limit, config.target_bytes) {
            (0, _) => 0,
            (limit, Some(target)) => limit.min(target),
            (limit, None) => limit,
        };
        if limit > 0 && config.peer_share_bytes.is_some_and(|share| held.saturating_add(growth) > share) {
            return LIMIT_REACHED;
        }
        let mut ledger = self.ledger();
        let (Some(base), Some(walked_at)) = (ledger.base, ledger.walked_at) else {
            return ACCOUNTING_FAILED;
        };
        if walked_at.elapsed() > self.shared.config.max_age {
            return ACCOUNTING_FAILED;
        }
        let used = base
            .saturating_add(ledger.landed.saturating_sub(ledger.landed_at_walk))
            .saturating_add(ledger.outstanding);
        if limit > 0 && used.saturating_add(growth) > limit {
            return LIMIT_REACHED;
        }
        if limit > 0 {
            ledger.outstanding = ledger.outstanding.saturating_add(growth);
            ledger.grants += 1;
        }
        used.min(ACCOUNTING_FAILED - 1)
    }

    fn release(&self, growth: u64) {
        let mut ledger = self.ledger();
        let growth = growth.min(ledger.outstanding);
        ledger.outstanding -= growth;
        ledger.landed = ledger.landed.saturating_add(growth);
    }

    /// One walk outside the ledger lock, then an O(1) swap of the base.
    fn rewalk(&self) {
        let landed_before = self.ledger().landed;
        match (self.shared.walker)(&self.shared.roots) {
            Ok(bytes) => {
                let mut ledger = self.ledger();
                ledger.base = Some(bytes);
                ledger.walked_at = Some(std::time::Instant::now());
                ledger.landed_at_walk = landed_before;
                ledger.walks += 1;
            }
            Err(error) => tracing::warn!(%error,
                "volume usage walk failed; serving the previous figure until it ages out"),
        }
    }

    pub fn stats(&self) -> AccountantStats {
        let ledger = self.ledger();
        AccountantStats { walks: ledger.walks, grants: ledger.grants, outstanding: ledger.outstanding }
    }

    /// Serve one connection. Each request gets a reply; a release frame gets
    /// none. Grants this connection still holds at EOF (exit or crash) are
    /// released, so a dead writer never leaks headroom.
    fn serve(&self, stream: &mut std::os::unix::net::UnixStream) {
        let mut held = 0_u64;
        loop {
            let mut request = [0; 16];
            if stream.read_exact(&mut request).is_err() {
                break;
            }
            let (limit, growth) = parse(&request);
            if limit == RELEASE_LIMIT {
                // Only this connection's own grants can be released.
                let growth = growth.min(held);
                held -= growth;
                self.release(growth);
                continue;
            }
            let reply = self.answer(limit, growth, held);
            if limit > 0 && reply < ACCOUNTING_FAILED {
                held = held.saturating_add(growth);
            }
            if stream.write_all(&reply.to_le_bytes()).is_err() {
                break;
            }
        }
        self.release(held);
    }

    /// A preconnected connection for one jailed tenant process. Pass the
    /// returned fd with `SCM_RIGHTS`; a dedicated thread serves it until the
    /// process closes its end (exit or crash).
    pub fn pair(&self) -> std::io::Result<std::os::fd::OwnedFd> {
        let (mut ours, theirs) = std::os::unix::net::UnixStream::pair()?;
        let accountant = self.clone();
        std::thread::Builder::new()
            .name("volume-usage-peer".into())
            .spawn(move || accountant.serve(&mut ours))?;
        Ok(theirs.into())
    }

    fn spawn_walker(&self) -> std::io::Result<std::sync::mpsc::Receiver<()>> {
        let (first_tx, first_rx) = std::sync::mpsc::channel();
        let weak = std::sync::Arc::downgrade(&self.shared);
        let interval = self.shared.config.rewalk_interval;
        std::thread::Builder::new()
            .name("volume-usage-walk".into())
            .spawn(move || {
                while let Some(shared) = weak.upgrade() {
                    Accountant { shared }.rewalk();
                    let _ = first_tx.send(());
                    std::thread::sleep(interval);
                }
            })?;
        Ok(first_rx)
    }
}

/// The filesystem `path` lives on: its own device, or its nearest existing
/// ancestor's (the hot root may not exist before the accountant creates it).
/// Stacked/shared-capacity filesystems are unknown: distinct device IDs do
/// not prove independent capacity for overlay upper dirs or Btrfs subvolumes.
fn device_of(path: &Path) -> Option<u64> {
    for dir in path.ancestors() {
        match std::fs::metadata(dir) {
            Ok(meta) => {
                let filesystem = nix::sys::statfs::statfs(dir).ok()?.filesystem_type();
                return independent_device(meta.dev(), filesystem);
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            // Permission, symlink-loop and I/O errors do not prove the
            // path is absent: its parent may be on a different filesystem.
            // Keep the root charged rather than guessing that device.
            Err(_) => return None,
        }
    }
    None
}

fn independent_device(device: u64, filesystem: nix::sys::statfs::FsType) -> Option<u64> {
    use nix::sys::statfs::{BTRFS_SUPER_MAGIC, OVERLAYFS_SUPER_MAGIC};
    if filesystem == OVERLAYFS_SUPER_MAGIC || filesystem == BTRFS_SUPER_MAGIC {
        None
    } else {
        Some(device)
    }
}

/// NAN-4777: the `candidates` that share `root`'s filesystem, `root` first.
/// The hot-window target is the size of the volume holding `root`. Bytes on
/// another filesystem never use that space, so they must not count as
/// "other data" on it.
///
/// Before this, the persistent A/B hot PVC (NAN-3647) was still charged
/// with the whole data volume (#5207 predates the split). On one hosted
/// tenant that was
/// 34.7 GB: the producer warm-on-write tier, ingest, slatedb and the
/// agent-catalog export. Together with 37 GB of product state actually on
/// the hot volume, it shrank the window to a 4-18 GB target against the
/// ~47 GB a 168 h window needs. The fence then refused hot downloads as
/// "saturated by leased or protected objects", although the cache held
/// almost no leases.
///
/// When a device is unknown (unreadable path or shared-capacity filesystem),
/// the candidate is kept. That over-counts, the safe direction for a fence.
pub fn same_volume_roots(root: &Path, candidates: impl IntoIterator<Item = PathBuf>) -> Vec<PathBuf> {
    same_volume_roots_by(root, candidates, device_of)
}

fn same_volume_roots_by(
    root: &Path,
    candidates: impl IntoIterator<Item = PathBuf>,
    device: impl Fn(&Path) -> Option<u64>,
) -> Vec<PathBuf> {
    let home = device(root);
    let mut roots = vec![root.to_path_buf()];
    for candidate in candidates {
        if roots.contains(&candidate) {
            continue;
        }
        let same = match (home, device(&candidate)) {
            (Some(home), Some(other)) => home == other,
            _ => true,
        };
        if same {
            roots.push(candidate);
        } else {
            tracing::info!(root = %root.display(), excluded = %candidate.display(),
                "volume accountant: root is on another filesystem; not charged to the hot-window volume");
        }
    }
    roots
}

/// NAN-4777: the cell's hot-window accountant. It is bound at `hot_root` and
/// charges only the `other_roots` that share its filesystem (see
/// [`same_volume_roots`]). The supervisor passes the data dir. When the hot
/// window lives on the data volume (no A/B hot PVC), the data dir is still
/// counted, as before.
pub fn start_hot_window_accountant(hot_root: PathBuf, other_roots: Vec<PathBuf>) -> std::io::Result<Accountant> {
    let roots = same_volume_roots(&hot_root, other_roots);
    start(hot_root, roots)
}

/// [`start_hot_window_accountant`] with an explicit config and device lookup
/// (tests: two filesystems in one temp dir).
pub fn start_hot_window_accountant_with(
    hot_root: PathBuf,
    other_roots: Vec<PathBuf>,
    config: AccountantConfig,
    device: impl Fn(&Path) -> Option<u64>,
) -> std::io::Result<Accountant> {
    let roots = same_volume_roots_by(&hot_root, other_roots, device);
    start_with(hot_root, roots, config)
}

/// Bind before starting tenant processes. Requests contain no paths or tenant
/// identifiers: clients cannot use the supervisor to read arbitrary files.
/// Jailed tenant processes cannot reach the socket; give them [`Accountant::pair`].
pub fn start(root: PathBuf, accounting_roots: Vec<PathBuf>) -> std::io::Result<Accountant> {
    start_with(root, accounting_roots, AccountantConfig::from_env())
}

pub fn start_with(
    root: PathBuf,
    accounting_roots: Vec<PathBuf>,
    config: AccountantConfig,
) -> std::io::Result<Accountant> {
    start_walking(root, accounting_roots, config, Box::new(|roots| walk(roots, true)))
}

fn start_walking(
    root: PathBuf,
    accounting_roots: Vec<PathBuf>,
    config: AccountantConfig,
    walker: Box<Walker>,
) -> std::io::Result<Accountant> {
    std::fs::create_dir_all(&root)?;
    let socket = root.join(SOCKET);
    match std::fs::remove_file(&socket) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    let listener = std::os::unix::net::UnixListener::bind(&socket)?;
    std::fs::set_permissions(socket, std::fs::Permissions::from_mode(0o666))?;
    let accountant = Accountant {
        shared: std::sync::Arc::new(Shared {
            roots: accounting_roots,
            config,
            walker,
            ledger: std::sync::Mutex::default(),
        }),
    };
    // Serve from the first walk when it is quick; a slow first walk only
    // means "accounting failed" (statvfs headroom) until it lands.
    let _ = accountant.spawn_walker()?.recv_timeout(FIRST_WALK_WAIT);
    let served = accountant.clone();
    std::thread::Builder::new()
        .name("volume-usage".into())
        .spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else {
                    break;
                };
                let timeout = Some(std::time::Duration::from_secs(30));
                let _ = stream.set_write_timeout(timeout);
                let _ = stream.set_read_timeout(timeout);
                let accountant = served.clone();
                // One thread per connection: a granted connection is held
                // open until its write ends (EOF releases), and must not stall
                // other clients. A killed/crashed writer closes the fd.
                let _ = std::thread::Builder::new().name("volume-usage-conn".into()).spawn(move || {
                    let mut request = [0; 16];
                    if stream.read_exact(&mut request).is_err() {
                        return;
                    }
                    let (limit, growth) = parse(&request);
                    if limit == RELEASE_LIMIT {
                        return;
                    }
                    let reply = accountant.answer(limit, growth, 0);
                    let granted = limit > 0 && reply < ACCOUNTING_FAILED;
                    if granted && stream.write_all(&reply.to_le_bytes()).is_ok() {
                        let _ = stream.set_read_timeout(None);
                        let _ = stream.read(&mut [0]);
                    } else if !granted {
                        let _ = stream.write_all(&reply.to_le_bytes());
                    }
                    if granted {
                        accountant.release(growth);
                    }
                });
            }
        })?;
    Ok(accountant)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn concurrent_writers_cannot_spend_the_same_headroom() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().to_path_buf();
        start(root.clone(), vec![root.clone()]).unwrap();
        let limit = usage(&root).unwrap() + 8192;
        let first = reserve_write(&root, limit, 8192).unwrap();
        let (started_tx, started_rx) = std::sync::mpsc::channel();
        let second_root = root.clone();
        let second = std::thread::spawn(move || {
            started_tx.send(()).unwrap();
            reserve_write(&second_root, limit, 8192).is_err()
        });
        started_rx.recv().unwrap();
        std::fs::write(root.join("first"), vec![0; 8192]).unwrap();
        drop(first);
        assert!(
            second.join().unwrap(),
            "second writer must see the first allocation"
        );
        assert!(usage(&root).unwrap() <= limit);
    }

    fn leaked_client(accountant: &Accountant) -> &'static AccountantClient {
        Box::leak(Box::new(AccountantClient::new(accountant.pair().unwrap()).unwrap()))
    }

    /// NAN-3139: under the real tenant seccomp policy, creating an AF_UNIX
    /// socket (the old per-request connect to SOCKET) is EPERM, which failed
    /// every hot-window cache admission in the query process. The
    /// supervisor-passed connection must serve usage and fences there.
    #[test]
    fn jailed_thread_reaches_accountant_only_through_passed_fd() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().to_path_buf();
        let accountant = start(root.clone(), vec![root.clone()]).unwrap();
        let client = leaked_client(&accountant);
        let socket = root.join(SOCKET);
        let expected = directory_bytes(&root).unwrap();
        let root_in_jail = root.clone();
        std::thread::spawn(move || {
            // seccomp filters are per-thread without TSYNC: only this thread is jailed.
            // SAFETY: plain prctl on the calling thread.
            assert_eq!(unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) }, 0);
            for program in crate::jail::seccomp_filter().unwrap() {
                seccompiler::apply_filter(&program).unwrap();
            }
            let denied = std::os::unix::net::UnixStream::connect(&socket).unwrap_err();
            assert_eq!(denied.raw_os_error(), Some(libc::EPERM), "{denied}");
            let old_path = usage(&root_in_jail).unwrap_err();
            assert_eq!(old_path.raw_os_error(), Some(libc::EPERM), "{old_path}");
            assert_eq!(client.usage().unwrap(), expected);
            drop(client.reserve_write(expected + (1 << 20), 4096).unwrap());
            let full = client.reserve_write(1, 4096).err().expect("over the target");
            assert!(is_limit_reached(&full), "{full}");
            // The connection stays in sync after a grant, a release and a
            // refusal. The released grant stays charged until the next walk.
            assert_eq!(client.usage().unwrap(), expected + 4096);
        })
        .join()
        .unwrap();
    }

    #[test]
    fn passed_connections_share_one_fence() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().to_path_buf();
        let accountant = start(root.clone(), vec![root.clone()]).unwrap();
        let (first_client, second_client) = (leaked_client(&accountant), leaked_client(&accountant));
        let limit = first_client.usage().unwrap() + 8192;
        let first = first_client.reserve_write(limit, 8192).unwrap();
        let second = std::thread::spawn(move || {
            second_client
                .reserve_write(limit, 8192)
                .err()
                .is_some_and(|error| is_limit_reached(&error))
        });
        std::fs::write(root.join("first"), vec![0; 8192]).unwrap();
        drop(first);
        assert!(second.join().unwrap(), "second writer must see the first allocation");
    }

    /// A walker that counts calls and reports a settable figure.
    fn counted(
        root: &Path,
        config: AccountantConfig,
    ) -> (Accountant, std::sync::Arc<std::sync::atomic::AtomicU64>, std::sync::Arc<std::sync::atomic::AtomicU64>) {
        use std::sync::atomic::{AtomicU64, Ordering};
        let walks = std::sync::Arc::new(AtomicU64::new(0));
        let figure = std::sync::Arc::new(AtomicU64::new(1 << 20));
        let (w, f) = (walks.clone(), figure.clone());
        let accountant = start_walking(root.to_path_buf(), vec![root.to_path_buf()], config, Box::new(move |_| {
            w.fetch_add(1, Ordering::SeqCst);
            Ok(f.load(Ordering::SeqCst))
        }))
        .unwrap();
        (accountant, walks, figure)
    }

    /// NAN-3147: every request walked the whole cell volume under the global
    /// fence (7.6 s -> 52 s searches). Answers must come from memory.
    #[test]
    fn answers_never_walk_on_the_request_path() {
        use std::sync::atomic::Ordering;
        let dir = tempfile::tempdir().unwrap();
        let (accountant, walks, _) = counted(dir.path(), AccountantConfig::every(std::time::Duration::from_secs(3600)));
        let client = leaked_client(&accountant);
        for _ in 0..500 {
            client.usage().unwrap();
            drop(client.reserve_write(u64::MAX - 7, 4096).unwrap());
        }
        for _ in 0..50 {
            drop(reserve_write(dir.path(), 1 << 40, 4096).unwrap());
        }
        assert_eq!(walks.load(Ordering::SeqCst), 1, "only the start-up walk; none per request");
        assert_eq!(accountant.stats().grants, 550);
    }

    /// Held grants are charged in memory: concurrent writers never spend the
    /// same headroom even though no lock is held across a grant.
    #[test]
    fn concurrent_grants_never_exceed_the_limit() {
        let dir = tempfile::tempdir().unwrap();
        let (accountant, _, _) = counted(dir.path(), AccountantConfig::every(std::time::Duration::from_secs(3600)));
        let base = (1 << 20) as u64;
        let limit = base + 10 * 4096;
        let clients: Vec<_> = (0..4).map(|_| leaked_client(&accountant)).collect();
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(4));
        let handles: Vec<_> = clients
            .into_iter()
            .map(|client| {
                let barrier = barrier.clone();
                std::thread::spawn(move || {
                    barrier.wait();
                    (0..10).filter_map(|_| client.reserve_write(limit, 4096).ok()).collect::<Vec<_>>()
                })
            })
            .collect();
        let held: Vec<WriteGuard> = handles.into_iter().flat_map(|h| h.join().unwrap()).collect();
        assert_eq!(held.len(), 10, "exactly the headroom is granted");
        assert_eq!(accountant.stats().outstanding, 10 * 4096);
        drop(held);
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while accountant.stats().outstanding != 0 && std::time::Instant::now() < deadline {
            std::thread::yield_now();
        }
        // Released bytes stay charged (landed) until a walk sees them.
        let client = leaked_client(&accountant);
        assert_eq!(client.usage().unwrap(), limit);
        assert!(is_limit_reached(&client.reserve_write(limit, 1).err().unwrap()));
    }

    /// The next walk replaces the base; outstanding grants survive it,
    /// grants released before the walk began are reconciled away.
    #[test]
    fn walks_reconcile_landed_bytes_and_keep_outstanding_grants() {
        use std::sync::atomic::Ordering;
        let dir = tempfile::tempdir().unwrap();
        let (accountant, walks, figure) = counted(dir.path(), AccountantConfig::every(std::time::Duration::from_millis(20)));
        let client = leaked_client(&accountant);
        let base = 1 << 20;
        let held = client.reserve_write(1 << 40, 8192).unwrap();
        drop(client.reserve_write(1 << 40, 4096).unwrap());
        assert!(client.usage().unwrap() >= base + 8192 + 4096);
        // The released write landed on disk; the next walks see it.
        figure.store(base + 4096, Ordering::SeqCst);
        let seen = walks.load(Ordering::SeqCst);
        while walks.load(Ordering::SeqCst) < seen + 2 {
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        assert_eq!(client.usage().unwrap(), base + 4096 + 8192, "outstanding grant survives the walk");
        drop(held);
    }

    /// A stuck walker must not block answers: past max_age every request is
    /// "accounting failed" (statvfs-headroom degrade), not a wait.
    #[test]
    fn stuck_walker_degrades_instead_of_blocking() {
        let dir = tempfile::tempdir().unwrap();
        let calls = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
        let seen = calls.clone();
        let config = AccountantConfig {
            rewalk_interval: std::time::Duration::from_millis(10),
            max_age: std::time::Duration::from_millis(100),
            target_bytes: None,
            peer_share_bytes: None,
        };
        let accountant = start_walking(dir.path().to_path_buf(), vec![], config, Box::new(move |_| {
            if seen.fetch_add(1, std::sync::atomic::Ordering::SeqCst) > 0 {
                std::thread::sleep(std::time::Duration::from_secs(3600));
            }
            Ok(4096)
        }))
        .unwrap();
        let client = leaked_client(&accountant);
        assert_eq!(client.usage().unwrap(), 4096);
        std::thread::sleep(std::time::Duration::from_millis(200));
        let started = std::time::Instant::now();
        let error = client.reserve_write(1 << 40, 4096).err().expect("stale figure");
        assert!(!is_limit_reached(&error), "{error}");
        assert!(client.usage().is_err());
        assert!(started.elapsed() < std::time::Duration::from_secs(1));
    }

    /// NAN-3147: a grant (an in-flight hydration download) used to hold the
    /// process's accountant connection and the supervisor fence until it was
    /// released, so foreground cold-fetch admissions queued behind it.
    #[test]
    fn held_grant_does_not_block_other_admissions() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().to_path_buf();
        let accountant = start(root.clone(), vec![root.clone()]).unwrap();
        let (client, other) = (leaked_client(&accountant), leaked_client(&accountant));
        let hydration = client.reserve_write(1 << 40, 1 << 20).unwrap();
        let socket = reserve_write(&root, 1 << 40, 1 << 20).unwrap();
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            // Same process connection, another process, and the socket path.
            let same = client.reserve_write(1 << 40, 4096).map(drop).is_ok();
            let peer = other.reserve_write(1 << 40, 4096).map(drop).is_ok();
            let listener = reserve_write(&root, 1 << 40, 4096).map(drop).is_ok();
            let _ = done_tx.send(same && peer && listener);
        });
        let admitted = done_rx.recv_timeout(std::time::Duration::from_secs(2));
        drop((hydration, socket));
        assert_eq!(admitted, Ok(true), "foreground admission blocked behind a held grant");
    }

    /// A crashed writer's grants are released by EOF.
    #[test]
    fn closed_peer_releases_its_grants() {
        let dir = tempfile::tempdir().unwrap();
        let (accountant, _, _) = counted(dir.path(), AccountantConfig::every(std::time::Duration::from_secs(3600)));
        let client = AccountantClient::new(accountant.pair().unwrap()).unwrap();
        let client: &'static AccountantClient = Box::leak(Box::new(client));
        let guard = client.reserve_write(1 << 40, 8192).unwrap();
        std::mem::forget(guard);
        assert_eq!(accountant.stats().outstanding, 8192);
        *client.stream.lock().unwrap() = None;
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while accountant.stats().outstanding != 0 {
            assert!(std::time::Instant::now() < deadline, "EOF must release");
            std::thread::yield_now();
        }
    }

    #[test]
    fn usage_counts_other_data_and_deduplicates_pins() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("ingest"), vec![0; 8192]).unwrap();
        let before = directory_bytes(dir.path()).unwrap();
        std::fs::hard_link(dir.path().join("ingest"), dir.path().join("pin")).unwrap();
        assert_eq!(directory_bytes(dir.path()).unwrap(), before);
        std::os::unix::fs::symlink("/", dir.path().join("outside")).unwrap();
        assert!(directory_bytes(dir.path()).unwrap() < before + 8192);
        start(dir.path().to_path_buf(), vec![dir.path().to_path_buf()]).unwrap();
        assert_eq!(
            usage(dir.path()).unwrap(),
            directory_bytes(dir.path()).unwrap()
        );
    }

    /// NAN-3523: the per-tenant disk walk skips the named subtree and stops
    /// at its entry bound with a lower-bound figure.
    #[test]
    fn owned_tree_usage_skips_and_bounds() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("query/cache")).unwrap();
        std::fs::create_dir_all(dir.path().join("ingest/tmp")).unwrap();
        std::fs::write(dir.path().join("query/cache/part"), vec![1; 1 << 20]).unwrap();
        std::fs::write(dir.path().join("ingest/tmp/spill"), vec![1; 1 << 16]).unwrap();
        let all = owned_tree_usage(dir.path(), &[], u64::MAX).unwrap();
        let skip = Path::new("query/cache");
        let some = owned_tree_usage(dir.path(), &[skip], u64::MAX).unwrap();
        assert!(all.complete && some.complete);
        assert!(all.bytes >= some.bytes + (1 << 20), "{all:?} {some:?}");
        assert!(some.bytes >= 1 << 16);
        let bounded = owned_tree_usage(dir.path(), &[], 1).unwrap();
        assert!(!bounded.complete && bounded.entries == 1 && bounded.bytes <= all.bytes);
        assert_eq!(directory_bytes(dir.path()).unwrap(), all.bytes);
    }

    /// NAN-3289 P2-5: a tenant's huge `limit`/`growth` frame neither
    /// saturates the cell-wide ledger nor starves another tenant, and one
    /// connection cannot hold more than its share.
    #[test]
    fn client_limits_and_growth_are_not_trusted() {
        let dir = tempfile::tempdir().unwrap();
        let target = 64 << 20;
        let config = AccountantConfig::every(std::time::Duration::from_secs(3600)).with_target(target);
        let (accountant, _, _) = counted(dir.path(), config);
        let (alpha, bravo) = (leaked_client(&accountant), leaked_client(&accountant));
        // The saturation frame from the review.
        let refused = alpha.ask(u64::MAX - 2, u64::MAX - 3).unwrap_err();
        assert!(is_limit_reached(&refused), "{refused}");
        assert_eq!(accountant.stats().outstanding, 0, "nothing charged");
        // A client limit above the target is capped to it.
        assert!(is_limit_reached(&alpha.reserve_write(u64::MAX - 7, target).err().unwrap()));
        // Per-connection share: target / 4.
        let share = target / PEER_SHARE_DIVISOR;
        let held = alpha.reserve_write(u64::MAX - 7, share).unwrap();
        assert!(is_limit_reached(&alpha.reserve_write(u64::MAX - 7, 4096).err().unwrap()), "over alpha's share");
        // Bravo still gets its own headroom.
        drop(bravo.reserve_write(u64::MAX - 7, 4096).unwrap());
        drop(held);
        assert_eq!(target_from(None), DEFAULT_TARGET_BYTES);
        assert_eq!(target_from(Some(" 1024 ")), 1024);
        assert_eq!(target_from(Some("0")), DEFAULT_TARGET_BYTES);
        assert!(AccountantConfig::from_env().target_bytes.is_some(), "the supervisor always caps");
    }

    /// NAN-4777: only roots on the hot root's filesystem are charged to it.
    /// An unknown device is kept (over-counting is the safe side).
    #[test]
    fn hot_window_accountant_charges_only_its_own_filesystem() {
        let (hot, data, shared) = (PathBuf::from("/hot"), PathBuf::from("/data"), PathBuf::from("/hot-scratch"));
        let device = |path: &Path| match path.to_str() {
            Some("/hot" | "/hot-scratch") => Some(1),
            Some("/data") => Some(2),
            _ => None,
        };
        assert_eq!(same_volume_roots_by(&hot, [data.clone(), shared.clone(), hot.clone()], device), vec![hot.clone(), shared]);
        // The hot window on the data volume (no A/B PVC): both, as before.
        assert_eq!(same_volume_roots_by(&data, [data.clone()], device), vec![data.clone()]);
        assert_eq!(same_volume_roots_by(&hot, [PathBuf::from("/unknown")], device), vec![hot.clone(), PathBuf::from("/unknown")]);
        // Real devices: a temp dir shares its own filesystem, and a root
        // that does not exist yet resolves through its ancestors.
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("not-yet");
        assert_eq!(same_volume_roots(&missing, [dir.path().to_path_buf()]), vec![missing.clone(), dir.path().to_path_buf()]);

        // Production start: a separate "data volume" full of bytes is not
        // charged to the hot volume's figure.
        let (hot_dir, data_dir) = (dir.path().join("hot"), dir.path().join("data"));
        std::fs::create_dir_all(&data_dir).unwrap();
        std::fs::File::create(data_dir.join("producer-tier")).unwrap().set_len(1 << 30).unwrap();
        let config = || AccountantConfig::every(std::time::Duration::from_secs(3600));
        let apart = |path: &Path| Some(if path.starts_with(&data_dir) { 2 } else { 1 });
        start_hot_window_accountant_with(hot_dir.clone(), vec![data_dir.clone()], config(), apart).unwrap();
        assert!(usage(&hot_dir).unwrap() < 1 << 20, "data volume charged to the hot volume");
        start_hot_window_accountant_with(hot_dir.clone(), vec![data_dir.clone()], config(), |_: &Path| Some(1)).unwrap();
        assert!(usage(&hot_dir).unwrap() >= 1 << 30, "one shared volume still counts the data dir");
    }

    #[test]
    fn device_lookup_errors_do_not_guess_the_parent_filesystem() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("not-yet/created");
        assert_eq!(device_of(&missing), device_of(dir.path()));

        // ELOOP is deterministic even when the test runs as root. Like
        // EACCES or EIO it must leave identity unknown, not use the parent.
        let unreadable = dir.path().join("loop");
        std::os::unix::fs::symlink("loop", &unreadable).unwrap();
        assert_eq!(device_of(&unreadable), None);
        assert_eq!(
            same_volume_roots(&unreadable, [dir.path().to_path_buf()]),
            vec![unreadable.clone(), dir.path().to_path_buf()],
        );
        assert_eq!(
            same_volume_roots(dir.path(), [unreadable.clone()]),
            vec![dir.path().to_path_buf(), unreadable],
        );
    }

    #[test]
    fn shared_volume_accountant_counts_nested_data_and_hot_roots_once() {
        let data = tempfile::tempdir().unwrap();
        let hot = data.path().join("hot");
        std::fs::create_dir_all(&hot).unwrap();
        std::fs::File::create(data.path().join("producer-tier")).unwrap().set_len(1 << 20).unwrap();
        std::fs::File::create(hot.join("reader-cache")).unwrap().set_len(1 << 20).unwrap();
        let _accountant = start_hot_window_accountant(hot.clone(), vec![data.path().to_path_buf()]).unwrap();
        assert_eq!(usage(&hot).unwrap(), directory_bytes(data.path()).unwrap());
    }

    #[test]
    fn production_accountant_rechecks_the_device_for_each_hot_root() {
        let data = tempfile::tempdir().unwrap();
        let Ok(hot_a) = tempfile::tempdir_in("/dev/shm") else {
            eprintln!("no writable /dev/shm for the real two-filesystem test");
            return;
        };
        let (Some(data_device), Some(hot_device)) = (device_of(data.path()), device_of(hot_a.path())) else {
            eprintln!("stacked/shared-capacity filesystem; cannot prove separate devices");
            return;
        };
        if data_device == hot_device {
            eprintln!("temp dir and /dev/shm share one filesystem");
            return;
        }
        std::fs::File::create(data.path().join("producer-tier")).unwrap().set_len(1 << 20).unwrap();
        let _a = start_hot_window_accountant(hot_a.path().to_path_buf(), vec![data.path().to_path_buf()]).unwrap();
        assert_eq!(usage(hot_a.path()).unwrap(), directory_bytes(hot_a.path()).unwrap());

        // A fresh accountant on a shared filesystem must select roots
        // again; it must not reuse the previous hot root's device decision.
        let hot_b = data.path().join("hot-b");
        let _b = start_hot_window_accountant(hot_b.clone(), vec![data.path().to_path_buf()]).unwrap();
        assert_eq!(usage(&hot_b).unwrap(), directory_bytes(data.path()).unwrap());
        assert!(usage(&hot_b).unwrap() >= 1 << 20);
    }

    #[test]
    fn shared_capacity_devices_remain_charged() {
        use nix::sys::statfs::{BTRFS_SUPER_MAGIC, EXT4_SUPER_MAGIC, OVERLAYFS_SUPER_MAGIC};
        let (hot, data) = (PathBuf::from("/hot"), PathBuf::from("/data"));
        // Different overlay instances or Btrfs subvolumes can share one
        // backing filesystem. Exercise both directions of the comparison.
        for shared in [OVERLAYFS_SUPER_MAGIC, BTRFS_SUPER_MAGIC] {
            for hot_shared in [true, false] {
                let device = |path: &Path| {
                    let is_hot = path == hot;
                    independent_device(
                        if is_hot { 1 } else { 2 },
                        if is_hot == hot_shared { shared } else { EXT4_SUPER_MAGIC },
                    )
                };
                assert_eq!(same_volume_roots_by(&hot, [data.clone()], device), vec![hot.clone(), data.clone()]);
            }
        }
        let separate = |path: &Path| {
            independent_device(if path == hot { 1 } else { 2 }, EXT4_SUPER_MAGIC)
        };
        assert_eq!(same_volume_roots_by(&hot, [data], separate), vec![hot.clone()]);
    }
}
