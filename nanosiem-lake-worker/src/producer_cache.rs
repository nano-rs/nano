// SPDX-License-Identifier: AGPL-3.0-or-later
//! Bounded producer tier on the tenant's shared, reader-read-only parts mount.
//! Readers still admit and lease bytes through the verified reader cache.
use anyhow::{ensure, Result};
use fs2::FileExt;
use std::os::unix::fs::PermissionsExt;
use std::collections::{BTreeSet, HashMap};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant, SystemTime};
pub static READER_CACHE_WARM_ON_WRITE_OBJECTS: AtomicU64 = AtomicU64::new(0);

pub fn root(parts: &Path) -> PathBuf {
    parts.join("reader-objects")
}
pub fn object(parts: &Path, digest: &str) -> Result<PathBuf> {
    ensure!(
        crate::parts::is_sha256_hex(digest),
        "invalid producer object digest"
    );
    Ok(root(parts).join(format!("{digest}.bin")))
}
fn index_path(parts: &Path, key: &str) -> PathBuf {
    root(parts).join(format!("{}.ref", crate::parts::sha256_hex(key.as_bytes())))
}
fn locked<T>(parts: &Path, work: impl FnOnce() -> Result<T>) -> Result<T> {
    let dir = root(parts);
    std::fs::create_dir_all(&dir)?;
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o2770))?;
    let lock = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(dir.join(".lock"))?;
    lock.lock_exclusive()?;
    work()
}

/// Staging subdirectory (same filesystem, so publication is a rename).
/// Staging outside the tier's own directory leaves that directory's mtime
/// to the locked writers, which is how a stale in-memory index is detected.
const STAGING: &str = ".staging";
/// A staging file older than this belongs to a terminated writer. Staging
/// runs outside the lock (NAN-3610), so a younger one may be in use.
const ABANDONED_STAGING_AGE: Duration = Duration::from_secs(3600);
/// Rebuild the in-memory index from the directory at least this often, a
/// backstop for another process's change the directory mtime check missed.
const INDEX_RESCAN_INTERVAL: Duration = Duration::from_secs(600);
/// The stale-reference sweep (GC pass) runs at most this often per tier.
const REF_SWEEP_INTERVAL: Duration = Duration::from_secs(3600);

/// What one producer tier holds, kept in memory so a warm costs O(evicted)
/// rather than a scan of every cached object (NAN-3610: three directory
/// scans and a read of every `.ref` per file, 0.17 s -> 2.7 s per part
/// after 5 h on the load-test tenant, all on the ingest flush's critical path).
/// Only valid while the directory is unchanged since this process last
/// held the lock (its mtime), and rebuilt every [`INDEX_RESCAN_INTERVAL`].
struct TierIndex {
    /// digest -> (age key, bytes).
    objects: HashMap<String, (SystemTime, u64)>,
    /// Oldest first: the capacity eviction order.
    by_age: BTreeSet<(SystemTime, String)>,
    used: u64,
    dir_mtime: Option<SystemTime>,
    scanned_at: Instant,
}

impl TierIndex {
    fn scan(dir: &Path) -> Result<Self> {
        let mut index = TierIndex {
            objects: HashMap::new(),
            by_age: BTreeSet::new(),
            used: 0,
            dir_mtime: None,
            scanned_at: Instant::now(),
        };
        let now = SystemTime::now();
        // Remove only staging files no live writer can still own.
        if let Ok(entries) = std::fs::read_dir(dir.join(STAGING)) {
            for entry in entries {
                let entry = entry?;
                let abandoned = entry.metadata().and_then(|meta| meta.modified()).map_or(true, |modified| {
                    now.duration_since(modified).unwrap_or_default() >= ABANDONED_STAGING_AGE
                });
                if abandoned {
                    remove_if_present(&entry.path())?;
                }
            }
        }
        for entry in std::fs::read_dir(dir)? {
            let entry = entry?;
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if name.starts_with(".warm-") {
                // Staged here (under the lock) by an older build: abandoned.
                remove_if_present(&entry.path())?;
                continue;
            }
            let Some(digest) = name.strip_suffix(".bin") else { continue };
            if !crate::parts::is_sha256_hex(digest) {
                continue;
            }
            let meta = match entry.metadata() {
                Ok(meta) => meta,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(error) => return Err(error.into()),
            };
            index.insert(digest.to_string(), meta.modified()?, meta.len());
        }
        Ok(index)
    }

    fn insert(&mut self, digest: String, age: SystemTime, bytes: u64) {
        self.remove(&digest);
        self.used = self.used.saturating_add(bytes);
        self.by_age.insert((age, digest.clone()));
        self.objects.insert(digest, (age, bytes));
    }

    fn remove(&mut self, digest: &str) {
        if let Some((age, bytes)) = self.objects.remove(digest) {
            self.by_age.remove(&(age, digest.to_string()));
            self.used = self.used.saturating_sub(bytes);
        }
    }
}

type Tiers = Mutex<HashMap<PathBuf, TierIndex>>;

fn tiers() -> &'static Tiers {
    static TIERS: OnceLock<Tiers> = OnceLock::new();
    TIERS.get_or_init(|| Mutex::new(HashMap::new()))
}

fn dir_mtime(dir: &Path) -> Option<SystemTime> {
    std::fs::metadata(dir).and_then(|meta| meta.modified()).ok()
}

fn remove_if_present(path: &Path) -> Result<()> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

/// Run `work` on the tier's index with the cross-process lock held. The
/// index is rebuilt first when another process changed the directory (its
/// mtime moved since this process last released the lock) or it is older
/// than [`INDEX_RESCAN_INTERVAL`]; on error it is dropped, so a partial
/// change is never trusted.
fn with_index<T>(parts: &Path, work: impl FnOnce(&Path, &mut TierIndex) -> Result<T>) -> Result<T> {
    locked(parts, || {
        let dir = root(parts);
        let mut tiers = tiers().lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let current = dir_mtime(&dir);
        let fresh = tiers.get(&dir).is_some_and(|index| {
            index.dir_mtime.is_some() && index.dir_mtime == current
                && index.scanned_at.elapsed() < INDEX_RESCAN_INTERVAL
        });
        if !fresh {
            tiers.insert(dir.clone(), TierIndex::scan(&dir)?);
        }
        let index = tiers.get_mut(&dir).expect("inserted above");
        match work(&dir, index) {
            Ok(value) => {
                index.dir_mtime = dir_mtime(&dir);
                Ok(value)
            }
            Err(error) => {
                tiers.remove(&dir);
                Err(error)
            }
        }
    })
}

/// Copy rather than hard-link a mutable writer inode. Hash the copy, then
/// atomically publish it read-only. Capacity eviction never affects an open
/// reader fd; readers copy into their normal leased cache before execution.
///
/// NAN-3610: the copy, its verification and fsync run outside the lock, so
/// warms of one flush overlap; under the lock only the eviction (O(evicted)
/// through the in-memory index), the rename and the key reference remain.
/// A reader that misses an object (not yet warmed, evicted, or over
/// capacity) still fetches it from the object store.
fn warm_indexed(
    parts: &Path,
    key: &str,
    source: &Path,
    digest: &str,
    bytes: u64,
    max_bytes: u64,
) -> Result<bool> {
    let target = object(parts, digest)?;
    if bytes > max_bytes {
        return Ok(false);
    }
    let staging = root(parts).join(STAGING);
    std::fs::create_dir_all(&staging)?;
    let mut temp = tempfile::Builder::new()
        .prefix(".warm-")
        .tempfile_in(&staging)?;
    std::io::copy(
        &mut std::io::Read::take(std::fs::File::open(source)?, bytes.saturating_add(1)),
        &mut temp,
    )?;
    ensure!(
        temp.as_file().metadata()?.len() == bytes
            && crate::native::file_sha256(temp.path())? == digest,
        "producer object failed signed length/digest verification"
    );
    temp.as_file().sync_all()?;
    std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o444))?;
    with_index(parts, |dir, index| {
        // Replace an existing digest too: a damaged local copy must not win.
        index.remove(digest);
        remove_if_present(&target)?;
        while index.used.saturating_add(bytes) > max_bytes {
            let Some((_, oldest)) = index.by_age.first().cloned() else { break };
            index.remove(&oldest);
            remove_if_present(&dir.join(format!("{oldest}.bin")))?;
        }
        // Stale `.ref`s of evicted objects are swept by the GC pass
        // ([`sweep_stale_refs`]); readers never read them.
        temp.persist(&target).map_err(|error| error.error)?;
        index.insert(digest.to_string(), SystemTime::now(), bytes);
        std::fs::write(index_path(parts, key), digest)?;
        READER_CACHE_WARM_ON_WRITE_OBJECTS.fetch_add(1, Ordering::Relaxed);
        Ok(true)
    })
}

/// Called only after GC verified an exact durable absence receipt.
fn evict_key_indexed(parts: &Path, key: &str) -> Result<()> {
    if !root(parts).is_dir() {
        return Ok(());
    }
    with_index(parts, |_, tier| {
        let reference = index_path(parts, key);
        match std::fs::read_to_string(&reference) {
            Ok(digest) => {
                let path = object(parts, &digest)?;
                tier.remove(&digest);
                remove_if_present(&path)?;
                std::fs::remove_file(reference)?;
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        Ok(())
    })
}

/// Flag off (today's path, unchanged): every warm scans the tier under
/// the lock and removes stale references inline.
/// Copy rather than hard-link a mutable writer inode. Hash the copy, then
/// atomically publish it read-only. Capacity eviction never affects an open
/// reader fd; readers copy into their normal leased cache before execution.
fn warm_legacy(
    parts: &Path,
    key: &str,
    source: &Path,
    digest: &str,
    bytes: u64,
    max_bytes: u64,
) -> Result<bool> {
    let target = object(parts, digest)?;
    if bytes > max_bytes {
        return Ok(false);
    }
    locked(parts, || {
        let dir = root(parts);
        // Admission is serialized with GC and other writers; any leftover
        // staging file here belongs to a terminated predecessor.
        for entry in std::fs::read_dir(&dir)? {
            let entry = entry?;
            if entry.file_name().to_string_lossy().starts_with(".warm-") {
                std::fs::remove_file(entry.path())?;
            }
        }
        let mut temp = tempfile::Builder::new()
            .prefix(".warm-")
            .tempfile_in(&dir)?;
        std::io::copy(
            &mut std::io::Read::take(std::fs::File::open(source)?, bytes.saturating_add(1)),
            &mut temp,
        )?;
        ensure!(
            temp.as_file().metadata()?.len() == bytes
                && crate::native::file_sha256(temp.path())? == digest,
            "producer object failed signed length/digest verification"
        );
        let mut objects = Vec::new();
        let mut used = 0_u64;
        for entry in std::fs::read_dir(&dir)? {
            let entry = entry?;
            if entry.path().extension().is_some_and(|ext| ext == "bin") {
                let meta = entry.metadata()?;
                used = used.saturating_add(meta.len());
                objects.push((meta.modified()?, meta.len(), entry.path()));
            }
        }
        objects.sort();
        // Replace an existing digest too: a damaged local copy must not win.
        for (_, size, path) in objects {
            if path == target || used.saturating_add(bytes) > max_bytes {
                std::fs::remove_file(path)?;
                used = used.saturating_sub(size);
            }
        }
        temp.as_file().sync_all()?;
        std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o444))?;
        temp.persist(&target).map_err(|error| error.error)?;
        // Remove stale references as well, so metadata stays bounded.
        for entry in std::fs::read_dir(&dir)? {
            let path = entry?.path();
            if path.extension().is_some_and(|ext| ext == "ref") {
                let sha = std::fs::read_to_string(&path)?;
                if object(parts, &sha).map_or(true, |object| !object.exists()) {
                    std::fs::remove_file(path)?;
                }
            }
        }
        std::fs::write(index_path(parts, key), digest)?;
        READER_CACHE_WARM_ON_WRITE_OBJECTS.fetch_add(1, Ordering::Relaxed);
        Ok(true)
    })
}

/// Called only after GC verified an exact durable absence receipt.
fn evict_key_legacy(parts: &Path, key: &str) -> Result<()> {
    if !root(parts).is_dir() {
        return Ok(());
    }
    locked(parts, || {
        let reference = index_path(parts, key);
        match std::fs::read_to_string(&reference) {
            Ok(digest) => {
                let path = object(parts, &digest)?;
                match std::fs::remove_file(path) {
                    Ok(()) => {}
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                    Err(error) => return Err(error.into()),
                }
                std::fs::remove_file(reference)?;
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        Ok(())
    })
}

/// Env flag for the indexed producer tier (NAN-3610). Off (default):
/// [`warm`] and [`evict_key`] behave exactly as before; the flush warms
/// files one by one and nothing calls [`sweep_stale_refs`].
pub const INDEX_ENV: &str = "NANO_LAKE_PRODUCER_CACHE_INDEX";

/// [`INDEX_ENV`] parsed: `1`, `true` or `on` turn it on.
pub fn index_flag(value: Option<&str>) -> bool {
    matches!(value.map(|v| v.trim().to_ascii_lowercase()).as_deref(), Some("1" | "true" | "on"))
}

/// Whether this process uses the indexed tier (read once).
pub fn index_enabled() -> bool {
    static ENABLED: OnceLock<bool> = OnceLock::new();
    *ENABLED.get_or_init(|| index_flag(std::env::var(INDEX_ENV).ok().as_deref()))
}

/// Publish a verified copy of a signed part file into the producer tier
/// (see [`warm_with`]); the path follows [`INDEX_ENV`].
pub fn warm(parts: &Path, key: &str, source: &Path, digest: &str, bytes: u64, max_bytes: u64) -> Result<bool> {
    warm_with(index_enabled(), parts, key, source, digest, bytes, max_bytes)
}

/// [`warm`] with the path chosen explicitly (tests, benches).
pub fn warm_with(indexed: bool, parts: &Path, key: &str, source: &Path, digest: &str, bytes: u64, max_bytes: u64) -> Result<bool> {
    if indexed {
        warm_indexed(parts, key, source, digest, bytes, max_bytes)
    } else {
        warm_legacy(parts, key, source, digest, bytes, max_bytes)
    }
}

/// Called only after GC verified an exact durable absence receipt.
pub fn evict_key(parts: &Path, key: &str) -> Result<()> {
    evict_key_with(index_enabled(), parts, key)
}

/// [`evict_key`] with the path chosen explicitly (tests).
pub fn evict_key_with(indexed: bool, parts: &Path, key: &str) -> Result<()> {
    if indexed {
        evict_key_indexed(parts, key)
    } else {
        evict_key_legacy(parts, key)
    }
}

/// Remove `.ref` files whose object capacity eviction already removed, so
/// the tier's metadata stays bounded. Off the ingest critical path: the GC
/// pass calls it, at most once per [`REF_SWEEP_INTERVAL`] per tier (or
/// always with `force`). The directory is read without the lock; each stale
/// reference is re-checked under it before removal. Returns refs removed.
pub fn sweep_stale_refs(parts: &Path, force: bool) -> Result<usize> {
    static LAST: OnceLock<Mutex<HashMap<PathBuf, Instant>>> = OnceLock::new();
    let dir = root(parts);
    if !dir.is_dir() {
        return Ok(0);
    }
    {
        let mut last = LAST.get_or_init(|| Mutex::new(HashMap::new())).lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        if !force && last.get(&dir).is_some_and(|at| at.elapsed() < REF_SWEEP_INTERVAL) {
            return Ok(0);
        }
        last.insert(dir.clone(), Instant::now());
    }
    let is_stale = |path: &Path| -> Result<bool> {
        match std::fs::read_to_string(path) {
            Ok(digest) => Ok(object(parts, &digest).map_or(true, |object| !object.exists())),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(error) => Err(error.into()),
        }
    };
    let mut candidates = Vec::new();
    for entry in std::fs::read_dir(&dir)? {
        let path = entry?.path();
        if path.extension().is_some_and(|ext| ext == "ref") && is_stale(&path)? {
            candidates.push(path);
        }
    }
    if candidates.is_empty() {
        return Ok(0);
    }
    with_index(parts, |_, _| {
        let mut removed = 0;
        for path in candidates {
            // A warm may have re-pointed the key since the unlocked read.
            if is_stale(&path)? {
                remove_if_present(&path)?;
                removed += 1;
            }
        }
        Ok(removed)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn signed_copy_capacity_and_gc() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("source");
        std::fs::write(&source, b"first").unwrap();
        std::fs::create_dir_all(root(dir.path())).unwrap();
        let abandoned = root(dir.path()).join(".warm-abandoned");
        std::fs::write(&abandoned, b"abandoned copy").unwrap();
        // Staging runs outside the lock: only an old staging file is abandoned.
        let staging = root(dir.path()).join(STAGING);
        std::fs::create_dir_all(&staging).unwrap();
        let (stale, live) = (staging.join(".warm-stale"), staging.join(".warm-live"));
        std::fs::write(&stale, b"stale").unwrap();
        std::fs::write(&live, b"live").unwrap();
        std::fs::File::options().write(true).open(&stale).unwrap()
            .set_modified(SystemTime::now() - ABANDONED_STAGING_AGE * 2).unwrap();
        let first = crate::parts::sha256_hex(b"first");
        assert!(warm_with(true, dir.path(), "key1", &source, &first, 5, 5).unwrap());
        assert!(!abandoned.exists());
        assert!(!stale.exists());
        assert!(live.exists(), "a staging file a live writer may own is kept");
        let target = object(dir.path(), &first).unwrap();
        assert_eq!(
            std::fs::metadata(&target).unwrap().permissions().mode() & 0o777,
            0o444
        );
        std::fs::write(&source, b"other").unwrap();
        assert_eq!(std::fs::read(&target).unwrap(), b"first");
        assert!(warm_with(true, dir.path(), "bad", &source, &first, 5, 5).is_err());
        assert_eq!(std::fs::read(&target).unwrap(), b"first");
        let other = crate::parts::sha256_hex(b"other");
        // An open reader survives producer capacity eviction.
        let mut opened = std::fs::File::open(&target).unwrap();
        assert!(warm_with(true, dir.path(), "key2", &source, &other, 5, 5).unwrap());
        assert!(!target.exists());
        use std::io::Read;
        let mut bytes = Vec::new();
        opened.read_to_end(&mut bytes).unwrap();
        assert_eq!(bytes, b"first");
        // The evicted object's reference is swept by the GC pass, not the warm.
        assert!(index_path(dir.path(), "key1").exists());
        assert_eq!(sweep_stale_refs(dir.path(), true).unwrap(), 1);
        assert!(!index_path(dir.path(), "key1").exists());
        assert!(index_path(dir.path(), "key2").exists(), "a live reference is kept");
        assert_eq!(sweep_stale_refs(dir.path(), false).unwrap(), 0, "rate-limited");
        evict_key_with(true, dir.path(), "key2").unwrap();
        assert!(!object(dir.path(), &other).unwrap().exists());
        evict_key_with(true, dir.path(), "key2").unwrap();
        assert!(object(dir.path(), "../../escape").is_err());
        assert!(!warm_with(true, dir.path(), "oversize", &source, &other, 5, 4).unwrap());
    }

    /// The in-memory index must notice another process's change to the
    /// tier (its directory mtime), or capacity would be miscounted.
    #[test]
    fn index_rescans_after_an_outside_change() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("source");
        let on_disk = || -> u64 {
            std::fs::read_dir(root(dir.path())).unwrap().flatten()
                .filter(|e| e.path().extension().is_some_and(|ext| ext == "bin"))
                .map(|e| e.metadata().unwrap().len()).sum()
        };
        let put = |key: &str, body: &[u8]| {
            std::fs::write(&source, body).unwrap();
            assert!(warm_with(true, dir.path(), key, &source, &crate::parts::sha256_hex(body), body.len() as u64, 10).unwrap());
        };
        put("a", b"aaaaa");
        // Another writer adds an object without this process's index.
        std::thread::sleep(Duration::from_millis(30));
        let outside = crate::parts::sha256_hex(b"bbbbb");
        std::fs::write(object(dir.path(), &outside).unwrap(), b"bbbbb").unwrap();
        put("c", b"ccccc");
        assert!(on_disk() <= 10, "capacity counts the outside object: {} bytes", on_disk());
        assert!(object(dir.path(), &crate::parts::sha256_hex(b"ccccc")).unwrap().exists());
        // And an outside removal frees its capacity without evicting more.
        std::thread::sleep(Duration::from_millis(30));
        std::fs::remove_file(object(dir.path(), &outside).unwrap()).ok();
        put("d", b"ddddd");
        assert!(object(dir.path(), &crate::parts::sha256_hex(b"ccccc")).unwrap().exists());
        assert_eq!(on_disk(), 10);
    }
    /// NAN-3610 flag off: today's semantics, including the inline stale
    /// reference cleanup and the abandoned-staging removal in the tier.
    #[test]
    fn flag_off_keeps_the_scanning_path() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("source");
        std::fs::write(&source, b"first").unwrap();
        std::fs::create_dir_all(root(dir.path())).unwrap();
        let abandoned = root(dir.path()).join(".warm-abandoned");
        std::fs::write(&abandoned, b"abandoned copy").unwrap();
        let first = crate::parts::sha256_hex(b"first");
        assert!(warm_with(false, dir.path(), "key1", &source, &first, 5, 5).unwrap());
        assert!(!abandoned.exists());
        let target = object(dir.path(), &first).unwrap();
        assert_eq!(
            std::fs::metadata(&target).unwrap().permissions().mode() & 0o777,
            0o444
        );
        std::fs::write(&source, b"other").unwrap();
        assert_eq!(std::fs::read(&target).unwrap(), b"first");
        assert!(warm_with(false, dir.path(), "bad", &source, &first, 5, 5).is_err());
        assert_eq!(std::fs::read(&target).unwrap(), b"first");
        let other = crate::parts::sha256_hex(b"other");
        // An open reader survives producer capacity eviction.
        let mut opened = std::fs::File::open(&target).unwrap();
        assert!(warm_with(false, dir.path(), "key2", &source, &other, 5, 5).unwrap());
        assert!(!target.exists());
        use std::io::Read;
        let mut bytes = Vec::new();
        opened.read_to_end(&mut bytes).unwrap();
        assert_eq!(bytes, b"first");
        assert!(!index_path(dir.path(), "key1").exists());
        evict_key_with(false, dir.path(), "key2").unwrap();
        assert!(!object(dir.path(), &other).unwrap().exists());
        evict_key_with(false, dir.path(), "key2").unwrap();
        assert!(object(dir.path(), "../../escape").is_err());
        assert!(!warm_with(false, dir.path(), "oversize", &source, &other, 5, 4).unwrap());
    }

    #[test]
    fn index_flag_defaults_off() {
        assert!(!index_flag(None));
        assert!(!index_flag(Some("")));
        assert!(!index_flag(Some("0")));
        assert!(!index_flag(Some("yes")));
        assert!(index_flag(Some("1")));
        assert!(index_flag(Some(" TRUE ")));
        assert!(index_flag(Some("on")));
    }
}

#[cfg(test)]
mod scale_tests {
    use super::*;
    use std::time::Instant;

    /// Fill the producer tier with `cached` objects (each with its key
    /// reference, as warm-on-write leaves them), then time `samples` warms.
    fn median_warm_ms(indexed: bool, cached: usize, samples: usize) -> f64 {
        let dir = tempfile::tempdir().unwrap();
        let objects = root(dir.path());
        std::fs::create_dir_all(&objects).unwrap();
        for i in 0..cached {
            let body = format!("cached object {i}");
            let digest = crate::parts::sha256_hex(body.as_bytes());
            std::fs::write(objects.join(format!("{digest}.bin")), &body).unwrap();
            std::fs::write(index_path(dir.path(), &format!("cached/{i}")), &digest).unwrap();
        }
        let source = dir.path().join("source");
        let mut times = Vec::new();
        // The first warm may load the tier's state; time the steady state.
        for i in 0..=samples {
            let body = vec![(i % 251) as u8; 64 * 1024 + i];
            std::fs::write(&source, &body).unwrap();
            let digest = crate::parts::sha256_hex(&body);
            let started = Instant::now();
            assert!(warm_with(indexed, dir.path(), &format!("new/{i}"), &source, &digest, body.len() as u64, u64::MAX / 2).unwrap());
            if i > 0 {
                times.push(started.elapsed().as_secs_f64() * 1000.0);
            }
        }
        times.sort_by(f64::total_cmp);
        times[times.len() / 2]
    }

    /// NAN-3610 (flag on): warm-on-write sits on the ingest flush's critical path (32
    /// warms per 4-part flush). Its cost must not grow with the number of
    /// objects already cached (the load-test tenant: 0.17 s -> 2.7 s per part over 5 h).
    #[test]
    fn warm_cost_stays_flat_as_the_cache_fills() {
        let (legacy_small, legacy_large) = (median_warm_ms(false, 10, 25), median_warm_ms(false, 10_000, 25));
        let small = median_warm_ms(true, 10, 25);
        let large = median_warm_ms(true, 10_000, 25);
        eprintln!("NAN-3610 producer warm median: flag off {legacy_small:.3} ms at 10 cached objects, {legacy_large:.3} ms at 10,000; flag on {small:.3} ms, {large:.3} ms");
        assert!(large <= small * 3.0 + 2.0, "warm cost grew with the cache: {small:.3} ms -> {large:.3} ms");
    }
}

#[cfg(test)]
mod multiprocess_tests {
    use super::*;
    use crate::reader_object_cache::{
        ReaderObjectCache, ReaderObjectCacheSettings, ReaderObjectRef, ReaderObjectSource,
    };
    use std::sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    };
    use std::time::{Duration, Instant};
    const TENANT: &str = "12345678-1234-1234-1234-123456789abc";
    const KEY: &str = "lake/parts/v1/tenant=12345678-1234-1234-1234-123456789abc/parts/l0/object";

    #[test]
    fn producer_child() {
        let Some(dir) = std::env::var_os("NANO_TEST_PRODUCER_DIR") else {
            return;
        };
        let dir = PathBuf::from(dir);
        let source = dir.join("source");
        let digest = crate::native::file_sha256(&source).unwrap();
        warm(
            &dir,
            KEY,
            &source,
            &digest,
            std::fs::metadata(&source).unwrap().len(),
            16 * 1024 * 1024,
        )
        .unwrap();
    }

    struct Network {
        body: Vec<u8>,
        gets: AtomicU64,
    }
    #[async_trait::async_trait]
    impl ReaderObjectSource for Network {
        async fn stream_object(
            &self,
            _: &ReaderObjectRef,
            sink: &mut (dyn for<'b> FnMut(&'b [u8]) -> Result<()> + Send),
        ) -> Result<()> {
            self.gets.fetch_add(1, Ordering::Relaxed);
            tokio::time::sleep(Duration::from_millis(50)).await;
            sink(&self.body)
        }
    }
    fn cache(dir: &Path, source: Arc<Network>) -> ReaderObjectCache {
        ReaderObjectCache::open(
            ReaderObjectCacheSettings {
                root: dir.to_path_buf(),
                max_bytes: 16 * 1024 * 1024,
                query_max_bytes: 8 * 1024 * 1024,
                fetch_concurrency: 2,
                fetch_deadline: Duration::from_secs(10),
            },
            TENANT,
            "parts",
            "lake/parts/v1/tenant=12345678-1234-1234-1234-123456789abc",
            source,
        )
        .unwrap()
    }

    #[tokio::test]
    async fn multiprocess_warm_removes_query_fetches_and_preserves_leases() {
        let dir = tempfile::tempdir().unwrap();
        let body = vec![42_u8; 2 * 1024 * 1024];
        let digest = crate::parts::sha256_hex(&body);
        let reference = ReaderObjectRef {
            range: None,
            source_uri: format!("s3://parts/{KEY}"),
            sha256: digest.clone(),
            size_bytes: body.len() as u64,
        };
        std::fs::write(dir.path().join("source"), &body).unwrap();
        let network = Arc::new(Network {
            body,
            gets: AtomicU64::new(0),
        });
        let before = cache(&dir.path().join("before"), network.clone());
        let started = Instant::now();
        let lease = before.ensure_local(&[reference.clone()]).await.unwrap();
        let before_ms = started.elapsed().as_secs_f64() * 1000.0;
        assert_eq!(lease.misses(), 1);
        assert_eq!(network.gets.load(Ordering::Relaxed), 1);
        assert!(std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "producer_cache::multiprocess_tests::producer_child",
                "--exact"
            ])
            .env("NANO_TEST_PRODUCER_DIR", dir.path())
            .status()
            .unwrap()
            .success());
        let warmed = object(dir.path(), &digest).unwrap();
        let after = cache(&dir.path().join("after"), network.clone());
        let started = Instant::now();
        after.warm_local(&reference, &warmed).await.unwrap();
        let lease = after.ensure_local(&[reference.clone()]).await.unwrap();
        let after_ms = started.elapsed().as_secs_f64() * 1000.0;
        assert_eq!(lease.hits(), 1);
        assert_eq!(lease.misses(), 0);
        assert_eq!(
            network.gets.load(Ordering::Relaxed),
            1,
            "after query made no network GET"
        );
        assert_eq!(after.stats().misses, 0);
        evict_key(dir.path(), KEY).unwrap();
        assert!(!warmed.exists());
        assert_eq!(
            std::fs::read(after.object_path(&digest)).unwrap(),
            network.body
        );
        assert_eq!(
            after
                .ensure_local(&[reference.clone()])
                .await
                .unwrap()
                .hits(),
            1
        );
        let wrong = ReaderObjectRef {
            sha256: crate::parts::sha256_hex(b"wrong"),
            ..reference
        };
        assert!(after
            .warm_local(&wrong, &dir.path().join("source"))
            .await
            .is_err());
        eprintln!("warm-on-write multi-process 2 MiB query: network GETs 1 -> 0; preparation {before_ms:.3} -> {after_ms:.3} ms (simulated network 50 ms); reader misses 1 -> 0");
    }
}
