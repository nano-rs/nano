// SPDX-License-Identifier: AGPL-3.0-or-later

use super::*;

/// A deploy waits while another process (the entrypoint) holds the lock and
/// proceeds the moment it is released.
#[tokio::test]
async fn a_deploy_waits_for_the_entrypoint_lock() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join(CONFIG_LOCK_FILE), "").unwrap();
    // `flock -x` from another process, as the entrypoint does.
    let mut holder = std::process::Command::new("flock")
        .arg(dir.path().join(CONFIG_LOCK_FILE))
        .args(["-c", "sleep 1.5"])
        .spawn();
    let Ok(ref mut child) = holder else {
        eprintln!("flock(1) not installed; skipping");
        return;
    };
    tokio::time::sleep(Duration::from_millis(300)).await;
    let started = std::time::Instant::now();
    let _lock = ConfigDirLock::acquire(dir.path()).await;
    let waited = started.elapsed();
    child.wait().unwrap();
    assert!(waited >= Duration::from_millis(800), "took the lock while it was held ({waited:?})");
}

#[tokio::test]
async fn the_guard_serializes_in_process_and_releases_on_drop() {
    let dir = tempfile::tempdir().unwrap();
    let mutex = std::sync::Arc::new(tokio::sync::Mutex::new(()));
    let first = DeployGuard::acquire(mutex.clone(), dir.path()).await;
    assert!(mutex.try_lock().is_err());
    drop(first);
    let _second = DeployGuard::acquire(mutex.clone(), dir.path()).await;
}

#[tokio::test]
async fn an_unwritable_dir_degrades_to_no_file_lock() {
    let lock = ConfigDirLock::acquire(Path::new("/proc/definitely/not/writable")).await;
    assert!(lock._file.is_none());
}

/// NAN-5387: the entrypoint (root) creates the lock file before nano-api (uid
/// 999) starts, so the api cannot open it for writing. A read-only file must
/// still be lockable, and must exclude a second holder.
#[tokio::test]
async fn a_read_only_lock_file_is_still_locked() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join(CONFIG_LOCK_FILE);
    std::fs::write(&path, "").unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o444)).unwrap();
    let lock = ConfigDirLock::acquire(dir.path()).await;
    assert!(lock._file.is_some(), "a read-only lock file must not degrade to no lock");
    let other = open_lock_file(&path).unwrap();
    assert!(matches!(other.try_lock(), Err(std::fs::TryLockError::WouldBlock)));
    drop(lock);
    // A process another test forks in this binary can hold a copy of the
    // descriptor until it execs (CLOEXEC), so allow a moment for the release.
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while other.try_lock().is_err() {
        assert!(std::time::Instant::now() < deadline, "the lock was not released on drop");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

#[test]
fn a_missing_lock_file_is_created() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join(CONFIG_LOCK_FILE);
    open_lock_file(&path).unwrap();
    assert!(path.exists());
}
