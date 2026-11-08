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
