// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-4953 (codex P2): one lock between nano-api's config writers and the
//! Vector container's entrypoint.
//!
//! The entrypoint migrates pre-upgrade files in the shared dynamic volume
//! (escape them against env interpolation, quarantine pull sources that cannot
//! build) with a read-check-rename sequence. nano-api rewrites the same files on
//! every deploy, including at its own startup. Without a shared lock the two
//! interleave: the entrypoint reads an old file, the api writes the escaped
//! current one, and the entrypoint's rename puts the stale bytes back (or it
//! reads the api's half-written file, or escapes an already escaped one).
//!
//! The in-process deploy mutex cannot see a shell in another container, so
//! every deploy section also takes an exclusive `flock` on
//! `<config dir>/.nano-config.lock`. The entrypoint takes the same lock
//! (`flock`, util-linux) for its migration and cold-start guard; both sides use
//! `flock(2)` on the same file in the shared volume, which works across
//! containers on one kernel. Keep the file name in sync with
//! `config/vector/.nano/vector-entrypoint.sh`.
//!
//! Best effort by design: if the lock file cannot be opened (read-only or
//! missing dir) or the entrypoint holds it longer than [`MAX_WAIT`], the deploy
//! proceeds with a warning rather than stalling every deploy behind a wedged
//! container. Where nano-api and Vector do not share a kernel (the native
//! macOS e2e harness) the lock is advisory only.

use std::path::{Path, PathBuf};
use std::time::Duration;

/// Lock file name in the config dir (the Vector container's /etc/vector/dynamic).
pub const CONFIG_LOCK_FILE: &str = ".nano-config.lock";

/// Longest a deploy waits for the entrypoint (its cold-start guard validates
/// each pull source with a 90s bound).
///
/// NAN-5298: a deploy holds the lock through its reload wait, at most
/// `DEFAULT_RELOAD_ACK_MAX_SECS` (180) for the forward reload plus the base
/// window (45) for a rollback's, inside this bound (`reload_compile_budget_tests`).
pub(super) const MAX_WAIT: Duration = Duration::from_secs(300);

/// Held while a deploy writes the shared config; released on drop.
pub struct ConfigDirLock {
    _file: Option<std::fs::File>,
}

impl ConfigDirLock {
    pub async fn acquire(config_dir: &Path) -> Self {
        let path = config_dir.join(CONFIG_LOCK_FILE);
        let result = tokio::task::spawn_blocking(move || lock_blocking(&path)).await;
        match result {
            Ok(Ok(file)) => Self { _file: Some(file) },
            Ok(Err(error)) => {
                tracing::warn!(%error, "could not take the Vector config-dir lock; deploying without it");
                Self { _file: None }
            }
            Err(error) => {
                tracing::warn!(%error, "config-dir lock task failed; deploying without it");
                Self { _file: None }
            }
        }
    }
}

fn lock_blocking(path: &PathBuf) -> std::io::Result<std::fs::File> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let file = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(path)?;
    let deadline = std::time::Instant::now() + MAX_WAIT;
    loop {
        match file.try_lock() {
            Ok(()) => return Ok(file),
            Err(std::fs::TryLockError::WouldBlock) if std::time::Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(200));
            }
            Err(std::fs::TryLockError::WouldBlock) => {
                return Err(std::io::Error::other(format!(
                    "{} still held after {}s (the Vector entrypoint's migration?)",
                    path.display(),
                    MAX_WAIT.as_secs()
                )));
            }
            Err(std::fs::TryLockError::Error(error)) => return Err(error),
        }
    }
}

/// The deploy mutex plus the cross-process config-dir lock, held together.
/// Fields drop in order: the file lock is released before the mutex.
pub struct DeployGuard {
    _file: ConfigDirLock,
    _mutex: tokio::sync::OwnedMutexGuard<()>,
}

impl DeployGuard {
    pub async fn acquire(
        mutex: std::sync::Arc<tokio::sync::Mutex<()>>,
        config_dir: &Path,
    ) -> Self {
        // In-process first, so two api tasks never contend on the flock.
        let mutex = mutex.lock_owned().await;
        let file = ConfigDirLock::acquire(config_dir).await;
        Self { _file: file, _mutex: mutex }
    }
}

#[cfg(test)]
#[path = "config_lock_tests.rs"]
mod tests;
