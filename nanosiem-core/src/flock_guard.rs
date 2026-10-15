// SPDX-License-Identifier: AGPL-3.0-or-later
//! flock(2) guard that releases EXPLICITLY on drop (NAN-2818, NAN-2822).
//!
//! A flock belongs to the open file description, not the descriptor. Every
//! `Command::spawn` duplicates the whole descriptor table into the child, and
//! the child holds those copies until its exec closes the O_CLOEXEC ones. std
//! opens every file O_CLOEXEC, so the leak is bounded to that fork-to-exec
//! window. It matters only when another thread drops the lock during the window:
//! `spawn()` itself returns after the exec, so the spawning thread cannot. If the
//! guard only closes its descriptor, the child's copy keeps the lock alive, and a
//! NON-BLOCKING re-acquisition (in this process or another) reports spurious
//! contention. A blocking acquisition just waits out the window. LOCK_UN on
//! any duplicate releases the lock for all of them, so this guard calls it
//! before the descriptor closes.
use std::{
    fs::File,
    ops::{Deref, DerefMut},
    os::unix::io::AsRawFd,
};

/// A file whose flock (shared or exclusive) the caller has already acquired.
#[derive(Debug)]
pub struct FlockGuard(File);

impl FlockGuard {
    /// Take ownership of `file`, whose flock the caller holds.
    pub fn adopt(file: File) -> Self {
        Self(file)
    }
}

impl Deref for FlockGuard {
    type Target = File;
    fn deref(&self) -> &File {
        &self.0
    }
}

impl DerefMut for FlockGuard {
    fn deref_mut(&mut self) -> &mut File {
        &mut self.0
    }
}

impl Drop for FlockGuard {
    fn drop(&mut self) {
        // SAFETY: the descriptor is owned by self.0 and still open here.
        unsafe { libc::flock(self.0.as_raw_fd(), libc::LOCK_UN) };
    }
}

/// Test support: call `step(i)` repeatedly for `duration` while four other
/// threads fork+exec `/bin/true` continuously, the way parallel tests and
/// production spawners (the query compiler, the job runner's workers) do. The
/// window is microseconds wide, so a fixed iteration count that finishes
/// before the spawners warm up proves nothing: this waits until every spawner
/// has completed a spawn, then runs by wall clock. NAN-2818/NAN-2822 harness.
#[doc(hidden)]
pub fn with_concurrent_spawns(duration: std::time::Duration, mut step: impl FnMut(usize)) {
    use std::sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc,
    };
    const SPAWNERS: usize = 4;
    let stop = Arc::new(AtomicBool::new(false));
    let warm = Arc::new(AtomicUsize::new(0));
    let spawners: Vec<_> = (0..SPAWNERS)
        .map(|_| {
            let (stop, warm) = (stop.clone(), warm.clone());
            std::thread::spawn(move || {
                let mut first = true;
                while !stop.load(Ordering::Relaxed) {
                    let _ = std::process::Command::new("/bin/true").status();
                    if std::mem::take(&mut first) {
                        warm.fetch_add(1, Ordering::Relaxed);
                    }
                }
            })
        })
        .collect();
    while warm.load(Ordering::Relaxed) < SPAWNERS {
        std::thread::yield_now();
    }
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let deadline = std::time::Instant::now() + duration;
        let mut i = 0;
        while std::time::Instant::now() < deadline {
            step(i);
            i += 1;
        }
    }));
    stop.store(true, Ordering::Relaxed);
    for spawner in spawners {
        spawner.join().unwrap();
    }
    if let Err(panic) = outcome {
        std::panic::resume_unwind(panic);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn try_exclusive(file: &File) -> bool {
        unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) == 0 }
    }

    #[test]
    fn dropped_guard_is_not_held_by_concurrently_forked_children() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("lock");
        with_concurrent_spawns(std::time::Duration::from_secs(1), |i| {
            let file = File::create(&path).unwrap();
            assert!(try_exclusive(&file), "iteration {i}: lock still held");
            drop(FlockGuard::adopt(file));
        });
    }
}
