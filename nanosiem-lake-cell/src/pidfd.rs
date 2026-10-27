// SPDX-License-Identifier: AGPL-3.0-or-later

//! pidfd handles (NAN-2872): every signal the supervisor sends to a tenant
//! process goes through a pidfd, so a recycled pid can never be hit.
//!
//! A pid read from `/proc` can be recycled between the read and
//! `pidfd_open`. [`PidFd::open_verified`] closes that race: it opens the
//! pidfd first and then re-reads `/proc/<pid>/stat` and compares the start
//! time with the one the caller saw. If the pid was recycled in between the
//! start times differ and the handle is dropped. Once open, the pidfd pins
//! the process identity for the handle's whole lifetime.

use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd};

/// A pidfd-backed handle: signals can never hit a recycled pid.
#[derive(Debug)]
pub struct PidFd {
    fd: OwnedFd,
    pid: u32,
}

impl AsFd for PidFd {
    fn as_fd(&self) -> BorrowedFd<'_> { self.fd.as_fd() }
}

impl PidFd {
    /// `pidfd_open(pid)`. Use this only for a pid we are the parent of (a
    /// child we have not reaped cannot be recycled); otherwise use
    /// [`PidFd::open_verified`].
    pub fn open(pid: u32) -> std::io::Result<Self> {
        // SAFETY: raw syscall; returns a new fd or -1.
        let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid as libc::pid_t, 0) };
        if fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        // SAFETY: fresh fd we own.
        Ok(Self { fd: unsafe { OwnedFd::from_raw_fd(fd as i32) }, pid })
    }

    /// Open a pidfd for a pid seen in `/proc` with start time `starttime`
    /// (clock ticks since boot, field 22 of `/proc/<pid>/stat`). Returns
    /// `None` if the process is gone or the pid now names another process.
    pub fn open_verified(pid: u32, starttime: u64) -> Option<Self> {
        let fd = Self::open(pid).ok()?;
        let now = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
        (crate::procfs::parse_stat(&now)?.starttime == starttime).then_some(fd)
    }

    pub fn pid(&self) -> u32 {
        self.pid
    }

    /// Send `sig`. `ESRCH` after the process exited is not an error.
    pub fn signal(&self, sig: i32) -> std::io::Result<()> {
        // SAFETY: raw syscall on our pidfd with a null siginfo.
        let rc = unsafe {
            libc::syscall(libc::SYS_pidfd_send_signal, self.fd.as_raw_fd(), sig, std::ptr::null::<u8>(), 0)
        };
        if rc < 0 {
            let e = std::io::Error::last_os_error();
            if e.raw_os_error() == Some(libc::ESRCH) {
                return Ok(());
            }
            return Err(e);
        }
        Ok(())
    }

    pub fn kill(&self) {
        if let Err(e) = self.signal(libc::SIGKILL) {
            tracing::warn!(pid = self.pid, error = %e, "SIGKILL via pidfd failed (CAP_KILL missing?)");
        }
    }

    /// Has the process exited? (A pidfd polls readable once it has.)
    pub fn exited(&self) -> bool {
        let mut p = libc::pollfd { fd: self.fd.as_raw_fd(), events: libc::POLLIN, revents: 0 };
        // SAFETY: one valid pollfd, zero timeout.
        let rc = unsafe { libc::poll(&mut p, 1, 0) };
        rc > 0 && (p.revents & libc::POLLIN) != 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verified_open_rejects_a_wrong_start_time() {
        let me = std::process::id();
        let st = crate::procfs::parse_stat(&std::fs::read_to_string("/proc/self/stat").unwrap()).unwrap();
        let fd = PidFd::open_verified(me, st.starttime).expect("self");
        assert!(!fd.exited());
        fd.signal(0).unwrap();
        assert!(PidFd::open_verified(me, st.starttime + 1).is_none(), "recycled pid must be refused");
    }

    #[test]
    fn exited_child_is_detected_and_signal_is_harmless() {
        let mut c = std::process::Command::new("true").spawn().unwrap();
        let fd = PidFd::open(c.id()).unwrap();
        c.wait().unwrap();
        assert!(fd.exited());
        fd.signal(libc::SIGKILL).unwrap();
    }
}
