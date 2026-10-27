// SPDX-License-Identifier: AGPL-3.0-or-later

//! Control-socket framing and fd passing (NAN-2871).
//!
//! The supervisor and each tenant process talk over one connected
//! `AF_UNIX`/`SOCK_SEQPACKET` socketpair: one JSON message per packet, with
//! at most [`MAX_FDS`] file descriptors attached via `SCM_RIGHTS`. Received
//! fds are always `O_CLOEXEC` (`MSG_CMSG_CLOEXEC`).
//!
//! Secrets travel in a sealed memfd ([`secret_memfd`]): anonymous, never on a
//! filesystem, write-sealed before it is sent, and readable only by a process
//! holding the fd (or one allowed to ptrace a holder, which the jail denies).

use crate::contract::{MAX_CONTROL_MESSAGE, MAX_SECRET_BYTES};
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::io;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};
use tokio::io::unix::AsyncFd;
use tokio::io::Interest;
use zeroize::Zeroizing;

pub const MAX_FDS: usize = 4;

/// A connected SEQPACKET pair, both ends `O_CLOEXEC`.
pub fn seqpacket_pair() -> io::Result<(OwnedFd, OwnedFd)> {
    socketpair(libc::SOCK_SEQPACKET)
}

/// A connected STREAM pair, both ends `O_CLOEXEC` (one routed RPC).
pub fn stream_pair() -> io::Result<(OwnedFd, OwnedFd)> {
    socketpair(libc::SOCK_STREAM)
}

fn socketpair(ty: libc::c_int) -> io::Result<(OwnedFd, OwnedFd)> {
    let mut fds = [0 as RawFd; 2];
    // SAFETY: fds is a valid 2-element array.
    let rc = unsafe { libc::socketpair(libc::AF_UNIX, ty | libc::SOCK_CLOEXEC, 0, fds.as_mut_ptr()) };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: the kernel just returned two fresh fds we own.
    Ok(unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) })
}

/// Send one packet with optional fds. Blocking or non-blocking depending on
/// the socket (non-blocking returns `WouldBlock`).
pub fn send_packet(sock: BorrowedFd<'_>, data: &[u8], fds: &[BorrowedFd<'_>]) -> io::Result<()> {
    if data.len() > MAX_CONTROL_MESSAGE {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "control message too large"));
    }
    if fds.len() > MAX_FDS {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "too many fds"));
    }
    let raw: Vec<RawFd> = fds.iter().map(|f| f.as_raw_fd()).collect();
    let mut iov = libc::iovec { iov_base: data.as_ptr() as *mut _, iov_len: data.len() };
    // SAFETY: CMSG_SPACE is a pure size computation.
    let space = unsafe { libc::CMSG_SPACE((MAX_FDS * std::mem::size_of::<RawFd>()) as u32) } as usize;
    let mut cbuf = vec![0u8; space];
    // SAFETY: zeroed msghdr is a valid initial state.
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    if !raw.is_empty() {
        let len = raw.len() * std::mem::size_of::<RawFd>();
        msg.msg_control = cbuf.as_mut_ptr() as *mut _;
        // SAFETY: size computation only.
        msg.msg_controllen = unsafe { libc::CMSG_SPACE(len as u32) } as _;
        // SAFETY: msg_control points at a buffer of at least CMSG_SPACE(len).
        unsafe {
            let c = libc::CMSG_FIRSTHDR(&msg);
            (*c).cmsg_level = libc::SOL_SOCKET;
            (*c).cmsg_type = libc::SCM_RIGHTS;
            (*c).cmsg_len = libc::CMSG_LEN(len as u32) as _;
            std::ptr::copy_nonoverlapping(raw.as_ptr() as *const u8, libc::CMSG_DATA(c), len);
        }
    }
    loop {
        // SAFETY: msg is fully initialised above; MSG_NOSIGNAL avoids SIGPIPE.
        let n = unsafe { libc::sendmsg(sock.as_raw_fd(), &msg, libc::MSG_NOSIGNAL) };
        if n >= 0 {
            return Ok(());
        }
        let e = io::Error::last_os_error();
        if e.kind() != io::ErrorKind::Interrupted {
            return Err(e);
        }
    }
}

/// Receive one packet. `Ok(None)` is an orderly EOF (peer closed).
pub fn recv_packet(sock: BorrowedFd<'_>) -> io::Result<Option<(Vec<u8>, Vec<OwnedFd>)>> {
    let mut buf = vec![0u8; MAX_CONTROL_MESSAGE];
    let mut iov = libc::iovec { iov_base: buf.as_mut_ptr() as *mut _, iov_len: buf.len() };
    // SAFETY: size computation only.
    let space = unsafe { libc::CMSG_SPACE((MAX_FDS * std::mem::size_of::<RawFd>()) as u32) } as usize;
    let mut cbuf = vec![0u8; space];
    // SAFETY: zeroed msghdr is valid.
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cbuf.as_mut_ptr() as *mut _;
    msg.msg_controllen = space as _;
    let n = loop {
        // SAFETY: msg points at live buffers.
        let n = unsafe { libc::recvmsg(sock.as_raw_fd(), &mut msg, libc::MSG_CMSG_CLOEXEC) };
        if n >= 0 {
            break n as usize;
        }
        let e = io::Error::last_os_error();
        if e.kind() != io::ErrorKind::Interrupted {
            return Err(e);
        }
    };
    let mut fds = Vec::new();
    // SAFETY: iterate the control buffer the kernel filled in.
    unsafe {
        let mut c = libc::CMSG_FIRSTHDR(&msg);
        while !c.is_null() {
            if (*c).cmsg_level == libc::SOL_SOCKET && (*c).cmsg_type == libc::SCM_RIGHTS {
                let data = libc::CMSG_DATA(c);
                let len = (*c).cmsg_len as usize - libc::CMSG_LEN(0) as usize;
                let count = len / std::mem::size_of::<RawFd>();
                for i in 0..count {
                    let fd = std::ptr::read_unaligned((data as *const RawFd).add(i));
                    fds.push(OwnedFd::from_raw_fd(fd));
                }
            }
            c = libc::CMSG_NXTHDR(&msg, c);
        }
    }
    if msg.msg_flags & (libc::MSG_TRUNC | libc::MSG_CTRUNC) != 0 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "truncated control message"));
    }
    if n == 0 && fds.is_empty() {
        return Ok(None);
    }
    buf.truncate(n);
    Ok(Some((buf, fds)))
}

/// Blocking typed send.
pub fn send_json<T: Serialize>(sock: BorrowedFd<'_>, msg: &T, fds: &[BorrowedFd<'_>]) -> io::Result<()> {
    let data = serde_json::to_vec(msg).map_err(io::Error::other)?;
    send_packet(sock, &data, fds)
}

/// Blocking typed receive.
pub fn recv_json<T: DeserializeOwned>(sock: BorrowedFd<'_>) -> io::Result<Option<(T, Vec<OwnedFd>)>> {
    match recv_packet(sock)? {
        None => Ok(None),
        Some((data, fds)) => {
            let v = serde_json::from_slice(&data).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
            Ok(Some((v, fds)))
        }
    }
}

fn set_nonblocking(fd: &OwnedFd) -> io::Result<()> {
    // SAFETY: fcntl on a valid fd.
    unsafe {
        let flags = libc::fcntl(fd.as_raw_fd(), libc::F_GETFL);
        if flags < 0 || libc::fcntl(fd.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) < 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

/// The async (tokio) end of a control socket.
pub struct AsyncSeqpacket {
    inner: AsyncFd<OwnedFd>,
}

impl AsyncSeqpacket {
    pub fn new(fd: OwnedFd) -> io::Result<Self> {
        set_nonblocking(&fd)?;
        Ok(Self { inner: AsyncFd::with_interest(fd, Interest::READABLE | Interest::WRITABLE)? })
    }

    pub async fn send_json<T: Serialize>(&self, msg: &T, fds: &[BorrowedFd<'_>]) -> io::Result<()> {
        let data = serde_json::to_vec(msg).map_err(io::Error::other)?;
        loop {
            let mut guard = self.inner.writable().await?;
            match guard.try_io(|fd| send_packet(fd.get_ref().as_fd(), &data, fds)) {
                Ok(r) => return r,
                Err(_would_block) => continue,
            }
        }
    }

    /// Recheck lifecycle under the same gate as stop/drain, at the actual
    /// nonblocking sendmsg. No lock is retained while waiting for writability.
    pub async fn send_json_guarded<T: Serialize>(
        &self, msg: &T, fds: &[BorrowedFd<'_>], gate: &std::sync::Mutex<()>,
        current: impl Fn() -> io::Result<()>,
    ) -> io::Result<()> {
        let data = serde_json::to_vec(msg).map_err(io::Error::other)?;
        loop {
            let mut ready = self.inner.writable().await?;
            match ready.try_io(|fd| {
                let _permit = gate.lock().map_err(|_| io::Error::other("secret delivery gate poisoned"))?;
                current()?;
                send_packet(fd.get_ref().as_fd(), &data, fds)
            }) {
                Ok(result) => return result,
                Err(_would_block) => continue,
            }
        }
    }

    pub async fn recv_json<T: DeserializeOwned>(&self) -> io::Result<Option<(T, Vec<OwnedFd>)>> {
        loop {
            let mut guard = self.inner.readable().await?;
            match guard.try_io(|fd| recv_packet(fd.get_ref().as_fd())) {
                Ok(Ok(None)) => return Ok(None),
                Ok(Ok(Some((data, fds)))) => {
                    let v =
                        serde_json::from_slice(&data).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
                    return Ok(Some((v, fds)));
                }
                Ok(Err(e)) => return Err(e),
                Err(_would_block) => continue,
            }
        }
    }
}

/// Create a sealed, anonymous memfd holding `secret`. The fd is `O_CLOEXEC`
/// (it is passed with `SCM_RIGHTS`, never inherited) and sealed against
/// writes, growth, shrinking and further sealing.
pub fn secret_memfd(secret: &[u8]) -> io::Result<OwnedFd> {
    if secret.len() > MAX_SECRET_BYTES {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "secret too large"));
    }
    let name = c"nano-cell-secret";
    // SAFETY: valid C string; flags are constants.
    let fd = unsafe { libc::memfd_create(name.as_ptr(), libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: fresh fd we own.
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };
    let mut off = 0;
    while off < secret.len() {
        // SAFETY: writing from a live slice.
        let n = unsafe {
            libc::write(fd.as_raw_fd(), secret[off..].as_ptr() as *const _, secret.len() - off)
        };
        if n < 0 {
            let e = io::Error::last_os_error();
            if e.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(e);
        }
        off += n as usize;
    }
    let seals = libc::F_SEAL_WRITE | libc::F_SEAL_GROW | libc::F_SEAL_SHRINK | libc::F_SEAL_SEAL;
    // SAFETY: fcntl on our fd.
    if unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_ADD_SEALS, seals) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(fd)
}

/// Read a secret memfd from offset 0 into zeroizing memory, then drop it.
pub fn read_secret_memfd(fd: OwnedFd) -> io::Result<Zeroizing<Vec<u8>>> {
    let mut out = Zeroizing::new(vec![0u8; MAX_SECRET_BYTES]);
    let mut off = 0usize;
    loop {
        // SAFETY: pread into the live buffer tail.
        let n = unsafe {
            libc::pread(
                fd.as_raw_fd(),
                out[off..].as_mut_ptr() as *mut _,
                MAX_SECRET_BYTES - off,
                off as libc::off_t,
            )
        };
        if n < 0 {
            let e = io::Error::last_os_error();
            if e.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(e);
        }
        if n == 0 {
            break;
        }
        off += n as usize;
        if off == MAX_SECRET_BYTES {
            break;
        }
    }
    out.truncate(off);
    drop(fd);
    Ok(out)
}

/// `SO_PEERCRED` of a connected unix socket: (pid, uid, gid).
pub fn peer_cred(sock: BorrowedFd<'_>) -> io::Result<(i32, u32, u32)> {
    // SAFETY: zeroed ucred is valid; len matches.
    let mut cred: libc::ucred = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    let rc = unsafe {
        libc::getsockopt(
            sock.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            &mut cred as *mut _ as *mut _,
            &mut len,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok((cred.pid, cred.uid, cred.gid))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};

    #[test]
    fn packets_carry_fds() {
        let (a, b) = seqpacket_pair().unwrap();
        let (s1, s2) = stream_pair().unwrap();
        send_json(a.as_fd(), &serde_json::json!({"hi": 1}), &[s2.as_fd()]).unwrap();
        drop(s2);
        let (v, mut fds): (serde_json::Value, _) = recv_json(b.as_fd()).unwrap().unwrap();
        assert_eq!(v["hi"], 1);
        assert_eq!(fds.len(), 1);
        let mut got = std::os::unix::net::UnixStream::from(fds.pop().unwrap());
        let mut s1 = std::os::unix::net::UnixStream::from(s1);
        s1.write_all(b"ping").unwrap();
        let mut buf = [0u8; 4];
        got.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, b"ping");
        drop(a);
        assert!(recv_packet(b.as_fd()).unwrap().is_none());
    }

    #[test]
    fn memfd_is_sealed_and_readable() {
        let fd = secret_memfd(b"s3cret").unwrap();
        // Writes are sealed.
        let n = unsafe { libc::pwrite(fd.as_raw_fd(), b"x".as_ptr() as *const _, 1, 0) };
        assert_eq!(n, -1);
        let got = read_secret_memfd(fd).unwrap();
        assert_eq!(&got[..], b"s3cret");
    }

    #[test]
    fn peercred_reports_self() {
        let (a, _b) = stream_pair().unwrap();
        let (pid, uid, _) = peer_cred(a.as_fd()).unwrap();
        assert_eq!(pid as u32, std::process::id());
        assert_eq!(uid, unsafe { libc::geteuid() });
    }

    #[tokio::test]
    async fn guarded_secret_send_rechecks_after_backpressure_without_delivering_fds() {
        use std::sync::{Arc, Mutex, atomic::{AtomicBool, Ordering}};
        let (sender, receiver) = seqpacket_pair().unwrap();
        set_nonblocking(&sender).unwrap();
        set_nonblocking(&receiver).unwrap();
        let filler = vec![0_u8; 4096];
        let mut queued = 0;
        loop {
            match send_packet(sender.as_fd(), &filler, &[]) {
                Ok(()) => queued += 1,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                Err(error) => panic!("prepare real socket backpressure: {error}"),
            }
        }
        let gate = Arc::new(Mutex::new(()));
        let stopped = Arc::new(AtomicBool::new(false));
        let socket = Arc::new(AsyncSeqpacket::new(sender).unwrap());
        let (g, s, a) = (gate.clone(), stopped.clone(), socket.clone());
        let task = tokio::spawn(async move {
            let secret = secret_memfd(b"synthetic-bootstrap-token").unwrap();
            a.send_json_guarded(&serde_json::json!({"type":"secrets"}), &[secret.as_fd()], &g, || {
                if s.load(Ordering::SeqCst) { Err(io::Error::from(io::ErrorKind::PermissionDenied)) } else { Ok(()) }
            }).await
        });
        tokio::task::yield_now().await;
        assert!(!task.is_finished(), "send is actually waiting for the full socket");
        { let _permit = gate.lock().unwrap(); stopped.store(true, Ordering::SeqCst); }
        for _ in 0..queued {
            let (_, fds) = recv_packet(receiver.as_fd()).unwrap().unwrap();
            assert!(fds.is_empty(), "fillers never carried a secret");
        }
        let error = tokio::time::timeout(std::time::Duration::from_secs(2), task).await.unwrap().unwrap().unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        assert_eq!(recv_packet(receiver.as_fd()).unwrap_err().kind(), io::ErrorKind::WouldBlock,
            "no packet or ancillary fd was exposed after stop");
    }

    #[tokio::test]
    async fn guarded_secret_send_preserves_real_memfd_delivery_when_current() {
        let (sender, receiver) = seqpacket_pair().unwrap();
        let sender = AsyncSeqpacket::new(sender).unwrap();
        let secret = secret_memfd(b"synthetic-bootstrap-token").unwrap();
        sender.send_json_guarded(&serde_json::json!({"type":"secrets"}), &[secret.as_fd()], &std::sync::Mutex::new(()), || Ok(())).await.unwrap();
        let (_, mut fds) = recv_packet(receiver.as_fd()).unwrap().unwrap();
        assert_eq!(fds.len(), 1);
        assert_eq!(read_secret_memfd(fds.remove(0)).unwrap().as_slice(), b"synthetic-bootstrap-token");
    }
}
