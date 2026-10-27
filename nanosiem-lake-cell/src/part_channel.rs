// SPDX-License-Identifier: AGPL-3.0-or-later
//! H02 B2 (C14 Option A) part channel transport: the one fd a socketless
//! native Ingest/Query child holds to reach storage through its supervisor.
//!
//! One connected AF_UNIX SOCK_STREAM pair per process, created by the
//! supervisor; frames are a u32 little-endian length plus that many bytes,
//! at most [`PartChannelLimits::max_frame_bytes`] in either direction. The
//! frame schema (requests, receipts, tenant/scope checks, timeouts) belongs
//! to the cell composition; this layer only bounds and moves bytes, and
//! never interprets them. The child accepts the fd only after checking it is
//! a connected AF_UNIX stream whose peer is its own parent.
//!
//! Not cancel-safe: a timeout or error mid-frame leaves the stream out of
//! sync. Callers must treat any timeout or I/O error as fatal and drop the
//! channel (the worker exits and the supervisor restarts it); never retry
//! on the same channel.
use crate::contract::PartChannelLimits;
use std::io;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::unix::{OwnedReadHalf, OwnedWriteHalf};
use tokio::sync::Mutex;

fn refused(what: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, what)
}

fn sockopt(fd: BorrowedFd<'_>, name: libc::c_int) -> io::Result<libc::c_int> {
    let mut value: libc::c_int = 0;
    let mut size = std::mem::size_of_val(&value) as libc::socklen_t;
    // SAFETY: a live borrowed fd and a correctly sized writable output.
    let rc = unsafe {
        libc::getsockopt(fd.as_raw_fd(), libc::SOL_SOCKET, name, (&mut value as *mut libc::c_int).cast(), &mut size)
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(value)
}

/// Child-side check of a received part-channel fd: a connected AF_UNIX
/// SOCK_STREAM whose peer process is `expected_peer` (the supervisor, i.e.
/// the child's parent).
pub fn verify_received(fd: &OwnedFd, expected_peer: i32) -> io::Result<()> {
    if sockopt(fd.as_fd(), libc::SO_TYPE)? != libc::SOCK_STREAM
        || sockopt(fd.as_fd(), libc::SO_DOMAIN)? != libc::AF_UNIX
    {
        return Err(refused("part channel is not a unix stream"));
    }
    let (pid, _, _) = crate::fdpass::peer_cred(fd.as_fd())?;
    if pid != expected_peer || pid <= 0 {
        return Err(refused("part channel peer is not the supervisor"));
    }
    Ok(())
}

/// One end of a part channel. Sends and receives may run concurrently;
/// each direction is serialized so frames never interleave.
pub struct PartChannel {
    read: Mutex<OwnedReadHalf>,
    write: Mutex<OwnedWriteHalf>,
    limits: PartChannelLimits,
}

impl std::fmt::Debug for PartChannel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PartChannel").field("limits", &self.limits).finish_non_exhaustive()
    }
}

impl PartChannel {
    /// Wrap a connected stream end (requires a Tokio runtime).
    pub fn new(fd: OwnedFd, limits: PartChannelLimits) -> io::Result<Self> {
        if !limits.valid() {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "part channel limits"));
        }
        let stream = std::os::unix::net::UnixStream::from(fd);
        stream.set_nonblocking(true)?;
        let (read, write) = tokio::net::UnixStream::from_std(stream)?.into_split();
        Ok(Self { read: Mutex::new(read), write: Mutex::new(write), limits })
    }

    pub fn limits(&self) -> PartChannelLimits {
        self.limits
    }

    /// Send one frame. Refuses (without writing) a frame above the limit.
    pub async fn send_frame(&self, frame: &[u8]) -> io::Result<()> {
        let len = u32::try_from(frame.len())
            .ok()
            .filter(|len| *len <= self.limits.max_frame_bytes)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "part channel frame too large"))?;
        let mut write = self.write.lock().await;
        write.write_all(&len.to_le_bytes()).await?;
        write.write_all(frame).await?;
        write.flush().await
    }

    /// Receive one frame. `Ok(None)` is an orderly close at a frame boundary.
    /// A declared length above the limit is refused before any allocation;
    /// a close inside a frame is an error.
    ///
    /// NOT cancel-safe: a partial header or body lives in this future, so a
    /// dropped call desyncs the stream. Never race it in `select!`; keep one
    /// reader task that forwards whole frames (e.g. over an mpsc channel).
    pub async fn recv_frame(&self) -> io::Result<Option<Vec<u8>>> {
        let mut read = self.read.lock().await;
        let mut header = [0u8; 4];
        let mut got = 0;
        while got < header.len() {
            let n = read.read(&mut header[got..]).await?;
            if n == 0 {
                return if got == 0 {
                    Ok(None)
                } else {
                    Err(io::Error::new(io::ErrorKind::UnexpectedEof, "part channel closed inside a frame"))
                };
            }
            got += n;
        }
        let len = u32::from_le_bytes(header);
        if len > self.limits.max_frame_bytes {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "part channel frame too large"));
        }
        let mut frame = vec![0u8; len as usize];
        read.read_exact(&mut frame).await?;
        Ok(Some(frame))
    }

    /// Close our sending direction: the peer reads an orderly end of stream.
    pub async fn shutdown(&self) {
        let _ = self.write.lock().await.shutdown().await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pair(limit: u32) -> (PartChannel, PartChannel) {
        let (a, b) = crate::fdpass::stream_pair().unwrap();
        let limits = PartChannelLimits { max_frame_bytes: limit };
        (PartChannel::new(a, limits).unwrap(), PartChannel::new(b, limits).unwrap())
    }

    #[tokio::test]
    async fn frames_round_trip_in_order_and_close_cleanly() {
        let (a, b) = pair(4096);
        for frame in [&b""[..], b"one", &[7u8; 4096][..]] {
            a.send_frame(frame).await.unwrap();
            assert_eq!(b.recv_frame().await.unwrap().unwrap(), frame);
        }
        b.send_frame(b"back").await.unwrap();
        assert_eq!(a.recv_frame().await.unwrap().unwrap(), b"back");
        drop(a);
        assert!(b.recv_frame().await.unwrap().is_none());
    }

    #[tokio::test]
    async fn oversize_frames_are_refused_on_both_ends() {
        let (a, b) = pair(1024);
        assert!(a.send_frame(&[0u8; 1025]).await.is_err(), "sender refuses before writing");
        // A hostile peer declaring more than the limit: refused before allocation.
        let (raw, theirs) = crate::fdpass::stream_pair().unwrap();
        let victim = PartChannel::new(theirs, PartChannelLimits { max_frame_bytes: 1024 }).unwrap();
        let mut raw = std::os::unix::net::UnixStream::from(raw);
        use std::io::Write;
        raw.write_all(&u32::MAX.to_le_bytes()).unwrap();
        assert_eq!(victim.recv_frame().await.unwrap_err().kind(), io::ErrorKind::InvalidData);
        // Truncated frame then close.
        let (raw, theirs) = crate::fdpass::stream_pair().unwrap();
        let victim = PartChannel::new(theirs, PartChannelLimits { max_frame_bytes: 1024 }).unwrap();
        let mut raw = std::os::unix::net::UnixStream::from(raw);
        raw.write_all(&10u32.to_le_bytes()).unwrap();
        raw.write_all(b"abc").unwrap();
        drop(raw);
        assert_eq!(victim.recv_frame().await.unwrap_err().kind(), io::ErrorKind::UnexpectedEof);
        drop((a, b));
    }

    #[test]
    fn limits_are_bounded() {
        assert!(PartChannelLimits::DEFAULT.valid());
        assert!(!PartChannelLimits { max_frame_bytes: 0 }.valid());
        assert!(!PartChannelLimits { max_frame_bytes: PartChannelLimits::MAX_FRAME_BYTES + 1 }.valid());
    }

    #[test]
    fn receiver_accepts_only_a_unix_stream_from_the_expected_peer() {
        let me = std::process::id() as i32;
        let (_ours, theirs) = crate::fdpass::stream_pair().unwrap();
        // socketpair: the peer credential is the creating process (here, us).
        verify_received(&theirs, me).unwrap();
        assert!(verify_received(&theirs, me + 1).is_err(), "foreign peer");
        let (_a, packet) = crate::fdpass::seqpacket_pair().unwrap();
        assert!(verify_received(&packet, me).is_err(), "seqpacket is not the part channel");
        let file: OwnedFd = std::fs::File::open("/dev/null").unwrap().into();
        assert!(verify_received(&file, me).is_err(), "not a socket");
    }
}
