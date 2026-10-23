// SPDX-License-Identifier: AGPL-3.0-or-later

//! The tenant-process side of the cell contract (NAN-2871).
//!
//! Phase 2 (`ingest[T]`) and phase 3 (`query[T]`) binaries use this module:
//!
//! ```ignore
//! fn main() -> anyhow::Result<()> {
//!     // FIRST, before any runtime, thread or tenant I/O. Blocks while warm.
//!     let boot = nanosiem_lake_cell::child::bootstrap()?;
//!     tokio::runtime::Builder::new_multi_thread().enable_all().build()?.block_on(async move {
//!         let (assignment, secret, control) = boot.into_async()?;
//!         let svc = std::sync::Arc::new(MyService::new(assignment, secret).await?);
//!         nanosiem_lake_cell::child::run_service(svc, control).await
//!     })
//! }
//! ```
//!
//! [`bootstrap`] speaks the handshake of [`crate::contract`]: `Hello`, wait
//! for `Assign`, apply the jail in-process, `Jailed`, receive the secret
//! memfd, `Ready`. When it returns, the process is already confined and runs
//! as the tenant's uid.

use crate::contract::{
    Assignment, Heartbeat, ToChild, ToSupervisor, WakeReason, CONTROL_FD, CONTROL_FD_FLAG, HEARTBEAT_INTERVAL_MAX,
    PROTOCOL_VERSION,
};
use crate::fdpass::{self, AsyncSeqpacket};
use crate::jail::{self, JailReport};
use anyhow::{bail, Context};
use async_trait::async_trait;
use std::os::fd::{AsFd, AsRawFd, FromRawFd, OwnedFd};
use std::sync::Arc;
use std::time::Duration;
use zeroize::Zeroizing;

/// A confined, assigned tenant process, before its async runtime starts.
pub struct Bootstrapped {
    pub assignment: Assignment,
    pub jail: JailReport,
    secret: Zeroizing<Vec<u8>>,
    control: OwnedFd,
}

fn control_fd_from_args() -> anyhow::Result<OwnedFd> {
    let args: Vec<String> = std::env::args().collect();
    let fd = args
        .windows(2)
        .find(|w| w[0] == CONTROL_FD_FLAG)
        .map(|w| w[1].parse::<i32>())
        .transpose()
        .context("bad control fd")?
        .with_context(|| format!("missing {CONTROL_FD_FLAG}; this binary must be started by the cell supervisor"))?;
    if fd != CONTROL_FD {
        bail!("control fd must be {CONTROL_FD}, got {fd}");
    }
    // SAFETY: the supervisor installed a socket at fd 3 for us; we take
    // ownership exactly once. Mark it close-on-exec so helpers never inherit.
    unsafe {
        let flags = libc::fcntl(fd, libc::F_GETFD);
        if flags < 0 {
            bail!("control fd {fd} is not open");
        }
        libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC);
        Ok(OwnedFd::from_raw_fd(fd))
    }
}

fn send(fd: &OwnedFd, msg: &ToSupervisor) -> anyhow::Result<()> {
    fdpass::send_json(fd.as_fd(), msg, &[]).context("control send")
}

/// Run the handshake. Must be called while the process is single-threaded.
pub fn bootstrap() -> anyhow::Result<Bootstrapped> {
    bootstrap_with_native_init(|_| Ok(()))
}

/// Initialize trusted, image-owned native libraries after assignment, while
/// still single-threaded and before the jail makes `/proc/self/auxv` unreadable.
/// The callback must not open tenant data, receive secrets, or start threads.
pub fn bootstrap_with_native_init(init: impl FnOnce(&Assignment) -> anyhow::Result<()>) -> anyhow::Result<Bootstrapped> {
    crate::crash_capture::install().context("install native crash capture")?;
    let control = control_fd_from_args()?;
    send(&control, &ToSupervisor::Hello { pid: std::process::id(), protocol_version: PROTOCOL_VERSION })?;

    // Warm: wait (possibly minutes) for an assignment.
    let assignment = match fdpass::recv_json::<ToChild>(control.as_fd())? {
        None => std::process::exit(0), // supervisor gone or pool shrunk
        Some((ToChild::Assign { protocol_version, assignment }, mut fds)) => {
            if protocol_version != PROTOCOL_VERSION {
                let _ = send(&control, &ToSupervisor::Fatal { error: format!("protocol {protocol_version}") });
                bail!("supervisor protocol {protocol_version}, child {PROTOCOL_VERSION}");
            }
            // NAN-3139: a preconnected volume accountant (query role with
            // the local hot window). The jail forbids creating our own.
            if let Some(fd) = fds.pop() {
                crate::volume_usage::install_accountant(fd).context("install volume accountant")?;
            }
            *assignment
        }
        Some((ToChild::Shutdown { .. }, _)) => std::process::exit(0),
        Some((other, _)) => bail!("unexpected message before assignment: {other:?}"),
    };

    if let Err(error) = init(&assignment) {
        let _ = send(&control, &ToSupervisor::Fatal { error: format!("native initialization: {error:#}") });
        return Err(error.context("native initialization before jail"));
    }
    let report = match jail::apply(&assignment.jail) {
        Ok(r) => r,
        Err(e) => {
            let _ = send(&control, &ToSupervisor::Fatal { error: format!("jail: {e}") });
            bail!("jail: {e}");
        }
    };
    // No shared tmp: the role's private dirs only.
    std::env::set_var("TMPDIR", &assignment.tmp_dir);
    std::env::set_var("HOME", &assignment.state_dir);
    std::env::set_current_dir(&assignment.state_dir).context("chdir state dir")?;
    send(
        &control,
        &ToSupervisor::Jailed {
            uid: report.uid,
            gid: report.gid,
            landlock: report.landlock.clone(),
            seccomp: report.seccomp,
        },
    )?;

    let secret = match fdpass::recv_json::<ToChild>(control.as_fd())? {
        Some((ToChild::Secrets, mut fds)) if fds.len() == 1 => fdpass::read_secret_memfd(fds.remove(0))?,
        Some((ToChild::Shutdown { .. }, _)) | None => std::process::exit(0),
        Some((other, _)) => bail!("expected secrets, got {other:?}"),
    };
    send(&control, &ToSupervisor::Ready)?;
    Ok(Bootstrapped { assignment, jail: report, secret, control })
}

impl Bootstrapped {
    /// Hand over to async code. Call inside a tokio runtime.
    pub fn into_async(self) -> std::io::Result<(Assignment, Zeroizing<Vec<u8>>, ControlChannel)> {
        let sock = AsyncSeqpacket::new(self.control)?;
        Ok((self.assignment, self.secret, ControlChannel { sock: Arc::new(sock) }))
    }

    pub fn control_raw_fd(&self) -> i32 {
        self.control.as_raw_fd()
    }
}

pub enum Event {
    /// One routed request; speak HTTP/1.1 server-side on the stream.
    Rpc { request_id: u64, stream: tokio::net::UnixStream },
    FindingAppend { request_id: u64, stream: tokio::net::UnixStream },
    PeerRpc { request_id: u64, stream: tokio::net::UnixStream },
    Wake(WakeReason),
    /// A fresh bootstrap secret, answering [`ControlChannel::request_secrets`].
    Secrets(Zeroizing<Vec<u8>>),
    Shutdown { grace: Duration },
    /// The supervisor went away: exit.
    Closed,
}

#[derive(Clone)]
pub struct ControlChannel {
    sock: Arc<AsyncSeqpacket>,
}

impl ControlChannel {
    /// The child end of a control `SOCK_SEQPACKET` pair, already past the
    /// handshake ([`Bootstrapped::into_async`] does this for a spawned child;
    /// harnesses that play the supervisor use it directly).
    pub fn from_fd(fd: OwnedFd) -> std::io::Result<Self> {
        Ok(Self { sock: Arc::new(AsyncSeqpacket::new(fd)?) })
    }

    pub async fn next_event(&self) -> std::io::Result<Event> {
        loop {
            let Some((msg, mut fds)) = self.sock.recv_json::<ToChild>().await? else {
                return Ok(Event::Closed);
            };
            return Ok(match msg {
                ToChild::Rpc { request_id } => {
                    if fds.len() != 1 {
                        tracing::warn!(request_id, fds = fds.len(), "rpc without exactly one stream");
                        continue;
                    }
                    let std = std::os::unix::net::UnixStream::from(fds.remove(0));
                    std.set_nonblocking(true)?;
                    Event::Rpc { request_id, stream: tokio::net::UnixStream::from_std(std)? }
                }
                ToChild::PeerRpc { request_id } => {
                    if fds.len() != 1 {
                        tracing::warn!(request_id, fds = fds.len(), "peer rpc without exactly one stream");
                        continue;
                    }
                    let std = std::os::unix::net::UnixStream::from(fds.remove(0));
                    std.set_nonblocking(true)?;
                    Event::PeerRpc { request_id, stream: tokio::net::UnixStream::from_std(std)? }
                }
                ToChild::FindingAppend { request_id } => {
                    if fds.len() != 1 {
                        tracing::warn!(request_id, fds = fds.len(), "finding append without exactly one stream");
                        continue;
                    }
                    let std = std::os::unix::net::UnixStream::from(fds.remove(0));
                    std.set_nonblocking(true)?;
                    Event::FindingAppend { request_id, stream: tokio::net::UnixStream::from_std(std)? }
                }
                ToChild::Wake { reason } => Event::Wake(reason),
                ToChild::Shutdown { grace_ms } => Event::Shutdown { grace: Duration::from_millis(grace_ms) },
                ToChild::Secrets => {
                    if fds.len() != 1 {
                        tracing::warn!(fds = fds.len(), "secrets without exactly one memfd");
                        continue;
                    }
                    Event::Secrets(fdpass::read_secret_memfd(fds.remove(0))?)
                }
                ToChild::Assign { .. } => {
                    tracing::warn!("ignoring handshake message after ready");
                    continue;
                }
            });
        }
    }

    pub async fn heartbeat(&self, hb: &Heartbeat) -> std::io::Result<()> {
        self.sock.send_json(&ToSupervisor::Heartbeat(hb.clone()), &[]).await
    }

    /// Ask the supervisor for a fresh bootstrap secret (arrives as
    /// [`Event::Secrets`] / [`TenantService::secrets`]).
    pub async fn request_secrets(&self) -> std::io::Result<()> {
        self.sock.send_json(&ToSupervisor::RefreshSecrets, &[]).await
    }

    pub async fn connect_ingest(&self, request_id: u64) -> std::io::Result<()> {
        self.sock.send_json(&ToSupervisor::ConnectIngest { request_id }, &[]).await
    }

    pub async fn finding_append_complete(&self, request_id: u64) -> std::io::Result<()> {
        self.sock.send_json(&ToSupervisor::FindingAppendComplete { request_id }, &[]).await
    }

    pub async fn fatal(&self, error: &str) -> std::io::Result<()> {
        self.sock.send_json(&ToSupervisor::Fatal { error: error.to_owned() }, &[]).await
    }
}

/// What a tenant process implements. [`run_service`] drives it.
#[async_trait]
pub trait TenantService: Send + Sync + 'static {
    /// Serve one routed request (HTTP/1.1 on `stream`).
    async fn handle_rpc(self: Arc<Self>, request_id: u64, stream: tokio::net::UnixStream);
    /// Only Detect receives streams it requested to ingest[T].
    async fn peer_rpc(self: Arc<Self>, _request_id: u64, _stream: tokio::net::UnixStream) {}
    /// Typed ingest append authority, never a public router RPC.
    async fn finding_append(self: Arc<Self>, _request_id: u64, _stream: tokio::net::UnixStream, _control: ControlChannel) {}
    /// Data arrived / a detection is due / pre-warm.
    async fn wake(self: Arc<Self>, reason: WakeReason);
    /// Current progress facts; sent at least every [`HEARTBEAT_INTERVAL_MAX`].
    fn heartbeat(&self) -> Heartbeat;
    /// Flush and stop within `grace`.
    async fn shutdown(self: Arc<Self>, _grace: Duration) {}
    /// A fresh bootstrap secret arrived (after `request_secrets`).
    async fn secrets(self: Arc<Self>, _secret: Zeroizing<Vec<u8>>) {}
}

/// Drive a [`TenantService`] until shutdown or supervisor loss.
pub async fn run_service<S: TenantService>(svc: Arc<S>, control: ControlChannel) -> anyhow::Result<()> {
    let hb_every = HEARTBEAT_INTERVAL_MAX / 3;
    let hb_ctl = control.clone();
    let hb_svc = svc.clone();
    let hb_task = tokio::spawn(async move {
        let mut tick = tokio::time::interval(hb_every);
        loop {
            tick.tick().await;
            if hb_ctl.heartbeat(&hb_svc.heartbeat()).await.is_err() {
                break;
            }
        }
    });
    let result = loop {
        match control.next_event().await {
            Ok(Event::Rpc { request_id, stream }) => {
                tokio::spawn(svc.clone().handle_rpc(request_id, stream));
            }
            Ok(Event::PeerRpc { request_id, stream }) => {
                tokio::spawn(svc.clone().peer_rpc(request_id, stream));
            }
            Ok(Event::FindingAppend { request_id, stream }) => {
                tokio::spawn(svc.clone().finding_append(request_id, stream, control.clone()));
            }
            Ok(Event::Wake(reason)) => {
                tokio::spawn(svc.clone().wake(reason));
                // Report the wake promptly so the supervisor sees `busy`.
                let _ = control.heartbeat(&svc.heartbeat()).await;
            }
            Ok(Event::Secrets(secret)) => {
                tokio::spawn(svc.clone().secrets(secret));
            }
            Ok(Event::Shutdown { grace }) => {
                let _ = tokio::time::timeout(grace, svc.clone().shutdown(grace)).await;
                break Ok(());
            }
            Ok(Event::Closed) => break Ok(()),
            Err(e) => break Err(e.into()),
        }
    };
    hb_task.abort();
    result
}
