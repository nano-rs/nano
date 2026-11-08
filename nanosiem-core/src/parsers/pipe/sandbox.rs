// SPDX-License-Identifier: AGPL-3.0-or-later
//! Process isolation for Nano Pipe previews (NAN-4919, open core).
//!
//! A preview executes tenant-authored VRL. The API never runs it in its own
//! process: it re-executes its own binary with [`WORKER_ARGUMENT`], which the
//! binary's `main` dispatches to [`worker_main`] BEFORE configuration,
//! tracing, database pools or the HTTP server exist. The worker reads one
//! bounded JSON request on stdin, writes one bounded response on stdout, and
//! exits.
//!
//! Bounds:
//! - **Linux:** `RLIMIT_DATA` 256 MiB, `RLIMIT_AS` 1 GiB, `RLIMIT_CPU` 3 s, no
//!   core dumps, `PR_SET_NO_NEW_PRIVS`; installed between fork and exec and
//!   again inside the worker.
//! - **Every platform:** a cleared environment (no secrets reach the child),
//!   bounded stdin/stdout, a 10 s wall clock after which the child is killed
//!   and reaped, `kill_on_drop` on request cancellation. Non-Linux hosts (a
//!   macOS development box) also get `RLIMIT_CPU` / `RLIMIT_CORE`; the
//!   response is marked `degraded_isolation`.
//! - **Admission:** one running preview per user, then a per-replica gate
//!   (`NANO_PIPE_PREVIEW_CONCURRENCY`, 1–8, default 2). A refusal is an
//!   immediate 429 with `Retry-After`; nothing queues.
//!
//! Previews are OFF unless `NANO_PIPE_PREVIEW_ENABLED=true`.

use std::{
    collections::HashSet,
    io::{self, Read, Write},
    path::Path,
    process::{ExitStatus, Stdio},
    sync::{Mutex, OnceLock},
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    process::Command,
    sync::Semaphore,
};
use uuid::Uuid;

use super::preview::{PipePreviewRequest, PipePreviewResponse, MAX_REQUEST_BYTES, MAX_RESPONSE_BYTES};

/// The argument that turns the API binary into a one-shot preview worker.
pub const WORKER_ARGUMENT: &str = "--pipe-preview-worker";
pub const ENABLED_ENV: &str = "NANO_PIPE_PREVIEW_ENABLED";
pub const CONCURRENCY_ENV: &str = "NANO_PIPE_PREVIEW_CONCURRENCY";
pub const WORKER_PRIVATE_MEMORY_BYTES: u64 = 256 * 1024 * 1024;
pub const WORKER_ADDRESS_SPACE_BYTES: u64 = 1024 * 1024 * 1024;
pub const WORKER_THREAD_STACK_BYTES: usize = 8 * 1024 * 1024;
pub const WORKER_CPU_SECONDS: u64 = 3;
pub const WORKER_WALL_SECONDS: u64 = 10;
pub const DEFAULT_CONCURRENCY: usize = 2;
pub const MAX_CONCURRENCY: usize = 8;
pub const RETRY_AFTER_SECONDS: u64 = 2;

#[derive(Debug, thiserror::Error)]
pub enum PreviewSandboxError {
    #[error("Pipeline preview is disabled on this deployment")]
    Disabled,
    #[error("You already have a preview running; retry shortly")]
    UserBusy,
    #[error("Preview capacity is busy; retry shortly")]
    Busy,
    #[error("Preview exceeded its execution deadline; reduce the sample or the program")]
    Deadline,
    #[error("Preview output exceeded the inspection bound")]
    OutputLimit,
    #[error("Preview worker failed or exceeded its CPU or memory bound")]
    Worker,
    #[error("Invalid preview worker response")]
    Protocol,
    #[error("Preview process isolation is unavailable")]
    Unavailable,
    /// The draft or the events are invalid (a 400, with the reason).
    #[error("{0}")]
    Invalid(String),
}

impl PreviewSandboxError {
    /// `Retry-After` seconds for a refused admission (HTTP 429).
    pub fn retry_after_seconds(&self) -> Option<u64> {
        matches!(self, Self::Busy | Self::UserBusy).then_some(RETRY_AFTER_SECONDS)
    }
}

/// Whether previews are enabled (`NANO_PIPE_PREVIEW_ENABLED=true`).
pub fn enabled() -> bool {
    std::env::var(ENABLED_ENV).is_ok_and(|v| v.trim().eq_ignore_ascii_case("true"))
}

/// Whether this host enforces the full Linux resource limits.
pub const fn full_isolation() -> bool {
    cfg!(target_os = "linux")
}

/// `NANO_PIPE_PREVIEW_CONCURRENCY`, clamped to 1–8; unset or invalid → 2.
pub fn configured_concurrency(value: Option<&str>) -> usize {
    value
        .and_then(|value| value.trim().parse::<usize>().ok())
        .map(|value| value.clamp(1, MAX_CONCURRENCY))
        .unwrap_or(DEFAULT_CONCURRENCY)
}

fn gate() -> &'static Semaphore {
    static GATE: OnceLock<Semaphore> = OnceLock::new();
    GATE.get_or_init(|| {
        Semaphore::new(configured_concurrency(
            std::env::var(CONCURRENCY_ENV).ok().as_deref(),
        ))
    })
}

fn running_users() -> &'static Mutex<HashSet<Uuid>> {
    static USERS: OnceLock<Mutex<HashSet<Uuid>>> = OnceLock::new();
    USERS.get_or_init(Default::default)
}

/// One running preview per user; released on drop, including cancellation.
struct UserSlot(Uuid);

impl UserSlot {
    fn acquire(user: Uuid) -> Result<Self, PreviewSandboxError> {
        let mut running = running_users()
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if !running.insert(user) {
            return Err(PreviewSandboxError::UserBusy);
        }
        Ok(Self(user))
    }
}

impl Drop for UserSlot {
    fn drop(&mut self) {
        running_users()
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .remove(&self.0);
    }
}

/// Why a worker failed, for operator logs only (the caller sees one generic
/// error). The CPU limit delivers SIGXCPU then SIGKILL; memory exhaustion
/// aborts or faults on a guard page.
#[cfg(unix)]
fn classify_exit(status: &ExitStatus) -> &'static str {
    use std::os::unix::process::ExitStatusExt;
    match status.signal() {
        Some(libc::SIGXCPU) | Some(libc::SIGKILL) => "cpu_limit",
        Some(libc::SIGABRT) => "memory_limit",
        Some(libc::SIGSEGV) | Some(libc::SIGBUS) => "memory_or_stack_limit",
        Some(_) => "crash_signal",
        None => "worker_error_exit",
    }
}

#[cfg(not(unix))]
fn classify_exit(_status: &ExitStatus) -> &'static str {
    "worker_error_exit"
}

/// Lower a resource limit, never raising an inherited stricter one.
#[cfg(unix)]
fn cap(resource: libc::c_int, soft: u64, hard: u64) -> io::Result<()> {
    let mut inherited = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: the pointer refers to an initialized rlimit; getrlimit and
    // setrlimit are async-signal-safe, so this may run between fork and exec.
    if unsafe { libc::getrlimit(resource as _, &mut inherited) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let hard = inherited.rlim_max.min(hard as libc::rlim_t);
    let value = libc::rlimit {
        rlim_cur: inherited.rlim_cur.min(soft as libc::rlim_t).min(hard),
        rlim_max: hard,
    };
    // SAFETY: as above.
    if unsafe { libc::setrlimit(resource as _, &value) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Install the worker's resource limits (see the module docs).
#[cfg(target_os = "linux")]
pub fn apply_worker_limits() -> io::Result<()> {
    cap(
        libc::RLIMIT_DATA as _,
        WORKER_PRIVATE_MEMORY_BYTES,
        WORKER_PRIVATE_MEMORY_BYTES,
    )?;
    cap(
        libc::RLIMIT_AS as _,
        WORKER_ADDRESS_SPACE_BYTES,
        WORKER_ADDRESS_SPACE_BYTES,
    )?;
    cap(libc::RLIMIT_CPU as _, WORKER_CPU_SECONDS, WORKER_CPU_SECONDS + 1)?;
    cap(libc::RLIMIT_CORE as _, 0, 0)?;
    // SAFETY: integer arguments only; the child cannot gain privileges
    // through exec and cannot relax this.
    if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Degraded isolation: CPU time and core dumps only (macOS lacks an enforced
/// data/address-space limit). The wall clock still bounds the worker.
#[cfg(all(unix, not(target_os = "linux")))]
pub fn apply_worker_limits() -> io::Result<()> {
    cap(libc::RLIMIT_CPU as _, WORKER_CPU_SECONDS, WORKER_CPU_SECONDS + 1)?;
    cap(libc::RLIMIT_CORE as _, 0, 0)
}

#[cfg(not(unix))]
pub fn apply_worker_limits() -> io::Result<()> {
    Ok(())
}

fn read_request(reader: impl Read) -> Result<PipePreviewRequest, PreviewSandboxError> {
    let mut input = Vec::new();
    reader
        .take(MAX_REQUEST_BYTES as u64 + 1)
        .read_to_end(&mut input)
        .map_err(|_| PreviewSandboxError::Protocol)?;
    if input.len() > MAX_REQUEST_BYTES {
        return Err(PreviewSandboxError::Protocol);
    }
    let request: PipePreviewRequest =
        serde_json::from_slice(&input).map_err(|_| PreviewSandboxError::Protocol)?;
    request.validate().map_err(PreviewSandboxError::Invalid)?;
    Ok(request)
}

/// The worker's wire envelope: a result, or a user-facing refusal.
#[derive(serde::Serialize, serde::Deserialize)]
enum WorkerReply {
    Ok(Box<PipePreviewResponse>),
    Invalid(String),
}

/// Entry point for `nanosiem-api --pipe-preview-worker`. Call from a
/// synchronous `main` before anything else is initialized.
pub fn worker_main() -> Result<(), PreviewSandboxError> {
    apply_worker_limits().map_err(|_| PreviewSandboxError::Unavailable)?;
    let request = read_request(io::stdin().lock())?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .max_blocking_threads(1)
        .thread_stack_size(WORKER_THREAD_STACK_BYTES)
        .build()
        .map_err(|_| PreviewSandboxError::Unavailable)?;
    // Preview VRL output must never reach a log stream.
    let reply = tracing::subscriber::with_default(
        tracing::subscriber::NoSubscriber::default(),
        || runtime.block_on(super::preview::run(&request)),
    );
    let reply = match reply {
        Ok(mut response) => {
            response.degraded_isolation = !full_isolation();
            WorkerReply::Ok(Box::new(response))
        }
        Err(message) => WorkerReply::Invalid(message),
    };
    let output = serde_json::to_vec(&reply).map_err(|_| PreviewSandboxError::Protocol)?;
    if output.len() > MAX_RESPONSE_BYTES {
        return Err(PreviewSandboxError::OutputLimit);
    }
    io::stdout()
        .lock()
        .write_all(&output)
        .map_err(|_| PreviewSandboxError::Worker)
}

async fn exchange(
    mut command: Command,
    input: &[u8],
    wall: Duration,
    output_limit: usize,
) -> Result<Vec<u8>, PreviewSandboxError> {
    command
        .env_clear()
        .env("TZ", "UTC")
        // One glibc arena, so the address-space bound is not spent on
        // per-thread arena reservations.
        .env("MALLOC_ARENA_MAX", "1")
        .current_dir("/")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true);
    #[cfg(unix)]
    // SAFETY: only async-signal-safe rlimit/prctl syscalls run between fork
    // and exec: no allocation, logging or runtime work.
    unsafe {
        command.pre_exec(apply_worker_limits);
    }
    let mut child = command
        .spawn()
        .map_err(|_| PreviewSandboxError::Unavailable)?;
    let mut stdin = child.stdin.take().ok_or(PreviewSandboxError::Unavailable)?;
    let stdout = child
        .stdout
        .take()
        .ok_or(PreviewSandboxError::Unavailable)?;
    let task = async {
        stdin
            .write_all(input)
            .await
            .map_err(|_| PreviewSandboxError::Worker)?;
        stdin
            .shutdown()
            .await
            .map_err(|_| PreviewSandboxError::Worker)?;
        drop(stdin);
        let read = async {
            let mut output = Vec::new();
            stdout
                .take(output_limit as u64 + 1)
                .read_to_end(&mut output)
                .await
                .map_err(|_| PreviewSandboxError::Worker)?;
            if output.len() > output_limit {
                return Err(PreviewSandboxError::OutputLimit);
            }
            Ok(output)
        };
        let wait = async { child.wait().await.map_err(|_| PreviewSandboxError::Worker) };
        let (output, status) = tokio::try_join!(read, wait)?;
        if !status.success() {
            tracing::warn!(
                failure = classify_exit(&status),
                code = status.code(),
                "pipe preview worker failed"
            );
            return Err(PreviewSandboxError::Worker);
        }
        Ok(output)
    };
    let result = match tokio::time::timeout(wall, task).await {
        Ok(result) => result,
        Err(_) => {
            tracing::warn!(failure = "wall_deadline", "pipe preview worker failed");
            Err(PreviewSandboxError::Deadline)
        }
    };
    if result.is_err() {
        let _ = child.kill().await;
    }
    result
}

fn decode(output: &[u8], request: &PipePreviewRequest) -> Result<PipePreviewResponse, PreviewSandboxError> {
    match serde_json::from_slice::<WorkerReply>(output).map_err(|_| PreviewSandboxError::Protocol)? {
        WorkerReply::Invalid(message) => Err(PreviewSandboxError::Invalid(message)),
        WorkerReply::Ok(response) => {
            // The worker answers for exactly the events it was given.
            if response.results.len() != request.events.len()
                || response
                    .results
                    .iter()
                    .enumerate()
                    .any(|(index, row)| row.index != index)
            {
                return Err(PreviewSandboxError::Protocol);
            }
            Ok(*response)
        }
    }
}

/// Run one preview for `user` in a fresh worker process of this executable.
pub async fn preview(
    request: &PipePreviewRequest,
    user: Uuid,
) -> Result<PipePreviewResponse, PreviewSandboxError> {
    if !enabled() {
        return Err(PreviewSandboxError::Disabled);
    }
    let executable = std::env::current_exe().map_err(|_| PreviewSandboxError::Unavailable)?;
    preview_with_executable(request, user, &executable, &[WORKER_ARGUMENT]).await
}

/// [`preview`] against an explicit worker command (tests).
pub async fn preview_with_executable(
    request: &PipePreviewRequest,
    user: Uuid,
    executable: &Path,
    args: &[&str],
) -> Result<PipePreviewResponse, PreviewSandboxError> {
    request.validate().map_err(PreviewSandboxError::Invalid)?;
    // Per-user admission first, so one user never holds (or waits on) a
    // global slot while another of theirs runs.
    let _user = UserSlot::acquire(user)?;
    let _permit = gate().try_acquire().map_err(|_| PreviewSandboxError::Busy)?;
    let input = serde_json::to_vec(request).map_err(|_| PreviewSandboxError::Protocol)?;
    let mut command = Command::new(executable);
    command.args(args);
    let output = exchange(
        command,
        &input,
        Duration::from_secs(WORKER_WALL_SECONDS),
        MAX_RESPONSE_BYTES,
    )
    .await?;
    decode(&output, request)
}

#[cfg(test)]
#[path = "sandbox_tests.rs"]
mod tests;
