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
//! The process machinery is shared with parser tests
//! ([`crate::parsers::worker_process`]). Bounds:
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
    io::{self, Write},
    path::Path,
    sync::OnceLock,
    time::Duration,
};
use tokio::process::Command;
use uuid::Uuid;

use super::preview::{PipePreviewRequest, PipePreviewResponse, MAX_REQUEST_BYTES, MAX_RESPONSE_BYTES};
use crate::parsers::worker_process::{
    self, AdmissionRefused, WorkerFailure, WorkerGate, WorkerLimits,
};
pub use crate::parsers::worker_process::{full_isolation, WORKER_THREAD_STACK_BYTES};

/// The argument that turns the API binary into a one-shot preview worker.
pub const WORKER_ARGUMENT: &str = "--pipe-preview-worker";
pub const ENABLED_ENV: &str = "NANO_PIPE_PREVIEW_ENABLED";
pub const CONCURRENCY_ENV: &str = "NANO_PIPE_PREVIEW_CONCURRENCY";
pub const WORKER_PRIVATE_MEMORY_BYTES: u64 = 256 * 1024 * 1024;
pub const WORKER_ADDRESS_SPACE_BYTES: u64 = 1024 * 1024 * 1024;
pub const WORKER_CPU_SECONDS: u64 = 3;
pub const WORKER_WALL_SECONDS: u64 = 10;
pub const DEFAULT_CONCURRENCY: usize = 2;
pub const MAX_CONCURRENCY: usize = 8;
pub const RETRY_AFTER_SECONDS: u64 = 2;

/// The preview worker's OS bounds.
pub const LIMITS: WorkerLimits = WorkerLimits {
    private_memory_bytes: WORKER_PRIVATE_MEMORY_BYTES,
    address_space_bytes: WORKER_ADDRESS_SPACE_BYTES,
    cpu_seconds: WORKER_CPU_SECONDS,
    wall: Duration::from_secs(WORKER_WALL_SECONDS),
    max_output_bytes: MAX_RESPONSE_BYTES,
};

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

impl From<WorkerFailure> for PreviewSandboxError {
    fn from(failure: WorkerFailure) -> Self {
        match failure {
            WorkerFailure::Deadline => Self::Deadline,
            WorkerFailure::OutputLimit => Self::OutputLimit,
            WorkerFailure::Worker => Self::Worker,
            WorkerFailure::Unavailable => Self::Unavailable,
        }
    }
}

impl From<AdmissionRefused> for PreviewSandboxError {
    fn from(refused: AdmissionRefused) -> Self {
        match refused {
            AdmissionRefused::UserBusy => Self::UserBusy,
            AdmissionRefused::Busy => Self::Busy,
        }
    }
}

/// Whether previews are enabled (`NANO_PIPE_PREVIEW_ENABLED=true`).
pub fn enabled() -> bool {
    std::env::var(ENABLED_ENV).is_ok_and(|v| v.trim().eq_ignore_ascii_case("true"))
}

/// `NANO_PIPE_PREVIEW_CONCURRENCY`, clamped to 1–8; unset or invalid → 2.
pub fn configured_concurrency(value: Option<&str>) -> usize {
    worker_process::clamp_concurrency(value, DEFAULT_CONCURRENCY, MAX_CONCURRENCY)
}

/// One running preview per user, then the per-replica gate.
fn gate() -> &'static WorkerGate {
    static GATE: OnceLock<WorkerGate> = OnceLock::new();
    GATE.get_or_init(|| {
        WorkerGate::new(configured_concurrency(
            std::env::var(CONCURRENCY_ENV).ok().as_deref(),
        ))
    })
}

fn read_request(reader: impl io::Read) -> Result<PipePreviewRequest, PreviewSandboxError> {
    let input =
        worker_process::read_bounded(reader, MAX_REQUEST_BYTES).ok_or(PreviewSandboxError::Protocol)?;
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
    worker_process::enter_worker(&LIMITS).map_err(|_| PreviewSandboxError::Unavailable)?;
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
    let _admission = gate().try_admit(Some(user))?;
    let input = serde_json::to_vec(request).map_err(|_| PreviewSandboxError::Protocol)?;
    let mut command = Command::new(executable);
    command.args(args);
    let output = worker_process::exchange(command, &input, &LIMITS, "pipe_preview").await?;
    decode(&output, request)
}

#[cfg(test)]
#[path = "sandbox_tests.rs"]
mod tests;
