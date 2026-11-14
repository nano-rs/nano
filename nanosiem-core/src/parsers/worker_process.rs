// SPDX-License-Identifier: AGPL-3.0-or-later
//! One-shot, resource-limited worker processes for tenant VRL (open core).
//!
//! Shared by Nano Pipe previews ([`super::pipe::sandbox`], NAN-4919) and
//! parser tests ([`super::test_sandbox`], NAN-5234). The API never executes
//! either in its own process: it re-executes its own binary with a worker
//! argument, which the binary's `main` dispatches BEFORE configuration,
//! tracing, database pools or the HTTP server exist. The worker reads one
//! bounded request on stdin, writes one bounded response on stdout, and exits.
//!
//! Every worker gets, whatever it runs:
//! - **Linux:** `RLIMIT_DATA` / `RLIMIT_AS` / `RLIMIT_CPU` from its
//!   [`WorkerLimits`], no core dumps, `PR_SET_NO_NEW_PRIVS`; installed between
//!   fork and exec and again inside the worker. The worker also raises its own
//!   `oom_score_adj`, so a container-level OOM takes the worker, not the API.
//! - **Every platform:** a cleared environment (no secrets reach the child),
//!   bounded stdin/stdout, a wall clock after which the child is killed and
//!   reaped, and `kill_on_drop` on request cancellation. Non-Linux hosts (a
//!   macOS development box) get `RLIMIT_CPU` / `RLIMIT_CORE` only and report
//!   degraded isolation.
//! - **Admission:** a [`WorkerGate`] caps how many workers of one kind run at
//!   once on this replica (and, optionally, one per user).

use std::{
    collections::HashSet,
    io::{self, Read},
    process::{ExitStatus, Stdio},
    sync::Mutex,
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    process::Command,
    sync::{Semaphore, SemaphorePermit},
};
use uuid::Uuid;

/// Stack for the thread that executes tenant VRL inside a worker.
pub const WORKER_THREAD_STACK_BYTES: usize = 8 * 1024 * 1024;

/// The OS bounds for one kind of worker.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WorkerLimits {
    /// `RLIMIT_DATA` (Linux): heap and private anonymous mappings, the bound
    /// that actually stops a program that allocates without limit.
    pub private_memory_bytes: u64,
    /// `RLIMIT_AS` (Linux): the whole address space, binary image and thread
    /// stacks included.
    pub address_space_bytes: u64,
    /// `RLIMIT_CPU` soft limit (SIGXCPU) at spawn.
    pub cpu_seconds: u64,
    /// `RLIMIT_CPU` hard limit (SIGKILL): the ceiling no phase of the worker
    /// can pass, raised to at least `cpu_seconds + 1`. A worker with phases
    /// moves its soft limit inside this ceiling with
    /// [`extend_cpu_soft_limit`]; one without gets `cpu_seconds + 1`.
    pub cpu_ceiling_seconds: u64,
    /// Wall clock from spawn to reaped exit.
    pub wall: Duration,
    /// Largest stdout the parent reads.
    pub max_output_bytes: usize,
}

impl WorkerLimits {
    /// The effective `RLIMIT_CPU` hard limit.
    pub const fn cpu_hard_seconds(&self) -> u64 {
        if self.cpu_ceiling_seconds > self.cpu_seconds {
            self.cpu_ceiling_seconds
        } else {
            self.cpu_seconds + 1
        }
    }
}

/// Why a worker produced no usable reply. Callers map these to their own
/// user-facing errors; operator detail goes to the log only.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum WorkerFailure {
    #[error("worker exceeded its wall-clock deadline")]
    Deadline,
    #[error("worker output exceeded its bound")]
    OutputLimit,
    #[error("worker failed or exceeded its CPU or memory bound")]
    Worker,
    #[error("worker process could not be started")]
    Unavailable,
}

/// A refused admission (HTTP 429 at the edge).
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum AdmissionRefused {
    #[error("this user already has a worker running")]
    UserBusy,
    #[error("worker capacity is busy")]
    Busy,
}

/// Whether this host enforces the full Linux resource limits.
pub const fn full_isolation() -> bool {
    cfg!(target_os = "linux")
}

/// A worker-count setting, clamped to `1..=max`; unset or invalid → `default`.
pub fn clamp_concurrency(value: Option<&str>, default: usize, max: usize) -> usize {
    value
        .and_then(|value| value.trim().parse::<usize>().ok())
        .map(|value| value.clamp(1, max))
        .unwrap_or(default)
}

/// Per-replica worker admission for one kind of worker, with an optional
/// one-running-per-user rule. Nothing about it is global: each kind owns a
/// `static` gate.
pub struct WorkerGate {
    slots: Semaphore,
    users: Mutex<HashSet<Uuid>>,
}

/// Held while a worker runs; releases its slots on drop, including when the
/// request future is cancelled.
pub struct Admission<'a> {
    _slot: SemaphorePermit<'a>,
    user: Option<(&'a WorkerGate, Uuid)>,
}

impl Drop for Admission<'_> {
    fn drop(&mut self) {
        if let Some((gate, user)) = self.user.take() {
            gate.users
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .remove(&user);
        }
    }
}

impl WorkerGate {
    pub fn new(concurrency: usize) -> Self {
        Self {
            slots: Semaphore::new(concurrency.max(1)),
            users: Mutex::new(HashSet::new()),
        }
    }

    fn claim_user(&self, user: Option<Uuid>) -> Result<Option<(&Self, Uuid)>, AdmissionRefused> {
        let Some(user) = user else { return Ok(None) };
        let mut running = self
            .users
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if !running.insert(user) {
            return Err(AdmissionRefused::UserBusy);
        }
        Ok(Some((self, user)))
    }

    fn release_user(&self, claimed: Option<(&Self, Uuid)>) {
        if let Some((_, user)) = claimed {
            self.users
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .remove(&user);
        }
    }

    /// Admit now or refuse. The per-user rule is checked first, so one user
    /// never holds a replica slot while another of their workers runs.
    pub fn try_admit(&self, user: Option<Uuid>) -> Result<Admission<'_>, AdmissionRefused> {
        let claimed = self.claim_user(user)?;
        match self.slots.try_acquire() {
            Ok(slot) => Ok(Admission {
                _slot: slot,
                user: claimed,
            }),
            Err(_) => {
                self.release_user(claimed);
                Err(AdmissionRefused::Busy)
            }
        }
    }

    /// Admit within `wait` or refuse. A short wait absorbs bursts of
    /// millisecond-scale work without turning them into 429s; it never
    /// queues for longer than `wait`.
    pub async fn admit_within(
        &self,
        user: Option<Uuid>,
        wait: Duration,
    ) -> Result<Admission<'_>, AdmissionRefused> {
        let claimed = self.claim_user(user)?;
        match tokio::time::timeout(wait, self.slots.acquire()).await {
            Ok(Ok(slot)) => Ok(Admission {
                _slot: slot,
                user: claimed,
            }),
            _ => {
                self.release_user(claimed);
                Err(AdmissionRefused::Busy)
            }
        }
    }
}

/// Why a worker failed, for operator logs only (the caller sees one generic
/// error). The CPU limit delivers SIGXCPU then SIGKILL; memory exhaustion
/// aborts or faults on a guard page.
#[cfg(unix)]
pub fn classify_exit(status: &ExitStatus) -> &'static str {
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
pub fn classify_exit(_status: &ExitStatus) -> &'static str {
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

/// Install `limits` on the calling process (see the module docs). Only
/// async-signal-safe syscalls: safe between fork and exec.
#[cfg(target_os = "linux")]
pub fn apply_limits(limits: &WorkerLimits) -> io::Result<()> {
    cap(
        libc::RLIMIT_DATA as _,
        limits.private_memory_bytes,
        limits.private_memory_bytes,
    )?;
    cap(
        libc::RLIMIT_AS as _,
        limits.address_space_bytes,
        limits.address_space_bytes,
    )?;
    cap(libc::RLIMIT_CPU as _, limits.cpu_seconds, limits.cpu_hard_seconds())?;
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
pub fn apply_limits(limits: &WorkerLimits) -> io::Result<()> {
    cap(libc::RLIMIT_CPU as _, limits.cpu_seconds, limits.cpu_hard_seconds())?;
    cap(libc::RLIMIT_CORE as _, 0, 0)
}

#[cfg(not(unix))]
pub fn apply_limits(_limits: &WorkerLimits) -> io::Result<()> {
    Ok(())
}

/// CPU time (user + system) this process has used, all threads.
#[cfg(unix)]
pub fn self_cpu_time() -> Option<Duration> {
    rusage_cpu_time(libc::RUSAGE_SELF)
}

/// CPU time (user + system) of this process's reaped children.
#[cfg(unix)]
pub fn children_cpu_time() -> Option<Duration> {
    rusage_cpu_time(libc::RUSAGE_CHILDREN)
}

#[cfg(unix)]
fn rusage_cpu_time(who: libc::c_int) -> Option<Duration> {
    // SAFETY: getrusage only writes into the zeroed struct this frame owns.
    let mut usage: libc::rusage = unsafe { std::mem::zeroed() };
    if unsafe { libc::getrusage(who, &mut usage) } != 0 {
        return None;
    }
    let time = |t: libc::timeval| {
        Duration::from_secs(t.tv_sec.max(0) as u64) + Duration::from_micros(t.tv_usec.max(0) as u64)
    };
    Some(time(usage.ru_utime) + time(usage.ru_stime))
}

/// Inside a worker, once, between phases: allow `seconds` more CPU on top of
/// what the process has already used, by moving the `RLIMIT_CPU` soft limit
/// (raising it, or lowering it when the first phase finished early). Never
/// above the hard limit, which a process cannot raise, so neither can the
/// tenant program that runs after this call: the worker's ceiling
/// ([`WorkerLimits::cpu_ceiling_seconds`]) holds.
///
/// A stricter soft limit inherited from the parent (an operator's
/// `ulimit -t` below [`WorkerLimits::cpu_seconds`]) is never raised: the
/// soft limit found here below the configured first-phase limit can only be
/// that inherited one, since [`apply_limits`] never raises it.
#[cfg(unix)]
pub fn extend_cpu_soft_limit(limits: &WorkerLimits, seconds: u64) -> io::Result<()> {
    let used = self_cpu_time().ok_or_else(io::Error::last_os_error)?;
    // Whole seconds, rounded up: the kernel counts the partial one.
    let used = used.as_secs() + u64::from(used.subsec_nanos() > 0);
    let mut current = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: the pointer refers to an initialized rlimit.
    if unsafe { libc::getrlimit(libc::RLIMIT_CPU as _, &mut current) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let mut soft = (used.saturating_add(seconds) as libc::rlim_t).min(current.rlim_max);
    if current.rlim_cur < limits.cpu_seconds as libc::rlim_t {
        soft = soft.min(current.rlim_cur);
    }
    let value = libc::rlimit {
        rlim_cur: soft,
        rlim_max: current.rlim_max,
    };
    // SAFETY: as above.
    if unsafe { libc::setrlimit(libc::RLIMIT_CPU as _, &value) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(not(unix))]
pub fn extend_cpu_soft_limit(_limits: &WorkerLimits, _seconds: u64) -> io::Result<()> {
    Ok(())
}

/// First call of every worker entry point: re-apply `limits` (in case the
/// worker was started some other way than [`exchange`]) and make this process
/// the container's preferred OOM victim.
pub fn enter_worker(limits: &WorkerLimits) -> io::Result<()> {
    apply_limits(limits)?;
    #[cfg(target_os = "linux")]
    {
        // Raising the score needs no privilege; failure (an unusual /proc)
        // is not fatal because the rlimits above are the real bound.
        let _ = std::fs::write("/proc/self/oom_score_adj", b"1000");
    }
    Ok(())
}

/// Read at most `max` bytes; `None` when the input is larger or unreadable.
pub fn read_bounded(reader: impl Read, max: usize) -> Option<Vec<u8>> {
    let mut input = Vec::new();
    reader
        .take(max as u64 + 1)
        .read_to_end(&mut input)
        .ok()?;
    (input.len() <= max).then_some(input)
}

/// Run `command` as a worker: hand it `input`, return its stdout. `label`
/// names the worker kind in operator logs.
pub async fn exchange(
    mut command: Command,
    input: &[u8],
    limits: &WorkerLimits,
    label: &'static str,
) -> Result<Vec<u8>, WorkerFailure> {
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
    {
        let limits = *limits;
        // SAFETY: only async-signal-safe rlimit/prctl syscalls run between
        // fork and exec: no allocation, logging or runtime work.
        unsafe {
            command.pre_exec(move || apply_limits(&limits));
        }
    }
    let mut child = command.spawn().map_err(|_| WorkerFailure::Unavailable)?;
    let mut stdin = child.stdin.take().ok_or(WorkerFailure::Unavailable)?;
    let stdout = child.stdout.take().ok_or(WorkerFailure::Unavailable)?;
    let output_limit = limits.max_output_bytes;
    let task = async {
        // A worker that dies mid-request closes its stdin: that is a worker
        // failure, reported from its exit status below when possible.
        let write = async {
            let written = stdin.write_all(input).await;
            let shut = stdin.shutdown().await;
            drop(stdin);
            written.and(shut).map_err(|_| WorkerFailure::Worker)
        };
        let read = async {
            let mut output = Vec::new();
            stdout
                .take(output_limit as u64 + 1)
                .read_to_end(&mut output)
                .await
                .map_err(|_| WorkerFailure::Worker)?;
            if output.len() > output_limit {
                return Err(WorkerFailure::OutputLimit);
            }
            Ok(output)
        };
        let wait = async { child.wait().await.map_err(|_| WorkerFailure::Worker) };
        // An oversized reply fails fast (the wait is dropped, the child is
        // killed below); writing runs alongside so a large request can never
        // deadlock against a worker that is already replying.
        let (written, collected) = tokio::join!(write, async { tokio::try_join!(read, wait) });
        let (output, status) = collected?;
        if !status.success() {
            tracing::warn!(
                worker = label,
                failure = classify_exit(&status),
                code = status.code(),
                "sandbox worker failed"
            );
            return Err(WorkerFailure::Worker);
        }
        written?;
        Ok(output)
    };
    let result = match tokio::time::timeout(limits.wall, task).await {
        Ok(result) => result,
        Err(_) => {
            tracing::warn!(worker = label, failure = "wall_deadline", "sandbox worker failed");
            Err(WorkerFailure::Deadline)
        }
    };
    if result.is_err() {
        let _ = child.kill().await;
    }
    result
}

#[cfg(test)]
#[path = "worker_process_tests.rs"]
mod tests;
