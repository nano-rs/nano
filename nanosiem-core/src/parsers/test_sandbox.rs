// SPDX-License-Identifier: AGPL-3.0-or-later
//! Process isolation for parser tests (NAN-5234, open core).
//!
//! `test-vrl`, `test-live`, the parser editor's sample runs, parser-repository
//! sample checks and the AI parser loops all execute a DRAFT VRL program over
//! sample events (through [`crate::parsers::VrlValidator`]). The time budget
//! (NAN-5040) stops a slow program, but nothing in a shared process can stop
//! one that allocates gigabytes between two checkpoints. So the program never
//! runs in the API process: it runs in a one-shot worker, the API binary
//! re-executed with [`WORKER_ARGUMENT`] and dispatched in `main` before
//! configuration, tracing, pools or the server exist (the same machinery as
//! Nano Pipe previews: [`crate::parsers::worker_process`]).
//!
//! Validation (the security gates and the compile check) stays in the API
//! process; the worker re-compiles and executes. Bounds:
//!
//! | bound | value | why |
//! |---|---|---|
//! | `RLIMIT_DATA` | 512 MiB | the largest legitimate request is 24 MiB of JSON (16 MiB of samples, [`MAX_TEST_TOTAL_SAMPLE_BYTES`], plus programs); parsed, converted to VRL values and paired with up to 32 MiB of output it peaks near 300 MiB |
//! | `RLIMIT_AS` | 1.5 GiB | the data bound plus the binary image, thread stacks and allocator reservations (previews: 256 MiB data in 1 GiB) |
//! | `RLIMIT_CPU` soft, compile phase | 15 s | process start-up, decoding the request and compiling every program |
//! | `RLIMIT_CPU` soft, execution phase | +8 s | after compiling: the 5 s execution budget plus encoding the reply, on top of what compiling used |
//! | `RLIMIT_CPU` hard | 24 s | the ceiling for both phases together (SIGKILL) |
//! | wall clock | 28 s | the CPU ceiling plus process start-up |
//! | request | 24 MiB | [`MAX_REQUEST_BYTES`] |
//! | response | 32 MiB | [`MAX_RESPONSE_BYTES`] |
//!
//! The CPU bound has two phases (NAN-5396). Compiling dominates a large
//! parser's test: the largest shipped parser (crowdstrike_falcon, about 70 KiB
//! of VRL) takes 4.6 s of CPU to compile in a release build on Apple silicon
//! and 17 ms to run 100 samples. Under the old single 8 s bound a host 1.7x
//! slower per core could not test it at all. So compiling gets its own
//! allowance (about 3x that parser on the development box), and once every
//! program is compiled the worker moves its soft limit to "CPU used so far +
//! 8 s" ([`worker_process::extend_cpu_soft_limit`]).
//! The hard limit is set before exec and the worker cannot raise it: no
//! request costs more than [`WORKER_CPU_CEILING_SECONDS`] of CPU.
//!
//! Admission (NAN-5396): ONE gate per replica, sized from
//! `NANO_PARSER_TEST_WORKERS` (1–8, default [`DEFAULT_WORKERS`]): that many
//! tests run at once, and one principal holds at most
//! [`per_principal_workers`] of them (1 of the default 2), so one caller can
//! never take every worker. The HTTP handlers [`admit`] the caller's principal
//! BEFORE any validation, compile or query work and run the whole request
//! under that admission ([`admitted`]); its worker jobs then run one at a time
//! in that slot. Internal callers (AI parser loops, attestation) are admitted
//! per job against the same replica-wide limit. A caller waits up to
//! [`ADMISSION_WAIT`] for a slot (parser tests take milliseconds), then is
//! refused ([`VrlValidatorError::Busy`], HTTP 429).
//!
//! Tenant VRL on the test path compiles only in the worker: the API process
//! runs the text gates and leaves the compile to the worker (NAN-5396).
//!
//! # The deploy gate budget (NAN-5406)
//!
//! The bounds above are for INTERACTIVE tests, which answer behind a 30 s
//! upstream deadline. The OCSF sample gate that runs before a publish or
//! deploy goes live ([`Budget::DeployGate`]) is a privileged, explicit action
//! that runs once per deploy, under the deploy routes' 300 s edge budget. It
//! runs in the same worker with the same memory bounds and the same
//! compile/execute split, but with more CPU for the compile and a longer wall
//! clock:
//!
//! | bound | interactive | deploy gate |
//! |---|---|---|
//! | `RLIMIT_CPU` soft, compile phase | 15 s | 45 s |
//! | `RLIMIT_CPU` soft, execution phase | +8 s | +8 s |
//! | `RLIMIT_CPU` hard | 24 s | 54 s |
//! | wall clock | 28 s | 60 s |
//! | admission wait | 2 s, then 429 | [`DEPLOY_GATE_ADMISSION_WAIT`] |
//!
//! Why: compile CPU scales with the program and the host. On the
//! development box (Apple M5 Max, Linux arm64 container) the shipped OCSF
//! parsers take 2.9 s (windows_sysmon), 2.1 s (cisco_asa) and 5.5 s
//! (crowdstrike_falcon) of worker CPU, nearly all of it compiling. A cloud
//! core 3–4x slower per thread (GCE e2 on AMD EPYC Rome, where NAN-5406 was
//! seen) needs up to about 22 s for crowdstrike_falcon, past the interactive
//! 15 s allowance, so the official parser could not be deployed there. 45 s
//! keeps 2x headroom over that. The worker learns its budget from
//! [`DEPLOY_GATE_ARGUMENT`]; the parent sets the hard limit before exec, so
//! the worker can only ever lower it. A runaway program is still killed: at
//! 54 s of CPU, at 60 s of wall clock, or at the memory bounds.
//!
//! Parser testing is ON by default: it is a core feature. A process that has
//! not registered a worker executable (a library test harness, a binary that
//! does not dispatch [`WORKER_ARGUMENT`]) fails closed with a clear error; it
//! never falls back to running the program in-process.

use std::{
    io::{self, Write},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        OnceLock,
    },
    time::Duration,
};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::process::Command;

use super::validator::exec_bounds::{self, ExecutionBudget, TEST_EXECUTION_BUDGET};
use super::vrl_functions::VrlRegistry;
use super::worker_process::{self, WorkerFailure, WorkerLimits};
use crate::principal_gate::{GatePermit, GateRefused, PrincipalGate};
use super::VrlValidatorError;
pub use super::validator::exec_bounds::MAX_TEST_TOTAL_SAMPLE_BYTES;

/// The argument that turns the API binary into a one-shot parser-test worker.
pub const WORKER_ARGUMENT: &str = "--parser-test-worker";
pub const WORKERS_ENV: &str = "NANO_PARSER_TEST_WORKERS";
pub const DEFAULT_WORKERS: usize = 2;
pub const MAX_WORKERS: usize = 8;
/// How long a test waits for a worker slot before it is refused.
pub const ADMISSION_WAIT: Duration = Duration::from_secs(2);
/// Programs (stages) in one chained test: parser + extension in practice.
pub const MAX_STAGES: usize = 4;
/// The serialized worker request: every sample plus up to 8 MiB of program.
pub const MAX_REQUEST_BYTES: usize = MAX_TEST_TOTAL_SAMPLE_BYTES + 8 * 1024 * 1024;
/// The serialized worker reply (outputs for every sample).
pub const MAX_RESPONSE_BYTES: usize = 32 * 1024 * 1024;
pub const WORKER_PRIVATE_MEMORY_BYTES: u64 = 512 * 1024 * 1024;
pub const WORKER_ADDRESS_SPACE_BYTES: u64 = 1536 * 1024 * 1024;
/// CPU for start-up, decoding the request and compiling (the soft limit at
/// spawn).
pub const WORKER_COMPILE_CPU_SECONDS: u64 = 15;
/// CPU for executing the samples and encoding the reply, granted once every
/// program has compiled, on top of what the worker used until then.
pub const WORKER_EXECUTION_CPU_SECONDS: u64 = 8;
/// The hard `RLIMIT_CPU`: no parser test costs more CPU than this.
pub const WORKER_CPU_CEILING_SECONDS: u64 = WORKER_COMPILE_CPU_SECONDS + WORKER_EXECUTION_CPU_SECONDS + 1;
pub const WORKER_WALL_SECONDS: u64 = 28;

/// The parser-test worker's OS bounds (interactive tests).
pub const LIMITS: WorkerLimits = WorkerLimits {
    private_memory_bytes: WORKER_PRIVATE_MEMORY_BYTES,
    address_space_bytes: WORKER_ADDRESS_SPACE_BYTES,
    cpu_seconds: WORKER_COMPILE_CPU_SECONDS,
    cpu_ceiling_seconds: WORKER_CPU_CEILING_SECONDS,
    wall: Duration::from_secs(WORKER_WALL_SECONDS),
    max_output_bytes: MAX_RESPONSE_BYTES,
};

/// The second worker argument that selects the deploy gate budget.
pub const DEPLOY_GATE_ARGUMENT: &str = "--deploy-gate";
/// Deploy gate: CPU for start-up, decoding and compiling (NAN-5406).
pub const DEPLOY_GATE_COMPILE_CPU_SECONDS: u64 = 45;
/// Deploy gate: the hard `RLIMIT_CPU`.
pub const DEPLOY_GATE_CPU_CEILING_SECONDS: u64 =
    DEPLOY_GATE_COMPILE_CPU_SECONDS + WORKER_EXECUTION_CPU_SECONDS + 1;
pub const DEPLOY_GATE_WALL_SECONDS: u64 = 60;
/// How long the deploy gate waits for a worker slot. A deploy is an explicit,
/// privileged action: it waits for a slot instead of being refused because
/// someone is testing a parser. A slot frees within one interactive wall
/// clock unless the replica is genuinely saturated; only then is it a 429.
pub const DEPLOY_GATE_ADMISSION_WAIT: Duration = Duration::from_secs(60);

/// The deploy gate's OS bounds: the interactive memory bounds, more CPU and
/// wall clock (see the module docs).
pub const DEPLOY_GATE_LIMITS: WorkerLimits = WorkerLimits {
    cpu_seconds: DEPLOY_GATE_COMPILE_CPU_SECONDS,
    cpu_ceiling_seconds: DEPLOY_GATE_CPU_CEILING_SECONDS,
    wall: Duration::from_secs(DEPLOY_GATE_WALL_SECONDS),
    ..LIMITS
};

/// Which bounds a parser test runs under (NAN-5406).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Budget {
    /// Editor, test-vrl, test-live, AI loops: behind a 30 s upstream deadline.
    #[default]
    Interactive,
    /// The OCSF sample gate before a publish or deploy goes live.
    DeployGate,
}

impl Budget {
    pub const fn limits(self) -> &'static WorkerLimits {
        match self {
            Self::Interactive => &LIMITS,
            Self::DeployGate => &DEPLOY_GATE_LIMITS,
        }
    }

    /// The worker command line after the executable.
    pub const fn worker_args(self) -> &'static [&'static str] {
        match self {
            Self::Interactive => &[WORKER_ARGUMENT],
            Self::DeployGate => &[WORKER_ARGUMENT, DEPLOY_GATE_ARGUMENT],
        }
    }

    /// How long a job without an enclosing admission waits for a slot.
    pub const fn admission_wait(self) -> Duration {
        match self {
            Self::Interactive => ADMISSION_WAIT,
            Self::DeployGate => DEPLOY_GATE_ADMISSION_WAIT,
        }
    }

    /// The budget a worker was started with, from its arguments (after the
    /// executable). Anything else is the interactive budget, the smaller one.
    pub fn from_worker_args<S: AsRef<str>>(args: &[S]) -> Self {
        match args {
            [first, second, ..]
                if first.as_ref() == WORKER_ARGUMENT && second.as_ref() == DEPLOY_GATE_ARGUMENT =>
            {
                Self::DeployGate
            }
            _ => Self::Interactive,
        }
    }
}

/// One parser test: what to run, against which function registry.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ParserTestJob {
    pub registry: VrlRegistry,
    pub work: Work,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum Work {
    /// One program over each input independently (`test_vrl`,
    /// `test_vrl_batch`). `code` is the stored source: the worker resolves a
    /// stored Nano Pipe plan to its program, as validation does.
    Each { code: String, inputs: Vec<Value> },
    /// Programs in sequence over one input (`test_vrl_chain`); each stage
    /// carries its caller-facing index for error messages.
    Chain {
        stages: Vec<(usize, String)>,
        input: Value,
    },
    /// NAN-5400: [`super::VrlValidator::validate_vrl`] of one stored source
    /// (every gate, the compile and its warnings), for the validate endpoint.
    Validate { code: String },
    /// A processing plan with native steps, plus an optional extension.
    Native {
        plan: crate::parsers::pipe::Plan,
        extension: Option<String>,
        inputs: Vec<Value>,
    },
}

/// One native-plan row.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct NativeRow {
    pub outputs: Vec<Value>,
    pub error: Option<String>,
}

/// What a job produced. `Err` strings are user-facing (compile or runtime
/// errors, the time budget).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum Outcome {
    /// Outer `Err`: the program did not compile. Inner: one result per input.
    Each(Result<Vec<Result<Value, String>>, String>),
    Chain(Result<Value, String>),
    Native(Result<Vec<NativeRow>, String>),
    /// A validation verdict; an error validating reads as an invalid result
    /// carrying that error.
    Validate(super::VrlValidationResult),
}

impl ParserTestJob {
    fn inputs(&self) -> usize {
        match &self.work {
            Work::Each { inputs, .. } | Work::Native { inputs, .. } => inputs.len(),
            Work::Chain { .. } | Work::Validate { .. } => 1,
        }
    }

    /// Shape bounds (sizes are bounded by [`MAX_REQUEST_BYTES`]).
    pub fn validate(&self) -> Result<(), String> {
        let inputs = self.inputs();
        if inputs == 0 || inputs > exec_bounds::MAX_TEST_SAMPLES {
            return Err(format!(
                "A parser test takes 1–{} sample events",
                exec_bounds::MAX_TEST_SAMPLES
            ));
        }
        if let Work::Chain { stages, .. } = &self.work {
            if stages.is_empty() || stages.len() > MAX_STAGES {
                return Err(format!("A chained parser test takes 1–{MAX_STAGES} programs"));
            }
        }
        Ok(())
    }

    /// The outcome has exactly the shape this job asks for.
    fn matches(&self, outcome: &Outcome) -> bool {
        match (&self.work, outcome) {
            (Work::Each { inputs, .. }, Outcome::Each(Ok(rows))) => rows.len() == inputs.len(),
            (Work::Each { .. }, Outcome::Each(Err(_))) | (Work::Chain { .. }, Outcome::Chain(_)) => true,
            (Work::Native { inputs, .. }, Outcome::Native(Ok(rows))) => rows.len() == inputs.len(),
            (Work::Native { .. }, Outcome::Native(Err(_))) => true,
            (Work::Validate { .. }, Outcome::Validate(_)) => true,
            _ => false,
        }
    }
}

/// Why a parser test produced no outcome.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ParserTestSandboxError {
    #[error("Parser test capacity is busy; retry shortly")]
    Busy,
    /// The wall clock, in seconds, that ran out.
    #[error("Parser test exceeded its {0}s deadline; reduce the sample or simplify the program")]
    Deadline(u64),
    #[error("Parser test exceeded its memory or CPU bound; reduce the sample or simplify the program")]
    ResourceLimit,
    #[error("Parser test output exceeded {} MiB", MAX_RESPONSE_BYTES / (1024 * 1024))]
    OutputLimit,
    #[error("Invalid parser test worker response")]
    Protocol,
    #[error("Parser test isolation is unavailable in this process (no worker executable registered)")]
    Unavailable,
    /// The request is malformed or too large (a 400, with the reason).
    #[error("{0}")]
    Invalid(String),
}

impl ParserTestSandboxError {
    /// A bound the PROGRAM hit: reported as that test's failure, not as a
    /// service error.
    pub fn is_execution_bound(&self) -> bool {
        matches!(self, Self::Deadline(_) | Self::ResourceLimit | Self::OutputLimit)
    }

    /// A worker failure under `limits`.
    pub fn from_failure(failure: WorkerFailure, limits: &WorkerLimits) -> Self {
        match failure {
            WorkerFailure::Deadline => Self::Deadline(limits.wall.as_secs()),
            WorkerFailure::OutputLimit => Self::OutputLimit,
            WorkerFailure::Worker => Self::ResourceLimit,
            WorkerFailure::Unavailable => Self::Unavailable,
        }
    }
}

impl From<ParserTestSandboxError> for VrlValidatorError {
    fn from(error: ParserTestSandboxError) -> Self {
        match error {
            ParserTestSandboxError::Busy => Self::Busy(error.to_string()),
            ParserTestSandboxError::Invalid(message) => Self::InvalidInput(message),
            other => Self::ExecutionError(other.to_string()),
        }
    }
}

static WORKER_EXECUTABLE: OnceLock<PathBuf> = OnceLock::new();
static IN_PROCESS_FOR_TEST_HARNESS: AtomicBool = AtomicBool::new(false);

/// Record that this process's own executable serves [`WORKER_ARGUMENT`].
/// Call from `main` of every binary that dispatches the worker, after the
/// dispatch.
pub fn register_current_executable() {
    if let Ok(executable) = std::env::current_exe() {
        register_worker_executable(executable);
    }
}

/// Record the executable that serves [`WORKER_ARGUMENT`] (integration tests
/// pass the built API binary). The first registration wins.
pub fn register_worker_executable(executable: PathBuf) {
    let _ = WORKER_EXECUTABLE.set(executable);
}

/// Let a library test harness with no worker executable run parser tests
/// in-process. Never call this from a service binary.
#[doc(hidden)]
pub fn permit_in_process_for_test_harness() {
    IN_PROCESS_FOR_TEST_HARNESS.store(true, Ordering::SeqCst);
}

/// How [`run`] executes a job in this process.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Executor {
    Worker(PathBuf),
    InProcessTestHarness,
    Unavailable,
}

/// The executor decision: a registered worker always wins; in-process only
/// for an explicitly permitted test harness; otherwise fail closed.
pub fn choose_executor(registered: Option<&Path>, in_process_permitted: bool) -> Executor {
    match registered {
        Some(path) => Executor::Worker(path.to_path_buf()),
        None if in_process_permitted => Executor::InProcessTestHarness,
        None => Executor::Unavailable,
    }
}

fn current_executor() -> Executor {
    choose_executor(
        WORKER_EXECUTABLE.get().map(PathBuf::as_path),
        cfg!(test) || IN_PROCESS_FOR_TEST_HARNESS.load(Ordering::SeqCst),
    )
}

/// Retry-After for a refused parser test (seconds).
pub const RETRY_AFTER_SECONDS: u64 = 1;

/// How many parser-test workers this replica runs at once.
pub fn worker_count() -> usize {
    worker_process::clamp_concurrency(
        std::env::var(WORKERS_ENV).ok().as_deref(),
        DEFAULT_WORKERS,
        MAX_WORKERS,
    )
}

/// The most of `workers` one principal may hold: half, at least one. Below
/// the total whenever there are two or more.
pub const fn per_principal_workers(workers: usize) -> usize {
    if workers < 2 {
        1
    } else {
        workers / 2
    }
}

/// The replica's one parser-test admission gate.
fn gate() -> &'static PrincipalGate {
    static GATE: OnceLock<PrincipalGate> = OnceLock::new();
    GATE.get_or_init(|| {
        let workers = worker_count();
        PrincipalGate::new(
            "Parser test",
            per_principal_workers(workers),
            workers,
            RETRY_AFTER_SECONDS,
        )
    })
}

/// Admit one parser-test request for `principal` (`user:<id>` /
/// `api_key:<id>`, see the API's `principal_key`), waiting up to
/// [`ADMISSION_WAIT`]. `None` is an internal caller: only the replica-wide
/// limit applies. Hold the permit for the whole request and run the request
/// inside [`admitted`].
pub async fn admit(principal: Option<&str>) -> Result<GatePermit, GateRefused> {
    admit_waiting(principal, ADMISSION_WAIT).await
}

/// [`admit`], waiting up to `wait` for a slot.
pub async fn admit_waiting(principal: Option<&str>, wait: Duration) -> Result<GatePermit, GateRefused> {
    let internal;
    let key = match principal {
        Some(principal) => principal,
        None => {
            internal = format!("internal:{}", uuid::Uuid::new_v4());
            internal.as_str()
        }
    };
    let deadline = tokio::time::Instant::now() + wait;
    loop {
        match gate().try_acquire(key) {
            Ok(permit) => return Ok(permit),
            Err(refused) if tokio::time::Instant::now() >= deadline => return Err(refused),
            Err(_) => tokio::time::sleep(Duration::from_millis(20)).await,
        }
    }
}

tokio::task_local! {
    /// Set by [`admitted`]: this task already holds an admission; its worker
    /// jobs take turns on this lock instead of taking more slots.
    static ADMITTED: std::sync::Arc<tokio::sync::Mutex<()>>;
}

/// Run `work` under an admission the caller holds (from [`admit`]). Every
/// parser test inside runs in that one slot, one at a time.
pub async fn admitted<F: std::future::Future>(work: F) -> F::Output {
    ADMITTED
        .scope(std::sync::Arc::new(tokio::sync::Mutex::new(())), work)
        .await
}

/// The admission one worker job runs under.
enum JobAdmission {
    /// This job's own slot (an internal caller).
    Own(#[allow(dead_code)] GatePermit),
    /// A turn in the enclosing request's slot.
    Turn(#[allow(dead_code)] tokio::sync::OwnedMutexGuard<()>),
}

async fn admit_job(budget: Budget) -> Result<JobAdmission, ParserTestSandboxError> {
    if let Ok(turns) = ADMITTED.try_with(std::sync::Arc::clone) {
        return Ok(JobAdmission::Turn(turns.lock_owned().await));
    }
    admit_waiting(None, budget.admission_wait())
        .await
        .map(JobAdmission::Own)
        .map_err(|_| ParserTestSandboxError::Busy)
}

/// Run one parser test in a worker process of the registered executable.
pub async fn run(job: &ParserTestJob) -> Result<Outcome, ParserTestSandboxError> {
    run_under(job, Budget::Interactive).await
}

/// [`run`] under `budget`.
pub async fn run_under(job: &ParserTestJob, budget: Budget) -> Result<Outcome, ParserTestSandboxError> {
    match current_executor() {
        Executor::Worker(executable) => {
            run_with_executable_under(job, &executable, budget.worker_args(), budget).await
        }
        Executor::InProcessTestHarness => run_in_process(job.clone()).await,
        Executor::Unavailable => {
            tracing::error!(
                "parser test refused: this process has no parser-test worker executable \
                 (its main must dispatch {WORKER_ARGUMENT} and register itself)"
            );
            Err(ParserTestSandboxError::Unavailable)
        }
    }
}

/// [`execute`] on this process's blocking pool. Only for code that is
/// already inside a worker (previews) or a permitted test harness.
pub(crate) async fn run_in_process(job: ParserTestJob) -> Result<Outcome, ParserTestSandboxError> {
    job.validate().map_err(ParserTestSandboxError::Invalid)?;
    tokio::task::spawn_blocking(move || {
        tracing::subscriber::with_default(tracing::subscriber::NoSubscriber::default(), || {
            execute(&job)
        })
    })
    .await
    .map_err(|_| ParserTestSandboxError::ResourceLimit)
}

/// Serialize `job` as the worker request, enforcing [`MAX_REQUEST_BYTES`].
pub fn encode_request(job: &ParserTestJob) -> Result<Vec<u8>, ParserTestSandboxError> {
    job.validate().map_err(ParserTestSandboxError::Invalid)?;
    let input = serde_json::to_vec(job).map_err(|_| ParserTestSandboxError::Protocol)?;
    if input.len() > MAX_REQUEST_BYTES {
        return Err(ParserTestSandboxError::Invalid(format!(
            "A parser test request is at most {} MiB (got {} bytes)",
            MAX_REQUEST_BYTES / (1024 * 1024),
            input.len()
        )));
    }
    Ok(input)
}

/// The worker's wire envelope.
#[derive(Debug, Serialize, Deserialize)]
pub enum WorkerReply {
    Done(Outcome),
    Invalid(String),
    OutputTooLarge,
}

/// Decode a worker reply for `job`.
pub fn decode_reply(job: &ParserTestJob, output: &[u8]) -> Result<Outcome, ParserTestSandboxError> {
    match serde_json::from_slice::<WorkerReply>(output).map_err(|_| ParserTestSandboxError::Protocol)? {
        WorkerReply::Done(outcome) if job.matches(&outcome) => Ok(outcome),
        WorkerReply::Done(_) => Err(ParserTestSandboxError::Protocol),
        WorkerReply::Invalid(message) => Err(ParserTestSandboxError::Invalid(message)),
        WorkerReply::OutputTooLarge => Err(ParserTestSandboxError::OutputLimit),
    }
}

/// [`run`] against an explicit worker command (tests).
pub async fn run_with_executable(
    job: &ParserTestJob,
    executable: &Path,
    args: &[&str],
) -> Result<Outcome, ParserTestSandboxError> {
    run_with_executable_under(job, executable, args, Budget::Interactive).await
}

/// [`run_with_executable`] under `budget`'s bounds and admission wait. `args`
/// must select the same budget in the worker ([`Budget::worker_args`]).
pub async fn run_with_executable_under(
    job: &ParserTestJob,
    executable: &Path,
    args: &[&str],
    budget: Budget,
) -> Result<Outcome, ParserTestSandboxError> {
    let input = encode_request(job)?;
    let _admission = admit_job(budget).await?;
    let mut command = Command::new(executable);
    command.args(args);
    let limits = budget.limits();
    let output = worker_process::exchange(command, &input, limits, "parser_test")
        .await
        .map_err(|failure| ParserTestSandboxError::from_failure(failure, limits))?;
    decode_reply(job, &output)
}

/// Compile one stored source the way [`super::VrlValidator::validate_vrl`]
/// would (NAN-5396: the parser-test path never compiles tenant VRL in the API
/// process; this is its only compile). A stored stateless Nano Pipe plan
/// compiles to its program with event metadata read-only (NAN-4919). Returns
/// the text that runs, for runtime error spans. Errors are the validation
/// diagnostics, joined.
fn compile(registry: VrlRegistry, code: &str) -> Result<(String, vrl::compiler::Program), String> {
    use super::validator::PlanSource;
    #[cfg(test)]
    compile_counter::record(code);
    // NAN-5400: the API does not validate a stored plan at all (its checks
    // compile advanced VRL steps); validate it in full here first.
    if code.starts_with(super::pipe::HEADER) {
        let verdict = futures::executor::block_on(
            super::VrlValidator::for_registry(registry).inside_worker().validate_vrl(code),
        )
        .map_err(|error| error.to_string())?;
        if !verdict.valid {
            return Err(verdict.error.unwrap_or_else(|| "Invalid processing plan".into()));
        }
    }
    let functions = registry.functions();
    match super::validator::resolve_plan(code) {
        PlanSource::Plain => super::vrl_guard::compile_formatted(code, &functions)
            .map(|compiled| (code.to_string(), compiled.program))
            .map_err(|errors| errors.join("\n")),
        PlanSource::Program(program) => {
            match super::vrl_guard::compile_metadata_read_only(&program, &functions) {
                Ok(compiled) => Ok((program, compiled.program)),
                Err(error) => Err(error.messages(&program).join("\n")),
            }
        }
        PlanSource::Invalid(message) => Err(message),
        PlanSource::Native(_) => {
            Err("A processing plan with native steps runs as a native batch test".into())
        }
    }
}

/// Execute `job` in the calling process under one [`TEST_EXECUTION_BUDGET`].
/// The pure engine: the worker calls it, and so do unit tests of the VRL
/// logic. Service code reaches it only through [`run`].
pub fn execute(job: &ParserTestJob) -> Outcome {
    execute_phased(job, || {})
}

/// [`execute`], calling `on_compiled` once every program has compiled and before
/// any sample runs (the worker moves its CPU bound there). A Native plan
/// compiles its extension inside the bounded batch runner, so its hook runs
/// before the runner and that compile counts as execution.
pub fn execute_phased(job: &ParserTestJob, on_compiled: impl FnOnce()) -> Outcome {
    match &job.work {
        // Compile only: nothing runs after it, so the compile-phase CPU limit
        // is the whole bound.
        Work::Validate { code } => {
            let validator = super::VrlValidator::for_registry(job.registry).inside_worker();
            Outcome::Validate(
                futures::executor::block_on(validator.validate_vrl(code)).unwrap_or_else(|error| {
                    super::VrlValidationResult {
                        valid: false,
                        error: Some(error.to_string()),
                        warnings: Vec::new(),
                    }
                }),
            )
        }
        Work::Each { code, inputs } => Outcome::Each(compile(job.registry, code).map(|(code, program)| {
            on_compiled();
            let mut budget = ExecutionBudget::new(TEST_EXECUTION_BUDGET);
            inputs
                .iter()
                .map(|input| exec_bounds::run_program(&code, &program, input, &mut budget))
                .collect()
        })),
        Work::Chain { stages, input } => {
            let mut compiled = Vec::with_capacity(stages.len());
            for (index, code) in stages {
                match compile(job.registry, code) {
                    Ok((code, program)) => compiled.push((*index, code, program)),
                    // Reads as the per-stage validation error it replaces.
                    Err(error) => return Outcome::Chain(Err(format!("stage {index}: {error}"))),
                }
            }
            on_compiled();
            let mut budget = ExecutionBudget::new(TEST_EXECUTION_BUDGET);
            let mut current = input.clone();
            for (index, code, program) in &compiled {
                match exec_bounds::run_program(code, program, &current, &mut budget) {
                    Ok(output) => current = output,
                    Err(error) => {
                        return Outcome::Chain(Err(format!("stage {index}: execution error: {error}")))
                    }
                }
            }
            Outcome::Chain(Ok(current))
        }
        Work::Native {
            plan,
            extension,
            inputs,
        } => Outcome::Native({
            // NAN-5400: the API parsed only this plan's shape.
            let validator = super::VrlValidator::for_registry(job.registry).inside_worker();
            if let Err(error) = futures::executor::block_on(
                validator.validate_native_test(plan, extension.as_deref()),
            ) {
                return Outcome::Native(Err(error));
            }
            on_compiled();
            crate::parsers::pipe::batch::run_bounded(
                plan,
                inputs,
                extension.as_deref(),
                ExecutionBudget::new(TEST_EXECUTION_BUDGET),
            )
            .map(|rows| {
                rows.into_iter()
                    .map(|row| NativeRow {
                        outputs: row.outputs,
                        error: row.error,
                    })
                    .collect()
            })
        }),
    }
}

/// NAN-5406: how many times the test engine compiled a given source, so a
/// test can prove the deploy gate compiles each stage once, not per sample.
#[cfg(test)]
pub(crate) mod compile_counter {
    use std::collections::HashMap;
    use std::sync::Mutex;

    static COMPILES: Mutex<Option<HashMap<String, usize>>> = Mutex::new(None);

    pub(crate) fn record(code: &str) {
        let mut compiles = COMPILES.lock().unwrap_or_else(|p| p.into_inner());
        *compiles.get_or_insert_with(HashMap::new).entry(code.to_string()).or_insert(0) += 1;
    }

    pub(crate) fn count(code: &str) -> usize {
        let compiles = COMPILES.lock().unwrap_or_else(|p| p.into_inner());
        compiles.as_ref().and_then(|map| map.get(code).copied()).unwrap_or(0)
    }
}

fn worker_reply(input: Vec<u8>, limits: &WorkerLimits) -> WorkerReply {
    let job = match serde_json::from_slice::<ParserTestJob>(&input) {
        Ok(job) => job,
        Err(_) => return WorkerReply::Invalid("Invalid parser test request".into()),
    };
    drop(input);
    if let Err(message) = job.validate() {
        return WorkerReply::Invalid(message);
    }
    // Once every program has compiled, the samples get
    // WORKER_EXECUTION_CPU_SECONDS on top of what start-up and compiling used,
    // under the fixed hard ceiling. If moving the limit fails, the
    // compile-phase soft limit stays in force, which is still a bound.
    WorkerReply::Done(execute_phased(&job, || {
        let _ = worker_process::extend_cpu_soft_limit(limits, WORKER_EXECUTION_CPU_SECONDS);
    }))
}

/// Entry point for `nanosiem-api --parser-test-worker [--deploy-gate]`. Call
/// from a synchronous `main` before anything else is initialized.
pub fn worker_main() -> Result<(), ParserTestSandboxError> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let limits = Budget::from_worker_args(&args).limits();
    worker_process::enter_worker(limits).map_err(|_| ParserTestSandboxError::Unavailable)?;
    let input = worker_process::read_bounded(io::stdin().lock(), MAX_REQUEST_BYTES)
        .ok_or(ParserTestSandboxError::Protocol)?;
    // Tested VRL output must never reach a log stream.
    let reply = std::thread::Builder::new()
        .name("parser-test".into())
        .stack_size(worker_process::WORKER_THREAD_STACK_BYTES)
        .spawn(move || {
            tracing::subscriber::with_default(tracing::subscriber::NoSubscriber::default(), || {
                worker_reply(input, limits)
            })
        })
        .map_err(|_| ParserTestSandboxError::Unavailable)?
        .join()
        .map_err(|_| ParserTestSandboxError::ResourceLimit)?;
    let mut output = serde_json::to_vec(&reply).map_err(|_| ParserTestSandboxError::Protocol)?;
    if output.len() > MAX_RESPONSE_BYTES {
        drop(reply);
        output = serde_json::to_vec(&WorkerReply::OutputTooLarge)
            .map_err(|_| ParserTestSandboxError::Protocol)?;
    }
    io::stdout()
        .lock()
        .write_all(&output)
        .map_err(|_| ParserTestSandboxError::ResourceLimit)
}

#[cfg(test)]
#[path = "test_sandbox_tests.rs"]
mod tests;
