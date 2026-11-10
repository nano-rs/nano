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
//! | `RLIMIT_CPU` | 8 s | the 5 s execution budget plus compiling a 1 MiB program |
//! | wall clock | 12 s | the CPU bound plus process start-up |
//! | request | 24 MiB | [`MAX_REQUEST_BYTES`] |
//! | response | 32 MiB | [`MAX_RESPONSE_BYTES`] |
//!
//! Admission: at most [`DEFAULT_WORKERS`] workers per replica
//! (`NANO_PARSER_TEST_WORKERS`, 1–8). A caller waits up to
//! [`ADMISSION_WAIT`] for a slot (parser tests take milliseconds), then is
//! refused ([`VrlValidatorError::Busy`], HTTP 429). Per-user fairness is the
//! HTTP layer's per-principal parser-test gate.
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
use super::worker_process::{self, WorkerFailure, WorkerGate, WorkerLimits};
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
pub const WORKER_CPU_SECONDS: u64 = 8;
pub const WORKER_WALL_SECONDS: u64 = 12;

/// The parser-test worker's OS bounds.
pub const LIMITS: WorkerLimits = WorkerLimits {
    private_memory_bytes: WORKER_PRIVATE_MEMORY_BYTES,
    address_space_bytes: WORKER_ADDRESS_SPACE_BYTES,
    cpu_seconds: WORKER_CPU_SECONDS,
    wall: Duration::from_secs(WORKER_WALL_SECONDS),
    max_output_bytes: MAX_RESPONSE_BYTES,
};

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
    /// `test_vrl_batch`).
    Each { code: String, inputs: Vec<Value> },
    /// Programs in sequence over one input (`test_vrl_chain`); each stage
    /// carries its caller-facing index for error messages.
    Chain {
        stages: Vec<(usize, String)>,
        input: Value,
    },
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
}

impl ParserTestJob {
    fn inputs(&self) -> usize {
        match &self.work {
            Work::Each { inputs, .. } | Work::Native { inputs, .. } => inputs.len(),
            Work::Chain { .. } => 1,
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
            _ => false,
        }
    }
}

/// Why a parser test produced no outcome.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ParserTestSandboxError {
    #[error("Parser test capacity is busy; retry shortly")]
    Busy,
    #[error("Parser test exceeded its {WORKER_WALL_SECONDS}s deadline; reduce the sample or simplify the program")]
    Deadline,
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
        matches!(self, Self::Deadline | Self::ResourceLimit | Self::OutputLimit)
    }
}

impl From<WorkerFailure> for ParserTestSandboxError {
    fn from(failure: WorkerFailure) -> Self {
        match failure {
            WorkerFailure::Deadline => Self::Deadline,
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

fn gate() -> &'static WorkerGate {
    static GATE: OnceLock<WorkerGate> = OnceLock::new();
    GATE.get_or_init(|| {
        WorkerGate::new(worker_process::clamp_concurrency(
            std::env::var(WORKERS_ENV).ok().as_deref(),
            DEFAULT_WORKERS,
            MAX_WORKERS,
        ))
    })
}

/// Run one parser test in a worker process of the registered executable.
pub async fn run(job: &ParserTestJob) -> Result<Outcome, ParserTestSandboxError> {
    match current_executor() {
        Executor::Worker(executable) => run_with_executable(job, &executable, &[WORKER_ARGUMENT]).await,
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
    let input = encode_request(job)?;
    let _admission = gate()
        .admit_within(None, ADMISSION_WAIT)
        .await
        .map_err(|_| ParserTestSandboxError::Busy)?;
    let mut command = Command::new(executable);
    command.args(args);
    let output = worker_process::exchange(command, &input, &LIMITS, "parser_test").await?;
    decode_reply(job, &output)
}

fn compile(registry: VrlRegistry, code: &str) -> Result<vrl::compiler::Program, String> {
    super::vrl_guard::compile_formatted(code, &registry.functions())
        .map(|compiled| compiled.program)
        .map_err(|errors| errors.join("\n"))
}

/// Execute `job` in the calling process under one [`TEST_EXECUTION_BUDGET`].
/// The pure engine: the worker calls it, and so do unit tests of the VRL
/// logic. Service code reaches it only through [`run`].
pub fn execute(job: &ParserTestJob) -> Outcome {
    match &job.work {
        Work::Each { code, inputs } => Outcome::Each(compile(job.registry, code).map(|program| {
            let mut budget = ExecutionBudget::new(TEST_EXECUTION_BUDGET);
            inputs
                .iter()
                .map(|input| exec_bounds::run_program(code, &program, input, &mut budget))
                .collect()
        })),
        Work::Chain { stages, input } => {
            let mut compiled = Vec::with_capacity(stages.len());
            for (index, code) in stages {
                match compile(job.registry, code) {
                    Ok(program) => compiled.push((*index, code, program)),
                    Err(error) => {
                        return Outcome::Chain(Err(format!("stage {index}: execution error: {error}")))
                    }
                }
            }
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
        } => Outcome::Native(
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
            }),
        ),
    }
}

fn worker_reply(input: Vec<u8>) -> WorkerReply {
    let job = match serde_json::from_slice::<ParserTestJob>(&input) {
        Ok(job) => job,
        Err(_) => return WorkerReply::Invalid("Invalid parser test request".into()),
    };
    drop(input);
    if let Err(message) = job.validate() {
        return WorkerReply::Invalid(message);
    }
    WorkerReply::Done(execute(&job))
}

/// Entry point for `nanosiem-api --parser-test-worker`. Call from a
/// synchronous `main` before anything else is initialized.
pub fn worker_main() -> Result<(), ParserTestSandboxError> {
    worker_process::enter_worker(&LIMITS).map_err(|_| ParserTestSandboxError::Unavailable)?;
    let input = worker_process::read_bounded(io::stdin().lock(), MAX_REQUEST_BYTES)
        .ok_or(ParserTestSandboxError::Protocol)?;
    // Tested VRL output must never reach a log stream.
    let reply = std::thread::Builder::new()
        .name("parser-test".into())
        .stack_size(worker_process::WORKER_THREAD_STACK_BYTES)
        .spawn(move || {
            tracing::subscriber::with_default(tracing::subscriber::NoSubscriber::default(), || {
                worker_reply(input)
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
