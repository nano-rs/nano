// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-3080: process-level supervision now that release panics unwind.
//!
//! Under `panic = "abort"` a panicking background loop killed the process and
//! Kubernetes restarted it. Under `panic = "unwind"` the same panic ends only
//! that task: the pod stays Ready with, say, no detection scheduler. This
//! module restores "a dead loop is a dead process" for long-running tasks,
//! while per-execution tasks keep their deliberate isolation (they are never
//! supervised here; they surface as `JoinError` to their own caller).
//!
//! * [`install_panic_hook`]: every panic is logged through `tracing` (thread,
//!   location, message) and counted in `nano_panics_total{thread}`, then the
//!   previous hook runs (stderr stays as before).
//! * [`supervise`]: wraps a spawned long-running task. If it panics, or
//!   returns while the process is not shutting down, the error is logged and
//!   the injected exit fn is called with [`BACKGROUND_TASK_EXIT_CODE`].

use std::sync::Arc;
use std::time::Duration;

use crate::shutdown::ShutdownToken;

/// Exit status when a supervised background task dies (EX_SOFTWARE).
pub const BACKGROUND_TASK_EXIT_CODE: i32 = 70;

/// After a clean return, how long to wait for a shutdown that may already be
/// under way (a loop can observe its own stop signal slightly before the
/// registry's) before treating the return as fatal.
pub const RETURN_SHUTDOWN_GRACE: Duration = Duration::from_secs(5);

/// How the process leaves when a supervised task dies. Injectable for tests.
pub type ExitFn = Arc<dyn Fn(i32) + Send + Sync>;

/// Park a long-running task that has nothing to do in this deployment (its
/// feature is disabled, its tables are absent) until process shutdown.
///
/// NAN-3376: supervised loops run under [`TaskPolicy::Loop`], where a clean
/// return outside shutdown is fatal. A loop that decides at startup it has no
/// work must therefore wait for shutdown rather than return, or the process
/// exits with [`BACKGROUND_TASK_EXIT_CODE`] every few seconds. Genuine exits
/// still return and still trip the supervisor.
pub async fn park_until_shutdown(task: &'static str, reason: &str, shutdown: &ShutdownToken) {
    tracing::info!(
        task,
        reason,
        "background task disabled; parked until shutdown"
    );
    shutdown.cancelled().await;
}

/// The production exit: `std::process::exit` (k8s restarts the pod).
pub fn process_exit() -> ExitFn {
    Arc::new(|code| std::process::exit(code))
}

/// What a supervised task finishing (outside shutdown) means.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaskPolicy {
    /// A long-running loop: a panic OR a return is fatal (the default).
    Loop,
    /// A task that may legitimately finish (a one-shot sync, a loop that
    /// returns when its feature is disabled): only a panic is fatal.
    MayComplete,
}

/// How a supervised task ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TaskEnd {
    Returned,
    Panicked(String),
    Cancelled,
}

impl TaskEnd {
    pub fn from_join(result: Result<(), tokio::task::JoinError>) -> Self {
        match result {
            Ok(()) => Self::Returned,
            Err(error) if error.is_cancelled() => Self::Cancelled,
            Err(error) => {
                let message = match error.try_into_panic() {
                    Ok(payload) => panic_message(payload.as_ref()),
                    Err(error) => error.to_string(),
                };
                Self::Panicked(message)
            }
        }
    }

    fn outcome(&self) -> &'static str {
        match self {
            Self::Returned => "returned",
            Self::Panicked(_) => "panicked",
            Self::Cancelled => "cancelled",
        }
    }
}

/// The decision for a task that ended; pure, so it is unit-testable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// Shutdown, or an allowed completion: nothing to do.
    Ignore,
    /// A clean return of a loop: fatal unless shutdown starts within the grace.
    ExitUnlessShuttingDown,
    /// A panic outside shutdown: fatal now.
    Exit,
}

pub fn verdict(end: &TaskEnd, policy: TaskPolicy, shutting_down: bool) -> Verdict {
    if shutting_down {
        return Verdict::Ignore;
    }
    match (end, policy) {
        (TaskEnd::Panicked(_), _) => Verdict::Exit,
        (TaskEnd::Returned | TaskEnd::Cancelled, TaskPolicy::Loop) => Verdict::ExitUnlessShuttingDown,
        (TaskEnd::Returned | TaskEnd::Cancelled, TaskPolicy::MayComplete) => Verdict::Ignore,
    }
}

/// Aborts the supervised task when the supervisor itself is aborted/dropped
/// (shutdown deadline, leadership loss), so no task outlives its handle.
struct AbortOnDrop(tokio::task::AbortHandle);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// Supervise an already spawned task. The returned handle completes when the
/// task does; aborting it aborts the task (and never triggers an exit).
pub fn supervise(
    name: &'static str,
    task: tokio::task::JoinHandle<()>,
    policy: TaskPolicy,
    shutdown: ShutdownToken,
    exit: ExitFn,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let _abort_task = AbortOnDrop(task.abort_handle());
        let end = TaskEnd::from_join(task.await);
        on_task_end(name, end, policy, &shutdown, &exit, RETURN_SHUTDOWN_GRACE).await;
    })
}

async fn on_task_end(
    name: &'static str,
    end: TaskEnd,
    policy: TaskPolicy,
    shutdown: &ShutdownToken,
    exit: &ExitFn,
    grace: Duration,
) {
    let verdict = verdict(&end, policy, shutdown.is_cancelled());
    if verdict == Verdict::Ignore {
        tracing::debug!(task = name, outcome = end.outcome(), "background task finished");
        return;
    }
    if verdict == Verdict::ExitUnlessShuttingDown
        && tokio::time::timeout(grace, shutdown.cancelled()).await.is_ok()
    {
        return;
    }
    metrics::counter!("nano_background_task_deaths_total", "task" => name, "outcome" => end.outcome())
        .increment(1);
    match &end {
        TaskEnd::Panicked(message) => tracing::error!(task = name, panic = %message,
            exit_code = BACKGROUND_TASK_EXIT_CODE,
            "background task panicked; exiting so the orchestrator restarts the process"),
        _ => tracing::error!(task = name, outcome = end.outcome(),
            exit_code = BACKGROUND_TASK_EXIT_CODE,
            "long-running background task stopped outside shutdown; exiting so the orchestrator restarts the process"),
    }
    exit(BACKGROUND_TASK_EXIT_CODE);
}

fn panic_message(payload: &(dyn std::any::Any + Send)) -> String {
    if let Some(message) = payload.downcast_ref::<&'static str>() {
        (*message).to_string()
    } else if let Some(message) = payload.downcast_ref::<String>() {
        message.clone()
    } else {
        "non-string panic payload".to_string()
    }
}

/// Log every panic through `tracing` and count it, then run the previous
/// hook. Idempotent (installs once per process).
pub fn install_panic_hook() {
    static INSTALLED: std::sync::Once = std::sync::Once::new();
    INSTALLED.call_once(|| {
        let previous = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            record_panic(info);
            previous(info);
        }));
    });
}

fn record_panic(info: &std::panic::PanicHookInfo<'_>) {
    let thread = std::thread::current();
    let thread = thread_label(thread.name());
    let location = info
        .location()
        .map(|l| format!("{}:{}:{}", l.file(), l.line(), l.column()))
        .unwrap_or_else(|| "unknown".to_string());
    let message = panic_message(info.payload());
    metrics::counter!("nano_panics_total", "thread" => thread.clone()).increment(1);
    tracing::error!(thread = %thread, location = %location, panic = %message, "panic");
}

/// Bounded thread label: tokio workers share one name; unnamed threads and
/// anything unexpected collapse so the metric cannot explode in cardinality.
fn thread_label(name: Option<&str>) -> String {
    match name {
        Some(name) if name.len() <= 48 && name.chars().all(|c| c.is_ascii_alphanumeric() || "-_.".contains(c)) => {
            name.to_string()
        }
        Some(_) => "other".to_string(),
        None => "unnamed".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicI32, Ordering};

    fn recording_exit() -> (ExitFn, Arc<AtomicI32>) {
        let code = Arc::new(AtomicI32::new(-1));
        let seen = Arc::clone(&code);
        (Arc::new(move |c| seen.store(c, Ordering::SeqCst)), code)
    }

    #[test]
    fn verdicts() {
        let panic = TaskEnd::Panicked("boom".into());
        assert_eq!(verdict(&panic, TaskPolicy::Loop, false), Verdict::Exit);
        assert_eq!(verdict(&panic, TaskPolicy::MayComplete, false), Verdict::Exit);
        assert_eq!(verdict(&panic, TaskPolicy::Loop, true), Verdict::Ignore);
        assert_eq!(verdict(&TaskEnd::Returned, TaskPolicy::Loop, false), Verdict::ExitUnlessShuttingDown);
        assert_eq!(verdict(&TaskEnd::Returned, TaskPolicy::MayComplete, false), Verdict::Ignore);
        assert_eq!(verdict(&TaskEnd::Returned, TaskPolicy::Loop, true), Verdict::Ignore);
    }

    #[tokio::test]
    async fn a_panicking_loop_takes_the_exit_path() {
        let (exit, code) = recording_exit();
        let task = tokio::spawn(async {
            if std::hint::black_box(true) {
                panic!("scheduler loop blew up");
            }
        });
        supervise("test_loop", task, TaskPolicy::Loop, ShutdownToken::new(), exit)
            .await
            .unwrap();
        assert_eq!(code.load(Ordering::SeqCst), BACKGROUND_TASK_EXIT_CODE);
    }

    #[tokio::test]
    async fn a_panicking_one_shot_is_also_fatal() {
        let (exit, code) = recording_exit();
        let task = tokio::spawn(async {
            if std::hint::black_box(true) {
                panic!("one-shot blew up");
            }
        });
        supervise("one_shot", task, TaskPolicy::MayComplete, ShutdownToken::new(), exit)
            .await
            .unwrap();
        assert_eq!(code.load(Ordering::SeqCst), BACKGROUND_TASK_EXIT_CODE);
    }

    #[tokio::test(start_paused = true)]
    async fn a_returning_loop_exits_after_the_grace_unless_shutdown_starts() {
        let (exit, code) = recording_exit();
        let shutdown = ShutdownToken::new();
        on_task_end("loop", TaskEnd::Returned, TaskPolicy::Loop, &shutdown, &exit, Duration::from_secs(5)).await;
        assert_eq!(code.load(Ordering::SeqCst), BACKGROUND_TASK_EXIT_CODE);

        let (exit, code) = recording_exit();
        let shutdown = ShutdownToken::new();
        let stopping = shutdown.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(1)).await;
            stopping.cancel();
        });
        on_task_end("loop", TaskEnd::Returned, TaskPolicy::Loop, &shutdown, &exit, Duration::from_secs(5)).await;
        assert_eq!(code.load(Ordering::SeqCst), -1, "shutdown within the grace is not fatal");
    }

    #[tokio::test]
    async fn completion_and_shutdown_are_not_fatal() {
        let (exit, code) = recording_exit();
        let task = tokio::spawn(async {});
        supervise("one_shot", task, TaskPolicy::MayComplete, ShutdownToken::new(), exit.clone())
            .await
            .unwrap();
        let shutdown = ShutdownToken::new();
        shutdown.cancel();
        let task = tokio::spawn(async {
            if std::hint::black_box(true) {
                panic!("during shutdown");
            }
        });
        supervise("loop", task, TaskPolicy::Loop, shutdown, exit).await.unwrap();
        assert_eq!(code.load(Ordering::SeqCst), -1);
    }

    #[tokio::test]
    async fn aborting_the_supervisor_aborts_the_task_without_exiting() {
        let (exit, code) = recording_exit();
        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        let task = tokio::spawn(async move {
            let _tx = tx; // dropped when the task is aborted
            std::future::pending::<()>().await;
        });
        let supervisor = supervise("loop", task, TaskPolicy::Loop, ShutdownToken::new(), exit);
        tokio::task::yield_now().await;
        supervisor.abort();
        assert!(supervisor.await.unwrap_err().is_cancelled());
        assert!(rx.await.is_err(), "the supervised task was aborted too");
        assert_eq!(code.load(Ordering::SeqCst), -1);
    }

    #[tokio::test(start_paused = true)]
    async fn a_parked_disabled_loop_never_takes_the_exit_path() {
        // NAN-3376: a disabled loop parks instead of returning, so a Loop
        // supervisor stays quiet well past the return grace and the task ends
        // only with shutdown.
        let (exit, code) = recording_exit();
        let shutdown = ShutdownToken::new();
        let parked = shutdown.clone();
        let task = tokio::spawn(async move {
            park_until_shutdown("test_disabled", "feature off", &parked).await;
        });
        let supervisor = supervise(
            "test_disabled",
            task,
            TaskPolicy::Loop,
            shutdown.clone(),
            exit,
        );
        tokio::time::sleep(RETURN_SHUTDOWN_GRACE * 4).await;
        assert!(!supervisor.is_finished(), "a parked task must stay running");
        assert_eq!(code.load(Ordering::SeqCst), -1);
        shutdown.cancel();
        supervisor.await.unwrap();
        assert_eq!(
            code.load(Ordering::SeqCst),
            -1,
            "ending on shutdown is not fatal"
        );
    }

    #[test]
    fn panic_hook_logs_and_keeps_the_previous_hook() {
        install_panic_hook();
        install_panic_hook(); // idempotent
        let caught = std::panic::catch_unwind(|| {
            if std::hint::black_box(true) {
                panic!("hooked");
            }
        });
        assert!(caught.is_err());
        assert_eq!(thread_label(Some("tokio-runtime-worker")), "tokio-runtime-worker");
        assert_eq!(thread_label(Some("weird name with spaces")), "other");
        assert_eq!(thread_label(None), "unnamed");
    }
}
