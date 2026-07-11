// SPDX-License-Identifier: AGPL-3.0-or-later

//! Process shutdown signal handling shared by service binaries.

use std::fmt;
use std::future::{Future, IntoFuture};
use std::io;
use tokio_util::sync::CancellationToken;

/// Cloneable cooperative-cancellation signal for service-owned tasks.
#[derive(Clone, Debug, Default)]
pub struct ShutdownToken(CancellationToken);

impl ShutdownToken {
    pub fn new() -> Self {
        Self(CancellationToken::new())
    }

    pub fn cancel(&self) {
        self.0.cancel();
    }

    pub fn is_cancelled(&self) -> bool {
        self.0.is_cancelled()
    }

    pub async fn cancelled(&self) {
        self.0.cancelled().await;
    }

    /// Poll work only while shutdown has not been requested.
    ///
    /// The biased branch ensures an already-visible shutdown wins before a new
    /// claim or poll future is first polled.
    pub async fn run_until_cancelled<F>(&self, future: F) -> Option<F::Output>
    where
        F: Future,
    {
        tokio::select! {
            biased;
            _ = self.cancelled() => None,
            output = future => Some(output),
        }
    }
}

/// Operating-system signal that requested process shutdown.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShutdownSignal {
    Interrupt,
    Terminate,
}

impl fmt::Display for ShutdownSignal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Interrupt => "SIGINT",
            Self::Terminate => "SIGTERM",
        })
    }
}

#[cfg(unix)]
async fn select_shutdown_signal<I, T>(interrupt: I, terminate: T) -> io::Result<ShutdownSignal>
where
    I: Future<Output = io::Result<()>>,
    T: Future<Output = io::Result<()>>,
{
    tokio::select! {
        result = interrupt => {
            result?;
            Ok(ShutdownSignal::Interrupt)
        }
        result = terminate => {
            result?;
            Ok(ShutdownSignal::Terminate)
        }
    }
}

/// Wait for the platform shutdown signal.
///
/// Unix services handle both SIGINT (interactive shutdown) and SIGTERM
/// (Kubernetes/container shutdown). Other platforms use Tokio's Ctrl-C handler.
#[cfg(unix)]
pub async fn wait_for_shutdown_signal() -> io::Result<ShutdownSignal> {
    use tokio::signal::unix::{signal, SignalKind};

    let mut interrupt = signal(SignalKind::interrupt())?;
    let mut terminate = signal(SignalKind::terminate())?;

    select_shutdown_signal(
        async move {
            interrupt
                .recv()
                .await
                .map(|_| ())
                .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "SIGINT signal stream closed"))
        },
        async move {
            terminate
                .recv()
                .await
                .map(|_| ())
                .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "SIGTERM signal stream closed"))
        },
    )
    .await
}

/// Wait for an interactive shutdown request on non-Unix platforms.
#[cfg(not(unix))]
pub async fn wait_for_shutdown_signal() -> io::Result<ShutdownSignal> {
    tokio::signal::ctrl_c().await?;
    Ok(ShutdownSignal::Interrupt)
}

/// Run a server until it exits or shutdown is requested, always running cleanup.
///
/// When shutdown wins, `server_shutdown` is cancelled before cleanup is polled.
/// Axum can therefore stop accepting new connections immediately while service
/// tasks drain concurrently.
pub async fn run_server_with_shutdown<S, W, C>(
    server: S,
    server_shutdown: ShutdownToken,
    wait_for_shutdown: W,
    cleanup: C,
) -> S::Output
where
    S: IntoFuture,
    W: Future<Output = ()>,
    C: Future<Output = ()>,
{
    let server = server.into_future();
    tokio::pin!(server);
    tokio::pin!(wait_for_shutdown);

    tokio::select! {
        output = &mut server => {
            server_shutdown.cancel();
            cleanup.await;
            output
        }
        _ = &mut wait_for_shutdown => {
            server_shutdown.cancel();
            let (output, ()) = tokio::join!(&mut server, cleanup);
            output
        }
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::future::{pending, ready};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

    #[tokio::test]
    async fn selects_interrupt() {
        let selected = select_shutdown_signal(ready(Ok(())), pending::<io::Result<()>>())
            .await
            .unwrap();

        assert_eq!(selected, ShutdownSignal::Interrupt);
    }

    #[tokio::test]
    async fn selects_terminate() {
        let selected = select_shutdown_signal(pending::<io::Result<()>>(), ready(Ok(())))
            .await
            .unwrap();

        assert_eq!(selected, ShutdownSignal::Terminate);
    }

    #[tokio::test]
    async fn propagates_signal_errors() {
        let selected = select_shutdown_signal(
            ready(Err(io::Error::new(
                io::ErrorKind::Other,
                "registration failed",
            ))),
            pending::<io::Result<()>>(),
        )
        .await;

        assert_eq!(selected.unwrap_err().to_string(), "registration failed");
    }

    #[tokio::test]
    async fn visible_cancellation_prevents_work_from_being_polled() {
        let shutdown = ShutdownToken::new();
        let work_polled = Arc::new(AtomicBool::new(false));
        let future_polled = Arc::clone(&work_polled);
        shutdown.cancel();

        let result = shutdown
            .run_until_cancelled(async move {
                future_polled.store(true, Ordering::SeqCst);
                pending::<()>().await;
            })
            .await;

        assert!(result.is_none());
        assert!(!work_polled.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn server_shutdown_is_visible_before_cleanup_completes() {
        let server_shutdown = ShutdownToken::new();
        let server_token = server_shutdown.clone();
        let cleanup_token = server_shutdown.clone();
        let server_saw_shutdown = Arc::new(AtomicBool::new(false));
        let cleanup_started = Arc::new(AtomicBool::new(false));
        let finish_server = Arc::new(tokio::sync::Semaphore::new(0));

        let server_saw = Arc::clone(&server_saw_shutdown);
        let server_finish = Arc::clone(&finish_server);
        let server = async move {
            server_token.cancelled().await;
            server_saw.store(true, Ordering::SeqCst);
            let permit = server_finish.acquire().await.unwrap();
            permit.forget();
            42
        };

        let cleanup_flag = Arc::clone(&cleanup_started);
        let cleanup_finish = Arc::clone(&finish_server);
        let cleanup = async move {
            assert!(cleanup_token.is_cancelled());
            cleanup_flag.store(true, Ordering::SeqCst);
            cleanup_finish.add_permits(1);
        };

        let output = run_server_with_shutdown(server, server_shutdown, ready(()), cleanup).await;

        assert_eq!(output, 42);
        assert!(server_saw_shutdown.load(Ordering::SeqCst));
        assert!(cleanup_started.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn cleanup_runs_when_server_exits_without_a_signal() {
        let server_shutdown = ShutdownToken::new();
        let cleanup_ran = Arc::new(AtomicBool::new(false));
        let cleanup_flag = Arc::clone(&cleanup_ran);

        let output = run_server_with_shutdown(
            ready(7),
            server_shutdown.clone(),
            pending::<()>(),
            async move {
                cleanup_flag.store(true, Ordering::SeqCst);
            },
        )
        .await;

        assert_eq!(output, 7);
        assert!(server_shutdown.is_cancelled());
        assert!(cleanup_ran.load(Ordering::SeqCst));
    }
}
