// SPDX-License-Identifier: AGPL-3.0-or-later
//! NAN-4798: idempotent agent-catalog control calls ride out network loss.
//!
//! A single dropped packet, or several minutes of lost connectivity to the
//! platform control/catalog endpoints, must not fail a writer sync that is
//! one call away from converging. Every call retried here is idempotent on
//! the platform side (re-closing an open fence, re-publishing the same
//! epoch, re-dropping a dropped table, expiring an expired table, checking a
//! fence, committing a manifest whose checkpoint already landed), so a retry
//! after a lost response is safe.
//!
//! Only transport failures are retried: connection reset/refused/aborted,
//! timeouts, broken pipes and gateway overload statuses. A platform refusal
//! (HTTP 403 `catalog_custody_refused`), a local invariant or a privacy check
//! is returned at once. On exhaustion the error is returned and the caller's
//! read fence stays closed: retrying never opens anything.
use anyhow::Result;
use std::{future::Future, time::Duration};

/// Bounded, jittered exponential backoff with a total deadline.
#[derive(Clone, Copy, Debug)]
pub(crate) struct RetryPolicy {
    /// No new attempt starts after this much time since the first one.
    pub deadline: Duration,
    /// First backoff.
    pub base: Duration,
    /// Largest single backoff.
    pub cap: Duration,
}

impl RetryPolicy {
    /// Dan (10-28): "single packet drops happen, 5 minute packet drops
    /// happen". 12 minutes rides out a 10-minute outage, with each backoff at
    /// most 45 s. That fits in the 30-minute sync hard bound. Past it, the
    /// durable serving state lets the next sync resume (never re-mint).
    pub(crate) const CONTROL: Self = Self {
        deadline: Duration::from_secs(12 * 60),
        base: Duration::from_secs(1),
        cap: Duration::from_secs(45),
    };

    /// Backoff before attempt `attempt + 1` (`attempt` >= 1): a uniformly
    /// jittered value in `[ceiling / 2, ceiling]`, where the ceiling is
    /// `base * 2^(attempt - 1)` capped at `cap`.
    fn backoff(&self, attempt: u32, unit: f64) -> Duration {
        let ceiling = self
            .base
            .saturating_mul(1u32 << attempt.saturating_sub(1).min(20))
            .min(self.cap);
        ceiling.mul_f64(0.5 + 0.5 * unit.clamp(0.0, 1.0))
    }
}

/// Marker kept in an error chain whose message hides its source (so no
/// endpoint or credential detail is logged) when that source was transient.
#[derive(Debug, thiserror::Error)]
#[error("transient transport failure")]
pub(crate) struct Transient;

/// `anyhow!(message)` that stays retryable when `source` was transient.
pub(crate) fn unavailable(
    source: impl Into<anyhow::Error>,
    message: &'static str,
) -> anyhow::Error {
    if is_transient(&source.into()) {
        anyhow::Error::new(Transient).context(message)
    } else {
        anyhow::anyhow!(message)
    }
}

/// Retry only what a network blip explains. Anything unknown is permanent.
pub(crate) fn is_transient(error: &anyhow::Error) -> bool {
    for cause in error.chain() {
        if cause.is::<Transient>() {
            return true;
        }
        if let Some(status) = cause.downcast_ref::<crate::rest_commit::RestHttpStatus>() {
            return matches!(status.status, 408 | 429 | 502 | 503 | 504);
        }
        if let Some(refused) = cause.downcast_ref::<super::activation::ControlRefused>() {
            // The control route answers every refusal with 403. These come
            // from the edge, a load balancer or a restarting API pod.
            return matches!(refused.0, 408 | 429 | 502 | 503 | 504);
        }
        if let Some(error) = cause.downcast_ref::<iceberg::Error>() {
            if error.message() == "Received response with unexpected status code" {
                // iceberg-catalog-rest 0.10.1 stores the actual HTTP status as
                // its FIRST context field but exposes no context accessor.
                // Read only that prefix: remote JSON/headers must never turn
                // a 403 into a transient error by mentioning a reset or 503.
                let diagnostic = error.to_string();
                let status = diagnostic
                    .strip_prefix("Unexpected, context: { status: ")
                    .and_then(|text| text.split_whitespace().next())
                    .and_then(|status| status.parse::<u16>().ok());
                return status.is_some_and(|status| matches!(status, 408 | 429 | 502 | 503 | 504));
            }
        }
        if let Some(error) = cause.downcast_ref::<reqwest::Error>() {
            if error.is_connect() || error.is_timeout() {
                return true;
            }
            if let Some(status) = error.status() {
                return matches!(status.as_u16(), 408 | 429 | 502 | 503 | 504);
            }
            if error.is_request() || error.is_body() {
                return true;
            }
        }
        if let Some(error) = cause.downcast_ref::<std::io::Error>() {
            use std::io::ErrorKind::*;
            if matches!(
                error.kind(),
                ConnectionReset
                    | ConnectionAborted
                    | ConnectionRefused
                    | BrokenPipe
                    | TimedOut
                    | UnexpectedEof
                    | NotConnected
            ) {
                return true;
            }
        }
    }
    // iceberg-rust's REST client stringifies its transport errors.
    let text = format!("{error:#}").to_ascii_lowercase();
    [
        "connection reset",
        "connection refused",
        "connection closed before message completed",
        "broken pipe",
        "operation timed out",
        "error sending request",
    ]
    .iter()
    .any(|needle| text.contains(needle))
}

fn unit_jitter() -> f64 {
    let bits = uuid::Uuid::new_v4().as_u128() as u64 >> 11;
    bits as f64 / (1u64 << 53) as f64
}

/// Run `call` until it succeeds, fails permanently, or `policy.deadline`
/// passes (tokio time, so tests drive it with a paused clock).
pub(crate) async fn retry<T, F, Fut>(
    op: &'static str,
    policy: RetryPolicy,
    mut call: F,
) -> Result<T>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<T>>,
{
    let started = tokio::time::Instant::now();
    let deadline = started + policy.deadline;
    let mut attempt = 0u32;
    loop {
        if tokio::time::Instant::now() >= deadline {
            return Err(anyhow::Error::new(Transient)
                .context(format!("{op}: control call reached the retry deadline")));
        }
        attempt += 1;
        let error = match tokio::time::timeout_at(deadline, call()).await {
            Ok(Ok(value)) => {
                if attempt > 1 {
                    tracing::info!(
                        op,
                        attempts = attempt,
                        elapsed_ms = started.elapsed().as_millis() as u64,
                        "agent catalog control call recovered after transient failures"
                    );
                }
                return Ok(value);
            }
            Ok(Err(error)) => error,
            Err(_) => {
                return Err(anyhow::Error::new(Transient)
                    .context(format!("{op}: control call reached the retry deadline")));
            }
        };
        if !is_transient(&error) {
            return Err(error);
        }
        let wait = policy.backoff(attempt, unit_jitter());
        if started.elapsed() + wait > policy.deadline {
            tracing::warn!(op, attempts = attempt, elapsed_ms = started.elapsed().as_millis() as u64,
                error = %format!("{error:#}"), "agent catalog control retry budget spent; read fence stays closed");
            return Err(error.context(format!(
                "{op}: transient failures outlasted the retry budget"
            )));
        }
        tracing::warn!(op, attempt, backoff_ms = wait.as_millis() as u64, error = %format!("{error:#}"),
            "agent catalog control call failed transiently; retrying");
        tokio::time::sleep(wait).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    fn reset() -> anyhow::Error {
        std::io::Error::new(
            std::io::ErrorKind::ConnectionReset,
            "connection reset by peer",
        )
        .into()
    }

    #[test]
    fn backoff_is_jittered_exponential_and_capped() {
        let p = RetryPolicy::CONTROL;
        assert_eq!(p.backoff(1, 1.0), Duration::from_secs(1));
        assert_eq!(p.backoff(1, 0.0), Duration::from_millis(500));
        assert_eq!(p.backoff(4, 1.0), Duration::from_secs(8));
        assert_eq!(p.backoff(30, 1.0), Duration::from_secs(45));
        assert_eq!(p.backoff(30, 0.0), Duration::from_millis(22_500));
        for _ in 0..1000 {
            let u = unit_jitter();
            assert!((0.0..1.0).contains(&u));
        }
    }

    #[test]
    fn only_transport_failures_are_transient() {
        assert!(is_transient(&reset()));
        assert!(is_transient(&reset().context("purge_dropped")));
        assert!(is_transient(&unavailable(
            reset(),
            "catalog lifecycle session unavailable"
        )));
        assert_eq!(
            format!(
                "{:#}",
                unavailable(reset(), "catalog lifecycle session unavailable")
            ),
            "catalog lifecycle session unavailable: transient transport failure"
        );
        assert!(!is_transient(&unavailable(
            anyhow::anyhow!("bad table"),
            "catalog lifecycle session unavailable"
        )));
        assert!(is_transient(&anyhow::Error::new(
            super::super::activation::ControlRefused(503)
        )));
        assert!(!is_transient(&anyhow::Error::new(
            super::super::activation::ControlRefused(403)
        )));
        assert!(!is_transient(&anyhow::anyhow!(
            "catalog control refused: HTTP 403 (catalog_fresh_serving_proof_missing)"
        )));
        assert!(!is_transient(&anyhow::anyhow!(
            "serving table and writer table differ"
        )));
        assert!(is_transient(&anyhow::anyhow!(
            "Unexpected => Failed to execute http request, source: error sending request for url"
        )));
    }

    #[test]
    fn catalog_response_bodies_cannot_override_the_actual_http_status() {
        let error = iceberg::Error::new(
            iceberg::ErrorKind::Unexpected,
            "Received response with unexpected status code",
        )
        .with_context("status", "403 Forbidden")
        .with_context("json", r#"{"error":"connection reset; status: 503"}"#);
        assert!(!is_transient(&error.into()));
    }

    #[tokio::test(start_paused = true)]
    async fn a_five_minute_reset_window_is_ridden_out() {
        let until = tokio::time::Instant::now() + Duration::from_secs(5 * 60);
        let calls = AtomicU32::new(0);
        let started = tokio::time::Instant::now();
        let value = retry("test", RetryPolicy::CONTROL, || async {
            calls.fetch_add(1, Ordering::SeqCst);
            if tokio::time::Instant::now() < until {
                Err(reset())
            } else {
                Ok(7)
            }
        })
        .await
        .unwrap();
        assert_eq!(value, 7);
        assert!(started.elapsed() >= Duration::from_secs(5 * 60));
        // Bounded: never more than a cap (plus jitter) past the window.
        assert!(started.elapsed() <= Duration::from_secs(5 * 60 + 45));
        assert!(calls.load(Ordering::SeqCst) > 5);
    }

    #[tokio::test(start_paused = true)]
    async fn a_ten_minute_outage_is_ridden_out_and_a_longer_one_fails_closed_at_the_deadline() {
        let started = tokio::time::Instant::now();
        let until = started + Duration::from_secs(10 * 60);
        retry("test", RetryPolicy::CONTROL, || async {
            if tokio::time::Instant::now() < until {
                Err(reset())
            } else {
                Ok(())
            }
        })
        .await
        .unwrap();

        let started = tokio::time::Instant::now();
        let calls = AtomicU32::new(0);
        let error = retry("test", RetryPolicy::CONTROL, || async {
            calls.fetch_add(1, Ordering::SeqCst);
            Err::<(), _>(reset())
        })
        .await
        .unwrap_err();
        assert!(
            calls.load(Ordering::SeqCst) <= 37,
            "permanent outages cannot hot-loop"
        );
        assert!(is_transient(&error));
        assert!(format!("{error:#}").contains("outlasted the retry budget"));
        assert!(started.elapsed() <= RetryPolicy::CONTROL.deadline);
        assert!(started.elapsed() >= RetryPolicy::CONTROL.deadline - RetryPolicy::CONTROL.cap);
    }

    #[tokio::test(start_paused = true)]
    async fn a_stalled_call_cannot_outlast_the_total_retry_deadline() {
        let started = tokio::time::Instant::now();
        let calls = AtomicU32::new(0);
        let error = retry("stalled", RetryPolicy::CONTROL, || {
            calls.fetch_add(1, Ordering::SeqCst);
            std::future::pending::<Result<()>>()
        })
        .await
        .unwrap_err();
        assert!(
            is_transient(&error),
            "a canceled ambiguous call must remain resumable"
        );
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(started.elapsed(), RetryPolicy::CONTROL.deadline);
    }

    #[tokio::test(start_paused = true)]
    async fn slow_failed_attempts_share_one_total_retry_deadline() {
        let started = tokio::time::Instant::now();
        let calls = AtomicU32::new(0);
        let error = retry("slow", RetryPolicy::CONTROL, || async {
            calls.fetch_add(1, Ordering::SeqCst);
            tokio::time::sleep(Duration::from_secs(4 * 60)).await;
            Err::<(), _>(reset())
        })
        .await
        .unwrap_err();
        assert!(is_transient(&error));
        assert_eq!(calls.load(Ordering::SeqCst), 3);
        assert_eq!(started.elapsed(), RetryPolicy::CONTROL.deadline);
    }

    #[tokio::test(start_paused = true)]
    async fn a_refusal_is_never_retried() {
        let calls = AtomicU32::new(0);
        let started = tokio::time::Instant::now();
        assert!(retry("test", RetryPolicy::CONTROL, || async {
            calls.fetch_add(1, Ordering::SeqCst);
            Err::<(), _>(anyhow::Error::new(
                super::super::activation::ControlRefused(403),
            ))
        })
        .await
        .is_err());
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(started.elapsed(), Duration::ZERO);
    }
}
