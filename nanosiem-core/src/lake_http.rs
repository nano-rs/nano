// SPDX-License-Identifier: AGPL-3.0-or-later

//! HTTP recovery policy for idempotent reads from a tenant-pinned lake worker.

use reqwest::{RequestBuilder, Response, StatusCode};
use std::future::Future;
use std::time::{Duration, Instant};

const DEFAULT_RECOVERY_WINDOW: Duration = Duration::from_secs(30);
const INITIAL_RETRY_DELAY: Duration = Duration::from_millis(50);
const MAX_RETRY_DELAY: Duration = Duration::from_secs(1);

/// NAN-3270: response header carrying a lake worker error's `reason`
/// (the same value as the JSON body's), readable without the body.
pub const LAKE_REASON_HEADER: &str = "x-nano-lake-reason";
/// The worker's reason for a request its memory or concurrency budget
/// refused. Deterministic for the request: replaying it unchanged burns
/// another full execution, so the transport never does.
pub const QUERY_BUDGET_EXHAUSTED_REASON: &str = "query_budget_exhausted";

pub trait LakeRequestBuilderExt {
    fn send_idempotent_with_recovery(
        self,
    ) -> impl Future<Output = Result<Response, reqwest::Error>> + Send;

    /// [`send_idempotent_with_recovery`], bounded by a request deadline when
    /// one is given (lean-lake cell clients pass their client timeout): no
    /// attempt, retry delay or recovery outlives `deadline` from the first
    /// send. `None` is exactly [`send_idempotent_with_recovery`].
    fn send_idempotent_with_recovery_within(
        self,
        deadline: Option<Duration>,
    ) -> impl Future<Output = Result<Response, reqwest::Error>> + Send;
}

impl LakeRequestBuilderExt for RequestBuilder {
    fn send_idempotent_with_recovery(
        self,
    ) -> impl Future<Output = Result<Response, reqwest::Error>> + Send {
        send_idempotent_with_recovery(self)
    }

    fn send_idempotent_with_recovery_within(
        self,
        deadline: Option<Duration>,
    ) -> impl Future<Output = Result<Response, reqwest::Error>> + Send {
        send_idempotent_with_recovery_policy(self, DEFAULT_RECOVERY_WINDOW, deadline)
    }
}

/// Send an idempotent lake-worker request, waiting through a bounded worker
/// recycle instead of exposing a brief native-runtime restart as a product
/// error. Semantic failures and resource-budget rejections are never retried.
///
/// Request builders carrying streaming bodies are not cloneable and therefore
/// fall back to one attempt. Nano's worker read contracts use bounded JSON
/// bodies, so every current caller is replay-safe. Non-idempotent calls
/// (the detection commit) use a plain `send()` and are never replayed.
///
/// With a deadline (lean-lake cell clients) a replay never reuses a pooled
/// connection: it goes out on a brand new one, since the pooled connection
/// that failed may be pinned to a cell pod that is rolling away. The
/// first retry follows after a short jittered delay (25-50 ms), then the
/// delay doubles up to 1 s, still jittered, so the callers of one rolled pod
/// do not retry in lockstep.
pub async fn send_idempotent_with_recovery(
    request: RequestBuilder,
) -> Result<Response, reqwest::Error> {
    send_idempotent_with_recovery_policy(request, DEFAULT_RECOVERY_WINDOW, None).await
}

async fn send_idempotent_with_recovery_policy(
    request: RequestBuilder,
    recovery_window: Duration,
    deadline: Option<Duration>,
) -> Result<Response, reqwest::Error> {
    let started = Instant::now();
    // Retries stop at the recovery window, or earlier at the deadline.
    let retry_until = deadline.map_or(recovery_window, |d| d.min(recovery_window));
    let mut retry_delay = INITIAL_RETRY_DELAY;
    let mut replay = false;
    loop {
        let Some(mut attempt) = request.try_clone() else {
            return request.send().await;
        };
        if let Some(deadline) = deadline {
            // The attempt itself ends at the request deadline.
            let left = deadline.saturating_sub(started.elapsed()).max(Duration::from_millis(1));
            attempt = attempt.timeout(left);
        }
        let sent = if replay && deadline.is_some() {
            // A deadline-bound (lean-lake cell) replay goes out on a brand
            // new connection: the pooled one that failed may be pinned to a
            // cell pod that is rolling away.
            let (_, built) = attempt.build_split();
            match built {
                Ok(built) => fresh_connection_client().execute(built).await,
                Err(error) => Err(error),
            }
        } else {
            attempt.send().await
        };
        replay = true;
        match sent {
            Ok(response) => {
                if !is_transient_lake_response(&response)
                    || started.elapsed() >= retry_until
                {
                    return Ok(response);
                }
            }
            Err(error) => {
                if !is_transient_lake_transport_error(&error)
                    || started.elapsed() >= retry_until
                {
                    return Err(error);
                }
            }
        }

        let remaining = retry_until.saturating_sub(started.elapsed());
        if remaining.is_zero() {
            continue;
        }
        tokio::time::sleep(jittered(retry_delay).min(remaining)).await;
        retry_delay = retry_delay.saturating_mul(2).min(MAX_RETRY_DELAY);
    }
}

/// A client that never keeps a connection: every request it sends opens a
/// new one. Timeouts come from the request (the caller's deadline).
fn fresh_connection_client() -> &'static reqwest::Client {
    static FRESH: std::sync::OnceLock<reqwest::Client> = std::sync::OnceLock::new();
    FRESH.get_or_init(|| {
        reqwest::Client::builder()
            .pool_max_idle_per_host(0)
            .build()
            .unwrap_or_else(|_| reqwest::Client::new())
    })
}

/// `delay` scaled into `[delay / 2, delay]`.
fn jittered(delay: Duration) -> Duration {
    let half = delay / 2;
    half + half.mul_f64(rand::random::<f64>())
}

/// A transient status, unless the worker says its budget refused this very
/// request (NAN-3270: a 503 `query_budget_exhausted` was replayed ~4x for
/// 30 s before the search service could escalate it).
fn is_transient_lake_response(response: &Response) -> bool {
    is_transient_lake_status(response.status()) && !is_budget_refusal(response.headers())
}

fn is_budget_refusal(headers: &reqwest::header::HeaderMap) -> bool {
    headers.get(LAKE_REASON_HEADER).is_some_and(|reason| reason.as_bytes() == QUERY_BUDGET_EXHAUSTED_REASON.as_bytes())
}

fn is_transient_lake_status(status: StatusCode) -> bool {
    matches!(
        status,
        StatusCode::BAD_GATEWAY | StatusCode::SERVICE_UNAVAILABLE | StatusCode::GATEWAY_TIMEOUT
    )
}

fn is_transient_lake_transport_error(error: &reqwest::Error) -> bool {
    // A supervised worker can accept a TCP connection and then reset it while
    // its native executor is still loading. Reqwest classifies that as a
    // request error rather than a connect error. The read contracts using this
    // helper are idempotent, so replay transport failures that have no HTTP
    // response while continuing to return every semantic response unchanged.
    error.is_connect() || error.is_timeout() || error.is_request()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    #[test]
    fn only_transient_worker_availability_statuses_are_retried() {
        for status in [
            StatusCode::BAD_GATEWAY,
            StatusCode::SERVICE_UNAVAILABLE,
            StatusCode::GATEWAY_TIMEOUT,
        ] {
            assert!(is_transient_lake_status(status));
        }
        for status in [
            StatusCode::CONFLICT,
            StatusCode::BAD_REQUEST,
            StatusCode::UNAUTHORIZED,
            StatusCode::UNPROCESSABLE_ENTITY,
            StatusCode::INTERNAL_SERVER_ERROR,
        ] {
            assert!(!is_transient_lake_status(status));
        }
    }

    #[tokio::test]
    async fn transient_worker_restart_is_hidden_from_an_idempotent_reader() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let attempts = Arc::new(AtomicUsize::new(0));
        let server_attempts = attempts.clone();
        let server = tokio::spawn(async move {
            for status in [503, 503, 200] {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut request = [0_u8; 1024];
                let _ = stream.read(&mut request).await.unwrap();
                server_attempts.fetch_add(1, Ordering::Relaxed);
                let reason = if status == 200 {
                    "OK"
                } else {
                    "Service Unavailable"
                };
                let response = format!(
                    "HTTP/1.1 {status} {reason}\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{{}}"
                );
                stream.write_all(response.as_bytes()).await.unwrap();
            }
        });

        let response = send_idempotent_with_recovery_policy(
            reqwest::Client::new().get(format!("http://{address}/v1/query")),
            Duration::from_secs(2),
            None,
        )
        .await
        .unwrap();
        server.await.unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(attempts.load(Ordering::Relaxed), 3);
    }

    /// NAN-3270: a 503 the worker marks `query_budget_exhausted` is the
    /// request's own budget refusal, answered at once (the search handler
    /// escalates it); a bare 503 is still an outage and is replayed.
    #[tokio::test]
    async fn budget_refusal_503_is_not_replayed() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let attempts = Arc::new(AtomicUsize::new(0));
        let server_attempts = attempts.clone();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = [0_u8; 1024];
            let _ = stream.read(&mut request).await.unwrap();
            server_attempts.fetch_add(1, Ordering::Relaxed);
            let body = r#"{"ok":false,"reason":"query_budget_exhausted","error":"query memory budget exceeded"}"#;
            let response = format!(
                "HTTP/1.1 503 Service Unavailable\r\n{LAKE_REASON_HEADER}: {QUERY_BUDGET_EXHAUSTED_REASON}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            stream.write_all(response.as_bytes()).await.unwrap();
        });

        let response = send_idempotent_with_recovery_policy(
            reqwest::Client::new().get(format!("http://{address}/v1/query")),
            Duration::from_secs(2),
            None,
        )
        .await
        .unwrap();
        server.await.unwrap();

        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(attempts.load(Ordering::Relaxed), 1);
        assert!(response.text().await.unwrap().contains("query_budget_exhausted"));
    }

    #[tokio::test]
    async fn warming_conflict_is_not_replayed() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let attempts = Arc::new(AtomicUsize::new(0));
        let server_attempts = attempts.clone();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = [0_u8; 1024];
            let _ = stream.read(&mut request).await.unwrap();
            server_attempts.fetch_add(1, Ordering::Relaxed);
            stream
                .write_all(
                    b"HTTP/1.1 409 Conflict\r\nContent-Length: 52\r\nConnection: close\r\n\r\n{\"reason\":\"warming\",\"error\":\"product_state_warming\"}",
                )
                .await
                .unwrap();
        });

        let response = send_idempotent_with_recovery_policy(
            reqwest::Client::new().get(format!("http://{address}/v1/query")),
            Duration::from_secs(2),
            None,
        )
        .await
        .unwrap();
        server.await.unwrap();

        assert_eq!(response.status(), StatusCode::CONFLICT);
        let body: serde_json::Value = response.json().await.unwrap();
        assert_eq!(body["reason"], "warming");
        assert_eq!(attempts.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn connection_reset_during_worker_boot_is_retried() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let attempts = Arc::new(AtomicUsize::new(0));
        let server_attempts = attempts.clone();
        let server = tokio::spawn(async move {
            let (mut first, _) = listener.accept().await.unwrap();
            let mut request = [0_u8; 1024];
            let _ = first.read(&mut request).await.unwrap();
            server_attempts.fetch_add(1, Ordering::Relaxed);
            drop(first);

            let (mut second, _) = listener.accept().await.unwrap();
            let _ = second.read(&mut request).await.unwrap();
            server_attempts.fetch_add(1, Ordering::Relaxed);
            second
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}")
                .await
                .unwrap();
        });

        let response = send_idempotent_with_recovery_policy(
            reqwest::Client::new().get(format!("http://{address}/v1/query")),
            Duration::from_secs(2),
            None,
        )
        .await
        .unwrap();
        server.await.unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(attempts.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn retry_delays_are_jittered_within_half_to_full() {
        for _ in 0..200 {
            let d = jittered(Duration::from_millis(50));
            assert!(d >= Duration::from_millis(25) && d <= Duration::from_millis(50), "{d:?}");
        }
    }

    /// A lean-lake cell pod rolling away (NAN-3004 follow-up): the caller's
    /// pooled keep-alive connection is pinned to the old pod, which tears it
    /// down under the next request. The replay must go out on a fresh
    /// connection (to the pod that stays) and succeed.
    #[tokio::test]
    async fn a_keep_alive_connection_reset_by_a_rolled_pod_is_replayed_on_a_fresh_connection() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (connections, requests) = (Arc::new(AtomicUsize::new(0)), Arc::new(AtomicUsize::new(0)));
        let (c2, r2) = (connections.clone(), requests.clone());
        let server = tokio::spawn(async move {
            // Old pod: answers the first request keep-alive, then drops the
            // connection under the second one.
            let (mut old, _) = listener.accept().await.unwrap();
            c2.fetch_add(1, Ordering::Relaxed);
            let mut buf = [0_u8; 2048];
            let _ = old.read(&mut buf).await.unwrap();
            r2.fetch_add(1, Ordering::Relaxed);
            old.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}").await.unwrap();
            let _ = old.read(&mut buf).await.unwrap();
            r2.fetch_add(1, Ordering::Relaxed);
            drop(old);
            // New pod: a fresh connection.
            let (mut new, _) = listener.accept().await.unwrap();
            c2.fetch_add(1, Ordering::Relaxed);
            let _ = new.read(&mut buf).await.unwrap();
            r2.fetch_add(1, Ordering::Relaxed);
            new.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}").await.unwrap();
        });
        let client = reqwest::Client::new();
        let url = format!("http://{address}/v1/query");
        let first = client.get(&url).send_idempotent_with_recovery_within(Some(Duration::from_secs(5))).await.unwrap();
        assert_eq!(first.status(), StatusCode::OK);
        let _ = first.bytes().await.unwrap();
        let second = client.get(&url).send_idempotent_with_recovery_within(Some(Duration::from_secs(5))).await.unwrap();
        assert_eq!(second.status(), StatusCode::OK);
        server.await.unwrap();
        assert_eq!((connections.load(Ordering::Relaxed), requests.load(Ordering::Relaxed)), (2, 3));
    }

    /// A 503 from a draining pod on a keep-alive connection (no
    /// `Connection: close`): the replay must not go out on that connection.
    #[tokio::test]
    async fn a_503_connection_is_not_reused_for_the_replay() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let second_on_old = Arc::new(AtomicUsize::new(0));
        let flag = second_on_old.clone();
        let server = tokio::spawn(async move {
            let (mut old, _) = listener.accept().await.unwrap();
            let mut buf = [0_u8; 2048];
            let _ = old.read(&mut buf).await.unwrap();
            old.write_all(b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 2\r\n\r\n{}").await.unwrap();
            let (mut new, _) = listener.accept().await.unwrap();
            let _ = new.read(&mut buf).await.unwrap();
            new.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}").await.unwrap();
            // Anything more on the old connection is a reuse.
            if let Ok(Ok(n)) = tokio::time::timeout(Duration::from_millis(200), old.read(&mut buf)).await {
                if n > 0 {
                    flag.fetch_add(1, Ordering::Relaxed);
                }
            }
        });
        let response = reqwest::Client::new()
            .get(format!("http://{address}/v1/query"))
            .send_idempotent_with_recovery_within(Some(Duration::from_secs(5)))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        server.await.unwrap();
        assert_eq!(second_on_old.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn retries_stop_at_the_request_deadline() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let attempts = Arc::new(AtomicUsize::new(0));
        let counted = attempts.clone();
        tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else { return };
                let counted = counted.clone();
                tokio::spawn(async move {
                    let mut buf = [0_u8; 2048];
                    while let Ok(n) = stream.read(&mut buf).await {
                        if n == 0 {
                            return;
                        }
                        counted.fetch_add(1, Ordering::Relaxed);
                        let _ = stream
                            .write_all(b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}")
                            .await;
                        return;
                    }
                });
            }
        });
        let started = Instant::now();
        let response = reqwest::Client::new()
            .get(format!("http://{address}/v1/query"))
            .send_idempotent_with_recovery_within(Some(Duration::from_millis(400)))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert!(started.elapsed() < Duration::from_millis(1500), "{:?}", started.elapsed());
        assert!(attempts.load(Ordering::Relaxed) >= 2);
    }
}
