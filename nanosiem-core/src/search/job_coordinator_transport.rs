// SPDX-License-Identifier: AGPL-3.0-or-later

//! Bounded transport for the hosted job coordinator. This is not a selectable
//! SearchJobStore: callers must still authenticate signed envelopes, bind lease
//! identities and enforce result retention before exposing a job to a runtime.

use reqwest::header::{HeaderMap, HeaderValue, AUTHORIZATION, CONTENT_TYPE};
use serde::Deserialize;
use serde_json::Value;
use std::time::Duration;
use url::{Host, Url};

const MAX_BODY_BYTES: usize = 196_608;

// Keep diagnostics closed and non-secret even for malformed internal commands.
fn diagnostic_operation(command: &Value) -> &'static str {
    match command.get("op").and_then(Value::as_str) {
        Some("submit") => "submit",
        Some("get") => "get",
        Some("claim") => "claim",
        Some("renew") => "renew",
        Some("complete") => "complete",
        Some("progress") => "progress",
        Some("fail") => "fail",
        Some("cancel") => "cancel",
        Some("cancel_claim") => "cancel_claim",
        Some("release_claim") => "release_claim",
        Some("reconcile") => "reconcile",
        Some("describe") => "describe",
        Some("depth") => "depth",
        Some("list_page") => "list_page",
        _ => "other",
    }
}

#[derive(Default)]
struct BoundedBody {
    bytes: Vec<u8>,
    exceeded: bool,
}

impl std::io::Write for BoundedBody {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if bytes.len() > MAX_BODY_BYTES.saturating_sub(self.bytes.len()) {
            self.exceeded = true;
            return Err(std::io::Error::other("coordinator command limit"));
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, thiserror::Error, PartialEq, Eq)]
pub enum CoordinatorTransportError {
    #[error("invalid hosted coordinator configuration")]
    Configuration,
    #[error("hosted coordinator command exceeds its transport limit")]
    CommandTooLarge,
    #[error("hosted coordinator access denied")]
    AccessDenied,
    #[error("hosted coordinator rejected the command")]
    Rejected,
    #[error("hosted coordinator is unavailable")]
    Unavailable,
    #[error("hosted coordinator response is invalid")]
    Protocol,
}

/// Non-secret diagnostics for a failed command: the closed failure kind, the
/// HTTP status when one was received, and the coordinator's error code when
/// it is a short snake_case identifier (the Worker's `ContractError` codes,
/// e.g. `invalid_phase`). Free-form bodies are never retained.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoordinatorFailure {
    pub kind: CoordinatorTransportError,
    pub operation: &'static str,
    pub status: Option<u16>,
    pub code: Option<String>,
}

impl CoordinatorFailure {
    fn new(kind: CoordinatorTransportError, operation: &'static str) -> Self {
        Self { kind, operation, status: None, code: None }
    }
}

impl std::fmt::Display for CoordinatorFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "hosted coordinator {} command failed: {}", self.operation, self.kind)?;
        if let Some(status) = self.status {
            write!(f, " (status {status}")?;
            if let Some(code) = &self.code {
                write!(f, ", code {code}")?;
            }
            write!(f, ")")?;
        }
        Ok(())
    }
}

/// Only closed identifier-shaped codes are surfaced; anything else is dropped.
fn error_code(bytes: &[u8]) -> Option<String> {
    #[derive(Deserialize)]
    struct ErrorBody {
        error: String,
    }
    let body: ErrorBody = serde_json::from_slice(bytes).ok()?;
    let valid = (1..=64).contains(&body.error.len())
        && body
            .error
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_');
    valid.then_some(body.error)
}

const MAX_ERROR_BODY_BYTES: usize = 1024;
const ERROR_BODY_TIMEOUT: Duration = Duration::from_secs(2);

#[derive(Clone)]
pub struct HostedCoordinatorTransport {
    client: reqwest::Client,
    endpoint: Url,
}

impl std::fmt::Debug for HostedCoordinatorTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Neither credentials nor deployment identity belong in ordinary logs.
        f.debug_struct("HostedCoordinatorTransport")
            .finish_non_exhaustive()
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Success {
    result: Value,
}

impl HostedCoordinatorTransport {
    #[cfg(test)]
    pub(super) fn loopback_test_peer(address: std::net::SocketAddr) -> Self {
        assert!(address.ip().is_loopback());
        Self {
            client: reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .timeout(Duration::from_secs(3))
                .build()
                .unwrap(),
            endpoint: Url::parse(&format!("http://{address}/v1/coordinate")).unwrap(),
        }
    }

    /// Endpoint and token must come from trusted, tenant-pinned server config,
    /// never a public request. TLS verification remains enabled and redirects
    /// are forbidden, including redirects to another path on the same host.
    pub fn new(endpoint: &str, token: &str) -> Result<Self, CoordinatorTransportError> {
        let endpoint =
            Url::parse(endpoint).map_err(|_| CoordinatorTransportError::Configuration)?;
        if endpoint.scheme() != "https"
            || !matches!(endpoint.host(), Some(Host::Domain(host)) if host.contains('.'))
            || endpoint.port_or_known_default() != Some(443)
            || endpoint.path() != "/v1/coordinate"
            || endpoint.query().is_some()
            || endpoint.fragment().is_some()
            || !endpoint.username().is_empty()
            || endpoint.password().is_some()
            || !(43..=128).contains(&token.len())
            || !token
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
        {
            return Err(CoordinatorTransportError::Configuration);
        }
        let mut authorization = HeaderValue::from_str(&format!("Bearer {token}"))
            .map_err(|_| CoordinatorTransportError::Configuration)?;
        authorization.set_sensitive(true);
        let mut headers = HeaderMap::new();
        headers.insert(AUTHORIZATION, authorization);
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        let client = reqwest::Client::builder()
            .https_only(true)
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(15))
            .default_headers(headers)
            .build()
            .map_err(|_| CoordinatorTransportError::Configuration)?;
        Ok(Self { client, endpoint })
    }

    /// Low-level contract command. A successful response is still untrusted job
    /// data; the signed-envelope/lease validators are mandatory at the caller.
    /// There are deliberately no automatic retries: submit/claim callers must
    /// retain their original idempotency and attempt-session identities.
    pub async fn execute(&self, command: &Value) -> Result<Value, CoordinatorTransportError> {
        self.execute_detailed(command).await.map_err(|failure| failure.kind)
    }

    /// As [`Self::execute`], but a failure keeps the operation, HTTP status
    /// and closed coordinator error code so callers can log why a command
    /// was refused instead of a bare "command failed".
    pub async fn execute_detailed(&self, command: &Value) -> Result<Value, CoordinatorFailure> {
        let operation = diagnostic_operation(command);
        let fail = |kind| CoordinatorFailure::new(kind, operation);
        let started = std::time::Instant::now();
        let mut body = BoundedBody::default();
        serde_json::to_writer(&mut body, command).map_err(|_| {
            fail(if body.exceeded {
                CoordinatorTransportError::CommandTooLarge
            } else {
                CoordinatorTransportError::Protocol
            })
        })?;
        let mut response = self
            .client
            .post(self.endpoint.clone())
            .body(body.bytes)
            .send()
            .await
            .map_err(|error| {
                // Never format reqwest errors: they can carry endpoint URLs.
                let failure_class = if error.is_timeout() {
                    "timeout"
                } else if error.is_connect() {
                    "connect"
                } else {
                    "request"
                };
                tracing::warn!(operation, failure_class, stage = "send",
                    elapsed_ms = started.elapsed().as_millis() as u64,
                    "hosted coordinator transport failed");
                fail(CoordinatorTransportError::Unavailable)
            })?;
        let status = response.status().as_u16();
        if status != 200 {
            let kind = match status {
                401 | 403 => CoordinatorTransportError::AccessDenied,
                429 | 500..=599 => CoordinatorTransportError::Unavailable,
                400..=499 => CoordinatorTransportError::Rejected,
                _ => CoordinatorTransportError::Protocol,
            };
            // Read at most a small error body; only a closed code survives.
            let mut error_body = Vec::new();
            if !(300..400).contains(&status) {
                let read = async {
                    while let Ok(Some(chunk)) = response.chunk().await {
                        if chunk.len() > MAX_ERROR_BODY_BYTES.saturating_sub(error_body.len()) {
                            error_body.clear();
                            break;
                        }
                        error_body.extend_from_slice(&chunk);
                    }
                };
                if tokio::time::timeout(ERROR_BODY_TIMEOUT, read).await.is_err() {
                    error_body.clear();
                }
            }
            let code = error_code(&error_body);
            tracing::warn!(operation, stage = "status", status,
                code = code.as_deref().unwrap_or("-"),
                elapsed_ms = started.elapsed().as_millis() as u64,
                "hosted coordinator returned non-success status");
            return Err(CoordinatorFailure { kind, operation, status: Some(status), code });
        }
        let content_type = response
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|v| v.to_str().ok());
        if content_type.and_then(|v| v.split(';').next()) != Some("application/json")
            || response
                .content_length()
                .is_some_and(|n| n > MAX_BODY_BYTES as u64)
        {
            tracing::warn!(operation, stage = "headers", status,
                "hosted coordinator success response has an invalid content type or size");
            return Err(CoordinatorFailure {
                status: Some(status),
                ..fail(CoordinatorTransportError::Protocol)
            });
        }
        let mut bytes = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|error| {
                tracing::warn!(operation, stage = "body", timeout = error.is_timeout(),
                    elapsed_ms = started.elapsed().as_millis() as u64,
                    "hosted coordinator response body failed");
                fail(CoordinatorTransportError::Unavailable)
            })?
        {
            if chunk.len() > MAX_BODY_BYTES.saturating_sub(bytes.len()) {
                tracing::warn!(operation, stage = "body", status,
                    "hosted coordinator success response exceeds its limit");
                return Err(CoordinatorFailure {
                    status: Some(status),
                    ..fail(CoordinatorTransportError::Protocol)
                });
            }
            bytes.extend_from_slice(&chunk);
        }
        let success: Success = serde_json::from_slice(&bytes).map_err(|_| {
            // A 200 carrying an error envelope is reported by its code.
            let code = error_code(&bytes);
            tracing::warn!(operation, stage = "decode", status,
                code = code.as_deref().unwrap_or("-"),
                "hosted coordinator success response is not a result envelope");
            CoordinatorFailure {
                status: Some(status),
                code,
                ..fail(CoordinatorTransportError::Protocol)
            }
        })?;
        Ok(success.result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[test]
    fn diagnostic_operations_never_echo_untrusted_values() {
        assert_eq!(diagnostic_operation(&serde_json::json!({"op":"submit"})), "submit");
        assert_eq!(diagnostic_operation(&serde_json::json!({"op":"token-or-tenant-secret"})), "other");
        assert_eq!(diagnostic_operation(&serde_json::json!({"op":{"token":"secret"}})), "other");
    }

    #[test]
    fn configuration_rejects_ambiguous_endpoints_and_invalid_tokens() {
        let token = "a".repeat(43);
        for endpoint in [
            "http://jobs.example.com/v1/coordinate",
            "https://jobs.example.com/",
            "https://jobs.example.com:8443/v1/coordinate",
            "https://localhost/v1/coordinate",
            "https://127.0.0.1/v1/coordinate",
            "https://jobs.example.com/v1/coordinate?tenant=a",
            "https://jobs.example.com/v1/coordinate#fragment",
            "https://user:pass@jobs.example.com/v1/coordinate",
        ] {
            assert!(matches!(
                HostedCoordinatorTransport::new(endpoint, &token),
                Err(CoordinatorTransportError::Configuration)
            ));
        }
        for token in [
            "a".repeat(42),
            "a".repeat(129),
            " ".repeat(43),
            format!("{}\n", "a".repeat(43)),
        ] {
            assert!(HostedCoordinatorTransport::new(
                "https://jobs.example.com/v1/coordinate",
                &token
            )
            .is_err());
        }
        let transport =
            HostedCoordinatorTransport::new("https://jobs.example.com/v1/coordinate", &token)
                .unwrap();
        let debug = format!("{transport:?}");
        assert!(!debug.contains(&token));
        assert!(!debug.contains("example.com"));
    }

    // Test-only loopback HTTP peer. Production constructor cannot select HTTP.
    async fn peer(
        status: u16,
        headers: &str,
        body: &str,
    ) -> (HostedCoordinatorTransport, tokio::task::JoinHandle<()>) {
        let response = format!("HTTP/1.1 {status} Test\r\nConnection: close\r\nContent-Length: {}\r\n{headers}\r\n{body}", body.len());
        raw_peer(response).await
    }

    async fn raw_peer(
        response: String,
    ) -> (HostedCoordinatorTransport, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request = [0u8; 8192];
            let _ = socket.read(&mut request).await.unwrap();
            let _ = socket.write_all(response.as_bytes()).await;
        });
        (
            HostedCoordinatorTransport {
                client: reqwest::Client::builder()
                    .redirect(reqwest::redirect::Policy::none())
                    .timeout(Duration::from_secs(3))
                    .build()
                    .unwrap(),
                endpoint: Url::parse(&format!("http://{address}/v1/coordinate")).unwrap(),
            },
            server,
        )
    }

    #[tokio::test]
    async fn only_explicit_success_null_means_no_job() {
        let (transport, server) = peer(
            200,
            "Content-Type: application/json\r\n",
            r#"{"result":null}"#,
        )
        .await;
        assert_eq!(
            transport
                .execute(&serde_json::json!({"op":"claim"}))
                .await
                .unwrap(),
            Value::Null
        );
        server.await.unwrap();
        for (status, expected) in [
            (401, CoordinatorTransportError::AccessDenied),
            (403, CoordinatorTransportError::AccessDenied),
            (404, CoordinatorTransportError::Rejected),
            (409, CoordinatorTransportError::Rejected),
            (429, CoordinatorTransportError::Unavailable),
            (503, CoordinatorTransportError::Unavailable),
        ] {
            let (transport, server) = peer(
                status,
                "Content-Type: application/json\r\n",
                r#"{"error":"secret detail"}"#,
            )
            .await;
            assert_eq!(
                transport.execute(&serde_json::json!({})).await.unwrap_err(),
                expected
            );
            server.await.unwrap();
        }
    }

    #[tokio::test]
    async fn failures_keep_status_and_only_closed_error_codes() {
        for (status, body, code) in [
            (409, r#"{"error":"invalid_phase"}"#, Some("invalid_phase")),
            (403, r#"{"error":"forbidden"}"#, Some("forbidden")),
            (409, r#"{"error":"Bearer secret-token value"}"#, None),
            (503, "upstream text", None),
        ] {
            let (transport, server) =
                peer(status, "Content-Type: application/json\r\n", body).await;
            let failure = transport
                .execute_detailed(&serde_json::json!({"op":"progress"}))
                .await
                .unwrap_err();
            assert_eq!(failure.operation, "progress");
            assert_eq!(failure.status, Some(status));
            assert_eq!(failure.code.as_deref(), code);
            assert!(!failure.to_string().contains("secret"));
            server.await.unwrap();
        }
        // A 200 error envelope is a protocol failure that still names its code.
        let (transport, server) = peer(
            200,
            "Content-Type: application/json\r\n",
            r#"{"error":"completion_conflict"}"#,
        )
        .await;
        let failure = transport
            .execute_detailed(&serde_json::json!({"op":"complete"}))
            .await
            .unwrap_err();
        assert_eq!(failure.kind, CoordinatorTransportError::Protocol);
        assert_eq!(failure.code.as_deref(), Some("completion_conflict"));
        server.await.unwrap();
    }

    #[tokio::test]
    async fn rejects_redirects_bad_json_and_oversized_responses() {
        for (status, headers, body) in [
            (
                302,
                "Location: http://127.0.0.1:1/credential-leak\r\n",
                "".into(),
            ),
            (
                200,
                "Content-Type: text/plain\r\n",
                r#"{"result":null}"#.into(),
            ),
            (
                200,
                "Content-Type: application/json\r\n",
                r#"{"error":"not a success"}"#.into(),
            ),
            (200, "Content-Type: application/json\r\n", "{}".into()),
            (
                200,
                "Content-Type: application/json\r\n",
                r#"{"result":null,"unexpected":true}"#.into(),
            ),
            (
                200,
                "Content-Type: application/json\r\n",
                "invalid json".into(),
            ),
            (
                200,
                "Content-Type: application/json\r\n",
                "x".repeat(MAX_BODY_BYTES + 1),
            ),
        ] {
            let (transport, server) = peer(status, headers, &body).await;
            assert_eq!(
                transport.execute(&serde_json::json!({})).await.unwrap_err(),
                CoordinatorTransportError::Protocol
            );
            server.await.unwrap();
        }
    }

    #[tokio::test]
    async fn streamed_response_limit_does_not_depend_on_content_length() {
        for padding in [16, MAX_BODY_BYTES] {
            // Both responses are valid JSON. Only their actual streamed size
            // differs, so a parser error cannot mask a missing size check.
            let body = format!("{}{{\"result\":null}}", " ".repeat(padding));
            let mut response = String::from(
                "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n",
            );
            for chunk in body.as_bytes().chunks(4096) {
                response.push_str(&format!("{:x}\r\n", chunk.len()));
                response.push_str(std::str::from_utf8(chunk).unwrap());
                response.push_str("\r\n");
            }
            response.push_str("0\r\n\r\n");
            let (transport, server) = raw_peer(response).await;
            let actual = transport.execute(&serde_json::json!({})).await;
            if padding == 16 {
                assert_eq!(actual, Ok(Value::Null));
            } else {
                assert_eq!(actual, Err(CoordinatorTransportError::Protocol));
            }
            server.await.unwrap();
        }
    }

    #[tokio::test]
    async fn oversized_commands_fail_before_network_access() {
        let transport = HostedCoordinatorTransport::new(
            "https://jobs.example.com/v1/coordinate",
            &"a".repeat(43),
        )
        .unwrap();
        assert_eq!(
            transport
                .execute(&Value::String("x".repeat(MAX_BODY_BYTES)))
                .await
                .unwrap_err(),
            CoordinatorTransportError::CommandTooLarge
        );
    }

    /// Read-only qualification of this actual HTTPS client, not the Node probe
    /// harness. Never runs in normal CI or accepts a production-selected URL.
    #[tokio::test]
    #[ignore = "requires explicit isolated Cloudflare probe credentials"]
    async fn isolated_live_cloudflare_transport() {
        let file = std::env::var("NANO_COORDINATOR_LIVE_TEST_CREDENTIALS_FILE")
            .expect("explicit private probe credential file required");
        let bytes = std::fs::read(file).expect("read private probe credentials");
        let credentials: Value = serde_json::from_slice(&bytes)
            .unwrap_or_else(|_| panic!("invalid private probe credential format"));
        // The probe Worker is named `<staging>-jobs-probe` and serves its
        // coordinate route on its own workers.dev hostname.
        let worker = credentials["worker"].as_str().expect("probe worker required");
        assert!(worker.ends_with("-jobs-probe"), "{worker}");
        let epoch = credentials["epoch"].as_str().expect("probe epoch required");
        let endpoint = credentials["endpoint"].as_str().expect("probe endpoint required");
        assert!(
            endpoint.starts_with(&format!("https://{worker}."))
                && endpoint.ends_with(".workers.dev/v1/coordinate"),
            "{endpoint}"
        );
        let producer = HostedCoordinatorTransport::new(
            endpoint,
            credentials["tokens"]["producer"]
                .as_str()
                .expect("probe producer required"),
        )
        .unwrap();
        assert_eq!(
            producer
                .execute(&serde_json::json!({"op":"depth","epoch":epoch}))
                .await,
            Ok(serde_json::json!({"queued":0,"running":0}))
        );
        assert_eq!(
            producer
                .execute(&serde_json::json!({"op":"claim","epoch":epoch,
            "owner":"forbidden-readonly-test","lease_ms":5000}))
                .await,
            Err(CoordinatorTransportError::AccessDenied)
        );
        let other = HostedCoordinatorTransport::new(
            endpoint,
            credentials["tokens"]["otherProducer"]
                .as_str()
                .expect("other probe producer required"),
        )
        .unwrap();
        assert_eq!(
            other
                .execute(&serde_json::json!({"op":"get","epoch":epoch,
            "job_id":"one"}))
                .await,
            Ok(Value::Null)
        );
        let unknown = HostedCoordinatorTransport::new(endpoint, &"x".repeat(43)).unwrap();
        assert_eq!(
            unknown
                .execute(&serde_json::json!({"op":"depth","epoch":epoch}))
                .await,
            Err(CoordinatorTransportError::AccessDenied)
        );
    }
}
