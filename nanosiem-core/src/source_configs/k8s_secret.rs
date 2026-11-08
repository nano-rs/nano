// SPDX-License-Identifier: AGPL-3.0-or-later

//! Lightweight K8s API client for storing source-config credentials in a
//! tenant-namespace Secret.
//!
//! Talks directly to the Kubernetes API via reqwest — we only need a single
//! strategic-merge-patch endpoint, so pulling in `kube` + `k8s-openapi` would
//! add ~4 MB of compiled deps and ~30 s of CI build time for one route.
//!
//! The CA bundle and namespace come from the in-pod ServiceAccount mount that
//! kubelet always provides; `KUBERNETES_SERVICE_HOST` is injected by every
//! kubelet too. The bearer token is **read fresh on every request** because
//! kubelet rotates the projected SA token in place (default 1h expiry) — a
//! cached token leads to silent 401s on long-lived pods after an hour.
//!
//! `is_in_cluster()` returns true when the SA token file exists, which is the
//! cheap canonical check for "are we running in a pod".

use std::path::{Path, PathBuf};

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use thiserror::Error;

const SA_TOKEN_PATH: &str = "/var/run/secrets/kubernetes.io/serviceaccount/token";
const SA_CA_PATH: &str = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt";
const SA_NAMESPACE_PATH: &str = "/var/run/secrets/kubernetes.io/serviceaccount/namespace";

#[derive(Error, Debug)]
pub enum K8sSecretError {
    #[error("read in-pod credentials at {0}: {1}")]
    ReadFile(String, std::io::Error),
    #[error("KUBERNETES_SERVICE_HOST is unset")]
    MissingApiHost,
    #[error("invalid CA cert in pod: {0}")]
    InvalidCa(reqwest::Error),
    #[error("build HTTP client: {0}")]
    BuildClient(reqwest::Error),
    #[error("PATCH {0}: {1}")]
    Http(String, reqwest::Error),
    #[error("PATCH {url} returned HTTP {status}: {body}")]
    HttpStatus {
        url: String,
        status: u16,
        body: String,
    },
}

#[derive(Clone)]
pub(crate) struct K8sSecretClient {
    api_url: String,
    namespace: String,
    /// Path to the bearer token. Re-read on every request (kubelet rotates the
    /// projected SA token in place; caching it would silently 401 after expiry).
    token_path: PathBuf,
    http: reqwest::Client,
}

impl K8sSecretClient {
    /// Build the client by reading the in-pod ServiceAccount mount. Call sites
    /// should gate this on `is_in_cluster()` — outside a pod the SA files
    /// won't exist and this returns `ReadFile`.
    pub(crate) async fn from_pod_env() -> Result<Self, K8sSecretError> {
        // Fail fast if the token isn't readable now; we still re-read it
        // per-request below to pick up rotations, but we want construction to
        // surface obvious misconfiguration rather than defer it to first use.
        let _probe = read_trimmed(SA_TOKEN_PATH).await?;
        let namespace = read_trimmed(SA_NAMESPACE_PATH).await?;
        let ca_pem = tokio::fs::read(SA_CA_PATH)
            .await
            .map_err(|e| K8sSecretError::ReadFile(SA_CA_PATH.to_string(), e))?;
        let host = std::env::var("KUBERNETES_SERVICE_HOST")
            .map_err(|_| K8sSecretError::MissingApiHost)?;
        let port = std::env::var("KUBERNETES_SERVICE_PORT").unwrap_or_else(|_| "443".to_string());

        let cert = reqwest::Certificate::from_pem(&ca_pem).map_err(K8sSecretError::InvalidCa)?;
        let http = reqwest::Client::builder()
            .add_root_certificate(cert)
            .build()
            .map_err(K8sSecretError::BuildClient)?;

        Ok(Self {
            api_url: format!("https://{}:{}", host, port),
            namespace,
            token_path: PathBuf::from(SA_TOKEN_PATH),
            http,
        })
    }

    /// Set or remove a `data.<key>` field on `secret_name` in this pod's
    /// namespace via strategic-merge-patch. `value=Some(_)` writes the bytes
    /// (base64-encoded as required by the Secret spec); `value=None` removes
    /// the key (strategic merge interprets explicit `null` as deletion).
    pub(crate) async fn upsert_key(
        &self,
        secret_name: &str,
        key: &str,
        value: Option<&[u8]>,
    ) -> Result<(), K8sSecretError> {
        let token = self.read_token().await?;
        let url = format!(
            "{}/api/v1/namespaces/{}/secrets/{}",
            self.api_url, self.namespace, secret_name
        );
        // Some(bytes) -> JSON string of base64; None -> JSON null.
        let encoded: Option<String> = value.map(|v| BASE64.encode(v));
        let body = serde_json::json!({ "data": { key: encoded } });

        let resp = self
            .http
            .patch(&url)
            .header(
                reqwest::header::CONTENT_TYPE,
                "application/strategic-merge-patch+json",
            )
            .bearer_auth(&token)
            .json(&body)
            .send()
            .await
            .map_err(|e| K8sSecretError::Http(url.clone(), e))?;

        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(K8sSecretError::HttpStatus {
                url,
                status: status.as_u16(),
                body,
            });
        }
        Ok(())
    }

    async fn read_token(&self) -> Result<String, K8sSecretError> {
        read_path_trimmed(&self.token_path).await
    }
}

/// True when the ServiceAccount token file exists, indicating the process is
/// running inside a K8s pod. Used to auto-select the K8s creds backend.
pub(crate) fn is_in_cluster() -> bool {
    std::path::Path::new(SA_TOKEN_PATH).exists()
}

async fn read_trimmed(path: &'static str) -> Result<String, K8sSecretError> {
    read_path_trimmed(Path::new(path)).await
}

async fn read_path_trimmed(path: &Path) -> Result<String, K8sSecretError> {
    let raw = tokio::fs::read_to_string(path)
        .await
        .map_err(|e| K8sSecretError::ReadFile(path.display().to_string(), e))?;
    Ok(raw.trim().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;
    use wiremock::{matchers, Mock, MockServer, ResponseTemplate};

    /// Build a client pointing at a mock server with a tempfile-backed token.
    /// The returned `NamedTempFile` keeps the file alive for the test scope.
    async fn test_client(api_url: String) -> (K8sSecretClient, tempfile::NamedTempFile) {
        let mut token_file = tempfile::NamedTempFile::new().unwrap();
        token_file.write_all(b"token-A\n").unwrap();
        token_file.flush().unwrap();
        let http = reqwest::Client::builder().build().unwrap();
        let client = K8sSecretClient {
            api_url,
            namespace: "tenant-foo".into(),
            token_path: token_file.path().to_path_buf(),
            http,
        };
        (client, token_file)
    }

    #[tokio::test]
    async fn upsert_some_writes_base64_value_with_correct_url_and_headers() {
        let server = MockServer::start().await;
        Mock::given(matchers::method("PATCH"))
            .and(matchers::path(
                "/api/v1/namespaces/tenant-foo/secrets/vector-source-credentials",
            ))
            .and(matchers::header("authorization", "Bearer token-A"))
            .and(matchers::header(
                "content-type",
                "application/strategic-merge-patch+json",
            ))
            // base64("hello") = "aGVsbG8="
            .and(matchers::body_json(serde_json::json!({
                "data": { "gcp_x.creds": "aGVsbG8=" }
            })))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&server)
            .await;

        let (client, _tf) = test_client(server.uri()).await;
        client
            .upsert_key("vector-source-credentials", "gcp_x.creds", Some(b"hello"))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn upsert_none_emits_null_value_for_strategic_merge_delete() {
        let server = MockServer::start().await;
        Mock::given(matchers::method("PATCH"))
            .and(matchers::body_json(serde_json::json!({
                "data": { "gcp_x.creds": serde_json::Value::Null }
            })))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&server)
            .await;

        let (client, _tf) = test_client(server.uri()).await;
        client
            .upsert_key("vector-source-credentials", "gcp_x.creds", None)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn token_is_read_per_request_so_rotation_lands() {
        let server = MockServer::start().await;
        // First call must carry token-A.
        Mock::given(matchers::method("PATCH"))
            .and(matchers::header("authorization", "Bearer token-A"))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&server)
            .await;
        // Second call must carry token-B (rotated by kubelet).
        Mock::given(matchers::method("PATCH"))
            .and(matchers::header("authorization", "Bearer token-B"))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&server)
            .await;

        let (client, mut token_file) = test_client(server.uri()).await;
        client
            .upsert_key("s", "k", Some(b"v"))
            .await
            .expect("first call w/ token-A");

        // Simulate kubelet rotating the projected token in place. Truncate +
        // rewrite so the file inode stays the same (matches kubelet behavior).
        token_file.as_file_mut().set_len(0).unwrap();
        std::io::Seek::seek(token_file.as_file_mut(), std::io::SeekFrom::Start(0)).unwrap();
        token_file.write_all(b"token-B\n").unwrap();
        token_file.flush().unwrap();

        client
            .upsert_key("s", "k", Some(b"v"))
            .await
            .expect("second call must pick up token-B");
    }

    #[tokio::test]
    async fn http_error_status_surfaces_as_http_status_variant() {
        let server = MockServer::start().await;
        Mock::given(matchers::method("PATCH"))
            .respond_with(ResponseTemplate::new(403).set_body_string("forbidden"))
            .expect(1)
            .mount(&server)
            .await;

        let (client, _tf) = test_client(server.uri()).await;
        let err = client
            .upsert_key("s", "k", Some(b"v"))
            .await
            .expect_err("expected HttpStatus error");
        match err {
            K8sSecretError::HttpStatus { status, body, .. } => {
                assert_eq!(status, 403);
                assert_eq!(body, "forbidden");
            }
            other => panic!("expected HttpStatus, got {:?}", other),
        }
    }
}
