// SPDX-License-Identifier: AGPL-3.0-or-later

//! Where a tenant process's bootstrap secret comes from (NAN-2871).
//!
//! The supervisor never holds tenant keys. Per assignment it asks the control
//! plane for a **short-lived, tenant- and role-scoped bootstrap token**,
//! authenticating with the cell's own identity, writes it into a sealed
//! memfd and hands the fd to the jailed tenant process. The process
//! exchanges the token for its real credentials (R2 keys, the ingest signing
//! key) and the token is spent. What the supervisor transiently holds can
//! therefore start exactly one process for one tenant for a few minutes.
//!
//! The control-plane endpoint is part of the placement contract
//! (`docs-internal/NAN-2865-cell-placement-spec.md`):
//!
//! ```text
//! POST {control_url}/v1/lake/cells/{cell_id}/bootstrap-tokens
//! Authorization: Bearer <cell identity token>
//! {"tenant_id": "...", "role": "ingest"|"detect"|"query"}
//! → 200 application/octet-stream  (opaque token, ≤ 64 KiB)
//! ```
//!
//! The control plane must refuse a tenant that is not placed on `cell_id`.

use crate::contract::{Role, TenantId, MAX_SECRET_BYTES};
use async_trait::async_trait;
use std::collections::HashMap;
use std::path::PathBuf;
use zeroize::Zeroizing;

#[async_trait]
pub trait KeySource: Send + Sync + 'static {
    /// Mint the bootstrap secret for one `role` process of `tenant`.
    async fn mint(&self, tenant: &TenantId, role: Role) -> anyhow::Result<Zeroizing<Vec<u8>>>;
}

/// Production source: the control plane mints per-assignment tokens.
pub struct ControlPlaneKeySource {
    client: reqwest::Client,
    url: String,
    cell_id: String,
    identity_file: PathBuf,
}

impl ControlPlaneKeySource {
    /// `identity_file` holds the cell identity bearer (a projected
    /// service-account token or a mounted secret); it is re-read per mint so
    /// rotation needs no restart.
    pub fn new(url: String, cell_id: String, identity_file: PathBuf) -> anyhow::Result<Self> {
        let client = reqwest::Client::builder().timeout(std::time::Duration::from_secs(10)).build()?;
        Ok(Self { client, url: url.trim_end_matches('/').to_owned(), cell_id, identity_file })
    }
}

#[async_trait]
impl KeySource for ControlPlaneKeySource {
    async fn mint(&self, tenant: &TenantId, role: Role) -> anyhow::Result<Zeroizing<Vec<u8>>> {
        let identity = Zeroizing::new(tokio::fs::read_to_string(&self.identity_file).await?);
        let url = format!("{}/v1/lake/cells/{}/bootstrap-tokens", self.url, self.cell_id);
        let resp = self
            .client
            .post(url)
            .bearer_auth(identity.trim())
            .json(&serde_json::json!({"tenant_id": tenant.as_str(), "role": role.as_str()}))
            .send()
            .await?;
        let status = resp.status();
        if !status.is_success() {
            let retry_after = resp
                .headers()
                .get(reqwest::header::RETRY_AFTER)
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.trim().parse::<u64>().ok())
                .map(std::time::Duration::from_secs);
            // The refusal body is small JSON (`{"error": "<code>"}`); never
            // buffer more than a few KiB of it.
            let mut body = Vec::new();
            let mut resp = resp;
            while let Ok(Some(chunk)) = resp.chunk().await {
                body.extend_from_slice(&chunk);
                if body.len() > MAX_REFUSAL_BODY {
                    break;
                }
            }
            return Err(MintRefused::from_response(tenant, role, status.as_u16(), &body, retry_after).into());
        }
        let body = Zeroizing::new(resp.bytes().await?.to_vec());
        if body.is_empty() || body.len() > MAX_SECRET_BYTES {
            anyhow::bail!("bootstrap token has bad length {}", body.len());
        }
        Ok(body)
    }
}

/// Refusal bodies read past this are ignored (the codes are tiny).
const MAX_REFUSAL_BODY: usize = 4096;

/// The control plane answered a bootstrap-token mint with a non-2xx status.
///
/// Carries the platform's refusal code (the `error` field of its JSON body,
/// e.g. `detect_drain_disabled`, `tenant_not_placed`, `tenant_fenced`) so the
/// supervisor can back off and report *why* a role cannot start, instead of
/// retrying a bare `403` forever.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MintRefused {
    pub tenant: TenantId,
    pub role: Role,
    pub status: u16,
    /// Sanitized refusal code; the HTTP reason phrase (`forbidden`) when the
    /// body names none.
    pub code: String,
    /// `missing` from a `detect_control_functions_missing` refusal.
    pub missing: Option<String>,
    pub retry_after: Option<std::time::Duration>,
}

impl MintRefused {
    pub fn from_response(
        tenant: &TenantId,
        role: Role,
        status: u16,
        body: &[u8],
        retry_after: Option<std::time::Duration>,
    ) -> Self {
        let parsed: Option<serde_json::Value> = serde_json::from_slice(body).ok();
        let field = |k: &str| parsed.as_ref().and_then(|v| v.get(k)).and_then(|v| v.as_str()).map(sanitize_code).filter(|s| !s.is_empty());
        let code = field("error").unwrap_or_else(|| {
            reqwest::StatusCode::from_u16(status)
                .ok()
                .and_then(|s| s.canonical_reason())
                .map(sanitize_code)
                .unwrap_or_else(|| format!("http_{status}"))
        });
        Self { tenant: tenant.clone(), role, status, code, missing: field("missing"), retry_after }
    }

    /// A permanent-until-reconfigured refusal (4xx) as opposed to a
    /// transient one (5xx, e.g. `credential_mint_unavailable`).
    pub fn is_policy(&self) -> bool {
        (400..500).contains(&self.status)
    }
}

/// Lowercase `[a-z0-9_.:,-]`, spaces to `_`, at most 96 chars: the code ends up
/// in logs, status JSON and Prometheus label values.
fn sanitize_code(s: &str) -> String {
    s.trim()
        .chars()
        .map(|c| c.to_ascii_lowercase())
        .map(|c| if c == ' ' { '_' } else { c })
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | ':' | ',' | '-'))
        .take(96)
        .collect()
}

impl std::fmt::Display for MintRefused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "control plane refused bootstrap token for {}/{}: {} {}", self.tenant, self.role.as_str(), self.status, self.code)?;
        if let Some(m) = &self.missing {
            write!(f, " (missing {m})")?;
        }
        Ok(())
    }
}

impl std::error::Error for MintRefused {}

/// Development source: `<dir>/<tenant>/<role>.token`. The directory must be
/// private to the supervisor (0700); files are read per mint.
pub struct DirKeySource {
    dir: PathBuf,
}

impl DirKeySource {
    pub fn new(dir: PathBuf) -> anyhow::Result<Self> {
        use std::os::unix::fs::MetadataExt;
        let md = std::fs::metadata(&dir)?;
        if md.mode() & 0o077 != 0 {
            anyhow::bail!("{} must not be group/world accessible", dir.display());
        }
        Ok(Self { dir })
    }
}

#[async_trait]
impl KeySource for DirKeySource {
    async fn mint(&self, tenant: &TenantId, role: Role) -> anyhow::Result<Zeroizing<Vec<u8>>> {
        let p = self.dir.join(tenant.as_str()).join(format!("{}.token", role.as_str()));
        let bytes = Zeroizing::new(tokio::fs::read(&p).await?);
        if bytes.len() > MAX_SECRET_BYTES {
            anyhow::bail!("{} too large", p.display());
        }
        Ok(bytes)
    }
}

/// In-memory source (tests).
#[derive(Default)]
pub struct StaticKeySource {
    map: HashMap<(TenantId, Role), Vec<u8>>,
}

impl StaticKeySource {
    pub fn with(mut self, tenant: &TenantId, role: Role, secret: &[u8]) -> Self {
        self.map.insert((tenant.clone(), role), secret.to_vec());
        self
    }
}

#[async_trait]
impl KeySource for StaticKeySource {
    async fn mint(&self, tenant: &TenantId, role: Role) -> anyhow::Result<Zeroizing<Vec<u8>>> {
        self.map
            .get(&(tenant.clone(), role))
            .map(|v| Zeroizing::new(v.clone()))
            .ok_or_else(|| anyhow::anyhow!("no secret for {tenant}/{}", role.as_str()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tenant() -> TenantId {
        TenantId::new("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa").unwrap()
    }

    #[test]
    fn refusal_code_comes_from_the_body() {
        let r = MintRefused::from_response(&tenant(), Role::Detect, 403, br#"{"error":"detect_drain_disabled"}"#, None);
        assert_eq!(r.code, "detect_drain_disabled");
        assert!(r.is_policy());
        assert_eq!(r.to_string(),
            "control plane refused bootstrap token for aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa/detect: 403 detect_drain_disabled");
    }

    #[test]
    fn bare_status_falls_back_to_the_reason_phrase() {
        let r = MintRefused::from_response(&tenant(), Role::Detect, 403, b"", None);
        assert_eq!(r.code, "forbidden");
        let r = MintRefused::from_response(&tenant(), Role::Detect, 503, b"<html>", Some(std::time::Duration::from_secs(7)));
        assert_eq!(r.code, "service_unavailable");
        assert!(!r.is_policy());
        assert_eq!(r.retry_after, Some(std::time::Duration::from_secs(7)));
    }

    /// The production source against a control plane that refuses detect
    /// the way the platform does (403, JSON code, no-store).
    #[tokio::test]
    async fn control_plane_refusal_is_typed() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 4096];
            let _ = sock.read(&mut buf).await.unwrap();
            let body = r#"{"error":"detect_drain_disabled"}"#;
            let resp = format!("HTTP/1.1 403 Forbidden\r\ncontent-type: application/json\r\ncache-control: no-store\r\nretry-after: 30\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}", body.len());
            sock.write_all(resp.as_bytes()).await.unwrap();
        });
        let dir = tempfile::tempdir().unwrap();
        let identity = dir.path().join("identity");
        std::fs::write(&identity, "cell-identity").unwrap();
        let src = ControlPlaneKeySource::new(format!("http://{addr}"), "c1".into(), identity).unwrap();
        let err = src.mint(&tenant(), Role::Detect).await.unwrap_err();
        let r = err.downcast_ref::<MintRefused>().expect("typed refusal");
        assert_eq!((r.status, r.code.as_str(), r.retry_after), (403, "detect_drain_disabled", Some(std::time::Duration::from_secs(30))));
    }

    /// A catalog-probe 503 is transient and a later fresh mint can succeed.
    #[tokio::test]
    async fn detect_probe_failure_does_not_poison_the_next_mint() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            for (status, body) in [
                ("503 Service Unavailable", r#"{"error":"detect_control_probe_unavailable"}"#),
                ("200 OK", "fresh-test-bootstrap"),
            ] {
                let (mut sock, _) = listener.accept().await.unwrap();
                let mut buf = vec![0u8; 4096];
                let _ = sock.read(&mut buf).await.unwrap();
                let response = format!("HTTP/1.1 {status}\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}", body.len());
                sock.write_all(response.as_bytes()).await.unwrap();
            }
        });
        let dir = tempfile::tempdir().unwrap();
        let identity = dir.path().join("identity");
        std::fs::write(&identity, "test-cell-identity").unwrap();
        let source = ControlPlaneKeySource::new(format!("http://{addr}"), "c1".into(), identity).unwrap();
        let error = source.mint(&tenant(), Role::Detect).await.unwrap_err();
        let refusal = error.downcast_ref::<MintRefused>().unwrap();
        assert_eq!(refusal.status, 503);
        assert_eq!(refusal.code, "detect_control_probe_unavailable");
        assert!(!refusal.is_policy());
        let token = source.mint(&tenant(), Role::Detect).await.unwrap();
        assert!(token.as_slice() == b"fresh-test-bootstrap");
        server.await.unwrap();
    }

    #[test]
    fn codes_are_label_safe() {
        let r = MintRefused::from_response(&tenant(), Role::Detect, 503,
            br#"{"error":"detect_control_functions_missing","missing":"lake_detect_x (9003480)\"}\n"}"#, None);
        assert_eq!(r.code, "detect_control_functions_missing");
        assert_eq!(r.missing.as_deref(), Some("lake_detect_x_9003480"));
        let long = format!(r#"{{"error":"{}"}}"#, "A\"b".repeat(100));
        let r = MintRefused::from_response(&tenant(), Role::Query, 403, long.as_bytes(), None);
        assert!(r.code.len() <= 96 && r.code.chars().all(|c| c.is_ascii_lowercase()), "{}", r.code);
    }
}
