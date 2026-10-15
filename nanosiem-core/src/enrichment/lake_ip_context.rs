// SPDX-License-Identifier: AGPL-3.0-or-later

//! Typed client for custom CIDR context owned by Nano's lake enrichment
//! coordinator. IPinfo remains an immutable local MMDB; this client covers the
//! tenant-provided source payload that the legacy backend stored in a
//! ClickHouse IP_TRIE dictionary.

use super::IpEnrichmentResult;
use crate::lake_http::LakeRequestBuilderExt;
use serde::{Deserialize, Serialize};
use super::lean_assignments::{
    read_regular_file, LeanAssignmentLookup, LeanAssignmentSource, LeanAssignments,
};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use uuid::Uuid;
use std::time::Duration;
use thiserror::Error;

// Budgets for gen1 and lean envelopes. Publications are tiny; 10,000 sources
// with 256-byte identities fit comfortably in 4 MiB. Larger stats fail closed
// instead of allowing a coordinator's 10-million-row snapshot to dictate memory.
pub const MAX_SUCCESS_RESPONSE_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_STATS_SOURCES: usize = 10_000;
pub use super::lean_assignments::{MAX_ASSIGNMENT_BYTES, MAX_ASSIGNMENTS};
pub const MAX_CREDENTIAL_BYTES: usize = 4 * 1024;

#[derive(Debug, Error)]
pub enum LakeIpContextError {
    #[error("lake IP context configuration error: {0}")]
    Configuration(String),
    #[error("lake IP context request failed: {0}")]
    Request(String),
    #[error("lake IP context response failed its tenant or shape contract")]
    ResponseContract,
}

/// Server-owned assignments, live-reloaded through
/// [`LeanAssignmentSource`] (NAN-3531). Each resolve reads the tenant's own
/// credential, so a token that appears, rotates, or vanishes in the mounted
/// `tokens/` directory is seen on that tenant's next request.
#[derive(Clone)]
pub struct LakeIpContextResolver {
    assignments: Option<Arc<LeanAssignmentSource>>,
}

impl LakeIpContextResolver {
    /// A resolver over the process-wide source of `assignments_file`.
    pub fn new(assignments_file: Option<PathBuf>) -> Self {
        Self { assignments: assignments_file.map(|file| LeanAssignmentSource::shared(&file)) }
    }

    /// A resolver over an explicit source (tests inject the interval).
    pub fn with_source(source: Arc<LeanAssignmentSource>) -> Self {
        Self { assignments: Some(source) }
    }

    pub fn resolve(
        &self,
        tenant: &crate::auth::TrustedTenantContext,
    ) -> Result<LakeIpContextClient, LakeIpContextError> {
        let source = self.assignments.as_deref().ok_or_else(|| {
            LakeIpContextError::Configuration("lean coordinator assignments are not configured".into())
        })?;
        let assignments = source.current().map_err(|_| {
            LakeIpContextError::Configuration("cannot read lean coordinator assignments".into())
        })?;
        LakeIpContextClient::from_lean_assignments(&assignments, tenant.tenant_id)?
            .ok_or_else(|| LakeIpContextError::Configuration("tenant coordinator is not assigned".into()))
    }
}

/// The coordinator's NDJSON input; tenant identity is never part of a row.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(deny_unknown_fields)]
pub struct LakeIpContextInput {
    pub network: String,
    pub source_id: String,
    #[serde(default)]
    pub country: String,
    #[serde(default)]
    pub country_code: String,
    #[serde(default)]
    pub continent: String,
    #[serde(default)]
    pub continent_code: String,
    #[serde(default)]
    pub asn: String,
    #[serde(default)]
    pub as_name: String,
    #[serde(default)]
    pub as_domain: String,
    pub updated_at: chrono::DateTime<chrono::Utc>,
    #[serde(default)]
    pub deleted: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct LakeIpContextCounts {
    pub total_networks: usize,
    pub source_counts: std::collections::BTreeMap<String, usize>,
    pub snapshot_sha256: Option<String>,
}

#[derive(Clone)]
pub struct LakeIpContextClient {
    http: reqwest::Client,
    base_url: String,
    tenant_id: String,
    bearer_token: String,
}

impl LakeIpContextClient {
    /// Mirrors the lean enrichment assignment contract, without ambient fallback.
    pub fn from_lean_assignment(tenant_id: Uuid) -> Result<Option<Self>, LakeIpContextError> {
        let Some(source) = LeanAssignmentSource::from_env() else {
            return Ok(None);
        };
        let assignments = source.current().map_err(|_| {
            LakeIpContextError::Configuration("cannot read lean coordinator assignments".into())
        })?;
        Self::from_lean_assignments(&assignments, tenant_id)
    }

    /// One uncached read of `file`, with no last-good fallback.
    pub fn from_lean_assignment_file(
        file: &Path,
        tenant_id: Uuid,
    ) -> Result<Option<Self>, LakeIpContextError> {
        let (assignments, _) = LeanAssignments::read_file(file).map_err(|_| {
            LakeIpContextError::Configuration("invalid lean coordinator assignments".into())
        })?;
        Self::from_lean_assignments(&assignments, tenant_id)
    }

    /// Build this tenant's client from a parsed map, reading its credential now.
    pub fn from_lean_assignments(
        assignments: &LeanAssignments,
        tenant_id: Uuid,
    ) -> Result<Option<Self>, LakeIpContextError> {
        let invalid = || LakeIpContextError::Configuration("lean coordinator assignment is invalid".into());
        let assignment = match assignments.get(tenant_id) {
            LeanAssignmentLookup::Assigned(assignment) => assignment,
            LeanAssignmentLookup::NotAssigned => return Ok(None),
            LeanAssignmentLookup::Invalid => return Err(invalid()),
        };
        let origin = validate_origin(&assignment.internal_endpoint)?;
        let credential_path = std::fs::canonicalize(&assignment.credential_file).map_err(|_| invalid())?;
        // NAN-3531: another tenant's entry never fails this tenant's lookup.
        // Its token may not be mounted yet (tenant birth) or may have just
        // been removed. It still may not alias this tenant's endpoint or
        // credential: compare normalized origins (a trailing slash cannot
        // alias) and both the raw and, when it resolves, the canonical
        // credential path.
        for value in assignments.others(tenant_id) {
            let same_origin = value.internal_endpoint == assignment.internal_endpoint
                || validate_origin(&value.internal_endpoint).is_ok_and(|other| other == origin);
            let same_credential = value.credential_file == assignment.credential_file
                || std::fs::canonicalize(&value.credential_file)
                    .is_ok_and(|other| other == credential_path);
            if same_origin || same_credential {
                return Err(invalid());
            }
        }
        let credential = read_regular_file(&credential_path, MAX_CREDENTIAL_BYTES)
            .map_err(|_| LakeIpContextError::Configuration("cannot read lean coordinator credential".into()))?;
        let bearer_token = std::str::from_utf8(&credential).map_err(|_| invalid())?.trim().to_string();
        validate_token(&bearer_token)?;
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(assignment.timeout_secs))
            .redirect(reqwest::redirect::Policy::none())
            .build().map_err(|_| invalid())?;
        Ok(Some(Self { http, base_url: origin, tenant_id: tenant_id.to_string(), bearer_token }))
    }

    pub async fn upload_batch(&self, records: &[LakeIpContextInput]) -> Result<usize, LakeIpContextError> {
        if records.is_empty() || records.len() > 50_000 {
            return Err(LakeIpContextError::Configuration("IP context batch must contain 1..=50000 rows".into()));
        }
        let mut body = Vec::new();
        for record in records {
            validate_identity("source_id", &record.source_id)?;
            serde_json::to_writer(&mut body, record)
                .map_err(|_| LakeIpContextError::Configuration("invalid IP context row".into()))?;
            body.push(b'\n');
            if body.len() > 64 * 1024 * 1024 {
                return Err(LakeIpContextError::Configuration("IP context batch exceeds 64 MiB".into()));
            }
        }
        let response = self.http.post(format!("{}/v1/ip-context/batch", self.base_url))
            .bearer_auth(&self.bearer_token)
            .header("X-Nano-Tenant-ID", &self.tenant_id)
            .header("Content-Type", "application/x-ndjson")
            .body(body).send().await
            .map_err(|_| LakeIpContextError::Request("batch transport failed".into()))?;
        let envelope: TenantResponse<PublicationResult> = decode_response(response).await?;
        self.validate_tenant(&envelope.tenant_id)?;
        self.validate_publication(&envelope.result)?;
        Ok(envelope.result.rows)
    }

    fn validate_publication(&self, result: &PublicationResult) -> Result<(), LakeIpContextError> {
        if result.rows > 10_000_000 || result.tenant_id != self.tenant_id
            || !matches!(result.status.as_str(), "published" | "unchanged")
            || !valid_digest(&result.snapshot_sha256) {
            return Err(LakeIpContextError::ResponseContract);
        }
        Ok(())
    }

    pub fn from_env() -> Result<Self, LakeIpContextError> {
        let base_url = required_env("NANO_LAKE_ENRICHMENT_COORDINATOR_URL")?;
        let parsed = reqwest::Url::parse(&base_url).map_err(|error| {
            LakeIpContextError::Configuration(format!("invalid coordinator URL: {error}"))
        })?;
        if !matches!(parsed.scheme(), "http" | "https")
            || !parsed.username().is_empty()
            || parsed.password().is_some()
            || parsed.query().is_some()
            || parsed.fragment().is_some()
            || parsed.path() != "/"
        {
            return Err(LakeIpContextError::Configuration(
                "coordinator URL must be an HTTP(S) origin without credentials, query, fragment, or path"
                    .to_string(),
            ));
        }
        let tenant_id = required_env("NANO_LAKE_TENANT_ID")?;
        validate_identity("NANO_LAKE_TENANT_ID", &tenant_id)?;
        let token_path =
            PathBuf::from(required_env("NANO_LAKE_ENRICHMENT_COORDINATOR_TOKEN_FILE")?);
        let bearer_token = std::fs::read_to_string(&token_path)
            .map_err(|error| {
                LakeIpContextError::Configuration(format!(
                    "failed to read {}: {error}",
                    token_path.display()
                ))
            })?
            .trim()
            .to_string();
        if bearer_token.len() < 32 {
            return Err(LakeIpContextError::Configuration(
                "lake enrichment token must contain at least 32 bytes".to_string(),
            ));
        }
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(|error| LakeIpContextError::Configuration(error.to_string()))?;
        Ok(Self {
            http,
            base_url: base_url.trim_end_matches('/').to_string(),
            tenant_id,
            bearer_token,
        })
    }

    pub async fn lookup_bulk(
        &self,
        ips: &[String],
    ) -> Result<HashMap<String, IpEnrichmentResult>, LakeIpContextError> {
        if ips.is_empty() {
            return Ok(HashMap::new());
        }
        if ips.len() > 1_000
            || ips.iter().any(|ip| {
                ip.is_empty()
                    || ip.len() > 64
                    || ip.chars().any(char::is_control)
                    || ip.parse::<std::net::IpAddr>().is_err()
            })
        {
            return Err(LakeIpContextError::Configuration(
                "IP context lookup batch is invalid".to_string(),
            ));
        }
        let response = self
            .http
            .post(format!("{}/v1/ip-context/lookup", self.base_url))
            .bearer_auth(&self.bearer_token)
            .json(&BulkLookupRequest {
                tenant_id: &self.tenant_id,
                ips,
            })
            .send_idempotent_with_recovery()
            .await
            .map_err(|error| LakeIpContextError::Request(error.to_string()))?;
        let envelope: TenantResponse<HashMap<String, IpEnrichmentResult>> =
            decode_response(response).await?;
        self.validate_tenant(&envelope.tenant_id)?;
        if envelope
            .result
            .keys()
            .any(|ip| !ips.iter().any(|requested| requested == ip))
        {
            return Err(LakeIpContextError::ResponseContract);
        }
        Ok(envelope.result)
    }

    pub async fn stats(&self) -> Result<LakeIpContextCounts, LakeIpContextError> {
        let response = self
            .http
            .get(format!("{}/v1/ip-context/stats", self.base_url))
            .bearer_auth(&self.bearer_token)
            .query(&[("tenant_id", &self.tenant_id)])
            .send()
            .await
            .map_err(|_| LakeIpContextError::Request("stats transport failed".into()))?;
        let envelope: TenantResponse<LakeIpContextCounts> = decode_response(response).await?;
        self.validate_tenant(&envelope.tenant_id)?;
        if envelope.result.source_counts.len() > MAX_STATS_SOURCES
            || envelope.result.source_counts.keys().any(|source| validate_identity("source_id", source).is_err())
            || envelope.result.source_counts.values().try_fold(0usize, |sum, count| sum.checked_add(*count)) != Some(envelope.result.total_networks)
            || envelope
                .result
                .snapshot_sha256
                .as_deref()
                .is_some_and(|value| {
                    value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit())
                })
        {
            return Err(LakeIpContextError::ResponseContract);
        }
        Ok(envelope.result)
    }

    pub async fn delete_source(&self, source_id: &str) -> Result<(), LakeIpContextError> {
        validate_identity("source_id", source_id)?;
        let response = self
            .http
            .delete(format!(
                "{}/v1/ip-context/sources/{source_id}",
                self.base_url
            ))
            .bearer_auth(&self.bearer_token)
            .json(&TenantRequest {
                tenant_id: &self.tenant_id,
            })
            .send_idempotent_with_recovery()
            .await
            .map_err(|_| LakeIpContextError::Request("delete transport failed".into()))?;
        let envelope: TenantResponse<PublicationResult> = decode_response(response).await?;
        self.validate_tenant(&envelope.tenant_id)?;
        self.validate_publication(&envelope.result)?;
        Ok(())
    }

    fn validate_tenant(&self, returned: &str) -> Result<(), LakeIpContextError> {
        if returned == self.tenant_id {
            Ok(())
        } else {
            Err(LakeIpContextError::ResponseContract)
        }
    }
}

#[derive(Serialize)]
struct BulkLookupRequest<'a> {
    tenant_id: &'a str,
    ips: &'a [String],
}

#[derive(Serialize)]
struct TenantRequest<'a> {
    tenant_id: &'a str,
}

#[derive(Deserialize)]
struct TenantResponse<T> {
    tenant_id: String,
    result: T,
}

#[derive(Deserialize)]
struct PublicationResult {
    tenant_id: String,
    status: String,
    snapshot_sha256: String,
    rows: usize,
}

async fn decode_response<T: serde::de::DeserializeOwned>(
    mut response: reqwest::Response,
) -> Result<T, LakeIpContextError> {
    let status = response.status();
    // Error payloads are discarded without draining or buffering them.
    if !status.is_success() {
        return Err(LakeIpContextError::Request(format!("HTTP {status}")));
    }
    if response.content_length().is_some_and(|length| length > MAX_SUCCESS_RESPONSE_BYTES as u64) {
        return Err(LakeIpContextError::ResponseContract);
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await
        .map_err(|_| LakeIpContextError::Request("response transport failed".into()))? {
        // Content-Length is only an early rejection hint. Enforce this limit
        // on every chunk, before copying, even when the header is absent.
        if chunk.len() > MAX_SUCCESS_RESPONSE_BYTES - bytes.len() {
            return Err(LakeIpContextError::ResponseContract);
        }
        bytes.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&bytes).map_err(|_| LakeIpContextError::ResponseContract)
}

fn required_env(name: &str) -> Result<String, LakeIpContextError> {
    std::env::var(name)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .ok_or_else(|| LakeIpContextError::Configuration(format!("{name} is required")))
}

fn validate_identity(name: &str, value: &str) -> Result<(), LakeIpContextError> {
    if value.is_empty()
        || matches!(value, "." | "..")
        || value.len() > 256
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"_.:-".contains(&byte))
    {
        return Err(LakeIpContextError::Configuration(format!(
            "{name} is invalid"
        )));
    }
    Ok(())
}

fn valid_digest(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn validate_token(token: &str) -> Result<(), LakeIpContextError> {
    if token.len() < 32 || token.len() > MAX_CREDENTIAL_BYTES || !token.bytes().all(|byte| byte.is_ascii_graphic()) {
        return Err(LakeIpContextError::Configuration("lean coordinator token is invalid".into()));
    }
    Ok(())
}

fn validate_origin(value: &str) -> Result<String, LakeIpContextError> {
    let invalid = || LakeIpContextError::Configuration("invalid lean coordinator origin".into());
    let url = reqwest::Url::parse(value).map_err(|_| invalid())?;
    if !matches!(url.scheme(), "http" | "https") || url.host_str().is_none()
        || !url.username().is_empty() || url.password().is_some()
        || url.query().is_some() || url.fragment().is_some() || url.path() != "/" {
        return Err(invalid());
    }
    Ok(url.as_str().trim_end_matches('/').to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_token(dir: &Path, name: &str, content: &str) {
        let staging = dir.join(format!(".{name}.tmp"));
        std::fs::write(&staging, content).unwrap();
        std::fs::rename(&staging, dir.join(name)).unwrap();
    }

    fn assignment(port: u16, credential: &Path) -> serde_json::Value {
        serde_json::json!({"internal_endpoint": format!("http://127.0.0.1:{port}"), "credential_file": credential, "timeout_secs": 30})
    }

    fn resolver_token(resolver: &LakeIpContextResolver, tenant: Uuid) -> Option<String> {
        let trusted = crate::auth::TrustedTenantContext { tenant_id: tenant, tenant_slug: String::new() };
        resolver.resolve(&trusted).ok().map(|client| client.bearer_token)
    }

    /// NAN-3531: tokens appear in, rotate in, and vanish from the mounted
    /// `tokens/` directory while assignments.json stays unchanged. The map is
    /// cached (an hour-long interval here, so no reload happens at all), yet
    /// each resolve sees the current token, and another tenant's missing
    /// token never fails this tenant.
    #[test]
    fn lean_tokens_appear_rotate_and_vanish_without_an_assignments_change() {
        let root = tempfile::tempdir().unwrap();
        let tokens = root.path().join("tokens");
        std::fs::create_dir(&tokens).unwrap();
        let (a, b) = (Uuid::new_v4(), Uuid::new_v4());
        let file = root.path().join("assignments.json");
        std::fs::write(&file, serde_json::to_vec(&serde_json::json!({
            a.to_string(): assignment(9, &tokens.join(a.to_string())),
            b.to_string(): assignment(10, &tokens.join(b.to_string())),
        })).unwrap()).unwrap();
        write_token(&tokens, &a.to_string(), &"a".repeat(32));
        let resolver = LakeIpContextResolver::with_source(Arc::new(
            LeanAssignmentSource::with_interval(&file, Duration::from_secs(3_600)),
        ));

        assert_eq!(resolver_token(&resolver, a), Some("a".repeat(32)), "b's absent token must not fail a");
        assert_eq!(resolver_token(&resolver, b), None, "b has no token yet");

        write_token(&tokens, &b.to_string(), &"b".repeat(32));
        assert_eq!(resolver_token(&resolver, b), Some("b".repeat(32)), "b's token appeared");

        write_token(&tokens, &a.to_string(), &"r".repeat(32));
        assert_eq!(resolver_token(&resolver, a), Some("r".repeat(32)), "a's rotation is read");

        std::fs::remove_file(tokens.join(b.to_string())).unwrap();
        assert_eq!(resolver_token(&resolver, b), None, "b's token vanished");
        assert_eq!(resolver_token(&resolver, a), Some("r".repeat(32)), "a is untouched");
        assert_eq!(resolver_token(&resolver, Uuid::new_v4()), None, "unassigned tenant");
    }

    /// A newly assigned tenant is served after a forced reload, and a torn
    /// assignments file keeps the last good map.
    #[test]
    fn a_new_assignment_is_served_and_a_bad_file_keeps_the_last_good_map() {
        let root = tempfile::tempdir().unwrap();
        let (a, b) = (Uuid::new_v4(), Uuid::new_v4());
        write_token(root.path(), "a", &"a".repeat(32));
        write_token(root.path(), "b", &"b".repeat(32));
        let file = root.path().join("assignments.json");
        std::fs::write(&file, serde_json::to_vec(&serde_json::json!({
            a.to_string(): assignment(9, &root.path().join("a")),
        })).unwrap()).unwrap();
        let source = Arc::new(LeanAssignmentSource::with_interval(&file, Duration::from_secs(3_600)));
        let resolver = LakeIpContextResolver::with_source(Arc::clone(&source));
        assert_eq!(resolver_token(&resolver, b), None);
        std::fs::write(&file, serde_json::to_vec(&serde_json::json!({
            a.to_string(): assignment(9, &root.path().join("a")),
            b.to_string(): assignment(10, &root.path().join("b")),
        })).unwrap()).unwrap();
        source.reload();
        assert_eq!(resolver_token(&resolver, b), Some("b".repeat(32)));
        std::fs::write(&file, b"{ torn").unwrap();
        source.reload();
        assert_eq!(resolver_token(&resolver, a), Some("a".repeat(32)), "last good map kept");
    }

    /// Tolerating another tenant's missing token does not weaken aliasing:
    /// an entry naming this tenant's credential still refuses both.
    #[test]
    fn another_entry_still_may_not_alias_this_tenants_credential_or_origin() {
        let root = tempfile::tempdir().unwrap();
        let credential = root.path().join("a");
        std::fs::write(&credential, "a".repeat(32)).unwrap();
        let (a, b) = (Uuid::new_v4(), Uuid::new_v4());
        let file = root.path().join("assignments.json");
        for other in [assignment(10, &credential), serde_json::json!({"internal_endpoint": "http://127.0.0.1:9/", "credential_file": root.path().join("absent"), "timeout_secs": 30})] {
            std::fs::write(&file, serde_json::to_vec(&serde_json::json!({
                a.to_string(): assignment(9, &credential),
                b.to_string(): other,
            })).unwrap()).unwrap();
            assert!(LakeIpContextClient::from_lean_assignment_file(&file, a).is_err());
        }
    }
}
