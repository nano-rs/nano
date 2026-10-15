// SPDX-License-Identifier: AGPL-3.0-or-later

//! Tenant-pinned client for bounded Vector collector diagnostics in lake mode.

use super::CollectorError;
use serde::Deserialize;
use std::path::PathBuf;
use std::time::Duration;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum LakeCollectorDiagnosticsError {
    #[error("lake collector diagnostics configuration error: {0}")]
    Configuration(String),
    #[error("lake collector diagnostics request failed: {0}")]
    Request(String),
    #[error("lake collector diagnostics response failed its tenant contract")]
    ResponseContract,
}

#[derive(Debug, Deserialize)]
pub struct LakeCollectorDiagnostics {
    pub errors: Vec<CollectorError>,
    pub total_24h: i64,
}

#[derive(Clone)]
pub struct LakeCollectorDiagnosticsClient {
    http: reqwest::Client,
    base_url: String,
    tenant_id: String,
    bearer_token: String,
}

impl LakeCollectorDiagnosticsClient {
    pub fn from_env() -> Result<Self, LakeCollectorDiagnosticsError> {
        let base_url = required_env("NANO_LAKE_ENRICHMENT_COORDINATOR_URL")?;
        let parsed = reqwest::Url::parse(&base_url).map_err(|error| {
            LakeCollectorDiagnosticsError::Configuration(format!(
                "invalid coordinator URL: {error}"
            ))
        })?;
        if !matches!(parsed.scheme(), "http" | "https")
            || !parsed.username().is_empty()
            || parsed.password().is_some()
            || parsed.query().is_some()
            || parsed.fragment().is_some()
            || parsed.path() != "/"
        {
            return Err(LakeCollectorDiagnosticsError::Configuration(
                "coordinator URL must be an HTTP(S) origin without credentials, query, fragment, or path"
                    .to_string(),
            ));
        }
        let tenant_id = required_env("NANO_LAKE_TENANT_ID")?;
        let token_path =
            PathBuf::from(required_env("NANO_LAKE_ENRICHMENT_COORDINATOR_TOKEN_FILE")?);
        let bearer_token = std::fs::read_to_string(&token_path)
            .map_err(|error| {
                LakeCollectorDiagnosticsError::Configuration(format!(
                    "failed to read {}: {error}",
                    token_path.display()
                ))
            })?
            .trim()
            .to_string();
        if bearer_token.len() < 32 {
            return Err(LakeCollectorDiagnosticsError::Configuration(
                "lake enrichment token must contain at least 32 bytes".to_string(),
            ));
        }
        Ok(Self {
            http: reqwest::Client::builder()
                .timeout(Duration::from_secs(10))
                .build()
                .map_err(|error| LakeCollectorDiagnosticsError::Configuration(error.to_string()))?,
            base_url: base_url.trim_end_matches('/').to_string(),
            tenant_id,
            bearer_token,
        })
    }

    pub async fn list(
        &self,
        component_id: &str,
        limit: usize,
    ) -> Result<LakeCollectorDiagnostics, LakeCollectorDiagnosticsError> {
        if component_id.is_empty()
            || component_id.len() > 512
            || component_id.chars().any(char::is_control)
            || !(1..=100).contains(&limit)
        {
            return Err(LakeCollectorDiagnosticsError::Configuration(
                "collector component or limit is invalid".to_string(),
            ));
        }
        let limit_value = limit;
        let limit = limit.to_string();
        let response = self
            .http
            .get(format!("{}/v1/collector-errors", self.base_url))
            .bearer_auth(&self.bearer_token)
            .query(&[
                ("tenant_id", self.tenant_id.as_str()),
                ("component_id", component_id),
                ("limit", limit.as_str()),
            ])
            .send()
            .await
            .map_err(|error| LakeCollectorDiagnosticsError::Request(error.to_string()))?;
        let status = response.status();
        let bytes = response
            .bytes()
            .await
            .map_err(|error| LakeCollectorDiagnosticsError::Request(error.to_string()))?;
        if !status.is_success() {
            return Err(LakeCollectorDiagnosticsError::Request(format!(
                "HTTP {status}: {}",
                String::from_utf8_lossy(&bytes)
            )));
        }
        let envelope: TenantResponse<LakeCollectorDiagnostics> = serde_json::from_slice(&bytes)
            .map_err(|error| {
                LakeCollectorDiagnosticsError::Request(format!("invalid JSON response: {error}"))
            })?;
        if envelope.tenant_id != self.tenant_id
            || envelope.result.total_24h < envelope.result.errors.len() as i64
            || envelope.result.errors.len() > limit_value
        {
            return Err(LakeCollectorDiagnosticsError::ResponseContract);
        }
        Ok(envelope.result)
    }
}

#[derive(Deserialize)]
struct TenantResponse<T> {
    tenant_id: String,
    result: T,
}

fn required_env(name: &str) -> Result<String, LakeCollectorDiagnosticsError> {
    std::env::var(name)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .ok_or_else(|| LakeCollectorDiagnosticsError::Configuration(format!("{name} is required")))
}
