// SPDX-License-Identifier: AGPL-3.0-or-later

//! Typed client for the tenant-pinned identity directory owned by Nano's
//! existing lake enrichment coordinator.

use super::{ListUsersParams, UserListResponse, UserRecord};
use crate::lake_http::LakeRequestBuilderExt;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::time::Duration;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum LakeIdentityError {
    #[error("lake identity configuration error: {0}")]
    Configuration(String),
    #[error("lake identity request failed: {0}")]
    Request(String),
    #[error("lake identity response failed its tenant or shape contract")]
    ResponseContract,
}

#[derive(Debug, Clone, Deserialize)]
pub struct LakeIdentityCounts {
    pub total_users: i64,
    pub active_users: i64,
    pub disabled_users: i64,
    pub provider_counts: HashMap<String, i64>,
}

#[derive(Clone)]
pub struct LakeIdentityClient {
    http: reqwest::Client,
    base_url: String,
    tenant_id: String,
    bearer_token: String,
}

impl LakeIdentityClient {
    pub fn from_env() -> Result<Self, LakeIdentityError> {
        let base_url = required_env("NANO_LAKE_ENRICHMENT_COORDINATOR_URL")?;
        let parsed = reqwest::Url::parse(&base_url).map_err(|error| {
            LakeIdentityError::Configuration(format!(
                "invalid NANO_LAKE_ENRICHMENT_COORDINATOR_URL: {error}"
            ))
        })?;
        if !matches!(parsed.scheme(), "http" | "https")
            || !parsed.username().is_empty()
            || parsed.password().is_some()
            || parsed.query().is_some()
            || parsed.fragment().is_some()
            || parsed.path() != "/"
        {
            return Err(LakeIdentityError::Configuration(
                "NANO_LAKE_ENRICHMENT_COORDINATOR_URL must be an HTTP(S) origin without credentials, query, fragment, or path".to_string(),
            ));
        }
        let tenant_id = required_env("NANO_LAKE_TENANT_ID")?;
        validate_identity("NANO_LAKE_TENANT_ID", &tenant_id)?;
        let token_path =
            PathBuf::from(required_env("NANO_LAKE_ENRICHMENT_COORDINATOR_TOKEN_FILE")?);
        let bearer_token = std::fs::read_to_string(&token_path)
            .map_err(|error| {
                LakeIdentityError::Configuration(format!(
                    "failed to read {}: {error}",
                    token_path.display()
                ))
            })?
            .trim()
            .to_string();
        if bearer_token.len() < 32 {
            return Err(LakeIdentityError::Configuration(
                "lake enrichment token must contain at least 32 bytes".to_string(),
            ));
        }
        let timeout_secs = std::env::var("NANO_LAKE_IDENTITY_TIMEOUT_SECS")
            .ok()
            .filter(|value| !value.trim().is_empty())
            .map(|value| {
                value.parse::<u64>().map_err(|_| {
                    LakeIdentityError::Configuration(
                        "NANO_LAKE_IDENTITY_TIMEOUT_SECS must be an integer".to_string(),
                    )
                })
            })
            .transpose()?
            .unwrap_or(30);
        if !(1..=300).contains(&timeout_secs) {
            return Err(LakeIdentityError::Configuration(
                "NANO_LAKE_IDENTITY_TIMEOUT_SECS must be between 1 and 300".to_string(),
            ));
        }
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(timeout_secs))
            .build()
            .map_err(|error| LakeIdentityError::Configuration(error.to_string()))?;
        Ok(Self {
            http,
            base_url: base_url.trim_end_matches('/').to_string(),
            tenant_id,
            bearer_token,
        })
    }

    pub async fn list(
        &self,
        params: &ListUsersParams,
    ) -> Result<UserListResponse, LakeIdentityError> {
        let mut query = vec![
            ("tenant_id", self.tenant_id.clone()),
            ("page", params.page.to_string()),
            ("page_size", params.page_size.to_string()),
        ];
        if let Some(value) = &params.provider_id {
            query.push(("provider_id", value.clone()));
        }
        if let Some(value) = &params.search {
            query.push(("search", value.clone()));
        }
        if let Some(value) = &params.account_status {
            query.push(("account_status", value.clone()));
        }
        let result: UserListResponse = self.get("/v1/identity/users", &query).await?;
        if result.page != params.page.max(1)
            || result.page_size != params.page_size
            || result.users.len() > params.page_size.max(0) as usize
            || result.total < result.users.len() as i64
        {
            return Err(LakeIdentityError::ResponseContract);
        }
        Ok(result)
    }

    pub async fn lookup(&self, identifier: &str) -> Result<Option<UserRecord>, LakeIdentityError> {
        if identifier.is_empty()
            || identifier.len() > 2_048
            || identifier.chars().any(char::is_control)
        {
            return Err(LakeIdentityError::Configuration(
                "identity lookup value is invalid".to_string(),
            ));
        }
        self.get(
            "/v1/identity/users/lookup",
            &[
                ("tenant_id", self.tenant_id.clone()),
                ("q", identifier.to_string()),
            ],
        )
        .await
    }

    pub async fn get_user(
        &self,
        provider_id: &str,
        external_id: &str,
    ) -> Result<Option<UserRecord>, LakeIdentityError> {
        self.get(
            "/v1/identity/users/get",
            &[
                ("tenant_id", self.tenant_id.clone()),
                ("provider_id", provider_id.to_string()),
                ("external_id", external_id.to_string()),
            ],
        )
        .await
    }

    pub async fn count(&self, provider_id: &str) -> Result<i64, LakeIdentityError> {
        let count: i64 = self
            .get(
                "/v1/identity/users/count",
                &[
                    ("tenant_id", self.tenant_id.clone()),
                    ("provider_id", provider_id.to_string()),
                ],
            )
            .await?;
        if count < 0 {
            return Err(LakeIdentityError::ResponseContract);
        }
        Ok(count)
    }

    pub async fn counts(&self) -> Result<LakeIdentityCounts, LakeIdentityError> {
        let counts: LakeIdentityCounts = self
            .get(
                "/v1/identity/stats",
                &[("tenant_id", self.tenant_id.clone())],
            )
            .await?;
        if counts.total_users < 0
            || counts.active_users < 0
            || counts.disabled_users < 0
            || counts.provider_counts.values().any(|count| *count < 0)
        {
            return Err(LakeIdentityError::ResponseContract);
        }
        Ok(counts)
    }

    pub async fn reconcile(
        &self,
        provider_id: &str,
        cutoff: DateTime<Utc>,
    ) -> Result<u64, LakeIdentityError> {
        validate_identity("provider_id", provider_id)?;
        let response = self
            .http
            .post(format!(
                "{}/v1/identity/providers/{provider_id}/reconcile",
                self.base_url
            ))
            .bearer_auth(&self.bearer_token)
            .json(&ReconcileRequest {
                tenant_id: &self.tenant_id,
                cutoff,
            })
            .send_idempotent_with_recovery()
            .await
            .map_err(|error| LakeIdentityError::Request(error.to_string()))?;
        let envelope: TenantResponse<PublicationResult> = decode_response(response).await?;
        self.validate_tenant(&envelope.tenant_id)?;
        u64::try_from(envelope.result.changed).map_err(|_| LakeIdentityError::ResponseContract)
    }

    pub async fn delete_provider(&self, provider_id: &str) -> Result<u64, LakeIdentityError> {
        validate_identity("provider_id", provider_id)?;
        let response = self
            .http
            .delete(format!(
                "{}/v1/identity/providers/{provider_id}",
                self.base_url
            ))
            .bearer_auth(&self.bearer_token)
            .json(&TenantOnlyRequest {
                tenant_id: &self.tenant_id,
            })
            .send_idempotent_with_recovery()
            .await
            .map_err(|error| LakeIdentityError::Request(error.to_string()))?;
        let envelope: TenantResponse<PublicationResult> = decode_response(response).await?;
        self.validate_tenant(&envelope.tenant_id)?;
        u64::try_from(envelope.result.changed).map_err(|_| LakeIdentityError::ResponseContract)
    }

    async fn get<T: serde::de::DeserializeOwned>(
        &self,
        path: &str,
        query: &[(&str, String)],
    ) -> Result<T, LakeIdentityError> {
        let response = self
            .http
            .get(format!("{}{}", self.base_url, path))
            .bearer_auth(&self.bearer_token)
            .query(query)
            .send()
            .await
            .map_err(|error| LakeIdentityError::Request(error.to_string()))?;
        let envelope: TenantResponse<T> = decode_response(response).await?;
        self.validate_tenant(&envelope.tenant_id)?;
        Ok(envelope.result)
    }

    fn validate_tenant(&self, returned: &str) -> Result<(), LakeIdentityError> {
        if returned == self.tenant_id {
            Ok(())
        } else {
            Err(LakeIdentityError::ResponseContract)
        }
    }
}

#[derive(Deserialize)]
struct TenantResponse<T> {
    tenant_id: String,
    result: T,
}

#[derive(Serialize)]
struct ReconcileRequest<'a> {
    tenant_id: &'a str,
    cutoff: DateTime<Utc>,
}

#[derive(Serialize)]
struct TenantOnlyRequest<'a> {
    tenant_id: &'a str,
}

#[derive(Deserialize)]
struct PublicationResult {
    changed: usize,
}

async fn decode_response<T: serde::de::DeserializeOwned>(
    response: reqwest::Response,
) -> Result<T, LakeIdentityError> {
    let status = response.status();
    let bytes = response
        .bytes()
        .await
        .map_err(|error| LakeIdentityError::Request(error.to_string()))?;
    if !status.is_success() {
        let detail = serde_json::from_slice::<serde_json::Value>(&bytes)
            .ok()
            .and_then(|value| {
                value
                    .get("error")
                    .and_then(|value| value.as_str())
                    .map(str::to_string)
            })
            .unwrap_or_else(|| String::from_utf8_lossy(&bytes).to_string());
        return Err(LakeIdentityError::Request(format!(
            "HTTP {status}: {detail}"
        )));
    }
    serde_json::from_slice(&bytes)
        .map_err(|error| LakeIdentityError::Request(format!("invalid JSON response: {error}")))
}

fn required_env(name: &str) -> Result<String, LakeIdentityError> {
    std::env::var(name)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .ok_or_else(|| LakeIdentityError::Configuration(format!("{name} is required")))
}

fn validate_identity(name: &str, value: &str) -> Result<(), LakeIdentityError> {
    if value.is_empty()
        || value.len() > 256
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"_.:-".contains(&byte))
    {
        return Err(LakeIdentityError::Configuration(format!(
            "{name} is invalid"
        )));
    }
    Ok(())
}
