// SPDX-License-Identifier: AGPL-3.0-or-later

//! Entra ID (Microsoft Graph) sync provider
//!
//! Uses OAuth2 client credentials to fetch users from MS Graph API.
//! Supports both full sync and delta (incremental) sync via delta queries.

use async_trait::async_trait;
use tracing::{info, instrument, warn};

use super::{SyncError, SyncProvider};
use crate::identity::types::{ConnectionTestResult, DeltaSyncResult, EntraIdCredentials};

pub struct EntraIdSync {
    client: reqwest::Client,
}

impl EntraIdSync {
    pub fn new() -> Self {
        Self {
            client: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(30))
                .build()
                .unwrap_or_default(),
        }
    }

    /// Obtain an OAuth2 access token using client credentials grant
    async fn get_access_token(&self, creds: &EntraIdCredentials) -> Result<String, SyncError> {
        let url = format!(
            "https://login.microsoftonline.com/{}/oauth2/v2.0/token",
            creds.tenant_id
        );

        let resp = self
            .client
            .post(&url)
            .form(&[
                ("grant_type", "client_credentials"),
                ("client_id", &creds.client_id),
                ("client_secret", &creds.client_secret),
                ("scope", "https://graph.microsoft.com/.default"),
            ])
            .send()
            .await
            .map_err(|e| SyncError::NetworkError(e.to_string()))?;

        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            return Err(SyncError::AuthError(format!(
                "Token request failed ({status}): {body}"
            )));
        }

        let token_resp: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| SyncError::ParseError(e.to_string()))?;

        token_resp["access_token"]
            .as_str()
            .map(|s| s.to_string())
            .ok_or_else(|| SyncError::AuthError("No access_token in response".to_string()))
    }

    /// The field selection for MS Graph user queries
    fn user_select_fields() -> &'static str {
        "id,userPrincipalName,mail,displayName,givenName,surname,department,jobTitle,\
         companyName,officeLocation,city,country,mobilePhone,employeeId,employeeType,\
         accountEnabled,createdDateTime,signInActivity"
    }

    /// Fetch a single page from the Graph API and return raw user objects + next URL
    async fn fetch_page(
        &self,
        token: &str,
        url: &str,
    ) -> Result<(Vec<serde_json::Value>, Option<String>), SyncError> {
        let resp = self
            .client
            .get(url)
            .bearer_auth(token)
            .header("ConsistencyLevel", "eventual")
            .send()
            .await
            .map_err(|e| SyncError::NetworkError(e.to_string()))?;

        if resp.status() == 429 {
            let retry_after = resp
                .headers()
                .get("Retry-After")
                .and_then(|v| v.to_str().ok())
                .and_then(|s| s.parse::<u64>().ok());
            return Err(SyncError::RateLimited {
                retry_after_secs: retry_after,
            });
        }

        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            return Err(SyncError::ApiError {
                status,
                message: body,
            });
        }

        let body: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| SyncError::ParseError(e.to_string()))?;

        let mut users = Vec::new();
        if let Some(values) = body["value"].as_array() {
            for user in values {
                users.push(user.clone());
            }
        }

        let next_url = body["@odata.nextLink"].as_str().map(|s| s.to_string());
        Ok((users, next_url))
    }

    /// Build the starting URL for a full sync
    fn build_full_sync_url(config: &serde_json::Value) -> String {
        let select = Self::user_select_fields();
        let mut url = format!(
            "https://graph.microsoft.com/v1.0/users?$select={}&$top=999",
            select
        );

        if let Some(domain) = config.get("domain_filter").and_then(|v| v.as_str()) {
            url.push_str(&format!(
                "&$filter=endsWith(userPrincipalName,'{}')",
                domain
            ));
        }

        url
    }
}

#[async_trait]
impl SyncProvider for EntraIdSync {
    #[instrument(skip(self, credentials, config))]
    async fn full_sync(
        &self,
        credentials: &serde_json::Value,
        config: &serde_json::Value,
    ) -> Result<Vec<serde_json::Value>, SyncError> {
        let creds: EntraIdCredentials = serde_json::from_value(credentials.clone())
            .map_err(|e| SyncError::InvalidCredentials(e.to_string()))?;

        let token = self.get_access_token(&creds).await?;
        let mut url = Self::build_full_sync_url(config);
        let mut all_users = Vec::new();

        loop {
            let (page, next) = self.fetch_page(&token, &url).await?;
            all_users.extend(page);
            match next {
                Some(next_url) => url = next_url,
                None => break,
            }
        }

        info!(user_count = all_users.len(), "Entra ID full sync complete");
        Ok(all_users)
    }

    #[instrument(skip(self, credentials, config, on_page))]
    async fn full_sync_paged(
        &self,
        credentials: &serde_json::Value,
        config: &serde_json::Value,
        on_page: super::PageCallback<'_>,
    ) -> Result<u64, SyncError> {
        let creds: EntraIdCredentials = serde_json::from_value(credentials.clone())
            .map_err(|e| SyncError::InvalidCredentials(e.to_string()))?;

        let token = self.get_access_token(&creds).await?;
        let mut url = Self::build_full_sync_url(config);
        let mut total = 0u64;

        loop {
            let (page, next) = self.fetch_page(&token, &url).await?;
            let page_size = page.len();
            total += on_page(page).await?;

            info!(page_size, total, "Entra ID sync page processed");

            match next {
                Some(next_url) => url = next_url,
                None => break,
            }
        }

        info!(total, "Entra ID paged full sync complete");
        Ok(total)
    }

    #[instrument(skip(self, credentials, _config))]
    async fn delta_sync(
        &self,
        credentials: &serde_json::Value,
        _config: &serde_json::Value,
        delta_link: Option<&str>,
    ) -> Result<Option<DeltaSyncResult>, SyncError> {
        let delta_link = match delta_link {
            Some(link) => link,
            None => return Ok(None), // No delta link, fall back to full sync
        };

        let creds: EntraIdCredentials = serde_json::from_value(credentials.clone())
            .map_err(|e| SyncError::InvalidCredentials(e.to_string()))?;

        let token = self.get_access_token(&creds).await?;

        let mut users = Vec::new();
        let mut url = delta_link.to_string();
        let mut new_delta_link = None;

        loop {
            let resp = self
                .client
                .get(&url)
                .bearer_auth(&token)
                .header("ConsistencyLevel", "eventual")
                .send()
                .await
                .map_err(|e| SyncError::NetworkError(e.to_string()))?;

            if resp.status() == 429 {
                let retry_after = resp
                    .headers()
                    .get("Retry-After")
                    .and_then(|v| v.to_str().ok())
                    .and_then(|s| s.parse::<u64>().ok());
                return Err(SyncError::RateLimited {
                    retry_after_secs: retry_after,
                });
            }

            if !resp.status().is_success() {
                // Delta link may be expired — caller should fall back to full sync
                warn!(
                    "Delta sync failed ({}), caller should fall back to full sync",
                    resp.status()
                );
                return Ok(None);
            }

            let body: serde_json::Value = resp
                .json()
                .await
                .map_err(|e| SyncError::ParseError(e.to_string()))?;

            if let Some(values) = body["value"].as_array() {
                for user in values {
                    users.push(user.clone());
                }
            }

            // Check for delta link (final page) vs next link (more pages)
            if let Some(delta) = body["@odata.deltaLink"].as_str() {
                new_delta_link = Some(delta.to_string());
                break;
            } else if let Some(next) = body["@odata.nextLink"].as_str() {
                url = next.to_string();
            } else {
                break;
            }
        }

        info!(user_count = users.len(), "Entra ID delta sync complete");
        Ok(Some(DeltaSyncResult {
            users,
            new_delta_link,
        }))
    }

    #[instrument(skip(self, credentials))]
    async fn test_connection(
        &self,
        credentials: &serde_json::Value,
    ) -> Result<ConnectionTestResult, SyncError> {
        let start = std::time::Instant::now();

        let creds: EntraIdCredentials = serde_json::from_value(credentials.clone())
            .map_err(|e| SyncError::InvalidCredentials(e.to_string()))?;

        let token = match self.get_access_token(&creds).await {
            Ok(t) => t,
            Err(e) => {
                return Ok(ConnectionTestResult {
                    success: false,
                    response_time_ms: Some(start.elapsed().as_millis() as u64),
                    error: Some(e.to_string()),
                    user_count_sample: None,
                });
            }
        };

        // Try fetching a small number of users to verify permissions
        let resp = self
            .client
            .get("https://graph.microsoft.com/v1.0/users?$top=1&$select=id")
            .bearer_auth(&token)
            .send()
            .await
            .map_err(|e| SyncError::NetworkError(e.to_string()))?;

        let elapsed = start.elapsed().as_millis() as u64;

        if resp.status().is_success() {
            // Get approximate user count
            let count_resp = self
                .client
                .get("https://graph.microsoft.com/v1.0/users/$count")
                .bearer_auth(&token)
                .header("ConsistencyLevel", "eventual")
                .send()
                .await
                .ok()
                .and_then(|r| {
                    if r.status().is_success() {
                        Some(r)
                    } else {
                        None
                    }
                });

            let user_count = if let Some(r) = count_resp {
                r.text()
                    .await
                    .ok()
                    .and_then(|t| t.trim().parse::<u64>().ok())
            } else {
                None
            };

            Ok(ConnectionTestResult {
                success: true,
                response_time_ms: Some(elapsed),
                error: None,
                user_count_sample: user_count,
            })
        } else {
            let body = resp.text().await.unwrap_or_default();
            Ok(ConnectionTestResult {
                success: false,
                response_time_ms: Some(elapsed),
                error: Some(format!("API error: {}", body)),
                user_count_sample: None,
            })
        }
    }
}
