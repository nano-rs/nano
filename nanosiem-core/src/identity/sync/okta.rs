// SPDX-License-Identifier: AGPL-3.0-or-later

//! Okta sync provider
//!
//! Uses the Okta Users API with SSWS token authentication.
//! Supports full sync and delta sync via `lastUpdated` filter.

use async_trait::async_trait;
use sha2::{Digest, Sha256};
use tracing::{info, instrument};

use super::{SyncError, SyncProvider};
use crate::identity::types::{
    ConnectionTestResult, DeltaSyncResult, OktaCredentials, UserRecordUpsert,
};

pub struct OktaSync {
    client: reqwest::Client,
}

impl OktaSync {
    pub fn new() -> Self {
        Self {
            client: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(30))
                .build()
                .unwrap_or_default(),
        }
    }

    /// Build the base URL for the Okta Users API
    fn users_url(domain: &str) -> String {
        format!("https://{}/api/v1/users", domain)
    }

    /// Convert an Okta user JSON object to a UserRecordUpsert
    fn map_okta_user(user: &serde_json::Value) -> Option<UserRecordUpsert> {
        let external_id = user["id"].as_str()?.to_string();
        let profile = &user["profile"];

        let login = profile["login"].as_str().map(|s| s.to_string());
        let username = login
            .as_ref()
            .map(|l| l.split('@').next().unwrap_or(l).to_string());

        let display_name = profile["displayName"]
            .as_str()
            .map(|s| s.to_string())
            .or_else(|| {
                let first = profile["firstName"].as_str().unwrap_or("");
                let last = profile["lastName"].as_str().unwrap_or("");
                if first.is_empty() && last.is_empty() {
                    None
                } else {
                    Some(format!("{} {}", first, last).trim().to_string())
                }
            });

        let account_enabled = user["status"].as_str().map_or(true, |s| s == "ACTIVE");
        let account_status = if account_enabled {
            "active"
        } else {
            "disabled"
        }
        .to_string();

        let last_login = user["lastLogin"]
            .as_str()
            .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
            .map(|dt| dt.with_timezone(&chrono::Utc));

        let created_at = user["created"]
            .as_str()
            .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
            .map(|dt| dt.with_timezone(&chrono::Utc));

        // Compute sync hash from the raw user object
        let raw = serde_json::to_string(user).unwrap_or_default();
        let hash = hex::encode(Sha256::digest(raw.as_bytes()));

        Some(UserRecordUpsert {
            external_id,
            username,
            upn: login,
            email: profile["email"].as_str().map(|s| s.to_string()),
            display_name,
            first_name: profile["firstName"].as_str().map(|s| s.to_string()),
            last_name: profile["lastName"].as_str().map(|s| s.to_string()),
            department: profile["department"].as_str().map(|s| s.to_string()),
            title: profile["title"].as_str().map(|s| s.to_string()),
            manager_upn: profile["manager"].as_str().map(|s| s.to_string()),
            manager_display_name: None,
            company: profile["organization"].as_str().map(|s| s.to_string()),
            office_location: None,
            city: profile["city"].as_str().map(|s| s.to_string()),
            country: profile["countryCode"].as_str().map(|s| s.to_string()),
            groups: Vec::new(), // Requires per-user API call — skipped for now
            account_enabled,
            account_status,
            mfa_enabled: None, // Requires per-user factors API — skipped for now
            last_sign_in_at: last_login,
            created_in_directory_at: created_at,
            phone: profile["mobilePhone"].as_str().map(|s| s.to_string()),
            employee_id: profile["employeeNumber"].as_str().map(|s| s.to_string()),
            employee_type: profile["userType"].as_str().map(|s| s.to_string()),
            sync_hash: hash,
        })
    }

    /// Parse the `after` cursor from the Link header for pagination.
    /// Okta returns: `<https://domain/api/v1/users?after=xyz>; rel="next"`
    fn parse_next_link(headers: &reqwest::header::HeaderMap) -> Option<String> {
        let link = headers.get("link")?.to_str().ok()?;
        for part in link.split(',') {
            let part = part.trim();
            if part.contains("rel=\"next\"") {
                // Extract URL between < and >
                let start = part.find('<')? + 1;
                let end = part.find('>')?;
                return Some(part[start..end].to_string());
            }
        }
        None
    }

    /// Fetch a single page from the Okta API and return parsed users + next URL
    async fn fetch_page(
        &self,
        creds: &OktaCredentials,
        url: &str,
    ) -> Result<(Vec<UserRecordUpsert>, Option<String>), SyncError> {
        let resp = self
            .client
            .get(url)
            .header("Authorization", format!("SSWS {}", creds.api_token))
            .header("Accept", "application/json")
            .send()
            .await
            .map_err(|e| SyncError::NetworkError(e.to_string()))?;

        if resp.status().as_u16() == 429 {
            let retry_after = resp
                .headers()
                .get("x-rate-limit-reset")
                .and_then(|v| v.to_str().ok())
                .and_then(|s| s.parse::<u64>().ok())
                .map(|epoch| {
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs();
                    epoch.saturating_sub(now)
                });
            return Err(SyncError::RateLimited {
                retry_after_secs: retry_after,
            });
        }

        if resp.status().as_u16() == 401 {
            let body = resp.text().await.unwrap_or_default();
            return Err(SyncError::AuthError(format!(
                "Authentication failed: {}",
                body
            )));
        }

        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            return Err(SyncError::ApiError {
                status,
                message: body,
            });
        }

        let next_url = Self::parse_next_link(resp.headers());

        let body: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| SyncError::ParseError(e.to_string()))?;

        let mut users = Vec::new();
        if let Some(arr) = body.as_array() {
            for user in arr {
                if let Some(record) = Self::map_okta_user(user) {
                    users.push(record);
                }
            }
        }

        Ok((users, next_url))
    }
}

#[async_trait]
impl SyncProvider for OktaSync {
    #[instrument(skip(self, credentials, _config))]
    async fn full_sync(
        &self,
        credentials: &serde_json::Value,
        _config: &serde_json::Value,
    ) -> Result<Vec<UserRecordUpsert>, SyncError> {
        let creds: OktaCredentials = serde_json::from_value(credentials.clone())
            .map_err(|e| SyncError::InvalidCredentials(e.to_string()))?;

        let mut url = format!("{}?limit=200", Self::users_url(&creds.domain));
        let mut all_users = Vec::new();

        loop {
            let (page, next) = self.fetch_page(&creds, &url).await?;
            all_users.extend(page);
            match next {
                Some(next_url) => url = next_url,
                None => break,
            }
        }

        info!(user_count = all_users.len(), "Okta full sync complete");
        Ok(all_users)
    }

    #[instrument(skip(self, credentials, _config, on_page))]
    async fn full_sync_paged(
        &self,
        credentials: &serde_json::Value,
        _config: &serde_json::Value,
        on_page: super::PageCallback<'_>,
    ) -> Result<u64, SyncError> {
        let creds: OktaCredentials = serde_json::from_value(credentials.clone())
            .map_err(|e| SyncError::InvalidCredentials(e.to_string()))?;

        let mut url = format!("{}?limit=200", Self::users_url(&creds.domain));
        let mut total = 0u64;

        loop {
            let (page, next) = self.fetch_page(&creds, &url).await?;
            let page_size = page.len();
            total += on_page(page).await?;

            info!(page_size, total, "Okta sync page processed");

            match next {
                Some(next_url) => url = next_url,
                None => break,
            }
        }

        info!(total, "Okta paged full sync complete");
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
            None => return Ok(None),
        };

        let creds: OktaCredentials = serde_json::from_value(credentials.clone())
            .map_err(|e| SyncError::InvalidCredentials(e.to_string()))?;

        // delta_link is the ISO timestamp of the last sync
        let mut url = format!(
            "{}?filter=lastUpdated gt \"{}\"&limit=200",
            Self::users_url(&creds.domain),
            delta_link
        );

        // Delta syncs are bounded (only changed users), safe to collect
        let mut users = Vec::new();
        loop {
            let (page, next) = self.fetch_page(&creds, &url).await?;
            users.extend(page);
            match next {
                Some(next_url) => url = next_url,
                None => break,
            }
        }

        // New delta link = current time in ISO format
        let new_delta_link = chrono::Utc::now().to_rfc3339();

        info!(user_count = users.len(), "Okta delta sync complete");
        Ok(Some(DeltaSyncResult {
            users,
            new_delta_link: Some(new_delta_link),
        }))
    }

    #[instrument(skip(self, credentials))]
    async fn test_connection(
        &self,
        credentials: &serde_json::Value,
    ) -> Result<ConnectionTestResult, SyncError> {
        let start = std::time::Instant::now();

        let creds: OktaCredentials = serde_json::from_value(credentials.clone())
            .map_err(|e| SyncError::InvalidCredentials(e.to_string()))?;

        let url = format!("{}?limit=1", Self::users_url(&creds.domain));
        let resp = self
            .client
            .get(&url)
            .header("Authorization", format!("SSWS {}", creds.api_token))
            .header("Accept", "application/json")
            .send()
            .await;

        let elapsed = start.elapsed().as_millis() as u64;

        match resp {
            Ok(r) if r.status().is_success() => Ok(ConnectionTestResult {
                success: true,
                response_time_ms: Some(elapsed),
                error: None,
                user_count_sample: None,
            }),
            Ok(r) => {
                let status = r.status().as_u16();
                let body = r.text().await.unwrap_or_default();
                Ok(ConnectionTestResult {
                    success: false,
                    response_time_ms: Some(elapsed),
                    error: Some(format!("API error ({}): {}", status, body)),
                    user_count_sample: None,
                })
            }
            Err(e) => Ok(ConnectionTestResult {
                success: false,
                response_time_ms: Some(elapsed),
                error: Some(e.to_string()),
                user_count_sample: None,
            }),
        }
    }
}
