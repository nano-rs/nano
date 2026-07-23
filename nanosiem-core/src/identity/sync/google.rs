// SPDX-License-Identifier: AGPL-3.0-or-later

//! Google Workspace (Admin SDK) sync provider
//!
//! Uses service account JWT authentication with domain-wide delegation
//! to fetch users from the Google Admin Directory API.

use async_trait::async_trait;
use tracing::{info, instrument};

use super::{SyncError, SyncProvider};
use crate::identity::types::{
    ConnectionTestResult, DeltaSyncResult, GoogleWorkspaceCredentials,
};

pub struct GoogleWorkspaceSync;

/// NAN-1196: percent-encode a credential-supplied value before interpolating it
/// into a Google Directory API query string, so it cannot inject additional
/// query parameters (the host is the fixed `admin.googleapis.com`).
fn enc(s: &str) -> String {
    url::form_urlencoded::byte_serialize(s.as_bytes()).collect()
}

impl GoogleWorkspaceSync {
    pub fn new() -> Self {
        Self
    }

    /// Obtain an access token using JWT service account authentication.
    ///
    /// This uses the service_account_json credentials with domain-wide delegation
    /// impersonating the admin_email to access the Directory API.
    async fn get_access_token(
        &self,
        creds: &GoogleWorkspaceCredentials,
    ) -> Result<String, SyncError> {
        // Parse the service account JSON to extract private key and client email
        let sa: serde_json::Value =
            serde_json::from_str(&creds.service_account_json).map_err(|e| {
                SyncError::InvalidCredentials(format!("Invalid service account JSON: {}", e))
            })?;

        let client_email = sa["client_email"].as_str().ok_or_else(|| {
            SyncError::InvalidCredentials("Missing client_email in service account JSON".into())
        })?;

        let private_key_pem = sa["private_key"].as_str().ok_or_else(|| {
            SyncError::InvalidCredentials("Missing private_key in service account JSON".into())
        })?;

        // NAN-1196: pin the Google token endpoint rather than trusting the
        // uploaded service-account JSON's `token_uri` — an attacker-supplied
        // value would otherwise receive the signed JWT assertion (SSRF +
        // assertion capture). Real Google service accounts always use this URL,
        // and it is also the `aud` the assertion must be minted for.
        let token_uri = "https://oauth2.googleapis.com/token";

        // Build and sign JWT using jsonwebtoken crate
        let now = chrono::Utc::now().timestamp() as u64;
        let claims = serde_json::json!({
            "iss": client_email,
            "sub": creds.admin_email,
            "scope": "https://www.googleapis.com/auth/admin.directory.user.readonly https://www.googleapis.com/auth/admin.directory.group.readonly",
            "aud": token_uri,
            "iat": now,
            "exp": now + 3600,
        });

        let encoding_key = jsonwebtoken::EncodingKey::from_rsa_pem(private_key_pem.as_bytes())
            .map_err(|e| {
                SyncError::InvalidCredentials(format!("Invalid RSA private key: {}", e))
            })?;

        let header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256);
        let jwt = jsonwebtoken::encode(&header, &claims, &encoding_key)
            .map_err(|e| SyncError::InvalidCredentials(format!("JWT signing failed: {}", e)))?;

        // Exchange JWT for access token
        let (client, dial_url) =
            super::guarded_client(token_uri, std::time::Duration::from_secs(30)).await?;
        let resp = client
            .post(dial_url)
            .form(&[
                ("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"),
                ("assertion", &jwt),
            ])
            .send()
            .await
            .map_err(|e| SyncError::NetworkError(e.to_string()))?;

        if !resp.status().is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(SyncError::AuthError(format!(
                "Token exchange failed: {}",
                body
            )));
        }

        let token_resp: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| SyncError::ParseError(e.to_string()))?;

        token_resp["access_token"]
            .as_str()
            .map(|s| s.to_string())
            .ok_or_else(|| SyncError::AuthError("No access_token in response".into()))
    }

    /// Fetch a single page from the Google Directory API
    async fn fetch_page(
        &self,
        token: &str,
        domain: &str,
        page_token: Option<&str>,
    ) -> Result<(Vec<serde_json::Value>, Option<String>), SyncError> {
        let mut url = format!(
            "https://admin.googleapis.com/admin/directory/v1/users?customer=my_customer&domain={}&maxResults=500&projection=full",
            enc(domain)
        );
        if let Some(pt) = page_token {
            url.push_str(&format!("&pageToken={}", pt));
        }

        let (client, url) =
            super::guarded_client(&url, std::time::Duration::from_secs(30)).await?;
        let resp = client
            .get(url)
            .bearer_auth(token)
            .send()
            .await
            .map_err(|e| SyncError::NetworkError(e.to_string()))?;

        if resp.status() == 429 {
            return Err(SyncError::RateLimited {
                retry_after_secs: Some(60),
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
        if let Some(user_list) = body["users"].as_array() {
            for user in user_list {
                users.push(user.clone());
            }
        }

        let next = body["nextPageToken"].as_str().map(|s| s.to_string());
        Ok((users, next))
    }
}

#[async_trait]
impl SyncProvider for GoogleWorkspaceSync {
    #[instrument(skip(self, credentials, config))]
    async fn full_sync(
        &self,
        credentials: &serde_json::Value,
        config: &serde_json::Value,
    ) -> Result<Vec<serde_json::Value>, SyncError> {
        let creds: GoogleWorkspaceCredentials = serde_json::from_value(credentials.clone())
            .map_err(|e| SyncError::InvalidCredentials(e.to_string()))?;

        let token = self.get_access_token(&creds).await?;
        let domain = config
            .get("domain_filter")
            .and_then(|v| v.as_str())
            .unwrap_or(&creds.domain)
            .to_string();

        let mut all_users = Vec::new();
        let mut page_token: Option<String> = None;

        loop {
            let (page, next) = self
                .fetch_page(&token, &domain, page_token.as_deref())
                .await?;
            all_users.extend(page);
            match next {
                Some(t) => page_token = Some(t),
                None => break,
            }
        }

        info!(
            user_count = all_users.len(),
            "Google Workspace full sync complete"
        );
        Ok(all_users)
    }

    #[instrument(skip(self, credentials, config, on_page))]
    async fn full_sync_paged(
        &self,
        credentials: &serde_json::Value,
        config: &serde_json::Value,
        on_page: super::PageCallback<'_>,
    ) -> Result<u64, SyncError> {
        let creds: GoogleWorkspaceCredentials = serde_json::from_value(credentials.clone())
            .map_err(|e| SyncError::InvalidCredentials(e.to_string()))?;

        let token = self.get_access_token(&creds).await?;
        let domain = config
            .get("domain_filter")
            .and_then(|v| v.as_str())
            .unwrap_or(&creds.domain)
            .to_string();

        let mut total = 0u64;
        let mut page_token: Option<String> = None;

        loop {
            let (page, next) = self
                .fetch_page(&token, &domain, page_token.as_deref())
                .await?;
            let page_size = page.len();
            total += on_page(page).await?;

            info!(page_size, total, "Google Workspace sync page processed");

            match next {
                Some(t) => page_token = Some(t),
                None => break,
            }
        }

        info!(total, "Google Workspace paged full sync complete");
        Ok(total)
    }

    #[instrument(skip(self, credentials, config))]
    async fn delta_sync(
        &self,
        credentials: &serde_json::Value,
        config: &serde_json::Value,
        delta_link: Option<&str>,
    ) -> Result<Option<DeltaSyncResult>, SyncError> {
        // Google Workspace uses updatedMin parameter for pseudo-delta sync.
        // The delta_link stores the last sync timestamp as an RFC3339 string.
        let updated_min = match delta_link {
            Some(link) => link,
            None => return Ok(None),
        };

        let creds: GoogleWorkspaceCredentials = serde_json::from_value(credentials.clone())
            .map_err(|e| SyncError::InvalidCredentials(e.to_string()))?;

        let token = self.get_access_token(&creds).await?;

        let domain = config
            .get("domain_filter")
            .and_then(|v| v.as_str())
            .unwrap_or(&creds.domain);

        let mut users = Vec::new();
        let mut page_token: Option<String> = None;

        loop {
            let mut url = format!(
                "https://admin.googleapis.com/admin/directory/v1/users?customer=my_customer&domain={}&maxResults=500&projection=full&query=updatedMin='{}'",
                enc(domain), updated_min
            );
            if let Some(ref token) = page_token {
                url.push_str(&format!("&pageToken={}", token));
            }

            let (client, url) =
                super::guarded_client(&url, std::time::Duration::from_secs(30)).await?;
            let resp = client
                .get(url)
                .bearer_auth(&token)
                .send()
                .await
                .map_err(|e| SyncError::NetworkError(e.to_string()))?;

            if !resp.status().is_success() {
                return Ok(None); // Fall back to full sync
            }

            let body: serde_json::Value = resp
                .json()
                .await
                .map_err(|e| SyncError::ParseError(e.to_string()))?;

            if let Some(user_list) = body["users"].as_array() {
                for user in user_list {
                    users.push(user.clone());
                }
            }

            match body["nextPageToken"].as_str() {
                Some(next) => page_token = Some(next.to_string()),
                None => break,
            }
        }

        let new_delta = chrono::Utc::now().to_rfc3339();
        info!(
            user_count = users.len(),
            "Google Workspace delta sync complete"
        );

        Ok(Some(DeltaSyncResult {
            users,
            new_delta_link: Some(new_delta),
        }))
    }

    #[instrument(skip(self, credentials))]
    async fn test_connection(
        &self,
        credentials: &serde_json::Value,
    ) -> Result<ConnectionTestResult, SyncError> {
        let start = std::time::Instant::now();

        let creds: GoogleWorkspaceCredentials = serde_json::from_value(credentials.clone())
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

        // Try listing 1 user
        let (client, url) = super::guarded_client(
            &format!(
                "https://admin.googleapis.com/admin/directory/v1/users?customer=my_customer&domain={}&maxResults=1",
                enc(&creds.domain)
            ),
            std::time::Duration::from_secs(30),
        )
        .await?;
        let resp = client
            .get(url)
            .bearer_auth(&token)
            .send()
            .await
            .map_err(|e| SyncError::NetworkError(e.to_string()))?;

        let elapsed = start.elapsed().as_millis() as u64;

        if resp.status().is_success() {
            Ok(ConnectionTestResult {
                success: true,
                response_time_ms: Some(elapsed),
                error: None,
                user_count_sample: None,
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
