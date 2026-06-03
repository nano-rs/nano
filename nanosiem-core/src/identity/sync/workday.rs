// SPDX-License-Identifier: AGPL-3.0-or-later

//! Workday sync provider
//!
//! Uses Workday RaaS (Report as a Service) to pull worker directory data.
//! The admin creates a custom report in Workday with the needed fields,
//! publishes it as a web service, and provides the JSON report URL.
//! Auth is via Integration System User (ISU) basic auth.
//!
//! RaaS returns the full report in a single response (no native pagination),
//! so delta sync is not supported — only full sync.

use async_trait::async_trait;
use tracing::{info, instrument};

use super::{SyncError, SyncProvider};
use crate::identity::types::{ConnectionTestResult, DeltaSyncResult, WorkdayCredentials};

pub struct WorkdaySync {
    client: reqwest::Client,
}

impl WorkdaySync {
    pub fn new() -> Self {
        Self {
            client: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(120)) // RaaS reports can be large
                .redirect(super::restricted_redirect_policy())
                .build()
                .unwrap_or_default(),
        }
    }

    /// Extract the report entries array from the RaaS JSON response.
    /// Workday RaaS wraps results in `{ "Report_Entry": [...] }` but the
    /// outer key name can vary based on the report name.
    fn extract_entries(body: &serde_json::Value) -> Option<&Vec<serde_json::Value>> {
        // Try common wrapper key names
        for key in &["Report_Entry", "report_entry", "Report_Data"] {
            if let Some(arr) = body.get(*key).and_then(|v| v.as_array()) {
                return Some(arr);
            }
        }
        // If the body itself is an object, try the first key that has an array value
        if let Some(obj) = body.as_object() {
            for (_key, val) in obj {
                if let Some(arr) = val.as_array() {
                    return Some(arr);
                }
            }
        }
        // If the body itself is an array
        body.as_array()
    }
}

impl WorkdaySync {
    /// Fetch and parse the RaaS report, returning the raw JSON body
    async fn fetch_report(
        &self,
        credentials: &serde_json::Value,
    ) -> Result<serde_json::Value, SyncError> {
        let creds: WorkdayCredentials = serde_json::from_value(credentials.clone())
            .map_err(|e| SyncError::InvalidCredentials(e.to_string()))?;

        let mut url = creds.report_url.clone();
        if !url.contains("format=") {
            let sep = if url.contains('?') { "&" } else { "?" };
            url = format!("{}{}format=json", url, sep);
        }

        // NAN-1196: `report_url` is fully admin-controlled; validate the
        // destination before basic-auth credentials are sent to it.
        super::guard_outbound_url(&url).await?;
        let resp = self
            .client
            .get(&url)
            .basic_auth(&creds.username, Some(&creds.password))
            .header("Accept", "application/json")
            .send()
            .await
            .map_err(|e| SyncError::NetworkError(e.to_string()))?;

        if resp.status().as_u16() == 401 {
            return Err(SyncError::AuthError(
                "Authentication failed — check ISU username and password".into(),
            ));
        }

        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            return Err(SyncError::ApiError {
                status,
                message: body,
            });
        }

        resp.json()
            .await
            .map_err(|e| SyncError::ParseError(format!("Failed to parse RaaS JSON: {}", e)))
    }
}

#[async_trait]
impl SyncProvider for WorkdaySync {
    #[instrument(skip(self, credentials, _config))]
    async fn full_sync(
        &self,
        credentials: &serde_json::Value,
        _config: &serde_json::Value,
    ) -> Result<Vec<serde_json::Value>, SyncError> {
        let body = self.fetch_report(credentials).await?;

        let entries = Self::extract_entries(&body).ok_or_else(|| {
            SyncError::ParseError("No report entries found in RaaS response".into())
        })?;

        // NAN-1151: yield RAW RaaS report rows; mapping to user_registry happens in VRL.
        let users: Vec<serde_json::Value> = entries.iter().cloned().collect();

        info!(user_count = users.len(), "Workday full sync complete");
        Ok(users)
    }

    #[instrument(skip(self, credentials, _config, on_page))]
    async fn full_sync_paged(
        &self,
        credentials: &serde_json::Value,
        _config: &serde_json::Value,
        on_page: super::PageCallback<'_>,
    ) -> Result<u64, SyncError> {
        let body = self.fetch_report(credentials).await?;

        let entries = Self::extract_entries(&body).ok_or_else(|| {
            SyncError::ParseError("No report entries found in RaaS response".into())
        })?;

        // Process in chunks of 1000 to avoid holding all rows in a single page at once.
        // NAN-1151: pages carry RAW RaaS report rows; mapping happens in VRL.
        const CHUNK_SIZE: usize = 1000;
        let mut total = 0u64;

        for chunk in entries.chunks(CHUNK_SIZE) {
            let page: Vec<serde_json::Value> = chunk.iter().cloned().collect();

            let page_size = page.len();
            total += on_page(page).await?;
            info!(page_size, total, "Workday sync chunk processed");
        }

        info!(total, "Workday paged full sync complete");
        Ok(total)
    }

    #[instrument(skip(self, _credentials, _config))]
    async fn delta_sync(
        &self,
        _credentials: &serde_json::Value,
        _config: &serde_json::Value,
        _delta_link: Option<&str>,
    ) -> Result<Option<DeltaSyncResult>, SyncError> {
        // RaaS doesn't support delta sync — always fall back to full sync
        Ok(None)
    }

    #[instrument(skip(self, credentials))]
    async fn test_connection(
        &self,
        credentials: &serde_json::Value,
    ) -> Result<ConnectionTestResult, SyncError> {
        let start = std::time::Instant::now();

        let creds: WorkdayCredentials = serde_json::from_value(credentials.clone())
            .map_err(|e| SyncError::InvalidCredentials(e.to_string()))?;

        let mut url = creds.report_url.clone();
        if !url.contains("format=") {
            let sep = if url.contains('?') { "&" } else { "?" };
            url = format!("{}{}format=json", url, sep);
        }

        // NAN-1196: reject a hostile `report_url` (SSRF/credential exfil) before
        // sending basic-auth; surface it as a failed connection test.
        if let Err(e) = super::guard_outbound_url(&url).await {
            return Ok(ConnectionTestResult {
                success: false,
                response_time_ms: Some(start.elapsed().as_millis() as u64),
                error: Some(e.to_string()),
                user_count_sample: None,
            });
        }
        let resp = self
            .client
            .get(&url)
            .basic_auth(&creds.username, Some(&creds.password))
            .header("Accept", "application/json")
            .send()
            .await;

        let elapsed = start.elapsed().as_millis() as u64;

        match resp {
            Ok(r) if r.status().is_success() => {
                // Try to count entries in the response
                let count = r
                    .json::<serde_json::Value>()
                    .await
                    .ok()
                    .and_then(|body| Self::extract_entries(&body).map(|e| e.len() as u64));

                Ok(ConnectionTestResult {
                    success: true,
                    response_time_ms: Some(elapsed),
                    error: None,
                    user_count_sample: count,
                })
            }
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
