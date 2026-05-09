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
use sha2::{Digest, Sha256};
use tracing::{info, instrument};

use super::{SyncError, SyncProvider};
use crate::identity::types::{
    ConnectionTestResult, DeltaSyncResult, UserRecordUpsert, WorkdayCredentials,
};

pub struct WorkdaySync {
    client: reqwest::Client,
}

impl WorkdaySync {
    pub fn new() -> Self {
        Self {
            client: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(120)) // RaaS reports can be large
                .build()
                .unwrap_or_default(),
        }
    }

    /// Try to extract a string from a JSON value, checking multiple possible field names.
    /// Workday RaaS field names are admin-defined, so we check common variations.
    fn extract_field(row: &serde_json::Value, candidates: &[&str]) -> Option<String> {
        for key in candidates {
            if let Some(val) = row.get(*key).and_then(|v| v.as_str()) {
                if !val.is_empty() {
                    return Some(val.to_string());
                }
            }
        }
        None
    }

    /// Convert a Workday RaaS report row to a UserRecordUpsert
    fn map_workday_worker(row: &serde_json::Value) -> Option<UserRecordUpsert> {
        // External ID — required
        let external_id = Self::extract_field(
            row,
            &[
                "Worker_ID",
                "worker_id",
                "Employee_ID",
                "employee_id",
                "WID",
                "wid",
            ],
        )?;

        let username = Self::extract_field(
            row,
            &[
                "User_Name",
                "user_name",
                "Username",
                "username",
                "UserID",
                "userId",
            ],
        );
        let email = Self::extract_field(
            row,
            &[
                "Email",
                "email",
                "Email_Address",
                "email_address",
                "primaryWorkEmail",
                "Work_Email",
                "work_email",
            ],
        );
        let display_name = Self::extract_field(
            row,
            &[
                "Legal_Name_Full",
                "Preferred_Name_Full",
                "Display_Name",
                "display_name",
                "Full_Name",
                "full_name",
                "Worker",
            ],
        )
        .or_else(|| {
            let first = Self::extract_field(row, &["First_Name", "first_name", "Legal_First_Name"]);
            let last = Self::extract_field(row, &["Last_Name", "last_name", "Legal_Last_Name"]);
            match (first.as_deref(), last.as_deref()) {
                (Some(f), Some(l)) => Some(format!("{} {}", f, l)),
                (Some(f), None) => Some(f.to_string()),
                (None, Some(l)) => Some(l.to_string()),
                _ => None,
            }
        });

        let first_name = Self::extract_field(
            row,
            &[
                "First_Name",
                "first_name",
                "Legal_First_Name",
                "Preferred_First_Name",
            ],
        );
        let last_name = Self::extract_field(
            row,
            &[
                "Last_Name",
                "last_name",
                "Legal_Last_Name",
                "Preferred_Last_Name",
            ],
        );
        let department = Self::extract_field(
            row,
            &[
                "Department",
                "department",
                "Cost_Center",
                "Supervisory_Organization",
                "supervisoryOrganization",
            ],
        );
        let title = Self::extract_field(
            row,
            &[
                "Job_Title",
                "job_title",
                "Business_Title",
                "business_title",
                "Title",
                "title",
            ],
        );
        let manager_upn = Self::extract_field(
            row,
            &["Manager_Email", "manager_email", "Manager_ID", "manager_id"],
        );
        let manager_display_name =
            Self::extract_field(row, &["Manager", "manager", "Manager_Name", "manager_name"]);
        let company =
            Self::extract_field(row, &["Company", "company", "Organization", "organization"]);
        let city = Self::extract_field(
            row,
            &["City", "city", "Work_City", "work_city", "Location_City"],
        );
        let country = Self::extract_field(
            row,
            &[
                "Country",
                "country",
                "Work_Country",
                "work_country",
                "Country_Code",
            ],
        );
        let phone = Self::extract_field(
            row,
            &[
                "Phone",
                "phone",
                "Work_Phone",
                "work_phone",
                "primaryWorkPhone",
                "Mobile",
            ],
        );
        let employee_id =
            Self::extract_field(row, &["Employee_ID", "employee_id", "Badge_ID", "badge_id"])
                .or_else(|| Some(external_id.clone()));
        let employee_type = Self::extract_field(
            row,
            &[
                "Employee_Type",
                "employee_type",
                "Worker_Type",
                "worker_type",
                "Worker_Sub_Type",
                "Position_Type",
            ],
        );

        // Active status — check various field names and value formats
        let account_enabled = Self::extract_field(
            row,
            &[
                "Active_Status",
                "active_status",
                "Is_Active",
                "is_active",
                "Status",
                "status",
                "Active",
                "active",
            ],
        )
        .map_or(true, |v| {
            let lower = v.to_lowercase();
            lower == "1" || lower == "true" || lower == "yes" || lower == "active"
        });
        let account_status = if account_enabled {
            "active"
        } else {
            "disabled"
        }
        .to_string();

        let hire_date = Self::extract_field(
            row,
            &["Hire_Date", "hire_date", "Original_Hire_Date", "Start_Date"],
        )
        .and_then(|s| {
            chrono::DateTime::parse_from_rfc3339(&s)
                .ok()
                .map(|dt| dt.with_timezone(&chrono::Utc))
                .or_else(|| {
                    chrono::NaiveDate::parse_from_str(&s, "%Y-%m-%d")
                        .ok()
                        .and_then(|d| d.and_hms_opt(0, 0, 0))
                        .map(|dt| {
                            chrono::DateTime::<chrono::Utc>::from_naive_utc_and_offset(
                                dt,
                                chrono::Utc,
                            )
                        })
                })
        });

        let raw = serde_json::to_string(row).unwrap_or_default();
        let hash = hex::encode(Sha256::digest(raw.as_bytes()));

        Some(UserRecordUpsert {
            external_id,
            username,
            upn: email.clone(), // Workday doesn't have UPN; use email as best proxy
            email,
            display_name,
            first_name,
            last_name,
            department,
            title,
            manager_upn,
            manager_display_name,
            company,
            office_location: Self::extract_field(
                row,
                &[
                    "Location",
                    "location",
                    "Office",
                    "office",
                    "Work_Location",
                    "Building",
                ],
            ),
            city,
            country,
            groups: Vec::new(),
            account_enabled,
            account_status,
            mfa_enabled: None,
            last_sign_in_at: None, // Workday doesn't track sign-in
            created_in_directory_at: hire_date,
            phone,
            employee_id,
            employee_type,
            sync_hash: hash,
        })
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
    ) -> Result<Vec<UserRecordUpsert>, SyncError> {
        let body = self.fetch_report(credentials).await?;

        let entries = Self::extract_entries(&body).ok_or_else(|| {
            SyncError::ParseError("No report entries found in RaaS response".into())
        })?;

        let users: Vec<UserRecordUpsert> = entries
            .iter()
            .filter_map(|row| Self::map_workday_worker(row))
            .collect();

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

        // Process in chunks of 1000 to avoid holding all UserRecordUpserts at once.
        // The JSON body is still in memory, but we avoid doubling memory with the mapped records.
        const CHUNK_SIZE: usize = 1000;
        let mut total = 0u64;

        for chunk in entries.chunks(CHUNK_SIZE) {
            let page: Vec<UserRecordUpsert> = chunk
                .iter()
                .filter_map(|row| Self::map_workday_worker(row))
                .collect();

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
