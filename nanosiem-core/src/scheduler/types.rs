// SPDX-License-Identifier: AGPL-3.0-or-later

//! Scheduler types and data structures
//!
//! Defines types for scheduled data fetch jobs including job definitions,
//! retry policies, and execution status.
//!
//! Requirements: 4.1, 4.2, 4.3, 4.4, 4.5, 4.6, 4.7

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

use crate::typeid;

use crate::upload::{ParserConfig, UploadDestination};

/// Scheduled job definition
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct ScheduledJob {
    /// Unique job ID
    #[serde(with = "typeid::job")]
    #[schema(value_type = String)]
    pub id: Uuid,
    /// Job name
    pub name: String,
    /// Optional description
    pub description: Option<String>,
    /// Cron expression for scheduling (e.g., "0 0 * * *" for daily at midnight)
    pub cron_expression: String,
    /// URL to fetch data from
    pub url: String,
    /// Optional authentication headers
    pub auth_headers: Option<HashMap<String, String>>,
    /// Upload destination configuration
    pub destination: UploadDestination,
    /// Parser configuration for the fetched data
    pub parser_config: ParserConfig,
    /// Retry policy for failed fetches
    pub retry_policy: RetryPolicy,
    /// Whether the job is enabled
    pub enabled: bool,
    /// Last execution timestamp
    pub last_run_at: Option<DateTime<Utc>>,
    /// Last execution status
    pub last_run_status: Option<JobStatus>,
    /// Last execution error message
    pub last_run_error: Option<String>,
    /// Next scheduled run time
    pub next_run_at: Option<DateTime<Utc>>,
    /// The lookup table this ingestion job belongs to
    pub lookup_table_name: String,
    /// Creation timestamp
    pub created_at: DateTime<Utc>,
    /// Last update timestamp
    pub updated_at: DateTime<Utc>,
    /// Current distributed-claim generation. Internal scheduler state only.
    #[serde(skip)]
    #[schema(ignore)]
    pub claim_generation: i64,
    /// Stable identity for the current due run, preserved across stale reclaims.
    #[serde(skip)]
    #[schema(ignore)]
    pub claim_run_id: Option<Uuid>,
}

/// Database row representation for scheduled jobs
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct ScheduledJobRow {
    pub id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub cron_expression: String,
    pub url: String,
    pub auth_headers: Option<sqlx::types::Json<HashMap<String, String>>>,
    pub destination_type: String,
    pub destination_config: sqlx::types::Json<serde_json::Value>,
    pub parser_config: sqlx::types::Json<ParserConfig>,
    pub retry_max: i32,
    pub retry_delay_secs: i32,
    pub enabled: bool,
    pub last_run_at: Option<DateTime<Utc>>,
    pub last_run_status: Option<String>,
    pub last_run_error: Option<String>,
    pub next_run_at: Option<DateTime<Utc>>,
    pub lookup_table_name: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub claim_generation: i64,
    pub claim_run_id: Option<Uuid>,
}

impl TryFrom<ScheduledJobRow> for ScheduledJob {
    type Error = String;

    fn try_from(row: ScheduledJobRow) -> Result<Self, Self::Error> {
        let destination = parse_destination(&row.destination_type, &row.destination_config.0)?;

        Ok(Self {
            id: row.id,
            name: row.name,
            description: row.description,
            cron_expression: row.cron_expression,
            url: row.url,
            auth_headers: row.auth_headers.map(|h| h.0),
            destination,
            parser_config: row.parser_config.0,
            retry_policy: RetryPolicy {
                max_retries: row.retry_max as u32,
                retry_delay_secs: row.retry_delay_secs as u64,
            },
            enabled: row.enabled,
            last_run_at: row.last_run_at,
            last_run_status: row.last_run_status.and_then(|s| JobStatus::from_str(&s)),
            last_run_error: row.last_run_error,
            next_run_at: row.next_run_at,
            lookup_table_name: row.lookup_table_name,
            created_at: row.created_at,
            updated_at: row.updated_at,
            claim_generation: row.claim_generation,
            claim_run_id: row.claim_run_id,
        })
    }
}

/// Parse destination from database fields
fn parse_destination(
    dest_type: &str,
    config: &serde_json::Value,
) -> Result<UploadDestination, String> {
    match dest_type {
        "lookup" => {
            let table_name = config
                .get("table_name")
                .and_then(|v| v.as_str())
                .ok_or("Missing table_name in destination config")?
                .to_string();
            let primary_key = config
                .get("primary_key")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            let mode = config
                .get("mode")
                .and_then(|v| v.as_str())
                .and_then(|s| match s {
                    "replace" => Some(crate::upload::LookupMode::Replace),
                    "append" => Some(crate::upload::LookupMode::Append),
                    _ => None,
                })
                .unwrap_or_default();
            Ok(UploadDestination::LookupTable {
                table_name,
                primary_key,
                mode,
            })
        }
        _ => Err(format!("Unknown destination type: {}", dest_type)),
    }
}

/// Retry policy for failed job executions
#[derive(Debug, Clone, Copy, Serialize, Deserialize, utoipa::ToSchema)]
pub struct RetryPolicy {
    /// Maximum number of retry attempts
    pub max_retries: u32,
    /// Delay between retries in seconds
    pub retry_delay_secs: u64,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            max_retries: 3,
            retry_delay_secs: 60,
        }
    }
}

/// Job execution status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum JobStatus {
    /// Job completed successfully
    Success,
    /// Job failed
    Failed,
    /// Job is currently running
    Running,
}

impl JobStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::Failed => "failed",
            Self::Running => "running",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "success" => Some(Self::Success),
            "failed" => Some(Self::Failed),
            "running" => Some(Self::Running),
            _ => None,
        }
    }
}

impl std::fmt::Display for JobStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Request to create a new scheduled job
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct NewScheduledJob {
    /// Job name
    pub name: String,
    /// Optional description
    pub description: Option<String>,
    /// Cron expression for scheduling
    pub cron_expression: String,
    /// URL to fetch data from
    pub url: String,
    /// Optional authentication headers
    pub auth_headers: Option<HashMap<String, String>>,
    /// Upload destination configuration
    pub destination: UploadDestination,
    /// Parser configuration for the fetched data
    pub parser_config: ParserConfig,
    /// Retry policy (optional, uses defaults if not provided)
    #[serde(default)]
    pub retry_policy: RetryPolicy,
    /// Whether the job is enabled (default: true)
    #[serde(default = "default_enabled")]
    pub enabled: bool,
}

fn default_enabled() -> bool {
    true
}

/// Request to update an existing scheduled job
#[derive(Debug, Clone, Default, Serialize, Deserialize, utoipa::ToSchema)]
pub struct UpdateScheduledJob {
    /// Updated job name
    pub name: Option<String>,
    /// Updated description
    pub description: Option<Option<String>>,
    /// Updated cron expression
    pub cron_expression: Option<String>,
    /// Updated URL
    pub url: Option<String>,
    /// Updated authentication headers
    pub auth_headers: Option<Option<HashMap<String, String>>>,
    /// Updated destination configuration
    pub destination: Option<UploadDestination>,
    /// Updated parser configuration
    pub parser_config: Option<ParserConfig>,
    /// Updated retry policy
    pub retry_policy: Option<RetryPolicy>,
    /// Updated enabled status
    pub enabled: Option<bool>,
}

/// Result of a job execution
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct JobExecution {
    /// Job ID
    #[serde(with = "typeid::job")]
    #[schema(value_type = String)]
    pub job_id: Uuid,
    /// Execution start time
    pub started_at: DateTime<Utc>,
    /// Execution end time
    pub completed_at: Option<DateTime<Utc>>,
    /// Execution status
    pub status: JobStatus,
    /// Number of records processed
    pub records_processed: Option<usize>,
    /// Number of records ingested
    pub records_ingested: Option<usize>,
    /// Error message if failed
    pub error: Option<String>,
    /// Duration in milliseconds
    pub duration_ms: Option<u64>,
}

impl JobExecution {
    /// Create a new running execution
    pub fn running(job_id: Uuid) -> Self {
        Self {
            job_id,
            started_at: Utc::now(),
            completed_at: None,
            status: JobStatus::Running,
            records_processed: None,
            records_ingested: None,
            error: None,
            duration_ms: None,
        }
    }

    /// Mark execution as successful
    pub fn success(mut self, records_processed: usize, records_ingested: usize) -> Self {
        let completed_at = Utc::now();
        self.completed_at = Some(completed_at);
        self.status = JobStatus::Success;
        self.records_processed = Some(records_processed);
        self.records_ingested = Some(records_ingested);
        self.duration_ms = Some((completed_at - self.started_at).num_milliseconds() as u64);
        self
    }

    /// Mark execution as failed
    pub fn failed(mut self, error: impl Into<String>) -> Self {
        let completed_at = Utc::now();
        self.completed_at = Some(completed_at);
        self.status = JobStatus::Failed;
        self.error = Some(error.into());
        self.duration_ms = Some((completed_at - self.started_at).num_milliseconds() as u64);
        self
    }
}

/// Filter for listing scheduled jobs
#[derive(Debug, Clone, Default, Serialize, Deserialize, utoipa::ToSchema)]
pub struct JobFilter {
    /// Filter by enabled status
    pub enabled: Option<bool>,
    /// Filter by destination type
    pub destination_type: Option<String>,
    /// Maximum number of results
    pub limit: Option<i64>,
    /// Offset for pagination
    pub offset: Option<i64>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_job_status_conversion() {
        assert_eq!(JobStatus::Success.as_str(), "success");
        assert_eq!(JobStatus::Failed.as_str(), "failed");
        assert_eq!(JobStatus::Running.as_str(), "running");

        assert_eq!(JobStatus::from_str("success"), Some(JobStatus::Success));
        assert_eq!(JobStatus::from_str("FAILED"), Some(JobStatus::Failed));
        assert_eq!(JobStatus::from_str("invalid"), None);
    }

    #[test]
    fn test_retry_policy_default() {
        let policy = RetryPolicy::default();
        assert_eq!(policy.max_retries, 3);
        assert_eq!(policy.retry_delay_secs, 60);
    }

    #[test]
    fn test_job_execution_lifecycle() {
        let job_id = Uuid::now_v7();
        let execution = JobExecution::running(job_id);
        assert_eq!(execution.status, JobStatus::Running);
        assert!(execution.completed_at.is_none());

        let execution = execution.success(100, 95);
        assert_eq!(execution.status, JobStatus::Success);
        assert!(execution.completed_at.is_some());
        assert_eq!(execution.records_processed, Some(100));
        assert_eq!(execution.records_ingested, Some(95));
    }

    #[test]
    fn test_job_execution_failure() {
        let job_id = Uuid::now_v7();
        let execution = JobExecution::running(job_id);
        let execution = execution.failed("Connection timeout");

        assert_eq!(execution.status, JobStatus::Failed);
        assert_eq!(execution.error, Some("Connection timeout".to_string()));
    }
}
