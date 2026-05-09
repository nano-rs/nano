// SPDX-License-Identifier: AGPL-3.0-or-later

//! Scheduler Service
//!
//! Manages scheduled data fetch jobs including creation, execution,
//! and background scheduling.
//!
//! Requirements: 4.1, 4.2, 4.3, 4.4, 4.5, 4.6, 4.7

use chrono::{DateTime, Utc};
use sqlx::PgPool;
use thiserror::Error;
use tracing::{info, instrument, warn};
use uuid::Uuid;

use crate::inputlookup::{SsrfConfig, SsrfValidator};

use super::repository::{JobStats, SchedulerRepository, SchedulerRepositoryError};
use super::types::*;

/// Maximum response size for scheduled fetches (500MB)
/// Larger than upload limit since threat feeds can be large
const SCHEDULER_MAX_RESPONSE_SIZE: usize = 500 * 1024 * 1024;

/// Request timeout for scheduled fetches (30 minutes)
/// Longer than typical since large feeds may take time to download
const SCHEDULER_FETCH_TIMEOUT_SECS: u64 = 30 * 60;

#[derive(Error, Debug)]
pub enum SchedulerError {
    #[error("Repository error: {0}")]
    RepositoryError(#[from] SchedulerRepositoryError),

    #[error("Invalid cron expression: {0}")]
    InvalidCron(String),

    #[error("Job not found: {0}")]
    NotFound(Uuid),

    #[error("Fetch error: {0}")]
    FetchError(String),

    #[error("Upload error: {0}")]
    UploadError(String),

    #[error("Job is already running")]
    AlreadyRunning,

    #[error("URL blocked by SSRF protection: {0}")]
    SsrfBlocked(String),
}

/// Scheduler service for managing scheduled data fetch jobs
#[derive(Clone)]
pub struct SchedulerService {
    pool: PgPool,
    repository: SchedulerRepository,
    node_id: Option<String>,
}

impl SchedulerService {
    /// Create a new scheduler service
    pub fn new(pool: PgPool) -> Self {
        Self {
            repository: SchedulerRepository::new(pool.clone()),
            pool,
            node_id: None,
        }
    }

    /// Create a scheduler service with a node ID for distributed claiming
    pub fn with_node_id(pool: PgPool, node_id: String) -> Self {
        Self {
            repository: SchedulerRepository::new(pool.clone()),
            pool,
            node_id: Some(node_id),
        }
    }

    /// Create a new scheduled job
    #[instrument(skip(self, job))]
    pub async fn create_job(&self, job: NewScheduledJob) -> Result<ScheduledJob, SchedulerError> {
        // Validate cron expression
        validate_cron(&job.cron_expression)?;

        // Calculate next run time
        let next_run_at = calculate_next_run(&job.cron_expression)?;

        info!(
            name = %job.name,
            cron = %job.cron_expression,
            next_run = ?next_run_at,
            "Creating scheduled job"
        );

        Ok(self.repository.create_job(&job, next_run_at).await?)
    }

    /// Get a scheduled job by ID
    #[instrument(skip(self))]
    pub async fn get_job(&self, id: Uuid) -> Result<ScheduledJob, SchedulerError> {
        Ok(self.repository.get_job(id).await?)
    }

    /// List all scheduled jobs with optional filters
    #[instrument(skip(self))]
    pub async fn list_jobs(&self, filter: &JobFilter) -> Result<Vec<ScheduledJob>, SchedulerError> {
        Ok(self.repository.list_jobs(filter).await?)
    }

    /// Update a scheduled job
    #[instrument(skip(self, update))]
    pub async fn update_job(
        &self,
        id: Uuid,
        update: UpdateScheduledJob,
    ) -> Result<ScheduledJob, SchedulerError> {
        // If cron expression is being updated, validate it
        let next_run_at = if let Some(ref cron) = update.cron_expression {
            validate_cron(cron)?;
            calculate_next_run(cron)?
        } else {
            None
        };

        Ok(self.repository.update_job(id, &update, next_run_at).await?)
    }

    /// Delete a scheduled job
    #[instrument(skip(self))]
    pub async fn delete_job(&self, id: Uuid) -> Result<bool, SchedulerError> {
        Ok(self.repository.delete_job(id).await?)
    }

    /// Enable a scheduled job
    #[instrument(skip(self))]
    pub async fn enable_job(&self, id: Uuid) -> Result<ScheduledJob, SchedulerError> {
        let job = self.repository.get_job(id).await?;
        let next_run_at = calculate_next_run(&job.cron_expression)?;
        Ok(self.repository.enable_job(id, next_run_at).await?)
    }

    /// Disable a scheduled job
    #[instrument(skip(self))]
    pub async fn disable_job(&self, id: Uuid) -> Result<ScheduledJob, SchedulerError> {
        Ok(self.repository.disable_job(id).await?)
    }

    /// Get job statistics
    #[instrument(skip(self))]
    pub async fn get_stats(&self) -> Result<JobStats, SchedulerError> {
        Ok(self.repository.get_job_stats().await?)
    }

    /// Get the ingestion job for a lookup table (if any)
    #[instrument(skip(self))]
    pub async fn get_job_for_lookup_table(
        &self,
        lookup_table_name: &str,
    ) -> Result<Option<ScheduledJob>, SchedulerError> {
        Ok(self
            .repository
            .get_job_by_lookup_table(lookup_table_name)
            .await?)
    }

    /// Delete the ingestion job for a lookup table
    #[instrument(skip(self))]
    pub async fn delete_job_for_lookup_table(
        &self,
        lookup_table_name: &str,
    ) -> Result<bool, SchedulerError> {
        Ok(self
            .repository
            .delete_job_by_lookup_table(lookup_table_name)
            .await?)
    }

    /// Trigger the ingestion job for a lookup table
    #[instrument(skip(self))]
    pub async fn trigger_job_for_lookup_table(
        &self,
        lookup_table_name: &str,
    ) -> Result<JobExecution, SchedulerError> {
        let job = self
            .repository
            .get_job_by_lookup_table(lookup_table_name)
            .await?
            .ok_or_else(|| SchedulerError::NotFound(Uuid::nil()))?;

        if job.last_run_status == Some(JobStatus::Running) {
            return Err(SchedulerError::AlreadyRunning);
        }

        info!(job_id = %job.id, lookup_table = %lookup_table_name, "Manually triggering ingestion for lookup table");
        self.execute_job(&job).await
    }

    /// Manually trigger a job execution
    #[instrument(skip(self))]
    pub async fn trigger_job(&self, id: Uuid) -> Result<JobExecution, SchedulerError> {
        let job = self.repository.get_job(id).await?;

        // Check if job is already running
        if job.last_run_status == Some(JobStatus::Running) {
            return Err(SchedulerError::AlreadyRunning);
        }

        info!(job_id = %id, name = %job.name, "Manually triggering job");

        // Execute the job
        self.execute_job(&job).await
    }

    /// Execute a scheduled job
    #[instrument(skip(self, job), fields(job_id = %job.id, job_name = %job.name))]
    pub async fn execute_job(&self, job: &ScheduledJob) -> Result<JobExecution, SchedulerError> {
        let execution = JobExecution::running(job.id);

        // Mark job as running
        self.repository.mark_job_running(job.id).await?;

        // Execute the job with retry logic
        let result = self.execute_with_retry(job).await;

        // Calculate next run time
        let next_run_at = if job.enabled {
            calculate_next_run(&job.cron_expression)?
        } else {
            None
        };

        // Update job status based on result
        match result {
            Ok((records_processed, records_ingested)) => {
                self.repository
                    .update_job_status(job.id, JobStatus::Success, None, next_run_at)
                    .await?;

                info!(
                    job_id = %job.id,
                    records_processed,
                    records_ingested,
                    "Job completed successfully"
                );

                Ok(execution.success(records_processed, records_ingested))
            }
            Err(e) => {
                let error_msg = e.to_string();
                self.repository
                    .update_job_status(job.id, JobStatus::Failed, Some(&error_msg), next_run_at)
                    .await?;

                warn!(job_id = %job.id, error = %error_msg, "Job failed");

                Ok(execution.failed(error_msg))
            }
        }
    }

    /// Execute job with retry logic
    async fn execute_with_retry(
        &self,
        job: &ScheduledJob,
    ) -> Result<(usize, usize), SchedulerError> {
        let mut last_error = None;
        let max_attempts = job.retry_policy.max_retries + 1;

        for attempt in 1..=max_attempts {
            info!(
                job_id = %job.id,
                attempt,
                max_attempts,
                "Starting job execution attempt"
            );

            match self.fetch_and_process(job).await {
                Ok(result) => {
                    if attempt > 1 {
                        info!(
                            job_id = %job.id,
                            attempt,
                            "Job succeeded after retry"
                        );
                    }
                    return Ok(result);
                }
                Err(e) => {
                    let error_msg = e.to_string();
                    last_error = Some(e);

                    if attempt < max_attempts {
                        warn!(
                            job_id = %job.id,
                            attempt,
                            max_attempts,
                            delay_secs = job.retry_policy.retry_delay_secs,
                            error = %error_msg,
                            "Job attempt failed, will retry after delay"
                        );
                        tokio::time::sleep(std::time::Duration::from_secs(
                            job.retry_policy.retry_delay_secs,
                        ))
                        .await;
                    } else {
                        warn!(
                            job_id = %job.id,
                            attempt,
                            max_attempts,
                            error = %error_msg,
                            "Job failed after all retry attempts"
                        );
                    }
                }
            }
        }

        Err(last_error.unwrap_or_else(|| SchedulerError::FetchError("Unknown error".to_string())))
    }

    /// Fetch data from URL and process it
    async fn fetch_and_process(
        &self,
        job: &ScheduledJob,
    ) -> Result<(usize, usize), SchedulerError> {
        info!(job_id = %job.id, url = %job.url, "Fetching data from URL");

        // Validate URL against SSRF attacks (blocks private IPs, localhost, metadata endpoints)
        let ssrf_config = SsrfConfig {
            allow_http: true, // Allow HTTP for internal/legacy feeds
            blocked_domains: Vec::new(),
            max_redirects: 5,
            ..Default::default()
        };
        let ssrf_validator = SsrfValidator::new(ssrf_config);
        ssrf_validator
            .validate_with_dns(&job.url)
            .await
            .map_err(|e| SchedulerError::SsrfBlocked(e.to_string()))?;

        // Build HTTP client with timeout
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(SCHEDULER_FETCH_TIMEOUT_SECS))
            .build()
            .map_err(|e| {
                SchedulerError::FetchError(format!("Failed to create HTTP client: {}", e))
            })?;

        let mut request = client.get(&job.url);

        // Add authentication headers if provided
        if let Some(ref headers) = job.auth_headers {
            for (key, value) in headers {
                request = request.header(key, value);
            }
        }

        // Fetch the data
        let response = request.send().await.map_err(|e| {
            if e.is_timeout() {
                SchedulerError::FetchError("Request timed out".to_string())
            } else if e.is_connect() {
                SchedulerError::FetchError(format!("Connection failed: {}", e))
            } else {
                SchedulerError::FetchError(e.to_string())
            }
        })?;

        let status = response.status();
        if !status.is_success() {
            let error_body = response.text().await.unwrap_or_default();
            return Err(SchedulerError::FetchError(format!(
                "HTTP error {}: {}",
                status,
                if error_body.len() > 200 {
                    format!("{}...", &error_body[..200])
                } else {
                    error_body
                }
            )));
        }

        // Check Content-Length header before downloading (if available)
        if let Some(content_length) = response.content_length() {
            if content_length > SCHEDULER_MAX_RESPONSE_SIZE as u64 {
                return Err(SchedulerError::FetchError(format!(
                    "Response too large: Content-Length {} bytes exceeds maximum of {} bytes",
                    content_length, SCHEDULER_MAX_RESPONSE_SIZE
                )));
            }
        }

        // Validate Content-Type matches expected format
        let content_type = response
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");

        let expected_format = &job.parser_config.format;
        if !is_content_type_compatible(content_type, expected_format) {
            warn!(
                job_id = %job.id,
                content_type = content_type,
                expected_format = ?expected_format,
                "Content-Type mismatch - proceeding with caution"
            );
        }

        let content = response.bytes().await.map_err(|e| {
            SchedulerError::FetchError(format!("Failed to read response body: {}", e))
        })?;

        info!(
            job_id = %job.id,
            content_size = content.len(),
            "Data fetched successfully"
        );

        // Validate content size
        if content.is_empty() {
            return Err(SchedulerError::FetchError(
                "Empty response received".to_string(),
            ));
        }

        if content.len() > SCHEDULER_MAX_RESPONSE_SIZE {
            return Err(SchedulerError::FetchError(format!(
                "Response too large: {} bytes exceeds maximum of {} bytes",
                content.len(),
                SCHEDULER_MAX_RESPONSE_SIZE
            )));
        }

        // Basic content format validation
        validate_content_format(&content, expected_format)?;

        // Process through upload service
        let upload_service = crate::upload::UploadService::new(self.pool.clone());
        let upload_request = crate::upload::UploadRequest {
            filename: format!("scheduled_{}_{}.data", job.name, Utc::now().timestamp()),
            content: content.to_vec(),
            destination: job.destination.clone(),
            config: job.parser_config.clone(),
        };

        let result = upload_service
            .upload(upload_request)
            .await
            .map_err(|e| SchedulerError::UploadError(e.to_string()))?;

        Ok((result.records_processed, result.records_ingested))
    }

    /// Get jobs that are due to run
    #[instrument(skip(self))]
    pub async fn get_due_jobs(&self) -> Result<Vec<ScheduledJob>, SchedulerError> {
        Ok(self.repository.get_due_jobs().await?)
    }

    /// Run the scheduler loop (for background task).
    ///
    /// If a node_id is configured, uses SKIP LOCKED claiming for distributed execution.
    /// Otherwise falls back to the legacy get_due_jobs + mark_running pattern.
    pub async fn run_scheduler_loop(&self, poll_interval_secs: u64) {
        // Stale timeout for scheduled jobs is longer (45 min) since feed fetches can be slow
        let stale_timeout_secs: i64 = std::env::var("SCHEDULER_JOB_STALE_TIMEOUT_SECS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(2700); // 45 minutes

        if let Some(ref node_id) = self.node_id {
            info!(poll_interval_secs, node_id = %node_id, "Starting distributed scheduler loop (SKIP LOCKED)");
        } else {
            info!(poll_interval_secs, "Starting scheduler loop (legacy)");
        }

        loop {
            if let Some(ref node_id) = self.node_id {
                // Distributed mode: claim jobs via SKIP LOCKED
                match self
                    .repository
                    .claim_due_jobs(5, node_id, stale_timeout_secs)
                    .await
                {
                    Ok(jobs) => {
                        if !jobs.is_empty() {
                            info!(job_count = jobs.len(), node_id = %node_id, "Claimed due jobs");
                        }

                        for job in jobs {
                            let result = self.execute_with_retry(&job).await;

                            let next_run_at = if job.enabled {
                                calculate_next_run(&job.cron_expression).ok().flatten()
                            } else {
                                None
                            };

                            let (status, error_msg) = match result {
                                Ok((records_processed, records_ingested)) => {
                                    info!(
                                        job_id = %job.id,
                                        records_processed,
                                        records_ingested,
                                        "Job completed successfully"
                                    );
                                    (super::types::JobStatus::Success, None)
                                }
                                Err(e) => {
                                    let msg = e.to_string();
                                    warn!(job_id = %job.id, error = %msg, "Job failed");
                                    (super::types::JobStatus::Failed, Some(msg))
                                }
                            };

                            if let Err(e) = self
                                .repository
                                .release_job_claim(
                                    job.id,
                                    node_id,
                                    status,
                                    error_msg.as_deref(),
                                    next_run_at,
                                )
                                .await
                            {
                                warn!(job_id = %job.id, "Failed to release job claim: {}", e);
                            }
                        }
                    }
                    Err(e) => {
                        warn!(error = %e, "Failed to claim due jobs");
                    }
                }
            } else {
                // Legacy mode: get due jobs without locking
                match self.get_due_jobs().await {
                    Ok(jobs) => {
                        if !jobs.is_empty() {
                            info!(job_count = jobs.len(), "Found due jobs to execute");
                        }

                        for job in jobs {
                            if let Err(e) = self.execute_job(&job).await {
                                warn!(
                                    job_id = %job.id,
                                    job_name = %job.name,
                                    error = %e,
                                    "Failed to execute scheduled job"
                                );
                            }
                        }
                    }
                    Err(e) => {
                        warn!(error = %e, "Failed to get due jobs");
                    }
                }
            }

            // Sleep until next poll
            tokio::time::sleep(std::time::Duration::from_secs(poll_interval_secs)).await;
        }
    }

    /// Start the scheduler as a background task
    /// Returns a JoinHandle that can be used to await or abort the task
    pub fn start_scheduler(&self, poll_interval_secs: u64) -> tokio::task::JoinHandle<()> {
        let service = self.clone();
        tokio::spawn(async move {
            service.run_scheduler_loop(poll_interval_secs).await;
        })
    }

    /// Release all job claims held by this node (for graceful shutdown).
    pub async fn release_all_claims(&self) -> Result<u64, SchedulerError> {
        if let Some(ref node_id) = self.node_id {
            Ok(self.repository.release_all_job_claims(node_id).await?)
        } else {
            Ok(0)
        }
    }

    /// Run a single poll iteration (useful for testing)
    pub async fn poll_once(&self) -> Result<usize, SchedulerError> {
        let jobs = self.get_due_jobs().await?;
        let job_count = jobs.len();

        for job in jobs {
            if let Err(e) = self.execute_job(&job).await {
                warn!(
                    job_id = %job.id,
                    error = %e,
                    "Failed to execute scheduled job"
                );
            }
        }

        Ok(job_count)
    }
}

/// Normalize a cron expression to 6-field format (seconds included).
/// The cron crate requires 6 fields (sec min hour day month weekday)
/// but users typically write standard 5-field cron (min hour day month weekday).
fn normalize_cron(expression: &str) -> String {
    let parts: Vec<&str> = expression.split_whitespace().collect();
    if parts.len() == 5 {
        format!("0 {}", expression)
    } else {
        expression.to_string()
    }
}

/// Validate a cron expression
pub fn validate_cron(expression: &str) -> Result<(), SchedulerError> {
    let expr = normalize_cron(expression);
    cron::Schedule::from_str(&expr)
        .map_err(|e| SchedulerError::InvalidCron(format!("{}: {}", expression, e)))?;
    Ok(())
}

/// Calculate the next run time from a cron expression
pub fn calculate_next_run(expression: &str) -> Result<Option<DateTime<Utc>>, SchedulerError> {
    let expr = normalize_cron(expression);
    let schedule = cron::Schedule::from_str(&expr)
        .map_err(|e| SchedulerError::InvalidCron(format!("{}: {}", expression, e)))?;

    Ok(schedule.upcoming(Utc).next())
}

/// Calculate the next N run times from a cron expression
pub fn calculate_next_runs(
    expression: &str,
    count: usize,
) -> Result<Vec<DateTime<Utc>>, SchedulerError> {
    let expr = normalize_cron(expression);
    let schedule = cron::Schedule::from_str(&expr)
        .map_err(|e| SchedulerError::InvalidCron(format!("{}: {}", expression, e)))?;

    Ok(schedule.upcoming(Utc).take(count).collect())
}

/// Get a human-readable description of a cron expression
pub fn describe_cron(expression: &str) -> Result<String, SchedulerError> {
    // Validate first
    validate_cron(expression)?;

    // Parse the normalized expression parts
    let normalized = normalize_cron(expression);
    let parts: Vec<&str> = normalized.split_whitespace().collect();
    if parts.len() != 6 {
        return Ok(format!("Custom schedule: {}", expression));
    }

    let (sec, min, hour, day, month, weekday) =
        (parts[0], parts[1], parts[2], parts[3], parts[4], parts[5]);

    // Generate description based on common patterns
    match (sec, min, hour, day, month, weekday) {
        ("0", "0", "0", "*", "*", "*") => Ok("Daily at midnight".to_string()),
        ("0", "0", h, "*", "*", "*") if h != "*" => Ok(format!("Daily at {}:00", h)),
        ("0", m, "*", "*", "*", "*") if m.starts_with("*/") => {
            let interval = m.trim_start_matches("*/");
            Ok(format!("Every {} minutes", interval))
        }
        ("0", "0", "0", "1", "*", "*") => Ok("Monthly on the 1st at midnight".to_string()),
        ("0", "0", "0", "*", "*", "SUN") => Ok("Weekly on Sunday at midnight".to_string()),
        ("0", "0", "0", "*", "*", "MON") => Ok("Weekly on Monday at midnight".to_string()),
        _ => Ok(format!("Custom schedule: {}", expression)),
    }
}

/// Check if the Content-Type header is compatible with the expected format
fn is_content_type_compatible(
    content_type: &str,
    expected_format: &crate::upload::FileFormat,
) -> bool {
    use crate::upload::FileFormat;

    let ct_lower = content_type.to_lowercase();

    match expected_format {
        FileFormat::Csv => {
            ct_lower.contains("text/csv")
                || ct_lower.contains("text/plain")
                || ct_lower.contains("application/csv")
                || ct_lower.is_empty() // Some servers don't set Content-Type
        }
        FileFormat::Json | FileFormat::Ndjson => {
            ct_lower.contains("application/json")
                || ct_lower.contains("text/json")
                || ct_lower.contains("application/x-ndjson")
                || ct_lower.contains("text/plain")
                || ct_lower.is_empty()
        }
    }
}

/// Validate that the content appears to be the expected format
fn validate_content_format(
    content: &[u8],
    expected_format: &crate::upload::FileFormat,
) -> Result<(), SchedulerError> {
    use crate::upload::FileFormat;

    // Check for binary content (null bytes in first 100 bytes)
    if content.iter().take(100).any(|&b| b == 0) {
        return Err(SchedulerError::FetchError(
            "Content appears to be binary, not text".to_string(),
        ));
    }

    // Only check first 1KB for format detection
    let sample = &content[..content.len().min(1024)];
    let sample_str = String::from_utf8_lossy(sample);
    let trimmed = sample_str.trim_start();

    match expected_format {
        FileFormat::Json => {
            if !trimmed.starts_with('{') && !trimmed.starts_with('[') {
                return Err(SchedulerError::FetchError(
                    "Content does not appear to be JSON (expected '{' or '[')".to_string(),
                ));
            }
        }
        FileFormat::Ndjson => {
            // NDJSON should have lines starting with '{'
            if let Some(first_line) = trimmed.lines().next() {
                if !first_line.trim().starts_with('{') {
                    return Err(SchedulerError::FetchError(
                        "Content does not appear to be NDJSON (expected lines starting with '{')"
                            .to_string(),
                    ));
                }
            }
        }
        FileFormat::Csv => {
            // CSV is permissive - text content is fine
            // Could add header row validation if needed
        }
    }

    Ok(())
}

use std::str::FromStr;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_cron_valid() {
        // The cron crate uses 6-field format: sec min hour day month weekday
        // Weekday uses SUN-SAT or 1-7 (1=Monday in some implementations)
        assert!(validate_cron("0 0 0 * * *").is_ok()); // Daily at midnight
        assert!(validate_cron("0 */5 * * * *").is_ok()); // Every 5 minutes
        assert!(validate_cron("0 0 0 * * SUN").is_ok()); // Weekly on Sunday
        assert!(validate_cron("0 0 0 1 * *").is_ok()); // Monthly on 1st
    }

    #[test]
    fn test_validate_cron_invalid() {
        assert!(validate_cron("invalid").is_err());
        assert!(validate_cron("60 * * * * *").is_err()); // Invalid second
        assert!(validate_cron("* * * *").is_err()); // Missing fields
    }

    #[test]
    fn test_calculate_next_run() {
        // Use 6-field format
        let next = calculate_next_run("0 0 0 * * *").unwrap();
        assert!(next.is_some());

        let next_time = next.unwrap();
        assert!(next_time > Utc::now());
    }

    #[test]
    fn test_calculate_next_runs() {
        let runs = calculate_next_runs("0 0 0 * * *", 5).unwrap();
        assert_eq!(runs.len(), 5);

        // Verify they are in order
        for i in 1..runs.len() {
            assert!(runs[i] > runs[i - 1]);
        }
    }

    #[test]
    fn test_describe_cron() {
        assert_eq!(describe_cron("0 0 0 * * *").unwrap(), "Daily at midnight");
        assert_eq!(describe_cron("0 0 12 * * *").unwrap(), "Daily at 12:00");
        assert_eq!(describe_cron("0 */5 * * * *").unwrap(), "Every 5 minutes");
        assert_eq!(
            describe_cron("0 0 0 1 * *").unwrap(),
            "Monthly on the 1st at midnight"
        );
        assert_eq!(
            describe_cron("0 0 0 * * SUN").unwrap(),
            "Weekly on Sunday at midnight"
        );
    }
}
