// SPDX-License-Identifier: AGPL-3.0-or-later

//! Scheduler Repository
//!
//! Database operations for scheduled jobs including CRUD operations
//! and job status management.
//!
//! Requirements: 4.1, 4.3, 4.5

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use thiserror::Error;
use tracing::instrument;
use uuid::Uuid;

use super::types::*;
use crate::upload::UploadDestination;

#[derive(Error, Debug)]
pub enum SchedulerRepositoryError {
    #[error("Database error: {0}")]
    DatabaseError(#[from] sqlx::Error),

    #[error("Job not found: {0}")]
    NotFound(Uuid),

    #[error("Invalid job data: {0}")]
    InvalidData(String),

    #[error("Serialization error: {0}")]
    SerializationError(#[from] serde_json::Error),
}

/// Repository for scheduled job database operations
#[derive(Clone)]
pub struct SchedulerRepository {
    pool: PgPool,
}

impl SchedulerRepository {
    /// Create a new scheduler repository
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Create a new scheduled job
    #[instrument(skip(self, job))]
    pub async fn create_job(
        &self,
        job: &NewScheduledJob,
        next_run_at: Option<DateTime<Utc>>,
    ) -> Result<ScheduledJob, SchedulerRepositoryError> {
        let id = Uuid::now_v7();
        let (dest_type, dest_config) = serialize_destination(&job.destination)?;
        let auth_headers_json = job
            .auth_headers
            .as_ref()
            .map(|h| serde_json::to_value(h))
            .transpose()?;

        // Derive lookup_table_name from destination
        let lookup_table_name = match &job.destination {
            UploadDestination::LookupTable { table_name, .. } => table_name.clone(),
        };

        let row = sqlx::query_as::<_, ScheduledJobRow>(
            r#"
            INSERT INTO scheduled_jobs (
                id, name, description, cron_expression, url, auth_headers,
                destination_type, destination_config, parser_config,
                retry_max, retry_delay_secs, enabled, next_run_at, lookup_table_name
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
            RETURNING *
            "#,
        )
        .bind(id)
        .bind(&job.name)
        .bind(&job.description)
        .bind(&job.cron_expression)
        .bind(&job.url)
        .bind(auth_headers_json)
        .bind(dest_type)
        .bind(sqlx::types::Json(dest_config))
        .bind(sqlx::types::Json(&job.parser_config))
        .bind(job.retry_policy.max_retries as i32)
        .bind(job.retry_policy.retry_delay_secs as i32)
        .bind(job.enabled)
        .bind(next_run_at)
        .bind(&lookup_table_name)
        .fetch_one(&self.pool)
        .await?;

        row.try_into()
            .map_err(SchedulerRepositoryError::InvalidData)
    }

    /// Get a scheduled job by ID
    #[instrument(skip(self))]
    pub async fn get_job(&self, id: Uuid) -> Result<ScheduledJob, SchedulerRepositoryError> {
        let row =
            sqlx::query_as::<_, ScheduledJobRow>("SELECT * FROM scheduled_jobs WHERE id = $1")
                .bind(id)
                .fetch_optional(&self.pool)
                .await?
                .ok_or(SchedulerRepositoryError::NotFound(id))?;

        row.try_into()
            .map_err(SchedulerRepositoryError::InvalidData)
    }

    /// List all scheduled jobs with optional filters
    #[instrument(skip(self))]
    pub async fn list_jobs(
        &self,
        filter: &JobFilter,
    ) -> Result<Vec<ScheduledJob>, SchedulerRepositoryError> {
        let mut query = String::from("SELECT * FROM scheduled_jobs WHERE 1=1");
        let mut params: Vec<String> = Vec::new();

        if let Some(enabled) = filter.enabled {
            params.push(enabled.to_string());
            query.push_str(&format!(" AND enabled = ${}", params.len()));
        }

        if let Some(ref dest_type) = filter.destination_type {
            params.push(dest_type.clone());
            query.push_str(&format!(" AND destination_type = ${}", params.len()));
        }

        query.push_str(" ORDER BY created_at DESC");

        if let Some(limit) = filter.limit {
            query.push_str(&format!(" LIMIT {}", limit));
        }

        if let Some(offset) = filter.offset {
            query.push_str(&format!(" OFFSET {}", offset));
        }

        // Build the query dynamically
        let rows = match (filter.enabled, filter.destination_type.as_ref()) {
            (Some(enabled), Some(dest_type)) => {
                sqlx::query_as::<_, ScheduledJobRow>(&query)
                    .bind(enabled)
                    .bind(dest_type)
                    .fetch_all(&self.pool)
                    .await?
            }
            (Some(enabled), None) => {
                sqlx::query_as::<_, ScheduledJobRow>(&query)
                    .bind(enabled)
                    .fetch_all(&self.pool)
                    .await?
            }
            (None, Some(dest_type)) => {
                sqlx::query_as::<_, ScheduledJobRow>(&query)
                    .bind(dest_type)
                    .fetch_all(&self.pool)
                    .await?
            }
            (None, None) => {
                sqlx::query_as::<_, ScheduledJobRow>(&query)
                    .fetch_all(&self.pool)
                    .await?
            }
        };

        rows.into_iter()
            .map(|row| {
                row.try_into()
                    .map_err(SchedulerRepositoryError::InvalidData)
            })
            .collect()
    }

    /// Update a scheduled job
    #[instrument(skip(self, update))]
    pub async fn update_job(
        &self,
        id: Uuid,
        update: &UpdateScheduledJob,
        next_run_at: Option<DateTime<Utc>>,
    ) -> Result<ScheduledJob, SchedulerRepositoryError> {
        // First get the existing job
        let existing = self.get_job(id).await?;

        // Merge updates with existing values
        let name = update.name.as_ref().unwrap_or(&existing.name);
        let description = update.description.clone().unwrap_or(existing.description);
        let cron_expression = update
            .cron_expression
            .as_ref()
            .unwrap_or(&existing.cron_expression);
        let url = update.url.as_ref().unwrap_or(&existing.url);
        let auth_headers = update.auth_headers.clone().unwrap_or(existing.auth_headers);
        let destination = update.destination.clone().unwrap_or(existing.destination);
        let parser_config = update
            .parser_config
            .clone()
            .unwrap_or(existing.parser_config);
        let retry_policy = update.retry_policy.unwrap_or(existing.retry_policy);
        let enabled = update.enabled.unwrap_or(existing.enabled);

        let (dest_type, dest_config) = serialize_destination(&destination)?;
        let auth_headers_json = auth_headers
            .as_ref()
            .map(|h| serde_json::to_value(h))
            .transpose()?;

        let row = sqlx::query_as::<_, ScheduledJobRow>(
            r#"
            UPDATE scheduled_jobs SET
                name = $2,
                description = $3,
                cron_expression = $4,
                url = $5,
                auth_headers = $6,
                destination_type = $7,
                destination_config = $8,
                parser_config = $9,
                retry_max = $10,
                retry_delay_secs = $11,
                enabled = $12,
                next_run_at = COALESCE($13, next_run_at)
            WHERE id = $1
            RETURNING *
            "#,
        )
        .bind(id)
        .bind(name)
        .bind(&description)
        .bind(cron_expression)
        .bind(url)
        .bind(auth_headers_json)
        .bind(dest_type)
        .bind(sqlx::types::Json(dest_config))
        .bind(sqlx::types::Json(&parser_config))
        .bind(retry_policy.max_retries as i32)
        .bind(retry_policy.retry_delay_secs as i32)
        .bind(enabled)
        .bind(next_run_at)
        .fetch_one(&self.pool)
        .await?;

        row.try_into()
            .map_err(SchedulerRepositoryError::InvalidData)
    }

    /// Delete a scheduled job
    #[instrument(skip(self))]
    pub async fn delete_job(&self, id: Uuid) -> Result<bool, SchedulerRepositoryError> {
        let result = sqlx::query("DELETE FROM scheduled_jobs WHERE id = $1")
            .bind(id)
            .execute(&self.pool)
            .await?;

        Ok(result.rows_affected() > 0)
    }

    /// Get a scheduled job by lookup table name
    #[instrument(skip(self))]
    pub async fn get_job_by_lookup_table(
        &self,
        lookup_table_name: &str,
    ) -> Result<Option<ScheduledJob>, SchedulerRepositoryError> {
        let row = sqlx::query_as::<_, ScheduledJobRow>(
            "SELECT * FROM scheduled_jobs WHERE lookup_table_name = $1",
        )
        .bind(lookup_table_name)
        .fetch_optional(&self.pool)
        .await?;

        match row {
            Some(r) => Ok(Some(
                r.try_into()
                    .map_err(SchedulerRepositoryError::InvalidData)?,
            )),
            None => Ok(None),
        }
    }

    /// Delete a scheduled job by lookup table name
    #[instrument(skip(self))]
    pub async fn delete_job_by_lookup_table(
        &self,
        lookup_table_name: &str,
    ) -> Result<bool, SchedulerRepositoryError> {
        let result = sqlx::query("DELETE FROM scheduled_jobs WHERE lookup_table_name = $1")
            .bind(lookup_table_name)
            .execute(&self.pool)
            .await?;

        Ok(result.rows_affected() > 0)
    }

    /// Update job execution status
    #[instrument(skip(self))]
    pub async fn update_job_status(
        &self,
        id: Uuid,
        status: JobStatus,
        error: Option<&str>,
        next_run_at: Option<DateTime<Utc>>,
    ) -> Result<(), SchedulerRepositoryError> {
        sqlx::query(
            r#"
            UPDATE scheduled_jobs SET
                last_run_at = NOW(),
                last_run_status = $2,
                last_run_error = $3,
                next_run_at = $4
            WHERE id = $1
            "#,
        )
        .bind(id)
        .bind(status.as_str())
        .bind(error)
        .bind(next_run_at)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// Mark a job as running
    #[instrument(skip(self))]
    pub async fn mark_job_running(&self, id: Uuid) -> Result<(), SchedulerRepositoryError> {
        sqlx::query(
            r#"
            UPDATE scheduled_jobs SET
                last_run_status = 'running'
            WHERE id = $1
            "#,
        )
        .bind(id)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// Get jobs that are due to run
    #[instrument(skip(self))]
    pub async fn get_due_jobs(&self) -> Result<Vec<ScheduledJob>, SchedulerRepositoryError> {
        let rows = sqlx::query_as::<_, ScheduledJobRow>(
            r#"
            SELECT * FROM scheduled_jobs
            WHERE enabled = true
              AND next_run_at IS NOT NULL
              AND next_run_at <= NOW()
              AND (last_run_status IS NULL OR last_run_status != 'running')
            ORDER BY next_run_at ASC
            "#,
        )
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter()
            .map(|row| {
                row.try_into()
                    .map_err(SchedulerRepositoryError::InvalidData)
            })
            .collect()
    }

    /// Enable a job
    #[instrument(skip(self))]
    pub async fn enable_job(
        &self,
        id: Uuid,
        next_run_at: Option<DateTime<Utc>>,
    ) -> Result<ScheduledJob, SchedulerRepositoryError> {
        let row = sqlx::query_as::<_, ScheduledJobRow>(
            r#"
            UPDATE scheduled_jobs SET
                enabled = true,
                next_run_at = COALESCE($2, next_run_at)
            WHERE id = $1
            RETURNING *
            "#,
        )
        .bind(id)
        .bind(next_run_at)
        .fetch_one(&self.pool)
        .await?;

        row.try_into()
            .map_err(SchedulerRepositoryError::InvalidData)
    }

    /// Disable a job
    #[instrument(skip(self))]
    pub async fn disable_job(&self, id: Uuid) -> Result<ScheduledJob, SchedulerRepositoryError> {
        let row = sqlx::query_as::<_, ScheduledJobRow>(
            r#"
            UPDATE scheduled_jobs SET
                enabled = false
            WHERE id = $1
            RETURNING *
            "#,
        )
        .bind(id)
        .fetch_one(&self.pool)
        .await?;

        row.try_into()
            .map_err(SchedulerRepositoryError::InvalidData)
    }

    // ==================== DISTRIBUTED CLAIMING METHODS ====================

    /// Atomically claim a batch of due jobs using SKIP LOCKED.
    ///
    /// Returns jobs that are now claimed by this node. Other nodes calling
    /// this concurrently will get disjoint sets (no double-execution).
    #[instrument(skip(self))]
    pub async fn claim_due_jobs(
        &self,
        batch_size: i64,
        node_id: &str,
        stale_timeout_secs: i64,
    ) -> Result<Vec<ScheduledJob>, SchedulerRepositoryError> {
        let rows = sqlx::query_as::<_, ScheduledJobRow>(
            r#"
            WITH claimable AS (
                SELECT id FROM scheduled_jobs
                WHERE enabled = true
                  AND next_run_at IS NOT NULL AND next_run_at <= NOW()
                  AND (claimed_by IS NULL OR claimed_at < NOW() - make_interval(secs => $3))
                ORDER BY next_run_at ASC
                LIMIT $1
                FOR UPDATE SKIP LOCKED
            )
            UPDATE scheduled_jobs SET claimed_by = $2, claimed_at = NOW(), last_run_status = 'running'
            WHERE id IN (SELECT id FROM claimable)
            RETURNING *
            "#,
        )
        .bind(batch_size)
        .bind(node_id)
        .bind(stale_timeout_secs as f64)
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter()
            .map(|row| {
                row.try_into()
                    .map_err(SchedulerRepositoryError::InvalidData)
            })
            .collect()
    }

    /// Release a claimed job after execution, updating status and next_run_at.
    ///
    /// Safety: only releases if still claimed by the same node_id.
    #[instrument(skip(self))]
    pub async fn release_job_claim(
        &self,
        job_id: Uuid,
        node_id: &str,
        status: JobStatus,
        error: Option<&str>,
        next_run_at: Option<DateTime<Utc>>,
    ) -> Result<(), SchedulerRepositoryError> {
        sqlx::query(
            r#"
            UPDATE scheduled_jobs SET
                claimed_by = NULL,
                claimed_at = NULL,
                last_run_at = NOW(),
                last_run_status = $3,
                last_run_error = $4,
                next_run_at = $5
            WHERE id = $1 AND claimed_by = $2
            "#,
        )
        .bind(job_id)
        .bind(node_id)
        .bind(status.as_str())
        .bind(error)
        .bind(next_run_at)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// Release all claims held by a node (graceful shutdown).
    #[instrument(skip(self))]
    pub async fn release_all_job_claims(
        &self,
        node_id: &str,
    ) -> Result<u64, SchedulerRepositoryError> {
        let result = sqlx::query(
            r#"
            UPDATE scheduled_jobs
            SET claimed_by = NULL, claimed_at = NULL, last_run_status = NULL
            WHERE claimed_by = $1
            "#,
        )
        .bind(node_id)
        .execute(&self.pool)
        .await?;

        Ok(result.rows_affected())
    }

    /// Get job count by status
    #[instrument(skip(self))]
    pub async fn get_job_stats(&self) -> Result<JobStats, SchedulerRepositoryError> {
        let row = sqlx::query_as::<_, JobStatsRow>(
            r#"
            SELECT
                COUNT(*) as total,
                COUNT(*) FILTER (WHERE enabled = true) as enabled,
                COUNT(*) FILTER (WHERE enabled = false) as disabled,
                COUNT(*) FILTER (WHERE last_run_status = 'success') as last_success,
                COUNT(*) FILTER (WHERE last_run_status = 'failed') as last_failed,
                COUNT(*) FILTER (WHERE last_run_status = 'running') as running
            FROM scheduled_jobs
            "#,
        )
        .fetch_one(&self.pool)
        .await?;

        Ok(JobStats {
            total: row.total.unwrap_or(0),
            enabled: row.enabled.unwrap_or(0),
            disabled: row.disabled.unwrap_or(0),
            last_success: row.last_success.unwrap_or(0),
            last_failed: row.last_failed.unwrap_or(0),
            running: row.running.unwrap_or(0),
        })
    }
}

/// Serialize destination to database format
fn serialize_destination(
    destination: &UploadDestination,
) -> Result<(&'static str, serde_json::Value), serde_json::Error> {
    match destination {
        UploadDestination::LookupTable {
            table_name,
            primary_key,
            mode,
        } => {
            let config = serde_json::json!({
                "table_name": table_name,
                "primary_key": primary_key,
                "mode": mode.as_str(),
            });
            Ok(("lookup", config))
        }
    }
}

/// Job statistics
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct JobStats {
    pub total: i64,
    pub enabled: i64,
    pub disabled: i64,
    pub last_success: i64,
    pub last_failed: i64,
    pub running: i64,
}

#[derive(Debug, sqlx::FromRow)]
struct JobStatsRow {
    total: Option<i64>,
    enabled: Option<i64>,
    disabled: Option<i64>,
    last_success: Option<i64>,
    last_failed: Option<i64>,
    running: Option<i64>,
}
