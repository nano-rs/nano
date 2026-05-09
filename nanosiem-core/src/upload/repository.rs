// SPDX-License-Identifier: AGPL-3.0-or-later

//! Upload repository for database operations
//!
//! Provides database operations for upload history tracking.
//!
//! Requirements: 5.1, 5.2

use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use thiserror::Error;
use tracing::instrument;
use uuid::Uuid;

use super::parser::FileFormat;
use super::types::*;

#[derive(Error, Debug)]
pub enum UploadRepositoryError {
    #[error("Database error: {0}")]
    DatabaseError(#[from] sqlx::Error),
    #[error("Upload not found: {0}")]
    UploadNotFound(Uuid),
}

/// Repository for upload history operations
#[derive(Clone)]
pub struct UploadRepository {
    pool: PgPool,
}

impl UploadRepository {
    /// Create a new upload repository
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Create a new upload record (status: processing)
    #[instrument(skip(self))]
    pub async fn create_upload(
        &self,
        filename: &str,
        file_size: i64,
        file_format: FileFormat,
        destination: &UploadDestination,
    ) -> Result<UploadRecord, UploadRepositoryError> {
        let record = sqlx::query_as::<_, UploadRecord>(
            r#"
            INSERT INTO upload_history (
                filename, file_size, file_format, destination_type, destination_name, status
            )
            VALUES ($1, $2, $3, $4, $5, 'processing')
            RETURNING *
            "#,
        )
        .bind(filename)
        .bind(file_size)
        .bind(file_format.as_str())
        .bind(destination.destination_type())
        .bind(destination.destination_name())
        .fetch_one(&self.pool)
        .await?;

        Ok(record)
    }

    /// Update upload record with completion status
    #[instrument(skip(self))]
    pub async fn complete_upload(
        &self,
        upload_id: Uuid,
        records_total: i64,
        records_success: i64,
        records_failed: i64,
        error_message: Option<&str>,
    ) -> Result<UploadRecord, UploadRepositoryError> {
        let status = if error_message.is_some() || records_failed > 0 && records_success == 0 {
            "failed"
        } else {
            "completed"
        };

        let record = sqlx::query_as::<_, UploadRecord>(
            r#"
            UPDATE upload_history
            SET 
                records_total = $2,
                records_success = $3,
                records_failed = $4,
                status = $5,
                error_message = $6,
                completed_at = NOW()
            WHERE id = $1
            RETURNING *
            "#,
        )
        .bind(upload_id)
        .bind(records_total)
        .bind(records_success)
        .bind(records_failed)
        .bind(status)
        .bind(error_message)
        .fetch_optional(&self.pool)
        .await?
        .ok_or(UploadRepositoryError::UploadNotFound(upload_id))?;

        Ok(record)
    }

    /// Mark upload as failed with error message
    #[instrument(skip(self))]
    pub async fn fail_upload(
        &self,
        upload_id: Uuid,
        error_message: &str,
    ) -> Result<UploadRecord, UploadRepositoryError> {
        let record = sqlx::query_as::<_, UploadRecord>(
            r#"
            UPDATE upload_history
            SET 
                status = 'failed',
                error_message = $2,
                completed_at = NOW()
            WHERE id = $1
            RETURNING *
            "#,
        )
        .bind(upload_id)
        .bind(error_message)
        .fetch_optional(&self.pool)
        .await?
        .ok_or(UploadRepositoryError::UploadNotFound(upload_id))?;

        Ok(record)
    }

    /// Get upload record by ID
    #[instrument(skip(self))]
    pub async fn get_upload(&self, upload_id: Uuid) -> Result<UploadRecord, UploadRepositoryError> {
        let record =
            sqlx::query_as::<_, UploadRecord>("SELECT * FROM upload_history WHERE id = $1")
                .bind(upload_id)
                .fetch_optional(&self.pool)
                .await?
                .ok_or(UploadRepositoryError::UploadNotFound(upload_id))?;

        Ok(record)
    }

    /// List upload history with optional filters
    #[instrument(skip(self))]
    pub async fn list_uploads(
        &self,
        filter: &UploadFilter,
    ) -> Result<Vec<UploadRecord>, UploadRepositoryError> {
        let mut query = String::from("SELECT * FROM upload_history WHERE 1=1");
        let mut param_idx = 1;

        // Build dynamic query based on filters
        if filter.destination_type.is_some() {
            query.push_str(&format!(" AND destination_type = ${}", param_idx));
            param_idx += 1;
        }
        if filter.destination_name.is_some() {
            query.push_str(&format!(" AND destination_name = ${}", param_idx));
            param_idx += 1;
        }
        if filter.status.is_some() {
            query.push_str(&format!(" AND status = ${}", param_idx));
            param_idx += 1;
        }
        if filter.start_date.is_some() {
            query.push_str(&format!(" AND created_at >= ${}", param_idx));
            param_idx += 1;
        }
        if filter.end_date.is_some() {
            query.push_str(&format!(" AND created_at <= ${}", param_idx));
            #[allow(unused_assignments)]
            {
                param_idx += 1;
            }
        }

        query.push_str(" ORDER BY created_at DESC");

        if let Some(limit) = filter.limit {
            query.push_str(&format!(" LIMIT {}", limit));
        } else {
            query.push_str(" LIMIT 100"); // Default limit
        }

        if let Some(offset) = filter.offset {
            query.push_str(&format!(" OFFSET {}", offset));
        }

        // Build and execute query with bindings
        let mut q = sqlx::query_as::<_, UploadRecord>(&query);

        if let Some(ref dest_type) = filter.destination_type {
            q = q.bind(dest_type);
        }
        if let Some(ref dest_name) = filter.destination_name {
            q = q.bind(dest_name);
        }
        if let Some(ref status) = filter.status {
            q = q.bind(status);
        }
        if let Some(ref start_date) = filter.start_date {
            q = q.bind(start_date);
        }
        if let Some(ref end_date) = filter.end_date {
            q = q.bind(end_date);
        }

        let records = q.fetch_all(&self.pool).await?;
        Ok(records)
    }

    /// Delete an upload record
    #[instrument(skip(self))]
    pub async fn delete_upload(&self, upload_id: Uuid) -> Result<bool, UploadRepositoryError> {
        let result = sqlx::query("DELETE FROM upload_history WHERE id = $1")
            .bind(upload_id)
            .execute(&self.pool)
            .await?;

        Ok(result.rows_affected() > 0)
    }

    /// Get upload statistics
    #[instrument(skip(self))]
    pub async fn get_stats(&self) -> Result<UploadStats, UploadRepositoryError> {
        let row = sqlx::query_as::<_, (i64, i64, i64, i64, i64)>(
            r#"
            SELECT 
                COUNT(*) as total_uploads,
                COALESCE(SUM(records_success), 0) as total_records,
                COALESCE(SUM(file_size), 0) as total_bytes,
                COUNT(*) FILTER (WHERE status = 'completed') as successful_uploads,
                COUNT(*) FILTER (WHERE status = 'failed') as failed_uploads
            FROM upload_history
            "#,
        )
        .fetch_one(&self.pool)
        .await?;

        Ok(UploadStats {
            total_uploads: row.0,
            total_records: row.1,
            total_bytes: row.2,
            successful_uploads: row.3,
            failed_uploads: row.4,
        })
    }
}

/// Upload statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UploadStats {
    pub total_uploads: i64,
    pub total_records: i64,
    pub total_bytes: i64,
    pub successful_uploads: i64,
    pub failed_uploads: i64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_upload_filter_default() {
        let filter = UploadFilter::default();
        assert!(filter.destination_type.is_none());
        assert!(filter.status.is_none());
        assert!(filter.limit.is_none());
    }

    #[test]
    fn test_upload_status_conversion() {
        assert_eq!(
            UploadStatus::from_str("processing"),
            Some(UploadStatus::Processing)
        );
        assert_eq!(
            UploadStatus::from_str("completed"),
            Some(UploadStatus::Completed)
        );
        assert_eq!(UploadStatus::from_str("failed"), Some(UploadStatus::Failed));
        assert_eq!(UploadStatus::from_str("invalid"), None);
    }

    #[test]
    fn test_upload_destination() {
        let lookup_dest = UploadDestination::LookupTable {
            table_name: "assets".to_string(),
            primary_key: Some("ip".to_string()),
            mode: LookupMode::Replace,
        };
        assert_eq!(lookup_dest.destination_type(), "lookup");
        assert_eq!(lookup_dest.destination_name(), "assets");
    }
}
