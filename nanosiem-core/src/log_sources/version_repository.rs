// SPDX-License-Identifier: AGPL-3.0-or-later

//! Log Source Version Repository
//!
//! Manages versioned snapshots of log source parser configurations.
//! Follows the same pattern as `crate::tuning::versions::RuleVersionManager`.

use sqlx::PgPool;
use thiserror::Error;
use uuid::Uuid;

use super::types::LogSourceVersion;

#[derive(Error, Debug)]
pub enum LogSourceVersionError {
    #[error("Database error: {0}")]
    DatabaseError(String),
    #[error("Version not found: {0}")]
    VersionNotFound(i32),
    #[error("Log source not found: {0}")]
    LogSourceNotFound(Uuid),
}

impl From<sqlx::Error> for LogSourceVersionError {
    fn from(err: sqlx::Error) -> Self {
        LogSourceVersionError::DatabaseError(err.to_string())
    }
}

#[derive(Clone)]
pub struct LogSourceVersionRepository {
    pool: PgPool,
}

impl LogSourceVersionRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Create a new version, auto-incrementing version_number.
    /// If is_active=true, deactivates all other versions for this log source.
    pub async fn create_version(
        &self,
        log_source_id: Uuid,
        parser_vrl: &str,
        output_fields: Option<&serde_json::Value>,
        is_active: bool,
        created_by: Option<Uuid>,
        change_reason: &str,
        reverted_from: Option<i32>,
    ) -> Result<LogSourceVersion, LogSourceVersionError> {
        let mut tx = self.pool.begin().await?;

        // Get next version number
        let next_version: i32 = sqlx::query_scalar(
            "SELECT COALESCE(MAX(version_number), 0) + 1
             FROM log_source_versions
             WHERE log_source_id = $1",
        )
        .bind(log_source_id)
        .fetch_one(&mut *tx)
        .await?;

        // Deactivate others if this is active
        if is_active {
            sqlx::query(
                "UPDATE log_source_versions SET is_active = false WHERE log_source_id = $1",
            )
            .bind(log_source_id)
            .execute(&mut *tx)
            .await?;
        }

        let version: LogSourceVersion = sqlx::query_as(
            r#"INSERT INTO log_source_versions
               (log_source_id, version_number, parser_vrl, output_fields, is_active,
                created_by, change_reason, reverted_from_version)
               VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
               RETURNING id, log_source_id, version_number, parser_vrl, output_fields,
                         is_active, created_at, created_by, change_reason, reverted_from_version"#,
        )
        .bind(log_source_id)
        .bind(next_version)
        .bind(parser_vrl)
        .bind(output_fields)
        .bind(is_active)
        .bind(created_by)
        .bind(change_reason)
        .bind(reverted_from)
        .fetch_one(&mut *tx)
        .await?;

        tx.commit().await?;
        Ok(version)
    }

    /// Get the active version for a log source (None if never published)
    pub async fn get_active_version(
        &self,
        log_source_id: Uuid,
    ) -> Result<Option<LogSourceVersion>, LogSourceVersionError> {
        let version: Option<LogSourceVersion> = sqlx::query_as(
            r#"SELECT id, log_source_id, version_number, parser_vrl, output_fields,
                      is_active, created_at, created_by, change_reason, reverted_from_version
               FROM log_source_versions
               WHERE log_source_id = $1 AND is_active = true"#,
        )
        .bind(log_source_id)
        .fetch_optional(&self.pool)
        .await?;

        Ok(version)
    }

    /// Version history, newest first
    pub async fn get_version_history(
        &self,
        log_source_id: Uuid,
        limit: i32,
    ) -> Result<Vec<LogSourceVersion>, LogSourceVersionError> {
        let versions: Vec<LogSourceVersion> = sqlx::query_as(
            r#"SELECT id, log_source_id, version_number, parser_vrl, output_fields,
                      is_active, created_at, created_by, change_reason, reverted_from_version
               FROM log_source_versions
               WHERE log_source_id = $1
               ORDER BY version_number DESC
               LIMIT $2"#,
        )
        .bind(log_source_id)
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;

        Ok(versions)
    }

    /// Get specific version by id
    pub async fn get_version(
        &self,
        version_id: i32,
    ) -> Result<LogSourceVersion, LogSourceVersionError> {
        let version: LogSourceVersion = sqlx::query_as(
            r#"SELECT id, log_source_id, version_number, parser_vrl, output_fields,
                      is_active, created_at, created_by, change_reason, reverted_from_version
               FROM log_source_versions
               WHERE id = $1"#,
        )
        .bind(version_id)
        .fetch_optional(&self.pool)
        .await?
        .ok_or(LogSourceVersionError::VersionNotFound(version_id))?;

        Ok(version)
    }

    /// Activate a version (deactivate all others in transaction)
    pub async fn activate_version(
        &self,
        log_source_id: Uuid,
        version_id: i32,
    ) -> Result<(), LogSourceVersionError> {
        let mut tx = self.pool.begin().await?;

        // Verify the version exists and belongs to this log source
        let exists: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM log_source_versions WHERE id = $1 AND log_source_id = $2)",
        )
        .bind(version_id)
        .bind(log_source_id)
        .fetch_one(&mut *tx)
        .await?;

        if !exists {
            return Err(LogSourceVersionError::VersionNotFound(version_id));
        }

        sqlx::query("UPDATE log_source_versions SET is_active = false WHERE log_source_id = $1")
            .bind(log_source_id)
            .execute(&mut *tx)
            .await?;

        sqlx::query("UPDATE log_source_versions SET is_active = true WHERE id = $1")
            .bind(version_id)
            .execute(&mut *tx)
            .await?;

        tx.commit().await?;
        Ok(())
    }

    /// Prune oldest versions keeping max_versions. Never deletes the active version.
    /// Returns the number of versions deleted.
    pub async fn prune_versions(
        &self,
        log_source_id: Uuid,
        max_versions: i32,
    ) -> Result<i32, LogSourceVersionError> {
        let result = sqlx::query(
            r#"DELETE FROM log_source_versions
               WHERE log_source_id = $1 AND is_active = false
                 AND id NOT IN (
                   SELECT id FROM log_source_versions
                   WHERE log_source_id = $1
                   ORDER BY version_number DESC
                   LIMIT $2
                 )"#,
        )
        .bind(log_source_id)
        .bind(max_versions)
        .execute(&self.pool)
        .await?;

        Ok(result.rows_affected() as i32)
    }
}
