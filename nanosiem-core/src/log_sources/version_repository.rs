// SPDX-License-Identifier: AGPL-3.0-or-later

//! Log Source Version Repository
//!
//! Manages versioned snapshots of log source parser configurations.
//! Follows the same pattern as `crate::tuning::versions::RuleVersionManager`.

use chrono::{DateTime, Utc};
use sqlx::{PgPool, Postgres, Transaction};
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
        extension_vrl: Option<&str>,
        extension_enabled: bool,
    ) -> Result<LogSourceVersion, LogSourceVersionError> {
        let mut tx = self.pool.begin().await?;
        let version = insert_version(
            &mut tx,
            log_source_id,
            parser_vrl,
            output_fields,
            is_active,
            created_by,
            change_reason,
            reverted_from,
            extension_vrl,
            extension_enabled,
        )
        .await?;
        tx.commit().await?;
        Ok(version)
    }

    /// NAN-4919: publish exactly the working copy at `revision` (its
    /// `updated_at`, the revision the caller validated and reviewed). In ONE
    /// transaction: lock the source row, compare the revision, and create the
    /// active version from the locked row. `Ok(None)` = the working copy
    /// moved (the caller answers 409); nothing was created.
    pub async fn publish_revision(
        &self,
        log_source_id: Uuid,
        revision: DateTime<Utc>,
        created_by: Option<Uuid>,
    ) -> Result<Option<LogSourceVersion>, LogSourceVersionError> {
        let mut tx = self.pool.begin().await?;
        let row = lock_source(&mut tx, log_source_id).await?;
        if row.updated_at != revision {
            return Ok(None);
        }
        let version = insert_version(
            &mut tx,
            log_source_id,
            &row.parser_vrl,
            row.output_fields.as_ref(),
            true,
            created_by,
            "publish",
            None,
            row.extension_vrl.as_deref(),
            row.extension_enabled,
        )
        .await?;
        tx.commit().await?;
        Ok(Some(version))
    }

    /// NAN-4919: reset the working copy to the active version in ONE
    /// transaction: lock the source row (serializing with publish), compare
    /// the optional expected revision, read the active version under the same
    /// lock, and update the row.
    pub async fn discard_to_active(
        &self,
        log_source_id: Uuid,
        expected: Option<DateTime<Utc>>,
    ) -> Result<DiscardOutcome, LogSourceVersionError> {
        let mut tx = self.pool.begin().await?;
        let row = lock_source(&mut tx, log_source_id).await?;
        if expected.is_some_and(|expected| expected != row.updated_at) {
            return Ok(DiscardOutcome::Stale);
        }
        let active: Option<(String, Option<serde_json::Value>, Option<String>, bool)> =
            sqlx::query_as(
                "SELECT parser_vrl, output_fields, extension_vrl, extension_enabled
                 FROM log_source_versions
                 WHERE log_source_id = $1 AND is_active = true",
            )
            .bind(log_source_id)
            .fetch_optional(&mut *tx)
            .await?;
        let Some((parser_vrl, output_fields, extension_vrl, extension_enabled)) = active else {
            return Ok(DiscardOutcome::NoActiveVersion);
        };
        sqlx::query(
            "UPDATE log_sources SET
                 parser_vrl = $2,
                 output_fields = COALESCE($3, output_fields),
                 extension_vrl = $4,
                 extension_enabled = $5,
                 deployed = false
             WHERE id = $1",
        )
        .bind(log_source_id)
        .bind(&parser_vrl)
        .bind(&output_fields)
        .bind(extension_vrl.filter(|ext| !ext.is_empty()))
        .bind(extension_enabled)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(DiscardOutcome::Discarded)
    }

    /// Get the active version for a log source (None if never published)
    pub async fn get_active_version(
        &self,
        log_source_id: Uuid,
    ) -> Result<Option<LogSourceVersion>, LogSourceVersionError> {
        let version: Option<LogSourceVersion> = sqlx::query_as(
            r#"SELECT id, log_source_id, version_number, parser_vrl, output_fields,
                      is_active, created_at, created_by, change_reason, reverted_from_version,
                      extension_vrl, extension_enabled
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
                      is_active, created_at, created_by, change_reason, reverted_from_version,
                      extension_vrl, extension_enabled
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
                      is_active, created_at, created_by, change_reason, reverted_from_version,
                      extension_vrl, extension_enabled
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

/// What [`LogSourceVersionRepository::discard_to_active`] did.
#[derive(Debug, PartialEq, Eq)]
pub enum DiscardOutcome {
    Discarded,
    /// The working copy moved since the caller's expected revision.
    Stale,
    NoActiveVersion,
}

#[derive(sqlx::FromRow)]
struct LockedSource {
    parser_vrl: String,
    output_fields: Option<serde_json::Value>,
    extension_vrl: Option<String>,
    extension_enabled: bool,
    updated_at: DateTime<Utc>,
}

async fn lock_source(
    tx: &mut Transaction<'_, Postgres>,
    log_source_id: Uuid,
) -> Result<LockedSource, LogSourceVersionError> {
    sqlx::query_as::<_, LockedSource>(
        "SELECT parser_vrl, output_fields, extension_vrl, extension_enabled, updated_at
         FROM log_sources WHERE id = $1 FOR UPDATE",
    )
    .bind(log_source_id)
    .fetch_optional(&mut **tx)
    .await?
    .ok_or(LogSourceVersionError::LogSourceNotFound(log_source_id))
}

#[allow(clippy::too_many_arguments)]
async fn insert_version(
    tx: &mut Transaction<'_, Postgres>,
    log_source_id: Uuid,
    parser_vrl: &str,
    output_fields: Option<&serde_json::Value>,
    is_active: bool,
    created_by: Option<Uuid>,
    change_reason: &str,
    reverted_from: Option<i32>,
    extension_vrl: Option<&str>,
    extension_enabled: bool,
) -> Result<LogSourceVersion, LogSourceVersionError> {
    // Get next version number
    let next_version: i32 = sqlx::query_scalar(
        "SELECT COALESCE(MAX(version_number), 0) + 1
         FROM log_source_versions
         WHERE log_source_id = $1",
    )
    .bind(log_source_id)
    .fetch_one(&mut **tx)
    .await?;

    // Deactivate others if this is active
    if is_active {
        sqlx::query("UPDATE log_source_versions SET is_active = false WHERE log_source_id = $1")
            .bind(log_source_id)
            .execute(&mut **tx)
            .await?;
    }

    Ok(sqlx::query_as(
        r#"INSERT INTO log_source_versions
           (log_source_id, version_number, parser_vrl, output_fields, is_active,
            created_by, change_reason, reverted_from_version,
            extension_vrl, extension_enabled)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
           RETURNING id, log_source_id, version_number, parser_vrl, output_fields,
                     is_active, created_at, created_by, change_reason, reverted_from_version,
                     extension_vrl, extension_enabled"#,
    )
    .bind(log_source_id)
    .bind(next_version)
    .bind(parser_vrl)
    .bind(output_fields)
    .bind(is_active)
    .bind(created_by)
    .bind(change_reason)
    .bind(reverted_from)
    .bind(extension_vrl)
    .bind(extension_enabled)
    .fetch_one(&mut **tx)
    .await?)
}
