// SPDX-License-Identifier: AGPL-3.0-or-later

//! Rule Version Manager for AI Detection Auto-Tuning
//!
//! Manages detection rule versioning for tracking changes and enabling reverts:
//! - Creates new versions when tuning is applied
//! - Retrieves active and historical versions
//! - Activates specific versions
//! - Reverts to previous versions with audit trail
//! - Tracks version metadata (author, reason, proposal link)

use chrono::{Duration, Utc};
use sqlx::{PgPool, Row};
use thiserror::Error;
use uuid::Uuid;

use super::{RuleVersion, VersionChangeReason};

/// Errors that can occur during version management operations
#[derive(Error, Debug)]
pub enum VersionManagerError {
    #[error("Database error: {0}")]
    DatabaseError(String),

    #[error("Rule not found: {0}")]
    RuleNotFound(Uuid),

    #[error("Version not found: {0}")]
    VersionNotFound(i32),

    #[error("No active version found for rule: {0}")]
    NoActiveVersion(Uuid),

    #[error("Invalid version data: {0}")]
    InvalidVersionData(String),

    #[error("Version conflict: {0}")]
    VersionConflict(String),
}

impl From<sqlx::Error> for VersionManagerError {
    fn from(err: sqlx::Error) -> Self {
        VersionManagerError::DatabaseError(err.to_string())
    }
}

/// Rule version manager service
#[derive(Clone)]
pub struct RuleVersionManager {
    pg_pool: PgPool,
}

impl RuleVersionManager {
    /// Create a new rule version manager
    pub fn new(pg_pool: PgPool) -> Self {
        Self { pg_pool }
    }

    /// Create a new version for a detection rule
    ///
    /// This method creates a new version entry with incremented version number,
    /// preserving all rule metadata and tracking the change reason.
    ///
    /// # Arguments
    /// * `version` - The version data to create
    ///
    /// # Returns
    /// * `i32` - The ID of the created version
    ///
    /// # Errors
    /// * `RuleNotFound` - If the rule doesn't exist
    /// * `DatabaseError` - If the database operation fails
    pub async fn create_version(&self, version: RuleVersion) -> Result<i32, VersionManagerError> {
        // Verify rule exists
        let rule_exists: bool =
            sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM detection_rules WHERE id = $1)")
                .bind(version.rule_id)
                .fetch_one(&self.pg_pool)
                .await?;

        if !rule_exists {
            return Err(VersionManagerError::RuleNotFound(version.rule_id));
        }

        // Get the next version number
        let next_version_number: i32 = sqlx::query_scalar(
            "SELECT COALESCE(MAX(version_number), 0) + 1 
             FROM detection_rule_versions 
             WHERE rule_id = $1",
        )
        .bind(version.rule_id)
        .fetch_one(&self.pg_pool)
        .await?;

        // If this version is being marked as active, deactivate all other versions for this rule
        if version.is_active {
            sqlx::query(
                "UPDATE detection_rule_versions 
                 SET is_active = false 
                 WHERE rule_id = $1",
            )
            .bind(version.rule_id)
            .execute(&self.pg_pool)
            .await?;
        }

        // Insert the new version
        let version_id: i32 = sqlx::query_scalar(
            "INSERT INTO detection_rule_versions (
                rule_id, version_number, query, name, description, severity,
                enabled, is_active, created_by, change_reason, 
                tuning_proposal_id, reverted_from_version
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
            RETURNING id",
        )
        .bind(version.rule_id)
        .bind(next_version_number)
        .bind(&version.query)
        .bind(&version.name)
        .bind(&version.description)
        .bind(&version.severity)
        .bind(version.enabled)
        .bind(version.is_active)
        .bind(version.created_by)
        .bind(&version.change_reason)
        .bind(version.tuning_proposal_id)
        .bind(version.reverted_from_version)
        .fetch_one(&self.pg_pool)
        .await?;

        Ok(version_id)
    }

    /// Get the active version for a detection rule
    ///
    /// # Arguments
    /// * `rule_id` - UUID of the detection rule
    ///
    /// # Returns
    /// * `RuleVersion` - The active version
    ///
    /// # Errors
    /// * `NoActiveVersion` - If no active version exists
    /// * `RuleNotFound` - If the rule doesn't exist
    pub async fn get_active_version(
        &self,
        rule_id: Uuid,
    ) -> Result<RuleVersion, VersionManagerError> {
        let row = sqlx::query(
            r#"
            SELECT 
                id, rule_id, version_number, query, name, description,
                severity, enabled, is_active, created_at,
                created_by, change_reason, tuning_proposal_id,
                reverted_from_version
            FROM detection_rule_versions
            WHERE rule_id = $1 AND is_active = true
            "#,
        )
        .bind(rule_id)
        .fetch_optional(&self.pg_pool)
        .await?;

        match row {
            Some(row) => Ok(RuleVersion {
                id: row.get("id"),
                rule_id: row.get("rule_id"),
                version_number: row.get("version_number"),
                query: row.get("query"),
                name: row.get("name"),
                description: row.get("description"),
                severity: row.get("severity"),
                enabled: row.get("enabled"),
                is_active: row.get("is_active"),
                created_at: row.get("created_at"),
                created_by: row.get("created_by"),
                change_reason: row.get("change_reason"),
                tuning_proposal_id: row.get("tuning_proposal_id"),
                reverted_from_version: row.get("reverted_from_version"),
            }),
            None => Err(VersionManagerError::NoActiveVersion(rule_id)),
        }
    }

    /// Get all versions for a detection rule
    ///
    /// Returns versions in descending order by version number (newest first).
    ///
    /// # Arguments
    /// * `rule_id` - UUID of the detection rule
    ///
    /// # Returns
    /// * `Vec<RuleVersion>` - List of all versions
    pub async fn get_version_history(
        &self,
        rule_id: Uuid,
    ) -> Result<Vec<RuleVersion>, VersionManagerError> {
        let rows = sqlx::query(
            r#"
            SELECT 
                id, rule_id, version_number, query, name, description,
                severity, enabled, is_active, created_at,
                created_by, change_reason, tuning_proposal_id,
                reverted_from_version
            FROM detection_rule_versions
            WHERE rule_id = $1
            ORDER BY version_number DESC
            "#,
        )
        .bind(rule_id)
        .fetch_all(&self.pg_pool)
        .await?;

        let versions = rows
            .into_iter()
            .map(|row| RuleVersion {
                id: row.get("id"),
                rule_id: row.get("rule_id"),
                version_number: row.get("version_number"),
                query: row.get("query"),
                name: row.get("name"),
                description: row.get("description"),
                severity: row.get("severity"),
                enabled: row.get("enabled"),
                is_active: row.get("is_active"),
                created_at: row.get("created_at"),
                created_by: row.get("created_by"),
                change_reason: row.get("change_reason"),
                tuning_proposal_id: row.get("tuning_proposal_id"),
                reverted_from_version: row.get("reverted_from_version"),
            })
            .collect();

        Ok(versions)
    }

    /// Activate a specific version of a detection rule
    ///
    /// This method deactivates all other versions and marks the specified
    /// version as active. It also updates the main detection_rules table
    /// to reflect the activated version.
    ///
    /// # Arguments
    /// * `rule_id` - UUID of the detection rule
    /// * `version_id` - ID of the version to activate
    ///
    /// # Errors
    /// * `VersionNotFound` - If the version doesn't exist
    /// * `RuleNotFound` - If the rule doesn't exist
    pub async fn activate_version(
        &self,
        rule_id: Uuid,
        version_id: i32,
    ) -> Result<(), VersionManagerError> {
        // Start a transaction
        let mut tx = self.pg_pool.begin().await?;

        // Verify the version exists and belongs to the rule
        let row = sqlx::query(
            r#"
            SELECT 
                id, rule_id, version_number, query, name, description,
                severity, enabled, is_active, created_at,
                created_by, change_reason, tuning_proposal_id,
                reverted_from_version
            FROM detection_rule_versions
            WHERE id = $1 AND rule_id = $2
            "#,
        )
        .bind(version_id)
        .bind(rule_id)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or(VersionManagerError::VersionNotFound(version_id))?;

        let version = RuleVersion {
            id: row.get("id"),
            rule_id: row.get("rule_id"),
            version_number: row.get("version_number"),
            query: row.get("query"),
            name: row.get("name"),
            description: row.get("description"),
            severity: row.get("severity"),
            enabled: row.get("enabled"),
            is_active: row.get("is_active"),
            created_at: row.get("created_at"),
            created_by: row.get("created_by"),
            change_reason: row.get("change_reason"),
            tuning_proposal_id: row.get("tuning_proposal_id"),
            reverted_from_version: row.get("reverted_from_version"),
        };

        // Deactivate all versions for this rule
        sqlx::query(
            "UPDATE detection_rule_versions 
             SET is_active = false 
             WHERE rule_id = $1",
        )
        .bind(rule_id)
        .execute(&mut *tx)
        .await?;

        // Activate the specified version
        sqlx::query(
            "UPDATE detection_rule_versions 
             SET is_active = true 
             WHERE id = $1",
        )
        .bind(version_id)
        .execute(&mut *tx)
        .await?;

        // Update the main detection_rules table with the activated version
        // Note: archived/mode (which replaced the old 'enabled' column) are not changed
        // during version activation — rule enablement is managed separately
        sqlx::query(
            "UPDATE detection_rules
             SET query = $1, name = $2, description = $3, severity = $4
             WHERE id = $5",
        )
        .bind(&version.query)
        .bind(&version.name)
        .bind(&version.description)
        .bind(&version.severity)
        .bind(rule_id)
        .execute(&mut *tx)
        .await?;

        // Commit the transaction
        tx.commit().await?;

        Ok(())
    }

    /// Revert a detection rule to a previous version
    ///
    /// This method creates a new version entry marking it as a revert,
    /// activates the previous version, and disables auto-tuning for 7 days.
    ///
    /// # Arguments
    /// * `rule_id` - UUID of the detection rule
    /// * `version_id` - ID of the version to revert to
    /// * `reverted_by` - User UUID performing the revert
    ///
    /// # Returns
    /// * `i32` - The ID of the new revert version entry
    ///
    /// # Errors
    /// * `VersionNotFound` - If the version doesn't exist
    /// * `RuleNotFound` - If the rule doesn't exist
    pub async fn revert_to_version(
        &self,
        rule_id: Uuid,
        version_id: i32,
        reverted_by: Uuid,
    ) -> Result<i32, VersionManagerError> {
        // Start a transaction
        let mut tx = self.pg_pool.begin().await?;

        // Get the version to revert to
        let row = sqlx::query(
            r#"
            SELECT 
                id, rule_id, version_number, query, name, description,
                severity, enabled, is_active, created_at,
                created_by, change_reason, tuning_proposal_id,
                reverted_from_version
            FROM detection_rule_versions
            WHERE id = $1 AND rule_id = $2
            "#,
        )
        .bind(version_id)
        .bind(rule_id)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or(VersionManagerError::VersionNotFound(version_id))?;

        let target_version = RuleVersion {
            id: row.get("id"),
            rule_id: row.get("rule_id"),
            version_number: row.get("version_number"),
            query: row.get("query"),
            name: row.get("name"),
            description: row.get("description"),
            severity: row.get("severity"),
            enabled: row.get("enabled"),
            is_active: row.get("is_active"),
            created_at: row.get("created_at"),
            created_by: row.get("created_by"),
            change_reason: row.get("change_reason"),
            tuning_proposal_id: row.get("tuning_proposal_id"),
            reverted_from_version: row.get("reverted_from_version"),
        };

        // Get the current active version
        let current_version_row = sqlx::query(
            r#"
            SELECT 
                id, rule_id, version_number, query, name, description,
                severity, enabled, is_active, created_at,
                created_by, change_reason, tuning_proposal_id,
                reverted_from_version
            FROM detection_rule_versions
            WHERE rule_id = $1 AND is_active = true
            "#,
        )
        .bind(rule_id)
        .fetch_optional(&mut *tx)
        .await?;

        let current_version = current_version_row.map(|row| RuleVersion {
            id: row.get("id"),
            rule_id: row.get("rule_id"),
            version_number: row.get("version_number"),
            query: row.get("query"),
            name: row.get("name"),
            description: row.get("description"),
            severity: row.get("severity"),
            enabled: row.get("enabled"),
            is_active: row.get("is_active"),
            created_at: row.get("created_at"),
            created_by: row.get("created_by"),
            change_reason: row.get("change_reason"),
            tuning_proposal_id: row.get("tuning_proposal_id"),
            reverted_from_version: row.get("reverted_from_version"),
        });

        // Get the next version number
        let next_version_number: i32 = sqlx::query_scalar(
            "SELECT COALESCE(MAX(version_number), 0) + 1 
             FROM detection_rule_versions 
             WHERE rule_id = $1",
        )
        .bind(rule_id)
        .fetch_one(&mut *tx)
        .await?;

        // Create a new version entry marking it as a revert
        let revert_version_id: i32 = sqlx::query_scalar(
            "INSERT INTO detection_rule_versions (
                rule_id, version_number, query, name, description, severity,
                enabled, is_active, created_by, change_reason, 
                tuning_proposal_id, reverted_from_version
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
            RETURNING id",
        )
        .bind(rule_id)
        .bind(next_version_number)
        .bind(&target_version.query)
        .bind(&target_version.name)
        .bind(&target_version.description)
        .bind(&target_version.severity)
        .bind(target_version.enabled)
        .bind(false) // Not active yet
        .bind(Some(reverted_by))
        .bind(VersionChangeReason::Revert.to_string())
        .bind(target_version.tuning_proposal_id)
        .bind(current_version.as_ref().map(|v| v.id))
        .fetch_one(&mut *tx)
        .await?;

        // Deactivate all versions for this rule
        sqlx::query(
            "UPDATE detection_rule_versions 
             SET is_active = false 
             WHERE rule_id = $1",
        )
        .bind(rule_id)
        .execute(&mut *tx)
        .await?;

        // Activate the new revert version
        sqlx::query(
            "UPDATE detection_rule_versions 
             SET is_active = true 
             WHERE id = $1",
        )
        .bind(revert_version_id)
        .execute(&mut *tx)
        .await?;

        // Update the main detection_rules table with the reverted version
        // Note: archived/mode (which replaced the old 'enabled' column) are not changed
        // during version revert — rule enablement is managed separately
        sqlx::query(
            "UPDATE detection_rules
             SET query = $1, name = $2, description = $3, severity = $4
             WHERE id = $5",
        )
        .bind(&target_version.query)
        .bind(&target_version.name)
        .bind(&target_version.description)
        .bind(&target_version.severity)
        .bind(rule_id)
        .execute(&mut *tx)
        .await?;

        // Disable auto-tuning for 7 days
        let disabled_until = Utc::now() + Duration::days(7);
        sqlx::query(
            "UPDATE detection_rules 
             SET auto_tuning_disabled_until = $1 
             WHERE id = $2",
        )
        .bind(disabled_until)
        .bind(rule_id)
        .execute(&mut *tx)
        .await?;

        // Commit the transaction
        tx.commit().await?;

        Ok(revert_version_id)
    }

    /// Get a specific version by ID
    ///
    /// # Arguments
    /// * `version_id` - ID of the version to retrieve
    ///
    /// # Returns
    /// * `RuleVersion` - The requested version
    ///
    /// # Errors
    /// * `VersionNotFound` - If the version doesn't exist
    pub async fn get_version(&self, version_id: i32) -> Result<RuleVersion, VersionManagerError> {
        let row = sqlx::query(
            r#"
            SELECT 
                id, rule_id, version_number, query, name, description,
                severity, enabled, is_active, created_at,
                created_by, change_reason, tuning_proposal_id,
                reverted_from_version
            FROM detection_rule_versions
            WHERE id = $1
            "#,
        )
        .bind(version_id)
        .fetch_optional(&self.pg_pool)
        .await?;

        match row {
            Some(row) => Ok(RuleVersion {
                id: row.get("id"),
                rule_id: row.get("rule_id"),
                version_number: row.get("version_number"),
                query: row.get("query"),
                name: row.get("name"),
                description: row.get("description"),
                severity: row.get("severity"),
                enabled: row.get("enabled"),
                is_active: row.get("is_active"),
                created_at: row.get("created_at"),
                created_by: row.get("created_by"),
                change_reason: row.get("change_reason"),
                tuning_proposal_id: row.get("tuning_proposal_id"),
                reverted_from_version: row.get("reverted_from_version"),
            }),
            None => Err(VersionManagerError::VersionNotFound(version_id)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version_manager_error_display() {
        let err = VersionManagerError::RuleNotFound(Uuid::now_v7());
        assert!(err.to_string().contains("Rule not found"));

        let err = VersionManagerError::VersionNotFound(123);
        assert!(err.to_string().contains("Version not found"));

        let err = VersionManagerError::NoActiveVersion(Uuid::now_v7());
        assert!(err.to_string().contains("No active version found"));
    }
}
