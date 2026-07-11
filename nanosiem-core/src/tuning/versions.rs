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

    #[error("Tuning log not found: {0}")]
    TuningLogNotFound(Uuid),

    #[error("Tuning log cannot be reverted: {0}")]
    TuningLogNotRevertible(Uuid),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VersionRevertResult {
    pub version_id: i32,
    pub changed: bool,
    /// True only when this request replayed an already-committed tuning-log revert.
    pub replayed: bool,
    /// The PostgreSQL rollback committed, but the real-time execution view still
    /// needs to be reconciled to this version.
    pub runtime_sync_required: bool,
    /// This caller owns the persisted reconciliation lease and may rebuild the view.
    pub runtime_sync_claimed: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TuningRevertPlan {
    Ready,
    Replayed(VersionRevertResult),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingRuntimeSync {
    pub rule_id: Uuid,
    pub desired_version_id: i32,
}

impl From<sqlx::Error> for VersionManagerError {
    fn from(err: sqlx::Error) -> Self {
        VersionManagerError::DatabaseError(err.to_string())
    }
}

fn tuning_log_is_revertible(status: &str, already_reverted: bool, proposal_type: &str) -> bool {
    proposal_type == "query_tuning"
        && !already_reverted
        && matches!(status, "promoted" | "manually_approved")
}

fn same_rule_content(left: &RuleVersion, right: &RuleVersion) -> bool {
    left.query == right.query
        && left.name == right.name
        && left.description == right.description
        && left.severity == right.severity
}

fn rule_row_matches_target(
    query: &str,
    name: &str,
    description: &Option<String>,
    severity: &str,
    target: &RuleVersion,
) -> bool {
    query == target.query
        && name == target.name
        && description == &target.description
        && severity == target.severity
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
        let mut tx = self.pg_pool.begin().await?;

        // Every rule-version writer takes the same parent-row lock. This makes
        // MAX+1 allocation safe and serializes active-version replacement.
        let locked_rule: Option<Uuid> =
            sqlx::query_scalar("SELECT id FROM detection_rules WHERE id = $1 FOR UPDATE")
                .bind(version.rule_id)
                .fetch_optional(&mut *tx)
                .await?;

        if locked_rule.is_none() {
            return Err(VersionManagerError::RuleNotFound(version.rule_id));
        }

        // Get the next version number
        let next_version_number: i32 = sqlx::query_scalar(
            "SELECT COALESCE(MAX(version_number), 0) + 1 
             FROM detection_rule_versions 
             WHERE rule_id = $1",
        )
        .bind(version.rule_id)
        .fetch_one(&mut *tx)
        .await?;

        // If this version is being marked as active, deactivate all other versions for this rule
        if version.is_active {
            sqlx::query(
                "UPDATE detection_rule_versions 
                 SET is_active = false 
                 WHERE rule_id = $1",
            )
            .bind(version.rule_id)
            .execute(&mut *tx)
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
        .fetch_one(&mut *tx)
        .await?;

        tx.commit().await?;

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

        let locked_rule: Option<Uuid> =
            sqlx::query_scalar("SELECT id FROM detection_rules WHERE id = $1 FOR UPDATE")
                .bind(rule_id)
                .fetch_optional(&mut *tx)
                .await?;
        if locked_rule.is_none() {
            return Err(VersionManagerError::RuleNotFound(rule_id));
        }

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
    /// The version created (or reused) for the revert and its reconciliation state.
    ///
    /// # Errors
    /// * `VersionNotFound` - If the version doesn't exist
    /// * `RuleNotFound` - If the rule doesn't exist
    pub async fn revert_to_version(
        &self,
        rule_id: Uuid,
        version_id: i32,
        reverted_by: Uuid,
    ) -> Result<VersionRevertResult, VersionManagerError> {
        self.revert_to_version_inner(rule_id, version_id, reverted_by, None, None, None)
            .await
    }

    /// Revert while claiming any required runtime reconciliation for this node.
    pub async fn revert_to_version_claimed(
        &self,
        rule_id: Uuid,
        version_id: i32,
        reverted_by: Uuid,
        sync_owner: &str,
        expected_rule_mode: &str,
        expected_detection_mode: &str,
    ) -> Result<VersionRevertResult, VersionManagerError> {
        self.revert_to_version_inner(
            rule_id,
            version_id,
            reverted_by,
            None,
            Some(sync_owner),
            Some((expected_rule_mode, expected_detection_mode)),
        )
        .await
    }

    /// Validate that a tuning-log rollback points at the version immediately
    /// preceding the version applied by that log. This check runs again under
    /// the commit transaction; the preflight lets handlers reject a bad target
    /// before doing any external runtime work.
    pub async fn plan_tuning_revert(
        &self,
        rule_id: Uuid,
        version_id: i32,
        log_id: Uuid,
    ) -> Result<TuningRevertPlan, VersionManagerError> {
        let state: Option<(
            Uuid,
            String,
            Option<chrono::DateTime<Utc>>,
            Option<i32>,
            Option<i32>,
            Option<i32>,
            String,
        )> = sqlx::query_as(
            r#"
                SELECT tl.rule_id, tl.status, tl.reverted_at,
                       tl.reverted_to_version_id, tl.reverted_result_version_id,
                       tl.applied_version_id, tp.proposal_type
                FROM tuning_logs tl
                INNER JOIN tuning_proposals tp ON tp.id = tl.proposal_id
                WHERE tl.id = $1
                "#,
        )
        .bind(log_id)
        .fetch_optional(&self.pg_pool)
        .await?;

        let Some((
            log_rule_id,
            status,
            reverted_at,
            reverted_to_version_id,
            reverted_result_version_id,
            applied_version_id,
            proposal_type,
        )) = state
        else {
            return Err(VersionManagerError::TuningLogNotFound(log_id));
        };

        if log_rule_id == rule_id
            && status == "reverted"
            && reverted_to_version_id == Some(version_id)
        {
            if let Some(result_version_id) = reverted_result_version_id {
                let runtime_sync_required: bool = sqlx::query_scalar(
                    "SELECT EXISTS(
                        SELECT 1 FROM detection_rule_runtime_sync_jobs
                        WHERE rule_id = $1 AND desired_version_id = $2
                    )",
                )
                .bind(rule_id)
                .bind(result_version_id)
                .fetch_one(&self.pg_pool)
                .await?;
                return Ok(TuningRevertPlan::Replayed(VersionRevertResult {
                    version_id: result_version_id,
                    changed: false,
                    replayed: true,
                    runtime_sync_required,
                    runtime_sync_claimed: false,
                }));
            }
        }

        let predecessor_id = self
            .tuning_predecessor_id(log_rule_id, applied_version_id)
            .await?;
        if log_rule_id != rule_id
            || predecessor_id != Some(version_id)
            || !tuning_log_is_revertible(&status, reverted_at.is_some(), &proposal_type)
        {
            return Err(VersionManagerError::TuningLogNotRevertible(log_id));
        }

        Ok(TuningRevertPlan::Ready)
    }

    async fn tuning_predecessor_id(
        &self,
        rule_id: Uuid,
        applied_version_id: Option<i32>,
    ) -> Result<Option<i32>, VersionManagerError> {
        let Some(applied_version_id) = applied_version_id else {
            return Ok(None);
        };
        Ok(sqlx::query_scalar(
            r#"
            SELECT previous.id
            FROM detection_rule_versions applied
            INNER JOIN LATERAL (
                SELECT id
                FROM detection_rule_versions
                WHERE rule_id = applied.rule_id
                  AND version_number < applied.version_number
                ORDER BY version_number DESC
                LIMIT 1
            ) previous ON TRUE
            WHERE applied.id = $1 AND applied.rule_id = $2
            "#,
        )
        .bind(applied_version_id)
        .bind(rule_id)
        .fetch_optional(&self.pg_pool)
        .await?)
    }

    /// Revert a rule and mark its tuning log in the same transaction.
    pub async fn revert_tuning_log(
        &self,
        rule_id: Uuid,
        version_id: i32,
        reverted_by: Uuid,
        log_id: Uuid,
        reason: String,
    ) -> Result<VersionRevertResult, VersionManagerError> {
        if reason.trim().is_empty() {
            return Err(VersionManagerError::TuningLogNotRevertible(log_id));
        }
        self.revert_to_version_inner(
            rule_id,
            version_id,
            reverted_by,
            Some((log_id, reason)),
            None,
            None,
        )
        .await
    }

    /// Revert a tuning log and claim any runtime reconciliation for this node.
    pub async fn revert_tuning_log_claimed(
        &self,
        rule_id: Uuid,
        version_id: i32,
        reverted_by: Uuid,
        log_id: Uuid,
        reason: String,
        sync_owner: &str,
        expected_rule_mode: &str,
        expected_detection_mode: &str,
    ) -> Result<VersionRevertResult, VersionManagerError> {
        if reason.trim().is_empty() {
            return Err(VersionManagerError::TuningLogNotRevertible(log_id));
        }
        self.revert_to_version_inner(
            rule_id,
            version_id,
            reverted_by,
            Some((log_id, reason)),
            Some(sync_owner),
            Some((expected_rule_mode, expected_detection_mode)),
        )
        .await
    }

    async fn revert_to_version_inner(
        &self,
        rule_id: Uuid,
        version_id: i32,
        reverted_by: Uuid,
        tuning_log: Option<(Uuid, String)>,
        runtime_sync_owner: Option<&str>,
        expected_modes: Option<(&str, &str)>,
    ) -> Result<VersionRevertResult, VersionManagerError> {
        let _runtime_lock =
            crate::detection::materialized_view::acquire_rule_runtime_lock(&self.pg_pool, rule_id)
                .await?;
        // Start a transaction
        let mut tx = self.pg_pool.begin().await?;

        // Serialize reverts and version-number allocation for this rule. The
        // actual rule row is authoritative; version history can lag imports.
        let locked_rule = sqlx::query(
            r#"
            SELECT query, name, description, severity, mode, detection_mode
            FROM detection_rules
            WHERE id = $1
            FOR UPDATE
            "#,
        )
        .bind(rule_id)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or(VersionManagerError::RuleNotFound(rule_id))?;
        let locked_query: String = locked_rule.get("query");
        let locked_name: String = locked_rule.get("name");
        let locked_description: Option<String> = locked_rule.get("description");
        let locked_severity: String = locked_rule.get("severity");
        let rule_mode: String = locked_rule.get("mode");
        let detection_mode: String = locked_rule.get("detection_mode");
        if let Some((expected_rule_mode, expected_detection_mode)) = expected_modes {
            if rule_mode != expected_rule_mode || detection_mode != expected_detection_mode {
                return Err(VersionManagerError::VersionConflict(
                    "Rule execution mode changed while the rollback was being validated"
                        .to_string(),
                ));
            }
        }

        if let Some((log_id, _)) = tuning_log.as_ref() {
            let log_state: Option<(
                Uuid,
                String,
                Option<chrono::DateTime<Utc>>,
                Option<i32>,
                Option<i32>,
                Option<i32>,
                String,
            )> = sqlx::query_as(
                r#"
                SELECT tl.rule_id, tl.status, tl.reverted_at,
                       tl.reverted_to_version_id, tl.reverted_result_version_id,
                       tl.applied_version_id, tp.proposal_type
                FROM tuning_logs tl
                INNER JOIN tuning_proposals tp ON tp.id = tl.proposal_id
                WHERE tl.id = $1
                FOR UPDATE OF tl
                "#,
            )
            .bind(log_id)
            .fetch_optional(&mut *tx)
            .await?;

            let Some((
                log_rule_id,
                status,
                reverted_at,
                reverted_to_version_id,
                reverted_result_version_id,
                applied_version_id,
                proposal_type,
            )) = log_state
            else {
                return Err(VersionManagerError::TuningLogNotFound(*log_id));
            };
            if log_rule_id == rule_id
                && status == "reverted"
                && reverted_to_version_id == Some(version_id)
            {
                if let Some(result_version_id) = reverted_result_version_id {
                    let claimed = if let Some(owner) = runtime_sync_owner {
                        sqlx::query_scalar::<_, Uuid>(
                            r#"
                            UPDATE detection_rule_runtime_sync_jobs
                            SET claimed_by = $3, claimed_at = NOW(), updated_at = NOW()
                            WHERE rule_id = $1 AND desired_version_id = $2
                              AND (claimed_by IS NULL OR claimed_by = $3
                                   OR claimed_at < NOW() - INTERVAL '5 minutes')
                            RETURNING rule_id
                            "#,
                        )
                        .bind(rule_id)
                        .bind(result_version_id)
                        .bind(owner)
                        .fetch_optional(&mut *tx)
                        .await?
                        .is_some()
                    } else {
                        false
                    };
                    let runtime_sync_required: bool = sqlx::query_scalar(
                        "SELECT EXISTS(
                            SELECT 1 FROM detection_rule_runtime_sync_jobs
                            WHERE rule_id = $1 AND desired_version_id = $2
                        )",
                    )
                    .bind(rule_id)
                    .bind(result_version_id)
                    .fetch_one(&mut *tx)
                    .await?;
                    tx.commit().await?;
                    return Ok(VersionRevertResult {
                        version_id: result_version_id,
                        changed: false,
                        replayed: true,
                        runtime_sync_required,
                        runtime_sync_claimed: claimed,
                    });
                }
            }
            let predecessor_id: Option<i32> = if let Some(applied_version_id) = applied_version_id {
                sqlx::query_scalar(
                    r#"
                    SELECT previous.id
                    FROM detection_rule_versions applied
                    INNER JOIN LATERAL (
                        SELECT id
                        FROM detection_rule_versions
                        WHERE rule_id = applied.rule_id
                          AND version_number < applied.version_number
                        ORDER BY version_number DESC
                        LIMIT 1
                    ) previous ON TRUE
                    WHERE applied.id = $1 AND applied.rule_id = $2
                    "#,
                )
                .bind(applied_version_id)
                .bind(log_rule_id)
                .fetch_optional(&mut *tx)
                .await?
            } else {
                None
            };
            if log_rule_id != rule_id
                || predecessor_id != Some(version_id)
                || !tuning_log_is_revertible(&status, reverted_at.is_some(), &proposal_type)
            {
                return Err(VersionManagerError::TuningLogNotRevertible(*log_id));
            }
        }

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
            ORDER BY version_number DESC
            LIMIT 1
            FOR UPDATE
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

        let actual_matches_target = rule_row_matches_target(
            &locked_query,
            &locked_name,
            &locked_description,
            &locked_severity,
            &target_version,
        );
        let already_active = actual_matches_target
            && current_version
                .as_ref()
                .is_some_and(|current| same_rule_content(current, &target_version));
        let (revert_version_id, changed) = if already_active {
            (current_version.as_ref().expect("checked above").id, false)
        } else {
            let next_version_number: i32 = sqlx::query_scalar(
                "SELECT COALESCE(MAX(version_number), 0) + 1
                 FROM detection_rule_versions
                 WHERE rule_id = $1",
            )
            .bind(rule_id)
            .fetch_one(&mut *tx)
            .await?;

            let revert_version_id: i32 = sqlx::query_scalar(
                "INSERT INTO detection_rule_versions (
                    rule_id, version_number, query, name, description, severity,
                    enabled, is_active, created_by, change_reason,
                    tuning_proposal_id, reverted_from_version
                ) VALUES ($1, $2, $3, $4, $5, $6, $7, FALSE, $8, $9, $10, $11)
                RETURNING id",
            )
            .bind(rule_id)
            .bind(next_version_number)
            .bind(&target_version.query)
            .bind(&target_version.name)
            .bind(&target_version.description)
            .bind(&target_version.severity)
            .bind(target_version.enabled)
            .bind(Some(reverted_by))
            .bind(VersionChangeReason::Revert.to_string())
            .bind(target_version.tuning_proposal_id)
            .bind(current_version.as_ref().map(|version| version.id))
            .fetch_one(&mut *tx)
            .await?;

            sqlx::query(
                "UPDATE detection_rule_versions
                 SET is_active = false
                 WHERE rule_id = $1",
            )
            .bind(rule_id)
            .execute(&mut *tx)
            .await?;
            sqlx::query("UPDATE detection_rule_versions SET is_active = true WHERE id = $1")
                .bind(revert_version_id)
                .execute(&mut *tx)
                .await?;

            // archived/mode are intentionally unchanged; lifecycle is managed separately.
            sqlx::query(
                "UPDATE detection_rules
                 SET query = $1, name = $2, description = $3, severity = $4,
                     updated_at = NOW()
                 WHERE id = $5",
            )
            .bind(&target_version.query)
            .bind(&target_version.name)
            .bind(&target_version.description)
            .bind(&target_version.severity)
            .bind(rule_id)
            .execute(&mut *tx)
            .await?;

            (revert_version_id, true)
        };

        if let Some((log_id, reason)) = tuning_log {
            sqlx::query(
                r#"
                UPDATE tuning_logs
                SET status = 'reverted',
                    reverted_at = NOW(),
                    reverted_by = $1,
                    reverted_to_version_id = $2,
                    reverted_result_version_id = $3,
                    revert_reason = $4
                WHERE id = $5
                "#,
            )
            .bind(reverted_by)
            .bind(version_id)
            .bind(revert_version_id)
            .bind(reason)
            .bind(log_id)
            .execute(&mut *tx)
            .await?;
        }

        // Disable auto-tuning for 7 days
        let disabled_until = Utc::now() + Duration::days(7);
        sqlx::query(
            "UPDATE detection_rules
             SET auto_tuning_disabled_until = CASE
                    WHEN auto_tuning_disabled_until IS NULL
                         OR auto_tuning_disabled_until < $1 THEN $1
                    ELSE auto_tuning_disabled_until
                 END
             WHERE id = $2",
        )
        .bind(disabled_until)
        .bind(rule_id)
        .execute(&mut *tx)
        .await?;

        if detection_mode == "real-time" && changed {
            sqlx::query(
                r#"
                INSERT INTO detection_rule_runtime_sync_jobs (
                    rule_id, desired_version_id, status, attempts,
                    claimed_by, claimed_at, last_error
                )
                VALUES (
                    $1, $2, 'pending', 0, $3::TEXT,
                    CASE WHEN $3::TEXT IS NULL THEN NULL ELSE NOW() END,
                    NULL
                )
                ON CONFLICT (rule_id) DO UPDATE SET
                    desired_version_id = EXCLUDED.desired_version_id,
                    status = 'pending',
                    attempts = 0,
                    claimed_by = EXCLUDED.claimed_by,
                    claimed_at = EXCLUDED.claimed_at,
                    last_error = NULL,
                    updated_at = NOW()
                "#,
            )
            .bind(rule_id)
            .bind(revert_version_id)
            .bind(runtime_sync_owner)
            .execute(&mut *tx)
            .await?;
        } else if detection_mode != "real-time" {
            sqlx::query("DELETE FROM detection_rule_runtime_sync_jobs WHERE rule_id = $1")
                .bind(rule_id)
                .execute(&mut *tx)
                .await?;
        }

        if let Some(owner) = runtime_sync_owner {
            sqlx::query(
                r#"
                UPDATE detection_rule_runtime_sync_jobs
                SET claimed_by = $3, claimed_at = NOW(), updated_at = NOW()
                WHERE rule_id = $1 AND desired_version_id = $2
                  AND (claimed_by IS NULL OR claimed_by = $3
                       OR claimed_at < NOW() - INTERVAL '5 minutes')
                "#,
            )
            .bind(rule_id)
            .bind(revert_version_id)
            .bind(owner)
            .execute(&mut *tx)
            .await?;
        }

        let runtime_job: Option<Option<String>> = sqlx::query_scalar(
            "SELECT claimed_by FROM detection_rule_runtime_sync_jobs
             WHERE rule_id = $1 AND desired_version_id = $2",
        )
        .bind(rule_id)
        .bind(revert_version_id)
        .fetch_optional(&mut *tx)
        .await?;
        let runtime_sync_required = runtime_job.is_some();
        let runtime_sync_claimed = runtime_sync_owner.is_some_and(|owner| {
            runtime_job.as_ref().and_then(|claim| claim.as_deref()) == Some(owner)
        });

        // Commit the transaction
        tx.commit().await?;

        Ok(VersionRevertResult {
            version_id: revert_version_id,
            changed,
            replayed: false,
            runtime_sync_required,
            runtime_sync_claimed,
        })
    }

    /// Claim one pending real-time reconciliation job using a stale-safe lease.
    pub async fn claim_pending_runtime_sync(
        &self,
        owner: &str,
    ) -> Result<Option<PendingRuntimeSync>, VersionManagerError> {
        let mut tx = self.pg_pool.begin().await?;
        let row = sqlx::query(
            r#"
            SELECT rule_id, desired_version_id
            FROM detection_rule_runtime_sync_jobs
            WHERE (status = 'pending'
                   OR updated_at <= NOW() - (INTERVAL '5 seconds' * LEAST(attempts, 60)))
              AND (claimed_by IS NULL OR claimed_at < NOW() - INTERVAL '5 minutes')
            ORDER BY updated_at
            FOR UPDATE SKIP LOCKED
            LIMIT 1
            "#,
        )
        .fetch_optional(&mut *tx)
        .await?;
        let Some(row) = row else {
            tx.commit().await?;
            return Ok(None);
        };
        let pending = PendingRuntimeSync {
            rule_id: row.get("rule_id"),
            desired_version_id: row.get("desired_version_id"),
        };
        sqlx::query(
            r#"
            UPDATE detection_rule_runtime_sync_jobs
            SET claimed_by = $3, claimed_at = NOW(), updated_at = NOW()
            WHERE rule_id = $1 AND desired_version_id = $2
            "#,
        )
        .bind(pending.rule_id)
        .bind(pending.desired_version_id)
        .bind(owner)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(Some(pending))
    }

    /// Queue reconciliation for a rule update whose PostgreSQL write committed
    /// but whose external runtime DDL failed or timed out.
    pub async fn enqueue_runtime_sync(
        &self,
        rule_id: Uuid,
        desired_version_id: i32,
    ) -> Result<(), VersionManagerError> {
        let affected = sqlx::query(
            r#"
            INSERT INTO detection_rule_runtime_sync_jobs (
                rule_id, desired_version_id, status, attempts,
                claimed_by, claimed_at, last_error
            )
            SELECT $1, $2, 'pending', 0, NULL, NULL, NULL
            FROM detection_rules
            WHERE id = $1
            ON CONFLICT (rule_id) DO UPDATE SET
                desired_version_id = EXCLUDED.desired_version_id,
                status = 'pending',
                attempts = 0,
                claimed_by = NULL,
                claimed_at = NULL,
                last_error = NULL,
                updated_at = NOW()
            "#,
        )
        .bind(rule_id)
        .bind(desired_version_id)
        .execute(&self.pg_pool)
        .await?
        .rows_affected();
        if affected == 0 {
            return Err(VersionManagerError::RuleNotFound(rule_id));
        }
        Ok(())
    }

    /// Renew a reconciliation lease before an external DDL attempt.
    pub async fn renew_runtime_sync_lease(
        &self,
        pending: &PendingRuntimeSync,
        owner: &str,
    ) -> Result<bool, VersionManagerError> {
        Ok(sqlx::query(
            "UPDATE detection_rule_runtime_sync_jobs
             SET claimed_at = NOW(), updated_at = NOW()
             WHERE rule_id = $1 AND desired_version_id = $2 AND claimed_by = $3",
        )
        .bind(pending.rule_id)
        .bind(pending.desired_version_id)
        .bind(owner)
        .execute(&self.pg_pool)
        .await?
        .rows_affected()
            == 1)
    }

    /// Complete only when the caller owns the lease and PostgreSQL still has
    /// the exact rule revision whose DDL was rendered.
    pub async fn complete_runtime_sync(
        &self,
        pending: &PendingRuntimeSync,
        owner: &str,
        expected_rule_revision: chrono::DateTime<Utc>,
    ) -> Result<bool, VersionManagerError> {
        Ok(sqlx::query(
            "DELETE FROM detection_rule_runtime_sync_jobs job
             USING detection_rules rule
             WHERE job.rule_id = $1
               AND job.desired_version_id = $2
               AND job.claimed_by = $3
               AND rule.id = job.rule_id
               AND rule.updated_at = $4",
        )
        .bind(pending.rule_id)
        .bind(pending.desired_version_id)
        .bind(owner)
        .bind(expected_rule_revision)
        .execute(&self.pg_pool)
        .await?
        .rows_affected()
            == 1)
    }

    /// Complete an orphan-view cleanup after the PostgreSQL rule was deleted.
    pub async fn complete_deleted_runtime_sync(
        &self,
        pending: &PendingRuntimeSync,
        owner: &str,
    ) -> Result<bool, VersionManagerError> {
        Ok(sqlx::query(
            "DELETE FROM detection_rule_runtime_sync_jobs
             WHERE rule_id = $1 AND desired_version_id = $2 AND claimed_by = $3
               AND NOT EXISTS (SELECT 1 FROM detection_rules WHERE id = $1)",
        )
        .bind(pending.rule_id)
        .bind(pending.desired_version_id)
        .bind(owner)
        .execute(&self.pg_pool)
        .await?
        .rows_affected()
            == 1)
    }

    /// Record a failed reconciliation and release it for distributed retry.
    pub async fn fail_runtime_sync(
        &self,
        pending: &PendingRuntimeSync,
        owner: &str,
        error: &str,
    ) -> Result<bool, VersionManagerError> {
        Ok(sqlx::query(
            r#"
            UPDATE detection_rule_runtime_sync_jobs
            SET status = 'failed', attempts = attempts + 1,
                claimed_by = NULL, claimed_at = NULL,
                last_error = LEFT($4, 2000), updated_at = NOW()
            WHERE rule_id = $1 AND desired_version_id = $2 AND claimed_by = $3
            "#,
        )
        .bind(pending.rule_id)
        .bind(pending.desired_version_id)
        .bind(owner)
        .bind(error)
        .execute(&self.pg_pool)
        .await?
        .rows_affected()
            == 1)
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

    #[test]
    fn only_applied_unreverted_tuning_logs_can_revert() {
        assert!(tuning_log_is_revertible("promoted", false, "query_tuning"));
        assert!(tuning_log_is_revertible(
            "manually_approved",
            false,
            "query_tuning"
        ));
        assert!(!tuning_log_is_revertible("proposed", false, "query_tuning"));
        assert!(!tuning_log_is_revertible("promoted", true, "query_tuning"));
        assert!(!tuning_log_is_revertible("promoted", false, "hint_update"));
    }

    #[test]
    fn idempotent_revert_requires_identical_mutated_rule_content() {
        let base = RuleVersion {
            id: 1,
            rule_id: Uuid::now_v7(),
            version_number: 1,
            query: "source_type=windows".to_string(),
            name: "Rule".to_string(),
            description: Some("Description".to_string()),
            severity: "high".to_string(),
            enabled: true,
            is_active: true,
            created_at: Utc::now(),
            created_by: None,
            change_reason: "edit".to_string(),
            tuning_proposal_id: None,
            reverted_from_version: None,
        };
        let mut target = base.clone();
        target.id = 2;
        target.version_number = 2;
        assert!(same_rule_content(&base, &target));

        target.severity = "low".to_string();
        assert!(!same_rule_content(&base, &target));

        assert!(!rule_row_matches_target(
            "source_type=linux",
            &base.name,
            &base.description,
            &base.severity,
            &base,
        ));
    }

    #[test]
    fn revert_migration_persists_results_and_runtime_reconciliation() {
        // Revert idempotency touches the enterprise-only tuning_logs table, so it
        // lives in the enterprise overlay (9000031); the runtime-sync-jobs table
        // it reconciles against is created by core migration 225.
        let revert = include_str!(
            "../../../migrations/postgres-enterprise/9000031_tuning_revert_idempotency.sql"
        );
        assert!(revert.contains("reverted_result_version_id"));
        assert!(revert.contains("unambiguous_applied_versions"));
        assert!(revert.contains("proposal_status"));
        let runtime =
            include_str!("../../../migrations/postgres/225_atomic_rule_version_invariants.sql");
        assert!(runtime.contains("detection_rule_runtime_sync_jobs"));
        assert!(runtime.contains("desired_version_id"));
        assert!(runtime.contains("claimed_by"));
    }
}
