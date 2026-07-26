// SPDX-License-Identifier: AGPL-3.0-or-later

//! Status operations for log sources (enable, disable, validation, deploy markers)

use uuid::Uuid;

use super::helpers::row_to_log_source;
use super::{LogSourceRepository, LogSourceRepositoryError};
use crate::log_sources::types::LogSource;

impl LogSourceRepository {
    /// Enable a log source
    pub async fn enable(&self, id: Uuid) -> Result<LogSource, LogSourceRepositoryError> {
        let row = sqlx::query(
            r#"
            UPDATE log_sources SET enabled = true
            WHERE id = $1
            RETURNING id, name, description, namespace, timezone, source_type,
                parser_vrl, output_fields, category, vendor, product, icon, color,
                match_field, match_pattern, match_values,
                validated, validation_error, deployed, deployed_at, enabled,
                lifecycle_status,
                stale_alert_enabled, stale_threshold_minutes,
                sampling_ratio, sampling_exclude_condition,
                source_parser_repository_id, source_parser_path, source_parser_linked,
                dispatch_source_config_id,
                created_at, updated_at
            "#,
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?
        .ok_or_else(|| LogSourceRepositoryError::NotFound(id.to_string()))?;

        Ok(row_to_log_source(&row))
    }

    /// Disable a log source
    pub async fn disable(&self, id: Uuid) -> Result<LogSource, LogSourceRepositoryError> {
        let row = sqlx::query(
            r#"
            UPDATE log_sources SET enabled = false
            WHERE id = $1
            RETURNING id, name, description, namespace, timezone, source_type,
                parser_vrl, output_fields, category, vendor, product, icon, color,
                match_field, match_pattern, match_values,
                validated, validation_error, deployed, deployed_at, enabled,
                lifecycle_status,
                stale_alert_enabled, stale_threshold_minutes,
                sampling_ratio, sampling_exclude_condition,
                source_parser_repository_id, source_parser_path, source_parser_linked,
                dispatch_source_config_id,
                created_at, updated_at
            "#,
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?
        .ok_or_else(|| LogSourceRepositoryError::NotFound(id.to_string()))?;

        Ok(row_to_log_source(&row))
    }

    /// Set validation status
    pub async fn set_validation_status(
        &self,
        id: Uuid,
        validated: bool,
        error: Option<&str>,
    ) -> Result<(), LogSourceRepositoryError> {
        let result = sqlx::query(
            "UPDATE log_sources SET validated = $2, validation_error = $3 WHERE id = $1",
        )
        .bind(id)
        .bind(validated)
        .bind(error)
        .execute(&self.pool)
        .await?;

        if result.rows_affected() == 0 {
            return Err(LogSourceRepositoryError::NotFound(id.to_string()));
        }

        Ok(())
    }

    /// Mark as deployed
    pub async fn mark_deployed(&self, id: Uuid) -> Result<(), LogSourceRepositoryError> {
        let result = sqlx::query(
            "UPDATE log_sources SET deployed = true, deployed_at = NOW() WHERE id = $1",
        )
        .bind(id)
        .execute(&self.pool)
        .await?;

        if result.rows_affected() == 0 {
            return Err(LogSourceRepositoryError::NotFound(id.to_string()));
        }

        Ok(())
    }

    /// Mark every ENABLED source that isn't yet deployed as deployed. NAN-1275:
    /// a Vector deploy regenerates the whole config from ALL enabled sources, so
    /// they go live together — not just the one that triggered the deploy. Only
    /// flips `deployed = false` rows (leaves already-deployed sources'
    /// `deployed_at` untouched so the "edited since deploy" drift indicator is
    /// preserved). Returns the number of sources flipped.
    pub async fn mark_enabled_deployed(&self) -> Result<u64, LogSourceRepositoryError> {
        let result = sqlx::query(
            "UPDATE log_sources SET deployed = true, deployed_at = NOW() \
             WHERE enabled = true AND deployed = false",
        )
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected())
    }

    /// NAN-1920: flip a draft feed to active. Only touches rows currently in
    /// 'draft' (idempotent for already-active feeds), so re-deploying an active
    /// source is a no-op here. Called from the deploy success path so a feed
    /// onboarded via the AddFeed wizard leaves the Draft state once it's live.
    /// Returns the number of rows flipped (0 when the feed was already active).
    pub async fn mark_lifecycle_active(&self, id: Uuid) -> Result<u64, LogSourceRepositoryError> {
        let result = sqlx::query(
            "UPDATE log_sources SET lifecycle_status = 'active' \
             WHERE id = $1 AND lifecycle_status = 'draft'",
        )
        .bind(id)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected())
    }

    /// Mark as undeployed
    pub async fn mark_undeployed(&self, id: Uuid) -> Result<(), LogSourceRepositoryError> {
        let result = sqlx::query(
            "UPDATE log_sources SET deployed = false, deployed_at = NULL WHERE id = $1",
        )
        .bind(id)
        .execute(&self.pool)
        .await?;

        if result.rows_affected() == 0 {
            return Err(LogSourceRepositoryError::NotFound(id.to_string()));
        }

        Ok(())
    }
}
