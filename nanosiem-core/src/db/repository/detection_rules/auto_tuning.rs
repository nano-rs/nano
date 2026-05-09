// SPDX-License-Identifier: AGPL-3.0-or-later

//! Auto-tuning configuration and eligibility for detection rules

use uuid::Uuid;

use crate::models::DetectionRule;

use super::types::{DetectionRuleRepository, DetectionRuleRepositoryError};

impl DetectionRuleRepository {
    /// Disable auto-tuning for a rule for a specified duration (cooldown period)
    ///
    /// This is typically called after a revert to prevent immediate re-tuning.
    /// Requirements: 9.6, 12.1
    pub async fn disable_auto_tuning_until(
        &self,
        id: Uuid,
        disabled_until: chrono::DateTime<chrono::Utc>,
    ) -> Result<(), DetectionRuleRepositoryError> {
        let result = sqlx::query(
            r#"
            UPDATE detection_rules
            SET auto_tuning_disabled_until = $2,
                updated_at = NOW()
            WHERE id = $1
            "#,
        )
        .bind(id)
        .bind(disabled_until)
        .execute(&self.pool)
        .await?;

        if result.rows_affected() == 0 {
            return Err(DetectionRuleRepositoryError::NotFound(id));
        }

        Ok(())
    }

    /// Enable auto-tuning for a rule (clears cooldown period)
    ///
    /// Requirements: 12.1
    pub async fn enable_auto_tuning(&self, id: Uuid) -> Result<(), DetectionRuleRepositoryError> {
        let result = sqlx::query(
            r#"
            UPDATE detection_rules
            SET auto_tuning_disabled_until = NULL,
                updated_at = NOW()
            WHERE id = $1
            "#,
        )
        .bind(id)
        .execute(&self.pool)
        .await?;

        if result.rows_affected() == 0 {
            return Err(DetectionRuleRepositoryError::NotFound(id));
        }

        Ok(())
    }

    /// Update auto-tuning settings for a rule
    ///
    /// Requirements: 12.1, 12.2, 12.3, 12.4
    pub async fn update_auto_tuning_settings(
        &self,
        id: Uuid,
        enabled: Option<bool>,
        min_confidence: Option<f64>,
        critical: Option<bool>,
    ) -> Result<DetectionRule, DetectionRuleRepositoryError> {
        let result = sqlx::query_as::<_, DetectionRule>(
            r#"
            UPDATE detection_rules
            SET auto_tuning_enabled = COALESCE($2, auto_tuning_enabled),
                auto_tuning_min_confidence = COALESCE($3, auto_tuning_min_confidence),
                auto_tuning_critical = COALESCE($4, auto_tuning_critical),
                updated_at = NOW()
            WHERE id = $1
            RETURNING *
            "#,
        )
        .bind(id)
        .bind(enabled)
        .bind(min_confidence)
        .bind(critical)
        .fetch_optional(&self.pool)
        .await?
        .ok_or(DetectionRuleRepositoryError::NotFound(id))?;

        Ok(result)
    }

    /// List rules eligible for auto-tuning
    ///
    /// Returns rules where:
    /// - auto_tuning_enabled = true
    /// - auto_tuning_critical = false
    /// - auto_tuning_disabled_until is NULL or in the past
    /// - mode is not staging or paused
    /// - archived = false
    ///
    /// Requirements: 12.1, 12.2, 12.3
    pub async fn list_auto_tuning_eligible(
        &self,
    ) -> Result<Vec<DetectionRule>, DetectionRuleRepositoryError> {
        let results = sqlx::query_as::<_, DetectionRule>(
            r#"
            SELECT * FROM detection_rules
            WHERE auto_tuning_enabled = true
                AND auto_tuning_critical = false
                AND (auto_tuning_disabled_until IS NULL OR auto_tuning_disabled_until < NOW())
                AND mode NOT IN ('staging', 'paused')
                AND archived = false
            ORDER BY created_at DESC
            "#,
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(results)
    }
}
