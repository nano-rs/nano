// SPDX-License-Identifier: AGPL-3.0-or-later

//! Mode transition methods for detection rules (promote, demote, pause, resume)

use uuid::Uuid;

use crate::models::DetectionRule;

use super::types::{DetectionRuleRepository, DetectionRuleRepositoryError};

impl DetectionRuleRepository {
    /// Promote a rule from staging to live mode (ready for testing)
    pub async fn promote_to_live(
        &self,
        id: Uuid,
    ) -> Result<DetectionRule, DetectionRuleRepositoryError> {
        let result = sqlx::query_as::<_, DetectionRule>(
            r#"
            UPDATE detection_rules SET
                mode = 'live',
                updated_at = NOW()
            WHERE id = $1
            RETURNING *
            "#,
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?
        .ok_or(DetectionRuleRepositoryError::NotFound(id))?;

        Ok(result)
    }

    /// Promote a rule from live to alerting mode
    pub async fn promote_to_alerting(
        &self,
        id: Uuid,
    ) -> Result<DetectionRule, DetectionRuleRepositoryError> {
        let result = sqlx::query_as::<_, DetectionRule>(
            r#"
            UPDATE detection_rules SET
                mode = 'alerting',
                updated_at = NOW()
            WHERE id = $1 AND mode = 'live'
            RETURNING *
            "#,
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;

        match result {
            Some(rule) => Ok(rule),
            None => {
                // Distinguish "not found" from "wrong mode"
                let current_mode: Option<(String,)> =
                    sqlx::query_as("SELECT mode::text FROM detection_rules WHERE id = $1")
                        .bind(id)
                        .fetch_optional(&self.pool)
                        .await?;
                match current_mode {
                    Some((mode,)) => Err(DetectionRuleRepositoryError::InvalidModeTransition(
                        id, mode,
                    )),
                    None => Err(DetectionRuleRepositoryError::NotFound(id)),
                }
            }
        }
    }

    /// Demote a rule from alerting to live mode (for tuning)
    pub async fn demote_to_live(
        &self,
        id: Uuid,
    ) -> Result<DetectionRule, DetectionRuleRepositoryError> {
        let result = sqlx::query_as::<_, DetectionRule>(
            r#"
            UPDATE detection_rules SET
                mode = 'live',
                live_match_count = 0,
                updated_at = NOW()
            WHERE id = $1 AND mode = 'alerting'
            RETURNING *
            "#,
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;

        match result {
            Some(rule) => Ok(rule),
            None => {
                // Distinguish "not found" from "wrong mode"
                let current_mode: Option<(String,)> =
                    sqlx::query_as("SELECT mode::text FROM detection_rules WHERE id = $1")
                        .bind(id)
                        .fetch_optional(&self.pool)
                        .await?;
                match current_mode {
                    Some((mode,)) => Err(DetectionRuleRepositoryError::InvalidModeTransition(
                        id, mode,
                    )),
                    None => Err(DetectionRuleRepositoryError::NotFound(id)),
                }
            }
        }
    }

    /// Demote a rule from live to staging mode (back to development)
    pub async fn demote_to_staging(
        &self,
        id: Uuid,
    ) -> Result<DetectionRule, DetectionRuleRepositoryError> {
        let result = sqlx::query_as::<_, DetectionRule>(
            r#"
            UPDATE detection_rules SET
                mode = 'staging',
                updated_at = NOW()
            WHERE id = $1 AND mode = 'live'
            RETURNING *
            "#,
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;

        match result {
            Some(rule) => Ok(rule),
            None => {
                // Distinguish "not found" from "wrong mode"
                let current_mode: Option<(String,)> =
                    sqlx::query_as("SELECT mode::text FROM detection_rules WHERE id = $1")
                        .bind(id)
                        .fetch_optional(&self.pool)
                        .await?;
                match current_mode {
                    Some((mode,)) => Err(DetectionRuleRepositoryError::InvalidModeTransition(
                        id, mode,
                    )),
                    None => Err(DetectionRuleRepositoryError::NotFound(id)),
                }
            }
        }
    }

    /// Pause a detection rule (set mode to 'paused')
    pub async fn pause(&self, id: Uuid) -> Result<DetectionRule, DetectionRuleRepositoryError> {
        let result = sqlx::query_as::<_, DetectionRule>(
            r#"
            UPDATE detection_rules SET
                mode = 'paused',
                updated_at = NOW()
            WHERE id = $1 AND mode IN ('alerting', 'live')
            RETURNING *
            "#,
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;

        match result {
            Some(rule) => Ok(rule),
            None => {
                let current_mode: Option<(String,)> =
                    sqlx::query_as("SELECT mode::text FROM detection_rules WHERE id = $1")
                        .bind(id)
                        .fetch_optional(&self.pool)
                        .await?;
                match current_mode {
                    Some((mode,)) => Err(DetectionRuleRepositoryError::InvalidModeTransition(
                        id, mode,
                    )),
                    None => Err(DetectionRuleRepositoryError::NotFound(id)),
                }
            }
        }
    }

    /// Set a rule's mode directly (used by bulk operations)
    ///
    /// Unlike the transition methods (promote, demote, pause, resume), this does
    /// not enforce mode transition rules — it sets the mode unconditionally.
    pub async fn set_mode(
        &self,
        id: Uuid,
        mode: &str,
    ) -> Result<DetectionRule, DetectionRuleRepositoryError> {
        let result = sqlx::query_as::<_, DetectionRule>(
            r#"
            UPDATE detection_rules SET
                mode = $2,
                updated_at = NOW()
            WHERE id = $1
            RETURNING *
            "#,
        )
        .bind(id)
        .bind(mode)
        .fetch_optional(&self.pool)
        .await?
        .ok_or(DetectionRuleRepositoryError::NotFound(id))?;

        Ok(result)
    }

    /// Resume a paused detection rule (set mode back to 'alerting')
    pub async fn resume(&self, id: Uuid) -> Result<DetectionRule, DetectionRuleRepositoryError> {
        let result = sqlx::query_as::<_, DetectionRule>(
            r#"
            UPDATE detection_rules SET
                mode = 'alerting',
                updated_at = NOW()
            WHERE id = $1 AND mode = 'paused'
            RETURNING *
            "#,
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;

        match result {
            Some(rule) => Ok(rule),
            None => {
                let current_mode: Option<(String,)> =
                    sqlx::query_as("SELECT mode::text FROM detection_rules WHERE id = $1")
                        .bind(id)
                        .fetch_optional(&self.pool)
                        .await?;
                match current_mode {
                    Some((mode,)) => Err(DetectionRuleRepositoryError::InvalidModeTransition(
                        id, mode,
                    )),
                    None => Err(DetectionRuleRepositoryError::NotFound(id)),
                }
            }
        }
    }
}
