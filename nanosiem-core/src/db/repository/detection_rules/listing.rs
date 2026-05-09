// SPDX-License-Identifier: AGPL-3.0-or-later

//! Query methods for listing and filtering detection rules

use crate::models::{DetectionRule, RuleMode, Severity};

use super::types::{DetectionRuleRepository, DetectionRuleRepositoryError};

impl DetectionRuleRepository {
    /// List all detection rules (excluding archived by default)
    /// Limited to 10000 rules to prevent memory issues in pathological cases
    pub async fn list(&self) -> Result<Vec<DetectionRule>, DetectionRuleRepositoryError> {
        let results = sqlx::query_as::<_, DetectionRule>(
            r#"SELECT * FROM detection_rules WHERE archived = FALSE ORDER BY created_at DESC LIMIT 10000"#,
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(results)
    }

    /// List all detection rules including archived
    /// Limited to 10000 rules to prevent memory issues in pathological cases
    pub async fn list_all(&self) -> Result<Vec<DetectionRule>, DetectionRuleRepositoryError> {
        let results = sqlx::query_as::<_, DetectionRule>(
            r#"SELECT * FROM detection_rules ORDER BY created_at DESC LIMIT 10000"#,
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(results)
    }

    /// List only archived detection rules
    /// Limited to 10000 rules to prevent memory issues in pathological cases
    pub async fn list_archived(&self) -> Result<Vec<DetectionRule>, DetectionRuleRepositoryError> {
        let results = sqlx::query_as::<_, DetectionRule>(
            r#"SELECT * FROM detection_rules WHERE archived = TRUE ORDER BY created_at DESC LIMIT 10000"#,
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(results)
    }

    /// List active detection rules (not staging and not paused, excluding archived)
    /// Limited to 10000 rules to prevent memory issues in pathological cases
    pub async fn list_active(&self) -> Result<Vec<DetectionRule>, DetectionRuleRepositoryError> {
        let results = sqlx::query_as::<_, DetectionRule>(
            r#"SELECT * FROM detection_rules WHERE mode NOT IN ('staging', 'paused') AND archived = FALSE ORDER BY created_at DESC LIMIT 10000"#,
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(results)
    }

    /// List rules by mode (live or alerting), excluding archived
    pub async fn list_by_mode(
        &self,
        mode: RuleMode,
    ) -> Result<Vec<DetectionRule>, DetectionRuleRepositoryError> {
        let results = sqlx::query_as::<_, DetectionRule>(
            r#"SELECT * FROM detection_rules WHERE mode = $1 AND archived = FALSE ORDER BY created_at DESC"#,
        )
        .bind(mode)
        .fetch_all(&self.pool)
        .await?;

        Ok(results)
    }

    /// List rules in alerting mode (production rules), excluding archived
    pub async fn list_alerting(&self) -> Result<Vec<DetectionRule>, DetectionRuleRepositoryError> {
        let results = sqlx::query_as::<_, DetectionRule>(
            r#"SELECT * FROM detection_rules WHERE mode = 'alerting' AND archived = FALSE ORDER BY created_at DESC"#,
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(results)
    }

    /// List rules in live mode (bake-in rules), excluding archived
    pub async fn list_live(&self) -> Result<Vec<DetectionRule>, DetectionRuleRepositoryError> {
        let results = sqlx::query_as::<_, DetectionRule>(
            r#"SELECT * FROM detection_rules WHERE mode = 'live' AND archived = FALSE ORDER BY created_at DESC"#,
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(results)
    }

    /// List rules in staging mode (rules being developed), excluding archived
    pub async fn list_staging(&self) -> Result<Vec<DetectionRule>, DetectionRuleRepositoryError> {
        let results = sqlx::query_as::<_, DetectionRule>(
            r#"SELECT * FROM detection_rules WHERE mode = 'staging' AND archived = FALSE ORDER BY created_at DESC"#,
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(results)
    }

    /// List rules with real-time detection enabled (must be in alerting mode AND realtime_enabled), excluding archived
    pub async fn list_realtime_enabled(
        &self,
    ) -> Result<Vec<DetectionRule>, DetectionRuleRepositoryError> {
        let results = sqlx::query_as::<_, DetectionRule>(
            r#"SELECT * FROM detection_rules WHERE mode = 'alerting' AND realtime_enabled = true AND archived = FALSE ORDER BY created_at DESC"#,
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(results)
    }

    /// List rules by severity, excluding archived
    pub async fn list_by_severity(
        &self,
        severity: Severity,
    ) -> Result<Vec<DetectionRule>, DetectionRuleRepositoryError> {
        let results = sqlx::query_as::<_, DetectionRule>(
            r#"SELECT * FROM detection_rules WHERE severity = $1 AND archived = FALSE ORDER BY created_at DESC"#,
        )
        .bind(severity)
        .fetch_all(&self.pool)
        .await?;

        Ok(results)
    }
}
