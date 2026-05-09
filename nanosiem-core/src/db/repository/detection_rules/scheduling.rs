// SPDX-License-Identifier: AGPL-3.0-or-later

//! Distributed scheduler claim/release operations for detection rules

use uuid::Uuid;

use crate::models::DetectionRule;

use super::types::{DetectionRuleRepository, DetectionRuleRepositoryError};

impl DetectionRuleRepository {
    /// Atomically claim a batch of due detection rules using SKIP LOCKED.
    ///
    /// Returns rules that are now claimed by this node. Other nodes calling
    /// this concurrently will get disjoint sets (no double-execution).
    ///
    /// Also reclaims rules with stale claims (node crashed mid-execution).
    pub async fn claim_due_rules(
        &self,
        batch_size: i64,
        node_id: &str,
        stale_timeout_secs: i64,
    ) -> Result<Vec<DetectionRule>, DetectionRuleRepositoryError> {
        let results = sqlx::query_as::<_, DetectionRule>(
            r#"
            WITH claimable AS (
                SELECT id FROM detection_rules
                WHERE archived = false
                  AND detection_mode = 'scheduled' AND mode NOT IN ('staging', 'paused')
                  AND schedule_cron IS NOT NULL AND next_run_at IS NOT NULL
                  AND next_run_at <= NOW()
                  AND (claimed_by IS NULL OR claimed_at < NOW() - make_interval(secs => $3))
                ORDER BY next_run_at ASC
                LIMIT $1
                FOR UPDATE SKIP LOCKED
            )
            UPDATE detection_rules SET claimed_by = $2, claimed_at = NOW()
            WHERE id IN (SELECT id FROM claimable)
            RETURNING *
            "#,
        )
        .bind(batch_size)
        .bind(node_id)
        .bind(stale_timeout_secs as f64)
        .fetch_all(&self.pool)
        .await?;

        Ok(results)
    }

    /// Release a claimed rule after execution, updating last_run_at and next_run_at.
    ///
    /// Safety: only releases if still claimed by the same node_id.
    pub async fn release_claim(
        &self,
        rule_id: Uuid,
        node_id: &str,
        next_run_at: chrono::DateTime<chrono::Utc>,
    ) -> Result<(), DetectionRuleRepositoryError> {
        sqlx::query(
            r#"
            UPDATE detection_rules
            SET claimed_by = NULL, claimed_at = NULL, last_run_at = NOW(), next_run_at = $2
            WHERE id = $1 AND claimed_by = $3
            "#,
        )
        .bind(rule_id)
        .bind(next_run_at)
        .bind(node_id)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// Release all claims held by a node (graceful shutdown).
    pub async fn release_all_claims(
        &self,
        node_id: &str,
    ) -> Result<u64, DetectionRuleRepositoryError> {
        let result = sqlx::query(
            r#"
            UPDATE detection_rules
            SET claimed_by = NULL, claimed_at = NULL
            WHERE claimed_by = $1
            "#,
        )
        .bind(node_id)
        .execute(&self.pool)
        .await?;

        Ok(result.rows_affected())
    }

    /// Update the next_run_at for a rule (called by API handlers on CRUD changes).
    ///
    /// Pass None to clear next_run_at (e.g., when disabling or archiving a rule).
    pub async fn update_next_run_at(
        &self,
        rule_id: Uuid,
        next_run_at: Option<chrono::DateTime<chrono::Utc>>,
    ) -> Result<(), DetectionRuleRepositoryError> {
        sqlx::query(
            r#"
            UPDATE detection_rules
            SET next_run_at = $2
            WHERE id = $1
            "#,
        )
        .bind(rule_id)
        .bind(next_run_at)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// List all eligible rules that are missing next_run_at (for startup backfill).
    pub async fn list_missing_next_run_at(
        &self,
    ) -> Result<Vec<DetectionRule>, DetectionRuleRepositoryError> {
        let results = sqlx::query_as::<_, DetectionRule>(
            r#"
            SELECT * FROM detection_rules
            WHERE archived = false
              AND detection_mode = 'scheduled' AND mode NOT IN ('staging', 'paused')
              AND schedule_cron IS NOT NULL
              AND next_run_at IS NULL
            "#,
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(results)
    }
}
