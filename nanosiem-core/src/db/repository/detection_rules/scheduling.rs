// SPDX-License-Identifier: AGPL-3.0-or-later

//! Distributed scheduler claim/release operations for detection rules

use uuid::Uuid;

use crate::models::DetectionRule;

use super::types::{DetectionRuleRepository, DetectionRuleRepositoryError};

impl DetectionRuleRepository {
    /// Stop future scheduler claims before deleting a rule and report whether
    /// the current claim has drained.
    ///
    /// A scheduler executes outside the claim transaction. Deleting its rule
    /// row while that execution is still writing matches/statistics violates
    /// foreign keys and turns an ordinary lifecycle operation into a failed
    /// detection run. Pausing and clearing `next_run_at` closes the door to new
    /// claims; callers may delete only after `claimed_by` is empty.
    pub async fn quiesce_for_delete(
        &self,
        rule_id: Uuid,
    ) -> Result<bool, DetectionRuleRepositoryError> {
        let claimed_by: Option<Option<String>> = sqlx::query_scalar(
            r#"
            UPDATE detection_rules
            SET mode = 'paused',
                next_run_at = NULL
            WHERE id = $1
            RETURNING claimed_by
            "#,
        )
        .bind(rule_id)
        .fetch_optional(&self.pool)
        .await?;

        match claimed_by {
            Some(owner) => Ok(owner.is_none()),
            None => Err(DetectionRuleRepositoryError::NotFound(rule_id)),
        }
    }

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
        include_realtime_microbatches: bool,
    ) -> Result<Vec<DetectionRule>, DetectionRuleRepositoryError> {
        let results = sqlx::query_as::<_, DetectionRule>(
            r#"
            WITH claimable AS (
                SELECT id FROM detection_rules
                WHERE archived = false
                  AND (
                      detection_mode = 'scheduled'
                      OR ($4 AND detection_mode = 'real-time')
                  )
                  AND mode NOT IN ('staging', 'paused')
                  AND schedule_cron IS NOT NULL AND next_run_at IS NOT NULL
                  AND next_run_at <= NOW()
                  AND (claimed_by IS NULL OR claimed_at < NOW() - make_interval(secs => $3))
                  -- A due late-arrival repair shares this rule's claim fence.
                  -- Give it priority over the normal cron lane or a five-second
                  -- real-time rule can win every synchronized poll forever and
                  -- starve its repair job. Retry backoff does not block normal
                  -- execution until the repair is actually due again.
                  AND NOT EXISTS (
                      SELECT 1
                      FROM detection_late_replay_jobs replay
                      WHERE replay.rule_id = detection_rules.id
                        AND (
                            (replay.status = 'pending' AND replay.next_attempt_at <= NOW())
                            OR
                            (replay.status = 'running' AND replay.claim_expires_at < NOW())
                        )
                  )
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
        .bind(include_realtime_microbatches)
        .fetch_all(&self.pool)
        .await?;

        Ok(results)
    }

    /// Release a claimed rule after execution, updating last_run_at and next_run_at.
    ///
    /// Safety: only releases if still claimed by the same node_id.
    ///
    /// `advance_last_run_to` is the value `last_run_at` should take (audit
    /// D1+D2, NAN-1703), decided by `next_last_run_at`:
    /// - on success → the executed window `end`, so the next window starts
    ///   exactly where this one ended (a 60s query no longer skips 60s of
    ///   events), rather than `NOW()` at query-completion time;
    /// - on a normal failure → `None`, leaving the existing high-water mark
    ///   untouched (`COALESCE`) so the failed window is re-scanned next cycle
    ///   instead of being silently dropped.
    ///
    /// This makes `release_claim` the sole writer of `last_run_at`.
    pub async fn release_claim(
        &self,
        rule_id: Uuid,
        node_id: &str,
        next_run_at: chrono::DateTime<chrono::Utc>,
        advance_last_run_to: Option<chrono::DateTime<chrono::Utc>>,
    ) -> Result<(), DetectionRuleRepositoryError> {
        sqlx::query(
            r#"
            UPDATE detection_rules
            SET claimed_by = NULL,
                claimed_at = NULL,
                last_run_at = COALESCE($4, last_run_at),
                next_run_at = CASE
                    WHEN archived OR mode IN ('staging', 'paused') THEN NULL
                    ELSE $2
                END
            WHERE id = $1 AND claimed_by = $3
            "#,
        )
        .bind(rule_id)
        .bind(next_run_at)
        .bind(node_id)
        .bind(advance_last_run_to)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// Fetch just the current `schedule_cron` for a rule.
    ///
    /// Audit D26: the scheduler computes `next_run_at` at *release* time from the
    /// cron it snapshotted when it *claimed* the rule. A cron edit that lands
    /// mid-execution is otherwise clobbered for one cycle; re-reading here lets
    /// release honor the current value.
    pub async fn get_schedule_cron(
        &self,
        id: Uuid,
    ) -> Result<Option<String>, DetectionRuleRepositoryError> {
        let row: Option<(Option<String>,)> =
            sqlx::query_as("SELECT schedule_cron FROM detection_rules WHERE id = $1")
                .bind(id)
                .fetch_optional(&self.pool)
                .await?;
        Ok(row.and_then(|(cron,)| cron))
    }

    /// Release all claims held by a node (graceful shutdown).
    pub async fn release_all_claims(
        &self,
        node_id: &str,
    ) -> Result<u64, DetectionRuleRepositoryError> {
        let mut transaction = self.pool.begin().await?;
        // Late-arrival jobs share the rule claim to exclude a concurrent normal
        // cron run. Put owned jobs back before clearing those claims so another
        // node can safely resume them after this process shuts down.
        sqlx::query(
            r#"
            UPDATE detection_late_replay_jobs
            SET status = 'pending', claimed_by = NULL, claimed_at = NULL,
                claim_expires_at = NULL, next_attempt_at = NOW()
            WHERE status = 'running' AND claimed_by = $1
            "#,
        )
        .bind(node_id)
        .execute(&mut *transaction)
        .await?;
        let result = sqlx::query(
            r#"
            UPDATE detection_rules
            SET claimed_by = NULL, claimed_at = NULL
            WHERE claimed_by = $1
            "#,
        )
        .bind(node_id)
        .execute(&mut *transaction)
        .await?;
        transaction.commit().await?;

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
        include_realtime_microbatches: bool,
    ) -> Result<Vec<DetectionRule>, DetectionRuleRepositoryError> {
        let results = sqlx::query_as::<_, DetectionRule>(
            r#"
            SELECT * FROM detection_rules
            WHERE archived = false
              AND (
                  detection_mode = 'scheduled'
                  OR ($1 AND detection_mode = 'real-time')
              )
              AND mode NOT IN ('staging', 'paused')
              AND schedule_cron IS NOT NULL
              AND next_run_at IS NULL
            "#,
        )
        .bind(include_realtime_microbatches)
        .fetch_all(&self.pool)
        .await?;

        Ok(results)
    }
}
