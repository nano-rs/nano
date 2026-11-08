// SPDX-License-Identifier: AGPL-3.0-or-later

//! Distributed scheduler claim/release operations for detection rules

use uuid::Uuid;

use crate::models::DetectionRule;

/// A detection window the scheduler could not evaluate and moved past
/// (NAN-4910). Persisted in `detection_coverage_gaps`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DetectionCoverageGap {
    pub window_start: chrono::DateTime<chrono::Utc>,
    pub window_end: chrono::DateTime<chrono::Utc>,
    /// Consecutive size-class failures that led to the gap.
    pub attempts: i32,
    /// The last execution error (truncated).
    pub error_message: String,
}

use super::types::{DetectionRuleRepository, DetectionRuleRepositoryError};

impl DetectionRuleRepository {
    /// Stop future scheduler claims before archiving a deleted rule and report
    /// whether the current claim has drained (NAN-3816).
    ///
    /// A scheduler executes outside the claim transaction, so archiving while
    /// that execution is still writing matches/statistics would race it.
    /// Pausing and clearing `next_run_at` closes the door to new claims;
    /// callers may archive only after `claimed_by` is empty.
    ///
    /// Returns `Ok(false)` WITHOUT mutating the rule when it is claimed, so a
    /// retryable 409 leaves the rule running on its schedule (NAN-4902 review).
    /// The row lock taken by `FOR UPDATE` makes the check-and-pause atomic
    /// against `claim_due_rules`: a claim committed first is seen here (the
    /// locked read returns the latest row version), and a claim attempted
    /// after commit no longer matches its `mode`/`next_run_at` predicate.
    pub async fn quiesce_for_delete(
        &self,
        rule_id: Uuid,
    ) -> Result<bool, DetectionRuleRepositoryError> {
        let mut tx = self.pool.begin().await?;
        let claimed_by: Option<Option<String>> = sqlx::query_scalar(
            r#"
            SELECT claimed_by FROM detection_rules
            WHERE id = $1 AND archived = false
            FOR UPDATE
            "#,
        )
        .bind(rule_id)
        .fetch_optional(&mut *tx)
        .await?;

        match claimed_by {
            None => Err(DetectionRuleRepositoryError::NotFound(rule_id)),
            Some(Some(_)) => Ok(false),
            Some(None) => {
                sqlx::query(
                    r#"
                    UPDATE detection_rules
                    SET paused_from_mode = CASE
                            WHEN mode IN ('staging', 'live', 'alerting') THEN mode
                            ELSE paused_from_mode
                        END,
                        mode = 'paused',
                        next_run_at = NULL
                    WHERE id = $1
                    "#,
                )
                .bind(rule_id)
                .execute(&mut *tx)
                .await?;
                tx.commit().await?;
                Ok(true)
            }
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
    ///
    /// `advance_last_run_to` is the value `last_run_at` should take (audit
    /// D1+D2, NAN-1703), decided by `next_last_run_at`:
    /// - on success → the executed window `end`, so the next window starts
    ///   exactly where this one ended (a 60s query no longer skips 60s of
    ///   events), rather than `NOW()` at query-completion time;
    /// - on a normal failure → `None`, leaving the existing high-water mark
    ///   untouched (`COALESCE`) so the failed window is re-scanned next cycle
    ///   instead of being silently dropped;
    /// - on a recorded coverage gap (NAN-4910) → the gap's end.
    ///
    /// `catchup_size_failures` is the new consecutive size-failure count that
    /// selects the next catch-up slice size (NAN-4910). When `coverage_gap` is
    /// set, the unevaluated window is inserted into `detection_coverage_gaps`
    /// in the same statement, and only if this node still holds the claim.
    ///
    /// This makes `release_claim` the sole writer of `last_run_at`.
    pub async fn release_claim(
        &self,
        rule_id: Uuid,
        node_id: &str,
        next_run_at: chrono::DateTime<chrono::Utc>,
        advance_last_run_to: Option<chrono::DateTime<chrono::Utc>>,
        catchup_size_failures: i16,
        coverage_gap: Option<&DetectionCoverageGap>,
    ) -> Result<(), DetectionRuleRepositoryError> {
        let (gap_start, gap_end, gap_attempts, gap_error) = match coverage_gap {
            Some(gap) => (
                Some(gap.window_start),
                Some(gap.window_end),
                Some(gap.attempts),
                Some(gap.error_message.as_str()),
            ),
            None => (None, None, None, None),
        };
        sqlx::query(
            r#"
            WITH released AS (
                UPDATE detection_rules
                SET claimed_by = NULL,
                    claimed_at = NULL,
                    last_run_at = COALESCE($4, last_run_at),
                    next_run_at = $2,
                    catchup_size_failures = $5
                WHERE id = $1 AND claimed_by = $3
                RETURNING id
            )
            INSERT INTO detection_coverage_gaps (
                rule_id, window_start, window_end, attempts, error_message
            )
            SELECT id, $6, $7, $8, $9 FROM released
            WHERE $6::timestamptz IS NOT NULL
            "#,
        )
        .bind(rule_id)
        .bind(next_run_at)
        .bind(node_id)
        .bind(advance_last_run_to)
        .bind(catchup_size_failures)
        .bind(gap_start)
        .bind(gap_end)
        .bind(gap_attempts)
        .bind(gap_error)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// Current consecutive size-failure count for a rule's catch-up (NAN-4910).
    /// Selects how large the next catch-up slice may be.
    pub async fn get_catchup_size_failures(
        &self,
        id: Uuid,
    ) -> Result<i16, DetectionRuleRepositoryError> {
        let row: Option<(i16,)> =
            sqlx::query_as("SELECT catchup_size_failures FROM detection_rules WHERE id = $1")
                .bind(id)
                .fetch_optional(&self.pool)
                .await?;
        Ok(row.map(|(n,)| n).unwrap_or(0))
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
