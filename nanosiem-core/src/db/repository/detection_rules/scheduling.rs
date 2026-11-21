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

/// What `release_claim` writes after an execution attempt (NAN-4910,
/// NAN-5424).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClaimRelease<'a> {
    pub next_run_at: chrono::DateTime<chrono::Utc>,
    /// New `last_run_at`; `None` keeps the current high-water mark.
    pub advance_last_run_to: Option<chrono::DateTime<chrono::Utc>>,
    /// New consecutive size-class failure count (NAN-4910).
    pub catchup_size_failures: i16,
    /// New consecutive non-size failure count (NAN-5424).
    pub consecutive_failures: i16,
    /// Start of the current failure streak; `None` when healthy (NAN-5424).
    pub failing_since: Option<chrono::DateTime<chrono::Utc>>,
    /// Class of the current streak; `None` when healthy (NAN-5424).
    pub failure_class: Option<&'a str>,
    /// Error to record as the rule's `last_error` (stamped `NOW()`); `None`
    /// leaves the previous error in place.
    pub error: Option<&'a str>,
    /// A window recorded as not evaluated; inserted in the same statement.
    pub coverage_gap: Option<&'a DetectionCoverageGap>,
}

/// Consecutive-failure counters the scheduler reads before an attempt.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RuleFailureCounters {
    pub catchup_size_failures: i16,
    pub consecutive_failures: i16,
    pub failing_since: Option<chrono::DateTime<chrono::Utc>>,
    /// Class of the current streak (NAN-5424).
    pub failure_class: Option<String>,
    /// Earlier claims of this rule that were never released: the process
    /// executing them died mid-run (NAN-5424). Excludes the current claim.
    pub crashed_attempts: i16,
    /// Consecutive crashes attributed to this rule (it died running ALONE)
    /// (NAN-5736). Survives a coverage gap; reset when a run completes.
    pub crash_streak: i16,
    /// An earlier run died together with other rules; attribution is
    /// ambiguous, so the next run executes in isolation (NAN-5736).
    pub crash_suspect: bool,
    /// The last claim was executing in isolation (NAN-5736). Read together
    /// with `crashed_attempts > 0`: that claim died ALONE.
    pub isolated_claim: bool,
}

impl RuleFailureCounters {
    /// The rule must run in isolation: it died mid-run before (NAN-5736).
    pub fn crash_suspected(&self) -> bool {
        self.crashed_attempts > 0 || self.crash_suspect || self.crash_streak > 0
    }
}

/// What [`DetectionRuleRepository::release_crashed_claim`] writes when a claim
/// finds an earlier claim of the rule that never released (NAN-5736).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CrashRelease<'a> {
    /// Counters, error, optional gap and the back-off `next_run_at`.
    pub release: ClaimRelease<'a>,
    /// New attributed-crash count.
    pub crash_streak: i16,
    /// Whether the next run must execute in isolation.
    pub crash_suspect: bool,
}

/// Longest `last_error` stored (characters).
pub const MAX_RULE_ERROR_CHARS: usize = 1000;

/// Truncate and sanitize an error message for `last_error` /
/// `detection_coverage_gaps.error_message`, SIEM Health and logs. Errors can
/// quote event data verbatim (U+0000, line breaks, escape sequences); see
/// [`crate::db::pg_text::pg_safe_error_text`].
pub fn rule_error_text(message: &str) -> String {
    let truncated: String = message.chars().take(MAX_RULE_ERROR_CHARS).collect();
    crate::db::pg_text::pg_safe_error_text(&truncated)
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
    ///
    /// NAN-5736: a claim older than the scheduler's stale-claim timeout
    /// belongs to a process that died mid-run (it will never release). It no
    /// longer blocks the delete; it is cleared together with the pause.
    /// Before, a crashed rule that was paused first could never be deleted:
    /// a paused rule is never reclaimed, so its dead claim stayed forever.
    pub async fn quiesce_for_delete(
        &self,
        rule_id: Uuid,
    ) -> Result<bool, DetectionRuleRepositoryError> {
        let stale_secs = crate::detection::distributed_scheduler::DistributedSchedulerConfig::from_env()
            .effective_stale_claim_timeout_secs();
        let mut tx = self.pool.begin().await?;
        let claimed_by: Option<Option<String>> = sqlx::query_scalar(
            r#"
            SELECT CASE
                       WHEN claimed_at < NOW() - make_interval(secs => $2) THEN NULL
                       ELSE claimed_by
                   END
            FROM detection_rules
            WHERE id = $1 AND archived = false
            FOR UPDATE
            "#,
        )
        .bind(rule_id)
        .bind(stale_secs as f64)
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
                        next_run_at = NULL,
                        claimed_by = NULL,
                        claimed_at = NULL,
                        inflight_claims = 0,
                        isolated_claim = false
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
            UPDATE detection_rules SET claimed_by = $2, claimed_at = NOW(),
                -- NAN-5424: reset on release; > 1 here means an earlier
                -- claim died without releasing (crash / OOM mid-run).
                inflight_claims = LEAST(inflight_claims, 1000) + 1
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
    /// - on a retryable failure → `None`, leaving the existing high-water mark
    ///   untouched (`COALESCE`) so the failed window is re-scanned next cycle
    ///   instead of being silently dropped;
    /// - on a recorded coverage gap (NAN-4910, NAN-5424) → the gap's end.
    ///
    /// The failure counters select the next catch-up slice size (NAN-4910) and
    /// bound how often one window is retried (NAN-5424). When `coverage_gap`
    /// is set, the unevaluated window is inserted into
    /// `detection_coverage_gaps` in the same statement, and only if this node
    /// still holds the claim: the high-water mark can never move past a
    /// window without the gap row.
    ///
    /// This makes `release_claim` the sole writer of `last_run_at`.
    pub async fn release_claim(
        &self,
        rule_id: Uuid,
        node_id: &str,
        release: &ClaimRelease<'_>,
    ) -> Result<(), DetectionRuleRepositoryError> {
        let (gap_start, gap_end, gap_attempts, gap_error) = match release.coverage_gap {
            Some(gap) => (
                Some(gap.window_start),
                Some(gap.window_end),
                Some(gap.attempts),
                Some(rule_error_text(&gap.error_message)),
            ),
            None => (None, None, None, None),
        };
        let error = release.error.map(rule_error_text);
        sqlx::query(
            r#"
            WITH released AS (
                UPDATE detection_rules
                SET claimed_by = NULL,
                    claimed_at = NULL,
                    last_run_at = COALESCE($4, last_run_at),
                    next_run_at = $2,
                    catchup_size_failures = $5,
                    consecutive_failures = $10,
                    failing_since = $12,
                    failure_class = $13,
                    inflight_claims = 0,
                    -- NAN-5736: this run completed, so it is not crashing.
                    crash_streak = 0,
                    crash_suspect = false,
                    isolated_claim = false,
                    last_error = COALESCE($11, last_error),
                    last_error_at = CASE WHEN $11::text IS NULL THEN last_error_at ELSE NOW() END
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
        .bind(release.next_run_at)
        .bind(node_id)
        .bind(release.advance_last_run_to)
        .bind(release.catchup_size_failures)
        .bind(gap_start)
        .bind(gap_end)
        .bind(gap_attempts)
        .bind(gap_error)
        .bind(release.consecutive_failures)
        .bind(error)
        .bind(release.failing_since)
        .bind(release.failure_class)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// Record a claim's crashed predecessor and RELEASE the claim without
    /// running the rule (NAN-5736).
    ///
    /// A run that kills the process never reaches [`Self::release_claim`], so
    /// folding crashed attempts into the counters only in memory (as NAN-5424
    /// did) lost them again with the next crash: the breaker never tripped
    /// and the rule was retried every stale-claim timeout, forever. This
    /// writes the decided counters, error, optional coverage gap (same
    /// statement, same rules as `release_claim`) and the back-off
    /// `next_run_at`, and releases the claim: the back-off is the schedule,
    /// never a held claim, so pausing or deleting the rule works meanwhile.
    ///
    /// Only applies while this node still holds the claim; returns whether
    /// it did.
    pub async fn release_crashed_claim(
        &self,
        rule_id: Uuid,
        node_id: &str,
        crash: &CrashRelease<'_>,
    ) -> Result<bool, DetectionRuleRepositoryError> {
        let release = &crash.release;
        let (gap_start, gap_end, gap_attempts, gap_error) = match release.coverage_gap {
            Some(gap) => (
                Some(gap.window_start),
                Some(gap.window_end),
                Some(gap.attempts),
                Some(rule_error_text(&gap.error_message)),
            ),
            None => (None, None, None, None),
        };
        let error = release.error.map(rule_error_text);
        let updated: Option<Uuid> = sqlx::query_scalar(
            r#"
            WITH released AS (
                UPDATE detection_rules
                SET claimed_by = NULL,
                    claimed_at = NULL,
                    last_run_at = COALESCE($4, last_run_at),
                    next_run_at = $2,
                    catchup_size_failures = $5,
                    consecutive_failures = $10,
                    failing_since = $12,
                    failure_class = $13,
                    inflight_claims = 0,
                    crash_streak = $14,
                    crash_suspect = $15,
                    isolated_claim = false,
                    last_error = COALESCE($11, last_error),
                    last_error_at = CASE WHEN $11::text IS NULL THEN last_error_at ELSE NOW() END
                WHERE id = $1 AND claimed_by = $3
                RETURNING id
            ),
            gap AS (
                INSERT INTO detection_coverage_gaps (
                    rule_id, window_start, window_end, attempts, error_message
                )
                SELECT id, $6, $7, $8, $9 FROM released
                WHERE $6::timestamptz IS NOT NULL
            )
            SELECT id FROM released
            "#,
        )
        .bind(rule_id)
        .bind(release.next_run_at)
        .bind(node_id)
        .bind(release.advance_last_run_to)
        .bind(release.catchup_size_failures)
        .bind(gap_start)
        .bind(gap_end)
        .bind(gap_attempts)
        .bind(gap_error)
        .bind(release.consecutive_failures)
        .bind(error)
        .bind(release.failing_since)
        .bind(release.failure_class)
        .bind(crash.crash_streak)
        .bind(crash.crash_suspect)
        .fetch_optional(&self.pool)
        .await?;
        Ok(updated.is_some())
    }

    /// Mark the claim as executing in isolation, right before the run starts
    /// (NAN-5736). If the process dies during this run, the next claim finds
    /// the flag still set and attributes the crash to this rule. Returns
    /// whether this node still holds the claim.
    pub async fn mark_isolated_claim(
        &self,
        rule_id: Uuid,
        node_id: &str,
    ) -> Result<bool, DetectionRuleRepositoryError> {
        let result = sqlx::query(
            "UPDATE detection_rules SET isolated_claim = true WHERE id = $1 AND claimed_by = $2",
        )
        .bind(rule_id)
        .bind(node_id)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() == 1)
    }

    /// Record an error against a rule without changing its schedule or
    /// failure counters: a matched event that could not be persisted and was
    /// skipped while the rest of the batch went through (NAN-5424).
    pub async fn record_rule_error(
        &self,
        rule_id: Uuid,
        message: &str,
    ) -> Result<(), DetectionRuleRepositoryError> {
        sqlx::query(
            "UPDATE detection_rules SET last_error = $2, last_error_at = NOW() WHERE id = $1",
        )
        .bind(rule_id)
        .bind(rule_error_text(message))
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Durable record of a matched event whose writes PostgreSQL refused
    /// (NAN-5424). Only identifiers and the SQLSTATE, never the content.
    /// `reference_alert_id` is the minimal alert raised for it, if any
    /// (`Uuid::nil()` = raised by an earlier run).
    #[allow(clippy::too_many_arguments)]
    pub async fn record_skipped_event(
        &self,
        rule_id: Uuid,
        event_id: &str,
        event_timestamp: Option<chrono::DateTime<chrono::Utc>>,
        window: Option<(chrono::DateTime<chrono::Utc>, chrono::DateTime<chrono::Utc>)>,
        sqlstate: Option<&str>,
        error_class: &str,
        reference_alert_id: Option<Uuid>,
    ) -> Result<(), DetectionRuleRepositoryError> {
        let reference_alert_id = reference_alert_id.filter(|id| !id.is_nil());
        sqlx::query(
            r#"
            INSERT INTO detection_skipped_events (
                rule_id, event_id, event_timestamp, window_start, window_end,
                sqlstate, error_class, reference_alert_id
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            ON CONFLICT (rule_id, event_id) DO UPDATE SET
                window_start = EXCLUDED.window_start,
                window_end = EXCLUDED.window_end,
                sqlstate = EXCLUDED.sqlstate,
                reference_alert_id = COALESCE(EXCLUDED.reference_alert_id, detection_skipped_events.reference_alert_id),
                recorded_at = NOW()
            "#,
        )
        .bind(rule_id)
        .bind(crate::db::pg_text::pg_safe_error_text(event_id))
        .bind(event_timestamp)
        .bind(window.map(|w| w.0))
        .bind(window.map(|w| w.1))
        .bind(sqlstate.map(crate::db::pg_text::pg_safe_error_text))
        .bind(error_class)
        .bind(reference_alert_id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Both consecutive-failure counters for a rule (NAN-4910, NAN-5424).
    pub async fn get_failure_counters(
        &self,
        id: Uuid,
    ) -> Result<RuleFailureCounters, DetectionRuleRepositoryError> {
        Ok(self.read_failure_counters(id, None).await?.unwrap_or_default())
    }

    /// [`Self::get_failure_counters`], only while `node_id` holds the claim
    /// (NAN-5736): `None` when the claim was lost (another replica reclaimed
    /// it, or it was released), so the caller must not execute.
    pub async fn get_claimed_failure_counters(
        &self,
        id: Uuid,
        node_id: &str,
    ) -> Result<Option<RuleFailureCounters>, DetectionRuleRepositoryError> {
        self.read_failure_counters(id, Some(node_id)).await
    }

    async fn read_failure_counters(
        &self,
        id: Uuid,
        node_id: Option<&str>,
    ) -> Result<Option<RuleFailureCounters>, DetectionRuleRepositoryError> {
        #[allow(clippy::type_complexity)]
        let row: Option<(
            i16,
            i16,
            Option<chrono::DateTime<chrono::Utc>>,
            Option<String>,
            i16,
            i16,
            bool,
            bool,
        )> = sqlx::query_as(
            "SELECT catchup_size_failures, consecutive_failures, failing_since, \
                    failure_class, inflight_claims, crash_streak, crash_suspect, isolated_claim \
             FROM detection_rules WHERE id = $1 AND ($2::text IS NULL OR claimed_by = $2)",
        )
        .bind(id)
        .bind(node_id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(
            |(
                catchup_size_failures,
                consecutive_failures,
                failing_since,
                failure_class,
                inflight,
                crash_streak,
                crash_suspect,
                isolated_claim,
            )| RuleFailureCounters {
                catchup_size_failures,
                consecutive_failures,
                failing_since,
                failure_class,
                crashed_attempts: (inflight - 1).max(0),
                crash_streak,
                crash_suspect,
                isolated_claim,
            },
        ))
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
            SET claimed_by = NULL, claimed_at = NULL, inflight_claims = 0,
                isolated_claim = false
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
    ///
    /// NAN-5672: a schedule is never stamped onto an archived (deleted) rule,
    /// atomically: a handler holding a pre-delete copy of the rule cannot
    /// re-schedule it after the archive committed. Clearing always applies.
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
              AND ($2::timestamptz IS NULL OR archived = FALSE)
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
