// SPDX-License-Identifier: AGPL-3.0-or-later

//! Durable replay queue for events published behind a detection watermark.

use chrono::{DateTime, Duration, Utc};
use sha2::{Digest, Sha256};
use sqlx::{Postgres, Transaction};
use uuid::Uuid;

use crate::models::DetectionRule;
use crate::search::TimeRangeInput;

use super::types::{DetectionRuleRepository, DetectionRuleRepositoryError};

/// The bronze publisher's late-arrival publication record (NAN-2361).
///
/// It is committed in the same transaction as the staged object ledger. Exact
/// retries are accepted only when their event bounds match the original batch;
/// a mismatch returns no row. The conflict target is the table's primary key,
/// which leads with `security_tenant_id` in every edition: core migration 336
/// gives open core the shape enterprise overlay 9000084 established
/// (NAN-3374). Kept here, next to the queue that consumes these rows, so a
/// fresh-open-schema test can execute the exact statement the publisher runs.
///
/// Binds: `$1` tenant_id, `$2` bronze_store_id, `$3` batch_sha256,
/// `$4` min_event_time, `$5` max_event_time, `$6` security_tenant_id.
pub const LAKE_DETECTION_EVENT_PUBLICATION_UPSERT_SQL: &str =
    "INSERT INTO lake_detection_event_publications \
     (tenant_id, bronze_store_id, batch_sha256, min_event_time, max_event_time, \
      security_tenant_id) \
     VALUES ($1, $2, $3, $4, $5, $6) \
     ON CONFLICT (security_tenant_id, tenant_id, bronze_store_id, batch_sha256) DO UPDATE \
     SET published_at = lake_detection_event_publications.published_at \
     WHERE lake_detection_event_publications.min_event_time = EXCLUDED.min_event_time \
       AND lake_detection_event_publications.max_event_time = EXCLUDED.max_event_time \
     RETURNING batch_sha256";

#[derive(Debug, Clone)]
pub struct LateReplayClaim {
    pub job_id: Uuid,
    pub attempt: i32,
    pub time_range: TimeRangeInput,
    pub rule: DetectionRule,
}

/// The state durably committed while releasing a fenced replay claim.
///
/// The scheduler must label metrics and alarms from this repository outcome,
/// not from a pre-release guess based only on the attempt number. A retry can
/// intentionally remain pending beyond `max_attempts` until its repair horizon
/// expires.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LateReplayReleaseOutcome {
    Completed,
    Draining,
    Retry,
    DeadLetter,
    LostClaim,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct LateReplayPlan {
    pub publications: usize,
    pub jobs: usize,
    pub coalesced: usize,
    pub expired: usize,
    pub pruned_publications: usize,
    pub pruned_jobs: usize,
}

#[derive(sqlx::FromRow)]
struct EventPublication {
    tenant_id: String,
    bronze_store_id: String,
    batch_sha256: String,
    min_event_time: DateTime<Utc>,
    max_event_time: DateTime<Utc>,
    published_at: DateTime<Utc>,
}

#[derive(sqlx::FromRow)]
struct ReplayRow {
    id: Uuid,
    rule_id: Uuid,
    window_start: DateTime<Utc>,
    window_end: DateTime<Utc>,
    attempts: i32,
}

const SCHEDULER_DRAIN_TENANT: &str = "scheduler";
const SCHEDULER_DRAIN_STORE: &str = "scheduler:window-drain:v1";
// A publication row and ledger revision commit before the signer atomically
// replaces the worker's manifest. Do not declare a fresh publication planned
// during that visibility handoff: a normal rule may otherwise snapshot the old
// tail, advance its watermark, and strand the event. Thirty seconds matches the
// readiness incident threshold and comfortably covers the bounded signer loop.
pub const PUBLICATION_VISIBILITY_SETTLE_SECONDS: i64 = 30;

impl DetectionRuleRepository {
    /// Hand an exact scheduled-rule window to the durable repair lane.
    ///
    /// Per-event alerting commits bounded batches. Once the first batch is
    /// durable, this fixed interval owns the remainder so the normal scheduler
    /// may advance without losing the tail or chasing a moving lookback window.
    pub async fn enqueue_window_drain(
        &self,
        rule_id: Uuid,
        time_range: &TimeRangeInput,
    ) -> Result<(), DetectionRuleRepositoryError> {
        let identity = format!(
            "scheduler-window-drain-v1\0{rule_id}\0{}\0{}",
            time_range.start.timestamp_micros(),
            time_range.end.timestamp_micros()
        );
        let batch_sha256 = hex::encode(Sha256::digest(identity.as_bytes()));
        sqlx::query(
            r#"
            INSERT INTO detection_late_replay_jobs (
                rule_id, tenant_id, bronze_store_id, batch_sha256,
                window_start, window_end
            )
            VALUES ($1, $2, $3, $4, $5, $6)
            -- The job identity is the table's only non-PK unique key: open core
            -- (302) keys it (rule_id, tenant_id, bronze_store_id, batch_sha256) and
            -- the enterprise overlay (9000084) leads it with security_tenant_id.
            -- Naming either target breaks the other edition (42703 / 42P10), and a
            -- feature cfg cannot pick one: a workspace build unifies the enterprise
            -- feature onto open-core databases. `id` is a random uuid, so an
            -- untargeted DO NOTHING absorbs exactly the identity conflict.
            ON CONFLICT DO NOTHING
            "#,
        )
        .bind(rule_id)
        .bind(SCHEDULER_DRAIN_TENANT)
        .bind(SCHEDULER_DRAIN_STORE)
        .bind(batch_sha256)
        .bind(time_range.start)
        .bind(time_range.end)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Turn newly committed object batches into bounded per-rule repair jobs.
    ///
    /// Publication rows are locked one at a time. Job insertion and marking the
    /// publication planned share one transaction, so a coordinator crash can
    /// only roll the whole plan back. Existing jobs are protected by their
    /// `(rule, batch)` unique identity.
    pub async fn plan_late_replays(
        &self,
        publication_limit: usize,
        repair_horizon: Duration,
        default_context: Duration,
    ) -> Result<LateReplayPlan, DetectionRuleRepositoryError> {
        let now = Utc::now();
        let horizon_start = now - repair_horizon;
        let mut plan = LateReplayPlan::default();

        // Terminal metadata has a finite lifetime. Keep completed work for one
        // repair horizon and dead letters for four horizons so an operator has
        // ample time to inspect failures. Pending/running jobs are never reaped.
        let prune_limit =
            i64::try_from(publication_limit.max(100).saturating_mul(10)).unwrap_or(i64::MAX);
        plan.pruned_jobs = usize::try_from(
            sqlx::query(
                r#"
                DELETE FROM detection_late_replay_jobs
                WHERE id IN (
                    SELECT id FROM detection_late_replay_jobs
                    WHERE (
                        status = 'completed' AND completed_at < $1
                    ) OR (
                        status = 'dead_letter' AND completed_at < $2
                    )
                    ORDER BY completed_at, id
                    LIMIT $3
                )
                "#,
            )
            .bind(horizon_start)
            .bind(now - repair_horizon * 4)
            .bind(prune_limit)
            .execute(&self.pool)
            .await?
            .rows_affected(),
        )
        .unwrap_or_default();
        plan.pruned_publications = usize::try_from(
            sqlx::query(
                r#"
                DELETE FROM lake_detection_event_publications
                WHERE (tenant_id, bronze_store_id, batch_sha256) IN (
                    SELECT tenant_id, bronze_store_id, batch_sha256
                    FROM lake_detection_event_publications
                    WHERE COALESCE(planned_at, expired_at) < $1
                    ORDER BY COALESCE(planned_at, expired_at), tenant_id,
                             bronze_store_id, batch_sha256
                    LIMIT $2
                )
                "#,
            )
            .bind(horizon_start)
            .bind(prune_limit)
            .execute(&self.pool)
            .await?
            .rows_affected(),
        )
        .unwrap_or_default();

        for _ in 0..publication_limit {
            let mut transaction = self.pool.begin().await?;
            let publication = sqlx::query_as::<_, EventPublication>(
                r#"
                SELECT tenant_id, bronze_store_id, batch_sha256,
                       min_event_time, max_event_time, published_at
                FROM lake_detection_event_publications
                WHERE planned_at IS NULL AND expired_at IS NULL
                  AND published_at <= NOW() - make_interval(secs => $1)
                ORDER BY published_at, tenant_id, batch_sha256
                LIMIT 1
                FOR UPDATE SKIP LOCKED
                "#,
            )
            .bind(PUBLICATION_VISIBILITY_SETTLE_SECONDS as f64)
            .fetch_optional(&mut *transaction)
            .await?;
            let Some(publication) = publication else {
                transaction.rollback().await?;
                break;
            };

            if publication.max_event_time < horizon_start {
                mark_publication_expired(&mut transaction, &publication).await?;
                transaction.commit().await?;
                plan.publications += 1;
                plan.expired += 1;
                continue;
            }

            let rules = sqlx::query_as::<_, DetectionRule>(
                r#"
                SELECT *
                FROM detection_rules
                WHERE archived = false
                  AND mode NOT IN ('staging', 'paused')
                  AND kind <> 'retro_hunt'
                  AND (dataset IS NULL OR LOWER(dataset) = 'logs')
                  AND last_run_at IS NOT NULL
                  -- A mixed batch may contain both fresh rows and one late
                  -- row. The minimum, not the maximum, decides whether any
                  -- portion fell behind this rule's completed watermark.
                  AND (
                        last_run_at > $1 + INTERVAL '5 seconds'
                        -- If publication became durable after the rule took
                        -- its normal-run claim, it may have missed that run's
                        -- query snapshot. Plan it even before the run releases
                        -- and advances last_run_at; the shared rule claim keeps
                        -- replay execution serialized behind the normal run.
                        OR (claimed_at IS NOT NULL AND $2 >= claimed_at)
                      )
                ORDER BY id
                "#,
            )
            .bind(publication.min_event_time)
            .bind(publication.published_at)
            .fetch_all(&mut *transaction)
            .await?;

            for rule in rules {
                let context = rule
                    .lookback_minutes
                    .filter(|minutes| *minutes > 0)
                    .map(|minutes| Duration::minutes(i64::from(minutes)))
                    .unwrap_or(default_context);
                let watermark = rule
                    .last_run_at
                    .expect("query required a detection watermark");
                let in_flight_snapshot_race = rule
                    .claimed_at
                    .is_some_and(|claimed_at| publication.published_at >= claimed_at);
                let Some(time_range) = late_replay_window_for_rule(
                    publication.min_event_time,
                    publication.max_event_time,
                    watermark,
                    horizon_start,
                    context,
                    in_flight_snapshot_race,
                ) else {
                    continue;
                };
                // Merge an additional publication into the one unclaimed,
                // never-attempted successor for this rule/store. Object
                // batches routinely contain overlapping event-time ranges;
                // creating one job per batch turns ordinary out-of-order
                // delivery into an unbounded queue of redundant scans. A
                // running job and a retrying job remain immutable, so any new
                // publication safely accumulates in a distinct successor.
                let merged = sqlx::query(
                    r#"
                    UPDATE detection_late_replay_jobs
                    SET window_start = LEAST(window_start, $4),
                        window_end = GREATEST(window_end, $5)
                    WHERE id = (
                        SELECT id
                        FROM detection_late_replay_jobs
                        WHERE rule_id = $1
                          AND tenant_id = $2
                          AND bronze_store_id = $3
                          AND status = 'pending'
                          AND attempts = 0
                          AND claimed_by IS NULL
                        ORDER BY created_at, id
                        LIMIT 1
                        FOR UPDATE SKIP LOCKED
                    )
                    "#,
                )
                .bind(rule.id)
                .bind(&publication.tenant_id)
                .bind(&publication.bronze_store_id)
                .bind(time_range.start)
                .bind(time_range.end)
                .execute(&mut *transaction)
                .await?;
                if merged.rows_affected() > 0 {
                    plan.coalesced += 1;
                    continue;
                }

                let inserted = sqlx::query(
                    r#"
                    INSERT INTO detection_late_replay_jobs (
                        rule_id, tenant_id, bronze_store_id, batch_sha256,
                        window_start, window_end
                    )
                    VALUES ($1, $2, $3, $4, $5, $6)
                    -- The job identity is the table's only non-PK unique key: open core
                    -- (302) keys it (rule_id, tenant_id, bronze_store_id, batch_sha256) and
                    -- the enterprise overlay (9000084) leads it with security_tenant_id.
                    -- Naming either target breaks the other edition (42703 / 42P10), and a
                    -- feature cfg cannot pick one: a workspace build unifies the enterprise
                    -- feature onto open-core databases. `id` is a random uuid, so an
                    -- untargeted DO NOTHING absorbs exactly the identity conflict.
                    ON CONFLICT DO NOTHING
                    "#,
                )
                .bind(rule.id)
                .bind(&publication.tenant_id)
                .bind(&publication.bronze_store_id)
                .bind(&publication.batch_sha256)
                .bind(time_range.start)
                .bind(time_range.end)
                .execute(&mut *transaction)
                .await?;
                plan.jobs += usize::try_from(inserted.rows_affected()).unwrap_or_default();
            }

            mark_publication_planned(&mut transaction, &publication).await?;
            transaction.commit().await?;
            plan.publications += 1;
        }

        Ok(plan)
    }

    /// Claim repair jobs and their rules together. Reusing the rule claim keeps
    /// a normal cron run from racing a replay of the same rule on another node.
    pub async fn claim_late_replays(
        &self,
        batch_size: usize,
        node_id: &str,
        stale_claim_timeout: Duration,
        lease_duration: Duration,
    ) -> Result<Vec<LateReplayClaim>, DetectionRuleRepositoryError> {
        let mut claims = Vec::with_capacity(batch_size);
        for _ in 0..batch_size {
            let mut transaction = self.pool.begin().await?;
            let row = sqlx::query_as::<_, ReplayRow>(
                r#"
                SELECT j.id, j.rule_id, j.window_start, j.window_end, j.attempts
                FROM detection_late_replay_jobs j
                JOIN detection_rules r ON r.id = j.rule_id
                WHERE (
                        (j.status = 'pending' AND j.next_attempt_at <= NOW())
                        OR
                        (j.status = 'running' AND j.claim_expires_at < NOW())
                      )
                  AND r.archived = false
                  AND r.mode NOT IN ('staging', 'paused')
                  AND r.kind <> 'retro_hunt'
                  AND (
                        j.bronze_store_id = $2
                        OR r.dataset IS NULL
                        OR LOWER(r.dataset) = 'logs'
                      )
                  AND (
                        r.claimed_by IS NULL
                        OR r.claimed_at < NOW() - make_interval(secs => $1)
                      )
                ORDER BY j.next_attempt_at, j.created_at, j.id
                LIMIT 1
                FOR UPDATE OF j, r SKIP LOCKED
                "#,
            )
            .bind(stale_claim_timeout.num_milliseconds() as f64 / 1000.0)
            .bind(SCHEDULER_DRAIN_STORE)
            .fetch_optional(&mut *transaction)
            .await?;
            let Some(row) = row else {
                transaction.rollback().await?;
                break;
            };
            let attempt = row.attempts.saturating_add(1);
            sqlx::query(
                r#"
                UPDATE detection_rules
                SET claimed_by = $2, claimed_at = NOW()
                WHERE id = $1
                "#,
            )
            .bind(row.rule_id)
            .bind(node_id)
            .execute(&mut *transaction)
            .await?;
            sqlx::query(
                r#"
                UPDATE detection_late_replay_jobs
                SET status = 'running', attempts = $2,
                    claimed_by = $3, claimed_at = NOW(),
                    claim_expires_at = NOW() + make_interval(secs => $4),
                    completed_at = NULL
                WHERE id = $1
                "#,
            )
            .bind(row.id)
            .bind(attempt)
            .bind(node_id)
            .bind(lease_duration.num_milliseconds() as f64 / 1000.0)
            .execute(&mut *transaction)
            .await?;
            let rule =
                sqlx::query_as::<_, DetectionRule>("SELECT * FROM detection_rules WHERE id = $1")
                    .bind(row.rule_id)
                    .fetch_one(&mut *transaction)
                    .await?;
            transaction.commit().await?;
            claims.push(LateReplayClaim {
                job_id: row.id,
                attempt,
                time_range: TimeRangeInput::new(row.window_start, row.window_end),
                rule,
            });
        }
        Ok(claims)
    }

    /// Complete or retry one fenced repair attempt, always releasing the rule
    /// claim without touching `last_run_at` or `next_run_at`.
    pub async fn release_late_replay(
        &self,
        claim: &LateReplayClaim,
        node_id: &str,
        error: Option<&str>,
        max_attempts: i32,
        retry_horizon: Duration,
    ) -> Result<LateReplayReleaseOutcome, DetectionRuleRepositoryError> {
        let mut transaction = self.pool.begin().await?;
        let owned: Option<(i32, DateTime<Utc>)> = sqlx::query_as(
            r#"
            SELECT attempts, created_at
            FROM detection_late_replay_jobs
            WHERE id = $1 AND status = 'running'
              AND claimed_by = $2 AND attempts = $3
            FOR UPDATE
            "#,
        )
        .bind(claim.job_id)
        .bind(node_id)
        .bind(claim.attempt)
        .fetch_optional(&mut *transaction)
        .await?;
        if owned.is_none() {
            transaction.rollback().await?;
            return Ok(LateReplayReleaseOutcome::LostClaim);
        }

        let outcome;
        if let Some(error) = error {
            let bounded_error = error.chars().take(4_096).collect::<String>();
            let created_at = owned.expect("owned replay row checked above").1;
            // An attempt count prevents a tight permanent-error loop, but it
            // must not turn an ordinary catalog/signer outage into a manual
            // detection gap after only a few minutes. Keep backing off until
            // the same bounded repair horizon that admitted the event expires.
            let retry_expired = created_at <= Utc::now() - retry_horizon.max(Duration::minutes(1));
            if claim.attempt >= max_attempts.max(1) && retry_expired {
                sqlx::query(
                    r#"
                    UPDATE detection_late_replay_jobs
                    SET status = 'dead_letter', claimed_by = NULL,
                        claimed_at = NULL, claim_expires_at = NULL,
                        completed_at = NOW(), last_error = $2
                    WHERE id = $1
                    "#,
                )
                .bind(claim.job_id)
                .bind(bounded_error)
                .execute(&mut *transaction)
                .await?;
                outcome = LateReplayReleaseOutcome::DeadLetter;
            } else {
                let backoff_seconds = 2_i64
                    .saturating_pow(u32::try_from(claim.attempt).unwrap_or(30).min(10))
                    .min(3_600);
                sqlx::query(
                    r#"
                    UPDATE detection_late_replay_jobs
                    SET status = 'pending', claimed_by = NULL,
                        claimed_at = NULL, claim_expires_at = NULL,
                        next_attempt_at = NOW() + make_interval(secs => $2),
                        last_error = $3
                    WHERE id = $1
                    "#,
                )
                .bind(claim.job_id)
                .bind(backoff_seconds as f64)
                .bind(bounded_error)
                .execute(&mut *transaction)
                .await?;
                outcome = LateReplayReleaseOutcome::Retry;
            }
        } else {
            sqlx::query(
                r#"
                UPDATE detection_late_replay_jobs
                SET status = 'completed', claimed_by = NULL,
                    claimed_at = NULL, claim_expires_at = NULL,
                    completed_at = NOW(), last_error = NULL
                WHERE id = $1
                "#,
            )
            .bind(claim.job_id)
            .execute(&mut *transaction)
            .await?;
            outcome = LateReplayReleaseOutcome::Completed;
        }
        sqlx::query(
            r#"
            UPDATE detection_rules
            SET claimed_by = NULL, claimed_at = NULL
            WHERE id = $1 AND claimed_by = $2
            "#,
        )
        .bind(claim.rule.id)
        .bind(node_id)
        .execute(&mut *transaction)
        .await?;
        transaction.commit().await?;
        Ok(outcome)
    }

    /// Release a replay that committed a bounded batch but still has work in
    /// the same immutable window. Progress is not a failure attempt: reset the
    /// attempt budget and make the job immediately reclaimable while retaining
    /// the diagnostic message for operators.
    pub async fn release_late_replay_progress(
        &self,
        claim: &LateReplayClaim,
        node_id: &str,
        message: &str,
    ) -> Result<LateReplayReleaseOutcome, DetectionRuleRepositoryError> {
        let bounded_message = message.chars().take(4_096).collect::<String>();
        let mut transaction = self.pool.begin().await?;
        let updated = sqlx::query(
            r#"
            UPDATE detection_late_replay_jobs
            SET status = 'pending', attempts = 0,
                claimed_by = NULL, claimed_at = NULL, claim_expires_at = NULL,
                next_attempt_at = NOW() + INTERVAL '1 second',
                last_error = $4
            WHERE id = $1 AND status = 'running'
              AND claimed_by = $2 AND attempts = $3
            "#,
        )
        .bind(claim.job_id)
        .bind(node_id)
        .bind(claim.attempt)
        .bind(bounded_message)
        .execute(&mut *transaction)
        .await?;
        if updated.rows_affected() == 0 {
            transaction.rollback().await?;
            return Ok(LateReplayReleaseOutcome::LostClaim);
        }
        sqlx::query(
            r#"
            UPDATE detection_rules
            SET claimed_by = NULL, claimed_at = NULL
            WHERE id = $1 AND claimed_by = $2
            "#,
        )
        .bind(claim.rule.id)
        .bind(node_id)
        .execute(&mut *transaction)
        .await?;
        transaction.commit().await?;
        Ok(LateReplayReleaseOutcome::Draining)
    }
}

fn late_replay_window(
    min_event_time: DateTime<Utc>,
    max_event_time: DateTime<Utc>,
    completed_watermark: DateTime<Utc>,
    horizon_start: DateTime<Utc>,
    context: Duration,
) -> Option<TimeRangeInput> {
    if min_event_time >= completed_watermark - Duration::seconds(5) {
        return None;
    }
    let start = (min_event_time - context).max(horizon_start);
    let end = (max_event_time + Duration::milliseconds(1) + context).min(completed_watermark);
    (end > start).then(|| TimeRangeInput::new(start, end))
}

fn late_replay_window_for_rule(
    min_event_time: DateTime<Utc>,
    max_event_time: DateTime<Utc>,
    completed_watermark: DateTime<Utc>,
    horizon_start: DateTime<Utc>,
    context: Duration,
    in_flight_snapshot_race: bool,
) -> Option<TimeRangeInput> {
    if !in_flight_snapshot_race {
        return late_replay_window(
            min_event_time,
            max_event_time,
            completed_watermark,
            horizon_start,
            context,
        );
    }
    let start = (min_event_time - context).max(horizon_start);
    // Do not cap at the old watermark in the race case. The normal run may
    // have queried before this publication existed, including event times just
    // ahead of its prior watermark. The immutable publication bounds define
    // the exact repair interval.
    let end = max_event_time + Duration::milliseconds(1) + context;
    (end > start).then(|| TimeRangeInput::new(start, end))
}

async fn mark_publication_planned(
    transaction: &mut Transaction<'_, Postgres>,
    publication: &EventPublication,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"
        UPDATE lake_detection_event_publications
        SET planned_at = NOW()
        WHERE tenant_id = $1 AND bronze_store_id = $2 AND batch_sha256 = $3
        "#,
    )
    .bind(&publication.tenant_id)
    .bind(&publication.bronze_store_id)
    .bind(&publication.batch_sha256)
    .execute(&mut **transaction)
    .await?;
    Ok(())
}

async fn mark_publication_expired(
    transaction: &mut Transaction<'_, Postgres>,
    publication: &EventPublication,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"
        UPDATE lake_detection_event_publications
        SET expired_at = NOW()
        WHERE tenant_id = $1 AND bronze_store_id = $2 AND batch_sha256 = $3
        "#,
    )
    .bind(&publication.tenant_id)
    .bind(&publication.bronze_store_id)
    .bind(&publication.batch_sha256)
    .execute(&mut **transaction)
    .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(value: &str) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339(value)
            .unwrap()
            .with_timezone(&Utc)
    }

    #[test]
    fn mixed_fresh_and_late_batch_repairs_only_the_completed_window() {
        let window = late_replay_window(
            at("2026-08-15T09:30:00Z"),
            at("2026-08-15T10:05:00Z"),
            at("2026-08-15T10:00:00Z"),
            at("2026-08-08T10:00:00Z"),
            Duration::minutes(15),
        )
        .unwrap();
        assert_eq!(window.start, at("2026-08-15T09:15:00Z"));
        assert_eq!(window.end, at("2026-08-15T10:00:00Z"));
    }

    #[test]
    fn on_time_batch_does_not_create_a_repair_window() {
        assert!(late_replay_window(
            at("2026-08-15T09:59:58Z"),
            at("2026-08-15T10:00:02Z"),
            at("2026-08-15T10:00:00Z"),
            at("2026-08-08T10:00:00Z"),
            Duration::minutes(15),
        )
        .is_none());
    }

    #[test]
    fn repair_window_never_crosses_the_configured_horizon() {
        let horizon = at("2026-08-08T10:00:00Z");
        let window = late_replay_window(
            at("2026-08-08T09:50:00Z"),
            at("2026-08-08T10:02:00Z"),
            at("2026-08-15T10:00:00Z"),
            horizon,
            Duration::minutes(15),
        )
        .unwrap();
        assert_eq!(window.start, horizon);
    }

    #[test]
    fn publication_after_claim_gets_an_immutable_replay_window() {
        let window = late_replay_window_for_rule(
            at("2026-08-15T10:00:02Z"),
            at("2026-08-15T10:00:03Z"),
            at("2026-08-15T10:00:00Z"),
            at("2026-08-08T10:00:00Z"),
            Duration::minutes(15),
            true,
        )
        .unwrap();
        assert_eq!(window.start, at("2026-08-15T09:45:02Z"));
        assert_eq!(window.end, at("2026-08-15T10:15:03.001Z"));
    }
}
