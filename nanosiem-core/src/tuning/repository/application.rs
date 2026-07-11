// SPDX-License-Identifier: AGPL-3.0-or-later

//! Atomic application of tuning proposals.

use super::test_results::{
    count_as_i64, proof_allows_autonomous_apply, proof_reduction_percentage,
};
use super::TuningRepository;
use crate::detection::materialized_view::{acquire_rule_runtime_lock, MaterializedViewGenerator};
use crate::detection_code_target::acquire_autonomous_tuning_dac_lock;
use crate::models::DetectionRule;
use crate::tuning::types::{TuningStatus, TuningValidationProof};
use serde_json::Value;
use sha2::{Digest, Sha256};
use sqlx::{FromRow, Postgres, Transaction};
use thiserror::Error;
use uuid::Uuid;

const ACTIONABLE_PROPOSAL_STATUSES: &[&str] = &["proposed", "test_passed"];

/// Rule-side change performed while accepting a proposal.
#[derive(Debug, Clone)]
pub enum ProposalRuleMutation {
    /// Replace the rule query and create a new active version.
    Query {
        query: String,
        created_by: Option<Uuid>,
        change_reason: String,
    },
    /// Replace AI triage hints with the proposal's persisted `proposed_hints`.
    Hints,
    /// Pause a silent rule without changing its query.
    Pause,
    /// Record the analyst decision without changing the rule.
    Acknowledge,
}

/// Inputs needed to accept and audit a proposal in one PostgreSQL transaction.
#[derive(Debug, Clone)]
pub struct AtomicProposalApplyRequest {
    pub proposal_id: Uuid,
    pub target_status: TuningStatus,
    pub mutation: ProposalRuleMutation,
    pub reviewer_notes: Option<String>,
    pub log_trigger_reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AtomicProposalApplyResult {
    pub rule_id: Uuid,
    pub rule_name: String,
    pub version_id: Option<i32>,
    /// The PostgreSQL change committed with a durable ClickHouse sync job.
    pub runtime_sync_required: bool,
    /// This caller owns the persisted reconciliation lease.
    pub runtime_sync_claimed: bool,
}

#[derive(Debug, Error)]
pub enum AtomicProposalApplyError {
    #[error("tuning proposal not found: {0}")]
    ProposalNotFound(Uuid),
    #[error("tuning proposal {proposal_id} is not actionable (current status: {status})")]
    InvalidProposalState { proposal_id: Uuid, status: String },
    #[error("tuning proposal {proposal_id} is stale because rule {rule_id} changed after it was generated")]
    StaleRuleBase { proposal_id: Uuid, rule_id: Uuid },
    #[error("tuning proposal {proposal_id} must be applied through Detection-as-Code")]
    DetectionAsCodeRequired { proposal_id: Uuid },
    #[error("tuning proposal {proposal_id} cannot perform the requested mutation: {reason}")]
    InvalidMutation { proposal_id: Uuid, reason: String },
    #[error("tuning proposal {proposal_id} no longer satisfies autonomous apply policy: {reason}")]
    AutonomousPolicyRejected { proposal_id: Uuid, reason: String },
    #[error("tuning proposal {proposal_id} has no valid autonomous execution proof: {reason}")]
    AutonomousValidationRejected { proposal_id: Uuid, reason: String },
    #[error("tuning proposal {proposal_id} is incompatible with real-time execution: {reason}")]
    RealTimeValidation { proposal_id: Uuid, reason: String },
    #[error("database error while applying tuning proposal: {0}")]
    Database(#[from] sqlx::Error),
}

#[derive(Debug, FromRow)]
struct LockedProposalRule {
    rule_id: Uuid,
    proposal_type: String,
    proposal_status: String,
    proposal_confidence_score: f64,
    proposal_safety_validation: Value,
    original_query: String,
    proposed_query: String,
    current_hints: Option<Value>,
    proposed_hints: Option<Value>,
    rule_name: String,
    rule_description: Option<String>,
    rule_severity: String,
    rule_mode: String,
    rule_detection_mode: String,
    rule_archived: bool,
    rule_dataset: String,
    rule_schedule_cron: Option<String>,
    rule_lookback_minutes: Option<i32>,
    current_query: String,
    rule_hints: Value,
    rule_auto_tuning_enabled: bool,
    rule_auto_tuning_min_confidence: f64,
    rule_auto_tuning_critical: bool,
    rule_auto_apply_enabled: bool,
    rule_auto_tuning_cooldown_expired: bool,
}

#[derive(Debug, FromRow)]
struct LockedPersistedValidation {
    original_alert_count: i64,
    tuned_alert_count: i64,
    reduction_percentage: f64,
    true_positives_preserved: bool,
    validation_passed: bool,
    validation_proof: Option<Value>,
}

impl TuningRepository {
    /// Apply a proposal with stale-base and expected-state checks.
    ///
    /// The proposal row and rule row are locked together. Rule mutation, version
    /// activation, proposal transition, reviewer notes, and the tuning log are
    /// committed as one unit. Callers must send notifications only after this
    /// method returns successfully.
    pub async fn apply_proposal_atomic(
        &self,
        request: AtomicProposalApplyRequest,
    ) -> Result<AtomicProposalApplyResult, AtomicProposalApplyError> {
        self.apply_proposal_atomic_inner(request, None, None, None)
            .await
    }

    /// Apply a proposal while validating and durably reconciling real-time rules.
    ///
    /// Query mutations always take the shared per-rule runtime writer lock. A
    /// real-time query is rendered from the exact row locked by the transaction,
    /// then a reconciliation job is committed alongside the rule/version change.
    pub async fn apply_proposal_atomic_with_runtime(
        &self,
        request: AtomicProposalApplyRequest,
        realtime_validator: &MaterializedViewGenerator,
        runtime_sync_owner: Option<&str>,
    ) -> Result<AtomicProposalApplyResult, AtomicProposalApplyError> {
        self.apply_proposal_atomic_inner(
            request,
            Some(realtime_validator),
            runtime_sync_owner,
            None,
        )
        .await
    }

    /// Atomically apply an autonomously validated query proposal.
    ///
    /// The exact persisted replay result, true-positive corpus revision, rule
    /// execution policy, and Detection-as-Code routing state are checked while
    /// the proposal/rule/version/status/log transaction is still open.
    pub async fn apply_validated_query_atomic_with_runtime(
        &self,
        request: AtomicProposalApplyRequest,
        realtime_validator: &MaterializedViewGenerator,
        runtime_sync_owner: Option<&str>,
        test_result_id: Uuid,
        validation_proof: &TuningValidationProof,
    ) -> Result<AtomicProposalApplyResult, AtomicProposalApplyError> {
        self.apply_proposal_atomic_inner(
            request,
            Some(realtime_validator),
            runtime_sync_owner,
            Some((test_result_id, validation_proof)),
        )
        .await
    }

    async fn apply_proposal_atomic_inner(
        &self,
        request: AtomicProposalApplyRequest,
        realtime_validator: Option<&MaterializedViewGenerator>,
        runtime_sync_owner: Option<&str>,
        autonomous_validation: Option<(Uuid, &TuningValidationProof)>,
    ) -> Result<AtomicProposalApplyResult, AtomicProposalApplyError> {
        if !matches!(
            request.target_status,
            TuningStatus::ManuallyApproved | TuningStatus::Promoted
        ) {
            return Err(AtomicProposalApplyError::InvalidMutation {
                proposal_id: request.proposal_id,
                reason: format!(
                    "target status '{}' is not an apply terminal state",
                    request.target_status
                ),
            });
        }

        let requires_autonomous_validation =
            requires_autonomous_validation(request.target_status, &request.mutation);
        if requires_autonomous_validation && autonomous_validation.is_none() {
            return Err(AtomicProposalApplyError::AutonomousValidationRejected {
                proposal_id: request.proposal_id,
                reason: "promoted query mutations require a persisted execution proof".to_string(),
            });
        }
        if autonomous_validation.is_some() && !requires_autonomous_validation {
            return Err(AtomicProposalApplyError::InvalidMutation {
                proposal_id: request.proposal_id,
                reason: "autonomous execution proof supplied for a non-promoted query mutation"
                    .to_string(),
            });
        }

        // Query writers share NAN-1772's runtime lock with ordinary rule edits,
        // rollbacks, and the distributed ClickHouse reconciler. The proposal's
        // rule_id is immutable; it is re-read under row lock below.
        let query_rule_id = if matches!(&request.mutation, ProposalRuleMutation::Query { .. }) {
            Some(
                sqlx::query_scalar("SELECT rule_id FROM tuning_proposals WHERE id = $1")
                    .bind(request.proposal_id)
                    .fetch_optional(&self.pool)
                    .await?
                    .ok_or(AtomicProposalApplyError::ProposalNotFound(
                        request.proposal_id,
                    ))?,
            )
        } else {
            None
        };
        let _runtime_lock = if let Some(rule_id) = query_rule_id {
            Some(acquire_rule_runtime_lock(&self.pool, rule_id).await?)
        } else {
            None
        };

        let mut tx = self.pool.begin().await?;
        if query_rule_id.is_some() {
            // Each statement must observe a target activation that held the
            // DaC lock first. Every direct query writer participates, including
            // analyst approval; git remains authoritative once a target exists.
            sqlx::query("SET TRANSACTION ISOLATION LEVEL READ COMMITTED")
                .execute(&mut *tx)
                .await?;
            acquire_autonomous_tuning_dac_lock(&mut tx).await?;
            ensure_no_active_dac_target(&mut tx, request.proposal_id).await?;
        }
        if autonomous_validation.is_some() {
            // TP disposition writers use this per-rule lock. A writer that
            // commits first is visible to the proof revision check below.
            sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1::uuid::text, $2))")
                .bind(query_rule_id.expect("autonomous validation requires a query rule"))
                .bind(1767_i64)
                .execute(&mut *tx)
                .await?;
        }
        let locked = sqlx::query_as::<_, LockedProposalRule>(
            r#"
            SELECT
                tp.rule_id,
                COALESCE(tp.proposal_type, 'query_tuning') AS proposal_type,
                tp.status AS proposal_status,
                tp.confidence_score AS proposal_confidence_score,
                tp.safety_validation AS proposal_safety_validation,
                tp.original_query,
                tp.proposed_query,
                tp.current_hints,
                tp.proposed_hints,
                dr.name AS rule_name,
                dr.description AS rule_description,
                dr.severity AS rule_severity,
                dr.mode AS rule_mode,
                dr.detection_mode AS rule_detection_mode,
                dr.archived AS rule_archived,
                LOWER(COALESCE(dr.dataset, 'logs')) AS rule_dataset,
                dr.schedule_cron AS rule_schedule_cron,
                dr.lookback_minutes AS rule_lookback_minutes,
                dr.query AS current_query,
                dr.ai_triage_hints AS rule_hints,
                dr.auto_tuning_enabled AS rule_auto_tuning_enabled,
                COALESCE(dr.auto_tuning_min_confidence, 0.8) AS rule_auto_tuning_min_confidence,
                COALESCE(dr.auto_tuning_critical, false) AS rule_auto_tuning_critical,
                COALESCE(dr.auto_apply_enabled, false) AS rule_auto_apply_enabled,
                (
                    dr.auto_tuning_disabled_until IS NULL
                    OR dr.auto_tuning_disabled_until < NOW()
                ) AS rule_auto_tuning_cooldown_expired
            FROM tuning_proposals tp
            JOIN detection_rules dr ON dr.id = tp.rule_id
            WHERE tp.id = $1
            FOR UPDATE OF tp, dr
            "#,
        )
        .bind(request.proposal_id)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or(AtomicProposalApplyError::ProposalNotFound(
            request.proposal_id,
        ))?;

        if query_rule_id.is_some_and(|rule_id| rule_id != locked.rule_id) {
            return Err(stale_error(request.proposal_id, locked.rule_id));
        }

        if !ACTIONABLE_PROPOSAL_STATUSES.contains(&locked.proposal_status.as_str()) {
            return Err(AtomicProposalApplyError::InvalidProposalState {
                proposal_id: request.proposal_id,
                status: locked.proposal_status,
            });
        }

        if request.target_status == TuningStatus::Promoted {
            ensure_autonomous_policy(&locked, &request.mutation, request.proposal_id)?;
        }

        let applied_test_result_id = if let Some((test_result_id, proof)) = autonomous_validation {
            let mutation_query = match &request.mutation {
                ProposalRuleMutation::Query { query, .. } => query,
                _ => unreachable!("validated autonomous apply was bounded to query mutations"),
            };
            ensure_query_base(&locked, request.proposal_id)?;
            ensure_autonomous_validation_snapshot(
                &locked,
                mutation_query,
                proof,
                request.proposal_id,
            )?;
            verify_persisted_autonomous_validation(
                &mut tx,
                &locked,
                request.proposal_id,
                test_result_id,
                proof,
            )
            .await?;
            Some(test_result_id)
        } else {
            None
        };

        let version_id = match request.mutation {
            ProposalRuleMutation::Query {
                query,
                created_by,
                change_reason,
            } => {
                if locked.proposal_type != "query_tuning" && locked.proposal_type != "silent_rule" {
                    return Err(AtomicProposalApplyError::InvalidMutation {
                        proposal_id: request.proposal_id,
                        reason: format!(
                            "proposal type '{}' does not mutate rule queries",
                            locked.proposal_type
                        ),
                    });
                }
                ensure_query_base(&locked, request.proposal_id)?;

                if locked.rule_detection_mode == "real-time" {
                    let validator = realtime_validator.ok_or_else(|| {
                        AtomicProposalApplyError::RealTimeValidation {
                            proposal_id: request.proposal_id,
                            reason: "the caller did not provide the materialized-view validator"
                                .to_string(),
                        }
                    })?;
                    let mut prospective = sqlx::query_as::<_, DetectionRule>(
                        "SELECT * FROM detection_rules WHERE id = $1",
                    )
                    .bind(locked.rule_id)
                    .fetch_one(&mut *tx)
                    .await?;
                    prospective.query = query.clone();
                    validator.generate_view_ddl(&prospective).map_err(|error| {
                        AtomicProposalApplyError::RealTimeValidation {
                            proposal_id: request.proposal_id,
                            reason: error.to_string(),
                        }
                    })?;
                }

                let updated = sqlx::query(
                    "UPDATE detection_rules \
                     SET query = $1, updated_at = NOW() \
                     WHERE id = $2 AND query = $3",
                )
                .bind(&query)
                .bind(locked.rule_id)
                .bind(&locked.original_query)
                .execute(&mut *tx)
                .await?;
                if updated.rows_affected() != 1 {
                    return Err(stale_error(request.proposal_id, locked.rule_id));
                }

                let next_version_number: i32 = sqlx::query_scalar(
                    "SELECT COALESCE(MAX(version_number), 0) + 1 \
                     FROM detection_rule_versions WHERE rule_id = $1",
                )
                .bind(locked.rule_id)
                .fetch_one(&mut *tx)
                .await?;

                // The rule-row lock serializes all version writers. Deactivate and
                // insert in this transaction so an insert failure restores the old
                // active row instead of committing a zero-active state.
                sqlx::query(
                    "UPDATE detection_rule_versions SET is_active = false WHERE rule_id = $1",
                )
                .bind(locked.rule_id)
                .execute(&mut *tx)
                .await?;

                let id: i32 = sqlx::query_scalar(
                    r#"
                    INSERT INTO detection_rule_versions (
                        rule_id, version_number, query, name, description, severity,
                        enabled, is_active, created_by, change_reason,
                        tuning_proposal_id, reverted_from_version
                    )
                    VALUES ($1, $2, $3, $4, $5, $6, $7, true, $8, $9, $10, NULL)
                    RETURNING id
                    "#,
                )
                .bind(locked.rule_id)
                .bind(next_version_number)
                .bind(&query)
                .bind(&locked.rule_name)
                .bind(&locked.rule_description)
                .bind(&locked.rule_severity)
                .bind(locked.rule_mode != "staging" && locked.rule_mode != "paused")
                .bind(created_by)
                .bind(change_reason)
                .bind(request.proposal_id)
                .fetch_one(&mut *tx)
                .await?;
                Some(id)
            }
            ProposalRuleMutation::Hints => {
                if locked.proposal_type != "hint_update" {
                    return Err(AtomicProposalApplyError::InvalidMutation {
                        proposal_id: request.proposal_id,
                        reason: format!(
                            "proposal type '{}' does not mutate triage hints",
                            locked.proposal_type
                        ),
                    });
                }
                let expected = locked.current_hints.as_ref().ok_or_else(|| {
                    AtomicProposalApplyError::InvalidMutation {
                        proposal_id: request.proposal_id,
                        reason: "hint proposal has no current_hints base snapshot".to_string(),
                    }
                })?;
                if &locked.rule_hints != expected {
                    return Err(stale_error(request.proposal_id, locked.rule_id));
                }
                let proposed = locked.proposed_hints.as_ref().ok_or_else(|| {
                    AtomicProposalApplyError::InvalidMutation {
                        proposal_id: request.proposal_id,
                        reason: "hint proposal has no proposed_hints payload".to_string(),
                    }
                })?;

                let updated = sqlx::query(
                    "UPDATE detection_rules \
                     SET ai_triage_hints = $1, updated_at = NOW() \
                     WHERE id = $2 AND ai_triage_hints = $3",
                )
                .bind(proposed)
                .bind(locked.rule_id)
                .bind(expected)
                .execute(&mut *tx)
                .await?;
                if updated.rows_affected() != 1 {
                    return Err(stale_error(request.proposal_id, locked.rule_id));
                }
                None
            }
            ProposalRuleMutation::Pause => {
                if locked.proposal_type != "silent_rule" {
                    return Err(AtomicProposalApplyError::InvalidMutation {
                        proposal_id: request.proposal_id,
                        reason: format!(
                            "proposal type '{}' cannot pause a rule",
                            locked.proposal_type
                        ),
                    });
                }
                ensure_query_base(&locked, request.proposal_id)?;
                let updated = sqlx::query(
                    "UPDATE detection_rules \
                     SET mode = 'paused', updated_at = NOW() \
                     WHERE id = $1 AND query = $2",
                )
                .bind(locked.rule_id)
                .bind(&locked.original_query)
                .execute(&mut *tx)
                .await?;
                if updated.rows_affected() != 1 {
                    return Err(stale_error(request.proposal_id, locked.rule_id));
                }
                None
            }
            ProposalRuleMutation::Acknowledge => {
                if locked.proposal_type != "silent_rule" {
                    return Err(AtomicProposalApplyError::InvalidMutation {
                        proposal_id: request.proposal_id,
                        reason: format!(
                            "proposal type '{}' cannot be acknowledged without a rule change",
                            locked.proposal_type
                        ),
                    });
                }
                ensure_query_base(&locked, request.proposal_id)?;
                None
            }
        };

        let runtime_sync_required =
            locked.rule_detection_mode == "real-time" && version_id.is_some();
        let runtime_sync_claimed = runtime_sync_required && runtime_sync_owner.is_some();
        if runtime_sync_required {
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
            .bind(locked.rule_id)
            .bind(version_id.expect("runtime sync requires a created version"))
            .bind(runtime_sync_owner)
            .execute(&mut *tx)
            .await?;
        }

        let transitioned = sqlx::query(
            r#"
            UPDATE tuning_proposals
            SET status = $1,
                reviewer_notes = COALESCE($2, reviewer_notes)
            WHERE id = $3 AND status = $4
            "#,
        )
        .bind(request.target_status.to_string())
        .bind(request.reviewer_notes.as_deref())
        .bind(request.proposal_id)
        .bind(&locked.proposal_status)
        .execute(&mut *tx)
        .await?;
        if transitioned.rows_affected() != 1 {
            return Err(AtomicProposalApplyError::InvalidProposalState {
                proposal_id: request.proposal_id,
                status: locked.proposal_status,
            });
        }

        let log_status = request.target_status.to_string();
        let updated_logs = sqlx::query(
            r#"
            UPDATE tuning_logs
            SET status = $1,
                applied_version_id = COALESCE($2, applied_version_id),
                test_results_id = COALESCE($3, test_results_id)
            WHERE proposal_id = $4
            "#,
        )
        .bind(&log_status)
        .bind(version_id)
        .bind(applied_test_result_id)
        .bind(request.proposal_id)
        .execute(&mut *tx)
        .await?;

        if updated_logs.rows_affected() == 0 {
            sqlx::query(
                r#"
                INSERT INTO tuning_logs (
                    id, rule_id, rule_name, triggered_at, trigger_reason,
                    proposal_id, test_results_id, applied_version_id, status
                )
                VALUES ($1, $2, $3, NOW(), $4, $5, $6, $7, $8)
                "#,
            )
            .bind(Uuid::now_v7())
            .bind(locked.rule_id)
            .bind(&locked.rule_name)
            .bind(request.log_trigger_reason)
            .bind(request.proposal_id)
            .bind(applied_test_result_id)
            .bind(version_id)
            .bind(&log_status)
            .execute(&mut *tx)
            .await?;
        }

        tx.commit().await?;

        Ok(AtomicProposalApplyResult {
            rule_id: locked.rule_id,
            rule_name: locked.rule_name,
            version_id,
            runtime_sync_required,
            runtime_sync_claimed,
        })
    }

    /// Compare-and-set a proposal status, optionally recording reviewer notes.
    /// Returns `false` when another actor already moved the proposal.
    pub async fn transition_proposal_status(
        &self,
        proposal_id: Uuid,
        expected: &[TuningStatus],
        target: TuningStatus,
        reviewer_notes: Option<&str>,
    ) -> Result<bool, sqlx::Error> {
        let expected: Vec<String> = expected.iter().map(ToString::to_string).collect();
        let mut tx = self.pool.begin().await?;
        let transitioned_rule_id: Option<Uuid> = sqlx::query_scalar(
            r#"
            UPDATE tuning_proposals
            SET status = $1,
                reviewer_notes = COALESCE($2, reviewer_notes),
                pr_target_id = CASE WHEN $1 = 'rejected' THEN NULL ELSE pr_target_id END
            WHERE id = $3 AND status = ANY($4::text[])
            RETURNING rule_id
            "#,
        )
        .bind(target.to_string())
        .bind(reviewer_notes)
        .bind(proposal_id)
        .bind(expected)
        .fetch_optional(&mut *tx)
        .await?;

        let Some(rule_id) = transitioned_rule_id else {
            tx.rollback().await?;
            return Ok(false);
        };

        let log_status = target.to_string();
        let updated_logs = sqlx::query("UPDATE tuning_logs SET status = $1 WHERE proposal_id = $2")
            .bind(&log_status)
            .bind(proposal_id)
            .execute(&mut *tx)
            .await?;

        if updated_logs.rows_affected() == 0 {
            let rule_name: String =
                sqlx::query_scalar("SELECT name FROM detection_rules WHERE id = $1")
                    .bind(rule_id)
                    .fetch_one(&mut *tx)
                    .await?;
            let trigger_reason = reviewer_notes
                .map(|notes| format!("Proposal transitioned to {target}: {notes}"))
                .unwrap_or_else(|| format!("Proposal transitioned to {target}"));
            sqlx::query(
                r#"
                INSERT INTO tuning_logs (
                    id, rule_id, rule_name, triggered_at, trigger_reason,
                    proposal_id, status
                )
                VALUES ($1, $2, $3, NOW(), $4, $5, $6)
                "#,
            )
            .bind(Uuid::now_v7())
            .bind(rule_id)
            .bind(rule_name)
            .bind(trigger_reason)
            .bind(proposal_id)
            .bind(log_status)
            .execute(&mut *tx)
            .await?;
        }

        tx.commit().await?;
        Ok(true)
    }
}

fn ensure_autonomous_validation_snapshot(
    locked: &LockedProposalRule,
    mutation_query: &str,
    proof: &TuningValidationProof,
    proposal_id: Uuid,
) -> Result<(), AtomicProposalApplyError> {
    let reject = |reason: &str| AtomicProposalApplyError::AutonomousValidationRejected {
        proposal_id,
        reason: reason.to_string(),
    };

    if !proof_allows_autonomous_apply(proof) {
        return Err(reject(
            "execution proof is incomplete, inexact, over budget, or outside the allowed reduction range",
        ));
    }
    if locked.proposed_query != mutation_query {
        return Err(reject(
            "the requested query does not equal the proposal payload that was validated",
        ));
    }

    let original_query_sha256 = sha256_hex(&locked.original_query);
    if proof.original_query_sha256 != original_query_sha256
        || sha256_hex(&locked.current_query) != original_query_sha256
    {
        return Err(reject(
            "the validated original-query hash does not match the locked rule snapshot",
        ));
    }
    let proposed_query_sha256 = sha256_hex(&locked.proposed_query);
    if proof.proposed_query_sha256 != proposed_query_sha256
        || sha256_hex(mutation_query) != proposed_query_sha256
    {
        return Err(reject(
            "the validated proposed-query hash does not match the proposal and mutation payloads",
        ));
    }
    if proof.dataset != locked.rule_dataset {
        return Err(reject(
            "the validated dataset does not match the rule's current dataset",
        ));
    }
    if locked.rule_schedule_cron.as_deref() != Some(proof.schedule_cron.as_str()) {
        return Err(reject(
            "the validated schedule does not match the rule's current production schedule",
        ));
    }
    if locked.rule_lookback_minutes.map(i64::from) != Some(proof.lookback_minutes) {
        return Err(reject(
            "the validated lookback does not match the rule's current production lookback",
        ));
    }

    Ok(())
}

async fn ensure_no_active_dac_target(
    tx: &mut Transaction<'_, Postgres>,
    proposal_id: Uuid,
) -> Result<(), AtomicProposalApplyError> {
    let active: bool = sqlx::query_scalar(
        r#"
        SELECT EXISTS (
            SELECT 1
            FROM detection_code_targets
            WHERE enabled = TRUE
              AND token_encrypted IS NOT NULL
        )
        "#,
    )
    .fetch_one(&mut **tx)
    .await?;
    if active {
        return Err(AtomicProposalApplyError::DetectionAsCodeRequired { proposal_id });
    }
    Ok(())
}

async fn verify_persisted_autonomous_validation(
    tx: &mut Transaction<'_, Postgres>,
    locked: &LockedProposalRule,
    proposal_id: Uuid,
    test_result_id: Uuid,
    proof: &TuningValidationProof,
) -> Result<(), AtomicProposalApplyError> {
    let reject = |reason: &str| AtomicProposalApplyError::AutonomousValidationRejected {
        proposal_id,
        reason: reason.to_string(),
    };

    // Detection-match disposition triggers use the same per-rule advisory
    // lock, so a corpus writer is either visible here or linearizes afterward.
    let corpus_revision: i64 = sqlx::query_scalar(
        r#"
        SELECT COALESCE(
            (SELECT revision
             FROM tuning_tp_corpus_revisions
             WHERE rule_id = $1),
            0
        )
        "#,
    )
    .bind(locked.rule_id)
    .fetch_one(&mut **tx)
    .await?;
    if corpus_revision != proof.corpus_revision {
        return Err(reject(
            "the analyst-confirmed true-positive corpus changed after validation",
        ));
    }

    let persisted = sqlx::query_as::<_, LockedPersistedValidation>(
        r#"
        SELECT
            original_alert_count,
            tuned_alert_count,
            reduction_percentage,
            true_positives_preserved,
            validation_passed,
            validation_proof
        FROM tuning_test_results
        WHERE id = $1
          AND proposal_id = $2
        FOR SHARE
        "#,
    )
    .bind(test_result_id)
    .bind(proposal_id)
    .fetch_optional(&mut **tx)
    .await?
    .ok_or_else(|| reject("the persisted test result is missing or belongs to another proposal"))?;

    ensure_persisted_validation_binding(&persisted, proof, proposal_id)
}

fn ensure_persisted_validation_binding(
    persisted: &LockedPersistedValidation,
    proof: &TuningValidationProof,
    proposal_id: Uuid,
) -> Result<(), AtomicProposalApplyError> {
    let reject = |reason: &str| AtomicProposalApplyError::AutonomousValidationRejected {
        proposal_id,
        reason: reason.to_string(),
    };

    if !persisted.validation_passed || !persisted.true_positives_preserved {
        return Err(reject(
            "the persisted test result did not pass exact execution and true-positive preservation checks",
        ));
    }
    let expected_proof = serde_json::to_value(proof)
        .map_err(|_| reject("the execution proof could not be serialized for durable binding"))?;
    if persisted.validation_proof.as_ref() != Some(&expected_proof) {
        return Err(reject(
            "the supplied execution proof does not equal the persisted test evidence",
        ));
    }
    if persisted.original_alert_count != count_as_i64(proof.original_match_count)
        || persisted.tuned_alert_count != count_as_i64(proof.proposed_match_count)
        || persisted.reduction_percentage.to_bits() != proof_reduction_percentage(proof).to_bits()
    {
        return Err(reject(
            "the persisted result counts do not match the execution proof",
        ));
    }

    Ok(())
}

fn requires_autonomous_validation(
    target_status: TuningStatus,
    mutation: &ProposalRuleMutation,
) -> bool {
    target_status == TuningStatus::Promoted
        && matches!(mutation, ProposalRuleMutation::Query { .. })
}

fn sha256_hex(value: &str) -> String {
    hex::encode(Sha256::digest(value.as_bytes()))
}

fn ensure_query_base(
    locked: &LockedProposalRule,
    proposal_id: Uuid,
) -> Result<(), AtomicProposalApplyError> {
    if locked.current_query != locked.original_query {
        return Err(stale_error(proposal_id, locked.rule_id));
    }
    Ok(())
}

fn ensure_autonomous_policy(
    locked: &LockedProposalRule,
    mutation: &ProposalRuleMutation,
    proposal_id: Uuid,
) -> Result<(), AtomicProposalApplyError> {
    let reject = |reason: &str| AtomicProposalApplyError::AutonomousPolicyRejected {
        proposal_id,
        reason: reason.to_string(),
    };

    if !locked.rule_auto_apply_enabled {
        return Err(reject("auto-apply is disabled"));
    }
    if locked.rule_archived {
        return Err(reject("the rule is archived"));
    }
    if !matches!(locked.rule_mode.as_str(), "live" | "alerting") {
        return Err(reject("the rule is not in an executable production mode"));
    }
    if locked.proposal_confidence_score < locked.rule_auto_tuning_min_confidence {
        return Err(reject(
            "proposal confidence is below the current rule threshold",
        ));
    }
    if locked
        .proposal_safety_validation
        .get("is_safe")
        .and_then(Value::as_bool)
        != Some(true)
    {
        return Err(reject("proposal safety validation is not currently safe"));
    }

    if !locked.rule_auto_tuning_enabled {
        return Err(reject("auto-tuning is disabled"));
    }
    if locked.rule_auto_tuning_critical {
        return Err(reject("the rule currently requires critical-rule review"));
    }
    if !locked.rule_auto_tuning_cooldown_expired {
        return Err(reject("the rule is currently in its tuning cooldown"));
    }

    if !matches!(mutation, ProposalRuleMutation::Hints) {
        if locked.rule_detection_mode != "scheduled" {
            return Err(reject(
                "autonomous query application requires scheduled execution",
            ));
        }
        if locked.rule_schedule_cron.is_none() {
            return Err(reject(
                "autonomous query application requires an explicit production schedule",
            ));
        }
        if locked.rule_lookback_minutes.is_none() {
            return Err(reject(
                "autonomous query application requires an explicit production lookback",
            ));
        }
    }

    Ok(())
}

fn stale_error(proposal_id: Uuid, rule_id: Uuid) -> AtomicProposalApplyError {
    AtomicProposalApplyError::StaleRuleBase {
        proposal_id,
        rule_id,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Duration, TimeZone, Utc};

    fn locked_fixture(status: &str, current: &str, original: &str) -> LockedProposalRule {
        LockedProposalRule {
            rule_id: Uuid::now_v7(),
            proposal_type: "query_tuning".to_string(),
            proposal_status: status.to_string(),
            proposal_confidence_score: 0.95,
            proposal_safety_validation: serde_json::json!({ "is_safe": true }),
            original_query: original.to_string(),
            proposed_query: "tuned query".to_string(),
            current_hints: None,
            proposed_hints: None,
            rule_name: "test".to_string(),
            rule_description: None,
            rule_severity: "medium".to_string(),
            rule_mode: "alerting".to_string(),
            rule_detection_mode: "scheduled".to_string(),
            rule_archived: false,
            rule_dataset: "logs".to_string(),
            rule_schedule_cron: Some("*/5 * * * *".to_string()),
            rule_lookback_minutes: Some(5),
            current_query: current.to_string(),
            rule_hints: serde_json::json!({}),
            rule_auto_tuning_enabled: true,
            rule_auto_tuning_min_confidence: 0.8,
            rule_auto_tuning_critical: false,
            rule_auto_apply_enabled: true,
            rule_auto_tuning_cooldown_expired: true,
        }
    }

    fn valid_proof(locked: &LockedProposalRule) -> TuningValidationProof {
        let evaluation_start = Utc.with_ymd_and_hms(2026, 7, 9, 0, 0, 0).unwrap();
        let evaluation_end = evaluation_start + Duration::hours(24);
        let windows = vec![crate::tuning::types::TuningValidationWindow {
            start: evaluation_start,
            end: evaluation_start + Duration::minutes(5),
        }];
        let windows_sha256 = hex::encode(Sha256::digest(
            serde_json::to_vec(&windows).expect("serialize windows"),
        ));

        TuningValidationProof {
            proof_version: 1,
            original_query_sha256: sha256_hex(&locked.original_query),
            proposed_query_sha256: sha256_hex(&locked.proposed_query),
            dataset: locked.rule_dataset.clone(),
            schedule_cron: locked.rule_schedule_cron.clone().expect("test schedule"),
            lookback_minutes: i64::from(locked.rule_lookback_minutes.expect("test lookback")),
            evaluation_start,
            evaluation_end,
            windows,
            windows_sha256,
            corpus_count: 1,
            corpus_sha256: "a".repeat(64),
            corpus_revision: 7,
            corpus_unique_source_count: 1,
            corpus_source_ids_sha256: "b".repeat(64),
            corpus_truncated: false,
            corpus_identity_complete: true,
            original_match_count: 100,
            proposed_match_count: 50,
            original_source_ids_sha256: "c".repeat(64),
            proposed_source_ids_sha256: "d".repeat(64),
            original_failed_windows: 0,
            proposed_failed_windows: 0,
            original_truncated_windows: 0,
            proposed_truncated_windows: 0,
            original_identity_errors: 0,
            proposed_identity_errors: 0,
            original_rows_examined: 100,
            proposed_rows_examined: 50,
            original_bytes_examined: 1_000,
            proposed_bytes_examined: 500,
            original_budget_exceeded: false,
            proposed_budget_exceeded: false,
            counts_exact: true,
            true_positives_preserved: true,
            identity_mode: "physical_id_uuid_v1".to_string(),
        }
    }

    #[test]
    fn actionable_statuses_are_explicitly_bounded() {
        assert!(ACTIONABLE_PROPOSAL_STATUSES.contains(&"proposed"));
        assert!(ACTIONABLE_PROPOSAL_STATUSES.contains(&"test_passed"));
        assert!(!ACTIONABLE_PROPOSAL_STATUSES.contains(&"promoted"));
        assert!(!ACTIONABLE_PROPOSAL_STATUSES.contains(&"rejected"));
        assert!(!ACTIONABLE_PROPOSAL_STATUSES.contains(&"pr_pending"));
        assert!(!ACTIONABLE_PROPOSAL_STATUSES.contains(&"pr_opened"));
    }

    #[test]
    fn query_base_rejects_a_rule_edited_after_generation() {
        let proposal_id = Uuid::now_v7();
        let locked = locked_fixture("proposed", "newer analyst query", "proposal base query");
        let error = ensure_query_base(&locked, proposal_id).unwrap_err();
        assert!(matches!(
            error,
            AtomicProposalApplyError::StaleRuleBase { .. }
        ));
    }

    #[test]
    fn query_base_accepts_the_exact_persisted_snapshot() {
        let locked = locked_fixture("proposed", "same query", "same query");
        assert!(ensure_query_base(&locked, Uuid::now_v7()).is_ok());
    }

    #[test]
    fn autonomous_policy_uses_the_locked_rule_configuration() {
        let mut locked = locked_fixture("proposed", "same query", "same query");
        locked.rule_auto_apply_enabled = false;
        let result = ensure_autonomous_policy(
            &locked,
            &ProposalRuleMutation::Query {
                query: "new query".to_string(),
                created_by: None,
                change_reason: "test".to_string(),
            },
            Uuid::now_v7(),
        );
        assert!(matches!(
            result,
            Err(AtomicProposalApplyError::AutonomousPolicyRejected { .. })
        ));
    }

    #[test]
    fn every_promoted_query_requires_durable_validation() {
        let query = ProposalRuleMutation::Query {
            query: "tuned query".to_string(),
            created_by: None,
            change_reason: "test".to_string(),
        };

        assert!(requires_autonomous_validation(
            TuningStatus::Promoted,
            &query
        ));
        assert!(!requires_autonomous_validation(
            TuningStatus::ManuallyApproved,
            &query
        ));
        assert!(!requires_autonomous_validation(
            TuningStatus::Promoted,
            &ProposalRuleMutation::Hints
        ));
    }

    #[test]
    fn autonomous_validation_binds_queries_and_rule_execution_configuration() {
        let locked = locked_fixture("proposed", "base query", "base query");
        let proof = valid_proof(&locked);
        let proposal_id = Uuid::now_v7();
        assert!(ensure_autonomous_validation_snapshot(
            &locked,
            &locked.proposed_query,
            &proof,
            proposal_id,
        )
        .is_ok());

        let mut changed = proof.clone();
        changed.proposed_query_sha256 = "0".repeat(64);
        assert!(matches!(
            ensure_autonomous_validation_snapshot(
                &locked,
                &locked.proposed_query,
                &changed,
                proposal_id,
            ),
            Err(AtomicProposalApplyError::AutonomousValidationRejected { .. })
        ));

        let mut changed = proof.clone();
        changed.schedule_cron = "0 * * * *".to_string();
        assert!(ensure_autonomous_validation_snapshot(
            &locked,
            &locked.proposed_query,
            &changed,
            proposal_id,
        )
        .is_err());

        let mut changed = proof.clone();
        changed.dataset = "spans".to_string();
        assert!(ensure_autonomous_validation_snapshot(
            &locked,
            &locked.proposed_query,
            &changed,
            proposal_id,
        )
        .is_err());

        assert!(ensure_autonomous_validation_snapshot(
            &locked,
            "a different mutation payload",
            &proof,
            proposal_id,
        )
        .is_err());
    }

    #[test]
    fn persisted_validation_binding_requires_exact_proof_counts_and_preservation() {
        let locked = locked_fixture("proposed", "base query", "base query");
        let proof = valid_proof(&locked);
        let proposal_id = Uuid::now_v7();
        let mut persisted = LockedPersistedValidation {
            original_alert_count: 100,
            tuned_alert_count: 50,
            reduction_percentage: 50.0,
            true_positives_preserved: true,
            validation_passed: true,
            validation_proof: Some(serde_json::to_value(&proof).unwrap()),
        };
        assert!(ensure_persisted_validation_binding(&persisted, &proof, proposal_id).is_ok());

        persisted.tuned_alert_count = 49;
        assert!(matches!(
            ensure_persisted_validation_binding(&persisted, &proof, proposal_id),
            Err(AtomicProposalApplyError::AutonomousValidationRejected { .. })
        ));
        persisted.tuned_alert_count = 50;
        persisted.true_positives_preserved = false;
        assert!(ensure_persisted_validation_binding(&persisted, &proof, proposal_id).is_err());
    }

    #[test]
    fn autonomous_query_policy_rejects_non_executable_or_non_scheduled_rules() {
        let proposal_id = Uuid::now_v7();
        let mutation = ProposalRuleMutation::Query {
            query: "tuned query".to_string(),
            created_by: None,
            change_reason: "test".to_string(),
        };

        let mut locked = locked_fixture("proposed", "base query", "base query");
        locked.rule_mode = "staging".to_string();
        assert!(ensure_autonomous_policy(&locked, &mutation, proposal_id).is_err());

        let mut locked = locked_fixture("proposed", "base query", "base query");
        locked.rule_archived = true;
        assert!(ensure_autonomous_policy(&locked, &mutation, proposal_id).is_err());

        let mut locked = locked_fixture("proposed", "base query", "base query");
        locked.rule_detection_mode = "real-time".to_string();
        assert!(ensure_autonomous_policy(&locked, &mutation, proposal_id).is_err());

        let mut locked = locked_fixture("proposed", "base query", "base query");
        locked.rule_lookback_minutes = None;
        assert!(ensure_autonomous_policy(&locked, &mutation, proposal_id).is_err());
    }

    #[test]
    fn autonomous_hint_apply_honors_the_rule_tuning_stop_controls() {
        let mut locked = locked_fixture("proposed", "same query", "same query");
        locked.rule_auto_tuning_enabled = false;
        assert!(matches!(
            ensure_autonomous_policy(&locked, &ProposalRuleMutation::Hints, Uuid::now_v7()),
            Err(AtomicProposalApplyError::AutonomousPolicyRejected { .. })
        ));
    }
}
