// SPDX-License-Identifier: AGPL-3.0-or-later

//! Proposal operations for the tuning repository.

use super::{ProposalHistorySummary, TuningRepository};
use crate::detection_code_target::DetectionCodePushService;
use crate::models::detection_rule::DetectionRule;
use crate::models::AiTriageHints;
use crate::tuning::scope::TuningScope;
use crate::tuning::types::{HintsDiff, ProposalType, TuningProposal, TuningStatus};
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use sqlx::Row;
use thiserror::Error;
use uuid::Uuid;

const PR_OPERATION_LEASE_MINUTES: i64 = 5;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrApprovalProvenance {
    pub actor_user_id: Option<Uuid>,
    pub api_key_id: Option<Uuid>,
    pub api_key_name: Option<String>,
    pub validation_skipped: bool,
    pub reason: Option<String>,
}

impl PrApprovalProvenance {
    pub fn automated() -> Self {
        Self {
            actor_user_id: None,
            api_key_id: None,
            api_key_name: None,
            validation_skipped: false,
            reason: None,
        }
    }

    fn validate(&self, proposal_id: Uuid) -> std::result::Result<(), PrOperationError> {
        if self.validation_skipped && self.actor_user_id.is_none() {
            return Err(PrOperationError::InvalidMetadata {
                proposal_id,
                reason: "validation override has no durable authorizing actor".to_string(),
            });
        }
        if self.validation_skipped
            && self
                .reason
                .as_deref()
                .map(str::trim)
                .filter(|reason| !reason.is_empty())
                .is_none()
        {
            return Err(PrOperationError::InvalidMetadata {
                proposal_id,
                reason: "validation override has no durable approval reason".to_string(),
            });
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FrozenPrOperation {
    pub proposal_id: Uuid,
    pub target_id: Uuid,
    pub repo_url: String,
    pub base_branch: String,
    pub path_template: String,
    pub rule_format: String,
    pub branch: String,
    pub effective_query: String,
    pub original_query: String,
    pub rationale: String,
    pub confidence_score: f64,
    pub changes_summary: Vec<String>,
    pub rule: DetectionRule,
    #[serde(default)]
    pub approval_provenance: Option<PrApprovalProvenance>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrDestinationPayload {
    pub file_path: String,
    pub file_content: String,
    pub commit_message: String,
    pub title: String,
    pub body: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrOperationPhase {
    Claimed,
    DestinationReady,
    BranchReady,
    CommitReady,
    PrReady,
    Completed,
    Cancelled,
}

impl PrOperationPhase {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Claimed => "claimed",
            Self::DestinationReady => "destination_ready",
            Self::BranchReady => "branch_ready",
            Self::CommitReady => "commit_ready",
            Self::PrReady => "pr_ready",
            Self::Completed => "completed",
            Self::Cancelled => "cancelled",
        }
    }

    fn parse(proposal_id: Uuid, value: &str) -> std::result::Result<Self, PrOperationError> {
        match value {
            "claimed" => Ok(Self::Claimed),
            "destination_ready" => Ok(Self::DestinationReady),
            "branch_ready" => Ok(Self::BranchReady),
            "commit_ready" => Ok(Self::CommitReady),
            "pr_ready" => Ok(Self::PrReady),
            "completed" => Ok(Self::Completed),
            "cancelled" => Ok(Self::Cancelled),
            _ => Err(PrOperationError::InvalidMetadata {
                proposal_id,
                reason: format!("unknown PR operation phase '{value}'"),
            }),
        }
    }
}

/// Durable external-effect provenance loaded with a fenced PR claim.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrOperationCheckpoint {
    pub phase: PrOperationPhase,
    pub branch_sha: Option<String>,
    pub commit_sha: Option<String>,
    pub pr_url: Option<String>,
    pub pr_number: Option<i32>,
    pub pr_state: Option<String>,
}

impl PrOperationCheckpoint {
    fn validate(
        self,
        proposal_id: Uuid,
        destination_frozen: bool,
    ) -> std::result::Result<Self, PrOperationError> {
        let invalid = if self.phase >= PrOperationPhase::PrReady
            && (self.pr_url.is_none() || self.pr_number.is_none() || self.pr_state.is_none())
        {
            Some("PR-ready phase has no complete PR identity")
        } else if self.phase >= PrOperationPhase::CommitReady && self.commit_sha.is_none() {
            Some("commit-ready phase has no commit SHA")
        } else if self.phase >= PrOperationPhase::BranchReady && self.branch_sha.is_none() {
            Some("branch-ready phase has no branch SHA")
        } else if self.phase >= PrOperationPhase::DestinationReady && !destination_frozen {
            Some("destination-ready phase has no frozen destination")
        } else {
            None
        };
        if let Some(reason) = invalid {
            return Err(PrOperationError::InvalidMetadata {
                proposal_id,
                reason: reason.to_string(),
            });
        }
        Ok(self)
    }
}

#[derive(Debug, Clone)]
pub enum PrOperationClaim {
    Claimed {
        resumed: bool,
        attempt: i32,
        operation: FrozenPrOperation,
        destination: Option<PrDestinationPayload>,
        checkpoint: PrOperationCheckpoint,
    },
    AlreadyOpened {
        url: String,
        number: i32,
        state: String,
        effective_query: String,
    },
}

#[derive(Debug, Error)]
pub enum PrOperationError {
    #[error("tuning proposal not found: {0}")]
    ProposalNotFound(Uuid),
    #[error("tuning proposal {proposal_id} cannot start a PR operation from status '{status}'")]
    InvalidState { proposal_id: Uuid, status: String },
    #[error("tuning proposal {0} already has an active PR operation")]
    InProgress(Uuid),
    #[error("tuning proposal {proposal_id} is stale because rule {rule_id} changed after it was generated")]
    StaleRuleBase { proposal_id: Uuid, rule_id: Uuid },
    #[error("tuning proposal {proposal_id} has incompatible PR operation metadata: {reason}")]
    InvalidMetadata { proposal_id: Uuid, reason: String },
    #[error("database error while transitioning tuning PR operation: {0}")]
    Database(#[from] sqlx::Error),
}

impl TuningRepository {
    /// Create a new tuning proposal
    ///
    /// # Arguments
    /// * `proposal` - The tuning proposal to create
    pub async fn create_proposal(&self, proposal: &TuningProposal) -> Result<()> {
        let affected_patterns_json = serde_json::to_value(&proposal.affected_patterns)
            .context("Failed to serialize affected patterns")?;

        let safety_validation_json = serde_json::to_value(&proposal.safety_validation)
            .context("Failed to serialize safety validation")?;

        let current_hints_json = proposal
            .current_hints
            .as_ref()
            .map(|h| serde_json::to_value(h))
            .transpose()
            .context("Failed to serialize current hints")?;

        let proposed_hints_json = proposal
            .proposed_hints
            .as_ref()
            .map(|h| serde_json::to_value(h))
            .transpose()
            .context("Failed to serialize proposed hints")?;

        let hints_diff_json = proposal
            .hints_diff
            .as_ref()
            .map(|d| serde_json::to_value(d))
            .transpose()
            .context("Failed to serialize hints diff")?;

        let changes_summary_json = serde_json::to_value(&proposal.changes_summary)
            .context("Failed to serialize changes summary")?;

        // NAN-2085 / NAN-2088: normalize the producer's manifest here as well
        // as at the producer, so a caller that hand-builds a `TuningProposal`
        // cannot store un-normalized values that would silently fail the
        // read-side overlap test (i.e. fail OPEN).
        let source_types = crate::tuning::scope::normalize_source_manifest(&proposal.source_types);

        sqlx::query(
            r#"
            INSERT INTO tuning_proposals (
                id,
                rule_id,
                created_at,
                proposal_type,
                original_query,
                proposed_query,
                rationale,
                confidence_score,
                changes_summary,
                affected_patterns,
                safety_validation,
                status,
                current_hints,
                proposed_hints,
                hints_diff,
                source_types,
                source_types_complete
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17)
            "#,
        )
        .bind(&proposal.id)
        .bind(&proposal.rule_id)
        .bind(&proposal.created_at)
        .bind(proposal.proposal_type.to_string())
        .bind(&proposal.original_query)
        .bind(&proposal.proposed_query)
        .bind(&proposal.rationale)
        .bind(proposal.confidence_score)
        .bind(changes_summary_json)
        .bind(affected_patterns_json)
        .bind(safety_validation_json)
        .bind(proposal.status.to_string())
        .bind(current_hints_json)
        .bind(proposed_hints_json)
        .bind(hints_diff_json)
        .bind(&source_types)
        // An empty manifest can never be "complete" — that combination is the
        // pre-feature default and must keep denying restricted readers.
        .bind(proposal.source_types_complete && !source_types.is_empty())
        .execute(&self.pool)
        .await
        .context(format!(
            "Failed to create tuning proposal for rule_id={}, proposal_id={}",
            proposal.rule_id, proposal.id
        ))?;

        Ok(())
    }

    /// Return the target frozen by an in-flight PR claim. Recovery must use
    /// this exact target even if a different target became active meanwhile.
    pub async fn get_pr_operation_target_id(&self, proposal_id: Uuid) -> Result<Option<Uuid>> {
        let target: Option<(Option<Uuid>, Option<String>)> = sqlx::query_as(
            r#"
                SELECT pr_target_id, pr_operation_snapshot->>'target_id'
                FROM tuning_proposals WHERE id = $1
                "#,
        )
        .bind(proposal_id)
        .fetch_optional(&self.pool)
        .await
        .context("Failed to load tuning PR operation target")?;
        Ok(match target {
            Some((Some(target_id), _)) => Some(target_id),
            Some((None, Some(snapshot_target_id))) => Uuid::parse_str(&snapshot_target_id).ok(),
            Some((None, None)) | None => None,
        })
    }

    /// Oldest-expired-first recovery queue. Returning only expired leases keeps
    /// active workers out of the recovery batch, and the stable `(lease, id)`
    /// order prevents newer proposals from starving an older interrupted one.
    pub async fn list_recoverable_pr_operation_ids(&self, limit: i64) -> Result<Vec<Uuid>> {
        sqlx::query_scalar(
            r#"
            SELECT id
            FROM tuning_proposals
            WHERE status = 'pr_pending'
              AND (
                  pr_operation_started_at IS NULL
                  OR pr_operation_started_at <= NOW() - ($1 * INTERVAL '1 minute')
              )
            ORDER BY pr_operation_started_at ASC NULLS FIRST, id ASC
            LIMIT $2
            "#,
        )
        .bind(PR_OPERATION_LEASE_MINUTES)
        .bind(limit.clamp(1, 1_000))
        .fetch_all(&self.pool)
        .await
        .context("Failed to list recoverable tuning PR operations")
    }

    /// Move an expired candidate to the back of the recovery queue when it
    /// failed before `claim_pr_operation` could renew its lease. The expiry
    /// predicate prevents a delayed worker from touching a newer active claim.
    pub async fn defer_expired_pr_operation_recovery(
        &self,
        proposal_id: Uuid,
        error: &str,
    ) -> Result<bool> {
        let error: String = error.chars().take(1000).collect();
        let deferred = sqlx::query(
            r#"
            UPDATE tuning_proposals
            SET pr_operation_started_at = NOW(),
                pr_last_error = $1
            WHERE id = $2
              AND status = 'pr_pending'
              AND (
                  pr_operation_started_at IS NULL
                  OR pr_operation_started_at <= NOW() - ($3 * INTERVAL '1 minute')
              )
            "#,
        )
        .bind(error)
        .bind(proposal_id)
        .bind(PR_OPERATION_LEASE_MINUTES)
        .execute(&self.pool)
        .await
        .context("Failed to defer expired tuning PR recovery")?;
        Ok(deferred.rows_affected() == 1)
    }

    /// Persist a retryable failure against the current fenced attempt while
    /// keeping the operation pending. A stale worker cannot overwrite the
    /// diagnostics or renew the lease of a newer claimant.
    pub async fn record_pr_operation_error(
        &self,
        proposal_id: Uuid,
        branch: &str,
        attempt: i32,
        error: &str,
    ) -> std::result::Result<bool, PrOperationError> {
        let error: String = error.chars().take(1000).collect();
        let recorded = sqlx::query(
            r#"
            UPDATE tuning_proposals
            SET pr_operation_started_at = NOW(),
                pr_last_error = $1
            WHERE id = $2
              AND status = 'pr_pending'
              AND pr_branch = $3
              AND pr_attempt_count = $4
            "#,
        )
        .bind(error)
        .bind(proposal_id)
        .bind(branch)
        .bind(attempt)
        .execute(&self.pool)
        .await?;
        Ok(recorded.rows_affected() == 1)
    }

    /// Claim the deterministic GitHub side effect before making a network call.
    /// An expired `pr_pending` lease can be reclaimed so a crash between GitHub
    /// and PostgreSQL is resumable.
    pub async fn claim_pr_operation(
        &self,
        proposal_id: Uuid,
        target_id: Uuid,
        query: &str,
    ) -> std::result::Result<PrOperationClaim, PrOperationError> {
        self.claim_pr_operation_with_provenance(
            proposal_id,
            target_id,
            query,
            PrApprovalProvenance::automated(),
            // Automated claim: a background actor with no viewer.
            &TuningScope::system(),
        )
        .await
    }

    /// Claim a manual PR operation while freezing the authorizing actor and any
    /// validation override. Recovery must never infer these from a later retry.
    ///
    /// NAN-2085 / NAN-2088: `scope` is the ACTOR's deny scope, re-checked under
    /// the same row lock that freezes the claim. The returned
    /// `FrozenPrOperation` carries the proposal's `rationale` /
    /// `changes_summary` / both queries and ends up in a GitHub PR body, so a
    /// proposal re-stamped onto a denied source after the handler's preflight
    /// read must not be claimable. Reported as `ProposalNotFound`, identical to
    /// a missing proposal.
    pub async fn claim_pr_operation_with_provenance(
        &self,
        proposal_id: Uuid,
        target_id: Uuid,
        query: &str,
        approval_provenance: PrApprovalProvenance,
        scope: &TuningScope,
    ) -> std::result::Result<PrOperationClaim, PrOperationError> {
        approval_provenance.validate(proposal_id)?;
        let mut tx = self.pool.begin().await?;
        let row = sqlx::query(
            r#"
            SELECT
                tp.rule_id,
                COALESCE(tp.proposal_type, 'query_tuning') AS proposal_type,
                tp.status,
                tp.source_types,
                tp.source_types_complete,
                tp.original_query,
                tp.rationale,
                tp.confidence_score,
                tp.changes_summary,
                tp.pr_target_id,
                tp.pr_branch,
                tp.pr_operation_query,
                tp.pr_operation_snapshot,
                tp.pr_destination_payload,
                tp.pr_operation_phase,
                tp.pr_branch_sha,
                tp.pr_commit_sha,
                tp.pr_url,
                tp.pr_number,
                tp.pr_state,
                (
                    tp.pr_operation_started_at IS NULL
                    OR tp.pr_operation_started_at <= NOW() - ($2 * INTERVAL '1 minute')
                ) AS lease_expired,
                dr.query AS current_query,
                dr.name AS rule_name
            FROM tuning_proposals tp
            JOIN detection_rules dr ON dr.id = tp.rule_id
            WHERE tp.id = $1
            FOR UPDATE OF tp, dr
            "#,
        )
        .bind(proposal_id)
        .bind(PR_OPERATION_LEASE_MINUTES)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or(PrOperationError::ProposalNotFound(proposal_id))?;

        let rule_id: Uuid = row.try_get("rule_id")?;
        // NAN-2085 / NAN-2088: authorize the CURRENT provenance under the lock.
        let source_types: Vec<String> = row.try_get("source_types")?;
        let source_types_complete: bool = row.try_get("source_types_complete")?;
        if !scope.allows(&source_types, source_types_complete) {
            tx.rollback().await?;
            return Err(PrOperationError::ProposalNotFound(proposal_id));
        }
        let proposal_type: String = row.try_get("proposal_type")?;
        let status: String = row.try_get("status")?;
        let original_query: String = row.try_get("original_query")?;
        let rationale: String = row.try_get("rationale")?;
        let confidence_score: f64 = row.try_get("confidence_score")?;
        let changes_summary: serde_json::Value = row.try_get("changes_summary")?;
        let current_query: String = row.try_get("current_query")?;
        let rule_name: String = row.try_get("rule_name")?;
        let stored_target_id: Option<Uuid> = row.try_get("pr_target_id")?;
        let stored_branch: Option<String> = row.try_get("pr_branch")?;
        let stored_query: Option<String> = row.try_get("pr_operation_query")?;
        let stored_snapshot: Option<serde_json::Value> = row.try_get("pr_operation_snapshot")?;
        let stored_destination: Option<serde_json::Value> =
            row.try_get("pr_destination_payload")?;
        let stored_phase: Option<String> = row.try_get("pr_operation_phase")?;
        let stored_branch_sha: Option<String> = row.try_get("pr_branch_sha")?;
        let stored_commit_sha: Option<String> = row.try_get("pr_commit_sha")?;
        let lease_expired: bool = row.try_get("lease_expired")?;

        if status == "pr_opened" {
            let url: Option<String> = row.try_get("pr_url")?;
            let number: Option<i32> = row.try_get("pr_number")?;
            let state: Option<String> = row.try_get("pr_state")?;
            let effective_query = stored_snapshot
                .and_then(|value| serde_json::from_value::<FrozenPrOperation>(value).ok())
                .map(|operation| operation.effective_query)
                .or(stored_query);
            return match (url, number, effective_query) {
                (Some(url), Some(number), Some(effective_query)) => {
                    let updated = sqlx::query(
                        "UPDATE tuning_logs SET status = 'pr_opened' WHERE proposal_id = $1",
                    )
                    .bind(proposal_id)
                    .execute(&mut *tx)
                    .await?;
                    if updated.rows_affected() == 0 {
                        sqlx::query(
                            r#"
                            INSERT INTO tuning_logs (
                                id, rule_id, rule_name, triggered_at, trigger_reason,
                                proposal_id, status
                            )
                            VALUES ($1, $2, $3, NOW(), $4, $5, 'pr_opened')
                            "#,
                        )
                        .bind(Uuid::now_v7())
                        .bind(rule_id)
                        .bind(rule_name)
                        .bind("Reconciled an already-open Detection-as-Code PR")
                        .bind(proposal_id)
                        .execute(&mut *tx)
                        .await?;
                    }
                    tx.commit().await?;
                    Ok(PrOperationClaim::AlreadyOpened {
                        url,
                        number,
                        state: state.unwrap_or_else(|| "open".to_string()),
                        effective_query,
                    })
                }
                _ => {
                    tx.rollback().await?;
                    Err(PrOperationError::InvalidMetadata {
                        proposal_id,
                        reason: "pr_opened proposal has no URL/number/effective query".to_string(),
                    })
                }
            };
        }

        if proposal_type != "query_tuning" && proposal_type != "silent_rule" {
            return Err(PrOperationError::InvalidMetadata {
                proposal_id,
                reason: format!("proposal type '{proposal_type}' cannot open a PR"),
            });
        }

        let (resumed, operation_query) = if status == "pr_pending" {
            if stored_target_id != Some(target_id) {
                return Err(PrOperationError::InvalidMetadata {
                    proposal_id,
                    reason: format!(
                        "claimed target '{}' does not match retry target '{target_id}'",
                        stored_target_id
                            .map(|id| id.to_string())
                            .unwrap_or_else(|| "<missing>".to_string())
                    ),
                });
            }
            if !lease_expired {
                tx.rollback().await?;
                return Err(PrOperationError::InProgress(proposal_id));
            }
            let stored_query = stored_query.ok_or_else(|| PrOperationError::InvalidMetadata {
                proposal_id,
                reason: "pr_pending proposal has no frozen query".to_string(),
            })?;
            (true, stored_query)
        } else if status == "proposed" || status == "test_passed" {
            if current_query != original_query {
                return Err(PrOperationError::StaleRuleBase {
                    proposal_id,
                    rule_id,
                });
            }
            if let Some(stored_target_id) = stored_target_id {
                if stored_target_id != target_id {
                    return Err(PrOperationError::InvalidMetadata {
                        proposal_id,
                        reason: format!(
                            "prior target '{stored_target_id}' does not match retry target '{target_id}'"
                        ),
                    });
                }
                let stored_query =
                    stored_query.ok_or_else(|| PrOperationError::InvalidMetadata {
                        proposal_id,
                        reason: "retried proposal has no frozen query".to_string(),
                    })?;
                (true, stored_query)
            } else {
                (false, query.to_string())
            }
        } else {
            return Err(PrOperationError::InvalidState {
                proposal_id,
                status,
            });
        };

        let target = sqlx::query(
            r#"
            SELECT repo_url, base_branch, path_template, pr_branch_prefix, rule_format
            FROM detection_code_targets
            WHERE id = $1
            FOR UPDATE
            "#,
        )
        .bind(target_id)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or_else(|| PrOperationError::InvalidMetadata {
            proposal_id,
            reason: format!("claimed target '{target_id}' no longer exists"),
        })?;

        let operation = if let Some(snapshot) = stored_snapshot {
            let operation: FrozenPrOperation =
                serde_json::from_value(snapshot).map_err(|error| {
                    PrOperationError::InvalidMetadata {
                        proposal_id,
                        reason: format!("cannot decode frozen PR operation: {error}"),
                    }
                })?;
            if operation.target_id != target_id || operation.effective_query != operation_query {
                return Err(PrOperationError::InvalidMetadata {
                    proposal_id,
                    reason: "frozen PR operation disagrees with claimed metadata".to_string(),
                });
            }
            let provenance = operation.approval_provenance.as_ref().ok_or_else(|| {
                PrOperationError::InvalidMetadata {
                    proposal_id,
                    reason: "frozen PR operation has no durable approval provenance".to_string(),
                }
            })?;
            provenance.validate(proposal_id)?;
            operation
        } else {
            let frozen_rule: DetectionRule =
                sqlx::query_as("SELECT * FROM detection_rules WHERE id = $1")
                    .bind(rule_id)
                    .fetch_one(&mut *tx)
                    .await?;
            // F-38: reject a malformed composed head branch when the frozen PR
            // operation is first minted, so a bad `pr_branch_prefix` never
            // reaches GitHub as a doomed ref.
            let branch = DetectionCodePushService::branch_for_identity(
                target.try_get("pr_branch_prefix")?,
                &frozen_rule.name,
                proposal_id,
            )
            .map_err(|error| PrOperationError::InvalidMetadata {
                proposal_id,
                reason: format!("composed PR branch is not a valid git ref: {error}"),
            })?;
            FrozenPrOperation {
                proposal_id,
                target_id,
                repo_url: target.try_get("repo_url")?,
                base_branch: target.try_get("base_branch")?,
                path_template: target.try_get("path_template")?,
                rule_format: target.try_get("rule_format")?,
                branch,
                effective_query: operation_query.clone(),
                original_query: original_query.clone(),
                rationale,
                confidence_score,
                changes_summary: serde_json::from_value(changes_summary).map_err(|error| {
                    PrOperationError::InvalidMetadata {
                        proposal_id,
                        reason: format!("cannot decode proposal changes: {error}"),
                    }
                })?,
                rule: frozen_rule,
                approval_provenance: Some(approval_provenance),
            }
        };
        if stored_branch
            .as_deref()
            .is_some_and(|branch| branch != operation.branch)
        {
            return Err(PrOperationError::InvalidMetadata {
                proposal_id,
                reason: "stored branch disagrees with frozen PR operation".to_string(),
            });
        }
        let destination = stored_destination
            .map(|value| {
                serde_json::from_value(value).map_err(|error| PrOperationError::InvalidMetadata {
                    proposal_id,
                    reason: format!("cannot decode frozen PR destination: {error}"),
                })
            })
            .transpose()?;
        let checkpoint = PrOperationCheckpoint {
            phase: stored_phase
                .as_deref()
                .map(|phase| PrOperationPhase::parse(proposal_id, phase))
                .transpose()?
                .unwrap_or(if destination.is_some() {
                    PrOperationPhase::DestinationReady
                } else {
                    PrOperationPhase::Claimed
                }),
            branch_sha: stored_branch_sha,
            commit_sha: stored_commit_sha,
            pr_url: row.try_get("pr_url")?,
            pr_number: row.try_get("pr_number")?,
            pr_state: row.try_get("pr_state")?,
        }
        .validate(proposal_id, destination.is_some())?;
        if matches!(
            checkpoint.phase,
            PrOperationPhase::Completed | PrOperationPhase::Cancelled
        ) {
            return Err(PrOperationError::InvalidMetadata {
                proposal_id,
                reason: format!(
                    "actionable proposal has terminal PR operation phase '{}'",
                    checkpoint.phase.as_str()
                ),
            });
        }

        // NAN-1766 (D6): a reclaimed lease still at the `Claimed` phase has
        // produced zero external effects (no frozen destination, branch, commit,
        // or PR), so the frozen query can still be safely abandoned if the rule
        // changed under the lease. Fresh claims run this stale-base check before
        // freezing anything; the `pr_pending` reclaim path bypassed it, letting a
        // reclaimed operation open a PR against a query the rule no longer has.
        // Re-run it here, but only at `Claimed`: once the operation has advanced,
        // GitHub-visible artifacts may already exist and rechecking would orphan
        // them, so skipping the recheck there is intentional.
        if status == "pr_pending"
            && checkpoint.phase == PrOperationPhase::Claimed
            && current_query != original_query
        {
            return Err(PrOperationError::StaleRuleBase {
                proposal_id,
                rule_id,
            });
        }

        let snapshot = serde_json::to_value(&operation).map_err(|error| {
            PrOperationError::InvalidMetadata {
                proposal_id,
                reason: format!("cannot encode frozen PR operation: {error}"),
            }
        })?;

        let attempt: i32 = sqlx::query_scalar(
            r#"
            UPDATE tuning_proposals
            SET status = 'pr_pending',
                pr_target_id = $1,
                pr_branch = $2,
                pr_operation_query = $3,
                pr_operation_started_at = NOW(),
                pr_operation_completed_at = NULL,
                pr_attempt_count = pr_attempt_count + 1,
                pr_last_error = NULL,
                pr_operation_snapshot = COALESCE(pr_operation_snapshot, $4),
                pr_operation_phase = COALESCE(
                    pr_operation_phase,
                    CASE
                        WHEN pr_destination_payload IS NULL THEN 'claimed'
                        ELSE 'destination_ready'
                    END
                ),
                pr_phase_updated_at = COALESCE(pr_phase_updated_at, NOW())
            WHERE id = $5 AND status = $6
            RETURNING pr_attempt_count
            "#,
        )
        .bind(target_id)
        .bind(&operation.branch)
        .bind(&operation_query)
        .bind(snapshot)
        .bind(proposal_id)
        .bind(&status)
        .fetch_one(&mut *tx)
        .await?;

        let updated_logs =
            sqlx::query("UPDATE tuning_logs SET status = 'pr_pending' WHERE proposal_id = $1")
                .bind(proposal_id)
                .execute(&mut *tx)
                .await?;
        if updated_logs.rows_affected() == 0 {
            sqlx::query(
                r#"
                INSERT INTO tuning_logs (
                    id, rule_id, rule_name, triggered_at, trigger_reason,
                    proposal_id, status
                )
                VALUES ($1, $2, $3, NOW(), $4, $5, 'pr_pending')
                "#,
            )
            .bind(Uuid::now_v7())
            .bind(rule_id)
            .bind(rule_name)
            .bind(if resumed && status == "pr_pending" {
                "Detection-as-Code PR operation reclaimed after an expired lease"
            } else if resumed {
                "Detection-as-Code PR operation retried after a failed attempt"
            } else {
                "Detection-as-Code PR operation claimed"
            })
            .bind(proposal_id)
            .execute(&mut *tx)
            .await?;
        }

        tx.commit().await?;
        Ok(PrOperationClaim::Claimed {
            resumed,
            attempt,
            operation,
            destination,
            checkpoint,
        })
    }

    /// Persist the resolved GitHub destination before the first write. A stale
    /// worker cannot replace a destination after another worker reclaims the
    /// lease because the attempt number is fenced.
    pub async fn freeze_pr_destination(
        &self,
        proposal_id: Uuid,
        attempt: i32,
        destination: &PrDestinationPayload,
    ) -> std::result::Result<PrDestinationPayload, PrOperationError> {
        let value = serde_json::to_value(destination).map_err(|error| {
            PrOperationError::InvalidMetadata {
                proposal_id,
                reason: format!("cannot encode PR destination: {error}"),
            }
        })?;
        let stored: Option<serde_json::Value> = sqlx::query_scalar(
            r#"
            UPDATE tuning_proposals
            SET pr_destination_payload = COALESCE(pr_destination_payload, $1),
                pr_operation_phase = CASE
                    WHEN COALESCE(pr_operation_phase, 'claimed') = 'claimed'
                        THEN 'destination_ready'
                    ELSE pr_operation_phase
                END,
                pr_operation_started_at = NOW(),
                pr_phase_updated_at = NOW()
            WHERE id = $2
              AND status = 'pr_pending'
              AND pr_attempt_count = $3
              AND COALESCE(pr_operation_phase, 'claimed') IN (
                  'claimed', 'destination_ready', 'branch_ready',
                  'commit_ready', 'pr_ready'
              )
            RETURNING pr_destination_payload
            "#,
        )
        .bind(value)
        .bind(proposal_id)
        .bind(attempt)
        .fetch_optional(&self.pool)
        .await?;
        let stored = stored.ok_or_else(|| PrOperationError::InvalidState {
            proposal_id,
            status: "claim attempt is no longer current".to_string(),
        })?;
        serde_json::from_value(stored).map_err(|error| PrOperationError::InvalidMetadata {
            proposal_id,
            reason: format!("cannot decode PR destination: {error}"),
        })
    }

    /// Record the deterministic head ref after GitHub confirms it exists. The
    /// SHA is immutable provenance for this operation; a conflicting retry is
    /// rejected instead of silently attaching the proposal to another ref.
    pub async fn checkpoint_pr_branch(
        &self,
        proposal_id: Uuid,
        branch: &str,
        attempt: i32,
        branch_sha: &str,
    ) -> std::result::Result<(), PrOperationError> {
        self.checkpoint_pr_sha(
            proposal_id,
            branch,
            attempt,
            "branch_ready",
            branch_sha,
            true,
        )
        .await
    }

    /// Record the commit containing the exact frozen destination payload.
    pub async fn checkpoint_pr_commit(
        &self,
        proposal_id: Uuid,
        branch: &str,
        attempt: i32,
        commit_sha: &str,
    ) -> std::result::Result<(), PrOperationError> {
        self.checkpoint_pr_sha(
            proposal_id,
            branch,
            attempt,
            "commit_ready",
            commit_sha,
            false,
        )
        .await
    }

    async fn checkpoint_pr_sha(
        &self,
        proposal_id: Uuid,
        branch: &str,
        attempt: i32,
        next_phase: &str,
        sha: &str,
        branch_checkpoint: bool,
    ) -> std::result::Result<(), PrOperationError> {
        let checkpointed = if branch_checkpoint {
            sqlx::query(
                r#"
                UPDATE tuning_proposals
                SET pr_branch_sha = COALESCE(pr_branch_sha, $1),
                    pr_operation_phase = CASE
                        WHEN pr_operation_phase = 'destination_ready' THEN $2
                        ELSE pr_operation_phase
                    END,
                    pr_operation_started_at = NOW(),
                    pr_phase_updated_at = NOW()
                WHERE id = $3
                  AND status = 'pr_pending'
                  AND pr_branch = $4
                  AND pr_attempt_count = $5
                  AND pr_destination_payload IS NOT NULL
                  AND pr_operation_phase IN (
                      'destination_ready', 'branch_ready', 'commit_ready', 'pr_ready'
                  )
                  AND (pr_branch_sha IS NULL OR pr_branch_sha = $1)
                "#,
            )
            .bind(sha)
            .bind(next_phase)
            .bind(proposal_id)
            .bind(branch)
            .bind(attempt)
            .execute(&self.pool)
            .await?
        } else {
            sqlx::query(
                r#"
                UPDATE tuning_proposals
                SET pr_commit_sha = COALESCE(pr_commit_sha, $1),
                    pr_operation_phase = CASE
                        WHEN pr_operation_phase = 'branch_ready' THEN $2
                        ELSE pr_operation_phase
                    END,
                    pr_operation_started_at = NOW(),
                    pr_phase_updated_at = NOW()
                WHERE id = $3
                  AND status = 'pr_pending'
                  AND pr_branch = $4
                  AND pr_attempt_count = $5
                  AND pr_branch_sha IS NOT NULL
                  AND pr_operation_phase IN ('branch_ready', 'commit_ready', 'pr_ready')
                  AND (pr_commit_sha IS NULL OR pr_commit_sha = $1)
                "#,
            )
            .bind(sha)
            .bind(next_phase)
            .bind(proposal_id)
            .bind(branch)
            .bind(attempt)
            .execute(&self.pool)
            .await?
        };
        if checkpointed.rows_affected() == 0 {
            return Err(PrOperationError::InvalidState {
                proposal_id,
                status: format!("cannot record {next_phase} for this claim attempt"),
            });
        }
        Ok(())
    }

    /// Persist the remote PR identity before proposal/log completion. A retry
    /// after a lost database response can rediscover the same head/base PR and
    /// safely replay this fenced checkpoint.
    pub async fn checkpoint_pull_request(
        &self,
        proposal_id: Uuid,
        branch: &str,
        attempt: i32,
        pr_url: &str,
        pr_number: i64,
        pr_state: &str,
    ) -> std::result::Result<(), PrOperationError> {
        let number = i32::try_from(pr_number).map_err(|_| PrOperationError::InvalidMetadata {
            proposal_id,
            reason: format!("GitHub PR number {pr_number} does not fit in PostgreSQL INTEGER"),
        })?;
        let checkpointed = sqlx::query(
            r#"
            UPDATE tuning_proposals
            SET pr_url = COALESCE(pr_url, $1),
                pr_number = COALESCE(pr_number, $2),
                pr_state = $3,
                pr_operation_phase = 'pr_ready',
                pr_operation_started_at = NOW(),
                pr_phase_updated_at = NOW()
            WHERE id = $4
              AND status = 'pr_pending'
              AND pr_branch = $5
              AND pr_attempt_count = $6
              AND pr_commit_sha IS NOT NULL
              AND pr_operation_phase IN ('commit_ready', 'pr_ready')
              AND (pr_url IS NULL OR pr_url = $1)
              AND (pr_number IS NULL OR pr_number = $2)
            "#,
        )
        .bind(pr_url)
        .bind(number)
        .bind(pr_state)
        .bind(proposal_id)
        .bind(branch)
        .bind(attempt)
        .execute(&self.pool)
        .await?;
        if checkpointed.rows_affected() == 0 {
            return Err(PrOperationError::InvalidState {
                proposal_id,
                status: "cannot record pr_ready for this claim attempt".to_string(),
            });
        }
        Ok(())
    }

    /// Reconcile a remotely durable PR when PostgreSQL missed one or more
    /// preceding checkpoint responses. The verified PR head proves the branch
    /// and commit effects; any conflicting commit checkpoint remains fenced.
    pub async fn checkpoint_reconciled_pull_request(
        &self,
        proposal_id: Uuid,
        branch: &str,
        attempt: i32,
        head_sha: &str,
        pr_url: &str,
        pr_number: i64,
        pr_state: &str,
    ) -> std::result::Result<(), PrOperationError> {
        let number = i32::try_from(pr_number).map_err(|_| PrOperationError::InvalidMetadata {
            proposal_id,
            reason: format!("GitHub PR number {pr_number} does not fit in PostgreSQL INTEGER"),
        })?;
        let checkpointed = sqlx::query(
            r#"
            UPDATE tuning_proposals
            SET pr_branch_sha = COALESCE(pr_branch_sha, $1),
                pr_commit_sha = COALESCE(pr_commit_sha, $1),
                pr_url = COALESCE(pr_url, $2),
                pr_number = COALESCE(pr_number, $3),
                pr_state = $4,
                pr_operation_phase = 'pr_ready',
                pr_operation_started_at = NOW(),
                pr_phase_updated_at = NOW()
            WHERE id = $5
              AND status = 'pr_pending'
              AND pr_branch = $6
              AND pr_attempt_count = $7
              AND pr_destination_payload IS NOT NULL
              AND pr_operation_phase IN (
                  'destination_ready', 'branch_ready', 'commit_ready', 'pr_ready'
              )
              AND (pr_commit_sha IS NULL OR pr_commit_sha = $1)
              AND (pr_url IS NULL OR pr_url = $2)
              AND (pr_number IS NULL OR pr_number = $3)
            "#,
        )
        .bind(head_sha)
        .bind(pr_url)
        .bind(number)
        .bind(pr_state)
        .bind(proposal_id)
        .bind(branch)
        .bind(attempt)
        .execute(&self.pool)
        .await?;
        if checkpointed.rows_affected() == 0 {
            return Err(PrOperationError::InvalidState {
                proposal_id,
                status: "cannot reconcile remote PR for this claim attempt".to_string(),
            });
        }
        Ok(())
    }

    /// Complete a claimed PR operation and its tuning log atomically. Repeating
    /// the same completion is idempotent after a lost HTTP response.
    pub async fn complete_pr_operation(
        &self,
        proposal_id: Uuid,
        branch: &str,
        attempt: i32,
        pr_url: &str,
        pr_number: i64,
        pr_state: &str,
        reviewer_notes: Option<&str>,
        approval_provenance: &PrApprovalProvenance,
    ) -> std::result::Result<(), PrOperationError> {
        let pr_number =
            i32::try_from(pr_number).map_err(|_| PrOperationError::InvalidMetadata {
                proposal_id,
                reason: "GitHub PR number does not fit in PostgreSQL INTEGER".to_string(),
            })?;
        approval_provenance.validate(proposal_id)?;
        let approval_provenance = serde_json::to_value(approval_provenance).map_err(|error| {
            PrOperationError::InvalidMetadata {
                proposal_id,
                reason: format!("cannot encode PR approval provenance: {error}"),
            }
        })?;
        let mut tx = self.pool.begin().await?;
        let transitioned = sqlx::query(
            r#"
            UPDATE tuning_proposals
            SET status = 'pr_opened',
                pr_url = $1,
                pr_number = $2,
                pr_state = $3,
                pr_operation_completed_at = NOW(),
                pr_last_error = NULL,
                reviewer_notes = COALESCE($4, reviewer_notes),
                pr_target_id = NULL,
                pr_operation_phase = 'completed',
                pr_phase_updated_at = NOW()
            WHERE id = $5
              AND status = 'pr_pending'
              AND pr_branch = $6
              AND pr_attempt_count = $7
              AND pr_operation_phase = 'pr_ready'
              AND pr_url = $1
              AND pr_number = $2
            "#,
        )
        .bind(pr_url)
        .bind(pr_number)
        .bind(pr_state)
        .bind(reviewer_notes)
        .bind(proposal_id)
        .bind(branch)
        .bind(attempt)
        .execute(&mut *tx)
        .await?;

        if transitioned.rows_affected() == 0 {
            let existing: Option<(
                String,
                Option<String>,
                Option<i32>,
                Option<String>,
                Option<String>,
                i32,
            )> =
                sqlx::query_as(
                    "SELECT status, pr_url, pr_number, pr_state, pr_branch, pr_attempt_count FROM tuning_proposals WHERE id = $1",
                )
                .bind(proposal_id)
                .fetch_optional(&mut *tx)
                .await?;
            return match existing {
                Some((
                    status,
                    Some(url),
                    Some(number),
                    _stored_state,
                    stored_branch,
                    stored_attempt,
                )) if status == "pr_opened"
                    && url == pr_url
                    && number == pr_number
                    && stored_branch.as_deref() == Some(branch)
                    && stored_attempt == attempt =>
                {
                    // GitHub may report the same PR as open, closed, or merged
                    // on a later reconciliation. Accept the same fenced PR
                    // identity and refresh its state.
                    sqlx::query(
                        "UPDATE tuning_proposals
                         SET pr_state = $2,
                             pr_operation_completed_at = NOW(),
                             pr_last_error = NULL,
                             reviewer_notes = COALESCE($3, reviewer_notes),
                             pr_operation_phase = 'completed',
                             pr_phase_updated_at = NOW(),
                             pr_target_id = NULL
                         WHERE id = $1",
                    )
                    .bind(proposal_id)
                    .bind(pr_state)
                    .bind(reviewer_notes)
                    .execute(&mut *tx)
                    .await?;
                    let audited = sqlx::query(
                        "UPDATE tuning_logs
                         SET status = 'pr_opened',
                             pr_approval_provenance = COALESCE(pr_approval_provenance, $2)
                         WHERE proposal_id = $1",
                    )
                    .bind(proposal_id)
                    .bind(&approval_provenance)
                    .execute(&mut *tx)
                    .await?;
                    if audited.rows_affected() == 0 {
                        tx.rollback().await?;
                        return Err(PrOperationError::InvalidState {
                            proposal_id,
                            status: "completed PR operation has no tuning audit row".to_string(),
                        });
                    }
                    tx.commit().await?;
                    Ok(())
                }
                Some((status, _, _, _, _, _)) => {
                    tx.rollback().await?;
                    Err(PrOperationError::InvalidState {
                        proposal_id,
                        status,
                    })
                }
                None => {
                    tx.rollback().await?;
                    Err(PrOperationError::ProposalNotFound(proposal_id))
                }
            };
        }

        let audited = sqlx::query(
            "UPDATE tuning_logs
             SET status = 'pr_opened',
                 pr_approval_provenance = COALESCE(pr_approval_provenance, $2)
             WHERE proposal_id = $1",
        )
            .bind(proposal_id)
            .bind(&approval_provenance)
            .execute(&mut *tx)
            .await?;
        if audited.rows_affected() == 0 {
            tx.rollback().await?;
            return Err(PrOperationError::InvalidState {
                proposal_id,
                status: "PR operation cannot complete without a tuning audit row".to_string(),
            });
        }
        tx.commit().await?;
        Ok(())
    }

    /// Release a failed claimed PR operation back to analyst review. The
    /// attempt fence prevents a delayed worker from releasing a reclaimed or
    /// completed operation.
    pub async fn fail_pr_operation(
        &self,
        proposal_id: Uuid,
        branch: &str,
        attempt: i32,
        error: &str,
    ) -> std::result::Result<bool, PrOperationError> {
        let error: String = error.chars().take(1000).collect();
        let mut tx = self.pool.begin().await?;
        let failed = sqlx::query(
            r#"
            UPDATE tuning_proposals
            SET status = 'proposed',
                pr_operation_completed_at = NOW(),
                pr_last_error = $1
            WHERE id = $2
              AND status = 'pr_pending'
              AND pr_branch = $3
              AND pr_attempt_count = $4
            "#,
        )
        .bind(error)
        .bind(proposal_id)
        .bind(branch)
        .bind(attempt)
        .execute(&mut *tx)
        .await?;
        if failed.rows_affected() == 0 {
            tx.rollback().await?;
            return Ok(false);
        }
        sqlx::query("UPDATE tuning_logs SET status = 'proposed' WHERE proposal_id = $1")
            .bind(proposal_id)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(true)
    }

    /// Cancel an expired PR operation. Active attempts must finish, fail, or
    /// expire before cancellation so a user cannot race a live GitHub write.
    ///
    /// NAN-2085 / NAN-2088: `scope` is the ACTOR's deny scope, applied inside
    /// the cancelling UPDATE for the same reason as
    /// [`Self::transition_proposal_status`] — the preflight read cannot be
    /// trusted across a concurrent provenance re-stamp.
    pub async fn cancel_expired_pr_operation(
        &self,
        proposal_id: Uuid,
        reason: &str,
        scope: &TuningScope,
    ) -> std::result::Result<bool, PrOperationError> {
        let mut sql = String::from(
            r#"
            UPDATE tuning_proposals
            SET status = 'rejected',
                reviewer_notes = $1,
                pr_operation_completed_at = NOW(),
                pr_target_id = NULL,
                pr_operation_phase = 'cancelled',
                pr_phase_updated_at = NOW()
            WHERE id = $2
              AND status = 'pr_pending'
              AND (
                  pr_operation_started_at IS NULL
                  OR pr_operation_started_at <= NOW() - ($3 * INTERVAL '1 minute')
              )
            "#,
        );
        let scoped = !scope.is_unrestricted();
        if scoped {
            sql.push_str(&TuningScope::sql_predicate(
                "source_types",
                "source_types_complete",
                4,
            ));
        }

        let mut tx = self.pool.begin().await?;
        let mut update = sqlx::query(&sql)
            .bind(reason)
            .bind(proposal_id)
            .bind(PR_OPERATION_LEASE_MINUTES);
        if scoped {
            update = update.bind(scope.deny_bind_values().to_vec());
        }
        let cancelled = update.execute(&mut *tx).await?;
        if cancelled.rows_affected() == 0 {
            tx.rollback().await?;
            return Ok(false);
        }
        sqlx::query("UPDATE tuning_logs SET status = 'rejected' WHERE proposal_id = $1")
            .bind(proposal_id)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(true)
    }

    /// Whether a detection-as-code tuning PR was opened for `rule_id` within the
    /// last 7 days (NAN-1745). Used to avoid spamming duplicate PRs when a noisy
    /// rule keeps breaching before the earlier PR is reviewed. The window bounds
    /// suppression since v1 does not sync PR merge/close state back.
    pub async fn has_recent_pr_for_rule(&self, rule_id: Uuid) -> Result<bool> {
        let exists: bool = sqlx::query_scalar(
            r#"
            SELECT EXISTS (
                SELECT 1 FROM tuning_proposals
                WHERE rule_id = $1
                  AND status = 'pr_opened'
                  AND created_at > NOW() - INTERVAL '7 days'
            )
            "#,
        )
        .bind(rule_id)
        .fetch_one(&self.pool)
        .await
        .context("Failed to check for recent tuning PR")?;
        Ok(exists)
    }

    /// Upgrade an open silent-rule proposal in place when the rule crosses to
    /// a higher tier (NAN-880). Updates the descriptive fields without
    /// resetting `created_at`, so the analyst sees how long the rule has been
    /// queued and that it just escalated.
    ///
    /// Returns `false` when another actor actioned the proposal first.
    ///
    /// NAN-2088: the upgraded `rationale` / `changes_summary` are re-derived
    /// from FRESH source telemetry, so the origin manifest is rewritten in the
    /// same statement. Leaving the old stamp would let a proposal whose text
    /// now describes a newly-restricted source keep the previous (permissive)
    /// provenance.
    pub async fn upgrade_silent_proposal(
        &self,
        proposal_id: Uuid,
        rationale: &str,
        confidence_score: f64,
        changes_summary: &[String],
        source_types: &[String],
        source_types_complete: bool,
    ) -> Result<bool> {
        let changes_summary_json =
            serde_json::to_value(changes_summary).context("Failed to serialize changes summary")?;
        let source_types = crate::tuning::scope::normalize_source_manifest(source_types);

        let result = sqlx::query(
            r#"
            UPDATE tuning_proposals
            SET rationale = $1,
                confidence_score = $2,
                changes_summary = $3,
                source_types = $5,
                source_types_complete = $6
            WHERE id = $4 AND status IN ('proposed', 'test_passed')
            "#,
        )
        .bind(rationale)
        .bind(confidence_score)
        .bind(changes_summary_json)
        .bind(proposal_id)
        .bind(&source_types)
        .bind(source_types_complete && !source_types.is_empty())
        .execute(&self.pool)
        .await
        .context("Failed to upgrade silent proposal")?;

        Ok(result.rows_affected() == 1)
    }

    /// List tuning proposals with optional filters
    ///
    /// # Arguments
    /// * `rule_id` - Optional rule ID filter
    /// * `status` - Optional status filter
    /// * `proposal_type` - Optional proposal type filter
    /// * `limit` - Maximum number of proposals to return
    /// * `offset` - Offset for pagination
    /// * `scope` - the READER's effective per-source deny scope (NAN-2085 /
    ///   NAN-2088). Proposals whose origin manifest overlaps it — and every
    ///   proposal whose provenance is not COMPLETE — are excluded in SQL, so a
    ///   restricted reader never receives derived values from a denied source
    ///   and a source restricted after generation revokes access on the next
    ///   read. Background/system callers pass [`TuningScope::system`].
    ///
    /// # Returns
    /// Vector of tuning proposals matching the filters
    pub async fn list_proposals(
        &self,
        rule_id: Option<Uuid>,
        status: Option<TuningStatus>,
        proposal_type: Option<ProposalType>,
        limit: i64,
        offset: i64,
        scope: &TuningScope,
    ) -> Result<Vec<TuningProposal>> {
        // NAN-963: LEFT JOIN rules so the queue UI can render the rule
        // name without falling back to a truncated UUID. LEFT (not INNER)
        // so proposals against archived / deleted rules still surface.
        let mut query = String::from(
            r#"
            SELECT
                tp.id,
                tp.rule_id,
                r.name as rule_name,
                tp.created_at,
                COALESCE(tp.proposal_type, 'query_tuning') as proposal_type,
                tp.original_query,
                COALESCE(
                    tp.pr_operation_snapshot->>'effective_query',
                    tp.proposed_query
                ) AS proposed_query,
                tp.rationale,
                tp.confidence_score,
                tp.changes_summary,
                tp.affected_patterns,
                tp.safety_validation,
                tp.status,
                tp.current_hints,
                tp.proposed_hints,
                tp.hints_diff,
                tp.pr_url,
                tp.pr_number,
                tp.pr_state,
                tp.source_types,
                tp.source_types_complete
            FROM tuning_proposals tp
            LEFT JOIN detection_rules r ON r.id = tp.rule_id
            WHERE 1=1
            "#,
        );

        // Typed filter bindings. `rule_id` MUST bind as a real `Uuid`: binding
        // it as a String makes Postgres compare `uuid = text` and the whole
        // query errors out, which is why `?rule_id=` used to 500 (caught by
        // `tuning_proposal_scope_integration`). `status` / `proposal_type` are
        // genuinely text columns.
        enum ListBinding {
            RuleId(Uuid),
            Text(String),
        }

        let mut bindings: Vec<ListBinding> = vec![];
        let mut param_count = 1;

        // Column prefixes (`tp.`) required now that `rules` is joined —
        // bare names would be ambiguous.
        if let Some(rid) = rule_id {
            query.push_str(&format!(" AND tp.rule_id = ${}", param_count));
            bindings.push(ListBinding::RuleId(rid));
            param_count += 1;
        }

        if let Some(s) = status {
            query.push_str(&format!(" AND tp.status = ${}", param_count));
            bindings.push(ListBinding::Text(s.to_string()));
            param_count += 1;
        }

        if let Some(pt) = proposal_type {
            query.push_str(&format!(" AND tp.proposal_type = ${}", param_count));
            bindings.push(ListBinding::Text(pt.to_string()));
            param_count += 1;
        }

        // NAN-2085 / NAN-2088: filter in SQL, not after the fetch — a
        // post-filter would still page over denied artifacts and make the page
        // size an oracle. Nothing is emitted for an unrestricted reader.
        let scoped = !scope.is_unrestricted();
        if scoped {
            query.push_str(&TuningScope::sql_predicate(
                "tp.source_types",
                "tp.source_types_complete",
                param_count,
            ));
            param_count += 1;
        }

        query.push_str(&format!(
            " ORDER BY tp.created_at DESC LIMIT ${} OFFSET ${}",
            param_count,
            param_count + 1
        ));

        let mut sqlx_query = sqlx::query(&query);

        for binding in bindings {
            sqlx_query = match binding {
                ListBinding::RuleId(id) => sqlx_query.bind(id),
                ListBinding::Text(value) => sqlx_query.bind(value),
            };
        }

        if scoped {
            sqlx_query = sqlx_query.bind(scope.deny_bind_values().to_vec());
        }

        sqlx_query = sqlx_query.bind(limit).bind(offset);

        let rows = sqlx_query
            .fetch_all(&self.pool)
            .await
            .context("Failed to list tuning proposals")?;

        let mut proposals = Vec::new();
        for row in rows {
            let status_str: String = row.try_get("status")?;
            let status = match status_str.as_str() {
                "proposed" => TuningStatus::Proposed,
                "testing" => TuningStatus::Testing,
                "test_passed" => TuningStatus::TestPassed,
                "test_failed" => TuningStatus::TestFailed,
                "staging" => TuningStatus::Staging,
                "promoted" => TuningStatus::Promoted,
                "reverted" => TuningStatus::Reverted,
                "manually_approved" => TuningStatus::ManuallyApproved,
                "rejected" => TuningStatus::Rejected,
                "pr_pending" => TuningStatus::PrPending,
                "pr_opened" => TuningStatus::PrOpened,
                _ => TuningStatus::Proposed,
            };

            let proposal_type_str: String = row.try_get("proposal_type")?;
            let proposal_type = proposal_type_str
                .parse::<ProposalType>()
                .unwrap_or(ProposalType::QueryTuning);

            let current_hints: Option<AiTriageHints> = row
                .try_get::<Option<serde_json::Value>, _>("current_hints")?
                .and_then(|v| serde_json::from_value(v).ok());

            let proposed_hints: Option<AiTriageHints> = row
                .try_get::<Option<serde_json::Value>, _>("proposed_hints")?
                .and_then(|v| serde_json::from_value(v).ok());

            let hints_diff: Option<HintsDiff> = row
                .try_get::<Option<serde_json::Value>, _>("hints_diff")?
                .and_then(|v| serde_json::from_value(v).ok());

            proposals.push(TuningProposal {
                id: row.try_get("id")?,
                rule_id: row.try_get("rule_id")?,
                // NAN-963: from the `rules` LEFT JOIN — None if archived.
                rule_name: row.try_get("rule_name")?,
                created_at: row.try_get("created_at")?,
                proposal_type,
                original_query: row.try_get("original_query")?,
                proposed_query: row.try_get("proposed_query")?,
                rationale: row.try_get("rationale")?,
                confidence_score: row.try_get("confidence_score")?,
                changes_summary: serde_json::from_value(row.try_get("changes_summary")?)
                    .context("Failed to deserialize changes_summary")?,
                affected_patterns: serde_json::from_value(row.try_get("affected_patterns")?)
                    .context("Failed to deserialize affected_patterns")?,
                safety_validation: serde_json::from_value(row.try_get("safety_validation")?)
                    .context("Failed to deserialize safety_validation")?,
                status,
                current_hints,
                proposed_hints,
                hints_diff,
                pr_url: row.try_get("pr_url")?,
                pr_number: row.try_get("pr_number")?,
                pr_state: row.try_get("pr_state")?,
                source_types: row.try_get("source_types")?,
                source_types_complete: row.try_get("source_types_complete")?,
            });
        }

        Ok(proposals)
    }

    /// Get a specific tuning proposal by ID
    ///
    /// # Arguments
    /// * `proposal_id` - The UUID of the proposal
    /// * `scope` - the READER's effective per-source deny scope (NAN-2085 /
    ///   NAN-2088). A proposal derived from a denied source, or whose
    ///   provenance is not COMPLETE, returns `None` — indistinguishable from a
    ///   nonexistent id, so the route is not an existence oracle. The check is
    ///   in SQL, so it also gates the MUTATION handlers (approve / reject)
    ///   that load the proposal first. Background/system callers pass
    ///   [`TuningScope::system`].
    ///
    /// # Returns
    /// The tuning proposal if found AND visible to `scope`, None otherwise
    pub async fn get_proposal(
        &self,
        proposal_id: Uuid,
        scope: &TuningScope,
    ) -> Result<Option<TuningProposal>> {
        // NAN-963: LEFT JOIN rules (see list_proposals for rationale).
        let mut sql = String::from(
            r#"
            SELECT
                tp.id,
                tp.rule_id,
                r.name as rule_name,
                tp.created_at,
                COALESCE(tp.proposal_type, 'query_tuning') as proposal_type,
                tp.original_query,
                COALESCE(
                    tp.pr_operation_snapshot->>'effective_query',
                    tp.proposed_query
                ) AS proposed_query,
                tp.rationale,
                tp.confidence_score,
                tp.changes_summary,
                tp.affected_patterns,
                tp.safety_validation,
                tp.status,
                tp.current_hints,
                tp.proposed_hints,
                tp.hints_diff,
                tp.pr_url,
                tp.pr_number,
                tp.pr_state,
                tp.source_types,
                tp.source_types_complete
            FROM tuning_proposals tp
            LEFT JOIN detection_rules r ON r.id = tp.rule_id
            WHERE tp.id = $1
            "#,
        );
        let scoped = !scope.is_unrestricted();
        if scoped {
            sql.push_str(&TuningScope::sql_predicate(
                "tp.source_types",
                "tp.source_types_complete",
                2,
            ));
        }

        let mut query = sqlx::query(&sql).bind(proposal_id);
        if scoped {
            query = query.bind(scope.deny_bind_values().to_vec());
        }
        let row = query
            .fetch_optional(&self.pool)
            .await
            .context("Failed to fetch tuning proposal")?;

        if let Some(row) = row {
            let status_str: String = row.try_get("status")?;
            let status = match status_str.as_str() {
                "proposed" => TuningStatus::Proposed,
                "testing" => TuningStatus::Testing,
                "test_passed" => TuningStatus::TestPassed,
                "test_failed" => TuningStatus::TestFailed,
                "staging" => TuningStatus::Staging,
                "promoted" => TuningStatus::Promoted,
                "reverted" => TuningStatus::Reverted,
                "manually_approved" => TuningStatus::ManuallyApproved,
                "rejected" => TuningStatus::Rejected,
                "pr_pending" => TuningStatus::PrPending,
                "pr_opened" => TuningStatus::PrOpened,
                _ => TuningStatus::Proposed,
            };

            let proposal_type_str: String = row.try_get("proposal_type")?;
            let proposal_type = proposal_type_str
                .parse::<ProposalType>()
                .unwrap_or(ProposalType::QueryTuning);

            let current_hints: Option<AiTriageHints> = row
                .try_get::<Option<serde_json::Value>, _>("current_hints")?
                .and_then(|v| serde_json::from_value(v).ok());

            let proposed_hints: Option<AiTriageHints> = row
                .try_get::<Option<serde_json::Value>, _>("proposed_hints")?
                .and_then(|v| serde_json::from_value(v).ok());

            let hints_diff: Option<HintsDiff> = row
                .try_get::<Option<serde_json::Value>, _>("hints_diff")?
                .and_then(|v| serde_json::from_value(v).ok());

            Ok(Some(TuningProposal {
                id: row.try_get("id")?,
                rule_id: row.try_get("rule_id")?,
                rule_name: row.try_get("rule_name")?,
                created_at: row.try_get("created_at")?,
                proposal_type,
                original_query: row.try_get("original_query")?,
                proposed_query: row.try_get("proposed_query")?,
                rationale: row.try_get("rationale")?,
                confidence_score: row.try_get("confidence_score")?,
                changes_summary: serde_json::from_value(row.try_get("changes_summary")?)
                    .context("Failed to deserialize changes_summary")?,
                affected_patterns: serde_json::from_value(row.try_get("affected_patterns")?)
                    .context("Failed to deserialize affected_patterns")?,
                safety_validation: serde_json::from_value(row.try_get("safety_validation")?)
                    .context("Failed to deserialize safety_validation")?,
                status,
                current_hints,
                proposed_hints,
                hints_diff,
                pr_url: row.try_get("pr_url")?,
                pr_number: row.try_get("pr_number")?,
                pr_state: row.try_get("pr_state")?,
                source_types: row.try_get("source_types")?,
                source_types_complete: row.try_get("source_types_complete")?,
            }))
        } else {
            Ok(None)
        }
    }

    /// Get proposal history for a rule, including reviewer notes.
    ///
    /// Used by tuning agents to learn from prior accepted/rejected proposals
    /// and avoid re-proposing rejected approaches.
    pub async fn get_proposal_history(
        &self,
        rule_id: Uuid,
        limit: i64,
    ) -> Result<Vec<ProposalHistorySummary>> {
        let rows = sqlx::query(
            r#"
            SELECT status, rationale, confidence_score, proposed_query,
                   reviewer_notes, created_at, source_types, source_types_complete
            FROM tuning_proposals
            WHERE rule_id = $1
            ORDER BY created_at DESC
            LIMIT $2
            "#,
        )
        .bind(rule_id)
        .bind(limit)
        .fetch_all(&self.pool)
        .await
        .context("Failed to fetch proposal history")?;

        let mut summaries = Vec::new();
        for row in rows {
            summaries.push(ProposalHistorySummary {
                status: row.try_get("status")?,
                rationale: row.try_get("rationale")?,
                confidence_score: row.try_get("confidence_score")?,
                proposed_query: row.try_get("proposed_query")?,
                reviewer_notes: row.try_get("reviewer_notes")?,
                created_at: row.try_get("created_at")?,
                source_types: row.try_get("source_types")?,
                source_types_complete: row.try_get("source_types_complete")?,
            });
        }

        Ok(summaries)
    }

    /// Update reviewer notes on a proposal (set on approval/rejection).
    pub async fn set_reviewer_notes(&self, proposal_id: Uuid, notes: &str) -> Result<()> {
        sqlx::query("UPDATE tuning_proposals SET reviewer_notes = $1 WHERE id = $2")
            .bind(notes)
            .bind(proposal_id)
            .execute(&self.pool)
            .await
            .context("Failed to set reviewer notes")?;

        Ok(())
    }
}

#[cfg(test)]
mod approval_provenance_tests {
    use super::*;

    #[test]
    fn validation_override_requires_a_durable_reason() {
        let proposal_id = Uuid::now_v7();
        let mut provenance = PrApprovalProvenance {
            actor_user_id: Some(Uuid::now_v7()),
            api_key_id: None,
            api_key_name: None,
            validation_skipped: true,
            reason: Some("  ".to_string()),
        };
        assert!(matches!(
            provenance.validate(proposal_id),
            Err(PrOperationError::InvalidMetadata { .. })
        ));

        provenance.reason = Some("approved legacy syntax".to_string());
        assert!(provenance.validate(proposal_id).is_ok());

        provenance.actor_user_id = None;
        assert!(matches!(
            provenance.validate(proposal_id),
            Err(PrOperationError::InvalidMetadata { .. })
        ));
    }
}
