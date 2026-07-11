// SPDX-License-Identifier: AGPL-3.0-or-later

use axum::{
    extract::{Path, Query, State},
    Extension, Json,
};
use nanosiem_core::audit::{
    AuditEvent, AuditSource, ClientContext, DETECTION_CODE_PR_OPENED, PROPOSAL_APPROVED,
    PROPOSAL_REJECTED,
};
use nanosiem_core::auth::permissions;
use nanosiem_core::detection_code_target::PrExecutionError;
use nanosiem_core::tuning::{
    AtomicProposalApplyError, AtomicProposalApplyRequest, PendingRuntimeSync, PrApprovalProvenance,
    PrOperationClaim, PrOperationError, PrOperationPhase, ProposalRuleMutation, ProposalType,
    TuningProposal, TuningStatus,
};
use nanosiem_core::typeid::TypeIdParam;
use uuid::Uuid;

use super::types::{
    ApprovalOutcome, ApprovalResponse, ApproveProposalRequest, ListProposalsQuery,
    RejectProposalRequest, RejectionResponse,
};
use crate::error::ApiError;
use crate::handlers::AuditExt;
use crate::middleware::{ensure_permission, AuthContext};
use crate::state::AppState;

fn proposal_is_approvable(status: TuningStatus) -> bool {
    matches!(
        status,
        TuningStatus::Proposed | TuningStatus::TestPassed | TuningStatus::PrPending
    )
}

fn proposal_is_rejectable(status: TuningStatus) -> bool {
    !matches!(
        status,
        TuningStatus::ManuallyApproved
            | TuningStatus::Rejected
            | TuningStatus::Promoted
            | TuningStatus::Reverted
            | TuningStatus::PrOpened
    )
}

fn query_tuning_approval_audit_details(
    rule_id: Uuid,
    version_id: i32,
    validation_skipped: bool,
    comment: Option<&str>,
    runtime_sync_error: Option<&str>,
    safety_advisory: &[String],
) -> serde_json::Value {
    serde_json::json!({
        "rule_id": rule_id,
        "proposal_type": "query_tuning",
        "version_id": version_id,
        "validation_skipped": validation_skipped,
        "comment": comment,
        "runtime_sync_pending": runtime_sync_error.is_some(),
        "runtime_sync_error": runtime_sync_error,
        "safety_advisory": safety_advisory,
    })
}

/// Non-blocking safety advisory for a manually-approved query tuning (NAN-1784 / P2-1).
///
/// Applying a tuning query is a `DETECTIONS_EDIT` operation and stays that way; this
/// runs the same `SafetyValidator` the autonomous path uses purely to SURFACE (in the
/// approval response, audit trail, and logs) when a human-approved query drops a
/// critical detection indicator or trips a broad-exclusion check. It never blocks.
#[cfg_attr(not(feature = "enterprise"), allow(unused_variables))]
async fn manual_approve_safety_advisory(proposal: &TuningProposal, final_query: &str) -> Vec<String> {
    #[cfg(feature = "enterprise")]
    {
        let mut candidate = proposal.clone();
        candidate.proposed_query = final_query.to_string();
        if let Ok(validation) = nanosiem_enterprise::tuning::safety::SafetyValidator::new()
            .validate_safety(&candidate)
            .await
        {
            if !validation.is_safe {
                let mut advisories: Vec<String> = validation
                    .validation_checks
                    .iter()
                    .filter(|check| !check.passed)
                    .map(|check| format!("{}: {}", check.check_name, check.details))
                    .collect();
                advisories.extend(validation.warnings.iter().cloned());
                return advisories;
            }
        }
    }
    Vec::new()
}

fn enforce_validation_override(
    skip_validation: bool,
    can_promote: bool,
    comment: Option<&str>,
) -> Result<(), ApiError> {
    if !skip_validation {
        return Ok(());
    }
    if !can_promote {
        return Err(ApiError::Forbidden(
            "Skipping query validation requires detections:promote".to_string(),
        ));
    }
    if comment
        .map(str::trim)
        .filter(|reason| !reason.is_empty())
        .is_none()
    {
        return Err(ApiError::BadRequest(
            "Skipping query validation requires a non-empty approval comment".to_string(),
        ));
    }
    Ok(())
}

/// GET /api/tuning/proposals
///
/// List tuning proposals with optional filters.
///
/// Requirements: 3.1
#[utoipa::path(
    get,
    path = "/api/tuning/proposals",
    tag = "tuning",
    params(ListProposalsQuery),
    responses(
        (status = 200, description = "Proposals listed successfully", body = Vec<TuningProposal>),
        (status = 403, description = "Missing permission: detections:view"),
        (status = 500, description = "Internal server error")
    ),
    security(("api_key" = []))
)]
pub async fn list_proposals(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Query(query): Query<ListProposalsQuery>,
) -> Result<Json<Vec<TuningProposal>>, ApiError> {
    ensure_permission(&auth, permissions::DETECTIONS_VIEW)?;

    // List proposals with filters (including proposal_type)
    let proposals = state
        .tuning_repository
        .list_proposals(
            query.rule_id,
            query.status,
            query.proposal_type,
            query.limit,
            query.offset,
        )
        .await
        .map_err(|e| ApiError::InternalError(format!("Failed to list proposals: {}", e)))?;

    Ok(Json(proposals))
}

/// GET /api/tuning/proposals/:id
///
/// Get a specific tuning proposal by ID.
///
/// Requirements: 3.1
#[utoipa::path(
    get,
    path = "/api/tuning/proposals/{id}",
    tag = "tuning",
    params(
        ("id" = String, Path, description = "Proposal ID")
    ),
    responses(
        (status = 200, description = "Proposal retrieved successfully", body = TuningProposal),
        (status = 403, description = "Missing permission: detections:view"),
        (status = 404, description = "Proposal not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("api_key" = []))
)]
pub async fn get_proposal(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<TypeIdParam>,
) -> Result<Json<TuningProposal>, ApiError> {
    ensure_permission(&auth, permissions::DETECTIONS_VIEW)?;

    // Get proposal by ID
    let proposal = state
        .tuning_repository
        .get_proposal(*id)
        .await
        .map_err(|e| ApiError::InternalError(format!("Failed to get proposal: {}", e)))?
        .ok_or_else(|| ApiError::NotFound("Proposal not found".to_string()))?;

    Ok(Json(proposal))
}

/// POST /api/tuning/proposals/:id/approve
///
/// Approve a tuning proposal and apply it to the rule.
/// Handles both query tuning and hint update proposals.
///
/// Requirements: 11.3
#[utoipa::path(
    post,
    path = "/api/tuning/proposals/{id}/approve",
    tag = "tuning",
    params(
        ("id" = String, Path, description = "Proposal ID")
    ),
    request_body = ApproveProposalRequest,
    responses(
        (status = 200, description = "Proposal approved", body = ApprovalResponse),
        (status = 400, description = "Validation override requires a reason"),
        (status = 403, description = "Missing required detections permission"),
        (status = 404, description = "Proposal not found"),
        (status = 409, description = "Proposal state, rule base, or approvability changed"),
        (status = 422, description = "Proposed query failed validation"),
        (status = 500, description = "Internal server error")
    ),
    security(("api_key" = []))
)]
pub async fn approve_proposal(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    client: Extension<ClientContext>,
    Path(id): Path<TypeIdParam>,
    Json(request): Json<ApproveProposalRequest>,
) -> Result<Json<ApprovalResponse>, ApiError> {
    ensure_permission(&auth, permissions::DETECTIONS_EDIT)?;

    // 1. Retrieve proposal
    let proposal = state
        .tuning_repository
        .get_proposal(*id)
        .await
        .map_err(|e| ApiError::InternalError(format!("Failed to get proposal: {}", e)))?
        .ok_or_else(|| ApiError::NotFound("Proposal not found".to_string()))?;
    enforce_validation_override(
        request.skip_validation,
        auth.has_permission(permissions::DETECTIONS_PROMOTE),
        request.comment.as_deref(),
    )?;

    // 2. Validate it hasn't already been approved/rejected
    if proposal.status == TuningStatus::PrOpened {
        let url = proposal.pr_url.as_deref().ok_or_else(|| {
            ApiError::Conflict("Proposal is pr_opened but has no recorded PR URL".to_string())
        })?;
        let effective_query: String = sqlx::query_scalar(
            "SELECT COALESCE(pr_operation_snapshot->>'effective_query', pr_operation_query, proposed_query) FROM tuning_proposals WHERE id = $1",
        )
        .bind(proposal.id)
        .fetch_one(&state.pool)
        .await
        .map_err(|error| ApiError::InternalError(format!("Failed to load effective query: {error}")))?;
        return Ok(Json(ApprovalResponse {
            success: true,
            message: format!("Pull request already opened for review: {url}"),
            version_id: None,
            outcome: Some(ApprovalOutcome::PrOpened),
            status: Some(TuningStatus::PrOpened),
            pr_url: Some(url.to_string()),
            effective_query: Some(effective_query),
            runtime_sync_pending: false,
            runtime_sync_error: None,
        }));
    }
    if !proposal_is_approvable(proposal.status) {
        return Err(ApiError::Conflict(format!(
            "Proposal cannot be approved (current status: {:?})",
            proposal.status
        )));
    }

    // 3. Get the rule name for response/audit text. The locked rule snapshot
    // used for mutation and versioning is loaded inside apply_proposal_atomic.
    let rule_name: String = sqlx::query_scalar("SELECT name FROM detection_rules WHERE id = $1")
        .bind(proposal.rule_id)
        .fetch_optional(&state.pool)
        .await
        .map_err(|e| ApiError::InternalError(format!("Failed to fetch rule: {}", e)))?
        .ok_or_else(|| ApiError::NotFound("Rule not found".to_string()))?;

    // SilentRule proposals (NAN-880 phase 3c) route by what the detector
    // encoded in proposed_query:
    //
    // 1. Pause sentinel (`// __NANOSIEM_SILENT_ACTION:pause__`)
    //    → set rule mode='paused', record decision, audit.
    // 2. proposed_query == original_query (no rewrite)
    //    → record decision only (MissingFields / Generic causes; the
    //      analyst should use Customize to navigate to the rule editor).
    // 3. proposed_query != original_query, no sentinel
    //    → fall through to the QueryTuning apply path below, which
    //      validates the rewritten query, updates the rule, and creates
    //      a new rule version (Used by the ThresholdUnreachable cause).
    if proposal.proposal_type == ProposalType::SilentRule
        && nanosiem_core::tuning::silent_actions::is_pause_action(&proposal.proposed_query)
    {
        state
            .tuning_repository
            .apply_proposal_atomic(AtomicProposalApplyRequest {
                proposal_id: proposal.id,
                target_status: TuningStatus::ManuallyApproved,
                mutation: ProposalRuleMutation::Pause,
                reviewer_notes: request.comment.clone(),
                log_trigger_reason: "Silent-rule pause manually approved".to_string(),
            })
            .await
            .map_err(map_atomic_apply_error)?;

        state.emit_audit(
            AuditEvent::builder(AuditSource::Tuning, PROPOSAL_APPROVED)
                .actor(Some(auth.user_id()), None)
                .api_key(auth.api_key_id, auth.api_key_name.clone())
                .resource(
                    "tuning_proposal",
                    Some(proposal.id),
                    Some(rule_name.clone()),
                )
                .client_context(&client)
                .details(serde_json::json!({
                    "rule_id": proposal.rule_id,
                    "proposal_type": "silent_rule",
                    "action": "pause",
                    "comment": request.comment,
                }))
                .build(),
        );

        return Ok(Json(ApprovalResponse {
            success: true,
            message: format!("Silent rule paused: '{}'", rule_name),
            version_id: None,
            outcome: Some(ApprovalOutcome::Applied),
            status: Some(TuningStatus::ManuallyApproved),
            pr_url: None,
            effective_query: Some(proposal.original_query.clone()),
            runtime_sync_pending: false,
            runtime_sync_error: None,
        }));
    }

    if proposal.proposal_type == ProposalType::SilentRule
        && proposal.proposed_query == proposal.original_query
    {
        state
            .tuning_repository
            .apply_proposal_atomic(AtomicProposalApplyRequest {
                proposal_id: proposal.id,
                target_status: TuningStatus::ManuallyApproved,
                mutation: ProposalRuleMutation::Acknowledge,
                reviewer_notes: request.comment.clone(),
                log_trigger_reason: "Silent-rule diagnostic manually acknowledged".to_string(),
            })
            .await
            .map_err(map_atomic_apply_error)?;

        state.emit_audit(
            AuditEvent::builder(AuditSource::Tuning, PROPOSAL_APPROVED)
                .actor(Some(auth.user_id()), None)
                .api_key(auth.api_key_id, auth.api_key_name.clone())
                .resource(
                    "tuning_proposal",
                    Some(proposal.id),
                    Some(rule_name.clone()),
                )
                .client_context(&client)
                .details(serde_json::json!({
                    "rule_id": proposal.rule_id,
                    "proposal_type": "silent_rule",
                    "action": "acknowledge",
                    "comment": request.comment,
                }))
                .build(),
        );

        return Ok(Json(ApprovalResponse {
            success: true,
            message: format!(
                "Silent-rule diagnostic acknowledged for rule '{}'",
                rule_name
            ),
            version_id: None,
            outcome: Some(ApprovalOutcome::Applied),
            status: Some(TuningStatus::ManuallyApproved),
            pr_url: None,
            effective_query: Some(proposal.original_query.clone()),
            runtime_sync_pending: false,
            runtime_sync_error: None,
        }));
    }
    // Else: SilentRule with proposed_query != original_query (no sentinel)
    // → falls through to the QueryTuning apply logic below.

    // Handle based on proposal type
    let mut runtime_sync_error: Option<String> = None;
    let version_id = if proposal.proposal_type == ProposalType::HintUpdate {
        // Hint update: stale-check the persisted current_hints snapshot and
        // mutate hints/status/log in one transaction.
        state
            .tuning_repository
            .apply_proposal_atomic(AtomicProposalApplyRequest {
                proposal_id: proposal.id,
                target_status: TuningStatus::ManuallyApproved,
                mutation: ProposalRuleMutation::Hints,
                reviewer_notes: request.comment.clone(),
                log_trigger_reason: "Triage-hint proposal manually approved".to_string(),
            })
            .await
            .map_err(map_atomic_apply_error)?;

        // Emit audit event
        state.emit_audit(
            AuditEvent::builder(AuditSource::Tuning, PROPOSAL_APPROVED)
                .actor(Some(auth.user_id()), None)
                .api_key(auth.api_key_id, auth.api_key_name.clone())
                .resource(
                    "tuning_proposal",
                    Some(proposal.id),
                    Some(rule_name.clone()),
                )
                .client_context(&client)
                .details(serde_json::json!({
                    "rule_id": proposal.rule_id,
                    "proposal_type": "hint_update",
                    "comment": request.comment,
                }))
                .build(),
        );

        return Ok(Json(ApprovalResponse {
            success: true,
            message: format!("Hint proposal approved and applied to rule '{}'", rule_name),
            version_id: None,
            outcome: Some(ApprovalOutcome::Applied),
            status: Some(TuningStatus::ManuallyApproved),
            pr_url: None,
            effective_query: None,
            runtime_sync_pending: false,
            runtime_sync_error: None,
        }));
    } else {
        // Query tuning: Update query and create version
        // Use modified_query if analyst edited the proposal, otherwise use AI-proposed query
        let final_query = if proposal.status == TuningStatus::PrPending {
            &proposal.proposed_query
        } else {
            request
                .modified_query
                .as_deref()
                .unwrap_or(&proposal.proposed_query)
        };

        // 3b. Validate query syntax before applying
        // A pending operation reuses the query frozen by its original claim.
        // That payload was already validated (or explicitly overridden) before
        // the first GitHub attempt, and may differ from proposed_query after an
        // analyst edit.
        if !request.skip_validation && proposal.status != TuningStatus::PrPending {
            use nanosiem_core::parse_query;

            // Strip nPL comments before parsing
            let clean_query = crate::handlers::detections::strip_comments(final_query);
            if let Err(parse_err) = parse_query(&clean_query) {
                return Err(ApiError::ValidationError(format!(
                        "Query syntax validation failed — the proposed query has errors and cannot be applied. \
                        Fix the query using Edit Query, or set skip_validation to override.\n\nParse error: {}",
                        parse_err
                    )));
            }
        }

        // NAN-1745: if a detection-as-code push target is configured, open a PR
        // with the (possibly analyst-modified) query instead of applying it to
        // the DB. Git is the source of truth for these tenants.
        {
            let dac_repo =
                nanosiem_core::detection_code_target::DetectionCodeTargetRepository::with_crypto(
                    state.pool.clone(),
                    (*state.encryption_service).clone(),
                );
            let claimed_target_id = state
                .tuning_repository
                .get_pr_operation_target_id(proposal.id)
                .await
                .map_err(|e| {
                    ApiError::InternalError(format!("Failed to load claimed push target: {e}"))
                })?;
            let dac_target = if let Some(target_id) = claimed_target_id {
                Some(dac_repo.get(target_id).await.map_err(|e| {
                    ApiError::Conflict(format!("Claimed push target is unavailable: {e}"))
                })?)
            } else if proposal.status == TuningStatus::PrPending {
                return Err(ApiError::Conflict(
                    "Pending PR operation has no claimed push target".to_string(),
                ));
            } else {
                dac_repo.find_active().await.map_err(|e| {
                    ApiError::InternalError(format!("Failed to load push target: {e}"))
                })?
            };
            if let Some(target) = dac_target {
                let (operation, destination, attempt, mut checkpoint) = match state
                    .tuning_repository
                    .claim_pr_operation_with_provenance(
                        proposal.id,
                        target.id,
                        final_query,
                        PrApprovalProvenance {
                            actor_user_id: Some(auth.user_id()),
                            api_key_id: auth.api_key_id,
                            api_key_name: auth.api_key_name.clone(),
                            validation_skipped: request.skip_validation,
                            reason: request.comment.clone(),
                        },
                    )
                    .await
                    .map_err(map_pr_operation_error)?
                {
                    PrOperationClaim::AlreadyOpened {
                        url,
                        effective_query,
                        ..
                    } => {
                        return Ok(Json(ApprovalResponse {
                            success: true,
                            message: format!("Pull request already opened for review: {url}"),
                            version_id: None,
                            outcome: Some(ApprovalOutcome::PrOpened),
                            status: Some(TuningStatus::PrOpened),
                            pr_url: Some(url),
                            effective_query: Some(effective_query),
                            runtime_sync_pending: false,
                            runtime_sync_error: None,
                        }));
                    }
                    PrOperationClaim::Claimed {
                        operation,
                        destination,
                        attempt,
                        checkpoint,
                        ..
                    } => (operation, destination, attempt, checkpoint),
                };

                let push =
                    nanosiem_core::detection_code_target::DetectionCodePushService::new(dac_repo);
                let destination = match destination {
                    Some(destination) => destination,
                    None => match push.prepare_pr_operation(&operation).await {
                        Ok(destination) => {
                            let destination = state
                                .tuning_repository
                                .freeze_pr_destination(proposal.id, attempt, &destination)
                                .await
                                .map_err(map_pr_operation_error)?;
                            checkpoint.phase = PrOperationPhase::DestinationReady;
                            destination
                        }
                        Err(error) => {
                            let error = PrExecutionError::Remote(error);
                            if error.is_retryable() {
                                state
                                    .tuning_repository
                                    .record_pr_operation_error(
                                        proposal.id,
                                        &operation.branch,
                                        attempt,
                                        &error.to_string(),
                                    )
                                    .await
                                    .map_err(map_pr_operation_error)?;
                                tracing::warn!(
                                    proposal_id = %proposal.id,
                                    %error,
                                    "Detection-as-Code PR preparation remains pending for recovery"
                                );
                                return Err(ApiError::InternalError(
                                    "PR operation remains pending for automatic recovery"
                                        .to_string(),
                                ));
                            }
                            return Err(record_pr_execution_failure(
                                &state,
                                proposal.id,
                                &operation.branch,
                                attempt,
                                &error.to_string(),
                            )
                            .await);
                        }
                    },
                };
                let pr = match push
                    .reconcile_prepared_pr(
                        &state.tuning_repository,
                        &operation,
                        &destination,
                        checkpoint,
                        attempt,
                        request.comment.as_deref(),
                    )
                    .await
                {
                    Ok(pr) => pr,
                    Err(error) if error.is_retryable() => {
                        tracing::warn!(proposal_id = %proposal.id, %error, "Detection-as-Code PR operation remains pending for recovery");
                        return Err(ApiError::InternalError(
                            "PR operation remains pending for automatic recovery".to_string(),
                        ));
                    }
                    Err(error) => {
                        return Err(record_pr_execution_failure(
                            &state,
                            proposal.id,
                            &operation.branch,
                            attempt,
                            &error.to_string(),
                        )
                        .await);
                    }
                };

                let effective_query = operation.effective_query.clone();
                let approval = operation.approval_provenance.as_ref();
                let actor_user_id = approval
                    .and_then(|provenance| provenance.actor_user_id)
                    .unwrap_or_else(|| auth.user_id());
                let api_key_id = approval
                    .map(|provenance| provenance.api_key_id)
                    .unwrap_or(auth.api_key_id);
                let api_key_name = approval
                    .map(|provenance| provenance.api_key_name.clone())
                    .unwrap_or_else(|| auth.api_key_name.clone());
                let validation_skipped = approval
                    .map(|provenance| provenance.validation_skipped)
                    .unwrap_or(request.skip_validation);
                let approval_comment = approval
                    .map(|provenance| provenance.reason.as_deref())
                    .unwrap_or(request.comment.as_deref());
                state.emit_audit(
                    AuditEvent::builder(AuditSource::Tuning, DETECTION_CODE_PR_OPENED)
                        .actor(Some(actor_user_id), None)
                        .api_key(api_key_id, api_key_name)
                        .resource(
                            "tuning_proposal",
                            Some(proposal.id),
                            Some(rule_name.clone()),
                        )
                        .client_context(&client)
                        .details(serde_json::json!({
                            "rule_id": proposal.rule_id,
                            "pr_url": pr.html_url,
                            "pr_number": pr.number,
                            "pr_state": pr.state,
                            "effective_query": effective_query,
                            "validation_skipped": validation_skipped,
                            "comment": approval_comment,
                            "approval_actor_user_id": actor_user_id,
                            "reconciled_by_user_id": auth.user_id(),
                        }))
                        .build(),
                );
                return Ok(Json(ApprovalResponse {
                    success: true,
                    message: format!("Pull request opened for review: {}", pr.html_url),
                    version_id: None,
                    outcome: Some(ApprovalOutcome::PrOpened),
                    status: Some(TuningStatus::PrOpened),
                    pr_url: Some(pr.html_url),
                    effective_query: Some(effective_query),
                    runtime_sync_pending: false,
                    runtime_sync_error: None,
                }));
            }
        }

        if proposal.status == TuningStatus::PrPending {
            return Err(ApiError::Conflict(
                "Proposal has a pending Detection-as-Code operation but no matching active target"
                    .to_string(),
            ));
        }

        let user_id = auth.user_id();

        let runtime_sync_owner = format!("{}:tuning-apply:{}", state.node_id, Uuid::now_v7());
        let result = state
            .tuning_repository
            .apply_proposal_atomic_with_runtime(
                AtomicProposalApplyRequest {
                    proposal_id: proposal.id,
                    target_status: TuningStatus::ManuallyApproved,
                    mutation: ProposalRuleMutation::Query {
                        query: final_query.to_string(),
                        created_by: Some(user_id),
                        change_reason: format!(
                            "Auto-tuning {}: {}{}",
                            if request.modified_query.is_some() {
                                "applied (analyst-modified)"
                            } else {
                                "applied"
                            },
                            proposal.rationale,
                            request
                                .comment
                                .as_ref()
                                .map(|c| format!(" (Approver comment: {})", c))
                                .unwrap_or_default()
                        ),
                    },
                    reviewer_notes: request.comment.clone(),
                    log_trigger_reason: "Query-tuning proposal manually approved".to_string(),
                },
                state.materialized_view_generator.as_ref(),
                Some(&runtime_sync_owner),
            )
            .await
            .map_err(map_atomic_apply_error)?;
        let version_id = result.version_id.ok_or_else(|| {
            ApiError::InternalError("Atomic query application created no version".to_string())
        })?;
        if result.runtime_sync_required {
            if result.runtime_sync_claimed {
                let pending = PendingRuntimeSync {
                    rule_id: result.rule_id,
                    desired_version_id: version_id,
                };
                if let Err(error) = state
                    .reconcile_rule_runtime_sync(&pending, &runtime_sync_owner)
                    .await
                {
                    tracing::warn!(
                        proposal_id = %proposal.id,
                        rule_id = %result.rule_id,
                        %error,
                        "Tuning applied; real-time runtime reconciliation will retry"
                    );
                    runtime_sync_error = Some(
                        "ClickHouse reconciliation did not complete; distributed retry is active"
                            .to_string(),
                    );
                }
            } else {
                runtime_sync_error =
                    Some("real-time runtime reconciliation is owned by another node".to_string());
            }
        }
        version_id
    };

    // 7. Send notification (create a staging deployment for notification purposes)
    use nanosiem_core::tuning::StagingDeployment;

    let staging_deployment = StagingDeployment {
        id: Uuid::now_v7(),
        proposal_id: proposal.id,
        rule_id: proposal.rule_id,
        version_id,
        deployed_at: chrono::Utc::now(),
        staging_ends_at: chrono::Utc::now(),
        validation_passed: Some(true),
        promoted_at: Some(chrono::Utc::now()),
    };

    if let Err(e) = state
        .notification_service
        .notify_promoted(&staging_deployment, &rule_name)
        .await
    {
        tracing::warn!("Failed to send notification: {}", e);
    }

    // Non-blocking safety advisory on manual approve (NAN-1784 / P2-1): run the
    // same SafetyValidator the autonomous path uses, purely to surface — never
    // block — a human-approved query that drops a critical detection indicator.
    let applied_query = request
        .modified_query
        .as_deref()
        .unwrap_or(proposal.proposed_query.as_str());
    let safety_advisory = manual_approve_safety_advisory(&proposal, applied_query).await;
    if !safety_advisory.is_empty() {
        tracing::warn!(
            proposal_id = %proposal.id,
            rule_id = %proposal.rule_id,
            advisories = ?safety_advisory,
            "Manual tuning approval applied a query flagged by tuning safety checks (non-blocking)"
        );
    }

    // Emit audit event
    state.emit_audit(
        AuditEvent::builder(AuditSource::Tuning, PROPOSAL_APPROVED)
            .actor(Some(auth.user_id()), None)
            .api_key(auth.api_key_id, auth.api_key_name.clone())
            .resource(
                "tuning_proposal",
                Some(proposal.id),
                Some(rule_name.clone()),
            )
            .client_context(&client)
            .details(query_tuning_approval_audit_details(
                proposal.rule_id,
                version_id,
                request.skip_validation,
                request.comment.as_deref(),
                runtime_sync_error.as_deref(),
                &safety_advisory,
            ))
            .build(),
    );

    Ok(Json(ApprovalResponse {
        success: true,
        message: {
            let base = if runtime_sync_error.is_some() {
                format!(
                    "Proposal applied to rule '{}'; real-time runtime reconciliation is pending",
                    rule_name
                )
            } else {
                format!("Proposal approved and applied to rule '{}'", rule_name)
            };
            if safety_advisory.is_empty() {
                base
            } else {
                format!(
                    "{base} \u{26a0} Safety advisory (applied as requested): {}",
                    safety_advisory.join("; ")
                )
            }
        },
        version_id: Some(version_id),
        outcome: Some(ApprovalOutcome::Applied),
        status: Some(TuningStatus::ManuallyApproved),
        pr_url: None,
        effective_query: Some(
            request
                .modified_query
                .unwrap_or_else(|| proposal.proposed_query.clone()),
        ),
        runtime_sync_pending: runtime_sync_error.is_some(),
        runtime_sync_error,
    }))
}

fn map_atomic_apply_error(error: AtomicProposalApplyError) -> ApiError {
    match error {
        AtomicProposalApplyError::ProposalNotFound(id) => {
            ApiError::NotFound(format!("Proposal not found: {id}"))
        }
        AtomicProposalApplyError::InvalidProposalState { .. }
        | AtomicProposalApplyError::StaleRuleBase { .. }
        | AtomicProposalApplyError::DetectionAsCodeRequired { .. }
        | AtomicProposalApplyError::AutonomousPolicyRejected { .. }
        | AtomicProposalApplyError::AutonomousValidationRejected { .. } => {
            ApiError::Conflict(error.to_string())
        }
        AtomicProposalApplyError::InvalidMutation { .. }
        | AtomicProposalApplyError::RealTimeValidation { .. } => {
            ApiError::BadRequest(error.to_string())
        }
        AtomicProposalApplyError::Database(_) => ApiError::InternalError(error.to_string()),
    }
}

fn map_pr_operation_error(error: PrOperationError) -> ApiError {
    match error {
        PrOperationError::ProposalNotFound(id) => {
            ApiError::NotFound(format!("Proposal not found: {id}"))
        }
        PrOperationError::InProgress(_)
        | PrOperationError::InvalidState { .. }
        | PrOperationError::StaleRuleBase { .. }
        | PrOperationError::InvalidMetadata { .. } => ApiError::Conflict(error.to_string()),
        PrOperationError::Database(_) => ApiError::InternalError(error.to_string()),
    }
}

async fn record_pr_execution_failure(
    state: &AppState,
    proposal_id: Uuid,
    branch: &str,
    attempt: i32,
    error: &str,
) -> ApiError {
    match state
        .tuning_repository
        .fail_pr_operation(proposal_id, branch, attempt, error)
        .await
    {
        Ok(true) => ApiError::InternalError(format!("Failed to open pull request: {error}")),
        Ok(false) => ApiError::Conflict(
            "Proposal state changed while the PR operation was failing; the newer state was preserved"
                .to_string(),
        ),
        Err(record_error) => {
            tracing::error!(
                %proposal_id,
                %record_error,
                "Failed to release unsuccessful tuning PR operation"
            );
            ApiError::InternalError(format!("Failed to open pull request: {error}"))
        }
    }
}

/// POST /api/tuning/proposals/:id/reject
///
/// Reject a tuning proposal.
///
/// Requirements: 11.3
#[utoipa::path(
    post,
    path = "/api/tuning/proposals/{id}/reject",
    tag = "tuning",
    params(
        ("id" = String, Path, description = "Proposal ID")
    ),
    request_body = RejectProposalRequest,
    responses(
        (status = 200, description = "Proposal rejected", body = RejectionResponse),
        (status = 403, description = "Missing permission: detections:edit"),
        (status = 404, description = "Proposal not found"),
        (status = 409, description = "Proposal is no longer rejectable"),
        (status = 500, description = "Internal server error")
    ),
    security(("api_key" = []))
)]
pub async fn reject_proposal(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    client: Extension<ClientContext>,
    Path(id): Path<TypeIdParam>,
    Json(request): Json<RejectProposalRequest>,
) -> Result<Json<RejectionResponse>, ApiError> {
    ensure_permission(&auth, permissions::DETECTIONS_EDIT)?;

    // 1. Retrieve proposal
    let proposal = state
        .tuning_repository
        .get_proposal(*id)
        .await
        .map_err(|e| ApiError::InternalError(format!("Failed to get proposal: {}", e)))?
        .ok_or_else(|| ApiError::NotFound("Proposal not found".to_string()))?;

    // 2. Validate it hasn't already been approved/rejected
    if !proposal_is_rejectable(proposal.status) {
        return Err(ApiError::Conflict(format!(
            "Proposal cannot be rejected (current status: {:?})",
            proposal.status
        )));
    }

    // 3. Compare-and-set status and reviewer notes so approve/reject races have
    // exactly one winner and only that winner performs external side effects.
    let transitioned = if proposal.status == TuningStatus::PrPending {
        state
            .tuning_repository
            .cancel_expired_pr_operation(proposal.id, &request.reason)
            .await
            .map_err(map_pr_operation_error)?
    } else {
        state
            .tuning_repository
            .transition_proposal_status(
                proposal.id,
                &[
                    TuningStatus::Proposed,
                    TuningStatus::Testing,
                    TuningStatus::TestPassed,
                    TuningStatus::TestFailed,
                    TuningStatus::Staging,
                ],
                TuningStatus::Rejected,
                Some(&request.reason),
            )
            .await
            .map_err(|e| {
                ApiError::InternalError(format!("Failed to update proposal status: {}", e))
            })?
    };
    if !transitioned {
        return Ok(Json(RejectionResponse {
            success: false,
            message: if proposal.status == TuningStatus::PrPending {
                "The PR attempt is still active; retry cancellation after its lease expires"
                    .to_string()
            } else {
                "Proposal was already actioned by another request".to_string()
            },
        }));
    }

    // 4. Get rule name for notification
    let rule_name: Option<String> =
        sqlx::query_scalar("SELECT name FROM detection_rules WHERE id = $1")
            .bind(proposal.rule_id)
            .fetch_optional(&state.pool)
            .await
            .map_err(|e| ApiError::InternalError(format!("Failed to fetch rule: {}", e)))?;

    let rule_name = rule_name.unwrap_or_else(|| "Unknown Rule".to_string());

    // 5. Send notification
    let user_id = auth.user_id();

    if let Err(e) = state
        .notification_service
        .notify_reverted(proposal.id, &rule_name, &request.reason, Some(user_id))
        .await
    {
        tracing::warn!("Failed to send notification: {}", e);
    }

    // Emit audit event
    state.emit_audit(
        AuditEvent::builder(AuditSource::Tuning, PROPOSAL_REJECTED)
            .actor(Some(auth.user_id()), None)
            .api_key(auth.api_key_id, auth.api_key_name.clone())
            .resource(
                "tuning_proposal",
                Some(proposal.id),
                Some(rule_name.clone()),
            )
            .client_context(&client)
            .details(serde_json::json!({
                "rule_id": proposal.rule_id,
                "reason": request.reason,
            }))
            .build(),
    );

    Ok(Json(RejectionResponse {
        success: true,
        message: format!("Proposal rejected for rule '{}'", rule_name),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proposal_routes_reject_terminal_states_with_http_errors() {
        assert!(proposal_is_approvable(TuningStatus::Proposed));
        assert!(proposal_is_approvable(TuningStatus::TestPassed));
        assert!(!proposal_is_approvable(TuningStatus::Promoted));
        assert!(!proposal_is_approvable(TuningStatus::PrOpened));

        assert!(proposal_is_rejectable(TuningStatus::Proposed));
        assert!(!proposal_is_rejectable(TuningStatus::ManuallyApproved));
        assert!(!proposal_is_rejectable(TuningStatus::Rejected));
        assert!(!proposal_is_rejectable(TuningStatus::Promoted));
        assert!(!proposal_is_rejectable(TuningStatus::Reverted));
        assert!(!proposal_is_rejectable(TuningStatus::PrOpened));
    }

    #[test]
    fn query_tuning_apply_audit_details_are_complete() {
        let rule_id = Uuid::now_v7();
        let details = query_tuning_approval_audit_details(
            rule_id,
            29,
            true,
            Some("analyst reviewed"),
            Some("ClickHouse timeout"),
            &["Critical Indicator Preservation: removed powershell".to_string()],
        );
        assert_eq!(details["rule_id"], rule_id.to_string());
        assert_eq!(details["proposal_type"], "query_tuning");
        assert_eq!(details["version_id"], 29);
        assert_eq!(details["validation_skipped"], true);
        assert_eq!(details["comment"], "analyst reviewed");
        assert_eq!(details["runtime_sync_pending"], true);
        assert_eq!(
            details["safety_advisory"][0],
            "Critical Indicator Preservation: removed powershell"
        );
        assert_eq!(details["runtime_sync_error"], "ClickHouse timeout");
    }

    #[test]
    fn validation_override_requires_promote_permission() {
        assert!(matches!(
            enforce_validation_override(true, false, Some("emergency repair")),
            Err(ApiError::Forbidden(_))
        ));
    }

    #[test]
    fn validation_override_requires_a_nonempty_reason() {
        assert!(matches!(
            enforce_validation_override(true, true, Some("  ")),
            Err(ApiError::BadRequest(_))
        ));
        assert!(enforce_validation_override(true, true, Some("emergency repair")).is_ok());
    }

    #[test]
    fn normal_validation_path_needs_no_override_permission() {
        assert!(enforce_validation_override(false, false, None).is_ok());
    }
}
