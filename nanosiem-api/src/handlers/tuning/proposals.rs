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
use nanosiem_core::tuning::{ProposalType, TuningProposal, TuningStatus};
use nanosiem_core::typeid::TypeIdParam;
use uuid::Uuid;

use super::types::{
    ApprovalResponse, ApproveProposalRequest, ListProposalsQuery, RejectProposalRequest,
    RejectionResponse,
};
use crate::error::ApiError;
use crate::handlers::AuditExt;
use crate::middleware::{ensure_permission, AuthContext};
use crate::state::AppState;

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
        (status = 403, description = "Missing permission: detections:edit"),
        (status = 404, description = "Proposal not found"),
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

    // 2. Validate it hasn't already been approved/rejected
    if proposal.status != TuningStatus::Proposed && proposal.status != TuningStatus::TestPassed {
        return Ok(Json(ApprovalResponse {
            success: false,
            message: format!(
                "Proposal cannot be approved (current status: {:?})",
                proposal.status
            ),
            version_id: None,
        }));
    }

    // 3. Get the current rule details
    let rule: (String, Option<String>, String, String) = sqlx::query_as(
        "SELECT name, description, severity, mode FROM detection_rules WHERE id = $1",
    )
    .bind(proposal.rule_id)
    .fetch_optional(&state.pool)
    .await
    .map_err(|e| ApiError::InternalError(format!("Failed to fetch rule: {}", e)))?
    .ok_or_else(|| ApiError::NotFound("Rule not found".to_string()))?;

    let (rule_name, rule_description, rule_severity, rule_mode) = rule;

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
        sqlx::query(
            "UPDATE detection_rules SET mode = 'paused', updated_at = NOW() WHERE id = $1",
        )
        .bind(proposal.rule_id)
        .execute(&state.pool)
        .await
        .map_err(|e| ApiError::InternalError(format!("Failed to pause rule: {}", e)))?;

        state
            .tuning_repository
            .update_proposal_status(proposal.id, TuningStatus::ManuallyApproved)
            .await
            .map_err(|e| {
                ApiError::InternalError(format!("Failed to update proposal status: {}", e))
            })?;

        if let Some(ref comment) = request.comment {
            if let Err(e) = state
                .tuning_repository
                .set_reviewer_notes(proposal.id, comment)
                .await
            {
                tracing::warn!(
                    "Failed to set reviewer notes on silent-rule pause: {}",
                    e
                );
            }
        }

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
        }));
    }

    if proposal.proposal_type == ProposalType::SilentRule
        && proposal.proposed_query == proposal.original_query
    {
        state
            .tuning_repository
            .update_proposal_status(proposal.id, TuningStatus::ManuallyApproved)
            .await
            .map_err(|e| {
                ApiError::InternalError(format!("Failed to update proposal status: {}", e))
            })?;

        if let Some(ref comment) = request.comment {
            if let Err(e) = state
                .tuning_repository
                .set_reviewer_notes(proposal.id, comment)
                .await
            {
                tracing::warn!(
                    "Failed to set reviewer notes on silent-rule approval: {}",
                    e
                );
            }
        }

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
        }));
    }
    // Else: SilentRule with proposed_query != original_query (no sentinel)
    // → falls through to the QueryTuning apply logic below.

    // Handle based on proposal type
    let version_id = if proposal.proposal_type == ProposalType::HintUpdate {
        // Hint update: Update ai_triage_hints, no version needed
        if let Some(ref proposed_hints) = proposal.proposed_hints {
            sqlx::query(
                "UPDATE detection_rules SET ai_triage_hints = $1, updated_at = NOW() WHERE id = $2",
            )
            .bind(sqlx::types::Json(proposed_hints))
            .bind(proposal.rule_id)
            .execute(&state.pool)
            .await
            .map_err(|e| ApiError::InternalError(format!("Failed to update hints: {}", e)))?;
        }

        // Update proposal status
        state
            .tuning_repository
            .update_proposal_status(proposal.id, TuningStatus::ManuallyApproved)
            .await
            .map_err(|e| {
                ApiError::InternalError(format!("Failed to update proposal status: {}", e))
            })?;

        // Persist reviewer notes for the tuning feedback loop
        if let Some(ref comment) = request.comment {
            if let Err(e) = state
                .tuning_repository
                .set_reviewer_notes(proposal.id, comment)
                .await
            {
                tracing::warn!("Failed to set reviewer notes on hint approval: {}", e);
            }
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
        }));
    } else {
        // Query tuning: Update query and create version
        // Use modified_query if analyst edited the proposal, otherwise use AI-proposed query
        let final_query = request
            .modified_query
            .as_deref()
            .unwrap_or(&proposal.proposed_query);

        // 3b. Validate query syntax before applying
        if !request.skip_validation {
            use nanosiem_core::parse_query;

            // Strip nPL comments before parsing
            let clean_query = crate::handlers::detections::strip_comments(final_query);
            if let Err(parse_err) = parse_query(&clean_query) {
                return Ok(Json(ApprovalResponse {
                    success: false,
                    message: format!(
                        "Query syntax validation failed — the proposed query has errors and cannot be applied. \
                        Fix the query using Edit Query, or set skip_validation to override.\n\nParse error: {}",
                        parse_err
                    ),
                    version_id: None,
                }));
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
            if let Some(target) = dac_repo.find_active().await.map_err(|e| {
                ApiError::InternalError(format!("Failed to load push target: {e}"))
            })? {
                let full_rule: nanosiem_core::models::detection_rule::DetectionRule =
                    sqlx::query_as("SELECT * FROM detection_rules WHERE id = $1")
                        .bind(proposal.rule_id)
                        .fetch_optional(&state.pool)
                        .await
                        .map_err(|e| {
                            ApiError::InternalError(format!("Failed to fetch rule: {e}"))
                        })?
                        .ok_or_else(|| ApiError::NotFound("Rule not found".to_string()))?;

                // PR the final (possibly analyst-edited) query.
                let mut pr_proposal = proposal.clone();
                pr_proposal.proposed_query = final_query.to_string();

                let push =
                    nanosiem_core::detection_code_target::DetectionCodePushService::new(dac_repo);
                let pr = push
                    .open_pr_for_proposal(&target, &full_rule, &pr_proposal)
                    .await
                    .map_err(|e| {
                        ApiError::InternalError(format!("Failed to open pull request: {e}"))
                    })?;

                state
                    .tuning_repository
                    .set_pr_opened(proposal.id, &pr.html_url, pr.number)
                    .await
                    .map_err(|e| ApiError::InternalError(format!("Failed to record PR: {e}")))?;

                if let Some(ref comment) = request.comment {
                    let _ = state
                        .tuning_repository
                        .set_reviewer_notes(proposal.id, comment)
                        .await;
                }

                state.emit_audit(
                    AuditEvent::builder(AuditSource::Tuning, DETECTION_CODE_PR_OPENED)
                        .actor(Some(auth.user_id()), None)
                        .api_key(auth.api_key_id, auth.api_key_name.clone())
                        .resource("tuning_proposal", Some(proposal.id), Some(rule_name.clone()))
                        .client_context(&client)
                        .details(serde_json::json!({
                            "rule_id": proposal.rule_id,
                            "pr_url": pr.html_url,
                            "pr_number": pr.number,
                        }))
                        .build(),
                );

                return Ok(Json(ApprovalResponse {
                    success: true,
                    message: format!("Pull request opened for review: {}", pr.html_url),
                    version_id: None,
                }));
            }
        }

        // 4. Update the rule with the (possibly modified) tuned query
        sqlx::query("UPDATE detection_rules SET query = $1, updated_at = NOW() WHERE id = $2")
            .bind(final_query)
            .bind(proposal.rule_id)
            .execute(&state.pool)
            .await
            .map_err(|e| ApiError::InternalError(format!("Failed to update rule: {}", e)))?;

        // 5. Create a new rule version
        use nanosiem_core::tuning::versions::RuleVersionManager;
        use nanosiem_core::tuning::RuleVersion;

        let version_manager = RuleVersionManager::new(state.pool.clone());
        let user_id = auth.user_id();

        let new_version = RuleVersion {
            id: 0, // Will be set by DB
            rule_id: proposal.rule_id,
            version_number: 0, // Will be calculated by create_version
            query: final_query.to_string(),
            name: rule_name.clone(),
            description: rule_description.clone(),
            severity: rule_severity.clone(),
            enabled: rule_mode != "staging" && rule_mode != "paused",
            is_active: true,
            created_at: chrono::Utc::now(),
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
            tuning_proposal_id: Some(proposal.id),
            reverted_from_version: None,
        };

        version_manager
            .create_version(new_version)
            .await
            .map_err(|e| ApiError::InternalError(format!("Failed to create version: {}", e)))?
    };

    // 6. Update proposal status to manually approved
    state
        .tuning_repository
        .update_proposal_status(proposal.id, TuningStatus::ManuallyApproved)
        .await
        .map_err(|e| ApiError::InternalError(format!("Failed to update proposal status: {}", e)))?;

    // 6b. Persist reviewer notes for the tuning feedback loop
    if let Some(ref comment) = request.comment {
        if let Err(e) = state
            .tuning_repository
            .set_reviewer_notes(proposal.id, comment)
            .await
        {
            tracing::warn!("Failed to set reviewer notes on approval: {}", e);
        }
    }

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
                "proposal_type": "query_tuning",
                "version_id": version_id,
                "comment": request.comment,
            }))
            .build(),
    );

    Ok(Json(ApprovalResponse {
        success: true,
        message: format!("Proposal approved and applied to rule '{}'", rule_name),
        version_id: Some(version_id),
    }))
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
    if proposal.status == TuningStatus::ManuallyApproved
        || proposal.status == TuningStatus::Rejected
        || proposal.status == TuningStatus::Promoted
    {
        return Ok(Json(RejectionResponse {
            success: false,
            message: format!(
                "Proposal cannot be rejected (current status: {:?})",
                proposal.status
            ),
        }));
    }

    // 3. Update proposal status to rejected
    state
        .tuning_repository
        .update_proposal_status(proposal.id, TuningStatus::Rejected)
        .await
        .map_err(|e| ApiError::InternalError(format!("Failed to update proposal status: {}", e)))?;

    // 3b. Persist reviewer notes for the tuning feedback loop
    if let Err(e) = state
        .tuning_repository
        .set_reviewer_notes(proposal.id, &request.reason)
        .await
    {
        tracing::warn!("Failed to set reviewer notes on rejection: {}", e);
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
