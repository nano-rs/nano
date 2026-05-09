// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-445 — Phase 4: suggest + rule/case auto-attach endpoints.
//!
//! Three endpoints:
//!   * GET    /api/playbooks/suggest-for-rule/{rule_id}
//!   * POST   /api/playbooks/{id}/runs          (attach to case)
//!   * PATCH  /api/playbook-runs/{id}           (finish run)
//!
//! Attach + finish live under `/api/playbooks*` prefixes rather than nesting
//! under `/api/cases` to keep the Cases handler module stable — Phase 4b
//! wires the UI that hits these endpoints from the Cases Thread.

use axum::{
    extract::{Path, State},
    Extension, Json,
};
use nanosiem_core::auth::permissions;
use nanosiem_core::playbooks::{
    AttachToCaseRequest, FinishRunRequest, PlaybookRun, PlaybookService, PlaybookSuggestion,
    ResolvedRunResponse, UpdateStepCompletionRequest,
};
use nanosiem_core::typeid::TypeIdParam;

use crate::middleware::{check_permission, AuthContext};
use crate::{error::ApiError, state::AppState};

fn get_service(state: &AppState) -> PlaybookService {
    PlaybookService::new(state.pool.clone())
}

/// Suggest playbooks for a given detection rule.
#[utoipa::path(
    get,
    path = "/api/playbooks/suggest-for-rule/{rule_id}",
    tag = "playbooks",
    params(("rule_id" = String, Path, description = "Rule TypeID")),
    responses(
        (status = 200, description = "Ranked playbook suggestions", body = Vec<PlaybookSuggestion>),
        (status = 403, description = "Forbidden"),
        (status = 404, description = "Rule not found"),
    ),
    security(("api_key" = []))
)]
pub async fn suggest_for_rule(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Path(rule_id): Path<TypeIdParam>,
) -> Result<Json<Vec<PlaybookSuggestion>>, ApiError> {
    check_permission(&auth, permissions::PLAYBOOKS_VIEW)
        .map_err(|_| ApiError::Forbidden("Missing permission: playbooks:view".to_string()))?;

    let service = get_service(&state);
    let suggestions = service.suggest_for_rule(rule_id.into_uuid()).await?;
    Ok(Json(suggestions))
}

/// Attach a playbook to a case (create a new `playbook_runs` row in state
/// `active`). Gated on `playbooks:run`.
#[utoipa::path(
    post,
    path = "/api/playbooks/{id}/runs",
    tag = "playbooks",
    params(("id" = String, Path, description = "Playbook TypeID")),
    request_body = AttachToCaseRequest,
    responses(
        (status = 200, description = "Playbook attached; run created", body = PlaybookRun),
        (status = 403, description = "Forbidden"),
        (status = 404, description = "Playbook not found"),
    ),
    security(("api_key" = []))
)]
pub async fn attach_to_case(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<TypeIdParam>,
    Json(req): Json<AttachToCaseRequest>,
) -> Result<Json<PlaybookRun>, ApiError> {
    check_permission(&auth, permissions::PLAYBOOKS_RUN)
        .map_err(|_| ApiError::Forbidden("Missing permission: playbooks:run".to_string()))?;

    // TokenClaims carries only `sub` (user uuid); the display label is
    // resolved client-side or backfilled by the Analytics tab. Leaving
    // `operator_label` None keeps the row consistent.
    let user_id = Some(auth.user_id());
    let service = get_service(&state);
    let run = service
        .attach_to_case(id.into_uuid(), req, user_id, None)
        .await?;
    Ok(Json(run))
}

/// Finish a playbook run — mark it resolved, compute TTR, and optionally set
/// the outcome / step completion blob.
#[utoipa::path(
    patch,
    path = "/api/playbook-runs/{id}",
    tag = "playbooks",
    params(("id" = String, Path, description = "Playbook run TypeID")),
    request_body = FinishRunRequest,
    responses(
        (status = 200, description = "Run finished", body = PlaybookRun),
        (status = 403, description = "Forbidden"),
        (status = 404, description = "Run not found"),
    ),
    security(("api_key" = []))
)]
pub async fn finish_run(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<TypeIdParam>,
    Json(req): Json<FinishRunRequest>,
) -> Result<Json<PlaybookRun>, ApiError> {
    check_permission(&auth, permissions::PLAYBOOKS_RUN)
        .map_err(|_| ApiError::Forbidden("Missing permission: playbooks:run".to_string()))?;

    let service = get_service(&state);
    let run = service.finish_run(id.into_uuid(), req).await?;
    Ok(Json(run))
}

/// List playbook runs attached to a case.
#[utoipa::path(
    get,
    path = "/api/cases/{case_id}/playbook-runs",
    tag = "playbooks",
    params(("case_id" = String, Path, description = "Case TypeID")),
    responses(
        (status = 200, description = "Runs attached to the case", body = Vec<PlaybookRun>),
        (status = 403, description = "Forbidden"),
    ),
    security(("api_key" = []))
)]
pub async fn list_runs_for_case(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Path(case_id): Path<TypeIdParam>,
) -> Result<Json<Vec<PlaybookRun>>, ApiError> {
    check_permission(&auth, permissions::PLAYBOOKS_VIEW)
        .map_err(|_| ApiError::Forbidden("Missing permission: playbooks:view".to_string()))?;

    let service = get_service(&state);
    let runs = service.list_runs_for_case(case_id.into_uuid()).await?;
    Ok(Json(runs))
}

/// NAN-463 — upsert a single step's completion entry on an attached run.
///
/// Body fields are all optional; only fields present overwrite their
/// counterpart on the step's entry (so clicking the checkbox doesn't
/// clobber an existing note, and vice-versa). `completed=true` stamps
/// `completed_at + operator_user_id` to the authed user; `completed=false`
/// clears both.
#[utoipa::path(
    patch,
    path = "/api/playbook-runs/{run_id}/steps/{step_id}",
    tag = "playbooks",
    params(
        ("run_id" = String, Path, description = "Playbook run TypeID"),
        ("step_id" = String, Path, description = "Step id as it appears in the parsed tree"),
    ),
    request_body = UpdateStepCompletionRequest,
    responses(
        (status = 200, description = "Run with updated step_completion", body = PlaybookRun),
        (status = 403, description = "Forbidden"),
        (status = 404, description = "Run not found"),
    ),
    security(("api_key" = []))
)]
pub async fn update_step_completion(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Path((run_id, step_id)): Path<(TypeIdParam, String)>,
    Json(req): Json<UpdateStepCompletionRequest>,
) -> Result<Json<PlaybookRun>, ApiError> {
    check_permission(&auth, permissions::PLAYBOOKS_RUN)
        .map_err(|_| ApiError::Forbidden("Missing permission: playbooks:run".to_string()))?;

    let service = get_service(&state);
    let run = service
        .update_step_completion(run_id.into_uuid(), &step_id, req, Some(auth.user_id()))
        .await?;
    Ok(Json(run))
}

/// NAN-462 — resolve a playbook run against its frozen `run_context`
/// snapshot. Returns the parsed step tree with `{{...}}` tokens
/// substituted (or the original tree when the run has no context —
/// see `has_context` in the response).
#[utoipa::path(
    get,
    path = "/api/playbook-runs/{id}/resolved",
    tag = "playbooks",
    params(("id" = String, Path, description = "Playbook run TypeID")),
    responses(
        (status = 200, description = "Resolved step tree", body = ResolvedRunResponse),
        (status = 403, description = "Forbidden"),
        (status = 404, description = "Run or version not found"),
    ),
    security(("api_key" = []))
)]
pub async fn resolve_run(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<TypeIdParam>,
) -> Result<Json<ResolvedRunResponse>, ApiError> {
    check_permission(&auth, permissions::PLAYBOOKS_VIEW)
        .map_err(|_| ApiError::Forbidden("Missing permission: playbooks:view".to_string()))?;

    let service = get_service(&state);
    let resolved = service.resolve_run(id.into_uuid()).await?;
    Ok(Json(resolved))
}

// ============================================================================
// NAN-448 — Phase 7: analytics
// ============================================================================

use nanosiem_core::playbooks::PlaybookAnalytics;

/// Aggregate analytics for a playbook — replaces the synthetic
/// `pbAnalytics()` helper on the frontend with real numbers from
/// `playbook_runs`.
#[utoipa::path(
    get,
    path = "/api/playbooks/{id}/analytics",
    tag = "playbooks",
    params(("id" = String, Path, description = "Playbook TypeID")),
    responses(
        (status = 200, description = "Analytics aggregated from playbook_runs", body = PlaybookAnalytics),
        (status = 403, description = "Forbidden"),
        (status = 404, description = "Playbook not found"),
    ),
    security(("api_key" = []))
)]
pub async fn get_analytics(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<TypeIdParam>,
) -> Result<Json<PlaybookAnalytics>, ApiError> {
    check_permission(&auth, permissions::PLAYBOOKS_VIEW)
        .map_err(|_| ApiError::Forbidden("Missing permission: playbooks:view".to_string()))?;

    let service = get_service(&state);
    let analytics = service.compute_analytics(id.into_uuid()).await?;
    Ok(Json(analytics))
}

// ============================================================================
// NAN-447 — Phase 6: approval workflow + permissions
// ============================================================================

use nanosiem_core::playbooks::{
    ApprovalResponseRequest, PlaybookApproval, PlaybookPermission, SetPermissionRequest,
    SubmitForReviewRequest,
};

/// Submit a playbook for review. Creates a `playbook_approvals` row in the
/// `pending` state and flips the playbook's status to `pending_review`.
#[utoipa::path(
    post,
    path = "/api/playbooks/{id}/submit-for-review",
    tag = "playbooks",
    params(("id" = String, Path, description = "Playbook TypeID")),
    request_body = SubmitForReviewRequest,
    responses(
        (status = 200, description = "Approval created", body = PlaybookApproval),
        (status = 403, description = "Forbidden"),
        (status = 404, description = "Playbook not found"),
    ),
    security(("api_key" = []))
)]
pub async fn submit_for_review(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<TypeIdParam>,
    Json(req): Json<SubmitForReviewRequest>,
) -> Result<Json<PlaybookApproval>, ApiError> {
    check_permission(&auth, permissions::PLAYBOOKS_MANAGE)
        .map_err(|_| ApiError::Forbidden("Missing permission: playbooks:manage".to_string()))?;

    let requester_id = Some(auth.user_id());
    let service = get_service(&state);
    let approval = service
        .submit_for_review(id.into_uuid(), requester_id, req)
        .await?;
    Ok(Json(approval))
}

/// Approve a pending approval. Playbook flips to `live`.
#[utoipa::path(
    post,
    path = "/api/playbook-approvals/{id}/approve",
    tag = "playbooks",
    params(("id" = String, Path, description = "Approval id (UUID)")),
    request_body = ApprovalResponseRequest,
    responses(
        (status = 200, description = "Approval updated", body = PlaybookApproval),
        (status = 403, description = "Forbidden"),
        (status = 404, description = "Approval not found"),
    ),
    security(("api_key" = []))
)]
pub async fn approve_playbook(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<TypeIdParam>,
    Json(req): Json<ApprovalResponseRequest>,
) -> Result<Json<PlaybookApproval>, ApiError> {
    check_permission(&auth, permissions::PLAYBOOKS_PUBLISH)
        .map_err(|_| ApiError::Forbidden("Missing permission: playbooks:publish".to_string()))?;

    let approver_id = Some(auth.user_id());
    let service = get_service(&state);
    let approval = service
        .approve(id.into_uuid(), approver_id, req.response)
        .await?;
    Ok(Json(approval))
}

/// Reject a pending approval. Playbook reverts to `draft` if it was
/// pending_review.
#[utoipa::path(
    post,
    path = "/api/playbook-approvals/{id}/reject",
    tag = "playbooks",
    params(("id" = String, Path, description = "Approval id (UUID)")),
    request_body = ApprovalResponseRequest,
    responses(
        (status = 200, description = "Approval updated", body = PlaybookApproval),
        (status = 403, description = "Forbidden"),
        (status = 404, description = "Approval not found"),
    ),
    security(("api_key" = []))
)]
pub async fn reject_playbook(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<TypeIdParam>,
    Json(req): Json<ApprovalResponseRequest>,
) -> Result<Json<PlaybookApproval>, ApiError> {
    check_permission(&auth, permissions::PLAYBOOKS_PUBLISH)
        .map_err(|_| ApiError::Forbidden("Missing permission: playbooks:publish".to_string()))?;

    let approver_id = Some(auth.user_id());
    let service = get_service(&state);
    let approval = service
        .reject(id.into_uuid(), approver_id, req.response)
        .await?;
    Ok(Json(approval))
}

/// Upsert a per-role permission row for a playbook.
#[utoipa::path(
    put,
    path = "/api/playbooks/{id}/permissions/{role}",
    tag = "playbooks",
    params(
        ("id"   = String, Path, description = "Playbook TypeID"),
        ("role" = String, Path, description = "Role label, e.g. soc-leads"),
    ),
    request_body = SetPermissionRequest,
    responses(
        (status = 200, description = "Permission upserted", body = PlaybookPermission),
        (status = 403, description = "Forbidden"),
        (status = 404, description = "Playbook not found"),
    ),
    security(("api_key" = []))
)]
pub async fn set_permission(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Path((id, role)): Path<(TypeIdParam, String)>,
    Json(req): Json<SetPermissionRequest>,
) -> Result<Json<PlaybookPermission>, ApiError> {
    check_permission(&auth, permissions::PLAYBOOKS_MANAGE)
        .map_err(|_| ApiError::Forbidden("Missing permission: playbooks:manage".to_string()))?;

    let service = get_service(&state);
    let perm = service
        .upsert_permission(id.into_uuid(), &role, req)
        .await?;
    Ok(Json(perm))
}

/// Delete a per-role permission row.
#[utoipa::path(
    delete,
    path = "/api/playbooks/{id}/permissions/{role}",
    tag = "playbooks",
    params(
        ("id"   = String, Path, description = "Playbook TypeID"),
        ("role" = String, Path, description = "Role label, e.g. soc-leads"),
    ),
    responses(
        (status = 204, description = "Permission removed (or didn't exist)"),
        (status = 403, description = "Forbidden"),
    ),
    security(("api_key" = []))
)]
pub async fn delete_permission(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Path((id, role)): Path<(TypeIdParam, String)>,
) -> Result<axum::http::StatusCode, ApiError> {
    check_permission(&auth, permissions::PLAYBOOKS_MANAGE)
        .map_err(|_| ApiError::Forbidden("Missing permission: playbooks:manage".to_string()))?;

    let service = get_service(&state);
    service.delete_permission(id.into_uuid(), &role).await?;
    Ok(axum::http::StatusCode::NO_CONTENT)
}

// ============================================================================
// NAN-449 — Phase 5b: compose adaptive playbook from case
// ============================================================================

/// Compose an adaptive playbook from a case's Shadow Investigator notebook
/// entries. Returns the new playbook row with `adaptive=true`.
///
/// Manual-trigger endpoint for now — a follow-up wires this into the
/// shadow_investigation service's completion hook so adaptive playbooks
/// get composed automatically on investigation wrap.
#[utoipa::path(
    post,
    path = "/api/cases/{case_id}/compose-adaptive-playbook",
    tag = "playbooks",
    params(("case_id" = String, Path, description = "Case TypeID")),
    responses(
        (status = 200, description = "Adaptive playbook composed", body = nanosiem_core::playbooks::Playbook),
        (status = 403, description = "Forbidden"),
        (status = 404, description = "No shadow investigation entries to compose from"),
    ),
    security(("api_key" = []))
)]
pub async fn compose_adaptive_from_case(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Path(case_id): Path<TypeIdParam>,
) -> Result<Json<nanosiem_core::playbooks::Playbook>, ApiError> {
    check_permission(&auth, permissions::PLAYBOOKS_MANAGE)
        .map_err(|_| ApiError::Forbidden("Missing permission: playbooks:manage".to_string()))?;

    let user_id = Some(auth.user_id());
    let service = get_service(&state);
    let pb = service
        .compose_adaptive_from_case(case_id.into_uuid(), user_id)
        .await?;
    Ok(Json(pb))
}

// ============================================================================
// NAN-446 — Phase 5: adaptive → library promote
// ============================================================================

/// Promote an adaptive (agent-composed) playbook into the library. Flips
/// `adaptive=false`, `promoted=true`, and status to `pending_review`.
/// Snapshots into `playbook_versions` with `promoted_from_case_id` set.
/// Idempotent: calling on an already-promoted row returns it unchanged.
#[utoipa::path(
    post,
    path = "/api/playbooks/{id}/promote",
    tag = "playbooks",
    params(("id" = String, Path, description = "Playbook TypeID")),
    responses(
        (status = 200, description = "Playbook promoted", body = nanosiem_core::playbooks::Playbook),
        (status = 403, description = "Forbidden"),
        (status = 404, description = "Playbook not found"),
    ),
    security(("api_key" = []))
)]
pub async fn promote_playbook(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<TypeIdParam>,
) -> Result<Json<nanosiem_core::playbooks::Playbook>, ApiError> {
    check_permission(&auth, permissions::PLAYBOOKS_PUBLISH).map_err(|_| {
        ApiError::Forbidden("Missing permission: playbooks:publish".to_string())
    })?;

    let user_id = Some(auth.user_id());
    let service = get_service(&state);
    let pb = service
        .promote(id.into_uuid(), user_id, Some("promoted by operator".to_string()))
        .await?;
    Ok(Json(pb))
}
