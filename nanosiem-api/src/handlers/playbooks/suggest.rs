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

use super::types::playbook_principal;
use crate::middleware::{ensure_permission, AuthContext};
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
        (status = 403, description = "Forbidden — missing playbooks:view, or the detections:view capability this endpoint consumes"),
        (status = 404, description = "Rule not found"),
    ),
    security(("api_key" = []))
)]
pub async fn suggest_for_rule(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Path(rule_id): Path<TypeIdParam>,
) -> Result<Json<Vec<PlaybookSuggestion>>, ApiError> {
    ensure_permission(&auth, permissions::PLAYBOOKS_VIEW)?;
    // NAN-2104: this endpoint reads an ARBITRARY detection rule by caller-supplied
    // id and turns its name, folder and MITRE mappings into the response. That is
    // a `detection_rules` read, and it is also an exact rule-existence oracle
    // (200 for a rule that exists, 404 for one that doesn't). `detections:view`
    // is the capability the canonical route for that resource
    // (`GET /api/rules/{id}`) enforces, so require it here too — checked BEFORE
    // the lookup, so both existing and missing ids answer 403 identically and the
    // oracle disappears. A `playbooks:view` API key does not imply
    // `detections:view`; role bundling is not a boundary.
    ensure_permission(&auth, permissions::DETECTIONS_VIEW)?;

    let service = get_service(&state);
    // NAN-2097: the suggestion feed returns whole playbook rows (doc included),
    // so it is ACL-filtered like every other library read.
    let principal = playbook_principal(&state, &auth).await?;
    let suggestions = service
        .suggest_for_rule(rule_id.into_uuid(), &principal)
        .await?;
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
    ensure_permission(&auth, permissions::PLAYBOOKS_RUN)?;
    // NAN-2044: a playbook run is attached to a case, and the playbook
    // capability is NOT permission over that case. cases:edit is the capability
    // floor; the caller must also actually be able to SEE the target case, or
    // they could attach a run (and snapshot its private data) to a case they
    // cannot view. 404 when the case isn't visible so its existence isn't
    // leaked.
    ensure_permission(&auth, permissions::CASES_EDIT)?;

    // NAN-2044: attach enforces case visibility ATOMICALLY — the run row is
    // inserted only if the target case is visible to the caller (conditional
    // INSERT … WHERE EXISTS), so a concurrent revocation can't slip an attach
    // through. 404 (NotFound) when the case isn't visible or doesn't exist.
    let service = get_service(&state);
    // TokenClaims carries only `sub` (user uuid); the display label is
    // resolved client-side or backfilled by the Analytics tab. Leaving
    // `operator_label` None keeps the row consistent.
    let operator = Some(auth.user_id());
    let principal = playbook_principal(&state, &auth).await?;
    let run = service
        .attach_to_case(
            id.into_uuid(),
            req,
            operator,
            None,
            Some(auth.user_id()),
            &principal,
        )
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
    ensure_permission(&auth, permissions::PLAYBOOKS_RUN)?;
    // NAN-2044: mutating a run mutates its linked case's investigation state.
    // cases:edit is the capability floor; the caller must also be able to see
    // THIS run's case. 404 when it isn't visible so run existence isn't leaked.
    ensure_permission(&auth, permissions::CASES_EDIT)?;

    // NAN-2044: finish_run enforces case visibility ATOMICALLY — the UPDATE only
    // fires while the caller can still see the run's case (no separate
    // check-then-act, so no TOCTOU). A missing run and an invisible-case run
    // both yield 404, so the response is not a run-existence oracle.
    let service = get_service(&state);
    let principal = playbook_principal(&state, &auth).await?;
    let run = service
        .finish_run(*id, req, Some(auth.user_id()), &principal)
        .await?;
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
        (status = 404, description = "Case not found or not visible to the caller"),
    ),
    security(("api_key" = []))
)]
pub async fn list_runs_for_case(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Path(case_id): Path<TypeIdParam>,
) -> Result<Json<Vec<PlaybookRun>>, ApiError> {
    ensure_permission(&auth, permissions::PLAYBOOKS_VIEW)?;
    // NAN-2044: reading a case's runs reads that case's data, so cases:view is
    // only the capability floor — the caller must actually be able to see this
    // specific case. Apply the canonical case-visibility check; 404 when the
    // case is not visible so its existence isn't leaked.
    ensure_permission(&auth, permissions::CASES_VIEW)?;

    let service = get_service(&state);
    let principal = playbook_principal(&state, &auth).await?;
    let runs = service
        .list_runs_for_case(*case_id, auth.user_id(), &principal)
        .await?;
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
    ensure_permission(&auth, permissions::PLAYBOOKS_RUN)?;
    // NAN-2044: mutating a run mutates its linked case's investigation state.
    // cases:edit is the capability floor; the caller must also be able to see
    // THIS run's case. 404 when it isn't visible so run existence isn't leaked.
    ensure_permission(&auth, permissions::CASES_EDIT)?;

    // NAN-2044: same atomic case-visibility enforcement as finish_run — the
    // step-completion UPDATE only fires while the caller can still see the run's
    // case; missing/invisible both 404 (no oracle, no TOCTOU).
    let service = get_service(&state);
    let principal = playbook_principal(&state, &auth).await?;
    let run = service
        .update_step_completion(
            *run_id,
            &step_id,
            req,
            Some(auth.user_id()),
            Some(auth.user_id()),
            &principal,
        )
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
    ensure_permission(&auth, permissions::PLAYBOOKS_VIEW)?;
    // NAN-2044: resolving a run returns its frozen case run_context, so
    // cases:view is only the capability floor — the caller must actually be
    // able to see THIS run's case. Derive the case from the run and apply the
    // canonical case-visibility check; 404 (not 403) so run existence isn't
    // leaked to someone who can't see its case.
    ensure_permission(&auth, permissions::CASES_VIEW)?;

    let service = get_service(&state);
    let principal = playbook_principal(&state, &auth).await?;
    let resolved = service
        .resolve_run(*id, auth.user_id(), &principal)
        .await?;
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
    ensure_permission(&auth, permissions::PLAYBOOKS_VIEW)?;

    let service = get_service(&state);
    let principal = playbook_principal(&state, &auth).await?;
    let analytics = service
        .compute_analytics(id.into_uuid(), &principal)
        .await?;
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
    ensure_permission(&auth, permissions::PLAYBOOKS_MANAGE)?;

    let requester_id = Some(auth.user_id());
    let service = get_service(&state);
    let principal = playbook_principal(&state, &auth).await?;
    let approval = service
        .submit_for_review(id.into_uuid(), requester_id, req, &principal)
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
        (status = 404, description = "Approval not found, or assigned to a different reviewer"),
    ),
    security(("api_key" = []))
)]
pub async fn approve_playbook(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<TypeIdParam>,
    Json(req): Json<ApprovalResponseRequest>,
) -> Result<Json<PlaybookApproval>, ApiError> {
    ensure_permission(&auth, permissions::PLAYBOOKS_PUBLISH)?;

    // NAN-2098: `playbooks:publish` authorizes responding to an OPEN approval.
    // It is NOT authority over an approval assigned to a named reviewer — that
    // assignment is the separation-of-duties boundary the workflow exists for.
    // The predicate is enforced inside the UPDATE (see
    // `PlaybookRepository::approve_approval`), so it cannot be raced.
    let service = get_service(&state);
    let principal = playbook_principal(&state, &auth).await?;
    let approval = service
        .approve(
            id.into_uuid(),
            Some(auth.user_id()),
            assignee_claim(&auth),
            req.response,
            &principal,
        )
        .await?;
    Ok(Json(approval))
}

/// The identity permitted to answer an approval that names a specific reviewer
/// (NAN-2098).
///
/// `None` for API keys — deliberately, not defensively. An API key's
/// `auth.user_id()` is its OWNER's user id, so treating it as the assignee would
/// let any key its owner holds impersonate that human in a review gate (exactly
/// the reported bypass: a Fred-owned key approving a request assigned to Dan).
/// NAN-2145 already established that the owner-subject may be used for
/// attribution but never for an authorization decision. `None` collapses the SQL
/// predicate to `approver_id IS NULL`, so keys may still answer OPEN approvals —
/// automation keeps working, impersonation does not.
fn assignee_claim(auth: &AuthContext) -> Option<uuid::Uuid> {
    if auth.is_api_key {
        None
    } else {
        Some(auth.user_id())
    }
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
        (status = 404, description = "Approval not found, or assigned to a different reviewer"),
    ),
    security(("api_key" = []))
)]
pub async fn reject_playbook(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<TypeIdParam>,
    Json(req): Json<ApprovalResponseRequest>,
) -> Result<Json<PlaybookApproval>, ApiError> {
    ensure_permission(&auth, permissions::PLAYBOOKS_PUBLISH)?;

    // NAN-2098: same assignment boundary as approve — rejecting somebody else's
    // assigned review is as much a separation-of-duties break as approving it.
    let service = get_service(&state);
    let principal = playbook_principal(&state, &auth).await?;
    let approval = service
        .reject(
            id.into_uuid(),
            Some(auth.user_id()),
            assignee_claim(&auth),
            req.response,
            &principal,
        )
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
        ("role" = String, Path, description = "Role NAME as it appears in the roles table (e.g. Editor), or the literal `api_key` for API-key principals. NAN-2097: an unknown role is rejected — an ACL entry matching nobody would hide the playbook from everyone."),
    ),
    request_body = SetPermissionRequest,
    responses(
        (status = 200, description = "Permission upserted", body = PlaybookPermission),
        (
            status = 400,
            description = "Invalid ACL, including a change that would lock out the caller"
        ),
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
    ensure_permission(&auth, permissions::PLAYBOOKS_MANAGE)?;

    let service = get_service(&state);
    let principal = playbook_principal(&state, &auth).await?;
    let perm = service
        .upsert_permission(id.into_uuid(), &role, req, &principal)
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
        ("role" = String, Path, description = "Role NAME as it appears in the roles table (e.g. Editor), or the literal `api_key` for API-key principals. NAN-2097: an unknown role is rejected — an ACL entry matching nobody would hide the playbook from everyone."),
    ),
    responses(
        (status = 204, description = "Permission removed (or didn't exist)"),
        (
            status = 400,
            description = "Invalid ACL, including a change that would lock out the caller"
        ),
        (status = 403, description = "Forbidden"),
        (status = 404, description = "Playbook not found"),
    ),
    security(("api_key" = []))
)]
pub async fn delete_permission(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Path((id, role)): Path<(TypeIdParam, String)>,
) -> Result<axum::http::StatusCode, ApiError> {
    ensure_permission(&auth, permissions::PLAYBOOKS_MANAGE)?;

    let service = get_service(&state);
    let principal = playbook_principal(&state, &auth).await?;
    service
        .delete_permission(id.into_uuid(), &role, &principal)
        .await?;
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
    ensure_permission(&auth, permissions::PLAYBOOKS_MANAGE)?;
    // NAN-2044: this reads the case's Shadow Investigator notebook entries by
    // case_id and returns them as a composed playbook. cases:view is the
    // capability floor; the caller must also be able to SEE this specific case,
    // or they could exfiltrate a private case's investigation notes via the
    // composed playbook. 404 when the case isn't visible.
    ensure_permission(&auth, permissions::CASES_VIEW)?;

    // NAN-2044: compose reads the case's private investigation notes; the entry
    // read is gated on case visibility ATOMICALLY inside the query, so a caller
    // who cannot see the case gets nothing to compose (404) — no check-then-act.
    let service = get_service(&state);
    let composed_by = Some(auth.user_id());
    let pb = service
        .compose_adaptive_from_case(*case_id, composed_by, Some(auth.user_id()))
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
    ensure_permission(&auth, permissions::PLAYBOOKS_PUBLISH)?;

    let user_id = Some(auth.user_id());
    let service = get_service(&state);
    let principal = playbook_principal(&state, &auth).await?;
    let pb = service
        .promote(
            id.into_uuid(),
            user_id,
            Some("promoted by operator".to_string()),
            &principal,
        )
        .await?;
    Ok(Json(pb))
}
