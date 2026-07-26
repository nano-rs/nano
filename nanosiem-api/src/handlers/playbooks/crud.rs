// SPDX-License-Identifier: AGPL-3.0-or-later

//! Handlers for the main Playbooks library CRUD.

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    Extension, Json,
};
use nanosiem_core::auth::permissions;
use nanosiem_core::playbooks::{
    CreatePlaybookRequest, ForkPlaybookRequest, ListPlaybooksQuery, Playbook, PlaybookApproval,
    PlaybookPermission, PlaybookRun, PlaybookService, PlaybookVersion, UpdatePlaybookRequest,
};
use nanosiem_core::typeid::TypeIdParam;

use super::types::{playbook_principal, ListPlaybooksParams, ListPlaybooksResponse};
use crate::middleware::{ensure_permission, AuthContext};
use crate::{error::ApiError, state::AppState};

fn get_service(state: &AppState) -> PlaybookService {
    PlaybookService::new(state.pool.clone())
}

/// List playbooks
#[utoipa::path(
    get,
    path = "/api/playbooks",
    tag = "playbooks",
    params(ListPlaybooksParams),
    responses(
        (status = 200, description = "Playbooks retrieved successfully", body = ListPlaybooksResponse),
        (status = 403, description = "Forbidden"),
    ),
    security(("api_key" = []))
)]
pub async fn list_playbooks(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Query(params): Query<ListPlaybooksParams>,
) -> Result<Json<ListPlaybooksResponse>, ApiError> {
    ensure_permission(&auth, permissions::PLAYBOOKS_VIEW)?;

    let service = get_service(&state);
    let query = ListPlaybooksQuery {
        category: params.category,
        status: params.status,
        signal: params.signal,
        search: params.search,
        sort: params.sort,
        limit: params.limit,
        offset: params.offset,
        adaptive: params.adaptive,
    };
    let principal = playbook_principal(&state, &auth).await?;
    let result = service.list(&query, &principal).await?;
    Ok(Json(ListPlaybooksResponse {
        playbooks: result.playbooks,
        total: result.total,
    }))
}

/// Get a single playbook
#[utoipa::path(
    get,
    path = "/api/playbooks/{id}",
    tag = "playbooks",
    params(("id" = String, Path, description = "Playbook TypeID")),
    responses(
        (status = 200, description = "Playbook retrieved successfully", body = Playbook),
        (status = 403, description = "Forbidden"),
        (status = 404, description = "Not found"),
    ),
    security(("api_key" = []))
)]
pub async fn get_playbook(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<TypeIdParam>,
) -> Result<Json<Playbook>, ApiError> {
    ensure_permission(&auth, permissions::PLAYBOOKS_VIEW)?;

    let service = get_service(&state);
    let principal = playbook_principal(&state, &auth).await?;
    let pb = service.get(*id, &principal).await?;
    Ok(Json(pb))
}

/// Create a playbook
#[utoipa::path(
    post,
    path = "/api/playbooks",
    tag = "playbooks",
    request_body = CreatePlaybookRequest,
    responses(
        (status = 200, description = "Playbook created successfully", body = Playbook),
        (status = 403, description = "Forbidden"),
        (status = 400, description = "Bad request"),
    ),
    security(("api_key" = []))
)]
pub async fn create_playbook(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Json(req): Json<CreatePlaybookRequest>,
) -> Result<Json<Playbook>, ApiError> {
    ensure_permission(&auth, permissions::PLAYBOOKS_MANAGE)?;

    let service = get_service(&state);
    let pb = service.create(req, Some(auth.user_id())).await?;
    Ok(Json(pb))
}

/// Update a playbook (creates a new version on doc/meta change)
#[utoipa::path(
    patch,
    path = "/api/playbooks/{id}",
    tag = "playbooks",
    params(("id" = String, Path, description = "Playbook TypeID")),
    request_body = UpdatePlaybookRequest,
    responses(
        (status = 200, description = "Playbook updated successfully", body = Playbook),
        (status = 403, description = "Forbidden"),
        (status = 404, description = "Not found"),
    ),
    security(("api_key" = []))
)]
pub async fn update_playbook(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<TypeIdParam>,
    Json(req): Json<UpdatePlaybookRequest>,
) -> Result<Json<Playbook>, ApiError> {
    ensure_update_permissions(&auth, &req)?;

    let service = get_service(&state);
    let principal = playbook_principal(&state, &auth).await?;
    let pb = service
        .update(*id, req, Some(auth.user_id()), &principal)
        .await?;
    Ok(Json(pb))
}

/// A generic PATCH always needs edit authority. Explicitly setting the
/// lifecycle to `live` is also a publish operation, even when bundled with
/// metadata edits, so require both coarse capabilities before resolving the
/// per-playbook ACL in the repository. An edit to an existing live playbook
/// that omits `status` is returned to draft by the repository.
fn ensure_update_permissions(
    auth: &AuthContext,
    req: &UpdatePlaybookRequest,
) -> Result<(), ApiError> {
    ensure_permission(auth, permissions::PLAYBOOKS_MANAGE)?;
    if matches!(
        req.status,
        Some(nanosiem_core::playbooks::PlaybookStatus::Live)
    ) {
        ensure_permission(auth, permissions::PLAYBOOKS_PUBLISH)?;
    }
    Ok(())
}

/// Archive a playbook (soft-delete — sets status = 'archived')
#[utoipa::path(
    delete,
    path = "/api/playbooks/{id}",
    tag = "playbooks",
    params(("id" = String, Path, description = "Playbook TypeID")),
    responses(
        (status = 204, description = "Playbook archived successfully"),
        (status = 403, description = "Forbidden"),
        (status = 404, description = "Not found"),
    ),
    security(("api_key" = []))
)]
pub async fn archive_playbook(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<TypeIdParam>,
) -> Result<StatusCode, ApiError> {
    ensure_permission(&auth, permissions::PLAYBOOKS_MANAGE)?;

    let service = get_service(&state);
    let principal = playbook_principal(&state, &auth).await?;
    service.archive(*id, &principal).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// NAN-456: hard delete a playbook (permanent removal, not archive).
/// FK CASCADE removes versions/runs/approvals/permissions. Detection-rules
/// FK is RESTRICT — returns 409 if any rule still references this playbook.
#[utoipa::path(
    delete,
    path = "/api/playbooks/{id}/permanent",
    tag = "playbooks",
    params(("id" = String, Path, description = "Playbook TypeID")),
    responses(
        (status = 204, description = "Playbook permanently deleted"),
        (status = 403, description = "Forbidden"),
        (status = 404, description = "Not found"),
        (status = 409, description = "Playbook still referenced by a detection rule"),
    ),
    security(("api_key" = []))
)]
pub async fn delete_playbook_permanent(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<TypeIdParam>,
) -> Result<StatusCode, ApiError> {
    ensure_permission(&auth, permissions::PLAYBOOKS_MANAGE)?;

    let service = get_service(&state);
    let principal = playbook_principal(&state, &auth).await?;
    service.delete(*id, &principal).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Fork a playbook into a new, detached draft
#[utoipa::path(
    post,
    path = "/api/playbooks/{id}/fork",
    tag = "playbooks",
    params(("id" = String, Path, description = "Playbook TypeID")),
    request_body = ForkPlaybookRequest,
    responses(
        (status = 200, description = "Playbook forked successfully", body = Playbook),
        (status = 403, description = "Forbidden"),
        (status = 404, description = "Not found"),
    ),
    security(("api_key" = []))
)]
pub async fn fork_playbook(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<TypeIdParam>,
    Json(req): Json<ForkPlaybookRequest>,
) -> Result<Json<Playbook>, ApiError> {
    ensure_permission(&auth, permissions::PLAYBOOKS_MANAGE)?;

    let service = get_service(&state);
    let principal = playbook_principal(&state, &auth).await?;
    let pb = service
        .fork(*id, req, Some(auth.user_id()), &principal)
        .await?;
    Ok(Json(pb))
}

// =============================================================================
// Children
// =============================================================================

#[derive(Debug, serde::Serialize, utoipa::ToSchema)]
pub struct VersionsResponse {
    pub versions: Vec<PlaybookVersion>,
}

#[derive(Debug, serde::Serialize, utoipa::ToSchema)]
pub struct RunsResponse {
    pub runs: Vec<PlaybookRun>,
}

#[derive(Debug, serde::Serialize, utoipa::ToSchema)]
pub struct PermissionsResponse {
    pub permissions: Vec<PlaybookPermission>,
}

#[derive(Debug, serde::Serialize, utoipa::ToSchema)]
pub struct ApprovalsResponse {
    pub approvals: Vec<PlaybookApproval>,
}

/// List the version history for a playbook
#[utoipa::path(
    get,
    path = "/api/playbooks/{id}/versions",
    tag = "playbooks",
    params(("id" = String, Path, description = "Playbook TypeID")),
    responses(
        (status = 200, description = "Versions retrieved successfully", body = VersionsResponse),
        (status = 403, description = "Forbidden"),
        (status = 404, description = "Not found"),
    ),
    security(("api_key" = []))
)]
pub async fn list_versions(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<TypeIdParam>,
) -> Result<Json<VersionsResponse>, ApiError> {
    ensure_permission(&auth, permissions::PLAYBOOKS_VIEW)?;

    let service = get_service(&state);
    let principal = playbook_principal(&state, &auth).await?;
    let versions = service.list_versions(*id, &principal).await?;
    Ok(Json(VersionsResponse { versions }))
}

/// List per-case runs for a playbook
#[utoipa::path(
    get,
    path = "/api/playbooks/{id}/runs",
    tag = "playbooks",
    params(("id" = String, Path, description = "Playbook TypeID")),
    responses(
        (status = 200, description = "Runs retrieved successfully", body = RunsResponse),
        (status = 403, description = "Forbidden"),
        (status = 404, description = "Not found"),
    ),
    security(("api_key" = []))
)]
pub async fn list_runs(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<TypeIdParam>,
) -> Result<Json<RunsResponse>, ApiError> {
    ensure_permission(&auth, permissions::PLAYBOOKS_VIEW)?;
    // NAN-2044: these runs carry linked-case run_context. `cases:view` is the
    // capability floor; the runs are then filtered per-case so a run whose case
    // the caller cannot see is excluded (the same predicate as
    // CaseRepository::check_user_access, pushed into the list query).
    ensure_permission(&auth, permissions::CASES_VIEW)?;

    let service = get_service(&state);
    let principal = playbook_principal(&state, &auth).await?;
    let runs = service.list_runs(*id, auth.user_id(), &principal).await?;
    Ok(Json(RunsResponse { runs }))
}

/// List role-level permissions for a playbook
#[utoipa::path(
    get,
    path = "/api/playbooks/{id}/permissions",
    tag = "playbooks",
    params(("id" = String, Path, description = "Playbook TypeID")),
    responses(
        (status = 200, description = "Permissions retrieved successfully", body = PermissionsResponse),
        (status = 403, description = "Forbidden"),
        (status = 404, description = "Not found"),
    ),
    security(("api_key" = []))
)]
pub async fn list_permissions(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<TypeIdParam>,
) -> Result<Json<PermissionsResponse>, ApiError> {
    ensure_permission(&auth, permissions::PLAYBOOKS_VIEW)?;

    let service = get_service(&state);
    let principal = playbook_principal(&state, &auth).await?;
    let permissions = service.list_permissions(*id, &principal).await?;
    Ok(Json(PermissionsResponse { permissions }))
}

/// List approval requests for a playbook
#[utoipa::path(
    get,
    path = "/api/playbooks/{id}/approvals",
    tag = "playbooks",
    params(("id" = String, Path, description = "Playbook TypeID")),
    responses(
        (status = 200, description = "Approvals retrieved successfully", body = ApprovalsResponse),
        (status = 403, description = "Forbidden"),
        (status = 404, description = "Not found"),
    ),
    security(("api_key" = []))
)]
pub async fn list_approvals(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<TypeIdParam>,
) -> Result<Json<ApprovalsResponse>, ApiError> {
    ensure_permission(&auth, permissions::PLAYBOOKS_VIEW)?;

    let service = get_service(&state);
    let principal = playbook_principal(&state, &auth).await?;
    let approvals = service.list_approvals(*id, &principal).await?;
    Ok(Json(ApprovalsResponse { approvals }))
}

#[cfg(test)]
mod tests {
    use nanosiem_core::auth::token::{DEFAULT_TOKEN_AUDIENCE, DEFAULT_TOKEN_ISSUER};
    use nanosiem_core::auth::{permissions, TokenClaims};
    use nanosiem_core::playbooks::{PlaybookStatus, UpdatePlaybookRequest};
    use uuid::Uuid;

    use super::ensure_update_permissions;
    use crate::error::ApiError;
    use crate::middleware::AuthContext;

    fn auth(permissions: &[&str]) -> AuthContext {
        AuthContext::from_jwt(TokenClaims {
            iss: DEFAULT_TOKEN_ISSUER.to_string(),
            aud: DEFAULT_TOKEN_AUDIENCE.to_string(),
            sub: Uuid::now_v7(),
            roles: vec!["Editor".to_string()],
            permissions: permissions.iter().map(|value| value.to_string()).collect(),
            exp: i64::MAX,
            iat: 0,
            jti: Uuid::now_v7(),
            purpose: "access".to_string(),
        })
    }

    #[test]
    fn live_patch_requires_manage_and_publish_capabilities() {
        let req = UpdatePlaybookRequest {
            status: Some(PlaybookStatus::Live),
            ..Default::default()
        };

        let manage_only = auth(&[permissions::PLAYBOOKS_MANAGE]);
        assert!(matches!(
            ensure_update_permissions(&manage_only, &req),
            Err(ApiError::Forbidden(message))
                if message == "Missing permission: playbooks:publish"
        ));

        let publish_only = auth(&[permissions::PLAYBOOKS_PUBLISH]);
        assert!(matches!(
            ensure_update_permissions(&publish_only, &req),
            Err(ApiError::Forbidden(message))
                if message == "Missing permission: playbooks:manage"
        ));

        let both = auth(&[
            permissions::PLAYBOOKS_MANAGE,
            permissions::PLAYBOOKS_PUBLISH,
        ]);
        assert!(ensure_update_permissions(&both, &req).is_ok());
    }

    #[test]
    fn ordinary_patch_does_not_require_publish_capability() {
        let req = UpdatePlaybookRequest {
            title: Some("revised title".to_string()),
            ..Default::default()
        };
        let manage_only = auth(&[permissions::PLAYBOOKS_MANAGE]);
        assert!(ensure_update_permissions(&manage_only, &req).is_ok());
    }
}
