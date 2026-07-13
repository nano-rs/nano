// SPDX-License-Identifier: AGPL-3.0-or-later

//! Per-source RBAC scope admin API handlers (NAN-1799 / epic NAN-1789).
//!
//! Admin CRUD over the two PostgreSQL tables introduced in migration 244:
//!
//! - `restricted_source_types` — the deny-by-omission registry. Listing a
//!   `source_type` string value here makes it invisible-by-default; an empty
//!   registry is today's allow-all behaviour exactly.
//! - `source_type_grants` — which groups may see a restricted `source_type`.
//!   Granting a restricted value to the "Everyone" system group un-restricts it
//!   without deleting the registry row.
//!
//! The enforceable unit is the event-borne `source_type` STRING value (not a
//! `log_sources` UUID — events never carry that). Values are normalized to
//! `trim().to_lowercase()` on write so they match the resolver's lowercase
//! comparison and the ingest-lowercased `source_type` column.
//!
//! Every mutation (a) invalidates the [`SourceScopeResolver`] cache so the next
//! request re-derives each user's deny-set, and (b) emits a durable audit event
//! (the actions are registered in `SECURITY_CRITICAL_ACTIONS`) — losing an audit
//! write for a data-visibility change is not acceptable.
//!
//! Reads require `source_scopes:view`; mutations require `source_scopes:manage`
//! (both admin-only, granted to the Admin role in migration 244).

use axum::{
    extract::{Path, State},
    http::StatusCode,
    routing::{delete, get, post},
    Extension, Json, Router,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use nanosiem_core::audit::{
    AuditEvent, AuditSource, ClientContext, SOURCE_SCOPE_GRANTED, SOURCE_SCOPE_RESTRICTED,
    SOURCE_SCOPE_REVOKED, SOURCE_SCOPE_UNRESTRICTED,
};
use nanosiem_core::auth::permissions;
use nanosiem_core::db::repository::{
    RestrictedSourceType, SourceScopeError as RepoSourceScopeError, SourceTypeGrant,
};

use crate::handlers::AuditExt;
use crate::middleware::{ensure_permission, AuthContext};
use crate::{error::ApiError, state::AppState};

/// Max length of a `source_type` value (mirrors `VARCHAR(100)` in migration 244).
/// Rejected as a 400 up front rather than surfacing a truncation/DB error.
const MAX_SOURCE_TYPE_LEN: usize = 100;

/// Map the repository error onto an [`ApiError`]: a missing-row delete is a 404,
/// everything else (including a grant on an unregistered `source_type`, which
/// surfaces as an FK violation) is a 500.
fn map_scope_err(e: RepoSourceScopeError) -> ApiError {
    match e {
        RepoSourceScopeError::NotFound(s) => {
            ApiError::NotFound(format!("Restricted source type not found: {s}"))
        }
        RepoSourceScopeError::Database(e) => ApiError::InternalError(format!("Database error: {e}")),
    }
}

/// Normalize a caller-supplied `source_type` to the stored form
/// (`trim().to_lowercase()`), rejecting empty / over-long values with a 400.
fn normalize_source_type(raw: &str) -> Result<String, ApiError> {
    let normalized = raw.trim().to_lowercase();
    if normalized.is_empty() {
        return Err(ApiError::BadRequest(
            "source_type must not be empty".to_string(),
        ));
    }
    if normalized.len() > MAX_SOURCE_TYPE_LEN {
        return Err(ApiError::BadRequest(format!(
            "source_type must be at most {MAX_SOURCE_TYPE_LEN} characters"
        )));
    }
    Ok(normalized)
}

// =============================================================================
// Request / response DTOs
// =============================================================================

/// Request body for registering a `source_type` as restricted.
#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct AddRestrictedRequest {
    /// The event-borne `source_type` string value to restrict. Normalized to
    /// `trim().to_lowercase()` before storage.
    pub source_type: String,
    /// Optional admin-authored note (e.g. "insider-threat feed").
    #[serde(default)]
    pub description: Option<String>,
}

/// Request body for granting a group visibility of a restricted `source_type`.
#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct AddGrantRequest {
    /// The restricted `source_type` to unlock. Must already be registered
    /// (restricted) — a grant on an unregistered value is rejected. Normalized
    /// to `trim().to_lowercase()`.
    pub source_type: String,
    /// The group to grant. Granting the "Everyone" system group
    /// (`00000000-0000-0000-0000-000000000001`) un-restricts the value for all
    /// users without deleting the registry row. Rendered as a UUID string
    /// (utoipa `uuid` feature).
    pub group_id: Uuid,
}

/// Response listing the restricted-source registry.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct RestrictedSourceListResponse {
    pub restricted: Vec<RestrictedSourceType>,
    pub total: i64,
}

/// Response listing the group grants for a restricted `source_type`.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct SourceTypeGrantListResponse {
    pub grants: Vec<SourceTypeGrant>,
    pub total: i64,
}

// =============================================================================
// Restricted source registry
// =============================================================================

/// List every restricted `source_type` in the registry.
///
/// GET /api/source-scopes/restricted
#[utoipa::path(
    get,
    path = "/api/source-scopes/restricted",
    tag = "source_scopes",
    responses(
        (status = 200, description = "Restricted source registry", body = RestrictedSourceListResponse),
        (status = 403, description = "Forbidden - missing source_scopes:view"),
    ),
    security(("api_key" = []))
)]
pub async fn list_restricted(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
) -> Result<Json<RestrictedSourceListResponse>, ApiError> {
    ensure_permission(&auth, permissions::SOURCE_SCOPES_VIEW)?;

    let restricted = state
        .source_scope_repo
        .list_restricted()
        .await
        .map_err(map_scope_err)?;
    let total = restricted.len() as i64;

    Ok(Json(RestrictedSourceListResponse { restricted, total }))
}

/// Register a `source_type` as restricted (idempotent upsert — re-adding
/// refreshes the description).
///
/// POST /api/source-scopes/restricted
#[utoipa::path(
    post,
    path = "/api/source-scopes/restricted",
    tag = "source_scopes",
    request_body = AddRestrictedRequest,
    responses(
        (status = 200, description = "Source type registered as restricted", body = RestrictedSourceType),
        (status = 400, description = "Invalid source_type"),
        (status = 403, description = "Forbidden - missing source_scopes:manage"),
    ),
    security(("api_key" = []))
)]
pub async fn add_restricted(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Extension(client): Extension<ClientContext>,
    Json(req): Json<AddRestrictedRequest>,
) -> Result<Json<RestrictedSourceType>, ApiError> {
    ensure_permission(&auth, permissions::SOURCE_SCOPES_MANAGE)?;

    let source_type = normalize_source_type(&req.source_type)?;
    let description = req
        .description
        .as_deref()
        .map(str::trim)
        .filter(|d| !d.is_empty());

    let created = state
        .source_scope_repo
        .add_restricted(&source_type, description, Some(auth.user_id()))
        .await
        .map_err(map_scope_err)?;

    // Registry changed — force every user's deny-set to be re-derived.
    state.source_scope_resolver.invalidate();

    state.emit_audit(
        AuditEvent::builder(AuditSource::SourceScope, SOURCE_SCOPE_RESTRICTED)
            .actor(Some(auth.user_id()), None)
            .api_key(auth.api_key_id, auth.api_key_name.clone())
            .resource("source_scope", None, Some(source_type.clone()))
            .details(serde_json::json!({ "source_type": source_type }))
            .client_context(&client)
            .build(),
    );

    Ok(Json(created))
}

/// Un-restrict a `source_type` (removes it from the registry; cascades its
/// grants).
///
/// DELETE /api/source-scopes/restricted/{source_type}
#[utoipa::path(
    delete,
    path = "/api/source-scopes/restricted/{source_type}",
    tag = "source_scopes",
    params(
        ("source_type" = String, Path, description = "The restricted source_type value to remove")
    ),
    responses(
        (status = 204, description = "Source type un-restricted"),
        (status = 403, description = "Forbidden - missing source_scopes:manage"),
        (status = 404, description = "Source type was not restricted"),
    ),
    security(("api_key" = []))
)]
pub async fn remove_restricted(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Extension(client): Extension<ClientContext>,
    Path(source_type): Path<String>,
) -> Result<StatusCode, ApiError> {
    ensure_permission(&auth, permissions::SOURCE_SCOPES_MANAGE)?;

    let source_type = normalize_source_type(&source_type)?;

    state
        .source_scope_repo
        .remove_restricted(&source_type)
        .await
        .map_err(map_scope_err)?;

    state.source_scope_resolver.invalidate();

    state.emit_audit(
        AuditEvent::builder(AuditSource::SourceScope, SOURCE_SCOPE_UNRESTRICTED)
            .actor(Some(auth.user_id()), None)
            .api_key(auth.api_key_id, auth.api_key_name.clone())
            .resource("source_scope", None, Some(source_type.clone()))
            .details(serde_json::json!({ "source_type": source_type }))
            .client_context(&client)
            .build(),
    );

    Ok(StatusCode::NO_CONTENT)
}

// =============================================================================
// Grants
// =============================================================================

/// List the groups granted visibility of a restricted `source_type`.
///
/// GET /api/source-scopes/restricted/{source_type}/grants
#[utoipa::path(
    get,
    path = "/api/source-scopes/restricted/{source_type}/grants",
    tag = "source_scopes",
    params(
        ("source_type" = String, Path, description = "The restricted source_type value")
    ),
    responses(
        (status = 200, description = "Group grants for the source type", body = SourceTypeGrantListResponse),
        (status = 403, description = "Forbidden - missing source_scopes:view"),
    ),
    security(("api_key" = []))
)]
pub async fn list_grants(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Path(source_type): Path<String>,
) -> Result<Json<SourceTypeGrantListResponse>, ApiError> {
    ensure_permission(&auth, permissions::SOURCE_SCOPES_VIEW)?;

    let source_type = normalize_source_type(&source_type)?;

    let grants = state
        .source_scope_repo
        .list_grants(&source_type)
        .await
        .map_err(map_scope_err)?;
    let total = grants.len() as i64;

    Ok(Json(SourceTypeGrantListResponse { grants, total }))
}

/// Grant a group visibility of a restricted `source_type` (idempotent).
///
/// POST /api/source-scopes/grants
#[utoipa::path(
    post,
    path = "/api/source-scopes/grants",
    tag = "source_scopes",
    request_body = AddGrantRequest,
    responses(
        (status = 200, description = "Grant created", body = SourceTypeGrant),
        (status = 400, description = "Invalid source_type"),
        (status = 403, description = "Forbidden - missing source_scopes:manage"),
        (status = 500, description = "source_type is not registered as restricted"),
    ),
    security(("api_key" = []))
)]
pub async fn add_grant(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Extension(client): Extension<ClientContext>,
    Json(req): Json<AddGrantRequest>,
) -> Result<Json<SourceTypeGrant>, ApiError> {
    ensure_permission(&auth, permissions::SOURCE_SCOPES_MANAGE)?;

    let source_type = normalize_source_type(&req.source_type)?;

    let grant = state
        .source_scope_repo
        .add_grant(&source_type, req.group_id, Some(auth.user_id()))
        .await
        .map_err(map_scope_err)?;

    state.source_scope_resolver.invalidate();

    state.emit_audit(
        AuditEvent::builder(AuditSource::SourceScope, SOURCE_SCOPE_GRANTED)
            .actor(Some(auth.user_id()), None)
            .api_key(auth.api_key_id, auth.api_key_name.clone())
            .resource("source_scope", Some(req.group_id), Some(source_type.clone()))
            .details(serde_json::json!({
                "source_type": source_type,
                "group_id": req.group_id,
            }))
            .client_context(&client)
            .build(),
    );

    Ok(Json(grant))
}

/// Revoke a group's grant on a restricted `source_type`.
///
/// DELETE /api/source-scopes/grants/{source_type}/{group_id}
#[utoipa::path(
    delete,
    path = "/api/source-scopes/grants/{source_type}/{group_id}",
    tag = "source_scopes",
    params(
        ("source_type" = String, Path, description = "The restricted source_type value"),
        ("group_id" = String, Path, description = "The group whose grant is revoked")
    ),
    responses(
        (status = 204, description = "Grant revoked"),
        (status = 403, description = "Forbidden - missing source_scopes:manage"),
        (status = 404, description = "No such grant"),
    ),
    security(("api_key" = []))
)]
pub async fn remove_grant(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Extension(client): Extension<ClientContext>,
    Path((source_type, group_id)): Path<(String, Uuid)>,
) -> Result<StatusCode, ApiError> {
    ensure_permission(&auth, permissions::SOURCE_SCOPES_MANAGE)?;

    let source_type = normalize_source_type(&source_type)?;

    state
        .source_scope_repo
        .remove_grant(&source_type, group_id)
        .await
        .map_err(map_scope_err)?;

    state.source_scope_resolver.invalidate();

    state.emit_audit(
        AuditEvent::builder(AuditSource::SourceScope, SOURCE_SCOPE_REVOKED)
            .actor(Some(auth.user_id()), None)
            .api_key(auth.api_key_id, auth.api_key_name.clone())
            .resource("source_scope", Some(group_id), Some(source_type.clone()))
            .details(serde_json::json!({
                "source_type": source_type,
                "group_id": group_id,
            }))
            .client_context(&client)
            .build(),
    );

    Ok(StatusCode::NO_CONTENT)
}

/// Router for the per-source RBAC scope admin endpoints. Merged into the main
/// app router before `.with_state`, so it shares [`AppState`].
pub fn source_scopes_routes() -> Router<AppState> {
    Router::new()
        .route(
            "/api/source-scopes/restricted",
            get(list_restricted).post(add_restricted),
        )
        .route(
            "/api/source-scopes/restricted/{source_type}",
            delete(remove_restricted),
        )
        .route(
            "/api/source-scopes/restricted/{source_type}/grants",
            get(list_grants),
        )
        .route("/api/source-scopes/grants", post(add_grant))
        .route(
            "/api/source-scopes/grants/{source_type}/{group_id}",
            delete(remove_grant),
        )
}

/// OpenAPI documentation for per-source RBAC scope admin endpoints.
#[derive(utoipa::OpenApi)]
#[openapi(
    paths(
        list_restricted,
        add_restricted,
        remove_restricted,
        list_grants,
        add_grant,
        remove_grant,
    ),
    components(schemas(
        RestrictedSourceType,
        SourceTypeGrant,
        AddRestrictedRequest,
        AddGrantRequest,
        RestrictedSourceListResponse,
        SourceTypeGrantListResponse,
    )),
    tags(
        (name = "source_scopes", description = "Per-source RBAC scope registry and group grants")
    )
)]
pub struct SourceScopesApiDoc;
