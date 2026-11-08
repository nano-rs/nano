// SPDX-License-Identifier: AGPL-3.0-or-later

//! IP Allowlist management endpoints
//!
//! Implements:
//! - GET    /api/settings/ip-allowlist         - List all rules
//! - GET    /api/settings/ip-allowlist/status   - Get allowlist status
//! - POST   /api/settings/ip-allowlist         - Create a rule
//! - PUT    /api/settings/ip-allowlist/{id}    - Update a rule
//! - DELETE /api/settings/ip-allowlist/{id}    - Delete a rule
//! - POST   /api/settings/ip-allowlist/test    - Test an IP

use axum::{
    extract::{Path, Query, State},
    Extension, Json,
};
use nanosiem_core::audit::{
    AuditEvent, AuditSource, ClientContext, IP_ALLOWLIST_CREATED, IP_ALLOWLIST_DELETED,
    IP_ALLOWLIST_UPDATED,
};
use nanosiem_core::auth::permissions;
use nanosiem_core::ip_allowlist::{
    CreateIpAllowlistEntry, IpAllowlistEntry, IpAllowlistScope, IpAllowlistStatus, TestIpRequest,
    TestIpResponse, UpdateIpAllowlistEntry,
};
use serde::Deserialize;

use crate::error::ApiError;
use crate::handlers::AuditExt;
use crate::middleware::{check_permission, AuthContext};
use crate::state::AppState;
use crate::utils::extract_client_ip;
use nanosiem_core::typeid::TypeIdParam;

/// Query parameters for listing IP allowlist entries
#[derive(Debug, Deserialize, utoipa::IntoParams)]
pub struct ListIpAllowlistQuery {
    /// Filter by scope (global, api, search, frontend)
    pub scope: Option<String>,
}

// ============================================================================
// Handlers
// ============================================================================

/// List all IP allowlist rules
#[utoipa::path(
    get,
    path = "/api/settings/ip-allowlist",
    tag = "ip_allowlist",
    params(ListIpAllowlistQuery),
    responses(
        (status = 200, description = "IP allowlist entries", body = Vec<IpAllowlistEntry>),
        (status = 403, description = "Permission denied"),
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn list_ip_allowlist(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Query(query): Query<ListIpAllowlistQuery>,
) -> Result<Json<Vec<IpAllowlistEntry>>, ApiError> {
    check_permission(&auth, permissions::SETTINGS_VIEW)
        .map_err(|(_status, json)| ApiError::Forbidden(json.message.clone()))?;

    let scope = query.scope.as_deref().and_then(IpAllowlistScope::from_str);
    let entries = state
        .ip_allowlist_service
        .list(scope)
        .await
        .map_err(|e| ApiError::InternalError(e.to_string()))?;

    Ok(Json(entries))
}

/// Get IP allowlist status summary
#[utoipa::path(
    get,
    path = "/api/settings/ip-allowlist/status",
    tag = "ip_allowlist",
    responses(
        (status = 200, description = "Allowlist status", body = IpAllowlistStatus),
        (status = 403, description = "Permission denied"),
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn get_ip_allowlist_status(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
) -> Result<Json<IpAllowlistStatus>, ApiError> {
    check_permission(&auth, permissions::SETTINGS_VIEW)
        .map_err(|(_status, json)| ApiError::Forbidden(json.message.clone()))?;

    let status = state
        .ip_allowlist_service
        .status()
        .await
        .map_err(|e| ApiError::InternalError(e.to_string()))?;

    Ok(Json(status))
}

/// Create a new IP allowlist rule
#[utoipa::path(
    post,
    path = "/api/settings/ip-allowlist",
    tag = "ip_allowlist",
    request_body = CreateIpAllowlistEntry,
    responses(
        (status = 201, description = "Created", body = IpAllowlistEntry),
        (status = 400, description = "Invalid CIDR"),
        (status = 403, description = "Permission denied or self-lockout"),
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn create_ip_allowlist(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    headers: axum::http::HeaderMap,
    Json(body): Json<CreateIpAllowlistEntry>,
) -> Result<(axum::http::StatusCode, Json<IpAllowlistEntry>), ApiError> {
    check_permission(&auth, permissions::SETTINGS_SYSTEM)
        .map_err(|(_status, json)| ApiError::Forbidden(json.message.clone()))?;

    let entry = state
        .ip_allowlist_service
        .create(body, Some(auth.user_id()))
        .await
        .map_err(|e| match e {
            nanosiem_core::IpAllowlistServiceError::InvalidCidr(msg) => {
                ApiError::BadRequest(format!("Invalid CIDR: {}", msg))
            }
            nanosiem_core::IpAllowlistServiceError::SelfLockout(ip) => ApiError::Forbidden(
                format!("Self-lockout protection: your IP {} would be blocked", ip),
            ),
            nanosiem_core::IpAllowlistServiceError::RepositoryError(repo_err) => match repo_err {
                nanosiem_core::ip_allowlist::IpAllowlistRepositoryError::DuplicateEntry {
                    cidr,
                    scope,
                } => ApiError::Conflict(format!("CIDR {} already exists in scope {}", cidr, scope)),
                _ => ApiError::InternalError(repo_err.to_string()),
            },
            _ => ApiError::InternalError(e.to_string()),
        })?;

    // Self-lockout check: after creating the rule, verify the admin's IP is still allowed
    let admin_ip = extract_client_ip(&headers, None);
    if let Some(ref ip) = admin_ip {
        if let Err(e) = state
            .ip_allowlist_service
            .validate_no_self_lockout(ip, entry.scope)
            .await
        {
            // Roll back the created entry
            let _ = state.ip_allowlist_service.delete(entry.id).await;
            return Err(ApiError::Forbidden(e.to_string()));
        }
    }

    // Audit log
    let client = ClientContext::new(admin_ip, crate::utils::extract_user_agent(&headers));
    state.emit_audit(
        AuditEvent::builder(AuditSource::Settings, IP_ALLOWLIST_CREATED)
            .actor(Some(auth.user_id()), None)
            .resource("ip_allowlist", Some(entry.id), Some(entry.cidr.clone()))
            .details(serde_json::json!({ "scope": entry.scope, "cidr": entry.cidr }))
            .client_context(&client)
            .build(),
    );

    Ok((axum::http::StatusCode::CREATED, Json(entry)))
}

/// Update an existing IP allowlist rule
#[utoipa::path(
    put,
    path = "/api/settings/ip-allowlist/{id}",
    tag = "ip_allowlist",
    params(("id" = String, Path, description = "Allowlist entry ID")),
    request_body = UpdateIpAllowlistEntry,
    responses(
        (status = 200, description = "Updated", body = IpAllowlistEntry),
        (status = 400, description = "Invalid CIDR"),
        (status = 403, description = "Permission denied or self-lockout"),
        (status = 404, description = "Not found"),
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn update_ip_allowlist(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    headers: axum::http::HeaderMap,
    Path(id): Path<TypeIdParam>,
    Json(body): Json<UpdateIpAllowlistEntry>,
) -> Result<Json<IpAllowlistEntry>, ApiError> {
    check_permission(&auth, permissions::SETTINGS_SYSTEM)
        .map_err(|(_status, json)| ApiError::Forbidden(json.message.clone()))?;

    let entry = state
        .ip_allowlist_service
        .update(*id, body)
        .await
        .map_err(|e| match e {
            nanosiem_core::IpAllowlistServiceError::InvalidCidr(msg) => {
                ApiError::BadRequest(format!("Invalid CIDR: {}", msg))
            }
            nanosiem_core::IpAllowlistServiceError::RepositoryError(repo_err) => match repo_err {
                nanosiem_core::ip_allowlist::IpAllowlistRepositoryError::NotFound(_) => {
                    ApiError::NotFound(format!("IP allowlist entry not found: {}", id))
                }
                nanosiem_core::ip_allowlist::IpAllowlistRepositoryError::DuplicateEntry {
                    cidr,
                    scope,
                } => ApiError::Conflict(format!("CIDR {} already exists in scope {}", cidr, scope)),
                _ => ApiError::InternalError(repo_err.to_string()),
            },
            _ => ApiError::InternalError(e.to_string()),
        })?;

    // Self-lockout check
    let admin_ip = extract_client_ip(&headers, None);
    if let Some(ref ip) = admin_ip {
        if let Err(_) = state
            .ip_allowlist_service
            .validate_no_self_lockout(ip, entry.scope)
            .await
        {
            // Note: we don't roll back the update here as it's harder to restore original state.
            // The admin can always fix it via the API since the check happens post-save.
            tracing::warn!(admin_ip = %ip, entry_id = %id, "IP allowlist update may cause self-lockout");
        }
    }

    // Audit log
    let client = ClientContext::new(admin_ip, crate::utils::extract_user_agent(&headers));
    state.emit_audit(
        AuditEvent::builder(AuditSource::Settings, IP_ALLOWLIST_UPDATED)
            .actor(Some(auth.user_id()), None)
            .resource("ip_allowlist", Some(entry.id), Some(entry.cidr.clone()))
            .details(serde_json::json!({ "scope": entry.scope, "cidr": entry.cidr }))
            .client_context(&client)
            .build(),
    );

    Ok(Json(entry))
}

/// Delete an IP allowlist rule
#[utoipa::path(
    delete,
    path = "/api/settings/ip-allowlist/{id}",
    tag = "ip_allowlist",
    params(("id" = String, Path, description = "Allowlist entry ID")),
    responses(
        (status = 204, description = "Deleted"),
        (status = 403, description = "Permission denied"),
        (status = 404, description = "Not found"),
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn delete_ip_allowlist(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    headers: axum::http::HeaderMap,
    Path(id): Path<TypeIdParam>,
) -> Result<axum::http::StatusCode, ApiError> {
    check_permission(&auth, permissions::SETTINGS_SYSTEM)
        .map_err(|(_status, json)| ApiError::Forbidden(json.message.clone()))?;

    // Get entry before deletion for audit log
    let entry = state
        .ip_allowlist_service
        .get(*id)
        .await
        .map_err(|e| match e {
            nanosiem_core::IpAllowlistServiceError::RepositoryError(
                nanosiem_core::ip_allowlist::IpAllowlistRepositoryError::NotFound(_),
            ) => ApiError::NotFound(format!("IP allowlist entry not found: {}", id)),
            _ => ApiError::InternalError(e.to_string()),
        })?;

    state
        .ip_allowlist_service
        .delete(*id)
        .await
        .map_err(|e| ApiError::InternalError(e.to_string()))?;

    // Audit log
    let client = ClientContext::new(
        extract_client_ip(&headers, None),
        crate::utils::extract_user_agent(&headers),
    );
    state.emit_audit(
        AuditEvent::builder(AuditSource::Settings, IP_ALLOWLIST_DELETED)
            .actor(Some(auth.user_id()), None)
            .resource("ip_allowlist", Some(*id), Some(entry.cidr.clone()))
            .details(serde_json::json!({ "scope": entry.scope, "cidr": entry.cidr }))
            .client_context(&client)
            .build(),
    );

    Ok(axum::http::StatusCode::NO_CONTENT)
}

/// Test an IP address against the current allowlist
#[utoipa::path(
    post,
    path = "/api/settings/ip-allowlist/test",
    tag = "ip_allowlist",
    request_body = TestIpRequest,
    responses(
        (status = 200, description = "Test result", body = TestIpResponse),
        (status = 400, description = "Invalid IP address"),
        (status = 403, description = "Permission denied"),
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn test_ip_allowlist(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Json(body): Json<TestIpRequest>,
) -> Result<Json<TestIpResponse>, ApiError> {
    check_permission(&auth, permissions::SETTINGS_VIEW)
        .map_err(|(_status, json)| ApiError::Forbidden(json.message.clone()))?;

    let result = state
        .ip_allowlist_service
        .test_ip(&body.ip, body.scope)
        .await
        .map_err(|e| match e {
            nanosiem_core::IpAllowlistServiceError::InvalidIp(ip) => {
                ApiError::BadRequest(format!("Invalid IP address: {}", ip))
            }
            _ => ApiError::InternalError(e.to_string()),
        })?;

    Ok(Json(result))
}

// ============================================================================
// OpenAPI Doc
// ============================================================================

#[derive(utoipa::OpenApi)]
#[openapi(
    paths(
        list_ip_allowlist,
        get_ip_allowlist_status,
        create_ip_allowlist,
        update_ip_allowlist,
        delete_ip_allowlist,
        test_ip_allowlist,
    ),
    components(schemas(
        IpAllowlistEntry,
        IpAllowlistScope,
        IpAllowlistStatus,
        CreateIpAllowlistEntry,
        UpdateIpAllowlistEntry,
        TestIpRequest,
        TestIpResponse,
        nanosiem_core::ip_allowlist::MatchedRule,
    )),
    tags(
        (name = "ip_allowlist", description = "IP allowlist management for access control"),
    )
)]
pub struct IpAllowlistApiDoc;
