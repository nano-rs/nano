// SPDX-License-Identifier: AGPL-3.0-or-later

//! Identity Provider API handlers
//!
//! Endpoints for managing identity providers (Entra ID, Google Workspace, AD)
//! and browsing the unified user directory.
//!
//! Provider management:
//! - GET    /api/settings/identity-providers            — list providers
//! - POST   /api/settings/identity-providers            — create provider
//! - GET    /api/settings/identity-providers/{id}       — get provider
//! - PUT    /api/settings/identity-providers/{id}       — update provider
//! - DELETE /api/settings/identity-providers/{id}       — delete provider
//! - POST   /api/settings/identity-providers/{id}/credentials — update credentials
//! - POST   /api/settings/identity-providers/{id}/test  — test connection
//! - POST   /api/settings/identity-providers/{id}/sync  — trigger sync
//!
//! AD push:
//! - POST   /api/identity-providers/{id}/push           — push users (bearer token)
//!
//! User directory:
//! - GET    /api/identity/users                         — list users
//! - GET    /api/identity/users/{id}                    — get user
//! - GET    /api/identity/stats                         — identity stats

use axum::{
    Extension, Json,
    extract::{Path, Query, State},
};
use chrono::{DateTime, NaiveDateTime, Utc};
use nanosiem_core::audit::{AuditEvent, AuditSource};
use nanosiem_core::auth::{permissions, repository::audit_actions};
use nanosiem_core::identity::types::ConnectionTestResult;
use nanosiem_core::identity::{
    CreateIdentityProvider, IdentityProviderSummary, IdentityStats, ListUsersParams,
    UpdateIdentityProvider, UserListResponse, UserRecord,
};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::handlers::AuditExt;
use crate::middleware::{AuthContext, check_permission};
use crate::{error::ApiError, state::AppState};

// Note: `From<IdentityServiceError> for ApiError` lifted to
// nanosiem-api-lib in NAN-752 (orphan rule — `ApiError` lives there now).

// ============================================================================
// Response Types
// ============================================================================

#[derive(Debug, Serialize, ToSchema)]
pub struct ListIdentityProvidersResponse {
    pub providers: Vec<IdentityProviderSummary>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct SyncTriggerResponse {
    pub message: String,
    pub provider_id: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct IdentityConnectionTestResponse {
    pub success: bool,
    pub response_time_ms: Option<u64>,
    pub error: Option<String>,
    pub user_count_sample: Option<u64>,
}

impl From<ConnectionTestResult> for IdentityConnectionTestResponse {
    fn from(r: ConnectionTestResult) -> Self {
        Self {
            success: r.success,
            response_time_ms: r.response_time_ms,
            error: r.error,
            user_count_sample: r.user_count_sample,
        }
    }
}

// ============================================================================
// Request Types
// ============================================================================

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateIdentityProviderRequest {
    pub id: String,
    pub name: String,
    pub provider_type: String,
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub config: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateIdentityProviderRequest {
    pub name: Option<String>,
    pub enabled: Option<bool>,
    pub config: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateIdentityCredentialsRequest {
    pub credentials: serde_json::Value,
}

// ============================================================================
// Provider Management Handlers
// ============================================================================

/// List all identity providers
#[utoipa::path(
    get,
    path = "/api/settings/identity-providers",
    tag = "identity",
    responses(
        (status = 200, description = "List of identity providers", body = ListIdentityProvidersResponse),
        (status = 403, description = "Forbidden"),
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_identity_providers(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
) -> Result<Json<ListIdentityProvidersResponse>, ApiError> {
    check_permission(&auth, permissions::ENRICHMENTS_VIEW)
        .map_err(|_| ApiError::Forbidden("Missing permission: enrichments:view".into()))?;

    let providers = state.identity_service.list_providers().await?;
    let summaries: Vec<IdentityProviderSummary> = providers.into_iter().map(Into::into).collect();

    Ok(Json(ListIdentityProvidersResponse {
        providers: summaries,
    }))
}

/// Get a specific identity provider
#[utoipa::path(
    get,
    path = "/api/settings/identity-providers/{id}",
    tag = "identity",
    params(("id" = String, Path, description = "Provider ID")),
    responses(
        (status = 200, description = "Provider details", body = IdentityProviderSummary),
        (status = 403, description = "Forbidden"),
        (status = 404, description = "Not found"),
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_identity_provider(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<String>,
) -> Result<Json<IdentityProviderSummary>, ApiError> {
    check_permission(&auth, permissions::ENRICHMENTS_VIEW)
        .map_err(|_| ApiError::Forbidden("Missing permission: enrichments:view".into()))?;

    let provider = state.identity_service.get_provider(&id).await?;
    Ok(Json(IdentityProviderSummary::from(provider)))
}

/// Create a new identity provider
#[utoipa::path(
    post,
    path = "/api/settings/identity-providers",
    tag = "identity",
    request_body = CreateIdentityProviderRequest,
    responses(
        (status = 200, description = "Provider created", body = IdentityProviderSummary),
        (status = 400, description = "Validation error"),
        (status = 403, description = "Forbidden"),
        (status = 409, description = "Already exists"),
    ),
    security(("bearer_auth" = []))
)]
pub async fn create_identity_provider(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Json(req): Json<CreateIdentityProviderRequest>,
) -> Result<Json<IdentityProviderSummary>, ApiError> {
    check_permission(&auth, permissions::ENRICHMENTS_CONFIGURE)
        .map_err(|_| ApiError::Forbidden("Missing permission: enrichments:configure".into()))?;

    let create = CreateIdentityProvider {
        id: req.id,
        name: req.name,
        provider_type: req.provider_type,
        enabled: req.enabled,
        config: req.config,
    };

    let provider = state.identity_service.create_provider(&create).await?;

    state.emit_audit(
        AuditEvent::builder(
            AuditSource::Identity,
            audit_actions::IDENTITY_PROVIDER_CREATED,
        )
        .actor(Some(auth.user_id()), None)
        .resource(
            "identity_provider",
            None,
            Some(format!("{} ({})", provider.name, provider.id)),
        )
        .build(),
    );

    Ok(Json(IdentityProviderSummary::from(provider)))
}

/// Update an identity provider
#[utoipa::path(
    put,
    path = "/api/settings/identity-providers/{id}",
    tag = "identity",
    params(("id" = String, Path, description = "Provider ID")),
    request_body = UpdateIdentityProviderRequest,
    responses(
        (status = 200, description = "Provider updated", body = IdentityProviderSummary),
        (status = 403, description = "Forbidden"),
        (status = 404, description = "Not found"),
    ),
    security(("bearer_auth" = []))
)]
pub async fn update_identity_provider(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<String>,
    Json(req): Json<UpdateIdentityProviderRequest>,
) -> Result<Json<IdentityProviderSummary>, ApiError> {
    check_permission(&auth, permissions::ENRICHMENTS_CONFIGURE)
        .map_err(|_| ApiError::Forbidden("Missing permission: enrichments:configure".into()))?;

    let update = UpdateIdentityProvider {
        name: req.name,
        enabled: req.enabled,
        config: req.config,
    };

    let provider = state.identity_service.update_provider(&id, &update).await?;

    state.emit_audit(
        AuditEvent::builder(
            AuditSource::Identity,
            audit_actions::IDENTITY_PROVIDER_UPDATED,
        )
        .actor(Some(auth.user_id()), None)
        .resource(
            "identity_provider",
            None,
            Some(format!("{} ({})", provider.name, provider.id)),
        )
        .build(),
    );

    Ok(Json(IdentityProviderSummary::from(provider)))
}

/// Delete an identity provider
#[utoipa::path(
    delete,
    path = "/api/settings/identity-providers/{id}",
    tag = "identity",
    params(("id" = String, Path, description = "Provider ID")),
    responses(
        (status = 200, description = "Provider deleted"),
        (status = 403, description = "Forbidden"),
        (status = 404, description = "Not found"),
    ),
    security(("bearer_auth" = []))
)]
pub async fn delete_identity_provider(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    check_permission(&auth, permissions::ENRICHMENTS_CONFIGURE)
        .map_err(|_| ApiError::Forbidden("Missing permission: enrichments:configure".into()))?;

    state.identity_service.delete_provider(&id).await?;

    state.emit_audit(
        AuditEvent::builder(
            AuditSource::Identity,
            audit_actions::IDENTITY_PROVIDER_DELETED,
        )
        .actor(Some(auth.user_id()), None)
        .resource("identity_provider", None, Some(id.clone()))
        .build(),
    );

    Ok(Json(
        serde_json::json!({ "success": true, "message": format!("Provider {} deleted", id) }),
    ))
}

/// Update identity provider credentials
#[utoipa::path(
    post,
    path = "/api/settings/identity-providers/{id}/credentials",
    tag = "identity",
    params(("id" = String, Path, description = "Provider ID")),
    request_body = UpdateIdentityCredentialsRequest,
    responses(
        (status = 200, description = "Credentials updated"),
        (status = 403, description = "Forbidden"),
        (status = 404, description = "Not found"),
    ),
    security(("bearer_auth" = []))
)]
pub async fn update_identity_credentials(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<String>,
    Json(req): Json<UpdateIdentityCredentialsRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    check_permission(&auth, permissions::ENRICHMENTS_CONFIGURE)
        .map_err(|_| ApiError::Forbidden("Missing permission: enrichments:configure".into()))?;

    state
        .identity_service
        .update_credentials(&id, &req.credentials)
        .await?;

    state.emit_audit(
        AuditEvent::builder(
            AuditSource::Identity,
            audit_actions::IDENTITY_PROVIDER_CREDENTIALS_UPDATED,
        )
        .actor(Some(auth.user_id()), None)
        .resource("identity_provider", None, Some(id.clone()))
        .build(),
    );

    Ok(Json(
        serde_json::json!({ "success": true, "message": "Credentials updated" }),
    ))
}

/// Test identity provider connection
#[utoipa::path(
    post,
    path = "/api/settings/identity-providers/{id}/test",
    tag = "identity",
    params(("id" = String, Path, description = "Provider ID")),
    responses(
        (status = 200, description = "Connection test result", body = IdentityConnectionTestResponse),
        (status = 403, description = "Forbidden"),
        (status = 404, description = "Not found"),
    ),
    security(("bearer_auth" = []))
)]
pub async fn test_identity_connection(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<String>,
) -> Result<Json<IdentityConnectionTestResponse>, ApiError> {
    check_permission(&auth, permissions::ENRICHMENTS_CONFIGURE)
        .map_err(|_| ApiError::Forbidden("Missing permission: enrichments:configure".into()))?;

    let result = state.identity_service.test_connection(&id).await?;
    Ok(Json(IdentityConnectionTestResponse::from(result)))
}

/// Trigger a manual sync for an identity provider
#[utoipa::path(
    post,
    path = "/api/settings/identity-providers/{id}/sync",
    tag = "identity",
    params(("id" = String, Path, description = "Provider ID")),
    responses(
        (status = 202, description = "Sync triggered", body = SyncTriggerResponse),
        (status = 403, description = "Forbidden"),
        (status = 404, description = "Not found"),
        (status = 409, description = "Sync already in progress"),
    ),
    security(("bearer_auth" = []))
)]
pub async fn trigger_identity_sync(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<String>,
) -> Result<Json<SyncTriggerResponse>, ApiError> {
    check_permission(&auth, permissions::ENRICHMENTS_CONFIGURE)
        .map_err(|_| ApiError::Forbidden("Missing permission: enrichments:configure".into()))?;

    state.emit_audit(
        AuditEvent::builder(
            AuditSource::Identity,
            audit_actions::IDENTITY_SYNC_TRIGGERED,
        )
        .actor(Some(auth.user_id()), None)
        .resource("identity_provider", None, Some(id.clone()))
        .build(),
    );

    // Spawn the sync in the background so we can return 202 immediately
    let service = state.identity_service.clone();
    let provider_id = id.clone();
    let audit_state = state.clone();
    tokio::spawn(async move {
        match service.sync_provider(&provider_id).await {
            Ok(result) => {
                tracing::info!(
                    provider_id = %provider_id,
                    users_synced = result.users_synced,
                    "Manual sync completed"
                );
                audit_state.emit_audit(
                    AuditEvent::builder(
                        AuditSource::Identity,
                        audit_actions::IDENTITY_SYNC_COMPLETED,
                    )
                    .resource("identity_provider", None, Some(provider_id))
                    .build(),
                );
            }
            Err(e) => {
                tracing::error!(provider_id = %provider_id, error = %e, "Manual sync failed");
            }
        }
    });

    Ok(Json(SyncTriggerResponse {
        message: "Sync started".into(),
        provider_id: id,
    }))
}

// NAN-1151 (3d): the AD `/push` endpoint is retired. AD identity now flows
// through the nano_enrich lane like every other source — the external collector
// POSTs nano_enrich records (kind=identity, source=ad) to the Vector ingest
// endpoint, normalized by the repo-sourced enrichments/identity/ad parser. No
// in-app ingestion path or hard-coded mapping remains.

// ============================================================================
// User Lookup
// ============================================================================

#[derive(Debug, Deserialize, utoipa::IntoParams)]
pub struct LookupUserQuery {
    /// Username, UPN, or email to look up
    pub q: String,
}

#[derive(Debug, Deserialize, utoipa::IntoParams)]
pub struct ResolveIdentityQuery {
    /// IP address to resolve
    pub ip: String,
    /// Optional event timestamp for temporal resolution (RFC3339)
    pub timestamp: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct IdentityResolveMatchResponse {
    pub hostname: Option<String>,
    pub user: Option<String>,
    pub department: Option<String>,
    pub title: Option<String>,
    pub confidence: String,
    pub source: Option<String>,
    pub last_seen: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct IdentityResolveResponse {
    pub ip: String,
    pub r#match: Option<IdentityResolveMatchResponse>,
}

fn normalize_identity_user_candidates(user: &str) -> Vec<String> {
    let trimmed = user.trim();
    if trimmed.is_empty() {
        return Vec::new();
    }

    let mut candidates = Vec::new();
    candidates.push(trimmed.to_string());

    if let Some((_, suffix)) = trimmed.rsplit_once('\\') {
        candidates.push(suffix.to_string());
    }

    if let Some((prefix, _)) = trimmed.split_once('@') {
        candidates.push(prefix.to_string());
    }

    candidates.sort();
    candidates.dedup();
    candidates
}

fn identity_confidence(reference_time: DateTime<Utc>, observed_at: DateTime<Utc>) -> &'static str {
    let age = reference_time.signed_duration_since(observed_at);
    if age.num_seconds() < 0 {
        "high"
    } else if age.num_hours() < 1 {
        "high"
    } else if age.num_hours() < 4 {
        "medium"
    } else if age.num_hours() < 24 {
        "low"
    } else {
        "stale"
    }
}

/// Look up a user by username, UPN, or email
///
/// Performs an exact case-insensitive match against the user registry.
/// Returns the best match (prefers active accounts) or 404 if not found.
#[utoipa::path(
    get,
    path = "/api/identity/users/lookup",
    tag = "identity",
    params(LookupUserQuery),
    responses(
        (status = 200, description = "User found", body = UserRecord),
        (status = 403, description = "Forbidden"),
        (status = 404, description = "No matching user found"),
    ),
    security(("bearer_auth" = []))
)]
pub async fn lookup_identity_user(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Query(params): Query<LookupUserQuery>,
) -> Result<Json<UserRecord>, ApiError> {
    check_permission(&auth, permissions::ENRICHMENTS_VIEW)
        .map_err(|_| ApiError::Forbidden("Missing permission: enrichments:view".into()))?;

    let user = state
        .identity_service
        .lookup_user_by_identifier(&params.q)
        .await?
        .ok_or_else(|| ApiError::NotFound(format!("No user found for identifier: {}", params.q)))?;

    Ok(Json(user))
}

/// Resolve an IP address to the most recent observed identity mapping.
///
/// Uses ClickHouse identity observations to find the latest hostname/user
/// for an IP, optionally bounded to an event timestamp for temporal accuracy.
#[utoipa::path(
    get,
    path = "/api/identity/resolve",
    tag = "identity",
    params(ResolveIdentityQuery),
    responses(
        (status = 200, description = "Resolved identity match or null when unavailable", body = IdentityResolveResponse),
        (status = 403, description = "Forbidden"),
        (status = 400, description = "Invalid timestamp"),
    ),
    security(("bearer_auth" = []))
)]
pub async fn resolve_identity_ip(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Query(params): Query<ResolveIdentityQuery>,
) -> Result<Json<IdentityResolveResponse>, ApiError> {
    check_permission(&auth, permissions::ENRICHMENTS_VIEW)
        .map_err(|_| ApiError::Forbidden("Missing permission: enrichments:view".into()))?;

    let ip = params.ip.trim().to_string();
    if ip.is_empty() {
        return Ok(Json(IdentityResolveResponse { ip, r#match: None }));
    }

    let reference_time = match params.timestamp.as_deref() {
        Some(ts) => DateTime::parse_from_rfc3339(ts)
            .map(|dt| dt.with_timezone(&Utc))
            .map_err(|_| ApiError::ValidationError("Invalid timestamp; expected RFC3339".into()))?,
        None => Utc::now(),
    };

    let dual_pool = state.dual_pool();

    let identity_table = dual_pool.table_names().read("identity_observations");
    let sql = format!(
        r#"
        SELECT hostname, fqdn, user, source, toString(observed_at) AS observed_at
        FROM (
            SELECT
                hostname,
                fqdn,
                user,
                source,
                observed_at,
                ROW_NUMBER() OVER (ORDER BY source_priority DESC, observed_at DESC) AS rn
            FROM {identity_table}
            WHERE ip = ?
              AND observed_at <= parseDateTime64BestEffort(?)
              AND (hostname != '' OR user != '' OR fqdn != '')
        )
        WHERE rn = 1
        LIMIT 1
    "#
    );

    let row = match dual_pool
        .clickhouse()
        .query(&sql)
        .bind(&ip)
        .bind(reference_time.to_rfc3339())
        .fetch_all::<(String, String, String, String, String)>()
        .await
    {
        Ok(rows) => rows.into_iter().next(),
        Err(err) => {
            tracing::warn!(ip = %ip, error = %err, "Identity resolution query failed");
            None
        }
    };

    let Some((hostname, fqdn, user, source, observed_at_str)) = row else {
        return Ok(Json(IdentityResolveResponse { ip, r#match: None }));
    };

    let observed_at = NaiveDateTime::parse_from_str(&observed_at_str, "%Y-%m-%d %H:%M:%S%.f")
        .map(|dt| DateTime::<Utc>::from_naive_utc_and_offset(dt, Utc))
        .or_else(|_| {
            DateTime::parse_from_rfc3339(&observed_at_str).map(|dt| dt.with_timezone(&Utc))
        })
        .unwrap_or(reference_time);

    let mut department = None;
    let mut title = None;
    for candidate in normalize_identity_user_candidates(&user) {
        if let Some(record) = state
            .identity_service
            .lookup_user_by_identifier(&candidate)
            .await?
        {
            department = record.department;
            title = record.title;
            break;
        }
    }

    let resolved_hostname = if !fqdn.trim().is_empty() {
        Some(fqdn)
    } else if !hostname.trim().is_empty() {
        Some(hostname)
    } else {
        None
    };

    let resolved_user = if user.trim().is_empty() {
        None
    } else {
        Some(user)
    };

    Ok(Json(IdentityResolveResponse {
        ip,
        r#match: Some(IdentityResolveMatchResponse {
            hostname: resolved_hostname,
            user: resolved_user,
            department,
            title,
            confidence: identity_confidence(reference_time, observed_at).to_string(),
            source: if source.trim().is_empty() {
                None
            } else {
                Some(source)
            },
            last_seen: Some(observed_at.to_rfc3339()),
        }),
    }))
}

// ============================================================================
// User Directory Handlers
// ============================================================================

/// List users from the identity registry
#[utoipa::path(
    get,
    path = "/api/identity/users",
    tag = "identity",
    params(ListUsersParams),
    responses(
        (status = 200, description = "Paginated user list", body = UserListResponse),
        (status = 403, description = "Forbidden"),
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_identity_users(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Query(params): Query<ListUsersParams>,
) -> Result<Json<UserListResponse>, ApiError> {
    check_permission(&auth, permissions::ENRICHMENTS_VIEW)
        .map_err(|_| ApiError::Forbidden("Missing permission: enrichments:view".into()))?;

    let result = state.identity_service.list_users(&params).await?;
    Ok(Json(result))
}

/// Get a specific user from the identity registry
#[utoipa::path(
    get,
    path = "/api/identity/users/{id}",
    tag = "identity",
    params(("id" = String, Path, description = "Composite user id 'provider_id|external_id' (NAN-1117: replaced the legacy numeric id)")),
    responses(
        (status = 200, description = "User details", body = UserRecord),
        (status = 403, description = "Forbidden"),
        (status = 404, description = "User not found"),
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_identity_user(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<String>,
) -> Result<Json<UserRecord>, ApiError> {
    check_permission(&auth, permissions::ENRICHMENTS_VIEW)
        .map_err(|_| ApiError::Forbidden("Missing permission: enrichments:view".into()))?;

    let user = state.identity_service.get_user(&id).await?;
    Ok(Json(user))
}

/// Get identity provider statistics
#[utoipa::path(
    get,
    path = "/api/identity/stats",
    tag = "identity",
    responses(
        (status = 200, description = "Identity statistics", body = IdentityStats),
        (status = 403, description = "Forbidden"),
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_identity_stats(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
) -> Result<Json<IdentityStats>, ApiError> {
    check_permission(&auth, permissions::ENRICHMENTS_VIEW)
        .map_err(|_| ApiError::Forbidden("Missing permission: enrichments:view".into()))?;

    let stats = state.identity_service.get_stats().await?;
    Ok(Json(stats))
}

// ============================================================================
// OpenAPI Documentation
// ============================================================================

#[derive(utoipa::OpenApi)]
#[openapi(
    paths(
        list_identity_providers,
        get_identity_provider,
        create_identity_provider,
        update_identity_provider,
        delete_identity_provider,
        update_identity_credentials,
        test_identity_connection,
        trigger_identity_sync,
        lookup_identity_user,
        resolve_identity_ip,
        list_identity_users,
        get_identity_user,
        get_identity_stats,
    ),
    components(schemas(
        ListIdentityProvidersResponse,
        CreateIdentityProviderRequest,
        UpdateIdentityProviderRequest,
        UpdateIdentityCredentialsRequest,
        IdentityConnectionTestResponse,
        SyncTriggerResponse,
        IdentityResolveMatchResponse,
        IdentityResolveResponse,
    ))
)]
pub struct IdentityApiDoc;
