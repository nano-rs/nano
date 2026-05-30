// SPDX-License-Identifier: AGPL-3.0-or-later

//! API Key Management handlers
//!
//! Requirements: 12.1, 12.6, 12.8, 12.9
//!
//! This module provides handlers for:
//! - list_keys() - List all API keys (masked)
//! - create_key() - Create a new API key
//! - delete_key() - Delete an API key
//! - enable_key() - Enable a disabled API key
//! - disable_key() - Disable an API key

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    Json,
};
use serde::{Deserialize, Deserializer, Serialize};
use uuid::Uuid;

use nanosiem_core::audit::{
    AuditEvent, AuditSource, ClientContext, APIKEY_CREATED, APIKEY_DELETED, APIKEY_DISABLED,
    APIKEY_ENABLED, APIKEY_RESET, APIKEY_UPDATED,
};
use nanosiem_core::auth::{
    permissions, ApiKey, ApiKeyCreated, ApiKeyServiceError, CreateApiKeyRequest,
};
use nanosiem_core::typeid::TypeIdParam;

use crate::handlers::AuditExt;
use crate::middleware::{
    check_permission, require_session_auth, require_session_or_self, AuthContext,
};
use crate::state::AppState;

/// Error response for API key endpoints
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct ApiKeyApiError {
    pub error: String,
    pub message: String,
}

impl ApiKeyApiError {
    pub fn new(error: &str, message: &str) -> Self {
        Self {
            error: error.to_string(),
            message: message.to_string(),
        }
    }

    pub fn from_service_error(err: &ApiKeyServiceError) -> (StatusCode, Self) {
        let (status, error_type) = match err {
            ApiKeyServiceError::NotFound => (StatusCode::NOT_FOUND, "api_key_not_found"),
            ApiKeyServiceError::Disabled => (StatusCode::BAD_REQUEST, "api_key_disabled"),
            ApiKeyServiceError::Expired => (StatusCode::BAD_REQUEST, "api_key_expired"),
            ApiKeyServiceError::ValidationFailed => (StatusCode::UNAUTHORIZED, "validation_failed"),
            ApiKeyServiceError::InsufficientPermissions(_) => {
                (StatusCode::FORBIDDEN, "insufficient_permissions")
            }
            ApiKeyServiceError::RateLimitExceeded => {
                (StatusCode::TOO_MANY_REQUESTS, "rate_limit_exceeded")
            }
            ApiKeyServiceError::HashingError(_) => {
                (StatusCode::INTERNAL_SERVER_ERROR, "hashing_error")
            }
            ApiKeyServiceError::InvalidFormat => (StatusCode::BAD_REQUEST, "invalid_format"),
            ApiKeyServiceError::RepositoryError(_) => {
                (StatusCode::INTERNAL_SERVER_ERROR, "database_error")
            }
        };

        (status, Self::new(error_type, &err.to_string()))
    }
}

/// Query parameters for listing API keys
#[derive(Debug, Deserialize, utoipa::IntoParams)]
pub struct ListApiKeysQuery {
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

/// API key list response
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct ApiKeyListResponse {
    pub api_keys: Vec<ApiKeySummary>,
    pub total: i64,
}

/// API key summary for list response (masked key)
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct ApiKeySummary {
    #[serde(with = "nanosiem_core::typeid::api_key")]
    #[schema(value_type = String)]
    pub id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub key_prefix: String,
    pub permissions: Vec<String>,
    pub enabled: bool,
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
    pub rate_limit: Option<i32>,
    pub last_used_at: Option<chrono::DateTime<chrono::Utc>>,
    pub last_used_ip: Option<String>,
    #[serde(with = "nanosiem_core::typeid::user::opt")]
    #[schema(value_type = Option<String>)]
    pub created_by: Option<Uuid>,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

impl From<ApiKey> for ApiKeySummary {
    fn from(key: ApiKey) -> Self {
        Self {
            id: key.id,
            name: key.name,
            description: key.description,
            key_prefix: key.key_prefix,
            permissions: key.permissions,
            enabled: key.enabled,
            expires_at: key.expires_at,
            rate_limit: key.rate_limit,
            last_used_at: key.last_used_at,
            last_used_ip: key.last_used_ip,
            created_by: key.created_by,
            created_at: key.created_at,
        }
    }
}

/// List all API keys (masked)
///
/// Requirements: 12.8 - Allow administrators to view all API keys (masked) with last used timestamp
///
/// GET /api/api-keys
#[utoipa::path(
    get,
    path = "/api/api-keys",
    tag = "api_keys",
    params(ListApiKeysQuery),
    responses(
        (status = 200, description = "Successfully retrieved API keys", body = ApiKeyListResponse),
        (status = 403, description = "Permission denied", body = ApiKeyApiError),
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn list_keys(
    State(state): State<AppState>,
    auth: axum::Extension<AuthContext>,
    Query(_query): Query<ListApiKeysQuery>,
) -> Result<Json<ApiKeyListResponse>, (StatusCode, Json<ApiKeyApiError>)> {
    check_permission(&auth, permissions::APIKEYS_VIEW)
        .map_err(|(s, j)| (s, Json(ApiKeyApiError::new(&j.error, &j.message))))?;

    let keys = state.api_key_service.list_keys().await.map_err(|e| {
        let (status, err) = ApiKeyApiError::from_service_error(&e);
        (status, Json(err))
    })?;

    let total = keys.len() as i64;
    let api_keys: Vec<ApiKeySummary> = keys.into_iter().map(ApiKeySummary::from).collect();

    Ok(Json(ApiKeyListResponse { api_keys, total }))
}

/// Get a single API key by ID
///
/// GET /api/api-keys/{id}
#[utoipa::path(
    get,
    path = "/api/api-keys/{id}",
    tag = "api_keys",
    params(
        ("id" = String, Path, description = "API key ID")
    ),
    responses(
        (status = 200, description = "Successfully retrieved API key", body = ApiKeySummary),
        (status = 403, description = "Permission denied", body = ApiKeyApiError),
        (status = 404, description = "API key not found", body = ApiKeyApiError),
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn get_key(
    State(state): State<AppState>,
    auth: axum::Extension<AuthContext>,
    Path(id): Path<TypeIdParam>,
) -> Result<Json<ApiKeySummary>, (StatusCode, Json<ApiKeyApiError>)> {
    check_permission(&auth, permissions::APIKEYS_VIEW)
        .map_err(|(s, j)| (s, Json(ApiKeyApiError::new(&j.error, &j.message))))?;

    let key = state.api_key_service.get_key(*id).await.map_err(|e| {
        let (status, err) = ApiKeyApiError::from_service_error(&e);
        (status, Json(err))
    })?;

    Ok(Json(ApiKeySummary::from(key)))
}

/// Query parameters for the per-key usage endpoint
#[derive(Debug, Deserialize, utoipa::IntoParams)]
pub struct ApiKeyUsageQuery {
    /// Trailing window length in days (1–90, default 14)
    pub days: Option<i64>,
}

/// A single day's audited-action count for an API key
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct ApiKeyUsagePoint {
    /// UTC calendar day, `YYYY-MM-DD`
    pub date: String,
    /// Audited actions performed by this key on that day
    pub count: i64,
}

/// Per-key call-volume response.
///
/// Counts *audited* actions (mutations + authorization denials) attributed to
/// the key — not raw request volume. Read-only traffic is not audited and is
/// not reflected here.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct ApiKeyUsageResponse {
    /// Window length in days
    pub days: i64,
    /// Total audited actions across the window
    pub total: i64,
    /// Continuous daily series, oldest first, zero-filled
    pub series: Vec<ApiKeyUsagePoint>,
}

/// Get per-key call volume (audited actions per day)
///
/// Returns a continuous, zero-filled daily series over the trailing window.
/// Source is `audit_logs` filtered on the key's `api_key_id`, so this reflects
/// audited actions (mutations + authorization denials) rather than raw request
/// volume — read-only GET traffic is not audited.
///
/// GET /api/api-keys/{id}/usage
#[utoipa::path(
    get,
    path = "/api/api-keys/{id}/usage",
    tag = "api_keys",
    params(
        ("id" = String, Path, description = "API key ID"),
        ApiKeyUsageQuery,
    ),
    responses(
        (status = 200, description = "Daily audited-action counts for the key", body = ApiKeyUsageResponse),
        (status = 403, description = "Permission denied", body = ApiKeyApiError),
        (status = 404, description = "API key not found", body = ApiKeyApiError),
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn get_key_usage(
    State(state): State<AppState>,
    auth: axum::Extension<AuthContext>,
    Path(id): Path<TypeIdParam>,
    Query(query): Query<ApiKeyUsageQuery>,
) -> Result<Json<ApiKeyUsageResponse>, (StatusCode, Json<ApiKeyApiError>)> {
    check_permission(&auth, permissions::APIKEYS_VIEW)
        .map_err(|(s, j)| (s, Json(ApiKeyApiError::new(&j.error, &j.message))))?;

    // 404 for unknown keys rather than silently returning an empty series.
    state.api_key_service.get_key(*id).await.map_err(|e| {
        let (status, err) = ApiKeyApiError::from_service_error(&e);
        (status, Json(err))
    })?;

    let days = query.days.unwrap_or(14).clamp(1, 90);
    let start_date = chrono::Utc::now().date_naive() - chrono::Duration::days(days - 1);
    let start_ts = start_date
        .and_hms_opt(0, 0, 0)
        .expect("midnight is always a valid time")
        .and_utc();

    let rows = state
        .audit_repo
        .get_api_key_daily_usage(*id, start_ts)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ApiKeyApiError::new("database_error", &e.to_string())),
            )
        })?;

    let counts: std::collections::HashMap<chrono::NaiveDate, i64> =
        rows.into_iter().map(|r| (r.day, r.count)).collect();

    let mut series = Vec::with_capacity(days as usize);
    let mut total = 0i64;
    for offset in 0..days {
        let day = start_date + chrono::Duration::days(offset);
        let count = counts.get(&day).copied().unwrap_or(0);
        total += count;
        series.push(ApiKeyUsagePoint {
            date: day.format("%Y-%m-%d").to_string(),
            count,
        });
    }

    Ok(Json(ApiKeyUsageResponse { days, total, series }))
}

/// Create a new API key
///
/// Requirements: 12.1 - Allow creating API keys with name, description, and selected permissions
///
/// POST /api/api-keys
#[utoipa::path(
    post,
    path = "/api/api-keys",
    tag = "api_keys",
    request_body = CreateApiKeyRequest,
    responses(
        (status = 201, description = "API key successfully created", body = ApiKeyCreated),
        (status = 403, description = "Permission denied — session-only endpoint", body = ApiKeyApiError),
    ),
    security(("bearer_auth" = []))
)]
pub async fn create_key(
    State(state): State<AppState>,
    auth: axum::Extension<AuthContext>,
    client: axum::Extension<ClientContext>,
    Json(request): Json<CreateApiKeyRequest>,
) -> Result<(StatusCode, Json<ApiKeyCreated>), (StatusCode, Json<ApiKeyApiError>)> {
    require_session_auth(&auth)
        .map_err(|(s, j)| (s, Json(ApiKeyApiError::new(&j.error, &j.message))))?;
    check_permission(&auth, permissions::APIKEYS_CREATE)
        .map_err(|(s, j)| (s, Json(ApiKeyApiError::new(&j.error, &j.message))))?;

    // Prevent privilege escalation: caller cannot grant permissions they don't hold
    let caller_perms: std::collections::HashSet<&str> =
        auth.claims.permissions.iter().map(|s| s.as_str()).collect();
    let invalid: Vec<&str> = request
        .permissions
        .iter()
        .map(|s| s.as_str())
        .filter(|p| !caller_perms.contains(p))
        .collect();
    if !invalid.is_empty() {
        return Err((
            StatusCode::FORBIDDEN,
            Json(ApiKeyApiError::new(
                "permission_escalation",
                &format!(
                    "Cannot grant permissions you don't hold: {}",
                    invalid.join(", ")
                ),
            )),
        ));
    }

    // Use IP from ClientContext (populated by auth middleware with ConnectInfo fallback)
    let ip_address = client.ip_address.clone();
    let user_agent = client.user_agent.clone();
    let created_by = if auth.is_api_key {
        None
    } else {
        Some(auth.user_id())
    };
    let key_name = request.name.clone();

    let api_key = state
        .api_key_service
        .create_key(
            request,
            created_by,
            ip_address.as_deref(),
            user_agent.as_deref(),
        )
        .await
        .map_err(|e| {
            let (status, err) = ApiKeyApiError::from_service_error(&e);
            (status, Json(err))
        })?;

    // Emit audit event
    state.emit_audit(
        AuditEvent::builder(AuditSource::ApiKey, APIKEY_CREATED)
            .actor(Some(auth.user_id()), None)
            .api_key(auth.api_key_id, auth.api_key_name.clone())
            .resource("api_key", Some(api_key.id), Some(key_name))
            .client_context(&client)
            .build(),
    );

    Ok((StatusCode::CREATED, Json(api_key)))
}

/// Deserialize helper distinguishing an absent field (`None`) from an explicit
/// JSON `null` (`Some(None)`), so partial `PUT`s only touch provided fields.
fn double_option<'de, T, D>(de: D) -> Result<Option<Option<T>>, D::Error>
where
    T: Deserialize<'de>,
    D: Deserializer<'de>,
{
    Deserialize::deserialize(de).map(Some)
}

/// Request body for updating an API key.
///
/// Nullable fields (`description`, `expires_at`, `rate_limit`) use tri-state
/// semantics: **absent** = leave unchanged, **`null`** = clear, **value** = set.
/// `name` and `permissions` are non-nullable, so they only distinguish absent
/// (unchanged) from a provided value.
#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct UpdateApiKeyRequest {
    pub name: Option<String>,
    #[serde(default, deserialize_with = "double_option")]
    #[schema(value_type = Option<String>)]
    pub description: Option<Option<String>>,
    pub permissions: Option<Vec<String>>,
    #[serde(default, deserialize_with = "double_option")]
    #[schema(value_type = Option<chrono::DateTime<chrono::Utc>>)]
    pub expires_at: Option<Option<chrono::DateTime<chrono::Utc>>>,
    #[serde(default, deserialize_with = "double_option")]
    #[schema(value_type = Option<i32>)]
    pub rate_limit: Option<Option<i32>>,
}

/// Update an API key
///
/// PUT /api/api-keys/{id}
#[utoipa::path(
    put,
    path = "/api/api-keys/{id}",
    tag = "api_keys",
    params(
        ("id" = String, Path, description = "API key ID to update")
    ),
    request_body = UpdateApiKeyRequest,
    responses(
        (status = 200, description = "API key successfully updated", body = ApiKeySummary),
        (status = 403, description = "Permission denied", body = ApiKeyApiError),
        (status = 404, description = "API key not found", body = ApiKeyApiError),
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn update_key(
    State(state): State<AppState>,
    auth: axum::Extension<AuthContext>,
    client: axum::Extension<ClientContext>,
    Path(id): Path<TypeIdParam>,
    Json(request): Json<UpdateApiKeyRequest>,
) -> Result<Json<ApiKeySummary>, (StatusCode, Json<ApiKeyApiError>)> {
    require_session_or_self(&auth, *id)
        .map_err(|(s, j)| (s, Json(ApiKeyApiError::new(&j.error, &j.message))))?;
    check_permission(&auth, permissions::APIKEYS_EDIT)
        .map_err(|(s, j)| (s, Json(ApiKeyApiError::new(&j.error, &j.message))))?;

    // Prevent privilege escalation: caller cannot grant permissions they don't hold
    if let Some(ref perms) = request.permissions {
        let caller_perms: std::collections::HashSet<&str> =
            auth.claims.permissions.iter().map(|s| s.as_str()).collect();
        let invalid: Vec<&str> = perms
            .iter()
            .map(|s| s.as_str())
            .filter(|p| !caller_perms.contains(p))
            .collect();
        if !invalid.is_empty() {
            return Err((
                StatusCode::FORBIDDEN,
                Json(ApiKeyApiError::new(
                    "permission_escalation",
                    &format!(
                        "Cannot grant permissions you don't hold: {}",
                        invalid.join(", ")
                    ),
                )),
            ));
        }
    }

    let key = state
        .api_key_service
        .update_key(
            *id,
            request.name.as_deref(),
            request.description.as_ref().map(|d| d.as_deref()),
            request.permissions.as_deref(),
            request.expires_at,
            request.rate_limit,
        )
        .await
        .map_err(|e| {
            let (status, err) = ApiKeyApiError::from_service_error(&e);
            (status, Json(err))
        })?;

    // Emit audit event
    state.emit_audit(
        AuditEvent::builder(AuditSource::ApiKey, APIKEY_UPDATED)
            .actor(Some(auth.user_id()), None)
            .api_key(auth.api_key_id, auth.api_key_name.clone())
            .resource("api_key", Some(*id), Some(key.name.clone()))
            .client_context(&client)
            .build(),
    );

    Ok(Json(ApiKeySummary::from(key)))
}

/// Delete an API key
///
/// Requirements: 12.9 - Immediately reject requests using deleted key
///
/// DELETE /api/api-keys/{id}
#[utoipa::path(
    delete,
    path = "/api/api-keys/{id}",
    tag = "api_keys",
    params(
        ("id" = String, Path, description = "API key ID to delete")
    ),
    responses(
        (status = 204, description = "API key successfully deleted"),
        (status = 403, description = "Permission denied", body = ApiKeyApiError),
        (status = 404, description = "API key not found", body = ApiKeyApiError),
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn delete_key(
    State(state): State<AppState>,
    auth: axum::Extension<AuthContext>,
    client: axum::Extension<ClientContext>,
    Path(id): Path<TypeIdParam>,
) -> Result<StatusCode, (StatusCode, Json<ApiKeyApiError>)> {
    require_session_or_self(&auth, *id)
        .map_err(|(s, j)| (s, Json(ApiKeyApiError::new(&j.error, &j.message))))?;
    check_permission(&auth, permissions::APIKEYS_DELETE)
        .map_err(|(s, j)| (s, Json(ApiKeyApiError::new(&j.error, &j.message))))?;

    // Get key name for audit before deleting
    let key_name = state
        .api_key_service
        .get_key(*id)
        .await
        .map(|k| k.name)
        .unwrap_or_else(|_| "unknown".to_string());

    // Use IP from ClientContext (populated by auth middleware with ConnectInfo fallback)
    let ip_address = client.ip_address.clone();
    let user_agent = client.user_agent.clone();
    let user_id = if auth.is_api_key {
        None
    } else {
        Some(auth.user_id())
    };

    state
        .api_key_service
        .delete_key(*id, user_id, ip_address.as_deref(), user_agent.as_deref())
        .await
        .map_err(|e| {
            let (status, err) = ApiKeyApiError::from_service_error(&e);
            (status, Json(err))
        })?;

    // Emit audit event
    state.emit_audit(
        AuditEvent::builder(AuditSource::ApiKey, APIKEY_DELETED)
            .actor(Some(auth.user_id()), None)
            .api_key(auth.api_key_id, auth.api_key_name.clone())
            .resource("api_key", Some(*id), Some(key_name))
            .client_context(&client)
            .build(),
    );

    Ok(StatusCode::NO_CONTENT)
}

/// Enable an API key
///
/// Requirements: 12.6 - Allow enabling/disabling API keys without deletion
///
/// POST /api/api-keys/{id}/enable
#[utoipa::path(
    post,
    path = "/api/api-keys/{id}/enable",
    tag = "api_keys",
    params(
        ("id" = String, Path, description = "API key ID to enable")
    ),
    responses(
        (status = 200, description = "API key successfully enabled", body = ApiKeySummary),
        (status = 403, description = "Permission denied — session-only endpoint", body = ApiKeyApiError),
        (status = 404, description = "API key not found", body = ApiKeyApiError),
    ),
    security(("bearer_auth" = []))
)]
pub async fn enable_key(
    State(state): State<AppState>,
    auth: axum::Extension<AuthContext>,
    client: axum::Extension<ClientContext>,
    Path(id): Path<TypeIdParam>,
) -> Result<Json<ApiKeySummary>, (StatusCode, Json<ApiKeyApiError>)> {
    require_session_auth(&auth)
        .map_err(|(s, j)| (s, Json(ApiKeyApiError::new(&j.error, &j.message))))?;
    check_permission(&auth, permissions::APIKEYS_EDIT)
        .map_err(|(s, j)| (s, Json(ApiKeyApiError::new(&j.error, &j.message))))?;

    // Use IP from ClientContext (populated by auth middleware with ConnectInfo fallback)
    let ip_address = client.ip_address.clone();
    let user_agent = client.user_agent.clone();
    let user_id = if auth.is_api_key {
        None
    } else {
        Some(auth.user_id())
    };

    let key = state
        .api_key_service
        .enable_key(*id, user_id, ip_address.as_deref(), user_agent.as_deref())
        .await
        .map_err(|e| {
            let (status, err) = ApiKeyApiError::from_service_error(&e);
            (status, Json(err))
        })?;

    // Emit audit event
    state.emit_audit(
        AuditEvent::builder(AuditSource::ApiKey, APIKEY_ENABLED)
            .actor(Some(auth.user_id()), None)
            .api_key(auth.api_key_id, auth.api_key_name.clone())
            .resource("api_key", Some(*id), Some(key.name.clone()))
            .client_context(&client)
            .build(),
    );

    Ok(Json(ApiKeySummary::from(key)))
}

/// Disable an API key
///
/// Requirements: 12.6 - Allow enabling/disabling API keys without deletion
///
/// POST /api/api-keys/{id}/disable
#[utoipa::path(
    post,
    path = "/api/api-keys/{id}/disable",
    tag = "api_keys",
    params(
        ("id" = String, Path, description = "API key ID to disable")
    ),
    responses(
        (status = 200, description = "API key successfully disabled", body = ApiKeySummary),
        (status = 403, description = "Permission denied", body = ApiKeyApiError),
        (status = 404, description = "API key not found", body = ApiKeyApiError),
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn disable_key(
    State(state): State<AppState>,
    auth: axum::Extension<AuthContext>,
    client: axum::Extension<ClientContext>,
    Path(id): Path<TypeIdParam>,
) -> Result<Json<ApiKeySummary>, (StatusCode, Json<ApiKeyApiError>)> {
    require_session_or_self(&auth, *id)
        .map_err(|(s, j)| (s, Json(ApiKeyApiError::new(&j.error, &j.message))))?;
    check_permission(&auth, permissions::APIKEYS_EDIT)
        .map_err(|(s, j)| (s, Json(ApiKeyApiError::new(&j.error, &j.message))))?;

    // Use IP from ClientContext (populated by auth middleware with ConnectInfo fallback)
    let ip_address = client.ip_address.clone();
    let user_agent = client.user_agent.clone();
    let user_id = if auth.is_api_key {
        None
    } else {
        Some(auth.user_id())
    };

    let key = state
        .api_key_service
        .disable_key(*id, user_id, ip_address.as_deref(), user_agent.as_deref())
        .await
        .map_err(|e| {
            let (status, err) = ApiKeyApiError::from_service_error(&e);
            (status, Json(err))
        })?;

    // Emit audit event
    state.emit_audit(
        AuditEvent::builder(AuditSource::ApiKey, APIKEY_DISABLED)
            .actor(Some(auth.user_id()), None)
            .api_key(auth.api_key_id, auth.api_key_name.clone())
            .resource("api_key", Some(*id), Some(key.name.clone()))
            .client_context(&client)
            .build(),
    );

    Ok(Json(ApiKeySummary::from(key)))
}

/// Reset an API key (generate a new key value)
///
/// POST /api/api-keys/{id}/reset
#[utoipa::path(
    post,
    path = "/api/api-keys/{id}/reset",
    tag = "api_keys",
    params(
        ("id" = String, Path, description = "API key ID to reset")
    ),
    responses(
        (status = 200, description = "API key successfully reset", body = ApiKeyCreated),
        (status = 403, description = "Permission denied — session-only endpoint", body = ApiKeyApiError),
        (status = 404, description = "API key not found", body = ApiKeyApiError),
    ),
    security(("bearer_auth" = []))
)]
pub async fn reset_key(
    State(state): State<AppState>,
    auth: axum::Extension<AuthContext>,
    client: axum::Extension<ClientContext>,
    Path(id): Path<TypeIdParam>,
) -> Result<Json<ApiKeyCreated>, (StatusCode, Json<ApiKeyApiError>)> {
    require_session_auth(&auth)
        .map_err(|(s, j)| (s, Json(ApiKeyApiError::new(&j.error, &j.message))))?;
    check_permission(&auth, permissions::APIKEYS_EDIT)
        .map_err(|(s, j)| (s, Json(ApiKeyApiError::new(&j.error, &j.message))))?;

    let user_id = if auth.is_api_key {
        None
    } else {
        Some(auth.user_id())
    };

    let result = state
        .api_key_service
        .reset_key(
            *id,
            user_id,
            client.ip_address.as_deref(),
            client.user_agent.as_deref(),
        )
        .await
        .map_err(|e| {
            let (status, err) = ApiKeyApiError::from_service_error(&e);
            (status, Json(err))
        })?;

    // Emit audit event
    state.emit_audit(
        AuditEvent::builder(AuditSource::ApiKey, APIKEY_RESET)
            .actor(Some(auth.user_id()), None)
            .api_key(auth.api_key_id, auth.api_key_name.clone())
            .resource("api_key", Some(*id), Some(result.name.clone()))
            .client_context(&client)
            .build(),
    );

    Ok(Json(result))
}

/// OpenAPI documentation for API key management endpoints
#[derive(utoipa::OpenApi)]
#[openapi(
    paths(
        list_keys,
        create_key,
        get_key,
        get_key_usage,
        update_key,
        delete_key,
        enable_key,
        disable_key,
        reset_key,
    ),
    components(schemas(
        ApiKeyApiError,
        ApiKeyListResponse,
        ApiKeySummary,
        ApiKeyUsagePoint,
        ApiKeyUsageResponse,
        UpdateApiKeyRequest,
    )),
    tags(
        (name = "api_keys", description = "API key management API")
    )
)]
pub struct ApiKeysApiDoc;

#[cfg(test)]
mod tests {
    use super::*;

    // Tri-state partial-update semantics (NAN-1088): an absent field must leave
    // the column unchanged, an explicit JSON `null` must clear it, and a value
    // must set it. Regression guard against the handler clobbering omitted
    // fields to NULL.

    #[test]
    fn update_request_absent_fields_are_unchanged() {
        let req: UpdateApiKeyRequest = serde_json::from_str(r#"{"permissions":["search:read"]}"#).unwrap();
        assert!(req.name.is_none());
        assert_eq!(req.permissions.as_deref(), Some(["search:read".to_string()].as_slice()));
        assert!(req.description.is_none(), "absent description = unchanged");
        assert!(req.expires_at.is_none(), "absent expires_at = unchanged");
        assert!(req.rate_limit.is_none(), "absent rate_limit = unchanged");
    }

    #[test]
    fn update_request_explicit_null_clears() {
        let req: UpdateApiKeyRequest =
            serde_json::from_str(r#"{"description":null,"expires_at":null,"rate_limit":null}"#).unwrap();
        assert_eq!(req.description, Some(None), "null description = clear");
        assert_eq!(req.expires_at, Some(None), "null expires_at = clear");
        assert_eq!(req.rate_limit, Some(None), "null rate_limit = clear");
    }

    #[test]
    fn update_request_values_are_set() {
        let req: UpdateApiKeyRequest =
            serde_json::from_str(r#"{"description":"ci robot","rate_limit":600}"#).unwrap();
        assert_eq!(req.description, Some(Some("ci robot".to_string())));
        assert_eq!(req.rate_limit, Some(Some(600)));
        assert!(req.expires_at.is_none(), "omitted expires_at stays unchanged");
    }
}
