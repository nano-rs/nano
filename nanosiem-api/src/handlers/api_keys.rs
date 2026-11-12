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
        use nanosiem_core::auth::ApiKeyRepositoryError;

        let (status, error_type) = match err {
            ApiKeyServiceError::NotFound
            // NAN-2266: a repository "no such row" that a service method
            // propagated wholesale (delete/enable/disable/update all do) is
            // still a 404, not a database fault. Before this arm, deleting an
            // already-deleted key answered 500 — which is exactly what the
            // desktop hunt runner's best-effort re-revoke of a sweep key hits
            // on every tick after a successful revoke.
            | ApiKeyServiceError::RepositoryError(ApiKeyRepositoryError::NotFound(_)) => {
                (StatusCode::NOT_FOUND, "api_key_not_found")
            }
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
            ApiKeyServiceError::OwnerPermissionsUnavailable => {
                (StatusCode::SERVICE_UNAVAILABLE, "owner_permissions_unavailable")
            }
        };

        // NAN-2266: 5xx detail goes to the log (the request id is on the
        // enclosing tracing span), never into the response body — the previous
        // form echoed the raw repository/driver rendering to the client.
        if status.is_server_error() {
            tracing::error!(error = %nanosiem_api_lib::error_chain(err), "API key service error");
            return (status, Self::new(error_type, "An internal error occurred"));
        }

        // Both 404 arms mean the same thing to the caller; the repository
        // rendering ("Repository error: API key not found: <uuid>") is an
        // internal shape that should not become the response contract.
        if status == StatusCode::NOT_FOUND {
            return (status, Self::new(error_type, "API key not found"));
        }

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
    /// NAN-5044: stored permissions the key's owner no longer holds. They are
    /// withheld at request time (owner-clamp `enforce`), or only reported
    /// (`audit`). Always empty for ownerless and `system`-owned keys.
    #[serde(default)]
    pub withheld_permissions: Vec<String>,
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
            withheld_permissions: Vec::new(),
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
    let mut api_keys = Vec::with_capacity(keys.len());
    for key in keys {
        // NAN-5044: surface what the owner clamp withholds. Best-effort — a
        // resolution failure must not break the listing (the request path
        // fails closed on its own).
        let withheld = state
            .api_key_service
            .withheld_permissions(&key)
            .await
            .unwrap_or_default();
        let mut summary = ApiKeySummary::from(key);
        summary.withheld_permissions = withheld;
        api_keys.push(summary);
    }

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
/// Source is the ClickHouse audit store (`source_type='audit'`) filtered on the
/// key as the acting credential (`metadata.api_key_id`), so this reflects
/// audited actions performed *via* the key (mutations + authorization denials)
/// rather than raw request volume — read-only GET traffic is not audited, and
/// admin lifecycle actions taken *on* the key (create/enable/disable) are not
/// counted here since the key is the target, not the actor. NAN-1622 moved this
/// off the retired PostgreSQL `audit_logs` table.
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
        .audit_query_service
        .api_key_daily_usage(*id, start_ts)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ApiKeyApiError::new("query_error", &e.to_string())),
            )
        })?;

    let counts: std::collections::HashMap<chrono::NaiveDate, i64> = rows.into_iter().collect();

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

    // F-32: bind every new key to the human owner. `auth.user_id()` is the
    // owner's user_id even for an api-key principal (AuthContext::from_api_key
    // sets sub = owner), so a key minted VIA another key stays owner-bound and
    // is covered by the owner-status check in validate_key — it can no longer
    // outlive the owner's disable as a NULL-owner orphan. An already-orphaned
    // creating key resolves to a non-user subject and FK-fails here, which is
    // the intended outcome (orphaned keys must not mint new keys).
    let created_by = Some(auth.user_id());

    // NAN-4954: the key and its `apikey_created` audit record commit in ONE
    // PostgreSQL transaction — a key can never exist without its record, and a
    // failed record rolls the key back (explicit failure, not a silent drop).
    // Only the ClickHouse delivery is detached.
    let actor_name = state.audit_actor_name(auth.user_id()).await;
    // NAN-5324: the record says what the key can do, not only that it exists.
    let created_details = api_key_created_details(&request);
    let (api_key, event) = state
        .api_key_service
        .create_key_audited(request, created_by, |key_id, key_name| {
            AuditEvent::builder(AuditSource::ApiKey, APIKEY_CREATED)
                .actor(Some(auth.user_id()), actor_name)
                .api_key(auth.api_key_id, auth.api_key_name.clone())
                .resource("api_key", Some(key_id), Some(key_name.to_string()))
                .client_context(&client)
                .details(created_details)
                .build()
        })
        .await
        .map_err(|e| {
            let (status, err) = ApiKeyApiError::from_service_error(&e);
            (status, Json(err))
        })?;
    state.deliver_recorded_audit(event);

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

    let current = state.api_key_service.get_key(*id).await.map_err(|e| {
        let (status, err) = ApiKeyApiError::from_service_error(&e);
        (status, Json(err))
    })?;

    // NAN-5029: a key managing ITSELF may only tighten itself. A leaked key
    // must not be able to clear its own expiry or rate limit and persist.
    if auth.is_api_key {
        if let Err(reason) = self_update_is_tightening(
            current.expires_at,
            current.rate_limit,
            request.expires_at,
            request.rate_limit,
        ) {
            return Err((
                StatusCode::FORBIDDEN,
                Json(ApiKeyApiError::new("interactive_session_required", reason)),
            ));
        }
    }

    // NAN-5029 (cross-user): editing ANOTHER user's key is managing that user —
    // the editor needs authority over the owner (NAN-5027).
    ensure_can_manage_key_owner(&state, &auth, &current).await?;

    // Prevent privilege escalation. NAN-5044: the new set is bounded by what
    // the key's OWNER holds now (not by the editor), so a key can never be
    // raised above its owner. Ownerless legacy keys fall back to the editor.
    if let Some(ref perms) = request.permissions {
        let bound = key_permission_bound(&state, &auth, &current).await?;
        let invalid: Vec<&str> = perms
            .iter()
            .map(|s| s.as_str())
            .filter(|p| !bound.contains(*p))
            .collect();
        if !invalid.is_empty() {
            return Err((
                StatusCode::FORBIDDEN,
                Json(ApiKeyApiError::new(
                    "permission_escalation",
                    &format!(
                        "Cannot grant permissions the key's owner doesn't hold: {}",
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
    state.emit_audit_durable(
        AuditEvent::builder(AuditSource::ApiKey, APIKEY_UPDATED)
            .actor(Some(auth.user_id()), None)
            .api_key(auth.api_key_id, auth.api_key_name.clone())
            .resource("api_key", Some(*id), Some(key.name.clone()))
            .client_context(&client)
            .details(nanosiem_core::audit::changes::field_changes(
                &api_key_audit_snapshot(&current),
                &api_key_audit_snapshot(&key),
            ))
            .build(),
    ).await;

    Ok(Json(ApiKeySummary::from(key)))
}

/// NAN-5324: the audit-relevant state of a key — what it can do and for how
/// long. Never includes the secret or its hash.
pub(crate) fn api_key_audit_snapshot(key: &ApiKey) -> serde_json::Value {
    let mut permissions = key.permissions.clone();
    permissions.sort();
    serde_json::json!({
        "name": key.name,
        "description": key.description,
        "permissions": permissions,
        "enabled": key.enabled,
        "expires_at": key.expires_at,
        "rate_limit": key.rate_limit,
    })
}

/// NAN-5324: `apikey_created` details — the granted scopes and limits.
pub(crate) fn api_key_created_details(request: &CreateApiKeyRequest) -> serde_json::Value {
    let mut permissions = request.permissions.clone();
    permissions.sort();
    serde_json::json!({
        "permissions": permissions,
        "expires_at": request.expires_at,
        "rate_limit": request.rate_limit,
    })
}

/// NAN-5029: may a key's self-update be applied? Only changes that TIGHTEN it
/// are allowed: an earlier (or first) expiry and a lower (or first) rate
/// limit. Clearing either (`null`), extending the expiry or raising the limit
/// needs an interactive session. Absent fields are unchanged and always pass.
pub(crate) fn self_update_is_tightening(
    current_expires_at: Option<chrono::DateTime<chrono::Utc>>,
    current_rate_limit: Option<i32>,
    requested_expires_at: Option<Option<chrono::DateTime<chrono::Utc>>>,
    requested_rate_limit: Option<Option<i32>>,
) -> Result<(), &'static str> {
    match requested_expires_at {
        None => {}
        Some(None) => return Err("An API key cannot remove its own expiry; use an interactive session."),
        Some(Some(new)) => {
            if let Some(cur) = current_expires_at {
                if new > cur {
                    return Err("An API key cannot extend its own expiry; use an interactive session.");
                }
            }
        }
    }
    match requested_rate_limit {
        None => {}
        Some(None) => {
            return Err("An API key cannot remove its own rate limit; use an interactive session.")
        }
        Some(Some(new)) => {
            if let Some(cur) = current_rate_limit {
                if new > cur {
                    return Err("An API key cannot raise its own rate limit; use an interactive session.");
                }
            }
        }
    }
    Ok(())
}

/// The key's owner, when it is a principal other than the caller.
fn foreign_owner(auth: &AuthContext, key: &ApiKey) -> Option<Uuid> {
    match key.created_by {
        Some(owner) if auth.is_api_key || owner != auth.user_id() => Some(owner),
        _ => None,
    }
}

/// NAN-5029: changing, re-enabling or re-secreting ANOTHER user's key is
/// managing that user — require authority over the owner (NAN-5027).
/// A key acting on itself, and a session acting on its own keys, pass.
async fn ensure_can_manage_key_owner(
    state: &AppState,
    auth: &AuthContext,
    key: &ApiKey,
) -> Result<(), (StatusCode, Json<ApiKeyApiError>)> {
    let Some(owner) = foreign_owner(auth, key) else {
        return Ok(());
    };
    if auth.api_key_id == Some(key.id) {
        return Ok(());
    }
    crate::handlers::grant_authz::ensure_can_manage_principal(
        auth,
        &state.pool,
        permissions::APIKEYS_EDIT,
        owner,
        None,
    )
    .await
    .map(|_| ())
    .map_err(|g| (g.status, Json(ApiKeyApiError::new(g.code, &g.message))))
}

/// The permissions a key's permission set may contain (NAN-5044): what its
/// owner holds NOW, further bounded by the caller. Ownerless legacy keys are
/// bounded by the caller alone.
async fn key_permission_bound(
    state: &AppState,
    auth: &AuthContext,
    key: &ApiKey,
) -> Result<std::collections::HashSet<String>, (StatusCode, Json<ApiKeyApiError>)> {
    let caller: std::collections::HashSet<String> =
        auth.claims.permissions.iter().cloned().collect();
    let Some(owner) = key.created_by else {
        return Ok(caller);
    };
    let owner_perms = nanosiem_core::auth::PermissionResolver::new(state.pool.clone())
        .resolve_checked(owner)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "api-key owner permission resolution failed");
            (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(ApiKeyApiError::new(
                    "owner_permissions_unavailable",
                    "The key owner's permissions are temporarily unavailable; retry shortly.",
                )),
            )
        })?;
    Ok(owner_perms.into_iter().filter(|p| caller.contains(p)).collect())
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
    let existing = state.api_key_service.get_key(*id).await.ok();
    let key_name = existing
        .as_ref()
        .map(|k| k.name.clone())
        .unwrap_or_else(|| "unknown".to_string());

    // NAN-4954: the delete and its `apikey_deleted` audit record commit in ONE
    // PostgreSQL transaction; only the ClickHouse delivery is detached.
    let event = AuditEvent::builder(AuditSource::ApiKey, APIKEY_DELETED)
        .actor(Some(auth.user_id()), state.audit_actor_name(auth.user_id()).await)
        .api_key(auth.api_key_id, auth.api_key_name.clone())
        .resource("api_key", Some(*id), Some(key_name))
        .client_context(&client)
        .details(existing.as_ref().map(api_key_audit_snapshot).unwrap_or(serde_json::Value::Null))
        .build();
    state
        .api_key_service
        .delete_key_audited(*id, &event)
        .await
        .map_err(|e| {
            let (status, err) = ApiKeyApiError::from_service_error(&e);
            (status, Json(err))
        })?;
    state.deliver_recorded_audit(event);

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

    // NAN-5029: re-enabling or re-secreting ANOTHER user's key is managing that
    // user (a reset hands the caller a working secret with the owner's authority).
    let current = state.api_key_service.get_key(*id).await.map_err(|e| {
        let (status, err) = ApiKeyApiError::from_service_error(&e);
        (status, Json(err))
    })?;
    ensure_can_manage_key_owner(&state, &auth, &current).await?;

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
    state.emit_audit_durable(
        AuditEvent::builder(AuditSource::ApiKey, APIKEY_ENABLED)
            .actor(Some(auth.user_id()), None)
            .api_key(auth.api_key_id, auth.api_key_name.clone())
            .resource("api_key", Some(*id), Some(key.name.clone()))
            .client_context(&client)
            .build(),
    ).await;

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
    state.emit_audit_durable(
        AuditEvent::builder(AuditSource::ApiKey, APIKEY_DISABLED)
            .actor(Some(auth.user_id()), None)
            .api_key(auth.api_key_id, auth.api_key_name.clone())
            .resource("api_key", Some(*id), Some(key.name.clone()))
            .client_context(&client)
            .build(),
    ).await;

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

    // NAN-5029: re-enabling or re-secreting ANOTHER user's key is managing that
    // user (a reset hands the caller a working secret with the owner's authority).
    let current = state.api_key_service.get_key(*id).await.map_err(|e| {
        let (status, err) = ApiKeyApiError::from_service_error(&e);
        (status, Json(err))
    })?;
    ensure_can_manage_key_owner(&state, &auth, &current).await?;

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
    state.emit_audit_durable(
        AuditEvent::builder(AuditSource::ApiKey, APIKEY_RESET)
            .actor(Some(auth.user_id()), None)
            .api_key(auth.api_key_id, auth.api_key_name.clone())
            .resource("api_key", Some(*id), Some(result.name.clone()))
            .client_context(&client)
            .details(api_key_audit_snapshot(&current))
            .build(),
    ).await;

    Ok(Json(result))
}

/// Owner-clamp mode for API keys (NAN-5044).
#[derive(Debug, Serialize, Deserialize, utoipa::ToSchema)]
pub struct OwnerClampSettings {
    /// `enforce` (default): keys run with stored ∩ owner's current permissions.
    /// `audit`: stored permissions are used unchanged and withheld ones are only
    /// logged — a one-release escape hatch, scheduled for removal in v2.1.
    pub mode: nanosiem_core::auth::OwnerClampMode,
}

/// Get the API-key owner-clamp mode
///
/// GET /api/settings/api-keys/owner-clamp
#[utoipa::path(
    get,
    path = "/api/settings/api-keys/owner-clamp",
    tag = "api_keys",
    responses(
        (status = 200, description = "Current owner-clamp mode", body = OwnerClampSettings),
        (status = 403, description = "Permission denied", body = ApiKeyApiError),
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn get_owner_clamp(
    State(state): State<AppState>,
    auth: axum::Extension<AuthContext>,
) -> Result<Json<OwnerClampSettings>, (StatusCode, Json<ApiKeyApiError>)> {
    check_permission(&auth, permissions::APIKEYS_VIEW)
        .map_err(|(s, j)| (s, Json(ApiKeyApiError::new(&j.error, &j.message))))?;
    Ok(Json(OwnerClampSettings {
        mode: state.api_key_service.owner_clamp_mode().await,
    }))
}

/// Set the API-key owner-clamp mode
///
/// Switching to `audit` lets keys keep permissions their owners no longer
/// hold, so it is session-only and needs both `settings:system` and
/// `apikeys:edit`.
///
/// PUT /api/settings/api-keys/owner-clamp
#[utoipa::path(
    put,
    path = "/api/settings/api-keys/owner-clamp",
    tag = "api_keys",
    request_body = OwnerClampSettings,
    responses(
        (status = 200, description = "Updated owner-clamp mode", body = OwnerClampSettings),
        (status = 403, description = "Permission denied — session-only endpoint", body = ApiKeyApiError),
    ),
    security(("bearer_auth" = []))
)]
pub async fn update_owner_clamp(
    State(state): State<AppState>,
    auth: axum::Extension<AuthContext>,
    client: axum::Extension<ClientContext>,
    Json(request): Json<OwnerClampSettings>,
) -> Result<Json<OwnerClampSettings>, (StatusCode, Json<ApiKeyApiError>)> {
    require_session_auth(&auth)
        .map_err(|(s, j)| (s, Json(ApiKeyApiError::new(&j.error, &j.message))))?;
    check_permission(&auth, permissions::SETTINGS_SYSTEM)
        .map_err(|(s, j)| (s, Json(ApiKeyApiError::new(&j.error, &j.message))))?;
    check_permission(&auth, permissions::APIKEYS_EDIT)
        .map_err(|(s, j)| (s, Json(ApiKeyApiError::new(&j.error, &j.message))))?;

    state
        .api_key_service
        .set_owner_clamp_mode(request.mode)
        .await
        .map_err(|e| {
            let (status, err) = ApiKeyApiError::from_service_error(&e);
            (status, Json(err))
        })?;

    state.emit_audit_durable(
        AuditEvent::builder(AuditSource::ApiKey, APIKEY_UPDATED)
            .actor(Some(auth.user_id()), None)
            .api_key(auth.api_key_id, auth.api_key_name.clone())
            .resource("settings", None, Some("api_key_owner_clamp".to_string()))
            .client_context(&client)
            .details(serde_json::json!({ "owner_clamp_mode": request.mode.as_str() }))
            .build(),
    ).await;

    Ok(Json(OwnerClampSettings { mode: request.mode }))
}

#[cfg(test)]
#[path = "api_keys_self_update_tests.rs"]
mod self_update_tests;

#[cfg(test)]
#[path = "api_keys_audit_details_tests.rs"]
mod audit_details_tests;

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
        get_owner_clamp,
        update_owner_clamp,
    ),
    components(schemas(
        ApiKeyApiError,
        OwnerClampSettings,
        nanosiem_core::auth::OwnerClampMode,
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

    // NAN-2266: deleting an already-deleted key answered 500. The repository's
    // NotFound rode inside `ServiceError::RepositoryError` (delete/enable/
    // disable/update all propagate it wholesale), and every RepositoryError was
    // rendered as `500 database_error` — so the desktop hunt runner's
    // best-effort re-revoke of a sweep key failed loudly on every tick.

    #[test]
    fn a_repository_not_found_is_a_404_not_a_database_fault() {
        let err = ApiKeyServiceError::RepositoryError(
            nanosiem_core::auth::ApiKeyRepositoryError::NotFound(Uuid::nil()),
        );
        let (status, body) = ApiKeyApiError::from_service_error(&err);
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(body.error, "api_key_not_found");
        // The repository's internal rendering must not become the contract.
        assert_eq!(body.message, "API key not found");
    }

    #[test]
    fn a_real_database_fault_stays_500_with_a_generic_body() {
        let err = ApiKeyServiceError::RepositoryError(
            nanosiem_core::auth::ApiKeyRepositoryError::DatabaseError(sqlx::Error::PoolTimedOut),
        );
        let (status, body) = ApiKeyApiError::from_service_error(&err);
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(body.error, "database_error");
        // The driver's rendering goes to the log, never into the response.
        assert_eq!(body.message, "An internal error occurred");
        assert!(!body.message.to_lowercase().contains("pool"));
    }
}
