// SPDX-License-Identifier: AGPL-3.0-or-later

//! Log Source management endpoint handlers
//!
//! Implements:
//! - GET /api/log-sources - List all log sources
//! - POST /api/log-sources - Create a new log source
//! - GET /api/log-sources/:id - Get a log source by ID
//! - PUT /api/log-sources/:id - Update a log source
//! - DELETE /api/log-sources/:id - Delete a log source
//! - POST /api/log-sources/:id/toggle - Toggle enabled status
//! - POST /api/log-sources/:id/validate - Validate VRL
//! - POST /api/log-sources/:id/deploy - Deploy to Vector
//! - POST /api/log-sources/:id/undeploy - Undeploy from Vector
//! - GET /api/log-sources/:id/deployments - Get deployment history
//! - GET /api/log-sources/:id/health - Get health metrics
//! - GET /api/log-sources/ingestion-history - Get ingestion history for chart
//! - POST /api/log-sources/validate-vrl - Validate VRL code
//! - POST /api/log-sources/test-vrl - Test VRL against sample
//! - POST /api/log-sources/deploy-all - Deploy all enabled

use super::AuditExt;
use axum::{
    extract::{Path, Query, State},
    Extension, Json,
};
use nanosiem_core::audit::{
    AuditEvent, AuditSource, ClientContext, LOG_SOURCE_CREATED, LOG_SOURCE_DELETED,
    LOG_SOURCE_DEPLOYED, LOG_SOURCE_DEPLOY_ALL, LOG_SOURCE_PUBLISHED, LOG_SOURCE_REVERTED,
    LOG_SOURCE_TOGGLED, LOG_SOURCE_UNDEPLOYED, LOG_SOURCE_UPDATED,
};
use nanosiem_core::log_sources::{
    DeploymentResult, IngestionHistoryPoint, LiveTestResult, LogSource, LogSourceDeployment,
    CollectorError, LogSourceHealth, LogSourceVersion, LogSourceWithDraftStatus, NewLogSource,
    ParserTestResult,
    UpdateLogSource, VrlDiagnostic, VrlValidationResult,
};
use nanosiem_core::typeid::TypeIdParam;
use serde::Deserialize;
use utoipa::{IntoParams, ToSchema};

use crate::middleware::{ensure_permission, AuthContext};
use crate::{error::ApiError, state::AppState};

// Permission constants for log sources
const LOG_SOURCES_VIEW: &str = "log_sources:view";
const LOG_SOURCES_CREATE: &str = "log_sources:create";
const LOG_SOURCES_EDIT: &str = "log_sources:edit";
const LOG_SOURCES_DELETE: &str = "log_sources:delete";
const LOG_SOURCES_DEPLOY: &str = "log_sources:deploy";

/// List all log sources
#[utoipa::path(
    get,
    path = "/api/log-sources",
    tag = "log_sources",
    responses(
        (status = 200, description = "List of log sources", body = Vec<LogSource>),
        (status = 403, description = "Forbidden"),
    ),
    security(("api_key" = []))
)]
pub async fn list_log_sources(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
) -> Result<Json<Vec<LogSource>>, ApiError> {
    ensure_permission(&auth, LOG_SOURCES_VIEW)?;

    let log_sources = state.log_source_service.list(None).await?;
    Ok(Json(log_sources))
}

/// Get a log source by ID
#[utoipa::path(
    get,
    path = "/api/log-sources/{id}",
    tag = "log_sources",
    params(
        ("id" = String, Path, description = "Log source ID")
    ),
    responses(
        (status = 200, description = "Log source details", body = LogSource),
        (status = 403, description = "Forbidden"),
        (status = 404, description = "Not found"),
    ),
    security(("api_key" = []))
)]
pub async fn get_log_source(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<TypeIdParam>,
) -> Result<Json<LogSource>, ApiError> {
    ensure_permission(&auth, LOG_SOURCES_VIEW)?;

    let log_source = state.log_source_service.get(*id).await?;
    Ok(Json(log_source))
}

/// Create a new log source
#[utoipa::path(
    post,
    path = "/api/log-sources",
    tag = "log_sources",
    request_body = NewLogSource,
    responses(
        (status = 200, description = "Log source created", body = LogSource),
        (status = 403, description = "Forbidden"),
        (status = 400, description = "Bad request"),
        (status = 422, description = "Validation failed — invalid timezone, namespace, source type, or match_field (NAN-2158: match_field names a SQL column and must contain only letters, digits, '_' and '.')"),
    ),
    security(("api_key" = []))
)]
pub async fn create_log_source(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Extension(client): Extension<ClientContext>,
    Json(request): Json<NewLogSource>,
) -> Result<Json<LogSource>, ApiError> {
    ensure_permission(&auth, LOG_SOURCES_CREATE)?;

    // Tier enforcement: drafts are exempt (NAN-1920). A feed consumes a
    // data-source slot only once it's a real, non-draft source, so creating a
    // draft never trips the cap; the draft→active transition (deploy) re-checks.
    if request.lifecycle_status.as_deref() != Some("draft") {
        enforce_data_source_limit(&state).await?;
    }

    // Validate timezone
    if !nanosiem_core::timezone::is_valid_timezone(&request.timezone) {
        return Err(ApiError::BadRequest(format!(
            "Invalid timezone: {}",
            request.timezone
        )));
    }

    // Validate namespace format
    if !nanosiem_core::namespace::is_valid_namespace(&request.namespace) {
        return Err(ApiError::BadRequest(format!(
            "Invalid namespace format: {}",
            request.namespace
        )));
    }

    let log_source = state.log_source_service.create(request).await?;

    state.emit_audit(
        AuditEvent::builder(AuditSource::LogSource, LOG_SOURCE_CREATED)
            .actor(Some(auth.user_id()), None)
            .api_key(auth.api_key_id, auth.api_key_name.clone())
            .resource(
                "log_source",
                Some(log_source.id),
                Some(log_source.name.clone()),
            )
            .client_context(&client)
            .build(),
    );

    Ok(Json(log_source))
}

/// Enforce the data-source tier cap, counting only real (non-draft) sources.
/// Drafts are exempt (NAN-1920): a feed consumes a slot only once it's active,
/// so this is called at create (for non-draft creates) and at the draft→active
/// deploy transition. Mirrors the "data sources" limit semantics used elsewhere.
async fn enforce_data_source_limit(state: &AppState) -> Result<(), ApiError> {
    let tier_settings = nanosiem_core::TierSettings::new(state.pool.clone());
    let tier_limits = tier_settings.get_tier_limits().await?;
    if tier_limits.is_enforced() {
        // Fail closed: propagate a DB error (like get_tier_limits above) rather
        // than counting 0 and silently letting a create/deploy past the cap.
        let source_count = state
            .log_source_service
            .list(None)
            .await?
            .iter()
            .filter(|ls| ls.lifecycle_status != "draft")
            .count() as u32;
        nanosiem_core::check_limit(
            "data sources",
            source_count,
            tier_limits.max_data_sources,
            tier_limits.tier,
            "Upgrade to Starter for unlimited data sources.",
        )?;
    }
    Ok(())
}

/// Update a log source
#[utoipa::path(
    put,
    path = "/api/log-sources/{id}",
    tag = "log_sources",
    params(
        ("id" = String, Path, description = "Log source ID")
    ),
    request_body = UpdateLogSource,
    responses(
        (status = 200, description = "Log source updated", body = LogSource),
        (status = 403, description = "Forbidden"),
        (status = 404, description = "Not found"),
        (status = 409, description = "expected_updated_at is stale; reload before retrying"),
        (status = 422, description = "Validation failed — invalid timezone, source type, normalize_vrl, or match_field (NAN-2158: match_field names a SQL column and must contain only letters, digits, '_' and '.')"),
    ),
    security(("api_key" = []))
)]
pub async fn update_log_source(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Extension(client): Extension<ClientContext>,
    Path(id): Path<TypeIdParam>,
    Json(request): Json<UpdateLogSource>,
) -> Result<Json<LogSource>, ApiError> {
    ensure_permission(&auth, LOG_SOURCES_EDIT)?;

    // Validate timezone if provided
    if let Some(ref tz) = request.timezone {
        if !nanosiem_core::timezone::is_valid_timezone(tz) {
            return Err(ApiError::BadRequest(format!("Invalid timezone: {}", tz)));
        }
    }

    let log_source = state.log_source_service.update(*id, request).await?;

    state.emit_audit(
        AuditEvent::builder(AuditSource::LogSource, LOG_SOURCE_UPDATED)
            .actor(Some(auth.user_id()), None)
            .api_key(auth.api_key_id, auth.api_key_name.clone())
            .resource(
                "log_source",
                Some(log_source.id),
                Some(log_source.name.clone()),
            )
            .client_context(&client)
            .build(),
    );

    Ok(Json(log_source))
}

/// Delete a log source
#[utoipa::path(
    delete,
    path = "/api/log-sources/{id}",
    tag = "log_sources",
    params(
        ("id" = String, Path, description = "Log source ID")
    ),
    responses(
        (status = 200, description = "Log source deleted"),
        (status = 403, description = "Forbidden"),
        (status = 404, description = "Not found"),
    ),
    security(("api_key" = []))
)]
pub async fn delete_log_source(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Extension(client): Extension<ClientContext>,
    Path(id): Path<TypeIdParam>,
) -> Result<Json<serde_json::Value>, ApiError> {
    ensure_permission(&auth, LOG_SOURCES_DELETE)?;

    state.log_source_service.delete(*id).await?;

    state.emit_audit(
        AuditEvent::builder(AuditSource::LogSource, LOG_SOURCE_DELETED)
            .actor(Some(auth.user_id()), None)
            .api_key(auth.api_key_id, auth.api_key_name.clone())
            .resource("log_source", Some(*id), None::<String>)
            .client_context(&client)
            .build(),
    );

    Ok(Json(serde_json::json!({"deleted": true})))
}

/// Toggle request
#[derive(Debug, Deserialize, ToSchema)]
pub struct ToggleRequest {
    pub enabled: bool,
}

/// Toggle a log source's enabled status
#[utoipa::path(
    post,
    path = "/api/log-sources/{id}/toggle",
    tag = "log_sources",
    params(
        ("id" = String, Path, description = "Log source ID")
    ),
    request_body = ToggleRequest,
    responses(
        (status = 200, description = "Log source toggled", body = LogSource),
        (status = 403, description = "Forbidden"),
        (status = 404, description = "Not found"),
    ),
    security(("api_key" = []))
)]
pub async fn toggle_log_source(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Extension(client): Extension<ClientContext>,
    Path(id): Path<TypeIdParam>,
    Json(request): Json<ToggleRequest>,
) -> Result<Json<LogSource>, ApiError> {
    ensure_permission(&auth, LOG_SOURCES_EDIT)?;

    let log_source = state
        .log_source_service
        .toggle(*id, request.enabled)
        .await?;

    state.emit_audit(
        AuditEvent::builder(AuditSource::LogSource, LOG_SOURCE_TOGGLED)
            .actor(Some(auth.user_id()), None)
            .api_key(auth.api_key_id, auth.api_key_name.clone())
            .resource(
                "log_source",
                Some(log_source.id),
                Some(log_source.name.clone()),
            )
            .client_context(&client)
            .details(serde_json::json!({
                "enabled": request.enabled,
            }))
            .build(),
    );

    Ok(Json(log_source))
}

/// Validate a log source's VRL
#[utoipa::path(
    post,
    path = "/api/log-sources/{id}/validate",
    tag = "log_sources",
    params(
        ("id" = String, Path, description = "Log source ID")
    ),
    responses(
        (status = 200, description = "VRL validation result", body = VrlValidationResult),
        (status = 403, description = "Forbidden"),
        (status = 404, description = "Not found"),
    ),
    security(("api_key" = []))
)]
pub async fn validate_log_source(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<TypeIdParam>,
) -> Result<Json<VrlValidationResult>, ApiError> {
    ensure_permission(&auth, LOG_SOURCES_EDIT)?;

    let result = state.log_source_service.validate_log_source(*id).await?;
    Ok(Json(result))
}

/// Deploy a log source to Vector
#[utoipa::path(
    post,
    path = "/api/log-sources/{id}/deploy",
    tag = "log_sources",
    params(
        ("id" = String, Path, description = "Log source ID")
    ),
    responses(
        (status = 200, description = "Deployment result", body = DeploymentResult),
        (status = 403, description = "Forbidden"),
        (status = 404, description = "Not found"),
    ),
    security(("api_key" = []))
)]
pub async fn deploy_log_source(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Extension(client): Extension<ClientContext>,
    Path(id): Path<TypeIdParam>,
) -> Result<Json<DeploymentResult>, ApiError> {
    ensure_permission(&auth, LOG_SOURCES_DEPLOY)?;

    // Tier enforcement at the draft→active transition (NAN-1920): a draft is
    // exempt from the data-source cap, so activating one via deploy is the point
    // it starts consuming a slot. Enforce here so feeds can't be staged past the
    // limit as drafts and then deployed. Non-draft sources were already counted
    // at create, so re-deploying an active source skips the check.
    if state.log_source_service.get(*id).await?.lifecycle_status == "draft" {
        enforce_data_source_limit(&state).await?;
    }

    let result = state.log_source_service.deploy(*id).await?;

    state.emit_audit(
        AuditEvent::builder(AuditSource::LogSource, LOG_SOURCE_DEPLOYED)
            .actor(Some(auth.user_id()), None)
            .api_key(auth.api_key_id, auth.api_key_name.clone())
            .resource("log_source", Some(*id), None::<String>)
            .client_context(&client)
            .details(serde_json::json!({
                "success": result.success,
            }))
            .build(),
    );

    Ok(Json(result))
}

/// Undeploy a log source from Vector
#[utoipa::path(
    post,
    path = "/api/log-sources/{id}/undeploy",
    tag = "log_sources",
    params(
        ("id" = String, Path, description = "Log source ID")
    ),
    responses(
        (status = 200, description = "Undeployment result", body = DeploymentResult),
        (status = 403, description = "Forbidden"),
        (status = 404, description = "Not found"),
    ),
    security(("api_key" = []))
)]
pub async fn undeploy_log_source(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Extension(client): Extension<ClientContext>,
    Path(id): Path<TypeIdParam>,
) -> Result<Json<DeploymentResult>, ApiError> {
    ensure_permission(&auth, LOG_SOURCES_DEPLOY)?;

    let result = state.log_source_service.undeploy(*id).await?;

    state.emit_audit(
        AuditEvent::builder(AuditSource::LogSource, LOG_SOURCE_UNDEPLOYED)
            .actor(Some(auth.user_id()), None)
            .api_key(auth.api_key_id, auth.api_key_name.clone())
            .resource("log_source", Some(*id), None::<String>)
            .client_context(&client)
            .details(serde_json::json!({
                "success": result.success,
            }))
            .build(),
    );

    Ok(Json(result))
}

/// Get deployment history for a log source
#[utoipa::path(
    get,
    path = "/api/log-sources/{id}/deployments",
    tag = "log_sources",
    params(
        ("id" = String, Path, description = "Log source ID")
    ),
    responses(
        (status = 200, description = "Deployment history", body = Vec<LogSourceDeployment>),
        (status = 403, description = "Forbidden"),
        (status = 404, description = "Not found"),
    ),
    security(("api_key" = []))
)]
pub async fn get_log_source_deployments(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<TypeIdParam>,
) -> Result<Json<Vec<LogSourceDeployment>>, ApiError> {
    ensure_permission(&auth, LOG_SOURCES_VIEW)?;

    let history = state
        .log_source_service
        .get_deployment_history(*id, Some(50))
        .await?;
    Ok(Json(history))
}

/// Get health metrics for a log source
#[utoipa::path(
    get,
    path = "/api/log-sources/{id}/health",
    tag = "log_sources",
    params(
        ("id" = String, Path, description = "Log source ID")
    ),
    responses(
        (status = 200, description = "Health metrics", body = LogSourceHealth),
        (status = 403, description = "Forbidden"),
        (status = 404, description = "Not found"),
    ),
    security(("api_key" = []))
)]
pub async fn get_log_source_health(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<TypeIdParam>,
) -> Result<Json<LogSourceHealth>, ApiError> {
    ensure_permission(&auth, LOG_SOURCES_VIEW)?;

    // NAN-2059: `log_sources:view` authorizes reading the CONFIG; it does not
    // authorize reading the DATA the source ingested. Telemetry here is derived
    // from the logs table, so it carries the caller's effective source scope.
    // A denied source yields no matching rows → a zeroed `NoData` record, the
    // same response an allowed-but-idle source produces. The config row itself
    // stays listable, so this deliberately does NOT 404 (that would be a new
    // existence signal on a resource the caller can already enumerate).
    let health = state
        .log_source_service
        .get_health(*id, &auth.effective_viewer_scope())
        .await?;
    Ok(Json(health))
}

/// Query params for ingestion history
#[derive(Debug, Deserialize, IntoParams)]
pub struct IngestionHistoryQuery {
    pub hours: Option<i64>,
}

/// Get ingestion history for all log sources (for area chart)
#[utoipa::path(
    get,
    path = "/api/log-sources/ingestion-history",
    tag = "log_sources",
    params(
        IngestionHistoryQuery
    ),
    responses(
        (status = 200, description = "Ingestion history", body = Vec<IngestionHistoryPoint>),
        (status = 403, description = "Forbidden"),
    ),
    security(("api_key" = []))
)]
pub async fn get_all_ingestion_history(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Query(params): Query<IngestionHistoryQuery>,
) -> Result<Json<Vec<IngestionHistoryPoint>>, ApiError> {
    ensure_permission(&auth, LOG_SOURCES_VIEW)?;

    // NAN-2059: same boundary as per-source health — denied source types are
    // omitted from the per-source ingestion series entirely.
    let history = state
        .log_source_service
        .get_all_ingestion_history(params.hours, &auth.effective_viewer_scope())
        .await?;
    Ok(Json(history))
}

/// Namespace validation request
#[derive(Debug, Deserialize, ToSchema)]
pub struct ValidateNamespaceRequest {
    pub namespace: String,
}

/// Namespace validation response
#[derive(Debug, serde::Serialize, ToSchema)]
pub struct ValidateNamespaceResponse {
    pub valid: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Validate a namespace string without creating a log source.
///
/// Returns whether the namespace conforms to the expected format
/// (`default` or `<provider>:<suffix>` where provider is one of
/// aws/gcp/azure/onprem).
#[utoipa::path(
    post,
    path = "/api/log-sources/validate-namespace",
    tag = "log_sources",
    request_body = ValidateNamespaceRequest,
    responses(
        (status = 200, description = "Namespace validation result", body = ValidateNamespaceResponse),
        (status = 403, description = "Forbidden"),
    ),
    security(("api_key" = []))
)]
pub async fn validate_namespace(
    Extension(auth): Extension<AuthContext>,
    Json(request): Json<ValidateNamespaceRequest>,
) -> Result<Json<ValidateNamespaceResponse>, ApiError> {
    ensure_permission(&auth, LOG_SOURCES_VIEW)?;

    let valid = nanosiem_core::namespace::is_valid_namespace(&request.namespace);
    let error = if valid {
        None
    } else {
        Some(format!(
            "Invalid namespace format: {}. Expected 'default' or '<provider>:<suffix>' where provider is aws, gcp, azure, or onprem.",
            request.namespace
        ))
    };

    Ok(Json(ValidateNamespaceResponse { valid, error }))
}

/// VRL validation request
#[derive(Debug, Deserialize, ToSchema)]
pub struct ValidateVrlRequest {
    pub vrl_code: String,
}

/// Validate VRL code (without saving)
#[utoipa::path(
    post,
    path = "/api/log-sources/validate-vrl",
    tag = "log_sources",
    request_body = ValidateVrlRequest,
    responses(
        (status = 200, description = "VRL validation result", body = VrlValidationResult),
        (status = 403, description = "Forbidden"),
    ),
    security(("api_key" = []))
)]
pub async fn validate_vrl(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Json(request): Json<ValidateVrlRequest>,
) -> Result<Json<VrlValidationResult>, ApiError> {
    ensure_permission(&auth, LOG_SOURCES_VIEW)?;

    let result = state
        .log_source_service
        .validate_vrl(&request.vrl_code)
        .await;
    Ok(Json(result))
}

/// VRL test request
#[derive(Debug, Deserialize, ToSchema)]
pub struct TestVrlRequest {
    pub vrl_code: String,
    pub sample_log: String,
    /// Optional parser extension VRL to chain after `vrl_code` (NAN-874).
    /// When present, the request tests the combined pipeline: parse → extension.
    #[serde(default)]
    pub extension_vrl: Option<String>,
}

/// Test VRL against a sample log
#[utoipa::path(
    post,
    path = "/api/log-sources/test-vrl",
    tag = "log_sources",
    request_body = TestVrlRequest,
    responses(
        (status = 200, description = "VRL test result", body = ParserTestResult),
        (status = 403, description = "Forbidden"),
    ),
    security(("api_key" = []))
)]
pub async fn test_vrl(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Json(request): Json<TestVrlRequest>,
) -> Result<Json<ParserTestResult>, ApiError> {
    ensure_permission(&auth, LOG_SOURCES_VIEW)?;

    let result = state
        .log_source_service
        .test_vrl_chain(
            &request.vrl_code,
            request.extension_vrl.as_deref(),
            &request.sample_log,
        )
        .await;
    Ok(Json(result))
}

/// Test VRL against real events from ClickHouse
#[derive(Debug, Deserialize, ToSchema)]
pub struct TestVrlLiveRequest {
    /// The new/edited VRL code to test
    pub vrl_code: String,
    /// The currently deployed VRL code (for comparison). If omitted, only the new parse is returned.
    pub current_vrl: Option<String>,
    pub source_type: String,
    /// Number of events to test (default 10, max 20)
    pub limit: Option<usize>,
}

/// Test VRL against real events
#[utoipa::path(
    post,
    path = "/api/log-sources/test-live",
    tag = "log_sources",
    request_body = TestVrlLiveRequest,
    responses(
        (status = 200, description = "VRL test results comparing current vs new parse", body = Vec<LiveTestResult>),
        (status = 403, description = "Missing log_sources:view or search:execute permission"),
    ),
    security(("api_key" = []))
)]
pub async fn test_vrl_live(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Json(request): Json<TestVrlLiveRequest>,
) -> Result<Json<Vec<LiveTestResult>>, ApiError> {
    ensure_permission(&auth, LOG_SOURCES_VIEW)?;

    // NAN-2058: this returns UNREDACTED raw events in `LiveTestResult.input`,
    // for any caller-supplied `source_type`. It is an alternate raw-log read
    // surface and must be no more permissive than canonical search: same
    // capability (`search:execute`) and same effective source scope, so the
    // audit feed and restricted sources are unreachable here exactly as they
    // are through `/api/search`. Before this, `log_sources:view` alone returned
    // raw `audit` records to a key that `/api/search` 403s.
    //
    // Deliberately NOT raised to `log_sources:edit`: the finding floats that as
    // a "strongly consider", but parity with canonical search is the principled
    // line, and ReadOnly analysts legitimately use the test lab. The disclosure
    // is now exactly what `/api/search` would give the same caller.
    ensure_permission(&auth, nanosiem_core::auth::permissions::SEARCH_EXECUTE)?;

    let limit = request.limit.unwrap_or(10);
    let results = state
        .log_source_service
        .test_vrl_live(
            &request.vrl_code,
            request.current_vrl.as_deref(),
            &request.source_type,
            limit,
            &auth.effective_viewer_scope(),
        )
        .await
        .map_err(|e| ApiError::InternalError(format!("Live test failed: {}", e)))?;
    Ok(Json(results))
}

/// Deploy all enabled log sources
#[utoipa::path(
    post,
    path = "/api/log-sources/deploy-all",
    tag = "log_sources",
    responses(
        (status = 200, description = "All enabled log sources deployed"),
        (status = 403, description = "Forbidden"),
    ),
    security(("api_key" = []))
)]
pub async fn deploy_all_log_sources(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Extension(client): Extension<ClientContext>,
) -> Result<Json<serde_json::Value>, ApiError> {
    ensure_permission(&auth, LOG_SOURCES_DEPLOY)?;

    state.log_source_service.deploy_all().await?;

    state.emit_audit(
        AuditEvent::builder(AuditSource::LogSource, LOG_SOURCE_DEPLOY_ALL)
            .actor(Some(auth.user_id()), None)
            .api_key(auth.api_key_id, auth.api_key_name.clone())
            .client_context(&client)
            .build(),
    );

    Ok(Json(serde_json::json!({"deployed": true})))
}

// ============================================================================
// Versioning Endpoints
// ============================================================================

/// Get version history for a log source
#[utoipa::path(
    get,
    path = "/api/log-sources/{id}/versions",
    tag = "log_sources",
    params(
        ("id" = String, Path, description = "Log source ID")
    ),
    responses(
        (status = 200, description = "Version history", body = Vec<LogSourceVersion>),
        (status = 403, description = "Forbidden"),
        (status = 404, description = "Not found"),
    ),
    security(("api_key" = []))
)]
pub async fn get_log_source_versions(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<TypeIdParam>,
) -> Result<Json<Vec<LogSourceVersion>>, ApiError> {
    ensure_permission(&auth, LOG_SOURCES_VIEW)?;

    let versions = state.log_source_service.get_versions(*id, Some(50)).await?;
    Ok(Json(versions))
}

/// Publish working copy as new version and deploy
#[utoipa::path(
    post,
    path = "/api/log-sources/{id}/publish",
    tag = "log_sources",
    params(
        ("id" = String, Path, description = "Log source ID")
    ),
    responses(
        (status = 200, description = "Publish and deploy result", body = DeploymentResult),
        (status = 403, description = "Forbidden"),
        (status = 404, description = "Not found"),
    ),
    security(("api_key" = []))
)]
pub async fn publish_log_source(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Extension(client): Extension<ClientContext>,
    Path(id): Path<TypeIdParam>,
) -> Result<Json<DeploymentResult>, ApiError> {
    ensure_permission(&auth, LOG_SOURCES_DEPLOY)?;

    let result = state
        .log_source_service
        .publish(*id, Some(auth.user_id()))
        .await?;

    state.emit_audit(
        AuditEvent::builder(AuditSource::LogSource, LOG_SOURCE_PUBLISHED)
            .actor(Some(auth.user_id()), None)
            .api_key(auth.api_key_id, auth.api_key_name.clone())
            .resource("log_source", Some(*id), None::<String>)
            .client_context(&client)
            .details(serde_json::json!({
                "success": result.success,
            }))
            .build(),
    );

    Ok(Json(result))
}

/// Revert to a previous version
#[utoipa::path(
    post,
    path = "/api/log-sources/{id}/versions/{version_id}/revert",
    tag = "log_sources",
    params(
        ("id" = String, Path, description = "Log source ID"),
        ("version_id" = i32, Path, description = "Version ID to revert to"),
    ),
    responses(
        (status = 200, description = "New version created from revert", body = LogSourceVersion),
        (status = 403, description = "Forbidden"),
        (status = 404, description = "Not found"),
    ),
    security(("api_key" = []))
)]
pub async fn revert_log_source_version(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Extension(client): Extension<ClientContext>,
    Path((id, version_id)): Path<(TypeIdParam, i32)>,
) -> Result<Json<LogSourceVersion>, ApiError> {
    ensure_permission(&auth, LOG_SOURCES_DEPLOY)?;

    let version = state
        .log_source_service
        .revert_to_version(*id, version_id, Some(auth.user_id()))
        .await?;

    state.emit_audit(
        AuditEvent::builder(AuditSource::LogSource, LOG_SOURCE_REVERTED)
            .actor(Some(auth.user_id()), None)
            .api_key(auth.api_key_id, auth.api_key_name.clone())
            .resource("log_source", Some(*id), None::<String>)
            .client_context(&client)
            .details(serde_json::json!({
                "reverted_to_version": version_id,
                "new_version_number": version.version_number,
            }))
            .build(),
    );

    Ok(Json(version))
}

/// Discard draft changes and reset to active version
#[utoipa::path(
    post,
    path = "/api/log-sources/{id}/discard-draft",
    tag = "log_sources",
    params(
        ("id" = String, Path, description = "Log source ID")
    ),
    responses(
        (status = 200, description = "Draft discarded, log source reset", body = LogSource),
        (status = 403, description = "Forbidden"),
        (status = 404, description = "Not found"),
    ),
    security(("api_key" = []))
)]
pub async fn discard_log_source_draft(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<TypeIdParam>,
) -> Result<Json<LogSource>, ApiError> {
    ensure_permission(&auth, LOG_SOURCES_EDIT)?;

    let log_source = state.log_source_service.discard_draft(*id).await?;
    Ok(Json(log_source))
}

/// Get draft status for a log source
#[utoipa::path(
    get,
    path = "/api/log-sources/{id}/draft-status",
    tag = "log_sources",
    params(
        ("id" = String, Path, description = "Log source ID")
    ),
    responses(
        (status = 200, description = "Draft status", body = LogSourceWithDraftStatus),
        (status = 403, description = "Forbidden"),
        (status = 404, description = "Not found"),
    ),
    security(("api_key" = []))
)]
pub async fn get_log_source_draft_status(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<TypeIdParam>,
) -> Result<Json<LogSourceWithDraftStatus>, ApiError> {
    ensure_permission(&auth, LOG_SOURCES_VIEW)?;

    let status = state.log_source_service.get_draft_status(*id).await?;
    Ok(Json(status))
}

// ============================================================================
// OpenAPI Documentation
// ============================================================================

/// OpenAPI documentation for log sources endpoints
#[derive(utoipa::OpenApi)]
#[openapi(
    paths(
        list_log_sources,
        get_log_source,
        create_log_source,
        update_log_source,
        delete_log_source,
        toggle_log_source,
        validate_log_source,
        deploy_log_source,
        undeploy_log_source,
        get_log_source_deployments,
        get_log_source_health,
        get_all_ingestion_history,
        validate_vrl,
        validate_namespace,
        test_vrl,
        test_vrl_live,
        deploy_all_log_sources,
        get_log_source_versions,
        publish_log_source,
        revert_log_source_version,
        discard_log_source_draft,
        get_log_source_draft_status,
    ),
    components(schemas(
        ToggleRequest,
        ValidateVrlRequest,
        ValidateNamespaceRequest,
        ValidateNamespaceResponse,
        TestVrlRequest,
        TestVrlLiveRequest,
        LiveTestResult,
        LogSourceVersion,
        LogSourceWithDraftStatus,
        VrlValidationResult,
        VrlDiagnostic,
        ParserTestResult,
        // NAN-2196: the health response and its nested collector-error record.
        // Registered explicitly per the repo's OpenAPI convention rather than
        // left to utoipa's transitive collection, so a future refactor that
        // stops referencing them from a `body =` annotation cannot silently
        // drop them from the published spec.
        LogSourceHealth,
        CollectorError,
    ))
)]
pub struct LogSourcesApiDoc;

impl LogSourcesApiDoc {
    pub fn paths() -> Vec<utoipa::openapi::path::PathItem> {
        vec![]
    }

    pub fn schemas() -> Vec<(
        &'static str,
        utoipa::openapi::RefOr<utoipa::openapi::schema::Schema>,
    )> {
        vec![]
    }
}
