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
//! - GET /api/log-sources/delivery-status?generation=N - Re-check a role-split deploy

use super::AuditExt;
use axum::{
    extract::{Path, Query, State},
    Extension, Json,
};
use nanosiem_core::audit::{
    AuditEvent, AuditSource, ClientContext, LOG_SOURCE_CREATED, LOG_SOURCE_DELETED,
    LOG_SOURCE_DEPLOYED, LOG_SOURCE_DEPLOY_ALL, LOG_SOURCE_OCSF_UNATTESTED_PUBLISH,
    LOG_SOURCE_OCSF_UNATTESTED_SYSTEM_INSTALL,
    LOG_SOURCE_PUBLISHED, LOG_SOURCE_REVERTED,
    LOG_SOURCE_TOGGLED, LOG_SOURCE_UNDEPLOYED, LOG_SOURCE_UPDATED,
};
use nanosiem_core::log_sources::{
    LogSourceServiceError,
    DeploymentResult, IngestionHistoryPoint, LiveTestResult, LogSource, LogSourceDeployment,
    CollectorError, LogSourceHealth, LogSourceVersion, LogSourceWithDraftStatus, NewLogSource,
    ParserTestResult,
    UpdateLogSource, VrlDiagnostic, VrlValidationResult,
};
use nanosiem_core::parsers::vector_config_remote_delivery::{
    self as remote_delivery, DeliveryState, GenerationDelivery, GenerationDeliveryStatus,
    IngestHostDelivery,
};
use nanosiem_core::typeid::TypeIdParam;
use super::principal_admission::{principal_key, refused, run_admitted, too_many_requests};
use axum::response::{IntoResponse, Response};
use serde::Deserialize;
use utoipa::{IntoParams, ToSchema};

use super::log_source_deploy_jobs::{run_deploy_job, DeployAudit, DeployOk, DeployWaitQuery};
use crate::middleware::{ensure_permission, AuthContext};
use crate::{error::ApiError, state::AppState};
use nanosiem_core::log_sources::deploy_jobs::{DeployJob, DeployJobKind};

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
/// deploy transition.
///
/// NAN-2202: the implementation moved to `LogSourceService` so the non-HTTP
/// writers that also create active sources — collector stream provisioning and
/// repository parser import — can run the SAME check. This stays as a thin
/// adapter for `ApiError`; `From<TierError>` maps a cap hit to 403.
async fn enforce_data_source_limit(state: &AppState) -> Result<(), ApiError> {
    Ok(state.log_source_service.enforce_data_source_limit().await?)
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
///
/// NAN-5132: runs as a background deploy job. `?wait=false` answers 202 with
/// the job (poll its `status_path`); the default waits and answers 200 as
/// before. The deploy finishes or rolls back even if the client disconnects.
#[utoipa::path(
    post,
    path = "/api/log-sources/{id}/deploy",
    tag = "log_sources",
    params(
        ("id" = String, Path, description = "Log source ID"),
        DeployWaitQuery,
    ),
    request_body(content = Option<DeployLogSourceRequest>, description = "Optional: OCSF samples or the unattested acknowledgement for a source's first go-live"),
    responses(
        (status = 200, description = "Deployment result (wait=true)", body = DeploymentResult),
        (status = 202, description = "Deploy job accepted (wait=false, or wait=true still running after 270 s)", body = DeployJob),
        (status = 422, description = "OCSF validation failed, or no OCSF receipt for a first go-live (checked before any job is created)"),
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
    Query(wait): Query<DeployWaitQuery>,
    body: axum::body::Bytes,
) -> Result<Response, ApiError> {
    let request_started = std::time::Instant::now();
    ensure_permission(&auth, LOG_SOURCES_DEPLOY)?;
    let request = DeployLogSourceRequest::from_body(&body)?;

    // Tier enforcement at the draft→active transition (NAN-1920): a draft is
    // exempt from the data-source cap, so activating one via deploy is the point
    // it starts consuming a slot. Enforce here so feeds can't be staged past the
    // limit as drafts and then deployed. Non-draft sources were already counted
    // at create, so re-deploying an active source skips the check.
    if state.log_source_service.get(*id).await?.lifecycle_status == "draft" {
        enforce_data_source_limit(&state).await?;
    }

    let id = *id;
    // NAN-5079: the OCSF gate runs BEFORE the job is enqueued, so a refusal is
    // a 422 on both wait=true and wait=false and no job is created.
    let gate = nanosiem_core::log_sources::OcsfGateInput {
        samples: request.ocsf_sample_logs,
        acknowledge_unattested: request.acknowledge_unattested
            || request.unattested_system_install,
    };
    let checked = state.log_source_service.ocsf_deploy_precheck(id, &gate).await?;
    if checked.outcome == nanosiem_core::log_sources::OcsfGateOutcome::Unattested {
        audit_unattested_go_live(&state, &auth, &client, id, "deploy", request.unattested_system_install);
    }

    let audit = DeployAudit {
        action: LOG_SOURCE_DEPLOYED,
        auth: auth.clone(),
        client,
        extra: Some(serde_json::json!({ "ocsf_gate": format!("{:?}", checked.outcome) })),
    };
    run_deploy_job(&state, audit, DeployJobKind::Deploy, Some(id), wait.wait, request_started, move |state, progress| async move {
        // A save between the check and the job must not go live unchecked.
        state
            .log_source_service
            .ensure_ocsf_generation_unchanged(id, &checked)
            .await?;
        let result = state
            .log_source_service
            .deploy_with_progress(id, progress.as_ref())
            .await?;
        Ok(DeployOk::Result(result))
    })
    .await
}

/// Undeploy a log source from Vector
///
/// NAN-5132: a background deploy job; `?wait=` as for deploy.
#[utoipa::path(
    post,
    path = "/api/log-sources/{id}/undeploy",
    tag = "log_sources",
    params(
        ("id" = String, Path, description = "Log source ID"),
        DeployWaitQuery,
    ),
    responses(
        (status = 200, description = "Undeployment result (wait=true)", body = DeploymentResult),
        (status = 202, description = "Undeploy job accepted (wait=false, or wait=true still running after 270 s)", body = DeployJob),
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
    Query(wait): Query<DeployWaitQuery>,
) -> Result<Response, ApiError> {
    let request_started = std::time::Instant::now();
    ensure_permission(&auth, LOG_SOURCES_DEPLOY)?;

    // 404 before a job exists for a source that does not.
    state.log_source_service.get(*id).await?;

    let id = *id;
    let audit = DeployAudit { action: LOG_SOURCE_UNDEPLOYED, auth: auth.clone(), client, extra: None };
    run_deploy_job(&state, audit, DeployJobKind::Undeploy, Some(id), wait.wait, request_started, move |state, progress| async move {
        let result = state
            .log_source_service
            .undeploy_with_progress(id, progress.as_ref())
            .await?;
        Ok(DeployOk::Result(result))
    })
    .await
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
        (status = 429, description = "Too many parser tests or validations running for this caller or server; retry after Retry-After"),
    ),
    security(("api_key" = []))
)]
pub async fn validate_vrl(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Json(request): Json<ValidateVrlRequest>,
) -> Result<Json<VrlValidationResult>, Response> {
    ensure_permission(&auth, LOG_SOURCES_VIEW).map_err(IntoResponse::into_response)?;
    // NAN-5400: a view-only caller's draft compiles only in the bounded
    // parser-test worker, under the same per-principal admission as tests.
    let permit = nanosiem_core::parsers::test_sandbox::admit(Some(&principal_key(&auth)))
        .await
        .map_err(refused)?;
    let service = state.log_source_service.clone();
    let vrl_code = request.vrl_code;
    let result = run_admitted(
        permit,
        nanosiem_core::parsers::test_sandbox::admitted(async move {
            service.validate_vrl_isolated(&vrl_code).await
        }),
    )
    .await?
    .map_err(parser_test_error)?;
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
    /// NAN-5079: also validate the output against the embedded OCSF
    /// contract (after VRL ran). The result carries `schema_validation`.
    /// Ignored when the deployment's schema profile is not OCSF.
    #[serde(default)]
    pub validate_ocsf: bool,
    /// NAN-5079: bind a passing OCSF test to this source's STORED parser
    /// generation (only for a caller with `log_sources:edit`; otherwise the
    /// test still runs, unattested). An unsaved buffer is validated but never
    /// attested.
    #[serde(default)]
    #[schema(value_type = Option<String>)]
    pub log_source_id: Option<TypeIdParam>,
}

/// Test VRL against a sample log
#[utoipa::path(
    post,
    path = "/api/log-sources/test-vrl",
    tag = "log_sources",
    request_body = TestVrlRequest,
    responses(
        (status = 200, description = "VRL test result", body = ParserTestResult),
        (status = 400, description = "Sample larger than the per-event limit"),
        (status = 403, description = "Forbidden"),
        (status = 429, description = "Too many parser tests running for this caller or server; retry after Retry-After"),
    ),
    security(("api_key" = []))
)]
pub async fn test_vrl(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Json(request): Json<TestVrlRequest>,
) -> Result<Json<ParserTestResult>, Response> {
    ensure_permission(&auth, LOG_SOURCES_VIEW).map_err(IntoResponse::into_response)?;
    // Attesting writes the source's receipt, so it needs log_sources:edit. A
    // viewer's test (the Test Lab sends the id for everyone) is still
    // validated, just never attested: refusing it would break read-only use.
    let attest_id = request
        .log_source_id
        .as_ref()
        .filter(|_| auth.has_permission(LOG_SOURCES_EDIT))
        .map(|id| **id);
    check_test_sample(&request.sample_log).map_err(IntoResponse::into_response)?;
    // NAN-5396: the replica's one parser-test admission, per principal,
    // before any validation, compile or query work.
    let permit = nanosiem_core::parsers::test_sandbox::admit(Some(&principal_key(&auth)))
        .await
        .map_err(refused)?;

    let service = state.log_source_service.clone();
    let validate_ocsf = request.validate_ocsf;
    let vrl_code = request.vrl_code.clone();
    let extension_vrl = request.extension_vrl.clone();
    let sample_log = request.sample_log.clone();
    let result = run_admitted(permit, nanosiem_core::parsers::test_sandbox::admitted(async move {
        if validate_ocsf {
            service
                .test_vrl_chain_ocsf(&vrl_code, extension_vrl.as_deref(), &sample_log)
                .await
        } else {
            service
                .test_vrl_chain(&vrl_code, extension_vrl.as_deref(), &sample_log)
                .await
        }
    }))
    .await?
    .map_err(parser_test_error)?;

    // NAN-5079: a passing OCSF test of the STORED generation is a receipt.
    if validate_ocsf && result.success {
        if let Some(id) = attest_id {
            state
                .log_source_service
                .record_ocsf_test_attestation(
                    id,
                    &request.vrl_code,
                    request.extension_vrl.as_deref(),
                    &request.sample_log,
                )
                .await
                .map_err(|e| ApiError::from(e).into_response())?;
        }
    }
    Ok(Json(result))
}

/// A parser-test service error: busy workers are a 429 with `Retry-After`
/// (NAN-5234); anything else a 500.
fn parser_test_error(error: LogSourceServiceError) -> Response {
    match error {
        LogSourceServiceError::ParserTestBusy(message) => {
            too_many_requests(message, PARSER_TEST_RETRY_AFTER_SECS)
        }
        other => ApiError::InternalError(format!("Parser test failed: {}", other)).into_response(),
    }
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
        (status = 429, description = "Too many parser tests running for this caller or server; retry after Retry-After"),
    ),
    security(("api_key" = []))
)]
pub async fn test_vrl_live(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Json(request): Json<TestVrlLiveRequest>,
) -> Result<Json<Vec<LiveTestResult>>, Response> {
    test_vrl_live_inner(state, auth, request).await
}

async fn test_vrl_live_inner(
    state: AppState,
    auth: AuthContext,
    request: TestVrlLiveRequest,
) -> Result<Json<Vec<LiveTestResult>>, Response> {
    let api = |e: ApiError| e.into_response();
    ensure_permission(&auth, LOG_SOURCES_VIEW).map_err(api)?;

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
    ensure_permission(&auth, nanosiem_core::auth::permissions::SEARCH_EXECUTE).map_err(api)?;
    // NAN-5396: the replica's one parser-test admission, per principal,
    // before any validation, compile or query work.
    let permit = nanosiem_core::parsers::test_sandbox::admit(Some(&principal_key(&auth)))
        .await
        .map_err(refused)?;

    let limit = request.limit.unwrap_or(10);
    let service = state.log_source_service.clone();
    let scope = auth.effective_viewer_scope();
    let results = run_admitted(permit, nanosiem_core::parsers::test_sandbox::admitted(async move {
        service
            .test_vrl_live(
                &request.vrl_code,
                request.current_vrl.as_deref(),
                &request.source_type,
                limit,
                &scope,
            )
            .await
    }))
    .await?
    .map_err(parser_test_error)?;
    Ok(Json(results))
}

/// Retry-After for a refused parser test.
const PARSER_TEST_RETRY_AFTER_SECS: u64 = nanosiem_core::parsers::test_sandbox::RETRY_AFTER_SECONDS;

/// Largest raw `sample_log` accepted by test-vrl. Real events are tens of KiB.
pub const MAX_TEST_SAMPLE_BYTES: usize = 1024 * 1024;

/// Reject an oversized test sample with a 400 before any work is done.
fn check_test_sample(sample: &str) -> Result<(), ApiError> {
    if sample.len() > MAX_TEST_SAMPLE_BYTES {
        return Err(ApiError::BadRequest(format!(
            "sample_log is {} bytes; a parser test accepts at most {MAX_TEST_SAMPLE_BYTES} bytes",
            sample.len()
        )));
    }
    Ok(())
}

/// Deploy all enabled log sources
///
/// NAN-5132: a background deploy job; `?wait=` as for deploy.
#[utoipa::path(
    post,
    path = "/api/log-sources/deploy-all",
    tag = "log_sources",
    params(DeployWaitQuery),
    responses(
        (status = 200, description = "All enabled log sources deployed (wait=true)"),
        (status = 202, description = "Deploy-all job accepted (wait=false, or wait=true still running after 270 s)", body = DeployJob),
        (status = 403, description = "Forbidden"),
    ),
    security(("api_key" = []))
)]
pub async fn deploy_all_log_sources(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Extension(client): Extension<ClientContext>,
    Query(wait): Query<DeployWaitQuery>,
) -> Result<Response, ApiError> {
    let request_started = std::time::Instant::now();
    ensure_permission(&auth, LOG_SOURCES_DEPLOY)?;

    let audit = DeployAudit { action: LOG_SOURCE_DEPLOY_ALL, auth: auth.clone(), client, extra: None };
    run_deploy_job(&state, audit, DeployJobKind::DeployAll, None, wait.wait, request_started, move |state, progress| async move {
        state
            .log_source_service
            .deploy_all_with_progress(progress.as_ref())
            .await?;
        Ok(DeployOk::Done(
            serde_json::json!({"deployed": true}),
            "All enabled log sources deployed".to_string(),
        ))
    })
    .await
}

/// Query for [`get_delivery_status`].
#[derive(Debug, Deserialize, IntoParams)]
pub struct DeliveryStatusQuery {
    /// The generation a deploy published (its result's `delivery.generation`).
    pub generation: i64,
}

/// Re-check where a deploy's Vector configuration generation stands on the
/// ingest hosts (NAN-5279). One poll of every host's relay, no waiting: a
/// deploy that returned `delivery.state = "pending"` reads `acknowledged`
/// here once every host installed it.
#[utoipa::path(
    get,
    path = "/api/log-sources/delivery-status",
    tag = "log_sources",
    params(DeliveryStatusQuery),
    responses(
        (status = 200, description = "Delivery state of the generation across the ingest hosts", body = GenerationDeliveryStatus),
        (status = 400, description = "Invalid generation"),
        (status = 403, description = "Forbidden"),
    ),
    security(("api_key" = []))
)]
pub async fn get_delivery_status(
    Extension(auth): Extension<AuthContext>,
    Query(query): Query<DeliveryStatusQuery>,
) -> Result<Json<GenerationDeliveryStatus>, ApiError> {
    ensure_permission(&auth, LOG_SOURCES_VIEW)?;
    if query.generation <= 0 {
        return Err(ApiError::BadRequest("generation must be positive".to_string()));
    }
    Ok(Json(remote_delivery::delivery_status(query.generation).await))
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

/// Optional compare-and-swap guard for publish / discard-draft (NAN-4919):
/// the `updated_at` of the working copy the caller reviewed.
#[derive(Debug, Default, Deserialize, ToSchema)]
pub struct ExpectedRevision {
    pub expected_updated_at: Option<chrono::DateTime<chrono::Utc>>,
}

/// Publish body (all optional; an empty body is a plain publish).
#[derive(Debug, Default, Deserialize, ToSchema)]
pub struct PublishLogSourceRequest {
    /// NAN-4919 compare-and-swap guard (see [`ExpectedRevision`]).
    #[serde(default)]
    pub expected_updated_at: Option<chrono::DateTime<chrono::Utc>>,
    /// NAN-5079: representative raw events for the OCSF gate. On an OCSF
    /// deployment a changed parser goes live only after each sample passes
    /// VRL execution and OCSF validation; at most 50, 256 KiB each.
    #[serde(default)]
    pub ocsf_sample_logs: Vec<String>,
    /// NAN-5079 (D2): publish a source's FIRST parser without a sample. The
    /// publish is audited, and the next parser change needs a passing sample.
    #[serde(default)]
    pub acknowledge_unattested: bool,
}

/// Deploy body (all optional; an empty body is a plain deploy). Only a
/// source's first go-live (not deployed, never published) is gated.
#[derive(Debug, Default, Deserialize, ToSchema)]
pub struct DeployLogSourceRequest {
    /// NAN-5079: representative raw events for the OCSF gate; at most 50,
    /// 256 KiB each, 2 MiB total.
    #[serde(default)]
    pub ocsf_sample_logs: Vec<String>,
    /// NAN-5079 (D2): go live without a sample. Audited; the next parser
    /// change needs a passing sample.
    #[serde(default)]
    pub acknowledge_unattested: bool,
    /// NAN-5079: the Add data flow's own first go-live without a sample (the
    /// operator was not asked). Gated exactly like `acknowledge_unattested`
    /// but audited as a system-initiated unattested install, not as an
    /// operator acknowledgement.
    #[serde(default)]
    pub unattested_system_install: bool,
}

/// NAN-5079: audit a first go-live without a passing OCSF sample. An operator's
/// explicit acknowledgement and Add data's system-initiated install (the user
/// never ticked anything) are distinct actions.
fn audit_unattested_go_live(
    state: &AppState,
    auth: &AuthContext,
    client: &ClientContext,
    id: uuid::Uuid,
    action: &str,
    system_install: bool,
) {
    let (event, initiator) = if system_install {
        (LOG_SOURCE_OCSF_UNATTESTED_SYSTEM_INSTALL, "system")
    } else {
        (LOG_SOURCE_OCSF_UNATTESTED_PUBLISH, "user_acknowledged")
    };
    state.emit_audit(
        AuditEvent::builder(AuditSource::LogSource, event)
            .actor(Some(auth.user_id()), None)
            .api_key(auth.api_key_id, auth.api_key_name.clone())
            .resource("log_source", Some(id), None::<String>)
            .client_context(client)
            .details(serde_json::json!({ "action": action, "initiator": initiator }))
            .build(),
    );
}

impl DeployLogSourceRequest {
    fn from_body(body: &[u8]) -> Result<Self, ApiError> {
        if body.iter().all(u8::is_ascii_whitespace) {
            return Ok(Self::default());
        }
        serde_json::from_slice::<Self>(body)
            .map_err(|e| ApiError::BadRequest(format!("Invalid request body: {e}")))
    }
}

impl PublishLogSourceRequest {
    fn from_body(body: &[u8]) -> Result<Self, ApiError> {
        if body.iter().all(u8::is_ascii_whitespace) {
            return Ok(Self::default());
        }
        serde_json::from_slice::<Self>(body)
            .map_err(|e| ApiError::BadRequest(format!("Invalid request body: {e}")))
    }
}

impl ExpectedRevision {
    /// The body is optional and existing clients POST nothing (sometimes with
    /// a JSON content type), so an empty or whitespace body means "no guard".
    fn from_body(body: &[u8]) -> Result<Option<chrono::DateTime<chrono::Utc>>, ApiError> {
        if body.iter().all(u8::is_ascii_whitespace) {
            return Ok(None);
        }
        serde_json::from_slice::<ExpectedRevision>(body)
            .map(|revision| revision.expected_updated_at)
            .map_err(|e| ApiError::BadRequest(format!("Invalid request body: {e}")))
    }
}

/// Publish working copy as new version and deploy
///
/// NAN-5132: the publish (validation, version, deploy) is a background deploy
/// job; `?wait=` as for deploy. A 409 for a stale `expected_updated_at` comes
/// back from the job (`error_status: 409`) when `wait=false`.
#[utoipa::path(
    post,
    path = "/api/log-sources/{id}/publish",
    tag = "log_sources",
    params(
        ("id" = String, Path, description = "Log source ID"),
        DeployWaitQuery,
    ),
    request_body(content = Option<PublishLogSourceRequest>, description = "Optional: revision guard, OCSF samples, unattested acknowledgement"),
    responses(
        (status = 409, description = "The working copy changed since expected_updated_at"),
        (status = 200, description = "Publish and deploy result (wait=true)", body = DeploymentResult),
        (status = 202, description = "Publish job accepted (wait=false, or wait=true still running after 270 s)", body = DeployJob),
        (status = 422, description = "OCSF validation failed or no OCSF receipt for a changed parser (checked before any job is created)"),
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
    Query(wait): Query<DeployWaitQuery>,
    body: axum::body::Bytes,
) -> Result<Response, ApiError> {
    let request_started = std::time::Instant::now();
    ensure_permission(&auth, LOG_SOURCES_DEPLOY)?;

    let request = PublishLogSourceRequest::from_body(&body)?;
    let id = *id;
    // NAN-5079: the OCSF gate runs BEFORE the job is enqueued (422, no job, on
    // both wait paths). The job then publishes AT the revision the gate
    // checked, so an edit in between is a 409, never an unchecked publish.
    // This also answers 404 before a job exists for a missing source.
    let gate = nanosiem_core::log_sources::OcsfGateInput {
        samples: request.ocsf_sample_logs,
        acknowledge_unattested: request.acknowledge_unattested,
    };
    let checked = state
        .log_source_service
        .ocsf_publish_precheck(id, request.expected_updated_at, &gate)
        .await?;
    // Audited at the acknowledgement itself: once the job creates the version
    // it is active even if its deploy then fails.
    if checked.outcome == nanosiem_core::log_sources::OcsfGateOutcome::Unattested {
        audit_unattested_go_live(&state, &auth, &client, id, "publish", false);
    }

    let expected = Some(checked.revision);
    let audit = DeployAudit {
        action: LOG_SOURCE_PUBLISHED,
        auth: auth.clone(),
        client,
        extra: Some(serde_json::json!({ "ocsf_gate": format!("{:?}", checked.outcome) })),
    };
    let user_id = auth.user_id();
    run_deploy_job(&state, audit, DeployJobKind::Publish, Some(id), wait.wait, request_started, move |state, progress| async move {
        let result = state
            .log_source_service
            .publish_with_progress(id, Some(user_id), expected, progress.as_ref())
            .await?;
        Ok(DeployOk::Result(result))
    })
    .await
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
    request_body(content = Option<ExpectedRevision>, description = "Optional: refuse with 409 unless the working copy is still this revision"),
    responses(
        (status = 409, description = "The working copy changed since expected_updated_at"),
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
    body: axum::body::Bytes,
) -> Result<Json<LogSource>, ApiError> {
    ensure_permission(&auth, LOG_SOURCES_EDIT)?;

    let expected = ExpectedRevision::from_body(&body)?;
    let log_source = state.log_source_service.discard_draft(*id, expected).await?;
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
        get_delivery_status,
        get_log_source_versions,
        publish_log_source,
        revert_log_source_version,
        discard_log_source_draft,
        get_log_source_draft_status,
    ),
    components(schemas(
        ExpectedRevision,
        PublishLogSourceRequest,
        DeployLogSourceRequest,
        nanosiem_core::log_sources::OcsfAttestationStatus,
        nanosiem_core::log_sources::OcsfAttestationState,
        nanosiem_core::parsers::OcsfValidationResult,
        nanosiem_core::parsers::OcsfValidationDiagnostic,
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
        // NAN-5279: generation-delivery state on deploy results + re-check.
        DeliveryState,
        GenerationDelivery,
        GenerationDeliveryStatus,
        IngestHostDelivery,
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
