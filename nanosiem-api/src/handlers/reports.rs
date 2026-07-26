// SPDX-License-Identifier: AGPL-3.0-or-later

//! Scheduled report handlers (NAN-1793).
//!
//! Report definitions schedule a saved search or a dashboard to produce
//! downloadable artifacts on a cron recurrence. Definitions/runs/artifacts are
//! owner-scoped: a user manages their own reports; an admin (`settings:system`)
//! sees all. Execution runs under the report OWNER's per-source scope,
//! resolved fail-closed at run time (NAN-1809) — see
//! `nanosiem_core::reports::service`. Because rendered artifacts carry no
//! per-row source attribution, a source-restricted viewer whose deny set
//! intersects the stored provenance manifest cannot be row-filtered and is
//! refused the download; ownership is not an exemption.

use axum::{
    extract::{Path, Query, State},
    http::{header, StatusCode},
    response::IntoResponse,
    Extension, Json,
};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

use nanosiem_core::audit::{
    AuditEvent, AuditSource, ClientContext, REPORT_CREATED, REPORT_DELETED, REPORT_RUN_TRIGGERED,
    REPORT_UPDATED,
};
use nanosiem_core::auth::permissions;
use nanosiem_core::reports::{
    report_run_requires_search_sql, required_report_permissions, NewReportDefinition,
    ReportArtifactMeta, ReportAuthorizationError, ReportAuthorizationIntent, ReportAuthorizer,
    ReportDefinition, ReportError, ReportRun, ReportService, ReportSourceType,
    UpdateReportDefinition,
};
use nanosiem_core::typeid::TypeIdParam;

use super::AuditExt;
use crate::error::ApiError;
use crate::middleware::{ensure_permission, AuthContext};
use crate::state::AppState;

/// Lower bound on the relative report window (1 minute).
const MIN_TIME_RANGE_SECONDS: i64 = 60;
/// Upper bound on the relative report window (90 days).
const MAX_TIME_RANGE_SECONDS: i64 = 90 * 86_400;
/// Default relative window when unspecified (24 hours).
const DEFAULT_TIME_RANGE_SECONDS: i64 = 86_400;
/// Retention bounds (runs kept per definition).
const MIN_RETENTION_RUNS: i32 = 1;
const MAX_RETENTION_RUNS: i32 = 100;
const DEFAULT_RETENTION_RUNS: i32 = 20;
/// Max name length.
const MAX_NAME_LENGTH: usize = 200;

// ============================================================================
// Request / response types
// ============================================================================

/// Create a report definition.
#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateReportRequest {
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
    /// "search" or "dashboard".
    pub source_type: String,
    /// nPL query (required for search reports).
    #[serde(default)]
    pub source_query: Option<String>,
    /// Optional query_library provenance id (search reports).
    #[serde(default)]
    pub saved_query_id: Option<i32>,
    /// Dashboard id (required for dashboard reports), as a `dash_…` typeid.
    #[serde(default, with = "nanosiem_core::typeid::dashboard::opt")]
    #[schema(value_type = Option<String>)]
    pub source_dashboard_id: Option<Uuid>,
    /// Relative lookback window in seconds (default 86400 = 24h).
    #[serde(default)]
    pub time_range_seconds: Option<i64>,
    pub cron_expression: String,
    #[serde(default)]
    pub enabled: Option<bool>,
    /// Runs kept per definition (default 20, max 100).
    #[serde(default)]
    pub retention_runs: Option<i32>,
}

/// Update a report definition (only provided fields change).
#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateReportRequest {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default, deserialize_with = "double_option")]
    #[schema(value_type = Option<String>)]
    pub description: Option<Option<String>>,
    /// Replacement nPL query (search reports only; must be non-empty when
    /// provided — a search report's query cannot be blanked).
    #[serde(default)]
    pub source_query: Option<String>,
    #[serde(default)]
    pub time_range_seconds: Option<i64>,
    #[serde(default)]
    pub cron_expression: Option<String>,
    #[serde(default)]
    pub enabled: Option<bool>,
    #[serde(default)]
    pub retention_runs: Option<i32>,
}

/// Distinguish an absent field (`None`) from an explicit JSON `null`
/// (`Some(None)`) for tri-state description updates.
fn double_option<'de, T, D>(de: D) -> Result<Option<Option<T>>, D::Error>
where
    T: Deserialize<'de>,
    D: serde::Deserializer<'de>,
{
    Deserialize::deserialize(de).map(Some)
}

/// Query params for listing report definitions.
#[derive(Debug, Deserialize, IntoParams)]
pub struct ListReportsQuery {
    /// "mine" (default) or "all" (admin only — falls back to "mine" otherwise).
    #[serde(default)]
    pub filter: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ReportDefinitionResponse {
    pub report: ReportDefinition,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ReportListResponse {
    pub reports: Vec<ReportDefinition>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ReportRunListResponse {
    pub runs: Vec<ReportRun>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ReportRunResponse {
    pub run: ReportRun,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct TriggerReportResponse {
    /// The newly-started run id (`reprun_…`).
    pub run_id: String,
}

// ============================================================================
// Helpers
// ============================================================================

fn report_service(state: &AppState) -> ReportService {
    ReportService::with_node_id(
        state.pool.clone(),
        state.search_service.clone(),
        state.node_id.clone(),
    )
}

fn is_admin(auth: &AuthContext) -> bool {
    auth.claims.has_permission(permissions::SETTINGS_SYSTEM)
}

fn map_report_err(e: ReportError) -> ApiError {
    match e {
        ReportError::NotFound(_) => ApiError::NotFound("report not found".to_string()),
        ReportError::InvalidCron(m) | ReportError::InvalidDefinition(m) => {
            ApiError::ValidationError(m)
        }
        ReportError::Timeout => ApiError::Timeout("report execution timed out".to_string()),
        // Execution pool saturated — shed rather than queue (see ReportService's
        // process-global run semaphore). Tells the client to retry shortly.
        ReportError::Busy => ApiError::TooManyRequests(
            "too many report runs in flight; try again shortly".to_string(),
        ),
        ReportError::AuthorizationDenied(message) => ApiError::Forbidden(message),
        ReportError::AuthorizationResolution(message) => ApiError::InternalError(message),
        other => ApiError::InternalError(other.to_string()),
    }
}

fn map_report_auth_err(error: ReportAuthorizationError) -> ApiError {
    match error {
        ReportAuthorizationError::Denied(message) => ApiError::Forbidden(message),
        ReportAuthorizationError::Resolution(message) => ApiError::InternalError(message),
    }
}

/// Apply source-aware capabilities to the CURRENT request credential. Because
/// API-key permissions live in the key itself while JWT permissions come from
/// the user's roles, this must use `AuthContext` for credential parity.
fn ensure_report_permissions(
    auth: &AuthContext,
    source_type: ReportSourceType,
    intent: ReportAuthorizationIntent,
) -> Result<(), ApiError> {
    for permission in required_report_permissions(source_type, intent) {
        ensure_permission(auth, permission)?;
    }
    Ok(())
}

fn ensure_report_search_sql_permission(
    auth: &AuthContext,
    requires_search_sql: bool,
) -> Result<(), ApiError> {
    if requires_search_sql {
        ensure_permission(auth, permissions::SEARCH_SQL)?;
    }
    Ok(())
}

/// Apply the CURRENT requester's dashboard object ACL. This is separate from
/// the owner execution check because admins may operate a report they do not
/// own, but must not use it to read a dashboard they cannot access directly.
async fn ensure_report_dashboard_access(
    state: &AppState,
    auth: &AuthContext,
    definition: &ReportDefinition,
) -> Result<bool, ApiError> {
    if definition.source_type != ReportSourceType::Dashboard {
        return Ok(false);
    }
    let dashboard_id = definition.source_dashboard_id.ok_or_else(|| {
        ApiError::Forbidden("the report no longer identifies a dashboard".to_string())
    })?;
    let authorization = ReportAuthorizer::new(state.pool.clone())
        .authorize_dashboard_access(auth.user_id(), dashboard_id)
        .await
        .map_err(map_report_auth_err)?;
    Ok(authorization.requires_search_sql())
}

/// Load a definition and enforce owner-or-admin access.
async fn load_owned_definition(
    service: &ReportService,
    auth: &AuthContext,
    def_id: Uuid,
) -> Result<ReportDefinition, ApiError> {
    let def = service.get_definition(def_id).await.map_err(map_report_err)?;
    if def.owner_id != auth.user_id() && !is_admin(auth) {
        return Err(ApiError::Forbidden(
            "you do not own this report".to_string(),
        ));
    }
    Ok(def)
}

// ============================================================================
// Handlers
// ============================================================================

/// Create a scheduled report.
#[utoipa::path(
    post,
    path = "/api/reports",
    tag = "reports",
    request_body = CreateReportRequest,
    responses(
        (status = 200, description = "Report created", body = ReportDefinitionResponse),
        (status = 400, description = "Invalid request"),
        (status = 403, description = "Forbidden"),
    ),
    security(("api_key" = []))
)]
pub async fn create_report(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Extension(client): Extension<ClientContext>,
    Json(request): Json<CreateReportRequest>,
) -> Result<Json<ReportDefinitionResponse>, ApiError> {
    // Reports run searches — require the search-execute permission to create one.
    ensure_permission(&auth, permissions::SEARCH_EXECUTE)?;

    let name = request.name.trim().to_string();
    if name.is_empty() || name.len() > MAX_NAME_LENGTH {
        return Err(ApiError::ValidationError(format!(
            "name must be 1..={MAX_NAME_LENGTH} characters"
        )));
    }

    let source_type = ReportSourceType::from_str(&request.source_type).ok_or_else(|| {
        ApiError::ValidationError("source_type must be 'search' or 'dashboard'".to_string())
    })?;

    ensure_report_permissions(
        &auth,
        source_type,
        ReportAuthorizationIntent::Execute,
    )?;

    // Dashboard reports need access to THAT dashboard. There is no admin
    // bypass: this mirrors direct dashboard reads and the run-time recheck.
    let requires_search_sql = if source_type == ReportSourceType::Dashboard {
        let dashboard_id = request.source_dashboard_id.ok_or_else(|| {
            ApiError::ValidationError(
                "dashboard report requires source_dashboard_id".to_string(),
            )
        })?;
        let authorization = ReportAuthorizer::new(state.pool.clone())
            .authorize_dashboard_access(auth.user_id(), dashboard_id)
            .await
            .map_err(map_report_auth_err)?;
        authorization.requires_search_sql()
    } else {
        false
    };
    ensure_report_search_sql_permission(&auth, requires_search_sql)?;

    let time_range_seconds = request
        .time_range_seconds
        .unwrap_or(DEFAULT_TIME_RANGE_SECONDS)
        .clamp(MIN_TIME_RANGE_SECONDS, MAX_TIME_RANGE_SECONDS);
    let retention_runs = request
        .retention_runs
        .unwrap_or(DEFAULT_RETENTION_RUNS)
        .clamp(MIN_RETENTION_RUNS, MAX_RETENTION_RUNS);

    let new = NewReportDefinition {
        name: name.clone(),
        description: request.description.filter(|d| !d.is_empty()),
        source_type,
        source_query: request.source_query.filter(|q| !q.trim().is_empty()),
        saved_query_id: request.saved_query_id,
        source_dashboard_id: request.source_dashboard_id,
        time_range_seconds,
        cron_expression: request.cron_expression.trim().to_string(),
        owner_id: auth.user_id(),
        enabled: request.enabled.unwrap_or(true),
        retention_runs,
    };

    let service = report_service(&state);
    let report = service.create_definition(new).await.map_err(map_report_err)?;

    state.emit_audit(
        AuditEvent::builder(AuditSource::Report, REPORT_CREATED)
            .actor(Some(auth.user_id()), None)
            .api_key(auth.api_key_id, auth.api_key_name.clone())
            .resource("report", Some(report.id), Some(report.name.clone()))
            .client_context(&client)
            .build(),
    );

    Ok(Json(ReportDefinitionResponse { report }))
}

/// List report definitions (own reports; admins may pass `filter=all`).
#[utoipa::path(
    get,
    path = "/api/reports",
    tag = "reports",
    params(ListReportsQuery),
    responses(
        (status = 200, description = "Reports listed", body = ReportListResponse),
        (status = 403, description = "Forbidden"),
    ),
    security(("api_key" = []))
)]
pub async fn list_reports(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Query(query): Query<ListReportsQuery>,
) -> Result<Json<ReportListResponse>, ApiError> {
    ensure_permission(&auth, permissions::SEARCH_VIEW)?;

    // Only an admin may see every owner's reports; everyone else sees their own.
    let want_all = query.filter.as_deref() == Some("all");
    let owner_scope = if want_all && is_admin(&auth) {
        None
    } else {
        Some(auth.user_id())
    };

    let service = report_service(&state);
    let reports = service
        .list_definitions(owner_scope)
        .await
        .map_err(map_report_err)?;
    Ok(Json(ReportListResponse { reports }))
}

/// Get a report definition.
#[utoipa::path(
    get,
    path = "/api/reports/{id}",
    tag = "reports",
    params(("id" = String, Path, description = "Report ID")),
    responses(
        (status = 200, description = "Report", body = ReportDefinitionResponse),
        (status = 403, description = "Forbidden"),
        (status = 404, description = "Not found"),
    ),
    security(("api_key" = []))
)]
pub async fn get_report(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<TypeIdParam>,
) -> Result<Json<ReportDefinitionResponse>, ApiError> {
    ensure_permission(&auth, permissions::SEARCH_VIEW)?;
    let service = report_service(&state);
    let report = load_owned_definition(&service, &auth, *id).await?;
    Ok(Json(ReportDefinitionResponse { report }))
}

/// Update a report definition.
#[utoipa::path(
    put,
    path = "/api/reports/{id}",
    tag = "reports",
    params(("id" = String, Path, description = "Report ID")),
    request_body = UpdateReportRequest,
    responses(
        (status = 200, description = "Report updated", body = ReportDefinitionResponse),
        (status = 400, description = "Invalid request"),
        (status = 403, description = "Forbidden"),
        (status = 404, description = "Not found"),
    ),
    security(("api_key" = []))
)]
pub async fn update_report(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Extension(client): Extension<ClientContext>,
    Path(id): Path<TypeIdParam>,
    Json(request): Json<UpdateReportRequest>,
) -> Result<Json<ReportDefinitionResponse>, ApiError> {
    ensure_permission(&auth, permissions::SEARCH_EXECUTE)?;
    let service = report_service(&state);
    // Ownership check before mutating.
    let existing = load_owned_definition(&service, &auth, *id).await?;
    ensure_report_permissions(
        &auth,
        existing.source_type,
        ReportAuthorizationIntent::Execute,
    )?;
    let requires_search_sql = ensure_report_dashboard_access(&state, &auth, &existing).await?;
    ensure_report_search_sql_permission(&auth, requires_search_sql)?;

    if let Some(ref name) = request.name {
        if name.trim().is_empty() || name.len() > MAX_NAME_LENGTH {
            return Err(ApiError::ValidationError(format!(
                "name must be 1..={MAX_NAME_LENGTH} characters"
            )));
        }
    }

    let update = UpdateReportDefinition {
        name: request.name.map(|n| n.trim().to_string()),
        description: request.description,
        // Passed through untrimmed (create stores the query as provided); the
        // service rejects empty/whitespace and dashboard-report query edits.
        source_query: request.source_query,
        time_range_seconds: request
            .time_range_seconds
            .map(|s| s.clamp(MIN_TIME_RANGE_SECONDS, MAX_TIME_RANGE_SECONDS)),
        cron_expression: request.cron_expression.map(|c| c.trim().to_string()),
        enabled: request.enabled,
        retention_runs: request
            .retention_runs
            .map(|r| r.clamp(MIN_RETENTION_RUNS, MAX_RETENTION_RUNS)),
    };

    let report = service
        .update_definition(*id, update)
        .await
        .map_err(map_report_err)?;

    state.emit_audit(
        AuditEvent::builder(AuditSource::Report, REPORT_UPDATED)
            .actor(Some(auth.user_id()), None)
            .api_key(auth.api_key_id, auth.api_key_name.clone())
            .resource("report", Some(existing.id), Some(report.name.clone()))
            .client_context(&client)
            .build(),
    );

    Ok(Json(ReportDefinitionResponse { report }))
}

/// Delete a report definition (and its runs/artifacts via cascade).
#[utoipa::path(
    delete,
    path = "/api/reports/{id}",
    tag = "reports",
    params(("id" = String, Path, description = "Report ID")),
    responses(
        (status = 204, description = "Report deleted"),
        (status = 403, description = "Forbidden"),
        (status = 404, description = "Not found"),
    ),
    security(("api_key" = []))
)]
pub async fn delete_report(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Extension(client): Extension<ClientContext>,
    Path(id): Path<TypeIdParam>,
) -> Result<StatusCode, ApiError> {
    ensure_permission(&auth, permissions::SEARCH_EXECUTE)?;
    let service = report_service(&state);
    let existing = load_owned_definition(&service, &auth, *id).await?;

    let deleted = service.delete_definition(*id).await.map_err(map_report_err)?;
    if !deleted {
        return Err(ApiError::NotFound("report not found".to_string()));
    }

    state.emit_audit(
        AuditEvent::builder(AuditSource::Report, REPORT_DELETED)
            .actor(Some(auth.user_id()), None)
            .api_key(auth.api_key_id, auth.api_key_name.clone())
            .resource("report", Some(existing.id), Some(existing.name.clone()))
            .client_context(&client)
            .build(),
    );

    Ok(StatusCode::NO_CONTENT)
}

/// Manually trigger a report run now.
#[utoipa::path(
    post,
    path = "/api/reports/{id}/run",
    tag = "reports",
    params(("id" = String, Path, description = "Report ID")),
    responses(
        (status = 202, description = "Run started", body = TriggerReportResponse),
        (status = 403, description = "Forbidden"),
        (status = 404, description = "Not found"),
    ),
    security(("api_key" = []))
)]
pub async fn trigger_report(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Extension(client): Extension<ClientContext>,
    Path(id): Path<TypeIdParam>,
) -> Result<(StatusCode, Json<TriggerReportResponse>), ApiError> {
    ensure_permission(&auth, permissions::SEARCH_EXECUTE)?;
    let service = report_service(&state);
    let def = load_owned_definition(&service, &auth, *id).await?;

    // Current caller (JWT or API key), current source object, and current owner
    // are all checked before spawning. The execution repeats the owner check to
    // close the trigger-to-run TOCTOU window.
    ensure_report_permissions(
        &auth,
        def.source_type,
        ReportAuthorizationIntent::Execute,
    )?;
    let requires_search_sql = ensure_report_dashboard_access(&state, &auth, &def).await?;
    ensure_report_search_sql_permission(&auth, requires_search_sql)?;
    service
        .authorize_execution(&def)
        .await
        .map_err(map_report_err)?;

    let run_id = service
        .trigger_now(*id, auth.has_permission(permissions::SEARCH_SQL))
        .await
        .map_err(map_report_err)?;

    state.emit_audit(
        AuditEvent::builder(AuditSource::Report, REPORT_RUN_TRIGGERED)
            .actor(Some(auth.user_id()), None)
            .api_key(auth.api_key_id, auth.api_key_name.clone())
            .resource("report", Some(def.id), Some(def.name.clone()))
            .client_context(&client)
            .build(),
    );

    Ok((
        StatusCode::ACCEPTED,
        Json(TriggerReportResponse {
            run_id: nanosiem_core::typeid::encode(nanosiem_core::typeid::report_run::PREFIX, &run_id),
        }),
    ))
}

/// List a report's runs (newest first).
#[utoipa::path(
    get,
    path = "/api/reports/{id}/runs",
    tag = "reports",
    params(("id" = String, Path, description = "Report ID")),
    responses(
        (status = 200, description = "Runs listed", body = ReportRunListResponse),
        (status = 403, description = "Forbidden"),
        (status = 404, description = "Not found"),
    ),
    security(("api_key" = []))
)]
pub async fn list_report_runs(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<TypeIdParam>,
) -> Result<Json<ReportRunListResponse>, ApiError> {
    ensure_permission(&auth, permissions::SEARCH_VIEW)?;
    let service = report_service(&state);
    let definition = load_owned_definition(&service, &auth, *id).await?;
    ensure_report_permissions(
        &auth,
        definition.source_type,
        ReportAuthorizationIntent::Read,
    )?;
    ensure_report_dashboard_access(&state, &auth, &definition).await?;
    let mut runs = service.list_runs(*id, 100).await.map_err(map_report_err)?;
    if runs.iter().any(|run| {
        run.status == "success"
            && report_run_requires_search_sql(
                definition.source_type,
                run.requires_search_sql,
                run.search_sql_requirement_complete,
            )
    }) {
        ensure_report_search_sql_permission(&auth, true)?;
    }
    // F-31: redact (rather than 403) artifact metadata of runs the requester is
    // source-denied, so a restricted viewer cannot obtain the artifact ids to
    // download. Ownership is not an exemption. (List rows never populate
    // `artifacts` today, so this is also a forward guard.)
    let deny = auth.denied_sources.deny_set();
    if !deny.is_empty() {
        for run in runs.iter_mut() {
            if !nanosiem_core::reports::report_artifact_download_allowed(
                deny,
                &run.source_types,
                run.source_types_complete,
            ) {
                run.artifacts.clear();
            }
        }
    }
    Ok(Json(ReportRunListResponse { runs }))
}

/// Get a single run with its artifact metadata.
#[utoipa::path(
    get,
    path = "/api/reports/runs/{run_id}",
    tag = "reports",
    params(("run_id" = String, Path, description = "Run ID")),
    responses(
        (status = 200, description = "Run", body = ReportRunResponse),
        (status = 403, description = "Forbidden"),
        (status = 404, description = "Not found"),
    ),
    security(("api_key" = []))
)]
pub async fn get_report_run(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Path(run_id): Path<TypeIdParam>,
) -> Result<Json<ReportRunResponse>, ApiError> {
    ensure_permission(&auth, permissions::SEARCH_VIEW)?;
    let service = report_service(&state);
    // Resolve ownership without artifact metadata, authorize, then load the
    // protected metadata.
    let run_scope = service
        .get_run_authorization_scope(*run_id)
        .await
        .map_err(map_report_err)?;
    let definition = load_owned_definition(&service, &auth, run_scope.definition_id).await?;
    ensure_report_permissions(
        &auth,
        definition.source_type,
        ReportAuthorizationIntent::Read,
    )?;
    ensure_report_dashboard_access(&state, &auth, &definition).await?;
    if run_scope.has_artifacts
        && report_run_requires_search_sql(
            definition.source_type,
            run_scope.requires_search_sql,
            run_scope.search_sql_requirement_complete,
        )
    {
        ensure_report_search_sql_permission(&auth, true)?;
    }
    let run = service.get_run(*run_id).await.map_err(map_report_err)?;
    // F-31: apply the same source-scope predicate as download — ownership is not
    // an exemption. A restricted requester whose deny set intersects (or cannot
    // be cleared against) the run's manifest is refused the run detail (which
    // carries the downloadable artifact ids). Runs with NO artifacts
    // (failed/running) carry nothing to protect, so a scoped user can still see
    // their status.
    if !run.artifacts.is_empty()
        && !nanosiem_core::reports::report_artifact_download_allowed(
            auth.denied_sources.deny_set(),
            &run.source_types,
            run.source_types_complete,
        )
    {
        return Err(ApiError::Forbidden(
            "this report run draws on a source your account may not access".to_string(),
        ));
    }
    Ok(Json(ReportRunResponse { run }))
}

/// Download an artifact's bytes.
#[utoipa::path(
    get,
    path = "/api/reports/artifacts/{artifact_id}/download",
    tag = "reports",
    params(("artifact_id" = String, Path, description = "Artifact ID")),
    responses(
        (status = 200, description = "Artifact bytes", content_type = "application/octet-stream"),
        (status = 403, description = "Forbidden"),
        (status = 404, description = "Not found"),
    ),
    security(("api_key" = []))
)]
pub async fn download_report_artifact(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Path(artifact_id): Path<TypeIdParam>,
) -> Result<impl IntoResponse, ApiError> {
    ensure_permission(&auth, permissions::SEARCH_VIEW)?;
    let service = report_service(&state);
    // Fetch authorization facts without BYTEA, then load bytes only after all
    // current capability, object ACL, ownership, and source-scope gates pass.
    let scope = service
        .get_artifact_scope(*artifact_id)
        .await
        .map_err(map_report_err)?;
    // Ownership via the owning definition (owner-or-admin).
    let definition = load_owned_definition(&service, &auth, scope.definition_id).await?;
    ensure_report_permissions(
        &auth,
        definition.source_type,
        ReportAuthorizationIntent::Read,
    )?;
    ensure_report_dashboard_access(&state, &auth, &definition).await?;
    if report_run_requires_search_sql(
        definition.source_type,
        scope.requires_search_sql,
        scope.search_sql_requirement_complete,
    ) {
        ensure_report_search_sql_permission(&auth, true)?;
    }

    // F-31: OWNERSHIP IS NOT AN EXEMPTION. Stored artifacts are frozen bytes
    // with no per-row source attribution, so a source-restricted requester
    // (including the owner, or a source-scoped admin) cannot be row-filtered
    // here — gate the whole download on the run's stored source_type manifest.
    // Every pre-feature run has an incomplete manifest, which denies any
    // restricted requester (fail-closed).
    if !nanosiem_core::reports::report_artifact_download_allowed(
        auth.denied_sources.deny_set(),
        &scope.source_types,
        scope.source_types_complete,
    ) {
        return Err(ApiError::Forbidden(
            "this report artifact draws on a source your account may not access"
                .to_string(),
        ));
    }

    let artifact = service
        .get_artifact_content(*artifact_id)
        .await
        .map_err(map_report_err)?;

    // Filenames are server-generated (slug + timestamp), but strip any control
    // chars defensively before placing in the Content-Disposition header.
    let safe_name: String = artifact
        .filename
        .chars()
        .filter(|c| !c.is_control() && *c != '"')
        .collect();

    Ok((
        [
            (header::CONTENT_TYPE, artifact.content_type),
            (
                header::CONTENT_DISPOSITION,
                format!("attachment; filename=\"{safe_name}\""),
            ),
        ],
        artifact.content,
    ))
}

// ============================================================================
// OpenAPI
// ============================================================================

#[derive(utoipa::OpenApi)]
#[openapi(
    paths(
        create_report,
        list_reports,
        get_report,
        update_report,
        delete_report,
        trigger_report,
        list_report_runs,
        get_report_run,
        download_report_artifact,
    ),
    components(schemas(
        CreateReportRequest,
        UpdateReportRequest,
        ReportDefinitionResponse,
        ReportListResponse,
        ReportRunListResponse,
        ReportRunResponse,
        TriggerReportResponse,
        ReportDefinition,
        ReportRun,
        ReportArtifactMeta,
        ReportSourceType,
    ))
)]
pub struct ReportsApiDoc;

#[cfg(test)]
mod authorization_tests {
    use super::*;
    use nanosiem_core::auth::{ApiKeyInfo, TokenClaims};

    fn jwt(permissions: &[&str]) -> AuthContext {
        AuthContext::from_jwt(TokenClaims {
            iss: "test".to_string(),
            aud: "test".to_string(),
            sub: Uuid::now_v7(),
            roles: Vec::new(),
            permissions: permissions.iter().map(|permission| permission.to_string()).collect(),
            exp: i64::MAX,
            iat: 0,
            jti: Uuid::now_v7(),
            purpose: "access".to_string(),
        })
    }

    fn api_key(permissions: &[&str]) -> AuthContext {
        AuthContext::from_api_key(&ApiKeyInfo {
            id: Uuid::now_v7(),
            name: "report-test".to_string(),
            permissions: permissions.iter().map(|permission| permission.to_string()).collect(),
            user_id: Some(Uuid::now_v7()),
        })
    }

    #[test]
    fn jwt_and_api_key_share_the_same_zero_unrelated_revoked_and_allowed_matrix() {
        for context in [jwt(&[]), api_key(&[])] {
            assert!(ensure_report_permissions(
                &context,
                ReportSourceType::Dashboard,
                ReportAuthorizationIntent::Execute
            )
            .is_err());
        }
        for context in [
            jwt(&[permissions::DASHBOARDS_CREATE]),
            api_key(&[permissions::DASHBOARDS_CREATE]),
        ] {
            assert!(ensure_report_permissions(
                &context,
                ReportSourceType::Dashboard,
                ReportAuthorizationIntent::Execute
            )
            .is_err());
        }
        for context in [
            jwt(&[permissions::SEARCH_EXECUTE]),
            api_key(&[permissions::SEARCH_EXECUTE]),
        ] {
            assert!(ensure_report_permissions(
                &context,
                ReportSourceType::Dashboard,
                ReportAuthorizationIntent::Execute
            )
            .is_err());
        }
        for context in [
            jwt(&[
                permissions::SEARCH_EXECUTE,
                permissions::DASHBOARDS_VIEW,
            ]),
            api_key(&[
                permissions::SEARCH_EXECUTE,
                permissions::DASHBOARDS_VIEW,
            ]),
        ] {
            ensure_report_permissions(
                &context,
                ReportSourceType::Dashboard,
                ReportAuthorizationIntent::Execute,
            )
            .expect("complete capability set");
        }
        for context in [
            jwt(&[permissions::SEARCH_VIEW]),
            api_key(&[permissions::SEARCH_VIEW]),
        ] {
            assert!(ensure_report_permissions(
                &context,
                ReportSourceType::Dashboard,
                ReportAuthorizationIntent::Read
            )
            .is_err());
        }
        for context in [
            jwt(&[permissions::SEARCH_VIEW, permissions::DASHBOARDS_VIEW]),
            api_key(&[permissions::SEARCH_VIEW, permissions::DASHBOARDS_VIEW]),
        ] {
            ensure_report_permissions(
                &context,
                ReportSourceType::Dashboard,
                ReportAuthorizationIntent::Read,
            )
            .expect("complete read capability set");
        }
    }

    #[test]
    fn jwt_and_api_key_share_the_same_search_sql_gate() {
        for context in [jwt(&[]), api_key(&[])] {
            ensure_report_search_sql_permission(&context, false)
                .expect("nPL dashboard does not require search:sql");
            assert!(
                ensure_report_search_sql_permission(&context, true).is_err(),
                "raw-SQL dashboard must reject a credential without search:sql"
            );
        }
        for context in [
            jwt(&[permissions::SEARCH_SQL]),
            api_key(&[permissions::SEARCH_SQL]),
        ] {
            ensure_report_search_sql_permission(&context, true)
                .expect("search:sql permits raw-SQL dashboard access");
        }
    }

    fn handler_body<'a>(source: &'a str, signature: &str, next_marker: &str) -> &'a str {
        let start = source.find(signature).expect("handler signature");
        let end = source[start..]
            .find(next_marker)
            .map(|offset| start + offset)
            .expect("next handler marker");
        &source[start..end]
    }

    fn position(source: &str, needle: &str) -> usize {
        source
            .find(needle)
            .unwrap_or_else(|| panic!("expected production-path marker {needle:?}"))
    }

    #[test]
    fn protected_data_is_loaded_only_after_current_authorization() {
        let source = include_str!("reports.rs");
        let create = handler_body(
            source,
            "pub async fn create_report(",
            "\n/// List report definitions",
        );
        assert!(
            position(create, "ensure_report_search_sql_permission(")
                < position(create, "create_definition(new)"),
            "SQL-panel capability must precede report creation"
        );

        let update = handler_body(
            source,
            "pub async fn update_report(",
            "\n/// Delete a report definition",
        );
        assert!(
            position(update, "ensure_report_search_sql_permission(")
                < position(update, "update_definition(*id, update)"),
            "SQL-panel capability must precede report update"
        );

        let trigger = handler_body(
            source,
            "pub async fn trigger_report(",
            "\n/// List a report's runs",
        );
        assert!(
            position(trigger, "ensure_report_search_sql_permission(")
                < position(trigger, "authorize_execution(&def)")
                && position(trigger, "authorize_execution(&def)")
                    < position(
                        trigger,
                        "trigger_now(*id, auth.has_permission(permissions::SEARCH_SQL))",
                    ),
            "current caller and owner SQL authorization must happen before spawning"
        );

        let run = handler_body(
            source,
            "pub async fn get_report_run(",
            "\n/// Download an artifact's bytes",
        );
        assert!(
            position(run, "get_run_authorization_scope(*run_id)")
                < position(run, "ensure_report_permissions(")
                && position(run, "ensure_report_permissions(")
                    < position(run, "ensure_report_search_sql_permission(")
                && position(run, "ensure_report_search_sql_permission(")
                    < position(run, "get_run(*run_id)"),
            "run ownership/capabilities and frozen SQL gate must precede artifact metadata"
        );

        let artifact = handler_body(
            source,
            "pub async fn download_report_artifact(",
            "\n// ============================================================================\n// OpenAPI",
        );
        assert!(
            position(artifact, "get_artifact_scope(*artifact_id)")
                < position(artifact, "ensure_report_permissions(")
                && position(artifact, "ensure_report_permissions(")
                    < position(artifact, "ensure_report_search_sql_permission(")
                && position(artifact, "ensure_report_search_sql_permission(")
                    < position(artifact, "get_artifact_content(*artifact_id)"),
            "artifact authorization facts, capabilities, and frozen SQL gate must precede BYTEA loading"
        );
    }
}
