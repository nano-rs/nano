// SPDX-License-Identifier: AGPL-3.0-or-later

//! SIEM Health Check API handlers
//!
//! Provides endpoints for listing, retrieving, and triggering SIEM health check reports.
//! Reports are AI-driven analyses of ingestion, parsing, and detection quality.

use axum::{
    Extension, Json,
    extract::{Path, Query, State},
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::ApiError;
use crate::middleware::AuthContext;
use crate::state::AppState;
use nanosiem_core::siem_health::{SiemHealthReport, SiemHealthReportSummary, SiemHealthRepository};

/// Query parameters for listing health reports
#[derive(Debug, Deserialize, utoipa::IntoParams)]
pub struct ListReportsParams {
    /// Maximum number of reports to return (default: 20, max: 100)
    #[serde(default = "default_limit")]
    pub limit: i64,
    /// Offset for pagination (default: 0)
    #[serde(default)]
    pub offset: i64,
}

fn default_limit() -> i64 {
    20
}

/// Paginated list of health report summaries
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct ListReportsResponse {
    pub reports: Vec<SiemHealthReportSummary>,
    pub total: i64,
    pub limit: i64,
    pub offset: i64,
}

/// Response from triggering a health check
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct TriggerResponse {
    /// The ID of the newly created report, if successful
    pub report_id: Option<Uuid>,
    /// Human-readable status message
    pub message: String,
}

/// List SIEM health report summaries (paginated)
///
/// Returns a paginated list of health report summaries, ordered by most recent first.
/// Summaries omit the full metrics and dimension details for efficiency.
///
/// GET /api/siem-health/reports
#[utoipa::path(
    get,
    path = "/api/siem-health/reports",
    tag = "siem_health",
    params(ListReportsParams),
    responses(
        (status = 200, description = "Paginated list of health report summaries", body = ListReportsResponse),
    ),
    security(("api_key" = []))
)]
pub async fn list_reports(
    State(state): State<AppState>,
    Extension(_auth): Extension<AuthContext>,
    Query(params): Query<ListReportsParams>,
) -> Result<Json<ListReportsResponse>, ApiError> {
    let limit = params.limit.clamp(1, 100);
    let offset = params.offset.max(0);

    let repo = SiemHealthRepository::new(state.pool.clone());
    let (reports, total) = repo
        .list_summaries(limit, offset)
        .await
        .map_err(|e| ApiError::DatabaseError(e.to_string()))?;

    Ok(Json(ListReportsResponse {
        reports,
        total,
        limit,
        offset,
    }))
}

/// Get the most recent SIEM health report
///
/// Returns the latest full health report including metrics, recommendations,
/// and dimension details. Returns 404 if no reports exist yet.
///
/// GET /api/siem-health/reports/latest
#[utoipa::path(
    get,
    path = "/api/siem-health/reports/latest",
    tag = "siem_health",
    responses(
        (status = 200, description = "The most recent health report", body = SiemHealthReport),
        (status = 404, description = "No health reports exist yet"),
    ),
    security(("api_key" = []))
)]
pub async fn get_latest_report(
    State(state): State<AppState>,
    Extension(_auth): Extension<AuthContext>,
) -> Result<Json<SiemHealthReport>, ApiError> {
    let repo = SiemHealthRepository::new(state.pool.clone());
    let report = repo
        .get_latest()
        .await
        .map_err(|e| ApiError::DatabaseError(e.to_string()))?
        .ok_or_else(|| ApiError::NotFound("No health reports exist yet".to_string()))?;

    Ok(Json(report))
}

/// Get a specific SIEM health report by ID
///
/// Returns the full health report including metrics, recommendations,
/// and dimension details.
///
/// GET /api/siem-health/reports/{id}
#[utoipa::path(
    get,
    path = "/api/siem-health/reports/{id}",
    tag = "siem_health",
    params(
        ("id" = Uuid, Path, description = "Report UUID"),
    ),
    responses(
        (status = 200, description = "The requested health report", body = SiemHealthReport),
        (status = 404, description = "Report not found"),
    ),
    security(("api_key" = []))
)]
pub async fn get_report(
    State(state): State<AppState>,
    Extension(_auth): Extension<AuthContext>,
    Path(id): Path<Uuid>,
) -> Result<Json<SiemHealthReport>, ApiError> {
    let repo = SiemHealthRepository::new(state.pool.clone());
    let report = repo.get_by_id(id).await.map_err(|e| match e {
        nanosiem_core::siem_health::SiemHealthRepositoryError::NotFound(msg) => {
            ApiError::NotFound(msg)
        }
        other => ApiError::DatabaseError(other.to_string()),
    })?;

    Ok(Json(report))
}

/// Manually trigger a SIEM health check (admin only)
///
/// Runs the full health check pipeline: collect metrics from ClickHouse and PostgreSQL,
/// analyze with AI (or fallback scoring), and store the report. This is the same pipeline
/// that runs automatically every 12 hours.
///
/// Requires the `settings:system` permission.
///
/// POST /api/siem-health/reports/trigger
#[utoipa::path(
    post,
    path = "/api/siem-health/reports/trigger",
    tag = "siem_health",
    responses(
        (status = 200, description = "Health check triggered successfully", body = TriggerResponse),
        (status = 403, description = "Insufficient permissions"),
    ),
    security(("api_key" = []))
)]
pub async fn trigger_health_check(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
) -> Result<Json<TriggerResponse>, ApiError> {
    // Require admin permission
    crate::middleware::check_permission(&auth, nanosiem_core::auth::permissions::SETTINGS_SYSTEM)
        .map_err(|_| ApiError::Forbidden("Missing permission: settings:system".to_string()))?;

    let repo = SiemHealthRepository::new(state.pool.clone());

    // Get ClickHouse client from DualPool (if available)
    let ch_client = state.dual_pool().map(|dp| dp.clickhouse().clone());
    let is_clustered = state
        .dual_pool()
        .map(|dp| dp.table_names().is_clustered())
        .unwrap_or(false);

    // Construct the SiemHealthAiAnalyzer for this trigger. Enterprise builds
    // wrap the live meloD AI client; open-core builds use the noop analyzer,
    // which returns `Unavailable` and lets the scheduler fall through to the
    // rules-based `analyzer::fallback_report`.
    use std::sync::Arc;
    use nanosiem_core::extensions::SiemHealthAiAnalyzer;
    #[cfg(not(feature = "enterprise"))]
    use nanosiem_core::extensions::NoopSiemHealthAiAnalyzer;

    #[cfg(feature = "enterprise")]
    let ai_analyzer: Arc<dyn SiemHealthAiAnalyzer> = {
        use nanosiem_core::extensions::{AiClient, NoopAiClient};
        let ai_client: Arc<dyn AiClient> = state
            .melod_service
            .read()
            .await
            .as_ref()
            .map(|s| s.ai_client_arc())
            .map(|shared| {
                Arc::new(nanosiem_enterprise::melod::MelodAiClientBridge::new(shared))
                    as Arc<dyn AiClient>
            })
            .unwrap_or_else(|| Arc::new(NoopAiClient));
        Arc::new(nanosiem_enterprise::siem_health::AiPoweredSiemHealthAnalyzer::new(ai_client))
    };
    #[cfg(not(feature = "enterprise"))]
    let ai_analyzer: Arc<dyn SiemHealthAiAnalyzer> = Arc::new(NoopSiemHealthAiAnalyzer);

    let report_id = nanosiem_core::siem_health::scheduler::run_health_check_with_trigger(
        &state.pool,
        ch_client.as_ref(),
        is_clustered,
        ai_analyzer.as_ref(),
        &repo,
        Some(auth.user_id()),
    )
    .await;

    match report_id {
        Some(id) => Ok(Json(TriggerResponse {
            report_id: Some(id),
            message: "Health check completed successfully".to_string(),
        })),
        None => Err(ApiError::InternalError(
            "Health check failed to produce a report".to_string(),
        )),
    }
}

#[derive(utoipa::OpenApi)]
#[openapi(
    paths(list_reports, get_latest_report, get_report, trigger_health_check),
    components(schemas(
        ListReportsResponse,
        TriggerResponse,
        SiemHealthReport,
        SiemHealthReportSummary,
    ))
)]
pub struct SiemHealthApiDoc;
