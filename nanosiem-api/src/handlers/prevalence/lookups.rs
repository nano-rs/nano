// SPDX-License-Identifier: AGPL-3.0-or-later

//! Single artifact and bulk prevalence lookup handlers

use axum::http::StatusCode;
use axum::{
    Extension, Json,
    extract::{Path, Query, State},
};
use tracing::error;

use super::types::{
    BulkPrevalenceRequest, BulkPrevalenceResponse, PrevalenceQuery, PrevalenceResponse,
};
use super::{MAX_BULK_ARTIFACTS, effective_artifact_scope, parse_time_window};
use crate::middleware::{AuthContext, check_permission};
use crate::state::AppState;
use nanosiem_core::auth::permissions;
use nanosiem_core::prevalence::PrevalenceLookup;

/// GET /api/prevalence/hash/{hash}
///
/// Get prevalence data for a specific file hash.
/// Requirements: 4.1
#[utoipa::path(
    get,
    path = "/api/prevalence/hash/{hash}",
    tag = "prevalence",
    params(
        ("hash" = String, Path, description = "File hash to look up"),
        PrevalenceQuery
    ),
    responses(
        (status = 200, description = "Prevalence data for hash", body = PrevalenceResponse),
        (status = 403, description = "Forbidden - Missing permission: prevalence:view"),
        (status = 503, description = "Service unavailable - Prevalence tracking requires ClickHouse"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn get_hash_prevalence(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Path(hash): Path<String>,
    Query(params): Query<PrevalenceQuery>,
) -> Result<Json<PrevalenceResponse>, (StatusCode, String)> {
    check_permission(&auth, permissions::PREVALENCE_VIEW).map_err(|_| {
        (
            StatusCode::FORBIDDEN,
            "Missing permission: prevalence:view".to_string(),
        )
    })?;

    let time_window = parse_time_window(params.window.as_deref());
    let scope = effective_artifact_scope(&auth);

    if let Some(client) = super::primary_lake_prevalence_client(&state).await? {
        let artifact_type = nanosiem_core::prevalence::ArtifactType::detect(&hash);
        return match client.lookup(std::slice::from_ref(&hash), time_window, &scope).await {
            Ok(mut data) => Ok(Json(PrevalenceResponse {
                data: data.pop().unwrap_or_else(|| {
                    nanosiem_core::prevalence::PrevalenceData::empty(
                        hash,
                        artifact_type,
                    )
                }),
            })),
            Err(error) => {
                error!("Lake hash prevalence lookup failed: {}", error);
                Err((StatusCode::BAD_GATEWAY, error.to_string()))
            }
        };
    }

    let dual_pool = state.dual_pool();
    let prevalence_service = nanosiem_core::prevalence::PrevalenceService::with_database_config(
        dual_pool.clickhouse().clone(),
        dual_pool.table_names(),
        &state.pool,
    )
    .await;

    match prevalence_service
        .get_hash_prevalence(&hash, time_window, &scope)
        .await
    {
        Ok(data) => Ok(Json(PrevalenceResponse { data })),
        Err(e) => {
            error!("Failed to get hash prevalence: {}", e);
            Err((StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))
        }
    }
}

/// GET /api/prevalence/domain/{domain}
///
/// Get prevalence data for a specific domain.
/// Requirements: 4.2
#[utoipa::path(
    get,
    path = "/api/prevalence/domain/{domain}",
    tag = "prevalence",
    params(
        ("domain" = String, Path, description = "Domain to look up"),
        PrevalenceQuery
    ),
    responses(
        (status = 200, description = "Prevalence data for domain", body = PrevalenceResponse),
        (status = 403, description = "Forbidden - Missing permission: prevalence:view"),
        (status = 503, description = "Service unavailable - Prevalence tracking requires ClickHouse"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn get_domain_prevalence(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Path(domain): Path<String>,
    Query(params): Query<PrevalenceQuery>,
) -> Result<Json<PrevalenceResponse>, (StatusCode, String)> {
    check_permission(&auth, permissions::PREVALENCE_VIEW).map_err(|_| {
        (
            StatusCode::FORBIDDEN,
            "Missing permission: prevalence:view".to_string(),
        )
    })?;

    let time_window = parse_time_window(params.window.as_deref());
    let scope = effective_artifact_scope(&auth);

    if let Some(client) = super::primary_lake_prevalence_client(&state).await? {
        return match client
            .lookup(std::slice::from_ref(&domain), time_window, &scope)
            .await
        {
            Ok(mut data) => Ok(Json(PrevalenceResponse {
                data: data.pop().unwrap_or_else(|| {
                    nanosiem_core::prevalence::PrevalenceData::empty(
                        domain.clone(),
                        nanosiem_core::prevalence::ArtifactType::detect(&domain),
                    )
                }),
            })),
            Err(error) => {
                error!("Lake domain prevalence lookup failed: {}", error);
                Err((StatusCode::BAD_GATEWAY, error.to_string()))
            }
        };
    }

    let dual_pool = state.dual_pool();
    let prevalence_service = nanosiem_core::prevalence::PrevalenceService::with_database_config(
        dual_pool.clickhouse().clone(),
        dual_pool.table_names(),
        &state.pool,
    )
    .await;

    match prevalence_service
        .get_domain_prevalence(&domain, time_window, &scope)
        .await
    {
        Ok(data) => Ok(Json(PrevalenceResponse { data })),
        Err(e) => {
            error!("Failed to get domain prevalence: {}", e);
            Err((StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))
        }
    }
}

/// POST /api/prevalence/bulk
///
/// Get prevalence data for multiple artifacts in a single request.
/// Limited to 100 artifacts per request.
/// Requirements: 4.3
/// Optional paired RFC3339 start/end select a half-open analysis window (maximum 30 days).
/// Counts use whole covering parts, with requested and effective bounds echoed separately.
/// A legacy preset window cannot be combined with absolute bounds.
/// Older readers fail closed rather than silently serving a rolling lookback.
#[utoipa::path(
    post,
    path = "/api/prevalence/bulk",
    tag = "prevalence",
    request_body = BulkPrevalenceRequest,
    responses(
        (status = 200, description = "Bulk prevalence data", body = BulkPrevalenceResponse),
        (status = 400, description = "Bad request - Too many artifacts"),
        (status = 403, description = "Forbidden - Missing permission: prevalence:view"),
        (status = 503, description = "Service unavailable - Prevalence tracking requires ClickHouse"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn get_bulk_prevalence(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Json(request): Json<BulkPrevalenceRequest>,
) -> Result<Json<BulkPrevalenceResponse>, (StatusCode, String)> {
    check_permission(&auth, permissions::PREVALENCE_VIEW).map_err(|_| {
        (
            StatusCode::FORBIDDEN,
            "Missing permission: prevalence:view".to_string(),
        )
    })?;

    // Validate artifact count
    if request.artifacts.len() > MAX_BULK_ARTIFACTS {
        return Err((
            StatusCode::BAD_REQUEST,
            format!(
                "Too many artifacts: {} (max: {})",
                request.artifacts.len(),
                MAX_BULK_ARTIFACTS
            ),
        ));
    }

    let bounds = nanosiem_core::prevalence::ExactPrevalenceWindow::parse(request.start.as_deref(), request.end.as_deref())
        .map_err(|e| (StatusCode::BAD_REQUEST, e))?;
    if bounds.is_some() && request.window.is_some() {
        return Err((StatusCode::BAD_REQUEST, "use absolute bounds or a preset window".into()));
    }
    let time_window = parse_time_window(request.window.as_deref());
    let scope = effective_artifact_scope(&auth);

    if let Some(client) = super::primary_lake_prevalence_client(&state).await? {
        let result = match &bounds {
            Some(bounds) => client.lookup_between(&request.artifacts, bounds, &scope).await,
            None => client.lookup(&request.artifacts, time_window, &scope).await.map(|data| nanosiem_core::prevalence::lookup::LakePrevalenceRead { data, requested_window: None, effective_window: None, note: None }),
        };
        return match result {
            Ok(read) => {
                let total = read.data.len();
                Ok(Json(BulkPrevalenceResponse { data: read.data, total, requested_window: read.requested_window, effective_window: read.effective_window, note: read.note }))
            }
            Err(error) => {
                error!("Lake bulk prevalence lookup failed: {}", error);
                Err((StatusCode::BAD_GATEWAY, error.to_string()))
            }
        };
    }

    if bounds.is_some() {
        return Err((StatusCode::SERVICE_UNAVAILABLE, "absolute prevalence requires a tenant cell".into()));
    }
    let dual_pool = state.dual_pool();
    // Create service with database config for hot-reload support (Requirement 8.5)
    let prevalence_service = nanosiem_core::prevalence::PrevalenceService::with_database_config(
        dual_pool.clickhouse().clone(),
        dual_pool.table_names(),
        &state.pool,
    )
    .await;

    match prevalence_service
        .get_bulk_prevalence(&request.artifacts, time_window, &scope)
        .await
    {
        Ok(data) => {
            let total = data.len();
            Ok(Json(BulkPrevalenceResponse { data, total, requested_window: None, effective_window: None, note: None }))
        }
        Err(e) => {
            error!("Failed to get bulk prevalence: {}", e);
            Err((StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))
        }
    }
}
