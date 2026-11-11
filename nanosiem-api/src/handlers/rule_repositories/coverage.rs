// SPDX-License-Identifier: AGPL-3.0-or-later

use axum::{
    extract::{Query, State},
    Extension, Json,
};
use nanosiem_core::auth::permissions;
use nanosiem_core::{CoverageAnalysis, CoverageFilter};

use super::get_rule_repo_service;
use super::types::CoverageQuery;
use crate::middleware::{ensure_permission, AuthContext};
use crate::{error::ApiError, state::AppState};

/// Get coverage analysis
#[utoipa::path(
    get,
    path = "/api/rule-repositories/coverage",
    tag = "rule_repositories",
    params(CoverageQuery),
    responses(
        (status = 200, description = "Coverage analysis retrieved successfully", body = CoverageAnalysis),
        (status = 403, description = "Forbidden"),
    ),
    security(("api_key" = []))
)]
pub async fn get_coverage(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Query(query): Query<CoverageQuery>,
) -> Result<Json<CoverageAnalysis>, ApiError> {
    ensure_permission(&auth, permissions::RULE_REPOSITORIES_VIEW)?;

    let service = get_rule_repo_service(&state)?;

    let filter = CoverageFilter {
        repository_id: query.repository_id,
        severity: query.severity,
        mitre_tactic: query.mitre_tactic,
        mitre_technique: query.mitre_technique,
    };

    // NAN-2081: coverage is computed from live ClickHouse telemetry and echoes
    // source types back through `most_missing_fields[].source_types_with_field`.
    // Same two gates as the import preview — live-data capability, then the
    // requester's effective per-source deny set.
    let scope = auth.effective_viewer_scope();
    let access = super::rules::live_inventory_access(&auth, &scope);
    let analysis = service.get_coverage_analysis(filter, &access).await?;

    Ok(Json(analysis))
}

/// Refresh coverage data from ClickHouse
#[utoipa::path(
    post,
    path = "/api/rule-repositories/coverage/refresh",
    tag = "rule_repositories",
    responses(
        (status = 200, description = "Coverage data refreshed successfully"),
        (status = 403, description = "Forbidden"),
    ),
    security(("api_key" = []))
)]
pub async fn refresh_coverage(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
) -> Result<(), ApiError> {
    ensure_permission(&auth, permissions::RULE_REPOSITORIES_SYNC)?;

    let service = get_rule_repo_service(&state)?;
    service.refresh_coverage_data().await?;

    Ok(())
}
