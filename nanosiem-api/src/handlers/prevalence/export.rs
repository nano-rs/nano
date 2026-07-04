// SPDX-License-Identifier: AGPL-3.0-or-later

//! Prevalence data export handler (CSV/JSON)

use axum::{
    Extension,
    extract::{Query, State},
    http::{StatusCode, header},
    response::IntoResponse,
};
use tracing::error;

use crate::middleware::{AuthContext, check_permission};
use crate::state::AppState;
use nanosiem_core::auth::permissions;

use super::types::ExportQuery;
use super::{MAX_EXPORT_ARTIFACTS, parse_artifact_type, parse_time_window};

/// GET /api/prevalence/export
///
/// Export rare artifacts as CSV or JSON.
/// Requirements: 9.1, 9.2, 9.3, 9.4
#[utoipa::path(
    get,
    path = "/api/prevalence/export",
    tag = "prevalence",
    params(ExportQuery),
    responses(
        (status = 200, description = "Exported prevalence data", body = String, content_type = "text/csv"),
        (status = 403, description = "Forbidden - Missing permission: prevalence:export"),
        (status = 503, description = "Service unavailable - Prevalence tracking requires ClickHouse"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn export_prevalence(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Query(params): Query<ExportQuery>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    check_permission(&auth, permissions::PREVALENCE_EXPORT).map_err(|_| {
        (
            StatusCode::FORBIDDEN,
            "Missing permission: prevalence:export".to_string(),
        )
    })?;

    let dual_pool = state.dual_pool();

    // Create service with database config for hot-reload support (Requirement 8.5)
    let prevalence_service = nanosiem_core::prevalence::PrevalenceService::with_database_config(
        dual_pool.clickhouse().clone(),
        dual_pool.table_names(),
        &state.pool,
    )
    .await;

    let time_window = parse_time_window(params.window.as_deref());
    let artifact_type = parse_artifact_type(params.artifact_type.as_deref());
    // Default to the CONFIGURED rarity threshold (P1 audit — was hardcoded 3, so
    // a tenant that raised the threshold got an export cut at the wrong bound).
    let default_max_prevalence = prevalence_service.get_config().await.rarity_threshold;
    let max_prevalence = params.max_prevalence.unwrap_or(default_max_prevalence);
    let format = params.format.as_deref().unwrap_or("csv");

    // Get rare artifacts (limited to MAX_EXPORT_ARTIFACTS)
    let artifacts = prevalence_service
        .get_rare_artifacts(artifact_type, time_window, MAX_EXPORT_ARTIFACTS as i64)
        .await
        .map_err(|e| {
            error!("Failed to get artifacts for export: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
        })?;

    // Filter by max_prevalence
    let filtered: Vec<_> = artifacts
        .into_iter()
        .filter(|a| a.host_count <= max_prevalence)
        .collect();

    match format {
        "json" => {
            let json_data = serde_json::to_string_pretty(&filtered)
                .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

            Ok((
                [
                    (header::CONTENT_TYPE, "application/json"),
                    (
                        header::CONTENT_DISPOSITION,
                        "attachment; filename=\"prevalence_export.json\"",
                    ),
                ],
                json_data,
            ))
        }
        _ => {
            // Default to CSV
            let mut csv_data = String::from(
                "artifact,type,host_count,total_occurrences,first_seen,last_seen,is_rare,prevalence_score\n",
            );

            for artifact in &filtered {
                csv_data.push_str(&format!(
                    "{},{},{},{},{},{},{},{}\n",
                    escape_csv(&artifact.artifact),
                    artifact.artifact_type,
                    artifact.host_count,
                    artifact.total_occurrences,
                    artifact.first_seen.to_rfc3339(),
                    artifact.last_seen.to_rfc3339(),
                    artifact.is_rare,
                    artifact.prevalence_score,
                ));
            }

            Ok((
                [
                    (header::CONTENT_TYPE, "text/csv"),
                    (
                        header::CONTENT_DISPOSITION,
                        "attachment; filename=\"prevalence_export.csv\"",
                    ),
                ],
                csv_data,
            ))
        }
    }
}

/// Escape a string for CSV output
fn escape_csv(s: &str) -> String {
    if s.contains(',') || s.contains('"') || s.contains('\n') {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}
