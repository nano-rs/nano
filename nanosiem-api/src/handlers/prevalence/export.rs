// SPDX-License-Identifier: AGPL-3.0-or-later

//! Prevalence data export handler (CSV/JSON)

use nanosiem_core::csv_safe::escape_field as escape_csv;
use axum::{
    Extension, Json,
    extract::{Query, State},
    http::{StatusCode, header},
    response::{IntoResponse, Response},
};
use tracing::error;

use crate::middleware::{AuthContext, check_permission};
use crate::state::AppState;
use nanosiem_core::auth::permissions;
use nanosiem_core::prevalence::PrevalenceLookup;

use super::types::ExportQuery;
use super::{MAX_EXPORT_ARTIFACTS, effective_artifact_scope, parse_artifact_type, parse_time_window};

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
        (status = 202, description = "Complete export queued as a durable Search Job", body = nanosiem_core::search::AsyncSearchResponse),
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
) -> Result<Response, (StatusCode, String)> {
    check_permission(&auth, permissions::PREVALENCE_EXPORT).map_err(|_| {
        (
            StatusCode::FORBIDDEN,
            "Missing permission: prevalence:export".to_string(),
        )
    })?;

    let time_window = parse_time_window(params.window.as_deref());
    let artifact_type = parse_artifact_type(params.artifact_type.as_deref());
    let format = match params.format.as_deref() {
        Some("json") => "json",
        _ => "csv",
    };
    let viewer_scope = auth.effective_viewer_scope();
    let scope = effective_artifact_scope(&auth);

    let filtered = if let Some(client) = super::primary_lake_prevalence_client(&state).await? {
        let default_max_prevalence = client.rarity_threshold().await;
        let max_prevalence = params.max_prevalence.unwrap_or(default_max_prevalence);
        let result = client
            .export(
                artifact_type,
                time_window,
                max_prevalence,
                MAX_EXPORT_ARTIFACTS,
                &scope,
            )
            .await
            .map_err(|error| {
                error!("Lake prevalence export failed: {}", error);
                (StatusCode::BAD_GATEWAY, error.to_string())
            })?;
        if result.truncated {
            let artifact_kind = artifact_type.map(|kind| {
                if kind.is_hash() {
                    "hash"
                } else if kind.is_domain() {
                    "domain"
                } else {
                    "ip"
                }
            });
            let job_id = state
                .search_service
                .enqueue_durable_prevalence_export(
                    time_window,
                    artifact_kind,
                    max_prevalence,
                    format,
                    &viewer_scope,
                    auth.user_id(),
                    None,
                )
                .await
                .map_err(|error| {
                    error!(%error, "Durable lake prevalence export admission failed");
                    (StatusCode::SERVICE_UNAVAILABLE, error.to_string())
                })?;
            return Ok((
                StatusCode::ACCEPTED,
                Json(nanosiem_core::search::AsyncSearchResponse {
                    job_id,
                    status: "queued".to_string(),
                }),
            )
                .into_response());
        }
        result.artifacts
    } else {
        let dual_pool = state.dual_pool();
        let prevalence_service =
            nanosiem_core::prevalence::PrevalenceService::with_database_config(
                dual_pool.clickhouse().clone(),
                dual_pool.table_names(),
                &state.pool,
            )
            .await;
        // Default to the CONFIGURED rarity threshold (P1 audit — was hardcoded 3, so
        // a tenant that raised the threshold got an export cut at the wrong bound).
        let default_max_prevalence = prevalence_service.get_config().await.rarity_threshold;
        let max_prevalence = params.max_prevalence.unwrap_or(default_max_prevalence);
        let artifacts = prevalence_service
            .get_rare_artifacts(
                artifact_type,
                time_window,
                MAX_EXPORT_ARTIFACTS as i64,
                &scope,
            )
            .await
            .map_err(|error| {
                error!("Failed to get artifacts for export: {}", error);
                (StatusCode::INTERNAL_SERVER_ERROR, error.to_string())
            })?;
        artifacts
            .into_iter()
            .filter(|artifact| artifact.host_count <= max_prevalence)
            .collect()
    };

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
            )
                .into_response())
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
            )
                .into_response())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::escape_csv;

    #[test]
    fn prevalence_csv_neutralizes_formulas_and_quotes_cells() {
        assert_eq!(escape_csv("=cmd"), "'=cmd");
        assert_eq!(escape_csv("evil,\"hash\""), "\"evil,\"\"hash\"\"\"");
        // Formula leads behind whitespace / control characters are neutralized too.
        for payload in [" =1+1", "\t=1+1", "\r@SUM(A1)", "-1+1"] {
            assert!(escape_csv(payload).trim_start_matches('"').starts_with('\''), "{payload:?}");
        }
    }
}
