// SPDX-License-Identifier: AGPL-3.0-or-later

//! MITRE ATT&CK API handlers

use axum::{
    extract::{Query, State},
    http::StatusCode,
    Extension, Json,
};
use serde::{Deserialize, Serialize};

use crate::middleware::{check_permission, AuthContext};
use crate::state::AppState;
use nanosiem_core::auth::permissions;
use nanosiem_core::mitre::{
    MitreCoverageResponse, MitreRepository, MitreSync, MitreSyncMetadata, MitreTactic,
    MitreTechnique,
};

/// Ensure the ATT&CK catalog is populated, lazily syncing it from upstream on
/// first use. The catalog (`mitre_tactics` / `mitre_techniques`) is not seeded
/// by migration, so it must be synced at runtime. Sync failures are logged and
/// swallowed so the caller still returns a (possibly empty) response rather
/// than a 500 — the catalog is retried on the next request. Shared by
/// `get_mitre_data` and `get_mitre_coverage` so every MITRE surface self-seeds,
/// not just the rule-editor data endpoint (NAN-1103).
async fn ensure_mitre_catalog(pool: &sqlx::PgPool) {
    let sync = MitreSync::new(MitreRepository::new(pool.clone()));
    match sync.sync_if_empty().await {
        Ok(true) => tracing::info!("MITRE catalog was empty — lazily synced from upstream"),
        Ok(false) => {}
        Err(e) => tracing::warn!(
            "MITRE catalog lazy sync failed (will retry on next request): {}",
            e
        ),
    }
}

/// Response containing all MITRE data for frontend dropdowns
#[derive(Serialize, utoipa::ToSchema)]
pub struct MitreDataResponse {
    pub tactics: Vec<MitreTactic>,
    pub techniques: Vec<MitreTechnique>,
    pub last_sync: Option<MitreSyncMetadata>,
}

/// Get all MITRE ATT&CK tactics and techniques
#[utoipa::path(
    get,
    path = "/api/mitre",
    tag = "mitre",
    responses(
        (status = 200, description = "MITRE ATT&CK tactics and techniques", body = MitreDataResponse),
        (status = 403, description = "Forbidden - Missing permission: mitre:view"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn get_mitre_data(
    Extension(auth): Extension<AuthContext>,
    State(state): State<AppState>,
) -> Result<Json<MitreDataResponse>, (StatusCode, String)> {
    check_permission(&auth, permissions::MITRE_VIEW)
        .map_err(|(status, json)| (status, json.0.message))?;

    // Lazily seed the ATT&CK catalog on first use. If the sync fails, the
    // queries below return empty vecs — same graceful-empty result as before.
    ensure_mitre_catalog(&state.pool).await;

    let repo = MitreRepository::new(state.pool.clone());

    let tactics = repo.get_tactics().await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to get tactics: {}", e),
        )
    })?;

    let techniques = repo.get_techniques().await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to get techniques: {}", e),
        )
    })?;

    let last_sync = repo.get_sync_metadata().await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to get sync metadata: {}", e),
        )
    })?;

    Ok(Json(MitreDataResponse {
        tactics,
        techniques,
        last_sync,
    }))
}

/// Trigger a manual sync of MITRE data
#[utoipa::path(
    post,
    path = "/api/mitre/sync",
    tag = "mitre",
    responses(
        (status = 200, description = "MITRE data synced successfully", body = SyncResponse),
        (status = 403, description = "Forbidden - Missing permission: mitre:sync"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn sync_mitre_data(
    Extension(auth): Extension<AuthContext>,
    State(state): State<AppState>,
) -> Result<Json<SyncResponse>, (StatusCode, String)> {
    check_permission(&auth, permissions::MITRE_SYNC)
        .map_err(|(status, json)| (status, json.0.message))?;

    let repo = MitreRepository::new(state.pool.clone());
    let sync = MitreSync::new(repo);

    let (tactic_count, technique_count) = sync.sync().await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Sync failed: {}", e),
        )
    })?;

    Ok(Json(SyncResponse {
        success: true,
        tactic_count,
        technique_count,
    }))
}

#[derive(Serialize, utoipa::ToSchema)]
pub struct SyncResponse {
    pub success: bool,
    pub tactic_count: i32,
    pub technique_count: i32,
}

/// Query parameters for MITRE coverage endpoint
#[derive(Debug, Deserialize, utoipa::IntoParams)]
pub struct CoverageQueryParams {
    /// Comma-separated list of severities to filter by (e.g., "critical,high")
    pub severity: Option<String>,
    /// Comma-separated list of modes to filter by (e.g., "alerting,live")
    pub mode: Option<String>,
}

/// Get MITRE ATT&CK coverage data
/// Shows which techniques are covered by detection rules
#[utoipa::path(
    get,
    path = "/api/mitre/coverage",
    tag = "mitre",
    params(CoverageQueryParams),
    responses(
        (status = 200, description = "MITRE ATT&CK coverage data", body = MitreCoverageResponse),
        (status = 403, description = "Forbidden - Missing permission: mitre:view"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn get_mitre_coverage(
    Extension(auth): Extension<AuthContext>,
    State(state): State<AppState>,
    Query(params): Query<CoverageQueryParams>,
) -> Result<Json<MitreCoverageResponse>, (StatusCode, String)> {
    check_permission(&auth, permissions::MITRE_VIEW)
        .map_err(|(status, json)| (status, json.0.message))?;

    // Lazily seed the ATT&CK catalog so the Coverage page is self-sufficient
    // and never renders a phantom 0/0 before the first /api/mitre hit (NAN-1103).
    ensure_mitre_catalog(&state.pool).await;

    let repo = MitreRepository::new(state.pool.clone());

    // Parse comma-separated filter values
    let severity_filter: Option<Vec<String>> = params.severity.map(|s| {
        s.split(',')
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty())
            .collect()
    });

    let mode_filter: Option<Vec<String>> = params.mode.map(|s| {
        s.split(',')
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty())
            .collect()
    });

    let coverage = repo
        .get_coverage(severity_filter.as_deref(), mode_filter.as_deref())
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to get coverage data: {}", e),
            )
        })?;

    Ok(Json(coverage))
}

/// OpenAPI documentation for MITRE ATT&CK endpoints
pub struct MitreApiDoc;

impl utoipa::OpenApi for MitreApiDoc {
    fn openapi() -> utoipa::openapi::OpenApi {
        use utoipa::OpenApi;

        #[derive(OpenApi)]
        #[openapi(
            paths(
                get_mitre_data,
                get_mitre_coverage,
                sync_mitre_data,
            ),
            components(schemas(
                MitreDataResponse,
                SyncResponse,
            )),
            tags(
                (name = "mitre", description = "MITRE ATT&CK framework integration endpoints")
            )
        )]
        struct ApiDoc;

        ApiDoc::openapi()
    }
}
