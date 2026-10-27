// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-3807: read-only status of OCSF bucket-drop sources (open core / dedicated).
//!
//! - GET /api/landing-sources                       - sources with file/row totals
//! - GET /api/landing-sources/{source_id}/files     - a source's recent landed files
//!
//! Sources are created and revoked by the `lean-landing-admin` CLI
//! (`docker compose run --rm lean-landing-admin add --name <name>`), which holds
//! the object-store admin rights; the API has none, so it only reads.
//! Hosted-shared tenants do not mount these routes.

use axum::{
    extract::{Path, Query, State},
    Extension, Json,
};
use nanosiem_core::auth::permissions;
use nanosiem_core::landing_sources::{
    is_file_state, LandingFile, LandingSourceRepository, LandingSourceRepositoryError,
    LandingSourceStatus, FILE_STATES,
};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

use crate::error::ApiError;
use crate::middleware::{ensure_permission, AuthContext};
use crate::state::AppState;

/// `GET /api/landing-sources`.
#[derive(Debug, Serialize, ToSchema)]
pub struct LandingSourceList {
    /// Active first, newest first.
    pub sources: Vec<LandingSourceStatus>,
}

/// `GET /api/landing-sources/{source_id}/files` query.
#[derive(Debug, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct LandingFilesQuery {
    /// Files to return, 1-200 (default 50).
    pub limit: Option<i64>,
    /// Only files in this state: `listed`, `claimed`, `accepted` or `refused`.
    pub state: Option<String>,
}

/// `GET /api/landing-sources/{source_id}/files`.
#[derive(Debug, Serialize, ToSchema)]
pub struct LandingFileList {
    /// Newest first.
    pub files: Vec<LandingFile>,
}

fn dedicated_only(state: &AppState) -> Result<(), ApiError> {
    #[cfg(feature = "enterprise")]
    if state.config.deployment_mode.is_enterprise_shared() {
        return Err(ApiError::NotFound(
            "Bucket drop sources are not available on hosted tenants".into(),
        ));
    }
    Ok(())
}

/// NAN-4629: the tenant this API serves, the caller's tenant. A dedicated
/// or sovereign API process serves exactly one tenant
/// (`NANO_LAKE_TENANT_ID`, the same variable and normalization as the
/// landing converter); several tenants may share the database (an MSSP
/// sovereign install), so every status read is bound to it. Unset: no
/// tenant, nothing is served (fail closed).
fn serving_tenant() -> Result<String, ApiError> {
    tenant_from(std::env::var("NANO_LAKE_TENANT_ID").ok())
}

fn tenant_from(raw: Option<String>) -> Result<String, ApiError> {
    raw.map(|t| t.trim().to_ascii_lowercase())
        .filter(|t| {
            !t.is_empty()
                && t.len() <= 128
                && t.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        })
        .ok_or_else(|| ApiError::NotFound("Bucket drop sources are not configured on this deployment".into()))
}

fn repository_error(error: LandingSourceRepositoryError) -> ApiError {
    tracing::error!(%error, "landing source storage error");
    ApiError::InternalError("Bucket drop source storage unavailable".into())
}

#[utoipa::path(get, path = "/api/landing-sources", tag = "landing_sources",
    responses((status = 200, body = LandingSourceList), (status = 403, description = "Forbidden"),
        (status = 404, description = "Not available on hosted tenants")),
    security(("bearer_auth" = []), ("api_key" = [])))]
/// List bucket drop sources with file and row totals
pub async fn list_landing_sources(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
) -> Result<Json<LandingSourceList>, ApiError> {
    ensure_permission(&auth, permissions::LOG_SOURCES_VIEW)?;
    dedicated_only(&state)?;
    let tenant = serving_tenant()?;
    let sources = LandingSourceRepository::new(state.pool.clone())
        .list_sources(&tenant)
        .await
        .map_err(repository_error)?;
    Ok(Json(LandingSourceList { sources }))
}

#[utoipa::path(get, path = "/api/landing-sources/{source_id}/files", tag = "landing_sources",
    params(("source_id" = Uuid, Path, description = "Bucket drop source (log source) id"), LandingFilesQuery),
    responses((status = 200, body = LandingFileList), (status = 400, description = "Unknown state"),
        (status = 403, description = "Forbidden"),
        (status = 404, description = "Unknown source, or not available on hosted tenants")),
    security(("bearer_auth" = []), ("api_key" = [])))]
/// List a bucket drop source's recent landed files
pub async fn list_landing_files(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Path(source_id): Path<Uuid>,
    Query(query): Query<LandingFilesQuery>,
) -> Result<Json<LandingFileList>, ApiError> {
    ensure_permission(&auth, permissions::LOG_SOURCES_VIEW)?;
    dedicated_only(&state)?;
    let file_state = validate_state(query.state.as_deref())?;
    let tenant = serving_tenant()?;
    let repo = LandingSourceRepository::new(state.pool.clone());
    // Another tenant's source is indistinguishable from an unknown one.
    if !repo.source_exists(&tenant, source_id).await.map_err(repository_error)? {
        return Err(ApiError::NotFound("Bucket drop source not found".into()));
    }
    let files = repo
        .list_files(&tenant, source_id, query.limit, file_state)
        .await
        .map_err(repository_error)?;
    Ok(Json(LandingFileList { files }))
}

fn validate_state(state: Option<&str>) -> Result<Option<&str>, ApiError> {
    match state.map(str::trim).filter(|s| !s.is_empty()) {
        None => Ok(None),
        Some(s) if is_file_state(s) => Ok(Some(s)),
        Some(_) => Err(ApiError::BadRequest(format!(
            "state must be one of: {}",
            FILE_STATES.join(", ")
        ))),
    }
}

#[derive(utoipa::OpenApi)]
#[openapi(
    paths(list_landing_sources, list_landing_files),
    components(schemas(LandingSourceList, LandingSourceStatus, LandingFileList, LandingFile)),
    tags((name = "landing_sources", description = "OCSF bucket drop sources (open core / dedicated): read-only status"))
)]
pub struct LandingSourcesApiDoc;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_status_view_is_bound_to_the_serving_tenant_and_fails_closed() {
        assert_eq!(tenant_from(Some(" 7B2D3F1A-0C8E-4D6F-A1B2-C3D4E5F60718 ".into())).unwrap(),
            "7b2d3f1a-0c8e-4d6f-a1b2-c3d4e5f60718");
        assert_eq!(tenant_from(Some("default".into())).unwrap(), "default");
        for bad in [None, Some(String::new()), Some("  ".into()), Some("a/b".into()), Some("x".repeat(129))] {
            assert!(matches!(tenant_from(bad), Err(ApiError::NotFound(_))));
        }
    }

    #[test]
    fn state_filter_accepts_only_known_states() {
        assert_eq!(validate_state(None).unwrap(), None);
        assert_eq!(validate_state(Some("")).unwrap(), None);
        assert_eq!(validate_state(Some("refused")).unwrap(), Some("refused"));
        assert!(validate_state(Some("deleted")).is_err());
        assert!(validate_state(Some("'; DROP")).is_err());
    }
}
