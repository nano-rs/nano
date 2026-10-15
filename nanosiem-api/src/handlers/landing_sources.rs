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
    /// Only files in this state: `claimed`, `accepted` or `refused`.
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
    let sources = LandingSourceRepository::new(state.pool.clone())
        .list_sources()
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
    let repo = LandingSourceRepository::new(state.pool.clone());
    if !repo.source_exists(source_id).await.map_err(repository_error)? {
        return Err(ApiError::NotFound("Bucket drop source not found".into()));
    }
    let files = repo
        .list_files(source_id, query.limit, file_state)
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
    fn state_filter_accepts_only_known_states() {
        assert_eq!(validate_state(None).unwrap(), None);
        assert_eq!(validate_state(Some("")).unwrap(), None);
        assert_eq!(validate_state(Some("refused")).unwrap(), Some("refused"));
        assert!(validate_state(Some("deleted")).is_err());
        assert!(validate_state(Some("'; DROP")).is_err());
    }
}
