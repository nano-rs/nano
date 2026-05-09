// SPDX-License-Identifier: AGPL-3.0-or-later

//! /health finding suppression API handlers (NAN-615).
//!
//! Operators mark recommendations on /health as "not an issue" with a reason;
//! the active suppressions are loaded by the scheduler and injected into the
//! AI system prompt so the same class doesn't reappear on the next run.
//!
//! Read endpoints require authentication only (operators viewing the page);
//! mutations require `settings:system` to match the existing /health admin
//! gate (manual trigger uses the same permission).

use axum::{
    Extension, Json,
    extract::{Path, Query, State},
    http::StatusCode,
};
use serde::{Deserialize, Serialize};

use crate::error::ApiError;
use crate::middleware::AuthContext;
use crate::state::AppState;
use nanosiem_core::siem_health::finding_signature::signature_for_title;
use nanosiem_core::siem_health::{FindingSuppression, SuppressionRepository};
use nanosiem_core::typeid::TypeIdParam;

#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct CreateSuppressionRequest {
    /// Display title of the suppressed finding, verbatim from the
    /// recommendation card. The backend derives the stable signature from
    /// this title so the frontend doesn't need to reimplement the hash.
    pub title: String,
    /// Operator's reason — fed to the AI on subsequent runs so it can judge
    /// whether the suppression still applies.
    pub reason: String,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct ListSuppressionsResponse {
    pub suppressions: Vec<FindingSuppression>,
}

#[derive(Debug, Deserialize, utoipa::IntoParams)]
pub struct ListSuppressionsParams {
    /// When true, include deactivated (undone) suppressions as well as active
    /// ones. Defaults to false.
    #[serde(default)]
    pub include_deactivated: bool,
}

const REASON_MAX_LEN: usize = 500;
const TITLE_MAX_LEN: usize = 500;

/// Suppress a /health finding so the AI omits the same class on subsequent
/// report runs.
#[utoipa::path(
    post,
    path = "/api/siem-health/findings/suppressions",
    tag = "siem_health",
    request_body = CreateSuppressionRequest,
    responses(
        (status = 201, description = "Suppression created (or refreshed if one already exists for this signature)", body = FindingSuppression),
        (status = 400, description = "Invalid input"),
        (status = 403, description = "Insufficient permissions"),
    ),
    security(("api_key" = []))
)]
pub async fn create_suppression(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Json(req): Json<CreateSuppressionRequest>,
) -> Result<(StatusCode, Json<FindingSuppression>), ApiError> {
    crate::middleware::check_permission(&auth, nanosiem_core::auth::permissions::SETTINGS_SYSTEM)
        .map_err(|_| ApiError::Forbidden("Missing permission: settings:system".to_string()))?;

    let title = req.title.trim();
    let reason = req.reason.trim();
    if title.is_empty() {
        return Err(ApiError::BadRequest("title must not be empty".to_string()));
    }
    if reason.is_empty() {
        return Err(ApiError::BadRequest(
            "reason must not be empty — operators must explain why this is not an issue"
                .to_string(),
        ));
    }
    if title.len() > TITLE_MAX_LEN {
        return Err(ApiError::BadRequest(format!(
            "title exceeds {TITLE_MAX_LEN} chars"
        )));
    }
    if reason.len() > REASON_MAX_LEN {
        return Err(ApiError::BadRequest(format!(
            "reason exceeds {REASON_MAX_LEN} chars"
        )));
    }

    let signature = signature_for_title(title);
    let repo = SuppressionRepository::new(state.pool.clone());
    let suppression = repo
        .create(&signature, title, reason, auth.user_id())
        .await
        .map_err(|e| ApiError::DatabaseError(e.to_string()))?;

    Ok((StatusCode::CREATED, Json(suppression)))
}

/// List /health finding suppressions.
#[utoipa::path(
    get,
    path = "/api/siem-health/findings/suppressions",
    tag = "siem_health",
    params(ListSuppressionsParams),
    responses(
        (status = 200, description = "List of suppressions, oldest-first when active-only, newest-first when including deactivated", body = ListSuppressionsResponse),
    ),
    security(("api_key" = []))
)]
pub async fn list_suppressions(
    State(state): State<AppState>,
    Extension(_auth): Extension<AuthContext>,
    Query(params): Query<ListSuppressionsParams>,
) -> Result<Json<ListSuppressionsResponse>, ApiError> {
    let repo = SuppressionRepository::new(state.pool.clone());
    let suppressions = if params.include_deactivated {
        repo.list_all().await
    } else {
        repo.list_active().await
    }
    .map_err(|e| ApiError::DatabaseError(e.to_string()))?;

    Ok(Json(ListSuppressionsResponse { suppressions }))
}

/// Deactivate (undo) a suppression. Findings of this class will surface again
/// on the next report run.
#[utoipa::path(
    delete,
    path = "/api/siem-health/findings/suppressions/{id}",
    tag = "siem_health",
    params(
        ("id" = String, Path, description = "Suppression typeid (hsupp_<base32>) or bare UUID"),
    ),
    responses(
        (status = 200, description = "Suppression deactivated", body = FindingSuppression),
        (status = 403, description = "Insufficient permissions"),
        (status = 404, description = "Suppression not found or already deactivated"),
    ),
    security(("api_key" = []))
)]
pub async fn deactivate_suppression(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<TypeIdParam>,
) -> Result<Json<FindingSuppression>, ApiError> {
    crate::middleware::check_permission(&auth, nanosiem_core::auth::permissions::SETTINGS_SYSTEM)
        .map_err(|_| ApiError::Forbidden("Missing permission: settings:system".to_string()))?;

    let repo = SuppressionRepository::new(state.pool.clone());
    let suppression = repo
        .deactivate(*id, auth.user_id())
        .await
        .map_err(|e| match e {
            nanosiem_core::siem_health::SuppressionRepositoryError::NotFound(_) => {
                ApiError::NotFound("Suppression not found or already deactivated".to_string())
            }
            other => ApiError::DatabaseError(other.to_string()),
        })?;

    Ok(Json(suppression))
}

#[derive(utoipa::OpenApi)]
#[openapi(
    paths(create_suppression, list_suppressions, deactivate_suppression),
    components(schemas(
        CreateSuppressionRequest,
        ListSuppressionsResponse,
        FindingSuppression,
    ))
)]
pub struct SiemHealthSuppressionsApiDoc;
