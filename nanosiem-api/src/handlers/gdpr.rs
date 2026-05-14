// SPDX-License-Identifier: AGPL-3.0-or-later

//! GDPR Data Subject Anonymization API handlers
//!
//! Four endpoints for submitting, listing, viewing, and executing anonymization requests.
//! All gated by the `gdpr:anonymize` permission.

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    Json,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use utoipa::{IntoParams, OpenApi, ToSchema};

use nanosiem_core::typeid::TypeIdParam;

use nanosiem_core::audit::{AuditEvent, AuditSource, ClientContext};
use nanosiem_core::auth::permissions;
use nanosiem_core::gdpr::{
    AnonymizationError, AnonymizationPreview, AnonymizationRequest, AnonymizationService,
    AnonymizationStatus, IdentifierType,
};
use nanosiem_core::{
    GDPR_ANONYMIZATION_COMPLETED, GDPR_ANONYMIZATION_FAILED, GDPR_ANONYMIZATION_STARTED,
    GDPR_ANONYMIZATION_SUBMITTED,
};

use crate::handlers::AuditExt;
use crate::middleware::{check_permission, AuthContext};
use crate::state::AppState;

// =========================================================================
// Request / Response types
// =========================================================================

#[derive(Debug, Serialize, ToSchema)]
pub struct GdprApiError {
    pub error: String,
    pub message: String,
}

impl GdprApiError {
    pub fn new(error: &str, message: &str) -> Self {
        Self {
            error: error.to_string(),
            message: message.to_string(),
        }
    }
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct SubmitAnonymizationRequest {
    /// Type of identifier to anonymize
    pub identifier_type: IdentifierType,
    /// The plaintext identifier value (hashed immediately, never persisted)
    pub identifier_value: String,
    /// Justification for the anonymization request
    pub justification: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct AnonymizationListResponse {
    pub requests: Vec<AnonymizationRequest>,
    pub total: i64,
}

#[derive(Debug, Deserialize, IntoParams)]
pub struct ListAnonymizationParams {
    #[param(default = 50, minimum = 1, maximum = 100)]
    pub limit: Option<i64>,
    #[param(default = 0, minimum = 0)]
    pub offset: Option<i64>,
}

type GdprResult<T> = Result<T, (StatusCode, Json<GdprApiError>)>;

fn map_err(err: AnonymizationError) -> (StatusCode, Json<GdprApiError>) {
    let (status, error_type) = match &err {
        AnonymizationError::NotFound(_) => (StatusCode::NOT_FOUND, "not_found"),
        AnonymizationError::NotPending => (StatusCode::CONFLICT, "not_pending"),
        AnonymizationError::SaltNotConfigured => {
            (StatusCode::INTERNAL_SERVER_ERROR, "salt_not_configured")
        }
        AnonymizationError::InvalidIdentifier(_) => (StatusCode::BAD_REQUEST, "invalid_identifier"),
        AnonymizationError::Database(_) | AnonymizationError::ClickHouse(_) => {
            (StatusCode::INTERNAL_SERVER_ERROR, "internal_error")
        }
    };
    (
        status,
        Json(GdprApiError::new(error_type, &err.to_string())),
    )
}

// =========================================================================
// Handlers
// =========================================================================

/// Submit a GDPR anonymization request
///
/// Validates the identifier, computes its salted hash, estimates affected row
/// counts, and creates a pending job. The plaintext identifier is discarded
/// after hashing — only the irreversible hash is stored.
#[utoipa::path(
    post,
    path = "/api/gdpr/anonymize",
    tag = "gdpr",
    request_body = SubmitAnonymizationRequest,
    responses(
        (status = 201, description = "Anonymization request created", body = AnonymizationPreview),
        (status = 400, description = "Invalid identifier", body = GdprApiError),
        (status = 403, description = "Forbidden — missing gdpr:anonymize permission", body = GdprApiError),
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn submit_anonymization(
    State(state): State<AppState>,
    auth: axum::Extension<AuthContext>,
    client: axum::Extension<ClientContext>,
    Json(request): Json<SubmitAnonymizationRequest>,
) -> GdprResult<(StatusCode, Json<AnonymizationPreview>)> {
    check_permission(&auth, permissions::GDPR_ANONYMIZE)
        .map_err(|(s, j)| (s, Json(GdprApiError::new(&j.error, &j.message))))?;

    let service = build_service(&state)?;

    let preview = service
        .submit_request(
            auth.user_id(),
            request.identifier_type,
            &request.identifier_value,
            request.justification.as_deref(),
        )
        .await
        .map_err(map_err)?;

    state.emit_audit(
        AuditEvent::builder(AuditSource::Gdpr, GDPR_ANONYMIZATION_SUBMITTED)
            .actor(Some(auth.user_id()), None)
            .api_key(auth.api_key_id, auth.api_key_name.clone())
            .resource("gdpr_request", Some(preview.request_id), None)
            .client_context(&client)
            .details(json!({
                "identifier_type": request.identifier_type,
                "estimated_logs": preview.estimated_logs,
            }))
            .build(),
    );

    Ok((StatusCode::CREATED, Json(preview)))
}

/// List all GDPR anonymization requests
#[utoipa::path(
    get,
    path = "/api/gdpr/anonymize",
    tag = "gdpr",
    params(ListAnonymizationParams),
    responses(
        (status = 200, description = "List of anonymization requests", body = AnonymizationListResponse),
        (status = 403, description = "Forbidden", body = GdprApiError),
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn list_anonymization_requests(
    State(state): State<AppState>,
    auth: axum::Extension<AuthContext>,
    Query(params): Query<ListAnonymizationParams>,
) -> GdprResult<Json<AnonymizationListResponse>> {
    check_permission(&auth, permissions::GDPR_ANONYMIZE)
        .map_err(|(s, j)| (s, Json(GdprApiError::new(&j.error, &j.message))))?;

    let service = build_service(&state)?;
    let limit = params.limit.unwrap_or(50).clamp(1, 100);
    let offset = params.offset.unwrap_or(0).max(0);

    let (requests, total) = service
        .list_requests(limit, offset)
        .await
        .map_err(map_err)?;

    Ok(Json(AnonymizationListResponse { requests, total }))
}

/// Get a specific GDPR anonymization request
#[utoipa::path(
    get,
    path = "/api/gdpr/anonymize/{id}",
    tag = "gdpr",
    params(("id" = String, Path, description = "Request ID")),
    responses(
        (status = 200, description = "Anonymization request details", body = AnonymizationRequest),
        (status = 403, description = "Forbidden", body = GdprApiError),
        (status = 404, description = "Request not found", body = GdprApiError),
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn get_anonymization_request(
    State(state): State<AppState>,
    auth: axum::Extension<AuthContext>,
    Path(id): Path<TypeIdParam>,
) -> GdprResult<Json<AnonymizationRequest>> {
    check_permission(&auth, permissions::GDPR_ANONYMIZE)
        .map_err(|(s, j)| (s, Json(GdprApiError::new(&j.error, &j.message))))?;

    let service = build_service(&state)?;
    let request = service.get_request(*id).await.map_err(map_err)?;

    Ok(Json(request))
}

/// Execute a pending GDPR anonymization request
///
/// Validates the request is pending, then spawns the mutation work as a
/// background task. Returns 202 Accepted immediately — poll
/// `GET /api/gdpr/anonymize/{id}` for status updates.
#[utoipa::path(
    post,
    path = "/api/gdpr/anonymize/{id}/execute",
    tag = "gdpr",
    params(("id" = String, Path, description = "Request ID")),
    responses(
        (status = 202, description = "Anonymization started in background", body = AnonymizationRequest),
        (status = 403, description = "Forbidden", body = GdprApiError),
        (status = 404, description = "Request not found", body = GdprApiError),
        (status = 409, description = "Request not in pending status", body = GdprApiError),
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn execute_anonymization(
    State(state): State<AppState>,
    auth: axum::Extension<AuthContext>,
    client: axum::Extension<ClientContext>,
    Path(id): Path<TypeIdParam>,
) -> GdprResult<(StatusCode, Json<AnonymizationRequest>)> {
    check_permission(&auth, permissions::GDPR_ANONYMIZE)
        .map_err(|(s, j)| (s, Json(GdprApiError::new(&j.error, &j.message))))?;

    let service = build_service(&state)?;

    // Verify the request exists before spawning (the service will atomically
    // claim it via UPDATE ... WHERE status = 'pending', preventing races).
    let request = service.get_request(*id).await.map_err(map_err)?;

    state.emit_audit(
        AuditEvent::builder(AuditSource::Gdpr, GDPR_ANONYMIZATION_STARTED)
            .actor(Some(auth.user_id()), None)
            .api_key(auth.api_key_id, auth.api_key_name.clone())
            .resource("gdpr_request", Some(*id), None)
            .client_context(&client)
            .build(),
    );

    // Capture values for the background task
    let user_id = auth.user_id();
    let api_key_id = auth.api_key_id;
    let api_key_name = auth.api_key_name.clone();
    let bg_state = state.clone();
    let id = *id;

    tokio::spawn(async move {
        match service.execute_request(id).await {
            Ok(result) => {
                bg_state.emit_audit(
                    AuditEvent::builder(AuditSource::Gdpr, GDPR_ANONYMIZATION_COMPLETED)
                        .actor(Some(user_id), None)
                        .api_key(api_key_id, api_key_name.clone())
                        .resource("gdpr_request", Some(id), None)
                        .details(json!({
                            "mutation_ids": result.mutation_ids,
                        }))
                        .build(),
                );
            }
            Err(e) => {
                bg_state.emit_audit(
                    AuditEvent::builder(AuditSource::Gdpr, GDPR_ANONYMIZATION_FAILED)
                        .actor(Some(user_id), None)
                        .api_key(api_key_id, api_key_name.clone())
                        .resource("gdpr_request", Some(id), None)
                        .success(false)
                        .details(json!({ "error": e.to_string() }))
                        .build(),
                );
            }
        }
    });

    Ok((StatusCode::ACCEPTED, Json(request)))
}

// =========================================================================
// Helpers
// =========================================================================

fn build_service(
    state: &AppState,
) -> Result<AnonymizationService, (StatusCode, Json<GdprApiError>)> {
    Ok(AnonymizationService::new(
        state.pool.clone(),
        state.dual_pool.clone(),
    ))
}

// =========================================================================
// OpenAPI
// =========================================================================

#[derive(OpenApi)]
#[openapi(
    paths(
        submit_anonymization,
        list_anonymization_requests,
        get_anonymization_request,
        execute_anonymization,
    ),
    components(schemas(
        GdprApiError,
        SubmitAnonymizationRequest,
        AnonymizationPreview,
        AnonymizationRequest,
        AnonymizationListResponse,
        IdentifierType,
        AnonymizationStatus,
    )),
    tags((name = "gdpr", description = "GDPR data subject anonymization"))
)]
pub struct GdprApiDoc;
