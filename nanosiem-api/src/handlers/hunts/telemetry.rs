// SPDX-License-Identifier: AGPL-3.0-or-later

//! Environment-specific telemetry capability bindings for portable hunts.

use axum::{extract::State, Extension, Json};
use nanosiem_core::audit::{
    AuditEvent, AuditSource, HUNT_SOURCE_CAPABILITY_BOUND, HUNT_SOURCE_CAPABILITY_RESET,
};
use nanosiem_core::auth::permissions;
use nanosiem_core::hunts::{
    ResetSourceCapabilityBindingRequest, SetSourceCapabilityBindingRequest, SourceCapabilityBinding,
};
use nanosiem_core::ClientContext;
use serde::Serialize;

use super::service;
use crate::handlers::AuditExt;
use crate::middleware::{ensure_permission, AuthContext};
use crate::{error::ApiError, state::AppState};

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct ListSourceCapabilityBindingsResponse {
    /// Effective rows: analyst overrides take precedence over recon inference.
    pub bindings: Vec<SourceCapabilityBinding>,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct ResetSourceCapabilityBindingResponse {
    pub reset: bool,
}

/// List source-to-capability bindings
///
/// These rows explain how portable hunt requirements such as
/// `identity.authentication` resolve onto this deployment's concrete source
/// names. Low-confidence inferred rows remain visible even though they do not
/// satisfy a hard requirement until an analyst confirms them.
#[utoipa::path(
    get,
    path = "/api/hunts/source-capability-bindings",
    tag = "hunts",
    responses(
        (status = 200, description = "Effective telemetry bindings", body = ListSourceCapabilityBindingsResponse),
        (status = 403, description = "Forbidden"),
    ),
    security(("api_key" = []))
)]
pub async fn list_source_capability_bindings(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
) -> Result<Json<ListSourceCapabilityBindingsResponse>, ApiError> {
    ensure_permission(&auth, permissions::HUNTS_VIEW)?;
    let bindings = service(&state).list_source_capability_bindings().await?;
    Ok(Json(ListSourceCapabilityBindingsResponse { bindings }))
}

/// Confirm or reject a source capability binding
///
/// `state = mapped` trusts the binding. `state = ignored` is a durable negative
/// override which prevents a false-positive inference from satisfying a hunt.
#[utoipa::path(
    put,
    path = "/api/hunts/source-capability-bindings",
    tag = "hunts",
    request_body = SetSourceCapabilityBindingRequest,
    responses(
        (status = 200, description = "Analyst override stored", body = SourceCapabilityBinding),
        (status = 400, description = "Invalid binding"),
        (status = 403, description = "Forbidden"),
    ),
    security(("api_key" = []))
)]
pub async fn set_source_capability_binding(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Extension(client): Extension<ClientContext>,
    Json(request): Json<SetSourceCapabilityBindingRequest>,
) -> Result<Json<SourceCapabilityBinding>, ApiError> {
    ensure_permission(&auth, permissions::HUNTS_MANAGE)?;
    let binding = service(&state)
        .set_source_capability_binding(&request, Some(auth.user_id()))
        .await?;
    state.emit_audit(
        AuditEvent::builder(AuditSource::Hunt, HUNT_SOURCE_CAPABILITY_BOUND)
            .actor(Some(auth.user_id()), None)
            .api_key(auth.api_key_id, auth.api_key_name.clone())
            .resource(
                "hunt_source_capability_binding",
                None,
                Some(format!("{}:{}", binding.source_type, binding.capability)),
            )
            .client_context(&client)
            .details(serde_json::json!({
                "source_type": binding.source_type,
                "capability": binding.capability,
                "state": binding.state,
            }))
            .build(),
    );
    Ok(Json(binding))
}

/// Reset an analyst source capability override
///
/// Removes only the analyst row. If recon has an inferred row for the same
/// source/capability pair it becomes effective immediately.
#[utoipa::path(
    post,
    path = "/api/hunts/source-capability-bindings/reset",
    tag = "hunts",
    request_body = ResetSourceCapabilityBindingRequest,
    responses(
        (status = 200, description = "Override reset (idempotent)", body = ResetSourceCapabilityBindingResponse),
        (status = 400, description = "Invalid binding identity"),
        (status = 403, description = "Forbidden"),
    ),
    security(("api_key" = []))
)]
pub async fn reset_source_capability_binding(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Extension(client): Extension<ClientContext>,
    Json(request): Json<ResetSourceCapabilityBindingRequest>,
) -> Result<Json<ResetSourceCapabilityBindingResponse>, ApiError> {
    ensure_permission(&auth, permissions::HUNTS_MANAGE)?;
    let reset = service(&state)
        .reset_source_capability_binding(&request)
        .await?;
    if reset {
        state.emit_audit(
            AuditEvent::builder(AuditSource::Hunt, HUNT_SOURCE_CAPABILITY_RESET)
                .actor(Some(auth.user_id()), None)
                .api_key(auth.api_key_id, auth.api_key_name.clone())
                .resource(
                    "hunt_source_capability_binding",
                    None,
                    Some(format!("{}:{}", request.source_type, request.capability)),
                )
                .client_context(&client)
                .details(serde_json::json!({
                    "source_type": request.source_type,
                    "capability": request.capability,
                }))
                .build(),
        );
    }
    Ok(Json(ResetSourceCapabilityBindingResponse { reset }))
}
