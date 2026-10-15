// SPDX-License-Identifier: AGPL-3.0-or-later
//! Dedicated tenant export settings. Shared deployment uses its signed settings port.
use crate::{
    error::{ApiError, ErrorResponse},
    middleware::{ensure_permission, AuthContext},
    state::AppState,
};
use axum::{extract::State, Extension, Json};
use nanosiem_core::{
    audit::{AuditEvent, AuditSource, ClientContext},
    auth::permissions,
    iceberg_export::{self as core, ExportError, ExportSettings, UpdateExportSettings},
};
const DEDICATED_TENANT: &str = "00000000-0000-0000-0000-000000000100";
fn check(state: &AppState, auth: &AuthContext) -> Result<(), ApiError> {
    #[cfg(feature = "enterprise")]
    if state.config.deployment_mode.is_enterprise_shared() {
        return Err(ApiError::Forbidden(
            "Signed tenant export port required".into(),
        ));
    }
    ensure_permission(auth, permissions::SETTINGS_SYSTEM)?;
    if auth.is_api_key
        || !auth
            .claims
            .roles
            .iter()
            .any(|r| r.eq_ignore_ascii_case("admin"))
    {
        return Err(ApiError::Forbidden("Tenant admin session required".into()));
    }
    Ok(())
}
fn error(e: ExportError) -> ApiError {
    match e {
        ExportError::Invalid => {
            ApiError::ValidationError("Invalid export settings or feature disabled".into())
        }
        ExportError::Locked => ApiError::Conflict(
            "Export target revision changed, or target is active/immutable".into(),
        ),
        _ => ApiError::ServiceUnavailable("Export settings unavailable".into()),
    }
}
/// Get customer Iceberg export settings and health. Requires an interactive tenant Admin.
#[utoipa::path(get,operation_id="get_iceberg_export_settings",path="/api/settings/iceberg-export",tag="settings",responses((status=200,body=ExportSettings),(status=403,body=ErrorResponse),(status=503,body=ErrorResponse)),security(("bearer_auth"=[])))]
pub async fn get(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
) -> Result<Json<ExportSettings>, ApiError> {
    check(&state, &auth)?;
    let mut tx = state
        .pool
        .begin()
        .await
        .map_err(|_| ApiError::ServiceUnavailable("Export settings unavailable".into()))?;
    let value = core::read(
        &mut tx,
        DEDICATED_TENANT.parse().unwrap(),
        core::feature_enabled(),
    )
    .await
    .map_err(error)?;
    tx.commit()
        .await
        .map_err(|_| ApiError::ServiceUnavailable("Export settings unavailable".into()))?;
    Ok(Json(value))
}
/// Update customer Iceberg export settings. Credentials are write-only; requires an interactive tenant Admin.
#[utoipa::path(put,operation_id="update_iceberg_export_settings",path="/api/settings/iceberg-export",tag="settings",request_body=UpdateExportSettings,responses((status=200,body=ExportSettings),(status=400,body=ErrorResponse),(status=403,body=ErrorResponse),(status=409,body=ErrorResponse),(status=503,body=ErrorResponse)),security(("bearer_auth"=[])))]
pub async fn put(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Extension(client): Extension<ClientContext>,
    Json(input): Json<UpdateExportSettings>,
) -> Result<Json<ExportSettings>, ApiError> {
    check(&state, &auth)?;
    let credential_rotated = input.credentials.is_some();
    let mut tx = state
        .pool
        .begin()
        .await
        .map_err(|_| ApiError::ServiceUnavailable("Export settings unavailable".into()))?;
    let value = core::update(
        &mut tx,
        DEDICATED_TENANT.parse().unwrap(),
        &state.encryption_service,
        input,
    )
    .await
    .map_err(error)?;
    let event=AuditEvent::builder(AuditSource::Settings,"iceberg_export_updated").actor(Some(auth.user_id()),None)
        .resource("iceberg_export",None,None).details(serde_json::json!({"enabled":value.enabled,"revision":value.revision,"credential_rotated":credential_rotated})).client_context(&client).build();
    nanosiem_core::audit::append_dedicated_audit_in_transaction(
        &mut tx,
        DEDICATED_TENANT.parse().unwrap(),
        &event,
    )
    .await
    .map_err(|_| ApiError::ServiceUnavailable("Export audit unavailable".into()))?;
    tx.commit()
        .await
        .map_err(|_| ApiError::ServiceUnavailable("Export settings unavailable".into()))?;
    Ok(Json(value))
}
#[derive(utoipa::OpenApi)]
#[openapi(
    paths(get, put),
    components(schemas(
        ExportSettings,
        UpdateExportSettings,
        core::CustomerExportConfig,
        core::CatalogAuthentication
    ))
)]
pub struct IcebergExportApiDoc;
