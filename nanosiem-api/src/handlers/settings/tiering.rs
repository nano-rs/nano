// SPDX-License-Identifier: AGPL-3.0-or-later

//! S3 warm/cold storage tiering handlers

use axum::{extract::State, Extension, Json};
use nanosiem_core::audit::{
    AuditEvent, AuditSource, ClientContext, TIERING_CONFIG_APPLIED, TIERING_CONFIG_UPDATED,
    TIERING_CONNECTION_TESTED, TIERING_CREDENTIALS_SET,
};
use nanosiem_core::auth::permissions;
use nanosiem_core::settings::{
    ConnectionTestResult as TieringTestResult, S3Credentials, TierStats, TieringConfig,
    TieringService, UpdateTieringRequest,
};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use utoipa::ToSchema;

use crate::error::{ApiError, ErrorResponse};
use crate::handlers::AuditExt;
use crate::middleware::{ensure_permission, AuthContext};
use crate::state::AppState;

// ============================================================================
// Request/Response Types
// ============================================================================

/// Response for tiering configuration
#[derive(Debug, Serialize, ToSchema)]
pub struct TieringConfigResponse {
    pub enabled: bool,
    pub s3_endpoint: Option<String>,
    pub s3_bucket: Option<String>,
    pub s3_region: String,
    pub s3_path_style: bool,
    pub has_credentials: bool,
    pub retention_days: u32,
    pub move_factor: f32,
    pub status: String,
    pub status_message: Option<String>,
    pub last_applied_at: Option<String>,
}

impl From<TieringConfig> for TieringConfigResponse {
    fn from(config: TieringConfig) -> Self {
        Self {
            enabled: config.enabled,
            s3_endpoint: config.s3_endpoint,
            s3_bucket: config.s3_bucket,
            s3_region: config.s3_region,
            s3_path_style: config.s3_path_style,
            has_credentials: config.has_credentials,
            retention_days: config.retention_days,
            move_factor: config.move_factor,
            status: config.status.as_str().to_string(),
            status_message: config.status_message,
            last_applied_at: config.last_applied_at.map(|t| t.to_rfc3339()),
        }
    }
}

/// Request to set S3 credentials
#[derive(Debug, Deserialize, ToSchema)]
pub struct SetTieringCredentialsRequest {
    pub access_key_id: String,
    pub secret_access_key: String,
}

/// Response for tier statistics
#[derive(Debug, Serialize, ToSchema)]
pub struct TierStatsResponse {
    pub hot: TierInfoResponse,
    pub warm: TierInfoResponse,
    pub total_size_bytes: u64,
    pub total_size_pretty: String,
    pub total_row_count: u64,
    pub last_updated: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct TierInfoResponse {
    pub size_bytes: u64,
    pub size_pretty: String,
    pub row_count: u64,
}

impl From<TierStats> for TierStatsResponse {
    fn from(stats: TierStats) -> Self {
        Self {
            hot: TierInfoResponse {
                size_bytes: stats.hot.size_bytes,
                size_pretty: stats.hot.size_pretty,
                row_count: stats.hot.row_count,
            },
            warm: TierInfoResponse {
                size_bytes: stats.warm.size_bytes,
                size_pretty: stats.warm.size_pretty,
                row_count: stats.warm.row_count,
            },
            total_size_bytes: stats.total_size_bytes,
            total_size_pretty: stats.total_size_pretty,
            total_row_count: stats.total_row_count,
            last_updated: stats.last_updated.to_rfc3339(),
        }
    }
}

/// Response for connection test
#[derive(Debug, Serialize, ToSchema)]
pub struct TieringConnectionTestResponse {
    pub success: bool,
    pub message: String,
    pub latency_ms: Option<u64>,
}

impl From<TieringTestResult> for TieringConnectionTestResponse {
    fn from(result: TieringTestResult) -> Self {
        Self {
            success: result.success,
            message: result.message,
            latency_ms: result.latency_ms,
        }
    }
}

// ============================================================================
// Helpers
// ============================================================================
// Note: `From<TieringError> for ApiError` lifted to nanosiem-api-lib in
// NAN-752 (orphan rule — `ApiError` lives there now).
// ============================================================================

/// Helper to get tiering service
fn get_tiering_service(state: &AppState) -> Result<TieringService, ApiError> {
    let dual_pool = state.dual_pool();

    // Get config directory - default to ./clickhouse/config.d relative to working dir
    let config_dir = std::env::var("CLICKHOUSE_CONFIG_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("./clickhouse/config.d"));

    Ok(TieringService::with_crypto(
        dual_pool.postgres().clone(),
        dual_pool.clickhouse().clone(),
        config_dir,
        state.encryption_service.as_ref().clone(),
    ))
}

// ============================================================================
// Handler Functions
// ============================================================================

/// Get tiering configuration
///
/// GET /api/settings/tiering
///
/// Returns the current storage tiering configuration.
#[utoipa::path(
    get,
    path = "/api/settings/tiering",
    tag = "settings",
    responses(
        (status = 200, description = "Tiering configuration", body = TieringConfigResponse),
        (status = 400, description = "ClickHouse not enabled", body = ErrorResponse),
        (status = 403, description = "Missing permission", body = ErrorResponse),
        (status = 500, description = "Internal error", body = ErrorResponse)
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn get_tiering_config(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
) -> Result<Json<TieringConfigResponse>, ApiError> {
    ensure_permission(&auth, permissions::SETTINGS_RETENTION)?;
    #[cfg(feature = "enterprise")]
    super::reject_enterprise_shared_storage_settings(&state)?;

    let service = get_tiering_service(&state)?;
    let config = service.get_config().await?;

    Ok(Json(TieringConfigResponse::from(config)))
}

/// Update tiering configuration
///
/// PUT /api/settings/tiering
///
/// Updates the storage tiering configuration. Does not apply to ClickHouse
/// until apply_tiering_config is called.
#[utoipa::path(
    put,
    path = "/api/settings/tiering",
    tag = "settings",
    request_body = UpdateTieringRequest,
    responses(
        (status = 200, description = "Tiering updated", body = TieringConfigResponse),
        (status = 400, description = "Invalid config", body = ErrorResponse),
        (status = 403, description = "Missing permission", body = ErrorResponse),
        (status = 500, description = "Internal error", body = ErrorResponse)
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn update_tiering_config(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Extension(client): Extension<ClientContext>,
    Json(request): Json<UpdateTieringRequest>,
) -> Result<Json<TieringConfigResponse>, ApiError> {
    ensure_permission(&auth, permissions::SETTINGS_RETENTION)?;
    #[cfg(feature = "enterprise")]
    super::reject_enterprise_shared_storage_settings(&state)?;

    let service = get_tiering_service(&state)?;
    let config = service.update_config(request).await?;

    tracing::info!(
        enabled = config.enabled,
        retention_days = config.retention_days,
        move_factor = config.move_factor,
        "Tiering configuration updated"
    );

    state.emit_audit(
        AuditEvent::builder(AuditSource::Settings, TIERING_CONFIG_UPDATED)
            .actor(Some(auth.user_id()), None)
            .api_key(auth.api_key_id, auth.api_key_name.clone())
            .resource("settings", None, Some("tiering".to_string()))
            .client_context(&client)
            .build(),
    );

    Ok(Json(TieringConfigResponse::from(config)))
}

/// Set S3 credentials for tiering
///
/// POST /api/settings/tiering/credentials
///
/// Sets the S3 credentials used for tiered storage. Credentials are encrypted.
#[utoipa::path(
    post,
    path = "/api/settings/tiering/credentials",
    tag = "settings",
    request_body = SetTieringCredentialsRequest,
    responses(
        (status = 200, description = "Credentials set", body = serde_json::Value),
        (status = 400, description = "Invalid credentials", body = ErrorResponse),
        (status = 403, description = "Missing permission", body = ErrorResponse),
        (status = 500, description = "Internal error", body = ErrorResponse)
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn set_tiering_credentials(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Extension(client): Extension<ClientContext>,
    Json(request): Json<SetTieringCredentialsRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    ensure_permission(&auth, permissions::SETTINGS_RETENTION)?;
    #[cfg(feature = "enterprise")]
    super::reject_enterprise_shared_storage_settings(&state)?;

    let service = get_tiering_service(&state)?;

    let creds = S3Credentials {
        access_key_id: request.access_key_id,
        secret_access_key: request.secret_access_key,
    };

    service.set_credentials(creds).await?;

    tracing::info!("Tiering S3 credentials updated");

    state.emit_audit(
        AuditEvent::builder(AuditSource::Settings, TIERING_CREDENTIALS_SET)
            .actor(Some(auth.user_id()), None)
            .api_key(auth.api_key_id, auth.api_key_name.clone())
            .resource("settings", None, Some("tiering_credentials".to_string()))
            .client_context(&client)
            .build(),
    );

    Ok(Json(serde_json::json!({
        "success": true,
        "message": "S3 credentials saved successfully"
    })))
}

/// Test S3 connection for tiering
///
/// POST /api/settings/tiering/test
///
/// Tests the S3 connection using the stored credentials.
#[utoipa::path(
    post,
    path = "/api/settings/tiering/test",
    tag = "settings",
    responses(
        (status = 200, description = "Connection test result", body = TieringConnectionTestResponse),
        (status = 400, description = "ClickHouse not enabled", body = ErrorResponse),
        (status = 403, description = "Missing permission", body = ErrorResponse),
        (status = 500, description = "Internal error", body = ErrorResponse)
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn test_tiering_connection(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Extension(client): Extension<ClientContext>,
) -> Result<Json<TieringConnectionTestResponse>, ApiError> {
    ensure_permission(&auth, permissions::SETTINGS_RETENTION)?;
    #[cfg(feature = "enterprise")]
    super::reject_enterprise_shared_storage_settings(&state)?;

    let service = get_tiering_service(&state)?;
    let result = service.test_connection().await?;

    state.emit_audit(
        AuditEvent::builder(AuditSource::Settings, TIERING_CONNECTION_TESTED)
            .actor(Some(auth.user_id()), None)
            .api_key(auth.api_key_id, auth.api_key_name.clone())
            .resource("settings", None, Some("tiering".to_string()))
            .client_context(&client)
            .build(),
    );

    Ok(Json(TieringConnectionTestResponse::from(result)))
}

/// Apply tiering configuration to ClickHouse
///
/// POST /api/settings/tiering/apply
///
/// Generates ClickHouse storage configuration, reloads config, and applies TTL rules.
#[utoipa::path(
    post,
    path = "/api/settings/tiering/apply",
    tag = "settings",
    responses(
        (status = 200, description = "Configuration applied", body = serde_json::Value),
        (status = 400, description = "ClickHouse not enabled", body = ErrorResponse),
        (status = 403, description = "Missing permission", body = ErrorResponse),
        (status = 500, description = "Internal error", body = ErrorResponse)
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn apply_tiering_config(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Extension(client): Extension<ClientContext>,
) -> Result<Json<serde_json::Value>, ApiError> {
    ensure_permission(&auth, permissions::SETTINGS_RETENTION)?;
    #[cfg(feature = "enterprise")]
    super::reject_enterprise_shared_storage_settings(&state)?;

    let service = get_tiering_service(&state)?;
    service.apply_config().await?;

    tracing::info!("Tiering configuration applied to ClickHouse");

    state.emit_audit(
        AuditEvent::builder(AuditSource::Settings, TIERING_CONFIG_APPLIED)
            .actor(Some(auth.user_id()), None)
            .api_key(auth.api_key_id, auth.api_key_name.clone())
            .resource("settings", None, Some("tiering".to_string()))
            .client_context(&client)
            .build(),
    );

    Ok(Json(serde_json::json!({
        "success": true,
        "message": "Tiering configuration applied successfully"
    })))
}

/// Get storage tier statistics
///
/// GET /api/settings/tiering/stats
///
/// Returns storage statistics for each tier (hot/warm).
#[utoipa::path(
    get,
    path = "/api/settings/tiering/stats",
    tag = "settings",
    responses(
        (status = 200, description = "Tier statistics", body = TierStatsResponse),
        (status = 400, description = "ClickHouse not enabled", body = ErrorResponse),
        (status = 403, description = "Missing permission", body = ErrorResponse),
        (status = 500, description = "Internal error", body = ErrorResponse)
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn get_tier_stats(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
) -> Result<Json<TierStatsResponse>, ApiError> {
    ensure_permission(&auth, permissions::SETTINGS_VIEW)?;
    #[cfg(feature = "enterprise")]
    super::reject_enterprise_shared_storage_settings(&state)?;

    if state.search_service.backend() == nanosiem_core::SearchBackend::Lake {
        let lake = super::retention::lake_storage_stats_or_none(
            super::retention::lake_storage_stats_from_env(),
        );
        return Ok(Json(lake_tier_stats(lake)));
    }

    let service = get_tiering_service(&state)?;
    let stats = service.get_tier_stats().await?;

    Ok(Json(TierStatsResponse::from(stats)))
}

/// Lake tier stats: everything is warm (object storage), nothing hot.
///
/// NAN-3492: `None` (no readable lake manifest, e.g. a lean trusted-local
/// install) reports an all-zero tier instead of failing the request.
fn lake_tier_stats(lake: Option<super::retention::LakeStorageStatsResponse>) -> TierStatsResponse {
    let empty = || TierInfoResponse {
        size_bytes: 0,
        size_pretty: "0 B".to_string(),
        row_count: 0,
    };
    let Some(lake) = lake else {
        return TierStatsResponse {
            hot: empty(),
            warm: empty(),
            total_size_bytes: 0,
            total_size_pretty: "0 B".to_string(),
            total_row_count: 0,
            last_updated: chrono::Utc::now().to_rfc3339(),
        };
    };
    TierStatsResponse {
        hot: empty(),
        warm: TierInfoResponse {
            size_bytes: lake.total_size_bytes,
            size_pretty: lake.total_size_pretty.clone(),
            row_count: lake.row_count,
        },
        total_size_bytes: lake.total_size_bytes,
        total_size_pretty: lake.total_size_pretty,
        total_row_count: lake.row_count,
        last_updated: lake
            .manifest_modified_at
            .unwrap_or_else(|| chrono::Utc::now().to_rfc3339()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::handlers::settings::retention::LakeStorageStatsResponse;

    #[test]
    fn unavailable_lake_stats_report_an_all_zero_tier() {
        // NAN-3492: a lean install has no gen1 lake manifest; the tier stats
        // must degrade to zeros rather than 500.
        let stats = lake_tier_stats(None);
        assert_eq!(stats.hot.size_bytes, 0);
        assert_eq!(stats.warm.size_bytes, 0);
        assert_eq!(stats.warm.row_count, 0);
        assert_eq!(stats.total_size_bytes, 0);
        assert_eq!(stats.total_row_count, 0);
        assert_eq!(stats.total_size_pretty, "0 B");
        assert!(chrono::DateTime::parse_from_rfc3339(&stats.last_updated).is_ok());
    }

    #[test]
    fn available_lake_stats_are_all_warm() {
        let stats = lake_tier_stats(Some(LakeStorageStatsResponse {
            total_size_bytes: 4096,
            total_size_pretty: "4.00 KiB".to_string(),
            row_count: 12,
            object_count: 2,
            index_size_bytes: 0,
            index_size_pretty: "0 B".to_string(),
            index_overhead_percent: 0.0,
            file_format: "Parquet".to_string(),
            table_format: "Iceberg v2".to_string(),
            manifest_modified_at: Some("2026-10-10T00:00:00+00:00".to_string()),
        }));
        assert_eq!(stats.hot.size_bytes, 0);
        assert_eq!(stats.warm.size_bytes, 4096);
        assert_eq!(stats.total_row_count, 12);
        assert_eq!(stats.last_updated, "2026-10-10T00:00:00+00:00");
    }
}
