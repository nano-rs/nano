// SPDX-License-Identifier: AGPL-3.0-or-later

//! PostgreSQL retention and ClickHouse storage handlers

use axum::{extract::State, Extension, Json};
use nanosiem_core::audit::{
    AuditEvent, AuditSource, ClientContext, CH_RETENTION_RUN_TRIGGERED, CH_RETENTION_UPDATED,
    RETENTION_CONFIG_UPDATED, RETENTION_RUN_TRIGGERED,
};
use nanosiem_core::auth::permissions;
use nanosiem_core::settings::{
    ClickHouseStorageStats, DualSystemSettings, RetentionConfig, StorageStats, SystemSettings,
};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::error::{ApiError, ErrorResponse};
use crate::handlers::AuditExt;
use crate::middleware::{ensure_permission, AuthContext};
use crate::state::AppState;

// ============================================================================
// Request/Response Types
// ============================================================================

/// Response for retention configuration
#[derive(Debug, Serialize, ToSchema)]
pub struct RetentionConfigResponse {
    pub enabled: bool,
    pub retention_days: u32,
    pub job_id: Option<i32>,
}

impl From<RetentionConfig> for RetentionConfigResponse {
    fn from(config: RetentionConfig) -> Self {
        Self {
            enabled: config.enabled,
            retention_days: config.retention_days,
            job_id: config.job_id,
        }
    }
}

/// Request to update retention configuration
#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateRetentionRequest {
    pub enabled: bool,
    pub retention_days: u32,
}

/// Response for storage statistics
#[derive(Debug, Serialize, ToSchema)]
pub struct StorageStatsResponse {
    pub total_size_bytes: i64,
    pub total_size_pretty: String,
    pub chunk_count: i64,
    pub compressed_chunks: i64,
    pub oldest_log: Option<String>,
    pub newest_log: Option<String>,
    pub log_count: i64,
}

impl From<StorageStats> for StorageStatsResponse {
    fn from(stats: StorageStats) -> Self {
        Self {
            total_size_bytes: stats.total_size_bytes,
            total_size_pretty: stats.total_size_pretty,
            chunk_count: stats.chunk_count,
            compressed_chunks: stats.compressed_chunks,
            oldest_log: stats.oldest_log.map(|t| t.to_rfc3339()),
            newest_log: stats.newest_log.map(|t| t.to_rfc3339()),
            log_count: stats.log_count,
        }
    }
}

/// Response for ClickHouse storage statistics
#[derive(Debug, Serialize, ToSchema)]
pub struct ClickHouseStorageStatsResponse {
    pub total_size_bytes: u64,
    pub total_size_pretty: String,
    pub row_count: u64,
    pub partition_count: u64,
    pub parts_count: u64,
    pub oldest_log: Option<String>,
    pub newest_log: Option<String>,
    pub compression_ratio: f64,
    pub uncompressed_size_bytes: u64,
    pub ttl_days: Option<u32>,
}

impl From<ClickHouseStorageStats> for ClickHouseStorageStatsResponse {
    fn from(stats: ClickHouseStorageStats) -> Self {
        Self {
            total_size_bytes: stats.total_size_bytes,
            total_size_pretty: stats.total_size_pretty,
            row_count: stats.row_count,
            partition_count: stats.partition_count,
            parts_count: stats.parts_count,
            oldest_log: stats.oldest_log.map(|t| t.to_rfc3339()),
            newest_log: stats.newest_log.map(|t| t.to_rfc3339()),
            compression_ratio: stats.compression_ratio,
            uncompressed_size_bytes: stats.uncompressed_size_bytes,
            ttl_days: stats.ttl_days,
        }
    }
}

/// Disk pressure status for the API response
#[derive(Debug, Serialize, ToSchema)]
pub struct DiskPressureStatusResponse {
    /// Current disk usage fraction (0.0–1.0)
    pub usage_fraction: f64,
    /// Total disk bytes
    pub total_bytes: u64,
    /// Used disk bytes
    pub used_bytes: u64,
    /// Free disk bytes
    pub free_bytes: u64,
    /// Current pressure level (normal, elevated, critical, emergency)
    pub level: String,
    /// Estimated days of retention remaining
    pub estimated_retention_days: Option<f64>,
    /// Number of partition-dates dropped since service started
    pub partitions_dropped: u64,
    /// Whether ingestion is currently paused
    pub ingestion_paused: bool,
    /// Configured high watermark
    pub high_watermark: f64,
    /// Configured low watermark
    pub low_watermark: f64,
    /// Configured critical threshold
    pub critical_threshold: f64,
    /// Configured emergency threshold
    pub emergency_threshold: f64,
}

/// Combined storage overview response
#[derive(Debug, Serialize, ToSchema)]
pub struct StorageOverviewResponse {
    /// Whether ClickHouse is enabled for log storage
    pub clickhouse_enabled: bool,
    /// PostgreSQL storage stats (metadata)
    pub postgres: Option<StorageStatsResponse>,
    /// ClickHouse storage stats (logs)
    pub clickhouse: Option<ClickHouseStorageStatsResponse>,
    /// Disk pressure status (only when ClickHouse is enabled)
    pub disk_pressure: Option<DiskPressureStatusResponse>,
}

/// Request to update ClickHouse retention
#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateClickHouseRetentionRequest {
    pub retention_days: u32,
}

// ============================================================================
// Handler Functions
// ============================================================================
// Note: `From<RetentionError> for ApiError` lifted to nanosiem-api-lib in
// NAN-752 (orphan rule — `ApiError` lives there now).

/// Get retention configuration
///
/// GET /api/settings/retention
#[utoipa::path(
    get,
    path = "/api/settings/retention",
    tag = "settings",
    responses(
        (status = 200, description = "Retention configuration", body = RetentionConfigResponse),
        (status = 403, description = "Missing permission", body = ErrorResponse),
        (status = 500, description = "Internal error", body = ErrorResponse)
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn get_retention_config(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
) -> Result<Json<RetentionConfigResponse>, ApiError> {
    ensure_permission(&auth, permissions::SETTINGS_RETENTION)?;

    let settings = SystemSettings::new(state.pool.clone());
    let config = settings.get_retention_config().await?;
    Ok(Json(RetentionConfigResponse::from(config)))
}

/// Update retention configuration
///
/// PUT /api/settings/retention
#[utoipa::path(
    put,
    path = "/api/settings/retention",
    tag = "settings",
    request_body = UpdateRetentionRequest,
    responses(
        (status = 200, description = "Retention updated", body = RetentionConfigResponse),
        (status = 403, description = "Missing permission", body = ErrorResponse),
        (status = 500, description = "Internal error", body = ErrorResponse)
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn update_retention_config(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Extension(client): Extension<ClientContext>,
    Json(request): Json<UpdateRetentionRequest>,
) -> Result<Json<RetentionConfigResponse>, ApiError> {
    ensure_permission(&auth, permissions::SETTINGS_RETENTION)?;

    let settings = SystemSettings::new(state.pool.clone());

    let config = RetentionConfig {
        enabled: request.enabled,
        retention_days: request.retention_days,
        job_id: None,
    };

    let updated = settings.update_retention_config(config).await?;

    state.emit_audit(
        AuditEvent::builder(AuditSource::Settings, RETENTION_CONFIG_UPDATED)
            .actor(Some(auth.user_id()), None)
            .api_key(auth.api_key_id, auth.api_key_name.clone())
            .resource("settings", None, Some("retention".to_string()))
            .client_context(&client)
            .build(),
    );

    Ok(Json(RetentionConfigResponse::from(updated)))
}

/// Get storage statistics
///
/// GET /api/settings/storage
#[utoipa::path(
    get,
    path = "/api/settings/storage",
    tag = "settings",
    responses(
        (status = 200, description = "Storage statistics", body = StorageStatsResponse),
        (status = 403, description = "Missing permission", body = ErrorResponse),
        (status = 500, description = "Internal error", body = ErrorResponse)
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn get_storage_stats(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
) -> Result<Json<StorageStatsResponse>, ApiError> {
    ensure_permission(&auth, permissions::SETTINGS_VIEW)?;

    let settings = SystemSettings::new(state.pool.clone());
    let stats = settings.get_storage_stats().await?;
    Ok(Json(StorageStatsResponse::from(stats)))
}

/// Run retention now (manually drop old chunks)
///
/// POST /api/settings/retention/run
#[utoipa::path(
    post,
    path = "/api/settings/retention/run",
    tag = "settings",
    responses(
        (status = 200, description = "Retention job started", body = serde_json::Value),
        (status = 403, description = "Missing permission", body = ErrorResponse),
        (status = 500, description = "Internal error", body = ErrorResponse)
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn run_retention_now(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Extension(client): Extension<ClientContext>,
) -> Result<Json<serde_json::Value>, ApiError> {
    ensure_permission(&auth, permissions::SETTINGS_RETENTION)?;

    let settings = SystemSettings::new(state.pool.clone());
    let dropped = settings.run_retention_now().await?;

    state.emit_audit(
        AuditEvent::builder(AuditSource::Settings, RETENTION_RUN_TRIGGERED)
            .actor(Some(auth.user_id()), None)
            .api_key(auth.api_key_id, auth.api_key_name.clone())
            .resource("settings", None, Some("retention".to_string()))
            .client_context(&client)
            .build(),
    );

    Ok(Json(serde_json::json!({
        "success": true,
        "chunks_dropped": dropped
    })))
}

/// Get storage overview (both PostgreSQL and ClickHouse)
///
/// GET /api/settings/storage/overview
///
/// Returns storage statistics for both databases.
#[utoipa::path(
    get,
    path = "/api/settings/storage/overview",
    tag = "settings",
    responses(
        (status = 200, description = "Storage overview", body = StorageOverviewResponse),
        (status = 403, description = "Missing permission", body = ErrorResponse),
        (status = 500, description = "Internal error", body = ErrorResponse)
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn get_storage_overview(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
) -> Result<Json<StorageOverviewResponse>, ApiError> {
    ensure_permission(&auth, permissions::SETTINGS_VIEW)?;

    let dual_pool = state.dual_pool();
    let settings =
        DualSystemSettings::new(dual_pool.postgres().clone(), dual_pool.clickhouse().clone());

    let postgres_stats = match settings.get_pg_storage_stats().await {
        Ok(stats) => Some(StorageStatsResponse::from(stats)),
        Err(e) => {
            tracing::error!("Failed to get PostgreSQL storage stats: {}", e);
            None
        }
    };

    let clickhouse_stats = match settings.get_clickhouse_storage_stats().await {
        Ok(stats) => {
            tracing::debug!("ClickHouse storage stats retrieved successfully");
            Some(ClickHouseStorageStatsResponse::from(stats))
        }
        Err(e) => {
            tracing::error!("Failed to get ClickHouse storage stats: {:?}", e);
            None
        }
    };

    let disk_pressure = match state.disk_pressure_service.get_status().await {
        Ok(status) => Some(DiskPressureStatusResponse {
            usage_fraction: status.usage_fraction,
            total_bytes: status.total_bytes,
            used_bytes: status.used_bytes,
            free_bytes: status.free_bytes,
            level: status.level.to_string(),
            estimated_retention_days: status.estimated_retention_days,
            partitions_dropped: status.partitions_dropped,
            ingestion_paused: status.ingestion_paused,
            high_watermark: status.high_watermark,
            low_watermark: status.low_watermark,
            critical_threshold: status.critical_threshold,
            emergency_threshold: status.emergency_threshold,
        }),
        Err(e) => {
            tracing::warn!("Failed to get disk pressure status: {}", e);
            None
        }
    };

    Ok(Json(StorageOverviewResponse {
        clickhouse_enabled: true,
        postgres: postgres_stats,
        clickhouse: clickhouse_stats,
        disk_pressure,
    }))
}

/// Get ClickHouse storage statistics
///
/// GET /api/settings/storage/clickhouse
///
/// Returns detailed storage statistics for ClickHouse log storage.
#[utoipa::path(
    get,
    path = "/api/settings/storage/clickhouse",
    tag = "settings",
    responses(
        (status = 200, description = "ClickHouse storage stats", body = ClickHouseStorageStatsResponse),
        (status = 400, description = "ClickHouse not enabled", body = ErrorResponse),
        (status = 403, description = "Missing permission", body = ErrorResponse),
        (status = 500, description = "Internal error", body = ErrorResponse)
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn get_clickhouse_storage_stats(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
) -> Result<Json<ClickHouseStorageStatsResponse>, ApiError> {
    ensure_permission(&auth, permissions::SETTINGS_VIEW)?;

    let dual_pool = state.dual_pool();
    let settings =
        DualSystemSettings::new(dual_pool.postgres().clone(), dual_pool.clickhouse().clone());

    let stats = settings.get_clickhouse_storage_stats().await?;
    Ok(Json(ClickHouseStorageStatsResponse::from(stats)))
}

/// Update ClickHouse retention TTL
///
/// PUT /api/settings/storage/clickhouse/retention
///
/// Updates the TTL retention period for ClickHouse logs.
#[utoipa::path(
    put,
    path = "/api/settings/storage/clickhouse/retention",
    tag = "settings",
    request_body = UpdateClickHouseRetentionRequest,
    responses(
        (status = 200, description = "Retention updated", body = serde_json::Value),
        (status = 400, description = "Invalid request", body = ErrorResponse),
        (status = 403, description = "Missing permission", body = ErrorResponse),
        (status = 500, description = "Internal error", body = ErrorResponse)
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn update_clickhouse_retention(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Extension(client): Extension<ClientContext>,
    Json(request): Json<UpdateClickHouseRetentionRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    ensure_permission(&auth, permissions::SETTINGS_RETENTION)?;

    let dual_pool = state.dual_pool();

    if request.retention_days < 1 {
        return Err(ApiError::ValidationError(
            "Retention period must be at least 1 day".to_string(),
        ));
    }

    let settings =
        DualSystemSettings::new(dual_pool.postgres().clone(), dual_pool.clickhouse().clone());

    settings
        .update_clickhouse_retention(request.retention_days)
        .await?;

    tracing::info!(
        "ClickHouse retention updated to {} days",
        request.retention_days
    );

    state.emit_audit(
        AuditEvent::builder(AuditSource::Settings, CH_RETENTION_UPDATED)
            .actor(Some(auth.user_id()), None)
            .api_key(auth.api_key_id, auth.api_key_name.clone())
            .resource("settings", None, Some("clickhouse_retention".to_string()))
            .client_context(&client)
            .build(),
    );

    Ok(Json(serde_json::json!({
        "success": true,
        "retention_days": request.retention_days,
        "message": format!("Retention policy updated to {} days", request.retention_days)
    })))
}

/// Run ClickHouse retention now (force TTL materialization)
///
/// POST /api/settings/storage/clickhouse/retention/run
///
/// Forces ClickHouse to materialize TTL and delete expired data.
#[utoipa::path(
    post,
    path = "/api/settings/storage/clickhouse/retention/run",
    tag = "settings",
    responses(
        (status = 200, description = "Retention job completed", body = serde_json::Value),
        (status = 400, description = "ClickHouse not enabled", body = ErrorResponse),
        (status = 403, description = "Missing permission", body = ErrorResponse),
        (status = 500, description = "Internal error", body = ErrorResponse)
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn run_clickhouse_retention_now(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Extension(client): Extension<ClientContext>,
) -> Result<Json<serde_json::Value>, ApiError> {
    ensure_permission(&auth, permissions::SETTINGS_RETENTION)?;

    let dual_pool = state.dual_pool();

    let settings =
        DualSystemSettings::new(dual_pool.postgres().clone(), dual_pool.clickhouse().clone());

    // OPTIMIZE TABLE FINAL + MATERIALIZE TTL can take minutes on large tables.
    // Run with a timeout to return a proper error instead of a GKE 502.
    const CH_RETENTION_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(300);

    let deleted = tokio::time::timeout(
        CH_RETENTION_TIMEOUT,
        settings.run_clickhouse_retention_now(),
    )
    .await
    .map_err(|_| {
        tracing::warn!(
            "ClickHouse retention run timed out after {}s",
            CH_RETENTION_TIMEOUT.as_secs()
        );
        ApiError::Timeout(
            "ClickHouse retention timed out — the operation is still running server-side"
                .to_string(),
        )
    })?
    .map_err(ApiError::from)?;

    tracing::info!(
        "ClickHouse retention run completed, {} rows deleted",
        deleted
    );

    state.emit_audit(
        AuditEvent::builder(AuditSource::Settings, CH_RETENTION_RUN_TRIGGERED)
            .actor(Some(auth.user_id()), None)
            .api_key(auth.api_key_id, auth.api_key_name.clone())
            .resource("settings", None, Some("clickhouse_retention".to_string()))
            .client_context(&client)
            .build(),
    );

    Ok(Json(serde_json::json!({
        "success": true,
        "rows_deleted": deleted
    })))
}
