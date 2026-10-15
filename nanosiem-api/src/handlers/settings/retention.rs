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
use std::path::Path;
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

/// Storage statistics for the tenant-pinned Iceberg event snapshot. These are
/// read from the same immutable coordinator manifest used for schema and
/// sidecar fencing, never inferred from the compatibility ClickHouse service.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct LakeStorageStatsResponse {
    pub total_size_bytes: u64,
    pub total_size_pretty: String,
    pub row_count: u64,
    pub object_count: u64,
    pub index_size_bytes: u64,
    pub index_size_pretty: String,
    pub index_overhead_percent: f64,
    pub file_format: String,
    pub table_format: String,
    pub manifest_modified_at: Option<String>,
}

#[derive(Debug, Deserialize)]
struct LakeStorageManifest {
    #[serde(default)]
    source_bytes: u64,
    #[serde(default)]
    event_rows: u64,
    #[serde(default)]
    index_bytes: u64,
    #[serde(default)]
    objects: Vec<serde_json::Value>,
}

const LAKE_WORKER_CONFIG_ENV: &str = "NANO_LAKE_WORKER_CONFIG";

fn active_lake_storage_manifest(worker_config: &Path) -> Result<std::path::PathBuf, ApiError> {
    let raw = std::fs::read_to_string(worker_config).map_err(|error| {
        ApiError::InternalError(format!("failed to read active lake worker config: {error}"))
    })?;
    let config: serde_json::Value = serde_json::from_str(&raw).map_err(|error| {
        ApiError::InternalError(format!("invalid active lake worker config: {error}"))
    })?;
    let path = config
        .pointer("/tenant/source_manifest/path")
        .and_then(serde_json::Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| {
            ApiError::InternalError(
                "active lake worker config has no tenant source manifest".to_string(),
            )
        })?;
    Ok(std::path::PathBuf::from(path))
}

fn pretty_bytes(bytes: u64) -> String {
    const KIB: f64 = 1024.0;
    const MIB: f64 = KIB * 1024.0;
    const GIB: f64 = MIB * 1024.0;
    const TIB: f64 = GIB * 1024.0;
    let bytes = bytes as f64;
    if bytes >= TIB {
        format!("{:.2} TiB", bytes / TIB)
    } else if bytes >= GIB {
        format!("{:.2} GiB", bytes / GIB)
    } else if bytes >= MIB {
        format!("{:.2} MiB", bytes / MIB)
    } else if bytes >= KIB {
        format!("{:.2} KiB", bytes / KIB)
    } else {
        format!("{} B", bytes as u64)
    }
}

pub(super) fn lake_storage_stats_from_manifest(
    path: &Path,
) -> Result<LakeStorageStatsResponse, ApiError> {
    let raw = std::fs::read_to_string(path).map_err(|error| {
        ApiError::InternalError(format!("failed to read lake storage manifest: {error}"))
    })?;
    let manifest: LakeStorageManifest = serde_json::from_str(&raw).map_err(|error| {
        ApiError::InternalError(format!("invalid lake storage manifest: {error}"))
    })?;
    let modified_at = std::fs::metadata(path)
        .and_then(|metadata| metadata.modified())
        .ok()
        .map(chrono::DateTime::<chrono::Utc>::from)
        .map(|timestamp| timestamp.to_rfc3339());
    let overhead = if manifest.source_bytes == 0 {
        0.0
    } else {
        manifest.index_bytes as f64 * 100.0 / manifest.source_bytes as f64
    };
    Ok(LakeStorageStatsResponse {
        total_size_bytes: manifest.source_bytes,
        total_size_pretty: pretty_bytes(manifest.source_bytes),
        row_count: manifest.event_rows,
        object_count: manifest.objects.len() as u64,
        index_size_bytes: manifest.index_bytes,
        index_size_pretty: pretty_bytes(manifest.index_bytes),
        index_overhead_percent: overhead,
        file_format: "Parquet".to_string(),
        table_format: "Iceberg v2".to_string(),
        manifest_modified_at: modified_at,
    })
}

fn non_blank_env(name: &str) -> Option<String> {
    std::env::var(name)
        .ok()
        .filter(|value| !value.trim().is_empty())
}

pub(super) fn lake_storage_stats_from_env() -> Result<LakeStorageStatsResponse, ApiError> {
    lake_storage_stats_from_paths(
        non_blank_env(LAKE_WORKER_CONFIG_ENV).as_deref(),
        non_blank_env(nanosiem_core::schema::LAKE_SCHEMA_MANIFEST_ENV).as_deref(),
    )
}

/// Stats from the gen1 lake manifest: the worker config's active manifest when
/// a worker config is configured, else the explicit schema manifest.
fn lake_storage_stats_from_paths(
    worker_config: Option<&str>,
    schema_manifest: Option<&str>,
) -> Result<LakeStorageStatsResponse, ApiError> {
    if let Some(worker_config) = worker_config {
        let manifest = active_lake_storage_manifest(Path::new(worker_config))?;
        return lake_storage_stats_from_manifest(&manifest);
    }
    let path = schema_manifest.ok_or_else(|| {
        ApiError::InternalError(
            "lake worker config and schema manifest are not configured".to_string(),
        )
    })?;
    lake_storage_stats_from_manifest(Path::new(path))
}

/// NAN-3492: lake manifest stats are optional telemetry, not a precondition of
/// the storage pages. A lean trusted-local install has no gen1 worker config or
/// source manifest at all, so a missing/unreadable manifest degrades to `None`
/// (logged) instead of failing the whole response with a 500.
pub(super) fn lake_storage_stats_or_none(
    stats: Result<LakeStorageStatsResponse, ApiError>,
) -> Option<LakeStorageStatsResponse> {
    match stats {
        Ok(stats) => Some(stats),
        Err(error) => {
            tracing::warn!(
                %error,
                "lake storage manifest stats unavailable; reporting no lake stats"
            );
            None
        }
    }
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
    /// Active log storage backend (`clickhouse` or `iceberg`).
    pub log_backend: String,
    /// Whether ClickHouse is enabled for log storage
    pub clickhouse_enabled: bool,
    /// PostgreSQL storage stats (metadata)
    pub postgres: Option<StorageStatsResponse>,
    /// ClickHouse storage stats (logs)
    pub clickhouse: Option<ClickHouseStorageStatsResponse>,
    /// Iceberg/Parquet snapshot stats (only in primary-lake mode).
    pub lake: Option<LakeStorageStatsResponse>,
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
    #[cfg(feature = "enterprise")]
    super::reject_enterprise_shared_storage_settings(&state)?;

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
    #[cfg(feature = "enterprise")]
    super::reject_enterprise_shared_storage_settings(&state)?;

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
    #[cfg(feature = "enterprise")]
    super::reject_enterprise_shared_storage_settings(&state)?;

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
    #[cfg(feature = "enterprise")]
    super::reject_enterprise_shared_storage_settings(&state)?;

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
    #[cfg(feature = "enterprise")]
    super::reject_enterprise_shared_storage_settings(&state)?;

    if state.search_service.backend() == nanosiem_core::SearchBackend::Lake {
        let postgres = SystemSettings::new(state.pool.clone())
            .get_storage_stats()
            .await
            .ok()
            .map(StorageStatsResponse::from);
        return Ok(Json(StorageOverviewResponse {
            log_backend: "iceberg".to_string(),
            clickhouse_enabled: false,
            postgres,
            clickhouse: None,
            lake: lake_storage_stats_or_none(lake_storage_stats_from_env()),
            disk_pressure: None,
        }));
    }

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
        log_backend: "clickhouse".to_string(),
        clickhouse_enabled: true,
        postgres: postgres_stats,
        clickhouse: clickhouse_stats,
        lake: None,
        disk_pressure,
    }))
}

/// Message for ClickHouse storage endpoints on a lake (Iceberg) backend.
pub(crate) const CLICKHOUSE_STORAGE_NOT_APPLICABLE: &str =
    "ClickHouse storage settings are not applicable on the lake backend; use GET /api/settings/storage/overview";

/// Refuse ClickHouse-specific storage endpoints when logs live in the lake.
///
/// On `NANO_LOG_QUERY_BACKEND=lake` the ClickHouse pool is an inert
/// compatibility client: querying `system.parts` through it surfaces as a 500
/// "storage error" (NAN-3378). The storage overview already reports
/// `clickhouse_enabled: false` there, so these endpoints answer with a clean
/// 404 instead of touching ClickHouse.
fn ensure_clickhouse_storage_applicable(
    backend: nanosiem_core::SearchBackend,
) -> Result<(), ApiError> {
    if backend == nanosiem_core::SearchBackend::Lake {
        return Err(ApiError::NotFound(
            CLICKHOUSE_STORAGE_NOT_APPLICABLE.to_string(),
        ));
    }
    Ok(())
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
        (status = 404, description = "Not applicable: logs are stored in the lake backend", body = ErrorResponse),
        (status = 500, description = "Internal error", body = ErrorResponse)
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn get_clickhouse_storage_stats(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
) -> Result<Json<ClickHouseStorageStatsResponse>, ApiError> {
    ensure_permission(&auth, permissions::SETTINGS_VIEW)?;
    #[cfg(feature = "enterprise")]
    super::reject_enterprise_shared_storage_settings(&state)?;
    ensure_clickhouse_storage_applicable(state.search_service.backend())?;

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
        (status = 404, description = "Not applicable: logs are stored in the lake backend", body = ErrorResponse),
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
    #[cfg(feature = "enterprise")]
    super::reject_enterprise_shared_storage_settings(&state)?;
    ensure_clickhouse_storage_applicable(state.search_service.backend())?;

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
        (status = 404, description = "Not applicable: logs are stored in the lake backend", body = ErrorResponse),
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
    #[cfg(feature = "enterprise")]
    super::reject_enterprise_shared_storage_settings(&state)?;
    ensure_clickhouse_storage_applicable(state.search_service.backend())?;

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clickhouse_storage_endpoints_are_a_clean_404_on_lake() {
        use axum::response::IntoResponse;

        let err = ensure_clickhouse_storage_applicable(nanosiem_core::SearchBackend::Lake)
            .expect_err("lake backend must refuse ClickHouse storage endpoints");
        assert_eq!(err.code(), "NOT_FOUND");
        assert!(err
            .to_string()
            .contains("not applicable on the lake backend"));
        assert_eq!(
            err.into_response().status(),
            axum::http::StatusCode::NOT_FOUND
        );
    }

    #[test]
    fn clickhouse_storage_endpoints_proceed_on_clickhouse() {
        assert!(
            ensure_clickhouse_storage_applicable(nanosiem_core::SearchBackend::ClickHouse).is_ok()
        );
    }

    #[test]
    fn active_worker_config_selects_the_promoted_storage_manifest() {
        let directory = tempfile::tempdir().expect("temp directory");
        let stale = directory.path().join("stale.json");
        let active = directory.path().join("active.json");
        let worker = directory.path().join("worker.json");
        std::fs::write(
            &stale,
            r#"{"source_bytes":10,"event_rows":1,"index_bytes":2,"objects":[{}]}"#,
        )
        .expect("stale manifest");
        std::fs::write(
            &active,
            r#"{"source_bytes":1000,"event_rows":2313337,"index_bytes":250,"objects":[{},{},{}]}"#,
        )
        .expect("active manifest");
        std::fs::write(
            &worker,
            serde_json::json!({
                "tenant": {
                    "source_manifest": {
                        "path": active,
                        "sha256": "0".repeat(64),
                    }
                }
            })
            .to_string(),
        )
        .expect("worker config");

        let selected = active_lake_storage_manifest(&worker).expect("active path");
        let stats = lake_storage_stats_from_manifest(&selected).expect("active stats");
        assert_eq!(stats.row_count, 2_313_337);
        assert_eq!(stats.object_count, 3);
        assert_eq!(stats.total_size_bytes, 1_000);
        assert_eq!(stats.index_size_bytes, 250);
    }

    #[test]
    fn malformed_worker_config_does_not_fall_back_to_stale_telemetry() {
        let directory = tempfile::tempdir().expect("temp directory");
        let worker = directory.path().join("worker.json");
        std::fs::write(&worker, r#"{"tenant":{}}"#).expect("worker config");

        let error = active_lake_storage_manifest(&worker).expect_err("missing manifest");
        assert!(error
            .to_string()
            .contains("active lake worker config has no tenant source manifest"));
    }

    #[test]
    fn missing_worker_config_degrades_the_overview_to_no_lake_stats() {
        // NAN-3492: the lean compose used to point at a gen1 worker config that
        // never exists there; the overview must render without lake stats.
        let directory = tempfile::tempdir().expect("temp directory");
        let missing = directory.path().join("worker.json");
        let missing = missing.to_str().expect("utf-8 path");

        let error = lake_storage_stats_from_paths(Some(missing), None)
            .expect_err("missing worker config is an error at the source");
        assert!(error
            .to_string()
            .contains("failed to read active lake worker config"));
        assert!(lake_storage_stats_or_none(Err(error)).is_none());
    }

    #[test]
    fn unconfigured_lake_manifest_degrades_the_overview_to_no_lake_stats() {
        let result = lake_storage_stats_from_paths(None, None);
        assert!(result.is_err());
        assert!(lake_storage_stats_or_none(result).is_none());
    }

    #[test]
    fn readable_schema_manifest_still_reports_lake_stats() {
        let directory = tempfile::tempdir().expect("temp directory");
        let manifest = directory.path().join("manifest.json");
        std::fs::write(
            &manifest,
            r#"{"source_bytes":2048,"event_rows":7,"index_bytes":0,"objects":[{}]}"#,
        )
        .expect("manifest");

        let stats = lake_storage_stats_or_none(lake_storage_stats_from_paths(
            None,
            Some(manifest.to_str().expect("utf-8 path")),
        ))
        .expect("stats");
        assert_eq!(stats.total_size_bytes, 2048);
        assert_eq!(stats.row_count, 7);
        assert_eq!(stats.object_count, 1);
    }
}
