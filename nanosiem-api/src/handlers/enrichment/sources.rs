// SPDX-License-Identifier: AGPL-3.0-or-later

//! Enrichment source management handlers

use axum::{
    extract::{Path, State},
    Extension, Json,
};
use nanosiem_core::audit::{
    AuditEvent, AuditSource, ClientContext, AUTO_SYNC_CONFIGURED, ENRICHMENT_DISABLED,
    ENRICHMENT_ENABLED,
};
use nanosiem_core::auth::permissions;

use super::sanitize_config;
use super::types::*;
use super::AuditExt;
use crate::middleware::{check_permission, AuthContext};
use crate::{error::ApiError, state::AppState};

/// List all enrichment sources
#[utoipa::path(
    get,
    path = "/api/enrichment/sources",
    tag = "enrichment",
    security(
        ("bearer_auth" = []),
        ("api_key" = [])
    ),
    responses(
        (status = 200, description = "List of enrichment sources", body = EnrichmentSourcesResponse),
        (status = 403, description = "Forbidden - missing permission"),
    )
)]
pub async fn list_enrichment_sources(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
) -> Result<Json<EnrichmentSourcesResponse>, ApiError> {
    check_permission(&auth, permissions::ENRICHMENTS_VIEW)
        .map_err(|_| ApiError::Forbidden("Missing permission: enrichments:view".to_string()))?;

    let enrichment = state.enrichment.read().await;
    let sources = enrichment
        .list_sources()
        .await
        .map_err(|e| ApiError::InternalError(format!("Failed to list sources: {}", e)))?;

    let sources = sources
        .into_iter()
        .map(|s| EnrichmentSourceInfo {
            id: s.id,
            name: s.name,
            source_type: s.source_type,
            description: s.description,
            download_url: s.download_url,
            enabled: s.enabled,
            last_sync_at: s.last_sync_at.map(|t| t.to_rfc3339()),
            last_sync_status: s.last_sync_status,
            record_count: s.record_count,
            config: sanitize_config(s.config),
        })
        .collect();

    Ok(Json(EnrichmentSourcesResponse { sources }))
}

/// Enable an enrichment source
#[utoipa::path(
    post,
    path = "/api/enrichment/sources/{id}/enable",
    tag = "enrichment",
    security(
        ("bearer_auth" = []),
        ("api_key" = [])
    ),
    params(
        ("id" = String, Path, description = "Source ID")
    ),
    responses(
        (status = 200, description = "Source enabled successfully", body = serde_json::Value),
        (status = 403, description = "Forbidden - missing permission"),
        (status = 404, description = "Source not found"),
    )
)]
pub async fn enable_enrichment_source(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Extension(client): Extension<ClientContext>,
    Path(source_id): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    check_permission(&auth, permissions::ENRICHMENTS_CONFIGURE).map_err(|_| {
        ApiError::Forbidden("Missing permission: enrichments:configure".to_string())
    })?;

    let enrichment = state.enrichment.read().await;
    enrichment
        .repository()
        .set_source_enabled(&source_id, true)
        .await
        .map_err(|e| ApiError::NotFound(format!("Source not found: {}", e)))?;

    state.emit_audit(
        AuditEvent::builder(AuditSource::Enrichment, ENRICHMENT_ENABLED)
            .actor(Some(auth.user_id()), None)
            .api_key(auth.api_key_id, auth.api_key_name.clone())
            .resource("enrichment", None, Some(source_id.clone()))
            .client_context(&client)
            .build(),
    );

    Ok(Json(serde_json::json!({
        "success": true,
        "message": format!("Source {} enabled", source_id)
    })))
}

/// Disable an enrichment source
#[utoipa::path(
    post,
    path = "/api/enrichment/sources/{id}/disable",
    tag = "enrichment",
    security(
        ("bearer_auth" = []),
        ("api_key" = [])
    ),
    params(
        ("id" = String, Path, description = "Source ID")
    ),
    responses(
        (status = 200, description = "Source disabled successfully", body = serde_json::Value),
        (status = 403, description = "Forbidden - missing permission"),
        (status = 404, description = "Source not found"),
    )
)]
pub async fn disable_enrichment_source(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Extension(client): Extension<ClientContext>,
    Path(source_id): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    check_permission(&auth, permissions::ENRICHMENTS_CONFIGURE).map_err(|_| {
        ApiError::Forbidden("Missing permission: enrichments:configure".to_string())
    })?;

    let enrichment = state.enrichment.read().await;
    enrichment
        .repository()
        .set_source_enabled(&source_id, false)
        .await
        .map_err(|e| ApiError::NotFound(format!("Source not found: {}", e)))?;

    state.emit_audit(
        AuditEvent::builder(AuditSource::Enrichment, ENRICHMENT_DISABLED)
            .actor(Some(auth.user_id()), None)
            .api_key(auth.api_key_id, auth.api_key_name.clone())
            .resource("enrichment", None, Some(source_id.clone()))
            .client_context(&client)
            .build(),
    );

    Ok(Json(serde_json::json!({
        "success": true,
        "message": format!("Source {} disabled", source_id)
    })))
}

/// Get enrichment statistics
#[utoipa::path(
    get,
    path = "/api/enrichment/stats",
    tag = "enrichment",
    security(
        ("bearer_auth" = []),
        ("api_key" = [])
    ),
    responses(
        (status = 200, description = "Enrichment statistics", body = EnrichmentStatsResponse),
        (status = 403, description = "Forbidden - missing permission"),
    )
)]
pub async fn get_enrichment_stats(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
) -> Result<Json<EnrichmentStatsResponse>, ApiError> {
    check_permission(&auth, permissions::ENRICHMENTS_VIEW)
        .map_err(|_| ApiError::Forbidden("Missing permission: enrichments:view".to_string()))?;

    let enrichment = state.enrichment.read().await;
    let stats = enrichment
        .get_stats()
        .await
        .map_err(|e| ApiError::InternalError(format!("Failed to get stats: {}", e)))?;

    Ok(Json(EnrichmentStatsResponse {
        enabled_sources: stats.enabled_sources,
        total_ip_records: stats.total_ip_records,
    }))
}

/// Get auto-sync configuration for a source
#[utoipa::path(
    get,
    path = "/api/enrichment/sources/{id}/auto-sync",
    tag = "enrichment",
    security(
        ("bearer_auth" = []),
        ("api_key" = [])
    ),
    params(
        ("id" = String, Path, description = "Source ID")
    ),
    responses(
        (status = 200, description = "Auto-sync configuration", body = AutoSyncConfigResponse),
        (status = 403, description = "Forbidden - missing permission"),
        (status = 404, description = "Source not found"),
    )
)]
pub async fn get_auto_sync_config(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Path(source_id): Path<String>,
) -> Result<Json<AutoSyncConfigResponse>, ApiError> {
    check_permission(&auth, permissions::ENRICHMENTS_VIEW)
        .map_err(|_| ApiError::Forbidden("Missing permission: enrichments:view".to_string()))?;

    let enrichment = state.enrichment.read().await;
    let sources = enrichment
        .list_sources()
        .await
        .map_err(|e| ApiError::InternalError(format!("Failed to list sources: {}", e)))?;

    let source = sources
        .into_iter()
        .find(|s| s.id == source_id)
        .ok_or_else(|| ApiError::NotFound(format!("Source not found: {}", source_id)))?;

    let auto_sync_enabled = source
        .config
        .get("auto_sync_enabled")
        .and_then(|v| v.as_bool())
        .unwrap_or(true);

    let sync_interval_hours = source
        .config
        .get("sync_interval_hours")
        .and_then(|v| v.as_u64())
        .unwrap_or(24);

    let next_sync_at = nanosiem_core::enrichment::scheduler::get_next_sync_time(&source, 24)
        .map(|t| t.to_rfc3339());

    Ok(Json(AutoSyncConfigResponse {
        source_id,
        auto_sync_enabled,
        sync_interval_hours,
        next_sync_at,
    }))
}

/// Configure auto-sync settings for a source
#[utoipa::path(
    post,
    path = "/api/enrichment/sources/{id}/auto-sync",
    tag = "enrichment",
    security(
        ("bearer_auth" = []),
        ("api_key" = [])
    ),
    params(
        ("id" = String, Path, description = "Source ID")
    ),
    request_body = AutoSyncConfigRequest,
    responses(
        (status = 200, description = "Auto-sync configured successfully", body = AutoSyncConfigResponse),
        (status = 403, description = "Forbidden - missing permission"),
        (status = 404, description = "Source not found"),
    )
)]
pub async fn configure_auto_sync(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Extension(client): Extension<ClientContext>,
    Path(source_id): Path<String>,
    Json(request): Json<AutoSyncConfigRequest>,
) -> Result<Json<AutoSyncConfigResponse>, ApiError> {
    check_permission(&auth, permissions::ENRICHMENTS_CONFIGURE).map_err(|_| {
        ApiError::Forbidden("Missing permission: enrichments:configure".to_string())
    })?;

    let enrichment = state.enrichment.read().await;

    // Get current source to merge config
    let sources = enrichment
        .list_sources()
        .await
        .map_err(|e| ApiError::InternalError(format!("Failed to list sources: {}", e)))?;

    let source = sources
        .into_iter()
        .find(|s| s.id == source_id)
        .ok_or_else(|| ApiError::NotFound(format!("Source not found: {}", source_id)))?;

    // Merge new settings into existing config
    let mut config = source.config.clone();
    config["auto_sync_enabled"] = serde_json::json!(request.enabled);
    config["sync_interval_hours"] = serde_json::json!(request.interval_hours);

    // Save to database
    enrichment
        .repository()
        .update_source_config(&source_id, config)
        .await
        .map_err(|e| ApiError::InternalError(format!("Failed to save config: {}", e)))?;

    // Calculate next sync time
    let next_sync_at = if request.enabled && source.enabled {
        source
            .last_sync_at
            .map(|t| (t + chrono::Duration::hours(request.interval_hours as i64)).to_rfc3339())
            .or_else(|| Some(chrono::Utc::now().to_rfc3339()))
    } else {
        None
    };

    state.emit_audit(
        AuditEvent::builder(AuditSource::Enrichment, AUTO_SYNC_CONFIGURED)
            .actor(Some(auth.user_id()), None)
            .api_key(auth.api_key_id, auth.api_key_name.clone())
            .resource("enrichment", None, Some(source_id.clone()))
            .client_context(&client)
            .build(),
    );

    Ok(Json(AutoSyncConfigResponse {
        source_id,
        auto_sync_enabled: request.enabled,
        sync_interval_hours: request.interval_hours,
        next_sync_at,
    }))
}
