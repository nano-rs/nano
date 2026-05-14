// SPDX-License-Identifier: AGPL-3.0-or-later

//! ThreatFox IOC enrichment handlers

use axum::{
    extract::{Path, State},
    http::StatusCode,
    Extension, Json,
};
use nanosiem_core::audit::{
    AuditEvent, AuditSource, ClientContext, ENRICHMENT_CONFIGURED, ENRICHMENT_SYNCED,
};
use nanosiem_core::auth::permissions;

use super::is_sync_in_progress;
use super::types::*;
use super::AuditExt;
use crate::middleware::{check_permission, AuthContext};
use crate::{error::ApiError, state::AppState};

/// Configure ThreatFox enrichment source
#[utoipa::path(
    post,
    path = "/api/enrichment/threatfox/configure",
    tag = "enrichment",
    security(
        ("bearer_auth" = []),
        ("api_key" = [])
    ),
    request_body = ConfigureThreatFoxRequest,
    responses(
        (status = 200, description = "ThreatFox configured successfully", body = serde_json::Value),
        (status = 403, description = "Forbidden - missing permission"),
        (status = 404, description = "Source not found"),
    )
)]
pub async fn configure_threatfox(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Extension(client): Extension<ClientContext>,
    Json(request): Json<ConfigureThreatFoxRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    check_permission(&auth, permissions::ENRICHMENTS_CONFIGURE).map_err(|_| {
        ApiError::Forbidden("Missing permission: enrichments:configure".to_string())
    })?;

    let enrichment = state.enrichment.read().await;

    // Get current source config
    let sources = enrichment
        .list_sources()
        .await
        .map_err(|e| ApiError::InternalError(format!("Failed to list sources: {}", e)))?;

    let source = sources
        .into_iter()
        .find(|s| s.id == "threatfox")
        .ok_or_else(|| ApiError::NotFound("ThreatFox source not found".to_string()))?;

    // Merge new config
    let mut config = source.config.clone();
    if let Some(api_key) = request.api_key {
        config["api_key"] = serde_json::json!(api_key);
    }
    if let Some(interval) = request.sync_interval_hours {
        config["sync_interval_hours"] = serde_json::json!(interval);
    }
    if let Some(ttl) = request.ttl_days {
        config["ttl_days"] = serde_json::json!(ttl);
    }
    if let Some(auto_sync) = request.auto_sync_enabled {
        config["auto_sync_enabled"] = serde_json::json!(auto_sync);
    }

    // Save to database
    enrichment
        .repository()
        .update_source_config("threatfox", config)
        .await
        .map_err(|e| ApiError::InternalError(format!("Failed to save config: {}", e)))?;

    state.emit_audit(
        AuditEvent::builder(AuditSource::Enrichment, ENRICHMENT_CONFIGURED)
            .actor(Some(auth.user_id()), None)
            .api_key(auth.api_key_id, auth.api_key_name.clone())
            .resource("enrichment", None, Some("threatfox".to_string()))
            .client_context(&client)
            .build(),
    );

    Ok(Json(serde_json::json!({
        "success": true,
        "message": "ThreatFox configured. Run sync to load IOC data."
    })))
}

/// Sync ThreatFox IOC data (async - returns 202 Accepted)
///
/// This endpoint spawns a background task to perform the sync and returns immediately.
/// The client should poll `/api/enrichment/sources` to check sync status.
#[utoipa::path(
    post,
    path = "/api/enrichment/threatfox/sync",
    tag = "enrichment",
    security(
        ("bearer_auth" = []),
        ("api_key" = [])
    ),
    responses(
        (status = 202, description = "Sync started in background", body = AsyncSyncResponse),
        (status = 409, description = "Sync already in progress", body = AsyncSyncResponse),
        (status = 403, description = "Forbidden - missing permission"),
    )
)]
pub async fn sync_threatfox(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Extension(client): Extension<ClientContext>,
) -> Result<(StatusCode, Json<AsyncSyncResponse>), ApiError> {
    check_permission(&auth, permissions::ENRICHMENTS_CONFIGURE).map_err(|_| {
        ApiError::Forbidden("Missing permission: enrichments:configure".to_string())
    })?;

    const SOURCE_ID: &str = "threatfox";

    // Check if sync is already in progress
    {
        let enrichment = state.enrichment.read().await;
        let (in_progress, updated_at) = is_sync_in_progress(&enrichment, SOURCE_ID).await?;
        if in_progress {
            let started = updated_at.map(|t| t.to_rfc3339()).unwrap_or_default();
            return Ok((
                StatusCode::CONFLICT,
                Json(AsyncSyncResponse {
                    source_id: SOURCE_ID.to_string(),
                    status: "in_progress".to_string(),
                    message: format!("Sync already in progress (started {}). Poll /api/enrichment/sources for status.", started),
                }),
            ));
        }
    }

    // Spawn background task
    let enrichment = state.enrichment.clone();
    let dual_pool = state.dual_pool.clone();
    let handle = tokio::spawn(async move {
        let enrichment_guard = enrichment.read().await;
        match enrichment_guard.sync_threatfox().await {
            Ok(result) => {
                if result.success {
                    tracing::info!(
                        source_id = SOURCE_ID,
                        records_loaded = result.records_loaded,
                        duration_ms = result.duration_ms,
                        "ThreatFox sync completed successfully"
                    );
                    {
                        if let Err(e) = dual_pool
                            .clickhouse()
                            .query("SYSTEM RELOAD DICTIONARY nanosiem.ioc_enrichment_dict")
                            .execute()
                            .await
                        {
                            tracing::warn!("Failed to reload ioc_enrichment_dict: {}", e);
                        } else {
                            tracing::info!("Reloaded ioc_enrichment_dict after sync");
                        }
                    }
                } else {
                    tracing::warn!(
                        source_id = SOURCE_ID,
                        error = ?result.error,
                        "ThreatFox sync completed with errors"
                    );
                }
            }
            Err(e) => {
                tracing::error!(
                    source_id = SOURCE_ID,
                    error = %e,
                    "ThreatFox sync failed"
                );
            }
        }
    });

    // Register for graceful shutdown
    state.add_task_handle(handle).await;

    state.emit_audit(
        AuditEvent::builder(AuditSource::Enrichment, ENRICHMENT_SYNCED)
            .actor(Some(auth.user_id()), None)
            .api_key(auth.api_key_id, auth.api_key_name.clone())
            .resource("enrichment", None, Some("threatfox".to_string()))
            .client_context(&client)
            .build(),
    );

    Ok((
        StatusCode::ACCEPTED,
        Json(AsyncSyncResponse {
            source_id: SOURCE_ID.to_string(),
            status: "in_progress".to_string(),
            message: "Sync started. Poll /api/enrichment/sources for status.".to_string(),
        }),
    ))
}

/// Lookup IOC enrichment for a value (IP, domain, or hash)
#[utoipa::path(
    get,
    path = "/api/enrichment/ioc/lookup/{value}",
    tag = "enrichment",
    security(
        ("bearer_auth" = []),
        ("api_key" = [])
    ),
    params(
        ("value" = String, Path, description = "IOC value to lookup (IP, domain, or hash)")
    ),
    responses(
        (status = 200, description = "IOC enrichment data", body = IocLookupResponse),
        (status = 403, description = "Forbidden - missing permission"),
    )
)]
pub async fn lookup_ioc(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Path(value): Path<String>,
) -> Result<Json<IocLookupResponse>, ApiError> {
    check_permission(&auth, permissions::ENRICHMENTS_VIEW)
        .map_err(|_| ApiError::Forbidden("Missing permission: enrichments:view".to_string()))?;

    let enrichment = state.enrichment.read().await;
    let result = enrichment
        .lookup_ioc(&value)
        .await
        .map_err(|e| ApiError::InternalError(format!("Lookup failed: {}", e)))?;

    match result {
        Some(r) => Ok(Json(IocLookupResponse {
            value,
            found: true,
            ioc_type: r.ioc_type,
            source_id: r.source_id,
            threat_type: r.threat_type,
            malware: r.malware,
            confidence_level: r.confidence_level,
            tags: r.tags,
        })),
        None => Ok(Json(IocLookupResponse {
            value,
            found: false,
            ioc_type: None,
            source_id: None,
            threat_type: None,
            malware: None,
            confidence_level: None,
            tags: vec![],
        })),
    }
}

/// Get IOC statistics for a source
#[utoipa::path(
    get,
    path = "/api/enrichment/ioc/stats/{source_id}",
    tag = "enrichment",
    security(
        ("bearer_auth" = []),
        ("api_key" = [])
    ),
    params(
        ("source_id" = String, Path, description = "Source ID")
    ),
    responses(
        (status = 200, description = "IOC statistics", body = IocStatsResponse),
        (status = 403, description = "Forbidden - missing permission"),
    )
)]
pub async fn get_ioc_stats(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Path(source_id): Path<String>,
) -> Result<Json<IocStatsResponse>, ApiError> {
    check_permission(&auth, permissions::ENRICHMENTS_VIEW)
        .map_err(|_| ApiError::Forbidden("Missing permission: enrichments:view".to_string()))?;

    let enrichment = state.enrichment.read().await;
    let stats = enrichment
        .get_ioc_stats(&source_id)
        .await
        .map_err(|e| ApiError::InternalError(format!("Failed to get stats: {}", e)))?;

    Ok(Json(IocStatsResponse {
        ip_count: stats.ip_count,
        domain_count: stats.domain_count,
        hash_count: stats.hash_count,
        url_count: stats.url_count,
        total: stats.total,
    }))
}
