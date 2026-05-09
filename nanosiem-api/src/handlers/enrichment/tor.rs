// SPDX-License-Identifier: AGPL-3.0-or-later

//! TOR Exit Nodes enrichment handlers

use axum::{extract::State, http::StatusCode, Extension, Json};
use nanosiem_core::audit::{
    AuditEvent, AuditSource, ClientContext, ENRICHMENT_CONFIGURED, ENRICHMENT_SYNCED,
};
use nanosiem_core::auth::permissions;

use super::is_sync_in_progress;
use super::types::*;
use super::AuditExt;
use crate::middleware::{check_permission, AuthContext};
use crate::{error::ApiError, state::AppState};

/// Configure TOR Exit Nodes enrichment source
#[utoipa::path(
    post,
    path = "/api/enrichment/tor/configure",
    tag = "enrichment",
    security(
        ("bearer_auth" = []),
        ("api_key" = [])
    ),
    request_body = ConfigureTorRequest,
    responses(
        (status = 200, description = "TOR Exit Nodes configured successfully", body = serde_json::Value),
        (status = 403, description = "Forbidden - missing permission"),
        (status = 404, description = "Source not found"),
    )
)]
pub async fn configure_tor_exit_nodes(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Extension(client): Extension<ClientContext>,
    Json(request): Json<ConfigureTorRequest>,
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
        .find(|s| s.id == "tor_exit_nodes")
        .ok_or_else(|| ApiError::NotFound("TOR Exit Nodes source not found".to_string()))?;

    // Merge new config
    let mut config = source.config.clone();
    if let Some(interval) = request.sync_interval_hours {
        config["sync_interval_hours"] = serde_json::json!(interval);
    }
    if let Some(ttl) = request.ttl_days {
        config["ttl_days"] = serde_json::json!(ttl);
    }
    if let Some(confidence) = request.confidence_level {
        config["confidence_level"] = serde_json::json!(confidence);
    }
    if let Some(auto_sync) = request.auto_sync_enabled {
        config["auto_sync_enabled"] = serde_json::json!(auto_sync);
    }

    // Save to database
    enrichment
        .repository()
        .update_source_config("tor_exit_nodes", config)
        .await
        .map_err(|e| ApiError::InternalError(format!("Failed to save config: {}", e)))?;

    state.emit_audit(
        AuditEvent::builder(AuditSource::Enrichment, ENRICHMENT_CONFIGURED)
            .actor(Some(auth.user_id()), None)
            .api_key(auth.api_key_id, auth.api_key_name.clone())
            .resource("enrichment", None, Some("tor_exit_nodes".to_string()))
            .client_context(&client)
            .build(),
    );

    Ok(Json(serde_json::json!({
        "success": true,
        "message": "TOR Exit Nodes configured. Run sync to load IOC data."
    })))
}

/// Sync TOR Exit Nodes data from Onionoo API (async - returns 202 Accepted)
///
/// This endpoint spawns a background task to perform the sync and returns immediately.
/// The client should poll `/api/enrichment/sources` to check sync status.
#[utoipa::path(
    post,
    path = "/api/enrichment/tor/sync",
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
pub async fn sync_tor_exit_nodes(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Extension(client): Extension<ClientContext>,
) -> Result<(StatusCode, Json<AsyncSyncResponse>), ApiError> {
    check_permission(&auth, permissions::ENRICHMENTS_CONFIGURE).map_err(|_| {
        ApiError::Forbidden("Missing permission: enrichments:configure".to_string())
    })?;

    const SOURCE_ID: &str = "tor_exit_nodes";

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
        match enrichment_guard.sync_tor_exit_nodes().await {
            Ok(result) => {
                if result.success {
                    tracing::info!(
                        source_id = SOURCE_ID,
                        records_loaded = result.records_loaded,
                        duration_ms = result.duration_ms,
                        "TOR exit nodes sync completed successfully"
                    );
                    if let Some(ref dp) = dual_pool {
                        if let Err(e) = dp
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
                        "TOR exit nodes sync completed with errors"
                    );
                }
            }
            Err(e) => {
                tracing::error!(
                    source_id = SOURCE_ID,
                    error = %e,
                    "TOR exit nodes sync failed"
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
            .resource("enrichment", None, Some("tor_exit_nodes".to_string()))
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
