// SPDX-License-Identifier: AGPL-3.0-or-later

//! IPinfo enrichment handlers

use axum::{
    extract::{Path, State},
    http::StatusCode,
    Extension, Json,
};
use nanosiem_core::audit::{
    AuditEvent, AuditSource, ClientContext, ENRICHMENT_CONFIGURED, ENRICHMENT_SYNCED,
};
use nanosiem_core::auth::permissions;

use super::types::*;
use super::AuditExt;
use super::{is_sync_in_progress, validate_external_url};
use crate::middleware::{check_permission, AuthContext};
use crate::{error::ApiError, state::AppState};

/// Configure IPinfo Lite enrichment source
#[utoipa::path(
    post,
    path = "/api/enrichment/ipinfo/configure",
    tag = "enrichment",
    security(
        ("bearer_auth" = []),
        ("api_key" = [])
    ),
    request_body = ConfigureEnrichmentRequest,
    responses(
        (status = 200, description = "IPinfo configured successfully", body = serde_json::Value),
        (status = 400, description = "Invalid URL or SSRF prevention"),
        (status = 403, description = "Forbidden - missing permission"),
    )
)]
pub async fn configure_ipinfo(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Extension(client): Extension<ClientContext>,
    Json(request): Json<ConfigureEnrichmentRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    check_permission(&auth, permissions::ENRICHMENTS_CONFIGURE).map_err(|_| {
        ApiError::Forbidden("Missing permission: enrichments:configure".to_string())
    })?;

    // Validate URL to prevent SSRF attacks (DNS-aware: rejects hostnames that
    // resolve to loopback / private / link-local / metadata addresses).
    validate_external_url(&request.download_url).await?;

    // Save URL to database for persistence
    let enrichment = state.enrichment.read().await;
    enrichment
        .repository()
        .update_source_url("ipinfo_lite", &request.download_url)
        .await
        .map_err(|e| ApiError::InternalError(format!("Failed to save URL: {}", e)))?;
    drop(enrichment);

    // Also update the in-memory service
    let mut enrichment = state.enrichment.write().await;
    enrichment.set_ipinfo_url(request.download_url);

    state.emit_audit(
        AuditEvent::builder(AuditSource::Enrichment, ENRICHMENT_CONFIGURED)
            .actor(Some(auth.user_id()), None)
            .api_key(auth.api_key_id, auth.api_key_name.clone())
            .resource("enrichment", None, Some("ipinfo".to_string()))
            .client_context(&client)
            .build(),
    );

    Ok(Json(serde_json::json!({
        "success": true,
        "message": "IPinfo Lite configured. Run sync to load data."
    })))
}

/// Sync IPinfo Lite data (async - returns 202 Accepted)
///
/// This endpoint spawns a background task to perform the sync and returns immediately.
/// The client should poll `/api/enrichment/sources` to check sync status.
#[utoipa::path(
    post,
    path = "/api/enrichment/ipinfo/sync",
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
pub async fn sync_ipinfo(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Extension(client): Extension<ClientContext>,
) -> Result<(StatusCode, Json<AsyncSyncResponse>), ApiError> {
    check_permission(&auth, permissions::ENRICHMENTS_CONFIGURE).map_err(|_| {
        ApiError::Forbidden("Missing permission: enrichments:configure".to_string())
    })?;

    const SOURCE_ID: &str = "ipinfo_lite";

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
        match enrichment_guard.sync_ipinfo_lite().await {
            Ok(result) => {
                if result.success {
                    tracing::info!(
                        source_id = SOURCE_ID,
                        records_loaded = result.records_loaded,
                        duration_ms = result.duration_ms,
                        "IPinfo Lite sync completed successfully"
                    );
                    // Reload ClickHouse dictionary so new enrichment data takes effect immediately
                    if let Some(ref dp) = dual_pool {
                        if let Err(e) = dp
                            .clickhouse()
                            .query("SYSTEM RELOAD DICTIONARY nanosiem.ip_enrichment_dict")
                            .execute()
                            .await
                        {
                            tracing::warn!("Failed to reload ip_enrichment_dict: {}", e);
                        } else {
                            tracing::info!("Reloaded ip_enrichment_dict after sync");
                        }
                    }
                } else {
                    tracing::warn!(
                        source_id = SOURCE_ID,
                        error = ?result.error,
                        "IPinfo Lite sync completed with errors"
                    );
                }
            }
            Err(e) => {
                tracing::error!(
                    source_id = SOURCE_ID,
                    error = %e,
                    "IPinfo Lite sync failed"
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
            .resource("enrichment", None, Some("ipinfo".to_string()))
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

/// Lookup enrichment for a specific IP
#[utoipa::path(
    get,
    path = "/api/enrichment/lookup/{ip}",
    tag = "enrichment",
    security(
        ("bearer_auth" = []),
        ("api_key" = [])
    ),
    params(
        ("ip" = String, Path, description = "IP address to lookup")
    ),
    responses(
        (status = 200, description = "IP enrichment data", body = IpLookupResponse),
        (status = 403, description = "Forbidden - missing permission"),
    )
)]
pub async fn lookup_ip(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Path(ip): Path<String>,
) -> Result<Json<IpLookupResponse>, ApiError> {
    check_permission(&auth, permissions::ENRICHMENTS_VIEW)
        .map_err(|_| ApiError::Forbidden("Missing permission: enrichments:view".to_string()))?;

    // Validate IP format before hitting the database
    if ip.parse::<std::net::IpAddr>().is_err() {
        return Err(ApiError::ValidationError(format!(
            "Invalid IP address: {}",
            ip
        )));
    }

    let enrichment = state.enrichment.read().await;
    let result = enrichment.lookup_ip(&ip).await.map_err(|e| {
        tracing::error!(error = %e, ip = %ip, "Enrichment lookup failed");
        ApiError::InternalError("Enrichment lookup failed".to_string())
    })?;

    match result {
        Some(r) => Ok(Json(IpLookupResponse {
            ip,
            found: true,
            country: r.country,
            country_code: r.country_code,
            continent: r.continent,
            continent_code: r.continent_code,
            asn: r.asn,
            as_name: r.as_name,
            as_domain: r.as_domain,
        })),
        None => Ok(Json(IpLookupResponse {
            ip,
            found: false,
            country: None,
            country_code: None,
            continent: None,
            continent_code: None,
            asn: None,
            as_name: None,
            as_domain: None,
        })),
    }
}
