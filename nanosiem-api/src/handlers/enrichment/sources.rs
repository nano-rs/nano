// SPDX-License-Identifier: AGPL-3.0-or-later

//! Enrichment source management handlers

use axum::{
    extract::{Path, State},
    Extension, Json,
};
use nanosiem_core::audit::{
    AuditEvent, AuditSource, ClientContext, ENRICHMENT_DISABLED, ENRICHMENT_ENABLED,
};
use nanosiem_core::auth::permissions;

use super::sanitize_config;
use super::types::*;
use super::AuditExt;
use crate::middleware::{ensure_permission, AuthContext};
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
    ensure_permission(&auth, permissions::ENRICHMENTS_VIEW)?;

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
            enabled: s.enabled,
            last_sync_at: s.last_sync_at.map(|t| t.to_rfc3339()),
            last_sync_status: s.last_sync_status,
            record_count: s.record_count,
            deprovisioned_count: s.deprovisioned_count,
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
    ensure_permission(&auth, permissions::ENRICHMENTS_CONFIGURE)?;

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
    ensure_permission(&auth, permissions::ENRICHMENTS_CONFIGURE)?;

    let enrichment = state.enrichment.read().await;
    enrichment
        .repository()
        .set_source_enabled(&source_id, false)
        .await
        .map_err(|e| ApiError::NotFound(format!("Source not found: {}", e)))?;

    // NAN-1117: the ip_enrichment_dict source is now ClickHouse and can't join
    // PG's `enabled` flag. To preserve the legacy "disable -> enrichment blanks"
    // UX, tombstone this source's CH payload rows so the dict drops them, then
    // reload the dict so the change takes effect immediately rather than after
    // its LIFETIME. Best-effort: a CH hiccup must not fail the config write.
    if let Err(e) = enrichment.clear_ip_enrichments_for_source(&source_id).await {
        tracing::warn!(source_id = %source_id, error = %e, "Failed to tombstone CH IP enrichment rows on disable");
    } else {
        // Fan the reload out to every node when clustered: the dict loads
        // per-node, so a single-node reload would leave the other 5 nodes
        // serving the disabled source's data until their LIFETIME expires
        // (NAN-1728 H3). `on_cluster_clause()` is empty on single-node → the
        // emitted `SYSTEM RELOAD DICTIONARY …` is byte-identical to before.
        // TODO(NAN-1728 H3 follow-up): the dict sources from
        // `ip_enrichment_dict_staging`, refreshed on a schedule (5m–6h); a
        // `SYSTEM REFRESH VIEW ip_enrichment_dict_refresh` (+ WAIT) before the
        // reload would make the tombstone visible immediately rather than at
        // the next staging refresh. Deferred (async-refresh/reload race +
        // pre-existing single-node staleness) — tracked separately.
        // NAN-4957: the split geo dictionaries, never the old single
        // ip_enrichment_dict (a reload loads 1.32 GiB).
        let on_cluster = nanosiem_core::db::dual_pool::on_cluster_clause();
        if let Err(e) =
            nanosiem_core::enrichment::ip_geo::reload_pair(
                state.dual_pool.clickhouse_admin(),
                state.dual_pool.clickhouse(),
                &on_cluster,
            )
            .await
        {
            tracing::warn!(error = %format!("{e:#}"), "Failed to reload the IP geo dictionaries after disable");
        }
    }
    drop(enrichment);

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
    ensure_permission(&auth, permissions::ENRICHMENTS_VIEW)?;

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
