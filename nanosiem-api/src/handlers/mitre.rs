// SPDX-License-Identifier: AGPL-3.0-or-later

//! MITRE ATT&CK API handlers

use axum::{
    extract::{Query, State},
    http::{header, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    Extension, Json,
};
use serde::{Deserialize, Serialize};

use crate::handlers::AuditExt;
use crate::middleware::{check_permission, AuthContext};
use crate::state::AppState;
use nanosiem_core::audit::{AuditEvent, AuditSource, ClientContext, MITRE_CATALOG_SYNCED};
use nanosiem_core::auth::permissions;
use nanosiem_core::mitre::{
    DataSource, DataSourceReadiness, MitreCoverageResponse, MitreQuarantinedMapping,
    MitreRepository, MitreSync, MitreSyncMetadata, MitreSyncOutcome, MitreSyncState, MitreTactic,
    MitreTechnique, TelemetryReadinessSnapshot, TELEMETRY_READINESS_LOOKBACK_HOURS,
};

const TELEMETRY_READINESS_QUERY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// Response containing all MITRE data for frontend dropdowns
#[derive(Serialize, utoipa::ToSchema)]
pub struct MitreDataResponse {
    pub tactics: Vec<MitreTactic>,
    pub techniques: Vec<MitreTechnique>,
    pub last_sync: Option<MitreSyncMetadata>,
    pub sync_state: Option<MitreSyncState>,
}

/// Get all MITRE ATT&CK tactics and techniques
#[utoipa::path(
    get,
    path = "/api/mitre",
    tag = "mitre",
    responses(
        (status = 200, description = "MITRE ATT&CK tactics and techniques", body = MitreDataResponse),
        (status = 403, description = "Forbidden - Missing permission: mitre:view"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn get_mitre_data(
    Extension(auth): Extension<AuthContext>,
    State(state): State<AppState>,
) -> Result<Response, (StatusCode, String)> {
    check_permission(&auth, permissions::MITRE_VIEW)
        .map_err(|(status, json)| (status, json.0.message))?;

    let repo = MitreRepository::new(state.pool.clone());

    let tactics = repo.get_tactics().await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to get tactics: {}", e),
        )
    })?;

    let techniques = repo.get_techniques().await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to get techniques: {}", e),
        )
    })?;

    let last_sync = repo.get_sync_metadata().await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to get sync metadata: {}", e),
        )
    })?;

    let sync_state = repo.get_sync_state().await.map_err(|e| {
        tracing::error!(%e, "Failed to get MITRE sync state");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to get MITRE sync state".to_string(),
        )
    })?;

    // The ATT&CK catalog changes only on manual/scheduled sync, so a populated
    // response keeps a long browser cache. An *empty* catalog, however, is the
    // transient boot/seed window — caching it for an hour would hide the
    // freshly-seeded catalog from every client for that long (NAN-1766 / D5).
    // Setting the header here supersedes the route's static Cache-Control layer,
    // which is now `if_not_present`.
    let cache_control = if tactics.is_empty() || techniques.is_empty() {
        "private, no-store"
    } else {
        "private, max-age=3600, stale-while-revalidate=300"
    };

    Ok((
        [(header::CACHE_CONTROL, HeaderValue::from_static(cache_control))],
        Json(MitreDataResponse {
            tactics,
            techniques,
            last_sync,
            sync_state,
        }),
    )
        .into_response())
}

/// Trigger a manual sync of MITRE data
#[utoipa::path(
    post,
    path = "/api/mitre/sync",
    tag = "mitre",
    responses(
        (status = 200, description = "MITRE data synced successfully", body = SyncResponse),
        (status = 403, description = "Forbidden - Missing permission: mitre:sync"),
        (status = 409, description = "A MITRE sync is already running"),
        (status = 503, description = "Outbound synchronization is disabled"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn sync_mitre_data(
    Extension(auth): Extension<AuthContext>,
    Extension(client): Extension<ClientContext>,
    State(state): State<AppState>,
) -> Result<Json<SyncResponse>, (StatusCode, String)> {
    check_permission(&auth, permissions::MITRE_SYNC)
        .map_err(|(status, json)| (status, json.0.message))?;

    let repo = MitreRepository::new(state.pool.clone());
    let sync = MitreSync::new(repo);
    let expected_release = sync.release().to_string();
    let expected_source_url = sync.source_url().to_string();
    let expected_source_sha256 = sync.source_sha256().to_string();

    if !state.config.egress_jobs_enabled() {
        state.emit_audit(
            AuditEvent::builder(AuditSource::Mitre, MITRE_CATALOG_SYNCED)
                .actor(Some(auth.user_id()), None)
                .api_key(auth.api_key_id, auth.api_key_name.clone())
                .resource("mitre_catalog", None, Some(expected_release.clone()))
                .client_context(&client)
                .success(false)
                .details(serde_json::json!({
                    "release": expected_release,
                    "source_url": expected_source_url,
                    "source_sha256": expected_source_sha256,
                    "result": "egress_disabled",
                }))
                .build(),
        );
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            "Outbound MITRE catalog synchronization is disabled".to_string(),
        ));
    }

    match sync.sync().await {
        Ok(MitreSyncOutcome::Synced(result)) => {
            state.emit_audit(
                AuditEvent::builder(AuditSource::Mitre, MITRE_CATALOG_SYNCED)
                    .actor(Some(auth.user_id()), None)
                    .api_key(auth.api_key_id, auth.api_key_name.clone())
                    .resource("mitre_catalog", None, Some(result.release.clone()))
                    .client_context(&client)
                    .details(serde_json::json!({
                        "release": &result.release,
                        "source_url": &result.source_url,
                        "source_sha256": &result.source_sha256,
                        "tactic_count": result.tactic_count,
                        "technique_count": result.technique_count,
                    }))
                    .build(),
            );

            Ok(Json(SyncResponse {
                success: true,
                release: result.release,
                source_sha256: result.source_sha256,
                tactic_count: result.tactic_count,
                technique_count: result.technique_count,
            }))
        }
        Ok(outcome) => {
            let reason = match outcome {
                MitreSyncOutcome::AlreadyRunning => "already_running",
                MitreSyncOutcome::AlreadyCurrent => "already_current",
                MitreSyncOutcome::RetryBackoff => "retry_backoff",
                MitreSyncOutcome::Synced(_) => unreachable!(),
            };
            state.emit_audit(
                AuditEvent::builder(AuditSource::Mitre, MITRE_CATALOG_SYNCED)
                    .actor(Some(auth.user_id()), None)
                    .api_key(auth.api_key_id, auth.api_key_name.clone())
                    .resource("mitre_catalog", None, None)
                    .client_context(&client)
                    .success(false)
                    .details(serde_json::json!({
                        "release": expected_release,
                        "source_url": expected_source_url,
                        "source_sha256": expected_source_sha256,
                        "result": reason,
                    }))
                    .build(),
            );
            Err((
                StatusCode::CONFLICT,
                "MITRE catalog synchronization is already in progress".to_string(),
            ))
        }
        Err(error) => {
            tracing::error!(%error, "Manual MITRE catalog sync failed");
            state.emit_audit(
                AuditEvent::builder(AuditSource::Mitre, MITRE_CATALOG_SYNCED)
                    .actor(Some(auth.user_id()), None)
                    .api_key(auth.api_key_id, auth.api_key_name.clone())
                    .resource("mitre_catalog", None, None)
                    .client_context(&client)
                    .success(false)
                    .details(serde_json::json!({
                        "release": expected_release,
                        "source_url": expected_source_url,
                        "source_sha256": expected_source_sha256,
                        "error": error.to_string(),
                    }))
                    .build(),
            );
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                "MITRE catalog synchronization failed".to_string(),
            ))
        }
    }
}

#[derive(Serialize, utoipa::ToSchema)]
pub struct SyncResponse {
    pub success: bool,
    pub release: String,
    pub source_sha256: String,
    pub tactic_count: i32,
    pub technique_count: i32,
}

/// Query parameters for MITRE coverage endpoint
#[derive(Debug, Deserialize, utoipa::IntoParams)]
pub struct CoverageQueryParams {
    /// Comma-separated list of severities to filter by (e.g., "critical,high")
    pub severity: Option<String>,
    /// Comma-separated list of modes to filter by (e.g., "alerting,live")
    pub mode: Option<String>,
}

/// Get MITRE ATT&CK coverage data
/// Shows which techniques are covered by detection rules
#[utoipa::path(
    get,
    path = "/api/mitre/coverage",
    tag = "mitre",
    params(CoverageQueryParams),
    responses(
        (status = 200, description = "MITRE ATT&CK coverage data", body = MitreCoverageResponse),
        (status = 403, description = "Forbidden - Missing permission: mitre:view"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn get_mitre_coverage(
    Extension(auth): Extension<AuthContext>,
    State(state): State<AppState>,
    Query(params): Query<CoverageQueryParams>,
) -> Result<Json<MitreCoverageResponse>, (StatusCode, String)> {
    check_permission(&auth, permissions::MITRE_VIEW)
        .map_err(|(status, json)| (status, json.0.message))?;

    let repo = MitreRepository::new(state.pool.clone());

    let configured_source_types = repo.configured_source_types().await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to get configured telemetry sources: {}", e),
        )
    })?;
    let telemetry = if configured_source_types.is_empty() {
        TelemetryReadinessSnapshot::observed(
            configured_source_types,
            std::collections::HashMap::new(),
            chrono::Utc::now(),
        )
    } else {
        let requested_sources: Vec<String> = configured_source_types.iter().cloned().collect();
        // NAN-1801 (P3 side-doors): the readiness probe reads the
        // per-source `logs_per_source_5m` rollup, so scope it by the
        // viewer's effective deny set — a viewer denied a source (or
        // lacking `audit:view`) must not recover that source's last-seen
        // timestamp here. Denied sources fall out of the stats map and
        // render as "unknown" readiness; an empty deny set (unrestricted
        // viewer) emits byte-identical SQL.
        let deny_set = auth.effective_source_deny_set();
        let stats = match tokio::time::timeout(
            TELEMETRY_READINESS_QUERY_TIMEOUT,
            state
                .log_telemetry_service
                .stats_by_source_type(
                    &requested_sources,
                    TELEMETRY_READINESS_LOOKBACK_HOURS,
                    &deny_set,
                ),
        )
        .await
        {
            Ok(Ok(stats)) => Some(stats),
            Ok(Err(error)) => {
                tracing::warn!(
                    error = %error,
                    configured_source_count = requested_sources.len(),
                    "MITRE telemetry readiness unavailable; returning unknown readiness"
                );
                None
            }
            Err(_) => {
                tracing::warn!(
                    configured_source_count = requested_sources.len(),
                    timeout_seconds = TELEMETRY_READINESS_QUERY_TIMEOUT.as_secs(),
                    "MITRE telemetry readiness timed out; returning unknown readiness"
                );
                None
            }
        };

        match stats {
            Some(stats) => {
                let last_seen_by_source_type = stats
                    .into_iter()
                    .filter_map(|(source_type, stats)| {
                        stats
                            .last_event_at
                            .map(|last_seen| (source_type, last_seen))
                    })
                    .collect();
                TelemetryReadinessSnapshot::observed(
                    configured_source_types,
                    last_seen_by_source_type,
                    chrono::Utc::now(),
                )
            }
            None => {
                TelemetryReadinessSnapshot::unavailable(configured_source_types, chrono::Utc::now())
            }
        }
    };

    // Parse comma-separated filter values
    let severity_filter: Option<Vec<String>> = params.severity.map(|s| {
        s.split(',')
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty())
            .collect()
    });

    let mode_filter: Option<Vec<String>> = params.mode.map(|s| {
        s.split(',')
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty())
            .collect()
    });

    let coverage = repo
        .get_coverage(
            severity_filter.as_deref(),
            mode_filter.as_deref(),
            &telemetry,
        )
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to get coverage data: {}", e),
            )
        })?;

    Ok(Json(coverage))
}

/// Query parameters for the quarantined-mapping listing.
#[derive(Deserialize, utoipa::IntoParams)]
pub struct QuarantineQuery {
    /// Include mappings a later sync already restored. Defaults to false, so
    /// the listing shows only rules whose mapping is still missing.
    #[serde(default)]
    pub include_repaired: bool,
    /// Maximum rows to return (1-500, default 100).
    pub limit: Option<i64>,
}

/// Detection-rule MITRE mappings a catalog sync could not resolve.
#[derive(Serialize, utoipa::ToSchema)]
pub struct QuarantineResponse {
    pub mappings: Vec<MitreQuarantinedMapping>,
    /// Mappings still missing a resolution — the number worth acting on.
    pub unrepaired_count: usize,
}

/// List detection-rule MITRE mappings dropped by a catalog sync.
///
/// NAN-1918: before this endpoint existed the quarantine table had no reader at
/// all, so a sync that renumbered techniques destroyed rule mappings with no
/// operator-visible trace beyond a log line carrying a bare count.
#[utoipa::path(
    get,
    path = "/api/mitre/quarantine",
    tag = "mitre",
    params(QuarantineQuery),
    responses(
        (status = 200, description = "Quarantined MITRE mappings", body = QuarantineResponse),
        (status = 403, description = "Forbidden - Missing permission: mitre:view"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn get_quarantined_mappings(
    Extension(auth): Extension<AuthContext>,
    State(state): State<AppState>,
    Query(params): Query<QuarantineQuery>,
) -> Result<Json<QuarantineResponse>, (StatusCode, String)> {
    check_permission(&auth, permissions::MITRE_VIEW)
        .map_err(|(status, json)| (status, json.0.message))?;

    let limit = params.limit.unwrap_or(100).clamp(1, 500);
    let repo = MitreRepository::new(state.pool.clone());
    let mappings = repo
        .list_quarantined_mappings(params.include_repaired, limit)
        .await
        .map_err(|error| {
            tracing::error!(%error, "Failed to list quarantined MITRE mappings");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to list quarantined MITRE mappings".to_string(),
            )
        })?;

    let unrepaired_count = mappings
        .iter()
        .filter(|mapping| mapping.repaired_at.is_none())
        .count();

    Ok(Json(QuarantineResponse {
        mappings,
        unrepaired_count,
    }))
}

/// OpenAPI documentation for MITRE ATT&CK endpoints
pub struct MitreApiDoc;

impl utoipa::OpenApi for MitreApiDoc {
    fn openapi() -> utoipa::openapi::OpenApi {
        use utoipa::OpenApi;

        #[derive(OpenApi)]
        #[openapi(
            paths(
                get_mitre_data,
                get_mitre_coverage,
                sync_mitre_data,
                get_quarantined_mappings,
            ),
            components(schemas(
                MitreDataResponse,
                MitreSyncState,
                SyncResponse,
                DataSource,
                DataSourceReadiness,
                QuarantineResponse,
                MitreQuarantinedMapping,
            )),
            tags(
                (name = "mitre", description = "MITRE ATT&CK framework integration endpoints")
            )
        )]
        struct ApiDoc;

        ApiDoc::openapi()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn coverage_data_source_json_exposes_truthful_readiness_contract() {
        let active = DataSource {
            id: "process_process_creation".to_string(),
            name: "Process: Process Creation".to_string(),
            mapping_known: true,
            configured: true,
            readiness: DataSourceReadiness::Active,
            last_seen_at: Some(chrono::DateTime::UNIX_EPOCH),
            connected: true,
        };
        let stale = DataSource {
            readiness: DataSourceReadiness::Stale,
            last_seen_at: None,
            connected: false,
            ..active.clone()
        };
        let unknown = DataSource {
            configured: true,
            readiness: DataSourceReadiness::Unknown,
            last_seen_at: None,
            connected: false,
            ..active.clone()
        };

        let active_json = serde_json::to_value(active).expect("serialize active source");
        let stale_json = serde_json::to_value(stale).expect("serialize stale source");
        let unknown_json = serde_json::to_value(unknown).expect("serialize unknown source");

        assert_eq!(active_json["readiness"], "active");
        assert_eq!(active_json["mapping_known"], true);
        assert_eq!(active_json["configured"], true);
        assert_eq!(active_json["connected"], true);
        assert_eq!(stale_json["readiness"], "stale");
        assert_eq!(stale_json["last_seen_at"], serde_json::Value::Null);
        assert_eq!(stale_json["connected"], false);
        assert_eq!(unknown_json["readiness"], "unknown");
        assert_eq!(unknown_json["connected"], false);
    }
}
