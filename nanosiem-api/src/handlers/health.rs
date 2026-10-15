// SPDX-License-Identifier: AGPL-3.0-or-later

//! Health check handlers
//!
//! Provides health check endpoints for monitoring the API server and database connections.
//! Reports PostgreSQL plus the active event backend: ClickHouse in legacy mode
//! or the canonical lake worker in lake mode.
//! Also checks downstream ingest and Search service health when available. The
//! lake product's ingest boundary is Vector; the retired standalone ingest
//! service remains relevant only to the legacy profile.
//!
//! Requirements: 4.4 (Main API reports its own status and downstream service status)
//! Requirements: 7.3 (X-Request-ID header propagation)

use axum::{extract::State, Extension, Json};
use serde::Serialize;
use nanosiem_core::request_timing::{timed, Phase};

use crate::middleware::RequestId;
use crate::state::AppState;

/// NAN-1728 (L-1): all-shard ClickHouse liveness probe. On a multi-shard cluster
/// the DualPool health `SELECT 1` only touches the LB-connected node, so a dead
/// shard reports healthy while every `_distributed` read errors. This forces
/// contact with every shard's replica set via `clusterAllReplicas('<cluster>',
/// system.one)`; `Ok(())` means all shards answered. `CLICKHOUSE_CLUSTER` is set
/// only on clustered ClickHouse — unset (single-node / open-core) returns
/// `Ok(())` without issuing any query, so the health path is byte-identical.
async fn cluster_all_shard_ch_probe(dual_pool: &nanosiem_core::db::DualPool) -> Result<(), String> {
    if !dual_pool.is_clustered() {
        return Ok(());
    }
    let Some(cluster) = std::env::var("CLICKHOUSE_CLUSTER")
        .ok()
        .filter(|c| !c.trim().is_empty())
    else {
        return Ok(());
    };
    let sql = format!("SELECT count() FROM clusterAllReplicas('{cluster}', system.one)");
    dual_pool
        .clickhouse()
        .query(&sql)
        .fetch_one::<u64>()
        .await
        .map(|_| ())
        .or_else(|e| {
            // NAN-2025: the runtime `nanosiem` CH user intentionally lacks the
            // REMOTE grant (`clusterAllReplicas`/`remote` are denied per the
            // NAN-2001 SSRF posture), and on a single-shard cluster this all-shard
            // probe has no diagnostic value anyway (the LB `SELECT 1` already
            // proved the sole shard reachable). Treat a privilege denial as a skip
            // rather than flipping the whole health check to a false CH-down
            // verdict and flooding WARN on every /health call.
            let msg = e.to_string();
            if msg.contains("ACCESS_DENIED") || msg.contains("Code: 497") {
                tracing::debug!("all-shard health probe skipped (probe not permitted): {msg}");
                Ok(())
            } else {
                Err(msg)
            }
        })
}

/// Minimal public health check response (prevents information disclosure)
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct PublicHealthResponse {
    pub status: String,
}

// Shared API control-plane availability must not depend on the separate Search
// fleet. Retired gen1 assignments can time out even while lean tenant requests
// and PostgreSQL work; Search owns its own dependency readiness.
async fn api_dependencies_ready(
    shared: bool,
    postgres_probe: impl std::future::Future<Output = bool>,
    lake_probe: impl std::future::Future<Output = bool>,
) -> bool {
    postgres_probe.await && (shared || lake_probe.await)
}

async fn control_plane_ready(state: &AppState) -> bool {
    #[cfg(feature = "enterprise")]
    let shared_profile = state.config.deployment_mode.is_enterprise_shared();
    #[cfg(not(feature = "enterprise"))]
    let shared_profile = false;
    api_dependencies_ready(
        shared_profile,
        async {
            timed(Phase::Authority, state.dual_pool().health_check())
                .await
                .postgres_healthy
        },
        async { timed(Phase::Upstream, state.search_service.lake_worker_ready()).await },
    )
    .await
}

/// Health check response for PostgreSQL-only mode
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct HealthResponse {
    pub status: String,
    pub version: String,
    pub database: String,
}

/// Detailed health check response for dual database mode with downstream services
/// SECURITY: This detailed response should only be returned to authenticated users
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct DualHealthResponse {
    pub status: String,
    pub version: String,
    /// Overall database status
    pub database: String,
    /// PostgreSQL connection status
    pub postgres: DatabaseHealth,
    /// ClickHouse connection status (if enabled)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub clickhouse: Option<DatabaseHealth>,
    /// Whether dual database mode is enabled
    pub dual_mode_enabled: bool,
    /// Downstream service health (Ingest and Search services)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub services: Option<DownstreamServicesHealth>,
    /// Pinned lake schema generation and whether it still matches the manifest
    /// the assigned worker is serving. Absent outside lake deployments.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub schema: Option<SchemaProfileHealth>,
}

/// Which lake schema generation this process resolves OCSF field names against.
///
/// the profile is pinned at boot and refreshed on a low-frequency tick,
/// so between a promotion and the next tick the pinned generation can lag the
/// worker's. That window is legitimate; a lag that never clears is a real defect,
/// and it used to be invisible. Reported here (and warned about in the log) so
/// operators can see the pinned identity rather than infer it.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct SchemaProfileHealth {
    /// Number of fields in the pinned field inventory — the universe query
    /// validation is resolved against.
    pub field_count: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pinned_generation_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pinned_manifest_digest: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pinned_manifest_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pinned_tenant_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub active_generation_id: Option<String>,
    /// Digest the worker config DECLARES for its active manifest. Reported for
    /// comparison only — adoption re-hashes the bytes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub active_declared_digest: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub active_tenant_id: Option<String>,
    /// True when the on-disk active manifest is not the pinned one, or when
    /// agreement could not be established at all.
    pub drifted: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Cheap: reads the small worker config, never hashes the multi-MB manifest, so
/// a health poll cannot become expensive work on the request path.
fn schema_profile_health(state: &AppState) -> Option<SchemaProfileHealth> {
    let status = state.schema_profile.drift_status()?;
    if status.drifted {
        tracing::warn!(
            pinned_generation = status.pinned_generation_id.as_deref().unwrap_or("unknown"),
            active_generation = status.active_generation_id.as_deref().unwrap_or("unknown"),
            error = status.error.as_deref().unwrap_or(""),
            "pinned lake schema manifest differs from the worker's active manifest; \
             OCSF field resolution may describe a generation that is no longer served"
        );
    }
    Some(SchemaProfileHealth {
        field_count: state.schema_profile().fields().len(),
        pinned_generation_id: status.pinned_generation_id,
        pinned_manifest_digest: status.pinned_digest,
        pinned_manifest_path: status.pinned_manifest_path,
        pinned_tenant_id: status.pinned_tenant_id,
        active_generation_id: status.active_generation_id,
        active_declared_digest: status.active_declared_digest,
        active_tenant_id: status.active_tenant_id,
        drifted: status.drifted,
        error: status.error,
    })
}

/// Health status for a single database
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct DatabaseHealth {
    pub status: String,
    pub latency_ms: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Health status for downstream services
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct DownstreamServicesHealth {
    /// Active ingest boundary health (Vector for lake, Ingest Service for legacy)
    pub ingest: ServiceHealth,
    /// Search Service health (port 3002)
    pub search: ServiceHealth,
}

fn ingest_health_url(
    lake_backend: bool,
    ingest_service_url: Option<String>,
    vector_api_url: Option<String>,
) -> String {
    if lake_backend {
        vector_api_url.unwrap_or_else(|| "http://vector:8686/health".to_string())
    } else {
        ingest_service_url.unwrap_or_else(|| "http://ingest:3001/health".to_string())
    }
}

/// Health status for a single downstream service
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct ServiceHealth {
    pub status: String,
    pub url: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latency_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Check health of a downstream service
/// Propagates X-Request-ID header for distributed tracing (Requirements: 7.3)
async fn check_service_health(url: &str, request_id: Option<&str>) -> ServiceHealth {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build();

    let client = match client {
        Ok(c) => c,
        Err(e) => {
            return ServiceHealth {
                status: "error".to_string(),
                url: url.to_string(),
                latency_ms: None,
                error: Some(format!("Failed to create HTTP client: {}", e)),
            };
        }
    };

    let start = std::time::Instant::now();

    // Build request with optional X-Request-ID header
    let mut request_builder = client.get(url);
    if let Some(rid) = request_id {
        request_builder = request_builder.header("X-Request-ID", rid);
    }

    let result = request_builder.send().await;
    let latency_ms = start.elapsed().as_millis() as u64;

    match result {
        Ok(response) => {
            if response.status().is_success() {
                ServiceHealth {
                    status: "healthy".to_string(),
                    url: url.to_string(),
                    latency_ms: Some(latency_ms),
                    error: None,
                }
            } else {
                ServiceHealth {
                    status: "unhealthy".to_string(),
                    url: url.to_string(),
                    latency_ms: Some(latency_ms),
                    error: Some(format!("HTTP {}", response.status())),
                }
            }
        }
        Err(e) => {
            // Service might not be deployed yet - this is expected in some configurations
            ServiceHealth {
                status: "unavailable".to_string(),
                url: url.to_string(),
                latency_ms: None,
                error: Some(e.to_string()),
            }
        }
    }
}

/// Public health check endpoint - returns minimal information
///
/// SECURITY: This endpoint is public and returns only "ok" or "error" status
/// to prevent information disclosure about system architecture.
/// Use /health/detailed (authenticated) for full diagnostics.
///
/// GET /health
#[utoipa::path(
    get,
    path = "/health",
    tag = "health",
    responses(
        (status = 200, description = "Health status", body = PublicHealthResponse),
    ),
    security(())
)]
pub async fn health_check(State(state): State<AppState>) -> Json<PublicHealthResponse> {
    let lake_backend = state.search_service.backend() == nanosiem_core::SearchBackend::Lake;
    let mut is_healthy = if lake_backend {
        control_plane_ready(&state).await
    } else {
        timed(Phase::Authority, state.dual_pool().health_check()).await.is_healthy()
    };

    // NAN-1728 (L-1): the DualPool `SELECT 1` only touches the LB-connected node,
    // so a cluster with a dead shard reports healthy while every distributed read
    // errors. When clustered, additionally require an all-shard probe to succeed.
    // Single-node skips the probe (`Ok(())`), so this is byte-identical there.
    if is_healthy && !lake_backend {
        if let Err(e) = timed(Phase::Authority, cluster_all_shard_ch_probe(state.dual_pool())).await {
            tracing::warn!("ClickHouse all-shard health probe failed: {}", e);
            is_healthy = false;
        }
    }

    Json(PublicHealthResponse {
        status: if is_healthy {
            "ok".to_string()
        } else {
            "error".to_string()
        },
    })
}

#[utoipa::path(
    get, path = "/ready", tag = "health",
    responses(
        (status = 200, description = "API control plane is ready; shared Search readiness is checked separately", body = PublicHealthResponse),
        (status = 503, description = "API dependencies are unavailable", body = PublicHealthResponse),
    ),
    security(())
)]
pub async fn ready_check(State(state): State<AppState>) -> impl axum::response::IntoResponse {
    let ready = control_plane_ready(&state).await;
    let status = if ready {
        axum::http::StatusCode::OK
    } else {
        axum::http::StatusCode::SERVICE_UNAVAILABLE
    };
    (
        status,
        Json(PublicHealthResponse {
            status: if ready { "ready" } else { "not_ready" }.to_string(),
        }),
    )
}

/// Shallow liveness/readiness probe (NAN-1786).
///
/// Returns 200 whenever the process is running and the HTTP server is
/// responsive — it deliberately touches NO dependencies. The listener only
/// binds after DualPool init + migrations (see `main.rs`), so "serving" already
/// implies "booted with deps present". This is what Kubernetes liveness (and
/// readiness) probes should target: gating them on a live PG/CH check — as
/// `/health` (deep PG+CH+shards) and `/ready` (control-plane) do — restart-storms
/// or de-pools every replica on a transient backend blip. `/health` and `/ready`
/// remain for monitoring/dashboards, not for k8s probes.
#[utoipa::path(
    get, path = "/livez", tag = "health",
    responses((status = 200, description = "Process is alive", body = PublicHealthResponse)),
    security(())
)]
pub async fn livez() -> Json<PublicHealthResponse> {
    Json(PublicHealthResponse {
        status: "alive".to_string(),
    })
}

/// Detailed health check endpoint (authenticated)
///
/// Returns health status for all configured databases and downstream services.
/// In legacy dual mode, checks both PostgreSQL and ClickHouse. Primary-lake
/// mode reports PostgreSQL plus the ingest/search services and does not make an
/// unused compatibility ClickHouse instance part of readiness.
/// Also checks Ingest Service (port 3001) and Search Service (port 3002) health.
/// Propagates X-Request-ID header to downstream services for distributed tracing.
///
/// SECURITY: This endpoint requires authentication to prevent information disclosure.
///
/// Requirements: 1.4, 4.4, 7.3, 8.3, 9.5
///
/// GET /health/detailed (authenticated)
#[utoipa::path(
    get,
    path = "/health/detailed",
    tag = "health",
    responses(
        (status = 200, description = "Detailed health status with database and service diagnostics", body = DualHealthResponse),
    ),
    security(
        ("bearer_auth" = []),
        ("api_key" = [])
    )
)]
pub async fn health_check_detailed(
    State(state): State<AppState>,
    Extension(auth): Extension<crate::middleware::AuthContext>,
    request_id: Option<Extension<RequestId>>,
) -> Result<Json<DualHealthResponse>, crate::error::ApiError> {
    // NAN-2070: this response leaks internal service URLs, database/service
    // topology, latencies, and raw backend/HTTP error strings that the public
    // `/health` endpoint intentionally suppresses. Gate it on the privileged
    // `settings:system` capability, not the broad read-only `settings:view`.
    crate::middleware::ensure_permission(&auth, nanosiem_core::auth::permissions::SETTINGS_SYSTEM)?;

    let lake_backend = state.search_service.backend() == nanosiem_core::SearchBackend::Lake;

    // The standalone ingest service was removed. Canonical lake deployments
    // health-check the Vector API that owns their active ingest pipeline;
    // legacy deployments retain the old ingest-service contract.
    let ingest_url = ingest_health_url(
        lake_backend,
        std::env::var("INGEST_SERVICE_URL").ok(),
        std::env::var("VECTOR_API_URL").ok(),
    );
    let search_url = std::env::var("SEARCH_SERVICE_URL")
        .unwrap_or_else(|_| "http://search:3002/health".to_string());

    // Extract request ID for propagation
    let rid = request_id.as_ref().map(|r| r.0.as_str());

    // Check downstream services in parallel, propagating request ID
    let (ingest_health, search_health) = tokio::join!(
        check_service_health(&ingest_url, rid),
        check_service_health(&search_url, rid)
    );

    let services_health = DownstreamServicesHealth {
        ingest: ingest_health,
        search: search_health,
    };

    // Use DualPool health check for comprehensive status
    let health_status = state.dual_pool().health_check().await;

    let postgres_healthy = health_status.postgres_healthy;
    let mut clickhouse_healthy = health_status.clickhouse_healthy;
    let mut clickhouse_error = health_status.clickhouse_error;

    // NAN-1728 (L-1): on a cluster, downgrade ClickHouse to error when the
    // all-shard probe fails even though the LB-connected node answered `SELECT 1`
    // — a dead shard would otherwise report healthy. Single-node skips the probe
    // (`Ok(())`), so `clickhouse_healthy` is unchanged and this is byte-identical.
    if clickhouse_healthy && !lake_backend {
        if let Err(e) = cluster_all_shard_ch_probe(state.dual_pool()).await {
            tracing::warn!("ClickHouse all-shard health probe failed: {}", e);
            clickhouse_healthy = false;
            clickhouse_error = Some(format!("all-shard probe failed: {e}"));
        }
    }

    let lake_worker_healthy = state.search_service.lake_worker_ready().await;
    let is_healthy = postgres_healthy
        && if lake_backend {
            lake_worker_healthy
        } else {
            clickhouse_healthy
        };

    let postgres_health = DatabaseHealth {
        status: if postgres_healthy {
            "connected"
        } else {
            "error"
        }
        .to_string(),
        latency_ms: health_status.postgres_latency_ms,
        error: health_status.postgres_error,
    };

    let clickhouse_health = DatabaseHealth {
        status: if clickhouse_healthy {
            "connected"
        } else {
            "error"
        }
        .to_string(),
        latency_ms: health_status.clickhouse_latency_ms,
        error: clickhouse_error,
    };

    let ingest_ok = services_health.ingest.status == "healthy";
    let search_ok = services_health.search.status == "healthy";

    let overall_status = if is_healthy {
        if ingest_ok && search_ok {
            "ok"
        } else if services_health.ingest.status == "unavailable"
            && services_health.search.status == "unavailable"
        {
            // Services not deployed yet
            "ok"
        } else {
            "degraded"
        }
    } else {
        "unhealthy"
    };

    let database_status = if is_healthy && lake_backend {
        "postgres connected; events served by lake query backend".to_string()
    } else if lake_backend && postgres_healthy {
        "postgres connected; lake query worker unavailable or mismatched".to_string()
    } else if is_healthy {
        "all connected".to_string()
    } else if postgres_healthy {
        "clickhouse error".to_string()
    } else if clickhouse_healthy {
        "postgres error".to_string()
    } else {
        "both databases error".to_string()
    };

    Ok(Json(DualHealthResponse {
        status: overall_status.to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        database: database_status,
        postgres: postgres_health,
        clickhouse: (!lake_backend).then_some(clickhouse_health),
        dual_mode_enabled: !lake_backend,
        services: Some(services_health),
        // Drift is reported, not folded into `status`: a promotion legitimately
        // leaves this true for up to one refresh interval, and flipping the
        // deployment to "degraded" every 15 minutes would train operators to
        // ignore it.
        schema: schema_profile_health(&state),
    }))
}

#[derive(utoipa::OpenApi)]
#[openapi(
    paths(health_check, ready_check, livez, health_check_detailed),
    components(schemas(
        PublicHealthResponse,
        HealthResponse,
        DualHealthResponse,
        DatabaseHealth,
        DownstreamServicesHealth,
        ServiceHealth,
        SchemaProfileHealth
    ))
)]
pub struct HealthApiDoc;

#[cfg(test)]
mod tests {
    use super::{api_dependencies_ready, ingest_health_url};

    #[tokio::test]
    async fn shared_api_stays_ready_when_search_never_answers() {
        let ready = tokio::time::timeout(
            std::time::Duration::from_millis(100),
            api_dependencies_ready(true, async { true }, std::future::pending()),
        )
        .await
        .expect("shared API readiness must not wait for the search fleet");
        assert!(ready);
    }

    #[tokio::test]
    async fn postgres_failure_keeps_all_api_modes_unready() {
        for shared in [false, true] {
            assert!(
                !api_dependencies_ready(shared, async { false }, async {
                    panic!("failed PostgreSQL must short-circuit downstream probes")
                })
                .await
            );
        }
    }

    #[tokio::test]
    async fn non_shared_api_still_checks_its_lake_worker() {
        assert!(!api_dependencies_ready(false, async { true }, async { false }).await);
        assert!(api_dependencies_ready(false, async { true }, async { true }).await);
    }

    #[test]
    fn lake_health_uses_vector_instead_of_the_retired_ingest_service() {
        assert_eq!(
            ingest_health_url(
                true,
                Some("http://legacy-ingest:3001/health".to_string()),
                Some("http://vector:8686/health".to_string()),
            ),
            "http://vector:8686/health"
        );
        assert_eq!(
            ingest_health_url(true, None, None),
            "http://vector:8686/health"
        );
    }

    #[test]
    fn legacy_health_keeps_the_ingest_service_contract() {
        assert_eq!(
            ingest_health_url(
                false,
                Some("http://legacy-ingest:3001/health".to_string()),
                Some("http://vector:8686/health".to_string()),
            ),
            "http://legacy-ingest:3001/health"
        );
    }
}
