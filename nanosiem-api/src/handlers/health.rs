// SPDX-License-Identifier: AGPL-3.0-or-later

//! Health check handlers
//!
//! Provides health check endpoints for monitoring the API server and database connections.
//! Supports dual database architecture with ClickHouse and PostgreSQL.
//! Also checks downstream service health (Ingest Service, Search Service) when available.
//!
//! Requirements: 4.4 (Main API reports its own status and downstream service status)
//! Requirements: 7.3 (X-Request-ID header propagation)

use axum::{extract::State, Extension, Json};
use serde::Serialize;

use crate::middleware::RequestId;
use crate::state::AppState;

/// NAN-1728 (L-1): all-shard ClickHouse liveness probe. On a multi-shard cluster
/// the DualPool health `SELECT 1` only touches the LB-connected node, so a dead
/// shard reports healthy while every `_distributed` read errors. This forces
/// contact with every shard's replica set via `clusterAllReplicas('<cluster>',
/// system.one)`; `Ok(())` means all shards answered. `CLICKHOUSE_CLUSTER` is set
/// only on clustered ClickHouse — unset (single-node / open-core) returns
/// `Ok(())` without issuing any query, so the health path is byte-identical.
async fn cluster_all_shard_ch_probe(
    dual_pool: &nanosiem_core::db::DualPool,
) -> Result<(), String> {
    if !dual_pool.is_clustered() {
        return Ok(());
    }
    let Some(cluster) = std::env::var("CLICKHOUSE_CLUSTER")
        .ok()
        .filter(|c| !c.trim().is_empty())
    else {
        return Ok(());
    };
    // NAN-5367: run the fan-out as the admin identity, which holds REMOTE
    // (users.d admin = ALL; k8s/BYOC admin is granted REMOTE, CLUSTER). The
    // runtime user deliberately has no REMOTE (NAN-2001 SSRF posture), so
    // issuing this as the runtime user was denied (Code 497) on every call and
    // the probe never ran. Remote shards answer as the remote_servers user,
    // which can read system.one. Without admin credentials there is no
    // identity allowed to fan out: skip without querying, as before.
    if !dual_pool.has_clickhouse_admin() {
        tracing::debug!("all-shard health probe skipped: no ClickHouse admin identity configured");
        return Ok(());
    }
    let sql = format!(
        "SELECT count() FROM clusterAllReplicas('{}', system.one)",
        nanosiem_core::sql_hygiene::escape_sql_string(&cluster)
    );
    dual_pool
        .clickhouse_admin()
        .query(&sql)
        .fetch_one::<u64>()
        .await
        .map(|_| ())
        .or_else(|e| {
            // Defense in depth: an admin identity without REMOTE (a custom
            // BYOC role) is a skip, not a false ClickHouse-down verdict.
            let msg = e.to_string();
            if msg.contains("ACCESS_DENIED") || msg.contains("Code: 497") {
                tracing::debug!("all-shard health probe skipped (probe not permitted): {msg}");
                Ok(())
            } else {
                Err(msg)
            }
        })
}

/// NAN-5390: `/health` query. `strict=1` (or `true`) maps "error" to HTTP 503.
#[derive(Debug, Default, utoipa::IntoParams)]
#[into_params(parameter_in = Query)]
pub struct HealthQuery {
    /// `1` / `true`: answer 503 instead of 200 when the status is "error".
    pub strict: Option<String>,
}

impl HealthQuery {
    pub fn from_raw(raw: Option<&str>) -> Self {
        let strict = raw
            .unwrap_or("")
            .split('&')
            .filter_map(|kv| kv.split_once('=').or(Some((kv, ""))))
            .find(|(k, _)| *k == "strict")
            .map(|(_, v)| v.to_string());
        Self { strict }
    }

    pub fn is_strict(&self) -> bool {
        matches!(self.strict.as_deref(), Some("1") | Some("true"))
    }
}

/// Minimal public health check response (prevents information disclosure)
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct PublicHealthResponse {
    pub status: String,
}

async fn control_plane_ready(state: &AppState) -> bool {
    // The API intentionally degrades to PostgreSQL-only operation when ClickHouse
    // is unavailable. Search has its own CH-dependent readiness endpoint.
    state.dual_pool().health_check().await.postgres_healthy
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
    /// NAN-5424: detection execution health. `degraded` when a rule is
    /// failing or a detection window went unevaluated in the last 24h; the
    /// overall `status` is then `degraded` too. Only on this authenticated
    /// endpoint: the public `/health` answers infrastructure liveness and
    /// must not tell an unauthenticated caller that detection is impaired.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detection: Option<nanosiem_core::detection::health::DetectionExecutionHealth>,
    /// NAN-5450: usage of the ClickHouse disks, the PostgreSQL volume and the
    /// Vector disk buffers (warning at 80 %, critical at 90 %). A critical
    /// volume makes the overall `status` `degraded`. Cached for 30 seconds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disk: Option<nanosiem_core::health::disk_monitor::DiskHealthReport>,
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
    /// Ingest (Vector) health: its metrics endpoint, or the ingest proxy on a
    /// role-split app host
    pub ingest: ServiceHealth,
    /// Search Service health (port 3002)
    pub search: ServiceHealth,
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

/// NAN-5387: where `/health/detailed` probes ingest and search.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct DownstreamProbeUrls {
    pub ingest: String,
    pub search: String,
}

/// Compose service names shared by the open-core and enterprise single-host
/// stacks (docker-compose.opensource.yml). Helm and role-split set the
/// variables below to their own addresses.
const DEFAULT_INGEST_PROBE_URL: &str = "http://vector:9598/metrics";
const DEFAULT_SEARCH_PROBE_URL: &str = "http://nano-search:3002/health";

/// NAN-5387: the probes used to default to `http://ingest:3001/health` and
/// `http://search:3002/health`, services no shipped topology has (there is no
/// separate ingest service: Vector is ingest), so open-core Compose and Helm
/// always reported both "unavailable".
///
/// * ingest: `INGEST_SERVICE_URL` (role-split app hosts: the ingest proxy's
///   end-to-end `/healthz`), else `VECTOR_METRICS_URL` (Vector's
///   internal-metrics exporter, which the deploy path already reads; Helm
///   points it at the vector-metrics Service), else the Compose default.
/// * search: `SEARCH_SERVICE_URL`, else `NANO_HEALTH_SEARCH_URL` (the
///   variable the health exporter reads), else the Compose default.
pub(crate) fn downstream_probe_urls(get: impl Fn(&str) -> Option<String>) -> DownstreamProbeUrls {
    let first = |keys: &[&str], default: &str| {
        keys.iter()
            .filter_map(|key| get(key))
            .map(|value| value.trim().to_string())
            .find(|value| !value.is_empty())
            .unwrap_or_else(|| default.to_string())
    };
    DownstreamProbeUrls {
        ingest: first(&["INGEST_SERVICE_URL", "VECTOR_METRICS_URL"], DEFAULT_INGEST_PROBE_URL),
        search: first(&["SEARCH_SERVICE_URL", "NANO_HEALTH_SEARCH_URL"], DEFAULT_SEARCH_PROBE_URL),
    }
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
/// NAN-5390: `?strict=1` serves "error" with HTTP 503, for checks that only
/// read the status code (`helm test`, external monitors) and must see a
/// ClickHouse that refuses nano's login. Plain `/health` keeps its 200 +
/// body contract: Compose healthchecks, edge routing checks, the upgrader and
/// legacy k8s probes consume it, and a 503 there would unroute or restart the
/// API on every transient ClickHouse/shard blip (one replica down in HA fails
/// the all-shard probe). Kubernetes probes target `/livez`.
///
/// GET /health
#[utoipa::path(
    get,
    path = "/health",
    tag = "health",
    params(HealthQuery),
    responses(
        (status = 200, description = "Health status (always 200 without `strict`; read `status`)", body = PublicHealthResponse),
        (status = 503, description = "With `strict=1`: PostgreSQL or ClickHouse is down or refuses nano's login", body = PublicHealthResponse),
    ),
    security(())
)]
pub async fn health_check(
    State(state): State<AppState>,
    axum::extract::RawQuery(raw): axum::extract::RawQuery,
) -> (axum::http::StatusCode, Json<PublicHealthResponse>) {
    // Parsed by hand so a malformed query string can never turn a health
    // check into a 400 (the typed `Query` extractor rejects it).
    let query = HealthQuery::from_raw(raw.as_deref());
    let mut is_healthy = state.dual_pool().health_check().await.is_healthy();

    // NAN-1728 (L-1): the DualPool `SELECT 1` only touches the LB-connected node,
    // so a cluster with a dead shard reports healthy while every distributed read
    // errors. When clustered, additionally require an all-shard probe to succeed.
    // Single-node skips the probe (`Ok(())`), so this is byte-identical there.
    if is_healthy {
        if let Err(e) = cluster_all_shard_ch_probe(state.dual_pool()).await {
            tracing::warn!("ClickHouse all-shard health probe failed: {}", e);
            is_healthy = false;
        }
    }

    let code = if is_healthy || !query.is_strict() {
        axum::http::StatusCode::OK
    } else {
        axum::http::StatusCode::SERVICE_UNAVAILABLE
    };
    (
        code,
        Json(PublicHealthResponse {
            status: if is_healthy { "ok" } else { "error" }.to_string(),
        }),
    )
}

#[utoipa::path(
    get, path = "/ready", tag = "health",
    responses(
        (status = 200, description = "API is ready", body = PublicHealthResponse),
        (status = 503, description = "API dependencies are unavailable", body = PublicHealthResponse),
    ),
    security(())
)]
pub async fn ready_check(State(state): State<AppState>) -> impl axum::response::IntoResponse {
    let ready = control_plane_ready(&state).await;
    let status = if ready { axum::http::StatusCode::OK }
        else { axum::http::StatusCode::SERVICE_UNAVAILABLE };
    (status, Json(PublicHealthResponse {
        status: if ready { "ready" } else { "not_ready" }.to_string(),
    }))
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
/// In dual mode, checks both PostgreSQL and ClickHouse.
/// Also checks ingest (Vector) and the Search Service (port 3002).
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

    // NAN-5387: probe the services each topology actually runs.
    let DownstreamProbeUrls { ingest: ingest_url, search: search_url } =
        downstream_probe_urls(|key| std::env::var(key).ok());

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
    if clickhouse_healthy {
        if let Err(e) = cluster_all_shard_ch_probe(state.dual_pool()).await {
            tracing::warn!("ClickHouse all-shard health probe failed: {}", e);
            clickhouse_healthy = false;
            clickhouse_error = Some(format!("all-shard probe failed: {e}"));
        }
    }

    let is_healthy = postgres_healthy && clickhouse_healthy;

    let postgres_health = DatabaseHealth {
        status: if postgres_healthy { "connected" } else { "error" }.to_string(),
        latency_ms: health_status.postgres_latency_ms,
        error: health_status.postgres_error,
    };

    let clickhouse_health = DatabaseHealth {
        status: if clickhouse_healthy { "connected" } else { "error" }.to_string(),
        latency_ms: health_status.clickhouse_latency_ms,
        error: clickhouse_error,
    };

    let ingest_ok = services_health.ingest.status == "healthy";
    let search_ok = services_health.search.status == "healthy";

    // NAN-5424: a rule that cannot persist its matches, or a detection
    // window recorded as never evaluated, degrades the platform status.
    let detection = if postgres_healthy {
        match nanosiem_core::detection::health::read_execution_health(&state.pool).await {
            Ok(health) => Some(health),
            Err(e) => {
                tracing::warn!("Detection execution health read failed: {}", e);
                None
            }
        }
    } else {
        None
    };
    let detection_ok = detection.as_ref().is_none_or(|d| d.status == "ok");

    // NAN-5450: disk usage. Each source is bounded (5 s) and the report is
    // cached for 30 s, so this endpoint stays fast under polling.
    let disk = nanosiem_core::health::disk_monitor::cached_disk_health(state.dual_pool()).await;
    let disk_ok = disk.status < nanosiem_core::health::disk_monitor::DiskLevel::Critical;

    let overall_status = if is_healthy {
        if !detection_ok || !disk_ok {
            "degraded"
        } else if ingest_ok && search_ok {
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

    let database_status = if is_healthy {
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
        clickhouse: Some(clickhouse_health),
        dual_mode_enabled: true,
        services: Some(services_health),
        detection,
        disk: Some(disk),
    }))
}

/// NAN-5450: what the admin disk banner shows.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct DiskAlertResponse {
    /// Worst level over the data disks: `ok` / `unknown` show nothing,
    /// `warning` (80 %) a notice on Settings -> Storage, `critical` (90 %, or
    /// forecast to fill within 24 hours) a banner on every page, `imminent`
    /// (95 %) a red banner that cannot be dismissed.
    pub level: nanosiem_core::health::disk_monitor::DiskLevel,
    /// Disks at warning or worse, each underlying disk once, worst first.
    /// Each carries its free bytes, usage, growth rate and forecast.
    pub disks: Vec<nanosiem_core::health::disk_monitor::DiskVolumeHealth>,
    /// Whether ingestion is paused right now (by disk pressure or an admin).
    pub ingestion_paused: bool,
    /// `disk_pressure` or `manual` while paused.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ingestion_pause_source: Option<String>,
    /// Usage fractions the levels start at.
    pub warn_fraction: f64,
    pub critical_fraction: f64,
    pub imminent_fraction: f64,
    /// The disk-full recovery runbook.
    pub runbook: String,
    pub checked_at: chrono::DateTime<chrono::Utc>,
}

/// Disk space alert for the admin banner
///
/// The data disks (ClickHouse, PostgreSQL, Vector disk buffers) at 80 % or
/// more, with the growth forecast, and whether ingestion is paused. Polled by
/// the web app for `settings:system` holders. Cached for 30 seconds.
#[utoipa::path(
    get,
    path = "/api/system/disk-alert",
    tag = "system",
    responses(
        (status = 200, description = "Disk space alert", body = DiskAlertResponse),
        (status = 403, description = "Missing settings:system", body = crate::error::ErrorResponse)
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn get_disk_alert(
    State(state): State<AppState>,
    Extension(auth): Extension<crate::middleware::AuthContext>,
) -> Result<Json<DiskAlertResponse>, crate::error::ApiError> {
    use nanosiem_core::health::disk_monitor::{self, DiskLevel};
    crate::middleware::ensure_permission(&auth, nanosiem_core::auth::permissions::SETTINGS_SYSTEM)?;
    let report = disk_monitor::cached_disk_health(state.dual_pool()).await;
    let disks: Vec<_> = report.alarming_disks().into_iter().cloned().collect();
    let level = disks.first().map(|d| d.level).unwrap_or(if report.status == DiskLevel::Unknown {
        DiskLevel::Unknown
    } else {
        DiskLevel::Ok
    });
    let pause = state.ingestion_pause.state().await.ok();
    Ok(Json(DiskAlertResponse {
        level,
        disks,
        ingestion_paused: pause.as_ref().is_some_and(|p| p.paused),
        ingestion_pause_source: pause
            .as_ref()
            .filter(|p| p.paused)
            .and_then(|p| p.source)
            .map(|s| serde_json::to_value(s).ok().and_then(|v| v.as_str().map(String::from)).unwrap_or_default()),
        warn_fraction: report.warn_fraction,
        critical_fraction: report.critical_fraction,
        imminent_fraction: report.imminent_fraction,
        runbook: disk_monitor::DISK_FULL_RUNBOOK.to_string(),
        checked_at: report.checked_at,
    }))
}

#[derive(utoipa::OpenApi)]
#[openapi(
    paths(health_check, ready_check, livez, health_check_detailed, get_disk_alert),
    components(schemas(
        PublicHealthResponse,
        HealthResponse,
        DualHealthResponse,
        DatabaseHealth,
        DownstreamServicesHealth,
        ServiceHealth,
        nanosiem_core::detection::health::DetectionExecutionHealth,
        nanosiem_core::health::disk_monitor::DiskHealthReport,
        nanosiem_core::health::disk_monitor::DiskVolumeHealth,
        nanosiem_core::health::disk_monitor::DiskLevel,
        nanosiem_core::health::disk_monitor::DiskComponent,
        nanosiem_core::health::disk_monitor::DiskForecast,
        DiskAlertResponse
    ))
)]
pub struct HealthApiDoc;

#[cfg(test)]
#[path = "health_tests.rs"]
mod tests;
