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

/// Minimal public health check response (prevents information disclosure)
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct PublicHealthResponse {
    pub status: String,
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
    /// Ingest Service health (port 3001)
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
    // Simple check - just verify we can reach the database
    let is_healthy = if let Some(dual_pool) = state.dual_pool() {
        let health_status = dual_pool.health_check().await;
        health_status.is_healthy()
    } else {
        sqlx::query("SELECT 1").fetch_one(&state.pool).await.is_ok()
    };

    Json(PublicHealthResponse {
        status: if is_healthy {
            "ok".to_string()
        } else {
            "error".to_string()
        },
    })
}

/// Detailed health check endpoint (authenticated)
///
/// Returns health status for all configured databases and downstream services.
/// In dual mode, checks both PostgreSQL and ClickHouse.
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
    // L2: Restrict detailed health to admin role — exposes internal service URLs
    crate::middleware::check_permission(&auth, nanosiem_core::auth::permissions::SETTINGS_VIEW)
        .map_err(|_| {
            crate::error::ApiError::Forbidden("Missing permission: settings:view".to_string())
        })?;

    // Get service URLs from environment or use defaults
    let ingest_url = std::env::var("INGEST_SERVICE_URL")
        .unwrap_or_else(|_| "http://ingest:3001/health".to_string());
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

    // Check if we're in dual pool mode
    if let Some(dual_pool) = state.dual_pool() {
        // Use DualPool health check for comprehensive status
        let health_status = dual_pool.health_check().await;

        // Check overall health first before moving values
        let is_healthy = health_status.is_healthy();
        let postgres_healthy = health_status.postgres_healthy;
        let clickhouse_healthy = health_status.clickhouse_healthy;

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
            error: health_status.clickhouse_error,
        };

        // Check downstream service health
        let ingest_ok = services_health.ingest.status == "healthy";
        let search_ok = services_health.search.status == "healthy";

        // Overall status considers databases and optionally downstream services
        // Main API is "healthy" if databases are OK
        // Main API is "degraded" if databases are OK but downstream services are not
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
        }))
    } else {
        // PostgreSQL-only mode
        let start = std::time::Instant::now();
        let pg_result = sqlx::query("SELECT 1").fetch_one(&state.pool).await;
        let latency_ms = start.elapsed().as_millis() as u64;

        let (pg_status, pg_error) = match pg_result {
            Ok(_) => ("connected".to_string(), None),
            Err(e) => ("error".to_string(), Some(e.to_string())),
        };

        let postgres_health = DatabaseHealth {
            status: pg_status.clone(),
            latency_ms,
            error: pg_error,
        };

        // Check downstream service health
        let ingest_ok = services_health.ingest.status == "healthy";
        let search_ok = services_health.search.status == "healthy";

        let overall_status = if pg_status == "connected" {
            if ingest_ok && search_ok {
                "ok"
            } else if services_health.ingest.status == "unavailable"
                && services_health.search.status == "unavailable"
            {
                // Services not deployed yet - this is OK for Main API
                "ok"
            } else {
                "degraded"
            }
        } else {
            "unhealthy"
        };

        Ok(Json(DualHealthResponse {
            status: overall_status.to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            database: pg_status,
            postgres: postgres_health,
            clickhouse: None,
            dual_mode_enabled: false,
            services: Some(services_health),
        }))
    }
}

#[derive(utoipa::OpenApi)]
#[openapi(
    paths(health_check, health_check_detailed),
    components(schemas(
        PublicHealthResponse,
        HealthResponse,
        DualHealthResponse,
        DatabaseHealth,
        DownstreamServicesHealth,
        ServiceHealth
    ))
)]
pub struct HealthApiDoc;
