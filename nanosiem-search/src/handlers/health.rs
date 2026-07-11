// SPDX-License-Identifier: AGPL-3.0-or-later

//! Health check and readiness endpoints.

use axum::{Json, extract::State};
use serde::Serialize;

use crate::SearchState;

/// Health check response
///
/// SECURITY: Only includes status field in the unauthenticated response.
/// Version, uptime, and dependency details are omitted to prevent information
/// disclosure to unauthenticated users.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct HealthResponse {
    /// Service status: "healthy", "degraded", or "unhealthy"
    pub status: String,
}

/// Health check endpoint
///
/// Returns the health status of the Search Service and its dependencies.
#[utoipa::path(
    get,
    path = "/health",
    tag = "health",
    security(()),
    responses(
        (status = 200, description = "Service health status", body = HealthResponse),
    )
)]
pub async fn health(State(state): State<SearchState>) -> Json<HealthResponse> {
    let health_status = state.dual_pool.health_check().await;

    let status = if health_status.is_healthy() {
        "healthy"
    } else if health_status.clickhouse_healthy {
        // Can still search if ClickHouse is up (saved searches from PG are optional)
        "degraded"
    } else {
        "unhealthy"
    };

    Json(HealthResponse {
        status: status.to_string(),
    })
}

/// Readiness check response
///
/// SECURITY: Only exposes ready status. Dependency details and leader election
/// state are omitted from the unauthenticated response to prevent reconnaissance.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct ReadyResponse {
    /// Whether the service is ready to accept traffic
    pub ready: bool,
}

/// Readiness check endpoint
///
/// Returns whether the service is ready to accept traffic.
/// In the default active/active mode (leader election disabled), all instances
/// are ready as long as ClickHouse is available. When leader election is enabled
/// (legacy active/standby), only the leader instance is ready.
/// Returns 503 when not ready so Kubernetes stops routing traffic.
#[utoipa::path(
    get,
    path = "/ready",
    tag = "health",
    security(()),
    responses(
        (status = 200, description = "Service is ready", body = ReadyResponse),
        (status = 503, description = "Service is not ready (standby or ClickHouse down)", body = ReadyResponse),
    )
)]
pub async fn ready(State(state): State<SearchState>) -> impl axum::response::IntoResponse {
    let health_status = state.dual_pool.health_check().await;
    let is_leader = state.is_leader();

    // Ready only if: leader + ClickHouse available
    let ready = is_leader && health_status.clickhouse_healthy;

    let body = Json(ReadyResponse { ready });

    if ready {
        (axum::http::StatusCode::OK, body)
    } else {
        (axum::http::StatusCode::SERVICE_UNAVAILABLE, body)
    }
}

/// Shallow liveness/readiness probe (NAN-1786).
///
/// Returns 200 whenever the process is responsive — it touches NO dependencies.
/// `/health` and `/ready` are deep (ClickHouse / leader-gated) and are for
/// monitoring; k8s liveness/readiness probes should target this instead so a
/// backend blip doesn't restart-storm or de-pool every replica.
#[utoipa::path(
    get,
    path = "/livez",
    tag = "health",
    security(()),
    responses(
        (status = 200, description = "Process is alive", body = HealthResponse),
    )
)]
pub async fn livez() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "alive".to_string(),
    })
}
