// SPDX-License-Identifier: AGPL-3.0-or-later

//! Observability ↔ Security convergence — service security signals (NAN-1542).
//!
//! The Observability service-detail view cross-links into the SECURITY world:
//! "which detections fired against the hosts/IPs this service runs on?". This
//! endpoint resolves the service's distinct entities (src_ip + host) from
//! `otel_spans` over the window, then surfaces the security DETECTION signals
//! (the ClickHouse `signals` table) whose matched `risk_entity` is one of those
//! entities. Both reads are bounded + injection-safe (every id escaped, single
//! time-bound WHERE) — the heavy lifting lives in the search service glue
//! (`observability_service_security_signals`).
//!
//! Read endpoint requires `search:view` (the console is a search-adjacent
//! surface, matching the SLO/synthetics read gate).

use axum::{
    Extension, Json,
    extract::{Path, Query, State},
};
use serde::{Deserialize, Serialize};

use crate::error::{ApiError, ErrorResponse};
use crate::middleware::{AuthContext, check_permission};
use crate::state::AppState;
use nanosiem_core::auth::permissions;
use nanosiem_core::query::TimeRange;

/// Default lookback window (hours) when `start` is omitted.
fn default_window_hours() -> i64 {
    1
}

/// Query parameters for the service security-signals cross-link (NAN-1542).
#[derive(Debug, Deserialize, utoipa::IntoParams)]
pub struct ServiceSecuritySignalsParams {
    /// Window start (RFC3339). Defaults to `now - window_hours`.
    pub start: Option<chrono::DateTime<chrono::Utc>>,
    /// Window end (RFC3339). Defaults to `now`.
    pub end: Option<chrono::DateTime<chrono::Utc>>,
    /// Lookback window in hours used when `start` is omitted. Default 1.
    #[serde(default = "default_window_hours")]
    pub window_hours: i64,
    /// Max signals to sample (clamped `[1, 1000]` by the SQL builder; default
    /// 100).
    pub limit: Option<u32>,
}

/// One security detection signal touching a service's host/IP (NAN-1542).
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct SecuritySignal {
    /// Signal timestamp (RFC3339).
    pub ts: String,
    /// The detection rule name that fired.
    pub rule_name: String,
    /// The matched host, when the entity was a hostname (else `null`).
    pub src_host: Option<String>,
    /// The matched IP, when the entity was an IP address (else `null`).
    pub src_ip: Option<String>,
    /// The signal severity.
    pub severity: String,
}

/// Response for the service security-signals cross-link.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct ServiceSecuritySignalsResponse {
    /// Number of distinct entities (src_ip + host) resolved for the service.
    pub host_count: usize,
    /// Number of security signals returned (bounded by `limit`).
    pub signal_count: usize,
    /// The bounded signal sample, most recent first.
    pub signals: Vec<serde_json::Value>,
}

/// Security signals firing against a service's hosts/IPs.
///
/// Resolves the service's distinct entities (src_ip + host) from `otel_spans`
/// over the window, then returns the security DETECTION signals (ClickHouse
/// `signals`) whose matched `risk_entity` is one of those entities — the
/// convergence cross-link in the Observability service-detail view. Bounded +
/// injection-safe. Requires `search:view`.
#[utoipa::path(
    get,
    path = "/api/observability/services/{service}/security-signals",
    tag = "observability",
    params(
        ("service" = String, Path, description = "service.name to cross-link"),
        ServiceSecuritySignalsParams,
    ),
    responses(
        (status = 200, description = "Security signals against the service's hosts/IPs", body = ServiceSecuritySignalsResponse),
        (status = 400, description = "Invalid input", body = ErrorResponse),
        (status = 403, description = "Forbidden", body = ErrorResponse),
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn get_service_security_signals(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Path(service): Path<String>,
    Query(params): Query<ServiceSecuritySignalsParams>,
) -> Result<Json<ServiceSecuritySignalsResponse>, ApiError> {
    check_permission(&auth, permissions::SEARCH_VIEW)
        .map_err(|_| ApiError::Forbidden("Missing permission: search:view".to_string()))?;

    if service.trim().is_empty() {
        return Err(ApiError::BadRequest("service must not be empty".to_string()));
    }

    // Resolve the window: explicit start/end win; else look back window_hours
    // (clamped to a sane 1..=720h / 30d range).
    let now = chrono::Utc::now();
    let window_hours = params.window_hours.clamp(1, 720);
    let end = params.end.unwrap_or(now);
    let begin = params
        .start
        .unwrap_or_else(|| end - chrono::Duration::hours(window_hours));
    if begin >= end {
        return Err(ApiError::BadRequest("start must be before end".to_string()));
    }
    let time_range = TimeRange::new(begin, end);

    let (host_count, signal_count, signals) = state
        .search_service
        .observability_service_security_signals(&service, &time_range, params.limit)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, service = %service, "service security-signals query failed");
            ApiError::InternalError("Failed to fetch service security signals".to_string())
        })?;

    Ok(Json(ServiceSecuritySignalsResponse {
        host_count,
        signal_count,
        signals,
    }))
}

#[derive(utoipa::OpenApi)]
#[openapi(
    paths(get_service_security_signals),
    components(schemas(ServiceSecuritySignalsResponse, SecuritySignal))
)]
pub struct ObservabilityServiceSignalsApiDoc;
