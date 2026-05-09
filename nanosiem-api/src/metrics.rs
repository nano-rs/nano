// SPDX-License-Identifier: AGPL-3.0-or-later

//! Prometheus metrics for NanoSIEM API
//!
//! Provides HTTP request metrics, database pool metrics, and custom application metrics.

use axum::http::{HeaderMap, StatusCode};
use axum::{routing::get, Router};
use axum_prometheus::metrics_exporter_prometheus::PrometheusHandle;
use axum_prometheus::PrometheusMetricLayer;
use metrics::{counter, gauge, histogram};

/// Application metrics handles
pub struct AppMetrics {
    /// Handle to render Prometheus metrics
    prometheus_handle: PrometheusHandle,
}

impl AppMetrics {
    /// Create new application metrics with the Prometheus layer
    pub fn new() -> (Self, PrometheusMetricLayer<'static>) {
        let (prometheus_layer, metric_handle) = PrometheusMetricLayer::pair();

        (
            Self {
                prometheus_handle: metric_handle,
            },
            prometheus_layer,
        )
    }

    /// Create the metrics endpoint router.
    /// If `METRICS_AUTH_TOKEN` is set, requires `Authorization: Bearer <token>`.
    pub fn metrics_router(&self) -> Router {
        let handle = self.prometheus_handle.clone();
        let required_token = std::env::var("METRICS_AUTH_TOKEN")
            .ok()
            .filter(|t| !t.is_empty());
        Router::new().route(
            "/metrics",
            get(move |headers: HeaderMap| {
                let handle = handle.clone();
                let required_token = required_token.clone();
                async move {
                    if let Some(expected) = &required_token {
                        let provided = headers
                            .get("authorization")
                            .and_then(|v| v.to_str().ok())
                            .and_then(|v| v.strip_prefix("Bearer "));
                        match provided {
                            Some(token) if token == expected => {}
                            _ => return Err(StatusCode::UNAUTHORIZED),
                        }
                    }
                    Ok(handle.render())
                }
            }),
        )
    }
}

impl Default for AppMetrics {
    fn default() -> Self {
        let (metrics, _) = Self::new();
        metrics
    }
}

// =============================================================================
// Database Metrics
// =============================================================================

/// Record database query latency
pub fn record_db_query_latency(db_type: &str, operation: &str, duration_ms: f64) {
    histogram!(
        "nanosiem_db_query_duration_seconds",
        "db" => db_type.to_string(),
        "operation" => operation.to_string()
    )
    .record(duration_ms / 1000.0);
}

/// Record database pool statistics
pub fn record_pool_stats(db_type: &str, active: u32, idle: u32, max: u32) {
    gauge!(
        "nanosiem_db_pool_active_connections",
        "db" => db_type.to_string()
    )
    .set(active as f64);

    gauge!(
        "nanosiem_db_pool_idle_connections",
        "db" => db_type.to_string()
    )
    .set(idle as f64);

    gauge!(
        "nanosiem_db_pool_max_connections",
        "db" => db_type.to_string()
    )
    .set(max as f64);
}

// =============================================================================
// Detection Metrics
// =============================================================================

/// Record detection rule execution duration
pub fn record_detection_execution_duration(mode: &str, success: bool, duration_secs: f64) {
    histogram!(
        "nanosiem_detection_execution_duration_seconds",
        "mode" => mode.to_string(),
        "success" => success.to_string()
    )
    .record(duration_secs);
}

/// Record detection rule execution count
pub fn record_detection_execution_count(mode: &str, success: bool) {
    counter!(
        "nanosiem_detection_executions_total",
        "mode" => mode.to_string(),
        "success" => success.to_string()
    )
    .increment(1);
}

/// Record detection matches
pub fn record_detection_matches(mode: &str, severity: &str, count: u64) {
    counter!(
        "nanosiem_detection_matches_total",
        "mode" => mode.to_string(),
        "severity" => severity.to_string()
    )
    .increment(count);
}

/// Record mean time to detect (MTTD) — time from oldest matched event to detection
pub fn record_detection_mttd(severity: &str, mttd_seconds: f64) {
    histogram!(
        "nanosiem_detection_mttd_seconds",
        "severity" => severity.to_string()
    )
    .record(mttd_seconds);
}

/// Set the count of active alerts by severity
pub fn set_active_alerts_count(severity: &str, count: u64) {
    gauge!(
        "nanosiem_active_alerts",
        "severity" => severity.to_string()
    )
    .set(count as f64);
}

/// Set the count of detection rules
pub fn set_detection_rules_count(enabled: u64, total: u64) {
    gauge!("nanosiem_detection_rules_enabled").set(enabled as f64);
    gauge!("nanosiem_detection_rules_total").set(total as f64);
}

// =============================================================================
// Search Metrics
// =============================================================================

/// Record search query execution metrics
pub fn record_search_query(query_type: &str, duration_ms: f64, success: bool) {
    histogram!(
        "nanosiem_search_query_duration_seconds",
        "type" => query_type.to_string(),
        "success" => success.to_string()
    )
    .record(duration_ms / 1000.0);
}

// =============================================================================
// Ingestion Metrics
// =============================================================================

/// Record ingestion batch metrics
pub fn record_ingestion_batch(source_type: &str, event_count: u64, bytes: u64) {
    counter!(
        "nanosiem_ingestion_events_total",
        "source_type" => source_type.to_string()
    )
    .increment(event_count);

    counter!(
        "nanosiem_ingestion_bytes_total",
        "source_type" => source_type.to_string()
    )
    .increment(bytes);
}

// =============================================================================
// Service Health Metrics
// =============================================================================

/// Record service health status (1 = healthy, 0 = unhealthy)
pub fn set_service_health(service: &str, healthy: bool) {
    gauge!(
        "nanosiem_service_health",
        "service" => service.to_string()
    )
    .set(if healthy { 1.0 } else { 0.0 });
}

/// Record database latency from health checks
pub fn record_health_check_latency(db_type: &str, latency_ms: u64) {
    gauge!(
        "nanosiem_health_check_latency_ms",
        "db" => db_type.to_string()
    )
    .set(latency_ms as f64);
}
