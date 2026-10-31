// SPDX-License-Identifier: AGPL-3.0-or-later

//! Prometheus metrics for NanoSIEM Search Service
//!
//! Provides HTTP request metrics and search query latency tracking.

use axum::Router;
use axum_prometheus::metrics_exporter_prometheus::PrometheusHandle;
use axum_prometheus::PrometheusMetricLayer;
use metrics::histogram;

/// Application metrics handles
pub struct SearchMetrics {
    /// Handle to render Prometheus metrics
    prometheus_handle: PrometheusHandle,
}

impl SearchMetrics {
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

    pub fn registered_routes(&self) -> nanosiem_api_lib::route_policy::Router {
        use nanosiem_api_lib::route_policy::{routing::get, Router};
        use nanosiem_core::auth::route_policy::RoutePolicy;
        let handle = self.prometheus_handle.clone();
        Router::new().route(
            "/metrics",
            get(
                move || {
                    let handle = handle.clone();
                    async move { handle.render() }
                },
                RoutePolicy::service("operations-collector", "telemetry:read"),
            ),
        )
    }
    /// Standalone private telemetry app. Missing credentials always deny.
    pub fn metrics_router(&self) -> Router {
        self.registered_routes().into_private_router(
            nanosiem_api_lib::route_policy::ServiceAuthenticators::default().bearer(
                "operations-collector",
                std::env::var("METRICS_AUTH_TOKEN").ok(),
                "authorization",
            ),
        )
    }
}

impl Default for SearchMetrics {
    fn default() -> Self {
        let (metrics, _) = Self::new();
        metrics
    }
}

/// Record search query execution metrics
pub fn record_search_query(query_type: &str, duration_ms: f64, success: bool) {
    histogram!(
        "nanosiem_search_query_duration_seconds",
        "type" => query_type.to_string(),
        "success" => success.to_string()
    )
    .record(duration_ms / 1000.0);
}

// ============================================================================
// Admission Control Metrics
// ============================================================================
//
// The following Prometheus metrics are emitted directly from the admission
// controller in nanosiem-core/src/search/admission.rs using the `metrics` crate:
//
// Counters:
//   nanosiem_search_jobs_admitted_total{priority}  — searches admitted by priority
//   nanosiem_search_jobs_queued_total              — searches that entered the queue
//   nanosiem_search_jobs_rejected_total{reason}    — searches refused or dropped: queue_timeout (wait
//                                                    budget ended), queue_full, principal_queue_full,
//                                                    client_gone (caller left while queued, never run)
//
// Histogram:
//   nanosiem_search_queue_wait_seconds{outcome}    — time spent queued (admitted, rejected, cancelled)
//
// Gauges:
//   nanosiem_search_queue_depth                    — current queue depth
//   nanosiem_search_active_queries                 — current concurrent ad-hoc queries
