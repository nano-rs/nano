// SPDX-License-Identifier: AGPL-3.0-or-later

//! Prometheus metrics for NanoSIEM Search Service
//!
//! Provides HTTP request metrics and search query latency tracking.

use axum::http::{HeaderMap, StatusCode};
use axum::{Router, routing::get};
use axum_prometheus::PrometheusMetricLayer;
use axum_prometheus::metrics_exporter_prometheus::PrometheusHandle;
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
//   nanosiem_search_jobs_rejected_total{reason}    — searches rejected (user_limit, queue_full, queue_timeout)
//
// Histogram:
//   nanosiem_search_queue_wait_seconds             — time spent waiting in queue before admission
//
// Gauges:
//   nanosiem_search_queue_depth                    — current queue depth
//   nanosiem_search_active_queries                 — current concurrent ad-hoc queries
