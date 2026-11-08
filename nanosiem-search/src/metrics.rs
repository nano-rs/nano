// SPDX-License-Identifier: AGPL-3.0-or-later

//! Prometheus metrics for NanoSIEM Search Service
//!
//! Provides HTTP request metrics and search query latency tracking.

use axum::http::StatusCode;
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
    ///
    /// NAN-2042: `/metrics` is a private service route. It requires the shared
    /// service credential (`NANO_SERVICE_TOKEN`, falling back to
    /// `METRICS_AUTH_TOKEN`) as `Authorization: Bearer <token>`, always — the
    /// search listener is user-facing (often behind a same-host proxy), so a
    /// loopback peer proves nothing. The server must
    /// be started with `into_make_service_with_connect_info::<SocketAddr>()`,
    /// otherwise the peer is unknown and an unconfigured listener refuses all.
    pub fn metrics_router(&self) -> Router {
        self.metrics_router_with(
            nanosiem_core::auth::service_credential::ServiceCredential::from_env(),
        )
    }

    /// [`Self::metrics_router`] with an explicit credential (tests).
    pub fn metrics_router_with(
        &self,
        credential: nanosiem_core::auth::service_credential::ServiceCredential,
    ) -> Router {
        let handle = self.prometheus_handle.clone();
        let credential = std::sync::Arc::new(credential);
        Router::new().route(
            "/metrics",
            get(move |request: axum::extract::Request| {
                let handle = handle.clone();
                let credential = credential.clone();
                async move {
                    if !private_route_admitted(
                        &credential,
                        &request,
                        nanosiem_core::auth::service_credential::LoopbackPolicy::RequireToken,
                    ) {
                        return Err(StatusCode::UNAUTHORIZED);
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

/// NAN-2042: admission for a private service route. Exactly one
/// `Authorization` header is considered (a repeated header is refused), and the
/// peer is the TCP peer from `ConnectInfo`, never a forwarded-for header.
pub fn private_route_admitted(
    credential: &nanosiem_core::auth::service_credential::ServiceCredential,
    request: &axum::extract::Request,
    loopback: nanosiem_core::auth::service_credential::LoopbackPolicy,
) -> bool {
    let mut values = request.headers().get_all(axum::http::header::AUTHORIZATION).iter();
    let authorization = match (values.next(), values.next()) {
        (Some(v), None) => v.to_str().ok(),
        _ => None,
    };
    // Same lookup order as axum's `ConnectInfo` extractor: the real listener
    // peer first, then a test `MockConnectInfo` layer.
    let extensions = request.extensions();
    let peer = extensions
        .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
        .map(|info| info.0.ip())
        .or_else(|| {
            extensions
                .get::<axum::extract::connect_info::MockConnectInfo<std::net::SocketAddr>>()
                .map(|info| info.0.ip())
        });
    credential.admit(authorization, peer, loopback).is_allowed()
}

#[cfg(test)]
#[path = "metrics_tests.rs"]
mod tests;
