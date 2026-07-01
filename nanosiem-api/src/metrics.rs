// SPDX-License-Identifier: AGPL-3.0-or-later

//! Prometheus metrics for NanoSIEM API
//!
//! Provides HTTP request metrics, database pool metrics, and custom application metrics.

use axum::http::{HeaderMap, StatusCode};
use axum::{routing::get, Router};
use axum_prometheus::metrics_exporter_prometheus::PrometheusHandle;
use axum_prometheus::PrometheusMetricLayer;

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
