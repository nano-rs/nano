// SPDX-License-Identifier: AGPL-3.0-or-later

//! Prometheus metrics for NanoSIEM API
//!
//! Provides HTTP request metrics, database pool metrics, and custom application metrics.

use axum::http::StatusCode;
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
    ///
    /// NAN-2042: `/metrics` is a private service route. It requires the shared
    /// service credential (`NANO_SERVICE_TOKEN`, falling back to
    /// `METRICS_AUTH_TOKEN`) as `Authorization: Bearer <token>`. `loopback`
    /// is `RequireToken` on the user-facing api listener (a same-host proxy
    /// makes remote requests arrive from loopback) and
    /// `AllowWhenUnconfigured` only on jobs' loopback-bound listener. The server must
    /// be started with `into_make_service_with_connect_info::<SocketAddr>()`,
    /// otherwise the peer is unknown and an unconfigured listener refuses all.
    pub fn metrics_router(
        &self,
        loopback: nanosiem_core::auth::service_credential::LoopbackPolicy,
    ) -> Router {
        self.metrics_router_with(
            nanosiem_core::auth::service_credential::ServiceCredential::from_env(),
            loopback,
        )
    }

    /// [`Self::metrics_router`] with an explicit credential (tests).
    pub fn metrics_router_with(
        &self,
        credential: nanosiem_core::auth::service_credential::ServiceCredential,
        loopback: nanosiem_core::auth::service_credential::LoopbackPolicy,
    ) -> Router {
        let handle = self.prometheus_handle.clone();
        let credential = std::sync::Arc::new(credential);
        Router::new().route(
            "/metrics",
            get(move |request: axum::extract::Request| {
                let handle = handle.clone();
                let credential = credential.clone();
                async move {
                    if !private_route_admitted(&credential, &request, loopback) {
                        return Err(StatusCode::UNAUTHORIZED);
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
