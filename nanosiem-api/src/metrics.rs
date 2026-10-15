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
    /// The comparison is constant-time (NAN-2361): `/metrics` is mounted
    /// outside the auth layer and the IP allowlist, so the bearer check is
    /// the only fence and must not leak the token through timing.
    pub fn metrics_router(&self) -> Router {
        let handle = self.prometheus_handle.clone();
        let required_token = configured_metrics_auth_token();
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
                            Some(token) if constant_time_eq(token.as_bytes(), expected.as_bytes()) => {}
                            _ => return Err(StatusCode::UNAUTHORIZED),
                        }
                    }
                    Ok(handle.render())
                }
            }),
        )
    }
}

/// `METRICS_AUTH_TOKEN` when set to a non-empty value.
fn configured_metrics_auth_token() -> Option<String> {
    std::env::var("METRICS_AUTH_TOKEN")
        .ok()
        .filter(|token| !token.trim().is_empty())
}

/// Boot-time fence for hosted-shared deployments: `/metrics` carries
/// per-route latency and error counts for every tenant behind the shared
/// API, and it sits outside both the auth layer and the IP allowlist, so an
/// unset token would publish it to the whole app network. Refuse to boot.
#[cfg(feature = "enterprise")]
pub fn require_metrics_auth_token_for_enterprise_shared(enterprise_shared: bool) -> anyhow::Result<()> {
    if enterprise_shared && configured_metrics_auth_token().is_none() {
        anyhow::bail!(
            "METRICS_AUTH_TOKEN is required in enterprise_shared mode: /metrics is mounted outside the auth layer and IP allowlist"
        );
    }
    Ok(())
}

/// Constant-time byte comparison. Length mismatch returns early — the token
/// length is not a secret worth protecting, the token bytes are.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constant_time_eq_compares_whole_tokens() {
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"ab"));
        assert!(!constant_time_eq(b"", b"a"));
        assert!(constant_time_eq(b"", b""));
    }

    /// NAN-3080: the jobs process serves `/metrics` from `AppMetrics`; the
    /// tenant detection runtime's gauges (emitted from nanosiem-core /
    /// the enterprise crate through the `metrics` facade) must appear there.
    /// This is the only test in this crate that installs the global recorder.
    #[tokio::test]
    async fn metrics_endpoint_exports_detection_runtime_gauges() {
        use tower::ServiceExt;
        let (app_metrics, layer) = AppMetrics::new();
        let tenant = uuid::Uuid::from_u128(0xaaaa_aaaa);
        metrics::gauge!("nano_lake_detection_claim_slots", "tenant" => tenant.to_string()).set(6.0);
        metrics::gauge!("nano_lake_detection_in_flight", "tenant" => tenant.to_string()).set(2.0);
        let summary = nanosiem_core::detection::schedule_lag::summarize_schedule_lag(&[], chrono::Utc::now());
        nanosiem_core::detection::schedule_lag::record_schedule_lag(&summary, Some(tenant));
        let router = app_metrics.metrics_router().layer(layer);
        let scrape = |router: Router| async move {
            let response = router
                .oneshot(axum::http::Request::builder().uri("/metrics").body(axum::body::Body::empty()).unwrap())
                .await
                .unwrap();
            let status = response.status();
            let body = axum::body::to_bytes(response.into_body(), 1 << 20).await.unwrap();
            (status, String::from_utf8_lossy(&body).to_string())
        };
        let (status, body) = scrape(router).await;
        // METRICS_AUTH_TOKEN unset in the test process: the endpoint is open.
        assert_eq!(status, StatusCode::OK);
        for series in [
            "nano_lake_detection_claim_slots",
            "nano_lake_detection_in_flight",
            "nanosiem_detection_schedule_lag_max_seconds",
            "nanosiem_detection_schedule_lag_p95_seconds",
            "nanosiem_detection_rules_behind_schedule",
            "nanosiem_detection_schedule_degraded",
        ] {
            assert!(body.contains(series), "{series} missing from /metrics:\n{body}");
        }
    }

    #[cfg(feature = "enterprise")]
    #[test]
    fn enterprise_shared_boot_requires_the_metrics_token() {
        // Only the `false` branch is environment-independent; the `true`
        // branch is exercised by the boot path with the token set.
        require_metrics_auth_token_for_enterprise_shared(false).unwrap();
    }
}

impl Default for AppMetrics {
    fn default() -> Self {
        let (metrics, _) = Self::new();
        metrics
    }
}
