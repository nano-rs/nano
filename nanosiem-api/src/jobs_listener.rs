// SPDX-License-Identifier: AGPL-3.0-or-later
//! The Jobs process has no customer API listener. Its private HTTP app has
//! explicit liveness plus service-identity-only metrics and diagnostics.
use crate::metrics::AppMetrics;
use axum::Router;
use nanosiem_api_lib::route_policy::{
    routing::get, Router as RegisteredRouter, ServiceAuthenticators,
};
use nanosiem_core::auth::route_policy::RoutePolicy;

fn registered_routes(metrics: &AppMetrics) -> RegisteredRouter {
    RegisteredRouter::new()
        .route("/health", get(|| async { "ok" }, RoutePolicy::public()))
        .merge(metrics.registered_routes())
        .merge(crate::routes::registered_hosted_config_routes())
}
pub fn route_manifest(metrics: &AppMetrics) -> Vec<nanosiem_api_lib::route_policy::Entry> {
    registered_routes(metrics).manifest().to_vec()
}
pub fn create_jobs_router(metrics: &AppMetrics) -> Router {
    let token = std::env::var("METRICS_AUTH_TOKEN").ok();
    registered_routes(metrics).into_private_router(
        ServiceAuthenticators::default()
            .bearer("operations-collector", token.clone(), "authorization")
            .bearer(
                "hosted-config-reader",
                token,
                "x-nano-service-authorization",
            ),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use nanosiem_core::auth::route_policy::AuthMode;
    use tower::ServiceExt;

    #[tokio::test]
    async fn production_jobs_route_policy_http_matrix() {
        const MARKER: &str = "12042";
        if std::env::var("JOBS_PORT").as_deref() != Ok(MARKER) {
            // One isolated process per configuration: do not mutate the global
            // metrics credential while the real recorder/runtime is running.
            for configured in [false, true] {
                let mut child = std::process::Command::new(std::env::current_exe().unwrap());
                child
                    .args([
                        "--exact",
                        "jobs_listener::tests::production_jobs_route_policy_http_matrix",
                        "--nocapture",
                    ])
                    .env("JOBS_PORT", MARKER);
                if configured {
                    child.env("METRICS_AUTH_TOKEN", "fixture-jobs-service-token");
                } else {
                    child.env_remove("METRICS_AUTH_TOKEN");
                }
                let output = child.output().unwrap();
                assert!(
                    output.status.success(),
                    "{}\n{}",
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr)
                );
            }
            return;
        }
        let configured = std::env::var("METRICS_AUTH_TOKEN").is_ok();
        let (metrics, _) = AppMetrics::new();
        let app = create_jobs_router(&metrics);
        let rows = route_manifest(&metrics);
        assert_eq!(rows.len(), if cfg!(feature = "enterprise") { 3 } else { 2 });
        let mut probes = 0;
        for row in &rows {
            let header = if row.path == "/internal/hosted-config" {
                "x-nano-service-authorization"
            } else {
                "authorization"
            };
            if row.path == "/health" {
                assert!(row.policy.is_public());
            } else {
                assert!(matches!(
                    row.policy.auth_mode(),
                    AuthMode::ServiceIdentity(_)
                ));
            }
            for credential in [
                None,
                Some("Bearer customer-jwt"),
                Some("Bearer unrelated-service"),
            ] {
                let mut request = Request::builder().uri(&row.path);
                if let Some(value) = credential {
                    request = request.header(header, value);
                }
                let response = app
                    .clone()
                    .oneshot(request.body(Body::from("{malformed")).unwrap())
                    .await
                    .unwrap();
                assert_eq!(
                    response.status(),
                    if row.policy.is_public() {
                        StatusCode::OK
                    } else {
                        StatusCode::UNAUTHORIZED
                    },
                    "{}",
                    row.path
                );
                probes += 1;
            }
            if !row.policy.is_public() {
                let response = app
                    .clone()
                    .oneshot(
                        Request::builder()
                            .uri(&row.path)
                            .header("x-api-key", "fixture-customer-api-key")
                            .body(Body::empty())
                            .unwrap(),
                    )
                    .await
                    .unwrap();
                assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
                probes += 1;
            }
            if !row.policy.is_public() {
                let duplicate = Request::builder()
                    .uri(&row.path)
                    .header(header, "Bearer fixture-jobs-service-token")
                    .header(header, "Bearer fixture-jobs-service-token")
                    .body(Body::empty())
                    .unwrap();
                assert_eq!(
                    app.clone().oneshot(duplicate).await.unwrap().status(),
                    StatusCode::UNAUTHORIZED
                );
                probes += 1;
            }
            for method in ["GET", "HEAD"] {
                let response = app
                    .clone()
                    .oneshot(
                        Request::builder()
                            .method(method)
                            .uri(&row.path)
                            .header(header, "Bearer fixture-jobs-service-token")
                            .body(Body::empty())
                            .unwrap(),
                    )
                    .await
                    .unwrap();
                assert_eq!(
                    response.status(),
                    if row.policy.is_public() || configured {
                        StatusCode::OK
                    } else {
                        StatusCode::UNAUTHORIZED
                    },
                    "{method} {}",
                    row.path
                );
                probes += 1;
            }
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method("DELETE")
                        .uri(&row.path)
                        .header(header, "Bearer fixture-jobs-service-token")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert!(!response.status().is_success(), "undeclared private verb");
            probes += 1;
        }
        assert_eq!(
            app.oneshot(
                Request::builder()
                    .uri("/internal/unclassified")
                    .header("authorization", "Bearer fixture-jobs-service-token")
                    .body(Body::empty())
                    .unwrap()
            )
            .await
            .unwrap()
            .status(),
            StatusCode::FORBIDDEN
        );
        eprintln!("Jobs production RoutePolicy HTTP probes: {probes}; configured={configured}");
    }
}
