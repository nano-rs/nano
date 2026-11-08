// SPDX-License-Identifier: AGPL-3.0-or-later

//! Tests for the default API `Cache-Control` middleware (NAN-3198).

use super::*;
use axum::{routing::get, Router};
use tower::ServiceExt;

fn app() -> Router {
    Router::new()
        .route("/api/rules/{id}", get(|| async { "rule" }))
        .route(
            "/api/mitre",
            get(|| async {
                (
                    [(header::CACHE_CONTROL, "private, max-age=3600")],
                    "catalog",
                )
            }),
        )
        .route("/assets/app.js", get(|| async { "js" }))
        .fallback(not_found)
        .layer(axum::middleware::from_fn(api_default_cache_control))
}

async fn cache_control(path: &str) -> Option<String> {
    let response = app()
        .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
        .await
        .unwrap();
    response
        .headers()
        .get(header::CACHE_CONTROL)
        .map(|v| v.to_str().unwrap().to_string())
}

#[tokio::test]
async fn api_answers_default_to_no_store() {
    assert_eq!(
        cache_control("/api/rules/r1").await.as_deref(),
        Some(API_DEFAULT_CACHE_CONTROL)
    );
    // Unknown API paths (404) are not cacheable either.
    assert_eq!(
        cache_control("/api/nope").await.as_deref(),
        Some(API_DEFAULT_CACHE_CONTROL)
    );
}

#[tokio::test]
async fn explicit_cache_control_and_non_api_paths_are_untouched() {
    assert_eq!(
        cache_control("/api/mitre").await.as_deref(),
        Some("private, max-age=3600")
    );
    assert_eq!(cache_control("/assets/app.js").await, None);
}

#[test]
fn api_path_match_is_prefix_exact() {
    assert!(is_api_path("/api/rules"));
    assert!(is_api_path("/api"));
    assert!(!is_api_path("/apidocs"));
    assert!(!is_api_path("/swagger-ui"));
}
