// SPDX-License-Identifier: AGPL-3.0-or-later

//! Default `Cache-Control` for API responses (NAN-3198).
//!
//! API answers are tenant data behind credentials. Without an explicit
//! `Cache-Control`, a shared HTTP cache on the path (a corporate TLS-inspecting
//! proxy, a CDN rule) may store a GET answer heuristically and replay it to
//! later callers: an `x-api-key` request carries no `Authorization` header,
//! so such caches do not treat it as authenticated. On 2026-10-07 a
//! workstation MITM proxy replayed `/api/rules/{id}`, `/api/alerts` and
//! `/api/risk/entities` answers for 20+ minutes, which froze the e2e detection
//! tester's view of rule runs, alerts and risk (and would serve one caller's
//! tenant data to the next).
//!
//! Every `/api/` response without its own `Cache-Control` therefore gets
//! `private, no-store`. Routes that opt into caching (`/api/mitre`, static
//! metadata) set the header themselves and are left untouched.

use axum::{
    body::Body,
    http::{header, HeaderValue, Request},
    middleware::Next,
    response::Response,
};

/// The default for API responses that do not choose their own caching.
pub const API_DEFAULT_CACHE_CONTROL: &str = "private, no-store";

/// Whether a request path is an API path whose answer must not be stored by
/// shared caches unless the handler says otherwise.
pub fn is_api_path(path: &str) -> bool {
    path == "/api" || path.starts_with("/api/")
}

/// Insert [`API_DEFAULT_CACHE_CONTROL`] on `/api/` responses that carry no
/// `Cache-Control` of their own.
pub async fn api_default_cache_control(req: Request<Body>, next: Next) -> Response {
    let api = is_api_path(req.uri().path());
    let mut response = next.run(req).await;
    if api && !response.headers().contains_key(header::CACHE_CONTROL) {
        response.headers_mut().insert(
            header::CACHE_CONTROL,
            HeaderValue::from_static(API_DEFAULT_CACHE_CONTROL),
        );
    }
    response
}

#[cfg(test)]
mod tests {
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
}
