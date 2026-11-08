// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-4930: the search service applies the shared `private, no-store`
//! default (ingress routes `/api/search*` here), including to auth rejections
//! and handler errors, through the same layering `create_router` uses.

use super::DefaultCacheControl;
use crate::{auth_middleware, AuthState};
use axum::{
    body::Body,
    http::{header, Request, StatusCode},
    middleware as axum_middleware,
    routing::get,
    Router,
};
use nanosiem_api_lib::api_cache_control::API_DEFAULT_CACHE_CONTROL;
use tower::ServiceExt;

const SECRET: &str = "nan4930-search-cache-control-test-secret-0123456789";

fn app() -> Router {
    let auth = AuthState::from_jwt_secret(SECRET);
    Router::new()
        .route("/api/search/saved", get(|| async { "saved searches" }))
        .route(
            "/api/search/jobs/{id}/results",
            get(|| async { (StatusCode::NOT_FOUND, "no such job") }),
        )
        .route(
            "/api/search/cached",
            get(|| async { ([(header::CACHE_CONTROL, "private, max-age=30")], "cached") }),
        )
        .fallback(nanosiem_api_lib::api_cache_control::not_found)
        .layer(axum_middleware::from_fn_with_state(auth, auth_middleware))
        .pipe_default_cache_control()
}

fn bearer() -> String {
    let auth = AuthState::from_jwt_secret(SECRET);
    let token = auth
        .token_service
        .create_access_token(uuid::Uuid::now_v7(), vec!["Admin".into()])
        .expect("token");
    format!("Bearer {token}")
}

async fn get_path(path: &str, authorization: Option<&str>) -> (StatusCode, Option<String>) {
    let mut request = Request::builder().uri(path);
    if let Some(value) = authorization {
        request = request.header(header::AUTHORIZATION, value);
    }
    let response = app().oneshot(request.body(Body::empty()).unwrap()).await.unwrap();
    let cache = response
        .headers()
        .get(header::CACHE_CONTROL)
        .map(|v| v.to_str().unwrap().to_string());
    (response.status(), cache)
}

#[tokio::test]
async fn authenticated_search_get_is_no_store() {
    let (status, cache) = get_path("/api/search/saved", Some(&bearer())).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(cache.as_deref(), Some(API_DEFAULT_CACHE_CONTROL));
}

#[tokio::test]
async fn search_errors_and_auth_rejections_are_no_store() {
    let (status, cache) = get_path("/api/search/jobs/j1/results", Some(&bearer())).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(cache.as_deref(), Some(API_DEFAULT_CACHE_CONTROL));

    let (status, cache) = get_path("/api/search/saved", None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(cache.as_deref(), Some(API_DEFAULT_CACHE_CONTROL));
}

#[tokio::test]
async fn a_handler_choosing_its_own_caching_keeps_it() {
    let (status, cache) = get_path("/api/search/cached", Some(&bearer())).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(cache.as_deref(), Some("private, max-age=30"));
}

#[tokio::test]
async fn an_unknown_search_path_is_no_store() {
    let (status, cache) = get_path("/api/search/nope", Some(&bearer())).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(cache.as_deref(), Some(API_DEFAULT_CACHE_CONTROL));
}
