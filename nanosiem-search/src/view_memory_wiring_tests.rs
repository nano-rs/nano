// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-3282: product-view routes run under their own view-memory ledger (an
//! oversized ClickHouse read there is a typed 413); other routes are not
//! budgeted.

use axum::{
    body::Body,
    extract::Request,
    http::StatusCode,
    middleware,
    response::{IntoResponse, Response},
    routing::post,
    Router,
};
use nanosiem_core::search::view_memory;
use tower::ServiceExt;

use crate::middleware::{
    product_view_memory_middleware, product_view_memory_name, PRODUCT_VIEW_MEMORY_ROUTES,
};

async fn report() -> Response {
    let view = view_memory::current().map(|ledger| ledger.view().to_string());
    // An answer far past any per-request budget.
    match view_memory::charge_wire_bytes(1 << 40).await {
        Ok(()) => view.unwrap_or_else(|| "unscoped".to_string()).into_response(),
        Err(error) => crate::error::SearchError::from(error).into_response(),
    }
}

#[tokio::test]
async fn product_view_routes_run_under_a_view_memory_ledger() {
    let app = Router::new()
        .route("/api/search/asset-dossier", post(report))
        .route("/api/search/tree-page", post(report))
        .route("/api/search", post(report))
        .layer(middleware::from_fn(product_view_memory_middleware));
    let send = |uri: &'static str| {
        let app = app.clone();
        async move {
            let response = app
                .oneshot(Request::builder().method("POST").uri(uri).body(Body::empty()).unwrap())
                .await
                .unwrap();
            let status = response.status();
            let body = axum::body::to_bytes(response.into_body(), 1 << 16).await.unwrap();
            (status, String::from_utf8(body.to_vec()).unwrap())
        }
    };
    for uri in ["/api/search/asset-dossier", "/api/search/tree-page"] {
        let (status, body) = send(uri).await;
        assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE, "{uri}: {body}");
        let body: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(body["error"]["code"], "VIEW_TOO_LARGE");
    }
    let (status, body) = send("/api/search").await;
    assert_eq!((status, body.as_str()), (StatusCode::OK, "unscoped"));

    assert_eq!(product_view_memory_name("/api/search/asset-events"), Some("asset-events"));
    assert_eq!(product_view_memory_name("/api/search/asset-events/x"), None);
    // Every budgeted route is a real route on the search router.
    let lib = include_str!("lib.rs");
    for (route, _) in PRODUCT_VIEW_MEMORY_ROUTES {
        assert!(lib.contains(&format!("\"{route}\"")), "{route} is not routed");
    }
}

/// A busy view budget is a retryable 503.
#[tokio::test]
async fn view_memory_busy_is_retryable() {
    let response = crate::SearchError::ViewMemoryBusy("busy".into()).into_response();
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(response.headers()[axum::http::header::RETRY_AFTER], "2");
}
