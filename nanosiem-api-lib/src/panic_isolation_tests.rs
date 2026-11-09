// SPDX-License-Identifier: AGPL-3.0-or-later

use super::*;
use crate::request_id::request_id_middleware;
use axum::{
    body::Body,
    extract::Request,
    http::StatusCode,
    routing::get,
    Router,
};
use tower::ServiceExt;

async fn boom() -> StatusCode {
    panic!("secret internal detail")
}

/// The layer order the services use: request id outermost, panic isolation
/// inside it, handlers innermost.
fn app() -> Router {
    Router::new()
        .route("/boom", get(boom))
        .route("/ok", get(|| async { StatusCode::OK }))
        .layer(catch_panic_layer())
        .layer(axum::middleware::from_fn(request_id_middleware))
}

fn get_req(path: &str) -> Request {
    Request::builder()
        .uri(path)
        .header("x-request-id", "req-boom")
        .body(Body::empty())
        .unwrap()
}

#[tokio::test]
async fn handler_panic_answers_500_for_that_request_only() {
    let app = app();

    let response = app.clone().oneshot(get_req("/boom")).await.unwrap();
    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(
        response.headers()["x-request-id"],
        "req-boom",
        "the 500 must still carry the request id for correlation"
    );
    let body = axum::body::to_bytes(response.into_body(), 4096)
        .await
        .unwrap();
    let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(body["error"]["code"], "INTERNAL_ERROR");
    assert!(
        !body.to_string().contains("secret internal detail"),
        "panic text leaked to the client: {body}"
    );

    let next = app.oneshot(get_req("/ok")).await.unwrap();
    assert_eq!(next.status(), StatusCode::OK);
}
