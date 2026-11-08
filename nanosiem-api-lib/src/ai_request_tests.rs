// SPDX-License-Identifier: AGPL-3.0-or-later

use super::*;
use axum::body::Body;
use axum::http::Request;
use axum::{middleware, routing::post, Router};
use tower::ServiceExt;

#[test]
fn nan4753_async_requires_explicit_preference() {
    let mut headers = HeaderMap::new();
    assert!(!prefers_async(&headers));
    headers.insert("prefer", "wait=5, Respond-Async".parse().unwrap());
    assert!(prefers_async(&headers));
    headers.insert("prefer", "respond-async=false".parse().unwrap());
    assert!(!prefers_async(&headers));
}

#[test]
fn wizard_deadline_leaves_headroom_under_a_100s_edge() {
    assert!(WIZARD_HTTP_TIMEOUT < std::time::Duration::from_secs(100));
    assert!(WIZARD_HTTP_TIMEOUT >= std::time::Duration::from_secs(60));
}

#[tokio::test(start_paused = true)]
async fn nan4753_slow_sse_sends_headers_immediately_and_keeps_flowing() {
    use axum::response::sse::{Event, KeepAlive, Sse};
    use futures::StreamExt;
    use std::convert::Infallible;

    let app = Router::new()
        .route(
            "/api/melod/parser/stream",
            post(|| async {
                Sse::new(futures::stream::pending::<Result<Event, Infallible>>())
                    .keep_alive(KeepAlive::new().interval(std::time::Duration::from_secs(15)))
            }),
        )
        .layer(middleware::from_fn(crate::sse::sse_unbuffered));
    let started = tokio::time::Instant::now();
    let response = app
        .oneshot(
            Request::post("/api/melod/parser/stream")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.headers()["x-accel-buffering"], "no");
    assert!(started.elapsed() < std::time::Duration::from_secs(1));
    let first = response
        .into_body()
        .into_data_stream()
        .next()
        .await
        .unwrap()
        .unwrap();
    assert!(!first.is_empty());
    assert_eq!(started.elapsed(), std::time::Duration::from_secs(15));
}
