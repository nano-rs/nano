// SPDX-License-Identifier: AGPL-3.0-or-later

use super::*;
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::{middleware, routing::get, Router};
use std::convert::Infallible;
use tower::ServiceExt;

fn app() -> Router {
    Router::new()
        .route(
            "/stream",
            get(|| async {
                let events = futures::stream::iter(vec![Ok::<_, Infallible>(
                    Event::default().data("x"),
                )]);
                Sse::new(events).keep_alive(KeepAlive::default())
            }),
        )
        .route("/json", get(|| async { axum::Json(serde_json::json!({"ok": true})) }))
        .layer(middleware::from_fn(sse_unbuffered))
}

async fn headers(path: &str) -> axum::http::HeaderMap {
    let response = app()
        .oneshot(Request::get(path).body(Body::empty()).unwrap())
        .await
        .unwrap();
    response.headers().clone()
}

#[tokio::test]
async fn event_streams_opt_out_of_proxy_buffering() {
    let h = headers("/stream").await;
    assert_eq!(h.get("x-accel-buffering").unwrap(), "no");
    assert_eq!(h.get(header::CACHE_CONTROL).unwrap(), "no-cache");
}

#[tokio::test]
async fn other_responses_are_untouched() {
    let h = headers("/json").await;
    assert!(h.get("x-accel-buffering").is_none());
    assert!(h.get(header::CACHE_CONTROL).is_none());
}

#[test]
fn content_type_parameters_are_ignored() {
    let mut h = axum::http::HeaderMap::new();
    h.insert(header::CONTENT_TYPE, HeaderValue::from_static("Text/Event-Stream; charset=utf-8"));
    assert!(is_event_stream(&h));
    h.insert(header::CONTENT_TYPE, HeaderValue::from_static("application/json"));
    assert!(!is_event_stream(&h));
}
