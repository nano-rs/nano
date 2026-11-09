// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-5102: the per-request span must follow the request's future, not the
//! worker thread. Holding `span.enter()` across `.await` left the span
//! entered on the thread while the task was parked, so other requests polled
//! on that thread ran inside it (`request{A}:request{B}` in the API logs), and
//! the registry's span stack drifted until `tracing-subscriber` panicked.

use super::*;
use axum::{body::Body, http::StatusCode, routing::get, Router};
use std::sync::Arc;
use tokio::sync::Barrier;
use tower::ServiceExt;

/// A handler that parks between two reads of the current span. Both
/// concurrent requests are inside their middleware span while parked,
/// so a span that is held entered on the thread (instead of instrumenting the
/// future) shows up as the *other* request's span after the barrier.
fn interleaving_router(barrier: Arc<Barrier>) -> Router {
    Router::new()
        .route(
            "/",
            get(move || {
                let barrier = barrier.clone();
                async move {
                    let before = tracing::Span::current().id();
                    barrier.wait().await;
                    // The last arrival passes the barrier without parking;
                    // park it here so the first arrival resumes while the
                    // second request is still in flight on the same thread.
                    tokio::task::yield_now().await;
                    let after = tracing::Span::current().id();
                    if before.is_some() && before == after {
                        StatusCode::OK
                    } else {
                        StatusCode::INTERNAL_SERVER_ERROR
                    }
                }
            }),
        )
        .layer(axum::middleware::from_fn(request_id_middleware))
}

fn request(id: &str) -> Request {
    Request::builder()
        .uri("/")
        .header(REQUEST_ID_HEADER, id)
        .body(Body::empty())
        .unwrap()
}

#[tokio::test(flavor = "current_thread")]
async fn request_span_does_not_leak_into_concurrent_request() {
    let _subscriber = tracing::subscriber::set_default(tracing_subscriber::registry());
    let app = interleaving_router(Arc::new(Barrier::new(2)));

    // Separate tasks on one thread, as a server runs connections: the
    // scheduler interleaves them, A parks first and resumes while B is parked.
    let a = tokio::spawn(app.clone().oneshot(request("req-a")));
    let b = tokio::spawn(app.clone().oneshot(request("req-b")));
    let (a, b) = (a.await.unwrap().unwrap(), b.await.unwrap().unwrap());

    assert_eq!(
        a.status(),
        StatusCode::OK,
        "request A resumed inside another request's span"
    );
    assert_eq!(
        b.status(),
        StatusCode::OK,
        "request B resumed inside another request's span"
    );
    assert_eq!(a.headers()["x-request-id"], "req-a");
    assert_eq!(b.headers()["x-request-id"], "req-b");
    assert!(
        tracing::Span::current().is_none(),
        "a request span stayed entered on the thread after the request finished"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn generated_request_id_is_returned() {
    let _subscriber = tracing::subscriber::set_default(tracing_subscriber::registry());
    let app = Router::new()
        .route("/", get(|| async { StatusCode::OK }))
        .layer(axum::middleware::from_fn(request_id_middleware));

    let response = app
        .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let id = response.headers()["x-request-id"].to_str().unwrap();
    assert!(Uuid::parse_str(id).is_ok(), "not a generated id: {id}");
}
