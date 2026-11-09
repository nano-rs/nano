// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-5102: concurrent requests through `request_id_middleware` on a
//! multi-thread runtime, under a real registry + fmt subscriber (what the
//! services install). With the span held entered across `.await`, request
//! tasks migrate between worker threads with their span still on the old
//! thread's stack; `tracing-subscriber` then panics in the registry
//! (`tried to clone a span ... that already closed`, sharded.rs) and the
//! connection task dies, which the edge reports as a 502. This test runs in
//! its own binary because it installs a global subscriber.

use axum::{body::Body, extract::Request, http::StatusCode, routing::get, Router};
use nanosiem_api_lib::request_id::request_id_middleware;
use tower::ServiceExt;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::registry::{LookupSpan, Registry};

const REQUESTS: usize = 10_000;

/// How many `request` spans enclose the current span. Exactly one when the
/// middleware's span follows its own future; more when another request's
/// span leaked onto this thread and became this request's parent.
fn enclosing_request_spans() -> usize {
    tracing::Span::current()
        .with_subscriber(|(id, dispatch)| {
            let registry = dispatch.downcast_ref::<Registry>()?;
            let span = registry.span(id)?;
            Some(span.scope().filter(|s| s.name() == "request").count())
        })
        .flatten()
        .unwrap_or(0)
}

async fn handler() -> StatusCode {
    for i in 0..4 {
        if enclosing_request_spans() != 1 {
            return StatusCode::INTERNAL_SERVER_ERROR;
        }
        let child = tracing::info_span!("handler_step", step = i);
        child.in_scope(|| tracing::info!("step"));
        if i % 2 == 0 {
            tokio::task::yield_now().await;
        } else {
            tokio::time::sleep(std::time::Duration::from_micros(50)).await;
        }
    }
    StatusCode::OK
}

#[test]
fn concurrent_requests_never_panic_the_span_registry() {
    let subscriber = tracing_subscriber::registry().with(
        tracing_subscriber::fmt::layer()
            .with_writer(std::io::sink)
            .with_ansi(false)
            .with_span_events(tracing_subscriber::fmt::format::FmtSpan::FULL),
    );
    tracing::subscriber::set_global_default(subscriber).expect("global subscriber");

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(8)
        .enable_all()
        .build()
        .unwrap();

    let (panics, failures) = runtime.block_on(async {
        let app = Router::new()
            .route("/", get(handler))
            .layer(axum::middleware::from_fn(request_id_middleware));
        let tasks: Vec<_> = (0..REQUESTS)
            .map(|_| {
                let app = app.clone();
                tokio::spawn(async move {
                    app.oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
                        .await
                        .map(|r| r.status())
                })
            })
            .collect();
        let (mut panics, mut failures) = (0usize, 0usize);
        for task in tasks {
            match task.await {
                Ok(Ok(StatusCode::OK)) => {}
                Ok(_) => failures += 1,
                Err(e) if e.is_panic() => panics += 1,
                Err(_) => failures += 1,
            }
        }
        (panics, failures)
    });

    assert_eq!(panics, 0, "{panics}/{REQUESTS} request tasks panicked");
    assert_eq!(
        failures, 0,
        "{failures}/{REQUESTS} requests ran inside another request's span or failed"
    );
}
