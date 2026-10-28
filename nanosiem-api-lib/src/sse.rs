// SPDX-License-Identifier: AGPL-3.0-or-later

//! Server-Sent Events must reach the client unbuffered (NAN-4753).
//!
//! Hosted regions put an NGINX ingress (default `proxy_buffering on`) between
//! Cloudflare and the API. NGINX holds a streamed response, headers included,
//! in its proxy buffer until the buffer fills or the upstream finishes. A
//! slow SSE stream that only sends 15 s keep-alives therefore shows Cloudflare
//! nothing at all, and after 100 s Cloudflare answers the browser with a 524
//! HTML page. That is what happened to the AU parser-draft stream on
//! 2026-10-27/28.
//!
//! `X-Accel-Buffering: no` is NGINX's per-response opt-out, so every
//! `text/event-stream` response carries it. The header is harmless to every
//! other proxy. `Cache-Control: no-cache` is added when the handler did not
//! choose its own caching, as the SSE spec recommends.

use axum::{
    body::Body,
    http::{header, HeaderName, HeaderValue, Request},
    middleware::Next,
    response::Response,
};

/// NGINX's per-response proxy-buffering switch.
pub const X_ACCEL_BUFFERING: HeaderName = HeaderName::from_static("x-accel-buffering");

/// Whether `response` is a Server-Sent Events stream.
pub fn is_event_stream(headers: &axum::http::HeaderMap) -> bool {
    headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| {
            v.split(';')
                .next()
                .is_some_and(|mime| mime.trim().eq_ignore_ascii_case("text/event-stream"))
        })
}

/// Mark every SSE response so reverse proxies stream it instead of buffering.
pub fn mark_unbuffered(response: &mut Response) {
    if !is_event_stream(response.headers()) {
        return;
    }
    let headers = response.headers_mut();
    headers.insert(X_ACCEL_BUFFERING, HeaderValue::from_static("no"));
    if !headers.contains_key(header::CACHE_CONTROL) {
        headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-cache"));
    }
}

/// Middleware form of [`mark_unbuffered`].
pub async fn sse_unbuffered(req: Request<Body>, next: Next) -> Response {
    let mut response = next.run(req).await;
    mark_unbuffered(&mut response);
    response
}

#[cfg(test)]
mod tests {
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
}
