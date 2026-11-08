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
#[path = "sse_tests.rs"]
mod tests;
