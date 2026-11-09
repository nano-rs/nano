// SPDX-License-Identifier: AGPL-3.0-or-later

//! Request ID middleware shared by the Main API and the Search service
//!
//! Provides request ID extraction/generation for distributed tracing.
//! Propagates request IDs to downstream services (Ingest, Search).
//!
//! Requirements: 7.3 - X-Request-ID header propagation

use axum::{
    extract::Request,
    http::{HeaderName, HeaderValue},
    middleware::Next,
    response::Response,
};
use tracing::Instrument;
use uuid::Uuid;

/// Header name for request ID
pub const REQUEST_ID_HEADER: &str = "X-Request-ID";

/// Extension type for storing request ID in request extensions
#[derive(Clone, Debug)]
pub struct RequestId(pub String);

impl RequestId {
    /// Create a new random request ID
    pub fn new() -> Self {
        Self(Uuid::now_v7().to_string())
    }

    /// Create from an existing ID string
    pub fn from_string(id: String) -> Self {
        Self(id)
    }

    /// Get the request ID as a string slice
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Default for RequestId {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for RequestId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Middleware that extracts or generates a request ID
///
/// If the incoming request has an X-Request-ID header, it will be used.
/// Otherwise, a new UUID will be generated.
///
/// The request ID is:
/// 1. Added to request extensions for use in handlers
/// 2. Added to the tracing span for log correlation
/// 3. Added to the response headers
///
/// Requirements: 7.3
pub async fn request_id_middleware(mut request: Request, next: Next) -> Response {
    // Extract existing request ID or generate a new one
    let request_id = request
        .headers()
        .get(REQUEST_ID_HEADER)
        .and_then(|v| v.to_str().ok())
        .map(|s| RequestId::from_string(s.to_string()))
        .unwrap_or_else(RequestId::new);

    // Create a tracing span with the request ID
    let span = tracing::info_span!(
        "request",
        request_id = %request_id,
        method = %request.method(),
        uri = %request.uri(),
    );

    // Add request ID to extensions for use in handlers
    request.extensions_mut().insert(request_id.clone());

    // NAN-5102: instrument the inner future; never hold `span.enter()`
    // across `.await`. An entered guard stays on the worker thread's span
    // stack while the task is parked, so every request polled on that thread
    // meanwhile runs inside this span and parents its own spans to it. Under
    // load that chained requests into `request{A}:request{B}:…`, tripped
    // tracing-subscriber's registry assertions, and the recursive close of the
    // ever-deeper chain overflowed the stack, aborting the whole process.
    let start = std::time::Instant::now();
    let response = next.run(request).instrument(span.clone()).await;
    let duration_ms = start.elapsed().as_millis() as u64;
    let status = response.status().as_u16();
    span.in_scope(|| {
        tracing::info!(
            status = status,
            duration_ms = duration_ms,
            "Request completed"
        );
    });

    // Add request ID to response headers
    let mut response = response;
    if let Ok(header_value) = HeaderValue::from_str(request_id.as_str()) {
        response
            .headers_mut()
            .insert(HeaderName::from_static("x-request-id"), header_value);
    }

    response
}

#[cfg(test)]
#[path = "request_id_tests.rs"]
mod tests;
