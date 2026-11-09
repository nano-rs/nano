// SPDX-License-Identifier: AGPL-3.0-or-later

//! Per-request panic isolation for the HTTP services (NAN-5102).
//!
//! Without it, a panic in a handler or middleware unwinds out of the hyper
//! connection task: tokio contains it, but the connection is torn down with no
//! response, which the edge reports as a 502 for that request and anything
//! queued on the same keep-alive connection. With it, the panicking request
//! gets a generic JSON 500 and every other request is untouched.
//!
//! This covers unwinding panics only. An abort (a stack overflow, a panic
//! while already panicking) still ends the process; those must be fixed at
//! the source, as the request-span leak in [`crate::request_id`] was.

use axum::response::{IntoResponse, Response};
use std::any::Any;
use tower_http::catch_panic::CatchPanicLayer;

use crate::ApiError;

/// The panic handler type, nameable so services can store the layer.
pub type PanicResponder = fn(Box<dyn Any + Send + 'static>) -> Response;

/// A `CatchPanicLayer` that logs the panic message server-side and answers
/// with the standard `INTERNAL_ERROR` body. The panic text never reaches the
/// client.
pub fn catch_panic_layer() -> CatchPanicLayer<PanicResponder> {
    CatchPanicLayer::custom(panic_response as PanicResponder)
}

fn panic_response(panic: Box<dyn Any + Send + 'static>) -> Response {
    let detail = panic
        .downcast_ref::<String>()
        .map(String::as_str)
        .or_else(|| panic.downcast_ref::<&str>().copied())
        .unwrap_or("non-string panic payload");
    tracing::error!(panic = %detail, "request handler panicked; answering 500");
    ApiError::InternalError("request handler panicked".to_string()).into_response()
}

#[cfg(test)]
#[path = "panic_isolation_tests.rs"]
mod tests;
