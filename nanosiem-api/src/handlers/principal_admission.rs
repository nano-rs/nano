// SPDX-License-Identifier: AGPL-3.0-or-later

//! HTTP glue for [`nanosiem_core::principal_gate`]: the principal key for an
//! authenticated caller, and the 429 + `Retry-After` refusal (security review
//! 2026-11-08).

use axum::http::{header::RETRY_AFTER, HeaderValue};
use axum::response::{IntoResponse, Response};
use nanosiem_core::principal_gate::{GatePermit, GateRefused};

use crate::error::ApiError;
use crate::middleware::AuthContext;

/// The admission key for `auth`: the API key id for an API key (a key is its
/// own principal, separate from its owner's interactive sessions), otherwise
/// the user id. Never the source address.
pub fn principal_key(auth: &AuthContext) -> String {
    match (auth.is_api_key, auth.api_key_id) {
        (true, Some(key)) => format!("api_key:{key}"),
        _ => format!("user:{}", auth.user_id()),
    }
}

/// HTTP 429 naming the limit, with `Retry-After`.
pub fn refused(refusal: GateRefused) -> Response {
    too_many_requests(refusal.to_string(), refusal.retry_after_secs)
}

/// HTTP 429 with `message` and `Retry-After: seconds`.
pub fn too_many_requests(message: String, seconds: u64) -> Response {
    let mut response = ApiError::TooManyRequests(message).into_response();
    if let Ok(value) = HeaderValue::from_str(&seconds.to_string()) {
        response.headers_mut().insert(RETRY_AFTER, value);
    }
    response
}

/// Run admitted `work` on its own task that owns `permit` until the work ends.
///
/// The work's CPU-heavy part runs on `spawn_blocking`, which a dropped request
/// cannot cancel. Holding the permit in the request future would free the slot
/// the moment the client disconnects while the blocking work keeps running, so
/// a client that connects and hangs up in a loop could pile up unbounded work.
/// Owning the permit in a detached task ties the slot to the work instead.
pub async fn run_admitted<F, T>(permit: GatePermit, work: F) -> Result<T, Response>
where
    F: std::future::Future<Output = T> + Send + 'static,
    T: Send + 'static,
{
    tokio::spawn(async move {
        let _permit = permit;
        work.await
    })
    .await
    .map_err(|e| ApiError::InternalError(format!("parser test task failed: {e}")).into_response())
}

#[cfg(test)]
#[path = "principal_admission_tests.rs"]
mod tests;
