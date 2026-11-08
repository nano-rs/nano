// SPDX-License-Identifier: AGPL-3.0-or-later

//! Tier-based API write access guard
//!
//! Blocks write operations (POST/PUT/DELETE/PATCH) for API key-authenticated
//! requests when the organization tier restricts API access to read-only.
//! JWT-authenticated (UI) requests are always allowed so dashboard users
//! are never blocked.

use axum::{
    extract::{Request, State},
    http::{Method, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
use sqlx::PgPool;

use super::auth::AuthContext;
use crate::error::{ErrorDetail, ErrorResponse};

/// Safe HTTP methods that are always allowed regardless of tier.
fn is_safe_method(method: &Method) -> bool {
    matches!(*method, Method::GET | Method::HEAD | Method::OPTIONS)
}

/// Middleware that enforces API write access restrictions based on the
/// organization's tier. Only applies to API key-authenticated requests
/// using non-safe HTTP methods.
///
/// Must be layered **after** auth_middleware (inner to it) so that
/// `AuthContext` is available in request extensions.
pub async fn api_write_guard(
    State(pool): State<PgPool>,
    request: Request,
    next: Next,
) -> Result<Response, Response> {
    // Only check non-safe methods
    if is_safe_method(request.method()) {
        return Ok(next.run(request).await);
    }

    // Only restrict API key auth — JWT (UI) users are unrestricted
    let is_api_key = request
        .extensions()
        .get::<AuthContext>()
        .map(|auth| auth.is_api_key)
        .unwrap_or(false);

    if !is_api_key {
        return Ok(next.run(request).await);
    }

    // Check tier limits
    let tier_settings = nanosiem_core::TierSettings::new(pool);
    match tier_settings.get_tier_limits().await {
        Ok(limits) => {
            if !limits.is_enforced() {
                return Ok(next.run(request).await);
            }
            if let Err(_) = nanosiem_core::check_api_write_access(&limits) {
                let body = ErrorResponse {
                    error: ErrorDetail {
                        code: "API_WRITE_RESTRICTED".to_string(),
                        message: "Write API access is not available on your plan. Upgrade to Growth or higher.".to_string(),
                        details: None,
                    },
                };
                return Err((StatusCode::FORBIDDEN, Json(body)).into_response());
            }
        }
        Err(e) => {
            // If we can't read tier settings, log and allow the request through.
            // Fail open — don't block legitimate API usage due to a transient DB issue.
            tracing::warn!(error = %e, "Failed to check tier limits for API write guard, allowing request");
        }
    }

    Ok(next.run(request).await)
}
