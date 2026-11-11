// SPDX-License-Identifier: AGPL-3.0-or-later

//! V2 license enforcement middleware.
//!
//! Enterprise-only routes receive [`licensed_surface_guard`]. Shared routes
//! are intentionally outside that layer and remain available at hard stop,
//! matching the open build boundary. [`license_guard`] only publishes grace /
//! hard-stop response headers across the shared router.

use axum::{
    extract::{Request, State},
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
use nanosiem_core::license::{LicenseState, LicenseStatus};
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::error::{ErrorDetail, ErrorResponse};

pub async fn licensed_surface_guard(
    State(license_status): State<Arc<RwLock<LicenseStatus>>>,
    request: Request,
    next: Next,
) -> Result<Response, Response> {
    let status = license_status.read().await.effective(chrono::Utc::now());
    if status.state != LicenseState::Locked {
        return Ok(next.run(request).await);
    }

    let body = ErrorResponse {
        error: ErrorDetail {
            code: "LICENSE_REQUIRED".to_string(),
            message: "This licensed feature is unavailable at the license hard stop. Open/core features and stored data remain available.".to_string(),
            details: None,
        },
    };
    Err((StatusCode::FORBIDDEN, Json(body)).into_response())
}

/// Publish the current license state on responses from the whole API.
///
/// - Active: pass through
/// - Grace period: pass through with X-License-State header
/// - Locked: shared/open routes continue with `X-License-State: locked`
///
/// Must be layered **before** auth middleware (outer to it) so it runs first.
pub async fn license_guard(
    State(license_status): State<Arc<RwLock<LicenseStatus>>>,
    request: Request,
    next: Next,
) -> Result<Response, Response> {
    let status = license_status.read().await.effective(chrono::Utc::now());

    match status.state {
        LicenseState::Active => Ok(next.run(request).await),

        LicenseState::GracePeriod => {
            let mut response = next.run(request).await;
            // Add header so frontend knows to show warning banner
            response
                .headers_mut()
                .insert("X-License-State", "grace_period".parse().unwrap());
            if let Some(grace_ends) = &status.grace_ends_at {
                response.headers_mut().insert(
                    "X-License-Grace-Ends",
                    grace_ends.to_rfc3339().parse().unwrap(),
                );
            }
            Ok(response)
        }

        LicenseState::Locked => {
            let mut response = next.run(request).await;
            response
                .headers_mut()
                .insert("X-License-State", "locked".parse().unwrap());
            Ok(response)
        }
    }
}

#[cfg(test)]
#[path = "license_guard_tests.rs"]
mod tests;
