// SPDX-License-Identifier: AGPL-3.0-or-later

//! License enforcement middleware
//!
//! Blocks all API requests when the deployment's license is in locked state.
//! During grace period, requests are allowed but a header is added to signal
//! the frontend to show a warning banner.
//!
//! Self-hosted deployments without heartbeat configured are never blocked.

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

/// Endpoints that are never blocked by license enforcement.
/// Health check must remain accessible for monitoring, and the license
/// status endpoint must be readable so the frontend can show the right UI.
const LICENSE_EXEMPT_PREFIXES: &[&str] = &[
    "/health",
    "/api/license",
    "/api/auth/login",
    "/api/auth/refresh",
    "/api/setup",
    "/swagger-ui",
    "/api-docs",
    "/metrics",
    // Build edition + capability flags. The SPA hits this on boot to decide
    // which surfaces to render (incl. whether to show the license lockout
    // overlay at all); a Locked install that 403'd it would render blank with
    // no recovery path (NAN-1222).
    "/api/capabilities",
    // Offline-license import is the ONLY recovery path for a fail-closed
    // air-gapped install (NAN-1222). It must stay reachable while Locked, or
    // the operator can never unlock. Scoped to the exact license-import route —
    // the other /api/airgap/* bundle imports (parsers/enrichment/rules/
    // playbooks) intentionally remain guarded and require a valid license.
    "/api/airgap/license/import",
];

/// Middleware that enforces license status on all API requests.
///
/// - Active: pass through
/// - Grace period: pass through with X-License-State header
/// - Locked: return 403 with clear error message
///
/// Must be layered **before** auth middleware (outer to it) so it runs first.
pub async fn license_guard(
    State(license_status): State<Arc<RwLock<LicenseStatus>>>,
    request: Request,
    next: Next,
) -> Result<Response, Response> {
    let path = request.uri().path();

    // Always allow exempt endpoints
    if LICENSE_EXEMPT_PREFIXES
        .iter()
        .any(|prefix| path.starts_with(prefix))
    {
        return Ok(next.run(request).await);
    }

    // Compute the effective status: read-time `expires_at` enforcement degrades
    // an expired (incl. offline air-gap) license to Locked with no network
    // (NAN-1206 / WS4). Online installs never carry a past `expires_at` while
    // Active, so this is a no-op for them.
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
            let body = ErrorResponse {
                error: ErrorDetail {
                    code: "LICENSE_EXPIRED".to_string(),
                    message: "Your subscription has expired. Data is preserved but inaccessible. Resubscribe at app.nano.rs to restore access.".to_string(),
                    details: None,
                },
            };
            Err((StatusCode::FORBIDDEN, Json(body)).into_response())
        }
    }
}
