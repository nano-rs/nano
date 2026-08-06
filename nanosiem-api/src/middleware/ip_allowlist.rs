// SPDX-License-Identifier: AGPL-3.0-or-later

//! IP Allowlist Middleware
//!
//! Blocks requests from IPs not on the allowlist.
//! Runs before auth middleware so denied IPs never hit authentication.
//! Bypasses health/ready endpoints so infrastructure probes always work.

use axum::{
    extract::{ConnectInfo, Request, State},
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
use serde::Serialize;
use std::net::SocketAddr;
use std::sync::Arc;

use nanosiem_core::ip_allowlist::{IpAllowlistScope, IpAllowlistService};

/// Endpoints that bypass IP allowlist checks (infrastructure probes)
const BYPASS_ENDPOINTS: &[&str] = &["/health", "/ready", "/livez", "/metrics"];

/// State for the IP allowlist middleware
#[derive(Clone)]
pub struct IpAllowlistState {
    pub service: Arc<IpAllowlistService>,
    pub scope: IpAllowlistScope,
}

/// Response body for IP-denied requests
#[derive(Debug, Serialize)]
struct IpDeniedResponse {
    error: IpDeniedError,
}

#[derive(Debug, Serialize)]
struct IpDeniedError {
    code: &'static str,
    message: String,
}

/// IP allowlist middleware function
///
/// Must be applied as an outer layer (before auth) so denied IPs
/// are rejected without any authentication processing.
pub async fn ip_allowlist_middleware(
    State(state): State<IpAllowlistState>,
    request: Request,
    next: Next,
) -> Response {
    let path = request.uri().path();

    // Always allow infrastructure probe endpoints
    for bypass in BYPASS_ENDPOINTS {
        if path == *bypass {
            return next.run(request).await;
        }
    }

    // NAN-1931: the Vector config-consumer sidecar is in-cluster
    // infrastructure, like the probes above — a tenant-configured UI/API
    // allowlist must not be able to freeze config delivery to Vector. The
    // endpoints carry their own VECTOR_AUTH_TOKEN bearer gate.
    if path.starts_with("/api/internal/vector-config/") {
        return next.run(request).await;
    }

    // Extract ConnectInfo from request extensions (set by into_make_service_with_connect_info)
    let connect_info = request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ci| ci.0);
    let headers = request.headers();
    let client_ip = crate::utils::extract_client_ip(headers, connect_info.as_ref());

    let ip_str = match client_ip {
        Some(ref ip) => ip.as_str(),
        None => {
            // If we can't determine the client IP, deny by default when allowlist is active
            tracing::warn!(
                "Could not extract client IP for allowlist check — denying request to {}",
                path
            );
            return ip_denied_response("unknown");
        }
    };

    // Check against the allowlist
    if !state.service.is_allowed(ip_str, state.scope).await {
        tracing::info!(
            ip = %ip_str,
            path = %path,
            scope = %state.scope,
            "IP denied by allowlist"
        );
        return ip_denied_response(ip_str);
    }

    next.run(request).await
}

fn ip_denied_response(ip: &str) -> Response {
    let body = IpDeniedResponse {
        error: IpDeniedError {
            code: "IP_DENIED",
            message: format!(
                "Your IP address ({}) is not authorized to access this service. Contact your administrator.",
                ip
            ),
        },
    };

    (StatusCode::FORBIDDEN, Json(body)).into_response()
}
