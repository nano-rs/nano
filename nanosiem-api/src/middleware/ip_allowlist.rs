// SPDX-License-Identifier: AGPL-3.0-or-later

//! IP Allowlist Middleware
//!
//! Blocks requests from IPs not on the allowlist.
//! Runs before auth middleware so denied IPs never hit authentication.
//! Bypasses health/ready endpoints so infrastructure probes always work.
//!
//! NAN-5077: when the rules cannot be loaded and none were loaded before,
//! protected routes answer 503 `IP_ALLOWLIST_UNAVAILABLE` (fail closed). A
//! TCP-loopback peer and `NANO_IP_ALLOWLIST_DISABLED=true` remain the
//! break-glass paths (docs/administration/ip-allowlist.md).

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

use nanosiem_core::ip_allowlist::{AllowlistDecision, IpAllowlistScope, IpAllowlistService};

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

    // NAN-4907: the OTLP edge's auth_request. Its caller is an ingest sender
    // (like /ingest, which never reaches this API); the source-bound ingest
    // token it carries is the gate, not the UI/API allowlist.
    if path == "/api/internal/otlp-auth" {
        return next.run(request).await;
    }

    // NAN-5217: the ingest edge's pause-admission auth_request, likewise.
    if path == "/api/internal/ingest-admission" {
        return next.run(request).await;
    }

    // NAN-5204: the nano-backup sidecar is host infrastructure on the compose
    // network; a UI/API allowlist must not silence backup failure reports.
    // The endpoint carries its own NANO_BACKUP_STATUS_TOKEN bearer gate.
    if path == "/api/internal/backup-status" {
        return next.run(request).await;
    }

    // Extract ConnectInfo from request extensions (set by into_make_service_with_connect_info)
    let connect_info = request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ci| ci.0);
    let headers = request.headers();
    // NAN-5015: keep WHERE the address came from — only a socket-derived
    // loopback address gets the local pass.
    let client_ip = nanosiem_api_lib::extract_client_ip_origin(headers, connect_info.as_ref());

    let (ip_str, from_socket) = match client_ip {
        Some(ref ip) => (ip.ip.as_str(), ip.from_socket),
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
    match state
        .service
        .is_allowed_client(ip_str, from_socket, state.scope)
        .await
    {
        AllowlistDecision::Allowed => {}
        AllowlistDecision::Denied => {
            tracing::info!(
                ip = %ip_str,
                path = %path,
                scope = %state.scope,
                "IP denied by allowlist"
            );
            return ip_denied_response(ip_str);
        }
        // NAN-5077: rules could not be loaded — fail closed (the service
        // logs the load error once per retry window, not per request).
        AllowlistDecision::Unavailable => {
            tracing::debug!(ip = %ip_str, path = %path, scope = %state.scope, "IP allowlist unavailable — refusing");
            return ip_allowlist_unavailable_response();
        }
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

/// NAN-5077: the allowlist rules could not be loaded, so the request is
/// refused without claiming the client is unlisted. 503 + Retry-After: the
/// condition clears by itself once PostgreSQL is reachable again.
fn ip_allowlist_unavailable_response() -> Response {
    let body = IpDeniedResponse {
        error: IpDeniedError {
            code: "IP_ALLOWLIST_UNAVAILABLE",
            message: "The IP allowlist could not be loaded, so access is refused until it can be. \
                      Retry shortly; if this persists, contact your administrator."
                .to_string(),
        },
    };
    (
        StatusCode::SERVICE_UNAVAILABLE,
        [(axum::http::header::RETRY_AFTER, "5")],
        Json(body),
    )
        .into_response()
}

#[cfg(test)]
#[path = "ip_allowlist_tests.rs"]
mod tests;
