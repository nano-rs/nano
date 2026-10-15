// SPDX-License-Identifier: AGPL-3.0-or-later

//! Client Context
//!
//! Holds client connection information extracted from HTTP requests
//! for inclusion in audit events.

/// Client context extracted from HTTP requests for audit logging
///
/// This is injected by the auth middleware and can be extracted in handlers
/// to include client information in audit events.
#[derive(Debug, Clone, Default)]
pub struct ClientContext {
    /// Client IP address (from X-Forwarded-For, X-Real-IP, or connection)
    pub ip_address: Option<String>,
    /// Client user agent string
    pub user_agent: Option<String>,
    /// Per-request id (`X-Request-ID`, set by the API's request-id
    /// middleware) — the OCSF `api.request.uid` of audit events (NAN-3227).
    pub request_id: Option<String>,
}

impl ClientContext {
    /// Create a new client context
    pub fn new(ip_address: Option<String>, user_agent: Option<String>) -> Self {
        Self {
            ip_address,
            user_agent,
            request_id: None,
        }
    }

    /// Attach the per-request id (`X-Request-ID`).
    pub fn with_request_id(mut self, request_id: Option<String>) -> Self {
        self.request_id = request_id;
        self
    }
}
