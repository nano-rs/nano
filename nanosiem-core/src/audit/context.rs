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
}

impl ClientContext {
    /// Create a new client context
    pub fn new(ip_address: Option<String>, user_agent: Option<String>) -> Self {
        Self {
            ip_address,
            user_agent,
        }
    }
}
