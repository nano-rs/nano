// SPDX-License-Identifier: AGPL-3.0-or-later

//! Client Context
//!
//! Holds client connection information extracted from HTTP requests
//! for inclusion in audit events.

/// Client context extracted from HTTP requests for audit logging
///
/// This is injected by the auth middleware and can be extracted in handlers
/// to include client information in audit events.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ClientContext {
    /// Client IP address (from X-Forwarded-For, X-Real-IP, or connection)
    pub ip_address: Option<String>,
    /// Client user agent string
    pub user_agent: Option<String>,
    /// NAN-5571: the in-app surface that made the request on the user's
    /// behalf (`pivt` when the analyst applied a pivt-proposed action). Taken
    /// from the `X-Nano-Origin` header against an allowlist, recorded in the
    /// audit event's details. Never a privilege: the actor is still the user.
    pub origin: Option<&'static str>,
}

/// Header the web client sets on requests a pivt action makes.
pub const ORIGIN_HEADER: &str = "x-nano-origin";

/// Origins that may be recorded. Anything else is ignored.
const KNOWN_ORIGINS: &[&str] = &["pivt"];

impl ClientContext {
    /// Create a new client context
    pub fn new(ip_address: Option<String>, user_agent: Option<String>) -> Self {
        Self {
            ip_address,
            user_agent,
            origin: None,
        }
    }

    /// Record the request's origin if it is a known one (NAN-5571).
    pub fn with_origin_header(mut self, value: Option<&str>) -> Self {
        self.origin = value.and_then(|v| KNOWN_ORIGINS.iter().copied().find(|o| o.eq_ignore_ascii_case(v.trim())));
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_known_origins_are_recorded() {
        let c = |v| ClientContext::new(None, None).with_origin_header(v).origin;
        assert_eq!(c(Some("pivt")), Some("pivt"));
        assert_eq!(c(Some(" PIVT ")), Some("pivt"));
        assert_eq!(c(Some("system")), None);
        assert_eq!(c(Some("pivt\nadmin")), None);
        assert_eq!(c(None), None);
    }
}
