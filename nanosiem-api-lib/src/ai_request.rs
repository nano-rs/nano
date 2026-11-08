// SPDX-License-Identifier: AGPL-3.0-or-later

//! HTTP deadline and async negotiation for AI wizard requests (NAN-4753).
//!
//! A reasoning model drafts a parser for minutes, far past any reverse-proxy
//! response deadline (Cloudflare 100 s, NGINX 60 s by default). Wizard
//! endpoints therefore negotiate: a caller that sends
//! `Prefer: respond-async` gets `202` and a job id to poll; an existing
//! caller keeps its synchronous result shape, bounded by
//! [`WIZARD_HTTP_TIMEOUT`] so it fails with JSON before the edge answers
//! with an HTML page.
//!
//! Unlike main, the deadline is applied per endpoint (the parser create
//! route), not as a router-wide `/api/melod/*` middleware: on the
//! single-tenant product several synchronous meloD routes legitimately run
//! longer behind no edge, and capping them all at 85 s would be a silent
//! behavior change outside this feature.

use axum::http::HeaderMap;

/// Leave headroom under the edge's 100-second response deadline, including
/// admission, database access and model execution before response headers.
pub const WIZARD_HTTP_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(85);

/// Existing clients retain their result shape; updated clients request jobs.
pub fn prefers_async(headers: &HeaderMap) -> bool {
    headers
        .get_all("prefer")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .any(|v| {
            v.split(',')
                .any(|preference| preference.trim().eq_ignore_ascii_case("respond-async"))
        })
}

#[cfg(test)]
#[path = "ai_request_tests.rs"]
mod tests;
