// SPDX-License-Identifier: AGPL-3.0-or-later

//! Default `Cache-Control` for API responses (NAN-3198).
//!
//! API answers are tenant data behind credentials. Without an explicit
//! `Cache-Control`, a shared HTTP cache on the path (a corporate TLS-inspecting
//! proxy, a CDN rule) may store a GET answer heuristically and replay it to
//! later callers: an `x-api-key` request carries no `Authorization` header,
//! so such caches do not treat it as authenticated. On 2026-10-07 a
//! workstation MITM proxy replayed `/api/rules/{id}`, `/api/alerts` and
//! `/api/risk/entities` answers for 20+ minutes, which froze the e2e detection
//! tester's view of rule runs, alerts and risk (and would serve one caller's
//! tenant data to the next).
//!
//! Every `/api/` response without its own `Cache-Control` therefore gets
//! `private, no-store`. Routes that opt into caching (`/api/mitre`, static
//! metadata) set the header themselves and are left untouched.
//!
//! Shared by `nanosiem-api` and `nanosiem-search` (ingress sends `/api/search*`
//! to the search service), and layered outside auth / IP-allowlist so their
//! rejections are covered too (NAN-4930).

use axum::{
    body::Body,
    http::{header, HeaderValue, Request},
    middleware::Next,
    response::Response,
};

/// The default for API responses that do not choose their own caching.
pub const API_DEFAULT_CACHE_CONTROL: &str = "private, no-store";

/// Whether a request path is an API path whose answer must not be stored by
/// shared caches unless the handler says otherwise.
pub fn is_api_path(path: &str) -> bool {
    path == "/api" || path.starts_with("/api/")
}

/// Insert [`API_DEFAULT_CACHE_CONTROL`] on `/api/` responses that carry no
/// `Cache-Control` of their own.
pub async fn api_default_cache_control(req: Request<Body>, next: Next) -> Response {
    let api = is_api_path(req.uri().path());
    let mut response = next.run(req).await;
    if api && !response.headers().contains_key(header::CACHE_CONTROL) {
        response.headers_mut().insert(
            header::CACHE_CONTROL,
            HeaderValue::from_static(API_DEFAULT_CACHE_CONTROL),
        );
    }
    response
}

/// Router fallback for unmatched paths. `Router::layer` middleware runs only
/// for matched routes and an explicit fallback, so both services install this
/// before their layers: an unknown `/api/...` path then also gets
/// [`API_DEFAULT_CACHE_CONTROL`] (NAN-4930).
pub async fn not_found() -> axum::http::StatusCode {
    axum::http::StatusCode::NOT_FOUND
}

#[cfg(test)]
#[path = "api_cache_control_tests.rs"]
mod tests;
