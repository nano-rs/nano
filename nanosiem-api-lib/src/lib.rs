// SPDX-License-Identifier: AGPL-3.0-or-later

//! nanosiem-api-lib
//!
//! Shared library code used by both `nanosiem-api` (the open-core HTTP server
//! crate) and the enterprise crate (the proprietary handler/service crate).
//!
//! ## Why this crate exists
//!
//! `nanosiem-api` already takes an optional cfg-gated dependency on
//! the enterprise crate. To physically relocate enterprise-tier handler
//! modules out of the open-core source tree (NAN-751), the enterprise crate
//! needs to import a small set of API-tier types (auth context, request
//! helpers, cookie builders). Adding a direct dependency
//! `the enterprise crate -> nanosiem-api` would create a cycle, so the
//! shared types live here instead.
//!
//! Keep this crate intentionally thin — only the bits that genuinely cross
//! the open/enterprise boundary belong here. Anything that's only used by
//! nanosiem-api stays in nanosiem-api.

pub mod api_error;
pub mod audit_ext;
pub mod auth_context;
pub mod cookies;
pub mod grant_authz;
pub mod headers;
pub mod pagination;
pub mod source_inventory;
pub mod tenant_path;

pub use api_error::{error_chain, ApiError, ErrorDetail, ErrorResponse, ExpectedUnavailable};
pub use audit_ext::AuditExt;
pub use auth_context::{
    check_all_permissions, check_any_permission, check_permission, ensure_interactive_session,
    ensure_permission, require_session_auth, require_session_or_self, AuthContext, AuthErrorResponse,
};
pub use cookies::{
    append_set_cookies, build_access_token_cookie, build_access_token_cookie_for,
    build_mfa_challenge_cookie, build_mfa_challenge_cookie_for, build_refresh_token_cookie,
    build_refresh_token_cookie_for, clear_access_token_cookie, clear_access_token_cookie_for,
    clear_mfa_challenge_cookie, clear_mfa_challenge_cookie_for, clear_refresh_token_cookie,
    clear_refresh_token_cookie_for, clear_session_cookies_for, extract_mfa_challenge_cookie,
    extract_refresh_token_cookie, extract_scoped_cookie, issued_session_set_cookies,
    legacy_session_cookie_tenant, request_cookies, scoped_cookie_discriminator,
    select_tenant_cookie, session_cookie_scope_for_issued, shared_access_token_tenant,
    shared_mfa_challenge_tenant, shared_refresh_token_tenant, tenant_cookie_discriminator,
    RequestCookies, SessionCookieScope, SharedRefreshCookie, SharedRefreshCookieError,
    TenantCookie, ACCESS_TOKEN_COOKIE, MAX_TENANT_SESSION_COOKIES, MFA_CHALLENGE_COOKIE,
    REFRESH_TOKEN_COOKIE, TENANT_COOKIE_DISCRIMINATOR_LEN,
};
pub use headers::{extract_client_ip, extract_user_agent, peer_client_ip, PeerAddr};
pub use pagination::Pagination;
pub use source_inventory::{
    ensure_source_inventory_access, permits_source_inventory, SOURCE_INVENTORY_CAPS,
};
