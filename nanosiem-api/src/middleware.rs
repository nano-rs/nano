// SPDX-License-Identifier: AGPL-3.0-or-later

//! API middleware
//!
//! Provides middleware for:
//! - Request logging
//! - Authentication and authorization
//! - Error handling
//! - Request ID propagation for distributed tracing
//! - Rate limiting for auth endpoints

pub mod audit_authz;
pub mod auth;
pub mod demo_guard;
pub mod ip_allowlist;
pub mod license_guard;
pub mod logging;
pub mod rate_limit;
pub mod request_id;
pub mod sanitize_errors;
pub mod tier_guard;

pub use audit_authz::audit_authz_failures;
pub use auth::{
    auth_middleware, check_all_permissions, check_any_permission, check_permission,
    optional_auth_middleware, require_session_auth, require_session_or_self, AuthContext,
    AuthErrorResponse, AuthState, PermissionGuard,
};
pub use demo_guard::demo_guard;
pub use ip_allowlist::{ip_allowlist_middleware, IpAllowlistState};
pub use license_guard::license_guard;
pub use logging::request_logging_layer;
pub use rate_limit::{
    dry_resolve_rate_limit_middleware, login_rate_limit_middleware,
    password_reset_rate_limit_middleware, upload_rate_limit_middleware, RateLimitConfig,
    RateLimitState,
};
pub use request_id::{request_id_middleware, RequestId, REQUEST_ID_HEADER};
pub use sanitize_errors::sanitize_error_responses;
pub use tier_guard::api_write_guard;
