//! nanosiem-api-lib
//!
//! Shared library code used by both `nanosiem-api` (the open-core HTTP server
//! crate) and `nanosiem-enterprise` (the proprietary handler/service crate).
//!
//! ## Why this crate exists
//!
//! `nanosiem-api` already takes an optional cfg-gated dependency on
//! `nanosiem-enterprise`. To physically relocate enterprise-tier handler
//! modules out of the open-core source tree (NAN-751), `nanosiem-enterprise`
//! needs to import a small set of API-tier types (auth context, request
//! helpers, cookie builders). Adding a direct dependency
//! `nanosiem-enterprise -> nanosiem-api` would create a cycle, so the
//! shared types live here instead.
//!
//! Keep this crate intentionally thin — only the bits that genuinely cross
//! the open/enterprise boundary belong here. Anything that's only used by
//! nanosiem-api stays in nanosiem-api.

pub mod api_error;
pub mod audit_ext;
pub mod auth_context;
pub mod cookies;
pub mod headers;

pub use api_error::{ApiError, ErrorDetail, ErrorResponse};
pub use audit_ext::AuditExt;
pub use auth_context::{
    check_all_permissions, check_any_permission, check_permission, require_session_auth,
    require_session_or_self, AuthContext, AuthErrorResponse,
};
pub use cookies::{
    build_access_token_cookie, build_refresh_token_cookie, clear_access_token_cookie,
    clear_refresh_token_cookie, extract_refresh_token_cookie,
};
pub use headers::{extract_client_ip, extract_user_agent};
