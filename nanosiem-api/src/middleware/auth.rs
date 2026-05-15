// SPDX-License-Identifier: AGPL-3.0-or-later

//! Authentication and Authorization Middleware
//!
//! Requirements: 8.1, 8.3, 8.4, 8.6
//!
//! This module provides:
//! - JWT token validation from Authorization header
//! - API key validation from X-API-Key header
//! - Token claims injection into request extensions
//! - Public endpoint bypass
//! - Permission guard functions for route handlers

use axum::{
    extract::{ConnectInfo, Request, State},
    http::{header, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
    Extension, Json,
};
use std::net::SocketAddr;
use std::sync::Arc;

use nanosiem_core::audit::ClientContext;
use nanosiem_core::auth::{
    audit_actions, ApiKeyService, ApiKeyServiceError, AuditRepository, PermissionResolver,
    TokenConfig, TokenService,
};

// AuthContext, AuthErrorResponse, and the check_*/require_* permission helpers
// were lifted to nanosiem-api-lib (NAN-751) so that handlers in
// nanosiem-enterprise can consume them without creating a circular crate
// dependency. Re-exported here so downstream `use crate::middleware::*`
// imports continue to resolve.
pub use nanosiem_api_lib::{
    check_all_permissions, check_any_permission, check_permission, require_session_auth,
    require_session_or_self, AuthContext, AuthErrorResponse,
};

/// Public endpoints that don't require authentication.
/// All entries are matched exactly (no prefix matching).
const PUBLIC_ENDPOINTS: &[&str] = &[
    "/health",
    "/api/auth/login",
    "/api/auth/refresh",
    "/api/auth/password/reset-request",
    "/api/auth/password/reset",
    "/api/auth/oidc/providers",
    "/api/setup/status",
    "/api/setup/initialize",
    // The SPA fetches /api/capabilities pre-auth to decide which edition
    // features to surface. Requiring auth here would 401 the boot fetch
    // and pin the SPA on the FALLBACK_CAPABILITIES (which assume
    // enterprise), leaking Risk/Cases/Notebooks nav into open-core
    // deployments. NAN-807 bug #10.
    "/api/capabilities",
    "/api/auth/mfa/challenge",
    // Forced-MFA enrolment: a user bounced by the global `Require MFA`
    // policy holds only a 5-minute `mfa_challenge` token, not a session.
    // The handlers themselves authenticate via that token (or via Bearer
    // for voluntary enrolment), so the middleware lets the request
    // through unconditionally.
    "/api/auth/mfa/setup",
    "/api/auth/mfa/verify-setup",
];

/// Check if a path is a public endpoint.
/// Uses exact matching for all entries plus explicit pattern matching
/// for OIDC provider-specific routes (authorize and callback only).
fn is_public_endpoint(path: &str) -> bool {
    // Exact matches
    if PUBLIC_ENDPOINTS.iter().any(|public| path == *public) {
        return true;
    }

    // OIDC provider-specific public routes: /api/auth/oidc/{slug}/authorize and /api/auth/oidc/{slug}/callback
    // Matched explicitly to avoid accidentally exposing future routes under this prefix.
    if let Some(rest) = path.strip_prefix("/api/auth/oidc/") {
        let parts: Vec<&str> = rest.splitn(2, '/').collect();
        if parts.len() == 2 {
            let action = parts[1];
            return action == "authorize" || action == "callback";
        }
    }

    // Identity provider push endpoint: /api/identity-providers/{id}/push
    // Uses its own bearer token auth (collector_token), not JWT.
    if let Some(rest) = path.strip_prefix("/api/identity-providers/") {
        if rest.ends_with("/push") {
            return true;
        }
    }

    // Demo session public endpoints (only exist on DEPLOYMENT_MODE=demo deployments):
    // - POST /api/demo/session (create session)
    // - POST /api/demo/session/{token}/claim (claim one-time link)
    // These paths skip auth — the router returns 404 on non-demo deployments.
    if path == "/api/demo/session" {
        return true;
    }
    if let Some(rest) = path.strip_prefix("/api/demo/session/") {
        if rest.ends_with("/claim") {
            return true;
        }
    }

    false
}

/// Extract Bearer token from Authorization header
fn extract_bearer_token(request: &Request) -> Option<String> {
    request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|auth| {
            if auth.starts_with("Bearer ") {
                Some(auth[7..].to_string())
            } else {
                None
            }
        })
}

/// Extract API key from X-API-Key header
fn extract_api_key(request: &Request) -> Option<String> {
    request
        .headers()
        .get("X-API-Key")
        .and_then(|value| value.to_str().ok())
        .map(|s| s.to_string())
}

/// Extract JWT from access_token cookie
fn extract_jwt_cookie(request: &Request) -> Option<String> {
    request
        .headers()
        .get(header::COOKIE)
        .and_then(|value| value.to_str().ok())
        .and_then(|cookies| {
            cookies
                .split(';')
                .map(|s| s.trim())
                .find(|s| s.starts_with("access_token="))
                .map(|s| s["access_token=".len()..].to_string())
                .filter(|s| !s.is_empty())
        })
}

/// Extract client IP address from request headers with socket fallback.
/// Delegates to the shared `crate::utils::extract_client_ip` implementation.
fn extract_ip_address(request: &Request, connect_info: Option<&SocketAddr>) -> Option<String> {
    crate::utils::extract_client_ip(request.headers(), connect_info)
}

/// Extract user agent from request
fn extract_user_agent(request: &Request) -> Option<String> {
    request
        .headers()
        .get(header::USER_AGENT)
        .and_then(|value| value.to_str().ok())
        .map(|s| s.to_string())
}

/// Authentication state that holds the services needed for auth
#[derive(Clone)]
pub struct AuthState {
    pub token_service: Arc<TokenService>,
    pub api_key_service: Option<Arc<ApiKeyService>>,
    pub audit_repo: Arc<AuditRepository>,
    pub auth_enabled: bool,
    /// Resolves user permissions from PostgreSQL with caching.
    /// Populated after JWT validation to keep permissions out of the token.
    pub permission_resolver: Option<Arc<PermissionResolver>>,
}

impl AuthState {
    /// Create a new auth state
    pub fn new(
        token_service: TokenService,
        api_key_service: Option<ApiKeyService>,
        audit_repo: AuditRepository,
        auth_enabled: bool,
    ) -> Self {
        Self {
            token_service: Arc::new(token_service),
            api_key_service: api_key_service.map(Arc::new),
            audit_repo: Arc::new(audit_repo),
            auth_enabled,
            permission_resolver: None,
        }
    }

    /// Create from Arc-wrapped services (for use with AppState)
    pub fn from_arcs(
        token_service: Arc<TokenService>,
        api_key_service: Option<Arc<ApiKeyService>>,
        audit_repo: Arc<AuditRepository>,
        auth_enabled: bool,
    ) -> Self {
        Self {
            token_service,
            api_key_service,
            audit_repo,
            auth_enabled,
            permission_resolver: None,
        }
    }

    /// Create from JWT secret (minimal setup)
    pub fn from_jwt_secret(jwt_secret: &str, audit_repo: AuditRepository) -> Self {
        let token_config = TokenConfig::new(jwt_secret.to_string());
        let token_service = TokenService::new(token_config);

        Self {
            token_service: Arc::new(token_service),
            api_key_service: None,
            audit_repo: Arc::new(audit_repo),
            auth_enabled: true,
            permission_resolver: None,
        }
    }

    /// Set the permission resolver for server-side permission resolution
    pub fn with_permission_resolver(mut self, resolver: PermissionResolver) -> Self {
        self.permission_resolver = Some(Arc::new(resolver));
        self
    }
}

/// Main authentication middleware
///
/// Requirements: 8.1, 8.3, 8.4, 8.6
/// - 8.1: Validate JWT tokens on every request except public endpoints
/// - 8.3: Return 401 Unauthorized when token is expired
/// - 8.4: Return 401 Unauthorized when token is invalid
/// - 8.6: Support API keys for service-to-service authentication
pub async fn auth_middleware(
    State(auth_state): State<AuthState>,
    mut request: Request,
    next: Next,
) -> Result<Response, Response> {
    // Skip auth if not enabled
    if !auth_state.auth_enabled {
        return Ok(next.run(request).await);
    }

    let path = request.uri().path().to_string();

    // Extract ConnectInfo and inject ClientContext BEFORE the public endpoint check.
    // SECURITY: Public endpoints (like /api/identity-providers/{id}/push) that use
    // Extension<ClientContext> for audit logging would crash with 500 if ClientContext
    // was only injected after the public check.
    let connect_info = request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ci| ci.0);
    let ip_address = extract_ip_address(&request, connect_info.as_ref());
    let user_agent = extract_user_agent(&request);
    let client_context = ClientContext::new(ip_address.clone(), user_agent.clone());
    request.extensions_mut().insert(client_context);

    // Skip auth for public endpoints
    if is_public_endpoint(&path) {
        return Ok(next.run(request).await);
    }

    // Try JWT token first (Authorization: Bearer <token>)
    if let Some(token) = extract_bearer_token(&request) {
        match auth_state
            .token_service
            .validate_access_token_async(&token)
            .await
        {
            Ok(mut claims) => {
                // SECURITY: Reject non-access tokens (e.g. MFA challenge tokens)
                // to prevent them from being used to access protected endpoints.
                if claims.purpose != "access" {
                    tracing::debug!("Rejected token with purpose={}", claims.purpose);
                    return Err((
                        StatusCode::UNAUTHORIZED,
                        Json(AuthErrorResponse::unauthorized("Invalid token purpose")),
                    )
                        .into_response());
                }
                // Resolve permissions server-side (not stored in JWT)
                if let Some(ref resolver) = auth_state.permission_resolver {
                    claims.permissions = resolver.resolve_with_roles(claims.sub, &claims.roles).await;
                }
                let auth_context = AuthContext::from_jwt(claims.clone());
                request.extensions_mut().insert(auth_context);
                request.extensions_mut().insert(claims);
                return Ok(next.run(request).await);
            }
            Err(e) => {
                tracing::warn!(error = %e, "JWT validation failed");
                // Fall through to try API key
            }
        }
    }

    // Try API key (X-API-Key header)
    if let Some(api_key) = extract_api_key(&request) {
        if let Some(ref api_key_service) = auth_state.api_key_service {
            match api_key_service
                .validate_key(&api_key, ip_address.as_deref())
                .await
            {
                Ok(info) => {
                    let auth_context = AuthContext::from_api_key(&info);
                    let claims = auth_context.claims.clone();
                    request.extensions_mut().insert(auth_context);
                    request.extensions_mut().insert(claims);
                    return Ok(next.run(request).await);
                }
                Err(e) => {
                    tracing::warn!(error = %e, "API key validation failed");

                    let (status, message) = match e {
                        ApiKeyServiceError::Disabled => {
                            (StatusCode::UNAUTHORIZED, "API key is disabled")
                        }
                        ApiKeyServiceError::Expired => {
                            (StatusCode::UNAUTHORIZED, "API key has expired")
                        }
                        ApiKeyServiceError::RateLimitExceeded => {
                            (StatusCode::TOO_MANY_REQUESTS, "Rate limit exceeded")
                        }
                        _ => (StatusCode::UNAUTHORIZED, "Invalid API key"),
                    };

                    return Err(
                        (status, Json(AuthErrorResponse::unauthorized(message))).into_response()
                    );
                }
            }
        }
    }

    // Try JWT from cookie (access_token cookie for browser-based Swagger UI access).
    // CSRF protection: cookie-only auth is restricted to safe (read-only) HTTP methods,
    // EXCEPT for auth-lifecycle endpoints (logout, refresh) which must work with cookies
    // because the access token may be expired when the user initiates logout.
    if let Some(token) = extract_jwt_cookie(&request) {
        let method = request.method().clone();
        let is_auth_lifecycle =
            path.starts_with("/api/auth/logout") || path.starts_with("/api/auth/refresh");
        if !method.is_safe() && !is_auth_lifecycle {
            tracing::debug!(
                "Rejecting cookie-only auth for non-safe method {} on {}",
                method,
                path
            );
            return Err((
                StatusCode::FORBIDDEN,
                Json(AuthErrorResponse::forbidden(
                    "Cookie authentication is not allowed for state-changing requests. \
                     Use Authorization: Bearer header.",
                )),
            )
                .into_response());
        }

        match auth_state
            .token_service
            .validate_access_token_async(&token)
            .await
        {
            Ok(mut claims) => {
                if claims.purpose != "access" {
                    tracing::debug!("Rejected cookie token with purpose={}", claims.purpose);
                    return Err((
                        StatusCode::UNAUTHORIZED,
                        Json(AuthErrorResponse::unauthorized("Invalid token purpose")),
                    )
                        .into_response());
                }
                // Resolve permissions server-side (not stored in JWT)
                if let Some(ref resolver) = auth_state.permission_resolver {
                    claims.permissions = resolver.resolve_with_roles(claims.sub, &claims.roles).await;
                }
                let auth_context = AuthContext::from_jwt(claims.clone());
                request.extensions_mut().insert(auth_context);
                request.extensions_mut().insert(claims);
                return Ok(next.run(request).await);
            }
            Err(e) => {
                tracing::warn!(error = %e, "Cookie JWT validation failed");
            }
        }
    }

    // No valid authentication found
    tracing::warn!(path = %path, "Unauthenticated request denied");

    Err((
        StatusCode::UNAUTHORIZED,
        Json(AuthErrorResponse::unauthorized("Authentication required")),
    )
        .into_response())
}

/// Optional authentication middleware
///
/// Similar to auth_middleware but doesn't fail if no auth is provided.
/// Useful for endpoints that have different behavior for authenticated vs anonymous users.
pub async fn optional_auth_middleware(
    State(auth_state): State<AuthState>,
    mut request: Request,
    next: Next,
) -> Response {
    // Extract ConnectInfo from request extensions (set by into_make_service_with_connect_info)
    let connect_info = request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ci| ci.0);
    let ip_address = extract_ip_address(&request, connect_info.as_ref());
    let user_agent = extract_user_agent(&request);
    let client_context = ClientContext::new(ip_address, user_agent);
    request.extensions_mut().insert(client_context);

    // Skip auth if not enabled
    if !auth_state.auth_enabled {
        return next.run(request).await;
    }

    // Try JWT token first
    if let Some(token) = extract_bearer_token(&request) {
        if let Ok(mut claims) = auth_state
            .token_service
            .validate_access_token_async(&token)
            .await
        {
            // Resolve permissions server-side (not stored in JWT)
            if let Some(ref resolver) = auth_state.permission_resolver {
                claims.permissions = resolver.resolve_with_roles(claims.sub, &claims.roles).await;
            }
            let auth_context = AuthContext::from_jwt(claims.clone());
            request.extensions_mut().insert(auth_context);
            request.extensions_mut().insert(claims);
        }
    }
    // Try API key if JWT not present
    else if let Some(api_key) = extract_api_key(&request) {
        if let Some(ref api_key_service) = auth_state.api_key_service {
            // Reuse ip_address from ClientContext we already extracted
            let ctx_ip = request
                .extensions()
                .get::<ClientContext>()
                .and_then(|c| c.ip_address.clone());
            if let Ok(info) = api_key_service
                .validate_key(&api_key, ctx_ip.as_deref())
                .await
            {
                let auth_context = AuthContext::from_api_key(&info);
                let claims = auth_context.claims.clone();
                request.extensions_mut().insert(auth_context);
                request.extensions_mut().insert(claims);
            }
        }
    }

    next.run(request).await
}

/// Permission guard that checks if the user has the required permission
///
/// Requirements: 5.2, 8.2, 8.5
/// - 5.2: Return 403 Forbidden when user lacks required permission
/// - 8.2: Extract user permissions from JWT and enforce on each endpoint
/// - 8.5: Log all authorization failures
pub async fn require_permission(
    Extension(auth_context): Extension<AuthContext>,
    State(auth_state): State<AuthState>,
    request: Request,
    permission: &'static str,
) -> Result<(), Response> {
    if auth_context.has_permission(permission) {
        return Ok(());
    }

    // Log authorization failure
    let connect_info = request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ci| ci.0);
    let ip_address = extract_ip_address(&request, connect_info.as_ref());
    let user_agent = extract_user_agent(&request);
    let path = request.uri().path().to_string();

    let _ = auth_state
        .audit_repo
        .log_event(
            if auth_context.is_api_key {
                None
            } else {
                Some(auth_context.user_id())
            },
            auth_context.api_key_id,
            audit_actions::AUTH_DENIED,
            Some("endpoint"),
            None,
            Some(serde_json::json!({
                "path": path,
                "required_permission": permission,
                "user_permissions": auth_context.claims.permissions,
            })),
            ip_address.as_deref(),
            user_agent.as_deref(),
            false,
        )
        .await;

    Err((
        StatusCode::FORBIDDEN,
        Json(AuthErrorResponse::forbidden(&format!(
            "Missing required permission: {}",
            permission
        ))),
    )
        .into_response())
}

// `check_permission`, `require_session_auth`, `require_session_or_self`,
// `check_any_permission`, and `check_all_permissions` were lifted to
// nanosiem-api-lib (NAN-751). They are re-exported at the top of this
// module so existing `crate::middleware::*` import sites still resolve.

/// Permission guard with audit logging
///
/// Requirements: 5.2, 8.2, 8.5
/// - 5.2: Return 403 Forbidden when user lacks required permission
/// - 8.2: Extract user permissions from JWT and enforce on each endpoint
/// - 8.5: Log all authorization failures with user ID, endpoint, and required permission
pub struct PermissionGuard {
    audit_repo: Arc<AuditRepository>,
}

impl PermissionGuard {
    pub fn new(audit_repo: Arc<AuditRepository>) -> Self {
        Self { audit_repo }
    }

    /// Check permission and log failure if denied
    pub async fn require(
        &self,
        auth: &AuthContext,
        permission: &str,
        endpoint: &str,
        ip_address: Option<&str>,
        user_agent: Option<&str>,
    ) -> Result<(), (StatusCode, Json<AuthErrorResponse>)> {
        if auth.has_permission(permission) {
            return Ok(());
        }

        // Log authorization failure (Requirements: 8.5)
        let _ = self
            .audit_repo
            .log_event(
                if auth.is_api_key {
                    None
                } else {
                    Some(auth.user_id())
                },
                auth.api_key_id,
                audit_actions::AUTH_DENIED,
                Some("endpoint"),
                None,
                Some(serde_json::json!({
                    "endpoint": endpoint,
                    "required_permission": permission,
                    "user_permissions": auth.claims.permissions,
                })),
                ip_address,
                user_agent,
                false,
            )
            .await;

        Err((
            StatusCode::FORBIDDEN,
            Json(AuthErrorResponse::forbidden(&format!(
                "Missing required permission: {}",
                permission
            ))),
        ))
    }

    /// Check any of multiple permissions and log failure if denied
    pub async fn require_any(
        &self,
        auth: &AuthContext,
        permissions: &[&str],
        endpoint: &str,
        ip_address: Option<&str>,
        user_agent: Option<&str>,
    ) -> Result<(), (StatusCode, Json<AuthErrorResponse>)> {
        if auth.has_any_permission(permissions) {
            return Ok(());
        }

        // Log authorization failure
        let _ = self
            .audit_repo
            .log_event(
                if auth.is_api_key {
                    None
                } else {
                    Some(auth.user_id())
                },
                auth.api_key_id,
                audit_actions::AUTH_DENIED,
                Some("endpoint"),
                None,
                Some(serde_json::json!({
                    "endpoint": endpoint,
                    "required_permissions": permissions,
                    "user_permissions": auth.claims.permissions,
                })),
                ip_address,
                user_agent,
                false,
            )
            .await;

        Err((
            StatusCode::FORBIDDEN,
            Json(AuthErrorResponse::forbidden(&format!(
                "Missing required permission: one of {:?}",
                permissions
            ))),
        ))
    }
}

/// Macro to create a permission guard layer for a specific permission
///
/// Usage:
/// ```ignore
/// let app = Router::new()
///     .route("/api/rules", get(list_detections))
///     .layer(permission_layer!(permissions::DETECTIONS_VIEW));
/// ```
#[macro_export]
macro_rules! permission_layer {
    ($permission:expr) => {
        axum::middleware::from_fn(
            move |auth: Extension<AuthContext>, request, next| async move {
                if auth.has_permission($permission) {
                    next.run(request).await
                } else {
                    (
                        StatusCode::FORBIDDEN,
                        Json(AuthErrorResponse::forbidden(&format!(
                            "Missing required permission: {}",
                            $permission
                        ))),
                    )
                        .into_response()
                }
            },
        )
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_public_endpoint() {
        // Exact matches
        assert!(is_public_endpoint("/health"));
        assert!(is_public_endpoint("/api/auth/login"));
        assert!(is_public_endpoint("/api/auth/refresh"));
        assert!(is_public_endpoint("/api/auth/oidc/providers"));
        assert!(is_public_endpoint("/api/setup/status"));

        // OIDC provider-specific public routes
        assert!(is_public_endpoint("/api/auth/oidc/azure/callback"));
        assert!(is_public_endpoint("/api/auth/oidc/azure/authorize"));
        assert!(is_public_endpoint("/api/auth/oidc/google/callback"));

        // Must NOT match arbitrary sub-paths under /api/auth/oidc/
        assert!(!is_public_endpoint("/api/auth/oidc/settings"));
        assert!(!is_public_endpoint("/api/auth/oidc/azure/delete"));
        assert!(!is_public_endpoint("/api/auth/oidc/"));

        assert!(!is_public_endpoint("/api/search"));
        assert!(!is_public_endpoint("/api/rules"));
        assert!(!is_public_endpoint("/api/users"));
        assert!(!is_public_endpoint("/swagger-ui/"));
        assert!(!is_public_endpoint("/api-docs/openapi.json"));
    }

    // AuthContext / permission-helper tests moved with the types to
    // nanosiem-api-lib (NAN-751) — see `nanosiem-api-lib/src/auth_context.rs`
    // for the test module.
}
