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
    Json,
};
use std::net::SocketAddr;
use std::sync::Arc;

use nanosiem_core::audit::ClientContext;
use nanosiem_core::auth::{
    ApiKeyService, ApiKeyServiceError, PermissionResolver, SourceScopeResolver, TokenConfig,
    TokenService, UserStatusResolver,
};

// AuthContext, AuthErrorResponse, and the check_*/require_* permission helpers
// were lifted to nanosiem-api-lib (NAN-751) so that handlers in
// nanosiem-enterprise can consume them without creating a circular crate
// dependency. Re-exported here so downstream `use crate::middleware::*`
// imports continue to resolve.
pub use nanosiem_api_lib::{
    check_all_permissions, check_any_permission, check_permission, ensure_interactive_session,
    ensure_permission, require_session_auth, require_session_or_self, AuthContext, AuthErrorResponse,
};

/// Public endpoints that don't require authentication.
/// All entries are matched exactly (no prefix matching).
const PUBLIC_ENDPOINTS: &[&str] = &[
    "/health",
    // Kubernetes readiness probe (HA8, NAN-1777). Probes are unauthenticated;
    // without this the auth middleware 401s /ready before the handler's
    // 200/503 control-plane check runs, so the pod never becomes Ready. The
    // IP-allowlist middleware already bypasses /ready — keep the two in sync.
    "/ready",
    // Shallow liveness probe (NAN-1786) — unauthenticated, like /health//ready.
    "/livez",
    "/api/auth/login",
    "/api/auth/refresh",
    "/api/auth/password/reset-request",
    "/api/auth/password/reset",
    "/api/auth/oidc/providers",
    // NAN-2181: the login page reads this pre-auth to decide whether to render
    // a password field. Requiring auth would 401 the boot fetch and leave the
    // page guessing — the failure mode being a password prompt on an SSO-only
    // tenant, which is exactly what the setting exists to remove. Discloses one
    // boolean of tenant config and nothing per-account.
    "/api/auth/methods",
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

    // NAN-1151 (3d): the AD /push endpoint (the only collector-token-auth'd
    // identity endpoint) is retired — AD identity now flows through the
    // nano_enrich lane. No identity-provider path is auth-exempt anymore.

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
    pub auth_enabled: bool,
    /// Resolves user permissions from PostgreSQL with caching.
    /// Populated after JWT validation to keep permissions out of the token.
    pub permission_resolver: Option<Arc<PermissionResolver>>,
    /// Resolves the caller's SOURCE-scope deny set (per-source RBAC, NAN-1799)
    /// from PostgreSQL with caching. FAIL-CLOSED on PG unavailability. Populated
    /// into `AuthContext::denied_sources` after authentication succeeds. `None`
    /// in minimal setups (e.g. tests) — callers then resolve to unrestricted.
    /// Cheap to clone (Arc-backed internally), so it is stored by value.
    pub source_scope_resolver: Option<SourceScopeResolver>,
    /// F-32: resolves the caller's `status` + `tokens_valid_from` watermark
    /// (fail-closed, short-TTL cache) so the middleware can reject disabled/
    /// locked/deleted users and access tokens issued before a forced revocation.
    /// `None` in minimal setups (tests) — the gate is then skipped.
    pub user_status_resolver: Option<UserStatusResolver>,
}

impl AuthState {
    /// Create a new auth state
    pub fn new(
        token_service: TokenService,
        api_key_service: Option<ApiKeyService>,
        auth_enabled: bool,
    ) -> Self {
        Self {
            token_service: Arc::new(token_service),
            api_key_service: api_key_service.map(Arc::new),
            auth_enabled,
            permission_resolver: None,
            source_scope_resolver: None,
            user_status_resolver: None,
        }
    }

    /// Create from Arc-wrapped services (for use with AppState)
    pub fn from_arcs(
        token_service: Arc<TokenService>,
        api_key_service: Option<Arc<ApiKeyService>>,
        auth_enabled: bool,
    ) -> Self {
        Self {
            token_service,
            api_key_service,
            auth_enabled,
            permission_resolver: None,
            source_scope_resolver: None,
            user_status_resolver: None,
        }
    }

    /// Create from JWT secret (minimal setup)
    pub fn from_jwt_secret(jwt_secret: &str) -> Self {
        let token_config = TokenConfig::new(jwt_secret.to_string());
        let token_service = TokenService::new(token_config);

        Self {
            token_service: Arc::new(token_service),
            api_key_service: None,
            auth_enabled: true,
            permission_resolver: None,
            source_scope_resolver: None,
            user_status_resolver: None,
        }
    }

    /// Set the permission resolver for server-side permission resolution
    pub fn with_permission_resolver(mut self, resolver: PermissionResolver) -> Self {
        self.permission_resolver = Some(Arc::new(resolver));
        self
    }

    /// Set the source-scope resolver so the middleware populates each request's
    /// `AuthContext::denied_sources` (per-source RBAC, NAN-1799).
    pub fn with_source_scope_resolver(mut self, resolver: SourceScopeResolver) -> Self {
        self.source_scope_resolver = Some(resolver);
        self
    }

    /// F-32: set the user-status resolver so the middleware rejects disabled/
    /// locked/deleted users and pre-revocation access tokens.
    pub fn with_user_status_resolver(mut self, resolver: UserStatusResolver) -> Self {
        self.user_status_resolver = Some(resolver);
        self
    }
}

/// Resolve the caller's SOURCE-scope deny set to stamp onto `AuthContext`.
///
/// FAIL-CLOSED (NAN-1799): when a resolver is configured but cannot produce a
/// scope — PostgreSQL unreachable with no known restricted registry — the
/// request is rejected with 503 rather than proceeding with an empty
/// (fail-open) deny set. When no resolver is configured (minimal `AuthState`,
/// e.g. tests) the caller resolves to unrestricted for back-compat.
async fn resolve_source_scope(
    auth_state: &AuthState,
    user_id: uuid::Uuid,
    roles: &[String],
    permissions: &[String],
) -> Result<nanosiem_core::auth::ScopeSet, Response> {
    let Some(ref resolver) = auth_state.source_scope_resolver else {
        return Ok(nanosiem_core::auth::ScopeSet::default());
    };
    match resolver.resolve(user_id, roles, permissions).await {
        Ok(scope) => Ok(scope),
        Err(e) => {
            tracing::error!(
                error = %e,
                user_id = %user_id,
                "source-scope resolution failed — failing closed (503)"
            );
            Err((
                StatusCode::SERVICE_UNAVAILABLE,
                Json(AuthErrorResponse {
                    error: "source_scope_unavailable".to_string(),
                    message: "Source access scope is temporarily unavailable. Please retry shortly."
                        .to_string(),
                }),
            )
                .into_response())
        }
    }
}

/// F-32: enforce that the JWT/cookie principal is still `active` and that the
/// token was issued after any forced-revocation watermark.
///
/// FAIL-CLOSED (mirrors [`resolve_source_scope`]): a resolver error returns the
/// 503 [`Response`] the caller MUST return — the request is NEVER allowed to
/// proceed as if the user were active. A non-active status or a pre-revocation
/// token returns 401. When no resolver is configured (minimal `AuthState`, e.g.
/// tests) the gate is skipped for back-compat.
///
/// ONLY the JWT/cookie paths call this (their `sub` is a real `users.id`). The
/// API-key path checks the OWNER's status inside `ApiKeyService::validate_key`
/// instead — an api-key principal's `sub` is the key owner but the check belongs
/// with key validation, and it must not be skipped when this resolver is absent.
async fn enforce_user_status(
    auth_state: &AuthState,
    user_id: uuid::Uuid,
    token_iat: i64,
) -> Result<(), Response> {
    let Some(ref resolver) = auth_state.user_status_resolver else {
        return Ok(());
    };
    match resolver.resolve(user_id).await {
        Ok(snapshot) => {
            if !snapshot.is_active() || snapshot.token_predates_revocation(token_iat) {
                tracing::warn!(
                    user_id = %user_id,
                    status = %snapshot.status,
                    "rejecting request: account not active or token revoked"
                );
                return Err((
                    StatusCode::UNAUTHORIZED,
                    Json(AuthErrorResponse::unauthorized(
                        "Account is not active or the session has been revoked",
                    )),
                )
                    .into_response());
            }
            Ok(())
        }
        Err(e) => {
            tracing::error!(
                error = %e,
                user_id = %user_id,
                "user-status resolution failed — failing closed (503)"
            );
            Err((
                StatusCode::SERVICE_UNAVAILABLE,
                Json(AuthErrorResponse {
                    error: "user_status_unavailable".to_string(),
                    message: "Account status is temporarily unavailable. Please retry shortly."
                        .to_string(),
                }),
            )
                .into_response())
        }
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
                // F-32: reject disabled/locked/deleted users and pre-revocation
                // tokens (fail-closed 503 on lookup error).
                if let Err(response) =
                    enforce_user_status(&auth_state, claims.sub, claims.iat).await
                {
                    return Err(response);
                }
                // Resolve permissions server-side (not stored in JWT)
                if let Some(ref resolver) = auth_state.permission_resolver {
                    claims.permissions = resolver.resolve_with_roles(claims.sub, &claims.roles).await;
                }
                // Resolve the caller's source-scope deny set (fail-closed 503).
                let scope =
                    match resolve_source_scope(&auth_state, claims.sub, &claims.roles, &claims.permissions)
                        .await
                    {
                        Ok(scope) => scope,
                        Err(response) => return Err(response),
                    };
                let mut auth_context = AuthContext::from_jwt(claims.clone());
                auth_context.denied_sources = scope;
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
                    let mut auth_context = AuthContext::from_api_key(&info);
                    let claims = auth_context.claims.clone();
                    // NAN-2043: resolve SOURCE-scope grants against the KEY's own
                    // identity, not the key owner. `claims.sub` is the owner's
                    // user_id (retained for FK / audit via `user_id()`); resolving
                    // groups against it would let a key WITHOUT
                    // `source_scopes:view_all` inherit the owner's group
                    // source-grants and read restricted sources that the search
                    // service correctly hides (search resolves against the key id
                    // → no groups → deny-all-restricted). The key's OWN permissions
                    // still drive the `source_scopes:view_all` positive bypass
                    // inside `resolve`. See `AuthContext::source_scope_principal`.
                    let scope_principal = auth_context.source_scope_principal();
                    let scope =
                        match resolve_source_scope(&auth_state, scope_principal, &claims.roles, &claims.permissions)
                        .await
                    {
                            Ok(scope) => scope,
                            Err(response) => return Err(response),
                        };
                    auth_context.denied_sources = scope;
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
                // F-32: reject disabled/locked/deleted users and pre-revocation
                // tokens (fail-closed 503 on lookup error).
                if let Err(response) =
                    enforce_user_status(&auth_state, claims.sub, claims.iat).await
                {
                    return Err(response);
                }
                // Resolve permissions server-side (not stored in JWT)
                if let Some(ref resolver) = auth_state.permission_resolver {
                    claims.permissions = resolver.resolve_with_roles(claims.sub, &claims.roles).await;
                }
                // Resolve the caller's source-scope deny set (fail-closed 503).
                let scope =
                    match resolve_source_scope(&auth_state, claims.sub, &claims.roles, &claims.permissions)
                        .await
                    {
                        Ok(scope) => scope,
                        Err(response) => return Err(response),
                    };
                let mut auth_context = AuthContext::from_jwt(claims.clone());
                auth_context.denied_sources = scope;
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

// Authorization denials are audited centrally by the `audit_authz_failures`
// middleware (NAN-687), which captures every 403 from an authenticated caller
// and emits an `auth_denied` event to the ClickHouse audit store. The former
// `require_permission` guard and `PermissionGuard` struct wrote those denials
// to the now-retired PostgreSQL `audit_logs` table and were unused — removed in
// NAN-1622.

// `check_permission`, `require_session_auth`, `require_session_or_self`,
// `check_any_permission`, and `check_all_permissions` were lifted to
// nanosiem-api-lib (NAN-751). They are re-exported at the top of this
// module so existing `crate::middleware::*` import sites still resolve.

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
        assert!(is_public_endpoint("/ready"));
        assert!(is_public_endpoint("/livez"));
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
