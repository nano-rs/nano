// SPDX-License-Identifier: AGPL-3.0-or-later

//! Middleware for the Search Service
//!
//! Provides request ID extraction/generation for distributed tracing
//! and authentication middleware for JWT/API key validation.
//!
//! Requirements: 7.3 - X-Request-ID header propagation
//! Requirements: 8.1, 8.3, 8.4, 8.6 - Authentication

use axum::{
    Json,
    extract::{ConnectInfo, Request, State},
    http::{HeaderName, HeaderValue, StatusCode, header},
    middleware::Next,
    response::{IntoResponse, Response},
};
use serde::Serialize;
use std::net::SocketAddr;
use std::sync::Arc;
use uuid::Uuid;

use nanosiem_core::auth::{
    ApiKeyInfo, ApiKeyService, ApiKeyServiceError, PermissionResolver, SourceScopeResolver,
    TokenClaims, TokenConfig, TokenService, UserStatusResolver,
};
use nanosiem_core::ip_allowlist::{IpAllowlistScope, IpAllowlistService};

/// Header name for request ID
pub const REQUEST_ID_HEADER: &str = "X-Request-ID";

/// Extension type for storing request ID in request extensions
#[derive(Clone, Debug)]
pub struct RequestId(pub String);

impl RequestId {
    /// Create a new random request ID
    pub fn new() -> Self {
        Self(Uuid::now_v7().to_string())
    }

    /// Create from an existing ID string
    pub fn from_string(id: String) -> Self {
        Self(id)
    }

    /// Get the request ID as a string slice
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Default for RequestId {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for RequestId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Public endpoints that don't require authentication
const PUBLIC_ENDPOINTS: &[&str] = &["/health", "/ready", "/livez", "/metrics"];

/// Error response for authentication failures
#[derive(Debug, Serialize)]
pub struct AuthErrorResponse {
    pub error: String,
    pub message: String,
}

impl AuthErrorResponse {
    pub fn unauthorized(message: &str) -> Self {
        Self {
            error: "unauthorized".to_string(),
            message: message.to_string(),
        }
    }
}

/// Authentication context that can be extracted from requests
#[derive(Debug, Clone)]
pub struct AuthContext {
    /// Token claims (from JWT or API key)
    pub claims: TokenClaims,
    /// Whether authentication was via API key
    pub is_api_key: bool,
    /// API key ID if authenticated via API key
    pub api_key_id: Option<Uuid>,
    /// NAN-2145: the api key's OWNER user id (`created_by`), for API-key
    /// principals. `None` for JWT sessions (the owner IS `claims.sub`) and for
    /// keys with no recorded owner. This is DISTINCT from `claims.sub`, which is
    /// the KEY id for API keys (NAN-2043, so a key does not inherit owner group
    /// grants for source-scope). Use `ownership_user_id()` — never `claims.sub`
    /// — when writing/filtering a `users(id)` ownership FK (e.g. saved searches).
    pub api_key_owner: Option<Uuid>,
    /// Per-user SOURCE-scope deny set — the restricted `source_type`s this
    /// principal may NOT read. Populated fail-closed by `SourceScopeResolver`
    /// in `auth_middleware`; defaults to unrestricted (`ScopeSet::default()`)
    /// for the constructors. NOTE: the `audit` deny is NOT baked in here —
    /// handlers UNION it separately based on the `audit:view` permission.
    pub denied_sources: nanosiem_core::auth::ScopeSet,
}

impl AuthContext {
    /// Create from JWT token claims
    pub fn from_jwt(claims: TokenClaims) -> Self {
        Self {
            claims,
            is_api_key: false,
            api_key_id: None,
            api_key_owner: None,
            denied_sources: nanosiem_core::auth::ScopeSet::default(),
        }
    }

    /// Create from API key info
    pub fn from_api_key(info: &ApiKeyInfo) -> Self {
        use nanosiem_core::auth::token::{DEFAULT_TOKEN_AUDIENCE, DEFAULT_TOKEN_ISSUER};

        Self {
            claims: TokenClaims {
                iss: DEFAULT_TOKEN_ISSUER.to_string(),
                aud: DEFAULT_TOKEN_AUDIENCE.to_string(),
                sub: info.id,
                roles: vec!["api_key".to_string()],
                permissions: info.permissions.clone(),
                exp: i64::MAX,
                iat: chrono::Utc::now().timestamp(),
                jti: Uuid::now_v7(),
                purpose: "access".to_string(),
            },
            is_api_key: true,
            api_key_id: Some(info.id),
            api_key_owner: info.user_id,
            denied_sources: nanosiem_core::auth::ScopeSet::default(),
        }
    }

    /// NAN-2145: the real `users(id)` to use as the RESOURCE OWNER for this
    /// principal — the api key's owner for API keys, or `claims.sub` for JWT
    /// sessions. Returns `None` only for an API key with no recorded owner
    /// (callers must fail closed rather than write a key id into a user FK).
    ///
    /// Keep using `claims.sub` for authorization, source-scope, and audit —
    /// this is ONLY for the ownership relationship, and must not reintroduce
    /// owner group/source-scope inheritance (NAN-2043).
    pub fn ownership_user_id(&self) -> Option<Uuid> {
        if self.is_api_key {
            self.api_key_owner
        } else {
            Some(self.claims.sub)
        }
    }

    /// NAN-2100: the CREDENTIAL that is acting — the api-key id for api-key
    /// auth, the user id for an interactive session.
    ///
    /// This is the identity that query-ownership records (`QueryTracker` /
    /// the shared Redis owner registry) are keyed on, so `DELETE
    /// /api/search/{request_id}` can permit cancellation only by the exact
    /// credential that started the query. In THIS service `claims.sub` is
    /// already the key id for api keys (NAN-2043) — unlike `nanosiem-api-lib`'s
    /// `AuthContext`, where `claims.sub` is the key's human OWNER and several
    /// owner-subject-confusion findings originated. Reading the credential
    /// through a named accessor keeps the cancel boundary correct even if the
    /// two contexts' `sub` conventions ever converge: a key must never inherit
    /// the authority of its owner's session or of the owner's other keys.
    pub fn credential_principal_id(&self) -> Uuid {
        if self.is_api_key {
            // `api_key_id` is always `Some` on an api-key context; the fallback
            // is defensive and, today, identical (`claims.sub` == key id).
            self.api_key_id.unwrap_or(self.claims.sub)
        } else {
            self.claims.sub
        }
    }
}

/// Check if a path is a public endpoint
fn is_public_endpoint(path: &str) -> bool {
    PUBLIC_ENDPOINTS.iter().any(|public| path == *public)
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

/// SECURITY: Extract client IP address from request headers with socket fallback.
///
/// Priority order matches `nanosiem-api/src/utils.rs::extract_client_ip`:
/// 1. CF-Connecting-IP  — set by Cloudflare edge, not client-controlled
/// 2. True-Client-IP    — set by Cloudflare Enterprise / Akamai edge
/// 3. X-Forwarded-For   — **rightmost** entry only (appended by trusted LB)
/// 4. X-Real-IP         — set by nginx reverse proxy
/// 5. Socket address    — direct connection, no proxy
///
/// IMPORTANT: The leftmost X-Forwarded-For entry is client-controlled and trivially
/// spoofable. We use `rsplit` to take the rightmost entry, which is appended by
/// the last trusted proxy (e.g., GKE load balancer).
fn extract_ip_address(request: &Request, connect_info: Option<&SocketAddr>) -> Option<String> {
    // Prefer CF-Connecting-IP (Cloudflare sets this to the true client IP)
    if let Some(cf_ip) = request.headers().get("CF-Connecting-IP") {
        if let Ok(value) = cf_ip.to_str() {
            let ip = value.trim();
            if !ip.is_empty() {
                return Some(ip.to_string());
            }
        }
    }
    // True-Client-IP (Cloudflare Enterprise / Akamai — also edge-set)
    if let Some(true_ip) = request.headers().get("True-Client-IP") {
        if let Ok(value) = true_ip.to_str() {
            let ip = value.trim();
            if !ip.is_empty() {
                return Some(ip.to_string());
            }
        }
    }
    // X-Forwarded-For: use the rightmost (last) entry — appended by trusted LB
    if let Some(forwarded) = request.headers().get("X-Forwarded-For") {
        if let Ok(value) = forwarded.to_str() {
            let ip = value.rsplit(',').next().unwrap_or(value).trim();
            if !ip.is_empty() {
                return Some(ip.to_string());
            }
        }
    }
    // Try X-Real-IP (nginx default)
    if let Some(real_ip) = request.headers().get("X-Real-IP") {
        if let Ok(value) = real_ip.to_str() {
            let ip = value.trim();
            if !ip.is_empty() {
                return Some(ip.to_string());
            }
        }
    }
    // Fall back to connection socket address
    connect_info.map(|addr| addr.ip().to_string())
}

/// Authentication state that holds the services needed for auth
#[derive(Clone)]
pub struct AuthState {
    pub token_service: Arc<TokenService>,
    pub api_key_service: Option<Arc<ApiKeyService>>,
    pub auth_enabled: bool,
    /// Resolves user permissions from PostgreSQL with caching.
    pub permission_resolver: Option<Arc<PermissionResolver>>,
    /// Resolves the per-user source-scope deny set (fail-closed). Mirrors
    /// `permission_resolver`; attached via `with_source_scope_resolver`.
    pub source_scope_resolver: Option<Arc<SourceScopeResolver>>,
    /// F-32: resolves the caller's `status` + `tokens_valid_from` watermark
    /// (fail-closed, short-TTL cache) so the JWT path rejects disabled/locked/
    /// deleted users and pre-revocation tokens. `None` disables the gate.
    pub user_status_resolver: Option<Arc<UserStatusResolver>>,
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

    /// Create from JWT secret (minimal setup for microservices)
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

    /// Create with API key service
    pub fn with_api_key_service(mut self, api_key_service: ApiKeyService) -> Self {
        self.api_key_service = Some(Arc::new(api_key_service));
        self
    }

    /// Set the permission resolver for server-side permission resolution
    pub fn with_permission_resolver(mut self, resolver: PermissionResolver) -> Self {
        self.permission_resolver = Some(Arc::new(resolver));
        self
    }

    /// Set the source-scope resolver for fail-closed per-user source deny-set
    /// resolution (mirrors `with_permission_resolver`).
    pub fn with_source_scope_resolver(mut self, resolver: SourceScopeResolver) -> Self {
        self.source_scope_resolver = Some(Arc::new(resolver));
        self
    }

    /// F-32: set the user-status resolver so the JWT path rejects disabled/
    /// locked/deleted users and pre-revocation access tokens.
    pub fn with_user_status_resolver(mut self, resolver: UserStatusResolver) -> Self {
        self.user_status_resolver = Some(Arc::new(resolver));
        self
    }

    /// Disable authentication (for development/testing)
    pub fn disabled() -> Self {
        let token_config = TokenConfig::new("disabled".to_string());
        let token_service = TokenService::new(token_config);

        Self {
            token_service: Arc::new(token_service),
            api_key_service: None,
            auth_enabled: false,
            permission_resolver: None,
            source_scope_resolver: None,
            user_status_resolver: None,
        }
    }
}

/// Resolve the per-user SOURCE-scope deny set, FAILING CLOSED on registry
/// unavailability.
///
/// On success returns the resolved [`ScopeSet`](nanosiem_core::auth::ScopeSet).
/// On failure returns the HTTP 503 [`Response`] the caller MUST return — the
/// request is never allowed to proceed unscoped (an empty/partial deny set is
/// never substituted on error).
///
/// When no resolver is attached (minimal/legacy `AuthState` that never wired
/// source-scoping) the deny set is empty (unrestricted). That is the
/// feature-not-configured path — distinct from the resolver erroring — and
/// preserves prior behavior for setups without a PG-backed resolver.
async fn resolve_denied_sources(
    auth_state: &AuthState,
    user_id: Uuid,
    roles: &[String],
    permissions: &[String],
) -> Result<nanosiem_core::auth::ScopeSet, Response> {
    let Some(resolver) = auth_state.source_scope_resolver.as_ref() else {
        return Ok(nanosiem_core::auth::ScopeSet::default());
    };
    match resolver.resolve(user_id, roles, permissions).await {
        Ok(scope) => Ok(scope),
        Err(e) => {
            tracing::error!(
                error = %e,
                "Source-scope registry unavailable — failing closed (503)"
            );
            Err((
                StatusCode::SERVICE_UNAVAILABLE,
                Json(AuthErrorResponse {
                    error: "source_scope_unavailable".to_string(),
                    message: "Source-scope authorization is temporarily unavailable".to_string(),
                }),
            )
                .into_response())
        }
    }
}

/// F-32: enforce that the JWT principal is still `active` and that the token was
/// issued after any forced-revocation watermark.
///
/// FAIL-CLOSED (mirrors [`resolve_denied_sources`]): a resolver error returns the
/// 503 [`Response`] the caller MUST return — never proceeds as if active. A
/// non-active status or pre-revocation token returns 401. No resolver configured
/// → gate skipped (back-compat). ONLY the JWT path calls this; the API-key path
/// checks the owner's status inside `ApiKeyService::validate_key`.
async fn enforce_user_status(
    auth_state: &AuthState,
    user_id: Uuid,
    token_iat: i64,
) -> Result<(), Response> {
    let Some(resolver) = auth_state.user_status_resolver.as_ref() else {
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
                    message: "Account status is temporarily unavailable".to_string(),
                }),
            )
                .into_response())
        }
    }
}

/// Main authentication middleware for the Search Service
///
/// Validates JWT tokens from Authorization header or API keys from X-API-Key header.
/// Allows public endpoints (health, ready, metrics) without authentication.
pub async fn auth_middleware(
    State(auth_state): State<AuthState>,
    mut request: Request,
    next: Next,
) -> Result<Response, Response> {
    // Skip auth if not enabled
    if !auth_state.auth_enabled {
        return Ok(next.run(request).await);
    }

    // Skip auth for CORS preflight requests (OPTIONS method)
    // These are handled by the CORS layer and don't include auth headers
    if request.method() == axum::http::Method::OPTIONS {
        return Ok(next.run(request).await);
    }

    let path = request.uri().path().to_string();

    // Skip auth for public endpoints
    if is_public_endpoint(&path) {
        return Ok(next.run(request).await);
    }

    // Extract ConnectInfo from request extensions (set by into_make_service_with_connect_info)
    let connect_info = request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ci| ci.0);
    let ip_address = extract_ip_address(&request, connect_info.as_ref());

    // Try JWT token first (Authorization: Bearer <token>)
    if let Some(token) = extract_bearer_token(&request) {
        match auth_state
            .token_service
            .validate_access_token_async(&token)
            .await
        {
            Ok(mut claims) => {
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
                // Resolve the per-user source-scope deny set (fail closed → 503).
                let denied_sources = match resolve_denied_sources(
                    &auth_state,
                    claims.sub,
                    &claims.roles,
                    &claims.permissions,
                )
                .await
                {
                    Ok(scope) => scope,
                    Err(response) => return Err(response),
                };
                let mut auth_context = AuthContext::from_jwt(claims.clone());
                auth_context.denied_sources = denied_sources;
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
                    // Resolve the per-user source-scope deny set (fail closed → 503).
                    // NOTE: the API-key principal's `sub` is the KEY id (not the
                    // owner), so it resolves to empty groups => deny-all-restricted.
                    // That fail-closed default for API keys is intended — keep it.
                    // A key that itself carries `source_scopes:view_all` bypasses
                    // (NAN-1841): the bypass is a POSITIVE permission check on the
                    // key's own permission set, applied inside `resolve`.
                    let denied_sources = match resolve_denied_sources(
                        &auth_state,
                        auth_context.claims.sub,
                        &auth_context.claims.roles,
                        &auth_context.claims.permissions,
                    )
                    .await
                    {
                        Ok(scope) => scope,
                        Err(response) => return Err(response),
                    };
                    auth_context.denied_sources = denied_sources;
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

    // No valid authentication found
    tracing::warn!(path = %path, "Unauthenticated request denied");

    Err((
        StatusCode::UNAUTHORIZED,
        Json(AuthErrorResponse::unauthorized("Authentication required")),
    )
        .into_response())
}

/// Middleware that intercepts plain-text error responses from axum extractor
/// rejections and replaces them with sanitized JSON error responses.
///
/// Axum's Path<T>, Query<T>, and Json<T> extractors return plain-text errors
/// that reflect raw user input verbatim — a reflected XSS vector.
/// This replaces them with safe JSON responses that omit the original input.
pub async fn sanitize_error_responses(request: Request, next: Next) -> Response {
    let response = next.run(request).await;

    let status = response.status();

    // Only intercept 400 and 422 responses with text/plain content type
    // (axum's default format for extractor rejections)
    if status != StatusCode::BAD_REQUEST && status != StatusCode::UNPROCESSABLE_ENTITY {
        return response;
    }

    let is_plain_text = response
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(|ct| ct.starts_with("text/plain"))
        .unwrap_or(false);

    if !is_plain_text {
        return response;
    }

    // Discard the original body which contains unsanitized user input
    let (parts, _body) = response.into_parts();
    tracing::debug!(status = %status, "Sanitized plain-text extractor rejection");

    let message = if status == StatusCode::UNPROCESSABLE_ENTITY {
        "Invalid request body"
    } else {
        "Invalid request"
    };

    let error_body = crate::error::ErrorResponse {
        error: crate::error::ErrorDetail::Simple {
            code: "VALIDATION_ERROR".to_string(),
            message: message.to_string(),
        },
    };

    let mut sanitized = Json(error_body).into_response();
    *sanitized.status_mut() = parts.status;
    // Preserve request-id header if present
    if let Some(req_id) = parts.headers.get("x-request-id") {
        sanitized
            .headers_mut()
            .insert("x-request-id", req_id.clone());
    }

    sanitized
}

/// Middleware that extracts or generates a request ID
///
/// If the incoming request has an X-Request-ID header, it will be used.
/// Otherwise, a new UUID will be generated.
///
/// The request ID is:
/// 1. Added to request extensions for use in handlers
/// 2. Added to the tracing span for log correlation
/// 3. Added to the response headers
///
/// Requirements: 7.3
pub async fn request_id_middleware(mut request: Request, next: Next) -> Response {
    // Extract existing request ID or generate a new one
    let request_id = request
        .headers()
        .get(REQUEST_ID_HEADER)
        .and_then(|v| v.to_str().ok())
        .map(|s| RequestId::from_string(s.to_string()))
        .unwrap_or_else(RequestId::new);

    // Create a tracing span with the request ID
    let span = tracing::info_span!(
        "request",
        request_id = %request_id,
        method = %request.method(),
        uri = %request.uri(),
    );

    // Add request ID to extensions for use in handlers
    request.extensions_mut().insert(request_id.clone());

    // Process the request within the span, measuring duration
    let start = std::time::Instant::now();
    let response = {
        let _guard = span.enter();
        next.run(request).await
    };
    let duration_ms = start.elapsed().as_millis() as u64;
    let status = response.status().as_u16();
    {
        let _guard = span.enter();
        tracing::info!(
            status = status,
            duration_ms = duration_ms,
            "Request completed"
        );
    }

    // Add request ID to response headers
    let mut response = response;
    if let Ok(header_value) = HeaderValue::from_str(request_id.as_str()) {
        response
            .headers_mut()
            .insert(HeaderName::from_static("x-request-id"), header_value);
    }

    response
}

// ============================================================================
// IP Allowlist Middleware
// ============================================================================

/// Endpoints that bypass IP allowlist checks (infrastructure probes)
const IP_BYPASS_ENDPOINTS: &[&str] = &["/health", "/ready", "/livez", "/metrics"];

/// State for the IP allowlist middleware
#[derive(Clone)]
pub struct IpAllowlistState {
    pub service: Arc<IpAllowlistService>,
    pub scope: IpAllowlistScope,
}

/// IP-denied response body
#[derive(Serialize)]
struct IpDeniedResponse {
    error: IpDeniedError,
}

#[derive(Serialize)]
struct IpDeniedError {
    code: &'static str,
    message: String,
}

/// IP allowlist middleware — blocks requests from IPs not on the allowlist.
/// Runs before auth middleware so denied IPs never reach authentication.
pub async fn ip_allowlist_middleware(
    State(state): State<IpAllowlistState>,
    request: Request,
    next: Next,
) -> Response {
    let path = request.uri().path();

    for bypass in IP_BYPASS_ENDPOINTS {
        if path == *bypass {
            return next.run(request).await;
        }
    }

    let connect_info = request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ci| ci.0);
    let client_ip = extract_ip_address(&request, connect_info.as_ref());

    let ip_str = match client_ip {
        Some(ref ip) => ip.as_str(),
        None => {
            tracing::warn!(
                "Could not extract client IP for allowlist check — denying request to {}",
                path
            );
            return ip_denied_response("unknown");
        }
    };

    if !state.service.is_allowed(ip_str, state.scope).await {
        tracing::info!(ip = %ip_str, path = %path, scope = %state.scope, "IP denied by allowlist");
        return ip_denied_response(ip_str);
    }

    next.run(request).await
}

fn ip_denied_response(ip: &str) -> Response {
    let body = IpDeniedResponse {
        error: IpDeniedError {
            code: "IP_DENIED",
            message: format!(
                "Your IP address ({}) is not authorized to access this service. Contact your administrator.",
                ip
            ),
        },
    };
    (StatusCode::FORBIDDEN, Json(body)).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn api_key_info(id: Uuid, owner: Option<Uuid>) -> ApiKeyInfo {
        ApiKeyInfo {
            id,
            name: "automation".to_string(),
            permissions: vec![],
            user_id: owner,
        }
    }

    /// NAN-2145: an API key's authorization principal (`claims.sub`) is the KEY
    /// id (NAN-2043), but the RESOURCE OWNER is the key's `user_id`. Using the
    /// key id as the `saved_searches.user_id` FK 500'd create; ownership must
    /// resolve to the owner while authz/source-scope stay key-scoped.
    #[test]
    fn ownership_user_id_uses_key_owner_not_key_id_for_api_keys() {
        let owner = Uuid::now_v7();
        let key_id = Uuid::now_v7();
        let ctx = AuthContext::from_api_key(&api_key_info(key_id, Some(owner)));
        assert_eq!(ctx.claims.sub, key_id, "authz principal stays the key id");
        assert_eq!(
            ctx.ownership_user_id(),
            Some(owner),
            "ownership resolves to the key owner"
        );
    }

    /// Fail closed rather than write a key id into a user FK.
    #[test]
    fn ownership_user_id_fails_closed_for_ownerless_key() {
        let ctx = AuthContext::from_api_key(&api_key_info(Uuid::now_v7(), None));
        assert_eq!(ctx.ownership_user_id(), None);
    }

    /// For a JWT session the owner IS `claims.sub` (behavior unchanged).
    #[test]
    fn ownership_user_id_is_sub_for_jwt_sessions() {
        let sub = Uuid::now_v7();
        let claims = TokenClaims {
            iss: "iss".to_string(),
            aud: "aud".to_string(),
            sub,
            roles: vec![],
            permissions: vec![],
            exp: i64::MAX,
            iat: 0,
            jti: Uuid::now_v7(),
            purpose: "access".to_string(),
        };
        let ctx = AuthContext::from_jwt(claims);
        assert_eq!(ctx.ownership_user_id(), Some(sub));
    }
}
