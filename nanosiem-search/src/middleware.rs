// SPDX-License-Identifier: AGPL-3.0-or-later

//! Middleware for the Search Service
//!
//! Provides request ID extraction/generation for distributed tracing
//! and authentication middleware for JWT/API key validation.
//!
//! Requirements: 7.3 - X-Request-ID header propagation
//! Requirements: 8.1, 8.3, 8.4, 8.6 - Authentication

#[cfg(feature = "enterprise")]
use nanosiem_core::request_timing::RequestDb;

#[cfg(feature = "enterprise")]
mod admission;
#[cfg(all(test, feature = "enterprise"))]
mod admission_parity_tests;
#[cfg(feature = "enterprise")]
mod enterprise_shared_auth;
#[cfg(feature = "enterprise")]
use enterprise_shared_auth::*;
#[cfg(feature = "enterprise")]
pub(crate) use enterprise_shared_auth::enterprise_shared_search_route_is_open;
use axum::{
    extract::{ConnectInfo, Request, State},
    http::{header, HeaderName, HeaderValue, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
use serde::Serialize;
use std::net::SocketAddr;
use std::sync::Arc;
use uuid::Uuid;

use nanosiem_core::auth::{
    ApiKeyInfo, ApiKeyService, ApiKeyServiceError, PermissionResolver, SourceScopeResolver,
    TenantMembershipResolver, TokenClaims, TokenConfig, TokenService, TrustedTenantContext,
    UserStatusResolver,
};
#[cfg(feature = "enterprise")]
use nanosiem_core::auth::TenantResolutionError;
#[cfg(feature = "enterprise")]
use nanosiem_core::enterprise_shared_automation_keys::{
    AuthenticatedTenantAutomationKey, TenantAutomationKeyError, TenantAutomationKeyService,
};
use nanosiem_core::ip_allowlist::{IpAllowlistScope, IpAllowlistService};
use nanosiem_core::query_retention_authority::QueryRetentionAuthority;
use nanosiem_core::search::SearchTenantScope;
#[cfg(feature = "enterprise")]
use nanosiem_core::tenant_entitlements::TenantComponent;
use nanosiem_core::tenant_entitlements::TenantEntitlementResolver;

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

/// Every failed revalidation names its cause in logs; dependency details never
/// enter the public response.
#[derive(Debug)]
#[cfg_attr(not(feature = "enterprise"), allow(dead_code))]
pub(crate) enum SharedAuthority {
    Current,
    Revoked,
    Unavailable,
}

impl SharedAuthority {
    pub(crate) fn into_result(self) -> Result<(), crate::error::SearchError> {
        match self {
            Self::Current => Ok(()),
            Self::Revoked => Err(crate::error::SearchError::Forbidden(
                "Search authority is no longer current".to_string(),
            )),
            Self::Unavailable => Err(crate::error::SearchError::SearchAuthorityUnavailable),
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
    /// Server-authenticated search keyspace. A shared scope is constructed
    /// only after the signed tenant envelope and current membership both pass.
    /// Route/header tenant selectors never reach this field.
    pub tenant_scope: SearchTenantScope,
    /// Server-owned plan/component revision that authorized Search for this
    /// shared tenant. Dedicated profiles leave this unset. Shared service
    /// resolution refuses a missing/zero revision.
    pub shared_search_entitlement_revision: Option<u64>,
    /// Whether the same immutable shared plan revision grants the tenant's
    /// prevalence component. Dedicated/open requests ignore this bit.
    pub shared_prevalence_entitled: bool,
    /// Immutable authority generations captured at shared request admission.
    /// Long-lived/result-delivery paths re-read and compare every dimension
    /// before releasing additional tenant data.
    pub shared_request_authority: Option<SharedSearchRequestAuthority>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SharedSearchRequestAuthority {
    pub tenant: TrustedTenantContext,
    pub credential: SharedSearchCredentialAuthority,
    pub membership_authority_revision: i64,
    pub entitlement_assignment_revision: i64,
    pub retention: QueryRetentionAuthority,
}

#[derive(Debug, Clone)]
pub enum SharedSearchCredentialAuthority {
    Session {
        access_jti: Uuid,
        credential_time_micros: i64,
    },
    #[cfg(feature = "enterprise")]
    TenantAutomationKey(AuthenticatedTenantAutomationKey),
}

impl PartialEq for SharedSearchCredentialAuthority {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (
                Self::Session {
                    access_jti: left_jti,
                    credential_time_micros: left_time,
                },
                Self::Session {
                    access_jti: right_jti,
                    credential_time_micros: right_time,
                },
            ) => left_jti == right_jti && left_time == right_time,
            #[cfg(feature = "enterprise")]
            (Self::TenantAutomationKey(left), Self::TenantAutomationKey(right)) => {
                left.tenant == right.tenant
                    && left.info.id == right.info.id
                    && left.info.user_id == right.info.user_id
                    && left.info.permissions == right.info.permissions
                    && left.owner_user_id == right.owner_user_id
                    && left.key_revision == right.key_revision
                    && left.authority_revision == right.authority_revision
                    && left.assignment_revision == right.assignment_revision
                    && left.issued_at == right.issued_at
                    && left.expires_at == right.expires_at
            }
            #[allow(unreachable_patterns)]
            _ => false,
        }
    }
}

impl Eq for SharedSearchCredentialAuthority {}

impl AuthContext {
    /// Create from JWT token claims
    pub fn from_jwt(claims: TokenClaims) -> Self {
        Self {
            claims,
            is_api_key: false,
            api_key_id: None,
            api_key_owner: None,
            denied_sources: nanosiem_core::auth::ScopeSet::default(),
            tenant_scope: SearchTenantScope::dedicated(),
            shared_search_entitlement_revision: None,
            shared_prevalence_entitled: false,
            shared_request_authority: None,
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
            tenant_scope: SearchTenantScope::dedicated(),
            shared_search_entitlement_revision: None,
            shared_prevalence_entitled: false,
            shared_request_authority: None,
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

    /// Capture non-secret enterprise-shared authority for durable work. The
    /// Redis admission write binds this exact stamp atomically to the job; the
    /// isolated runner revalidates it from PostgreSQL before consuming compute,
    /// on every lease heartbeat, and before publishing an artifact.
    pub fn durable_search_authority(
        &self,
    ) -> Option<nanosiem_core::search::DurableSearchJobAuthority> {
        let authority = self.shared_request_authority.as_ref()?;
        let tenant_id = self.tenant_scope.tenant_id()?;
        let (retention_revision, retention_days, irreversible_event_time_floor_micros) =
            self.tenant_scope.require_retention_identity().ok()?;
        if authority.tenant.tenant_id != tenant_id {
            return None;
        }
        let mut roles = self.claims.roles.clone();
        roles.sort();
        roles.dedup();
        let mut permissions = self.claims.permissions.clone();
        permissions.sort();
        permissions.dedup();
        Some(nanosiem_core::search::DurableSearchJobAuthority {
            tenant_id,
            user_id: self.claims.sub,
            credential: match &authority.credential {
                SharedSearchCredentialAuthority::Session {
                    access_jti,
                    credential_time_micros,
                } => nanosiem_core::search::DurableSearchCredentialAuthority::Session {
                    access_jti: *access_jti,
                    credential_time_micros: *credential_time_micros,
                },
                #[cfg(feature = "enterprise")]
                SharedSearchCredentialAuthority::TenantAutomationKey(key) => {
                    nanosiem_core::search::DurableSearchCredentialAuthority::TenantAutomationKey {
                        key_id: key.info.id,
                        owner_user_id: key.owner_user_id,
                        key_revision: key.key_revision,
                        issued_at_micros: key.issued_at.timestamp_micros(),
                        expires_at_micros: key.expires_at.map(|value| value.timestamp_micros()),
                        tenant_slug: key.tenant.tenant_slug.clone(),
                    }
                }
            },
            membership_authority_revision: authority.membership_authority_revision,
            entitlement_assignment_revision: authority.entitlement_assignment_revision,
            retention_revision,
            retention_days,
            irreversible_event_time_floor_micros,
            roles,
            permissions,
        })
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

/// Use the same direct-peer trusted-proxy boundary as the API. A supplied
/// forwarding header is never itself evidence that the sender is a proxy.
pub(crate) fn extract_ip_address(request: &Request, connect_info: Option<&SocketAddr>) -> Option<String> {
    nanosiem_api_lib::extract_client_ip(request.headers(), connect_info)
}

/// Authentication state that holds the services needed for auth
#[derive(Clone)]
pub struct AuthState {
    pub(crate) admission_cache: Arc<crate::auth_cache::AuthCache>,
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
    /// Authoritative active tenant/member resolver. Required by the hosted
    /// shared profile and deliberately unused by dedicated profiles.
    pub tenant_resolver: Option<Arc<TenantMembershipResolver>>,
    pub shared_search_entitlement_resolver: Option<Arc<TenantEntitlementResolver>>,
    /// Current immutable retention head required by every shared query path.
    pub shared_query_retention_pool: Option<sqlx::PgPool>,
    /// PostgreSQL authority for exact enterprise-shared session revocation.
    /// Redis remains the fast propagation path, but shared Search must not
    /// treat a Redis miss or outage as proof that a JTI is active.
    pub shared_session_revocation_pool: Option<sqlx::PgPool>,
    #[cfg(feature = "enterprise")]
    pub shared_automation_key_service: Option<Arc<TenantAutomationKeyService>>,
    /// Exact deployment profile bit. This is separate from the route fence so
    /// shared authentication can be tested while product routes remain closed.
    #[cfg(feature = "enterprise")]
    pub enterprise_shared: bool,
    /// Phase-0 safety boundary: shared-mode search routes stay closed until
    /// request auth, cache/job ownership, and every result reader all consume
    /// one server-resolved tenant context end to end.
    #[cfg(feature = "enterprise")]
    pub enterprise_shared_routes_closed: bool,
}

impl AuthState {
    /// Create a new auth state
    pub fn new(
        token_service: TokenService,
        api_key_service: Option<ApiKeyService>,
        auth_enabled: bool,
    ) -> Self {
        Self {
            admission_cache: Arc::new(crate::auth_cache::AuthCache::default()),
            token_service: Arc::new(token_service),
            api_key_service: api_key_service.map(Arc::new),
            auth_enabled,
            permission_resolver: None,
            source_scope_resolver: None,
            user_status_resolver: None,
            tenant_resolver: None,
            shared_search_entitlement_resolver: None,
            shared_query_retention_pool: None,
            shared_session_revocation_pool: None,
            #[cfg(feature = "enterprise")]
            shared_automation_key_service: None,
            #[cfg(feature = "enterprise")]
            enterprise_shared: false,
            #[cfg(feature = "enterprise")]
            enterprise_shared_routes_closed: false,
        }
    }

    /// Create from JWT secret (minimal setup for microservices)
    pub fn from_jwt_secret(jwt_secret: &str) -> Self {
        let token_config = TokenConfig::new(jwt_secret.to_string());
        let token_service = TokenService::new(token_config);

        Self {
            admission_cache: Arc::new(crate::auth_cache::AuthCache::default()),
            token_service: Arc::new(token_service),
            api_key_service: None,
            auth_enabled: true,
            permission_resolver: None,
            source_scope_resolver: None,
            user_status_resolver: None,
            tenant_resolver: None,
            shared_search_entitlement_resolver: None,
            shared_query_retention_pool: None,
            shared_session_revocation_pool: None,
            #[cfg(feature = "enterprise")]
            shared_automation_key_service: None,
            #[cfg(feature = "enterprise")]
            enterprise_shared: false,
            #[cfg(feature = "enterprise")]
            enterprise_shared_routes_closed: false,
        }
    }

    /// Whether this process serves the hosted shared deployment profile.
    /// An open build cannot be configured for it, so it is always `false`.
    pub fn shared_profile(&self) -> bool {
        #[cfg(feature = "enterprise")]
        {
            self.enterprise_shared
        }
        #[cfg(not(feature = "enterprise"))]
        {
            false
        }
    }

    /// Create with API key service
    pub fn with_api_key_service(mut self, api_key_service: ApiKeyService) -> Self {
        self.api_key_service = Some(Arc::new(api_key_service));
        self
    }

    pub fn with_shared_search_entitlement_resolver(
        mut self,
        resolver: TenantEntitlementResolver,
    ) -> Self {
        self.shared_search_entitlement_resolver = Some(Arc::new(resolver));
        self
    }

    pub fn with_shared_query_retention_pool(mut self, pool: sqlx::PgPool) -> Self {
        self.shared_query_retention_pool = Some(pool);
        self
    }

    pub fn with_shared_session_revocation_pool(mut self, pool: sqlx::PgPool) -> Self {
        self.shared_session_revocation_pool = Some(pool);
        self
    }

    #[cfg(feature = "enterprise")]
    pub fn with_shared_automation_key_service(
        mut self,
        service: TenantAutomationKeyService,
    ) -> Self {
        self.shared_automation_key_service = Some(Arc::new(service));
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
            admission_cache: Arc::new(crate::auth_cache::AuthCache::default()),
            token_service: Arc::new(token_service),
            api_key_service: None,
            auth_enabled: false,
            permission_resolver: None,
            source_scope_resolver: None,
            user_status_resolver: None,
            tenant_resolver: None,
            shared_search_entitlement_resolver: None,
            shared_query_retention_pool: None,
            shared_session_revocation_pool: None,
            #[cfg(feature = "enterprise")]
            shared_automation_key_service: None,
            #[cfg(feature = "enterprise")]
            enterprise_shared: false,
            #[cfg(feature = "enterprise")]
            enterprise_shared_routes_closed: false,
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
    tenant_id: Option<Uuid>,
    user_id: Uuid,
    authority_revision: Option<i64>,
    assignment_revision: Option<i64>,
    source_version: Option<i64>,
    roles: &[String],
    permissions: &[String],
) -> Result<nanosiem_core::auth::ScopeSet, Response> {
    nanosiem_core::request_timing::timed(nanosiem_core::request_timing::Phase::Scope, async {

    let Some(resolver) = auth_state.source_scope_resolver.as_ref() else {
        if tenant_id.is_some() {
            tracing::error!(
                user_id = %user_id,
                "enterprise-shared Search has no source-scope resolver"
            );
            return Err((
                StatusCode::SERVICE_UNAVAILABLE,
                Json(AuthErrorResponse {
                    error: "source_scope_unavailable".to_string(),
                    message: "Source visibility is temporarily unavailable".to_string(),
                }),
            )
                .into_response());
        }
        return Ok(nanosiem_core::auth::ScopeSet::default());
    };
    let resolved = match (tenant_id, authority_revision, assignment_revision) {
        (Some(tenant_id), Some(authority_revision), Some(assignment_revision)) => {
            resolver
                .resolve_for_tenant_at_source_version(
                    tenant_id,
                    user_id,
                    authority_revision,
                    assignment_revision,
                    roles,
                    permissions,
                    source_version,
                )
                .await
        }
        (None, None, None) => resolver.resolve(user_id, roles, permissions).await,
        _ => Err(nanosiem_core::auth::SourceScopeError::Unavailable),
    };
    match resolved {
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

    }).await
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

/// Re-read every authority dimension of a shared request before a
/// long-lived request emits more tenant data. Any denial or dependency
/// failure is fail-closed. Dedicated and open-build requests carry no shared
/// authority, so this is a no-op for them.
pub(crate) async fn revalidate_shared_context(
    auth_state: &AuthState,
    context: &AuthContext,
) -> SharedAuthority {
    #[cfg(feature = "enterprise")]
    {
        enterprise_shared_auth::revalidate_enterprise_shared_context(auth_state, context).await
    }
    #[cfg(not(feature = "enterprise"))]
    {
        let _ = (auth_state, context);
        SharedAuthority::Current
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

    #[cfg(feature = "enterprise")]
    if auth_state.enterprise_shared {
        return enterprise_shared_auth_middleware(auth_state, request, next, path).await;
    }

    #[cfg(feature = "enterprise")]
    if enterprise_shared_route_is_closed(&auth_state, request.method(), &path) {
        return Err(shared_closed_route_response(&path));
    }

    // Dedicated/open-core AUTH_ENABLED=false retains the historical behavior.
    // The enterprise-shared safety fence above is deliberately independent of
    // auth enablement so a configuration mistake cannot open shared routes.
    if !auth_state.auth_enabled {
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
                    claims.permissions =
                        resolver.resolve_with_roles(claims.sub, &claims.roles).await;
                }
                // Resolve the per-user source-scope deny set (fail closed → 503).
                let denied_sources = match resolve_denied_sources(
                    &auth_state,
                    None,
                    claims.sub,
                    None,
                    None,
                    None,
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
                        None,
                        auth_context.claims.sub,
                        None,
                        None,
                        None,
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
    use tracing::Instrument;
    use nanosiem_core::request_timing::{Phase, RequestTiming};
    let timing = Arc::new(RequestTiming::default());
    request.extensions_mut().insert(timing.clone());
    let response = timing.clone().scope(next.run(request).instrument(span.clone())).await;
    let duration_ms = start.elapsed().as_millis() as u64;
    let status = response.status().as_u16();
    {
        let _guard = span.enter();
        tracing::info!(
            status = status,
            duration_ms = duration_ms,
            auth_ms = timing.milliseconds(Phase::Auth),
            scope_ms = timing.milliseconds(Phase::Scope),
            authority_ms = timing.milliseconds(Phase::Authority),
            ledger_ms = timing.milliseconds(Phase::Ledger),
            upstream_ms = timing.milliseconds(Phase::Upstream),
            audit_ms = timing.milliseconds(Phase::Audit),
            db_roundtrips = timing.db_roundtrips(),
            admission = timing.admission().as_str(),
            "Request completed"
        );
    }

    // Add request ID to response headers
    let mut response = response;
    if let Ok(value) = HeaderValue::from_str(&timing.server_timing(start.elapsed().as_secs_f64() * 1000.0)) {
        response.headers_mut().append(HeaderName::from_static("server-timing"), value);
    }
    if let Ok(header_value) = HeaderValue::from_str(request_id.as_str()) {
        response
            .headers_mut()
            .insert(HeaderName::from_static("x-request-id"), header_value);
    }

    response
}

// ============================================================================
// Product-view memory budget (NAN-3282)
// ============================================================================

/// Product views assembled in this process from lake answers, by route, with
/// the view name their memory ledger reports. Each request on one of these
/// routes runs under its own [`nanosiem_core::search::view_memory`] ledger:
/// every lake response it reads is charged (before decode) against the
/// per-request budget and reserved from the process-wide view budget.
pub(crate) const PRODUCT_VIEW_MEMORY_ROUTES: &[(&str, &str)] = &[
    ("/api/search/asset-dossier", "asset-dossier"),
    ("/api/search/asset-events", "asset-events"),
    ("/api/search/asset-artifacts", "asset-artifacts"),
    ("/api/search/asset-true-time-range", "asset-time-range"),
    ("/api/search/cloud-overview", "cloud-overview"),
    ("/api/search/cloud-dossier", "cloud-dossier"),
    ("/api/search/cloud-events", "cloud-events"),
    ("/api/search/cloud-user-timeline", "cloud-user-timeline"),
    ("/api/search/cloud-entity-pivot", "cloud-entity-pivot"),
    ("/api/search/tree-page", "tree-page"),
    ("/api/search/prevalence-artifacts", "prevalence-artifacts"),
];

pub(crate) fn product_view_memory_name(path: &str) -> Option<&'static str> {
    PRODUCT_VIEW_MEMORY_ROUTES
        .iter()
        .find(|(route, _)| *route == path)
        .map(|(_, view)| *view)
}

/// NAN-3282: run a product-view request under a fresh view-memory ledger.
/// The ledger (and its share of the process budget) is released when the
/// handler returns. Other routes pass through untouched.
pub async fn product_view_memory_middleware(request: Request, next: Next) -> Response {
    match product_view_memory_name(request.uri().path()) {
        Some(view) => nanosiem_core::search::view_memory::scoped(view, next.run(request)).await,
        None => next.run(request).await,
    }
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

    let allowed = match state.service.check_allowed(ip_str, state.scope).await {
        Ok(allowed) => allowed,
        Err(_) => {
            tracing::error!(scope = %state.scope, "IP allowlist policy unavailable; request not admitted");
            return (StatusCode::SERVICE_UNAVAILABLE, Json(IpDeniedResponse {
                error: IpDeniedError {
                    code: "IP_POLICY_UNAVAILABLE",
                    message: "Access policy is temporarily unavailable. Please retry later.".into(),
                },
            })).into_response();
        }
    };
    if !allowed {
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
    #[test]
    fn forwarding_headers_without_a_trusted_peer_cannot_supply_client_identity() {
        for header in ["cf-connecting-ip", "true-client-ip", "x-forwarded-for", "x-real-ip"] {
            let request = Request::builder().header(header, "127.0.0.1")
                .body(axum::body::Body::empty()).unwrap();
            assert_eq!(extract_ip_address(&request, None), None, "{header}");
        }
        let peer = "203.0.113.5:1234".parse::<SocketAddr>().unwrap();
        let request = Request::builder().body(axum::body::Body::empty()).unwrap();
        assert_eq!(extract_ip_address(&request, Some(&peer)).as_deref(), Some("203.0.113.5"));
    }

    /// NAN-3282: product-view routes run under their own view-memory ledger
    /// (an oversized lake read there is a typed 413); other routes are not
    /// budgeted.
    #[tokio::test]
    async fn product_view_routes_run_under_a_view_memory_ledger() {
        use axum::{body::Body, middleware, response::IntoResponse, routing::post, Router};
        use nanosiem_core::search::view_memory;
        use tower::ServiceExt;

        async fn report() -> Response {
            let view = view_memory::current().map(|ledger| ledger.view().to_string());
            // A lake answer far past any per-request budget.
            match view_memory::charge_wire_bytes(1 << 40).await {
                Ok(()) => view.unwrap_or_else(|| "unscoped".to_string()).into_response(),
                Err(error) => crate::error::SearchError::from(error).into_response(),
            }
        }
        let app = Router::new()
            .route("/api/search/asset-dossier", post(report))
            .route("/api/search/tree-page", post(report))
            .route("/api/search", post(report))
            .layer(middleware::from_fn(product_view_memory_middleware));
        let send = |uri: &'static str| {
            let app = app.clone();
            async move {
                let response = app
                    .oneshot(Request::builder().method("POST").uri(uri).body(Body::empty()).unwrap())
                    .await
                    .unwrap();
                let status = response.status();
                let body = axum::body::to_bytes(response.into_body(), 1 << 16).await.unwrap();
                (status, String::from_utf8(body.to_vec()).unwrap())
            }
        };
        for uri in ["/api/search/asset-dossier", "/api/search/tree-page"] {
            let (status, body) = send(uri).await;
            assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE, "{uri}: {body}");
            let body: serde_json::Value = serde_json::from_str(&body).unwrap();
            assert_eq!(body["error"]["code"], "VIEW_TOO_LARGE");
            assert_eq!(body["error"]["reason"], "view_too_large");
        }
        let (status, body) = send("/api/search").await;
        assert_eq!((status, body.as_str()), (StatusCode::OK, "unscoped"));

        assert_eq!(product_view_memory_name("/api/search/asset-events"), Some("asset-events"));
        assert_eq!(product_view_memory_name("/api/search/asset-events/x"), None);
        // Every budgeted route is a real route on the search router.
        let lib = include_str!("lib.rs");
        for (route, _) in PRODUCT_VIEW_MEMORY_ROUTES {
            assert!(lib.contains(&format!("\"{route}\"")), "{route} is not routed");
        }
    }

    #[tokio::test]
    async fn ip_policy_outage_blocks_search_but_preserves_health_probe() {
        use axum::{body::Body, middleware, routing::get, Router};
        use tower::ServiceExt;

        let pool = sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgres://fixture:fixture@127.0.0.1:1/never_connect").unwrap();
        pool.close().await;
        let state = IpAllowlistState {
            service: Arc::new(IpAllowlistService::new(pool)), scope: IpAllowlistScope::Search,
        };
        let app = Router::new().route("/api/search", get(|| async { "handler reached" }))
            .route("/health", get(|| async { "healthy" }))
            .layer(middleware::from_fn_with_state(state, ip_allowlist_middleware));
        let mut request = Request::builder().uri("/api/search").body(Body::empty()).unwrap();
        request.extensions_mut().insert(ConnectInfo("203.0.113.5:1234".parse::<SocketAddr>().unwrap()));
        let response = app.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        let body = axum::body::to_bytes(response.into_body(), 4096).await.unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body, serde_json::json!({"error": {
            "code": "IP_POLICY_UNAVAILABLE",
            "message": "Access policy is temporarily unavailable. Please retry later."
        }}));
        let response = app.oneshot(Request::builder().uri("/health").body(Body::empty()).unwrap()).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }
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

    #[cfg(feature = "enterprise")]
    #[test]
    fn shared_automation_key_durable_stamp_keeps_key_and_owner_distinct() {
        let tenant_id = Uuid::from_u128(0xa);
        let key_id = Uuid::from_u128(2);
        let owner = Uuid::from_u128(1);
        let issued_at = chrono::Utc::now();
        let authenticated = AuthenticatedTenantAutomationKey {
            info: ApiKeyInfo {
                id: key_id,
                name: "soc-agent".to_string(),
                permissions: vec!["search:execute".to_string()],
                user_id: Some(owner),
            },
            tenant: TrustedTenantContext {
                tenant_id,
                tenant_slug: "tenant-a".to_string(),
            },
            owner_user_id: owner,
            key_revision: 3,
            authority_revision: 4,
            assignment_revision: 5,
            issued_at,
            expires_at: Some(issued_at + chrono::Duration::hours(1)),
        };
        let mut context = AuthContext::from_api_key(&authenticated.info);
        let retention = QueryRetentionAuthority {
            tenant_id,
            assignment_revision: 5,
            retention_revision: 6,
            retention_entitlement_revision: 1,
            retention_option_revision: 1,
            retention_days: 365,
            irreversible_event_time_floor: chrono::DateTime::UNIX_EPOCH,
            effective_at: issued_at,
        };
        context.tenant_scope = retention.search_scope().unwrap();
        context.shared_search_entitlement_revision = Some(5);
        context.shared_request_authority = Some(SharedSearchRequestAuthority {
            tenant: authenticated.tenant.clone(),
            credential: SharedSearchCredentialAuthority::TenantAutomationKey(authenticated),
            membership_authority_revision: 4,
            entitlement_assignment_revision: 5,
            retention,
        });

        let durable = context
            .durable_search_authority()
            .expect("shared key must produce exact durable authority");
        assert_eq!(durable.user_id, key_id);
        assert!(durable
            .validate_for(context.tenant_scope, key_id)
            .is_ok());
        assert!(durable
            .validate_for(context.tenant_scope, owner)
            .is_err());
        assert!(matches!(
            durable.credential,
            nanosiem_core::search::DurableSearchCredentialAuthority::TenantAutomationKey {
                key_id: stamped_key,
                owner_user_id: stamped_owner,
                key_revision: 3,
                ..
            } if stamped_key == key_id && stamped_owner == owner
        ));
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

#[cfg(test)]
mod request_timing_log_tests {
    use super::*;
    use axum::{body::Body, routing::get, Router};
    use tower::ServiceExt;

    #[tokio::test]
    async fn completed_request_log_contains_all_phase_fields_even_for_404() {
        let (events, _guard) = crate::test_support::capture_logs();
        let app = Router::new().route("/missing", get(|| async { StatusCode::NOT_FOUND }))
            .layer(axum::middleware::from_fn(request_id_middleware));
        let response = app.oneshot(Request::builder().uri("/missing").body(Body::empty()).unwrap()).await.unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        let timing = response.headers().get("server-timing").unwrap().to_str().unwrap();
        for metric in ["total", "auth", "scope", "authority", "ledger", "upstream", "audit"] {
            let prefix = format!("{metric};dur=");
            assert!(timing.split(", ").find_map(|entry| entry.strip_prefix(&prefix))
                .and_then(|value| value.parse::<f64>().ok()).is_some(), "missing {metric}: {timing}");
        }
        let events = events.lock().unwrap();
        let event = events.iter().find(|event| event.rendered.contains("Request completed")).expect("completion event");
        for field in ["auth_ms", "scope_ms", "authority_ms", "ledger_ms", "upstream_ms", "audit_ms", "duration_ms", "db_roundtrips"] {
            let prefix = format!("{field}=");
            let value = event.rendered.split_whitespace().find_map(|word| word.strip_prefix(&prefix));
            assert!(value.and_then(|value| value.parse::<f64>().ok()).is_some(), "missing numeric {field}: {event:?}");
        }
        assert!(event.rendered.contains("status=404"));
    }
}
