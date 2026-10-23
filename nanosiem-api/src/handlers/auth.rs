// SPDX-License-Identifier: AGPL-3.0-or-later

//! Authentication API handlers
//!
//! Requirements: 1.2, 1.3, 2.3, 2.6, 1.7
//!
//! This module provides handlers for:
//! - login() - Authenticate with email/password
//! - logout() - Invalidate session
//! - refresh_token() - Get new access token
//! - request_password_reset() - Request password reset email
//! - reset_password() - Complete password reset
//! - get_current_user() - Get authenticated user info

use axum::{
    extract::{ConnectInfo, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Extension, Json,
};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use uuid::Uuid;

use crate::utils::{extract_client_ip, extract_user_agent};
use nanosiem_core::audit::{
    AuditEvent, AuditSource, ClientContext, LOGIN_FAILED, LOGIN_SUCCESS, LOGOUT,
    MFA_CHALLENGE_ISSUED, PASSWORD_CHANGED, PASSWORD_RESET_COMPLETE, PASSWORD_RESET_REQUEST,
    USER_LOCKED,
};
use nanosiem_core::auth::{
    AuthError, AuthResponse, LoginRequest, LoginResult, PasswordResetCompletion,
    PasswordResetRequest, RefreshTokenRequest, TrustedTenantContext,
};

use crate::config::DeploymentMode;
use crate::handlers::AuditExt;
use crate::middleware::{require_session_auth, AuthContext};
use crate::state::AppState;

// The Set-Cookie helpers (`build_access_token_cookie`,
// `build_refresh_token_cookie`, the `clear_*` variants, and
// `extract_refresh_token_cookie`) were lifted to nanosiem-api-lib in NAN-751
// so that the OIDC handlers in the enterprise crate can reuse them without
// creating a circular crate dependency. Re-exported here so existing
// `crate::handlers::auth::*` imports continue to resolve.
pub use nanosiem_api_lib::{
    build_access_token_cookie, build_refresh_token_cookie, clear_access_token_cookie,
    clear_refresh_token_cookie, extract_refresh_token_cookie,
};
use nanosiem_api_lib::{
    append_set_cookies, clear_session_cookies_for, issued_session_set_cookies,
    legacy_session_cookie_tenant, select_tenant_cookie, shared_refresh_token_tenant,
    SessionCookieScope, REFRESH_TOKEN_COOKIE,
};
#[cfg(feature = "enterprise")]
use nanosiem_api_lib::{request_cookies, SharedRefreshCookieError};
#[cfg(feature = "enterprise")]
use nanosiem_core::auth::session_cookies::select_shared_refresh_cookie;

/// Error response for auth endpoints
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct AuthApiError {
    pub error: String,
    pub message: String,
}

impl AuthApiError {
    pub fn new(error: &str, message: &str) -> Self {
        Self {
            error: error.to_string(),
            message: message.to_string(),
        }
    }

    pub fn from_auth_error(err: &AuthError) -> (StatusCode, Self) {
        // SECURITY: Normalize authentication errors to prevent enumeration attacks
        // All credential-related failures return the same generic error to avoid
        // revealing whether a user exists, is locked, or is disabled.
        let (status, error_type, message) = match err {
            // Normalize all credential/account status errors to same response
            AuthError::InvalidCredentials
            | AuthError::AccountLocked
            | AuthError::AccountDisabled
            | AuthError::UserNotFound => (
                StatusCode::UNAUTHORIZED,
                "invalid_credentials",
                "Invalid email or password",
            ),
            // NAN-2181: NOT folded into the generic 401 above. Those variants
            // are normalized because they differ per account; this one is
            // identical for every request and is decided before any user
            // lookup, so it leaks no account state. Telling the user which
            // method to use is the entire point.
            AuthError::LocalPasswordDisabled => (
                StatusCode::FORBIDDEN,
                "local_password_disabled",
                "Password sign-in is disabled for this organization. Sign in with single sign-on.",
            ),
            AuthError::InvalidToken => (
                StatusCode::UNAUTHORIZED,
                "invalid_token",
                "Invalid or expired token",
            ),
            AuthError::SessionNotFound => (
                StatusCode::UNAUTHORIZED,
                "session_not_found",
                "Session not found or expired",
            ),
            AuthError::TenantRequired => (
                StatusCode::BAD_REQUEST,
                "tenant_required",
                "An active tenant selection is required",
            ),
            AuthError::TenantAccessDenied => (
                StatusCode::FORBIDDEN,
                "tenant_access_denied",
                "Tenant access denied",
            ),
            AuthError::TenantUnavailable => (
                StatusCode::SERVICE_UNAVAILABLE,
                "tenant_unavailable",
                "Tenant membership is temporarily unavailable",
            ),
            AuthError::PasswordRequirementsNotMet(msg) => (
                StatusCode::BAD_REQUEST,
                "password_requirements",
                msg.as_str(),
            ),
            AuthError::InvalidResetToken => (
                StatusCode::BAD_REQUEST,
                "invalid_reset_token",
                "Invalid password reset token",
            ),
            AuthError::ResetTokenExpired => (
                StatusCode::BAD_REQUEST,
                "reset_token_expired",
                "Password reset token has expired",
            ),
            AuthError::DatabaseError(_) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                "An error occurred",
            ),
            AuthError::TokenError(_) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                "An error occurred",
            ),
            AuthError::InternalError(_) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                "An error occurred",
            ),
        };

        (status, Self::new(error_type, message))
    }
}

/// Login with email and password
///
/// Requirements: 1.2, 1.3
/// - 1.2: Issue JWT access token and refresh token on valid credentials
/// - 1.3: Return authentication error without revealing which field was incorrect
///
/// POST /api/auth/login
#[utoipa::path(
    post,
    path = "/api/auth/login",
    tag = "auth",
    request_body = LoginRequest,
    responses(
        (status = 200, description = "Login successful", body = AuthResponse),
        (status = 401, description = "Invalid credentials", body = AuthApiError),
        (status = 503, description = "Authentication or durable audit unavailable", body = AuthApiError),
    ),
    security(())
)]
pub async fn login(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(request): Json<LoginRequest>,
) -> Result<Response, (StatusCode, Json<AuthApiError>)> {
    let ip_address = extract_client_ip(&headers, Some(&addr));
    let user_agent = extract_user_agent(&headers);
    let client_ctx = ClientContext::new(ip_address.clone(), user_agent.clone());

    let result = state
        .auth_service
        .login(
            &request.email,
            &request.password,
            request.tenant_slug.as_deref(),
            ip_address.as_deref(),
            user_agent.as_deref(),
        )
        .await;

    match result {
        Ok(LoginResult::Success(response)) => {
            // Emit login success audit event
            state.emit_audit(
                AuditEvent::builder(AuditSource::Auth, LOGIN_SUCCESS)
                    .actor(Some(response.user.id), Some(response.user.email.clone()))
                    .resource(
                        "user",
                        Some(response.user.id),
                        Some(response.user.email.clone()),
                    )
                    .client_context(&client_ctx)
                    .build(),
            );

            // Set the access_token cookie (browser-based access, e.g. Swagger UI)
            // and the HttpOnly refresh_token cookie (scoped to /api/auth).
            // NAN-3548: hosted-shared names them per tenant.
            #[cfg(feature = "enterprise")]
            let cookies = issued_session_set_cookies(
                &headers,
                &state.token_service,
                state.config.deployment_mode.is_enterprise_shared(),
                &response.tokens.access_token,
                response.tokens.expires_in,
                &response.tokens.refresh_token,
                state.token_service.refresh_token_ttl(),
            );
            #[cfg(not(feature = "enterprise"))]
            let cookies = issued_session_set_cookies(
                &headers,
                &state.token_service,
                false,
                &response.tokens.access_token,
                response.tokens.expires_in,
                &response.tokens.refresh_token,
                state.token_service.refresh_token_ttl(),
            );
            let mut res = Json(&response).into_response();
            append_set_cookies(res.headers_mut(), cookies);
            Ok(res)
        }
        Ok(LoginResult::MfaRequired { challenge_token }) => {
            // Password verified; MFA code now required. Audit the challenge
            // issuance (the actor is recovered from the freshly minted challenge
            // token). Completion/failure is audited by verify_mfa_challenge.
            #[cfg(feature = "enterprise")]
            if state.config.deployment_mode.is_enterprise_shared() {
                super::auth_challenge_audit::record(
                    &state, &challenge_token, request.tenant_slug.as_deref(), &client_ctx,
                    MFA_CHALLENGE_ISSUED, true, None,
                ).await.map_err(|_| (StatusCode::SERVICE_UNAVAILABLE, Json(
                    AuthApiError::new("audit_unavailable", "Authentication auditing is temporarily unavailable"),
                )))?;
            } else {
                let actor_id = state.token_service.validate_mfa_challenge_token_async(&challenge_token)
                    .await.ok().map(|c| c.sub);
                state.emit_audit(
                    AuditEvent::builder(AuditSource::Auth, MFA_CHALLENGE_ISSUED)
                        .actor(actor_id, Some(request.email.clone()))
                        .resource("user", actor_id, Some(request.email.clone()))
                        .client_context(&client_ctx).build(),
                );
            }
            #[cfg(not(feature = "enterprise"))]
            {
                let actor_id = state.token_service.validate_mfa_challenge_token_async(&challenge_token)
                    .await.ok().map(|c| c.sub);
                state.emit_audit(
                    AuditEvent::builder(AuditSource::Auth, MFA_CHALLENGE_ISSUED)
                        .actor(actor_id, Some(request.email.clone()))
                        .resource("user", actor_id, Some(request.email.clone()))
                        .client_context(&client_ctx).build(),
                );
            }
            // MFA enabled — return challenge token, no cookies/tokens
            Ok(Json(serde_json::json!({
                "status": "mfa_required",
                "mfa_required": true,
                "challenge_token": challenge_token,
            }))
            .into_response())
        }
        Ok(LoginResult::MfaSetupRequired { challenge_token }) => {
            // Admin requires MFA but user hasn't enrolled yet
            #[cfg(feature = "enterprise")]
            if state.config.deployment_mode.is_enterprise_shared() {
                super::auth_challenge_audit::record(
                    &state, &challenge_token, request.tenant_slug.as_deref(), &client_ctx,
                    MFA_CHALLENGE_ISSUED, true, Some(serde_json::json!({"setup_required": true})),
                ).await.map_err(|_| (StatusCode::SERVICE_UNAVAILABLE, Json(
                    AuthApiError::new("audit_unavailable", "Authentication auditing is temporarily unavailable"),
                )))?;
            }
            Ok(Json(serde_json::json!({
                "status": "mfa_setup_required",
                "mfa_setup_required": true,
                "challenge_token": challenge_token,
            }))
            .into_response())
        }
        Err(e) => {
            // Emit login failed audit event. NAN-3790: on the hosted shared
            // host there is no verified actor; the row is written actorless
            // into the tenant the route slug selects.
            state.emit_preauth_audit(
                request.tenant_slug.as_deref(),
                AuditEvent::builder(AuditSource::Auth, LOGIN_FAILED)
                    .actor(None, Some(request.email.clone()))
                    .resource("user", None, Some(request.email.clone()))
                    .client_context(&client_ctx)
                    .success(false)
                    .details(serde_json::json!({
                        "error": e.to_string(),
                        // NAN-2181: separates "wrong password" from "password
                        // sign-in is switched off for this tenant", so an
                        // SSO-only org can alert on clients still presenting
                        // local credentials — a stale bookmark, an unmigrated
                        // script, or someone probing.
                        "blocked_reason": matches!(e, AuthError::LocalPasswordDisabled)
                            .then_some("local_password_disabled"),
                    }))
                    .build(),
            );
            // The auth service signals a fresh lockout via AccountLocked, returned
            // ONLY on the attempt that crosses the failed-attempt threshold (not on
            // every subsequent attempt against an already-throttled account), so
            // user_locked is audited exactly once per lock episode. Within the login
            // flow authenticate() returns AccountLocked only at that crossing — its
            // disabled and hard-locked checks return generic InvalidCredentials for
            // enumeration safety — so this match is precise (refresh_token's own
            // AccountLocked never reaches this handler). AccountLocked is normalized
            // to a generic 401 by from_auth_error, so the client still can't
            // enumerate. The account is identified by email; no user_id is exposed
            // here (enumeration-safety), matching login_failed.
            if matches!(e, AuthError::AccountLocked) {
                state.emit_preauth_audit(
                    request.tenant_slug.as_deref(),
                    AuditEvent::builder(AuditSource::Auth, USER_LOCKED)
                        .actor(None, Some(request.email.clone()))
                        .resource("user", None, Some(request.email.clone()))
                        .client_context(&client_ctx)
                        .success(false)
                        .details(serde_json::json!({
                            "reason": "failed_login_threshold_exceeded"
                        }))
                        .build(),
                );
            }
            let (status, err) = AuthApiError::from_auth_error(&e);
            Err((status, Json(err)))
        }
    }
}

/// Logout request body
#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct LogoutRequest {
    pub refresh_token: Option<String>,
}

/// Logout and invalidate session
///
/// Requirements: 2.6 - Invalidate the refresh token on logout
///
/// POST /api/auth/logout
#[utoipa::path(
    post,
    path = "/api/auth/logout",
    tag = "auth",
    request_body = LogoutRequest,
    responses(
        (status = 204, description = "Logout successful"),
        (status = 401, description = "Invalid token", body = AuthApiError),
        (status = 403, description = "Forbidden — interactive session required (API keys have no session)", body = AuthApiError),
        (status = 500, description = "Shared-mode durable revocation could not be completed safely", body = AuthApiError),
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn logout(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Extension(auth): Extension<AuthContext>,
    tenant: Option<Extension<TrustedTenantContext>>,
    Json(request): Json<LogoutRequest>,
) -> Result<Response, Response> {
    // NAN-2040: an API key has no interactive browser session to end. Its subject
    // is its owner, so without this a (possibly zero-permission) key could
    // force-revoke ALL of the owner's browser sessions via the bulk termination
    // below (the alternate route past the session-handler guards). API keys are
    // revoked by deleting the key, not by logout.
    #[cfg(feature = "enterprise")]
    let shared_logout = state.config.deployment_mode.is_enterprise_shared();
    #[cfg(not(feature = "enterprise"))]
    let shared_logout = false;
    let shared_tenant_id = tenant.as_ref().map(|Extension(tenant)| tenant.tenant_id);
    // NAN-3548: shared logout ends exactly the authenticated tenant's browser
    // session; other tenants' cookies in the same jar are never touched. The
    // legacy unsuffixed pair is cleared only when it is bound to this tenant.
    let logout_clears = match (shared_logout, shared_tenant_id) {
        (false, _) => clear_session_cookies_for(SessionCookieScope::Default),
        (true, None) => Vec::new(),
        (true, Some(tenant_id)) => {
            let mut clears = clear_session_cookies_for(SessionCookieScope::Tenant(tenant_id));
            if legacy_session_cookie_tenant(&headers, &state.token_service) == Some(tenant_id) {
                clears.extend(clear_session_cookies_for(SessionCookieScope::Default));
            }
            clears
        }
    };
    if auth.is_api_key {
        return Err(logout_error_response(
            &logout_clears,
            StatusCode::FORBIDDEN,
            AuthApiError::new(
                "interactive_session_required",
                "Logout requires an interactive session; API keys have no session to end.",
            ),
        ));
    }

    let ip_address = extract_client_ip(&headers, Some(&addr));
    let user_agent = extract_user_agent(&headers);
    let client_ctx = ClientContext::new(ip_address.clone(), user_agent.clone());
    let refresh_token = request.refresh_token.or_else(|| {
        if shared_logout {
            shared_tenant_id.and_then(|tenant_id| {
                select_tenant_cookie(&headers, REFRESH_TOKEN_COOKIE, tenant_id, |token| {
                    shared_refresh_token_tenant(&state.token_service, token)
                })
                .map(|cookie| cookie.value)
            })
        } else {
            extract_refresh_token_cookie(&headers)
        }
    });

    // A queued tenant-A logout can run after another tab has installed tenant
    // B's origin-wide refresh cookie. The bearer still authenticates A, so
    // compare the independently presented refresh credential before mutating
    // either identity. A mismatch is a stale browser operation: fail without
    // clearing cookies or deleting B's session.
    #[cfg(feature = "enterprise")]
    if shared_logout {
        let trusted_tenant = tenant
            .as_ref()
            .map(|Extension(tenant)| tenant)
            .ok_or_else(|| {
                logout_error_response_without_cookie_clear(
                    StatusCode::SERVICE_UNAVAILABLE,
                    AuthApiError::new(
                        "tenant_context_unavailable",
                        "Tenant session authorization is temporarily unavailable",
                    ),
                )
            })?;
        if let Some(token) = refresh_token.as_deref() {
            if let Ok(refresh) = state
                .token_service
                .validate_enterprise_shared_refresh_token(token)
            {
                if !shared_logout_identity_matches(
                    auth.user_id(),
                    trusted_tenant.tenant_id,
                    refresh.claims.sub,
                    refresh.tenant_id,
                ) {
                    // The replacement cookie belongs to B, but the presented
                    // bearer is still A's exact credential. Revoke the whole
                    // tenant-A session namespace while preserving B. Otherwise
                    // a captured A refresh cookie could survive a user-visible
                    // logout simply because B currently owns the browser's
                    // origin-wide refresh cookie.
                    state
                        .session_service
                        .terminate_tenant_user_sessions(
                            trusted_tenant.tenant_id,
                            auth.user_id(),
                            auth.user_id(),
                            true,
                        )
                        .await
                        .map_err(|error| {
                            tracing::error!(
                                tenant_id = %trusted_tenant.tenant_id,
                                user_id = %auth.user_id(),
                                %error,
                                "failed to revoke replaced tenant session namespace"
                            );
                            logout_error_response_without_cookie_clear(
                                StatusCode::SERVICE_UNAVAILABLE,
                                AuthApiError::new(
                                    "revocation_unavailable",
                                    "Tenant session could not be revoked safely",
                                ),
                            )
                        })?;
                    nanosiem_core::auth::token::persist_revoked_token(
                        &state.pool,
                        auth.claims.jti,
                        auth.claims.exp,
                    )
                    .await
                    .map_err(|error| {
                        tracing::error!(jti = %auth.claims.jti, %error, "failed to persist stale logout credential revocation");
                        logout_error_response_without_cookie_clear(
                            StatusCode::SERVICE_UNAVAILABLE,
                            AuthApiError::new(
                                "revocation_unavailable",
                                "Logout credential could not be revoked safely",
                            ),
                        )
                    })?;
                    state
                        .token_service
                        .revoke_token(auth.claims.jti, auth.claims.exp)
                        .await;
                    return Err(logout_error_response_without_cookie_clear(
                        StatusCode::CONFLICT,
                        AuthApiError::new(
                            "session_replaced",
                            "A different tenant session replaced this browser session",
                        ),
                    ));
                }
            }
        }
    }

    // Shared logout revokes exactly this authenticated tenant's sessions.
    // The same user can independently belong to another tenant. Dedicated
    // compatibility still revokes all sessions for the authenticated user.
    // C4: Always revoke ALL sessions in the selected namespace on logout.
    // Previously only the session matching the provided refresh token was deleted,
    // leaving other refresh tokens alive for up to 7 days. The service now
    // advances the user (dedicated) or membership (shared) revocation watermark
    // in the same transaction as the session
    // delete, so an in-flight refresh response cannot restore a usable access
    // cookie after this logout completes.
    let terminate_result = if shared_logout {
        let tenant_id = tenant.as_ref().map(|Extension(tenant)| tenant.tenant_id)
            .ok_or_else(|| {
                logout_error_response_without_cookie_clear(
                    StatusCode::SERVICE_UNAVAILABLE,
                    AuthApiError::new(
                        "tenant_context_unavailable",
                        "Tenant session authorization is temporarily unavailable",
                    ),
                )
            })?;
        state.session_service
            .terminate_tenant_user_sessions(tenant_id, auth.user_id(), auth.user_id(), true)
            .await
    } else {
        state.session_service.terminate_all_user_sessions(
            auth.user_id(), auth.user_id(), true,
            ip_address.as_deref(), user_agent.as_deref(),
        ).await
    };
    let termination_failed = terminate_result
        .inspect_err(|error| {
            tracing::warn!(user_id = %auth.user_id(), %error, "failed to terminate sessions during logout");
        })
        .is_err();

    // Dedicated compatibility retains the legacy single-session cleanup.
    // Shared logout already atomically removed this authenticated tenant/user
    // namespace above. Any independently presented refresh credential was
    // identity-matched before mutation; bearer-only clients need no cookie.
    if !shared_logout {
        if let Some(ref token) = refresh_token {
            let _ = state
                .auth_service
                .logout(token, ip_address.as_deref(), user_agent.as_deref())
                .await;
        }
    }

    // Revoke the current access token so it cannot be reused before expiry
    state
        .token_service
        .revoke_token(auth.claims.jti, auth.claims.exp)
        .await;
    // H8: Persist revocation to PostgreSQL so it survives restarts
    let persistence = nanosiem_core::auth::token::persist_revoked_token(
        &state.pool,
        auth.claims.jti,
        auth.claims.exp,
    )
    .await;
    let persistence_failed = persistence
        .inspect_err(|error| {
            tracing::warn!(jti = %auth.claims.jti, %error, "failed to persist token revocation during logout");
        })
        .is_err();
    if shared_logout && (termination_failed || persistence_failed) {
        return Err(logout_error_response(
            &logout_clears,
            StatusCode::INTERNAL_SERVER_ERROR,
            AuthApiError::new("internal_error", "Logout could not be completed safely"),
        ));
    }

    // Emit logout audit event. NAN-3790: hosted shared writes it in the
    // authenticated tenant (the shared emitter refuses tenantless rows).
    let logout_event = AuditEvent::builder(AuditSource::Auth, LOGOUT)
        .actor(Some(auth.user_id()), None)
        .resource("session", None, None)
        .client_context(&client_ctx)
        .build();
    match tenant.filter(|_| shared_logout) {
        Some(Extension(tenant)) => state.emit_tenant_auth_audit(tenant, auth.user_id(), vec![logout_event]),
        None => state.emit_audit(logout_event),
    }

    // Clear this session's access + refresh cookies
    let mut res = StatusCode::NO_CONTENT.into_response();
    append_set_cookies(res.headers_mut(), logout_clears);
    Ok(res)
}

fn logout_error_response(clears: &[String], status: StatusCode, error: AuthApiError) -> Response {
    let mut response = (status, Json(error)).into_response();
    append_set_cookies(response.headers_mut(), clears.iter().cloned());
    response
}

fn logout_error_response_without_cookie_clear(
    status: StatusCode,
    error: AuthApiError,
) -> Response {
    (status, Json(error)).into_response()
}

#[cfg(feature = "enterprise")]
fn shared_logout_identity_matches(
    authenticated_user_id: Uuid,
    authenticated_tenant_id: Uuid,
    refresh_user_id: Uuid,
    refresh_tenant_id: Uuid,
) -> bool {
    authenticated_user_id == refresh_user_id && authenticated_tenant_id == refresh_tenant_id
}

/// Refresh token response
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct RefreshTokenResponse {
    pub access_token: String,
    pub refresh_token: String,
    pub token_type: String,
    pub expires_in: i64,
}

/// Refresh access token
///
/// Requirements: 2.3 - Allow token refresh using a valid refresh token
///
/// POST /api/auth/refresh
#[utoipa::path(
    post,
    path = "/api/auth/refresh",
    tag = "auth",
    request_body = RefreshTokenRequest,
    responses(
        (status = 200, description = "Token refreshed successfully", body = RefreshTokenResponse),
        (status = 400, description = "No refresh token in body or cookie (e.g. hosted-shared activation before MFA enrollment issues a session)", body = AuthApiError),
        (status = 401, description = "Invalid refresh token", body = AuthApiError),
    ),
    security(())
)]
pub async fn refresh_token(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(request): Json<RefreshTokenRequest>,
) -> Result<Response, (StatusCode, Json<AuthApiError>)> {
    let ip_address = extract_client_ip(&headers, Some(&addr));
    let user_agent = extract_user_agent(&headers);
    let tenant_slug = request.tenant_slug.clone();

    #[cfg(feature = "enterprise")]
    let enterprise_shared = state.config.deployment_mode.is_enterprise_shared();
    let missing_token = || {
        (
            StatusCode::BAD_REQUEST,
            Json(AuthApiError::new(
                "missing_token",
                "Refresh token required (in body or cookie)",
            )),
        )
    };

    // Resolve refresh token from body or cookie. `refusal_clears` names the
    // cookies a refused refresh may clear: in single-tenant modes the one
    // session pair; in hosted-shared only the pair of the tenant being
    // refreshed (NAN-3548), so a refusal for tenant B never ends tenant A.
    #[cfg(feature = "enterprise")]
    let (refresh_token_value, refusal_clears) = match request.refresh_token {
        Some(token) => (
            token,
            if enterprise_shared {
                Vec::new()
            } else {
                clear_session_cookies_for(SessionCookieScope::Default)
            },
        ),
        None if enterprise_shared => {
            match select_shared_refresh_cookie(
                &state.auth_service,
                &state.token_service,
                &request_cookies(&headers),
                tenant_slug.as_deref(),
            )
            .await
            {
                Ok(cookie) => (cookie.value, cookie.refusal_clears),
                Err(SharedRefreshCookieError::Missing) => return Err(missing_token()),
                Err(SharedRefreshCookieError::Auth(error)) => {
                    let (status, err) = AuthApiError::from_auth_error(&error);
                    return Err((status, Json(err)));
                }
            }
        }
        None => (
            extract_refresh_token_cookie(&headers).ok_or_else(missing_token)?,
            clear_session_cookies_for(SessionCookieScope::Default),
        ),
    };
    #[cfg(not(feature = "enterprise"))]
    let (refresh_token_value, refusal_clears) = match request.refresh_token {
        Some(token) => (token, clear_session_cookies_for(SessionCookieScope::Default)),
        None => (
            extract_refresh_token_cookie(&headers).ok_or_else(missing_token)?,
            clear_session_cookies_for(SessionCookieScope::Default),
        ),
    };

    let token_pair = match state
        .auth_service
        .refresh_token(
            &refresh_token_value,
            tenant_slug.as_deref(),
            ip_address.as_deref(),
            user_agent.as_deref(),
        )
        .await
    {
        Ok(pair) => pair,
        Err(e) => {
            let (status, err) = AuthApiError::from_auth_error(&e);
            // Clear stale cookies so they don't persist and keep failing
            let mut res = (status, Json(err)).into_response();
            append_set_cookies(res.headers_mut(), refusal_clears);
            return Ok(res);
        }
    };

    let response = RefreshTokenResponse {
        access_token: token_pair.access_token,
        refresh_token: token_pair.refresh_token,
        token_type: token_pair.token_type,
        expires_in: token_pair.expires_in,
    };

    // Set updated cookies (append pattern for multiple Set-Cookie headers).
    // NAN-3548: shared mode re-issues under the tenant-suffixed names and
    // clears the same tenant's legacy unsuffixed pair (migration).
    #[cfg(feature = "enterprise")]
    let cookies = issued_session_set_cookies(
        &headers,
        &state.token_service,
        enterprise_shared,
        &response.access_token,
        response.expires_in,
        &response.refresh_token,
        state.token_service.refresh_token_ttl(),
    );
    #[cfg(not(feature = "enterprise"))]
    let cookies = issued_session_set_cookies(
        &headers,
        &state.token_service,
        false,
        &response.access_token,
        response.expires_in,
        &response.refresh_token,
        state.token_service.refresh_token_ttl(),
    );
    let mut res = Json(&response).into_response();
    append_set_cookies(res.headers_mut(), cookies);
    Ok(res)
}

/// Password reset request response
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct PasswordResetResponse {
    pub message: String,
}

/// Request password reset
///
/// Requirements: 1.7 - Generate a time-limited reset token valid for 1 hour
///
/// POST /api/auth/password/reset-request
#[utoipa::path(
    post,
    path = "/api/auth/password/reset-request",
    tag = "auth",
    request_body = PasswordResetRequest,
    responses(
        (status = 200, description = "Password reset email sent (always returns success to prevent email enumeration)", body = PasswordResetResponse),
    ),
    security(())
)]
pub async fn request_password_reset(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(request): Json<PasswordResetRequest>,
) -> Result<Json<PasswordResetResponse>, (StatusCode, Json<AuthApiError>)> {
    let ip_address = extract_client_ip(&headers, Some(&addr));
    let user_agent = extract_user_agent(&headers);
    let client_ctx = ClientContext::new(ip_address.clone(), user_agent.clone());

    // Note: In production, this would send an email instead of returning the token
    let result = state
        .auth_service
        .request_password_reset(
            &request.email,
            request.tenant_slug.as_deref(),
            ip_address.as_deref(),
            user_agent.as_deref(),
        )
        .await;

    // Emit audit event regardless of success (but don't reveal if email exists)
    // NAN-3790: actorless; hosted shared scopes it to the slug's tenant.
    state.emit_preauth_audit(
        request.tenant_slug.as_deref(),
        AuditEvent::builder(AuditSource::Auth, PASSWORD_RESET_REQUEST)
            .actor(None, Some(request.email.clone()))
            .resource("user", None, Some(request.email.clone()))
            .client_context(&client_ctx)
            .success(result.is_ok())
            .build(),
    );

    // Map error but still return success message to prevent email enumeration
    let _token = result.map_err(|e| {
        let (status, err) = AuthApiError::from_auth_error(&e);
        (status, Json(err))
    })?;

    // Always return success to prevent email enumeration
    Ok(Json(PasswordResetResponse {
        message: "If an account with that email exists, a password reset link has been sent."
            .to_string(),
    }))
}

/// Password reset complete response
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct PasswordResetCompleteResponse {
    pub message: String,
}

/// Complete password reset
///
/// Requirements: 1.7 - Reset password with valid token
///
/// POST /api/auth/password/reset
#[utoipa::path(
    post,
    path = "/api/auth/password/reset",
    tag = "auth",
    request_body = PasswordResetCompletion,
    responses(
        (status = 200, description = "Password reset successful", body = PasswordResetCompleteResponse),
        (status = 400, description = "Invalid or expired token", body = AuthApiError),
    ),
    security(())
)]
pub async fn reset_password(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(request): Json<PasswordResetCompletion>,
) -> Result<Json<PasswordResetCompleteResponse>, (StatusCode, Json<AuthApiError>)> {
    let ip_address = extract_client_ip(&headers, Some(&addr));
    let user_agent = extract_user_agent(&headers);
    let client_ctx = ClientContext::new(ip_address.clone(), user_agent.clone());

    let result = state
        .auth_service
        .reset_password(
            &request.token,
            &request.new_password,
            ip_address.as_deref(),
            user_agent.as_deref(),
        )
        .await;

    match &result {
        Ok(user_id) => {
            // Emit password reset complete audit event. NAN-3790: hosted
            // shared writes it, signed as the account whose password changed,
            // in its home tenant (tenant-scoped identity) or in every tenant
            // where a legacy global identity is an active member.
            state.emit_password_reset_complete_audit(*user_id, client_ctx.clone());
        }
        Err(e) => {
            // Emit failed password reset audit event. The token resolved to
            // no account, so hosted shared has no tenant to scope it to.
            state.emit_preauth_audit(
                None,
                AuditEvent::builder(AuditSource::Auth, PASSWORD_RESET_COMPLETE)
                    .resource("user", None, None)
                    .client_context(&client_ctx)
                    .success(false)
                    .details(serde_json::json!({
                        "error": e.to_string()
                    }))
                    .build(),
            );
        }
    }

    result.map_err(|e| {
        let (status, err) = AuthApiError::from_auth_error(&e);
        (status, Json(err))
    })?;

    Ok(Json(PasswordResetCompleteResponse {
        message: "Password has been reset successfully. Please log in with your new password."
            .to_string(),
    }))
}

/// Change password request
#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct ChangePasswordRequest {
    pub current_password: String,
    pub new_password: String,
}

/// Change password response
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct ChangePasswordResponse {
    pub message: String,
}

/// Change own password (authenticated)
///
/// Allows a logged-in user to change their own password by providing
/// their current password and a new password that meets complexity requirements.
/// All existing sessions are invalidated on success.
///
/// PUT /api/auth/password
#[utoipa::path(
    put,
    path = "/api/auth/password",
    tag = "auth",
    request_body = ChangePasswordRequest,
    responses(
        (status = 200, description = "Password changed successfully", body = ChangePasswordResponse),
        (status = 401, description = "Current password is incorrect", body = AuthApiError),
        (status = 403, description = "Session-only endpoint — API keys are rejected", body = AuthApiError),
        (status = 400, description = "New password does not meet requirements", body = AuthApiError),
    ),
    security(("bearer_auth" = []))
)]
#[cfg_attr(not(feature = "enterprise"), allow(unused_variables))]
pub async fn change_password(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Extension(auth): Extension<AuthContext>,
    tenant: Option<Extension<TrustedTenantContext>>,
    Json(request): Json<ChangePasswordRequest>,
) -> Result<Response, (StatusCode, Json<AuthApiError>)> {
    // NAN-2080: credential mutation is session-only. An owner-bound API key maps
    // its `sub` to the owner user id, so without this gate a leaked automation
    // key plus the owner's password could rotate the password / take over the
    // account without an MFA-completed interactive session. Password confirmation
    // is re-auth, not proof of a second factor. (Note: a password change does NOT
    // revoke the owner's API keys — a long-lived key survives the rotation.)
    require_session_auth(&auth)
        .map_err(|(s, j)| (s, Json(AuthApiError::new(&j.error, &j.message))))?;

    let ip_address = extract_client_ip(&headers, Some(&addr));
    let user_agent = extract_user_agent(&headers);
    let client_ctx = ClientContext::new(ip_address.clone(), user_agent.clone());

    let result = state
        .auth_service
        .change_password(
            auth.user_id(),
            &request.current_password,
            &request.new_password,
            ip_address.as_deref(),
            user_agent.as_deref(),
        )
        .await;

    let mut password_event = AuditEvent::builder(AuditSource::Auth, PASSWORD_CHANGED)
        .actor(Some(auth.user_id()), None)
        .resource("user", Some(auth.user_id()), None)
        .client_context(&client_ctx);
    if let Err(e) = &result {
        password_event = password_event
            .success(false)
            .details(serde_json::json!({
                "error": e.to_string()
            }));
    }
    let password_event = password_event.build();
    // NAN-3790: hosted shared writes it in the authenticated tenant.
    #[cfg(feature = "enterprise")]
    match tenant.clone().filter(|_| state.config.deployment_mode.is_enterprise_shared()) {
        Some(Extension(tenant)) => {
            state.emit_tenant_auth_audit(tenant, auth.user_id(), vec![password_event])
        }
        None => state.emit_audit(password_event),
    }
    #[cfg(not(feature = "enterprise"))]
    state.emit_audit(password_event);

    result.map_err(|e| {
        let (status, err) = AuthApiError::from_auth_error(&e);
        (status, Json(err))
    })?;

    // Clear cookies since all sessions are invalidated
    let mut res = Json(ChangePasswordResponse {
        message: "Password changed successfully. Please log in again.".to_string(),
    })
    .into_response();
    // NAN-3548: shared mode clears this tenant's pair (and the legacy pair
    // only when it is bound to this tenant); single-tenant modes unchanged.
    #[cfg(feature = "enterprise")]
    let clears = match tenant.filter(|_| state.config.deployment_mode.is_enterprise_shared()) {
        Some(Extension(tenant)) => {
            let mut clears =
                clear_session_cookies_for(SessionCookieScope::Tenant(tenant.tenant_id));
            if legacy_session_cookie_tenant(&headers, &state.token_service)
                == Some(tenant.tenant_id)
            {
                clears.extend(clear_session_cookies_for(SessionCookieScope::Default));
            }
            clears
        }
        None => clear_session_cookies_for(SessionCookieScope::Default),
    };
    #[cfg(not(feature = "enterprise"))]
    let clears = clear_session_cookies_for(SessionCookieScope::Default);
    append_set_cookies(res.headers_mut(), clears);
    Ok(res)
}

/// Current user response
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct ActiveTenantResponse {
    #[schema(value_type = String)]
    pub id: Uuid,
    pub slug: String,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct CurrentUserResponse {
    #[serde(with = "nanosiem_core::typeid::user")]
    #[schema(value_type = String)]
    pub id: Uuid,
    pub email: String,
    pub name: String,
    pub roles: Vec<String>,
    pub permissions: Vec<String>,
    pub is_api_key: bool,
    pub preferred_query_mode: Option<String>,
    pub landing_page: Option<String>,
    /// Exact server-owned profile. The browser must not infer shared tenancy
    /// from a build flag or from the route it happened to load.
    pub deployment_mode: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub active_tenant: Option<ActiveTenantResponse>,
    /// Present only for a live demo analyst of a demo tenant.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub demo: Option<CurrentUserDemo>,
}

/// The caller's demo session (shared demo tenants only).
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct CurrentUserDemo {
    pub active: bool,
    pub expires_at: chrono::DateTime<chrono::Utc>,
}

/// Get current authenticated user
///
/// GET /api/auth/me
///
/// Note: User info (email, name) is fetched from the database rather than
/// being stored in the JWT token. This keeps PII out of tokens for security.
#[utoipa::path(
    get,
    path = "/api/auth/me",
    tag = "auth",
    responses(
        (status = 200, description = "Current user information", body = CurrentUserResponse),
        (status = 401, description = "Not authenticated", body = AuthApiError),
        (status = 404, description = "User not found", body = AuthApiError),
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn get_current_user(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    tenant: Option<Extension<TrustedTenantContext>>,
    #[cfg(feature = "enterprise")] demo: Option<Extension<nanosiem_core::enterprise_shared_demo::SharedDemoPrincipal>>,
) -> Result<Json<CurrentUserResponse>, (StatusCode, Json<AuthApiError>)> {
    #[cfg(feature = "enterprise")]
    let demo = demo.map(|Extension(principal)| CurrentUserDemo { active: true, expires_at: principal.expires_at });
    #[cfg(not(feature = "enterprise"))]
    let demo: Option<CurrentUserDemo> = None;
    let deployment_mode = match state.config.deployment_mode {
        DeploymentMode::Managed => "managed",
        #[cfg(feature = "enterprise")]
        DeploymentMode::EnterpriseShared => "enterprise_shared",
        DeploymentMode::SelfHosted => "self-hosted",
        DeploymentMode::Demo => "demo",
    }
    .to_string();
    let active_tenant = tenant.map(|Extension(tenant)| ActiveTenantResponse {
        id: tenant.tenant_id,
        slug: tenant.tenant_slug,
    });
    if auth.is_api_key {
        // For API keys, we don't have a real user - return API key info
        return Ok(Json(CurrentUserResponse {
            id: auth.claims.sub,
            email: format!(
                "apikey:{}",
                auth.api_key_id.map(|id| id.to_string()).unwrap_or_default()
            ),
            name: "API Key".to_string(),
            roles: auth.claims.roles.clone(),
            permissions: auth.claims.permissions.clone(),
            is_api_key: true,
            preferred_query_mode: None,
            landing_page: None,
            deployment_mode,
            active_tenant,
            demo,
        }));
    }

    // Fetch user info from database
    let user = state
        .user_repo
        .get_user_by_id(auth.claims.sub)
        .await
        .map_err(|_| {
            (
                StatusCode::NOT_FOUND,
                Json(AuthApiError::new("user_not_found", "User not found")),
            )
        })?;

    // Get user preferences
    let prefs = state.user_repo.get_preferences(auth.claims.sub).await.ok();

    let preferred_query_mode = prefs.as_ref().map(|p| p.preferred_query_mode.to_string());
    let landing_page = prefs.as_ref().map(|p| p.landing_page.to_string());

    Ok(Json(CurrentUserResponse {
        id: user.id,
        email: user.email,
        name: user.name,
        roles: auth.claims.roles.clone(),
        permissions: auth.claims.permissions.clone(),
        is_api_key: false,
        preferred_query_mode,
        landing_page,
        deployment_mode,
        active_tenant,
        demo,
    }))
}

/// Server-resolved identity for an owner-bound agent search key.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct AgentLaneIdentity {
    pub tenant_id: Uuid,
    pub key_id: Uuid,
    pub owner_id: Uuid,
    pub permissions: Vec<String>,
    pub restricted: bool,
    pub source: Option<String>,
    pub source_allowed: Option<bool>,
}

/// A decision for one requested source; never disclose the viewer's deny sets.
#[derive(Debug, Default, Deserialize, utoipa::IntoParams)]
pub struct AgentLaneValidationQuery {
    pub agent_tenant: Option<Uuid>,
    pub agent_source: Option<String>,
}

/// Token validation response.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct TokenValidationResponse {
    pub valid: bool,
    #[serde(with = "nanosiem_core::typeid::user")]
    #[schema(value_type = String)]
    pub user_id: Uuid,
    pub expires_at: i64,
    /// Present only for an owner-bound search API key in a trusted tenant.
    /// The gateway never accepts a client-supplied tenant or source scope.
    pub agent_lane: Option<AgentLaneIdentity>,
}

/// Validate token (for frontend to check if token is still valid)
///
/// GET /api/auth/validate
#[utoipa::path(
    get,
    path = "/api/auth/validate",
    tag = "auth",
    params(AgentLaneValidationQuery),
    responses(
        (status = 200, description = "Token is valid", body = TokenValidationResponse),
        (status = 401, description = "Token is invalid or expired", body = AuthApiError),
        (status = 403, description = "Requested agent tenant does not match the key", body = AuthApiError),
        (status = 400, description = "Invalid source decision request", body = AuthApiError),
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn validate_token(
    Extension(auth): Extension<AuthContext>,
    tenant: Option<Extension<TrustedTenantContext>>,
    axum::extract::Query(query): axum::extract::Query<AgentLaneValidationQuery>,
) -> Result<Json<TokenValidationResponse>, (StatusCode, Json<AuthApiError>)> {
    if query.agent_tenant.is_some_and(|expected| tenant.as_ref().is_none_or(|t| t.tenant_id != expected)) {
        return Err((StatusCode::FORBIDDEN, Json(AuthApiError::new("agent_tenant_denied", "The key does not authorize the requested tenant"))));
    }
    if query.agent_source.as_ref().is_some_and(|s| s.is_empty() || s.len() > 255
        || !s.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"_:-".contains(&b))) {
        return Err((StatusCode::BAD_REQUEST, Json(AuthApiError::new("invalid_agent_source", "Invalid source decision request"))));
    }
    let agent_lane = tenant.and_then(|Extension(tenant)| {
        if !auth.is_api_key || auth.user_id().is_nil() || tenant.tenant_id.is_nil()
            || !auth.has_permission("search:execute") {
            return None;
        }
        let scope = auth.effective_viewer_scope();
        Some(AgentLaneIdentity {
            tenant_id: tenant.tenant_id,
            key_id: auth.api_key_id?,
            owner_id: auth.user_id(),
            permissions: auth.claims.permissions.clone(),
            restricted: scope.is_restricted() || scope.is_artifact_restricted(),
            source_allowed: query.agent_source.as_ref().map(|source| !scope.deny_set().contains(source)),
            source: query.agent_source,
        })
    });
    Ok(Json(TokenValidationResponse {
        valid: true,
        user_id: auth.claims.sub,
        expires_at: auth.claims.exp,
        agent_lane,
    }))
}

/// Which authentication methods this deployment currently accepts.
///
/// Public by necessity: the login page has to know whether to offer a password
/// field before anyone has authenticated. The only thing disclosed is tenant
/// configuration the sign-in screen would reveal anyway — no account data, no
/// provider secrets, nothing per-user.
#[derive(Debug, Serialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct AuthMethodsResponse {
    /// Whether `POST /api/auth/login` accepts local email/password credentials.
    ///
    /// Always true in open-core builds: there is no SSO surface to fall back
    /// to, so there is nothing to switch off.
    pub local_password: bool,
}

/// Get the authentication methods available on this deployment.
///
/// GET /api/auth/methods
#[utoipa::path(
    get,
    path = "/api/auth/methods",
    tag = "auth",
    responses(
        (status = 200, description = "Available authentication methods", body = AuthMethodsResponse),
        (status = 500, description = "Internal server error", body = AuthApiError),
    ),
    security(())
)]
pub async fn get_auth_methods(
    State(state): State<AppState>,
) -> Result<Json<AuthMethodsResponse>, (StatusCode, Json<AuthApiError>)> {
    let local_password = state
        .local_auth_settings
        .is_local_password_enabled()
        .await
        .map_err(|e| {
            tracing::error!("failed to read local auth setting: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(AuthApiError {
                    error: "internal_error".to_string(),
                    message: "Failed to read authentication settings".to_string(),
                }),
            )
        })?;

    Ok(Json(AuthMethodsResponse { local_password }))
}

/// OpenAPI documentation for auth endpoints
#[derive(utoipa::OpenApi)]
#[openapi(
    paths(
        login,
        logout,
        refresh_token,
        request_password_reset,
        reset_password,
        change_password,
        get_current_user,
        validate_token,
        get_auth_methods
    ),
    components(schemas(
        AuthApiError,
        LogoutRequest,
        RefreshTokenResponse,
        PasswordResetResponse,
        PasswordResetCompleteResponse,
        ChangePasswordRequest,
        ChangePasswordResponse,
        CurrentUserResponse,
        ActiveTenantResponse,
        CurrentUserDemo,
        TokenValidationResponse,
        AgentLaneIdentity,
        AuthMethodsResponse
    ))
)]
pub struct AuthApiDoc;

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn agent_lane_identity_uses_trusted_tenant_and_canonical_viewer_scope() {
        let key = nanosiem_core::auth::ApiKeyInfo {
            id: Uuid::now_v7(), name: "desktop".into(),
            permissions: vec!["search:execute".into()], user_id: Some(Uuid::now_v7()),
        };
        let mut auth = AuthContext::from_api_key(&key);
        auth.denied_sources = nanosiem_core::auth::ScopeSet::from_denied(
            ["windows_sysmon".to_string()].into_iter().collect());
        let tenant = TrustedTenantContext { tenant_id: Uuid::now_v7(), tenant_slug: "tenant-a".into() };
        let query = || axum::extract::Query(AgentLaneValidationQuery { agent_tenant: Some(tenant.tenant_id), agent_source: Some("windows_sysmon".into()) });
        let Json(response) = validate_token(Extension(auth.clone()), Some(Extension(tenant.clone())), query()).await.unwrap();
        let identity = response.agent_lane.unwrap();
        assert_eq!(identity.tenant_id, tenant.tenant_id);
        assert_eq!(identity.key_id, key.id);
        assert_eq!(identity.owner_id, key.user_id.unwrap());
        assert!(identity.restricted);
        assert_eq!(identity.source.as_deref(), Some("windows_sysmon"));
        assert_eq!(identity.source_allowed, Some(false));
        let encoded = serde_json::to_value(&identity).unwrap();
        assert!(encoded.get("denied_sources").is_none());
        assert!(encoded.get("artifact_denied_sources").is_none());
        let public = || axum::extract::Query(AgentLaneValidationQuery::default());
        assert!(validate_token(Extension(auth.clone()), None, public()).await.unwrap().0.agent_lane.is_none());
        auth.is_api_key = false;
        assert!(validate_token(Extension(auth.clone()), Some(Extension(tenant.clone())), public()).await.unwrap().0.agent_lane.is_none());
        auth.is_api_key = true;
        auth.claims.permissions.clear();
        assert!(validate_token(Extension(auth), Some(Extension(tenant)), public()).await.unwrap().0.agent_lane.is_none());
    }

    /// NAN-3790: on the hosted shared host the plain `emit_audit` path can
    /// persist nothing (the shared emitter refuses tenantless rows), so every
    /// auth emission reachable there must use a tenant-aware writer.
    #[test]
    fn hosted_reachable_auth_audit_uses_tenant_aware_writers() {
        let auth = include_str!("auth.rs");
        let mfa = include_str!("mfa.rs");
        // Production code only: this test's own literals must not satisfy it.
        let compact = |source: &str| {
            source.split("#[cfg(test)]").next().unwrap_or_default().split_whitespace().collect::<String>()
        };
        let (auth, mfa) = (compact(auth), compact(mfa));
        for action in ["LOGIN_FAILED", "USER_LOCKED", "PASSWORD_RESET_REQUEST"] {
            assert!(auth.contains(&format!(
                "state.emit_preauth_audit(request.tenant_slug.as_deref(),AuditEvent::builder(AuditSource::Auth,{action})"
            )), "{action} must be scoped to the route slug's tenant");
        }
        assert!(auth.contains("state.emit_preauth_audit(None,AuditEvent::builder(AuditSource::Auth,PASSWORD_RESET_COMPLETE)"));
        assert!(auth.contains("Ok(user_id)=>{"), "a completed reset is audited for its account");
        assert!(auth.contains("state.emit_password_reset_complete_audit(*user_id,client_ctx.clone());"));
        assert!(auth.contains("Some(Extension(tenant))=>state.emit_tenant_auth_audit(tenant,auth.user_id(),vec![logout_event])"));
        assert!(auth.contains("state.emit_tenant_auth_audit(tenant,auth.user_id(),vec![password_event])"));
        assert!(mfa.contains("Some(tenant)=>state.emit_tenant_auth_audit(tenant,user.id,vec![setup_complete])"));
        assert!(mfa.contains("matchoutcome.tenant{Some(tenant)=>state.emit_tenant_auth_audit(tenant,actor_id,events)"));
    }

    #[cfg(feature = "enterprise")]
    #[test]
    fn enterprise_shared_logout_does_not_swallow_durable_revocation_failures() {
        let source = include_str!("auth.rs");
        assert!(source.contains("let terminate_result = if shared_logout"));
        assert!(
            source.contains("let persistence = nanosiem_core::auth::token::persist_revoked_token")
        );
        assert!(source.contains("shared_logout && (termination_failed || persistence_failed)"));
        assert!(source.contains("Shared-mode durable revocation could not be completed safely"));
        assert!(source.contains("fn logout_error_response"));
        assert!(source.contains("clear_refresh_token_cookie"));
    }

    #[cfg(feature = "enterprise")]
    #[test]
    fn enterprise_shared_logout_rejects_a_foreign_refresh_cookie_without_clearing_it() {
        let user_a = Uuid::now_v7();
        let user_b = Uuid::now_v7();
        let tenant_a = Uuid::now_v7();
        let tenant_b = Uuid::now_v7();
        assert!(shared_logout_identity_matches(user_a, tenant_a, user_a, tenant_a));
        assert!(!shared_logout_identity_matches(user_a, tenant_a, user_a, tenant_b));
        assert!(!shared_logout_identity_matches(user_a, tenant_a, user_b, tenant_a));

        let source = include_str!("auth.rs");
        assert!(source.contains("logout_error_response_without_cookie_clear"));
        assert!(source.contains("\"session_replaced\""));
        assert!(source.contains("if !shared_logout"));
    }

    #[test]
    fn normal_shared_logout_revokes_only_the_authenticated_tenant_namespace() {
        let source = include_str!("auth.rs");
        let branch = source.split("let terminate_result = if shared_logout {").nth(1).unwrap();
        let shared = branch.split("} else {").next().unwrap();
        assert!(shared.contains("tenant.as_ref()"));
        assert!(shared.contains("terminate_tenant_user_sessions("));
        assert!(!shared.contains("terminate_all_user_sessions("));
        assert!(branch.split("} else {").nth(1).unwrap().contains("terminate_all_user_sessions("));
    }

    /// NAN-2080: `change_password` is session-only. An owner-bound API key (whose
    /// `sub` maps to the owner) plus the owner's password must not be able to
    /// rotate the password — `require_session_auth` rejects it with 403 before
    /// any credential mutation.
    #[test]
    fn change_password_rejects_api_key_principals() {
        use nanosiem_core::auth::ApiKeyInfo;

        let api_key_ctx = AuthContext::from_api_key(&ApiKeyInfo {
            id: Uuid::now_v7(),
            name: "automation".to_string(),
            permissions: vec![],
            user_id: Some(Uuid::now_v7()),
        });

        let err = require_session_auth(&api_key_ctx)
            .map_err(|(s, j)| (s, Json(AuthApiError::new(&j.error, &j.message))))
            .expect_err("api-key principal must be rejected on change_password");
        assert_eq!(err.0, StatusCode::FORBIDDEN);
    }
}
