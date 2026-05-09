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
    http::{header::SET_COOKIE, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Extension, Json,
};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use uuid::Uuid;

use crate::utils::{extract_client_ip, extract_user_agent};
use nanosiem_core::audit::{
    AuditEvent, AuditSource, ClientContext, LOGIN_FAILED, LOGIN_SUCCESS, LOGOUT, PASSWORD_CHANGED,
    PASSWORD_RESET_COMPLETE, PASSWORD_RESET_REQUEST,
};
use nanosiem_core::auth::{
    AuthError, AuthResponse, LoginRequest, LoginResult, PasswordResetCompletion,
    PasswordResetRequest, RefreshTokenRequest,
};

use crate::handlers::AuditExt;
use crate::middleware::AuthContext;
use crate::state::AppState;

// The Set-Cookie helpers (`build_access_token_cookie`,
// `build_refresh_token_cookie`, the `clear_*` variants, and
// `extract_refresh_token_cookie`) were lifted to nanosiem-api-lib in NAN-751
// so that the OIDC handlers in nanosiem-enterprise can reuse them without
// creating a circular crate dependency. Re-exported here so existing
// `crate::handlers::auth::*` imports continue to resolve.
pub use nanosiem_api_lib::{
    build_access_token_cookie, build_refresh_token_cookie, clear_access_token_cookie,
    clear_refresh_token_cookie, extract_refresh_token_cookie,
};

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

            // Set access_token cookie for browser-based access (e.g. Swagger UI)
            let access_cookie = build_access_token_cookie(
                &response.tokens.access_token,
                response.tokens.expires_in,
            );
            // Set refresh_token HttpOnly cookie (scoped to /api/auth)
            let refresh_cookie = build_refresh_token_cookie(
                &response.tokens.refresh_token,
                state.token_service.refresh_token_ttl(),
            );
            let mut res = Json(&response).into_response();
            res.headers_mut().append(
                SET_COOKIE,
                access_cookie.parse().expect("valid cookie header"),
            );
            res.headers_mut().append(
                SET_COOKIE,
                refresh_cookie.parse().expect("valid cookie header"),
            );
            Ok(res)
        }
        Ok(LoginResult::MfaRequired { challenge_token }) => {
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
            Ok(Json(serde_json::json!({
                "status": "mfa_setup_required",
                "mfa_setup_required": true,
                "challenge_token": challenge_token,
            }))
            .into_response())
        }
        Err(e) => {
            // Emit login failed audit event
            state.emit_audit(
                AuditEvent::builder(AuditSource::Auth, LOGIN_FAILED)
                    .actor(None, Some(request.email.clone()))
                    .resource("user", None, Some(request.email.clone()))
                    .client_context(&client_ctx)
                    .success(false)
                    .details(serde_json::json!({
                        "error": e.to_string()
                    }))
                    .build(),
            );
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
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn logout(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Extension(auth): Extension<AuthContext>,
    Json(request): Json<LogoutRequest>,
) -> Result<Response, (StatusCode, Json<AuthApiError>)> {
    let ip_address = extract_client_ip(&headers, Some(&addr));
    let user_agent = extract_user_agent(&headers);
    let client_ctx = ClientContext::new(ip_address.clone(), user_agent.clone());

    // C4: Always revoke ALL sessions for the authenticated user on logout.
    // Previously only the session matching the provided refresh token was deleted,
    // leaving other refresh tokens alive for up to 7 days.
    let _ = state
        .session_service
        .terminate_all_user_sessions(
            auth.user_id(),
            auth.user_id(),
            true, // user is terminating their own sessions
            ip_address.as_deref(),
            user_agent.as_deref(),
        )
        .await;

    // Also try single-session logout via refresh token for audit trail
    let refresh_token = request
        .refresh_token
        .or_else(|| extract_refresh_token_cookie(&headers));
    if let Some(ref token) = refresh_token {
        let _ = state
            .auth_service
            .logout(token, ip_address.as_deref(), user_agent.as_deref())
            .await;
    }

    // Revoke the current access token so it cannot be reused before expiry
    state
        .token_service
        .revoke_token(auth.claims.jti, auth.claims.exp)
        .await;
    // H8: Persist revocation to PostgreSQL so it survives restarts
    nanosiem_core::auth::token::persist_revoked_token(
        &state.pool,
        auth.claims.jti,
        auth.claims.exp,
    )
    .await;

    // Emit logout audit event
    state.emit_audit(
        AuditEvent::builder(AuditSource::Auth, LOGOUT)
            .actor(Some(auth.user_id()), None)
            .resource("session", None, None)
            .client_context(&client_ctx)
            .build(),
    );

    // Clear both cookies
    let mut res = StatusCode::NO_CONTENT.into_response();
    res.headers_mut().append(
        SET_COOKIE,
        clear_access_token_cookie()
            .parse()
            .expect("valid cookie header"),
    );
    res.headers_mut().append(
        SET_COOKIE,
        clear_refresh_token_cookie()
            .parse()
            .expect("valid cookie header"),
    );
    Ok(res)
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

    // Resolve refresh token from body or cookie
    let refresh_token_value = request
        .refresh_token
        .or_else(|| extract_refresh_token_cookie(&headers))
        .ok_or_else(|| {
            (
                StatusCode::BAD_REQUEST,
                Json(AuthApiError::new(
                    "missing_token",
                    "Refresh token required (in body or cookie)",
                )),
            )
        })?;

    let token_pair = match state
        .auth_service
        .refresh_token(
            &refresh_token_value,
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
            res.headers_mut().append(
                SET_COOKIE,
                clear_access_token_cookie()
                    .parse()
                    .expect("valid cookie header"),
            );
            res.headers_mut().append(
                SET_COOKIE,
                clear_refresh_token_cookie()
                    .parse()
                    .expect("valid cookie header"),
            );
            return Ok(res);
        }
    };

    let response = RefreshTokenResponse {
        access_token: token_pair.access_token,
        refresh_token: token_pair.refresh_token,
        token_type: token_pair.token_type,
        expires_in: token_pair.expires_in,
    };

    // Set updated cookies (append pattern for multiple Set-Cookie headers)
    let access_cookie = build_access_token_cookie(&response.access_token, response.expires_in);
    let refresh_cookie = build_refresh_token_cookie(
        &response.refresh_token,
        state.token_service.refresh_token_ttl(),
    );
    let mut res = Json(&response).into_response();
    res.headers_mut().append(
        SET_COOKIE,
        access_cookie.parse().expect("valid cookie header"),
    );
    res.headers_mut().append(
        SET_COOKIE,
        refresh_cookie.parse().expect("valid cookie header"),
    );
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
        .request_password_reset(&request.email, ip_address.as_deref(), user_agent.as_deref())
        .await;

    // Emit audit event regardless of success (but don't reveal if email exists)
    state.emit_audit(
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
        Ok(_) => {
            // Emit password reset complete audit event
            state.emit_audit(
                AuditEvent::builder(AuditSource::Auth, PASSWORD_RESET_COMPLETE)
                    .resource("user", None, None)
                    .client_context(&client_ctx)
                    .build(),
            );
        }
        Err(e) => {
            // Emit failed password reset audit event
            state.emit_audit(
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
        (status = 400, description = "New password does not meet requirements", body = AuthApiError),
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn change_password(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Extension(auth): Extension<AuthContext>,
    Json(request): Json<ChangePasswordRequest>,
) -> Result<Response, (StatusCode, Json<AuthApiError>)> {
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

    match &result {
        Ok(_) => {
            state.emit_audit(
                AuditEvent::builder(AuditSource::Auth, PASSWORD_CHANGED)
                    .actor(Some(auth.user_id()), None)
                    .resource("user", Some(auth.user_id()), None)
                    .client_context(&client_ctx)
                    .build(),
            );
        }
        Err(e) => {
            state.emit_audit(
                AuditEvent::builder(AuditSource::Auth, PASSWORD_CHANGED)
                    .actor(Some(auth.user_id()), None)
                    .resource("user", Some(auth.user_id()), None)
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

    // Clear cookies since all sessions are invalidated
    let mut res = Json(ChangePasswordResponse {
        message: "Password changed successfully. Please log in again.".to_string(),
    })
    .into_response();
    res.headers_mut().append(
        SET_COOKIE,
        clear_access_token_cookie()
            .parse()
            .expect("valid cookie header"),
    );
    res.headers_mut().append(
        SET_COOKIE,
        clear_refresh_token_cookie()
            .parse()
            .expect("valid cookie header"),
    );
    Ok(res)
}

/// Current user response
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
) -> Result<Json<CurrentUserResponse>, (StatusCode, Json<AuthApiError>)> {
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
    }))
}

/// Token validation response
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct TokenValidationResponse {
    pub valid: bool,
    #[serde(with = "nanosiem_core::typeid::user")]
    #[schema(value_type = String)]
    pub user_id: Uuid,
    pub expires_at: i64,
}

/// Validate token (for frontend to check if token is still valid)
///
/// GET /api/auth/validate
#[utoipa::path(
    get,
    path = "/api/auth/validate",
    tag = "auth",
    responses(
        (status = 200, description = "Token is valid", body = TokenValidationResponse),
        (status = 401, description = "Token is invalid or expired", body = AuthApiError),
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn validate_token(
    Extension(auth): Extension<AuthContext>,
) -> Json<TokenValidationResponse> {
    Json(TokenValidationResponse {
        valid: true,
        user_id: auth.claims.sub,
        expires_at: auth.claims.exp,
    })
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
        validate_token
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
        TokenValidationResponse
    ))
)]
pub struct AuthApiDoc;
