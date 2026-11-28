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
    AuditEvent, AuditSource, ClientContext, LOGIN_FAILED, LOGIN_SUCCESS, LOGOUT,
    MFA_CHALLENGE_ISSUED, PASSWORD_CHANGED, PASSWORD_RESET_COMPLETE, PASSWORD_RESET_REQUEST,
    LOGIN_ACCOUNT_THROTTLED, TOKEN_REFRESH, USER_LOCKED,
};
use nanosiem_core::auth::{
    AuthError, AuthResponse, CurrentSessionLogout, LoginRequest, LoginResult, PasswordResetCompletion,
    PasswordResetRequest, RefreshTokenRequest,
};

use crate::handlers::AuditExt;
use crate::middleware::{require_session_auth, AuthContext};
use crate::state::AppState;

// The Set-Cookie helpers (`build_access_token_cookie`, the paired
// `append_refresh_token_cookies` / `append_clear_refresh_token_cookies`
// (refresh cookie + `nano_session` presence cookie, NAN-5483), and
// `extract_refresh_token_cookie`) were lifted to nanosiem-api-lib in NAN-751
// so that the OIDC handlers in nanosiem-enterprise can reuse them without
// creating a circular crate dependency. Re-exported here so existing
// `crate::handlers::auth::*` imports continue to resolve.
pub use nanosiem_api_lib::{
    append_clear_refresh_token_cookies, append_refresh_token_cookies, build_access_token_cookie,
    clear_access_token_cookie, extract_refresh_token_cookie,
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
            | AuthError::LoginThrottled { .. }
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
            // NAN-5973: detected reuse answers exactly like an unknown
            // session; the revocation is recorded in the audit row only.
            AuthError::SessionNotFound | AuthError::RefreshTokenReused { .. } => (
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
            state.emit_audit_durable(
                AuditEvent::builder(AuditSource::Auth, LOGIN_SUCCESS)
                    .actor(Some(response.user.id), Some(response.user.email.clone()))
                    .resource(
                        "user",
                        Some(response.user.id),
                        Some(response.user.email.clone()),
                    )
                    .client_context(&client_ctx)
                    .build(),
            ).await;

            // Set access_token cookie for browser-based access (e.g. Swagger UI)
            let access_cookie = build_access_token_cookie(
                &response.tokens.access_token,
                response.tokens.expires_in,
            );
            let mut res = Json(&response).into_response();
            res.headers_mut().append(
                SET_COOKIE,
                access_cookie.parse().expect("valid cookie header"),
            );
            // Set refresh_token HttpOnly cookie (scoped to /api/auth) plus
            // its JS-readable presence cookie (NAN-5483)
            append_refresh_token_cookies(
                res.headers_mut(),
                &response.tokens.refresh_token,
                state.token_service.refresh_token_ttl(),
            );
            Ok(res)
        }
        Ok(LoginResult::MfaRequired { challenge_token }) => {
            // Password verified; MFA code now required. Audit the challenge
            // issuance (the actor is recovered from the freshly minted challenge
            // token). Completion/failure is audited by verify_mfa_challenge.
            let actor_id = state
                .token_service
                .validate_mfa_challenge_token(&challenge_token)
                .ok()
                .map(|c| c.sub);
            state.emit_audit(
                AuditEvent::builder(AuditSource::Auth, MFA_CHALLENGE_ISSUED)
                    .actor(actor_id, Some(request.email.clone()))
                    .resource("user", actor_id, Some(request.email.clone()))
                    .client_context(&client_ctx)
                    .build(),
            );
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
            // NAN-5149: the auth service reports a throttle threshold crossing
            // once, on the failed attempt that crossed it, so each is audited
            // exactly once per episode: `user_locked` when this (email, source
            // address) pair was locked, `login_account_throttled` when the
            // failures for this email across every address reached the alert
            // threshold. Both are keyed on the email string (no user id), and
            // the client still gets the generic 401 from from_auth_error.
            if let AuthError::LoginThrottled {
                ip_locked,
                account_alert,
            } = e
            {
                if ip_locked {
                    state.emit_audit_durable(
                        AuditEvent::builder(AuditSource::Auth, USER_LOCKED)
                            .actor(None, Some(request.email.clone()))
                            .resource("user", None, Some(request.email.clone()))
                            .client_context(&client_ctx)
                            .success(false)
                            .details(serde_json::json!({
                                "reason": "failed_login_threshold_exceeded",
                                "scope": "source_address",
                            }))
                            .build(),
                    ).await;
                }
                if account_alert {
                    state.emit_audit_durable(
                        AuditEvent::builder(AuditSource::Auth, LOGIN_ACCOUNT_THROTTLED)
                            .actor(None, Some(request.email.clone()))
                            .resource("user", None, Some(request.email.clone()))
                            .client_context(&client_ctx)
                            .success(false)
                            .details(serde_json::json!({
                                "reason": "account_failure_alert_threshold",
                            }))
                            .build(),
                    ).await;
                }
            }
            let (status, err) = AuthApiError::from_auth_error(&e);
            Err((status, Json(err)))
        }
    }
}

/// Logout request body
#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct LogoutRequest {
    /// Refresh token of the session to end. Only consulted when the access
    /// token predates session binding (no `sid` claim); the `refresh_token`
    /// cookie is used when this is omitted.
    pub refresh_token: Option<String>,
}

/// Log out of the current session
///
/// Ends only the session the caller's access token belongs to and revokes
/// that access token. The user's other sessions (other browsers, devices,
/// CLI logins) stay signed in. To sign out everywhere, use
/// `DELETE /api/sessions/user/{user_id}` with your own user id.
///
/// Access tokens issued before session binding (no `sid` claim) are matched
/// to their session by the refresh token (body, else the `refresh_token`
/// cookie), including a refresh token that was already rotated once. If none
/// identifies a live session the request is rejected with 400 and nothing is
/// changed. Such a token stops working when it expires (the access-token
/// TTL, 15 minutes by default); refreshing yields a session-bound token that
/// logs out normally.
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
        (status = 204, description = "Logout successful: the current session is ended; other sessions are unaffected"),
        (status = 400, description = "session_not_identified: the access token predates session binding and no refresh token identified its session; nothing was changed. Retry with refresh_token.", body = AuthApiError),
        (status = 401, description = "Invalid token", body = AuthApiError),
        (status = 403, description = "Forbidden — interactive session required (API keys have no session)", body = AuthApiError),
        (status = 503, description = "session_end_failed: the session could not be ended (the access token is revoked; refresh and retry). revocation_unavailable (HA only): the revocation could not be persisted to PostgreSQL; retry", body = AuthApiError),
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
    // NAN-2040: an API key has no interactive browser session to end. Its subject
    // is its owner, so without this a (possibly zero-permission) key could end
    // the owner's browser sessions (the alternate route past the
    // session-handler guards). API keys are revoked by deleting the key, not by
    // logout.
    if auth.is_api_key {
        return Err((
            StatusCode::FORBIDDEN,
            Json(AuthApiError::new(
                "interactive_session_required",
                "Logout requires an interactive session; API keys have no session to end.",
            )),
        ));
    }

    let ip_address = extract_client_ip(&headers, Some(&addr));
    let user_agent = extract_user_agent(&headers);
    let client_ctx = ClientContext::new(ip_address.clone(), user_agent.clone());

    // NAN-5573: end the CURRENT session only. The access token's `sid` names
    // it; a token minted before `sid` existed falls back to the refresh token
    // (body, else cookie). This used to delete every session the user had
    // (C4 / NAN-167), which signed them out of every other browser and device.
    // The C4 concern, a logout that leaves THIS session's refresh token alive,
    // is covered because `sid` identifies the session without needing the
    // refresh token. Signing out everywhere is the explicit
    // `DELETE /api/sessions/user/{user_id}`.
    let refresh_token = request
        .refresh_token
        .or_else(|| extract_refresh_token_cookie(&headers));
    let session = state
        .auth_service
        .logout_current_session(auth.user_id(), auth.claims.sid, refresh_token.as_deref())
        .await;
    let audit_logout = |success: bool, details: serde_json::Value| {
        state.emit_audit(
            AuditEvent::builder(AuditSource::Auth, LOGOUT)
                .actor(Some(auth.user_id()), None)
                .resource(
                    "session",
                    session.as_ref().ok().and_then(|s| s.session_id()).or(auth.claims.sid),
                    None,
                )
                .client_context(&client_ctx)
                .success(success)
                .details(details)
                .build(),
        );
    };

    // A pre-`sid` token whose session nothing identifies: refuse before any
    // side effect so the client can retry with its refresh token, instead
    // of a 204 that leaves a renewable session alive.
    if let Some(rejection) = logout_rejection(&session) {
        audit_logout(
            false,
            serde_json::json!({ "scope": "current_session", "reason": rejection.1.error.clone() }),
        );
        return Err((rejection.0, Json(rejection.1)));
    }
    let session_end_failed = match &session {
        Ok(_) => false,
        Err(error) => {
            tracing::error!(user_id = %auth.user_id(), %error, "logout: failed to end the current session");
            true
        }
    };
    // H8 / NAN-5243: persist the revocation to PostgreSQL first. It is the
    // durable record (synchronously replicated in HA) that every API/search
    // process re-reads (spawn_revocation_sync), so a revocation the shared
    // Valkey later loses is still enforced.
    let persisted = nanosiem_core::auth::token::persist_revoked_token(
        &state.pool,
        auth.claims.jti,
        auth.claims.exp,
    )
    .await;
    // Revoke the current access token so it cannot be reused before expiry.
    // A Valkey replica not confirming it is logged, not fatal: HA must
    // survive one host down (a two-member Valkey set then has no replica).
    if let Err(error) = state
        .token_service
        .revoke_token_durable(auth.claims.jti, auth.claims.exp)
        .await
    {
        tracing::warn!(jti = %auth.claims.jti, %error, "logout revocation not confirmed on a Valkey replica; PostgreSQL holds it");
    }
    if let Some((status, error)) = logout_failure(
        session_end_failed,
        persisted.is_ok(),
        state.token_service.revocation_fail_closed(),
    ) {
        // The access token is revoked either way. Cookies are kept so the
        // client can refresh and retry while the session row survives.
        audit_logout(
            false,
            serde_json::json!({ "scope": "current_session", "reason": error.error.clone() }),
        );
        return Err((status, Json(error)));
    }

    // Emit logout audit event, scoped to the one session that was ended.
    audit_logout(
        true,
        serde_json::json!({
            "scope": "current_session",
            "session_ended": matches!(session, Ok(CurrentSessionLogout::Ended(_))),
        }),
    );

    // Clear both cookies
    let mut res = StatusCode::NO_CONTENT.into_response();
    res.headers_mut().append(
        SET_COOKIE,
        clear_access_token_cookie()
            .parse()
            .expect("valid cookie header"),
    );
    append_clear_refresh_token_cookies(res.headers_mut());
    Ok(res)
}

/// NAN-5573: refuse a logout that cannot name the session to end (a token
/// minted before `sid`, with no refresh token matching a live session).
/// Checked before any side effect so the same access token can retry.
pub(crate) fn logout_rejection(
    session: &Result<CurrentSessionLogout, AuthError>,
) -> Option<(StatusCode, AuthApiError)> {
    matches!(session, Ok(CurrentSessionLogout::NotIdentified)).then(|| {
        (
            StatusCode::BAD_REQUEST,
            AuthApiError::new(
                "session_not_identified",
                "This access token predates session binding and no refresh token identified its \
                 session. Retry with refresh_token; nothing was changed.",
            ),
        )
    })
}

/// NAN-5573 review: never report a logout that may have left a live session
/// or a non-durable revocation. A failed session delete is always a 503
/// (the session's refresh token would otherwise stay usable for its full
/// TTL); a non-durable revocation is a 503 only in HA fail-closed mode.
pub(crate) fn logout_failure(
    session_end_failed: bool,
    revocation_persisted: bool,
    revocation_fail_closed: bool,
) -> Option<(StatusCode, AuthApiError)> {
    if session_end_failed {
        return Some((
            StatusCode::SERVICE_UNAVAILABLE,
            AuthApiError::new(
                "session_end_failed",
                "Your session could not be ended. Refresh and retry logout.",
            ),
        ));
    }
    if revocation_fail_closed && !revocation_persisted {
        return Some((
            StatusCode::SERVICE_UNAVAILABLE,
            AuthApiError::new("revocation_unavailable", "Logout could not be confirmed; retry."),
        ));
    }
    None
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

    // NAN-3460: attribute the refresh to the session owner. Only a
    // signature-valid, unexpired refresh JWT names a user; a forged or expired
    // token is audited without an actor rather than trusting its payload.
    let refresh_owner = state
        .token_service
        .validate_refresh_token(&refresh_token_value)
        .ok()
        .map(|claims| claims.sub);
    let client_ctx = ClientContext::new(ip_address.clone(), user_agent.clone());

    // NAN-5973: run the refresh and its audit row on a spawned task. If the
    // client disconnects (a page navigation aborts the request), axum drops
    // this handler future; the rotation and the audit still run to
    // completion instead of stopping between statements. A rotation whose
    // response never reached the client is recovered by the reuse interval
    // (the previous token gets the current one back).
    let task_state = state.clone();
    let outcome = tokio::spawn(async move {
        let result = task_state
            .auth_service
            .refresh_token(
                &refresh_token_value,
                ip_address.as_deref(),
                user_agent.as_deref(),
            )
            .await;
        match &result {
            Ok(outcome) => task_state.emit_audit(refresh_audit_event(
                refresh_owner,
                &client_ctx,
                Some(outcome.session_id),
                None,
                outcome.is_grace(),
            )),
            Err(e) => task_state.emit_audit(refresh_audit_event(
                refresh_owner,
                &client_ctx,
                None,
                Some(e),
                false,
            )),
        }
        result
    })
    .await
    .unwrap_or_else(|e| Err(AuthError::InternalError(format!("refresh task failed: {e}"))));

    let outcome = match outcome {
        Ok(outcome) => outcome,
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
            append_clear_refresh_token_cookies(res.headers_mut());
            return Ok(res);
        }
    };

    let sets_refresh_token = outcome.sets_refresh_token();
    let token_pair = outcome.tokens;
    let response = RefreshTokenResponse {
        access_token: token_pair.access_token,
        refresh_token: token_pair.refresh_token,
        token_type: token_pair.token_type,
        expires_in: token_pair.expires_in,
    };

    // Set updated cookies (append pattern for multiple Set-Cookie headers).
    // NAN-5973: a reuse-interval refresh returns the session's CURRENT
    // refresh token, so the cookie is (re)set to it and a client that missed
    // the rotation catches up. Only the access-only grace fallback (no token
    // to hand back) leaves the refresh cookie untouched.
    let access_cookie = build_access_token_cookie(&response.access_token, response.expires_in);
    let mut res = Json(&response).into_response();
    res.headers_mut().append(
        SET_COOKIE,
        access_cookie.parse().expect("valid cookie header"),
    );
    if sets_refresh_token {
        append_refresh_token_cookies(
            res.headers_mut(),
            &response.refresh_token,
            state.token_service.refresh_token_ttl(),
        );
    }
    Ok(res)
}

/// Audit row for one `POST /api/auth/refresh` (NAN-3460).
///
/// A refresh mints a new access token and rotates the single-use refresh
/// token, so it is a session event a SOC needs: the row names the session
/// owner and the client of THIS request (trusted-proxy-aware IP and user
/// agent), never the session's creation metadata. A failed refresh is
/// recorded too: after rotation, a second presentation of the same refresh
/// token is either a lost multi-tab race or token replay from another client,
/// and only the client address separates the two.
///
/// NAN-5973: the row names the session (token family). Detected reuse, which
/// revokes the whole session, is its own reason (`refresh_token_reuse`) with
/// `family_revoked: true`.
pub(crate) fn refresh_audit_event(
    user_id: Option<Uuid>,
    client_ctx: &ClientContext,
    session_id: Option<Uuid>,
    failure: Option<&AuthError>,
    grace: bool,
) -> AuditEvent {
    let session_id = session_id.or(match failure {
        Some(AuthError::RefreshTokenReused { session_id }) => Some(*session_id),
        _ => None,
    });
    let mut builder = AuditEvent::builder(AuditSource::Auth, TOKEN_REFRESH)
        .actor(user_id, None)
        .resource("session", session_id, None)
        .client_context(client_ctx)
        .success(failure.is_none());
    if let Some(err) = failure {
        let details = match err {
            AuthError::RefreshTokenReused { .. } => serde_json::json!({
                "reason": "refresh_token_reuse",
                "family_revoked": true,
            }),
            AuthError::SessionNotFound | AuthError::InvalidToken => {
                serde_json::json!({ "reason": "refresh_token_rejected" })
            }
            AuthError::AccountDisabled | AuthError::AccountLocked | AuthError::UserNotFound => {
                serde_json::json!({ "reason": "account_unavailable" })
            }
            _ => serde_json::json!({ "reason": "refresh_failed" }),
        };
        builder = builder.details(details);
    } else if grace {
        // NAN-2453 / NAN-5973: served from the previous-token reuse interval
        // (a concurrent tab rotated first, or the rotation response was
        // lost). Recorded so replay of a just-rotated token from a different
        // client stays visible.
        builder = builder.details(serde_json::json!({ "grace": true }));
    }
    builder.build()
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
            state.emit_audit_durable(
                AuditEvent::builder(AuditSource::Auth, PASSWORD_RESET_COMPLETE)
                    .resource("user", None, None)
                    .client_context(&client_ctx)
                    .build(),
            ).await;
        }
        Err(e) => {
            // Emit failed password reset audit event
            state.emit_audit_durable(
                AuditEvent::builder(AuditSource::Auth, PASSWORD_RESET_COMPLETE)
                    .resource("user", None, None)
                    .client_context(&client_ctx)
                    .success(false)
                    .details(serde_json::json!({
                        "error": e.to_string()
                    }))
                    .build(),
            ).await;
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
pub async fn change_password(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Extension(auth): Extension<AuthContext>,
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

    match &result {
        Ok(_) => {
            state.emit_audit_durable(
                AuditEvent::builder(AuditSource::Auth, PASSWORD_CHANGED)
                    .actor(Some(auth.user_id()), None)
                    .resource("user", Some(auth.user_id()), None)
                    .client_context(&client_ctx)
                    .build(),
            ).await;
        }
        Err(e) => {
            state.emit_audit_durable(
                AuditEvent::builder(AuditSource::Auth, PASSWORD_CHANGED)
                    .actor(Some(auth.user_id()), None)
                    .resource("user", Some(auth.user_id()), None)
                    .client_context(&client_ctx)
                    .success(false)
                    .details(serde_json::json!({
                        "error": e.to_string()
                    }))
                    .build(),
            ).await;
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
    append_clear_refresh_token_cookies(res.headers_mut());
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
    /// NAN-5328: true when the caller's data scope hides some sources from
    /// live data (per-source RBAC, or the `audit` source without
    /// `audit:view`). Lets an empty search say rows may be hidden by scope.
    /// Only a boolean: the denied source names are not disclosed.
    pub data_scope_restricted: bool,
}

/// NAN-5328: whether the caller's effective live-data scope denies any source.
pub(crate) fn data_scope_restricted(auth: &AuthContext) -> bool {
    auth.effective_viewer_scope().is_restricted()
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
            data_scope_restricted: data_scope_restricted(&auth),
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
        data_scope_restricted: data_scope_restricted(&auth),
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
        TokenValidationResponse,
        AuthMethodsResponse
    ))
)]
pub struct AuthApiDoc;

#[cfg(test)]
#[path = "auth_refresh_audit_tests.rs"]
mod refresh_audit_tests;

// NAN-5573: logout fails closed on an unidentified or un-ended session.
#[cfg(test)]
#[path = "auth_logout_tests.rs"]
mod logout_tests;

// NAN-5328: `/api/auth/me` data-scope flag.
#[cfg(test)]
#[path = "auth_me_scope_tests.rs"]
mod me_scope_tests;

#[cfg(test)]
mod tests {
    use super::*;

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
