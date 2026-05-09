// SPDX-License-Identifier: AGPL-3.0-or-later

//! MFA (Multi-Factor Authentication) API handlers
//!
//! Provides TOTP enrollment, verification, and management endpoints.
//! Supports user-optional MFA and admin-enforced MFA for all local users.

use axum::{
    extract::{ConnectInfo, Path, State},
    http::{header::SET_COOKIE, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Extension, Json,
};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use uuid::Uuid;

use crate::handlers::auth::{build_access_token_cookie, build_refresh_token_cookie};
use crate::handlers::AuditExt;
use crate::middleware::AuthContext;
use crate::state::AppState;
use crate::utils::{extract_client_ip, extract_user_agent};
use nanosiem_core::audit::{AuditEvent, AuditSource, ClientContext};
use nanosiem_core::auth::repository::audit_actions;
use nanosiem_core::auth::{
    mfa, MfaChallengeRequest, MfaDisableRequest, MfaRegenerateBackupCodesRequest,
    MfaSetupCompleteResponse, MfaSetupRequest, MfaSetupResponse, MfaStatusResponse,
    MfaVerifySetupRequest,
};
use nanosiem_core::typeid::TypeIdParam;

/// Error response for MFA endpoints
#[derive(Debug, Serialize, Deserialize, utoipa::ToSchema)]
pub struct MfaApiError {
    pub error: String,
    pub message: String,
}

/// Pull a Bearer token from the `Authorization` header, if present + valid.
fn bearer_from_headers(headers: &HeaderMap) -> Option<String> {
    headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .map(|t| t.to_string())
}

/// Pull the access_token cookie value, if present.
fn access_token_cookie(headers: &HeaderMap) -> Option<String> {
    headers
        .get(axum::http::header::COOKIE)
        .and_then(|v| v.to_str().ok())
        .and_then(|cookies| {
            cookies
                .split(';')
                .map(|s| s.trim())
                .find(|s| s.starts_with("access_token="))
                .map(|s| s["access_token=".len()..].to_string())
        })
}

/// Resolved actor for a setup-flow request. When the request authenticated
/// via challenge_token, `challenge_jti` carries the JTI + exp so the
/// caller can revoke it on a successful operation (single-use semantics).
/// Voluntary Bearer-auth callers don't get a JTI — Bearer tokens have
/// their own lifecycle.
struct SetupActor {
    user_id: Uuid,
    challenge_jti: Option<(Uuid, i64)>,
}

/// Resolve the user_id for a setup-flow request. Accepts either a Bearer
/// session (voluntary enrolment from User Settings) or an `mfa_challenge`
/// token in the body (forced enrolment, where the caller has no session
/// yet — only the 5-minute challenge token from the prior login response).
///
/// Returns a single `unauthorized` error for both "no auth" and "invalid
/// challenge" cases — distinguishing them client-side is a token-validity
/// oracle for probers. The exact reason is logged server-side via tracing.
async fn resolve_setup_actor(
    state: &AppState,
    headers: &HeaderMap,
    challenge_token: Option<&str>,
) -> Result<SetupActor, (StatusCode, Json<MfaApiError>)> {
    // Prefer Bearer / cookie session — keeps the voluntary path identical.
    if let Some(token) = bearer_from_headers(headers).or_else(|| access_token_cookie(headers)) {
        if let Ok(claims) = state
            .token_service
            .validate_access_token_async(&token)
            .await
        {
            return Ok(SetupActor {
                user_id: claims.sub,
                challenge_jti: None,
            });
        }
    }
    // Fall back to a challenge_token explicitly passed in the body.
    if let Some(token) = challenge_token.filter(|s| !s.is_empty()) {
        match state.token_service.validate_mfa_challenge_token(token) {
            Ok(claims) => {
                return Ok(SetupActor {
                    user_id: claims.sub,
                    challenge_jti: Some((claims.jti, claims.exp)),
                });
            }
            Err(e) => {
                tracing::debug!(error = %e, "MFA setup: challenge_token rejected");
            }
        }
    }
    Err((
        StatusCode::UNAUTHORIZED,
        Json(MfaApiError {
            error: "unauthorized".into(),
            message: "Authentication required".into(),
        }),
    ))
}

// === Setup Endpoints ===

/// Initiate MFA setup — generate TOTP secret and QR code
///
/// POST /api/auth/mfa/setup
#[utoipa::path(
    post,
    path = "/api/auth/mfa/setup",
    tag = "mfa",
    request_body = MfaSetupRequest,
    responses(
        (status = 200, description = "MFA setup initiated", body = MfaSetupResponse),
        (status = 400, description = "MFA already enabled or OIDC user", body = MfaApiError),
        (status = 401, description = "Authentication required", body = MfaApiError),
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn setup_mfa(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: Option<Json<MfaSetupRequest>>,
) -> Result<Json<MfaSetupResponse>, (StatusCode, Json<MfaApiError>)> {
    // Body is optional — voluntary enrolment from User Settings POSTs an
    // empty body and authenticates via Bearer; forced enrolment passes the
    // mfa_challenge token in the body because there's no session yet.
    let challenge_token = body.as_ref().and_then(|b| b.0.challenge_token.as_deref());
    let actor = resolve_setup_actor(&state, &headers, challenge_token).await?;
    let ip_address = extract_client_ip(&headers, Some(&addr));
    let user_agent = extract_user_agent(&headers);
    let client_ctx = ClientContext::new(ip_address, user_agent);
    let user = state.user_repo.get_user_by_id(actor.user_id).await.map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(MfaApiError {
                error: "internal_error".into(),
                message: "Failed to fetch user".into(),
            }),
        )
    })?;

    // Reject OIDC-only users
    if user.oidc_provider_id.is_some() && user.password_hash.is_none() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(MfaApiError {
                error: "oidc_user".into(),
                message:
                    "OIDC users cannot configure MFA — it is managed by your identity provider"
                        .into(),
            }),
        ));
    }

    // Reject if already enabled
    if user.mfa_enabled {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(MfaApiError {
                error: "already_enabled".into(),
                message: "MFA is already enabled for this account".into(),
            }),
        ));
    }

    // Generate TOTP secret
    let (totp, secret_base32) = mfa::generate_totp_secret(&user.email).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(MfaApiError {
                error: "totp_error".into(),
                message: e.to_string(),
            }),
        )
    })?;

    let qr_code_base64 = mfa::generate_qr_code(&totp).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(MfaApiError {
                error: "qr_error".into(),
                message: e.to_string(),
            }),
        )
    })?;

    let otpauth_uri = totp.get_url();

    // Encrypt and store the secret (pending, not yet active)
    let encrypted =
        mfa::encrypt_secret(&secret_base32, &state.encryption_service).map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(MfaApiError {
                    error: "encryption_error".into(),
                    message: e.to_string(),
                }),
            )
        })?;

    let ciphertext = base64::Engine::decode(
        &base64::engine::general_purpose::STANDARD,
        &encrypted.ciphertext,
    )
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(MfaApiError {
                error: "encoding_error".into(),
                message: e.to_string(),
            }),
        )
    })?;

    state
        .user_repo
        .store_pending_totp_secret(user.id, &ciphertext, &encrypted.nonce)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(MfaApiError {
                    error: "db_error".into(),
                    message: e.to_string(),
                }),
            )
        })?;

    state.emit_audit(
        AuditEvent::builder(AuditSource::Auth, audit_actions::MFA_SETUP_INITIATED)
            .actor(Some(user.id), Some(user.email.clone()))
            .resource("user", Some(user.id), Some(user.email))
            .client_context(&client_ctx)
            .build(),
    );

    Ok(Json(MfaSetupResponse {
        secret: secret_base32,
        otpauth_uri,
        qr_code_base64,
    }))
}

/// Verify MFA setup with first TOTP code — activates MFA and returns backup codes
///
/// POST /api/auth/mfa/verify-setup
#[utoipa::path(
    post,
    path = "/api/auth/mfa/verify-setup",
    tag = "mfa",
    request_body = MfaVerifySetupRequest,
    responses(
        (status = 200, description = "MFA activated, backup codes returned", body = MfaSetupCompleteResponse),
        (status = 400, description = "Invalid code or no pending setup", body = MfaApiError),
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn verify_mfa_setup(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(request): Json<MfaVerifySetupRequest>,
) -> Result<Json<MfaSetupCompleteResponse>, (StatusCode, Json<MfaApiError>)> {
    // Same dual-auth as `setup_mfa`: Bearer/cookie for voluntary enrolment;
    // challenge_token in body for forced enrolment users without a session.
    let actor =
        resolve_setup_actor(&state, &headers, request.challenge_token.as_deref()).await?;
    let ip_address = extract_client_ip(&headers, Some(&addr));
    let user_agent = extract_user_agent(&headers);
    let client_ctx = ClientContext::new(ip_address, user_agent);
    let user = state.user_repo.get_user_by_id(actor.user_id).await.map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(MfaApiError {
                error: "internal_error".into(),
                message: "Failed to fetch user".into(),
            }),
        )
    })?;

    if user.mfa_enabled {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(MfaApiError {
                error: "already_enabled".into(),
                message: "MFA is already enabled".into(),
            }),
        ));
    }

    // Require a pending setup. Together with `mfa_setup_pending=TRUE`
    // being flipped atomically by `store_pending_totp_secret` (so it can
    // only flow from a fresh `/api/auth/mfa/setup` call), this prevents
    // a stolen challenge_token from advancing the wizard against a user
    // who never started enrolment in this window.
    if !user.mfa_setup_pending {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(MfaApiError {
                error: "no_pending_setup".into(),
                message: "No pending MFA setup — call POST /api/auth/mfa/setup first".into(),
            }),
        ));
    }

    // Decrypt the pending TOTP secret
    let totp_encrypted = user.totp_secret_encrypted.as_ref().ok_or_else(|| {
        (
            StatusCode::BAD_REQUEST,
            Json(MfaApiError {
                error: "no_pending_setup".into(),
                message: "No pending MFA setup — call POST /api/auth/mfa/setup first".into(),
            }),
        )
    })?;
    let totp_nonce = user.totp_secret_nonce.as_ref().ok_or_else(|| {
        (
            StatusCode::BAD_REQUEST,
            Json(MfaApiError {
                error: "no_pending_setup".into(),
                message: "No pending MFA setup".into(),
            }),
        )
    })?;

    let secret = mfa::decrypt_secret(totp_encrypted, totp_nonce, &state.encryption_service)
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(MfaApiError {
                    error: "decryption_error".into(),
                    message: e.to_string(),
                }),
            )
        })?;

    // Verify the code
    let valid = mfa::verify_totp(&secret, &user.email, &request.code).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(MfaApiError {
                error: "totp_error".into(),
                message: e.to_string(),
            }),
        )
    })?;

    if !valid {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(MfaApiError {
                error: "invalid_code".into(),
                message: "Invalid TOTP code — check your authenticator app and try again".into(),
            }),
        ));
    }

    // Generate backup codes
    let backup_codes = mfa::generate_backup_codes();
    let hashed_codes = mfa::hash_backup_codes(&backup_codes);
    let encrypted_backups = mfa::encrypt_backup_codes(&hashed_codes, &state.encryption_service)
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(MfaApiError {
                    error: "encryption_error".into(),
                    message: e.to_string(),
                }),
            )
        })?;

    let backup_ciphertext = base64::Engine::decode(
        &base64::engine::general_purpose::STANDARD,
        &encrypted_backups.ciphertext,
    )
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(MfaApiError {
                error: "encoding_error".into(),
                message: e.to_string(),
            }),
        )
    })?;

    // Activate MFA
    state
        .user_repo
        .enable_mfa(
            user.id,
            totp_encrypted,
            totp_nonce,
            &backup_ciphertext,
            &encrypted_backups.nonce,
        )
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(MfaApiError {
                    error: "db_error".into(),
                    message: e.to_string(),
                }),
            )
        })?;

    // Single-use challenge_token: revoke the JTI so a leaked token can't
    // re-run setup → verify and overwrite this user's TOTP secret. Only
    // applies to the forced-enrolment path; Bearer-auth callers don't
    // carry a JTI here (their access tokens have their own lifecycle).
    if let Some((jti, exp)) = actor.challenge_jti {
        state.token_service.revoke_token(jti, exp).await;
    }

    state.emit_audit(
        AuditEvent::builder(AuditSource::Auth, audit_actions::MFA_SETUP_COMPLETE)
            .actor(Some(user.id), Some(user.email.clone()))
            .resource("user", Some(user.id), Some(user.email))
            .client_context(&client_ctx)
            .build(),
    );

    Ok(Json(MfaSetupCompleteResponse { backup_codes }))
}

// === Login Challenge ===

/// Complete MFA challenge during login
///
/// POST /api/auth/mfa/challenge
#[utoipa::path(
    post,
    path = "/api/auth/mfa/challenge",
    tag = "mfa",
    request_body = MfaChallengeRequest,
    responses(
        (status = 200, description = "MFA verified, login complete", body = nanosiem_core::auth::AuthResponse),
        (status = 401, description = "Invalid code or challenge token", body = MfaApiError),
    ),
    security(())
)]
pub async fn verify_mfa_challenge(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(request): Json<MfaChallengeRequest>,
) -> Result<Response, (StatusCode, Json<MfaApiError>)> {
    let ip_address = extract_client_ip(&headers, Some(&addr));
    let user_agent = extract_user_agent(&headers);

    let response = state
        .auth_service
        .complete_mfa_login(
            &request.challenge_token,
            &request.code,
            &state.encryption_service,
            ip_address.as_deref(),
            user_agent.as_deref(),
        )
        .await
        .map_err(|_| {
            (
                StatusCode::UNAUTHORIZED,
                Json(MfaApiError {
                    error: "invalid_credentials".into(),
                    message: "Invalid MFA code or expired challenge".into(),
                }),
            )
        })?;

    // Set cookies (same as normal login success)
    let access_cookie =
        build_access_token_cookie(&response.tokens.access_token, response.tokens.expires_in);
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

// === Management Endpoints ===

/// Get MFA status for current user
///
/// GET /api/auth/mfa/status
#[utoipa::path(
    get,
    path = "/api/auth/mfa/status",
    tag = "mfa",
    responses(
        (status = 200, description = "MFA status", body = MfaStatusResponse),
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn get_mfa_status(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
) -> Result<Json<MfaStatusResponse>, (StatusCode, Json<MfaApiError>)> {
    let user = state
        .user_repo
        .get_user_by_id(auth.claims.sub)
        .await
        .map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(MfaApiError {
                    error: "internal_error".into(),
                    message: "Failed to fetch user".into(),
                }),
            )
        })?;

    let mfa_required_globally = state
        .user_repo
        .is_mfa_required_globally()
        .await
        .unwrap_or(false);

    Ok(Json(MfaStatusResponse {
        mfa_enabled: user.mfa_enabled,
        mfa_setup_pending: user.mfa_setup_pending,
        mfa_required_globally,
    }))
}

/// Disable MFA for current user (requires password confirmation)
///
/// DELETE /api/auth/mfa
#[utoipa::path(
    delete,
    path = "/api/auth/mfa",
    tag = "mfa",
    request_body = MfaDisableRequest,
    responses(
        (status = 204, description = "MFA disabled"),
        (status = 400, description = "Invalid password or MFA not enabled", body = MfaApiError),
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn disable_mfa(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Extension(auth): Extension<AuthContext>,
    Json(request): Json<MfaDisableRequest>,
) -> Result<StatusCode, (StatusCode, Json<MfaApiError>)> {
    let ip_address = extract_client_ip(&headers, Some(&addr));
    let user_agent = extract_user_agent(&headers);
    let client_ctx = ClientContext::new(ip_address, user_agent);

    let user = state
        .user_repo
        .get_user_by_id(auth.claims.sub)
        .await
        .map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(MfaApiError {
                    error: "internal_error".into(),
                    message: "Failed to fetch user".into(),
                }),
            )
        })?;

    if !user.mfa_enabled {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(MfaApiError {
                error: "not_enabled".into(),
                message: "MFA is not enabled for this account".into(),
            }),
        ));
    }

    // Verify password
    let password_hash = user.password_hash.as_ref().ok_or_else(|| {
        (
            StatusCode::BAD_REQUEST,
            Json(MfaApiError {
                error: "no_password".into(),
                message: "Cannot disable MFA without a password".into(),
            }),
        )
    })?;

    let pwd = request.password.clone();
    let h = password_hash.clone();
    let valid = tokio::task::spawn_blocking(move || nanosiem_core::auth::verify_password(&pwd, &h))
        .await
        .map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(MfaApiError {
                    error: "internal_error".into(),
                    message: "Password verification failed".into(),
                }),
            )
        })?
        .map_err(|_| {
            (
                StatusCode::BAD_REQUEST,
                Json(MfaApiError {
                    error: "invalid_password".into(),
                    message: "Invalid password".into(),
                }),
            )
        })?;

    if !valid {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(MfaApiError {
                error: "invalid_password".into(),
                message: "Invalid password".into(),
            }),
        ));
    }

    state.user_repo.disable_mfa(user.id).await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(MfaApiError {
                error: "db_error".into(),
                message: e.to_string(),
            }),
        )
    })?;

    state.emit_audit(
        AuditEvent::builder(AuditSource::Auth, audit_actions::MFA_DISABLED)
            .actor(Some(user.id), Some(user.email.clone()))
            .resource("user", Some(user.id), Some(user.email))
            .client_context(&client_ctx)
            .build(),
    );

    Ok(StatusCode::NO_CONTENT)
}

/// Regenerate backup codes (requires password confirmation)
///
/// POST /api/auth/mfa/backup-codes
#[utoipa::path(
    post,
    path = "/api/auth/mfa/backup-codes",
    tag = "mfa",
    request_body = MfaRegenerateBackupCodesRequest,
    responses(
        (status = 200, description = "New backup codes generated", body = MfaSetupCompleteResponse),
        (status = 400, description = "Invalid password or MFA not enabled", body = MfaApiError),
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn regenerate_backup_codes(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Json(request): Json<MfaRegenerateBackupCodesRequest>,
) -> Result<Json<MfaSetupCompleteResponse>, (StatusCode, Json<MfaApiError>)> {
    let user = state
        .user_repo
        .get_user_by_id(auth.claims.sub)
        .await
        .map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(MfaApiError {
                    error: "internal_error".into(),
                    message: "Failed to fetch user".into(),
                }),
            )
        })?;

    if !user.mfa_enabled {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(MfaApiError {
                error: "not_enabled".into(),
                message: "MFA is not enabled".into(),
            }),
        ));
    }

    // Verify password
    let password_hash = user.password_hash.as_ref().ok_or_else(|| {
        (
            StatusCode::BAD_REQUEST,
            Json(MfaApiError {
                error: "no_password".into(),
                message: "Cannot regenerate backup codes without a password".into(),
            }),
        )
    })?;

    let pwd = request.password.clone();
    let h = password_hash.clone();
    let valid = tokio::task::spawn_blocking(move || nanosiem_core::auth::verify_password(&pwd, &h))
        .await
        .map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(MfaApiError {
                    error: "internal_error".into(),
                    message: "Password verification failed".into(),
                }),
            )
        })?
        .map_err(|_| {
            (
                StatusCode::BAD_REQUEST,
                Json(MfaApiError {
                    error: "invalid_password".into(),
                    message: "Invalid password".into(),
                }),
            )
        })?;

    if !valid {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(MfaApiError {
                error: "invalid_password".into(),
                message: "Invalid password".into(),
            }),
        ));
    }

    // Generate new backup codes
    let backup_codes = mfa::generate_backup_codes();
    let hashed_codes = mfa::hash_backup_codes(&backup_codes);
    let encrypted_backups = mfa::encrypt_backup_codes(&hashed_codes, &state.encryption_service)
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(MfaApiError {
                    error: "encryption_error".into(),
                    message: e.to_string(),
                }),
            )
        })?;

    let backup_ciphertext = base64::Engine::decode(
        &base64::engine::general_purpose::STANDARD,
        &encrypted_backups.ciphertext,
    )
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(MfaApiError {
                error: "encoding_error".into(),
                message: e.to_string(),
            }),
        )
    })?;

    state
        .user_repo
        .update_backup_codes(user.id, &backup_ciphertext, &encrypted_backups.nonce)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(MfaApiError {
                    error: "db_error".into(),
                    message: e.to_string(),
                }),
            )
        })?;

    state.emit_audit(
        AuditEvent::builder(
            AuditSource::Auth,
            audit_actions::MFA_BACKUP_CODES_REGENERATED,
        )
        .actor(Some(user.id), Some(user.email.clone()))
        .resource("user", Some(user.id), Some(user.email))
        .build(),
    );

    Ok(Json(MfaSetupCompleteResponse { backup_codes }))
}

/// Admin: reset MFA for a user
///
/// DELETE /api/admin/users/{id}/mfa
#[utoipa::path(
    delete,
    path = "/api/admin/users/{id}/mfa",
    tag = "mfa",
    params(("id" = String, Path, description = "User ID")),
    responses(
        (status = 204, description = "User MFA reset"),
        (status = 403, description = "Insufficient permissions", body = MfaApiError),
        (status = 404, description = "User not found", body = MfaApiError),
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn admin_reset_mfa(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Extension(auth): Extension<AuthContext>,
    Path(user_id): Path<TypeIdParam>,
) -> Result<StatusCode, (StatusCode, Json<MfaApiError>)> {
    let ip_address = extract_client_ip(&headers, Some(&addr));
    let user_agent = extract_user_agent(&headers);
    let client_ctx = ClientContext::new(ip_address, user_agent);

    // Require users:manage permission
    if !auth.claims.has_permission("users:manage") {
        return Err((
            StatusCode::FORBIDDEN,
            Json(MfaApiError {
                error: "forbidden".into(),
                message: "Insufficient permissions".into(),
            }),
        ));
    }

    let target_user = state.user_repo.get_user_by_id(*user_id).await.map_err(|_| {
        (
            StatusCode::NOT_FOUND,
            Json(MfaApiError {
                error: "not_found".into(),
                message: "User not found".into(),
            }),
        )
    })?;

    state.user_repo.disable_mfa(*user_id).await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(MfaApiError {
                error: "db_error".into(),
                message: e.to_string(),
            }),
        )
    })?;

    state.emit_audit(
        AuditEvent::builder(AuditSource::Auth, audit_actions::MFA_ADMIN_RESET)
            .actor(Some(auth.claims.sub), None)
            .resource("user", Some(*user_id), Some(target_user.email))
            .client_context(&client_ctx)
            .build(),
    );

    Ok(StatusCode::NO_CONTENT)
}

/// Admin: set global MFA requirement
///
/// PUT /api/settings/mfa-required
#[utoipa::path(
    put,
    path = "/api/settings/mfa-required",
    tag = "mfa",
    request_body = MfaRequiredRequest,
    responses(
        (status = 200, description = "MFA requirement updated", body = MfaRequiredResponse),
        (status = 403, description = "Insufficient permissions", body = MfaApiError),
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn set_mfa_required(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Extension(auth): Extension<AuthContext>,
    Json(request): Json<MfaRequiredRequest>,
) -> Result<Json<MfaRequiredResponse>, (StatusCode, Json<MfaApiError>)> {
    let ip_address = extract_client_ip(&headers, Some(&addr));
    let user_agent = extract_user_agent(&headers);
    let client_ctx = ClientContext::new(ip_address, user_agent);

    // Require settings:system permission
    if !auth.claims.has_permission("settings:system") {
        return Err((
            StatusCode::FORBIDDEN,
            Json(MfaApiError {
                error: "forbidden".into(),
                message: "Insufficient permissions".into(),
            }),
        ));
    }

    state
        .user_repo
        .set_mfa_required_globally(request.required)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(MfaApiError {
                    error: "db_error".into(),
                    message: e.to_string(),
                }),
            )
        })?;

    state.emit_audit(
        AuditEvent::builder(AuditSource::Auth, audit_actions::MFA_ENFORCED_GLOBALLY)
            .actor(Some(auth.claims.sub), None)
            .resource("system_settings", None::<Uuid>, None::<String>)
            .client_context(&client_ctx)
            .details(serde_json::json!({ "mfa_required": request.required }))
            .build(),
    );

    Ok(Json(MfaRequiredResponse {
        mfa_required: request.required,
    }))
}

/// Request to set global MFA requirement
#[derive(Debug, Clone, Deserialize, utoipa::ToSchema)]
pub struct MfaRequiredRequest {
    pub required: bool,
}

/// Response confirming global MFA requirement
#[derive(Debug, Clone, Serialize, utoipa::ToSchema)]
pub struct MfaRequiredResponse {
    pub mfa_required: bool,
}

/// OpenAPI documentation for MFA endpoints
#[derive(utoipa::OpenApi)]
#[openapi(
    paths(
        setup_mfa,
        verify_mfa_setup,
        verify_mfa_challenge,
        get_mfa_status,
        disable_mfa,
        regenerate_backup_codes,
        admin_reset_mfa,
        set_mfa_required,
    ),
    components(schemas(
        MfaApiError,
        MfaSetupResponse,
        MfaVerifySetupRequest,
        MfaSetupCompleteResponse,
        MfaChallengeRequest,
        MfaStatusResponse,
        MfaDisableRequest,
        MfaRegenerateBackupCodesRequest,
        MfaRequiredRequest,
        MfaRequiredResponse,
    ))
)]
pub struct MfaApiDoc;

#[cfg(test)]
mod tests {
    use super::*;
    use nanosiem_core::typeid;
    use std::str::FromStr;

    /// Regression: User.id is serialized as `user_<base32>`, and admin tooling
    /// pulls the user_id for `DELETE /api/admin/users/{id}/mfa` straight from
    /// the users list response. The path extractor must accept that form.
    #[test]
    fn typeid_param_accepts_user_prefixed_id_for_admin_reset_mfa() {
        let id = Uuid::now_v7();
        let encoded = typeid::encode(typeid::user::PREFIX, &id);
        assert!(encoded.starts_with("user_"));

        let extracted = TypeIdParam::from_str(&encoded).expect("user_ id should parse");
        assert_eq!(*extracted, id);
    }

    /// Backwards-compat: bare UUIDs still work for any internal callers.
    #[test]
    fn typeid_param_still_accepts_bare_uuid_for_admin_reset_mfa() {
        let id = Uuid::now_v7();
        let extracted = TypeIdParam::from_str(&id.to_string()).expect("bare uuid should parse");
        assert_eq!(*extracted, id);
    }
}
