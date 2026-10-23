// SPDX-License-Identifier: AGPL-3.0-or-later

//! MFA (Multi-Factor Authentication) API handlers
//!
//! Provides TOTP enrollment, verification, and management endpoints.
//! Supports user-optional MFA and admin-enforced MFA for all local users.

use axum::{
    extract::{ConnectInfo, Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Extension, Json,
};
#[cfg(feature = "enterprise")]
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use uuid::Uuid;

use crate::handlers::AuditExt;
use crate::middleware::{require_session_auth, AuthContext};
use crate::state::AppState;
use crate::utils::{extract_client_ip, extract_user_agent};
use nanosiem_core::audit::{actions as audit_actions, AuditEvent, AuditSource, ClientContext};
use nanosiem_core::auth::{
    mfa, permissions, AuthError, MfaChallengeRequest, MfaDisableRequest,
    MfaRegenerateBackupCodesRequest, MfaSetupCompleteResponse, MfaSetupRequest, MfaSetupResponse,
    MfaStatusResponse, MfaVerifySetupRequest, SharedMfaSetupAuthority,
};
use nanosiem_core::typeid::TypeIdParam;
use nanosiem_api_lib::{
    append_set_cookies, clear_mfa_challenge_cookie, clear_mfa_challenge_cookie_for,
    extract_scoped_cookie, issued_session_set_cookies, shared_mfa_challenge_tenant,
    SessionCookieScope, MFA_CHALLENGE_COOKIE,
};
#[cfg(feature = "enterprise")]
use nanosiem_api_lib::{select_tenant_cookie, shared_access_token_tenant, ACCESS_TOKEN_COOKIE};

// Hosted tenant-bound MFA setup actor resolution (NAN-3861).
#[cfg(feature = "enterprise")]
mod enterprise_shared_setup_actor;
#[cfg(feature = "enterprise")]
use enterprise_shared_setup_actor::resolve_setup_actor;

/// Error response for MFA endpoints
#[derive(Debug, Serialize, Deserialize, utoipa::ToSchema)]
pub struct MfaApiError {
    pub error: String,
    pub message: String,
}

fn shared_continuation_error(error: AuthError) -> (StatusCode, Json<MfaApiError>) {
    let (status, code, message) = match error {
        AuthError::TenantAccessDenied => (
            StatusCode::FORBIDDEN, "tenant_access_denied", "Tenant access denied",
        ),
        AuthError::TenantUnavailable => (
            StatusCode::SERVICE_UNAVAILABLE, "tenant_unavailable", "Tenant access is temporarily unavailable",
        ),
        _ => (StatusCode::UNAUTHORIZED, "unauthorized", "Invalid or expired authentication"),
    };
    (status, Json(MfaApiError { error: code.into(), message: message.into() }))
}

/// NAN-2080: adapt a `require_session_auth` rejection into this module's error
/// shape. Used to gate MFA-state read/mutation to interactive sessions only —
/// an owner-bound API key must never be able to inspect or remove the second
/// factor, even with the owner's password.
fn mfa_session_error(
    err: (StatusCode, Json<crate::middleware::AuthErrorResponse>),
) -> (StatusCode, Json<MfaApiError>) {
    let (status, body) = err;
    (
        status,
        Json(MfaApiError {
            error: body.error.clone(),
            message: body.message.clone(),
        }),
    )
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
    #[cfg_attr(not(feature = "enterprise"), allow(dead_code))]
    shared_authority: Option<SharedMfaSetupAuthority>,
    /// NAN-3436: the verified tenant, so pre-session audit can be signed.
    #[cfg_attr(not(feature = "enterprise"), allow(dead_code))]
    shared_tenant: Option<nanosiem_core::auth::TrustedTenantContext>,
}

#[cfg(not(feature = "enterprise"))]
/// Open build: Bearer / `access_token` cookie session, else a body
/// `challenge_token`; there is no tenant-bound credential to resolve.
async fn resolve_setup_actor(
    state: &AppState,
    headers: &HeaderMap,
    challenge_token: Option<&str>,
    tenant_slug: Option<&str>,
    _ip_address: Option<&str>,
) -> Result<SetupActor, (StatusCode, Json<MfaApiError>)> {
    let bearer = bearer_from_headers(headers);
    let session_cookie = access_token_cookie(headers);

    // Prefer Bearer / cookie session — keeps the voluntary path identical.
    if let Some(token) = bearer.or(session_cookie) {
        if tenant_slug.is_none() {
            if let Ok(claims) = state
                .token_service
                .validate_access_token_async(&token)
                .await
            {
                if claims.purpose == "access" {
                    return Ok(SetupActor {
                        user_id: claims.sub,
                        challenge_jti: None,
                        shared_authority: None,
                        shared_tenant: None,
                    });
                }
            }
        }
    }
    // Fall back to a challenge_token explicitly passed in the body.
    if let Some(token) = challenge_token.filter(|s| !s.is_empty()) {
        if tenant_slug.is_none() {
            match state
                .token_service
                .validate_mfa_challenge_token_async(token)
                .await
            {
                Ok(claims) if claims.purpose == "mfa_challenge" => {
                    return Ok(SetupActor {
                        user_id: claims.sub,
                        challenge_jti: Some((claims.jti, claims.exp)),
                        shared_authority: None,
                        shared_tenant: None,
                    });
                }
                Ok(_) => {}
                Err(e) => {
                    tracing::debug!(error = %e, "MFA setup: challenge_token rejected");
                }
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
        (status = 403, description = "Tenant access denied", body = MfaApiError),
        (status = 503, description = "Tenant access policy unavailable", body = MfaApiError),
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn setup_mfa(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: Option<Json<MfaSetupRequest>>,
) -> Result<Json<MfaSetupResponse>, (StatusCode, Json<MfaApiError>)> {
    // Body is optional — voluntary enrollment from User Settings POSTs an
    // empty body and authenticates via Bearer; forced enrollment passes the
    // mfa_challenge token in the body because there's no session yet.
    let challenge_token = body.as_ref().and_then(|b| b.0.challenge_token.as_deref());
    let tenant_slug = body.as_ref().and_then(|b| b.0.tenant_slug.as_deref());
    let ip_address = extract_client_ip(&headers, Some(&addr));
    let actor = resolve_setup_actor(&state, &headers, challenge_token, tenant_slug, ip_address.as_deref()).await?;
    let user_agent = extract_user_agent(&headers);
    let client_ctx = ClientContext::new(ip_address, user_agent);
    let user = state
        .user_repo
        .get_user_by_id(actor.user_id)
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

    // The challenge proves a recent password check, not that the account is
    // still active. Do not let a disabled/locked user mutate MFA state during
    // the five-minute enrollment window.
    if user.status != "active" {
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(MfaApiError {
                error: "unauthorized".into(),
                message: "Authentication required".into(),
            }),
        ));
    }

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
        mfa::encrypt_secret(&secret_base32, &(&state.encryption_service).with_context(nanosiem_core::crypto::CredentialScope::Account(user.id), "account.totp", user.id)).map_err(|e| {
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

    #[cfg(feature = "enterprise")]
    if state.config.deployment_mode.is_enterprise_shared() {
        let authority = actor.shared_authority.ok_or_else(|| {
            (
                StatusCode::UNAUTHORIZED,
                Json(MfaApiError {
                    error: "unauthorized".into(),
                    message: "Authentication required".into(),
                }),
            )
        })?;
        let stored = state
            .user_repo
            .store_pending_totp_secret_for_shared_authority(
                user.id,
                authority,
                &ciphertext,
                &encrypted.nonce,
            )
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "shared MFA setup authority persistence failed");
                (
                    StatusCode::SERVICE_UNAVAILABLE,
                    Json(MfaApiError {
                        error: "mfa_setup_unavailable".into(),
                        message: "MFA setup is temporarily unavailable".into(),
                    }),
                )
            })?;
        if !stored {
            return Err((
                StatusCode::UNAUTHORIZED,
                Json(MfaApiError {
                    error: "credential_stale".into(),
                    message: "Authentication must be repeated before MFA setup".into(),
                }),
            ));
        }
    } else {
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
    }
    #[cfg(not(feature = "enterprise"))]
    {
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
    }

    let setup_event = AuditEvent::builder(AuditSource::Auth, audit_actions::MFA_SETUP_INITIATED)
        .actor(Some(user.id), Some(user.email.clone()))
        .resource("user", Some(user.id), Some(user.email))
        .client_context(&client_ctx)
        .build();
    // NAN-3436: hosted-shared enrollment runs before any session; write its
    // audit row in a signed tenant + actor transaction (the shared emitter
    // refuses tenantless writes and could only log it "for recovery").
    #[cfg(feature = "enterprise")]
    let setup_event = match (actor.shared_tenant.as_ref(), state.tenant_ai_rls_runtime.as_ref()) {
        (Some(tenant), Some(runtime)) => match runtime.tenant_pre_session_audit().record(tenant, user.id, &setup_event).await {
            Ok(()) => None,
            Err(error) => {
                tracing::error!(tenant_id = %tenant.tenant_id, %error, "MFA setup audit not written in a signed tenant transaction; logged for recovery");
                Some(setup_event)
            }
        },
        _ => Some(setup_event),
    };
    #[cfg(not(feature = "enterprise"))]
    let setup_event = Some(setup_event);
    if let Some(event) = setup_event {
        state.emit_audit(event);
    }

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
        (status = 401, description = "Authentication required", body = MfaApiError),
        (status = 403, description = "Tenant access denied", body = MfaApiError),
        (status = 503, description = "Tenant access policy unavailable", body = MfaApiError),
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn verify_mfa_setup(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(request): Json<MfaVerifySetupRequest>,
) -> Result<Response, (StatusCode, Json<MfaApiError>)> {
    // Same dual-auth as `setup_mfa`: Bearer/cookie for voluntary enrollment;
    // challenge_token in body for forced enrollment users without a session.
    let ip_address = extract_client_ip(&headers, Some(&addr));
    let actor = resolve_setup_actor(
        &state,
        &headers,
        request.challenge_token.as_deref(),
        request.tenant_slug.as_deref(),
        ip_address.as_deref(),
    )
    .await?;
    let user_agent = extract_user_agent(&headers);
    let client_ctx = ClientContext::new(ip_address, user_agent);
    let user = state
        .user_repo
        .get_user_by_id(actor.user_id)
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

    if user.status != "active" {
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(MfaApiError {
                error: "unauthorized".into(),
                message: "Authentication required".into(),
            }),
        ));
    }

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
    // who never started enrollment in this window.
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

    let secret = mfa::decrypt_secret(totp_encrypted, totp_nonce, &(&state.encryption_service).with_context(nanosiem_core::crypto::CredentialScope::Account(user.id), "account.totp", user.id))
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
    let encrypted_backups = mfa::encrypt_backup_codes(&hashed_codes, &(&state.encryption_service).with_context(nanosiem_core::crypto::CredentialScope::Account(user.id), "account.backup-codes", user.id))
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

    // Activate MFA. Shared mode atomically revalidates the exact tenant
    // credential, the user watermark and the exact pending-secret snapshot;
    // a reset/logout or competing setup cannot win between TOTP verification
    // and this state transition.
    #[cfg(feature = "enterprise")]
    if state.config.deployment_mode.is_enterprise_shared() {
        let authority = actor.shared_authority.ok_or_else(|| {
            (
                StatusCode::UNAUTHORIZED,
                Json(MfaApiError {
                    error: "unauthorized".into(),
                    message: "Authentication required".into(),
                }),
            )
        })?;
        let enabled = state
            .user_repo
            .enable_mfa_for_shared_authority(
                user.id,
                authority,
                totp_encrypted,
                totp_nonce,
                &backup_ciphertext,
                &encrypted_backups.nonce,
            )
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "shared MFA activation authority check failed");
                (
                    StatusCode::SERVICE_UNAVAILABLE,
                    Json(MfaApiError {
                        error: "mfa_setup_unavailable".into(),
                        message: "MFA setup is temporarily unavailable".into(),
                    }),
                )
            })?;
        if !enabled {
            return Err((
                StatusCode::UNAUTHORIZED,
                Json(MfaApiError {
                    error: "credential_stale".into(),
                    message: "Authentication must be repeated before MFA setup".into(),
                }),
            ));
        }
    } else {
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
    }
    #[cfg(not(feature = "enterprise"))]
    {
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
    }

    // Single-use challenge_token: revoke the JTI so a leaked token can't
    // re-run setup → verify and overwrite this user's TOTP secret. Only
    // applies to the forced-enrollment path; Bearer-auth callers don't
    // carry a JTI here (their access tokens have their own lifecycle).
    if let Some((jti, exp)) = actor.challenge_jti {
        state.token_service.revoke_token(jti, exp).await;
    }

    let setup_complete = AuditEvent::builder(AuditSource::Auth, audit_actions::MFA_SETUP_COMPLETE)
        .actor(Some(user.id), Some(user.email.clone()))
        .resource("user", Some(user.id), Some(user.email))
        .client_context(&client_ctx)
        .build();
    // NAN-3790: hosted shared writes it in the verified tenant (the shared
    // emitter refuses tenantless rows).
    match actor.shared_tenant.clone() {
        Some(tenant) => state.emit_tenant_auth_audit(tenant, user.id, vec![setup_complete]),
        None => state.emit_audit(setup_complete),
    }

    let clear_challenge = actor.challenge_jti.is_some();
    let mut response = Json(MfaSetupCompleteResponse { backup_codes }).into_response();
    if clear_challenge {
        // NAN-3548: clear the tenant-suffixed challenge, and the legacy
        // unsuffixed one only when it is bound to the same tenant.
        let clears = match actor.shared_tenant.as_ref() {
            Some(tenant) => {
                let mut clears = vec![clear_mfa_challenge_cookie_for(SessionCookieScope::Tenant(
                    tenant.tenant_id,
                ))];
                let legacy_tenant = extract_scoped_cookie(
                    &headers,
                    MFA_CHALLENGE_COOKIE,
                    SessionCookieScope::Default,
                )
                .and_then(|token| shared_mfa_challenge_tenant(&state.token_service, &token));
                if legacy_tenant == Some(tenant.tenant_id) {
                    clears.push(clear_mfa_challenge_cookie());
                }
                clears
            }
            None => vec![clear_mfa_challenge_cookie()],
        };
        append_set_cookies(response.headers_mut(), clears);
    }
    Ok(response)
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
        (status = 403, description = "Tenant access denied", body = MfaApiError),
        (status = 503, description = "Authentication or durable audit unavailable", body = MfaApiError),
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
    let client_ctx = ClientContext::new(ip_address.clone(), user_agent.clone());

    let outcome = match state
        .auth_service
        .complete_mfa_login(
            &request.challenge_token,
            &request.code,
            request.tenant_slug.as_deref(),
            &state.encryption_service,
            ip_address.as_deref(),
            user_agent.as_deref(),
        )
        .await
    {
        Ok(outcome) => outcome,
        Err(e) => {
            if matches!(e, AuthError::TenantAccessDenied | AuthError::TenantUnavailable) {
                return Err(shared_continuation_error(e));
            }
            // Only an actually-wrong MFA code is a failed *challenge*.
            // `complete_mfa_login` returns `InvalidCredentials` for exactly that
            // case (bad TOTP and no/invalid backup code). Every other error here
            // — an invalid/expired challenge token, or a DB/role/session error
            // that occurs AFTER a correct code during login completion — is NOT
            // an MFA verification failure and must not be mis-audited as one, so
            // it is left unaudited on this path.
            if matches!(e, AuthError::InvalidCredentials) {
                // The challenge token validated (we got past its check), so the
                // actor resolves from it.
                #[cfg(feature = "enterprise")]
                if state.config.deployment_mode.is_enterprise_shared() {
                    super::auth_challenge_audit::record(
                        &state, &request.challenge_token, request.tenant_slug.as_deref(), &client_ctx,
                        audit_actions::MFA_CHALLENGE_FAILED, false,
                        Some(serde_json::json!({"reason": "invalid_mfa_code"})),
                    ).await.map_err(|_| (StatusCode::SERVICE_UNAVAILABLE, Json(MfaApiError {
                        error: "audit_unavailable".into(),
                        message: "Authentication auditing is temporarily unavailable".into(),
                    })))?;
                } else {
                    let actor_id = state.token_service
                        .validate_mfa_challenge_token_async(&request.challenge_token)
                        .await.ok().map(|c| c.sub);
                    state.emit_audit(
                        AuditEvent::builder(AuditSource::Auth, audit_actions::MFA_CHALLENGE_FAILED)
                            .actor(actor_id, None).resource("user", actor_id, None)
                            .client_context(&client_ctx).success(false)
                            .details(serde_json::json!({"reason": "invalid_mfa_code"})).build(),
                    );
                }
                #[cfg(not(feature = "enterprise"))]
                {
                    let actor_id = state.token_service
                        .validate_mfa_challenge_token_async(&request.challenge_token)
                        .await.ok().map(|c| c.sub);
                    state.emit_audit(
                        AuditEvent::builder(AuditSource::Auth, audit_actions::MFA_CHALLENGE_FAILED)
                            .actor(actor_id, None).resource("user", actor_id, None)
                            .client_context(&client_ctx).success(false)
                            .details(serde_json::json!({"reason": "invalid_mfa_code"})).build(),
                    );
                }
            }
            return Err((
                StatusCode::UNAUTHORIZED,
                Json(MfaApiError {
                    error: "invalid_credentials".into(),
                    message: "Invalid MFA code or expired challenge".into(),
                }),
            ));
        }
    };

    let response = outcome.response;
    let actor_id = response.user.id;
    let actor_email = response.user.email.clone();

    let mut events = Vec::with_capacity(3);
    // A single-use backup code was consumed — defenders track these (a burst can
    // indicate the user lost their authenticator or an attacker is draining
    // codes).
    if outcome.used_backup_code {
        events.push(
            AuditEvent::builder(AuditSource::Auth, audit_actions::MFA_BACKUP_CODE_USED)
                .actor(Some(actor_id), Some(actor_email.clone()))
                .resource("user", Some(actor_id), Some(actor_email.clone()))
                .client_context(&client_ctx)
                .build(),
        );
    }
    // The MFA challenge was satisfied, and login completed. The non-MFA path
    // emits login_success from the login handler; the MFA-completion path must
    // emit its own (with mfa_verified) so MFA users' logins are audited too.
    events.push(
        AuditEvent::builder(AuditSource::Auth, audit_actions::MFA_CHALLENGE_SUCCESS)
            .actor(Some(actor_id), Some(actor_email.clone()))
            .resource("user", Some(actor_id), Some(actor_email.clone()))
            .client_context(&client_ctx)
            .details(serde_json::json!({
                "method": if outcome.used_backup_code { "backup_code" } else { "totp" }
            }))
            .build(),
    );
    events.push(
        AuditEvent::builder(AuditSource::Auth, audit_actions::LOGIN_SUCCESS)
            .actor(Some(actor_id), Some(actor_email.clone()))
            .resource("user", Some(actor_id), Some(actor_email))
            .client_context(&client_ctx)
            .details(serde_json::json!({ "mfa_verified": true }))
            .build(),
    );
    // NAN-3790: hosted shared writes the login in the tenant the challenge
    // was revalidated against, in one signed tenant + actor transaction.
    match outcome.tenant {
        Some(tenant) => state.emit_tenant_auth_audit(tenant, actor_id, events),
        None => events.into_iter().for_each(|event| state.emit_audit(event)),
    }

    // Set cookies (same as normal login success; per-tenant names in shared mode)
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
        (status = 403, description = "Session-only endpoint — API keys are rejected", body = MfaApiError),
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_mfa_status(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
) -> Result<Json<MfaStatusResponse>, (StatusCode, Json<MfaApiError>)> {
    // NAN-2080: MFA state is session-only (see `disable_mfa`).
    require_session_auth(&auth).map_err(mfa_session_error)?;

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
        (status = 403, description = "Session-only endpoint — API keys are rejected", body = MfaApiError),
        (status = 400, description = "Invalid password or MFA not enabled", body = MfaApiError),
    ),
    security(("bearer_auth" = []))
)]
pub async fn disable_mfa(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Extension(auth): Extension<AuthContext>,
    Json(request): Json<MfaDisableRequest>,
) -> Result<StatusCode, (StatusCode, Json<MfaApiError>)> {
    // NAN-2080: removing the second factor is session-only. Password confirmation
    // below is re-auth, not proof of an MFA-completed session — an owner-bound
    // API key plus the owner's password must not be able to disable MFA.
    require_session_auth(&auth).map_err(mfa_session_error)?;

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
        (status = 403, description = "Session-only endpoint — API keys are rejected", body = MfaApiError),
        (status = 400, description = "Invalid password or MFA not enabled", body = MfaApiError),
    ),
    security(("bearer_auth" = []))
)]
pub async fn regenerate_backup_codes(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Json(request): Json<MfaRegenerateBackupCodesRequest>,
) -> Result<Json<MfaSetupCompleteResponse>, (StatusCode, Json<MfaApiError>)> {
    // NAN-2080: minting fresh recovery credentials is session-only (see
    // `disable_mfa`) — an owner-bound API key must not be able to regenerate
    // backup codes with only the owner's password.
    require_session_auth(&auth).map_err(mfa_session_error)?;

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
    let encrypted_backups = mfa::encrypt_backup_codes(&hashed_codes, &(&state.encryption_service).with_context(nanosiem_core::crypto::CredentialScope::Account(user.id), "account.backup-codes", user.id))
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

/// Permission required to clear another user's second factor (NAN-2226).
///
/// This gate used to name `users:manage`, an id that exists in NO migration,
/// is absent from [`nanosiem_core::auth::permissions::ALL_PERMISSIONS`], and is
/// therefore not offered by `GET /api/permissions`. Because `role_permissions`
/// carries an FK onto the seeded catalogue, and a role may only be granted
/// permissions the grantor holds, no principal could ever hold it — the route
/// was a permanent 403 on fresh AND legacy installs, so an admin had no way to
/// unlock a user who lost their authenticator.
///
/// [`permissions::USERS_EDIT`] is the correct authority level: it is what every
/// other "administer someone else's account" route already requires
/// (`update_user`, `enable_user`, `disable_user`, group membership changes in
/// `handlers::users`), and clearing a factor is an account modification of the
/// same weight — strictly less than `users:delete`, and not merely `users:view`.
const ADMIN_RESET_MFA_PERMISSION: &str = permissions::USERS_EDIT;

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

    // Require the permission that authorizes modifying another user's account.
    if !auth.claims.has_permission(ADMIN_RESET_MFA_PERMISSION) {
        return Err((
            StatusCode::FORBIDDEN,
            Json(MfaApiError {
                error: "forbidden".into(),
                message: "Insufficient permissions".into(),
            }),
        ));
    }

    let target_user = state
        .user_repo
        .get_user_by_id(*user_id)
        .await
        .map_err(|_| {
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

    // Require settings:system permission. Named via the constant, not a string
    // literal, so it cannot drift out of the seeded catalogue (NAN-2226).
    if !auth.claims.has_permission(permissions::SETTINGS_SYSTEM) {
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
    #[test]
    fn tenant_ip_policy_continuation_errors_are_sanitized_and_distinct() {
        use super::*;
        for (error, expected_status, expected_code) in [
            (AuthError::TenantAccessDenied, StatusCode::FORBIDDEN, "tenant_access_denied"),
            (AuthError::TenantUnavailable, StatusCode::SERVICE_UNAVAILABLE, "tenant_unavailable"),
            (AuthError::DatabaseError("private database detail".into()), StatusCode::UNAUTHORIZED, "unauthorized"),
        ] {
            let (status, Json(body)) = shared_continuation_error(error);
            assert_eq!(status, expected_status);
            assert_eq!(body.error, expected_code);
            assert!(!body.message.contains("private"));
        }
    }

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

    /// NAN-2080: `get_mfa_status`, `disable_mfa`, and `regenerate_backup_codes`
    /// are session-only. An owner-bound API key (whose `sub` maps to the owner)
    /// must be rejected with 403 by `require_session_auth` before any user lookup
    /// — password confirmation in those handlers is re-auth, not proof of an
    /// MFA-completed session. Also guards the `mfa_session_error` mapping.
    #[test]
    fn mfa_endpoints_reject_api_key_principals() {
        use nanosiem_core::auth::ApiKeyInfo;

        let api_key_ctx = AuthContext::from_api_key(&ApiKeyInfo {
            id: Uuid::now_v7(),
            name: "automation".to_string(),
            permissions: vec![],
            user_id: Some(Uuid::now_v7()),
        });

        let err = require_session_auth(&api_key_ctx)
            .map_err(mfa_session_error)
            .expect_err("api-key principal must be rejected on MFA endpoints");
        assert_eq!(err.0, StatusCode::FORBIDDEN);
        assert!(!err.1.message.is_empty(), "403 body should carry a message");
    }

    /// NAN-2226: the gate on `DELETE /api/admin/users/{id}/mfa` must name a
    /// permission the catalogue actually seeds. It previously named
    /// `users:manage`, which exists in no migration and in no constant — so it
    /// could never be held, and the route was an unconditional 403 that left
    /// admins unable to unlock a user who lost their authenticator.
    ///
    /// `has_permission` is an exact string match with no wildcard and no admin
    /// bypass, so an unseeded id here is not a lint nit — it is a dead route.
    #[test]
    fn admin_reset_mfa_permission_exists_in_the_catalogue() {
        assert!(
            permissions::is_valid_permission(ADMIN_RESET_MFA_PERMISSION),
            "admin MFA reset gates on `{}`, which is not in ALL_PERMISSIONS — \
             no role can be granted it, so the route would 403 forever",
            ADMIN_RESET_MFA_PERMISSION,
        );
        assert!(
            permissions::is_valid_permission(permissions::SETTINGS_SYSTEM),
            "set_mfa_required gates on `{}`, which is not in ALL_PERMISSIONS",
            permissions::SETTINGS_SYSTEM,
        );
    }

    /// A principal holding the gate permission passes, one without it does not.
    /// Guards the swap itself, not just the id's existence.
    #[test]
    fn admin_reset_mfa_gate_admits_only_the_permission_holder() {
        use nanosiem_core::auth::ApiKeyInfo;

        let holder = AuthContext::from_api_key(&ApiKeyInfo {
            id: Uuid::now_v7(),
            name: "admin-tooling".to_string(),
            permissions: vec![ADMIN_RESET_MFA_PERMISSION.to_string()],
            user_id: Some(Uuid::now_v7()),
        });
        assert!(holder.claims.has_permission(ADMIN_RESET_MFA_PERMISSION));

        let viewer = AuthContext::from_api_key(&ApiKeyInfo {
            id: Uuid::now_v7(),
            name: "read-only".to_string(),
            permissions: vec![permissions::USERS_VIEW.to_string()],
            user_id: Some(Uuid::now_v7()),
        });
        assert!(!viewer.claims.has_permission(ADMIN_RESET_MFA_PERMISSION));
    }
}
