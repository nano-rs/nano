// SPDX-License-Identifier: AGPL-3.0-or-later

//! Token management + connectivity probe for push targets.

use axum::{
    extract::{Path, State},
    Extension, Json,
};
use nanosiem_core::audit::{
    AuditEvent, AuditSource, ClientContext, DETECTION_CODE_TARGET_CONNECTION_TESTED,
    DETECTION_CODE_TARGET_TOKEN_SET,
};
use nanosiem_core::auth::permissions;
use nanosiem_core::detection_code_target::{
    DetectionCodeTarget, GitHubWriteClient, GitHubWriteError,
};
use uuid::Uuid;

use super::{
    get_target_repo, map_target_err,
    types::{SetTokenRequest, TestConnectionResponse},
    AuditExt,
};
use crate::middleware::{ensure_permission, AuthContext};
use crate::{error::ApiError, state::AppState};

/// Set (or replace) the stored GitHub PAT for a target. Write-only — the token
/// is never returned; the response reflects `has_token = true`.
#[utoipa::path(
    post,
    path = "/api/detection-code-targets/{id}/token",
    tag = "detection_code_targets",
    params(("id" = String, Path, description = "Push target ID")),
    request_body = SetTokenRequest,
    responses(
        (status = 200, description = "Token stored", body = DetectionCodeTarget),
        (status = 400, description = "Empty token"),
        (status = 403, description = "Forbidden"),
        (status = 404, description = "Not found"),
    ),
    security(("api_key" = []))
)]
pub async fn set_token(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Extension(client): Extension<ClientContext>,
    Path(id): Path<Uuid>,
    Json(req): Json<SetTokenRequest>,
) -> Result<Json<DetectionCodeTarget>, ApiError> {
    ensure_permission(&auth, permissions::DETECTION_CODE_TARGETS_MANAGE)?;

    if req.token.trim().is_empty() {
        return Err(ApiError::BadRequest("token must not be empty".into()));
    }

    let target = get_target_repo(&state)
        .set_token(id, req.token.trim())
        .await
        .map_err(map_target_err)?;

    state.emit_audit(
        AuditEvent::builder(AuditSource::RuleRepo, DETECTION_CODE_TARGET_TOKEN_SET)
            .actor(Some(auth.user_id()), None)
            .api_key(auth.api_key_id, auth.api_key_name.clone())
            .resource(
                "detection_code_target",
                Some(target.id),
                Some(target.name.clone()),
            )
            .client_context(&client)
            .build(),
    );
    Ok(Json(target))
}

/// Probe the target repo with the stored token: can we read it, and can we open
/// PRs? Returns a 200 with `success = false` on failure (this is a probe, not a
/// mutation), mirroring the agent-enrichment test-connection contract.
#[utoipa::path(
    post,
    path = "/api/detection-code-targets/{id}/test",
    tag = "detection_code_targets",
    params(("id" = String, Path, description = "Push target ID")),
    responses(
        (status = 200, description = "Probe result", body = TestConnectionResponse),
        (status = 403, description = "Forbidden"),
        (status = 404, description = "Not found"),
        (status = 429, description = "Too many connection-test requests"),
    ),
    security(("api_key" = []))
)]
pub async fn test_connection(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Extension(client_context): Extension<ClientContext>,
    Path(id): Path<Uuid>,
) -> Result<Json<TestConnectionResponse>, ApiError> {
    ensure_test_connection_permission(&auth)?;

    let repo = get_target_repo(&state);
    let target = match repo.get(id).await {
        Ok(target) => target,
        Err(error) => {
            emit_connection_test_audit(
                &state,
                &auth,
                &client_context,
                id,
                None,
                false,
                "target_lookup_failed",
                false,
                false,
            );
            return Err(map_target_err(error));
        }
    };
    let token = match repo.get_decrypted_token(id).await {
        Ok(token) => token,
        Err(error) => {
            emit_connection_test_audit(
                &state,
                &auth,
                &client_context,
                id,
                Some(target.name.clone()),
                false,
                "credential_unavailable",
                false,
                false,
            );
            return Err(map_target_err(error));
        }
    };

    let Some(token) = token else {
        emit_connection_test_audit(
            &state,
            &auth,
            &client_context,
            id,
            Some(target.name.clone()),
            false,
            "token_not_configured",
            false,
            false,
        );
        return Ok(Json(TestConnectionResponse {
            success: false,
            can_read: false,
            can_write: false,
            default_branch: None,
            error_code: Some("token_not_configured".into()),
            message: "No GitHub token configured for this target.".into(),
        }));
    };

    let client = GitHubWriteClient::new(token);
    match client.check_access(&target.repo_url).await {
        Ok(access) => {
            let success = access.can_read && access.can_write;
            let message = if success {
                "Connected — token can read the repo and open pull requests.".into()
            } else if access.can_read {
                "Token can read the repo but is missing 'Pull requests: write'.".into()
            } else {
                "Token cannot access this repository.".into()
            };
            emit_connection_test_audit(
                &state,
                &auth,
                &client_context,
                id,
                Some(target.name),
                success,
                if success {
                    "connected"
                } else if access.can_read {
                    "write_access_missing"
                } else {
                    "read_access_missing"
                },
                access.can_read,
                access.can_write,
            );
            Ok(Json(TestConnectionResponse {
                success,
                can_read: access.can_read,
                can_write: access.can_write,
                default_branch: access.default_branch,
                error_code: (!success).then(|| {
                    if access.can_read {
                        "write_access_missing".into()
                    } else {
                        "read_access_missing".into()
                    }
                }),
                message,
            }))
        }
        Err(error) => {
            let error_code = github_error_code(&error);
            tracing::warn!(
                target_id = %id,
                error = %error,
                error_code,
                "Detection-code target connection test failed"
            );
            emit_connection_test_audit(
                &state,
                &auth,
                &client_context,
                id,
                Some(target.name),
                false,
                error_code,
                false,
                false,
            );
            Ok(Json(TestConnectionResponse {
                success: false,
                can_read: false,
                can_write: false,
                default_branch: None,
                error_code: Some(error_code.into()),
                message: "GitHub connection test failed.".into(),
            }))
        }
    }
}

fn ensure_test_connection_permission(auth: &AuthContext) -> Result<(), ApiError> {
    ensure_permission(auth, permissions::DETECTION_CODE_TARGETS_MANAGE)
}

fn github_error_code(error: &GitHubWriteError) -> &'static str {
    match error {
        GitHubWriteError::Request(_) => "github_unavailable",
        GitHubWriteError::Api {
            status: 401 | 403, ..
        } => "authentication_failed",
        GitHubWriteError::Api { status: 404, .. } => "repository_not_found",
        GitHubWriteError::Api { status: 429, .. } => "github_rate_limited",
        GitHubWriteError::Api { .. } => "github_api_error",
        GitHubWriteError::NotGitHub(_)
        | GitHubWriteError::InvalidUrl(_)
        | GitHubWriteError::InvalidRef(_) => "invalid_repository",
        GitHubWriteError::BlockedEndpoint(_) => "egress_blocked",
        GitHubWriteError::RemoteConflict(_) => "repository_conflict",
    }
}

#[allow(clippy::too_many_arguments)]
fn emit_connection_test_audit(
    state: &AppState,
    auth: &AuthContext,
    client_context: &ClientContext,
    target_id: Uuid,
    target_name: Option<String>,
    success: bool,
    result: &str,
    can_read: bool,
    can_write: bool,
) {
    state.emit_audit(
        AuditEvent::builder(
            AuditSource::RuleRepo,
            DETECTION_CODE_TARGET_CONNECTION_TESTED,
        )
        .actor(Some(auth.user_id()), None)
        .api_key(auth.api_key_id, auth.api_key_name.clone())
        .resource("detection_code_target", Some(target_id), target_name)
        .client_context(client_context)
        .success(success)
        .details(serde_json::json!({
            "result": result,
            "can_read": can_read,
            "can_write": can_write,
        }))
        .build(),
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use nanosiem_core::auth::api_key::ApiKeyInfo;
    use nanosiem_core::auth::token::{DEFAULT_TOKEN_AUDIENCE, DEFAULT_TOKEN_ISSUER};
    use nanosiem_core::auth::TokenClaims;

    fn session(permissions: &[&str]) -> AuthContext {
        AuthContext::from_jwt(TokenClaims {
            iss: DEFAULT_TOKEN_ISSUER.to_string(),
            aud: DEFAULT_TOKEN_AUDIENCE.to_string(),
            sub: Uuid::now_v7(),
            roles: Vec::new(),
            permissions: permissions.iter().map(ToString::to_string).collect(),
            exp: chrono::Utc::now().timestamp() + 60,
            iat: chrono::Utc::now().timestamp(),
            jti: Uuid::now_v7(),
            purpose: "access".to_string(),
        })
    }

    fn api_key(permissions: &[&str]) -> AuthContext {
        AuthContext::from_api_key(&ApiKeyInfo {
            id: Uuid::now_v7(),
            name: "connection-probe".to_string(),
            permissions: permissions.iter().map(ToString::to_string).collect(),
            user_id: Some(Uuid::now_v7()),
        })
    }

    #[test]
    fn connection_test_requires_manage_for_sessions_and_api_keys() {
        for auth in [
            session(&[]),
            session(&[permissions::DETECTION_CODE_TARGETS_VIEW]),
            api_key(&[]),
            api_key(&[permissions::DETECTION_CODE_TARGETS_VIEW]),
        ] {
            assert!(matches!(
                ensure_test_connection_permission(&auth),
                Err(ApiError::Forbidden(_))
            ));
        }

        for auth in [
            session(&[permissions::DETECTION_CODE_TARGETS_MANAGE]),
            api_key(&[permissions::DETECTION_CODE_TARGETS_MANAGE]),
        ] {
            assert!(ensure_test_connection_permission(&auth).is_ok());
        }
    }

    #[test]
    fn provider_errors_are_reduced_to_stable_non_secret_classes() {
        assert_eq!(
            github_error_code(&GitHubWriteError::Api {
                status: 401,
                message: "token ghp_secret was rejected".to_string(),
            }),
            "authentication_failed"
        );
        assert_eq!(
            github_error_code(&GitHubWriteError::Api {
                status: 404,
                message: "private/repository".to_string(),
            }),
            "repository_not_found"
        );
        assert_eq!(
            github_error_code(&GitHubWriteError::InvalidUrl(
                "https://example.invalid/private".to_string(),
            )),
            "invalid_repository"
        );
    }
}
