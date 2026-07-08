// SPDX-License-Identifier: AGPL-3.0-or-later

//! Token management + connectivity probe for push targets.

use axum::{
    extract::{Path, State},
    Extension, Json,
};
use nanosiem_core::audit::{AuditEvent, AuditSource, ClientContext, DETECTION_CODE_TARGET_TOKEN_SET};
use nanosiem_core::auth::permissions;
use nanosiem_core::detection_code_target::{DetectionCodeTarget, GitHubWriteClient};
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
    ),
    security(("api_key" = []))
)]
pub async fn test_connection(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<Uuid>,
) -> Result<Json<TestConnectionResponse>, ApiError> {
    ensure_permission(&auth, permissions::DETECTION_CODE_TARGETS_VIEW)?;

    let repo = get_target_repo(&state);
    let target = repo.get(id).await.map_err(map_target_err)?;
    let token = repo.get_decrypted_token(id).await.map_err(map_target_err)?;

    let Some(token) = token else {
        return Ok(Json(TestConnectionResponse {
            success: false,
            can_read: false,
            can_write: false,
            default_branch: None,
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
            Ok(Json(TestConnectionResponse {
                success,
                can_read: access.can_read,
                can_write: access.can_write,
                default_branch: access.default_branch,
                message,
            }))
        }
        Err(e) => Ok(Json(TestConnectionResponse {
            success: false,
            can_read: false,
            can_write: false,
            default_branch: None,
            message: format!("GitHub error: {e}"),
        })),
    }
}
