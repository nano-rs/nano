// SPDX-License-Identifier: AGPL-3.0-or-later

//! Folder Settings handlers (NAN-730)
//!
//! Per-folder display metadata (icon) for the rule-editor folder rail.
//! Folders themselves remain derived from `detection_rules.folder` strings —
//! this surface only stores presentation overrides keyed by folder name.
//!
//! Permission requirements:
//! * `detections:view` — read folder settings (anyone who can see rules
//!   needs to see their icons).
//! * `detections:edit` — set or clear an icon (mirrors rule-folder mutation
//!   perms; matches the perm gate on RuleRail's drag-drop / meta-row picker).

use std::collections::HashMap;

use axum::{
    extract::{Path, State},
    http::StatusCode,
    Extension, Json,
};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use nanosiem_core::audit::{
    AuditEvent, AuditSource, FOLDER_ICON_CLEARED, FOLDER_ICON_SET,
};
use nanosiem_core::auth::permissions;
use nanosiem_core::db::repository::{FolderSettingsError, FolderSettingsRepository};

use crate::handlers::AuditExt;
use crate::middleware::{check_permission, AuthContext};
use crate::state::AppState;
use crate::utils::{extract_client_ip, extract_user_agent};
use axum::http::HeaderMap;

/// Mirrors the backend folder-name validator at
/// nanosiem-core/src/models/detection_rule.rs:564 — alphanumeric + dash +
/// underscore, ≤ 50 chars. Must start with an alphanumeric to match the
/// frontend's create-time gate (NAN-729).
fn is_valid_folder_name(name: &str) -> bool {
    if name.is_empty() || name.len() > 50 {
        return false;
    }
    let mut chars = name.chars();
    let first = chars.next().unwrap();
    if !first.is_ascii_alphanumeric() {
        return false;
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
}

/// Curated set of icon slugs the frontend renders. Kept here as a defensive
/// allow-list so a future client bug or a tampered request can't smuggle
/// arbitrary text into the column. Mirrors `FOLDER_ICONS` slugs in
/// nanosiem-web/src/components/rule-editor/folder-icons.ts.
const ALLOWED_ICONS: &[&str] = &[
    "folder",
    "globe",
    "user",
    "box",
    "cloud",
    "shield",
    "bug",
    "lock",
    "key",
    "database",
    "server",
    "mail",
    "file-text",
    "code",
    "terminal",
    "eye",
    "target",
    "flag",
    "bookmark",
    "hash",
];

fn is_allowed_icon(icon: &str) -> bool {
    ALLOWED_ICONS.contains(&icon)
}

#[derive(Debug, Serialize, ToSchema)]
pub struct FolderSettingsApiError {
    pub error: String,
    pub message: String,
}

impl FolderSettingsApiError {
    fn new(error: &str, message: &str) -> Self {
        Self {
            error: error.to_string(),
            message: message.to_string(),
        }
    }

    fn from_repo_error(err: &FolderSettingsError) -> (StatusCode, Self) {
        match err {
            FolderSettingsError::Database(e) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                Self::new("database_error", &e.to_string()),
            ),
        }
    }
}

/// Whole-map response for `GET /api/folder-settings`.
#[derive(Debug, Serialize, ToSchema)]
pub struct FolderSettingsResponse {
    /// Map of folder name → icon slug. Folders without a row are absent.
    pub icons: HashMap<String, String>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct SetFolderIconRequest {
    pub icon: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct SetFolderIconResponse {
    pub name: String,
    pub icon: String,
}

/// List every folder's icon override. Returns the full map (small table —
/// one row per user-customized folder).
#[utoipa::path(
    get,
    path = "/api/folder-settings",
    tag = "folder_settings",
    responses(
        (status = 200, description = "Folder icon overrides", body = FolderSettingsResponse),
        (status = 403, description = "Missing permission: detections:view", body = FolderSettingsApiError),
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn list_folder_settings(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
) -> Result<Json<FolderSettingsResponse>, (StatusCode, Json<FolderSettingsApiError>)> {
    check_permission(&auth, permissions::DETECTIONS_VIEW).map_err(|_| {
        (
            StatusCode::FORBIDDEN,
            Json(FolderSettingsApiError::new(
                "forbidden",
                "Missing permission: detections:view",
            )),
        )
    })?;

    let repo = FolderSettingsRepository::new(state.pool.clone());
    let rows = repo.list().await.map_err(|e| {
        let (status, body) = FolderSettingsApiError::from_repo_error(&e);
        (status, Json(body))
    })?;

    let icons = rows.into_iter().map(|r| (r.name, r.icon)).collect();
    Ok(Json(FolderSettingsResponse { icons }))
}

/// Set or change a folder's icon. Upsert: creates the row if absent.
#[utoipa::path(
    put,
    path = "/api/folder-settings/{name}",
    tag = "folder_settings",
    params(("name" = String, Path, description = "Folder name (alphanumeric, dash, underscore, up to 50 chars)")),
    request_body = SetFolderIconRequest,
    responses(
        (status = 200, description = "Folder icon set", body = SetFolderIconResponse),
        (status = 400, description = "Invalid folder name or icon", body = FolderSettingsApiError),
        (status = 403, description = "Missing permission: detections:edit", body = FolderSettingsApiError),
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn set_folder_icon(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    headers: HeaderMap,
    axum::extract::ConnectInfo(addr): axum::extract::ConnectInfo<std::net::SocketAddr>,
    Path(name): Path<String>,
    Json(req): Json<SetFolderIconRequest>,
) -> Result<Json<SetFolderIconResponse>, (StatusCode, Json<FolderSettingsApiError>)> {
    check_permission(&auth, permissions::DETECTIONS_EDIT).map_err(|_| {
        (
            StatusCode::FORBIDDEN,
            Json(FolderSettingsApiError::new(
                "forbidden",
                "Missing permission: detections:edit",
            )),
        )
    })?;

    if !is_valid_folder_name(&name) {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(FolderSettingsApiError::new(
                "invalid_folder_name",
                "Folder name must be alphanumeric + dash + underscore, ≤ 50 chars, starting with alphanumeric",
            )),
        ));
    }

    if !is_allowed_icon(&req.icon) {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(FolderSettingsApiError::new(
                "invalid_icon",
                "Icon is not part of the allowed set",
            )),
        ));
    }

    let repo = FolderSettingsRepository::new(state.pool.clone());
    let row = repo.set_icon(&name, &req.icon).await.map_err(|e| {
        let (status, body) = FolderSettingsApiError::from_repo_error(&e);
        (status, Json(body))
    })?;

    let client = nanosiem_core::audit::ClientContext::new(
        extract_client_ip(&headers, Some(&addr)),
        extract_user_agent(&headers),
    );
    state.emit_audit(
        AuditEvent::builder(AuditSource::Detection, FOLDER_ICON_SET)
            .actor(Some(auth.user_id()), None)
            .api_key(auth.api_key_id, auth.api_key_name.clone())
            .resource("folder", None, Some(name.clone()))
            .client_context(&client)
            .details(serde_json::json!({ "icon": row.icon }))
            .build(),
    );

    Ok(Json(SetFolderIconResponse {
        name: row.name,
        icon: row.icon,
    }))
}

/// Clear a folder's icon override. Folder reverts to the frontend's default
/// icon mapping.
#[utoipa::path(
    delete,
    path = "/api/folder-settings/{name}",
    tag = "folder_settings",
    params(("name" = String, Path, description = "Folder name")),
    responses(
        (status = 204, description = "Folder icon cleared (or never set)"),
        (status = 403, description = "Missing permission: detections:edit", body = FolderSettingsApiError),
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn clear_folder_icon(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    headers: HeaderMap,
    axum::extract::ConnectInfo(addr): axum::extract::ConnectInfo<std::net::SocketAddr>,
    Path(name): Path<String>,
) -> Result<StatusCode, (StatusCode, Json<FolderSettingsApiError>)> {
    check_permission(&auth, permissions::DETECTIONS_EDIT).map_err(|_| {
        (
            StatusCode::FORBIDDEN,
            Json(FolderSettingsApiError::new(
                "forbidden",
                "Missing permission: detections:edit",
            )),
        )
    })?;

    let repo = FolderSettingsRepository::new(state.pool.clone());
    let removed = repo.delete(&name).await.map_err(|e| {
        let (status, body) = FolderSettingsApiError::from_repo_error(&e);
        (status, Json(body))
    })?;

    if removed {
        let client = nanosiem_core::audit::ClientContext::new(
            extract_client_ip(&headers, Some(&addr)),
            extract_user_agent(&headers),
        );
        state.emit_audit(
            AuditEvent::builder(AuditSource::Detection, FOLDER_ICON_CLEARED)
                .actor(Some(auth.user_id()), None)
                .api_key(auth.api_key_id, auth.api_key_name.clone())
                .resource("folder", None, Some(name))
                .client_context(&client)
                .build(),
        );
    }

    Ok(StatusCode::NO_CONTENT)
}

#[derive(utoipa::OpenApi)]
#[openapi(
    paths(list_folder_settings, set_folder_icon, clear_folder_icon),
    components(schemas(
        FolderSettingsApiError,
        FolderSettingsResponse,
        SetFolderIconRequest,
        SetFolderIconResponse,
    ))
)]
pub struct FolderSettingsApiDoc;
