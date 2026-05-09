// SPDX-License-Identifier: AGPL-3.0-or-later

//! Prevalence settings handlers — configuration management

use axum::http::StatusCode;
use axum::{extract::State, Extension, Json};
use serde::{Deserialize, Serialize};
use tracing::error;

use crate::middleware::{check_permission, AuthContext};
use crate::state::AppState;
use nanosiem_core::auth::permissions;
use nanosiem_core::prevalence::{PrevalenceConfig, PrevalenceSettings, PrevalenceSettingsError};

/// Response for prevalence settings
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct PrevalenceSettingsResponse {
    /// Number of hosts below which an artifact is considered "rare"
    pub rarity_threshold: u64,
    /// Whether hash tracking is enabled
    pub enable_hash_tracking: bool,
    /// Whether domain tracking is enabled
    pub enable_domain_tracking: bool,
    /// Number of days to retain prevalence data
    pub retention_days: u32,
    /// Cache TTL in seconds
    pub cache_ttl_seconds: u64,
}

impl From<PrevalenceConfig> for PrevalenceSettingsResponse {
    fn from(config: PrevalenceConfig) -> Self {
        Self {
            rarity_threshold: config.rarity_threshold,
            enable_hash_tracking: config.enable_hash_tracking,
            enable_domain_tracking: config.enable_domain_tracking,
            retention_days: config.retention_days,
            cache_ttl_seconds: config.cache_ttl_seconds,
        }
    }
}

/// Request to update prevalence settings
#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct UpdatePrevalenceSettingsRequest {
    /// Number of hosts below which an artifact is considered "rare" (1-1000)
    pub rarity_threshold: Option<u64>,
    /// Whether to enable hash tracking
    pub enable_hash_tracking: Option<bool>,
    /// Whether to enable domain tracking
    pub enable_domain_tracking: Option<bool>,
    /// Number of days to retain prevalence data (1-365)
    pub retention_days: Option<u32>,
    /// Cache TTL in seconds (0-3600)
    pub cache_ttl_seconds: Option<u64>,
}

/// Convert PrevalenceSettingsError to HTTP response
pub(super) fn prevalence_settings_error_to_response(
    err: PrevalenceSettingsError,
) -> (StatusCode, String) {
    match &err {
        PrevalenceSettingsError::InvalidRarityThreshold(_)
        | PrevalenceSettingsError::InvalidRetentionDays(_)
        | PrevalenceSettingsError::InvalidCacheTtl(_) => (StatusCode::BAD_REQUEST, err.to_string()),
        PrevalenceSettingsError::Database(_) => {
            error!("Database error in prevalence settings: {}", err);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Database error".to_string(),
            )
        }
    }
}

/// GET /api/settings/prevalence
///
/// Get current prevalence tracking settings.
/// Requirements: 8.1, 8.2, 8.3, 8.4
#[utoipa::path(
    get,
    path = "/api/settings/prevalence",
    tag = "prevalence",
    responses(
        (status = 200, description = "Current prevalence settings", body = PrevalenceSettingsResponse),
        (status = 403, description = "Forbidden - Missing permission: prevalence:configure"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn get_prevalence_settings(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
) -> Result<Json<PrevalenceSettingsResponse>, (StatusCode, String)> {
    check_permission(&auth, permissions::PREVALENCE_CONFIGURE).map_err(|_| {
        (
            StatusCode::FORBIDDEN,
            "Missing permission: prevalence:configure".to_string(),
        )
    })?;

    let settings = PrevalenceSettings::new(state.pool.clone());
    let config = settings
        .get_config()
        .await
        .map_err(prevalence_settings_error_to_response)?;

    Ok(Json(PrevalenceSettingsResponse::from(config)))
}

/// PUT /api/settings/prevalence
///
/// Update prevalence tracking settings.
/// Only provided fields are updated.
/// Changes are applied immediately without restart (hot-reload).
/// Requirements: 8.1, 8.2, 8.3, 8.4, 8.5
#[utoipa::path(
    put,
    path = "/api/settings/prevalence",
    tag = "prevalence",
    request_body = UpdatePrevalenceSettingsRequest,
    responses(
        (status = 200, description = "Updated prevalence settings", body = PrevalenceSettingsResponse),
        (status = 400, description = "Bad request - Invalid settings"),
        (status = 403, description = "Forbidden - Missing permission: prevalence:configure"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn update_prevalence_settings(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Json(request): Json<UpdatePrevalenceSettingsRequest>,
) -> Result<Json<PrevalenceSettingsResponse>, (StatusCode, String)> {
    check_permission(&auth, permissions::PREVALENCE_CONFIGURE).map_err(|_| {
        (
            StatusCode::FORBIDDEN,
            "Missing permission: prevalence:configure".to_string(),
        )
    })?;

    let settings = PrevalenceSettings::new(state.pool.clone());

    // Get current config
    let mut config = settings
        .get_config()
        .await
        .map_err(prevalence_settings_error_to_response)?;

    // Apply updates
    if let Some(rarity_threshold) = request.rarity_threshold {
        config.rarity_threshold = rarity_threshold;
    }
    if let Some(enable_hash_tracking) = request.enable_hash_tracking {
        config.enable_hash_tracking = enable_hash_tracking;
    }
    if let Some(enable_domain_tracking) = request.enable_domain_tracking {
        config.enable_domain_tracking = enable_domain_tracking;
    }
    if let Some(retention_days) = request.retention_days {
        config.retention_days = retention_days;
    }
    if let Some(cache_ttl_seconds) = request.cache_ttl_seconds {
        config.cache_ttl_seconds = cache_ttl_seconds;
    }

    // Save updated config
    let updated = settings
        .update_config(config)
        .await
        .map_err(prevalence_settings_error_to_response)?;

    // Hot-reload: Update the prevalence service config if it exists
    // The PrevalenceService will pick up the new config on next request
    // since it reads from the database through PrevalenceSettings
    // Requirement: 8.5

    Ok(Json(PrevalenceSettingsResponse::from(updated)))
}
