// SPDX-License-Identifier: AGPL-3.0-or-later

//! Organizational context, health monitoring, developer settings, and search admission handlers

use axum::{extract::State, Extension, Json};
use nanosiem_core::audit::{
    AuditEvent, AuditSource, ClientContext, DEVELOPER_SETTINGS_UPDATED, HEALTH_MONITORING_UPDATED,
    ORG_CONTEXT_UPDATED, SEARCH_SETTINGS_UPDATED,
};
use nanosiem_core::auth::permissions;
use nanosiem_core::settings::{
    OrganizationalContext, OrganizationalContextService, UpdateOrganizationalContextRequest,
};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::error::{ApiError, ErrorResponse};
use crate::handlers::AuditExt;
use crate::middleware::{ensure_permission, AuthContext};
use crate::state::AppState;

// ============================================================================
// Organizational Context Types
// ============================================================================

/// Response for organizational context configuration
#[derive(Debug, Serialize, ToSchema)]
pub struct OrganizationalContextResponse {
    pub organization_name: Option<String>,
    pub industry: Option<String>,
    pub environment: Option<String>,
    pub attack_vectors: Option<String>,
    pub compliance_frameworks: Vec<String>,
    pub custom_context: Option<String>,
    pub enable_for_chat: bool,
    pub enable_for_query: bool,
    pub enable_for_detection: bool,
    pub enable_for_parser: bool,
    pub enable_for_dashboard: bool,
}

impl From<OrganizationalContext> for OrganizationalContextResponse {
    fn from(ctx: OrganizationalContext) -> Self {
        Self {
            organization_name: ctx.organization_name,
            industry: ctx.industry,
            environment: ctx.environment,
            attack_vectors: ctx.attack_vectors,
            compliance_frameworks: ctx.compliance_frameworks,
            custom_context: ctx.custom_context,
            enable_for_chat: ctx.enable_for_chat,
            enable_for_query: ctx.enable_for_query,
            enable_for_detection: ctx.enable_for_detection,
            enable_for_parser: ctx.enable_for_parser,
            enable_for_dashboard: ctx.enable_for_dashboard,
        }
    }
}

/// Request to update organizational context
#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateOrganizationalContextApiRequest {
    pub organization_name: Option<String>,
    pub industry: Option<String>,
    pub environment: Option<String>,
    pub attack_vectors: Option<String>,
    pub compliance_frameworks: Option<Vec<String>>,
    pub custom_context: Option<String>,
    pub enable_for_chat: Option<bool>,
    pub enable_for_query: Option<bool>,
    pub enable_for_detection: Option<bool>,
    pub enable_for_parser: Option<bool>,
    pub enable_for_dashboard: Option<bool>,
}

// Note: `From<OrganizationalContextError> for ApiError` lifted to
// nanosiem-api-lib in NAN-752 (orphan rule — `ApiError` lives there now).

// ============================================================================
// Health Monitoring Types
// ============================================================================

/// Response for health monitoring settings (split into AI and feed monitoring)
#[derive(Debug, Serialize, ToSchema)]
pub struct HealthMonitoringSettingsResponse {
    /// AI provider monitoring (costs API credits to check)
    pub ai_monitoring_enabled: bool,
    /// Feed staleness monitoring (free - just DB queries)
    pub feed_monitoring_enabled: bool,
    /// Legacy field for backwards compatibility (returns ai_monitoring_enabled)
    pub enabled: bool,
}

/// Request to update health monitoring settings
#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateHealthMonitoringSettingsRequest {
    /// Legacy field - if provided alone, updates ai_monitoring_enabled
    #[serde(default)]
    pub enabled: Option<bool>,
    /// AI provider monitoring (costs API credits)
    #[serde(default)]
    pub ai_monitoring_enabled: Option<bool>,
    /// Feed staleness monitoring (free)
    #[serde(default)]
    pub feed_monitoring_enabled: Option<bool>,
}

// ============================================================================
// Developer Settings Types
// ============================================================================

/// Response for developer settings (scheduler enable/disable)
#[derive(Debug, Serialize, ToSchema)]
pub struct DeveloperSettingsResponse {
    /// Detection scheduler (5s interval, queries ClickHouse for rule execution)
    pub detection_scheduler_enabled: bool,
    /// Tuning scheduler (metrics, baselines, thresholds - queries ClickHouse)
    pub tuning_scheduler_enabled: bool,
    /// Enrichment auto-sync scheduler (may query ClickHouse for cleanup)
    pub enrichment_sync_scheduler_enabled: bool,
    /// Custom enrichment scheduler (INSERT/SELECT for enrichments)
    pub custom_enrichment_scheduler_enabled: bool,
    /// AI provider monitoring (costs API credits)
    pub ai_monitoring_enabled: bool,
    /// Feed staleness monitoring (queries ClickHouse)
    pub feed_monitoring_enabled: bool,
    /// Model catalog auto-sync scheduler (daily GitHub sync + deprecated model notifications)
    pub model_catalog_sync_scheduler_enabled: bool,
}

/// Request to update developer settings (partial updates supported)
#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateDeveloperSettingsRequest {
    #[serde(default)]
    pub detection_scheduler_enabled: Option<bool>,
    #[serde(default)]
    pub tuning_scheduler_enabled: Option<bool>,
    #[serde(default)]
    pub enrichment_sync_scheduler_enabled: Option<bool>,
    #[serde(default)]
    pub custom_enrichment_scheduler_enabled: Option<bool>,
    #[serde(default)]
    pub ai_monitoring_enabled: Option<bool>,
    #[serde(default)]
    pub feed_monitoring_enabled: Option<bool>,
    #[serde(default)]
    pub model_catalog_sync_scheduler_enabled: Option<bool>,
}

// ============================================================================
// Organizational Context Handlers
// ============================================================================

/// Get organizational context configuration
///
/// GET /api/settings/organizational-context
///
/// Returns the current organizational context that is injected into AI prompts.
#[utoipa::path(
    get,
    path = "/api/settings/organizational-context",
    tag = "settings",
    responses(
        (status = 200, description = "Organizational context", body = OrganizationalContextResponse),
        (status = 403, description = "Missing permission", body = ErrorResponse),
        (status = 500, description = "Internal error", body = ErrorResponse)
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn get_organizational_context(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
) -> Result<Json<OrganizationalContextResponse>, ApiError> {
    ensure_permission(&auth, permissions::SETTINGS_AI)?;

    let service = OrganizationalContextService::new(state.pool.clone());
    let context = service.get_context().await?;

    Ok(Json(OrganizationalContextResponse::from(context)))
}

/// Update organizational context configuration
///
/// PUT /api/settings/organizational-context
///
/// Updates the organizational context that is injected into AI prompts.
/// Only provided fields are updated.
#[utoipa::path(
    put,
    path = "/api/settings/organizational-context",
    tag = "settings",
    request_body = UpdateOrganizationalContextApiRequest,
    responses(
        (status = 200, description = "Context updated", body = OrganizationalContextResponse),
        (status = 403, description = "Missing permission", body = ErrorResponse),
        (status = 500, description = "Internal error", body = ErrorResponse)
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn update_organizational_context(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Extension(client): Extension<ClientContext>,
    Json(request): Json<UpdateOrganizationalContextApiRequest>,
) -> Result<Json<OrganizationalContextResponse>, ApiError> {
    ensure_permission(&auth, permissions::SETTINGS_AI)?;

    let service = OrganizationalContextService::new(state.pool.clone());

    let update_request = UpdateOrganizationalContextRequest {
        organization_name: request.organization_name,
        industry: request.industry,
        environment: request.environment,
        attack_vectors: request.attack_vectors,
        compliance_frameworks: request.compliance_frameworks,
        custom_context: request.custom_context,
        enable_for_chat: request.enable_for_chat,
        enable_for_query: request.enable_for_query,
        enable_for_detection: request.enable_for_detection,
        enable_for_parser: request.enable_for_parser,
        enable_for_dashboard: request.enable_for_dashboard,
    };

    let context = service.update_context(update_request).await?;

    tracing::info!(
        org = ?context.organization_name,
        industry = ?context.industry,
        "Organizational context updated"
    );

    state.emit_audit(
        AuditEvent::builder(AuditSource::Settings, ORG_CONTEXT_UPDATED)
            .actor(Some(auth.user_id()), None)
            .api_key(auth.api_key_id, auth.api_key_name.clone())
            .resource("settings", None, Some("organizational_context".to_string()))
            .client_context(&client)
            .build(),
    );

    Ok(Json(OrganizationalContextResponse::from(context)))
}

// ============================================================================
// Health Monitoring Handlers
// ============================================================================

/// Get health monitoring settings
///
/// GET /api/settings/health-monitoring
#[utoipa::path(
    get,
    path = "/api/settings/health-monitoring",
    tag = "settings",
    responses(
        (status = 200, description = "Health monitoring settings", body = HealthMonitoringSettingsResponse),
        (status = 403, description = "Missing permission", body = ErrorResponse),
        (status = 500, description = "Internal error", body = ErrorResponse)
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn get_health_monitoring_settings(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
) -> Result<Json<HealthMonitoringSettingsResponse>, ApiError> {
    ensure_permission(&auth, permissions::SETTINGS_SYSTEM)?;

    let row = sqlx::query(
        "SELECT COALESCE(ai_monitoring_enabled, false) as ai_enabled, \
         COALESCE(feed_monitoring_enabled, true) as feed_enabled \
         FROM system_settings WHERE id = 'default'",
    )
    .fetch_optional(&state.pool)
    .await
    .map_err(|e| ApiError::DatabaseError(e.to_string()))?;

    let (ai_enabled, feed_enabled) = match row {
        Some(r) => {
            use sqlx::Row;
            (
                r.get::<bool, _>("ai_enabled"),
                r.get::<bool, _>("feed_enabled"),
            )
        }
        None => (false, true),
    };

    Ok(Json(HealthMonitoringSettingsResponse {
        ai_monitoring_enabled: ai_enabled,
        feed_monitoring_enabled: feed_enabled,
        enabled: ai_enabled, // Legacy compatibility
    }))
}

/// Update health monitoring settings
///
/// PUT /api/settings/health-monitoring
#[utoipa::path(
    put,
    path = "/api/settings/health-monitoring",
    tag = "settings",
    request_body = UpdateHealthMonitoringSettingsRequest,
    responses(
        (status = 200, description = "Settings updated", body = HealthMonitoringSettingsResponse),
        (status = 403, description = "Missing permission", body = ErrorResponse),
        (status = 500, description = "Internal error", body = ErrorResponse)
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn update_health_monitoring_settings(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Extension(client): Extension<ClientContext>,
    Json(request): Json<UpdateHealthMonitoringSettingsRequest>,
) -> Result<Json<HealthMonitoringSettingsResponse>, ApiError> {
    ensure_permission(&auth, permissions::SETTINGS_SYSTEM)?;

    // Handle legacy 'enabled' field - maps to ai_monitoring_enabled
    let ai_enabled = request.ai_monitoring_enabled.or(request.enabled);
    let feed_enabled = request.feed_monitoring_enabled;

    // Update AI monitoring if provided
    if let Some(ai) = ai_enabled {
        sqlx::query(
            "UPDATE system_settings SET ai_monitoring_enabled = $1, updated_at = NOW() WHERE id = 'default'"
        )
        .bind(ai)
        .execute(&state.pool)
        .await
        .map_err(|e| ApiError::DatabaseError(e.to_string()))?;

        tracing::info!(
            "AI monitoring {} by user",
            if ai { "enabled" } else { "disabled" }
        );
    }

    // Update feed monitoring if provided
    if let Some(feed) = feed_enabled {
        sqlx::query(
            "UPDATE system_settings SET feed_monitoring_enabled = $1, updated_at = NOW() WHERE id = 'default'"
        )
        .bind(feed)
        .execute(&state.pool)
        .await
        .map_err(|e| ApiError::DatabaseError(e.to_string()))?;

        tracing::info!(
            "Feed monitoring {} by user",
            if feed { "enabled" } else { "disabled" }
        );
    }

    // Fetch current state to return
    let row = sqlx::query(
        "SELECT COALESCE(ai_monitoring_enabled, false) as ai_enabled, \
         COALESCE(feed_monitoring_enabled, true) as feed_enabled \
         FROM system_settings WHERE id = 'default'",
    )
    .fetch_optional(&state.pool)
    .await
    .map_err(|e| ApiError::DatabaseError(e.to_string()))?;

    let (ai_result, feed_result) = match row {
        Some(r) => {
            use sqlx::Row;
            (
                r.get::<bool, _>("ai_enabled"),
                r.get::<bool, _>("feed_enabled"),
            )
        }
        None => (true, true),
    };

    state.emit_audit(
        AuditEvent::builder(AuditSource::Settings, HEALTH_MONITORING_UPDATED)
            .actor(Some(auth.user_id()), None)
            .api_key(auth.api_key_id, auth.api_key_name.clone())
            .resource("settings", None, Some("health_monitoring".to_string()))
            .client_context(&client)
            .build(),
    );

    Ok(Json(HealthMonitoringSettingsResponse {
        ai_monitoring_enabled: ai_result,
        feed_monitoring_enabled: feed_result,
        enabled: ai_result, // Legacy compatibility
    }))
}

// ============================================================================
// Developer Settings Handlers
// ============================================================================

/// Get developer settings (scheduler control)
///
/// GET /api/settings/developer
#[utoipa::path(
    get,
    path = "/api/settings/developer",
    tag = "settings",
    responses(
        (status = 200, description = "Developer settings", body = DeveloperSettingsResponse),
        (status = 403, description = "Missing permission", body = ErrorResponse),
        (status = 500, description = "Internal error", body = ErrorResponse)
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn get_developer_settings(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
) -> Result<Json<DeveloperSettingsResponse>, ApiError> {
    ensure_permission(&auth, permissions::SETTINGS_SYSTEM)?;

    let row = sqlx::query(
        r#"
        SELECT
            COALESCE(detection_scheduler_enabled, true) as detection,
            COALESCE(tuning_scheduler_enabled, true) as tuning,
            COALESCE(enrichment_sync_scheduler_enabled, true) as enrichment,
            COALESCE(custom_enrichment_scheduler_enabled, true) as custom,
            COALESCE(ai_monitoring_enabled, false) as ai,
            COALESCE(feed_monitoring_enabled, true) as feed,
            COALESCE(model_catalog_sync_scheduler_enabled, true) as model_catalog
        FROM system_settings
        WHERE id = 'default'
        "#,
    )
    .fetch_optional(&state.pool)
    .await
    .map_err(|e| ApiError::DatabaseError(e.to_string()))?;

    let (detection, tuning, enrichment, custom, ai, feed, model_catalog) = match row {
        Some(r) => {
            use sqlx::Row;
            (
                r.get::<bool, _>("detection"),
                r.get::<bool, _>("tuning"),
                r.get::<bool, _>("enrichment"),
                r.get::<bool, _>("custom"),
                r.get::<bool, _>("ai"),
                r.get::<bool, _>("feed"),
                r.get::<bool, _>("model_catalog"),
            )
        }
        None => (true, true, true, true, false, true, true),
    };

    Ok(Json(DeveloperSettingsResponse {
        detection_scheduler_enabled: detection,
        tuning_scheduler_enabled: tuning,
        enrichment_sync_scheduler_enabled: enrichment,
        custom_enrichment_scheduler_enabled: custom,
        ai_monitoring_enabled: ai,
        feed_monitoring_enabled: feed,
        model_catalog_sync_scheduler_enabled: model_catalog,
    }))
}

/// Update developer settings (scheduler control)
///
/// PUT /api/settings/developer
#[utoipa::path(
    put,
    path = "/api/settings/developer",
    tag = "settings",
    request_body = UpdateDeveloperSettingsRequest,
    responses(
        (status = 200, description = "Settings updated", body = DeveloperSettingsResponse),
        (status = 403, description = "Missing permission", body = ErrorResponse),
        (status = 500, description = "Internal error", body = ErrorResponse)
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn update_developer_settings(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Extension(client): Extension<ClientContext>,
    Json(request): Json<UpdateDeveloperSettingsRequest>,
) -> Result<Json<DeveloperSettingsResponse>, ApiError> {
    ensure_permission(&auth, permissions::SETTINGS_SYSTEM)?;

    // Update each field if provided
    if let Some(enabled) = request.detection_scheduler_enabled {
        sqlx::query(
            "UPDATE system_settings SET detection_scheduler_enabled = $1, updated_at = NOW() WHERE id = 'default'"
        )
        .bind(enabled)
        .execute(&state.pool)
        .await
        .map_err(|e| ApiError::DatabaseError(e.to_string()))?;

        tracing::info!(
            "Detection scheduler {} by user {}",
            if enabled { "enabled" } else { "disabled" },
            auth.user_id()
        );
    }

    if let Some(enabled) = request.tuning_scheduler_enabled {
        sqlx::query(
            "UPDATE system_settings SET tuning_scheduler_enabled = $1, updated_at = NOW() WHERE id = 'default'"
        )
        .bind(enabled)
        .execute(&state.pool)
        .await
        .map_err(|e| ApiError::DatabaseError(e.to_string()))?;

        tracing::info!(
            "Tuning scheduler {} by user {}",
            if enabled { "enabled" } else { "disabled" },
            auth.user_id()
        );
    }

    if let Some(enabled) = request.enrichment_sync_scheduler_enabled {
        sqlx::query(
            "UPDATE system_settings SET enrichment_sync_scheduler_enabled = $1, updated_at = NOW() WHERE id = 'default'"
        )
        .bind(enabled)
        .execute(&state.pool)
        .await
        .map_err(|e| ApiError::DatabaseError(e.to_string()))?;

        tracing::info!(
            "Enrichment sync scheduler {} by user {}",
            if enabled { "enabled" } else { "disabled" },
            auth.user_id()
        );
    }

    if let Some(enabled) = request.custom_enrichment_scheduler_enabled {
        sqlx::query(
            "UPDATE system_settings SET custom_enrichment_scheduler_enabled = $1, updated_at = NOW() WHERE id = 'default'"
        )
        .bind(enabled)
        .execute(&state.pool)
        .await
        .map_err(|e| ApiError::DatabaseError(e.to_string()))?;

        tracing::info!(
            "Custom enrichment scheduler {} by user {}",
            if enabled { "enabled" } else { "disabled" },
            auth.user_id()
        );
    }

    if let Some(enabled) = request.ai_monitoring_enabled {
        sqlx::query(
            "UPDATE system_settings SET ai_monitoring_enabled = $1, updated_at = NOW() WHERE id = 'default'"
        )
        .bind(enabled)
        .execute(&state.pool)
        .await
        .map_err(|e| ApiError::DatabaseError(e.to_string()))?;

        tracing::info!(
            "AI monitoring {} by user {}",
            if enabled { "enabled" } else { "disabled" },
            auth.user_id()
        );
    }

    if let Some(enabled) = request.feed_monitoring_enabled {
        sqlx::query(
            "UPDATE system_settings SET feed_monitoring_enabled = $1, updated_at = NOW() WHERE id = 'default'"
        )
        .bind(enabled)
        .execute(&state.pool)
        .await
        .map_err(|e| ApiError::DatabaseError(e.to_string()))?;

        tracing::info!(
            "Feed monitoring {} by user {}",
            if enabled { "enabled" } else { "disabled" },
            auth.user_id()
        );
    }

    if let Some(enabled) = request.model_catalog_sync_scheduler_enabled {
        sqlx::query(
            "UPDATE system_settings SET model_catalog_sync_scheduler_enabled = $1, updated_at = NOW() WHERE id = 'default'"
        )
        .bind(enabled)
        .execute(&state.pool)
        .await
        .map_err(|e| ApiError::DatabaseError(e.to_string()))?;

        tracing::info!(
            "Model catalog sync scheduler {} by user {}",
            if enabled { "enabled" } else { "disabled" },
            auth.user_id()
        );
    }

    // Fetch current state to return
    let row = sqlx::query(
        r#"
        SELECT
            COALESCE(detection_scheduler_enabled, true) as detection,
            COALESCE(tuning_scheduler_enabled, true) as tuning,
            COALESCE(enrichment_sync_scheduler_enabled, true) as enrichment,
            COALESCE(custom_enrichment_scheduler_enabled, true) as custom,
            COALESCE(ai_monitoring_enabled, false) as ai,
            COALESCE(feed_monitoring_enabled, true) as feed,
            COALESCE(model_catalog_sync_scheduler_enabled, true) as model_catalog
        FROM system_settings
        WHERE id = 'default'
        "#,
    )
    .fetch_optional(&state.pool)
    .await
    .map_err(|e| ApiError::DatabaseError(e.to_string()))?;

    let (detection, tuning, enrichment, custom, ai, feed, model_catalog) = match row {
        Some(r) => {
            use sqlx::Row;
            (
                r.get::<bool, _>("detection"),
                r.get::<bool, _>("tuning"),
                r.get::<bool, _>("enrichment"),
                r.get::<bool, _>("custom"),
                r.get::<bool, _>("ai"),
                r.get::<bool, _>("feed"),
                r.get::<bool, _>("model_catalog"),
            )
        }
        None => (true, true, true, true, false, true, true),
    };

    state.emit_audit(
        AuditEvent::builder(AuditSource::Settings, DEVELOPER_SETTINGS_UPDATED)
            .actor(Some(auth.user_id()), None)
            .api_key(auth.api_key_id, auth.api_key_name.clone())
            .resource("settings", None, Some("developer".to_string()))
            .client_context(&client)
            .build(),
    );

    Ok(Json(DeveloperSettingsResponse {
        detection_scheduler_enabled: detection,
        tuning_scheduler_enabled: tuning,
        enrichment_sync_scheduler_enabled: enrichment,
        custom_enrichment_scheduler_enabled: custom,
        ai_monitoring_enabled: ai,
        feed_monitoring_enabled: feed,
        model_catalog_sync_scheduler_enabled: model_catalog,
    }))
}

// ============================================================================
// Search Admission Handlers
// ============================================================================

/// Get search admission control settings
///
/// GET /api/settings/search
#[utoipa::path(
    get,
    path = "/api/settings/search",
    tag = "settings",
    responses(
        (status = 200, description = "Search admission settings", body = nanosiem_core::settings::SearchAdmissionConfig),
        (status = 403, description = "Missing permission", body = ErrorResponse),
        (status = 500, description = "Internal error", body = ErrorResponse)
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn get_search_admission_settings(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
) -> Result<Json<nanosiem_core::settings::SearchAdmissionConfig>, ApiError> {
    ensure_permission(&auth, permissions::SETTINGS_SYSTEM)?;

    let settings = nanosiem_core::settings::SearchAdmissionSettings::new(state.pool.clone());
    let config = settings
        .get_config()
        .await
        .map_err(|e| ApiError::InternalError(e.to_string()))?;
    Ok(Json(config))
}

/// Update search admission control settings
///
/// PUT /api/settings/search
#[utoipa::path(
    put,
    path = "/api/settings/search",
    tag = "settings",
    request_body = nanosiem_core::settings::SearchAdmissionConfig,
    responses(
        (status = 200, description = "Updated search admission settings", body = nanosiem_core::settings::SearchAdmissionConfig),
        (status = 400, description = "Validation error", body = ErrorResponse),
        (status = 403, description = "Missing permission", body = ErrorResponse),
        (status = 500, description = "Internal error", body = ErrorResponse)
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn update_search_admission_settings(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Extension(client): Extension<ClientContext>,
    Json(config): Json<nanosiem_core::settings::SearchAdmissionConfig>,
) -> Result<Json<nanosiem_core::settings::SearchAdmissionConfig>, ApiError> {
    ensure_permission(&auth, permissions::SETTINGS_SYSTEM)?;

    let settings = nanosiem_core::settings::SearchAdmissionSettings::new(state.pool.clone());
    let updated = settings.update_config(config).await.map_err(|e| match e {
        nanosiem_core::settings::SearchAdmissionSettingsError::Validation(msg) => {
            ApiError::ValidationError(msg)
        }
        _ => ApiError::InternalError(e.to_string()),
    })?;

    state.emit_audit(
        AuditEvent::builder(AuditSource::Settings, SEARCH_SETTINGS_UPDATED)
            .actor(Some(auth.user_id()), None)
            .api_key(auth.api_key_id, auth.api_key_name.clone())
            .resource("settings", None, Some("search_admission".to_string()))
            .client_context(&client)
            .build(),
    );

    Ok(Json(updated))
}

// ============================================================================
// Search Query Safety Limits
// ============================================================================

/// Get search query safety limit settings
///
/// GET /api/settings/search/query-limits
#[utoipa::path(
    get,
    path = "/api/settings/search/query-limits",
    tag = "settings",
    responses(
        (status = 200, description = "Current search query limits", body = nanosiem_core::settings::SearchQueryLimitsConfig),
        (status = 403, description = "Missing permission", body = ErrorResponse),
        (status = 500, description = "Internal error", body = ErrorResponse)
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn get_search_query_limits(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
) -> Result<Json<nanosiem_core::settings::SearchQueryLimitsConfig>, ApiError> {
    ensure_permission(&auth, permissions::SETTINGS_SYSTEM)?;

    let settings = nanosiem_core::settings::SearchQueryLimitsSettings::new(state.pool.clone());
    let config = settings
        .get_config()
        .await
        .map_err(|e| ApiError::InternalError(e.to_string()))?;
    Ok(Json(config))
}

/// Update search query safety limit settings
///
/// PUT /api/settings/search/query-limits
#[utoipa::path(
    put,
    path = "/api/settings/search/query-limits",
    tag = "settings",
    request_body = nanosiem_core::settings::SearchQueryLimitsConfig,
    responses(
        (status = 200, description = "Updated search query limits", body = nanosiem_core::settings::SearchQueryLimitsConfig),
        (status = 400, description = "Validation error", body = ErrorResponse),
        (status = 403, description = "Missing permission", body = ErrorResponse),
        (status = 500, description = "Internal error", body = ErrorResponse)
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn update_search_query_limits(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Extension(client): Extension<ClientContext>,
    Json(config): Json<nanosiem_core::settings::SearchQueryLimitsConfig>,
) -> Result<Json<nanosiem_core::settings::SearchQueryLimitsConfig>, ApiError> {
    ensure_permission(&auth, permissions::SETTINGS_SYSTEM)?;

    let settings = nanosiem_core::settings::SearchQueryLimitsSettings::new(state.pool.clone());
    let updated = settings.update_config(config).await.map_err(|e| match e {
        nanosiem_core::settings::SearchQueryLimitsError::Validation(msg) => {
            ApiError::ValidationError(msg)
        }
        _ => ApiError::InternalError(e.to_string()),
    })?;

    state.emit_audit(
        AuditEvent::builder(AuditSource::Settings, SEARCH_SETTINGS_UPDATED)
            .actor(Some(auth.user_id()), None)
            .api_key(auth.api_key_id, auth.api_key_name.clone())
            .resource("settings", None, Some("search_query_limits".to_string()))
            .client_context(&client)
            .build(),
    );

    Ok(Json(updated))
}
