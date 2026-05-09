// SPDX-License-Identifier: AGPL-3.0-or-later

//! Organization tier and usage handlers

use axum::{extract::State, Extension, Json};
use nanosiem_core::audit::{AuditEvent, AuditSource, ClientContext};
use nanosiem_core::auth::permissions;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::error::{ApiError, ErrorResponse};
use crate::handlers::AuditExt;
use crate::middleware::{check_permission, AuthContext};
use crate::state::AppState;

// ============================================================================
// Request/Response Types
// ============================================================================

/// Response for tier status (limits + current usage + proactive warnings)
#[derive(Debug, Serialize, ToSchema)]
pub struct TierStatusResponse {
    pub limits: nanosiem_core::TierLimits,
    pub usage: TierUsageResponse,
    /// AI usage for the current billing period
    pub ai_usage: nanosiem_core::AiUsage,
    /// Proactive warnings when resources are at 80%+ of tier limits
    pub warnings: Vec<nanosiem_core::TierWarning>,
}

/// Current usage counts
#[derive(Debug, Serialize, ToSchema)]
pub struct TierUsageResponse {
    pub data_sources: u32,
    pub detection_rules: u32,
    pub team_members: u32,
    pub today: nanosiem_core::DailyUsage,
}

/// Request to set the organization tier
#[derive(Debug, Deserialize, ToSchema)]
pub struct SetTierRequest {
    /// Tier name: unrestricted, hobby, startup, growth, team, starter, pro, enterprise
    pub tier: String,
}

/// Query params for usage history
#[derive(Debug, Deserialize, utoipa::IntoParams)]
pub struct UsageRangeQuery {
    /// Start date (YYYY-MM-DD), defaults to 30 days ago
    pub from: Option<chrono::NaiveDate>,
    /// End date (YYYY-MM-DD), defaults to today
    pub to: Option<chrono::NaiveDate>,
}

// ============================================================================
// Handler Functions
// ============================================================================

/// Get current organization tier, limits, and usage
#[utoipa::path(
    get,
    path = "/api/settings/tier",
    tag = "settings",
    responses(
        (status = 200, body = TierStatusResponse),
        (status = 403, body = ErrorResponse),
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn get_tier_status(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
) -> Result<Json<TierStatusResponse>, ApiError> {
    check_permission(&auth, permissions::SETTINGS_SYSTEM)
        .map_err(|_| ApiError::Forbidden("Missing permission: settings:system".to_string()))?;

    let tier_settings = nanosiem_core::TierSettings::new(state.pool.clone());
    let limits = tier_settings.get_tier_limits().await?;

    let today = chrono::Utc::now().date_naive();
    let today_usage = tier_settings.get_daily_usage(today).await?;

    // Count current resources
    let rules = state
        .detection_service
        .list_rules()
        .await
        .map(|r| r.len() as u32)
        .unwrap_or(0);

    let data_sources = state
        .log_source_service
        .list(None)
        .await
        .map(|s| s.len() as u32)
        .unwrap_or(0);

    let team_members = state
        .user_repo
        .count_users()
        .await
        .map(|c| c as u32)
        .unwrap_or(0);

    let usage = TierUsageResponse {
        data_sources,
        detection_rules: rules,
        team_members,
        today: today_usage,
    };

    // Generate proactive warnings for resources approaching limits
    let core_usage = nanosiem_core::TierUsage {
        data_sources,
        detection_rules: rules,
        team_members,
        today: usage.today.clone(),
    };
    let warnings = nanosiem_core::generate_warnings(&limits, &core_usage);

    // AI credit usage for current month
    let credits_used = tier_settings.get_ai_credits_used().await.unwrap_or(0);
    let ai_usage = nanosiem_core::AiUsage {
        credits_used,
        credits_limit: limits.ai_credits_per_month,
        model_tier: limits.ai_model_tier,
    };

    Ok(Json(TierStatusResponse {
        limits,
        usage,
        ai_usage,
        warnings,
    }))
}

/// Update the organization tier
#[utoipa::path(
    put,
    path = "/api/settings/tier",
    tag = "settings",
    request_body = SetTierRequest,
    responses(
        (status = 200, body = nanosiem_core::TierLimits),
        (status = 403, body = ErrorResponse),
        (status = 422, body = ErrorResponse),
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn set_tier(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Extension(client): Extension<ClientContext>,
    Json(req): Json<SetTierRequest>,
) -> Result<Json<nanosiem_core::TierLimits>, ApiError> {
    check_permission(&auth, permissions::SETTINGS_SYSTEM)
        .map_err(|_| ApiError::Forbidden("Missing permission: settings:system".to_string()))?;

    let tier: nanosiem_core::OrganizationTier = req
        .tier
        .parse()
        .map_err(|e: nanosiem_core::TierError| ApiError::ValidationError(e.to_string()))?;

    let tier_settings = nanosiem_core::TierSettings::new(state.pool.clone());
    let limits = tier_settings.set_tier(tier).await?;

    state.emit_audit(
        AuditEvent::builder(AuditSource::Settings, nanosiem_core::audit::TIER_UPDATED)
            .actor(Some(auth.user_id()), None)
            .api_key(auth.api_key_id, auth.api_key_name.clone())
            .resource("settings", None, Some("tier".to_string()))
            .details(serde_json::json!({ "tier": req.tier }))
            .client_context(&client)
            .build(),
    );

    tracing::info!(tier = %req.tier, user_id = %auth.user_id(), "Organization tier updated");

    Ok(Json(limits))
}

/// Update specific tier limit overrides
#[utoipa::path(
    put,
    path = "/api/settings/tier/limits",
    tag = "settings",
    request_body = nanosiem_core::UpdateTierLimits,
    responses(
        (status = 200, body = nanosiem_core::TierLimits),
        (status = 403, body = ErrorResponse),
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn update_tier_limits(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Extension(client): Extension<ClientContext>,
    Json(req): Json<nanosiem_core::UpdateTierLimits>,
) -> Result<Json<nanosiem_core::TierLimits>, ApiError> {
    check_permission(&auth, permissions::SETTINGS_SYSTEM)
        .map_err(|_| ApiError::Forbidden("Missing permission: settings:system".to_string()))?;

    let tier_settings = nanosiem_core::TierSettings::new(state.pool.clone());
    let limits = tier_settings.update_limits(req).await?;

    state.emit_audit(
        AuditEvent::builder(
            AuditSource::Settings,
            nanosiem_core::audit::TIER_LIMITS_UPDATED,
        )
        .actor(Some(auth.user_id()), None)
        .api_key(auth.api_key_id, auth.api_key_name.clone())
        .resource("settings", None, Some("tier_limits".to_string()))
        .client_context(&client)
        .build(),
    );

    Ok(Json(limits))
}

/// Get daily usage history
#[utoipa::path(
    get,
    path = "/api/settings/tier/usage",
    tag = "settings",
    params(UsageRangeQuery),
    responses(
        (status = 200, body = Vec<nanosiem_core::DailyUsage>),
        (status = 403, body = ErrorResponse),
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn get_usage_history(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    axum::extract::Query(query): axum::extract::Query<UsageRangeQuery>,
) -> Result<Json<Vec<nanosiem_core::DailyUsage>>, ApiError> {
    check_permission(&auth, permissions::SETTINGS_SYSTEM)
        .map_err(|_| ApiError::Forbidden("Missing permission: settings:system".to_string()))?;

    let today = chrono::Utc::now().date_naive();
    let from = query
        .from
        .unwrap_or_else(|| today - chrono::Duration::days(30));
    let to = query.to.unwrap_or(today);

    let tier_settings = nanosiem_core::TierSettings::new(state.pool.clone());
    let usage = tier_settings.get_usage_range(from, to).await?;

    Ok(Json(usage))
}
