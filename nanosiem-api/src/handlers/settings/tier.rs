// SPDX-License-Identifier: AGPL-3.0-or-later

//! Organization tier and usage handlers

use axum::{extract::State, Extension, Json};
use nanosiem_core::audit::{AuditEvent, AuditSource, ClientContext};
use nanosiem_core::auth::permissions;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::error::{ApiError, ErrorResponse};
use crate::handlers::AuditExt;
use crate::middleware::{ensure_permission, AuthContext};
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

/// Query params for the AI usage detail endpoint
#[derive(Debug, Deserialize, utoipa::IntoParams)]
pub struct AiUsageQuery {
    /// Start date (YYYY-MM-DD, UTC), defaults to the first of the current month
    pub from: Option<chrono::NaiveDate>,
    /// End date (YYYY-MM-DD, UTC, inclusive), defaults to today
    pub to: Option<chrono::NaiveDate>,
    /// Max rows for the recent-call log (1–500, default 50)
    pub limit: Option<i64>,
}

/// Detailed AI usage: billed credits plus per-agent / daily / recent breakdowns
/// from the `ai_usage_events` ledger.
#[derive(Debug, Serialize, ToSchema)]
pub struct AiUsageDetailResponse {
    /// Billed AI credits this month — authoritative, sourced from
    /// `ai_request_counts` (one charge per request). The ledger breakdowns below
    /// count individual LLM calls, so their summed `credits` may exceed this.
    pub credits_used: i32,
    /// Monthly credit limit (None = unlimited)
    pub credits_limit: Option<u32>,
    pub model_tier: nanosiem_core::AiModelTier,
    /// Inclusive start date the breakdowns cover (UTC)
    pub from: chrono::NaiveDate,
    /// Inclusive end date the breakdowns cover (UTC)
    pub to: chrono::NaiveDate,
    /// Per-agent rollup over [from, to]
    pub by_agent: Vec<nanosiem_core::AgentUsage>,
    /// Daily series over [from, to]
    pub daily: Vec<nanosiem_core::DailyAiUsage>,
    /// Most recent AI calls (latest first), independent of the date range
    pub recent: Vec<nanosiem_core::AiUsageEvent>,
}

// ============================================================================
// Handler Functions
// ============================================================================

/// Clamp stored tier entitlements to what this build can actually serve.
///
/// The tier row says what the plan *allows*; it cannot grant a surface the
/// binary does not contain. Open-core builds have no OIDC/SAML handlers, so
/// reporting `sso_enabled: true` there contradicts `/api/capabilities` and the
/// 404s from `/api/settings/oidc` (NAN-3378).
fn clamp_to_build(mut limits: nanosiem_core::TierLimits) -> nanosiem_core::TierLimits {
    limits.sso_enabled &= crate::handlers::capabilities::SSO_AVAILABLE;
    limits
}

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
    ensure_permission(&auth, permissions::SETTINGS_SYSTEM)?;

    let tier_settings = nanosiem_core::TierSettings::new(state.pool.clone());
    let limits = clamp_to_build(tier_settings.get_tier_limits().await?);

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
    ensure_permission(&auth, permissions::SETTINGS_SYSTEM)?;

    let tier: nanosiem_core::OrganizationTier = req
        .tier
        .parse()
        .map_err(|e: nanosiem_core::TierError| ApiError::ValidationError(e.to_string()))?;

    let tier_settings = nanosiem_core::TierSettings::new(state.pool.clone());
    let limits = clamp_to_build(tier_settings.set_tier(tier).await?);

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
    ensure_permission(&auth, permissions::SETTINGS_SYSTEM)?;

    let tier_settings = nanosiem_core::TierSettings::new(state.pool.clone());
    let limits = clamp_to_build(tier_settings.update_limits(req).await?);

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
    ensure_permission(&auth, permissions::SETTINGS_SYSTEM)?;

    let today = chrono::Utc::now().date_naive();
    let from = query
        .from
        .unwrap_or_else(|| today - chrono::Duration::days(30));
    let to = query.to.unwrap_or(today);

    let tier_settings = nanosiem_core::TierSettings::new(state.pool.clone());
    let usage = tier_settings.get_usage_range(from, to).await?;

    Ok(Json(usage))
}

/// Get detailed AI usage: billed credits + per-agent, daily, and recent-call
/// breakdowns from the AI usage ledger.
#[utoipa::path(
    get,
    path = "/api/settings/ai-usage",
    tag = "settings",
    params(AiUsageQuery),
    responses(
        (status = 200, body = AiUsageDetailResponse),
        (status = 403, body = ErrorResponse),
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn get_ai_usage_detail(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    axum::extract::Query(query): axum::extract::Query<AiUsageQuery>,
) -> Result<Json<AiUsageDetailResponse>, ApiError> {
    use chrono::Datelike;

    ensure_permission(&auth, permissions::SETTINGS_SYSTEM)?;

    let today = chrono::Utc::now().date_naive();
    let first_of_month = today.with_day(1).unwrap_or(today);
    let from = query.from.unwrap_or(first_of_month);
    let to = query.to.unwrap_or(today);
    if from > to {
        return Err(ApiError::BadRequest(
            "`from` must be on or before `to`".to_string(),
        ));
    }
    let limit = query.limit.unwrap_or(50);

    // Convert the inclusive [from, to] date range to a half-open UTC timestamp
    // range [from 00:00, (to+1) 00:00) so the `to` day is fully covered.
    // `checked_add_days` guards against overflow on extreme user-supplied dates
    // (a bare `+ Duration::days(1)` would panic at chrono's max date).
    let from_ts = from.and_hms_opt(0, 0, 0).unwrap_or_default().and_utc();
    let to_excl = to
        .checked_add_days(chrono::Days::new(1))
        .and_then(|d| d.and_hms_opt(0, 0, 0))
        .map(|dt| dt.and_utc())
        .ok_or_else(|| ApiError::BadRequest("`to` date is out of range".to_string()))?;

    let tier_settings = nanosiem_core::TierSettings::new(state.pool.clone());
    let limits = tier_settings.get_tier_limits().await?;
    // Headline billed-credit figure degrades to 0 rather than failing the whole
    // request — the ledger breakdowns below are the primary payload here.
    let credits_used = tier_settings.get_ai_credits_used().await.unwrap_or(0);
    let by_agent = tier_settings
        .get_ai_usage_by_agent(from_ts, to_excl)
        .await?;
    let daily = tier_settings.get_ai_usage_daily(from_ts, to_excl).await?;
    let recent = tier_settings.get_recent_ai_events(limit).await?;

    Ok(Json(AiUsageDetailResponse {
        credits_used,
        credits_limit: limits.ai_credits_per_month,
        model_tier: limits.ai_model_tier,
        from,
        to,
        by_agent,
        daily,
        recent,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use nanosiem_core::{OrganizationTier, TierLimits};

    /// NAN-3378: the tier row grants SSO on `unrestricted`, but an open build
    /// has no OIDC handlers. `/api/settings/tier` must agree with
    /// `/api/capabilities` instead of advertising a surface that 404s.
    #[test]
    fn tier_sso_enabled_follows_build_availability() {
        let stored = TierLimits::for_tier_unoverridden(OrganizationTier::Unrestricted);
        assert!(stored.sso_enabled, "precondition: unrestricted grants SSO");

        let reported = clamp_to_build(stored);
        assert_eq!(
            reported.sso_enabled,
            crate::handlers::capabilities::SSO_AVAILABLE
        );
        #[cfg(not(feature = "enterprise"))]
        assert!(
            !reported.sso_enabled,
            "open build must report sso_enabled=false"
        );
        #[cfg(feature = "enterprise")]
        assert!(
            reported.sso_enabled,
            "enterprise build keeps the plan grant"
        );
    }

    #[test]
    fn clamp_never_grants_sso_the_plan_withheld() {
        let mut stored = TierLimits::for_tier_unoverridden(OrganizationTier::Unrestricted);
        stored.sso_enabled = false;
        assert!(!clamp_to_build(stored).sso_enabled);
    }

    #[test]
    fn capabilities_and_tier_agree_on_sso() {
        let caps = crate::handlers::capabilities::build_capabilities(
            crate::config::IngestMode::Vector,
        );
        let tier = clamp_to_build(TierLimits::for_tier_unoverridden(
            OrganizationTier::Unrestricted,
        ));
        assert_eq!(caps.capabilities.sso, tier.sso_enabled);
    }
}
