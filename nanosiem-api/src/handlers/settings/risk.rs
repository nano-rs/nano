// SPDX-License-Identifier: AGPL-3.0-or-later

//! Risk weight, decay, and notable configuration handlers
//!
//! - Risk **weight** (`/api/settings/risk`) stays open: it's a single PG
//!   column on `system_settings` consumed by the detection scoring path
//!   (`nanosiem_core::detection::risk::ScoreCalculator`).
//! - Risk **decay TTL** (`/api/settings/risk-decay`) is enterprise-only —
//!   the decay factors are read by `RiskAnalyticsService` time-windowed
//!   queries, which live in `nanosiem-enterprise::risk`.
//! - Risk **notables** (`/api/settings/risk-notables`, NAN-1792) are
//!   enterprise-only. Since NAN-1805 the bespoke `RiskNotableScheduler` is
//!   retired and notables run as the seeded DEFAULT DETECTION RULE over
//!   `dataset=risk` (`DEFAULT_RISK_NOTABLE_RULE_ID`, enterprise migration
//!   9000033). This endpoint is a thin editor over that rule: thresholds and
//!   per-type overrides regenerate the rule's WHERE, cooldown maps to
//!   `alert_cooldown_minutes`, and `enabled` maps to Live vs Alerting mode.
//!   The `system_settings.risk_notable_*` columns remain the storage for the
//!   threshold numbers (the rule query is generated FROM them), so the card's
//!   contract (`RiskNotableConfig`) is unchanged.
//!
//! NAN-2114: every handler in this module gates on `risk:configure`
//! (`permissions::RISK_CONFIGURE`) — the capability the frontend already treats
//! as the authority for the Risk Scoring settings page. The near-duplicate
//! `settings:risk` was never the UI-advertised authority and is no longer
//! enforced here, so the catalog/frontend and the route policy now agree.

use axum::{extract::State, Extension, Json};
use nanosiem_core::audit::{AuditEvent, AuditSource, ClientContext, RISK_CONFIG_UPDATED};
#[cfg(feature = "enterprise")]
use nanosiem_core::audit::{RISK_DECAY_CONFIG_UPDATED, RISK_NOTABLE_CONFIG_UPDATED};
use nanosiem_core::auth::permissions;
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use utoipa::ToSchema;

use crate::error::{ApiError, ErrorResponse};
use crate::handlers::AuditExt;
use crate::middleware::{ensure_permission, AuthContext};
use crate::state::AppState;

// ============================================================================
// Request/Response Types
// ============================================================================

/// Response for risk configuration
#[derive(Debug, Serialize, ToSchema)]
pub struct RiskConfigResponse {
    pub risk_weight: f64,
}

/// Request to update risk configuration
#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateRiskConfigRequest {
    pub risk_weight: f64,
}

/// Response for risk decay configuration
#[cfg(feature = "enterprise")]
#[derive(Debug, Serialize, ToSchema)]
pub struct RiskDecayConfigResponse {
    pub decay_0_24h: f64,
    pub decay_1_3d: f64,
    pub decay_3_5d: f64,
    pub decay_5_7d: f64,
}

/// Request to update risk decay configuration
#[cfg(feature = "enterprise")]
#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateRiskDecayConfigRequest {
    pub decay_0_24h: f64,
    pub decay_1_3d: f64,
    pub decay_3_5d: f64,
    pub decay_5_7d: f64,
}

// ============================================================================
// Handler Functions
// ============================================================================

/// Get risk configuration
///
/// GET /api/settings/risk
///
/// Returns the current global risk weight multiplier.
///
/// Requirements: 9.1
#[utoipa::path(
    get,
    path = "/api/settings/risk",
    tag = "settings",
    responses(
        (status = 200, description = "Risk configuration", body = RiskConfigResponse),
        (status = 403, description = "Missing permission", body = ErrorResponse),
        (status = 500, description = "Internal error", body = ErrorResponse)
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn get_risk_config(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
) -> Result<Json<RiskConfigResponse>, ApiError> {
    ensure_permission(&auth, permissions::RISK_CONFIGURE)?;

    let risk_weight = get_risk_weight_from_db(&state.pool).await?;
    Ok(Json(RiskConfigResponse { risk_weight }))
}

/// Update risk configuration
///
/// PUT /api/settings/risk
///
/// Updates the global risk weight multiplier (0.0-1.0).
/// The new weight is applied to all future signals immediately.
///
/// Requirements: 9.1, 9.4
#[utoipa::path(
    put,
    path = "/api/settings/risk",
    tag = "settings",
    request_body = UpdateRiskConfigRequest,
    responses(
        (status = 200, description = "Risk updated", body = RiskConfigResponse),
        (status = 400, description = "Invalid weight", body = ErrorResponse),
        (status = 403, description = "Missing permission", body = ErrorResponse),
        (status = 500, description = "Internal error", body = ErrorResponse)
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn update_risk_config(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Extension(client): Extension<ClientContext>,
    Json(request): Json<UpdateRiskConfigRequest>,
) -> Result<Json<RiskConfigResponse>, ApiError> {
    ensure_permission(&auth, permissions::RISK_CONFIGURE)?;

    use nanosiem_core::detection::risk::ScoreCalculator;

    // Validate the weight is within bounds
    ScoreCalculator::validate_weight(request.risk_weight)?;

    // Update the risk_weight in the database
    update_risk_weight_in_db(&state.pool, request.risk_weight).await?;

    tracing::info!("Risk weight updated to {}", request.risk_weight);

    state.emit_audit(
        AuditEvent::builder(AuditSource::Settings, RISK_CONFIG_UPDATED)
            .actor(Some(auth.user_id()), None)
            .api_key(auth.api_key_id, auth.api_key_name.clone())
            .resource("settings", None, Some("risk".to_string()))
            .client_context(&client)
            .build(),
    );

    Ok(Json(RiskConfigResponse {
        risk_weight: request.risk_weight,
    }))
}

/// Helper function to get risk_weight from the database
pub(super) async fn get_risk_weight_from_db(pool: &PgPool) -> Result<f64, ApiError> {
    let row: (sqlx::types::Decimal,) =
        sqlx::query_as("SELECT risk_weight FROM system_settings WHERE id = 'default'")
            .fetch_one(pool)
            .await
            .map_err(|e| ApiError::DatabaseError(e.to_string()))?;

    // Convert Decimal to f64
    let weight_str = row.0.to_string();
    let weight = weight_str.parse::<f64>().unwrap_or(1.0);
    Ok(weight)
}

/// Helper function to update risk_weight in the database
pub(super) async fn update_risk_weight_in_db(pool: &PgPool, weight: f64) -> Result<(), ApiError> {
    use sqlx::types::Decimal;

    // Convert f64 to Decimal
    let decimal_weight =
        Decimal::try_from(weight).unwrap_or_else(|_| Decimal::try_from(1.0).unwrap());

    sqlx::query(
        "UPDATE system_settings SET risk_weight = $1, updated_at = NOW() WHERE id = 'default'",
    )
    .bind(decimal_weight)
    .execute(pool)
    .await
    .map_err(|e| ApiError::DatabaseError(e.to_string()))?;

    Ok(())
}

/// Get risk decay configuration
///
/// GET /api/settings/risk-decay
///
/// Returns the current TTL decay factors for risk scoring.
/// Decay is applied based on signal age (Google SecOps-style).
#[cfg(feature = "enterprise")]
#[utoipa::path(
    get,
    path = "/api/settings/risk-decay",
    tag = "settings",
    responses(
        (status = 200, description = "Risk decay configuration", body = RiskDecayConfigResponse),
        (status = 403, description = "Missing permission", body = ErrorResponse),
        (status = 500, description = "Internal error", body = ErrorResponse)
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn get_risk_decay_config(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
) -> Result<Json<RiskDecayConfigResponse>, ApiError> {
    ensure_permission(&auth, permissions::RISK_CONFIGURE)?;

    let config = state
        .risk_service
        .get_decay_config()
        .await
        .map_err(|e| ApiError::DatabaseError(e.to_string()))?;

    Ok(Json(RiskDecayConfigResponse {
        decay_0_24h: config.decay_0_24h,
        decay_1_3d: config.decay_1_3d,
        decay_3_5d: config.decay_3_5d,
        decay_5_7d: config.decay_5_7d,
    }))
}

/// Update risk decay configuration
///
/// PUT /api/settings/risk-decay
///
/// Updates the TTL decay factors for risk scoring.
/// All factors must be between 0.0 and 1.0.
#[cfg(feature = "enterprise")]
#[utoipa::path(
    put,
    path = "/api/settings/risk-decay",
    tag = "settings",
    request_body = UpdateRiskDecayConfigRequest,
    responses(
        (status = 200, description = "Risk decay updated", body = RiskDecayConfigResponse),
        (status = 400, description = "Invalid factors", body = ErrorResponse),
        (status = 403, description = "Missing permission", body = ErrorResponse),
        (status = 500, description = "Internal error", body = ErrorResponse)
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn update_risk_decay_config(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Extension(client): Extension<ClientContext>,
    Json(request): Json<UpdateRiskDecayConfigRequest>,
) -> Result<Json<RiskDecayConfigResponse>, ApiError> {
    ensure_permission(&auth, permissions::RISK_CONFIGURE)?;

    use nanosiem_core::risk::types::RiskDecayConfig;

    let config = RiskDecayConfig {
        decay_0_24h: request.decay_0_24h,
        decay_1_3d: request.decay_1_3d,
        decay_3_5d: request.decay_3_5d,
        decay_5_7d: request.decay_5_7d,
    };

    state
        .risk_service
        .update_decay_config(&config)
        .await
        .map_err(|e| ApiError::ValidationError(e.to_string()))?;

    tracing::info!(
        "Risk decay config updated: 0-24h={}, 1-3d={}, 3-5d={}, 5-7d={}",
        config.decay_0_24h,
        config.decay_1_3d,
        config.decay_3_5d,
        config.decay_5_7d
    );

    state.emit_audit(
        AuditEvent::builder(AuditSource::Settings, RISK_DECAY_CONFIG_UPDATED)
            .actor(Some(auth.user_id()), None)
            .api_key(auth.api_key_id, auth.api_key_name.clone())
            .resource("settings", None, Some("risk_decay".to_string()))
            .client_context(&client)
            .build(),
    );

    Ok(Json(RiskDecayConfigResponse {
        decay_0_24h: config.decay_0_24h,
        decay_1_3d: config.decay_1_3d,
        decay_3_5d: config.decay_3_5d,
        decay_5_7d: config.decay_5_7d,
    }))
}

/// Get risk-notable configuration
///
/// GET /api/settings/risk-notables
///
/// Returns the risk-notable settings (NAN-1792/NAN-1805): the 24h/7d
/// decayed-score thresholds and per-entity-type overrides (stored on
/// `system_settings`, from which the default rule's query is generated), plus
/// the live state of the seeded default `dataset=risk` detection rule —
/// `enabled` reflects whether the rule is in Alerting mode and
/// `cooldown_minutes` reflects its `alert_cooldown_minutes`. When the default
/// rule has been deleted, `enabled` reads false (nothing evaluates).
#[cfg(feature = "enterprise")]
#[utoipa::path(
    get,
    path = "/api/settings/risk-notables",
    tag = "settings",
    responses(
        (status = 200, description = "Risk notable configuration", body = nanosiem_core::risk::RiskNotableConfig),
        (status = 403, description = "Missing permission", body = ErrorResponse),
        (status = 500, description = "Internal error", body = ErrorResponse)
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn get_risk_notable_config(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
) -> Result<Json<nanosiem_core::risk::RiskNotableConfig>, ApiError> {
    ensure_permission(&auth, permissions::RISK_CONFIGURE)?;

    let mut config = state
        .risk_service
        .get_notable_config()
        .await
        .map_err(|e| ApiError::DatabaseError(e.to_string()))?;

    // NAN-1805: the default dataset=risk rule is the execution surface —
    // overlay its live state so the card reflects reality even after the rule
    // was edited directly (rule editor / DaC).
    use nanosiem_core::models::RuleMode;
    use nanosiem_core::risk::DEFAULT_RISK_NOTABLE_RULE_ID;
    match state
        .detection_service
        .get_rule(DEFAULT_RISK_NOTABLE_RULE_ID)
        .await
    {
        Ok(rule) => {
            config.enabled = rule.mode == RuleMode::Alerting;
            if let Some(cooldown) = rule.alert_cooldown_minutes.filter(|m| *m > 0) {
                config.cooldown_minutes = cooldown;
            }
        }
        Err(nanosiem_core::DetectionError::RuleNotFound(_)) => {
            // Deleted by the operator: nothing evaluates, so notables are off.
            config.enabled = false;
        }
        Err(e) => {
            // Degrade to the persisted settings rather than failing the card.
            tracing::warn!(error = %e, "risk-notables: failed to read the default rule; returning persisted settings");
        }
    }

    Ok(Json(config))
}

/// Update risk-notable configuration
///
/// PUT /api/settings/risk-notables
///
/// Updates the risk-notable settings AND syncs the seeded default
/// `dataset=risk` detection rule (NAN-1805): thresholds + per-type overrides
/// regenerate the rule's query, `cooldown_minutes` writes its
/// `alert_cooldown_minutes`, and `enabled` maps to Alerting (true) vs Live
/// (false) mode — the same explicit operator action that previously flipped
/// the scheduler switch. Thresholds and cooldown must be positive; the
/// cooldown may not exceed 10080 (7 days). If the default rule was deleted,
/// the settings are still persisted and a warning is logged (nothing
/// evaluates until a risk rule exists again).
#[cfg(feature = "enterprise")]
#[utoipa::path(
    put,
    path = "/api/settings/risk-notables",
    tag = "settings",
    request_body = nanosiem_core::risk::RiskNotableConfig,
    responses(
        (status = 200, description = "Risk notable config updated", body = nanosiem_core::risk::RiskNotableConfig),
        (status = 400, description = "Invalid config", body = ErrorResponse),
        (status = 403, description = "Missing permission", body = ErrorResponse),
        (status = 500, description = "Internal error", body = ErrorResponse)
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn update_risk_notable_config(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Extension(client): Extension<ClientContext>,
    Json(config): Json<nanosiem_core::risk::RiskNotableConfig>,
) -> Result<Json<nanosiem_core::risk::RiskNotableConfig>, ApiError> {
    ensure_permission(&auth, permissions::RISK_CONFIGURE)?;

    // The rule's alert_cooldown_minutes is CHECK-bounded at 7 days
    // (migration 248); reject up front instead of 500ing on the constraint.
    if config.cooldown_minutes > nanosiem_core::models::detection_rule::MAX_ALERT_COOLDOWN_MINUTES
    {
        return Err(ApiError::ValidationError(format!(
            "cooldown_minutes must be at most {} (7 days)",
            nanosiem_core::models::detection_rule::MAX_ALERT_COOLDOWN_MINUTES
        )));
    }

    state
        .risk_service
        .update_notable_config(&config)
        .await
        .map_err(|e| ApiError::ValidationError(e.to_string()))?;

    // NAN-1805: sync the default dataset=risk rule — it is the execution
    // surface for these settings now that the scheduler is retired. Mapping
    // `enabled` to Alerting mode via this SETTINGS_RISK-gated endpoint is
    // behavior parity with NAN-1792 (enabling the scheduler needed the same
    // permission). enabled=false only demotes Alerting → Live; a rule the
    // operator parked in Staging/Paused is left alone.
    {
        use nanosiem_core::models::{RuleMode, UpdateDetectionRule};
        use nanosiem_core::risk::DEFAULT_RISK_NOTABLE_RULE_ID;

        match state
            .detection_service
            .get_rule(DEFAULT_RISK_NOTABLE_RULE_ID)
            .await
        {
            Ok(rule) => {
                let mode = if config.enabled {
                    (rule.mode != RuleMode::Alerting).then_some(RuleMode::Alerting)
                } else {
                    (rule.mode == RuleMode::Alerting).then_some(RuleMode::Live)
                };
                let update = UpdateDetectionRule {
                    query: Some(config.default_rule_query()),
                    alert_cooldown_minutes: Some(config.cooldown_minutes),
                    mode,
                    ..Default::default()
                };
                let updated = state
                    .detection_service
                    .update_rule(DEFAULT_RISK_NOTABLE_RULE_ID, update)
                    .await?;
                // Keep distributed scheduling in step with a mode change
                // (Live/Alerting both schedule; this is a no-op otherwise).
                state.detection_service.sync_next_run_at(&updated).await;
            }
            Err(nanosiem_core::DetectionError::RuleNotFound(_)) => {
                tracing::warn!(
                    "risk-notables: default rule {} not found — settings persisted but nothing evaluates them (the rule was deleted; re-create a dataset=risk rule to resume notables)",
                    DEFAULT_RISK_NOTABLE_RULE_ID
                );
            }
            Err(e) => return Err(e.into()),
        }
    }

    tracing::info!(
        enabled = config.enabled,
        threshold_24h = config.threshold_24h,
        threshold_7d = config.threshold_7d,
        cooldown_minutes = config.cooldown_minutes,
        "Risk notable config updated (default rule synced)"
    );

    state.emit_audit(
        AuditEvent::builder(AuditSource::Settings, RISK_NOTABLE_CONFIG_UPDATED)
            .actor(Some(auth.user_id()), None)
            .api_key(auth.api_key_id, auth.api_key_name.clone())
            .resource("settings", None, Some("risk_notables".to_string()))
            .client_context(&client)
            .build(),
    );

    Ok(Json(config))
}
