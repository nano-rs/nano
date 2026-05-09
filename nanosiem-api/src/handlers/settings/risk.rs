// SPDX-License-Identifier: AGPL-3.0-or-later

//! Risk weight and decay configuration handlers
//!
//! - Risk **weight** (`/api/settings/risk`) stays open: it's a single PG
//!   column on `system_settings` consumed by the detection scoring path
//!   (`nanosiem_core::detection::risk::ScoreCalculator`).
//! - Risk **decay TTL** (`/api/settings/risk-decay`) is enterprise-only —
//!   the decay factors are read by `RiskAnalyticsService` time-windowed
//!   queries, which live in `nanosiem-enterprise::risk`.

use axum::{extract::State, Extension, Json};
use nanosiem_core::audit::{AuditEvent, AuditSource, ClientContext, RISK_CONFIG_UPDATED};
#[cfg(feature = "enterprise")]
use nanosiem_core::audit::RISK_DECAY_CONFIG_UPDATED;
use nanosiem_core::auth::permissions;
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use utoipa::ToSchema;

use crate::error::{ApiError, ErrorResponse};
use crate::handlers::AuditExt;
use crate::middleware::{check_permission, AuthContext};
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
    check_permission(&auth, permissions::SETTINGS_RISK)
        .map_err(|_| ApiError::Forbidden("Missing permission: settings:risk".to_string()))?;

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
    check_permission(&auth, permissions::SETTINGS_RISK)
        .map_err(|_| ApiError::Forbidden("Missing permission: settings:risk".to_string()))?;

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
    check_permission(&auth, permissions::SETTINGS_RISK)
        .map_err(|_| ApiError::Forbidden("Missing permission: settings:risk".to_string()))?;

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
    check_permission(&auth, permissions::SETTINGS_RISK)
        .map_err(|_| ApiError::Forbidden("Missing permission: settings:risk".to_string()))?;

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
