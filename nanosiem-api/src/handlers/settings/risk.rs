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

