// SPDX-License-Identifier: AGPL-3.0-or-later

//! Per-match disposition state + rule-level rollup.
//!
//! NAN-498 — analysts classify each match as true_positive / false_positive /
//! benign / unclassified. The hero on the Matches page shows the FP count
//! over the rule's recent window so noisy rules surface for tuning.

use axum::{
    extract::{Path, Query, State},
    Extension, Json,
};
use chrono::{DateTime, Utc};
use nanosiem_core::auth::permissions;
use nanosiem_core::detection::match_scope::DetectionMatchRepository;
use nanosiem_core::typeid::TypeIdParam;
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};

use super::stats::effective_match_scope;
use crate::middleware::{ensure_permission, AuthContext};
use crate::{
    error::{ApiError, ErrorResponse},
    state::AppState,
};

/// Allowed disposition values. Mirrors the CHECK constraint in
/// `migrations/postgres/162_match_disposition.sql`.
const ALLOWED_DISPOSITIONS: &[&str] = &[
    "unclassified",
    "true_positive",
    "false_positive",
    "benign",
];

/// Query parameters for `GET /api/rules/{id}/disposition-stats`.
#[derive(Debug, Deserialize, IntoParams)]
pub struct DispositionStatsQuery {
    /// Window in days (default 28). Must be 1..=365.
    pub days: Option<i64>,
}

/// Rule-level disposition rollup over a time window.
#[derive(Debug, Serialize, ToSchema)]
pub struct DispositionStatsResponse {
    /// Total matches over the window (sum of all dispositions).
    pub total: i64,
    /// Matches still unclassified.
    pub unclassified: i64,
    /// True positives.
    pub true_positive: i64,
    /// False positives.
    pub false_positive: i64,
    /// Benign (legitimate but noisy).
    pub benign: i64,
    /// Window start (RFC 3339).
    pub window_start: DateTime<Utc>,
    /// Window end (RFC 3339).
    pub window_end: DateTime<Utc>,
}

/// Request body for `POST /api/matches/{id}/disposition`.
#[derive(Debug, Deserialize, ToSchema)]
pub struct SetDispositionRequest {
    /// New disposition value.
    pub disposition: String,
}

/// Response after setting a per-match disposition.
#[derive(Debug, Serialize, ToSchema)]
pub struct MatchDispositionResponse {
    /// The disposition now stored on the match.
    pub disposition: String,
}

/// Get disposition stats for a rule over a recent window.
#[utoipa::path(
    get,
    path = "/api/rules/{id}/disposition-stats",
    tag = "detections",
    params(
        ("id" = String, Path, description = "Detection rule ID"),
        DispositionStatsQuery,
    ),
    responses(
        (status = 200, description = "Disposition counts over the window", body = DispositionStatsResponse),
        (status = 403, description = "Missing permission: detections:view", body = ErrorResponse),
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn get_rule_disposition_stats(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<TypeIdParam>,
    Query(params): Query<DispositionStatsQuery>,
) -> Result<Json<DispositionStatsResponse>, ApiError> {
    ensure_permission(&auth, permissions::DETECTIONS_VIEW)?;

    let days = params.days.unwrap_or(28).clamp(1, 365);
    let window_end = Utc::now();
    let window_start = window_end - chrono::Duration::days(days);

    // NAN-2071: the rollup must count exactly the rows `/api/rules/{id}/matches`
    // would return. An unscoped rollup let a caller denied every source on a
    // match still learn that the match happened, when, and how it was
    // classified — a count oracle over the data the row read path hides.
    let stats = DetectionMatchRepository::new(state.pool.clone())
        .disposition_stats(*id, window_start, window_end, &effective_match_scope(&auth))
        .await?;

    Ok(Json(DispositionStatsResponse {
        total: stats.total,
        unclassified: stats.unclassified,
        true_positive: stats.true_positive,
        false_positive: stats.false_positive,
        benign: stats.benign,
        window_start,
        window_end,
    }))
}

/// Set the disposition on a single match.
#[utoipa::path(
    post,
    path = "/api/matches/{id}/disposition",
    tag = "detections",
    params(("id" = String, Path, description = "Detection match ID")),
    request_body = SetDispositionRequest,
    responses(
        (status = 200, description = "Disposition updated", body = MatchDispositionResponse),
        (status = 400, description = "Invalid disposition value", body = ErrorResponse),
        (status = 403, description = "Missing permission: detections:edit", body = ErrorResponse),
        (status = 404, description = "Match not found", body = ErrorResponse),
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn set_match_disposition(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<TypeIdParam>,
    Json(body): Json<SetDispositionRequest>,
) -> Result<Json<MatchDispositionResponse>, ApiError> {
    ensure_permission(&auth, permissions::DETECTIONS_EDIT)?;

    if !ALLOWED_DISPOSITIONS.contains(&body.disposition.as_str()) {
        return Err(ApiError::ValidationError(format!(
            "Invalid disposition '{}'. Must be one of: {}",
            body.disposition,
            ALLOWED_DISPOSITIONS.join(", ")
        )));
    }

    // NAN-2071: the source-scope predicate is part of the UPDATE, so a match
    // stamped with a denied source is never written — this was an IDOR that let
    // `detections:edit` reclassify matches the caller cannot read. A denied
    // match and a nonexistent one both fall out as `None` → identical 404, so
    // the route is not an existence oracle either.
    let updated = DetectionMatchRepository::new(state.pool.clone())
        .set_disposition(*id, &body.disposition, &effective_match_scope(&auth))
        .await?;

    let Some(disposition) = updated else {
        return Err(ApiError::NotFound(format!("Match not found: {}", *id)));
    };

    tracing::info!(match_id = %*id, disposition = %disposition, user_id = %auth.user_id(),
        "match disposition set");

    Ok(Json(MatchDispositionResponse { disposition }))
}
