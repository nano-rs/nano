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
use nanosiem_core::typeid::TypeIdParam;
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};

use crate::middleware::{check_permission, AuthContext};
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
    check_permission(&auth, permissions::DETECTIONS_VIEW)
        .map_err(|_| ApiError::Forbidden("Missing permission: detections:view".to_string()))?;

    let days = params.days.unwrap_or(28).clamp(1, 365);
    let window_end = Utc::now();
    let window_start = window_end - chrono::Duration::days(days);

    // One pass, FILTER per disposition. Avoids 4 round trips and uses the new
    // composite index (rule_id, disposition, detected_at).
    let row: (i64, i64, i64, i64, i64) = sqlx::query_as(
        r#"
        SELECT
            COUNT(*) AS total,
            COUNT(*) FILTER (WHERE disposition = 'unclassified')   AS unclassified,
            COUNT(*) FILTER (WHERE disposition = 'true_positive')  AS true_positive,
            COUNT(*) FILTER (WHERE disposition = 'false_positive') AS false_positive,
            COUNT(*) FILTER (WHERE disposition = 'benign')         AS benign
        FROM detection_matches
        WHERE rule_id = $1
          AND detected_at >= $2
          AND detected_at <= $3
        "#,
    )
    .bind(*id)
    .bind(window_start)
    .bind(window_end)
    .fetch_one(&state.pool)
    .await?;

    Ok(Json(DispositionStatsResponse {
        total: row.0,
        unclassified: row.1,
        true_positive: row.2,
        false_positive: row.3,
        benign: row.4,
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
    check_permission(&auth, permissions::DETECTIONS_EDIT)
        .map_err(|_| ApiError::Forbidden("Missing permission: detections:edit".to_string()))?;

    if !ALLOWED_DISPOSITIONS.contains(&body.disposition.as_str()) {
        return Err(ApiError::ValidationError(format!(
            "Invalid disposition '{}'. Must be one of: {}",
            body.disposition,
            ALLOWED_DISPOSITIONS.join(", ")
        )));
    }

    let updated: Option<(String,)> = sqlx::query_as(
        "UPDATE detection_matches SET disposition = $2 WHERE id = $1 RETURNING disposition",
    )
    .bind(*id)
    .bind(&body.disposition)
    .fetch_optional(&state.pool)
    .await?;

    let Some((disposition,)) = updated else {
        return Err(ApiError::NotFound(format!("Match not found: {}", *id)));
    };

    tracing::info!(match_id = %*id, disposition = %disposition, user_id = %auth.user_id(),
        "match disposition set");

    Ok(Json(MatchDispositionResponse { disposition }))
}
