// SPDX-License-Identifier: AGPL-3.0-or-later

//! Per-match review state.
//!
//! NAN-494 — analysts mark a match as reviewed from the Matches detail pane.
//! State lives in `match_reviews` (Postgres) keyed by `match_id` UUID.

use axum::{
    extract::{Path, State},
    Extension, Json,
};
use chrono::{DateTime, Utc};
use nanosiem_core::auth::permissions;
use nanosiem_core::typeid::TypeIdParam;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::middleware::{check_permission, AuthContext};
use crate::{
    error::{ApiError, ErrorResponse},
    state::AppState,
};

/// Request body for `POST /api/matches/{id}/review`.
#[derive(Debug, Deserialize, ToSchema)]
pub struct MarkReviewRequest {
    /// Whether the match should be marked reviewed (true) or unmarked (false).
    /// Defaults to true; analysts typically POST without a body.
    #[serde(default = "default_reviewed")]
    pub reviewed: bool,
    /// Optional analyst note captured at review time.
    pub note: Option<String>,
}

fn default_reviewed() -> bool {
    true
}

/// Response for review state lookups + writes.
#[derive(Debug, Serialize, ToSchema)]
pub struct MatchReviewResponse {
    /// Whether the match is currently flagged reviewed.
    pub reviewed: bool,
    /// When it was reviewed (RFC 3339), if reviewed.
    pub reviewed_at: Option<DateTime<Utc>>,
    /// Reviewer user id (RFC 3339), if reviewed and the user still exists.
    #[serde(with = "nanosiem_core::typeid::user::opt")]
    #[schema(value_type = Option<String>)]
    pub reviewed_by: Option<Uuid>,
    /// Optional analyst note.
    pub note: Option<String>,
}

/// Mark a detection match as reviewed (or clear the review flag with `reviewed=false`).
#[utoipa::path(
    post,
    path = "/api/matches/{id}/review",
    tag = "detections",
    params(("id" = String, Path, description = "Detection match ID")),
    request_body = MarkReviewRequest,
    responses(
        (status = 200, description = "Review state after the update", body = MatchReviewResponse),
        (status = 403, description = "Missing permission: detections:edit", body = ErrorResponse),
        (status = 404, description = "Match not found", body = ErrorResponse),
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn mark_match_reviewed(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<TypeIdParam>,
    Json(body): Json<MarkReviewRequest>,
) -> Result<Json<MatchReviewResponse>, ApiError> {
    check_permission(&auth, permissions::DETECTIONS_EDIT)
        .map_err(|_| ApiError::Forbidden("Missing permission: detections:edit".to_string()))?;

    // Verify the match exists so we can return a clean 404 (the FK would also
    // reject, but its error message is opaque).
    let exists: Option<(Uuid,)> =
        sqlx::query_as("SELECT id FROM detection_matches WHERE id = $1")
            .bind(*id)
            .fetch_optional(&state.pool)
            .await?;
    if exists.is_none() {
        return Err(ApiError::NotFound(format!("Match not found: {}", *id)));
    }

    let user_id = auth.user_id();

    if !body.reviewed {
        // Treat reviewed=false as an explicit clear.
        sqlx::query("DELETE FROM match_reviews WHERE match_id = $1")
            .bind(*id)
            .execute(&state.pool)
            .await?;
        tracing::info!(match_id = %*id, user_id = %user_id, "match review cleared");
        return Ok(Json(MatchReviewResponse {
            reviewed: false,
            reviewed_at: None,
            reviewed_by: None,
            note: None,
        }));
    }

    let now = Utc::now();
    let row: (DateTime<Utc>, Option<Uuid>, Option<String>) = sqlx::query_as(
        r#"
        INSERT INTO match_reviews (match_id, reviewed_at, reviewed_by, note)
        VALUES ($1, $2, $3, $4)
        ON CONFLICT (match_id) DO UPDATE
        SET reviewed_at = EXCLUDED.reviewed_at,
            reviewed_by = EXCLUDED.reviewed_by,
            note        = EXCLUDED.note
        RETURNING reviewed_at, reviewed_by, note
        "#,
    )
    .bind(*id)
    .bind(now)
    .bind(user_id)
    .bind(body.note.as_deref())
    .fetch_one(&state.pool)
    .await?;

    tracing::info!(match_id = %*id, user_id = %user_id, "match marked reviewed");

    Ok(Json(MatchReviewResponse {
        reviewed: true,
        reviewed_at: Some(row.0),
        reviewed_by: row.1,
        note: row.2,
    }))
}

/// Clear the reviewed flag on a match.
#[utoipa::path(
    delete,
    path = "/api/matches/{id}/review",
    tag = "detections",
    params(("id" = String, Path, description = "Detection match ID")),
    responses(
        (status = 200, description = "Review cleared", body = MatchReviewResponse),
        (status = 403, description = "Missing permission: detections:edit", body = ErrorResponse),
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn unmark_match_reviewed(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<TypeIdParam>,
) -> Result<Json<MatchReviewResponse>, ApiError> {
    check_permission(&auth, permissions::DETECTIONS_EDIT)
        .map_err(|_| ApiError::Forbidden("Missing permission: detections:edit".to_string()))?;

    sqlx::query("DELETE FROM match_reviews WHERE match_id = $1")
        .bind(*id)
        .execute(&state.pool)
        .await?;

    Ok(Json(MatchReviewResponse {
        reviewed: false,
        reviewed_at: None,
        reviewed_by: None,
        note: None,
    }))
}
