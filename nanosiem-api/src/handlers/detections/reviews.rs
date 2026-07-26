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
use nanosiem_core::detection::match_scope::DetectionMatchRepository;
use nanosiem_core::typeid::TypeIdParam;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

use super::stats::effective_match_scope;
use crate::middleware::{ensure_permission, AuthContext};
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
    ensure_permission(&auth, permissions::DETECTIONS_EDIT)?;

    // NAN-2071: the existence check used to be `WHERE id = $1` with no source
    // predicate, and the write followed it — so a caller denied every source on
    // the match could both confirm the match existed and flip its review state.
    // Visibility is now part of the mutating statement itself (no probe, no
    // TOCTOU window) and a denied match is reported exactly like a missing one.
    let repo = DetectionMatchRepository::new(state.pool.clone());
    let scope = effective_match_scope(&auth);
    let user_id = auth.user_id();

    if !body.reviewed {
        // Treat reviewed=false as an explicit clear.
        if !repo.clear_review(*id, &scope).await? {
            return Err(ApiError::NotFound(format!("Match not found: {}", *id)));
        }
        tracing::info!(match_id = %*id, user_id = %user_id, "match review cleared");
        return Ok(Json(MatchReviewResponse {
            reviewed: false,
            reviewed_at: None,
            reviewed_by: None,
            note: None,
        }));
    }

    let now = Utc::now();
    let Some(review) = repo
        .mark_reviewed(*id, now, user_id, body.note.as_deref(), &scope)
        .await?
    else {
        return Err(ApiError::NotFound(format!("Match not found: {}", *id)));
    };

    tracing::info!(match_id = %*id, user_id = %user_id, "match marked reviewed");

    Ok(Json(MatchReviewResponse {
        reviewed: true,
        reviewed_at: Some(review.reviewed_at),
        reviewed_by: review.reviewed_by,
        note: review.note,
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
        (status = 404, description = "Match not found or not visible to the caller", body = ErrorResponse),
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn unmark_match_reviewed(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<TypeIdParam>,
) -> Result<Json<MatchReviewResponse>, ApiError> {
    ensure_permission(&auth, permissions::DETECTIONS_EDIT)?;

    // NAN-2071: same scoped, single-statement clear as the POST route. This
    // used to delete by match id alone, so a denied-source match's review flag
    // was mutable by anyone holding `detections:edit`. It also used to answer
    // 200 unconditionally; a denied or missing match is now a 404 (identical
    // for both, so still no existence oracle).
    if !DetectionMatchRepository::new(state.pool.clone())
        .clear_review(*id, &effective_match_scope(&auth))
        .await?
    {
        return Err(ApiError::NotFound(format!("Match not found: {}", *id)));
    }

    Ok(Json(MatchReviewResponse {
        reviewed: false,
        reviewed_at: None,
        reviewed_by: None,
        note: None,
    }))
}
