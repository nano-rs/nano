// SPDX-License-Identifier: AGPL-3.0-or-later

//! Query-parameter and envelope types for the hunts API.

use std::str::FromStr;

use nanosiem_core::hunts::{
    ClaimedSweep, Hunt, HuntLead, HuntProfile, HuntRuleIdea, HuntRunner, HuntSuppression, HuntSweep,
};
use nanosiem_core::typeid::TypeIdParam;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::ApiError;

/// Default page size for every hunt listing. Deliberately small: the bench is a
/// triage surface, not an export.
pub const DEFAULT_PAGE: i64 = 50;
/// Ceiling on a caller-supplied page size.
pub const MAX_PAGE: i64 = 500;

/// Clamp a caller-supplied page size into `1..=MAX_PAGE`.
pub fn page_size(requested: Option<i64>) -> i64 {
    requested.unwrap_or(DEFAULT_PAGE).clamp(1, MAX_PAGE)
}

/// Parse an optional TypeID query parameter into a UUID.
///
/// Rejects rather than ignores: silently dropping an unparseable
/// `?playbook_id=` would widen the query to every hunt, which reads as "the
/// filter did nothing" and is the worst possible failure for a filter on a
/// triage queue.
pub fn optional_typeid(raw: Option<&str>, field: &str) -> Result<Option<Uuid>, ApiError> {
    match raw.map(str::trim).filter(|s| !s.is_empty()) {
        None => Ok(None),
        Some(value) => TypeIdParam::from_str(value)
            .map(|p| Some(*p))
            .map_err(|e| ApiError::BadRequest(format!("invalid {field}: {e}"))),
    }
}

#[derive(Debug, Deserialize, utoipa::IntoParams)]
pub struct ListHuntsParams {
    /// Only hunts whose schedule is enabled.
    #[serde(default)]
    pub enabled_only: bool,
    #[serde(default)]
    pub limit: Option<i64>,
    #[serde(default)]
    pub offset: Option<i64>,
}

#[derive(Debug, Deserialize, utoipa::IntoParams)]
pub struct ListSweepsParams {
    /// `queued` | `leased` | `running` | `finished` | `failed` | `abandoned`.
    #[serde(default)]
    pub status: Option<String>,
    #[serde(default)]
    pub limit: Option<i64>,
    #[serde(default)]
    pub offset: Option<i64>,
}

#[derive(Debug, Deserialize, utoipa::IntoParams)]
pub struct ListLeadsParams {
    #[serde(default)]
    pub playbook_id: Option<String>,
    #[serde(default)]
    pub sweep_id: Option<String>,
    /// One or more of `unreviewed` | `in_review` | `promoted` | `dismissed`,
    /// comma-joined (`state=unreviewed,in_review` — the bench's segments are
    /// multi-state). An unknown state is a 400, never a silent no-match.
    #[serde(default)]
    pub state: Option<String>,
    /// Only leads whose verdict the CALLER recorded (`reviewed_by` = the
    /// authenticated user). `reviewed_by` is stamped by promote and dismiss,
    /// so this is "leads I triaged" — there is no assignment mechanism.
    #[serde(default)]
    pub mine: bool,
    /// Floor on the SERVER-computed score.
    #[serde(default)]
    pub min_score: Option<f64>,
    #[serde(default)]
    pub limit: Option<i64>,
    #[serde(default)]
    pub offset: Option<i64>,
}

#[derive(Debug, Deserialize, utoipa::IntoParams)]
pub struct ListSuppressionsParams {
    /// Include revoked and expired suppressions.
    #[serde(default)]
    pub include_revoked: bool,
}

#[derive(Debug, Deserialize, utoipa::IntoParams)]
pub struct ListRuleIdeasParams {
    #[serde(default)]
    pub playbook_id: Option<String>,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct ListHuntsResponse {
    pub hunts: Vec<Hunt>,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct ListRunnersResponse {
    pub runners: Vec<HuntRunner>,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct ListSweepsResponse {
    pub sweeps: Vec<HuntSweep>,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct ListLeadsResponse {
    pub leads: Vec<HuntLead>,
    /// Filter-matched total past the page window, under the caller's artifact
    /// scope — the bench header's "N leads in this queue". The desktop's
    /// `LeadListResponse` declares this; while it was missing, the header fell
    /// back to zero and claimed the queue was empty above the rows it listed.
    pub total_count: i64,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct ListHuntSuppressionsResponse {
    pub suppressions: Vec<HuntSuppression>,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct ListRuleIdeasResponse {
    pub rule_ideas: Vec<HuntRuleIdea>,
}

/// The result of a claim poll.
///
/// "Nothing to do" is a 200 with `sweep: null`, not a 404. A runner polls every
/// few seconds and an empty queue is the normal case; making it an error would
/// fill the log with failures that mean "everything is fine".
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct ClaimSweepOutcome {
    pub sweep: Option<ClaimedSweep>,
}

/// The recon profile, or `null` when recon has never run.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct ProfileResponse {
    pub profile: Option<HuntProfile>,
}
