// SPDX-License-Identifier: AGPL-3.0-or-later

//! Auto retro-hunt rule model (NAN-1791).
//!
//! A retro-hunt rule is a `DetectionRule` with `kind = "retro_hunt"`. On its
//! schedule it computes the DELTA of newly-landed threat-intel indicators (feed
//! rows in `custom_enrichment_results` above a per-rule watermark, minus the set
//! already hunted), runs the retro engine over just that delta across historical
//! logs, and emits hits through the standard signal processor → alerts path.
//!
//! This module holds the config/state/run-history models plus the API request
//! shapes and validation. The execution engine lives in
//! `detection::service::retro_hunt`; the ClickHouse candidate/hunt queries live
//! in `search::service::retro`.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

/// Default cron for a retro-hunt rule (every 30 minutes). Retro hunts are not
/// latency-sensitive — the indicator was already published — so a modest cadence
/// keeps the historical scans cheap.
pub const DEFAULT_RETRO_HUNT_CRON: &str = "*/30 * * * *";

/// Default lookback window (days) a retro hunt scans history over.
pub const DEFAULT_RETRO_HUNT_LOOKBACK_DAYS: i32 = 90;

/// Maximum lookback (days) — the `logs` table carries a 365-day TTL, so a hunt
/// can never usefully reach further.
pub const MAX_RETRO_HUNT_LOOKBACK_DAYS: i32 = 365;

/// Default per-run indicator cap. Overflow is carried to the next run.
pub const DEFAULT_RETRO_HUNT_MAX_INDICATORS: i32 = 500;

/// Hard ceiling on the per-run indicator cap — mirrors the retro engine's own
/// `RETRO_MAX_INDICATORS` so a run never expands more indicators than the engine
/// will aggregate.
pub const MAX_RETRO_HUNT_MAX_INDICATORS: i32 = 1000;

/// Artifact types a retro-hunt rule may filter on. Empty selection = all types.
/// These mirror `custom_enrichment_results.key_type`.
pub const VALID_RETRO_HUNT_ARTIFACT_TYPES: &[&str] = &["ip", "domain", "hash", "url"];

/// Per-rule retro-hunt configuration (`retro_hunt_rule_config`).
#[derive(Debug, Clone, Serialize, Deserialize, FromRow, utoipa::ToSchema)]
pub struct RetroHuntConfig {
    #[serde(with = "crate::typeid::rule")]
    #[schema(value_type = String)]
    pub rule_id: Uuid,
    /// Selected feed names (`enrichment_name`); empty = ALL feeds.
    pub feeds: Vec<String>,
    /// Artifact-type filter (`ip`/`domain`/`hash`/`url`); empty = ALL types.
    pub artifact_types: Vec<String>,
    /// How far back the retro hunt scans (1..=365 days).
    pub lookback_days: i32,
    /// Hard per-run indicator cap (1..=1000). Overflow carried to the next run.
    pub max_indicators_per_run: i32,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Per-rule retro-hunt delta state (`retro_hunt_rule_state`).
///
/// `(watermark, watermark_value)` is a KEYSET cursor over the feed ordered by
/// `(fetched_at, lower(key_value))`. A bare timestamp cursor cannot drain a tie
/// group (a feed sync stamps thousands of indicators with the same `fetched_at`)
/// larger than the per-run cap — it would either skip the tie group's tail or
/// stall on it forever. The value tiebreak makes the cursor strictly monotonic.
/// NULL = never run.
#[derive(Debug, Clone, Serialize, Deserialize, FromRow, utoipa::ToSchema)]
pub struct RetroHuntState {
    #[serde(with = "crate::typeid::rule")]
    #[schema(value_type = String)]
    pub rule_id: Uuid,
    /// Cursor: `fetched_at` of the last candidate covered.
    pub watermark: Option<DateTime<Utc>>,
    /// Cursor tiebreak: lowercased indicator value of that same candidate.
    #[serde(default)]
    pub watermark_value: Option<String>,
    pub last_run_at: Option<DateTime<Utc>>,
    pub updated_at: DateTime<Utc>,
}

/// One retro-hunt execution's history row (`retro_hunt_runs`).
#[derive(Debug, Clone, Serialize, Deserialize, FromRow, utoipa::ToSchema)]
pub struct RetroHuntRun {
    pub id: i64,
    #[serde(with = "crate::typeid::rule")]
    #[schema(value_type = String)]
    pub rule_id: Uuid,
    pub started_at: DateTime<Utc>,
    pub finished_at: Option<DateTime<Utc>>,
    /// `running` | `ok` | `error`.
    pub status: String,
    /// Distinct candidate indicators considered (post filter, pre cap).
    pub candidates_considered: i32,
    /// Indicators actually hunted this run (<= cap).
    pub indicators_hunted: i32,
    /// Indicators found in historical logs (emitted as signals/alerts).
    pub hits: i32,
    /// The per-run cap truncated the batch this run.
    pub truncated: bool,
    /// Best-effort count of candidates carried to the next run.
    pub overflow_remaining: i32,
    pub watermark_before: Option<DateTime<Utc>>,
    pub watermark_after: Option<DateTime<Utc>>,
    pub error: Option<String>,
}

/// Combined view returned by `GET /api/rules/{id}/retro-hunt`: the rule's
/// retro-hunt config plus its current delta state.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct RetroHuntRuleView {
    pub config: RetroHuntConfig,
    pub state: Option<RetroHuntState>,
}

/// Request body for `POST /api/rules/retro-hunt` (create a retro-hunt rule).
///
/// Reuses the standard detection-rule metadata (name/severity/mode/cron/…) and
/// adds the retro-hunt config. `mode` defaults to `live` (bake-in) and `cron`
/// to [`DEFAULT_RETRO_HUNT_CRON`] when omitted.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct CreateRetroHuntRequest {
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub severity: Option<crate::models::Severity>,
    /// Rule mode: `live` (default, bake-in) or `alerting`.
    #[serde(default)]
    pub mode: Option<crate::models::RuleMode>,
    /// Cron schedule; defaults to [`DEFAULT_RETRO_HUNT_CRON`].
    #[serde(default)]
    pub schedule_cron: Option<String>,
    #[serde(default)]
    pub folder: Option<String>,
    #[serde(default)]
    pub tags: Option<Vec<String>>,
    /// Selected feed names; empty/omitted = ALL feeds.
    #[serde(default)]
    pub feeds: Vec<String>,
    /// Artifact-type filter; empty/omitted = ALL types.
    #[serde(default)]
    pub artifact_types: Vec<String>,
    /// Lookback window (days); defaults to [`DEFAULT_RETRO_HUNT_LOOKBACK_DAYS`].
    #[serde(default)]
    pub lookback_days: Option<i32>,
    /// Per-run indicator cap; defaults to [`DEFAULT_RETRO_HUNT_MAX_INDICATORS`].
    #[serde(default)]
    pub max_indicators_per_run: Option<i32>,
    /// Base risk score (0-100) for emitted findings.
    #[serde(default)]
    pub risk_score: Option<i32>,
}

/// Request body for `PUT /api/rules/{id}/retro-hunt` (update config). All fields
/// optional; omitted fields are left unchanged.
#[derive(Debug, Clone, Default, Serialize, Deserialize, utoipa::ToSchema)]
pub struct UpdateRetroHuntConfigRequest {
    #[serde(default)]
    pub feeds: Option<Vec<String>>,
    #[serde(default)]
    pub artifact_types: Option<Vec<String>>,
    #[serde(default)]
    pub lookback_days: Option<i32>,
    #[serde(default)]
    pub max_indicators_per_run: Option<i32>,
}

/// Validation error for retro-hunt config fields.
#[derive(Debug, Clone, PartialEq)]
pub enum RetroHuntConfigValidationError {
    /// lookback_days is out of the 1..=365 range.
    LookbackOutOfBounds(i32),
    /// max_indicators_per_run is out of the 1..=1000 range.
    MaxIndicatorsOutOfBounds(i32),
    /// An artifact type is not one of ip/domain/hash/url.
    InvalidArtifactType(String),
}

impl std::fmt::Display for RetroHuntConfigValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::LookbackOutOfBounds(v) => write!(
                f,
                "lookback_days {v} is out of bounds (must be 1-{MAX_RETRO_HUNT_LOOKBACK_DAYS})"
            ),
            Self::MaxIndicatorsOutOfBounds(v) => write!(
                f,
                "max_indicators_per_run {v} is out of bounds (must be 1-{MAX_RETRO_HUNT_MAX_INDICATORS})"
            ),
            Self::InvalidArtifactType(t) => write!(
                f,
                "invalid artifact_type '{t}' (must be one of ip/domain/hash/url)"
            ),
        }
    }
}

impl std::error::Error for RetroHuntConfigValidationError {}

/// Validate a lookback/cap/artifact-type triple against the shared bounds.
/// `None` fields (a partial update) are skipped.
pub fn validate_retro_hunt_fields(
    lookback_days: Option<i32>,
    max_indicators_per_run: Option<i32>,
    artifact_types: Option<&[String]>,
) -> Result<(), RetroHuntConfigValidationError> {
    if let Some(days) = lookback_days {
        if !(1..=MAX_RETRO_HUNT_LOOKBACK_DAYS).contains(&days) {
            return Err(RetroHuntConfigValidationError::LookbackOutOfBounds(days));
        }
    }
    if let Some(cap) = max_indicators_per_run {
        if !(1..=MAX_RETRO_HUNT_MAX_INDICATORS).contains(&cap) {
            return Err(RetroHuntConfigValidationError::MaxIndicatorsOutOfBounds(cap));
        }
    }
    if let Some(types) = artifact_types {
        for t in types {
            if !VALID_RETRO_HUNT_ARTIFACT_TYPES.contains(&t.as_str()) {
                return Err(RetroHuntConfigValidationError::InvalidArtifactType(t.clone()));
            }
        }
    }
    Ok(())
}

impl CreateRetroHuntRequest {
    /// Validate the retro-hunt config fields (bounds + artifact types).
    pub fn validate(&self) -> Result<(), RetroHuntConfigValidationError> {
        validate_retro_hunt_fields(
            self.lookback_days,
            self.max_indicators_per_run,
            Some(&self.artifact_types),
        )
    }
}

impl UpdateRetroHuntConfigRequest {
    /// Validate the retro-hunt config fields being patched.
    pub fn validate(&self) -> Result<(), RetroHuntConfigValidationError> {
        validate_retro_hunt_fields(
            self.lookback_days,
            self.max_indicators_per_run,
            self.artifact_types.as_deref(),
        )
    }
}

#[cfg(test)]
mod tests;
