// SPDX-License-Identifier: AGPL-3.0-or-later

//! Data models for the playbook library

use chrono::{DateTime, NaiveDate, Utc};
use serde::{Deserialize, Deserializer, Serialize};
use sqlx::FromRow;
use std::collections::HashMap;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::typeid;

// =============================================================================
// Enums (stored as TEXT in Postgres; serialized as lowercase strings)
// =============================================================================

/// Playbook category. Must match CHECK constraint in migrations/postgres/157_playbooks.sql.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum PlaybookCategory {
    Identity,
    Endpoint,
    Cloud,
    Data,
    Network,
    Email,
}

impl PlaybookCategory {
    pub fn as_str(&self) -> &'static str {
        match self {
            PlaybookCategory::Identity => "identity",
            PlaybookCategory::Endpoint => "endpoint",
            PlaybookCategory::Cloud => "cloud",
            PlaybookCategory::Data => "data",
            PlaybookCategory::Network => "network",
            PlaybookCategory::Email => "email",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "identity" => Some(PlaybookCategory::Identity),
            "endpoint" => Some(PlaybookCategory::Endpoint),
            "cloud" => Some(PlaybookCategory::Cloud),
            "data" => Some(PlaybookCategory::Data),
            "network" => Some(PlaybookCategory::Network),
            "email" => Some(PlaybookCategory::Email),
            _ => None,
        }
    }
}

/// Playbook status / lifecycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum PlaybookStatus {
    Draft,
    PendingReview,
    Live,
    Archived,
}

impl PlaybookStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            PlaybookStatus::Draft => "draft",
            PlaybookStatus::PendingReview => "pending_review",
            PlaybookStatus::Live => "live",
            PlaybookStatus::Archived => "archived",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "draft" => Some(PlaybookStatus::Draft),
            "pending_review" => Some(PlaybookStatus::PendingReview),
            "live" => Some(PlaybookStatus::Live),
            "archived" => Some(PlaybookStatus::Archived),
            _ => None,
        }
    }
}

/// Playbook scope.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum PlaybookScope {
    Tenant,
    Environment,
}

impl PlaybookScope {
    pub fn as_str(&self) -> &'static str {
        match self {
            PlaybookScope::Tenant => "tenant",
            PlaybookScope::Environment => "environment",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "tenant" => Some(PlaybookScope::Tenant),
            "environment" => Some(PlaybookScope::Environment),
            _ => None,
        }
    }
}

// =============================================================================
// Adaptive Source
// =============================================================================

/// Metadata for an agent-composed (adaptive) playbook.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct AdaptiveSource {
    #[serde(with = "typeid::case::opt", default)]
    #[schema(value_type = Option<String>)]
    pub case_id: Option<Uuid>,
    pub composed_at: Option<DateTime<Utc>>,
    pub composed_by: Option<String>,
    #[serde(default)]
    pub based_on: Vec<String>,
}

/// Per-danger-level policy, e.g. `{"action:high": "approval", "action:medium": "auto"}`.
pub type DangerPolicy = HashMap<String, String>;

// =============================================================================
// Main Playbook
// =============================================================================

/// A playbook row from the `playbooks` table.
#[derive(Debug, Clone, Serialize, Deserialize, FromRow, ToSchema)]
pub struct Playbook {
    #[serde(with = "typeid::playbook")]
    #[schema(value_type = String)]
    pub id: Uuid,
    pub title: String,
    pub subtitle: Option<String>,
    pub category: String,
    pub doc: String,
    pub parsed_steps: Option<serde_json::Value>,
    pub match_signals: Vec<String>,
    pub danger_policy: serde_json::Value,
    pub review_cadence: String,
    pub scope: String,
    pub tags: Vec<String>,
    pub owner_team: Option<String>,
    #[serde(default, with = "typeid::user::opt")]
    #[schema(value_type = Option<String>)]
    pub maintainer_user_id: Option<Uuid>,
    pub status: String,
    pub current_version: i32,
    pub adaptive: bool,
    pub adaptive_source: Option<serde_json::Value>,
    pub promoted: bool,
    #[serde(default, with = "typeid::playbook_repo::opt")]
    #[schema(value_type = Option<String>)]
    pub source_repository_id: Option<Uuid>,
    pub source_playbook_path: Option<String>,
    pub source_linked: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    #[serde(default, with = "typeid::user::opt")]
    #[schema(value_type = Option<String>)]
    pub created_by: Option<Uuid>,
    pub last_reviewed_at: Option<DateTime<Utc>>,
    pub next_review_due_at: Option<DateTime<Utc>>,
}

// =============================================================================
// Versions / Runs / Permissions / Approvals
// =============================================================================

#[derive(Debug, Clone, Serialize, Deserialize, FromRow, ToSchema)]
pub struct PlaybookVersion {
    #[serde(with = "typeid::playbook_version")]
    #[schema(value_type = String)]
    pub id: Uuid,
    #[serde(with = "typeid::playbook")]
    #[schema(value_type = String)]
    pub playbook_id: Uuid,
    pub version: i32,
    pub doc: String,
    pub metadata: serde_json::Value,
    pub note: Option<String>,
    pub diff_added: i32,
    pub diff_removed: i32,
    #[serde(default, with = "typeid::user::opt")]
    #[schema(value_type = Option<String>)]
    pub author_id: Option<Uuid>,
    pub author_name: Option<String>,
    #[serde(default, with = "typeid::case::opt")]
    #[schema(value_type = Option<String>)]
    pub promoted_from_case_id: Option<Uuid>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow, ToSchema)]
pub struct PlaybookRun {
    #[serde(with = "typeid::playbook_run")]
    #[schema(value_type = String)]
    pub id: Uuid,
    #[serde(with = "typeid::playbook")]
    #[schema(value_type = String)]
    pub playbook_id: Uuid,
    pub playbook_version: i32,
    #[serde(with = "typeid::case")]
    #[schema(value_type = String)]
    pub case_id: Uuid,
    pub started_at: DateTime<Utc>,
    pub finished_at: Option<DateTime<Utc>>,
    pub status: String,
    #[serde(default, with = "typeid::user::opt")]
    #[schema(value_type = Option<String>)]
    pub operator_user_id: Option<Uuid>,
    pub operator_label: Option<String>,
    pub outcome: Option<String>,
    pub ttr_minutes: Option<i32>,
    pub step_completion: Option<serde_json::Value>,
    /// NAN-462: frozen snapshot of `{case, alert, rule, source_type,
    /// top_matched_event, entities}` captured at attach time. Consumed by
    /// the templating engine at render time (see `playbooks::runtime`).
    /// Null for manual-attach runs without alert context.
    #[sqlx(default)]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub run_context: Option<serde_json::Value>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow, ToSchema)]
pub struct PlaybookPermission {
    #[serde(with = "typeid::playbook")]
    #[schema(value_type = String)]
    pub playbook_id: Uuid,
    /// Display label. AUTHORITATIVE only for the reserved synthetic principals
    /// (`api_key`, `demo_analyst`), which carry `role_id = None`.
    pub role: String,
    /// NAN-2097: the STABLE ACL key for a real role. `None` only for the
    /// synthetic principals above. Matching on the id rather than the name is
    /// what makes an entry survive a role rename, prevents a later role reusing
    /// the name from capturing the grant, and lets `ON DELETE RESTRICT` require
    /// an operator to unwind grants explicitly before deleting a role.
    #[serde(with = "typeid::role::opt")]
    #[schema(value_type = Option<String>)]
    pub role_id: Option<Uuid>,
    pub can_view: bool,
    pub can_run: bool,
    pub can_edit: bool,
    pub can_publish: bool,
    pub member_count: Option<i32>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow, ToSchema)]
pub struct PlaybookApproval {
    #[serde(with = "typeid::playbook_approval")]
    #[schema(value_type = String)]
    pub id: Uuid,
    #[serde(with = "typeid::playbook")]
    #[schema(value_type = String)]
    pub playbook_id: Uuid,
    pub version: i32,
    #[serde(default, with = "typeid::user::opt")]
    #[schema(value_type = Option<String>)]
    pub requester_id: Option<Uuid>,
    #[serde(default, with = "typeid::user::opt")]
    #[schema(value_type = Option<String>)]
    pub approver_id: Option<Uuid>,
    pub status: String,
    pub message: Option<String>,
    pub response: Option<String>,
    pub requested_at: DateTime<Utc>,
    pub responded_at: Option<DateTime<Utc>>,
}

// =============================================================================
// Request DTOs
// =============================================================================

/// Request body for creating a playbook.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct CreatePlaybookRequest {
    pub title: String,
    #[serde(default)]
    pub subtitle: Option<String>,
    pub category: PlaybookCategory,
    pub doc: String,
    #[serde(default)]
    pub match_signals: Vec<String>,
    #[serde(default)]
    pub danger_policy: Option<DangerPolicy>,
    #[serde(default)]
    pub review_cadence: Option<String>,
    #[serde(default)]
    pub scope: Option<PlaybookScope>,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub owner_team: Option<String>,
    #[serde(default)]
    pub status: Option<PlaybookStatus>,
    #[serde(default)]
    pub adaptive: Option<bool>,
    #[serde(default)]
    pub adaptive_source: Option<AdaptiveSource>,
    #[serde(default)]
    pub source_playbook_path: Option<String>,
    /// ID of the source playbook repository, if this import originates from one.
    #[serde(default, with = "typeid::playbook_repo::opt")]
    #[schema(value_type = Option<String>)]
    pub source_repository_id: Option<Uuid>,
    #[serde(default)]
    pub source_linked: Option<bool>,
}

/// Request body for updating a playbook. All fields optional.
#[derive(Debug, Clone, Default, Serialize, Deserialize, ToSchema)]
pub struct UpdatePlaybookRequest {
    pub title: Option<String>,
    pub subtitle: Option<String>,
    pub category: Option<PlaybookCategory>,
    pub doc: Option<String>,
    pub match_signals: Option<Vec<String>>,
    pub danger_policy: Option<DangerPolicy>,
    pub review_cadence: Option<String>,
    pub scope: Option<PlaybookScope>,
    pub tags: Option<Vec<String>>,
    pub owner_team: Option<String>,
    pub status: Option<PlaybookStatus>,
    /// Author-supplied change note (saved onto the new version).
    pub note: Option<String>,
}

/// Filter/sort parameters for listing playbooks.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ListPlaybooksQuery {
    pub category: Option<PlaybookCategory>,
    pub status: Option<PlaybookStatus>,
    /// Match a single signal (search for playbooks whose match_signals contains it).
    pub signal: Option<String>,
    /// Free-text search over title/subtitle.
    pub search: Option<String>,
    /// Sort mode: "recent" | "title" | "attached" (default: recent).
    pub sort: Option<String>,
    pub limit: Option<i64>,
    pub offset: Option<i64>,
    /// Filter to adaptive playbooks only (true) or exclude them (false).
    pub adaptive: Option<bool>,
}

/// Request body for forking a playbook.
#[derive(Debug, Clone, Default, Serialize, Deserialize, ToSchema)]
pub struct ForkPlaybookRequest {
    pub title: Option<String>,
    pub owner_team: Option<String>,
}

// =============================================================================
// Response DTOs
// =============================================================================

/// Response for listing playbooks.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct PlaybookListResponse {
    pub playbooks: Vec<Playbook>,
    pub total: i64,
}

// =============================================================================
// Parser output shape
// =============================================================================

/// Result of parsing a playbook doc into a step tree.
#[derive(Debug, Clone, Default, Serialize, Deserialize, ToSchema)]
pub struct ParsedStepTree {
    pub title: String,
    #[serde(default)]
    pub intro: Vec<String>,
    #[serde(default)]
    pub phases: Vec<PlaybookPhase>,
    /// Steps that appeared outside a phase (rare — most playbooks use H2 phases).
    #[serde(default)]
    pub steps: Vec<PlaybookStep>,
}

/// A phase (H2 heading) within a playbook.
#[derive(Debug, Clone, Default, Serialize, Deserialize, ToSchema)]
pub struct PlaybookPhase {
    pub heading: String,
    #[serde(default)]
    pub body: Vec<String>,
    #[serde(default)]
    pub steps: Vec<PlaybookStep>,
}

/// A single slash-command step inside a phase.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct PlaybookStep {
    pub id: String,
    /// Slash command kind: `query` | `pivot` | `enrichment` | `decision` | `action` | `review` | `note`.
    pub kind: String,
    pub label: String,
    #[serde(default)]
    pub params: serde_json::Value,
    /// Only present if the doc provided `_auto_result:`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auto_result: Option<serde_json::Value>,
    /// Decision-only: the agent's suggested answer.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub suggested: Option<serde_json::Value>,
    /// Decision-only: confidence 0..1.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub suggested_conf: Option<f64>,
    /// Decision-only: comma-separated list of options that require a note.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note_required_on: Option<String>,
    /// Decision-only: option list.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub options: Option<Vec<serde_json::Value>>,
    /// Short decision id (e.g. "d1") that other steps may reference in `when:` clauses.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decision_id: Option<String>,
    /// Parsed `when:` clause, if present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub when: Option<WhenClause>,
}

/// Parsed `when:` clause.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct WhenClause {
    /// The decision id being referenced.
    #[serde(rename = "ref")]
    pub ref_id: String,
    pub op: WhenOp,
    pub values: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum WhenOp {
    /// Equality: `when: d1 = yes`.
    #[serde(rename = "=")]
    Eq,
    /// Set membership: `when: d1 in [yes, partial]`.
    In,
}

impl WhenOp {
    pub fn as_str(&self) -> &'static str {
        match self {
            WhenOp::Eq => "=",
            WhenOp::In => "in",
        }
    }
}

// =============================================================================
// Frontmatter
// =============================================================================

/// YAML frontmatter pulled from the top of a playbook doc.
#[derive(Debug, Clone, Default, Serialize, Deserialize, ToSchema)]
pub struct PlaybookFrontmatter {
    #[serde(default)]
    pub title: Option<String>,
    #[serde(default)]
    pub subtitle: Option<String>,
    #[serde(default)]
    pub category: Option<String>,
    #[serde(default)]
    pub owner: Option<String>,
    #[serde(default, deserialize_with = "deserialize_optional_naive_date")]
    pub authored: Option<NaiveDate>,
    #[serde(default)]
    pub match_signals: Vec<String>,
    #[serde(default)]
    pub danger_policy: HashMap<String, String>,
    #[serde(default)]
    pub review_cadence: Option<String>,
    #[serde(default)]
    pub scope: Option<String>,
    #[serde(default)]
    pub tags: Vec<String>,
}

/// Helper: accept either a NaiveDate or a string (empty → None).
fn deserialize_optional_naive_date<'de, D>(d: D) -> Result<Option<NaiveDate>, D::Error>
where
    D: Deserializer<'de>,
{
    let opt: Option<String> = Option::deserialize(d)?;
    match opt {
        None => Ok(None),
        Some(s) if s.is_empty() => Ok(None),
        Some(s) => NaiveDate::parse_from_str(&s, "%Y-%m-%d")
            .map(Some)
            .map_err(serde::de::Error::custom),
    }
}

// ============================================================================
// NAN-445 — Phase 4: rule/case auto-attach + suggest.
// ============================================================================

/// A scored playbook suggestion for a given rule or case.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct PlaybookSuggestion {
    pub playbook: Playbook,
    /// Total match score. Signal hits weight heavier than category-only matches.
    pub score: i32,
    /// Which of the rule's signals matched `playbook.match_signals`.
    pub matched_signals: Vec<String>,
    /// True if the rule's folder equals playbook.category (matches even when
    /// no explicit signal overlap).
    pub matched_by_category: bool,
}

/// Body for `POST /api/playbooks/{id}/runs` — attach a playbook to a case.
#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct AttachToCaseRequest {
    /// Case typeid (`case_*`) or bare UUID.
    #[serde(with = "typeid::case")]
    #[schema(value_type = String)]
    pub case_id: Uuid,
    /// Playbook version to pin the run to; defaults to current_version.
    #[serde(default)]
    pub version: Option<i32>,
}

/// Body for `PATCH /api/playbook-runs/{id}` — finish a run.
#[derive(Debug, Clone, Default, Deserialize, ToSchema)]
pub struct FinishRunRequest {
    /// Free-form disposition; matches the Analytics tab's `outcome` filter.
    #[serde(default)]
    pub outcome: Option<String>,
    /// Per-step completion / skip state. JSONB blob; shape is
    /// `{ step_id: { completed_at?, skipped?, operator_note? }, ... }`.
    #[serde(default)]
    pub step_completion: Option<serde_json::Value>,
    /// NAN-475: optional closing note from the analyst. Stored under the
    /// synthetic step id `__run__` in `step_completion` so it co-locates
    /// with the documented per-step schema (`operator_note` field) without
    /// needing a dedicated column.
    #[serde(default)]
    pub note: Option<String>,
}

// ============================================================================
// NAN-447 — Phase 6: approval workflow + per-role permissions.
// ============================================================================

/// Body for `POST /api/playbooks/{id}/submit-for-review`.
#[derive(Debug, Clone, Default, Deserialize, ToSchema)]
pub struct SubmitForReviewRequest {
    /// Active user to assign the review to. They must currently hold
    /// `playbooks:publish` and this playbook's publish ACL grant. Optional — if
    /// omitted, any publisher with both grants can respond. If a named reviewer
    /// later loses either grant, another eligible publisher may recover the
    /// pending review.
    #[serde(default, with = "typeid::user::opt")]
    #[schema(value_type = Option<String>)]
    pub approver_id: Option<Uuid>,
    /// Requester's note to the approver.
    #[serde(default)]
    pub message: Option<String>,
}

/// Body for `POST /api/playbook-approvals/{id}/approve` and `.../reject`.
#[derive(Debug, Clone, Default, Deserialize, ToSchema)]
pub struct ApprovalResponseRequest {
    /// Approver's response note (free-form).
    #[serde(default)]
    pub response: Option<String>,
}

// ============================================================================
// NAN-448 — Phase 7: real analytics.
// ============================================================================

/// Aggregated analytics for a playbook, computed from `playbook_runs`.
/// Returned by `GET /api/playbooks/{id}/analytics`.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct PlaybookAnalytics {
    /// Total runs attached to cases (last 30 days).
    pub attached: i64,
    /// Runs the agent/operator actually started (currently == attached).
    pub started: i64,
    /// Runs in `status='resolved'` (last 30 days).
    pub finished: i64,
    /// Placeholder for "evidence promoted" — 0 until evidence tracking lands.
    pub evd: i64,
    /// Median TTR in minutes across resolved runs (last 90 days). None if no
    /// runs yet.
    pub ttr_median_min: Option<f64>,
    /// Hours since the most recent run started. None if no runs yet.
    pub hours_since_last_run: Option<f64>,
    /// 30 daily attach counts, oldest → newest.
    pub spark_30d: Vec<i64>,
}

// ============================================================================
// NAN-447 — Phase 6: approval workflow + per-role permissions (continued).
// ============================================================================

/// Body for `PUT /api/playbooks/{id}/permissions/{role}`.
#[derive(Debug, Clone, Default, Deserialize, ToSchema)]
pub struct SetPermissionRequest {
    #[serde(default)]
    pub can_view: bool,
    #[serde(default)]
    pub can_run: bool,
    #[serde(default)]
    pub can_edit: bool,
    #[serde(default)]
    pub can_publish: bool,
    /// Optional cached member count for the detail view.
    #[serde(default)]
    pub member_count: Option<i32>,
}

/// NAN-463 — body for `PATCH /api/playbook-runs/{run_id}/steps/{step_id}`.
///
/// Only fields present in the request overwrite the corresponding fields
/// on the step's `step_completion` entry. Omitting a field preserves what
/// was there (e.g. toggling `completed` without clobbering the note).
#[derive(Debug, Clone, Default, Deserialize, ToSchema)]
pub struct UpdateStepCompletionRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub completed: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub skipped: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

/// NAN-462 — response body for `GET /api/playbook-runs/{id}/resolved`.
///
/// Returns the parsed playbook doc with `{{...}}` tokens substituted
/// against the run's frozen [`crate::playbooks::runtime::RunContext`]
/// snapshot. Legacy runs (created before the run_context column shipped)
/// and manual-attach runs without alert context surface as
/// `has_context = false`; the tree is still parsed so the UI can render
/// it, but token substitution is a no-op.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct ResolvedRunResponse {
    /// Whether a `run_context` snapshot was present on the run.
    pub has_context: bool,
    /// Parsed step tree with `{{...}}` tokens substituted.
    pub tree: ParsedStepTree,
    /// Paths whose namespace was unresolved — useful for the UI's
    /// "missing context" indicator. Empty when `has_context = false`.
    pub unresolved: Vec<String>,
}
