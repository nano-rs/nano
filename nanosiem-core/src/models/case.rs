// SPDX-License-Identifier: AGPL-3.0-or-later

//! Case Management models
//!
//! Full case-centric workflow for SOC investigations

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

use super::Severity;
use crate::typeid;

// =============================================================================
// ENUMS
// =============================================================================

/// Case status
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type, utoipa::ToSchema,
)]
#[sqlx(type_name = "text", rename_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum CaseStatus {
    Open,
    InProgress,
    Pending,
    Resolved,
    Closed,
}

impl Default for CaseStatus {
    fn default() -> Self {
        Self::Open
    }
}

impl std::fmt::Display for CaseStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Open => write!(f, "open"),
            Self::InProgress => write!(f, "in_progress"),
            Self::Pending => write!(f, "pending"),
            Self::Resolved => write!(f, "resolved"),
            Self::Closed => write!(f, "closed"),
        }
    }
}

/// Case disposition when closed
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type, utoipa::ToSchema,
)]
#[sqlx(type_name = "text", rename_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum CaseDisposition {
    TruePositive,
    FalsePositive,
    Benign,
    Inconclusive,
    Merged,
}

/// AI-recommended disposition from the shadow investigator (NAN-1251).
///
/// Mirrors `CaseDisposition` but adds `NeedsInvestigation` — the third verdict
/// the LLM already emits, which has no human-disposition equivalent (an analyst
/// who can't decide leaves the case open rather than dispositioning it). Kept a
/// separate type so the AI's recommendation is never confused with the human's
/// final `disposition`.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type, utoipa::ToSchema,
)]
#[sqlx(type_name = "text", rename_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum AiDisposition {
    TruePositive,
    FalsePositive,
    Benign,
    Inconclusive,
    NeedsInvestigation,
}

impl AiDisposition {
    /// Wire/DB string form (`snake_case`).
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::TruePositive => "true_positive",
            Self::FalsePositive => "false_positive",
            Self::Benign => "benign",
            Self::Inconclusive => "inconclusive",
            Self::NeedsInvestigation => "needs_investigation",
        }
    }

    /// Parse the verdict string the LLM returns. Tolerant of the common
    /// phrasings the model emits ("needs further investigation", spaces, case).
    pub fn parse_verdict(raw: &str) -> Option<Self> {
        let n = raw.trim().to_lowercase().replace([' ', '-'], "_");
        match n.as_str() {
            "true_positive" | "tp" | "malicious" => Some(Self::TruePositive),
            "false_positive" | "fp" => Some(Self::FalsePositive),
            "benign" | "legitimate" => Some(Self::Benign),
            "inconclusive" | "unknown" => Some(Self::Inconclusive),
            s if s.starts_with("needs") => Some(Self::NeedsInvestigation),
            _ => None,
        }
    }

    /// True when this verdict warrants human attention (floats to the
    /// "Must Investigate" inbox bucket). FP/benign/inconclusive do not.
    pub fn is_actionable(&self) -> bool {
        matches!(self, Self::TruePositive | Self::NeedsInvestigation)
    }
}

/// Grouping type for auto-case creation
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type, utoipa::ToSchema,
)]
#[sqlx(type_name = "text", rename_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum GroupingType {
    Host,
    User,
    Rule,
    Ip,
    Manual,
}

impl std::fmt::Display for GroupingType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Host => write!(f, "host"),
            Self::User => write!(f, "user"),
            Self::Rule => write!(f, "rule"),
            Self::Ip => write!(f, "ip"),
            Self::Manual => write!(f, "manual"),
        }
    }
}

impl std::str::FromStr for GroupingType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "host" => Ok(Self::Host),
            "user" => Ok(Self::User),
            "rule" => Ok(Self::Rule),
            "ip" => Ok(Self::Ip),
            "manual" => Ok(Self::Manual),
            _ => Err(format!("Unknown grouping type: {}", s)),
        }
    }
}

/// Entity type for case entities
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type, utoipa::ToSchema,
)]
#[sqlx(type_name = "text", rename_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum CaseEntityType {
    User,
    Host,
    Ip,
    Domain,
    Hash,
    Url,
    File,
    Process,
    Email,
}

impl std::fmt::Display for CaseEntityType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::User => write!(f, "user"),
            Self::Host => write!(f, "host"),
            Self::Ip => write!(f, "ip"),
            Self::Domain => write!(f, "domain"),
            Self::Hash => write!(f, "hash"),
            Self::Url => write!(f, "url"),
            Self::File => write!(f, "file"),
            Self::Process => write!(f, "process"),
            Self::Email => write!(f, "email"),
        }
    }
}

/// Case wall entry type
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type, utoipa::ToSchema,
)]
#[sqlx(type_name = "text", rename_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum CaseWallEntryType {
    Comment,
    StatusChange,
    AssignmentChange,
    AlertAdded,
    AlertRemoved,
    EntityAdded,
    EnrichmentResult,
    AiAnalysis,
    ActionTaken,
    Attachment,
    System,
}

/// Case relation type
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type, utoipa::ToSchema,
)]
#[sqlx(type_name = "text", rename_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum CaseRelationType {
    Related,
    Parent,
    Child,
    Duplicate,
}

/// Severity rule for case grouping
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type, utoipa::ToSchema,
)]
#[sqlx(type_name = "text", rename_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum SeverityRule {
    Highest,
    Lowest,
    First,
    MostCommon,
}

impl Default for SeverityRule {
    fn default() -> Self {
        Self::Highest
    }
}

// =============================================================================
// CASE MODEL
// =============================================================================

/// A security investigation case containing grouped alerts
#[derive(Debug, Clone, Serialize, Deserialize, FromRow, utoipa::ToSchema)]
pub struct Case {
    #[serde(with = "typeid::case")]
    #[schema(value_type = String)]
    pub id: Uuid,
    pub case_number: i32,
    pub title: String,
    pub description: Option<String>,
    pub severity: String,
    pub status: String,
    pub disposition: Option<String>,
    pub priority: i32,

    // Assignment
    #[serde(default, with = "typeid::user::opt")]
    #[schema(value_type = Option<String>)]
    pub assigned_to: Option<Uuid>,
    pub assigned_at: Option<DateTime<Utc>>,
    #[serde(default, with = "typeid::group::opt")]
    #[schema(value_type = Option<String>)]
    pub assigned_group: Option<Uuid>,
    pub assigned_group_at: Option<DateTime<Utc>>,

    // AI Summary
    pub ai_summary: Option<String>,
    pub ai_recommendations: Option<serde_json::Value>,
    pub ai_summary_generated_at: Option<DateTime<Utc>>,

    // AI Tier-1 triage verdict (NAN-1251). Structured shadow-investigator
    // recommendation, kept distinct from the human `disposition` above.
    #[serde(default)]
    pub ai_disposition: Option<String>,
    #[serde(default)]
    pub ai_confidence: Option<f64>,
    #[serde(default)]
    pub ai_recommended_action: Option<String>,
    /// AI-recommended severity (NAN-1297). Drives symmetric re-triage:
    /// escalate severity + priority on actionable verdicts.
    #[serde(default)]
    pub ai_recommended_severity: Option<String>,
    #[serde(default)]
    pub ai_key_evidence: Option<serde_json::Value>,
    #[serde(default)]
    pub ai_triaged_at: Option<DateTime<Utc>>,

    // Retroactive revision (NAN-1251 P3) — set when a later case escalated a
    // shared entity this case had closed as FP/benign.
    #[serde(default)]
    pub needs_review: bool,
    #[serde(default)]
    pub needs_review_reason: Option<String>,
    #[serde(default)]
    pub needs_review_at: Option<DateTime<Utc>>,

    // Auto-close marker (NAN-1251 P4) — true when the AI Tier-1 triage closed
    // this case. Cleared on reopen.
    #[serde(default)]
    pub ai_closed: bool,

    // Grouping
    pub grouping_key: Option<String>,
    pub grouping_type: Option<String>,

    // MITRE ATT&CK
    pub mitre_tactics: Vec<String>,
    pub mitre_techniques: Vec<String>,

    // Timestamps
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub first_activity_at: Option<DateTime<Utc>>,
    pub last_activity_at: Option<DateTime<Utc>>,
    pub resolved_at: Option<DateTime<Utc>>,
    #[serde(default, with = "typeid::user::opt")]
    #[schema(value_type = Option<String>)]
    pub resolved_by: Option<Uuid>,
    pub closed_at: Option<DateTime<Utc>>,
    #[serde(default, with = "typeid::user::opt")]
    #[schema(value_type = Option<String>)]
    pub closed_by: Option<Uuid>,

    // SLA tracking timestamps
    pub first_response_at: Option<DateTime<Utc>>,
    pub triage_completed_at: Option<DateTime<Utc>>,

    // Visibility and ownership
    pub visibility: String,
    #[serde(default, with = "typeid::user::opt")]
    #[schema(value_type = Option<String>)]
    pub created_by: Option<Uuid>,

    // Workflow persistence (NAN-415) — populated via `SELECT *`.
    #[serde(default)]
    pub close_reason: Option<String>,
    #[serde(default)]
    pub pending_kind: Option<String>,
    #[serde(default)]
    pub pending_target: Option<String>,
    #[serde(default)]
    pub pending_since: Option<DateTime<Utc>>,
}

/// Case with additional computed fields for list views
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct CaseWithDetails {
    #[serde(with = "typeid::case")]
    #[schema(value_type = String)]
    pub id: Uuid,
    pub case_number: i32,
    pub title: String,
    pub description: Option<String>,
    pub severity: String,
    pub status: String,
    pub disposition: Option<String>,
    pub priority: i32,
    #[serde(default, with = "typeid::user::opt")]
    #[schema(value_type = Option<String>)]
    pub assigned_to: Option<Uuid>,
    pub assigned_at: Option<DateTime<Utc>>,
    #[serde(default, with = "typeid::group::opt")]
    #[schema(value_type = Option<String>)]
    pub assigned_group: Option<Uuid>,
    pub assigned_group_at: Option<DateTime<Utc>>,
    pub ai_summary: Option<String>,
    // AI Tier-1 triage verdict (NAN-1251) — surfaced on list rows + the
    // elevated-case verdict strip.
    #[serde(default)]
    pub ai_disposition: Option<String>,
    #[serde(default)]
    pub ai_confidence: Option<f64>,
    #[serde(default)]
    pub ai_recommended_action: Option<String>,
    #[serde(default)]
    pub ai_recommended_severity: Option<String>,
    #[serde(default)]
    pub ai_key_evidence: Option<serde_json::Value>,
    #[serde(default)]
    pub ai_triaged_at: Option<DateTime<Utc>>,
    // Retroactive revision flag (NAN-1251 P3).
    #[serde(default)]
    pub needs_review: bool,
    #[serde(default)]
    pub needs_review_reason: Option<String>,
    #[serde(default)]
    pub needs_review_at: Option<DateTime<Utc>>,
    // Auto-close marker (NAN-1251 P4).
    #[serde(default)]
    pub ai_closed: bool,
    pub grouping_type: Option<String>,
    pub mitre_tactics: Vec<String>,
    pub mitre_techniques: Vec<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub first_activity_at: Option<DateTime<Utc>>,
    pub last_activity_at: Option<DateTime<Utc>>,
    // Visibility and ownership
    pub visibility: String,
    #[serde(default, with = "typeid::user::opt")]
    #[schema(value_type = Option<String>)]
    pub created_by: Option<Uuid>,
    pub creator_name: Option<String>,
    #[serde(default)]
    pub shared_groups: Vec<SharedGroup>,
    #[serde(default)]
    pub is_creator: bool,
    // SLA tracking timestamps
    pub first_response_at: Option<DateTime<Utc>>,
    pub triage_completed_at: Option<DateTime<Utc>>,
    // Computed fields
    pub alert_count: i64,
    pub entity_count: i64,
    pub assignee_name: Option<String>,
    pub assigned_group_name: Option<String>,
    // Workflow persistence (NAN-415)
    #[serde(default)]
    pub close_reason: Option<String>,
    #[serde(default)]
    pub pending_kind: Option<String>,
    #[serde(default)]
    pub pending_target: Option<String>,
    #[serde(default)]
    pub pending_since: Option<DateTime<Utc>>,
    // Incident linkage (NAN-417)
    #[serde(default, with = "typeid::incident::opt")]
    #[schema(value_type = Option<String>)]
    pub incident_id: Option<Uuid>,
    /// Parent-incident summary, populated by the repo after a LEFT JOIN.
    /// `None` when the case is not attached to an incident.
    #[serde(default)]
    pub incident: Option<super::incident::IncidentSummary>,
    /// Derived pending-state snapshot. Mirrors what `GET /api/cases/{id}`
    /// returns so the list + detail surfaces can share indicator code.
    /// `None` when the case has no active pending state.
    #[serde(default)]
    pub pending_state: Option<CasePendingState>,
    /// Latest open peer-to-peer handoff on this case (NAN-420). `None` when
    /// no pending/offered handoff is currently in flight.
    #[serde(default)]
    pub active_handoff: Option<ActiveHandoffSummary>,
    /// Live-collaboration presence summary (NAN-420). Currently just a
    /// viewer count; expanded later to carry avatars.
    #[serde(default)]
    pub collab_presence: CollabPresenceSummary,
}

/// Internal struct for query results before adding shared_groups
#[derive(Debug, Clone, FromRow)]
pub struct CaseWithDetailsRow {
    pub id: Uuid,
    pub case_number: i32,
    pub title: String,
    pub description: Option<String>,
    pub severity: String,
    pub status: String,
    pub disposition: Option<String>,
    pub priority: i32,
    pub assigned_to: Option<Uuid>,
    pub assigned_at: Option<DateTime<Utc>>,
    pub assigned_group: Option<Uuid>,
    pub assigned_group_at: Option<DateTime<Utc>>,
    pub ai_summary: Option<String>,
    pub ai_disposition: Option<String>,
    pub ai_confidence: Option<f64>,
    pub ai_recommended_action: Option<String>,
    pub ai_recommended_severity: Option<String>,
    pub ai_key_evidence: Option<serde_json::Value>,
    pub ai_triaged_at: Option<DateTime<Utc>>,
    pub needs_review: bool,
    pub needs_review_reason: Option<String>,
    pub needs_review_at: Option<DateTime<Utc>>,
    pub ai_closed: bool,
    pub grouping_type: Option<String>,
    pub mitre_tactics: Vec<String>,
    pub mitre_techniques: Vec<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub first_activity_at: Option<DateTime<Utc>>,
    pub last_activity_at: Option<DateTime<Utc>>,
    pub visibility: String,
    pub created_by: Option<Uuid>,
    pub creator_name: Option<String>,
    // SLA tracking timestamps
    pub first_response_at: Option<DateTime<Utc>>,
    pub triage_completed_at: Option<DateTime<Utc>>,
    pub alert_count: i64,
    pub entity_count: i64,
    pub assignee_name: Option<String>,
    pub assigned_group_name: Option<String>,
    // Workflow persistence (NAN-415)
    pub close_reason: Option<String>,
    pub pending_kind: Option<String>,
    pub pending_target: Option<String>,
    pub pending_since: Option<DateTime<Utc>>,
    // Incident linkage (NAN-417)
    pub incident_id: Option<Uuid>,
    pub incident_number: Option<i32>,
    pub incident_title: Option<String>,
    pub incident_severity: Option<String>,
    pub incident_status: Option<String>,
    pub incident_source: Option<String>,
    // Active handoff (NAN-420). Populated by a lateral subquery selecting the
    // most recent row from `case_handoffs` where `state = 'pending'`.
    pub active_handoff_id: Option<Uuid>,
    pub active_handoff_target_user_id: Option<Uuid>,
    pub active_handoff_target_user_name: Option<String>,
    pub active_handoff_target_label: Option<String>,
    pub active_handoff_state: Option<String>,
    pub active_handoff_created_at: Option<DateTime<Utc>>,
}

/// Case summary for dashboard widgets
#[derive(Debug, Clone, Serialize, Deserialize, FromRow, utoipa::ToSchema)]
pub struct CaseSummary {
    #[serde(with = "typeid::case")]
    #[schema(value_type = String)]
    pub id: Uuid,
    pub case_number: i32,
    pub title: String,
    pub severity: String,
    pub status: String,
    pub alert_count: i64,
    pub created_at: DateTime<Utc>,
    pub last_activity_at: Option<DateTime<Utc>>,
}

/// Input for creating a new case
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct NewCase {
    pub title: String,
    pub description: Option<String>,
    pub severity: Severity,
    #[serde(default)]
    pub priority: i32,
    #[serde(default, with = "typeid::user::opt")]
    #[schema(value_type = Option<String>)]
    pub assigned_to: Option<Uuid>,
    #[serde(default, with = "typeid::group::opt")]
    #[schema(value_type = Option<String>)]
    pub assigned_group: Option<Uuid>,
    pub grouping_key: Option<String>,
    pub grouping_type: Option<GroupingType>,
    /// Set from auth context when creating via API
    #[serde(skip_deserializing, serialize_with = "typeid::user::opt::serialize")]
    #[schema(value_type = Option<String>)]
    pub created_by: Option<Uuid>,
    /// Visibility for the case ('public', 'group', 'private')
    /// Defaults to 'public' if not specified
    #[serde(default)]
    pub visibility: Option<String>,
    /// Group IDs for case access (when visibility = 'group')
    /// Inherited from detection rule for auto-created cases
    #[serde(default)]
    pub group_ids: Option<Vec<Uuid>>,
}

/// Input for updating a case
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct UpdateCase {
    pub title: Option<String>,
    pub description: Option<String>,
    pub severity: Option<Severity>,
    pub status: Option<CaseStatus>,
    pub disposition: Option<CaseDisposition>,
    pub priority: Option<i32>,
    pub ai_summary: Option<String>,
    pub ai_recommendations: Option<serde_json::Value>,
}

/// Input for writing the shadow-investigator's structured verdict back to a
/// case (NAN-1251). Separate from `UpdateCase` so the AI write path is its own
/// repository method — it never touches the human-owned columns (`disposition`,
/// `status`), only the `ai_*` recommendation columns.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct UpdateCaseAiVerdict {
    pub ai_disposition: AiDisposition,
    /// 0.0–1.0. Clamped on write.
    pub ai_confidence: f64,
    pub ai_recommended_action: Option<String>,
    /// AI-recommended severity (NAN-1297), e.g. "critical"/"high"/…. Drives
    /// symmetric re-triage when more severe than the case's current severity.
    pub ai_recommended_severity: Option<String>,
    /// JSON array of evidence strings the AI cited.
    pub ai_key_evidence: Option<serde_json::Value>,
    /// The narrative rationale, persisted to `ai_summary` alongside the verdict.
    pub ai_summary: Option<String>,
}

/// Input for assigning a case
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct AssignCase {
    #[serde(default, with = "typeid::user::opt")]
    #[schema(value_type = Option<String>)]
    pub assigned_to: Option<Uuid>,
    #[serde(default, with = "typeid::group::opt")]
    #[schema(value_type = Option<String>)]
    pub assigned_group: Option<Uuid>,
    #[serde(with = "typeid::user")]
    #[schema(value_type = String)]
    pub assigned_by: Uuid,
    /// Resolved display name of the assignee (for notebook entries)
    #[serde(skip)]
    #[schema(ignore)]
    pub assignee_name: Option<String>,
    /// Resolved display name of the assigned group (for notebook entries)
    #[serde(skip)]
    #[schema(ignore)]
    pub assigned_group_name: Option<String>,
    /// Resolved display name of the assigner (for notebook entries)
    #[serde(skip)]
    #[schema(ignore)]
    pub assigner_name: Option<String>,
}

/// Input for escalating a case while it remains active
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct EscalateCase {
    #[serde(default, with = "typeid::user::opt")]
    #[schema(value_type = Option<String>)]
    pub assigned_to: Option<Uuid>,
    #[serde(default, with = "typeid::group::opt")]
    #[schema(value_type = Option<String>)]
    pub assigned_group: Option<Uuid>,
    pub reason: String,
    #[serde(with = "typeid::user")]
    #[schema(value_type = String)]
    pub escalated_by: Uuid,
    #[serde(skip)]
    #[schema(ignore)]
    pub target_user_name: Option<String>,
    #[serde(skip)]
    #[schema(ignore)]
    pub target_group_name: Option<String>,
    #[serde(skip)]
    #[schema(ignore)]
    pub escalator_name: Option<String>,
}

/// Input for changing case status
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct ChangeCaseStatus {
    pub status: CaseStatus,
    pub disposition: Option<CaseDisposition>,
    #[serde(with = "typeid::user")]
    #[schema(value_type = String)]
    pub changed_by: Uuid,
    /// Optional close note to persist when transitioning to Closed.
    #[serde(default)]
    pub close_note: Option<NewCaseCloseNoteInline>,
    /// Optional pending kind when transitioning to Pending.
    #[serde(default)]
    pub pending_kind: Option<String>,
    /// Optional pending target (free-form) when transitioning to Pending.
    #[serde(default)]
    pub pending_target: Option<String>,
}

// =============================================================================
// CASE ALERT MODEL
// =============================================================================

/// Junction table linking alerts to cases
#[derive(Debug, Clone, Serialize, Deserialize, FromRow, utoipa::ToSchema)]
pub struct CaseAlert {
    #[serde(with = "typeid::case_alert")]
    #[schema(value_type = String)]
    pub id: Uuid,
    #[serde(with = "typeid::case")]
    #[schema(value_type = String)]
    pub case_id: Uuid,
    #[serde(with = "typeid::alert")]
    #[schema(value_type = String)]
    pub alert_id: Uuid,
    pub added_at: DateTime<Utc>,
    #[serde(default, with = "typeid::user::opt")]
    #[schema(value_type = Option<String>)]
    pub added_by: Option<Uuid>,
    pub is_primary: bool,
}

/// Input for adding an alert to a case
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct AddAlertToCase {
    #[serde(with = "typeid::alert")]
    #[schema(value_type = String)]
    pub alert_id: Uuid,
    #[serde(default, with = "typeid::user::opt")]
    #[schema(value_type = Option<String>)]
    pub added_by: Option<Uuid>,
    #[serde(default)]
    pub is_primary: bool,
}

// =============================================================================
// CASE ENTITY MODEL
// =============================================================================

/// Entity extracted from case alerts
#[derive(Debug, Clone, Serialize, Deserialize, FromRow, utoipa::ToSchema)]
pub struct CaseEntity {
    #[serde(with = "typeid::case_entity")]
    #[schema(value_type = String)]
    pub id: Uuid,
    #[serde(with = "typeid::case")]
    #[schema(value_type = String)]
    pub case_id: Uuid,
    pub entity_type: String,
    pub entity_value: String,
    pub first_seen_at: Option<DateTime<Utc>>,
    pub last_seen_at: Option<DateTime<Utc>>,
    pub occurrence_count: i32,
    pub risk_score: Option<i32>,
    pub is_primary: bool,
    pub enrichment_data: Option<serde_json::Value>,
    pub enrichment_updated_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

/// Summary of entities by type for the entities panel
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct EntityTypeSummary {
    pub entity_type: String,
    pub count: i64,
    pub entities: Vec<CaseEntity>,
}

/// Input for adding an entity to a case
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct NewCaseEntity {
    #[serde(with = "typeid::case")]
    #[schema(value_type = String)]
    pub case_id: Uuid,
    pub entity_type: CaseEntityType,
    pub entity_value: String,
    #[serde(default)]
    pub is_primary: bool,
}

// =============================================================================
// CASE WALL MODEL
// =============================================================================

/// Case wall entry (activity timeline / comments)
#[derive(Debug, Clone, Serialize, Deserialize, FromRow, utoipa::ToSchema)]
pub struct CaseWallEntry {
    #[serde(with = "typeid::case_wall")]
    #[schema(value_type = String)]
    pub id: Uuid,
    #[serde(with = "typeid::case")]
    #[schema(value_type = String)]
    pub case_id: Uuid,
    pub entry_type: String,
    pub content: Option<String>,
    pub metadata: serde_json::Value,
    pub is_internal: bool,
    #[serde(default, with = "typeid::user::opt")]
    #[schema(value_type = Option<String>)]
    pub created_by: Option<Uuid>,
    pub created_at: DateTime<Utc>,
}

/// Case wall entry with creator name for display
#[derive(Debug, Clone, Serialize, Deserialize, FromRow, utoipa::ToSchema)]
pub struct CaseWallEntryWithCreator {
    #[serde(with = "typeid::case_wall")]
    #[schema(value_type = String)]
    pub id: Uuid,
    #[serde(with = "typeid::case")]
    #[schema(value_type = String)]
    pub case_id: Uuid,
    pub entry_type: String,
    pub content: Option<String>,
    pub metadata: serde_json::Value,
    pub is_internal: bool,
    #[serde(default, with = "typeid::user::opt")]
    #[schema(value_type = Option<String>)]
    pub created_by: Option<Uuid>,
    pub created_at: DateTime<Utc>,
    pub creator_name: Option<String>,
}

/// Input for creating a case wall entry
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct NewCaseWallEntry {
    #[serde(with = "typeid::case")]
    #[schema(value_type = String)]
    pub case_id: Uuid,
    pub entry_type: CaseWallEntryType,
    pub content: Option<String>,
    #[serde(default)]
    pub metadata: serde_json::Value,
    #[serde(default)]
    pub is_internal: bool,
    #[serde(default, with = "typeid::user::opt")]
    #[schema(value_type = Option<String>)]
    pub created_by: Option<Uuid>,
}

// =============================================================================
// CASE RELATION MODEL
// =============================================================================

/// Relationship between cases
#[derive(Debug, Clone, Serialize, Deserialize, FromRow, utoipa::ToSchema)]
pub struct CaseRelation {
    #[serde(with = "typeid::case_relation")]
    #[schema(value_type = String)]
    pub id: Uuid,
    #[serde(with = "typeid::case")]
    #[schema(value_type = String)]
    pub source_case_id: Uuid,
    #[serde(with = "typeid::case")]
    #[schema(value_type = String)]
    pub target_case_id: Uuid,
    pub relation_type: String,
    pub confidence: Option<f64>,
    pub reason: Option<String>,
    pub shared_entities: Option<serde_json::Value>,
    pub created_at: DateTime<Utc>,
    #[serde(default, with = "typeid::user::opt")]
    #[schema(value_type = Option<String>)]
    pub created_by: Option<Uuid>,
}

/// Related case summary for display
#[derive(Debug, Clone, Serialize, Deserialize, FromRow, utoipa::ToSchema)]
pub struct RelatedCaseSummary {
    #[serde(with = "typeid::case")]
    #[schema(value_type = String)]
    pub id: Uuid,
    pub case_number: i32,
    pub title: String,
    pub severity: String,
    pub status: String,
    pub relation_type: String,
    pub confidence: Option<f64>,
    pub shared_entity_count: i64,
    /// Actor who linked this relation. `None` for auto-detected (entity
    /// intersection) relations; `Some(user_id)` for manual links added via
    /// `POST /api/cases/{id}/related` (NAN-431). The UI surfaces this to
    /// distinguish analyst-confirmed links from the algorithmic ones.
    #[serde(default, with = "typeid::user::opt")]
    #[schema(value_type = Option<String>)]
    pub created_by: Option<Uuid>,
    /// Free-form reason the analyst typed when manually linking, or the
    /// auto-detector's "N shared entities" string.
    #[serde(default)]
    pub reason: Option<String>,
}

/// Duplicate-candidate result (NAN-421).
///
/// Surfaced by the dedup detector (`GET /api/cases/:id/duplicates`). Each
/// candidate represents another case that shares enough signal with the
/// subject case to be worth showing the analyst as a merge candidate.
///
/// The detector is rule-based, not ML — it looks for:
/// - same `grouping_key` (strong signal: auto-grouper already thinks they
///   should collapse)
/// - shared entities (`case_entities` intersection)
/// - same rule fired within a 24h window (secondary)
///
/// The `reason` field is a short human-readable explanation of why the
/// candidate surfaced (e.g. "Same grouping key · 4 shared entities").
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct DuplicateCandidate {
    #[serde(with = "typeid::case")]
    #[schema(value_type = String)]
    pub case_id: Uuid,
    pub case_number: i32,
    pub title: String,
    pub severity: String,
    pub status: String,
    /// Confidence score in [0.0, 1.0]. Higher = more likely duplicate.
    pub confidence: f32,
    pub reason: String,
}

/// Input for creating a case relation
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct NewCaseRelation {
    #[serde(with = "typeid::case")]
    #[schema(value_type = String)]
    pub source_case_id: Uuid,
    #[serde(with = "typeid::case")]
    #[schema(value_type = String)]
    pub target_case_id: Uuid,
    pub relation_type: CaseRelationType,
    pub confidence: Option<f64>,
    pub reason: Option<String>,
    pub shared_entities: Option<serde_json::Value>,
    #[serde(default, with = "typeid::user::opt")]
    #[schema(value_type = Option<String>)]
    pub created_by: Option<Uuid>,
}

// =============================================================================
// CASE GROUPING RULES MODEL
// =============================================================================

/// Configuration for auto-grouping alerts into cases
#[derive(Debug, Clone, Serialize, Deserialize, FromRow, utoipa::ToSchema)]
pub struct CaseGroupingRule {
    #[serde(with = "typeid::case_grouping_rule")]
    #[schema(value_type = String)]
    pub id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub enabled: bool,
    pub priority: i32,

    // Matching criteria
    pub match_type: String,
    pub match_conditions: Option<serde_json::Value>,

    // Grouping behavior
    pub time_window_minutes: i32,
    pub min_alerts: i32,
    pub max_alerts: i32,
    pub auto_create_case: bool,

    // Case template
    pub case_title_template: Option<String>,
    pub case_severity_rule: String,
    #[serde(default, with = "typeid::user::opt")]
    #[schema(value_type = Option<String>)]
    pub auto_assign_to: Option<Uuid>,

    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    #[serde(default, with = "typeid::user::opt")]
    #[schema(value_type = Option<String>)]
    pub created_by: Option<Uuid>,
}

/// Input for creating a grouping rule
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct NewCaseGroupingRule {
    pub name: String,
    pub description: Option<String>,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub priority: i32,
    pub match_type: GroupingType,
    pub match_conditions: Option<serde_json::Value>,
    #[serde(default = "default_time_window")]
    pub time_window_minutes: i32,
    #[serde(default = "default_one")]
    pub min_alerts: i32,
    #[serde(default = "default_max_alerts")]
    pub max_alerts: i32,
    #[serde(default = "default_true")]
    pub auto_create_case: bool,
    pub case_title_template: Option<String>,
    #[serde(default)]
    pub case_severity_rule: SeverityRule,
    #[serde(default, with = "typeid::user::opt")]
    #[schema(value_type = Option<String>)]
    pub auto_assign_to: Option<Uuid>,
}

/// Input for updating a grouping rule
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct UpdateCaseGroupingRule {
    pub name: Option<String>,
    pub description: Option<String>,
    pub enabled: Option<bool>,
    pub priority: Option<i32>,
    pub match_type: Option<GroupingType>,
    pub match_conditions: Option<serde_json::Value>,
    pub time_window_minutes: Option<i32>,
    pub min_alerts: Option<i32>,
    pub max_alerts: Option<i32>,
    pub auto_create_case: Option<bool>,
    pub case_title_template: Option<String>,
    pub case_severity_rule: Option<SeverityRule>,
    #[serde(default, with = "typeid::user::opt")]
    #[schema(value_type = Option<String>)]
    pub auto_assign_to: Option<Uuid>,
}

// Default value helpers
fn default_true() -> bool {
    true
}

fn default_time_window() -> i32 {
    60
}

fn default_one() -> i32 {
    1
}

fn default_max_alerts() -> i32 {
    100
}

// =============================================================================
// STATISTICS
// =============================================================================

/// Case statistics for dashboard
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct CaseStats {
    pub total: i64,
    pub open: i64,
    pub in_progress: i64,
    pub pending: i64,
    pub resolved: i64,
    pub closed: i64,
    pub by_severity: std::collections::HashMap<String, i64>,
    pub avg_resolution_time_hours: Option<f64>,
}

/// Filter for listing cases
#[derive(Debug, Clone, Default, Serialize, Deserialize, utoipa::ToSchema)]
pub struct CaseFilter {
    pub status: Option<Vec<CaseStatus>>,
    pub severity: Option<Vec<Severity>>,
    #[serde(default, with = "typeid::user::opt")]
    #[schema(value_type = Option<String>)]
    pub assigned_to: Option<Uuid>,
    #[serde(default, with = "typeid::group::opt")]
    #[schema(value_type = Option<String>)]
    pub assigned_group: Option<Uuid>,
    /// NAN-1093: multi-group filter. Used by the Signal Inbox Escalations
    /// tab to scope to "cases assigned to any of the analyst's groups". Set
    /// either this or `assigned_group`, not both. Empty vec means no match.
    /// Typeid encoding is handled at the handler boundary; on the wire here
    /// these are bare UUIDs.
    #[serde(default)]
    #[schema(value_type = Option<Vec<String>>)]
    pub assigned_groups: Option<Vec<Uuid>>,
    /// Include cases where this user was mentioned in a comment
    #[serde(default, with = "typeid::user::opt")]
    #[schema(value_type = Option<String>)]
    pub mentioned_by: Option<Uuid>,
    pub search: Option<String>,
    /// NAN-1074: free-text mode. When set, the list query joins against
    /// `case_alerts` + `alerts` and ILIKE-matches alert content
    /// (`rule_name`, serialised `matched_events`) in addition to case
    /// title/description. Slower than `search`; intended for hunting.
    /// `search` and `free_text` are mutually exclusive in the UI but
    /// both honoured by the repo if set.
    pub free_text: Option<String>,
    pub created_after: Option<DateTime<Utc>>,
    pub created_before: Option<DateTime<Utc>>,
    /// Filter by visibility levels
    pub visibility: Option<Vec<String>>,
    /// NAN-1093: when set, filter to cases with a NULL or NOT-NULL
    /// `incident_id`. Used by the Signal Inbox so the paginated loose
    /// list (incident_id_is_null=true) and the incident summary (false)
    /// stay in sync without overlap.
    #[serde(default)]
    pub incident_id_is_null: Option<bool>,
    /// NAN-1093: result ordering. Default `Newest` preserves the
    /// pre-1093 behaviour for callers that don't pass a sort.
    #[serde(default)]
    pub sort: CaseSort,
    /// NAN-1251: "Must Investigate" bucket. When `Some(true)`, restrict to
    /// cases the AI flagged as actionable (`ai_disposition` ∈ {true_positive,
    /// needs_investigation}) that a human has not yet dispositioned. `None` /
    /// `Some(false)` disables the filter.
    #[serde(default)]
    pub ai_escalated_only: Option<bool>,
    /// NAN-1095: per-severity SLA target minutes. Required when
    /// `sort = CaseSort::Sla`; ignored otherwise. Caller fetches from
    /// `CaseSettings::get_config()` and converts via
    /// `SlaTargets::from_sla_config`.
    #[serde(skip)]
    pub sla_targets: Option<SlaTargets>,
}

/// NAN-1093: order options for `CaseRepository::list`. The Signal Inbox
/// drives all of these; the legacy default is `Newest` which preserves
/// the pre-1093 behaviour for any caller that doesn't pass a sort.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum CaseSort {
    /// Most recent activity first (current default).
    #[default]
    Newest,
    /// Oldest activity first.
    Oldest,
    /// Severity first (critical → informational), recency tiebreaker.
    Severity,
    /// Cases assigned to the current user first, then by recency. The
    /// user id comes from `user_id` passed to `list`.
    MineFirst,
    /// NAN-1095: SLA urgency — least remaining time across TTA / TTR /
    /// TTClose, ascending. Breached rows (negative remaining) come
    /// first. Requires `CaseFilter::sla_targets` to be set or the
    /// repository falls back to `Newest`.
    Sla,
    /// NAN-1251: AI-actionable first — cases the AI flagged as
    /// true_positive / needs_investigation, highest confidence first,
    /// then recency. Floats the "Must Investigate" work to the top.
    AiPriority,
}

/// NAN-1095: per-severity SLA target minutes. Lifted out of the
/// enterprise `SlaConfig` so the core repository can take it without a
/// reverse dependency. Mirrors the 5×3 grid (5 severities × triage /
/// response / resolution). The repo inlines these as numeric literals
/// into ORDER BY — safe because every field is an `i32` from a closed
/// settings table, not user input.
#[derive(Debug, Clone, Copy)]
pub struct SlaTargets {
    pub critical_triage_minutes: i32,
    pub critical_response_minutes: i32,
    pub critical_resolution_minutes: i32,
    pub high_triage_minutes: i32,
    pub high_response_minutes: i32,
    pub high_resolution_minutes: i32,
    pub medium_triage_minutes: i32,
    pub medium_response_minutes: i32,
    pub medium_resolution_minutes: i32,
    pub low_triage_minutes: i32,
    pub low_response_minutes: i32,
    pub low_resolution_minutes: i32,
    pub informational_triage_minutes: i32,
    pub informational_response_minutes: i32,
    pub informational_resolution_minutes: i32,
}

// =============================================================================
// AI RECOMMENDATIONS
// =============================================================================

/// AI-generated recommendation for case remediation
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct AiRecommendation {
    pub title: String,
    pub description: String,
    pub priority: String,
    pub action_type: String,
    pub suggested_action: Option<String>,
}

/// AI summary generation request
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct GenerateAiSummaryRequest {
    #[serde(with = "typeid::case")]
    #[schema(value_type = String)]
    pub case_id: Uuid,
    pub regenerate: bool,
}

/// AI summary generation response
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct AiSummaryResponse {
    pub summary: String,
    pub recommendations: Vec<AiRecommendation>,
    pub generated_at: DateTime<Utc>,
}

// =============================================================================
// FULL CASE RESPONSE
// =============================================================================

/// Complete case response with all related data
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct CaseFullResponse {
    pub case: CaseWithDetails,
    pub alerts: Vec<CaseAlertDetail>,
    pub entities: Vec<EntityTypeSummary>,
    pub wall: Vec<CaseWallEntryWithCreator>,
    pub related_cases: Vec<RelatedCaseSummary>,
    pub stats: CaseResponseStats,
    pub playbook: Option<CasePlaybookState>,
    /// Active (non-superseded) close note, if present.
    #[serde(default)]
    pub close_note: Option<CaseCloseNote>,
    /// Derived pending state from the `cases.pending_*` columns.
    #[serde(default)]
    pub pending_state: Option<CasePendingState>,
    /// Structured escalation records (newest first).
    #[serde(default)]
    pub escalations: Vec<CaseEscalation>,
    /// Peer-to-peer handoff records (newest first).
    #[serde(default)]
    pub handoffs: Vec<CaseHandoff>,
    /// State-transition audit spine (newest first, limit 50).
    #[serde(default)]
    pub workflow_events: Vec<CaseWorkflowEvent>,
    /// Pre-resolved lookup from `case_*` typeid → case metadata (case_number,
    /// title, status, severity). Populated by the handler after scanning the
    /// wall + workflow_events for any referenced linked-case typeids, so the
    /// frontend can render `CASE-<n> · <title>` chips without extra fetches.
    ///
    /// Keyed by the full typeid string (e.g. `case_01hk...`). Empty map when
    /// no links are present. Missing entries mean the referenced case was
    /// deleted or the user lacks visibility — render a fallback pill.
    #[serde(default)]
    pub linked_cases_index: std::collections::HashMap<String, LinkedCaseRef>,
}

/// Compact case reference used in `CaseFullResponse::linked_cases_index` to
/// resolve `case_*` typeid mentions into human-readable labels + deep links.
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow, utoipa::ToSchema)]
pub struct LinkedCaseRef {
    /// Case typeid (`case_<base32>`).
    #[serde(with = "typeid::case")]
    #[schema(value_type = String)]
    pub id: Uuid,
    /// Display serial (shown as `CASE-<n>`).
    pub case_number: i32,
    pub title: String,
    pub status: String,
    pub severity: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct CasePlaybookState {
    pub title: String,
    pub summary: Option<String>,
    pub status: String,
    pub source: String,
    pub started_at: Option<DateTime<Utc>>,
    pub updated_at: Option<DateTime<Utc>>,
    pub evidence_count: i32,
    pub suggested_queries: Vec<String>,
    pub steps: Vec<CasePlaybookStep>,
}

#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct CasePlaybookStep {
    pub title: String,
    pub status: String,
}

/// Alert detail within a case
#[derive(Debug, Clone, Serialize, Deserialize, FromRow, utoipa::ToSchema)]
pub struct CaseAlertDetail {
    #[serde(with = "typeid::case_alert")]
    #[schema(value_type = String)]
    pub id: Uuid,
    #[serde(with = "typeid::alert")]
    #[schema(value_type = String)]
    pub alert_id: Uuid,
    #[serde(default, with = "typeid::rule::opt")]
    #[schema(value_type = Option<String>)]
    pub rule_id: Option<Uuid>,
    pub rule_name: Option<String>,
    pub severity: String,
    pub status: String,
    pub disposition: Option<String>,
    pub matched_event_count: Option<i32>,
    pub created_at: DateTime<Utc>,
    pub added_at: DateTime<Utc>,
    pub is_primary: bool,
    pub triage_verdict: Option<String>,
    pub triage_confidence: Option<f64>,
    /// Per-alert risk-score contribution sourced from the firing rule's
    /// `detection_rules.risk_score` (0–100). Used by the Risk page to render a
    /// per-alert weight bar against the entity's aggregate risk score.
    #[serde(default)]
    pub score_contribution: Option<i32>,
    /// MITRE ATT&CK tactic IDs from the firing rule's `detection_rules.mitre_tactics`
    /// (e.g. `["TA0006", "TA0001"]`). Empty when the rule has no tactics tagged.
    #[serde(default)]
    pub mitre_tactics: Vec<String>,
}

/// Stats for a single case
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct CaseResponseStats {
    pub alert_count: i64,
    pub entity_count: i64,
    pub comment_count: i64,
    pub time_open_hours: Option<f64>,
}

// =============================================================================
// SHARING
// =============================================================================

/// A group that a case is shared with
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct SharedGroup {
    #[serde(with = "typeid::group")]
    #[schema(value_type = String)]
    pub id: Uuid,
    pub name: String,
}

/// Input for sharing a case
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct ShareCaseRequest {
    pub visibility: String,
    pub group_ids: Option<Vec<Uuid>>,
}

/// A user affected by a share change
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct CaseAffectedUser {
    #[serde(with = "typeid::user")]
    #[schema(value_type = String)]
    pub user_id: Uuid,
    pub user_name: String,
    pub user_email: String,
}

/// Result of a share operation, including users who lost access
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct CaseShareResult {
    /// The updated case with details
    pub case: CaseWithDetails,
    /// Users who lost access due to group removal
    pub users_who_lost_access: Vec<CaseAffectedUser>,
}

// =============================================================================
// CASE WORKFLOW MODELS (NAN-415)
// =============================================================================

/// Durable close note attached to a case close event.
///
/// A single case may have multiple close notes over its lifetime (close / reopen
/// cycles). Only one row per case has `superseded_at IS NULL` at a time.
#[derive(Debug, Clone, Serialize, Deserialize, FromRow, utoipa::ToSchema)]
pub struct CaseCloseNote {
    #[schema(value_type = String)]
    pub id: Uuid,
    #[serde(with = "typeid::case")]
    #[schema(value_type = String)]
    pub case_id: Uuid,
    #[serde(default, with = "typeid::user::opt")]
    #[schema(value_type = Option<String>)]
    pub created_by: Option<Uuid>,
    pub close_reason: String,
    pub title: String,
    pub summary: String,
    pub emits: Vec<String>,
    pub tuning_action: Option<String>,
    pub escalation_target: Option<String>,
    pub duplicate_primary_case_number: Option<i32>,
    #[serde(default, with = "typeid::case::opt")]
    #[schema(value_type = Option<String>)]
    pub duplicate_primary_case_id: Option<Uuid>,
    pub ack_audit: bool,
    pub audit_id: Option<String>,
    pub superseded_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

/// Input for inserting a new close note (with explicit case_id + created_by).
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct NewCaseCloseNote {
    #[serde(with = "typeid::case")]
    #[schema(value_type = String)]
    pub case_id: Uuid,
    #[serde(default, with = "typeid::user::opt")]
    #[schema(value_type = Option<String>)]
    pub created_by: Option<Uuid>,
    pub close_reason: String,
    pub title: String,
    pub summary: String,
    #[serde(default)]
    pub emits: Vec<String>,
    pub tuning_action: Option<String>,
    pub escalation_target: Option<String>,
    pub duplicate_primary_case_number: Option<i32>,
    #[serde(default, with = "typeid::case::opt")]
    #[schema(value_type = Option<String>)]
    pub duplicate_primary_case_id: Option<Uuid>,
    #[serde(default)]
    pub ack_audit: bool,
    pub audit_id: Option<String>,
}

/// Inline close-note payload used inside `ChangeCaseStatus` — the service
/// fills in `case_id` + `created_by`, so callers don't need to repeat them.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct NewCaseCloseNoteInline {
    pub close_reason: String,
    pub title: String,
    pub summary: String,
    #[serde(default)]
    pub emits: Vec<String>,
    pub tuning_action: Option<String>,
    pub escalation_target: Option<String>,
    pub duplicate_primary_case_number: Option<i32>,
    #[serde(default, with = "typeid::case::opt")]
    #[schema(value_type = Option<String>)]
    pub duplicate_primary_case_id: Option<Uuid>,
    #[serde(default)]
    pub ack_audit: bool,
    pub audit_id: Option<String>,
}

/// Structured escalation record (SOC tier to IR/legal/exec).
#[derive(Debug, Clone, Serialize, Deserialize, FromRow, utoipa::ToSchema)]
pub struct CaseEscalation {
    #[schema(value_type = String)]
    pub id: Uuid,
    #[serde(with = "typeid::case")]
    #[schema(value_type = String)]
    pub case_id: Uuid,
    #[serde(default, with = "typeid::user::opt")]
    #[schema(value_type = Option<String>)]
    pub source_user_id: Option<Uuid>,
    #[serde(default, with = "typeid::user::opt")]
    #[schema(value_type = Option<String>)]
    pub target_user_id: Option<Uuid>,
    #[serde(default, with = "typeid::group::opt")]
    #[schema(value_type = Option<String>)]
    pub target_group_id: Option<Uuid>,
    pub target_label: String,
    pub reason: String,
    #[serde(default, with = "typeid::user::opt")]
    #[schema(value_type = Option<String>)]
    pub previous_assigned_to: Option<Uuid>,
    #[serde(default, with = "typeid::group::opt")]
    #[schema(value_type = Option<String>)]
    pub previous_assigned_group: Option<Uuid>,
    pub acknowledged_at: Option<DateTime<Utc>>,
    #[serde(default, with = "typeid::user::opt")]
    #[schema(value_type = Option<String>)]
    pub acknowledged_by: Option<Uuid>,
    pub created_at: DateTime<Utc>,
}

/// Input for inserting a new escalation record.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct NewCaseEscalation {
    #[serde(with = "typeid::case")]
    #[schema(value_type = String)]
    pub case_id: Uuid,
    #[serde(default, with = "typeid::user::opt")]
    #[schema(value_type = Option<String>)]
    pub source_user_id: Option<Uuid>,
    #[serde(default, with = "typeid::user::opt")]
    #[schema(value_type = Option<String>)]
    pub target_user_id: Option<Uuid>,
    #[serde(default, with = "typeid::group::opt")]
    #[schema(value_type = Option<String>)]
    pub target_group_id: Option<Uuid>,
    pub target_label: String,
    pub reason: String,
    #[serde(default, with = "typeid::user::opt")]
    #[schema(value_type = Option<String>)]
    pub previous_assigned_to: Option<Uuid>,
    #[serde(default, with = "typeid::group::opt")]
    #[schema(value_type = Option<String>)]
    pub previous_assigned_group: Option<Uuid>,
}

/// Peer-to-peer ownership transfer (handoff) record.
#[derive(Debug, Clone, Serialize, Deserialize, FromRow, utoipa::ToSchema)]
pub struct CaseHandoff {
    #[schema(value_type = String)]
    pub id: Uuid,
    #[serde(with = "typeid::case")]
    #[schema(value_type = String)]
    pub case_id: Uuid,
    #[serde(with = "typeid::user")]
    #[schema(value_type = String)]
    pub source_user_id: Uuid,
    #[serde(default, with = "typeid::user::opt")]
    #[schema(value_type = Option<String>)]
    pub target_user_id: Option<Uuid>,
    #[serde(default, with = "typeid::group::opt")]
    #[schema(value_type = Option<String>)]
    pub target_group_id: Option<Uuid>,
    pub target_label: String,
    pub reason: Option<String>,
    pub context_payload: serde_json::Value,
    /// One of: pending, accepted, bounced, canceled.
    pub state: String,
    pub accepted_at: Option<DateTime<Utc>>,
    #[serde(default, with = "typeid::user::opt")]
    #[schema(value_type = Option<String>)]
    pub accepted_by: Option<Uuid>,
    pub bounced_at: Option<DateTime<Utc>>,
    #[serde(default, with = "typeid::user::opt")]
    #[schema(value_type = Option<String>)]
    pub bounced_by: Option<Uuid>,
    pub bounce_reason: Option<String>,
    pub canceled_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

/// Input for creating a new handoff record.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct NewCaseHandoff {
    #[serde(with = "typeid::case")]
    #[schema(value_type = String)]
    pub case_id: Uuid,
    #[serde(with = "typeid::user")]
    #[schema(value_type = String)]
    pub source_user_id: Uuid,
    #[serde(default, with = "typeid::user::opt")]
    #[schema(value_type = Option<String>)]
    pub target_user_id: Option<Uuid>,
    #[serde(default, with = "typeid::group::opt")]
    #[schema(value_type = Option<String>)]
    pub target_group_id: Option<Uuid>,
    pub target_label: String,
    pub reason: Option<String>,
    #[serde(default)]
    pub context_payload: serde_json::Value,
}

/// State transition record for the case workflow audit spine.
#[derive(Debug, Clone, Serialize, Deserialize, FromRow, utoipa::ToSchema)]
pub struct CaseWorkflowEvent {
    #[schema(value_type = String)]
    pub id: Uuid,
    #[serde(with = "typeid::case")]
    #[schema(value_type = String)]
    pub case_id: Uuid,
    #[serde(default, with = "typeid::user::opt")]
    #[schema(value_type = Option<String>)]
    pub actor_id: Option<Uuid>,
    pub event_kind: String,
    pub from_status: Option<String>,
    pub to_status: Option<String>,
    pub reason: Option<String>,
    pub metadata: serde_json::Value,
    #[schema(value_type = Option<String>)]
    pub close_note_id: Option<Uuid>,
    #[schema(value_type = Option<String>)]
    pub escalation_id: Option<Uuid>,
    #[schema(value_type = Option<String>)]
    pub handoff_id: Option<Uuid>,
    pub created_at: DateTime<Utc>,
}

/// Input for inserting a new workflow event.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct NewCaseWorkflowEvent {
    #[serde(with = "typeid::case")]
    #[schema(value_type = String)]
    pub case_id: Uuid,
    #[serde(default, with = "typeid::user::opt")]
    #[schema(value_type = Option<String>)]
    pub actor_id: Option<Uuid>,
    pub event_kind: String,
    pub from_status: Option<String>,
    pub to_status: Option<String>,
    pub reason: Option<String>,
    #[serde(default)]
    pub metadata: serde_json::Value,
    #[schema(value_type = Option<String>)]
    pub close_note_id: Option<Uuid>,
    #[schema(value_type = Option<String>)]
    pub escalation_id: Option<Uuid>,
    #[schema(value_type = Option<String>)]
    pub handoff_id: Option<Uuid>,
}

/// Derived pending-state snapshot from the `cases.pending_*` columns.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct CasePendingState {
    pub kind: String,
    pub target: Option<String>,
    pub since: DateTime<Utc>,
}

/// Summary of the latest open handoff on a case, surfaced on the list
/// response so the Cases page can render a "handoff to X" pill on rows
/// without fetching the full case detail (NAN-420).
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct ActiveHandoffSummary {
    /// Handoff row id. Kept as a plain UUID schema — the list indicator
    /// doesn't need to round-trip a typeid back to the backend.
    #[schema(value_type = String)]
    pub id: Uuid,
    /// Recipient user id (`None` when the handoff targets a group queue).
    #[serde(default, with = "typeid::user::opt")]
    #[schema(value_type = Option<String>)]
    pub to_user_id: Option<Uuid>,
    /// Resolved display name of the recipient user (if known).
    pub to_user_name: Option<String>,
    /// Human-readable target label (e.g. "SOC L2 queue" or "Riley Chen").
    /// Always populated even when the recipient is a group queue.
    pub target_label: String,
    /// When the handoff was initiated.
    pub initiated_at: DateTime<Utc>,
    /// Lifecycle state — one of `pending`, `accepted`, `bounced`, `canceled`.
    /// Currently the list query only surfaces `pending`, but the field is
    /// typed for forward compatibility with `offered` if/when it lands.
    pub state: String,
}

/// Collaboration presence summary for a case on the list response
/// (NAN-420). Currently surfaces only a viewer count; expanded to carry
/// avatars + presence dots in a follow-up.
#[derive(Debug, Clone, Default, Serialize, Deserialize, utoipa::ToSchema)]
pub struct CollabPresenceSummary {
    /// Number of analysts actively viewing the case, EXCLUDING the caller.
    /// Zero when nobody else is on the case (or when presence tracking is
    /// disabled for this deployment).
    pub viewer_count: u32,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Pins the AI verdict string ↔ `AiDisposition` contract (NAN-1251). The
    /// shadow investigator and the inbox both depend on these exact strings.
    #[test]
    fn ai_disposition_round_trips_wire_strings() {
        let cases = [
            (AiDisposition::TruePositive, "true_positive"),
            (AiDisposition::FalsePositive, "false_positive"),
            (AiDisposition::Benign, "benign"),
            (AiDisposition::Inconclusive, "inconclusive"),
            (AiDisposition::NeedsInvestigation, "needs_investigation"),
        ];
        for (variant, wire) in cases {
            assert_eq!(variant.as_str(), wire);
            assert_eq!(AiDisposition::parse_verdict(wire), Some(variant));
        }
    }

    #[test]
    fn ai_disposition_parses_model_phrasings() {
        assert_eq!(
            AiDisposition::parse_verdict("True Positive"),
            Some(AiDisposition::TruePositive)
        );
        assert_eq!(
            AiDisposition::parse_verdict("needs further investigation"),
            Some(AiDisposition::NeedsInvestigation)
        );
        assert_eq!(
            AiDisposition::parse_verdict("FP"),
            Some(AiDisposition::FalsePositive)
        );
        assert_eq!(AiDisposition::parse_verdict("whatever"), None);
    }

    #[test]
    fn only_tp_and_needs_investigation_are_actionable() {
        assert!(AiDisposition::TruePositive.is_actionable());
        assert!(AiDisposition::NeedsInvestigation.is_actionable());
        assert!(!AiDisposition::FalsePositive.is_actionable());
        assert!(!AiDisposition::Benign.is_actionable());
        assert!(!AiDisposition::Inconclusive.is_actionable());
    }
}
