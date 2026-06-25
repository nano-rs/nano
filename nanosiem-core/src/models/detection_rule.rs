// SPDX-License-Identifier: AGPL-3.0-or-later

//! Detection rule model

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

use crate::detection::risk::RiskModifier;
use crate::typeid;

/// AI triage hints for guiding automated alert analysis
///
/// These hints help the AI understand what's normal vs suspicious
/// for this specific detection rule, improving triage accuracy.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, utoipa::ToSchema)]
pub struct AiTriageHints {
    /// Conditions that indicate this is likely benign/expected
    /// e.g., "Destination is a well-known legitimate website"
    #[serde(default)]
    pub ignore_when: Vec<String>,
    /// Conditions that indicate this is especially suspicious
    /// e.g., "Multiple destinations contacted in short time window"
    #[serde(default)]
    pub suspicious_when: Vec<String>,
    /// Additional context for the AI about this detection
    /// e.g., "This rule fires for low-prevalence domains. Common false positives include CDNs and news sites."
    #[serde(default)]
    pub context: Option<String>,
}

/// Severity levels for detection rules
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type, utoipa::ToSchema,
)]
#[sqlx(type_name = "text", rename_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Informational,
}

/// Rule mode - determines whether matches generate alerts or just logs
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type, Default, utoipa::ToSchema,
)]
#[sqlx(type_name = "text", rename_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum RuleMode {
    /// Staging mode - rule is being developed/edited, not executed at all
    /// Use this when creating or modifying rules before they're ready for testing
    #[default]
    Staging,
    /// Live mode - rule is in bake-in period, matches are logged but don't generate alerts
    /// Use this to test rules against live data and tune for false positives
    Live,
    /// Alerting mode - rule is production-ready, matches generate real alerts
    Alerting,
    /// Paused mode - rule was in alerting but temporarily stopped
    /// Use this to temporarily stop a production rule without losing its alerting context
    Paused,
}

/// Detection execution mode - determines how and when the rule is executed
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type, Default, utoipa::ToSchema,
)]
#[sqlx(type_name = "text", rename_all = "kebab-case")]
#[serde(rename_all = "kebab-case")]
pub enum DetectionMode {
    /// Real-time detection via ClickHouse materialized views (10-30s latency)
    /// Best for: Simple IOC matching (IP/hash blacklists), atomic detections
    /// Limitations: No aggregations, no joins, must specify risk_entity_field
    RealTime,
    /// Scheduled detection via cron (default: every minute for continuous, custom for scheduled)
    /// Best for: All detection types - complex queries, aggregations, correlations
    /// The scheduler checks every 15 seconds and fires rules based on their cron schedule
    /// Use */1 * * * * for continuous (1-minute) detection
    #[default]
    Scheduled,
}

/// Alert mode - determines how matched events map to alerts
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type, Default, utoipa::ToSchema,
)]
#[sqlx(type_name = "text", rename_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum AlertMode {
    /// Grouped mode (default) - all matched events from one execution bundled into a single alert
    #[default]
    Grouped,
    /// Per-event mode - each matched event becomes its own alert (1:1 mapping)
    /// Ideal for vendor pass-through (e.g., CrowdStrike/SentinelOne detections)
    PerEvent,
}

impl std::fmt::Display for RuleMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RuleMode::Staging => write!(f, "staging"),
            RuleMode::Live => write!(f, "live"),
            RuleMode::Alerting => write!(f, "alerting"),
            RuleMode::Paused => write!(f, "paused"),
        }
    }
}

/// A detection rule for identifying threats
#[derive(Debug, Clone, Serialize, Deserialize, FromRow, utoipa::ToSchema)]
pub struct DetectionRule {
    #[serde(with = "typeid::rule")]
    #[schema(value_type = String)]
    pub id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub query: String,
    pub severity: Severity,
    pub mitre_tactics: Vec<String>,
    pub mitre_techniques: Vec<String>,
    pub schedule_cron: Option<String>,
    /// Rule mode: staging (dev), live (bake-in), alerting (production), or paused (temporarily stopped)
    #[sqlx(default)]
    pub mode: RuleMode,
    /// AI-generated narrative explaining what the rule detects and why it matters
    #[sqlx(default)]
    pub narrative: Option<String>,
    /// Reference URL for more information (e.g., blog post, CVE, threat intel)
    #[sqlx(default)]
    pub reference_url: Option<String>,
    /// Author of the rule
    #[sqlx(default)]
    pub author: Option<String>,
    /// Tags for categorization beyond MITRE (e.g., "ransomware", "apt", "insider-threat")
    #[sqlx(default)]
    pub tags: Vec<String>,
    /// Whether this rule was created using AI assistance (meloD)
    #[sqlx(default)]
    pub ai_generated: bool,
    /// Whether real-time detection is enabled for this rule
    #[sqlx(default)]
    pub realtime_enabled: bool,
    /// Detection execution mode (real-time or scheduled)
    #[sqlx(default)]
    pub detection_mode: DetectionMode,
    /// Materialized view name for real-time rules (auto-generated)
    #[sqlx(default)]
    pub materialized_view_name: Option<String>,
    /// Base risk score (0-100), defaults based on severity if not set
    #[sqlx(default)]
    pub risk_score: Option<i32>,
    /// UDM field to extract risk entity from (e.g., src_ip, user, hostname)
    #[sqlx(default)]
    pub risk_entity_field: Option<String>,
    /// Conditional score modifiers as JSON
    #[sqlx(default)]
    #[schema(value_type = Vec<RiskModifier>)]
    pub risk_modifiers: sqlx::types::Json<Vec<RiskModifier>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub last_run_at: Option<DateTime<Utc>>,
    /// Timestamp of when the rule last matched an event (regardless of mode)
    #[sqlx(default)]
    pub last_match_at: Option<DateTime<Utc>>,
    pub match_count: i64,
    /// Count of matches during live/bake-in mode (for tuning)
    #[sqlx(default)]
    pub live_match_count: i64,
    /// Whether the rule is archived (hidden by default, must be unarchived before activating)
    #[sqlx(default)]
    pub archived: bool,
    /// Folder for organizing rules (network, identity, endpoint, cloud, stash, or custom)
    #[sqlx(default)]
    pub folder: Option<String>,
    /// AI triage hints for guiding automated alert analysis
    #[sqlx(default)]
    #[schema(value_type = AiTriageHints)]
    pub ai_triage_hints: sqlx::types::Json<AiTriageHints>,
    /// Custom lookback period in minutes for scheduled execution
    /// If None, uses the default from scheduler config (typically 15 minutes)
    /// Useful for prevalence-based detections that need longer lookback windows
    #[sqlx(default)]
    pub lookback_minutes: Option<i32>,
    /// Dataset this rule queries: None/"logs" (default UDM/OCSF), "spans", or
    /// "metrics" (NAN-1561). Mirrors `SearchRequest.dataset`. Spans/metrics
    /// rules are SCHEDULED-ONLY — the real-time MV path rejects them.
    ///
    /// NOTE: a spans/metrics rule that wants risk scoring must set an explicit
    /// `risk_entity_field` to a column that exists in that dataset (e.g.
    /// `service_name`); `risk::ScoreCalculator::extract_entity` reads the field
    /// by name, so no UDM allowlist gates it. With no `risk_entity_field` the
    /// UDM auto-detection falls back to a default entity that won't exist in
    /// spans/metrics rows and the rule simply records no risk entity.
    #[sqlx(default)]
    pub dataset: Option<String>,
    /// Whether auto-tuning is enabled for this rule
    #[sqlx(default)]
    pub auto_tuning_enabled: bool,
    /// Minimum confidence threshold for auto-tuning (0.0-1.0)
    #[sqlx(default)]
    pub auto_tuning_min_confidence: f64,
    /// Whether this rule is marked as critical (prevents auto-tuning)
    #[sqlx(default)]
    pub auto_tuning_critical: bool,
    /// Timestamp until which auto-tuning is disabled (e.g., 7 days after revert)
    #[sqlx(default)]
    pub auto_tuning_disabled_until: Option<DateTime<Utc>>,
    /// Visibility to apply to cases created by this rule ('public', 'group', 'private')
    #[sqlx(default)]
    pub case_visibility: String,
    /// Group to assign cases to (queue routing). Overrides system default.
    #[sqlx(default)]
    pub case_assigned_group: Option<Uuid>,
    /// Alert mode: grouped (all matches → 1 alert) or per_event (each match → 1 alert)
    #[sqlx(default)]
    pub alert_mode: AlertMode,
    /// Next scheduled execution time (persisted for distributed SKIP LOCKED scheduling)
    #[sqlx(default)]
    pub next_run_at: Option<DateTime<Utc>>,
    /// Node ID currently executing this rule (NULL = available for claiming)
    #[sqlx(default)]
    pub claimed_by: Option<String>,
    /// When the rule was claimed (for stale claim recovery)
    #[sqlx(default)]
    pub claimed_at: Option<DateTime<Utc>>,
    /// Playbook attachment mode for alerts produced by this rule: 'none', 'specific', or 'adaptive'
    #[sqlx(default)]
    pub playbook_selector_mode: String,
    /// Library playbook to attach when rule fires (only set when playbook_selector_mode = 'specific')
    #[sqlx(default)]
    #[serde(default, with = "typeid::playbook::opt")]
    #[schema(value_type = Option<String>)]
    pub playbook_id: Option<Uuid>,
}

/// Input for creating a new detection rule
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct NewDetectionRule {
    pub name: String,
    pub description: Option<String>,
    pub query: String,
    pub severity: Severity,
    pub mitre_tactics: Option<Vec<String>>,
    pub mitre_techniques: Option<Vec<String>>,
    pub schedule_cron: Option<String>,
    /// Rule mode - defaults to Staging for new rules being developed
    pub mode: Option<RuleMode>,
    /// AI-generated narrative explaining what the rule detects
    pub narrative: Option<String>,
    /// Reference URL for more information
    pub reference_url: Option<String>,
    /// Author of the rule
    pub author: Option<String>,
    /// Tags for categorization
    pub tags: Option<Vec<String>>,
    /// Whether this rule was created using AI assistance
    pub ai_generated: Option<bool>,
    /// Whether real-time detection is enabled for this rule
    pub realtime_enabled: Option<bool>,
    /// Detection execution mode (real-time or scheduled)
    pub detection_mode: Option<DetectionMode>,
    /// Base risk score (0-100), defaults based on severity if not set
    pub risk_score: Option<i32>,
    /// UDM field to extract risk entity from (e.g., src_ip, user, hostname)
    pub risk_entity_field: Option<String>,
    /// Conditional score modifiers
    pub risk_modifiers: Option<Vec<RiskModifier>>,
    /// Custom lookback period in minutes for scheduled execution
    pub lookback_minutes: Option<i32>,
    /// Dataset this rule queries: "logs" (default), "spans", or "metrics".
    /// Spans/metrics force scheduled mode.
    pub dataset: Option<String>,
    /// Whether auto-tuning is enabled for this rule
    pub auto_tuning_enabled: Option<bool>,
    /// Minimum confidence threshold for auto-tuning (0.0-1.0)
    pub auto_tuning_min_confidence: Option<f64>,
    /// Whether this rule is marked as critical (prevents auto-tuning)
    pub auto_tuning_critical: Option<bool>,
    /// AI triage hints for guiding automated alert analysis
    pub ai_triage_hints: Option<AiTriageHints>,
    /// Folder for organizing rules (network, identity, endpoint, cloud, stash, or custom)
    pub folder: Option<String>,
    /// Visibility for cases created by this rule ('public', 'group', 'private')
    pub case_visibility: Option<String>,
    /// Group IDs for case permissions (when case_visibility = 'group')
    pub case_group_ids: Option<Vec<Uuid>>,
    /// Group to assign cases to (queue routing). Overrides system default.
    pub case_assigned_group: Option<Uuid>,
    /// Alert mode: grouped (default) or per_event (each match → its own alert)
    pub alert_mode: Option<AlertMode>,
    /// Playbook attachment mode for alerts: 'none' (default), 'specific', or 'adaptive'
    pub playbook_selector_mode: Option<String>,
    /// Library playbook to attach (required when playbook_selector_mode = 'specific')
    #[serde(default, with = "typeid::playbook::opt")]
    #[schema(value_type = Option<String>)]
    pub playbook_id: Option<Uuid>,
}

/// Input for updating a detection rule
#[derive(Debug, Clone, Serialize, Deserialize, Default, utoipa::ToSchema)]
pub struct UpdateDetectionRule {
    pub name: Option<String>,
    pub description: Option<String>,
    pub query: Option<String>,
    pub severity: Option<Severity>,
    pub mitre_tactics: Option<Vec<String>>,
    pub mitre_techniques: Option<Vec<String>>,
    pub schedule_cron: Option<String>,
    /// Rule mode - set to Alerting when bake-in is complete
    pub mode: Option<RuleMode>,
    /// AI-generated narrative
    pub narrative: Option<String>,
    /// Reference URL
    pub reference_url: Option<String>,
    /// Author
    pub author: Option<String>,
    /// Tags
    pub tags: Option<Vec<String>>,
    /// Whether this rule was created using AI assistance
    pub ai_generated: Option<bool>,
    /// Whether real-time detection is enabled for this rule
    pub realtime_enabled: Option<bool>,
    /// Detection execution mode (real-time or scheduled)
    pub detection_mode: Option<DetectionMode>,
    /// Materialized view name for real-time rules (auto-generated)
    pub materialized_view_name: Option<Option<String>>,
    /// Base risk score (0-100), defaults based on severity if not set
    pub risk_score: Option<i32>,
    /// UDM field to extract risk entity from (e.g., src_ip, user, hostname)
    pub risk_entity_field: Option<String>,
    /// Conditional score modifiers
    pub risk_modifiers: Option<Vec<RiskModifier>>,
    /// Whether the rule is archived (hidden by default, must be unarchived before activating)
    pub archived: Option<bool>,
    /// Custom lookback period in minutes for scheduled execution
    pub lookback_minutes: Option<i32>,
    /// Dataset this rule queries: "logs" (default), "spans", or "metrics".
    pub dataset: Option<String>,
    /// Whether auto-tuning is enabled for this rule
    pub auto_tuning_enabled: Option<bool>,
    /// Minimum confidence threshold for auto-tuning (0.0-1.0)
    pub auto_tuning_min_confidence: Option<f64>,
    /// Whether this rule is marked as critical (prevents auto-tuning)
    pub auto_tuning_critical: Option<bool>,
    /// AI triage hints for guiding automated alert analysis
    pub ai_triage_hints: Option<AiTriageHints>,
    /// Folder for organizing rules (network, identity, endpoint, cloud, stash, or custom)
    pub folder: Option<String>,
    /// Visibility for cases created by this rule ('public', 'group', 'private')
    pub case_visibility: Option<String>,
    /// Group IDs for case permissions (when case_visibility = 'group')
    pub case_group_ids: Option<Vec<Uuid>>,
    /// Group to assign cases to (queue routing). Overrides system default.
    pub case_assigned_group: Option<Uuid>,
    /// Alert mode: grouped or per_event (each match → its own alert)
    pub alert_mode: Option<AlertMode>,
    /// Playbook attachment mode for alerts: 'none', 'specific', or 'adaptive'
    pub playbook_selector_mode: Option<String>,
    /// Library playbook to attach (set only when playbook_selector_mode = 'specific';
    /// server clears automatically when mode becomes 'none' or 'adaptive')
    #[serde(default, with = "typeid::playbook::opt")]
    #[schema(value_type = Option<String>)]
    pub playbook_id: Option<Uuid>,
}

/// Validation error for detection rule risk fields
#[derive(Debug, Clone, PartialEq)]
pub enum RiskValidationError {
    /// Risk score is outside the valid range (0-100)
    ScoreOutOfBounds(i32),
    /// Risk modifier score is outside the valid range (0-100)
    ModifierScoreOutOfBounds(i32),
    /// Risk modifier condition is invalid
    InvalidModifierCondition(String),
}

/// Validation error for detection rule auto-tuning fields
#[derive(Debug, Clone, PartialEq)]
pub enum AutoTuningValidationError {
    /// Auto-tuning confidence threshold is outside the valid range (0.0-1.0)
    ConfidenceOutOfBounds(f64),
}

/// Validation error for detection rule fields
#[derive(Debug, Clone, PartialEq)]
pub enum FieldValidationError {
    /// case_visibility has an invalid value (must be "public", "group", or "private")
    InvalidCaseVisibility(String),
    /// case_visibility is "group" but no group_ids provided
    GroupVisibilityWithoutGroups,
    /// lookback_minutes is out of valid range (must be 1-10080, i.e., 1 minute to 7 days)
    LookbackMinutesOutOfBounds(i32),
    /// folder has an invalid value
    InvalidFolder(String),
    /// playbook_selector_mode has an invalid value
    InvalidPlaybookSelectorMode(String),
    /// playbook_selector_mode is 'specific' but no playbook_id provided
    SpecificPlaybookWithoutId,
    /// playbook_id provided but playbook_selector_mode is not 'specific'
    PlaybookIdWithoutSpecificMode,
    /// dataset has an invalid value (must be 'logs', 'spans', or 'metrics')
    InvalidDataset(String),
}

impl std::fmt::Display for RiskValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RiskValidationError::ScoreOutOfBounds(score) => {
                write!(f, "Risk score {} is out of bounds (must be 0-100)", score)
            }
            RiskValidationError::ModifierScoreOutOfBounds(score) => {
                write!(
                    f,
                    "Risk modifier score {} is out of bounds (must be 0-100)",
                    score
                )
            }
            RiskValidationError::InvalidModifierCondition(msg) => {
                write!(f, "Invalid risk modifier condition: {}", msg)
            }
        }
    }
}

impl std::error::Error for RiskValidationError {}

impl std::fmt::Display for AutoTuningValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AutoTuningValidationError::ConfidenceOutOfBounds(confidence) => {
                write!(
                    f,
                    "Auto-tuning confidence threshold {} is out of bounds (must be 0.0-1.0)",
                    confidence
                )
            }
        }
    }
}

impl std::error::Error for AutoTuningValidationError {}

impl std::fmt::Display for FieldValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FieldValidationError::InvalidCaseVisibility(value) => {
                write!(
                    f,
                    "Invalid case_visibility '{}' (must be 'public', 'group', or 'private')",
                    value
                )
            }
            FieldValidationError::GroupVisibilityWithoutGroups => {
                write!(
                    f,
                    "case_visibility is 'group' but no case_group_ids provided"
                )
            }
            FieldValidationError::LookbackMinutesOutOfBounds(minutes) => {
                write!(
                    f,
                    "lookback_minutes {} is out of bounds (must be 1-10080)",
                    minutes
                )
            }
            FieldValidationError::InvalidFolder(value) => {
                write!(f, "Invalid folder '{}' (must be 'network', 'identity', 'endpoint', 'cloud', 'stash', or custom alphanumeric)", value)
            }
            FieldValidationError::InvalidPlaybookSelectorMode(value) => {
                write!(f, "Invalid playbook_selector_mode '{}' (must be 'none', 'specific', or 'adaptive')", value)
            }
            FieldValidationError::SpecificPlaybookWithoutId => {
                write!(f, "playbook_selector_mode is 'specific' but no playbook_id provided")
            }
            FieldValidationError::PlaybookIdWithoutSpecificMode => {
                write!(f, "playbook_id provided but playbook_selector_mode is not 'specific'")
            }
            FieldValidationError::InvalidDataset(value) => {
                write!(f, "Invalid dataset '{}' (must be 'logs', 'spans', or 'metrics')", value)
            }
        }
    }
}

impl std::error::Error for FieldValidationError {}

/// Valid case visibility values
pub const VALID_CASE_VISIBILITIES: &[&str] = &["public", "group", "private"];

/// Valid folder values (built-in, custom folders are allowed if alphanumeric)
pub const BUILTIN_FOLDERS: &[&str] = &["network", "identity", "endpoint", "cloud", "stash"];

/// Maximum lookback period in minutes (7 days)
pub const MAX_LOOKBACK_MINUTES: i32 = 10080;

/// Valid playbook selector modes (rule → playbook assignment at firing time)
pub const VALID_PLAYBOOK_SELECTOR_MODES: &[&str] = &["none", "specific", "adaptive"];

/// Valid dataset values for a detection rule (NAN-1561). NULL/"logs" = default
/// UDM/OCSF logs; "spans"/"metrics" = OTLP datasets (scheduled-only).
pub const VALID_DATASETS: &[&str] = &["logs", "spans", "metrics"];

impl NewDetectionRule {
    /// Validate risk-related fields
    ///
    /// Returns Ok(()) if all risk fields are valid, or an error describing the validation failure.
    pub fn validate_risk_fields(&self) -> Result<(), RiskValidationError> {
        // Validate risk_score bounds (0-100)
        if let Some(score) = self.risk_score {
            if score < 0 || score > 100 {
                return Err(RiskValidationError::ScoreOutOfBounds(score));
            }
        }

        // Validate risk_modifiers
        if let Some(ref modifiers) = self.risk_modifiers {
            for modifier in modifiers {
                // Validate modifier score bounds
                if modifier.score < 0 || modifier.score > 100 {
                    return Err(RiskValidationError::ModifierScoreOutOfBounds(
                        modifier.score,
                    ));
                }
                // Validate modifier condition
                if let Err(e) = RiskModifier::validate_condition(&modifier.condition) {
                    return Err(RiskValidationError::InvalidModifierCondition(e.to_string()));
                }
            }
        }

        Ok(())
    }

    /// Validate auto-tuning related fields
    ///
    /// Returns Ok(()) if all auto-tuning fields are valid, or an error describing the validation failure.
    pub fn validate_auto_tuning_fields(&self) -> Result<(), AutoTuningValidationError> {
        // Validate auto_tuning_min_confidence bounds (0.0-1.0); the negated
        // contains() also rejects NaN, which would otherwise pass both
        // comparisons and trip the database check constraint
        if let Some(confidence) = self.auto_tuning_min_confidence {
            if !(0.0..=1.0).contains(&confidence) {
                return Err(AutoTuningValidationError::ConfidenceOutOfBounds(confidence));
            }
        }

        Ok(())
    }

    /// Validate field constraints (case_visibility, lookback_minutes, folder)
    ///
    /// Returns Ok(()) if all fields are valid, or an error describing the validation failure.
    pub fn validate_fields(&self) -> Result<(), FieldValidationError> {
        // Validate case_visibility enum
        if let Some(ref visibility) = self.case_visibility {
            if !VALID_CASE_VISIBILITIES.contains(&visibility.as_str()) {
                return Err(FieldValidationError::InvalidCaseVisibility(
                    visibility.clone(),
                ));
            }
            // If visibility is "group", ensure group_ids are provided
            if visibility == "group" {
                match &self.case_group_ids {
                    None => return Err(FieldValidationError::GroupVisibilityWithoutGroups),
                    Some(ids) if ids.is_empty() => {
                        return Err(FieldValidationError::GroupVisibilityWithoutGroups)
                    }
                    _ => {}
                }
            }
        }

        // Validate lookback_minutes bounds (1 minute to 7 days)
        if let Some(minutes) = self.lookback_minutes {
            if minutes < 1 || minutes > MAX_LOOKBACK_MINUTES {
                return Err(FieldValidationError::LookbackMinutesOutOfBounds(minutes));
            }
        }

        // Validate folder - must be builtin or alphanumeric custom
        if let Some(ref folder) = self.folder {
            let is_valid = BUILTIN_FOLDERS.contains(&folder.as_str())
                || (folder.len() <= 50
                    && folder
                        .chars()
                        .all(|c| c.is_alphanumeric() || c == '_' || c == '-'));
            if !is_valid {
                return Err(FieldValidationError::InvalidFolder(folder.clone()));
            }
        }

        // Validate playbook selector mode + playbook_id coupling
        let mode = self.playbook_selector_mode.as_deref().unwrap_or("none");
        if !VALID_PLAYBOOK_SELECTOR_MODES.contains(&mode) {
            return Err(FieldValidationError::InvalidPlaybookSelectorMode(
                mode.to_string(),
            ));
        }
        match (mode, self.playbook_id) {
            ("specific", None) => return Err(FieldValidationError::SpecificPlaybookWithoutId),
            ("none" | "adaptive", Some(_)) => {
                return Err(FieldValidationError::PlaybookIdWithoutSpecificMode)
            }
            _ => {}
        }

        // Validate dataset (NAN-1561). An unknown value would otherwise silently
        // degrade to a logs scan via Dataset::from_selector, so reject it here.
        if let Some(ref ds) = self.dataset {
            if !VALID_DATASETS.contains(&ds.as_str()) {
                return Err(FieldValidationError::InvalidDataset(ds.clone()));
            }
        }

        Ok(())
    }
}

impl UpdateDetectionRule {
    /// Validate risk-related fields
    ///
    /// Returns Ok(()) if all risk fields are valid, or an error describing the validation failure.
    pub fn validate_risk_fields(&self) -> Result<(), RiskValidationError> {
        // Validate risk_score bounds (0-100)
        if let Some(score) = self.risk_score {
            if score < 0 || score > 100 {
                return Err(RiskValidationError::ScoreOutOfBounds(score));
            }
        }

        // Validate risk_modifiers
        if let Some(ref modifiers) = self.risk_modifiers {
            for modifier in modifiers {
                // Validate modifier score bounds
                if modifier.score < 0 || modifier.score > 100 {
                    return Err(RiskValidationError::ModifierScoreOutOfBounds(
                        modifier.score,
                    ));
                }
                // Validate modifier condition
                if let Err(e) = RiskModifier::validate_condition(&modifier.condition) {
                    return Err(RiskValidationError::InvalidModifierCondition(e.to_string()));
                }
            }
        }

        Ok(())
    }

    /// Validate auto-tuning related fields
    ///
    /// Returns Ok(()) if all auto-tuning fields are valid, or an error describing the validation failure.
    pub fn validate_auto_tuning_fields(&self) -> Result<(), AutoTuningValidationError> {
        // Validate auto_tuning_min_confidence bounds (0.0-1.0); the negated
        // contains() also rejects NaN, which would otherwise pass both
        // comparisons and trip the database check constraint
        if let Some(confidence) = self.auto_tuning_min_confidence {
            if !(0.0..=1.0).contains(&confidence) {
                return Err(AutoTuningValidationError::ConfidenceOutOfBounds(confidence));
            }
        }

        Ok(())
    }

    /// Validate field constraints (case_visibility, lookback_minutes, folder)
    ///
    /// Returns Ok(()) if all fields are valid, or an error describing the validation failure.
    pub fn validate_fields(&self) -> Result<(), FieldValidationError> {
        // Validate case_visibility enum
        if let Some(ref visibility) = self.case_visibility {
            if !VALID_CASE_VISIBILITIES.contains(&visibility.as_str()) {
                return Err(FieldValidationError::InvalidCaseVisibility(
                    visibility.clone(),
                ));
            }
            // If visibility is "group", ensure group_ids are provided
            if visibility == "group" {
                match &self.case_group_ids {
                    None => return Err(FieldValidationError::GroupVisibilityWithoutGroups),
                    Some(ids) if ids.is_empty() => {
                        return Err(FieldValidationError::GroupVisibilityWithoutGroups)
                    }
                    _ => {}
                }
            }
        }

        // Validate lookback_minutes bounds (1 minute to 7 days)
        if let Some(minutes) = self.lookback_minutes {
            if minutes < 1 || minutes > MAX_LOOKBACK_MINUTES {
                return Err(FieldValidationError::LookbackMinutesOutOfBounds(minutes));
            }
        }

        // Validate folder - must be builtin or alphanumeric custom
        if let Some(ref folder) = self.folder {
            let is_valid = BUILTIN_FOLDERS.contains(&folder.as_str())
                || (folder.len() <= 50
                    && folder
                        .chars()
                        .all(|c| c.is_alphanumeric() || c == '_' || c == '-'));
            if !is_valid {
                return Err(FieldValidationError::InvalidFolder(folder.clone()));
            }
        }

        // Validate playbook selector mode + playbook_id coupling.
        // In Update semantics: only check if mode is explicitly being set.
        // If the caller is setting mode='specific' without a playbook_id in the
        // same patch, reject — they must update both together. Conversely,
        // if the caller supplies a playbook_id with mode!='specific', reject.
        if let Some(ref mode) = self.playbook_selector_mode {
            if !VALID_PLAYBOOK_SELECTOR_MODES.contains(&mode.as_str()) {
                return Err(FieldValidationError::InvalidPlaybookSelectorMode(
                    mode.clone(),
                ));
            }
            match (mode.as_str(), self.playbook_id) {
                ("specific", None) => return Err(FieldValidationError::SpecificPlaybookWithoutId),
                ("none" | "adaptive", Some(_)) => {
                    return Err(FieldValidationError::PlaybookIdWithoutSpecificMode)
                }
                _ => {}
            }
        }

        // Validate dataset (NAN-1561) if it is being set in this patch.
        if let Some(ref ds) = self.dataset {
            if !VALID_DATASETS.contains(&ds.as_str()) {
                return Err(FieldValidationError::InvalidDataset(ds.clone()));
            }
        }

        Ok(())
    }
}

// =============================================================================
// Case Permission Types for Detection Rules
// =============================================================================

use crate::models::SharedGroup;

/// Detection rule with case permission groups included
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct DetectionRuleWithCaseGroups {
    #[serde(flatten)]
    pub rule: DetectionRule,
    /// Groups that cases from this rule will be shared with
    pub case_groups: Vec<SharedGroup>,
}

/// Request to update case permissions for a detection rule
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct UpdateRuleCasePermissionsRequest {
    /// Visibility for cases created by this rule ('public', 'group', 'private')
    pub case_visibility: String,
    /// Group IDs for case permissions (required when case_visibility = 'group')
    pub case_group_ids: Option<Vec<Uuid>>,
    /// Group to assign cases to (queue routing). Overrides system default.
    pub case_assigned_group: Option<Uuid>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn new_rule_with_confidence(confidence: Option<f64>) -> NewDetectionRule {
        NewDetectionRule {
            name: "Test Rule".to_string(),
            description: None,
            query: "error".to_string(),
            severity: Severity::Medium,
            mitre_tactics: None,
            mitre_techniques: None,
            schedule_cron: None,
            mode: None,
            narrative: None,
            reference_url: None,
            author: None,
            tags: None,
            ai_generated: None,
            realtime_enabled: None,
            detection_mode: None,
            risk_score: None,
            risk_entity_field: None,
            risk_modifiers: None,
            lookback_minutes: None,
            dataset: None,
            auto_tuning_enabled: None,
            auto_tuning_min_confidence: confidence,
            auto_tuning_critical: None,
            ai_triage_hints: None,
            folder: None,
            case_visibility: None,
            case_group_ids: None,
            case_assigned_group: None,
            alert_mode: None,
            playbook_selector_mode: None,
            playbook_id: None,
        }
    }

    #[test]
    fn new_rule_confidence_out_of_bounds_rejected() {
        for confidence in [-1.0, -0.001, 1.001, 1.5, f64::NAN, f64::INFINITY] {
            let rule = new_rule_with_confidence(Some(confidence));
            assert!(
                matches!(
                    rule.validate_auto_tuning_fields(),
                    Err(AutoTuningValidationError::ConfidenceOutOfBounds(_))
                ),
                "confidence {} should be rejected",
                confidence
            );
        }
    }

    #[test]
    fn new_rule_confidence_in_bounds_accepted() {
        for confidence in [0.0, 0.5, 1.0] {
            let rule = new_rule_with_confidence(Some(confidence));
            assert!(
                rule.validate_auto_tuning_fields().is_ok(),
                "confidence {} should be accepted",
                confidence
            );
        }
        assert!(new_rule_with_confidence(None)
            .validate_auto_tuning_fields()
            .is_ok());
    }

    #[test]
    fn new_rule_critical_with_auto_tuning_enabled_accepted() {
        // The rule editor's auto-tune popover allows marking a rule critical
        // while auto-tuning stays enabled (critical = reviewer sign-off
        // required); validation must not reject that combination
        let mut rule = new_rule_with_confidence(Some(0.8));
        rule.auto_tuning_enabled = Some(true);
        rule.auto_tuning_critical = Some(true);
        assert!(rule.validate_auto_tuning_fields().is_ok());
    }

    #[test]
    fn update_rule_confidence_out_of_bounds_rejected() {
        for confidence in [-1.0, 1.5, f64::NAN] {
            let update = UpdateDetectionRule {
                auto_tuning_min_confidence: Some(confidence),
                ..Default::default()
            };
            assert!(
                matches!(
                    update.validate_auto_tuning_fields(),
                    Err(AutoTuningValidationError::ConfidenceOutOfBounds(_))
                ),
                "confidence {} should be rejected",
                confidence
            );
        }
    }

    #[test]
    fn update_rule_confidence_in_bounds_accepted() {
        for confidence in [Some(0.0), Some(0.5), Some(1.0), None] {
            let update = UpdateDetectionRule {
                auto_tuning_min_confidence: confidence,
                ..Default::default()
            };
            assert!(
                update.validate_auto_tuning_fields().is_ok(),
                "confidence {:?} should be accepted",
                confidence
            );
        }
    }

    #[test]
    fn update_rule_critical_only_partial_update_accepted() {
        // A partial update flipping only auto_tuning_critical must not be
        // rejected regardless of the rule's stored auto_tuning_enabled state
        let update = UpdateDetectionRule {
            auto_tuning_critical: Some(true),
            ..Default::default()
        };
        assert!(update.validate_auto_tuning_fields().is_ok());
    }
}
