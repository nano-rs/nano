// SPDX-License-Identifier: AGPL-3.0-or-later

//! AI Detection Auto-Tuning Types
//!
//! Core types for the auto-tuning system including metrics, baselines,
//! threshold breaches, tuning proposals, test results, and audit logs.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

use crate::models::AiTriageHints;

/// Status of a baseline: provisional (early data) vs established (full confidence)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum BaselineStatus {
    /// Provisional baseline (< 7 days or < 168 data points). Uses wider thresholds (mean + 3σ).
    #[default]
    Provisional,
    /// Established baseline (7+ days and 168+ data points). Uses standard thresholds (mean + 2σ).
    Established,
}

/// Type of tuning proposal
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum ProposalType {
    /// Query tuning - modifies the detection rule query
    #[default]
    QueryTuning,
    /// Hint update - updates AI triage hints for the rule
    HintUpdate,
}

impl std::fmt::Display for ProposalType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProposalType::QueryTuning => write!(f, "query_tuning"),
            ProposalType::HintUpdate => write!(f, "hint_update"),
        }
    }
}

impl std::str::FromStr for ProposalType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "query_tuning" => Ok(ProposalType::QueryTuning),
            "hint_update" => Ok(ProposalType::HintUpdate),
            _ => Err(format!("Unknown proposal type: {}", s)),
        }
    }
}

/// Diff between current and proposed AI triage hints
#[derive(Debug, Clone, Default, Serialize, Deserialize, utoipa::ToSchema)]
pub struct HintsDiff {
    /// Conditions added to ignore_when
    pub added_ignore: Vec<String>,
    /// Conditions removed from ignore_when
    pub removed_ignore: Vec<String>,
    /// Conditions added to suspicious_when
    pub added_suspicious: Vec<String>,
    /// Conditions removed from suspicious_when
    pub removed_suspicious: Vec<String>,
    /// Whether the context field changed
    pub context_changed: bool,
    /// Previous context value (if changed)
    pub old_context: Option<String>,
    /// New context value (if changed)
    pub new_context: Option<String>,
}

impl HintsDiff {
    /// Calculate the diff between two AiTriageHints
    pub fn calculate(current: &AiTriageHints, proposed: &AiTriageHints) -> Self {
        let added_ignore: Vec<String> = proposed
            .ignore_when
            .iter()
            .filter(|h| !current.ignore_when.contains(h))
            .cloned()
            .collect();

        let removed_ignore: Vec<String> = current
            .ignore_when
            .iter()
            .filter(|h| !proposed.ignore_when.contains(h))
            .cloned()
            .collect();

        let added_suspicious: Vec<String> = proposed
            .suspicious_when
            .iter()
            .filter(|h| !current.suspicious_when.contains(h))
            .cloned()
            .collect();

        let removed_suspicious: Vec<String> = current
            .suspicious_when
            .iter()
            .filter(|h| !proposed.suspicious_when.contains(h))
            .cloned()
            .collect();

        let context_changed = current.context != proposed.context;

        Self {
            added_ignore,
            removed_ignore,
            added_suspicious,
            removed_suspicious,
            context_changed,
            old_context: if context_changed {
                current.context.clone()
            } else {
                None
            },
            new_context: if context_changed {
                proposed.context.clone()
            } else {
                None
            },
        }
    }

    /// Check if there are any changes
    pub fn has_changes(&self) -> bool {
        !self.added_ignore.is_empty()
            || !self.removed_ignore.is_empty()
            || !self.added_suspicious.is_empty()
            || !self.removed_suspicious.is_empty()
            || self.context_changed
    }

    /// Get a summary of changes
    pub fn summary(&self) -> Vec<String> {
        let mut changes = Vec::new();

        if !self.added_ignore.is_empty() {
            changes.push(format!(
                "Added {} benign condition(s)",
                self.added_ignore.len()
            ));
        }
        if !self.removed_ignore.is_empty() {
            changes.push(format!(
                "Removed {} benign condition(s)",
                self.removed_ignore.len()
            ));
        }
        if !self.added_suspicious.is_empty() {
            changes.push(format!(
                "Added {} suspicious condition(s)",
                self.added_suspicious.len()
            ));
        }
        if !self.removed_suspicious.is_empty() {
            changes.push(format!(
                "Removed {} suspicious condition(s)",
                self.removed_suspicious.len()
            ));
        }
        if self.context_changed {
            changes.push("Updated context".to_string());
        }

        changes
    }
}

/// Metrics collected for a detection rule
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow, utoipa::ToSchema)]
pub struct RuleMetrics {
    /// Rule ID
    pub rule_id: Uuid,
    /// Timestamp when metrics were collected
    pub timestamp: DateTime<Utc>,
    /// Alert count in the last 1 hour
    pub alert_count_1h: i64,
    /// Alert count in the last 24 hours
    pub alert_count_24h: i64,
    /// Alert count in the last 7 days
    pub alert_count_7d: i64,
    /// Number of unique users in alerts
    pub unique_users: i64,
    /// Number of unique hosts in alerts
    pub unique_hosts: i64,
    /// Number of unique IP addresses in alerts
    pub unique_ips: i64,
    /// Average severity of alerts
    pub avg_severity: f64,
    /// Query execution time in milliseconds
    pub execution_time_ms: i64,
}

/// Pattern identified in alerts
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct AlertPattern {
    /// Field name (e.g., "process.name")
    pub field_name: String,
    /// Field value (e.g., "chrome.exe")
    pub field_value: String,
    /// Number of times this pattern occurred
    pub occurrence_count: i64,
    /// Percentage of total alerts with this pattern
    pub percentage: f64,
}

/// Statistical baseline for a detection rule
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow, utoipa::ToSchema)]
pub struct Baseline {
    /// Rule ID
    pub rule_id: Uuid,
    /// When the baseline was first established
    pub established_at: DateTime<Utc>,
    /// Last time the baseline was updated
    pub last_updated: DateTime<Utc>,
    /// Mean alerts per hour
    pub mean_alerts_per_hour: f64,
    /// Standard deviation of alerts per hour
    pub std_dev_alerts_per_hour: f64,
    /// 95th percentile of alerts per hour
    pub percentile_95: f64,
    /// 99th percentile of alerts per hour
    pub percentile_99: f64,
    /// Threshold for breach detection (mean + 2*std_dev)
    pub threshold_breach_level: f64,
    /// Number of data points used to calculate baseline
    pub data_points: i32,
    /// Whether the baseline is provisional or established (computed, not stored)
    #[sqlx(skip)]
    #[serde(default)]
    pub status: BaselineStatus,
}

impl Baseline {
    /// Compute the baseline status based on age and data points.
    /// Established requires 7+ days of data AND 168+ data points.
    pub fn compute_status(&mut self) {
        let age = Utc::now().signed_duration_since(self.established_at);
        if age >= chrono::Duration::days(7) && self.data_points >= 168 {
            self.status = BaselineStatus::Established;
        } else {
            self.status = BaselineStatus::Provisional;
        }
    }
}

/// Threshold breach detected for a rule
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow, utoipa::ToSchema)]
pub struct ThresholdBreach {
    /// Rule ID
    pub rule_id: Uuid,
    /// When the breach was detected
    pub detected_at: DateTime<Utc>,
    /// Current alert volume
    pub current_value: f64,
    /// Baseline mean value
    pub baseline_mean: f64,
    /// Baseline threshold (mean + 2*std_dev)
    pub baseline_threshold: f64,
    /// Magnitude of deviation in standard deviations
    pub deviation_magnitude: f64,
    /// Number of consecutive periods in breach
    pub consecutive_periods: i32,
    /// Whether this breach should trigger auto-tuning
    #[sqlx(rename = "tuning_triggered")]
    pub should_trigger_tuning: bool,
}

/// Safety validation result for a tuning proposal
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct SafetyValidation {
    /// Whether the proposal is safe to apply
    pub is_safe: bool,
    /// Whether critical security indicators are preserved
    pub critical_indicators_preserved: bool,
    /// List of validation checks performed
    pub validation_checks: Vec<SafetyCheck>,
    /// Warnings about the proposal
    pub warnings: Vec<String>,
}

/// Individual safety check result
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct SafetyCheck {
    /// Name of the check
    pub check_name: String,
    /// Whether the check passed
    pub passed: bool,
    /// Details about the check result
    pub details: String,
}

/// AI-generated tuning proposal for a detection rule
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct TuningProposal {
    /// Unique proposal ID
    pub id: Uuid,
    /// Rule ID being tuned
    pub rule_id: Uuid,
    /// When the proposal was created
    pub created_at: DateTime<Utc>,
    /// Type of proposal (query tuning or hint update)
    #[serde(default)]
    pub proposal_type: ProposalType,
    /// Original query before tuning (for query_tuning proposals)
    pub original_query: String,
    /// Proposed modified query (for query_tuning proposals)
    pub proposed_query: String,
    /// AI-generated rationale for the changes
    pub rationale: String,
    /// Confidence score (0.0 - 1.0)
    pub confidence_score: f64,
    /// Summary of changes made
    pub changes_summary: Vec<String>,
    /// Alert patterns that triggered this proposal
    pub affected_patterns: Vec<AlertPattern>,
    /// Safety validation results
    pub safety_validation: SafetyValidation,
    /// Current status of the proposal
    #[serde(default = "default_tuning_status")]
    pub status: TuningStatus,
    /// Current hints snapshot (for hint_update proposals)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub current_hints: Option<AiTriageHints>,
    /// Proposed new hints (for hint_update proposals)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proposed_hints: Option<AiTriageHints>,
    /// Diff showing what changed in hints (for hint_update proposals)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hints_diff: Option<HintsDiff>,
}

fn default_tuning_status() -> TuningStatus {
    TuningStatus::Proposed
}

/// Comparison metrics between original and tuned rule
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct ComparisonMetrics {
    /// Number of alerts removed by tuning
    pub alerts_removed: i64,
    /// Number of alerts preserved
    pub alerts_preserved: i64,
    /// Number of unique entities removed
    pub unique_entities_removed: i64,
    /// Change in severity distribution
    pub severity_distribution_change: HashMap<String, i64>,
    /// Pattern changes
    pub pattern_changes: Vec<PatternChange>,
}

/// Change in alert pattern
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct PatternChange {
    /// Field name
    pub field_name: String,
    /// Field value
    pub field_value: String,
    /// Count before tuning
    pub before_count: i64,
    /// Count after tuning
    pub after_count: i64,
}

/// Test results for a tuning proposal
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct TestResults {
    /// Proposal ID being tested
    pub proposal_id: Uuid,
    /// When the test was performed
    pub tested_at: DateTime<Utc>,
    /// Number of alerts from original rule
    pub original_alert_count: i64,
    /// Number of alerts from tuned rule
    pub tuned_alert_count: i64,
    /// Percentage reduction in alerts
    pub reduction_percentage: f64,
    /// Whether known true positives still trigger
    pub true_positives_preserved: bool,
    /// Whether validation passed (30-80% reduction)
    pub validation_passed: bool,
    /// Detailed comparison metrics
    pub comparison_metrics: ComparisonMetrics,
}

/// Detection rule version
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct RuleVersion {
    /// Version ID
    pub id: i32,
    /// Rule ID
    pub rule_id: Uuid,
    /// Version number (incremental)
    pub version_number: i32,
    /// Query for this version
    pub query: String,
    /// Rule name
    pub name: String,
    /// Rule description
    pub description: Option<String>,
    /// Severity level
    pub severity: String,
    /// Whether this version is enabled
    pub enabled: bool,
    /// Whether this is the active version
    pub is_active: bool,
    /// When this version was created
    pub created_at: DateTime<Utc>,
    /// User who created this version
    pub created_by: Option<Uuid>,
    /// Reason for creating this version
    pub change_reason: String,
    /// Associated tuning proposal (if auto-tuned)
    pub tuning_proposal_id: Option<Uuid>,
    /// Version this was reverted from (if revert)
    pub reverted_from_version: Option<i32>,
}

/// Reason for creating a new rule version
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum VersionChangeReason {
    /// Manual edit by user
    ManualEdit,
    /// Automatic tuning applied
    AutoTuning,
    /// Reverted to previous version
    Revert,
    /// Initial rule creation
    InitialCreation,
}

impl std::fmt::Display for VersionChangeReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VersionChangeReason::ManualEdit => write!(f, "manual_edit"),
            VersionChangeReason::AutoTuning => write!(f, "auto_tuning"),
            VersionChangeReason::Revert => write!(f, "revert"),
            VersionChangeReason::InitialCreation => write!(f, "initial_creation"),
        }
    }
}

/// Status of a tuning operation
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum TuningStatus {
    /// Proposal has been created
    Proposed,
    /// Testing in progress
    Testing,
    /// Test passed validation
    TestPassed,
    /// Test failed validation
    TestFailed,
    /// Deployed to staging
    Staging,
    /// Promoted to production
    Promoted,
    /// Reverted to previous version
    Reverted,
    /// Manually approved by user
    ManuallyApproved,
    /// Rejected by user or system
    Rejected,
}

impl std::fmt::Display for TuningStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TuningStatus::Proposed => write!(f, "proposed"),
            TuningStatus::Testing => write!(f, "testing"),
            TuningStatus::TestPassed => write!(f, "test_passed"),
            TuningStatus::TestFailed => write!(f, "test_failed"),
            TuningStatus::Staging => write!(f, "staging"),
            TuningStatus::Promoted => write!(f, "promoted"),
            TuningStatus::Reverted => write!(f, "reverted"),
            TuningStatus::ManuallyApproved => write!(f, "manually_approved"),
            TuningStatus::Rejected => write!(f, "rejected"),
        }
    }
}

/// Staging deployment information
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct StagingDeployment {
    /// Deployment ID
    pub id: Uuid,
    /// Proposal ID
    pub proposal_id: Uuid,
    /// Rule ID
    pub rule_id: Uuid,
    /// Version ID deployed to staging
    pub version_id: i32,
    /// When staging deployment started
    pub deployed_at: DateTime<Utc>,
    /// When staging period ends
    pub staging_ends_at: DateTime<Utc>,
    /// Whether staging validation passed
    pub validation_passed: Option<bool>,
    /// When promoted to production (if applicable)
    pub promoted_at: Option<DateTime<Utc>>,
}

/// Tuning log entry for audit trail
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct TuningLogEntry {
    /// Log entry ID
    pub id: Uuid,
    /// Rule ID
    pub rule_id: Uuid,
    /// Rule name at time of tuning
    pub rule_name: String,
    /// When tuning was triggered
    pub triggered_at: DateTime<Utc>,
    /// Reason for triggering tuning
    pub trigger_reason: String,
    /// The tuning proposal
    pub proposal: TuningProposal,
    /// Test results (if tested)
    pub test_results: Option<TestResults>,
    /// Staging deployment info (if deployed)
    pub staging_deployment: Option<StagingDeployment>,
    /// Current status
    pub status: TuningStatus,
    /// When reverted (if applicable)
    pub reverted_at: Option<DateTime<Utc>>,
    /// User who reverted (if applicable)
    pub reverted_by: Option<Uuid>,
    /// Reason for revert (if applicable)
    pub revert_reason: Option<String>,
}

/// Type of notification
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum NotificationType {
    /// Tuning was triggered
    TuningTriggered,
    /// Validation completed
    ValidationComplete,
    /// Deployed to staging
    StagingDeployed,
    /// Promoted to production
    Promoted,
    /// Reverted to previous version
    Reverted,
}

impl std::fmt::Display for NotificationType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NotificationType::TuningTriggered => write!(f, "tuning_triggered"),
            NotificationType::ValidationComplete => write!(f, "tuning_validation_complete"),
            NotificationType::StagingDeployed => write!(f, "tuning_staging_deployed"),
            NotificationType::Promoted => write!(f, "tuning_promoted"),
            NotificationType::Reverted => write!(f, "tuning_reverted"),
        }
    }
}

/// Notification for tuning events
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct Notification {
    /// Notification ID
    pub id: Uuid,
    /// User ID to notify
    pub user_id: Uuid,
    /// Type of notification
    pub notification_type: NotificationType,
    /// Notification title
    pub title: String,
    /// Notification message
    pub message: String,
    /// Link to relevant page
    pub link: String,
    /// When notification was created
    pub created_at: DateTime<Utc>,
    /// When notification was read (if applicable)
    pub read_at: Option<DateTime<Utc>>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version_change_reason_display() {
        assert_eq!(VersionChangeReason::ManualEdit.to_string(), "manual_edit");
        assert_eq!(VersionChangeReason::AutoTuning.to_string(), "auto_tuning");
        assert_eq!(VersionChangeReason::Revert.to_string(), "revert");
        assert_eq!(
            VersionChangeReason::InitialCreation.to_string(),
            "initial_creation"
        );
    }

    #[test]
    fn test_tuning_status_display() {
        assert_eq!(TuningStatus::Proposed.to_string(), "proposed");
        assert_eq!(TuningStatus::Testing.to_string(), "testing");
        assert_eq!(TuningStatus::TestPassed.to_string(), "test_passed");
        assert_eq!(TuningStatus::TestFailed.to_string(), "test_failed");
        assert_eq!(TuningStatus::Staging.to_string(), "staging");
        assert_eq!(TuningStatus::Promoted.to_string(), "promoted");
        assert_eq!(TuningStatus::Reverted.to_string(), "reverted");
        assert_eq!(
            TuningStatus::ManuallyApproved.to_string(),
            "manually_approved"
        );
        assert_eq!(TuningStatus::Rejected.to_string(), "rejected");
    }

    #[test]
    fn test_notification_type_display() {
        assert_eq!(
            NotificationType::TuningTriggered.to_string(),
            "tuning_triggered"
        );
        assert_eq!(
            NotificationType::ValidationComplete.to_string(),
            "tuning_validation_complete"
        );
        assert_eq!(
            NotificationType::StagingDeployed.to_string(),
            "tuning_staging_deployed"
        );
        assert_eq!(NotificationType::Promoted.to_string(), "tuning_promoted");
        assert_eq!(NotificationType::Reverted.to_string(), "tuning_reverted");
    }

    #[test]
    fn test_proposal_type_display() {
        assert_eq!(ProposalType::QueryTuning.to_string(), "query_tuning");
        assert_eq!(ProposalType::HintUpdate.to_string(), "hint_update");
    }

    #[test]
    fn test_proposal_type_from_str() {
        assert_eq!(
            "query_tuning".parse::<ProposalType>().unwrap(),
            ProposalType::QueryTuning
        );
        assert_eq!(
            "hint_update".parse::<ProposalType>().unwrap(),
            ProposalType::HintUpdate
        );
        assert!("invalid".parse::<ProposalType>().is_err());
    }

    #[test]
    fn test_hints_diff_calculate() {
        let current = AiTriageHints {
            ignore_when: vec!["condition1".to_string(), "condition2".to_string()],
            suspicious_when: vec!["suspicious1".to_string()],
            context: Some("old context".to_string()),
        };

        let proposed = AiTriageHints {
            ignore_when: vec!["condition1".to_string(), "condition3".to_string()],
            suspicious_when: vec!["suspicious1".to_string(), "suspicious2".to_string()],
            context: Some("new context".to_string()),
        };

        let diff = HintsDiff::calculate(&current, &proposed);

        assert_eq!(diff.added_ignore, vec!["condition3".to_string()]);
        assert_eq!(diff.removed_ignore, vec!["condition2".to_string()]);
        assert_eq!(diff.added_suspicious, vec!["suspicious2".to_string()]);
        assert!(diff.removed_suspicious.is_empty());
        assert!(diff.context_changed);
        assert_eq!(diff.old_context, Some("old context".to_string()));
        assert_eq!(diff.new_context, Some("new context".to_string()));
    }

    #[test]
    fn test_hints_diff_has_changes() {
        let empty_diff = HintsDiff::default();
        assert!(!empty_diff.has_changes());

        let diff_with_changes = HintsDiff {
            added_ignore: vec!["new condition".to_string()],
            ..Default::default()
        };
        assert!(diff_with_changes.has_changes());
    }

    #[test]
    fn test_hints_diff_summary() {
        let diff = HintsDiff {
            added_ignore: vec!["a".to_string(), "b".to_string()],
            removed_ignore: vec!["c".to_string()],
            added_suspicious: vec!["d".to_string()],
            removed_suspicious: vec![],
            context_changed: true,
            old_context: None,
            new_context: Some("context".to_string()),
        };

        let summary = diff.summary();
        assert_eq!(summary.len(), 4);
        assert!(summary.contains(&"Added 2 benign condition(s)".to_string()));
        assert!(summary.contains(&"Removed 1 benign condition(s)".to_string()));
        assert!(summary.contains(&"Added 1 suspicious condition(s)".to_string()));
        assert!(summary.contains(&"Updated context".to_string()));
    }
}
