// SPDX-License-Identifier: AGPL-3.0-or-later

//! Data models for rule repository feature

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use std::collections::HashMap;
use uuid::Uuid;

use crate::typeid;

// =============================================================================
// Rule Repository
// =============================================================================

/// External rule repository (public GitHub repos only)
#[derive(Debug, Clone, Serialize, Deserialize, FromRow, utoipa::ToSchema)]
pub struct RuleRepository {
    #[serde(with = "typeid::rule_repo")]
    #[schema(value_type = String)]
    pub id: Uuid,
    pub name: String,
    pub slug: String,
    pub description: Option<String>,
    pub url: String,
    pub branch: String,
    pub rules_path: Option<String>,
    pub rule_format: String,
    pub auto_sync_enabled: bool,
    pub sync_interval_hours: i32,
    pub last_synced_at: Option<DateTime<Utc>>,
    pub last_sync_commit: Option<String>,
    pub last_sync_status: Option<String>,
    pub last_sync_error: Option<String>,
    pub rule_count: i32,
    pub enabled: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    #[serde(default, with = "typeid::user::opt")]
    #[schema(value_type = Option<String>)]
    pub created_by: Option<Uuid>,
    /// Selected paths to sync. NULL = sync all, Some([]) = none, Some([...]) = only those
    pub selected_paths: Option<Vec<String>>,
}

/// Request to create a new rule repository
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NewRuleRepository {
    pub name: String,
    pub slug: Option<String>,
    pub description: Option<String>,
    pub url: String,
    pub branch: Option<String>,
    pub rules_path: Option<String>,
    pub rule_format: Option<String>,
    pub auto_sync_enabled: Option<bool>,
    pub sync_interval_hours: Option<i32>,
}

/// Information about a folder in a repository (for folder selection)
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct FolderInfo {
    /// Folder name (e.g., "windows")
    pub name: String,
    /// Full path (e.g., "rules/windows")
    pub path: String,
    /// Total file count in this folder
    pub file_count: i32,
    /// Rule file count (.yml/.yaml)
    pub rule_count: i32,
}

/// Request to update a rule repository
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct UpdateRuleRepository {
    pub name: Option<String>,
    pub description: Option<String>,
    pub branch: Option<String>,
    pub rules_path: Option<String>,
    pub auto_sync_enabled: Option<bool>,
    pub sync_interval_hours: Option<i32>,
    pub enabled: Option<bool>,
    /// Set selected paths for sync. Use Some(vec![]) to clear, None to leave unchanged.
    pub selected_paths: Option<Vec<String>>,
}

// =============================================================================
// Repository Rule (cached from external repo)
// =============================================================================

/// A rule cached from an external repository
#[derive(Debug, Clone, Serialize, Deserialize, FromRow, utoipa::ToSchema)]
pub struct RepositoryRule {
    #[serde(with = "typeid::repo_rule")]
    #[schema(value_type = String)]
    pub id: Uuid,
    #[serde(with = "typeid::rule_repo")]
    #[schema(value_type = String)]
    pub repository_id: Uuid,
    pub file_path: String,
    pub file_sha: Option<String>,
    pub raw_content: String,
    // Parsed metadata
    pub title: Option<String>,
    pub description: Option<String>,
    pub severity: Option<String>,
    pub mitre_tactics: Option<Vec<String>>,
    pub mitre_techniques: Option<Vec<String>>,
    pub tags: Option<Vec<String>>,
    // UDM requirements
    pub requires_fields: Option<Vec<String>>,
    pub requires_source_types: Option<Vec<String>>,
    // Conversion status
    pub conversion_status: String,
    pub converted_npl: Option<String>,
    pub conversion_confidence: Option<f64>,
    pub conversion_warnings: Option<Vec<String>>,
    pub conversion_field_mappings: Option<serde_json::Value>,
    // Coverage
    pub coverage_status: Option<String>,
    pub coverage_missing_fields: Option<Vec<String>>,
    // Timestamps
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Filter for listing repository rules
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RepositoryRuleFilter {
    pub path_prefix: Option<String>,
    pub severity: Option<String>,
    pub conversion_status: Option<String>,
    pub coverage_status: Option<String>,
    pub search: Option<String>,
    pub has_npl: Option<bool>,
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

// =============================================================================
// Rule Import (link between repo rule and detection rule)
// =============================================================================

/// Type of rule import
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ImportType {
    /// Rule is linked - will receive updates from upstream
    Linked,
    /// Rule is forked - independent copy, no auto-updates
    Forked,
}

impl std::fmt::Display for ImportType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ImportType::Linked => write!(f, "linked"),
            ImportType::Forked => write!(f, "forked"),
        }
    }
}

impl std::str::FromStr for ImportType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "linked" => Ok(ImportType::Linked),
            "forked" => Ok(ImportType::Forked),
            _ => Err(format!("Invalid import type: {}", s)),
        }
    }
}

/// Result of an `import_rule` call: distinguishes between a freshly-imported
/// rule and an existing import that was re-imported from a newer upstream
/// commit (NAN-673). Lets the batch handler bucket bulk-import results into
/// imported / updated / skipped instead of conflating "created" with "no-op".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ImportOutcome {
    /// A new detection rule was created.
    Created,
    /// An existing import was refreshed against newer upstream content.
    Updated,
}

/// A rule import record
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct RuleImport {
    #[serde(with = "typeid::rule_repo")]
    pub id: Uuid,
    #[serde(with = "typeid::repo_rule")]
    pub repository_rule_id: Uuid,
    #[serde(with = "typeid::rule")]
    pub detection_rule_id: Uuid,
    pub import_type: String,
    pub imported_at: DateTime<Utc>,
    #[serde(default, with = "typeid::user::opt")]
    pub imported_by: Option<Uuid>,
    pub imported_commit: Option<String>,
    pub last_sync_commit: Option<String>,
    pub upstream_changed: bool,
    pub customizations: Option<serde_json::Value>,
}

/// AI-generated hints for alert triage (passed from conversion)
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ConversionTriageHints {
    /// Conditions that make this especially suspicious
    #[serde(default)]
    pub suspicious_when: Vec<String>,
    /// Additional context about this detection for triage
    #[serde(default)]
    pub context: Option<String>,
}

/// Request to import a rule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportRequest {
    /// Import as linked or forked
    pub import_type: ImportType,
    /// Target folder for the detection rule
    pub folder: Option<String>,
    /// Override the rule name
    pub name: Option<String>,
    /// Override the severity
    pub severity: Option<String>,
    /// Override the mode (staging, live, alerting)
    pub mode: Option<String>,
    /// Custom nPL query (overrides conversion)
    pub custom_npl: Option<String>,
    /// AI-generated triage hints from conversion
    pub ai_triage_hints: Option<ConversionTriageHints>,
    /// Source type mappings: { original_type: replacement_type }
    pub source_type_mappings: Option<HashMap<String, String>>,
    /// Merge all source types to a single type
    pub merge_to_single_source_type: Option<String>,
}

impl Default for ImportRequest {
    fn default() -> Self {
        Self {
            import_type: ImportType::Linked,
            folder: None,
            name: None,
            severity: None,
            mode: None,
            custom_npl: None,
            ai_triage_hints: None,
            source_type_mappings: None,
            merge_to_single_source_type: None,
        }
    }
}

/// Preview of what importing a rule will create
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct ImportPreview {
    /// The repository rule being imported
    pub repository_rule: RepositoryRule,
    /// Proposed detection rule properties
    pub proposed_name: String,
    pub proposed_description: Option<String>,
    pub proposed_severity: String,
    pub proposed_query: Option<String>,
    pub proposed_mitre_tactics: Vec<String>,
    pub proposed_mitre_techniques: Vec<String>,
    /// Conversion details
    pub conversion_status: String,
    pub conversion_confidence: Option<f64>,
    pub conversion_warnings: Vec<String>,
    pub field_mappings: Option<serde_json::Value>,
    /// Coverage information
    pub coverage_status: Option<String>,
    pub missing_fields: Vec<String>,
    pub available_source_types: Vec<String>,
    /// Source type validation
    pub required_source_types: Vec<String>,
    pub missing_source_types: Vec<String>,
    pub source_type_suggestions: Vec<SourceTypeSuggestion>,
    /// Whether this rule has already been imported
    pub already_imported: bool,
    pub existing_import_type: Option<String>,
    #[serde(default, with = "typeid::rule::opt")]
    #[schema(value_type = Option<String>)]
    pub existing_detection_rule_id: Option<Uuid>,
}

/// Suggestion for an alternative source type
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct SourceTypeSuggestion {
    /// The source type that is missing
    pub missing_type: String,
    /// Suggested alternative source type
    pub suggested_type: String,
    /// Reason for the suggestion
    pub reason: String,
}

// =============================================================================
// Sync Types
// =============================================================================

/// Status of a sync operation
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SyncStatus {
    Success,
    Failed,
    Syncing,
}

impl std::fmt::Display for SyncStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SyncStatus::Success => write!(f, "success"),
            SyncStatus::Failed => write!(f, "failed"),
            SyncStatus::Syncing => write!(f, "syncing"),
        }
    }
}

/// Result of a sync operation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncResult {
    #[serde(with = "typeid::rule_repo")]
    pub repository_id: Uuid,
    pub status: SyncStatus,
    pub commit: Option<String>,
    pub rules_added: i32,
    pub rules_updated: i32,
    pub rules_removed: i32,
    pub rules_total: i32,
    pub conversion_succeeded: i32,
    pub conversion_failed: i32,
    pub duration_ms: u64,
    pub error: Option<String>,
}

/// A rule that has been updated upstream
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct UpdatedRule {
    #[serde(with = "typeid::repo_rule")]
    #[schema(value_type = String)]
    pub repository_rule_id: Uuid,
    #[serde(with = "typeid::rule")]
    #[schema(value_type = String)]
    pub detection_rule_id: Uuid,
    pub file_path: String,
    pub title: Option<String>,
    pub change_type: String, // "modified" | "deleted"
    pub old_sha: Option<String>,
    pub new_sha: Option<String>,
}

/// Diff between imported detection rule and upstream repository rule
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct UpstreamDiff {
    #[serde(with = "typeid::rule")]
    #[schema(value_type = String)]
    pub detection_rule_id: Uuid,
    #[serde(with = "typeid::repo_rule")]
    #[schema(value_type = String)]
    pub repository_rule_id: Uuid,
    pub file_path: String,
    pub upstream_title: Option<String>,
    pub upstream_description: Option<String>,
    pub upstream_severity: Option<String>,
    pub upstream_query: String,
    pub upstream_raw_content: String,
    pub current_query: String,
    pub current_title: String,
    pub current_description: Option<String>,
    pub has_changes: bool,
    /// Whether stored customizations (source_type mappings) were applied to upstream_query
    pub customizations_applied: Option<bool>,
}

// =============================================================================
// Coverage Types
// =============================================================================

/// Filter for coverage analysis
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CoverageFilter {
    #[serde(default, with = "typeid::rule_repo::opt")]
    pub repository_id: Option<Uuid>,
    pub severity: Option<String>,
    pub mitre_tactic: Option<String>,
    pub mitre_technique: Option<String>,
}

impl CoverageFilter {
    /// Return a canonical filter so equivalent API inputs share matching
    /// semantics across repository metadata from Sigma and nPL sources.
    pub(crate) fn normalized(&self) -> Self {
        Self {
            repository_id: self.repository_id,
            severity: normalize_optional_filter(
                self.severity.as_deref(),
                normalize_coverage_severity,
            ),
            mitre_tactic: normalize_optional_filter(
                self.mitre_tactic.as_deref(),
                normalize_coverage_tactic,
            ),
            mitre_technique: normalize_optional_filter(
                self.mitre_technique.as_deref(),
                normalize_technique,
            ),
        }
    }

    /// Whether a repository rule belongs to this canonical coverage scope.
    pub(crate) fn matches_normalized(&self, rule: &RepositoryRule) -> bool {
        if self
            .repository_id
            .is_some_and(|repository_id| repository_id != rule.repository_id)
        {
            return false;
        }

        if let Some(severity) = self.severity.as_deref() {
            if rule
                .severity
                .as_deref()
                .map(normalize_coverage_severity)
                .as_deref()
                != Some(severity)
            {
                return false;
            }
        }

        if let Some(tactic) = self.mitre_tactic.as_deref() {
            let matches_tactic = rule
                .mitre_tactics
                .as_deref()
                .unwrap_or_default()
                .iter()
                .any(|candidate| normalize_coverage_tactic(candidate) == tactic);
            if !matches_tactic {
                return false;
            }
        }

        if let Some(technique) = self.mitre_technique.as_deref() {
            let matches_technique = rule
                .mitre_techniques
                .as_deref()
                .unwrap_or_default()
                .iter()
                .any(|candidate| normalize_technique(candidate) == technique);
            if !matches_technique {
                return false;
            }
        }

        true
    }
}

fn normalize_optional_filter(
    value: Option<&str>,
    normalize: impl Fn(&str) -> String,
) -> Option<String> {
    value
        .map(normalize)
        .and_then(|value| (!value.is_empty()).then_some(value))
}

pub(crate) fn normalize_coverage_severity(value: &str) -> String {
    value.trim().to_ascii_lowercase()
}

pub(crate) fn normalize_coverage_tactic(value: &str) -> String {
    let normalized = normalize_coverage_severity(value)
        .split(|character: char| {
            character.is_ascii_whitespace() || character == '-' || character == '_'
        })
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>()
        .join("_");

    match normalized.as_str() {
        "reconnaissance" | "ta0043" => "TA0043",
        "resource_development" | "ta0042" => "TA0042",
        "initial_access" | "ta0001" => "TA0001",
        "execution" | "ta0002" => "TA0002",
        "persistence" | "ta0003" => "TA0003",
        "privilege_escalation" | "ta0004" => "TA0004",
        "defense_evasion" | "ta0005" => "TA0005",
        "credential_access" | "ta0006" => "TA0006",
        "discovery" | "ta0007" => "TA0007",
        "lateral_movement" | "ta0008" => "TA0008",
        "collection" | "ta0009" => "TA0009",
        "command_and_control" | "c2" | "ta0011" => "TA0011",
        "exfiltration" | "ta0010" => "TA0010",
        "impact" | "ta0040" => "TA0040",
        _ => return normalized,
    }
    .to_string()
}

fn normalize_technique(value: &str) -> String {
    value.trim().to_ascii_uppercase()
}

/// Result of coverage check for a single rule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoverageResult {
    pub status: String, // "full" | "partial" | "none"
    pub required_fields: Vec<String>,
    pub available_fields: Vec<String>,
    pub missing_fields: Vec<String>,
    pub suggested_source_types: Vec<String>,
    pub available_source_types: Vec<String>,
}

/// Aggregated coverage analysis
///
/// `Default` is the "nothing to report" shape returned when the caller may not
/// consult live telemetry at all (NAN-2081) — all counts zero, all lists empty.
#[derive(Debug, Clone, Default, Serialize, Deserialize, utoipa::ToSchema)]
pub struct CoverageAnalysis {
    pub total_rules: i32,
    pub full_coverage: i32,
    pub partial_coverage: i32,
    pub no_coverage: i32,
    pub coverage_by_severity: CoverageBySeverity,
    pub coverage_by_tactic: Vec<TacticCoverage>,
    pub most_missing_fields: Vec<MissingFieldCount>,
    pub suggested_source_types: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, utoipa::ToSchema)]
pub struct CoverageBySeverity {
    pub critical: CoverageCount,
    pub high: CoverageCount,
    pub medium: CoverageCount,
    pub low: CoverageCount,
    pub informational: CoverageCount,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, utoipa::ToSchema)]
pub struct CoverageCount {
    pub total: i32,
    pub full: i32,
    pub partial: i32,
    pub none: i32,
}

#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct TacticCoverage {
    pub tactic: String,
    pub tactic_name: String,
    pub total: i32,
    pub full: i32,
    pub partial: i32,
    pub none: i32,
}

#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct MissingFieldCount {
    pub field: String,
    pub count: i32,
    pub source_types_with_field: Vec<String>,
}

// =============================================================================
// Air-gapped Bundle Import (NAN-1220)
// =============================================================================

/// Aggregate result of syncing an air-gapped rule bundle into the synthetic
/// air-gap repository's catalog (NAN-1226). This is the offline equivalent of
/// a GitHub repo *sync* — the rules land as available-to-import; nothing is
/// imported or activated. The synthetic repository is returned so callers can
/// browse/import via the normal rule-repository surface.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct RuleBundleImportResult {
    /// The synthetic air-gap repository the bundle rules landed in.
    #[serde(with = "typeid::rule_repo")]
    #[schema(value_type = String)]
    pub repository_id: Uuid,
    /// Caller-defined content version from the bundle manifest.
    pub content_version: String,
    /// Number of rules synced (upserted) into the repository catalog.
    pub synced: usize,
}

#[cfg(test)]
mod coverage_filter_tests {
    use super::*;

    fn repository_rule(repository_id: Uuid) -> RepositoryRule {
        let now = Utc::now();
        RepositoryRule {
            id: Uuid::now_v7(),
            repository_id,
            file_path: "rules/example.yml".to_string(),
            file_sha: None,
            raw_content: String::new(),
            title: Some("Example".to_string()),
            description: None,
            severity: Some("HIGH".to_string()),
            mitre_tactics: Some(vec!["Credential Access".to_string()]),
            mitre_techniques: Some(vec!["t1059.001".to_string()]),
            tags: None,
            requires_fields: None,
            requires_source_types: None,
            conversion_status: "pending".to_string(),
            converted_npl: None,
            conversion_confidence: None,
            conversion_warnings: None,
            conversion_field_mappings: None,
            coverage_status: None,
            coverage_missing_fields: None,
            created_at: now,
            updated_at: now,
        }
    }

    #[test]
    fn coverage_filter_normalizes_and_applies_every_dimension() {
        let repository_id = Uuid::now_v7();
        let rule = repository_rule(repository_id);
        let filter = CoverageFilter {
            repository_id: Some(repository_id),
            severity: Some(" high ".to_string()),
            mitre_tactic: Some("credential -  access".to_string()),
            mitre_technique: Some(" t1059.001 ".to_string()),
        }
        .normalized();

        assert_eq!(filter.severity.as_deref(), Some("high"));
        assert_eq!(filter.mitre_tactic.as_deref(), Some("TA0006"));
        assert_eq!(filter.mitre_technique.as_deref(), Some("T1059.001"));
        assert!(filter.matches_normalized(&rule));
        assert!(CoverageFilter {
            mitre_tactic: Some("ta0006".to_string()),
            ..Default::default()
        }
        .normalized()
        .matches_normalized(&rule));
    }

    #[test]
    fn coverage_filter_rejects_each_mismatch_and_combinations() {
        let repository_id = Uuid::now_v7();
        let rule = repository_rule(repository_id);

        for filter in [
            CoverageFilter {
                repository_id: Some(Uuid::now_v7()),
                ..Default::default()
            },
            CoverageFilter {
                severity: Some("critical".to_string()),
                ..Default::default()
            },
            CoverageFilter {
                mitre_tactic: Some("execution".to_string()),
                ..Default::default()
            },
            CoverageFilter {
                mitre_technique: Some("T1078".to_string()),
                ..Default::default()
            },
            CoverageFilter {
                repository_id: Some(repository_id),
                severity: Some("high".to_string()),
                mitre_tactic: Some("credential_access".to_string()),
                mitre_technique: Some("T1078".to_string()),
            },
        ] {
            assert!(!filter.normalized().matches_normalized(&rule));
        }
    }

    #[test]
    fn blank_coverage_filters_are_ignored() {
        let rule = repository_rule(Uuid::now_v7());
        let filter = CoverageFilter {
            repository_id: None,
            severity: Some("  ".to_string()),
            mitre_tactic: Some(String::new()),
            mitre_technique: Some("\t".to_string()),
        }
        .normalized();

        assert_eq!(filter.severity, None);
        assert_eq!(filter.mitre_tactic, None);
        assert_eq!(filter.mitre_technique, None);
        assert!(filter.matches_normalized(&rule));
    }
}
