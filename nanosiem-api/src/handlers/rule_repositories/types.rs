// SPDX-License-Identifier: AGPL-3.0-or-later

use nanosiem_core::{FolderInfo, RepositoryRule, RuleRepository};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

// =============================================================================
// Repository CRUD Types
// =============================================================================

/// Response for listing repositories
#[derive(Debug, Serialize, ToSchema)]
pub struct ListRepositoriesResponse {
    pub repositories: Vec<RuleRepository>,
}

/// Request to create a repository
#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateRepositoryRequest {
    pub name: String,
    pub url: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub branch: Option<String>,
    #[serde(default)]
    pub rules_path: Option<String>,
    #[serde(default)]
    pub rule_format: Option<String>,
    #[serde(default)]
    pub auto_sync_enabled: Option<bool>,
    #[serde(default)]
    pub sync_interval_hours: Option<i32>,
}

/// Request to update a repository
#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateRepositoryRequest {
    pub name: Option<String>,
    pub description: Option<String>,
    pub branch: Option<String>,
    pub rules_path: Option<String>,
    pub auto_sync_enabled: Option<bool>,
    pub sync_interval_hours: Option<i32>,
    pub enabled: Option<bool>,
    /// Selected paths to sync. Send empty array to clear, omit to leave unchanged.
    pub selected_paths: Option<Vec<String>>,
}

// =============================================================================
// Folder/Rule Browsing Types
// =============================================================================

/// Response for listing folders
#[derive(Debug, Serialize, ToSchema)]
pub struct ListFoldersResponse {
    pub folders: Vec<FolderInfo>,
}

/// Query parameters for listing rules
#[derive(Debug, Deserialize, Default, IntoParams)]
pub struct ListRulesQuery {
    pub path_prefix: Option<String>,
    pub severity: Option<String>,
    pub conversion_status: Option<String>,
    pub coverage_status: Option<String>,
    pub search: Option<String>,
    pub has_npl: Option<bool>,
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

/// Repository rule with import status for API response
#[derive(Debug, Serialize, ToSchema)]
pub struct RepositoryRuleResponse {
    #[serde(flatten)]
    pub rule: RepositoryRule,
    pub is_imported: bool,
    #[serde(with = "nanosiem_core::typeid::rule::opt")]
    #[schema(value_type = Option<String>)]
    pub linked_detection_rule_id: Option<Uuid>,
}

// =============================================================================
// Import Types
// =============================================================================

/// Request to import a rule
#[derive(Debug, Deserialize, ToSchema)]
pub struct ImportRuleRequest {
    #[serde(default = "default_import_type")]
    pub import_type: String,
    pub folder: Option<String>,
    pub name: Option<String>,
    pub severity: Option<String>,
    pub mode: Option<String>,
    pub custom_npl: Option<String>,
    /// Source type mappings: { original_type: replacement_type }
    pub source_type_mappings: Option<std::collections::HashMap<String, String>>,
    /// Merge all source types to a single type
    pub merge_to_single_source_type: Option<String>,
}

pub(crate) fn default_import_type() -> String {
    "linked".to_string()
}

/// Response for import operation
#[derive(Debug, Serialize, ToSchema)]
pub struct ImportRuleResponse {
    #[serde(with = "nanosiem_core::typeid::rule")]
    #[schema(value_type = String)]
    pub detection_rule_id: Uuid,
    pub import_type: String,
}

// =============================================================================
// Coverage/Sigma Types
// =============================================================================

/// Query parameters for coverage analysis
#[derive(Debug, Deserialize, Default, IntoParams)]
pub struct CoverageQuery {
    #[serde(default, with = "nanosiem_core::typeid::rule_repo::opt")]
    #[param(value_type = Option<String>)]
    pub repository_id: Option<Uuid>,
    pub severity: Option<String>,
    pub mitre_tactic: Option<String>,
    pub mitre_technique: Option<String>,
}

/// Request for standalone Sigma conversion
#[derive(Debug, Deserialize, ToSchema)]
pub struct ConvertSigmaRequest {
    pub sigma_yaml: String,
}

/// Response for Sigma conversion
#[derive(Debug, Serialize, ToSchema)]
pub struct ConvertSigmaResponse {
    pub npl_query: String,
    pub confidence: f64,
    pub field_mappings: Vec<FieldMappingResponse>,
    pub unmapped_fields: Vec<String>,
    pub requires_fields: Vec<String>,
    pub warnings: Vec<String>,
    pub needs_review: bool,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct FieldMappingResponse {
    pub sigma_field: String,
    pub udm_field: String,
    pub confidence: f64,
    pub notes: Option<String>,
}

// =============================================================================
// Sync Types
// =============================================================================

#[derive(Debug, Serialize, ToSchema)]
pub struct SyncStartResponse {
    #[serde(with = "nanosiem_core::typeid::rule_repo")]
    #[schema(value_type = String)]
    pub repository_id: Uuid,
    pub status: String,
    pub message: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct SyncStatusResponse {
    pub status: Option<String>,
    pub last_synced_at: Option<chrono::DateTime<chrono::Utc>>,
    pub last_sync_commit: Option<String>,
    pub last_sync_error: Option<String>,
    pub rule_count: i32,
}

// =============================================================================
// Upstream Types
// =============================================================================

/// Response for upstream updates
#[derive(Debug, Serialize, ToSchema)]
pub struct UpstreamUpdatesResponse {
    pub updates: Vec<nanosiem_core::rule_repository::UpdatedRule>,
    pub total_count: i64,
}

// =============================================================================
// Batch Types
// =============================================================================

/// A single rule to import in a batch operation
#[derive(Debug, Deserialize, ToSchema)]
pub struct BatchImportItem {
    /// File path of the rule in the repository
    pub path: String,
    /// Override severity (uses rule's own severity if omitted)
    pub severity: Option<String>,
    /// Initial mode: staging, live, or alerting (default: staging)
    pub mode: Option<String>,
    /// Source type mappings: { original_type: replacement_type }
    pub source_type_mappings: Option<std::collections::HashMap<String, String>>,
    /// Merge all source types to a single type
    pub merge_to_single_source_type: Option<String>,
}

/// Request body for batch import
#[derive(Debug, Deserialize, ToSchema)]
pub struct BatchImportRequest {
    pub items: Vec<BatchImportItem>,
}

/// Response for batch import operation. NAN-673 added `updated` so the
/// caller can distinguish freshly-imported rules from existing ones that
/// were re-imported against newer upstream content.
#[derive(Debug, Serialize, ToSchema)]
pub struct BatchImportResponse {
    pub imported: usize,
    pub updated: usize,
    pub skipped: usize,
    pub failed: Vec<BatchFailure>,
}

/// Response for batch remove operation
#[derive(Debug, Serialize, ToSchema)]
pub struct BatchRemoveResponse {
    pub removed: usize,
    pub failed: Vec<BatchRemoveFailure>,
}

/// A failed import in a batch operation
#[derive(Debug, Serialize, ToSchema)]
pub struct BatchFailure {
    pub path: String,
    pub error: String,
}

/// A failed removal in a batch operation
#[derive(Debug, Serialize, ToSchema)]
pub struct BatchRemoveFailure {
    #[serde(with = "nanosiem_core::typeid::rule")]
    #[schema(value_type = String)]
    pub detection_rule_id: Uuid,
    pub error: String,
}
