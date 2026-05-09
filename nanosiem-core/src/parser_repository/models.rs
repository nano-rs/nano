// SPDX-License-Identifier: AGPL-3.0-or-later

//! Data models for parser repository operations

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::typeid;

// =============================================================================
// Parser Repository
// =============================================================================

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow, utoipa::ToSchema)]
pub struct ParserRepository {
    #[serde(with = "typeid::parser_repo")]
    #[schema(value_type = String)]
    pub id: Uuid,
    pub name: String,
    pub slug: String,
    pub description: Option<String>,
    pub url: String,
    pub branch: String,
    pub parsers_path: Option<String>,
    pub auto_sync_enabled: bool,
    pub sync_interval_hours: i32,
    pub last_synced_at: Option<DateTime<Utc>>,
    pub last_sync_commit: Option<String>,
    pub last_sync_status: Option<String>,
    pub last_sync_error: Option<String>,
    pub parser_count: i32,
    pub enabled: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    #[serde(default, with = "typeid::user::opt")]
    #[schema(value_type = Option<String>)]
    pub created_by: Option<Uuid>,
}

#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct NewParserRepository {
    pub name: String,
    pub slug: Option<String>,
    pub description: Option<String>,
    pub url: String,
    pub branch: Option<String>,
    pub parsers_path: Option<String>,
    pub auto_sync_enabled: Option<bool>,
    pub sync_interval_hours: Option<i32>,
}

#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct UpdateParserRepository {
    pub name: Option<String>,
    pub description: Option<String>,
    pub branch: Option<String>,
    pub parsers_path: Option<String>,
    pub auto_sync_enabled: Option<bool>,
    pub sync_interval_hours: Option<i32>,
    pub enabled: Option<bool>,
}

// =============================================================================
// Repository Parser (cached from GitHub)
// =============================================================================

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow, utoipa::ToSchema)]
pub struct RepositoryParser {
    #[serde(with = "typeid::repo_parser")]
    #[schema(value_type = String)]
    pub id: Uuid,
    #[serde(with = "typeid::parser_repo")]
    #[schema(value_type = String)]
    pub repository_id: Uuid,
    pub file_path: String,
    pub file_sha: Option<String>,
    pub raw_content: String,
    pub name: Option<String>,
    pub display_name: Option<String>,
    pub description: Option<String>,
    pub version: Option<String>,
    pub category: Option<String>,
    pub vendor: Option<String>,
    pub product: Option<String>,
    pub parser_vrl: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, utoipa::IntoParams)]
pub struct RepositoryParserFilter {
    pub category: Option<String>,
    pub search: Option<String>,
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

// =============================================================================
// Parser Import
// =============================================================================

#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub enum ParserImportType {
    #[serde(rename = "linked")]
    Linked,
    #[serde(rename = "forked")]
    Forked,
}

impl std::fmt::Display for ParserImportType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ParserImportType::Linked => write!(f, "linked"),
            ParserImportType::Forked => write!(f, "forked"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow, utoipa::ToSchema)]
pub struct ParserImport {
    #[serde(with = "typeid::parser_repo")]
    #[schema(value_type = String)]
    pub id: Uuid,
    #[serde(with = "typeid::repo_parser")]
    #[schema(value_type = String)]
    pub repository_parser_id: Uuid,
    #[serde(with = "typeid::log_source")]
    #[schema(value_type = String)]
    pub log_source_id: Uuid,
    pub import_type: String,
    pub imported_at: DateTime<Utc>,
    #[serde(default, with = "typeid::user::opt")]
    #[schema(value_type = Option<String>)]
    pub imported_by: Option<Uuid>,
    pub imported_commit: Option<String>,
    pub last_sync_commit: Option<String>,
    pub upstream_changed: bool,
}

/// Enriched upstream update entry with display info from the repository parser
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct ParserUpstreamUpdate {
    #[serde(with = "typeid::log_source")]
    #[schema(value_type = String)]
    pub log_source_id: Uuid,
    #[serde(with = "typeid::repo_parser")]
    #[schema(value_type = String)]
    pub repository_parser_id: Uuid,
    pub file_path: String,
    pub display_name: Option<String>,
    pub version: Option<String>,
    pub import_type: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct ParserImportRequest {
    pub import_type: ParserImportType,
    /// The match value that activates this parser via routing rules (e.g., "apache")
    pub source_type: Option<String>,
    /// Ingestion method: routed, kafka, aws_s3, gcp_pubsub, splunk_hec, vector
    pub ingestion_method: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct ParserImportPreview {
    pub repository_parser: RepositoryParser,
    pub proposed_name: String,
    pub proposed_description: Option<String>,
    pub proposed_category: Option<String>,
    pub proposed_vendor: Option<String>,
    pub proposed_product: Option<String>,
    pub already_imported: bool,
    pub existing_import_type: Option<String>,
    #[serde(default, with = "typeid::log_source::opt")]
    #[schema(value_type = Option<String>)]
    pub existing_log_source_id: Option<Uuid>,
}

// =============================================================================
// Sync Types
// =============================================================================

#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub enum SyncStatus {
    #[serde(rename = "success")]
    Success,
    #[serde(rename = "failed")]
    Failed,
    #[serde(rename = "syncing")]
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

#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct SyncResult {
    #[serde(with = "typeid::parser_repo")]
    #[schema(value_type = String)]
    pub repository_id: Uuid,
    pub status: SyncStatus,
    pub commit: Option<String>,
    pub parsers_added: i32,
    pub parsers_updated: i32,
    pub parsers_removed: i32,
    pub parsers_total: i32,
    pub duration_ms: u64,
    pub error: Option<String>,
}

// =============================================================================
// Upstream Update Result
// =============================================================================

#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct ApplyUpstreamUpdateResult {
    #[serde(with = "typeid::log_source")]
    #[schema(value_type = String)]
    pub log_source_id: Uuid,
    pub updated: bool,
    /// Whether the log source is deployed and needs re-deploy
    pub needs_deploy: bool,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct BulkApplyUpstreamResult {
    pub updated: u32,
    pub failed: u32,
    pub results: Vec<ApplyUpstreamUpdateResult>,
}

// =============================================================================
// Upstream Diff
// =============================================================================

#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct UpstreamParserDiff {
    #[serde(with = "typeid::log_source")]
    #[schema(value_type = String)]
    pub log_source_id: Uuid,
    #[serde(with = "typeid::repo_parser")]
    #[schema(value_type = String)]
    pub repository_parser_id: Uuid,
    pub file_path: String,
    pub upstream_display_name: Option<String>,
    pub upstream_description: Option<String>,
    pub upstream_version: Option<String>,
    pub upstream_vrl: String,
    pub current_vrl: String,
    pub has_changes: bool,
}
