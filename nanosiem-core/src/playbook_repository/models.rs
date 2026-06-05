// SPDX-License-Identifier: AGPL-3.0-or-later

//! Data models for external playbook repositories.

use chrono::{DateTime, NaiveDate, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::typeid;

/// External playbook repository row (mirrors `playbook_repositories` table).
#[derive(Debug, Clone, Serialize, Deserialize, FromRow, ToSchema)]
pub struct PlaybookRepository {
    #[serde(with = "typeid::playbook_repo")]
    #[schema(value_type = String)]
    pub id: Uuid,
    pub name: String,
    pub slug: String,
    pub description: Option<String>,
    pub url: String,
    pub branch: String,
    pub playbooks_path: Option<String>,
    pub auto_sync_enabled: Option<bool>,
    pub sync_interval_hours: Option<i32>,
    pub last_synced_at: Option<DateTime<Utc>>,
    pub last_sync_commit: Option<String>,
    pub last_sync_status: Option<String>,
    pub last_sync_error: Option<String>,
    pub playbook_count: Option<i32>,
    pub enabled: Option<bool>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    #[serde(default, with = "typeid::user::opt")]
    #[schema(value_type = Option<String>)]
    pub created_by: Option<Uuid>,
}

/// Request to create a new playbook repository.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct NewPlaybookRepository {
    pub name: String,
    pub url: String,
    #[serde(default)]
    pub slug: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub branch: Option<String>,
    #[serde(default)]
    pub playbooks_path: Option<String>,
    #[serde(default)]
    pub auto_sync_enabled: Option<bool>,
    #[serde(default)]
    pub sync_interval_hours: Option<i32>,
}

/// Request to update a playbook repository.
#[derive(Debug, Clone, Default, Serialize, Deserialize, ToSchema)]
pub struct UpdatePlaybookRepository {
    pub name: Option<String>,
    pub description: Option<String>,
    pub branch: Option<String>,
    pub playbooks_path: Option<String>,
    pub auto_sync_enabled: Option<bool>,
    pub sync_interval_hours: Option<i32>,
    pub enabled: Option<bool>,
}

/// A cached playbook from a repository.
#[derive(Debug, Clone, Serialize, Deserialize, FromRow, ToSchema)]
pub struct RepositoryPlaybook {
    #[serde(with = "typeid::repo_playbook")]
    #[schema(value_type = String)]
    pub id: Uuid,
    #[serde(with = "typeid::playbook_repo")]
    #[schema(value_type = String)]
    pub repository_id: Uuid,
    pub file_path: String,
    pub file_sha: Option<String>,
    pub raw_content: String,
    pub title: Option<String>,
    pub subtitle: Option<String>,
    pub category: Option<String>,
    pub match_signals: Option<Vec<String>>,
    pub tags: Option<Vec<String>>,
    pub owner_team: Option<String>,
    pub authored_date: Option<NaiveDate>,
    pub danger_policy: Option<serde_json::Value>,
    pub review_cadence: Option<String>,
    pub scope: Option<String>,
    pub parse_status: String,
    pub parse_error: Option<String>,
    pub step_count: Option<i32>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Filter for listing repository playbooks.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RepositoryPlaybookFilter {
    pub category: Option<String>,
    pub parse_status: Option<String>,
    pub search: Option<String>,
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

/// Import type.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum PlaybookImportType {
    Linked,
    Forked,
}

impl std::fmt::Display for PlaybookImportType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PlaybookImportType::Linked => write!(f, "linked"),
            PlaybookImportType::Forked => write!(f, "forked"),
        }
    }
}

/// A playbook import record linking a repository playbook to a local playbook.
#[derive(Debug, Clone, Serialize, Deserialize, FromRow, ToSchema)]
pub struct PlaybookImport {
    #[schema(value_type = String)]
    pub id: Uuid,
    #[serde(with = "typeid::repo_playbook")]
    #[schema(value_type = String)]
    pub repository_playbook_id: Uuid,
    #[serde(with = "typeid::playbook")]
    #[schema(value_type = String)]
    pub playbook_id: Uuid,
    pub import_type: String,
    pub imported_at: DateTime<Utc>,
    #[serde(default, with = "typeid::user::opt")]
    #[schema(value_type = Option<String>)]
    pub imported_by: Option<Uuid>,
    pub imported_commit: Option<String>,
    pub last_sync_commit: Option<String>,
    pub upstream_changed: Option<bool>,
    pub customizations: Option<serde_json::Value>,
}

/// Request body for importing a repository playbook.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct PlaybookImportRequest {
    #[serde(default = "default_import_type")]
    pub import_type: PlaybookImportType,
    #[serde(default)]
    pub owner_team: Option<String>,
}

fn default_import_type() -> PlaybookImportType {
    PlaybookImportType::Linked
}

/// Response for import operation.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct PlaybookImportResponse {
    #[serde(with = "typeid::playbook")]
    #[schema(value_type = String)]
    pub playbook_id: Uuid,
    pub import_type: String,
}

/// Status of a sync operation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum PlaybookSyncStatus {
    Success,
    Failed,
    Syncing,
}

impl std::fmt::Display for PlaybookSyncStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PlaybookSyncStatus::Success => write!(f, "success"),
            PlaybookSyncStatus::Failed => write!(f, "failed"),
            PlaybookSyncStatus::Syncing => write!(f, "syncing"),
        }
    }
}

/// Result of a sync operation.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct PlaybookSyncResult {
    #[serde(with = "typeid::playbook_repo")]
    #[schema(value_type = String)]
    pub repository_id: Uuid,
    pub status: PlaybookSyncStatus,
    pub commit: Option<String>,
    pub playbooks_added: i32,
    pub playbooks_updated: i32,
    pub playbooks_removed: i32,
    pub playbooks_total: i32,
    pub duration_ms: u64,
    pub error: Option<String>,
}

// =============================================================================
// Air-gapped Bundle Sync (NAN-1226)
// =============================================================================

/// Aggregate result of syncing an air-gapped playbook bundle into the synthetic
/// air-gap repository's catalog (NAN-1226). This is the offline equivalent of a
/// GitHub repo *sync* — the playbooks land as available-to-import; nothing is
/// imported or activated. The synthetic repository is returned so callers can
/// browse/import via the normal playbook-repository surface.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct PlaybookBundleImportResult {
    /// The synthetic air-gap repository the bundle playbooks landed in.
    #[serde(with = "typeid::playbook_repo")]
    #[schema(value_type = String)]
    pub repository_id: Uuid,
    /// Caller-defined content version from the bundle manifest.
    pub content_version: String,
    /// Number of playbooks synced (upserted) into the repository catalog.
    pub synced: usize,
}
