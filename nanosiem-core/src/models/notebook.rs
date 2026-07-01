// SPDX-License-Identifier: AGPL-3.0-or-later

//! Investigation Notebook models
//!
//! AI-powered shadow agent for tracking analyst investigations

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

use crate::typeid;

fn default_source() -> String {
    "analyst".to_string()
}

fn default_source_option() -> Option<String> {
    Some("analyst".to_string())
}

/// Notebook visibility options
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type, utoipa::ToSchema,
)]
#[sqlx(type_name = "text", rename_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum NotebookVisibility {
    Private,
    Shared,
    Public,
}

impl Default for NotebookVisibility {
    fn default() -> Self {
        Self::Private
    }
}

/// Notebook status
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type, utoipa::ToSchema,
)]
#[sqlx(type_name = "text", rename_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum NotebookStatus {
    Active,
    Paused,
    Closed,
    Merged,
}

impl Default for NotebookStatus {
    fn default() -> Self {
        Self::Active
    }
}

/// Entry types for notebook timeline
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type, utoipa::ToSchema,
)]
#[sqlx(type_name = "text", rename_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum NotebookEntryType {
    ManualNote,
    SearchExecuted,
    SearchRefined,
    AlertViewed,
    AlertActioned,
    DetectionViewed,
    DetectionModified,
    AiSuggestion,
    AiSummary,
    // @ command entry types
    EntityReference,
    IocMarker,
    TimelineMarker,
    LinkedAlert,
    LinkedDetection,
    AiQuery,
    PivotSuggestions,
    UserMention,
    CaseEvent,
    // AI chat types (NAN-48: conversational AI in notebooks)
    AiChatMessage,
    AiChatResponse,
    AiSearchResult,
}

/// Share permission levels
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type, utoipa::ToSchema,
)]
#[sqlx(type_name = "text", rename_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum SharePermission {
    View,
    Edit,
}

impl Default for SharePermission {
    fn default() -> Self {
        Self::View
    }
}

/// Reference types for linking notebooks to other entities
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type, utoipa::ToSchema,
)]
#[sqlx(type_name = "text", rename_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum ReferenceType {
    Alert,
    Detection,
    SavedSearch,
    Case,
}

/// An investigation notebook
#[derive(Debug, Clone, Serialize, Deserialize, FromRow, utoipa::ToSchema)]
pub struct Notebook {
    #[serde(with = "typeid::notebook")]
    #[schema(value_type = String)]
    pub id: Uuid,
    pub title: String,
    #[serde(with = "typeid::user")]
    #[schema(value_type = String)]
    pub owner_id: Uuid,
    #[serde(skip_serializing_if = "Option::is_none", with = "typeid::case::opt")]
    #[schema(value_type = Option<String>)]
    pub case_id: Option<Uuid>,
    #[serde(
        skip_serializing_if = "Option::is_none",
        with = "typeid::notebook::opt"
    )]
    #[schema(value_type = Option<String>)]
    pub merged_into_id: Option<Uuid>,
    pub visibility: String,
    pub status: String,
    pub summary: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub closed_at: Option<DateTime<Utc>>,
}

/// Notebook with owner name for display
#[derive(Debug, Clone, Serialize, Deserialize, FromRow, utoipa::ToSchema)]
pub struct NotebookWithOwner {
    #[serde(with = "typeid::notebook")]
    #[schema(value_type = String)]
    pub id: Uuid,
    pub title: String,
    #[serde(with = "typeid::user")]
    #[schema(value_type = String)]
    pub owner_id: Uuid,
    #[serde(skip_serializing_if = "Option::is_none", with = "typeid::case::opt")]
    #[schema(value_type = Option<String>)]
    pub case_id: Option<Uuid>,
    #[serde(
        skip_serializing_if = "Option::is_none",
        with = "typeid::notebook::opt"
    )]
    #[schema(value_type = Option<String>)]
    pub merged_into_id: Option<Uuid>,
    pub visibility: String,
    pub status: String,
    pub summary: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub closed_at: Option<DateTime<Utc>>,
    pub owner_name: Option<String>,
}

/// Notebook with entry count and owner for list view
#[derive(Debug, Clone, Serialize, Deserialize, FromRow, utoipa::ToSchema)]
pub struct NotebookSummary {
    #[serde(with = "typeid::notebook")]
    #[schema(value_type = String)]
    pub id: Uuid,
    pub title: String,
    #[serde(with = "typeid::user")]
    #[schema(value_type = String)]
    pub owner_id: Uuid,
    #[serde(skip_serializing_if = "Option::is_none", with = "typeid::case::opt")]
    #[schema(value_type = Option<String>)]
    pub case_id: Option<Uuid>,
    #[serde(
        skip_serializing_if = "Option::is_none",
        with = "typeid::notebook::opt"
    )]
    #[schema(value_type = Option<String>)]
    pub merged_into_id: Option<Uuid>,
    pub visibility: String,
    pub status: String,
    pub summary: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub closed_at: Option<DateTime<Utc>>,
    pub owner_name: Option<String>,
    pub entry_count: i64,
}

/// Input for creating a new notebook
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct NewNotebook {
    pub title: String,
    #[serde(with = "typeid::user")]
    #[schema(value_type = String)]
    pub owner_id: Uuid,
    #[serde(skip_serializing_if = "Option::is_none", with = "typeid::case::opt")]
    #[schema(value_type = Option<String>)]
    pub case_id: Option<Uuid>,
    #[serde(default)]
    pub visibility: NotebookVisibility,
}

/// Input for updating a notebook
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct UpdateNotebook {
    pub title: Option<String>,
    pub visibility: Option<NotebookVisibility>,
    pub status: Option<NotebookStatus>,
    pub summary: Option<String>,
}

/// A notebook entry (timeline item)
#[derive(Debug, Clone, Serialize, Deserialize, FromRow, utoipa::ToSchema)]
pub struct NotebookEntry {
    #[serde(with = "typeid::notebook_entry")]
    #[schema(value_type = String)]
    pub id: Uuid,
    #[serde(with = "typeid::notebook")]
    #[schema(value_type = String)]
    pub notebook_id: Uuid,
    pub entry_type: String,
    pub content: serde_json::Value,
    pub source_url: Option<String>,
    #[serde(with = "typeid::user")]
    #[schema(value_type = String)]
    pub created_by: Uuid,
    pub created_at: DateTime<Utc>,
    #[serde(
        skip_serializing_if = "Option::is_none",
        with = "typeid::notebook::opt"
    )]
    #[schema(value_type = Option<String>)]
    pub merged_from_notebook_id: Option<Uuid>,
    pub merged_from_notebook_title: Option<String>,
    pub original_created_at: Option<DateTime<Utc>>,
    /// Source of the entry: 'analyst' (default) or 'shadow_investigation'
    #[serde(default = "default_source")]
    pub source: String,
}

/// Notebook entry with creator name
#[derive(Debug, Clone, Serialize, Deserialize, FromRow, utoipa::ToSchema)]
pub struct NotebookEntryWithCreator {
    #[serde(with = "typeid::notebook_entry")]
    #[schema(value_type = String)]
    pub id: Uuid,
    #[serde(with = "typeid::notebook")]
    #[schema(value_type = String)]
    pub notebook_id: Uuid,
    pub entry_type: String,
    pub content: serde_json::Value,
    pub source_url: Option<String>,
    #[serde(with = "typeid::user")]
    #[schema(value_type = String)]
    pub created_by: Uuid,
    pub created_at: DateTime<Utc>,
    pub creator_name: Option<String>,
    #[serde(
        skip_serializing_if = "Option::is_none",
        with = "typeid::notebook::opt"
    )]
    #[schema(value_type = Option<String>)]
    pub merged_from_notebook_id: Option<Uuid>,
    pub merged_from_notebook_title: Option<String>,
    pub original_created_at: Option<DateTime<Utc>>,
    /// Source of the entry: 'analyst' (default) or 'shadow_investigation'
    #[serde(default = "default_source_option")]
    pub source: Option<String>,
}

/// Input for creating a new notebook entry
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct NewNotebookEntry {
    #[serde(with = "typeid::notebook")]
    #[schema(value_type = String)]
    pub notebook_id: Uuid,
    pub entry_type: NotebookEntryType,
    pub content: serde_json::Value,
    pub source_url: Option<String>,
    #[serde(with = "typeid::user")]
    #[schema(value_type = String)]
    pub created_by: Uuid,
    /// Optional custom timestamp for the entry (e.g., timeline markers)
    pub original_created_at: Option<chrono::DateTime<chrono::Utc>>,
}

/// A notebook share record
#[derive(Debug, Clone, Serialize, Deserialize, FromRow, utoipa::ToSchema)]
pub struct NotebookShare {
    #[serde(with = "typeid::notebook_share")]
    #[schema(value_type = String)]
    pub id: Uuid,
    #[serde(with = "typeid::notebook")]
    #[schema(value_type = String)]
    pub notebook_id: Uuid,
    #[serde(skip_serializing_if = "Option::is_none", with = "typeid::user::opt")]
    #[schema(value_type = Option<String>)]
    pub shared_with_user_id: Option<Uuid>,
    #[serde(skip_serializing_if = "Option::is_none", with = "typeid::group::opt")]
    #[schema(value_type = Option<String>)]
    pub shared_with_group_id: Option<Uuid>,
    pub permission: String,
    pub created_at: DateTime<Utc>,
}

/// Notebook share with names for display
#[derive(Debug, Clone, Serialize, Deserialize, FromRow, utoipa::ToSchema)]
pub struct NotebookShareWithNames {
    #[serde(with = "typeid::notebook_share")]
    #[schema(value_type = String)]
    pub id: Uuid,
    #[serde(with = "typeid::notebook")]
    #[schema(value_type = String)]
    pub notebook_id: Uuid,
    #[serde(skip_serializing_if = "Option::is_none", with = "typeid::user::opt")]
    #[schema(value_type = Option<String>)]
    pub shared_with_user_id: Option<Uuid>,
    #[serde(skip_serializing_if = "Option::is_none", with = "typeid::group::opt")]
    #[schema(value_type = Option<String>)]
    pub shared_with_group_id: Option<Uuid>,
    pub permission: String,
    pub created_at: DateTime<Utc>,
    pub user_name: Option<String>,
    pub group_name: Option<String>,
}

/// Input for creating a notebook share
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct NewNotebookShare {
    #[serde(with = "typeid::notebook")]
    #[schema(value_type = String)]
    pub notebook_id: Uuid,
    #[serde(skip_serializing_if = "Option::is_none", with = "typeid::user::opt")]
    #[schema(value_type = Option<String>)]
    pub shared_with_user_id: Option<Uuid>,
    #[serde(skip_serializing_if = "Option::is_none", with = "typeid::group::opt")]
    #[schema(value_type = Option<String>)]
    pub shared_with_group_id: Option<Uuid>,
    #[serde(default)]
    pub permission: SharePermission,
}

/// A reference linking notebook to another entity
#[derive(Debug, Clone, Serialize, Deserialize, FromRow, utoipa::ToSchema)]
pub struct NotebookReference {
    #[serde(with = "typeid::notebook_ref")]
    #[schema(value_type = String)]
    pub id: Uuid,
    #[serde(with = "typeid::notebook")]
    #[schema(value_type = String)]
    pub notebook_id: Uuid,
    pub reference_type: String,
    pub reference_id: Uuid,
    pub reference_name: Option<String>,
    pub created_at: DateTime<Utc>,
}

/// Input for creating a notebook reference
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct NewNotebookReference {
    #[serde(with = "typeid::notebook")]
    #[schema(value_type = String)]
    pub notebook_id: Uuid,
    pub reference_type: ReferenceType,
    pub reference_id: Uuid,
    pub reference_name: Option<String>,
}

/// One event the shadow agent pins as evidence backing a finding/hypothesis.
/// Rendered as a row in the Evidence drawer, tied back to the notebook entry
/// whose content carried it.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct EvidenceEvent {
    pub timestamp: DateTime<Utc>,
    /// One of: critical, high, medium, low, informational, or a free-form level
    /// like error/warn/info that the UI maps to a visual severity.
    pub severity: String,
    /// Service or source name (e.g. "auth-api", "waf"). Shown inline.
    pub service: String,
    /// One-line event description / summary.
    pub message: String,
    /// Optional host / source IP, displayed adjacent to the service.
    pub host: Option<String>,
}

// ============================================================================
// Notebook Tabs
// ============================================================================

/// A notebook tab (user's open notebook)
#[derive(Debug, Clone, Serialize, Deserialize, FromRow, utoipa::ToSchema)]
pub struct NotebookTab {
    #[serde(with = "typeid::notebook_tab")]
    #[schema(value_type = String)]
    pub id: Uuid,
    #[serde(with = "typeid::user")]
    #[schema(value_type = String)]
    pub user_id: Uuid,
    #[serde(with = "typeid::notebook")]
    #[schema(value_type = String)]
    pub notebook_id: Uuid,
    pub is_pinned: bool,
    pub is_active: bool,
    pub tab_order: i32,
    pub last_accessed_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
}

/// Notebook tab with notebook details for display
#[derive(Debug, Clone, Serialize, Deserialize, FromRow, utoipa::ToSchema)]
pub struct NotebookTabWithDetails {
    #[serde(with = "typeid::notebook_tab")]
    #[schema(value_type = String)]
    pub id: Uuid,
    #[serde(with = "typeid::user")]
    #[schema(value_type = String)]
    pub user_id: Uuid,
    #[serde(with = "typeid::notebook")]
    #[schema(value_type = String)]
    pub notebook_id: Uuid,
    pub is_pinned: bool,
    pub is_active: bool,
    pub tab_order: i32,
    pub last_accessed_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    // Notebook details
    pub notebook_title: String,
    pub notebook_status: String,
    pub entry_count: i64,
    #[serde(skip_serializing_if = "Option::is_none", with = "typeid::case::opt")]
    #[schema(value_type = Option<String>)]
    pub case_id: Option<Uuid>,
}

/// Input for opening a notebook as a tab
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct OpenTabRequest {
    #[serde(with = "typeid::notebook")]
    #[schema(value_type = String)]
    pub notebook_id: Uuid,
}

/// Input for updating a notebook tab
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct UpdateTabRequest {
    pub is_pinned: Option<bool>,
}

/// Input for reordering tabs
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct ReorderTabsRequest {
    #[serde(default, with = "typeid::notebook::vec")]
    #[schema(value_type = Vec<String>)]
    pub tab_ids: Vec<Uuid>,
}

// ============================================================================
// Notebook Merge & Link Types
// ============================================================================

/// Request to merge multiple notebooks into a target notebook
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct MergeNotebooksRequest {
    /// IDs of notebooks to merge into the target
    #[serde(default, with = "typeid::notebook::vec")]
    #[schema(value_type = Vec<String>)]
    pub source_notebook_ids: Vec<Uuid>,
}

/// Response from merge operation
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct MergeNotebooksResponse {
    /// Number of entries merged
    pub entries_merged: i64,
    /// IDs of source notebooks that were merged and archived
    #[serde(default, with = "typeid::notebook::vec")]
    #[schema(value_type = Vec<String>)]
    pub merged_notebook_ids: Vec<Uuid>,
}

/// Request to link a notebook to a case
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct LinkNotebookRequest {
    /// ID of the notebook to link
    #[serde(with = "typeid::notebook")]
    #[schema(value_type = String)]
    pub notebook_id: Uuid,
}

// ============================================================================
// Notebook Sharing
// ============================================================================

/// Request to share a notebook (bulk visibility + group update)
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct ShareNotebookRequest {
    /// Visibility: 'public', 'shared', or 'private'
    pub visibility: String,
    /// Group IDs to share with (required when visibility = 'shared')
    pub group_ids: Option<Vec<Uuid>>,
}

/// A group that a notebook is shared with
#[derive(Debug, Clone, Serialize, Deserialize, FromRow, utoipa::ToSchema)]
pub struct NotebookSharedGroup {
    #[serde(with = "typeid::group")]
    #[schema(value_type = String)]
    pub id: Uuid,
    pub name: String,
}

/// A user affected by a notebook sharing change
#[derive(Debug, Clone, Serialize, Deserialize, FromRow, utoipa::ToSchema)]
pub struct NotebookAffectedUser {
    #[serde(with = "typeid::user")]
    #[schema(value_type = String)]
    pub user_id: Uuid,
    pub user_name: String,
    pub user_email: String,
}

/// Result of sharing a notebook
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct NotebookShareResult {
    pub notebook: NotebookSummary,
    /// Groups the notebook is shared with
    pub shared_groups: Vec<NotebookSharedGroup>,
    /// Users who lost access due to this change
    pub users_who_lost_access: Vec<NotebookAffectedUser>,
}
