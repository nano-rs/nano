// SPDX-License-Identifier: AGPL-3.0-or-later

//! Dashboard model

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

use crate::typeid;

/// A dashboard with visualization panels
#[derive(Debug, Clone, Serialize, Deserialize, FromRow, utoipa::ToSchema)]
pub struct Dashboard {
    #[serde(with = "typeid::dashboard")]
    #[schema(value_type = String)]
    pub id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub layout: serde_json::Value,
    pub panels: serde_json::Value,
    pub refresh_interval: Option<i32>,
    /// User who owns this dashboard (NULL for legacy/system dashboards)
    #[serde(default, with = "typeid::user::opt")]
    #[schema(value_type = Option<String>)]
    pub owner_id: Option<Uuid>,
    /// Visibility: 'public', 'group', or 'private'
    pub visibility: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Dashboard with owner name for display purposes
#[derive(Debug, Clone, Serialize, Deserialize, FromRow, utoipa::ToSchema)]
pub struct DashboardWithOwner {
    #[serde(with = "typeid::dashboard")]
    #[schema(value_type = String)]
    pub id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub layout: serde_json::Value,
    pub panels: serde_json::Value,
    pub refresh_interval: Option<i32>,
    #[serde(default, with = "typeid::user::opt")]
    #[schema(value_type = Option<String>)]
    pub owner_id: Option<Uuid>,
    /// Visibility: 'public', 'group', or 'private'
    pub visibility: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    /// Owner's display name (joined from users table)
    pub owner_name: Option<String>,
}

/// Dashboard with full sharing context for API responses
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct DashboardWithContext {
    #[serde(with = "typeid::dashboard")]
    #[schema(value_type = String)]
    pub id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub layout: serde_json::Value,
    pub panels: serde_json::Value,
    pub refresh_interval: Option<i32>,
    #[serde(default, with = "typeid::user::opt")]
    #[schema(value_type = Option<String>)]
    pub owner_id: Option<Uuid>,
    pub visibility: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub owner_name: Option<String>,
    /// Groups this dashboard is shared with (when visibility = 'group')
    pub shared_groups: Vec<DashboardSharedGroup>,
    /// Whether the requesting user is the owner
    pub is_owner: bool,
}

/// A group that a dashboard is shared with
#[derive(Debug, Clone, Serialize, Deserialize, FromRow, utoipa::ToSchema)]
pub struct DashboardSharedGroup {
    #[serde(with = "typeid::group")]
    #[schema(value_type = String)]
    pub id: Uuid,
    pub name: String,
}

/// Request to share a dashboard
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct ShareDashboardRequest {
    /// Visibility: 'public', 'group', or 'private'
    pub visibility: String,
    /// Group IDs to share with (required when visibility = 'group')
    pub group_ids: Option<Vec<Uuid>>,
}

/// Result of sharing a dashboard
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct DashboardShareResult {
    pub dashboard: DashboardWithContext,
    /// Users who lost access due to this change
    pub users_who_lost_access: Vec<DashboardAffectedUser>,
}

/// A user affected by a dashboard sharing change
#[derive(Debug, Clone, Serialize, Deserialize, FromRow, utoipa::ToSchema)]
pub struct DashboardAffectedUser {
    #[serde(with = "typeid::user")]
    #[schema(value_type = String)]
    pub user_id: Uuid,
    pub user_name: String,
    pub user_email: String,
}

/// Input for creating a new dashboard
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct NewDashboard {
    pub name: String,
    pub description: Option<String>,
    pub layout: serde_json::Value,
    pub panels: serde_json::Value,
    pub refresh_interval: Option<i32>,
    /// Owner of the dashboard (set from authenticated user)
    #[serde(default, with = "typeid::user::opt")]
    #[schema(value_type = Option<String>)]
    pub owner_id: Option<Uuid>,
    /// Visibility: 'public', 'group', or 'private' (defaults to 'public')
    #[serde(default = "default_visibility")]
    pub visibility: String,
}

fn default_visibility() -> String {
    "public".to_string()
}

/// Input for updating a dashboard.
///
/// `description` and `refresh_interval` use tri-state semantics so they can be
/// explicitly cleared (DSH13): `None` = leave unchanged, `Some(None)` = set to
/// NULL, `Some(Some(v))` = set to `v`. The API request type maps its
/// double-`Option` wire fields onto these.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct UpdateDashboard {
    pub name: Option<String>,
    #[schema(value_type = Option<String>)]
    pub description: Option<Option<String>>,
    pub layout: Option<serde_json::Value>,
    pub panels: Option<serde_json::Value>,
    #[schema(value_type = Option<i32>)]
    pub refresh_interval: Option<Option<i32>>,
}
