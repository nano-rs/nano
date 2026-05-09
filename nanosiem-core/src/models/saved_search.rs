// SPDX-License-Identifier: AGPL-3.0-or-later

//! Saved search model

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

use crate::typeid;

/// A saved search query
#[derive(Debug, Clone, Serialize, Deserialize, FromRow, utoipa::ToSchema)]
pub struct SavedSearch {
    #[serde(with = "typeid::saved_search")]
    #[schema(value_type = String)]
    pub id: Uuid,
    pub name: String,
    pub query: String,
    pub time_range: Option<serde_json::Value>,
    pub created_at: DateTime<Utc>,
    #[serde(default, with = "typeid::user::opt")]
    #[schema(value_type = Option<String>)]
    pub user_id: Option<Uuid>,
    pub visibility: Option<String>,
    pub updated_at: Option<DateTime<Utc>>,
}

/// Saved search with additional context for the frontend
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct SavedSearchWithContext {
    #[serde(with = "typeid::saved_search")]
    #[schema(value_type = String)]
    pub id: Uuid,
    pub name: String,
    pub query: String,
    pub time_range: Option<serde_json::Value>,
    pub created_at: DateTime<Utc>,
    #[serde(default, with = "typeid::user::opt")]
    #[schema(value_type = Option<String>)]
    pub user_id: Option<Uuid>,
    pub visibility: String,
    pub updated_at: Option<DateTime<Utc>>,
    pub is_owner: bool,
    pub owner_name: Option<String>,
    pub shared_groups: Vec<SharedGroup>,
}

/// A group that a saved search is shared with
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow, utoipa::ToSchema)]
pub struct SharedGroup {
    #[serde(with = "typeid::group")]
    #[schema(value_type = String)]
    pub id: Uuid,
    pub name: String,
}

/// Input for creating a new saved search
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct NewSavedSearch {
    pub name: String,
    pub query: String,
    pub time_range: Option<serde_json::Value>,
    pub visibility: Option<String>,
    pub group_ids: Option<Vec<Uuid>>,
}

/// Input for updating a saved search
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct UpdateSavedSearch {
    pub name: Option<String>,
    pub query: Option<String>,
    pub time_range: Option<serde_json::Value>,
}

/// Input for sharing a saved search
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct ShareSavedSearchRequest {
    pub visibility: String,
    pub group_ids: Option<Vec<Uuid>>,
}

/// Result of a share operation, including users who lost access
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct ShareResult {
    /// The updated saved search
    pub search: SavedSearchWithContext,
    /// Users who lost access due to group removal (user_id, user_name, search_name)
    pub users_who_lost_access: Vec<AffectedUser>,
}

/// A user affected by a share change
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct AffectedUser {
    #[serde(with = "typeid::user")]
    #[schema(value_type = String)]
    pub user_id: Uuid,
    pub user_name: String,
    pub user_email: String,
}
