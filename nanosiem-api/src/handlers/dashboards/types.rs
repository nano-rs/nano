// SPDX-License-Identifier: AGPL-3.0-or-later

//! Dashboard request/response types, validation constants, and query parameters

use chrono::{DateTime, Utc};
use nanosiem_core::{Dashboard, DashboardSharedGroup, DashboardWithOwner, TimeRangeInput};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

// ============================================================================
// Validation Constants
// ============================================================================

/// Maximum size of import JSON payload in bytes (1MB)
pub(super) const MAX_IMPORT_PAYLOAD_SIZE: usize = 1_048_576;
/// Maximum length for dashboard name
pub(super) const MAX_NAME_LENGTH: usize = 200;
/// Maximum length for dashboard description
pub(super) const MAX_DESCRIPTION_LENGTH: usize = 2000;
/// Maximum number of panels per dashboard
pub(super) const MAX_PANELS: usize = 50;
/// Maximum length for individual panel query
pub(super) const MAX_QUERY_LENGTH: usize = 10_000;
/// Maximum length for panel title
pub(super) const MAX_PANEL_TITLE_LENGTH: usize = 200;
/// Valid visualization types
pub(super) const VALID_VIZ_TYPES: &[&str] = &[
    "bar",
    "line",
    "area",
    "pie",
    "table",
    "single_value",
    "timeline",
];
/// Valid query modes
pub(super) const VALID_QUERY_MODES: &[&str] = &["piped", "sql"];

// ============================================================================
// Request/Response Types
// ============================================================================

/// Request for creating a dashboard
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct CreateDashboardRequest {
    pub name: String,
    pub description: Option<String>,
    pub layout: serde_json::Value,
    pub panels: serde_json::Value,
    pub refresh_interval: Option<i32>,
    /// Visibility: 'public', 'group', or 'private' (defaults to 'public')
    #[serde(default = "default_visibility")]
    pub visibility: String,
}

fn default_visibility() -> String {
    "public".to_string()
}

/// Request for updating a dashboard
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct UpdateDashboardRequest {
    pub name: Option<String>,
    pub description: Option<String>,
    pub layout: Option<serde_json::Value>,
    pub panels: Option<serde_json::Value>,
    pub refresh_interval: Option<i32>,
}

/// Query parameters for listing dashboards
#[derive(Debug, Clone, Deserialize, IntoParams)]
pub struct ListDashboardsQuery {
    /// Filter: "my" for user's own dashboards, "all" for all accessible
    #[serde(default = "default_filter")]
    pub filter: String,
}

fn default_filter() -> String {
    "my".to_string()
}

/// Summary of a dashboard for list view
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct DashboardSummary {
    #[serde(with = "nanosiem_core::typeid::dashboard")]
    #[schema(value_type = String)]
    pub id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub panel_count: usize,
    #[serde(with = "nanosiem_core::typeid::user::opt")]
    #[schema(value_type = Option<String>)]
    pub owner_id: Option<Uuid>,
    pub owner_name: Option<String>,
    /// Visibility: 'public', 'group', or 'private'
    pub visibility: String,
    /// Groups this dashboard is shared with (when visibility = 'group')
    #[serde(default)]
    pub shared_groups: Vec<DashboardSharedGroup>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl From<Dashboard> for DashboardSummary {
    fn from(d: Dashboard) -> Self {
        let panel_count = d.panels.as_array().map(|arr| arr.len()).unwrap_or(0);

        Self {
            id: d.id,
            name: d.name,
            description: d.description,
            panel_count,
            owner_id: d.owner_id,
            owner_name: None,
            visibility: d.visibility,
            shared_groups: vec![],
            created_at: d.created_at,
            updated_at: d.updated_at,
        }
    }
}

impl From<DashboardWithOwner> for DashboardSummary {
    fn from(d: DashboardWithOwner) -> Self {
        let panel_count = d.panels.as_array().map(|arr| arr.len()).unwrap_or(0);

        Self {
            id: d.id,
            name: d.name,
            description: d.description,
            panel_count,
            owner_id: d.owner_id,
            owner_name: d.owner_name,
            visibility: d.visibility,
            shared_groups: vec![],
            created_at: d.created_at,
            updated_at: d.updated_at,
        }
    }
}

/// Request for executing a panel query
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct PanelQueryRequest {
    /// The query string
    pub query: String,
    /// Query mode: "piped" or "sql"
    pub query_mode: String,
    /// Time range for the query
    pub time_range: TimeRangeInput,
    /// Optional variables for substitution
    pub variables: Option<HashMap<String, String>>,
}

/// Response from a panel query
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct PanelQueryResponse {
    pub results: Vec<serde_json::Value>,
    pub total_count: u64,
    pub execution_time_ms: u64,
}

/// Dashboard export format
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct DashboardExport {
    pub version: String,
    pub exported_at: DateTime<Utc>,
    pub dashboard: DashboardExportData,
}

/// Dashboard data for export (without ID and timestamps)
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct DashboardExportData {
    pub name: String,
    pub description: Option<String>,
    pub layout: serde_json::Value,
    pub panels: serde_json::Value,
    pub refresh_interval: Option<i32>,
}

/// Request for importing a dashboard
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ImportDashboardRequest {
    /// JSON string of the dashboard export
    pub json: String,
}
