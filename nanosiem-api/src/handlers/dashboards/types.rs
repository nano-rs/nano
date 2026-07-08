// SPDX-License-Identifier: AGPL-3.0-or-later

//! Dashboard request/response types, validation constants, and query parameters

use chrono::{DateTime, Utc};
use nanosiem_core::{Dashboard, DashboardSharedGroup, DashboardWithOwner, TimeRangeInput};
use serde::{Deserialize, Deserializer, Serialize};
use std::collections::HashMap;
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

/// Deserialize helper distinguishing an absent field (`None`) from an explicit
/// JSON `null` (`Some(None)`), so partial `PUT`s only touch provided fields
/// (DSH13). Mirrors the api_keys handler's helper.
fn double_option<'de, T, D>(de: D) -> Result<Option<Option<T>>, D::Error>
where
    T: Deserialize<'de>,
    D: Deserializer<'de>,
{
    Deserialize::deserialize(de).map(Some)
}

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
/// Valid visualization types.
///
/// DSH15: kept in lock-step with the frontend `VisualizationType` union
/// (`nanosiem-web/src/lib/api/types.ts`). The five entries after `timeline`
/// were shipping in the union but missing here, so a legitimate re-import of a
/// tree/ranked_bar/transaction/flow/obs_metric panel would have been rejected
/// once the (previously dead, snake_case) whitelist actually ran.
pub(super) const VALID_VIZ_TYPES: &[&str] = &[
    "bar",
    "line",
    "area",
    "pie",
    "table",
    "single_value",
    "timeline",
    "tree",
    "ranked_bar",
    "transaction",
    "flow",
    "obs_metric",
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

/// Request for updating a dashboard.
///
/// `description`/`refresh_interval` use tri-state semantics (DSH13): **absent**
/// = leave unchanged, **`null`** = clear to NULL, **value** = set. They map
/// onto the double-`Option` fields of the core `UpdateDashboard`.
#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct UpdateDashboardRequest {
    pub name: Option<String>,
    #[serde(default, deserialize_with = "double_option")]
    #[schema(value_type = Option<String>)]
    pub description: Option<Option<String>>,
    pub layout: Option<serde_json::Value>,
    pub panels: Option<serde_json::Value>,
    #[serde(default, deserialize_with = "double_option")]
    #[schema(value_type = Option<i32>)]
    pub refresh_interval: Option<Option<i32>>,
    /// Optimistic-concurrency precondition (DSH9): the client's last-seen
    /// `updated_at`. When present, a server-side mismatch returns 409 Conflict
    /// so concurrent editors don't silently clobber each other. Optional so
    /// existing callers keep working (unconditional update).
    pub expected_updated_at: Option<DateTime<Utc>>,
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
    /// DSH8: when true, skip the result cache and recompute live (the
    /// user-initiated "refresh" affordance), repopulating the cache for the
    /// next caller. Absent/false serves from cache as before.
    #[serde(default)]
    pub bypass_cache: Option<bool>,
}

/// Response from a panel query
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct PanelQueryResponse {
    pub results: Vec<serde_json::Value>,
    pub total_count: u64,
    pub execution_time_ms: u64,
    /// Column order for table display (forwarded from the search response,
    /// DSH53) so numeric group-by columns render as labels, not values.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub column_order: Option<Vec<String>>,
    /// DSH40: true when the result hit the hard row cap and more rows matched,
    /// so the UI can show a truncation affordance instead of a clean "success".
    #[serde(default)]
    pub truncated: bool,
    /// DSH8: true when the body was served from the result cache.
    #[serde(default)]
    pub cached: bool,
    /// DSH8: age in whole seconds of a cache hit (absent on a live result).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cache_age_secs: Option<u64>,
}

/// Dashboard export format.
///
/// DSH44: `deny_unknown_fields` so a newer export carrying extra top-level keys
/// fails loudly on import into an older deployment instead of silently dropping
/// them and masquerading as a clean round-trip. Combined with the major-version
/// gate in `validate_dashboard_export`.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct DashboardExport {
    pub version: String,
    pub exported_at: DateTime<Utc>,
    pub dashboard: DashboardExportData,
}

/// Dashboard data for export (without ID and timestamps).
///
/// DSH44: `deny_unknown_fields` — see [`DashboardExport`]. `layout`/`panels`
/// are untyped `Value`s, so nested additions inside them are still permitted;
/// only unexpected top-level dashboard keys are rejected.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
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
