// SPDX-License-Identifier: AGPL-3.0-or-later

//! Dashboard endpoint handlers
//!
//! Split into focused submodules by domain:
//! - `types` — request/response types, validation constants, and query parameters
//! - `crud` — list, get, create, update, share, delete
//! - `query` — panel query execution and variable substitution
//! - `export` — dashboard export/import and validation

mod crud;
mod export;
mod query;
mod types;

pub use crud::*;
pub use export::*;
pub use query::*;
pub use types::*;

use super::AuditExt;

// ============================================================================
// Error Conversion
// ============================================================================

// Note: `From<DashboardRepositoryError> for ApiError` lifted to
// nanosiem-api-lib in NAN-752 (orphan rule — `ApiError` lives there now).

// ============================================================================
// OpenAPI Documentation
// ============================================================================

/// OpenAPI documentation for dashboards endpoints
#[derive(utoipa::OpenApi)]
#[openapi(
    paths(
        list_dashboards,
        create_dashboard,
        get_dashboard,
        update_dashboard,
        share_dashboard,
        delete_dashboard,
        panel_query,
        export_dashboard,
        import_dashboard,
    ),
    components(schemas(
        CreateDashboardRequest,
        UpdateDashboardRequest,
        DashboardSummary,
        PanelQueryRequest,
        PanelQueryResponse,
        DashboardExport,
        DashboardExportData,
        ImportDashboardRequest,
    ))
)]
pub struct DashboardsApiDoc;

impl DashboardsApiDoc {
    pub fn openapi_paths() -> Vec<utoipa::openapi::path::PathItem> {
        vec![]
    }
}
