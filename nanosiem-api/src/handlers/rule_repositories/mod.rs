// SPDX-License-Identifier: AGPL-3.0-or-later

//! Rule Repository endpoint handlers
//!
//! Split into focused submodules by domain:
//! - `types` — request/response types and query parameters
//! - `crud` — list, get, create, update, delete
//! - `sync` — repository sync and status
//! - `rules` — folder browsing, rule listing, preview, import
//! - `coverage` — coverage analysis, refresh, sigma conversion
//! - `upstream` — upstream change detection and diff
//! - `batch` — batch import and remove operations

mod batch;
mod coverage;
mod crud;
mod rules;
mod sync;
pub mod types;
mod upstream;

pub use batch::*;
pub use coverage::*;
pub use crud::*;
pub use rules::*;
pub use sync::*;
pub use types::*;
pub use upstream::*;

use nanosiem_core::RuleRepositoryService;

use super::AuditExt;
use crate::{error::ApiError, state::AppState};

// =============================================================================
// SHARED HELPERS
// =============================================================================

/// Create a RuleRepositoryService from app state
pub(crate) fn get_rule_repo_service(state: &AppState) -> Result<RuleRepositoryService, ApiError> {
    let service = RuleRepositoryService::with_dual_pool(&state.dual_pool);
    let detection_service = std::sync::Arc::new(state.detection_service.clone());
    Ok(service.with_detection_service(detection_service))
}

// Note: `From<RuleRepositoryError> for ApiError` lifted to nanosiem-api-lib
// in NAN-752 (orphan rule — `ApiError` lives there now).

/// OpenAPI documentation for rule repository endpoints
#[derive(utoipa::OpenApi)]
#[openapi(
    paths(
        list_repositories,
        get_repository,
        create_repository,
        update_repository,
        delete_repository,
        sync_repository,
        get_sync_status,
        list_folders,
        list_repository_rules,
        get_repository_rule,
        preview_import,
        import_rule,
        batch_import_rules,
        remove_all_imported,
        get_coverage,
        refresh_coverage,
        convert_sigma,
        get_upstream_updates,
        get_upstream_diff,
        dismiss_upstream_changes,
    ),
    components(schemas(
        ListRepositoriesResponse,
        CreateRepositoryRequest,
        UpdateRepositoryRequest,
        ListFoldersResponse,
        RepositoryRuleResponse,
        ImportRuleRequest,
        ImportRuleResponse,
        BatchImportRequest,
        BatchImportItem,
        BatchImportResponse,
        BatchRemoveResponse,
        BatchFailure,
        BatchRemoveFailure,
        ConvertSigmaRequest,
        ConvertSigmaResponse,
        FieldMappingResponse,
        SyncStartResponse,
        SyncStatusResponse,
        UpstreamUpdatesResponse,
    ))
)]
pub struct RuleRepositoriesApiDoc;
