// SPDX-License-Identifier: AGPL-3.0-or-later

//! Prevalence Tracking API Handlers
//!
//! REST API endpoints for querying prevalence data for file hashes and domains.
//! Requirements: 4.1, 4.2, 4.3, 7.1, 7.2, 7.3, 9.1, 9.2, 9.3, 9.4
//!
//! Split into focused submodules by domain:
//! - `types` — request/response types and query parameters
//! - `lookups` — single artifact and bulk prevalence lookups
//! - `discovery` — rare, new, scatter, and query-based artifact exploration
//! - `export` — CSV/JSON export
//! - `settings` — prevalence configuration management

mod discovery;
mod export;
mod lookups;
mod settings;
mod types;

pub use discovery::*;
pub use export::*;
pub use lookups::*;
pub use settings::*;
pub use types::*;

use nanosiem_core::prevalence::{ArtifactType, TimeWindow};

/// Maximum artifacts per bulk request
const MAX_BULK_ARTIFACTS: usize = 100;

/// Maximum artifacts per export request
const MAX_EXPORT_ARTIFACTS: usize = 10_000;

/// Parse time window from query parameter
fn parse_time_window(window: Option<&str>) -> TimeWindow {
    window.and_then(TimeWindow::from_str).unwrap_or_default()
}

/// Parse artifact type from query parameter
fn parse_artifact_type(type_str: Option<&str>) -> Option<ArtifactType> {
    match type_str?.to_lowercase().as_str() {
        "hash" | "hashes" | "md5" | "sha256" => Some(ArtifactType::HashMd5), // Will match any hash
        "domain" | "domains" => Some(ArtifactType::Domain),
        "ip" | "ips" | "ip_address" => Some(ArtifactType::IpAddress),
        _ => None,
    }
}

/// OpenAPI documentation for prevalence endpoints
pub struct PrevalenceApiDoc;

impl utoipa::OpenApi for PrevalenceApiDoc {
    fn openapi() -> utoipa::openapi::OpenApi {
        use utoipa::OpenApi;

        #[derive(OpenApi)]
        #[openapi(
            paths(
                get_hash_prevalence,
                get_domain_prevalence,
                get_bulk_prevalence,
                get_rare_artifacts,
                get_new_artifacts,
                get_artifact_explorer,
                get_artifact_detail,
                export_prevalence,
                get_scatter_data,
                get_query_artifacts,
                get_prevalence_settings,
                update_prevalence_settings,
            ),
            components(schemas(
                BulkPrevalenceRequest,
                QueryArtifactsRequest,
                QueryArtifactsResponse,
                ArtifactPoint,
                ScatterPlotRequest,
                ScatterArtifacts,
                PrevalenceResponse,
                BulkPrevalenceResponse,
                ArtifactListResponse,
                nanosiem_core::prevalence::ArtifactExplorerResponse,
                nanosiem_core::prevalence::ArtifactExplorerItem,
                nanosiem_core::prevalence::ArtifactDailyCount,
                nanosiem_core::prevalence::ArtifactDetailResponse,
                nanosiem_core::prevalence::ArtifactHostEntry,
                nanosiem_core::prevalence::ArtifactUserEntry,
                nanosiem_core::prevalence::ArtifactSourceEntry,
                nanosiem_core::prevalence::ArtifactProcessEntry,
                nanosiem_core::prevalence::ArtifactNetworkEntry,
                nanosiem_core::prevalence::ArtifactGeoEntry,
                PrevalenceSettingsResponse,
                UpdatePrevalenceSettingsRequest,
            )),
            tags(
                (name = "prevalence", description = "Prevalence tracking and analysis endpoints")
            )
        )]
        struct ApiDoc;

        ApiDoc::openapi()
    }
}
