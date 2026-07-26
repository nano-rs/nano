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

/// One composition seam for every prevalence read. `AuthContext` is populated
/// identically by JWT and API-key middleware; `effective_viewer_scope` also
/// folds in the implicit audit deny when the principal lacks `audit:view`.
fn effective_artifact_scope(
    auth: &crate::middleware::AuthContext,
) -> nanosiem_core::auth::ArtifactScope {
    nanosiem_core::auth::ArtifactScope::from_scope(&auth.effective_viewer_scope())
}

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
                nanosiem_core::prevalence::ArtifactDetailResponse,
                nanosiem_core::prevalence::ArtifactHostEntry,
                nanosiem_core::prevalence::ArtifactUserEntry,
                nanosiem_core::prevalence::ArtifactSourceEntry,
                nanosiem_core::prevalence::ArtifactProcessEntry,
                nanosiem_core::prevalence::ArtifactFileNameEntry,
                nanosiem_core::prevalence::ArtifactThreatIntelEntry,
                nanosiem_core::prevalence::ArtifactInlineContext,
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

#[cfg(test)]
mod scope_tests {
    use super::effective_artifact_scope;
    use crate::middleware::AuthContext;
    use nanosiem_core::auth::api_key::ApiKeyInfo;
    use nanosiem_core::auth::permissions;
    use nanosiem_core::auth::token::{DEFAULT_TOKEN_AUDIENCE, DEFAULT_TOKEN_ISSUER};
    use nanosiem_core::auth::{ScopeSet, TokenClaims};
    use std::collections::BTreeSet;
    use uuid::Uuid;

    fn denied(values: &[&str]) -> ScopeSet {
        ScopeSet::from_denied(values.iter().map(|value| value.to_string()).collect())
    }

    fn session(permissions: &[&str], denied_sources: &[&str]) -> AuthContext {
        let mut auth = AuthContext::from_jwt(TokenClaims {
            iss: DEFAULT_TOKEN_ISSUER.to_string(),
            aud: DEFAULT_TOKEN_AUDIENCE.to_string(),
            sub: Uuid::now_v7(),
            roles: Vec::new(),
            permissions: permissions.iter().map(|value| value.to_string()).collect(),
            exp: 0,
            iat: 0,
            jti: Uuid::now_v7(),
            purpose: "access".to_string(),
        });
        auth.denied_sources = denied(denied_sources);
        auth
    }

    fn api_key(permissions: &[&str], denied_sources: &[&str]) -> AuthContext {
        let mut auth = AuthContext::from_api_key(&ApiKeyInfo {
            id: Uuid::now_v7(),
            name: "prevalence-scope-probe".to_string(),
            permissions: permissions.iter().map(|value| value.to_string()).collect(),
            user_id: Some(Uuid::now_v7()),
        });
        auth.denied_sources = denied(denied_sources);
        auth
    }

    #[test]
    fn jwt_and_api_key_build_identical_prevalence_scope() {
        let permissions = [permissions::PREVALENCE_VIEW];
        let jwt = session(&permissions, &["secret_source"]);
        let key = api_key(&permissions, &["secret_source"]);

        assert_eq!(
            effective_artifact_scope(&jwt),
            effective_artifact_scope(&key)
        );
        let jwt_scope = effective_artifact_scope(&jwt);
        let values: BTreeSet<_> = jwt_scope
            .deny_bind_values()
            .iter()
            .map(String::as_str)
            .collect();
        assert!(values.contains("secret_source"));
        assert!(values.contains("audit"));
    }

    #[test]
    fn audit_view_and_no_source_denies_preserve_system_fast_path() {
        let auth = session(
            &[permissions::PREVALENCE_VIEW, permissions::AUDIT_VIEW],
            &[],
        );
        assert!(effective_artifact_scope(&auth).is_unrestricted());
    }
}
