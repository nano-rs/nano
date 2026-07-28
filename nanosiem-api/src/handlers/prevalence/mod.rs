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

/// One composition seam for every prevalence ARTIFACT read. `AuthContext` is
/// populated identically by JWT and API-key middleware.
///
/// NAN-2219: `ArtifactScope::from_scope` reads the scope's per-source RBAC half
/// and deliberately NOT the `audit:view` gate. The gate belongs to live rows —
/// the raw-logs drilldowns in `discovery.rs` still use
/// `effective_viewer_scope()` / `effective_source_deny_set()` for exactly that
/// reason. Folding it in here made every non-Admin `is_restricted()`, which
/// routed them onto the `*_prevalence_source_agg` tables that migration 170
/// shipped without a backfill; a miss there returns `PrevalenceData::empty`, so
/// every hash, domain and IP read back as `host_count: 0, is_rare: true,
/// first_seen: now` — prevalence inverted for every non-Admin, including on
/// tenants with no source scoping at all.
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
        // A genuinely source-scoped caller keeps its real per-source boundary
        // in the artifact scope.
        assert!(values.contains("secret_source"));
        // NAN-2219: the `audit:view` gate is NOT folded into the artifact
        // scope. It stays on the row-filter half, which the raw-logs
        // drilldowns in `discovery.rs` use.
        assert!(!values.contains("audit"));
        assert!(auth_row_filter_denies_audit(&jwt));
    }

    fn auth_row_filter_denies_audit(auth: &AuthContext) -> bool {
        auth.effective_viewer_scope().deny_set().contains("audit")
    }

    #[test]
    fn audit_view_and_no_source_denies_preserve_system_fast_path() {
        let auth = session(
            &[permissions::PREVALENCE_VIEW, permissions::AUDIT_VIEW],
            &[],
        );
        assert!(effective_artifact_scope(&auth).is_unrestricted());
    }

    /// NAN-2219 (the bug): an ordinary analyst on a tenant with an EMPTY
    /// `restricted_source_types` registry has no per-source boundary at all.
    /// They must NOT be artifact-restricted — that is what routed them onto the
    /// unbackfilled `*_prevalence_source_agg` tables and made every artifact
    /// read back as first-seen and rare.
    #[test]
    fn unscoped_analyst_without_audit_view_is_not_artifact_restricted() {
        for auth in [
            session(&[permissions::PREVALENCE_VIEW], &[]),
            api_key(&[permissions::PREVALENCE_VIEW], &[]),
        ] {
            assert!(
                effective_artifact_scope(&auth).is_unrestricted(),
                "an unscoped caller lacking audit:view must keep the unrestricted \
                 prevalence fast path (NAN-2219)"
            );
            // …while still being denied audit ROWS on the live-data paths.
            assert!(auth_row_filter_denies_audit(&auth));
        }
    }

    /// A tenant that genuinely restricts `audit` through the registry puts it in
    /// the caller's per-source RBAC scope, so it is denied in BOTH halves —
    /// NAN-2219 must not weaken that.
    #[test]
    fn registry_restricted_audit_is_denied_in_the_artifact_scope_too() {
        let auth = session(
            &[permissions::PREVALENCE_VIEW, permissions::AUDIT_VIEW],
            &["audit"],
        );
        let artifact_scope = effective_artifact_scope(&auth);
        let values: BTreeSet<_> = artifact_scope
            .deny_bind_values()
            .iter()
            .map(String::as_str)
            .collect();
        assert!(values.contains("audit"));
        assert!(auth_row_filter_denies_audit(&auth));
    }
}
