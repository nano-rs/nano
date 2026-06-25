// SPDX-License-Identifier: AGPL-3.0-or-later

//! OpenAPI/Swagger documentation for the NanoSIEM Search Service
//!
//! Provides a complete OpenAPI 3.1 spec served via Swagger UI.
//! Handler annotations are composed here via programmatic merging.

use utoipa::openapi::security::{ApiKey, ApiKeyValue, HttpAuthScheme, HttpBuilder, SecurityScheme};
use utoipa::{Modify, OpenApi};

use crate::handlers;

/// Root OpenAPI document for the NanoSIEM Search Service.
///
/// Defines the top-level info, tags, security, and shared schemas.
/// Handler sub-docs are merged programmatically in [`build_openapi`].
#[derive(OpenApi)]
#[openapi(
    info(
        title = "NanoSIEM Search Service",
        description = "Search microservice for NanoSIEM - handles query execution, saved searches, field statistics, and asset event queries against ClickHouse.\n\nAuthenticate using either:\n- **Bearer JWT** via the Authorization header\n- **API Key** via the X-API-Key header",
        version = "0.1.0",
        license(name = "MIT"),
    ),
    modifiers(&SecurityAddon),
    tags(
        (name = "search", description = "Search queries, saved searches, field stats, and asset events"),
        (name = "search-admin", description = "Admin search job management and admission stats"),
        (name = "identity", description = "Identity resolution for IP addresses"),
        (name = "health", description = "Health and readiness check endpoints"),
    ),
)]
pub struct SearchServiceApiDoc;

/// Adds Bearer JWT and X-API-Key security schemes to the OpenAPI spec.
struct SecurityAddon;

impl Modify for SecurityAddon {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        if let Some(components) = openapi.components.as_mut() {
            components.add_security_scheme(
                "bearer_auth",
                SecurityScheme::Http(
                    HttpBuilder::new()
                        .scheme(HttpAuthScheme::Bearer)
                        .bearer_format("JWT")
                        .description(Some("JWT access token from /api/auth/login"))
                        .build(),
                ),
            );
            components.add_security_scheme(
                "api_key",
                SecurityScheme::ApiKey(ApiKey::Header(ApiKeyValue::with_description(
                    "X-API-Key",
                    "API key for service-to-service authentication",
                ))),
            );
        }
    }
}

/// Build the complete OpenAPI spec by merging handler sub-docs into the root.
///
/// Uses programmatic composition (same approach as nanosiem-api) rather than
/// the `#[openapi(nest(...))]` macro attribute.
pub fn build_openapi() -> utoipa::openapi::OpenApi {
    let mut spec = SearchServiceApiDoc::openapi();

    // Merge handler sub-docs. Paths already include the full `/api/...` prefix.
    for sub in [
        handlers::SearchApiDoc::openapi(),
        handlers::identity::IdentityApiDoc::openapi(),
    ] {
        spec.paths.paths.extend(sub.paths.paths);
        if let Some(sub_components) = sub.components {
            if let Some(ref mut components) = spec.components {
                components.schemas.extend(sub_components.schemas);
            } else {
                spec.components = Some(sub_components);
            }
        }
    }

    spec
}

/// Build the Swagger UI service that serves the interactive docs.
pub fn swagger_ui() -> utoipa_swagger_ui::SwaggerUi {
    utoipa_swagger_ui::SwaggerUi::new("/swagger-ui").url("/api-docs/openapi.json", build_openapi())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verify_openapi_spec_generates() {
        let spec = build_openapi();
        assert!(
            !spec.paths.paths.is_empty(),
            "OpenAPI spec should have paths"
        );
    }

    #[test]
    fn verify_openapi_has_security_schemes() {
        let spec = build_openapi();
        let components = spec.components.expect("spec should have components");
        assert!(
            components.security_schemes.contains_key("bearer_auth"),
            "Should have bearer_auth scheme"
        );
        assert!(
            components.security_schemes.contains_key("api_key"),
            "Should have api_key scheme"
        );
    }

    #[test]
    fn verify_openapi_has_all_paths() {
        let spec = build_openapi();
        let paths: Vec<&str> = spec.paths.paths.keys().map(|s| s.as_str()).collect();

        // Verify key paths exist
        let expected = vec![
            "/api/search",
            "/api/search/stream",
            "/api/search/sql",
            "/api/search/explain",
            "/api/search/log",
            "/api/search/prevalence-artifacts",
            "/api/search/field-stats",
            "/api/search/field-values",
            "/api/search/saved",
            "/api/search/saved/shared",
            "/api/search/saved/mine",
            "/api/search/saved/{id}",
            "/api/search/saved/{id}/share",
            "/api/search/asset-events",
            "/api/search/cloud-events",
            "/api/search/cloud-user-timeline",
            "/api/search/cloud-entity-pivot",
            "/api/search/asset-true-time-range",
            "/api/search/asset-artifacts",
            "/api/search/asset-dossier",
            "/api/search/cloud-overview",
            "/api/search/cloud-dossier",
            "/api/search/jobs/{job_id}",
            "/api/search/{request_id}",
            "/api/search/admin/jobs",
            "/api/search/admin/stats",
            "/api/search/admin/jobs/{job_id}",
            "/api/identity/resolve",
            "/api/search/traces",
            "/api/search/metrics/names",
            "/api/search/metrics/tags",
            "/api/search/services",
            "/api/search/services/{service}",
            "/api/search/infra/hosts",
            "/api/search/rum",
            "/health",
            "/ready",
        ];

        for path in &expected {
            assert!(
                paths.contains(path),
                "Missing path: {}. Available: {:?}",
                path,
                paths
            );
        }
    }
}
