// SPDX-License-Identifier: AGPL-3.0-or-later

//! OpenAPI/Swagger documentation for the NanoSIEM API
//!
//! Provides a complete OpenAPI 3.1 spec served via Swagger UI.
//! All handler annotations are composed here via programmatic merging of sub-docs.

use utoipa::openapi::security::{ApiKey, ApiKeyValue, HttpAuthScheme, HttpBuilder, SecurityScheme};
use utoipa::{Modify, OpenApi};

use crate::error::{ErrorDetail, ErrorResponse};
use crate::handlers;

/// Root OpenAPI document for the NanoSIEM API.
///
/// Defines only the top-level info, tags, security, and shared schemas.
/// Handler sub-docs are merged programmatically in [`build_openapi`].
#[derive(OpenApi)]
#[openapi(
    info(
        title = "NanoSIEM API",
        description = "REST API for NanoSIEM - a lightweight Security Information and Event Management system.\n\nAuthenticate using either:\n- **Bearer JWT** via the Authorization header\n- **API Key** via the X-API-Key header",
        version = "0.1.0",
        license(name = "MIT"),
    ),
    modifiers(&SecurityAddon),
    tags(
        (name = "health", description = "Health check endpoints"),
        (name = "setup", description = "First-run system setup"),
        (name = "auth", description = "Authentication (login, logout, token refresh, password reset)"),
        (name = "mfa", description = "Multi-factor authentication (TOTP enrollment, verification, management)"),
        (name = "users", description = "User management"),
        (name = "groups", description = "Group management"),
        (name = "roles", description = "Role and permission management"),
        (name = "api_keys", description = "API key management"),
        (name = "sessions", description = "Session management"),
        (name = "audit", description = "Audit log viewing and export"),
        (name = "airgap", description = "Air-gapped offline bundle import (signed parsers / IP & IOC enrichment / license)"),
        (name = "oidc", description = "OIDC provider configuration and authentication"),
        (name = "search", description = "Search queries, saved searches, field stats, and asset events (served by the search microservice on port 3002)"),
        (name = "search_history", description = "Per-user search history"),
        (name = "fields", description = "Field metadata and UDM schema"),
        (name = "detections", description = "Detection rule lifecycle (create, test, promote, trigger)"),
        (name = "alerts", description = "Alert management and triage"),
        (name = "cases", description = "Case management, wall entries, and alert correlation"),
        (name = "incidents", description = "Incident management (groups related cases into campaigns)"),
        (name = "entities", description = "Entity context (risk, alerts, cases for a given entity)"),
        (name = "enrichment", description = "IP/IOC enrichment sources (IPInfo, ThreatFox, TOR)"),
        (name = "identity", description = "Identity provider sync (Entra ID, Google Workspace, AD) and user directory"),
        (name = "agent_enrichment", description = "AI-powered threat intelligence provider settings"),
        (name = "custom_enrichment", description = "User-defined TypeScript enrichments"),
        (name = "prevalence", description = "Artifact prevalence tracking and analysis"),
        (name = "risk", description = "Entity risk scoring and analytics"),
        (name = "mitre", description = "MITRE ATT&CK framework data and coverage"),
        (name = "log_sources", description = "Log source configuration, VRL validation, and deployment"),
        (name = "source_configs", description = "Source infrastructure configuration and routing rules"),
        (name = "credentials", description = "Cloud credential management"),
        (name = "dashboards", description = "Dashboard CRUD, panel queries, import/export"),
        (name = "notebooks", description = "Investigation notebooks, entries, sharing, and tabs"),
        (name = "tuning", description = "Detection rule tuning (baselines, proposals, versions)"),
        (name = "melod", description = "meloD AI assistant (chat, parser, query, detection, dashboard generation)"),
        (name = "settings", description = "System settings (retention, storage, risk, AI providers, etc.)"),
        (name = "notifications", description = "User notifications"),
        (name = "feedback", description = "User feedback"),
        (name = "recent_activity", description = "Recent activity tracking (Continue Working feature)"),
        (name = "query_library", description = "Pre-built query library"),
        (name = "lookup", description = "Lookup table management, queries, and ingestion"),
        (name = "rule_repositories", description = "External Sigma rule repository syncing"),
        (name = "parser_repositories", description = "External parser repository syncing and import"),
        (name = "playbooks", description = "SOC investigation playbook library (markdown + slash-command format)"),
        (name = "playbook_repositories", description = "External playbook repository syncing and import"),
        (name = "upload", description = "File upload and preview"),
        (name = "marketplace", description = "Enrichment marketplace (unified catalog, repos, install/uninstall)"),
        (name = "gdpr", description = "GDPR data subject anonymization"),
        (name = "ip_allowlist", description = "IP allowlist management for access control"),
        (name = "onboarding", description = "Onboarding wizard progress and status"),
        (name = "siem_health", description = "SIEM health check reports and analysis"),
        (name = "system", description = "System overview and metrics"),
    ),
    components(schemas(ErrorResponse, ErrorDetail))
)]
pub struct ApiDoc;

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

/// Build the complete OpenAPI spec by merging all handler sub-docs into the root.
///
/// We use the runtime `nest()` method (which accepts empty string paths) rather
/// than the `#[openapi(nest(...))]` macro attribute (which rejects empty paths).
pub fn build_openapi() -> utoipa::openapi::OpenApi {
    let mut spec = ApiDoc::openapi();

    // Merge each handler module's sub-doc. Since handler paths already include
    // the full `/api/...` prefix, we nest with "/" to avoid path duplication.
    // The vec is mutated below only on enterprise builds (to push meloD +
    // notebooks); open builds use it read-only.
    #[cfg_attr(not(feature = "enterprise"), allow(unused_mut))]
    let mut sub_docs: Vec<utoipa::openapi::OpenApi> = vec![
        handlers::health::HealthApiDoc::openapi(),
        handlers::capabilities::CapabilitiesApiDoc::openapi(),
        handlers::setup::SetupApiDoc::openapi(),
        handlers::auth::AuthApiDoc::openapi(),
        handlers::mfa::MfaApiDoc::openapi(),
        handlers::users::UsersApiDoc::openapi(),
        handlers::groups::GroupsApiDoc::openapi(),
        handlers::roles::RolesApiDoc::openapi(),
        handlers::api_keys::ApiKeysApiDoc::openapi(),
        handlers::sessions::SessionsApiDoc::openapi(),
        handlers::audit::AuditApiDoc::openapi(),
        handlers::search::SearchApiDoc::openapi(),
        handlers::search_history::SearchHistoryApiDoc::openapi(),
        handlers::fields::FieldsApiDoc::openapi(),
        handlers::detections::DetectionsApiDoc::openapi(),
        handlers::alerts::AlertsApiDoc::openapi(),
        handlers::enrichment::EnrichmentApiDoc::openapi(),
        handlers::identity::IdentityApiDoc::openapi(),
        handlers::prevalence::PrevalenceApiDoc::openapi(),
        handlers::mitre::MitreApiDoc::openapi(),
        handlers::log_sources::LogSourcesApiDoc::openapi(),
        handlers::source_configs::SourceConfigsApiDoc::openapi(),
        handlers::credentials::CredentialsApiDoc::openapi(),
        handlers::dashboards::DashboardsApiDoc::openapi(),
        handlers::demo::DemoApiDoc::openapi(),
        handlers::tuning::TuningApiDoc::openapi(),
        handlers::settings::SettingsApiDoc::openapi(),
        handlers::notifications::NotificationsApiDoc::openapi(),
        handlers::feedback::FeedbackApiDoc::openapi(),
        handlers::folder_settings::FolderSettingsApiDoc::openapi(),
        handlers::recent_activity::RecentActivityApiDoc::openapi(),
        handlers::query_library::QueryLibraryApiDoc::openapi(),
        handlers::lookup::LookupApiDoc::openapi(),
        handlers::rule_repositories::RuleRepositoriesApiDoc::openapi(),
        handlers::parser_repositories::ParserRepositoriesApiDoc::openapi(),
        handlers::playbooks::PlaybooksApiDoc::openapi(),
        handlers::playbook_repositories::PlaybookRepositoriesApiDoc::openapi(),
        handlers::marketplace::MarketplaceApiDoc::openapi(),
        handlers::upload::UploadApiDoc::openapi(),
        handlers::gdpr::GdprApiDoc::openapi(),
        handlers::ip_allowlist::IpAllowlistApiDoc::openapi(),
        handlers::onboarding::OnboardingApiDoc::openapi(),
        handlers::siem_health::SiemHealthApiDoc::openapi(),
        handlers::siem_health_suppressions::SiemHealthSuppressionsApiDoc::openapi(),
        handlers::system::SystemApiDoc::openapi(),
    ];

    // Enterprise-only sub-docs. Their handler modules (`melod`, `notebooks`,
    // `risk`) and the `nanosiem-enterprise::*` types they reference are gated
    // behind the `enterprise` feature, so the registrations have to live
    // here too — open builds simply omit these endpoints from the spec.
    #[cfg(feature = "enterprise")]
    {
        // License / phone-home (NAN-1193): stripped from the open edition, so
        // the open spec omits the /api/license path entirely.
        sub_docs.push(handlers::license::LicenseApiDoc::openapi());
        // Phase 3.2 (NAN-744): cases + incidents lifted to enterprise.
        sub_docs.push(handlers::cases::CasesApiDoc::openapi());
        sub_docs.push(handlers::incidents::IncidentsApiDoc::openapi());
        sub_docs.push(handlers::notebooks::NotebooksApiDoc::openapi());
        sub_docs.push(handlers::melod::MelodApiDoc::openapi());
        sub_docs.push(handlers::risk::RiskApiDoc::openapi());
        sub_docs.push(handlers::entity_context::EntityContextApiDoc::openapi());
        sub_docs.push(handlers::agent_enrichment::AgentEnrichmentApiDoc::openapi());
        sub_docs.push(handlers::custom_enrichment::CustomEnrichmentApiDoc::openapi());
        // /api/enrichment/agent/lookup lives inside handlers::enrichment but
        // its handler + supporting types are cfg-gated for enterprise (Phase
        // 3.3); keep the doc alongside the handler.
        sub_docs.push(handlers::enrichment::EnrichmentAgentApiDoc::openapi());
        // OIDC / SSO — open-core split (NAN-745). Gated alongside the
        // handler module; the open spec omits these paths entirely.
        sub_docs.push(handlers::oidc::OidcApiDoc::openapi());
        // Air-gapped bundle import (NAN-1201) — enterprise only.
        sub_docs.push(handlers::airgap::parsers::AirgapParsersApiDoc::openapi());
        sub_docs.push(handlers::airgap::enrichment::AirgapEnrichmentApiDoc::openapi());
        sub_docs.push(handlers::airgap::license::AirgapLicenseApiDoc::openapi());
        // Air-gapped rule + playbook bundle import (NAN-1220) — enterprise only.
        sub_docs.push(handlers::airgap::rules::AirgapRulesApiDoc::openapi());
        sub_docs.push(handlers::airgap::playbooks::AirgapPlaybooksApiDoc::openapi());
    }

    for sub in sub_docs {
        // Merge paths
        spec.paths.paths.extend(sub.paths.paths);

        // Merge components (schemas, etc.)
        if let Some(sub_components) = sub.components {
            if let Some(ref mut components) = spec.components {
                components.schemas.extend(sub_components.schemas);
            } else {
                spec.components = Some(sub_components);
            }
        }
    }

    // Merge search service endpoints (nanosiem-search, port 3002)
    let search_spec = nanosiem_search::openapi::build_openapi();
    spec.paths.paths.extend(search_spec.paths.paths);
    if let Some(search_components) = search_spec.components {
        if let Some(ref mut components) = spec.components {
            components.schemas.extend(search_components.schemas);
        } else {
            spec.components = Some(search_components);
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
        // Ensure spec has paths
        assert!(
            !spec.paths.paths.is_empty(),
            "OpenAPI spec should have paths"
        );
    }

    #[test]
    fn verify_openapi_path_count() {
        let spec = build_openapi();
        let path_count = spec.paths.paths.len();
        eprintln!("OpenAPI spec has {path_count} paths (includes merged search service endpoints)");

        // Enterprise builds register the full handler set including meloD,
        // notebooks, risk analytics, agent + custom enrichment, and (post
        // Phase 3.2 of NAN-744) cases + incidents + case-grouping settings;
        // open builds omit those. The enterprise→open delta is roughly:
        // - ai_providers settings (~14) + meloD endpoints (~25) +
        //   notebooks endpoints (~26) + risk page endpoints (~7) +
        //   risk-decay settings (~2) +
        //   agent_enrichment + custom_enrichment + agent lookup (~24) +
        //   cases (~32) + queues + queue-routing-rules (~11) +
        //   incidents (~5) + case-grouping settings (~6) ≈ ~150.
        // Open clears ~366; enterprise ~470 (floors, current values higher).
        // NAN-1093 added 2 enterprise paths: /inbox-counts + /inbox-incidents.
        // NAN-1201 added 3 enterprise paths: air-gap parsers/enrichment/license import.
        // NAN-1220 added 2 enterprise paths: air-gap rules/playbooks import.
        // NAN-1232 removed 1 shared path: /api/news (dead cybersecurity news feed).
        // NAN-1241 (OCSF Phase 3b) added 1 shared path: /api/schema/fields
        // (profile-aware field universe), counted in both editions.
        #[cfg(feature = "enterprise")]
        let min_paths = 475;
        #[cfg(not(feature = "enterprise"))]
        let min_paths = 366;

        assert!(
            path_count >= min_paths,
            "Expected at least {min_paths} paths, got {path_count}"
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
}
