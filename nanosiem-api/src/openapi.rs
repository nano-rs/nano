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
        (name = "source_scopes", description = "Per-source RBAC scope registry (restricted source_types) and group grants"),
        (name = "credentials", description = "Cloud credential management"),
        (name = "dashboards", description = "Dashboard CRUD, panel queries, import/export"),
        (name = "artifacts", description = "Shared artifact-analysis store (specimen reports: verdict, deobfuscation, IOCs, MITRE)"),
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
        (name = "hunts", description = "Active Hunter: scheduled autonomous threat hunts, sweeps, scored leads, and triage"),
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
        // Per-source RBAC scope admin (NAN-1799) — core (open + enterprise).
        handlers::source_scopes::SourceScopesApiDoc::openapi(),
        handlers::credentials::CredentialsApiDoc::openapi(),
        handlers::dashboards::DashboardsApiDoc::openapi(),
        // Shared artifact-analysis store (NAN-1977) — core (open + enterprise);
        // the desktop Artifacts pane must work against open tenants.
        handlers::artifacts::ArtifactsApiDoc::openapi(),
        handlers::demo::DemoApiDoc::openapi(),
        handlers::tuning::TuningApiDoc::openapi(),
        handlers::settings::SettingsApiDoc::openapi(),
        handlers::notifications::NotificationsApiDoc::openapi(),
        handlers::feedback::FeedbackApiDoc::openapi(),
        handlers::folder_settings::FolderSettingsApiDoc::openapi(),
        handlers::recent_activity::RecentActivityApiDoc::openapi(),
        handlers::query_library::QueryLibraryApiDoc::openapi(),
        handlers::reports::ReportsApiDoc::openapi(),
        handlers::lookup::LookupApiDoc::openapi(),
        handlers::rule_repositories::RuleRepositoriesApiDoc::openapi(),
        handlers::detection_code_targets::DetectionCodeTargetsApiDoc::openapi(),
        handlers::parser_repositories::ParserRepositoriesApiDoc::openapi(),
        handlers::playbooks::PlaybooksApiDoc::openapi(),
        // NAN-2238 Active Hunter. Registered alongside playbooks because a hunt
        // definition IS a playbooks row; the runtime is what splits.
        handlers::hunts::HuntsApiDoc::openapi(),
        handlers::playbook_repositories::PlaybookRepositoriesApiDoc::openapi(),
        handlers::marketplace::MarketplaceApiDoc::openapi(),
        #[cfg(feature = "enterprise")]
        handlers::integrations::IntegrationsApiDoc::openapi(),
        handlers::upload::UploadApiDoc::openapi(),
        handlers::gdpr::GdprApiDoc::openapi(),
        handlers::ip_allowlist::IpAllowlistApiDoc::openapi(),
        handlers::onboarding::OnboardingApiDoc::openapi(),
        handlers::siem_health::SiemHealthApiDoc::openapi(),
        handlers::siem_health_suppressions::SiemHealthSuppressionsApiDoc::openapi(),
        handlers::observability_slos::ObservabilitySlosApiDoc::openapi(),
        handlers::observability_synthetics::ObservabilitySyntheticsApiDoc::openapi(),
        handlers::observability_metric_monitors::ObservabilityMetricMonitorsApiDoc::openapi(),
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
        // Observability ↔ Security convergence cross-link (NAN-1542) — gated to
        // enterprise in NAN-1544. The open spec omits this path entirely.
        sub_docs
            .push(handlers::observability_service_signals::ObservabilityServiceSignalsApiDoc::openapi());
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
    use utoipa::openapi::path::HttpMethod;

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
    fn verify_log_source_transport_ownership_contract() {
        let generated = serde_json::to_value(build_openapi()).expect("serialize generated spec");

        // NAN-2169: read the checked-in spec at RUNTIME, not via include_str!.
        // The open-core strip drops everything under docs/ except img/
        // (tools/sync-to-nano-mirror.sh), so a compile-time include makes this
        // test unbuildable in the mirror tree and fails sync-mirror before it
        // can push. The generated spec is asserted in both editions; the
        // checked-in half is additive and only runs where the file survives.
        let checked_in_path = concat!(env!("CARGO_MANIFEST_DIR"), "/../docs/api/openapi.json");
        let checked_in: Option<serde_json::Value> = match std::fs::read_to_string(checked_in_path) {
            Ok(raw) => Some(serde_json::from_str(&raw).expect("parse checked-in spec")),
            // Only a genuinely absent file means "stripped tree". Any other IO
            // error (permissions, read fault) must stay loud — silently skipping
            // would turn this into a half-test that still reports green.
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => None,
            Err(err) => panic!("read checked-in spec {checked_in_path}: {err}"),
        };

        let mut specs = vec![("generated", generated)];
        match checked_in {
            Some(spec) => specs.push(("checked-in", spec)),
            None => eprintln!(
                "skipping checked-in spec assertions: {checked_in_path} absent (open-core stripped tree)"
            ),
        }

        for (label, spec) in specs {
            let schemas = &spec["components"]["schemas"];
            for schema_name in ["LogSource", "NewLogSource", "UpdateLogSource"] {
                let properties = schemas[schema_name]["properties"]
                    .as_object()
                    .unwrap_or_else(|| panic!("{label} spec missing {schema_name}.properties"));
                for retired in ["source_config", "credential_id", "parser_only"] {
                    assert!(
                        !properties.contains_key(retired),
                        "{label} {schema_name} retained retired field {retired}"
                    );
                }
            }

            let source_config_properties = schemas["NewSourceConfiguration"]["properties"]
                .as_object()
                .unwrap_or_else(|| {
                    panic!("{label} spec missing NewSourceConfiguration.properties")
                });
            assert!(
                source_config_properties.contains_key("credential_id"),
                "{label} source-configuration contract lost active credential_id"
            );
        }
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
        // NAN-1519 added 1 shared path: /api/settings/ai-usage (AI usage ledger
        // detail — per-agent/daily/recent breakdowns), counted in both editions.
        // NAN-1528 added 2 shared search-service paths (merged below):
        // GET /api/search/trace/{trace_id} + POST /api/search/metrics/timeseries
        // (OpenTelemetry trace waterfall + metric series), counted in both editions.
        // NAN-1534 added 2 shared search-service paths (merged below):
        // GET /api/search/traces (recent-traces list) + GET /api/search/metrics/names
        // (OTLP explorers — Traces table + Metrics dropdown), counted in both editions.
        // NAN-1536 added 4 shared paths (Observability console): 2 search-service
        // (GET /api/search/services + GET /api/search/services/{service} — services
        // overview + service detail, merged below) and 2 api-service SLO paths
        // (/api/observability/slos + /api/observability/slos/{id} — SLO CRUD),
        // counted in both editions.
        // NAN-1538 added 2 shared api-service paths (Observability synthetics):
        // /api/observability/synthetics + /api/observability/synthetics/{id}.
        // NAN-1537 added 2 shared search-service paths: GET /api/search/infra/hosts
        // + GET /api/search/rum.
        // NAN-1540 added 3 shared paths (Metrics v2): GET /api/search/metrics/tags
        // + /api/observability/metric-monitors + .../{id} (monitor CRUD).
        // NAN-1542 added 1 api-service path (Observability ↔ Security
        // convergence): GET /api/observability/services/{service}/security-signals.
        // NAN-1544 re-gated that convergence path to ENTERPRISE only — it now
        // counts in the enterprise spec only, dropping the open floor by 1.
        // NAN-1580 added 1 shared search-service path (merged below):
        // POST /api/search/retro (IOC retro-hunt rollup), counted in both editions.
        // NAN-1745 added 4 shared paths (detection-as-code push targets):
        // /api/detection-code-targets, /{id}, /{id}/token, /{id}/test — both editions.
        // NAN-1790 added 2 shared paths (notification channels): GET + PUT
        // /api/settings/notifications/config (deep-link base URL), both editions.
        // NAN-1792 added 1 ENTERPRISE path: /api/settings/risk-notables
        // (GET + PUT — risk-notable thresholds/cooldown config).
        // NAN-1793 added 9 shared paths (scheduled reports): /api/reports (GET,
        // POST), /api/reports/{id} (GET, PUT, DELETE), /api/reports/{id}/run,
        // /api/reports/{id}/runs, /api/reports/runs/{run_id}, and
        // /api/reports/artifacts/{artifact_id}/download — counted in both editions.
        // NAN-1791 added 4 shared paths (auto retro-hunt rules): POST
        // /api/rules/retro-hunt, GET /api/rules/retro-hunt/feeds, GET+PUT
        // /api/rules/{id}/retro-hunt (one path), GET /api/rules/{id}/retro-hunt/runs
        // — counted in both editions.
        // NAN-1799 +6 source-scope paths (per-source RBAC admin CRUD, shared/core):
        // 6 operations across 5 distinct path templates —
        // GET+POST /api/source-scopes/restricted (one template, two methods),
        // DELETE /api/source-scopes/restricted/{source_type},
        // GET /api/source-scopes/restricted/{source_type}/grants,
        // POST /api/source-scopes/grants,
        // DELETE /api/source-scopes/grants/{source_type}/{group_id}.
        // Floor bumped by 6 (operation count, matching the ledger convention);
        // the floors are loose lower bounds so this stays a valid minimum.
        // Counted in both editions.
        // NAN-1806 removed 1 ENTERPRISE path: GET /api/risk/thresholds (the
        // retired RiskNotableScheduler's candidate view; consumer-free after
        // NAN-1805 made risk alerting a dataset=risk detection rule). The
        // enterprise floor nets 513 + 6 (NAN-1799) − 1 (NAN-1806) = 518; the
        // open edition never had the thresholds path.
        // NAN-1977 added 2 shared path templates (artifact-analysis store):
        // /api/artifacts (GET, POST) + /api/artifacts/{id} (GET, PUT, DELETE) —
        // counted in both editions, so both floors bump by 2 (518→520, 408→410).
        // NAN-1981 added 1 ENTERPRISE path: GET /api/risk/notable-count (count of
        // entities at/above the risk-notable thresholds — the Home "matter"
        // number). Enterprise floor 520 + 1 = 521; open edition has no risk page.
        // NAN-2189 added 3 ENTERPRISE path templates for integration collectors:
        // /api/integrations/instances (GET, POST), /api/integrations/instances/{id}
        // (GET, PUT, DELETE) and /api/integrations/instances/{id}/run (POST).
        // Enterprise-only — collectors need egress and the Deno runtime, neither
        // of which the open edition ships. Enterprise floor 521 + 3 = 524.
        // NAN-2238 added 20 shared path templates (Active Hunter), counted in
        // both editions. A hunt definition is a `playbooks` row and the whole
        // surface is registered ungated, matching how playbooks itself ships:
        //   /api/hunts/summary, /api/hunts, /api/hunts/{id},
        //   /api/hunts/{id}/sweeps, /api/hunts/{id}/toggle,
        //   /api/hunts/runners, /api/hunts/runners/{id}/heartbeat,
        //   /api/hunts/runners/{id}/claim,
        //   /api/hunts/sweeps/{id}, /api/hunts/sweeps/{id}/report,
        //   /api/hunts/leads, /api/hunts/leads/{id},
        //   /api/hunts/leads/{id}/promote, /api/hunts/leads/{id}/dismiss,
        //   /api/hunts/suppressions, /api/hunts/suppressions/{id},
        //   /api/hunts/profile, /api/hunts/rule-ideas,
        //   /api/hunts/rule-ideas/{id}/send, /api/hunts/rule-ideas/{id}/reject.
        // Enterprise floor 524 + 20 = 544; open floor 410 + 20 = 430.
        //
        // Recon generation added 1 more shared path template:
        //   /api/hunts/profile/run.
        // Enterprise floor 544 + 1 = 545; open floor 430 + 1 = 431.
        //
        // Reworking recon from a closed job into agent-driven primitives added
        // 3 more shared path TEMPLATES:
        //   /api/hunts/profile/census (POST), /api/hunts/profile/surface (POST)
        //   and /api/hunts/drafts (POST).
        // `POST /api/hunts/profile` is a fourth new OPERATION but reuses the
        // template `GET /api/hunts/profile` already contributes, and this
        // assertion counts templates — so the floor moves by 3, not 4.
        // Enterprise floor 545 + 3 = 548; open floor 431 + 3 = 434.
        //
        // NAN-2239 then added 2 shared path templates (hunt knowledge), counted
        // in both editions alongside the rest of the hunts surface:
        //   /api/hunts/knowledge (GET recall + POST record — one template, two
        //   operations) and /api/hunts/knowledge/{id}/revoke (POST).
        // Enterprise floor 548 + 2 = 550; open floor 434 + 2 = 436.
        //
        // NAN-2264 then added 1 shared path template, the Antigravity sweep
        // waiver: /api/hunts/runners/{id}/agy-waiver (POST grant + DELETE
        // revoke — one template, two operations, so the floor moves by 1).
        // Enterprise floor 550 + 1 = 551; open floor 436 + 1 = 437.
        #[cfg(feature = "enterprise")]
        let min_paths = 551;
        #[cfg(not(feature = "enterprise"))]
        let min_paths = 437;

        assert!(
            path_count >= min_paths,
            "Expected at least {min_paths} paths, got {path_count}"
        );
    }

    /// NAN-1918: the quarantine listing is the only operator-visible surface
    /// for mappings a catalog sync dropped. If it silently falls out of the
    /// spec it also falls out of the generated client.
    #[test]
    fn verify_mitre_quarantine_path_is_documented() {
        let spec = build_openapi();
        assert!(
            spec.paths.paths.contains_key("/api/mitre/quarantine"),
            "GET /api/mitre/quarantine must be registered in MitreApiDoc"
        );
    }

    /// A duplicated `#[test]` attribute on the test above had been absorbing
    /// this one's, so from the day it was written until NAN-2055 this assertion
    /// never ran and the compiler reported it only as dead code. Restored.
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
    fn verify_ingestion_updates_document_optimistic_concurrency() {
        let spec = build_openapi();

        for path in ["/api/source-configurations/{id}", "/api/log-sources/{id}"] {
            let operation = spec
                .paths
                .get_path_operation(path, HttpMethod::Put)
                .unwrap_or_else(|| panic!("missing PUT operation for {path}"));
            assert!(
                operation.responses.responses.contains_key("409"),
                "{path} must document stale expected_updated_at as 409 Conflict"
            );
        }

        let components = spec.components.expect("spec should have components");
        for schema_name in ["UpdateSourceConfiguration", "UpdateLogSource"] {
            let schema = components
                .schemas
                .get(schema_name)
                .unwrap_or_else(|| panic!("missing {schema_name} schema"));
            let schema = serde_json::to_value(schema).expect("serialize OpenAPI schema");
            assert!(
                schema.pointer("/properties/expected_updated_at").is_some(),
                "{schema_name} must expose expected_updated_at"
            );
        }
    }

    #[test]
    fn verify_source_config_credential_use_contract() {
        let spec = serde_json::to_value(build_openapi()).expect("serialize OpenAPI");
        for (path, method) in [
            ("/api/source-configurations", "post"),
            ("/api/source-configurations/{id}", "put"),
            ("/api/source-configurations/{id}/deploy", "post"),
            ("/api/source-configurations/deploy-all", "post"),
        ] {
            let description = spec["paths"][path][method]["responses"]["403"]["description"]
                .as_str()
                .unwrap_or_else(|| panic!("{method} {path} must document its 403 response"));
            assert!(
                description.contains("credentials:use"),
                "{method} {path} must document the credentials:use requirement"
            );
        }
    }

    /// NAN-2243 — the recon contract that keeps an agent's context intact.
    ///
    /// Both halves of this are spec-level facts a generated MCP client reads,
    /// and both regressed into a 371 KB tool result the last time they were
    /// only documented in prose:
    ///
    ///   1. `profile/surface` takes a `detail` parameter and its DEFAULT is the
    ///      bounded summary. A caller that says nothing must not get the matrix.
    ///   2. `census` and `huntable_surface` are not required on a save. They are
    ///      the deterministic halves; the agent authors neither, and requiring
    ///      them is what made it shuttle them back through its own context.
    #[test]
    fn verify_recon_surface_is_bounded_by_default_and_the_save_needs_no_echo() {
        let spec = serde_json::to_value(build_openapi()).expect("serialize OpenAPI");

        let parameters = spec["paths"]["/api/hunts/profile/surface"]["post"]["parameters"]
            .as_array()
            .expect("profile/surface must document its query parameters");
        let detail = parameters
            .iter()
            .find(|parameter| parameter["name"] == "detail")
            .expect("profile/surface must expose a `detail` parameter");
        assert_eq!(detail["in"], "query", "{detail}");
        assert_ne!(
            detail["required"], serde_json::json!(true),
            "`detail` must be optional — its default is the whole point: {detail}"
        );

        // The save's two deterministic halves are optional. `required` is either
        // absent entirely or names neither.
        let required = spec["components"]["schemas"]["SaveProfileRequest"]["required"].clone();
        let required: Vec<&str> = required
            .as_array()
            .map(|names| names.iter().filter_map(|n| n.as_str()).collect())
            .unwrap_or_default();
        for half in ["census", "huntable_surface"] {
            assert!(
                !required.contains(&half),
                "SaveProfileRequest must not require `{half}` — the server recomputes it.                  required = {required:?}"
            );
        }
        // And the judgement half it DOES author is still required, so an empty
        // body is not a valid profile.
        assert!(
            required.contains(&"fingerprint"),
            "SaveProfileRequest must still require the fingerprint: {required:?}"
        );
    }
}
