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
        (name = "system_health", description = "Durable system health lifecycles and external delivery"),
    ),
    components(schemas(ErrorResponse, ErrorDetail))
)]
pub struct ApiDoc;

/// Adds Bearer JWT and X-API-Key security schemes to the OpenAPI spec.
struct SecurityAddon;

impl Modify for SecurityAddon {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        if let Some(components) = openapi.components.as_mut() {
            #[cfg(feature = "enterprise")]
            components.add_security_scheme(
                "nano_main_service_identity",
                SecurityScheme::Http(HttpBuilder::new().scheme(HttpAuthScheme::Bearer)
                    .bearer_format("JWT").description(Some("Private mTLS connection and operation, tenant and body-bound platform JWT required")).build()),
            );
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
    let sub_docs = sub_docs();
    merge_sub_docs(&mut spec, sub_docs);
    finish_openapi(spec)
}

/// Every handler module's sub-doc, in merge order.
///
/// Split out of `build_openapi` so `verify_no_schema_name_collisions` can walk
/// the same list. Merging is `extend`, which silently OVERWRITES a duplicate
/// schema name with whichever sub-doc merges later — that is how
/// `/api/hunts/suppressions` came to be documented as returning SIEM-health's
/// `FindingSuppression` (NAN-2270). Nothing downstream can detect it: the spec
/// is internally consistent, just wrong.
#[cfg_attr(not(feature = "enterprise"), allow(unused_mut))]
fn sub_docs() -> Vec<utoipa::openapi::OpenApi> {
    // The vec is mutated below only on enterprise builds (to push meloD +
    // notebooks); open builds use it read-only.
    let mut sub_docs: Vec<utoipa::openapi::OpenApi> = vec![
        handlers::health::HealthApiDoc::openapi(),
        handlers::egress::EgressApiDoc::openapi(),
        handlers::capabilities::CapabilitiesApiDoc::openapi(),
        handlers::setup::SetupApiDoc::openapi(),
        handlers::auth::AuthApiDoc::openapi(),
        handlers::mfa::MfaApiDoc::openapi(),
        handlers::users::UsersApiDoc::openapi(),
        handlers::browser_telemetry::BrowserTelemetryApiDoc::openapi(),
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
        handlers::source_onboarding::SourceOnboardingApiDoc::openapi(),
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
        handlers::iceberg_export::IcebergExportApiDoc::openapi(),
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
        handlers::connector_feeds::ConnectorFeedsApiDoc::openapi(),
        handlers::ingest_tokens::IngestTokensApiDoc::openapi(),
        handlers::landing_sources::LandingSourcesApiDoc::openapi(),
        #[cfg(feature = "enterprise")]
        handlers::integrations::IntegrationsApiDoc::openapi(),
        handlers::upload::UploadApiDoc::openapi(),
        handlers::gdpr::GdprApiDoc::openapi(),
        handlers::ip_allowlist::IpAllowlistApiDoc::openapi(),
        handlers::onboarding::OnboardingApiDoc::openapi(),
        handlers::siem_health::SiemHealthApiDoc::openapi(),
        handlers::siem_health_suppressions::SiemHealthSuppressionsApiDoc::openapi(),
        handlers::system_health_events::SystemHealthEventsApiDoc::openapi(),
        handlers::observability_slos::ObservabilitySlosApiDoc::openapi(),
        handlers::observability_synthetics::ObservabilitySyntheticsApiDoc::openapi(),
        handlers::observability_metric_monitors::ObservabilityMetricMonitorsApiDoc::openapi(),
        handlers::system::SystemApiDoc::openapi(),
        handlers::vector_config_delivery::VectorConfigDeliveryApiDoc::openapi(),
    ];

    // Enterprise-only sub-docs. Their handler modules (`melod`, `notebooks`,
    // `risk`) and the `enterprise::*` types they reference are gated
    // behind the `enterprise` feature, so the registrations have to live
    // here too — open builds simply omit these endpoints from the spec.
    #[cfg(feature = "enterprise")]
    {
        // License / phone-home (NAN-1193): stripped from the open edition, so
        // the open spec omits the /api/license path entirely.
        sub_docs.push(handlers::license::LicenseApiDoc::openapi());
        sub_docs.extend(shared_sub_docs());
        // Phase 3.2 (NAN-744): cases + incidents lifted to enterprise.
        sub_docs.push(handlers::cases::CasesApiDoc::openapi());
        sub_docs.push(handlers::incidents::IncidentsApiDoc::openapi());
        sub_docs.push(handlers::notebooks::NotebooksApiDoc::openapi());
        sub_docs.push(handlers::melod::MelodApiDoc::openapi());
        sub_docs.push(handlers::risk::RiskApiDoc::openapi());
        sub_docs.push(handlers::risk_watchlists::RiskWatchlistsApiDoc::openapi());
        sub_docs.push(handlers::entity_context::EntityContextApiDoc::openapi());
        sub_docs.push(handlers::agent_enrichment::AgentEnrichmentApiDoc::openapi());
        sub_docs.push(handlers::custom_enrichment::CustomEnrichmentApiDoc::openapi());
        sub_docs.push(handlers::integration_generation::IntegrationGenerationApiDoc::openapi());
        // /api/enrichment/agent/lookup lives inside handlers::enrichment but
        // its handler + supporting types are cfg-gated for enterprise (Phase
        // 3.3); keep the doc alongside the handler.
        sub_docs.push(handlers::enrichment::EnrichmentAgentApiDoc::openapi());
        // OIDC / SSO — open-core split (NAN-745). Gated alongside the
        // handler module; the open spec omits these paths entirely.
        sub_docs.push(handlers::oidc::OidcApiDoc::openapi());
        // NAN-4152: public per-tenant demo claim (enterprise_shared).
        sub_docs.push(handlers::shared_demo_claim::SharedDemoClaimApiDoc::openapi());
        // Air-gapped bundle import (NAN-1201) — enterprise only.
        sub_docs.push(handlers::airgap::parsers::AirgapParsersApiDoc::openapi());
        sub_docs.push(handlers::airgap::enrichment::AirgapEnrichmentApiDoc::openapi());
        sub_docs.push(handlers::airgap::license::AirgapLicenseApiDoc::openapi());
        // Air-gapped rule + playbook bundle import (NAN-1220) — enterprise only.
        sub_docs.push(handlers::airgap::rules::AirgapRulesApiDoc::openapi());
        sub_docs.push(handlers::airgap::playbooks::AirgapPlaybooksApiDoc::openapi());
    }

    sub_docs
}

/// Shared handlers replace dedicated operations at the same URL. Keep this
/// inventory shared by both the combined and tenant-specific spec builders.
#[cfg(feature = "enterprise")]
fn shared_sub_docs() -> Vec<utoipa::openapi::OpenApi> {
    vec![
        nanosiem_enterprise::handlers::enterprise_shared_detections::EnterpriseSharedDetectionsApiDoc::openapi(),
        nanosiem_enterprise::handlers::enterprise_shared_alerts::EnterpriseSharedAlertsApiDoc::openapi(),
        nanosiem_enterprise::handlers::enterprise_shared_alert_triage::EnterpriseSharedAlertTriageApiDoc::openapi(),
        nanosiem_enterprise::handlers::enterprise_shared_app_shell::EnterpriseSharedAppShellApiDoc::openapi(),
        nanosiem_enterprise::handlers::enterprise_shared_dashboards::EnterpriseSharedDashboardsApiDoc::openapi(),
        nanosiem_enterprise::handlers::enterprise_shared_dashboard_panels::EnterpriseSharedDashboardPanelsApiDoc::openapi(),
        nanosiem_enterprise::handlers::enterprise_shared_reports::EnterpriseSharedReportsApiDoc::openapi(),
        nanosiem_enterprise::handlers::enterprise_shared_cases_notebooks::EnterpriseSharedCasesNotebooksApiDoc::openapi(),
        nanosiem_enterprise::handlers::enterprise_shared_observability::EnterpriseSharedObservabilityApiDoc::openapi(),
        nanosiem_enterprise::handlers::enterprise_shared_detection_dashboard::EnterpriseSharedDetectionDashboardApiDoc::openapi(),
        nanosiem_enterprise::handlers::enterprise_shared_detection_editor::EnterpriseSharedDetectionEditorApiDoc::openapi(),
        nanosiem_enterprise::handlers::enterprise_shared_mitre::EnterpriseSharedMitreApiDoc::openapi(),
        nanosiem_enterprise::handlers::enterprise_shared_rule_repositories::EnterpriseSharedRuleRepositoriesApiDoc::openapi(),
        nanosiem_enterprise::handlers::enterprise_shared_iam::EnterpriseSharedIamApiDoc::openapi(),
        nanosiem_enterprise::handlers::enterprise_shared_settings::EnterpriseSharedSettingsApiDoc::openapi(),
        nanosiem_enterprise::handlers::enterprise_shared_sources::EnterpriseSharedSourcesApiDoc::openapi(),
        nanosiem_enterprise::handlers::enterprise_shared_enrichment::EnterpriseSharedEnrichmentApiDoc::openapi(),
        nanosiem_enterprise::handlers::soar::SoarApiDoc::openapi(),
        nanosiem_enterprise::handlers::shared_soar_mail::SoarMailBridgeApiDoc::openapi(),
        // NAN-4369: the egress proxy's SOAR check (internal, helper bearer).
        nanosiem_enterprise::soar::egress::SoarEgressApiDoc::openapi(),
        nanosiem_enterprise::handlers::enterprise_shared_melod::EnterpriseSharedMelodApiDoc::openapi(),
        // NAN-4535: pivt SOAR flow drafting.
        nanosiem_enterprise::handlers::enterprise_shared_flow_draft::EnterpriseSharedFlowDraftApiDoc::openapi(),
        // NAN-4653: pivt edit-session turns.
        nanosiem_enterprise::handlers::enterprise_shared_edit_session::EnterpriseSharedEditSessionApiDoc::openapi(),
        nanosiem_enterprise::handlers::enterprise_shared_cases_extras::EnterpriseSharedCasesExtrasApiDoc::openapi(),
        nanosiem_enterprise::handlers::enterprise_shared_hunting::EnterpriseSharedHuntingApiDoc::openapi(),
        nanosiem_enterprise::handlers::enterprise_shared_playbooks::EnterpriseSharedPlaybooksApiDoc::openapi(),
        nanosiem_enterprise::handlers::enterprise_shared_tuning::EnterpriseSharedTuningApiDoc::openapi(),
        nanosiem_enterprise::handlers::enterprise_shared_marketplace::EnterpriseSharedMarketplaceApiDoc::openapi(),
        nanosiem_enterprise::handlers::hosted_collectors::HostedCollectorsApiDoc::openapi(),
        nanosiem_enterprise::handlers::enterprise_shared_pull_sources::EnterpriseSharedPullSourcesApiDoc::openapi(),
        nanosiem_enterprise::handlers::enterprise_shared_rules_alerts_remainder::EnterpriseSharedRulesAlertsRemainderApiDoc::openapi(),
        nanosiem_enterprise::handlers::shared_automation_keys::SharedAutomationKeysApiDoc::openapi(),
        nanosiem_enterprise::handlers::enterprise_shared_oidc_settings::EnterpriseSharedOidcSettingsApiDoc::openapi(),
        nanosiem_enterprise::handlers::enterprise_shared_queues::EnterpriseSharedQueuesApiDoc::openapi(),
        nanosiem_enterprise::handlers::enterprise_shared_exports::EnterpriseSharedExportsApiDoc::openapi(),
        nanosiem_enterprise::handlers::enterprise_shared_search_extras::EnterpriseSharedSearchExtrasApiDoc::openapi(),
        nanosiem_enterprise::handlers::enterprise_shared_iam_extras::EnterpriseSharedIamExtrasApiDoc::openapi(),
        nanosiem_enterprise::handlers::shared_r2_owner_observation::R2OwnerObservationApiDoc::openapi(),
        // NAN-4152: public web path alias resolver (enterprise_shared only).
        nanosiem_enterprise::handlers::shared_tenant_path_alias::SharedTenantPathAliasPublicApiDoc::openapi(),
    ]
}

fn build_shared_openapi() -> utoipa::openapi::OpenApi {
    let mut spec = ApiDoc::openapi();
    #[cfg(feature = "enterprise")]
    merge_sub_docs(&mut spec, shared_sub_docs());
    // First-operation-wins now preserves the tenant handler's wire contract.
    // Unported legacy paths are removed by the live shared route fences below.
    merge_sub_docs(&mut spec, sub_docs());
    let mut spec = finish_openapi(spec);
    #[cfg(feature = "enterprise")]
    for (path, item) in &mut spec.paths.paths {
        for (method, operation) in [(axum::http::Method::GET, &mut item.get), (axum::http::Method::POST, &mut item.post)] {
            if nanosiem_enterprise::handlers::enterprise_shared_agent_features::legacy_cell_route(&method, path) {
                if let Some(operation) = operation {
                    let note = "Session-only heavy read. Automation requires reason, narrow entities and a bounded window at POST /api/agent/features; use lake_sql stamps for discovery. Legacy calls are refused even if reason is supplied.";
                    operation.description = Some(format!("{}\n\n{note}", operation.description.as_deref().unwrap_or_default()));
                    operation.responses.responses.insert("400".into(), utoipa::openapi::response::Response::new(note).into());
                }
            }
        }
    }
    spec
}

fn merge_sub_docs(spec: &mut utoipa::openapi::OpenApi, sub_docs: Vec<utoipa::openapi::OpenApi>) {
    for sub in sub_docs {
        // Merge paths per OPERATION, first wins. A whole-item `extend` let a
        // later doc that documents only `GET /x/{id}` erase the earlier doc's
        // `PUT /x/{id}` (NAN-2361: the hosted-shared docs share many
        // paths with the dedicated handlers they replace in shared mode).
        for (path, item) in sub.paths.paths {
            match spec.paths.paths.get_mut(&path) {
                None => {
                    spec.paths.paths.insert(path, item);
                }
                Some(existing) => {
                    macro_rules! keep_first {
                        ($($m:ident),*) => {$(
                            if existing.$m.is_none() { existing.$m = item.$m; }
                        )*};
                    }
                    keep_first!(get, put, post, delete, options, head, patch, trace);
                }
            }
        }

        // Merge components (schemas, etc.)
        if let Some(sub_components) = sub.components {
            if let Some(ref mut components) = spec.components {
                components.schemas.extend(sub_components.schemas);
            } else {
                spec.components = Some(sub_components);
            }
        }
    }
}

fn finish_openapi(mut spec: utoipa::openapi::OpenApi) -> utoipa::openapi::OpenApi {

    // Merge search service endpoints (nanosiem-search, port 3002)
    let search_spec = nanosiem_search::openapi::build_openapi();
    spec.paths.paths.extend(search_spec.paths.paths);
    if let Some(search_components) = search_spec.components {
        if let Some(ref mut components) = spec.components {
            components.schemas.extend(search_components.schemas);
            for (name, scheme) in search_components.security_schemes {
                components.security_schemes.entry(name).or_insert(scheme);
            }
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

/// Shared root docs disclose only the static location of tenant documentation.
/// Like tenant docs assets, this response is independent of credentials.
/// Install outside the API auth layers, only on a shared deployment.
pub async fn shared_root_docs_fence(
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    use axum::response::IntoResponse;
    let path = request.uri().path();
    if path == "/api-docs/openapi.json" || path == "/swagger-ui" || path.starts_with("/swagger-ui/")
    {
        tracing::warn!(path, "enterprise-shared root documentation unavailable");
        return (
            axum::http::StatusCode::NOT_FOUND,
            axum::Json(serde_json::json!({
                "error": "route_not_available",
                "message": "Use /t/<tenant>/swagger-ui/ for hosted tenant API documentation",
            })),
        )
            .into_response();
    }
    next.run(request).await
}

/// Operations whose own annotation declares human-session security only.
///
/// Read from handler docs whose `security(...)` is maintained per operation and
/// pinned by contract tests (SOAR: settings PUT and approval decisions refuse
/// API keys). Many older handlers declare `bearer_auth` alone while accepting
/// keys, so this is deliberately not applied to every merged document.
fn human_session_only_operations() -> std::collections::BTreeSet<(String, &'static str)> {
    #[allow(unused_mut)]
    let mut docs: Vec<utoipa::openapi::OpenApi> = Vec::new();
    #[cfg(feature = "enterprise")]
    docs.push(nanosiem_enterprise::handlers::soar::SoarApiDoc::openapi());
    let mut found = std::collections::BTreeSet::new();
    for doc in docs {
        let doc = serde_json::to_value(doc).expect("serialize OpenAPI");
        let Some(paths) = doc["paths"].as_object() else { continue };
        for (path, item) in paths {
            for method in ["get", "post", "put", "patch", "delete", "head", "options", "trace"] {
                let Some(security) = item[method]["security"].as_array() else { continue };
                if !security.iter().any(|scheme| scheme.get("api_key").is_some()) {
                    found.insert((path.clone(), method));
                }
            }
        }
    }
    found
}

/// Public, static tenant API contract. No tenant records or credentials are
/// read to render documentation. Runtime auth still decides permissions.
fn shared_openapi_template() -> &'static serde_json::Value {
    static SPEC: std::sync::OnceLock<serde_json::Value> = std::sync::OnceLock::new();
    SPEC.get_or_init(|| {
        use axum::http::Method;
        let mut spec = serde_json::to_value(build_shared_openapi()).expect("serialize OpenAPI");
        let human_only = human_session_only_operations();
        let paths = spec["paths"].as_object_mut().expect("OpenAPI paths");
        paths.retain(|path, item| {
            if !path.starts_with("/api/") { return false; }
            let probe = path.split('/').map(|part| {
                if part.starts_with('{') && part.ends_with('}') {
                    match part {
                        "{page}" => "0",
                        "{slug}" => "example",
                        _ => "00000000-0000-4000-8000-000000000001",
                    }
                } else { part }
            }).collect::<Vec<_>>().join("/");
            let ops = item.as_object_mut().expect("OpenAPI path item");
            ops.remove("servers");
            for (name, method) in [("get", Method::GET), ("post", Method::POST),
                ("put", Method::PUT), ("patch", Method::PATCH), ("delete", Method::DELETE),
                ("head", Method::HEAD), ("options", Method::OPTIONS), ("trace", Method::TRACE)] {
                let allowed = if path.starts_with("/api/search") && ![
                    "/api/search/history", "/api/search/share", "/api/search/shared",
                    "/api/search/explanation", "/api/search/saved",
                ].iter().any(|base| path == base || path.starts_with(&format!("{base}/"))) {
                    nanosiem_search::openapi::shared_documented_operation(&method, &probe)
                } else {
                    crate::middleware::auth::shared_documented_operation(&method, &probe)
                };
                // This document offers only X-API-Key. An operation that refuses
                // keys (human session only) cannot be called from it, and
                // advertising it with api_key would be false (NAN-4375).
                if !allowed || human_only.contains(&(path.clone(), name)) { ops.remove(name); }
                else if let Some(operation) = ops.get_mut(name) {
                    operation.as_object_mut().expect("OpenAPI operation").remove("servers");
                    operation["security"] = serde_json::json!([{ "api_key": [] }]);
                }
            }
            ["get", "post", "put", "patch", "delete", "head", "options", "trace"]
                .iter().any(|name| ops.contains_key(*name))
        });
        // Keep only schemas reachable from the tenant contract. Platform-only
        // endpoints and their model inventory must not leak into this document.
        fn references(value: &serde_json::Value, names: &mut std::collections::BTreeSet<String>) {
            match value {
                serde_json::Value::Object(map) => {
                    if let Some(reference) = map.get("$ref").and_then(|v| v.as_str()) {
                        if let Some(name) = reference.strip_prefix("#/components/schemas/") {
                            names.insert(name.to_owned());
                        }
                    }
                    for value in map.values() { references(value, names); }
                }
                serde_json::Value::Array(values) => for value in values { references(value, names); },
                _ => {}
            }
        }
        let mut needed = std::collections::BTreeSet::new();
        references(&spec["paths"], &mut needed);
        let schemas = spec["components"]["schemas"].as_object_mut().expect("OpenAPI schemas");
        loop {
            let count = needed.len();
            for name in needed.clone() {
                if let Some(schema) = schemas.get(&name) { references(schema, &mut needed); }
            }
            if count == needed.len() { break; }
        }
        schemas.retain(|name, _| needed.contains(name));
        spec["components"]["securitySchemes"].as_object_mut().expect("security schemes")
            .retain(|name, _| name == "api_key");
        spec["security"] = serde_json::json!([{ "api_key": [] }]);
        spec["info"]["description"] = serde_json::json!(
            "Tenant API. Use Authorize to paste an X-API-Key for this tenant. Browser sessions are not used by Try it out. Existing API permissions and tenant isolation apply. Authenticated requests to endpoints unavailable for hosted tenants return HTTP 404 with route_not_available and the message: This endpoint is not available for hosted tenants."
        );
        spec.as_object_mut().unwrap().remove("tags");
        spec
    })
}

fn tenant_openapi(slug: &str) -> serde_json::Value {
    let mut spec = shared_openapi_template().clone();
    spec["servers"] = serde_json::json!([{ "url": format!("/t/{slug}") }]);
    spec
}

/// Tenant docs are auth-independent static assets; only explicit API
/// credentials can execute requests, through the tenant path/auth fence.
pub fn tenant_swagger_router() -> axum::Router {
    use axum::{
        extract::Path,
        http::{header, StatusCode},
        response::{IntoResponse, Redirect, Response},
        routing::get,
    };
    use nanosiem_api_lib::tenant_path::canonical_slug;
    async fn spec(Path(slug): Path<String>) -> Response {
        if !canonical_slug(&slug) {
            return StatusCode::NOT_FOUND.into_response();
        }
        axum::Json(tenant_openapi(&slug)).into_response()
    }
    async fn redirect(Path(slug): Path<String>) -> Response {
        if !canonical_slug(&slug) {
            return StatusCode::NOT_FOUND.into_response();
        }
        Redirect::temporary(&format!("/t/{slug}/swagger-ui/")).into_response()
    }
    async fn asset(slug: String, asset: String) -> Response {
        if !canonical_slug(&slug) {
            return StatusCode::NOT_FOUND.into_response();
        }
        if asset == "swagger-initializer.js" {
            return (
                [(header::CONTENT_TYPE, "application/javascript")],
                include_str!("tenant_swagger.js"),
            )
                .into_response();
        }
        match utoipa_swagger_ui::serve(
            &asset,
            std::sync::Arc::new(utoipa_swagger_ui::Config::default()),
        ) {
            Ok(Some(file)) => (
                [(header::CONTENT_TYPE, file.content_type)],
                file.bytes.into_owned(),
            )
                .into_response(),
            Ok(None) => StatusCode::NOT_FOUND.into_response(),
            Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
        }
    }
    axum::Router::new()
        .route("/t/{slug}/api-docs/openapi.json", get(spec))
        .route("/t/{slug}/swagger-ui", get(redirect))
        .route("/t/{slug}/swagger-ui/", get(|Path(slug): Path<String>| asset(slug, String::new())))
        .route("/t/{slug}/swagger-ui/{*asset}", get(|Path((slug, file)): Path<(String, String)>| asset(slug, file)))
        .layer(axum::middleware::map_response(|mut response: Response| async move {
            response.headers_mut().insert(header::CACHE_CONTROL, "no-store".parse().unwrap());
            response.headers_mut().insert(header::CONTENT_SECURITY_POLICY,
                "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; object-src 'none'".parse().unwrap());
            response.headers_mut().insert(header::X_CONTENT_TYPE_OPTIONS, "nosniff".parse().unwrap());
            response
        }))
}

/// True for the API paths whose response shapes cross the desktop's typed
/// hunting/playbook boundary.
///
/// Hunts remain a subtree; the library adds only its repository read and the
/// one repository action the desktop exposes. Keeping the repository's edit,
/// catalog and per-file import surfaces out of this contract avoids turning a
/// focused drift gate into a second copy of the full OpenAPI document.
fn is_desktop_wire_path(path: &str) -> bool {
    path.starts_with("/api/hunts")
        || matches!(
            path,
            "/api/playbook-repositories"
                | "/api/playbook-repositories/{id}/sync-and-import"
        )
}

/// Schemas included even though no selected desktop path references them directly.
///
/// Both are the READ shapes behind columns the models declare as untyped
/// `serde_json::Value`, so the `$ref` walk alone can never reach them:
///
/// * `Hunt.steps` serializes `playbooks.parsed_steps`, which the playbook
///   parser writes as a `ParsedStepTree`.
/// * `HuntProfile.fingerprint` serializes the stored org fingerprint, which
///   recon writes as an `OrgFingerprint` (NOT `ProfileFingerprint` — that is
///   the agent's submission shape and never comes back on a read).
///
/// They are pulled in explicitly so the desktop can type those fields against
/// the shapes the server actually stores and serves.
const DESKTOP_WIRE_EXTRA_SCHEMAS: &[&str] = &["ParsedStepTree", "OrgFingerprint"];

/// The scoped OpenAPI document the desktop's generated TypeScript wire types
/// are built from (NAN-2263, NAN-2312): every `/api/hunts` path plus the
/// repository collection and sync/import action,
/// with the schemas transitively reachable from them.
///
/// # Why a scoped spec rather than the whole thing
///
/// * The full spec differs between the open and enterprise editions (meloD,
///   notebooks, cases…), so a committed copy of it could never be asserted
///   from both test matrices. The hunts surface is registered ungated and its
///   playbook models live in `nanosiem-core`, so this seam is identical in both —
///   which is what lets the drift test run under either feature set.
/// * The committed `docs/api/openapi.json` is refreshed on a different cadence
///   and for a different consumer (the docs RAG); coupling the desktop's
///   compile-time guarantee to it would make that refresh a breaking change.
///
/// Paths and schemas are emitted through `BTreeMap` so the output is sorted
/// and byte-stable regardless of `serde_json`'s `preserve_order` feature.
pub fn desktop_wire_spec() -> serde_json::Value {
    use std::collections::{BTreeMap, BTreeSet};

    fn collect_refs(value: &serde_json::Value, into: &mut BTreeSet<String>) {
        match value {
            serde_json::Value::Object(map) => {
                if let Some(serde_json::Value::String(reference)) = map.get("$ref") {
                    if let Some(name) = reference.strip_prefix("#/components/schemas/") {
                        into.insert(name.to_string());
                    }
                }
                for nested in map.values() {
                    collect_refs(nested, into);
                }
            }
            serde_json::Value::Array(items) => {
                for item in items {
                    collect_refs(item, into);
                }
            }
            _ => {}
        }
    }

    let full = serde_json::to_value(build_openapi()).expect("serialize OpenAPI spec");
    let all_schemas = full["components"]["schemas"]
        .as_object()
        .expect("spec has components.schemas");

    let paths: BTreeMap<String, serde_json::Value> = full["paths"]
        .as_object()
        .expect("spec has paths")
        .iter()
        .filter(|(path, _)| is_desktop_wire_path(path))
        .map(|(path, item)| (path.clone(), item.clone()))
        .collect();

    let mut needed: BTreeSet<String> = DESKTOP_WIRE_EXTRA_SCHEMAS
        .iter()
        .map(|name| (*name).to_string())
        .collect();
    for item in paths.values() {
        collect_refs(item, &mut needed);
    }

    // Transitive closure over `$ref` until no schema pulls in another.
    let mut schemas: BTreeMap<String, serde_json::Value> = BTreeMap::new();
    loop {
        let pending: Vec<String> = needed
            .iter()
            .filter(|name| !schemas.contains_key(*name))
            .cloned()
            .collect();
        if pending.is_empty() {
            break;
        }
        for name in pending {
            let schema = all_schemas
                .get(&name)
                .unwrap_or_else(|| panic!("desktop wire spec references unknown schema {name}"))
                .clone();
            collect_refs(&schema, &mut needed);
            schemas.insert(name, schema);
        }
    }

    serde_json::json!({
        "openapi": full["openapi"],
        "info": {
            "title": "nano desktop hunting + playbook wire seam",
            "description": "GENERATED — do not edit. The API paths used by nano-desktop's Hunting and Playbook Library surfaces, plus transitively referenced schemas. Regenerate with: cargo run -p nanosiem-api --bin export_openapi -- --desktop-wire > nano-desktop/openapi/hunts-wire.json",
            "version": full["info"]["version"],
        },
        "paths": paths,
        "components": { "schemas": schemas },
    })
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "enterprise")]
    #[test]
    fn legacy_heavy_reads_document_guarded_automation_requirement() {
        let spec = serde_json::to_value(build_shared_openapi()).unwrap();
        for (path, method) in [
            ("/api/prevalence/hash/{hash}", "get"),
            ("/api/prevalence/domain/{domain}", "get"),
            ("/api/prevalence/new", "get"),
            ("/api/prevalence/explorer", "get"),
            ("/api/entities/{entity_type}/{entity_value}/context", "get"),
            ("/api/identity/resolve", "get"),
            ("/api/lookup-tables/query", "post"),
            ("/api/threat-intel/indicator-lookup", "post"),
        ] {
            let operation = &spec["paths"][path][method];
            assert!(operation["description"].as_str().unwrap().contains("POST /api/agent/features"), "{path}");
            assert!(operation["responses"]["400"]["description"].as_str().unwrap().contains("reason"), "{path}");
        }
    }

    #[test]
    fn bulk_prevalence_documents_absolute_bounds_and_echo() {
        #[cfg(not(feature="enterprise"))]
        let spec = serde_json::to_value(build_openapi()).unwrap();
        #[cfg(feature="enterprise")]
        let spec = serde_json::to_value(build_shared_openapi()).unwrap();
        let operation = &spec["paths"]["/api/prevalence/bulk"]["post"];
        let request = operation["requestBody"]["content"]["application/json"]["schema"]["$ref"].as_str().unwrap();
        let response = operation["responses"]["200"]["content"]["application/json"]["schema"]["$ref"].as_str().unwrap();
        let schema = |reference: &str| &spec["components"]["schemas"][reference.rsplit('/').next().unwrap()];
        for field in ["start", "end", "window"] {
            assert!(schema(request)["properties"].get(field).is_some(), "{field}");
        }
        let response_schema = schema(response);
        #[cfg(feature="enterprise")]
        let response_schema = {
            let variants = response_schema.get("oneOf").or_else(|| response_schema.get("anyOf")).unwrap_or_else(|| panic!("missing guarded response {response}: {response_schema}")).as_array().unwrap();
            assert!(variants.iter().any(|v| v["$ref"].as_str().is_some_and(|r| r.ends_with("/FeatureResponse"))));
            let session = variants.iter().find_map(|v| v["$ref"].as_str().filter(|r| r.ends_with("/EnterpriseSharedBulkPrevalenceResponse"))).unwrap();
            assert!(operation["responses"].get("429").is_some());
            assert!(schema(request)["properties"].get("reason").is_some());
            schema(session)
        };
        for field in ["requested_window", "effective_window", "note"] { assert!(response_schema["properties"].get(field).is_some()); }
        assert!(spec["components"]["schemas"]["ExactPrevalenceWindow"]["properties"].get("start").is_some());
    }

    #[test]
    fn user_visible_openapi_contains_no_internal_ticket_ids() {
        fn walk(value: &serde_json::Value, path: &str, pattern: &regex::Regex, violations: &mut Vec<String>) {
            match value {
                serde_json::Value::String(text) => {
                    if pattern.is_match(text) { violations.push(path.to_owned()); }
                }
                serde_json::Value::Array(values) => {
                    for (index, value) in values.iter().enumerate() {
                        walk(value, &format!("{path}/{index}"), pattern, violations);
                    }
                }
                serde_json::Value::Object(values) => {
                    for (key, value) in values {
                        walk(value, &format!("{path}/{key}"), pattern, violations);
                    }
                }
                _ => {}
            }
        }
        let pattern = regex::Regex::new(r"\b(?:NAN|FOR)-?\d+\b").unwrap();
        let mut violations = Vec::new();
        walk(&serde_json::to_value(super::build_openapi()).unwrap(), "", &pattern, &mut violations);
        assert!(violations.is_empty(), "internal ticket references in OpenAPI at:\n{}", violations.join("\n"));
    }

    #[test]
    fn iceberg_export_contract_is_admin_bearer_and_write_only() {
        let check=|spec:serde_json::Value| {
        let path=&spec["paths"]["/api/settings/iceberg-export"];
        for method in ["get","put"] {
            assert!(path[method]["security"].as_array().unwrap().iter().any(|s|s.get("bearer_auth").is_some()));
            assert!(path[method]["responses"]["403"].is_object());
        }
        let schemas=&spec["components"]["schemas"];
        assert_eq!(schemas["UpdateExportSettings"]["properties"]["credentials"]["writeOnly"],true);
        let response=schemas["ExportSettings"]["properties"].as_object().unwrap();
        for secret in ["credentials","catalog_credential","access_key_id","secret_access_key","session_token","credentials_encrypted","credentials_nonce"] { assert!(!response.contains_key(secret)); }
        assert!(schemas["CustomerExportConfig"].is_object());
        assert!(schemas["CatalogAuthentication"].is_object());
        };
        check(serde_json::to_value(super::build_openapi()).unwrap());
        #[cfg(feature="enterprise")]
        check(serde_json::to_value(super::build_shared_openapi()).unwrap());
    }

    /// NAN-3652: API descriptions say "HEC", never the vendor name; only the
    /// HEC wire literals (`Authorization: Splunk`, `splunk_hec*`) may carry it.
    #[test]
    fn openapi_descriptions_do_not_name_a_vendor() {
        let check = |spec: serde_json::Value| {
            let text = serde_json::to_string(&spec).unwrap();
            let mentions = nanosiem_core::branding::vendor_name_mentions(&text);
            assert!(mentions.is_empty(), "OpenAPI text names a vendor: {mentions:#?}");
        };
        check(serde_json::to_value(super::build_openapi()).unwrap());
        #[cfg(feature = "enterprise")]
        check(serde_json::to_value(super::build_shared_openapi()).unwrap());
    }

    /// NAN-4282: API prose (descriptions, summaries, titles) never names the
    /// internal code name "lean"; identifiers (paths, operation ids, enum
    /// values, `lean_*` fields) are not prose and stay.
    #[test]
    fn openapi_prose_does_not_use_the_internal_code_name() {
        fn walk(value: &serde_json::Value, path: &str, found: &mut Vec<String>) {
            match value {
                serde_json::Value::Object(map) => {
                    for (key, value) in map {
                        let here = format!("{path}/{key}");
                        match (key.as_str(), value) {
                            ("description" | "summary" | "title", serde_json::Value::String(text)) => {
                                for mention in nanosiem_core::branding::code_name_mentions(text) {
                                    found.push(format!("{here}: {mention}"));
                                }
                            }
                            _ => walk(value, &here, found),
                        }
                    }
                }
                serde_json::Value::Array(values) => {
                    for (index, value) in values.iter().enumerate() { walk(value, &format!("{path}/{index}"), found); }
                }
                _ => {}
            }
        }
        let check = |spec: serde_json::Value| {
            let mut found = Vec::new();
            walk(&spec, "", &mut found);
            assert!(found.is_empty(), "OpenAPI prose uses the internal code name:\n{}", found.join("\n"));
        };
        check(serde_json::to_value(super::build_openapi()).unwrap());
        #[cfg(feature = "enterprise")]
        check(super::shared_openapi_template().clone());
    }

    use super::*;
    use utoipa::openapi::path::HttpMethod;

    #[tokio::test]
    async fn shared_root_docs_return_neutral_404_and_tenant_docs_stay_open() {
        use axum::{
            body::{to_bytes, Body},
            http::{Request, StatusCode},
            Router,
        };
        use tower::ServiceExt;
        let app = nanosiem_api_lib::tenant_path::scoped_api_router(tenant_swagger_router())
            .layer(axum::middleware::from_fn(shared_root_docs_fence));
        for path in [
            "/api-docs/openapi.json",
            "/swagger-ui",
            "/swagger-ui/",
            "/swagger-ui/swagger-ui-bundle.js",
        ] {
            for credential in [
                None,
                Some(("x-api-key", "local-fixture")),
                Some(("authorization", "Bearer local-fixture")),
            ] {
                let mut request = Request::builder().uri(path);
                if let Some((name, value)) = credential {
                    request = request.header(name, value);
                }
                let response = app
                    .clone()
                    .oneshot(request.body(Body::empty()).unwrap())
                    .await
                    .unwrap();
                assert_eq!(response.status(), StatusCode::NOT_FOUND, "{path}");
                assert!(!response.headers().contains_key("retry-after"));
                let body: serde_json::Value =
                    serde_json::from_slice(&to_bytes(response.into_body(), 4096).await.unwrap())
                        .unwrap();
                assert_eq!(body["error"], "route_not_available");
                assert_eq!(
                    body["message"],
                    "Use /t/<tenant>/swagger-ui/ for hosted tenant API documentation"
                );
                for word in ["isolation", "scoped", "not yet"] {
                    assert!(!body.to_string().contains(word));
                }
            }
        }
        for path in ["/t/acme/swagger-ui/", "/t/acme/api-docs/openapi.json"] {
            let response = app
                .clone()
                .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK, "{path}");
        }
        // The dedicated/open-core root docs router remains available.
        let dedicated: Router = Router::new().merge(swagger_ui());
        for path in ["/api-docs/openapi.json", "/swagger-ui/"] {
            let response = dedicated
                .clone()
                .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK, "{path}");
        }
    }

    // Tenant API docs are mounted only for the hosted shared profile.
    #[cfg(feature = "enterprise")]
    #[tokio::test]
    async fn tenant_swagger_is_real_ui_and_spec_targets_its_tenant() {
        use axum::{
            body::{to_bytes, Body},
            http::{Request, StatusCode},
        };
        use tower::ServiceExt;
        let app = nanosiem_api_lib::tenant_path::scoped_api_router(tenant_swagger_router());
        for slug in ["acme-soc", "other-soc"] {
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .uri(format!("/t/{slug}/swagger-ui/"))
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            assert!(response.headers()["content-security-policy"]
                .to_str()
                .unwrap()
                .contains("script-src 'self'"));
            let html = String::from_utf8(
                to_bytes(response.into_body(), usize::MAX)
                    .await
                    .unwrap()
                    .to_vec(),
            )
            .unwrap();
            assert!(html.contains("Swagger UI"));
            assert!(html.contains("swagger-ui-bundle.js"));
            assert!(!html.contains("/src/main.tsx"));
            for asset in [
                "swagger-ui-bundle.js",
                "swagger-ui.css",
                "swagger-initializer.js",
            ] {
                let response = app
                    .clone()
                    .oneshot(
                        Request::builder()
                            .uri(format!("/t/{slug}/swagger-ui/{asset}"))
                            .body(Body::empty())
                            .unwrap(),
                    )
                    .await
                    .unwrap();
                assert_eq!(response.status(), StatusCode::OK, "{asset}");
                assert!(
                    to_bytes(response.into_body(), usize::MAX)
                        .await
                        .unwrap()
                        .len()
                        > 100
                );
            }
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .uri(format!("/t/{slug}/api-docs/openapi.json"))
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            let spec: serde_json::Value =
                serde_json::from_slice(&to_bytes(response.into_body(), usize::MAX).await.unwrap())
                    .unwrap();
            assert_eq!(
                spec["servers"],
                serde_json::json!([{ "url": format!("/t/{slug}") }])
            );
            assert!(spec["paths"]["/api/search"]["post"].is_object());
            #[cfg(feature = "enterprise")]
            assert_eq!(
                spec["paths"]["/api/rules"]["post"]["requestBody"]["content"]["application/json"]["schema"]["$ref"],
                "#/components/schemas/CreateTenantDetectionRequest"
            );
            for path in [
                "/api/internal/vector-config/{id}",
                "/api/platform/tenants",
                "/api/airgap/license/import",
                "/api/search/sql",
                "/api/search/admin/stats",
            ] {
                assert!(spec["paths"].get(path).is_none(), "{path}");
            }
            assert!(spec["paths"]["/api/settings/tier"].get("put").is_none());
            assert_eq!(
                spec["components"]["securitySchemes"]
                    .as_object()
                    .unwrap()
                    .len(),
                1
            );
            assert_eq!(
                spec["components"]["securitySchemes"]["api_key"]["name"],
                "X-API-Key"
            );
        }
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/t/%61cme/api-docs/openapi.json")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[cfg(feature = "enterprise")]
    #[test]
    fn tenant_collector_contract_includes_every_lifecycle_operation() {
        let spec = tenant_openapi("buddytenant");
        for (path, method) in [
            ("/api/marketplace/collectors", "get"),
            ("/api/marketplace/collectors/{slug}", "get"),
            ("/api/marketplace/collectors/{slug}", "put"),
            ("/api/marketplace/collectors/{slug}", "delete"),
            ("/api/marketplace/collectors/{slug}/install", "post"),
            ("/api/marketplace/collectors/{slug}/feeds/{feed_id}/reset-checkpoint", "post"),
            ("/api/marketplace/collectors/{slug}/feeds/{feed_id}/rotate-credential", "post"),
            ("/api/marketplace/collectors/{slug}/credentials", "put"),
            ("/api/marketplace/collectors/{slug}/components", "get"),
            ("/api/marketplace/collectors/{slug}/components/{component}", "put"),
            ("/api/marketplace/collectors/{slug}/components/{component}", "delete"),
        ] {
            let operation = &spec["paths"][path][method];
            assert!(operation.is_object(), "missing tenant collector {method} {path}");
            assert_eq!(operation["security"], serde_json::json!([{ "api_key": [] }]));
        }
        assert_eq!(
            spec["paths"]["/api/marketplace/collectors/{slug}/install"]["post"]
                ["requestBody"]["content"]["application/json"]["schema"]["$ref"],
            "#/components/schemas/InstallInput"
        );
        assert_eq!(
            spec["paths"]["/api/marketplace/collectors/{slug}/feeds/{feed_id}/reset-checkpoint"]["post"]
                ["requestBody"]["content"]["application/json"]["schema"]["$ref"],
            "#/components/schemas/ResetCheckpointInput"
        );
    }

    #[cfg(feature = "enterprise")]
    #[test]
    fn tenant_pull_source_contract_includes_every_operation() {
        let spec = tenant_openapi("buddytenant");
        for (path, method) in [
            ("/api/pull-sources", "get"),
            ("/api/pull-sources", "post"),
            ("/api/pull-sources/setup/aws", "get"),
            ("/api/pull-sources/setup/gcp", "get"),
            ("/api/pull-sources/{id}", "get"),
            ("/api/pull-sources/{id}", "delete"),
            ("/api/pull-sources/{id}", "patch"),
            ("/api/pull-sources/{id}/pause", "post"),
            ("/api/pull-sources/{id}/resume", "post"),
            ("/api/pull-sources/{id}/retry", "post"),
        ] {
            let operation = &spec["paths"][path][method];
            assert!(operation.is_object(), "missing tenant pull-source {method} {path}");
            assert_eq!(operation["security"], serde_json::json!([{ "api_key": [] }]));
        }
        assert_eq!(
            spec["paths"]["/api/pull-sources"]["post"]["requestBody"]["content"]["application/json"]
                ["schema"]["$ref"],
            "#/components/schemas/CreatePullSourceRequest"
        );
        assert_eq!(
            spec["paths"]["/api/pull-sources/{id}"]["patch"]["requestBody"]["content"]["application/json"]
                ["schema"]["$ref"],
            "#/components/schemas/UpdatePullSourceRequest"
        );
    }

    #[cfg(feature = "enterprise")]
    #[test]
    fn shared_repository_sync_accepted_contract() {
        let spec = serde_json::to_value(build_openapi()).unwrap();
        for kind in ["rule", "parser", "playbook"] {
            let path = format!("/api/{kind}-repositories/{{id}}/sync");
            assert!(spec["paths"][&path]["post"]["responses"].get("202").is_some(), "{path}");
        }
        let schema = &spec["components"]["schemas"]["SyncAccepted"];
        for field in ["sync_started_at", "sync_lease_expires_at", "status"] {
            assert!(schema["required"].as_array().unwrap().iter().any(|value| value == field));
        }
    }

    #[cfg(feature = "enterprise")]
    #[test]
    fn platform_repository_sync_accepted_contract() {
        let spec = serde_json::to_value(build_openapi()).unwrap();
        let responses = &spec["paths"]["/api/marketplace/repos/{id}/sync"]["post"]["responses"];
        assert!(responses.get("200").is_some());
        assert!(responses.get("202").is_some());
        assert!(responses["429"]["headers"].get("Retry-After").is_some());
        let schema = &spec["components"]["schemas"]["SyncNowAccepted"];
        for field in ["request_id", "repository_id", "managed_by_platform", "status"] {
            assert!(schema["required"].as_array().unwrap().iter().any(|value| value == field));
        }
    }

    #[cfg(feature = "enterprise")]
    #[test]
    fn marketplace_inventory_contract() {
        let spec = serde_json::to_value(build_openapi()).unwrap();
        for (path, method) in [
            ("/api/marketplace/items", "get"),
            ("/api/marketplace/items/{id}", "get"),
            ("/api/marketplace/items/{id}/toggle", "post"),
        ] {
            let op = &spec["paths"][path][method];
            assert!(op["security"].is_array(), "{path}");
            assert!(op["responses"].get("200").is_some());
            assert!(op["responses"].get("403").is_some());
        }
        for (path, method) in [
            ("/api/marketplace/items/{feed_id}/checkout", "get"),
            ("/api/marketplace/items/{feed_id}/checkout", "post"),
            ("/api/platform/feeds", "get"),
            ("/api/platform/feeds/{feed_id}/tenants", "get"),
            ("/api/platform/feeds/{feed_id}/commands", "post"),
        ] {
            let op = &spec["paths"][path][method];
            assert!(op["security"].is_array(), "{path}");
            assert!(op["responses"].get("200").is_some());
            assert!(op["responses"].get("403").is_some());
        }
        assert_eq!(spec["components"]["schemas"]["CheckoutRequest"]["additionalProperties"], false);
        assert_eq!(spec["components"]["schemas"]["FeedCommand"]["additionalProperties"], false);
        let toggle = &spec["paths"]["/api/marketplace/items/{id}/toggle"]["post"];
        for status in ["400", "404", "409", "503"] {
            assert!(toggle["responses"].get(status).is_some());
        }
        let schema = &spec["components"]["schemas"];
        assert!(schema["InventoryProvenance"]["oneOf"].as_array().unwrap().len() == 3);
        assert!(schema["InventoryToggle"]["required"].as_array().unwrap().iter().any(|field| field == "expected_revision"));
    }

    #[cfg(feature = "enterprise")]
    #[test]
    fn synthient_lifecycle_private_callback_and_tenant_preferences() {
        use nanosiem_enterprise::handlers::shared_private_provisioning::EnterpriseSharedPrivateProvisioningApiDoc;
        let private=serde_json::to_value(EnterpriseSharedPrivateProvisioningApiDoc::openapi()).unwrap();
        let callback="/internal/v1/enterprise-shared/platform-enrichment:billing";
        let op=&private["paths"][callback]["post"];
        assert!(op["security"][0]["nano_main_service_identity"].is_array());
        assert_eq!(private["components"]["schemas"]["BillingEvent"]["additionalProperties"],false);
        let public=serde_json::to_value(build_openapi()).unwrap();
        assert!(public["paths"].get(callback).is_none());
        let path="/api/enrichment/entitlements/{feed_id}";
        for method in ["get","post"] {
            assert!(public["paths"][path][method]["security"].is_array());
            assert!(public["paths"][path][method]["responses"]["403"].is_object());
        }
        assert_eq!(public["components"]["schemas"]["EntitlementPreference"]["additionalProperties"],false);
    }

    #[cfg(feature = "enterprise")]
    #[test]
    fn ingest_cell_generation_roll_is_documented_only_on_private_listener() {
        use nanosiem_enterprise::handlers::shared_private_provisioning::EnterpriseSharedPrivateProvisioningApiDoc;
        let path = "/internal/v1/enterprise-shared/ingest-cells:roll-generation";
        let private = serde_json::to_value(EnterpriseSharedPrivateProvisioningApiDoc::openapi()).unwrap();
        // Phase 7 adds the sandbox billing callback on the private listener;
        // NAN-2590 adds ingest-credential-requests:pending and :fulfil;
        // NAN-2594 adds ingest-credential-requests:fulfil-collector;
        // NAN-2590 (9001880) adds ingest-credential-requests:reject;
        // NAN-2879 adds lake-part-deletes:attest and lake-part-log:index;
        // NAN-2942 adds provisioning-outbox:expedite;
        // NAN-2980 adds hec-sources:credentials.
        // SOAR owner status and signed delivery remain private-only.
        // NAN-4678 adds activation-invitations:reassign-owner.
        assert_eq!(private["paths"].as_object().unwrap().len(), 32);
        assert!(private["paths"]["/internal/v1/enterprise-shared/hec-sources:credentials"]["post"].is_object());
        assert!(!build_openapi().paths.paths.contains_key("/internal/v1/enterprise-shared/hec-sources:credentials"),
            "hec-sources:credentials must stay off the public spec");
        assert!(!build_openapi().paths.paths.contains_key("/internal/v1/enterprise-shared/bronze-deletes:attest"));
        for private_only in ["/internal/v1/enterprise-shared/lake-part-deletes:attest", "/internal/v1/enterprise-shared/lake-part-log:index"] {
            assert!(private["paths"][private_only]["post"].is_object(), "{private_only}");
            assert!(!build_openapi().paths.paths.contains_key(private_only), "{private_only} must stay off the public spec");
        }
        let operation = &private["paths"][path]["post"];
        assert!(operation["security"][0]["nano_main_service_identity"].is_array());
        assert_eq!(operation["requestBody"]["content"]["application/json"]["schema"]["$ref"],
            "#/components/schemas/IngestCellRollGenerationRequest");
        for status in ["200", "400", "401", "403", "409", "413", "415", "429", "503", "504"] {
            assert!(operation["responses"][status].is_object(), "{status}");
        }
        let schema = &private["components"]["schemas"]["IngestCellRollGenerationRequest"];
        for field in ["request_id", "tenant_id", "expected_generation", "actor", "reason", "release"] {
            assert!(schema["required"].as_array().unwrap().iter().any(|v| v == field), "{field}");
        }
        assert_eq!(schema["additionalProperties"], false);
        assert!(!build_openapi().paths.paths.contains_key(path));
    }

    #[cfg(feature = "enterprise")]
    #[test]
    fn ingest_credential_fulfilment_is_documented_only_on_private_listener() {
        use nanosiem_enterprise::handlers::shared_private_provisioning::EnterpriseSharedPrivateProvisioningApiDoc;
        let private = serde_json::to_value(EnterpriseSharedPrivateProvisioningApiDoc::openapi()).unwrap();
        for (path, schema) in [
            ("/internal/v1/enterprise-shared/ingest-credential-requests:pending", "IngestCredentialRequestsPendingRequest"),
            ("/internal/v1/enterprise-shared/ingest-credential-requests:fulfil", "IngestCredentialRequestFulfilRequest"),
            ("/internal/v1/enterprise-shared/ingest-credential-requests:fulfil-collector", "IngestCredentialCollectorFulfilRequest"),
            ("/internal/v1/enterprise-shared/ingest-credential-requests:reject", "IngestCredentialRequestRejectRequest"),
        ] {
            let operation = &private["paths"][path]["post"];
            assert!(operation["security"][0]["nano_main_service_identity"].is_array(), "{path}");
            assert_eq!(operation["requestBody"]["content"]["application/json"]["schema"]["$ref"],
                format!("#/components/schemas/{schema}"));
            for status in ["200", "400", "401", "403", "413", "415", "429", "503", "504"] {
                assert!(operation["responses"][status].is_object(), "{path} {status}");
            }
            assert_eq!(private["components"]["schemas"][schema]["additionalProperties"], false, "{schema}");
            assert!(!build_openapi().paths.paths.contains_key(path));
        }
        let fulfil = &private["components"]["schemas"]["IngestCredentialRequestFulfilRequest"];
        for field in ["request_id", "tenant_id", "template_route_id", "expected_template", "digest_key_id",
            "secret_digest_hex", "sealed_token_hex", "actor"] {
            assert!(fulfil["required"].as_array().unwrap().iter().any(|v| v == field), "{field}");
        }
        // NAN-2594: the collector twin carries the template ARRAY instead.
        let collector = &private["components"]["schemas"]["IngestCredentialCollectorFulfilRequest"];
        for field in ["request_id", "tenant_id", "expected_templates", "digest_key_id",
            "secret_digest_hex", "sealed_token_hex", "actor"] {
            assert!(collector["required"].as_array().unwrap().iter().any(|v| v == field), "{field}");
        }
        assert!(collector["properties"].get("template_route_id").is_none());
    }

    #[cfg(feature = "enterprise")]
    #[test]
    fn source_enrollment_protocols_keep_private_path_contract() {
        use nanosiem_enterprise::handlers::shared_private_provisioning::EnterpriseSharedPrivateProvisioningApiDoc;
        let private = serde_json::to_value(EnterpriseSharedPrivateProvisioningApiDoc::openapi()).unwrap();
        // NAN-2423 extends the body, adding no public or private paths
        // (the NAN-2590 / NAN-2594 fulfilment operations, and 9001880's
        // reject, are counted here too; so are NAN-2879's two lake-part
        // paths, which this count had missed, and NAN-2942's
        // provisioning-outbox:expedite, and NAN-2980's hec-sources:credentials).
        // NAN-4678 adds activation-invitations:reassign-owner.
        assert_eq!(private["paths"].as_object().unwrap().len(), 32);
        let path = "/internal/v1/enterprise-shared/hec-sources:enroll";
        assert_eq!(private["paths"][path]["post"]["requestBody"]["content"]["application/json"]["schema"]["$ref"],
            "#/components/schemas/HecSourceEnrollRequest");
        let schemas = &private["components"]["schemas"];
        assert!(schemas["HecSourceEnrollRequest"]["properties"]["sources"].is_object());
        assert!(schemas["SourceProtocolEnrollment"]["properties"]["protocols"].is_object());
        assert!(!schemas["HecSourceEnrollRequest"]["required"].as_array().unwrap().iter().any(|v| v == "sources"));
        assert!(!build_openapi().paths.paths.contains_key(path));
    }

    #[cfg(feature = "enterprise")]
    #[test]
    fn activation_owner_reassign_is_documented_only_on_private_listener() {
        use nanosiem_enterprise::handlers::shared_private_provisioning::EnterpriseSharedPrivateProvisioningApiDoc;
        // NAN-4678: nano-main re-points a pending hosted-shared owner; never
        // in the customer spec.
        let private = serde_json::to_value(EnterpriseSharedPrivateProvisioningApiDoc::openapi()).unwrap();
        let path = "/internal/v1/enterprise-shared/activation-invitations:reassign-owner";
        let operation = &private["paths"][path]["post"];
        assert_eq!(operation["requestBody"]["content"]["application/json"]["schema"]["$ref"],
            "#/components/schemas/ActivationOwnerReassignRequest");
        for status in ["200", "400", "401", "404", "409", "503"] {
            assert!(operation["responses"][status].is_object(), "{status}");
        }
        let schemas = &private["components"]["schemas"];
        let request = &schemas["ActivationOwnerReassignRequest"];
        for field in ["request_id", "tenant_id", "invitation_id", "prior_secret_digest_hex",
            "renewed_secret_digest_hex", "renewed_expires_at", "owner", "actor", "reason"] {
            assert!(request["required"].as_array().unwrap().iter().any(|v| v == field), "{field}");
        }
        assert_eq!(request["additionalProperties"], false);
        assert_eq!(schemas["ActivationOwnerReassignOwner"]["additionalProperties"], false);
        for field in ["invitation_id", "tenant_id", "renewal_revision", "expires_at", "owner_user_id"] {
            assert!(schemas["ActivationOwnerReassignReceipt"]["properties"][field].is_object(), "{field}");
        }
        assert!(!build_openapi().paths.paths.contains_key(path));
    }

    #[cfg(feature = "enterprise")]
    #[test]
    fn operator_automation_key_op_is_documented_only_on_private_listener() {
        use nanosiem_enterprise::handlers::shared_operator_automation_keys::EnterpriseSharedOperatorAutomationKeyApiDoc;
        // NAN-3843: automation-keys:issue for nano-main super-admins; never in
        // the customer spec.
        let private = serde_json::to_value(EnterpriseSharedOperatorAutomationKeyApiDoc::openapi()).unwrap();
        let paths = private["paths"].as_object().unwrap();
        assert_eq!(paths.len(), 1);
        let path = "/internal/v1/enterprise-shared/automation-keys:issue";
        assert!(paths.contains_key(path));
        assert!(!build_openapi().paths.paths.contains_key(path));
    }

    #[cfg(feature = "enterprise")]
    #[test]
    fn tenant_path_alias_op_is_private_and_resolver_is_public() {
        use nanosiem_enterprise::handlers::shared_tenant_path_alias::EnterpriseSharedTenantPathAliasApiDoc;
        // NAN-4152: tenant-path-alias:set for nano-main; never in the customer
        // spec. The public resolver is.
        let private = serde_json::to_value(EnterpriseSharedTenantPathAliasApiDoc::openapi()).unwrap();
        let paths = private["paths"].as_object().unwrap();
        assert_eq!(paths.len(), 1);
        let path = "/internal/v1/enterprise-shared/tenant-path-alias:set";
        assert!(paths.contains_key(path));
        let customer = build_openapi();
        assert!(!customer.paths.paths.contains_key(path));
        assert!(customer.paths.paths.contains_key("/api/auth/shared/tenant-path-alias/{alias}"));
    }

    #[cfg(feature = "enterprise")]
    #[test]
    fn landing_source_ops_are_documented_only_on_private_listener() {
        use nanosiem_enterprise::handlers::shared_landing_sources::EnterpriseSharedLandingSourcesApiDoc;
        // NAN-4136: landing-sources:* for nano-main's bucket drop UI and the
        // destroy job; never in the customer spec.
        let private = serde_json::to_value(EnterpriseSharedLandingSourcesApiDoc::openapi()).unwrap();
        let paths = private["paths"].as_object().unwrap();
        assert_eq!(paths.len(), 5);
        for action in ["read", "issue", "rotate", "revoke", "revoke-all"] {
            let path = format!("/internal/v1/enterprise-shared/landing-sources:{action}");
            assert!(paths.contains_key(&path), "{path}");
            assert!(!build_openapi().paths.paths.contains_key(&path), "{path}");
        }
    }

    #[cfg(feature = "enterprise")]
    #[test]
    fn operator_member_ops_are_documented_only_on_private_listener() {
        use nanosiem_enterprise::handlers::shared_operator_members::EnterpriseSharedOperatorMembersApiDoc;
        // NAN-3825: tenant-members:list / tenant-members:manage for MSSP
        // partners through nano-main; never in the customer spec.
        let private = serde_json::to_value(EnterpriseSharedOperatorMembersApiDoc::openapi()).unwrap();
        let paths = private["paths"].as_object().unwrap();
        assert_eq!(paths.len(), 2);
        for path in ["/internal/v1/enterprise-shared/tenant-members:list", "/internal/v1/enterprise-shared/tenant-members:manage"] {
            assert!(paths.contains_key(path), "{path}");
            assert!(!build_openapi().paths.paths.contains_key(path), "{path}");
        }
    }

    #[cfg(feature = "enterprise")]
    #[test]
    fn tenant_ai_allowance_op_is_documented_only_on_private_listener() {
        use nanosiem_enterprise::handlers::shared_tenant_ai_allowance::EnterpriseSharedTenantAiAllowanceApiDoc;
        // NAN-3512: tenant-ai-allowance:set for nano-main's lean billing; never
        // in the customer spec.
        let private = serde_json::to_value(EnterpriseSharedTenantAiAllowanceApiDoc::openapi()).unwrap();
        let paths = private["paths"].as_object().unwrap();
        assert_eq!(paths.len(), 1);
        let path = "/internal/v1/enterprise-shared/tenant-ai-allowance:set";
        assert!(paths.contains_key(path));
        assert!(!build_openapi().paths.paths.contains_key(path));
    }

    #[cfg(feature = "enterprise")]
    #[test]
    fn tenant_demo_ops_are_documented_only_on_private_listener() {
        use nanosiem_enterprise::handlers::shared_demo_sessions::EnterpriseSharedTenantDemoApiDoc;
        // NAN-4152: tenant-demo:set + demo-session:create for nano-main; never
        // in the customer spec. The public claim is.
        let private = serde_json::to_value(EnterpriseSharedTenantDemoApiDoc::openapi()).unwrap();
        let paths = private["paths"].as_object().unwrap();
        assert_eq!(paths.len(), 2);
        let public = build_openapi();
        for path in ["/internal/v1/enterprise-shared/tenant-demo:set", "/internal/v1/enterprise-shared/demo-session:create"] {
            assert!(paths.contains_key(path), "{path}");
            assert!(!public.paths.paths.contains_key(path), "{path}");
        }
        assert!(public.paths.paths.contains_key("/api/auth/shared/demo/claim"));
    }

    #[cfg(feature = "enterprise")]
    #[test]
    fn region_rls_key_op_is_documented_only_on_private_listener() {
        use nanosiem_enterprise::handlers::shared_region_rls_key::EnterpriseSharedRegionRlsKeyApiDoc;
        // NAN-3361: rls-context-keys:region-rotate for nano-main's region key
        // rotator; never in the customer spec, and no receipt schema carries
        // key bytes.
        let private = serde_json::to_value(EnterpriseSharedRegionRlsKeyApiDoc::openapi()).unwrap();
        let paths = private["paths"].as_object().unwrap();
        assert_eq!(paths.len(), 1);
        let path = "/internal/v1/enterprise-shared/rls-context-keys:region-rotate";
        assert!(paths.contains_key(path));
        assert!(!build_openapi().paths.paths.contains_key(path));
        for receipt in ["EnterpriseSharedRegionRlsKeyReceipt", "EnterpriseSharedRegionRlsKeyMetadata"] {
            let schema = serde_json::to_string(&private["components"]["schemas"][receipt]).unwrap();
            assert!(schema.len() > 2 && !schema.contains("hmac"), "{receipt}");
        }
    }

    #[cfg(feature = "enterprise")]
    #[test]
    fn parser_bundle_roll_ops_are_documented_only_on_private_listener() {
        use nanosiem_enterprise::handlers::shared_parser_bundle_roll::EnterpriseSharedParserBundleRollApiDoc;
        // NAN-2603: eight private provisioner ops, plus NAN-2607's
        // parser-rollouts:sources, plus 9001860's parser-rollouts:tenant-sources;
        // none may leak into the customer spec.
        let private = serde_json::to_value(EnterpriseSharedParserBundleRollApiDoc::openapi()).unwrap();
        let paths = private["paths"].as_object().unwrap();
        assert_eq!(paths.len(), 10);
        let public = build_openapi();
        for path in paths.keys() {
            assert!(path.starts_with("/internal/v1/enterprise-shared/parser-"), "{path}");
            assert!(!public.paths.paths.contains_key(path), "{path}");
        }
        let schema = &private["components"]["schemas"]["EnterpriseSharedParserBundleRollRequest"];
        for field in ["request_id", "tenant_id", "expected_activation_revision", "actor", "reason", "origin", "composition", "release"] {
            assert!(schema["required"].as_array().unwrap().iter().any(|v| v == field), "{field}");
        }
        assert_eq!(schema["additionalProperties"], false);
    }

    #[cfg(feature = "enterprise")]
    #[test]
    fn tenant_ip_context_routes_survive_root_merge_with_auth_and_schemas() {
        let spec = serde_json::to_value(build_openapi()).unwrap();
        for (path, method) in [
            ("/api/enrichment/ip-context/batch", "post"),
            ("/api/enrichment/ip-context/sources/{id}", "delete"),
            ("/api/enrichment/ip-context/stats", "get"),
        ] {
            let item = &spec["paths"][path];
            assert_eq!(item.as_object().unwrap().len(), 1);
            let op = &item[method];
            assert_eq!(op["security"], serde_json::json!([{"bearer_auth": []}, {"api_key": []}]));
            assert!(op["responses"]["503"].is_object());
        }
        assert_eq!(spec["paths"]["/api/enrichment/ip-context/batch"]["post"]["requestBody"]
            ["content"]["application/json"]["schema"]["$ref"], "#/components/schemas/TenantIpContextBatchRequest");
        for schema in ["TenantIpContextBatchRequest", "TenantIpContextBatchResponse", "TenantIpContextDeleteResponse",
            "TenantIpContextStatsResponse", "LakeIpContextInput"] {
            assert!(spec["components"]["schemas"][schema].is_object(), "{schema}");
        }
        assert!(spec["paths"]["/v1/ip-context/batch"].is_null());
        assert!(spec["paths"]["/v1/ip-context/stats"].is_null());
    }

    #[cfg(feature = "enterprise")]
    #[test]
    fn egress_expected_op_is_documented_only_on_private_listener() {
        use nanosiem_enterprise::handlers::shared_egress_expected::EnterpriseSharedEgressExpectedApiDoc;
        // NAN-4371: nano-main's leader refresh reads egress-expected:read; it
        // must never leak into the customer spec, and its destination carries
        // tenant_id / purpose / host, plus the optional configured SMTP port.
        let private = serde_json::to_value(EnterpriseSharedEgressExpectedApiDoc::openapi()).unwrap();
        let paths = private["paths"].as_object().unwrap();
        assert_eq!(paths.keys().collect::<Vec<_>>(), ["/internal/v1/enterprise-shared/egress-expected:read"]);
        let public = build_openapi();
        assert!(!public.paths.paths.contains_key("/internal/v1/enterprise-shared/egress-expected:read"));
        let properties = private["components"]["schemas"]["EnterpriseSharedEgressExpectedDestination"]["properties"]
            .as_object().unwrap();
        assert_eq!(properties.keys().collect::<Vec<_>>(), ["host", "port", "purpose", "tenant_id"]);
        let mut required: Vec<_> = private["components"]["schemas"]["EnterpriseSharedEgressExpectedDestination"]["required"]
            .as_array().unwrap().iter().map(|v| v.as_str().unwrap()).collect();
        required.sort_unstable();
        assert_eq!(required, ["host", "purpose", "tenant_id"]);
        assert_eq!(private["components"]["schemas"]["EnterpriseSharedEgressPurpose"]["enum"],
            serde_json::json!(["inputlookup", "soar", "soar_smtp"]));
    }

    #[cfg(feature = "enterprise")]
    #[test]
    fn lake_pipeline_alerts_op_is_documented_only_on_private_listener() {
        use nanosiem_enterprise::handlers::shared_lake_pipeline_alerts::EnterpriseSharedLakePipelineAlertsApiDoc;
        // NAN-2632: nano-main's platform alert pipeline polls
        // lake-pipeline-alerts:read; it must never leak into the customer spec.
        let private = serde_json::to_value(EnterpriseSharedLakePipelineAlertsApiDoc::openapi()).unwrap();
        let paths = private["paths"].as_object().unwrap();
        assert_eq!(paths.len(), 1);
        let public = build_openapi();
        for path in paths.keys() {
            assert_eq!(path, "/internal/v1/enterprise-shared/lake-pipeline-alerts:read");
            assert!(!public.paths.paths.contains_key(path), "{path}");
        }
        let alert = &private["components"]["schemas"]["EnterpriseSharedLakePipelineAlert"];
        for field in ["alert_key", "stage", "signal", "severity", "state", "first_fired_at", "last_changed_at", "threshold", "unit", "revision"] {
            assert!(alert["required"].as_array().unwrap().iter().any(|v| v == field), "{field}");
        }
    }

    #[cfg(feature = "enterprise")]
    #[test]
    fn parser_rollout_observation_ops_are_documented_only_on_private_listener() {
        use nanosiem_enterprise::handlers::shared_parser_rollout_observation::EnterpriseSharedParserRolloutObservationApiDoc;
        // NAN-2645: lake-generations:state, parser-rollouts:landing and
        // parser-rollouts:probe for nano-main's rollout orchestrator; none may
        // leak into the customer spec.
        let private = serde_json::to_value(EnterpriseSharedParserRolloutObservationApiDoc::openapi()).unwrap();
        let paths = private["paths"].as_object().unwrap();
        assert_eq!(paths.len(), 3);
        let public = build_openapi();
        for path in paths.keys() {
            assert!(["/internal/v1/enterprise-shared/lake-generations:state",
                     "/internal/v1/enterprise-shared/parser-rollouts:landing",
                     "/internal/v1/enterprise-shared/parser-rollouts:probe"].contains(&path.as_str()), "{path}");
            assert!(!public.paths.paths.contains_key(path), "{path}");
        }
        let state = &private["components"]["schemas"]["EnterpriseSharedLakeGenerationState"];
        for field in ["tenant_id", "evaluated_at", "publish_in_flight", "in_flight", "latest", "last_published_at",
                      "consecutive_failed_cycles", "upload_p95_seconds"] {
            assert!(state["properties"][field].is_object(), "{field}");
        }
        let source = &private["components"]["schemas"]["EnterpriseSharedParserRolloutLandingSource"];
        for field in ["source_slug", "rows_since", "parsed_ok", "parse_errors", "rows_under_pending_bundle", "searchable"] {
            assert!(source["required"].as_array().unwrap().iter().any(|v| v == field), "{field}");
        }
    }

    #[cfg(feature = "enterprise")]
    #[test]
    fn lean_audit_delivery_ops_are_documented_only_on_private_listener() {
        use nanosiem_enterprise::handlers::shared_lean_audit_delivery::EnterpriseSharedLeanAuditDeliveryApiDoc;
        // NAN-2999: audit-events:delivery and audit-events:ack for nano-main's
        // lean audit delivery loop; neither may leak into the customer spec.
        let private = serde_json::to_value(EnterpriseSharedLeanAuditDeliveryApiDoc::openapi()).unwrap();
        let paths = private["paths"].as_object().unwrap();
        assert_eq!(paths.len(), 2);
        let public = build_openapi();
        for path in paths.keys() {
            assert!(["/internal/v1/enterprise-shared/audit-events:delivery",
                     "/internal/v1/enterprise-shared/audit-events:ack"].contains(&path.as_str()), "{path}");
            assert!(!public.paths.paths.contains_key(path), "{path}");
        }
        let envelope = &private["components"]["schemas"]["EnterpriseSharedLeanAuditDeliveryEnvelope"];
        for field in ["via", "protocol", "source_slug", "method", "path", "headers", "body_base64", "body_bytes", "body_sha256"] {
            assert!(envelope["required"].as_array().unwrap().iter().any(|v| v == field), "{field}");
        }
    }

    #[test]
    fn cold_ceiling_search_contract_documents_actionable_422_and_bytes() {
        let spec = serde_json::to_value(build_openapi()).unwrap();
        for path in ["/api/search", "/api/search/stream"] {
            let description = spec["paths"][path]["post"]["responses"]["422"]["description"].as_str().unwrap();
            // NAN-3644: the 2 GiB COLD_BUDGET_EXCEEDED refusal is gone; only
            // the reader's ceiling is a 422.
            assert!(description.contains("COLD_SCAN_TOO_LARGE"), "{description}");
            assert!(!description.contains("COLD_BUDGET_EXCEEDED"), "{description}");
        }
        let detail = &spec["components"]["schemas"]["ErrorDetail"];
        let alternatives = detail["anyOf"].as_array().or_else(|| detail["oneOf"].as_array()).unwrap();
        assert!(alternatives.iter().any(|variant| {
            let properties = &variant["properties"];
            properties.get("needed_bytes").is_some()
                && properties.get("ceiling_bytes").is_some()
                && properties.get("background_ceiling_bytes").is_some()
                && properties.get("retryable").is_some()
                && properties.get("reason").is_some()
        }), "{detail}");
    }

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
    fn verify_tree_page_contract() {
        let spec = serde_json::to_value(build_openapi()).unwrap();
        let operation = &spec["paths"]["/api/search/tree-page"]["post"];
        assert_eq!(operation["requestBody"]["content"]["application/json"]["schema"]["$ref"], "#/components/schemas/TreePageRequest");
        assert_eq!(operation["responses"]["200"]["content"]["application/json"]["schema"]["$ref"], "#/components/schemas/TreePageResponse");
        assert!(operation["security"].as_array().unwrap().iter().any(|security| security.get("api_key").is_some()));
        let response = &spec["components"]["schemas"]["TreePageResponse"]["properties"];
        assert_eq!(response["nodes"]["type"], "array");
        assert_eq!(response["total_count_exact"]["type"], "boolean");
        assert!(response.get("next_offset").is_some());
        assert!(response.get("source_truncated").is_some());
    }

    #[test]
    fn verify_source_onboarding_contract() {
        let spec = serde_json::to_value(build_openapi()).unwrap();
        for (path, method) in [
            ("/api/source-onboarding", "get"),
            ("/api/source-onboarding/actions", "post"),
            ("/api/source-onboarding/import-preview", "post"),
            ("/api/source-onboarding/export", "get"),
        ] {
            let operation = &spec["paths"][path][method];
            assert!(operation["responses"]["200"].is_object(), "{path}");
            assert!(operation["responses"]["403"].is_object(), "{path}");
            assert!(operation["security"].as_array().unwrap().iter().any(|s| s.get("api_key").is_some()), "{path}");
        }
        assert_eq!(spec["paths"]["/api/source-onboarding/actions"]["post"]["requestBody"]["content"]["application/json"]["schema"]["$ref"], "#/components/schemas/Action");
        assert_eq!(spec["paths"]["/api/source-onboarding/import-preview"]["post"]["requestBody"]["content"]["application/json"]["schema"]["$ref"], "#/components/schemas/CsvRequest");
        assert!(spec["paths"]["/api/source-onboarding/export"]["get"]["responses"]["200"]["content"]["text/csv"].is_object());
        for schema in ["Action", "CsvRequest", "JoinedPlan", "JoinedSource", "PlannedSource", "Wave", "Progress", "Suggestion", "Settings", "PreviewRow"] {
            assert!(spec["components"]["schemas"][schema].is_object(), "{schema}");
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
        // NAN-2282 added 5 shared system-health path templates: events,
        // summary, acknowledge, resolve, and delivery history.
        // NAN-2281 then added 4 ENTERPRISE templates for authoring bounded custom
        // API collectors: /api/integrations/custom/validate,
        // /api/integrations/custom/preview, /api/integrations/custom, and
        // /api/integrations/custom/{id}. Open is unchanged.
        // NAN-2306 added 2 shared hunt-report audit receipt templates:
        // /api/hunts/report-branding-events and /api/hunts/{id}/report-exports.
        // PDF bytes and branding remain device-local; both paths count in both editions.
        // NAN-1931 adds 2 shared path templates (internal Vector config
        // generation delivery for the managed consumer sidecar):
        //   GET /api/internal/vector-config/current/manifest
        //   GET /api/internal/vector-config/generations/{generation}/files/{path}
        // Counted in both editions — the delivery endpoint is not gated.
        // Enterprise floor 562 + 2 = 564; open floor 444 + 2 = 446.
        // NAN-2361 moved the Observability ↔ Security convergence cross-link
        // (NAN-1542/NAN-1544, previously the ENTERPRISE-only api-service path
        // GET /api/observability/services/{service}/security-signals) into the
        // search service as the shared path
        // GET /api/search/services/{service}/security-signals (merged below,
        // both editions). Enterprise floor 564 - 1 + 1 = 564; open floor
        // 446 + 1 = 447.
        #[cfg(feature = "enterprise")]
        // NAN-2469 phase 10 adds four checkout/operator paths: 569 + 4 = 573.
        // NAN-2592 adds four ENTERPRISE shared-onboarding templates:
        //   /api/log-sources/ingest-credentials/requests/{id} (GET state),
        //   /api/log-sources/ingest-credentials/requests/{id}/reveal (POST),
        //   /api/log-sources/ingest-credentials/{credential_id}/revoke (POST),
        //   /api/log-sources/sender-templates (GET). Open is unchanged.
        // Enterprise floor 573 + 4 = 577.
        // NAN-2597 adds two ENTERPRISE "credentials that can write S" reads:
        //   /api/log-sources/{id}/credentials (GET),
        //   /api/log-sources/ingest-credentials/writers/{source_slug} (GET).
        // Enterprise floor 577 + 2 = 579.
        // NAN-2607 adds seven ENTERPRISE shared parser-rollout templates:
        //   /api/log-sources/{id}/rollout (POST), /api/log-sources/{id}/rollouts,
        //   /api/log-sources/rollouts, /api/log-sources/rollouts/{rollout_id},
        //   /api/log-sources/parser-base-offers,
        //   /api/log-sources/parser-base-offers/{offer_id}/merge (POST),
        //   /api/log-sources/{id}/samples (GET/PUT). Open is unchanged.
        // Enterprise floor 579 (NAN-2597) + 7 = 586.
        // NAN-2617 adds one ENTERPRISE decision (b) pre-check:
        //   /api/log-sources/ingest-credentials/precheck (POST). Open is unchanged.
        // Enterprise floor 586 + 1 = 587.
        // NAN-2598 adds two ENTERPRISE activity reads:
        //   /api/log-sources/ingest-credentials/{credential_id}/activity (GET),
        //   /api/log-sources/ingest-sources/{source_slug}/activity (GET).
        // Enterprise floor 587 + 2 = 589.
        // NAN-2977 adds one ENTERPRISE zero-base carry-forward:
        //   /api/log-sources/parser-base-offers/{offer_id}/carry-forward (POST).
        // Enterprise floor 589 + 1 = 590.
        // NAN-3038 adds three ENTERPRISE code-free IOC list routes:
        //   /api/ioc-lists (GET/POST), /api/ioc-lists/{id} (GET/PUT/DELETE),
        //   /api/ioc-lists/{id}/publish (POST).
        // Enterprise floor 590 + 3 = 593.
        // NAN-3064 adds /api/rules/scheduling-lag (GET) to both builds.
        // Enterprise floor 593 + 1 = 594; open 447 + 1 = 448.
        // NAN-3077 adds the shared POST /api/search/tree-page template.
        // NAN-3109 phase 2 adds the allowlist item and internal search ACL paths.
        // NAN-3009 adds three authenticated custom IP context paths.
        // NAN-3191 adds one ENTERPRISE shared-tenant AI tier path:
        //   /api/melod/settings/ai-tier (GET/PUT). Open is unchanged.
        // NAN-3203 adds three ENTERPRISE shared playbook upstream paths:
        //   /api/playbook-repositories/{id}/upstream-updates (GET),
        //   /api/playbook-repositories/{id}/apply-all-upstream-updates (POST),
        //   /api/playbooks/{id}/apply-upstream-update (POST). Open is unchanged.
        // NAN-3205 adds one ENTERPRISE pivt playbook drafting path:
        //   /api/melod/playbook/draft (POST). Open is unchanged.
        // NAN-3207 adds two ENTERPRISE per-source health series reads:
        //   /api/log-sources/health-series (GET),
        //   /api/log-sources/{id}/health-series (GET). Open is unchanged.
        // NAN-3219 adds one ENTERPRISE AI tuning mode path:
        //   /api/melod/settings/ai-tuning (GET/PUT, dedicated + shared twin).
        //   Open is unchanged.
        // NAN-3225 adds one ENTERPRISE entity risk series read:
        //   /api/entities/{entity_type}/{entity_value}/risk-timeline (GET).
        // NAN-3226 adds one ENTERPRISE internal-domains settings path:
        //   /api/settings/internal-domains (GET/PUT, dedicated + shared twin).
        //   Open is unchanged.
        // NAN-3228 adds six ENTERPRISE risk watchlist paths (dedicated + shared twin):
        //   /api/risk/watchlists (GET/POST), /api/risk/watchlists/{watchlist_id}
        //   (GET/PATCH/DELETE), .../{watchlist_id}/members (POST),
        //   .../{watchlist_id}/members/remove (POST), /api/risk/watchlists/lookup
        //   (GET), /api/risk/watchlists/memberships (GET). Open is unchanged.
        // NAN-3249 adds one ENTERPRISE risk watchlist path (dedicated + shared twin):
        //   /api/risk/watchlists/suggest (POST). Open is unchanged.
        // NAN-3421 adds four enterprise Pipe inspection path templates.
        // NAN-3418 adds the capture snapshot read:
        //   /api/log-sources/{id}/capture-sessions/{session_id}/snapshot (GET).
        // NAN-3447 adds the recent-events read for Pipe preview:
        //   /api/log-sources/{id}/pipe-recent-events (POST).
        // NAN-3572 adds three hosted collector lifecycle path templates.
        // NAN-3592 adds five tenant pull-source path templates:
        //   /api/pull-sources (GET/POST), /api/pull-sources/setup/aws (GET),
        //   /api/pull-sources/{id} (GET/DELETE), .../{id}/pause, .../{id}/resume (POST).
        // NAN-3598 adds /api/pull-sources/setup/gcp (GET).
        // NAN-3604 adds /api/pull-sources/setup/azure (GET).
        // NAN-3618 adds /api/pull-sources/{id}/retry (POST).
        // NAN-3729 adds PATCH on /api/pull-sources/{id} (no new path template).
        // NAN-3621 adds the Pipe lane inputs reads:
        //   /api/log-sources/{id}/pipe-inputs (GET), /api/log-sources/pipe-inputs (GET).
        // NAN-3490 adds the hosted feed checkpoint reset:
        //   /api/marketplace/collectors/{slug}/feeds/{feed_id}/reset-checkpoint (POST).
        // NAN-3503 adds the hosted collector vendor components:
        //   /api/marketplace/collectors/{slug}/components (GET),
        //   /api/marketplace/collectors/{slug}/components/{component} (PUT/DELETE).
        // NAN-3684: four source-onboarding paths.
        // NAN-3729 adds the hosted credential rotation path.
        // NAN-3770 adds three dedicated ingest-token path templates to both
        // builds: /api/ingest-tokens (GET/POST),
        // /api/ingest-tokens/{credential_id}/revoke (POST),
        // /api/ingest-tokens/install-token (PUT).
        // NAN-3806 adds /api/ingest-tokens/{credential_id}/bind (POST) to both builds.
        // NAN-3763 adds hosted threat-intel lookups: /api/threat-intel/providers (GET),
        //   /api/threat-intel/providers/{provider} (PUT/DELETE), /api/threat-intel/lookup (POST).
        // NAN-3807 adds two dedicated bucket-drop path templates to both builds:
        //   /api/landing-sources (GET), /api/landing-sources/{source_id}/files (GET).
        // NAN-3812 adds /api/me/field-usage (GET) to both builds.
        // NAN-3881 adds hosted /api/threat-intel/indicator-lookup (POST).
        // NAN-3882 adds the ENTERPRISE IOC list viewer:
        //   /api/ioc-lists/{list_id}/indicators (GET). Open is unchanged.
        // NAN-3904 adds four shared OIDC admin paths; NAN-3910 adds two IOC upload paths.
        // NAN-3660 adds the hosted feed ingest-credential rotation:
        //   /api/marketplace/collectors/{slug}/feeds/{feed_id}/rotate-credential (POST).
        // NAN-4152 adds the shared /api/auth/shared/tenant-path-alias/{alias} (GET).
        // NAN-4152 adds the public demo claim /api/auth/shared/demo/claim (POST).
        let min_paths = 674; // NAN-4402: proxy check, requirements, origin ACL, active-tenant roster.
        #[cfg(not(feature = "enterprise"))]
        // NAN-3577: floor matches the regenerated default-feature published spec.
        // NAN-3806: +1 (/api/ingest-tokens/{credential_id}/bind); NAN-3807: +2 (landing sources);
        // NAN-3812: +1 (/api/me/field-usage).
        let min_paths = 485; // NAN-4402: proxy check, requirements, origin ACL, active-tenant roster.

        // Keep the SOAR increment separate so the baseline follows main.
        // M2: ten paths; M3c: nine; tenant settings: one (enterprise only);
        // NAN-4369: the internal egress check, one.
        // NAN-4380: tenant-bound agent query receipts, one.
        #[cfg(feature = "enterprise")]
        let min_paths = min_paths + 28; // NAN-4471: mail settings, recipients and SMTP egress.
        #[cfg(feature = "enterprise")]
        let min_paths = min_paths + 2; // NAN-4465 CP2: saved and draft flow test admission.
        #[cfg(feature = "enterprise")]
        let min_paths = min_paths + 2; // NAN-4496: SOAR upstream list and apply-all.
        #[cfg(feature = "enterprise")]
        let min_paths = min_paths + 1; // NAN-4556: SOAR run volume.
        #[cfg(feature = "enterprise")]
        let min_paths = min_paths + 1; // NAN-4535: /api/melod/flow/draft (POST).
        #[cfg(feature = "enterprise")]
        let min_paths = min_paths + 1; // NAN-4585: /api/soar/flows/validate-search (POST).
        #[cfg(feature = "enterprise")]
        let min_paths = min_paths + 1; // NAN-4653: /api/melod/edit/turn (POST).
        let min_paths = min_paths + 1; // NAN-4759: /api/enrichment/platform-feeds (GET).

        assert!(
            path_count >= min_paths,
            "Expected at least {min_paths} paths, got {path_count}"
        );
    }

    #[cfg(feature = "enterprise")]
    #[test]
    fn soar_upstream_updates_match_repository_contracts() {
        let spec = serde_json::to_value(build_openapi()).unwrap();
        for (path, method, response) in [
            ("/api/soar/packs/upstream-updates", "get", "SoarUpstreamUpdates"),
            ("/api/soar/packs/apply-all-upstream-updates", "post", "BulkApplySoarUpstreamResult"),
        ] {
            let op = &spec["paths"][path][method];
            assert_eq!(op["security"], serde_json::json!([{"bearer_auth":[]},{"api_key":[]}]));
            assert_eq!(op["responses"]["200"]["content"]["application/json"]["schema"]["$ref"],format!("#/components/schemas/{response}"));
            assert!(!op["responses"]["409"].is_null());
        }
        for (schema, fields) in [
            ("SoarPack", vec!["upstream_changed", "upstream_version"]),
            ("SoarPacks", vec!["upstream_changed_count"]),
            ("SoarUpstreamUpdates", vec!["updates", "total_count"]),
            ("BulkApplySoarUpstreamResult", vec!["updated", "failed", "results"]),
        ] {
            for field in fields { assert!(!spec["components"]["schemas"][schema]["properties"][field].is_null(),"{schema}.{field}"); }
        }
        assert!(!spec["paths"]["/api/soar/packs/{name}/upgrade"]["post"].is_null());
    }

    #[cfg(feature = "enterprise")]
    #[test]
    fn soar_saved_and_draft_test_paths_have_request_and_timeline_schemas() {
        let spec=serde_json::to_value(build_openapi()).unwrap();
        for (path,request) in [
            ("/api/soar/flows/{id}/test","TestFlow"),
            ("/api/soar/flows/test","TestDraftFlow"),
        ] {
            let post=&spec["paths"][path]["post"];
            assert_eq!(post["requestBody"]["content"]["application/json"]["schema"]["$ref"],format!("#/components/schemas/{request}"));
            assert_eq!(post["responses"]["202"]["content"]["application/json"]["schema"]["$ref"],"#/components/schemas/SoarTestRun");
        }
        assert!(!spec["components"]["schemas"]["SoarStepResult"].is_null());
    }

    #[test]
    #[cfg(feature = "enterprise")]
    fn soar_contract_has_protected_operations_and_write_only_credentials() {
        let spec = serde_json::to_value(build_openapi()).unwrap();
        let paths: Vec<_> = spec["paths"].as_object().unwrap().iter()
            .filter(|(path, _)| path.starts_with("/api/soar/")).collect();
        // NAN-4544 added GET /api/soar/flows/stats; NAN-4556 GET /api/soar/runs/volume;
        // NAN-4585 POST /api/soar/flows/validate-search.
        assert_eq!(paths.len(), 30);
        let mut ids = std::collections::BTreeSet::new();
        for (_, path) in paths {
            for method in ["get", "post", "put", "delete"] {
                if let Some(operation) = path.get(method) {
                    assert!(!operation["security"].as_array().unwrap().is_empty());
                    let id = operation["operationId"].as_str().unwrap();
                    assert!(id.starts_with("soar_"));
                    assert!(ids.insert(id));
                }
            }
        }
        assert_eq!(ids.len(), 40);
        let schemas = &spec["components"]["schemas"];
        // NAN-4544 read-only UI fields: names, blast radius, stage deadlines
        // and the one-query per-flow 24h aggregate.
        for (schema, field) in [
            ("SoarRun", "requested_by_name"),
            ("SoarRun", "affected_entities"),
            ("SoarApproval", "requested_by_name"),
            ("SoarApproval", "decided_by_name"),
            ("SoarStepResult", "deadline_at"),
            ("SoarFlowStats", "window_hours"),
            ("SoarFlowStats", "since"),
            ("SoarFlowStats", "flows"),
            ("SoarFlowRunStats", "runs"),
            ("SoarFlowRunStats", "succeeded"),
            ("SoarFlowRunStats", "failed"),
        ] {
            let text = schemas[schema].to_string();
            assert!(text.contains(&format!("\"{field}\"")), "{schema}.{field}");
        }
        let stats = &spec["paths"]["/api/soar/flows/stats"]["get"];
        assert_eq!(stats["operationId"], "soar_flow_stats");
        assert_eq!(
            stats["responses"]["200"]["content"]["application/json"]["schema"]["$ref"],
            "#/components/schemas/SoarFlowStats"
        );
        assert_eq!(schemas["UpdateMailTransport"]["properties"]["password"]["writeOnly"], true);
        let transport = schemas["MailTransport"]["properties"].as_object().unwrap();
        for secret in ["password", "password_encrypted", "password_nonce"] {
            assert!(!transport.contains_key(secret));
        }
        for request in ["SoarCreateConnection", "SoarUpdateConnection"] {
            assert_eq!(schemas[request]["properties"]["credentials"]["writeOnly"], true);
        }
        let connection = schemas["SoarConnection"]["properties"].as_object().unwrap();
        for secret in ["credentials", "credentials_encrypted", "credentials_nonce"] {
            assert!(!connection.contains_key(secret));
        }
        let parameters = spec["paths"]["/api/soar/runs"]["get"]["parameters"].as_array().unwrap();
        assert!(parameters.iter().all(|p| p["in"] == "query"));
        // NAN-4540: optional case filter for the case-linked Automation panel.
        let case_filter = parameters.iter().find(|p| p["name"] == "case_id").expect("case_id");
        assert_ne!(case_filter["required"], true);
        for decision in ["approve", "reject"] {
            let path = format!("/api/soar/approvals/{{id}}/{decision}");
            assert_eq!(spec["paths"][&path]["post"]["security"], serde_json::json!([{"bearer_auth": []}]));
        }
        assert_eq!(spec["paths"]["/api/soar/runs/{id}"]["get"]["responses"]["200"]["content"]["application/json"]["schema"]["$ref"], "#/components/schemas/SoarRunDetail");
        for schema in ["CreateFlow", "UpdateFlow", "ValidateFlow", "RunFlow", "TestFlow", "TestDraftFlow", "DecideApproval"] {
            assert_eq!(schemas[schema]["additionalProperties"], false, "{schema}");
        }
        for schema in ["SoarFlow", "SoarFlows", "FlowValidation", "SoarRunDetail", "SoarStepExecution", "SoarApproval", "SoarApprovals"] {
            assert!(schemas[schema].is_object(), "{schema}");
        }
        for schema in ["SoarSettings", "UpdateSoarSettings"] {
            assert!(schemas[schema]["properties"]["ai_daily_token_budget"].is_object(), "{schema}");
        }
        assert!(schemas["SoarSettings"]["properties"]["ai_usage"].is_object());
        assert!(schemas["SoarRunDetail"].to_string().contains("ai_usage"));
        for field in ["ai_tokens", "ai_budget_tokens", "ai_cached"] {
            assert!(schemas["SoarStepExecution"]["properties"][field].is_object(), "{field}");
        }
        assert!(schemas["RequestAuthority"].is_null());
        assert!(schemas["SoarFlows"]["properties"]["event_overflow_count"].is_object());
        assert!(schemas["SoarFlows"]["properties"]["last_event_overflow_at"].is_object());
        assert_eq!(spec["paths"]["/api/playbooks/{id}/run"]["post"]["responses"]["200"]["content"]["application/json"]["schema"]["$ref"], "#/components/schemas/EnterpriseSharedGovernedRunPlaybookResponse");
        let bridge = schemas["EnterpriseSharedGovernedRunPlaybookResponse"].to_string();
        assert!(bridge.contains("soar_run_id") && bridge.contains("soar_status"));
        let approval_parameters = spec["paths"]["/api/soar/approvals"]["get"]["parameters"].as_array().unwrap();
        assert!(approval_parameters.iter().all(|p| p["in"] == "query"));
        // NAN-4375: run-detail paging is a query string, not path segments.
        let run_parameters = spec["paths"]["/api/soar/runs/{id}"]["get"]["parameters"].as_array().unwrap();
        for name in ["steps_limit", "steps_offset", "approvals_limit", "approvals_offset"] {
            let parameter = run_parameters.iter().find(|p| p["name"] == name).expect(name);
            assert_eq!(parameter["in"], "query", "{name}");
            assert_ne!(parameter["required"], true, "{name}");
        }
        let id = run_parameters.iter().find(|p| p["name"] == "id").unwrap();
        assert_eq!(id["in"], "path");
        assert_eq!(spec["paths"]["/api/soar/settings"]["put"]["security"], serde_json::json!([{"bearer_auth": []}]));
    }

    #[test]
    #[cfg(feature = "enterprise")]
    fn tenant_doc_omits_soar_operations_that_refuse_api_keys() {
        // The tenant document authenticates only with X-API-Key. Settings PUT and
        // approval decisions accept a human session only (NAN-4375).
        let human_only = human_session_only_operations();
        for (path, method) in [
            ("/api/soar/settings", "put"),
            ("/api/soar/recipients", "put"),
            ("/api/soar/mail-transport", "put"),
            ("/api/soar/mail-transport/test", "post"),
            ("/api/soar/approvals/{id}/approve", "post"),
            ("/api/soar/approvals/{id}/reject", "post"),
        ] {
            assert!(human_only.contains(&(path.to_string(), method)), "{method} {path}");
        }
        assert_eq!(human_only.len(), 6, "{human_only:?}");
        let spec = tenant_openapi("buddytenant");
        for (path, method) in human_only {
            assert!(spec["paths"][&path][method].is_null(), "tenant doc advertises {method} {path} with api_key");
        }
        // Key-capable SOAR operations stay, on the key scheme.
        for (path, method) in [("/api/soar/settings", "get"), ("/api/soar/approvals", "get"), ("/api/soar/runs/{id}", "get"), ("/api/soar/flows/{id}/test", "post"), ("/api/soar/flows/test", "post")] {
            let operation = &spec["paths"][path][method];
            assert!(operation.is_object(), "missing tenant {method} {path}");
            assert_eq!(operation["security"], serde_json::json!([{ "api_key": [] }]), "{method} {path}");
        }
    }

    #[test]
    #[cfg(feature = "enterprise")]
    fn threat_intel_lookup_contract_is_published() {
        let spec = build_openapi();
        let item = |p: &str| spec.paths.paths.get(p).unwrap_or_else(|| panic!("missing {p}"));
        assert!(item("/api/threat-intel/providers").get.is_some());
        let provider = item("/api/threat-intel/providers/{provider}");
        assert!(provider.put.is_some() && provider.delete.is_some());
        let lookup = item("/api/threat-intel/lookup");
        assert!(lookup.post.is_some());
        assert!(item("/api/threat-intel/indicator-lookup").post.is_some());
        let body = serde_json::to_string(&spec.components).unwrap();
        for schema in ["ThreatIntelLookupRequest", "ThreatIntelLookupResponse", "ThreatIntelProviderResult", "ThreatIntelProviderStatus", "ThreatIntelProvidersResponse",
            "ThreatIntelIndicatorLookupRequest", "ThreatIntelIndicatorLookupResponse", "ThreatIntelIndicatorSourceMatches", "ThreatIntelIndicatorMatch"] {
            assert!(body.contains(&format!("\"{schema}\"")), "missing schema {schema}");
        }
    }

    #[test]
    #[cfg(feature = "enterprise")]
    fn pipe_inspection_contract_keeps_runtime_ops_private() {
        use nanosiem_enterprise::handlers::shared_pipe_capture::{SharedPipeCaptureApiDoc, PENDING_PATH, CLAIM_PATH, COMPLETE_PATH};
        let public = build_openapi();
        for path in ["/api/log-sources/{id}/pipe-capabilities", "/api/log-sources/{id}/pipe-preview",
            "/api/log-sources/{id}/pipe-recent-events", "/api/log-sources/{id}/pipe-inputs", "/api/log-sources/pipe-inputs", "/api/log-sources/{id}/capture-sessions", "/api/log-sources/{id}/capture-sessions/{session_id}"] {
            assert!(public.paths.paths.contains_key(path), "missing {path}");
        }
        let private = SharedPipeCaptureApiDoc::openapi();
        for path in [PENDING_PATH, CLAIM_PATH, COMPLETE_PATH] {
            assert!(!public.paths.paths.contains_key(path), "private runtime operation exposed");
            assert!(private.paths.paths.contains_key(path));
        }
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

    #[test]
    fn inputlookup_internal_auth_is_a_separate_service_scheme() {
        let spec = serde_json::to_value(build_openapi()).unwrap();
        assert!(spec["components"]["securitySchemes"].get("egress_service_bearer").is_some());
        assert_eq!(spec["paths"]["/internal/inputlookup/egress-check"]["post"]["security"][0], serde_json::json!({"egress_service_bearer": []}));
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

    /// NAN-2270 — two handler modules may not name two DIFFERENT schemas the
    /// same thing.
    ///
    /// `merge_sub_docs` merges with `extend`, so a duplicate name is resolved by
    /// merge order and the loser vanishes without a word. That is not a
    /// hypothetical: `hunts::ListSuppressionsResponse` (`Vec<HuntSuppression>`)
    /// and `siem_health_suppressions::ListSuppressionsResponse`
    /// (`Vec<FindingSuppression>`) collided, and because SIEM health merges
    /// later, the spec claimed `/api/hunts/suppressions` returns
    /// `FindingSuppression`. The generated TypeScript then repeated it.
    ///
    /// Nothing downstream can catch this — the spec stays internally consistent
    /// and both drift gates pass, because the wrong contract is generated
    /// faithfully from the wrong spec. It has to be caught at the merge.
    ///
    /// The baseline this test shipped with (15 more collisions, 9 of them
    /// enterprise-only) is now empty: every one was resolved with
    /// `#[schema(as = …)]`, which renames the SCHEMA without touching the Rust
    /// type. Duplicate Rust names across modules are fine — it is only the
    /// OpenAPI component registry that is flat.
    #[test]
    fn verify_no_schema_name_collisions() {
        use std::collections::HashMap;

        let mut seen: HashMap<String, serde_json::Value> = HashMap::new();
        let mut conflicts: Vec<String> = Vec::new();

        for sub in sub_docs() {
            let Some(components) = sub.components else {
                continue;
            };
            for (name, schema) in components.schemas {
                let rendered =
                    serde_json::to_value(&schema).expect("serialize schema for comparison");
                match seen.get(&name) {
                    // Same name, same definition: harmless — a shared type
                    // pulled into two sub-docs resolves to one entry.
                    Some(existing) if *existing == rendered => {}
                    Some(_) => conflicts.push(name.clone()),
                    None => {
                        seen.insert(name, rendered);
                    }
                }
            }
        }

        conflicts.sort();
        conflicts.dedup();

        assert!(
            conflicts.is_empty(),
            "these schema names are defined DIFFERENTLY by more than one handler module, so the \
             later merge silently overwrites the earlier one and its endpoints end up documented \
             with the wrong body: {conflicts:?}\n\n\
             Fix with `#[schema(as = QualifiedName)]` on the less canonical type — that renames \
             the SCHEMA only, leaving the Rust type and every import untouched. Do NOT add an \
             exemption list."
        );
    }

    /// NAN-2271 — `docs/api/openapi.json` is the PUBLISHED API reference, a
    /// committed artifact of `tools/export-openapi.sh`. Nothing regenerated it,
    /// and nothing failed when it wasn't: it drifted to 74 paths and 174
    /// schemas behind the code before anyone noticed. Whole product surfaces —
    /// Active Hunter, observability, reports, source scopes, trace search —
    /// were simply absent from the docs.
    ///
    /// NAN-3577 — compare the entire parsed document, so changes to existing
    /// operations, schema fields, security, servers, and descriptions also
    /// require regeneration. JSON equality ignores formatting and object key
    /// order while preserving every published value. This runs in the existing
    /// CI and pre-commit `openapi::tests` validation path without another build.
    ///
    /// Open build only: the script exports with default features, so under
    /// `--features enterprise` the fresh spec legitimately carries ~143 extra
    /// paths and comparing them would be meaningless.
    #[test]
    #[cfg(not(feature = "enterprise"))]
    fn verify_published_api_docs_are_current() {
        // `tools/sync-to-nano-mirror.sh` deletes ITSELF along with docs/, so its
        // absence is a precise "this tree was stripped" signal. Keyed on that
        // rather than on the spec being missing — a missing spec is exactly the
        // failure this test exists to catch, and must never be self-excusing.
        let repo_root = concat!(env!("CARGO_MANIFEST_DIR"), "/..");
        if !std::path::Path::new(&format!("{repo_root}/tools/sync-to-nano-mirror.sh")).is_file() {
            eprintln!("skipping published API docs check: stripped tree (mirror)");
            return;
        }

        let committed_path = format!("{repo_root}/docs/api/openapi.json");
        let raw = std::fs::read_to_string(&committed_path).unwrap_or_else(|err| {
            panic!(
                "read published API spec {committed_path}: {err}\n\n\
                 This is a full checkout, so the file should be here. Regenerate it:\n  \
                 bash tools/export-openapi.sh"
            )
        });
        let committed: serde_json::Value =
            serde_json::from_str(&raw).expect("parse published API spec");
        let fresh = serde_json::to_value(build_openapi()).expect("serialize fresh spec");

        /// Sorted keys of the object at `pointer`, empty when absent.
        fn keys_at(spec: &serde_json::Value, pointer: &str) -> Vec<String> {
            let mut v: Vec<String> = spec
                .pointer(pointer)
                .and_then(|n| n.as_object())
                .map(|m| m.keys().cloned().collect())
                .unwrap_or_default();
            v.sort();
            v
        }

        let committed_paths = keys_at(&committed, "/paths");
        let fresh_paths = keys_at(&fresh, "/paths");
        let committed_schemas = keys_at(&committed, "/components/schemas");
        let fresh_schemas = keys_at(&fresh, "/components/schemas");

        // An empty side would make every comparison below pass or fail
        // vacuously; both specs must actually have content.
        assert!(
            !fresh_paths.is_empty() && !committed_paths.is_empty(),
            "one side has no paths at all (committed {}, fresh {}) — the comparison would be \
             meaningless",
            committed_paths.len(),
            fresh_paths.len()
        );

        let missing_paths: Vec<&String> =
            fresh_paths.iter().filter(|p| !committed_paths.contains(p)).collect();
        let stale_paths: Vec<&String> =
            committed_paths.iter().filter(|p| !fresh_paths.contains(p)).collect();
        let missing_schemas: Vec<&String> =
            fresh_schemas.iter().filter(|s| !committed_schemas.contains(s)).collect();
        let stale_schemas: Vec<&String> =
            committed_schemas.iter().filter(|s| !fresh_schemas.contains(s)).collect();
        let changed_paths: Vec<&String> = fresh_paths
            .iter()
            .filter(|p| committed_paths.contains(p) && committed["paths"][*p] != fresh["paths"][*p])
            .collect();
        let changed_schemas: Vec<&String> = fresh_schemas
            .iter()
            .filter(|s| {
                committed_schemas.contains(s)
                    && committed["components"]["schemas"][*s] != fresh["components"]["schemas"][*s]
            })
            .collect();
        let changed_sections: Vec<String> = keys_at(&committed, "")
            .into_iter()
            .chain(keys_at(&fresh, ""))
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .filter(|key| committed.get(key) != fresh.get(key))
            .collect();

        assert!(
            committed == fresh,
            "docs/api/openapi.json is STALE — the published API reference no longer matches the \
             code.\n\n\
             undocumented endpoints ({}): {missing_paths:?}\n\
             documented but gone ({}): {stale_paths:?}\n\
             undocumented schemas ({}): {missing_schemas:?}\n\
             documented but gone ({}): {stale_schemas:?}\n\n\
             changed existing endpoints ({}): {changed_paths:?}\n\
             changed existing schemas ({}): {changed_schemas:?}\n\
             changed document sections: {changed_sections:?}\n\n\
             Regenerate:\n  bash tools/export-openapi.sh\n\n\
             Then skim the diff — a newly appearing path is a surface you are about to publish.",
            missing_paths.len(),
            stale_paths.len(),
            missing_schemas.len(),
            stale_schemas.len(),
            changed_paths.len(),
            changed_schemas.len(),
        );
    }

    /// NAN-2263 / NAN-2312 — the desktop's hunting and playbook-library
    /// TypeScript is GENERATED from
    /// `nano-desktop/openapi/hunts-wire.json`. If the server's wire shapes move
    /// and that file does not, the desktop compiles against a contract the
    /// server no longer honours — which is exactly how ~30 silent mismatches
    /// shipped with a green suite. This test regenerates the scoped spec and
    /// fails when the committed copy differs.
    ///
    /// The committed file lives in `nano-desktop/`, which the open-core strip
    /// removes (`tools/sync-to-nano-mirror.sh`), so — like
    /// `verify_log_source_transport_ownership_contract` (NAN-2169) — the file
    /// is read at RUNTIME and only a genuinely absent file skips the
    /// comparison. Any other IO error stays loud.
    #[test]
    fn verify_desktop_wire_spec_is_current() {
        let generated = desktop_wire_spec();

        // Sanity floors first, so an over-narrow filter cannot make the
        // comparison below pass vacuously (an empty spec matching an empty
        // file guarantees nothing).
        let path_count = generated["paths"].as_object().map_or(0, |m| m.len());
        assert!(
            path_count >= 22,
            "desktop wire spec collapsed to {path_count} paths — the path filter broke"
        );
        for schema in [
            "Hunt",
            "HuntSummary",
            "HuntLead",
            "HuntLeadDetail",
            "HuntSweep",
            "HuntRuleIdea",
            "HuntSuppression",
            "HuntKnowledge",
            "HuntProfile",
            "ListLeadsResponse",
            "ListRuleIdeasResponse",
            "ParsedStepTree",
            "TrailStep",
            "Contribution",
            "CensusRow",
            "OrgFingerprint",
            "HuntableSurface",
            "PlaybookRepository",
            "ListPlaybookRepositoriesResponse",
            "SyncAndImportResponse",
        ] {
            assert!(
                generated["components"]["schemas"].get(schema).is_some(),
                "desktop wire spec lost schema {schema}"
            );
        }

        let committed_path =
            concat!(env!("CARGO_MANIFEST_DIR"), "/../nano-desktop/openapi/hunts-wire.json");
        // Skip ONLY in the stripped mirror, which is identified by the whole
        // `nano-desktop/` tree being gone. A missing spec file inside a tree
        // that still HAS nano-desktop means the file was deleted or renamed —
        // that must fail, or the gate quietly becomes a no-op (the exact way
        // this check was already dead in CI).
        let desktop_root = concat!(env!("CARGO_MANIFEST_DIR"), "/../nano-desktop");
        if !std::path::Path::new(desktop_root).is_dir() {
            eprintln!(
                "skipping desktop wire spec drift check: {desktop_root} absent (open-core stripped tree)"
            );
            return;
        }
        let committed = std::fs::read_to_string(committed_path).unwrap_or_else(|err| {
            panic!(
                "read committed desktop wire spec {committed_path}: {err}\n\n\
                 nano-desktop/ exists, so this is NOT the stripped mirror — the spec was deleted \
                 or renamed. Regenerate it:\n  \
                 cargo run -p nanosiem-api --bin export_openapi -- --desktop-wire > nano-desktop/openapi/hunts-wire.json"
            )
        });
        let committed: serde_json::Value =
            serde_json::from_str(&committed).expect("parse committed desktop wire spec");

        // Value comparison, not text: `serde_json` map equality is
        // order-insensitive, so a feature set that changes key ordering
        // (preserve_order on/off) cannot fake drift.
        if committed != generated {
            panic!(
                "nano-desktop/openapi/hunts-wire.json is STALE — the server's desktop wire \
                 contract moved. Regenerate the spec and the TypeScript it feeds:\n\n  \
                 cargo run -p nanosiem-api --bin export_openapi -- --desktop-wire > nano-desktop/openapi/hunts-wire.json\n  \
                 (cd nano-desktop && npm run generate:api-types)\n\n\
                 then fix whatever the desktop compiler now rejects — each error is a real \
                 client/server mismatch, not noise."
            );
        }
    }

    #[cfg(feature="enterprise")]
    #[test]
    fn guarded_cell_feature_contract_and_fence() {
        let spec=serde_json::to_value(build_openapi()).unwrap();
        let op=&spec["paths"]["/api/agent/features"]["post"];
        assert!(op["responses"]["429"]["description"].as_str().unwrap().contains("budget"));
        assert_eq!(nanosiem_enterprise::handlers::enterprise_shared_enrichment::enterprise_shared_enrichment_fence(&axum::http::Method::POST,"/api/agent/features"),Some("search:execute"));
        let request=&spec["components"]["schemas"]["FeatureRequest"];
        assert!(request["required"].as_array().unwrap().iter().any(|v|v=="reason"));
        assert_eq!(request["additionalProperties"],false);
    }
}
