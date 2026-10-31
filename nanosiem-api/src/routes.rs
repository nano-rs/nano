// SPDX-License-Identifier: AGPL-3.0-or-later

//! API route definitions

use nanosiem_api_lib::route_policy::{Router, routing::{delete, get, patch, post, put}};
use nanosiem_core::auth::route_policy::RoutePolicy;
use axum::{
    extract::DefaultBodyLimit,
    http::{header, HeaderName, HeaderValue},
    middleware as axum_middleware,
};
use std::sync::Arc;
use tower_http::compression::CompressionLayer;
use tower_http::cors::CorsLayer;
use tower_http::set_header::SetResponseHeaderLayer;

/// Maximum upload file size: 100MB + overhead for multipart encoding
const MAX_UPLOAD_SIZE: usize = 105 * 1024 * 1024;

/// Body limit for the artifact-analysis store (NAN-1977). Sized above the
/// handler's per-field caps (specimen `original`/`deobfuscated` at 4 MiB each +
/// the structured JSON fields) so the handler's clean 400 — not axum's 2 MiB
/// default 413 — is the authoritative rejection for oversized specimens.
const ARTIFACT_BODY_LIMIT: usize = 12 * 1024 * 1024;

/// Max size for an air-gap import bundle. The IPinfo-Lite enrichment payload is
/// ~400MB uncompressed; the compressed `.tar.gz` is buffered before the
/// streaming verify/parse, so the cap must comfortably exceed the 105MB upload
/// limit. Enterprise-only — the import surface ships only in the enterprise edition.
#[cfg(feature = "enterprise")]
const MAX_AIRGAP_BUNDLE_SIZE: usize = 1024 * 1024 * 1024;

#[cfg(feature = "enterprise")]
use crate::middleware::rate_limit::marketplace_preview_rate_limit_middleware;
use crate::{
    config::ApiConfig,
    handlers,
    middleware::{
        auth::{auth_middleware, AuthState},
        ip_allowlist::{ip_allowlist_middleware, IpAllowlistState},
        rate_limit::{
            detection_code_probe_rate_limit_middleware, dry_resolve_rate_limit_middleware,
            kafka_probe_rate_limit_middleware, login_rate_limit_middleware,
            mfa_setup_rate_limit_middleware, password_reset_rate_limit_middleware,
            upload_rate_limit_middleware, RateLimitState,
        },
        request_id_middleware, request_logging_layer,
    },
    openapi,
    state::AppState,
};
use nanosiem_core::hunts::recon::PROFILE_BODY_LIMIT_BYTES;
use nanosiem_core::ip_allowlist::IpAllowlistScope;

/// Private hosted-producer diagnostics. The public app never mounts this router.
#[cfg(not(feature = "enterprise"))]
pub(crate) fn registered_hosted_config_routes() -> Router { Router::new() }
#[cfg(feature = "enterprise")]
pub(crate) fn registered_hosted_config_routes() -> Router {
    Router::new().route("/internal/hosted-config", get(|| async {
        axum::Json(nanosiem_core::search::hosted_producer_reload::process_hosted_config_status())
    }, RoutePolicy::service("hosted-config-reader", "telemetry:read")))
}
pub fn hosted_config_router() -> axum::Router {
    registered_hosted_config_routes().into_private_router(
        nanosiem_api_lib::route_policy::ServiceAuthenticators::default()
            .bearer("hosted-config-reader", std::env::var("METRICS_AUTH_TOKEN").ok(), "x-nano-service-authorization"))
}

/// Private SOAR egress app, authenticated as its proxy service.
#[cfg(feature = "enterprise")]
pub fn soar_egress_router(state: &AppState) -> axum::Router {
    let resolver = state
        .config
        .deployment_mode
        .is_enterprise_shared()
        .then(|| nanosiem_core::auth::TenantMembershipResolver::new(state.pool.clone()));
    nanosiem_enterprise::soar::egress::router(state.soar_service.clone(), resolver)
}
#[cfg(not(feature = "enterprise"))]
pub fn soar_egress_router(_state: &AppState) -> axum::Router {
    axum::Router::new()
}

/// Reserved private service port; never publish it through a public ingress.
pub const INTERNAL_API_PORT: u16 = 13000;

fn registered_internal_routes(state: &AppState, metrics: &crate::metrics::AppMetrics, admission_file: &std::path::Path) -> Router {
    let app = Router::new()
        .route("/api/internal/vector-config/current/manifest", get(
            handlers::vector_config_delivery::get_current_manifest,
            RoutePolicy::service("vector-config-consumer", "vector-config:read")))
        .route("/api/internal/vector-config/generations/{generation}/files/{*path}", get(
            handlers::vector_config_delivery::get_generation_file,
            RoutePolicy::service("vector-config-consumer", "vector-config:read")));
    #[cfg(feature = "enterprise")]
    let dedicated = !state.config.deployment_mode.is_enterprise_shared();
    #[cfg(not(feature = "enterprise"))]
    let dedicated = true;
    let app = app.route_if(dedicated, "/api/internal/otlp-auth", get(
        handlers::ingest_tokens::authenticate_otlp,
        RoutePolicy::service("ingress-proxy", "ingest:authenticate")))
        .with_inner_state(state.clone())
        .merge(metrics.registered_routes())
        .merge(registered_hosted_config_routes())
        .merge(handlers::egress::runtime_registered_router(state,
            admission_file));
    #[cfg(feature = "enterprise")]
    let app = {
        let resolver = state.config.deployment_mode.is_enterprise_shared()
            .then(|| nanosiem_core::auth::TenantMembershipResolver::new(state.pool.clone()));
        app.merge(nanosiem_enterprise::soar::egress::registered_router(state.soar_service.clone(), resolver))
    };
    app
}

pub fn internal_route_manifest(state: &AppState, metrics: &crate::metrics::AppMetrics)
    -> Vec<nanosiem_api_lib::route_policy::Entry> {
    registered_internal_routes(state, metrics, std::path::Path::new(handlers::egress::RUNTIME_ADMISSION_PATH)).manifest().to_vec()
}

/// Complete private app. Service identity resolution runs before RoutePolicy;
/// missing credentials/configuration deny before body extraction or owner work.
pub fn create_internal_router(state: &AppState, metrics: &crate::metrics::AppMetrics) -> axum::Router {
    internal_router_with_admission(state, metrics, std::path::Path::new(handlers::egress::RUNTIME_ADMISSION_PATH))
}
fn internal_router_with_admission(state: &AppState, metrics: &crate::metrics::AppMetrics, admission_file: &std::path::Path) -> axum::Router {
    use nanosiem_api_lib::route_policy::ServiceAuthenticators;
    let vector = std::env::var("VECTOR_AUTH_TOKEN").ok();
    let key = nanosiem_core::egress::key_from_env().ok();
    let auth = ServiceAuthenticators::default()
        .bearer("operations-collector", std::env::var("METRICS_AUTH_TOKEN").ok(), "authorization")
        .bearer("hosted-config-reader", std::env::var("METRICS_AUTH_TOKEN").ok(), "x-nano-service-authorization")
        .bearer("vector-config-consumer", vector.clone(), "authorization")
        .bearer("ingress-proxy", vector, "x-nano-service-authorization")
        .bearer("soar-egress-proxy", std::env::var("NANOSIEM_SOAR_EGRESS_CHECK_TOKEN").ok(), "authorization")
        .register("egress-proxy", move |headers| {
            key.as_ref().is_some_and(|key| handlers::egress::verify_private_principal(key,headers).is_ok())
        });
    registered_internal_routes(state, metrics, admission_file).into_private_router(auth)
}

/// Capabilities `nanosiem-api` and `nanosiem-jobs` report to
/// `--print-features` (NAN-3531 N2a). Only the enterprise build carries the
/// live hosted producer reload.
#[cfg(feature = "enterprise")]
pub const APP_FEATURES: &[&str] = &[nanosiem_core::search::hosted_producer_reload::HOSTED_CONFIG_DIR_FEATURE];
#[cfg(not(feature = "enterprise"))]
pub const APP_FEATURES: &[&str] = &[];

fn register_routes(state: &AppState) -> Router<AppState> {
    let config = state.config.clone();
    // NAN-2361: in hosted-shared mode every product area is served by its
    // tenant-transaction-scoped port (mounted below); the legacy handlers for
    // the same paths are not registered at all, so a shared tenant can never
    // reach a deployment-global handler and axum never sees a duplicate route.
    #[cfg(feature = "enterprise")]
    let shared_product = config.deployment_mode.is_enterprise_shared();
    #[cfg(not(feature = "enterprise"))]
    let shared_product = false;
    // NAN-3463: AI-tuning breaches, proposals and logs read tables that exist
    // only under the enterprise overlay (`detection_threshold_breaches`,
    // `tuning_proposals`, `tuning_logs`). The open edition does not mount them,
    // so they answer 404 instead of a 500. Rule versions, baselines, metrics,
    // settings and notifications are open and stay mounted.
    let ai_tuning_routes = cfg!(feature = "enterprise") && !shared_product;

    // Build rate limit state for auth endpoints (PostgreSQL-backed, shared across nodes)
    let rate_limit_state = Arc::new(RateLimitState::from_env(state.pool.clone()));

    // Rate-limited login route
    let login_route = Router::new()
        .route("/api/auth/login", post(handlers::auth::login, RoutePolicy::public()))
        .layer(axum_middleware::from_fn_with_state(
            (*rate_limit_state).clone(),
            login_rate_limit_middleware,
        ));

    // Rate-limited password reset routes
    // SECURITY: Both reset-request AND reset (token redemption) are rate-limited
    // to prevent brute-force attacks on reset tokens.
    let password_reset_routes = Router::new()
        .route(
            "/api/auth/password/reset-request",
            post(handlers::auth::request_password_reset, RoutePolicy::public()),
        )
        .route(
            "/api/auth/password/reset",
            post(handlers::auth::reset_password, RoutePolicy::public()),
        )
        .layer(axum_middleware::from_fn_with_state(
            (*rate_limit_state).clone(),
            password_reset_rate_limit_middleware,
        ));

    // Rate-limited MFA challenge route (same rate limit as login)
    let mfa_challenge_route = Router::new()
        .route(
            "/api/auth/mfa/challenge",
            post(handlers::mfa::verify_mfa_challenge, RoutePolicy::public()),
        )
        .layer(axum_middleware::from_fn_with_state(
            (*rate_limit_state).clone(),
            login_rate_limit_middleware,
        ));

    // Rate-limited MFA setup + verify-setup routes. Both are public
    // (challenge_token-authenticated for forced enrollment), so without a
    // limiter they're a brute-force surface for the 6-digit TOTP and an
    // amplifier for repeated encryption-service calls. Uses the dedicated
    // `mfa_setup_ip` bucket (NAN-592) — separate from `login_ip` so a
    // busy login window doesn't exhaust the budget for users currently
    // enrolling, and sized higher to accommodate corporate NAT.
    let mfa_setup_routes = Router::new()
        .route("/api/auth/mfa/setup", post(handlers::mfa::setup_mfa, RoutePolicy::public()))
        .route(
            "/api/auth/mfa/verify-setup",
            post(handlers::mfa::verify_mfa_setup, RoutePolicy::public()),
        )
        .layer(axum_middleware::from_fn_with_state(
            (*rate_limit_state).clone(),
            mfa_setup_rate_limit_middleware,
        ));

    // Rate-limited upload routes (prevents DoS via large file uploads)
    // Body limit is enforced at HTTP layer before loading into memory
    // Note: Log upload removed - logs go through Vector ingestion pipeline
    let upload_routes = Router::new()
        .route_if(!shared_product, "/api/upload/preview", post(handlers::preview_upload, RoutePolicy::any_of(&["upload:logs", "lookup:create"])))
        .layer(DefaultBodyLimit::max(MAX_UPLOAD_SIZE))
        .layer(axum_middleware::from_fn_with_state(
            (*rate_limit_state).clone(),
            upload_rate_limit_middleware,
        ));

    // Artifact-analysis store (NAN-1977) — shared, RBAC-scoped. Its own sub-router
    // so create/update carry a body limit above the specimen caps (see
    // ARTIFACT_BODY_LIMIT) rather than inheriting axum's 2 MiB default; GET/DELETE
    // ride along harmlessly. Auth is applied as an outer layer after the merge.
    let artifact_routes = Router::new()
        .route_if(!shared_product, "/api/artifacts", get(handlers::artifacts::list_artifacts, RoutePolicy::all_of(&["artifacts:view"])))
        .route_if(!shared_product, "/api/artifacts", post(handlers::artifacts::create_artifact, RoutePolicy::all_of(&["artifacts:create"])))
        .route_if(!shared_product, 
            "/api/artifacts/{id}",
            get(handlers::artifacts::get_artifact, RoutePolicy::all_of(&["artifacts:view"])),
        )
        .route_if(!shared_product, 
            "/api/artifacts/{id}",
            put(handlers::artifacts::update_artifact, RoutePolicy::all_of(&["artifacts:edit"])),
        )
        .route_if(!shared_product, 
            "/api/artifacts/{id}",
            delete(handlers::artifacts::delete_artifact, RoutePolicy::all_of(&["artifacts:delete"])),
        )
        .layer(DefaultBodyLimit::max(ARTIFACT_BODY_LIMIT));

    // Air-gapped bundle import routes (NAN-1201) — enterprise only. These accept
    // large signed `.tar.gz` bundles (the IPinfo enrichment payload dwarfs the
    // 105MB upload cap), so they live in their own sub-router with a much larger
    // DefaultBodyLimit rather than inheriting axum's 2MB default. The license
    // import route is registered separately (tiny payload, license-guard-exempt).
    #[cfg(feature = "enterprise")]
    let airgap_import_routes = Router::new()
        .route(
            "/api/airgap/parsers/import",
            post(handlers::airgap::parsers::import_parser_bundle, RoutePolicy::all_of(&["parser_repositories:import"])),
        )
        .route(
            "/api/airgap/enrichment/import",
            post(handlers::airgap::enrichment::import_enrichment_bundle, RoutePolicy::all_of(&["enrichments:configure"])),
        )
        .route(
            "/api/airgap/rules/import",
            post(handlers::airgap::rules::import_rule_bundle, RoutePolicy::all_of(&["rule_repositories:import"])),
        )
        .route(
            "/api/airgap/playbooks/import",
            post(handlers::airgap::playbooks::import_playbook_bundle, RoutePolicy::all_of(&["playbook_repositories:import"])),
        )
        .layer(DefaultBodyLimit::max(MAX_AIRGAP_BUNDLE_SIZE));

    // NAN-474: dry-resolve is rate-limited per authenticated user because
    // templating cost scales with `{{...}}` token count. The middleware
    // runs inside the outer auth layer, so `AuthContext` is available.
    let dry_resolve_routes = Router::new()
        .route_if(!shared_product, 
            "/api/playbooks/dry-resolve",
            post(handlers::playbooks::dry_resolve, RoutePolicy::all_of(&["playbooks:manage"])),
        )
        .layer(axum_middleware::from_fn_with_state(
            (*rate_limit_state).clone(),
            dry_resolve_rate_limit_middleware,
        ));

    // NAN-939 H3: Kafka broker reachability probe is rate-limited per
    // authenticated user. Each call can hold a worker for up to
    // `(DNS + TCP) × MAX_BROKERS` ms, and the endpoint dials caller-supplied
    // addresses — without a per-user cap it's a DoS + port-scan amplifier.
    let kafka_probe_routes = Router::new()
        .route_if(!shared_product, 
            "/api/source-configurations/{id}/rules/check-reachability",
            post(handlers::source_configs::check_routing_rule_reachability, RoutePolicy::all_of(&["source_configs:view"])),
        )
        .layer(axum_middleware::from_fn_with_state(
            (*rate_limit_state).clone(),
            kafka_probe_rate_limit_middleware,
        ));

    // NAN-2064: this probe decrypts a stored GitHub PAT and spends external API
    // budget. Keep it out of the general route tree so every invocation is
    // rate-limited per interactive user/API key and target.
    let detection_code_probe_routes = Router::new()
        .route_if(!shared_product, 
            "/api/detection-code-targets/{id}/test",
            post(handlers::detection_code_targets::test_connection, RoutePolicy::all_of(&["detection_code_targets:manage"])),
        )
        .layer(axum_middleware::from_fn_with_state(
            (*rate_limit_state).clone(),
            detection_code_probe_rate_limit_middleware,
        ));

    // NAN-2062: preview can decrypt saved provider credentials, execute Deno
    // code, and make outbound requests. Every call is rate-limited per
    // interactive user/API key and provider slug.
    #[cfg(feature = "enterprise")]
    let marketplace_preview_routes = Router::new()
        .route_if(!shared_product, 
            "/api/marketplace/catalog/{slug}/preview",
            post(handlers::marketplace::preview_enrichment, RoutePolicy::all_of(&["enrichments:configure"])),
        )
        .layer(axum_middleware::from_fn_with_state(
            (*rate_limit_state).clone(),
            marketplace_preview_rate_limit_middleware,
        ));

    // Cacheable route groups with Cache-Control headers
    // Static metadata - 5 minute browser cache
    let cached_metadata = Router::new()
        .route_if(!shared_product, "/api/udm/fields", get(handlers::get_udm_fields, RoutePolicy::all_of(&["search:view"])))
        .route_if(!shared_product, "/api/schema/fields", get(handlers::get_schema_fields, RoutePolicy::all_of(&["search:view"])))
        .route_if(!shared_product, "/api/source-types", get(handlers::get_source_types, RoutePolicy::any_of(&nanosiem_api_lib::SOURCE_INVENTORY_CAPS)))
        .route_if(!shared_product, "/api/permissions", get(handlers::roles::list_permissions, RoutePolicy::all_of(&["roles:view"])))
        .route_if(!shared_product, "/api/audit/actions", get(handlers::audit::get_action_types, RoutePolicy::all_of(&["audit:view"])))
        .route_if(!shared_product, 
            "/api/audit/resource-types",
            get(handlers::audit::get_resource_types, RoutePolicy::all_of(&["audit:view"])),
        )
        .layer(SetResponseHeaderLayer::overriding(
            header::CACHE_CONTROL,
            HeaderValue::from_static("private, max-age=300, stale-while-revalidate=60"),
        ));

    // ATT&CK catalog data changes only on manual sync, so a populated catalog
    // keeps the longer browser cache. The handler sets Cache-Control itself so
    // it can drop the cache to `no-store` while the catalog is empty (the boot/
    // seed window) and avoid pinning an empty catalog for an hour (NAN-1766 /
    // D5). This layer is `if_not_present` so it only supplies a default when the
    // handler somehow didn't set the header.
    let cached_mitre = Router::new()
        .route_if(!shared_product, "/api/mitre", get(handlers::mitre::get_mitre_data, RoutePolicy::all_of(&["mitre:view"])))
        .layer(SetResponseHeaderLayer::if_not_present(
            header::CACHE_CONTROL,
            HeaderValue::from_static("private, max-age=3600, stale-while-revalidate=300"),
        ));

    // Coverage includes live ingestion readiness. Keep it briefly cacheable
    // without allowing the previous one-hour catalog cache to hide a source
    // becoming active or stale.
    let cached_mitre_coverage = Router::new()
        .route_if(!shared_product, 
            "/api/mitre/coverage",
            get(handlers::mitre::get_mitre_coverage, RoutePolicy::all_of(&["mitre:view", "detections:view"])),
        )
        .layer(SetResponseHeaderLayer::overriding(
            header::CACHE_CONTROL,
            HeaderValue::from_static("private, max-age=30, stale-while-revalidate=30"),
        ));

    // Demo routes — only registered when DEPLOYMENT_MODE=demo.
    // Non-demo deployments don't have these paths at all (404, not 503).
    let demo_routes = if config.deployment_mode.is_demo() {
        Some(
            Router::new()
                .route(
                    "/api/demo/session",
                    post(handlers::demo::create_demo_session, RoutePolicy::public()),
                )
                .route(
                    "/api/demo/session/status",
                    get(handlers::demo::get_demo_session_status, RoutePolicy::authenticated()),
                )
                .route(
                    "/api/demo/session/{token}/claim",
                    post(handlers::demo::claim_demo_token, RoutePolicy::public()),
                ),
        )
    } else {
        None
    };

    // Build the router
    let mut app = Router::new()

        // Health check (public - minimal info only)
        .route("/health", get(handlers::health_check, RoutePolicy::public()))
        .route("/ready", get(handlers::ready_check, RoutePolicy::public()))
        // Shallow liveness/readiness probe — no dep checks (NAN-1786). What k8s
        // liveness/readiness probes should target; /health and /ready are deep
        // (dependency-gated) and are for monitoring, not probes.
        .route("/livez", get(handlers::livez, RoutePolicy::public()))
        // Detailed health check (authenticated - full diagnostics)
        .route("/health/detailed", get(handlers::health_check_detailed, RoutePolicy::all_of(&["settings:system"])))
        // Build edition + capability flags (public; the SPA hits this on boot
        // before login to decide which surfaces to render). NAN-745.
        .route_if(!shared_product, 
            "/api/capabilities",
            get(handlers::capabilities::get_capabilities, RoutePolicy::public()),
        )
        // Setup endpoints (public - for first-run setup)
        .route_if(!shared_product, "/api/setup/status", get(handlers::setup::get_setup_status, RoutePolicy::public()))
        .route(
            "/api/setup/initialize",
            post(handlers::setup::initialize_system, RoutePolicy::public()),
        )
        // Authentication endpoints (public) - rate-limited routes merged in
        .merge(login_route)
        .route("/api/auth/logout", post(handlers::auth::logout, RoutePolicy::interactive_session()))
        .route("/api/auth/refresh", post(handlers::auth::refresh_token, RoutePolicy::public()))
        // NAN-2181: public — the login page needs this before anyone has
        // authenticated, to know whether to offer a password field at all.
        // Listed in PUBLIC_ENDPOINTS; registered here beside the other auth
        // routes rather than in the rate-limited group, since it is a cheap
        // read of one boolean and gates nothing.
        .route("/api/auth/methods", get(handlers::auth::get_auth_methods, RoutePolicy::public()))
        .merge(password_reset_routes)
        .route("/api/auth/password", put(handlers::auth::change_password, RoutePolicy::interactive_session()))
        .route("/api/auth/me", get(handlers::auth::get_current_user, RoutePolicy::interactive_session()))
        .route("/api/auth/validate", get(handlers::auth::validate_token, RoutePolicy::authenticated()))
        // Authenticated server-owned plan + component snapshot for the exact
        // hosted-shared tenant. The handler is 404 outside that profile;
        // the auth middleware keeps it inside the narrow shared shell fence.
        .route(
            "/api/auth/tenant-bootstrap",
            get(handlers::capabilities::get_tenant_capabilities, RoutePolicy::authenticated()),
        )
        // MFA endpoints
        .merge(mfa_challenge_route)
        .merge(mfa_setup_routes)
        .route("/api/auth/mfa/status", get(handlers::mfa::get_mfa_status, RoutePolicy::interactive_session()))
        .route("/api/auth/mfa", delete(handlers::mfa::disable_mfa, RoutePolicy::interactive_session()))
        .route(
            "/api/auth/mfa/backup-codes",
            post(handlers::mfa::regenerate_backup_codes, RoutePolicy::interactive_session()),
        )
        .route(
            "/api/admin/users/{id}/mfa",
            delete(handlers::mfa::admin_reset_mfa, RoutePolicy::all_of(&["users:edit"])),
        )
        .route_if(!shared_product, 
            "/api/settings/mfa-required",
            put(handlers::mfa::set_mfa_required, RoutePolicy::all_of(&["settings:system"])),
        )
        // OIDC authentication endpoints — gated to enterprise (NAN-745).
        // Registered below in the enterprise-only block.
        // User management endpoints
        .route_if(!shared_product, "/api/users", get(handlers::users::list_users, RoutePolicy::all_of(&["users:view"])))
        .route_if(!shared_product, "/api/users", post(handlers::users::create_user, RoutePolicy::all_of(&["users:create"])))
        // User preferences (must be before {id} routes)
        .route_if(!shared_product, 
            "/api/users/me/preferences",
            get(handlers::users::get_my_preferences, RoutePolicy::interactive_session()),
        )
        .route_if(!shared_product, 
            "/api/users/me/preferences",
            patch(handlers::users::update_my_preferences, RoutePolicy::interactive_session()),
        )
        .route_if(!shared_product, "/api/users/{id}", get(handlers::users::get_user, RoutePolicy::all_of(&["users:view"])))
        .route_if(!shared_product, "/api/users/{id}", put(handlers::users::update_user, RoutePolicy::all_of(&["users:edit"])))
        .route_if(!shared_product, "/api/users/{id}", delete(handlers::users::delete_user, RoutePolicy::all_of(&["users:delete"])))
        .route(
            "/api/users/{id}/groups",
            put(handlers::users::update_user_groups, RoutePolicy::all_of(&["users:edit"])),
        )
        .route_if(!shared_product, "/api/users/{id}/unlock", post(handlers::users::unlock_user, RoutePolicy::all_of(&["users:edit"])))
        .route_if(!shared_product, 
            "/api/users/{id}/disable",
            post(handlers::users::disable_user, RoutePolicy::all_of(&["users:edit"])),
        )
        .route_if(!shared_product, "/api/users/{id}/enable", post(handlers::users::enable_user, RoutePolicy::all_of(&["users:edit"])))
        // Group management endpoints
        .route_if(!shared_product, "/api/groups", get(handlers::groups::list_groups, RoutePolicy::all_of(&["groups:view"])))
        .route_if(!shared_product, "/api/groups", post(handlers::groups::create_group, RoutePolicy::all_of(&["groups:create"])))
        .route_if(!shared_product, "/api/groups/{id}", get(handlers::groups::get_group, RoutePolicy::all_of(&["groups:view"])))
        .route_if(!shared_product, "/api/groups/{id}", put(handlers::groups::update_group, RoutePolicy::all_of(&["groups:edit"])))
        .route_if(!shared_product, "/api/groups/{id}", delete(handlers::groups::delete_group, RoutePolicy::all_of(&["groups:delete"])))
        .route_if(!shared_product, 
            "/api/groups/{id}/roles",
            put(handlers::groups::update_group_roles, RoutePolicy::all_of(&["groups:edit"])),
        )
        .route_if(!shared_product, 
            "/api/groups/{id}/members",
            get(handlers::groups::get_group_members, RoutePolicy::all_of(&["groups:view"])),
        )
        // Role management endpoints
        .route_if(!shared_product, "/api/roles", get(handlers::roles::list_roles, RoutePolicy::all_of(&["roles:view"])))
        .route_if(!shared_product, "/api/roles", post(handlers::roles::create_role, RoutePolicy::all_of(&["roles:create"])))
        .route_if(!shared_product, "/api/roles/{id}", get(handlers::roles::get_role, RoutePolicy::all_of(&["roles:view"])))
        .route_if(!shared_product, "/api/roles/{id}", put(handlers::roles::update_role, RoutePolicy::all_of(&["roles:edit"])))
        .route_if(!shared_product, "/api/roles/{id}", delete(handlers::roles::delete_role, RoutePolicy::all_of(&["roles:delete"])))
        // Session management endpoints
        .route_if(!shared_product, "/api/sessions", get(handlers::sessions::list_all_sessions, RoutePolicy::all_of(&["sessions:admin"])))
        .route_if(!shared_product, 
            "/api/sessions/me",
            get(handlers::sessions::list_my_sessions, RoutePolicy::interactive_session()),
        )
        .route_if(!shared_product, 
            "/api/sessions/count",
            get(handlers::sessions::count_sessions, RoutePolicy::interactive_or_all_of(&["users:view"])),
        )
        .route_if(!shared_product, "/api/sessions/{id}", get(handlers::sessions::get_session, RoutePolicy::interactive_or_all_of(&["users:view"])))
        .route_if(!shared_product, 
            "/api/sessions/{id}",
            delete(handlers::sessions::terminate_session, RoutePolicy::interactive_or_all_of(&["users:edit"])),
        )
        .route_if(!shared_product, 
            "/api/sessions/user/{user_id}",
            delete(handlers::sessions::terminate_user_sessions, RoutePolicy::interactive_or_all_of(&["users:edit"])),
        )
        // Audit log endpoints
        .route("/api/audit", get(handlers::audit::query_audit_logs, RoutePolicy::all_of(&["audit:view"])))
        .route_if(!shared_product, 
            "/api/audit/export",
            post(handlers::audit::export_audit_logs, RoutePolicy::all_of(&["audit:view"])),
        )
        // NOTE: Core search endpoints (/api/search, /api/search/sql, /api/search/explain,
        // /api/search/saved/*) moved to nanosiem-search service (port 3002) and are routed
        // there via nginx.
        // Search history (per-user) - remains in Main API
        .route_if(!shared_product, 
            "/api/search/history",
            get(handlers::search_history::list_history, RoutePolicy::interactive_all_of(&["search:view"])),
        )
        .route_if(!shared_product, 
            "/api/search/history",
            post(handlers::search_history::add_history, RoutePolicy::interactive_all_of(&["search:execute"])),
        )
        .route_if(!shared_product, 
            "/api/search/history",
            delete(handlers::search_history::clear_history, RoutePolicy::interactive_all_of(&["search:execute"])),
        )
        .route_if(!shared_product, 
            "/api/search/history/settings",
            put(handlers::search_history::set_history_enabled, RoutePolicy::interactive_all_of(&["search:execute"])),
        )
        .route_if(!shared_product, 
            "/api/search/history/{id}",
            delete(handlers::search_history::delete_history_entry, RoutePolicy::interactive_all_of(&["search:execute"])),
        )
        // Search-autocomplete field ranking (NAN-3812); hosted mounts its own.
        .route_if(!shared_product,
            "/api/me/field-usage",
            get(handlers::search_history::get_field_usage, RoutePolicy::interactive_all_of(&["search:view"])),
        )
        // Recent activity (Continue Working feature)
        .route_if(!shared_product, 
            "/api/me/recent",
            get(handlers::recent_activity::list_recent_activity, RoutePolicy::interactive_session()),
        )
        .route_if(!shared_product, 
            "/api/me/recent",
            post(handlers::recent_activity::record_activity, RoutePolicy::interactive_session()),
        )
        .route_if(!shared_product, 
            "/api/me/recent",
            delete(handlers::recent_activity::clear_recent_activity, RoutePolicy::interactive_session()),
        )
        // Shared searches (short URLs)
        .route_if(!shared_product, "/api/search/share", post(handlers::create_shared_search, RoutePolicy::all_of(&["search:share"])))
        .route_if(!shared_product, "/api/search/shared/{id}", get(handlers::get_shared_search, RoutePolicy::all_of(&["search:view"])))
        // Query explanations (AI reasoning cache)
        .route_if(!shared_product,
            "/api/search/explanation",
            post(handlers::store_query_explanation, RoutePolicy::all_of(&["search:execute"])),
        )
        .route_if(!shared_product,
            "/api/search/explanation",
            get(handlers::get_query_explanation, RoutePolicy::all_of(&["search:execute"])),
        )
        // Rules (detection rules)
        .route_if(!shared_product, "/api/rules/import", post(handlers::import_detections, RoutePolicy::all_of(&["detections:create"])))
        .route_if(!shared_product, "/api/rules/export", get(handlers::export_detections, RoutePolicy::all_of(&["detections:export"])))
        // Auto retro-hunt rules (NAN-1791). Static paths BEFORE `/api/rules/{id}`.
        .route_if(!shared_product, "/api/rules/retro-hunt", post(handlers::create_retro_hunt, RoutePolicy::all_of(&["detections:create"])))
        .route_if(!shared_product, 
            "/api/rules/retro-hunt/feeds",
            get(handlers::list_retro_hunt_feeds, RoutePolicy::all_of(&["detections:view"])),
        )
        .route_if(!shared_product, 
            "/api/rules/{id}/retro-hunt",
            get(handlers::get_retro_hunt, RoutePolicy::all_of(&["detections:view"])).put(handlers::update_retro_hunt, RoutePolicy::all_of(&["detections:edit"])),
        )
        .route_if(!shared_product, 
            "/api/rules/{id}/retro-hunt/runs",
            get(handlers::list_retro_hunt_runs, RoutePolicy::all_of(&["detections:view"])),
        )
        .route_if(!shared_product, "/api/rules/test", post(handlers::test_query, RoutePolicy::all_of(&["detections:create", "search:execute"])))
        .route_if(!shared_product, "/api/rules/format", post(handlers::format_query, RoutePolicy::all_of(&["detections:view"])))
        .route_if(!shared_product, "/api/rules/validate", post(handlers::validate_detection, RoutePolicy::all_of(&["detections:view"])))
        .route_if(!shared_product, "/api/rules/bulk-update", post(handlers::bulk_update_rules, RoutePolicy::all_of(&["detections:promote"])))
        .route_if(!shared_product, "/api/rules/{id}", put(handlers::update_detection, RoutePolicy::all_of(&["detections:edit"])))
        .route_if(!shared_product, "/api/rules/{id}", delete(handlers::delete_detection, RoutePolicy::all_of(&["detections:delete"])))
        .route_if(!shared_product, "/api/rules/{id}/test", post(handlers::test_detection, RoutePolicy::all_of(&["detections:view", "search:execute"])))
        .route_if(!shared_product, "/api/rules/{id}/trigger", post(handlers::trigger_detection, RoutePolicy::all_of(&["detections:promote"])))
        .route_if(!shared_product, 
            "/api/rules/{id}/matches",
            get(handlers::get_detection_matches, RoutePolicy::all_of(&["detections:view"])),
        )
        .route_if(!shared_product, "/api/rules/{id}/versions", get(handlers::get_rule_versions, RoutePolicy::all_of(&["detections:view"])))
        .route_if(!shared_product, 
            "/api/rules/{id}/versions/{version_id}/revert",
            post(handlers::revert_to_version, RoutePolicy::all_of(&["detections:edit", "detections:promote"])),
        )
        .route_if(!shared_product, "/api/rules/stats", get(handlers::get_detection_stats, RoutePolicy::all_of(&["detections:view"])))
        .route_if(!shared_product, "/api/rules/today-counts", get(handlers::get_today_counts, RoutePolicy::all_of(&["detections:view"])))
        .route_if(!shared_product, 
            "/api/rules/health-summary",
            get(handlers::get_detection_health_summary, RoutePolicy::all_of(&["detections:view"])),
        )
        .route_if(!shared_product, "/api/rules/fleet-health", get(handlers::get_fleet_health, RoutePolicy::all_of(&["detections:view"])))
        .route_if(!shared_product, "/api/rules/scheduling-lag", get(handlers::get_scheduling_lag, RoutePolicy::all_of(&["detections:view"])))
        .route_if(!shared_product, "/api/rules/noisy", get(handlers::get_noisy_rules, RoutePolicy::all_of(&["detections:view"])))
        // Per-match review state (NAN-494)
        .route_if(!shared_product, 
            "/api/matches/{id}/review",
            post(handlers::mark_match_reviewed, RoutePolicy::all_of(&["detections:edit"])).delete(handlers::unmark_match_reviewed, RoutePolicy::all_of(&["detections:edit"])),
        )
        // Per-match disposition + rule-level rollup (NAN-498)
        .route_if(!shared_product, 
            "/api/rules/{id}/disposition-stats",
            get(handlers::get_rule_disposition_stats, RoutePolicy::all_of(&["detections:view"])),
        )
        .route_if(!shared_product, 
            "/api/matches/{id}/disposition",
            post(handlers::set_match_disposition, RoutePolicy::all_of(&["detections:edit"])),
        )
        // Parsed nPL predicates for the Matches detail "Rule conditions" card (NAN-501)
        .route_if(!shared_product, 
            "/api/rules/{id}/predicates",
            get(handlers::get_rule_predicates, RoutePolicy::all_of(&["detections:view"])),
        )
        // Alerts
        .route_if(!shared_product, "/api/alerts/stream", get(handlers::stream_alerts, RoutePolicy::all_of(&["alerts:view"])))
        .route_if(!shared_product, "/api/alerts/bulk", post(handlers::bulk_alerts, RoutePolicy::any_of(&["alerts:acknowledge", "alerts:close"])))
        .route_if(!shared_product, "/api/alerts/counts", get(handlers::alert_counts, RoutePolicy::all_of(&["alerts:view"])))
        .route_if(!shared_product, "/api/alerts/velocity", get(handlers::alert_velocity, RoutePolicy::all_of(&["alerts:view"])))
        .route_if(!shared_product, "/api/alerts/{id}/assign", post(handlers::assign_alert, RoutePolicy::all_of(&["alerts:assign"])));

    // Select the reviewed shared adapter only for the shared deployment.
    // Other legacy rule methods remain fenced by exact middleware admission.
    #[cfg(feature = "enterprise")]
    let shared_detections = config.deployment_mode.is_enterprise_shared();
    #[cfg(not(feature = "enterprise"))]
    let shared_detections = false;
    if !shared_detections {
        app = app
        .route("/api/alerts/{id}/acknowledge", post(handlers::acknowledge_alert, RoutePolicy::all_of(&["alerts:acknowledge"])))
        .route("/api/alerts/{id}/close", post(handlers::close_alert, RoutePolicy::all_of(&["alerts:close"])))
        .route("/api/alerts", get(handlers::list_alerts, RoutePolicy::all_of(&["alerts:view"])))
        .route("/api/alerts/{id}", get(handlers::get_alert, RoutePolicy::all_of(&["alerts:view"])))
        .route_if(!shared_product, "/api/settings/iceberg-export", get(handlers::iceberg_export::get, RoutePolicy::interactive_all_of(&["settings:system"])).put(handlers::iceberg_export::put, RoutePolicy::interactive_all_of(&["settings:system"])))
        .route("/api/rules", get(handlers::list_detections, RoutePolicy::all_of(&["detections:view"])))
        .route("/api/rules", post(handlers::create_detection, RoutePolicy::all_of(&["detections:create"])))
        .route_if(!shared_product, "/api/rules/{id}", get(handlers::get_detection, RoutePolicy::all_of(&["detections:view"])))
        .route("/api/rules/{id}/pause", post(handlers::pause_detection, RoutePolicy::all_of(&["detections:promote"])))
        .route("/api/rules/{id}/resume", post(handlers::resume_detection, RoutePolicy::all_of(&["detections:promote"])))
        .route("/api/rules/{id}/promote", post(handlers::promote_detection, RoutePolicy::all_of(&["detections:promote"])))
        .route("/api/rules/{id}/demote", post(handlers::demote_detection, RoutePolicy::all_of(&["detections:promote"])));
    }
    {
        app = app
            .route_if(!shared_product, "/api/connector-specs", get(handlers::connector_feeds::list_specs, RoutePolicy::all_of(&["log_sources:view"])))
            .route_if(!shared_product, "/api/connector-feeds", get(handlers::connector_feeds::list_feeds, RoutePolicy::all_of(&["log_sources:view"])).post(handlers::connector_feeds::create_feed, RoutePolicy::all_of(&["log_sources:create", "log_sources:deploy"])))
            .route_if(!shared_product, "/api/connector-feeds/{id}", patch(handlers::connector_feeds::set_enabled, RoutePolicy::all_of(&["log_sources:edit"])).delete(handlers::connector_feeds::delete_feed, RoutePolicy::all_of(&["log_sources:delete"])))
            // NAN-3770: named per-sender ingest tokens (dedicated only).
            .route_if(!shared_product, "/api/ingest-tokens", get(handlers::ingest_tokens::list_ingest_tokens, RoutePolicy::all_of(&["log_sources:view"])).post(handlers::ingest_tokens::create_ingest_token, RoutePolicy::all_of(&["settings:system"])))
            .route_if(!shared_product, "/api/ingest-tokens/install-token", put(handlers::ingest_tokens::update_install_token, RoutePolicy::all_of(&["settings:system"])))
            .route_if(!shared_product, "/api/ingest-tokens/{credential_id}/bind", post(handlers::ingest_tokens::bind_ingest_token, RoutePolicy::all_of(&["settings:system"])))
            .route_if(!shared_product, "/api/ingest-tokens/{credential_id}/revoke", post(handlers::ingest_tokens::revoke_ingest_token, RoutePolicy::all_of(&["settings:system"])))
            // NAN-3807: OCSF bucket drop source status (dedicated only, read-only).
            .route_if(!shared_product, "/api/landing-sources", get(handlers::landing_sources::list_landing_sources, RoutePolicy::all_of(&["log_sources:view"])))
            .route_if(!shared_product, "/api/landing-sources/{source_id}/files", get(handlers::landing_sources::list_landing_files, RoutePolicy::all_of(&["log_sources:view"])));
    }

    #[cfg(feature = "enterprise")]
    if shared_detections {
        use nanosiem_enterprise::handlers::enterprise_shared_detections as shared;
        app = app
            .route("/api/alerts", get(nanosiem_enterprise::handlers::enterprise_shared_alerts::list_alerts::<AppState>, RoutePolicy::all_of(&["alerts:view"])))
            .route("/api/alerts/{id}", get(nanosiem_enterprise::handlers::enterprise_shared_alerts::get_alert::<AppState>, RoutePolicy::all_of(&["alerts:view"])))
            .route("/api/alerts/{id}/acknowledge", post(nanosiem_enterprise::handlers::enterprise_shared_alert_triage::acknowledge_alert::<AppState>, RoutePolicy::all_of(&["alerts:acknowledge"])))
            .route("/api/alerts/{id}/close", post(nanosiem_enterprise::handlers::enterprise_shared_alert_triage::close_alert::<AppState>, RoutePolicy::all_of(&["alerts:close"])))
            .route("/api/rules", get(shared::list_detections::<AppState>, RoutePolicy::all_of(&["detections:view"])).post(shared::create_detection::<AppState>, RoutePolicy::all_of(&["detections:create"])))
            .route("/api/rules/{id}", get(shared::get_detection::<AppState>, RoutePolicy::all_of(&["detections:view"])))
            .route("/api/rules/{id}/pause", post(shared::pause_detection::<AppState>, RoutePolicy::all_of(&["detections:promote"])))
            .route("/api/rules/{id}/resume", post(shared::resume_detection::<AppState>, RoutePolicy::all_of(&["detections:promote"])))
            .route("/api/rules/{id}/promote", post(shared::promote_detection::<AppState>, RoutePolicy::all_of(&["detections:promote"])))
            .route("/api/rules/{id}/demote", post(shared::demote_detection::<AppState>, RoutePolicy::all_of(&["detections:promote"])));
    }

    // NAN-2361: the rest of the product, on the tenant-transaction substrate.
    // Each module exports its own router and its own fence (consulted in
    // middleware/auth.rs); the legacy handlers for these paths are not
    // registered in shared mode (see `route_if(!shared_product, …)`).
    #[cfg(feature = "enterprise")]
    if shared_product {
        use nanosiem_enterprise::handlers as eh;
        app = app
            .merge(eh::enterprise_shared_app_shell::enterprise_shared_app_shell_routes::<AppState>())
            .merge(eh::enterprise_shared_dashboards::enterprise_shared_dashboards_routes::<AppState>())
            .merge(eh::enterprise_shared_dashboard_panels::enterprise_shared_dashboard_panels_routes::<AppState>())
            .merge(eh::enterprise_shared_reports::enterprise_shared_reports_routes::<AppState>())
            .merge(eh::enterprise_shared_observability::enterprise_shared_observability_routes::<AppState>())
            .merge(eh::enterprise_shared_detection_dashboard::enterprise_shared_detection_dashboard_routes::<AppState>())
            .merge(eh::enterprise_shared_detection_editor::enterprise_shared_detection_editor_routes::<AppState>())
            .merge(eh::enterprise_shared_mitre::enterprise_shared_mitre_routes::<AppState>())
            .merge(eh::enterprise_shared_rule_repositories::enterprise_shared_rule_repositories_routes::<AppState>())
            // wave 2
            .merge(eh::enterprise_shared_iam::enterprise_shared_iam_routes::<AppState>())
            .merge(eh::enterprise_shared_settings::enterprise_shared_settings_routes::<AppState>())
            .merge(eh::enterprise_shared_sources::enterprise_shared_sources_routes::<AppState>())
            .merge(eh::enterprise_shared_enrichment::enterprise_shared_enrichment_routes::<AppState>())
            .merge(eh::soar::routes::<AppState>())
            .merge(eh::enterprise_shared_melod::enterprise_shared_melod_routes::<AppState>())
            // NAN-4535: pivt SOAR flow drafting (needs meloD + SOAR state).
            .merge(eh::enterprise_shared_flow_draft::enterprise_shared_flow_draft_routes::<AppState>())
            // NAN-4653: pivt edit-session turns (needs meloD + SOAR state for flows).
            .merge(eh::enterprise_shared_edit_session::enterprise_shared_edit_session_routes::<AppState>())
            .merge(eh::enterprise_shared_cases_extras::enterprise_shared_cases_extras_routes::<AppState>())
            .merge(eh::enterprise_shared_hunting::enterprise_shared_hunting_routes::<AppState>())
            .merge(eh::enterprise_shared_playbooks::enterprise_shared_playbooks_routes::<AppState>())
            .merge(eh::enterprise_shared_tuning::enterprise_shared_tuning_routes::<AppState>())
            .merge(eh::enterprise_shared_marketplace::enterprise_shared_marketplace_routes::<AppState>())
            .merge(eh::hosted_collectors::routes::<AppState>())
            .merge(eh::enterprise_shared_pull_sources::routes::<AppState>())
            .merge(eh::enterprise_shared_rules_alerts_remainder::enterprise_shared_rules_alerts_remainder_routes::<AppState>())
            // wave 3
            .merge(eh::enterprise_shared_oidc_settings::enterprise_shared_oidc_settings_routes::<AppState>())
            // wave 5
            .merge(eh::enterprise_shared_queues::enterprise_shared_queues_routes::<AppState>())
            .merge(eh::enterprise_shared_exports::enterprise_shared_exports_routes::<AppState>())
            .merge(eh::enterprise_shared_search_extras::enterprise_shared_search_extras_routes::<AppState>())
            // Both routes are auth-lifecycle POSTs (TOTP step-up, invitation
            // acceptance): same login rate limit as the other credential proofs.
            .merge(
                eh::enterprise_shared_iam_extras::enterprise_shared_iam_extras_routes::<AppState>().layer(
                    axum_middleware::from_fn_with_state((*rate_limit_state).clone(), login_rate_limit_middleware),
                ),
            );
    }

    // Shared customer automation credentials are a separate tenant-bound
    // registry. The legacy deployment-global handlers remain byte-for-byte on
    // dedicated/open-core modes and are never mounted in hosted-shared.
    #[cfg(feature = "enterprise")]
    {
        if config.deployment_mode.is_enterprise_shared() {
            app = app
                .route(
                    "/api/api-keys",
                    get(handlers::shared_automation_keys::list::<AppState>, RoutePolicy::interactive_all_of(&["apikeys:view"]))
                        .post(handlers::shared_automation_keys::create::<AppState>, RoutePolicy::interactive_all_of(&["apikeys:create"])),
                )
                .route(
                    "/api/api-keys/{id}/rotate",
                    post(handlers::shared_automation_keys::rotate::<AppState>, RoutePolicy::interactive_all_of(&["apikeys:edit"])),
                )
                .route(
                    "/api/api-keys/{id}",
                    delete(handlers::shared_automation_keys::revoke::<AppState>, RoutePolicy::interactive_all_of(&["apikeys:delete"])),
                )
                // NAN-2361 wave 3: edit + usage for tenant automation keys
                .merge(handlers::shared_automation_keys::shared_automation_key_extension_routes::<AppState>());
        } else {
            app = app.merge(legacy_api_key_routes());
        }
    }
    #[cfg(not(feature = "enterprise"))]
    {
        app = app.merge(legacy_api_key_routes());
    }

    // License status (exempt from license guard so the frontend can check it).
    // Enterprise-only: the open edition ships no license handler (NAN-1193).
    #[cfg(feature = "enterprise")]
    {
        // NAN-2361: in shared mode the app-shell port answers /api/license from
        // the tenant's plan; registering both would panic at boot (same method).
        app = app.route_if(!shared_product, "/api/license", get(handlers::license::get_license_status, RoutePolicy::authenticated()));
        // Air-gapped offline license import (NAN-1206). Kept license-guard-exempt
        // so a fresh / locked install with no license yet can import one to recover.
        // Payload is tiny (<256KB), so it stays under the default body limit.
        app = app.route(
            "/api/airgap/license/import",
            post(handlers::airgap::license::import_offline_license, RoutePolicy::all_of(&["settings:system"])),
        );
    }

    // Cases + queues + queue-routing-rules + incidents — Phase 3.2 (NAN-744)
    // lifted nanosiem-core/src/cases/ + incidents/ to the enterprise crate.
    #[cfg(feature = "enterprise")]
    {
        // Shared OIDC is an independent tenant-bound flow. Do not register it
        // at all in dedicated deployments; dedicated routes below remain
        // byte-for-byte on their existing handlers and global provider tables.
        if config.deployment_mode.is_enterprise_shared() {
            let shared_activation_route = Router::new()
                .route(
                    "/api/auth/shared/activate",
                    post(handlers::shared_activation::activate_shared_local_account::<AppState>, RoutePolicy::public()),
                )
                .layer(axum_middleware::from_fn_with_state(
                    (*rate_limit_state).clone(),
                    login_rate_limit_middleware,
                ))
                .layer(DefaultBodyLimit::max(8 * 1024));
            let shared_oidc_routes = Router::new()
                .route(
                    "/api/auth/shared/oidc/entry",
                    post(handlers::oidc::shared_oidc_entry::<AppState>, RoutePolicy::public()),
                )
                .route(
                    "/api/auth/shared/oidc/callback",
                    post(handlers::oidc::shared_oidc_callback::<AppState>, RoutePolicy::public()),
                )
                .layer(axum_middleware::from_fn_with_state(
                    (*rate_limit_state).clone(),
                    login_rate_limit_middleware,
                ))
                .layer(DefaultBodyLimit::max(32 * 1024));
            let shared_oidc_login_routes = Router::new()
                .route(
                    "/api/auth/shared/oidc/providers",
                    post(handlers::oidc::shared_oidc_login_providers::<AppState>, RoutePolicy::public()),
                )
                .route(
                    "/api/auth/shared/oidc/start",
                    post(handlers::oidc::shared_oidc_start::<AppState>, RoutePolicy::public()),
                )
                .layer(axum_middleware::from_fn_with_state(
                    (*rate_limit_state).clone(),
                    login_rate_limit_middleware,
                ))
                .layer(DefaultBodyLimit::max(8 * 1024));
            // NAN-4152: public web path alias resolver (`/t/<alias>` ->
            // canonical slug). Per-IP limited like SSO discovery, but on its
            // own bucket: page loads never spend the login budget.
            let shared_tenant_path_alias_route = Router::new()
                .route(
                    "/api/auth/shared/tenant-path-alias/{alias}",
                    get(nanosiem_enterprise::handlers::shared_tenant_path_alias::resolve_shared_tenant_path_alias::<AppState>, RoutePolicy::public()),
                )
                .layer(axum_middleware::from_fn_with_state(
                    (*rate_limit_state).clone(),
                    crate::middleware::rate_limit::tenant_path_alias_rate_limit_middleware,
                ))
                .layer(DefaultBodyLimit::max(1024));
            // NAN-4152: public demo-link claim; rate-limited like the
            // public OIDC login routes.
            let shared_demo_claim_route = Router::new()
                .route(
                    nanosiem_core::enterprise_shared_demo::DEMO_CLAIM_PATH,
                    post(handlers::shared_demo_claim::claim_shared_demo, RoutePolicy::public()),
                )
                .layer(axum_middleware::from_fn_with_state(
                    (*rate_limit_state).clone(),
                    login_rate_limit_middleware,
                ))
                .layer(DefaultBodyLimit::max(8 * 1024));
            let shared_membership_acceptance_route =
                Router::new()
                    .route(
                        "/api/auth/shared/memberships/accept",
                        post(
                            handlers::shared_membership_acceptance::accept_shared_membership::<
                                AppState,
                            >, RoutePolicy::public()),
                    )
                    .layer(axum_middleware::from_fn_with_state(
                        (*rate_limit_state).clone(),
                        login_rate_limit_middleware,
                    ))
                    .layer(DefaultBodyLimit::max(8 * 1024));
            let shared_oidc_admin_routes = Router::new()
                .route(
                    "/api/auth/shared/oidc/admin/providers",
                    get(handlers::oidc::list_shared_oidc_admin_providers::<AppState>, RoutePolicy::interactive_all_of(&["settings:system"]))
                        .post(handlers::oidc::create_shared_oidc_admin_provider::<AppState>, RoutePolicy::interactive_all_of(&["settings:system"])),
                )
                .route(
                    "/api/auth/shared/oidc/admin/providers/{provider_id}",
                    get(handlers::oidc::get_shared_oidc_admin_provider::<AppState>, RoutePolicy::interactive_all_of(&["settings:system"]))
                        .put(handlers::oidc::update_shared_oidc_admin_provider::<AppState>, RoutePolicy::interactive_all_of(&["settings:system"]))
                        .delete(handlers::oidc::delete_shared_oidc_admin_provider::<AppState>, RoutePolicy::interactive_all_of(&["settings:system"])),
                )
                .route(
                    "/api/auth/shared/oidc/admin/providers/{provider_id}/rotate-secret",
                    post(handlers::oidc::rotate_shared_oidc_admin_provider_secret::<AppState>, RoutePolicy::interactive_all_of(&["settings:system"])),
                )
                .route(
                    "/api/auth/shared/oidc/admin/providers/{provider_id}/enable",
                    post(handlers::oidc::enable_shared_oidc_admin_provider::<AppState>, RoutePolicy::interactive_all_of(&["settings:system"])),
                )
                .route(
                    "/api/auth/shared/oidc/admin/providers/{provider_id}/disable",
                    post(handlers::oidc::disable_shared_oidc_admin_provider::<AppState>, RoutePolicy::interactive_all_of(&["settings:system"])),
                )
                .layer(axum_middleware::from_fn_with_state(
                    (*rate_limit_state).clone(),
                    login_rate_limit_middleware,
                ))
                .layer(DefaultBodyLimit::max(8 * 1024));
            app = app
                .merge(shared_demo_claim_route)
                .merge(shared_activation_route)
                .merge(shared_oidc_login_routes)
                .merge(shared_tenant_path_alias_route)
                .merge(shared_oidc_routes)
                .merge(shared_membership_acceptance_route)
                .merge(shared_oidc_admin_routes);

            // Only the signed-RLS read adapter replaces these four canonical
            // product reads in shared mode. No legacy mutation handler is
            // mounted on the same collection/resource paths.
            // NAN-2361: reads AND writes (case lifecycle, wall, handoffs,
            // notebooks, tabs, entries) on the signed-RLS adapter.
            app = app.merge(
                nanosiem_enterprise::handlers::enterprise_shared_cases_notebooks::enterprise_shared_cases_notebooks_routes::<AppState>(),
            );
        } else {
            app = app
                .route_if(!shared_product, "/api/cases", get(handlers::cases::list_cases::<AppState>, RoutePolicy::all_of(&["cases:view"])))
                .route_if(!shared_product, "/api/cases", post(handlers::cases::create_case::<AppState>, RoutePolicy::all_of(&["cases:create"])))
                .route_if(!shared_product, 
                    "/api/cases/{id}",
                    get(handlers::cases::get_case::<AppState>, RoutePolicy::all_of(&["cases:view"])),
                )
                .route_if(!shared_product, 
                    "/api/cases/{id}",
                    put(handlers::cases::update_case::<AppState>, RoutePolicy::all_of(&["cases:edit"])),
                )
                .route_if(!shared_product, 
                    "/api/cases/{id}",
                    delete(handlers::cases::delete_case::<AppState>, RoutePolicy::all_of(&["cases:delete"])),
                );
        }

        app = app
            // Cases
            .route_if(!shared_product, 
                "/api/cases/events",
                get(handlers::cases::case_events_stream::<AppState>, RoutePolicy::all_of(&["cases:view"])),
            )
            .route_if(!shared_product, 
                "/api/cases/my",
                get(handlers::cases::get_my_cases::<AppState>, RoutePolicy::all_of(&["cases:view"])),
            )
            .route_if(!shared_product, 
                "/api/cases/stats",
                get(handlers::cases::get_case_stats::<AppState>, RoutePolicy::all_of(&["cases:view"])),
            )
            // NAN-1093: Signal Inbox aggregation — per-tab counts + incident pills.
            .route_if(!shared_product, 
                "/api/cases/inbox-counts",
                get(handlers::cases::get_inbox_counts::<AppState>, RoutePolicy::all_of(&["cases:view"])),
            )
            .route_if(!shared_product, 
                "/api/cases/inbox-incidents",
                get(handlers::cases::get_inbox_incidents::<AppState>, RoutePolicy::all_of(&["cases:view"])),
            )
            .route_if(!shared_product, 
                "/api/cases/bulk/status",
                post(handlers::cases::bulk_change_case_status::<AppState>, RoutePolicy::any_of(&["cases:close", "cases:edit"])),
            )
            .route_if(!shared_product, 
                "/api/cases/bulk/assign",
                post(handlers::cases::bulk_assign_cases::<AppState>, RoutePolicy::all_of(&["cases:assign"])),
            )
            .route_if(!shared_product, 
                "/api/cases/{id}/alerts",
                post(handlers::cases::add_alert_to_case::<AppState>, RoutePolicy::all_of(&["cases:edit", "alerts:view"])),
            )
            .route_if(!shared_product, 
                "/api/cases/{id}/alerts/{alert_id}",
                delete(handlers::cases::remove_alert_from_case::<AppState>, RoutePolicy::all_of(&["cases:edit", "alerts:view"])),
            )
            .route_if(!shared_product, 
                "/api/cases/{id}/wall",
                get(handlers::cases::get_case_wall::<AppState>, RoutePolicy::all_of(&["cases:view"])),
            )
            .route_if(!shared_product, 
                "/api/cases/{id}/wall",
                post(handlers::cases::add_case_wall_entry::<AppState>, RoutePolicy::all_of(&["cases:comment"])),
            )
            .route_if(!shared_product, 
                "/api/cases/{id}/assign",
                post(handlers::cases::assign_case::<AppState>, RoutePolicy::all_of(&["cases:assign"])),
            )
            .route_if(!shared_product, 
                "/api/cases/{id}/escalate",
                post(handlers::cases::escalate_case::<AppState>, RoutePolicy::all_of(&["cases:assign"])),
            )
            .route_if(!shared_product, 
                "/api/cases/{id}/status",
                post(handlers::cases::change_case_status::<AppState>, RoutePolicy::any_of(&["cases:close", "cases:edit"])),
            )
            .route_if(!shared_product, 
                "/api/cases/{id}/related",
                get(handlers::cases::get_related_cases::<AppState>, RoutePolicy::all_of(&["cases:view"]))
                    .post(handlers::cases::link_related_case::<AppState>, RoutePolicy::all_of(&["cases:edit"])),
            )
            .route_if(!shared_product, 
                "/api/cases/{id}/related/{target_id}",
                nanosiem_api_lib::route_policy::routing::delete(handlers::cases::unlink_related_case::<AppState>, RoutePolicy::all_of(&["cases:edit"])),
            )
            .route_if(!shared_product, 
                "/api/cases/{id}/duplicates",
                get(handlers::cases::get_duplicate_candidates::<AppState>, RoutePolicy::all_of(&["cases:view"])),
            )
            .route_if(!shared_product, 
                "/api/cases/{id}/share",
                post(handlers::cases::share_case::<AppState>, RoutePolicy::all_of(&["cases:share"])),
            )
            .route_if(!shared_product, 
                "/api/cases/{id}/merge",
                post(handlers::cases::merge_cases::<AppState>, RoutePolicy::all_of(&["cases:edit"])),
            )
            // Case handoffs (NAN-415)
            .route_if(!shared_product, 
                "/api/cases/{id}/handoff",
                post(handlers::cases::create_handoff::<AppState>, RoutePolicy::all_of(&["cases:assign"])),
            )
            .route_if(!shared_product, 
                "/api/cases/{id}/handoff/{handoff_id}/accept",
                post(handlers::cases::accept_handoff::<AppState>, RoutePolicy::all_of(&["cases:assign"])),
            )
            .route_if(!shared_product, 
                "/api/cases/{id}/handoff/{handoff_id}/bounce",
                post(handlers::cases::bounce_handoff::<AppState>, RoutePolicy::all_of(&["cases:assign"])),
            )
            .route_if(!shared_product, 
                "/api/cases/{id}/handoff/{handoff_id}/cancel",
                post(handlers::cases::cancel_handoff::<AppState>, RoutePolicy::all_of(&["cases:assign"])),
            )
            // Case collab-presence heartbeat (NAN-420)
            .route_if(!shared_product, 
                "/api/cases/{id}/presence",
                post(handlers::cases::post_case_presence_heartbeat::<AppState>, RoutePolicy::all_of(&["cases:view"])),
            )
            // Case-Notebook integration
            .route_if(!shared_product, 
                "/api/cases/{id}/notebook",
                get(handlers::cases::get_case_notebook::<AppState>, RoutePolicy::all_of(&["cases:view"])),
            )
            .route_if(!shared_product, 
                "/api/cases/{id}/notebook",
                post(handlers::cases::link_notebook_to_case::<AppState>, RoutePolicy::all_of(&["cases:edit", "notebooks:edit"])),
            )
            .route_if(!shared_product, 
                "/api/cases/{id}/notebook",
                delete(handlers::cases::unlink_notebook_from_case::<AppState>, RoutePolicy::all_of(&["cases:edit", "notebooks:edit"])),
            )
            .route_if(!shared_product, 
                "/api/cases/{id}/notebook/merge",
                post(handlers::cases::merge_notebook_into_case::<AppState>, RoutePolicy::all_of(&["cases:edit", "notebooks:edit"])),
            )
            .route_if(!shared_product, 
                "/api/cases/{id}/related-notebooks",
                get(handlers::cases::get_related_notebooks::<AppState>, RoutePolicy::all_of(&["cases:view"])),
            )
            // Case saved searches (NAN-1072)
            .route_if(!shared_product, 
                "/api/cases/saved-searches",
                get(handlers::cases::list_case_saved_searches::<AppState>, RoutePolicy::all_of(&["cases:view"])),
            )
            .route_if(!shared_product, 
                "/api/cases/saved-searches",
                post(handlers::cases::create_case_saved_search::<AppState>, RoutePolicy::all_of(&["cases:create"])),
            )
            .route_if(!shared_product, 
                "/api/cases/saved-searches/{id}",
                nanosiem_api_lib::route_policy::routing::patch(handlers::cases::update_case_saved_search::<AppState>, RoutePolicy::all_of(&["cases:edit"])),
            )
            .route_if(!shared_product, 
                "/api/cases/saved-searches/{id}",
                delete(handlers::cases::delete_case_saved_search::<AppState>, RoutePolicy::all_of(&["cases:delete"])),
            )
            // Queues (NAN-426)
            .route_if(!shared_product, "/api/queues", get(handlers::cases::list_queues::<AppState>, RoutePolicy::all_of(&["cases:view"])))
            .route_if(!shared_product,
                "/api/queues",
                post(handlers::cases::create_queue::<AppState>, RoutePolicy::all_of(&["settings:system"])),
            )
            .route_if(!shared_product, 
                "/api/queues/mine",
                get(handlers::cases::list_my_queues::<AppState>, RoutePolicy::all_of(&["cases:view"])),
            )
            .route_if(!shared_product,
                "/api/queues/{id}",
                get(handlers::cases::get_queue::<AppState>, RoutePolicy::all_of(&["cases:view"])),
            )
            .route_if(!shared_product,
                "/api/queues/{id}",
                put(handlers::cases::update_queue::<AppState>, RoutePolicy::all_of(&["settings:system"])),
            )
            .route_if(!shared_product,
                "/api/queues/{id}",
                delete(handlers::cases::delete_queue::<AppState>, RoutePolicy::all_of(&["settings:system"])),
            )
            // Queue routing rules (NAN-427)
            .route_if(!shared_product, 
                "/api/queue-routing-rules",
                get(handlers::cases::list_queue_routing_rules::<AppState>, RoutePolicy::all_of(&["settings:view"])),
            )
            .route_if(!shared_product,
                "/api/queue-routing-rules",
                post(handlers::cases::create_queue_routing_rule::<AppState>, RoutePolicy::all_of(&["settings:system"])),
            )
            .route_if(!shared_product,
                "/api/queue-routing-rules/preview",
                post(handlers::cases::preview_queue_routing::<AppState>, RoutePolicy::all_of(&["settings:system"])),
            )
            .route_if(!shared_product,
                "/api/queue-routing-rules/{id}",
                put(handlers::cases::update_queue_routing_rule::<AppState>, RoutePolicy::all_of(&["settings:system"])),
            )
            .route_if(!shared_product,
                "/api/queue-routing-rules/{id}",
                delete(handlers::cases::delete_queue_routing_rule::<AppState>, RoutePolicy::all_of(&["settings:system"])),
            )
            // Incidents (NAN-417)
            .route_if(!shared_product, 
                "/api/incidents",
                post(handlers::incidents::create_incident::<AppState>, RoutePolicy::all_of(&["cases:edit"])),
            )
            .route_if(!shared_product, 
                "/api/incidents",
                get(handlers::incidents::list_incidents::<AppState>, RoutePolicy::all_of(&["cases:view"])),
            )
            .route_if(!shared_product, 
                "/api/incidents/{id}",
                get(handlers::incidents::get_incident::<AppState>, RoutePolicy::all_of(&["cases:view"])),
            )
            .route_if(!shared_product, 
                "/api/incidents/{id}/cases",
                post(handlers::incidents::add_case_to_incident::<AppState>, RoutePolicy::all_of(&["cases:edit"])),
            )
            .route_if(!shared_product, 
                "/api/incidents/{id}/cases/{case_id}",
                delete(handlers::incidents::remove_case_from_incident::<AppState>, RoutePolicy::all_of(&["cases:edit"])),
            );
    }

    #[cfg(feature = "enterprise")]
    {
        app = app.merge(marketplace_preview_routes);
    }

    app = app
        // Fields
        .route_if(!shared_product, "/api/fields/ext", get(handlers::get_ext_fields, RoutePolicy::all_of(&["search:execute"])))
        .route_if(!shared_product, "/api/fields/{name}/values", get(handlers::get_field_values, RoutePolicy::all_of(&["search:execute"])))
        // Enrichment
        .route_if(!shared_product, 
            "/api/enrichment/sources",
            get(handlers::list_enrichment_sources, RoutePolicy::all_of(&["enrichments:view"])),
        )
        .route_if(!shared_product, 
            "/api/enrichment/ipinfo/configure",
            post(handlers::configure_ipinfo, RoutePolicy::all_of(&["enrichments:configure"])),
        )
        .route_if(!shared_product, "/api/enrichment/ipinfo/sync", post(handlers::sync_ipinfo, RoutePolicy::all_of(&["enrichments:configure"])))
        // NAN-4759: self-hosted platform feed freshness (hosted uses /api/marketplace/items).
        .route_if(!shared_product, "/api/enrichment/platform-feeds", get(handlers::get_platform_feeds, RoutePolicy::all_of(&["enrichments:view"])))
        .route_if(!shared_product, 
            "/api/enrichment/sources/{id}/enable",
            post(handlers::enable_enrichment_source, RoutePolicy::all_of(&["enrichments:configure"])),
        )
        .route_if(!shared_product, 
            "/api/enrichment/sources/{id}/disable",
            post(handlers::disable_enrichment_source, RoutePolicy::all_of(&["enrichments:configure"])),
        )
        .route_if(!shared_product, 
            "/api/enrichment/sources/{id}/auto-sync",
            get(handlers::get_auto_sync_config, RoutePolicy::all_of(&["enrichments:view"])),
        )
        .route_if(!shared_product, 
            "/api/enrichment/sources/{id}/auto-sync",
            post(handlers::configure_auto_sync, RoutePolicy::all_of(&["enrichments:configure"])),
        )
        .route_if(!shared_product, "/api/enrichment/stats", get(handlers::get_enrichment_stats, RoutePolicy::all_of(&["enrichments:view"])))
        .route_if(!shared_product, "/api/enrichment/lookup/{ip}", get(handlers::lookup_ip, RoutePolicy::all_of(&["enrichments:view"])));
    // NAN-1111 sunset: ThreatFox + TOR Exit Nodes per-provider configure
    // and sync routes lived here; both moved to the marketplace + Deno
    // (nano-rs/nano-enrichments). The `/api/enrichment/ioc/{lookup,stats}`
    // endpoints lived in `threatfox.rs` and had no remaining UI callers
    // — deleted with the rest. IPinfo Lite routes above stay (single
    // pre-built provider that doesn't fit the marketplace contract;
    // see project_ipinfo_lite_stays_native).

    // Agent enrichment lookup (Deno providers — VirusTotal, AbuseIPDB, etc.)
    // — enterprise only, depends on the lifted agent_enrichment +
    // custom_enrichment::sandbox modules.
    #[cfg(feature = "enterprise")]
    {
        app = app.route_if(!shared_product, "/api/enrichment/agent/lookup", post(handlers::agent_lookup, RoutePolicy::all_of(&["enrichments:configure"])));
    }

    app = app
        // Cloud Credentials
        .route_if(!shared_product, 
            "/api/credentials",
            get(handlers::credentials::list_credentials, RoutePolicy::all_of(&["credentials:view"])),
        )
        .route_if(!shared_product, 
            "/api/credentials",
            post(handlers::credentials::create_credential, RoutePolicy::all_of(&["credentials:create"])),
        )
        .route_if(!shared_product, 
            "/api/credentials/provider/{provider}",
            get(handlers::credentials::list_credentials_by_provider, RoutePolicy::all_of(&["credentials:view"])),
        )
        .route_if(!shared_product, 
            "/api/credentials/{id}",
            get(handlers::credentials::get_credential, RoutePolicy::all_of(&["credentials:view"])),
        )
        .route_if(!shared_product, 
            "/api/credentials/{id}",
            put(handlers::credentials::update_credential, RoutePolicy::all_of(&["credentials:edit"])),
        )
        .route_if(!shared_product, 
            "/api/credentials/{id}",
            delete(handlers::credentials::delete_credential, RoutePolicy::all_of(&["credentials:delete"])),
        )
        .route_if(!shared_product, 
            "/api/credentials/{id}/rotate",
            post(handlers::credentials::rotate_credential, RoutePolicy::all_of(&["credentials:rotate"])),
        )
        .route_if(!shared_product, 
            "/api/credentials/{id}/versions",
            get(handlers::credentials::list_credential_versions, RoutePolicy::all_of(&["credentials:view"])),
        )
        .route_if(!shared_product, 
            "/api/credentials/{id}/rollback",
            post(handlers::credentials::rollback_credential, RoutePolicy::all_of(&["credentials:rotate"])),
        )
        // Source onboarding (dedicated; hosted uses the signed tenant adapter).
        .route_if(!shared_product,"/api/source-onboarding",get(handlers::source_onboarding::read, RoutePolicy::all_of(&["log_sources:view"])))
        .route_if(!shared_product,"/api/source-onboarding/actions",post(handlers::source_onboarding::mutate, RoutePolicy::all_of(&["log_sources:edit"])).layer(DefaultBodyLimit::max(nanosiem_core::source_onboarding::csv::IMPORT_BODY_LIMIT_BYTES)))
        .route_if(!shared_product,"/api/source-onboarding/import-preview",post(handlers::source_onboarding::preview, RoutePolicy::all_of(&["log_sources:edit"])).layer(DefaultBodyLimit::max(nanosiem_core::source_onboarding::csv::IMPORT_BODY_LIMIT_BYTES)))
        .route_if(!shared_product,"/api/source-onboarding/export",get(handlers::source_onboarding::export, RoutePolicy::all_of(&["log_sources:view"])))
        // Log Sources
        .route_if(!shared_product, 
            "/api/log-sources",
            get(handlers::log_sources::list_log_sources, RoutePolicy::all_of(&["log_sources:view"])),
        )
        .route_if(!shared_product, 
            "/api/log-sources",
            post(handlers::log_sources::create_log_source, RoutePolicy::all_of(&["log_sources:create"])),
        )
        .route_if(!shared_product, 
            "/api/log-sources/validate-vrl",
            post(handlers::log_sources::validate_vrl, RoutePolicy::all_of(&["log_sources:view"])),
        )
        .route_if(!shared_product, 
            "/api/log-sources/validate-namespace",
            post(handlers::log_sources::validate_namespace, RoutePolicy::all_of(&["log_sources:view"])),
        )
        .route_if(!shared_product, 
            "/api/log-sources/test-vrl",
            post(handlers::log_sources::test_vrl, RoutePolicy::all_of(&["log_sources:view"])),
        )
        .route_if(!shared_product, 
            "/api/log-sources/test-live",
            post(handlers::log_sources::test_vrl_live, RoutePolicy::all_of(&["log_sources:view", "search:execute"])),
        )
        .route_if(!shared_product, 
            "/api/log-sources/deploy-all",
            post(handlers::log_sources::deploy_all_log_sources, RoutePolicy::all_of(&["log_sources:deploy"])),
        )
        .route_if(!shared_product, 
            "/api/log-sources/ingestion-history",
            get(handlers::log_sources::get_all_ingestion_history, RoutePolicy::all_of(&["log_sources:view"])),
        )
        .route_if(!shared_product, 
            "/api/log-sources/{id}",
            get(handlers::log_sources::get_log_source, RoutePolicy::all_of(&["log_sources:view"])),
        )
        .route_if(!shared_product, 
            "/api/log-sources/{id}",
            put(handlers::log_sources::update_log_source, RoutePolicy::all_of(&["log_sources:edit"])),
        )
        .route_if(!shared_product, 
            "/api/log-sources/{id}",
            delete(handlers::log_sources::delete_log_source, RoutePolicy::all_of(&["log_sources:delete"])),
        )
        .route_if(!shared_product, 
            "/api/log-sources/{id}/toggle",
            post(handlers::log_sources::toggle_log_source, RoutePolicy::all_of(&["log_sources:edit"])),
        )
        .route_if(!shared_product, 
            "/api/log-sources/{id}/validate",
            post(handlers::log_sources::validate_log_source, RoutePolicy::all_of(&["log_sources:edit"])),
        )
        .route_if(!shared_product, 
            "/api/log-sources/{id}/deploy",
            post(handlers::log_sources::deploy_log_source, RoutePolicy::all_of(&["log_sources:deploy"])),
        )
        .route_if(!shared_product, 
            "/api/log-sources/{id}/undeploy",
            post(handlers::log_sources::undeploy_log_source, RoutePolicy::all_of(&["log_sources:deploy"])),
        )
        .route_if(!shared_product, 
            "/api/log-sources/{id}/deployments",
            get(handlers::log_sources::get_log_source_deployments, RoutePolicy::all_of(&["log_sources:view"])),
        )
        .route_if(!shared_product, 
            "/api/log-sources/{id}/health",
            get(handlers::log_sources::get_log_source_health, RoutePolicy::all_of(&["log_sources:view"])),
        )
        .route_if(!shared_product, 
            "/api/log-sources/{id}/versions",
            get(handlers::log_sources::get_log_source_versions, RoutePolicy::all_of(&["log_sources:view"])),
        )
        .route_if(!shared_product, 
            "/api/log-sources/{id}/publish",
            post(handlers::log_sources::publish_log_source, RoutePolicy::all_of(&["log_sources:deploy"])),
        )
        .route_if(!shared_product, 
            "/api/log-sources/{id}/versions/{version_id}/revert",
            post(handlers::log_sources::revert_log_source_version, RoutePolicy::all_of(&["log_sources:deploy"])),
        )
        .route_if(!shared_product, 
            "/api/log-sources/{id}/discard-draft",
            post(handlers::log_sources::discard_log_source_draft, RoutePolicy::all_of(&["log_sources:edit"])),
        )
        .route_if(!shared_product, 
            "/api/log-sources/{id}/draft-status",
            get(handlers::log_sources::get_log_source_draft_status, RoutePolicy::all_of(&["log_sources:view"])),
        )
        // Source configurations (infrastructure + routing)
        .route_if(!shared_product, 
            "/api/source-configurations",
            get(handlers::source_configs::list_source_configs, RoutePolicy::all_of(&["source_configs:view"])),
        )
        .route_if(!shared_product, 
            "/api/source-configurations",
            post(handlers::source_configs::create_source_config, RoutePolicy::all_of(&["source_configs:create"])),
        )
        .route_if(!shared_product, 
            "/api/source-configurations/deploy-all",
            post(handlers::source_configs::deploy_all_source_configs, RoutePolicy::all_of(&["source_configs:deploy"])),
        )
        // NAN-649: per-driver type metadata (presets, push/pull, default
        // match_field). Must be registered before `/{id}` so axum doesn't
        // route the `types` literal as a TypeIdParam.
        .route_if(!shared_product, 
            "/api/source-configurations/types",
            get(handlers::source_configs::list_source_config_types, RoutePolicy::all_of(&["source_configs:view"])),
        )
        .route_if(!shared_product, 
            "/api/source-configurations/{id}",
            get(handlers::source_configs::get_source_config, RoutePolicy::all_of(&["source_configs:view"])),
        )
        .route_if(!shared_product, 
            "/api/source-configurations/{id}/full",
            get(handlers::source_configs::get_source_config_with_rules, RoutePolicy::all_of(&["source_configs:view"])),
        )
        .route_if(!shared_product, 
            "/api/source-configurations/{id}",
            put(handlers::source_configs::update_source_config, RoutePolicy::all_of(&["source_configs:edit"])),
        )
        .route_if(!shared_product, 
            "/api/source-configurations/{id}",
            delete(handlers::source_configs::delete_source_config, RoutePolicy::all_of(&["source_configs:delete"])),
        )
        .route_if(!shared_product, 
            "/api/source-configurations/{id}/toggle",
            post(handlers::source_configs::toggle_source_config, RoutePolicy::all_of(&["source_configs:edit"])),
        )
        .route_if(!shared_product, 
            "/api/source-configurations/{id}/deploy",
            post(handlers::source_configs::deploy_source_config, RoutePolicy::all_of(&["source_configs:deploy"])),
        )
        .route_if(!shared_product, 
            "/api/source-configurations/{id}/undeploy",
            post(handlers::source_configs::undeploy_source_config, RoutePolicy::all_of(&["source_configs:deploy"])),
        )
        .route_if(!shared_product, 
            "/api/source-configurations/{id}/deployments",
            get(handlers::source_configs::get_source_config_deployments, RoutePolicy::all_of(&["source_configs:view"])),
        )
        // Routing rules (nested under source configurations)
        .route_if(!shared_product, 
            "/api/source-configurations/{source_config_id}/rules",
            get(handlers::source_configs::list_routing_rules, RoutePolicy::all_of(&["source_configs:view"])),
        )
        .route_if(!shared_product, 
            "/api/source-configurations/{source_config_id}/rules",
            post(handlers::source_configs::create_routing_rule, RoutePolicy::all_of(&["source_configs:edit"])),
        )
        .route_if(!shared_product, 
            "/api/source-configurations/{source_config_id}/rules/reorder",
            post(handlers::source_configs::reorder_routing_rules, RoutePolicy::all_of(&["source_configs:edit"])),
        )
        .route_if(!shared_product, 
            "/api/source-configurations/{source_config_id}/rules/{rule_id}",
            put(handlers::source_configs::update_routing_rule, RoutePolicy::all_of(&["source_configs:edit"])),
        )
        .route_if(!shared_product, 
            "/api/source-configurations/{source_config_id}/rules/{rule_id}",
            delete(handlers::source_configs::delete_routing_rule, RoutePolicy::all_of(&["source_configs:edit"])),
        );
    // NAN-939: probe route is registered separately via `kafka_probe_routes`
    // below so it picks up the per-user rate-limit middleware.

    // meloD AI assistant endpoints — enterprise only.
    #[cfg(feature = "enterprise")]
    {
        app = app
            .route_if(!shared_product, "/api/melod/chat", post(handlers::melod_chat::<AppState>, RoutePolicy::all_of(&["melod:chat"])))
            .route_if(!shared_product, 
                "/api/melod/chat/stream",
                post(handlers::melod_chat_streaming::<AppState>, RoutePolicy::all_of(&["melod:chat"])),
            )
            .route_if(!shared_product, 
                "/api/melod/parser",
                post(handlers::melod_create_parser::<AppState>, RoutePolicy::all_of_any_of(&["melod:parser"], &["log_sources:view", "parsers:view"])),
            )
            .route_if(!shared_product, 
                "/api/melod/parser/stream",
                post(handlers::melod_create_parser_streaming::<AppState>, RoutePolicy::all_of_any_of(&["melod:parser"], &["log_sources:view", "parsers:view"])),
            )
            .route_if(!shared_product, 
                "/api/melod/parser/edit",
                post(handlers::melod_edit_parser::<AppState>, RoutePolicy::all_of(&["melod:parser"])),
            )
            .route_if(!shared_product, 
                "/api/melod/query",
                post(handlers::melod_build_query::<AppState>, RoutePolicy::all_of(&["melod:query", "search:execute"])),
            )
            .route(
                "/api/melod/correct-query",
                post(handlers::melod_correct_query::<AppState>, RoutePolicy::all_of(&["melod:query"])),
            )
            .route_if(!shared_product, 
                "/api/melod/review-query",
                post(handlers::melod_review_query::<AppState>, RoutePolicy::all_of(&["melod:query"])),
            )
            .route_if(!shared_product, 
                "/api/melod/detection",
                post(handlers::melod_create_detection::<AppState>, RoutePolicy::all_of(&["melod:detection", "detections:create", "detections:view", "search:execute"])),
            )
            .route_if(!shared_product, 
                "/api/melod/detection/tune",
                post(handlers::melod_tune_detection::<AppState>, RoutePolicy::all_of(&["melod:detection", "detections:view", "alerts:view", "search:execute"])),
            )
            // NAN-3219: tenant-wide AI tuning mode (shared twin lives in
            // enterprise_shared_melod_routes).
            .route_if(!shared_product,
                "/api/melod/settings/ai-tuning",
                get(handlers::melod_get_ai_tuning_mode::<AppState>, RoutePolicy::all_of(&["settings:ai"]))
                    .put(handlers::melod_update_ai_tuning_mode::<AppState>, RoutePolicy::all_of(&["settings:ai"])),
            )
            .route_if(!shared_product, 
                "/api/melod/detection/hints",
                post(handlers::melod_generate_detection_hints::<AppState>, RoutePolicy::all_of(&["melod:detection"])),
            )
            .route_if(!shared_product, 
                "/api/melod/summarize",
                post(handlers::melod_summarize::<AppState>, RoutePolicy::all_of(&["melod:summarize"])),
            )
            .route_if(!shared_product, 
                "/api/melod/fetch-url",
                post(handlers::melod_fetch_url::<AppState>, RoutePolicy::all_of(&["melod:detection"])),
            )
            .route_if(!shared_product, 
                "/api/melod/notebook/summarize",
                post(handlers::melod_summarize_notebook::<AppState>, RoutePolicy::all_of(&["melod:notebook", "notebooks:view"])),
            )
            .route_if(!shared_product, 
                "/api/melod/notebook/suggest-queries",
                post(handlers::melod_suggest_queries::<AppState>, RoutePolicy::all_of(&["melod:notebook"])),
            )
            .route_if(!shared_product, 
                "/api/melod/notebook/analyze-note",
                post(handlers::melod_analyze_note::<AppState>, RoutePolicy::all_of(&["melod:notebook"])),
            )
            .route_if(!shared_product, 
                "/api/melod/notebook/generate-timeline",
                post(handlers::melod_generate_timeline::<AppState>, RoutePolicy::all_of(&["melod:notebook"])),
            )
            // Dashboard generation endpoints
            .route_if(!shared_product, 
                "/api/melod/dashboard/generate",
                post(handlers::melod_generate_dashboard::<AppState>, RoutePolicy::all_of(&["melod:dashboard", "search:execute"])),
            )
            .route_if(!shared_product, 
                "/api/melod/dashboard/refine",
                post(handlers::melod_refine_dashboard::<AppState>, RoutePolicy::all_of(&["melod:dashboard", "search:execute"])),
            )
            // NAN-3205: pivt playbook drafting
            .route_if(!shared_product, 
                "/api/melod/playbook/draft",
                post(handlers::melod_draft_playbook::<AppState>, RoutePolicy::all_of(&["melod:chat", "playbooks:manage"])),
            )
            // Generic meloD async job poll endpoint
            .route_if(!shared_product, 
                "/api/melod/jobs/{job_id}",
                get(handlers::melod_get_job::<AppState>, RoutePolicy::any_of(&["enrichments:code", "melod:chat", "melod:query", "melod:parser", "melod:detection", "melod:summarize", "melod:dashboard", "melod:notebook"])),
            )
            // AI Debug endpoints
            .route_if(!shared_product, 
                "/api/melod/failures",
                get(handlers::melod::get_ai_failures::<AppState>, RoutePolicy::interactive_all_of(&["settings:ai", "settings:system"])),
            );
    }

    // OIDC / SSO endpoints — open-core split (NAN-745). The handlers module
    // itself is gated, so both the public `/api/auth/oidc/*` discovery routes
    // and the `/api/settings/oidc/*` admin routes only register when the
    // `enterprise` feature is on. Open builds simply omit them — the frontend
    // already gates the SSO surface behind `capabilities.sso`.
    //
    // NAN-751 Phase 2: handlers were lifted to the enterprise crate. They are
    // generic over the `OidcAppState` trait, so each call site below pins the
    // type parameter to `AppState` (the concrete state this router is built
    // with).
    #[cfg(feature = "enterprise")]
    {
        app = app
            // OIDC authentication endpoints (public)
            .route(
                "/api/auth/oidc/providers",
                get(handlers::oidc::list_enabled_providers::<AppState>, RoutePolicy::public()),
            )
            .route(
                "/api/auth/oidc/{provider}/authorize",
                get(handlers::oidc::get_auth_url::<AppState>, RoutePolicy::public()),
            )
            .route(
                "/api/auth/oidc/{provider}/callback",
                post(handlers::oidc::handle_callback::<AppState>, RoutePolicy::public()),
            )
            // OIDC provider management (admin)
            .route_if(!shared_product, 
                "/api/settings/oidc",
                get(handlers::oidc::list_providers::<AppState>, RoutePolicy::all_of(&["settings:system"])),
            )
            .route_if(!shared_product, 
                "/api/settings/oidc",
                post(handlers::oidc::create_provider::<AppState>, RoutePolicy::interactive_all_of(&["settings:system"])),
            )
            .route_if(!shared_product, 
                "/api/settings/oidc/{id}",
                get(handlers::oidc::get_provider::<AppState>, RoutePolicy::all_of(&["settings:system"])),
            )
            .route_if(!shared_product, 
                "/api/settings/oidc/{id}",
                put(handlers::oidc::update_provider::<AppState>, RoutePolicy::interactive_all_of(&["settings:system"])),
            )
            .route_if(!shared_product, 
                "/api/settings/oidc/{id}",
                delete(handlers::oidc::delete_provider::<AppState>, RoutePolicy::all_of(&["settings:system"])),
            )
            .route_if(!shared_product, 
                "/api/settings/oidc/{id}/enable",
                post(handlers::oidc::enable_provider::<AppState>, RoutePolicy::all_of(&["settings:system"])),
            )
            .route_if(!shared_product, 
                "/api/settings/oidc/{id}/disable",
                post(handlers::oidc::disable_provider::<AppState>, RoutePolicy::all_of(&["settings:system"])),
            )
            .route_if(!shared_product, 
                "/api/settings/oidc/{id}/mappings",
                get(handlers::oidc::get_group_mappings::<AppState>, RoutePolicy::all_of(&["settings:system"])),
            )
            .route_if(!shared_product, 
                "/api/settings/oidc/{id}/mappings",
                put(handlers::oidc::update_group_mappings::<AppState>, RoutePolicy::interactive_all_of(&["settings:system"])),
            )
            .route_if(!shared_product, 
                "/api/settings/oidc/{id}/token-groups",
                get(handlers::oidc::get_token_groups::<AppState>, RoutePolicy::all_of(&["settings:system"])),
            )
            // NAN-2181: the SSO-only toggle. Registered alongside the OIDC
            // admin routes because both halves of its lockout guard need
            // provider state — and because it is meaningless without SSO, so
            // it should not exist as a surface in an open-core build.
            .route_if(!shared_product,
                "/api/settings/auth-methods",
                get(handlers::oidc::get_auth_methods_settings::<AppState>, RoutePolicy::all_of(&["settings:system"])),
            )
            .route_if(!shared_product,
                "/api/settings/auth-methods",
                put(handlers::oidc::update_auth_methods_settings::<AppState>, RoutePolicy::all_of(&["settings:system"])),
            );
    }

    app = app
        // Retention settings
        .route_if(!shared_product, 
            "/api/settings/retention",
            get(handlers::get_retention_config, RoutePolicy::all_of(&["settings:retention"])),
        )
        .route_if(!shared_product, 
            "/api/settings/retention",
            put(handlers::update_retention_config, RoutePolicy::all_of(&["settings:retention"])),
        )
        .route(
            "/api/settings/retention/run",
            post(handlers::run_retention_now, RoutePolicy::all_of(&["settings:retention"])),
        )
        .route_if(!shared_product, "/api/settings/storage", get(handlers::get_storage_stats, RoutePolicy::all_of(&["settings:view"])))
        // Storage overview (both PostgreSQL and ClickHouse)
        .route_if(!shared_product, 
            "/api/settings/storage/overview",
            get(handlers::get_storage_overview, RoutePolicy::all_of(&["settings:view"])),
        )
        // ClickHouse storage settings
        .route(
            "/api/settings/storage/clickhouse",
            get(handlers::get_clickhouse_storage_stats, RoutePolicy::all_of(&["settings:view"])),
        )
        .route(
            "/api/settings/storage/clickhouse/retention",
            put(handlers::update_clickhouse_retention, RoutePolicy::all_of(&["settings:retention"])),
        )
        .route(
            "/api/settings/storage/clickhouse/retention/run",
            post(handlers::run_clickhouse_retention_now, RoutePolicy::all_of(&["settings:retention"])),
        )
        // Storage tiering settings
        .route("/api/settings/tiering", get(handlers::get_tiering_config, RoutePolicy::all_of(&["settings:retention"])))
        .route(
            "/api/settings/tiering",
            put(handlers::update_tiering_config, RoutePolicy::all_of(&["settings:retention"])),
        )
        .route(
            "/api/settings/tiering/credentials",
            post(handlers::set_tiering_credentials, RoutePolicy::all_of(&["settings:retention"])),
        )
        .route(
            "/api/settings/tiering/test",
            post(handlers::test_tiering_connection, RoutePolicy::all_of(&["settings:retention"])),
        )
        .route(
            "/api/settings/tiering/apply",
            post(handlers::apply_tiering_config, RoutePolicy::all_of(&["settings:retention"])),
        )
        .route("/api/settings/tiering/stats", get(handlers::get_tier_stats, RoutePolicy::all_of(&["settings:view"])))
        // Risk settings (weight stays open; decay TTL config is enterprise)
        .route_if(!shared_product, "/api/settings/risk", get(handlers::get_risk_config, RoutePolicy::all_of(&["risk:configure"])))
        .route_if(!shared_product, "/api/settings/risk", put(handlers::update_risk_config, RoutePolicy::all_of(&["risk:configure"])));

    // Risk decay TTL + risk-notable config — enterprise only
    // (RiskAnalyticsService, NAN-1792; since NAN-1805 the notable config is a
    // thin editor over the seeded default dataset=risk detection rule).
    #[cfg(feature = "enterprise")]
    {
        app = app
            .route_if(!shared_product, 
                "/api/settings/risk-decay",
                get(handlers::get_risk_decay_config, RoutePolicy::all_of(&["risk:configure"])),
            )
            .route_if(!shared_product, 
                "/api/settings/risk-decay",
                put(handlers::update_risk_decay_config, RoutePolicy::all_of(&["risk:configure"])),
            )
            .route_if(!shared_product, 
                "/api/settings/risk-notables",
                get(handlers::get_risk_notable_config, RoutePolicy::all_of(&["risk:configure"])),
            )
            .route_if(!shared_product, 
                "/api/settings/risk-notables",
                put(handlers::update_risk_notable_config, RoutePolicy::all_of(&["risk:configure"])),
            )
            // NAN-3226: dedicated internal DNS suffixes (shared tenants are
            // served by enterprise_shared_settings on the same path).
            .route_if(!shared_product, 
                "/api/settings/internal-domains",
                get(handlers::get_internal_domains, RoutePolicy::all_of(&["search:execute"])).put(handlers::update_internal_domains, RoutePolicy::all_of(&["settings:system"])),
            );
    }

    // Case settings + case grouping rules — Phase 3.2 (NAN-744): both
    // surfaces are part of the cases lift to enterprise.
    #[cfg(feature = "enterprise")]
    {
        app = app
            // Case settings (global auto-grouping config)
            .route_if(!shared_product, 
                "/api/settings/cases",
                get(handlers::cases::get_case_settings::<AppState>, RoutePolicy::all_of(&["settings:view"])),
            )
            .route_if(!shared_product, 
                "/api/settings/cases",
                put(handlers::cases::update_case_settings::<AppState>, RoutePolicy::all_of(&["settings:system"])),
            )
            // Case grouping rules
            .route_if(!shared_product, 
                "/api/settings/case-grouping",
                get(handlers::cases::list_grouping_rules::<AppState>, RoutePolicy::all_of(&["settings:view"])),
            )
            .route_if(!shared_product, 
                "/api/settings/case-grouping",
                post(handlers::cases::create_grouping_rule::<AppState>, RoutePolicy::all_of(&["settings:system"])),
            )
            .route_if(!shared_product, 
                "/api/settings/case-grouping/{id}",
                put(handlers::cases::update_grouping_rule::<AppState>, RoutePolicy::all_of(&["settings:system"])),
            )
            .route_if(!shared_product, 
                "/api/settings/case-grouping/{id}",
                delete(handlers::cases::delete_grouping_rule::<AppState>, RoutePolicy::all_of(&["settings:system"])),
            );
    }

    app = app
        // Prevalence settings
        .route_if(!shared_product, 
            "/api/settings/prevalence",
            get(handlers::prevalence::get_prevalence_settings, RoutePolicy::all_of(&["prevalence:configure"])),
        )
        .route_if(!shared_product, 
            "/api/settings/prevalence",
            put(handlers::prevalence::update_prevalence_settings, RoutePolicy::all_of(&["prevalence:configure"])),
        )
        // Identity provider settings (Entra ID, Google Workspace, AD)
        .route(
            "/api/settings/identity-providers",
            get(handlers::identity::list_identity_providers, RoutePolicy::all_of(&["enrichments:view"])),
        )
        .route(
            "/api/settings/identity-providers",
            post(handlers::identity::create_identity_provider, RoutePolicy::all_of(&["enrichments:configure"])),
        )
        .route(
            "/api/settings/identity-providers/{id}",
            get(handlers::identity::get_identity_provider, RoutePolicy::all_of(&["enrichments:view"])),
        )
        .route(
            "/api/settings/identity-providers/{id}",
            put(handlers::identity::update_identity_provider, RoutePolicy::all_of(&["enrichments:configure"])),
        )
        .route(
            "/api/settings/identity-providers/{id}",
            delete(handlers::identity::delete_identity_provider, RoutePolicy::all_of(&["enrichments:configure"])),
        )
        .route(
            "/api/settings/identity-providers/{id}/credentials",
            post(handlers::identity::update_identity_credentials, RoutePolicy::all_of(&["enrichments:configure"])),
        )
        .route(
            "/api/settings/identity-providers/{id}/test",
            post(handlers::identity::test_identity_connection, RoutePolicy::all_of(&["enrichments:configure"])),
        )
        .route(
            "/api/settings/identity-providers/{id}/sync",
            post(handlers::identity::trigger_identity_sync, RoutePolicy::all_of(&["enrichments:configure"])),
        )
        // NAN-1151 (3d): the AD /push endpoint is retired — AD identity flows
        // through the nano_enrich lane (collector POSTs to Vector ingest).
        // Identity user directory
        .route_if(!shared_product, 
            "/api/identity/users/lookup",
            get(handlers::identity::lookup_identity_user, RoutePolicy::all_of(&["enrichments:view"])),
        )
        .route_if(!shared_product, 
            "/api/identity/resolve",
            get(handlers::identity::resolve_identity_ip, RoutePolicy::all_of(&["enrichments:view"])),
        )
        .route_if(!shared_product, 
            "/api/identity/users",
            get(handlers::identity::list_identity_users, RoutePolicy::all_of(&["enrichments:view"])),
        )
        .route_if(!shared_product, 
            "/api/identity/users/{id}",
            get(handlers::identity::get_identity_user, RoutePolicy::all_of(&["enrichments:view"])),
        )
        .route_if(!shared_product, 
            "/api/identity/stats",
            get(handlers::identity::get_identity_stats, RoutePolicy::all_of(&["enrichments:view"])),
        );

    // Agent + custom enrichment routes — enterprise only (Phase 3.3 of
    // NAN-744 lifted both core modules + handler files; the Risk-page-style
    // AI-powered IOC enrichment surface and the Deno user-defined
    // enrichment surface are enterprise capabilities).
    #[cfg(feature = "enterprise")]
    {
        app = app
            // Agent enrichment settings (AI-powered threat intel providers).
            // NAN-2718: dedicated only. `agent_enrichment_providers` and
            // `enrichment_cache` carry no tenant_id, so in enterprise_shared
            // mode these routes are not mounted (404) rather than relying on
            // the runtime role's missing grants to fail closed.
            .route_if(!shared_product,
                "/api/settings/agent-enrichments",
                get(handlers::agent_enrichment::list_providers::<AppState>, RoutePolicy::all_of(&["enrichments:view"])),
            )
            .route_if(!shared_product,
                "/api/settings/agent-enrichments",
                post(handlers::agent_enrichment::create_provider::<AppState>, RoutePolicy::all_of(&["enrichments:configure"])),
            )
            .route_if(!shared_product,
                "/api/settings/agent-enrichments/{provider_id}",
                get(handlers::agent_enrichment::get_provider::<AppState>, RoutePolicy::all_of(&["enrichments:view"])),
            )
            .route_if(!shared_product,
                "/api/settings/agent-enrichments/{provider_id}",
                put(handlers::agent_enrichment::update_provider::<AppState>, RoutePolicy::all_of(&["enrichments:configure"])),
            )
            .route_if(!shared_product,
                "/api/settings/agent-enrichments/{provider_id}",
                delete(handlers::agent_enrichment::delete_provider::<AppState>, RoutePolicy::all_of(&["enrichments:configure"])),
            )
            .route_if(!shared_product,
                "/api/settings/agent-enrichments/{provider_id}/credentials",
                post(handlers::agent_enrichment::update_credentials::<AppState>, RoutePolicy::all_of(&["enrichments:configure"])),
            )
            .route_if(!shared_product,
                "/api/settings/agent-enrichments/{provider_id}/test",
                post(handlers::agent_enrichment::test_connection::<AppState>, RoutePolicy::all_of(&["enrichments:configure"])),
            )
            .route_if(!shared_product,
                "/api/settings/agent-enrichments/{provider_id}/usage",
                get(handlers::agent_enrichment::get_usage_stats::<AppState>, RoutePolicy::all_of(&["enrichments:view"])),
            )
            // Custom enrichments (user-defined TypeScript enrichments)
            .route_if(!shared_product, 
                "/api/custom-enrichments",
                get(handlers::custom_enrichment::list_custom_enrichments::<AppState>, RoutePolicy::all_of(&["enrichments:view"])),
            )
            .route_if(!shared_product, 
                "/api/custom-enrichments",
                post(handlers::custom_enrichment::create_custom_enrichment::<AppState>, RoutePolicy::all_of(&["enrichments:custom:create", "enrichments:code"])),
            )
            .route_if(!shared_product, 
                "/api/custom-enrichments/templates",
                get(handlers::custom_enrichment::get_templates, RoutePolicy::all_of(&["enrichments:view"])),
            )
            .route_if(!shared_product, 
                "/api/custom-enrichments/generate-code",
                post(handlers::custom_enrichment::generate_code::<AppState>, RoutePolicy::all_of(&["enrichments:code"])),
            )
            .route_if(!shared_product, 
                "/api/custom-enrichments/{id}",
                get(handlers::custom_enrichment::get_custom_enrichment::<AppState>, RoutePolicy::all_of(&["enrichments:view"])),
            )
            .route_if(!shared_product, 
                "/api/custom-enrichments/{id}",
                put(handlers::custom_enrichment::update_custom_enrichment::<AppState>, RoutePolicy::all_of(&["enrichments:configure"])),
            )
            .route_if(!shared_product, 
                "/api/custom-enrichments/{id}",
                delete(handlers::custom_enrichment::delete_custom_enrichment::<AppState>, RoutePolicy::all_of(&["enrichments:custom:delete"])),
            )
            .route_if(!shared_product, 
                "/api/custom-enrichments/{id}/validate",
                post(handlers::custom_enrichment::validate_enrichment::<AppState>, RoutePolicy::all_of(&["enrichments:configure"])),
            )
            .route_if(!shared_product, 
                "/api/custom-enrichments/{id}/deploy",
                post(handlers::custom_enrichment::deploy_enrichment::<AppState>, RoutePolicy::all_of(&["enrichments:configure"])),
            )
            .route_if(!shared_product, 
                "/api/custom-enrichments/{id}/disable",
                post(handlers::custom_enrichment::disable_enrichment::<AppState>, RoutePolicy::all_of(&["enrichments:configure"])),
            )
            .route_if(!shared_product, 
                "/api/custom-enrichments/{id}/versions",
                get(handlers::custom_enrichment::get_versions::<AppState>, RoutePolicy::all_of(&["enrichments:view"])),
            )
            .route_if(!shared_product, 
                "/api/custom-enrichments/{id}/versions/{version}/diff",
                get(handlers::custom_enrichment::get_version_diff::<AppState>, RoutePolicy::all_of(&["enrichments:view", "enrichments:code"])),
            )
            .route_if(!shared_product, 
                "/api/custom-enrichments/{id}/runs",
                get(handlers::custom_enrichment::get_runs::<AppState>, RoutePolicy::all_of(&["enrichments:view"])),
            )
            .route_if(!shared_product, 
                "/api/custom-enrichments/{id}/runs",
                post(handlers::custom_enrichment::trigger_run::<AppState>, RoutePolicy::all_of(&["enrichments:configure"])),
            );
    }

    // Integration collectors (NAN-2189). Enterprise only — the sandbox runtime
    // and scheduler that back these live in the enterprise crate.
    #[cfg(feature = "enterprise")]
    {
        app = app
            .route_if(!shared_product, 
                "/api/integrations/custom/generate-code",
                post(handlers::integration_generation::generate_collector_code::<AppState>, RoutePolicy::all_of(&["log_sources:create", "enrichments:code"])),
            )
            .route_if(!shared_product, 
                "/api/integrations/custom/validate",
                post(handlers::integrations::validate_custom_collector, RoutePolicy::all_of(&["log_sources:create", "enrichments:code"])),
            )
            .route_if(!shared_product, 
                "/api/integrations/custom/preview",
                post(handlers::integrations::preview_custom_collector, RoutePolicy::all_of(&["log_sources:create", "enrichments:code"])),
            )
            .route_if(!shared_product, 
                "/api/integrations/custom",
                post(handlers::integrations::create_custom_collector, RoutePolicy::all_of(&["log_sources:create", "enrichments:code"])),
            )
            // NAN-2862: must stay gated. The legacy PUT runs `deno check` on
            // tenant code in the shared API container; in shared mode the
            // ported router answers this path with `platform_managed`.
            .route_if(!shared_product,
                "/api/integrations/custom/{id}",
                get(handlers::integrations::get_custom_collector, RoutePolicy::all_of(&["log_sources:view", "enrichments:code"]))
                    .put(handlers::integrations::update_custom_collector, RoutePolicy::all_of(&["log_sources:edit", "enrichments:code"]))
                    .delete(handlers::integrations::delete_custom_collector, RoutePolicy::all_of(&["log_sources:delete", "enrichments:code"])),
            )
            .route_if(!shared_product, 
                "/api/integrations/instances",
                get(handlers::integrations::list_instances, RoutePolicy::all_of(&["log_sources:view"]))
                    .post(handlers::integrations::create_instance, RoutePolicy::all_of(&["log_sources:edit"])),
            )
            .route_if(!shared_product, 
                "/api/integrations/instances/{id}",
                get(handlers::integrations::get_instance, RoutePolicy::all_of(&["log_sources:view"]))
                    .put(handlers::integrations::update_instance, RoutePolicy::all_of(&["log_sources:edit"]))
                    .delete(handlers::integrations::delete_instance, RoutePolicy::all_of(&["log_sources:delete"])),
            )
            .route_if(!shared_product, 
                "/api/integrations/instances/{id}/run",
                post(handlers::integrations::trigger_run, RoutePolicy::all_of(&["log_sources:edit"])),
            );
    }

    app = app
        // Enrichment Marketplace (unified catalog)
        .route_if(!shared_product, 
            "/api/marketplace/catalog",
            get(handlers::marketplace::list_catalog, RoutePolicy::all_of(&["enrichments:view"])),
        )
        .route_if(!shared_product, 
            "/api/marketplace/catalog/{slug}",
            get(handlers::marketplace::get_catalog_entry, RoutePolicy::all_of(&["enrichments:view"])),
        )
        .route_if(!shared_product, 
            "/api/marketplace/catalog/{slug}/install",
            post(handlers::marketplace::install_enrichment, RoutePolicy::all_of(&["enrichments:configure"])),
        )
        .route_if(!shared_product, 
            "/api/marketplace/catalog/{slug}/uninstall",
            post(handlers::marketplace::uninstall_enrichment, RoutePolicy::all_of(&["enrichments:configure"])),
        )
        .route_if(!shared_product, 
            "/api/marketplace/catalog/{slug}/update",
            post(handlers::marketplace::update_enrichment, RoutePolicy::all_of(&["enrichments:configure"])),
        )
        .route_if(!shared_product, 
            "/api/marketplace/catalog/{slug}/configure",
            put(handlers::marketplace::configure_enrichment, RoutePolicy::all_of(&["enrichments:configure"])),
        )
        .route_if(!shared_product, 
            "/api/marketplace/catalog/{slug}/sync",
            post(handlers::marketplace::sync_enrichment, RoutePolicy::all_of(&["enrichments:configure"])),
        )
        .route_if(!shared_product, 
            "/api/marketplace/catalog/{slug}/status",
            get(handlers::marketplace::get_enrichment_status, RoutePolicy::all_of(&["enrichments:view"])),
        )
        .route_if(!shared_product, 
            "/api/marketplace/catalog/{slug}/export",
            get(handlers::marketplace::export_enrichment, RoutePolicy::all_of(&["enrichments:view", "enrichments:code"])),
        );

    app = app
        .route_if(!shared_product, 
            "/api/marketplace/coverage",
            get(handlers::marketplace::get_coverage, RoutePolicy::all_of(&["enrichments:view", "search:execute"])),
        )
        .route_if(!shared_product, 
            "/api/marketplace/coverage/refresh",
            post(handlers::marketplace::refresh_coverage, RoutePolicy::all_of(&["enrichments:view", "search:execute"])),
        )
        .route_if(!shared_product, 
            "/api/marketplace/repos",
            get(handlers::marketplace::list_repos, RoutePolicy::all_of(&["enrichments:view"])),
        )
        .route_if(!shared_product, 
            "/api/marketplace/repos",
            post(handlers::marketplace::create_repo, RoutePolicy::all_of(&["enrichments:configure"])),
        )
        .route_if(!shared_product, 
            "/api/marketplace/repos/{id}",
            put(handlers::marketplace::update_repo, RoutePolicy::all_of(&["enrichments:configure"])),
        )
        .route_if(!shared_product, 
            "/api/marketplace/repos/{id}",
            delete(handlers::marketplace::delete_repo, RoutePolicy::all_of(&["enrichments:configure"])),
        )
        .route_if(!shared_product, 
            "/api/marketplace/repos/{id}/sync",
            post(handlers::marketplace::sync_repo, RoutePolicy::all_of(&["enrichments:configure"])),
        )
        .route_if(!shared_product, 
            "/api/marketplace/repos/{id}/browse",
            get(handlers::marketplace::browse_repo, RoutePolicy::all_of(&["enrichments:view"])),
        )
        // Organizational context settings (custom prompt data)
        .route(
            "/api/settings/organizational-context",
            get(handlers::get_organizational_context, RoutePolicy::any_of(&["settings:view", "settings:ai"])),
        )
        .route(
            "/api/settings/organizational-context",
            put(handlers::update_organizational_context, RoutePolicy::all_of(&["settings:ai"])),
        );

    // AI provider credentials, agent-model bindings, and the model catalog
    // are enterprise only — they touch state.melod_service /
    // state.agent_config_registry, both of which live behind the enterprise
    // feature gate.
    #[cfg(feature = "enterprise")]
    {
        app = app
            .route_if(!shared_product, 
                "/api/settings/ai-availability",
                get(handlers::get_ai_availability, RoutePolicy::all_of(&["settings:ai"])),
            )
            .route_if(!shared_product, 
                "/api/settings/ai-providers",
                get(handlers::list_ai_providers, RoutePolicy::all_of(&["settings:ai_providers"])),
            )
            .route_if(!shared_product, 
                "/api/settings/ai-providers/{provider}",
                get(handlers::get_ai_provider, RoutePolicy::all_of(&["settings:ai_providers"])),
            )
            .route_if(!shared_product, 
                "/api/settings/ai-providers/{provider}",
                put(handlers::update_ai_provider, RoutePolicy::all_of(&["settings:ai_providers"])),
            )
            .route_if(!shared_product, 
                "/api/settings/ai-providers/{provider}/validate",
                post(handlers::validate_ai_provider, RoutePolicy::all_of(&["settings:ai_providers"])),
            )
            // Agent model configuration
            .route(
                "/api/settings/agent-models",
                get(handlers::list_agent_model_configs, RoutePolicy::all_of(&["settings:agent_models"])),
            )
            .route(
                "/api/settings/agent-models/{agent_id}",
                get(handlers::get_agent_model_config, RoutePolicy::all_of(&["settings:agent_models"])),
            )
            .route(
                "/api/settings/agent-models/{agent_id}",
                put(handlers::update_agent_model_config, RoutePolicy::all_of(&["settings:agent_models"])),
            )
            // Available models (filtered by enabled providers)
            .route(
                "/api/settings/available-models/all",
                get(handlers::list_all_available_models, RoutePolicy::all_of(&["settings:agent_models"])),
            )
            .route(
                "/api/settings/available-models",
                get(handlers::list_available_models, RoutePolicy::all_of(&["settings:agent_models"])),
            )
            .route(
                "/api/settings/available-models",
                post(handlers::create_available_model, RoutePolicy::all_of(&["settings:agent_models"])),
            )
            .route(
                "/api/settings/available-models/{model_id}",
                put(handlers::update_available_model, RoutePolicy::all_of(&["settings:agent_models"])),
            )
            .route(
                "/api/settings/available-models/{model_id}",
                delete(handlers::delete_available_model, RoutePolicy::all_of(&["settings:agent_models"])),
            )
            // Model catalog sync
            .route(
                "/api/settings/model-catalog/sync",
                post(handlers::sync_model_catalog, RoutePolicy::all_of(&["settings:agent_models"])),
            )
            .route(
                "/api/settings/model-catalog/status",
                get(handlers::get_model_catalog_status, RoutePolicy::all_of(&["settings:agent_models"])),
            );
    }

    app = app
        // Health monitoring settings
        .route_if(!shared_product, 
            "/api/settings/health-monitoring",
            get(handlers::get_health_monitoring_settings, RoutePolicy::all_of(&["settings:system"])),
        )
        .route_if(!shared_product, 
            "/api/settings/health-monitoring",
            put(handlers::update_health_monitoring_settings, RoutePolicy::all_of(&["settings:system"])),
        )
        // Developer settings (scheduler control)
        .route(
            "/api/settings/developer",
            get(handlers::get_developer_settings, RoutePolicy::all_of(&["settings:system"])),
        )
        .route(
            "/api/settings/developer",
            put(handlers::update_developer_settings, RoutePolicy::all_of(&["settings:system"])),
        )
        // Search admission control settings
        .route_if(!shared_product, 
            "/api/settings/search",
            get(handlers::get_search_admission_settings, RoutePolicy::all_of(&["settings:system"])),
        )
        .route_if(!shared_product, 
            "/api/settings/search",
            put(handlers::update_search_admission_settings, RoutePolicy::all_of(&["settings:system"])),
        )
        // Search query safety limits
        .route_if(!shared_product, 
            "/api/settings/search/query-limits",
            get(handlers::get_search_query_limits, RoutePolicy::all_of(&["settings:system"])),
        )
        .route_if(!shared_product, 
            "/api/settings/search/query-limits",
            put(handlers::update_search_query_limits, RoutePolicy::all_of(&["settings:system"])),
        )
        // Tier settings
        .route_if(!shared_product, "/api/settings/tier", get(handlers::get_tier_status, RoutePolicy::all_of(&["settings:system"])))
        .route_if(!shared_product, "/api/settings/tier", put(handlers::set_tier, RoutePolicy::all_of(&["settings:system"])))
        .route_if(!shared_product, 
            "/api/settings/tier/limits",
            put(handlers::update_tier_limits, RoutePolicy::all_of(&["settings:system"])),
        )
        .route("/api/settings/tier/usage", get(handlers::get_usage_history, RoutePolicy::all_of(&["settings:system"])))
        .route_if(!shared_product, "/api/settings/ai-usage", get(handlers::get_ai_usage_detail, RoutePolicy::all_of(&["settings:system"])))
        // Webhook settings
        .route_if(!shared_product, "/api/settings/webhooks", get(handlers::list_webhooks, RoutePolicy::all_of(&["settings:webhooks"])))
        .route_if(!shared_product, "/api/settings/webhooks", post(handlers::create_webhook, RoutePolicy::all_of(&["settings:webhooks"])))
        .route_if(!shared_product, "/api/settings/webhooks/{id}", get(handlers::get_webhook, RoutePolicy::all_of(&["settings:webhooks"])))
        .route_if(!shared_product, "/api/settings/webhooks/{id}", put(handlers::update_webhook, RoutePolicy::all_of(&["settings:webhooks"])))
        .route_if(!shared_product, 
            "/api/settings/webhooks/{id}",
            delete(handlers::delete_webhook, RoutePolicy::all_of(&["settings:webhooks"])),
        )
        .route_if(!shared_product, 
            "/api/settings/webhooks/{id}/test",
            post(handlers::test_webhook, RoutePolicy::all_of(&["settings:webhooks"])),
        )
        .route_if(!shared_product, 
            "/api/settings/webhooks/{id}/deliveries",
            get(handlers::list_webhook_deliveries, RoutePolicy::all_of(&["settings:webhooks"])),
        )
        // Notification config (deep-link base URL) — NAN-1790
        .route_if(!shared_product, 
            "/api/settings/notifications/config",
            get(handlers::get_notification_config, RoutePolicy::all_of(&["settings:webhooks"])),
        )
        .route_if(!shared_product, 
            "/api/settings/notifications/config",
            put(handlers::update_notification_config, RoutePolicy::all_of(&["settings:webhooks"])),
        )
        // Onboarding wizard
        .route_if(!shared_product, 
            "/api/onboarding/progress",
            get(handlers::onboarding::get_onboarding_progress, RoutePolicy::interactive_session()),
        )
        .route_if(!shared_product, 
            "/api/onboarding/progress",
            put(handlers::onboarding::update_onboarding_progress, RoutePolicy::interactive_session()),
        )
        .route_if(!shared_product, 
            "/api/onboarding/complete-step",
            post(handlers::onboarding::complete_onboarding_step, RoutePolicy::interactive_session()),
        )
        .route_if(!shared_product, 
            "/api/onboarding/skip-step",
            post(handlers::onboarding::skip_onboarding_step, RoutePolicy::interactive_session()),
        )
        .route_if(!shared_product, 
            "/api/onboarding/dismiss",
            post(handlers::onboarding::dismiss_onboarding, RoutePolicy::interactive_all_of(&["settings:view"])),
        )
        .route_if(!shared_product, 
            "/api/onboarding/reset",
            post(handlers::onboarding::reset_onboarding, RoutePolicy::interactive_all_of(&["settings:view"])),
        )
        .route_if(!shared_product, 
            "/api/onboarding/status",
            get(handlers::onboarding::get_onboarding_status, RoutePolicy::interactive_all_of(&["settings:view"])),
        )
        // IP Allowlist settings
        .route(
            "/api/settings/ip-allowlist",
            get(handlers::ip_allowlist::list_ip_allowlist, RoutePolicy::all_of(&["settings:view"])),
        )
        .route(
            "/api/settings/ip-allowlist",
            post(handlers::ip_allowlist::create_ip_allowlist, RoutePolicy::all_of(&["settings:system"])),
        )
        .route(
            "/api/settings/ip-allowlist/status",
            get(handlers::ip_allowlist::get_ip_allowlist_status, RoutePolicy::all_of(&["settings:view"])),
        )
        .route(
            "/api/settings/ip-allowlist/test",
            post(handlers::ip_allowlist::test_ip_allowlist, RoutePolicy::all_of(&["settings:view"])),
        )
        .route(
            "/api/settings/ip-allowlist/{id}",
            put(handlers::ip_allowlist::update_ip_allowlist, RoutePolicy::all_of(&["settings:system"])),
        )
        .route(
            "/api/settings/ip-allowlist/{id}",
            delete(handlers::ip_allowlist::delete_ip_allowlist, RoutePolicy::all_of(&["settings:system"])),
        )
        // Feedback
        .route_if(!shared_product, "/api/feedback", get(handlers::feedback::list_feedback, RoutePolicy::interactive_session()))
        .route_if(!shared_product, "/api/feedback", post(handlers::feedback::create_feedback, RoutePolicy::interactive_session()))
        .route_if(!shared_product, 
            "/api/feedback/me",
            get(handlers::feedback::list_my_feedback, RoutePolicy::interactive_session()),
        )
        .route_if(!shared_product, "/api/feedback/{id}", get(handlers::feedback::get_feedback, RoutePolicy::all_of(&["users:view"])))
        .route_if(!shared_product, 
            "/api/feedback/{id}",
            put(handlers::feedback::update_feedback, RoutePolicy::all_of(&["users:edit"])),
        )
        .route_if(!shared_product, 
            "/api/feedback/{id}",
            delete(handlers::feedback::delete_feedback, RoutePolicy::all_of(&["users:edit"])),
        )
        // Folder settings (NAN-730)
        .route_if(!shared_product, 
            "/api/folder-settings",
            get(handlers::folder_settings::list_folder_settings, RoutePolicy::all_of(&["detections:view"])),
        )
        .route_if(!shared_product, 
            "/api/folder-settings/{name}",
            put(handlers::folder_settings::set_folder_icon, RoutePolicy::all_of(&["detections:edit"])),
        )
        .route_if(!shared_product, 
            "/api/folder-settings/{name}",
            delete(handlers::folder_settings::clear_folder_icon, RoutePolicy::all_of(&["detections:edit"])),
        )
        // Notifications
        .route_if(!shared_product, 
            "/api/notifications",
            get(handlers::notifications::list_notifications, RoutePolicy::interactive_all_of(&["notifications:view"])),
        )
        .route_if(!shared_product, 
            "/api/notifications/unread-count",
            get(handlers::notifications::get_unread_count, RoutePolicy::interactive_all_of(&["notifications:view"])),
        )
        .route_if(!shared_product, 
            "/api/notifications/read-all",
            post(handlers::notifications::mark_all_notifications_read, RoutePolicy::interactive_all_of(&["notifications:view"])),
        )
        .route_if(!shared_product, 
            "/api/notifications/{id}/read",
            post(handlers::notifications::mark_notification_read, RoutePolicy::interactive_all_of(&["notifications:view"])),
        );

    // Risk analytics (RiskAnalyticsService) — enterprise only.
    #[cfg(feature = "enterprise")]
    {
        if !config.deployment_mode.is_enterprise_shared() {
            app = app
                .route_if(!shared_product, 
                    "/api/risk/entities",
                    get(handlers::risk::get_risky_entities::<AppState>, RoutePolicy::all_of(&["risk:view"])),
                )
                .route_if(!shared_product, 
                    "/api/risk/overview",
                    get(handlers::risk::get_risk_overview::<AppState>, RoutePolicy::all_of(&["risk:view"])),
                )
                .route_if(!shared_product, 
                    "/api/risk/clear",
                    post(handlers::risk::clear_entity_risk::<AppState>, RoutePolicy::all_of(&["risk:clear"])),
                )
                .route_if(!shared_product, 
                    "/api/risk/clear-all",
                    post(handlers::risk::clear_all_risk_scores::<AppState>, RoutePolicy::all_of(&["risk:clear"])),
                )
                .route_if(!shared_product, 
                    "/api/risk/time-windowed",
                    get(handlers::risk::get_time_windowed_risk_scores::<AppState>, RoutePolicy::all_of(&["risk:view"])),
                )
                .route_if(!shared_product, 
                    "/api/risk/notable-count",
                    get(handlers::risk::get_notable_count::<AppState>, RoutePolicy::all_of(&["risk:view"])),
                )
                // NAN-1806: /api/risk/thresholds retired with the notable scheduler
                // (NAN-1805) — risk alerting is a `dataset=risk` detection rule.
                .route_if(!shared_product, 
                    "/api/risk/entity-activity",
                    get(handlers::risk::get_entity_activity::<AppState>, RoutePolicy::all_of(&["risk:view"])),
                )
                // NAN-3228: weighted risk watchlists.
                .route_if(!shared_product,
                    "/api/risk/watchlists",
                    get(handlers::risk_watchlists::list_watchlists::<AppState>, RoutePolicy::all_of(&["risk:view", "risk:watchlists"]))
                        .post(handlers::risk_watchlists::create_watchlist::<AppState>, RoutePolicy::all_of(&["risk:view", "risk:watchlists"])),
                )
                .route_if(!shared_product,
                    "/api/risk/watchlists/memberships",
                    get(handlers::risk_watchlists::get_memberships::<AppState>, RoutePolicy::all_of(&["risk:view", "risk:watchlists"])),
                )
                .route_if(!shared_product,
                    "/api/risk/watchlists/lookup",
                    get(handlers::risk_watchlists::lookup_entity::<AppState>, RoutePolicy::all_of(&["risk:view", "risk:watchlists"])),
                )
                // NAN-3249: observed entity variants + "not seen" flag.
                .route_if(!shared_product,
                    "/api/risk/watchlists/suggest",
                    post(handlers::risk_watchlists::suggest_entities::<AppState>, RoutePolicy::all_of(&["risk:view", "risk:watchlists"])),
                )
                .route_if(!shared_product,
                    "/api/risk/watchlists/{watchlist_id}",
                    get(handlers::risk_watchlists::get_watchlist::<AppState>, RoutePolicy::all_of(&["risk:view", "risk:watchlists"]))
                        .patch(handlers::risk_watchlists::update_watchlist::<AppState>, RoutePolicy::all_of(&["risk:view", "risk:watchlists"]))
                        .delete(handlers::risk_watchlists::delete_watchlist::<AppState>, RoutePolicy::all_of(&["risk:view", "risk:watchlists"])),
                )
                .route_if(!shared_product,
                    "/api/risk/watchlists/{watchlist_id}/members",
                    post(handlers::risk_watchlists::add_members::<AppState>, RoutePolicy::all_of(&["risk:view", "risk:watchlists"])),
                )
                .route_if(!shared_product,
                    "/api/risk/watchlists/{watchlist_id}/members/remove",
                    post(handlers::risk_watchlists::remove_members::<AppState>, RoutePolicy::all_of(&["risk:view", "risk:watchlists"])),
                );
        }
    }

    // Entity context — enterprise only (depends on RiskAnalyticsService).
    #[cfg(feature = "enterprise")]
    {
        if !config.deployment_mode.is_enterprise_shared() {
            app = app.route_if(!shared_product, 
                "/api/entities/{entity_type}/{entity_value}/context",
                get(handlers::entity_context::get_entity_context::<AppState>, RoutePolicy::all_of(&["risk:view", "alerts:view", "cases:view", "detections:view"])),
            );
            // NAN-3225: entity risk score over time.
            app = app.route_if(!shared_product,
                "/api/entities/{entity_type}/{entity_value}/risk-timeline",
                get(handlers::entity_context::get_entity_risk_timeline::<AppState>, RoutePolicy::all_of(&["risk:view", "detections:view"])),
            );
        }
    }

    app = app
        // Prevalence tracking
        .route_if(!shared_product, 
            "/api/prevalence/hash/{hash}",
            get(handlers::prevalence::get_hash_prevalence, RoutePolicy::all_of(&["prevalence:view"])),
        )
        .route_if(!shared_product, 
            "/api/prevalence/domain/{domain}",
            get(handlers::prevalence::get_domain_prevalence, RoutePolicy::all_of(&["prevalence:view"])),
        )
        .route_if(!shared_product, 
            "/api/prevalence/bulk",
            post(handlers::prevalence::get_bulk_prevalence, RoutePolicy::all_of(&["prevalence:view"])),
        )
        .route_if(!shared_product, 
            "/api/prevalence/rare",
            get(handlers::prevalence::get_rare_artifacts, RoutePolicy::all_of(&["prevalence:view"])),
        )
        .route_if(!shared_product, 
            "/api/prevalence/new",
            get(handlers::prevalence::get_new_artifacts, RoutePolicy::all_of(&["prevalence:view"])),
        )
        .route_if(!shared_product, 
            "/api/prevalence/export",
            get(handlers::prevalence::export_prevalence, RoutePolicy::all_of(&["prevalence:export"])),
        )
        .route_if(!shared_product, 
            "/api/prevalence/scatter",
            post(handlers::prevalence::get_scatter_data, RoutePolicy::all_of(&["prevalence:view"])),
        )
        .route_if(!shared_product, 
            "/api/prevalence/query-artifacts",
            post(handlers::prevalence::get_query_artifacts, RoutePolicy::all_of(&["prevalence:view", "search:execute"])),
        )
        .route_if(!shared_product, 
            "/api/prevalence/explorer",
            get(handlers::prevalence::get_artifact_explorer, RoutePolicy::all_of(&["prevalence:view"])),
        )
        .route_if(!shared_product, 
            "/api/prevalence/explorer/detail",
            get(handlers::prevalence::get_artifact_detail, RoutePolicy::all_of(&["prevalence:view"])),
        )
        // MITRE ATT&CK framework
        .route("/api/mitre/sync", post(handlers::mitre::sync_mitre_data, RoutePolicy::all_of(&["mitre:sync"])))
        // NAN-1918: uncached — an operator checking this has just been told a
        // sync dropped mappings, and a stale answer would be worse than none.
        .route_if(!shared_product, 
            "/api/mitre/quarantine",
            get(handlers::mitre::get_quarantined_mappings, RoutePolicy::all_of(&["mitre:view"])),
        )
        // Detection-as-code push targets: AI tuning opens PRs here (NAN-1745).
        .route_if(!shared_product, 
            "/api/detection-code-targets",
            get(handlers::detection_code_targets::list_targets, RoutePolicy::all_of(&["detection_code_targets:view"]))
                .post(handlers::detection_code_targets::create_target, RoutePolicy::all_of(&["detection_code_targets:manage"])),
        )
        .route_if(!shared_product, 
            "/api/detection-code-targets/{id}",
            get(handlers::detection_code_targets::get_target, RoutePolicy::all_of(&["detection_code_targets:view"]))
                .put(handlers::detection_code_targets::update_target, RoutePolicy::all_of(&["detection_code_targets:manage"]))
                .delete(handlers::detection_code_targets::delete_target, RoutePolicy::all_of(&["detection_code_targets:manage"])),
        )
        .route_if(!shared_product, 
            "/api/detection-code-targets/{id}/token",
            post(handlers::detection_code_targets::set_token, RoutePolicy::all_of(&["detection_code_targets:manage"])),
        )
        // Rule Repositories (external Sigma rule syncing)
        .route_if(!shared_product, 
            "/api/rule-repositories",
            get(handlers::rule_repositories::list_repositories, RoutePolicy::all_of(&["rule_repositories:view"])),
        )
        .route_if(!shared_product, 
            "/api/rule-repositories",
            post(handlers::rule_repositories::create_repository, RoutePolicy::all_of(&["rule_repositories:manage"])),
        )
        .route_if(!shared_product, 
            "/api/rule-repositories/coverage",
            get(handlers::rule_repositories::get_coverage, RoutePolicy::all_of(&["rule_repositories:view"])),
        )
        .route_if(!shared_product, 
            "/api/rule-repositories/coverage/refresh",
            post(handlers::rule_repositories::refresh_coverage, RoutePolicy::all_of(&["rule_repositories:sync"])),
        )
        .route_if(!shared_product, 
            "/api/rule-repositories/{id}",
            get(handlers::rule_repositories::get_repository, RoutePolicy::all_of(&["rule_repositories:view"])),
        )
        .route_if(!shared_product, 
            "/api/rule-repositories/{id}",
            put(handlers::rule_repositories::update_repository, RoutePolicy::all_of(&["rule_repositories:manage"])),
        )
        .route_if(!shared_product, 
            "/api/rule-repositories/{id}",
            delete(handlers::rule_repositories::delete_repository, RoutePolicy::all_of(&["rule_repositories:manage"])),
        )
        .route_if(!shared_product, 
            "/api/rule-repositories/{id}/sync",
            post(handlers::rule_repositories::sync_repository, RoutePolicy::all_of(&["rule_repositories:sync"])),
        )
        .route_if(!shared_product, 
            "/api/rule-repositories/{id}/sync/status",
            get(handlers::rule_repositories::get_sync_status, RoutePolicy::all_of(&["rule_repositories:view"])),
        )
        .route_if(!shared_product, 
            "/api/rule-repositories/{id}/folders",
            get(handlers::rule_repositories::list_folders, RoutePolicy::all_of(&["rule_repositories:view"])),
        )
        .route_if(!shared_product, 
            "/api/rule-repositories/{id}/rules",
            get(handlers::rule_repositories::list_repository_rules, RoutePolicy::all_of(&["rule_repositories:view"])),
        )
        .route_if(!shared_product, 
            "/api/rule-repositories/{id}/rules/by-path/{*path}",
            get(handlers::rule_repositories::get_repository_rule, RoutePolicy::all_of(&["rule_repositories:view"])),
        )
        .route_if(!shared_product, 
            "/api/rule-repositories/{id}/rules/preview/{*path}",
            get(handlers::rule_repositories::preview_import, RoutePolicy::all_of(&["rule_repositories:view"])),
        )
        .route_if(!shared_product, 
            "/api/rule-repositories/{id}/rules/import/{*path}",
            post(handlers::rule_repositories::import_rule, RoutePolicy::all_of(&["rule_repositories:import"])),
        )
        .route_if(!shared_product, 
            "/api/rule-repositories/{id}/rules/import-batch",
            post(handlers::rule_repositories::batch_import_rules, RoutePolicy::all_of(&["rule_repositories:import"])),
        )
        .route_if(!shared_product, 
            "/api/rule-repositories/{id}/rules/remove-all-imported",
            post(handlers::rule_repositories::remove_all_imported, RoutePolicy::all_of(&["rule_repositories:manage"])),
        )
        .route_if(!shared_product, 
            "/api/rule-repositories/{id}/upstream-updates",
            get(handlers::rule_repositories::get_upstream_updates, RoutePolicy::all_of(&["rule_repositories:view"])),
        )
        // Upstream diff for a detection rule (separate from repo routes)
        .route_if(!shared_product, 
            "/api/detection-rules/{id}/upstream-diff",
            get(handlers::rule_repositories::get_upstream_diff, RoutePolicy::all_of(&["rule_repositories:view"])),
        )
        .route_if(!shared_product, 
            "/api/detection-rules/{id}/upstream-diff/dismiss",
            post(handlers::rule_repositories::dismiss_upstream_changes, RoutePolicy::all_of(&["detections:edit"])),
        )
        // Sigma conversion (standalone)
        .route(
            "/api/sigma/convert",
            post(handlers::rule_repositories::convert_sigma, RoutePolicy::all_of(&["melod:detection"])),
        )
        // Parser Repositories (external parser syncing)
        .route_if(!shared_product, 
            "/api/parser-repositories",
            get(handlers::parser_repositories::list_parser_repositories, RoutePolicy::all_of(&["parser_repositories:view"])),
        )
        .route_if(!shared_product, 
            "/api/parser-repositories",
            post(handlers::parser_repositories::create_parser_repository, RoutePolicy::all_of(&["parser_repositories:manage"])),
        )
        // NAN-2120: repository-scoped. The predecessor
        // `/api/parser-repositories/fixup-match-values` rewrote live
        // `match_values` for EVERY import in the tenant from a single request
        // holding only `parser_repositories:manage`.
        .route_if(!shared_product, 
            "/api/parser-repositories/{id}/fixup-match-values",
            post(handlers::parser_repositories::fixup_match_values, RoutePolicy::all_of(&["parser_repositories:manage"])),
        )
        .route_if(!shared_product, 
            "/api/parser-repositories/{id}",
            get(handlers::parser_repositories::get_parser_repository, RoutePolicy::all_of(&["parser_repositories:view"])),
        )
        .route_if(!shared_product, 
            "/api/parser-repositories/{id}",
            put(handlers::parser_repositories::update_parser_repository, RoutePolicy::all_of(&["parser_repositories:manage"])),
        )
        .route_if(!shared_product, 
            "/api/parser-repositories/{id}",
            delete(handlers::parser_repositories::delete_parser_repository, RoutePolicy::all_of(&["parser_repositories:manage"])),
        )
        .route_if(!shared_product, 
            "/api/parser-repositories/{id}/sync",
            post(handlers::parser_repositories::sync_parser_repository, RoutePolicy::all_of(&["parser_repositories:sync"])),
        )
        .route_if(!shared_product, 
            "/api/parser-repositories/{id}/sync/status",
            get(handlers::parser_repositories::get_parser_sync_status, RoutePolicy::all_of(&["parser_repositories:view"])),
        )
        .route_if(!shared_product, 
            "/api/parser-repositories/{id}/parsers",
            get(handlers::parser_repositories::list_repository_parsers, RoutePolicy::all_of(&["parser_repositories:view"])),
        )
        .route_if(!shared_product, 
            "/api/parser-repositories/{id}/parsers/by-path/{*path}",
            get(handlers::parser_repositories::get_repository_parser, RoutePolicy::all_of(&["parser_repositories:view"])),
        )
        .route_if(!shared_product, 
            "/api/parser-repositories/{id}/parsers/preview/{*path}",
            get(handlers::parser_repositories::preview_parser_import, RoutePolicy::all_of(&["parser_repositories:view"])),
        )
        .route_if(!shared_product, 
            "/api/parser-repositories/{id}/parsers/import/{*path}",
            post(handlers::parser_repositories::import_parser, RoutePolicy::all_of(&["parser_repositories:import"])),
        )
        .route_if(!shared_product, 
            "/api/parser-repositories/{id}/parsers/import-batch",
            post(handlers::parser_repositories::batch_import_parsers, RoutePolicy::all_of(&["parser_repositories:import"])),
        )
        .route_if(!shared_product, 
            "/api/parser-repositories/{id}/parsers/remove-all-imported",
            post(handlers::parser_repositories::remove_all_imported_parsers, RoutePolicy::all_of(&["parser_repositories:manage"])),
        )
        .route_if(!shared_product, 
            "/api/parser-repositories/{id}/upstream-updates",
            get(handlers::parser_repositories::get_parser_upstream_updates, RoutePolicy::all_of(&["parser_repositories:view"])),
        )
        // Upstream diff for a log source (parser repo)
        .route_if(!shared_product, 
            "/api/log-sources/{id}/upstream-diff",
            get(handlers::parser_repositories::get_log_source_upstream_diff, RoutePolicy::all_of(&["parser_repositories:view"])),
        )
        .route_if(!shared_product, 
            "/api/log-sources/{id}/upstream-diff/dismiss",
            post(handlers::parser_repositories::dismiss_parser_upstream_changes, RoutePolicy::all_of(&["parsers:edit"])),
        )
        .route_if(!shared_product, 
            "/api/log-sources/{id}/apply-upstream-update",
            post(handlers::parser_repositories::apply_upstream_update, RoutePolicy::all_of(&["parsers:edit"])),
        )
        .route_if(!shared_product, 
            "/api/parser-repositories/{id}/apply-all-upstream-updates",
            post(handlers::parser_repositories::apply_all_upstream_updates, RoutePolicy::all_of(&["parsers:edit"])),
        )
        // Playbooks library
        .route_if(!shared_product, "/api/playbooks", get(handlers::playbooks::list_playbooks, RoutePolicy::all_of(&["playbooks:view"])))
        .route_if(!shared_product, "/api/playbooks", post(handlers::playbooks::create_playbook, RoutePolicy::all_of(&["playbooks:manage"])))
        .route_if(!shared_product, 
            "/api/playbooks/{id}",
            get(handlers::playbooks::get_playbook, RoutePolicy::all_of(&["playbooks:view"])),
        )
        .route_if(!shared_product, 
            "/api/playbooks/{id}",
            patch(handlers::playbooks::update_playbook, RoutePolicy::all_of(&["playbooks:manage"])),
        )
        .route_if(!shared_product, 
            "/api/playbooks/{id}",
            delete(handlers::playbooks::archive_playbook, RoutePolicy::all_of(&["playbooks:manage"])),
        )
        .route_if(!shared_product, 
            "/api/playbooks/{id}/fork",
            post(handlers::playbooks::fork_playbook, RoutePolicy::all_of(&["playbooks:manage"])),
        )
        .route_if(!shared_product, 
            "/api/playbooks/{id}/permanent",
            delete(handlers::playbooks::delete_playbook_permanent, RoutePolicy::all_of(&["playbooks:manage"])),
        )
        .route_if(!shared_product, 
            "/api/playbooks/{id}/versions",
            get(handlers::playbooks::list_versions, RoutePolicy::all_of(&["playbooks:view"])),
        )
        .route_if(!shared_product, 
            "/api/playbooks/{id}/runs",
            get(handlers::playbooks::list_runs, RoutePolicy::all_of(&["playbooks:view", "cases:view"])),
        )
        .route_if(!shared_product, 
            "/api/playbooks/{id}/permissions",
            get(handlers::playbooks::list_permissions, RoutePolicy::all_of(&["playbooks:view"])),
        )
        .route_if(!shared_product, 
            "/api/playbooks/{id}/approvals",
            get(handlers::playbooks::list_approvals, RoutePolicy::all_of(&["playbooks:view"])),
        )
        // NAN-445: Phase 4 — suggest + runs (rule/case auto-attach)
        .route_if(!shared_product, 
            "/api/playbooks/suggest-for-rule/{rule_id}",
            get(handlers::playbooks::suggest_for_rule, RoutePolicy::all_of(&["playbooks:view", "detections:view"])),
        )
        // NAN-473: dry-resolve mounted separately below (rate-limited sub-router).
        .route_if(!shared_product, 
            "/api/playbooks/{id}/runs",
            post(handlers::playbooks::attach_to_case, RoutePolicy::all_of(&["playbooks:run", "cases:edit"])),
        )
        .route_if(!shared_product, 
            "/api/playbook-runs/{id}",
            patch(handlers::playbooks::finish_run, RoutePolicy::all_of(&["playbooks:run", "cases:edit"])),
        )
        .route_if(!shared_product, 
            "/api/cases/{case_id}/playbook-runs",
            get(handlers::playbooks::list_runs_for_case, RoutePolicy::all_of(&["playbooks:view", "cases:view"])),
        )
        // NAN-462: resolve a run against its run_context snapshot
        .route_if(!shared_product, 
            "/api/playbook-runs/{id}/resolved",
            get(handlers::playbooks::resolve_run, RoutePolicy::all_of(&["playbooks:view", "cases:view"])),
        )
        // NAN-463: per-step completion upsert (active-run surface)
        .route_if(!shared_product, 
            "/api/playbook-runs/{run_id}/steps/{step_id}",
            patch(handlers::playbooks::update_step_completion, RoutePolicy::all_of(&["playbooks:run", "cases:edit"])),
        )
        // NAN-446: Phase 5 — adaptive → library promote
        .route_if(!shared_product, 
            "/api/playbooks/{id}/promote",
            post(handlers::playbooks::promote_playbook, RoutePolicy::all_of(&["playbooks:publish"])),
        )
        // NAN-447: Phase 6 — approval workflow + permissions
        .route_if(!shared_product, 
            "/api/playbooks/{id}/submit-for-review",
            post(handlers::playbooks::submit_for_review, RoutePolicy::all_of(&["playbooks:manage"])),
        )
        .route_if(!shared_product, 
            "/api/playbook-approvals/{id}/approve",
            post(handlers::playbooks::approve_playbook, RoutePolicy::all_of(&["playbooks:publish"])),
        )
        .route_if(!shared_product, 
            "/api/playbook-approvals/{id}/reject",
            post(handlers::playbooks::reject_playbook, RoutePolicy::all_of(&["playbooks:publish"])),
        )
        .route_if(!shared_product, 
            "/api/playbooks/{id}/permissions/{role}",
            nanosiem_api_lib::route_policy::routing::put(handlers::playbooks::set_permission, RoutePolicy::all_of(&["playbooks:manage"])),
        )
        .route_if(!shared_product, 
            "/api/playbooks/{id}/permissions/{role}",
            nanosiem_api_lib::route_policy::routing::delete(handlers::playbooks::delete_permission, RoutePolicy::all_of(&["playbooks:manage"])),
        )
        // NAN-448: Phase 7 — real analytics
        .route_if(!shared_product, 
            "/api/playbooks/{id}/analytics",
            get(handlers::playbooks::get_analytics, RoutePolicy::all_of(&["playbooks:view"])),
        )
        // NAN-449: Phase 5b — compose adaptive playbook from case
        .route_if(!shared_product, 
            "/api/cases/{case_id}/compose-adaptive-playbook",
            post(handlers::playbooks::compose_adaptive_from_case, RoutePolicy::all_of(&["playbooks:manage", "cases:view"])),
        )
        // NAN-2238 Active Hunter.
        //
        // The static collections (`runners`, `sweeps`, `leads`, `suppressions`,
        // `profile`, `rule-ideas`, `summary`) sit beside the `{id}` parameter at
        // the same position. matchit gives a static segment priority, which is
        // the same shape `/api/playbooks/suggest-for-rule/{rule_id}` already
        // relies on — but it does mean a hunt whose TypeID rendered as one of
        // those words would be unreachable, and TypeIDs are prefixed base32 so
        // that cannot happen.
        .route_if(!shared_product, "/api/hunts/summary", get(handlers::hunts::hunts_summary, RoutePolicy::all_of(&["hunts:view"])))
        .route_if(!shared_product, "/api/hunts", get(handlers::hunts::list_hunts, RoutePolicy::all_of(&["hunts:view"])))
        .route_if(!shared_product, "/api/hunts", post(handlers::hunts::create_hunt, RoutePolicy::all_of(&["hunts:manage"])))
        .route_if(!shared_product, 
            "/api/hunts/source-capability-bindings",
            get(handlers::hunts::list_source_capability_bindings, RoutePolicy::all_of(&["hunts:view"]))
                .put(handlers::hunts::set_source_capability_binding, RoutePolicy::all_of(&["hunts:manage"])),
        )
        .route_if(!shared_product, 
            "/api/hunts/source-capability-bindings/reset",
            post(handlers::hunts::reset_source_capability_binding, RoutePolicy::all_of(&["hunts:manage"])),
        )
        .route_if(!shared_product, "/api/hunts/runners", get(handlers::hunts::list_runners, RoutePolicy::all_of(&["hunts:view"])))
        .route_if(!shared_product, "/api/hunts/runners", post(handlers::hunts::register_runner, RoutePolicy::all_of(&["hunts:manage"])))
        .route_if(!shared_product, 
            "/api/hunts/runners/{id}/heartbeat",
            post(handlers::hunts::runner_heartbeat, RoutePolicy::all_of(&["hunts:report"])),
        )
        .route_if(!shared_product, 
            "/api/hunts/runners/{id}/claim",
            post(handlers::hunts::claim_sweep, RoutePolicy::all_of(&["hunts:report"])),
        )
        // The Antigravity sweep waiver (NAN-2264). `hunts:manage` on both
        // verbs — a runner cannot widen its own authority.
        .route_if(!shared_product, 
            "/api/hunts/runners/{id}/agy-waiver",
            post(handlers::hunts::grant_runner_agy_waiver, RoutePolicy::all_of(&["hunts:manage"]))
                .delete(handlers::hunts::revoke_runner_agy_waiver, RoutePolicy::all_of(&["hunts:manage"])),
        )
        .route_if(!shared_product, "/api/hunts/sweeps/{id}", get(handlers::hunts::get_sweep, RoutePolicy::all_of(&["hunts:view"])))
        // The only endpoint `hunts:report` reaches that writes leads.
        .route_if(!shared_product, 
            "/api/hunts/sweeps/{id}/report",
            post(handlers::hunts::report_sweep, RoutePolicy::all_of(&["hunts:report"])),
        )
        .route_if(!shared_product, "/api/hunts/leads", get(handlers::hunts::list_leads, RoutePolicy::all_of(&["hunts:view"])))
        .route_if(!shared_product, "/api/hunts/leads/{id}", get(handlers::hunts::get_lead, RoutePolicy::all_of(&["hunts:view"])))
        .route_if(!shared_product, 
            "/api/hunts/leads/{id}/promote",
            post(handlers::hunts::promote_lead, RoutePolicy::all_of(&["hunts:triage", "cases:create"])),
        )
        .route_if(!shared_product, 
            "/api/hunts/leads/{id}/dismiss",
            post(handlers::hunts::dismiss_lead, RoutePolicy::all_of(&["hunts:triage"])),
        )
        // NAN-2239 knowledge. Recall is `hunts:view`; recording is the one
        // write a sweep key can make besides its report; revocation is
        // `hunts:triage`. Nothing here suppresses — see handlers/hunts/knowledge.rs.
        .route_if(!shared_product, 
            "/api/hunts/knowledge",
            get(handlers::hunts::list_knowledge, RoutePolicy::all_of(&["hunts:view"])).post(handlers::hunts::record_knowledge, RoutePolicy::all_of(&["hunts:report"])),
        )
        .route_if(!shared_product, 
            "/api/hunts/knowledge/{id}/revoke",
            post(handlers::hunts::revoke_knowledge, RoutePolicy::all_of(&["hunts:triage"])),
        )
        .route_if(!shared_product, 
            "/api/hunts/suppressions",
            get(handlers::hunts::list_suppressions, RoutePolicy::all_of(&["hunts:view"]))
                // POST is the RUNNER's (`hunts:report`), not the analyst's and
                // not the agent's. Sharing the path with the list keeps the two
                // halves of the suppression story in one place.
                .post(handlers::hunts::record_suppression, RoutePolicy::all_of(&["hunts:report"])),
        )
        .route_if(!shared_product, 
            "/api/hunts/suppressions/{id}",
            delete(handlers::hunts::revoke_suppression, RoutePolicy::all_of(&["hunts:triage"])),
        )
        .route_if(!shared_product, 
            "/api/hunts/profile",
            get(handlers::hunts::get_latest_profile, RoutePolicy::all_of(&["hunts:view"])),
        )
        // Recon's whole write surface is `hunts:manage` rather than
        // `hunts:run`: it creates hunt DEFINITIONS. See handlers/hunts/recon.rs.
        //
        // The save carries a census, a full ATT&CK surface and model-written
        // prose, so its body limit is stated rather than inherited — a change
        // to axum's 2 MB default must not silently widen what a model may push
        // into a shared JSONB column. Layered on this one route so the rest of
        // the hunts surface keeps the global limit.
        .route_if(!shared_product, 
            "/api/hunts/profile",
            post(handlers::hunts::save_recon_profile, RoutePolicy::any_of(&["hunts:profile_write", "hunts:manage"]))
                .layer(DefaultBodyLimit::max(PROFILE_BODY_LIMIT_BYTES)),
        )
        .route_if(!shared_product, 
            "/api/hunts/profile/census",
            post(handlers::hunts::recon_census, RoutePolicy::any_of(&["hunts:profile_write", "hunts:manage"])),
        )
        .route_if(!shared_product, 
            "/api/hunts/profile/surface",
            post(handlers::hunts::recon_surface, RoutePolicy::any_of(&["hunts:profile_write", "hunts:manage"])),
        )
        .route_if(!shared_product, 
            "/api/hunts/profile/run",
            post(handlers::hunts::run_recon_profile, RoutePolicy::any_of(&["hunts:profile_write", "hunts:manage"])),
        )
        .route_if(!shared_product, 
            "/api/hunts/drafts",
            post(handlers::hunts::create_hunt_drafts, RoutePolicy::any_of(&["hunts:profile_write", "hunts:manage"])),
        )
        .route_if(!shared_product, 
            "/api/hunts/rule-ideas",
            get(handlers::hunts::list_rule_ideas, RoutePolicy::all_of(&["hunts:view"])),
        )
        // The report itself and the sanitized logo remain device-local. These
        // static receipts carry hashes and bounded presentation metadata only.
        .route_if(!shared_product, 
            "/api/hunts/report-branding-events",
            post(handlers::hunts::record_hunt_report_branding, RoutePolicy::all_of(&["hunts:view"])),
        )
        .route_if(!shared_product, 
            "/api/hunts/rule-ideas/{id}/send",
            post(handlers::hunts::send_rule_idea, RoutePolicy::all_of(&["hunts:manage"])),
        )
        .route_if(!shared_product, 
            "/api/hunts/rule-ideas/{id}/reject",
            post(handlers::hunts::reject_rule_idea, RoutePolicy::all_of(&["hunts:manage"])),
        )
        .route_if(!shared_product, "/api/hunts/{id}", get(handlers::hunts::get_hunt, RoutePolicy::all_of(&["hunts:view"])))
        .route_if(!shared_product, "/api/hunts/{id}", patch(handlers::hunts::update_hunt, RoutePolicy::all_of(&["hunts:manage"])))
        .route_if(!shared_product, "/api/hunts/{id}", delete(handlers::hunts::archive_hunt, RoutePolicy::all_of(&["hunts:manage"])))
        .route_if(!shared_product, 
            "/api/hunts/{id}/sweeps",
            get(handlers::hunts::list_hunt_sweeps, RoutePolicy::all_of(&["hunts:view"])),
        )
        .route_if(!shared_product, 
            "/api/hunts/{id}/sweeps",
            post(handlers::hunts::trigger_sweep, RoutePolicy::all_of(&["hunts:run"])),
        )
        .route_if(!shared_product, "/api/hunts/{id}/toggle", post(handlers::hunts::toggle_hunt, RoutePolicy::all_of(&["hunts:run"])))
        .route_if(!shared_product, 
            "/api/hunts/{id}/report-exports",
            post(handlers::hunts::record_hunt_report_export, RoutePolicy::all_of(&["hunts:view"])),
        )
        // Its own route rather than a PATCH field, like the toggle beside it:
        // `update_hunt` COALESCEs every column, so "manual only" — a real choice
        // — is inexpressible there and clearing a cadence was a silent no-op.
        .route_if(!shared_product, 
            "/api/hunts/{id}/schedule",
            post(handlers::hunts::set_hunt_schedule, RoutePolicy::all_of(&["hunts:run"])),
        )
        // Playbook repositories (external sync)
        .route_if(!shared_product, 
            "/api/playbook-repositories",
            get(handlers::playbook_repositories::list_playbook_repositories, RoutePolicy::all_of(&["playbook_repositories:view"])),
        )
        .route_if(!shared_product, 
            "/api/playbook-repositories",
            post(handlers::playbook_repositories::create_playbook_repository, RoutePolicy::all_of(&["playbook_repositories:manage"])),
        )
        .route_if(!shared_product, 
            "/api/playbook-repositories/{id}",
            get(handlers::playbook_repositories::get_playbook_repository, RoutePolicy::all_of(&["playbook_repositories:view"])),
        )
        .route_if(!shared_product, 
            "/api/playbook-repositories/{id}",
            patch(handlers::playbook_repositories::update_playbook_repository, RoutePolicy::all_of(&["playbook_repositories:manage"])),
        )
        .route_if(!shared_product, 
            "/api/playbook-repositories/{id}",
            delete(handlers::playbook_repositories::delete_playbook_repository, RoutePolicy::all_of(&["playbook_repositories:manage"])),
        )
        .route_if(!shared_product, 
            "/api/playbook-repositories/{id}/sync",
            post(handlers::playbook_repositories::sync_playbook_repository, RoutePolicy::all_of(&["playbook_repositories:sync"])),
        )
        .route_if(!shared_product, 
            "/api/playbook-repositories/{id}/sync/status",
            get(handlers::playbook_repositories::get_playbook_sync_status, RoutePolicy::all_of(&["playbook_repositories:view"])),
        )
        .route_if(!shared_product, 
            "/api/playbook-repositories/{id}/playbooks",
            get(handlers::playbook_repositories::list_repository_playbooks, RoutePolicy::all_of(&["playbook_repositories:view"])),
        )
        // NAN-611: bulk import — promotes every parseable cached playbook into
        // the library. Must be registered before the `import/{*path}` catch-all
        // below so axum doesn't route "import-all" as a path parameter.
        .route_if(!shared_product, 
            "/api/playbook-repositories/{id}/playbooks/import-all",
            post(handlers::playbook_repositories::import_all_repository_playbooks, RoutePolicy::all_of(&["playbook_repositories:import"])),
        )
        // NAN-611: combined sync + bulk import — backs the "Sync now" button on
        // the Playbooks library so users get one toast per click instead of
        // polling sync status from the browser.
        .route_if(!shared_product, 
            "/api/playbook-repositories/{id}/sync-and-import",
            post(handlers::playbook_repositories::sync_and_import_repository, RoutePolicy::all_of(&["playbook_repositories:sync", "playbook_repositories:import"])),
        )
        // NAN-453: axum requires catch-all params `{*path}` to be the last
        // segment. Matches the rule_repositories pattern at line 1537:
        // `/rule-repositories/{id}/rules/import/{*path}`.
        .route_if(!shared_product, 
            "/api/playbook-repositories/{id}/playbooks/import/{*path}",
            post(handlers::playbook_repositories::import_repository_playbook, RoutePolicy::all_of(&["playbook_repositories:import"])),
        )
        // Query library
        .route_if(!shared_product, "/api/query-library", get(handlers::list_queries, RoutePolicy::all_of(&["search:view"])))
        .route_if(!shared_product, "/api/query-library", post(handlers::create_query, RoutePolicy::all_of(&["search:save"])))
        .route_if(!shared_product, 
            "/api/query-library/categories",
            get(handlers::get_categories, RoutePolicy::all_of(&["search:view"])),
        )
        .route_if(!shared_product, "/api/query-library/tags", get(handlers::get_tags, RoutePolicy::all_of(&["search:view"])))
        .route_if(!shared_product, "/api/query-library/{id}", get(handlers::get_query, RoutePolicy::all_of(&["search:view"])))
        .route_if(!shared_product, "/api/query-library/{id}", delete(handlers::delete_query, RoutePolicy::all_of(&["search:save"])))
        // GDPR anonymization
        .route_if(!shared_product, 
            "/api/gdpr/anonymize",
            post(handlers::gdpr::submit_anonymization, RoutePolicy::all_of(&["gdpr:anonymize"])),
        )
        .route_if(!shared_product, 
            "/api/gdpr/anonymize",
            get(handlers::gdpr::list_anonymization_requests, RoutePolicy::all_of(&["gdpr:anonymize"])),
        )
        .route_if(!shared_product, 
            "/api/gdpr/anonymize/{id}",
            get(handlers::gdpr::get_anonymization_request, RoutePolicy::all_of(&["gdpr:anonymize"])),
        )
        .route_if(!shared_product, 
            "/api/gdpr/anonymize/{id}/execute",
            post(handlers::gdpr::execute_anonymization, RoutePolicy::all_of(&["gdpr:anonymize"])),
        )
        // System metrics
        .route("/api/system/overview", get(handlers::get_system_overview, RoutePolicy::all_of(&["settings:view", "search:execute", "alerts:view", "detections:view"])))
        .route(
            "/api/system/config",
            get(handlers::system::get_system_config, RoutePolicy::all_of(&["settings:view"])),
        )
        // Upload endpoints (rate-limited to prevent DoS)
        .merge(upload_routes)
        // Artifact-analysis store (NAN-1977) — body-limited sub-router
        .merge(artifact_routes)
        // NAN-474: rate-limited dry-resolve sub-router
        .merge(dry_resolve_routes)
        // NAN-939: rate-limited Kafka broker-probe sub-router
        .merge(kafka_probe_routes)
        // NAN-2064: rate-limited stored-credential GitHub probe
        .merge(detection_code_probe_routes)
        .route_if(!shared_product, "/api/upload/history", get(handlers::get_upload_history, RoutePolicy::all_of(&["upload:history"])))
        // Lookup table endpoints
        .route_if(!shared_product, "/api/lookup-tables", post(handlers::create_lookup_table, RoutePolicy::all_of(&["lookup:create"])))
        .route_if(!shared_product, "/api/lookup-tables", get(handlers::list_lookup_tables, RoutePolicy::all_of(&["lookup:view"])))
        .route_if(!shared_product, 
            "/api/lookup-tables/schema",
            post(handlers::create_lookup_table_from_schema, RoutePolicy::all_of(&["lookup:create"])),
        )
        .route_if(!shared_product, "/api/lookup-tables/query", post(handlers::lookup_query, RoutePolicy::all_of(&["lookup:view"])))
        .route_if(!shared_product, "/api/lookup-tables/{name}", get(handlers::get_lookup_table, RoutePolicy::all_of(&["lookup:view"])))
        .route_if(!shared_product, 
            "/api/lookup-tables/{name}",
            delete(handlers::delete_lookup_table, RoutePolicy::all_of(&["lookup:delete"])),
        )
        .route_if(!shared_product, 
            "/api/lookup-tables/{name}/sample",
            get(handlers::get_lookup_table_sample, RoutePolicy::all_of(&["lookup:view"])),
        )
        .route_if(!shared_product, 
            "/api/lookup-tables/{name}/usage",
            get(handlers::get_lookup_table_usage, RoutePolicy::all_of(&["lookup:view", "detections:view"])),
        )
        .route_if(!shared_product, 
            "/api/lookup-tables/{name}/ingestion-history",
            get(handlers::get_lookup_table_ingestion_history, RoutePolicy::all_of(&["lookup:view"])),
        )
        .route_if(!shared_product, 
            "/api/lookup-tables/{name}/rows",
            get(handlers::list_lookup_rows, RoutePolicy::all_of(&["lookup:view"])),
        )
        .route_if(!shared_product, 
            "/api/lookup-tables/{name}/rows",
            post(handlers::add_lookup_rows, RoutePolicy::all_of(&["lookup:edit"])),
        )
        .route_if(!shared_product, 
            "/api/lookup-tables/{name}/rows",
            delete(handlers::delete_lookup_rows, RoutePolicy::all_of(&["lookup:edit"])),
        )
        .route_if(!shared_product, 
            "/api/lookup-tables/{name}/rows/{row_id}",
            put(handlers::update_lookup_row, RoutePolicy::all_of(&["lookup:edit"])),
        )
        .route_if(!shared_product, 
            "/api/lookup-tables/{name}/rows/{row_id}",
            delete(handlers::delete_lookup_row, RoutePolicy::all_of(&["lookup:edit"])),
        )
        // Lookup table ingestion endpoints
        .route_if(!shared_product, 
            "/api/lookup-tables/validate-cron",
            post(handlers::lookup::ingestion::validate_cron_expression, RoutePolicy::any_of(&["lookup:create", "lookup:edit"])),
        )
        .route_if(!shared_product, 
            "/api/lookup-tables/{name}/ingestion",
            get(handlers::lookup::ingestion::get_lookup_ingestion, RoutePolicy::all_of(&["lookup:view"])),
        )
        .route_if(!shared_product, 
            "/api/lookup-tables/{name}/ingestion",
            put(handlers::lookup::ingestion::upsert_lookup_ingestion, RoutePolicy::all_of(&["lookup:edit"])),
        )
        .route_if(!shared_product, 
            "/api/lookup-tables/{name}/ingestion",
            delete(handlers::lookup::ingestion::delete_lookup_ingestion, RoutePolicy::all_of(&["lookup:edit"])),
        )
        .route_if(!shared_product, 
            "/api/lookup-tables/{name}/ingestion/trigger",
            post(handlers::lookup::ingestion::trigger_lookup_ingestion, RoutePolicy::all_of(&["lookup:edit"])),
        )
        .route_if(!shared_product, 
            "/api/lookup-tables/{name}/ingestion/enable",
            post(handlers::lookup::ingestion::enable_lookup_ingestion, RoutePolicy::all_of(&["lookup:edit"])),
        )
        .route_if(!shared_product, 
            "/api/lookup-tables/{name}/ingestion/disable",
            post(handlers::lookup::ingestion::disable_lookup_ingestion, RoutePolicy::all_of(&["lookup:edit"])),
        )
        // Dashboard endpoints
        .route_if(!shared_product, "/api/dashboards", get(handlers::list_dashboards, RoutePolicy::all_of(&["dashboards:view"])))
        .route_if(!shared_product, "/api/dashboards", post(handlers::create_dashboard, RoutePolicy::all_of(&["dashboards:create"])))
        // NAN-2771: shared tenants run panels on their tenant-pinned lake via
        // `shared_dashboard_panels` (merged below).
        .route_if(!shared_product, "/api/dashboards/panel/query", post(handlers::panel_query, RoutePolicy::all_of_any_of(&["dashboards:view"], &["search:execute", "search:sql"])))
        .route_if(!shared_product, "/api/dashboards/import", post(handlers::import_dashboard, RoutePolicy::all_of(&["dashboards:create"])))
        .route_if(!shared_product, 
            "/api/dashboards/export/{id}",
            post(handlers::export_dashboard, RoutePolicy::all_of(&["dashboards:view"])),
        )
        .route_if(!shared_product, "/api/dashboards/{id}", get(handlers::get_dashboard, RoutePolicy::all_of(&["dashboards:view"])))
        .route_if(!shared_product, "/api/dashboards/{id}", put(handlers::update_dashboard, RoutePolicy::all_of(&["dashboards:edit"])))
        .route_if(!shared_product, "/api/dashboards/{id}", delete(handlers::delete_dashboard, RoutePolicy::all_of(&["dashboards:delete"])))
        .route_if(!shared_product, 
            "/api/dashboards/{id}/share",
            post(handlers::share_dashboard, RoutePolicy::all_of(&["dashboards:edit"])),
        )
        // Scheduled report endpoints (NAN-1793). Static segments (`runs`,
        // `artifacts`) are declared before `{id}` so matchit prefers them.
        // Referenced via the qualified module path because `reports` is not
        // glob-re-exported (its list_reports/get_report collide with siem_health).
        .route_if(!shared_product, "/api/reports", get(handlers::reports::list_reports, RoutePolicy::all_of(&["search:view"])))
        .route_if(!shared_product, "/api/reports", post(handlers::reports::create_report, RoutePolicy::all_of(&["search:execute"])))
        .route_if(!shared_product, 
            "/api/reports/runs/{run_id}",
            get(handlers::reports::get_report_run, RoutePolicy::all_of(&["search:view"])),
        )
        .route_if(!shared_product, 
            "/api/reports/artifacts/{artifact_id}/download",
            get(handlers::reports::download_report_artifact, RoutePolicy::all_of(&["search:view"])),
        )
        .route_if(!shared_product, "/api/reports/{id}", get(handlers::reports::get_report, RoutePolicy::all_of(&["search:view"])))
        .route_if(!shared_product, "/api/reports/{id}", put(handlers::reports::update_report, RoutePolicy::all_of(&["search:execute"])))
        .route_if(!shared_product, 
            "/api/reports/{id}",
            delete(handlers::reports::delete_report, RoutePolicy::all_of(&["search:execute"])),
        )
        .route_if(!shared_product, 
            "/api/reports/{id}/run",
            post(handlers::reports::trigger_report, RoutePolicy::all_of(&["search:execute"])),
        )
        .route_if(!shared_product, 
            "/api/reports/{id}/runs",
            get(handlers::reports::list_report_runs, RoutePolicy::all_of(&["search:view"])),
        );

    // Notebook endpoints — enterprise only (cases-coupled).
    #[cfg(feature = "enterprise")]
    {
        if !config.deployment_mode.is_enterprise_shared() {
            app = app
                .route_if(!shared_product, 
                    "/api/notebooks",
                    get(handlers::notebooks::list_notebooks::<AppState>, RoutePolicy::all_of(&["notebooks:view"])),
                )
                .route_if(!shared_product, 
                    "/api/notebooks",
                    post(handlers::notebooks::create_notebook::<AppState>, RoutePolicy::all_of(&["notebooks:create"])),
                )
                .route_if(!shared_product, 
                    "/api/notebooks/{id}",
                    get(handlers::notebooks::get_notebook::<AppState>, RoutePolicy::all_of(&["notebooks:view"])),
                )
                .route_if(!shared_product, 
                    "/api/notebooks/{id}",
                    put(handlers::notebooks::update_notebook::<AppState>, RoutePolicy::all_of(&["notebooks:edit"])),
                )
                .route_if(!shared_product, 
                    "/api/notebooks/{id}",
                    delete(handlers::notebooks::delete_notebook::<AppState>, RoutePolicy::all_of(&["notebooks:delete"])),
                );
        }

        app = app
            .route_if(!shared_product, 
                "/api/notebooks/active",
                get(handlers::notebooks::get_active_notebook::<AppState>, RoutePolicy::all_of(&["notebooks:view"])),
            )
            .route_if(!shared_product, 
                "/api/notebooks/by-reference",
                get(handlers::notebooks::find_by_reference::<AppState>, RoutePolicy::all_of(&["notebooks:view"])),
            )
            // Notebook tabs (must be before {id} routes)
            .route_if(!shared_product, 
                "/api/notebooks/tabs",
                get(handlers::notebooks::list_tabs::<AppState>, RoutePolicy::all_of(&["notebooks:view"])),
            )
            .route_if(!shared_product, 
                "/api/notebooks/tabs",
                post(handlers::notebooks::open_tab::<AppState>, RoutePolicy::all_of(&["notebooks:view"])),
            )
            .route_if(!shared_product, 
                "/api/notebooks/tabs/reorder",
                post(handlers::notebooks::reorder_tabs::<AppState>, RoutePolicy::all_of(&["notebooks:view"])),
            )
            .route_if(!shared_product, 
                "/api/notebooks/tabs/{tab_id}",
                delete(handlers::notebooks::close_tab::<AppState>, RoutePolicy::all_of(&["notebooks:view"])),
            )
            .route_if(!shared_product, 
                "/api/notebooks/tabs/{tab_id}",
                patch(handlers::notebooks::update_tab::<AppState>, RoutePolicy::all_of(&["notebooks:view"])),
            )
            .route_if(!shared_product, 
                "/api/notebooks/tabs/active/{notebook_id}",
                post(handlers::notebooks::set_active_tab::<AppState>, RoutePolicy::all_of(&["notebooks:view"])),
            )
            // Individual notebook routes
            .route_if(!shared_product, 
                "/api/notebooks/{id}/entries",
                get(handlers::notebooks::get_entries::<AppState>, RoutePolicy::all_of(&["notebooks:view"])),
            )
            .route_if(!shared_product, 
                "/api/notebooks/{id}/entries",
                post(handlers::notebooks::add_entry::<AppState>, RoutePolicy::any_of(&["notebooks:edit", "cases:edit"])),
            )
            .route_if(!shared_product,
                // NAN-1840: the ONLY endpoint that accepts AI-typed entries, and it
                // stamps their provenance server-side. `/entries` still refuses them.
                "/api/notebooks/{id}/agent-entries",
                post(handlers::notebooks::add_agent_entry::<AppState>, RoutePolicy::all_of(&["notebooks:agent_record"])),
            )
            .route_if(!shared_product, 
                "/api/notebooks/{id}/entries/{entry_id}",
                delete(handlers::notebooks::delete_entry::<AppState>, RoutePolicy::all_of(&["notebooks:edit"])),
            )
            .route_if(!shared_product, 
                "/api/notebooks/{id}/shares",
                get(handlers::notebooks::get_shares::<AppState>, RoutePolicy::all_of(&["notebooks:view"])),
            )
            .route_if(!shared_product, 
                "/api/notebooks/{id}/shares",
                post(handlers::notebooks::add_share::<AppState>, RoutePolicy::all_of(&["notebooks:share"])),
            )
            .route_if(!shared_product, 
                "/api/notebooks/{id}/shares/{share_id}",
                delete(handlers::notebooks::delete_share::<AppState>, RoutePolicy::all_of(&["notebooks:share"])),
            )
            .route_if(!shared_product, 
                "/api/notebooks/{id}/share",
                post(handlers::notebooks::share_notebook::<AppState>, RoutePolicy::all_of(&["notebooks:share"])),
            )
            .route_if(!shared_product, 
                "/api/notebooks/{id}/references",
                get(handlers::notebooks::get_references::<AppState>, RoutePolicy::all_of(&["notebooks:view"])),
            )
            .route_if(!shared_product, 
                "/api/notebooks/{id}/references",
                post(handlers::notebooks::add_reference::<AppState>, RoutePolicy::all_of(&["notebooks:edit"])),
            )
            .route_if(!shared_product, 
                "/api/notebooks/{id}/references/{ref_id}",
                delete(handlers::notebooks::delete_reference::<AppState>, RoutePolicy::all_of(&["notebooks:edit"])),
            )
            .route_if(!shared_product, 
                "/api/notebooks/{id}/escalate",
                post(handlers::notebooks::escalate_to_case::<AppState>, RoutePolicy::all_of(&["notebooks:edit", "cases:create"])),
            )
            .route_if(!shared_product, 
                "/api/notebooks/{id}/merge",
                post(handlers::notebooks::merge_notebooks::<AppState>, RoutePolicy::all_of(&["notebooks:edit"])),
            )
            .route_if(!shared_product, 
                "/api/notebooks/{id}/unlink",
                post(handlers::notebooks::unlink_notebook_from_case::<AppState>, RoutePolicy::all_of(&["notebooks:edit"])),
            )
            .route_if(shared_product,
                "/api/notebooks/{id}/chat",
                post(nanosiem_enterprise::handlers::enterprise_shared_notebook_chat::notebook_chat::<AppState>, RoutePolicy::all_of(nanosiem_enterprise::melod::TenantAiOperation::NotebookChat.permissions()).interactive()),
            )
            .route_if(shared_product,
                "/api/notebooks/{id}/chat/stream",
                post(nanosiem_enterprise::handlers::enterprise_shared_notebook_chat::notebook_chat_stream::<AppState>, RoutePolicy::all_of(nanosiem_enterprise::melod::TenantAiOperation::NotebookChat.permissions()).interactive()),
            )
            .route_if(!shared_product,
                "/api/notebooks/{id}/chat",
                post(handlers::notebooks::notebook_chat::<AppState>, RoutePolicy::all_of_any_of(&["melod:notebook"], &["notebooks:edit", "cases:edit"])),
            )
            .route_if(!shared_product,
                "/api/notebooks/{id}/chat/stream",
                post(handlers::notebooks::notebook_chat_stream::<AppState>, RoutePolicy::all_of_any_of(&["melod:notebook"], &["notebooks:edit", "cases:edit"])),
            );
    }

    app = app
        // SIEM Health Check
        .route_if(!shared_product, 
            "/api/siem-health/reports",
            get(handlers::siem_health::list_reports, RoutePolicy::all_of(&["settings:system"])),
        )
        .route_if(!shared_product, 
            "/api/siem-health/reports/latest",
            get(handlers::siem_health::get_latest_report, RoutePolicy::all_of(&["settings:system"])),
        )
        .route_if(!shared_product, 
            "/api/siem-health/reports/trigger",
            post(handlers::siem_health::trigger_health_check, RoutePolicy::all_of(&["settings:system"])),
        )
        .route_if(!shared_product, 
            "/api/siem-health/reports/{id}",
            get(handlers::siem_health::get_report, RoutePolicy::all_of(&["settings:system"])),
        )
        .route_if(!shared_product, 
            "/api/siem-health/findings/suppressions",
            get(handlers::siem_health_suppressions::list_suppressions, RoutePolicy::all_of(&["settings:system"]))
                .post(handlers::siem_health_suppressions::create_suppression, RoutePolicy::all_of(&["settings:system"])),
        )
        .route_if(!shared_product, 
            "/api/siem-health/findings/suppressions/{id}",
            nanosiem_api_lib::route_policy::routing::delete(handlers::siem_health_suppressions::deactivate_suppression, RoutePolicy::all_of(&["settings:system"])),
        )
        // Normalized, owner-visible system health lifecycles and durable delivery.
        .route_if(!shared_product, 
            "/api/system-health/events",
            get(handlers::system_health_events::list_health_events, RoutePolicy::all_of(&["system_health:view"])),
        )
        .route_if(!shared_product, 
            "/api/system-health/summary",
            get(handlers::system_health_events::get_health_summary, RoutePolicy::all_of(&["system_health:view"])),
        )
        .route_if(!shared_product, 
            "/api/system-health/events/{id}/acknowledge",
            post(handlers::system_health_events::acknowledge_health_event, RoutePolicy::all_of(&["system_health:manage"])),
        )
        .route_if(!shared_product, 
            "/api/system-health/events/{id}/resolve",
            post(handlers::system_health_events::resolve_health_event, RoutePolicy::all_of(&["system_health:manage"])),
        )
        .route_if(!shared_product, 
            "/api/system-health/events/{id}/deliveries",
            get(handlers::system_health_events::list_health_deliveries, RoutePolicy::all_of(&["system_health:view"])),
        )
        .route("/api/observability/browser", post(handlers::browser_telemetry::pageview, RoutePolicy::authenticated()).layer(axum::extract::DefaultBodyLimit::max(1024)))
        // Observability console SLOs (NAN-1536) — PG-backed definitions,
        // attainment computed on read from otel_spans.
        .route_if(!shared_product, 
            "/api/observability/slos",
            get(handlers::observability_slos::list_slos, RoutePolicy::all_of(&["search:view", "search:execute"]))
                .post(handlers::observability_slos::create_slo, RoutePolicy::all_of(&["settings:system"])),
        )
        .route_if(!shared_product, 
            "/api/observability/slos/{id}",
            put(handlers::observability_slos::update_slo, RoutePolicy::all_of(&["settings:system"]))
                .delete(handlers::observability_slos::delete_slo, RoutePolicy::all_of(&["settings:system"])),
        )
        // Observability console synthetic checks (NAN-1538) — PG-backed
        // definitions; live uptime/latency/history computed on read from the
        // ClickHouse synthetic_check_results table the jobs runner writes.
        .route_if(!shared_product, 
            "/api/observability/synthetics",
            get(handlers::observability_synthetics::list_synthetics, RoutePolicy::all_of(&["search:view", "search:execute"]))
                .post(handlers::observability_synthetics::create_synthetic, RoutePolicy::all_of(&["settings:system"])),
        )
        .route_if(!shared_product, 
            "/api/observability/synthetics/{id}",
            put(handlers::observability_synthetics::update_synthetic, RoutePolicy::all_of(&["settings:system"]))
                .delete(handlers::observability_synthetics::delete_synthetic, RoutePolicy::all_of(&["settings:system"])),
        )
        // Observability metric monitors (NAN-1540) — PG-backed definitions;
        // the jobs runner evaluates due monitors and raises alerts on breach.
        .route_if(!shared_product, 
            "/api/observability/metric-monitors",
            get(handlers::observability_metric_monitors::list_metric_monitors, RoutePolicy::all_of(&["search:view"]))
                .post(handlers::observability_metric_monitors::create_metric_monitor, RoutePolicy::all_of(&["settings:system"])),
        )
        .route_if(!shared_product, 
            "/api/observability/metric-monitors/{id}",
            put(handlers::observability_metric_monitors::update_metric_monitor, RoutePolicy::all_of(&["settings:system"]))
                .delete(handlers::observability_metric_monitors::delete_metric_monitor, RoutePolicy::all_of(&["settings:system"])),
        )
        // Tuning endpoints
        .route_if(!shared_product, 
            "/api/tuning/baselines/{rule_id}",
            get(handlers::get_baseline, RoutePolicy::all_of(&["detections:view"])),
        )
        .route_if(!shared_product, "/api/tuning/metrics/{rule_id}", get(handlers::get_metrics, RoutePolicy::all_of(&["detections:view"])))
        .route_if(ai_tuning_routes,
            "/api/tuning/breaches/{rule_id}",
            get(handlers::get_breaches, RoutePolicy::all_of(&["detections:view"])),
        )
        .route_if(ai_tuning_routes, "/api/tuning/proposals", get(handlers::list_proposals, RoutePolicy::all_of(&["detections:view"])))
        .route_if(ai_tuning_routes, "/api/tuning/proposals/{id}", get(handlers::get_proposal, RoutePolicy::all_of(&["detections:view"])))
        .route_if(ai_tuning_routes,
            "/api/tuning/proposals/{id}/approve",
            post(handlers::approve_proposal, RoutePolicy::all_of(&["detections:edit"])),
        )
        .route_if(ai_tuning_routes,
            "/api/tuning/proposals/{id}/reject",
            post(handlers::reject_proposal, RoutePolicy::all_of(&["detections:edit"])),
        )
        .route_if(!shared_product, 
            "/api/tuning/versions/{rule_id}",
            get(handlers::list_versions, RoutePolicy::all_of(&["detections:view"])),
        )
        .route_if(!shared_product, 
            "/api/tuning/versions/{rule_id}/{version_id}",
            get(handlers::get_version, RoutePolicy::all_of(&["detections:view"])),
        )
        .route_if(!shared_product, 
            "/api/tuning/versions/{rule_id}/{version_id}/activate",
            post(handlers::activate_version, RoutePolicy::all_of(&["detections:edit", "detections:promote"])),
        )
        .route_if(ai_tuning_routes, "/api/tuning/logs", get(handlers::list_logs, RoutePolicy::all_of(&["detections:view"])))
        .route_if(ai_tuning_routes, "/api/tuning/logs/{id}", get(handlers::get_log, RoutePolicy::all_of(&["detections:view"])))
        .route_if(ai_tuning_routes,
            "/api/tuning/logs/{id}/revert",
            post(handlers::revert_tuning, RoutePolicy::all_of(&["detections:edit", "detections:promote"])),
        )
        .route_if(!shared_product, 
            "/api/tuning/notifications",
            get(handlers::tuning::list_tuning_notifications, RoutePolicy::all_of(&["detections:view"])),
        )
        .route_if(!shared_product, 
            "/api/tuning/notifications/{id}/read",
            post(handlers::tuning::mark_tuning_notification_read, RoutePolicy::all_of(&["detections:view"])),
        )
        .route_if(!shared_product, 
            "/api/tuning/notifications/read-all",
            post(handlers::tuning::mark_all_tuning_notifications_read, RoutePolicy::all_of(&["detections:view"])),
        )
        .route_if(!shared_product, 
            "/api/tuning/settings/{rule_id}",
            get(handlers::get_tuning_settings, RoutePolicy::all_of(&["detections:view"])),
        )
        .route_if(!shared_product, 
            "/api/tuning/settings/{rule_id}",
            put(handlers::update_tuning_settings, RoutePolicy::all_of(&["detections:edit"])),
        )
        // Cacheable routes (with Cache-Control headers)
        .merge(cached_metadata)
        .merge(cached_mitre)
        .merge(cached_mitre_coverage)
        // OpenAPI / Swagger UI
        .merge(if shared_product { Router::new() } else { registered_swagger_ui() });
    // Observability ↔ Security convergence cross-link (NAN-1542/NAN-1544) moved
    // to the search service in NAN-2361: GET
    // /api/search/services/{service}/security-signals now resolves entities and
    // signals from the OCSF/Iceberg lake. The legacy ClickHouse glue stays in
    // nanosiem-core for the UDM build, but this crate no longer routes to it.
    // Demo routes (only on DEPLOYMENT_MODE=demo deployments)
    if let Some(demo) = demo_routes {
        app = app.merge(demo);
    }
    // Air-gapped large-bundle import sub-router (NAN-1201, enterprise). Merged
    // before with_state so it shares AppState, and before the license guard
    // layer below so parser/enrichment imports require a valid license.
    #[cfg(feature = "enterprise")]
    {
        app = app.merge(airgap_import_routes);
    }
    // Per-source RBAC scope administration (NAN-1799) — restricted source_type
    // registry + per-group grants. Core surface (not enterprise-gated); the
    // handlers gate on the source_scopes:view / source_scopes:manage
    // permissions. Merged here so it shares AppState and sits inside the
    // authenticated router group (behind the auth middleware layer below).
    // NAN-2361: source visibility is served by the settings port in shared mode.
    if !shared_product {
        app = app.merge(handlers::source_scopes::source_scopes_routes());
    }
    app
}

/// Actual method/template inventory from the same production registrations.
pub fn route_manifest(state: &AppState) -> Vec<nanosiem_api_lib::route_policy::Entry> {
    #[allow(unused_mut)]
    let mut entries=register_routes(state).manifest().to_vec();
    #[cfg(feature="enterprise")]
    if state.config.deployment_mode.is_enterprise_shared() {
        entries.extend_from_slice(openapi::registered_tenant_swagger_router().manifest());
    }
    entries
}

fn registered_swagger_ui() -> Router<AppState> {
    // Credential-protected reference documentation has no tenant data or mutations.
    Router::documented(openapi::swagger_ui().into(), &[
        "/api-docs/openapi.json", "/swagger-ui", "/swagger-ui/", "/swagger-ui/{*rest}",
    ], RoutePolicy::authenticated())
}

/// Build the complete public production app. No internal/metrics route is merged here.
pub fn create_router(state: AppState) -> axum::Router {
    create_router_with_auth_layer(state, |app, auth_state| {
        app.layer(axum_middleware::from_fn_with_state(auth_state, auth_middleware))
    })
}

// One production composition. Tests replace only credential resolution with
// resolved principals; all guarded state/auth constructors, policy ordering,
// resource guards, aliases, error handling and mounts remain the same.
fn create_router_with_auth_layer(
    state: AppState,
    authenticate: impl FnOnce(axum::Router, AuthState) -> axum::Router,
) -> axum::Router {
    let config = state.config.clone();
    #[cfg(feature = "enterprise")]
    let shared_product = config.deployment_mode.is_enterprise_shared();
    #[cfg(not(feature = "enterprise"))]
    let shared_product = false;
    let cors = build_cors_layer(&config);
    // Build IP allowlist state for middleware
    let ip_allowlist_state = IpAllowlistState {
        service: state.ip_allowlist_service.clone(),
        scope: IpAllowlistScope::Api,
    };

    // Build auth state for middleware
    let permission_resolver = nanosiem_core::auth::PermissionResolver::new(state.pool.clone());
    let auth_state = AuthState::from_arcs(
        state.token_service.clone(),
        Some(state.api_key_service.clone()),
        state.auth_enabled,
    )
    .with_permission_resolver(permission_resolver)
    // Per-source RBAC (NAN-1799): the middleware resolves each caller's
    // source-scope deny set into AuthContext::denied_sources, failing closed
    // (503) if the registry is unavailable.
    .with_source_scope_resolver(state.source_scope_resolver.clone())
    // F-32: reject disabled/locked/deleted users and pre-revocation access
    // tokens on every request (fail-closed 503 on lookup error).
    .with_user_status_resolver(nanosiem_core::auth::UserStatusResolver::new(
        state.pool.clone(),
    ));
    #[cfg(feature = "enterprise")]
    let auth_state = if state.config.deployment_mode.is_enterprise_shared() {
        auth_state.with_enterprise_shared_tenant_resolver(
            nanosiem_core::auth::TenantMembershipResolver::new(state.pool.clone()),
            state.pool.clone(),
        )
    } else {
        auth_state
    };
    #[cfg(feature = "enterprise")]
    let auth_state=auth_state.with_shared_authorization_audit(
        state.tenant_ai_rls_runtime.as_ref().map(|runtime|runtime.tenant_authorization_audit()));
    #[cfg(feature = "enterprise")]
    let auth_state = auth_state.with_shared_demo(
        state.tenant_ai_rls_runtime.as_ref().map(|runtime| runtime.demo_runtime()));

    let app = register_routes(&state);
    let registry = Arc::new(nanosiem_api_lib::route_policy::Registry::new(app.manifest().to_vec()));
    let app = app
        // Add state
        .with_state(state.clone())
        // Demo guard (runs after auth, blocks admin endpoints for demo users)
        .layer(axum_middleware::from_fn_with_state(
            state.config.deployment_mode,
            crate::middleware::demo_guard,
        ))
        // NAN-3844: an `install.sh --tenzir` install has no Vector; refuse the
        // mutations that need it with a 409 naming the fix (runs after auth).
        .layer(axum_middleware::from_fn_with_state(
            state.config.ingest_mode,
            crate::middleware::vector_ingest_guard,
        ))
        // Tier-based API write guard (runs after auth, blocks API key writes on readonly tiers)
        // NAN-2761: shared tenants resolve limits from their own plan
        // assignment (control pool); the guard fails closed on read errors.
        .layer(axum_middleware::from_fn_with_state(
            crate::middleware::tier_guard::ApiWriteGuardState {
                pool: state.pool.clone(),
                #[cfg(feature = "enterprise")]
                enterprise_shared: state.config.deployment_mode.is_enterprise_shared(),
            },
            crate::middleware::api_write_guard,
        ))
        // Match URL tenant after authentication, inside the existing denial
        // audit wrapper and before any handler or write guard executes.
        .layer(axum_middleware::from_fn(
            nanosiem_api_lib::tenant_path::enforce_tenant_path,
        ))
        // Capability before guards that may resolve plan/tenant data or parse bodies.
        .layer(axum_middleware::from_fn_with_state(registry, nanosiem_api_lib::route_policy::enforce))
        // Audit middleware: capture 403s from handlers + downstream guards and
        // emit auth_denied events. Sits between auth (which sets AuthContext)
        // and the per-handler guards so it observes their 403s as well.
        // Linear: NAN-687
        .layer(axum_middleware::from_fn_with_state(
            state.clone(),
            crate::middleware::audit_authz_failures,
        ))
        // NAN-3222: audit nPL run on a member's behalf that names a source the
        // member cannot see (needs AuthContext; the response is untouched).
        .layer(axum_middleware::from_fn_with_state(
            crate::middleware::denied_source_audit::sink(state.clone()),
            crate::middleware::denied_source_audit::denied_source_audit_middleware,
        ));
    // Credential resolution remains outside the policy/resource guards and
    // inside license/CORS/logging, for every production profile.
    #[cfg_attr(not(feature = "enterprise"), allow(unused_mut))]
    let mut app = authenticate(app, auth_state);

    // License enforcement (runs before auth — locked deployments get 403
    // immediately). Enterprise-only: the open edition has no license guard, so
    // requests are never gated on license state (NAN-1193). Kept at this exact
    // point in the layer sequence so the enterprise stack is byte-for-byte
    // identical to before.
    #[cfg(feature = "enterprise")]
    {
        app = app.layer(axum_middleware::from_fn_with_state(
            state.license_status.clone(),
            crate::middleware::license_guard,
        ));
    }

    // Shared authentication enforces the exact tenant policy after verified
    // identity. Its restricted database role cannot read the legacy global
    // allowlist, which belongs only to open-core and dedicated deployments.
    #[cfg(feature = "enterprise")]
    let shared_tenant_ip_policy = config.deployment_mode.is_enterprise_shared();
    #[cfg(not(feature = "enterprise"))]
    let shared_tenant_ip_policy = false;
    let app = if shared_tenant_ip_policy {
        app
    } else {
        app.layer(axum_middleware::from_fn_with_state(
            ip_allowlist_state,
            ip_allowlist_middleware,
        ))
    };
    let app = app
        // Catch handler panics so a single bad request returns 500 instead of
        // dropping the connection (NAN-2361; nanosiem-search already does this).
        .layer(tower_http::catch_panic::CatchPanicLayer::new())
        // Sanitize framework-generated error responses (e.g. Json extractor rejections)
        .layer(axum_middleware::from_fn(
            crate::middleware::sanitize_error_responses,
        ))
        // NAN-3198: API answers are never stored by shared caches unless the
        // route sets its own Cache-Control.
        .layer(axum_middleware::from_fn(
            crate::middleware::api_default_cache_control,
        ))
        // NAN-4753: SSE answers opt out of ingress proxy buffering, or NGINX
        // holds them (headers included) until Cloudflare 524s at 100 s.
        .layer(axum_middleware::from_fn(nanosiem_api_lib::sse::sse_unbuffered))
        .layer(axum_middleware::from_fn(nanosiem_api_lib::ai_request::wizard_request_deadline))
        // Add middleware
        .layer(CompressionLayer::new().gzip(true))
        .layer(SetResponseHeaderLayer::overriding(
            HeaderName::from_static("x-frame-options"),
            HeaderValue::from_static("DENY"),
        ))
        .layer(SetResponseHeaderLayer::overriding(
            HeaderName::from_static("x-content-type-options"),
            HeaderValue::from_static("nosniff"),
        ))
        .layer(SetResponseHeaderLayer::overriding(
            HeaderName::from_static("referrer-policy"),
            HeaderValue::from_static("strict-origin-when-cross-origin"),
        ))
        .layer(SetResponseHeaderLayer::overriding(
            HeaderName::from_static("permissions-policy"),
            HeaderValue::from_static("geolocation=(), microphone=(), camera=()"),
        ))
        .layer(SetResponseHeaderLayer::overriding(
            HeaderName::from_static("x-xss-protection"),
            HeaderValue::from_static("0"),
        ))
        .layer(cors)
        .layer(request_logging_layer())
        // Add request ID middleware (outermost - runs first)
        .layer(axum_middleware::from_fn(request_id_middleware));

    if shared_product {
        nanosiem_api_lib::tenant_path::scoped_api_router(app.merge(openapi::tenant_swagger_router()))
            .layer(axum_middleware::from_fn(openapi::shared_root_docs_fence))
    } else {
        app
    }
}

fn legacy_api_key_routes() -> Router<AppState> {
    Router::new()
        .route("/api/api-keys", get(handlers::api_keys::list_keys, RoutePolicy::all_of(&["apikeys:view"])))
        .route("/api/api-keys", post(handlers::api_keys::create_key, RoutePolicy::interactive_all_of(&["apikeys:create"])))
        .route("/api/api-keys/{id}", get(handlers::api_keys::get_key, RoutePolicy::all_of(&["apikeys:view"])))
        .route(
            "/api/api-keys/{id}/usage",
            get(handlers::api_keys::get_key_usage, RoutePolicy::all_of(&["apikeys:view"])),
        )
        .route("/api/api-keys/{id}", put(handlers::api_keys::update_key, RoutePolicy::all_of(&["apikeys:edit"])))
        .route("/api/api-keys/{id}", delete(handlers::api_keys::delete_key, RoutePolicy::all_of(&["apikeys:delete"])))
        .route(
            "/api/api-keys/{id}/enable",
            post(handlers::api_keys::enable_key, RoutePolicy::interactive_all_of(&["apikeys:edit"])),
        )
        .route(
            "/api/api-keys/{id}/disable",
            post(handlers::api_keys::disable_key, RoutePolicy::interactive_all_of(&["apikeys:edit"])),
        )
        .route(
            "/api/api-keys/{id}/reset",
            post(handlers::api_keys::reset_key, RoutePolicy::interactive_all_of(&["apikeys:edit"])),
        )
}

/// Build CORS layer from configuration.
/// When specific origins are configured, credentials (cookies) are allowed.
/// With wildcard "*", credentials are NOT allowed (browser spec restriction).
fn build_cors_layer(config: &ApiConfig) -> CorsLayer {
    use tower_http::cors::AllowOrigin;

    let mut cors = CorsLayer::new()
        .allow_methods([
            axum::http::Method::GET,
            axum::http::Method::POST,
            axum::http::Method::PUT,
            axum::http::Method::PATCH,
            axum::http::Method::DELETE,
            axum::http::Method::OPTIONS,
        ])
        .allow_headers([
            axum::http::header::AUTHORIZATION,
            axum::http::header::CONTENT_TYPE,
            axum::http::header::ACCEPT,
            axum::http::header::HeaderName::from_static("prefer"),
            axum::http::header::HeaderName::from_static("x-api-key"),
            axum::http::header::HeaderName::from_static("x-request-id"),
            axum::http::header::HeaderName::from_static("x-ioc-list-options"),
        ]);

    // Only allow wildcard CORS if explicitly configured with "*"
    if config.cors_origins.len() == 1 && config.cors_origins.contains(&"*".to_string()) {
        tracing::warn!(
            "CORS configured to allow ALL origins (*) - this should only be used in development"
        );
        // AllowOrigin::any() sets `Access-Control-Allow-Origin: *` which blocks
        // credentials (cookies). We accept that trade-off for the wildcard case:
        // mirror_request() + credentials would let ANY website make authenticated
        // requests, which is a CSRF-equivalent vulnerability.
        // For dev environments that need cookies, configure explicit origins instead.
        cors = cors.allow_origin(AllowOrigin::any());
    } else {
        // Parse and validate specific origins
        let origins: Vec<axum::http::HeaderValue> = config
            .cors_origins
            .iter()
            .filter_map(|origin| match origin.parse::<axum::http::HeaderValue>() {
                Ok(header_value) => {
                    tracing::info!("CORS: Allowing origin: {}", origin);
                    Some(header_value)
                }
                Err(e) => {
                    tracing::error!("CORS: Invalid origin '{}': {}", origin, e);
                    None
                }
            })
            .collect();

        if origins.is_empty() {
            tracing::error!(
                "CORS: No valid origins configured! API will reject all cross-origin requests."
            );
            // Return a CORS layer that allows no origins (most secure default)
            cors = cors.allow_origin(AllowOrigin::predicate(|_origin, _parts| false));
        } else {
            cors = cors
                .allow_origin(AllowOrigin::list(origins))
                .allow_credentials(true);
        }
    }

    cors
}

#[cfg(test)]
mod policy_tests;
