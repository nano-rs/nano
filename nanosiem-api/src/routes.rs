// SPDX-License-Identifier: AGPL-3.0-or-later

//! API route definitions

use axum::{
    extract::DefaultBodyLimit,
    http::{header, HeaderName, HeaderValue},
    middleware as axum_middleware,
    routing::{delete, get, patch, post, put},
    Router,
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
#[cfg(feature = "enterprise")]
use crate::middleware::rate_limit::marketplace_preview_rate_limit_middleware;
use nanosiem_core::ip_allowlist::IpAllowlistScope;

/// Create the API router with all routes
pub fn create_router(state: AppState) -> Router {
    let config = state.config.clone();

    // Build CORS layer
    let cors = build_cors_layer(&config);

    // Build rate limit state for auth endpoints (PostgreSQL-backed, shared across nodes)
    let rate_limit_state = Arc::new(RateLimitState::from_env(state.pool.clone()));

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

    // Rate-limited login route
    let login_route = Router::new()
        .route("/api/auth/login", post(handlers::auth::login))
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
            post(handlers::auth::request_password_reset),
        )
        .route(
            "/api/auth/password/reset",
            post(handlers::auth::reset_password),
        )
        .layer(axum_middleware::from_fn_with_state(
            (*rate_limit_state).clone(),
            password_reset_rate_limit_middleware,
        ));

    // Rate-limited MFA challenge route (same rate limit as login)
    let mfa_challenge_route = Router::new()
        .route(
            "/api/auth/mfa/challenge",
            post(handlers::mfa::verify_mfa_challenge),
        )
        .layer(axum_middleware::from_fn_with_state(
            (*rate_limit_state).clone(),
            login_rate_limit_middleware,
        ));

    // Rate-limited MFA setup + verify-setup routes. Both are public
    // (challenge_token-authenticated for forced enrolment), so without a
    // limiter they're a brute-force surface for the 6-digit TOTP and an
    // amplifier for repeated encryption-service calls. Uses the dedicated
    // `mfa_setup_ip` bucket (NAN-592) — separate from `login_ip` so a
    // busy login window doesn't exhaust the budget for users currently
    // enrolling, and sized higher to accommodate corporate NAT.
    let mfa_setup_routes = Router::new()
        .route("/api/auth/mfa/setup", post(handlers::mfa::setup_mfa))
        .route(
            "/api/auth/mfa/verify-setup",
            post(handlers::mfa::verify_mfa_setup),
        )
        .layer(axum_middleware::from_fn_with_state(
            (*rate_limit_state).clone(),
            mfa_setup_rate_limit_middleware,
        ));

    // Rate-limited upload routes (prevents DoS via large file uploads)
    // Body limit is enforced at HTTP layer before loading into memory
    // Note: Log upload removed - logs go through Vector ingestion pipeline
    let upload_routes = Router::new()
        .route("/api/upload/preview", post(handlers::preview_upload))
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
        .route("/api/artifacts", get(handlers::artifacts::list_artifacts))
        .route("/api/artifacts", post(handlers::artifacts::create_artifact))
        .route("/api/artifacts/{id}", get(handlers::artifacts::get_artifact))
        .route(
            "/api/artifacts/{id}",
            put(handlers::artifacts::update_artifact),
        )
        .route(
            "/api/artifacts/{id}",
            delete(handlers::artifacts::delete_artifact),
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
            post(handlers::airgap::parsers::import_parser_bundle),
        )
        .route(
            "/api/airgap/enrichment/import",
            post(handlers::airgap::enrichment::import_enrichment_bundle),
        )
        .route(
            "/api/airgap/rules/import",
            post(handlers::airgap::rules::import_rule_bundle),
        )
        .route(
            "/api/airgap/playbooks/import",
            post(handlers::airgap::playbooks::import_playbook_bundle),
        )
        .layer(DefaultBodyLimit::max(MAX_AIRGAP_BUNDLE_SIZE));

    // NAN-474: dry-resolve is rate-limited per authenticated user because
    // templating cost scales with `{{...}}` token count. The middleware
    // runs inside the outer auth layer, so `AuthContext` is available.
    let dry_resolve_routes = Router::new()
        .route(
            "/api/playbooks/dry-resolve",
            post(handlers::playbooks::dry_resolve),
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
        .route(
            "/api/source-configurations/{id}/rules/check-reachability",
            post(handlers::source_configs::check_routing_rule_reachability),
        )
        .layer(axum_middleware::from_fn_with_state(
            (*rate_limit_state).clone(),
            kafka_probe_rate_limit_middleware,
        ));

    // NAN-2064: this probe decrypts a stored GitHub PAT and spends external API
    // budget. Keep it out of the general route tree so every invocation is
    // rate-limited per interactive user/API key and target.
    let detection_code_probe_routes = Router::new()
        .route(
            "/api/detection-code-targets/{id}/test",
            post(handlers::detection_code_targets::test_connection),
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
        .route(
            "/api/marketplace/catalog/{slug}/preview",
            post(handlers::marketplace::preview_enrichment),
        )
        .layer(axum_middleware::from_fn_with_state(
            (*rate_limit_state).clone(),
            marketplace_preview_rate_limit_middleware,
        ));

    // Cacheable route groups with Cache-Control headers
    // Static metadata - 5 minute browser cache
    let cached_metadata = Router::new()
        .route("/api/udm/fields", get(handlers::get_udm_fields))
        .route("/api/schema/fields", get(handlers::get_schema_fields))
        .route("/api/source-types", get(handlers::get_source_types))
        .route("/api/permissions", get(handlers::roles::list_permissions))
        .route("/api/audit/actions", get(handlers::audit::get_action_types))
        .route(
            "/api/audit/resource-types",
            get(handlers::audit::get_resource_types),
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
        .route("/api/mitre", get(handlers::mitre::get_mitre_data))
        .layer(SetResponseHeaderLayer::if_not_present(
            header::CACHE_CONTROL,
            HeaderValue::from_static("private, max-age=3600, stale-while-revalidate=300"),
        ));

    // Coverage includes live ingestion readiness. Keep it briefly cacheable
    // without allowing the previous one-hour catalog cache to hide a source
    // becoming active or stale.
    let cached_mitre_coverage = Router::new()
        .route(
            "/api/mitre/coverage",
            get(handlers::mitre::get_mitre_coverage),
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
                    post(handlers::demo::create_demo_session),
                )
                .route(
                    "/api/demo/session/status",
                    get(handlers::demo::get_demo_session_status),
                )
                .route(
                    "/api/demo/session/{token}/claim",
                    post(handlers::demo::claim_demo_token),
                ),
        )
    } else {
        None
    };

    // Build the router
    let mut app = Router::new()
        // Health check (public - minimal info only)
        .route("/health", get(handlers::health_check))
        .route("/ready", get(handlers::ready_check))
        // Shallow liveness/readiness probe — no dep checks (NAN-1786). What k8s
        // liveness/readiness probes should target; /health and /ready are deep
        // (dependency-gated) and are for monitoring, not probes.
        .route("/livez", get(handlers::livez))
        // Detailed health check (authenticated - full diagnostics)
        .route("/health/detailed", get(handlers::health_check_detailed))
        // Build edition + capability flags (public; the SPA hits this on boot
        // before login to decide which surfaces to render). NAN-745.
        .route("/api/capabilities", get(handlers::capabilities::get_capabilities))
        // Setup endpoints (public - for first-run setup)
        .route("/api/setup/status", get(handlers::setup::get_setup_status))
        .route(
            "/api/setup/initialize",
            post(handlers::setup::initialize_system),
        )
        // Authentication endpoints (public) - rate-limited routes merged in
        .merge(login_route)
        .route("/api/auth/logout", post(handlers::auth::logout))
        .route("/api/auth/refresh", post(handlers::auth::refresh_token))
        .merge(password_reset_routes)
        .route("/api/auth/password", put(handlers::auth::change_password))
        .route("/api/auth/me", get(handlers::auth::get_current_user))
        .route("/api/auth/validate", get(handlers::auth::validate_token))
        // MFA endpoints
        .merge(mfa_challenge_route)
        .merge(mfa_setup_routes)
        .route("/api/auth/mfa/status", get(handlers::mfa::get_mfa_status))
        .route("/api/auth/mfa", delete(handlers::mfa::disable_mfa))
        .route(
            "/api/auth/mfa/backup-codes",
            post(handlers::mfa::regenerate_backup_codes),
        )
        .route(
            "/api/admin/users/{id}/mfa",
            delete(handlers::mfa::admin_reset_mfa),
        )
        .route(
            "/api/settings/mfa-required",
            put(handlers::mfa::set_mfa_required),
        )
        // OIDC authentication endpoints — gated to enterprise (NAN-745).
        // Registered below in the enterprise-only block.
        // User management endpoints
        .route("/api/users", get(handlers::users::list_users))
        .route("/api/users", post(handlers::users::create_user))
        // User preferences (must be before {id} routes)
        .route(
            "/api/users/me/preferences",
            get(handlers::users::get_my_preferences),
        )
        .route(
            "/api/users/me/preferences",
            patch(handlers::users::update_my_preferences),
        )
        .route("/api/users/{id}", get(handlers::users::get_user))
        .route("/api/users/{id}", put(handlers::users::update_user))
        .route("/api/users/{id}", delete(handlers::users::delete_user))
        .route(
            "/api/users/{id}/groups",
            put(handlers::users::update_user_groups),
        )
        .route("/api/users/{id}/unlock", post(handlers::users::unlock_user))
        .route(
            "/api/users/{id}/disable",
            post(handlers::users::disable_user),
        )
        .route("/api/users/{id}/enable", post(handlers::users::enable_user))
        // Group management endpoints
        .route("/api/groups", get(handlers::groups::list_groups))
        .route("/api/groups", post(handlers::groups::create_group))
        .route("/api/groups/{id}", get(handlers::groups::get_group))
        .route("/api/groups/{id}", put(handlers::groups::update_group))
        .route("/api/groups/{id}", delete(handlers::groups::delete_group))
        .route(
            "/api/groups/{id}/roles",
            put(handlers::groups::update_group_roles),
        )
        .route(
            "/api/groups/{id}/members",
            get(handlers::groups::get_group_members),
        )
        // Role management endpoints
        .route("/api/roles", get(handlers::roles::list_roles))
        .route("/api/roles", post(handlers::roles::create_role))
        .route("/api/roles/{id}", get(handlers::roles::get_role))
        .route("/api/roles/{id}", put(handlers::roles::update_role))
        .route("/api/roles/{id}", delete(handlers::roles::delete_role))
        // API key management endpoints
        .route("/api/api-keys", get(handlers::api_keys::list_keys))
        .route("/api/api-keys", post(handlers::api_keys::create_key))
        .route("/api/api-keys/{id}", get(handlers::api_keys::get_key))
        .route(
            "/api/api-keys/{id}/usage",
            get(handlers::api_keys::get_key_usage),
        )
        .route("/api/api-keys/{id}", put(handlers::api_keys::update_key))
        .route("/api/api-keys/{id}", delete(handlers::api_keys::delete_key))
        .route(
            "/api/api-keys/{id}/enable",
            post(handlers::api_keys::enable_key),
        )
        .route(
            "/api/api-keys/{id}/disable",
            post(handlers::api_keys::disable_key),
        )
        .route(
            "/api/api-keys/{id}/reset",
            post(handlers::api_keys::reset_key),
        )
        // Session management endpoints
        .route("/api/sessions", get(handlers::sessions::list_all_sessions))
        .route(
            "/api/sessions/me",
            get(handlers::sessions::list_my_sessions),
        )
        .route(
            "/api/sessions/count",
            get(handlers::sessions::count_sessions),
        )
        .route("/api/sessions/{id}", get(handlers::sessions::get_session))
        .route(
            "/api/sessions/{id}",
            delete(handlers::sessions::terminate_session),
        )
        .route(
            "/api/sessions/user/{user_id}",
            delete(handlers::sessions::terminate_user_sessions),
        )
        // Audit log endpoints
        .route("/api/audit", get(handlers::audit::query_audit_logs))
        .route(
            "/api/audit/export",
            post(handlers::audit::export_audit_logs),
        )
        // NOTE: Core search endpoints (/api/search, /api/search/sql, /api/search/explain,
        // /api/search/saved/*) moved to nanosiem-search service (port 3002) and are routed
        // there via nginx.
        // Search history (per-user) - remains in Main API
        .route(
            "/api/search/history",
            get(handlers::search_history::list_history),
        )
        .route(
            "/api/search/history",
            post(handlers::search_history::add_history),
        )
        .route(
            "/api/search/history",
            delete(handlers::search_history::clear_history),
        )
        .route(
            "/api/search/history/settings",
            put(handlers::search_history::set_history_enabled),
        )
        .route(
            "/api/search/history/{id}",
            delete(handlers::search_history::delete_history_entry),
        )
        // Recent activity (Continue Working feature)
        .route(
            "/api/me/recent",
            get(handlers::recent_activity::list_recent_activity),
        )
        .route(
            "/api/me/recent",
            post(handlers::recent_activity::record_activity),
        )
        .route(
            "/api/me/recent",
            delete(handlers::recent_activity::clear_recent_activity),
        )
        // Shared searches (short URLs)
        .route("/api/search/share", post(handlers::create_shared_search))
        .route("/api/search/shared/{id}", get(handlers::get_shared_search))
        // Query explanations (AI reasoning cache)
        .route(
            "/api/search/explanation",
            post(handlers::store_query_explanation),
        )
        .route(
            "/api/search/explanation",
            get(handlers::get_query_explanation),
        )
        // Rules (detection rules)
        .route("/api/rules", get(handlers::list_detections))
        .route("/api/rules", post(handlers::create_detection))
        .route("/api/rules/import", post(handlers::import_detections))
        .route("/api/rules/export", get(handlers::export_detections))
        // Auto retro-hunt rules (NAN-1791). Static paths BEFORE `/api/rules/{id}`.
        .route("/api/rules/retro-hunt", post(handlers::create_retro_hunt))
        .route(
            "/api/rules/retro-hunt/feeds",
            get(handlers::list_retro_hunt_feeds),
        )
        .route(
            "/api/rules/{id}/retro-hunt",
            get(handlers::get_retro_hunt).put(handlers::update_retro_hunt),
        )
        .route(
            "/api/rules/{id}/retro-hunt/runs",
            get(handlers::list_retro_hunt_runs),
        )
        .route("/api/rules/test", post(handlers::test_query))
        .route("/api/rules/format", post(handlers::format_query))
        .route("/api/rules/validate", post(handlers::validate_detection))
        .route("/api/rules/bulk-update", post(handlers::bulk_update_rules))
        .route("/api/rules/{id}", get(handlers::get_detection))
        .route("/api/rules/{id}", put(handlers::update_detection))
        .route("/api/rules/{id}", delete(handlers::delete_detection))
        .route("/api/rules/{id}/pause", post(handlers::pause_detection))
        .route("/api/rules/{id}/resume", post(handlers::resume_detection))
        .route("/api/rules/{id}/test", post(handlers::test_detection))
        .route("/api/rules/{id}/promote", post(handlers::promote_detection))
        .route("/api/rules/{id}/demote", post(handlers::demote_detection))
        .route("/api/rules/{id}/trigger", post(handlers::trigger_detection))
        .route(
            "/api/rules/{id}/matches",
            get(handlers::get_detection_matches),
        )
        .route("/api/rules/{id}/versions", get(handlers::get_rule_versions))
        .route(
            "/api/rules/{id}/versions/{version_id}/revert",
            post(handlers::revert_to_version),
        )
        .route("/api/rules/stats", get(handlers::get_detection_stats))
        .route("/api/rules/today-counts", get(handlers::get_today_counts))
        .route(
            "/api/rules/health-summary",
            get(handlers::get_detection_health_summary),
        )
        .route(
            "/api/rules/fleet-health",
            get(handlers::get_fleet_health),
        )
        .route("/api/rules/noisy", get(handlers::get_noisy_rules))
        // Per-match review state (NAN-494)
        .route(
            "/api/matches/{id}/review",
            post(handlers::mark_match_reviewed).delete(handlers::unmark_match_reviewed),
        )
        // Per-match disposition + rule-level rollup (NAN-498)
        .route(
            "/api/rules/{id}/disposition-stats",
            get(handlers::get_rule_disposition_stats),
        )
        .route(
            "/api/matches/{id}/disposition",
            post(handlers::set_match_disposition),
        )
        // Parsed nPL predicates for the Matches detail "Rule conditions" card (NAN-501)
        .route(
            "/api/rules/{id}/predicates",
            get(handlers::get_rule_predicates),
        )
        // Alerts
        .route("/api/alerts", get(handlers::list_alerts))
        .route("/api/alerts/stream", get(handlers::stream_alerts))
        .route("/api/alerts/bulk", post(handlers::bulk_alerts))
        .route("/api/alerts/counts", get(handlers::alert_counts))
        .route("/api/alerts/velocity", get(handlers::alert_velocity))
        .route("/api/alerts/{id}", get(handlers::get_alert))
        .route(
            "/api/alerts/{id}/acknowledge",
            post(handlers::acknowledge_alert),
        )
        .route("/api/alerts/{id}/close", post(handlers::close_alert))
        .route("/api/alerts/{id}/assign", post(handlers::assign_alert));

    // License status (exempt from license guard so the frontend can check it).
    // Enterprise-only: the open edition ships no license handler (NAN-1193).
    #[cfg(feature = "enterprise")]
    {
        app = app.route("/api/license", get(handlers::license::get_license_status));
        // Air-gapped offline license import (NAN-1206). Kept license-guard-exempt
        // so a fresh / locked install with no license yet can import one to recover.
        // Payload is tiny (<256KB), so it stays under the default body limit.
        app = app.route(
            "/api/airgap/license/import",
            post(handlers::airgap::license::import_offline_license),
        );
    }

    // Cases + queues + queue-routing-rules + incidents — Phase 3.2 (NAN-744)
    // lifted nanosiem-core/src/cases/ + incidents/ to nanosiem-enterprise.
    #[cfg(feature = "enterprise")]
    {
        app = app
            // Cases
            .route("/api/cases/events", get(handlers::cases::case_events_stream::<AppState>))
            .route("/api/cases", get(handlers::cases::list_cases::<AppState>))
            .route("/api/cases", post(handlers::cases::create_case::<AppState>))
            .route("/api/cases/my", get(handlers::cases::get_my_cases::<AppState>))
            .route("/api/cases/stats", get(handlers::cases::get_case_stats::<AppState>))
            // NAN-1093: Signal Inbox aggregation — per-tab counts + incident pills.
            .route(
                "/api/cases/inbox-counts",
                get(handlers::cases::get_inbox_counts::<AppState>),
            )
            .route(
                "/api/cases/inbox-incidents",
                get(handlers::cases::get_inbox_incidents::<AppState>),
            )
            .route(
                "/api/cases/bulk/status",
                post(handlers::cases::bulk_change_case_status::<AppState>),
            )
            .route(
                "/api/cases/bulk/assign",
                post(handlers::cases::bulk_assign_cases::<AppState>),
            )
            .route("/api/cases/{id}", get(handlers::cases::get_case::<AppState>))
            .route("/api/cases/{id}", put(handlers::cases::update_case::<AppState>))
            .route("/api/cases/{id}", delete(handlers::cases::delete_case::<AppState>))
            .route(
                "/api/cases/{id}/alerts",
                post(handlers::cases::add_alert_to_case::<AppState>),
            )
            .route(
                "/api/cases/{id}/alerts/{alert_id}",
                delete(handlers::cases::remove_alert_from_case::<AppState>),
            )
            .route("/api/cases/{id}/wall", get(handlers::cases::get_case_wall::<AppState>))
            .route(
                "/api/cases/{id}/wall",
                post(handlers::cases::add_case_wall_entry::<AppState>),
            )
            .route("/api/cases/{id}/assign", post(handlers::cases::assign_case::<AppState>))
            .route(
                "/api/cases/{id}/escalate",
                post(handlers::cases::escalate_case::<AppState>),
            )
            .route(
                "/api/cases/{id}/status",
                post(handlers::cases::change_case_status::<AppState>),
            )
            .route(
                "/api/cases/{id}/related",
                get(handlers::cases::get_related_cases::<AppState>)
                    .post(handlers::cases::link_related_case::<AppState>),
            )
            .route(
                "/api/cases/{id}/related/{target_id}",
                axum::routing::delete(handlers::cases::unlink_related_case::<AppState>),
            )
            .route(
                "/api/cases/{id}/duplicates",
                get(handlers::cases::get_duplicate_candidates::<AppState>),
            )
            .route("/api/cases/{id}/share", post(handlers::cases::share_case::<AppState>))
            .route("/api/cases/{id}/merge", post(handlers::cases::merge_cases::<AppState>))
            // Case handoffs (NAN-415)
            .route(
                "/api/cases/{id}/handoff",
                post(handlers::cases::create_handoff::<AppState>),
            )
            .route(
                "/api/cases/{id}/handoff/{handoff_id}/accept",
                post(handlers::cases::accept_handoff::<AppState>),
            )
            .route(
                "/api/cases/{id}/handoff/{handoff_id}/bounce",
                post(handlers::cases::bounce_handoff::<AppState>),
            )
            .route(
                "/api/cases/{id}/handoff/{handoff_id}/cancel",
                post(handlers::cases::cancel_handoff::<AppState>),
            )
            // Case collab-presence heartbeat (NAN-420)
            .route(
                "/api/cases/{id}/presence",
                post(handlers::cases::post_case_presence_heartbeat::<AppState>),
            )
            // Case-Notebook integration
            .route(
                "/api/cases/{id}/notebook",
                get(handlers::cases::get_case_notebook::<AppState>),
            )
            .route(
                "/api/cases/{id}/notebook",
                post(handlers::cases::link_notebook_to_case::<AppState>),
            )
            .route(
                "/api/cases/{id}/notebook",
                delete(handlers::cases::unlink_notebook_from_case::<AppState>),
            )
            .route(
                "/api/cases/{id}/notebook/merge",
                post(handlers::cases::merge_notebook_into_case::<AppState>),
            )
            .route(
                "/api/cases/{id}/related-notebooks",
                get(handlers::cases::get_related_notebooks::<AppState>),
            )
            // Case saved searches (NAN-1072)
            .route(
                "/api/cases/saved-searches",
                get(handlers::cases::list_case_saved_searches::<AppState>),
            )
            .route(
                "/api/cases/saved-searches",
                post(handlers::cases::create_case_saved_search::<AppState>),
            )
            .route(
                "/api/cases/saved-searches/{id}",
                axum::routing::patch(handlers::cases::update_case_saved_search::<AppState>),
            )
            .route(
                "/api/cases/saved-searches/{id}",
                delete(handlers::cases::delete_case_saved_search::<AppState>),
            )
            // Queues (NAN-426)
            .route("/api/queues", get(handlers::cases::list_queues::<AppState>))
            .route("/api/queues", post(handlers::cases::create_queue::<AppState>))
            .route("/api/queues/mine", get(handlers::cases::list_my_queues::<AppState>))
            .route("/api/queues/{id}", get(handlers::cases::get_queue::<AppState>))
            .route("/api/queues/{id}", put(handlers::cases::update_queue::<AppState>))
            .route("/api/queues/{id}", delete(handlers::cases::delete_queue::<AppState>))
            // Queue routing rules (NAN-427)
            .route(
                "/api/queue-routing-rules",
                get(handlers::cases::list_queue_routing_rules::<AppState>),
            )
            .route(
                "/api/queue-routing-rules",
                post(handlers::cases::create_queue_routing_rule::<AppState>),
            )
            .route(
                "/api/queue-routing-rules/preview",
                post(handlers::cases::preview_queue_routing::<AppState>),
            )
            .route(
                "/api/queue-routing-rules/{id}",
                put(handlers::cases::update_queue_routing_rule::<AppState>),
            )
            .route(
                "/api/queue-routing-rules/{id}",
                delete(handlers::cases::delete_queue_routing_rule::<AppState>),
            )
            // Incidents (NAN-417)
            .route(
                "/api/incidents",
                post(handlers::incidents::create_incident::<AppState>),
            )
            .route("/api/incidents", get(handlers::incidents::list_incidents::<AppState>))
            .route(
                "/api/incidents/{id}",
                get(handlers::incidents::get_incident::<AppState>),
            )
            .route(
                "/api/incidents/{id}/cases",
                post(handlers::incidents::add_case_to_incident::<AppState>),
            )
            .route(
                "/api/incidents/{id}/cases/{case_id}",
                delete(handlers::incidents::remove_case_from_incident::<AppState>),
            );
    }

    #[cfg(feature = "enterprise")]
    {
        app = app.merge(marketplace_preview_routes);
    }

    app = app
        // Fields
        .route("/api/fields/ext", get(handlers::get_ext_fields))
        .route("/api/fields/{name}/values", get(handlers::get_field_values))
        // Enrichment
        .route(
            "/api/enrichment/sources",
            get(handlers::list_enrichment_sources),
        )
        .route(
            "/api/enrichment/ipinfo/configure",
            post(handlers::configure_ipinfo),
        )
        .route("/api/enrichment/ipinfo/sync", post(handlers::sync_ipinfo))
        .route(
            "/api/enrichment/sources/{id}/enable",
            post(handlers::enable_enrichment_source),
        )
        .route(
            "/api/enrichment/sources/{id}/disable",
            post(handlers::disable_enrichment_source),
        )
        .route(
            "/api/enrichment/sources/{id}/auto-sync",
            get(handlers::get_auto_sync_config),
        )
        .route(
            "/api/enrichment/sources/{id}/auto-sync",
            post(handlers::configure_auto_sync),
        )
        .route("/api/enrichment/stats", get(handlers::get_enrichment_stats))
        .route("/api/enrichment/lookup/{ip}", get(handlers::lookup_ip));
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
        app = app.route("/api/enrichment/agent/lookup", post(handlers::agent_lookup));
    }

    app = app
        // Cloud Credentials
        .route(
            "/api/credentials",
            get(handlers::credentials::list_credentials),
        )
        .route(
            "/api/credentials",
            post(handlers::credentials::create_credential),
        )
        .route(
            "/api/credentials/provider/{provider}",
            get(handlers::credentials::list_credentials_by_provider),
        )
        .route(
            "/api/credentials/{id}",
            get(handlers::credentials::get_credential),
        )
        .route(
            "/api/credentials/{id}",
            put(handlers::credentials::update_credential),
        )
        .route(
            "/api/credentials/{id}",
            delete(handlers::credentials::delete_credential),
        )
        .route(
            "/api/credentials/{id}/rotate",
            post(handlers::credentials::rotate_credential),
        )
        .route(
            "/api/credentials/{id}/versions",
            get(handlers::credentials::list_credential_versions),
        )
        .route(
            "/api/credentials/{id}/rollback",
            post(handlers::credentials::rollback_credential),
        )
        // Log Sources
        .route(
            "/api/log-sources",
            get(handlers::log_sources::list_log_sources),
        )
        .route(
            "/api/log-sources",
            post(handlers::log_sources::create_log_source),
        )
        .route(
            "/api/log-sources/validate-vrl",
            post(handlers::log_sources::validate_vrl),
        )
        .route(
            "/api/log-sources/validate-namespace",
            post(handlers::log_sources::validate_namespace),
        )
        .route(
            "/api/log-sources/test-vrl",
            post(handlers::log_sources::test_vrl),
        )
        .route(
            "/api/log-sources/test-live",
            post(handlers::log_sources::test_vrl_live),
        )
        .route(
            "/api/log-sources/deploy-all",
            post(handlers::log_sources::deploy_all_log_sources),
        )
        .route(
            "/api/log-sources/ingestion-history",
            get(handlers::log_sources::get_all_ingestion_history),
        )
        .route(
            "/api/log-sources/{id}",
            get(handlers::log_sources::get_log_source),
        )
        .route(
            "/api/log-sources/{id}",
            put(handlers::log_sources::update_log_source),
        )
        .route(
            "/api/log-sources/{id}",
            delete(handlers::log_sources::delete_log_source),
        )
        .route(
            "/api/log-sources/{id}/toggle",
            post(handlers::log_sources::toggle_log_source),
        )
        .route(
            "/api/log-sources/{id}/validate",
            post(handlers::log_sources::validate_log_source),
        )
        .route(
            "/api/log-sources/{id}/deploy",
            post(handlers::log_sources::deploy_log_source),
        )
        .route(
            "/api/log-sources/{id}/undeploy",
            post(handlers::log_sources::undeploy_log_source),
        )
        .route(
            "/api/log-sources/{id}/deployments",
            get(handlers::log_sources::get_log_source_deployments),
        )
        .route(
            "/api/log-sources/{id}/health",
            get(handlers::log_sources::get_log_source_health),
        )
        .route(
            "/api/log-sources/{id}/versions",
            get(handlers::log_sources::get_log_source_versions),
        )
        .route(
            "/api/log-sources/{id}/publish",
            post(handlers::log_sources::publish_log_source),
        )
        .route(
            "/api/log-sources/{id}/versions/{version_id}/revert",
            post(handlers::log_sources::revert_log_source_version),
        )
        .route(
            "/api/log-sources/{id}/discard-draft",
            post(handlers::log_sources::discard_log_source_draft),
        )
        .route(
            "/api/log-sources/{id}/draft-status",
            get(handlers::log_sources::get_log_source_draft_status),
        )
        // Source configurations (infrastructure + routing)
        .route(
            "/api/source-configurations",
            get(handlers::source_configs::list_source_configs),
        )
        .route(
            "/api/source-configurations",
            post(handlers::source_configs::create_source_config),
        )
        .route(
            "/api/source-configurations/deploy-all",
            post(handlers::source_configs::deploy_all_source_configs),
        )
        // NAN-649: per-driver type metadata (presets, push/pull, default
        // match_field). Must be registered before `/{id}` so axum doesn't
        // route the `types` literal as a TypeIdParam.
        .route(
            "/api/source-configurations/types",
            get(handlers::source_configs::list_source_config_types),
        )
        .route(
            "/api/source-configurations/{id}",
            get(handlers::source_configs::get_source_config),
        )
        .route(
            "/api/source-configurations/{id}/full",
            get(handlers::source_configs::get_source_config_with_rules),
        )
        .route(
            "/api/source-configurations/{id}",
            put(handlers::source_configs::update_source_config),
        )
        .route(
            "/api/source-configurations/{id}",
            delete(handlers::source_configs::delete_source_config),
        )
        .route(
            "/api/source-configurations/{id}/toggle",
            post(handlers::source_configs::toggle_source_config),
        )
        .route(
            "/api/source-configurations/{id}/deploy",
            post(handlers::source_configs::deploy_source_config),
        )
        .route(
            "/api/source-configurations/{id}/undeploy",
            post(handlers::source_configs::undeploy_source_config),
        )
        .route(
            "/api/source-configurations/{id}/deployments",
            get(handlers::source_configs::get_source_config_deployments),
        )
        // Routing rules (nested under source configurations)
        .route(
            "/api/source-configurations/{source_config_id}/rules",
            get(handlers::source_configs::list_routing_rules),
        )
        .route(
            "/api/source-configurations/{source_config_id}/rules",
            post(handlers::source_configs::create_routing_rule),
        )
        .route(
            "/api/source-configurations/{source_config_id}/rules/reorder",
            post(handlers::source_configs::reorder_routing_rules),
        )
        .route(
            "/api/source-configurations/{source_config_id}/rules/{rule_id}",
            put(handlers::source_configs::update_routing_rule),
        )
        .route(
            "/api/source-configurations/{source_config_id}/rules/{rule_id}",
            delete(handlers::source_configs::delete_routing_rule),
        );
    // NAN-939: probe route is registered separately via `kafka_probe_routes`
    // below so it picks up the per-user rate-limit middleware.

    // meloD AI assistant endpoints — enterprise only.
    #[cfg(feature = "enterprise")]
    {
        app = app
            .route("/api/melod/chat", post(handlers::melod_chat::<AppState>))
            .route(
                "/api/melod/chat/stream",
                post(handlers::melod_chat_streaming::<AppState>),
            )
            .route(
                "/api/melod/parser",
                post(handlers::melod_create_parser::<AppState>),
            )
            .route(
                "/api/melod/parser/stream",
                post(handlers::melod_create_parser_streaming::<AppState>),
            )
            .route(
                "/api/melod/parser/edit",
                post(handlers::melod_edit_parser::<AppState>),
            )
            .route(
                "/api/melod/query",
                post(handlers::melod_build_query::<AppState>),
            )
            .route(
                "/api/melod/correct-query",
                post(handlers::melod_correct_query::<AppState>),
            )
            .route(
                "/api/melod/review-query",
                post(handlers::melod_review_query::<AppState>),
            )
            .route(
                "/api/melod/detection",
                post(handlers::melod_create_detection::<AppState>),
            )
            .route(
                "/api/melod/detection/tune",
                post(handlers::melod_tune_detection::<AppState>),
            )
            .route(
                "/api/melod/detection/hints",
                post(handlers::melod_generate_detection_hints::<AppState>),
            )
            .route(
                "/api/melod/summarize",
                post(handlers::melod_summarize::<AppState>),
            )
            .route(
                "/api/melod/fetch-url",
                post(handlers::melod_fetch_url::<AppState>),
            )
            .route(
                "/api/melod/notebook/summarize",
                post(handlers::melod_summarize_notebook::<AppState>),
            )
            .route(
                "/api/melod/notebook/suggest-queries",
                post(handlers::melod_suggest_queries::<AppState>),
            )
            .route(
                "/api/melod/notebook/analyze-note",
                post(handlers::melod_analyze_note::<AppState>),
            )
            .route(
                "/api/melod/notebook/generate-timeline",
                post(handlers::melod_generate_timeline::<AppState>),
            )
            // Dashboard generation endpoints
            .route(
                "/api/melod/dashboard/generate",
                post(handlers::melod_generate_dashboard::<AppState>),
            )
            .route(
                "/api/melod/dashboard/refine",
                post(handlers::melod_refine_dashboard::<AppState>),
            )
            // Generic meloD async job poll endpoint
            .route(
                "/api/melod/jobs/{job_id}",
                get(handlers::melod_get_job::<AppState>),
            )
            // AI Debug endpoints
            .route(
                "/api/melod/failures",
                get(handlers::melod::get_ai_failures::<AppState>),
            );
    }

    // OIDC / SSO endpoints — open-core split (NAN-745). The handlers module
    // itself is gated, so both the public `/api/auth/oidc/*` discovery routes
    // and the `/api/settings/oidc/*` admin routes only register when the
    // `enterprise` feature is on. Open builds simply omit them — the frontend
    // already gates the SSO surface behind `capabilities.sso`.
    //
    // NAN-751 Phase 2: handlers were lifted to `nanosiem-enterprise`. They are
    // generic over the `OidcAppState` trait, so each call site below pins the
    // type parameter to `AppState` (the concrete state this router is built
    // with).
    #[cfg(feature = "enterprise")]
    {
        app = app
            // OIDC authentication endpoints (public)
            .route(
                "/api/auth/oidc/providers",
                get(handlers::oidc::list_enabled_providers::<AppState>),
            )
            .route(
                "/api/auth/oidc/{provider}/authorize",
                get(handlers::oidc::get_auth_url::<AppState>),
            )
            .route(
                "/api/auth/oidc/{provider}/callback",
                post(handlers::oidc::handle_callback::<AppState>),
            )
            // OIDC provider management (admin)
            .route(
                "/api/settings/oidc",
                get(handlers::oidc::list_providers::<AppState>),
            )
            .route(
                "/api/settings/oidc",
                post(handlers::oidc::create_provider::<AppState>),
            )
            .route(
                "/api/settings/oidc/{id}",
                get(handlers::oidc::get_provider::<AppState>),
            )
            .route(
                "/api/settings/oidc/{id}",
                put(handlers::oidc::update_provider::<AppState>),
            )
            .route(
                "/api/settings/oidc/{id}",
                delete(handlers::oidc::delete_provider::<AppState>),
            )
            .route(
                "/api/settings/oidc/{id}/enable",
                post(handlers::oidc::enable_provider::<AppState>),
            )
            .route(
                "/api/settings/oidc/{id}/disable",
                post(handlers::oidc::disable_provider::<AppState>),
            )
            .route(
                "/api/settings/oidc/{id}/mappings",
                get(handlers::oidc::get_group_mappings::<AppState>),
            )
            .route(
                "/api/settings/oidc/{id}/mappings",
                put(handlers::oidc::update_group_mappings::<AppState>),
            )
            .route(
                "/api/settings/oidc/{id}/token-groups",
                get(handlers::oidc::get_token_groups::<AppState>),
            );
    }

    app = app
        // Retention settings
        .route(
            "/api/settings/retention",
            get(handlers::get_retention_config),
        )
        .route(
            "/api/settings/retention",
            put(handlers::update_retention_config),
        )
        .route(
            "/api/settings/retention/run",
            post(handlers::run_retention_now),
        )
        .route("/api/settings/storage", get(handlers::get_storage_stats))
        // Storage overview (both PostgreSQL and ClickHouse)
        .route(
            "/api/settings/storage/overview",
            get(handlers::get_storage_overview),
        )
        // ClickHouse storage settings
        .route(
            "/api/settings/storage/clickhouse",
            get(handlers::get_clickhouse_storage_stats),
        )
        .route(
            "/api/settings/storage/clickhouse/retention",
            put(handlers::update_clickhouse_retention),
        )
        .route(
            "/api/settings/storage/clickhouse/retention/run",
            post(handlers::run_clickhouse_retention_now),
        )
        // Storage tiering settings
        .route("/api/settings/tiering", get(handlers::get_tiering_config))
        .route(
            "/api/settings/tiering",
            put(handlers::update_tiering_config),
        )
        .route(
            "/api/settings/tiering/credentials",
            post(handlers::set_tiering_credentials),
        )
        .route(
            "/api/settings/tiering/test",
            post(handlers::test_tiering_connection),
        )
        .route(
            "/api/settings/tiering/apply",
            post(handlers::apply_tiering_config),
        )
        .route("/api/settings/tiering/stats", get(handlers::get_tier_stats))
        // Risk settings (weight stays open; decay TTL config is enterprise)
        .route("/api/settings/risk", get(handlers::get_risk_config))
        .route("/api/settings/risk", put(handlers::update_risk_config));

    // Risk decay TTL + risk-notable config — enterprise only
    // (RiskAnalyticsService, NAN-1792; since NAN-1805 the notable config is a
    // thin editor over the seeded default dataset=risk detection rule).
    #[cfg(feature = "enterprise")]
    {
        app = app
            .route(
                "/api/settings/risk-decay",
                get(handlers::get_risk_decay_config),
            )
            .route(
                "/api/settings/risk-decay",
                put(handlers::update_risk_decay_config),
            )
            .route(
                "/api/settings/risk-notables",
                get(handlers::get_risk_notable_config),
            )
            .route(
                "/api/settings/risk-notables",
                put(handlers::update_risk_notable_config),
            );
    }

    // Case settings + case grouping rules — Phase 3.2 (NAN-744): both
    // surfaces are part of the cases lift to enterprise.
    #[cfg(feature = "enterprise")]
    {
        app = app
            // Case settings (global auto-grouping config)
            .route(
                "/api/settings/cases",
                get(handlers::cases::get_case_settings::<AppState>),
            )
            .route(
                "/api/settings/cases",
                put(handlers::cases::update_case_settings::<AppState>),
            )
            // Case grouping rules
            .route(
                "/api/settings/case-grouping",
                get(handlers::cases::list_grouping_rules::<AppState>),
            )
            .route(
                "/api/settings/case-grouping",
                post(handlers::cases::create_grouping_rule::<AppState>),
            )
            .route(
                "/api/settings/case-grouping/{id}",
                put(handlers::cases::update_grouping_rule::<AppState>),
            )
            .route(
                "/api/settings/case-grouping/{id}",
                delete(handlers::cases::delete_grouping_rule::<AppState>),
            );
    }

    app = app
        // Prevalence settings
        .route(
            "/api/settings/prevalence",
            get(handlers::prevalence::get_prevalence_settings),
        )
        .route(
            "/api/settings/prevalence",
            put(handlers::prevalence::update_prevalence_settings),
        )
        // Identity provider settings (Entra ID, Google Workspace, AD)
        .route(
            "/api/settings/identity-providers",
            get(handlers::identity::list_identity_providers),
        )
        .route(
            "/api/settings/identity-providers",
            post(handlers::identity::create_identity_provider),
        )
        .route(
            "/api/settings/identity-providers/{id}",
            get(handlers::identity::get_identity_provider),
        )
        .route(
            "/api/settings/identity-providers/{id}",
            put(handlers::identity::update_identity_provider),
        )
        .route(
            "/api/settings/identity-providers/{id}",
            delete(handlers::identity::delete_identity_provider),
        )
        .route(
            "/api/settings/identity-providers/{id}/credentials",
            post(handlers::identity::update_identity_credentials),
        )
        .route(
            "/api/settings/identity-providers/{id}/test",
            post(handlers::identity::test_identity_connection),
        )
        .route(
            "/api/settings/identity-providers/{id}/sync",
            post(handlers::identity::trigger_identity_sync),
        )
        // NAN-1151 (3d): the AD /push endpoint is retired — AD identity flows
        // through the nano_enrich lane (collector POSTs to Vector ingest).
        // Identity user directory
        .route(
            "/api/identity/users/lookup",
            get(handlers::identity::lookup_identity_user),
        )
        .route(
            "/api/identity/resolve",
            get(handlers::identity::resolve_identity_ip),
        )
        .route(
            "/api/identity/users",
            get(handlers::identity::list_identity_users),
        )
        .route(
            "/api/identity/users/{id}",
            get(handlers::identity::get_identity_user),
        )
        .route(
            "/api/identity/stats",
            get(handlers::identity::get_identity_stats),
        );

    // Agent + custom enrichment routes — enterprise only (Phase 3.3 of
    // NAN-744 lifted both core modules + handler files; the Risk-page-style
    // AI-powered IOC enrichment surface and the Deno user-defined
    // enrichment surface are enterprise capabilities).
    #[cfg(feature = "enterprise")]
    {
        app = app
            // Agent enrichment settings (AI-powered threat intel providers)
            .route(
                "/api/settings/agent-enrichments",
                get(handlers::agent_enrichment::list_providers::<AppState>),
            )
            .route(
                "/api/settings/agent-enrichments",
                post(handlers::agent_enrichment::create_provider::<AppState>),
            )
            .route(
                "/api/settings/agent-enrichments/{provider_id}",
                get(handlers::agent_enrichment::get_provider::<AppState>),
            )
            .route(
                "/api/settings/agent-enrichments/{provider_id}",
                put(handlers::agent_enrichment::update_provider::<AppState>),
            )
            .route(
                "/api/settings/agent-enrichments/{provider_id}",
                delete(handlers::agent_enrichment::delete_provider::<AppState>),
            )
            .route(
                "/api/settings/agent-enrichments/{provider_id}/credentials",
                post(handlers::agent_enrichment::update_credentials::<AppState>),
            )
            .route(
                "/api/settings/agent-enrichments/{provider_id}/test",
                post(handlers::agent_enrichment::test_connection::<AppState>),
            )
            .route(
                "/api/settings/agent-enrichments/{provider_id}/usage",
                get(handlers::agent_enrichment::get_usage_stats::<AppState>),
            )
            // Custom enrichments (user-defined TypeScript enrichments)
            .route(
                "/api/custom-enrichments",
                get(handlers::custom_enrichment::list_custom_enrichments::<AppState>),
            )
            .route(
                "/api/custom-enrichments",
                post(handlers::custom_enrichment::create_custom_enrichment::<AppState>),
            )
            .route(
                "/api/custom-enrichments/templates",
                get(handlers::custom_enrichment::get_templates),
            )
            .route(
                "/api/custom-enrichments/generate-code",
                post(handlers::custom_enrichment::generate_code::<AppState>),
            )
            .route(
                "/api/custom-enrichments/{id}",
                get(handlers::custom_enrichment::get_custom_enrichment::<AppState>),
            )
            .route(
                "/api/custom-enrichments/{id}",
                put(handlers::custom_enrichment::update_custom_enrichment::<AppState>),
            )
            .route(
                "/api/custom-enrichments/{id}",
                delete(handlers::custom_enrichment::delete_custom_enrichment::<AppState>),
            )
            .route(
                "/api/custom-enrichments/{id}/validate",
                post(handlers::custom_enrichment::validate_enrichment::<AppState>),
            )
            .route(
                "/api/custom-enrichments/{id}/deploy",
                post(handlers::custom_enrichment::deploy_enrichment::<AppState>),
            )
            .route(
                "/api/custom-enrichments/{id}/disable",
                post(handlers::custom_enrichment::disable_enrichment::<AppState>),
            )
            .route(
                "/api/custom-enrichments/{id}/versions",
                get(handlers::custom_enrichment::get_versions::<AppState>),
            )
            .route(
                "/api/custom-enrichments/{id}/versions/{version}/diff",
                get(handlers::custom_enrichment::get_version_diff::<AppState>),
            )
            .route(
                "/api/custom-enrichments/{id}/runs",
                get(handlers::custom_enrichment::get_runs::<AppState>),
            )
            .route(
                "/api/custom-enrichments/{id}/runs",
                post(handlers::custom_enrichment::trigger_run::<AppState>),
            );
    }

    app = app
        // Enrichment Marketplace (unified catalog)
        .route(
            "/api/marketplace/catalog",
            get(handlers::marketplace::list_catalog),
        )
        .route(
            "/api/marketplace/catalog/{slug}",
            get(handlers::marketplace::get_catalog_entry),
        )
        .route(
            "/api/marketplace/catalog/{slug}/install",
            post(handlers::marketplace::install_enrichment),
        )
        .route(
            "/api/marketplace/catalog/{slug}/uninstall",
            post(handlers::marketplace::uninstall_enrichment),
        )
        .route(
            "/api/marketplace/catalog/{slug}/update",
            post(handlers::marketplace::update_enrichment),
        )
        .route(
            "/api/marketplace/catalog/{slug}/configure",
            put(handlers::marketplace::configure_enrichment),
        )
        .route(
            "/api/marketplace/catalog/{slug}/sync",
            post(handlers::marketplace::sync_enrichment),
        )
        .route(
            "/api/marketplace/catalog/{slug}/status",
            get(handlers::marketplace::get_enrichment_status),
        )
        .route(
            "/api/marketplace/catalog/{slug}/export",
            get(handlers::marketplace::export_enrichment),
        );

    app = app
        .route(
            "/api/marketplace/coverage",
            get(handlers::marketplace::get_coverage),
        )
        .route(
            "/api/marketplace/coverage/refresh",
            post(handlers::marketplace::refresh_coverage),
        )
        .route(
            "/api/marketplace/repos",
            get(handlers::marketplace::list_repos),
        )
        .route(
            "/api/marketplace/repos",
            post(handlers::marketplace::create_repo),
        )
        .route(
            "/api/marketplace/repos/{id}",
            put(handlers::marketplace::update_repo),
        )
        .route(
            "/api/marketplace/repos/{id}",
            delete(handlers::marketplace::delete_repo),
        )
        .route(
            "/api/marketplace/repos/{id}/sync",
            post(handlers::marketplace::sync_repo),
        )
        .route(
            "/api/marketplace/repos/{id}/browse",
            get(handlers::marketplace::browse_repo),
        )
        // Organizational context settings (custom prompt data)
        .route(
            "/api/settings/organizational-context",
            get(handlers::get_organizational_context),
        )
        .route(
            "/api/settings/organizational-context",
            put(handlers::update_organizational_context),
        );

    // AI provider credentials, agent-model bindings, and the model catalog
    // are enterprise only — they touch state.melod_service /
    // state.agent_config_registry, both of which live behind the enterprise
    // feature gate.
    #[cfg(feature = "enterprise")]
    {
        app = app
            .route(
                "/api/settings/ai-availability",
                get(handlers::get_ai_availability),
            )
            .route(
                "/api/settings/ai-providers",
                get(handlers::list_ai_providers),
            )
            .route(
                "/api/settings/ai-providers/{provider}",
                get(handlers::get_ai_provider),
            )
            .route(
                "/api/settings/ai-providers/{provider}",
                put(handlers::update_ai_provider),
            )
            .route(
                "/api/settings/ai-providers/{provider}/validate",
                post(handlers::validate_ai_provider),
            )
            // Agent model configuration
            .route(
                "/api/settings/agent-models",
                get(handlers::list_agent_model_configs),
            )
            .route(
                "/api/settings/agent-models/{agent_id}",
                get(handlers::get_agent_model_config),
            )
            .route(
                "/api/settings/agent-models/{agent_id}",
                put(handlers::update_agent_model_config),
            )
            // Available models (filtered by enabled providers)
            .route(
                "/api/settings/available-models/all",
                get(handlers::list_all_available_models),
            )
            .route(
                "/api/settings/available-models",
                get(handlers::list_available_models),
            )
            .route(
                "/api/settings/available-models",
                post(handlers::create_available_model),
            )
            .route(
                "/api/settings/available-models/{model_id}",
                put(handlers::update_available_model),
            )
            .route(
                "/api/settings/available-models/{model_id}",
                delete(handlers::delete_available_model),
            )
            // Model catalog sync
            .route(
                "/api/settings/model-catalog/sync",
                post(handlers::sync_model_catalog),
            )
            .route(
                "/api/settings/model-catalog/status",
                get(handlers::get_model_catalog_status),
            );
    }

    app = app
        // Health monitoring settings
        .route(
            "/api/settings/health-monitoring",
            get(handlers::get_health_monitoring_settings),
        )
        .route(
            "/api/settings/health-monitoring",
            put(handlers::update_health_monitoring_settings),
        )
        // Developer settings (scheduler control)
        .route(
            "/api/settings/developer",
            get(handlers::get_developer_settings),
        )
        .route(
            "/api/settings/developer",
            put(handlers::update_developer_settings),
        )
        // Search admission control settings
        .route(
            "/api/settings/search",
            get(handlers::get_search_admission_settings),
        )
        .route(
            "/api/settings/search",
            put(handlers::update_search_admission_settings),
        )
        // Search query safety limits
        .route(
            "/api/settings/search/query-limits",
            get(handlers::get_search_query_limits),
        )
        .route(
            "/api/settings/search/query-limits",
            put(handlers::update_search_query_limits),
        )
        // Tier settings
        .route("/api/settings/tier", get(handlers::get_tier_status))
        .route("/api/settings/tier", put(handlers::set_tier))
        .route(
            "/api/settings/tier/limits",
            put(handlers::update_tier_limits),
        )
        .route("/api/settings/tier/usage", get(handlers::get_usage_history))
        .route(
            "/api/settings/ai-usage",
            get(handlers::get_ai_usage_detail),
        )
        // Webhook settings
        .route("/api/settings/webhooks", get(handlers::list_webhooks))
        .route("/api/settings/webhooks", post(handlers::create_webhook))
        .route("/api/settings/webhooks/{id}", get(handlers::get_webhook))
        .route("/api/settings/webhooks/{id}", put(handlers::update_webhook))
        .route(
            "/api/settings/webhooks/{id}",
            delete(handlers::delete_webhook),
        )
        .route(
            "/api/settings/webhooks/{id}/test",
            post(handlers::test_webhook),
        )
        .route(
            "/api/settings/webhooks/{id}/deliveries",
            get(handlers::list_webhook_deliveries),
        )
        // Notification config (deep-link base URL) — NAN-1790
        .route(
            "/api/settings/notifications/config",
            get(handlers::get_notification_config),
        )
        .route(
            "/api/settings/notifications/config",
            put(handlers::update_notification_config),
        )
        // Onboarding wizard
        .route(
            "/api/onboarding/progress",
            get(handlers::onboarding::get_onboarding_progress),
        )
        .route(
            "/api/onboarding/progress",
            put(handlers::onboarding::update_onboarding_progress),
        )
        .route(
            "/api/onboarding/complete-step",
            post(handlers::onboarding::complete_onboarding_step),
        )
        .route(
            "/api/onboarding/skip-step",
            post(handlers::onboarding::skip_onboarding_step),
        )
        .route(
            "/api/onboarding/dismiss",
            post(handlers::onboarding::dismiss_onboarding),
        )
        .route(
            "/api/onboarding/reset",
            post(handlers::onboarding::reset_onboarding),
        )
        .route(
            "/api/onboarding/status",
            get(handlers::onboarding::get_onboarding_status),
        )
        // IP Allowlist settings
        .route(
            "/api/settings/ip-allowlist",
            get(handlers::ip_allowlist::list_ip_allowlist),
        )
        .route(
            "/api/settings/ip-allowlist",
            post(handlers::ip_allowlist::create_ip_allowlist),
        )
        .route(
            "/api/settings/ip-allowlist/status",
            get(handlers::ip_allowlist::get_ip_allowlist_status),
        )
        .route(
            "/api/settings/ip-allowlist/test",
            post(handlers::ip_allowlist::test_ip_allowlist),
        )
        .route(
            "/api/settings/ip-allowlist/{id}",
            put(handlers::ip_allowlist::update_ip_allowlist),
        )
        .route(
            "/api/settings/ip-allowlist/{id}",
            delete(handlers::ip_allowlist::delete_ip_allowlist),
        )
        // Feedback
        .route("/api/feedback", get(handlers::feedback::list_feedback))
        .route("/api/feedback", post(handlers::feedback::create_feedback))
        .route(
            "/api/feedback/me",
            get(handlers::feedback::list_my_feedback),
        )
        .route("/api/feedback/{id}", get(handlers::feedback::get_feedback))
        .route(
            "/api/feedback/{id}",
            put(handlers::feedback::update_feedback),
        )
        .route(
            "/api/feedback/{id}",
            delete(handlers::feedback::delete_feedback),
        )
        // Folder settings (NAN-730)
        .route(
            "/api/folder-settings",
            get(handlers::folder_settings::list_folder_settings),
        )
        .route(
            "/api/folder-settings/{name}",
            put(handlers::folder_settings::set_folder_icon),
        )
        .route(
            "/api/folder-settings/{name}",
            delete(handlers::folder_settings::clear_folder_icon),
        )
        // Notifications
        .route(
            "/api/notifications",
            get(handlers::notifications::list_notifications),
        )
        .route(
            "/api/notifications/unread-count",
            get(handlers::notifications::get_unread_count),
        )
        .route(
            "/api/notifications/read-all",
            post(handlers::notifications::mark_all_notifications_read),
        )
        .route(
            "/api/notifications/{id}/read",
            post(handlers::notifications::mark_notification_read),
        );

    // Risk analytics (RiskAnalyticsService) — enterprise only.
    #[cfg(feature = "enterprise")]
    {
        app = app
            .route(
                "/api/risk/entities",
                get(handlers::risk::get_risky_entities::<AppState>),
            )
            .route(
                "/api/risk/overview",
                get(handlers::risk::get_risk_overview::<AppState>),
            )
            .route(
                "/api/risk/clear",
                post(handlers::risk::clear_entity_risk::<AppState>),
            )
            .route(
                "/api/risk/clear-all",
                post(handlers::risk::clear_all_risk_scores::<AppState>),
            )
            .route(
                "/api/risk/time-windowed",
                get(handlers::risk::get_time_windowed_risk_scores::<AppState>),
            )
            .route(
                "/api/risk/notable-count",
                get(handlers::risk::get_notable_count::<AppState>),
            )
            // NAN-1806: /api/risk/thresholds retired with the notable scheduler
            // (NAN-1805) — risk alerting is a `dataset=risk` detection rule.
            .route(
                "/api/risk/entity-activity",
                get(handlers::risk::get_entity_activity::<AppState>),
            );
    }

    // Entity context — enterprise only (depends on RiskAnalyticsService).
    #[cfg(feature = "enterprise")]
    {
        app = app.route(
            "/api/entities/{entity_type}/{entity_value}/context",
            get(handlers::entity_context::get_entity_context::<AppState>),
        );
    }

    app = app
        // Prevalence tracking
        .route(
            "/api/prevalence/hash/{hash}",
            get(handlers::prevalence::get_hash_prevalence),
        )
        .route(
            "/api/prevalence/domain/{domain}",
            get(handlers::prevalence::get_domain_prevalence),
        )
        .route(
            "/api/prevalence/bulk",
            post(handlers::prevalence::get_bulk_prevalence),
        )
        .route(
            "/api/prevalence/rare",
            get(handlers::prevalence::get_rare_artifacts),
        )
        .route(
            "/api/prevalence/new",
            get(handlers::prevalence::get_new_artifacts),
        )
        .route(
            "/api/prevalence/export",
            get(handlers::prevalence::export_prevalence),
        )
        .route(
            "/api/prevalence/scatter",
            post(handlers::prevalence::get_scatter_data),
        )
        .route(
            "/api/prevalence/query-artifacts",
            post(handlers::prevalence::get_query_artifacts),
        )
        .route(
            "/api/prevalence/explorer",
            get(handlers::prevalence::get_artifact_explorer),
        )
        .route(
            "/api/prevalence/explorer/detail",
            get(handlers::prevalence::get_artifact_detail),
        )
        // MITRE ATT&CK framework
        .route("/api/mitre/sync", post(handlers::mitre::sync_mitre_data))
        // NAN-1918: uncached — an operator checking this has just been told a
        // sync dropped mappings, and a stale answer would be worse than none.
        .route(
            "/api/mitre/quarantine",
            get(handlers::mitre::get_quarantined_mappings),
        )
        // Detection-as-code push targets: AI tuning opens PRs here (NAN-1745).
        .route(
            "/api/detection-code-targets",
            get(handlers::detection_code_targets::list_targets)
                .post(handlers::detection_code_targets::create_target),
        )
        .route(
            "/api/detection-code-targets/{id}",
            get(handlers::detection_code_targets::get_target)
                .put(handlers::detection_code_targets::update_target)
                .delete(handlers::detection_code_targets::delete_target),
        )
        .route(
            "/api/detection-code-targets/{id}/token",
            post(handlers::detection_code_targets::set_token),
        )
        // Rule Repositories (external Sigma rule syncing)
        .route(
            "/api/rule-repositories",
            get(handlers::rule_repositories::list_repositories),
        )
        .route(
            "/api/rule-repositories",
            post(handlers::rule_repositories::create_repository),
        )
        .route(
            "/api/rule-repositories/coverage",
            get(handlers::rule_repositories::get_coverage),
        )
        .route(
            "/api/rule-repositories/coverage/refresh",
            post(handlers::rule_repositories::refresh_coverage),
        )
        .route(
            "/api/rule-repositories/{id}",
            get(handlers::rule_repositories::get_repository),
        )
        .route(
            "/api/rule-repositories/{id}",
            put(handlers::rule_repositories::update_repository),
        )
        .route(
            "/api/rule-repositories/{id}",
            delete(handlers::rule_repositories::delete_repository),
        )
        .route(
            "/api/rule-repositories/{id}/sync",
            post(handlers::rule_repositories::sync_repository),
        )
        .route(
            "/api/rule-repositories/{id}/sync/status",
            get(handlers::rule_repositories::get_sync_status),
        )
        .route(
            "/api/rule-repositories/{id}/folders",
            get(handlers::rule_repositories::list_folders),
        )
        .route(
            "/api/rule-repositories/{id}/rules",
            get(handlers::rule_repositories::list_repository_rules),
        )
        .route(
            "/api/rule-repositories/{id}/rules/by-path/{*path}",
            get(handlers::rule_repositories::get_repository_rule),
        )
        .route(
            "/api/rule-repositories/{id}/rules/preview/{*path}",
            get(handlers::rule_repositories::preview_import),
        )
        .route(
            "/api/rule-repositories/{id}/rules/import/{*path}",
            post(handlers::rule_repositories::import_rule),
        )
        .route(
            "/api/rule-repositories/{id}/rules/import-batch",
            post(handlers::rule_repositories::batch_import_rules),
        )
        .route(
            "/api/rule-repositories/{id}/rules/remove-all-imported",
            post(handlers::rule_repositories::remove_all_imported),
        )
        .route(
            "/api/rule-repositories/{id}/upstream-updates",
            get(handlers::rule_repositories::get_upstream_updates),
        )
        // Upstream diff for a detection rule (separate from repo routes)
        .route(
            "/api/detection-rules/{id}/upstream-diff",
            get(handlers::rule_repositories::get_upstream_diff),
        )
        .route(
            "/api/detection-rules/{id}/upstream-diff/dismiss",
            post(handlers::rule_repositories::dismiss_upstream_changes),
        )
        // Sigma conversion (standalone)
        .route(
            "/api/sigma/convert",
            post(handlers::rule_repositories::convert_sigma),
        )
        // Parser Repositories (external parser syncing)
        .route(
            "/api/parser-repositories",
            get(handlers::parser_repositories::list_parser_repositories),
        )
        .route(
            "/api/parser-repositories",
            post(handlers::parser_repositories::create_parser_repository),
        )
        // NAN-2120: repository-scoped. The predecessor
        // `/api/parser-repositories/fixup-match-values` rewrote live
        // `match_values` for EVERY import in the tenant from a single request
        // holding only `parser_repositories:manage`.
        .route(
            "/api/parser-repositories/{id}/fixup-match-values",
            post(handlers::parser_repositories::fixup_match_values),
        )
        .route(
            "/api/parser-repositories/{id}",
            get(handlers::parser_repositories::get_parser_repository),
        )
        .route(
            "/api/parser-repositories/{id}",
            put(handlers::parser_repositories::update_parser_repository),
        )
        .route(
            "/api/parser-repositories/{id}",
            delete(handlers::parser_repositories::delete_parser_repository),
        )
        .route(
            "/api/parser-repositories/{id}/sync",
            post(handlers::parser_repositories::sync_parser_repository),
        )
        .route(
            "/api/parser-repositories/{id}/sync/status",
            get(handlers::parser_repositories::get_parser_sync_status),
        )
        .route(
            "/api/parser-repositories/{id}/parsers",
            get(handlers::parser_repositories::list_repository_parsers),
        )
        .route(
            "/api/parser-repositories/{id}/parsers/by-path/{*path}",
            get(handlers::parser_repositories::get_repository_parser),
        )
        .route(
            "/api/parser-repositories/{id}/parsers/preview/{*path}",
            get(handlers::parser_repositories::preview_parser_import),
        )
        .route(
            "/api/parser-repositories/{id}/parsers/import/{*path}",
            post(handlers::parser_repositories::import_parser),
        )
        .route(
            "/api/parser-repositories/{id}/parsers/import-batch",
            post(handlers::parser_repositories::batch_import_parsers),
        )
        .route(
            "/api/parser-repositories/{id}/parsers/remove-all-imported",
            post(handlers::parser_repositories::remove_all_imported_parsers),
        )
        .route(
            "/api/parser-repositories/{id}/upstream-updates",
            get(handlers::parser_repositories::get_parser_upstream_updates),
        )
        // Upstream diff for a log source (parser repo)
        .route(
            "/api/log-sources/{id}/upstream-diff",
            get(handlers::parser_repositories::get_log_source_upstream_diff),
        )
        .route(
            "/api/log-sources/{id}/upstream-diff/dismiss",
            post(handlers::parser_repositories::dismiss_parser_upstream_changes),
        )
        .route(
            "/api/log-sources/{id}/apply-upstream-update",
            post(handlers::parser_repositories::apply_upstream_update),
        )
        .route(
            "/api/parser-repositories/{id}/apply-all-upstream-updates",
            post(handlers::parser_repositories::apply_all_upstream_updates),
        )
        // Playbooks library
        .route(
            "/api/playbooks",
            get(handlers::playbooks::list_playbooks),
        )
        .route(
            "/api/playbooks",
            post(handlers::playbooks::create_playbook),
        )
        .route(
            "/api/playbooks/{id}",
            get(handlers::playbooks::get_playbook),
        )
        .route(
            "/api/playbooks/{id}",
            patch(handlers::playbooks::update_playbook),
        )
        .route(
            "/api/playbooks/{id}",
            delete(handlers::playbooks::archive_playbook),
        )
        .route(
            "/api/playbooks/{id}/fork",
            post(handlers::playbooks::fork_playbook),
        )
        .route(
            "/api/playbooks/{id}/permanent",
            delete(handlers::playbooks::delete_playbook_permanent),
        )
        .route(
            "/api/playbooks/{id}/versions",
            get(handlers::playbooks::list_versions),
        )
        .route(
            "/api/playbooks/{id}/runs",
            get(handlers::playbooks::list_runs),
        )
        .route(
            "/api/playbooks/{id}/permissions",
            get(handlers::playbooks::list_permissions),
        )
        .route(
            "/api/playbooks/{id}/approvals",
            get(handlers::playbooks::list_approvals),
        )
        // NAN-445: Phase 4 — suggest + runs (rule/case auto-attach)
        .route(
            "/api/playbooks/suggest-for-rule/{rule_id}",
            get(handlers::playbooks::suggest_for_rule),
        )
        // NAN-473: dry-resolve mounted separately below (rate-limited sub-router).
        .route(
            "/api/playbooks/{id}/runs",
            post(handlers::playbooks::attach_to_case),
        )
        .route(
            "/api/playbook-runs/{id}",
            patch(handlers::playbooks::finish_run),
        )
        .route(
            "/api/cases/{case_id}/playbook-runs",
            get(handlers::playbooks::list_runs_for_case),
        )
        // NAN-462: resolve a run against its run_context snapshot
        .route(
            "/api/playbook-runs/{id}/resolved",
            get(handlers::playbooks::resolve_run),
        )
        // NAN-463: per-step completion upsert (active-run surface)
        .route(
            "/api/playbook-runs/{run_id}/steps/{step_id}",
            patch(handlers::playbooks::update_step_completion),
        )
        // NAN-446: Phase 5 — adaptive → library promote
        .route(
            "/api/playbooks/{id}/promote",
            post(handlers::playbooks::promote_playbook),
        )
        // NAN-447: Phase 6 — approval workflow + permissions
        .route(
            "/api/playbooks/{id}/submit-for-review",
            post(handlers::playbooks::submit_for_review),
        )
        .route(
            "/api/playbook-approvals/{id}/approve",
            post(handlers::playbooks::approve_playbook),
        )
        .route(
            "/api/playbook-approvals/{id}/reject",
            post(handlers::playbooks::reject_playbook),
        )
        .route(
            "/api/playbooks/{id}/permissions/{role}",
            axum::routing::put(handlers::playbooks::set_permission),
        )
        .route(
            "/api/playbooks/{id}/permissions/{role}",
            axum::routing::delete(handlers::playbooks::delete_permission),
        )
        // NAN-448: Phase 7 — real analytics
        .route(
            "/api/playbooks/{id}/analytics",
            get(handlers::playbooks::get_analytics),
        )
        // NAN-449: Phase 5b — compose adaptive playbook from case
        .route(
            "/api/cases/{case_id}/compose-adaptive-playbook",
            post(handlers::playbooks::compose_adaptive_from_case),
        )
        // Playbook repositories (external sync)
        .route(
            "/api/playbook-repositories",
            get(handlers::playbook_repositories::list_playbook_repositories),
        )
        .route(
            "/api/playbook-repositories",
            post(handlers::playbook_repositories::create_playbook_repository),
        )
        .route(
            "/api/playbook-repositories/{id}",
            get(handlers::playbook_repositories::get_playbook_repository),
        )
        .route(
            "/api/playbook-repositories/{id}",
            patch(handlers::playbook_repositories::update_playbook_repository),
        )
        .route(
            "/api/playbook-repositories/{id}",
            delete(handlers::playbook_repositories::delete_playbook_repository),
        )
        .route(
            "/api/playbook-repositories/{id}/sync",
            post(handlers::playbook_repositories::sync_playbook_repository),
        )
        .route(
            "/api/playbook-repositories/{id}/sync/status",
            get(handlers::playbook_repositories::get_playbook_sync_status),
        )
        .route(
            "/api/playbook-repositories/{id}/playbooks",
            get(handlers::playbook_repositories::list_repository_playbooks),
        )
        // NAN-611: bulk import — promotes every parseable cached playbook into
        // the library. Must be registered before the `import/{*path}` catch-all
        // below so axum doesn't route "import-all" as a path parameter.
        .route(
            "/api/playbook-repositories/{id}/playbooks/import-all",
            post(handlers::playbook_repositories::import_all_repository_playbooks),
        )
        // NAN-611: combined sync + bulk import — backs the "Sync now" button on
        // the Playbooks library so users get one toast per click instead of
        // polling sync status from the browser.
        .route(
            "/api/playbook-repositories/{id}/sync-and-import",
            post(handlers::playbook_repositories::sync_and_import_repository),
        )
        // NAN-453: axum requires catch-all params `{*path}` to be the last
        // segment. Matches the rule_repositories pattern at line 1537:
        // `/rule-repositories/{id}/rules/import/{*path}`.
        .route(
            "/api/playbook-repositories/{id}/playbooks/import/{*path}",
            post(handlers::playbook_repositories::import_repository_playbook),
        )
        // Query library
        .route("/api/query-library", get(handlers::list_queries))
        .route("/api/query-library", post(handlers::create_query))
        .route(
            "/api/query-library/categories",
            get(handlers::get_categories),
        )
        .route("/api/query-library/tags", get(handlers::get_tags))
        .route("/api/query-library/{id}", get(handlers::get_query))
        .route("/api/query-library/{id}", delete(handlers::delete_query))
        // GDPR anonymization
        .route(
            "/api/gdpr/anonymize",
            post(handlers::gdpr::submit_anonymization),
        )
        .route(
            "/api/gdpr/anonymize",
            get(handlers::gdpr::list_anonymization_requests),
        )
        .route(
            "/api/gdpr/anonymize/{id}",
            get(handlers::gdpr::get_anonymization_request),
        )
        .route(
            "/api/gdpr/anonymize/{id}/execute",
            post(handlers::gdpr::execute_anonymization),
        )
        // System metrics
        .route("/api/system/overview", get(handlers::get_system_overview))
        .route(
            "/api/system/config",
            get(handlers::system::get_system_config),
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
        .route("/api/upload/history", get(handlers::get_upload_history))
        // Lookup table endpoints
        .route("/api/lookup-tables", post(handlers::create_lookup_table))
        .route("/api/lookup-tables", get(handlers::list_lookup_tables))
        .route(
            "/api/lookup-tables/schema",
            post(handlers::create_lookup_table_from_schema),
        )
        .route("/api/lookup-tables/query", post(handlers::lookup_query))
        .route("/api/lookup-tables/{name}", get(handlers::get_lookup_table))
        .route(
            "/api/lookup-tables/{name}",
            delete(handlers::delete_lookup_table),
        )
        .route(
            "/api/lookup-tables/{name}/sample",
            get(handlers::get_lookup_table_sample),
        )
        .route(
            "/api/lookup-tables/{name}/usage",
            get(handlers::get_lookup_table_usage),
        )
        .route(
            "/api/lookup-tables/{name}/ingestion-history",
            get(handlers::get_lookup_table_ingestion_history),
        )
        .route(
            "/api/lookup-tables/{name}/rows",
            get(handlers::list_lookup_rows),
        )
        .route(
            "/api/lookup-tables/{name}/rows",
            post(handlers::add_lookup_rows),
        )
        .route(
            "/api/lookup-tables/{name}/rows",
            delete(handlers::delete_lookup_rows),
        )
        .route(
            "/api/lookup-tables/{name}/rows/{row_id}",
            put(handlers::update_lookup_row),
        )
        .route(
            "/api/lookup-tables/{name}/rows/{row_id}",
            delete(handlers::delete_lookup_row),
        )
        // Lookup table ingestion endpoints
        .route(
            "/api/lookup-tables/validate-cron",
            post(handlers::lookup::ingestion::validate_cron_expression),
        )
        .route(
            "/api/lookup-tables/{name}/ingestion",
            get(handlers::lookup::ingestion::get_lookup_ingestion),
        )
        .route(
            "/api/lookup-tables/{name}/ingestion",
            put(handlers::lookup::ingestion::upsert_lookup_ingestion),
        )
        .route(
            "/api/lookup-tables/{name}/ingestion",
            delete(handlers::lookup::ingestion::delete_lookup_ingestion),
        )
        .route(
            "/api/lookup-tables/{name}/ingestion/trigger",
            post(handlers::lookup::ingestion::trigger_lookup_ingestion),
        )
        .route(
            "/api/lookup-tables/{name}/ingestion/enable",
            post(handlers::lookup::ingestion::enable_lookup_ingestion),
        )
        .route(
            "/api/lookup-tables/{name}/ingestion/disable",
            post(handlers::lookup::ingestion::disable_lookup_ingestion),
        )
        // Dashboard endpoints
        .route("/api/dashboards", get(handlers::list_dashboards))
        .route("/api/dashboards", post(handlers::create_dashboard))
        .route("/api/dashboards/panel/query", post(handlers::panel_query))
        .route("/api/dashboards/import", post(handlers::import_dashboard))
        .route(
            "/api/dashboards/export/{id}",
            post(handlers::export_dashboard),
        )
        .route("/api/dashboards/{id}", get(handlers::get_dashboard))
        .route("/api/dashboards/{id}", put(handlers::update_dashboard))
        .route("/api/dashboards/{id}", delete(handlers::delete_dashboard))
        .route(
            "/api/dashboards/{id}/share",
            post(handlers::share_dashboard),
        )
        // Scheduled report endpoints (NAN-1793). Static segments (`runs`,
        // `artifacts`) are declared before `{id}` so matchit prefers them.
        // Referenced via the qualified module path because `reports` is not
        // glob-re-exported (its list_reports/get_report collide with siem_health).
        .route("/api/reports", get(handlers::reports::list_reports))
        .route("/api/reports", post(handlers::reports::create_report))
        .route(
            "/api/reports/runs/{run_id}",
            get(handlers::reports::get_report_run),
        )
        .route(
            "/api/reports/artifacts/{artifact_id}/download",
            get(handlers::reports::download_report_artifact),
        )
        .route("/api/reports/{id}", get(handlers::reports::get_report))
        .route("/api/reports/{id}", put(handlers::reports::update_report))
        .route("/api/reports/{id}", delete(handlers::reports::delete_report))
        .route("/api/reports/{id}/run", post(handlers::reports::trigger_report))
        .route(
            "/api/reports/{id}/runs",
            get(handlers::reports::list_report_runs),
        );

    // Notebook endpoints — enterprise only (cases-coupled).
    #[cfg(feature = "enterprise")]
    {
        app = app
            .route(
                "/api/notebooks",
                get(handlers::notebooks::list_notebooks::<AppState>),
            )
            .route(
                "/api/notebooks",
                post(handlers::notebooks::create_notebook::<AppState>),
            )
            .route(
                "/api/notebooks/active",
                get(handlers::notebooks::get_active_notebook::<AppState>),
            )
            .route(
                "/api/notebooks/by-reference",
                get(handlers::notebooks::find_by_reference::<AppState>),
            )
            // Notebook tabs (must be before {id} routes)
            .route(
                "/api/notebooks/tabs",
                get(handlers::notebooks::list_tabs::<AppState>),
            )
            .route(
                "/api/notebooks/tabs",
                post(handlers::notebooks::open_tab::<AppState>),
            )
            .route(
                "/api/notebooks/tabs/reorder",
                post(handlers::notebooks::reorder_tabs::<AppState>),
            )
            .route(
                "/api/notebooks/tabs/{tab_id}",
                delete(handlers::notebooks::close_tab::<AppState>),
            )
            .route(
                "/api/notebooks/tabs/{tab_id}",
                patch(handlers::notebooks::update_tab::<AppState>),
            )
            .route(
                "/api/notebooks/tabs/active/{notebook_id}",
                post(handlers::notebooks::set_active_tab::<AppState>),
            )
            // Individual notebook routes
            .route(
                "/api/notebooks/{id}",
                get(handlers::notebooks::get_notebook::<AppState>),
            )
            .route(
                "/api/notebooks/{id}",
                put(handlers::notebooks::update_notebook::<AppState>),
            )
            .route(
                "/api/notebooks/{id}",
                delete(handlers::notebooks::delete_notebook::<AppState>),
            )
            .route(
                "/api/notebooks/{id}/entries",
                get(handlers::notebooks::get_entries::<AppState>),
            )
            .route(
                "/api/notebooks/{id}/entries",
                post(handlers::notebooks::add_entry::<AppState>),
            )
            .route(
                // NAN-1840: the ONLY endpoint that accepts AI-typed entries, and it
                // stamps their provenance server-side. `/entries` still refuses them.
                "/api/notebooks/{id}/agent-entries",
                post(handlers::notebooks::add_agent_entry::<AppState>),
            )
            .route(
                "/api/notebooks/{id}/entries/{entry_id}",
                delete(handlers::notebooks::delete_entry::<AppState>),
            )
            .route(
                "/api/notebooks/{id}/shares",
                get(handlers::notebooks::get_shares::<AppState>),
            )
            .route(
                "/api/notebooks/{id}/shares",
                post(handlers::notebooks::add_share::<AppState>),
            )
            .route(
                "/api/notebooks/{id}/shares/{share_id}",
                delete(handlers::notebooks::delete_share::<AppState>),
            )
            .route(
                "/api/notebooks/{id}/share",
                post(handlers::notebooks::share_notebook::<AppState>),
            )
            .route(
                "/api/notebooks/{id}/references",
                get(handlers::notebooks::get_references::<AppState>),
            )
            .route(
                "/api/notebooks/{id}/references",
                post(handlers::notebooks::add_reference::<AppState>),
            )
            .route(
                "/api/notebooks/{id}/references/{ref_id}",
                delete(handlers::notebooks::delete_reference::<AppState>),
            )
            .route(
                "/api/notebooks/{id}/escalate",
                post(handlers::notebooks::escalate_to_case::<AppState>),
            )
            .route(
                "/api/notebooks/{id}/merge",
                post(handlers::notebooks::merge_notebooks::<AppState>),
            )
            .route(
                "/api/notebooks/{id}/unlink",
                post(handlers::notebooks::unlink_notebook_from_case::<AppState>),
            )
            .route(
                "/api/notebooks/{id}/chat",
                post(handlers::notebooks::notebook_chat::<AppState>),
            )
            .route(
                "/api/notebooks/{id}/chat/stream",
                post(handlers::notebooks::notebook_chat_stream::<AppState>),
            );
    }

    app = app
        // SIEM Health Check
        .route(
            "/api/siem-health/reports",
            get(handlers::siem_health::list_reports),
        )
        .route(
            "/api/siem-health/reports/latest",
            get(handlers::siem_health::get_latest_report),
        )
        .route(
            "/api/siem-health/reports/trigger",
            post(handlers::siem_health::trigger_health_check),
        )
        .route(
            "/api/siem-health/reports/{id}",
            get(handlers::siem_health::get_report),
        )
        .route(
            "/api/siem-health/findings/suppressions",
            get(handlers::siem_health_suppressions::list_suppressions)
                .post(handlers::siem_health_suppressions::create_suppression),
        )
        .route(
            "/api/siem-health/findings/suppressions/{id}",
            axum::routing::delete(handlers::siem_health_suppressions::deactivate_suppression),
        )
        // Observability console SLOs (NAN-1536) — PG-backed definitions,
        // attainment computed on read from otel_spans.
        .route(
            "/api/observability/slos",
            get(handlers::observability_slos::list_slos)
                .post(handlers::observability_slos::create_slo),
        )
        .route(
            "/api/observability/slos/{id}",
            put(handlers::observability_slos::update_slo)
                .delete(handlers::observability_slos::delete_slo),
        )
        // Observability console synthetic checks (NAN-1538) — PG-backed
        // definitions; live uptime/latency/history computed on read from the
        // ClickHouse synthetic_check_results table the jobs runner writes.
        .route(
            "/api/observability/synthetics",
            get(handlers::observability_synthetics::list_synthetics)
                .post(handlers::observability_synthetics::create_synthetic),
        )
        .route(
            "/api/observability/synthetics/{id}",
            put(handlers::observability_synthetics::update_synthetic)
                .delete(handlers::observability_synthetics::delete_synthetic),
        )
        // Observability metric monitors (NAN-1540) — PG-backed definitions;
        // the jobs runner evaluates due monitors and raises alerts on breach.
        .route(
            "/api/observability/metric-monitors",
            get(handlers::observability_metric_monitors::list_metric_monitors)
                .post(handlers::observability_metric_monitors::create_metric_monitor),
        )
        .route(
            "/api/observability/metric-monitors/{id}",
            put(handlers::observability_metric_monitors::update_metric_monitor)
                .delete(handlers::observability_metric_monitors::delete_metric_monitor),
        )
        // Tuning endpoints
        .route(
            "/api/tuning/baselines/{rule_id}",
            get(handlers::get_baseline),
        )
        .route("/api/tuning/metrics/{rule_id}", get(handlers::get_metrics))
        .route(
            "/api/tuning/breaches/{rule_id}",
            get(handlers::get_breaches),
        )
        .route("/api/tuning/proposals", get(handlers::list_proposals))
        .route("/api/tuning/proposals/{id}", get(handlers::get_proposal))
        .route(
            "/api/tuning/proposals/{id}/approve",
            post(handlers::approve_proposal),
        )
        .route(
            "/api/tuning/proposals/{id}/reject",
            post(handlers::reject_proposal),
        )
        .route(
            "/api/tuning/versions/{rule_id}",
            get(handlers::list_versions),
        )
        .route(
            "/api/tuning/versions/{rule_id}/{version_id}",
            get(handlers::get_version),
        )
        .route(
            "/api/tuning/versions/{rule_id}/{version_id}/activate",
            post(handlers::activate_version),
        )
        .route("/api/tuning/logs", get(handlers::list_logs))
        .route("/api/tuning/logs/{id}", get(handlers::get_log))
        .route(
            "/api/tuning/logs/{id}/revert",
            post(handlers::revert_tuning),
        )
        .route(
            "/api/tuning/notifications",
            get(handlers::tuning::list_tuning_notifications),
        )
        .route(
            "/api/tuning/notifications/{id}/read",
            post(handlers::tuning::mark_tuning_notification_read),
        )
        .route(
            "/api/tuning/notifications/read-all",
            post(handlers::tuning::mark_all_tuning_notifications_read),
        )
        .route(
            "/api/tuning/settings/{rule_id}",
            get(handlers::get_tuning_settings),
        )
        .route(
            "/api/tuning/settings/{rule_id}",
            put(handlers::update_tuning_settings),
        )
        // Cacheable routes (with Cache-Control headers)
        .merge(cached_metadata)
        .merge(cached_mitre)
        .merge(cached_mitre_coverage)
        // OpenAPI / Swagger UI
        .merge(openapi::swagger_ui());
    // Observability ↔ Security convergence cross-link (NAN-1542) — ENTERPRISE
    // only (NAN-1544). The service-detail "which detections fired against this
    // service's hosts/IPs?" strip. Open builds omit the route (404) and the FE
    // hides the strip via the `observabilityConvergence` capability flag.
    #[cfg(feature = "enterprise")]
    {
        app = app.route(
            "/api/observability/services/{service}/security-signals",
            get(handlers::observability_service_signals::get_service_security_signals),
        );
    }
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
    app = app.merge(handlers::source_scopes::source_scopes_routes());
    #[cfg_attr(not(feature = "enterprise"), allow(unused_mut))]
    let mut app = app
        // Add state
        .with_state(state.clone())
        // Demo guard (runs after auth, blocks admin endpoints for demo users)
        .layer(axum_middleware::from_fn_with_state(
            state.config.deployment_mode,
            crate::middleware::demo_guard,
        ))
        // Tier-based API write guard (runs after auth, blocks API key writes on readonly tiers)
        .layer(axum_middleware::from_fn_with_state(
            state.pool.clone(),
            crate::middleware::api_write_guard,
        ))
        // Audit middleware: capture 403s from handlers + downstream guards and
        // emit auth_denied events. Sits between auth (which sets AuthContext)
        // and the per-handler guards so it observes their 403s as well.
        // Linear: NAN-687
        .layer(axum_middleware::from_fn_with_state(
            state.clone(),
            crate::middleware::audit_authz_failures,
        ))
        // Add auth middleware (must be before CORS and logging)
        .layer(axum_middleware::from_fn_with_state(
            auth_state,
            auth_middleware,
        ));

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

    let app = app
        // IP allowlist middleware (runs before auth — denied IPs never hit authentication)
        .layer(axum_middleware::from_fn_with_state(
            ip_allowlist_state,
            ip_allowlist_middleware,
        ))
        // Sanitize framework-generated error responses (e.g. Json extractor rejections)
        .layer(axum_middleware::from_fn(
            crate::middleware::sanitize_error_responses,
        ))
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

    app
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
            axum::http::header::HeaderName::from_static("x-api-key"),
            axum::http::header::HeaderName::from_static("x-request-id"),
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
